//! Node **telemetry** for finality-stall observability (M10-T0-2, issue #63).
//!
//! The Crosslink feature-net stall (design §4 status, 2026-07-24) was painful in
//! part because an operator had no first-class read of *how badly* finality had
//! fallen behind. This module is the operator surface: a single versioned
//! [`Telemetry`] snapshot carrying the finality regime plus the numbers a stall
//! runbook (and the T0-3 soak monitor) actually watch — stall depth, how long
//! finality has been stuck, peers, mempool, heights, and epoch.
//!
//! Wire discipline mirrors the N6 surfaces ([`crate::rpc::NodeStatus`]): a
//! [`RPC_VERSION`] lead version byte, little-endian fixed fields, and
//! reject-unknown-version / reject-trailing on decode (§0). Peer count and epoch
//! are **injected** from the P2P layer (they are not node-state — the N1 traits do
//! not carry them), so the node-owned half is assembled from live state and the
//! network half is stamped in by the p2p glue via
//! [`crate::rpc::NodeRpc::set_net_facts`].
//!
//! # Checkpoint identity (issue #117, wire `0x02`)
//!
//! `final=` says how *high* a node finalized and never *what*, so two nodes that
//! finalized different checkpoints at one height printed identical telemetry.
//! #110 put the identity on the `TELEMETRY` log line and on `/metrics`; this wire
//! carries it too, because it is the operator surface and checkpoint identity is
//! the operator's most severe question. Mirroring the log line:
//!
//! - [`Telemetry::finalized_id`] (`fid`) — **what** this node finalized.
//! - [`Telemetry::signed`] (`sslot`/`sid`) — what this node's own committee keys
//!   are committed to, and at which slot. A minority that signed a different
//!   variant still finalizes the majority's, so a split shows up *here* while
//!   `final` and `fid` still agree everywhere.
//! - [`Telemetry::tip_difficulty`] (`diff`) — a **fourth** field beyond the three
//!   the #117 decision named, added because the operator view that decision exists
//!   to serve is required to render difficulty per node and no wire carried it.
//!   Riding the same version bump costs nothing extra; shipping a column that
//!   could only say `-` would.
//!
//! Like peer count and epoch, they are **injected**: they live in the committee
//! finality tracker and the never-double-sign ledgers, not in [`crate::Node`].
//! A composition that does not inject them reports them absent, which is the
//! truth about that composition rather than a zero standing in for one.
//!
//! Appending them is a breaking change on a reject-unknown-version wire — that is
//! deliberate (§0: a truncated or stale read fails loudly instead of misparsing),
//! and it is why [`RPC_VERSION`] went `0x01` → `0x02`. Issue #121 adds only the
//! publishable committee aggregates (never signer identities) and the supply
//! attestation, moving the wire to `0x03`. An old reader is *supposed* to fail
//! against a new node.
//!
//! # The durable finalized head (issue #212, wire `0x04`)
//!
//! Everything above — `final=`, `fid` — reads **head #1**, the committee
//! [`FinalityTracker`](qlab_devnet::finality::FinalityTracker). It needs only a
//! quorum of votes and it is **discarded at shutdown**.
//!
//! [`Telemetry::durable`] (`dfin`/`dfinbh`) is **head #3**: the state machine's
//! chain store — the head [`crate::Snapshot`]`.finalized` is written from, the one
//! `no_reorg_past_finalized_checkpoint_ever` executes on, and the only one that
//! survives a restart. `PR #207` put its height on the container log as `dfin=`; it
//! was not on any wire, and `qumbra-opview` — the pass/fail instrument for the four
//! T0 drills — reads the wire and nothing else. On 2026-08-01 node1 held
//! `final=1056 fid=fa3f9ac3680a` while its durable head was 1048 for hours, and
//! opview would have reported four-way agreement the whole time.
//!
//! 🔴 **`fid` and the durable head's identity are not values in the same space.**
//! `fid` is a [`qlab_devnet::committee::Checkpoint::identity`] — a digest of the
//! exact bytes the committee's ML-DSA keys signed. The durable head offers a
//! **block hash**, and no truncation of a block hash becomes a checkpoint identity.
//! `qumbra-deploy/OPERATOR.md` §3 already carries *"Two different values are called
//! 'the genesis hash'. Comparing them is meaningless"*, written after an operator
//! compared a block-header hash to a genesis-file hash and concluded a host was
//! broken. [`BlockIdentity`] exists so that the second instance of that mistake
//! **does not compile**.

use qlab_cbserver::codec::{write_varint, CodecError};
use qlab_devnet::committee::{checkpoint_id_hex, CHECKPOINT_ID_ABSENT, CHECKPOINT_ID_BYTES};
use qlab_devnet::ebbflow::FinalityStatus;
use qlab_devnet::halt::regime as halt_regime;

use crate::rpc::{Reader, RPC_VERSION};
use crate::store::Hash32;
use crate::supply::SupplyEpoch;

/// Wire discriminant for [`FinalityStatus::Final`].
const STATUS_FINAL: u8 = 0;
/// Wire discriminant for [`FinalityStatus::Degraded`].
const STATUS_DEGRADED: u8 = 1;
/// Wire discriminant for [`FinalityStatus::Halting`] (halt-height upgrade, #74).
const STATUS_HALTING: u8 = 2;
/// Wire discriminant for [`FinalityStatus::Halted`].
const STATUS_HALTED: u8 = 3;

/// Wire discriminant for [`DurableView::Unavailable`] (issue #212).
const DURABLE_UNAVAILABLE: u8 = 0;
/// Wire discriminant for [`DurableView::Nothing`].
const DURABLE_NOTHING: u8 = 1;
/// Wire discriminant for [`DurableView::Head`], followed by height + identity.
const DURABLE_HEAD: u8 = 2;

/// The first [`RPC_VERSION`] whose `/v1/telemetry` payload carries the durable
/// finalized head (issue #212). Below it the tail is simply not there, which is a
/// different fact from a node that carries the tail and reports
/// [`DurableView::Unavailable`] in it.
pub const DURABLE_HEAD_SINCE_VERSION: u8 = 0x04;

/// **The telemetry wire versions a READER in this build can decode**, newest last.
///
/// 🔴 This is the answer to the roll problem, and it is deliberately narrow. `T0`
/// rolls one host at a time (`OPERATOR.md` §4: *"with no durable copy anywhere,
/// rolling several at once has nothing left to resync from"*) and the roll of all
/// four took 23 minutes on 2026-08-03. [`Telemetry::from_bytes`] is an **equality**
/// check on the version byte, so an `opview` built at `0x04` could read *nothing*
/// from a node still serving `0x03` — not a degraded subset, nothing — and
/// `qumbra-opview`'s verdict is *cross-host agreement*, which an instrument that
/// can see two of four hosts cannot answer. A bump with no reader-side answer would
/// reintroduce, for the length of the roll, exactly the blindness issue #212 exists
/// to remove.
///
/// **What this is not.** It is not a relaxation of §0's reject-unknown rule:
/// `0x01` and `0x02` are still refused, unknown versions are still refused, and
/// [`Telemetry::from_bytes`] — the path the node's own tests and every non-operator
/// consumer use — remains a hard equality check on [`RPC_VERSION`]. This list is a
/// **bounded, named set of versions this build knows the layout of**, read only by
/// [`Telemetry::from_bytes_compat`], which hands its caller the version it decoded
/// so the caller can say *why* a field is absent instead of printing a bare `-`.
///
/// **What removes `0x03` from it:** all four T0 hosts serving `0x04` or later.
/// Until then a reader that drops it is blind during the roll; after then, keeping
/// it lets a forgotten host look healthy, which is the failure mode in the other
/// direction. `0x04` (issue #275's route bump — the telemetry *payload* is
/// byte-identical at `0x04` and `0x05`) leaves under the same rule.
pub const READABLE_TELEMETRY_VERSIONS: &[u8] = &[0x03, 0x04, RPC_VERSION];

/// **An identity in the block-hash space**: the first [`CHECKPOINT_ID_BYTES`] of a
/// block hash, big-endian, rendered at `fid`'s width through `fid`'s helper.
///
/// 🔴 **This is not a [`qlab_devnet::committee::Checkpoint::identity`], and
/// comparing the two is meaningless.** A checkpoint identity is
/// `keccak256(height ‖ block_hash ‖ root)` truncated — the digest of the exact
/// bytes the committee's ML-DSA keys commit to, so two nodes reporting one identity
/// were provably asked to sign one thing. A block hash is the name of a block. They
/// are the same *width* and the same *rendering* and nothing else, and this repo has
/// already been bitten once by two same-shaped values with different meanings
/// (`OPERATOR.md` §3, issue #206).
///
/// # Why it is a type and not a convention
///
/// Because a convention was already tried and is already half-broken. `stipid=`
/// (#162 finding 6) is a block-hash prefix and `fid=`/`sid=` are checkpoint
/// identities, all three are `u64`, all three render identically, and **nothing
/// stops `applied.identity() == telemetry.finalized_id`** — a comparison that
/// type-checks, reads plausibly, and cannot mean anything. Issue #212 adds a third
/// value in the block-hash space, so the choice was to add a third opportunity for
/// that mistake or to make it a compile error. This is the compile error:
/// `BlockIdentity` has no `PartialEq<u64>`, so lining it up against `fid` does not
/// build.
///
/// [`Self::bits`] is the one escape hatch, and it exists because a wire and a
/// Prometheus gauge carry integers. It is named to be conspicuous at a call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockIdentity(u64);

impl BlockIdentity {
    /// The identity of `hash`: its first [`CHECKPOINT_ID_BYTES`], big-endian.
    ///
    /// The prefix is taken **directly** rather than re-hashed, for the reason
    /// [`AppliedTip`]'s docs give: re-hashing a hash would be a second derivation of
    /// one identity, and a divergence between two derivations presents as "the
    /// identities match" while the objects differ.
    pub fn of(hash: &Hash32) -> Self {
        Self(hash[..CHECKPOINT_ID_BYTES].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    /// **The raw 48 bits — for an encoder or a gauge, never for a comparison.**
    ///
    /// Any call site that feeds this into a comparison against `fid`, `sid`, or any
    /// [`qlab_devnet::committee::Checkpoint::identity`] has defeated the entire
    /// reason this type exists. The two live sites are
    /// [`Telemetry::to_bytes`] and `qumbra_node`'s `qumbra_state_tip_id` gauge.
    pub fn bits(self) -> u64 {
        self.0
    }

    /// Rebuild from [`Self::bits`] — the decoder's counterpart, and nothing else.
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// The canonical 12-char lowercase hex, from the same helper as `fid=`/`sid=`:
    /// one width and one scheme, so an operator reads the digits the same way. That
    /// they are *readable* the same way is exactly why they must not be *compared*.
    pub fn field(self) -> String {
        checkpoint_id_hex(Some(self.0))
    }
}

/// The `sid=` token when a node's own held keys are committed to *different*
/// checkpoints at the same slot (issue #84). Distinguishable from an identity by
/// length and by not being hex; see [`LocalCommitment::id_field`].
///
/// *(Moved here from `qumbra-node`'s run loop by issue #117 so the wire, the log
/// line and any reader share one definition; `qumbra_node::run` re-exports it.)*
pub const LOCAL_COMMITMENT_SPLIT: &str = "split";

/// What a node's own committee keys are committed to at one slot (issue #84).
///
/// The slot reported is the highest any held key has committed to, which is
/// deliberately **not** the finalized height: at a split, the minority still
/// finalizes the majority's checkpoint, so the two nodes agree on `final` (and on
/// `fid`) and differ only here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCommitment {
    /// The highest slot any held key has committed to.
    pub slot: u64,
    /// The identity every held key that committed to `slot` agrees on, or `None`
    /// when they disagree — this node's key set is split across two variants.
    pub id: Option<u64>,
}

impl LocalCommitment {
    /// The `sid=` field: the identity hex, or [`LOCAL_COMMITMENT_SPLIT`] when this
    /// node's own held keys are committed to different checkpoints for one slot.
    ///
    /// `split` is reachable — a key restored from a ledger written on one history
    /// refuses to re-sign while a key with no ledger signs the new one — and it is
    /// this node equivocating against itself across its own key set. Picking one of
    /// the two to print would be the exact failure #84 exists to remove: a line
    /// that looks healthy while the thing it describes is not.
    pub fn id_field(&self) -> String {
        match self.id {
            Some(id) => checkpoint_id_hex(Some(id)),
            None => LOCAL_COMMITMENT_SPLIT.to_string(),
        }
    }
}

/// **The one comparison of the two chain views this node holds** (issue #130): the
/// height the *state machine* has applied bodies up to, against the height *fork
/// choice* has headers up to.
///
/// It exists as a type because three surfaces need the same verdict and this repo
/// has ruled three times in one week that a second copy of a derivation is the
/// defect, not the convenience (#116, #102, #125):
///
/// - [`SupplyCoverage`] — a supply figure is publishable only at zero lag (#126);
/// - the `TELEMETRY` line's `stip=` / `slag=` fields and the `/metrics` gauges,
///   which is how an operator sees the lag at all;
/// - `qlab_p2p::adapter::NodeAdapter::state_lag`, which is the **duty gate**: while
///   this is nonzero the node refuses to mine or to admit a transaction, because
///   both would be acting on a view it knows is stale.
///
/// `fork_choice_tip` is always ≥ `state_tip` in a healthy node — headers land in
/// fork choice first and the body follows — so the difference is measured
/// saturating and a nonsensical pair reads as zero rather than underflowing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateLag {
    /// Highest height whose **body** this node has applied to state.
    pub state_tip: u64,
    /// Highest height whose **header** fork choice holds.
    pub fork_choice_tip: u64,
}

impl StateLag {
    pub fn new(state_tip: u64, fork_choice_tip: u64) -> Self {
        Self { state_tip, fork_choice_tip }
    }

    /// How many blocks the state machine trails fork choice by; 0 when the two
    /// views agree.
    pub fn blocks(&self) -> u64 {
        self.fork_choice_tip.saturating_sub(self.state_tip)
    }

    /// Whether the state machine is behind its own chain — the predicate every
    /// duty refusal keys on. One definition, so a duty cannot be refused on one
    /// reading while a figure is published on another.
    pub fn is_lagging(&self) -> bool {
        self.blocks() > 0
    }
}

/// The `schain=` token for an applied tip that **is** the main-chain block at its
/// own height: healthy, whatever `slag=` says. It will catch up.
pub const APPLIED_TIP_ON_MAIN: &str = "main";

/// The `schain=` token for an applied tip that is **not** the main-chain block at
/// its own height (issue #162 finding 6) — the state machine is on a branch fork
/// choice did not choose, and since `qlab_node::Node` cannot rewind
/// (`node.rs`'s `NotExtendingTip`; *"fork/reorg handling is N-later"*), it will
/// never catch up. **This is the absorbing state, made loud.**
pub const APPLIED_TIP_OFF_MAIN: &str = "fork";

/// **The identity of the state machine's applied tip, and whether it is on the
/// chain this node is following** (issue #162, finding 6).
///
/// [`StateLag`] answers *how far* the state machine trails fork choice. It cannot
/// answer *whether trailing is the whole story*, and those are different questions
/// with opposite operator responses:
///
/// - `slag=13` on a node whose applied tip is the main-chain block at height 1 is a
///   node **catching up**. Wait.
/// - `slag=13` on a node whose applied tip is a **sibling** of the main-chain block
///   at height 1 is a node that will never catch up. Intervene.
///
/// On the 2026-07-31 T0 net those two printed identically, and separating them
/// needed an archive dive: `node0`'s `stip=1` and `node2`'s `stip=1` looked the
/// same and were different blocks — node2's a sibling on a losing branch, node0's
/// the main chain. That is issue #84's sentence one layer down: *"`final=` says how
/// high, never **what**."*
///
/// # The identity is derived, not invented
///
/// [`Self::identity`] takes the first [`CHECKPOINT_ID_BYTES`] of the block hash,
/// big-endian, and renders it through the same [`checkpoint_id_hex`] that prints
/// `fid` and `sid` — one width, one scheme, three fields comparable by eye.
///
/// The block hash is *already* `keccak256` over the header preimage
/// (`qlab_devnet::header::BlockHeader::header_hash`), i.e. the canonical name of
/// the object, which is the same thing
/// [`qlab_devnet::committee::Checkpoint::identity`] takes its prefix of (there, the
/// digest of the exact bytes the committee signs). So the prefix is taken
/// **directly** rather than re-hashed: re-hashing a hash would be a second
/// derivation of one identity, which is the failure mode this repo has ruled
/// against repeatedly — and a divergence between two encodings presents as "the
/// identities match" while the objects differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedTip {
    /// Height whose body the state machine has applied — the same number
    /// [`StateLag::state_tip`] carries, from the same place.
    pub height: u64,
    /// The hash of the block the state machine applied **at that height**. This is
    /// the fact `stip=` alone cannot carry.
    pub hash: Hash32,
    /// The hash fork choice holds on its **main chain** at [`Self::height`], or
    /// `None` when fork choice has no block at that height at all.
    ///
    /// `None` is not reachable on a node whose fork-choice tip is at or above its
    /// applied tip (every applied block arrived through fork choice), which is
    /// every node in a healthy or a lagging state. It is kept as an honest third
    /// answer rather than collapsed into either verdict: an unjudgeable comparison
    /// must not print as "on the main chain".
    pub main_chain_hash: Option<Hash32>,
}

impl AppliedTip {
    pub fn new(height: u64, hash: Hash32, main_chain_hash: Option<Hash32>) -> Self {
        Self { height, hash, main_chain_hash }
    }

    /// **The applied tip's identity**: the first [`CHECKPOINT_ID_BYTES`] of the
    /// block hash, big-endian — the same width and the same fold as
    /// [`qlab_devnet::committee::Checkpoint::identity`]. See the type docs for why
    /// the prefix is taken directly.
    ///
    /// *(Issue #212 changed the return type from a bare `u64` to
    /// [`BlockIdentity`]. The value is byte-for-byte what it was — the change is
    /// that it no longer type-checks against `fid`, which is a comparison of two
    /// different spaces and was always meaningless. Adding a third block-hash
    /// identity to this file while leaving this one a bare `u64` would have made the
    /// type system claim the two are different spaces, which is worse than either
    /// uniform choice.)*
    pub fn identity(&self) -> BlockIdentity {
        BlockIdentity::of(&self.hash)
    }

    /// The `stipid=` field: [`Self::identity`] as the canonical 12-char lowercase
    /// hex, from the same helper as `fid=` and `sid=`.
    ///
    /// **Always a value.** A node always has an applied tip — genesis at minimum —
    /// so there is no absent case to print `-` for, and inventing one would be a
    /// sentinel that never fires.
    pub fn id_field(&self) -> String {
        self.identity().field()
    }

    /// **The detector**, and the one place it is computed:
    /// `state.tip_hash() != chain.main_chain_hash_at(state.tip_height())`.
    ///
    /// `None` when the comparison cannot be made ([`Self::main_chain_hash`] is
    /// absent). Every surface — the `schain=` field, the `/metrics` gauge, any
    /// future consumer — reads its verdict from here, so none of them can be
    /// checking a different condition than the others.
    pub fn off_main_chain(&self) -> Option<bool> {
        self.main_chain_hash.map(|main| main != self.hash)
    }

    /// [`Self::off_main_chain`] as a plain predicate: `false` when the comparison
    /// could not be made, because an alarm must not fire on the absence of
    /// evidence.
    pub fn is_off_main_chain(&self) -> bool {
        self.off_main_chain().unwrap_or(false)
    }

    /// The `schain=` field: [`APPLIED_TIP_ON_MAIN`], [`APPLIED_TIP_OFF_MAIN`], or
    /// [`CHECKPOINT_ID_ABSENT`] when fork choice holds no block at this height.
    ///
    /// This is the field that separates a lagging node from a wedged one on the one
    /// line an operator reads. `slag=` covers both; this does not.
    pub fn chain_field(&self) -> &'static str {
        match self.off_main_chain() {
            None => CHECKPOINT_ID_ABSENT,
            Some(false) => APPLIED_TIP_ON_MAIN,
            Some(true) => APPLIED_TIP_OFF_MAIN,
        }
    }
}

// ---- issue #212: the durable finalized head (head #3) ----------------------

/// **The durable finalized head**: the height head #3 holds, and the identity of
/// the block it holds there (issue #212).
///
/// Head #3 is the state machine's chain store — what [`crate::Snapshot`]`.finalized`
/// is written from, what the no-reorg-past-finality rule executes on, and the only
/// finalized head that survives a restart. `final=`/`fid` are head #1, the committee
/// tracker, which needs only a quorum of votes and is discarded at shutdown.
///
/// # The identity is a block hash, and that is the whole design decision
///
/// [`Self::identity`] is a [`BlockIdentity`] — `ChainStore::finalized_hash`'s prefix
/// — because a block hash is what head #3 actually offers
/// (`qlab-node/src/store.rs`'s `finalized_hash() -> Option<Hash32>`). It is
/// therefore comparable **node-to-node at a shared [`Self::height`]** and never
/// against `fid`. The alternative — having head #3 remember the
/// [`qlab_devnet::committee::Checkpoint::identity`] it finalized under, which would
/// be comparable to `fid` on a single node — is a [`crate::FORMAT_VERSION`] change
/// (`Snapshot` grows a field), and the ruling between the two is the coordinator's.
/// See the PR for both costings.
///
/// # What this pair detects that a height alone does not
///
/// The 2026-08-01 node1 case was a **height** divergence — `final=1056` over a
/// durable 1048 — and [`Self::height`] alone is sufficient for it. The identity
/// covers the *other* failure: two hosts both durably finalized at height `H` and
/// holding **different blocks** there. That one survives a restart on both hosts,
/// which is why it is a stop and not a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableHead {
    /// The height head #3 has recorded as finalized.
    pub height: u64,
    /// The identity of the block head #3 holds at [`Self::height`] — a **block
    /// hash** prefix, never a checkpoint identity.
    pub identity: BlockIdentity,
}

impl DurableHead {
    pub fn new(height: u64, block_hash: &Hash32) -> Self {
        Self { height, identity: BlockIdentity::of(block_hash) }
    }
}

/// **What a snapshot can say about head #3** (issue #212).
///
/// Three states, because two of them are routinely confused and they are not the
/// same fact:
///
/// - [`Self::Unavailable`] — *this composition does not read head #3.* A
///   [`crate::rpc::NodeRpc`] holds one node and no adapter; a test harness may inject
///   nothing. Saying "no durable head" there would be a claim about the chain made
///   from a fact about the plumbing.
/// - [`Self::Nothing`] — *head #3 was read and it has finalized nothing.* On a node
///   simultaneously reporting `final=2864` this is an alarm, not a blank.
/// - [`Self::Head`] — head #3 was read and this is what it holds.
///
/// The `dfin=` log field renders the first two identically as `-`, on purpose:
/// `dfin=`'s vocabulary is unchanged from `PR #207`, and the composition that emits
/// that line (`qumbra_node::run`) always injects, so it can never be
/// `Unavailable`. The distinction is for `qumbra-opview`, which polls compositions
/// it did not build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableView {
    /// This composition does not read head #3 and declines to answer.
    Unavailable,
    /// Head #3 was read; it has finalized nothing.
    Nothing,
    /// Head #3 was read; this is its head.
    Head(DurableHead),
}

impl DurableView {
    /// The head, if one was both readable and present.
    pub fn head(self) -> Option<DurableHead> {
        match self {
            DurableView::Head(h) => Some(h),
            _ => None,
        }
    }

    /// Whether this composition read head #3 at all.
    pub fn is_available(self) -> bool {
        !matches!(self, DurableView::Unavailable)
    }

    /// The `dfin=` field: head #3's height, or `-`.
    ///
    /// **Always printed, `-` included** (the #130 (a) rule). `-` covers both
    /// unreadable and nothing-finalized; see the type docs for why that is right on
    /// this surface and wrong on `qumbra-opview`'s.
    pub fn height_field(self) -> String {
        match self {
            DurableView::Head(h) => h.height.to_string(),
            _ => CHECKPOINT_ID_ABSENT.to_string(),
        }
    }

    /// The `dfinbh=` field: the identity of the **block** head #3 holds, or `-`.
    ///
    /// 🔴 Named `dfinbh` — durable-finalized **b**lock **h**ash — and deliberately
    /// not `dfid`. Every identity field on this surface so far ends in `id`
    /// (`fid`, `sid`, `stipid`) and two of those three spaces are already
    /// incomparable, so a fourth `…id` would invite the one comparison that cannot
    /// mean anything. The name says what the value is.
    pub fn id_field(self) -> String {
        match self {
            DurableView::Head(h) => h.identity.field(),
            _ => CHECKPOINT_ID_ABSENT.to_string(),
        }
    }
}

/// **The one comparison of head #1 against head #3 on a single node** (issue #212),
/// and the one place it is computed.
///
/// This is a *different alarm* from a cross-host split and the two must never be
/// merged: this one says **"this node will come back different"** and a cross-host
/// durable split says **"these nodes finalized different things"**. `#84` established
/// the same separation for `fid` vs `sid` and `agree.rs` honours it; the durable head
/// is a third such thing and gets its own name and its own alarm.
///
/// It is a type for the reason [`StateLag`] is a type: three surfaces need the same
/// verdict (the node's own line by eye, `qumbra-opview`'s per-node reading, and its
/// exit status), and this repo has ruled repeatedly that a second copy of a
/// derivation is the defect and not the convenience (#116, #102, #125).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableAgreement {
    /// This snapshot cannot see head #3. Not agreement and not disagreement.
    Unavailable,
    /// The two heads name one height (or both hold nothing).
    Agreed,
    /// 🟡 Head #1 is **ahead** of head #3 — the 2026-08-01 node1 shape exactly.
    ///
    /// A single sample cannot establish that this is sustained, and the routine
    /// cause is benign: `sync_state_finality` re-attempts on every drain, so the
    /// window between a checkpoint finalizing and its body being applied reads
    /// exactly like this. **Sustained is the alarm**; one sample is a reading. That
    /// is the same discipline the coordinator applied to `cpq=1` on 2026-08-02
    /// (*"watch, do not assume"*), and the pair to read it against is `slag=` and
    /// `fdrop=`.
    TrackerAhead { tracker: u64, durable: u64 },
    /// 🟡 Head #3 is ahead of head #1, or holds a head while head #1 reports
    /// nothing finalized.
    ///
    /// **Not reachable by construction today**: head #1 is re-derived at `open` from
    /// head #3 and only advances afterwards. It is a distinguished variant rather
    /// than folded into [`Self::TrackerAhead`] because if it is ever observed, the
    /// finding is about this code and not about the net — and a verdict that could
    /// not say which would send an operator hunting the wrong layer.
    DurableAhead { tracker: Option<u64>, durable: u64 },
    /// 🟡 Head #1 reports a finalized height and head #3 holds **nothing at all**.
    ///
    /// Distinct from [`Self::TrackerAhead`] because "1048 vs 1056" and "2864 vs
    /// nothing" are different magnitudes of the same failure, and the second one
    /// means a restart returns to genesis.
    NothingDurable { tracker: u64 },
}

impl DurableAgreement {
    /// Whether the two heads disagree. `false` for [`Self::Unavailable`], because
    /// **an alarm must not fire on the absence of evidence** — the same rule
    /// [`AppliedTip::is_off_main_chain`] follows.
    pub fn is_divergent(self) -> bool {
        !matches!(self, DurableAgreement::Agreed | DurableAgreement::Unavailable)
    }

    /// **A stable token alerting may depend on**, or `None` when the two heads agree
    /// or could not be compared.
    ///
    /// This is the mechanism that makes a 🟡 severity acceptable rather than a
    /// silence: issue #136 ruled the same way for `UNAVAILABLE` — a condition every
    /// briefly-lagging node reports must not be a non-zero exit code, or operators
    /// learn to ignore the one code that means STOP, so it is reported **in the
    /// output** as a greppable word instead.
    pub fn token(self) -> Option<&'static str> {
        match self {
            DurableAgreement::Agreed => None,
            DurableAgreement::Unavailable => None,
            DurableAgreement::TrackerAhead { .. } => Some("DURABLE_LAG"),
            DurableAgreement::DurableAhead { .. } => Some("DURABLE_AHEAD"),
            DurableAgreement::NothingDurable { .. } => Some("DURABLE_ABSENT"),
        }
    }
}

/// Whether the supply ledger covers the same tip as fork choice.
///
/// The supply rows are derived from bodies the state machine has applied, while
/// [`Telemetry::tip_height`] is fork choice. Issue #130 established that those
/// views can disagree permanently on a late joiner. A partial ledger must
/// therefore be rendered as unavailable, never as supply agreement or a supply
/// violation.
///
/// The verdict is [`StateLag::is_lagging`] — see [`Telemetry::supply_lag`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyCoverage {
    /// The last applied supply row reaches the fork-choice tip.
    Complete,
    /// The views disagree, or this composition supplied no ledger rows.
    Unavailable {
        state_tip: Option<u64>,
        fork_choice_tip: u64,
    },
}

/// A single observability snapshot of a node's finality health.
///
/// `stall_depth` and `last_finalized_age_secs` are the two the runbook keys on:
/// the former is the *height* gap (tip − finalized), the latter the *chain-time*
/// gap in seconds since the last finalized checkpoint — the same stall seen in the
/// two units an operator reasons in ("how many blocks behind" vs "how long stuck").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Telemetry {
    /// The Ebb-and-Flow finality regime (frozen §4 semantics, read here).
    pub finality_status: FinalityStatus,
    /// Fork-choice tip height.
    pub tip_height: u64,
    /// Finalized head height, if anything is finalized.
    pub finalized_height: Option<u64>,
    /// Stall depth = `tip − finalized` (or `tip` if nothing is finalized).
    pub stall_depth: u64,
    /// Chain-time seconds since the last finalized checkpoint (tip block timestamp
    /// − finalized block timestamp). Derived from block timestamps, so it is
    /// deterministic — no wall clock.
    ///
    /// **0, and rendered `-`, while there is no finalized checkpoint to measure
    /// from** — nothing finalized (S8) *or* the finalized head still genesis
    /// (issue #73). Genesis is finalized as a bootstrap act, not by a checkpoint
    /// round (`is_checkpoint_height`: genesis is never a slot), and its timestamp
    /// is the `0` placeholder — differencing a `WallClock` tip against it printed
    /// the whole Unix epoch (`age_s=1785352360` on every node of a fresh net).
    /// See [`Self::age_field`], the one rendering rule for this field.
    pub last_finalized_age_secs: u64,
    /// Connected peer count (injected from the P2P layer).
    pub peer_count: u64,
    /// Pending mempool size.
    pub mempool_size: u64,
    /// Current committee epoch (injected from the P2P/committee layer).
    pub epoch: u64,
    /// Roster size of the current committee.
    ///
    /// This is deliberately an aggregate. Per-signer participation belongs on the
    /// operator's loopback `/metrics` and in the `ROUND` journal, never on this
    /// public wire (issue #121).
    pub committee_size: u64,
    /// Active committee members (roster minus tombstoned/jailed).
    pub committee_active: u64,
    /// Quorum threshold currently in force, read from committee state.
    pub committee_quorum: u64,
    /// Scheduled-issuance attestation grouped by epoch, from genesis through the
    /// state machine's applied tip. Each row compares integer bessel at zero
    /// tolerance.
    ///
    /// Consumers must use [`Self::supply_coverage`] before rendering or acting on
    /// these rows: the state tip may trail the fork-choice `tip_height`.
    pub supply: Vec<SupplyEpoch>,
    /// **The identity of the finalized checkpoint** (`fid`, issue #117), or `None`
    /// when nothing is finalized *or* when the composition serving this snapshot
    /// does not carry a committee finality tracker to read it from.
    ///
    /// Injected via [`Self::with_checkpoint`] — see the module docs. Two nodes
    /// reporting the same `finalized_height` with different `finalized_id` is two
    /// different checkpoints at one height: the R2 stop condition, and the reason
    /// this field exists.
    pub finalized_id: Option<u64>,
    /// **What this node's own committee keys are committed to** (`sslot`/`sid`,
    /// issue #117), or `None` when it holds no committee keys, has committed to
    /// nothing, or the composition does not inject it.
    pub signed: Option<LocalCommitment>,
    /// The tip block's PoW difficulty (issue #117), or `None` when the tip header
    /// is not available to the composition serving this snapshot.
    ///
    /// Already on the `TELEMETRY` log line as `diff=` (Phase B-lite amendment-1
    /// item 4, so the LWMA retarget trace is visible over a soak) and on
    /// `/metrics`, but on no wire — and #117's operator view is required to render
    /// it per node. Carried here inside the same `0x02` bump rather than shipping a
    /// column that could only ever say `-`; see the PR for why this is a fourth
    /// field beside the three the decision named.
    pub tip_difficulty: Option<u64>,
    /// **Head #3 — the durable finalized head** (`dfin`/`dfinbh`, issue #212,
    /// wire `0x04`).
    ///
    /// [`Self::finalized_height`] and [`Self::finalized_id`] are head #1, the
    /// committee tracker, and do not survive a restart. This is the head that does.
    /// Injected exactly like the checkpoint identity — via
    /// [`Self::with_durable_head`] — because it lives in the adapter's state
    /// machine, which [`crate::Node`] alone cannot see.
    ///
    /// Its own field, its own name and its own alarm, never a slot inside
    /// `finalized_id`: `#84` established that `fid` and `sid` stay apart because a
    /// split in each is a different severity, and this is a third such thing.
    pub durable: DurableView,
}

impl Telemetry {
    /// Assemble a snapshot from the node-owned facts + the injected network facts.
    /// `max_lag` is the degraded-mode threshold
    /// ([`qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS`]); the finality
    /// regime and stall depth are derived from it exactly as the adapter's
    /// `finality_status` does — this module never re-defines the frozen rule.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        tip_height: u64,
        finalized_height: Option<u64>,
        last_finalized_age_secs: u64,
        mempool_size: u64,
        peer_count: u64,
        epoch: u64,
        max_lag: u64,
    ) -> Self {
        Self::assemble_with_halt(
            tip_height,
            finalized_height,
            last_finalized_age_secs,
            mempool_size,
            peer_count,
            epoch,
            max_lag,
            None,
        )
    }

    /// [`Self::assemble`], halt-aware (issue #74). `halt_at` is the running
    /// release's halt height, if it carries one; when a halt governs, the regime is
    /// `Halting`/`Halted` instead of the ordinary Ebb-and-Flow pair. The rule comes
    /// from [`qlab_devnet::halt::regime`] — this module never re-defines it.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_with_halt(
        tip_height: u64,
        finalized_height: Option<u64>,
        last_finalized_age_secs: u64,
        mempool_size: u64,
        peer_count: u64,
        epoch: u64,
        max_lag: u64,
        halt_at: Option<u64>,
    ) -> Self {
        let finality_status = halt_regime(tip_height, finalized_height, max_lag, halt_at);
        let stall_depth = match finalized_height {
            Some(fh) => tip_height.saturating_sub(fh),
            None => tip_height,
        };
        Self {
            finality_status,
            tip_height,
            finalized_height,
            stall_depth,
            last_finalized_age_secs,
            peer_count,
            mempool_size,
            epoch,
            committee_size: 0,
            committee_active: 0,
            committee_quorum: 0,
            supply: Vec::new(),
            finalized_id: None,
            signed: None,
            tip_difficulty: None,
            // Issue #212: `Unavailable` and NOT `Nothing`. This constructor cannot
            // see head #3, and "no durable head" would be a claim about the chain
            // made from a fact about the plumbing.
            durable: DurableView::Unavailable,
        }
    }

    /// Stamp in the public committee aggregates (issue #121).
    ///
    /// There is intentionally no signer list in this type, so neither the wire nor
    /// any consumer can accidentally turn it into an availability map.
    pub fn with_committee(
        mut self,
        committee_size: u64,
        committee_active: u64,
        committee_quorum: u64,
    ) -> Self {
        self.committee_size = committee_size;
        self.committee_active = committee_active;
        self.committee_quorum = committee_quorum;
        self
    }

    /// Stamp in the public per-epoch supply attestation (issue #121).
    pub fn with_supply(mut self, supply: Vec<SupplyEpoch>) -> Self {
        self.supply = supply;
        self
    }

    /// The one availability rule for supply figures.
    ///
    /// This mirrors [`Self::age_field`]'s refusal discipline: figures are
    /// publishable only when the applied state ledger and fork choice name the
    /// same tip height. The existing `0x03` payload already carries both heights
    /// (`tip_height` and the last supply row's `end_height`), so this rule needs
    /// no wire change.
    pub fn supply_coverage(&self) -> SupplyCoverage {
        match self.supply_lag() {
            Some(lag) if !lag.is_lagging() => SupplyCoverage::Complete,
            // Either the ledger trails fork choice, or this composition supplied no
            // rows at all — `state_tip` keeps those two apart for the reader.
            other => SupplyCoverage::Unavailable {
                state_tip: other.map(|lag| lag.state_tip),
                fork_choice_tip: self.tip_height,
            },
        }
    }

    /// The [`StateLag`] this snapshot can see, or `None` when it carries no supply
    /// rows to read an applied height from.
    ///
    /// The last supply row's `end_height` **is** the state machine's applied tip:
    /// the ledger is fed from applied bodies (`qumbra_node::run::RunningNode::telemetry`
    /// walks it to `state_chain.tip_height()`), so the `0x03` payload already carries
    /// both heights of the comparison and no wire bump is needed to publish it.
    pub fn supply_lag(&self) -> Option<StateLag> {
        self.supply.last().map(|row| StateLag::new(row.end_height, self.tip_height))
    }

    /// Stamp in the checkpoint-identity half (issue #117), the way
    /// [`crate::rpc::NodeRpc::set_net_facts`] stamps in peers/epoch: these live in
    /// the committee finality tracker and the never-double-sign ledgers, which
    /// [`crate::Node`] does not own.
    ///
    /// Leaving them unset is honest, not a gap — it says "this composition cannot
    /// see the identity", which is different from "there is no identity", and a
    /// reader that needs the distinction has it.
    pub fn with_checkpoint(
        mut self,
        finalized_id: Option<u64>,
        signed: Option<LocalCommitment>,
    ) -> Self {
        self.finalized_id = finalized_id;
        self.signed = signed;
        self
    }

    /// Stamp in the tip block's PoW difficulty (issue #117) — the `diff=` field of
    /// the `TELEMETRY` line, which lives in the header chain rather than in the
    /// finality state.
    pub fn with_tip_difficulty(mut self, difficulty: Option<u64>) -> Self {
        self.tip_difficulty = difficulty;
        self
    }

    /// Stamp in **head #3, the durable finalized head** (issue #212), from
    /// `qlab_p2p::NodeAdapter::durable_finalized_head`'s `(height, block_hash)`
    /// pair.
    ///
    /// 🔴 **Calling this at all is the availability signal.** A composition that
    /// calls it with `None` is saying *"I read head #3 and it holds nothing"*
    /// ([`DurableView::Nothing`]); a composition that never calls it reports
    /// [`DurableView::Unavailable`]. Those are different facts and this is the seam
    /// that keeps them apart — a node reporting `final=2864` beside a durable head of
    /// *nothing* is an alarm, and a node whose reader simply cannot see head #3 is
    /// not.
    pub fn with_durable_head(mut self, head: Option<(u64, Hash32)>) -> Self {
        self.durable = match head {
            Some((height, hash)) => DurableView::Head(DurableHead::new(height, &hash)),
            None => DurableView::Nothing,
        };
        self
    }

    /// **The one comparison of head #1 against head #3** — see [`DurableAgreement`]
    /// for the severities and for why this is not the cross-host verdict.
    ///
    /// Every consumer reads its verdict from here: the node's own surface, the
    /// `qumbra-opview` per-node row, and that tool's exit status. None of them can
    /// be checking a different condition than the others, which is the rule
    /// [`AppliedTip::off_main_chain`] and [`Self::supply_coverage`] already follow.
    pub fn durable_agreement(&self) -> DurableAgreement {
        match (self.finalized_height, self.durable) {
            (_, DurableView::Unavailable) => DurableAgreement::Unavailable,
            // Nothing finalized on either head: consistent, and the state every
            // fresh net boots into.
            (None, DurableView::Nothing) => DurableAgreement::Agreed,
            (None, DurableView::Head(d)) => {
                DurableAgreement::DurableAhead { tracker: None, durable: d.height }
            }
            (Some(t), DurableView::Nothing) => DurableAgreement::NothingDurable { tracker: t },
            (Some(t), DurableView::Head(d)) => match t.cmp(&d.height) {
                std::cmp::Ordering::Equal => DurableAgreement::Agreed,
                std::cmp::Ordering::Greater => {
                    DurableAgreement::TrackerAhead { tracker: t, durable: d.height }
                }
                std::cmp::Ordering::Less => {
                    DurableAgreement::DurableAhead { tracker: Some(t), durable: d.height }
                }
            },
        }
    }

    /// The `diff=` field: the tip block's difficulty, or `-` when unavailable.
    pub fn diff_field(&self) -> String {
        self.tip_difficulty.map(|d| d.to_string()).unwrap_or_else(|| "-".to_string())
    }

    /// The `age_s=` field: `-` while there is no finalized **checkpoint** to
    /// measure an age from, else [`Self::last_finalized_age_secs`].
    ///
    /// `-` covers two states an operator must not read a number in: nothing
    /// finalized at all (S8, PR #72), and the finalized head still genesis
    /// (issue #73) — the bootstrap finalization every fresh net starts from, which
    /// is not a checkpoint round and whose `timestamp = 0` placeholder is not a
    /// time. The rule keys on `finalized_height == Some(0)` rather than on the
    /// timestamp because height 0 IS genesis on every net, and height is what this
    /// wire carries — so the log line, `qumbra-opview` and any other reader derive
    /// the same `-` from the same snapshot (the #117 discipline).
    pub fn age_field(&self) -> String {
        match self.finalized_height {
            None | Some(0) => "-".to_string(),
            Some(_) => self.last_finalized_age_secs.to_string(),
        }
    }

    /// The `fid=` field: the finalized checkpoint's identity as the canonical
    /// 12-char lowercase hex, or `-` when absent — the same rendering as the
    /// `TELEMETRY` log line (#84), from the same helper.
    pub fn fid_field(&self) -> String {
        checkpoint_id_hex(self.finalized_id)
    }

    /// The `sslot=` field: the slot this node's keys last committed to, or `-`.
    pub fn sslot_field(&self) -> String {
        self.signed.map(|c| c.slot.to_string()).unwrap_or_else(|| "-".to_string())
    }

    /// The `sid=` field: the signed identity hex, `-` when this node holds no
    /// committee keys or has committed to nothing, or
    /// [`LOCAL_COMMITMENT_SPLIT`] when its own keys disagree.
    pub fn sid_field(&self) -> String {
        match self.signed {
            None => checkpoint_id_hex(None),
            Some(c) => c.id_field(),
        }
    }

    /// `version(0x04) ‖ finality(u8) ‖ tip(8 LE) ‖ has_final(u8) ‖
    /// [final_height(8 LE) if has] ‖ stall_depth(8) ‖ age_secs(8) ‖
    /// peer_count(8) ‖ mempool_size(8) ‖ epoch(8) ‖`
    /// `has_fid(u8) ‖ [finalized_id(8 LE) if has] ‖ has_signed(u8) ‖`
    /// `[signed_slot(8 LE) ‖ has_signed_id(u8) ‖ [signed_id(8 LE) if has] if has] ‖`
    /// `has_diff(u8) ‖ [tip_difficulty(8 LE) if has] ‖`
    /// `committee_size(8 LE) ‖ committee_active(8 LE) ‖ committee_quorum(8 LE) ‖`
    /// `n_supply(varint) ‖ n × (epoch ‖ start_height ‖ end_height ‖`
    /// `measured_coinbase ‖ expected_coinbase ‖ fees)` (all entry fields u64 LE) ‖`
    /// `durable_state(u8) ‖ [durable_height(8 LE) ‖ durable_id(8 LE) if state==2]`
    ///
    /// The `0x02` tail (issue #117) nests `sid` **inside** `sslot`'s presence, so
    /// "an identity with no slot" is not representable on the wire: a signed
    /// identity without the slot it was signed at is not a fact anyone can act on.
    ///
    /// The `0x04` tail (issue #212) is one **three-valued** discriminant and not a
    /// presence byte, for the same reason: `unavailable` (0), `nothing` (1) and a
    /// head (2) are three different facts, and a two-state presence byte would have
    /// forced two of them to share an encoding. An unknown discriminant is
    /// **rejected** exactly like an unknown finality status (§0), because a fourth
    /// state this build has never heard of must not be coerced into one of the
    /// three it has. The identity is a **block-hash** prefix
    /// ([`BlockIdentity`]) and is encoded in its own 8 LE bytes beside the height,
    /// never merged into `finalized_id`'s slot.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.push(match self.finality_status {
            FinalityStatus::Final => STATUS_FINAL,
            FinalityStatus::Degraded => STATUS_DEGRADED,
            FinalityStatus::Halting => STATUS_HALTING,
            FinalityStatus::Halted => STATUS_HALTED,
        });
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.stall_depth.to_le_bytes());
        out.extend_from_slice(&self.last_finalized_age_secs.to_le_bytes());
        out.extend_from_slice(&self.peer_count.to_le_bytes());
        out.extend_from_slice(&self.mempool_size.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        // ---- issue #117: the checkpoint-identity tail ----
        match self.finalized_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
            }
            None => out.push(0),
        }
        match self.signed {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.slot.to_le_bytes());
                match c.id {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(&id.to_le_bytes());
                    }
                    // The `split` state: this node's own keys are committed to two
                    // different variants at one slot, so there is no single identity
                    // to encode. Absent-with-a-slot IS the signal.
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
        match self.tip_difficulty {
            Some(d) => {
                out.push(1);
                out.extend_from_slice(&d.to_le_bytes());
            }
            None => out.push(0),
        }
        // ---- issue #121: publishable committee aggregates only --------------
        out.extend_from_slice(&self.committee_size.to_le_bytes());
        out.extend_from_slice(&self.committee_active.to_le_bytes());
        out.extend_from_slice(&self.committee_quorum.to_le_bytes());
        write_varint(&mut out, self.supply.len() as u64);
        for row in &self.supply {
            out.extend_from_slice(&row.epoch.to_le_bytes());
            out.extend_from_slice(&row.start_height.to_le_bytes());
            out.extend_from_slice(&row.end_height.to_le_bytes());
            out.extend_from_slice(&row.measured_coinbase.to_le_bytes());
            out.extend_from_slice(&row.expected_coinbase.to_le_bytes());
            out.extend_from_slice(&row.fees.to_le_bytes());
        }
        // ---- issue #212: head #3, the durable finalized head -----------------
        match self.durable {
            DurableView::Unavailable => out.push(DURABLE_UNAVAILABLE),
            DurableView::Nothing => out.push(DURABLE_NOTHING),
            DurableView::Head(h) => {
                out.push(DURABLE_HEAD);
                out.extend_from_slice(&h.height.to_le_bytes());
                // `bits()` is the escape hatch, and this is one of its two live
                // sites. It is a BLOCK-HASH prefix; it is not comparable to
                // `finalized_id` above and the type is what says so.
                out.extend_from_slice(&h.identity.bits().to_le_bytes());
            }
        }
        out
    }

    /// Decode a payload stamped with the **current** [`RPC_VERSION`], and nothing
    /// else.
    ///
    /// This is the strict path and it stays strict: an equality check on the version
    /// byte, exactly as §0 requires, so a stale reader against a new node or a new
    /// reader against a stale node fails loudly rather than returning a snapshot
    /// whose tail is silently absent. [`Telemetry::from_bytes_compat`] is the one
    /// caller-opt-in exception and it exists for a named, bounded reason.
    pub fn from_bytes(b: &[u8]) -> Result<Telemetry, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        Self::decode_body(&mut r, RPC_VERSION)
    }

    /// **Decode a payload stamped with any version in [`READABLE_TELEMETRY_VERSIONS`],
    /// and say which one it was** (issue #212).
    ///
    /// The version comes back because the caller needs it to render an *honest*
    /// absence. A `0x03` node carries no durable tail at all, so its snapshot decodes
    /// with [`DurableView::Unavailable`] — the same value a `0x04` node whose
    /// composition does not inject head #3 would report. Those are different facts
    /// (*"this host has not been rolled yet"* vs *"this reader cannot see head #3"*),
    /// the version byte is the only thing that separates them, and during a rolling
    /// upgrade the first one is the state of most of the net.
    ///
    /// Every other failure mode is unchanged: an unknown version, a truncated body
    /// and a trailing byte are all still errors.
    pub fn from_bytes_compat(b: &[u8]) -> Result<(u8, Telemetry), CodecError> {
        let mut r = Reader::new(b);
        let version = r.version_in(READABLE_TELEMETRY_VERSIONS)?;
        Ok((version, Self::decode_body(&mut r, version)?))
    }

    /// The body decoder, shared by both entry points so there is exactly one
    /// definition of the layout. `version` selects which tails are present — it is
    /// never inferred from the remaining length, because "parse what is there" is how
    /// a truncated body becomes a healthy-looking snapshot.
    fn decode_body(r: &mut Reader, version: u8) -> Result<Telemetry, CodecError> {
        let finality_status = match r.u8()? {
            STATUS_FINAL => FinalityStatus::Final,
            STATUS_DEGRADED => FinalityStatus::Degraded,
            STATUS_HALTING => FinalityStatus::Halting,
            STATUS_HALTED => FinalityStatus::Halted,
            // Unknown finality discriminant: reject rather than silently coerce
            // (§0 reject-unknown, applied to the status byte as well).
            got => return Err(CodecError::BadVersion { got }),
        };
        let tip_height = r.u64()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let stall_depth = r.u64()?;
        let last_finalized_age_secs = r.u64()?;
        let peer_count = r.u64()?;
        let mempool_size = r.u64()?;
        let epoch = r.u64()?;
        // ---- issue #117: the checkpoint-identity tail ----
        let finalized_id = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let signed = if r.u8()? == 1 {
            let slot = r.u64()?;
            let id = if r.u8()? == 1 { Some(r.u64()?) } else { None };
            Some(LocalCommitment { slot, id })
        } else {
            None
        };
        let tip_difficulty = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let committee_size = r.u64()?;
        let committee_active = r.u64()?;
        let committee_quorum = r.u64()?;
        let n_supply = r.varint()?;
        // Do not preallocate from an untrusted count. A truncated/malicious body
        // fails on the first absent field without turning its varint into a memory
        // allocation request.
        let mut supply = Vec::new();
        for _ in 0..n_supply {
            supply.push(SupplyEpoch {
                epoch: r.u64()?,
                start_height: r.u64()?,
                end_height: r.u64()?,
                measured_coinbase: r.u64()?,
                expected_coinbase: r.u64()?,
                fees: r.u64()?,
                burned: 0,
            });
        }
        // ---- issue #212: head #3 -----------------------------------------------
        // Absent below 0x04, and that absence is carried by the VERSION the caller
        // was handed, not by this value: `Unavailable` here means "this snapshot
        // does not state a durable head", which is true of a 0x03 payload and of a
        // 0x04 composition that does not inject one.
        let durable = if version >= DURABLE_HEAD_SINCE_VERSION {
            match r.u8()? {
                DURABLE_UNAVAILABLE => DurableView::Unavailable,
                DURABLE_NOTHING => DurableView::Nothing,
                DURABLE_HEAD => {
                    let height = r.u64()?;
                    DurableView::Head(DurableHead {
                        height,
                        identity: BlockIdentity::from_bits(r.u64()?),
                    })
                }
                // Reject rather than coerce (§0 reject-unknown, applied to this
                // discriminant as it already is to the finality status byte).
                got => return Err(CodecError::BadVersion { got }),
            }
        } else {
            DurableView::Unavailable
        };
        r.finish()?;
        Ok(Telemetry {
            finality_status,
            tip_height,
            finalized_height,
            stall_depth,
            last_finalized_age_secs,
            peer_count,
            mempool_size,
            epoch,
            committee_size,
            committee_active,
            committee_quorum,
            supply,
            finalized_id,
            signed,
            tip_difficulty,
            durable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS as MAX_LAG;

    #[test]
    fn telemetry_roundtrips_both_regimes() {
        // Within lag ⇒ Final.
        let t = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        assert_eq!(t.finality_status, FinalityStatus::Final);
        assert_eq!(t.stall_depth, 4);
        assert_eq!(Telemetry::from_bytes(&t.to_bytes()).unwrap(), t);

        // Lag beyond threshold ⇒ Degraded (the stall the runbook fires on).
        let d = Telemetry::assemble(100, Some(8), 6900, 2, 5, 1, MAX_LAG);
        assert_eq!(d.finality_status, FinalityStatus::Degraded);
        assert_eq!(d.stall_depth, 92);
        assert_eq!(Telemetry::from_bytes(&d.to_bytes()).unwrap(), d);

        // Nothing finalized ⇒ Degraded, depth = tip, no finalized height.
        let n = Telemetry::assemble(5, None, 200, 0, 1, 0, MAX_LAG);
        assert_eq!(n.finality_status, FinalityStatus::Degraded);
        assert_eq!(n.stall_depth, 5);
        assert_eq!(n.finalized_height, None);
        assert_eq!(Telemetry::from_bytes(&n.to_bytes()).unwrap(), n);
    }

    /// Issue #73: `age_field` is the one rendering rule for `age_s=`, and it
    /// refuses to state an age in BOTH no-checkpoint states — nothing finalized
    /// (S8) and finalized-at-genesis — while a real finalized height renders the
    /// number. The wire encoding is untouched: the same fields round-trip, only
    /// the value carried while the head is genesis changes.
    #[test]
    fn age_field_is_dash_until_a_real_checkpoint_finalizes() {
        // Nothing finalized (S8): `-`.
        let none = Telemetry::assemble(5, None, 0, 0, 1, 0, MAX_LAG);
        assert_eq!(none.age_field(), "-");

        // Finalized head still genesis (#73): `-`, never a number — this is the
        // state every fresh net boots into (`final=0` until slot 8 finalizes).
        let genesis = Telemetry::assemble(1, Some(0), 0, 0, 1, 0, MAX_LAG);
        assert_eq!(genesis.age_field(), "-");
        assert_eq!(Telemetry::from_bytes(&genesis.to_bytes()).unwrap(), genesis);

        // First non-genesis checkpoint: the field speaks, in chain-time seconds.
        let real = Telemetry::assemble(10, Some(8), 150, 0, 1, 0, MAX_LAG);
        assert_eq!(real.age_field(), "150");
    }

    /// Issue #74: the halt regimes ride the SAME status field (extended, not
    /// forked), round-trip on the wire, and are derived from the halt rule rather
    /// than re-defined here.
    #[test]
    fn telemetry_roundtrips_halting_and_halted() {
        const H: u64 = 16;
        // Tip at H, H not finalized yet ⇒ Halting.
        let halting = Telemetry::assemble_with_halt(H, Some(8), 600, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(halting.finality_status, FinalityStatus::Halting);
        assert_eq!(Telemetry::from_bytes(&halting.to_bytes()).unwrap(), halting);
        assert_eq!(halting.to_bytes()[1], STATUS_HALTING);

        // H finalized ⇒ Halted, stall depth 0 (the boundary IS the tip).
        let halted = Telemetry::assemble_with_halt(H, Some(H), 0, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(halted.finality_status, FinalityStatus::Halted);
        assert_eq!(halted.stall_depth, 0);
        assert_eq!(Telemetry::from_bytes(&halted.to_bytes()).unwrap(), halted);
        assert_eq!(halted.to_bytes()[1], STATUS_HALTED);

        // Below H the halt does not govern — ordinary Ebb-and-Flow.
        let pre = Telemetry::assemble_with_halt(10, Some(8), 150, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(pre.finality_status, FinalityStatus::Final);

        // A node with no halt scheduled is byte-identical to the pre-#74 surface.
        let a = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        let b = Telemetry::assemble_with_halt(20, Some(16), 300, 3, 7, 1, MAX_LAG, None);
        assert_eq!(a, b);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn telemetry_rejects_bad_version_and_trailing_and_bad_status() {
        let t = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        let good = t.to_bytes();

        // Unknown version byte.
        let mut bad_ver = good.clone();
        bad_ver[0] = 9;
        assert!(matches!(
            Telemetry::from_bytes(&bad_ver),
            Err(CodecError::BadVersion { got: 9 })
        ));

        // Unknown finality-status discriminant (byte 1).
        let mut bad_status = good.clone();
        bad_status[1] = 9;
        assert!(matches!(
            Telemetry::from_bytes(&bad_status),
            Err(CodecError::BadVersion { got: 9 })
        ));

        // Trailing byte.
        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(
            Telemetry::from_bytes(&extra),
            Err(CodecError::TrailingBytes { .. })
        ));

        // Truncation.
        assert!(Telemetry::from_bytes(&good[..good.len() - 1]).is_err());
    }

    // ---- issue #117: the checkpoint-identity tail ---------------------------

    /// The pre-#117 `0x01` encoding, hand-rolled. This is what a node built before
    /// this change emits and what a reader built before it expects — kept here as a
    /// literal so the rejection test cannot drift with the encoder it is testing.
    fn v1_payload(t: &Telemetry) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x01);
        out.push(match t.finality_status {
            FinalityStatus::Final => STATUS_FINAL,
            FinalityStatus::Degraded => STATUS_DEGRADED,
            FinalityStatus::Halting => STATUS_HALTING,
            FinalityStatus::Halted => STATUS_HALTED,
        });
        out.extend_from_slice(&t.tip_height.to_le_bytes());
        match t.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&t.stall_depth.to_le_bytes());
        out.extend_from_slice(&t.last_finalized_age_secs.to_le_bytes());
        out.extend_from_slice(&t.peer_count.to_le_bytes());
        out.extend_from_slice(&t.mempool_size.to_le_bytes());
        out.extend_from_slice(&t.epoch.to_le_bytes());
        out
    }

    /// `Telemetry` keeps the #117 identity states intact at the current version:
    /// absent, present, and the `split` case where a node's own keys are committed
    /// to two variants at one slot.
    #[test]
    fn telemetry_roundtrips_checkpoint_identity_at_0x05() {
        let base = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 2, MAX_LAG);

        // Nothing injected: the composition cannot see the identity. Fields render
        // as absent, exactly like the `TELEMETRY` log line's `-`.
        assert_eq!(base.finalized_id, None);
        assert_eq!(base.signed, None);
        assert_eq!(base.fid_field(), "-");
        assert_eq!(base.sslot_field(), "-");
        assert_eq!(base.sid_field(), "-");
        assert_eq!(Telemetry::from_bytes(&base.to_bytes()).unwrap(), base);
        assert_eq!(base.to_bytes()[0], RPC_VERSION);
        assert_eq!(RPC_VERSION, 0x05, "the issue #275 route bump (payload unchanged from #212's 0x04)");

        // Fully populated: finalized identity + this node's own signed variant.
        let full = base
            .clone()
            .with_checkpoint(Some(0x3f1a_9c2b_0d41), Some(LocalCommitment { slot: 3776, id: Some(0x3f1a_9c2b_0d41) }))
            .with_tip_difficulty(Some(1_048_576));
        assert_eq!(full.diff_field(), "1048576");
        assert_eq!(base.diff_field(), "-", "absent until injected");
        assert_eq!(full.fid_field(), "3f1a9c2b0d41");
        assert_eq!(full.sslot_field(), "3776");
        assert_eq!(full.sid_field(), "3f1a9c2b0d41");
        assert_eq!(Telemetry::from_bytes(&full.to_bytes()).unwrap(), full);

        // The split: a slot, and deliberately no identity for it.
        let split = base
            .clone()
            .with_checkpoint(Some(0x3f1a_9c2b_0d41), Some(LocalCommitment { slot: 3776, id: None }));
        assert_eq!(split.sslot_field(), "3776");
        assert_eq!(split.sid_field(), LOCAL_COMMITMENT_SPLIT);
        assert_eq!(Telemetry::from_bytes(&split.to_bytes()).unwrap(), split);

        // A verify-only node: it finalized something, but holds no keys, so it has
        // signed nothing. Distinct on the wire from the split above.
        let verify_only = base.clone().with_checkpoint(Some(0x3f1a_9c2b_0d41), None);
        assert_eq!(verify_only.sslot_field(), "-");
        assert_eq!(verify_only.sid_field(), "-");
        assert_eq!(Telemetry::from_bytes(&verify_only.to_bytes()).unwrap(), verify_only);
        assert_ne!(
            verify_only.to_bytes(),
            split.to_bytes(),
            "`no keys` and `my keys disagree` must not encode alike — one is fine and one is a finding"
        );
    }

    /// **Acceptance (#121, re-pinned at `0x04` by #212 and at `0x05` by #275):
    /// committee aggregates round-trip at the current version, while an older wire
    /// is rejected on its version byte by the STRICT decoder.**
    #[test]
    fn committee_aggregates_roundtrip_at_0x05_and_older_is_rejected() {
        let t = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 3, MAX_LAG)
            .with_committee(21, 19, 15)
            .with_supply(vec![SupplyEpoch {
                epoch: 3,
                start_height: 3456,
                end_height: 3776,
                measured_coinbase: 1_234_567,
                expected_coinbase: 1_234_567,
                fees: 890,
                burned: 0,
            }]);
        let bytes = t.to_bytes();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(Telemetry::from_bytes(&bytes).unwrap(), t);
        assert_eq!(
            (t.epoch, t.committee_size, t.committee_active, t.committee_quorum),
            (3, 21, 19, 15),
        );
        assert_eq!(t.supply.len(), 1);
        assert_eq!(t.supply[0].divergence_bessel(), 0);
        assert_eq!(t.supply_coverage(), SupplyCoverage::Complete);

        // The strict decoder refuses EVERY older version, including the `0x03` and
        // `0x04` the compat decoder now knowingly reads. Those are different paths
        // on purpose and this is the line that keeps them from converging (#212).
        for old_version in [0x01u8, 0x02, 0x03, 0x04] {
            let mut old = bytes.clone();
            old[0] = old_version;
            assert!(
                matches!(
                    Telemetry::from_bytes(&old),
                    Err(CodecError::BadVersion { got }) if got == old_version
                ),
                "the strict decoder must reject 0x{old_version:02x}"
            );
        }
    }

    #[test]
    fn supply_coverage_refuses_a_state_tip_behind_fork_choice_without_a_wire_change() {
        let partial = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG)
            .with_supply(vec![SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 4,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
                burned: 0,
            }]);
        assert_eq!(
            partial.supply_coverage(),
            SupplyCoverage::Unavailable {
                state_tip: Some(4),
                fork_choice_tip: 14,
            }
        );

        let decoded = Telemetry::from_bytes(&partial.to_bytes()).unwrap();
        assert_eq!(decoded.supply_coverage(), partial.supply_coverage());
        assert_eq!(decoded.to_bytes()[0], 0x05, "coverage uses fields already on the wire");
    }

    /// **Acceptance (#130 (a)): `SupplyCoverage` and the state-lag figures are one
    /// comparison, not two.**
    ///
    /// #126 already derived "the applied ledger does not reach fork choice" here.
    /// (a) needs the same comparison as a number on `TELEMETRY` and `/metrics`, and
    /// this repo has ruled derive-don't-restate three times in one week (#116, #102,
    /// #125). So [`StateLag`] is the single definition and `supply_coverage` is
    /// expressed in terms of it — this test fails if either grows its own copy.
    #[test]
    fn supply_coverage_and_state_lag_are_the_same_comparison() {
        let partial = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG).with_supply(vec![
            SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 4,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
                burned: 0,
            },
        ]);
        let lag = StateLag::new(4, 14);
        assert_eq!(lag.blocks(), 10);
        assert!(lag.is_lagging());
        // The coverage verdict is the lag verdict, on the same two heights.
        assert_eq!(partial.supply_lag(), Some(lag));
        assert_eq!(
            partial.supply_coverage(),
            SupplyCoverage::Unavailable { state_tip: Some(4), fork_choice_tip: 14 }
        );

        // Agreement is a zero lag, and vice versa — one predicate, both readings.
        let complete = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG).with_supply(vec![
            SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 14,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
                burned: 0,
            },
        ]);
        assert_eq!(complete.supply_lag(), Some(StateLag::new(14, 14)));
        assert!(!complete.supply_lag().unwrap().is_lagging());
        assert_eq!(complete.supply_coverage(), SupplyCoverage::Complete);

        // No ledger rows ⇒ no lag can be computed, and coverage is Unavailable for
        // that reason rather than for a disagreement. The two are different facts.
        let no_rows = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG);
        assert_eq!(no_rows.supply_lag(), None);
        assert_eq!(
            no_rows.supply_coverage(),
            SupplyCoverage::Unavailable { state_tip: None, fork_choice_tip: 14 }
        );
    }

    /// A state tip can never exceed fork choice (fork choice is where headers land
    /// first), and if arithmetic ever says otherwise the answer is zero rather than
    /// an underflow — the `saturating_sub` discipline #73/#87 already apply to every
    /// other derived gap on this surface.
    #[test]
    fn state_lag_never_underflows_and_zero_is_not_lagging() {
        assert_eq!(StateLag::new(14, 4).blocks(), 0);
        assert!(!StateLag::new(14, 4).is_lagging());
        assert_eq!(StateLag::new(0, 0).blocks(), 0);
        assert!(!StateLag::new(0, 0).is_lagging());
        assert!(StateLag::new(0, 1).is_lagging());
    }

    // ---- issue #162 finding 6: the applied tip's identity and the detector ----

    fn h(first: u8) -> Hash32 {
        let mut out = [0xee; 32];
        out[0] = first;
        out
    }

    /// **`stipid` is `fid`'s scheme applied to a block, not a second one.** Same
    /// width, same fold, same renderer — and the value is the block hash's own
    /// prefix rather than a re-hash, so an operator lining `stipid=` up against a
    /// block hash from any other tool sees the same digits.
    #[test]
    fn the_applied_tip_identity_is_the_block_hashs_prefix_at_fids_width() {
        let hash = h(0x01);
        let tip = AppliedTip::new(1, hash, Some(hash));
        assert_eq!(tip.identity().bits(), 0x01ee_eeee_eeee, "the first 6 bytes, big-endian");
        assert_eq!(tip.id_field(), "01eeeeeeeeee");
        assert_eq!(tip.id_field().len(), checkpoint_id_hex(Some(0)).len(), "fid's width");
        // Two blocks differing only outside the prefix are NOT separated — a 48-bit
        // identity is a display width, and this states the collision bound honestly
        // rather than implying the field is a hash comparison.
        let mut far = hash;
        far[31] ^= 0xff;
        assert_eq!(AppliedTip::new(1, far, Some(far)).identity(), tip.identity());
        // Two blocks differing inside it are.
        assert_ne!(AppliedTip::new(1, h(0x02), Some(h(0x02))).identity(), tip.identity());
    }

    /// **The detector, and the third answer.** `schain=` fires only on a genuine
    /// mismatch: `main` when the applied tip IS the main-chain block at its height
    /// (however far behind fork choice it is), `fork` when it is not, and `-` when
    /// there is no main-chain block at that height to compare against — because an
    /// alarm must not fire on the absence of evidence, and an unmade comparison must
    /// not print as healthy either.
    #[test]
    fn the_wedge_verdict_separates_lagging_from_stranded_and_refuses_to_guess() {
        let mine = h(0x01);
        let theirs = h(0x02);

        let on_main = AppliedTip::new(1, mine, Some(mine));
        assert_eq!(on_main.off_main_chain(), Some(false));
        assert!(!on_main.is_off_main_chain());
        assert_eq!(on_main.chain_field(), APPLIED_TIP_ON_MAIN);

        let stranded = AppliedTip::new(1, mine, Some(theirs));
        assert_eq!(stranded.off_main_chain(), Some(true));
        assert!(stranded.is_off_main_chain());
        assert_eq!(stranded.chain_field(), APPLIED_TIP_OFF_MAIN);

        let unjudgeable = AppliedTip::new(1, mine, None);
        assert_eq!(unjudgeable.off_main_chain(), None);
        assert!(!unjudgeable.is_off_main_chain(), "no evidence is not an alarm");
        assert_eq!(unjudgeable.chain_field(), CHECKPOINT_ID_ABSENT);

        // The three tokens are distinguishable and none is a prefix of another, so a
        // `qumbra-ops/` parser cannot match `main` inside anything else.
        let tokens = [APPLIED_TIP_ON_MAIN, APPLIED_TIP_OFF_MAIN, CHECKPOINT_ID_ABSENT];
        for (i, a) in tokens.iter().enumerate() {
            for (j, b) in tokens.iter().enumerate() {
                assert_eq!(i == j, a == b, "{a} vs {b}");
            }
        }
    }

    /// **`slag=` and `schain=` are independent, which is the entire finding.** The
    /// height gap says nothing about which branch the state machine is on, and the
    /// branch says nothing about the gap — all four combinations are reachable and
    /// each is a different operator instruction.
    #[test]
    fn the_lag_and_the_branch_are_orthogonal() {
        let mine = h(0x01);
        let theirs = h(0x02);
        // Healthy: caught up, on the main chain.
        assert_eq!(StateLag::new(3, 3).blocks(), 0);
        assert_eq!(AppliedTip::new(3, mine, Some(mine)).chain_field(), APPLIED_TIP_ON_MAIN);
        // Lagging but sound — wait, it converges when the bodies arrive.
        assert_eq!(StateLag::new(0, 3).blocks(), 3);
        assert_eq!(AppliedTip::new(0, mine, Some(mine)).chain_field(), APPLIED_TIP_ON_MAIN);
        // Wedged — same nonzero `slag=`, opposite response. This pair printed
        // identically before this field existed, and that is what cost an afternoon.
        assert_eq!(StateLag::new(1, 3).blocks(), 2);
        assert_eq!(AppliedTip::new(1, mine, Some(theirs)).chain_field(), APPLIED_TIP_OFF_MAIN);
        // And the fourth corner: a zero gap over a disagreeing block. Not reachable
        // through `NodeAdapter` today (fork choice's tip IS the applied block there),
        // but the verdict must not be derived from the gap, so it is asserted.
        assert_eq!(StateLag::new(3, 3).blocks(), 0);
        assert_eq!(AppliedTip::new(3, mine, Some(theirs)).chain_field(), APPLIED_TIP_OFF_MAIN);
    }

    /// **Acceptance (#117): a `0x01` payload is REJECTED, not best-effort parsed.**
    ///
    /// This is the property the version byte exists for. A stale reader against a
    /// new node, or a new reader against a stale node, must fail loudly rather than
    /// return a snapshot whose identity half is silently absent — which would read
    /// exactly like "this node finalized nothing", the healthiest-looking possible
    /// rendering of an unknown.
    #[test]
    fn a_v1_telemetry_payload_is_rejected_not_best_effort_parsed() {
        let t = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 2, MAX_LAG);
        let old = v1_payload(&t);

        // The old encoding is genuinely the prefix of the new one — i.e. the failure
        // mode being guarded against is real and not hypothetical.
        assert_eq!(&t.to_bytes()[1..old.len()], &old[1..], "v2 appends, it does not reshuffle");
        assert!(t.to_bytes().len() > old.len());

        assert!(
            matches!(Telemetry::from_bytes(&old), Err(CodecError::BadVersion { got: 1 })),
            "a 0x01 payload must be rejected on the version byte"
        );

        // And the tail is not optional: a current-version-stamped payload that
        // stops where v1 stopped is truncated, not "current with the tail absent".
        let mut stamped = old.clone();
        stamped[0] = RPC_VERSION;
        assert!(
            matches!(Telemetry::from_bytes(&stamped), Err(CodecError::Truncated { .. })),
            "the versioned tails are mandatory at the current version"
        );
        // …and the compat decoder does not weaken that. `0x01` is not in the readable
        // set, so it is refused by both paths (issue #212).
        assert!(
            matches!(Telemetry::from_bytes_compat(&old), Err(CodecError::BadVersion { got: 1 })),
            "the compat path is a NAMED SET, not a `>=` comparison"
        );
    }

    // ---- issue #212: head #3, the durable finalized head ---------------------

    /// The `0x03` payload of `t`, hand-rolled: the current encoding minus the
    /// durable-head tail, stamped `0x03`.
    ///
    /// Built by *construction* rather than by truncating `to_bytes()` at a computed
    /// offset, so the fixture cannot drift into agreement with the encoder it is
    /// testing — the same reason [`v1_payload`] is a literal.
    fn v3_payload(t: &Telemetry) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x03);
        out.push(match t.finality_status {
            FinalityStatus::Final => STATUS_FINAL,
            FinalityStatus::Degraded => STATUS_DEGRADED,
            FinalityStatus::Halting => STATUS_HALTING,
            FinalityStatus::Halted => STATUS_HALTED,
        });
        out.extend_from_slice(&t.tip_height.to_le_bytes());
        match t.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&t.stall_depth.to_le_bytes());
        out.extend_from_slice(&t.last_finalized_age_secs.to_le_bytes());
        out.extend_from_slice(&t.peer_count.to_le_bytes());
        out.extend_from_slice(&t.mempool_size.to_le_bytes());
        out.extend_from_slice(&t.epoch.to_le_bytes());
        match t.finalized_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
            }
            None => out.push(0),
        }
        match t.signed {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.slot.to_le_bytes());
                match c.id {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(&id.to_le_bytes());
                    }
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
        match t.tip_difficulty {
            Some(d) => {
                out.push(1);
                out.extend_from_slice(&d.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&t.committee_size.to_le_bytes());
        out.extend_from_slice(&t.committee_active.to_le_bytes());
        out.extend_from_slice(&t.committee_quorum.to_le_bytes());
        write_varint(&mut out, t.supply.len() as u64);
        for row in &t.supply {
            out.extend_from_slice(&row.epoch.to_le_bytes());
            out.extend_from_slice(&row.start_height.to_le_bytes());
            out.extend_from_slice(&row.end_height.to_le_bytes());
            out.extend_from_slice(&row.measured_coinbase.to_le_bytes());
            out.extend_from_slice(&row.expected_coinbase.to_le_bytes());
            out.extend_from_slice(&row.fees.to_le_bytes());
        }
        out
    }

    fn with_durable(t: Telemetry, head: Option<(u64, u8)>) -> Telemetry {
        t.with_durable_head(head.map(|(height, first)| (height, h(first))))
    }

    /// **Acceptance (#212 A): the three durable states are three distinct encodings,
    /// and each round-trips.**
    ///
    /// `unavailable` (this reader cannot see head #3) and `nothing` (head #3 holds
    /// nothing) must not encode alike — one is a fact about the plumbing and the
    /// other, beside a real `final=`, is an alarm. This is `#117`'s
    /// `no keys` vs `my keys disagree` assertion applied to head #3.
    #[test]
    fn the_three_durable_states_are_distinct_on_the_wire_and_round_trip() {
        let base = Telemetry::assemble(2871, Some(2864), 75, 0, 3, 2, MAX_LAG);

        // Not injected at all: this composition does not read head #3.
        assert_eq!(base.durable, DurableView::Unavailable);
        assert_eq!(base.durable.height_field(), "-");
        assert_eq!(base.durable.id_field(), "-");
        assert!(!base.durable.is_available());
        assert_eq!(Telemetry::from_bytes(&base.to_bytes()).unwrap(), base);

        // Injected, and head #3 holds nothing.
        let nothing = with_durable(base.clone(), None);
        assert_eq!(nothing.durable, DurableView::Nothing);
        assert!(nothing.durable.is_available());
        assert_eq!(nothing.durable.height_field(), "-", "`dfin=`'s vocabulary, unchanged");
        assert_eq!(nothing.durable.id_field(), "-");
        assert_eq!(Telemetry::from_bytes(&nothing.to_bytes()).unwrap(), nothing);

        // Injected, and head #3 holds a block.
        let head = with_durable(base.clone(), Some((2864, 0xa1)));
        assert_eq!(head.durable.height_field(), "2864");
        assert_eq!(head.durable.id_field(), "a1eeeeeeeeee");
        assert_eq!(head.durable.head().unwrap().height, 2864);
        assert_eq!(Telemetry::from_bytes(&head.to_bytes()).unwrap(), head);

        // All three are different bytes. `unavailable` vs `nothing` is the pair that
        // matters and it is asserted explicitly.
        assert_ne!(
            base.to_bytes(),
            nothing.to_bytes(),
            "`I cannot see head #3` and `head #3 holds nothing` must not encode alike"
        );
        assert_ne!(nothing.to_bytes(), head.to_bytes());

        // A fourth discriminant this build has never heard of is REJECTED, not
        // coerced into one of the three (§0, as for the finality status byte).
        let mut bad = head.to_bytes();
        let tail = bad.len() - 17;
        bad[tail] = 9;
        bad.truncate(tail + 1);
        assert!(matches!(
            Telemetry::from_bytes(&bad),
            Err(CodecError::BadVersion { got: 9 })
        ));
    }

    /// **Acceptance (#212 B): a block identity is not a checkpoint identity, and it
    /// is the same block-hash prefix `stipid=` publishes.**
    ///
    /// The 🔴 trap in one test. The two values render at one width through one
    /// helper — which is why they must not be compared — and
    /// `BlockIdentity`'s missing `PartialEq<u64>` is what makes the comparison a
    /// compile error rather than a plausible line of code. That half cannot be
    /// asserted at runtime, so what is asserted here is the *other* half: the value
    /// really is the block hash's own prefix and really is NOT what
    /// `Checkpoint::identity` would produce for the same block.
    #[test]
    fn the_durable_identity_is_a_block_hash_prefix_and_not_a_checkpoint_identity() {
        let hash = h(0xa1);
        let height = 2864u64;
        let durable = DurableHead::new(height, &hash);

        // It is the block hash's own first 6 bytes, taken directly.
        let expected: String = hash[..CHECKPOINT_ID_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(durable.identity.field(), expected);
        // …i.e. exactly what `stipid=` publishes for the same block, one scheme.
        assert_eq!(durable.identity, AppliedTip::new(height, hash, Some(hash)).identity());

        // And NOT the checkpoint identity of the checkpoint that finalized it. The
        // committee signs `height ‖ block_hash ‖ root`; a block hash is the name of a
        // block. Same width, different space — comparing them is meaningless, and
        // this is the line that says so with numbers.
        let cp = qlab_devnet::committee::Checkpoint::new(height, hash, hash);
        assert_ne!(
            durable.identity.bits(),
            cp.identity(),
            "if these were ever equal the trap would be invisible"
        );
        assert_eq!(
            durable.identity.field().len(),
            cp.id_hex().len(),
            "they are the same WIDTH, which is exactly why the type has to keep them apart"
        );
    }

    /// **Acceptance (#212 C): the single-node comparison of head #1 against head #3,
    /// including the 2026-08-01 node1 reading exactly.**
    #[test]
    fn the_tracker_and_the_durable_head_are_compared_in_one_place() {
        let t = |fin: Option<u64>, durable: Option<Option<(u64, u8)>>| {
            let base = Telemetry::assemble(1100, fin, 75, 0, 3, 0, MAX_LAG);
            match durable {
                None => base,
                Some(d) => with_durable(base, d),
            }
        };

        // 🔴 The reading this issue exists for: node1, 2026-08-01. `final=1056`
        // over a durable head of 1048, for hours, and opview reported four-way
        // agreement the whole time.
        let node1 = t(Some(1056), Some(Some((1048, 0xfa))));
        assert_eq!(
            node1.durable_agreement(),
            DurableAgreement::TrackerAhead { tracker: 1056, durable: 1048 }
        );
        assert!(node1.durable_agreement().is_divergent());
        assert_eq!(node1.durable_agreement().token(), Some("DURABLE_LAG"));

        // The healthy T0 reading (all four hosts, 2026-08-03 07:11:27Z):
        // `final=2864 dfin=2864`.
        let healthy = t(Some(2864), Some(Some((2864, 0x63))));
        assert_eq!(healthy.durable_agreement(), DurableAgreement::Agreed);
        assert!(!healthy.durable_agreement().is_divergent());
        assert_eq!(healthy.durable_agreement().token(), None);

        // Head #3 holds NOTHING while head #1 reports a height: a restart returns to
        // genesis. Its own variant, because "2864 vs nothing" and "1056 vs 1048" are
        // different magnitudes of the same failure.
        let absent = t(Some(2864), Some(None));
        assert_eq!(
            absent.durable_agreement(),
            DurableAgreement::NothingDurable { tracker: 2864 }
        );
        assert_eq!(absent.durable_agreement().token(), Some("DURABLE_ABSENT"));

        // Nothing finalized on either head: consistent, and the state every fresh
        // net boots into. Not an alarm.
        let cold = t(None, Some(None));
        assert_eq!(cold.durable_agreement(), DurableAgreement::Agreed);
        assert_eq!(cold.durable_agreement().token(), None);

        // Head #3 ahead. Unreachable by construction today (head #1 is re-derived
        // from head #3 at `open`), and distinguished so that observing it points at
        // this code rather than at the net.
        let ahead = t(Some(1048), Some(Some((1056, 0x11))));
        assert_eq!(
            ahead.durable_agreement(),
            DurableAgreement::DurableAhead { tracker: Some(1048), durable: 1056 }
        );
        assert_eq!(ahead.durable_agreement().token(), Some("DURABLE_AHEAD"));
        let blind_tracker = t(None, Some(Some((1056, 0x11))));
        assert_eq!(
            blind_tracker.durable_agreement(),
            DurableAgreement::DurableAhead { tracker: None, durable: 1056 }
        );

        // 🔴 And the refusal: a composition that cannot see head #3 is NOT agreement
        // and NOT disagreement. An alarm must not fire on the absence of evidence,
        // and an unmade comparison must not print as healthy.
        let unavailable = t(Some(1056), None);
        assert_eq!(unavailable.durable_agreement(), DurableAgreement::Unavailable);
        assert!(!unavailable.durable_agreement().is_divergent());
        assert_eq!(unavailable.durable_agreement().token(), None);
    }

    /// **Acceptance (#212 D — the roll, extended by #275): a current reader can
    /// still read a `0x03` or `0x04` node, and is told that is what it read.**
    ///
    /// This is the whole answer to the roll problem. T0 rolls one host at a time and
    /// the last roll took 23 minutes; without this, an `opview` built at the current
    /// version would read *nothing* from the un-rolled hosts for that whole window,
    /// and its verdict is cross-host agreement — which an instrument seeing two of
    /// four hosts cannot answer. The version comes back so an absent durable head can
    /// be attributed to the wire rather than reported as a fact about the chain.
    #[test]
    fn a_current_reader_still_reads_a_0x03_or_0x04_node_and_knows_that_it_did() {
        let live = with_durable(
            Telemetry::assemble(2871, Some(2864), 75, 0, 3, 2, MAX_LAG)
                .with_committee(21, 21, 15)
                .with_checkpoint(Some(0x63e4_2f7e_13a7), None),
            Some((2864, 0x63)),
        );

        // The rolled host: full fidelity, and the version says so.
        let (v, rolled) = Telemetry::from_bytes_compat(&live.to_bytes()).unwrap();
        assert_eq!(v, 0x05);
        assert_eq!(rolled, live);
        assert!(rolled.durable.is_available());

        // A `0x04` host (issue #275: the route bump changed no payload byte, so the
        // `0x04` body is the `0x05` body): full fidelity too, attributed to `0x04`.
        let mut v4 = live.to_bytes();
        v4[0] = 0x04;
        let (v_mid, host_0x04) = Telemetry::from_bytes_compat(&v4).unwrap();
        assert_eq!(v_mid, 0x04);
        assert_eq!(host_0x04, live);
        assert!(host_0x04.durable.is_available(), "0x04 already carried the durable tail");

        // The un-rolled host: everything `0x03` carried is still read, and the
        // durable head is absent — attributably so.
        let old = v3_payload(&live);
        let (v_old, unrolled) = Telemetry::from_bytes_compat(&old).unwrap();
        assert_eq!(v_old, 0x03);
        assert!(v_old < DURABLE_HEAD_SINCE_VERSION, "this wire predates the field");
        assert_eq!(unrolled.finalized_height, Some(2864), "the pre-existing fields still read");
        assert_eq!(unrolled.fid_field(), "63e42f7e13a7");
        assert_eq!(unrolled.committee_size, 21);
        assert_eq!(unrolled.durable, DurableView::Unavailable);
        assert_eq!(unrolled.durable_agreement(), DurableAgreement::Unavailable);

        // 🔴 The strict decoder is UNCHANGED: `0x03` is refused there. The compat
        // window is a caller's explicit opt-in, not a property of the wire.
        assert!(matches!(
            Telemetry::from_bytes(&old),
            Err(CodecError::BadVersion { got: 3 })
        ));

        // The readable set is bounded and named, and it is not a `>=` comparison:
        // `0x02` and an unknown future `0x06` are both refused by BOTH paths.
        assert_eq!(READABLE_TELEMETRY_VERSIONS, &[0x03, 0x04, 0x05]);
        for refused in [0x00u8, 0x01, 0x02, 0x06, 0xff] {
            let mut bytes = live.to_bytes();
            bytes[0] = refused;
            assert!(
                matches!(
                    Telemetry::from_bytes_compat(&bytes),
                    Err(CodecError::BadVersion { got }) if got == refused
                ),
                "0x{refused:02x} must not be readable"
            );
        }

        // Truncation and trailing bytes are still errors on the compat path — the
        // relaxation is the version byte and nothing else.
        assert!(Telemetry::from_bytes_compat(&old[..old.len() - 1]).is_err());
        let mut extra = old.clone();
        extra.push(0);
        assert!(matches!(
            Telemetry::from_bytes_compat(&extra),
            Err(CodecError::TrailingBytes { .. })
        ));
    }

    /// **The `0x03` payload really is the prefix of the current one** — the durable
    /// tail `0x04` appended, and nothing before it moved (`0x05` changed no payload
    /// byte at all, issue #275).
    ///
    /// This is the field-discipline check for this bump, in bytes: `PRE_I84_FIELDS`
    /// protects the log line, and this protects the wire. If a future edit inserts a
    /// field anywhere but the end, this fails before any consumer notices.
    #[test]
    fn the_0x04_wire_appends_and_does_not_reshuffle() {
        let t = with_durable(
            Telemetry::assemble(2871, Some(2864), 75, 4, 3, 2, MAX_LAG)
                .with_committee(21, 21, 15)
                .with_checkpoint(Some(0x63e4_2f7e_13a7), Some(LocalCommitment { slot: 2864, id: Some(0x63e4_2f7e_13a7) }))
                .with_tip_difficulty(Some(1_048_576))
                .with_supply(vec![SupplyEpoch {
                    epoch: 2,
                    start_height: 2304,
                    end_height: 2871,
                    measured_coinbase: 1_234_567,
                    expected_coinbase: 1_234_567,
                    fees: 89,
                    burned: 0,
                }]),
            Some((2864, 0x63)),
        );
        let new = t.to_bytes();
        let old = v3_payload(&t);
        assert_eq!(&new[1..old.len()], &old[1..], "0x04 appends, it does not reshuffle");
        assert_eq!(
            new.len(),
            old.len() + 1 + 8 + 8,
            "the tail is exactly the discriminant, the height and the identity"
        );
    }
}
