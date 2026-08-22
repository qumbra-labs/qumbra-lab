//! Mempool admission + block assembly (M9-N4).
//!
//! Two consensus-facing node duties the N1 skeleton left open:
//!
//! 1. **Mempool admission** ([`Mempool::admit`]) — the gate a candidate
//!    transaction clears before it may be relayed or mined. It enforces the
//!    protocol's public-surface rules, cheapest first (consensus §1: "block
//!    validity checking is nearly free"; the proof verify runs last):
//!    - **posted-price fee** — `fee == posted_fee(bucket)`, the frozen §5 table
//!      (0.01 / 0.02 / 0.04 QMB); a wrong fee is invalid (protocol-spec §4);
//!    - **valid anchor** — a finalized commitment root within the ≤ 1,152-block
//!      window ([`NodeState::is_valid_anchor`], §4/§7);
//!      (**not** coinbase maturity — that left this list at issue #102 and is now
//!      enforced by the commitment tree's append schedule; see below);
//!    - **double-spend** — no nullifier already in the consensus set, none
//!      repeated within the candidate itself (issue #278), and none already
//!      claimed by another pooled tx (so an assembled block never in-block
//!      double-spends);
//!    - **discovery binds** — the §4 lone-tx discovery rules, via the same
//!      [`check_tx_discovery`] block validation runs per tx (issue #278);
//!    - **proof validity** — via the injected [`TxVerifier`] (this crate stays
//!      prover-free, exactly as [`crate::Node::apply_block`]).
//!
//! 2. **Block assembly** ([`Mempool::assemble`]) — build the next block template:
//!    select pooled txs under the **two-median weight governor** (frozen §6:
//!    10 MB free zone, hard cap 2× the effective median — an over-weight template
//!    is refused), pay the **coinbase** for the height ([`crate::emission`]:
//!    `coinbase(h) = S_atomic(h+1) − S_atomic(h)`), split it 65/15/20 (§3), and
//!    add the block's fees to the miner's take.
//!
//! Everything an assembled template asserts is exactly what [`crate::Node::
//! apply_block`] → `validate_body` re-checks, so a mempool-admitted tx set
//! assembles into a body the node accepts (the fee source is the *same*
//! `posted_fee`; the anchor gate is the *same* `is_valid_anchor`; the discovery
//! and in-tx nullifier rules are the *same* §4 functions — issue #278, which is
//! the incident where this paragraph was not yet true: a peer-delivered tx the
//! pool admitted but `validate_body` refused stayed pooled forever, and every
//! template assembled from the pool re-failed — a standing mining wedge).
//!
//! ## Coinbase maturity is not enforced here any more (issue #102)
//!
//! A coinbase note "carries public value at creation and enters the pool as an
//! ordinary note after a maturity delay" (tokenomics §6, one-hop transparency).
//! Issue #101 made it a **real note** — [`crate::coinbase::coinbase_note`],
//! openable by the 2×2 circuit — with a leaf, a membership witness, and a real
//! 2×2 spend. Issue #102 moved the *delay* out of this file.
//!
//! There used to be an admission gate here: the mempool kept a
//! commitment → creation-height registry, a candidate transaction **declared**
//! the coinbase notes it consumed, and admission required each to be ≥ 144 blocks
//! deep. All of it is deleted, because the declaration could not be made to work:
//!
//! - it was **submitter-controlled** — `vec![]` skipped the gate entirely;
//! - the P2P path (`NodeAdapter::ingest_tx`) hardcoded `vec![]`, so on the only
//!   path that carries other people's transactions the loop ran zero times;
//! - an undeclared-but-unknown commitment fell through the registry lookup and
//!   passed; and the registry was in-memory, rebuilt only from blocks connected
//!   during this process's lifetime, so **after any restart every historical
//!   coinbase was unknown** and every immature spend of one was admitted;
//! - and worst, the gate *when used honestly* published that this transaction is
//!   the coinbase's next hop — on a chain with one global shielded pool and no
//!   transparent tier, that is precisely the link tokenomics §6 promises to
//!   erase, collapsing the anonymity set of a new user's first transaction.
//!
//! A gate that only fires when the spender deanonymises themself is not a gate.
//! So maturity is now **structural**, enforced by the commitment tree's shape:
//! [`crate::coinbase::matures_coinbase_minted_at`] delays the coinbase leaf's
//! append by 144 blocks, so until it matures **no valid anchor contains the leaf**
//! and an immature spend has no witness against one, so no spend of it verifies.
//! There is nothing to declare, so nothing to lie about, and the rule binds a
//! submitter who lies, a peer that bypasses this mempool, and a node that just
//! restarted.
//!
//! Note the precise claim: **not** "an immature spend is unprovable" — an attacker
//! can prove a true statement about a tree of their own making, and the production
//! verifier accepts it. Their anchor is what is false, and anchors are consensus
//! state. See `matures_coinbase_minted_at` and the forged-anchor test it names.
//!
//! `COINBASE_MATURITY_BLOCKS` is unchanged at 144 and means the same thing; only
//! the place it is enforced moved. A holder asking *why* a note has no witness
//! yet gets [`crate::coinbase::CoinbaseMaturity`], which is public-data-only and
//! implies nothing about a spend.

use std::collections::{BTreeMap, HashMap, HashSet};

use qlab_devnet::body::{
    check_tx_discovery, repeated_nullifier_in_tx, BlockBody, BodyError, TxEntry, TxVerifier,
};
use qlab_devnet::fees::posted_fee;
use qlab_devnet::hash::keccak256;
use qlab_devnet::weight::{
    is_weight_admissible, quadratic_penalty, weight_limit, WeightGovernor, WeightParams,
};

// `COINBASE_MATURITY_BLOCKS` is deliberately not imported here any more (issue
// #102): this module no longer enforces maturity, and importing the constant would
// invite a second, weaker gate to grow back beside the structural one.
use crate::emission::{coinbase_for, RewardSplit};
use crate::node::NodeState;
use crate::store::Hash32;

/// A transaction identity — Keccak-256 of the canonical per-tx preimage (the same
/// injective `anchor ‖ nfs ‖ cms ‖ bucket ‖ fee ‖ proof_len ‖ proof` encoding a
/// block body commits to, protocol-spec §6).
pub type TxId = Hash32;

// ---------------------------------------------------------------------------
// Frozen consensus weight parameters (§6).
// ---------------------------------------------------------------------------

/// The FROZEN §6 long-term median window: **100,000 blocks** (≈ 87 days at 75 s,
/// Monero-parity — the measured creep damper; consensus-parameters §6, decided
/// 2026-07-23). `qlab-devnet`'s `WEIGHT_LONG_WINDOW` placeholder stays at the
/// smaller devnet value so the load-harness sweep runs in bounded time; the node
/// enforces the frozen window.
pub const FROZEN_WEIGHT_LONG_WINDOW: usize = 100_000;

/// The frozen §6 block-weight governor parameters the node enforces: free zone
/// 10 MB, hard cap 2×, long window 100,000, `lt_cap` 1.4×, `st_cap` 50. All but
/// the long window already equal the (converged) `params_devnet` placeholders, so
/// this reuses them and overrides only the window.
pub fn consensus_weight_params() -> WeightParams {
    WeightParams { long_window: FROZEN_WEIGHT_LONG_WINDOW, ..WeightParams::devnet_default() }
}

/// Node-side mempool/assembly configuration. Holds the frozen weight governor
/// parameters; the fee schedule and emission are global (`posted_fee`,
/// [`crate::emission`]).
#[derive(Clone, Copy, Debug)]
pub struct MempoolParams {
    /// The two-median weight-governor parameters (frozen §6).
    pub weight: WeightParams,
}

impl Default for MempoolParams {
    fn default() -> Self {
        Self { weight: consensus_weight_params() }
    }
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

/// Why a candidate transaction was refused admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MempoolError {
    /// Fee ≠ the posted price for the tx's bucket (protocol-spec §4, frozen §5).
    WrongFee { expected: u64, got: u64 },
    /// The anchor is not a valid transaction anchor now (not finalized, or aged
    /// past the ≤ 1,152-block window — §4/§7).
    AnchorNotValid,
    // NOTE (issue #102): there is no `ImmatureCoinbase` variant. Maturity is not a
    // policy refusal any more — an immature coinbase has no commitment-tree leaf,
    // so an immature spend cannot be *constructed*, and a forged attempt fails at
    // `AnchorNotValid` or `ProofInvalid` like any other unprovable claim. A
    // variant here would be unreachable, and an unreachable refusal reads as an
    // enforced one.
    /// A nullifier is already spent in the consensus set (cross-block double-spend).
    AlreadySpent { nullifier: Hash32 },
    /// A nullifier is repeated *within* this transaction — what block validation
    /// calls `DoubleSpendInBlock` once the tx is inside a block (issue #278).
    /// The two gates below both compare against state *outside* the candidate,
    /// so neither can see this; without this variant the self-double-spend
    /// pooled cleanly and every template assembled from it failed the miner's
    /// own `validate_body`.
    NullifierRepeatedInTx { nullifier: Hash32 },
    /// A nullifier is already claimed by another pooled tx (would in-block
    /// double-spend if both were mined).
    NullifierConflictInPool { nullifier: Hash32 },
    /// This exact transaction is already pooled.
    DuplicateTx,
    /// The tx fails the §4 discovery rules for a lone transaction (issue #278) —
    /// carries [`check_tx_discovery`]'s verdict whole, so an admit-time refusal
    /// names exactly what block validation would have named (only the
    /// `Discovery*` variants of [`BodyError`] can appear here, with `index: 0`).
    DiscoveryInvalid(BodyError),
    /// The tx carries a name rider that block validation would refuse (lab
    /// #367) — malformed bytes, a rider at a prospective height where riders
    /// are not active, a fee that is not `posted + name_fee`, or a rule
    /// failure. Carries `validate_body`'s own `BodyError` (only the `Rider*`
    /// variants appear here) so admit names exactly what block validation
    /// would.
    ///
    /// **This variant closes a #278 detonator introduced by #381**: a COMMIT
    /// rider pays the relay tier only, so its declared fee *equals*
    /// `posted_fee` and the bare fee check admitted it — while `validate_body`
    /// refused it (rider before the boundary), leaving a poisoned tx that no
    /// template can mine and nothing evicts. The mempool must run the same
    /// rider rules the block does, exactly as it already does for discovery.
    RiderInvalid(BodyError),
    /// The STARK proof does not verify against the public surface.
    ProofInvalid,
}

/// Why a block template could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssemblyError {
    /// The selected transaction set exceeds the hard block-weight cap
    /// (`> 2 × effective median`, frozen §6) — an invalid, refused template.
    TemplateOverWeight { weight: u64, hard_cap: u64 },
    /// A referenced transaction id is not in the pool.
    UnknownTx { txid: TxId },
}

// ---------------------------------------------------------------------------
// Pool entries + weight/id helpers.
// ---------------------------------------------------------------------------

/// A pooled transaction: its consensus entry and cached weight.
///
/// The `spends_coinbase` field is gone with the declaration it recorded (issue
/// #102) — the pool stored it only to feed a maturity gate that has moved into
/// the commitment tree's append schedule.
#[derive(Clone)]
pub struct MempoolTx {
    /// The transaction id (Keccak of the canonical preimage).
    pub txid: TxId,
    /// The consensus entry (opaque proof + public surface).
    pub entry: TxEntry,
    /// Serialized weight in bytes (proof + public surface).
    pub weight: u64,
    /// The name op this tx's rider carries, as [`names_admit_op`] decoded it at
    /// admission (lab #387). `None` is "no rider" — admission already refused
    /// every rider that does not decode, so a pooled tx's rider is either absent
    /// or a decoded op, and neither assembly nor eviction has to re-decode.
    ///
    /// It is a **cache of a pure function of `entry.rider`**, not independent
    /// state: `decode_rider(&entry.rider)` recomputes it exactly. It is stored
    /// because the two consumers below run per pooled tx per block, and because
    /// re-decoding would be a second decoder to keep in step with the first.
    pub name_op: Option<qlab_devnet::names::NameOp>,
}

/// Canonical Keccak-256 id of a transaction — the injective per-tx encoding the
/// body commitment uses (protocol-spec §6): `anchor ‖ nfs ‖ cms ‖ bucket(u8) ‖
/// fee(8 LE) ‖ proof_len(8 LE) ‖ proof`.
pub fn txid(entry: &TxEntry) -> TxId {
    let mut buf = Vec::new();
    buf.extend_from_slice(&entry.public.anchor);
    for nf in &entry.public.nullifiers {
        buf.extend_from_slice(nf);
    }
    for cm in &entry.public.commitments {
        buf.extend_from_slice(cm);
    }
    buf.push(entry.public.bucket.logical_actions() as u8);
    buf.extend_from_slice(&entry.public.fee.to_le_bytes());
    buf.extend_from_slice(&(entry.proof.len() as u64).to_le_bytes());
    buf.extend_from_slice(&entry.proof);
    // Lab #367: a non-absent rider is part of tx identity — without this, a
    // rider-carrying registration and its rider-stripped twin share a txid and
    // the pool dedups them as one, letting a stripped copy block the real
    // registration at the mempool. Presence-conditional so every pre-#367
    // txid is unchanged.
    if entry.rider != qlab_devnet::names::RIDER_ABSENT {
        buf.extend_from_slice(&(entry.rider.len() as u64).to_le_bytes());
        buf.extend_from_slice(&entry.rider);
    }
    keccak256(&buf)
}

/// A transaction's block weight in bytes: the opaque proof plus its public
/// surface (anchor 32 + Σnf·32 + Σcm·32 + bucket 1 + fee 8). Block weight is the
/// resource the §6 governor and the §5 fee floor bound (weight = Σ tx weight).
pub fn tx_weight(entry: &TxEntry) -> u64 {
    let public = 32
        + entry.public.nullifiers.len() * 32
        + entry.public.commitments.len() * 32
        + 1
        + 8;
    // Lab #367: rider bytes are body bytes and are priced like every other
    // body byte (task book stage 1). Presence-conditional so a rider-free
    // transaction's weight — i.e. every pre-#367 weight — is unchanged.
    let rider = if entry.rider != qlab_devnet::names::RIDER_ABSENT {
        8 + entry.rider.len()
    } else {
        0
    };
    (entry.proof.len() + public + rider) as u64
}

// `coinbase_note_commitment` was DELETED by issue #101, not deprecated. It
// computed `keccak256(b"qumbra:devnet:coinbase-note:v1" ‖ height ‖ total)` — a
// digest under its own domain, deliberately incapable of colliding with a real
// note commitment, and therefore an object the 2×2 circuit could never open.
// Appending it to the commitment tree would have produced a leaf that was still
// unspendable. The real coinbase note lives in [`crate::coinbase`]; there is one
// kind of coinbase note now, and it is an ordinary note.

// ---------------------------------------------------------------------------
// The block template assembly produces.
// ---------------------------------------------------------------------------

/// A candidate next block: the selected transactions plus the fully-computed
/// reward accounting for the height.
///
/// (No `PartialEq` — `qlab_devnet::TxEntry`/`BlockBody` carry none by design;
/// compare via the public accounting fields. `Debug` is hand-written to skip the
/// opaque tx/body fields.)
#[derive(Clone)]
pub struct BlockTemplate {
    /// The block height this template is for (`tip + 1`).
    pub height: u64,
    /// The selected transactions, in assembly order.
    pub txs: Vec<TxEntry>,
    /// Total block weight in bytes (Σ tx weight).
    pub total_weight: u64,
    /// The §6 effective median `M` the template was built against.
    pub effective_median: u64,
    /// The scheduled coinbase emission for the height (`coinbase(h)`, telescoping-
    /// exact — the supply-audit anchor input).
    pub coinbase_total: u64,
    /// The 65/15/20 division of `coinbase_total` (frozen §3).
    pub reward_split: RewardSplit,
    /// Total transaction fees (Σ posted price) — paid to the miner, never burned.
    pub total_fees: u64,
    /// The §6 quadratic weight penalty on the coinbase (0 in the free zone; a
    /// backstop that only bites blocks past the effective median).
    pub weight_penalty: u64,
    /// The miner's realized take: 65 % share − weight penalty + all fees.
    ///
    /// ⚠️ **Not the coinbase note's value.** [`crate::coinbase::coinbase_note_value`]
    /// is `65 % share + fees` with the §6 weight penalty **omitted**, because the
    /// penalty depends on the governor's effective median — node state the block
    /// *applier* does not reconstruct. The two agree everywhere inside the 10 MB
    /// free zone (penalty 0), which is every block on any net we run; they are
    /// still different expressions, and [`Self::coinbase_note`] is the one that
    /// is actually minted.
    pub miner_take: u64,
    /// The miner's raw `rkm` this template pays (issue #101) — the value that
    /// goes into `BlockBody::coinbase_rkm` and therefore into the note preimage.
    pub coinbase_rkm: [u64; 4],
    /// The **real** note commitment this block mints, as
    /// [`crate::coinbase::coinbase_note_leaf`] derives it. `None` only for a
    /// non-minting body (`coinbase == 0`).
    ///
    /// Derived from the assembled body by the same function the applier uses, so
    /// the assembler and the applier cannot disagree about the leaf's *identity*.
    ///
    /// **It is not a tree leaf yet, and there is no registry keyed on it** (issue
    /// #102 — this doc used to say both). `Node::apply_state` will append it 144
    /// blocks from now, when the block at
    /// [`crate::coinbase::coinbase_leaf_appears_at`] of this height is applied; until
    /// then it is in no anchor and has no membership witness. Nothing in the tree
    /// reflects this field at assembly time.
    pub coinbase_note: Option<Hash32>,
    /// The block body ready to hand to [`crate::Node::apply_block`]. The coinbase
    /// counter carries the scheduled emission `coinbase_total`.
    pub body: BlockBody,
}

impl std::fmt::Debug for BlockTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockTemplate")
            .field("height", &self.height)
            .field("n_txs", &self.txs.len())
            .field("total_weight", &self.total_weight)
            .field("effective_median", &self.effective_median)
            .field("coinbase_total", &self.coinbase_total)
            .field("reward_split", &self.reward_split)
            .field("total_fees", &self.total_fees)
            .field("weight_penalty", &self.weight_penalty)
            .field("miner_take", &self.miner_take)
            .finish()
    }
}

impl BlockTemplate {
    /// Assemble the accounting for a chosen transaction set at `height` against
    /// effective median `M`. Refuses if the set exceeds the hard cap (frozen §6).
    fn build(
        form: qlab_devnet::forms::GenesisForm,
        height: u64,
        chosen: Vec<TxEntry>,
        total_weight: u64,
        effective_median: u64,
        params: &MempoolParams,
        coinbase_rkm: [u64; 4],
    ) -> Result<Self, AssemblyError> {
        let hard_cap = weight_limit(effective_median, &params.weight);
        if !is_weight_admissible(total_weight, effective_median, &params.weight) {
            return Err(AssemblyError::TemplateOverWeight { weight: total_weight, hard_cap });
        }
        // Lab #470 stage 4a / #520: the template mints the schedule ITS NET
        // runs — the same form-keyed fork the auditor uses (`coinbase_for`),
        // so assembler and attester cannot drift apart. v4 is the
        // boundary-grandfathered function; v5 is exact natively (what
        // validate_body_v5 will demand of this very template).
        let coinbase_total = coinbase_for(form, height);
        let reward_split = RewardSplit::of(coinbase_total);
        let total_fees: u64 = chosen.iter().map(|t| t.public.fee).sum();
        let weight_penalty =
            quadratic_penalty(coinbase_total, total_weight, effective_median, &params.weight);
        let miner_take = reward_split.miner.saturating_sub(weight_penalty) + total_fees;
        let body =
            BlockBody::from_single_payee(chosen.clone(), coinbase_total, coinbase_rkm);
        let coinbase_note = crate::coinbase::coinbase_note_leaf_for(form, height, &body);
        Ok(Self {
            height,
            txs: chosen,
            total_weight,
            effective_median,
            coinbase_total,
            reward_split,
            total_fees,
            weight_penalty,
            miner_take,
            coinbase_rkm,
            coinbase_note,
            body,
        })
    }
}

// ---------------------------------------------------------------------------
// The mempool.
// ---------------------------------------------------------------------------

/// The transaction mempool + block assembler.
///
/// Holds admitted transactions (indexed by id) and a nullifier → owning-tx index
/// (the in-pool double-spend gate). It reads consensus state through the
/// [`NodeState`] trait, so it composes with any node backend.
///
/// The coinbase-note registry is gone (issue #102). It existed to answer "how
/// deep is this coinbase note", which only the commitment tree's append schedule
/// now needs to know — and unlike this map, the tree survives a restart.
#[derive(Clone)]
pub struct Mempool {
    params: MempoolParams,
    /// Admitted txs, ordered by id (deterministic assembly/iteration).
    txs: BTreeMap<TxId, MempoolTx>,
    /// nullifier → the pooled tx that claims it.
    nf_index: HashMap<Hash32, TxId>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(MempoolParams::default())
    }
}

impl Mempool {
    /// A fresh mempool with the given (frozen) parameters.
    pub fn new(params: MempoolParams) -> Self {
        Self { params, txs: BTreeMap::new(), nf_index: HashMap::new() }
    }

    /// The configured parameters.
    pub fn params(&self) -> &MempoolParams {
        &self.params
    }

    /// Number of pooled transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Whether a transaction id is pooled.
    pub fn contains(&self, id: &TxId) -> bool {
        self.txs.contains_key(id)
    }

    /// All pooled transactions in deterministic (txid) order — the pending set a
    /// block assembler / compact-block reconstruction (N7) draws from. Read-only;
    /// does not mutate the pool.
    pub fn entries(&self) -> Vec<TxEntry> {
        self.txs.values().map(|m| m.entry.clone()).collect()
    }

    /// A pooled transaction by its body-commitment id ([`txid`]), if present.
    pub fn get(&self, id: &TxId) -> Option<&TxEntry> {
        self.txs.get(id).map(|m| &m.entry)
    }

    /// Admit a candidate transaction, or say why it was refused. Checks run
    /// cheapest-first; the proof verify is last.
    ///
    /// ⚠️ This convenience hardcodes the **v4** name boundary
    /// ([`qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT`]). A **production caller
    /// on a form-aware node must use [`Self::admit_above`] with
    /// [`qlab_devnet::forms::GenesisForm::rider_admit_boundary`]** instead — on a
    /// v5 net this path would refuse every name rider as `RiderBeforeBoundary`
    /// (see `NodeAdapter::submit_tx_typed`). Kept for v4/test callers whose txs
    /// carry no rider (rider-free txs are boundary-agnostic — `names_admit_op`
    /// returns early before the boundary check).
    ///
    /// There is no maturity check and no `spends_coinbase` argument (issue #102):
    /// an immature coinbase has no leaf in any valid anchor, so an immature spend
    /// has no witness and cannot be proved. Enforcement is
    /// [`crate::coinbase::matures_coinbase_minted_at`], applied by
    /// `Node::apply_state`, and it binds every path into the node rather than
    /// this one.
    pub fn admit<S: NodeState, V: TxVerifier, N: qlab_devnet::names::NameView>(
        &mut self,
        entry: TxEntry,
        state: &S,
        verifier: &V,
        names: &N,
    ) -> Result<TxId, MempoolError> {
        self.admit_above(
            qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT,
            entry,
            state,
            verifier,
            names,
        )
    }

    /// [`Mempool::admit`] with the name boundary as an argument — the **drill**
    /// seam, and nothing else (the `validate_body_above` pattern; see
    /// [`qlab_devnet::names::names_admit_op_above`]).
    ///
    /// Below the shipped boundary every rider is refused, so the pool's
    /// *armed* behaviour — which is what lab #387 is about — has no other way
    /// to be exercised. Production calls [`Mempool::admit`].
    pub fn admit_above<S: NodeState, V: TxVerifier, N: qlab_devnet::names::NameView>(
        &mut self,
        boundary: Option<u64>,
        entry: TxEntry,
        state: &S,
        verifier: &V,
        names: &N,
    ) -> Result<TxId, MempoolError> {
        // 0. The name rider (lab #367), decoded first because the fee rule
        //    below depends on the op it carries. A malformed rider is a pure
        //    function of the tx, like the discovery decode — it can never
        //    become valid, so it is refused here exactly as block validation
        //    refuses it (`RiderMalformed`).
        let prospective_height = state.tip_height() + 1;
        let op = qlab_devnet::names::names_admit_op_above(
            boundary,
            &entry,
            prospective_height,
            names,
        )
        .map_err(MempoolError::RiderInvalid)?;

        // 1. Posted-price fee (protocol-spec §4, frozen §5) PLUS the burned
        //    name fee for any rider (the fee split — the reveal declares
        //    `posted + name_fee`, and without this it was refused as WrongFee).
        //    Cheapest — a pure function of the public bucket and the op.
        let expected =
            posted_fee(entry.public.bucket) + op.as_ref().map_or(0, qlab_devnet::names::name_fee_for);
        if entry.public.fee != expected {
            return Err(MempoolError::WrongFee { expected, got: entry.public.fee });
        }

        // 2. A nullifier repeated within the candidate itself (issue #278) — a
        //    pure function of the tx, so it runs with the cheap checks. The two
        //    nullifier gates below compare against state *outside* the candidate
        //    and structurally cannot see it, and a pooled self-double-spend is
        //    exactly the mining wedge: every template that selects it fails the
        //    miner's own `validate_body` as `DoubleSpendInBlock`, and nothing
        //    evicts it.
        if let Some(nullifier) = repeated_nullifier_in_tx(&entry.public) {
            return Err(MempoolError::NullifierRepeatedInTx { nullifier });
        }

        // 3. Anchor: a finalized root within the ≤ 1,152-block window (§4/§7).
        if !state.is_valid_anchor(&entry.public.anchor) {
            return Err(MempoolError::AnchorNotValid);
        }

        // 4. Double-spend against the permanent consensus nullifier set.
        for nf in &entry.public.nullifiers {
            if state.is_spent(nf) {
                return Err(MempoolError::AlreadySpent { nullifier: *nf });
            }
        }

        // 5. Exact duplicate? (Checked before the in-pool nullifier gate — an
        //    identical resubmission shares its own nullifiers, so it would
        //    otherwise report the less-specific conflict below.)
        let id = txid(&entry);
        if self.txs.contains_key(&id) {
            return Err(MempoolError::DuplicateTx);
        }

        // 6. A *distinct* tx reusing a pooled nullifier (would in-block
        //    double-spend if both were mined).
        for nf in &entry.public.nullifiers {
            if self.nf_index.contains_key(nf) {
                return Err(MempoolError::NullifierConflictInPool { nullifier: *nf });
            }
        }

        // 7. The §4 discovery rules for a lone transaction (issue #278) — the
        //    same consensus function `validate_body` runs per block-tx, so admit
        //    and block validation cannot disagree about a discovery group.
        //    O(tx bytes) decode + re-encode, dwarfed by the proof verify below;
        //    index 0 because the refusal names this candidate, not a block
        //    position.
        if let Err(e) = check_tx_discovery(0, &entry) {
            return Err(MempoolError::DiscoveryInvalid(e));
        }

        // 8. Proof verify — last, the only non-trivial cost (consensus §1).
        if !verifier.verify_tx(&entry) {
            return Err(MempoolError::ProofInvalid);
        }

        // Admit: index nullifiers, store.
        for nf in &entry.public.nullifiers {
            self.nf_index.insert(*nf, id);
        }
        let weight = tx_weight(&entry);
        // The decoded op rides with the tx (lab #387): assembly's per-template
        // name dedup and the eviction re-check both need to know which pooled
        // txs carry a rider, and neither may re-decode to find out.
        self.txs.insert(id, MempoolTx { txid: id, entry, weight, name_op: op });
        Ok(id)
    }

    /// Drop a transaction by id (e.g. after it is mined), releasing its nullifier
    /// claims. Returns the removed entry if present.
    pub fn remove(&mut self, id: &TxId) -> Option<MempoolTx> {
        let tx = self.txs.remove(id)?;
        for nf in &tx.entry.public.nullifiers {
            self.nf_index.remove(nf);
        }
        Some(tx)
    }

    /// Reconcile the pool after a block is connected: drop the txs it mined, and
    /// evict any pooled tx that now double-spends a nullifier the block consumed
    /// or whose anchor has aged out. Keeps the pool a set of txs that can still be
    /// mined next.
    ///
    /// It no longer records the block's coinbase note (issue #102). That write was
    /// the only reason this function needed the height, and it was load-bearing for
    /// a maturity gate that is now structural — which matters because this is
    /// called *only* from `ingest_block`'s success arm, an arm issue #130 shows is
    /// skipped once the state machine falls behind fork choice. Maturity must not
    /// depend on a call site that stops firing on a desynchronised node, and now
    /// it does not.
    ///
    /// ## The name leg (lab #387)
    ///
    /// Nullifiers and anchors are not the only way a pooled tx can go stale. A
    /// pooled REVEAL whose name someone else's mined tx just registered is
    /// refused by `validate_body` from now until `reopens_at` — a tx no
    /// template can mine, which nothing above evicts, i.e. exactly the #278
    /// poison class the admit leg (PR #385) closed at the front door. So after
    /// the nullifier/anchor pass, every pooled tx that carries a rider is
    /// re-asked the admission question against the **new** registry view at the
    /// **new** prospective height, and evicted if the answer is now no. Reusing
    /// [`qlab_devnet::names::names_admit_op`] is what makes it the same
    /// question: an outraced reveal, a renewal whose name lapsed past grace,
    /// and a reveal whose commit window has aged out all fall out of one call.
    ///
    /// `names` is the view **after** the block was applied — this runs on
    /// `apply_block`'s success arm, so the caller's registry already carries
    /// the block's own registrations.
    pub fn on_block_connected<S: NodeState, N: qlab_devnet::names::NameView>(
        &mut self,
        body: &BlockBody,
        state: &S,
        names: &N,
    ) {
        self.on_block_connected_above(
            qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT,
            body,
            state,
            names,
        )
    }

    /// [`Mempool::on_block_connected`] with the name boundary as an argument —
    /// the **drill** seam, and nothing else (see [`Mempool::admit_above`]).
    /// Production calls [`Mempool::on_block_connected`].
    pub fn on_block_connected_above<S: NodeState, N: qlab_devnet::names::NameView>(
        &mut self,
        boundary: Option<u64>,
        body: &BlockBody,
        state: &S,
        names: &N,
    ) {
        // Collect the nullifiers the block spent.
        let spent: HashSet<Hash32> =
            body.txs.iter().flat_map(|t| t.public.nullifiers.iter().copied()).collect();

        // Evict pooled txs that share any spent nullifier (mined, or now conflicting),
        // or whose anchor is no longer valid.
        let doomed: Vec<TxId> = self
            .txs
            .values()
            .filter(|tx| {
                tx.entry.public.nullifiers.iter().any(|nf| spent.contains(nf))
                    || !state.is_valid_anchor(&tx.entry.public.anchor)
            })
            .map(|tx| tx.txid)
            .collect();
        for id in doomed {
            self.remove(&id);
        }

        // The name leg: re-ask the admission rider question for every surviving
        // rider-carrying tx against the updated view. `name_op.is_some()` IS the
        // rider test — no re-decode — so a rider-free pool (every pool on the
        // chain as shipped) reaches no name code at all.
        let prospective_height = state.tip_height() + 1;
        let outraced: Vec<TxId> = self
            .txs
            .values()
            .filter(|tx| tx.name_op.is_some())
            .filter(|tx| {
                qlab_devnet::names::names_admit_op_above(
                    boundary,
                    &tx.entry,
                    prospective_height,
                    names,
                )
                .is_err()
            })
            .map(|tx| tx.txid)
            .collect();
        for id in outraced {
            self.remove(&id);
        }
    }

    /// The hard block-weight cap for effective median `M` (frozen §6: `2 × M`). A
    /// template above this is invalid.
    pub fn hard_cap(&self, effective_median: u64) -> u64 {
        weight_limit(effective_median, &self.params.weight)
    }

    /// Assemble the next block template: greedily select the highest-fee pooled
    /// txs that fit the **penalty-free zone** (`Σweight ≤ effective_median`, so a
    /// healthy block pays no weight penalty), then compute the coinbase + split +
    /// fees. `effective_median` comes from the caller's [`WeightGovernor`] fed with
    /// recent block weights (see [`Mempool::effective_median`]).
    ///
    /// At most **one reveal per name** per template (lab #387) — see the fill
    /// loop. No registry view is needed for it: the question is not "is this
    /// name free on chain" (admission already asked that, and asks it again on
    /// every block connect) but "did an earlier tx in *this* template already
    /// take it", which is answerable from the template alone.
    pub fn assemble<S: NodeState>(
        &self,
        state: &S,
        effective_median: u64,
        coinbase_rkm: [u64; 4],
    ) -> BlockTemplate {
        let height = state.tip_height() + 1;
        let mut candidates: Vec<&MempoolTx> = self.txs.values().collect();
        // Highest fee first; tie-break on id for determinism.
        candidates.sort_by(|a, b| {
            b.entry.public.fee.cmp(&a.entry.public.fee).then(a.txid.cmp(&b.txid))
        });
        let mut chosen = Vec::new();
        let mut weight = 0u64;
        // Names revealed earlier in THIS template (lab #387) — the assembly-side
        // mirror of `validate_body`'s `pending_names`. Two reveals of one name
        // both pass admit (the pool admits one tx at a time, so admission's
        // pending set is empty by construction), and a template carrying both is
        // refused by the miner's own block validation as `RiderRule(NameTaken)`
        // — the node building itself an invalid block. First reveal in fee order
        // takes the slot; the loser is skipped FOR THIS TEMPLATE ONLY and stays
        // pooled to compete again next block, because it is a perfectly valid tx
        // that merely lost a race.
        let mut pending_names: HashSet<Vec<u8>> = HashSet::new();
        for tx in candidates {
            // Only a Reveal claims a name. A Renew of a name revealed earlier in
            // the same block is legal (`check_op`: any payer, N4) and a Commit
            // reveals nothing, so neither is skipped here — the rule mirrors
            // `validate_body`'s, which is the only rule that matters.
            let claims = match &tx.name_op {
                Some(qlab_devnet::names::NameOp::Reveal { record, .. }) => Some(&record.name),
                _ => None,
            };
            if let Some(name) = claims {
                if pending_names.contains(name) {
                    continue;
                }
            }
            if weight + tx.weight <= effective_median {
                if let Some(name) = claims {
                    pending_names.insert(name.clone());
                }
                chosen.push(tx.entry.clone());
                weight += tx.weight;
            }
        }
        // The fill guarantees `weight ≤ effective_median ≤ hard_cap`, so build
        // never errors here.
        BlockTemplate::build(
            state.genesis_form(),
            height,
            chosen,
            weight,
            effective_median,
            &self.params,
            coinbase_rkm,
        )
            .expect("free-zone fill is always within the hard cap")
    }

    /// Assemble a template from an **explicit** transaction selection, refusing
    /// with [`AssemblyError::TemplateOverWeight`] if it exceeds the hard cap
    /// (frozen §6). This is the validity gate for a proposed/relayed block body:
    /// a set summing past `2 × M` is an invalid template.
    ///
    /// **Deliberately no name dedup here** (lab #387). [`Mempool::assemble`]
    /// *chooses* a set and so owns the choice not to build an invalid one; this
    /// path is handed a set someone else chose, and silently dropping a tx from
    /// it would answer a different question than the caller asked. A selection
    /// carrying a same-name pair is an invalid selection, and saying so is
    /// `validate_body`'s job — one same-block tie rule, in one place.
    pub fn assemble_selection<S: NodeState>(
        &self,
        state: &S,
        effective_median: u64,
        txids: &[TxId],
        coinbase_rkm: [u64; 4],
    ) -> Result<BlockTemplate, AssemblyError> {
        let height = state.tip_height() + 1;
        let mut chosen = Vec::with_capacity(txids.len());
        let mut weight = 0u64;
        for id in txids {
            let tx = self.txs.get(id).ok_or(AssemblyError::UnknownTx { txid: *id })?;
            chosen.push(tx.entry.clone());
            weight += tx.weight;
        }
        BlockTemplate::build(
            state.genesis_form(),
            height,
            chosen,
            weight,
            effective_median,
            &self.params,
            coinbase_rkm,
        )
    }

    /// Compute the current §6 effective median `M` from a chain of recent block
    /// weights (oldest first), using the frozen governor parameters. A convenience
    /// for callers that keep block-weight history but not a live governor.
    pub fn effective_median(&self, recent_block_weights: &[u64]) -> u64 {
        let mut gov = WeightGovernor::new(self.params.weight);
        for &w in recent_block_weights {
            gov.push_block(w);
        }
        gov.effective_median()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::coinbase;
    use qlab_devnet::fees::ArityBucket;

    /// A non-zero payout key for test bodies that mint (issue #101).
    const TEST_RKM: [u64; 4] = [0xC0, 0xFF, 0xEE, 0x01];

    // ── A minimal NodeState for focused admission tests ──────────────────────

    /// A hand-built consensus-state view: a set of valid anchors, a spent-
    /// nullifier set, and a tip height. Enough to drive every admission branch
    /// without spinning a full node (an end-to-end `MemNode` test is separate).
    #[derive(Default)]
    struct TestState {
        tip: u64,
        finalized: Option<u64>,
        valid_anchors: HashSet<Hash32>,
        spent: HashSet<Hash32>,
    }
    impl NodeState for TestState {
        fn tip_height(&self) -> u64 {
            self.tip
        }
        fn tip_hash(&self) -> Hash32 {
            [0; 32]
        }
        fn finalized_height(&self) -> Option<u64> {
            self.finalized
        }
        fn commitment_root(&self) -> Hash32 {
            [0; 32]
        }
        fn commitment_count(&self) -> u64 {
            0
        }
        fn is_spent(&self, nf: &Hash32) -> bool {
            self.spent.contains(nf)
        }
        fn nullifier_count(&self) -> usize {
            self.spent.len()
        }
        fn is_valid_anchor(&self, root: &Hash32) -> bool {
            self.valid_anchors.contains(root)
        }
    }

    /// Mock verifier: a proof is valid iff its bytes are exactly `b"ok"`.
    struct MockVerifier;
    impl TxVerifier for MockVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    const ANCHOR: Hash32 = [0x0F; 32];

    fn state_with_anchor() -> TestState {
        let mut s = TestState { tip: 200, finalized: Some(190), ..Default::default() };
        s.valid_anchors.insert(ANCHOR);
        s
    }

    /// A well-formed candidate paying the correct 2×2 posted price.
    fn good_tx(nf: u8) -> TxEntry {
        TxEntry::with_placeholder_discovery(b"ok".to_vec(), qlab_devnet::body::TxPublic {
            anchor: ANCHOR,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(100); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
            })
    }

    // ── admission positives ──────────────────────────────────────────────────

    #[test]
    fn admits_a_well_formed_tx() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let id = mp.admit(good_tx(1), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("admit");
        assert_eq!(mp.len(), 1);
        assert!(mp.contains(&id));
    }

    #[test]
    fn entries_and_get_expose_admitted_txs() {
        // The N7 pending-pool read surface: `entries()` lists the pooled txs and
        // `get(id)` resolves one by its body-commitment id.
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let tx = good_tx(1);
        let id = mp.admit(tx.clone(), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("admit");
        let listed = mp.entries();
        assert_eq!(listed.len(), 1);
        assert_eq!(txid(&listed[0]), id);
        assert_eq!(txid(mp.get(&id).expect("present")), id);
        assert!(mp.get(&[0xEE; 32]).is_none());
    }

    // ── admission negatives (the acceptance set) ─────────────────────────────

    /// Lab #367 — the #278 detonator the wallet UI can now produce. A COMMIT
    /// rider pays the relay tier only, so its declared fee EQUALS `posted_fee`
    /// and the bare fee check admitted it — while `validate_body` refuses it
    /// (rider before the boundary, which is `None` today). The mempool must
    /// refuse it too, or it pools a tx no template can mine and nothing
    /// evicts. Mutation check: delete the rider leg in `admit` and this test
    /// admits the poison.
    #[test]
    fn a_rider_before_the_boundary_is_refused_at_admit_not_pooled_as_poison() {
        use qlab_devnet::names::{EmptyNameView, NameOp};
        let mut mp = Mempool::default();
        let st = state_with_anchor();

        // A commit rider: fee == posted (commits burn nothing), so the fee
        // check alone would wave it through.
        let commit = good_tx(1).with_name_op(&NameOp::Commit { commit: [0x5A; 32] });
        assert_eq!(commit.public.fee, posted_fee(ArityBucket::TwoByTwo), "the trap: fee looks right");
        assert!(matches!(
            mp.admit(commit, &st, &MockVerifier, &EmptyNameView),
            Err(MempoolError::RiderInvalid(
                qlab_devnet::body::BodyError::RiderBeforeBoundary { .. }
            ))
        ));
        assert_eq!(mp.len(), 0, "the poison never entered the pool");

        // And a reveal, which declares posted + name_fee, is refused the same
        // way (before the boundary) rather than as a WrongFee red herring.
        let reveal = good_tx(2).with_name_op(&NameOp::Reveal {
            record: qlab_devnet::names::NameRecord {
                kind: qlab_devnet::names::RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xAB; qlab_devnet::names::L1_ADDRESS_LEN],
            },
            salt: [7; 32],
        });
        let reveal = TxEntry {
            public: qlab_devnet::body::TxPublic {
                fee: posted_fee(ArityBucket::TwoByTwo) + qlab_devnet::names::name_fee_bessel(5),
                ..reveal.public.clone()
            },
            ..reveal
        };
        assert!(matches!(
            mp.admit(reveal, &st, &MockVerifier, &EmptyNameView),
            Err(MempoolError::RiderInvalid(
                qlab_devnet::body::BodyError::RiderBeforeBoundary { .. }
            ))
        ));
    }

    /// Lab #470 C4 / the T2 first-registration blocker: on a v5 net the name
    /// rule is native from height ≥ 1, so the mempool must ADMIT a rider the v4
    /// boundary refuses. `GenesisForm::V5.rider_admit_boundary()` is `Some(0)`;
    /// the same commit that production `admit` (v4 `NAME_RULE_BOUNDARY_HEIGHT`)
    /// refuses as `RiderBeforeBoundary` at a low height is admitted under the v5
    /// boundary. This is the exact asymmetry that made `submit_tx_typed` refuse
    /// on T2 what `validate_body_v5` accepts. Mutation check: set the v5 arm of
    /// `rider_admit_boundary` to `None` and the admit below refuses (rider never
    /// active); leave it `NAME_RULE_BOUNDARY_HEIGHT` and it stays refused.
    #[test]
    fn a_v5_net_admits_a_name_rider_the_v4_boundary_refuses() {
        use qlab_devnet::forms::GenesisForm;
        use qlab_devnet::names::{EmptyNameView, NameOp};
        let st = state_with_anchor();
        let commit = good_tx(1).with_name_op(&NameOp::Commit { commit: [0x5A; 32] });

        // Production `admit` (v4 boundary) refuses it at this low height.
        let mut v4 = Mempool::default();
        assert!(matches!(
            v4.admit(commit.clone(), &st, &MockVerifier, &EmptyNameView),
            Err(MempoolError::RiderInvalid(
                qlab_devnet::body::BodyError::RiderBeforeBoundary { .. }
            ))
        ));

        // The v5 admit boundary (Some(0)) admits the identical rider.
        let mut v5 = Mempool::default();
        v5.admit_above(
            GenesisForm::V5.rider_admit_boundary(),
            commit,
            &st,
            &MockVerifier,
            &EmptyNameView,
        )
        .expect("a v5 net admits a name rider above genesis");
        assert_eq!(v5.len(), 1, "the rider tx pooled");
    }

    // ── the armed pool: assembly + eviction (lab #387) ───────────────────────
    //
    // The test above is the pool BELOW the boundary, where every rider is
    // refused and none of this is reachable. These two are the pool ABOVE it —
    // the state arming day puts the net in, and the only state in which the
    // same-name race exists. Reaching it needs the boundary stated explicitly
    // (`_above`, the `validate_body_above` convention); the shipped `None`
    // constant would refuse the fixtures at admit and prove nothing.

    /// The drill boundary these tests arm at. Below every fixture height, so
    /// riders are active throughout, and never the shipped constant.
    const DRILL_BOUNDARY: Option<u64> = Some(10);
    /// The height the fixtures' COMMIT riders were mined at — inside
    /// `[201 − COMMIT_MAX_AGE, 201 − COMMIT_MIN_AGE]`, so a reveal at the
    /// prospective height 201 finds its commit in window.
    const COMMIT_HEIGHT: u64 = 100;

    /// A REVEAL of `name` (paying `posted + name_fee`, the split) together with
    /// the COMMIT transaction whose on-chain inclusion it depends on. Distinct
    /// `salt_byte`s make two reveals of ONE name two genuinely different
    /// transactions, which is exactly the race: neither is malformed, neither is
    /// a duplicate, and each is individually admissible.
    fn reveal_pair(nf: u8, name: &[u8], salt_byte: u8) -> (TxEntry, TxEntry) {
        use qlab_devnet::names::{
            commit_hash, name_fee_bessel, NameOp, NameRecord, L1_ADDRESS_LEN,
            RECORD_KIND_L1_ADDRESS,
        };
        let record = NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: name.to_vec(),
            address: vec![0xAB; L1_ADDRESS_LEN],
        };
        let salt = [salt_byte; 32];
        let commit = good_tx(nf.wrapping_add(50))
            .with_name_op(&NameOp::Commit { commit: commit_hash(&record, &salt) });
        let reveal = good_tx(nf).with_name_op(&NameOp::Reveal { record, salt });
        let reveal = TxEntry {
            public: qlab_devnet::body::TxPublic {
                fee: posted_fee(ArityBucket::TwoByTwo) + name_fee_bessel(name.len()),
                ..reveal.public.clone()
            },
            ..reveal
        };
        (commit, reveal)
    }

    /// The **real** [`crate::name_registry::NameRegistry`] — the production
    /// `NameView` — with `txs`' riders applied at `height`. A hand-rolled mock
    /// view would let these tests agree with a registry that does not exist.
    fn registry_with(height: u64, txs: &[TxEntry]) -> crate::name_registry::NameRegistry {
        let mut reg = crate::name_registry::NameRegistry::default();
        let stored: Vec<crate::store::StoredTx> =
            txs.iter().map(crate::store::StoredTx::from).collect();
        reg.apply_block_riders(height, &stored).expect("fixture riders decode");
        reg
    }

    /// Lab #387 path 1 — **the node must not build itself an invalid block.**
    ///
    /// `names_admit_op` rule-checks with an EMPTY pending set (the pool admits
    /// one tx at a time and says so), so two reveals of one unregistered name
    /// both pass admit and both pool. A name-blind greedy fill packs both into
    /// one template, and `validate_body`'s same-block tie rule then refuses that
    /// block — the miner's own validation rejecting the miner's own template.
    ///
    /// Mutation check: delete the `pending_names` skip in `assemble` and this
    /// test fails twice over — two reveals in the template, and the
    /// `validate_body_above` assertion returns `RiderRule(NameTaken)`.
    #[test]
    fn a_template_carries_at_most_one_reveal_per_name_and_validates() {
        use qlab_devnet::names::NameOp;
        let mut mp = Mempool::default();
        let st = state_with_anchor(); // tip 200 ⇒ prospective height 201

        let (commit_a, reveal_a) = reveal_pair(1, b"alice", 0xA1);
        let (commit_b, reveal_b) = reveal_pair(2, b"alice", 0xB2);
        let reg = registry_with(COMMIT_HEIGHT, &[commit_a, commit_b]);

        let id_a = mp
            .admit_above(DRILL_BOUNDARY, reveal_a, &st, &MockVerifier, &reg)
            .expect("the first reveal admits");
        let id_b = mp
            .admit_above(DRILL_BOUNDARY, reveal_b, &st, &MockVerifier, &reg)
            .expect("and so does the second — admission's pending set is empty by construction");
        assert_eq!(mp.len(), 2, "the race is real: both are individually valid");

        // A median far above both weights, so nothing but the name rule can
        // keep the second one out.
        let t = mp.assemble(&st, 1_000_000, TEST_RKM);
        let revealed: Vec<Vec<u8>> = t
            .txs
            .iter()
            .filter_map(|tx| {
                match qlab_devnet::names::decode_rider(&tx.rider).expect("template riders decode") {
                    Some(NameOp::Reveal { record, .. }) => Some(record.name),
                    _ => None,
                }
            })
            .collect();
        assert_eq!(revealed, vec![b"alice".to_vec()], "exactly one reveal of the name");
        assert_eq!(t.txs.len(), 1, "the loser is not in the template at all");

        // It is still POOLED: it lost a slot in one template, not its validity.
        // Next block it competes again — and wins, once the winner is mined and
        // this one is evicted by the name leg below, or if the winner is not.
        assert_eq!(mp.len(), 2, "the loser stays pooled");
        assert!(mp.contains(&id_a) && mp.contains(&id_b));

        // The whole point: the template the node would mine passes the node's
        // own block validation, under the same view and the same boundary.
        let genesis = qlab_devnet::header::BlockHeader::genesis(1, 0);
        let header = qlab_devnet::header::BlockHeader {
            height: t.height,
            ..qlab_devnet::header::BlockHeader::child_of(
                &genesis,
                75,
                1,
                t.body.commitment_above(DRILL_BOUNDARY, t.height),
            )
        };
        assert_eq!(
            qlab_devnet::body::validate_body_above(
                DRILL_BOUNDARY,
                &header,
                &t.body,
                &MockVerifier,
                |r| *r == ANCHOR,
                &reg,
            ),
            Ok(()),
            "the assembled template is a block this node accepts"
        );
    }

    /// Lab #387 path 2 — **an outraced reveal must not be stranded.**
    ///
    /// Eviction was nullifier- and anchor-keyed only, and a reveal whose name
    /// someone else registers shares neither: it stays pooled, un-minable until
    /// `reopens_at`, re-selected into every template — the #278 poison shape the
    /// admit leg (PR #385) closed at the front door, arriving through the back.
    ///
    /// Note what the mined block does NOT do: it spends a different nullifier
    /// and leaves the pooled tx's anchor valid, so both pre-#387 eviction legs
    /// see nothing to do. Mutation check: delete the name leg in
    /// `on_block_connected_above` and the pooled reveal survives — this fails.
    #[test]
    fn a_name_outraced_reveal_is_evicted_on_block_connect_not_stranded() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();

        let (my_commit, my_reveal) = reveal_pair(1, b"alice", 0xA1);
        let (their_commit, their_reveal) = reveal_pair(2, b"alice", 0xB2);
        let reg = registry_with(COMMIT_HEIGHT, &[my_commit, their_commit]);

        let mine = mp
            .admit_above(DRILL_BOUNDARY, my_reveal.clone(), &st, &MockVerifier, &reg)
            .expect("my reveal admits — the name is free when I send it");
        let plain = mp
            .admit_above(DRILL_BOUNDARY, good_tx(3), &st, &MockVerifier, &reg)
            .expect("a rider-free tx admits");
        assert_eq!(mp.len(), 2);

        // Someone else's reveal of the SAME name is mined at 201, and the
        // registry the node now holds carries their registration.
        let body = BlockBody::from_single_payee(vec![their_reveal.clone()], coinbase(201), TEST_RKM);
        let mut reg_after = reg.clone();
        reg_after
            .apply_block_riders(201, &[crate::store::StoredTx::from(&their_reveal)])
            .expect("the mined rider applies");
        let st_after = TestState { tip: 201, ..state_with_anchor() };

        mp.on_block_connected_above(DRILL_BOUNDARY, &body, &st_after, &reg_after);

        assert!(!mp.contains(&mine), "the outraced reveal is evicted, not left un-minable");
        assert!(mp.contains(&plain), "and the rider-free tx beside it is untouched");
        assert_eq!(mp.len(), 1);

        // The cause, stated rather than inferred: the pooled reveal now fails
        // the very check admission ran, which is why reusing `names_admit_op`
        // is the whole of the eviction rule.
        assert!(matches!(
            qlab_devnet::names::names_admit_op_above(DRILL_BOUNDARY, &my_reveal, 202, &reg_after),
            Err(qlab_devnet::body::BodyError::RiderRule {
                err: qlab_devnet::names::NameRuleError::NameTaken { .. },
                ..
            })
        ));
    }

    #[test]
    fn rejects_wrong_fee() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.public.fee += 1; // one bessel off the posted price → invalid (§4)
        assert_eq!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::WrongFee {
                expected: posted_fee(ArityBucket::TwoByTwo),
                got: posted_fee(ArityBucket::TwoByTwo) + 1,
            })
        );
        assert!(mp.is_empty(), "a rejected tx must not enter the pool");
    }

    #[test]
    fn rejects_wrong_fee_even_for_a_different_bucket() {
        // A 4×4 tx paying the 2×2 price is still wrong-fee.
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.public.bucket = ArityBucket::FourByFour;
        tx.public.fee = posted_fee(ArityBucket::TwoByTwo);
        assert_eq!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::WrongFee {
                expected: posted_fee(ArityBucket::FourByFour),
                got: posted_fee(ArityBucket::TwoByTwo),
            })
        );
    }

    #[test]
    fn rejects_invalid_anchor() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.public.anchor = [0xEE; 32]; // not a finalized/in-window root
        assert_eq!(mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView), Err(MempoolError::AnchorNotValid));
    }

    /// The mempool has **no opinion on coinbase maturity**, and that is the point
    /// of issue #102 rather than a regression.
    ///
    /// This replaces `rejects_immature_coinbase_spend_then_admits_after_maturity`,
    /// which asserted the old policy gate. That test passed for the entire life of
    /// the defect while the rule it named was unenforced on every path a stranger
    /// could use, because it drove `Mempool::admit` directly and hand-fed it the
    /// declaration that production hardcoded empty. A test can only be as honest as
    /// the seam it exercises.
    ///
    /// So what is pinned here is the *boundary*: this pool admits a transaction
    /// whose surface is well-formed without asking about maturity at all, because a
    /// transaction spending an immature coinbase cannot have a valid proof to bring
    /// — the leaf is in no anchor, so no witness exists. The real property is
    /// asserted where it now lives: `qumbra-node/tests/coinbase_spend.rs` (an
    /// immature spend is unprovable, against the production verifier) and
    /// `qlab-node/tests/maturity_schedule.rs` (the append schedule and its replay).
    #[test]
    fn admission_does_not_consider_coinbase_maturity() {
        let mut mp = Mempool::default();

        // A coinbase note minted at 100, whose leaf under the frozen delay does not
        // enter the tree until 244 — i.e. immature at this tip by any reading.
        let minted_at = 100;
        let cb = crate::coinbase::coinbase_note_leaf(
            minted_at,
            &BlockBody::from_single_payee(vec![], coinbase(minted_at), TEST_RKM),
        )
        .expect("a minting body has a coinbase leaf");
        assert_eq!(crate::coinbase::coinbase_leaf_appears_at(minted_at), 244);

        // Tip 200: the leaf does not exist yet. The pool admits anyway — there is no
        // maturity gate and no declaration to carry `cb` through one. `MockVerifier`
        // stands in for a proof; on a real net no such proof could be produced,
        // which is exactly the enforcement this pool is no longer responsible for.
        let st = state_with_anchor(); // tip 200
        mp.admit(good_tx(1), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("admission is maturity-blind");
        assert_eq!(mp.len(), 1);

        // And the commitment is nowhere in the pool's state: nothing records it, so
        // nothing can be lied to about it, and no restart can lose it.
        let _ = cb;
    }

    #[test]
    fn rejects_cross_block_double_spend() {
        let mut mp = Mempool::default();
        let mut st = state_with_anchor();
        st.spent.insert([7; 32]); // nullifier already in the consensus set
        assert_eq!(
            mp.admit(good_tx(7), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::AlreadySpent { nullifier: [7; 32] })
        );
    }

    #[test]
    fn rejects_in_pool_double_spend() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        mp.admit(good_tx(9), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("first admits");
        // A different tx (distinct commitments) reusing the same nullifier.
        let mut tx2 = good_tx(9);
        tx2.public.commitments = vec![[200; 32]];
        assert_eq!(
            mp.admit(tx2, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::NullifierConflictInPool { nullifier: [9; 32] })
        );
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn rejects_duplicate_tx() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        mp.admit(good_tx(3), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).expect("first");
        assert_eq!(
            mp.admit(good_tx(3), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::DuplicateTx)
        );
    }

    #[test]
    fn rejects_invalid_proof_last() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.proof = b"forged".to_vec();
        assert_eq!(mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView), Err(MempoolError::ProofInvalid));
    }

    // ── the §4 lone-tx rules (issue #278) ────────────────────────────────────
    //
    // Block validation refuses these two shapes (`DoubleSpendInBlock`,
    // `Discovery*`), and until #278 admission did not — so a peer could pool a
    // tx every template assembled from would fail the miner's own
    // `validate_body`, and `on_block_connected` (the only eviction) never fires
    // for a block that failed validation. What these tests pin is the refusal
    // AT THE POOL, by name; the node-still-mines half of the acceptance bar
    // lives at the adapter, where mining actually happens
    // (`qlab-p2p::adapter`, `poisoned_tx_is_refused_at_admit_and_the_node_still_mines`).

    #[test]
    fn rejects_a_nullifier_repeated_within_one_tx() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(4);
        tx.public.nullifiers = vec![[4; 32], [4; 32]];
        assert_eq!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::NullifierRepeatedInTx { nullifier: [4; 32] })
        );
        assert!(mp.is_empty(), "a self-double-spend must not enter the pool");
    }

    #[test]
    fn rejects_a_discovery_group_that_does_not_bind() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        // A well-formed group describing a DIFFERENT commitment than the tx
        // declares (§4 rule 2 / D4).
        let mut tx = good_tx(5);
        tx.discovery = qlab_devnet::body::placeholder_discovery(&[[0xEE; 32]]);
        assert_eq!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::DiscoveryInvalid(BodyError::DiscoveryDoesNotBind {
                index: 0,
                expected: 1,
                got: 1,
                first_mismatch: Some(0),
            }))
        );
        assert!(mp.is_empty());
    }

    #[test]
    fn rejects_an_omitted_discovery_group_as_the_n_zero_case() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        // §4 rule 1: omission is `DiscoveryDoesNotBind`'s n = 0 case, not a
        // separate branch — a tx with one output and no discovery is exactly the
        // "recipient can never find this" shape #278's flavour 1 delivers.
        let mut tx = good_tx(6);
        tx.discovery = TxEntry::empty_discovery();
        assert_eq!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::DiscoveryInvalid(BodyError::DiscoveryDoesNotBind {
                index: 0,
                expected: 1,
                got: 0,
                first_mismatch: None,
            }))
        );
        assert!(mp.is_empty());
    }

    #[test]
    fn rejects_malformed_discovery_bytes() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(7);
        tx.discovery = vec![0xFF; 7]; // not a §2 group encoding at all
        assert!(matches!(
            mp.admit(tx, &st, &MockVerifier, &qlab_devnet::names::EmptyNameView),
            Err(MempoolError::DiscoveryInvalid(BodyError::DiscoveryMalformed { .. }))
        ));
        assert!(mp.is_empty());
    }

    // ── weight parameters (frozen §6) ────────────────────────────────────────

    #[test]
    fn consensus_weight_params_are_the_frozen_set() {
        let p = consensus_weight_params();
        assert_eq!(p.min_weight, 10_000_000, "free zone 10 MB");
        assert_eq!(p.max_multiple, 2, "hard cap 2×");
        assert_eq!(p.long_window, 100_000, "long window 100,000");
        assert_eq!((p.lt_cap_num, p.lt_cap_den), (7, 5), "lt cap 1.4×");
        assert_eq!(p.st_cap, 50, "st cap 50");
        assert_eq!(p.short_window, 100, "short window (Monero-parity)");
    }

    // ── assembly ─────────────────────────────────────────────────────────────

    #[test]
    fn assemble_fills_the_free_zone_and_pays_the_coinbase() {
        let mut mp = Mempool::default();
        let st = state_with_anchor(); // tip 200 ⇒ height 201
        for nf in 0..5u8 {
            mp.admit(good_tx(nf), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).unwrap();
        }
        // A tiny effective median so only a couple of ~135-byte mock txs fit free.
        let m = 2 * tx_weight(&good_tx(0)); // exactly two txs fit the free zone
        let t = mp.assemble(&st, m, TEST_RKM);
        assert_eq!(t.height, 201);
        assert_eq!(t.txs.len(), 2, "free-zone fill selects exactly two");
        assert!(t.total_weight <= m && t.weight_penalty == 0, "no penalty in the free zone");
        assert_eq!(t.coinbase_total, coinbase(201));
        assert_eq!(t.reward_split.total(), t.coinbase_total);
        assert_eq!(t.total_fees, 2 * posted_fee(ArityBucket::TwoByTwo));
        // Miner take = 65 % of coinbase (no penalty) + fees.
        assert_eq!(t.miner_take, t.reward_split.miner + t.total_fees);
        assert_eq!(t.body.coinbase_total(), t.coinbase_total);
        // The template carries the payee and the real leaf the applier will
        // append — derived from the same function, so the two cannot disagree.
        assert_eq!(t.coinbase_rkm, TEST_RKM);
        assert_eq!(t.body.coinbase_payees[0].rkm, TEST_RKM);
        assert_eq!(t.coinbase_note, crate::coinbase::coinbase_note_leaf(201, &t.body));
        assert!(t.coinbase_note.is_some(), "a minting template mints a note");
    }

    #[test]
    fn over_weight_template_is_refused() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut ids = Vec::new();
        for nf in 0..5u8 {
            ids.push(mp.admit(good_tx(nf), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).unwrap());
        }
        let one = tx_weight(&good_tx(0));
        // Effective median so the hard cap (2·M) admits only 3 of the 5 txs.
        let m = one; // hard cap = 2·one ⇒ at most 2 fit; 5 exceeds it
        let hard_cap = mp.hard_cap(m);
        let err = mp.assemble_selection(&st, m, &ids, TEST_RKM).unwrap_err();
        assert_eq!(
            err,
            AssemblyError::TemplateOverWeight { weight: 5 * one, hard_cap }
        );
        // A subset within the cap is accepted (and pays a penalty above the median).
        let ok = mp.assemble_selection(&st, m, &ids[..2], TEST_RKM).expect("subset within cap");
        assert_eq!(ok.total_weight, 2 * one);
        assert!(ok.weight_penalty > 0, "at 2M the block is fully penalized");
    }

    #[test]
    fn assemble_selection_rejects_unknown_tx() {
        let mp = Mempool::default();
        let st = state_with_anchor();
        let bogus = [0xAB; 32];
        assert_eq!(
            mp.assemble_selection(&st, 1_000_000, &[bogus], TEST_RKM).unwrap_err(),
            AssemblyError::UnknownTx { txid: bogus }
        );
    }

    /// Eviction only. The `…_and_records_coinbase` half of this test's old name is
    /// gone with the registry it checked (issue #102): the pool no longer records
    /// the block's coinbase note, so `on_block_connected` no longer takes a height.
    #[test]
    fn on_block_connected_evicts_mined_and_conflicting_txs() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let a = mp.admit(good_tx(1), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).unwrap();
        let _b = mp.admit(good_tx(2), &st, &MockVerifier, &qlab_devnet::names::EmptyNameView).unwrap();
        assert_eq!(mp.len(), 2);

        // A block at height 201 mines tx `a` (spends nullifier [1;32]).
        let mined = mp.txs.get(&a).unwrap().entry.clone();
        let body =
            BlockBody::from_single_payee(vec![mined], coinbase(201), TEST_RKM);
        mp.on_block_connected(&body, &st, &qlab_devnet::names::EmptyNameView);

        // `a` is gone; `b` remains.
        assert!(!mp.contains(&a));
        assert_eq!(mp.len(), 1);
    }
}
