//! Node RPC for wallets + embedded compact-block serving over **live node state**
//! (M9-N6, issue #53).
//!
//! This is the wallet-facing surface of a Qumbra full node. It composes two
//! things that already exist, adding no new consensus logic and **no forked
//! codec**:
//!
//! - The node's own consensus state ([`crate::Node`] via the [`crate::NodeState`]
//!   read view) — status, valid anchors, and transaction admission.
//! - `qlab-cbserver`'s ratified note-discovery serving ([`qlab_cbserver::codec`]
//!   + [`qlab_cbserver::tree`]) — `/v1/compact`, `/v1/…/full`, and
//!   `/v1/tree/frontier`. The bytes are produced by cbserver's **exact**,
//!   golden-locked encoders (reused, never re-implemented — the golden digest is
//!   re-asserted in the tests), so a wallet cannot tell a node's compact stream
//!   from the reference server's.
//!
//! # Wallet API (in-process)
//!
//! - [`NodeRpc::submit_tx`] — admit a transaction: the cheap public checks
//!   against **live** node state (anchor valid *now* per §4/§7, posted fee per
//!   §4, no already-spent or in-tx-repeated nullifier), the discovery-artifact ↔
//!   `cm` consistency check, then the injected [`TxVerifier`] proof check. On
//!   success the tx joins a light pending pool and its note-discovery artifacts
//!   are recorded for later serving. *(The pending pool is N6's own thin holding
//!   area — the real mempool with weight/block-assembly policy is N4 (#51); N7
//!   (#54) rewires this `submit_tx` onto it. It is kept deliberately minimal.)*
//! - [`NodeRpc::status`] / [`NodeRpc::anchors`] — the read views wallets poll.
//!
//! # Serving against live node state
//!
//! `/v1/compact` and `/v1/…/full` are **gated by the node's accepted chain**: a
//! height is only served if the node has it (≤ tip), and each served group is
//! assembled from the block's real transactions joined to the recorded discovery
//! artifacts by transaction id. `/v1/tree/frontier` is served straight from the
//! node's **live** depth-32 commitment tree ([`crate::CommitmentStore::tree`]) —
//! the very tree the M3 bucket proves membership against — at the leaf count the
//! node reached by the requested height. The frontier bytes follow protocol-spec
//! §3 exactly (`version ‖ depth ‖ n_leaves ‖ leaf ‖ per-level present+node`,
//! `present` == bit *i* of `n_leaves−1`); a served frontier reconstructs the same
//! root the node reports (asserted end-to-end).
//!
//! # New wires (status / anchors)
//!
//! `/v1/status` and `/v1/anchors` are new N6 surfaces (no prior golden). They
//! follow the repo's versioning discipline — a [`RPC_VERSION`] lead byte,
//! unknown-version and trailing-byte rejection — and are round-trip +
//! golden-digest locked here. The compact/full/frontier wires are **not** touched
//! and stay at [`qlab_cbserver::WIRE_VERSION`]; issue #117 moved `RPC_VERSION` to
//! `0x02`, and issue #121 moved it to `0x03`. See its doc for why the two
//! constants are no longer the same one.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use qlab_cbserver::codec::{
    committed_payloads_per_recipient, decode_committed_discovery, encode_committed_discovery,
    encode_compact_response, encode_full_response,
    read_varint, write_varint, BlockCoinbase, BlockNullifiers, CodecError, CoinbasePage,
    CompactBlock, CompactGroup, BlockNames, NamesPage, NullifierPage,
};
use qlab_cbserver::tree::Frontier;
use qlab_devnet::body::{TxEntry, TxPublic, TxVerifier};
use qlab_devnet::params_devnet::{DEGRADED_MODE_LAG_BLOCKS, MAX_ANCHOR_AGE_BLOCKS};
use qlab_note::hash::{digest_bytes, keccak256};
use qlab_note::wire::RecipientBundle;

use std::collections::HashMap;

use crate::mempool::{Mempool, MempoolError};
use crate::node::{Node, NodeState};
use crate::store::{ChainStore, CommitmentStore, Hash32, NullifierStore, StoredBlock};
use crate::telemetry::{LocalCommitment, Telemetry};

/// The RPC wire-format version byte for the node's **own** surfaces —
/// `/v1/status`, `/v1/anchors` and `/v1/telemetry`.
///
/// It was `0x01`, defined as `= qlab_cbserver::
/// WIRE_VERSION` and documented as deliberately equal "so a client speaks one
/// version to the whole node". Adding the finalized-checkpoint identity to
/// [`Telemetry`] is a payload change on a reject-unknown-version wire, so the
/// `0x02` bump was the ratified mechanism (#117). Adding the public committee
/// aggregates and supply attestation made the same ratified bump to `0x03`
/// (#121), and adding the **durable finalized head** — head #3, the only finalized
/// head that survives a restart, which `final=`/`fid` are not — makes it again to
/// `0x04` (#212). It necessarily keeps that tie severed:
///
/// - The ratified **compact-block** family (`/v1/compact`, `/v1/…/full`,
///   `/v1/tree/frontier`) stays at [`qlab_cbserver::WIRE_VERSION`] = `0x01`. It
///   is golden-digest locked and its lead byte is asserted on the P2P compact
///   relay path (`qlab_p2p::compact`), so bumping it would be a wire-codepoint
///   change. Untouched here, on purpose.
/// - `/v1/status` and `/v1/anchors` share this constant and therefore bump too,
///   although their payloads did not change. That is accepted rather than giving
///   `Telemetry` a private version byte: the node's own surfaces move as one, and
///   an old reader failing loudly against a new node is the reject-unknown
///   feature working, not a regression.
///
/// At that release a client spoke `0x05` to the node's own wires and `0x01` to
/// the compact-block wires it shares with the `qlab-cbserver` reference server.
///
/// **`0x05` since issue #275, and this bump is a ROUTE bump, not a payload one.**
/// The wallet-send server half adds `/v1/tree/leaves` (a new versioned wire, see
/// [`TreeLeaves`]) and the deployed `POST /v1/tx` submit surface; every existing
/// payload is byte-for-byte what it was at `0x04`. The version still moves because
/// it is the one capability signal a client has: a wallet that reads `0x05` off
/// `/v1/status` knows the send seams exist without probing for a 404, and the
/// house rule stays one rule — the node's own surfaces move as one.
///
/// > **🔴 That rationale is SUPERSEDED — ruled at PR #315 (issue #314), 2026-08-10.**
/// > [`Reader::version`] is an equality check, so a client built after a bump reads
/// > *nothing* — including `/v1/status` — from a pre-bump node: the "capability
/// > signal" structurally cannot be delivered by the node that lacks the capability,
/// > and the probe that works across vintages is the route itself (a 404, surfaced
/// > as a named UNAVAILABLE — required client behaviour since #312/#315). **The
/// > rule now: a change to an EXISTING surface's bytes bumps `RPC_VERSION`; a pure
/// > route addition does not.** `/v1/nullifiers` (#314) is the first route added
/// > under the ruled form; `0x05` stays as history, not as precedent.
///
/// **`0x07` since lab #553.** The existing `/v1/mine/template` response and
/// `/v1/mine/block` request moved from one flat `(miner_rkm, coinbase_amount)`
/// pair to an ordered payee list. Those JSON routes do not carry this lead byte,
/// but the house rule keeps one node-RPC release boundary; `qumbra-pool` moves in
/// the same source tree.
///
/// # The reader side of a bump is not free, and #212 is where that was paid
///
/// [`Reader::version`] is an equality check, so **a reader built at `0x05` reads
/// nothing at all from a node still serving `0x03` or `0x04`.** T0 rolls one host
/// at a time, so every bump blinds `qumbra-opview` — the drills' cross-host
/// pass/fail instrument — on every un-rolled host for the length of the roll. #212
/// pays for it with [`crate::telemetry::READABLE_TELEMETRY_VERSIONS`]: a bounded,
/// named set of versions a *reader* may opt into via
/// [`Telemetry::from_bytes_compat`], which hands back the version it decoded so an
/// absent field can be attributed. #275's bump pays the same way: `0x04` joins that
/// list (its telemetry layout is `0x05`'s, unchanged), so an opview built here still
/// reads every host of the current fleet. **This constant, and every strict
/// `from_bytes`, are unchanged in their strictness** — the node still serves exactly
/// one version and still refuses every other on its own decode paths.
pub const RPC_VERSION: u8 = 0x07;

// ---------------------------------------------------------------------------
// Transaction identity + note-discovery artifacts
// ---------------------------------------------------------------------------

/// Deterministic transaction id: Keccak-256 over the canonical public surface
/// (anchor ‖ nullifiers ‖ commitments ‖ logical-actions ‖ fee, all in order).
/// Proof bytes are intentionally excluded — the id names the *statement*, so the
/// same tx maps to its discovery artifacts whether it is still pending or already
/// embedded in an accepted block (whose [`StoredTx`] carries the same surface).
pub fn tx_id(anchor: &Hash32, nullifiers: &[Hash32], commitments: &[Hash32], actions: u32, fee: u64) -> Hash32 {
    let mut buf = Vec::new();
    buf.extend_from_slice(anchor);
    for nf in nullifiers {
        buf.extend_from_slice(nf);
    }
    for cm in commitments {
        buf.extend_from_slice(cm);
    }
    buf.extend_from_slice(&actions.to_le_bytes());
    buf.extend_from_slice(&fee.to_le_bytes());
    keccak256(&buf)
}

fn tx_id_of_public(p: &TxPublic) -> Hash32 {
    tx_id(&p.anchor, &p.nullifiers, &p.commitments, p.bucket.logical_actions(), p.fee)
}

// NOTE (issue #188, the serving+open baton): `tx_id_of_stored` is gone. Its one
// caller was `/v1/…/full`'s join from a stored transaction into the in-memory
// discovery side table, and that join is what made the route answer 404 for
// every transaction this node did not itself admit. Serving projects the
// committed region now, so nothing needs a stored transaction's statement id.

// Re-exported from where the rule now lives (issue #278): `qlab_devnet::body`,
// beside the block-level rule it projects. The "rpc-layer precheck on purpose"
// reasoning this function's doc used to carry is the premise #278 overturned —
// a precheck bolted onto each surface left the peer wire with none, and the
// pool poisoned. `Mempool::admit` now runs it on every path into the pool; the
// re-export keeps the deployed `POST /v1/tx` surface's call path
// (`qlab_node::repeated_nullifier_in_tx`) stable.
pub use qlab_devnet::body::repeated_nullifier_in_tx;

/// One recipient's note-discovery artifacts: the compact bundle a light client
/// pre-filters over ([`RecipientBundle`] = shared ML-KEM ct + per-output
/// `cm ‖ tag`) plus the AEAD payloads a wallet pulls only on a tag match.
#[derive(Clone)]
pub struct RecipientDiscovery {
    pub bundle: RecipientBundle,
    pub payloads: Vec<Vec<u8>>,
}

/// A transaction's full note-discovery artifacts (per recipient), submitted
/// alongside the consensus tx so the node can serve them to light clients.
#[derive(Clone, Default)]
pub struct TxDiscovery {
    pub recipients: Vec<RecipientDiscovery>,
}

// NOTE (issue #188 baton 2): `TxDiscovery::commitments` is gone. It stated D4's
// recipient-major-then-per-output order a second time, next to
// `qlab_note::compact::contents_commitments` which is now the consensus statement
// of the same rule — and a rule written twice is a rule that can disagree with
// itself, which is D1's own argument. Its one caller (the submit-time binding
// check) compares committed bytes now, which is strictly stronger.

// ---------------------------------------------------------------------------
// The committed-discovery projection (issue #188 baton 2)
// ---------------------------------------------------------------------------

/// The most blocks one `/v1/compact` response will ever carry.
///
/// A range request is a client-chosen number, and before this bound existed
/// [`NodeRpc::compact_range`] iterated `from..=to` literally — so `to = u64::MAX`
/// was an unbounded loop against a node, reachable by anyone who could reach the
/// endpoint. That was harmless while the only caller was an in-process test and
/// stops being harmless the moment a deployed node serves this (issue #188 baton
/// 2, scope item 2), so the bound lands with the exposure that makes it matter.
///
/// **The contract, because a truncated range must not read as an empty one:** a
/// response carries every main-chain height in `[from, to]` the node holds, up to
/// this many blocks. A client that receives exactly this many pages from the last
/// height + 1. `1024` blocks is ~21 hours of chain at the 75 s target.
pub const MAX_COMPACT_BLOCKS: usize = 1024;

/// One main-chain block's **committed** note-discovery, as the verbatim bytes the
/// body preimage covers — the projection `/v1/compact` serves.
///
/// ## Why this type exists rather than a `StoredBlock`
///
/// Serving needs a transaction's discovery group and nothing else about it. A
/// `StoredBlock` also carries the proof, which is ~136 KB against a discovery
/// group's ~1.2 KB, so a serving surface that had to hold blocks would hold ~99 %
/// bytes it never reads. `qumbra-node`'s discovery server publishes a snapshot of
/// these and therefore pays ~1 % of the block store rather than a second copy of
/// it.
///
/// `groups[i]` is `block.txs[i].discovery` **cloned, never re-encoded**. That is
/// the whole guarantee: there is no code path from a `StoredBlock` to a served
/// group that could produce different bytes, because there is no encoder between
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDiscovery {
    /// The block's height on the main chain.
    pub height: u64,
    /// The block's header hash — carried so a consumer maintaining an incremental
    /// projection can tell "extends what I have" from "replaces it".
    pub hash: Hash32,
    /// Per transaction, in block order: the committed §2 group **contents**,
    /// verbatim. Coinbase contributes nothing (D5).
    pub groups: Vec<Vec<u8>>,
    /// Every nullifier this block spends, in block order (transaction order,
    /// then each transaction's declared order) — `StoredTx::nullifiers`
    /// **cloned and concatenated**, never re-derived (lab issue #314).
    ///
    /// ## Why it rides in this type rather than a projection of its own
    ///
    /// This type is "one main-chain block, as the serving surfaces need it", and
    /// its whole guarantee is that there is no encoder between the block and the
    /// served bytes. A second projection would need a second main-chain walk and
    /// a second incremental/reorg rule (`DiscoveryView::refresh`), and two
    /// restatements of "what the main chain is" is exactly the shape this file
    /// keeps refusing elsewhere. The cost is 32 B per nullifier — 64 B per 2×2
    /// transaction against that transaction's ~1.2 KB of discovery, i.e. ~5 % of
    /// a projection that is itself ~1 % of the block store.
    ///
    /// Coinbase contributes nothing here either: it spends nothing, so it has no
    /// nullifier, and an empty list for a coinbase-only block is the meaningful
    /// answer *"this block spent nothing"* — see [`NullifierPage`] for why that
    /// must never be confused with "this block was not served".
    pub nullifiers: Vec<Hash32>,
    /// Every transaction's committed name rider, verbatim, block order —
    /// **including the absent `[0x00]`**, so `riders[i]` is tx `i` and the
    /// same-block tie rule survives serving without a second numbering
    /// (lab #367). Same no-encoder-between-block-and-served-bytes guarantee
    /// as `groups`.
    pub riders: Vec<Vec<u8>>,
    /// This block's sole coinbase payee, projected from `body.coinbase_payees` (lab #415).
    ///
    /// ## Why it rides here too
    ///
    /// [`BlockDiscovery::nullifiers`] states the argument and it applies
    /// unchanged: this type is "one main-chain block, as the serving surfaces
    /// need it", and a second projection would mean a second main-chain walk and
    /// a second incremental/reorg rule. The cost is 32 B + three integers per
    /// block against a projection that is already ~1.2 KB per transaction.
    ///
    /// Unlike the two fields above, **a coinbase-only block is exactly where
    /// this one is non-empty** — which is the point: the whole defect lab #415
    /// records is that a chain of coinbase-only blocks projected to nothing a
    /// wallet could read.
    pub coinbase_rkm: [u64; 4],
    /// `body.coinbase_total()` — the issuance this block declared. **Not the
    /// coinbase note's value**; see [`crate::coinbase::coinbase_note_value_parts`].
    pub coinbase: u64,
    /// `body.total_fees()` — the declared fees, which are the miner's.
    pub fees: u64,
    /// `body.total_name_burn()` — the burned half that is not (lab #367),
    /// computed by `qlab_devnet::names::burn_of_riders` over **this projection's
    /// own `riders`**, i.e. the same function `BlockBody::total_name_burn` calls
    /// on the same bytes.
    pub name_burn: u64,
}

impl BlockDiscovery {
    /// Project a stored block. `hash` is the caller's — the chain store keys blocks
    /// by it, so re-hashing the header here would be a second derivation of a fact
    /// the caller already holds.
    ///
    /// The coinbase fields are read off the stored block rather than off
    /// `StoredBlock::body()`: rebuilding the body would clone every proof in it
    /// (~145 KB each) on a path that runs per request. `fees` is the same sum
    /// `BlockBody::total_fees` is, over the same per-transaction field, and
    /// `the_projections_coinbase_facts_are_the_bodys_own` pins the pair against a
    /// real body rather than trusting the sentence.
    pub fn of(hash: Hash32, block: &StoredBlock) -> Self {
        let riders: Vec<Vec<u8>> = block.txs.iter().map(|t| t.rider.clone()).collect();
        Self {
            height: block.header.height,
            hash,
            groups: block.txs.iter().map(|t| t.discovery.clone()).collect(),
            nullifiers: block.txs.iter().flat_map(|t| t.nullifiers.iter().copied()).collect(),
            coinbase_rkm: block.coinbase_rkm,
            coinbase: block.coinbase,
            fees: block.txs.iter().map(|t| t.fee).sum(),
            name_burn: qlab_devnet::names::burn_of_riders(riders.iter().map(|r| r.as_slice())),
            riders,
        }
    }

    /// Bytes of committed **discovery** this block carries. Deliberately not the
    /// whole projection's cost since lab issue #314 — see
    /// [`Self::nullifier_len_bytes`] for the other half, kept separate so a
    /// caller reporting "how much committed discovery am I holding" still gets
    /// that number and not a sum of two different things.
    pub fn len_bytes(&self) -> usize {
        self.groups.iter().map(|g| g.len()).sum()
    }

    /// Bytes of nullifier this block carries (lab issue #314) — `32 × n`.
    pub fn nullifier_len_bytes(&self) -> usize {
        self.nullifiers.len() * 32
    }

    /// The serving-form groups: `tx_index` = position in the block, contents =
    /// the committed bytes decoded.
    ///
    /// 🔴 **This decode cannot change the bytes, and that is a consensus fact
    /// rather than a hope.** `qlab_devnet::body::check_tx_discovery` refuses any
    /// body whose discovery does not re-encode to itself (`DiscoveryNotCanonical`,
    /// `discovery-on-the-consensus-wire.md` §4 rule 3), so for every block in a
    /// node's store `encode_committed_discovery(decode_committed_discovery(b)) == b`
    /// already held before the block was accepted. Serving is therefore the
    /// projection D2 requires and not a re-encoding of it.
    ///
    /// 🔴 Since issue #188 (a) the projection is `varint(position) ‖ the
    /// **`group_contents` prefix** of the committed bytes` — the relocated AEAD
    /// payload section is committed but deliberately **not** on the compact wire,
    /// which is what keeps `/v1/compact`'s golden vector byte-identical across the
    /// relocation. `served_groups_are_the_committed_bytes_verbatim` asserts that
    /// byte identity against the prefix rather than trusting this paragraph.
    ///
    /// An `Err` here means a stored block carries bytes `validate_body` would have
    /// rejected, i.e. a broken internal invariant. It is returned rather than
    /// flattened to an empty group **because an empty group is a meaningful
    /// answer** — it is `n = 0`, "this transaction attaches no discovery", which is
    /// exactly the state a recipient must never be told about a transaction that
    /// does. A serving surface that answers a corrupt block with "no outputs here"
    /// is the absence-reads-as-healthy shape option 3 exists to remove.
    pub fn compact_groups(&self) -> Result<Vec<CompactGroup>, CodecError> {
        self.groups
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                Ok(CompactGroup {
                    tx_index: i as u64,
                    recipients: decode_committed_discovery(bytes)?.0,
                })
            })
            .collect()
    }

    /// One transaction's committed **AEAD payloads**, per recipient — the other
    /// half of the projection, and the half `/v1/compact` deliberately leaves
    /// behind (issue #188, the serving+open baton).
    ///
    /// `None` when this block has no transaction at `tx_index`; `Err` when the
    /// committed region does not decode, which is a broken internal invariant
    /// for the same reason [`Self::compact_groups`] gives — and refused for the
    /// same reason too: an empty payload list is the meaningful answer *"this
    /// transaction attaches nothing to open"*, and a serving surface that says
    /// that about bytes it could not read is the absence-reads-as-healthy shape
    /// option 3 exists to remove.
    ///
    /// The bytes come out of `self.groups[tx_index]`, which is
    /// `StoredTx::discovery` cloned, so there is no encoder between the block
    /// and the served payload and no side table between them either.
    pub fn payloads_of(&self, tx_index: u64) -> Option<Result<Vec<Vec<Vec<u8>>>, CodecError>> {
        let bytes = self.groups.get(usize::try_from(tx_index).ok()?)?;
        Some(committed_payloads_per_recipient(bytes))
    }
}

/// Why `/v1/block/{h}/tx/{i}/full` could not answer — each case named, because
/// the client half turns each one into a different sentence for a person
/// (`qlab_cbserver::client::Unopened`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FullRefusal {
    /// The node's main-chain projection holds no block at this height. A
    /// **client fault by coordinates**, and the same 404 a wallet gets from the
    /// reference server: the height is not on this node's chain, or not yet.
    NoSuchBlock { height: u64 },
    /// The block exists and has no transaction at this index. Carries the count
    /// it does have, so a wallet can tell "I asked past the end" from "the node
    /// is on a different chain".
    NoSuchTx { height: u64, tx_index: u64, n_txs: usize },
    /// The committed region of that transaction did not decode — a stored block
    /// carrying bytes `validate_body` would have refused. Never an empty
    /// payload list; see [`BlockDiscovery::payloads_of`].
    Undecodable { height: u64, tx_index: u64, err: CodecError },
}

/// Encode the `/v1/block/{h}/tx/{i}/full` response over a main-chain
/// projection — the payload half of the serving story (issue #188).
///
/// **The response is one transaction's whole payload section, or a refusal.**
/// There is no page, no cursor and no client-chosen amount of work in this
/// route, so unlike [`compact_response`] it has nothing to truncate: the
/// request names one `(height, tx_index)` and the answer's size is decided by
/// the block, not by the caller. That size is bounded twice over by the
/// committed region's own shape — `n_recipients` is a `u8` and every payload is
/// exactly `PAYLOAD_LEN` — and once more by consensus, since
/// `check_tx_discovery` binds the payload count to the transaction's declared
/// commitments (2 under the FROZEN 2×2 shape, i.e. 240 B of payload). A wallet
/// therefore never has to ask whether it got all of it; **that is the contract,
/// and it is the reason this route needs no client-side paging loop where
/// `/v1/compact` needed one (lab issue #309).**
///
/// The wire is [`encode_full_response`] — the same encoder, and therefore the
/// same decoder, that `qlab-cbserver`'s reference server and the light-client
/// scan already speak. A second wire for the deployed node would be a second
/// thing to keep in step for no gain.
pub fn full_response(
    blocks: &[BlockDiscovery],
    height: u64,
    tx_index: u64,
) -> Result<Vec<u8>, FullRefusal> {
    let block = blocks
        .iter()
        .find(|b| b.height == height)
        .ok_or(FullRefusal::NoSuchBlock { height })?;
    let payloads = block.payloads_of(tx_index).ok_or(FullRefusal::NoSuchTx {
        height,
        tx_index,
        n_txs: block.groups.len(),
    })?;
    let payloads = payloads.map_err(|err| FullRefusal::Undecodable { height, tx_index, err })?;
    Ok(encode_full_response(&payloads))
}

/// Encode the `/v1/compact` response for `[from, to]` over an **ascending**
/// main-chain projection.
///
/// Iterates the projection and filters, rather than iterating the requested range
/// and looking up: the cost is then bounded by what the node holds instead of by
/// what the client asked for (see [`MAX_COMPACT_BLOCKS`]).
pub fn compact_response(
    blocks: &[BlockDiscovery],
    from: u64,
    to: u64,
) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    for b in blocks {
        if b.height < from || b.height > to {
            continue;
        }
        if out.len() == MAX_COMPACT_BLOCKS {
            break;
        }
        out.push(CompactBlock { height: b.height, groups: b.compact_groups()? });
    }
    Ok(encode_compact_response(&out))
}

// ---------------------------------------------------------------------------
// Submit outcome
// ---------------------------------------------------------------------------

/// The result of [`NodeRpc::submit_tx`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Admitted to the pending pool; carries the transaction id.
    Accepted(Hash32),
    /// Already pending (same id); no state change.
    Duplicate,
    /// Rejected by a live-state check; the reason is stable and machine-usable.
    Rejected(RejectReason),
}

/// Why a submitted transaction was rejected. All checks read **live** node state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The anchor is not a valid anchor now (not finalized, or aged out — §4/§7).
    AnchorNotValid,
    /// The fee does not equal the posted price for the bucket (§4).
    WrongFee { expected: u64, got: u64 },
    /// A nullifier is already in the permanent spent set (cross-block double-spend).
    NullifierSpent,
    /// A nullifier is repeated within this transaction.
    NullifierRepeatedInTx,
    /// A nullifier collides with one already reserved by a pending transaction.
    NullifierPending,
    /// The submitted discovery artifacts are not the transaction's **own
    /// committed group**, byte for byte (issue #188 baton 2 — it compared
    /// commitments only before the group entered the body preimage).
    DiscoveryMismatch,
    /// The transaction's own committed discovery group fails the §4 lone-tx
    /// rules — refused by the pool (`MempoolError::DiscoveryInvalid`, issue
    /// #278). Distinct from [`Self::DiscoveryMismatch`], which says the
    /// separately-submitted artifacts are not the committed bytes; this one
    /// says the committed bytes themselves are malformed, non-canonical, or do
    /// not bind the declared commitments.
    DiscoveryInvalid,
    /// The tx carries a name rider block validation would refuse (lab #367):
    /// malformed, before the boundary, wrong fee split, or a rule failure.
    RiderInvalid,
    /// The proof failed to verify under the injected verifier.
    ProofInvalid,
    // NOTE (issue #102): `ImmatureCoinbase` is gone. Maturity is enforced by the
    // commitment tree's append schedule, so an immature spend has no witness against
    // any acceptable anchor and cannot reach a refusal reason at all. A wallet that wants
    // to know *why* a coinbase note has no witness yet asks
    // [`NodeRpc::coinbase_maturity`], which answers from public chain facts.
}

// ---------------------------------------------------------------------------
// NodeRpc
// ---------------------------------------------------------------------------

/// The wallet-facing node RPC: owns a [`Node`], a light pending pool, and the
/// note-discovery store, and serves reads over live node state.
pub struct NodeRpc<C: ChainStore, N: NullifierStore, T: CommitmentStore> {
    node: Node<C, N, T>,
    /// The real N4 pending pool (M9-N7 rewire): admission runs the same
    /// posted-fee / anchor / maturity / double-spend / injected-proof gates a
    /// block assembler enforces, and holds txs by their body-commitment id.
    mempool: Mempool,
    /// Note-discovery artifacts by **statement** tx id ([`tx_id_of_public`]) — the
    /// source `/v1/compact` and `/v1/…/full` join accepted-block transactions
    /// against. Keyed by the statement id, NOT the mempool's body-commitment id:
    /// the two encodings are deliberately distinct (see the module docs).
    discovery: HashMap<Hash32, TxDiscovery>,
    /// Network-layer facts the node itself cannot observe (peer count, committee
    /// epoch): the N1 traits do not carry them, so the P2P glue stamps them in via
    /// [`Self::set_net_facts`] for `/v1/telemetry`. Zero on a standalone node.
    net: NetFacts,
    /// Checkpoint-identity facts the node itself cannot observe (issue #117): they
    /// live in the committee finality tracker and the never-double-sign ledgers.
    /// Stamped in by the same glue via [`Self::set_checkpoint_facts`]; **absent**
    /// on a standalone node, which is the truth about it.
    checkpoint: CheckpointFacts,
}

/// The network-layer half of [`Telemetry`], injected by the P2P layer (M10-T0-2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetFacts {
    /// Connected peer count.
    pub peer_count: u64,
    /// Current committee epoch.
    pub epoch: u64,
}

/// The checkpoint-identity half of [`Telemetry`], injected the same way
/// [`NetFacts`] is (issue #117). Default = both absent, i.e. "this composition
/// cannot see the identity" — never a zero standing in for one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckpointFacts {
    /// `fid` — the identity of the finalized checkpoint.
    pub finalized_id: Option<u64>,
    /// `sslot`/`sid` — what this node's own committee keys are committed to.
    pub signed: Option<LocalCommitment>,
}

/// The default all-in-memory RPC composition.
pub type MemNodeRpc = NodeRpc<
    crate::store::MemChainStore,
    crate::store::MemNullifierStore,
    crate::store::MemCommitmentStore,
>;

impl<C: ChainStore, N: NullifierStore, T: CommitmentStore> NodeRpc<C, N, T> {
    /// Wrap a node in the RPC surface.
    pub fn new(node: Node<C, N, T>) -> Self {
        Self {
            node,
            mempool: Mempool::default(),
            discovery: HashMap::new(),
            net: NetFacts::default(),
            checkpoint: CheckpointFacts::default(),
        }
    }

    /// Borrow the underlying node (read views / block application in tests + N7).
    pub fn node(&self) -> &Node<C, N, T> {
        &self.node
    }

    /// Mutably borrow the underlying node — the block pipeline (N4/N7) applies
    /// blocks here; the discovery already recorded at submit then becomes
    /// serveable once a block embeds the tx.
    pub fn node_mut(&mut self) -> &mut Node<C, N, T> {
        &mut self.node
    }

    /// Number of pending (submitted, not-yet-embedded) transactions.
    pub fn pending_len(&self) -> usize {
        self.mempool.len()
    }

    /// The pending transactions (submitted, awaiting inclusion) — what a block
    /// assembler (N4) / the N7 wiring draws from.
    pub fn pending_txs(&self) -> Vec<TxEntry> {
        self.mempool.entries()
    }

    /// The underlying pending pool (read-only) — block assembly / N7 harness.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// Record note-discovery artifacts for a tx id directly (composition entry
    /// point for a driver that embeds blocks without routing them through
    /// [`Self::submit_tx`] — e.g. genesis import or N7 wiring).
    pub fn record_discovery(&mut self, txid: Hash32, discovery: TxDiscovery) {
        self.discovery.insert(txid, discovery);
    }

    /// Admit a transaction for a wallet. Cheap public checks against live node
    /// state run first (anchor validity, posted fee, nullifier gates, discovery
    /// binding); the injected proof verify runs last. On success the tx is pended
    /// and its discovery artifacts recorded for serving. The installed node form
    /// selects the rider boundary, so this in-process API cannot reintroduce the
    /// v4-hardcoded admission bug if a form-aware composition wires it later.
    pub fn submit_tx<V: TxVerifier>(
        &mut self,
        tx: TxEntry,
        discovery: TxDiscovery,
        verifier: &V,
    ) -> SubmitOutcome {
        let p = &tx.public;
        // The wallet-facing (statement) id — what discovery is keyed by and what a
        // caller gets back. Distinct from the mempool's body-commitment id.
        let txid = tx_id_of_public(p);

        // One rpc-layer pre-check the mempool contract does not cover (the in-tx
        // nullifier repeat that used to be checked here first is a pool gate
        // since issue #278 — `MempoolError::NullifierRepeatedInTx`, mapped
        // below, so every path into the pool runs it rather than only the
        // surfaces that remembered to):
        // the submitted artifacts must be **the transaction's own committed
        // group**, byte for byte.
        //
        // Until issue #188 baton 2 this compared commitments only, which was the
        // strongest check available while both `/v1/compact` and `/v1/…/full` read
        // the same side table — they could not disagree because they had one
        // source. They now have two: compact groups come from the block and
        // payloads from here. A submission whose bundles merely *agree on the
        // commitments* would put payloads on `/v1/…/full` that are index-aligned
        // against a different ciphertext than `/v1/compact` serves, so a wallet
        // that matched a committed tag would AEAD-decrypt with a key derived from
        // a `ct` the chain never saw and silently find nothing. Byte equality is
        // what keeps the two surfaces one artifact; it implies the old
        // commitment check.
        // 🔴 Since issue #188 (a) the payloads are part of the committed artifact
        // too, so this compares BOTH halves. That is strictly stronger than
        // before and it closes the gap the paragraph above describes at its
        // source: a submission whose payloads differ from the committed ones can
        // no longer be accepted at all, rather than being accepted and then
        // serving payloads index-aligned against a `ct` the chain never saw.
        if encode_committed_discovery(
            &discovery.recipients.iter().map(|r| r.bundle.clone()).collect::<Vec<_>>(),
            &discovery.recipients.iter().flat_map(|r| r.payloads.clone()).collect::<Vec<_>>(),
        ) != tx.discovery
        {
            return SubmitOutcome::Rejected(RejectReason::DiscoveryMismatch);
        }

        // The N4 mempool runs the real admission gates (posted fee → valid anchor →
        // consensus double-spend → duplicate → in-pool nullifier conflict →
        // injected proof) against live node state and holds the tx.
        //
        // No maturity gate, and no empty declaration standing in for one (issue
        // #102): this call site used to pass a hardcoded `vec![]`, which made the
        // frozen §2 rule unreachable from the wallet RPC. It is now enforced by the
        // commitment tree's append schedule, so there is nothing to pass and no way
        // for this path to skip it.
        let rider_boundary = self.node.genesis_form().rider_admit_boundary();
        match self.mempool.admit_above(
            rider_boundary,
            tx,
            &self.node,
            verifier,
            self.node.names(),
        ) {
            Ok(_body_id) => {
                self.discovery.insert(txid, discovery);
                SubmitOutcome::Accepted(txid)
            }
            Err(MempoolError::DuplicateTx) => SubmitOutcome::Duplicate,
            Err(MempoolError::WrongFee { expected, got }) => {
                SubmitOutcome::Rejected(RejectReason::WrongFee { expected, got })
            }
            Err(MempoolError::AnchorNotValid) => {
                SubmitOutcome::Rejected(RejectReason::AnchorNotValid)
            }
            Err(MempoolError::AlreadySpent { .. }) => {
                SubmitOutcome::Rejected(RejectReason::NullifierSpent)
            }
            Err(MempoolError::NullifierRepeatedInTx { .. }) => {
                SubmitOutcome::Rejected(RejectReason::NullifierRepeatedInTx)
            }
            Err(MempoolError::NullifierConflictInPool { .. }) => {
                SubmitOutcome::Rejected(RejectReason::NullifierPending)
            }
            Err(MempoolError::DiscoveryInvalid(_)) => {
                SubmitOutcome::Rejected(RejectReason::DiscoveryInvalid)
            }
            Err(MempoolError::RiderInvalid(_)) => {
                SubmitOutcome::Rejected(RejectReason::RiderInvalid)
            }
            Err(MempoolError::ProofInvalid) => SubmitOutcome::Rejected(RejectReason::ProofInvalid),
        }
    }

    // ---- live read views ---------------------------------------------------

    /// Current node status (live).
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            tip_height: self.node.tip_height(),
            tip_hash: self.node.tip_hash(),
            finalized_height: self.node.finalized_height(),
            commitment_root: self.node.commitment_root(),
            commitment_count: self.node.commitment_count(),
            nullifier_count: self.node.nullifier_count() as u64,
            pending_count: self.mempool.len() as u64,
        }
    }

    /// Whether the coinbase note minted at `minted_height` is in the commitment
    /// tree yet, and if not, at what height it will be (issue #102).
    ///
    /// The wallet-facing half of option (b). A holder that cannot build a
    /// membership witness for a coinbase note needs to tell "not yet mature" from
    /// "no such note", and under (b) the tree alone cannot tell them apart — the
    /// leaf is simply absent in both cases. `qumbra-faucet` §6.2 settled the same
    /// question for an unservable faucet by refusing with a height rather than
    /// queueing silently; this is the equivalent, and it is a read rather than a
    /// refusal because the wallet needs the answer *before* it tries to prove.
    pub fn coinbase_maturity(&self, minted_height: u64) -> crate::coinbase::CoinbaseMaturity {
        self.node.coinbase_maturity(minted_height)
    }

    /// The set of commitment roots that are valid anchors right now (finalized +
    /// within the age window), newest first, plus the window context a wallet
    /// needs. Enumerated over the main chain using only the public node API.
    pub fn anchors(&self) -> AnchorSet {
        anchor_set(&self.node)
    }

    /// Stamp in the network-layer facts the node cannot observe itself (peer
    /// count, committee epoch). The P2P glue calls this so `/v1/telemetry` reports
    /// the full picture; a standalone node leaves them at zero.
    pub fn set_net_facts(&mut self, peer_count: u64, epoch: u64) {
        self.net = NetFacts { peer_count, epoch };
    }

    /// Stamp in the checkpoint-identity facts the node cannot observe itself
    /// (issue #117): what it finalized (`fid`) and what its own committee keys are
    /// committed to (`sslot`/`sid`). The P2P/committee glue calls this; a
    /// composition that does not leaves them absent, and `/v1/telemetry` then says
    /// so rather than reporting a checkpoint identity it never had.
    pub fn set_checkpoint_facts(&mut self, facts: CheckpointFacts) {
        self.checkpoint = facts;
    }

    /// A live finality-health snapshot (`/v1/telemetry`, M10-T0-2). The node-owned
    /// half (regime, stall depth, last-finalized age, heights, mempool) is derived
    /// from live state; peer count and epoch come from the injected [`NetFacts`].
    ///
    /// `last_finalized_age_secs` is chain-time (block timestamps), not wall clock,
    /// so telemetry is deterministic given the chain: the gap between the tip
    /// block's timestamp and the finalized block's (or genesis, if nothing is
    /// finalized).
    pub fn telemetry(&self) -> Telemetry {
        let tip_height = self.node.tip_height();
        let finalized_height = self.node.finalized_height();
        let age = self.last_finalized_age_secs();
        Telemetry::assemble(
            tip_height,
            finalized_height,
            age,
            self.mempool.len() as u64,
            self.net.peer_count,
            self.net.epoch,
            DEGRADED_MODE_LAG_BLOCKS,
        )
        .with_checkpoint(self.checkpoint.finalized_id, self.checkpoint.signed)
        // Unlike the identity half, this one IS node state: the tip header is in
        // the chain store, so it is read rather than injected (issue #117).
        .with_tip_difficulty(
            self.node.chain().block(&self.node.tip_hash()).map(|b| b.header.difficulty),
        )
    }

    /// Chain-time seconds between the tip block and the finalized block. Reports
    /// **0 when nothing is finalized** (M10-T0-5 / S8): the T0-2 runbook keys its
    /// stall alarm on this field, and a genesis fallback made "no finality yet" read
    /// as a huge absolute age (Phase B-lite logged `age_s=1784917791`). Reports **0
    /// while the finalized head is still genesis too** (issue #73) — the same door:
    /// genesis is finalized as a bootstrap act, not by a checkpoint round, and its
    /// `timestamp = 0` placeholder differenced against a `WallClock` tip is the wall
    /// clock itself. Uses only the public chain store.
    fn last_finalized_age_secs(&self) -> u64 {
        match self.node.finalized_height() {
            // Nothing finalized, or only the genesis bootstrap ⇒ no finalized
            // CHECKPOINT exists, so there is no finalized-age to report.
            None | Some(0) => return 0,
            Some(_) => {}
        }
        let chain = self.node.chain();
        let tip_ts = chain
            .block(&chain.tip_hash())
            .map(|b| b.header.timestamp)
            .unwrap_or(0);
        let base_hash = chain.finalized_hash().unwrap_or_else(|| chain.genesis_block_hash());
        let base_ts = chain.block(&base_hash).map(|b| b.header.timestamp).unwrap_or(0);
        tip_ts.saturating_sub(base_ts)
    }

    // ---- main-chain helpers (public API only) ------------------------------
    //
    // NOTE (issue #188, the serving+open baton): the `main_chain()` wrapper over
    // `main_chain_of` is gone with its last caller. `/v1/…/full` was that caller
    // — it walked whole `StoredBlock`s, proofs included, to reach one
    // transaction's discovery bytes; it now reads the same
    // `main_chain_discovery()` projection `/v1/compact` does, which is ~1 % of
    // the bytes and the same source.

    /// `(height, commitment-count-after-this-block)` for each main-chain height.
    ///
    /// Must count exactly what `Node::apply_state` appends, in the same order, or
    /// every root this module reconstructs is wrong. Miscounting here would not
    /// fail loudly: it would publish anchors nobody can build a witness against.
    ///
    /// Since issue #102 that is the coinbase leaf the block **matures** (the one
    /// minted 144 blocks back, not its own), then its transaction commitments.
    /// The offset makes this a *sliding* rule, and two independent restatements of
    /// a sliding rule is worse than two of a fixed one — so this does not restate
    /// it. Both sides call [`crate::coinbase::matured_coinbase_leaf`], differing
    /// only in how they resolve an ancestor: `apply_state` walks `prev` through the
    /// chain store, and this walks the main chain it already materialised. That is
    /// what issue #116 asked for, and (b) is why it stopped being optional.
    fn main_chain_counts(&self) -> Vec<(u64, u64)> {
        main_chain_counts_of(&self.node)
    }


    /// Leaf count of the commitment tree at the end of `height` (clamped to the
    /// live tree). Heights beyond the tip clamp to the full tree.
    fn leaves_at(&self, height: u64) -> u64 {
        let mut count = 0;
        for (h, c) in self.main_chain_counts() {
            if h <= height {
                count = c;
            } else {
                break;
            }
        }
        count
    }

    // ---- compact-block serving (byte-identical, live-gated) -----------------

    /// The main chain's **committed** discovery, genesis-first — the projection
    /// `/v1/compact` is served from (issue #188 baton 2).
    ///
    /// Public because `qumbra-node`'s discovery server publishes exactly this and
    /// must not grow a second way of computing it.
    pub fn main_chain_discovery(&self) -> Vec<BlockDiscovery> {
        let chain = self.node.chain();
        let mut out = Vec::new();
        let mut hash = chain.tip_hash();
        loop {
            let Some(block) = chain.block(&hash) else { break };
            let prev = block.header.prev;
            let height = block.header.height;
            out.push(BlockDiscovery::of(hash, block));
            if height == 0 {
                break;
            }
            hash = prev;
        }
        out.reverse();
        out
    }

    /// The `/v1/compact` response for `[from, to]` (inclusive), gated by the
    /// node's accepted chain: heights the node does not have are skipped.
    ///
    /// 🔴 **The groups come from the block, not from [`Self::discovery`]** (issue
    /// #188 baton 2). Until body-bound discovery landed, this joined each stored
    /// transaction to the in-memory side table by statement id and served an
    /// **empty group** whenever the lookup missed — which is every transaction
    /// this node did not itself admit, every transaction after a restart, and
    /// every transaction on a node that never had a wallet talk to it. The bytes
    /// are now in `StoredTx::discovery`, covered by `tx_body_commitment`, so the
    /// side table is not consulted here at all and cannot make a served group
    /// differ from the committed one.
    ///
    /// 🔴 **And `/v1/…/full` no longer reads it either** (issue #188, the
    /// serving+open baton). The sentence that stood here — *"the AEAD payloads
    /// it holds are not in the body preimage … so there is nowhere else for them
    /// to come from"* — was true when it was written and stopped being true at
    /// the mint (PR #252, issue #188 (a) as amended), which relocated the 120 B
    /// payloads **into** the committed region. Both surfaces now project from
    /// the block, so the side table is not a source for anything served and
    /// cannot make a served byte differ from a committed one.
    fn compact_range_bytes(&self, from: u64, to: u64) -> Result<Vec<u8>, CodecError> {
        compact_response(&self.main_chain_discovery(), from, to)
    }

    /// The `/v1/…/full` per-recipient payload lists for one accepted `(height,
    /// tx_index)`, **projected from the committed region** — one function,
    /// [`full_response`], shared with `qumbra-node`'s discovery server so the
    /// in-process route and the deployed one cannot disagree about what a
    /// transaction's payloads are.
    ///
    /// It used to join the block to the in-memory side table by statement id and
    /// answer `None` when the lookup missed — i.e. a 404 for every transaction
    /// this node did not itself admit, and for every transaction at all after a
    /// restart. That is the same defect `/v1/compact` was carrying until issue
    /// #188 baton 2, and it has the same fix.
    fn full_bytes(&self, height: u64, tx_index: u64) -> Result<Vec<u8>, FullRefusal> {
        full_response(&self.main_chain_discovery(), height, tx_index)
    }

    /// The frontier of the **live** node commitment tree at the leaf count the
    /// node reached by `height` (protocol-spec §3).
    fn frontier_at(&self, height: u64) -> Frontier {
        let count = self.leaves_at(height);
        self.node.commitments().tree().frontier_at(count)
    }

    // ---- pure request router (no socket) -----------------------------------

    /// Route a GET request URL to its response bytes — the socket-free serving
    /// core (mirrors [`qlab_cbserver::server::route`]). Mutations (submit) are
    /// the in-process [`Self::submit_tx`] API, not a URL.
    pub fn route(&self, url: &str) -> RouteResult {
        let (path, query) = url.split_once('?').unwrap_or((url, ""));
        let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
        match segs.as_slice() {
            ["v1", "status"] => Ok(self.status().to_bytes()),
            ["v1", "anchors"] => Ok(self.anchors().to_bytes()),
            ["v1", "telemetry"] => Ok(self.telemetry().to_bytes()),
            ["v1", "compact"] => {
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
                if to < from {
                    return Err((400, "'to' < 'from'"));
                }
                // A stored block whose committed discovery does not decode is a
                // broken internal invariant (`validate_body` refuses such a body),
                // and the one thing this must not do is answer it with an empty
                // group — see [`BlockDiscovery::compact_groups`].
                self.compact_range_bytes(from, to)
                    .map_err(|_| (500, "stored discovery does not decode"))
            }
            ["v1", "block", h, "tx", i, "full"] => {
                let height = h.parse::<u64>().map_err(|_| (400, "invalid height"))?;
                let index = i.parse::<u64>().map_err(|_| (400, "invalid tx index"))?;
                self.full_bytes(height, index).map_err(|e| match e {
                    FullRefusal::NoSuchBlock { .. } | FullRefusal::NoSuchTx { .. } => {
                        (404, "no such (height, tx)")
                    }
                    // Same discipline as `/v1/compact`'s: a stored block whose
                    // committed region does not decode is a broken invariant,
                    // never an empty payload list.
                    FullRefusal::Undecodable { .. } => (500, "stored discovery does not decode"),
                })
            }
            ["v1", "tree", "frontier"] => {
                let at = query_u64(query, "at").ok_or((400, "missing/invalid 'at'"))?;
                Ok(self.frontier_at(at).to_bytes())
            }
            ["v1", "nullifiers"] => {
                // Lab issue #314: the public per-block nullifier lists a wallet
                // subtracts its own spent notes against. Bulk over a range —
                // never a per-nullifier membership query, see [`NullifierPage`].
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
                if to < from {
                    return Err((400, "'to' < 'from'"));
                }
                Ok(nullifier_page(&self.main_chain_discovery(), from, to).to_bytes())
            }
            ["v1", "coinbase"] => {
                // Lab #415: the per-block coinbase facts a mining wallet matches
                // its own rkm against. Bulk over a range; there is no per-key
                // form and there must never be one — see [`CoinbasePage`] for
                // why this needs no privacy read while #188 (a) did.
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
                if to < from {
                    return Err((400, "'to' < 'from'"));
                }
                Ok(coinbase_page(&self.main_chain_discovery(), from, to).to_bytes())
            }
            ["v1", "names"] => {
                // Lab #367: the D2 bulk-sync surface — per-block rider lists a
                // wallet replays into a LOCAL registry. Bulk over a range;
                // resolve-by-name is refused BY NAME below, permanently
                // (name-service-decision D2 — the correlation rule's fourth
                // application after #315/tx-view/explorer).
                if query_u64(query, "name").is_some() || query.contains("name=") {
                    return Err((400, "no resolve-by-name exists, by design (D2): sync the range and resolve locally"));
                }
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
                if to < from {
                    return Err((400, "'to' < 'from'"));
                }
                Ok(names_page(&self.main_chain_discovery(), from, to).to_bytes())
            }
            ["v1", "tree", "leaves"] => {
                // Issue #275 (decision brief B1): the witness source. Served here
                // as well as by `qumbra-node`'s discovery server — stamp rider (2):
                // the routes land in the node repo so ANY full node can serve
                // them, not only T1's single stamped host.
                let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
                Ok(TreeLeaves::page(self.node.commitments_ordered(), from).to_bytes())
            }
            _ => Err((404, "unknown endpoint")),
        }
    }
}

/// The pure router result: response bytes, or an `(http status, message)` error.
pub type RouteResult = Result<Vec<u8>, (u16, &'static str)>;

fn query_u64(query: &str, key: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return v.parse::<u64>().ok();
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Status / anchors wire (new N6 surfaces — versioned, round-trip locked)
// ---------------------------------------------------------------------------

/// Live node status a wallet polls (`/v1/status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub tip_height: u64,
    pub tip_hash: Hash32,
    pub finalized_height: Option<u64>,
    pub commitment_root: Hash32,
    pub commitment_count: u64,
    pub nullifier_count: u64,
    pub pending_count: u64,
}

impl NodeStatus {
    /// `version(0x01) ‖ tip_height(8 LE) ‖ tip_hash(32) ‖ has_final(u8) ‖
    /// [final_height(8 LE) if has] ‖ root(32) ‖ commitment_count(8 LE) ‖
    /// nullifier_count(8 LE) ‖ pending_count(8 LE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        out.extend_from_slice(&self.tip_hash);
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.commitment_root);
        out.extend_from_slice(&self.commitment_count.to_le_bytes());
        out.extend_from_slice(&self.nullifier_count.to_le_bytes());
        out.extend_from_slice(&self.pending_count.to_le_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<NodeStatus, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let tip_height = r.u64()?;
        let tip_hash = r.hash32()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let commitment_root = r.hash32()?;
        let commitment_count = r.u64()?;
        let nullifier_count = r.u64()?;
        let pending_count = r.u64()?;
        r.finish()?;
        Ok(NodeStatus {
            tip_height,
            tip_hash,
            finalized_height,
            commitment_root,
            commitment_count,
            nullifier_count,
            pending_count,
        })
    }
}

/// The valid-anchor set + window context (`/v1/anchors`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSet {
    pub tip_height: u64,
    pub finalized_height: Option<u64>,
    pub max_age_blocks: u64,
    /// Valid anchor roots, newest first.
    pub roots: Vec<Hash32>,
}

impl AnchorSet {
    /// `version(0x01) ‖ tip_height(8) ‖ has_final(u8) ‖ [final_height(8) if has]
    /// ‖ max_age_blocks(8) ‖ n_roots(varint) ‖ [root(32) × n]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.max_age_blocks.to_le_bytes());
        write_varint(&mut out, self.roots.len() as u64);
        for r in &self.roots {
            out.extend_from_slice(r);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<AnchorSet, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let tip_height = r.u64()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let max_age_blocks = r.u64()?;
        let n = r.varint()?;
        let mut roots = Vec::with_capacity(n as usize);
        for _ in 0..n {
            roots.push(r.hash32()?);
        }
        r.finish()?;
        Ok(AnchorSet { tip_height, finalized_height, max_age_blocks, roots })
    }
}

// ---------------------------------------------------------------------------
// The main-chain projections, over a bare `Node`
// ---------------------------------------------------------------------------
//
// These were `NodeRpc` methods until issue #276. They are free functions over
// `&Node` for the same reason `TreeLeaves::page` is a free-standing function
// (issue #275): the deployed binary composes **no `NodeRpc`**, so anything only
// reachable through one is unreachable from `qumbra-node`'s discovery server —
// and a second implementation of the anchor derivation is exactly the drift
// `main_chain_counts`' own doc comment warns about, where miscounting "would
// not fail loudly: it would publish anchors nobody can build a witness
// against." `NodeRpc`'s methods now delegate here, so there is one.

/// The main chain, genesis-first, as stored blocks (walks tip→genesis via
/// `header.prev`, then reverses).
pub fn main_chain_of<C: ChainStore, N: NullifierStore, T: CommitmentStore>(
    node: &Node<C, N, T>,
) -> Vec<StoredBlock> {
    let chain = node.chain();
    let mut out = Vec::new();
    let mut hash = chain.tip_hash();
    loop {
        let Some(block) = chain.block(&hash) else { break };
        let block = block.clone();
        let prev = block.header.prev;
        let height = block.header.height;
        out.push(block);
        if height == 0 {
            break;
        }
        hash = prev;
    }
    out.reverse();
    out
}

/// `(height, commitment-count-after-this-block)` for each main-chain height.
/// See [`NodeRpc::main_chain_counts`]'s doc comment for why this must track
/// `apply_state`'s append schedule exactly.
pub fn main_chain_counts_of<C: ChainStore, N: NullifierStore, T: CommitmentStore>(
    node: &Node<C, N, T>,
) -> Vec<(u64, u64)> {
    let chain = main_chain_of(node);
    let by_height: HashMap<u64, &StoredBlock> =
        chain.iter().map(|b| (b.header.height, b)).collect();
    let mut count = 0u64;
    chain
        .iter()
        .map(|b| {
            let matured = crate::coinbase::matured_coinbase_leaf(b.header.height, |minted_at| {
                by_height.get(&minted_at).map(|a| a.body())
            });
            if matured.is_some() {
                count += 1;
            }
            count += b.txs.iter().map(|t| t.commitments.len() as u64).sum::<u64>();
            (b.header.height, count)
        })
        .collect()
}

/// `(height, root-after-this-block)` for each main-chain height, recomputed
/// from the live tree prefix.
pub fn main_chain_roots_of<C: ChainStore, N: NullifierStore, T: CommitmentStore>(
    node: &Node<C, N, T>,
) -> Vec<(u64, Hash32)> {
    let tree = node.commitments().tree();
    main_chain_counts_of(node)
        .into_iter()
        .map(|(h, c)| (h, digest_bytes(&tree.root_at(c))))
        .collect()
}

/// The set of commitment roots that are valid anchors right now (finalized +
/// within the age window), newest first, plus the window context a wallet
/// needs (`/v1/anchors`).
///
/// **Why a wallet cannot do without this** (issue #276): a valid anchor is a
/// *finalized* root ([`crate::NodeState::is_valid_anchor`]), while the leaf
/// stream's `total` is the live count at the **applied tip**. A wallet that
/// built its witness at the count it just synced to would declare an
/// unfinalized root and be refused `anchor-not-valid` on every net whose
/// finality runs on a cadence. This is how it learns which of its local leaf
/// counts it may legally build at — it matches its own reconstructed roots
/// against this set, so the server still learns nothing positional (the B2
/// rejection holds).
pub fn anchor_set<C: ChainStore, N: NullifierStore, T: CommitmentStore>(
    node: &Node<C, N, T>,
) -> AnchorSet {
    let mut roots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Walk main chain tip→genesis, accumulating leaf counts, and test each
    // height's root for anchor validity.
    for (_, root) in main_chain_roots_of(node).into_iter().rev() {
        if node.is_valid_anchor(&root) && seen.insert(root) {
            roots.push(root);
        }
    }
    AnchorSet {
        tip_height: node.tip_height(),
        finalized_height: node.finalized_height(),
        max_age_blocks: MAX_ANCHOR_AGE_BLOCKS,
        roots,
    }
}

// ---------------------------------------------------------------------------
// The leaf stream (`/v1/tree/leaves` — issue #275, decision brief B1)
// ---------------------------------------------------------------------------

/// The most leaves one `/v1/tree/leaves` response will ever carry.
///
/// The same contract shape as [`MAX_COMPACT_BLOCKS`], for the same reason: `from`
/// is a client-chosen number and the response cost must be bounded by the server,
/// not the request. A full page is `4096 × 32 B = 128 KiB` of leaves plus the
/// ≤19-byte header — smaller than one transaction proof (~136 KB), so a page costs
/// the wire less than the tx it lets a wallet spend. A client that receives
/// exactly this many leaves pages from `from + MAX_TREE_LEAVES`; `total` tells it
/// when to stop. `[devnet-placeholder]` testnet-tunable, NOT frozen — the framing
/// below is what freezes, and it carries `n` explicitly so this bound can move
/// without touching the golden.
pub const MAX_TREE_LEAVES: usize = 4096;

/// One page of the node's commitment-tree leaves, in **authoritative append
/// order** (`/v1/tree/leaves?from=N` — issue #275, decision brief B1).
///
/// This is the witness source for a nodeless wallet: it maintains a local tree
/// from these pages and computes `auth_path` itself, so the server learns which
/// IP syncs leaves and never which positions matter to it — the exact privacy
/// line that rejected the server-computed-witness alternative (brief B2). The
/// order served is the order [`crate::Node::apply_state`] appended: **the
/// coinbase leaf a block matures goes in before that block's own transaction
/// commitments** (issue #102), and the client never recomputes maturity — a
/// compact-only reconstruction has wrong *positions*, not just holes, which is
/// the gap this wire exists to close.
///
/// Self-verifying end to end: a wrong or reordered stream yields a wrong local
/// root, which fails the anchor check at submission. A lying server can censor
/// (the already-accepted posture) but cannot make a wallet spend against a fake
/// tree undetected.
///
/// # Wire (GOLDEN — stamp rider (1))
///
/// `version ‖ from(8 LE) ‖ total(8 LE) ‖ n(varint) ‖ [leaf(32) × n]`
///
/// This is an interop-O5-class *served* wire, so it freezes deliberately, with
/// byte-exact vectors like `/v1/compact`'s, not by accident — see
/// `golden_bytes_lock_the_leaf_stream_framing`. `from` is echoed so a paging
/// client cannot misattribute a response; `total` is the tree's live leaf count,
/// which is both the loop condition ("page until `from + n == total`") and the
/// honest answer to a `from` beyond the tree (an **empty page carrying `total`**,
/// never an error — "you are ahead of me" is a meaningful state during a reorg
/// or against a lagging server, and the wallet's own root check is what judges
/// it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeLeaves {
    /// Index of `leaves[0]` in the tree (echo of the request's `from`).
    pub from: u64,
    /// Leaves the serving tree holds right now.
    pub total: u64,
    /// At most [`MAX_TREE_LEAVES`] commitments, append order, as the 32-byte cm
    /// wire bytes the block carried (what [`crate::Node`] appends).
    pub leaves: Vec<Hash32>,
}

impl TreeLeaves {
    /// The page at `from` over an append-ordered leaf slice — the one projection
    /// both servers use (`NodeRpc::route` here, and `qumbra-node`'s discovery
    /// server over its snapshot), so there is no second implementation of the
    /// clamp arithmetic to drift.
    pub fn page(leaves: &[Hash32], from: u64) -> TreeLeaves {
        let total = leaves.len() as u64;
        let start = from.min(total) as usize;
        let end = (start + MAX_TREE_LEAVES).min(leaves.len());
        TreeLeaves { from, total, leaves: leaves[start..end].to_vec() }
    }

    /// `version ‖ from(8 LE) ‖ total(8 LE) ‖ n(varint) ‖ [leaf(32) × n]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        write_varint(&mut out, self.leaves.len() as u64);
        for leaf in &self.leaves {
            out.extend_from_slice(leaf);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<TreeLeaves, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let from = r.u64()?;
        let total = r.u64()?;
        let n = r.varint()?;
        // The count is attacker-adjacent input on a served wire: cap the
        // allocation by what the remaining bytes could actually hold, so a tiny
        // payload claiming 2^60 leaves is a `Truncated` refusal and not a giant
        // allocation.
        let mut leaves = Vec::with_capacity((n as usize).min(b.len() / 32));
        for _ in 0..n {
            leaves.push(r.hash32()?);
        }
        r.finish()?;
        Ok(TreeLeaves { from, total, leaves })
    }
}

// ---------------------------------------------------------------------------
// The nullifier stream (`/v1/nullifiers` — lab issue #314)
// ---------------------------------------------------------------------------

/// The `/v1/nullifiers` page for `[from, to]` over an **ascending** main-chain
/// projection — the per-block nullifier lists a wallet subtracts its own spent
/// notes against (lab issue #314).
///
/// The wire itself lives in [`qlab_cbserver::codec::NullifierPage`], with
/// `/v1/compact`'s version byte and beside `/v1/compact`'s encoder, because it
/// is that route's sibling by every structural test: same projection, same range
/// paging, same light client — and both this node and the reference server serve
/// it, so a wallet pointed at either can subtract its spends. This function is
/// only the projection step, and it is the one both servers here call
/// (`NodeRpc::route` and `qumbra-node`'s discovery server over its snapshot), so
/// there is no second implementation of the bound to drift.
///
/// The nullifiers come from [`BlockDiscovery::nullifiers`] — `StoredTx`'s own
/// section, cloned — so there is no encoder between the block and the served
/// bytes and no second source for them.
pub fn nullifier_page(blocks: &[BlockDiscovery], from: u64, to: u64) -> NullifierPage {
    NullifierPage::page(
        blocks
            .iter()
            .map(|b| BlockNullifiers { height: b.height, nullifiers: b.nullifiers.clone() }),
        from,
        to,
    )
}

/// The `/v1/coinbase` page for `[from, to]` over an **ascending** main-chain
/// projection — the per-block coinbase facts a mining wallet matches its own
/// `rkm` against (lab #415).
///
/// `nullifier_page`'s twin in every respect, and here for the same reason: one
/// implementation of the bound, called by both this crate's router and
/// `qumbra-node`'s discovery server over its snapshot, so there is nothing to
/// drift. The facts come from [`BlockDiscovery`] — the block's own fields,
/// cloned — so there is no encoder between the block and the served bytes.
///
/// 🔴 **What is deliberately NOT here: the note's value.** The route serves the
/// three numbers the value is a function of and lets the holder run
/// [`crate::coinbase::coinbase_note_parts_for`] — the dispatcher `apply_state`
/// resolves through when it appends the leaf, given the same
/// [`qlab_devnet::forms::GenesisForm`]. Deriving it here would put a consensus
/// rule on the serving path and would leave the `qlab-cbserver` reference
/// server — which cannot depend on this crate — stating a rule of its own
/// invention.
///
/// 🔴 **And the form is not on this wire either.** This comment named the v4
/// `coinbase_note_parts` and said it was "the same call `apply_state` makes",
/// which stopped being true at the T2 mint: `apply_state` has been form-aware
/// since #470 stage 4a. A holder reading the old sentence and calling the v4
/// function derives commitments that are in no v5 tree — lab #566, which is
/// exactly what `qumbra-wallet` did. The route's honesty property below still
/// holds, with the form as its precondition: **the served facts reconstruct the
/// leaf this node appended, provided the holder derives under the net's own
/// form.** Where the holder gets that form is the open question on #566.
pub fn coinbase_page(blocks: &[BlockDiscovery], from: u64, to: u64) -> CoinbasePage {
    CoinbasePage::page(
        blocks.iter().map(|b| BlockCoinbase {
            height: b.height,
            coinbase_rkm: b.coinbase_rkm,
            coinbase: b.coinbase,
            fees: b.fees,
            name_burn: b.name_burn,
        }),
        from,
        to,
    )
}

/// The `/v1/names` projection step (lab #367) — `nullifier_page`'s twin, and
/// for the same reason it lives here: one implementation of the bound, called
/// by both servers, no drift. The riders come from [`BlockDiscovery::riders`]
/// — `StoredTx`'s own section, cloned, no encoder in between.
pub fn names_page(blocks: &[BlockDiscovery], from: u64, to: u64) -> NamesPage {
    NamesPage::page(
        blocks.iter().map(|b| BlockNames { height: b.height, riders: b.riders.clone() }),
        from,
        to,
    )
}

/// A tiny cursor reusing cbserver's `CodecError` vocabulary + varint, so the N6
/// wires reject exactly like the ratified ones (unknown version, truncation,
/// trailing bytes).
pub(crate) struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    /// Consume the version byte, requiring **exactly** [`RPC_VERSION`].
    ///
    /// This is the strict §0 check and every node-side decode uses it. It is
    /// expressed through [`Self::version_in`] so there is one implementation of
    /// "read a byte, decide, or fail" rather than two that could drift.
    pub(crate) fn version(&mut self) -> Result<(), CodecError> {
        self.version_in(&[RPC_VERSION]).map(|_| ())
    }

    /// Consume the version byte, requiring membership in `allowed`, and return it
    /// (issue #212).
    ///
    /// 🔴 **This is not a relaxation of reject-unknown.** `allowed` is always a
    /// short, named, compile-time list of versions whose layout this build knows —
    /// the only caller passing more than one element is
    /// [`crate::telemetry::Telemetry::from_bytes_compat`], with
    /// [`crate::telemetry::READABLE_TELEMETRY_VERSIONS`]. A version outside the list
    /// is still [`CodecError::BadVersion`], and the alternative that was considered
    /// and rejected — turning this into a `>=` comparison — does not work anyway:
    /// the fields after the prefix are not skippable, so an old reader would fail on
    /// [`Self::finish`]'s trailing-byte check instead of on the version, i.e. the
    /// same blindness reported under a misleading error.
    pub(crate) fn version_in(&mut self, allowed: &[u8]) -> Result<u8, CodecError> {
        let v = *self.b.get(self.pos).ok_or(CodecError::Truncated { what: "version" })?;
        self.pos += 1;
        if !allowed.contains(&v) {
            return Err(CodecError::BadVersion { got: v });
        }
        Ok(v)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, CodecError> {
        let v = *self.b.get(self.pos).ok_or(CodecError::Truncated { what: "u8" })?;
        self.pos += 1;
        Ok(v)
    }
    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        let end = self.pos + 8;
        let slice = self.b.get(self.pos..end).ok_or(CodecError::Truncated { what: "u64" })?;
        self.pos = end;
        Ok(u64::from_le_bytes(slice.try_into().unwrap()))
    }
    pub(crate) fn hash32(&mut self) -> Result<Hash32, CodecError> {
        let end = self.pos + 32;
        let slice = self.b.get(self.pos..end).ok_or(CodecError::Truncated { what: "hash32" })?;
        self.pos = end;
        Ok(slice.try_into().unwrap())
    }
    #[allow(dead_code)]
    pub(crate) fn varint(&mut self) -> Result<u64, CodecError> {
        read_varint(self.b, &mut self.pos)
    }
    pub(crate) fn finish(&self) -> Result<(), CodecError> {
        if self.pos != self.b.len() {
            return Err(CodecError::TrailingBytes { remaining: self.b.len() - self.pos });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Localhost HTTP serving (GET reads only — submit is the in-process API)
// ---------------------------------------------------------------------------

/// A running node-RPC HTTP server: bound address + worker thread. Read-only over
/// the wire (GET); the state is shared behind a mutex so an owner can keep
/// submitting / applying blocks while it serves. Mirrors
/// [`qlab_cbserver::server`], localhost only.
pub struct RpcServerHandle {
    addr: SocketAddr,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
    served: Arc<AtomicU64>,
}

impl RpcServerHandle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Serve `rpc`'s GET endpoints on `127.0.0.1:0`. The shared `Arc<Mutex<..>>`
/// lets the caller keep mutating node state (submit / apply) between requests.
pub fn serve<C, N, T>(rpc: Arc<Mutex<NodeRpc<C, N, T>>>) -> RpcServerHandle
where
    C: ChainStore + Send + 'static,
    N: NullifierStore + Send + 'static,
    T: CommitmentStore + Send + 'static,
{
    use tiny_http::{Method, Response, Server};
    let server = Arc::new(Server::http("127.0.0.1:0").expect("bind localhost ephemeral port"));
    let addr = server.server_addr().to_ip().expect("tcp listener has an ip address");
    let served = Arc::new(AtomicU64::new(0));

    let worker_server = Arc::clone(&server);
    let worker_served = Arc::clone(&served);
    let thread = std::thread::spawn(move || {
        for request in worker_server.incoming_requests() {
            worker_served.fetch_add(1, Ordering::Relaxed);
            if *request.method() != Method::Get {
                let _ = request.respond(Response::from_string("method not allowed").with_status_code(405));
                continue;
            }
            let url = request.url().to_string();
            let response = rpc.lock().expect("rpc mutex poisoned").route(&url);
            let _ = match response {
                Ok(bytes) => request.respond(Response::from_data(bytes)),
                Err((code, msg)) => request.respond(Response::from_string(msg).with_status_code(code)),
            };
        }
    });

    RpcServerHandle { addr, server, thread: Some(thread), served }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::fees::posted_fee;
    use crate::node::{genesis_block, genesis_block_for, MemNode};
    use qlab_cbserver::codec::decode_compact_response;
    use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::forms::GenesisForm;
    use qlab_devnet::header::BlockHeader;
    use qlab_note::wire::{ClueSlot, CompactEntry};

    // A verifier that accepts iff the proof bytes are exactly b"ok".
    struct OkVerifier;
    impl TxVerifier for OkVerifier {
        fn verify_tx(&self, entry: &TxEntry) -> bool {
            entry.proof == b"ok"
        }
    }

    fn cm_bytes(seed: u8) -> Hash32 {
        [seed; 32]
    }

    fn recip(ct_base: u8, cms: &[u8]) -> RecipientDiscovery {
        let ct: [u8; qlab_note::kem::CT_LEN] =
            core::array::from_fn(|i| ct_base.wrapping_add((i % 251) as u8));
        let entries = cms
            .iter()
            .map(|&c| CompactEntry { cm: cm_bytes(c), tag: [c ^ 0xa5; 8], clue: ClueSlot::Empty })
            .collect();
        RecipientDiscovery {
            bundle: RecipientBundle { ct, entries },
            payloads: cms.iter().map(|&c| vec![c; 120]).collect(),
        }
    }

    /// The one ct pattern every fixture transaction commits to. Since issue #188
    /// baton 2 a fixture cannot pick its discovery group independently of its
    /// transaction: the group is IN the transaction, and `submit_tx` refuses a
    /// submission whose bundles are not the committed ones byte for byte.
    const CT_BASE: u8 = 0x10;

    /// A transaction whose committed discovery group is the real bundle
    /// [`disc_for`] hands the RPC — the pairing every honest submission has.
    fn tx_with(anchor: Hash32, nfs: &[u8], cms: &[u8], fee: u64) -> TxEntry {
        let disc = recip(CT_BASE, cms);
        TxEntry::new(
            b"ok".to_vec(),
            TxPublic {
                anchor,
                nullifiers: nfs.iter().map(|&n| [n; 32]).collect(),
                commitments: cms.iter().map(|&c| cm_bytes(c)).collect(),
                bucket: ArityBucket::TwoByTwo,
                fee,
            },
            // Issue #188 (a): the payloads are committed alongside the bundles,
            // and they must be the SAME ones `disc_for` hands the RPC — the
            // fixture cannot pick them independently of its transaction any more
            // than it can pick its bundle, because `submit_tx` now compares both
            // halves byte for byte.
            &[disc.bundle],
            &disc.payloads,
        )
    }

    /// The submitted artifacts (bundle + AEAD payloads) matching [`tx_with`]'s
    /// committed group.
    fn disc_for(cms: &[u8]) -> TxDiscovery {
        TxDiscovery { recipients: vec![recip(CT_BASE, cms)] }
    }

    // A node with genesis finalized so anchors become valid, plus one applied
    // block, returned wrapped in NodeRpc. Returns (rpc, genesis_root, anchor).
    fn rpc_with_finalized_genesis() -> (MemNodeRpc, Hash32) {
        let genesis = genesis_block(1_000, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).unwrap().is_recorded());
        let anchor = node.commitment_root(); // empty-tree root, finalized at height 0
        assert!(node.is_valid_anchor(&anchor), "genesis root is a valid anchor once finalized");
        (NodeRpc::new(node), anchor)
    }

    fn rpc_for_form_with_finalized_genesis(form: GenesisForm) -> (MemNodeRpc, Hash32) {
        let genesis = genesis_block_for(form, 1_000, 0);
        let mut node = MemNode::in_memory_for(form, genesis);
        let ghash = node.chain().genesis_block_hash();
        assert!(node.finalize(ghash).unwrap().is_recorded());
        let anchor = node.commitment_root();
        assert!(node.is_valid_anchor(&anchor));
        (NodeRpc::new(node), anchor)
    }

    /// S8: with nothing finalized, the finalized-age telemetry field is 0, NOT the
    /// tip−genesis fallback (which read as a huge absolute value in Phase B-lite).
    #[test]
    fn telemetry_age_is_zero_when_nothing_finalized() {
        let node = MemNode::in_memory(genesis_block(1_000, 0));
        let rpc = NodeRpc::new(node);
        let t = rpc.telemetry();
        assert_eq!(t.finalized_height, None, "fresh node has no finalized head");
        assert_eq!(t.last_finalized_age_secs, 0, "age is 0 when nothing is finalized");
    }

    // Apply one coinbase-only block with an explicit timestamp; returns its hash.
    // Issue #73's shape needs a wall-clock-magnitude tip over the ts=0 genesis.
    fn apply_block_at(node: &mut MemNode, timestamp: u64) -> Hash32 {
        let tip_hash = node.tip_hash();
        let parent = node.chain().block(&tip_hash).expect("tip block stored").header();
        let height = parent.height + 1;
        let body = BlockBody::from_single_payee(vec![], height, [height, 2, 3, 4]);
        let header = BlockHeader::child_of(&parent, timestamp, 1_000, body.commitment());
        let hash = header.header_hash();
        node.apply_block(header, body, &OkVerifier).expect("block applies");
        hash
    }

    /// Issue #73: while the finalized head is still GENESIS (the bootstrap
    /// finalization every fresh net starts from), the age must not difference the
    /// tip against genesis's `timestamp = 0` placeholder — on a WallClock net that
    /// read as the wall clock itself (`age_s=1785352360` on all four nodes of the
    /// #119 run, for the ~7 minutes before slot 8 finalized). The value is 0 and
    /// the rendering `-`; the field starts speaking at the first non-genesis
    /// finalization. S8 closed the `None` case; this closes `Some(0)`.
    #[test]
    fn telemetry_age_is_zero_while_the_finalized_head_is_genesis() {
        let (mut rpc, _anchor) = rpc_with_finalized_genesis();
        // A wall-clock-magnitude tip timestamp over the ts=0 genesis — the exact
        // shape of the live defect.
        let h1 = apply_block_at(rpc.node_mut(), 1_785_352_360);
        let t = rpc.telemetry();
        assert_eq!(t.finalized_height, Some(0), "the finalized head is genesis");
        assert_eq!(
            t.last_finalized_age_secs, 0,
            "age must never be tip_ts − genesis placeholder"
        );
        assert_eq!(t.age_field(), "-", "rendered as refusal, not as a confident number");

        // The boundary: the first non-genesis block finalizes ⇒ a real age, from
        // real timestamps on both ends of the subtraction.
        let _h2 = apply_block_at(rpc.node_mut(), 1_785_352_435); // 75 s later
        assert!(rpc.node_mut().finalize(h1).unwrap().is_recorded(), "height 1 finalizes");
        let t = rpc.telemetry();
        assert_eq!(t.finalized_height, Some(1));
        assert_eq!(t.last_finalized_age_secs, 75, "tip_ts − finalized_ts, both real");
        assert_eq!(t.age_field(), "75");
    }

    #[test]
    fn submit_accepts_valid_tx_and_records_discovery() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        let disc = disc_for(&[10, 11]);
        let out = rpc.submit_tx(tx.clone(), disc, &OkVerifier);
        assert!(matches!(out, SubmitOutcome::Accepted(_)));
        assert_eq!(rpc.pending_len(), 1);
        // Duplicate submit is a no-op.
        let disc2 = disc_for(&[10, 11]);
        assert_eq!(rpc.submit_tx(tx, disc2, &OkVerifier), SubmitOutcome::Duplicate);
    }

    /// Lab #612's loaded-gun check: `NodeRpc` has no production submit caller,
    /// but it owns a real form-keyed `Node`. Derive admission from that form so
    /// a future composition cannot accept v5 blocks while refusing their native
    /// name riders through this API. The v4 half is the opposite mutation lock.
    #[test]
    fn submit_tx_uses_the_wrapped_nodes_rider_boundary() {
        use qlab_devnet::names::NameOp;

        let (mut v5, v5_anchor) =
            rpc_for_form_with_finalized_genesis(GenesisForm::V5);
        let v5_commit = tx_with(
            v5_anchor,
            &[0x61],
            &[0x71],
            posted_fee(ArityBucket::TwoByTwo),
        )
        .with_name_op(&NameOp::Commit { commit: [0xB5; 32] });
        assert!(matches!(
            v5.submit_tx(v5_commit, disc_for(&[0x71]), &OkVerifier),
            SubmitOutcome::Accepted(_)
        ));

        let (mut v4, v4_anchor) =
            rpc_for_form_with_finalized_genesis(GenesisForm::V4);
        let v4_commit = tx_with(
            v4_anchor,
            &[0x62],
            &[0x72],
            posted_fee(ArityBucket::TwoByTwo),
        )
        .with_name_op(&NameOp::Commit { commit: [0xB6; 32] });
        assert_eq!(
            v4.submit_tx(v4_commit, disc_for(&[0x72]), &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::RiderInvalid)
        );
    }

    #[test]
    fn submit_rejects_each_bad_condition() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);

        // Bad anchor.
        let bad_anchor = tx_with([0xEE; 32], &[1], &[10], fee);
        let d = disc_for(&[10]);
        assert_eq!(
            rpc.submit_tx(bad_anchor, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::AnchorNotValid)
        );

        // Wrong fee.
        let wrong_fee = tx_with(anchor, &[1], &[10], fee + 1);
        let d = disc_for(&[10]);
        assert_eq!(
            rpc.submit_tx(wrong_fee, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::WrongFee { expected: fee, got: fee + 1 })
        );

        // Repeated nullifier in-tx.
        let dup_nf = tx_with(anchor, &[5, 5], &[10, 11], fee);
        let d = disc_for(&[10, 11]);
        assert_eq!(
            rpc.submit_tx(dup_nf, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::NullifierRepeatedInTx)
        );

        // Discovery mismatch: the submitted bundle is not the transaction's own
        // committed group. Both halves are exercised — a different cm here, and a
        // same-cm-different-ct case in
        // `submit_refuses_artifacts_that_are_not_the_committed_group`.
        let mismatch = tx_with(anchor, &[1], &[10], fee);
        let d = TxDiscovery { recipients: vec![recip(CT_BASE, &[99])] };
        assert_eq!(
            rpc.submit_tx(mismatch, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::DiscoveryMismatch)
        );

        // Bad proof (verifier rejects).
        let mut bad_proof = tx_with(anchor, &[1], &[10], fee);
        bad_proof.proof = b"nope".to_vec();
        let d = disc_for(&[10]);
        assert_eq!(
            rpc.submit_tx(bad_proof, d, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::ProofInvalid)
        );

        assert_eq!(rpc.pending_len(), 0, "no rejected tx is pended");
    }

    #[test]
    fn submit_rejects_pending_and_spent_nullifiers() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let a = tx_with(anchor, &[7], &[10], fee);
        assert!(matches!(
            rpc.submit_tx(a, disc_for(&[10]), &OkVerifier),
            SubmitOutcome::Accepted(_)
        ));
        // A second tx reusing nullifier 7 conflicts with the pending reservation.
        let b = tx_with(anchor, &[7], &[11], fee);
        assert_eq!(
            rpc.submit_tx(b, disc_for(&[11]), &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::NullifierPending)
        );
    }

    #[test]
    fn status_and_anchors_roundtrip_and_reflect_state() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        rpc.submit_tx(tx, disc_for(&[10, 11]), &OkVerifier);

        let s = rpc.status();
        assert_eq!(s.tip_height, 0);
        assert_eq!(s.pending_count, 1);
        assert_eq!(NodeStatus::from_bytes(&s.to_bytes()).unwrap(), s, "status round-trips");

        let a = rpc.anchors();
        assert!(a.roots.contains(&anchor), "finalized genesis root is a valid anchor");
        assert_eq!(a.max_age_blocks, MAX_ANCHOR_AGE_BLOCKS);
        assert_eq!(AnchorSet::from_bytes(&a.to_bytes()).unwrap(), a, "anchors round-trip");
    }

    #[test]
    fn telemetry_endpoint_reflects_state_and_injected_net_facts() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        // Inject the network half (peers, epoch) the node cannot observe itself.
        rpc.set_net_facts(4, 2);
        // …and the checkpoint-identity half (issue #117), which lives in the
        // committee finality tracker and the never-double-sign ledgers.
        assert_eq!(rpc.telemetry().finalized_id, None, "absent until injected");
        rpc.set_checkpoint_facts(CheckpointFacts {
            finalized_id: Some(0x3f1a_9c2b_0d41),
            signed: Some(LocalCommitment { slot: 0, id: Some(0x3f1a_9c2b_0d41) }),
        });
        let tx = tx_with(anchor, &[1, 2], &[10, 11], posted_fee(ArityBucket::TwoByTwo));
        rpc.submit_tx(tx, disc_for(&[10, 11]), &OkVerifier);

        let t = rpc.telemetry();
        // Genesis finalized at height 0, tip 0 ⇒ Final, no stall.
        assert_eq!(t.finality_status, qlab_devnet::ebbflow::FinalityStatus::Final);
        assert_eq!(t.tip_height, 0);
        assert_eq!(t.finalized_height, Some(0));
        assert_eq!(t.stall_depth, 0);
        assert_eq!(t.peer_count, 4, "injected peer count surfaces");
        assert_eq!(t.epoch, 2, "injected epoch surfaces");
        assert_eq!(t.mempool_size, 1, "one pending tx");
        assert_eq!(t.fid_field(), "3f1a9c2b0d41", "injected checkpoint identity surfaces");
        assert_eq!(t.sslot_field(), "0");
        assert_eq!(t.sid_field(), "3f1a9c2b0d41");
        assert_eq!(Telemetry::from_bytes(&t.to_bytes()).unwrap(), t, "telemetry round-trips");

        // The `/v1/telemetry` route serves exactly those bytes.
        let served = rpc.route("/v1/telemetry").unwrap();
        assert_eq!(served, t.to_bytes());
        assert_eq!(Telemetry::from_bytes(&served).unwrap(), t);
    }

    #[test]
    fn wires_reject_bad_version_and_trailing() {
        let (rpc, _) = rpc_with_finalized_genesis();
        let mut sb = rpc.status().to_bytes();
        let good = sb.clone();
        assert_eq!(good[0], RPC_VERSION);
        sb[0] = 0x09;
        assert!(matches!(NodeStatus::from_bytes(&sb), Err(CodecError::BadVersion { got: 9 })));
        let mut extra = good.clone();
        extra.push(0xff);
        assert!(matches!(NodeStatus::from_bytes(&extra), Err(CodecError::TrailingBytes { .. })));
        assert!(NodeStatus::from_bytes(&good[..good.len() - 1]).is_err());

        let mut ab = rpc.anchors().to_bytes();
        let good_a = ab.clone();
        ab[0] = 0x09;
        assert!(matches!(AnchorSet::from_bytes(&ab), Err(CodecError::BadVersion { got: 9 })));
        let mut extra_a = good_a.clone();
        extra_a.push(0);
        assert!(matches!(AnchorSet::from_bytes(&extra_a), Err(CodecError::TrailingBytes { .. })));
    }

    // ---- the leaf stream (`/v1/tree/leaves`, issue #275) ---------------------

    fn hex32(b: &Hash32) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// GOLDEN BYTES — the leaf-stream framing (stamp rider (1)): this is an
    /// interop-O5-class *served* wire, so it freezes deliberately, with byte-exact
    /// vectors like `/v1/compact`'s, not by accident. A fixed page; we assert the
    /// exact field bytes, the exact total length, and a Keccak-256 digest over the
    /// whole serialization. Any framing drift breaks this test.
    #[test]
    fn golden_bytes_lock_the_leaf_stream_framing() {
        let page =
            TreeLeaves { from: 2, total: 5, leaves: vec![[0xAA; 32], [0xBB; 32], [0xCC; 32]] };
        let bytes = page.to_bytes();

        // version(1) + from(8) + total(8) + n(1, varint) + 3 × leaf(32) = 114.
        assert_eq!(bytes.len(), 114, "golden total length");
        assert_eq!(bytes[0], 0x07, "golden version — RPC_VERSION at the #553 mine-payee bump");
        assert_eq!(&bytes[1..9], &2u64.to_le_bytes(), "golden from (LE)");
        assert_eq!(&bytes[9..17], &5u64.to_le_bytes(), "golden total (LE)");
        assert_eq!(bytes[17], 0x03, "golden n (varint)");
        assert_eq!(&bytes[18..50], &[0xAA; 32], "golden leaf 0");
        assert_eq!(&bytes[50..82], &[0xBB; 32], "golden leaf 1");
        assert_eq!(&bytes[82..114], &[0xCC; 32], "golden leaf 2");

        let digest = keccak256(&bytes);
        assert_eq!(
            hex32(&digest),
            "3b0b2aa648e527d99d1c1e7eb68a731f6cf539a5b40a83d5be53c89f268085ec",
            "GOLDEN digest — update ONLY with an intentional, documented framing change \
             (lab #553: RPC_VERSION 0x06 -> 0x07, the leaf stream's version byte moved)"
        );

        assert_eq!(TreeLeaves::from_bytes(&bytes).unwrap(), page, "and it round-trips");

        // The empty page — the "you are ahead of me" answer — is part of the
        // framing too: header only, n = 0.
        let empty = TreeLeaves { from: 9, total: 4, leaves: vec![] };
        let ebytes = empty.to_bytes();
        assert_eq!(ebytes.len(), 18, "golden empty-page length");
        assert_eq!(ebytes[17], 0x00, "golden empty-page n");
        assert_eq!(TreeLeaves::from_bytes(&ebytes).unwrap(), empty);
    }

    // ---- the nullifier stream (`/v1/nullifiers`, lab issue #314) -------------
    //
    // The wire, its golden vectors, its rejections and its page bound are
    // `qlab_cbserver::codec`'s (see `nullifier_page`). What is this crate's, and
    // is tested here, is the PROJECTION and the ROUTE.

    /// 🔴 **Projection discipline (lab issue #314 scope item 1): the served
    /// nullifiers are the stored block's own nullifier section, cloned.**
    ///
    /// Asserted against the stored block rather than against a value this test
    /// computed a second way — the claim is *these are the same bytes*, and only
    /// the block can say so. A coinbase-only block is present and empty, which
    /// is the answer a subtracting client needs to distinguish "spent nothing"
    /// from "not served".
    #[test]
    fn route_serves_the_stored_blocks_nullifier_section_verbatim() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let a = tx_with(anchor, &[1, 2], &[10, 11], fee);
        let b = tx_with(anchor, &[3, 4], &[12, 13], fee);
        apply_block_with(rpc.node_mut(), vec![a, b]);
        apply_block_with(rpc.node_mut(), vec![]); // a block that spends nothing

        let served = rpc.route("/v1/nullifiers?from=0&to=2").unwrap();
        let page = NullifierPage::from_bytes(&served).expect("the served bytes are the wire");
        assert_eq!((page.from, page.to), (0, 2));
        assert_eq!(page.blocks.len(), 3, "genesis, the tx block, the empty block — all present");
        assert_eq!(page.blocks[0].height, 0);
        assert!(page.blocks[0].nullifiers.is_empty(), "genesis spends nothing");

        let stored = {
            let chain = rpc.node().chain();
            let mut hash = chain.tip_hash();
            // height 1 is the tx block: walk back one from the tip.
            hash = chain.block(&hash).expect("tip stored").header.prev;
            chain.block(&hash).expect("the tx block is stored").clone()
        };
        let committed: Vec<Hash32> =
            stored.txs.iter().flat_map(|t| t.nullifiers.iter().copied()).collect();
        assert_eq!(committed.len(), 4, "two 2-nullifier transactions");
        assert_eq!(
            page.blocks[1].nullifiers, committed,
            "the served list IS the stored block's nullifier section, in block order"
        );

        assert_eq!(page.blocks[2].height, 2);
        assert!(
            page.blocks[2].nullifiers.is_empty(),
            "a coinbase-only block is SERVED and empty — never omitted"
        );
    }

    /// The route's refusals are `/v1/compact`'s refusals — a bound that is
    /// missing or unparseable is a 400, an inverted range is a 400. An empty
    /// success in either case would be a wallet quoting a balance it could not
    /// have subtracted against.
    #[test]
    fn the_nullifier_route_refuses_bad_bounds_rather_than_answering_empty() {
        let (rpc, _) = rpc_with_finalized_genesis();
        assert_eq!(rpc.route("/v1/nullifiers"), Err((400, "missing/invalid 'from'")));
        assert_eq!(rpc.route("/v1/nullifiers?from=0"), Err((400, "missing/invalid 'to'")));
        assert_eq!(rpc.route("/v1/nullifiers?from=zz&to=1"), Err((400, "missing/invalid 'from'")));
        assert_eq!(rpc.route("/v1/nullifiers?from=5&to=1"), Err((400, "'to' < 'from'")));
        // And there is no per-nullifier membership form of this route: an
        // unknown path stays a 404, so a probe cannot be answered by accident.
        assert!(matches!(rpc.route("/v1/nullifier?nf=00"), Err((404, _))));
    }

    // ---- the coinbase stream (`/v1/coinbase`, lab #415) ---------------------
    //
    // The wire, its goldens, its rejections and its page bound are
    // `qlab_cbserver::codec`'s. What is this crate's, and is tested here, is the
    // PROJECTION, the ROUTE, and the one property the whole route exists for:
    // that what it serves reconstructs the note the node itself appended.

    /// 🔴 **The property the route exists for: the served facts reconstruct the
    /// leaf `apply_state` appended — under the chain's own genesis form.**
    ///
    /// A wallet holding this page runs
    /// [`crate::coinbase::coinbase_note_parts_for`] — the dispatcher
    /// [`crate::coinbase::coinbase_note_for`] resolves through, and the one
    /// `apply_state`'s append path reaches via `matured_coinbase_leaf_for` — and
    /// the commitment it derives must be a leaf of the node's own tree. This is
    /// what makes the value *checkable* rather than trusted: a server that lied
    /// about `coinbase` or `fees` would produce a `cm` that is in no tree, and the
    /// spend would refuse instead of proving something false.
    ///
    /// 🔴 **The form is a precondition of that property, and this test used to
    /// hide it.** It said "a wallet holding this page runs `coinbase_note_parts`
    /// — the same call", naming the **v4** derivation, and ran on a v4 chain, so
    /// it passed while the sentence stopped being true at the T2 mint. Lab #566:
    /// `qumbra-wallet` called exactly that v4 function on a v5 chain and every
    /// note it reconstructed was a commitment in no tree — 131 matured notes a
    /// miner was told they had and could not move. **The route is not what was
    /// wrong** (it serves the block's own bytes and derives nothing), but this
    /// test was the check that should have caught the holder, and being V4-only
    /// is why it did not. It now takes the form from the node under test, so a
    /// form-blind derivation cannot pass here again; the v5 end of the property
    /// is pinned in `coinbase.rs` by
    /// `the_served_five_facts_reconstruct_the_appended_note_under_either_form`
    /// and, at the holder, by `qumbra-wallet`'s
    /// `a_v5_chains_mined_note_is_the_leaf_the_node_appended_and_v4s_is_not`.
    ///
    /// It is also the check that would have caught the task book's original
    /// premise — "amount = the emission schedule's value at that height" — which
    /// is neither the miner's share nor inclusive of the fees the block below
    /// carries.
    #[test]
    fn the_served_coinbase_facts_reconstruct_the_leaf_the_node_appended() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        // A block with transactions, so `fees` is non-zero and the difference
        // between "the schedule" and "what the miner took" is observable.
        apply_block_with(rpc.node_mut(), vec![tx_with(anchor, &[1, 2], &[10, 11], fee)]);

        let page = CoinbasePage::from_bytes(&rpc.route("/v1/coinbase?from=1&to=1").unwrap())
            .expect("the served bytes are the wire");
        let blk = &page.blocks[0];
        assert_eq!(blk.fees, fee, "the block's own fees are on the wire");

        // The stored block is the authority on all five facts.
        let stored = {
            let chain = rpc.node().chain();
            let hash = chain.tip_hash();
            chain.block(&hash).expect("the tip is stored").clone()
        };
        let body = stored.body();
        let (body_coinbase, body_rkm) = body.single_payee_parts().expect("current-cap body");
        assert_eq!(blk.coinbase_rkm, body_rkm);
        assert_eq!(blk.coinbase, body_coinbase);
        assert_eq!(blk.fees, body.total_fees());
        assert_eq!(blk.name_burn, body.total_name_burn());

        // Reconstructed from the served facts alone — no body, as a wallet, and
        // under the form of the node that served them rather than a literal.
        let form = rpc.node().form();
        let note = crate::coinbase::coinbase_note_parts_for(
            form,
            blk.height,
            blk.coinbase_rkm,
            blk.coinbase,
            blk.fees,
            blk.name_burn,
        )
        .expect("a minting block mints a note");
        assert_eq!(
            Some(&note),
            crate::coinbase::coinbase_note_for(form, 1, &body).as_ref(),
            "the wallet's note IS the applier's note — same dispatcher, same form"
        );

        // 🔴 …and the schedule alone would NOT have produced it: the value is
        // the miner's share plus this block's fees.
        assert_eq!(note.value, crate::RewardSplit::of(body.coinbase_total()).miner + fee);
        assert_ne!(note.value, body.coinbase_total(), "the whole emission is not the miner's");
        assert_ne!(
            note.value,
            crate::RewardSplit::of(body.coinbase_total()).miner,
            "and the fees are part of it — the task book's rule would have been short by {fee}"
        );

        // The leaf is the node's own, once maturity puts it in the tree.
        let leaf = digest_bytes(&note.commitment());
        assert_eq!(
            leaf,
            crate::coinbase::coinbase_note_leaf_for(form, 1, &body).expect("mints"),
            "and the leaf the tree gets is the leaf of that same note"
        );
    }

    /// Projection discipline, `route_serves_the_stored_blocks_nullifier_section_verbatim`'s
    /// twin: every held height in range is present — **including a non-minting
    /// block**, whose `[0; 4]` payee and zero coinbase are a real answer and not
    /// an omission. A hole here is indistinguishable from "the payee was not you".
    #[test]
    fn the_coinbase_route_serves_every_held_height_including_the_non_minting_ones() {
        let (mut rpc, _anchor) = rpc_with_finalized_genesis();
        apply_block_with_shape(rpc.node_mut(), vec![], true); // height 1, mints
        apply_block_with_shape(rpc.node_mut(), vec![], false); // height 2, mints nothing

        let page = CoinbasePage::from_bytes(&rpc.route("/v1/coinbase?from=0&to=2").unwrap())
            .unwrap();
        assert_eq!((page.from, page.to), (0, 2));
        assert_eq!(page.blocks.len(), 3, "genesis, the minting block, the non-minting one");
        assert_eq!(page.blocks[0].height, 0);
        assert_eq!(page.blocks[0].coinbase, 0, "genesis mints nothing");
        assert_eq!(page.blocks[0].coinbase_rkm, [0; 4], "…and names no payee");
        assert_eq!(page.blocks[1].coinbase_rkm, [1, 2, 3, 4], "the minting block's payee");
        assert_eq!(page.blocks[2].height, 2);
        assert_eq!(
            page.blocks[2].coinbase_rkm,
            [0; 4],
            "a non-minting block is SERVED with the no-payee sentinel — never omitted"
        );
        assert!(!page.is_truncated(), "and the page reaches the `to` it echoes");
        // Nothing is derivable from a non-minting block, and the shared
        // derivation says so rather than minting a zero-value note.
        assert!(crate::coinbase::coinbase_note_parts_for(
            rpc.node().form(),
            2,
            [0; 4],
            0,
            0,
            0
        )
        .is_none());
    }

    /// The route's refusals are `/v1/nullifiers`' refusals, and there is no
    /// per-key form: "did this rkm mine anything" would tell the server which
    /// miner is asking, so the shape does not exist.
    #[test]
    fn the_coinbase_route_refuses_bad_bounds_and_has_no_per_key_form() {
        let (rpc, _) = rpc_with_finalized_genesis();
        assert_eq!(rpc.route("/v1/coinbase"), Err((400, "missing/invalid 'from'")));
        assert_eq!(rpc.route("/v1/coinbase?from=0"), Err((400, "missing/invalid 'to'")));
        assert_eq!(rpc.route("/v1/coinbase?from=zz&to=1"), Err((400, "missing/invalid 'from'")));
        assert_eq!(rpc.route("/v1/coinbase?from=5&to=1"), Err((400, "'to' < 'from'")));
        assert!(matches!(rpc.route("/v1/coinbase/deadbeef"), Err((404, _))));
    }

    /// The projection's coinbase facts are the body's own, including the two
    /// sums — asserted against a real `BlockBody` rather than against the
    /// sentence in `BlockDiscovery::of`'s doc comment, because `fees` is
    /// computed there from the stored transactions instead of by rebuilding the
    /// body (which would clone every proof).
    #[test]
    fn the_projections_coinbase_facts_are_the_bodys_own() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        apply_block_with(
            rpc.node_mut(),
            vec![
                tx_with(anchor, &[1, 2], &[10, 11], fee),
                tx_with(anchor, &[3, 4], &[12, 13], fee),
            ],
        );
        let stored = {
            let chain = rpc.node().chain();
            let hash = chain.tip_hash();
            chain.block(&hash).expect("stored").clone()
        };
        let body = stored.body();
        let projected = BlockDiscovery::of(rpc.node().tip_hash(), &stored);

        let (body_coinbase, body_rkm) = body.single_payee_parts().expect("current-cap body");
        assert_eq!(projected.coinbase, body_coinbase);
        assert_eq!(projected.coinbase_rkm, body_rkm);
        assert_eq!(projected.fees, body.total_fees(), "two transactions' worth of fee");
        assert_eq!(projected.fees, 2 * fee);
        assert_eq!(projected.name_burn, body.total_name_burn());
        assert_eq!(
            crate::coinbase::coinbase_note_value_parts(
                projected.coinbase,
                projected.fees,
                projected.name_burn
            ),
            crate::coinbase::coinbase_note_value(&body),
            "the projection and the body reach the same value through the same function"
        );
    }

    /// The leaf wire rejects exactly like the node's other own wires: unknown
    /// version, trailing bytes, truncation — and a claimed count the bytes cannot
    /// hold is a refusal, not an allocation.
    #[test]
    fn leaf_stream_rejects_bad_version_trailing_truncation_and_count_lies() {
        let good = TreeLeaves { from: 0, total: 2, leaves: vec![[0x11; 32], [0x22; 32]] }.to_bytes();
        assert_eq!(TreeLeaves::from_bytes(&good).unwrap().leaves.len(), 2);

        let mut bad_v = good.clone();
        bad_v[0] = 0x04;
        assert!(matches!(TreeLeaves::from_bytes(&bad_v), Err(CodecError::BadVersion { got: 4 })));

        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(TreeLeaves::from_bytes(&extra), Err(CodecError::TrailingBytes { .. })));

        assert!(matches!(
            TreeLeaves::from_bytes(&good[..good.len() - 1]),
            Err(CodecError::Truncated { .. })
        ));

        // An 18-byte payload claiming 2^60 leaves: `Truncated`, never a 2^65-byte
        // allocation — the count is attacker-adjacent input on a served wire.
        let mut lie = Vec::new();
        lie.push(RPC_VERSION);
        lie.extend_from_slice(&0u64.to_le_bytes());
        lie.extend_from_slice(&0u64.to_le_bytes());
        write_varint(&mut lie, 1u64 << 60);
        assert!(matches!(TreeLeaves::from_bytes(&lie), Err(CodecError::Truncated { .. })));
    }

    /// The page arithmetic: bounded at [`MAX_TREE_LEAVES`], the client loops from
    /// `from + n`, and a `from` at or beyond `total` is an **empty page carrying
    /// `total`** — a meaningful state (reorg, lagging server), never an error.
    #[test]
    fn leaf_pages_are_bounded_and_from_beyond_total_is_an_empty_page() {
        let leaves: Vec<Hash32> = (0..MAX_TREE_LEAVES as u64 + 5)
            .map(|i| {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&i.to_le_bytes());
                h
            })
            .collect();

        let p0 = TreeLeaves::page(&leaves, 0);
        assert_eq!(p0.leaves.len(), MAX_TREE_LEAVES, "a full page is the bound, not the tree");
        assert_eq!(p0.total, leaves.len() as u64);
        assert_eq!(p0.leaves[0], leaves[0]);

        // The client's loop: page from where the last one stopped.
        let p1 = TreeLeaves::page(&leaves, MAX_TREE_LEAVES as u64);
        assert_eq!(p1.leaves.len(), 5);
        assert_eq!(p1.leaves[0], leaves[MAX_TREE_LEAVES]);
        assert_eq!(p1.from + p1.leaves.len() as u64, p1.total, "…and this page says stop");

        let beyond = TreeLeaves::page(&leaves, u64::MAX);
        assert!(beyond.leaves.is_empty());
        assert_eq!(beyond.total, leaves.len() as u64, "the empty page still says where the server is");
        assert_eq!(beyond.from, u64::MAX, "the echo is the request's — a paging client cannot misattribute it");
    }

    /// **Acceptance (#275 seam 2): the route serves the node's own append order —
    /// matured-coinbase-first (issue #102) — and the stream is self-verifying: a
    /// wallet folding it into a fresh tree reproduces the node's root**, which is
    /// the anchor its spend will be judged against. This is the property that lets
    /// the client never recompute maturity.
    #[test]
    fn route_serves_the_leaf_stream_in_apply_order_and_it_rebuilds_the_root() {
        let genesis = genesis_block(1_000, 0);
        let mut node = MemNode::in_memory(genesis);
        let g = node.chain().genesis_block_hash();
        assert!(node.finalize(g).unwrap().is_recorded());
        let anchor = node.commitment_root();

        // Mint at height 1, walk to the maturity horizon, then land a real
        // transaction in the exact block that matures height 1's coinbase — the
        // one block where compact-only reconstruction gets positions wrong.
        apply_block_with_shape(&mut node, vec![], true);
        for _ in 2..=crate::emission::COINBASE_MATURITY_BLOCKS {
            apply_block_with_shape(&mut node, vec![], false);
        }
        let before = node.commitments_ordered().len();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        apply_block_with_shape(
            &mut node,
            vec![tx_with(anchor, &[0x21, 0x22], &[0x77, 0x78], fee)],
            false,
        );
        let ordered = node.commitments_ordered();
        assert_eq!(ordered.len(), before + 3, "one matured coinbase leaf + two tx commitments");
        assert_ne!(ordered[before], cm_bytes(0x77), "the coinbase leaf goes in FIRST (issue #102)");
        assert_eq!(&ordered[before + 1..], &[cm_bytes(0x77), cm_bytes(0x78)], "then the tx's, in order");

        let rpc = NodeRpc::new(node);
        let served = TreeLeaves::from_bytes(&rpc.route("/v1/tree/leaves?from=0").unwrap())
            .expect("the route serves the versioned wire");
        assert_eq!(served.leaves, rpc.node().commitments_ordered(), "served == applied, byte for byte");
        assert_eq!(served.total as usize, served.leaves.len());

        // Self-verifying end to end: the wallet's replayed tree IS the node's.
        let mut wallet_tree = qlab_cbserver::tree::CommitmentTree::new();
        for leaf in &served.leaves {
            wallet_tree.append_bytes(leaf);
        }
        assert_eq!(
            digest_bytes(&wallet_tree.root()),
            rpc.node().commitment_root(),
            "a wallet that replays the stream holds the root its anchor check needs"
        );

        // Refusals mirror the neighbouring routes': a missing bound is a 400.
        assert_eq!(rpc.route("/v1/tree/leaves").unwrap_err().0, 400);
        assert_eq!(rpc.route("/v1/tree/leaves?from=zzz").unwrap_err().0, 400);
    }

    /// Issue #121's **collateral, made explicit** (re-pinned at `0x04` by #212 and
    /// at `0x05` by #275): `/v1/status` and `/v1/anchors` share `RPC_VERSION` with
    /// `/v1/telemetry`, so bumping it — for #212's durable-head tail, and again for
    /// #275's route additions — moves them too even though their payloads are
    /// byte-for-byte what they were. An older reader now fails loudly against them.
    ///
    /// That is the accepted trade (see [`RPC_VERSION`]'s doc), and it is locked
    /// here so nobody later "fixes" it back into a silent accept-both.
    ///
    /// 🔴 **Note what #212 did NOT do**: `Telemetry::from_bytes_compat` reads `0x03`
    /// (and, since #275, `0x04`), and these two surfaces gained no such path. That is
    /// deliberate — `qumbra-opview` polls `/v1/telemetry` and nothing else, so the
    /// roll problem is that route's alone, and widening the compat window to routes
    /// nothing needs it on would be leniency bought for free.
    #[test]
    fn status_and_anchors_moved_to_0x07_with_telemetry_and_reject_older_versions() {
        let (rpc, _) = rpc_with_finalized_genesis();
        assert_eq!(RPC_VERSION, 0x07);

        for mut payload in [rpc.status().to_bytes(), rpc.anchors().to_bytes(), rpc.telemetry().to_bytes()] {
            assert_eq!(payload[0], 0x07, "the node's own surfaces move as one");
            for old in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06] {
                payload[0] = old;
                let as_status = NodeStatus::from_bytes(&payload);
                let as_anchors = AnchorSet::from_bytes(&payload);
                let as_telemetry = Telemetry::from_bytes(&payload);
                assert!(matches!(as_status, Err(CodecError::BadVersion { got }) if got == old));
                assert!(matches!(as_anchors, Err(CodecError::BadVersion { got }) if got == old));
                assert!(matches!(as_telemetry, Err(CodecError::BadVersion { got }) if got == old));
            }
        }

        // …while the ratified compact-block family is untouched at 0x01. Bumping it
        // would be a wire-codepoint change (it is asserted on the p2p relay path).
        assert_eq!(qlab_cbserver::WIRE_VERSION, 0x01);
        assert_eq!(rpc.route("/v1/compact?from=0&to=0").unwrap()[0], qlab_cbserver::WIRE_VERSION);
        assert_eq!(rpc.route("/v1/tree/frontier?at=0").unwrap()[0], qlab_cbserver::WIRE_VERSION);
    }

    // Apply one real block with the requested minting/transaction shape.
    fn apply_block_with_shape(node: &mut MemNode, txs: Vec<TxEntry>, minting: bool) {
        let tip_hash = node.tip_hash();
        let parent = node.chain().block(&tip_hash).expect("tip block stored").header();
        let height = parent.height + 1;
        let (coinbase, coinbase_rkm) =
            if minting { (height, [height, 2, 3, 4]) } else { (0, [0; 4]) };
        let body = BlockBody::from_single_payee(txs, coinbase, coinbase_rkm);
        // child_of's 2nd arg is the timestamp; height is derived from the parent.
        let header = BlockHeader::child_of(&parent, height, 1_000, body.commitment());
        node.apply_block(header, body, &OkVerifier).expect("block applies");
    }

    // Apply one real minting block carrying `tx` to the node (so it becomes
    // serveable).
    fn apply_block_with(node: &mut MemNode, txs: Vec<TxEntry>) {
        apply_block_with_shape(node, txs, true);
    }

    #[test]
    fn main_chain_counts_matches_apply_state_sequence_for_mixed_blocks() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let mut applied = vec![(rpc.node().tip_height(), rpc.node().commitment_count())];

        // Exercise all four minting/transaction combinations. The expected
        // sequence is observed after the real state-transition funnel; it does
        // not encode how either kind of output is scheduled or ordered.
        apply_block_with_shape(rpc.node_mut(), vec![], true);
        applied.push((rpc.node().tip_height(), rpc.node().commitment_count()));

        apply_block_with_shape(
            rpc.node_mut(),
            vec![tx_with(anchor, &[1, 2], &[10, 11], fee)],
            false,
        );
        applied.push((rpc.node().tip_height(), rpc.node().commitment_count()));

        apply_block_with_shape(
            rpc.node_mut(),
            vec![
                tx_with(anchor, &[3, 4], &[12, 13], fee),
                tx_with(anchor, &[5, 6], &[14, 15], fee),
            ],
            true,
        );
        applied.push((rpc.node().tip_height(), rpc.node().commitment_count()));

        apply_block_with_shape(rpc.node_mut(), vec![], false);
        applied.push((rpc.node().tip_height(), rpc.node().commitment_count()));

        // Keep walking beyond #102's ratified height-offset boundary. This
        // deliberately says nothing about whether those later transitions
        // append a matured coinbase leaf; it only ensures the comparison still
        // observes that append site after the schedule changes.
        for height in 5..=(crate::COINBASE_MATURITY_BLOCKS + 4) {
            apply_block_with_shape(rpc.node_mut(), vec![], height % 2 == 1);
            applied.push((rpc.node().tip_height(), rpc.node().commitment_count()));
        }

        assert_eq!(
            rpc.main_chain_counts(),
            applied,
            "the RPC count sequence must be derived from exactly what state application appended"
        );
    }

    #[test]
    fn compact_and_full_serve_accepted_blocks_only() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        let disc = disc_for(&[10, 11]);
        assert!(matches!(rpc.submit_tx(tx.clone(), disc, &OkVerifier), SubmitOutcome::Accepted(_)));

        // Before the tx is in a block, nothing is served for height 1.
        let empty = rpc.route("/v1/compact?from=1&to=1").unwrap();
        assert_eq!(decode_compact_response(&empty).unwrap().len(), 0, "no accepted block yet");

        // Embed the tx in a block and apply it.
        apply_block_with(rpc.node_mut(), vec![tx]);

        let bytes = rpc.route("/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 1);
        assert_eq!(blocks[0].groups.len(), 1);
        assert_eq!(blocks[0].groups[0].recipients[0].entries.len(), 2, "2 outputs served");

        // Full-fetch payloads for that (height, tx).
        let full = rpc.route("/v1/block/1/tx/0/full").unwrap();
        let per_recipient = qlab_cbserver::codec::decode_full_response(&full).unwrap();
        assert_eq!(per_recipient.len(), 1);
        assert_eq!(per_recipient[0].len(), 2, "two AEAD payloads");

        // A height the node does not have serves nothing / errors as cbserver does.
        assert!(matches!(rpc.route("/v1/block/9/tx/0/full"), Err((404, _))));
    }

    /// 🔴 **The baton's first acceptance item, stated as a byte identity.**
    ///
    /// A served group is `varint(position) ‖ StoredTx::discovery` — the committed
    /// bytes, concatenated, never re-encoded. Asserted against the stored block
    /// itself rather than against a value the test computed a second way, because
    /// the claim is *these are the same bytes* and only the block can say so.
    #[test]
    fn served_groups_are_the_committed_bytes_verbatim() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let a = tx_with(anchor, &[1, 2], &[10, 11], fee);
        let b = tx_with(anchor, &[3, 4], &[12, 13], fee);
        apply_block_with(rpc.node_mut(), vec![a, b]);

        let served = rpc.route("/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&served).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].groups.len(), 2);

        let hash = rpc.node().chain().tip_hash();
        let stored = rpc.node().chain().block(&hash).expect("tip stored").clone();
        for (i, group) in blocks[0].groups.iter().enumerate() {
            assert_eq!(group.tx_index, i as u64, "position is the index, nothing else is");
            // 🔴 Since issue #188 (a) "verbatim" means the committed region's
            // `group_contents` PREFIX — serving projects it and leaves the
            // relocated payload section behind. Still a projection and not a
            // re-encoding: these bytes are copied out of `stored.txs[i].discovery`.
            let committed = &stored.txs[i].discovery;
            let prefix = qlab_cbserver::codec::committed_contents_prefix(committed)
                .expect("a stored block's committed region decodes");
            let mut expected = Vec::new();
            write_varint(&mut expected, i as u64);
            expected.extend_from_slice(prefix);
            assert_eq!(
                qlab_cbserver::codec::encode_group(group),
                expected,
                "the served group is varint(position) ‖ the committed PREFIX, verbatim"
            );
            // The other half of the projection, asserted rather than assumed: the
            // payload section is committed and NOT served here. If these were
            // equal, the compact wire would have grown by 120 B per output and
            // `golden_bytes_lock_the_framing` would be the one that moved.
            assert!(
                prefix.len() < committed.len(),
                "the committed region must carry a payload section beyond the prefix"
            );
            assert_eq!(
                committed.len() - prefix.len(),
                stored.txs[i].commitments.len() * qlab_cbserver::codec::PAYLOAD_LEN,
                "one fixed-width payload per output, committed but not served"
            );
        }
    }

    /// 🔴 **The defect this baton exists to fix.** `/v1/compact` used to join each
    /// stored transaction to `NodeRpc`'s in-memory side table by statement id and
    /// serve an **empty group** when the lookup missed — so a node that had not
    /// itself admitted the transaction (every peer's node, and every node after a
    /// restart) told a wallet "this transaction pays nobody".
    ///
    /// Here nothing is ever recorded in the side table, and the block still serves
    /// its full group. Then the side table is deliberately **poisoned** with a
    /// different group for the same statement id and the served bytes do not move:
    /// the side table is not merely unused on the happy path, it is not consulted.
    #[test]
    fn compact_serves_the_block_and_never_the_side_table() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        // NOT submitted: no `submit_tx`, no `record_discovery`. The block arrives
        // the way a peer's block arrives.
        apply_block_with(rpc.node_mut(), vec![tx.clone()]);
        assert!(rpc.discovery.is_empty(), "the side table is empty on this path");

        let from_block = rpc.route("/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&from_block).unwrap();
        assert_eq!(blocks[0].groups[0].recipients.len(), 1);
        assert_eq!(
            blocks[0].groups[0].commitments(),
            tx.public.commitments,
            "the committed group binds the transaction's own outputs"
        );

        // Poison the side table with a group describing different outputs.
        let txid = tx_id_of_public(&tx.public);
        rpc.record_discovery(txid, disc_for(&[99]));
        assert_eq!(
            rpc.route("/v1/compact?from=1&to=1").unwrap(),
            from_block,
            "a side table that disagrees with the block changes nothing that is served"
        );
    }

    /// 🔴 **The same defect, one route later** (issue #188, the serving+open
    /// baton). `/v1/…/full` kept the side-table join after `/v1/compact` lost
    /// it, so a node answered 404 for every transaction it had not itself
    /// admitted — every peer's transaction, and every transaction at all after
    /// a restart. Since the mint the payloads are in the committed region, so
    /// the block can answer.
    ///
    /// Nothing is submitted here, and the side table is then **poisoned** with
    /// payloads for the same statement id: the served bytes do not move.
    #[test]
    fn full_serves_the_block_and_never_the_side_table() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        apply_block_with(rpc.node_mut(), vec![tx.clone()]);
        assert!(rpc.discovery.is_empty(), "the side table is empty on this path");

        let served = rpc.route("/v1/block/1/tx/0/full").expect("the block can answer");
        let per_recipient = qlab_cbserver::codec::decode_full_response(&served).unwrap();
        assert_eq!(per_recipient.len(), 1);
        assert_eq!(per_recipient[0], vec![vec![10u8; 120], vec![11u8; 120]]);

        // Byte identity with the committed region's tail — the projection, not a
        // re-encoding of something that merely agrees with it.
        let hash = rpc.node().chain().tip_hash();
        let stored = rpc.node().chain().block(&hash).expect("tip stored").clone();
        let committed = &stored.txs[0].discovery;
        let prefix = qlab_cbserver::codec::committed_contents_prefix(committed).unwrap().len();
        assert_eq!(per_recipient.concat().concat(), committed[prefix..].to_vec());

        // Poison the side table with different payloads for the same statement.
        let txid = tx_id_of_public(&tx.public);
        rpc.record_discovery(txid, disc_for(&[99]));
        assert_eq!(
            rpc.route("/v1/block/1/tx/0/full").unwrap(),
            served,
            "a side table that disagrees with the block changes nothing that is served"
        );

        // A transaction index past the block's end is a 404, not an empty list.
        assert!(matches!(rpc.route("/v1/block/1/tx/9/full"), Err((404, _))));
    }

    /// The submitted artifacts must BE the transaction's committed group, not
    /// merely agree with it about commitments — otherwise `/v1/…/full` would hand
    /// back payloads keyed to a ciphertext `/v1/compact` never served, and a wallet
    /// that matched a committed tag would decrypt to nothing and report no funds.
    #[test]
    fn submit_refuses_artifacts_that_are_not_the_committed_group() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        // Same commitments, in the same order — a different ML-KEM ciphertext.
        // The pre-#188 check compared commitments and would have accepted this.
        let wrong_ct = TxDiscovery { recipients: vec![recip(CT_BASE ^ 0xff, &[10, 11])] };
        assert_eq!(
            wrong_ct.recipients[0].bundle.entries.iter().map(|e| e.cm).collect::<Vec<_>>(),
            tx.public.commitments,
            "the fixture really does agree on commitments"
        );
        assert_eq!(
            rpc.submit_tx(tx.clone(), wrong_ct, &OkVerifier),
            SubmitOutcome::Rejected(RejectReason::DiscoveryMismatch)
        );
        // The honest pairing is admitted.
        assert!(matches!(
            rpc.submit_tx(tx, disc_for(&[10, 11]), &OkVerifier),
            SubmitOutcome::Accepted(_)
        ));
    }

    /// A range is a client-chosen number and must not become a client-chosen amount
    /// of node work. Before this the router iterated `from..=to` literally, so
    /// `to = u64::MAX` was an unbounded loop; the response is now bounded by what
    /// the node holds and then by [`MAX_COMPACT_BLOCKS`].
    #[test]
    fn a_range_is_bounded_by_what_the_node_holds_not_by_what_was_asked() {
        let (mut rpc, _anchor) = rpc_with_finalized_genesis();
        for _ in 0..3 {
            apply_block_with(rpc.node_mut(), vec![]);
        }
        let bytes = rpc.route("/v1/compact?from=0&to=18446744073709551615").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 4, "genesis + 3, and not one iteration more");
        assert_eq!(blocks.last().unwrap().height, 3);

        // The cap is a cap on blocks, not a filter on heights: with fewer blocks
        // than the cap the whole chain is served, which is what makes a short
        // response unambiguous here.
        assert!(blocks.len() < MAX_COMPACT_BLOCKS);
    }

    #[test]
    fn e2e_over_localhost_socket() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        rpc.submit_tx(tx.clone(), disc_for(&[10, 11]), &OkVerifier);
        apply_block_with(rpc.node_mut(), vec![tx]);

        let shared = Arc::new(Mutex::new(rpc));
        let handle = serve(Arc::clone(&shared));
        let base = handle.base_url();
        assert!(base.starts_with("http://127.0.0.1:"));
        let bytes = qlab_cbserver::client::http_get(&base, "/v1/compact?from=1&to=1").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        let sb = qlab_cbserver::client::http_get(&base, "/v1/status").unwrap();
        let status = NodeStatus::from_bytes(&sb).unwrap();
        assert_eq!(status.tip_height, 1);
        assert!(handle.requests_served() >= 2);
        handle.shutdown();
    }

    #[test]
    fn frontier_served_from_live_tree_reconstructs_node_root() {
        let (mut rpc, anchor) = rpc_with_finalized_genesis();
        let fee = posted_fee(ArityBucket::TwoByTwo);
        let tx = tx_with(anchor, &[1, 2], &[10, 11], fee);
        rpc.submit_tx(tx.clone(), disc_for(&[10, 11]), &OkVerifier);
        apply_block_with(rpc.node_mut(), vec![tx]);

        let bytes = rpc.route("/v1/tree/frontier?at=1").unwrap();
        let f = Frontier::from_bytes(&bytes).unwrap();
        let root = digest_bytes(&f.root());
        assert_eq!(root, rpc.node().commitment_root(), "served frontier reconstructs the LIVE node root");
        // Frontier at height 0 is the empty tree.
        let f0 = Frontier::from_bytes(&rpc.route("/v1/tree/frontier?at=0").unwrap()).unwrap();
        assert_eq!(f0.n_leaves, 0);
    }

    /// The embedded compact encoder is byte-identical to cbserver's golden
    /// framing — reused, not forked. Reproduce cbserver's golden vector through
    /// the exact encoder this module calls and assert the on-record digest.
    #[test]
    fn compact_encoder_matches_golden_framing() {
        let ct: [u8; qlab_note::kem::CT_LEN] = core::array::from_fn(|i| (i % 256) as u8);
        let e0 = CompactEntry { cm: [0xAA; 32], tag: [0xBB; 8], clue: ClueSlot::Empty };
        let e1 = CompactEntry { cm: [0xCC; 32], tag: [0xDD; 8], clue: ClueSlot::Empty };
        let group = CompactGroup {
            tx_index: 2,
            recipients: vec![RecipientBundle { ct, entries: vec![e0, e1] }],
        };
        let block = CompactBlock { height: 7, groups: vec![group] };
        let bytes = encode_compact_response(&[block]);
        assert_eq!(bytes.len(), 1177, "golden total length");
        let digest = keccak256(&bytes);
        let hex: String = digest.iter().map(|x| format!("{x:02x}")).collect();
        assert_eq!(
            hex, "3ee2a5e66192bdba4d86e3f6283edbf8ed842f2ef854b724e60b071c9cf54017",
            "compact framing must stay byte-identical to cbserver's golden vector"
        );
    }
}
