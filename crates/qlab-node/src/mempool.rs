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
//!    - **coinbase maturity** — a coinbase note may not be spent until 144 blocks
//!      after it was mined (frozen §2; tokenomics §6 one-hop-transparency model,
//!      below);
//!    - **double-spend** — no nullifier already in the consensus set, and none
//!      already claimed by another pooled tx (so an assembled block never
//!      in-block double-spends);
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
//! `posted_fee`; the anchor gate is the *same* `is_valid_anchor`).
//!
//! ## Coinbase-maturity model (issue #101 moved half of this into reality)
//!
//! A coinbase note "carries public value at creation and enters the pool as an
//! ordinary note after a maturity delay" (tokenomics §6, one-hop transparency).
//!
//! Block assembly now mints a **real note** — [`crate::coinbase::coinbase_note`],
//! openable by the 2×2 circuit — and `Node::apply_state` appends its commitment
//! to the depth-32 tree, so a mined coin has a leaf and a membership witness and
//! can actually be spent. What was here before was a domain-separated digest that
//! no circuit could open, deliberately incapable of being a note; it is deleted.
//!
//! **Maturity itself is still policy, not structure.** The node records the note
//! with its creation height ([`Mempool::record_coinbase_note`]); a candidate tx
//! **declares** the coinbase notes it consumes (`spends_coinbase`), and admission
//! requires each to be ≥ 144 blocks deep at the prospective block height. That
//! declaration is only as good as the submitter — see
//! [#102](https://github.com/lai3d/qumbra-lab/issues/102), which this baton turns
//! from an unreachable seam into a live hole and which is sequenced next.
//!
//! A **structural** alternative exists and needs no circuit change: append the
//! coinbase leaf at `h + 144` rather than at `h`, so no anchor contains the leaf
//! until it has matured and an immature spend is *unprovable* rather than
//! refused-by-policy. Not taken here (it is a further consensus-layer decision,
//! and it would leave `record_coinbase_note` with nothing to do), but recorded as
//! the option on the table when #102 is written.

use std::collections::{BTreeMap, HashMap, HashSet};

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::fees::posted_fee;
use qlab_devnet::hash::keccak256;
use qlab_devnet::weight::{
    is_weight_admissible, quadratic_penalty, weight_limit, WeightGovernor, WeightParams,
};

use crate::emission::{coinbase, RewardSplit, COINBASE_MATURITY_BLOCKS};
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
    /// The tx spends a coinbase note that has not matured (frozen §2: 144 blocks).
    ImmatureCoinbase { commitment: Hash32, created_at: u64, matures_at: u64, prospective_height: u64 },
    /// A nullifier is already spent in the consensus set (cross-block double-spend).
    AlreadySpent { nullifier: Hash32 },
    /// A nullifier is already claimed by another pooled tx (would in-block
    /// double-spend if both were mined).
    NullifierConflictInPool { nullifier: Hash32 },
    /// This exact transaction is already pooled.
    DuplicateTx,
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

/// A pooled transaction: its consensus entry, cached weight, and the coinbase
/// notes it declares it spends (for the maturity gate).
#[derive(Clone)]
pub struct MempoolTx {
    /// The transaction id (Keccak of the canonical preimage).
    pub txid: TxId,
    /// The consensus entry (opaque proof + public surface).
    pub entry: TxEntry,
    /// Serialized weight in bytes (proof + public surface).
    pub weight: u64,
    /// Coinbase-note commitments this tx consumes (one-hop-transparency model).
    pub spends_coinbase: Vec<Hash32>,
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
    (entry.proof.len() + public) as u64
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
    /// [`crate::coinbase::coinbase_note_leaf`] derives it — the leaf
    /// `Node::apply_state` will append and the value the maturity registry is
    /// keyed on. `None` only for a non-minting body (`coinbase == 0`).
    ///
    /// Derived from the assembled body by the same function the applier uses, so
    /// the assembler and the applier cannot disagree about the leaf.
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
        let coinbase_total = coinbase(height);
        let reward_split = RewardSplit::of(coinbase_total);
        let total_fees: u64 = chosen.iter().map(|t| t.public.fee).sum();
        let weight_penalty =
            quadratic_penalty(coinbase_total, total_weight, effective_median, &params.weight);
        let miner_take = reward_split.miner.saturating_sub(weight_penalty) + total_fees;
        let body =
            BlockBody { txs: chosen.clone(), coinbase: coinbase_total, coinbase_rkm };
        let coinbase_note = crate::coinbase::coinbase_note_leaf(height, &body);
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
/// Holds admitted transactions (indexed by id), a nullifier → owning-tx index
/// (the in-pool double-spend gate), and the coinbase-note registry (creation
/// heights for the maturity gate). It reads consensus state through the
/// [`NodeState`] trait, so it composes with any node backend.
#[derive(Clone)]
pub struct Mempool {
    params: MempoolParams,
    /// Admitted txs, ordered by id (deterministic assembly/iteration).
    txs: BTreeMap<TxId, MempoolTx>,
    /// nullifier → the pooled tx that claims it.
    nf_index: HashMap<Hash32, TxId>,
    /// coinbase-note commitment → creation height (maturity = +144 blocks).
    coinbase_notes: HashMap<Hash32, u64>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(MempoolParams::default())
    }
}

impl Mempool {
    /// A fresh mempool with the given (frozen) parameters.
    pub fn new(params: MempoolParams) -> Self {
        Self {
            params,
            txs: BTreeMap::new(),
            nf_index: HashMap::new(),
            coinbase_notes: HashMap::new(),
        }
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

    /// Record a coinbase note minted at `height` (its maturity clock starts here).
    /// Called when a block is accepted; the coinbase note becomes spendable at
    /// `height + 144` (frozen §2).
    ///
    /// Issue #101 narrowed this to **maturity bookkeeping only** and re-keyed it
    /// on the real note commitment. Remaining callers: [`Self::on_block_connected`]
    /// (the production path — every accepted block), and the mempool/assembly and
    /// faucet tests that seed a matured note. Nothing computes a coinbase
    /// "commitment" here any more; the leaf comes from [`crate::coinbase`].
    pub fn record_coinbase_note(&mut self, commitment: Hash32, height: u64) {
        self.coinbase_notes.insert(commitment, height);
    }

    /// The recorded creation height of a coinbase note, if known.
    pub fn coinbase_note_height(&self, commitment: &Hash32) -> Option<u64> {
        self.coinbase_notes.get(commitment).copied()
    }

    /// Admit a candidate transaction, or say why it was refused. `spends_coinbase`
    /// lists the coinbase-note commitments the tx consumes (empty for ordinary
    /// spends). Checks run cheapest-first; the proof verify is last.
    pub fn admit<S: NodeState, V: TxVerifier>(
        &mut self,
        entry: TxEntry,
        spends_coinbase: Vec<Hash32>,
        state: &S,
        verifier: &V,
    ) -> Result<TxId, MempoolError> {
        // The block this tx would first be mineable in.
        let prospective_height = state.tip_height() + 1;

        // 1. Posted-price fee (protocol-spec §4, frozen §5). Cheapest — pure
        //    function of the public bucket.
        let expected = posted_fee(entry.public.bucket);
        if entry.public.fee != expected {
            return Err(MempoolError::WrongFee { expected, got: entry.public.fee });
        }

        // 2. Anchor: a finalized root within the ≤ 1,152-block window (§4/§7).
        if !state.is_valid_anchor(&entry.public.anchor) {
            return Err(MempoolError::AnchorNotValid);
        }

        // 3. Coinbase maturity (frozen §2): each spent coinbase note must be
        //    ≥ 144 blocks deep at the prospective height.
        for cm in &spends_coinbase {
            if let Some(&created_at) = self.coinbase_notes.get(cm) {
                let matures_at = created_at + COINBASE_MATURITY_BLOCKS;
                if prospective_height < matures_at {
                    return Err(MempoolError::ImmatureCoinbase {
                        commitment: *cm,
                        created_at,
                        matures_at,
                        prospective_height,
                    });
                }
            }
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

        // 7. Proof verify — last, the only non-trivial cost (consensus §1).
        if !verifier.verify_tx(&entry) {
            return Err(MempoolError::ProofInvalid);
        }

        // Admit: index nullifiers, store.
        for nf in &entry.public.nullifiers {
            self.nf_index.insert(*nf, id);
        }
        let weight = tx_weight(&entry);
        self.txs.insert(id, MempoolTx { txid: id, entry, weight, spends_coinbase });
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

    /// Reconcile the pool after a block is connected at `height`: record its
    /// coinbase note, drop the txs it mined, and evict any pooled tx that now
    /// double-spends a nullifier the block consumed. Keeps the pool a set of txs
    /// that can still be mined next.
    pub fn on_block_connected<S: NodeState>(&mut self, height: u64, body: &BlockBody, state: &S) {
        // Record the coinbase note (its maturity clock starts at this height).
        // Keyed on the REAL note commitment now (issue #101) — the same leaf
        // `Node::apply_state` appended, so the maturity registry and the
        // commitment tree name the same object.
        if let Some(cb) = crate::coinbase::coinbase_note_leaf(height, body) {
            self.record_coinbase_note(cb, height);
        }

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
        for tx in candidates {
            if weight + tx.weight <= effective_median {
                chosen.push(tx.entry.clone());
                weight += tx.weight;
            }
        }
        // The fill guarantees `weight ≤ effective_median ≤ hard_cap`, so build
        // never errors here.
        BlockTemplate::build(height, chosen, weight, effective_median, &self.params, coinbase_rkm)
            .expect("free-zone fill is always within the hard cap")
    }

    /// Assemble a template from an **explicit** transaction selection, refusing
    /// with [`AssemblyError::TemplateOverWeight`] if it exceeds the hard cap
    /// (frozen §6). This is the validity gate for a proposed/relayed block body:
    /// a set summing past `2 × M` is an invalid template.
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
        BlockTemplate::build(height, chosen, weight, effective_median, &self.params, coinbase_rkm)
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
        TxEntry {
            proof: b"ok".to_vec(),
            public: qlab_devnet::body::TxPublic {
                anchor: ANCHOR,
                nullifiers: vec![[nf; 32]],
                commitments: vec![[nf.wrapping_add(100); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        }
    }

    // ── admission positives ──────────────────────────────────────────────────

    #[test]
    fn admits_a_well_formed_tx() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let id = mp.admit(good_tx(1), vec![], &st, &MockVerifier).expect("admit");
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
        let id = mp.admit(tx.clone(), vec![], &st, &MockVerifier).expect("admit");
        let listed = mp.entries();
        assert_eq!(listed.len(), 1);
        assert_eq!(txid(&listed[0]), id);
        assert_eq!(txid(mp.get(&id).expect("present")), id);
        assert!(mp.get(&[0xEE; 32]).is_none());
    }

    // ── admission negatives (the acceptance set) ─────────────────────────────

    #[test]
    fn rejects_wrong_fee() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.public.fee += 1; // one bessel off the posted price → invalid (§4)
        assert_eq!(
            mp.admit(tx, vec![], &st, &MockVerifier),
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
            mp.admit(tx, vec![], &st, &MockVerifier),
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
        assert_eq!(mp.admit(tx, vec![], &st, &MockVerifier), Err(MempoolError::AnchorNotValid));
    }

    #[test]
    fn rejects_immature_coinbase_spend_then_admits_after_maturity() {
        let mut mp = Mempool::default();

        // A coinbase note minted at height 100 — the REAL note commitment now.
        let cb = crate::coinbase::coinbase_note_leaf(
            100,
            &BlockBody { txs: vec![], coinbase: coinbase(100), coinbase_rkm: TEST_RKM },
        )
        .expect("a minting body has a coinbase leaf");
        mp.record_coinbase_note(cb, 100);

        // Tip 200 ⇒ prospective height 201; matures at 100 + 144 = 244 > 201.
        let st = state_with_anchor(); // tip 200
        let err = mp.admit(good_tx(1), vec![cb], &st, &MockVerifier).unwrap_err();
        assert_eq!(
            err,
            MempoolError::ImmatureCoinbase {
                commitment: cb,
                created_at: 100,
                matures_at: 244,
                prospective_height: 201,
            }
        );
        assert!(mp.is_empty());

        // Advance the tip to 243 ⇒ prospective 244 == matures_at ⇒ spendable.
        let st2 = TestState { tip: 243, finalized: Some(240), ..state_with_anchor() };
        mp.admit(good_tx(1), vec![cb], &st2, &MockVerifier).expect("matured coinbase spends");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn rejects_cross_block_double_spend() {
        let mut mp = Mempool::default();
        let mut st = state_with_anchor();
        st.spent.insert([7; 32]); // nullifier already in the consensus set
        assert_eq!(
            mp.admit(good_tx(7), vec![], &st, &MockVerifier),
            Err(MempoolError::AlreadySpent { nullifier: [7; 32] })
        );
    }

    #[test]
    fn rejects_in_pool_double_spend() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        mp.admit(good_tx(9), vec![], &st, &MockVerifier).expect("first admits");
        // A different tx (distinct commitments) reusing the same nullifier.
        let mut tx2 = good_tx(9);
        tx2.public.commitments = vec![[200; 32]];
        assert_eq!(
            mp.admit(tx2, vec![], &st, &MockVerifier),
            Err(MempoolError::NullifierConflictInPool { nullifier: [9; 32] })
        );
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn rejects_duplicate_tx() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        mp.admit(good_tx(3), vec![], &st, &MockVerifier).expect("first");
        assert_eq!(
            mp.admit(good_tx(3), vec![], &st, &MockVerifier),
            Err(MempoolError::DuplicateTx)
        );
    }

    #[test]
    fn rejects_invalid_proof_last() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut tx = good_tx(1);
        tx.proof = b"forged".to_vec();
        assert_eq!(mp.admit(tx, vec![], &st, &MockVerifier), Err(MempoolError::ProofInvalid));
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
            mp.admit(good_tx(nf), vec![], &st, &MockVerifier).unwrap();
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
        assert_eq!(t.body.coinbase, t.coinbase_total);
        // The template carries the payee and the real leaf the applier will
        // append — derived from the same function, so the two cannot disagree.
        assert_eq!(t.coinbase_rkm, TEST_RKM);
        assert_eq!(t.body.coinbase_rkm, TEST_RKM);
        assert_eq!(t.coinbase_note, crate::coinbase::coinbase_note_leaf(201, &t.body));
        assert!(t.coinbase_note.is_some(), "a minting template mints a note");
    }

    #[test]
    fn over_weight_template_is_refused() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let mut ids = Vec::new();
        for nf in 0..5u8 {
            ids.push(mp.admit(good_tx(nf), vec![], &st, &MockVerifier).unwrap());
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

    #[test]
    fn on_block_connected_evicts_mined_and_conflicting_txs_and_records_coinbase() {
        let mut mp = Mempool::default();
        let st = state_with_anchor();
        let a = mp.admit(good_tx(1), vec![], &st, &MockVerifier).unwrap();
        let _b = mp.admit(good_tx(2), vec![], &st, &MockVerifier).unwrap();
        assert_eq!(mp.len(), 2);

        // A block at height 201 mines tx `a` (spends nullifier [1;32]).
        let mined = mp.txs.get(&a).unwrap().entry.clone();
        let body =
            BlockBody { txs: vec![mined], coinbase: coinbase(201), coinbase_rkm: TEST_RKM };
        mp.on_block_connected(201, &body, &st);

        // `a` is gone; `b` remains; the coinbase note is registered at 201.
        assert!(!mp.contains(&a));
        assert_eq!(mp.len(), 1);
        let cb = crate::coinbase::coinbase_note_leaf(201, &body).expect("minting body");
        assert_eq!(mp.coinbase_note_height(&cb), Some(201));
    }
}
