//! Building one grant: witnesses from the live tree, a real 2×2 proof, both
//! outputs encrypted, and an anchor lease with a deadline.
//!
//! ## There is nothing to pre-generate
//!
//! The natural optimisation for a slow prover is "compute a queue of proofs while
//! idle". It does not exist here, and the reason is structural rather than
//! practical: a grant's statement binds the recipient's `rkm` through `cm_out`, so
//! **no grant proof can be built before its request arrives**. The only proofs the
//! faucet could pre-compute are self-transactions, and those are Δ0 in note count
//! ([`crate::inventory`]) — they buy nothing.
//!
//! So the 24 h window (`MAX_ANCHOR_AGE_BLOCKS` = 1,152 blocks × 75 s) is not a
//! shelf life for a queue that does not exist. It is a **submission deadline** on a
//! proof already built: bind an anchor, spend ~2.3 s proving, and the transaction
//! must reach a block before that anchor ages out of the window or it is refused.
//!
//! There *is* one pre-generation design that works, and it is a different product:
//! pre-mint notes to faucet-derived addresses and hand out their note secrets as
//! bearer claims. Grants then cost no proof at request time at all. It is rejected
//! here on grounds worth recording — the faucet retains the spend authority for
//! every unclaimed note (it can spend one out from under its claimant), the first
//! hop is not private from the faucet, and issuance stops being atomic. That is a
//! custodial voucher scheme wearing a faucet's clothes, and it is how one would
//! reach 10 grants/min if that ever became a requirement.
//!
//! ## The lease is conservative because the wire cannot be precise
//!
//! `/v1/anchors` publishes roots but not their heights (see [`crate::view`]), so a
//! wallet cannot compute a root's true expiry. Fixing that is a payload change — a
//! stop point for this baton — so [`AnchorLease`] takes the conservative route:
//! a short self-imposed lease ([`PROOF_LEASE_BLOCKS`]) measured from the tip at
//! acquisition, **plus** a live `is_valid_anchor` re-check immediately before
//! submission. The re-check is the load-bearing half; the lease is what stops the
//! faucet spending 2.3 s of proving on a plan it should already have abandoned.

use std::time::Instant;

use qlab_air::narrow::{
    build_bucket_with_witnesses, BucketInstance, MerkleWitness, TxInput, TxOutput,
};
use qlab_cbserver::tree::CommitmentTree;
use qlab_consensus::{prove_bucket, Config, Proof, Val, LOG_HEIGHT};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::Hash32;
use qlab_devnet::params_devnet::MAX_ANCHOR_AGE_BLOCKS;
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_node::{RecipientDiscovery, TxDiscovery};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use rand::CryptoRng;

use crate::inventory::OwnedNote;
use crate::view::ChainView;

/// How long the faucet lets itself hold an anchor before re-planning.
/// `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// **Not** the protocol window (1,152 blocks): the faucet cannot compute where in
/// that window its anchor sits (module docs), so it caps its own exposure instead.
/// 8 blocks = 10 min at the frozen 75 s, chosen as
/// `CHECKPOINT_CADENCE_BLOCKS` — one checkpoint cadence, i.e. the shortest span
/// over which a fresh finalized root is expected to appear, so a re-plan always has
/// something newer to bind to. It is **1/144th** of the protocol window, so the
/// unknown initial age of the anchor would have to exceed 1,144 blocks before this
/// lease could outlive the real deadline.
pub const PROOF_LEASE_BLOCKS: u64 = qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS;

/// A held anchor and the deadline the faucet imposes on itself for using it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorLease {
    /// The anchor root, as the transaction declares it.
    pub anchor: Hash32,
    /// The same root in circuit lanes (what the witnesses must fold to).
    pub anchor_lanes: [u64; 4],
    /// Leaf count of the tree prefix this root commits to — the count witnesses
    /// must be cut against.
    pub leaf_count: u64,
    /// Tip height when the lease was taken.
    pub acquired_at_tip: u64,
    /// Finalized height when the lease was taken. Recorded because it is the only
    /// published bound on how old the anchor already was.
    pub acquired_at_finalized: Option<u64>,
    /// Self-imposed lease length in blocks.
    pub lease_blocks: u64,
}

impl AnchorLease {
    /// Take a lease on the newest valid anchor, or `None` if nothing is finalized
    /// (a cold net has no valid anchors, and therefore no spendable faucet — the
    /// cold-start problem, reported honestly rather than papered over).
    pub fn acquire<V: ChainView>(view: &V, lease_blocks: u64) -> Option<AnchorLease> {
        let anchor = view.newest_anchor()?;
        let leaf_count = view.anchor_leaf_count(&anchor)?;
        Some(AnchorLease {
            anchor,
            anchor_lanes: digest_from_bytes(&anchor),
            leaf_count,
            acquired_at_tip: view.tip_height(),
            acquired_at_finalized: view.finalized_height(),
            lease_blocks,
        })
    }

    /// The tip height past which the faucet re-plans rather than submit.
    pub fn expires_at_tip(&self) -> u64 {
        self.acquired_at_tip.saturating_add(self.lease_blocks)
    }

    /// The **upper bound** on how many more blocks this anchor could remain valid,
    /// derived from the one thing the wire does publish: the anchor's height is at
    /// most the finalized height at acquisition, so its remaining life is at most
    /// `finalized + MAX_ANCHOR_AGE_BLOCKS − tip`.
    ///
    /// It is an upper bound and nothing more — the true figure needs the anchor's
    /// own height, which `/v1/anchors` does not carry. Reported so an operator can
    /// see the lease is *inside* the bound rather than trusting that it is.
    pub fn window_bound_blocks(&self) -> Option<u64> {
        let fin = self.acquired_at_finalized?;
        Some(
            fin.saturating_add(MAX_ANCHOR_AGE_BLOCKS)
                .saturating_sub(self.acquired_at_tip),
        )
    }

    /// Whether this lease may no longer be used: either the self-imposed lease has
    /// run out, **or** the chain no longer accepts the anchor. The second check is
    /// the load-bearing one; the first is what stops wasted proving.
    pub fn is_expired<V: ChainView>(&self, view: &V) -> bool {
        view.tip_height() > self.expires_at_tip() || !view.is_valid_anchor(&self.anchor)
    }
}

/// Why a grant could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// Nothing is finalized, so no root is a valid anchor. On a fresh net this is
    /// the cold start: the faucet is funded but unspendable until finality forms.
    NoValidAnchor,
    /// The requester's address does not carry a usable ML-KEM encapsulation key, so
    /// the grant note could not be encrypted to them.
    UnusableRecipientAddress,
    /// A selected input note is not a leaf of the anchor's prefix, or its witness
    /// does not fold to the anchor. Reaching this means the inventory and the tree
    /// disagree; it is kept as a typed error rather than a panic because a faucet
    /// must survive its own bookkeeping being wrong.
    WitnessDoesNotResolve { cm: [u64; 4] },
    /// The chosen inputs do not cover `grant + fee` — a selection-layer bug if it
    /// reaches here, since [`crate::Inventory::select_pair`] filters on exactly this.
    Unbalanced { inputs: u64, need: u64 },
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::NoValidAnchor => f.write_str(
                "no valid anchor: nothing is finalized, so no commitment root can be spent against",
            ),
            GrantError::UnusableRecipientAddress => {
                f.write_str("recipient address carries no usable ML-KEM encapsulation key")
            }
            GrantError::WitnessDoesNotResolve { .. } => f.write_str(
                "a spend input's membership witness does not resolve to the anchor",
            ),
            GrantError::Unbalanced { inputs, need } => {
                write!(f, "inputs {inputs} do not cover {need} bessel")
            }
        }
    }
}

impl std::error::Error for GrantError {}

/// A built, proved grant — everything needed to submit it, plus the inventory
/// bookkeeping to apply on acceptance or roll back on refusal.
pub struct GrantPlan {
    /// The consensus transaction: bincode-encoded real proof + declared surface.
    pub entry: TxEntry,
    /// Note-discovery artifacts for **both** outputs, in the tx's commitment order:
    /// the grant to the requester, then the change to the faucet.
    pub discovery: TxDiscovery,
    /// The anchor this proof is bound to, and its deadline.
    pub lease: AnchorLease,
    /// Grant value in bessel.
    pub grant_value: u64,
    /// Posted fee paid (frozen §5 2×2 price).
    pub fee: u64,
    /// The two notes spent. Held so a refusal can restore them.
    pub spent: [OwnedNote; 2],
    /// The change note the faucet gains — *held*, not yet *anchored*.
    pub change: OwnedNote,
    /// Wall-clock seconds spent inside [`prove_bucket`] for this grant.
    pub prove_secs: f64,
    /// Serialized proof length in bytes (the consensus wire).
    pub proof_bytes: usize,
}

impl GrantPlan {
    /// Whether this plan may still be submitted: the self-imposed lease has not run
    /// out **and** the chain still accepts the anchor.
    ///
    /// A faucet that skips this check does not fail safely — it spends a slot, a fee
    /// and 2.3 s of proving on a transaction the mempool will refuse, and (worse)
    /// learns nothing about why. Checking here is what makes an aged-out anchor a
    /// *reported* refusal rather than a silent stall.
    pub fn is_submittable<V: ChainView>(&self, view: &V) -> bool {
        !self.lease.is_expired(view)
    }

    // `spends_coinbase()` is deleted (issue #102). It computed the list of
    // coinbase-note commitments a grant consumes, for `Mempool::admit`'s maturity
    // gate — and that list *is* the §6 privacy leak the gate was retired over: on a
    // chain with one global shielded pool and no transparent tier, naming the
    // coinbase notes a transaction spends links the spend to the coinbase and
    // collapses the anonymity set of exactly the first transaction a new user makes.
    // Maturity is now structural (an immature note has no leaf, so no witness), so
    // there is nothing to declare. Keeping a helper that computes a declaration
    // nobody consumes would leave the leak one call site away from returning.
}

impl std::fmt::Debug for GrantPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantPlan")
            .field("grant_value", &self.grant_value)
            .field("fee", &self.fee)
            .field("anchor", &hex4(&self.lease.anchor))
            .field("lease_expires_at_tip", &self.lease.expires_at_tip())
            .field("change_value", &self.change.value)
            .field("prove_secs", &self.prove_secs)
            .field("proof_bytes", &self.proof_bytes)
            .finish()
    }
}

fn hex4(h: &Hash32) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Fetch the membership witness for `cm` from the live tree, cut against the
/// anchor's leaf count, and cross-check locally that it folds to the anchor.
///
/// The local fold check is the point: a stale or wrong-prefix witness produces an
/// **unprovable** instance, and discovering that after 1.7 s of proving (or worse,
/// at the node) is strictly worse than discovering it here for the price of 32
/// Keccak permutations. Mirrors what `qlab_demo::prover::live_witness` does for the
/// demo; that one takes a spend witness (i.e. the key), while a faucet already
/// holds the commitment, and depending on a demo crate from a service crate would
/// be the wrong direction of arrow.
pub fn witness_for(
    tree: &CommitmentTree,
    leaf_count: u64,
    anchor_lanes: [u64; 4],
    cm: &[u64; 4],
) -> Result<MerkleWitness, GrantError> {
    let pos = tree
        .position_of(cm)
        .filter(|&p| p < leaf_count)
        .ok_or(GrantError::WitnessDoesNotResolve { cm: *cm })?;
    let w = tree.auth_path(pos, leaf_count);
    if w.fold_root(cm) != anchor_lanes {
        return Err(GrantError::WitnessDoesNotResolve { cm: *cm });
    }
    Ok(w)
}

/// Build and prove one grant.
///
/// `inputs` are the two notes to spend (chosen by [`crate::Inventory::select_pair`]),
/// `recipient` is where the grant goes, and `change_d` is the faucet's own address
/// diversifier for the change output. Returns the plan plus the proved instance the
/// caller may verify locally.
///
/// The change output is encrypted to the faucet's **own** address, not left
/// unencrypted: `TxDiscovery` must describe every output commitment in order or the
/// node refuses the submission (`RejectReason::DiscoveryMismatch`), and a faucet
/// that cannot re-derive its own change from the chain cannot be restored from its
/// seed.
#[allow(clippy::too_many_arguments)]
pub fn build_grant<R: CryptoRng>(
    wallet: &Wallet,
    change_d: Diversifier,
    recipient: &Address,
    grant_value: u64,
    inputs: [OwnedNote; 2],
    lease: AnchorLease,
    tree: &CommitmentTree,
    rng: &mut R,
) -> Result<(GrantPlan, BucketInstance, Vec<Val>, Proof<Config>), GrantError> {
    let fee = posted_fee(ArityBucket::TwoByTwo);
    let in_total = inputs[0].value.saturating_add(inputs[1].value);
    let need = grant_value.saturating_add(fee);
    if in_total < need {
        return Err(GrantError::Unbalanced { inputs: in_total, need });
    }
    let change_value = in_total - need;

    let recipient_ek = recipient
        .encapsulation_key()
        .ok_or(GrantError::UnusableRecipientAddress)?;

    // Spend witnesses (the spend capability lives only on the wallet) and their
    // live membership paths, both cut against the anchor's prefix.
    let spend: [TxInput; 2] = [inputs[0].spend_input(wallet), inputs[1].spend_input(wallet)];
    let witnesses: [MerkleWitness; 2] = [
        witness_for(tree, lease.leaf_count, lease.anchor_lanes, &inputs[0].cm)?,
        witness_for(tree, lease.leaf_count, lease.anchor_lanes, &inputs[1].cm)?,
    ];

    // Output 0: the grant, to the requester's rkm. Output 1: change, to ours.
    // ρ/rseed are fresh CSPRNG draws — ρ is what the nullifier binds, so a repeat
    // would make the change note unspendable behind an already-published nullifier.
    let grant_rho = rand_lanes(rng);
    let grant_rseed = rand_lanes(rng);
    let change_rho = rand_lanes(rng);
    let change_rseed = rand_lanes(rng);
    let change_rkm = wallet.rkm(change_d);
    let outputs = [
        TxOutput {
            value: grant_value,
            rkm: recipient.rkm_lanes(),
            rho: grant_rho,
            rseed: grant_rseed,
        },
        TxOutput { value: change_value, rkm: change_rkm, rho: change_rho, rseed: change_rseed },
    ];

    let inst = build_bucket_with_witnesses(
        LOG_HEIGHT,
        &spend,
        &outputs,
        fee,
        &witnesses,
        lease.anchor_lanes,
    );

    let t = Instant::now();
    let (pvs, proof) = prove_bucket(&inst);
    let prove_secs = t.elapsed().as_secs_f64();

    // The consensus proof wire (protocol-spec §4): bincode fixint, the encoding
    // qlab-consensus pins at 145,609 B and the node's real verifier decodes.
    let proof_bytes_vec = bincode::serialize(&proof).expect("proof serializes");
    let proof_bytes = proof_bytes_vec.len();

    // Encrypt each output to its owner. The bundles are laid out recipient-major in
    // the SAME order as `commitments`, which is what binds discovery to the
    // statement (`TxDiscovery::commitments() == tx.public.commitments`).
    let grant_note = Note {
        value: grant_value,
        rkm: recipient.rkm_lanes(),
        rho: grant_rho,
        rseed: grant_rseed,
    };
    let change_note =
        Note { value: change_value, rkm: change_rkm, rho: change_rho, rseed: change_rseed };
    debug_assert_eq!(inst.cm_out[0], grant_note.commitment(), "grant cm seam");
    debug_assert_eq!(inst.cm_out[1], change_note.commitment(), "change cm seam");

    let to_recipient = encrypt_to_recipient(&recipient_ek, &[grant_note], rng);
    let self_ek = wallet.diversified_keypair(&change_d).ek;
    let to_self = encrypt_to_recipient(&self_ek, &[change_note], rng);

    // Issue #188: the grant's discovery group is now part of the transaction the
    // body commits to, and these are the REAL ML-KEM/AEAD bundles — recipient
    // first, then change-to-self, which is exactly D4's recipient-major order
    // over `commitments = [grant_cm, change_cm]`. The `TxDiscovery` below keeps
    // the AEAD payloads for the RPC full-fetch path; only the compact bundles
    // enter consensus.
    let entry = TxEntry::new(
        proof_bytes_vec,
        TxPublic {
            anchor: lease.anchor,
            nullifiers: vec![digest_bytes(&inst.nf[0]), digest_bytes(&inst.nf[1])],
            commitments: vec![digest_bytes(&inst.cm_out[0]), digest_bytes(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        &[to_recipient.bundle.clone(), to_self.bundle.clone()],
    );
    let discovery = TxDiscovery {
        recipients: vec![
            RecipientDiscovery { bundle: to_recipient.bundle, payloads: to_recipient.payloads },
            RecipientDiscovery { bundle: to_self.bundle, payloads: to_self.payloads },
        ],
    };

    let change = OwnedNote {
        value: change_value,
        rho: change_rho,
        rseed: change_rseed,
        d: change_d,
        cm: inst.cm_out[1],
        // Change is never coinbase-derived: it is the output of an ordinary spend,
        // so it carries no maturity obligation of its own.
        coinbase_minted_at: None,
    };

    let plan = GrantPlan {
        entry,
        discovery,
        lease,
        grant_value,
        fee,
        spent: inputs,
        change,
        prove_secs,
        proof_bytes,
    };
    Ok((plan, inst, pvs, proof))
}

fn rand_lanes<R: CryptoRng>(rng: &mut R) -> [u64; 4] {
    core::array::from_fn(|_| {
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lease arithmetic, with no chain: the numbers the report quotes.
    #[test]
    fn the_lease_sits_far_inside_the_protocol_window() {
        let lease = AnchorLease {
            anchor: [7u8; 32],
            anchor_lanes: [0; 4],
            leaf_count: 3,
            acquired_at_tip: 1_000,
            acquired_at_finalized: Some(1_000),
            lease_blocks: PROOF_LEASE_BLOCKS,
        };
        assert_eq!(PROOF_LEASE_BLOCKS, 8, "one checkpoint cadence");
        assert_eq!(lease.expires_at_tip(), 1_008);
        // The published upper bound on remaining life, with finality caught up.
        assert_eq!(lease.window_bound_blocks(), Some(MAX_ANCHOR_AGE_BLOCKS));
        assert_eq!(MAX_ANCHOR_AGE_BLOCKS, 1_152, "24 h at 75 s (frozen)");
        // 8 of 1,152: the unknown initial age would have to exceed 1,144 blocks
        // before the self-imposed lease could outlive the real deadline.
        assert_eq!(MAX_ANCHOR_AGE_BLOCKS / PROOF_LEASE_BLOCKS, 144);

        // Finality lagging shrinks the bound by exactly the lag.
        let lagging = AnchorLease { acquired_at_finalized: Some(900), ..lease };
        assert_eq!(lagging.window_bound_blocks(), Some(MAX_ANCHOR_AGE_BLOCKS - 100));
        // Nothing finalized ⇒ no bound to state.
        let cold = AnchorLease { acquired_at_finalized: None, ..lease };
        assert_eq!(cold.window_bound_blocks(), None);
    }
}
