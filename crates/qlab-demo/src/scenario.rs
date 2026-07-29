//! The scripted end-to-end payment loop: Alice pays Bob a note (real M3 proof,
//! validated by a devnet node), Bob detects it via the compact-block scan path
//! (socket-free) and spends it (second real M3 proof); double-spends are
//! rejected, the spend block finalizes, and the supply counter stays consistent.
//!
//! **Issue #39 — real finalized anchors.** The spends no longer anchor to a
//! fabricated membership root. A single global commitment tree (`anchor_tree`)
//! holds the notes being spent; its root is *finalized* through the committee,
//! and each spend fetches a live membership witness (`prover::live_witness`) that
//! resolves to that finalized root. Block validation runs the full §6 + §8 gate
//! (`FinalityTracker::is_anchor_acceptable`): finalized-only AND within the
//! ≤24 h age window. Two negatives are exercised — a never-finalized anchor and
//! an expired (too-old finalized) anchor are both rejected.
//!
//! Honest composition notes (see docs/demo-run.md): the cbserver discovery
//! `Devnet` keeps its own light-client tree view built from the block's
//! encrypted entries (the scan layer); `anchor_tree` is the consensus commitment
//! tree the proofs prove membership against — the same note commitments, two
//! views. The persistent nullifier set + supply counter are demo-side glue (F4);
//! the prover config is reconstructed in `crate::prover` (F1).

use std::time::Instant;

use qlab_consensus::Proof;

use qlab_air::narrow::{build_bucket_with_witnesses, derive_input, BucketInstance, TxInput, TxOutput};
use qlab_cbserver::client::{scan_local, DecoyPolicy, ScanConfig, ScanStats};
use qlab_cbserver::data::{Devnet, StoredBlock, StoredRecipient, StoredTx};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::body::{validate_body, BlockBody, BodyError, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, Checkpoint, CommitteeState, Validator, Vote};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::node::{Node, SimConfig};
use qlab_devnet::params_devnet::{BOND_AMOUNT, CHECKPOINT_CADENCE_BLOCKS, COMMITTEE_SIZE};
use qlab_devnet::pow::KeccakPow;
use qlab_note::note::Note;
use qlab_note::scan::{encrypt_to_recipient, ScanMode};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::ledger::{NullifierSet, SupplyTracker};
use crate::prover::{live_witness, prove_bucket, verify_proof, Config, Val, LOG_HEIGHT};

/// Demo anchor-age window (blocks). Compressed from the real
/// `MAX_ANCHOR_AGE_BLOCKS` (24 h @ 60 s = 1440) so the accelerated sim can
/// actually *show* an anchor expiring within a handful of blocks. Fresh spends
/// (age 0) pass; a root this many blocks behind the finalized head is expired.
const DEMO_ANCHOR_WINDOW_BLOCKS: u64 = 4;

/// `[u64;4]` qlab-air digest → 32 bytes (lane-major LE) — the m6devnet convention.
fn h32(x: &[u64; 4]) -> Hash32 {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&x[i].to_le_bytes());
    }
    o
}

/// The real M3 verifier injected into `validate_body`: it holds proved
/// instances/pvs/proofs and runs `crate::prover::verify_proof`. The TxEntry's
/// proof bytes encode the pool index (little-endian u64), the m6devnet pattern.
struct PoolVerifier {
    pool: Vec<(BucketInstance, Vec<Val>, Proof<Config>)>,
}
impl TxVerifier for PoolVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        let idx = usize::from_le_bytes(entry.proof[..8].try_into().expect("8-byte index"));
        let (inst, pvs, proof) = &self.pool[idx];
        verify_proof(inst, pvs, proof)
    }
}

/// A `TxEntry` (pool index 0) carrying `inst`'s real public surface.
fn tx_entry(inst: &BucketInstance) -> TxEntry {
    TxEntry {
        proof: 0u64.to_le_bytes().to_vec(),
        public: TxPublic {
            anchor: h32(&inst.anchor),
            nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
            commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}

/// A structurally-valid `TxEntry` carrying an arbitrary `anchor` — for the
/// anchor-rejection negatives. `validate_body` checks the header/body binding
/// first (issue #77) and the anchor gate next, so these bodies are always paired
/// with [`header_committing_to`] and the nullifier/commitment/fee fields stay
/// inert (never reached).
fn entry_with_anchor(anchor: Hash32) -> TxEntry {
    TxEntry {
        proof: 0u64.to_le_bytes().to_vec(),
        public: TxPublic {
            anchor,
            nullifiers: vec![[0u8; 32], [1u8; 32]],
            commitments: vec![[2u8; 32], [3u8; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}

/// The header this body belongs to, for the demo's `validate_body` calls
/// (issue #77 — validation now takes the header, so the body it is handed must be
/// the body the header committed to).
///
/// The demo mines through `qlab_devnet::Node::mine_next(commitment)`, the
/// header-only lane that is handed a commitment *value* rather than a body
/// (Addendum A4), so the header does not exist yet at validation time and this
/// stands one in with the same commitment `mine_next` is about to be given. The
/// binding is therefore satisfied by construction here — the demo shows the
/// happy path; the seams that must *reject* a mismatch are test-locked in
/// `qlab-p2p` and `qlab-node`, plus the empty-body negative asserted below.
fn header_committing_to(body: &BlockBody) -> BlockHeader {
    BlockHeader::child_of(&BlockHeader::genesis(1, 0), 0, 1, body.commitment())
}

/// Structural stand-in header for the discovery-layer StoredBlock. The compact
/// server serves compact/full/frontier only — it never consults the header —
/// so its exact contents are immaterial; it is carried for fidelity.
fn header_stub(body: &BlockBody) -> BlockHeader {
    let g = BlockHeader::genesis(1_000, 0);
    BlockHeader::child_of(&g, 1, 1_000, body.commitment())
}

/// Stand-in chain for `Devnet::from_parts` (the discovery layer never reads it).
fn dummy_chain() -> qlab_devnet::chain::ChainState {
    qlab_devnet::chain::ChainState::new(BlockHeader::genesis(1_000, 0))
}

/// Finalize the commitment-tree `root` at block `height` (issue #39): a
/// committee ⅔ quorum signs a checkpoint whose ROOT is the commitment root
/// (the block hash comes from the node's main chain, as consensus requires),
/// so `node.finality().is_anchor_acceptable(root, …)` then reports it final.
fn finalize_root(
    node: &mut Node<KeccakPow>,
    cstate: &CommitteeState,
    validators: &[Validator],
    height: u64,
    root: Hash32,
) {
    let base = node.checkpoint_at(height).expect("main-chain block at height");
    let cp = Checkpoint::new(height, base.block_hash, root);
    let quorum = cstate.quorum_threshold();
    let votes: Vec<Vote> = validators[..quorum].iter().map(|v| v.sign_checkpoint(&cp)).collect();
    node.finalize(&cp, &votes, cstate).expect("finalize commitment root");
}

/// Structured result of one payment-loop run (consumed by the bin + the e2e test).
#[derive(Clone)]
pub struct LoopReport {
    pub sent_value: u64,
    pub detected_value: u64,
    pub bob_nullifier: [u8; 32],
    pub double_spend_rejected: bool,
    pub within_block_double_spend_rejected: bool,
    /// Issue #77: an honest header relayed with an EMPTY body is rejected by the
    /// header/body binding — the cheapest state-divergence exploit.
    pub unbound_body_rejected: bool,
    /// Issue #39: the send anchored to a REAL finalized commitment-tree root
    /// (not a fabricated one), and the live membership witness resolved to it.
    pub anchor_finalized: bool,
    /// The finalized commitment root the send proof anchored to (R0).
    pub real_anchor: [u8; 32],
    /// A never-finalized anchor is rejected by the §6 finalized-only gate.
    pub non_final_anchor_rejected: bool,
    /// A finalized-but-too-old anchor is rejected by the §8 age window.
    pub expired_anchor_rejected: bool,
    pub spend_finalized: bool,
    pub supply_minted: u64,
    pub supply_consistent: bool,
    pub cm_seam_holds: bool,
    pub proofs_generated: usize,
    pub prove_secs: Vec<f64>,
    pub scan_stats: ScanStats,
    pub wall_secs: f64,
    pub transcript: Vec<String>,
}

pub fn run_loop(seed: u64) -> LoopReport {
    let t_start = Instant::now();
    let mut tr: Vec<String> = Vec::new();
    macro_rules! say {
        ($($a:tt)*) => { tr.push(format!($($a)*)); };
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut supply = SupplyTracker::new();
    let mut nullifiers = NullifierSet::new();
    let mut prove_secs = Vec::new();
    let d = Diversifier::default();

    // ── 1. Two wallets; Bob publishes an address ────────────────────────────
    let alice = Wallet::from_seed_lanes([0x1111_1111_1111_1111; 4]);
    let bob = Wallet::from_seed_lanes([0x2222_2222_2222_2222; 4]);
    let bob_addr_str = bob.address(d).encode();
    let bob_addr = Address::decode(&bob_addr_str).expect("bob address round-trips");
    let bob_ek = bob_addr.encapsulation_key().expect("bob ek");
    let bob_kp = bob.diversified_keypair(&d);
    say!("Bob publishes address {}… ({} chars)", &bob_addr_str[..24], bob_addr_str.len());

    // ── 2. Devnet node + committee + the global commitment tree ─────────────
    let mut node = Node::new(KeccakPow, SimConfig::default());
    let (committee, validators) = devnet_committee(COMMITTEE_SIZE);
    let cstate = CommitteeState::new(committee, BOND_AMOUNT);
    // The global note-commitment tree the spends prove membership against.
    let mut anchor_tree = CommitmentTree::new();
    let leaf = |inp: &TxInput| derive_input(inp).2;

    // Genesis coinbase: Alice 50k+30k, Bob 40k — their commitments enter the tree
    // as the pre-existing UTXOs the loop will spend.
    supply.mint_coinbase(50_000);
    supply.mint_coinbase(30_000);
    supply.mint_coinbase(40_000);
    let a_inputs = [
        alice.spend_input(50_000, [0x11; 4], [0x12; 4], d),
        alice.spend_input(30_000, [0x13; 4], [0x14; 4], d),
    ];
    let bob_40k = bob.spend_input(40_000, [0x21; 4], [0x22; 4], d);
    anchor_tree.append(leaf(&a_inputs[0])); // pos 0
    anchor_tree.append(leaf(&a_inputs[1])); // pos 1
    anchor_tree.append(leaf(&bob_40k)); //     pos 2
    // Finalize the genesis commitment root R0 (height 0) — the anchor Alice will
    // prove against (finalized BEFORE she spends, per §6).
    let r0_lanes = anchor_tree.root();
    let r0 = h32(&r0_lanes);
    let count0 = anchor_tree.len();
    finalize_root(&mut node, &cstate, &validators, 0, r0);
    say!(
        "Genesis coinbase minted (supply {}); commitment tree has {} notes; root R0 finalized",
        supply.minted(),
        count0
    );

    // ── 3. Alice → Bob: fetch live witnesses, prove the send against R0 ──────
    let sent_value = 60_000u64;
    let (bob_rho, bob_rseed) = ([0x51u64; 4], [0x52u64; 4]);
    let bob_note = Note {
        value: sent_value,
        rkm: bob_addr.rkm_lanes(),
        rho: bob_rho,
        rseed: bob_rseed,
    };
    let a_outputs = [
        TxOutput { value: sent_value, rkm: bob_addr.rkm_lanes(), rho: bob_rho, rseed: bob_rseed },
        TxOutput { value: 19_000, rkm: alice.rkm(d), rho: [0x15; 4], rseed: [0x16; 4] },
    ];
    // The wallet/prover fetches each input's membership witness from the live
    // tree; each resolves to the finalized R0 (issue #39 — no fabricated tree).
    let a_witnesses = [
        live_witness(&anchor_tree, count0, r0_lanes, &a_inputs[0]),
        live_witness(&anchor_tree, count0, r0_lanes, &a_inputs[1]),
    ];
    let send_inst =
        build_bucket_with_witnesses(LOG_HEIGHT, &a_inputs, &a_outputs, 1_000, &a_witnesses, r0_lanes);
    let anchor_finalized = send_inst.anchor == r0_lanes && node.finality().is_root_final(&r0);
    // cm seam: the proof's output commitment[0] == the note's own commitment.
    let cm_seam_holds = send_inst.cm_out[0] == bob_note.commitment();
    say!(
        "Alice builds send tx (2-in/2-out) anchored to finalized R0; cm seam holds: {cm_seam_holds}"
    );

    let t = Instant::now();
    let (send_pvs, send_proof) = prove_bucket(&send_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #1 (send): {:.2} s", prove_secs[0]);

    // Encrypt the note to Bob (the compact-entry cm == send_inst.cm_out[0]).
    let enc = encrypt_to_recipient(&bob_ek, &[bob_note], &mut rng);

    // ── 4. Node validates the send against the full §6 + §8 anchor gate ──────
    let send_entry = tx_entry(&send_inst);
    let send_body = BlockBody { txs: vec![send_entry], coinbase: 0, coinbase_rkm: [0; 4] };
    // cm_out surfaces bound into the send proof; keep them for the tree append.
    let send_out_cms = send_inst.cm_out;
    let verifier = PoolVerifier { pool: vec![(send_inst, send_pvs, send_proof)] };
    let send_header = header_committing_to(&send_body);
    validate_body(&send_header, &send_body, &verifier, |r: &Hash32| {
        node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
    })
    .expect("send block validates (REAL proof + finalized fresh anchor)");
    // Issue #77, the cheapest exploit: the same honest header relayed with an
    // EMPTY body. Every other body rule passes trivially on an empty body — the
    // binding is the only thing that rejects it.
    let empty_body_rejected = matches!(
        validate_body(&send_header, &BlockBody::default(), &verifier, |r: &Hash32| {
            node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
        }),
        Err(BodyError::CommitmentMismatch { .. })
    );
    say!("Honest send header + EMPTY body rejected (issue #77): {empty_body_rejected}");
    node.mine_next(send_body.commitment()).expect("mine send block");
    supply.record_fee(1_000);
    // The send's outputs join the commitment tree; finalize the new root R1.
    anchor_tree.append(send_out_cms[0]); // Bob's 60k note -> pos 3
    anchor_tree.append(send_out_cms[1]); // Alice's 19k change -> pos 4
    let r1_lanes = anchor_tree.root();
    let r1 = h32(&r1_lanes);
    let count1 = anchor_tree.len();
    let h1 = node.tip_height();
    finalize_root(&mut node, &cstate, &validators, h1, r1);
    say!(
        "Send block mined + validated (real proof, finalized anchor) at height {}; outputs appended, root R1 finalized ({} notes)",
        node.tip_height(),
        count1
    );

    // ── 5. Build the discovery layer + Bob scans (socket-free real path) ─────
    let mut disc_tree = CommitmentTree::new();
    for e in &enc.bundle.entries {
        disc_tree.append_bytes(&e.cm);
    }
    let leaves = vec![(1u64, disc_tree.len())];
    let stored = StoredBlock {
        height: 1,
        header: header_stub(&send_body),
        body: send_body.clone(),
        txs: vec![StoredTx { recipients: vec![StoredRecipient { enc, ours: true }] }],
    };
    let devnet = Devnet::from_parts(vec![stored], disc_tree, dummy_chain(), bob_kp, 1, leaves);
    let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } };
    let outcome = scan_local(&devnet, &devnet.our.dk, 1, 1, cfg, &mut rng);
    assert!(!outcome.notes.is_empty(), "Bob must detect his note");
    let detected = &outcome.notes[0].detected.note;
    let detected_value = detected.value;
    let (det_rho, det_rseed) = (detected.rho, detected.rseed);
    say!(
        "Bob scans compact stream → detects note value {detected_value} (sent {sent_value})"
    );

    // ── 6. Bob spends the detected note (real proof #2) against R1 ───────────
    // Bob's inputs: the detected 60k (now leaf 3) + his genesis 40k (leaf 2).
    let b_inputs = [
        bob.spend_input(detected_value, det_rho, det_rseed, d),
        bob_40k,
    ];
    let b_outputs = [
        TxOutput { value: 60_000, rkm: alice.rkm(d), rho: [0x23; 4], rseed: [0x24; 4] },
        TxOutput { value: 39_000, rkm: bob.rkm(d), rho: [0x25; 4], rseed: [0x26; 4] },
    ];
    let b_witnesses = [
        live_witness(&anchor_tree, count1, r1_lanes, &b_inputs[0]),
        live_witness(&anchor_tree, count1, r1_lanes, &b_inputs[1]),
    ];
    let spend_inst =
        build_bucket_with_witnesses(LOG_HEIGHT, &b_inputs, &b_outputs, 1_000, &b_witnesses, r1_lanes);
    let bob_nullifier = h32(&spend_inst.nf[0]);
    let spend_entry = tx_entry(&spend_inst);

    let t = Instant::now();
    let (spend_pvs, spend_proof) = prove_bucket(&spend_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #2 (spend, anchored to finalized R1): {:.2} s", prove_secs[1]);

    let verifier2 = PoolVerifier { pool: vec![(spend_inst, spend_pvs, spend_proof)] };
    let spend_body = BlockBody { txs: vec![spend_entry.clone()], coinbase: 0, coinbase_rkm: [0; 4] };
    validate_body(&header_committing_to(&spend_body), &spend_body, &verifier2, |r: &Hash32| {
        node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
    })
    .expect("spend block validates");
    node.mine_next(spend_body.commitment()).expect("mine spend block");
    supply.record_fee(1_000);
    assert!(nullifiers.insert(bob_nullifier), "first spend lands");
    say!("Spend block mined; Bob's nullifier landed at height {}", node.tip_height());

    // Double-spend #1 (cross-block): re-submit the same nullifier → rejected by set.
    let double_spend_rejected = !nullifiers.insert(bob_nullifier);
    // Double-spend #2 (within-block): two entries with the same nullifier.
    let two_same = BlockBody { txs: vec![spend_entry.clone(), spend_entry], coinbase: 0, coinbase_rkm: [0; 4] };
    let within_block_double_spend_rejected = matches!(
        validate_body(&header_committing_to(&two_same), &two_same, &verifier2, |r: &Hash32| {
            node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
        }),
        Err(BodyError::DoubleSpendInBlock { .. })
    );
    say!(
        "Double-spend rejected — cross-block: {double_spend_rejected}, within-block: {within_block_double_spend_rejected}"
    );

    // ── 7. Anchor negative #1: a never-finalized root is rejected (§6) ───────
    // root_at(4) is a real intermediate tree state that was never checkpointed.
    let never_final = h32(&anchor_tree.root_at(4));
    assert!(!node.finality().is_root_final(&never_final), "root_at(4) was never finalized");
    let nf_body = BlockBody { txs: vec![entry_with_anchor(never_final)], coinbase: 0, coinbase_rkm: [0; 4] };
    let non_final_anchor_rejected = matches!(
        validate_body(&header_committing_to(&nf_body), &nf_body, &verifier2, |r: &Hash32| {
            node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
        }),
        Err(BodyError::AnchorNotFinal { .. })
    );
    say!("Non-finalized anchor (root_at 4) rejected: {non_final_anchor_rejected}");

    // ── 8. Finality (spend_finalized) + then anchor negative #2: expiry ──────
    let quorum = cstate.quorum_threshold();
    while node.tip_height() % CHECKPOINT_CADENCE_BLOCKS != 0 {
        node.mine_next(spend_body.commitment()).expect("mine to cadence");
    }
    let h = node.tip_height();
    let cp = node.checkpoint_at(h).expect("checkpoint");
    let votes: Vec<Vote> = validators[..quorum].iter().map(|v| v.sign_checkpoint(&cp)).collect();
    node.finalize(&cp, &votes, &cstate).expect("finalize");
    let spend_finalized = node.finalized_height().map(|f| f >= 2).unwrap_or(false);
    say!(
        "Finalized to height {:?}; spend (height 2) finalized: {spend_finalized}",
        node.finalized_height()
    );

    // Anchor negative #2 (§8 age window): R0 is still a finalized root, but the
    // head is now far ahead — R0 is EXPIRED (age > window) and rejected.
    let r0_still_final = node.finality().is_root_final(&r0);
    let r0_age = node.finality().anchor_age(&r0);
    let r0_expired = !node.finality().is_anchor_acceptable(&r0, DEMO_ANCHOR_WINDOW_BLOCKS);
    let exp_body = BlockBody { txs: vec![entry_with_anchor(r0)], coinbase: 0, coinbase_rkm: [0; 4] };
    let expired_anchor_rejected = r0_still_final
        && r0_expired
        && matches!(
            validate_body(&header_committing_to(&exp_body), &exp_body, &verifier2, |r: &Hash32| {
                node.finality().is_anchor_acceptable(r, DEMO_ANCHOR_WINDOW_BLOCKS)
            }),
            Err(BodyError::AnchorNotFinal { .. })
        );
    say!(
        "Expired anchor R0 rejected: {expired_anchor_rejected} (still final: {r0_still_final}, age: {r0_age:?} > window {DEMO_ANCHOR_WINDOW_BLOCKS})"
    );

    // Supply: only coinbase mints (120k) create value; transfers conserve it
    // in-circuit (the balance constraint); two fees (2k) leave circulation.
    let supply_consistent = supply.minted() == 120_000 && supply.circulating() == 118_000;
    say!(
        "Supply: minted {}, circulating {} (2 fees) — consistent: {supply_consistent}",
        supply.minted(),
        supply.circulating()
    );

    LoopReport {
        sent_value,
        detected_value,
        bob_nullifier,
        double_spend_rejected,
        within_block_double_spend_rejected,
        unbound_body_rejected: empty_body_rejected,
        anchor_finalized,
        real_anchor: r0,
        non_final_anchor_rejected,
        expired_anchor_rejected,
        spend_finalized,
        supply_minted: supply.minted(),
        supply_consistent,
        cm_seam_holds,
        proofs_generated: 2,
        prove_secs,
        scan_stats: outcome.stats,
        wall_secs: t_start.elapsed().as_secs_f64(),
        transcript: tr,
    }
}
