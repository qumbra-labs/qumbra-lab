//! The scripted end-to-end payment loop: Alice pays Bob a note (real M3 proof,
//! validated by a devnet node), Bob detects it via the compact-block scan path
//! (socket-free) and spends it (second real M3 proof); double-spends are
//! rejected, the spend block finalizes, and the supply counter stays consistent.
//!
//! Honest composition notes (see docs/demo-run.md): the M3 proof's `anchor` is
//! build_bucket's fabricated membership root (F2), treated as finalized for
//! validation; the persistent nullifier set + supply counter are demo-side glue
//! (F4); the prover config is reconstructed in `crate::prover` (F1).

use std::time::Instant;

use p3_uni_stark::Proof;

use qlab_air::narrow::{build_bucket, BucketInstance, TxOutput};
use qlab_cbserver::client::{scan_local, DecoyPolicy, ScanConfig, ScanStats};
use qlab_cbserver::data::{Devnet, StoredBlock, StoredRecipient, StoredTx};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::body::{validate_body, BlockBody, BodyError, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::committee::{devnet_committee, CommitteeState, Vote};
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
use crate::prover::{prove_bucket, verify_proof, Config, Val, LOG_HEIGHT};

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

/// Structured result of one payment-loop run (consumed by the bin + the e2e test).
#[derive(Clone)]
pub struct LoopReport {
    pub sent_value: u64,
    pub detected_value: u64,
    pub bob_nullifier: [u8; 32],
    pub double_spend_rejected: bool,
    pub within_block_double_spend_rejected: bool,
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

    // ── 2. Genesis coinbase: Alice 50k+30k, Bob 40k ─────────────────────────
    supply.mint_coinbase(50_000);
    supply.mint_coinbase(30_000);
    supply.mint_coinbase(40_000);
    say!("Genesis coinbase minted: supply = {}", supply.minted());

    // ── 3. Alice → Bob: build the note, prove the send ──────────────────────
    let sent_value = 60_000u64;
    let (bob_rho, bob_rseed) = ([0x51u64; 4], [0x52u64; 4]);
    let bob_note = Note {
        value: sent_value,
        rkm: bob_addr.rkm_lanes(),
        rho: bob_rho,
        rseed: bob_rseed,
    };
    let a_inputs = [
        alice.spend_input(50_000, [0x11; 4], [0x12; 4], d),
        alice.spend_input(30_000, [0x13; 4], [0x14; 4], d),
    ];
    let a_outputs = [
        TxOutput { value: sent_value, rkm: bob_addr.rkm_lanes(), rho: bob_rho, rseed: bob_rseed },
        TxOutput { value: 19_000, rkm: alice.rkm(d), rho: [0x15; 4], rseed: [0x16; 4] },
    ];
    let send_inst = build_bucket(LOG_HEIGHT, &a_inputs, &a_outputs, 1_000);
    // cm seam: the proof's output commitment[0] == the note's own commitment.
    let cm_seam_holds = send_inst.cm_out[0] == bob_note.commitment();
    say!("Alice builds send tx (2-in/2-out); cm seam holds: {cm_seam_holds}");

    let t = Instant::now();
    let (send_pvs, send_proof) = prove_bucket(&send_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #1 (send): {:.2} s", prove_secs[0]);

    // Encrypt the note to Bob (the compact-entry cm == send_inst.cm_out[0]).
    let enc = encrypt_to_recipient(&bob_ek, &[bob_note], &mut rng);

    // ── 4. Devnet chain + real-proof block validation ───────────────────────
    let mut node = Node::new(KeccakPow, SimConfig::default());
    let send_entry = tx_entry(&send_inst);
    let send_anchor = h32(&send_inst.anchor);
    let send_body = BlockBody { txs: vec![send_entry], coinbase: 0 };
    let verifier = PoolVerifier { pool: vec![(send_inst, send_pvs, send_proof)] };
    // F2: the proof's fabricated anchor is treated as finalized for validation.
    validate_body(&send_body, &verifier, |r: &Hash32| *r == send_anchor)
        .expect("send block validates (real proof verifies)");
    node.mine_next(send_body.commitment()).expect("mine send block");
    supply.record_fee(1_000);
    say!(
        "Send block mined + validated (REAL proof verified by node) at height {}",
        node.tip_height()
    );

    // ── 5. Build the discovery layer + Bob scans (socket-free real path) ─────
    let mut tree = CommitmentTree::new();
    for e in &enc.bundle.entries {
        tree.append_bytes(&e.cm);
    }
    let leaves = vec![(1u64, tree.len())];
    let stored = StoredBlock {
        height: 1,
        header: header_stub(&send_body),
        body: send_body.clone(),
        txs: vec![StoredTx { recipients: vec![StoredRecipient { enc, ours: true }] }],
    };
    let devnet = Devnet::from_parts(vec![stored], tree, dummy_chain(), bob_kp, 1, leaves);
    let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } };
    let outcome = scan_local(&devnet, &devnet.our.dk, 1, 1, cfg, &mut rng);
    assert!(!outcome.notes.is_empty(), "Bob must detect his note");
    let detected = &outcome.notes[0].detected.note;
    let detected_value = detected.value;
    let (det_rho, det_rseed) = (detected.rho, detected.rseed);
    say!(
        "Bob scans compact stream → detects note value {detected_value} (sent {sent_value})"
    );

    // ── 6. Bob spends the detected note (real proof #2) ──────────────────────
    let b_inputs = [
        bob.spend_input(detected_value, det_rho, det_rseed, d),
        bob.spend_input(40_000, [0x21; 4], [0x22; 4], d),
    ];
    let b_outputs = [
        TxOutput { value: 60_000, rkm: alice.rkm(d), rho: [0x23; 4], rseed: [0x24; 4] },
        TxOutput { value: 39_000, rkm: bob.rkm(d), rho: [0x25; 4], rseed: [0x26; 4] },
    ];
    let spend_inst = build_bucket(LOG_HEIGHT, &b_inputs, &b_outputs, 1_000);
    let bob_nullifier = h32(&spend_inst.nf[0]);
    let spend_entry = tx_entry(&spend_inst);
    let spend_anchor = h32(&spend_inst.anchor);

    let t = Instant::now();
    let (spend_pvs, spend_proof) = prove_bucket(&spend_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #2 (spend): {:.2} s", prove_secs[1]);

    let verifier2 = PoolVerifier { pool: vec![(spend_inst, spend_pvs, spend_proof)] };
    let spend_body = BlockBody { txs: vec![spend_entry.clone()], coinbase: 0 };
    validate_body(&spend_body, &verifier2, |r: &Hash32| *r == spend_anchor)
        .expect("spend block validates");
    node.mine_next(spend_body.commitment()).expect("mine spend block");
    supply.record_fee(1_000);
    assert!(nullifiers.insert(bob_nullifier), "first spend lands");
    say!("Spend block mined; Bob's nullifier landed at height {}", node.tip_height());

    // Double-spend #1 (cross-block): re-submit the same nullifier → rejected by set.
    let double_spend_rejected = !nullifiers.insert(bob_nullifier);
    // Double-spend #2 (within-block): two entries with the same nullifier.
    let two_same = BlockBody { txs: vec![spend_entry.clone(), spend_entry], coinbase: 0 };
    let within_block_double_spend_rejected = matches!(
        validate_body(&two_same, &verifier2, |r: &Hash32| *r == spend_anchor),
        Err(BodyError::DoubleSpendInBlock { .. })
    );
    say!(
        "Double-spend rejected — cross-block: {double_spend_rejected}, within-block: {within_block_double_spend_rejected}"
    );

    // ── 7. Finality + supply invariant ──────────────────────────────────────
    let (committee, validators) = devnet_committee(COMMITTEE_SIZE);
    let cstate = CommitteeState::new(committee, BOND_AMOUNT);
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

    // Supply: only coinbase mints (120k) create value; transfers conserve it
    // in-circuit (build_bucket balance); two fees (2k) leave circulation.
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
