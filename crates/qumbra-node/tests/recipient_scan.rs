//! Issue #188 baton 3 acceptance: **a recipient of a real transaction on a real
//! node finds its outputs, and is told plainly what it could not read.**
//!
//! This is the first test in the tree where all four of these hold at once:
//!
//! 1. the chain belongs to a running [`RunningNode`] — the composition the binary
//!    ships, `NodeAdapter` + `P2pNode` over disk stores, not a bare `MemNode`;
//! 2. the transaction got there through the node's **own** admission path
//!    (`submit_local_tx` → `announce_tx` → `ingest_tx` → `Mempool::admit`) and was
//!    assembled into a block by the node's own miner — nothing was hand-applied;
//! 3. the wallet is on the other side of a **real socket**, holding only its
//!    ML-KEM decapsulation key and the node's discovery address;
//! 4. the wallet is the reference light client (`qlab_cbserver::client`), not a
//!    detection loop this file wrote.
//!
//! Baton 2's acceptance had (3) and (4) against a `MemNode` the test applied
//! blocks to by hand, and `run.rs`'s socket test had (1) and (3) against a
//! **coinbase-only** chain with no discovery group in it. Neither could see what
//! this one is for.
//!
//! ## 🔴 What it establishes, and the half it establishes is missing
//!
//! **Finding works and opening does not, and that is a property of the chain
//! rather than of this node.** `discovery-on-the-consensus-wire.md` D2 commits
//! `n_recipients ‖ [ct(1088) ‖ n_outputs ‖ [cm(32) ‖ tag(8) ‖ clue_len(1)]]` and
//! nothing else. The AEAD payload — `Note::to_plaintext()` under
//! `aead_key(K, i)`, the only place a transaction output's `(value, ρ, rseed)`
//! exists — is not in that framing, so it is not in `StoredTx`, not in the body
//! preimage, and not on the P2P wire. There is no chain state in which a
//! `qumbra-node` could serve it, which is why `/v1/block/{h}/tx/{i}/full` is a
//! 404 and why that 404 is honest.
//!
//! So the acceptance this file can carry is: the recipient **locates** every
//! output paid to it, at the right height and transaction, with the right
//! commitments, from a real node over a real socket — and the scan reports
//! `Incomplete` with the coordinates of what it could not open, so a wallet can
//! never render that state as "no notes". Recovering the *value* needs bytes
//! nobody committed; that is reported on the issue as a coordinator decision.

use std::time::Duration;

use qlab_cbserver::client::{
    light_client_scan, Completeness, DecoyPolicy, ScanConfig, Unopened,
};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::Hash32;
use qlab_devnet::pow::KeccakPow;
use qlab_node::{ChainStore, NodeState};
use qlab_note::kem::{generate_keypair, Ek, Keypair};
use qlab_note::note::Note;
use qlab_note::scan::encrypt_to_recipient;
use qlab_note::wire::CM_LEN;
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A test rig: temp data dir + genesis file + all 21 committee key files, and a
/// config pointing at them. Mirrors `run.rs`'s in-crate `rig`, which is
/// `#[cfg(test)]` and so cannot be reached from an integration test.
///
/// `discovery_addr` is `None` here for the same reason it is there: the default
/// is a fixed loopback port, and these tests bind an ephemeral one explicitly.
fn rig(tag: &str) -> (NodeConfig, GenesisFile, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("qumbra-i188-b3-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp dir");
    let genesis = GenesisFile::new_devnet_t0();
    let gpath = base.join("genesis.qmb");
    genesis.write(&gpath).expect("write genesis");
    let keys = genesis.write_committee_key_files(base.join("keys")).expect("write keys");
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: gpath,
        committee_key_paths: keys, // all 21 → this node can finalize on its own
        mining: true,
        expected_genesis_hash: Some(genesis.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: None,
    };
    (config, genesis, base)
}

fn lanes(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

fn note(rng: &mut StdRng) -> Note {
    Note {
        value: 1 + (rng.next_u64() % 1_000_000),
        rkm: lanes(rng),
        rho: lanes(rng),
        rseed: lanes(rng),
    }
}

/// A transaction paying `k` real notes to `ek`, whose discovery group **is** the
/// ML-KEM bundle those notes were encrypted under — the same construction baton
/// 2's acceptance uses, so the group binds `TxPublic::commitments` by
/// construction and `check_tx_discovery` has something real to check.
fn payment_to(
    ek: &Ek,
    k: usize,
    nf_seed: u8,
    anchor: Hash32,
    rng: &mut StdRng,
) -> (TxEntry, Vec<Note>) {
    let notes: Vec<Note> = (0..k).map(|_| note(rng)).collect();
    let enc = encrypt_to_recipient(ek, &notes, rng);
    let commitments: Vec<Hash32> = enc.bundle.entries.iter().map(|e| e.cm).collect();
    let tx = TxEntry::new(
        b"proof-placeholder".to_vec(),
        TxPublic {
            anchor,
            nullifiers: (0..k).map(|i| [nf_seed.wrapping_add(i as u8); 32]).collect(),
            commitments,
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
        &[enc.bundle],
    );
    (tx, notes)
}

fn cm_of(n: &Note) -> [u8; CM_LEN] {
    qlab_note::hash::digest_bytes(&n.commitment())
}

/// 🔴 **The acceptance test.**
///
/// The proof is a placeholder and the verifier is the rehearsal no-op, for the
/// reason baton 2 gave and which has not changed: `check_tx_discovery` never
/// reads a proof, and a real 2×2 STARK here would add ~2.3 s and ~11.8 GB to
/// re-test what `tests/coinbase_spend.rs` already tests against the production
/// verifier. What is *not* stubbed is everything this test is about — the
/// mempool, the miner, `validate_body`, the block store, the projection, the
/// socket and the reference wallet.
#[test]
fn a_recipient_finds_its_outputs_on_a_running_nodes_own_chain_over_a_real_socket() {
    let mut rng = StdRng::seed_from_u64(0x188_3);
    let recipient: Keypair = generate_keypair(&mut rng);
    let neighbour: Keypair = generate_keypair(&mut rng);
    let stranger: Keypair = generate_keypair(&mut rng);

    let (config, genesis, base) = rig("recipient-finds");
    let mut node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("the node starts on its own genesis");
    node.set_mine_interval(Duration::ZERO);

    // Finalize genesis, which is what makes the empty commitment root an anchor a
    // transaction may bind to. Nothing below is hand-applied.
    node.try_checkpoint();
    assert_eq!(node.finalized_height(), Some(0), "genesis finalized");
    let anchor = node.state().commitment_root();
    assert!(node.state().is_valid_anchor(&anchor), "the finalized empty root is an anchor");

    // A 2-output payment to the recipient and a 1-output payment to somebody else,
    // so "found mine" is a discrimination and not a count.
    let (mine, paid) = payment_to(&recipient.ek, 2, 1, anchor, &mut rng);
    let (theirs, _) = payment_to(&neighbour.ek, 1, 40, anchor, &mut rng);
    assert!(node.submit_local_tx(mine), "the node's own mempool admits it");
    assert!(node.submit_local_tx(theirs), "and the neighbour's");

    // The node's own miner assembles and applies the block.
    assert!(node.try_mine(), "KeccakPow mines at genesis difficulty");
    let height = node.tip_height();
    assert_eq!(height, 1);

    // The block really carries two committed discovery groups — otherwise every
    // assertion below could pass against a chain that mined an empty block.
    {
        let tip = node.state().tip_hash();
        let stored = node.state().chain().block(&tip).expect("tip stored");
        assert_eq!(stored.txs.len(), 2, "both transactions were mined");
        assert!(
            stored.txs.iter().all(|t| t.discovery.len() > qlab_note::kem::CT_LEN),
            "real committed bundles, not the n = 0 case"
        );
    }

    let bound = node.start_discovery_endpoint("127.0.0.1:0").expect("bind ephemeral");
    let base_url = format!("http://{bound}");
    let cfg = ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off };

    // ---- The wallet. Only `dk`, only `base_url`. ---------------------------
    let mut wrng = StdRng::seed_from_u64(7);
    let out = light_client_scan(&base_url, &recipient.dk, 0, height, cfg, &mut wrng)
        .expect("the committed half resolves, so the scan runs");

    // 🔴 THE PROPERTY: located, at the right coordinates, with the right
    // commitments — from a running node's own chain, over a socket.
    assert_eq!(out.stats.detected_outputs, 2, "both outputs paid to this wallet were located");
    assert!(
        out.unopened.iter().all(|u| u.height == height),
        "at the height the payment was mined at: {:?}",
        out.unopened
    );
    let mut located: Vec<[u8; CM_LEN]> = out.unopened.iter().map(|u| u.cm).collect();
    let mut expected: Vec<[u8; CM_LEN]> = paid.iter().map(cm_of).collect();
    located.sort();
    expected.sort();
    assert_eq!(
        located, expected,
        "and they are the commitments of the notes actually paid, not merely two of something"
    );
    // The tx index is a real chain coordinate, not a constant: whichever slot the
    // node's assembler put the payment in, both outputs agree on it.
    let tx_indices: Vec<u64> = out.unopened.iter().map(|u| u.tx_index).collect();
    assert!(tx_indices.windows(2).all(|w| w[0] == w[1]), "one transaction: {tx_indices:?}");

    // 🔴 AND THE SECOND PROPERTY: this is reported as an incomplete scan, never as
    // an empty wallet. The node holds no AEAD payload because no block does.
    assert_eq!(out.notes.len(), 0, "nothing can be opened from chain data alone");
    assert_eq!(
        out.completeness(),
        Completeness::Incomplete { detected: 2, opened: 0 },
        "a scan that could not complete must not read as a scan that found nothing"
    );
    for u in &out.unopened {
        match &u.why {
            Unopened::PayloadUnavailable(e) => assert!(
                e.contains("404"),
                "the reason is the node's honest 404 on /v1/…/full, verbatim: {e}"
            ),
            other => panic!("expected the payload route to be absent, got {other:?}"),
        }
    }

    // ---- A different key recovers nothing from the same chain. -------------
    let mut srng = StdRng::seed_from_u64(9);
    let none = light_client_scan(&base_url, &stranger.dk, 0, height, cfg, &mut srng)
        .expect("scan runs");
    assert_eq!(none.stats.detected_outputs, 0, "a stranger's key detects nothing");
    assert_eq!(none.notes.len(), 0);
    assert!(none.unopened.is_empty());
    assert_eq!(
        none.completeness(),
        Completeness::Complete,
        "🔴 and *that* empty answer is complete — the distinction this baton exists for"
    );
    assert_eq!(none.stats.matched_fetches, 0, "no detection ⇒ no fetch ⇒ no pattern to observe");

    // The neighbour finds exactly its own one output, so detection is a key
    // operation and not a server-side filter — the node was never told who asked.
    let mut nrng = StdRng::seed_from_u64(11);
    let neighbours = light_client_scan(&base_url, &neighbour.dk, 0, height, cfg, &mut nrng)
        .expect("scan runs");
    assert_eq!(neighbours.stats.detected_outputs, 1);
    assert_ne!(
        neighbours.unopened[0].tx_index, out.unopened[0].tx_index,
        "and it is the other transaction"
    );

    let _ = std::fs::remove_dir_all(&base);
}
