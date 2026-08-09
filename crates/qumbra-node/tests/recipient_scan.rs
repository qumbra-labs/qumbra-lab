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
//! ## 🔴 What it establishes — and the half that was missing is now here
//!
//! **Finding worked and opening did not**, and this file used to say so at
//! length: D2 committed `n_recipients ‖ [ct ‖ n_outputs ‖ [cm ‖ tag ‖
//! clue_len]]` and nothing else, so the AEAD payload — the only place a
//! transaction output's `(value, ρ, rseed)` exists — was not in `StoredTx`, not
//! in the body preimage, and unserveable by any node. **That paragraph is
//! obsolete twice over** and is kept only in this note so a reader does not
//! trust a stale copy of it elsewhere:
//!
//! 1. the mint (PR #252, issue #188 (a) as amended) relocated the 120 B payload
//!    **into** the committed region, so every node holds it;
//! 2. this baton's `GET /v1/block/{h}/tx/{i}/full` serves it, as a projection of
//!    that region.
//!
//! So the acceptance is now the whole sentence: the recipient **locates** every
//! output paid to it and **opens** it, recovering the value the sender actually
//! paid, from a real node over a real socket — and a stranger's key still
//! recovers nothing. The honesty vocabulary keeps its shape where it is still
//! the truth: a payload that fails AEAD is `detected N, opened M<N` with the
//! reason, never a partial total (`a_tampered_committed_payload_…` below).

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
        // Issue #188 (a) as amended: the real payloads ride in the committed
        // discovery region, not only in a served side table.
        &enc.payloads,
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
        out.notes.iter().all(|n| n.height == height),
        "at the height the payment was mined at: {:?}",
        out.notes.iter().map(|n| n.height).collect::<Vec<_>>()
    );
    let mut located: Vec<[u8; CM_LEN]> = out.notes.iter().map(|n| n.cm).collect();
    let mut expected: Vec<[u8; CM_LEN]> = paid.iter().map(cm_of).collect();
    located.sort();
    expected.sort();
    assert_eq!(
        located, expected,
        "and they are the commitments of the notes actually paid, not merely two of something"
    );
    // The tx index is a real chain coordinate, not a constant: whichever slot the
    // node's assembler put the payment in, both outputs agree on it.
    let tx_indices: Vec<u64> = out.notes.iter().map(|n| n.tx_index).collect();
    assert!(tx_indices.windows(2).all(|w| w[0] == w[1]), "one transaction: {tx_indices:?}");

    // 🔴 AND THE SECOND PROPERTY, which is the one this baton added: the outputs
    // OPEN. The committed payload section carries `(value, ρ, rseed)`, the node
    // serves it as a projection of the block, and the scan recovers the notes
    // the sender actually paid — value included, which is the number a balance
    // is made of.
    assert!(out.unopened.is_empty(), "nothing was left unopened: {:?}", out.unopened);
    assert_eq!(
        out.completeness(),
        Completeness::Complete,
        "detected AND opened — the verdict a wallet may print a figure under"
    );
    let mut opened: Vec<Note> = out.notes.iter().map(|n| n.detected.note.clone()).collect();
    let mut paid_sorted = paid.clone();
    opened.sort_by_key(|n| n.value);
    paid_sorted.sort_by_key(|n| n.value);
    assert_eq!(opened, paid_sorted, "the opened notes ARE the notes that were paid");
    assert_eq!(
        out.spendable_value(),
        paid.iter().map(|n| u128::from(n.value)).sum::<u128>(),
        "and the spendable balance is the value the sender actually sent"
    );
    assert_eq!(out.stats.matched_fetches, 1, "one payload fetch, for the one matched transaction");

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

    // The neighbour finds and opens exactly its own one output, so detection is a
    // key operation and not a server-side filter — the node was never told who
    // asked, and it served the same payload bytes to both wallets.
    let mut nrng = StdRng::seed_from_u64(11);
    let neighbours = light_client_scan(&base_url, &neighbour.dk, 0, height, cfg, &mut nrng)
        .expect("scan runs");
    assert_eq!(neighbours.stats.detected_outputs, 1);
    assert_eq!(neighbours.completeness(), Completeness::Complete);
    assert_ne!(
        neighbours.notes[0].tx_index, out.notes[0].tx_index,
        "and it is the other transaction"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// 🔴 **The live acceptance shape, in miniature: a grant beyond the first
/// compact page is detected AND opened, and the spendable balance equals the
/// grant.** This extends lab issue #309's regression (PR #312) from the
/// reference server onto a real node's serving surface — #312 proved the client
/// pages, and could not prove that what the later page points at is openable,
/// because nothing served the payloads then.
///
/// **The page bound is shrunk client-side and that is deliberate**, stated
/// rather than buried: a deployed node's real bound is
/// `qlab_node::MAX_COMPACT_BLOCKS` = 1,024 blocks, and mining 1,025 blocks here
/// would cost minutes of rig time to exercise arithmetic the client already
/// owns. The wrapper below truncates every `/v1/compact` response to two blocks
/// — the same condition, at a size a test can hold — and passes `/full` through
/// untouched, so the only thing under test is that paging and opening compose.
#[test]
fn a_grant_beyond_the_first_compact_page_is_detected_and_opened() {
    use qlab_cbserver::client::light_client_scan_with;
    use qlab_cbserver::codec::{decode_compact_response, encode_compact_response};

    let mut rng = StdRng::seed_from_u64(0x309_188);
    let recipient: Keypair = generate_keypair(&mut rng);
    let stranger: Keypair = generate_keypair(&mut rng);

    let (config, genesis, base) = rig("paged-grant");
    let mut node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("the node starts on its own genesis");
    node.set_mine_interval(Duration::ZERO);
    node.try_checkpoint();
    let anchor = node.state().commitment_root();

    // Four blocks paying a stranger, then the grant in the fifth — so the first
    // two-block page cannot contain it and a client that does not page reports
    // the #309 symptom (`Complete` / nothing) about a chain that paid it.
    for i in 0..4u8 {
        let (theirs, _) = payment_to(&stranger.ek, 1, 40 + i, anchor, &mut rng);
        assert!(node.submit_local_tx(theirs), "the node admits the stranger's payment");
        assert!(node.try_mine(), "mined");
    }
    let (grant_tx, granted) = payment_to(&recipient.ek, 1, 1, anchor, &mut rng);
    assert!(node.submit_local_tx(grant_tx));
    assert!(node.try_mine());
    let tip = node.tip_height();
    assert_eq!(tip, 5, "five blocks, the grant in the last one");

    let bound = node.start_discovery_endpoint("127.0.0.1:0").expect("bind ephemeral");
    let base_url = format!("http://{bound}");
    let cfg = ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off };

    // The node's real HTTP, with compact responses clipped to two blocks.
    let asked = std::cell::RefCell::new(Vec::new());
    let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
        let bytes = qlab_cbserver::client::http_get(&base_url, path).map_err(|e| e.to_string())?;
        if path.starts_with("/v1/compact") {
            asked.borrow_mut().push(path.to_string());
            let blocks = decode_compact_response(&bytes).expect("the node serves the wire");
            let page: Vec<_> = blocks.into_iter().take(2).collect();
            return Ok(encode_compact_response(&page));
        }
        Ok(bytes)
    };
    let mut wrng = StdRng::seed_from_u64(0x309);
    let out = light_client_scan_with(&mut fetch, &recipient.dk, 0, tip, cfg, &mut wrng)
        .expect("the compact half resolves");

    // The client walked the range one page at a time…
    assert_eq!(
        *asked.borrow(),
        vec![
            "/v1/compact?from=0&to=5".to_string(),
            "/v1/compact?from=2&to=5".to_string(),
            "/v1/compact?from=4&to=5".to_string(),
        ],
        "pages resume from the last served height + 1"
    );
    // …and the grant on the last page is real, spendable money.
    assert_eq!(out.stats.detected_outputs, 1, "the grant is detected");
    assert_eq!(out.completeness(), Completeness::Complete);
    assert_eq!(out.notes.len(), 1);
    assert_eq!(out.notes[0].height, 5, "at its real chain coordinate");
    assert_eq!(out.notes[0].detected.note, granted[0], "opened to the note that was paid");
    assert_eq!(
        out.spendable_value(),
        u128::from(granted[0].value),
        "🔴 spendable equals the grant value — the live acceptance sentence"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// 🔴 **The negative that keeps the positive honest: a payload that does not
/// authenticate is `detected 1, opened 0` with the reason — never a silent
/// zero, and never a partial total.**
///
/// Consensus deliberately does not judge payload validity
/// (`discovery-on-the-consensus-wire.md` §4 rule 4 — a node cannot decrypt a
/// ciphertext addressed to someone else), so a sender CAN commit a payload that
/// will not open: the region still re-encodes to itself and still binds the
/// declared commitments. That makes this a reachable chain state rather than a
/// hypothetical, and the recipient is the only party who can see it.
#[test]
fn a_tampered_committed_payload_is_reported_not_silently_dropped() {
    let mut rng = StdRng::seed_from_u64(0x188_5);
    let recipient: Keypair = generate_keypair(&mut rng);

    let (config, genesis, base) = rig("tampered-payload");
    let mut node = RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier)
        .expect("the node starts on its own genesis");
    node.set_mine_interval(Duration::ZERO);
    node.try_checkpoint();
    let anchor = node.state().commitment_root();

    // A real payment whose committed payload section has one byte flipped. The
    // tag and `cm` are untouched, so detection still succeeds — which is the
    // whole point: the chain says this output is yours and it will not open.
    let (mut tx, _notes) = payment_to(&recipient.ek, 1, 1, anchor, &mut rng);
    let last = tx.discovery.len() - 1;
    tx.discovery[last] ^= 0xff;
    assert!(
        node.submit_local_tx(tx),
        "consensus checks shape and binding, never payload validity (§4 rule 4) — so this is a \
         chain state a sender can really produce"
    );
    assert!(node.try_mine());
    let height = node.tip_height();

    let bound = node.start_discovery_endpoint("127.0.0.1:0").expect("bind ephemeral");
    let cfg = ScanConfig { mode: qlab_note::scan::ScanMode::FullFo, decoy: DecoyPolicy::Off };
    let mut wrng = StdRng::seed_from_u64(5);
    let out = light_client_scan(&format!("http://{bound}"), &recipient.dk, 0, height, cfg, &mut wrng)
        .expect("the compact half resolves");

    assert_eq!(out.stats.detected_outputs, 1, "the committed tag still matches");
    assert!(out.notes.is_empty(), "and nothing opened");
    assert_eq!(
        out.completeness(),
        Completeness::Incomplete { detected: 1, opened: 0 },
        "detected N, opened M<N — the honesty vocabulary, unchanged"
    );
    assert_eq!(out.unopened.len(), 1);
    assert_eq!(
        out.unopened[0].why,
        Unopened::PayloadRejected,
        "🔴 and the reason is AEAD rejection, NOT `PayloadUnavailable`: the node served the \
         bytes, they are the bytes the block commits, and they do not authenticate"
    );
    assert_eq!(out.spendable_value(), 0, "no value is credited under an incomplete verdict");

    let _ = std::fs::remove_dir_all(&base);
}
