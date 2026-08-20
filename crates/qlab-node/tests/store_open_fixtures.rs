//! Lab #521 / PR #524 — the T2 store-open panic, decided against REAL
//! production datadirs (`tests/fixtures/README.md` carries their provenance).
//!
//! `t2-faucet-panic-0932Z` is svc1's faucet datadir, captured after the node —
//! healthy and serving 26 seconds earlier — panicked eleven times in a row at
//! `store.rs:446` `UnknownParent` on an ordinary recreate. It is a PANIC-class
//! artifact: its snapshot prefix carries live same-height rewinds, so
//! `MemChainStore::rewind_to`'s rebuild runs on open, and before PR #524 that
//! rebuild was keyed to hard-coded v4 identities on this v5 chain. Every test
//! of the fix before these fixtures existed used cbnode's REFUSAL-class
//! artifact, which dies in `rewind_path` and never reaches the fixed line.
//!
//! On unfixed code the two open tests below panic at `store.rs:446` — the
//! reproduction IS the test run. Because a green suite cannot show that side,
//! `the_pre_fix_rebuild_refuses_the_panic_fixtures_first_reinsert` pins the
//! mechanism itself: the exact pre-fix rebuild expression, fed the fixture's
//! real genesis and its real height-1 block, refuses with `UnknownParent` —
//! proving these fixtures actually exercise the defect and are not stores
//! that never failed.
//!
//! # How the launch genesis is reconstructed (no genesis.qmb in the repo)
//!
//! The genesis BLOCK is fully determined by (form, difficulty, timestamp):
//! committee keys live in the genesis FILE, not the block
//! (`qumbra_node::genesis::t2_from_committee_keys` builds the block via
//! `qlab_node::genesis_block_for(V5, difficulty, 0)` regardless of keys). The
//! launch difficulty is recovered from the fixtures' own bytes: the v5 genesis
//! header preimage at difficulty 256 (the `T0_GENESIS_DIFFICULTY` placeholder —
//! the ceremony did not override it) hashes to `13338962…dba939`, which is the
//! `prev` of every height-1 record in both logs and both snapshots'
//! `genesis_block_hash`. `the_recovered_launch_genesis_matches_both_fixtures`
//! locks that derivation; if it fails, every other failure here is noise.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use qlab_devnet::chain::InsertError;
use qlab_devnet::forms::GenesisForm;
use qlab_node::{
    genesis_block_for, read_records, ChainStore as _, LogRecord, MemChainStore, MemNode,
    StoredBlock,
};

/// The T2 launch genesis PoW difficulty, recovered from the fixture bytes
/// (module doc). The ceremony kept the `T0_GENESIS_DIFFICULTY` placeholder.
const LAUNCH_GENESIS_DIFFICULTY: u64 = 256;

/// The v5 genesis block-header hash both fixtures were written against — the
/// value inside `snapshot.bin`'s `genesis_block_hash` and the `prev` of every
/// height-1 record. NOT the operational genesis hash (`d1dad4ea…`): that one
/// covers the whole genesis FILE, committee keys included (issue #206).
const LAUNCH_GENESIS_BLOCK_HASH: &str =
    "1333896227a3ff1ce065e6261cad9d6adb809d31ace195a72e47dfe018dba939";

/// Production facts from the incident (lab #521, fixtures README): svc1's
/// faucet was at tip 248 / finalized 240 when it stopped reopening; svc0's
/// healthy cbnode snapshot is at 232 with two applied blocks past it (tip 234,
/// finalized 224).
const PANIC_FIXTURE_TIP: u64 = 248;
const PANIC_FIXTURE_FINALIZED: u64 = 240;
const HEALTHY_FIXTURE_SNAPSHOT: u64 = 232;
const HEALTHY_FIXTURE_TIP: u64 = 234;
const HEALTHY_FIXTURE_FINALIZED: u64 = 224;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!("qlab-node-fixture-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

/// A disposable copy of a committed fixture. The fixtures are production
/// evidence: nothing may open them in place, because an opened node holds the
/// datadir path and any later persistence would rewrite the evidence.
fn copy_of(name: &str) -> PathBuf {
    let src = fixture_dir(name);
    let dst = temp_dir(name);
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
    dst
}

/// The T2 launch genesis block, reconstructed (module doc).
fn launch_genesis() -> StoredBlock {
    genesis_block_for(GenesisForm::V5, LAUNCH_GENESIS_DIFFICULTY, 0)
}

fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixture's block record at `height`, asserted unique at that height.
fn unique_block_at(records: &[LogRecord], height: u64) -> StoredBlock {
    let mut found: Vec<StoredBlock> = records
        .iter()
        .filter_map(|r| match r {
            LogRecord::Block(b) if b.header.height == height => Some(b.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(found.len(), 1, "expected exactly one record at height {height}");
    found.pop().unwrap()
}

/// The derivation everything else stands on: the reconstructed launch genesis
/// is the block both production datadirs were written against.
#[test]
fn the_recovered_launch_genesis_matches_both_fixtures() {
    let genesis_hash = launch_genesis().header().header_hash_for(GenesisForm::V5);
    assert_eq!(
        hex32(&genesis_hash),
        LAUNCH_GENESIS_BLOCK_HASH,
        "genesis_block_for(V5, {LAUNCH_GENESIS_DIFFICULTY}, 0) no longer hashes to the \
         launch genesis — if this moved, the v5 header rule or the empty-body commitment \
         moved, which is a network-identity change (stop-point territory)"
    );
    for fixture in ["t2-faucet-panic-0932Z", "t2-cbnode-healthy-0919Z"] {
        let records = read_records(&fixture_dir(fixture)).unwrap();
        let h1 = unique_block_at(&records, 1);
        assert_eq!(
            h1.header.prev, genesis_hash,
            "{fixture}: the height-1 record's prev is not the reconstructed launch genesis"
        );
    }
}

/// The defect's mechanism, pinned with production bytes. Before PR #524,
/// `MemChainStore::rewind_to` rebuilt with `Self::new(kept[0])` — hard-coded
/// v4 identities — and the rebuild's first re-insert is exactly `kept[1]`, the
/// height-1 block, whose `prev` is the v5 genesis hash. That re-insert is the
/// `.expect` at store.rs:446. Here it is as a refusal instead of a panic: the
/// pre-fix expression refuses the fixture's real height-1 block by name, and
/// the form-keyed rebuild links it. If identity keying ever collapses the two
/// forms (or someone re-hardcodes a form on the rebuild path), this fails.
#[test]
fn the_pre_fix_rebuild_refuses_the_panic_fixtures_first_reinsert() {
    let records = read_records(&fixture_dir("t2-faucet-panic-0932Z")).unwrap();
    let h1 = unique_block_at(&records, 1);

    // The pre-fix rebuild, verbatim: a v4-keyed store seeded with the v5
    // genesis. store.rs:446's expect fired on exactly this Err.
    let mut v4_keyed = MemChainStore::new(launch_genesis());
    assert_eq!(
        v4_keyed.put_block(h1.clone()),
        Err(InsertError::UnknownParent),
        "a v4-keyed rebuild accepted a v5 chain's height-1 block — the two forms' \
         genesis identities have collapsed, and the panic fixture no longer exercises \
         the lab #521 defect"
    );

    // PR #524's rebuild: keyed to the store's own form, the same block links.
    let mut form_keyed = MemChainStore::new_for(GenesisForm::V5, launch_genesis());
    assert!(
        form_keyed.put_block(h1).is_ok(),
        "the form-keyed rebuild must re-link the retained path's first block"
    );
}

/// THE DECIDING TEST (lab #521 item 2): the datadir production could not
/// reopen, opened through the same path a starting node uses. Its snapshot
/// prefix carries 32 live rewinds (first at height 37), so `rewind_to`'s
/// rebuild — the fixed line — runs 32 times before this returns. On unfixed
/// code this test panics at store.rs:446, exactly as svc1 did eleven times.
#[test]
fn the_production_panic_datadir_reopens_through_the_snapshot_resume_path() {
    let dir = copy_of("t2-faucet-panic-0932Z");
    let node = MemNode::open_for(GenesisForm::V5, &dir, launch_genesis())
        .expect("the production panic datadir must reopen with the form-keyed rebuild");

    // The snapshot was honoured — not rejected into a fall-through replay. The
    // whole log is at or below the snapshot height, so a resume that honours
    // it replays zero tail blocks; a full replay wearing a green result would
    // show snapshot_rejected: Some(..) here and be caught.
    let report = node.recovery_report();
    assert_eq!(report.snapshot_rejected, None, "snapshot must be honoured: {report}");
    assert_eq!(report.snapshot_height, Some(PANIC_FIXTURE_TIP));

    // The state svc1 was serving 26 seconds before the incident.
    assert_eq!(node.chain().tip_height(), PANIC_FIXTURE_TIP);
    assert_eq!(node.chain().finalized_height(), Some(PANIC_FIXTURE_FINALIZED));
    let records = read_records(&dir).unwrap();
    let tip = unique_block_at(&records, PANIC_FIXTURE_TIP);
    assert_eq!(
        node.chain().tip_hash(),
        tip.header().header_hash_for(GenesisForm::V5),
        "the resumed tip is not the block svc1 was serving at capture"
    );
}

/// The control (lab #521 item 3): the healthy cbnode store opens clean and
/// proves the harness — genesis reconstruction, fixture copying, the open
/// path — against a store that never failed in production. One honest caveat,
/// found by reading the fixture's own bytes: both nodes followed the same
/// chain, so this log carries the SAME 32 pre-snapshot rewinds — pre-fix code
/// panics on this datadir too (svc0's earlier 14:31 panic was this store's
/// own container). It controls for the harness, not for the defect; unlike
/// the faucet fixture it also applies two blocks PAST its snapshot, so the
/// node-layer tail-replay path is exercised here and only here.
#[test]
fn the_healthy_control_datadir_reopens_clean() {
    let dir = copy_of("t2-cbnode-healthy-0919Z");
    let node = MemNode::open_for(GenesisForm::V5, &dir, launch_genesis())
        .expect("the healthy control datadir must open clean");

    let report = node.recovery_report();
    assert_eq!(report.snapshot_rejected, None, "snapshot must be honoured: {report}");
    assert_eq!(report.snapshot_height, Some(HEALTHY_FIXTURE_SNAPSHOT));
    assert_eq!(node.chain().tip_height(), HEALTHY_FIXTURE_TIP);
    assert_eq!(node.chain().finalized_height(), Some(HEALTHY_FIXTURE_FINALIZED));
}

/// The operator recovery lab #521 documented — the block log is the source of
/// truth and a from-genesis replay (what deleting `snapshot.bin` costs)
/// reaches the state the snapshot resume reaches, on the very datadir that
/// panicked. This is the persistence suite's standing open==replay invariant,
/// asserted for the first time on a real production log with live rewinds in
/// it; it also exercises the node-layer rewind (`Node::rewind_to`), the OTHER
/// rewind implementation, 32 times against the same records.
#[test]
fn full_replay_of_the_panic_log_reaches_the_resumed_state() {
    let dir = copy_of("t2-faucet-panic-0932Z");
    let opened = MemNode::open_for(GenesisForm::V5, &dir, launch_genesis())
        .expect("snapshot resume (proven above)");
    let replayed = MemNode::replay_for(GenesisForm::V5, &dir, launch_genesis())
        .expect("the log must replay from genesis without the snapshot");

    assert_eq!(replayed.chain().tip_hash(), opened.chain().tip_hash());
    assert_eq!(replayed.chain().tip_height(), opened.chain().tip_height());
    assert_eq!(replayed.chain().finalized_height(), opened.chain().finalized_height());
    assert_eq!(
        replayed.commitments_ordered(),
        opened.commitments_ordered(),
        "snapshot-restored derived state must equal the from-genesis fold"
    );
}
