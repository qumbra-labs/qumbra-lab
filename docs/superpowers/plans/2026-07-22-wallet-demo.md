# qlab-demo — End-to-End Wallet Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scripted end-to-end payment loop (Alice → Bob note, two real M3 proofs, real compact-block scan, placeholder-consensus block validation, double-spend rejection, finality, supply invariant) wired as both integration tests and a `qlab-demo` bin printing a human transcript.

**Architecture:** New additive workspace crate `crates/qlab-demo` composes `qlab-wallet` + `qlab-note` + `qlab-air` + `qlab-devnet` + `qlab-cbserver`. Two additive `pub` helpers are added to `qlab-cbserver` (an ingest constructor + a socket-free scan) so the real serving/scan path runs in-process on a real Alice→Bob tx. The Plonky3 consensus prover config (trapped `pub(crate)` in the `qlab-bench` binary) is reconstructed in `qlab-demo/src/prover.rs`, value-locked to the documented decision.

**Tech Stack:** Rust 2021, Plonky3 `=0.6.1` (`p3-uni-stark` `prove`/`verify`, KoalaBear + Keccak-Merkle FRI), ML-KEM-768 / ChaCha20-Poly1305 (via qlab-note), Keccak-f narrow AIR (qlab-air).

## Global Constraints

- **Acceptance bar:** the full **unfiltered** workspace suite `cargo test --release` must be green at tip (baseline 227). Never a mode-scoped filter.
- **`cargo check` green on every commit**; staged commits.
- Composed crates (wallet/note/air/devnet/cbserver) change **only by additive helpers** — no edits to existing behavior, signatures, or golden-bytes locks. `qlab-bench` is **not** touched this session.
- **No real networking** (no socket): the scan runs fully in-process. **No design-repo writes.** Consensus stays placeholder.
- Consensus config is **value-locked**: `FriCfg { log_blowup: 4, num_queries: 20, grind_bits: 22, log_final_poly_len: 4, max_log_arity: 4 }` (`b16/q20/g22/fp16/a16`), `LOG_HEIGHT = 18`. Plonky3 pinned `=0.6.1`.
- Verify cwd is the `qumbra-lab-walletdemo` worktree (branch `claude/wallet-demo`) before **every** edit batch (repeat-gotcha: two prior main-worktree incidents). Never enter other worktrees.
- Balanced bucket ledger everywhere: `Σinputs == Σoutputs + fee` (in-circuit constraint).

---

### Task 1: Scaffold `qlab-demo` crate + workspace wiring

**Files:**
- Modify: `Cargo.toml` (root, `members` list)
- Create: `crates/qlab-demo/Cargo.toml`
- Create: `crates/qlab-demo/src/lib.rs`

**Interfaces:**
- Produces: an empty compiling library crate `qlab_demo`.

- [ ] **Step 1: Add the crate to the workspace members.** Edit root `Cargo.toml`, append `"crates/qlab-demo"` to the `members` array (keep formatting identical to neighbors).

- [ ] **Step 2: Write `crates/qlab-demo/Cargo.toml`.**

```toml
[package]
name = "qlab-demo"
version = "0.0.0"
edition.workspace = true
publish.workspace = true

[[bin]]
name = "qlab-demo"
path = "src/bin/qlab-demo.rs"

[dependencies]
qlab-air = { path = "../qlab-air" }
qlab-note = { path = "../qlab-note" }
qlab-wallet = { path = "../qlab-wallet" }
qlab-devnet = { path = "../qlab-devnet" }
qlab-cbserver = { path = "../qlab-cbserver" }

# Plonky3 pinned exactly at 0.6.1 (matches qlab-bench / Cargo.lock). The prover
# config is reconstructed here because it is pub(crate) in the qlab-bench binary
# (see docs friction F1). parallel feature turns on multithreaded prove.
p3-air = "=0.6.1"
p3-challenger = "=0.6.1"
p3-commit = "=0.6.1"
p3-dft = "=0.6.1"
p3-field = "=0.6.1"
p3-fri = "=0.6.1"
p3-keccak = "=0.6.1"
p3-koala-bear = "=0.6.1"
p3-matrix = "=0.6.1"
p3-maybe-rayon = { version = "=0.6.1", features = ["parallel"] }
p3-merkle-tree = "=0.6.1"
p3-symmetric = "=0.6.1"
p3-uni-stark = "=0.6.1"

rand = "0.10"
bincode = "1"
```

- [ ] **Step 3: Write `crates/qlab-demo/src/lib.rs`.**

```rust
//! qlab-demo: the first end-to-end compose of the Qumbra prototype stack —
//! wallet keys/addresses + note encryption + a REAL M3 tx proof + placeholder-
//! consensus devnet block validation + compact-block scan, driven as a scripted
//! payment loop (Alice pays Bob, Bob detects and spends).
//!
//! Two crates are composed with additive helpers only; the prover config is
//! reconstructed in `prover` (see docs/demo-run.md friction F1).

// The narrow-Keccak AIR builds a large symbolic constraint tree; its
// monomorphization pushes rustc's default recursion limit (matches qlab-bench).
#![recursion_limit = "512"]

pub mod prover;
pub mod ledger;
pub mod scenario;
```

- [ ] **Step 4: Verify it compiles.**

Run: `cd ~/develop/qumbra/qumbra-lab-walletdemo && cargo check -p qlab-demo 2>&1 | tail -20`
Expected: fails — `prover`/`ledger`/`scenario` modules don't exist yet. That's the next tasks; create empty stubs to get a clean check:

- [ ] **Step 5: Add empty module stubs** so the scaffold compiles standalone.
  Create `crates/qlab-demo/src/prover.rs` with `//! (filled in Task 2)`.
  Create `crates/qlab-demo/src/ledger.rs` with `//! (filled in Task 5)`.
  Create `crates/qlab-demo/src/scenario.rs` with `//! (filled in Task 6)`.
  Create `crates/qlab-demo/src/bin/qlab-demo.rs` with `fn main() {}`.

Run: `cargo check -p qlab-demo 2>&1 | tail -5`
Expected: clean (warnings about empty modules OK).

- [ ] **Step 6: Commit.**

```bash
git add Cargo.toml crates/qlab-demo
git commit -m "qlab-demo: scaffold crate + workspace wiring"
```

---

### Task 2: `prover.rs` — reconstruct the value-locked consensus config (F1)

**Files:**
- Modify: `crates/qlab-demo/src/prover.rs`

**Interfaces:**
- Produces:
  - `pub type Val = KoalaBear;`
  - `pub type Config = StarkConfig<Pcs, Challenge, Challenger>;` (opaque to consumers)
  - `pub struct FriCfg { pub log_blowup, num_queries, grind_bits, log_final_poly_len, max_log_arity: usize }`
  - `pub const CONSENSUS_CFG: FriCfg` and `pub const LOG_HEIGHT: usize = 18;`
  - `pub fn make_config() -> Config`
  - `pub fn prove_bucket(inst: &BucketInstance) -> (Vec<Val>, Proof<Config>)` — generate trace + prove at CONSENSUS_CFG
  - `pub fn verify_proof(inst: &BucketInstance, pvs: &[Val], proof: &Proof<Config>) -> bool`

- [ ] **Step 1: Write the failing test first** (append to `prover.rs`). This is the F1 value-lock + real prove→verify roundtrip.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::{build_bucket, TxInput, TxOutput};

    #[test]
    fn consensus_cfg_is_value_locked() {
        // Locked to the documented decision (issue #22 B′): b16/q20/g22/fp16/a16.
        assert_eq!(CONSENSUS_CFG.log_blowup, 4);
        assert_eq!(CONSENSUS_CFG.num_queries, 20);
        assert_eq!(CONSENSUS_CFG.grind_bits, 22);
        assert_eq!(CONSENSUS_CFG.log_final_poly_len, 4);
        assert_eq!(CONSENSUS_CFG.max_log_arity, 4);
        assert_eq!(LOG_HEIGHT, 18);
    }

    #[test]
    fn real_m3_proof_roundtrips() {
        // A balanced 2-in/2-out bucket (50k+30k = 60k+19k+1k fee).
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: 50_000, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12], d: [0, 0] },
            TxInput { sk: [13, 14, 15, 16], value: 30_000, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24], d: [0, 0] },
        ];
        let outputs = [
            TxOutput { value: 60_000, rkm: [1; 4], rho: [2; 4], rseed: [3; 4] },
            TxOutput { value: 19_000, rkm: [4; 4], rho: [5; 4], rseed: [6; 4] },
        ];
        let inst = build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000);
        let (pvs, proof) = prove_bucket(&inst);
        assert!(verify_proof(&inst, &pvs, &proof), "real M3 proof must verify");
    }
}
```

- [ ] **Step 2: Run it, expect a compile failure** (`prove_bucket` etc. undefined).

Run: `cargo test --release -p qlab-demo prover:: 2>&1 | tail -20`
Expected: FAIL — unresolved names.

- [ ] **Step 3: Implement `prover.rs`.** Reconstruct the config verbatim from `crates/qlab-bench/src/main.rs:60-247` and `m4gaterec.rs:53-61`, made `pub`. Full module:

```rust
//! F1: the Plonky3 consensus prover configuration, reconstructed as library API.
//!
//! The identical plumbing lives `pub(crate)` inside the `qlab-bench` *binary*
//! (main.rs type aliases + `make_config_with`; m4gaterec.rs `CONSENSUS_CFG`),
//! so it cannot be imported. This is the standard StarkConfig any integrator
//! constructs; it is NOT a fork of crate logic. Value-locked to the documented
//! decision (issue #22 B′) and guarded by `real_m3_proof_roundtrips`.
//! Follow-up: extract a shared `qlab-consensus` crate so bench + demo agree.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};

use qlab_air::narrow::BucketInstance;

pub type Val = KoalaBear;
type Challenge = BinomialExtensionField<Val, 4>;

type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type ValMmcs = MerkleTreeMmcs<[Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN], FieldHash, MyCompress, 2, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
type Dft = p3_dft::Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// One FRI parameter point (only FRI params vary; field/hash held fixed).
#[derive(Clone, Copy)]
pub struct FriCfg {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub grind_bits: usize,
    pub log_final_poly_len: usize,
    pub max_log_arity: usize,
}

/// The decided consensus config (issue #22 B′): b16/q20/g22/fp16/a16.
pub const CONSENSUS_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 20,
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};
pub const LOG_HEIGHT: usize = 18;

pub fn make_config() -> Config {
    let byte_hash = ByteHash {};
    let u64_hash = U64Hash::new(KeccakF {});
    let field_hash = FieldHash::new(u64_hash);
    let compress = MyCompress::new(u64_hash);
    let val_mmcs = ValMmcs::new(field_hash, compress, 3);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let challenger = Challenger::from_hasher(vec![], byte_hash);
    let fri_params = FriParameters {
        log_blowup: CONSENSUS_CFG.log_blowup,
        log_final_poly_len: CONSENSUS_CFG.log_final_poly_len,
        max_log_arity: CONSENSUS_CFG.max_log_arity,
        num_queries: CONSENSUS_CFG.num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: CONSENSUS_CFG.grind_bits,
        mmcs: challenge_mmcs,
    };
    assert!(
        fri_params.conjectured_soundness_bits() >= 100,
        "consensus config must clear the ~100-bit capacity bar"
    );
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    Config::new(pcs, challenger)
}

/// Public values as field elements, from a bucket instance.
pub fn public_values(inst: &BucketInstance) -> Vec<Val> {
    inst.pvs.iter().map(|v| Val::from_u32(*v)).collect()
}

/// Generate the trace and prove the bucket at the consensus config (~1.6 s).
pub fn prove_bucket(inst: &BucketInstance) -> (Vec<Val>, Proof<Config>) {
    let config = make_config();
    let pvs = public_values(inst);
    let trace = inst.air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
    let proof = prove(&config, &inst.air, trace, &pvs);
    (pvs, proof)
}

/// Node-side verification of a proof against its instance + public values.
pub fn verify_proof(inst: &BucketInstance, pvs: &[Val], proof: &Proof<Config>) -> bool {
    let config = make_config();
    verify(&config, &inst.air, proof, pvs).is_ok()
}
```

Then append the `#[cfg(test)] mod tests` block from Step 1.

- [ ] **Step 4: Run the tests, expect PASS** (the roundtrip proves + verifies a real proof, ~1.6 s).

Run: `cargo test --release -p qlab-demo prover:: 2>&1 | tail -20`
Expected: 2 passed. (If `generate_trace` type inference complains, the `PrimeCharacteristicRing` import covers `from_u32`.)

- [ ] **Step 5: Commit.**

```bash
git add crates/qlab-demo/src/prover.rs
git commit -m "qlab-demo: F1 value-locked consensus prover config + real proof roundtrip"
```

---

### Task 3: cbserver additive helper — `Devnet::from_parts` (F3, ingest)

**Files:**
- Modify: `crates/qlab-cbserver/src/data.rs`

**Interfaces:**
- Produces: `pub fn Devnet::from_parts(blocks: Vec<StoredBlock>, tree: CommitmentTree, chain: ChainState, our: Keypair, expected_matches: usize, leaves_at_end_of_height: Vec<(u64, u64)>) -> Devnet`
- Consumes (by qlab-demo later): the existing `StoredBlock`/`StoredTx`/`StoredRecipient` pub structs, `compact_range`, `full_payloads`, `leaves_at`.

- [ ] **Step 1: Write the failing test** (append to `data.rs` `#[cfg(test)] mod tests`). It rebuilds a `Devnet` from a `generate`d one's parts and asserts identical serving behavior.

```rust
#[test]
fn from_parts_reconstructs_equivalent_devnet() {
    let g = Devnet::generate(GenParams::default());
    // Re-derive leaves_at_end_of_height via the public leaves_at() over heights.
    let leaves: Vec<(u64, u64)> = (1..=g.tip_height()).map(|h| (h, g.leaves_at(h))).collect();
    let root = g.tree.root();
    let tip = g.tip_height();
    let expected = g.expected_matches;
    // Move g's parts into a fresh Devnet.
    let d = Devnet::from_parts(g.blocks, g.tree, g.chain, g.our, expected, leaves);
    assert_eq!(d.tip_height(), tip);
    assert_eq!(d.tree.root(), root);
    assert_eq!(d.leaves_at(tip), d.tree.len());
    assert_eq!(d.expected_matches, expected);
    // Serving still works.
    assert!(!d.compact_range(1, tip).is_empty());
}
```

- [ ] **Step 2: Run it, expect compile failure** (`from_parts` undefined).

Run: `cargo test --release -p qlab-cbserver data::tests::from_parts 2>&1 | tail -15`
Expected: FAIL — no method `from_parts`.

- [ ] **Step 3: Implement `from_parts`** as an additive method in `impl Devnet` (place right after `generate`), documented as the composition entry point.

```rust
/// Assemble a `Devnet` from externally-built REAL blocks/notes — the
/// composition entry point for a driver (e.g. qlab-demo) that produces its
/// own Alice→Bob transaction rather than the self-generated `generate` mix.
/// `leaves_at_end_of_height` is `(height, cumulative_tree_len)` per block in
/// ascending height (the same invariant `generate` maintains internally).
/// Additive: existing `generate`/serving behavior is unchanged.
pub fn from_parts(
    blocks: Vec<StoredBlock>,
    tree: CommitmentTree,
    chain: ChainState,
    our: Keypair,
    expected_matches: usize,
    leaves_at_end_of_height: Vec<(u64, u64)>,
) -> Self {
    Devnet { blocks, tree, chain, our, leaves_at_end_of_height, expected_matches }
}
```

- [ ] **Step 4: Run the test, expect PASS.**

Run: `cargo test --release -p qlab-cbserver data::tests::from_parts 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add crates/qlab-cbserver/src/data.rs
git commit -m "qlab-cbserver: additive Devnet::from_parts ingest constructor (composition entry)"
```

---

### Task 4: cbserver additive helper — `client::scan_local` (F3, socket-free scan)

**Files:**
- Modify: `crates/qlab-cbserver/src/client.rs`

**Interfaces:**
- Produces: `pub fn scan_local(devnet: &crate::data::Devnet, dk: &Dk, from: u64, to: u64, config: ScanConfig, rng: &mut StdRng) -> ScanOutcome`
- Consumes: `crate::server::route` (pub), `decode_compact_response`, `decode_full_response`, the private `bundle_has_tag_match` (same module), `qlab_note::scan::scan`.

Rationale: this is the **exact** `light_client_scan` loop with `crate::server::route(devnet, url)` substituted for `http_get(base_url, path)` — so it still exercises real server routing + real codec + real scan + decoy over-fetch, with **no socket**.

- [ ] **Step 1: Write the failing test** (append to `client.rs` `#[cfg(test)] mod tests`). It asserts `scan_local` finds exactly the planted notes and matches `light_client_scan` note-count, over a `generate`d Devnet — no server handle.

```rust
#[test]
fn scan_local_matches_socket_scan_and_finds_planted_notes() {
    let d = Devnet::generate(GenParams::default());
    let mut rng = StdRng::seed_from_u64(1);
    let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
    let out = scan_local(&d, &d.our.dk, 1, d.tip_height(), cfg, &mut rng);
    assert_eq!(out.notes.len(), d.expected_matches, "socket-free scan finds all planted notes");
    assert_eq!(out.stats.notes_found, d.expected_matches);
    assert!(out.stats.matched_fetches > 0);
}

#[test]
fn scan_local_wrong_key_finds_nothing() {
    let d = Devnet::generate(GenParams::default());
    let mut rng = StdRng::seed_from_u64(3);
    let stranger = qlab_note::kem::generate_keypair(&mut StdRng::seed_from_u64(999));
    let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
    let out = scan_local(&d, &stranger.dk, 1, d.tip_height(), cfg, &mut rng);
    assert_eq!(out.notes.len(), 0);
    assert_eq!(out.stats.matched_fetches, 0);
}
```

- [ ] **Step 2: Run, expect compile failure** (`scan_local` undefined).

Run: `cargo test --release -p qlab-cbserver client::tests::scan_local 2>&1 | tail -15`
Expected: FAIL.

- [ ] **Step 3: Implement `scan_local`** (place right after `light_client_scan`). It mirrors the loop; a tiny local `route_get` helper maps `RouteResult` to bytes.

```rust
/// The light-client scan flow, run **fully in-process** against a `&Devnet`
/// via `crate::server::route` — no socket, no `TcpStream`. Behaviourally
/// identical to [`light_client_scan`] (same codec, same tag pre-filter, same
/// `qlab_note::scan::scan`, same decoy over-fetch); this is the composition
/// path for an in-process driver (qlab-demo) under a no-networking constraint.
pub fn scan_local(
    devnet: &crate::data::Devnet,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> ScanOutcome {
    // `route` never errors for well-formed internal URLs; unwrap the bytes.
    let route_get = |url: &str| -> Vec<u8> {
        crate::server::route(devnet, url).expect("in-process route must succeed")
    };

    let compact = route_get(&format!("/v1/compact?from={from}&to={to}"));
    let mut stats = ScanStats { compact_bytes: compact.len(), ..Default::default() };
    let blocks = decode_compact_response(&compact).expect("internal compact response decodes");

    let tx_space: Vec<(u64, u64)> = blocks
        .iter()
        .map(|b| (b.height, b.groups.len() as u64))
        .filter(|(_, n)| *n > 0)
        .collect();

    let mut notes = Vec::new();
    for block in &blocks {
        for group in &block.groups {
            let matched = group
                .recipients
                .iter()
                .any(|bundle| bundle_has_tag_match(dk, bundle));
            if !matched {
                continue;
            }
            let full = route_get(&format!("/v1/block/{}/tx/{}/full", block.height, group.tx_index));
            stats.matched_fetches += 1;
            let payloads_per_recipient =
                decode_full_response(&full).expect("internal full response decodes");
            for (ri, bundle) in group.recipients.iter().enumerate() {
                let Some(payloads) = payloads_per_recipient.get(ri) else { continue };
                let enc = EncryptedOutputs { bundle: bundle.clone(), payloads: payloads.clone() };
                for detected in scan(dk, &enc, config.mode) {
                    notes.push(LocatedNote {
                        height: block.height,
                        tx_index: group.tx_index,
                        recipient_index: ri,
                        detected,
                    });
                }
            }
            if let DecoyPolicy::PerMatch { max } = config.decoy {
                let max = max.max(1);
                let n_decoys = 1 + (rng.next_u64() as usize % max);
                for _ in 0..n_decoys {
                    if tx_space.is_empty() {
                        break;
                    }
                    let (h, n_tx) = tx_space[rng.next_u64() as usize % tx_space.len()];
                    let ti = rng.next_u64() % n_tx;
                    let _ = route_get(&format!("/v1/block/{h}/tx/{ti}/full"));
                    stats.decoy_fetches += 1;
                }
            }
        }
    }
    stats.notes_found = notes.len();
    ScanOutcome { notes, stats }
}
```

Note: the `#[cfg(test)] use crate::data::{Devnet, GenParams};` import may need adding to the test mod (the existing tests import them inside `fresh()`); add `use crate::data::{Devnet, GenParams};` at the top of the test mod if not present.

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test --release -p qlab-cbserver client::tests::scan_local 2>&1 | tail -15`
Expected: 2 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/qlab-cbserver/src/client.rs
git commit -m "qlab-cbserver: additive client::scan_local (socket-free real scan path)"
```

---

### Task 5: `ledger.rs` — supply tracker + persistent nullifier set (F4)

**Files:**
- Modify: `crates/qlab-demo/src/ledger.rs`

**Interfaces:**
- Produces:
  - `pub struct SupplyTracker { minted: u64, fees_burned: u64 }` with `new()`, `mint_coinbase(&mut self, amount: u64)`, `record_fee(&mut self, fee: u64)`, `circulating(&self) -> u64` (= minted − fees_burned), `minted(&self) -> u64`.
  - `pub struct NullifierSet { seen: std::collections::HashSet<[u8; 32]> }` with `new()`, `insert(&mut self, nf: [u8; 32]) -> bool` (false if already present = double-spend), `contains(&self, nf: &[u8; 32]) -> bool`, `len()`.

- [ ] **Step 1: Write the failing tests** (in `ledger.rs`).

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_tracks_coinbase_and_fees() {
        let mut s = SupplyTracker::new();
        s.mint_coinbase(80_000);
        s.mint_coinbase(40_000);
        assert_eq!(s.minted(), 120_000);
        assert_eq!(s.circulating(), 120_000);
        s.record_fee(1_000); // a fee removes value from circulation (placeholder burn)
        assert_eq!(s.circulating(), 119_000);
        assert_eq!(s.minted(), 120_000, "minting supply is unchanged by fees");
    }

    #[test]
    fn nullifier_set_rejects_double_spend() {
        let mut n = NullifierSet::new();
        let nf = [7u8; 32];
        assert!(n.insert(nf), "first spend lands");
        assert!(!n.insert(nf), "second spend of same nullifier rejected");
        assert!(n.contains(&nf));
        assert_eq!(n.len(), 1);
    }
}
```

- [ ] **Step 2: Run, expect compile failure.**

Run: `cargo test --release -p qlab-demo ledger:: 2>&1 | tail -15`
Expected: FAIL.

- [ ] **Step 3: Implement `ledger.rs`.**

```rust
//! F4: the value-conservation glue qlab-devnet does not provide — a placeholder
//! supply/coinbase tracker and a persistent (cross-block) nullifier set. Both
//! are documented devnet *extensions* (qlab-devnet enforces only within-block
//! nullifier uniqueness and carries a bare coinbase counter).

use std::collections::HashSet;

/// Placeholder supply accounting: coinbase mints add to supply; fees are treated
/// as removed from circulation (a burn stand-in). Shielded transfers conserve
/// value in-circuit (build_bucket's balance constraint), so they do not move
/// these counters.
#[derive(Debug, Default, Clone)]
pub struct SupplyTracker {
    minted: u64,
    fees_burned: u64,
}

impl SupplyTracker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn mint_coinbase(&mut self, amount: u64) {
        self.minted += amount;
    }
    pub fn record_fee(&mut self, fee: u64) {
        self.fees_burned += fee;
    }
    pub fn minted(&self) -> u64 {
        self.minted
    }
    pub fn circulating(&self) -> u64 {
        self.minted - self.fees_burned
    }
}

/// Persistent nullifier set: `insert` returns `false` if the nullifier was
/// already spent (the cross-block double-spend rejection qlab-devnet lacks).
#[derive(Debug, Default, Clone)]
pub struct NullifierSet {
    seen: HashSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, nf: [u8; 32]) -> bool {
        self.seen.insert(nf)
    }
    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        self.seen.contains(nf)
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
```

- [ ] **Step 4: Run, expect PASS.**

Run: `cargo test --release -p qlab-demo ledger:: 2>&1 | tail -15`
Expected: 2 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/qlab-demo/src/ledger.rs
git commit -m "qlab-demo: ledger — supply tracker + persistent nullifier set (F4 glue)"
```

---

### Task 6: `scenario.rs` — the payment loop + invariant asserts

**Files:**
- Modify: `crates/qlab-demo/src/scenario.rs`

This is the core. It ties every seam together and returns a structured `LoopReport` the bin and the tests both consume. Split into small steps; the loop is one function `run_loop(seed: u64) -> LoopReport` plus a `Transcript` accumulator of human-readable lines.

**Interfaces:**
- Produces:
  - `pub struct LoopReport { pub sent_value: u64, pub detected_value: u64, pub bob_nullifier: [u8;32], pub double_spend_rejected: bool, pub within_block_double_spend_rejected: bool, pub spend_finalized: bool, pub supply_minted: u64, pub supply_consistent: bool, pub cm_seam_holds: bool, pub proofs_generated: usize, pub prove_secs: Vec<f64>, pub scan_stats: qlab_cbserver::client::ScanStats, pub wall_secs: f64, pub transcript: Vec<String> }`
  - `pub fn run_loop(seed: u64) -> LoopReport`
- Consumes: `crate::prover::{prove_bucket, verify_proof, LOG_HEIGHT}`, `crate::ledger::{SupplyTracker, NullifierSet}`, qlab-wallet, qlab-note, qlab-air, qlab-devnet, qlab-cbserver `from_parts`/`scan_local`.

**Shared helpers to define at top of module** (mirroring `m6devnet.rs`):

```rust
use std::time::Instant;

use qlab_air::narrow::{build_bucket, BucketInstance, TxInput, TxOutput};
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
use qlab_note::hash::digest_bytes;
use qlab_note::note::Note;
use qlab_note::scan::{encrypt_to_recipient, ScanMode};
use qlab_wallet::address::{Address, Diversifier};
use qlab_wallet::Wallet;
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::ledger::{NullifierSet, SupplyTracker};
use crate::prover::{prove_bucket, verify_proof, LOG_HEIGHT};

/// `[u64;4]` qlab-air digest → 32 bytes (lane-major LE) — the m6devnet convention.
fn h32(x: &[u64; 4]) -> Hash32 {
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&x[i].to_le_bytes());
    }
    o
}

/// The real M3 verifier injected into `validate_body`: it holds the proved
/// instances/pvs/proofs and runs `crate::prover::verify_proof`. The TxEntry's
/// proof bytes encode the pool index (little-endian u64), the m6devnet pattern.
struct PoolVerifier {
    pool: Vec<(BucketInstance, Vec<crate::prover::Val>, p3_uni_stark::Proof<crate::prover::Config>)>,
}
impl TxVerifier for PoolVerifier {
    fn verify_tx(&self, entry: &TxEntry) -> bool {
        let idx = usize::from_le_bytes(entry.proof[..8].try_into().expect("8-byte index"));
        let (inst, pvs, proof) = &self.pool[idx];
        verify_proof(inst, pvs, proof)
    }
}

fn tx_entry(idx: usize, inst: &BucketInstance) -> TxEntry {
    TxEntry {
        proof: (idx as u64).to_le_bytes().to_vec(),
        public: TxPublic {
            anchor: h32(&inst.anchor),
            nullifiers: vec![h32(&inst.nf[0]), h32(&inst.nf[1])],
            commitments: vec![h32(&inst.cm_out[0]), h32(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    }
}
```

Note: add `p3-uni-stark` types via `use crate::prover::{Config, Val};` and reference `p3_uni_stark::Proof` (already a dep). Simpler: add `pub use p3_uni_stark::Proof;` re-export in `prover.rs` and use `crate::prover::Proof`.

- [ ] **Step 1: Write the failing integration test** at `crates/qlab-demo/tests/e2e.rs` (the acceptance for this task).

```rust
//! End-to-end invariant assertions for the Qumbra payment loop.
use qlab_demo::scenario::run_loop;

#[test]
fn end_to_end_payment_loop_holds_all_invariants() {
    let r = run_loop(0xA11CE_B0B);

    // (1) Bob detects exactly the value Alice sent.
    assert_eq!(r.detected_value, r.sent_value, "detected == sent");
    assert!(r.sent_value > 0);

    // (6) The cm seam: on-chain commitment == compact-entry cm == Note::commitment().
    assert!(r.cm_seam_holds, "cm byte-identical across proof / wire / note");

    // (2) Two real M3 proofs were generated and verified in-block.
    assert_eq!(r.proofs_generated, 2);
    assert_eq!(r.prove_secs.len(), 2);

    // (3) Double-spend: persistent-set rejection + native within-block rejection.
    assert!(r.double_spend_rejected, "cross-block double-spend rejected");
    assert!(r.within_block_double_spend_rejected, "within-block double-spend rejected");

    // (4) Bob's spend block finalizes under the committee quorum.
    assert!(r.spend_finalized, "spend block finalized");

    // (5) Supply invariant.
    assert!(r.supply_consistent, "supply/coinbase counter consistent across the loop");
}
```

- [ ] **Step 2: Run, expect compile failure** (`run_loop` undefined).

Run: `cargo test --release -p qlab-demo --test e2e 2>&1 | tail -20`
Expected: FAIL.

- [ ] **Step 3: Implement `run_loop`** in `scenario.rs`. Full body (append after the helpers above). Value choreography: Alice coins 50k+30k; pays Bob 60k note + 19k change, fee 1k. Bob's genesis coin 40k; Bob spends [60k note, 40k coin] → 60k to Alice + 39k change, fee 1k. `Diversifier::default()` throughout.

```rust
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
    macro_rules! say { ($($a:tt)*) => { tr.push(format!($($a)*)); } }

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
    let (bob_rho, bob_rseed) = ([0x51; 4], [0x52; 4]);
    let bob_note = Note {
        value: sent_value,
        rkm: bob_addr.rkm_lanes(),
        rho: bob_rho,
        rseed: bob_rseed,
    };
    // Alice's two inputs (her coinbase coins) + outputs [Bob note, Alice change].
    let a_inputs = [
        alice.spend_input(50_000, [0x11; 4], [0x12; 4], d),
        alice.spend_input(30_000, [0x13; 4], [0x14; 4], d),
    ];
    let a_outputs = [
        TxOutput { value: sent_value, rkm: bob_addr.rkm_lanes(), rho: bob_rho, rseed: bob_rseed },
        TxOutput { value: 19_000, rkm: alice.rkm(d), rho: [0x15; 4], rseed: [0x16; 4] },
    ];
    let send_inst = build_bucket(LOG_HEIGHT, &a_inputs, &a_outputs, 1_000);
    // cm seam: proof commitment[0] == the note's own commitment.
    let cm_seam_holds = send_inst.cm_out[0] == bob_note.commitment();
    say!("Alice builds send tx (2-in/2-out); cm seam holds: {cm_seam_holds}");
    let t = Instant::now();
    let (send_pvs, send_proof) = prove_bucket(&send_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #1 (send): {:.2} s", prove_secs[0]);

    // Encrypt the note to Bob (the compact-entry cm == send_inst.cm_out[0]).
    let enc = encrypt_to_recipient(&bob_ek, &[bob_note.clone()], &mut rng);

    // ── 4. Devnet chain + real-proof block validation ───────────────────────
    let mut node = Node::new(KeccakPow, SimConfig::default());
    let pool = vec![(send_inst.clone(), send_pvs, send_proof)];
    let verifier = PoolVerifier { pool };
    let send_entry = tx_entry(0, &send_inst);
    let send_anchor = h32(&send_inst.anchor);
    let send_body = BlockBody { txs: vec![send_entry.clone()], coinbase: 0 };
    // F2: the proof's fabricated anchor is treated as finalized for validation.
    validate_body(&send_body, &verifier, |r: &Hash32| *r == send_anchor)
        .expect("send block validates (real proof verifies)");
    node.mine_next(send_body.commitment()).expect("mine send block");
    say!("Send block mined + validated (REAL proof verified by node) at height {}", node.tip_height());
    supply.record_fee(1_000);

    // ── 5. Build the discovery layer + Bob scans (socket-free real path) ─────
    let mut tree = CommitmentTree::new();
    for e in &enc.bundle.entries {
        tree.append_bytes(&e.cm);
    }
    let stored = StoredBlock {
        height: 1,
        header: send_header_stub(&node, &send_body),
        body: send_body.clone(),
        txs: vec![StoredTx { recipients: vec![StoredRecipient { enc: enc.clone(), ours: true }] }],
    };
    let leaves = vec![(1u64, tree.len())];
    let devnet = Devnet::from_parts(vec![stored], tree, dummy_chain(), bob_kp, 1, leaves);
    let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } };
    let outcome = scan_local(&devnet, &devnet.our.dk, 1, 1, cfg, &mut rng);
    let detected = &outcome.notes[0].detected.note;
    let detected_value = detected.value;
    say!("Bob scans compact stream → detects note value {detected_value} (sent {sent_value})");

    // ── 6. Bob spends the detected note (real proof #2) ──────────────────────
    supply.mint_coinbase(0); // (Bob's 40k coin already minted at genesis)
    let b_inputs = [
        bob.spend_input(detected_value, detected.rho, detected.rseed, d),
        bob.spend_input(40_000, [0x21; 4], [0x22; 4], d),
    ];
    let b_outputs = [
        TxOutput { value: 60_000, rkm: alice.rkm(d), rho: [0x23; 4], rseed: [0x24; 4] },
        TxOutput { value: 39_000, rkm: bob.rkm(d), rho: [0x25; 4], rseed: [0x26; 4] },
    ];
    let spend_inst = build_bucket(LOG_HEIGHT, &b_inputs, &b_outputs, 1_000);
    let bob_nullifier = h32(&spend_inst.nf[0]);
    let t = Instant::now();
    let (spend_pvs, spend_proof) = prove_bucket(&spend_inst);
    prove_secs.push(t.elapsed().as_secs_f64());
    say!("Real M3 proof #2 (spend): {:.2} s", prove_secs[1]);
    let verifier2 = PoolVerifier { pool: vec![(spend_inst.clone(), spend_pvs, spend_proof)] };
    let spend_entry = tx_entry(0, &spend_inst);
    let spend_anchor = h32(&spend_inst.anchor);
    let spend_body = BlockBody { txs: vec![spend_entry.clone()], coinbase: 0 };
    validate_body(&spend_body, &verifier2, |r: &Hash32| *r == spend_anchor)
        .expect("spend block validates");
    node.mine_next(spend_body.commitment()).expect("mine spend block");
    supply.record_fee(1_000);
    // nullifier lands in the persistent set.
    assert!(nullifiers.insert(bob_nullifier), "first spend lands");
    say!("Spend block mined; Bob's nullifier landed at height {}", node.tip_height());

    // Double-spend #1 (cross-block): re-submit the same nullifier → rejected by set.
    let double_spend_rejected = !nullifiers.insert(bob_nullifier);
    // Double-spend #2 (within-block): two entries with the same nullifier.
    let two_same = BlockBody { txs: vec![spend_entry.clone(), spend_entry.clone()], coinbase: 0 };
    let within_block_double_spend_rejected = matches!(
        validate_body(&two_same, &verifier2, |r: &Hash32| *r == spend_anchor),
        Err(BodyError::DoubleSpendInBlock { .. })
    );
    say!("Double-spend rejected — cross-block: {double_spend_rejected}, within-block: {within_block_double_spend_rejected}");

    // ── 7. Finality + supply invariant ──────────────────────────────────────
    let (committee, validators) = devnet_committee(COMMITTEE_SIZE);
    let cstate = CommitteeState::new(committee, BOND_AMOUNT);
    let quorum = cstate.quorum_threshold();
    // Mine to the first checkpoint boundary and finalize.
    while node.tip_height() % CHECKPOINT_CADENCE_BLOCKS != 0 {
        node.mine_next(spend_body.commitment()).expect("mine to cadence");
    }
    let h = node.tip_height();
    let cp = node.checkpoint_at(h).expect("checkpoint");
    let votes: Vec<Vote> = validators[..quorum].iter().map(|v| v.sign_checkpoint(&cp)).collect();
    node.finalize(&cp, &votes, &cstate).expect("finalize");
    let spend_finalized = node.finalized_height().map(|f| f >= 2).unwrap_or(false);
    say!("Finalized to height {:?}; spend finalized: {spend_finalized}", node.finalized_height());

    // Supply: only coinbase mints (130k) create value; transfers conserve it in-circuit.
    let supply_consistent = supply.minted() == 130_000 && supply.circulating() == 130_000 - 2_000;
    say!("Supply: minted {}, circulating {} (2 fees) — consistent: {supply_consistent}",
        supply.minted(), supply.circulating());

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
```

Two small support fns are needed (`send_header_stub`, `dummy_chain`) because `StoredBlock` requires a `BlockHeader` and `Devnet` a `ChainState`, but the discovery layer never consults them for `compact_range`/`full_payloads`. Implement minimally:

```rust
fn send_header_stub(node: &Node<KeccakPow>, body: &BlockBody) -> BlockHeader {
    // The discovery layer only serves compact/full/frontier — the header is
    // carried for structural fidelity, not consulted by scan_local. Use the
    // genesis-child shape bound to this body's commitment.
    let genesis = BlockHeader::genesis(1_000, 0);
    let _ = node; // node's real header chain is separate (placeholder consensus)
    BlockHeader::child_of(&genesis, 1, 1_000, body.commitment())
}

fn dummy_chain() -> qlab_devnet::chain::ChainState {
    qlab_devnet::chain::ChainState::new(BlockHeader::genesis(1_000, 0))
}
```

VERIFY during implementation: exact signatures of `BlockHeader::genesis`, `BlockHeader::child_of`, `ChainState::new`, `Wallet::rkm(d)` (takes `Diversifier` by value per viewing.rs:168), `Wallet::spend_input(value, rho, rseed, d)` (viewing.rs:206), `Node::finalized_height`, `params_devnet::{BOND_AMOUNT, CHECKPOINT_CADENCE_BLOCKS, COMMITTEE_SIZE}`. Adjust field/arg forms to the real signatures (they were mapped in recon; confirm at the callsite). If `Wallet::from_seed_lanes` or `address` differ, fix to the real names.

- [ ] **Step 4: Run the integration test, expect PASS** (generates 2 real proofs, ~3–4 s + verify).

Run: `cargo test --release -p qlab-demo --test e2e 2>&1 | tail -30`
Expected: `end_to_end_payment_loop_holds_all_invariants ... ok`.

- [ ] **Step 5: Add a `pub use` for the report/loop in `lib.rs`** (`pub use scenario::{run_loop, LoopReport};`) and re-check.

Run: `cargo check -p qlab-demo 2>&1 | tail -5`
Expected: clean.

- [ ] **Step 6: Commit.**

```bash
git add crates/qlab-demo/src/scenario.rs crates/qlab-demo/src/lib.rs crates/qlab-demo/tests/e2e.rs
git commit -m "qlab-demo: end-to-end payment loop + invariant integration test"
```

---

### Task 7: `bin/qlab-demo.rs` — human-readable transcript

**Files:**
- Modify: `crates/qlab-demo/src/bin/qlab-demo.rs`

**Interfaces:**
- Consumes: `qlab_demo::run_loop`.

- [ ] **Step 1: Implement the bin.**

```rust
//! `qlab-demo`: run the end-to-end Qumbra payment loop and print a transcript.
use qlab_demo::run_loop;

fn main() {
    println!("== Qumbra end-to-end wallet demo ==\n");
    let r = run_loop(0xA11CE_B0B);
    for line in &r.transcript {
        println!("  {line}");
    }
    println!("\n-- summary --");
    println!("  sent = {}  detected = {}  (match: {})", r.sent_value, r.detected_value, r.sent_value == r.detected_value);
    println!("  cm seam holds: {}", r.cm_seam_holds);
    println!("  proofs generated: {} ({})", r.proofs_generated,
        r.prove_secs.iter().map(|s| format!("{s:.2}s")).collect::<Vec<_>>().join(" + "));
    println!("  scan: {} compact bytes, {} matched fetch(es), {} decoy fetch(es), {} note(s) found",
        r.scan_stats.compact_bytes, r.scan_stats.matched_fetches, r.scan_stats.decoy_fetches, r.scan_stats.notes_found);
    println!("  double-spend rejected (cross-block / within-block): {} / {}",
        r.double_spend_rejected, r.within_block_double_spend_rejected);
    println!("  spend finalized: {}", r.spend_finalized);
    println!("  supply minted: {}  consistent: {}", r.supply_minted, r.supply_consistent);
    println!("  wall-clock: {:.2} s", r.wall_secs);
    assert!(r.detected_value == r.sent_value && r.cm_seam_holds && r.spend_finalized && r.supply_consistent,
        "invariants must hold");
}
```

- [ ] **Step 2: Run the bin** and eyeball the transcript.

Run: `cargo run --release -p qlab-demo --bin qlab-demo 2>&1 | tail -40`
Expected: full transcript + summary, all invariants true.

- [ ] **Step 3: Commit.**

```bash
git add crates/qlab-demo/src/bin/qlab-demo.rs
git commit -m "qlab-demo: bin prints the human-readable payment-loop transcript"
```

---

### Task 8: Full-suite acceptance + `docs/demo-run.md` (measured, reproduced twice)

**Files:**
- Create: `docs/demo-run.md`

- [ ] **Step 1: Run the FULL unfiltered workspace suite (acceptance bar).**

Run: `cargo test --release 2>&1 | tail -40`
Expected: every crate green; total test count ≥ 227 baseline + the new demo/cbserver tests. Record the count. If any pre-existing test regressed, STOP and fix (additive helpers must not disturb them).

- [ ] **Step 2: Capture run #1** of the bin (wall-clock, proof times, scan stats).

Run: `cargo run --release -p qlab-demo --bin qlab-demo 2>&1 | tee /tmp/demo-run1.txt | tail -40`

- [ ] **Step 3: Capture run #2** (reproduction, per lab discipline).

Run: `cargo run --release -p qlab-demo --bin qlab-demo 2>&1 | tee /tmp/demo-run2.txt | tail -40`

- [ ] **Step 4: Write `docs/demo-run.md`** with: git rev, hardware/OS/power, both runs' wall-clock + per-proof prove time + proof count (2) + scan time/stats, a transcript sample, and the one-paragraph "what composed / what needed glue" honesty note built from F1–F4 (prover config reconstruction; build_bucket's fabricated anchor; the two additive cbserver helpers; devnet's missing tree/nullifier-set/supply). State reproduction status (twice).

- [ ] **Step 5: Commit.**

```bash
git add docs/demo-run.md
git commit -m "qlab-demo: measured demo-run report + integration-friction note (reproduced x2)"
```

---

## Self-Review

**Spec coverage:** loop steps 1–7 → Tasks 6/7; two real proofs → Task 2 (roundtrip) + Task 6 (send/spend); F1 → Task 2; F3 helpers → Tasks 3/4; F4 glue → Task 5; invariants 1–6 → Task 6 test; measured note → Task 8. All spec sections map to a task.

**Placeholder scan:** no TBD/TODO; every code step carries real code. The two `VERIFY during implementation` notes (Task 6) are signature confirmations against already-mapped recon, not deferred design.

**Type consistency:** `Val`/`Config`/`Proof` flow prover→scenario via `crate::prover`; `LoopReport` fields consumed by Task 6 test + Task 7 bin match the struct; `h32`/`tx_entry`/`PoolVerifier` mirror `m6devnet.rs` exactly; `ScanConfig`/`DecoyPolicy`/`ScanStats`/`ScanOutcome` names match cbserver `client.rs`; `Devnet::from_parts` arg order matches Task 3.

## Risks / watch items
- Real proving RAM: two `build_bucket`+`prove` at b16 (~2^18 rows) — bounded, far under the m4 interior footprints the rig already runs; serial, not concurrent.
- `send_header_stub`/`dummy_chain`: confirm `BlockHeader::genesis`/`child_of`/`ChainState::new` signatures at callsite; the discovery layer does not consult them, so exact values are immaterial.
- If `validate_body`'s `is_anchor_final` closure type differs, match the real `F: Fn(&Hash32) -> bool` bound (m6devnet uses a `let is_final = |r| ...`).
