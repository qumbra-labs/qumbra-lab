# qlab-demo — measured end-to-end run + integration-friction report

The first build that proves the whole Qumbra prototype stack **composes**: a
scripted Alice→Bob payment loop over a local placeholder-consensus devnet, with
two REAL M3 tx proofs, real ML-KEM/ChaCha20 note encryption, the real
compact-block scan path (socket-free), and node-side proof validation.

## Environment

- **Repo rev:** `deb6e3b` (branch `claude/wallet-demo`)
- **Prover crates:** Plonky3 pinned `=0.6.1` (matches `qlab-bench`/`Cargo.lock`)
- **Consensus config:** `b16/q20/g22/fp16/a16`, `log_height 18` (issue #22 B′; value-locked in `qlab-demo/src/prover.rs`, reconstructed from the `qlab-bench` binary's `pub(crate)` plumbing — friction F1)
- **Hardware:** Apple M5 Max, 36 GiB
- **OS / power:** macOS 26.5.2 / AC power
- **Reproduction:** loop run **twice**, back-to-back, clean machine (both below).

## What the loop does (7 steps)

1. **Genesis + chain.** `qlab_devnet::Node::new(KeccakPow, SimConfig::default())`; three coinbase mints seed the supply (Alice 50k+30k, Bob 40k).
2. **Two wallets.** Alice & Bob via `qlab_wallet::Wallet::from_seed_lanes`; Bob publishes `bob.address(d).encode()` → a 1,985-char `qaddr1…` bech32m address; Alice `Address::decode`s it.
3. **Alice → Bob.** Alice builds Bob's `Note`, encrypts it to `addr.encapsulation_key()` (ML-KEM-768 + ChaCha20-Poly1305), and produces a **real M3 proof** (`build_bucket` → `p3_uni_stark::prove`). A devnet node runs `validate_body` whose injected `TxVerifier` calls the **real** `p3_uni_stark::verify` on the proof bytes.
4. **Bob scans.** `qlab_cbserver::client::scan_local` runs the real compact-stream → tag-match → full-fetch → decrypt → cm-recheck loop **fully in-process** (no socket), detects the note.
5. **Bob spends.** A **second real M3 proof**; his nullifier lands.
6. **Double-spend rejected** two ways: the persistent (cross-block) nullifier set, and devnet's native within-block `BodyError::DoubleSpendInBlock`.
7. **Finality + supply.** The spend block finalizes under the ML-DSA ⅔-committee quorum; the supply/coinbase counter stays consistent.

## Measured (two clean reproductions)

| Metric | Run 1 | Run 2 |
|---|---|---|
| Full-loop wall-clock | **5.78 s** | **7.05 s** |
| Real M3 proofs generated | 2 | 2 |
| Proof #1 (send) prove time | 3.40 s | 3.96 s |
| Proof #2 (spend) prove time | 2.33 s | 3.03 s |
| Scan compact-stream bytes | 1,136 B | 1,136 B |
| Matched full-fetches | 1 | 1 |
| Decoy full-fetches | 1 | 1 |
| Notes detected | 1 | 1 |
| detected value == sent value | 60,000 == 60,000 ✓ | 60,000 == 60,000 ✓ |
| cm seam (proof cm == wire cm == Note::commitment) | ✓ | ✓ |
| Double-spend rejected (cross-block / within-block) | ✓ / ✓ | ✓ / ✓ |
| Spend block finalized (height 2 ≤ finalized 8) | ✓ | ✓ |
| Supply minted / circulating | 120,000 / 118,000 | 120,000 / 118,000 |

**Note on proof time.** These single-proof times (2.3–4.0 s) exceed the M3 headline
"1.6 s" because the consensus config carries **grind 22** (issue #22 B′; the M3
headline was measured at g20). Grinding is a prove-time PoW nonce with a
**known heavy tail** (issue #22: "expected-case ~7–9 s interior, high variance");
it does not change proof size. Both proofs verify in well under a millisecond
(the m6devnet finding), so block validation is effectively free.

## Acceptance

Full **unfiltered** workspace suite green at tip (`cargo test --release`):
**all crates pass, 0 failures** — qlab-air 12, qlab-bench 80 (693 s; the heavy
real-proof gate/interior tests), qlab-cbserver 28 (incl. the 3 new helper tests),
qlab-devnet 59, qlab-note 22, qlab-wallet 23 + 3 integration, **qlab-demo 4 unit +
1 e2e**. The 8 new tests (qlab-demo 5, cbserver 3) lift the baseline 227 with no
pre-existing regression.

## What composed / what needed glue (the honest integration-friction report)

Most of the stack composed **cleanly through public APIs**: `qlab-wallet`'s
`address()`/`encapsulation_key()`/`spend_input()`/`nullifier()`, `qlab-note`'s
`encrypt_to_recipient`/`scan`, `qlab-air`'s `build_bucket`, and `qlab-devnet`'s
`validate_body(TxVerifier)`/`Node`/committee `finalize` slotted together with no
surprises — and the single tightest seam held **byte-for-byte**: the output
commitment the M3 proof commits (`inst.cm_out[0]`), the `cm` in the compact wire
entry, and `Note::commitment()` are the *same 32 bytes*, which is what let Bob's
scan match land on exactly the note the proof attests. Four things needed glue,
and they are the real report:

**F1 — the prover config was trapped in a binary crate.** `qlab-air` exposes the
AIR and `build_bucket` but **not** `prove`/`verify` or the consensus `StarkConfig`;
that plumbing lives `pub(crate)` inside the `qlab-bench` *binary*, so no library
consumer can import it. `qlab-demo` had to reconstruct the standard Plonky3
consensus config (`src/prover.rs`), value-locked to the documented decision and
guarded by a real prove→verify roundtrip test. This is the standard harness any
integrator would write — not a fork of crate logic — but it is a genuine
composability gap. **Recommended follow-up:** extract a shared `qlab-consensus`
library so `qlab-bench` and any consumer share one definition.

**F2 — `build_bucket` fabricated its own membership tree. RESOLVED
([issue #39](https://github.com/lai3d/qumbra-lab/issues/39)).** It used to derive
depth-32 Merkle siblings pseudo-randomly and assert a single self-consistent
*invented* root, accepting no caller witness — so the proof's `anchor` was not
the live commitment-tree root. Now `build_bucket_with_witnesses` takes a
caller-supplied `MerkleWitness` per input plus the anchor; the legacy
`build_bucket` is a thin fabricating wrapper for benches. The demo builds a
global `anchor_tree`, **finalizes its root through the committee**
(`finalize_root`), and the wallet/prover fetches a live membership witness
(`prover::live_witness`, backed by `CommitmentTree::auth_path`) that resolves to
that finalized root. Validation runs the full §6 + §8 gate
(`FinalityTracker::is_anchor_acceptable` — finalized-only AND ≤24 h age window),
and two negatives are exercised: a never-finalized anchor and an expired
finalized anchor are both rejected.

**F3 — `qlab-cbserver`'s serving/scan path was bolted to a self-generating
`Devnet`.** `Devnet::generate(GenParams)` plants its *own* notes and is the only
constructor; `light_client_scan` is socket-only (loopback `tiny_http`). Serving a
*real* Alice→Bob tx through the real client path needed **two additive `pub`
helpers**: `data::Devnet::from_parts(...)` (ingest externally-built real
blocks/notes) and `client::scan_local(...)` (the exact `light_client_scan` loop
with `server::route` substituted for `http_get` — same codec, same tag pre-filter,
same `qlab_note::scan::scan`, same decoy over-fetch, **no socket**). Both are
purely additive; existing behaviour and the golden-bytes framing locks are
untouched, and the full suite stays green.

**F4 — `qlab-devnet` deliberately has no commitment tree, no cross-block nullifier
set, and no supply invariant** (all three flagged as extensions in its own
source). The demo supplied them as thin glue: the tree comes from
`qlab-cbserver::tree::CommitmentTree`; the persistent nullifier set + supply/
coinbase tracker are `qlab-demo/src/ledger.rs`. These are placeholder accounting,
appropriate for a devnet.

**Bottom line:** the stack composes. One gap (F1) is worth closing with a small
shared crate; F2 (circuit-vs-chain anchor binding) is now **closed** by issue #39
— real finalized anchors with live membership witnesses; F3/F4 were closed with
additive, suite-green glue. No composed crate was forked.
