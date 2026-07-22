# qlab-demo — end-to-end wallet demo (design)

**Date:** 2026-07-22
**Branch:** `claude/wallet-demo`
**Status:** design approved (composition seams + 2 forks decided 2026-07-22)

## Goal

The first build that proves the whole Qumbra stack *composes*: a scripted end-to-end
payment loop over a local devnet chain, exercising real keys, a real note, **two real
M3 tx proofs**, real compact-block scan, and placeholder-consensus block validation —
wired as both integration tests (assert invariants) and a `qlab-demo` bin (human transcript).
Secondary deliverable: the first honest cross-crate **integration-friction report**
(`docs/demo-run.md`).

Not in scope: real networking, real consensus, a network daemon, binding the M3 circuit's
membership to the live commitment tree (see F2), design-repo writes.

## Crates composed (no changes beyond additive helpers)

| Crate | Role in the loop | Key API used |
|---|---|---|
| `qlab-wallet` | Alice/Bob keys, Bob's published address, scan-key | `Wallet::from_seed_lanes`, `wallet.address(d).encode()`, `Address::decode`, `addr.encapsulation_key()`, `diversified_keypair(&d).dk`, `wallet.spend_input(...)`, `wallet.nullifier(&rho)` |
| `qlab-note` | note build, encrypt-to-recipient, decrypt/detect | `Note`, `Note::commitment()`, `encrypt_to_recipient(ek, notes, rng)`, `scan(dk, out, mode)` |
| `qlab-air` | the 2×2 bucket statement (real M3 proof) | `build_bucket(18, &inputs, &outputs, fee) -> BucketInstance`, `inst.air.generate_trace`, `inst.pvs`, `inst.nf`, `inst.cm_out`, `inst.anchor` |
| `qlab-devnet` | chain, block, real-proof validation, finality | `Node::new(KeccakPow, SimConfig)`, `node.mine_next`, `BlockBody`/`TxEntry`/`TxPublic`, `validate_body(body, verifier, is_anchor_final)`, `TxVerifier` trait, `posted_fee(ArityBucket::TwoByTwo)`, committee/`finalize` |
| `qlab-cbserver` | commitment tree, compact serving, client scan | `tree::CommitmentTree`, `codec::CompactBlock/CompactGroup`, **NEW** `Devnet::from_scenario(...)`, **NEW** `client::scan_local(...)` |

## The payment loop (scenario driver)

1. **Genesis + chain.** `Node::new(KeccakPow, SimConfig::default())`. Bootstrap: Alice owns
   2 coinbase notes, Bob owns 1 coinbase note (minted at genesis into the demo `ledger`
   supply tracker + appended to the `CommitmentTree`).
2. **Two wallets.** Alice, Bob via `Wallet::from_seed_lanes`. Bob publishes
   `bob.address(Diversifier::default()).encode()` (`qaddr1…`); Alice parses it with `Address::decode`.
3. **Alice → Bob note.** Alice constructs Bob's `Note { value: V, rkm: addr.rkm_lanes(), rho, rseed }`,
   then a matching `TxOutput` so `build_bucket(...).cm_out[0] == note.commitment()`. She
   `encrypt_to_recipient(addr.encapsulation_key(), &[note], rng)`.
   Alice's tx: inputs `[coinA0, coinA1]`, outputs `[Bob note V, Alice change C]`,
   `fee = posted_fee(TwoByTwo)`, balance `V+C+fee == valueA0+valueA1` (enforced in-circuit).
4. **Real M3 proof #1.** `prove(&config, &inst.air, trace, &pvs)` (~1.6 s). Wrap the public
   surface into `TxEntry { proof: proof_bytes, public: TxPublic{ anchor, nullifiers, commitments,
   bucket: TwoByTwo, fee } }`; the `anchor` is `inst.anchor` (see F2). Mine a block carrying it;
   a peer runs `validate_body` whose injected `TxVerifier` calls the **real** `verify` on the proof.
5. **Bob scans (real cbserver client path, in-process).** Build a `cbserver::data::Devnet`
   from the real chain via the new `Devnet::from_scenario`; `client::scan_local(&devnet, &bob_dk,
   from, to, ScanConfig{ mode: FullFo, decoy: PerMatch{max:1} }, rng)` runs the exact
   compact-stream → tag-match → full-fetch → decrypt → cm-recheck loop with **no socket**.
   Assert: exactly one `DetectedNote`, `detected.note.value == V` (**detected == sent**).
6. **Bob spends (real M3 proof #2).** Bob spends `[detected note V, coinB0]` → outputs (e.g.
   back to Alice + change). `nf = bob.nullifier(&rho)` lands in `ledger` nullifier set. A
   re-submitted spend with the same `nf` is rejected (persistent-set check + devnet's native
   within-block `BodyError::DoubleSpendInBlock` demonstrated in a 2-tx block).
7. **Finality + supply.** Finalize at the checkpoint cadence via the ML-DSA committee
   (`devnet_committee` + `node.finalize`); assert Bob's spend block finalizes and the
   `ledger` supply/coinbase counter is unchanged across the loop (each tx conserves value
   in-circuit; fees are accounted, not minted).

## Composition friction (the report)

- **F1 — prover config trapped in a binary crate.** `qlab-air` exposes the AIR + `build_bucket`
  but not `prove`/`verify` or the consensus `StarkConfig`; those are `pub(crate)` in the
  `qlab-bench` *binary*. **Resolution (decided):** `qlab-demo/src/prover.rs` reconstructs the
  standard Plonky3 consensus config, **value-locked** to `b16/q20/g22/fp16/a16`, `log_height 18`,
  guarded by a `prove→verify` roundtrip test. Not a fork of crate logic (the standard harness any
  integrator writes). Follow-up recommended: extract `qlab-consensus` so bench + demo share one
  definition. (Bench left untouched this session — 227-test acceptance blast radius.)
- **F2 — `build_bucket` fabricates its own depth-32 membership tree** (pseudo-random siblings,
  asserts a single root); it accepts no caller Merkle witness. The proof's `anchor` is therefore
  a self-consistent *invented* root, not the live `CommitmentTree` root. The driver declares that
  anchor and marks it finalized so `validate_body`'s `is_anchor_final` passes. Tying circuit
  membership to the live tree is future work — would require changing `build_bucket` (beyond
  additive → a real STOP-POINT if it were required; it is not for this demo).
- **F3 — `cbserver` serving is bolted to a self-generating `Devnet`.** `generate(GenParams)`
  plants its own notes; `light_client_scan` is socket-only. **Resolution (decided):** two
  additive `pub` helpers — `data::Devnet::from_scenario(...)` (ingest externally-built real
  blocks/notes) and `client::scan_local(...)` (the real client loop against `&Devnet`, no socket).
  Additive-only; existing behavior and golden-bytes locks untouched; full suite stays green.
- **F4 — `qlab-devnet` has no commitment tree, no cross-block nullifier set, no supply
  invariant** (all three flagged as devnet extensions in its own source). Demo supplies them as
  glue: tree via `cbserver::tree::CommitmentTree`; persistent nullifier set + supply/coinbase
  tracker in `qlab-demo/src/ledger.rs`.

## Crate layout

```
crates/qlab-demo/
  Cargo.toml            # deps: qlab-wallet, qlab-note, qlab-air, qlab-devnet, qlab-cbserver,
                        #       p3-* (uni-stark/koala-bear/etc, matched to bench Cargo.lock), rand
  src/lib.rs            # re-export scenario entry + result types
  src/prover.rs         # F1: Val/Config type aliases, FriCfg, CONSENSUS_CFG, make_config, prove/verify wrappers
  src/ledger.rs         # F4: SupplyTracker + persistent NullifierSet (documented devnet extensions)
  src/scenario.rs       # the payment loop; returns a structured LoopReport (values, proof timings, scan stats)
  src/bin/qlab-demo.rs  # thin CLI: run the loop, print the human transcript
  tests/e2e.rs          # integration tests asserting every invariant
```

## Invariants asserted (tests/e2e.rs)

1. Bob detects exactly one note; `detected value == Alice sent value`.
2. Both real M3 proofs `verify().is_ok()`; a tampered proof/public-value is rejected by `validate_body`.
3. Bob's spend nullifier lands; a duplicate-`nf` resubmission is rejected (persistent set) and a
   within-block duplicate is rejected natively (`BodyError::DoubleSpendInBlock`).
4. Bob's spend block finalizes under the ML-DSA committee quorum.
5. Supply/coinbase counter is invariant across the whole loop.
6. The on-chain `cm` (`TxPublic.commitments[0]`), the compact-entry `cm`, and `Note::commitment()`
   are byte-identical (the tight composition seam).

## Measured note (docs/demo-run.md)

Full-loop wall-clock; proof-gen count (2) + per-proof time; scan time + `ScanStats`; and the
one-paragraph "what composed / what needed glue" honesty note built from F1–F4. Reproduced twice
per lab discipline.

## Discipline

Staged commits; **full unfiltered `cargo test --release` workspace suite** green at tip (baseline
227; qlab-demo adds tests, cbserver additive helpers add tests); subagents isolated or serial;
never enter other worktrees. PR (no merge) with: test count, transcript sample, friction report,
remainder. Handoff note if interrupted.
