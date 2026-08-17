# Qumbra transaction circuit + consensus verifier

The fixed-shape STARK circuit behind a Qumbra transaction, and the verifier that
checks one — extracted from a private prototype lab into a standalone tree so
that the circuit's shape, its frozen constants, and a real proof can all be
checked by someone with no access to that lab.

Qumbra is a post-quantum privacy-chain **design exercise**: note-based UTXO, one
global shielded pool, one monolithic STARK per transaction (spend authorization
lives inside the proof — there are no per-spend signatures), conservative
hash (Keccak-class) everywhere in consensus. This repository is the part of it
that is a mathematical claim rather than an operational one, which is why it is
the part that opens first.

**This is research code.** It has not been audited. Nothing here is running on a
network you can put money on.

---

## What you can check, and how

```sh
cargo run --release --example verify     # ~seconds, any machine
```

That loads a committed real consensus proof, reconstructs the public-value
vector from the *declared* transaction surface exactly as a node does, verifies
it at the frozen config — and then shows the same proof being **refused** after
one 16-bit chunk of a declared nullifier is flipped.

The full suite:

```sh
cargo test --release -- --test-threads=1
```

`--test-threads=1` is not stylistic. `qlab-consensus`'s own tests prove from
scratch, and a single 2×2 proof peaks around **12.2 GB** of resident memory
(measured, see below); running several at once will exhaust an ordinary machine.
If you only want the verify path — which is the part that costs nothing — run:

```sh
cargo test --release --test verify_fixture
```

That is seven tests, no proving, and it is the whole open-sourced claim.

---

## What this pins

| Constant | Value | Where it is checked |
|---|---|---|
| FRI consensus config | `b16/q21/g22/fp16/a16` (blowup 16, 21 queries, 22 grind bits, final poly 16, max arity 16) | `consensus_cfg_is_value_locked` |
| Field | KoalaBear, `p = 2³¹ − 2²⁴ + 1`; degree-4 binomial extension challenge | `qlab_consensus::{Val, Challenge}` |
| Commitment hash | Keccak-256 throughout the FRI/Merkle layer | `qlab_consensus` type aliases |
| Merkle cap height | 3 | `consensus_cfg_is_value_locked` |
| Trace height | 2¹⁸ rows (84 permutations) | `LOG_HEIGHT`, `consensus_cfg_is_value_locked` |
| Consensus wire size | **148,625 B** | `consensus_wire_is_148625_bytes` (proves), `fixture_size_matches_the_crate_pin` (committed artifact) |
| Circuit shape | 2 × depth-32 Merkle membership + 2 × nullifier PRF + 2 × spend-key knowledge + 2 × commitment well-formedness + in-circuit balance | `qlab_air::narrow`, `full_bucket_satisfies_constraints` |
| Trace width | read off the matrix, never a literal | `q69_trace_width_is_read_off_the_matrix` |
| Quotient degree | does not move | `q69_quotient_degree_does_not_move` |

The FRI config is **frozen v1.0** — a genesis-binding value in the design. It
changes only through a halt-height upgrade carrying its own revision document,
never by editing this repository.

### Security label

`~100-bit conjectured`, under list-decoding-capacity accounting repriced against
the 2025 literature (DG25/CS25). Proven-Johnson is ≈ 59/58 bits query-phase,
field-capped around 80. `make_config_with` asserts the pinned Plonky3
`conjectured_soundness_bits() >= 100` on every construction, so a config below
the bar aborts rather than quietly verifying something weaker. The full
accounting lives in the spec repository, not here.

---

## Crates

- **`qlab-air`** — the fixed-shape AIR. A correct-semantics Keccak-f[1600] at 371
  columns (against the published 2,633-column AIR), a reference implementation
  cross-checked against `p3-keccak`, and the 2×2-bucket program built on top:
  membership, nullifier derivation, spend-key knowledge, commitment
  well-formedness, in-circuit balance, and the dummy-input latch that makes a
  single-note spend indistinguishable from a two-note one.
- **`qlab-consensus`** — the single source of truth for the consensus
  `StarkConfig` (field / hash / FRI plumbing), the frozen `CONSENSUS_CFG`, and
  the `prove_bucket` / `verify_proof` wrappers. Nothing here forks prover logic:
  it is the standard Plonky3 `StarkConfig` any integrator constructs, pinned to
  Qumbra's choices.

Both are `0.0.0` and unpublished. Names match the private lab's on purpose —
renaming across a boundary invites the two copies to drift.

---

## Numbers, and what they were measured against

Every figure below carries its caliper. A number without one should be treated
as unverified.

| Figure | Value | Basis |
|---|---|---|
| Consensus proof size | 148,625 B | Deterministic: a function of `log_height`, width, quotient degree and the FRI config only. Byte-exact across the lab's runs and reproduced standalone in this tree by `examples/prove_fixture`. Not a sample. |
| Prove peak memory | 12.21 GB | 1 sample, `/usr/bin/time -l` peak memory footprint, `--release`, Apple M-class laptop, this tree, 2026-08-17. Matches the private lab's independently recorded 12.21 GB. |
| Prove wall time | not quoted here | Deliberately: a timing taken on one unpinned laptop is not a publishable number, and this repository has no rig to pin it to. |

The design targets these are judged against — transaction ≤ 150 KB, prove ≤ 3 s
on a laptop — live in the spec, along with the third-party benchmark survey they
were set from.

---

## The proof fixture

`crates/qlab-consensus/tests/fixtures/` holds two committed files:

- `consensus-proof-2x2.bin` — one real consensus proof, 148,625 B, bincode
  fixint (which *is* the consensus wire encoding).
- `consensus-proof-2x2.public` — the public surface that transaction declared:
  `anchor ‖ nf₀ ‖ nf₁ ‖ cm₀ ‖ cm₁ ‖ fee`, 21 × `u64` little-endian.

The surface is stored rather than the packed public-value vector on purpose. A
verifier handed the packed vector would be trusting the fixture's own packing;
storing the surface forces the verify path to run `pv_vec` itself, and that is
the step binding a proof to *what a transaction claims*. Rewrite the claim and
the proof stops verifying — `every_declared_field_is_bound` walks all six fields.

The proof is committed rather than generated on demand because proving costs
~12.2 GB and verifying costs milliseconds, and verification is the property being
opened. It is not magic: `cargo run --release --example prove_fixture`
regenerates it from source, and the byte count must not move.

---

## What is NOT here

This is one repository out of a larger private project, opened in stages. Absent,
and private for now:

- **The node** — consensus rules, block validation, emission schedule, the
  halt-height upgrade mechanism, persistence.
- **P2P** — the wire protocol, peer discovery, gossip, rate limiting.
- **The wallet** — key derivation, note scanning, ML-KEM note encryption, the
  transaction builder, the CLI.
- **The committee / finality layer**, the faucet, the explorer, the operator
  tooling, and all deployment infrastructure.
- **The design documents**, which are the binding specification for everything
  above and are the authority whenever this code and a document disagree.

None of that is a dependency of what *is* here — the whole build graph is this
tree plus Plonky3 (see `Cargo.lock`). That was one of the things the extraction
set out to establish.

Spec documents and the staging tracker: **`qumbra-labs/qumbra`**.

Comments in the sources reference issue and PR numbers (`issue #215`, `PR #239`,
…). Those are the private lab's, kept deliberately — they are the provenance of
decisions you would otherwise have to take on faith, and a reader is better off
seeing that a constant was argued somewhere than seeing a bare number.

---

## Dependency pinning

Plonky3 is pinned at exactly `=0.6.1` and `Cargo.lock` is committed. **Build with
`--locked`.** A fresh resolve is not equivalent: `p3-util` declares a caret
requirement, so an unlocked build silently takes 0.6.3 while every other Plonky3
crate stays at 0.6.1. Proof bytes are only meaningful against a fixed prover.

---

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
