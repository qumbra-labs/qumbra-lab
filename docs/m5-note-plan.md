# M5 Note-Encryption Prototype — Implementation Plan

> **For agentic workers:** executed inline (single session) with staged commits + TDD.
> Steps use checkbox (`- [ ]`) syntax for tracking. This doc doubles as the
> **decision record** the M5 task requires (crate choice, cipher rationale,
> detection-tag derivation justification).

**Goal:** Prototype ML-KEM-768 note encryption + the ratified compact-entry wire
layout (Decision 1/2 of `qumbra-design/note-discovery.md`, ratified 2026-07-21),
with a measurable client scan flow on both the standard FO path and the
experimental FO-skip path.

**Architecture:** New isolated crate `qlab-note` (library) holding the KEM
wrapper, AEAD, domain-separated key/tag derivation, wire layout, and scan flow.
Correctness authenticity for the FO-skip path is via recomputing the note
commitment — which **calls qlab-air's `reference::keccak_f` with the exact
`value‖rkm‖rho‖rseed` packing** the circuit binds (`crates/qlab-air/src/narrow.rs`
`build_bucket`), never a fork. A thin `m5note` module in `qlab-bench` holds the
bench mode + the authoritative integration/negative tests so they land in the
acceptance command `cargo test --release -p qlab-bench`.

**Tech Stack:** Rust 2021; `ml-kem` 0.3.2 (RustCrypto, FIPS 203 final); `chacha20poly1305`
0.11 (RustCrypto, RFC 8439); Keccak-256 sponge over `qlab_air::reference::keccak_f`.

## Global Constraints

- **Design repo is READ-ONLY.** No writes to `qumbra-design/`. This plan + results
  live in `qumbra-lab/docs/` (scratch); publishable numbers go to the design repo
  only via the coordinator, after the lab reproduction discipline.
- **Do not touch** `m4gate.rs` / `m4interior.rs` / `m4assembly.rs` / `qlab-air`
  (parallel batons: M-WHIR, issue #21 on m4gate.rs). All workspace changes
  **additive-only**: new crate `qlab-note`; new `crates/qlab-bench/src/m5note.rs`;
  one additive dep line + `mod`/match-arm in `qlab-bench` (`Cargo.toml`, `main.rs`).
- **No consensus-circuit coupling, no network code, no design-repo writes.**
- **cm recompute = call qlab-air, do not fork.** Regression-locked to
  `qlab_air::narrow::build_bucket(...).cm_out[i]` by a cross-check test.
- **Acceptance bar:** full unfiltered `cargo test --release -p qlab-bench` green at
  every commit. Also run whole-workspace `cargo test --release` for `qlab-note`'s
  own unit tests.
- **Bench discipline:** pin exact crate versions in Cargo.lock; every result carries
  git rev / crate revs / hardware / OS / power; reproduce twice.
- FO path (a) is the **default**; FO-skip path (b) is **EXPERIMENTAL** (the ANON-CCA
  written argument is an OPEN design-repo obligation, doc §2 — I do NOT write it).

---

## Crate-choice record (task deliverable)

| Role | Crate | Version | FIPS-203 / vector status | Notes |
|---|---|---|---|---|
| ML-KEM-768 | **`ml-kem`** (RustCrypto) | `=0.3.2` (2026-05-10) | FIPS 203 **final**; tested vs **NIST ACVP** (`key-gen`, `encap-decap`) + **Wycheproof** | pure-Rust, `no_std`, MSRV 1.85; **unaudited (self-declared)** — recorded remainder |
| AEAD | **`chacha20poly1305`** (RustCrypto) | `=0.11.0` (2026-06-28) | RFC 8439; **RUSTSEC-clean** | pure-Rust, MSRV 1.85, same ecosystem |
| Hash | qlab-air `reference::keccak_f` | in-repo | cross-checked vs `p3-keccak` | Keccak-256 sponge built on it |

**Alternative considered — `libcrux-ml-kem` 0.0.10 (Cryspen):** formally verified
(hax/F*), shipped in Firefox/NSS. Rejected as the prototype default for `0.0.x`
instability + no stated MSRV + KAT status not advertised; **named as the
formally-verified production alternative** in the PR remainder. STOP-and-report
clause **not** triggered: a vetted pure-Rust crate exists.

## Cipher rationale (task deliverable)

ChaCha20-Poly1305 (the doc's expected ChaCha20-Poly1305-class default): IETF/RFC-8439
standardized AEAD, constant-time pure-Rust, no hardware-AES dependence (matters for
the low-end-phone scan target), RUSTSEC-clean. AES-256-GCM was the alternative;
rejected to avoid timing-safety pitfalls on phone cores without AES-NI.

## Detection-tag derivation (task deliverable — doc §2 open spec detail)

All derivations use `KDF = Keccak-256` (original/Ethereum pad10*1, matching qlab-air's
Merkle/commitment layer and Qumbra's conservative-hash-everywhere stance). `K` = the
32-byte ML-KEM shared secret (shared per `(tx, recipient)`); `cm_i` = the note
commitment; `i` = the note's canonical public output index in the tx.

```
tag_i    = Keccak256( DS_TAG   ‖ K ‖ cm_i )[0..8]     # 8 bytes  → 2^-64 false-positive
k_aead_i = Keccak256( DS_AEAD  ‖ K ‖ u32le(i) )[0..32] # ChaCha20 key
nonce_i  = Keccak256( DS_NONCE ‖ K ‖ u32le(i) )[0..12] # 96-bit nonce
```
with distinct domain constants `DS_TAG=b"qumbra:note-detect:v1"`,
`DS_AEAD=b"qumbra:note-aead-key:v1"`, `DS_NONCE=b"qumbra:note-aead-nonce:v1"`.

**Justification:**
- **2^-64 FP:** tag is 8 uniform bytes; for a wrong `(K, cm)` the output is uniform →
  P(spurious match) = 2^-64, meeting the doc's target.
- **Domain separation:** distinct `DS_*` prefixes make tag / AEAD-key / nonce
  independent RO outputs of the same secret — the public 8-B tag leaks nothing about
  the AEAD key/nonce.
- **Tag binds `(K, cm)`:** `K` is secret (only sender+recipient) → wrong-key scan
  yields tag mismatch (no false detection / anonymity), and no attacker can forge a
  tag for a chosen `cm`.
- **AEAD key binds `(K, index)`, NOT cm:** `K` is shared across a recipient's outputs
  in one tx (amortization); indexing by `i` gives a **distinct key+nonce per note** →
  no nonce reuse under the shared `K`. Deliberately independent of `cm` so that the
  **cm-recompute is the sole authenticity binding to the on-chain commitment** on path
  (b) — an independently testable layer, not shadowed by key derivation.

## Wire layout (ratified Decision 1/2)

Compact per-note entry (the per-note download stream; AEAD payload/memo is
full-fetched only on match, NOT in this stream):

| field | bytes | source |
|---|---|---|
| `cm` note commitment | 32 | qlab-air commitment (authenticity anchor) |
| ML-KEM-768 `ct` | 1088 / #outputs-to-recipient | **shared per (tx, recipient)** |
| detection `tag` | 8 | derivation above |
| `clue` slot | 1 (empty, versioned) | Decision 2 genesis reservation (0x00 = empty; future OMR ≈1 KB) |

Amortized bytes/note = `32 + 8 + 1 + ceil(1088 / k)` for `k` outputs to the recipient.
- 1-of-1: 32+8+1+1088 = **1129 B** (matches doc ~1.1 KB unamortized).
- 2-of-1: 32+8+1+544 = **585 B** (matches doc ~600 B amortized).

## File structure

- Create `crates/qlab-note/Cargo.toml` — deps: `ml-kem =0.3.2`, `chacha20poly1305 =0.11`, `qlab-air` (path), `rand 0.10`; dev: `tiny-keccak` or a hardcoded KAT for the sponge cross-check.
- Create `crates/qlab-note/src/lib.rs` — module wiring + public re-exports + doc.
- Create `crates/qlab-note/src/hash.rs` — `keccak256(&[u8]) -> [u8;32]` sponge over `qlab_air::reference::keccak_f`; unit test vs known vectors.
- Create `crates/qlab-note/src/note.rs` — `Note{value,rkm,rho,rseed}`, `note_commitment()` calling qlab-air packing; plaintext (de)serialization.
- Create `crates/qlab-note/src/kem.rs` — ML-KEM-768 encap/decap wrapper (path a); optional CPA-decap (path b) if the crate exposes it; KAT sanity test.
- Create `crates/qlab-note/src/derive.rs` — `DS_*` constants + `tag/k_aead/nonce` derivation.
- Create `crates/qlab-note/src/wire.rs` — `CompactEntry`, `ClueSlot`, `SharedCiphertext`, `RecipientBundle`, byte (de)serialization + size accounting.
- Create `crates/qlab-note/src/scan.rs` — `encrypt_to_recipient(...)`, `scan(dk, bundle, ScanMode)` with `ScanMode::{FullFo, FoSkip}`; both variants behind the flag.
- Modify `Cargo.toml` (workspace) — add `crates/qlab-note` to members (additive).
- Modify `crates/qlab-bench/Cargo.toml` — add `qlab-note = { path = "../qlab-note" }` (additive).
- Modify `crates/qlab-bench/src/main.rs` — `mod m5note;` + `"m5note"` match arm (additive).
- Create `crates/qlab-bench/src/m5note.rs` — bench mode (decap/s both paths, bytes/note table) + **authoritative integration/negative tests** (round-trip, wrong-key, tampered ct, tampered cm recompute, amortization) + **qlab-air cm cross-check**.

## Tasks (staged commits; suite green at each)

- [ ] **T1 — Scaffold + plan.** New crate `qlab-note` (empty lib), workspace member, this plan doc. `cargo check` green. Commit.
- [ ] **T2 — Keccak-256 sponge (`hash.rs`).** TDD: test `keccak256(b"")` == known vector `c5d2…a470`; test multi-block. Implement sponge over `qlab_air::reference::keccak_f`. Commit.
- [ ] **T3 — Note + commitment (`note.rs`).** TDD: cross-check `note_commitment(v,rkm,rho,rseed)` == qlab-air packing (this test moves to qlab-bench in T9 for the acceptance run; keep a local one too). Plaintext codec round-trip. Commit.
- [ ] **T4 — KEM wrapper (`kem.rs`).** TDD: encap→decap round-trip returns equal `K`; wrong-key decap returns different `K`; ACVP-shape sanity. Path-(b) CPA-decap: implement if crate exposes K-PKE.Decrypt, else record the measurement-decomposition fallback. Commit.
- [ ] **T5 — Derivation (`derive.rs`).** TDD: tag determinism; distinct domains → distinct outputs; per-index key/nonce distinctness. Commit.
- [ ] **T6 — Wire layout (`wire.rs`).** TDD: serialize/deserialize round-trip; byte-size accounting asserts 1129 (1-of-1) and 585 (2-of-1). Commit.
- [ ] **T7 — Encrypt + scan both paths (`scan.rs`).** TDD: `encrypt_to_recipient` then `scan` FullFo + FoSkip both detect+decrypt the round-trip. Commit.
- [ ] **T8 — Negative + amortization tests (in qlab-note).** wrong-key → no detection; tampered ct → no detection/AEAD fail; tampered cm → FoSkip recompute rejects; 2-output/one-ct amortization detects both. Commit.
- [ ] **T9 — qlab-bench integration (`m5note.rs` + main.rs arm).** Port the enumerated round-trip/negative/amortization tests + qlab-air cm cross-check into qlab-bench so `cargo test --release -p qlab-bench` exercises them. Commit.
- [ ] **T10 — Bench mode + measure twice.** decap/s single-core (both paths + FO-skip speedup factor vs doc's 40–50%), bytes/note (1-of-1, 2-of-1) vs doc ~600 B and survey's ~10k decap/s A72 ref. Write results to `docs/m5note-run{1,2}.md`. Commit.
- [ ] **T11 — Full unfiltered suite green; open PR.** Body: test count, measured table vs doc numbers, crate-choice record, remainder (ANON-CCA argument stays OPEN and named; unaudited crate; CPA-decap API status). Do NOT merge.

## Remainder (stays open — named)

- **ANON-CCA / FO-skip security argument** — design-repo deliverable (doc §2), NOT written here.
- `ml-kem` unaudited (formal-verified libcrux is the production alternative).
- Exact amortization ratio vs Qumbra's real output distribution (doc open item).
