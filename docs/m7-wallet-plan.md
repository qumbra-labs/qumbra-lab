# M7 — Wallet core (`qlab-wallet`) — plan & decision record

Status: in progress. Builder session `privacy-m7-team-dev`, branch `claude/m7-wallet-core`.

Scope: the **key layer** of the Qumbra wallet — key hierarchy, diversified
addresses, and the standing-disclosure (fvk/ivk) capability split — wired to the
already-built `qlab-note` (KEM/AEAD/scan) and cross-checked byte-for-byte against
`qlab-air`'s in-circuit spend-key derivation. **No proving, no networking, no
persistence, no disclosure PROOFS** (the selective-disclosure STARK is a future
milestone; only the KEY layer here).

Binding spec: `qumbra-design/transaction-model-and-anonymity-set.md` §4 (key
hierarchy table + note/cm/nf objects + address shape); `auditable-privacy.md` §4
(four-layer disclosure stack — fvk/ivk are the **standing** layer); `note-discovery.md`
§2 (ratified compact-entry wire — `qlab-note` implements it, REUSED not forked).

---

## 1. The derivation table — byte-for-byte with the circuit

The circuit (`qlab-air::narrow`) is the authority: these derivations are what the
STARK actually checks (roles `ROLE_ANK`/`ROLE_ARKM`/`ROLE_NF`, host path in
`build_bucket`, `narrow.rs:935-966`). The wallet MUST reproduce them exactly or a
wallet-made note cannot be spent. All are single-block Keccak-f[1600] over a
`[u64; 25]` state (lane `i` = 64-bit little-endian word), digest = output lanes 0..3.

| Key | Formula | State packing (indices into `[u64;25]`) | Domain marker | Pad10*1 |
|---|---|---|---|---|
| `nk` (nullifier key) | `H(sk ‖ D_N)` | `st[0..4]=sk` | `st[4]=1<<0` (bit z0 @ lane 4) | `st[5]=1` (bit 320), `st[16]=1<<63` (bit 1087) |
| `rkm` (recipient key material) | `H(nk ‖ D_R)` | `st[0..4]=nk` | `st[4]=1<<1` (bit z1 @ lane 4) | `st[5]=1`, `st[16]=1<<63` |
| `nf` (nullifier) | `H(nk ‖ ρ)` | `st[0..4]=nk`, `st[4..8]=ρ` | — (message is 512 bits) | `st[8]=1` (bit 512), `st[16]=1<<63` |
| `cm` (commitment) | `H(value ‖ rkm ‖ ρ ‖ rseed)` | `st[0]=value`, `st[1..5]=rkm`, `st[5..9]=ρ`, `st[9..13]=rseed` | — | `st[13]=1` (bit 832), `st[16]=1<<63` |

`cm` is already implemented + regression-locked in `qlab-note::note::note_commitment`
(REUSED). `nk`/`rkm`/`nf` are this crate's new derivations.

### Domain strings — a deliberate note

`qlab-note` uses ASCII domain-separation prefixes (`b"qumbra:note-detect:v1"`, …)
for its KDF/tag outputs. The **circuit-bound** derivations above CANNOT use ASCII
prefixes: they must be byte-identical to what the STARK checks, and the circuit
separates domains with a **single marker bit at lane 4** (`z0` for the nk-domain
"N", `z1` for the rkm-domain "R"), because an in-circuit ASCII absorb would cost
extra Keccak lanes the circuit was optimised not to spend. So:

- **Circuit-bound layer** (`nk`, `rkm`, `nf`): compact bit-position domain markers,
  transcribed verbatim from `narrow.rs`. Documented above; regression-locked (§4).
- **Wallet-only layer** (ML-KEM seed, diversifier keypairs, any non-circuit KDF):
  ASCII DS strings à la `qlab-note`:
  - `DS_MLKEM_SEED = b"qumbra:wallet:mlkem-seed:v1"` — base ML-KEM keypair seed `= Keccak(DS_MLKEM_SEED ‖ sk_bytes)`.
  - `DS_MLKEM_DIV  = b"qumbra:wallet:mlkem-div:v1"` — diversified keypair seed `= Keccak(DS_MLKEM_DIV ‖ div_seed ‖ d)`.
  - `DS_DIV_SEED   = b"qumbra:wallet:div-seed:v1"` — `div_seed = Keccak(DS_DIV_SEED ‖ sk_bytes)` (carried by ivk/fvk so they can regenerate any diversified keypair).
  - `DS_SHORTADDR  = b"qumbra:wallet:short-addr:v1"` — short-address hash commitment.

Domain non-collision: `nk` and `rkm` share the 320-bit message length but differ in
lane 4 (1 vs 2) and lanes 0..3 (sk vs nk) → distinct. `nf` (512-bit message, pad at
lane 8) is length-separated from both. No cross-derivation collision.

---

## 2. Diversification — the spec question, and the decision

**The gap (reported, coordinator-confirmed):** the circuit binds `rkm = H(nk ‖ D_R)`
— *one fixed value per spending key, no diversifier input*. The doc (§4) calls for a
*"diversified address = (diversifier, ivk-derived key material, ML-KEM ek)"* whose
purpose (Sapling/Orchard precedent) is **unlinkability across a wallet's addresses**.
Because a sender must know `rkm` to compute `cm`, `rkm` must appear in the address;
with `rkm` fixed, all of a wallet's addresses **share `rkm` and are linkable**.
Diversifying only the ML-KEM `ek` does not buy unlinkability. Making `rkm` depend on
the diversifier would require changing the ratified, already-measured circuit —
**out of M7 scope**.

**Decision (Option 1, coordinator-confirmed):**
- The **diversifier** deterministically derives a per-address ML-KEM keypair
  (`ek_d`/`dk_d`); `rkm` stays the shared circuit-bound `H(nk ‖ D_R)`.
- Circuit untouched; the `qlab-note` cm/nf regression locks hold.
- Ship the honest limitation: *addresses of one wallet are linkable via `rkm`; full
  unlinkability requires the circuit to bind `rkm = H(nk ‖ D_R ‖ d)`.*

**Circuit-change proposal (for the coordinator to file as a lab issue; PR body will
carry the précis):**
- **What:** absorb a per-address diversifier `d` into the rkm derivation:
  `rkm = H(nk ‖ D_R ‖ d)` — one extra 256-bit lane group in the `ROLE_ARKM` message.
- **Where:** `crates/qlab-air/src/narrow.rs:950-956` (the `rkm_in` packing in
  `build_bucket`'s `derive` closure) + the matching `ROLE_ARKM` message wiring in
  the AIR `eval` (`msg_arkm`, ~narrow.rs:554-562) + the rkm role doc (narrow.rs:117-119).
- **Cost estimate:** `d` fits in the ARKM perm's existing free witness lanes
  (rkm currently uses lanes 0..4 of a single-block absorb; `d` extends the message
  by 4 lanes, still one Keccak-f block) → ≈ **no new perms** if it stays in one
  block, at most one extra perm per input if a second block is forced. Either way a
  **full re-bench is required** (consensus config size/prove numbers are the gate).
- **Not done here** (would be a silent divergence from the ratified circuit —
  forbidden by CLAUDE.md). The wallet implements exactly what the circuit checks today.

---

## 3. Addresses — encoding & short-address

- **Raw address** = `version(1) ‖ diversifier(d) ‖ rkm(32) ‖ ML-KEM-768 ek(1184)`.
  Diversifier width TBD in build (8 or 16 B); raw size measured + reported in PR
  (expected ≈ 1.3 KB, dominated by the 1,184-B ek — matches doc §4).
- **Encoding:** **bech32m-class** — versioned human-readable prefix + base32 +
  BCH checksum (the m-variant constant, the one Bitcoin adopted for v1+ segwit /
  Taproot after the original bech32 insertion-bug finding). Justification: (a) the
  doc explicitly cites "bech32m-class expected"; (b) BCH checksum gives strong
  typo/transposition detection at this size; (c) versioned prefix lets the format
  evolve (e.g. when the diversified-rkm circuit lands). For a ~1.3 KB payload the
  encoded string is long (~2 KB, doc's estimate) — hence the short-address layer.
  *(Impl note: a self-contained bech32m codec is written in-crate — no new external
  dep beyond the workspace set, keeping the additive-only discipline.)*
- **Short-address indirection** (Abelian precedent, doc §4): `short = Keccak(DS_SHORTADDR ‖ raw_address)[..N]`,
  encoded compact. A **resolution stub** maps `short -> raw_address` as an in-memory
  table only — **format + interface, no network** (resolution transport is out of scope).

---

## 4. Regression-lock strategy (the acceptance-critical bit)

Same precedent as `qlab-note`'s `commitment_matches_qlab_air_build_bucket`: lock the
wallet's derivations to **public outputs of `qlab_air::narrow::build_bucket`**, so a
change to the circuit's derivation breaks the wallet test.

- **nk path (external):** for inputs `i` with spend key `sk_i` and seed `ρ_i`,
  `wallet::derive_nf(derive_nk(sk_i), ρ_i) == build_bucket(...).nf[i]`. Since
  `nf = H(nk ‖ ρ)`, any drift in the nk derivation (packing, domain bit, pad) flips
  `nf`. Locks `sk → nk → nf`.
- **rkm path (external, via anchor):** rebuild the shared tree from wallet-derived
  input commitments (`cm = H(value ‖ rkm ‖ ρ ‖ rseed)`, `rkm = H(nk ‖ D_R)`) using
  `reference::merkle_node_state` + the same sibling schedule, and assert the root
  equals `build_bucket(...).anchor`. The anchor depends on the input `cm`, which
  depends on `rkm`, which depends on `nk` → locks the rkm derivation to the circuit.
- **rkm packing (belt-and-suspenders):** a byte-identical replication test of the
  `narrow.rs:950-956` `rkm_in` packing, asserting `derive_rkm(nk)` equals it.

Acceptance bar (non-negotiable, CLAUDE.md §Bench discipline 5): **full unfiltered
`cargo test --release`** green on every commit — the whole workspace, not a filter.

---

## 5. Disclosure hooks — capability model (auditable-privacy §4 standing layer)

Type-level separation; spend capability lives ONLY in `SpendingKey`.

| Type | Holds | Can | Cannot |
|---|---|---|---|
| `SpendingKey` | `sk` | derive everything; produce a spend witness (`TxInput` for the circuit) | — |
| `Fvk` (full viewing) | `nk`, ML-KEM `dk`, `div_seed` | derive `rkm`; **view spends** (`nf = H(nk ‖ ρ)`); detect + decrypt incoming | **spend** (no `sk`; no `TxInput` constructor) |
| `Ivk` (incoming viewing) | `rkm`, ML-KEM `dk`, `div_seed` | detect + decrypt incoming (via `qlab-note::scan`); recompute `cm` | compute `nf` (no `nk`); **spend** |

- `fvk ⊇ ivk`: `Fvk::to_ivk()` derives `rkm` from `nk` and drops `nk` — a one-way
  downgrade (preimage resistance: `ivk` cannot recover `nk`).
- "Neither can spend" is **type-level**: only `SpendingKey` exposes a method that
  yields the circuit's `TxInput` witness. `Fvk`/`Ivk` have no such method and do not
  carry `sk`. (Proving is out of scope; "spend capability" at the key layer = the
  ability to produce the spend witness the circuit consumes.)
- Negatives tested: wrong-key scan detects nothing; `ivk` has no `nf`/spend path;
  `fvk`/`ivk` round-trip (downgrade + re-derive) is consistent.

---

## 6. Open questions (parked, per scope)

- **HD-seed / seed format:** how `sk` (and thus `div_seed`, ML-KEM seed) is derived
  from a master seed / mnemonic (BIP-32/39-class vs a PQ-native KDF tree) is
  **explicitly out of M7 scope**. This crate takes `sk` as a given 256-bit secret.
  Flagged for a future milestone. Note the tension: a BIP-39 mnemonic is a
  classical construct; a PQ chain may want a seed scheme with no 2048-word English
  wordlist assumption — a design-repo question when it's picked up.
- **Diversified `rkm`** (unlinkability): the circuit-change proposal in §2 — owned by
  the coordinator (design-repo §4 correction + lab issue).
- **Diversifier width / policy** (how many, how chosen, exhaustion): prototype uses a
  caller-supplied `d`; wallet-level diversifier management is future work.

---

## 7. Commit staging

1. Plan doc + crate scaffold (this) → workspace member `qlab-wallet`.
2. Key hierarchy (`keys.rs`) + regression locks.
3. Addresses (`address.rs`) + bech32m codec + short-address.
4. Disclosure hooks (`viewing.rs`) + capability tests.
5. End-to-end test + PR (no merge; coordinator accepts).

Full unfiltered `cargo test --release` green at every commit.

---

## 8. Results (measured)

- **Address sizes (CI-locked, `address::tests::measured_sizes`):** raw
  **1,233 B** (~1.2 KB, dominated by the 1,184-B ML-KEM ek), bech32m-encoded
  **1,985 chars** (~2 KB), short address **35 chars**. Matches tx-model §4's
  "~1.3 KB raw, ~2 KB encoded"; short address beats Abelian's 136-char handle.
- **Derivation locks:** `nk_nf_path_locked_to_build_bucket` (sk→nk→nf vs
  circuit `nf[]`), `rkm_path_locked_via_anchor` (rkm→input-cm→root vs circuit
  `anchor`), `rkm_packing_byte_identical`. All green.
- **End-to-end:** `derive_address_encrypt_scan_recompute_and_spend` — full loop
  incl. spending the received note (circuit `nf[0]` == wallet nullifier) and
  `cm_out` == recomputed commitment. Green.
- **Test count:** qlab-wallet 22 unit + 2 integration + 2 compile_fail
  doc-tests; +1 additive qlab-note test (`ek_from_bytes`). Full unfiltered
  workspace suite green (qlab-air 11, qlab-bench 80, qlab-devnet 59,
  qlab-note 22, qlab-wallet 24 +2 doc).
