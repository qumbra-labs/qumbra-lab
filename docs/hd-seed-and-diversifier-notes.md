# HD seed format + diversifier management — notes & spec proposal (issue #43)

Status: implemented in `qlab-wallet` (issue #43, branch `claude/hd-seed`). This
doc records the design and offers a **proposal for a new seed-format section of
`wallet-interop-spec.md`**. The spec body itself is design-repo / coordinator
owned — this is the lab-side input, mirroring how PR #34 fed the frontier
serialization to interop-spec O5.

Scope guard: `qlab-wallet` only. Zero consensus surface, zero touch to
`qlab-air` / `qlab-bench` / `m4gate` / config — the HD tree and diversifier
machinery are *wallet-only* KDFs the STARK never sees (contrast the circuit-bound
`nk`/`rkm`/`nf`, which are byte-locked to `build_bucket`).

---

## 1. What M7 parked, and why it is unblocked now

M7 (PR #33) shipped the key hierarchy taking `sk` as a *given* 256-bit secret and
parked two items (`docs/m7-wallet-plan.md` §6): (a) how `sk` descends from a
master seed / mnemonic, (b) diversifier bookkeeping. Both are additive and
non-consensus. Diversifier management became *useful* only after issue #32
(PR #35) made `rkm = H(nk ‖ D_R ‖ d)` diversifier-dependent — before that, all of
a wallet's addresses shared one `rkm` and were linkable, so "manage many
diversifiers" bought nothing. Post-#32 the addresses are genuinely unlinkable, so
the wallet needs the bookkeeping to allocate/rotate/persist them.

---

## 2. HD seed → key hierarchy (implemented)

**No BIP-32, no BIP-44 secp256k1 point math** — public-key derivation (xpub) is
meaningless for a hash/STARK PQ chain, and there is no elliptic curve to derive
on. **No HMAC-SHA512** — the whole tree is the single conservative permutation
Qumbra uses everywhere (`qlab_air::reference::keccak_f`, via
`qlab_note::hash::keccak256`). Every level is *hardened* by construction (mixes
the full parent secret); there is deliberately no non-hardened branch.

### Master seed (versioned)

`MasterSeed = { version: u8, entropy: [u8; 32] }`. The version byte leads the
master absorb, so a future scheme change produces an entirely disjoint tree from
the same entropy — a clean forward-compat door. Current `SEED_VERSION = 1`.

### Derivation path `m / account / role`

```text
node_master     = Keccak256( "qumbra:hd:v1:master"  ‖ [version] ‖ entropy(32) )
node_account(a) = Keccak256( "qumbra:hd:v1:account" ‖ node_master     ‖ a.to_le_bytes()   )   // a: u32
sk(a, role)     = Keccak256( "qumbra:hd:v1:role"    ‖ node_account(a) ‖ role.to_le_bytes() )   // role: u32
```

- **account** (u32): independent sub-wallets of one seed (Zcash ZIP-32 account
  precedent). Each account has its own `nk`/`fvk`/`ivk`/`div_seed`.
- **role** (u32): reserves the leaf level for future key roles; only
  `Role::Spend = 0` is defined at v1, and its output is the `sk` that feeds the
  existing circuit-bound hierarchy. The `nk`/`rkm`/`nf` split is NOT an HD level
  — it is the fixed hierarchy in `keys.rs`; the HD tree only mints the account's
  root `sk`.

Domain separation: distinct ASCII prefix per level ⇒ prefix-free; a `node_account`
can never be confused with an `sk` leaf or the master node, even at colliding
index bytes. (Wallet-only KDFs use ASCII prefixes à la `qlab-note`; the compact
bit-marker convention is reserved for the circuit-bound derivations.)

**Byte-for-byte lock.** A phrase is the wallet's only backup, so derivation may
never silently drift: `seed::tests::sk_derivation_is_byte_frozen` pins a golden
`sk`, `chain_matches_by_hand` re-derives the full chain independently, and the
end-to-end test proves a seed-derived key spends against `build_bucket`.

---

## 3. Mnemonic — BIP-39-*style*, two deliberate deviations (implemented)

24 words for the 256-bit seed, over the **canonical 2048-word BIP-39 English
wordlist** (embedded verbatim; gives the unique-4-prefix UX). Two deviations,
documented loudly in code:

1. **Checksum hash = Keccak-256, not SHA-256.** Keeps Qumbra on one hash family.
   *Consequence:* a Qumbra phrase is **NOT interchangeable with a BIP-39 wallet** —
   same words, different checksum. Visible marker: the all-zero-entropy phrase is
   `abandon ×23 + ahead` (BIP-39's is `abandon ×23 + art`).
2. **No PBKDF2 / passphrase stretching.** The phrase is a reversible encoding of
   the 256-bit entropy, which *is* the `MasterSeed` entropy. A passphrase-hardened
   variant (BIP-39 §"25th word") is a future option, not implemented.

Negatives locked: bad checksum, wrong word count, unknown word all rejected;
whitespace-tolerant decode; zero-entropy golden phrase pinned.

> **Open question for the design repo:** whether a PQ chain should adopt an
> English 2048-word list at all, or a wordlist-free / larger-alphabet backup
> scheme. This lab impl is deliberately conservative (reuse the familiar UX) but
> flags the tension M7 raised; the coordinator owns the call.

---

## 4. Diversifier management (implemented)

### Index → diversifier (pseudorandom, not the raw index)

```text
d(index) = Keccak256( "qumbra:wallet:div-index:v1" ‖ div_seed ‖ index.to_le_bytes() )[..16]
```

Using the raw index as `d` would leak sequence and count to anyone holding two
addresses — undoing #32's unlinkability. Hashing under `div_seed` makes each `d`
look independently random while staying deterministic and reproducible by any
`div_seed` holder. `div_seed` is the same value that seeds each diversified
ML-KEM keypair, so one secret drives both the `rkm`-side `d` and the encryption
key `dk_d`.

### Ledger — persistence & guards

`DiversifierLedger` tracks `index -> d` and a monotonic cursor, with a
byte-serializable format (`version ‖ next_index ‖ count ‖ [index ‖ d]*`). Two
guards, each with a negative test:

- **Reuse:** an index is allocated at most once.
- **Collision:** no two live indices bind the same `d` — binding two slots to one
  on-wire diversifier would make those addresses identical/linkable. (For derived
  `d` this is a ~2⁻⁶⁴ accident; the guard's real job is catching a *manual* `d`
  — e.g. a legacy/default diversifier — that clashes with a managed slot.)

### Rotation & capability boundary

- `Wallet`/`Fvk`: `diversifier_at_index`, `address_at_index`,
  `next_address(&mut ledger)` (the rotation primitive — fresh unlinkable address
  per call). Address generation needs `nk` (to derive `rkm(d)`), so it stays an
  **fvk capability** (issue #32).
- `Ivk`: `diversifier_at_index` only — a scanning-side, `div_seed`-only power
  (an exchange enumerating its own deposit slots). It confers **no**
  address-generation ability; the #32 type-level boundary is intact.

---

## 5. Proposed `wallet-interop-spec.md` section (draft for the coordinator)

> ### §5 Seed & key-derivation format (proposed)
>
> - **Master seed:** 256-bit entropy + 1-byte scheme version (`v1`).
> - **Backup phrase:** 24-word mnemonic, canonical BIP-39 English wordlist,
>   **Keccak-256 checksum** (NOT BIP-39-portable, by design), no passphrase at
>   v1. Version-parameterized decode.
> - **Derivation:** hardened-only Keccak chain, path `m / account / role`, domain
>   strings `qumbra:hd:v1:{master,account,role}`. `role = 0` (Spend) → the `sk`
>   that roots the tx-model §4 hierarchy. `account` (u32) = independent
>   sub-wallets.
> - **Diversifier:** `d(index) = Keccak256("qumbra:wallet:div-index:v1" ‖
>   div_seed ‖ index_le)[..16]`; wallets persist a ledger of live indices with
>   reuse + collision guards; address rotation = allocate next index.
> - **Version discipline:** any change to the chain, checksum hash, or diversifier
>   PRF is a `SEED_VERSION` bump (disjoint tree), never a silent edit.
>
> Open (for the design repo): O-seed-1 wordlist choice for a PQ chain
> (English-2048 vs alternative); O-seed-2 passphrase/25th-word hardening;
> O-seed-3 whether `account`/`role` widths and the role registry are frozen at
> genesis.

---

## 6. Interop / version note carried to the PR

The address `ADDRESS_VERSION` stays `1` (byte layout unchanged since #32). The
seed format introduces its own independent `SEED_VERSION = 1` and a ledger
`LEDGER_FORMAT_VERSION = 1`. None of this is consensus-visible; all three are
wallet-interop concerns for the coordinator to fold into the spec's version
registry when the seed section lands.
