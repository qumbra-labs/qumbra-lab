# Hash-based one-time spend authorization — research candidate

**Status: RESEARCH CANDIDATE, NOT ACCEPTED OR BUILT. Follow-up review found
unresolved P0 state-rollback/key-reuse, incomplete WOTS+ instantiation, and
dummy-slot rules. See
[`remote-proving-decision.md`](remote-proving-decision.md) §6. Any accepted
version would require a consensus change and T2 re-mint; every number marked
"est." remains unmeasured.**
Paired with
[`hash-ots-spend-authorization-zh.md`](hash-ots-spend-authorization-zh.md).

Written 2026-08-23 as the follow-up owed by
[`backend-assisted-proving-security.md`](backend-assisted-proving-security.md)
(PR #618) §8 row 3, "phone-held transaction-intent authorization". That
document established that a shared Qumbra prover is feasible only as a
*trusted* service, because `WitnessBundle` hands the worker the input `sk` and
nothing in the protocol stops the worker from proving and submitting a
different spend of the same notes. This document explores a protocol shape
intended to remove that trust. The property is **not established** until the
P0 blockers in the current decision record are closed.

---

## 1. Answer in one sentence

Candidate: commit a per-address Merkle root of hash-based one-time public keys
(WOTS+) into the note's recipient key material; spend by signing a canonical
*intent digest* with one of those one-time keys on the phone; let the circuit
prove only that the revealed one-time public key belongs to the spent note's
address; let the node verify the signature outside the STARK. The prover then
needs the **proving** material (`nk`, note openings, Merkle paths) but never
the **authorizing** material (`sk_auth`, one-time secrets).

## 2. Why this shape and not another

Two load-bearing facts from the current code drive the whole design:

1. **The circuit uses `sk` for exactly one permutation.** `ROLE_ANK` computes
   `nk = H(sk ‖ D_N)` (`crates/qlab-air/src/narrow.rs:1292,1430`). Every other
   role — `ROLE_NF`, `ROLE_ARKM`, `ROLE_ACM`, `ROLE_MERKLE` — consumes `nk`,
   not `sk`. The key-hierarchy header
   (`crates/qlab-wallet/src/keys.rs:1-29`) confirms it: `sk → nk → rkm`, and
   `nf = H(nk ‖ ρ)`.
2. **`rkm` is a single Keccak block with spare rate.** `rkm = H(nk ‖ D_R ‖ d)`
   occupies lanes 0..7 of a 17-lane rate (`keys.rs:57-66`); nine lanes are
   free. A 256-bit `ak_root` fits in the same block at lanes 7..10, so the
   in-circuit cost of binding it is **zero additional permutations** — only a
   re-layout of `ROLE_ARKM`'s absorb.

Every alternative was traced to the same dead end. Whatever links a spend
authorization key to a hidden note must be *proved*, and a proof needs the
linking secret as witness. Concretely:

| alternative | where it fails |
|---|---|
| per-note one-time key `sk_ots = H(sk_auth ‖ ρ)`, pk derived in circuit | the circuit needs `sk_auth` to derive pk → worker gets `sk_auth` |
| per-address authorization key revealed at spend | reveals the same key on every spend from that address → full linkability |
| Sapling-style re-randomized EC key (`rk = ak + αG`) | point addition inside a Keccak-only AIR is prohibitively expensive; also not PQ |
| split STARK: phone proves the key chain, worker proves membership, linked by a hiding commitment | works, but a second FRI proof has a ~100 KB floor → ~230 KB transactions, same class as b4 (which needs no service at all) |
| MPC / encrypted proving | research; rejected by PR #618 on the same evidence |
| keep the monolithic-STARK rule and pick a trusted operator | the status quo of PR #618; theft is bounded by policy, not by the protocol |

The only construction where the circuit can bind a *fresh, unlinkable* public
key to a hidden note **without** holding the authorizing secret is the
XMSS/SPHINCS pattern: a tree of one-time public keys, whose root is committed
in the note, and whose membership is a plain hash-path proof. That is what
this document specifies.

## 2a. This deviates from a binding design decision — say so

`CLAUDE.md`'s one-paragraph definition of Qumbra, and
`qumbra-design/transaction-model-and-anonymity-set.md` behind it, say **"one
monolithic STARK per transaction (spend authorization inside the proof — no
per-spend signatures)"**. This design adds two per-spend signatures. That is
not an oversight; it is the cost of the property. The original decision was
taken for a wallet that proves its own transactions, where a signature is
redundant with the proof. The phone-self-proving reopening established that
most phones will not prove their own transactions, and PR #618 established
that a delegated prover holding the proof witness holds spend authority. A
spend authorization *outside* the proof is precisely the thing that makes the
proof delegable.

If §11.1 is accepted, the design repo owes a dated correction to the
transaction-model doc and the one-paragraph definition, the same way
`performance-budget` §2 retracted the "layered hedge". Until that correction
lands, this document is a proposal against the binding spec, not part of it.

## 3. Key hierarchy

```
sk_root                                   256-bit, phone only
├── sk_spend = H(sk_root ‖ D_SPEND)       256-bit, today's `sk`
│   └── nk   = H(sk_spend ‖ D_N)          proving key; MAY be handed to a prover
└── sk_auth  = H(sk_root ‖ D_AUTH)        256-bit, NEVER leaves the phone

per address d (128-bit diversifier, unchanged):
    for i in 0 .. 2^DEPTH:
        seed_i  = H(sk_auth ‖ D_OTS ‖ d ‖ i)
        sk_ots_i = WOTS+.keygen(seed_i)
        leaf_i  = H(WOTS+.pk(sk_ots_i))                 256-bit
    ak_root(d) = MerkleRoot_DEPTH(leaf_0 .. leaf_{2^DEPTH - 1})

    rkm(d) = H(nk ‖ D_R ‖ d ‖ ak_root(d))               single Keccak block
```

`D_SPEND`, `D_AUTH`, `D_OTS` are wallet-side ASCII domain strings in the
`address`/`viewing` style (`keys.rs:15-17`). `D_N` and `D_R` keep their
in-circuit marker-bit form.

**What a prover receives** (the new `WitnessBundle v2`): per input `nk`,
`value`, `ρ`, `rseed`, `d`, `ak_root`, the Merkle witness, plus `pk_ots_i`
and its `DEPTH`-deep path to `ak_root`; both outputs as today; the approved
`intent` and the two WOTS+ signatures. **Not** `sk_root`, `sk_spend`,
`sk_auth`, or any `sk_ots`.

**What `nk` gives the prover.** `nk` is full-viewing-class material
(`keys.rs:25-28`): it derives every `rkm(d)` and every `nf` for a known `ρ`.
It does *not* decrypt incoming notes (that is the ML-KEM incoming viewing key
in `address`/`viewing`), so a prover holding only `nk` cannot discover the
wallet's other notes from public chain data. This is the same boundary Zcash
Sapling draws between the *proof authorizing key* `(ak, nsk)` given to a
delegated prover and the *spend authorizing key* `ask` that is not. Disclose
it; do not pretend it away.

## 4. The intent digest

```
intent = SHA3-256(
    "qumbra-intent-v1"      ‖
    network_id              ‖ genesis_hash           ‖
    anchor                  ‖
    nf_1 ‖ nf_2             ‖
    cm_1 ‖ cm_2             ‖
    bucket ‖ fee            ‖
    SHA3-256(discovery)     ‖ SHA3-256(rider)        ‖
    pk_ots_1 ‖ pk_ots_2
)
```

Every field is already part of, or derivable from, the transaction's public
surface (`TxPublic`, `TxEntry.discovery`, `TxEntry.rider` —
`crates/qlab-devnet/src/body.rs:166-230`) plus the two new public values.
The node recomputes `intent` from the received transaction and verifies both
signatures against it. A prover that changes **any** of anchor, nullifiers,
output commitments, fee, discovery bytes, rider, or the revealed one-time
keys invalidates both signatures. Including `pk_ots_{1,2}` closes the
"swap in a different leaf from the same tree" substitution.

Replay is excluded by construction: `nf_1`, `nf_2` are in the digest, and a
nullifier lands at most once.

## 5. Signature scheme

WOTS+ with `n = 32` bytes, `w = 16`, Keccak-based chaining (same permutation
the circuit already uses; the node verifies it natively in software):

- `len_1 = 64`, `len_2 = 3`, `len = 67` chains of up to 15 steps;
- signature: 67 × 32 = **2,144 bytes**; public key after compression:
  32 bytes;
- one signature per input → 4,288 bytes per transaction;
- verification: ≤ 67 × 15 ≈ 1,005 Keccak-f calls per signature, ~2 k per
  transaction — microseconds on a node, negligible beside STARK verification.

Why WOTS+ and not XMSS/SPHINCS+ as a whole: the tree part of XMSS is exactly
what the *circuit* proves (§6), so the node only ever sees the leaf scheme.
Why not ML-DSA/Falcon as the leaf: a lattice public key could sit in the
tree just as well, but a note is spent exactly once, so a one-time scheme
loses nothing; WOTS+ keeps the leaf at 32 bytes, the signature at ~2 KB
versus ML-DSA-44's 1.3 KB key + 2.4 KB signature, and reuses the Keccak
primitive the node and circuit already trust.

**One-time discipline.** Each `leaf_i` MUST be used at most once. The wallet
persists a per-address "next unused index" and refuses to sign with a
consumed index; an index is considered consumed the moment a signature is
produced, not when the transaction lands. Losing that counter (device
restore from an old backup) is recoverable by scanning the chain for the
address's revealed `pk_ots` values — they are public values in `TxPublic`.

## 6. Circuit changes

Current program: 84 permutation slots at 2^18 rows
(`narrow.rs:1220-1224`, `BUCKET_PERMS`), 1.33 slots spare.

| change | slots | note |
|---|---:|---|
| drop `ROLE_ANK` (`nk` becomes the witness) | −2 | `sk` no longer enters the circuit at all |
| `ROLE_ARKM` absorbs `ak_root` at lanes 7..10 | 0 | same block; pad moves from lane 7 to lane 11 |
| new `ROLE_OTS_LEAF`: `leaf = H(pk_ots)` per input, `pk_ots` bound to `PV_PK1/PV_PK2` by the boundary bank | +2 | same shape as `ROLE_ACM` binding |
| new `ROLE_OTS_MERKLE` × `DEPTH` per input, terminating in a boundary check against the `ak_root` lanes of the preceding `ROLE_ARKM` witness | +2·DEPTH | identical arithmetic to `ROLE_MERKLE`; separate role code for the same reason `ROLE_ARHO` has one (`narrow.rs:228-236`) |

With `DEPTH = 16`: 84 − 2 + 2 + 32 = **116 slots → 2^19 rows**
(116 × 3072 = 356,352 ≤ 524,288; 54 slots spare). With `DEPTH = 12`: 108
slots, also 2^19. There is no `DEPTH` that stays inside 2^18, so the row
doubling is the real cost and `DEPTH = 16` (65,536 spends per address) is
chosen because the marginal slots are free once 2^19 is paid.

**This is the point PR #618 did not reach:** once proving leaves the phone,
the circuit's memory budget is a server's, not a handset's. Doubling the
trace is acceptable on a worker host; it was never acceptable on an iPhone.

**Domain-separation review required.** `ROLE_ARHO`'s comment
(`narrow.rs:228-236`) records a real collision that a missing marker would
have opened. Moving `ROLE_ARKM`'s pad and adding two roles MUST be reviewed
against every other absorb shape with the same discipline; the regression
locks in `qlab-note` and `qlab-wallet` that pin host derivations to
`build_bucket` outputs must be re-derived, not edited to pass.

Public values: `PV_LEN` 84 → 116 (two 32-byte `pk_ots`, 16 chunks each),
layout appended after `PV_FEE`.

## 7. Transaction wire and node rules

`TxEntry` gains `auth: [WotsSignature; 2]` (2 × 2,144 bytes) and `TxPublic`
gains `pk_ots: [Hash32; 2]`. Encoding follows `encode_tx`'s existing
discipline (`crates/qlab-p2p/src/codec.rs:398`): fixed-width, canonical,
reject-unknown.

Node acceptance, in order, before STARK verification:

1. decode canonically; reject non-canonical bytes as today;
2. recompute `intent` (§4) from the decoded public surface;
3. verify `auth[0]` under `pk_ots[0]` and `auth[1]` under `pk_ots[1]`;
4. reject if either fails — **before** spending verifier time on the proof;
5. verify the STARK against the extended public values.

Estimated wire (est.): proof at 2^19 rows grows by one FRI layer per query
path, ≈ +6–8 % → ~158 KB; plus 4,288 bytes of signatures and 64 bytes of
keys → **≈ 163 KB per transaction**, against 148,625 bytes today and ~236 KB
under b4. To be replaced by a measurement before any size claim is repeated.

## 8. Wallet changes

- Address creation generates the `ak_root(d)` tree: 65,536 WOTS+ keygens ≈
  65,536 × 67 × 15 ≈ 66 M Keccak-f (est. 2–6 s on a modern phone, once per
  address; `DEPTH = 12` is ~0.3 s if that matters for UX). Cache the tree;
  regenerate deterministically from `sk_auth` on restore.
- `Address` layout is unchanged: `rkm` was already a 32-byte hash
  (`crates/qlab-wallet/src/address.rs:82-93`, 1,233 bytes raw).
- Spend flow on the phone: select → build → compute `intent` → sign twice →
  emit `WitnessBundle v2`. The signing step is the only new user-visible
  latency and is sub-millisecond.
- Per-address index counter with the one-time discipline of §5; UI must
  surface "address exhausted, rotate" long before `2^DEPTH`.
- `SpendingKey::spend_input` (`keys.rs:128`) splits into
  `ProvingKey::prove_input` (emits `nk`-based `TxInput`) and
  `AuthKey::sign_intent`.

## 9. What a malicious prover can and cannot do

| action | before (PR #618 trusted model) | after |
|---|---|---|
| prove the approved transaction | yes | yes |
| change outputs / fee / discovery / rider | yes, and submit it | signatures fail; node rejects |
| submit a conflicting spend of the same notes | yes (nullifier race) | cannot produce a valid one |
| learn which notes were spent, amounts, recipients | yes | yes — **unchanged** |
| derive the wallet's other addresses | yes (`sk`) | yes (`nk`) — **unchanged in effect**, narrower in material |
| decrypt the wallet's incoming notes | no | no |
| refuse, delay, or selectively censor | yes | yes |

The theft row is the one this design exists for. The privacy rows are the
separate "cannot see" gate that PR #618 §3/§6 folded into theft; they remain
open and are addressed by confidential workers, multi-operator proving, or
both — none of which this document decides.

## 10. Consequences for the open decision

| choice | every phone sends | prover cannot redirect | tx size | T2 | enduring dependency |
|---|---|---|---:|---|---|
| b4 local prove + fallback | fallback on low-memory devices | n/a (no prover) | ~236 KB | re-mint | fallback prover |
| trusted Qumbra backend (PR #618) | yes | **no** | 148 KB | none | trusted, single operator |
| split STARK | yes | yes | ~230 KB (est.) | re-mint | a service |
| **hash-OTS authorization (this doc)** | yes | **intended yes; not established** | ~163 KB (est.) | re-mint | *any* prover, decentralizable |

Both b4 and an accepted version of this shape would pay one T2 re-mint. b4
buys phone independence at the cost of the largest transactions and a fallback
that is still a trusted prover. If the P0 blockers are solved, this shape is
intended to buy resistance to prover redirection, smaller transactions than b4,
zero phone memory pressure, and the option to let community nodes, pools, or a
market prove for phones. The current construction does not yet establish those
properties.

## 11. Decisions owed

1. Do not accept this construction until the P0 blockers in
   [`remote-proving-decision.md`](remote-proving-decision.md) §6 are closed;
   compare it with a stateless ML-DSA-leaf construction before selecting a
   primitive.
2. `DEPTH` (12 vs 16) and WOTS+ `w` (16 vs 256: 256 halves signature size to
   ~1.1 KB but costs ~17× verification hashes).
3. Whether `pk_ots` enters `intent` as specified or is bound by the circuit
   alone (this doc says both; belt and braces against leaf substitution).
4. Whether `nk` may be given to a non-Qumbra prover, or whether a narrower
   per-transaction proving material is worth a further hierarchy level.
5. Re-mint sequencing with any other pending T2 circuit change.

## 12. Evidence owed before implementation

1. Prove the modified circuit once at 2^19 rows on the intended worker class:
   peak RSS, wall time, proof bytes. This replaces every "est." above.
2. A collision/domain review of all absorb shapes after the `ROLE_ARKM`
   re-layout and two new roles, recorded the way `ROLE_ARHO`'s was.
3. WOTS+ reference vectors and a node verifier benchmark.
4. An end-to-end adversarial test: a prover that alters each field of §4 in
   turn must produce a transaction the node rejects at step 3 or 5.
5. Address-creation time on the slowest supported phone at `DEPTH = 16`.

## 13. Scope at this handoff

- Current ruling: this construction is not accepted; the paired current
  decision record is authoritative.
- Nothing is implemented. `CONSENSUS_CFG`, the circuit, the wire, and the
  wallet are untouched.
- This document does not supersede the phone handoff or authorize a protocol
  direction. Its findings feed
  [`remote-proving-decision.md`](remote-proving-decision.md) §6.
