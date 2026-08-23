# Remote proving — Phase 1 authorization spike

**Status: RESEARCH SPIKE, 2026-08-23. NOT A PRIMITIVE SELECTION OR
IMPLEMENTATION APPROVAL. Nothing in this change is reachable from a shipping
wallet, node, transaction codec, AIR, genesis, or service.** Tracks
[lab issue #630](https://github.com/qumbra-labs/qumbra-lab/issues/630) and is
paired with
[`remote-proving-authorization-spike-zh.md`](remote-proving-authorization-spike-zh.md).

The governing ruling remains
[`remote-proving-candidate-ruling.md`](remote-proving-candidate-ruling.md):
consensus-bound phone-held authorization (Candidate A) is mandatory for a
real-value shared prover; a confidential worker (Candidate B) is optional
privacy hardening.

---

## 1. Result and recommendation

The spike implements one complete-intent surface and compares three leaf
rows under the same fixed two-input shape:

| row | state property | exact two-slot auth section | result |
|---|---|---:|---|
| FIPS 204 ML-DSA-44 | signature keys are safely reusable; rotation non-reuse is a privacy rule, not a forgery rule | 7,544 B | **only primitive recommended to advance, in a rotation tree** |
| RFC 8391 `WOTSP-SHA2_256`, stateful index | an OTS index must never be reused | 4,432 B | **blocked:** a valid old backup and two devices can reuse an index |
| RFC 8391 `WOTSP-SHA2_256`, random index | no journal, but an index collision is catastrophic | 4,432 B | **comparator only:** practical collision bounds are unacceptable |

The primitive and commitment-shape decision is now explicit: advance a
**rotation tree of ML-DSA leaves** and do not advance depth 0. A depth-0
verifying key is a public, stable sender-address fingerprint. Because slot 0 is
always real while a dummy slot-1 key is ephemeral, history also turns reusable
real keys into a delayed distinguisher between one-real and two-real spends.
That is a privacy failure even though ML-DSA unforgeability survives key reuse.

The rotation tree adds two Merkle-path permutations per depth, makes address
construction `O(2^D)`, and moves every practical depth to 2^19 rows. The spike
implements a private deterministic shuffle without replacement so public leaf
indices are neither sequential ordinals nor independent draws that collide.
This is a **public/on-chain unlinkability** improvement only. An ordinary
Candidate A prover sees each private authorization path, can recover the stable
per-address `auth_root`, and can additionally join the wallet if the future
envelope retains `nk`.

Production persistence, restore, and multi-device allocation remain gates. The
final fixed depth is not guessed here: D12 through D16 require mobile
measurement before the binding-design correction, and the selected `D` must be
one network-wide protocol constant rather than a per-wallet choice. Depth 0
remains only a valueless mechanics comparator. This spike makes no shape
consensus.

## 2. What was implemented

The research-only [`qlab-remote-auth`](../crates/qlab-remote-auth/) crate
contains:

- scheme-fixed 372-byte ML-DSA and 436-byte WOTS+ versioned complete-intent
  preimages;
- deterministic FIPS 204 ML-DSA-44 vectors using the workspace's pinned
  `ml-dsa = 0.1.1` implementation;
- RFC 8391 `WOTSP-SHA2_256` F/H/PRF, addresses, base-w checksum, chains and
  L-tree compression, including the RFC authors' HRS16 key expansion;
- a strict, no-length-field two-slot authorization-section codec;
- a domain-, level- and direction-bound outer Keccak tree with no public
  per-address ML-DSA tag;
- a private ML-DSA leaf permutation without replacement;
- an executable hidden-dummy acceptance model that requires both slots to
  exist before phone approval;
- a checksummed reserve-before-export WOTS+ journal plus executable old-backup
  and two-device failure models;
- exact birthday-bound and candidate AIR geometry reports; and
- byte-exact fixtures plus an integration test that regenerates them.

The command surface is:

```console
cargo run -p qlab-remote-auth --bin qlab-remote-auth-spike -- report
cargo run -p qlab-remote-auth --bin qlab-remote-auth-spike -- vector
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- measure --iterations 100
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- address mldsa 12
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- address wots 12
```

The last three are measurement instruments, not published mobile or production
benchmarks. This record does not convert an unrun command into evidence.

## 3. Complete intent and canonical codec

The spike signs `Keccak256(intent_preimage)`, where the fixed-width preimage is:

```text
"qumbra:remote-auth:intent:v1"
|| version_le16
|| genesis_format_le32 || genesis_hash
|| anchor
|| nf[0] || nf[1]
|| cm[0] || cm[1]
|| bucket_u8 || fee_le64
|| Keccak256(discovery_bytes)
|| Keccak256(rider_bytes)
|| scheme_u8
|| auth_descriptor[0] || auth_descriptor[1]
```

The descriptor is scheme-fixed:

- ML-DSA uses 36 bytes: `leaf_index_le32 || leaf[32]`. It deliberately carries
  no public per-address context.
- WOTS+ uses 68 bytes: `public_seed[32] || leaf_index_le32 || leaf[32]`; the RFC
  8391 public seed is required for native verification.

The complete preimage is therefore 372 bytes for ML-DSA and 436 bytes for
WOTS+. The scheme tag separates stateless ML-DSA, stateful WOTS+, and
random-index WOTS+ safety contracts even though the two WOTS+ rows share a
primitive. Changing any semantic field changes the digest. Adding a future
semantic field requires a new version; it cannot be appended where an old
signer would ignore it.

The spike authorization section begins with fixed magic `QRA1`, version,
scheme, and slot count. The scheme fixes every later width; decode rejects an
unknown scheme, wrong slot count, truncation, wrong payload width, or trailing
byte.

| component | ML-DSA-44 | WOTS+ |
|---|---:|---:|
| header | 8 | 8 |
| descriptor, two slots | 72 | 136 |
| verifying key per slot | 1,312 | 0; recovered 32-byte leaf is in the descriptor |
| signature per slot | 2,420 | 2,144 |
| **two-slot total** | **7,544** | **4,432** |

The exact delta is 3,112 bytes. These are spike-section bytes, not a production
transaction-wire decision.

The binding wire specification must also decide whether transaction identity
commits to the authorization section and then define body/P2P encoding, mempool
deduplication, wallet history joins, and replay behavior consistently. This
spike deliberately does not make that transaction-ID decision.

A future node's required order is: strict decode; reconstruct the complete
intent from the actual transaction; require descriptor equality; verify both
phone authorizations; only then spend work on STARK verification. The crate
models that order but is deliberately not connected to the current node.

## 4. Note binding and candidate AIR arithmetic

One candidate note binding extends the existing `ROLE_ARKM` absorb:

```text
rkm = Keccak256(nk || D_R || d || auth_root || pad10*1)
```

In the current lane spelling this occupies `nk` lanes 0..3, domain lane 4,
diversifier lanes 5..6, authorization root lanes 7..10, pad start lane 11, and
the final rate bit in lane 16. It therefore fits one 17-lane Keccak rate block
and leaves the former context lanes unused. This is spike arithmetic; the
binding design spec must still fix the exact production field/byte encoding
and domain review.

The node derives an ML-DSA leaf as
`Keccak256(leaf_domain || leaf_index_le32 || verifying_key)`. Outer parents bind
the node domain, level, left child, and right child, but no public address tag.
Address separation comes from a unique private per-address derivation master
and the resulting hidden `auth_root`, not a repeated wire value. For WOTS+,
native verification recovers the RFC L-tree leaf using its descriptor's public
seed. A future AIR need only fold the public leaf through the authorization
path and bind its root through the same hidden note material. It need not
verify either signature inside the STARK.

The authorization path and `auth_root` are STARK-private witness values: they
must never enter the authorization section, transaction body, or STARK public
values. The ordinary worker nevertheless sees them while proving and can use
the stable `auth_root` to cluster jobs for one address. Publishing the path
would let every chain observer compute the same cluster and would completely
undo the public unlinkability gained by removing `tree_context`.

Starting from 84 current permutation slots, dropping the two `ROLE_ANK` slots
and adding two depth-`D` paths gives `82 + 2D` slots:

| depth | meaning | slots | active rows (`slots × 3,072`) | padded trace |
|---:|---|---:|---:|---:|
| 0 | reusable ML-DSA leaf, no path | 82 | 251,904 | 2^18 |
| 1 | smallest non-empty tree | 84 | 258,048 | 2^18 |
| 12 | 4,096 leaves | 106 | 325,632 | 2^19 |
| 16 | 65,536 leaves | 114 | 350,208 | 2^19 |
| 20 | 1,048,576 leaves | 122 | 374,784 | 2^19 |
| 31 | largest index range modeled by the spike | 144 | 442,368 | 2^19 |

Every depth 0..31 is emitted by `report`. No AIR, selector, public-value bank,
quotient-degree, proof-size, RSS, or proving-time change has been implemented
or measured.

## 5. Hidden dummy rule

The current privacy shape keeps slot 0 real and hides whether slot 1 is a real
note or a zero-value off-tree dummy. The candidate rule preserves that shape:

1. both slots always have a valid authorization signature, descriptor, path,
   and root-to-note binding;
2. slot 0 always proves note-tree membership;
3. for two real inputs, slot 1 also proves note-tree membership;
4. for one real input, slot 1 instead proves the existing hidden zero-value
   dummy condition; and
5. no public dummy flag is introduced.

The phone must create the dummy slot's ephemeral key, descriptor, random path
material, and hidden root before it constructs and signs the common intent. It
then signs the same complete intent with both slot keys and only afterwards
uploads the proving envelope. The worker may not create or replace dummy
authorization material: both descriptors are part of the digest, and material
created after phone signing was never approved. The random dummy path need not
build a full address tree because its sibling nodes can be generated directly;
its public descriptor remains identically shaped. Its `leaf_index` must also be
sampled uniformly from the same network-fixed `[0, 2^D)` range as a real leaf;
shape without the same distribution would remain a public one-real-input
distinguisher. Removing slot 0's always-real invariant would still invalidate
this rule.

## 6. WOTS+ exactness and the state failure

The comparator uses the standardized RFC 8391 `WOTSP-SHA2_256` shape:
`n = 32`, `w = 16`, `len_1 = 64`, `len_2 = 3`, `len = 67`, and a 2,144-byte
signature. One leaf generation performs 67 private-element expansions, 1,005
chain steps, and 66 L-tree nodes. With the RFC SHA-256 constructions that is
exactly 3,346 SHA-256 calls.

The fixture's full signature and 32-byte leaf were compared byte for byte with
the RFC authors' reference implementation at commit
`171ccbd26f098542a67eb5d2b128281c80bd71a6`; see
[`fixtures/README.md`](../crates/qlab-remote-auth/fixtures/README.md) and
[`authorization-v1.txt`](../crates/qlab-remote-auth/fixtures/authorization-v1.txt).

The 42-byte journal persists the increment before exporting a reserved index,
and cancellation burns that index. This closes a crash window inside one
current state file. It cannot distinguish a valid old backup from current
state, and two devices restored from the same state both reserve index zero.
Both failure states pass the journal checksum. The executable model therefore
confirms, rather than resolves, the P0 blocker described by
[NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) and
[RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html).

## 7. Random-index collision evidence

For `q` uses of one depth-`D` tree, the spike uses the required ideal-uniform
union bound `min(1, q(q-1)/2^(D+1))`. For `T` separately keyed address trees,
the multi-target bound is `min(1, T × per_tree_bound)`; equal indices in two
different trees are harmless, while any within-tree reuse is catastrophic.

Selected rows from the executable 1..31 report are:

| D | uses/address | one target | 1,000 targets |
|---:|---:|---:|---:|
| 12 | 10 | 1.099% | 100% cap |
| 16 | 100 | 7.553% | 100% cap |
| 20 | 100 | 0.4721% | 100% cap |
| 24 | 100 | 0.02950% | 29.50% |
| 31 | 1,000 | 0.02326% | 23.26% |

Even the depth-31 multi-target row is not an acceptable funds-safety basis,
and constructing its `2^31` leaves is not a product option. A random leaf from
one WOTS+ tree is not SLH-DSA and does not inherit FIPS 205's FORS/hypertree
security argument.

## 8. Wire and proof-size consequence

Today's 148,625-byte value is the serialized **STARK proof**, not the complete
transaction. Adding only the spike authorization section produces these lower
bounds before any new public values or proof growth:

| row | current proof | auth section | proof + auth only |
|---|---:|---:|---:|
| ML-DSA-44 | 148,625 | 7,544 | 156,169 B |
| WOTS+ | 148,625 | 4,432 | 153,057 B |

These sums are not predictions of the future proof or full transaction. They
show that an all-in transport interpretation of the ≤150 KB target is already
exceeded. The existing regression target is proof-only, and the future proof
must be remeasured. Depth 0 may retain 2^18 height but fails the selected
privacy shape; practical trees move to 2^19. Proof bytes, full transaction
bytes, prover RSS/time, and node verification time remain open gates.

## 9. Mobile lifecycle and privacy

For ML-DSA, a phone-only wallet master derives a unique private master for each
receiving address, which in turn derives the tree's leaf keys. The candidate
selector deterministically shuffles all indices from a private address seed
and consumes them without replacement. Once measurement selects `D`, every
wallet on that network uses the same value.

Production state must be crash-safe and reserve an index against one intent
digest before any authorization bytes leave the phone. A retry of that same
job reuses the exact signed envelope; a new digest never reuses a reserved or
exported leaf. Before export, abandoned local preparation may release its
reservation. After export, the leaf is permanently consumed even if the prover
fails, withholds the result, or the transaction never lands. Exhaustion refuses
the spend rather than wrapping. Service failures must not silently advance to
a new leaf or expose a distinct "leaves remaining" oracle.

Restore and multi-device allocation are not solved by the shuffle. An on-chain
scan can recover landed descriptors but cannot discover an authorization that
left the phone and never landed. Production therefore needs rollback-resistant,
backed-up reservation state or a specified safe tree migration; if the wallet
cannot prove that state current after restore, it must refuse remote spending
from the ambiguous tree. Concurrent devices need coordinated leases or
cryptographically disjoint allocations. Reuse is a privacy failure, not the
WOTS+ forgery failure. Building or caching `2^D` public leaves remains an
unmeasured address-creation cost.

Stateful WOTS+ requires rollback-proof, multi-device-coordinated state that the
current wallet product does not provide. Random-index WOTS+ removes the journal
but replaces it with quantified catastrophic collision risk. Neither advances.

Candidate A does not hide the witness from an ordinary remote prover. This
crate does not serialize a proving envelope, so it cannot yet prove which live
`WitnessBundle` fields have been removed. The next specification must name at
least:

- authorization signing seeds: forbidden from the envelope;
- current `TxInput.sk`: forbidden from a production envelope and must be
  removed before Phase 2 can serialize one; this spike does not implement that
  removal;
- `nk`: if present, it is account-global spend-viewing material, so one job is
  a wallet-level disclosure to that operator and later jobs can link different
  diversified addresses;
- authorization Merkle paths and `auth_root`: private STARK witness only, never
  transaction or public-value fields, but necessarily visible to an ordinary
  Candidate A prover and stable enough to cluster one address;
- `rho`, `rseed`, `d`, note Merkle paths, recipient/discovery/rider bytes, amount,
  change, and internal dummy state: inherited from today's bundle until each is
  explicitly removed or narrowed; intent hashes prevent rewriting, not
  observation; and
- IP, device identity, timing, queue metadata, and the resulting chain event:
  still visible outside a confidential worker.

Depth 0 would additionally publish a stable verifying-key cluster and the
delayed dummy-arity distinguisher described in §1, so it is not a production
option. A rotation tree removes that repeated public address tag when leaves
are not reused, but it does not remove service metadata or A-only witness
visibility. Candidate B may reduce worker payload visibility; it does not
alter the authorization ruling.

The phone boundary is mandatory in both directions. Before upload, the wallet
must reconstruct the complete intent, verify both locally created slots, and
assert that authorization secrets, `TxInput.sk`, wallet seeds, `div_seed`, and
incoming-viewing/decryption keys are absent. After proving, it must decode the
returned artifact, reconstruct its intent, and require exact equality with the
approved intent before submission. Direct worker submission is not the default:
it adds a race and gives the node a worker-origin correlation signal.

## 10. Verification and remaining gates

Completed locally:

```console
cargo fmt -p qlab-remote-auth
cargo check -p qlab-remote-auth --all-targets --locked
cargo clippy -p qlab-remote-auth --all-targets --locked -- -D warnings
cargo run -q -p qlab-remote-auth --bin qlab-remote-auth-spike -- vector
```

The regenerated vector stdout is byte-identical to the committed fixture. The
RFC reference signature and leaf comparison was byte-identical. Repository
policy forbids agent sessions from running local `cargo test`, so the written
unit/integration tests await CI. No mobile or pinned-rig performance number is
claimed by this document.

Independent post-remediation reviews at `5e679ad` by
[Claude Code](https://github.com/qumbra-labs/qumbra-lab/pull/632#issuecomment-5386685515)
for protocol/cryptographic seams and
[Grok](https://github.com/qumbra-labs/qumbra-lab/pull/632#issuecomment-5386698823)
for the proving-envelope/privacy boundary both returned **APPROVE WITH
NON-BLOCKING FOLLOW-UPS** and no blocker. This revision incorporates their
shared privacy/lifecycle clarifications; the new head requires delta
confirmation.

The shape decision is resolved: ML-DSA rotation advances; depth 0 and both
WOTS+ rows do not. Phase 2 remains blocked on D12..D16 mobile measurements, a
binding production allocation/restore rule, and accepted delta review. Only
then may the result be translated into a dated EN/ZH binding-design correction.
AIR, transaction wire/identity, node verification, activation, genesis/re-mint,
wallet integration, and the prover service remain later, separately authorized
phases.
