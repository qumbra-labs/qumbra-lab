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
| FIPS 204 ML-DSA-44 | signature keys are safely reusable; no monotonic counter | 7,608 B | **only row recommended to advance** |
| RFC 8391 `WOTSP-SHA2_256`, stateful index | an OTS index must never be reused | 4,432 B | **blocked:** a valid old backup and two devices can reuse an index |
| RFC 8391 `WOTSP-SHA2_256`, random index | no journal, but an index collision is catastrophic | 4,432 B | **comparator only:** practical collision bounds are unacceptable |

The recommended next design question is therefore not “ML-DSA or WOTS+.” It
is which ML-DSA commitment shape Qumbra accepts:

- **depth 0 / one reusable leaf per receiving address** is the smallest
  security baseline. `auth_root == H(pk)`, there is no authorization path, and
  the candidate AIR remains at 2^18 rows. Reuse does not enable forgery, but it
  links spends made with the same authorization key;
- **a rotation tree of ML-DSA leaves** reduces that linkage, but adds two
  Merkle-path permutations per depth, makes address construction `O(2^D)`, and
  moves every practical depth to 2^19 rows.

Larry must choose that privacy/complexity tradeoff after mobile measurements
and independent review. The spike makes neither shape consensus.

## 2. What was implemented

The research-only [`qlab-remote-auth`](../crates/qlab-remote-auth/) crate
contains:

- a 436-byte, versioned, fixed-width complete-intent preimage;
- deterministic FIPS 204 ML-DSA-44 vectors using the workspace's pinned
  `ml-dsa = 0.1.1` implementation;
- RFC 8391 `WOTSP-SHA2_256` F/H/PRF, addresses, base-w checksum, chains and
  L-tree compression, including the RFC authors' HRS16 key expansion;
- a strict, no-length-field two-slot authorization-section codec;
- a domain-, context-, level- and direction-bound outer Keccak tree;
- an executable hidden-dummy acceptance model;
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

Each 68-byte descriptor is `tree_context[32] || leaf_index_le32 || leaf[32]`.
The scheme tag separates stateless ML-DSA, stateful WOTS+, and random-index
WOTS+ safety contracts even though the two WOTS+ rows share a primitive.
Changing any semantic field changes the digest. Adding a future semantic field
requires a new version; it cannot be appended where an old signer would ignore
it.

The spike authorization section begins with fixed magic `QRA1`, version,
scheme, and slot count. The scheme fixes every later width; decode rejects an
unknown scheme, wrong slot count, truncation, wrong payload width, or trailing
byte.

| component | ML-DSA-44 | WOTS+ |
|---|---:|---:|
| header | 8 | 8 |
| descriptor, two slots | 136 | 136 |
| verifying key per slot | 1,312 | 0; recovered 32-byte leaf is in the descriptor |
| signature per slot | 2,420 | 2,144 |
| **two-slot total** | **7,608** | **4,432** |

The exact delta is 3,176 bytes, not the earlier 3,112-byte paper estimate.
These are spike-section bytes, not a production transaction-wire decision.

A future node's required order is: strict decode; reconstruct the complete
intent from the actual transaction; require descriptor equality; verify both
phone authorizations; only then spend work on STARK verification. The crate
models that order but is deliberately not connected to the current node.

## 4. Note binding and candidate AIR arithmetic

One candidate note binding extends the existing `ROLE_ARKM` absorb:

```text
rkm = Keccak256(nk || D_R || d || auth_root || tree_context || pad10*1)
```

In the current lane spelling this occupies `nk` lanes 0..3, domain lane 4,
diversifier lanes 5..6, authorization root lanes 7..10, context lanes 11..14,
pad start lane 15, and the final rate bit in lane 16. It therefore fits one
17-lane Keccak rate block. This is spike arithmetic; the binding design spec
must still fix the exact production field/byte encoding and domain review.

The node derives an ML-DSA leaf as a domain-separated hash of tree context,
leaf index, and the complete 1,312-byte public key. For WOTS+, native
verification recovers the RFC L-tree leaf. A future AIR need only fold the
public leaf through the authorization path and bind its root/context through
the same hidden note material. It need not verify either signature inside the
STARK.

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

The worker may create the dummy slot's ephemeral authorization material. That
does not grant redirection authority because the non-dummy slot 0 phone key is
note-bound and signs the complete common intent, including both outputs and
both authorization descriptors. Removing slot 0's always-real invariant would
invalidate this rule.

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
| ML-DSA-44 | 148,625 | 7,608 | 156,233 B |
| WOTS+ | 148,625 | 4,432 | 153,057 B |

These sums are not predictions of the future proof or full transaction. They
show that an all-in transport interpretation of the ≤150 KB target is already
exceeded. The existing regression target is proof-only, and the future proof
must be remeasured: depth 0 may retain 2^18 height but changes the AIR/public
surface; practical trees move to 2^19. Proof bytes, full transaction bytes,
prover RSS/time, and node verification time remain open gates.

## 9. Mobile lifecycle and privacy

For ML-DSA, a phone-only master authorization seed can deterministically
derive address/leaf keys. Depth 0 restores from the seed with no monotonic
journal. Multiple legitimate devices holding the same seed do not create the
WOTS+ forgery failure, although duplicate signing, key compromise, and spend
linkability still require product handling. A rotation tree also restores from
the seed, but building or caching `2^D` public leaves is an unmeasured address
creation cost.

Stateful WOTS+ requires rollback-proof, multi-device-coordinated state that the
current wallet product does not provide. Random-index WOTS+ removes the journal
but replaces it with quantified catastrophic collision risk. Neither advances.

Candidate A does not hide the witness from an ordinary remote prover. The
service can still observe selected notes, values, recipient/discovery material,
privacy-sensitive `nk`, IP, device identity, timing, and the resulting chain
event. ML-DSA depth 0 additionally exposes a reusable public key/leaf that can
link spends. A rotation tree reduces that particular link but not service
metadata. Candidate B may reduce worker payload visibility; it does not alter
the authorization ruling.

## 10. Verification and remaining gates

Completed locally:

```console
cargo fmt -p qlab-remote-auth
cargo check -p qlab-remote-auth --all-targets --locked
```

The RFC reference signature and leaf comparison was byte-identical. Repository
policy forbids agent sessions from running local `cargo test`, so the written
unit/integration tests await CI. No mobile or pinned-rig performance number is
claimed by this document.

Before Phase 2, Larry must decide the ML-DSA depth/linkability shape from this
spike plus mobile evidence, and Claude Code must independently review the
immutable PR. Grok's review must cover the A-only witness/metadata boundary and
the depth-0 linkage tradeoff. Only an accepted result may be translated into a
dated EN/ZH binding-design correction. AIR, transaction wire/identity, node
verification, activation, genesis/re-mint, wallet integration, and the prover
service remain later, separately authorized phases.
