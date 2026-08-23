# Remote proving — Candidate A vs B recommendation

**Status: RECORDED RECOMMENDATION, NOT LARRY RATIFICATION, NOT
IMPLEMENTATION APPROVAL.** This document answers the A-or-B question that
[`remote-proving-decision.md`](remote-proving-decision.md) left open. It does
not replace that record. The authorization primitive, confidential-compute
target, and §8 launch gates remain unmeasured. No public prover may carry real
value until those gates pass.
Paired with
[`remote-proving-a-vs-b-zh.md`](remote-proving-a-vs-b-zh.md).

Written 2026-08-23 after PR #620. English is authoritative.

This recommendation does not silently amend Qumbra's binding design
specification. Selecting protocol-level authorization still requires a dated
design-repo correction to "one monolithic STARK; no per-spend signatures"
before any lab circuit or wire change.

---

## 1. Verdict in one sentence

**A is the load-bearing launch basis** (consensus-bound phone authorization the
worker cannot forge). **B is a required privacy overlay** for the
Qumbra-operated default send path, not a substitute for A. Real-value public
proving launches only when both bars are met: A for steal, B for witness
visibility.

If §3 of the parent record must mark exactly one cell: **A**.

---

## 2. What this is answering

The parent record settled the product constraints and named two candidates. It
did not pick. The honest matrix is:

| | cannot steal | cannot see/link witness | T2 / consensus |
|---|---|---|---|
| **A** — phone-held authorization | yes, if consensus binds the full phone-approved intent | **fails** at an ordinary worker | re-mint-class protocol change |
| **B** — attested confidential worker | only under TEE / image / isolation assumptions | payload visibility reduced; ingress metadata remains | no protocol re-mint in principle |

Larry already ruled that every supported phone must send, and that a user's
Mac, home server, or rented VM cannot be the standing send path. The shared
service is therefore the **default** phone send path, not an optional
power-user fallback. That fact loads both columns: theft on the default path
is disqualifying, and a viewing oracle on the default path is also
disqualifying.

The comparison is not "b4 versus trust Qumbra." It is not "A xor B" as if
either row were a complete product.

---

## 3. Why A is load-bearing

Qumbra's binding design is cryptographic, not hardware-trust:

- the whitepaper and
  [`transaction-model-and-anonymity-set.md`](https://github.com/qumbra-labs/qumbra-design/blob/main/transaction-model-and-anonymity-set.md)
  put spend authorization **inside** one monolithic STARK, with no trusted
  setup and a conservative Keccak-only consensus path
- "no per-spend signatures" was true **because the wallet proved its own
  transaction**, so a signature was redundant with in-circuit `sk` knowledge
- that premise is dead: phones cannot hold b16 (~15 GB peak RSS on the M2
  ladder), and Larry ruled user-operated persistent proving out of scope
- PR #618: a delegated prover holding `WitnessBundle` holds selected-input
  spend authority

A is the design-repo correction the new product actually needs. B preserves
today's wire by moving spend security onto SEV-SNP / TDX / firmware / cloud /
side-channel assumptions — the class of extra trust Qumbra refused everywhere
else.

Retrofit asymmetry decides sequencing:

| if you ship first | later adding the other |
|---|---|
| **A first** | B is a transport and trust-boundary upgrade; no second re-mint |
| **B first** | A still needs T2 re-mint, AIR / wire / genesis, and a dated design-spec correction |

A cannot be cheaply retrofitted. B can. Therefore A is the protocol
destination; B is infrastructure.

Hash-OTS as written is **not** A. Keep the structural seam: commit an
authorization-key-tree root inside `rkm`, prove a 32-byte leaf in the STARK,
verify the signature natively at the node. Drop the current WOTS+ draft until
the parent record's §6 P0s close (state rollback / key reuse, incomplete
instantiation, dummy-slot rule). The authorization spike should treat a
standardized **stateless** leaf (ML-DSA first) as the default A primitive
unless measured WOTS+ beats it on rollback safety.

---

## 4. Why A-alone is not a privacy product

The parent matrix is explicit: A **fails** `cannot see/link` at an ordinary
worker. [`hash-ots-spend-authorization.md`](hash-ots-spend-authorization.md)
is also explicit that `nk` is full-viewing-class material.

Default phone path + A-alone means the Qumbra-operated service sees, for every
remote send:

- selected inputs, nullifiers, amounts, recipient and change
- `nk` (full-viewing-class)
- device identity, IP, timing, and the later on-chain transaction

That is a viewing oracle sitting on the only send path most phones will use.
Theft-prevention without privacy is not this chain's product.

B is the only current route that keeps today's consensus **and** withholds
witness plaintext from the ordinary operator. Ingress metadata linkability
remains either way and needs its own launch review.

---

## 5. Why B-alone is not the theft model

B's "cannot steal" holds only if attestation, image pin, isolation,
debug-disabled, and the TEE / cloud / firmware story all hold. One break gives
**both** theft and full witness. That is not a non-custodial claim Qumbra can
market.

B is also not selectable from the current rows. Before it can be a product
option, the exact SEV-SNP/TDX-class target must show:

1. current 12–15 GB-class b16 job: peak private memory, cold/warm time, proof
   bytes, failure behavior, and cost
2. iOS and Android verification of fresh, correct, non-debug, non-revoked
   attestation, including negatives
3. encryption across ingress, queue, host, snapshot, swap, crash collection,
   and operator observability
4. rollback, replay, cancellation, teardown, and regional outage behavior
5. an explicit hardware, firmware, cloud, side-channel, and availability trust
   statement

STARK proving is a hostile TEE workload: huge structured LDEs, predictable
memory traffic, long runtimes. Side-channel and memory-encryption tax are not
paperwork. Measure them.

Use B for: (1) a valueless service-mechanics experiment on current consensus,
which the parent record already allows; (2) payload hiding once A exists. Not
as the long-term cannot-steal claim.

---

## 6. What "both" means, operationally

| layer | job | failure mode if omitted |
|---|---|---|
| **A** (consensus) | worker cannot authorize outputs or semantic fields the phone did not approve | TEE / operator / image bug spends the selected notes |
| **B** (transport) | ordinary ingress, queue, host, and operator see ciphertext only | default send path is a viewing oracle |
| **Neither A nor B** | trusted `WitnessBundle` | already rejected for real value |
| **A without B** | cannot steal, can see | privacy product is false on the default path |
| **B without A** | operator cannot read *if* the TEE holds | theft model is Intel/AMD/cloud, forever |

Ingress can still join device identity, IP, timing, and the resulting
transaction. That is a third bar. It does not choose A or B; it constrains
how the service is exposed.

---

## 7. What this does not decide

The parent work order still runs. This file does not skip it:

0. Independent hardening: replace both 128 MiB paired-prover protocol ceilings
   with measured bundle/artifact ceilings.
1. Authorization spike: specify and compare standardized WOTS+, a standardized
   stateless signature leaf, and a random-index WOTS+ leaf, including dummy
   semantics and rollback/multi-device behavior.
2. Confidential-worker lane: run today's b16 circuit on the exact target
   instance and complete mobile attestation negatives.
3. Then lock the launch basis. The recommendation here is **A, with B as
   overlay**. Do not lock cost, wire bytes, or TEE fit from estimated rows.
4. If A remains the protocol destination after the spike: dated correction to
   the design repo **before** lab circuit or wire changes.
5. Only then implement and pilot the public service boundary.

No backend, circuit, `CONSENSUS_CFG`, genesis, cloud resource, or deployment
is built here.

---

## 8. How to read this against the parent record

- [`remote-proving-decision.md`](remote-proving-decision.md) remains the
  authoritative entry point for settled constraints and launch gates. Until
  Larry ratifies this recommendation, that record's "route not selected"
  stands.
- [`backend-assisted-proving-security.md`](backend-assisted-proving-security.md)
  remains the threat-model and topology evidence.
- [`hash-ots-spend-authorization.md`](hash-ots-spend-authorization.md) remains
  a research candidate. Its `rkm` root-binding insight is used here; its
  WOTS+ safety claim is not.
- [`phone-self-proving-reopened.md`](phone-self-proving-reopened.md) and
  [`m2-iphone-plan.md`](m2-iphone-plan.md) remain the reason the default path
  is remote proving rather than b4-for-everyone.

If this recommendation and the parent record ever disagree on a settled
constraint, the parent wins. If they disagree on A-versus-B, this file is the
recorded recommendation until the parent is updated by a dated amendment.
