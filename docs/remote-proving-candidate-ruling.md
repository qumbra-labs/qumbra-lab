# Remote proving — candidate ruling: A is the launch security basis, B is a later layer

**Status: RULED 2026-08-23. Larry accepted the reviewer-f5 recommendation
below in the same session that produced it. This ruling selects the *launch
security basis* of [`remote-proving-decision.md`](remote-proving-decision.md)
§9.3. It does not approve implementation, does not select a signature
primitive, and does not amend the binding design specification — those remain
gated exactly as that record says.**
Paired with
[`remote-proving-candidate-ruling-zh.md`](remote-proving-candidate-ruling-zh.md).

---

## 1. The ruling

**Candidate A — consensus-bound phone-held authorization — is the security
basis on which a real-value shared prover launches. Candidate B — an attested
confidential worker — is a deployment-layer privacy hardening to be added on
top of A later, and is not a launch prerequisite.**

The two are not alternatives at the same layer, and the decision record's
"A or B or both" framing should be read as resolved to **A first, B later**.

## 2. Why — in the order that decided it

### 2.1 The two candidates compose in only one direction

A changes the **protocol**: the node rejects any transaction that lacks the
phone's authorization over the complete intent. Its guarantee is a
mathematical property anyone can verify from the chain.

B changes the **deployment**: the worker runs inside a SEV-SNP/TDX-class
confidential VM. Its guarantee is a chain of assumptions — CPU vendor
firmware, the cloud operator, the attestation service, a measured image, and
the absence of an exploitable side channel.

B can be added to a chain that already has A without touching consensus. A
cannot be added to a deployment that launched on B without a re-mint or a
hard fork. A first is the only order that does not foreclose the other.

### 2.2 The re-mint window is open for A and irrelevant to B

T2 is minted and not launched. Today A's consensus change is one PR and one
re-mint through the existing ceremony. After launch it is a hard fork with
live value on both sides. B never needs that window. The window closes on its
own; only A is hurt by waiting.

### 2.3 B alone contradicts the chain's own trust thesis

Qumbra's design wager is conservative hash plus STARK everywhere in consensus,
declining even lattice signatures on engineering-conservatism grounds. Making
the one question that matters most to a user — *who can spend my money* —
depend on TEE attestation would put the weakest trust assumption in the whole
system at its most sensitive point. The published record of SGX and SEV
breaks is long enough that "attestation holds" is not a sentence a privacy
chain's security statement can rest on. B is a good **additional** barrier
and a bad **only** barrier.

### 2.4 A also dissolves the availability and censorship dependency

Under A a prover cannot steal, so a prover does not need to be Qumbra.
Community nodes, pools, or a paid market can prove for phones; the central
service becomes one provider among several. Under B a prover must forever be
"an attested Qumbra-approved image", which keeps
[`backend-assisted-proving-security.md`](backend-assisted-proving-security.md)
§7's single-operator availability and censorship problem permanent.

### 2.5 Why this can be ruled before the measurements

`remote-proving-decision.md` §9.3 says "do not select from estimated rows".
This ruling does not: none of §2.1–2.4 is a number. They are layering,
sequencing, and trust-model facts that no measurement changes. What the
measurements still decide is listed in §4 — and all of it gates
*implementation*, not the choice of basis.

## 3. What A does not give, stated plainly

- **A does not pass the "cannot see/link" bar.** An ordinary worker still
  observes the selected notes, amounts, recipient plaintexts, nullifiers,
  device identity, IP, and timing, and receives full-viewing-class `nk`. That
  is a privacy gap, not a funds-safety gap, and it is exactly what B (or
  multi-operator proving) is for later.
- **A requires a dated correction to the binding design spec** — the "one
  monolithic STARK, no per-spend signatures" decision. That correction is
  Larry's to make in the design repo and must land before the lab circuit or
  wire moves (`remote-proving-decision.md` §9.4).
- **A is a T2 re-mint-class change.** Note/`rkm` binding, AIR and public
  values, transaction wire, node verification, transaction identity, genesis.

## 4. How A proceeds — recommendations, not rulings

These are the reviewer's recommendations for the §9.1 authorization spike.
They are offered so the spike starts from a position, and each is overridable
by its measurement.

1. **Default the leaf to ML-DSA-44, not WOTS+.** It is stateless, so the
   rollback/key-reuse P0 in `remote-proving-decision.md` §6 disappears rather
   than being managed; it is a NIST standard with published vectors, so the
   incomplete-instantiation P0 disappears too. The price is about +3.1 KB per
   transaction over the WOTS+ row (≈166 KB est., still under b4's ~236 KB).
   WOTS+ and random-index WOTS+ stay in the comparison as future size
   optimizations, not as the launch path.
2. **Write the dummy-slot rule first.** The #219 latch makes slot 1 a
   prover-side dummy with no note and no key tree. Its authorization rule
   (ephemeral phone-held key, latch path binding that key rather than a tree
   path, real-input count still hidden) is the first deliverable of the spike,
   because every other part of the spec depends on the two slots having one
   public shape.
3. **Keep the structural seam from
   [`hash-ots-spend-authorization.md`](hash-ots-spend-authorization.md):**
   per-address root in `rkm`'s spare Keccak rate, 32-byte leaf, membership
   proved in-circuit, signature verified natively at the node before STARK
   verification. The primitive changes; the seam does not.
4. **Run B's confidential-VM fit lane in parallel, not on the critical path.**
   It is cheap, and its result decides *when* B is layered on, not *whether*
   A proceeds.

Effort, in Claude session hours (wall time depends on how sessions are
spaced): spec + vectors + dummy rule ≈ 5 h; circuit change with the
domain-separation review ≈ 15–20 h; wire, node verification, wallet key
hierarchy ≈ 15 h; the re-mint itself follows the existing ceremony.
**≈ 40–50 session hours**, plus 2^19 prover measurements on the rig (machine
time, not session time). The design-spec correction and the T2 launch
sequencing are Larry's steps and are outside this estimate.

## 5. What this ruling changes in the other records

- `remote-proving-decision.md` §9.3 is resolved: the launch security basis is
  A. §9.1 (spike), §9.2 (B lane, now parallel), §9.4 (spec correction) and
  §9.5 stand unchanged and still gate implementation.
- §8's launch gates are unchanged; A must pass every applicable one.
- Nothing in `backend-assisted-proving-security.md`,
  `hash-ots-spend-authorization.md`, or `phone-self-proving-reopened.md` is
  amended by this ruling.

## 6. Scope at this handoff

- No code, circuit, wire, genesis, cloud resource, or deployment changed.
- `CONSENSUS_CFG` remains untouched.
- The binding design specification remains unamended until its own
  correction process runs.
