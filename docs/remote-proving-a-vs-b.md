# Remote proving — Grok's A vs B judgment (superseded as the pick)

**Author: Grok 4.6 (xAI), 2026-08-23.** This file records **Grok's** A-or-B
judgment. It is not Larry's ruling and it is not a lab consensus.

**Status: SUPERSEDED as the launch-basis pick.** Larry's accepted ruling is
[`remote-proving-candidate-ruling.md`](remote-proving-candidate-ruling.md).
Do not cite this file as if Larry or the lab chose B as required.
Paired with
[`remote-proving-a-vs-b-zh.md`](remote-proving-a-vs-b-zh.md).

Written in the `claude/remote-proving-ab-pick` worktree after reading
[`remote-proving-decision.md`](remote-proving-decision.md) (PR #620). PR #621
and PR #623 then recorded Larry's ruling. This note is kept so Grok's
argument stays attributed and findable.

---

## Grok's judgment

Grok's pick, 2026-08-23:

- **A is the load-bearing protocol destination.** Spend security must be
  consensus-bound phone authorization the worker cannot forge. That is the
  only theft model that matches Qumbra's cryptographic, no-trusted-setup
  design once phones cannot self-prove b16 and user-operated persistent
  proving is out of scope.
- **B is a required privacy overlay on the Qumbra-operated default send
  path**, not a substitute for A. A-alone hands the official service a
  viewing oracle: selected inputs, amounts, recipient/change, and `nk`
  (full-viewing-class).
- **B-alone is not the theft model.** Its "cannot steal" rests on
  SEV-SNP/TDX, firmware, cloud, attestation, and side-channels. A
  sufficiently strong breach that permits reading or modifying the
  confidential worker can collapse the spend-integrity and
  witness-confidentiality guarantees together.
- Hash-OTS as written is **not** A. Keep the `rkm` root-binding seam.
  Default the authorization spike to a standardized stateless leaf (ML-DSA
  first) until the parent record's §6 P0s close.

If one cell in the parent matrix had to be marked, Grok marked **A**. Real
value, in Grok's view, still needed both bars: A for steal, B for witness
visibility on the default phone path.

---

## What Larry ruled instead

PR #621 and PR #623 recorded Larry's ruling, not Grok's:

- **A is mandatory** for every real-value shared prover.
- **B is optional defense-in-depth**, not a funds-safety trust root and not a
  launch prerequisite.
- A-only is allowed if the privacy boundary is stated honestly.
- B-only remains valueless-experiment-only.
- The authorization primitive is still unselected.

The claim Grok made that **did not land** is "B is required on the official
default path." Larry's ruling allows an A-only official service.

Architecture, invariants, execution order, and TEE/ML-DSA sources: the
candidate ruling. Launch gates:
[`remote-proving-decision.md`](remote-proving-decision.md).
