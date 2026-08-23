# Remote proving — A vs B research (superseded)

**Status: SUPERSEDED 2026-08-23.** The current pick is
[`remote-proving-candidate-ruling.md`](remote-proving-candidate-ruling.md).
Do not treat this file as the launch-basis decision.
Paired with
[`remote-proving-a-vs-b-zh.md`](remote-proving-a-vs-b-zh.md).

Written 2026-08-23 as a research note before PR #621 / PR #623 landed. Kept
only so the pre-ruling argument is findable.

---

## What this note recommended

- **A** as the load-bearing protocol destination: consensus-bound phone
  authorization the worker cannot forge.
- **B** as a **required** privacy overlay on the Qumbra-operated default send
  path, because A-alone hands the service a viewing oracle (`nk` is
  full-viewing-class).
- Hash-OTS as written is not A; keep the `rkm` root-binding seam and default
  the authorization spike to a standardized stateless leaf (ML-DSA first).

## What was accepted instead

PR #621 and PR #623 recorded Larry's ruling:

- **A is mandatory** for every real-value shared prover.
- **B is optional defense-in-depth**, not a funds-safety trust root and not a
  launch prerequisite.
- A-only is allowed if the privacy boundary is stated honestly.
- B-only remains valueless-experiment-only.
- The authorization primitive is still unselected.

The one claim this note made that did **not** land: B as a required overlay.
The accepted ruling allows an A-only official service.

Read the candidate ruling for architecture, invariants, execution order, and
TEE/ML-DSA sources. Read
[`remote-proving-decision.md`](remote-proving-decision.md) for launch gates.
