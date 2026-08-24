# Dispatch prompt — Grok remote-prover A-only privacy red-team

You are the independent privacy/metadata red-team. Perform a **read-only**
review and post the complete result as a separate comment on
<https://github.com/qumbra-labs/qumbra-lab/pull/639>. Do not implement fixes and
do not treat agreement with another reviewer as evidence.

Review these immutable merged targets. Abort and report drift if you cannot
address both exact commits:

- `qumbra-labs/qumbra-lab` commit
  `7d689df2e303697e34c3e1de2f6650d501141417` (PR #639).
- `qumbra-labs/qumbra-deploy` commit
  `9987b5545c2c411b7209186292975106b9455cd6` (PR #246).

Read the service implementation, reachable preflight/prove paths, Docker target
and exact deployment skeleton. This is an A-only, valueless mechanics target:
the ordinary prover sees the full witness, the current `WitnessBundle` remains
spend authority, Candidate A is not integrated, and Candidate B/TEE is not
implemented. Challenge every privacy claim within that honest scope; do not
credit a future Candidate B control.

Build a data-flow/observer matrix for the client, external ingress, API
process, prover child, anchor/nullifier read endpoints, operator, container
host, image/runtime, logs/crash tooling and an attacker. Track at least:

1. witness and spend metadata copies in HTTP/base64/serde allocations, queue,
   pipes, child/process memory, result/error handling, cancellation, panic,
   core dump, swap and teardown;
2. client IP, bearer token, idempotency key, job capability, timestamps,
   polling cadence, queue state, refusal class, result size/hash and build
   revision;
3. timing/size correlation among ingress traffic, upstream anchor/nullifier
   reads, proving duration, result polling and later on-chain appearance;
4. `/healthz`, admission/refusal/TTL behavior and other cross-user load oracles;
5. what a same-UID compromised worker can read or exfiltrate through the token
   mount and unrestricted bridge egress;
6. access/error/application/container/host/cloud logging defaults, retention,
   support access, backups and crash collection, including claims the skeleton
   does not actually enforce;
7. reusable shared bearer authentication versus per-install identity,
   revocation, abuse handling and the privacy cost of account/IP controls; and
8. whether each failure affects only privacy/availability or can expose current
   spend authority. State separately why eventual Candidate A protects funds
   but does not hide the witness, client identity, timing or correlations.

Treat the prior partial security comment on PR #639 as input to challenge, not
as a conclusion. Separate loopback-valueless limitations from blockers for an
Internet-facing valueless pilot.

Output requirements:

- exact reviewed commits and whether they matched;
- verdict: request changes, approve with non-blocking findings, or approve;
- findings classified P0/P1/P2/advisory, each with file/line or reproducible
  invariant and a concrete remediation acceptance test;
- the observer/data-flow matrix and properties attacked but found holding;
- an explicit disposition for all eight numbered areas; and
- commands/tests not run and any scope not completed.

Do not approve deployment, capacity, real value or launch. Larry retains every
such gate.
