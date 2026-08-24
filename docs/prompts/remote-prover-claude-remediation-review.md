# Dispatch prompt — Claude Code remote-prover remediation delta review

You are the independent protocol/security reviewer. Perform a **read-only final
delta review** and post the complete result as a comment on
<https://github.com/qumbra-labs/qumbra-lab/pull/648>. Do not implement fixes,
edit either implementation branch, deploy anything, start a listener, or run a
real proof.

Review both exact merged targets. Abort and report drift if you cannot address
both full commits:

- `qumbra-labs/qumbra-lab`
  `702456d4c7315df1ec2838ae729bdcab8edb1342` (PR #652; parent
  `dae9f10ec5d57dad5773260a0ad15630e816c12e`).
- `qumbra-labs/qumbra-deploy`
  `33afc24826381778841e3b123401ef56545a7f0f` (PR #249; parent
  `228d57e3d86eb63c32e16f7a319fb453e73a35b0`).

Read the final tree and exact parent-to-commit deltas, not only the PR prose.
Use the baseline reports and preliminary cross-reviews as untrusted prior input:

- <https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391401951>
- <https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392271552>
- <https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392278098>

The preliminary reviews targeted older heads and found two blockers that were
subsequently changed: lab merge hygiene around `qlab-http-framing`, and crossed
node/anchor versus scan/nullifier egress routes. They are findings to retest,
not final verdicts.

Independently account for every row in
`docs/remote-proving-service-review-ledger.md` §2, and specifically attack:

1. whether the final lab tree uses `qlab_http_framing::read_response` without a
   private `dechunk`, shares one fail-closed response budget across anchor and
   all nullifier reads, and keeps all prior response-framing guarantees;
2. the exact runtime mapping
   `NODE_URL → :8081 → /v1/anchors → NODE_AUTHORITY` and
   `SCAN_URL → :8082 → /v1/nullifiers → SCAN_AUTHORITY`, including crossed
   paths, extra query keys, reordered query keys, verbs and trailing paths;
3. ingress deadlines/body limits and the fact that `tiny_http` remains unsafe
   if directly published; distinguish the protected Compose path from the
   standalone binary;
4. liveness-only `/healthz`, token comparison, client-token/hop-token
   separation, same-UID hop-token residual, idempotency/job-capability caller
   binding and retained-job denial;
5. the final Docker network graph and every possible worker route, including
   metadata/private destinations, ingress reachability, DNS/IPv4/IPv6/default
   routes and the difference between static Compose evidence and an unrun live
   isolation test;
6. upstream response behavior: worker byte ceiling, egress response-body
   availability, timeout behavior and the documented configuration coupling;
7. typed `WitnessBundle` zeroization coverage, post-handoff drop, allocator and
   STARK-working-set limits, swap/core/crash collection boundaries; and
8. exact pinned-image startup, Caddy's file capability, the minimal
   `NET_BIND_SERVICE` grants, prover capability absence, token CR/LF hard gate,
   both egress listener health checks and static-checker negative behavior.

Confirm the reachable API/worker call graph still has no transaction-submit
path and that Candidate A remains absent. This is a valueless mechanics target;
the current `WitnessBundle` is spend authority. Do not convert infrastructure
hardening into real-value approval.

Output requirements:

- exact commits and parents reviewed, with a drift statement;
- verdict for readiness to prepare an **isolated, single-operator, loopback-only
  capacity task book**: request changes, approve with non-blocking findings, or
  approve;
- one row-by-row disposition for every ledger §2 finding plus both preliminary
  cross-review blockers;
- each new finding classified P0/P1/P2/advisory with file/line or reproducible
  invariant and an acceptance test;
- properties attacked and found holding;
- a separate list of static properties versus live/runtime gates not run; and
- commands/tests not run and any incomplete scope.

Repository policy forbids agent sessions from running local `cargo test`.
Neither an approval nor green CI authorizes capacity execution, a host,
deployment, public ingress, real value or launch; Larry retains those gates.
