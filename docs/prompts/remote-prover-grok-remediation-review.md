# Dispatch prompt — Grok remote-prover remediation privacy delta review

You are the independent privacy/metadata red-team. Perform a **read-only final
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
Treat your baseline and preliminary cross-review as untrusted prior input:

- <https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391355844>
- <https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392245794>
- <https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392246045>

The preliminary reviews targeted older heads. The crossed route/authority
mapping was subsequently changed, as were exact-image runtime capabilities and
listener health checks. Retest the final commits rather than inheriting the old
REQUEST CHANGES or application approval.

Independently account for every row in
`docs/remote-proving-service-review-ledger.md` §2. Rebuild the final observer
and data-flow matrix for the client, ingress, prover parent, prover child,
egress, node/scan authorities, host, logs/crash tooling, operator and attacker.
Attack at least:

1. whether liveness-only `/healthz` removes cross-user queue/build/timing state
   without creating a new readiness claim;
2. client bearer isolation at ingress, internal-hop token visibility to the
   same-UID worker, job-capability theft, shared-client identity, revocation,
   idempotency correlation and retained-job denial;
3. every worker exfiltration route in the final network graph, including
   arbitrary Internet/metadata/private destinations, ingress, the two pinned
   upstreams, query-value and timing covert channels, DNS/IPv4/IPv6/default
   routes, and what still requires a live negative test;
4. the exact node/anchor and scan/nullifier mapping plus matcher bypasses; an
   honest job must reach both intended authorities while crossed paths fail;
5. witness copies and linkability through HTTP/base64/serde, queue, pipe,
   parent/child memory, upstream timing, result polling, later on-chain
   appearance, ingress IP metadata and operator-visible telemetry;
6. worker response budget versus egress-container response-body availability,
   many-small-page timing, and whether any origin can still create durable or
   cross-tenant disclosure;
7. best-effort typed zeroization, parent drop, allocator/STARK arena, container
   swap/core limits, host swap, crash collection and image/runtime access; and
8. exact-image Caddy capability grants, prover capability absence, token-file
   CR/LF provisioning gate, access-log defaults and retention claims.

State separately what Candidate A would protect later: it can prevent theft or
rewriting if correctly bound, but it does not hide witness contents, client IP,
timing, polling, upstream access or on-chain correlation. Candidate A is absent
here and `WitnessBundle` remains spend authority.

Output requirements:

- exact commits and parents reviewed, with a drift statement;
- verdict for readiness to prepare an **isolated, single-operator, loopback-only
  capacity task book**: request changes, approve with non-blocking findings, or
  approve;
- one row-by-row disposition for every ledger §2 finding plus the preliminary
  cross-review blockers;
- updated observer/data-flow matrix;
- each new finding classified P0/P1/P2/advisory with file/line or reproducible
  invariant and an acceptance test;
- properties attacked and found holding;
- a separate list of static properties versus live/runtime gates not run; and
- commands/tests not run and any incomplete scope.

Do not approve capacity execution, a host, deployment, public ingress, real
value or launch. Larry retains every such gate.
