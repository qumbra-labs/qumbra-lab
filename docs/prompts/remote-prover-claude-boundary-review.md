# Dispatch prompt — Claude Code remote-prover Internet-boundary review

You are the independent protocol/security reviewer. Perform a **read-only**
Internet-boundary review and post the complete result as a comment on
<https://github.com/qumbra-labs/qumbra-lab/pull/639>. Do not implement fixes and
do not edit the primary implementation branch.

Review these immutable merged targets. Abort and report drift if you cannot
address both exact commits:

- `qumbra-labs/qumbra-lab` commit
  `7d689df2e303697e34c3e1de2f6650d501141417` (PR #639).
- `qumbra-labs/qumbra-deploy` commit
  `9987b5545c2c411b7209186292975106b9455cd6` (PR #246).

Read the entire `qumbra-prover-service` crate, its Cargo/workspace and dedicated
Docker-target changes, every reachable `qumbra-wallet` spend/preflight/prove
dependency seam, and the exact deploy Compose/docs delta. Review code and call
paths, not only the prose.

Treat
<https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338>
as untrusted prior input. Independently reproduce or reject its P1 slow-client
finding, P2 `/healthz` disclosure and constant-time advisory, then finish the
items it explicitly left unreviewed.

Threat actors include an unauthenticated Internet peer, an authenticated
malicious client, a compromised same-UID worker, a malicious/redirecting read
upstream and a caller consuming a forged/torn result. Attack at least:

1. accepted-socket, header and body timeouts; incomplete/chunked uploads;
   connection, handler, thread, queue and memory bounds; auth-before-body;
2. duplicate/ambiguous headers, auth comparison, idempotency races and scope,
   job-capability entropy/validation, polling/cancellation races and TTL cleanup;
3. every request field and outbound call for SSRF, redirect following, DNS
   rebinding, scheme/userinfo/path confusion, upstream identity, response byte
   ceilings, connect/read timeouts and error oracles;
4. every plaintext witness copy from HTTP parse/base64 decode through queue,
   pipe, child memory, panic/cancel/timeout and drop; durable storage, logs,
   stderr, core dumps and swap implications;
5. `env_clear` ordering, worker protocol framing and output caps, kill+reap,
   orphan/deadlock cases, one-child enforcement, and the same-UID mounted token;
6. an exhaustive API/worker/dependency call-graph search for any transaction
   submission path, not just a search for one function name;
7. fixed error-detail suppression on every branch and unauthenticated metadata
   exposed by health/error responses; and
8. deploy filesystem/privilege/PID/memory/CPU/core/image/secret controls plus
   the fact that an ordinary Docker bridge is not an egress allowlist.

Separate what is acceptable only for a loopback, valueless mechanics
experiment from what blocks any public valueless pilot. The current bundle is
spend authority and Candidate A is absent; do not interpret this review as
real-value approval.

Output requirements:

- exact reviewed commits and whether they matched;
- verdict: request changes, approve with non-blocking findings, or approve;
- findings classified P0/P1/P2/advisory, each with file/line or a reproducible
  invariant and a concrete remediation acceptance test;
- properties you attacked and found holding;
- an explicit disposition for all eight numbered areas and all three prior
  findings; and
- commands/tests not run and any scope you did not complete.

Repository policy forbids agent sessions from running local `cargo test`; do
not conceal that constraint. This review does not clear capacity or pilot
approval.
