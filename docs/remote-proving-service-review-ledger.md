# Remote proving service — Internet-boundary review ledger

**Status: OPEN REVIEW GATE, 2026-08-24. VALUELESS MECHANICS ONLY. THIS RECORD
DOES NOT AUTHORIZE A LISTENER, HOST, PILOT, REAL VALUE, OR TRANSACTION
SUBMISSION.** Paired with
[`remote-proving-service-review-ledger-zh.md`](remote-proving-service-review-ledger-zh.md).

The governing service record is
[`remote-proving-service-mvp.md`](remote-proving-service-mvp.md). This ledger
turns the independent-review requirement in
[`remote-proving-implementation-plan.md`](remote-proving-implementation-plan.md)
into a commit-addressed checklist. A checked sub-invariant is evidence about
that sub-invariant only; it does not clear the review gate.

## 1. Immutable review target

Reviewers must inspect these exact merged artifacts, not a verbal summary or a
later `main` tree:

| repository | immutable target | artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`7d689df2e303697e34c3e1de2f6650d501141417`](https://github.com/qumbra-labs/qumbra-lab/commit/7d689df2e303697e34c3e1de2f6650d501141417) | PR [#639](https://github.com/qumbra-labs/qumbra-lab/pull/639): service, worker boundary, Docker target and service docs |
| `qumbra-labs/qumbra-deploy` | [`9987b5545c2c411b7209186292975106b9455cd6`](https://github.com/qumbra-labs/qumbra-deploy/commit/9987b5545c2c411b7209186292975106b9455cd6) | PR [#246](https://github.com/qumbra-labs/qumbra-deploy/pull/246): standalone loopback-only Compose skeleton and deployment record |

The lab target is deliberately pre-Candidate-A. Its `WitnessBundle` remains
spend authority, so every experiment is valueless. The deployment target is a
static review skeleton, not a deployed ingress.

## 2. Findings currently on the record

The first read-only security pass is preserved in
[#639 comment 5391225338](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338).
It explicitly declared itself partial. These entries therefore remain open
until fixed or rejected with a recorded rationale and independently re-reviewed:

Grok's complete privacy report is preserved in
[#639 comment 5391355844](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391355844).
Its verdict approves only the frozen loopback, valueless, Compose-render-only
target. It explicitly does **not** approve an Internet-facing pilot. The table
uses the higher reported severity where the two passes differ:

| effective severity | status | source | finding / required disposition |
|---|---|---|---|
| P1 | OPEN | both | `tiny_http::Server::http` has no accepted-socket read deadline or connection cap. `MAX_HTTP_HANDLERS` begins after a request has been received, so unauthenticated slow/incomplete headers can consume listener resources before admission accounting. |
| P1 | OPEN | security pass P2; Grok P1 | Unauthenticated `/healthz` exposes `queued`, `running`, `retained`, `queue_capacity` and `build_revision`, enabling load/timing observation and exact version fingerprinting. Public liveness needs no per-service activity counters. |
| P1 | OPEN | Grok | A compromised same-UID worker can read the mounted shared API token; one stolen credential is the entire experiment identity and can retrieve any separately leaked job capability. |
| P1 | OPEN | Grok | The default bridge provides no egress allowlist, so a compromised worker that holds the current spend-authority bundle can exfiltrate it to arbitrary destinations. |
| P2 | OPEN | Grok | A client-chosen idempotency key may be a stable cross-attempt identifier and its reuse-conflict response is an existence oracle during retention. |
| P2 | OPEN | Grok | A shared bearer plus a leaked job identifier can retrieve another caller's full artifact; there is no per-install or per-job holder binding. |
| P2 | OPEN | Grok | Nullifier preflight spans `0..=tip` and the reachable HTTP read has no response-byte ceiling, permitting a pinned or compromised upstream to amplify memory while the witness remains resident. |
| P2 | OPEN | Grok | Host swap or crash collection can outlive the claimed in-process retention window; core disablement alone does not close host/cloud persistence. |
| Advisory | OPEN | both | `ApiToken::matches` uses a hand-written compare without an optimizer-resistant constant-time primitive. Decide whether to replace it or retain it with a documented rationale. |
| Advisory | OPEN | Grok | `health()` always returns `ready: true`; it must not be treated as prover readiness or idleness. |

The same pass found the following properties holding in the immutable lab
target once a request reaches application handling: handler accounting
precedes authorization and body parsing; declared and actual body ceilings are
both enforced; cancellation/timeout kills and reaps the child; `SecretBytes`
and the API token zeroize on drop; TTL cleanup also bounds the idempotency map;
and duplicate authorization headers are refused. These are retained
observations, not a verdict.

Grok independently confirmed that the current service crate has no
`spend::submit` call, requests cannot select upstream URLs, inherited worker
environment is cleared, worker errors are allowlisted, job identifiers are
unguessable, results are TTL-bounded in process memory, and the Compose
skeleton is loopback-only with the documented privilege/mount limits. It also
confirmed that `env_clear` is not worker isolation and that the architecture's
external ingress is absent from the skeleton. Claude still owes the broader
security/call-graph review specified below.

## 3. Required independent coverage

Claude Code must independently reproduce or reject the recorded findings and
complete every service-security invariant. At minimum its report must cover:

- every request field and dependency call path for request-selected endpoints,
  redirects, DNS rebinding, upstream identity, response byte/time ceilings and
  SSRF;
- the plaintext witness lifecycle across HTTP parsing, decoded copies, queue,
  pipes, child memory, result/error handling, cancellation, panic and teardown;
- whether the worker environment is cleared before witness delivery, and what
  the same-UID token mount plus unrestricted bridge egress still permit;
- fixed-error suppression on every branch, including worker panics and
  upstream failures;
- an exhaustive code/dependency search proving that the API and worker have no
  transaction-submission path;
- connection/header/body slow-client behavior, handler/thread/queue bounds,
  idempotency races, job capability handling, cancellation races and child
  output framing; and
- the deploy skeleton's filesystem, privilege, PID/memory/CPU/core-dump,
  secret, network and image-digest boundaries.

Grok's A-only privacy and metadata assignment is **COMPLETE for the immutable
target** in comment 5391355844. It supplied the required observer/data-flow
matrix, covered all eight dispatch areas, separated privacy/availability from
current spend-authority exposure, and disclosed its unrun live-host, ingress,
Candidate A and Candidate B scope. Its public-pilot blockers remain open.

The exact dispatch instructions are retained in:

- [`prompts/remote-prover-claude-boundary-review.md`](prompts/remote-prover-claude-boundary-review.md)
- [`prompts/remote-prover-grok-privacy-review.md`](prompts/remote-prover-grok-privacy-review.md)

Each reviewer must classify findings as P0/P1/P2 or advisory, cite a file/line
or reproducible invariant, list properties attacked and found holding, disclose
anything not reviewed or run, and post a commit-addressed report on lab PR
#639. Neither reviewer edits the implementation branch.

## 4. Gate-closing rule and next action

The review gate remains open until all of the following are recorded:

1. Claude's complete Internet-boundary report and Grok's independent privacy
   report both target the two commits in §1; Grok is complete and Claude is
   still owed;
2. Codex records a fix or reasoned rejection for every finding;
3. every accepted P0/P1 is fixed in a scoped PR with regression coverage;
4. both reviewers inspect the immutable remediation commit and explicitly
   account for every original finding and required coverage item; and
5. no unresolved finding can expose spend authority, plaintext witnesses,
   reusable credentials, arbitrary network access, or unauthenticated resource
   exhaustion at the intended pilot boundary.

Only then may an isolated-host capacity task book be prepared. Capacity work
must still be separately approved and must record cold/warm latency, peak RSS
and committed memory, one-worker cancellation and memory release, artifact
sizes, safe concurrency and cost. A green review plus good capacity numbers
still do not approve a valueless pilot: that remains a separate Larry gate.
