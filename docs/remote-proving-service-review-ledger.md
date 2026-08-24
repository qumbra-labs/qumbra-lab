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

## 1. Immutable review targets

The first-pass findings came from these immutable baseline artifacts:

| repository | immutable target | artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`7d689df2e303697e34c3e1de2f6650d501141417`](https://github.com/qumbra-labs/qumbra-lab/commit/7d689df2e303697e34c3e1de2f6650d501141417) | PR [#639](https://github.com/qumbra-labs/qumbra-lab/pull/639): service, worker boundary, Docker target and service docs |
| `qumbra-labs/qumbra-deploy` | [`9987b5545c2c411b7209186292975106b9455cd6`](https://github.com/qumbra-labs/qumbra-deploy/commit/9987b5545c2c411b7209186292975106b9455cd6) | PR [#246](https://github.com/qumbra-labs/qumbra-deploy/pull/246): standalone loopback-only Compose skeleton and deployment record |

The final delta review must inspect this exact paired remediation tree, not an
earlier PR head, verbal summary, or later `main` tree:

| repository | immutable remediation target | artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`702456d4c7315df1ec2838ae729bdcab8edb1342`](https://github.com/qumbra-labs/qumbra-lab/commit/702456d4c7315df1ec2838ae729bdcab8edb1342) | PR [#652](https://github.com/qumbra-labs/qumbra-lab/pull/652): liveness-only health, bounded upstream reads, token comparison and witness zeroization; parent `dae9f10ec5d57dad5773260a0ad15630e816c12e` |
| `qumbra-labs/qumbra-deploy` | [`33afc24826381778841e3b123401ef56545a7f0f`](https://github.com/qumbra-labs/qumbra-deploy/commit/33afc24826381778841e3b123401ef56545a7f0f) | PR [#249](https://github.com/qumbra-labs/qumbra-deploy/pull/249): split ingress/prover/egress trust domains, route allowlist and runtime hardening; parent `228d57e3d86eb63c32e16f7a319fb453e73a35b0` |

Both lab targets are deliberately pre-Candidate-A. `WitnessBundle` remains
spend authority, so every experiment is valueless. The deployment target is
still standalone and host-loopback-only; nothing in this ledger records an
actual deployment or authorizes a public ingress.

## 2. Findings and remediation currently on the record

The first read-only security pass is preserved in
[#639 comment 5391225338](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338).
It explicitly declared itself partial. These entries therefore remain open
until fixed or rejected with a recorded rationale and independently re-reviewed:

Grok's complete privacy report is preserved in
[#639 comment 5391355844](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391355844).
Claude's complete Internet-boundary report is preserved in
[#639 comment 5391401951](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391401951).
Both verdicts approve only the frozen loopback, valueless,
Compose-render-only target. Neither approves an Internet-facing pilot. The
table uses the higher reported severity where the reports differ. A
`REMEDIATED / RE-REVIEW OPEN` entry records implementation evidence; only the
independent final delta review may close it.

| effective severity | current status | source | finding | remediation / remaining boundary |
|---|---|---|---|---|
| P1 | REMEDIATED ON THE PUBLISHED COMPOSE PATH / RE-REVIEW OPEN | Claude + Grok | `tiny_http::Server::http` has no accepted-socket deadline or connection cap before application admission. | PR #249 places unpublished `tiny_http` behind ingress header/body/idle deadlines and a 96 KiB edge body cap. The binary alone remains unsuitable as a listener; a live slow-client check remains a pre-start gate. |
| P1 | REMEDIATED / RE-REVIEW OPEN | Claude P2; Grok P1 | Unauthenticated `/healthz` exposed load counters and build revision. | PR #652 reduces the public response to `{"alive":true}` and regression-locks that shape. It is liveness, not readiness or idleness. |
| P1 | REMEDIATED AT THE CLIENT-CREDENTIAL BOUNDARY / RE-REVIEW OPEN | Grok | A same-UID worker could read the mounted client API token. | PR #249 keeps the client bearer in the ingress domain and gives the prover a separate internal-hop token. A compromised worker can still read and misuse that hop token against its own API; that residual is explicit and is not client identity. |
| P1 | STATICALLY REMEDIATED / LIVE VERIFICATION AND RE-REVIEW OPEN | Claude P2; Grok P1 | The worker had unrestricted bridge egress while holding the spend-authority bundle. | PR #249 puts the prover only on two `internal: true` networks and permits outbound traffic through a GET-only, authority-pinned egress proxy. Live DNS/SYN/IPv4/IPv6 negative checks remain mandatory before any start. |
| P2 | OPEN / DEFERRED BEFORE A MULTI-CLIENT PILOT | Grok | A client-chosen idempotency key may become a stable identifier and its reuse-conflict response is a retention-window existence oracle. | Not changed. It does not block single-operator loopback capacity measurement; it remains in scope for per-install authentication and a public API contract. |
| P2 | OPEN / DEFERRED BEFORE A MULTI-CLIENT PILOT | Grok | A shared bearer plus a leaked job identifier can retrieve another caller's artifact; there is no per-install or per-job holder binding. | Client and hop credentials are now separated, but caller binding is unchanged. No public or multi-client pilot is authorized. |
| P2 | REMEDIATED IN THE WORKER / EGRESS AVAILABILITY RE-REVIEW OPEN | Claude + Grok | Nullifier preflight had no response-byte ceiling and could amplify worker memory while the witness remained resident. | PR #652 shares one fail-closed byte budget across anchor and nullifier reads. Egress does not independently cap response bodies, so hostile-origin egress-container availability and the documented configuration coupling remain for review. |
| P2 | PARTIALLY REMEDIATED / HOST GATE OPEN | Claude + Grok | Swap, crash collection and ordinary allocations can outlive in-process retention; `WitnessBundle` was not zeroized. | PR #652 adds typed best-effort zeroization and drops the parent bundle after handoff. PR #249 disables container swap growth and core dumps. Host swap/crash collection, allocator copies and the STARK working set are not claimed erased and remain pre-start checks. |
| Advisory | REMEDIATED / RE-REVIEW OPEN | Claude + Grok | `ApiToken::matches` used a hand-written compare. | PR #652 uses `subtle::ConstantTimeEq`; token length remains validated separately. |
| Advisory | REMEDIATED / RE-REVIEW OPEN | Grok | `health()` always returned `ready: true`. | PR #652 removes readiness entirely and exposes liveness only. |
| Advisory | OPEN | Claude | One shared-token holder can occupy retained-job slots for the TTL. | Authentication remains intentionally single-operator for the valueless mechanics lane. This must be revisited before shared-client admission. |

The first cross-review of the remediation PRs inspected lab head `3c0670b` and
deploy head `f042080`, not the final commits in §1. Grok and Claude independently
found the same crossed mapping: the prover's node/anchor and scan/nullifier URLs
would both receive `403`. Claude also required the lab branch to be rebased over
the shared HTTP-framing extraction. Those findings were fixed before merge:

- final lab CI exercised merge ref `7a26369f9c621282ba4fa450e983e53b9be3d06a`;
  its wallet network path uses `qlab_http_framing::read_response` and contains no
  private `dechunk` implementation;
- the final deploy mapping is `NODE_URL` → `:8081` → `/v1/anchors` →
  `NODE_AUTHORITY` and `SCAN_URL` → `:8082` → `/v1/nullifiers` →
  `SCAN_AUTHORITY`; a static checker locks the mapping and its negative mutation
  fails;
- the exact pinned Caddy image was validated with both allowed routes and both
  crossed `403` routes; and
- exact-image startup exposed Caddy's file capability interaction with
  `cap_drop: ALL`, so each Caddy now receives only `NET_BIND_SERVICE`; the prover
  receives no capability. The checker locks that shape.

These are implementation-owner observations, not independent closure. Neither
reviewer has yet inspected both final §1 commits. No real proof, live network
isolation test, capacity run, host or public listener is part of this record.

The same pass found the following properties holding in the immutable lab
target once a request reaches application handling: handler accounting
precedes authorization and body parsing; declared and actual body ceilings are
both enforced; cancellation/timeout kills and reaps the child; `SecretBytes`
and the API token zeroize on drop; TTL cleanup also bounds the idempotency map;
and duplicate authorization headers are refused. These are retained
observations, not a verdict.

The two reports independently confirmed that requests cannot select upstream
URLs, inherited worker environment is cleared, worker errors are allowlisted,
job identifiers are unguessable, results are TTL-bounded in process memory,
and the Compose skeleton is loopback-only with the documented privilege/mount
limits. Claude additionally verified in-app SSRF and redirect resistance, TLS
roots and timeouts, worker framing/cancellation, every fixed-error branch and
the no-submission property through the reachable call graph. Grok correctly
retains the filesystem distinction: clearing the child's environment does not
stop that same-UID child reading the mounted token file. The external ingress
shown in the architecture is absent from the deployment skeleton.

## 3. Required independent coverage

Claude Code's independent service-security assignment is **COMPLETE for the
baseline target** in comment 5391401951. It covered the required areas,
including call-graph-level no-submission verification, and disclosed its unrun
live listener, fuzzing and capacity scope. Its lower severity for egress and
its failure to elevate same-UID filesystem token access do not override Grok's
higher public-boundary finding; the implementation owner accepts the stricter
classification.

The completed Claude report covered:

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

Grok's A-only privacy and metadata assignment is **COMPLETE for the baseline
target** in comment 5391355844. It supplied the required observer/data-flow
matrix, covered all eight dispatch areas, separated privacy/availability from
current spend-authority exposure, and disclosed its unrun live-host, ingress,
Candidate A and Candidate B scope. Its public-pilot blockers remain open.

The baseline dispatch instructions are retained in:

- [`prompts/remote-prover-claude-boundary-review.md`](prompts/remote-prover-claude-boundary-review.md)
- [`prompts/remote-prover-grok-privacy-review.md`](prompts/remote-prover-grok-privacy-review.md)

Their preliminary cross-reviews of non-final remediation heads are preserved in
lab [comment 5392271552](https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392271552),
lab [comment 5392245794](https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392245794),
deploy [comment 5392278098](https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392278098)
and deploy [comment 5392246045](https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392246045).
They do not constitute final approval because both heads changed afterward.

The exact final delta-review instructions are:

- [`prompts/remote-prover-claude-remediation-review.md`](prompts/remote-prover-claude-remediation-review.md)
- [`prompts/remote-prover-grok-remediation-review.md`](prompts/remote-prover-grok-remediation-review.md)

Each reviewer must target both final commits in §1, account for every row in
§2, distinguish static evidence from unrun live gates, and post a
commit-addressed report on PR #648. Neither reviewer edits an implementation
branch or approves deployment, capacity, real value or launch.

## 4. Gate-closing rule and next action

The review gate remains open. Current checklist:

1. [x] Claude's complete Internet-boundary report and Grok's independent
   privacy report target the two baseline commits in §1.
2. [x] Codex records a fix, explicit residual or reasoned deferral for every
   finding.
3. [x] Accepted P1 remediation is merged in scoped PRs #652 and #249 with
   regression/static coverage and green CI.
4. [ ] Both reviewers inspect both immutable remediation commits in §1 and
   explicitly account for every original and cross-review finding.
5. [ ] The independent reports agree that no unresolved finding can expose
   spend authority, plaintext witnesses, the client credential, arbitrary
   network access or unauthenticated resource exhaustion at the intended
   isolated capacity boundary.

Only then may an isolated-host capacity task book be prepared. Capacity work
must still be separately approved and must record cold/warm latency, peak RSS
and committed memory, one-worker cancellation and memory release, artifact
sizes, safe concurrency and cost. A green review plus good capacity numbers
still do not approve a valueless pilot: that remains a separate Larry gate.
