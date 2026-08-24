# 远程证明服务 —— Internet-boundary review 账本

**状态：2026-08-24 的开放 review gate。仅限无价值 mechanics。本文不授权 listener、
host、pilot、真实价值或 transaction submission。** 英文权威版：
[`remote-proving-service-review-ledger.md`](remote-proving-service-review-ledger.md)。

服务约束以
[`remote-proving-service-mvp-zh.md`](remote-proving-service-mvp-zh.md) 为准。本文把
[`remote-proving-implementation-plan-zh.md`](remote-proving-implementation-plan-zh.md)
里的 independent-review 要求变成 commit-addressed checklist。某个 sub-invariant 打勾，
只说明该小项有证据；不等于整个 review gate 已关闭。

## 1. 不可变 review target

Reviewer 必须检查以下精确 merged artifacts，不能只看口头总结或之后变化的 `main`：

| Repository | Immutable target | Artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`7d689df2e303697e34c3e1de2f6650d501141417`](https://github.com/qumbra-labs/qumbra-lab/commit/7d689df2e303697e34c3e1de2f6650d501141417) | PR [#639](https://github.com/qumbra-labs/qumbra-lab/pull/639)：service、worker boundary、Docker target 与服务文档 |
| `qumbra-labs/qumbra-deploy` | [`9987b5545c2c411b7209186292975106b9455cd6`](https://github.com/qumbra-labs/qumbra-deploy/commit/9987b5545c2c411b7209186292975106b9455cd6) | PR [#246](https://github.com/qumbra-labs/qumbra-deploy/pull/246)：standalone loopback-only Compose skeleton 与部署记录 |

Lab target 有意停留在 Candidate A 之前。它的 `WitnessBundle` 仍是 spend authority，所以
所有 experiment 都必须无价值。Deployment target 是静态 review skeleton，不是已部署
ingress。

## 2. 当前已有 findings

首轮 read-only security 检查保存在
[#639 comment 5391225338](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338)。
该评论明确声明只完成了部分检查。以下条目在修复或留下有记录理由的 rejection 并完成
独立 re-review 前都保持开放：

Grok 的完整 privacy report 保存在
[#639 comment 5391355844](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391355844)。
它只批准 frozen loopback、valueless、仅 Compose render 的 target，并明确**不批准**
Internet-facing pilot。两轮 severity 不一致时，下表采用更高等级：

| Effective severity | 状态 | 来源 | Finding／所需处理 |
|---|---|---|---|
| P1 | OPEN | 两者 | `tiny_http::Server::http` 没有 accepted-socket read deadline 或 connection cap。`MAX_HTTP_HANDLERS` 在完整 request 已被接收后才计数，因此 unauthenticated slow/incomplete headers 可以在 admission accounting 之前消耗 listener resources。 |
| P1 | OPEN | security pass P2；Grok P1 | 未认证 `/healthz` 暴露 `queued`、`running`、`retained`、`queue_capacity` 与 `build_revision`，可以观察 load/timing 并做精确 version fingerprinting。Public liveness 不需要这些逐服务 activity counters。 |
| P1 | OPEN | Grok | 被攻破的 same-UID worker 可以读取 mounted shared API token；一个泄露 credential 就代表整个 experiment identity，并能读取任何另行泄露 job capability 对应的结果。 |
| P1 | OPEN | Grok | Default bridge 没有 egress allowlist，因此持有当前 spend-authority bundle 的 compromised worker 可以向任意目的地 exfiltrate。 |
| P2 | OPEN | Grok | Client-chosen idempotency key 可能成为跨 attempt 的稳定 identifier；retention 期间 reuse-conflict response 还是 existence oracle。 |
| P2 | OPEN | Grok | Shared bearer 加泄露 job identifier 可以读取其他 caller 的完整 artifact；没有 per-install 或 per-job holder binding。 |
| P2 | OPEN | Grok | Nullifier preflight 覆盖 `0..=tip`，可达 HTTP read 没有 response-byte ceiling；pinned/compromised upstream 可以在 witness 仍驻留时放大内存。 |
| P2 | OPEN | Grok | Host swap 或 crash collection 可以活得比 in-process retention window 更久；只禁用 core 不能关闭 host/cloud persistence。 |
| Advisory | OPEN | 两者 | `ApiToken::matches` 使用手写 compare，没有 optimizer-resistant constant-time primitive。需要决定替换，或保留并记录理由。 |
| Advisory | OPEN | Grok | `health()` 永远返回 `ready: true`；不能把它当成 prover readiness 或 idleness。 |

同一轮检查认为 immutable lab target 在 request 进入 application handling 后的以下性质成立：
handler accounting 先于 authorization 与 body parsing；同时执行 declared 与 actual body
ceilings；cancel/timeout 会 kill 并 reap child；`SecretBytes` 与 API token 在 drop 时
zeroize；TTL cleanup 同时约束 idempotency map；重复 authorization headers 会被拒绝。
这些只是保留的 observations，不是 verdict。

Grok 独立确认：当前 service crate 没有 `spend::submit` call，request 不能选择 upstream URL，
worker inherited environment 已清空，worker error 有 allowlist，job identifiers 不可猜，result
在 process memory 中受 TTL 约束，Compose skeleton 保持 loopback-only 并具备已记录的
privilege/mount limits。它也确认 `env_clear` 不是 worker isolation，架构图里的 external
ingress 并未出现在 skeleton 中。Claude 仍需完成下述更广的 security/call-graph review。

## 3. 必须完成的独立覆盖

Claude Code 必须独立复现或否定已记录 finding，并完成所有 service-security invariants。
最低覆盖范围：

- 沿所有 request fields 与 dependency call paths 检查 request-selected endpoint、redirect、
  DNS rebinding、upstream identity、response byte/time ceilings 与 SSRF；
- 追踪 HTTP parsing、decoded copies、queue、pipes、child memory、result/error handling、
  cancellation、panic 与 teardown 的 plaintext witness 生命周期；
- 确认 worker 在收到 witness 前已清空 environment，并判断 same-UID token mount 与没有
  限制的 bridge egress 仍允许什么；
- 检查每条 branch 的 fixed-error suppression，包括 worker panic 与 upstream failures；
- 穷尽 code/dependency search，证明 API 与 worker 不存在 transaction-submission path；
- 检查 connection/header/body slow-client 行为、handler/thread/queue bounds、idempotency
  races、job capability、cancellation races 与 child output framing；以及
- 检查 deploy skeleton 的 filesystem、privilege、PID/memory/CPU/core-dump、secret、network
  与 image-digest boundaries。

Grok 的 A-only privacy 与 metadata assignment 对 immutable target 已**完成**，记录在 comment
5391355844。它给出了要求的 observer/data-flow matrix，覆盖全部八个 dispatch areas，区分了
privacy/availability 与当前 spend-authority exposure，并如实披露未运行的 live-host、ingress、
Candidate A 与 Candidate B scope。它列出的 public-pilot blockers 仍保持开放。

精确派发指令保存在：

- [`prompts/remote-prover-claude-boundary-review.md`](prompts/remote-prover-claude-boundary-review.md)
- [`prompts/remote-prover-grok-privacy-review.md`](prompts/remote-prover-grok-privacy-review.md)

每位 reviewer 都必须把 finding 分成 P0/P1/P2 或 advisory，引用 file/line 或 reproducible
invariant，列出被攻击但成立的性质，如实说明未检查或未运行项，并在 lab PR #639 发布
commit-addressed report。两位 reviewer 都不修改 implementation branch。

## 4. Gate 关闭规则与下一步

只有以下项目全部留档，review gate 才能关闭：

1. Claude 的完整 Internet-boundary report 与 Grok 的独立 privacy report 都针对 §1 的
   两个 commits；Grok 已完成，Claude 仍未完成；
2. Codex 对每条 finding 留下 fix 或 reasoned rejection；
3. 每个被接受的 P0/P1 都在 scoped PR 中修复并带 regression coverage；
4. 两位 reviewer 都检查 immutable remediation commit，并逐条交代原 findings 与所需覆盖
   项；以及
5. 在计划中的 pilot boundary，没有 unresolved finding 能暴露 spend authority、plaintext
   witness、reusable credential、arbitrary network access 或 unauthenticated resource
   exhaustion。

满足后才可以准备 isolated-host capacity task book。Capacity 仍需单独批准，并必须记录
cold/warm latency、peak RSS 与 committed memory、one-worker cancel 与 memory release、
artifact sizes、safe concurrency 与 cost。Review 绿色和 capacity 数字良好仍不批准 valueless
pilot；后者继续由 Larry 单独 gate。
