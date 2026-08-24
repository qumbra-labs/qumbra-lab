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

首轮 read-only 检查保存在
[#639 comment 5391225338](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338)。
该评论明确声明只完成了部分检查。以下条目在修复或留下有记录理由的 rejection 并完成
独立 re-review 前都保持开放：

| Severity | 状态 | Finding／所需处理 |
|---|---|---|
| P1 | OPEN | `tiny_http::Server::http` 没有 accepted-socket read deadline 或 connection cap。`MAX_HTTP_HANDLERS` 在完整 request 已被接收后才计数，因此 unauthenticated slow/incomplete headers 可以在 admission accounting 之前消耗 listener resources。 |
| P2 | OPEN | 未认证 `/healthz` 暴露 `queued`、`running`、`retained`、`queue_capacity` 与 `build_revision`，可以观察 load/timing 并做精确 version fingerprinting。Public liveness 不需要这些逐服务 activity counters。 |
| Advisory | OPEN | `ApiToken::matches` 使用手写 compare，没有 optimizer-resistant constant-time primitive。需要决定替换，或保留并记录理由。 |

同一轮检查认为 immutable lab target 在 request 进入 application handling 后的以下性质成立：
handler accounting 先于 authorization 与 body parsing；同时执行 declared 与 actual body
ceilings；cancel/timeout 会 kill 并 reap child；`SecretBytes` 与 API token 在 drop 时
zeroize；TTL cleanup 同时约束 idempotency map；重复 authorization headers 会被拒绝。
这些只是保留的 observations，不是 verdict。

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

Grok 必须独立给出 A-only privacy 与 metadata report。最低覆盖范围：列出 client、ingress、
API、worker、read endpoints、operator、container host、logging/crash tooling 与 attacker 分别
能看见什么；测试 IP/device/timing/job/polling/upstream/on-chain correlation；检查 plaintext
copies 与 retention；挑战 `/healthz`、refusal/timing oracles；并准确说明 Candidate A 能与不能
解决哪些风险。

精确派发指令保存在：

- [`prompts/remote-prover-claude-boundary-review.md`](prompts/remote-prover-claude-boundary-review.md)
- [`prompts/remote-prover-grok-privacy-review.md`](prompts/remote-prover-grok-privacy-review.md)

每位 reviewer 都必须把 finding 分成 P0/P1/P2 或 advisory，引用 file/line 或 reproducible
invariant，列出被攻击但成立的性质，如实说明未检查或未运行项，并在 lab PR #639 发布
commit-addressed report。两位 reviewer 都不修改 implementation branch。

## 4. Gate 关闭规则与下一步

只有以下项目全部留档，review gate 才能关闭：

1. Claude 的完整 Internet-boundary report 与 Grok 的独立 privacy report 都针对 §1 的
   两个 commits；
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
