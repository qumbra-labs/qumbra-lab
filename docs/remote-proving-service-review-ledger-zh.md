# 远程证明服务 —— Internet-boundary review 账本

**状态：2026-08-24 final remediation review 已完成；可以准备 capacity task book，但不授权
capacity execution。仅限无价值 mechanics。本文不授权 listener、host、pilot、真实价值或
transaction submission。** 英文权威版：
[`remote-proving-service-review-ledger.md`](remote-proving-service-review-ledger.md)。

服务约束以
[`remote-proving-service-mvp-zh.md`](remote-proving-service-mvp-zh.md) 为准。本文把
[`remote-proving-implementation-plan-zh.md`](remote-proving-implementation-plan-zh.md)
里的 independent-review 要求变成 commit-addressed checklist。某个 sub-invariant 打勾，
只说明该小项有证据；§4 说明精确关闭了哪个 gate，以及哪些 gate 仍保持开放。

## 1. 不可变 review targets

首轮 findings 来自以下不可变 baseline artifacts：

| Repository | Immutable target | Artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`7d689df2e303697e34c3e1de2f6650d501141417`](https://github.com/qumbra-labs/qumbra-lab/commit/7d689df2e303697e34c3e1de2f6650d501141417) | PR [#639](https://github.com/qumbra-labs/qumbra-lab/pull/639)：service、worker boundary、Docker target 与服务文档 |
| `qumbra-labs/qumbra-deploy` | [`9987b5545c2c411b7209186292975106b9455cd6`](https://github.com/qumbra-labs/qumbra-deploy/commit/9987b5545c2c411b7209186292975106b9455cd6) | PR [#246](https://github.com/qumbra-labs/qumbra-deploy/pull/246)：standalone loopback-only Compose skeleton 与部署记录 |

最终 delta review 必须检查以下精确成对 remediation tree，不能检查更早 PR head、口头摘要
或之后变化的 `main`：

| Repository | Immutable remediation target | Artifact |
|---|---|---|
| `qumbra-labs/qumbra-lab` | [`702456d4c7315df1ec2838ae729bdcab8edb1342`](https://github.com/qumbra-labs/qumbra-lab/commit/702456d4c7315df1ec2838ae729bdcab8edb1342) | PR [#652](https://github.com/qumbra-labs/qumbra-lab/pull/652)：liveness-only health、bounded upstream read、token compare 与 witness zeroize；parent `dae9f10ec5d57dad5773260a0ad15630e816c12e` |
| `qumbra-labs/qumbra-deploy` | [`33afc24826381778841e3b123401ef56545a7f0f`](https://github.com/qumbra-labs/qumbra-deploy/commit/33afc24826381778841e3b123401ef56545a7f0f) | PR [#249](https://github.com/qumbra-labs/qumbra-deploy/pull/249)：拆分 ingress/prover/egress trust domains、route allowlist 与 runtime hardening；parent `228d57e3d86eb63c32e16f7a319fb453e73a35b0` |

两个 lab target 都有意停留在 Candidate A 之前。`WitnessBundle` 仍是 spend authority，所以
所有 experiment 都必须无价值。Deployment target 仍是 standalone、host-loopback-only；
本文不记录实际 deployment，也不授权 public ingress。

## 2. 当前 findings 与 remediation

首轮 read-only security 检查保存在
[#639 comment 5391225338](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391225338)。
该评论明确声明只完成了部分检查。以下条目在修复或留下有记录理由的 rejection 并完成
独立 re-review 前都保持开放：

Grok 的完整 privacy report 保存在
[#639 comment 5391355844](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391355844)。
Claude 的完整 Internet-boundary report 保存在
[#639 comment 5391401951](https://github.com/qumbra-labs/qumbra-lab/pull/639#issuecomment-5391401951)。
两份 verdict 都只批准 frozen loopback、valueless、仅 Compose render 的 target；都不批准
Internet-facing pilot。报告 severity 不一致时，下表采用更高等级。Claude 与 Grok 已分别
复审最终 remediation pair；状态栏现在区分已确认 remediation 与仍开放的 live/multi-client
gates：

| Effective severity | 当前状态 | 来源 | Finding | Remediation／剩余边界 |
|---|---|---|---|---|
| P1 | COMPOSE PATH 已确认修复／LIVE GATE 开放 | Claude + Grok | `tiny_http::Server::http` 在 application admission 前没有 accepted-socket deadline 或 connection cap。 | PR #249 把未发布的 `tiny_http` 放在具有 header/body/idle deadline 与 96 KiB edge body cap 的 ingress 后面。Binary 单独仍不能作为 listener；live slow-client check 仍是 pre-start gate。 |
| P1 | 已确认修复 | Claude P2；Grok P1 | 未认证 `/healthz` 暴露 load counters 与 build revision。 | PR #652 把 public response 缩减为 `{"alive":true}` 并用 regression test 锁定。它是 liveness，不是 readiness/idleness；invariant probe timing 是仅在 loopback 接受的 advisory。 |
| P1 | CLIENT-CREDENTIAL BOUNDARY 已确认修复／HOP-TOKEN RESIDUAL | Grok | Same-UID worker 可以读取 mounted client API token。 | PR #249 把 client bearer 留在 ingress domain，prover 只获得独立 internal-hop token。Compromised worker 仍可读取并针对自己的 API 滥用 hop token；两位 reviewer 接受该 single-operator lane residual。 |
| P1 | 静态修复已确认／LIVE GATE 开放 | Claude P2；Grok P1 | Worker 持有 spend-authority bundle 时具有 unrestricted bridge egress。 | PR #249 让 prover 只连接两个 `internal: true` network，出站只能经过 GET-only、authority-pinned egress proxy。任何启动前仍必须做 live DNS/SYN/IPv4/IPv6 negative checks。 |
| P2 | 开放／MULTI-CLIENT PILOT 前处理 | Grok | Client-chosen idempotency key 可能成为稳定 identifier，reuse-conflict 是 retention-window existence oracle。 | 未改变。它不阻塞 single-operator loopback capacity measurement；仍属于 per-install auth 与 public API contract 范围。 |
| P2 | 开放／MULTI-CLIENT PILOT 前处理 | Grok | Shared bearer 加泄露 job id 可以读取其他 caller artifact；没有 per-install/per-job holder binding。 | Client 与 hop credential 已拆分，但 caller binding 未变。未授权 public/multi-client pilot。 |
| P2 | WORKER 内已确认修复／EGRESS RESIDUAL 开放 | Claude + Grok | Nullifier preflight 没有 response-byte ceiling，可在 witness 驻留时放大 worker memory。 | PR #652 为 anchor/nullifier read 共用 fail-closed byte budget。Egress 不独立限制 response body，因此 hostile-origin egress-container availability 与已记录的配置 coupling 仍是 capacity stop conditions。 |
| P2 | 部分修复／HOST GATE 开放 | Claude + Grok | Swap、crash collection 与普通 allocation 可活过 in-process retention；`WitnessBundle` 未 zeroize。 | PR #652 加入 typed best-effort zeroize，并在 handoff 后 drop parent bundle。PR #249 禁止 container swap growth 与 core dump。Host swap/crash collection、allocator copies 与 STARK working set 不声称已擦除，仍是 pre-start checks。 |
| Advisory | 已确认修复 | Claude + Grok | `ApiToken::matches` 使用手写 compare。 | PR #652 使用 `subtle::ConstantTimeEq`；token length 仍单独验证。 |
| Advisory | 已确认修复 | Grok | `health()` 永远返回 `ready: true`。 | PR #652 完全移除 readiness，只暴露 liveness。 |
| Advisory | 开放 | Claude | 一个 shared-token holder 可在 TTL 内占满 retained-job slots。 | 无价值 mechanics lane 有意保持 single-operator auth；shared-client admission 前必须重新处理。 |

Remediation PR 首次 cross-review 检查的是 lab head `3c0670b` 与 deploy head `f042080`，并非
§1 最终 commits。Grok 与 Claude 独立发现同一个 crossed mapping：prover 的 node/anchor 和
scan/nullifier URL 都会收到 `403`。Claude 还要求 lab branch rebase 到 shared HTTP-framing
extraction 之后。合并前这些 findings 已修复：

- 最终 lab CI 运行 merge ref `7a26369f9c621282ba4fa450e983e53b9be3d06a`；wallet network
  path 使用 `qlab_http_framing::read_response`，没有私有 `dechunk` implementation；
- 最终 deploy mapping 是 `NODE_URL` → `:8081` → `/v1/anchors` → `NODE_AUTHORITY`，以及
  `SCAN_URL` → `:8082` → `/v1/nullifiers` → `SCAN_AUTHORITY`；static checker 锁定该 mapping，
  negative mutation 会失败；
- exact pinned Caddy image 已验证两个 allowed routes 与两个 crossed `403` routes；以及
- exact-image startup 暴露 Caddy file capability 与 `cap_drop: ALL` 的 interaction，所以
  每个 Caddy 只获得 `NET_BIND_SERVICE`，prover 不获得 capability；checker 锁定该 shape。

两份 final reports 已分别在精确 §1 commits 上确认这些 implementation observations。本文
不包含 real proof、live network isolation、capacity run、host 或 public listener。

同一轮检查认为 immutable lab target 在 request 进入 application handling 后的以下性质成立：
handler accounting 先于 authorization 与 body parsing；同时执行 declared 与 actual body
ceilings；cancel/timeout 会 kill 并 reap child；`SecretBytes` 与 API token 在 drop 时
zeroize；TTL cleanup 同时约束 idempotency map；重复 authorization headers 会被拒绝。
这些只是保留的 observations，不是 verdict。

两份报告独立确认：request 不能选择 upstream URL，worker inherited environment 已清空，
worker error 有 allowlist，job identifiers 不可猜，result 在 process memory 中受 TTL 约束，
Compose skeleton 保持 loopback-only 并具备已记录的 privilege/mount limits。Claude 还验证了
in-app SSRF/redirect resistance、TLS roots/timeouts、worker framing/cancellation、全部 fixed-error
branches，以及 reachable call graph 上的 no-submission property。Grok 正确保留了 filesystem
区别：清空 child environment 不能阻止 same-UID child 读取 mounted token file。架构图里的
external ingress 并未出现在 deployment skeleton 中。

## 3. 必须完成的独立覆盖

Claude Code 的独立 service-security assignment 对 baseline target 已**完成**，记录在 comment
5391401951。它覆盖了要求的 areas，包括 call-graph-level no-submission verification，并披露
未运行 live listener、fuzzing 与 capacity。它对 egress 的较低 severity，以及未把 same-UID
filesystem token access 升级，不能推翻 Grok 较高的 public-boundary finding；implementation
owner 采用更严格分级。

已完成的 Claude report 覆盖：

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

Grok 的 A-only privacy 与 metadata assignment 对 baseline target 已**完成**，记录在 comment
5391355844。它给出了要求的 observer/data-flow matrix，覆盖全部八个 dispatch areas，区分了
privacy/availability 与当前 spend-authority exposure，并如实披露未运行的 live-host、ingress、
Candidate A 与 Candidate B scope。它列出的 public-pilot blockers 仍保持开放。

Baseline 精确派发指令保存在：

- [`prompts/remote-prover-claude-boundary-review.md`](prompts/remote-prover-claude-boundary-review.md)
- [`prompts/remote-prover-grok-privacy-review.md`](prompts/remote-prover-grok-privacy-review.md)

两位 reviewer 对 non-final remediation heads 的 preliminary cross-review 保存在 lab
[comment 5392271552](https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392271552)、
lab [comment 5392245794](https://github.com/qumbra-labs/qumbra-lab/pull/652#issuecomment-5392245794)、
deploy [comment 5392278098](https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392278098)
与 deploy [comment 5392246045](https://github.com/qumbra-labs/qumbra-deploy/pull/249#issuecomment-5392246045)。
由于两条 head 随后都改变，这些不是 final approval。

Final delta-review 精确指令是：

- [`prompts/remote-prover-claude-remediation-review.md`](prompts/remote-prover-claude-remediation-review.md)
- [`prompts/remote-prover-grok-remediation-review.md`](prompts/remote-prover-grok-remediation-review.md)

两份 final report 都针对 §1 精确 pair 返回，无 drift：

- Claude Code
  [comment 5393523859](https://github.com/qumbra-labs/qumbra-lab/pull/648#issuecomment-5393523859)：
  对 capacity task-book preparation 给出 **approve with non-blocking findings**；
- Grok 4.6
  [comment 5393591701](https://github.com/qumbra-labs/qumbra-lab/pull/648#issuecomment-5393591701)：
  对同一 boundary 给出 **approve with non-blocking findings**。

两份 report 都逐条交代 §2 与两个 preliminary blockers，没有发现新的 P0/P1 blocker。其澄清的
non-blocking residual 是 task book 的 binding inputs：

- 启动前必须检查 token file 为 32–256 bytes、精确 ownership 且**没有 CR/LF**；依赖
  application trim 会 fail closed 为静默 `401`，不能作为 provisioning gate；
- 未认证 invariant health response 在 load 下仍可能携带 timing signal，只在 loopback
  single-operator measurement 接受；
- 8 MiB worker budget 仍是唯一 upstream response-body ceiling；egress OOM/stream stall 是
  stop condition，提升 budget 需要重新 review；以及
- same-UID worker 可以读取 internal-hop token 并针对 parent API 使用。这是已承认 residual，
  不是 client-credential exposure。

两位 reviewer 都没有修改 implementation branch，也没有批准 capacity execution、deployment、
host、public ingress、real value 或 launch。

## 4. Review 结果与下一步

Final remediation-review gate 已完成，可**准备** isolated、single-operator、loopback-only
capacity task book。当前 checklist：

1. [x] Claude 完整 Internet-boundary report 与 Grok 独立 privacy report 针对 §1 两个
   baseline commits。
2. [x] Codex 对每条 finding 记录 fix、明确 residual 或 reasoned deferral。
3. [x] 已接受 P1 remediation 在 scoped PR #652/#249 中合并，具有 regression/static
   coverage 与绿色 CI。
4. [x] 两位 reviewer 都检查 §1 两个 immutable remediation commits，并逐条交代原 finding
   与 cross-review finding。
5. [x] 两份 report 一致认为，计划中的 capacity boundary 没有 unresolved remediation
   regression 会暴露 **client** credential、arbitrary network access、unauthenticated health
   state 或 unbounded worker-side upstream body retention。被承认的 pre-Candidate-A worker
   仍可看到 plaintext spend authority，因此 experiment 必须严格无价值。

下一项允许的 action 是 docs-only isolated-host capacity task book。它必须在接受任何 witness
之前安排两位 reviewer 的 live gates：exact image/digest read-back；不打印 value 的 token
byte/ownership/CRLF checks；pinned image 上两条 allowed 与 crossed egress routes；ingress
slow-client deadlines；从 prover namespace 做 IPv4/IPv6 DNS/SYN/default-route negatives；host
swap/crash/log-shipper checks；target engine swap-limit behavior；以及 egress OOM/stall 与异常
hop-token behavior stop conditions。随后必须定义 cold/warm latency、peak RSS/committed memory、
one-worker cancel/memory release、artifact sizes、safe concurrency 与 cost evidence。

准备 task book **不授权** capacity execution、host、image pull、token provisioning、listener、
proof、public pilot、real value 或 launch。每项仍需 Larry 单独 gate。
