# 远程证明 —— A 对 B 调研（已取代）

**状态:2026-08-23 已被取代。** 当前选型是
[`remote-proving-candidate-ruling-zh.md`](remote-proving-candidate-ruling-zh.md)。
不要把本文当 launch-basis 决策。
英文权威版:[`remote-proving-a-vs-b.md`](remote-proving-a-vs-b.md)。

写于 2026-08-23,是 PR #621 / PR #623 落地前的调研笔记。保留只为能找到裁定前的
论证。

---

## 这份笔记当时的推荐

- **A** 作为承重的协议目的地:共识绑定、worker 无法伪造的手机持有授权。
- **B** 作为 Qumbra 运营默认 send 路径上**必须有**的隐私层,因为只有 A 会把一台
  viewing oracle 交给服务（`nk` 是 full-viewing-class）。
- 现稿 Hash-OTS 不是 A;保留 `rkm` root-binding 接缝,authorization spike 默认用
  标准化 stateless leaf（先 ML-DSA）。

## 后来真正接受的是什么

PR #621 与 PR #623 记录了 Larry 的裁定:

- 所有承载真实价值的共享 prover **强制 A**。
- **B 是可选 defense-in-depth**,不是资金安全 trust root,也不是上线前提。
- 只要诚实写明 privacy boundary,允许只有 A。
- B-only 仍只可用于无价值实验。
- authorization primitive 仍未选定。

这份笔记里**没有落地**的那一条:B 作为必须 overlay。接受的裁定允许官方服务只跑
A。

架构、invariants、执行顺序与 TEE/ML-DSA 来源读 candidate ruling。上线门槛读
[`remote-proving-decision-zh.md`](remote-proving-decision-zh.md)。
