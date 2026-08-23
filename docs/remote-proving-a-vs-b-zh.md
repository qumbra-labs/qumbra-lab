# 远程证明 —— Grok 的 A 对 B 判断（作为选型已被取代）

**作者:Grok 4.6（xAI），2026-08-23。** 本文记录的是 **Grok** 的 A-or-B 判断。
不是 Larry 的裁定，也不是 lab 共识。

**状态:作为 launch-basis 选型已被取代。** Larry 接受的裁定是
[`remote-proving-candidate-ruling-zh.md`](remote-proving-candidate-ruling-zh.md)。
不要引用本文，把它说成 Larry 或 lab 把 B 选成了必选项。
英文权威版:[`remote-proving-a-vs-b.md`](remote-proving-a-vs-b.md)。

写于 `claude/remote-proving-ab-pick` worktree，在读完
[`remote-proving-decision-zh.md`](remote-proving-decision-zh.md)（PR #620）之后。
随后 PR #621 / PR #623 记录了 Larry 的裁定。保留本文，是为了让 Grok 的论证有署名、
能找到。

---

## Grok 的判断

Grok 在 2026-08-23 的选型:

- **A 是承重的协议目的地。** 花费安全必须是共识绑定、worker 无法伪造的手机持有
  授权。手机不能自证 b16、用户运营常驻 prover 又被排除之后，这是唯一匹配 Qumbra
  「密码学、无 trusted setup」设计的盗币模型。
- **B 是 Qumbra 运营默认 send 路径上必须有的隐私层**，不是 A 的替代品。只有 A
  会把一台 viewing oracle 交给官方服务:selected inputs、金额、收款/找零，以及
  `nk`（full-viewing-class）。
- **单靠 B 不是盗币模型。** 它的「不能盗」绑在 SEV-SNP/TDX、firmware、cloud、
  attestation 与 side-channel 上。一次足够强、能读取或改写 confidential worker
  的破裂，可以把花费完整性与 witness 保密性两道保证一起打穿。
- 现稿 Hash-OTS **不是** A。保留 `rkm` root-binding 接缝。Authorization spike
  默认用标准化 stateless leaf（先 ML-DSA），直到父记录 §6 的 P0 关闭。

如果父记录矩阵只能标一格，Grok 标的是 **A**。在 Grok 看来，真实价值仍要两道
门槛都过:A 管盗币，B 管默认手机路径上的 witness 可见性。

---

## Larry 后来裁定的是什么

PR #621 与 PR #623 记录的是 Larry 的裁定，不是 Grok 的:

- 所有承载真实价值的共享 prover **强制 A**。
- **B 是可选 defense-in-depth**，不是资金安全 trust root，也不是上线前提。
- 只要诚实写明 privacy boundary，允许只有 A。
- B-only 仍只可用于无价值实验。
- authorization primitive 仍未选定。

Grok 做出、**没有落地**的那一条是「官方默认路径上 B 必选」。Larry 的裁定允许
官方服务只跑 A。

架构、invariants、执行顺序与 TEE/ML-DSA 来源读 candidate ruling。上线门槛读
[`remote-proving-decision-zh.md`](remote-proving-decision-zh.md)。
