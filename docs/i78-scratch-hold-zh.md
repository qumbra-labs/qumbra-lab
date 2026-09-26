# Issue #78：在两次写入之间保持 scratch 值

[English（技术权威版本）](i78-scratch-hold.md)。范围：[issue #78](https://github.com/qumbra-labs/qumbra-lab/issues/78) 的 finding 2，也是 [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750) 的前置工作。

原测试 `i78_finding2_scr_no_hold` 故意断言：在 M_FHI 写入 SCR0 后、下次读取前
修改它，约束仍然 SAT。它证明缺少保持约束，不代表已经构造了完整 proof 伪造。
本次把同一篡改翻转为 `gate_neg_scr_no_hold`，要求 UNSAT，并补充跨 permutation、
wide 和 interior 覆盖。

## 约束变化

每个 scratch slot 的写入选择器由已有、已绑定的选择器组成：

- leaf fold：会写入该 slot 的各轮 `GF[round] * VC[2 * slot + 1]`；
- higher fold：对应的物化 `FHG`，排除写入 RUNEV 的最后一对；
- reduced opening：`M_RO * step[row]`，SCR0..4 分别在行 0、1、2、4、6 写入。

新增 transition 约束为 `(1 - writes[slot]) * (next_scr - scr) == 0`，原有写入
约束保留。phase/query 路由使这些写入选择器互斥，因此每个 slot 要么写入、要么保持。
补集同时覆盖 permutation 间隔、child 边界、padding 和 merge 行。
现有 witness generator 已将 SCR 继承给第二个 child，并在尾部保持最后一个 child
的寄存器，所以无需更改 fill，也无需豁免边界。

源代码推导成本 **[P]**：8 个 extension slot × 4 个 limb = **32 条约束**，
**不增加列**，新增约束最大 degree 为 **3**。这些不是证明耗时或内存实测。
原有 degree、宽高回归门槛保留。交易 AIR、共识参数和已提交交易 fixture 不变；
实验性 M4 verifier AIR 的约束增强，其测试 proof 会按新约束重新生成。

## 测试和剩余工作

- 翻转 narrow 的历史自由区间测试，保留 RUNEV 拒绝对照；
- 在没有 fold 读取的位置，跨 permutation 边界篡改 SCR7；
- 在已有 wide negative 中加入自由区间篡改，并分别覆盖 distinct two-child
  interior 的左右 child；
- 复用原有 narrow/wide/interior 诚实轨迹和符号 degree 检查。篡改后重算派生列，
  避免陈旧辅助值造成假拒绝。

未在本地运行测试、证明或测量。workspace 编译通过；测试是否成功以 PR 对应的
完整 Graviton 验收为准。

未验证事项按最可能失败排序：wide/interior 边界的诚实轨迹兼容性、新增拒绝用例、
目标机器性能。Finding 4（W0C/W1C 与 sponge 的绑定）仍未解决，prototype 仍缺少
完整 AIR/quotient 验证。本次不关闭 issue #78，不宣布递归 soundness 或 F2 内存通过。
