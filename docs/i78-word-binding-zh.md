# Issue #78：将被消费的 word 绑定到 sponge

[English（技术权威）](i78-word-binding.md)。范围为 [issue #78](https://github.com/qumbra-labs/qumbra-lab/issues/78) 的 finding 4，接在 [PR #752](https://github.com/qumbra-labs/qumbra-lab/pull/752) 的 SCR carry 修复之后，也是 [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750) 的前置工作。

M4 算术流水线消费 `W0C/W1C`，其中包括经 ASM 拼装的值的两半。此前 word
恢复约束只在 F0 permutation 生效，duplicate chain、final-polynomial flush
和 query leaf absorb 缺少到 sponge 输入的直接绑定。单独修改一个 word
可能早已被下游算术约束拒绝，但这不能证明存在 sponge 绑定。

## 绑定范围与成本

复用既有的直接恢复和逐位 XOR 恢复约束，扩展生效范围：

| Permutation | 恢复方式 |
|---|---|
| 每个 observation flush 的首块 | 直接读取 preimage rate |
| 后续 observation 块，原始 F2 除外 | preimage XOR 前一输出 rate |
| Refill | 直接读取 preimage rate |
| Duplicate 首块 | 直接读取 preimage rate |
| Duplicate 后续块 | preimage XOR 前一输出 rate |
| Query leaf absorb 的 role 1–5，包含 continuation | 直接读取 preimage rate（overwrite sponge） |
| 原始 F2 中间块、query arithmetic/path、padding、merge | 不绑定 routed word；这些位置不消费这些单元 |

原始 F2 中间块没有填充 routed word。被消费的 opening 来自 duplicate chain，
既有 digest 比较把该链绑定到原始 observation。本次不修改该比较或 witness 填充。

令 `O0` 为 observation 首块选择器之和，`OX` 为除 F2 外后续块选择器之和，
`QA` 为 query absorb-role 选择器之和。既有 materialization 已约束
`xsel = phd*(1-cmpc) + OX`。现在使用：

```text
gxor = xsel
gdir = O0 + refsel + phd - xsel + OX + QA
```

因此 duplicate 首块项在代数上等于 `phd*cmpc`，但表达式只使用线性列。
乘以 degree-2 row mux 后仍不超过 degree 3。源码推导成本 **[P]**：
**0 新列、0 新约束**，复用原有 **140** 条恢复约束覆盖更多 permutation。
没有声称证明时间或内存有所改善。

## 能区分修复前后的检查

既有 narrow、wide 和不同双子节点 SAT 测试复用已经分配的 trace，增加组件检查。
每个子节点的每个 permutation 都将约束 gate 与 recorder schedule 的独立分类比较。
每类 observation/direct/XOR/query-role-and-batch 选取代表行，覆盖首尾 rate 行、
首尾非 rate 行、两个 word 列，以及保持布尔性的 preimage/output 分解位篡改。

仅用于测试的 F0-only 参考组件计算相同恢复等式。在 F0 之外，被消费 word 的
篡改通过旧组件，却被扩展后的组件拒绝，从而把本次绑定与下游 accumulator
约束的反向限制区分开。这是组件回归检查，不是完整伪造 proof 的构造。
另检查 padding/merge gate 不生效，并在既有 symbolic degree 检查中固定组件约束数。

## 验证与限制

本地 `cargo check --workspace --all-targets --locked` 和
`cargo clippy -p qlab-bench --all-targets --locked` 通过；Clippy 存在仓库原有警告。
没有本地运行测试、生成 proof 或测量性能。完整 Graviton 验收待完成。
只扩展既有测试函数的断言，预期测试计数仍是前置分支的 2721 项通过 **[P，待 CI]**。

本次修改实验性 M4 verifier AIR。Transaction AIR、共识参数、已提交 transaction
fixture、lockfile 和部署不变。生成的 M4 proof 必须使用加强后的 AIR。
尚未验证、按最可能先出问题排序：真实 wide/interior trace 与扩展绑定的兼容性
（待 CI）；新增组件拒绝检查（待 CI）；目标机器上的成本。
完整 AIR/quotient 验证和 hiding leaf 接入仍未完成。本次不关闭 issue #78，
不宣称完整递归健全性，也不代表 F2 内存门槛通过。
