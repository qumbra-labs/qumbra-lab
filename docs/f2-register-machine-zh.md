# F2：寄存器调度与受约束的参考执行器

[English（技术权威）](f2-register-machine.md)。依据 [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750)，接在 [PR #754](https://github.com/qumbra-labs/qumbra-lab/pull/754) 的可执行 OOD 算术模型之后。

OOD DAG 现在具备寄存器调度。另有一个**仅用于测试的参考 AIR**，约束相同的指令
语义以及寄存器读取、写入、保持。这是正确性检查点，不是最终聚合布局。
完整 S3/P3/R 调度通过稀疏执行与 DAG 对拍，没有分配或 prove 其大型 AIR trace；
参考 AIR 仅在有界组件程序上检查。

## 调度

编译器拒绝缺失的输出和非拓扑引用。迭代式深度优先遍历按依赖顺序输出可达节点，
在首次需要时加载输入和常量。共享节点只执行一次，不可达节点被省略。
最后一次使用分析在指令读取后释放源寄存器，因此目标可以复用该寄存器。
重复操作数不会重复释放，导出的结果持续存活到终止行。

OOD 程序导出 residual 和 trace-next opening point。稀疏执行逐条比较**每条指令
结果**与原始 DAG 节点，然后检查输出寄存器是否仍保留正确结果。这已接入既有
原生/DAG 对拍，包括合成输入与真实 proof 的篡改检查。只比较最终 residual
可能漏掉效果恰好抵消的寄存器错误复用。

## 参考 AIR

每行包含扩展域值 A/B/C 与寄存器文件，每个值展开成四个 KoalaBear limb。
固定、整周期的列编码 opcode、源/目标选择、常量和公共输入选择。
这些是 AIR 自带的 ROM，不是证明者可选的 witness 标志。七种指令分别为
input、constant、add、subtract、negate、multiply、inverse；padding 有独立固定选择器。

- A/B 必须等于选中的当前行寄存器；没有操作数时为零。
- 算术约束确定 C，乘法模 `X^4 - 3`，inverse 满足 `A * C = 1`；零没有合法逆元 witness。
- 所有寄存器初始为零。每个 transition 满足
  `next_r - r = write_selector * (C - r)`，同时覆盖写入和所有未写入位置的保持。
- Input 将 C 绑定到选中的公共扩展域 limb，constant 将 C 绑定到 ROM 常量。
  最后一行将输出寄存器绑定到预期公共输出。F2 接入时必须把 residual 输出固定为零。
- Padding 强制 A/B/C 为零并保持寄存器。最后一条指令之后必有终止行，
  因此最终写入不会逃过 transition 约束。

这里的输入是**组件公共值**，尚不是经认证的 PCS/Fiat–Shamir 连线。
该组件证明固定程序在声明输入上的执行，不证明输入来自某个 proof、不证明标为
`Public` 的源已经接到原交易 PV，也不证明 challenge 来自 transcript。
这些接入绑定仍然需要实现。

## 成本计入

Price 模式的 `ood_arithmetic` 或 census 模式的 `ood_algebra.arithmetic`
新增 `register_schedule`，标为 **P**，来自编译后的调度。报告指令数、被省略节点、
分配的扩展域寄存器峰值、逻辑输入来源、输出数、padded 行数，以及 trace 和
参考 ROM 各自的原始存储量。

对于 R 个寄存器、I 个输入值和 K 条指令，参考尺寸为 **[P，源码推导]**：

```text
trace 宽度 = 12 + 4R
ROM 宽度   = 12 + 3R + I
高度       = next_power_of_two(K + 1)
原始字节数 = 4 * 宽度 * 高度，trace 与 ROM 分开计算
```

整周期 ROM 的成本已经列出，不视作免费的 verifier 元数据。这些是原始基域矩阵，
不是 prover 峰值 RSS；不包含 LDE、quotient/FRI、allocator/workspace 或与 hiding
PCS/Keccak lane 组合的成本。Dense 构造在分配前检查调用者给定的 trace 加 ROM
总 cell 预算。CLI 只报告稀疏调度。

参考约束 degree 不超过三 **[P，由 CI 检查]**。四个新测试覆盖原生扩展域算术、
degree、每个结果 limb、操作数读取、写入目标、不读不写的存活寄存器间隙、
首尾行和 padding。协调篡改会为另一组输入或另一种 opcode 调度重算完整 trace
及匹配输出，仍必须被原输入/程序绑定拒绝。零逆元检查保持写入、carry 和公共输出
一致，使逆元等式本身必须拒绝。另覆盖错误 DAG、重复输出和分配预算。

## 验证与后续工作

没有也不允许在本地运行测试、生成 proof 或 benchmark。本地 workspace 编译和
限定范围 Clippy 用于预检查，完整 `verify-graviton` CI 才是验收门槛。
在已合并的 2730 项基线上新增四项，预期为 2734 项通过 **[P，待 CI]**。

尚未验证、按最可能先出问题排序：参考 AIR 回归与完整 shape 稀疏寄存器对拍
（待 CI）；可用的认证输入路由/ROM 布局；真实尺寸的完整 OOD AIR；hiding PCS
组合及目标机器内存。`full_ood_air_checked`、`pcs_input_bindings_complete`、
`complete_verifier_layout`、`memory_gate_pass` 均保持 false。
不修改 transaction AIR、共识参数、proof fixture、lockfile 或部署。
