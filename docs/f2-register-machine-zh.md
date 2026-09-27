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

这里的输入是**组件公共值**，尚不是经认证的 PCS/Fiat–Shamir 连线
（下文 F2b-2a 在测试组件里补上了这层绑定，FRI 那一半仍未做）。
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

## F2b-2a：输入绑定到 transcript

F2b-2a 把参考执行器的公共 limb 输入，换成在电路内绑定到一份**重放的**
Fiat–Shamir transcript 上的输入。这份 transcript 来自一个真实的 **hiding**
uni-stark proof，绑定范围一直到 opened values 被吸收为止。它仍然是只用于测试的组件
（`crates/qlab-bench/src/f2/ood/bind.rs`），和参考 AIR 一样逐行扫描，不做 prove。
fixture 是一个两列、degree 3 的玩具 AIR，在测试里用 L2 lane 加固定种子的 hiding
config 现场生成 proof，所以 CI 每次重放的都是同一份 transcript。仓库里不提交 fixture 文件。

### 绑定了什么

同一组行上放了三样东西：Keccak lane（原版 p3-keccak-air，经 m4skel 的
`LaneBuilder` 接入，每个置换 24 行）、sponge 与 Fiat–Shamir 绑定，以及寄存器执行器。

- **Sponge。** 每个置换的第 0 步那一行带着本块的消息位 `M` 和上一个输出的 rate
  位 `S`，preimage 逐 limb 等于 `M xor S`。块在 flush 内部时 `S` 取上一置换的输出，
  flush 的第一块则 `S` 为零；capacity 或者沿用，或者从零开始。哪个置换开启一次 flush，
  由周期选择列定死，证明者没有选择余地。
- **Transcript 顺序**（已对照 p3-uni-stark 0.6.1 `verifier.rs` 和 p3-fri
  `two_adic_pcs.rs` 核对）：F0 = committed degree bits ‖ original degree bits ‖
  preprocessed 宽度 0 ‖ trace cap ‖ PVs，随后抽 α；F1 = D0 ‖ quotient cap ‖
  randomizer cap，随后抽 ζ；F2 = D1 ‖ randomizer opening（4 个扩展域值）‖ trace local ‖
  trace next ‖ quotient chunks。randomizer opening 参与哈希，但不接入执行器，
  因为它不出现在 OOD 等式里。`zeta_next` 用的是原始域 N（trace 提交在 2N 上），
  执行器的 next-point 输出固定为 `g_N · ζ`。
- **每个块的每个 rate 字都有绑定**：元数据和填充对常量，cap 按 16 位 limb 对外层
  公共值，内层 PV 对外层 PV，opened value 对执行器输入，链接前缀在 flush 接缝处用
  状态相等来约束。
- **Fiat–Shamir 抽样。** 第 j 次抽样读 digest 的第 31−4j … 28−4j 字节（challenger
  从输出缓冲区尾部往前弹），截成 31 位，≥ p 就拒绝。拒绝位由逆元见证的判零约束
  唯一确定；再用 one-hot 选择把第 k 个**被接受**的抽样值放进第 k 个 limb。
  被拒的抽样不推进任何东西，和原生的重抽行为一致。执行器的 `Alpha`、`Zeta`
  输入分别等于两个 digest 行上选出的抽样值。
- **执行器输入。** `Public(i)` 等于外层 PV i，外层 PV i 又等于其 F0 字乘 R⁻¹；
  `Alpha`/`Zeta` 来自抽样；`Local`/`Next`/`Quotient` 等于各自 F2 字乘 R⁻¹。
  最后一行把 residual 固定为零，把 next-point 固定为 `g_N · ζ`。
- **输出。** F2 的 digest D2 以 16 个公共 limb 的形式公开。fri_alpha 由它导出，
  F2b-2b 从这里接手。

### 两个陷阱

1. **Montgomery 字。** challenger 序列化用的是 `to_unique_u32`，也就是 Monty
   内部表示 `R·v mod p`。M4 之所以可以全程带着 R 因子，是因为它算的每个等式对
   opened values 都是线性的。OOD 等式不是（玩具 AIR 的 `x·y·y + x` 对 R 不齐次），
   所以每个 opened value 和内层 PV 都以 `R⁻¹ · word` 接入。challenge 由
   `from_canonical_unchecked` 产生，**不带** R 因子（已在 `serializing_challenger.rs`
   核对）。对应的负例把带 R 的值接进执行器，在 `bind_opened` 处被拒；同时断言
   这组带 R 输入下 DAG 的 residual 不为零。
2. **不能用随机线性组合做等式。** 如果用随机线性组合把执行器输入绑到字流上，
   就需要一个外层证明者事先猜不到的 challenge。内层 proof 的 challenge 在外层 trace
   选定之前就已知；p3-uni-stark 0.6.1 又是单阶段的，没有外层 challenge 可用。所以这里
   每条绑定都是确定性的同行相等：保持列在所有行上取同一个值，在承载该字的第 0 步
   行上等于 `R⁻¹ · word`，执行器的 input 指令读的也是这些保持列。

**规范性。** 一个字有 32 位，而域元素小于 p，所以 `v` 和 `v + p` 都满足
`R⁻¹ · word = v`。每个域元素字（内层 PV 和全部 opened values）都带一个 `< p`
比较器：第 31 位为零，并且不能同时满足"第 24..30 位全为 1"和"第 0..23 位非零"。
cap、digest 和常量按 16 位 limb 比较，本身就是精确的。别名负例把一个 opened value
编码成 `word + p`，只有这个比较器能拦住它。

### 复用了什么，没复用什么

复用：通过 `m4skel::LaneBuilder` 接入的 p3-keccak-air，`m4gaterec::keccakf`/`digest_of`，
以及参考执行器的约束核心（`machine::eval_machine`，现在两个组件共用）。没有复用的是
M4 gate 矩形本身：它写死在旧的非 hiding 配置上（固定 2^16 行、`N_CAPS`/`FLUSH_BYTES`
常量、三组 opened values、没有 randomizer cap），它的抽样 gadget 和规范性比较器也都
接在那套布局的列上。F2b-2a 按同样的判定条件写了窄版实现。规范性判定用的是
"第 24..30 位 popcount = 7"的判零，不是 M4 那种分级 7 位 AND。

**与任务书的偏差：用保持列，不用序言。** 任务书建议把输入读取重排成按 transcript
顺序的序言，再用同行相等绑定。这一版改为把每个执行器输入放在四列里，这四列在所有
行上取同一个值。绑定同样是确定性的，而且不用改调度。代价是每个输入 4 列（玩具 AIR
为 160 列）。这**不代表**对生产布局的任何判断。

### 约束分组与测试

约束按 18 个具名分组依次求值（`keccak`、`bits`、`absorb`、`chain_state`、
`flush_chain`、`bind_const`、`bind_cap`、`bind_inner_pv`、`canonical`、`digest_out`、
`fs_reject`、`fs_select`、`fs_bind`、`bind_opened`、`in_public`、`in_hold`、`machine`、
`machine_out`）。测试在 symbolic builder 上计数，把每个约束编号映射到分组；每个负例都在
该分组所在的行上断言违反落在哪个分组：

| 负例 | 拒绝位置 |
|---|---|
| ζ 的某个 limb 错（执行器重算） | `fs_bind`，ζ 的 digest 行 |
| α 错（执行器重算） | `fs_bind`，α 的 digest 行 |
| 换一个 ζ，重解 quotient 使 residual 为零，重建 F2/D2 | 只有 `fs_bind`；最后一行干净 |
| 跳过一个被接受的抽样 | `fs_select`，不是 `fs_bind` |
| 先吸收 randomizer cap 再吸收 quotient cap，完整自洽的重放 | 只有 `bind_cap`，F1 第一块；ζ 行和最后一行都干净 |
| 只改 transcript 里的一个 opened value，执行器不动 | `bind_opened` |
| 改一个 trace-next 值，执行器重算 | `machine_out`（residual 固定为零）；F2 各行干净 |
| 改一个 quotient limb，执行器重算（residual 非零） | `machine_out` |
| 按 R 缩放接入（漏了 R⁻¹） | `bind_opened` |
| 把 opened value 编码为 `word + p` | 只有 `canonical` |

诚实用例还把重放结果和原生 p3 challenger 交叉核对：α、ζ 必须一致，D2 的第一次抽样
必须等于 verifier 的 fri_alpha，这就把 F2 消息的顺序钉死了。随后做一次全量 SAT 扫描，
并检查最大约束 degree ≤ 3 **[P，由 CI 检查]**。

### 尺寸

玩具 transcript 的尺寸 **[P，源码推导]**：F0/F1/F2 共 3 + 5 + 5 = 13 个 lane 置换
（312 行）。宽度 = 2,633（Keccak lane）+ 2 × 1,088（M 位和 S 位）+ 68（规范性）
+ 72（八次抽样）+ 4I（保持的输入，玩具 AIR 的 I = 40）+ 12 + 4R（执行器）。
高度 = max(next_power_of_two(24 × 置换数), next_power_of_two(K + 1))。

### ROM 编码成本

Price 模式下 `ood_arithmetic.rom_encoding` 紧挨着 `register_schedule`，给出执行器 ROM
（W_rom 列 × H 行）两种编码的成本 **[P]**，代码里不做取舍：

- **周期列**：在 ζ 处求值需要 W_rom·H 次扩展域乘加，没有 PCS 成本；
- **提交的 preprocessed 列**：F0 多一个 256 字节的 cap，F2 多 16·W_rom 字节的 opening，
  每个 query 多 ceil((W_rom + 4)/34) 次叶子置换和一条 input path（分别给出每 query 值和
  × 43 的总值），外加 W_rom 个 fri_alpha 项和 W_rom 次 DAG 输入读取。

### 尚未绑定（F2b-2b）

fri_alpha、FRI 的各个 beta 和 commit 阶段的 cap、PoW、query 下标、reduced opening、
加盐的 input-Merkle 叶子和路径，以及 final polynomial。**F2b-2a 没有任何约束把 opened
values 和已提交的 cap 联系起来**，那一半从 D2 开始。若某个抽样窗口需要补充（超过八次
抽样，每个 challenge 的概率约 1e-9），则无法满足；这是完备性缺口，不会导致误接受。
`pcs_input_bindings_complete`、`full_ood_air_checked`、`complete_verifier_layout`、
`memory_gate_pass` 均保持 **false**。

### 验证

本地没有运行测试、生成 proof 或跑 benchmark。本地预检只有 `cargo check`、限定范围的
Clippy 和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`bind.rs` 三个、
`price.rs` 一个，相对基线分支共四个 **[P，待 CI]**。预计新测试在 Graviton lane 上总耗时
不超过 30 秒 **[P]**：一次玩具 hiding proof，约十一个稠密 trace（约 512–1,024 行 ×
5.4k 列），一次全量扫描，每个负例只扫单行。尚未验证、按最可能先出问题排序：重放与原生
challenger 的交叉核对（抽样字节序、cap 序列化）；symbolic 与 debug 两种 builder 的
约束编号计数不一致；玩具 AIR 高度很小（log 4）时 hiding PCS 的表现。

