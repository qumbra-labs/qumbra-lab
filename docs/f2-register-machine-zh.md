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
（下文 F2b-2a 在测试组件里补上了这层绑定，F2b-2b-i 把 transcript 接着推过了 FRI 的全部 challenge；Merkle 和 query 检查仍未做）。
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

约束按 19 个具名分组依次求值（`keccak`、`bits`、`absorb`、`chain_state`、
`flush_chain`、`bind_const`、`bind_cap`、`bind_inner_pv`、`canonical`、`digest_out`、
`fs_reject`、`fs_select`、`fs_bind`、`bind_opened`、`in_public`、`in_hold`、`machine`、
`machine_out`，以及 F2b-2b-ii 新增的 `opened_out`，见该节）。测试在 symbolic builder 上计数，把每个约束编号映射到分组；每个负例都在
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
| 伪造 F0 元数据字（log_h），完整自洽的重放 | 只有 `bind_const`；α/ζ 行和最后一行干净 |
| 吸收的内层 PV 与声明的不同，完整自洽的重放 | 只有 `bind_inner_pv` |
| 把内层 PV 编码为 `word + p` | 只有 `canonical` |
| 导出的 ζ、某个接入执行器的 opened value 或 randomizer 值，与执行器自己的单元／字不一致（F2b-2b-ii） | 只有 `opened_out`，在它所在的行 |

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
Clippy 和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`bind.rs` 六个、
`price.rs` 一个，相对基线分支共七个 **[P，待 CI]**。预计新测试在 Graviton lane 上总耗时
不超过 30 秒 **[P]**：一次玩具 hiding proof，约十一个稠密 trace（约 512–1,024 行 ×
5.4k 列），一次全量扫描，每个负例只扫单行。尚未验证、按最可能先出问题排序：重放与原生
challenger 的交叉核对（抽样字节序、cap 序列化）；symbolic 与 debug 两种 builder 的
约束编号计数不一致；玩具 AIR 高度很小（log 4）时 hiding PCS 的表现。

## F2b-2b-i：FRI transcript

F2b-2b-i 把**同一份** Fiat–Shamir transcript 从 F2 往后接着推，覆盖原生 verifier
抽取的每个 FRI challenge：fri_alpha、每轮 commit 一个 β、query 阶段的 proof-of-work，
以及每个 query 下标。这一片只管 Fiat–Shamir，不检查 Merkle 路径、reduced opening、
折叠或 final polynomial 求值，那些归 2b-ii/iii。它和 2a 一样是只用于测试的组件
（`crates/qlab-bench/src/f2/ood/fri_fs.rs`），逐行扫描，不做 prove。

### 原生顺序（已对照源码）

challenger 是 `SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256, 32>>`，
配置为仓库钉住的 hiding 配置（`qlab-consensus` 的 `make_config_from`；L2 lane
`L2_CFG_PROVISIONAL` = b4/q43/g22/fp16/a16，`CAP_HEIGHT` 3，rc = 0）。p3-fri 0.6.1 中：

1. `two_adic_pcs.rs:696-701` 吸收 opened values（F2），随后 `verifier.rs:195` 抽
   fri_alpha。这次 flush 的 digest 就是 D2，2a 已经把它作为输出公开；在本组件里，
   D2 是公共**输入**。
2. `verifier.rs:302-311`，每一轮依次是：`observe(commit)`、
   `check_witness(commit_proof_of_work_bits, w)`、抽 β。仓库把
   `commit_proof_of_work_bits` 定为 0，而 `check_witness` 在 0 位时什么都不吸收就直接
   返回（p3-challenger `grinding_challenger.rs:41-47`），所以 commit 阶段的 witness
   根本不进 transcript。第 r 轮的 flush 为 G_r = D_{r−1} ‖ cap_r。
3. `verifier.rs:323` 吸收 final polynomial（16 个系数，每个 4 个基 limb），
   `verifier.rs:334-336` 把每轮的 log-arity 作为基域元素吸收，`verifier.rs:339` 调用
   `check_witness(22, w)`，即先吸收 w，再要求 `sample_bits(22) == 0`。这几次吸收之间
   没有任何抽样，所以合起来是**一次** flush：H = D_{R−1} ‖ final poly ‖ arities ‖ w。
4. `verifier.rs:352-353` 为 43 个 query 各调用一次 `sample_bits(log_global_max_height)`。
   `TwoAdicFriFolding` 不额外加位（`two_adic_pcs.rs:106`）。

**`sample_bits` 和域元素抽样不是一回事。** 它同样弹出四个字节（小端，位置与域元素
抽样相同），但只保留低 `bits` 位：不截 31 位，也不拒绝。由此有两个结论。第一，PoW
条件落在 H 的 digest 第 0 次抽样的**低** 22 位上；任务书写的"前导零位"在此更正为末尾零位。
第二，每个 query 下标都在固定的（digest, 抽样）位置上：query i 是从 H 的 digest 开始的
抽样流里的第 i + 1 次，所以 query 阶段不需要选择 gadget。一个 digest 的八次抽样用完后，
challenger 会重新 flush 它的输入缓冲区，而这时缓冲区里恰好只有上一个 digest
（`hash_challenger.rs` 的 `flush`）。每次补充为 Q_w = hash(D_{w−1})，一个置换。

**PoW 位数。** query 阶段的 PoW 是 22 位（非零），所以直接按原生难度测这个 gadget。
commit 阶段的 PoW 在钉住的配置里是 0 位，那里没有可约束的东西。

### 绑定了什么

- **Sponge。** lane 和各个 gadget 与 2a 相同，现在集中放在 `lane.rs`（见下）。第一次
  flush 的链接前缀固定为 D2 的公共 limb（`seed`，第 0 行，那里 S = 0）；之后每次 flush
  的前缀由 `flush_chain` 固定。
- **字。** 填充和各轮 log-arity 是逐 limb 精确的常量。cap 对外层公共 limb。
  final polynomial 的 limb 必须规范，并且在保持列里等于 `R⁻¹ · word`：Montgomery 陷阱
  对它们和对 opened values 一样成立。PoW witness 必须规范。
- **抽样。** fri_alpha（取自 D2 的窗口，在 G_0 第一块上读出）和每个 β 都用 2a 的拒绝加
  one-hot 选择。PoW 约束为 22 个零位。每个下标位等于该窗口 digest 行上对应的抽样位。
- **输出。** 保持列在所有行上取同一个值，里面放着 fri_alpha、每个 β、final polynomial
  和每个 query 下标的各个位，供 2b-ii/iii 在同一行空间里做路径选择。同样这些值也作为
  公共输出公开（在第 0 行绑定），这样独立的组件可以靠公共值相等来接收。这相当于 2a 的
  D2 输出：原生 verifier 在 query 抽样之后不再吸收任何东西，所以不再公开更后面的 digest。

**折叠方案是形状常量。** p3 的 verifier 接受任意一组每轮 log-arity，只要每个在
1..=max 之间、总和与输入高度一致。这里的布局把它固定为 p3 prover 实际采用的方案
（`price::fri_log_arities`，从 census 里提出来，两处共用一个函数）。用别的合法方案折叠的
proof 会被拒；这是完备性上的限制，不会导致误接受，诚实的 prover 也不会生成这样的 proof。
诚实用例断言真实 proof 的 arity 与布局一致。

### 复用

sponge lane 从 `bind.rs` 搬到了 `lane.rs`：pad10*1、吸收循环、抽样顺序、
`accepted`/`challenge`、Keccak 列映射、周期性 sponge 选择列、分组区间计数，以及约束
gadget `bits`、`absorb`、`chain_state`、`flush_chain`、`< p` 比较器、`fs_reject` 和
`fs_select`。每个 gadget 产生的约束与原来相同、顺序也相同，所以 2a 那些按编号定位分组的
负例不受影响。2a 的测试没有改动，只是玩具 AIR、它的 proof，以及原生 challenger 重放到
F2 的那段代码，现在都来自 `lane::toy`（同一份代码，两边共用）。每个组件把自己的字绑到
什么上，仍然留在组件自己里面。

### 约束分组与测试

共 17 个具名分组：`keccak`、`bits`、`absorb`、`chain_state`、`flush_chain`、`seed`、
`bind_const`、`bind_cap`、`canonical`、`fs_reject`、`fs_select`、`fs_bind`、
`bind_final`、`pow`、`fs_index`、`hold`、`cells_out`。fixture 仍是那个玩具 AIR，高度取
log 8（L2 lane 上加固定种子的 hiding proof）。按 2a 的 log 4，LDE 为 2^7，只折叠一次；
log 8 时 2^11 先按 16 折、再按 2 折，有两轮 commit，交换负例才有意义。D2 取自 2a 自己的
`Replay` 对同一个 proof 的重放，顺带检验两个组件之间的接缝。

每个负例都扫描**全部**行，并断言所有违反都落在指定分组、指定行上（比 2a 的单行检查更严）：

| 负例 | 拒绝位置 |
|---|---|
| fri_alpha 的某个 limb 错，输出一致 | 只有 `fs_bind`，D2 行 |
| β_0 取了第五个被接受的抽样（跳过） | 只有 `fs_select`，G_0 digest 行 |
| 两轮的 cap 按相反顺序吸收；β、PoW（由 p3 challenger 重新 grind）和下标全部自洽 | 只有 `bind_cap`，G_0/G_1 各行 |
| transcript 吸收伪造的 final-poly 系数，query 阶段拿到的是诚实值；PoW 重新 grind，下标按新 transcript 重放 | 只有 `bind_final` |
| 把 final-poly 的一个字编码为 `word + p` | 该行的 `canonical`，外加窗口行的 `pow`（没有重新 grind：原生 challenger 吸收不了非规范字） |
| PoW witness 不满足 22 位条件，下标按它重放 | 只有 `pow`（p3 的 `check_witness` 同样拒绝） |
| 翻转一个 query 下标位，保持列和公共下标一致 | 只有 `fs_index` |
| 某个 query 用了另一个 query 的下标，transcript 不动 | 只有 `fs_index` |
| query 7 及之后每个都取下一次抽样（跳过） | 只有 `fs_index` |

**范围边界（有断言）。** 如果 transcript 吸收的 final polynomial 和对外给出的一致，
PoW 也重新 grind 过，本组件会**接受**。Fiat–Shamir 这一层没有任何东西能拒绝它，
必须由 2b-iii 的 final polynomial 求值来拒绝。测试把这一点写成断言，边界不会悄悄移动。

诚实用例把重放结果和原生 p3 challenger 交叉核对，challenger 按 verifier 自己的吸收顺序
驱动。核对内容：fri_alpha（取自 2a 的 D2）、两个 β，以及 proof 里的 PoW witness 在这个
位置能通过 `check_witness(22)`。若经过 H 的消息顺序有误，只有 2⁻²² 的巧合才能通过，
所以这一步独立于重放本身把顺序钉死。此外还核对全部 43 个 query 下标、形状（arity [4, 1]、
两个 commit 和两个 witness、16 个系数、43 个 query、11 个下标位、六个窗口）、一次全量
SAT 扫描，以及最大约束 degree ≤ 3 **[P，由 CI 检查]**。

### 尺寸

**[P，源码推导]** 玩具 AIR（log 8，R = 2）：flush 依次为 G_0、G_1（各 3 个置换：8 + 64 个字）、
H（3 个：8 + 64 + 2 + 1），以及六次补充，各一个置换，共 15 个置换（360 行 → 高度 512）。
宽度 = 2,633（Keccak）+ 2 × 1,088（M、S）+ 68（规范性）+ 72（域元素抽样）+ 保持列
4(R+1) + 64 + 43 · 11 = 549，合计 5,498。公共值：16（D2）+ 128R（cap）+ 4(R+1) + 64 + 43 = 391。

按 shape P（log 20，LDE 2^23）：arity 为 [4, 4, 4, 4, 1]，R = 5，下标 23 位，置换数
5 × 3 + 3 + 6 = 24。这与 census `fs_floor` 里 FRI 那几项
（R × blocks(32 + cap) + blocks(final ‖ arities ‖ witness) + 5 次补充）一致，只多一个置换：
末尾那次补充的第一块用来承载最后一个窗口的 digest 位。这是"从后继块的 M 位读抽样"
这种布局的代价，不是 transcript 的代价。保持列：24 + 64 + 43 · 23 = 1,077。

### 尚未绑定（2b-ii/iii）

input 与 commit 阶段的 Merkle 路径、加盐叶子、reduced opening、折叠（兄弟值、β 的幂），
以及每个 query 上的 final polynomial 求值。若 fri_alpha 或某个 β 的抽样窗口需要补充
（超过八次域元素抽样，每个 challenge 的概率约 1e-9），则无法满足；和 2a 一样，这是完备性
缺口，不会导致误接受。`pcs_input_bindings_complete`、`full_ood_air_checked`、
`complete_verifier_layout`、`memory_gate_pass` 均保持 **false**。

### 验证

本地没有运行测试、生成 proof 或跑 benchmark。本地预检为
`cargo check --workspace --all-targets`、`qlab-bench` 的 Clippy（`f2/` 下无告警）和
rustfmt；验收以 `verify-graviton` CI 为准。本片在 `fri_fs.rs` 新增六个测试，别处没有新增。
**[P，待 CI]**：2769 + 6 = 2775 项通过、0 失败、15 项忽略，以 2a 的验收运行 36325459774
为基线核算（此后 main 没有变动）。

新测试在 Graviton lane 上的预计耗时为 15–40 秒 **[P]**。大头是一次 log 8 的玩具 hiding
proof（含它自己的 22 位 grind）和两次原生 22 位重新 grind（每次期望 2²² 次 Keccak-256
吸收，rayon 并行）。其余是约十个 512 × 5,498 的 trace、一次并行 SAT 扫描、约九次全表违反
扫描（每次 512 行）和一次 symbolic degree 计算。2a 的六个测试现在共用 lane 代码，耗时应当不变。

尚未验证，按最可能先出问题排序：

1. 原生交叉核对本身：重放里 H 的消息顺序和补充语义是否与 p3 challenger 一致（诚实用例的
   `check_witness` 和下标断言会暴露问题）。
2. fixture 的折叠方案：`[4, 1]` 假定 hiding 的每个输入都提交在 2N 行上。若某个 quotient
   chunk 提交得更低，p3 prover 会先折到它的高度，arity 断言就会失败。
3. 把 2a 的 gadget 挪进 `lane.rs` 的重构：分组内的约束顺序按构造保持不变，但能检验这一点的
   只有 2a 的负例。
4. 某个负例依赖种子：β_0 的窗口里至少要有五个被接受的抽样（不满足的概率约 3·10⁻⁷，
   对固定种子而言结果是确定的）。

## F2b-2b-ii：输入批次的打开

F2b-2b-ii 在电路里核对每个 FRI query 在其下标处打开的三个输入批次：加盐的叶子、
通往已提交 cap 的 Merkle 路径，以及这个 query 交给第一次折叠的 reduced opening。
折叠和 final polynomial 属于 2b-iii。和 2a、2b-i 一样，这是仅用于测试的组件
（`crates/qlab-bench/src/f2/ood/open.rs`），逐行扫描，从不 prove。它不引入任何新的
内层 proof 声明：它认证的每个值，要么是 2a 或 2b-i 导出的公共输入，要么是它自己
哈希进这些 cap 的字。

### 原生事实（已对照源码）

除非另行注明，行号均指 p3 0.6.1。

- **批次顺序和打开点。** uni-stark `verifier.rs:453-510` 按顺序交给 PCS 三组声明：
  randomizer（一个矩阵，4 列，在 ζ 处打开）、trace（一个矩阵，w 列，在 ζ 和 ζ·g_N 处
  打开，g_N 是**原始** N 行域的生成元）、quotient（8 个 chunk 矩阵，各 4 列，在 ζ 处
  打开）。`open_input` 也按这个顺序遍历（`verifier.rs:640-753`）。
- **只有一个高度。** hiding PCS 把所有输入都提交在 2N 行上：`hiding_pcs.rs` 的
  `commit`（105-131 行）把 trace 与随机行交错，`get_quotient_ldes`（168-256 行）把每个
  大小为 N 的 chunk 按 `log_blowup + 1` 扩展，randomizer 直接在 2N 域上抽取（438-458 行）。
  因此所有矩阵都在 2^lde 行，lde = log N + 1 + log_blowup（玩具为 11，S/P/R 为 22/23/21）。
  约化后的下标就是 query 下标本身（`verifier.rs:687-691`），每个 query 只有一个 reduced
  opening。
- **叶子的序列化。** `hiding_mmcs.rs:169-176` 在每个矩阵行后面接上 4 个元素的盐。
  `mmcs/batch.rs:200-206` 把同一高度的所有行当作一条流来哈希，按矩阵顺序依次是
  行 ‖ 盐（`hash_iter_slices` 直接拼平，`hasher.rs:24-30`）。哈希器是
  `PaddingFreeSponge<KeccakF, 25, 17, 4>` 外面套一层 `SerializingHasher`
  （`qlab-consensus` `lib.rs:58-61`）。域元素取其 Monty 字，每两个打包成一个 u64，
  低字在前；元素个数为奇数时，最后一个字单独占一个 u64（`p3-field integers.rs:494-507`）。
  这个 sponge 对每块的 17 个 rate lane 是**覆盖写入**，不是异或，这一点和 challenger 用的
  pad10*1 Keccak 不同。最后一块不满时，尾部 lane 保留上一次置换的输出；digest 取
  lane 0..3（`sponge.rs:172-204`）。
- **路径。** `CompressionFunctionFromHasher<_, 2, 4>` 就是对 左 ‖ 右（8 个 u64）
  做一次全新的 sponge 置换（`compression.rs`）。第 t 层读下标的第 t 位，该位为 0 时
  当前 digest 在左边（`mmcs/batch.rs:210-235`）。层级方案是二叉的，最上面
  `CAP_HEIGHT` = 3 层并入 cap（`mmcs/mod.rs:262-297`）。cap 表项是 `index >> path`，
  path = lde − 3。
- **Reduced opening**（`verifier.rs:706-753`）。x = GENERATOR ·
  ω_lde^{rev_lde(index)}（下标按位反转，域的平移就是域生成元）。对每个矩阵、每个点、
  每一列，ro += α^k · (p(z) − p(x)) / (z − x)，k 是贯穿三个批次的同一个计数器（只有一个
  高度，所以只有一个计数器）。z = x 在原生代码里是报错（`try_inverse`），这里表现为
  无法满足的求逆约束。

### 绑定了什么

- **覆盖模式的 sponge。** 用的还是同一条 stock Keccak lane。每个置换 step-0 行上的
  M 比特**就是**它的 rate 原像；没有 S 比特，因为没有东西被异或进去。capacity 只在
  叶子的内部块之间传递，进入其他任何置换时都为零。叶子的字分四类：行值（规范的 Monty 字，
  以 `R⁻¹ · word` 计入累加）、盐（自由的 witness 字，只参与哈希）、零，以及从上一次输出
  带过来的尾部 lane。
- **路径。** 在给第 t 层喂数据的那一行上，刚算出的 digest 必须放在子节点的左半边
  （该 query 下标第 t 位为 0）或右半边（为 1）；另一半是兄弟节点，不加约束。最终 digest
  等于由下标最高三位的 one-hot 选出的 cap 表项。cap 就是 2a 导出的 cap 公共值，逐 limb 对应。
- **Reduced opening。** 在该 query 的叶子行上累加两个和 α^k · v：ζ 的项记为 Ax，
  ζ·g_N 的项记为 Bx。到这一段的最后一行，ro = (Az − Ax)·inv_A + (Bz − Bx)·inv_B，
  其中 (ζ − x)·inv_A = 1、(ζ·g_N − x)·inv_B = 1 都是扩域乘积约束。Az、Bz（即 Σ α^k z_k）
  和 α 的各次幂在保持列里每个实例只算一次。x 是一串常数因子的连乘，每个下标位一个：
  第 t 位乘上 ω^{2^{lde−1−t}}，这恰好就是按位反转。所有约束的 degree 都 ≤ 3。
- **输出。** 每个 query 的 reduced opening 放在保持列里（所有行上取值相同），同时作为
  公共输出，供 2b-iii 使用。

**统一布局。** 每个 query 跑同一段置换序列：randomizer 叶子、randomizer 路径、trace 叶子、
trace 路径、quotient 叶子、quotient 路径。每个 query 自己的值（下标位、cap one-hot、x 链、
逆元、ro）是逐行寄存器，由分段选择器绑定到该 query 的公共下标上。所以 periodic 列的数量
随叶子角色、层数和 query 数增长，而不随置换数增长（玩具 22 列；S 在 43 个 query 时 96 列）。

### 与 2a、2b-i 的衔接

F2b 的各部分是彼此独立的 AIR，通过公共值连接，和 2a 的 D2 用的是同一种接缝。为此，
**2a 增加了一个分组 `opened_out`**：它把 ζ 和每一个 opened value 作为公共输出导出，而且
**直接取自执行器自己的单元**。执行器读取的值，从执行器读的那一列保持列导出（首行；该列在
所有行上不变）；执行器从不读取的 randomizer opening，则从它在 transcript 里的字导出（在其
step-0 行上取 `R⁻¹ · word`）。2b-i 本来就导出 fri_alpha 和各个下标。在本组件里，这些值是
公共**输入**，在第 0 行绑定到保持列（`opened_in`），并绑定到逐行的下标位（`index`）。
于是 FRI 读到的 z 值就是执行器读到的那一份，接缝两侧各有一条对同一个公共值的等式，不存在
可能对不上的第二份拷贝：

- 交给 FRI 的 z 值与 2a 导出的不同：本组件的 `opened_in`，第 0 行；
- 导出值与执行器的单元或字不同：2a 的 `opened_out`，在它所在的行。

接缝测试把三个组件的公共值逐段比对：cap、ζ 和 z 值对照 2a 在 log 8 下对同一个 proof 的
导出，fri_alpha 和本实例覆盖的下标对照 2b-i 的导出。

### 约束分组与测试

共 20 个具名分组：`keccak`、`bits`、`absorb`、`capacity`、`bind_zero`、`bind_carry`、
`bind_child`、`cap`、`canonical`、`accumulate`、`opened_in`、`index`、`cap_select`、
`x_point`、`inverse`、`alpha_pow`、`z_sum`、`reduce`、`hold`、`ro_out`。fixture 直接用
2b-i 的：同一个固定种子的 log 8 玩具 proof（每个测试二进制只生成一次），连同它的下标和
fri_alpha。实例覆盖两个 cap 表项不同的 query。每个负例都扫描**全部**行，并断言违反的
（行，分组）集合与预期完全相同：

| 负例 | 拒绝位置 |
|---|---|
| 改一个盐 | 只有 `cap`，该批次的 cap 行 |
| 改一个行值、另选新盐，ro 一致地重算 | 只有 `cap`（叶子规范且自洽，所以此前没有任何约束拒绝它，也没有任何约束放它过去） |
| 交换两个兄弟节点 | 只有 `cap` |
| 子节点放错一侧，下标位不动 | 该层喂数据那一行的 `bind_child`，外加 `cap` |
| 翻转一个下标位，放置方向、x 和 ro 都随之改变 | 该段每一行的 `index`，外加三个批次的 `cap` |
| 选错 cap 表项 | 该 query 寄存器所在各行的 `cap_select`，外加三个批次的 `cap` |
| 交给 FRI 的 z 值 ≠ 2a 的导出，Az 和 ro 重算（一个执行器读取的 trace 值，以及 randomizer） | 只有 `opened_in`，第 0 行 |
| fri_alpha ≠ 2b-i 的导出，α 的各次幂、Az/Bz 和 ro 重算 | 只有 `opened_in`，第 0 行 |
| 用**未经**位反转的下标算 x，逆元和 ro 重算 | 只有 `x_point`，在该 query 寄存器所在各行 |
| 改一个 reduced opening（保持列和公共输出一致） | 只有 `reduce`，该段最后一行 |

在 2a 一侧，新增的负例分别改动导出的 ζ、一个接入执行器的 opened value 和一个 randomizer
值；每一种都只被 `opened_out` 拒绝，而且就在它所在的行，ζ 的 digest 行和最后一行保持干净。

**原生交叉核对**（诚实用例），覆盖**全部 43 个** query，而不只是实例覆盖的两个：

- p3 自己的 hiding MMCS（`verify_batch`）在完整下标处接受每个批次的打开；
- lab 对叶子哈希和路径的原生重放到达同一个 cap 表项；
- 按 uni-stark 的顺序喂入 proof 里的 opened values、逐项照搬 `open_input` 的原生实现，
  其结果等于电路按 (Az − Ax)/(ζ − x) + … 分组计算的结果；
- 这个值**正是** FRI 折叠的输入：把它插到第 0 轮兄弟值中 `index % 16` 的位置，p3 的
  commit-phase MMCS 接受这一行。这样 reduced opening 就被钉在已提交的 codeword 上，
  与两份实现都无关。

诚实用例还做一次 SAT 扫描，检查保持列和公共输出里的 reduced opening 等于原生值、最大约束
degree ≤ 3 **[P，由 CI 检查]**，并检查玩具布局与 `price::input_openings` 一致（宽度、高度、
periodic 列数和公共值个数）。

### 尺寸 **[P，源码推导]**

玩具（w = 2，log 8，lde 11，path 8，40 个 opened 项，2 个 query）：每个 query 有
1 + 1 + 2 个叶子置换（分别 8、6、64 个元素）加 3 × 8 次压缩，共 28 个；两个 query 共
56 个置换、1,344 行，高度 2,048。宽度 4,187 = 2,633（Keccak）+ 1,088（M）+ 68（规范性）+
8（累加器）+ 46（寄存器，2·lde + 24）+ 344（保持列，16 + 8·40 + 4·2）。periodic 列 22 个，
公共值 562 个。

`f2price` 现在按形状给出 43 个 query 下的 `input_openings`（`price::input_openings`，由
`input_openings_split_the_census` 钉住）：

| 形状 | 每 query 叶子 / 压缩 | 每 query 置换 | 叶子 / 压缩 × 43 | lane 行数（补齐后） | opened 项 | 列数 | periodic | PV |
|---|---|---|---|---|---|---|---|---|
| S（w 721，lde 22） | 25 / 57 | 82 | 1,075 / 2,451 | 84,624（2^17） | 1,478 | 15,877 | 96 | 6,519 |
| P（w 798，lde 23） | 27 / 60 | 87 | 1,161 / 2,580 | 89,784（2^17） | 1,632 | 17,111 | 99 | 7,135 |
| R（w 734，lde 21） | 25 / 54 | 79 | 1,075 / 2,322 | 81,528（2^17） | 1,504 | 16,083 | 95 | 6,623 |

**与 census 对账。** 把 FRI commit 阶段的份额（S 每个 query 8 个叶子置换、36 个路径置换）
加到输入份额上，S 在 43 个 query 时得到 1,075 + 344 = **1,419** 个叶子置换和
2,451 + 1,548 = **3,999** 个路径置换，正是 census 实测的数。测试对三种形状都按 census
的几何做了同样的拆分断言。

**Reduced opening 的算术量。** 每个 query：每个 opened 项一次扩域乘基域（S 为 1,478 次），
lde 次基域乘法算 x，两次求逆检查，两次扩域乘法。每个实例：α 的各次幂 terms − 1 次扩域乘法，
Az/Bz 共 terms 次。

**一个布局上的发现，没有在这里解决。** 到了 L2 的宽度，稠密的保持表（α 的幂和 z 值，
8·terms 列）占了宽度的大头：S 的 15.9k 列里有 11.8k 是它们。生产布局应当把这两张表放进
行里，用一列 periodic 下标去索引，而不是横向铺开。这里把数字列出来，是为了让这个杠杆
看得见；本片不实现它。

### 尚未绑定（2b-iii）

commit 阶段的打开（兄弟值、FRI 的 Merkle 路径）、用 β 做的折叠，以及 final polynomial 的
求值。reduced opening 已经为那个组件导出。*（这三项现在由下面的 2b-iii 绑定；它补齐了什么、
还缺什么，见那一节的“还缺什么”。）*

### 验证

本地没有跑任何测试、proof 或 benchmark。本地预检为
`cargo check --workspace --all-targets --locked`、`qlab-bench` 上的 Clippy（`f2/` 下无告警）
和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`open.rs` 五个、`bind.rs` 一个、
`price.rs` 一个，共七个。**[P，待 CI]**：以 2b-i 待定的 2,775 为基线，应为 2,782 项通过、
0 失败、15 项忽略。

新测试在 Graviton lane 上的预计耗时为 10–40 秒 **[P]**。proof 与 2b-i 的 fixture 共用
（每个测试二进制一份）。其余是 2a 在 log 8 下的导出重放、43 个 query 的原生 MMCS 与折叠
核对、约十二个 2,048 × 4,187 的 trace、一次并行 SAT 扫描、约十一次并行的全表违反扫描，
以及一次 symbolic degree 计算。

尚未验证，按最可能先出问题排序：

1. lab 原生 `Walk` 复现的叶子序列化和覆盖语义（奇数字的打包、quotient 叶子第二块里带过来的
   尾部 lane）。诚实用例里“根等于 cap”的断言和 p3 的 `verify_batch` 会暴露不一致。
2. reduced opening 的分组方式和项的顺序是否与逐项的原生实现一致，以及两者是否与折叠一致。
   第 0 轮的 commit-phase 核对是独立的锚点。
3. 负例里（行，分组）集合是否精确。某个负例若多触发一个分组（比如 padding 行上的寄存器，
   或者被改动的保持列触发 `hold`），会明确失败而不是悄悄通过；正确的修法是把多出来的行写进
   预期，而不是放宽断言。
4. 表里手算的 S/P/R 数字：`input_openings_split_the_census` 把它们钉住，算错会让 CI 失败。

## F2b-2b-iii：FRI 折叠

F2b-2b-iii 把 FRI 的 query 阶段搬进电路。对实例覆盖的每个 query，它逐轮用该轮的 cap
认证加盐的叶子，检查当前值就是该 query 所在位置上那个已提交的值，用这一轮的 β 折叠整组，
最后要求 final polynomial 在终点处的取值等于最后一次折叠的结果。和前几片一样，这是仅用于
测试的组件（`crates/qlab-bench/src/f2/ood/fold.rs`），逐行扫描，从不 prove。它的公共输入
全都是别的组件的公共输出：commit 阶段的 cap、每一轮的 β、final polynomial 和下标来自 2b-i，
reduced opening 来自 2b-ii。

### 原生事实（已对照源码）

除非另行注明，行号均指 p3 0.6.1 的 `p3-fri`。

- **单个 query 的顺序**（`verifier.rs:448-584`，`verify_query`）。链条从全局最大高度上的
  reduced opening 出发（`verifier.rs:470-480`）。每一轮：在已被前几轮右移过的下标上取
  `index_in_group = index % arity`（`508`）；把当前值插到这个位置，其余位置按顺序填入兄弟值，
  得到 evals（`509-517`）；下标右移本轮的 log-arity（`529`）；commit 阶段的 MMCS 在右移后的
  下标处核对 evals（`531-541`）；然后 `fold_row`（`543-549`）。换成电路的说法：第 r 轮用
  query 下标的第 S_r..S_r+a 位定位置，用第 S_{r+1} 位往上定路径和折叠点，S_r 是前几轮 arity
  之和。
- **reduced opening 的注入**（`verifier.rs:554-565`）。折叠之后，如果有输入**恰好提交在折叠后
  的高度**，原生代码会加上 β^arity · ro。hiding 配置把三个批次都提交在同一个高度上（见 2b-ii），
  所以唯一的 reduced opening 就是起点那一个，之后没有任何注入；每个 query 只有一个 `ro`，
  从结构上就排除了第二个高度。
- **折叠公式**（`two_adic_pcs.rs:110-133`，`lagrange_interpolate_at` `221-258`）。arity 为 n
  的一组值在 xs[i] = s · ω_n^{rev_a(i)}（按位反转）上的插值多项式在 β 处的取值，
  s = ω_{h+a}^{rev_h(index′)}，index′ 是右移后的下标，h 是折叠后的 log 高度。原生用重心公式，
  并在 β 恰好等于某个 x 时提前返回；插值多项式在那一点的值也正是它，所以两者处处一致。
- **终点**（`verifier.rs:394-410`）。x = ω_lde^{rev_lde(index >> S_R)}，**没有陪集平移**
  （输入那边的 x 是 GENERATOR · …，这里不是）。按 Horner 从最高次系数算起，结果必须等于
  最后一次折叠的值。
- **commit 阶段的叶子也加盐。** `ChallengeMmcs = ExtensionMmcs<Val, E, ValMmcs>`
  （qlab-consensus `lib.rs:90`），而 `ValMmcs` 就是 hiding MMCS。`ExtensionMmcs` 把 n 个值按
  基底顺序拆成 4n 个基域 limb（`extension_mmcs.rs:77-82`），`hiding_mmcs.rs:175` 再接上
  `SALT_ELEMS` = 4 个盐。sponge、打包和路径与输入 MMCS 完全相同（见 2b-ii）。arity 16 时叶子是
  68 个字，正好两个覆盖块；arity 2 时是 12 个字，一块装下；R 的最后一轮（arity 8）是 36 个字，
  第二块要带上一块输出的尾部 lane。

### 绑定了什么

- **叶子和路径**，直接复用 2b-ii 的 gadget 和叶子字布局。叶子里的行字是规范的 Monty 字，
  等于 R 乘以本轮组寄存器 G 的值（`leaf_bind`）；盐字自由。每一层子节点放左边还是右边，由
  下标绑定所钉住的**同一组**下标位单元决定。cap 表项总是下标最高三位
  （S_{r+1} + path_r = lde − 3），所以 cap 的 one-hot 与 2b-ii 同形。每一轮的根等于**这一轮**
  commit 阶段 cap 里被选中的那一项，cap 取自 2b-i 吸收过的公共值。
- **位置。** 对第 S_r..S_r+a 位逐位搭一层 one-hot（每个单元 degree 2）。选中的那一项必须等于
  当前值（`select`）。
- **折叠，写成逆 DFT。** p(β) = Σ_k d_k u^k，其中 d_k = n⁻¹ Σ_i ω_n^{−rev_a(i)·k} G[i]
  （基域常数，对 G 是线性的），u = β · s⁻¹。s⁻¹ 是一串由下标位挑选的**常数**因子
  ω_{h+a}^{−2^{h−1−t}} 的连乘，所以**这个组件里没有任何求逆 witness**：1/n 是常数，s⁻¹ 是
  常数因子链。u 的各次幂放在单元里，u^{k+1} = u^k · u。
- **final polynomial。** x 是第 S_R..lde−1 位上的常数因子链；Horner 单元
  h_k = h_{k+1} · x + c_k 作用在保持列里的 final polynomial 上；h_0 等于最后一次折叠的值
  （`final`）。
- **寄存器。** 每个 query 的寄存器在它那一段里保持不变（`ctx_hold`），所以叶子 step-0 行上
  绑定的那组值，就是每一行拿去折叠的那组值。所有约束的 degree 都 ≤ 3 **[P，由 CI 检查]**。

### 与 2b-i、2b-ii 的衔接

β 和 final polynomial 放在保持列里，在第 0 行绑定到各自的公共输入（`inbound`）。下标位和链条
的起点在该 query 那一段的每一行上钉住（`index`、`ro_in`）。2b-i 的
`fri_transcript_rejects_final_poly_forgeries` 表明：一个被一致地吸收并导出的 final polynomial
在 transcript 层面是合法的；拒绝它的地方就在本组件。接缝测试逐段比对公共值：cap、β、
final polynomial 和下标对照 2b-i 对同一个 proof 的公共值，reduced opening 对照 2b-ii 的输出。

### 约束分组与测试

共 24 个具名分组：`keccak`、`bits`、`absorb`、`capacity`、`bind_zero`、`bind_carry`、
`bind_child`、`cap`、`canonical`、`leaf_bind`、`index`、`cap_select`、`position`、`ro_in`、
`select`、`s_inv`、`fold_pow`、`fold`、`final_x`、`horner`、`final`、`inbound`、`hold`、
`ctx_hold`。fixture 沿用 2b-i 和 2b-ii 的：同一个固定种子的 log 8 玩具 proof，同样覆盖两个
query。每个负例都扫描**全部**行，并断言违反的（行，分组）集合与预期完全相同：

| 负例 | 拒绝位置 |
|---|---|
| 改 commit 阶段的一个盐 | 只有 `cap`，该轮的 cap 行 |
| 改两个兄弟值，使折叠结果**不变**（w_i·δ_i + w_j·δ_j = 0，p3 的 `fold_row` 也确认），另选新盐 | 只有 `cap`，第 0 轮的 cap 行 |
| 交换两个兄弟值，链条重算 | 第 0、1 轮的 `cap`，外加该 query 各行的 `final` |
| 第 1 轮沿用第 0 轮的下标右移量（位置、路径、s⁻¹ 和折叠都随之重算） | 错位的位确实不同时的 `position` / `s_inv`，放置方向变了的那几层的 `bind_child`，根变了时的 `cap`，以及 `final` |
| 第 1 轮用第 0 轮的 β 折叠，各次幂和折叠结果与之自洽 | 该 query 各行的 `fold_pow` 和 `final` |
| 改动两轮之间的当前值 | 该 query 各行的 `fold` 和 `select` |
| 链条不从 2b-ii 的 reduced opening 出发 | 只有 `ro_in`，该 query 那一段 |
| 第 0 轮之后再注入一次 ro（原生代码对第二个高度才会这么做） | 该 query 各行的 `fold` 和 `final`，外加第 1 轮的 `cap` |
| 一致地伪造一个 final polynomial 系数（2b-i 接受的那种伪造） | 只有 `final`，所有行 |
| 改终点 x 链中间的一个单元，下标不动 | 只有 `final_x`，该 query 各行 |
| 只在寄存器里翻转下标第 S_R 位（终点 x 的第一位） | 该段的 `index`；该 query 各行的 `final_x` 和 `s_inv`（两轮的 s⁻¹ 都读这一位）；读这一位的两层上的 `bind_child` |

下标右移那个负例的预期集合，是按该 query 自己的下标位算出来的；测试会断言这次错位至少
改变了一位。根是否改变，以原生重放为准。

**原生交叉核对**（诚实用例），覆盖**全部 43 个** query：p3 的 commit 阶段 MMCS
（`verify_batch`）在右移后的下标处接受每一轮的那组值；从 2b-ii 的原生 reduced opening 出发、
用 p3 自己的 `fold_row` 走完的链条，终点等于 final polynomial 在终点处的取值（也就是 `verify`
做的那项检查）；电路的复现（逆 DFT 折叠、常数链的 s⁻¹ 和 x、lab 的 Merkle 重放）得到相同的
中间值、相同的 Horner 结果和相同的 cap 表项。玩具 proof 在生成时已经通过了
`p3_uni_stark::verify`。诚实用例还做一次 SAT 扫描、检查 degree ≤ 3，并把玩具布局钉到
`price::query_phase` 上。

**真实 S3 proof 上的生产折叠方案。** 玩具按 `[4, 1]` 折叠（两轮）。另有一个测试在真实
hiding S3 proof 的方案上跑这个 AIR：四轮、每轮 arity 16，路径 15/11/7/3 层，4,096 行，覆盖
43 个 query 中的 2 个。它用的是 census 测试那份 S3 proof（`f2::s3_fixture`，现在是两个测试
共用的 `OnceLock`，所以 CI 每个测试二进制仍只 prove 一次 S3），用 p3 自己的 challenger 重放
FRI，用 2b-ii 的逐项实现重算 reduced opening，把 p3 的 commit 阶段 MMCS、`fold_row` 链和终点
检查与电路复现逐一比对，做一次 SAT 扫描，并断言改动两轮之间的当前值时恰好只触发该 query
各行的 `fold` 和 `select`。

### 尺寸 **[P，源码推导]**

玩具（lde 11，arity 先 16 后 2，路径 4 层和 3 层，终点域 2^6，16 个系数，2 个 query）：每个
query 2 + 4 + 1 + 3 = 10 个置换，共 20 个、480 行，高度 512。宽度 4,147 = 2,633（Keccak）+
1,088（M）+ 68（规范性）+ 286（寄存器）+ 72（保持列：2 个 β 加 16 个系数）。periodic 列
15 个，公共值 338 个。

`f2price` 现在按形状给出 43 个 query 下的 `query_phase`（`price::query_phase`，由
`query_phase_splits_the_census` 钉住）：

| 形状 | arity | 每 query 叶子 / 压缩 | 叶子 / 压缩 × 43 | lane 行数（补齐后） | 列数 | periodic | PV |
|---|---|---|---|---|---|---|---|
| S（lde 22） | 16, 16, 16, 16 | 8 / 36 | 344 / 1,548 | 45,408（2^16） | 4,657 | 74 | 807 |
| P（lde 23） | 16, 16, 16, 16, 2 | 9 / 43 | 387 / 1,849 | 53,664（2^16） | 4,690 | 77 | 939 |
| R（lde 21） | 16, 16, 16, 8 | 8 / 33 | 344 / 1,419 | 42,312（2^16） | 4,573 | 74 | 807 |

**与 census 对账。** S 在 43 个 query 时给出 **344** 个叶子置换和 **1,548** 个路径置换，正是
census 实测的 FRI 份额（1,419 − 1,075 和 3,999 − 2,451）。测试对三种形状都断言：输入份额加上
这一份，等于 census 几何给出的每 query 总数。

**每个 query 的折叠算术量**（arity 16）：29 次扩域乘法（u² … u¹⁵ 以及 Σ d_k u^k）、17 次扩域
乘基域（u 和位置选择）、逆 DFT 的线性组合（常数系数）、s⁻¹ 上 h 次基域乘法；之后 x 用 6 次基域
乘法，Horner 15 步。没有求逆 witness。

### 还缺什么

2a + 2b-i + 2b-ii + 2b-iii 现在覆盖了原生 hiding PCS verifier 对单个叶子 proof 所做的每一项
检查，但**各自在自己的 AIR 里**，还不是一个 verifier：

1. **组合。** 四个组件只通过公共值相连，它们之间的等式（D2；cap、ζ、z 值；fri_alpha、β、
   final polynomial、下标；reduced opening）目前由测试框架核对，而不是由电路强制。完整的单叶子
   verifier 需要二选一：把四个组件放进同一个电路，或者加一个显式的接缝核对组件，用约束强制
   这些等式。
2. **query 覆盖。** 各实例只覆盖 43 个 query 中的 2 个。在完整 S3 尺寸下带上全部 43 个 query
   的约束满足性，是 F2b-4 的验收项。
3. **quotient 恒等式与 periodic 求值**（`full_ood_air_checked`）以及 R-PV，属于 F2b-3，本片
   没有涉及。

因此 `pcs_input_bindings_complete`、`full_ood_air_checked`、`complete_verifier_layout` 和
`memory_gate_pass` 都保持 **false**：接缝还没有被任何约束强制，这几个标志在代码层面没有一个
真正成立。

### 验证

本地没有跑任何测试、proof 或 benchmark。本地预检为
`cargo check --workspace --all-targets --locked`、`qlab-bench` 上的 Clippy（`f2/` 下无告警）
和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`fold.rs` 八个、`price.rs` 一个，
共九个。**[P，待 CI]**：以 2b-ii 待定的 2,782 为基线，应为 2,791 项通过、0 失败、15 项忽略。

玩具相关的新测试在 Graviton lane 上预计耗时 5–30 秒 **[P]**。proof 和 2a 的导出与 2b-i、
2b-ii 的 fixture 共用（每个测试二进制一份）。其余是 43 条原生 query 链（每条两次 MMCS 核对、
两次 `fold_row`）、约十二个 512 × 4,147 的 trace、一次 SAT 扫描、约十二次并行的全表违反扫描，
以及一次 symbolic degree 计算。S3 测试**不新增 prove**：S3 proof（在 rig 上约 26 秒、峰值约
14 GiB，Graviton 上耗时约 2.7 倍）本来就由 census 测试生成一次，现在两者共用。它自己的工作是
一次 FS 重放、两个 reduced opening、两个 4,096 × 4,657 的 trace（各约 76 MB）、一次 SAT 扫描和
一次违反扫描：**约 5–20 秒，在共用 proof 之外不到 1 GiB [P]**。两个测试谁先跑，谁承担那次
prove。

尚未验证，按最可能先出问题排序：

1. 逆 DFT 形式的折叠与 `fold_row` 是否一致，尤其是兄弟值的位反转顺序和 s⁻¹ 的指数。玩具
   测试对全部 43 个 query 比对两者，但只在玩具的 `[4, 1]` 方案上。在生产方案（四轮 arity 16）
   上，比对、满足性检查和一个负例只覆盖**一个 S3 proof 的 43 个 query 中的 2 个**；P3 第五轮的
   arity 2、R 最后一轮的 arity 8（唯一带尾部 lane 的叶子）只经过 `price::query_phase` 的计数，
   从未经过这个 AIR。
2. 负例里（行，分组）集合是否精确，尤其是会连锁触发的那几个（交换兄弟值、下标错位、重复注入）。
   多触发一个分组会明确失败；正确的修法是把多出来的行写进预期，而不是放宽断言。
3. commit 阶段叶子的序列化（扩域 limb 按基底顺序，然后是盐）。p3 的 `verify_batch` 和
   “根等于 cap”的断言会暴露不一致。
4. 手算的 S/P/R 列数、periodic 数和 PV 数：census 拆分测试把它们钉住。

## F2b 组合 C1：transcript、执行器和 FRI transcript 共用一条 lane

这是协调者在 issue #750 上记下的组合方案（“F2b composition: two proofs per leaf”）的第一片。
p3 0.6.1 只能证明单张表，所以四个 F2b 组件被合成每个叶子两份 proof。**C1** 把 2a（uni-stark
transcript 加寄存器执行器）和 2b-i（FRI transcript）放进同一个 AIR、同一条 duplex Keccak lane，
并带上杠杆 **L1**。C2（2b-ii + 2b-iii）是下一片。C1 是仅用于测试的组件
（`crates/qlab-bench/src/f2/ood/c1.rs`），逐行扫描，从不 prove。已合并的四个组件及其测试
原样保留，继续作为回归基线。

### 一条 lane，一份 transcript

各次 flush 首尾相接：F0 → α，F1 → ζ，F2（opened value）→ fri_alpha，然后每个 commit 轮
G_r → β_r，再是 H（final polynomial、arity、PoW witness）→ PoW 和各个 query 窗口，最后是
refill。字的顺序全部沿用 2a、2b-i 已经对照 p3 源码钉住的顺序。**D2 变成了内部值**：F2 的
最后一个置换把 digest 交给 G_0 的第一块，用的就是其余每次 flush 都在用的 `flush_chain` 等式。
D2 不再有任何公开部分，2a→2b-i 这道接缝随之消失。honest 测试断言：lane 上 F2 的 digest 等于
2a 的重放结果，fri_alpha、每个 β、每个下标都等于 2b-i 对同一个 proof 的输出。

执行器就是 2a 的那个，没有改动：输入放在保持单元里，分别绑定到 transcript 中对应的字、
内层 PV 和 α/ζ 的抽样；最后一行上残差钉为 0，下一点钉为 g_N·ζ。

### 调度：transcript 部分不再用全周期 selector

2a 和 2b-i 给每个置换配一列全周期 periodic 列来做绑定的门控，另外还有两列 sponge 列。
下一层递归要在 ζ 处对每一列 periodic 列求值，代价是列数 × 周期。C1 改用主 trace 来调度，
做法与 m4gate 相同：

- **Keccak 自带的 `step_flags`**：p3-keccak-air 本来就约束了这个周期 24 的环，由它给出每个
  置换的 step-0 行和最后一行。
- **置换环（perm ring）**：每个 lane 置换一列主列，在它所指置换的全部 24 行上取 1。第一行指向
  置换 0，每个置换的最后一行把令牌交给下一个（`ring`）。最后一个置换之后环就空了。这个环
  完全由 Keccak 标志决定。

由环单元 P_p 门控的绑定在置换 p 的全部 24 行上成立，因此 prover 要把该置换的消息位、状态位、
规范性 witness 和抽样 witness **在这些行上复制一遍**。这样每个门控的 degree 都保持为 1，
与原来的 periodic selector 相同。可靠性的理由也和以前一样：复制的行里包含 step-0 行，
`absorb` 就在那一行把这些位绑到置换的输入上。链接类的门控再乘上 Keccak 的末行标志。
**剩下的 periodic 列只有执行器的 ROM**，仍是全周期的；去掉它们要靠杠杆 L5，本片没有做，
代价见下文。

### L1：在吸收行上累加 Az 和 Bz

原生的 `open_input`（p3-fri `verifier.rs:706-753`）给第 k 个 opened value 乘上 fri_alpha^k。
计数器只有一个，依次走过随机化器、trace 在 ζ 处和 ζ·g_N 处的值、quotient 各块，而这恰好就是
F2 的吸收顺序（2b-ii 的 `Geom::term` 及其测试已经钉住）。所以 Az（ζ 点各项的 Σ α^k z_k）和
Bz（ζ·g_N 点各项的同一求和）可以按 F2 的块依次累加：

- 一块 34 个字，最多碰到九项（j = 0..8）。F2 开头是 8 个链接字，而 34 ≡ 2 (mod 4)，所以
  **偶数块**从项的边界开始（槽 s → 项 j = s/4，limb s mod 4）；**奇数块**从上一块截断的那一项
  的 limb 2 开始：j = (s+2)/4，limb (s+2) mod 4。两套槽映射覆盖所有块。第 0 块按偶数块处理，
  j = 0 处对应项号 −2；那里是 D1 的字，由掩码滤掉。构造 AIR 时会用布局核对这两套映射，
  而不是想当然。
- 每行有 q_j = α^{k0+j}：九个扩域单元，q_{j+1} = q_j·α，T = q_8·α。q_0 在每个 F2 置换的最后
  一行更新：偶数块之后变成 q_8（下一块接着那个被截断的项），奇数块之后变成 T。F2 第一块上的
  锚点 q_2 = 1 把那里的 k0 定为 −2（`alpha_chain`）。
- pA_j、pB_j 是 q_j 按第 k0 + j 项的（静态）求值点做掩码的结果；D1 的字、padding 和另一个
  求值点上都为零。掩码是环单元之和，所以每个单元都是一个 degree 2 的等式（`mask`）。
- 在每个 F2 的 step-0 行上，Az += Σ_s pA_{j(s)}·e_{l(s)}·(R⁻¹·word_s)，Bz 用 pB 以同样方式
  累加。两个物化的门控（step-0 ∧ 偶数块、step-0 ∧ 奇数块）让这次更新保持在 degree 3
  （`gate`、`accumulate`）。

这样 C2 就不再需要那张 5,912 列的 α 幂次与 z 值表（S3）。C1→C2 的接缝传的是 Az、Bz 这 8 个
值，而不是 1,478 个 opened value。

**为什么在抽出 fri_alpha 之前累加是可靠的。** fri_alpha 从 D2 抽出，而 D2 是在 opened value
吸收**之后**才有的；但 F2 各行上的累加又要用到它。α 放在一个**保持**单元里：每一行都是同一个
值（`hold`），并且等于 G_0 第一块上的抽样（`fs_bind`）。有了保持，“F2 各行上用的 α”和
“从 D2 抽出的 α”就是同一个单元，前面那些行算出的累加和用的正是抽出来的值。这里没有循环：
trace 是一次性给定的静态 witness，每条约束都只是 prover 同时定下的若干单元之间的等式。
抽样是 D2 的函数，D2 是被吸收的字的函数，Az、Bz 则是同一批字和同一个 α 的函数。若 prover
在 F2 各行放 α′、在抽样行放抽出的 α，`hold` 就会在单元变化的那一行被打破；下面的负例测的
正是这个。

### C1 导出的接缝

`c1.rs` 里的 `Seam` 把 C1→C2 的接缝表示成值，`Seam::read` 是从 C1 公共值读出它的、可直接
供 `check_seams` 使用的访问器。输入是内层 PV 和每一个 cap（trace、quotient、随机化器，然后是
各 commit 轮），它们约束被吸收的字。输出是 ζ（取自执行器的保持单元）、fri_alpha（保持单元）、
Az 和 Bz（最后一行上的累加器）、每个 β、final polynomial 以及 43 个 query 下标；每一项都在
自己的抽样行或字所在行上直接绑定，不另设保持副本。合计 16 + 4R + 64 + 43 个值，S3 为 139 个。
opened value **不导出**，因为 C2 只需要 ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x)。
honest 测试针对**全部 43 个 query**，把这个拆分与 2b-ii 的顺序版 `open_input` 复刻逐一比对。

### 约束分组与测试

共 27 个命名分组：`keccak`、`bits`、`absorb`、`ring`、`chain_state`、`flush_chain`、
`bind_const`、`bind_cap`、`bind_inner_pv`、`canonical`、`fs_reject`、`fs_select`、`fs_bind`、
`bind_final`、`pow`、`fs_index`、`bind_opened`、`in_public`、`hold`、`machine`、`machine_out`、
`alpha_chain`、`mask`、`gate`、`accumulate`、`cells_out`、`az_out`。所有约束的 degree 都 ≤ 3，
由 honest 测试在 symbolic builder 上检查。fixture 是 2b-i 那个带种子的 log-8 玩具 proof（两轮
FRI），与 2b-ii、2b-iii 共用。每个负例都扫描**全部**行，并断言精确的（行，分组）集合。
下表中“置换各行”指该置换的全部 24 行。

| 负例 | 在哪里被拒 |
|---|---|
| ζ 的一个 limb 错了，执行器按错值重算 | ζ 抽样置换各行上的 `fs_bind`，加最后一行的 `machine_out` |
| α 的一个 limb 错了，执行器按错值重算 | α 抽样置换各行上的 `fs_bind`，加最后一行的 `machine_out` |
| fri_alpha 错了，但在每行保持、一致导出、累加和也按它重算 | 只有 G_0 第一个置换各行上的 `fs_bind` |
| **保持的 fri_alpha 前后不一**：F2 各行和导出用 α′，从抽样行起用抽出的 α | 只有 `hold`，就在单元变化的那一行 |
| β_0 取了一个被跳过的合格抽样，并一致导出 | 其抽样置换各行上的 `fs_select` |
| F1 的两个 cap 互换，整条 transcript 一致重放（自己的 ζ、重解 quotient、重建 F2/D2、自己的 fri_alpha 和 β、用 p3 的 challenger 重新 grind PoW、自己的下标和累加和） | 只有 `bind_cap`，在 cap 字变了的那些 F1 置换上 |
| FRI 两轮的 cap 互换，一致重放（自己的 β、重新 grind PoW） | 只有 `bind_cap`，在 cap 字变了的那些 G_0/G_1 置换上 |
| transcript 里改一个 opened value（trace local 第 0 列），执行器不动，F2 之后全部重放并重新 grind | 只有 `bind_opened`，在该值所在置换各行上 |
| **同一个值只在 Az 累加里改**（transcript 和执行器都诚实；Az 及其导出偏移 fri_alpha⁴） | 只有 `accumulate`，在该值的 step-0 行上 |
| **把一个 trace-next 项放到 ζ 的掩码下**（两个累加和都重算并导出） | 只有 `mask`，在该块置换各行上 |
| 一个 opened 字写成 word + p | 其置换各行上的 `canonical`，加窗口 0 置换各行上的 `pow`（D2 变了，PoW 未重新 grind） |
| PoW witness 过不了 grind，其余部分重放 | 窗口 0 置换各行上的 `pow` |
| 导出的某个下标翻转一位 | 其窗口置换各行上的 `fs_index` |
| **改动导出的 Az / Bz** | 最后一行的 `az_out` |
| 改动导出的 ζ / fri_alpha | 第 0 行的 `cells_out` |
| 改动导出的某个 β | 其抽样置换各行上的 `fs_bind` |

**原生交叉核对**（honest 测试）：每个挑战（α、ζ、fri_alpha、两个 β）都来自 p3 自己的
challenger；p3 的 `check_witness` 接受 PoW；每个下标都等于 p3 的 `sample_bits`；lane 上 F2 的
digest 就是 2a 的 D2；fri_alpha、β 和下标等于 2b-i 的输出。从公共值读出的 `Seam` 等于原生算出
的接缝。Az、Bz 来自按源码顺序写的 `open_input` 求和，直接从 proof 的结构写出，不依赖布局。
对全部 43 个 query，2b-ii 的原生 reduced opening 都等于
(Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x)。测试还跑一次 SAT 扫描、检查 degree ≤ 3，并把玩具
布局钉到 `price::composed_c1_layout`。

### 尺寸 **[P，源码推导]**

`price::composed_c1(shape)` 由 `composed_c1_pins_the_census` 钉住。lane 是整条 challenger
transcript，再加最后一次 refill，它的第一块携带最后一个窗口的 digest 位。S3 上就是 census 的
**206** 个 challenger 置换 + 1 = 207。

| shape | lane 置换（challenger + 1） | lane 行数 | 补齐后行数 | 列数 | periodic（ROM，全周期） | PV | 接缝输出 |
|---|---|---|---|---|---|---|---|
| S | 207（206 + 1） | 4,968 | 2^15 | 11,746 | 2,227 | 1,151 | 139 |
| P | 228（227 + 1） | 5,472 | 2^15 | 12,655 | 2,593 | 1,295 | 143 |
| R | 209（208 + 1） | 5,016 | 2^15 | 12,040 | 2,364 | 1,136 | 139 |

S 的列构成：Keccak 2,633，消息位和状态位 2,176，规范性 68，抽样 72，置换环 207，L1 122，
保持的 fri_alpha 4，执行器输入 5,248（1,312 × 4），执行器 1,216。行数由执行器决定：lane 只占
2^15 行中的 4,968 行。

**与计划对比**（S3 约 12.4k 列 × 2^15）：实际 11,746 × 2^15。C1 不再保留 2b-i 的下标位保持列
（S3 上 43 × 22 = 946 列）：每个下标直接从抽样位绑定到输出，由 C2 自己再拆位。新增的是置换环
（207）和 L1（122）。

**ROM 的代价（L5，暂缓）。** C1 的 verifier 要在 ζ 处对每一列全周期 ROM 求值：ROM 列数 × 2^15
次扩域乘法，**S3 为 7,300 万次**（2,227 × 2^15），P3 为 8,500 万次，R 为 7,750 万次。被置换环
取代的 sponge selector 原本还要再加 (置换数 + 2) × 2^15，S3 上是 685 万次。协调者说的
“C1 约 7,900 万次”正是两者之和（7,980 万次）；现在只剩 ROM 这一部分。

### C1 还没做的事

- **C2**（把 2b-ii + 2b-iii 做成按 query 分段，含杠杆 L2、L3）是下一片。目前还没有任何东西
  从 C2 的公共值里读出 C1 的 `Seam`，所以两份 proof 之间的接缝尚未被强制。`Seam::read` 就是
  将来 `check_seams` 要用的访问器。
- **执行器 ROM** 仍是全周期 periodic（L5）。
- **query 覆盖与完整尺寸。** 玩具只有两轮 FRI 和一个很小的执行器；完整 S3 尺寸（2^15 行）的
  C1 还从来没有构建过。

`pcs_input_bindings_complete`、`full_ood_air_checked`、`complete_verifier_layout` 和
`memory_gate_pass` 仍然是 **false**。

### 验证

本地没有跑任何测试、proof 或 benchmark。本地预检为
`cargo check --workspace --all-targets --locked`、`qlab-bench` 上的 Clippy（`f2/` 下无告警）
和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`c1.rs` 六个、`price.rs` 一个，共七个。
**[P，待 CI]**：以 2b-iii 的 2,791 为基线，应为 2,798 项通过、0 失败、15 项忽略。

新测试在 Graviton lane 上预计耗时 10–45 秒 **[P]**，**不新增 prove**：proof 用的是 2b-i 的，
每个测试二进制共用一份。工作量包括：用 p3 的并行 `grind` 做三次 22 位 grind（两次 cap 互换和
一次 opened value 改动）、十八次并行的全表违反扫描和一次 SAT 扫描（trace 为 2^10 行、约
5.5k 列）、43 次原生 reduced opening、一次 symbolic degree 计算，以及 price 测试里三个 shape
的程序各编译一次。

尚未验证，按最可能先出问题排序：

1. 复制之后（行，分组）集合是否精确。凡是由置换门控的违反，预期都出现在该置换的全部 24 行上。
   多出一个分组会明确失败；正确的修法是把它写进预期，而不是放宽断言。
2. L1 的槽映射，以及 q_0 跨越被截断项时的更新。构造时会用布局核对映射，43 个 query 的拆分核对
   也把累加和从头到尾走了一遍，但都只在玩具的五个 F2 块上。S3 的 F2（175 块）只有公式定价，
   `Layout::new` 的映射核对从没在它上面跑过。
3. 手算的 S/P/R 钉值：执行器尺寸取自 F2b-0 的 census 表，lane 置换数取自 census 的几何推导。

## F2b 组合 C2 与接缝

这是 issue #750 上记下的组合方案的第二片。**C2** 把 2b-ii（输入批次的 opening 和 reduced
opening）与 2b-iii（commit 阶段的 opening、折叠和 final polynomial）放进同一个 AIR、同一条
覆写模式的 Keccak lane（L4），**每个 query 一段**，并带上杠杆 **L2** 和 **L3**。C1 的导出值
通过一道有名字的接缝交给 C2。C2 是仅用于测试的组件（`crates/qlab-bench/src/f2/ood/c2.rs`，
接缝在 `ood/seam.rs`），逐行扫描，从不 prove。已合并的四个组件、C1 以及它们的测试，行为
都没有变；只是把布局类型改成了 `pub(super)`，让 C2 直接复用，不必另抄一份。

### 分段与调度

每个被覆盖的 query 占一段：先是 2b-ii 的置换，排法与 `open.rs` 完全相同（随机化器、trace、
quotient 三个叶子 sponge，加三条输入路径），紧接着是 2b-iii 的置换（每轮先叶子、后路径），
然后才轮到下一个 query。S3 上每个 query 是 82 + 44 = 126 个置换，43 个 query 占满 2^17 行中的
130,032 行。

**C2 完全没有 periodic 列。** Keccak 自带的周期 24 的 `step_flags` 给出每个置换的 step-0 行和
最后一行。**位置环**是 one-hot 的，每个段内位置一列主列，在该位置的置换的全部 24 行上取 1；它在
每个置换的最后一行前移，到段尾绕回位置 0，但若这一段属于最后一个 query，环就清空。**query 环**
也是 one-hot 的，每个被覆盖的 query 一列，在每个段尾前移。两个环都完全由 Keccak 标志决定。和 C1
一样，由位置单元门控的绑定在全部 24 行上成立，所以 prover 要把该置换的消息位和规范性 witness
在这些行上复制一遍。有些绑定只需要最后一行：把一个置换的输出与下一个置换的输入相比较的那些
（子节点左右位置、capacity 和尾部 lane 的延续），以及 cap 检查。它们的门控（末行标志 × 位置
单元）做成物化单元：路径层每读一个下标位配一个，每个 cap 检查配一个。这样这些绑定都保持在
degree 3（`gate`）。

### 使用 C1 的接缝

C2 里不出现任何 z 值，也不出现任何 opened value。**C2 的公共值就是接缝**（`seam::Seam`）：
每一个 cap（trace、quotient、随机化器、各 commit 轮）、ζ、fri_alpha、Az、Bz、每个 β、
final polynomial，以及被覆盖的 query 的下标。ζ、fri_alpha、Az、Bz、各 β 和 final polynomial
放在保持单元里，在第 0 行绑定到公共值（`seam_in`）；cap 由 cap 检查直接读取；下标经 query
环钉住下标位（`index`）。每个 query 上，

  ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x)，

其中 Ax、Bx 由经过 Merkle 认证的行值、按原生 `open_input` 的顺序累加而来。C1 吸收 opened value、
给 Az 和 Bz 加权，用的正是这个顺序。两个 AIR 都从**同一张表 `seam::open_order`** 读取它：C1 的
F2 布局由它生成，C2 的 `Layout::new` 则拿它逐块核对输入块。每块的行值必须是连续的项；trace
第 c 列在 ζ·g_N 处的项号必须等于它在 ζ 处的项号 + w；相邻两块必须逐项衔接，唯一的例外是 trace
之后要跨过那 w 个 ζ·g_N 项。所以两边不可能按不同的顺序求和。

### L2：fri_alpha 幂次逐步推进

2b-ii 给每个 opened 项保存一个 fri_alpha 幂次，S3 上是 5,912 列；与之配套的 z 值表已经被 L1
去掉了。C2 只保留：

- **保持的幂次表 α^1..α^34**：一个叶子块 34 个字，最多装 34 个行值；
- **保持的 α^w**，w 是 trace 宽度；
- 每行一个**滚动幂次 p = α^{k0}**，k0 是当前输入块第一个行值的项号。

块内行值是连续的项，所以 blk = Σ_i α^i v_i 直接查表（`blk`）。Ax += p·blk；在 trace 块上还有
Bx += pw·blk，pw = p·α^w（`accumulate`），因为 trace 第 c 列在 ζ·g_N 处的项号是 D + w + c。
这些累加都由 step-0 标志门控。p 的规则（`alpha_pow`）：

- **锚点**：每段第一块上 p = 1；
- **推进**：经过一个含 n 个行值的块，p 乘上 α^n。最后一个 trace 块之后乘 α^w·α^n（经由 pw），
  借此跳过那 w 个 ζ·g_N 项；
- **保持与复位**：p 在路径置换上保持不变，到段尾复位为 1；
- **钉住 α^w**：在 trace 项结束的地方，由最后一个 trace 块上的 p·α^n = α^D·α^w 定下 α^w。幂次表
  本身是从 fri_alpha 出发、在第一行上逐项相乘的一条链。

S3 上这套幂次只占 136 + 4 个保持列和 16 个滚动列，替换掉原来的 5,912 列。

### L3：交接

下标位和 ro 是**同一组寄存器单元**，在整段上保持不变（`handoff`）。同一组位单元驱动 x、三条
输入路径、cap 的 one-hot（所有批次和轮次共用）、commit 阶段的路径（第 r 轮第 t 层读第
S_{r+1} + t 位）、各轮折叠位置、s^-1 以及最终的 x。读同一个位的输入层和 commit 层共用一个门控
单元。reduced opening 在 opening 部分算出（`reduce`，放在最后一个输入置换的 24 行上，那里 Ax、
Bx 已经累加完），折叠链的起点就是这个单元（`select`，第 0 轮）。两部分之间没有任何重复：2b-iii
自己的那套下标位和 cap one-hot（lde + 12 列）已经不存在了。

### 接缝与 `check_seams`

`Seam` 就是 C1→C2 的精确取值集合，`SeamShape` 给出它唯一的编码方式。C1 的公共值是内层 PV
后面接上这一段；C2 的公共值恰好就是这一段，下标只带它覆盖的那几个 query 槽位。`Seam::read`
（C1）和 `Seam::decode`（C2）负责把它读回来。**`check_seams(c1, c2) -> Result`** 按分组逐项
比较，下一层递归要在电路里写的就是这些等式；出错时报出第一个不相等的分组名。C2 覆盖哪些槽位
是它布局的静态属性。C2 是否覆盖了 C1 抽出的每一个 query，另由 **`check_coverage`** 回答：
生产实例覆盖全部 43 个；玩具实例只覆盖 2 个，honest 测试断言 `check_coverage` 会拒绝它。

| 分组 | S3 上的个数 | 编码 |
|---|---:|---|
| cap（trace、quotient、随机化器、4 个 commit 轮） | 7 × 8 个 digest = 896 个 limb | 16 位 limb |
| ζ | 4 | 扩域 limb |
| fri_alpha | 4 | 扩域 limb |
| Az、Bz | 8 | 扩域 limb |
| β（每轮一个） | 16 | 扩域 limb |
| final polynomial | 64 | 扩域 limb |
| query 下标 | 43 | 每个一个域元素 |
| **合计** | **1,035** | = C1 的 1,151 个 PV − 116 个内层 PV |

不算 cap，S3 上的接缝是 139 个值，与 C1 的接缝输出数一致。cap 是 C1 声明的输入，C2 按同一种
编码读取。

### 约束分组与测试

共 32 个命名分组：`keccak`、`bits`、`absorb`、`ring`、`gate`、`capacity`、`bind_zero`、
`bind_carry`、`bind_child`、`cap`、`canonical`、`leaf_bind`、`index`、`cap_select`、
`x_point`、`inverse`、`alpha_pow`、`blk`、`accumulate`、`reduce`、`position`、`select`、
`s_inv`、`fold_pow`、`fold`、`final_x`、`horner`、`final`、`seam_in`、`hold`、`handoff`、
`ctx_hold`。所有约束的 degree 都 ≤ 3，玩具和 S3 两个实例都在 symbolic builder 上检查过。fixture
是 2b-i 那个带种子的 log-8 玩具 proof；C1 的 honest 接缝由同一个 proof 构建；C2 实例覆盖两个
cap 条目不同的 query（沿用 2b-ii 的选法）。每个负例都扫描**全部**行，并断言精确的（行，分组）
集合。

下表中的“连带后果”专指一个一致重推的伪造无法掩盖的东西，完全由原生重放算出：凡是根与其下标
所选的接缝 cap 条目不符的，在该检查所在行由 `cap` 拒绝；凡是最后一次折叠与 final polynomial
不符的 query，在它的寄存器各行由 `final` 拒绝。

| 负例 | 在哪里被拒 |
|---|---|
| 改输入叶子的 salt | 该批次 cap 行上的 `cap` |
| 改一个输入行值并换新 salt，Ax、ro 和折叠链随之重推 | 连带后果：输入 cap、两个 commit cap、`final` |
| 输入路径上两个 sibling 互换 | 该批次 cap 行上的 `cap` |
| 输入子节点放错边，下标位不动 | 送入那一层的行上的 `bind_child`，加 `cap` |
| 整段翻转下标第 3 位，其余一切随之改动 | 该段各行上的 `index`，加连带后果（其中包括全部三个输入 cap） |
| cap 的 one-hot 选错 | 该 query 各行上的 `cap_select`，加全部五个 cap 检查 |
| x 不做位反转，逆元、ro 和折叠链随之重推 | 该 query 各行上的 `x_point`，加连带后果 |
| 整段改动 ro | 最后一个输入置换各行上的 `reduce`，加该 query 各行上的 `select` |
| 改 commit 阶段的 salt | 第 1 轮 cap 行上的 `cap` |
| 改动第 0 轮两个 sibling，使折叠结果不变 | 只有第 0 轮 cap 行上的 `cap` |
| 第 0 轮 sibling 互换，链条重推 | 连带后果 |
| 第 1 轮用 β_0 折叠 | 该 query 各行上的 `fold_pow`，加 `final` |
| 改动两轮之间的值 | 该 query 各行上的 `fold` 和 `select` |
| 伪造 final polynomial（公共值与保持单元一致） | 每一行上的 `final` |
| 改动最终 x 链中的一个单元 | 该 query 各行上的 `final_x` |
| **公共值里的 Az 与保持单元不一致** | 第 0 行的 `seam_in` |
| **C1 给的 Az 不同，C2 按它一致重推**（保持单元、公共值、ro 和折叠全部重推） | `check_seams` 报出 `az`；在 C2 内部是连带后果（伪造的 ro 对不上 commit 阶段的叶子） |
| **八个接缝分组逐一在 C1 一侧、再在 C2 一侧篡改** | `check_seams` 报出对应的分组名，八组全部如此 |
| **重复使用一个滚动幂次**（query 1 最后一个 quotient 块沿用前一块的幂次，Ax、ro、折叠一致） | p 本该推进的那一行上的 `alpha_pow`，加连带后果 |
| **跳过一个滚动幂次**（query 0 的 trace 块多乘一次，后面各块跟着偏移） | 进入该块那一步的 `alpha_pow`，以及该块 24 行上的 `alpha_pow`（α^w 钉），加连带后果 |
| **ro 在两部分之间被改**（opening 部分算出诚实的 ro，折叠部分从 ro + 1 开始） | 交界行上的 `handoff`，加折叠部分各行上的 `select` |
| **折叠部分的下标第 S_R 位与 opening 部分不同** | 交界行上的 `handoff`；折叠部分各行上的 `index`、`x_point`、`s_inv`、`final_x`；读该位的两层 commit 路径上的 `bind_child` |

**原生交叉核对**（honest 测试）：

- 对**全部 43 个 query**，C2 按块计算的 Ax/Bx（用保持表里的滚动幂次）等于 C1 那个按源码顺序
  写的 `open_input` 求和；与 C1 的 Az/Bz 组合后，等于 2b-ii 顺序版的 reduced opening。
- 滚动幂次在共用的项序下正是 α^{k0}。
- 对被覆盖的 query，折叠链和最终检查与 p3 一致（commit 阶段的 MMCS、`fold_row`），每个根都是
  接缝里对应的 cap 条目。
- 此外还检查：SAT、degree ≤ 3、periodic 列为零；用同一个 proof 构建的 honest 组合上
  `check_seams(C1, C2)` 通过；玩具布局钉到 `price::composed_c2_layout`。
- **真实的 S3 生产调度**（25 个输入叶子置换和 3 × 19 个输入路径层，然后是四轮 arity 16、路径
  长 15/11/7/3 的折叠）在共享的 census proof 上跑两个 query。接缝由 p3 的 challenger 和按源码
  顺序的求和算出，ro、Ax/Bx 和各次折叠都与原生代码对拍。测试覆盖 SAT、degree ≤ 3 和价格钉值。

### 尺寸 **[P，源码推导]**

`price::composed_c2(shape)` 由 `composed_c2_pins_the_census_and_the_plan` 钉住。在 43 个
query 下，C2 的 lane 恰好是 **census 几何里全部的叶子置换和路径置换**，challenger 的置换归
C1。S3 上是 43 × (25 + 8) = **1,419** 个叶子置换，43 × (57 + 36) = **3,999** 个路径置换。

| shape | 每 query 置换（输入 + commit） | lane 行数 | 补齐后行数 | 列数 | periodic | PV（= 接缝） |
|---|---|---|---|---|---|---|
| S | 126（82 + 44） | 130,032 | 2^17 | 5,058 | 0 | 1,035 |
| P | 139（87 + 52） | 143,448 | 2^18 | 5,107 | 0 | 1,167 |
| R | 120（79 + 41） | 123,840 | 2^17 | 4,966 | 0 | 1,035 |

S 的列构成：Keccak 2,633，消息位 1,088，规范性 68，位置环与 query 环 169（126 + 43），末行门控
26，query 寄存器 818（其中 26 列是交接部分），滚动单元 24，保持的接缝值 232。

**与计划对比**（S3 约 5.0k 列 × 2^17；P3 → 2^18）：S3 实际 5,058 × 2^17，P3 为 2^18。与 2b-ii +
2b-iii 相比的差额来自三根杠杆：L1 和 L2 各去掉一张 5,912 列的表，L3 去掉 2b-iii 那套重复的
下标位和 one-hot（34 列）。新增的是两个环、门控单元和 140 个保持的幂次列。由于没有 periodic
列，下一层不必为 C2 的调度付出任何按行计的代价。

### C2 还没做的事

- **电路内的接缝。** `check_seams` 目前是原生的；下一层递归要在电路里写出同样的等式。
- **完整尺寸。** 43 个 query 的 C2（2^17 行）从没构建过；S3 测试只构建两个 query（2^13 行）。
- **计划中的第 3 片（selector 转换）和 C1 的全周期 ROM（L5）** 不在本片范围内。C2 本身已经
  没有 periodic 列。

`complete_verifier_layout` 和 `memory_gate_pass` 仍然是 **false**。

### 验证

本地没有跑任何测试、proof 或 benchmark。本地预检为
`cargo check --workspace --all-targets --locked`、`qlab-bench` 上的 Clippy（`f2/` 下无告警）
和 rustfmt；验收以 `verify-graviton` CI 为准。新增测试：`c2.rs` 七个、`price.rs` 一个，共八个。
**[P，待 CI]**：以 C1 的 2,798 为基线，应为 2,806 项通过、0 失败、15 项忽略。

新测试在 Graviton lane 上预计耗时 20–60 秒 **[P]**，**不新增 prove**：玩具 proof 用 2b-i 的，
S3 proof 用 census 测试的，每个测试二进制各共用一份；如果 C2 的 S3 测试先跑，就由它承担那次
原本就有的约 26 秒 S3 prove。工作量：

- 构建一次 C1 的 honest trace；
- 在 2^11 行、4,395 列的 trace 上做二十一次并行全表违反扫描和一次 SAT 扫描；
- 43 × 2 次原生 reduced opening 和块求和；
- 在 2^13 行、约 5.0k 列的 S3 trace 上做一次 SAT 扫描；
- 两次 symbolic degree 计算。

尚未验证，按最可能先出问题排序：

1. 复制之后（行，分组）集合是否精确，特别是由原生重放推出的“连带后果”集合，以及 `alpha_pow`
   所在行的取法（伪造块之前的最后一行）。
2. L2 在 S3 的 22 个 trace 块上的项号记账：只在两 query 的 S3 测试（SAT）里跑过，从没经过负例。
3. S/P/R 的钉值：假定 census 几何成立，且公式与列分配完全对应。玩具和两 query 的 S3 实例把公式
   钉到了 AIR 上；P 和 R 只有公式。
