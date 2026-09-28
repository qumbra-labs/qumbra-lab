# F2 原生验证计数：协调会话操作手册

[English（技术权威版本）](f2-census-runbook.md)。依据：[issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750)。

Larry 于 2026-09-26 同意 stage-zero 的建议：隐藏交易 AIR 保留 degree 4；
外层聚合采用 non-hiding，witness 仅含公开 proof 和公开数据；完整 verifier
及绑定工作完成后才能宣布聚合门槛通过；interior 优先走 b2。
旧记录的 GB/GiB 歧义解决前，暂用更严格的 **32,000,000,000 bytes** 工作门槛。
大内存机器用于测量，不代表生产内存标准已放宽。

本次新增首批工具 `f2fixture`、`f2census`、`f2price`。
尚未实现 `f2gate`、`f2interior` 或完整递归电路布局，未解决 issue #78，
也不宣布内存通过。符号报告会列出尚未定价的部分；聚合 trace 分配前必须补齐布局计数。

## 仅在协调会话的测量机器执行

开发者机器禁止运行测试、fixture proving 或 benchmark；本地可运行
`cargo check --workspace --all-targets --locked`。验收测试在 `verify-graviton`
CI 执行。fixture 生成必须使用能承载当前 hiding L2 proof 的机器，每个 producer
独立进程串行执行，不与 CI 或其他 benchmark 重叠。

测量机器先固定 checkout，再编译 release binary。记录完整 commit、`Cargo.lock`、
`rustc -Vv`、硬件、OS、实际可用内存、电源和温度状态。
`--revision` 明确是**操作者声明的构建版本**，不是二进制对自身来源的认证。

英文版提供完整命令：先用 `f2price --shape p3 --symbolic-only` 获取符号计数，
再用 `f2fixture --shape p3 --out <path>` 生成公开 fixture，最后通过独立进程
`f2census --shape p3 --proof-in <path>` 统计验证工作量。所有模式需要完整
`--revision`；census/price 可显式指定 `--input-pcs hiding --rc 0 --report json`。
输出 JSON 写到 stdout，诊断和 `/usr/bin/time -v` 记录写到 stderr。

对 `s3`、`r` 串行重复。两次独立样本使用不同输出路径，工具拒绝覆盖已有 fixture。
发布测量前须同机复现两次。保存原始内存单位：Linux 的 max RSS 是 KiB，
JSON 只报告 proof 字节数和哈希计数，**不报告内存峰值**。
producer 与 census 分开测；串行流水线峰值取两者最大值，不求和。
带计数器的 verifier 耗时属于插桩耗时。

fixture 仅包含 proof、规范公共值、shape digest、当前 lane/PCS 参数、格式版本和
producer revision，不含交易 witness 或密钥。来源是已有合成 L2 fixture builder，
不是用户交易。解码有大小限制并拒绝尾随字节；这是 bench 格式，不改变交易或网络格式。

## 输出能证明什么

`f2census` 拒绝 shape digest、PCS/lane、rc 不匹配、非规范公共值、错误 opening
维度、缺失 randomizer、盐值结构错误、路径或 fold 数错误。之后，同一份序列化
proof 必须同时通过当前 L2 config 和计数镜像的原生验证。计数适配器调用相同
Keccak 原语；没有计数版 prover。

成功后 `measured_hash_work` 标为 **M**：leaf absorb、Merkle compression、
Fiat–Shamir permutation 以及每次 transcript flush 的字节数。
几何推导标为 **P**；真实 leaf/path 数须与推导一致，transcript 数不得低于
不发生 rejection refill 时的下界。任何差异都导致命令失败，不输出成功报告。
rc0 仍然必须保留 randomizer 承诺和盐值。

`f2price` 读取真实 witness-free AIR 的符号约束，按共享指针统计 add/sub/neg/mul
节点，并报告最大 degree、hiding quotient chunk 数、periodic column 周期和
未优化 alpha fold。这属于 **P**，不是 prover 实测、结构公共子表达式消除后的最优解，
也不是寄存器或行布局；它不分配 trace、不 prove。
工具始终明确输出 `complete_verifier_layout: false` 和 `memory_gate_pass: false`。

### 可执行 OOD 算术模型

`f2price` 新增 `ood_arithmetic`，以显式扩展域算术 DAG 表达 periodic 求值、
AIR selector/约束、alpha fold、quotient 重组和最终 OOD 恒等式。
其计数标为 **P**，尚未做结构公共子表达式消除、常量折叠或寄存器分配。
输入读取和常量单独计数，inverse 是显式操作。这是可执行算术模型，**不是 AIR**。
`symbolic_air.not_lowered` 仍列出递归 AIR 中尚未实现的部分。

`f2census` 在原生 proof 验证成功后，重放包括 randomizer 承诺的 uni-stark
challenger 前缀，以真实 opening 执行 DAG，并将 periodic 值、selector、next-row
point、quotient 和 AIR fold 与原生实现比较。`ood_algebra.residual_zero` 必须为
true；任何差异均令 census 失败。不额外生成 proof。

AIR selector、periodic 列和 next-row point 使用原始 **N** 域，trace 承诺使用
**2N** 域。编译时对公开 AIR 常量做 IDFT 得到 periodic 系数，再以显式 Horner
操作在 `zeta^(N/period)` 求值。First/last selector 保留原生非归一化约定。
每个 quotient chunk 的四个 opening 本身是**扩展域元素**，与扩展域基常量相乘
后，再应用原生 split-domain 插值权重。随机化后的 PCS chunk commitment 域
不是重组域。原始 trace 域内的 zeta 被 inverse-of-zero 检查拒绝；输入维度错误
在索引之前被拒绝。不支持的 symbolic source 报错，不以零代替。

下一检查点须在递归 AIR 中约束这些操作，包括每个 inverse（`x * inv = 1`）、
输入读取、写入和寄存器 hold；还须补齐 randomizer/salt 绑定、shape/config 身份、
各 shape 的费用和状态转换，以及 issue #78 剩余工作。
由实现重新计算宽度和 padded height，不能把 stage-zero 宽度预算直接
当作已验证的分配尺寸。

`ood_arithmetic.register_schedule` 现在计入按最后使用位置复用寄存器的调度；
census 也将稀疏执行逐条与可达 DAG 节点比较。
[寄存器执行器说明](f2-register-machine-zh.md) 解释有界、仅用于测试的参考 AIR
及其显式 ROM 成本。这不改变完整布局/内存验收标志。

## 验证与限制

CI 回归测试会串行生成真实 S3/P3/R proof，检查两个原生 verifier、几何与计数一致性，
并修改 randomizer、salt、rc0 嵌套、P3 额外 fold 和公共值验证拒绝行为。
轻量测试固定纸面几何、当前 AIR 元数据，拒绝不兼容参数及 fixture 元数据。
测试代码存在不表示 CI 已通过，应以 PR 对应提交的 CI 结果为证据。
完整递归 soundness、最终宽高、混合 shape 聚合和内存门槛仍未由这些工具验证。

OOD 回归检查以确定性的扩展域输入对拍三个 shape，覆盖每个 quotient chunk 的
每个基系数，区分 N 与 2N，拒绝域内 zeta、错误维度和不支持的 source。
既有真实 proof 测试也检查诚实输入的零 residual，并篡改 quotient 系数、local/next
opening、被消费的公共值、alpha 和 zeta。这些是算术组件检查：原生 PCS 拒绝不能
代替对拍，通过也不代表完整递归验证已实现。

## R-PV（F2b-3）：所有叶子 PV 分组都走 (c)

依据 issue #750 的 R-PV 裁定及其补充。**C1 把内层叶子的全部 PV 原样暴露**为自己的公共值
`[0, pv_len)`：S3 116 个，P3 128 个，R 101 个。没有任何分组被压缩，也没有哪个内层 PV
被哈希、求和或并入别的值。因此 (c) 覆盖全部分组：

| shape | 暴露的分组（全部） | 压缩的分组 |
|---|---|---|
| S3 | anchor、nf1、nf2、cm1、cm2、fee、registry_root、nf3 | 无 |
| P3 | S3 的前七组、vp1/vp2（sign、amount、asset）、nf3 | 无 |
| R | anchor、nf、cm、fee、old_root、new_root、asset、cm_seed | 无 |

C1 **不**做范围检查。读取内层 PV 单元的约束只有两组：`bind_inner_pv`（PV = R⁻¹ · 吸收的
word，word 由 `canonical` 保证 `< p`）和 `in_public`（寄存器机的输入单元）。测试
`c1_accepts_an_out_of_range_leaf_pv` 演示了这一点：toy 叶子的 PV 1 远大于 2^16，C1 照样
满足约束。所以聚合 proof 的使用方在接受之前，必须先调用 `seam::check_leaf_pvs(shape, c1_pvs)`。
这个检查会拒绝超出位宽的 PV，并按分组和下标报出名字（例如 `` `fee[0]` ``）。

位宽**不在这里另写一份**。`seam::leaf_pv_widths` 直接取自叶子 AIR 自己的 PV 构造函数
（`qlab_air::l2::pv_vec_l2`、`l2p::pv_vec_l2p`、`l2r::pv_vec_r`，经 `qlab-l2` 再导出）：
把类型允许的最大输入喂进去，看每个槽位输出值的位长。结果是：

- 所有 `& 0xffff` 分块（摘要、fee、vPublic 金额）为 **16 位**；
- P3 的两个 vPublic 符号位（`redeem as u32`）为 **1 位**；
- P3 的 vPublic 和 R 暴露的资产 id（`as u32`）为 **32 位**。这一项做原生检查没有意义：
  KoalaBear 的 p < 2^31，而每个 PV 都是规范形式。在 AIR 内，这些槽位都与一个资产累加器
  单元相等。

`audit_pv_bits()`（lab issue #758）还没有进 main。它合入后，应钉住与本表相等。

## F2b-4：wrapper 运行（`f2wrap`）

`f2wrap` 读取一个 `f2fixture` 封装，按 `f2census` 的同一套标准接收它（元数据、几何、
在用的 L2 verifier），然后为这一个叶子构建**全尺寸**的 C1 和 C2，其中 C2 覆盖全部 43 个
query 槽位：

- `--check` 用 p3-air 的约束求值器逐行扫描两条 trace 的每一行。这就是
  `p3_air::check_constraints` 的行循环；`qlab_air::l2test` 包的也是这个循环，但按其 Cargo
  约定只能在测试里用。随后运行 `check_seams`、`check_coverage` 和 `check_leaf_pvs`，并检查
  两个 AIR 的 degree ≤ 3、实际构建的尺寸等于 `price::composed_*` 的规划值。不做 proving。
- `--prove --outer b2|b4` 在 **non-hiding** 外层配置下证明 C1 和 C2（stage-0 裁定 1：
  `qlab_consensus::legacy`）。车道沿用 M4 interior 自己的两条，现已提为具名常量
  `m4interior::INTERIOR_B2_CFG`（b2/q86/g22/fp16/a16）和 `INTERIOR_B4_CFG`
  （b4/q43/g22/fp16/a16）。两个 proof 都做原生验证，报告宽度、高度、约束数、degree、
  proof 字节数，以及证明和验证的墙钟时间。`--component c1|c2` 只证明其中一个（默认两个都证）。
  C1 总要构建，因为 C2 要用它的 seam。
- **预算：** `--max-cells`（默认 1,500,000,000）**在读取 fixture 之前、在任何 trace 或 ROM
  存在之前**就按规划值检查。C1/C2 的构造函数在分配前还会再查一次。两个组件依次构建，
  构建下一个之前先释放上一个的 trace，所以一个进程的峰值取两者中较大的那个。
- **输出：** JSON 写到 stdout，封装格式与 `f2census` 相同，带 `--revision`。该模式不写任何文件。
  检查未通过时仍会打印报告，然后以 2 退出。

**S3 的 [P] 规划**（`price::composed_*`，以及 #750 stage-0 的 k 模型
`peak_GiB ≈ k × width × 2^(h−18)`，k_b2 = 0.00265645，k_b4 = 0.00427969）。报告里
`plan.expected_peak_gib` 给出同样的数：

| 组件 | 列数 × 行数 [P] | k 模型 b2 [P] | k 模型 b4 [P] |
|---|---|---:|---:|
| C1 | 11,746（另有 2,227 列周期 ROM）× 2^15 | 3.900 GiB（含 ROM 4.640） | 6.284 GiB（含 ROM 7.475） |
| C2 | 5,058 × 2^17 | 6.718 GiB | 10.823 GiB |

k 模型是在旧 M4 interior 上拟合的，只是规划模型，不是上界，也从未在这两个 AIR 上校准过。

### 测量机器上的命令（协调会话，内存合格的机器）

串行运行，且单独占用机器：不跑 CI，不跑其他 benchmark。按前文记录 commit、`Cargo.lock`、
`rustc -Vv`、硬件、`MemTotal` 和电源状态。命令块见英文版“Box commands”一节，原样照抄：
`set -o noclobber` 后编译 release，然后循环两遍（pass 1、2）。每一遍依次运行以下四个命令，
每个都套在 `/usr/bin/time -v` 下，stdout 写 `.json`，stderr 写 `.time`：

1. `f2fixture --shape s3`；
2. `f2wrap --check`，非零退出就 `break`；
3. `f2wrap --prove --outer b2`；
4. `f2wrap --prove --outer b4`。

`--check` 非零退出时**停下**。`report.result.checks` 会写明哪项没过，
`sat_scan.first_violations` 会给出行号和约束组名。先把这些贴出来，再考虑证明。要把峰值
归到具体组件，就在不同进程里分别加 `--component c1` 或 `--component c2`。

**怎么判读内存门槛。** 峰值 RSS 取每个 `.time` 文件里的 `Maximum resident set size (kbytes)`，
GiB = kbytes / 1024²。JSON 里不会有实测峰值。

- **内存门槛通过**的意思是：两条外层车道、两遍运行中，每个 `f2wrap --prove` 进程的峰值都
  **≤ 60 GiB** [M]（stage-0 裁定 2：测量机为 r7g.2xlarge，可用 61 GiB），并且报告中每个
  被证明的组件都是 `native_verified: true`。
- **另外单独**报告每个峰值是否 **≤ 32 GiB**，即具名的 32 GiB 档。这是第二个结论，不是门槛本身。
- `f2fixture` 生成器（hiding **交易** prover，F2b-0 测得 S3 为 13.727 GiB）和 `--check`
  进程**不算**聚合内存。要记录，但不以它们判门槛。串行流水线的峰值取各进程的最大值，不是求和。
- 按 F2b-4 验收标准一并记录：`c1.built.max_degree` 和 `c2.built.max_degree` ≤ 3，
  以及每个组件的 `proof_bytes`、`prove_seconds` 和 `verify_seconds`。两遍结果一致后才能发布任何数字。

**这次改动没有确认的事：** 还没有构建、扫描或证明过任何全尺寸 trace。本地禁止运行，
CI 只跑 toy 和 2-query 实例。“规划值等于实际构建值”这一检查、43 个 query 下的约束扫描，
以及所有证明数据，都要等测量机实跑。
