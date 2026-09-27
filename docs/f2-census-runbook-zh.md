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

下一检查点须补齐 periodic 求值、quotient 重组与恒等式、randomizer/salt 绑定、
寄存器生命周期、shape/config 身份、各 shape 的费用和状态转换，以及 issue #78
剩余工作。由实现重新计算宽度和 padded height，不能把 stage-zero 宽度预算直接
当作已验证的分配尺寸。

## 验证与限制

CI 回归测试会串行生成真实 S3/P3/R proof，检查两个原生 verifier、几何与计数一致性，
并修改 randomizer、salt、rc0 嵌套、P3 额外 fold 和公共值验证拒绝行为。
轻量测试固定纸面几何、当前 AIR 元数据，拒绝不兼容参数及 fixture 元数据。
测试代码存在不表示 CI 已通过，应以 PR 对应提交的 CI 结果为证据。
完整递归 soundness、最终宽高、混合 shape 聚合和内存门槛仍未由这些工具验证。
