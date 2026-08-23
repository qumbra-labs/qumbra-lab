# 手机自证明,重新打开 —— 交接

**状态:未决。动任何参数之前,欠两个测量。**
配对文档:[`phone-self-proving-reopened.md`](phone-self-proving-reopened.md)

写于 2026-08-23,作为会话交接。本文所述**一件都没有动工**;产生它的那次会话
里每个 PR 都已合并,每棵工作树都干净。

**2026-08-23 后续:**Qumbra 运营的共享 prover 在算力上可行,能服务所有手机;但协议
不变的 trusted 形态能盗取 selected inputs,不是 real-value 产品路线。Larry 已裁决,
要求用户自己运营常驻 self-hosted prover 太麻烦,**不在考虑范围内**。可上线的
authorization/attestation 候选与公网安全边界记录在
[`backend-assisted-proving-security-zh.md`](backend-assisted-proving-security-zh.md)。

---

## 1. 这件事怎么起来的

Larry,2026-08-23:**"ios app 上 send 太麻烦了,还要跟 mac prover pair"**

摩擦是真的,而且比"配一次"更糟。按脚本现状实测:

| 步骤 | 在哪 |
|---|---|
| 跑 `scripts/run-paired-prover.sh <LAN-name>` | Mac 上,**每笔一次** |
| ……而它会先跑 `cargo build --release` | `qumbra-wallet-macos/scripts/run-paired-prover.sh:17` |
| 进程**服务完一次认证请求就退出** | `rust/src/bin/qumbra-paired-prover.rs:6,82` |
| 扫二维码 | 手机上,**每笔一次** |

所以这不是配一次就完事。是**每一笔支出**都要跑一次命令、扫一次码。

## 2. 配对为什么存在 —— 查证过,不是凭记忆

手机跑不动共识配置。`qumbra_ffi` 自己的头文件就这么写
(`crates/qumbra-ffi/include/qumbra_ffi.h:426`),出处是
[`self-proving-vs-proof-size.md`](https://github.com/qumbra-labs/qumbra-design/blob/main/self-proving-vs-proof-size.md)
的 branch (b),**Larry 于 2026-07-17 决定**。

那份文档同时把 **(a) 记作常备书面回退**,原文:

> flipping to (a) b4/241 KB remains a parameter change, not a redesign, **if
> phone-at-launch is ever re-judged critical** before WHIR matures.

Larry 这次抱怨就是那个"重新判定"。被问到时,他选了 **branch (a):翻到 b4,
手机本地证明**。

🔴 **但他是对着我写错的选项标签做的选择。** 我写的是"彻底不要 Mac"。这是假的,
见 §4。动手之前应当拿更正后的取舍**重新确认一次**。

## 3. 设计文档里的数字已经过时

那张阶梯表是 T2 mint 之前量的:

| 配置 | 工作集 | tx | 出处 |
|---|---|---|---|
| b16(现行共识) | 15.1 GB | 136.9 KB | 设计文档 §1 |
| b8 | 5.2 GB | 171.6 KB | 设计文档 M3 后续 |
| b4 | 2.6 GB | 236.4 KB | 设计文档 M3 后续 |

那之后 mint 改了电路:**width 617 → 643**,`CONSENSUS_WIRE_BYTES`
**145,609 → 148,625**(`crates/qumbra-node/src/genesis.rs:107`)。所以 b4 在
今天这棵树上的真实代价**没人量过**。文档自己也标了这个缺口:b4 的内存数字写着
*"to be confirmed on hardware in M2 step 2"*,而那个确认从未做过。

**测量一(欠着):当前电路上的 b4 与 b8 —— 工作集、wire 字节、证明耗时。**
agent 会话不得在 Larry 本机跑 `cargo test`(CLAUDE.md);这要走 `scripts/rig`
或 `verify-graviton` lane。

## 4. 🔴 b4 不会去掉 Mac,只是把线往下挪

Larry 的追问 —— **"配置低的手机上没法 send?"** —— 才是改变这笔账的那一问,
答案是:**对,低配机确实不行。**

iOS 把 app 封在约设备内存一半;
[increased-memory-limit entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit)
能抬高,幅度苹果不公开。对着文档的 2.6 GB:

| 机型内存 | 默认上限约 | b4 能否自证明 |
|---|---|---|
| 4 GB(iPhone 11、SE3) | ~2 GB | **不能** |
| 6 GB(13、14) | ~3 GB | 勉强,要 entitlement |
| 8 GB(15 Pro、16) | ~4 GB | 可以 |
| 12 GB(17 Pro) | ~6 GB+ | 可以,连 b8 都行 |

三条后果,合起来才是真实的取舍:

1. **配对那条路删不掉。** 它要留作低内存机型的回退。b4 买到的是"新手机不需要
   Mac",不是"没人需要"。
2. **代码变多不变少** —— 通道、二维码、Mac 那个 binary 全留着,**再加**本地证明
   路径,**再加**"这台机器走哪条"的判定。
3. **账还是照付**:永久 236 KB 的交易(超 ≤150 KB 目标 58%),外加一次 T2
   重新 mint 或一个永久双验证器(§5)。

## 5. T2 一定要重新 mint 吗?严格讲不必 —— 是我说绝对了

我跟 Larry 说翻配置就意味着 T2 重新 mint。**太绝对。** 查证结果:

**genesis 哈希确实会变,但这条绑定不咬人。**
`FrozenParams.consensus_fri` 就是字符串 `"b16/q21/g22/fp16/a16"`
(`crates/qumbra-node/src/genesis.rs:236`),而 `GenesisFile::hash()` 是对整个
结构体 bincode 后做 keccak256(`genesis.rs:706`)。所以**新生成的** genesis 会
不同 —— 但 T2 磁盘上那份不会变,节点照样匹配自己的 pin。

**验证器才是硬绑定。**

```rust
// crates/qlab-consensus/src/lib.rs:214
pub fn verify_proof(inst: &BucketInstance, pvs: &[Val], proof: &Proof<Config>) -> bool {
    let config = make_config();   // 读那个唯一的 `pub const CONSENSUS_CFG`
    verify(&config, &inst.air, proof, pvs).is_ok()
}
```

它**不接收高度**。按 b4 编出来的节点会用 b4 验**一切** —— 包括 T2 里用 b16
证出来的既有历史 —— 于是从 genesis 重放时整条拒掉。

所以有两条路,不是一条:

**A —— 重新 mint。** 一个配置,干净。T2 从新 genesis 起步。T2 本来就重启过一次
(tip 从 14.6k 回到 1.2k),而且它是测试网。

**B —— 按高度分档验证器。** 本仓库有两次先例:
`RULE_BOUNDARY_HEIGHT = 8_640`(`crates/qlab-devnet/src/emission_exact.rs:104`)
与 `NAME_RULE_BOUNDARY_HEIGHT = Some(19_008)`(`crates/qlab-devnet/src/names.rs:59`)。
但那两次分档的是**算术**;这次要分档的是**证明系统的构造**。`verify_proof` 必须
认高度,而两套配置要**永久**编在节点里 —— 任何从 genesis 同步的节点,永远要重放
一遍 b16 时代。这只是节点侧的负担;钱包是轻客户端,不验 STARK。

我的判断:对一条以"排练发布配置"为目的的测试网来说,重新 mint 比把双验证器
一路背进主网便宜。**但这是 Larry 的决定。**

## 6. app 现在没能力判断自己该走哪条路

在 `qumbra-wallet-ios` `8fa64d6` 上查证:

- **没有声明 `increased-memory-limit` entitlement**(`project.yml` 没有
  entitlements 段,也不存在 `.entitlements` 文件)
- **没有任何地方调用 `os_proc_available_memory()`** 或读 `physicalMemory`

所以在一台跑不动的机器上,app 不会拒绝 —— 它会开始跑,然后
**被 iOS jetsam 在证明中途杀掉**。钱没花掉(交易根本没提交),但工作白做,
而且在用户看来就是崩溃。

**测量二(欠着):Larry 那台真机上的 jetsam 余量。**
`os_proc_available_memory()` 返回的就是"离被杀还剩多少字节"。十几行探针加在他
手机上跑一次,就能把"大约一半,entitlement 抬高一个未公开的量"变成一个数字。

🔴 **这一个不管 b4 怎么定都值得做。** 即便留在 branch (b),app 也该自己知道并
说出来能走哪条路,而不是靠被杀掉才发现。

## 7. 新会话该按什么顺序做

1. **要对着诚实产品路线做选择,不能再用原来的二选一标签。**
   - b4:旧 mint 前数据约 236 KB + 重新 mint/双验证器 + 低内存设备仍要 fallback,
     换来新手机本地独立证明。
   - 共享 b16 backend + 手机持有 authorization:每台手机都能 send,prover 不能把
     selected inputs 改付给自己;但 note/public/wire/verifier 改动同样属于 re-mint 级,
     byte 与 prover 成本欠测。
   - attested confidential b16 backend:原则上不需 protocol re-mint,但 confidential-VM
     memory fit、performance、attestation、operator isolation 与 ingress linkability
     都未测。
   - 协议不变的 trusted b16 backend:今天 148,625 字节且不需 re-mint,但服务能盗取
     selected inputs。这只是可行性基线,不是 real-value 产品路线。
   - 用户每笔操作 Mac:当前行为,产品 UX 已拒绝。
2. **给两条可上线 backend 候选计价:**展开手机持有 authorization 设计,把它的
   re-mint/wire/prover 成本直接与 b4 比;另跑当前 b16 proof 的 attested
   confidential-VM lane。
3. **只有 b4 仍是候选时:**才做测量二(设备余量)与测量一(当前电路 b4/b8),并在
   各自规定的硬件上跑。Confidential backend 不依赖这两个测量;authorization 比较
   需要当前 b4 数字。
4. 完成选择与任何仍需测量后,才碰 `CONSENSUS_CFG`。

**已被取代的路线:**把用户 Mac prover 做成长驻在技术上仍可行,但 Larry 已裁决
用户运营常驻证明太麻烦。现有 one-shot 路径可留作开发工具;除非明确重开这条裁决,
不得围绕 self-hosting 构建产品。

## 8. 交接时的状态

- 原始交接:`qumbra-lab` `4f54b42`、`qumbra-wallet-ios` `8fa64d6`、
  `qumbra-design` `5983048`
- 共享 backend 后续查阅:`qumbra-lab` `1c5a27b`、`qumbra-wallet-macos`
  `4bdde1d`、`qumbra-wallet-ios` `e3a9e2d`
- Backend 架构/安全交接:`backend-assisted-proving-security.md` 与 `-zh`
- iOS `ROADMAP.md` / `-zh`:**24 ✅ / 11 ⬜**
- 本文所述一件都没动工。`CONSENSUS_CFG` 未被触碰。
