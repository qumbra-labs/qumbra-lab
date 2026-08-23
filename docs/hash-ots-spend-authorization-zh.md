# 基于哈希的一次性花费授权 —— 研究候选

**状态:研究候选,未接受、未构建。后续复查发现尚未解决的 P0 state rollback/key reuse、
不完整的 WOTS+ 实例化与 dummy-slot 规则。见
[`remote-proving-decision-zh.md`](remote-proving-decision-zh.md) §6。任何获接受的版本都会
改共识并需要 T2 re-mint;所有标"估"的数字仍未测量。**
英文权威版:[`hash-ots-spend-authorization.md`](hash-ots-spend-authorization.md)。

写于 2026-08-23,是 [`backend-assisted-proving-security.md`](backend-assisted-proving-security.md)
(PR #618)§8 第三行"手机持有交易意图授权"欠下的后续。那份文档证明了:共享 Qumbra prover
只能作为**受信任**服务存在,因为 `WitnessBundle` 把 input 的 `sk` 交给了 worker,而协议里
没有任何东西阻止 worker 用同一批 note 证明并提交另一笔花费。本文探索的是一条意图拆掉
这份信任的协议形状。在当前决策记录里的 P0 blockers 关闭前,这个属性**尚未成立**。

---

## 1. 一句话答案

候选方案:把每个地址的一棵 WOTS+ 一次性公钥 Merkle 树的树根写进 note 的 recipient key material;
花费时在手机上用其中一把一次性私钥对规范化的**意图摘要**签名;电路只证明"亮出来的一次性
公钥属于被花 note 的地址";节点在 STARK 之外验签。于是 prover 只需要**证明材料**(`nk`、
note 开口、Merkle 路径),永远拿不到**授权材料**(`sk_auth`、一次性私钥)。

## 2. 为什么是这个形状

两条来自现有代码的承重事实决定了整个设计:

1. **电路里 `sk` 只用在一个 permutation。** `ROLE_ANK` 算 `nk = H(sk ‖ D_N)`
   (`crates/qlab-air/src/narrow.rs:1292,1430`)。其余所有 role —— `ROLE_NF`、`ROLE_ARKM`、
   `ROLE_ACM`、`ROLE_MERKLE` —— 消费的是 `nk`,不是 `sk`。密钥层头注释
   (`crates/qlab-wallet/src/keys.rs:1-29`)印证:`sk → nk → rkm`,`nf = H(nk ‖ ρ)`。
2. **`rkm` 是单块 Keccak,rate 有富余。** `rkm = H(nk ‖ D_R ‖ d)` 只占 17 个 rate lane 中
   的 0..7(`keys.rs:57-66`),空着 9 个。256 位的 `ak_root` 放在同一块的 lanes 7..10,
   电路里绑定它**不多花一个 permutation**,只是重排 `ROLE_ARKM` 的吸收布局。

所有替代方案都走到同一个死胡同:要把花费授权密钥和一个隐藏的 note 连起来,必须*证明*,
而证明需要那个连接秘密作 witness。具体:

| 替代方案 | 败在哪 |
|---|---|
| 按 note 派生一次性密钥 `sk_ots = H(sk_auth ‖ ρ)`,电路内推公钥 | 电路要 `sk_auth` 才能推公钥 → worker 拿到 `sk_auth` |
| 按地址一把授权密钥,花费时亮出 | 同一地址每次花费亮同一把钥匙 → 完全可链接 |
| Sapling 式 EC 再随机化(`rk = ak + αG`) | 纯 Keccak AIR 里做点加贵得离谱;而且不抗量子 |
| 拆分 STARK:手机证钥匙链,worker 证成员关系,用隐藏承诺连接 | 能做,但第二个 FRI 证明有 ~100 KB 地板 → 交易 ~230 KB,和 b4 同级(b4 根本不需要服务) |
| MPC / 加密外包证明 | 研究课题;PR #618 基于同样证据已排除 |
| 维持单体 STARK 规则,选一个受信任运营方 | 即 PR #618 的现状;盗窃由政策约束,不由协议约束 |

唯一一种让电路能**在不持有授权秘密的情况下**把一把*新鲜、不可链接*的公钥绑到隐藏 note 上
的构造,就是 XMSS/SPHINCS 的模式:一棵一次性公钥树,树根写进 note,成员关系用普通哈希路径
证明。本文规定的就是它。

## 2a. 这偏离了一条绑定性设计决策 —— 要明说

`CLAUDE.md` 对 Qumbra 的一段话定义,以及背后的
`qumbra-design/transaction-model-and-anonymity-set.md`,写的是**"每笔交易一个单体 STARK
(花费授权在证明内 —— 没有按笔签名)"**。本设计加了两个按笔签名。这不是疏忽,是买这个
性质的代价。原决策面向的是自己证明自己交易的钱包,签名与证明重复。手机自证明的重开已确立
大多数手机不会自己证明;PR #618 已确立持有证明 witness 的委托 prover 就持有花费权。
证明*之外*的花费授权,正是让证明可委托的那个东西。

如果 §11.1 被接受,设计仓库欠交易模型文档和那段一句话定义一个带日期的更正,方式同
`performance-budget` §2 撤回"layered hedge"。更正落地之前,本文是对绑定规范的一份提案,
不是规范的一部分。

## 3. 密钥层

```
sk_root                                   256 位,只在手机
├── sk_spend = H(sk_root ‖ D_SPEND)       256 位,即今天的 `sk`
│   └── nk   = H(sk_spend ‖ D_N)          证明密钥;可以交给 prover
└── sk_auth  = H(sk_root ‖ D_AUTH)        256 位,永不离开手机

每个地址 d(128 位 diversifier,不变):
    for i in 0 .. 2^DEPTH:
        seed_i   = H(sk_auth ‖ D_OTS ‖ d ‖ i)
        sk_ots_i = WOTS+.keygen(seed_i)
        leaf_i   = H(WOTS+.pk(sk_ots_i))                256 位
    ak_root(d) = MerkleRoot_DEPTH(leaf_0 .. leaf_{2^DEPTH - 1})

    rkm(d) = H(nk ‖ D_R ‖ d ‖ ak_root(d))               单块 Keccak
```

`D_SPEND`、`D_AUTH`、`D_OTS` 是钱包侧 ASCII 域分隔串,风格同 `address`/`viewing`
(`keys.rs:15-17`)。`D_N`、`D_R` 保持电路内的 marker-bit 形式。

**prover 收到什么**(新的 `WitnessBundle v2`):每个 input 的 `nk`、`value`、`ρ`、`rseed`、
`d`、`ak_root`、Merkle witness,加上 `pk_ots_i` 及其到 `ak_root` 的 `DEPTH` 层路径;两个
output 同今天;已批准的 `intent` 和两个 WOTS+ 签名。**没有** `sk_root`、`sk_spend`、
`sk_auth`、任何 `sk_ots`。

**`nk` 给了 prover 什么。** `nk` 是 full-viewing 级别的材料(`keys.rs:25-28`):能推出所有
`rkm(d)`,以及任何已知 `ρ` 的 `nf`。它*不能*解密收到的 note(那是 `address`/`viewing` 里的
ML-KEM incoming viewing key),所以只持有 `nk` 的 prover 无法从公开链数据里找出该钱包的其他
note。这和 Zcash Sapling 交给委托 prover 的 *proof authorizing key* `(ak, nsk)` 与留在手上的
*spend authorizing key* `ask` 之间的界线一致。要披露它,别假装没有。

## 4. 意图摘要

```
intent = SHA3-256(
    "qumbra-intent-v1"      ‖
    network_id              ‖ genesis_hash           ‖
    anchor                  ‖
    nf_1 ‖ nf_2             ‖
    cm_1 ‖ cm_2             ‖
    bucket ‖ fee            ‖
    SHA3-256(discovery)     ‖ SHA3-256(rider)        ‖
    pk_ots_1 ‖ pk_ots_2
)
```

每个字段都已经在交易的公共面里,或可由其推出(`TxPublic`、`TxEntry.discovery`、
`TxEntry.rider` —— `crates/qlab-devnet/src/body.rs:166-230`),外加两个新公共值。节点从收到
的交易重算 `intent`,用它验两个签名。prover 改动 anchor、nullifier、output commitment、fee、
discovery 字节、rider 或亮出的一次性公钥中的**任何一个**,两个签名都作废。把 `pk_ots_{1,2}`
放进摘要堵住了"从同一棵树换一片叶子"的替换。

重放在构造上就排除了:`nf_1`、`nf_2` 在摘要里,而 nullifier 最多落地一次。

## 5. 签名方案

WOTS+,`n = 32` 字节,`w = 16`,Keccak 链(电路已经在用的同一个 permutation;节点用软件
原生验):

- `len_1 = 64`,`len_2 = 3`,`len = 67` 条链,每条至多 15 步;
- 签名:67 × 32 = **2,144 字节**;压缩后公钥 32 字节;
- 每个 input 一个签名 → 每笔 4,288 字节;
- 验证:每个签名 ≤ 67 × 15 ≈ 1,005 次 Keccak-f,每笔约 2k 次 —— 节点上微秒级,在 STARK
  验证旁边可忽略。

为什么是 WOTS+ 而不是整套 XMSS/SPHINCS+:XMSS 的树那一半正是*电路*证明的东西(§6),节点
永远只看到叶子方案。为什么叶子不用 ML-DSA/Falcon:格公钥同样可以放进树,但一个 note 恰好
花一次,一次性方案没有损失;WOTS+ 把叶子压在 32 字节、签名约 2 KB,对比 ML-DSA-44 的
1.3 KB 公钥 + 2.4 KB 签名,而且复用节点和电路已经信任的 Keccak。

**一次性纪律。** 每片 `leaf_i` 最多用一次。钱包持久化每地址的"下一个未用索引",拒绝用已
消耗的索引签名;索引在签名产生那一刻算消耗,不是交易落地时。丢了计数器(从旧备份恢复
设备)可以通过扫描链上该地址亮出过的 `pk_ots` 恢复 —— 它们是 `TxPublic` 里的公共值。

## 6. 电路改动

当前程序:2^18 行里 84 个 permutation slot(`narrow.rs:1220-1224`,`BUCKET_PERMS`),
剩 1.33 个。

| 改动 | slot | 说明 |
|---|---:|---|
| 删 `ROLE_ANK`(`nk` 直接作 witness) | −2 | `sk` 完全不再进电路 |
| `ROLE_ARKM` 在 lanes 7..10 吸收 `ak_root` | 0 | 同一块;pad 从 lane 7 挪到 lane 11 |
| 新 `ROLE_OTS_LEAF`:每个 input 算 `leaf = H(pk_ots)`,`pk_ots` 由边界 bank 绑到 `PV_PK1/PV_PK2` | +2 | 绑定形状同 `ROLE_ACM` |
| 新 `ROLE_OTS_MERKLE` × `DEPTH`,每个 input 一组,末端对前一个 `ROLE_ARKM` witness 的 `ak_root` lane 做边界检查 | +2·DEPTH | 算术与 `ROLE_MERKLE` 相同;单独 role 码,理由同 `ROLE_ARHO`(`narrow.rs:228-236`) |

取 `DEPTH = 16`:84 − 2 + 2 + 32 = **116 slot → 2^19 行**(116 × 3072 = 356,352 ≤ 524,288;
剩 54 slot)。取 `DEPTH = 12`:108 slot,同样 2^19。没有任何 `DEPTH` 能留在 2^18 里,所以
行数翻倍是真实代价;既然 2^19 已经付了,边际 slot 是免费的,因此选 `DEPTH = 16`
(每地址 65,536 次花费)。

**这正是 PR #618 没走到的那一步:**证明一旦离开手机,电路的内存预算就是服务器的,不是
手机的。trace 翻倍在 worker 主机上可以接受;在 iPhone 上从来不行。

**必须做域分隔复查。** `ROLE_ARHO` 的注释(`narrow.rs:228-236`)记录了一次真实的碰撞,缺一个
marker 就会被打开。挪 `ROLE_ARKM` 的 pad 和新增两个 role,必须以同样纪律对照其他所有吸收
形状复查;`qlab-note` 和 `qlab-wallet` 里把主机侧派生锁到 `build_bucket` 输出的回归锁要
重新推导,不是改到能过。

公共值:`PV_LEN` 84 → 116(两个 32 字节 `pk_ots`,各 16 chunk),布局接在 `PV_FEE` 之后。

## 7. 交易 wire 与节点规则

`TxEntry` 新增 `auth: [WotsSignature; 2]`(2 × 2,144 字节),`TxPublic` 新增
`pk_ots: [Hash32; 2]`。编码遵循 `encode_tx` 的现有纪律
(`crates/qlab-p2p/src/codec.rs:398`):定宽、规范、拒绝未知。

节点接受顺序,在 STARK 验证之前:

1. 规范解码;非规范字节照旧拒绝;
2. 从解码后的公共面重算 `intent`(§4);
3. 用 `pk_ots[0]` 验 `auth[0]`,用 `pk_ots[1]` 验 `auth[1]`;
4. 任一失败即拒 —— **在**给证明花验证器时间**之前**;
5. 对扩展后的公共值验 STARK。

估算 wire(估):2^19 行的证明每条 query 路径多一层 FRI,约 +6–8 % → ~158 KB;加 4,288
字节签名和 64 字节公钥 → **每笔 ≈ 163 KB**,对比今天 148,625 字节、b4 下约 236 KB。
在重复任何尺寸说法之前必须用测量替换。

## 8. 钱包改动

- 建地址时生成 `ak_root(d)` 树:65,536 次 WOTS+ keygen ≈ 65,536 × 67 × 15 ≈ 6,600 万次
  Keccak-f(估:现代手机 2–6 秒,每地址一次;如果 UX 在意,`DEPTH = 12` 约 0.3 秒)。缓存
  树;恢复时从 `sk_auth` 确定性重生成。
- `Address` 布局不变:`rkm` 本来就是 32 字节哈希
  (`crates/qlab-wallet/src/address.rs:82-93`,原始 1,233 字节)。
- 手机上的花费流程:选币 → 构造 → 算 `intent` → 签两次 → 产出 `WitnessBundle v2`。签名是
  唯一新增的用户可见延迟,亚毫秒。
- 每地址索引计数器,按 §5 的一次性纪律;UI 必须在远未到 `2^DEPTH` 时就提示"地址用尽,
  请轮换"。
- `SpendingKey::spend_input`(`keys.rs:128`)拆成 `ProvingKey::prove_input`(产出基于
  `nk` 的 `TxInput`)和 `AuthKey::sign_intent`。

## 9. 恶意 prover 能做什么、不能做什么

| 动作 | 改前(PR #618 受信任模型) | 改后 |
|---|---|---|
| 证明已批准的交易 | 能 | 能 |
| 改 outputs / fee / discovery / rider | 能,且能提交 | 签名失效;节点拒绝 |
| 用同一批 note 提交冲突花费 | 能(nullifier 赛跑) | 造不出合法的 |
| 得知花了哪些 note、金额、收款方 | 能 | 能 —— **不变** |
| 推导钱包的其他地址 | 能(`sk`) | 能(`nk`)—— **效果不变**,材料更窄 |
| 解密钱包收到的 note | 不能 | 不能 |
| 拒绝、拖延、选择性审查 | 能 | 能 |

盗窃那一行就是本设计存在的理由。隐私那几行是 PR #618 §3/§6 混进盗窃里的那道独立的
"看不见"门槛;它们仍然开着,要靠 confidential worker、多运营方证明或两者兼用 —— 本文
都不裁决。

## 10. 对悬而未决那个决定的影响

| 选择 | 每台手机能发 | prover 不能改道 | 交易大小 | T2 | 长期依赖 |
|---|---|---|---:|---|---|
| b4 本地证明 + fallback | 低内存设备靠 fallback | 不适用(没有 prover) | ~236 KB | re-mint | fallback prover |
| 受信任 Qumbra 后端(PR #618) | 能 | **否** | 148 KB | 无 | 受信任、单一运营方 |
| 拆分 STARK | 能 | 是 | ~230 KB(估) | re-mint | 一个服务 |
| **hash-OTS 授权(本文)** | 能 | **目标是;尚未成立** | ~163 KB(估) | re-mint | *任何* prover,可去中心化 |

b4 与获接受的这个方案都会付一次 T2 re-mint。b4 买到手机自立,代价是最大的交易和一个
仍然受信任的 fallback prover。如果 P0 blockers 被解决,这个方案的目标是买到防止 prover
改道、比 b4 小的交易、手机零内存压力,以及让社区节点、矿池或市场替手机证明的选项。
当前构造还没有证明这些属性成立。

## 11. 欠的决定

1. 在 [`remote-proving-decision-zh.md`](remote-proving-decision-zh.md) §6 的 P0
   blockers 关闭前,不要接受这份构造;选择 primitive 前必须与 stateless ML-DSA-leaf
   构造对比。
2. `DEPTH`(12 还是 16)与 WOTS+ `w`(16 还是 256:256 把签名砍到约 1.1 KB,验证哈希数
   约 17 倍)。
3. `pk_ots` 是按本文规定进入 `intent`,还是只靠电路绑定(本文写的是两者都要;对叶子替换
   双保险)。
4. `nk` 能否交给非 Qumbra 的 prover,还是值得再加一层更窄的按笔证明材料。
5. re-mint 与其他待定 T2 电路改动的排序。

## 12. 实现前欠的证据

1. 在目标 worker 机型上以 2^19 行证明一次改后电路:峰值 RSS、耗时、证明字节。替换上文
   所有"估"。
2. `ROLE_ARKM` 重排和两个新 role 之后,对所有吸收形状做碰撞/域复查,按 `ROLE_ARHO`
   那样记录。
3. WOTS+ 参考向量和节点验证器基准。
4. 端到端对抗测试:一个依次篡改 §4 每个字段的 prover,产出的交易必须在第 3 步或第 5 步
   被节点拒绝。
5. `DEPTH = 16` 下最慢支持机型的建地址时间。

## 13. 交接时的范围

- 当前裁决:不接受这份构造;配对的当前决策记录具有权威性。
- 什么都没实现。`CONSENSUS_CFG`、电路、wire、钱包均未触碰。
- 本文不取代 phone handoff,也不批准协议方向。它的 findings 汇入
  [`remote-proving-decision-zh.md`](remote-proving-decision-zh.md) §6。
