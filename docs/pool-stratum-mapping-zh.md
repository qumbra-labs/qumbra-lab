# 矿池 stratum 映射 — §4 阅读落地（lab #482 stage 0）

> 完全不了解 stratum?两分钟入门:[stratum-primer-zh.md](stratum-primer-zh.md)。
> [English](pool-stratum-mapping.md)

**状态：STAGE-0 交付物。** 落地
[pool-payout-axis-brief](https://github.com/qumbra-labs/qumbra-design/blob/main/pool-payout-axis-brief.md)
§4 所要求、并由
[pool-t1-brief](https://github.com/qumbra-labs/qumbra-design/blob/main/pool-t1-brief.md)
§3 route-A 裁决解门的 stratum 阅读。跟踪：
[lab #482](https://github.com/qumbra-labs/qumbra-lab/issues/482)。Multica：QUM-136。

本文是映射表 + crate 形态决策 + v4 兼容说明。可实现性证明在 `qlab-stratum`
的 fixture 往返测试（`tests/fixture_roundtrip.rs`）。**无 endpoint、无记账、
无共识接触** — 那些是 stage 1–3。

技术细节以英文版为准；本译稿与之配对，不另立分叉。

## 0. 先核前提

| 前提 | 树 / brief 说什么 | 核对 |
|---|---|---|
| `main` 上无 stratum/pool/extranonce 代码 | lab #356：grep NOT FOUND；M9-N3「节点内、solo、无模板面」 | **成立** — 本 PR 之前仍为空 |
| v5 头偏移（nonce 39–46，version+u48 在 32–38） | pool-t1-brief §3 DECIDED；lab PR #472 `preimage_for(V5)` | **成立** — `qlab-stratum::blob` 常量对齐 PR #472；#472 合入后需 assert |
| rx/0 比特同一 | lab #356 CLOSED，IDENTICAL | **成立** — 与布局无关；此处不重测 |
| 目标模型 = 前 8 字节 BE ≤ `u64::MAX/d` | lab #356 CLEAN；`qlab_devnet::pow` | **标量形状成立；🔴 字节选择被更正** — 见发现 6 / [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490)：stock xmrig 比较 `hash[24..32]` 小端，我们的共识比较 `hash[0..8]` 大端。已裁定：v5 网改用后 8 字节小端。`qlab-stratum::target` 的阈值算术与字节选择无关，仍然成立 |
| key-block 节奏 = Monero 掩码（2048/64） | `qlab-pow::keyblock`，测试锁 | **成立** — 矿池复用该 schedule，不另起炉灶 |

无一行要求改头布局。无一行说惯例在结构上扛不住 v5 头。**不对 #482 做 STOP-and-report。**

## 1. 惯例来源

| 来源 | 授权什么 |
|---|---|
| [xmrig-proxy `STRATUM.md`](https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM.md) | `login` / `job` / `submit` / `keepalived` 形态 |
| [xmrig-proxy `STRATUM_EXT.md`](https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM_EXT.md) | `algo` 协商；扩展 job 字段 |
| xmrig `Job.h`（#356 引用） | RandomX 族：`nonceOffset=39`，`nonceSize=4`；blob 窗口 `[43, 408)`；4/8 字节 target 解析 |
| pool-t1-brief §3 | v5 preimage 偏移（已裁决的头） |
| lab PR #472 `header.rs` | 字节级精确的 v5 preimage（97 B） |
| `qlab-pow::keyblock` | seed-height 算术；`is_rotation_height` |

## 2. 映射表 — Monero stratum ↔ Qumbra v5

### 2.1 传输

| 惯例 | Qumbra 映射 | 契合 |
|---|---|---|
| 纯 TCP，每行一个 LF 结尾的 JSON-RPC 2.0 对象 | 相同。编解码在 `qlab-stratum::codec`；监听器是 stage 1（`qumbra-pool`） | CLEAN |
| 惯例不要求 TLS | stage 0 不管；运维裁决另议 | n/a |

### 2.2 `login`（矿工 → 矿池）

| 字段 | 惯例 | Qumbra 映射 | 契合 / 出处 |
|---|---|---|---|
| `login` | 收款地址 / worker id | 矿池账户 id（stage 2 记账）。登录时**不是**链上地址 — 在支付轴 (c) 下矿池经 coinbase payee-list 支付，login 身份是矿池分配/矿工自选的记账键 | stratum CLEAN；记账属 stage 2 |
| `pass` | 自由文本 | 忽略或作 worker 口令 — 矿池策略 | CLEAN |
| `agent` | 矿工 UA | 记日志；共识不用 | CLEAN |
| `algo` | 如 `["rx/0"]` | 要求 `rx/0`（#356 IDENTICAL）。其余点名拒绝 | CLEAN |
| `rigid` | 可选 rig id | 可选；仅记账 | CLEAN |

登录成功返回带首个 job 的 `{ id, job, status: "OK" }`（STRATUM.md）。会话 `id` 在每次 `submit` 上回显。

### 2.3 `job`（矿池 → 矿工）— 承重面

| 字段 | 惯例 | Qumbra v5 映射 | 契合 / 出处 |
|---|---|---|---|
| `blob` | hex 哈希 blob；矿工在偏移 39 写 nonce | **`BlockHeader::preimage_for(V5)` 的 97 字节 hex**，池侧 extra-nonce 已写入 43–46，矿工窗口 39–42 清零（或保留前值）。长度 97 ∈ xmrig `[43, 408)` | route A 下 CLEAN。**相对 Monero 的偏差：** blob 是我们的头 preimage，不是 CryptoNote 块哈希 blob — 同一 stratum 字段，不同字节（点名；必需） |
| `job_id` | 不透明字符串 | 矿池生成；把 submit 绑到模板 | CLEAN |
| `target` | hex；4 字节 compact *或* 8 字节 raw | **`u64::MAX / difficulty` 的 8 字节 LE hex**（矿池 share 难度）。xmrig 接受 8 字节 raw；阈值标量对齐 | 编码层面 CLEAN — **但见发现 6（#490）**：拿哪些哈希字节与该 target 比较，stock xmrig 与 #490 之前的共识并不一致。**FINDING：** Monero 常见的 4 字节 compact **不是**我们的原生编码 — 我们不发出它。解码器仅为 fixture 检视接受 4 字节零扩展（`target.rs`）；线上 Qumbra job 永不使用 |
| `algo` | `"rx/0"` | 恒为 `"rx/0"` | CLEAN（#356） |
| `height` | 块高 | `header.height`（blob 内 u48；JSON 字段 u64） | CLEAN |
| `seed_hash` | 32 字节 hex RandomX key | `pow_seed(...)` → `KeyBlockSchedule::seed_height(height)` 处的 32 字节 key-block 头哈希 | CLEAN（#356） |
| `next_seed_hash` | 32 字节 hex；可选；预热下一 dataset | 矿池纯算术：当 tip 接近轮换（`is_rotation_height` 落在预热窗口内）时，发送*下一* seed height 处块的哈希。**无共识字段** — 仅矿池侧 | CLEAN-WITH-CAVEAT（#356：MISSING 但便宜）。预热窗口宽度 = 矿池策略（stage 1） |
| 矿工 nonce 窗口 | blob\[39..43\] | v5 preimage 上同一偏移 | CLEAN（route A 的全部意义） |
| 池侧 extra-nonce | Monero：coinbase 保留字节 | **blob\[43..47\]** — u64 nonce 的高 4 字节。按连接在发 job 前写入；矿工不得改动 | route A 下 CLEAN。**相对 Monero 的偏差：** 分区落在头 nonce 高半，而非 coinbase tx — stratum 仍无独立 JSON 字段（extra-nonce 在 blob 内，Monero 矿池亦然） |

#### Blob 字节图（v5）

```text
 0–31   prev                         （来自 tip）
32      header format version = 0x05
33–38   height, u48 LE
39–42   矿工研磨窗口                  ← xmrig 把 submit.nonce 写这里
43–46   池侧 extra-nonce              ← 矿池按连接设置
47–54   timestamp, u64 LE
55–62   difficulty, u64 LE           （模板的共识难度）
63–94   tx_body_commitment
95      AggregateProofSlot 标签 0xA6
96      EpochSupplyAttestation 标签 0x59
```

共识 `header.nonce: u64` = `[39..43) ‖ [43..47)` 的小端拼接。
助手：`qlab_stratum::blob::assemble_nonce`。

### 2.4 `submit`（矿工 → 矿池）

| 字段 | 惯例 | Qumbra 映射 | 契合 |
|---|---|---|---|
| `id` | 登录得到的会话 id | 相同 | CLEAN |
| `job_id` | 来自 job | 相同；查模板 + extranonce | CLEAN |
| `nonce` | 4 字节 hex LE | 写入 blob\[39..43\]；与已存 extranonce 合成 `header.nonce` | CLEAN |
| `result` | 32 字节 hex PoW 哈希 | 与 job target（share）比；若达块级再与共识难度比 | CLEAN |
| `algo` | 可选回显 | 若有则必须是 `rx/0` | CLEAN |

Share 校验（stage 1）：用 submit nonce 重建 blob，在 `seed_hash` 下 RandomX，检查**后 8 字节 LE `< job target`** — [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490) 裁定的 v5 谓词，且用严格 `<` 镜像 xmrig 自身的过滤（`<=` 校验器会拒掉 xmrig 反正不会提交的边界 share，镜像则消除这一类差异）。块候选（stage 1/2）：同样在 v5 谓词下 ≤ 共识难度，再组装整块提交给节点。*（stage 0 原文写的是前 8 字节 BE；2026-08-18 依 #490 更正。）*

### 2.5 Job 重发与模板失效

| 事件 | 什么在转 | 矿池做什么 | 出处 |
|---|---|---|---|
| Tip 前进（新 parent / height） | `prev`、`height`、`timestamp`、`difficulty`、`tx_body_commitment`（及可能的 coinbase body） | 推送带新 `job_id` 与 blob 的 `job`。未完成 job 变 **stale** — 针对它们的 submit 点名失败 | pool-t1-brief §4 模板草图；M9-N3 tip 即模板源 |
| Key-block 轮换 | `seed_hash`（及 `next_seed_hash`） | 在 `KeyBlockSchedule::is_rotation_height(height)` 时，在线 job 必须带新 seed。在矿工仍用旧 key 哈希新高度之前推送新 job。Dataset 重载成本在矿工侧 | `qlab-pow::keyblock`；#356 CLEAN |
| 矿池 share 难度变更 | 仅 `target` | 重发 job（允许同 blob/extranonce；新 `job_id` + target） | 矿池策略 |
| Extra-nonce 重分配 | blob\[43..47\] | 少见；带新 extranonce 的新 job，以保持搜索空间不相交 | route A |
| 终局 / checkpoint 前进 | **不**改变 PoW preimage | 无 stratum 字段。矿池*可以*偏好父块已终局的模板（策略）；非惯例要求 | 委员会终局与 RandomX 正交 |

**§4 关切，作答：** key-block 轮换精确映射到 `seed_hash` / `next_seed_hash`，与 Monero 相同；模板失效 = tip 变更（stale job）+ 轮换（seed 变更）。Checkpoint 节奏不是 stratum 事件。

## 3. FINDINGS（惯例表达不了的 / 点名偏差）

1. **Blob 内容 ≠ Monero CryptoNote blob。** stratum `blob` 字段承载我们的 v5 头 preimage。Stock xmrig 在 RandomX `(seed, message)` 接口上哈希给定字节 — 这能工作*是因为* route A 把研磨窗口放在偏移 39，而不是因为 blob 布局与 Monero 一致。点名偏差；必需；不是绕路。
2. **Target 编码：8 字节 raw，非 4 字节 compact。** 我们的共识阈值是完整 `u64`。发 Monero compact 会损失精度 / 标度不同。xmrig 接受 8 字节 raw（`Job.cpp`，#356）。我们承诺 8 字节 LE hex。**FINDING：** 盲目照搬 Monero 4 字节 compact 发射器的矿池会设错 share 难度。
3. **Extra-nonce 不是 JSON 字段。** 与 Monero 矿池相同（活在 blob 内）。我们的落在 header nonce\[4..8)，而非 coinbase 保留字节 — stratum 看不见，共识看得见。无惯例缺口。
4. **`next_seed_hash` 由矿池计算。** 无 Qumbra 共识字段。不构成对惯例的 finding — 惯例本就视其为矿池供给。
5. **v4 网对 stock xmrig 仍为 UNCLEAN**（lab #356）。Stage 0 不另作宣称 — 见 §5。
6. **🔴 工作量字节选择（协调者 stage-0 评审发现，2026-08-18 更正 —
   [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490)）。**
   stock xmrig 的 share 谓词读 RandomX 哈希的**后 8 字节小端**
   （`CpuWorker.cpp`：`*reinterpret_cast<uint64_t*>(m_hash + 24)`，严格 `<`）；
   #490 之前的共识读**前 8 字节大端**（`pow.rs::hash_to_work_value`）。通过概率相同、
   命中的哈希不同 — 矿池会拒掉 ~100% 的诚实 share，真块解永远不会被提交。此行在本文与
   #356 中都曾标 CLEAN：两次分析追了标量形状和 target hex 解析，但都没追**矿机比较的是
   哪些哈希字节**。**裁决（#490）：`GenesisForm::V5` 网使用后 8 字节小端（与 Monero 同构）；
   v4/T1 保持前 8 字节大端不变。**共识侧 `satisfies_target` 的 form 键控是 #490 自己的
   PR，不属本棒；stage 1 的 share 校验器消费它。

无 finding 改变 §3 前提。无 finding 要求进一步改头布局。发现 6 改变一条**共识谓词**
（已裁定，#490），但不动任何头字节、创世字节或 target 编码。

## 4. 测量 — fixture 往返

**测试：** `qlab_stratum` → `fixture_roundtrip::fixture_transcript_round_trips_login_job_submit`。

**Fixture：** `crates/qlab-stratum/fixtures/xmrig_submit_transcript.jsonl` —
按 xmrig-proxy STRATUM.md 形态手建。**点名偏差**（亦写在 fixture 的 `_comment` 行）：v5 blob；8 字节 raw target。尚无公开的 Qumbra↔xmrig 实采（尚无矿池 endpoint）；stage 3 e2e 用实采替换。

**证明什么：** login / job / submit 行可解码；blob 为 97 B 且 version `0x05`；写入矿工 nonce 后 extranonce 完好；拼出的 `u64` nonce 对齐已裁决的 LE 布局；target hex ↔ 难度 1024 往返。

**不证明什么：** RandomX 哈希正确性（属 `qlab-pow`，每次 acceptance 重证）；实况 TCP；share 记账。点名，不藏。

## 5. v4 兼容 / 模板源抽象

Stage 2 必须能在今日的 v4 devnet 上测试（N=1 单收款方回退）。PR #472 的
`ChainRules { form, halt }` 是选择点 — 模板源键在 `form` 上，从不键在游离开关上。

```text
TemplateSource
  ├─ form: GenesisForm          ← 来自 ChainRules（创世身份）
  ├─ tip_template() -> Template
  │     V5 → preimage_for(V5) blob；payee-list coinbase（上限随规则）
  │     V4 → preimage_for(V4) blob；N=1 单收款方 coinbase（今日形态）
  └─ submit_block(block)        ← 节点 RPC；form 已烘焙进编解码
```

后果，直说：

- **对 stock xmrig 的 stratum 是仅 v5 的产品主张。** 在 v4 上 blob 的 nonce 仍在偏移 56 — #356 UNCLEAN 仍在。指向 v4 的矿池要么 (a) 不提供 stratum、用进程内/`qumbra-node mine` fixture 驱动 share，要么 (b) 向打过补丁的矿工提供 stratum（route B，已否决为终点）。Stage 2 的「可在 v4 上测」意指 **记账 + N=1 的 payee-list 组装**，不是「stock xmrig 在 T1 上挣 share」。
- **一个二进制，两张网。** `qumbra-pool` 在启动时读一次节点的 genesis form（与 `qumbra-node` 的 `prepare_with_release` 同姿态），并据此构建模板源。无可能与创世哈希脱同步的配置开关（H1）。

## 6. Crate 形态决策（含复用勘察）

### 6.1 提案

| Crate | 角色 | Stage |
|---|---|---|
| **`qlab-stratum`** | 协议库：blob 布局、target 编码、login/job/submit 编解码、fixture 测试。**无 I/O 策略、无 TCP、无记账。** | 0（本 PR） |
| **`qumbra-pool`** | 交付二进制：TCP stratum endpoint + share 记账 + 经节点 RPC 的模板源。依赖 `qlab-stratum` + 节点/RPC 客户端。 | 1+（stage 0 不创建） |

依据：仓库 lib/binary 分裂（`qlab-faucet` / `qumbra-faucet`，`qlab-node` / `qumbra-node`，`qlab-cbserver` 编解码 vs 其 `tiny_http` 服务）。把 bin 放进 `qlab-stratum` 会把监听依赖拖进每个编解码消费者 — 与 `qumbra-faucet` 独立成 crate 的同一机械理由。

### 6.2 复用勘察

| 候选 | 已有什么 | 复用裁决 |
|---|---|---|
| `qlab-p2p` | 长度前缀二进制 peer 线、gossip、sync、`transport.rs` | **不复用于 stratum。** 协议族不同（分帧二进制 P2P ≠ 换行 JSON-RPC）。仅有风格亲缘（版本化拒未知）。 |
| `qlab-cbserver` | `tiny_http` 本机 HTTP + 金字节锁编解码 | **编解码纪律要，服务不要。** HTTP ≠ stratum TCP。可偷：版本头 / 金字节姿态、「参考字节*即*规范」。不依赖该 crate。 |
| `qlab-node::rpc` | 覆盖活节点状态的 HTTP 钱包面（`tiny_http`） | **模板源在 stage 1 消费它；stratum 不共享其传输。** 模板用的附加 RPC（pool-t1-brief §4）可旁落 — 仍是 HTTP，仍非 stratum。 |
| `qlab-pow::keyblock` | Seed-height schedule | **由 `qumbra-pool` 直接复用**（不进 `qlab-stratum` — 保持协议库远离 pow 依赖）。 |
| `qlab-devnet::pow::{target_threshold,…}` | u64 阈值助手 | **在 `qlab-stratum::target` 镜像为纯函数**，使该库离开 RandomX 图；`qumbra-pool` 可调用任一端。 |
| `qumbra-faucet` | 薄二进制覆在已测库上、无密钥主机姿态 | **`qumbra-pool` 的形态先例**（按 pool-t1-brief §4 / faucet §6.2 的无密钥模板主机）。 |

### 6.3 Stage 0 交付

- 本文（+ 英文版）
- `crates/qlab-stratum`（编解码草图 + fixture 测试）
- workspace 成员 + README 注释条目
- **不**建 `qumbra-pool`（空二进制延到 stage 1 — 现在建无操作 bin 只会占一个 crate 名额）

## 7. 验收对照

| 验收项 | 证据 |
|---|---|
| 映射文档 EN+ZH | `docs/pool-stratum-mapping.md`，`docs/pool-stratum-mapping-zh.md` |
| Fixture 往返 | `qlab_stratum::tests::fixture_roundtrip::*` |
| Crate 形态 + 复用勘察 | §6 |
| v4 兼容 / 模板抽象 | §5 |
| CI（`verify-graviton`） | PR 标签；算术 = `main` 基线 + 本 crate 测试（单元 + fixture）。构建者不在本地跑全 workspace 套件（MEMORY GUARDRAIL） |
| 无 endpoint / 记账 / 共识 / deploy | Diff 限于 `docs/` + `crates/qlab-stratum` + workspace/README 接线 |

## 8. 留给 stage 1（此处不裁决）

- TCP accept 循环 + 每连接 extranonce 分配器
- 节点上的模板 RPC 形态（附加、默认关闭 — pool-t1-brief §4）
- Share 难度默认值与 stale-job TTL
- `next_seed_hash` 预热窗口是 N 块还是墙钟时间
