# Explorer 前台(front-of-house)— 阶段 0:调研、路由提案、页面信息架构(lab #486)

> [English](explorer-foh-stage0.md)

**状态:PROPOSED(2026-08-18)——[#486](https://github.com/qumbra-labs/qumbra-lab/issues/486)
的阶段 0 调研交付物。本棒不含任何行为变更;代码 = 无(路由桩有意未做——原因见 §7)。
协调者要评审的对象是 §3 的路由表和 §5 的信息架构(IA)。**

事实核对基准:lab `main` `31e0cbd`、`qumbra-explorer-web` `667bc61`,以及在
2026-08-18 15:53–15:59 +08 采样的线上公开端点 `explorer.qumbra.org`。估算单位为
**Claude session-hours**(sh);墙钟时间取决于会话的安排间隔。

---

## 1. 盘点——API 今天已提供什么

共三条路由,仅 `GET`,其余一律为带类型的 404/405
(`crates/qumbra-explorer/src/http.rs:1-11`):

| 路由 | 文档 | 来源 |
|---|---|---|
| `/v1/health.json` | 链健康投影,`HEALTH_VERSION = 1`(`src/json.rs:54`) | `qlab_node::Telemetry`,由运行循环重新序列化(`src/main.rs:176-193`) |
| `/v1/txlist?from=&to=` | #326 的交易存在性视图,`TXLIST_VERSION = 1`(`src/txlist.rs:92`) | 从 `node.state().chain()` 投影出的 `TxListView`(`src/main.rs:131-132`) |
| `/healthz` | `"ok"`,无状态 | — |

`health.json` 字段(全部出自 `src/json.rs:65-104`):`v` · `genesis_file_hash` ·
`refresh_secs` · `chain{tip_height, tip_difficulty, regime, peers, mempool}` ·
`finality{head1{height, checkpoint_id, age_s, stall_depth}, head3{state, height, block_hash},
agreement{divergent, token, tracker, durable}}` · `committee{epoch, roster, active, quorum}` ·
`supply{coverage, epochs[]}`——每个 epoch 行已携带 `burned`
(`src/json.rs:187-199`,作为 #367 启用准备落地)。拒答纪律整体继承自
`Telemetry`(`age_s` 为字符串、以 `-` 表示,部分覆盖时 `epochs` 键缺失,
`UNAVAILABLE`/`DIVERGENT`/`KNOWN_SCAR` 标记——`src/json.rs:22-42,159-223`)。

`txlist` 中每个含交易的区块:高度 + 每笔交易的 `{txid, wire_bytes, fee, nullifiers,
commitments}`(`src/txlist.rs:134-151`),按 `MAX_TXLIST_HEIGHTS = 1024` /
`MAX_TXLIST_TXS = 256` 分页,附显式的 `covered_to`(`src/txlist.rs:111,126`),D3 的
边界说明句在带内直接提供(`src/txlist.rs:96-100`)。不支持按 txid 查询——D2,结构性决定
(`src/lib.rs:29-35`)。

**已对照任务书的前提逐条核实:** API 一半确实在 `qumbra-explorer` 里
(`31e0cbd` 时 `crates/` 下共 21 个 crate,而非工作区简报所说的 17 个);页面一半是
`qumbra-explorer-web`(已读,未动);`health.json` 与 #326 视图与追踪 issue 的描述一致。
有一条前提需要更正:**追踪 issue 所说的"边界跨越在本周四"在目标出块时间下不成立**——见 §6。

## 2. 盘点——观察者已持有但尚未提供的状态

无密钥观察者(`RunningNode`,在 `src/main.rs:112` 组装)应用完整区块并持久化它们。
在其今天的状态中,尚未对外提供的有:

| 已持有的状态 | 位置 | 提供状态 |
|---|---|---|
| **完整头链**:每个高度的 `prev, height, timestamp, difficulty, nonce, tx_body_commitment` | `qlab-devnet/src/header.rs:56-73`;主链可经 `ChainState::main_chain()` + `header(&hash)` 升序枚举(`qlab-devnet/src/chain.rs:286,250`),可通过 `state().chain().chain()` 触达(`qlab-node/src/store.rs:350`) | **未提供**——只有 `tip_height`/`tip_difficulty` 进入 `health.json` |
| **每个已应用高度的完整区块体**(从不裁剪:`store.rs:334,439`),含每区块的 coinbase 数值(bessel) | `StoredBlock`(`qlab-node/src/store.rs:153-163`),`block(&hash)`(`store.rs:458`) | 未提供(仅通过供应行给出按 epoch 的聚合) |
| **名称服务附载(rider),按笔交易持久化**——`Commit{commit}` / `Reveal{record, salt}` / `Renew{name}` | `StoredTx.rider`(`store.rs:100-108`);操作形状 `qlab-devnet/src/names.rs:162-172`;`NAME_RULE_BOUNDARY_HEIGHT = Some(19_008)`(`names.rs:59`,测试锁定于 `names.rs:615`);在 `qlab-node/src/node.rs:1591-1595` 折入 `NameRegistry` | **explorer 未提供**(node/cbserver 的 `/v1/names?from=&to=` 投影——`qlab-node/src/rpc.rs:1012-1024`、`names_page` `rpc.rs:1433`——是另一个表面,其形状可供 R4 镜像) |
| **已最终化检查点历史**(头 #1 追踪器):升序的 `Vec<Checkpoint{height, block_hash, root}>` | `qlab-devnet/src/finality.rs:74-78`;`Checkpoint` 位于 `qlab-devnet/src/committee.rs:177-184`;explorer 可经 `p2p().node().finality()` **触达**(`qumbra-node/src/run.rs:913`,`qlab-p2p/src/adapter.rs:935`) | 未提供且**不可枚举**——追踪器只暴露 `latest()`/`count()`(`finality.rs:142,198`),无迭代器;**进程生命周期**——重启后仅从恰好一个检查点再水化(`finality.rs:93-94`,`adapter.rs:648`);devnet 的 Vec 是无界的(`finality.rs:75-76` 注明的 `~144 roots` 上界并未实现——既有问题,#135 相邻,已标记但未修) |
| **创世网络标签** | `GenesisFile.network: String`(`qumbra-node/src/genesis.rs:368`,`[devnet-placeholder]`,非共识;t0 生成器写入 `"qumbra-devnet-t0"`,`genesis.rs:458`);explorer 已在启动时加载该文件(`src/main.rs:83`) | 未提供——`genesis_file_hash` 是今天线上唯一的网络身份 |
| **随时间变化的 peer 数 / 网络体征** | **任何地方都不存在**——`Telemetry.peer_count` 是瞬时值;`qlab-node`/`qumbra-node`/`qumbra-explorer` 中没有带时间戳的序列(metrics 的 `Histogram` 只做聚合,不保留样本——`qlab-node/src/metrics.rs:101`) | 需要一个新的(有界)投影 |

同样已持有且未提供、但 #486 的七个条目不需要的(点名列出,使路由表的省略读起来是
选择而非遗漏):按轮次的诊断环形缓冲——在无密钥观察者上也会填充,`RoundLedger.recent`,
64 条记录,含投票/变体/时序细节(`qlab-node/src/round.rs:603,95,942`);实时 peer 列表
(每个 peer 一条 `PeerInfo`,`qlab-p2p/src/peer.rs:113-120`);整张 `FrozenParams` 表 +
发布/修订身份(`genesis.rs:115-217`,`qumbra-node/src/release.rs:221-231`——未来的
`/v1/params` 可原样提供这些);`Telemetry.signed`(sslot/sid)与 `supply_lag()`;以及
完整的 Prometheus gauge 集合,可在进程内渲染而无需监听器(`run.rs:1736`)。

因此七个范围条目中:**四个是对已持久化链状态的纯服务侧新增**(区块滚动栏、难度/间隔
图表、名称事件流、横幅标签),**一个已经完整提供**(供应面板——仅页面工作),**两个
需要一个小的新投影**(最终性滚动栏:历史存在于内存中,但需要一个访问器或 explorer 侧
的环形缓冲;peer 数时间序列:需要一个采样环形缓冲,目前一无所有)。

## 3. 路由提案

版本化立场,只陈述一次并提议作为此表面的法则:**explorer 的 JSON 是它自己的公开表面,
有意不使用 `RPC_VERSION`**(`src/json.rs:44-54` 已有记录)。每个文档携带自己的版本常量。
**纯新增——一条新路由,或既有文档中的一个新键——不递增任何版本**(先例:`burned`
随 `supply.epochs[]` 行加入时 `v` 保持为 1;读取方忽略未知键、拒绝未知 `v`)。对既有键
的重命名、删除或语义变更则递增该文档的版本,并按设计使旧页面变暗(拒绝未知)。
**推论,因 §6 的发现而成为约束:** 每一次增量变更都在同一棒内刷新跨仓库金样语料
(`crates/qumbra-explorer/goldens/` → `qumbra-explorer-web/fixtures/`)——语料只有在
真的被复制过去时才能捕获偏差。

PR #315 的家规(主记录 `qlab-node/src/rpc.rs:113-118`;`RPC_VERSION = 0x06` 位于
`rpc.rs:135`)以平凡方式满足:**`qumbra-node` 的 RPC 路由与字节完全不动**——下面每个
提案都由 `qumbra-explorer` 从其自身观察者的状态提供。`RPC_VERSION` 不动。唯一一处
explorer crate 之外的改动是 R2 的增量访问器(见下),那是 lab 内部的 Rust API,不是线协议。

所有路由均按范围/批量提供,不设按 id、按名称或按地址的形式——D2 / PR #315 决定 3 的
关联面规则延伸到每条新路由:询问某一个具体事物会告诉服务器你关心哪个事物;范围查询
则不会。

### R1 — `GET /v1/blocks?from=&to=`(范围条目 1 + 3:区块滚动栏、难度 + 间隔图表)

纯服务侧新增;链上派生;可跨重启存活。

```json
{ "v": 1, "tip_height": 15761,
  "range": { "from": 15700, "to": 15761, "covered_to": 15761 },
  "blocks": [ { "height": 15761, "block_hash": "e0e0…", "timestamp": 1787039600,
                "difficulty": 2837, "body_commitment": "ab31…",
                "txs": 0, "coinbase": 4979012345 } ] }
```

- 事实来源:对 `StoredBlock` 的主链遍历(`store.rs:153-163`、`header.rs:56-70`)。
  每个字段都是共识公开的。
- 分页:原样沿用 `txlist` 的契约——`MAX_BLOCKS_HEIGHTS = 1024`、显式 `covered_to`、
  客户端向后翻页取历史(PR #312 的进度守卫形状)。
- 页面的区块滚动栏读取其尾部;难度/推算算力图表与区块间隔分布由客户端从 `difficulty`
  和相邻 `timestamp` 差值计算——**没有服务器侧图表数据、没有新投影、没有环形缓冲**。
  推算算力属于呈现层(难度 ÷ 目标间隔),在页面侧计算并标注为"推算"。
- `coinbase` 是每区块的已承诺数值(`store.rs:156`)——这也是让供应故事按区块可见的
  东西(追踪 issue 条目 1 的"coinbase presence";铸币后每个主链区块都携带一个,所以
  有意思的呈现是数值本身,而 19,008 之后是扣除名称燃烧后的净值)。
- 新文档 ⇒ `BLOCKS_VERSION = 1` + 两个金样(典型范围、空覆盖范围),二者都复制进
  web 语料。

### R2 — `GET /v1/checkpoints`(范围条目 2:最终性滚动栏)

历史存在于 `FinalityTracker.finalized`(`finality.rs:74-78`),且追踪器已可从 explorer
进程触达(`p2p().node().finality()`——`run.rs:913` + `adapter.rs:935`)——但它
**不可枚举**:追踪器的公开表面只有 `latest()`/`count()` 及同类(`finality.rs:142,198`),
没有对该 Vec 的迭代器。两个选项,**提案取 (a)**:

- **(a) 在 `FinalityTracker` 上增加一个纯增量方法**(qlab-devnet,lab 内部 Rust API,
  增量,不涉线协议,不涉 RPC):`finalized_tail(n) -> &[Checkpoint]`(或一个迭代器),
  返回升序的最后 `n` 个。explorer 通过已存在的访问器链提供该尾部。
- (b) explorer 侧的环形缓冲,靠在运行循环中观察 `telemetry().finalized_id` 的变化来
  填充。作为主方案被否:它只能看到在某个循环 tick 时恰好是头部的那些检查点,而且
  它是节点已持有状态的第二份拷贝。

```json
{ "v": 1, "history_from_height": 15320,
  "checkpoints": [ { "height": 15720, "block_hash": "e0e0e41fc07a", "fid": "3ba08370682f",
                     "span": 8 } ] }
```

- 服务上界:最后 `MAX_CHECKPOINTS = 512` 个(按 8 区块节奏约 2.8 天),这是一个与
  追踪器自身增长无关的服务侧上界。`span` = 与前一个已最终化检查点的高度差
  (Ebb-and-Flow 的故事:span > 节奏意味着跨越过降级时段)。
- **诚实字段 `history_from_height`**:追踪器重启时从一个检查点再水化
  (`adapter.rs:648`),所以深度是进程生命周期的。文档说明自己的历史实际从哪里开始;
  页面渲染为"自观察者上次重启以来",而不是暗示这是链生命周期的历史。
- `slot` 今天并不按历史检查点保留(遥测中只有实时头部的 `sslot`);滚动栏不带它上线,
  而不是去增长节点状态——记为与追踪 issue 所愿的"(fid, slot, span)"的唯一分歧。若确实
  想要 slot,那是节点侧的保留问题,是阶段 1 要在 issue 上问的问题,不能悄悄加上。
- 不提案:持久化这个环形缓冲。有界内存是法则(#135);滚动栏里的重启缺口既诚实又
  廉价,而第二种持久化格式两者皆非。

### R3 — `GET /v1/vitals`(范围条目 4:peer 数 + 随时间的网络体征)

唯一真正全新的投影:explorer 进程内的一个采样环形缓冲(今天任何地方都不持有这个)。

```json
{ "v": 1, "sample_secs": 60, "since": 1787000000,
  "samples": [ { "t": 1787039640, "peers": 5, "mempool": 0, "tip_height": 15761,
                 "stall_depth": 0 } ] }
```

- 运行循环(`src/main.rs:176-193`)已在持续 tick;它每 `sample_secs` 从它本就采集的
  同一个 `Telemetry` 快照中追加一条样本。
- **上界:`VITALS_SAMPLES = 1440` × 60 s = 24 h**,≈ 1440 × 40 B ≈ **58 KB 常驻**,
  固定——提议作为 #135 的上界。文档最坏情形 ≈ 120 KB JSON,整体提供(这个体量不需要
  分页)。
- 进程生命周期,`since` 予以言明(与 R2 相同的诚实规则)。不持久化,理由相同。

### R4 — `GET /v1/names/events?from=&to=`(范围条目 6:名称事件流)——完整设计见 §4

纯服务侧新增,从已持久化的附载(rider)链上派生(`store.rs:100-106`)——**不是**
环形缓冲,而这正是暗上线(dark-ship)得以成立的原因(§4)。

### 已提供——范围条目 5(供应量证明面板)

**无 API 变更。** `supply.epochs[]` 已按 epoch 携带 `expected_coinbase`、
`measured_coinbase`、`fees`、`burned`、`delta`、`verdict`
(`src/json.rs:183-215`),包括 `KNOWN_SCAR` 既往豁免。面板用来比对的排放计划是确定性
的,且这些行已携带比较的两侧。条目 5 是页面工作:渲染面板、增加 `burned` 列(当前
页面缺失——`qumbra-explorer-web/index.html:136-148` 没有 burned 列),并配上"随名称
注册开始变为非零"的文案。外加 §6(b) 欠下的 fixture 刷新。

### 增量字段——范围条目 7(TESTNET 横幅的网络名来源)

`health.json` 增加一个顶层键,纯增量,`v` 保持为 1:

```json
"network": "qumbra-testnet-t1"
```

- **来源:`GenesisFile.network` 原样照搬**(`genesis.rs:368`),explorer 已在启动时
  加载该文件(`src/main.rs:83`)。链上钉死——节点在 genesis-file-hash 不匹配时拒绝
  启动,因此标签不可能偏离实际观察的网络——并且永不硬编码在页面里。(线上 T1 创世
  文件携带的确切字符串在本棒中没有读取——创世文件在工作区的禁读清单上;该字段的存在
  与加载路径已在代码中核实。阶段 1 渲染它写的是什么就是什么。)
- 页面规则(阶段 2):只要 `network` 不是保留的主网标签(提议字面量:`qumbra-mainnet`,
  在主网创世时定夺),横幅就渲染;键缺失(旧版 API)时渲染为"未识别网络"状态的横幅
  而不是隐藏——宁可高声失败(fail-loud),遵循 naming-and-branding §7 的意图(没有人
  会把测试网错当成真钱的网)。抑制是例外,永远不是默认。
- §7 的带标记域名(`explorer.t1.qumbra.org`)尚未解析(2026-08-18 检查;按设计文档,
  该执行随 T2 批次进行)——横幅一定不能依赖主机名,这也是标签取自创世文件而非 URL
  的又一个理由。

## 4. 名称事件流的暗上线(dark-ship)设计(范围条目 6)

**数据通路。** 19,008 之后,v3 区块体携带每笔交易的附载(rider),观察者将其持久化
(`store.rs:100-106`)。该事件流是对主链遍历的一个投影,与 `txlist` 完全同构:解码
每笔已存储交易的附载(`names.rs:278` `decode_rider`),发出事件。

```json
{ "v": 1, "boundary_height": 19008, "tip_height": 15761,
  "range": { "from": 15000, "to": 15761, "covered_to": 15761 },
  "events": [
    { "height": 19012, "kind": "commit", "commit": "9a4f…" },
    { "height": 19031, "kind": "reveal", "name": "larry", "record_kind": "l1_address",
      "fee_burned": 12800000000, "expires_height": 33111 },
    { "height": 19400, "kind": "renew", "name": "larry", "fee_burned": 12800000000 } ]
}
```

- **commit 按其本来面目渲染**:一个不透明的 `H(record ‖ salt)`(`names.rs:163-165,356`)
  ——诚实的文案是:一个 commit 证明有人保留了*某个东西*,并将在 `[8, 2304]` 区块窗口
  内揭示(`names.rs:81-83`)。不做假解码,不做"待定名称"。
- **reveal 是名称服务存在的第一个用户可见证明**:名称(N3 语法,≤63 字节)、记录类型、
  以及按长度档位燃烧的费用(`names.rs:103` `name_fee_bessel`——1/32/128/512/2048 QMB)
  ——这同时也是供应面板的 `burned` 列变为非零的时刻,两个表面互相印证。**绑定的地址
  被有意从事件流文档中省略**:reveal 的线上表示还携带 1,233 字节的 L1 地址
  (`names.rs:150-156,94`)——共识公开,已可通过节点的 `/v1/names` 附载投影提供
  (`rpc.rs:1012-1024`)——但一个*事件流*回答的是"发生了什么",不是"解析这个名称",
  而且每个 reveal 携带 ~1.2 KB 会让事件流的重量变成地址簿的重量。想要该绑定的读者
  自有另一个表面可用。
- **renew** 同样是公开的共识事件(`names.rs:169-171`),搭乘同一条事件流——追踪
  issue 说的是"commit 与 reveal";纳入 renew,是因为从一个事件流中省略第三种公开操作
  类型将是一次无声的编辑取舍。已标记为一个小的范围扩展,协调者不想要可以划掉。
- **边界之前:诚实的空状态,不造假。** 文档始终携带 `boundary_height`(来自
  `NAME_RULE_BOUNDARY_HEIGHT`,`names.rs:59`);边界前任意已覆盖范围上的事件列表为空,
  *且页面说明原因*:"名称服务在高度 19,008 启用——每一次注册都会从其首个区块起出现在
  这里。"一个空的已覆盖范围是一个事实,不是一个错误(`txlist` 的空/覆盖之辨,
  `src/txlist.rs:716` 测试,原样复用)。
- **时间压力比追踪 issue 所述更宽松,这是一个发现,不是放慢的理由:** 因为事件流是从
  *已持久化的链状态*投影而来、而非在环形缓冲中累积,它会**回填**——在边界之后才滚动
  上线的 explorer 在下一次遍历时依然提供从区块 19,008 起的每一个事件。"API 形状应在
  阶段 1 落地,好让数据从第一个区块起累积"因此在构造上自动满足;提早落地真正买到的,
  是边界跨越那一刻页面已有东西可指——这依然值得在阶段 1 中把 R4 排在最前。
- 不做按名称解析、不做名称→历史查询:只按范围提供,若页面日后长出过滤器则在客户端
  匹配(D2 规则;节点自己的 `/v1/names` 路由已按 #381 的记录点名拒绝按名称解析)。

## 5. 页面 IA 草图(阶段 2 —— `qumbra-explorer-web`,恪守零构建)

恪守的约束:原生 ES 模块、无框架、无构建、无外部引用;`contract.js` 判定 / `app.js`
绘制(`README.md:29`);双语内嵌于 DOM;横幅机制与严重度样式类已存在
(`assets/app.css:134-153`)。**图表是由新的纯模块 `charts.js` 手写生成的内联 SVG**
(字符串入 → SVG 字符串出,像 `contract.js` 一样在 `node --test` 下测试;不用
`<canvas>`,不用库)。拆分决策文档点名"页面需要时间序列"是重开其轴 3 的诚实触发条件
(`t1-explorer-split-decision.md` §3)——此处采取的立场:**轴 3 不重开**,因为该触发
条件的实质是"图表库是一个真实依赖",而 ~150 行手写生成的 SVG 折线/直方图不是依赖。
若协调者按字面解读该触发条件,那是阶段 2 之前要在 #486 上求一句裁定的事。

```
┌────────────────────────────────────────────────────────────────┐
│ ⚠ TESTNET — qumbra-testnet-t1 — 币无价值                        │  ← 新增横幅,位于 topbar 之上,
│   (标签取自 health.json 的 "network";测试网上永不隐藏)          │    琥珀色 .banner.warn,双语
├────────────────────────────────────────────────────────────────┤
│ topbar: mark · Qumbra · [中文] [◐]                              │  (不变)
│ h1 链健康 — 导语(不变)                                          │
│ #status 横幅(不变)                                              │
├── 链 ──────────────────────────────────────────────────────────┤
│ tip · difficulty · regime · peers · mempool(表格不变)           │
│ 新增  实时区块:R1 的最近 12 条,最新在前,随轮询滚动              │
│       高度 · 距今 · 交易数 · coinbase · 区块体承诺(截短)         │
├── 最终性 ───────────────────────────────────────────────────────┤
│ 既有 head1/head3/agreement 表格(不变)                           │
│ 新增  检查点滚动栏:R2 的最近 8 条 — 高度 · fid · span            │
│       + "历史自观察者于 #15320 重启起"的诚实提示行                 │
├── 新增 工作量(图表,全部由客户端从 R1 计算)──────────────────────┤
│ 难度随高度变化(SVG 折线)+ 推算算力标注                           │
│ 区块间隔分布,最近 1024 个(SVG 直方图)                           │
│   图注:"LWMA 目标 75 s;离散是普通的 PoW 方差"                    │
├── 新增 网络(来自 R3)──────────────────────────────────────────┤
│ 24 h 内的 peers(SVG 折线)· mempool 迷你走势图                   │
│   + "自观察者启动起每 60 s 采样一次"的诚实提示行                   │
├── 委员会 ────────────────────────────────(不变)────────────────┤
├── 供应量证明 ───────────────────────────────────────────────────┤
│ 既有表格 + 新增 burned 列                                        │
│ 新增说明:"burned 随名称注册开始变为非零"                          │
├── 交易 ──────────────────────────────────(不变)────────────────┤
├── 新增 名称 ────────────────────────────────────────────────────┤
│ 19,008 之前:"名称服务在高度 19,008 启用。commit 与 reveal 是      │
│   公开的共识事件,自其首个区块起将在此出现。现在为空——             │
│   这是设计使然。"                                                 │
│ 之后:事件流(R4),最新在前:commit = 不透明哈希,附诚实           │
│   解释;reveal = 名称 · 类型 · 燃烧费用                            │
├── footer ──────────────────────────────────────────────────────┤
│ 既有"墙"段落 + 新增一句(产品文案,双语):                          │
│ "没有余额、没有地址、没有交易图——不是缺失,而是设计上的             │
│ 不存在:这条链本身不携带它们。"                                    │
└────────────────────────────────────────────────────────────────┘
```

"墙"所述的种种"不存在"从仅出现在 footer,变为**陈述在读者会去寻找那件缺失之物的页面
位置上**——名称区块解释 commit 之所以不透明*正因为协议如此*,footer 的句子收紧为上面
提议的产品文案("no balances — by design"是追踪 issue 的措辞,此处以完整句子呈现)。

## 6. 发现(阶段 0 的顺带发现,本棒一概未修)

**(a) 🔴 线上的 `health.json` 已冻结,而同一进程的 `txlist` 在前进。**
观察于 2026-08-18 15:53–15:57 +08,四次抓取可复现:`health.json` 逐字节相同地钉在
`tip_height 15727, age_s "491", stall_depth 7`,而 `/v1/txlist` 报告
`tip_height 15761`——健康文档至少落后 34 个区块(按目标约 42 分钟),且其冻结的
`age_s` 证明它根本没有被重新序列化(`refresh_secs` 下限的重渲染本应使 `age_s` 每
≤30 s 变动一次)。两个视图由*同一个*运行循环闭包更新(`src/main.rs:176-193`),所以
循环在跑;可疑的接缝正是健康写入本身:`if let Ok(mut p) = page.write() { … }`
(`src/main.rs:181-183`)**将中毒/失败的 `RwLock` 永久静默吞掉,没有任何日志行**——
进程历史上任何时点写入方的一次 panic,就会让该投影永久变暗,而 `/healthz` 仍继续回答
`ok`。这是假设,不是诊断:此席位无主机访问权限(也未寻求——部署超出范围)。无论根因
为何,阶段 1 应当 (i) 把静默吞掉换成响亮的日志 + `/healthz` 降级,以及 (ii) 运维侧
或许想现在就重启 explorer 容器——T-ops 定夺,已在 #486 上标记。

**(b) 🟡 跨仓库金样语料已经发生偏差。** lab 的金样在每个供应行中携带 `"burned":0`
(`crates/qumbra-explorer/goldens/agreed` 等,自 #367 启用准备起);
`qumbra-explorer-web/fixtures/{agreed,durable-lag,durable-absent}` 则没有——fixture
从未刷新,因此语料"一次重命名让一侧变红"的性质对这三个健康金样目前并不生效(两侧
套件各自对着自己的陈旧副本都是绿的)。阶段 2 刷新 fixture;§3 的版本化立场使同棒
刷新成为约束,以关闭这一类问题。

**(c) 🟡 在 4.4 分钟的实时窗口内观察到零个区块**(tip 15,761 未动,
15:54:44–15:59:06 +08,3 次采样)。弱证据——在 75 s 目标下这是 p≈3% 的安静窗口,
且冻结健康快照的 `stall_depth 7 / age_s 491` 早于该窗口。记为供 T-ops 关联的观察,
不作断言。

**(d) `explorer.t1.qumbra.org` 尚未解析**(naming-and-branding §7 的执行随 T2 批次
进行)——记录在案,免得阶段 2 假定带标记的主机名已存在。

**(e) `FinalityTracker.finalized` 在 devnet 上是无界的**(`finality.rs:75-76` 注明
~144-root 上界未实现)。当前高度下约 2.4 K 条——今天无害,既有问题,#135 相邻;
无论如何 R2 提供的是有界尾部。点名此事,以免有人把 R2 误当成需要该上界的那个东西。

**(f) lab `CLAUDE.md` 漂移:#381 条目仍写着 `NAME_RULE_BOUNDARY_HEIGHT = None`
("merged inert")**,而已上线的常量是 `Some(19_008)`(`names.rs:59`,测试锁定于
`names.rs:615`)。在 #381 合并时为真,自启用起过期。一行的文档修正,此处未做
(超出本棒范围)。

## 7. 为什么本 PR 不做路由桩

任务书允许"至多做带测试的路由桩"。有意未取:一个提供带版本空文档的桩,会在协调者
评审 §3 的形状之前,把四份新契约的 `v:1` 字节放上公开表面——而这个表面的整个版本化
立场就是:已提供的字节要经过深思熟虑才冻结。阶段 1 改为每条路由整体落地
(投影 + 金样 + web 语料副本)。

## 8. 阶段计划(估算单位为 Claude session-hours)

| 阶段 | 内容 | 估算 |
|---|---|---|
| **1 — API**(lab `qumbra-explorer`,一棒) | R4 最先(名称事件流,让页面在边界时已有它),然后 R1、`network` 字段、R2(连同增量的追踪器访问器)、R3;每条路由的金样 + web 语料副本;§6(a) 的静默吞掉修复顺带同行(同一文件,近乎前置条件——若折入则在 PR 中标明) | 3–4 sh |
| **2 — 页面**(`qumbra-explorer-web`) | 横幅 + 名称区块 + 实时区块 + 检查点滚动栏 + `charts.js`(SVG、纯函数、带测试)+ 网络区块 + burned 列 + 文案(EN/ZH)+ fixture 刷新(§6(b))+ publish-manifest/测试更新 | 3–4 sh |
| **3 — 上线** | svc0 镜像滚动升级(T-ops,常规;explorer API 先行,页面在后——页面对缺失路由的容忍方式是渲染其具名的 UNAVAILABLE 状态,`app.js:233-236` 先例) | 不在上述估算内 |

用于排期的边界算术:2026-08-18 15:54 +08 实时 tip 15,761;19,008 − 15,761
= 3,247 个区块 ≈ **按 75 s 目标 67.6 h ⇒ 约 2026-08-21(周五)午间 +08**,而非追踪
issue 所说的"本周四"——且实测尾部当前*慢于*目标(§6(c))。只要及时派发,阶段 1 无论
如何都能从容赶在边界之前落地;这个更正的意义只在于:不要有人把周四当成一个足以为
跳过评审辩护的硬截止。

## 9. 此处已定 vs 留给协调者

**提议:** §3 的路由表(R1–R4 + `network` 字段)· 增量不递增版本作为此表面的法则 +
有约束力的同棒语料刷新 · 名称事件流从链上派生(可回填;纳入 renew;绑定地址从事件流
中省略)· 横幅取自 `GenesisFile.network`,缺失时高声失败 · 图表为手写 SVG,轴 3 不
重开 · 阶段 0 不做桩。

**开放(已在 #486 上提问):** 是否从 R4 中划掉 renew?· R2 的增量访问器接缝 vs
explorer 侧环形缓冲 · 历史 `slot` 是否值得节点侧保留(R2 不带它上线)· 若手写 SVG 被
判定为重开轴 3,轴 3 应如何解读 · §6(a):现在就重启线上 explorer,还是等阶段 1 的修复。
