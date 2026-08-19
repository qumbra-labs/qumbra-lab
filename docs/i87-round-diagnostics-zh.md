# 轮次诊断与结构化指标 —— 操作者指南（issue #87）

*English: [i87-round-diagnostics.md](./i87-round-diagnostics.md)，技术细节以英文版为准。*

这份文档讲的是：一轮 checkpoint 没有 finalize 的时候，Qumbra 节点会说什么，以及怎么读。
它之所以存在，是因为此前 42 小时里节点什么都没说 —— T0 WAN soak 量到 14.5–15.9 % 的采样处于
`Degraded`、`stall` 峰值 42（阈值 16），而四个节点在整整 42 小时里只产出**十行**非 telemetry 日志，
全部在启动时。

有两个面，回答的是不同的问题。

| 面 | 回答什么 | 在哪里 |
|---|---|---|
| `ROUND` 日志行 | *第 1,384 轮为什么失败，谁没投？* | stdout，与 `TELEMETRY` 并排 → 容器日志 → 归档 |
| `/metrics` | *多频繁、多久、多严重 —— 在什么窗口上？* | HTTP 抓取端点，**不配置就不监听** |

两者不冗余。计数器说不出某一轮具体是谁缺席；一行日志给不出 p99。谁也不是谁的备份。

---

## 1. `ROUND` 行

一轮一行，在轮次**关闭**时输出；另外，开着太久的轮次在**仍然开着**的时候也会输出一行
（`close=open`、`why=open`），这样停滞是**在发生的过程中**可见，而不是等它结束才可见。
与 `TELEMETRY` 同为 `key=value` 形状，原有的 grep / awk 习惯直接可用。

```
ROUND slot=1384 epoch=12 why=votes_short close=superseded by=1392 have=11 need=15 active=21 roster=21 \
  voted=0,1,2,3,4,5,6,7,8,9,10 absent=11,12,13,14,15,16,17,18,19,20 excluded=- variants=1 msgs=3 local=6 \
  rej=f0/u0/d0/i0 open_ms=1769000000000 first_ms=211 last_ms=63402 quorum_ms=- closed_ms=600113
```

| 字段 | 含义 | 口径 |
|---|---|---|
| `slot` | 轮次号 = cadence 网格上的 checkpoint 高度 | 创世（高度 0）**永远不是**一轮 —— 它是引导性 finalize，没有提议，也没有谁可以「缺席」 |
| `epoch` | 该 slot 所依据的委员会 epoch | 从 epoch schedule 读出；签名者下标只在**同一 epoch 内**可比 |
| `why` | 判定 —— 见 §2 | 由其他字段推出；原始字段始终在行内，你可以不同意这个判定 |
| `close` | `finalized` \| `superseded` \| `evicted` | `evicted` 是被开启轮上限关掉的，不是一个结果 |
| `by` | 越过本轮的那个高度 | 仅在 `superseded` 时有值 |
| `have` | **本节点**累计到的去重**计数**签名者数 | 跨该节点收到的所有消息。不同节点对同一轮记出不同的 `have` 是合法的 —— 那个差异本身是「gossip 触达」的发现，不是不一致 |
| `need` | 当前生效的 quorum 门槛 | 从委员会状态**读取**；此处从不重新推导 |
| `active` | 该高度上 roster 减去 tombstone/jail | `active < need` ⇒ 无论网络多好这轮都赢不了 |
| `roster` | 该高度的委员会规模 | |
| `voted` | 谁有计数票，按委员会下标 | 升序 |
| `absent` | 在 roster 内、未被 tombstone/jail、且**其票没有到达本节点** | 是「触达」，**不是**该成员宕机的证明。在 `finalized` 轮次上它还偏向最慢的节点 —— 见 §7 |
| `excluded` | 票有效但因非活跃被排除的成员 | 由 FROZEN §4 规则排除 —— **不要**去查这些主机 |
| `variants` | 该高度上见到的不同 checkpoint 变体数 | `>1` 表示委员会分裂 —— 这与「票不够」是不同的故障 |
| `msgs` | 本轮摄入的票集消息数 | |
| `local` | 本节点用自己持有的密钥贡献的票数 | 本节点提议的 slot 上出现 `local=0`，意味着所有持有密钥都被 never-double-sign 守卫拒签了 —— 这本身是一条发现 |
| `rej` | `f`orged / `u`nknown-signer / `d`uplicate / `i`nactive | `have=0` 且 `rej` 很大，与 `have=0` 且毫无流量，是完全不同的故障 |
| `open_ms` | **本节点**打开该轮的 Unix 毫秒 | |
| `first_ms`、`last_ms` | 第一张与最近一张**新**计数票的偏移 | 节点本地墙钟；**绝不可跨主机相减** |
| `quorum_ms` | `have` 首次达到 `need` 的偏移 | 从未达到的轮次为 `-` |
| `closed_ms` | 轮次关闭的偏移 | |

在确定性时钟下（所有进程内仿真与 N7 soak），所有时间字段都是 `-`。这是刻意的：节点如实记录计数与
roster，**不会编造一个它并不具备的时间基准**。

---

## 2. 判定阶梯

`why=` 按以下顺序判定，第一个命中者胜出。

1. **`finalized`** —— 达到 quorum。
2. **`backfill`**（issue #105）—— 本节点是把这个槽位当作**历史**走过去的：它第一次得知这个槽位时，
   自己的 tip 已经领先了一个以上的 cadence，所以从来不存在它能投票的那一刻。resync 走过的每个槽位
   都是这个读数。**它不是失败，也不被计成失败** —— 什么都没有失败，是这个节点当时不在场。见 §2a。
3. **`quorum_impossible`** —— `active < need`。无论网络多好，这个 roster 都产生不了 quorum。
   去看 tombstone、jail 和 epoch 边界；**不要**去看延迟。
4. **`silent`** —— `have == 0`。什么都没到达本节点。问题在上游 —— 提议方，或到它的路径 ——
   不是参与度。看一眼 `rej`：有垃圾到达和什么都没到达是两回事。
5. **`timeout`** —— 最后一张*新*票落在关闭前 `STILL_ARRIVING_MS`（60 s）以内。这轮被切断时
   **仍在累积**。更多时间、或更早提议，很可能就关上了。
6. **`votes_short`** —— 票到过，然后在关闭前很久就停了。委员会给出了它能给的全部，仍然不够。
   **`absent` 列表就是那条发现。**
7. **`unclassified`** —— 没有时间基准（确定性时钟）。绝不作为原因断言。

`why=open` **不是**一种判定：还没结束的轮次没有原因。这种行上的计数是真的，只有结果未定，
并且它永远不会被计入「已关闭轮次」的任何计数器。一轮在开启超过 `OVERDUE_AFTER_MS`
（600 s = 一个轮次周期）后被报告一次，此后在票数变化时、或每过 `OVERDUE_REPEAT_MS` 再报一次 ——
所以卡在 `have=11/15` 的轮次会说一声，然后不再刷屏。

**issue #87 要的那条判据就是第 5 步与第 6 步之分**，而它**仅凭记录下来的字段**即可判定 ——
`closed_ms`、`last_ms`、`have`、`need`、`active`。这正是这份日志存在的意义，并由
`round::tests::diagnosis_separates_timeout_from_votes_short` 双向钉住，含边界值。

`STILL_ARRIVING_MS = 60 s` 属于 **devnet 级、可调、非 FROZEN**。依据：T0 网实测 RTT 68–223 ms，
因此健康轮次在约一秒的网络时间内完成；60 s 高出最差实测 RTT 约 270 倍，又低于 600 s 轮次周期约一个数量级。

---

## 2a. `rounds=` 与 `rfail=` 到底在数什么（issue #105）

`TELEMETRY` 为此带三个计数器，全部**自进程启动起累计** —— 重启会清零，这是刻意的，
因为这个项目要数重启：

```
… rounds=144 rfail=2 … rback=449
```

| 字段 | 读作 |
|---|---|
| `rounds=` | 本节点关闭的**活**轮次 —— 它作为参与者在场的那些轮次 |
| `rfail=` | 其中**没有 finalize** 就关闭的那些。这就是告警 |
| `rback=` | 它当作**历史**关闭的 cadence 槽位，即 `why=backfill` |

**把 `rfail` 读作：本节点在场、并且输掉的轮次。** 不是「它走过的槽位」—— 那是它过去的含义，
也正是它变得毫无用处的原因。

一轮是**活**的，当且仅当它的槽位在本节点第一次得知它时，落在**本节点自己的 tip** 前后一个
checkpoint cadence 之内：

```
tip − 8  <  slot  ≤  tip + 8
```

两个边界都取自本节点自己的链。这里既不看同步状态机（那是因为**对端声称**自己更高才进入的 ——
一个宣称荒谬高度的对端否则就能替所有人关掉这个告警），也不看 finalized head
（它在每次进程启动时被重建为空，并且在整个追赶过程中一直是 `None`，撑不起这个判定）。

判定在**轮次开启的那一刻取一次**，此后不再重算。这一点在一个方向上尤其重要：一个在委员会
中断期间继续挖矿的节点，会把自己的 tip 推到它真正输掉的那一轮很远的前面，而一个「关闭时再判」
的做法会把那也叫成 `backfill` —— 那就是告警换一条路把自己关掉。

### 为什么要改

一台刚 resync 了 3,597 块的**健康**节点报出：

```
rounds=1316 rfail=1315        ← 1,316 轮里有 1,315 轮「失败」
```

……而同时 `peers=6`、`regime=Final`、`variants=1`，它 finalize 的 checkpoint 与另外三台完全一致。
计数没有谎报它数了什么；它数错了东西。**一台健康节点上读数 99.9 % 的告警，已经被自己的数值关掉了**，
而任何重启过的节点都处在这个状态里。

### 没有改的部分

`ROUND` 日志仍然记录**每一个**跨过的槽位 —— 这次改的是什么东西给计数器加一，不是记录什么。
跨过的槽位不留痕迹是反方向的错误，而那正是 issue #87 存在的理由。

---

## 3. 指标

`/metrics` 输出 Prometheus 文本格式 v0.0.4。每个族的 `HELP` 里都带着自己的窗口与依据，
所以从端点读到的数字无法与「它是怎么取的」分离。

**计数器与直方图都是自进程启动以来。** 重启会清零 —— 这是刻意的，因为本项目要数重启次数，
而 `qumbra_process_start_time_seconds` 让一次重启可见。

### 此前不存在的那些族

| 指标 | 类型 | 它取代了什么 |
|---|---|---|
| `qumbra_finality_regime_seconds_total{regime}` | counter | **`Degraded` 占比。**各 regime 的*累计驻留秒数*，而不是「碰巧在 degraded 时被打印的采样比例」 |
| `qumbra_block_interval_seconds` | histogram | soak 那组 `mean 86 / median 60 / p99 312`，事件级全分辨率，而不是从 30 s 采样重建 |
| `qumbra_finality_advance_seconds` | histogram | soak 那组 `median 673 / p90 1802 / max 3161` |
| `qumbra_finality_advance_blocks` | histogram | 165 次推进里那 61 次一跳 16/24/32/40 的补课 |
| `qumbra_finality_stall_depth_blocks` | histogram | 停滞**清除那一刻**它已经掉了多深 —— 在事件上取样，不是从 gauge 上做差 |
| `qumbra_checkpoint_time_to_quorum_seconds` | histogram | 此前不存在。一轮成功时要多久 |
| `qumbra_checkpoint_vote_arrival_seconds` | histogram | 此前不存在。轮内每个签名者的到达延迟 |
| `qumbra_checkpoint_rounds_total{verdict}` | counter | 此前不存在。按判定分类的轮次数 |
| `qumbra_committee_absent_rounds_total{signer}` | counter | 此前不存在。按成员的缺席次数 |
| `qumbra_checkpoint_votes_total{result}` | counter | 此前不存在。计入 vs 丢弃的票数，按原因 |

其余（`qumbra_tip_height`、`qumbra_peers`、`qumbra_mempool_size`、`qumbra_committee_*` 等）
都是 **gauge**，因为「水位」的当前值就是它的全部含义。

### 为什么是直方图而不是 gauge

一个被打印出来的 gauge，已经丢掉了它在两次打印之间持有过的每一个值。从 30 s 采样恢复出的 p99，
是*采样的* p99。信息是在**打印那一刻**被销毁的，不是在解析那一刻 —— 所以解析端再小心也救不回来。
这就是这些量各自在产生它的事件上直接喂入的原因。

桶边界按实测 T0 数字选定（见 `qlab-node/src/metrics.rs` 中的常量），属于 **devnet 级、可调、非 FROZEN**。

### 标签基数

标签值只有静态 token 和十进制整数。按签名者分的族由**委员会 roster** 界定 —— 那是一个共识量，
永远不由对端能发送的东西界定，因为签名者下标在计入之前先要通过 roster 校验。
标签里没有任何来自操作者或对端的字符串。

---

## 4. 打开这个端点

**默认关闭。没有 `metrics_addr` 就没有监听。** 一个只在有人明确要求处才存在的端点，
不可能因为忘了关而一直开着。

```toml
# node.toml
metrics_addr = "0.0.0.0:9090"
```

或者通过部署工具：

```sh
deploy/deploy.sh --hosts hosts --metrics-port 9090 …
```

操作者必须知道的几条：

* **绑定失败是致命的。** 节点宁可拒绝启动，也不会在「自以为可观测」的状态下裸奔。
* **`deny_unknown_fields` 是刻意的。** 带 `metrics_addr` 的配置会被本次改动之前编译的二进制
  **拒绝**。**先发二进制，再发配置** —— 顺序不能反。
* **绑定不等于访问控制。** 非 loopback 绑定必须配一条入站规则，其 **source 是抓取端的固定地址或
  安全组** —— 绝不是 `0.0.0.0/0`，也绝不是漫游的操作者 IP。漫游 source 会在一个新地方复现
  42 h soak 的那次 10.15 h 盲区：SSH 那条路正是因此断的。用独立 `aws_security_group_rule` 资源；
  inline 规则曾经静默删掉过十二条 peer P2P 规则。
* **节点服务的是预渲染快照**，由运行循环每 5 s 刷新一次。一次抓取的代价是一次字符串 clone，
  永远不会与共识循环争抢节点状态 —— 这在 2 vCPU 主机上是要紧的。陈旧度从
  `qumbra_metrics_rendered_timestamp_seconds` 读，不要假定等于抓取时刻。
* **7 天保留期是监控，不是证据。** 只能通过 Prometheus 看到的东西，一周后就没了。
  归档节点自己的输出，并引用归档。

---

## 5. 开销

轮次日志**常开**，而它之所以能常开，是因为轮次速率由 **checkpoint cadence 决定，不由出块速率决定**：

```
cadence 8 × 75 s  = 每轮 600 s  =  144 轮/天
144 轮/天 × ≤ 400 B/行          ≈  ≤ 58 KB/天
```

再加上「仍然开着」的报告：正常运行时为 0（轮次在毫秒级关闭 —— lab 网第一条实测轮次在 315 ms 关闭）。
它们只在停滞期间出现，每个开启轮次至多在票数变化时或每 600 s 输出一行，而开启轮次数上限是
`MAX_OPEN_ROUNDS = 16`。42 h soak 见过的最坏停滞（40 块）大约对应 5 个开启轮次，
整段停滞加起来远不到 100 行。

两半都由测试钉住：`round::tests::journal_line_stays_within_the_quoted_budget` 钉住一个
21 人满员轮次的行长上界，`run::tests::round_journal_volume_is_set_by_the_cadence_not_the_block_rate`
把日写入量**推导**出来，而不是手写一个数字。

在这个量级上，一个开关的成本超过它省下的东西 —— 而且**出事时正好是关着的诊断，不是诊断**。
指标面每次抓取约 14 KB，外加 5 s 一次的渲染。

---

## 6. 常用查法

找出所有没 finalize 的轮次及其原因：

```sh
grep 'ROUND slot=' node.log | grep -vE 'why=(finalized|open)'
# （2026-08-19 更正，lab #512：日志行现携带原生 UTC 时间戳前缀，
#   这些配方锚定行内 token（ROUND slot=），绝不锚定行首 ^。）
```

在停滞发生的过程中盯着它（仍然开着的报告）：

```sh
grep 'ROUND slot=' node.log | grep 'why=open'
```

哪些成员缺席最多（对归档日志，全部轮次）：

```sh
grep 'ROUND slot=' node.log | sed 's/.* absent=\([^ ]*\).*/\1/' | tr ',' '\n' \
  | grep -v '^-$' | sort -n | uniq -c | sort -rn | head
```

这次停滞是延迟型还是参与度型？

```sh
grep 'ROUND slot=' node.log | grep -c 'why=timeout'      # 延迟型
grep 'ROUND slot=' node.log | grep -c 'why=votes_short'  # 参与度型
```

有抓取端之后的 PromQL：

```promql
# 最近一天的 Degraded 占比 —— 实测驻留，不是采样比例
rate(qumbra_finality_regime_seconds_total{regime="degraded"}[1d])

# 按原因分的轮次失败率。`backfill` 被刻意排除（issue #105）：它是本节点走过的历史，
# 不是它输掉的轮次；把它留在里面，正是这个数字在健康节点上读到 99.9 % 的原因。
rate(qumbra_checkpoint_rounds_total{verdict!="finalized",verdict!="backfill"}[1h])

# 本节点走过多少历史 —— 重启/resync 的特征值，值得知道，但永远不是告警。
rate(qumbra_checkpoint_rounds_total{verdict="backfill"}[1h])

# 谁在拖后腿：按签名者的缺席率
rate(qumbra_committee_absent_rounds_total[1h])

# time-to-quorum 的 p99
histogram_quantile(0.99, rate(qumbra_checkpoint_time_to_quorum_seconds_bucket[1h]))

# 补课式推进：finality 一次跨过不止一个 cadence
rate(qumbra_finality_advance_blocks_bucket{le="8"}[1h])
  / rate(qumbra_finality_advance_blocks_count[1h])
```

---

## 7. 这些**不能**告诉你什么

写在这里，免得有人从一条记录里读出它并不包含的东西。

* **`absent` 不是成员宕机的证明。** 它是「在本轮关闭前，该成员的票没有到达本节点」。
  一个活着但与*本节点*分区的成员，在这里缺席、在别处在场。把同一 slot 的 `absent` 在四个节点之间
  对照，才能区分这两者 —— 而这个对照现在才成为可能。
* **在 `finalized` 轮次上，`absent` 偏向最慢的节点。** 一轮在 quorum 达成的**那一刻**就关闭，
  所以比第 15 票晚 50 ms 的成员会被记成缺席。lab 网第一条实测行正是这个样子：它在
  `quorum_ms=315` 以 `have=16` 关闭，而最远那个节点持有的 5 把钥匙落在 `absent` 里 ——
  它们是慢，不是死。`qumbra_committee_absent_rounds_total` 继承这个偏差。
  **无偏的读法在失败轮次上**，因为失败轮次开着的时间长得多：日志按 `why!=finalized` 过滤，
  或者把该指标对着 `qumbra_checkpoint_rounds_total{verdict!="finalized",verdict!="backfill"}`
  读 —— 一个 `backfill` 轮次根本没有在场的人可供缺席。
  这样用，这个计数器回答的是「关键时刻谁不在」；直接用，它回答的是「谁离得最远」——
  那也是一件值得知道的事，但不是同一件事。
* **时间是节点本地且不同步的。** `first_ms`/`last_ms`/`quorum_ms` 都是相对*本节点*打开时刻、
  按*本节点*墙钟的偏移。绝不可跨主机相减。
* **`have` 是本节点的视角。** 权威的 quorum 闸门未作任何改动，并且位于所有这些记录的上游；
  这里没有任何东西能让某个东西 finalize，或阻止它 finalize。
* **判定是对字段的一种读法，不是一次测量。** 原始字段始终在行内。如果你不同意 `why=`，
  用来反驳它的证据就在同一行上。
* **这套东西不回答 `DEGRADED_MODE_LAG_BLOCKS = 16` 这个阈值对不对。** 它产出那个问题所需要的证据。
  该常量是 FROZEN，本次未动；改它要走 halt-height 升级，是独立的一件事。
