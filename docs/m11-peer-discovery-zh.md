# M11 —— 节点发现（issue #83）

*English: [`m11-peer-discovery.md`](m11-peer-discovery.md)（技术细节以英文版为准）。*

节点拿 `GetAddr`/`Addr` 做什么、怎么判定一个地址「可拨通」，以及为什么连接数上限必须
和 auto-connect 同一个 PR 落地。本文写自实现过程；范围以任务书为准。

## 一句话

此前：`dial_peers` 就是全世界 —— 可达节点集在部署时固定，节点永远学不到别人。它**会**
应答别人的 `GetAddr` 把地址簿给出去，却把收到的地址簿**直接丢掉**（`node.rs:248`，
`MsgType::Addr => { /* prototype: no auto-connect */ }`）。

现在：节点从对端学地址，判定其中哪些真的可拨通，在上限内自动连接，只 gossip 可拨通的，
并把学到的东西带过重启。

## 两半各在哪，以及为什么只有一条拨号路径

| 部件 | crate | 为什么在那 |
|---|---|---|
| 地址簿、dialable 状态、退避、上限、持久化格式 | `qlab-p2p::addrman` | 纯策略、不碰 socket，因此全部可单测 |
| `Transport::dial` | `qlab-p2p::transport` | 机制；**两个 transport 都实现**，于是发现循环在内存内确定性测试和真 socket 上是同一份代码 |
| 入站上限 | `qlab-p2p::transport`（accept 循环） | 必须在 **accept 处**拒绝；再往上一层连接就已经被收下了 |
| 维护轮次（`maintain`） | `qlab-p2p::node` | 对账 → 自动连接 → 索要地址 |
| 运行循环节奏、配置、持久化 I/O | `qumbra-node::run` | 它拥有数据目录、时钟和进程 |

**只有一条拨号路径，这是刻意的。** `qumbra-node` 里 T0-5/S9 那套重拨机制
（`RedialSlot`、`REDIAL_*`，按*配置里的地址*做 key）已删除；其行为原样搬进 `addrman`
—— 同一条退避阶梯、同一条「句柄还活着就跳过」规则 —— 现在也覆盖学到的地址。**两条退避
策略和上限各不相同的拨号路径，正是「节点超出了它自以为在执行的上限」的成因。** S9 的
验收测试是**转换**而非删除：`redial_reconnects_a_configured_peer_without_restart`
仍然走新路径通过。

## 决定

### 1. 可拨通 = 「我们连上去过」，别的都不算

学到的地址是**候选**。只有当我们成功**向它**建立过连接，它才变成 **dialable**，而且只有
dialable 的地址才会被 gossip 出去（S2）。「对方连到了我们」不构成任何证据：在一个接受
「只出不入」参与者的网络里，这类节点大多数是拨不回去的。

`dialable` 在断连后**保持**。一次分区不是不可达的证明；如果分区会清掉这个标记，恰恰在网络
最需要种子集的时候，种子集会不再可被 gossip。

### 2. 自身可达性用**显式配置**，不做推断

新增可选配置项：`advertise_addr`。

另一条路 —— 从观察到的入站连接推断 —— 在这里根本行不通。节点看到的是**对端**的源地址，
永远不是自己的公网地址；唯一的获知方式是让对端告诉它，而那是改 `Addr`/`Version` 载荷，
属于 wire break、属于 coordinator 的决定（S1）。所以：知道节点可达的运维方把它写出来。
四台 T0 主机会写（`deploy/deploy.sh` 与 docker 的 `entrypoint.sh` 现在都会生成该字段）。

没有 `advertise_addr` 的节点**永远不会被 gossip、不会出现在任何人的地址簿里**，并在启动时
用运维方看得懂的话说明这一点。对家用参与者而言这是**预期状态，不是降级**。

### 3. 持久化：**做**，且只存 dialable 条目

`data_dir/peers.dat`，版本 `0x01`，拒绝未知版本 / 拒绝尾随字节。

只写 dialable 条目。从未拨通过的候选跨重启一文不值，而存垃圾正是地址簿被无法使用的条目
填满的成因。种子无论如何都从配置回来，所以这个文件是缓存、从不是权威 —— 读不出来就记日志
忽略，绝不致命。

为什么要持久化：不做的话，每次重启节点都会塌回「只有种子是可拨通的」—— 而那恰恰是下面那个
NAT 重开触发器正在盯的状态。人为制造它会让这项测量说谎。

### 4. NAT 重开触发器是遥测行里的一个数

已记录决定的第 3 个条件要求：触发器**基于测量**触发，而不是基于谁还记得这个问题被推迟过。
stdout 的 `TELEMETRY` 行现在带：

    dialable=<可拨通数>/<已知数>

如果这个比值在 T1 期间塌向「只有种子可拨通」，那就是该建 NAT 穿透的信号。（`/v1/telemetry`
**wire 刻意没动** —— 往那里加字段是一次带版本的改动，本根棒没有理由做。如果运维希望通过
RPC 而不是日志拿到这个比值，那是一个小后续，并且应当带上版本号变更。）

### 5. 删除 `PeerTable::addr_book` / `remember_addr`

它们记录的是「每一个完成过握手的对端」—— 也就是 S2 明令禁止服务的那个「仅连接」集合。
留着就是第二本账，哪天有人从它服务出去，S2 就被静默违反了。

## 上限 —— 全部 `[devnet-placeholder]`、testnet 可调、**未冻结**

它们与 auto-connect 同一个 PR 落地（S3）：没有上限的 auto-connect，是这个功能自己引入的
资源耗尽漏洞。

| 常量 | 值 | 约束什么 |
|---|---|---|
| `MAX_OUTBOUND` | 8 | 我方主动建立的同时连接数 |
| `MAX_INBOUND` | 32 | 接受的同时连接数（**在 accept 处执行**） |
| `MAX_ADDR_BOOK` | 1024 | 地址簿条目数 |
| `MAX_ADDRS_PER_MSG` | 100 | 单条 `Addr` 里接受/服务的地址数 |
| `GETADDR_INTERVAL_MS` | 60 000 | 对*同一个*对端两次索要之间的最小间隔 |
| `DIAL_RETRY_INTERVAL_MS` | 5 000 | 维护轮次节奏（原 `REDIAL_INTERVAL`） |
| `DIAL_BACKOFF_START_MS` / `_MAX_MS` | 1 000 / 30 000 | 单地址失败退避（自 S9 搬来） |

淘汰永远不碰种子（S4），也不碰 dialable 条目；地址簿被这两类填满时，拒绝新候选，而不是
丢掉值得留的东西。

## 学来的地址**不可以**做什么（S6）

对端给的地址只是一个可以去试的候选，仅此而已。它永远不是打分输入：如果一个无效地址可以被
罚分，那任何对端都能通过点名让第三方挨罚。**帧**解不出来是另一回事 —— 那是发送方自己的
畸形消息，要罚。这与 `IngestOutcome::is_peer_fault` 为区块对象编码的是同一条规则
（#70 S5、#74）。

## 验收证据

| # | 要求 | 测试 |
|---|---|---|
| 1 | 只有一个种子的节点学会整张网并连上 | `node.rs::seed_only_node_learns_the_mesh_and_connects`（内存内）+ `run.rs::seed_only_node_learns_the_net_and_an_undialable_one_is_never_gossiped`（**真 TCP**） |
| 2 | 不可拨通的节点永不被 gossip，双向 | 同一个 TCP 测试（它确实连着 B，而 B 的地址簿严格等于 `[C]`）+ `node.rs::a_node_that_is_not_dialable_is_never_gossiped` |
| 3 | 上限生效；入站洪泛被拒绝而非吸收 | `transport.rs::tcp_inbound_cap_refuses_a_flood_rather_than_absorbing_it`、`node.rs::auto_connect_stops_at_the_outbound_cap` |
| 4 | 学到的地址跨重启存活 | `run.rs::the_address_book_survives_a_restart`（重启时种子列表**为空**）+ `a_corrupt_address_book_is_ignored_at_startup` |
| 5 | 全量不过滤 workspace 套件 | 已在 #64 请求 —— 占机期间**未**由 builder 跑 |

## 诚实剩余项

- **限速是按对端的，不是全局的。** 八个对端可以各自每分钟被问一次；除了每条消息
  `MAX_ADDRS_PER_MSG`，没有对入站 `Addr` 总量的聚合上限。T1 规模下够用，真有对抗性负载时
  值得重看。
- **没有地址质量/尝试衰减评分。** 排序是种子优先、其次失败次数少的、再次插入顺序。
  Bitcoin 那种按网络组分桶不在这里，抗 eclipse 也不在 —— 那属于 peer hardening，M11 这条
  线的另一半。
- **`peers.dat` 在优雅关停时写**，不是周期写。`SIGKILL` 会丢掉本次启动后学到的内容；种子
  仍能把网络找回来。
- **`/v1/telemetry` wire 不带这个比值**（见决定 4）。
- **`qumbra-deploy/OPERATOR.md` 欠一行**关于四台 T0 主机的 `advertise_addr` —— 属于另一个
  仓库，coordinator / T-ops 决定。
