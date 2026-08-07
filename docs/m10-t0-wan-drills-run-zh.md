# M10 Phase B-WAN —— 四个场景演练,运行于 2026-08-07(范围:**WAN**)

> [English](m10-t0-wan-drills-run.md)

**R1:本文是证据,不是判定。** 它记录四个演练在活的 T0 网上产生了什么——读数、时间戳,
以及与计划不同的地方。它不含 PASS,不把任何一次运行总结为成功,也不对它所报告的
findings 作裁定。那些属于 coordinator。

这四个演练是 M10 Phase B-WAN 欠下的最后一项。≥48 h 连续性 soak 已于 2026-07-28 封存
(PR #93);这四个场景被压着,等的是九天里攒齐的两年份前置条件——线上的 `fid`(#84)、
状态机 lag 读数(#130 a)、冷启动挖矿门(#106 第 1 项)、持久头(#212),最后是演练仪器
本身(#241 类型化拒绝原因、#226 按变体的 `have=`),它们在本次运行的前一天上到车队。

---

## 1. 出处

| | |
|---|---|
| 网 | T0-WAN,创世 `138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb`,格式 v4 |
| 主机 | 4 × AWS `t4g.small`(Graviton/arm64,Debian 12):node0 us-east-1(6 把密钥)· node1 eu-west-1(5)· node2 ap-southeast-1(5)· node3 ap-northeast-1(5)。委员会 21 把密钥,quorum 15 |
| 镜像 | `ghcr.io/qumbra-labs/qumbra-node@sha256:988c9f5d…a988` = `t0-wan-13`,revision `1d7fabbd…`,每台主机均读回 revision 标签 |
| 滚动 | 2026-08-06 10:21–11:04 +08,按修正后的每台门一次一台(`qumbra-deploy/tasks/roll-t0-wan-13-2026-08-06.md`) |
| 入场门 | 六项检查,2026-08-07 13:25 +08 达成——证据 `qumbra-ops/drills-138e1524/gate/` |
| R3 | 2026-08-06 07:31 +08 为全部四个演练授予;2026-08-06 20:25 +08 扩展,以覆盖 D4 的 dead-man 自愈 |
| 原始证据 | `qumbra-ops/drills-138e1524/{gate,d1,d2,d3,d4}/`——每个演练:`before/`、`during/`、`after/`、`FINDINGS.md` |
| 时钟 | 主机 UTC,操作者机器 +0800。下文每个时间戳都带其时区 |

**入场门的实测值。** 自滚动起 26 h 19 m 的采样(277 个样本),五次 `schain=fork` 出现,
**每次都在该主机的下一个采样上消解**(无一持续,这正是门槛的措辞),零条 STOP 类字符串,
四台自滚动起 `restarts=0`,`fid` 一致。两段观测缺口——1 h 17 m 与 40 m,成因都是操作者的
笔记本在路途中合盖休眠——已**从主记录**(容器日志)**补齐**,且两段都干净:
`qumbra-ops/recovered-gap-0806/`、`recovered-gap-0807am/`。
`caffeinate -i` 约束的是闲置休眠,并不能阻止合盖;这一条现已写进 run book,而不是继续
指望它不发生。

---

## 2. D1 —— 挖矿节点重启(node2)

**做了什么。** 日志环已归档;`docker compose stop`(优雅,`stop_grace_period: 30s`);
`docker compose start`;观察到 `mready=synced`。

```
13:26:14  before: all four tip=3157 final=3152 fid=e153e4ff0d08 slag=0 restarts=0
13:26:30  stop issued
13:27:01  container FinishedAt — exitcode=137 (128+9 = SIGKILL): the 30 s grace expired
13:27:45  start; container running
          ... 15 m 31 s of ZERO log output at CPU 100.38%, RSS 11.86 MiB ...
13:43:16  RECOVERY restored snapshot at height 1868, replayed 1987 records, resumed at tip 3157
          CPU → 4.98%, RSS → 270 MiB
13:47:58  node2 rejoined: tip=3172 final=3168 fid=3fb176af7bb8 slag=0 mready=synced
```

**这产生了三件事。**

1. **优雅停止没有 flush。** 没有关闭输出;`snapshot.bin` 与 `peers.dat` 仍带着容器启动时
   的 mtime。提交为 lab #286——并在 **46 分钟后被 D2 更正**(见 §3):flush 是间歇的,
   不是缺失。
2. **`replayed 1987 records`——本项目有史以来第一次观测到非零的 `blocks.log` 回放。**
   这是 lab #104 的关闭条件,已记录在该 issue 上。它之所以发生*正是因为* flush 失败了:
   磁盘上的快照停在高度 1868,陈旧了 26 h。
3. **一段 15 分钟、什么都不打印的回放,与卡死无法区分。** 提交为 lab #287。第 12 分钟那次
   操作者读数把首要假设记为 #106 第 (2) 项那个未解释的卡死,并论证 RSS 11.86 MiB 排除了
   回放;**那个推断是错的**——回放跑在 RandomX cache 加载之前,而仅有 coinbase 的状态
   几乎不推动 RSS。run book 在那种情形下的指示("不要重启,它可能自行消解")才是保住这次
   观测的原因。

**D1 期间的网**,node2 的 5 把密钥缺席(余 16 ≥ quorum 15):node0/1/3 处于
tip=3168-3169,`final` 从 3160 → 3168 推进,`fid` 一致,`slag=0`,`peers=4`。

---

## 3. D2 —— 迟到者同步(node3)

没有第五台主机,所以这里的"迟到者"是一个错过了一段链、必须从 peer 追上来的成员。

```
14:12:36  stop issued
14:12:38  exitcode=0 in 2 s — "shutdown complete (snapshot flushed)"
          snapshot.bin 225181 B and peers.dat both mtime 06:12Z — the flush RAN
          ... down 60 m 39 s (planned 45; the window simply ran longer — recorded, not rounded) ...
15:13:42  start
15:13:46  RECOVERY restored snapshot at height 3189, replayed 0 records, resumed at tip 3189   (4 s)
15:14:21  tip=3233 final=3216 peers=6 fid=016085340d11 slag=0 mready=synced rounds=2
          => 44 blocks of catch-up from peers in under 39 s, votes re-entered
15:14:38  all four: tip=3233 final=3216 fid=016085340d11 stip=3233 slag=0 peers=6
```

**node3 停机的那一小时里**,另外三台持续 finalize:`final` 3184 → 3192 → 3200 → 3208 →
3216,`fid` 每一步都在变,`slag=0`,`peers=4`。**一个 5 密钥成员的缺席不会让 finality
停下**——6/5/5/5 拓扑的 quorum 主张,已被测量。

**这一对演练计划外产生的 A/B 对照:**

| | D1 node2 | D2 node3 |
|---|---|---|
| 关闭 | 卡死,30 s 时 SIGKILL,无 flush | 干净,2 s 内 exit 0,已 flush |
| 磁盘上的快照 | 陈旧 26 h(高度 1868) | 新鲜(高度 3189) |
| 重启 → RECOVERY | **15 m 31 s**,静默,100 % CPU | **4 s** |
| 回放的记录数 | **1987** | **0** |

同一镜像、同一 compose、同样的密钥数,相隔 46 分钟。lab #286 据这份证据改题:关闭时的
flush 是**间歇的**。D1–D3 共执行了四次停止;**其中一次卡死**(node2)。一个值得检验而非
假定的假设——SIGTERM 到达时 node2 正在挖矿,而一次 nonce 预算很大的挖矿尝试,正是"某段
代码不观察关闭标志"的明显候选——已作为假设而非成因记录在 #286 上。

---

## 4. D3 —— 委员会停滞 → 恢复(停掉 node1 + node3)

停掉 node1+node3 移除 10 把密钥;余 11 把,低于 quorum 15,而网在其他方面完全连通。

**停滞之前先把 quorum 算术钉死**,因为这里最容易出现一个假的 R2:

```
07:17:11.84Z  node1 stopped (5 keys leave; 16 remain)
07:17:13.88Z  ROUND slot=3232 why=finalized have=16 need=15 absent=11,12,13,14,15 variants=1
              => finalized on a REAL quorum of 16, two seconds after node1 left
07:18:27.24Z  node3 stopped (11 remain — below quorum). Everything after this is the drill.
```

**停滞,23.5 分钟:**

```
15:19  tip=3238 final=3232 stall=6  regime=Final
15:31  tip=3245 final=3232 stall=13 regime=Final
15:37  tip=3249 final=3232 stall=17 regime=Degraded
15:40  tip=3251 final=3232 stall=19 regime=Degraded
```

`final` 冻结在 3232,而 `tip` 从 3238 推进到 3251——两台存活主机继续挖矿,什么都没
finalize。说明原因的那条 round,相隔十一分钟打印两次,内容不变:

```
ROUND slot=3240 why=open close=open have=11 need=15 active=21 roster=21
      voted=0,1,2,3,4,5,11,12,13,14,15   absent=6,7,8,9,10,16,17,18,19,20
```

`have=11` 恰好是 node0 的 6 加 node2 的 5;十个缺席索引恰好是被停主机的密钥。这是
**#87 的"票不够 vs 超时"判别器的首次实弹出场**,并通过 **#226 更正后的 `have=`** 读取
——这个数指的是单变体票数,所以"15 中的 11"没有歧义。在 #226 之前的仪器下,同一条 round
打印的是跨变体总数;那份歧义在 2026-08-02 花掉了五个小时。

**自愈:**

```
07:43:41Z  node3 start → 07:43:47Z  RECOVERY … replayed 0 records   (6 s)
07:44:53Z  node1 start → 07:45:00Z  RECOVERY … replayed 0 records   (7 s)
07:47:15Z  ROUND slot=3240 why=finalized have=16 need=15  quorum_ms=1576455  (26 m 16 s open)
07:47:15Z  ROUND slot=3248 why=finalized have=16 need=15  quorum_ms=646021   (10 m 46 s)
07:48:38Z  ROUND slot=3256 why=finalized have=16 need=15  quorum_ms=156332   ( 2 m 36 s)
```

**Finality 按顺序把整段停滞跨度补完,而不是跳过它。** 每条 round 的 `quorum_ms` 是它自己
的年龄。没有任何东西被烧掉:存活的 11 把投出的票留在计票里,回归的 10 把按顺序补齐了每一
条 round——与 §5 的对比正是重点,与 2026-08-05 事故的对比也是,那一晚每一把密钥都已经
承诺到了某个变体上。

---

## 5. D4 —— 2+2 分区 → 愈合

切分 **A = {node0, node2}**(11 把密钥)| **B = {node1, node3}**(10 把密钥),即定版拓扑;
每一侧各跨越两条最长链路之一。两侧按设计都低于 quorum。切断只施加在 A 侧,端口 9444
双向。**Dead-man 自愈与切断在同一次粘贴中,在两台 A 主机上布防**(2400 s),依 run book
2026-08-06 的修正。

```
16:00:37/40  cut applied; rules verified in place on both A hosts
16:01:07/08  dead-man armed
16:32:26     deepest divergence: node2(A) tip=3289 stipid=fd4134ebd4ed
                                 node1(B) tip=3289 stipid=66df395898cc
                                 final=3264 frozen on all four, regime=Degraded, stall=25
16:32:53/57  cut removed (0 rules remain); dead-man cancelled WITHOUT firing
16:47:20     FINALITY RESUMED: final 3264 → 3296
16:52:06     node2 DIALs node1, REWINDs, adopts the winning branch
16:53:50     all four: tip=3304-3305 final=3296 fid=b9869e62fcbd regime=Final slag=0
```

**三条 findings。**

1. 🔴 **`peers=` 与 `dialable=` 看不见静默分区。** 切断开始十四分钟后,每台主机仍然打印
   `peers=6 dialable=3/3`——恰恰是 run book 让操作者用来确认切断的那个读数。
   `iptables -j DROP` 是静默的,所以 TCP 连接保持 `ESTABLISHED`,每条发送队列里卡着约
   55 KB;节点数的是 socket。**真正看见了它的读数**是等高度上的 `stipid` 分歧,以及冻结
   的 `final` 配上不断攀升的 `stall`。run book 的验证步骤已在 `qumbra-deploy` 中更正。
2. **分区每跨过一个 cadence 就烧掉一个检查点 slot。** Finality 以 3264 → 3296 的跳跃
   恢复,越过了 3272/3280/3288——分裂期间每一侧的密钥都签了自己那一侧的变体。观测到的
   round:`slot=3272 have=11 voted=0,1,2,3,4,5,11,12,13,14,15`(A 侧的十一把),随后
   `slot=3280 have=5 voted=11,12,13,14,15`(只剩 node2,node0 此时已经转到了获胜分支)。
   这就是 #269 的机制,此处是刻意造出来的。
3. 🔴 **网络恢复完整之后,一台主机在失败分支上停留了约 20 分钟,而它自己 telemetry 行上
   的每一个字段都报告健康**——`tip=3291 stip=3291 slag=0
   mready=synced peers=6 dialable=3/3 bask=0@3291 unk=0/0`。通往 node1 的那条卡住的 socket 持续保持
   `ESTABLISHED`,发送队列里有 191,846 字节;节点把它算作一个活着的 peer,因此从不重拨。
   收敛来自一次内核超时,而不是节点的决定:socket 在 16:51:32 清除,DIAL 与 REWIND 随之
   发生在 16:52:06。只有**跨主机的 `fid` 比对**把它暴露出来。提交为 lab #289。

**Dead-man 的结果,作为证据记录:**未触发即取消——`/tmp/qumbra-deadman.log` 在两台主机
上都是 0 字节,布防时创建,从未被写入。给重复此步骤者的提示:**只杀 `sleep` 会触发它,
而不是取消它**,因为那样 `sh` 会立刻执行自愈主体;必须杀掉父进程,而空日志就是干净取消的
证明。

---

## 6. 诚实的余项

- **任何演练中都没有发生 R2 STOP-POINT。** `final` 从未回退,从未在没有 quorum 的情况下
  推进,没有两个检查点在同一高度被 finalize,也没有主机分歧到一个已 finalize 检查点的
  *前方*(node2 在 D4 的分歧落在 3264 这个已 finalize 头的后面)。
- **D2 实际跑了 60 m 39 s,而计划是 45 m**;操作者没有在计划时刻发出重启。如实记录而非
  取整;这使追赶距离变成 44 个块。
- **D1 的静默窗口在运行中被读错了**,误读连同其更正一起保留在 `d1/FINDINGS.md` 中。第 12
  分钟时可得的证据确实无法区分回放与卡死——这就是 #287,不是事后诸葛。
- **D4 的未收敛最初被记为"搁浅,机制未明"**,8 分钟后主机自愈时作了更正。两份文本都留在
  `d4/FINDINGS.md` 中。
- **追赶曲线没有分辨出来。** D2 的 node3 在启动后 39 s 的第一个读数上就已经是
  `mready=synced slag=0`;3189 到 3233 之间的形状未被测量。D4 的收敛同理。
- **after 状态里的 CPU 读数是单次 `docker stats --no-stream` 采样**,什么也测不出来;
  挖矿是突发的,没有任何演练对它做过仪表。在此注明,以免有人从中读出 finding。
- **没有擦除任何东西,也没有在演练步骤之外重启任何主机。** node2 在 D4 的分歧一直没被碰,
  直到它自行消解;run book 的擦除恢复路径从未被调用,仍是一条未经演练的流程。
- **`stop_grace_period` 没有做变量。** 30 s 究竟只是对这个链长度下的 flush 太短,还是关闭
  路径彻底卡死,这些演练没有解决(#286)。

## 7. 本次运行提交的 issue

| | |
|---|---|
| [#286](https://github.com/qumbra-labs/qumbra-lab/issues/286) | 关闭时的 flush 是间歇的——四次停止里卡死一次;在 grace 边界上 SIGKILL 留下一个陈旧快照 |
| [#287](https://github.com/qumbra-labs/qumbra-lab/issues/287) | 15 分钟的 `blocks.log` 回放什么都不打印,与卡死无法区分 |
| [#289](https://github.com/qumbra-labs/qumbra-lab/issues/289) | 分区愈合之后,卡住的 socket 让节点约 20 分钟不再重拨,而 telemetry 报告健康 |
| [#104](https://github.com/qumbra-labs/qumbra-lab/issues/104) | 关闭条件达成——首次 `replayed N>0` 观测,已记录在该 issue 上 |
