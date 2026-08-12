# `LOOP` 日志——在单台主机上读出主循环周期的劣化

[English](i107-loop-phase-journal.md)（技术细节以英文版为准）· issue [#107](https://github.com/qumbra-labs/qumbra-lab/issues/107) S1 · T1 Gate A / A3

`sample_interval` 是 30 s，而 `TELEMETRY` 的输出是主循环**末尾**的一次判断，所以 30 s 是两条遥测行之间间隔的**下界**，从来不是节拍：这一行要等循环下一次走到那里才出现。`t0-wan-1` 一直能压到这个下界（3,708 个样本，中位数 30.01 s）。此后的每个镜像，在四台主机的 53 个样本里**没有一个低于 131 s**。

围绕这个数字，先后有三种假设是从外部论证的——#87 的三次每轮调用、同步挖矿、注入时延——其中两种被测量推翻。原因是：唯一的仪器就是**那个间隔本身**，它只能说明循环慢了，完全说不出慢在哪一段。

本文说明如何读取取代这些争论的仪器。

## 两条行

两条都输出到 stdout，与 `TELEMETRY`、`ROUND` 并列（#87 的规则：容器日志才是被归档和引用的东西，而且与抓取端点不同，它不需要任何入站规则就能拿到）。两条都声明 `unit=ms`，并携带相同的字段尾部，所以一个 `awk` 可以同时解析两者。

### `LOOP kind=slow`——某一轮超过阈值

在该轮结束时**当场**输出，携带这一轮的完整分解。健康节点上保持沉默。每个遥测窗口最多 20 条，被抑制的条数计入窗口行。

```
LOOP kind=slow unit=ms ms=131195.0 phase=pump.dispatch phase_ms=131170.0 frames=6 ...
```

**`phase=` 就是这个 issue 一直缺的那个答案。** 它给出占主导的阶段；当该阶段是 pump 时，会继续下沉到 pump 自身的分解——是 `pump.dispatch`，不是 `pump`。

### `LOOP kind=window`——每条 `TELEMETRY` 配一条汇总

按遥测节拍输出，**始终输出**，紧挨着它所解释的那个样本。这一半对 #107 才是承重的：劣化样本是**持续**慢（最小 131 s、中位数 158–185 s，里面根本没有一个可供"尖峰"偏离的安静基线），只靠阈值的仪器在全部 53 个样本里都会保持沉默。

```
LOOP kind=window unit=ms win=30012.0 iters=1482 busy=2210.0 acct=30000.0 unacct=12.0 ...
```

## 字段说明

| 字段 | 含义 |
|---|---|
| `ms` / `busy` | 本轮 / 本窗口的工作时间。**不含空闲退避。** |
| `win` | 窗口实测墙钟时间 |
| `acct` | 同一窗口按各轮求和的结果（含退避） |
| `unacct` | `win − acct`——仪器的盲区。**见下；这是一个诊断字段，不是舍入说明。** |
| `iters` | 窗口内的循环轮数（空闲时约 50 次/秒） |
| `maxiter` / `maxphase` | 最差的单轮，及其主导阶段 |
| `slow` / `slowsup` | 已输出 / 被上限抑制的 slow 行数 |
| `frames` | pump 处理的帧数，含被限流丢弃的 |

**主循环阶段**（按执行顺序）：`pump` `journal` `mine` `boundary` `metrics` `discovery` `submit` `telemetry` `sample` `maintain` `snapshot` `hook`，然后是 `sleep`（20 ms 空闲退避，**不算工作**）。

**pump 内部子阶段**：`dials` `poll` `ratelimit` `decode` `dispatch` `sync`。

`send*` 是**叠加项，不是阶段**：它是 `Transport::send` 内部的时间，已经计入 `dispatch` 与 `sync`。**任何总和都不要再加上它。** 之所以单列，是因为 `TcpTransport::send` 在写的整个过程中持有 `writers` 互斥锁，并最多等待 `SEND_WRITE_TIMEOUT_MS`（100 ms）；一个慢对端把其余所有发送串行化，是 pump 路径上最后一个未被测量的阻塞调用——而这一项正是把"循环卡在 dispatch"和"循环卡在 socket 上"区分开的依据。

## 读一个劣化样本

```sh
grep 'LOOP kind=slow' node.log | sort -t= -k4 -rn | head
grep -o 'maxphase=[a-z.]*' node.log | sort | uniq -c | sort -rn
grep -E 'TELEMETRY|LOOP kind=window' node.log | tail -20
```

| `phase=` 的取值 | 含义 | 对既有记录的影响 |
|---|---|---|
| `pump.dispatch` 且 `send*` 数值相近 | socket 写阻塞了循环 | #289 的写超时被反复触发；是次数叠加，不是单次调用 |
| `pump.dispatch` 且 `send*` ≈ 0 | 共识 ingest/校验本身的开销 | 全新结论——本 issue 中没有任何假设预测过 |
| `pump.ratelimit` | #91 的逐帧计费 | **证实 7 月的排序**，而那一项从未被测量过 |
| `pump.poll` | 收件箱互斥锁 | transport 锁竞争假设成立 |
| `pump.dials` | 应用连接线程的完成结果 | #132 没有做干净 |
| `mine` | 同步 RandomX | 推翻 7 月"排除挖矿"的测量——必须大声说明 |
| `maintain` | 拨号轮次 | 属于 #83 的阶梯，不在 pump |
| `snapshot` | #359 的 fsync | 一项从未被计价的节拍开销 |
| `hook` | 同进程 faucet 的 STARK | 仅在 faucet 主机上属于预期 |

## `unacct`——盲区，以及它为什么是一个字段

阶段之间有三样东西：循环判断与读时钟（纳秒级）；`LOOP` 行自身的 `println!`（一个阶段无法为自己的报告计时）；以及**任何阻塞 stdout 的东西**。

第三项才是要盯的。`println!` 会拿 stdout 锁并写入管道；在 `docker logs` 或有限速的 journald 下，管道满会把**共识循环**阻塞到读取方跟上为止。本 issue 的全部历史中从未测量过这一点，而"阶段都很小、`unacct` 很大"正是它的样子。**窗口里 `unacct` 达到数十秒是一个发现，不是噪声**——那意味着循环周期是由日志消费者决定的。

## 上一台主机

改动只是新增日志：**不接触共识**（`finality.rs`、`recovery.rs`、`committee.rs` 零改动）；**wire 零变化**（不升 `RPC_VERSION`，无新 `MsgType`，无载荷改动，`TELEMETRY` 字段不动）；**不新增配置项、不新增线程**；**没有任何决策读取这些数值**（与 `RateStats`、`UnknownStats` 同一条规则）。

**日志量**：窗口行与 `TELEMETRY` 一一对应，约 2,880 条/天/主机。健康节点上 slow 行只在挖矿时出现，由 `mine_interval` 约束（约 1,150 条/天）；劣化节点上每 30 s 窗口至多 20 条（最坏约 57,600 条/天），超出部分只计数不打印。对端无法把节点刷爆。

**开销**：每轮 13 次读时钟，另加每帧 3 次，每次数十纳秒（vDSO 读取，无系统调用）——由 `ticktime::tests::instrumentation_costs_tens_of_nanoseconds_per_frame` 实测，一旦读时钟涨到微秒级该测试即失败。

## 它回答不了什么

它只说明**哪个**阶段慢，不说明**为什么**慢。它看不到内核里其他线程（读线程、连接线程）上的时间；也无法把 `poll` 的开销区分为"收件箱很大"还是"锁被占用"——那需要结合同一行的 `frames`，而不是只看 `poll`。

并且它**从未在 WAN 主机上运行过**。本文示例中的每个数字，要么来自本 issue 自己的归档，要么来自笔记本上的定向测试。
