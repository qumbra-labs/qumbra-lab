# Open issue 分诊，2026-08-03 —— 这个仓库的 issue 怎么变馊，以及它变馊的四种方式

**快照钉在 `main` @ `d16ffd5`。** 下面每一条状态都是在那个 revision 上读的，**任何东西一合并就开始衰减。** 状态表是这份文档里易腐的那一半；**§1 的四种失效类别是值得留下来的那一半。**

由一根只读审计棒（Multica QUM-70，Doc Auditor）对 15 个未在处理中的 open issue 逐个核出，外加一根估价棒（QUM-71，T-build-codex）—— 后者按自己的停止规则停了。原始输出在 [`issue #64`](https://github.com/qumbra-labs/qumbra-lab/issues/64) 和 [`issue #133`](https://github.com/qumbra-labs/qumbra-lab/issues/133)。

**没有关闭任何 issue，没有修改任何文件。这份文档不构成关闭授权** —— 它是关闭时要依据的证据。

---

## 1. issue 变馊的四种方式

一个 issue 是**对某一刻代码的一句断言**。这个仓库走得够快，断言和代码会分开，而且不止一种分法 —— **四种里只有一种是"有人修好了"。** 分辨它们就是分诊的全部内容。

### 1.1 `MOVED` —— 洞还在，只是没人走进去了

**最危险的一类，因为两半读起来都是真的。** 被引用的缺陷仍然原样在那一行；**走到它的那条路径搬走了。**

**`#169` 是标本。** 原文：*"`restore_from_snapshot` 把终局头丢了：每次保存都写，从来不读。"*

```rust
// node.rs:965-975 —— 今天 main 上的整个函数
fn restore_from_snapshot(&mut self, snap: &Snapshot) {
    for cm in &snap.commitments { self.commitments.append(*cm); }
    self.commitments_ordered = snap.commitments.clone();
    for nf in &snap.nullifiers { self.nullifiers.insert(*nf); }
    self.nullifiers_ordered = snap.nullifiers.clone();
    self.roots_by_height = snap.roots_by_height.iter().copied().collect();
}
```

`snap.finalized` 确实还是不读。**而 issue 已经不成立了** —— 因为这个函数**只有一个调用者** `resume_from_snapshot`，它在 76 行之后自己恢复了终局性：

```rust
// node.rs:693-703
if let Some((hash, height)) = snap.finalized {
    node.chain.restore_finalized(hash, height).map_err(NodeError::SnapshotFinality)?;
    if !records.iter().any(|rec| matches!(rec, LogRecord::Finalize(logged) if *logged == hash)) {
        return Err(NodeError::SnapshotFinalityNotLogged { hash, height });
    }
}
```

`git blame` 说清了剩下的：**修复本来落在调用者里（PR #171，`8ba0a07`），随后被 `#162` 的 rewind 重构挪走了**（PR #178，`d4f5e5f`）。没有人挪错，是后来的重构搬走了修复所在的那段代码。

> 🔴 **照着 issue 文本干活的 agent，会去补一个已经不在恢复路径上的私有函数** —— 一个过评审、过测试、什么也没修的改动。

**`MOVED` 不等于可关。** 正确动作是改 body，因为下一次重构可能给那个 helper 加上第二个调用者。

### 1.2 `PARTLY FIXED` —— 标题是假的，issue 不是

**`#133` 是尖锐的那个**，而且是花了一根派出去的棒才发现的。

标题：*"委员会惩罚是易失的 —— 重启会悄悄把被墓碑标记的作恶者恢复成 Active、带满额保证金。"* **在 `main` 上是假的。** `crates/qlab-p2p/src/punish.rs` 存在；`punishments.dat` 在 epoch 推进之前由 `NodeAdapter::open` 重放（PR #159，`a805488`）；`prest=<restored>/<known>` 已在 `TELEMETRY` 上（PR #192，`61b599f`）。三个测试跑的正是那条重启路径 —— 墓碑、10% 罚没、降额保证金、法定人数排除，**四样全都活下来了**。

而这个 issue 仍然该开着，因为**没修的那一半正是标题没提的那一半**：

```
a_non_witness_finalizes_a_checkpoint_the_restarted_witness_refuses   (adapter.rs:3788)
  委员会 7 / 法定 5，五票 {0,1,2,3,4}
  见证方   排除被墓碑的 3 → 4 < 5 → 拒绝
  未见证方 数满 5              → 终局
  重启见证方是"保住"分歧，不是弥合它
```

**一个从没见过那次作恶 gossip 的节点，永远学不到这个惩罚** —— 而证据是 push-once、没有 `InvKind`，所以它连问都问不了。这就是 `#133` 自己写的 *"there is no way to learn it again"*，而唯一能闭合它的构造 —— **证据进块** —— 是一个**共乘 T1 铸造的 payload 变更**，落在和 [`#232`](https://github.com/qumbra-labs/qumbra-lab/issues/232) 同一条 preimage 缝上。

> **教训不是"记得看标题"。** 是**一次部分修复会悄悄把 issue 重新瞄准，而标题不会跟着动。**

### 1.3 `FALSE AT FILING` —— 前提从一开始就不成立

**一个确认实例，而且它是从一个"存在的仪表的不存在"上论证的。**

**`#223`** 说 `qumbra-opview` 跨机器比 `fid` 但**不比** `sid`。opview **从第一个 commit 起就在比 `sid`** —— `7c7c33d`，PR #119，**2026-07-30**，比这个 issue 早三天：

| | |
|---|---|
| `agree.rs:70` | `SignedVerdict::VariantSplit` —— *"两个节点在同一 slot 上签了不同变体"* |
| `agree.rs:132` | `pub signed_verdict: SignedVerdict`，和 `fid` 那组字段并列 |
| `agree.rs:201-207` | `signed.iter().any(\|g\| g.is_split())`，**每次轮询都算** |
| `render.rs:231` | `"\nsigned variant (sslot/sid): {shead}\n"` |

`#223` 描述的那两次锁定 —— slot 2064 和 slot 2072，一台在共享 slot 上持不同 `sid` —— **正好就是 `VariantSplit`。** opview 会直接点名，不需要手工 diff；而 issue 给出的"看不见"的理由（*"一个没人例行去做的手工动作"*）描述的是一个本来就不必要的手工动作。

**这不否定这个 issue。** 它真正的诉求 —— **统计每个 slot 实际可用的钥匙余量** —— 完全没有仪表；而且有一条它本可以论证的真残余：**遥测只带最新的 `sslot`/`sid`，所以一次锁定只有在轮询正好落进那个窗口时才看得见。** 那是真缺口；*"它不比 `sid`"* 不是。

### 1.4 `WRONG IN THE DETAIL` —— 机制对，数字错

最便宜的一类，而每一条都会把修复带偏。

**`#226`** —— 机制核实无误：`have()` 就是 `self.voted.len()`（`round.rs:413-415`），总票数，印在一个单变体的 `need` 旁边。**位置的说法是错的**：`variants` 不是*"倒数第三个字段"* —— 那条线有 22 个字段，它是**第 13 个、倒数第 10**（`round.rs:496-530`）。issue 的摘录和 `docs/incident-2026-08-02-t0-wan-7-roll.md:66` 都是删节过的。

> **这让缺陷比描述的更糟，而不是更轻** —— 但一个照着*"往前挪三格"*去做的修复，瞄的是一条不存在的线。而且字段顺序是**测试锁死的**（`round.rs:1256-1267`，*"existing ROUND fields must not move or be renamed"*），所以"重排"那条路径撞的是一个常驻测试。

**`#78`** —— body 里估 `check_constraints` 0.2 秒 ⇒ class-(2) 全扫 12 分钟。PR #144 那根棒实测：**2.27–2.32 秒 ⇒ ~2.3 小时，低了 11 倍。** 已在讨论串里更正，**body 里仍是错的 —— 而排期的人读的正是 body。**

---

## 2. 快照 —— 易腐，钉在 `d16ffd5`

**没有一条适合直接关闭。**

| # | 状态 | 残余 |
|---|---|---|
| `#169` | **MOVED** | 洞在 `node.rs:965-975`，没人走到。改 body，别关。 |
| `#203` | **代码已修，生产未读** | 根因已改挂到 `#204`/`#205`，两个都被 PR #207 关掉。唯一一次生产 `dfin=` 读数是健康的、单台、**不是重启** —— 而 `#203` 记的正是一次重启。 |
| `#106` | PARTLY FIXED | 第 (1) 项已合（PR #153）。(2) 那次 53 分 49 秒的卡死、(3) `variants` 关联，都没动 —— **两条要的是证据不是 builder。** 三条引用全部搬家。 |
| `#133` | PARTLY FIXED | 见 §1.2。D1（证据进块）未建。 |
| `#188` | PARTLY FIXED | 1/4、2/4、3/4 已落（PR #193、#202、#214）。4/4 已裁定，**现在卡在 `#219`** —— 而 body 里没写这件事。 |
| `#215` | PARTLY FIXED | (ii) 已合（PR #216）。(i) 未建，挂在 `#219` 后面。**body 里每一条引用仍然准确**，包括 `narrow.rs:170-172` 的 "all witness"。 |
| `#78` | PARTLY FIXED | 发现 1 和 3 已修，2 和 4 开着并有常驻 SAT 见证。**这个 issue 当初就是为了拿到的那个 class-(2) 扫描，并不存在** —— `m4gate.rs:2689` 只是一句指向它的注释。 |
| `#107` | STILL OPEN | 修复已合（PR #132）且在。关闭需要**这个仓库里根本不存在的一次 WAN 读数**。对四份滚后日志跑一次 `grep DIAL` 就能定。 |
| `#112` | STILL OPEN | coordinator 收窄后的诉求（两个 inbox 锁计数器）不在 `main` 上。`transport.rs:118` 仍是裸 `Mutex`。**属于按时而非迟到**：它归给铸新网的那个镜像。 |
| `#213` | STILL OPEN | `VoteTally::on_finalized` 仍然删掉 slot（`tally.rs:158-161`）。PR #207 加了取、没加存，跟 issue 写的一模一样。 |
| `#220` | STILL OPEN | `ROLE_NF`/`ROLE_MERKLE` 仍无域分隔位。**预算算术核实**：0…13 已用，正好剩两个。 |
| `#223` | STILL OPEN | 见 §1.3。余量确实没人统计。 |
| `#224` | STILL OPEN | `deploy/docker/Dockerfile` 里没有 `LABEL`；`GIT_REVISION` 全仓找不到。 |
| `#226` | STILL OPEN | 见 §1.4。 |
| `#235` | STILL OPEN | 未开工；它那张"已经存在"的表逐行核实无误。 |

---

## 3. 这次审计明确没做的事

记下来，因为**说明白的缺口比抹平的缺口值钱。**

- **什么都没执行。** 没跑 `cargo test`、没跑 bench、没跑 `check_constraints`。所以 `#78` 的结论是"哪些测试常驻、它们断言什么"，**不是"它们现在通过"**。
- **没碰任何主机。** `#107` 的关闭条件、`#203` 的重启读数、`#223` 的锁定频率、`#133` 的活体行为，**四条都要四台 T0 上的读数，一条都没取。**
- **`qumbra-deploy` 不在范围内**，所以 `#224` 引用的另一半在这里无法核实 —— 它引的那段构建配方不在本仓库。
- 🔴 **`#188` 4/4 和 `#215` (i) 现在都卡在 `#219` 上，而 `#219` 在跳过名单里** —— 也就是说**这一轮里最大的两项，依赖一个今天没人分诊的 issue。**

---

## 4. 这份文档为什么存在

因为它描述的那种失败，在它被写下来之前的一小时里已经发生了两次。

**一根估价棒（QUM-71）被派去打 `#133`，五分钟后按自己的停止规则停了** —— 任务书的前提是馊的，它要估价的那个"复活"根本不复现，而正确动作是报告并停下，而不是对着一个已经修了一半的缺陷去估三条路。**那根棒花在了打听一件分诊本可以免费告诉我们的事上。**

**而 coordinator 为了论证该做分诊、随手核了一个 issue，把 `#169` 的分类说错了** —— 说成"已修"，实际是 `MOVED`。洞还在。**动作的结论对，状态的用词错 —— 而用词才是会驱动一次关闭的那部分。**

> **不做分诊的代价不是困惑，是派出去的活打在了不存在的缺陷上。**

**建议频次：** 任何一波改动了**恢复、终局性、遥测或 AIR** 之后重跑一遍 —— 这一轮里每一条搬过家的引用，都出在这四个区域。
