# Builder prompt — issue #101：让挖出来的币可以花

## 你的任务书

https://github.com/lai3d/qumbra-lab/issues/101

**读 issue 正文，再读 coordinator 的两条评论**：一条是任务书（尺寸和依赖），一条是三条 STOP-POINT 裁定。**三条裁定是前置条件，不是建议**——它们已经裁完了，你不需要等，但如果你认为其中哪条错了，**在动手之前**发在 issue 上。第 2 条（`rseed`）是设计文档没写、由我们自己定的，**它最可能是错的**。

## 先说这根棒是什么，因为标题会误导你

issue 标题读起来像"忘了往树里 append 一片叶子"。**不是。**

`coinbase_note_commitment` 是 `keccak256(b"qumbra:devnet:coinbase-note:v1" ‖ height ‖ total)`；真 note 承诺是 `note_commitment(value, rkm, rho, rseed)`——`H(value ‖ rkm ‖ rho ‖ rseed)`，Keccak-f 按电路 lane 打包，**没有域字符串**（`crates/qlab-note/src/note.rs:34`）。两个是不同的函数、不同的输入。

**把旧承诺 append 进树，进去的是一个 2×2 电路打不开的对象。叶子有了，still unspendable。**

所以这是三个改动：

```
1. BlockBody 加矿工收款字段     ← 块格式改动
2. 于是 BlockBody::commitment() 变 → 它绑进 header 的 tx_body_commitment
                                     (#79 刚加的绑定) → 线格式改动
3. 铸真 note、append 叶子        ← issue 要的这条,三者里最小
```

## 🔴 最红的一条：没有测试会因为你的改动而失败

我核过了。**`BlockBody::commitment()` 没有 golden vector 锁着。**

- `wire.rs:280` 的 `golden_header_bytes` 锁的是 **P2P 信封头**，不是块体；
- `body.rs:238` 只断言 `commitment() == commitment()`——**确定性，不是固定值**。

所以你改完 `BlockBody`，整个套件会安安静静地全绿，而你**已经破坏了和旧格式节点的兼容性**。

> **绿色套件不是兼容性的证据。这里它什么都不是。**

**你要补上这个缺口**：为 `BlockBody::commitment()` 加一条 golden 十六进制向量，并在 PR 里明说这个值是这次改动**故意**改掉的。下一个改块体的人应该看到一个失败的测试，而不是像你一样什么都看不到。

## 设计已经答了，不要重新设计

我本来以为这里有个隐私岔路要裁——公开可导出的 note opening 会让每个 coinbase 被全网识别。**设计文档两处都已定死，方向相反：**

> `qumbra-design/tokenomics-and-issuance.md:116` —— *"coinbase note **在创建时携带公开价值**，经成熟延迟后作为普通 note 进入池子……**一跳透明，然后消失**。"*
>
> `qumbra-design/transaction-model-and-anonymity-set.md:61` —— *"coinbase 类发行则用**交易位置派生** ρ。"*

**公开可导出不是要避免的泄漏，它就是供应量审计锚点**（`performance-budget` §9 整套挂在上面）。隐私在**花进池子时**才到来，不在创建时。

**照这两段写的做。** 如果你认为它们按字面实现不了（比如算 commitment 的时刻拿不到 `rkm`），**那是发现，在动手前报，不是做完再说。**

## 三条已裁定的（理由见 issue，这里只给结论）

1. 收款字段装 **raw `rkm: [u64; 4]`**，不装地址类型。
2. `rseed = H(新域 ‖ height ‖ rkm)`，确定性。**新域字符串——不许复用 `qumbra:devnet:coinbase-note:v1`。**
3. **删掉** `coinbase_note_commitment`（不是弃用）；`record_coinbase_note` 只留成熟度记账，并在 PR 里说清它还剩哪些调用方。

## 三条钉死项

1. **不要部署。** T0 内网四台在 `t0-wan-2` 跑着。块格式改动**不能**靠逐台换二进制滚上去——那要走 #74 的 halt-height 升级机制（PR #76 实现了，**从没演练过**）。**部署是另一件事，不归这根棒。** 你在本地新链上建和测。
2. **不碰 `qumbra-design`。** 裁定 1 和 2 是共识规则，该进 `transaction-model-and-anonymity-set.md` + `-zh`——**由 coordinator 在你的 PR 合并后落地**，理由是"先验证再提交"：万一规则实现不了，今天写进去的设计文档就会以权威口吻错一次。你若认为措辞该怎么写，写进 PR 正文。
3. **[#102](https://github.com/lai3d/qumbra-lab/issues/102) 不在范围内。** `submit_tx` 里那个硬编码的 `vec![]` 今天是够不着的接缝；**你这根棒落地之后它会变成活的正确性漏洞**——那是紧接着的下一根棒，不是这一根。看见了就报，别顺手修。

## 不要部署

再说一遍，因为这是本项目最贵的那类错误：**四台 VPS 正在跑一次活的共识实验，任何人不得因为一根棒方便就动它们。**

## 工作纪律(全部强制)

1. **独立 worktree**:

   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-i101-build -b claude/i101-coinbase-note

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **重活要问,而且现在尤其要问。** 定向测试随便跑(`-p qlab-devnet`、`-p qlab-node`);**全量 `cargo test --release --workspace` 开跑前必须先在 issue 上问**——coordinator 可能正在跑另一根棒的验收套件,并发两个 release 套件会 OOM(m4gate 峰值约 20 GB,36 GiB 机器)。**一律加 `--test-threads=1`。** rig 状态见 issue #64 的最新评论。

4. **分阶段提交。** 本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作。**

5. **停车点。** 你已经在一个 STOP-POINT 上了(共识状态改动),三条裁定就是放行条件。**如果做下去发现还需要第四个共识层决定,停下报告,不要先做了再说。**

## 验收

- **一个测试:挖一个块 → 等满 `COINBASE_MATURITY_BLOCKS` → 用真 2×2 证明把这个 coinbase note 花掉,并由 `qumbra_node::verifier::ConsensusVerifier` 验证通过。** 这是整根棒的目的。**只断言"叶子存在"的测试不算关掉它**——PR #103 的 builder 把生产 verifier 作为 dev-dependency 引进来验,照那个做。
- 一个测试:该 note **只有**收款 key 能花;成熟度深度被强制执行。
- 一个测试:块体字段缺失或畸形的块被拒。
- **`BlockBody::commitment()` 的 golden 向量**(见上面那条最红的),以及 PR 里一句话说明这个值是故意改的。
- PR 里一句**运维能拿去用的话**:没升级的节点会看到什么。

## 沟通走 GitHub,不走人(operating-model §3.3,必带)

**不要指望有人替你转述。** 向 coordinator 提问之后、以及动手做被提问的那部分之前,**先去 GitHub 查回复**:

    gh issue view 101 --json comments --jq '.comments[-3:] | .[].body'
    gh pr view <你的 PR 号> --comments

问题也发在那里,不要只写在自己的报告里——**写在报告里的问题没有人会看见。**

## 开 PR,不要合并

合并是 coordinator 的事,在独立验收之后(完整无过滤的 release 工作区套件,detached worktree)。

## 报告

PR 正文写清:

- **三条裁定你同意还是不同意**,不同意的给依据(第 2 条最可能错);
- **块格式改动的完整面**:改了哪些字节、golden 向量前后值、旧节点会看到什么;
- 每条验收对应的测试名;
- **诚实剩余项**:点名你认为最可能坏掉的那个东西,并直说你没见过它通过。
