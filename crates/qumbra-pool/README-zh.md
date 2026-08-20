# `qumbra-pool` —— 免托管矿池

> [English](README.md) —— 技术细节以英文版为准。
> **`pool.qumbra.org:3333` 已能解析,但还不会付钱——见下方状态板。**

## 状态板

一行由 ⬜ 翻 ✅,只发生在协调者验收之时,绝不在"写完了"之时。最后更新 2026-08-20 16:5x +08。

### 软件部分 —— 已完成

| 项 | 状态 |
|---|---|
| Stratum 映射 + `qlab-stratum` 协议 crate | ✅ 2026-08-18(lab PR #484) |
| TCP stratum 端点、按 form 键控的模板源 | ✅ 2026-08-19(lab PR #494) |
| RandomX share-PoW · PPLNS 窗口 · V5 收款人组装 | ✅ 2026-08-19(lab PR #499) |
| XMRig e2e 演练 + 五类具名对抗拒收 | ✅ 2026-08-19(lab PR #500) |
| 与 stock XMRig 同构的工作量取值(后 8 字节小端) | ✅ 2026-08-19(lab PR #492,issue #490) |
| 节点 mine RPC(`/v1/mine/template`、`/v1/mine/block`)+ 矿池二进制进镜像 | ✅ 2026-08-20(lab PR #513,issue #511) |

### 距离"能付钱的矿池"还差 —— 未完成

| 项 | 状态 | 卡在 |
|---|---|---|
| 拒绝误导矿工的闸(静态模板 / 空收款钥匙) | ⬜ PR #523 已开,CI 跑着 | 评审 |
| svc1 配置改为 `node_rpc`(而非静态假模板) | ⬜ 未开始 | lab #519 |
| 走入口的 `pool` 正路,不再覆盖入口 | ⬜ 未开始 | lab #519 |
| 矿池滚上 svc1、compose profile 打开 | ⬜ 未开始 | 上面两行 |
| **第一份来自 stock XMRig 的真实 share 端到端被接受** | ⬜ | 以上全部 |
| 对外公布端点 | ⬜ | 上一行——**端点只在它真能付钱时才公布** |

### 有意搁置 —— 不是忘了

| 项 | 状态 | 说明 |
|---|---|---|
| 运营费率政策 | ⬜ 无裁决 | 还没有人决定矿池收多少 |
| 每块多于一个收款人 | ⬜ `COINBASE_PAYEE_CAP_V5 = 1` | 抬高上限是**规则变更**,不是改配置 |
| 面向第三方运营者的公开手册 | ⬜ | 等我们自己跑通一个之后再写,不能在之前 |
| 审计 | ⬜ | 矿池在审计 RFP 范围内,尚未开始 |

### 已经就绪的前提

| 项 | 状态 |
|---|---|
| T2 上线,带 v5 收款人列表 coinbase | ✅ 2026-08-20 14:00 +08 |
| `pool.qumbra.org` DNS(灰云——stratum 是裸 TCP) | ✅ 2026-08-20 |
| 矿池收款钱包已生成,`payout_rkm` 已知 | ✅ 2026-08-20 |
| svc1 安全组开放 3333/tcp | ✅ 2026-08-20(deploy #197) |

**给快速浏览的人一句话:矿池已建成、已对着 fixture 验证通过;但它尚未部署,也从未付给任何矿工一分钱。**

## 这个矿池不一样在哪

传统矿池收到出块奖励,然后**欠**矿工各自的份额。这笔债就是矿池的权力、也是矿工的风险:
从出块到打款之间,你的收益由矿池托管;矿池跑路,收益跟着走。

Qumbra 的出块奖励是**写进共识的收款人列表**(`CoinbasePayee`,T2 的 v5 body 形式)。
**区块本身**在被接受的那一刻直接付给每个矿工。**矿池从不持有矿工的钱**——它只决定
份额、组装区块,付钱的是链。运营者中途消失,你损失的是这一轮,不是你的余额。

这正是收款人列表 coinbase 存在的全部理由,也是这个 crate 值得读而不只是值得跑的原因:
**任何人都可以运营一个**,而这个设计只有在不止一个人这么做时才有意义。

## 形状

```
  XMRig ──stratum/TCP──▶ qumbra-pool ──HTTP──▶ qumbra-node ──▶ 链
        login/job/submit              GET /v1/mine/template
                                      POST /v1/mine/block
```

- **矿工侧**:普通的 Monero 家族 stratum,stock XMRig 不改一行就能说。协议是什么见
  [`docs/stratum-primer-zh.md`](../../docs/stratum-primer-zh.md),逐字段映射(含具名偏差)见
  [`docs/pool-stratum-mapping-zh.md`](../../docs/pool-stratum-mapping-zh.md)。
- **链侧**:矿池向**自己的**节点要区块模板,并把完成的区块交回去。两条路由默认关闭,
  需要节点配置里 `template_serving = true`——运营者跑自己的节点,自己打开它。
- **share 校验**用 `qlab_devnet::pow::satisfies_target_for`——**与共识同一个谓词**——
  配 v5 的后 8 字节小端工作量取值(lab #490)。share 过滤用 XMRig 的严格 `<`,块候选用
  共识的 `<=`;这个差别是刻意的,并有测试锁定。
- **记账**是 PPLNS,窗口为最近 `PPLNS_WINDOW_SHARES = 1024` 份被接受的 share
  (`[devnet-placeholder]`,不是冻结参数)。

## 配置

带注释的完整示例见 [`qumbra-pool.example.toml`](qumbra-pool.example.toml)。要紧的字段:

| 字段 | 含义 |
|---|---|
| `listen_addr` | stratum 监听地址,`3333` 是惯例 |
| `share_difficulty` | 发给矿工的 share 目标;按设计低于链难度 |
| `node_rpc` | 你自己节点的 mine-RPC 地址。**这才是真正的模板源。** |
| `poll_ms` | 多久重新要一次模板(job 重发跟随 tip 变化) |
| `payout_rkm` | 矿池自己的收款身份,来自 `qumbra-wallet miner-rkm` |
| `[template]` | **静态 fixture,仅供测试**——见下面的拒绝 |

### 两条你应该期待、也应该想要的拒绝

一个**看起来活着、实则毫无用处**的矿池,比一个起不来的矿池更糟——因为矿工在为它烧真实的电。
所以在监听端口绑定**之前**:

- **静态 `[template]` 会被拒绝服务**(`static-template-source-refused`)。固定的高度和 prev
  可以看起来完全健康,却根本没在跟踪任何链:活照发、share 照记,而其中没有一份可能变成区块。
- **全零或不可用的 `payout_rkm` 会被拒绝**。付给空身份的 coinbase,**谁也花不了**,
  包括挣到它的矿工。

`check` 和 `run` 都会走这两条闸,在任何 RPC 连接或端口绑定之前。
*(随 lab #519 的第一个 PR 落地;这里写出来是因为它是既定契约,不是可选项。)*

## 怎么跑一个

```sh
qumbra-pool check  --config pool.toml   # 检查配置、拒绝闸、模板源——不开监听
qumbra-pool        --config pool.toml   # 开服
```

你还需要一个**自己的** `qumbra-node`,并打开 `template_serving = true`。mine RPC 按设计
只在容器内可达:矿池经私有网络访问节点,而**节点的 mine 路由永远不对公网发布**——
对外的只有 stratum 端口。

## 记录

设计:`qumbra-design/pool-t1-brief-zh.md`(route A、stratum 兼容头的裁决)与
`pool-payout-axis-brief-zh.md`(为什么选方案 (c) 的版本化收款人列表)。
施工:lab #482(阶段 0–3)、#490(让 stock XMRig 可用的工作量谓词)、#511(节点 mine RPC)、
#519(上线)。
