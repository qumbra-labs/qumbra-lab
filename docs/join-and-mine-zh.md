# 加入与挖矿 —— 运营者路径

English: [`join-and-mine.md`](./join-and-mine.md) —— 技术细节以英文版为准。

**状态:先于 T1 mint 写就。** 本文一切今天即可对着私网演练;只有公网才能提供的两个值——
genesis 文件与种子列表——标记为 **[T1 发布]**。本文即 testnet-plan §6 的 "join/mine docs" 行。

## 1. 你需要什么

| | |
|---|---|
| 硬件 | 2 vCPU / 2 GB 内存已被证明够用(T0 机队就是 `t4g.small`);RandomX 走 light 模式(~256 MB) |
| 网络 | **只需出站 TCP。** 不需要公网地址、端口转发或 NAT 技巧——本网按决定(2026-07-26)接受 outbound-only 参与者。 |
| 系统 | Linux x86-64/aarch64 或 macOS;Linux-aarch64 的 RandomX 构建坑已在 docker 镜像中解决 |

## 2. 获取软件

**Docker(推荐):** 节点镜像在 GHCR 公开——无需 registry 凭证,按发布 digest 锁定。
**[T1 发布:镜像 tag + digest]**

**源码构建:** Rust stable + `cmake` + C++ 工具链(RandomX 编译一个 C++ 库):

```sh
cargo build --release -p qumbra-node -p qumbra-wallet
```

## 3. 建钱包,取你的 `miner_rkm`

Coinbase 需要收款人。钱包 CLI 同时产出你的地址和挖矿身份的节点配置形式:

```sh
qumbra-wallet keygen --dir ~/.qumbra-wallet     # seed(0600)+ 地址 [0];不打印任何密钥材料
qumbra-wallet miner-rkm --dir ~/.qumbra-wallet  # → miner_rkm = "…64 hex…"
```

**先备份助记词**(`qumbra-wallet backup --dir … --reveal`)再开挖。助记词刻意**不是
BIP-39**——别的钱包恢复不了它,它也不接受别家的短语。

## 4. 节点配置,逐项讲清

```toml
data_dir     = "/var/lib/qumbra"        # 链存储 + snapshot;重启后仍在
listen_addr  = "0.0.0.0:9400"           # 入站 P2P —— 即使没人能连到你也照常绑定
genesis_file = "/etc/qumbra/genesis.qmb"          # [T1 发布]
expected_genesis_hash = "…"                       # [T1 发布]
dial_peers   = ["seed1.example:9400", "…"]        # [T1 发布]
mining       = true
miner_rkm    = "…第 3 步的 64 hex…"
```

- **`expected_genesis_hash` 是拒绝,不是校验和**:拿到错误 genesis 的节点不会启动。genesis
  文件**就是**网络身份。
- **`advertise_addr` —— 声明,而非发现。** 节点永远看不到自己的公网地址。**只有**当你确实
  有公网地址并希望接受入站时才设置;不设即为 outbound-only 参与者,完全受支持。不要猜着填:
  错误的广告会污染其他节点的地址簿。
- 种子之外的 peer 发现是自动的(学到的地址持久化在 `peers.dat`);连接上限默认出站 8 / 入站
  32。首跑一项都不用配。

## 5. 运行,并读懂那一行

`TELEMETRY` 行按运营者真正会问的顺序回答:

- **`mready=`** —— 挖矿就绪门。冷启动的节点**在知道链在哪之前绝不能挖**(真实缺陷,已修):
  `mready=synced` 表示门已通过;`mready=unknown` 表示还在找 peer——这是**刻意不挖**的节点,
  不是挖不动的节点。
- **`tip=` / `final=` / `regime=`** —— 你的高度、已终局高度、委员会终局是否在线(`Final`)
  或链处于 PoW-only 降级模式。
- **`dialable=n/known`** —— 地址簿里你真正连得上的比例。outbound-only 节点 `dialable` 低而
  `known` 上涨是正常的。

## 6. 你的 coinbase,照实说

- 你赢下的块付给 `miner_rkm`——那个身份就是你钱包的**地址 [0]**(或你选的 index)。note 是
  真实链上数据:按设计可从链本身复原。
- **成熟之后才可花**:`COINBASE_MATURITY_BLOCKS`(frozen §2——引自常量,当前为 144 块 ≈
  75 秒目标下 3 小时)。强制是结构性的:未成熟的 note 没有树叶,任何钱包——你的或贼的——都
  提前花不了。
- 🔴 **两件你现在还做不了的事,直说:**
  1. **花费。** T1 交易能力卡在 dummy 输入机制与 mint(lab #219 / #188)。挖矿与积累不受
     影响。
  2. **在 `qumbra-wallet scan` 里看到 coinbase 余额。** scan 面做的是交易输出的试解密;
     coinbase note 是从链数据派生的,CLI 的 coinbase 收割面是一个**点名的后续**,不是暗坑。
     币在链上、可复原;只是钱包还不能替你**数**它们。

## 7. 看起来不对劲时

`final=` 冻结而 `tip=` 上涨是委员会停摆,不是挖矿问题——继续挖;网会在无需你干预的情况下恢复
终局。journal 里带 `schain=fork` 的疑似卡死节点是在输掉的分支上;历史上这些都自恢复,该机制的
当前工作是公开的(lab #229)。重启不会丢失 `data_dir` 里的任何东西。
