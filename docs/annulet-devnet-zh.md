# Annulet 开发网 —— B6（lab #716）

[English](annulet-devnet.md)（技术细节以英文版为准）

Annulet 开发网由一个 sequencer、两个 follower 和一个手续费单位水龙头组成，跑的是 B1–B5 建好的 L2 链形态，交易证明用真实的 L2 验证器验证。本文讲怎么跑、证据证明了什么、没证明什么。

> **现状。** compose 文件只做过静态校验，还没有任何人真正起过它。这条流程的证据是下面列的 lane 测试（`verify-graviton`），不是一个正在跑的开发网。把 compose 起起来是之后另行安排的一步。

## 里面有什么

- **开发网 genesis**，即 `AnnuletGenesisFile::devnet()`。它是确定性的，哈希已钉住：`831de12f95b07762fa843d823824ca589fa331d5a7a552098eaf0fcd3be9e9ef`（5,230 B），`examples/annulet_devnet_genesis` 跑两次，逐字节一致。*（C3 重新钉住，lab #722：原来是 `6f0978eb2c56d6967a8c0ade9d1096ab8c4e79a9d846de53e39613cb43ddf374`。`USDT-test` 的冻结树根从带种子的测试夹具树，换成了规范的空树，任何钱包都能按发行方公开的名单自己重建。）*内容：
  - 注册表里有两种资产：asset 0（Cloaked），以及 asset 1 上的 `USDT-test`（Hybrid，开发用发行方密钥，冻结树为空）；
  - 16 张**库存票据**，每张正好够一次发放，都发给水龙头的 `rkm`。一张库存票据价值 `tier_p + tier_s` = 3，一次发放把它整张花掉：2 给申请人，1 是 S 手续费。不找零，也不回收；
  - 一张 genesis 铸出的 `USDT-test` 票据（1,000,000），归开发用的 **holder** 密钥。
- **只有开发密钥。** sequencer 种子、水龙头密钥、holder 密钥和 `USDT-test` 发行方密钥都公开在 `qumbra_node::annulet_genesis::devnet` 里，和委员会的彩排密钥一样。它们都不能承载价值。
- **`qumbra-node genesis annulet-devnet [--out DIR] [--sequencer-data-dir DIR]`** 用来写出这份 genesis。加上 `--sequencer-data-dir` 还会写出开发用的 sequencer 密钥文件，有了它节点才会成为出块方。
- **`qumbra-faucet annulet --node-config FILE [--listen ADDR]`** 运行水龙头：进程内带一个无密钥的 follower，用它自己的 discovery 端点作数据来源，对外提供 `POST /v1/annulet/grant`，请求体是一个地址字符串。
  - 库存是它的密钥名下的 genesis 票据，扣掉链上已出现 nullifier 的那些，所以重启后不会把发过的票据再发一次。
  - 以下三种情况它会点名拒绝启动：L1 genesis、不是开发网的 Annulet genesis、节点会成为 sequencer。
  - 不要票券，也不限流：库存一共就 16 次发放。
- **`POST /v1/tx` 的解码、请求体上限和 discovery 检查都改为按链形态区分：同一个接口上的三个问题。**
  - **解码。** B6 之前，节点的 HTTP 提交接口用的是 L1 交易线格式，Annulet 交易根本没法通过 HTTP 提交。现在改成了 `decode_tx_for(form, …)`。
  - **请求体上限。** 原来是 256 KiB，按 L1 证明定的，把所有 L2 交易都挡在了外面：S 交易 288,332 B，P 交易约 317 KB。这是第一次跑 lane 时发现的。现在改成 `max_tx_wire_bytes(form)`：L1 不变，Annulet 为 512 KiB `[devnet-placeholder]`，临时 lane 的线格式一变，这个值也跟着变。
  - **discovery 检查。** 这个接口提前做的 §4 检查用的是 L1 的 `check_tx_discovery`，于是把 L2 那 256 B 的密文段当成格式错误拒掉了（它期望 240 B）。这是第二次跑 lane 时发现的。现在改成 `check_tx_discovery_for(form, …)`，和 mempool 已经在用的检查一致；并在这个接口上加了单元测试钉住（`run_annulet`：L2 宽度的密文段在 Annulet 上放行，在 L1 上当格式错误拒掉）。顺带把整条准入路径扫了一遍，找按 L1 宽度定的其他常量，测试代码以外没有发现（清单写在提交说明里）。
  - **给以后改这个接口的人：** 这里凡是按 L1 交易大小定的常量，都要拿 L2 交易再核一遍。

## 怎么跑

**证据（lane）：** 在 B6 的 PR 上打 `verify-graviton` 标签，就会跑工作区全套测试，其中包括 B6 的五个测试文件：

| 测试 | 说明什么 |
|---|---|
| `qumbra-faucet/tests/annulet_journey.rs` | **完整流程。** 一个 sequencer 加两个 follower，走 TCP loopback，全部用真实的 `L2Verifier`：<br>1. 水龙头拒绝两种 L1 形态，读到 16 张库存票据。<br>2. 发两次 S：一次给 holder，一次给新生成的收款方。之后重启的水龙头只看到 14 张。<br>3. holder 把 `USDT-test` 转给收款方（shape P，vPublic = 0）。<br>4. 收款方通过**某个 follower** 的 `/v1/compact` + `/full` **发现**自己的两张票据，再把 `USDT-test` 转回去（P），见证数据都从这个 follower 读。这笔再提交一次会被拒。<br>最后三个节点的链头、承诺树根和 8 个 nullifier 完全一致，holder 在另一个 follower 上也找到了自己的票据。共 2 次 S、2 次 P 真实证明。 |
| `qumbra-node/tests/annulet_binary.rs` | 真实的 `qumbra-node` 二进制：`genesis annulet-devnet` 生成开发网，和钉住的哈希逐字节一致。`run` 以出块方身份启动，用真实的 L2 验证器，能提供 genesis 票据和 `USDT-test` 的注册表证明。`POST /v1/tx` 能解码 Annulet 线格式，SIGTERM 能干净退出。 |
| `qumbra-faucet/tests/annulet_binary.rs` | 真实的 `qumbra-faucet annulet`：拒绝非开发网 genesis 和 sequencer 节点，库存页显示 16 次，无法解码的地址被拒。不做证明。 |
| `qlab-p2p/tests/annulet_sync.rs` (b) | 新节点在**默认**限流器下追上 4,100 个 sealed 区块：两整批 2,000 个 3,462 B 的区块头，外加余下的一批。整批不超过 `MAX_PAYLOAD`，也在一次入站字节突发额度之内。 |
| `qlab-p2p/tests/annulet_sync.rs` (c) | 新节点的第一批区块体请求丢失，随后区块体倒序到达，最前沿那块扣着不给。它在 `BODY_REQUEST_TIMEOUT_MS` 之后重新请求，最终追到链头。 |

**journey 实测。** 机器是 Graviton m7g.2xlarge（run 自报 aarch64、8 核、30 GiB），`--release`，`--test-threads=1`。

| 步骤 | 耗时 | lane run |
|---|---|---|
| 2 次 S 发放（水龙头 → holder、水龙头 → 收款方），三节点封块并应用 | 19.2 s | 35936692340 |
| holder → 收款方 `USDT-test`（P），封块并应用 | 21.8 s | 35936692340 |
| 收款方通过 follower 2 找到自己的两张票据（外人一张也找不到） | 含在下一步里 | 35936692340 |
| 收款方 → holder `USDT-test`（P），封块并应用 | 19.5 s | 35936692340 |
| **整个 journey 通过**：重复提交被拒，**三个节点全部对齐在 8 个 nullifier**，链头和承诺树根一致，holder 在 follower 1 上找回自己的票据 | **57.86 s** | **35941580527**（2,602 / 0 / 15，157 组结果全部到齐） |

分步耗时取自 35936692340：那次每一步都跑完了，只在最后读到旧状态时失败，这个问题已经修掉。测试通过时 cargo 不打印它的 stderr，所以通过的那次只有整体耗时。点名测试 (b) 和 (c) 合计 5.40 s。

**compose（还没起过）：** 在 `qumbra-deploy` 的 `compose/docker-compose.annulet-devnet.yml`。先在本仓库构建 lab 镜像：

```sh
docker build -f deploy/docker/Dockerfile --target runtime -t qumbra-lab:annulet-devnet .
```

然后 `init` 写出 genesis 和开发用的 sequencer 密钥，sequencer 和两个 follower 跑 `qumbra-node run`，水龙头跑 `qumbra-faucet annulet`。对外端口全部只绑 loopback：两个 follower 的 discovery 在 9421 和 9422，水龙头在 8090。**内存：** 一次 S 发放峰值约 7 GB，一次 P 转账约 15 GB，水龙头容器得留出这么多余量。

## 证明了什么

- 节点自己的代码（`RunningNode`，走真实 TCP）能以 L2 验证器为默认值跑起一个 Annulet 网：区块由 sequencer 签封，被接受即最终，follower 用同一个验证器应用区块。
- 手续费单位水龙头能用恰好一次的库存票据发放，重启后不会重复发放。
- 一笔政策资产（`USDT-test`，Hybrid）的转账，shape P、vPublic = 0，用**服务端提供的**见证数据（承诺树、注册表证明）构造、证明，通过 HTTP 提交，被三个节点接受。
- 只知道自己 KEM 密钥的收款方，能从 follower 提供的接口找到自己的票据，并且能花出去。
- sealed 区块头在限流器下能跨整批追上；区块体丢失或乱序，最终也能收敛。

## 没证明什么

- **compose 能跑起来。** 它只被解析过（`docker compose config`），第一次起是之后另行安排的一步。
- **用户钱包。** 这里的花费组装（`qumbra_faucet::annulet`）其实是 L2 花费的钱包一侧，因为水龙头先用得上才在这里写；C2 会把它挪进钱包。*（C1 更正，lab #718：这里原先说还没有用户钱包能推导出可在 L2 花费的 `rkm`，这是错的。钱包的 `rkm = H(nk ‖ D ‖ d)` 和 `nf = H(nk ‖ ρ)` 与 L2 电路的推导逐个 lane 一致，现有钱包地址本来就能收可花的 L2 票据，现在有测试证明。C1 加上了扫描：`qumbra-wallet scan --net annulet`。）* *（C2，lab #720：花费组装已移到 `qlab-l2spend`，钱包和水龙头共用一份；`qumbra-wallet send --net annulet` 可以从普通钱包发送，钱包里没有面额恰好等于手续费的 asset-0 票据时，会先拆出一张。一笔交易最多只能动用一张非手续费资产的票据，这类资产的两张票据在 2×2 里无法合并，已作为试点的设计层阻断项记录。）*
- **发行方操作。** 铸造、赎回、冻结、白名单和非零 vPublic 属于 C3。这里的冻结树是空的，也从不更新。
- **运行时修改注册表。** A2 之前，注册表只在 genesis 里设定。
- **浏览器或证明页面。** 属于 D1。
- **防滥用。** 水龙头不要票券也不限流，16 次请求就能把它发空。
- **lane 是临时的**（`L2_CFG_PROVISIONAL`，A1），这里没有把它定下来。
- **乱序的区块体要多等一个重新请求的周期。** 在 Annulet 节点上，父块还没应用的 sealed 区块体不会被暂存，而是当作孤块丢掉，等 `BODY_REQUEST_TIMEOUT_MS` 之后再取一次。测试 (c) 证明它能收敛，但没证明它快。
- **Phase 0 的性质。** 原文引自 l2-own-circuit-decision §4：

  > Under Phase 0 option (a) — no QMB on L2 — a stablecoin pilot is honestly **a sidechain that
  > reads L1 anchors**: its value to Qumbra is the shared toolchain, the shared wallet, the
  > attestation surfaces, and the path to Phase 1; it is not yet Qumbra's money. The doc says so
  > because the pilot's press copy will be tempted not to.

  意思是：在 Phase 0 的方案 (a) 下（L2 上没有 QMB），稳定币试点老实说就是**一条读取 L1 锚点的侧链**。它对 Qumbra 的价值在于共用的工具链、共用的钱包、证明页面，以及通往 Phase 1 的路，但它还不是 Qumbra 的钱。文档之所以把这点写明，是因为试点对外宣传时会忍不住不这么说。

## 推迟的事项及原因

- **二进制遥测里的链形态字段推迟到 D1。** B6 没有带上任何读 Annulet `/v1/telemetry` 的消费者（浏览器和 opview 都是 D1 的事）。文本输出已经标明了链形态（`form=annulet finality=operator`，B2）；一次全网可见的 `RPC_VERSION` 升级，应该放在能用上它的里程碑里。#212 的做法随它一起带过去。
