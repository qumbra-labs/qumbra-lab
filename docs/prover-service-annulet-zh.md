# Annulet 证明服务——运维指南

*英文版：[`prover-service-annulet.md`](prover-service-annulet.md)。技术细节以英文版为准。*

Lab issue #924，5A-D3/D4；format 34 部分来自 lab #937 PR E。代码：`crates/qumbra-prover-service`（`src/annulet.rs`、`src/annulet_v3.rs`、`src/token.rs`）。

服务只服务一个 net，format 33 或 format 34。下文直到[「Format 34」](#format-34prover-在交易里收费)一节之前讲的都是 format 33；34 上的不同之处集中写在那一节。

## 它是什么

`qumbra-prover-service` 为自行保管密钥的钱包证明 Candidate A 的 **holder** 花费（shape S 和 P）。钱包上传一个 `ProvingBundle`：其中是证明留空的交易、已经签名并附上的授权段，以及 witness。该段的 intent 绑定了除证明之外的每一个公开字段。因此服务只能补上证明，别的什么都做不了，既不能花费，也不能改去向或重新签名。issuer 操作（带 issuer secret 的 P 行，或非零的 `vPublic`）会以 `issuer-shape` 被拒绝，永远不会被委托。

服务会自己提交证明好的交易，目标是钉定节点的 `POST /v1/tx`（若配置了 relay，也提交给 relay），并返回 tx id。

L1 的 `WitnessBundle` 模式（`/v1/jobs`）保持不变。它现在只在设置了它自己的无价值确认项时才运行，在 Annulet prover 上**默认关闭**。

## API

| 路由 | 认证 | 作用 |
|---|---|---|
| `GET /v2/annulet/info` | 无 | `genesis_format`、`genesis_hash`、`shapes`、`d_auth`、`max_bundle_bytes`、`queue_capacity`、`prove_timeout_secs`、`slot_secs`、**`recommended_valid_for_blocks`** |
| `GET /v2/annulet/quota` | Bearer | `per_day`、`used_today`、`in_flight` |
| `POST /v2/annulet/jobs` | Bearer | body 为 bundle 字节（`application/octet-stream`，≤ 80 KiB）；返回 202 及 `job_url`，或对同一 intent 已有的 job 返回 200 |
| `GET /v2/annulet/jobs/<cap>` | **URL 本身** | `state`（`queued` / `proving` / `submitting` / `submitted` / `failed` / `refused` / `cancelled`）、`queue_position`、`tx_id`、`refusal`、`expires_in_secs` |
| `DELETE /v2/annulet/jobs/<cap>` | **URL 本身** | 取消排队中或正在证明的 job |

**job URL 就是 capability。** 它是 32 个随机字节，也是读取或取消该 job 的唯一凭据。上传 bundle 的 popup 把它当作秘密持有。job 结束后，超过结果 TTL（默认 600 s）它就失效。

**准入顺序。** 每一次拒绝都有明确的名字，第 5 步通过之前不会派生任何进程，也不会入队：

1. token：签名、有效期窗口、net、吊销 → `401`，错误码为 `unauthorized`、`token-malformed`、`token-key-unknown`、`token-signature-invalid`、`token-window-invalid`、`token-expired`、`token-wrong-net` 或 `token-revoked`。
2. 该 token 唯一的 in-flight job、唯一一个正在读取的上传，以及每日配额 → `429`,错误码为 `token-busy` 或 `quota-exhausted`。只有**已准入**的 job 才计入配额。已准入的上传必须在 30 s 内传完。超时后处理线程放弃(记为 `upload-deadline`),但该 token 的读取名额要等连接真正断开才释放，所以慢速上传只拖住它自己的 token。
3. 字节上限，有界读取 → `413` `bundle-too-large`。
4. 解码 → `400` `bundle-malformed`，或 `403` `issuer-shape`。
5. 在本 net 上运行 bundle 的 lock → `422`，错误码为 `statement-mismatch`、`unauthorized-section`、`proof-present`、`auth-missing` 、`outputs-not-the-nets`（lab #937：bundle 的输出数与本 net 不符，例如 format 33 上的三输出 bundle）、`third-output-asset`（lab #937：三输出 bundle 的第三个输出的资产既不是任一输入的资产，也不是经 fee bank 支付的 asset 0——v3 AIR 对它没有证明）或 `fee-note-not-exact`（lab #937 PR D：slot 3 的手续费 note 既不恰好等于手续费，也不恰好等于手续费加一个 asset 0 的第三输出）。

准入之后，请求仍可能被 `409` `intent-in-flight`（另一个 token 持有该 intent）或 `503` `prover-busy`（队列已满）拒绝。

**幂等性。** 幂等键是已签名 intent 的摘要，由服务端计算。重新发送同一笔已签名交易，会返回它已有的 job。没有产出交易就结束的 job（`failed`、`refused`、`cancelled`）可以重试。

**有效期。** 服务不判断 `valid_until`，因为它不知道链尖。客户端签名时至少要用 `recommended_valid_for_blocks` = ⌈((queue + 1) × prove timeout + 60 s) / slot⌉。如果交易上链太晚，节点会拒收，job 以 `node-refused:<code>` 失败。

## Token

传输格式为 `qpt1.<base64url(payload ‖ ML-DSA-44 signature)>`。payload 是定长的：key id、16 字节的 token id、该 net 的 genesis hash、`not_before`、`not_after`（相隔最多 30 天）、`per_day`（0 表示使用运维方默认值），以及 flags（为零）。prover 只持有**验证密钥**；签发密钥绝不会碰到 prover 机器。

```sh
# 在运维人员自己的机器上做一次。seed 是文件里的 64 个十六进制字符，
# 绝不放在命令行上。
qumbra-prover-service token-key  --seed-file issuer.seed --key-id 1   > token-keys.txt   # 公开：拷到机器上
qumbra-prover-service mint-token --seed-file issuer.seed --key-id 1 \
    --genesis-hash <64 hex> --days 30 [--per-day 20]        # token 输出到 stdout，token id 输出到 stderr
```

要吊销 token，把它的 token id（32 位十六进制）加入 `QUMBRA_PROVER_TOKEN_DENY_FILE`。服务每分钟重新读取该文件。

网关的 portal 之后会通过调用 `qumbra_prover_service::token::mint` 来签发 token，使用它自己的 issuer 密钥和自己的 `key_id`。

## 配置

当且仅当设置了 `QUMBRA_PROVER_ANNULET_GENESIS_HASH` 时，Annulet 模式才开启。此时其余一切都按失败即关闭处理：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `QUMBRA_PROVER_ANNULET_GENESIS_HASH` | — | 64 位小写十六进制；该 net 的 genesis 文件哈希 |
| `QUMBRA_PROVER_ANNULET_SLOT_SECS` | — | genesis 中的 `slot_secs` |
| `QUMBRA_PROVER_ANNULET_NODE_URL` | — | 接受 `POST /v1/tx` 的节点；必须是 https，除非设置了下面的明文 http 确认项 |
| `QUMBRA_PROVER_ANNULET_RELAY_URL` | 未设置 | 尽力而为的第二次提交；规则同上 |
| `QUMBRA_PROVER_ANNULET_ALLOW_PLAIN_HTTP_NODE` | 未设置 | 值恰为 `I_UNDERSTAND_THE_NODE_LINK_IS_PLAINTEXT_AND_FIREWALLED_TO_THIS_HOST` 时，才允许 `http://` 的节点或中继 URL。只在防火墙只放行本机访问该端口时使用。链路上传的是已签名、已证明的交易：一提交就公开，任何改动都会让它失效，所以最坏只是丢掉一次提交。L1 实验的 `QUMBRA_PROVER_ALLOW_INSECURE_NODE_HTTP` 对这个模式不起作用 |
| `QUMBRA_PROVER_ANNULET_QUEUE` | 3 | 1..=8，排队的 job 数，不含正在运行的那个 |
| `QUMBRA_PROVER_ANNULET_TIMEOUT_SECS` | 300 | 30..=1800，每次 prove |
| `QUMBRA_PROVER_ANNULET_RESULT_TTL_SECS` | 600 | 60..=3600 |
| `QUMBRA_PROVER_ANNULET_PER_DAY` | 20 | 仅 format 33:1..=1000,token 中写 0 时使用的默认值 |
| `QUMBRA_PROVER_TOKEN_KEYS_FILE` | — | 仅 format 33(在那里必填):每行一条 `key_id verifying_key_hex` |
| `QUMBRA_PROVER_TOKEN_DENY_FILE` | 未设置 | 仅 format 33:已吊销的 token id |
| `QUMBRA_PROVER_SCRATCH` | — | **必须是 tmpfs 挂载**（启动时检查；仅 Linux） |
| `QUMBRA_PROVER_LISTEN`、`QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` | 同 L1 | TLS、限流和请求头大小上限都在 ingress 层 |

## worker 子进程

证明一次只跑一个，每个都在全新的 `annulet-worker` 子进程中运行：

- 环境变量被清空，只保留协议标签、genesis hash 和 genesis format，因此子进程没有 URL，也没有 token；
- 关闭 core dump：`RLIMIT_CORE = 0` 在 fork 与 exec 之间设置。Linux 上，子进程 exec 之后的第一件事是自己清掉 `PR_SET_DUMPABLE`(内核在 `execve` 时会重置这个标志)。此后同 uid 的进程既不能 `ptrace` 它，也读不了 `/proc/<pid>/mem`。服务进程启动时也对自己做同样的处理，因为它同样持有 bundle;
- 工作目录和 `TMPDIR` 都是 tmpfs scratch；
- stderr 被关闭；
- bundle 由单独的线程写进子进程的 stdin,因为 80 KiB 可能超过管道缓冲区。这样子进程若在读取前卡住，证明超时也能覆盖到。

两个进程丢弃解码后的 bundle 时都会擦除其中的 witness。

子进程会重新运行 bundle 的 lock 并证明。随后服务端检查返回的结果是否恰好是 bundle 的交易加上一个非空证明、别无其他（否则 job 以 `proof-mismatch` 失败），通过之后才提交。

## 日志与哪些状态会重置

- 每个 job：8 位十六进制的 job 前缀、shape、bundle 和 tx 的大小、排队等待时间、prove 时间，以及一个结果码。bundle 字节、交易字节、token id 和 tx id 一律不记录。
- 每分钟：按错误码统计的准入拒绝次数，以 token id 的 4 字节哈希为键（token 通过验证之前用 `-`）。这样既能看出滥用，又不会点出用户是谁。
- **每日计数、in-flight 状态和 job 都在内存中，重启后重置。**

## Format 34：prover 在交易里收费

Lab #937 PR E（裁定 D4、D5，以及 issue #937 上对 PR E 的裁定）。在 format 34 的 net 上（`QUMBRA_PROVER_ANNULET_GENESIS_FORMAT=34`），bundle 的**第三个输出就是付给本服务的费用**：收款方是配置的 payee 的 `rkm`，资产是 asset 0，金额不低于该 shape 公布的价格。没有 token，也没有账户。

**和 format 33 的区别：**

- **没有 token。** 不读 `QUMBRA_PROVER_TOKEN_KEYS_FILE`、`QUMBRA_PROVER_TOKEN_DENY_FILE` 和 `QUMBRA_PROVER_ANNULET_PER_DAY`,三者都不是必填项（lab #937 D6）。如果还配着，即使文件读不了或值不合法，服务也只是忽略而不拒绝启动，并用一行启动日志列出被忽略的变量。服务从不读 `Authorization`。`GET /v2/annulet/quota` 返回 `404 quota-not-served`。没有每日额度。
- **`/v2/annulet/info`** 多出 `fee_asset`（0）、`price`（`{"S": n, "P": n}`）和 `payee`（完整地址）三个字段。内核的 `prover_pins::admit` 就是拿这三项去和该网络的 pin 比对。format 33 上没有这三个字段。
- **`/healthz`**：nullifier 跟读第一次追上之前，以及之后落后超过一个 slot 的时候，都返回 `503` 加跟读的错误码（见下文）。

**34 上的准入顺序。** 每一种拒绝都有名字，第 5 步通过之前什么都不会进队列：

1. **客户端 IP**，取自 `X-Qumbra-Client-IP`：
   - 缺失、重复或不是 IP → `400 client-ip-unknown`；
   - 同一个 IP 已有一个活着的任务，或已有一个正在上传的请求 → `429 ip-busy`。

   IPv4-mapped 的 IPv6 地址按其 IPv4 地址算。IPv6 按 /64 网段算作同一个来源。因此同一个 NAT 或 CGNAT 后面的多个用户共用一个名额，要互相等对方的任务结束。测试网上接受这一点。
2. 字节上限、解码和 bundle 的 lock，和 33 上一样。两输出的 bundle 返回 `422 outputs-not-the-nets`。
3. **手续费**，从 witness 的第三个输出读取。lock 已经把这个输出绑定到交易的第三个 commitment 上：
   - 收款方不是 payee 的 `rkm`，或资产不是 asset 0 → `402 prover-fee-missing`；
   - 金额低于该 shape 的价格 → `402 prover-fee-short`。

   付得比价格多是接受的。
4. **nullifier**：
   - 其中一个已经上链 → `409 nullifier-landed`；
   - 跟读还没就绪 → `503 nullifiers-catching-up` 或 `503 nullifiers-stale`；
   - 其中一个已被本服务里一个仍可能上链的任务占用（排队中、证明中、提交中，或在结果 TTL 内已提交）→ `409 nullifier-in-flight`。

   幂等键仍然是 intent，提交者就是客户端的 IP。任务还活着的时候，同一 IP 的重试在第 1 步就会被拒（`429 ip-busy`，33 上的 `token-busy` 同理）。任务结束之后（`submitted`、`failed`、`refused`、`cancelled`），同一 IP 重试会拿回原来的任务；如果原任务没有产出交易，则新建一个。换一个 IP 则返回 `409 intent-in-flight`。
5. 保留任务数和队列上限，和 33 上一样。

**客户端 IP 及其前提。** 服务之所以信任 `X-Qumbra-Client-IP`，是因为它只监听内部 ingress 网络。`QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` 这个确认项涵盖的就是这个前提。

这个请求头由 Caddy 设置（属于切换时的部署改动，不在本 PR）：
- `trusted_proxies static <Cloudflare 公布的网段>`，配合 `client_ip_headers CF-Connecting-IP`；
- 在 `/v2/annulet/*` 上设 `header_up X-Qumbra-Client-IP {client_ip}`。这会覆盖客户端自己发来的同名请求头。

不是从 Cloudflare 网段来的连接，其客户端 IP 就是它自己的 socket 地址，所以绕开 Cloudflare 也冒充不了别的 IP。安全组只对 Cloudflare 网段开放 443，是切换时运维的步骤。

IP 从不进日志。拒绝计数记在一个按进程随机加盐的键的 4 字节哈希下面。

**nullifier 跟读。** 服务自己跟读它钉定的节点（`QUMBRA_PROVER_ANNULET_NODE_URL`）：
- tip 从 `GET /v1/registry/root` 读；
- 已上链的 nullifier 按页读 `GET /v1/nullifiers`；
- 每个块的 id 和 `prev` 从 `GET /v1/headers` 读（lab #945）。

每四分之一个 slot 轮询一次（最快 200 ms 一次），这样即使某次轮询较慢，也远在"超过一个 slot 即判为过期"的界限之内。每个高度都必须按顺序给出。跳过某个高度的页、或一个块都没有的页，都算错误，集合不会越过它往前走。每一步读一页 header（最多 256 个块）：先读 header，再读 nullifier，最后再读一次这页的最后一个 header。如果这几次读之间链变了，这次轮询失败；某个块的 `prev` 不是前一个块，也算失败（`headers-break`）。

**它承担的信任。** 跟读不校验它读到的 header 上的排序器签名。节点是运营方钉定的节点，服务对其他每一次读取（tip、nullifier、提交）本来就承担这份信任；校验签名每个块要多约 3.3 KB 的验签输入，却防不了这个节点本身（lab #945 的裁定）。

**重组（lab #945）。** 每次轮询先核对已跟读的块：节点在已跟读高度上的块，id 必须仍是跟读记下的那个。如果不是，或者 tip 已经低于它，跟读就在窗口（最近 65 个块）里往下找，找到节点仍然给出同一个块的最高高度，**回滚**到那里：恰好是那些块的 nullifier 离开集合（一个 nullifier 至多在一个块里），然后从那里读新分支。64 个块以内的重组（10 秒一个 slot 约 10.7 分钟）都这样回滚。更深的话，窗口里已经没有一个块还被节点给出：集合和它的存储都被清空，以 `error:` 记一条 `reorg-deeper-than-64:`，集合从高度 1 重建。

**存储（lab #945）。** 集合持久化在付费台账旁边，路径是 `<QUMBRA_PROVER_ANNULET_PAID_LEDGER>.nullifiers`，和台账一样以 0600 创建。它是只追加的文本：一行头 `qumbra-prover nullifiers v1 genesis=<64 位十六进制>`，然后每个块一行（`<高度> <块 id> <nullifier>*`，不花任何东西的块也有一行），每次回滚一行 `rollback <h>`。一次轮询的行先 fsync，内存里的集合才前进。v1 不做压缩。

启动时重放存储，跟读从最后一个完整高度接着走，所以重启只读新的部分。集合保留全部：任何 nullifier 都不会因为太旧被丢掉，因为忘掉的花费会换来一次完整证明，链随后拒绝那笔交易，证明费也就拿不到。启动时：
- 末尾残缺的一行（追加到一半时崩溃）会被截掉，那个高度重新读；
- 为别的创世写的存储，记为 `genesis-mismatch`，清空后从高度 1 重建；
- 行格式错、高度乱序、或回滚落在窗口外，以 `store-corrupt:` 拒绝启动。拒绝信息写明行号和处理办法：把文件挪开，跟读就从高度 1 重建；
- 存储无法创建、打开或读取，或者不是 0600，以 `store-unwritable:` 拒绝启动。之后某次追加失败只算一次轮询失败，集合不前进。

第一次追上时日志记下集合大小和耗时；恢复出来的存储会在启动时记下它到达的高度。（有存储之前，每次启动都从高度 1 重建；在 prover-1 上，演练链约 27,000 个块时只要几秒。）

**失败要响亮。** 下面两种情况，准入都回 `503`，`/healthz` 也报未就绪：
- 第一次追上之前：`nullifiers-catching-up`；
- 上次追上已超过一个 slot：`nullifiers-stale`。节点连不上和跟读落后都属于这种情况。

跟读失败以 `error:` 记一次日志，恢复时再记一次。

*残余风险。*
- **每个 IP 每个证明时长最多浪费一次证明。** 如果一笔交易输给了一笔跟读还没看到的花费，它仍会被证明一次；而对方那笔上链的花费要花掉攻击者真实的 note（D4 已接受）。
- 某个块被重组掉后，其中的 nullifier 在下一次轮询时离开集合（回滚）；重组深过 64 个块的，在重建之后离开。在那之前，相关的 note 会被当作 `nullifier-landed` 拒绝。

**付费台账（D5）。** `QUMBRA_PROVER_ANNULET_PAID_LEDGER` 指定一个文件。

*文件：*
- 由服务以 0600 权限创建，第一行写版本头 `qumbra-prover-paid-ledger 1`。
- 已存在的文件必须本来就是 0600，且以这一行开头，否则启动时按名拒绝。
- 要挂载在持久存储上。`/scratch` 是 tmpfs，重启就没了。
- 它从不进日志，也从不进 git。

*写入顺序。* 节点**接受** `POST /v1/tx` 之后，服务追加一行并 fsync，之后任务才显示 `submitted`。

*每行内容。* 先是条目版本号 `1`，后面是空格分隔的字段：

```
1 cm=<64 hex> value=<n> asset=0 rkm=<64 hex> rho=<64 hex> rseed=<64 hex> shape=<S|P> at=<unix 秒>
```

- `cm` 是交易的第三个 commitment，和链上一致。
- `rkm`、`rho`、`rseed` 是四个 `u64` lane，各自按 little-endian 写成 64 位 hex。
- 不记高度，因为服务不知道交易会落在哪个块。读取方按 `cm` 去树里找。

*不会写入的情况：*
- 节点拒收的提交。
- 准入阶段被拒的请求。
- 同一笔交易的重放，它会被 nullifier 去重拒掉。

*写入失败时。* 提交已经无法撤回。服务会记 `error: annulet paid ledger write failed for cm=<hex>`，由运维手工补救。

*崩溃时。* 写到一半崩溃，可能留下没有换行的最后一行，读取方跳过它。

运维把这个文件拷到 payee 钱包所在的机器上，payee 的 seed 不上这台机器。然后用 `qumbra-wallet import-openings --net annulet` 导入，见 [`prover-payee-wallet-zh.md`](prover-payee-wallet-zh.md)。诚实的内核也会把第三个输出的 discovery 载荷加密给 payee，所以 payee 平常扫链就能找到这些 note。台账是为没这么做的钱包兜底的。

**34 上的配置**，在上面那张表之外（token 那几行不适用）：

| 变量 | 默认值 | 说明 |
|---|---|---|
| `QUMBRA_PROVER_ANNULET_GENESIS_FORMAT` | 33 | 设为 `34` 即服务三输出的 net |
| `QUMBRA_PROVER_ANNULET_PAYEE` | — | payee 的**完整** version-2 地址（`qs1…` 短地址只是哈希，无法校验）；按解码后的 `rkm` 比对 |
| `QUMBRA_PROVER_ANNULET_PRICE_S` | — | shape S 的价格，单位是 asset-0 的手续费单位 |
| `QUMBRA_PROVER_ANNULET_PRICE_P` | — | shape P 的价格 |
| `QUMBRA_PROVER_ANNULET_PAID_LEDGER` | — | 付费台账的路径，放在持久存储上 |

## 试点机器（prover-1）

- **主机：** r7g.2xlarge（64 GiB，arm64）。一次 P prove 的峰值约为 32 GiB。
- **容器：** `mem_limit` 约 58g，无 swap，`ulimits: core: 0`，在 `/scratch` 挂载一个 tmpfs（1g），根文件系统只读。
- **环境变量：** 上文列出的变量。该 net 在 lab #937 切换之前是 format 33，切换后改为 34；genesis hash 从 deploy 仓库取。node URL 必须指向一个接受 `POST /v1/tx` 的节点。
- **Ingress:** TLS、限流和请求头大小上限(Caddy),外加 non-loopback 确认项。安全组开放 443,因为扩展直接调用该服务。**`/v2/annulet/jobs/<cap>` 不要进 ingress 的访问日志**,或者只记路径前缀：这个 URL 里的 capability 就是该任务的秘密。
- **由运维人员持有、不放在机器上：** issuer seed。
- **需要运维手动完成的步骤：** 主机及其安全组的 Terraform apply、DNS、保管 issuer seed，以及手动启停主机。
