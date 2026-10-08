# Annulet 证明服务——运维指南

*英文版：[`prover-service-annulet.md`](prover-service-annulet.md)。技术细节以英文版为准。*

Lab issue #924，5A-D3/D4。代码：`crates/qumbra-prover-service`（`src/annulet.rs`、`src/token.rs`）。

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
5. 在本 net 上运行 bundle 的 lock → `422`，错误码为 `statement-mismatch`、`unauthorized-section`、`proof-present`、`auth-missing` 或 `outputs-not-the-nets`（lab #937：bundle 的输出数与本 net 不符，例如 format 33 上的三输出 bundle）。

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
| `QUMBRA_PROVER_ANNULET_PER_DAY` | 20 | token 中写 0 时使用的默认值 |
| `QUMBRA_PROVER_TOKEN_KEYS_FILE` | — | 每行一条 `key_id verifying_key_hex` |
| `QUMBRA_PROVER_TOKEN_DENY_FILE` | 未设置 | 已吊销的 token id |
| `QUMBRA_PROVER_SCRATCH` | — | **必须是 tmpfs 挂载**（启动时检查；仅 Linux） |
| `QUMBRA_PROVER_LISTEN`、`QUMBRA_PROVER_ALLOW_NON_LOOPBACK_LISTEN` | 同 L1 | TLS、限流和请求头大小上限都在 ingress 层 |

## worker 子进程

证明一次只跑一个，每个都在全新的 `annulet-worker` 子进程中运行：

- 环境变量被清空，只保留协议标签和 genesis hash，因此子进程没有 URL，也没有 token；
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

## 试点机器（prover-1）

- **主机：** r7g.2xlarge（64 GiB，arm64）。一次 P prove 的峰值约为 32 GiB。
- **容器：** `mem_limit` 约 58g，无 swap，`ulimits: core: 0`，在 `/scratch` 挂载一个 tmpfs（1g），根文件系统只读。
- **环境变量：** 上文列出的变量。该 net 为 format 33；genesis hash 从 deploy 仓库取。node URL 必须指向一个接受 `POST /v1/tx` 的节点。
- **Ingress:** TLS、限流和请求头大小上限(Caddy),外加 non-loopback 确认项。安全组开放 443,因为扩展直接调用该服务。**`/v2/annulet/jobs/<cap>` 不要进 ingress 的访问日志**,或者只记路径前缀：这个 URL 里的 capability 就是该任务的秘密。
- **由运维人员持有、不放在机器上：** issuer seed。
- **需要运维手动完成的步骤：** 主机及其安全组的 Terraform apply、DNS、保管 issuer seed，以及手动启停主机。
