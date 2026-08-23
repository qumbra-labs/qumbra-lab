# 后端辅助证明 —— 可行性与安全交接

**状态:调研记录,不是 build plan。共享证明在算力拓扑上可行,但当前 trusted 形态
不能用于真实价值。不得把当前 paired-prover binary 直接暴露到公网。**
英文权威版:[`backend-assisted-proving-security.md`](backend-assisted-proving-security.md)。

写于 2026-08-23,接续手机自证明重新讨论。本文记录一条产品裁决和一条技术结论:

- **Larry 已决定:**要求用户自己运行常驻 prover 太麻烦,不在考虑范围内。产品不得
  建立在用户自己的 Mac、家用服务器或租用 VM 上。
- **已查证:**Qumbra 可以在不改 `CONSENSUS_CFG` 的前提下,为所有钱包运营一个公共
  逻辑 prover service;但协议不变时,这个服务有能力盗取 selected inputs。这是有用的
  可行性基线,不是可接受的产品架构。

"一个 service"不等于一个进程或一台机器。产品可以只有一个 endpoint,后面由准入
队列随需求增长,把任务派给多个隔离 worker。

---

## 1. 一句话答案

算力拓扑可以工作:保留 b16,手机本地选币并让用户确认,把 `WitnessBundle` 交给
Qumbra 运营的 worker,由它返回证明,最后仍由手机提交。**这个 trusted 拓扑本身不得
承载真实价值。** 公共产品还需要一份 worker 无法伪造的手机持有授权,或者一台运营方
无法读取的 attested confidential worker。

协议不变的 trusted 基线让所有支持手机都能 send,保留今天 148,625 字节的共识 wire,
也不需要 T2 重新 mint;但它拿 selected-input spend authority 来付账。这不是可以靠披露
接受的性质,而是淘汰条件。§8 的 authorization 设计能消除这份权限,但它本身是 T2
re-mint 级协议变更,wire/prover 成本仍欠测。

## 2. 已经存在的部分

当前拆分已经是正确的**功能接缝**:

1. 钱包扫描、扣除已花 notes、选 inputs、构造 Merkle witnesses、固定两个 outputs,
   然后产出带版本的 `WitnessBundle`。
2. Prover host 解码并重新验证 bundle,获取新鲜的公共 anchors/nullifiers,运行证明,
   返回规范交易字节。
3. iOS 钱包核对返回长度与 SHA3-256,再自己提交完全相同的字节。

本次交接查阅的版本与接缝:

| 仓库 | revision | 接缝 |
|---|---:|---|
| `qumbra-lab` | `1c5a27b` | `crates/qumbra-wallet/src/bundle.rs`、`spend.rs`; `crates/qumbra-ffi/src/pairing.rs` |
| `qumbra-wallet-macos` | `4bdde1d` | `rust/src/bin/qumbra-paired-prover.rs` |
| `qumbra-wallet-ios` | `e3a9e2d` | `PairedProverPipe.swift`、`SendFlow.swift` |

Mac 通道已经有全新 256-bit pairing secret、ChaCha20-Poly1305 framing、分方向 nonce、
严格 counter、bundle 校验、preflight、进度事件、artifact 分块和端到端 digest。这些部件
都能复用。但它的一次性 LAN 威胁模型不是公网服务安全设计。

## 3. 最关键的信任事实

`WitnessBundle` 不是不透明的证明提示。它会序列化每个 selected input 的 `sk`、value、
`rho`、`rseed`、diversifier 与 Merkle path
(`crates/qumbra-wallet/src/bundle.rs:33-40,385-401`)。模块顶层注释把它称为
"spend authority for exactly one transaction",并限定只能穿过用户本地可信边界。

这句话描述的是诚实实现预期的交接,不是对被修改 prover host 的密码学限制。Qumbra
现行交易模型把 spend-key knowledge 放在 STARK 内,没有另一份留在手机上的逐笔授权
签名。所以恶意 host 可以:

1. 读取 selected notes 的 openings 和 membership witnesses;
2. 无视收到 bundle 里用户批准的 output 字段;
3. 另造一组支付给自己的 outputs;
4. 自己证明并直接提交那笔冲突交易。

手机核对 host 返回的交易也堵不住这一攻击:host 可以给手机返回诚实 artifact,同时独立
提交冲突交易。最后是哪一笔落链,取决于 nullifier race。

爆炸半径有限,但足够严重:

- 服务**拿不到**钱包 seed,也拿不到本次 bundle 以外 notes 的 keys;
- 它能花掉 selected real inputs 的全部价值,包括本应作为找零返回的部分;
- 它能在同一点看到收款人/output 明文、amount、change、selected inputs、nullifiers、
  anchor、账户或设备身份以及来源 IP。

因此,Qumbra 运营的服务在技术上会暂时持有足以授权 selected-note spend 的材料。它在
法律上叫什么不属于本文范围;但从技术上,现行协议下不得宣传为 trustless 或
non-custodial,而且本文不建议把它用于真实价值。

## 4. 服务连通性基线

这张图只回答 apps、prover tier 与 Qumbra nodes 怎么连接,本身不是可上线安全设计。§8
必须用手机持有 authorization 或 attested confidential worker 替换图中标出的 trusted
worker 边界。

```mermaid
flowchart LR
    subgraph DEVICE["用户设备 —— 不运行 STARK proving"]
        IOS["iOS app"]
        ANDROID["Android app"]
        KERNEL["Wallet kernel<br/>scan • select • build • 用户确认"]
        LOCAL["始终留在设备<br/>wallet seed • 未选中 note keys"]
        IOS --> KERNEL
        ANDROID --> KERNEL
        KERNEL --- LOCAL
    end

    subgraph SERVICE["Qumbra prover service —— 一个公共逻辑 endpoint"]
        INGRESS["API ingress<br/>TLS 1.3 • 设备认证 • 限流"]
        ADMISSION["准入 + quota<br/>预留 worker lease"]
        WORKERS["Ephemeral prover workers<br/>每进程或 VM 只跑一个 job"]
        RISK["不可上线的 trusted 边界<br/>worker 看得到 selected-input 花费材料"]
        INGRESS --> ADMISSION --> WORKERS
        WORKERS --- RISK
    end

    subgraph NETWORK["Qumbra network"]
        READ["运营方固定 read endpoints<br/>compact • leaves • anchors • nullifiers"]
        SUBMIT["交易入口<br/>POST /v1/tx"]
    end

    KERNEL -->|"1. 从公共链数据 scan 与 select"| READ
    KERNEL -->|"2. 加密 WitnessBundle"| INGRESS
    WORKERS -->|"3. fresh GET anchors + nullifiers"| READ
    WORKERS -->|"4. 规范的已证明交易"| INGRESS
    INGRESS -->|"5. 加密 artifact"| KERNEL
    KERNEL -->|"6. 对照批准 bundle 后提交"| SUBMIT
```

**对,prover service 必须连接 Qumbra nodes。** 当前 preflight 会获取 node 现行合法
anchor 集合,以及直到当前 anchor tip 的 nullifier 历史。只要 bundle anchor 已不再被
接受、nullifier 覆盖不完整,或 selected input 已花,它就在分配 STARK 工作之前拒绝
(`crates/qumbra-wallet/src/spend.rs:358-405`)。Prover 不需要钱包 scan state、wallet
directory 或提交 credential。

Worker 访问 node 只做只读 preflight。`POST /v1/tx` 仍由手机负责。Worker 的 read
endpoints 与钱包预期的 network identity 都由运营方/app 固定;请求里绝不能携带任意
node URL。

Admission service 不应把明文 witness bundle 放进持久队列。优先采用两阶段协议:钱包先
拿到一个有边界的 worker lease,确认容量已预留后才上传加密 bundle。如果不得不用持久
队列,队列里只能放加密给 worker 层的 envelope,短期过期,edge 与日志层都没有解密 key。

每个 worker 在独立的非特权进程或 VM 内只服务一个 job,然后退出。常驻 coordinator
可以调度工作;真正接触 witness 的进程不得跨用户复用。

### 手机提交只是工程卫生,不是信任论据

提交方仍是手机,这样服务不持有提交 credential,而 incomplete/duplicate 恢复继续留在
钱包现有的类型化流程里。这是值得做的工程卫生,不是 selected-input theft 控制:恶意
worker 可以自己连接同一个公共 node,提交它的冲突 proof。架构图画的是诚实数据流,
不是能挡住 §3 的安全边界。

## 5. 任何公网 pilot 之前的 P0 门槛

| 风险 | 当前接缝事实 | 必须过的门槛 |
|---|---|---|
| Selected-input 被盗 | worker 收到 input `sk` 与 witness | 这个形态不得承载真实价值。必须采用 §8 的手机持有授权,或由钱包在上传前验证 measurement/key 的 attested worker |
| SSRF / 访问内网 | 客户端提供 `scan_url` 与 `node_url`;`required_url` 只检查 `http://` 或 `https://` 前缀(`qumbra-paired-prover.rs:286-289,411-415`) | 从公共请求删除 URL。只接收 network identifier,由服务映射到运营方固定 endpoints。禁止 worker 访问 loopback、私网、cloud metadata 及其他任何出站目标 |
| 计算耗尽 | 一个 b16 proof 是约 12–15 GB 级任务;目标部署机尚未实测 | 准入之前先认证;限制队列深度、每设备 jobs、全局并发、证明最长时间与重试。支持协作取消,或在 lease 到期时杀 worker |
| 认证前内存耗尽 | 服务端接受攻击者声明的最大 128 MiB 加密帧,并在 AEAD 认证前分配(`qumbra-paired-prover.rs:180-213`) | 按实际格式测量后设置接近真实 bundle 的上限;先认证一个很小的固定首帧,再分配 payload |
| 手机内存耗尽 | 手机接受服务端声明的 `byte_length/chunk_count`,然后直接分配 `vec![None; chunks]`(`crates/qumbra-ffi/src/pairing.rs:585-599`) | 限制 artifact 总字节、chunk 数、每 chunk 字节、事件数与总响应字节;chunk 数必须从声明长度推导 |
| 慢连接占坑 | 当前 listener 同步逐个处理连接,handshake I/O 预算 30 秒(`qumbra-paired-prover.rs:84-99`) | 前面加有界并发认证 ingress;限制 header/read deadline、每来源连接数和全部未认证内存 |
| Witness 落盘 | 普通 heap 副本可能进入 swap、core dump、崩溃报告、trace 或被复用 allocator | payload 不进日志/trace;禁 core dump;secret 不进 metrics/error;worker 避免 swap;可明确清除的 buffer 做 zeroize;每个 job 后退出销毁 worker |
| 可复用 bearer secret | 当前对称 key 来自 QR secret 与公开 server nonce;只有每进程换全新 secret 才适用 | daemon 不得复用现有 QR 协议。注册每安装实例的非对称设备 key,认证服务身份,每次 ephemeral key exchange 提供 forward secrecy,支持设备轮换/撤销,每个 job 绑定唯一 challenge |
| 错网络/config | 当前请求只写 URL,没有固定 genesis 与 consensus config | protocol version、network ID、genesis hash、consensus-config label 必须同时绑定到 request、preflight、artifact 与 audit event;证明前任何不一致都拒绝 |
| 结果被替换或畸形 | 手机目前只证明 bytes 符合同一个 server 自己声明的 digest | 提交前解码 `TxEntry`,把 anchor、nullifiers、commitments、fee、discovery、rider 与已批准 bundle 逐项比较。这能抓 bug/替换,但挡不住 §3 的 host 直接提交攻击 |
| Worker 被攻破并横向移动 | 公共 worker 在短暂持有 spend authority 时解析攻击者数据 | 非特权运行、只读镜像、无 shell、无 cloud credential、禁止 metadata、最小文件系统、严格 syscall/network policy、每进程/VM 只放一个 tenant;部署 artifact 签名并 pin |

这些是上线门槛,不是以后再补的 hardening 清单。当前 binary 完成的是它原本设计的安全
性质 —— 一台可信手机在可信 LAN 上发一次请求 —— 不能把它当作已经通过了公网这道完全
不同的门槛。

## 6. 认证、滥用控制和隐私互相牵制

一个匿名 endpoint 每次请求分配 12–15 GB,就是开放的算力放大器。传统用户账户能解决
quota 归属,但会创造持久的钱包—身份关联。只按 IP 限制既容易绕过,也会误伤 carrier
NAT 后面的用户。

合理起点是钱包生成每安装实例的非对称设备 key,服务给它发 quota credential。它认证
的是一台设备,不是法律身份。但设计仍欠一项 Sybil/成本决定:app attestation、邀请/quota
token、匿名限流凭据、付费,或若干组合。没有免费选项,实现前必须写清隐私性质。

### 两条独立的上线门槛

盗币与可关联性是两种不同失败。修好其中一条不代表另一条也好了:

| 门槛 | 问题 | Trusted worker | 手机持有授权 | Attested confidential worker |
|---|---|---|---|---|
| **不能盗币** | 服务能否授权手机没批准的 outputs? | **失败** | 只有共识把手机专属签名绑定到完整 intent 时才通过 | 只有接受 attested image/hardware 假设时才通过 |
| **不能看见/关联** | 服务能否把 input、output、amount、recipient、nullifier、device 与 IP 拼在一起? | **失败** | **仍然失败** —— authorization 防盗,不防观察 | 只有 bundle 直接加密给 attested worker 才能减少 host/operator 接触;ingress/device/IP metadata 仍需另一份隐私设计 |

可上线设计必须写明每条门槛覆盖哪个 adversary。匿名 quota credential、最小日志、
ingress identity 与 worker payload 分权、以及可能的 relay 可以降低关联性。但这些都不能
让普通非 confidential worker 看不见 witness。反过来,authorization signature 可以让
witness 在 spend integrity 上安全地暴露,同时服务仍然看得见整笔交易关系。

不管选哪种,协议最低要求都是:

- 唯一且会过期的 job ID,绑定认证请求与 bundle digest;
- 无需保留明文 bundle 的幂等状态/结果查询;
- 一个已接受 lease 不能同时启动两个 prove;
- 响应丢失时有边界的 retry 语义;
- 普通日志不得包含 recipient、amount、nullifier、bundle digest、IP 或 device key;
- abuse metadata 与 proving payload 分权访问并短期保留。

## 7. 容量与可用性

一个公共逻辑 endpoint 可以服务所有人,一个 prover 进程不可以。Pilot 可以故意从一个
排队 worker 起步;生产容量靠横向 worker,每个 worker 只为一个 proof 预留内存。

定容量之前,必须在真实部署 CPU/内存配置上测当前电路:

- peak RSS 与 peak committed memory;
- cold/warm prove time;
- 每 host 一个 worker 与安全并发时的耗时/内存方差;
- kill job 后取消延迟与内存归还;
- bundle 与 artifact 字节分布;
- 每个成功 proof 和每个被拒绝/放弃 job 的成本。

集中证明也会成为审查与可用性依赖。它需要公开的降级方式、UI 里有边界的排队估计、
在成为唯一 send 路径之前覆盖多个故障域,并明确区域性或全局故障时钱包怎么办。
"稍后再试"是诚实答案;无限 spinner 不是。

## 8. 可以上线的远程证明设计空间

| 路线 | 是否改共识 | Selected-input theft | 可关联性 | 状态 |
|---|---|---|---|---|
| Trusted Qumbra worker | 不改 | **worker 能盗币** | worker 与 ingress 都能关联 | 只作为可行性基线;不得承载真实价值 |
| 手机持有的 transaction-intent authorization | 要改 | 绑定正确时,worker 无法伪造另一份 intent | 服务仍能看到 witness 与交易关系 | 下文的候选协议设计 |
| Attested confidential worker | 原则上不改 | attestation/isolation 成立时,host/operator 不能盗币 | 可减少 host 看到 payload;ingress metadata 仍在 | 下文的具体测量路线 |
| MPC / 加密外包证明 | 很可能大改 | 目标是不让任何单个 worker 有盗币能力 | 可能减少 witness 可见性 | 研究项目,不是当前 launch 路径 |

### 8.1 候选 A —— 手机持有 transaction-intent authorization

这是目前从代码里看得到的最小设计,不是已经批准的协议。手机在证明前已经构造完整
intent:`WitnessBundle` 固定 anchor、真实 nullifiers、两个 output plaintext/commitment、
fee、已承诺 discovery bytes 与 rider。缺的是一把能授权这些字节、却永不进入 bundle
的 secret。

决定设计形状的当前约束:

- 一个 `sk` 同时派生 `nk`、nullifier 与 `rkm`;远程 prover 会收到它
  (`qlab-air/src/narrow.rs:1183-1198,1289-1324`);
- note 当前只承诺 `(value, rkm, rho, rseed)`
  (`qlab-note/src/note.rs:22-50`);
- STARK public values 只有 anchor、两个 nullifiers、两个 output commitments 与 fee
  (`qlab-air/src/narrow.rs:261-290`);
- `TxPublic` 也是同一表面,discovery 与 rider 在 `TxEntry` 旁边
  (`qlab-devnet/src/body.rs:166-214`)。

一份候选 fixed-shape 构造如下:

1. 手机为每个 note 派生独立 authorization secret `ask_i` 与相应的 post-quantum public
   key `apk_i`。`ask_i` 永不进入 `WitnessBundle`;spend secret 的 proving component
   仍会进入。
2. 把 `apk_i` 绑定进 note commitment 路径 —— 例如扩展 note plaintext/commitment,
   或扩展 `rkm` 派生。STARK 必须证明每个公开的 `apk_i` 属于同一个 input note,
   也就是它正在证明 membership/nullifier 的那一个。只把 key 摆在 proof 旁边不算绑定。
3. 定义唯一规范 intent digest,至少覆盖:

   ```text
   domain || protocol_version || network_id || genesis_hash ||
   anchor || nf_0 || nf_1 || cm_out_0 || cm_out_1 || fee ||
   H(discovery_bytes) || H(rider_bytes) || expiry/replay_domain
   ```

   Discovery 与 rider 即使不在今天的 STARK public-value vector 里也必须覆盖;否则
   worker 可以改写 recipient delivery material 或 name operation 而不破坏授权。
4. 手机用每个 fixed input slot 的 authorization key 给 digest 签名,只把 signature/public
   key 连 bundle 一起发送。即使一个 spend input 是 dummy,仍保留两个 authorization
   slots,避免泄露 frozen 2×2 shape 今天隐藏的真实 input 数。Dummy slot 可以使用手机
   临时生成并持有的 authorization key。
5. Proof 公开并绑定两个 `apk_i` 到 input-note relations。Node 在接受交易前,用同一
   canonical digest 验 signatures。STARK 外的 native verification 是当前最小假设;
   把 signature verification 放进 STARK 是另一条路线,需要单独计价。

在这份构造下,worker 可以重新随机化/重建 proof,也可以提交手机已经授权的交易,但只要
改一个 intent 字段,就必须伪造手机持有的 signature。Replay 带相同 nullifiers,退化成
现有 duplicate 规则。服务仍能审查并关联 spend;这份设计通过的是**不能盗币**,不是
**不能看见/关联**。

#### 协议与 T2 成本

这是 T2 re-mint 级变更,不是 API addition:

- note plaintext/commitment 或 `rkm` 派生改变,既有 notes 没有 authorization key;
- input witness/AIR relations 与 public-value layout 改变;
- `TxPublic`、`TxEntry`、P2P/body codecs、transaction ID/preimage rules 与 node verifier
  增加 authorization 字段与检查;
- frozen genesis 参数与 consensus wire-size pin 移动。

干净的 T2 re-mint 能让所有 live notes 都采用新形状。Height-gated legacy path 只有通过
永久保留旧 note verification,并继续为旧 notes 保留 trusted remote-spend 路径,才能
避免 re-mint —— 这与手机 b4 handoff 里 dual FRI verification 的历史负担同类。

成本量级尚未测量。它取决于 post-quantum authorization primitive、public keys 能否紧凑
承诺并逐 note 派生、signature 是 native 还是 STARK 内验证,以及额外 public-value/AIR
openings。Post-quantum spend-authority 设计不能悄悄假设 classical signature。最低要量:

- 两个固定 authorization public-key/signature slots 加 codec framing 的字节数;
- b16 下的新 circuit width/permutation count、peak prover memory、prove time、proof bytes
  与 verifier time;
- note plaintext/discovery 增长与 scan 成本;
- 公开 one-time authorization public keys 的隐私影响;
- activation boundary 两侧的 migration/replay 行为。

这份成本必须直接与 b4 的 re-mint 级成本比较。Backend 那一行不能一边默认已被淘汰的
trusted 模型,一边写"T2 consequence:none"。

### 8.2 候选 B —— attested confidential worker

Attested confidential VM 是目前唯一看得到的路线:保留今天的共识协议,同时不让普通
Qumbra/cloud operator 看到 witness 明文。它不是"给 VM 套 TLS"。钱包必须验证一份
remote attestation,确认 ephemeral encryption key 绑定到获准的 worker image 与安全
配置,再把 bundle 直接加密给那把 key。Ingress/queue 不得拥有解密能力。

Measured image 必须 pin prover binary、consensus config、protocol version、node allowlist、
debug-disabled 状态与 result-encryption 行为。Worker 仍只允许只读访问固定 nodes。结果
加密回钱包,job 后销毁 VM。

Go/no-go 问题很具体:当前 12–15 GB 级 b16 job 能否放进所选 SEV-SNP/TDX 级
confidential-VM offering,并达到可接受性能?把它当产品选项之前,应跑一条专用 lane:

1. 在完全相同的 confidential instance type 上证明当前电路,记录 peak private memory、
   cold/warm time、失败行为与成本;
2. iOS 与 Android 都验证完整 attestation 和 image/config measurement,包含 stale、debug、
   wrong-image 与 revoked-key negatives;
3. 证明 bundle 在 ingress、queue、host、snapshot、swap、crash collection 与 operator
   observability 全程保持加密;
4. 测 host/guest rollback、job replay、cancellation 与 teardown;
5. 明写接受哪些 hardware、firmware、cloud、side-channel 与 availability 信任。

Attestation 不会自动解决 linkability。Ingress 即使解不开 witness,只要认证 device 并看到
IP,仍能把 job timing 与随后上链的 transaction 联系起来。这需要 §6 的独立隐私控制。

### 8.3 延后路线 —— MPC 或加密外包证明

如果能在没有任何单个 worker 学到 witness 的条件下计算 STARK,就能在没有 hardware
root of trust 的情况下同时解决 operator theft 与部分 payload visibility。当前代码没有
这个接缝,性能与复杂度也未计价。它继续作为研究,但不能成为不去计量上面两个具体候选
的理由。

## 9. 与 b4 决策的关系

Backend-assisted proving 是手机决策里原先缺失的分支:

| 选择 | 所有支持手机都能 send | 共识 wire | T2 后果 | 永久依赖 |
|---|---|---:|---|---|
| b4 本地证明,无远程 fallback | 不行 —— 低内存手机被排除 | 旧 mint 前数据约 236 KB;当前值欠测 | 重新 mint 或永久双验证器 | 只有够强手机能诚实本地证明 |
| b16 + trusted Qumbra backend | 可以 | 今天 148,625 字节 | 无 | **不可上线:**服务能盗取 selected inputs 并关联 spend |
| 共享 b16 backend + 手机持有 authorization | 可以 | 148,625 字节 + 未测 proof/auth/wire 增量 | 重新 mint 或永久 legacy verifier/note path | 绑定正确时服务不能盗币;仍能看见并审查 |
| Attested confidential b16 backend | 原则上可以 | 今天 148,625 字节 | 原则上不需 protocol re-mint | hardware/cloud/attestation 信任;fit/performance 未测;ingress linkability 仍在 |
| 当前每笔 Mac 配对 | 只有用户每笔都操作 Mac 才能 | 今天 148,625 字节 | 无 | 产品 UX 已拒绝 |

因此,诚实产品比较是 **b4 本地证明** 对 **b16 backend + authorization/attestation**,
不是 b4 对"相信 Qumbra"。手机持有 authorization 与 b4 都是 T2 re-mint 级变更;
必须在当前电路上实测各自 wire、prover 与 migration 成本。

如果所有支持手机都必须 send,b4 自己不完整。低内存 fallback 仍需要与共享 backend
同样的 authorization 或 confidential-worker 保护,所以 b4 可能既要付更大 proof 的成本,
又要付 remote-prover security 的成本。

## 10. 仍欠的决定与证据

选 build plan 之前:

1. 把 §8.1 展开成 protocol spike,在当前电路上直接与 b4 比较 re-mint、wire、隐私与
   prover 成本。
2. 跑 §8.2 的当前 b16 confidential-VM fit/attestation lane,让"不改协议"选项有证据,
   不只是一行标签。
3. 决定上线范围:T2-only 实验、mainnet 可选路径,还是手机默认/唯一 send 路径。
   Trusted worker 只可用于无真实价值的服务机制实验,不能用于 real-value launch。
4. 决定 device credential 与滥用控制模型,不能悄悄造出一个钱包身份系统。
5. 定 retention、logging、incident response、queue/SLO 与 outage policy。
6. listener 暴露之前,分别对最终协议和部署做 threat model。

容量或成本声明之前要收的证据:

1. 目标 worker host 上当前 b16 的 peak memory 与 prove-time 分布。
2. 真实 bundle/artifact 上限,用来替换两边的 128 MiB protocol ceiling。
3. 一次 red-team drill,覆盖 SSRF、slowloris、未认证分配、认证 job flood、恶意 result
   size、disconnect/cancel、core dump、日志泄漏与 worker escape。
4. 一次端到端 drill,证明只要返回 artifact 的公共交易面与批准 bundle 任一项不同,
   手机就拒绝。

### 不需要产品决定的独立修复

替换两边的 128 MiB protocol ceiling 不依赖任何产品路线。测量当前最大合法
`WitnessBundle` 与 transaction artifact,取一个小倍数作为明确 request/response ceiling,
从 byte ceiling 推导 chunk count,并在独立 PR 里加 boundary tests。这会同时加固现有
trusted-LAN 工具与所有未来 transport,而不承诺 backend 架构。

## 11. 本次交接的范围

- 用户自己运营常驻 prover 已按产品裁决**排除**。
- 产生本文时没有构建 backend service、daemon、cloud resource、账户系统或协议改动。
- `CONSENSUS_CFG` 未被触碰。
- 当前 paired-prover 仍然只是可信 LAN 上的一次请求工具。
