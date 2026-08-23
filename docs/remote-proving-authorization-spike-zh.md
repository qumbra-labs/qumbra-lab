# 远程证明——Phase 1 授权 spike

**状态：2026-08-23 的研究 spike；不是 primitive 选择，也不是实现批准。本次
修改中的任何内容都无法从正式 wallet、node、交易 codec、AIR、genesis 或 service
到达。** 跟踪
[lab issue #630](https://github.com/qumbra-labs/qumbra-lab/issues/630)，英文配对文档为
[`remote-proving-authorization-spike.md`](remote-proving-authorization-spike.md)。

上位裁决仍是
[`remote-proving-candidate-ruling-zh.md`](remote-proving-candidate-ruling-zh.md)：
对承载真实资产的共享 prover，节点共识绑定且私钥留在手机的授权（Candidate A）
是强制基础；confidential worker（Candidate B）只是可选的隐私加固。

---

## 1. 结果与建议

Spike 在相同的固定双输入形状和同一 complete intent 下实现、比较了三种 leaf：

| 方案 | 状态属性 | 精确的双 slot auth section | 结果 |
|---|---|---:|---|
| FIPS 204 ML-DSA-44 | 签名 key 可安全复用；rotation 不复用是隐私规则，不是防伪造规则 | 7,544 B | **唯一建议推进的 primitive，且必须放入 rotation tree** |
| RFC 8391 `WOTSP-SHA2_256`，stateful index | OTS index 绝不能复用 | 4,432 B | **阻塞：**有效旧备份和两台设备都会复用 index |
| RFC 8391 `WOTSP-SHA2_256`，random index | 不需要 journal，但 index 碰撞是灾难性的 | 4,432 B | **只保留作 comparator：**实际碰撞界不可接受 |

Primitive 和 commitment 形状的决定现在已经明确：推进 **ML-DSA leaf rotation
tree**，不推进 depth 0。Depth-0 verifying key 是公开、稳定的 sender-address
fingerprint。由于 slot 0 永远是真实输入，而 dummy slot-1 key 是 ephemeral，历史记录
还会把可复用真实 key 变成一种延迟出现的 distinguisher，用于区分单真实输入与双真实
输入 spend。即使 ML-DSA key 复用不会破坏 unforgeability，这仍然是隐私失败。

Rotation tree 每层增加两个 Merkle-path permutation，建地址成本为 `O(2^D)`，并让
任何实用 depth 都进入 2^19 rows。Spike 实现了私有、deterministic、without-
replacement 的 shuffle，因此公开 leaf index 既不是顺序 ordinal，也不是会碰撞的
独立随机抽样。这只是一项**公开／链上不可关联性**改进。普通 Candidate A prover 会
看到每条私有授权路径，可以恢复稳定的 per-address `auth_root`；若未来 envelope 保留
`nk`，它还可以把整个 wallet 的 job 关联起来。

生产环境的持久化、恢复和多设备分配仍是 gate。这里不会猜最终固定 depth：D12 到
D16 必须先完成手机实测，再写 binding-design correction；选定的 `D` 必须是全网统一
的 protocol constant，不能由各 wallet 自选。Depth 0 只保留为无资产 mechanics
comparator。本 spike 不会把任何形状变成共识规则。

## 2. 已实现内容

仅用于研究的 [`qlab-remote-auth`](../crates/qlab-remote-auth/) crate 包含：

- scheme 固定宽度的 complete-intent preimage：ML-DSA 为 372 字节、WOTS+ 为
  436 字节；
- 使用 workspace 已 pin 的 `ml-dsa = 0.1.1` 生成的 deterministic FIPS 204
  ML-DSA-44 vectors；
- RFC 8391 `WOTSP-SHA2_256` 的 F/H/PRF、address、base-w checksum、chain、
  L-tree compression，以及 RFC 作者采用的 HRS16 key expansion；
- 无 length field、严格固定双 slot 的 authorization-section codec；
- 绑定 domain、level 和左右方向、但没有公开 ML-DSA 地址标签的外层 Keccak tree；
- 不放回抽样的私有 ML-DSA leaf permutation；
- 要求两个 slot 都在手机批准前已存在的可执行 hidden-dummy 接受模型；
- 带 checksum、先持久化再导出 index 的 WOTS+ journal，以及可执行的旧备份／
  双设备失败模型；
- 精确的 birthday bound 和候选 AIR geometry 报告；
- byte-exact fixture，以及逐字节重新生成 fixture 的 integration test。

命令入口为：

```console
cargo run -p qlab-remote-auth --bin qlab-remote-auth-spike -- report
cargo run -p qlab-remote-auth --bin qlab-remote-auth-spike -- vector
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- measure --iterations 100
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- address mldsa 12
cargo run --release -p qlab-remote-auth --bin qlab-remote-auth-spike -- address wots 12
```

后三个是 measurement instrument，不是已经发布的手机或生产 benchmark。本记录
不会把没有运行的命令写成 evidence。

## 3. Complete intent 与 canonical codec

Spike 签名的是 `Keccak256(intent_preimage)`；固定宽度 preimage 为：

```text
"qumbra:remote-auth:intent:v1"
|| version_le16
|| genesis_format_le32 || genesis_hash
|| anchor
|| nf[0] || nf[1]
|| cm[0] || cm[1]
|| bucket_u8 || fee_le64
|| Keccak256(discovery_bytes)
|| Keccak256(rider_bytes)
|| scheme_u8
|| auth_descriptor[0] || auth_descriptor[1]
```

Descriptor 的宽度由 scheme 固定：

- ML-DSA 为 36 字节：`leaf_index_le32 || leaf[32]`；它有意不携带公开的
  per-address context。
- WOTS+ 为 68 字节：`public_seed[32] || leaf_index_le32 || leaf[32]`；native
  verification 需要 RFC 8391 public seed。

因此 complete preimage 对 ML-DSA 是 372 字节，对 WOTS+ 是 436 字节。Scheme tag
将 stateless ML-DSA、stateful WOTS+ 和 random-index WOTS+ 的安全契约隔离开，
即使两种 WOTS+ 使用同一个 primitive。任何语义字段变化都会改变 digest。未来新增
语义字段必须升级版本，不能追加到旧 signer 会忽略的位置。

Spike authorization section 以固定 magic `QRA1`、version、scheme、slot count
开头。Scheme 决定其后所有字段宽度；decoder 会拒绝未知 scheme、错误 slot 数、
截断、错误 payload 宽度和 trailing byte。

| 组件 | ML-DSA-44 | WOTS+ |
|---|---:|---:|
| header | 8 | 8 |
| 两个 slot 的 descriptor | 72 | 136 |
| 每 slot verifying key | 1,312 | 0；恢复出的 32-byte leaf 已在 descriptor 中 |
| 每 slot signature | 2,420 | 2,144 |
| **双 slot 总计** | **7,544** | **4,432** |

精确差值是 3,112 字节。这些是 spike section bytes，不是生产交易 wire 的决定。

Binding wire 规格还必须决定 transaction identity 是否承诺 authorization section，
并据此统一规定 body/P2P encoding、mempool deduplication、wallet history join 与 replay
行为。本 spike 有意不做这项 transaction-ID 决定。

未来 node 的强制顺序应是：严格 decode；从真实交易重建 complete intent；要求
descriptor 完全相等；验证两份手机授权；最后才投入 STARK verification 成本。
Crate 模拟了这个顺序，但有意没有接入当前 node。

## 4. Note binding 与候选 AIR 算术

一种候选 note binding 是扩展现有 `ROLE_ARKM` absorb：

```text
rkm = Keccak256(nk || D_R || d || auth_root || pad10*1)
```

按当前 lane 写法，`nk` 占 lanes 0..3，domain 占 lane 4，diversifier 占
lanes 5..6，authorization root 占 lanes 7..10，pad start 在 lane 11，rate 最终
bit 在 lane 16。因此它可以放进一个 17-lane Keccak rate block，并让原 context
lanes 保持空闲。这只是 spike 算术；binding design spec 仍须确定生产使用的
field/byte encoding，并完成 domain review。

Node 对 ML-DSA leaf 的计算是
`Keccak256(leaf_domain || leaf_index_le32 || verifying_key)`。外层 parent 绑定 node
domain、level、left child 和 right child，但不包含公开地址标签。地址隔离来自每个
收款地址唯一的私有 derivation master 和由此生成、隐藏的 `auth_root`，而不是重复
出现的 wire value。对 WOTS+，native verification 使用 descriptor 中的 public seed
恢复 RFC L-tree leaf。未来 AIR 只需把 public leaf 沿授权路径折叠，并通过同一份
hidden note material 绑定 root；不需要在 STARK 内验证任一签名。

Authorization path 和 `auth_root` 都是 STARK-private witness：绝不能进入 authorization
section、transaction body 或 STARK public values。但普通 worker 在 proving 时仍会看到
它们，并可用稳定的 `auth_root` 关联同一地址的 job。若把 path 发布出去，任何链上观察者
都能计算同一个 cluster，移除 `tree_context` 所取得的公开不可关联性将被完全抵消。

从当前 84 个 permutation slot 出发，删掉两个 `ROLE_ANK`，再加入两个 depth-`D`
路径，得到 `82 + 2D` slots：

| depth | 含义 | slots | active rows（`slots × 3,072`） | padded trace |
|---:|---|---:|---:|---:|
| 0 | 可复用 ML-DSA leaf，无 path | 82 | 251,904 | 2^18 |
| 1 | 最小非空 tree | 84 | 258,048 | 2^18 |
| 12 | 4,096 leaves | 106 | 325,632 | 2^19 |
| 16 | 65,536 leaves | 114 | 350,208 | 2^19 |
| 20 | 1,048,576 leaves | 122 | 374,784 | 2^19 |
| 31 | spike 模型支持的最大 index 范围 | 144 | 442,368 | 2^19 |

`report` 会输出 0..31 的每个 depth。这里没有实现或测量 AIR、selector、
public-value bank、quotient degree、proof size、RSS 或 proving time 的变化。

## 5. Hidden dummy 规则

当前隐私形状保证 slot 0 为真实输入，并隐藏 slot 1 是真实 note，还是 value 为零
且 off-tree 的 dummy。候选规则保持这个形状：

1. 两个 slot 都始终有有效 authorization signature、descriptor、path 和
   root-to-note binding；
2. slot 0 始终证明 note-tree membership；
3. 双真实输入时，slot 1 也证明 note-tree membership；
4. 单真实输入时，slot 1 改为证明现有 hidden zero-value dummy 条件；
5. 不新增 public dummy flag。

手机必须先生成 dummy slot 的 ephemeral key、descriptor、随机 path material 和
hidden root，再构造并签名 common intent。手机用两个 slot key 签署同一个完整
intent，之后才上传 proving envelope。Worker 不得生成或替换 dummy authorization
material：两个 descriptor 都在 digest 内，手机签名之后才创建的材料从未获得批准。
Dummy 的随机 path 可以直接生成 sibling node，不需要构造完整地址树；其 public
descriptor 仍保持完全相同的形状。它的 `leaf_index` 也必须从与真实 leaf 相同、全网
固定的 `[0, 2^D)` 范围均匀抽样；只有形状相同而分布不同，仍会成为公开的单真实输入
distinguisher。如果删掉“slot 0 永远真实”这个 invariant，本规则仍会失效。

## 6. WOTS+ 的精确性和状态失败

Comparator 使用标准 RFC 8391 `WOTSP-SHA2_256` 形状：`n = 32`、`w = 16`、
`len_1 = 64`、`len_2 = 3`、`len = 67`，signature 为 2,144 字节。生成一个
leaf 需要 67 次 private-element expansion、1,005 个 chain step 和 66 个
L-tree node。按 RFC SHA-256 construction 计算，精确为 3,346 次 SHA-256。

Fixture 的完整 signature 和 32-byte leaf 已与 RFC 作者 reference implementation
的 commit `171ccbd26f098542a67eb5d2b128281c80bd71a6` 逐字节比较一致；参见
[`fixtures/README.md`](../crates/qlab-remote-auth/fixtures/README.md) 和
[`authorization-v1.txt`](../crates/qlab-remote-auth/fixtures/authorization-v1.txt)。

42-byte journal 会先持久化 increment，再导出 reserved index；取消 job 仍会烧掉
这个 index。这能关闭单个当前 state file 内的 crash window，但无法区分有效旧
备份与当前状态；从同一状态恢复的两台设备也都会 reserve index 0。两种失败状态
都能通过 journal checksum。因此这个可执行模型确认、而不是解决了
[NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) 和
[RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html) 所描述的 P0 blocker。

## 7. Random-index 碰撞 evidence

深度 `D` 的一棵 tree 使用 `q` 次时，spike 使用规定的 ideal-uniform union bound：
`min(1, q(q-1)/2^(D+1))`。对 `T` 棵独立 key 的地址树，multi-target bound 是
`min(1, T × per_tree_bound)`；不同 tree 使用相同 index 没有问题，任何一棵 tree
内部复用才是灾难事件。

可执行的 1..31 报告中，部分结果为：

| D | 每地址 uses | 单 target | 1,000 targets |
|---:|---:|---:|---:|
| 12 | 10 | 1.099% | 100% cap |
| 16 | 100 | 7.553% | 100% cap |
| 20 | 100 | 0.4721% | 100% cap |
| 24 | 100 | 0.02950% | 29.50% |
| 31 | 1,000 | 0.02326% | 23.26% |

即使 depth 31 的 multi-target 行也不能作为资产安全基础，而且构造 `2^31`
leaves 不具备产品可行性。单棵 WOTS+ tree 的 random leaf 不是 SLH-DSA，不能继承
FIPS 205 的 FORS/hypertree security argument。

## 8. Wire 与 proof-size 后果

今天的 148,625 字节是序列化后的 **STARK proof**，不是完整交易。只加入 spike
authorization section，尚未计入新 public value 和 proof 增长时，下界已是：

| 方案 | 当前 proof | auth section | 仅 proof + auth |
|---|---:|---:|---:|
| ML-DSA-44 | 148,625 | 7,544 | 156,169 B |
| WOTS+ | 148,625 | 4,432 | 153,057 B |

这些和数既不是未来 proof，也不是完整交易的预测；它们说明如果把 ≤150 KB
解释为全量 transport artifact，目标已经超出。现有 regression target 只针对
proof，未来 proof 仍必须重新测量。Depth 0 可能保持 2^18 height，但不满足已经选择
的隐私形状；实用 tree 会升到 2^19。Proof bytes、完整 transaction bytes、prover
RSS/time 和 node verification time 都仍是 open gate。

## 9. 手机生命周期与隐私

对 ML-DSA，手机持有的 wallet master 为每个收款地址派生唯一的私有 master，再由
后者派生整棵树的 leaf key。候选 selector 用私有 address seed 对所有 index 做
deterministic shuffle，并以不放回方式消耗。一旦实测选定 `D`，该网络上的每个 wallet
都必须使用同一个值。

生产状态必须 crash-safe，并在任何 authorization bytes 离开手机前，把 index 绑定到
一个 intent digest 后持久化 reserve。同一 job 重试时复用完全相同的 signed envelope；
新的 digest 绝不能复用已 reserve 或已导出的 leaf。本地准备若在导出前放弃，可以释放
reservation；一旦导出，即使 prover 失败、扣留结果或交易从未上链，该 leaf 也永久视为
已消耗。耗尽时必须拒绝 spend，绝不能 wrap。Service failure 不得悄悄跳到下一个 leaf，
也不得通过不同错误暴露“剩余 leaf 数量”oracle。

Shuffle 本身没有解决恢复和多设备分配。扫链能找回已上链 descriptor，却无法发现已经
离开手机但从未上链的 authorization。因此生产环境需要 rollback-resistant、已备份的
reservation state，或明确规定的安全 tree migration；wallet 恢复后若无法证明状态是
最新的，就必须拒绝从这棵状态不明的 tree 做远程 spend。并发设备必须使用协调 lease
或密码学上不重叠的 allocation。复用是隐私失败，但不是 WOTS+ 那种伪造失败。创建或
缓存 `2^D` public leaves 的地址构建成本仍未实测。

Stateful WOTS+ 要求当前 wallet 产品并不具备的 rollback-proof、跨设备协调状态。
Random-index WOTS+ 不需要 journal，却换成了有明确数值的灾难性碰撞风险。两者都
不推进。

Candidate A 不会向普通 remote prover 隐藏 witness。本 crate 不会序列化 proving
envelope，因此目前无法证明 live `WitnessBundle` 中哪些字段已经移除。下一份规格至少
必须明确：

- authorization signing seed：禁止进入 envelope；
- 当前的 `TxInput.sk`：禁止进入生产 envelope，Phase 2 能序列化 envelope 前必须移除；
  本 spike 尚未实现该移除；
- `nk`：如果存在，它是 account-global spend-viewing material，因此一次 job 就是对
  该 operator 的 wallet-level disclosure，后续 job 还能关联不同 diversified address；
- authorization Merkle path 与 `auth_root`：只能是 private STARK witness，绝不能成为
  transaction 或 public-value field；但普通 Candidate A prover 必然可见，并足以稳定
  关联同一地址；
- `rho`、`rseed`、`d`、note Merkle path、recipient/discovery/rider bytes、amount、change
  和内部 dummy state：在逐项明确移除或缩窄之前，视为继承自当前 bundle；intent hash
  能防止改写，不能阻止观察；
- IP、device identity、timing、queue metadata 和对应链上事件：在 confidential
  worker 外仍然可见。

Depth 0 还会公开稳定 verifying-key cluster，以及 §1 所述的延迟 dummy-arity
distinguisher，因此不能进入生产。Rotation tree 在不复用 leaf 时可以移除这种重复的
公开地址标签，但不会消除 service metadata 或 A-only witness 可见性。Candidate B
可以减少 worker 对 payload 的可见性，但不会改变授权裁决。

手机边界的两个方向都属于强制要求。上传前，wallet 必须重建 complete intent，验证两个
本地生成的 slot，并断言 authorization secret、`TxInput.sk`、wallet seed、`div_seed`
以及 incoming-viewing/decryption key 均不在 envelope 内。证明完成后，手机必须 decode
返回 artifact，从该 artifact 重建 intent，并在提交前要求它与已批准 intent 完全相等。
默认不允许 worker 直接提交；这既增加 race，也会给 node 暴露 worker-origin 关联信号。

## 10. 验证与剩余 gate

本地已完成：

```console
cargo fmt -p qlab-remote-auth
cargo check -p qlab-remote-auth --all-targets --locked
cargo clippy -p qlab-remote-auth --all-targets --locked -- -D warnings
cargo run -q -p qlab-remote-auth --bin qlab-remote-auth-spike -- vector
```

重新生成的 vector stdout 与已提交 fixture 逐字节一致。RFC reference signature 和
leaf 的比较也逐字节一致。Repo policy 禁止 agent session 在本地运行 `cargo test`，
所以已经写好的 unit/integration tests 等待 CI。本文不声称任何手机或 pinned-rig
性能数字。

[Claude Code](https://github.com/qumbra-labs/qumbra-lab/pull/632#issuecomment-5386685515)
对协议／密码学 seam、
[Grok](https://github.com/qumbra-labs/qumbra-lab/pull/632#issuecomment-5386698823)
对 proving-envelope／隐私边界在 `5e679ad` 完成了独立 post-remediation review；两者均
给出 **APPROVE WITH NON-BLOCKING FOLLOW-UPS**，没有 blocker。本次修订吸收了双方共同
的隐私／生命周期澄清；新 head 仍需 delta confirmation。

形状选择已经解决：推进 ML-DSA rotation；不推进 depth 0 和两种 WOTS+。Phase 2 仍被
D12..D16 手机实测、具有约束力的生产 allocation/restore 规则和已接受的 delta review
所阻塞。只有全部完成后，结果才能写入带日期的中英文 binding-design correction。
AIR、交易 wire/identity、node verification、activation、genesis/re-mint、wallet
integration 和 prover service 仍属于后续分别授权的 phase。
