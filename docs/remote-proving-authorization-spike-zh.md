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
| FIPS 204 ML-DSA-44 | 签名 key 可安全复用；不需要单调 counter | 7,608 B | **唯一建议继续推进的方案** |
| RFC 8391 `WOTSP-SHA2_256`，stateful index | OTS index 绝不能复用 | 4,432 B | **阻塞：**有效旧备份和两台设备都会复用 index |
| RFC 8391 `WOTSP-SHA2_256`，random index | 不需要 journal，但 index 碰撞是灾难性的 | 4,432 B | **只保留作 comparator：**实际碰撞界不可接受 |

所以下一个应该裁决的问题不再是“ML-DSA 还是 WOTS+”，而是 Qumbra 接受哪种
ML-DSA commitment 形状：

- **depth 0／每个收款地址一个可复用 leaf** 是最小的安全基线。此时
  `auth_root == H(pk)`，没有授权路径，候选 AIR 保持在 2^18 rows。复用不会让
  attacker 伪造签名，但会关联使用同一 authorization key 的多次 spend；
- **ML-DSA leaf rotation tree** 可以减少这种关联，但每一层要增加两个 Merkle
  path permutation，建地址成本为 `O(2^D)`，任何实用 depth 都会把 trace 提升到
  2^19 rows。

Larry 需要在手机实测和独立 review 后裁决这个隐私／复杂度 tradeoff。Spike
没有把任一形状变成共识规则。

## 2. 已实现内容

仅用于研究的 [`qlab-remote-auth`](../crates/qlab-remote-auth/) crate 包含：

- 436 字节、带版本、固定宽度的 complete-intent preimage；
- 使用 workspace 已 pin 的 `ml-dsa = 0.1.1` 生成的 deterministic FIPS 204
  ML-DSA-44 vectors；
- RFC 8391 `WOTSP-SHA2_256` 的 F/H/PRF、address、base-w checksum、chain、
  L-tree compression，以及 RFC 作者采用的 HRS16 key expansion；
- 无 length field、严格固定双 slot 的 authorization-section codec；
- 绑定 domain、context、level 和左右方向的外层 Keccak tree；
- 可执行的 hidden-dummy 接受模型；
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

每个 68 字节 descriptor 是
`tree_context[32] || leaf_index_le32 || leaf[32]`。Scheme tag 将 stateless
ML-DSA、stateful WOTS+ 和 random-index WOTS+ 的安全契约隔离开，即使两种
WOTS+ 使用同一个 primitive。任何语义字段变化都会改变 digest。未来新增语义
字段必须升级版本，不能追加到旧 signer 会忽略的位置。

Spike authorization section 以固定 magic `QRA1`、version、scheme、slot count
开头。Scheme 决定其后所有字段宽度；decoder 会拒绝未知 scheme、错误 slot 数、
截断、错误 payload 宽度和 trailing byte。

| 组件 | ML-DSA-44 | WOTS+ |
|---|---:|---:|
| header | 8 | 8 |
| 两个 slot 的 descriptor | 136 | 136 |
| 每 slot verifying key | 1,312 | 0；恢复出的 32-byte leaf 已在 descriptor 中 |
| 每 slot signature | 2,420 | 2,144 |
| **双 slot 总计** | **7,608** | **4,432** |

精确差值是 3,176 字节，而不是早期 3,112 字节的纸面估算。这些是 spike
section bytes，不是生产交易 wire 的决定。

未来 node 的强制顺序应是：严格 decode；从真实交易重建 complete intent；要求
descriptor 完全相等；验证两份手机授权；最后才投入 STARK verification 成本。
Crate 模拟了这个顺序，但有意没有接入当前 node。

## 4. Note binding 与候选 AIR 算术

一种候选 note binding 是扩展现有 `ROLE_ARKM` absorb：

```text
rkm = Keccak256(nk || D_R || d || auth_root || tree_context || pad10*1)
```

按当前 lane 写法，`nk` 占 lanes 0..3，domain 占 lane 4，diversifier 占
lanes 5..6，authorization root 占 lanes 7..10，context 占 lanes 11..14，
pad start 在 lane 15，rate 最终 bit 在 lane 16。因此它可以放进一个 17-lane
Keccak rate block。这只是 spike 算术；binding design spec 仍须确定生产使用的
field/byte encoding，并完成 domain review。

Node 对 ML-DSA leaf 的计算是完整 1,312-byte public key、tree context 和 leaf
index 的 domain-separated hash。对 WOTS+，native verification 会恢复 RFC L-tree
leaf。未来 AIR 只需把 public leaf 沿授权路径折叠，并通过同一份 hidden note
material 绑定 root/context；不需要在 STARK 内验证任一签名。

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

Worker 可以生成 dummy slot 的 ephemeral authorization material。这不会给予它
重定向权，因为非 dummy 的 slot 0 手机 key 与真实 note 绑定，而且签名完整的
common intent，其中包括两个 output 和两个 authorization descriptor。如果删掉
“slot 0 永远真实”这个 invariant，本规则就不再成立。

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
| ML-DSA-44 | 148,625 | 7,608 | 156,233 B |
| WOTS+ | 148,625 | 4,432 | 153,057 B |

这些和数既不是未来 proof，也不是完整交易的预测；它们说明如果把 ≤150 KB
解释为全量 transport artifact，目标已经超出。现有 regression target 只针对
proof，未来 proof 仍必须重新测量：depth 0 可能保持 2^18 height，但仍会改变
AIR/public surface；实用 tree 会升到 2^19。Proof bytes、完整 transaction bytes、
prover RSS/time 和 node verification time 都仍是 open gate。

## 9. 手机生命周期与隐私

对 ML-DSA，手机持有的 master authorization seed 可以 deterministic 地派生
address/leaf key。Depth 0 可只靠 seed 恢复，不需要 monotonic journal。多台合法
设备持有同一 seed 不会制造 WOTS+ 的伪造失败，但 duplicate signing、key compromise
和 spend linkability 仍需要产品规则。Rotation tree 同样可从 seed 恢复，但创建
或缓存 `2^D` public leaves 的地址构建成本尚未实测。

Stateful WOTS+ 要求当前 wallet 产品并不具备的 rollback-proof、跨设备协调状态。
Random-index WOTS+ 不需要 journal，却换成了有明确数值的灾难性碰撞风险。两者都
不推进。

Candidate A 不会向普通 remote prover 隐藏 witness。Service 仍可观察 selected
notes、value、recipient/discovery material、隐私敏感的 `nk`、IP、device identity、
timing 和对应的链上事件。ML-DSA depth 0 还会公开可复用 public key/leaf，从而关联
spend。Rotation tree 只减少这一种关联，不会消除 service metadata。Candidate B
可以减少 worker 对 payload 的可见性，但不会改变授权裁决。

## 10. 验证与剩余 gate

本地已完成：

```console
cargo fmt -p qlab-remote-auth
cargo check -p qlab-remote-auth --all-targets --locked
```

RFC reference signature 和 leaf 的比较逐字节一致。Repo policy 禁止 agent session
在本地运行 `cargo test`，所以已经写好的 unit/integration tests 等待 CI。本文不声称
任何手机或 pinned-rig 性能数字。

进入 Phase 2 前，Larry 必须结合本 spike、手机 evidence 裁决 ML-DSA depth／
linkability 形状；Claude Code 必须独立 review immutable PR。Grok 的 review 必须
覆盖 A-only witness/metadata 边界和 depth-0 linkability tradeoff。只有接受后的结果
才能写入带日期的中英文 binding-design correction。AIR、交易 wire/identity、node
verification、activation、genesis/re-mint、wallet integration 和 prover service
仍属于后续分别授权的 phase。
