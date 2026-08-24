# Remote proving — Candidate A 手机基准

**状态：测量工具，2026-08-24。不是协议常量、primitive 重新选择、钱包集成或实现批准。
只有把 clean revision 的真机 JSON evidence 提交后，才可主张任何手机实测结果。**
跟踪 [lab issue #630](https://github.com/qumbra-labs/qumbra-lab/issues/630)，与
[`remote-proving-mobile-benchmark.md`](remote-proving-mobile-benchmark.md) 配对。

首轮真机 D12..D16 evidence 记录在
[`remote-proving-mobile-evidence-2026-08-24-zh.md`](remote-proving-mobile-evidence-2026-08-24-zh.md)。
它只确认两台实测设备的结果，supported-device-floor 与全网 depth gate 仍明确开放。

当前裁决不变：Candidate A 是真钱 shared prover 的强制安全基础；Candidate B 只是可选隐私层。
Phase 1 已决定只推进 ML-DSA rotation tree，排除 depth 0 和两种 WOTS+；在选择全网统一深度前，
必须真机测 D12 到 D16。

## 1. 手机到底测什么

b16 STARK 全部由 backend prover 执行。不能外包的是花费授权权力，因此工具只测：

1. 从固定的合成 per-address master 派生 `2^D` 个 ML-DSA-44 叶密钥；
2. 只暴露公开 leaf hash，并用 `O(D)` streaming Merkle frontier 独立计算 `auth_root`；
3. 生成私有、无重复的 rotation schedule；
4. 每笔交易重建两个被选中的叶密钥，构造完整 two-slot intent，签名两次并编码 7,544-byte auth section；
5. 在本机验证两份签名。

它不做 STARK proving，不扫描链、不连接 node/service、不打开钱包、不从钱包 seed 派生，
也不访问 Keychain/Keystore。所有密钥都是公开、固定的 research fixture。

## 2. 手机与 backend 的边界

手机保留 private auth master，只把公开 leaves 交给 service 缓存。Service 可以存公开树和
Merkle path，让手机不用常驻整棵树；但手机必须把返回 path fold 到自己算出的 root。
恶意 cache 最多拒绝服务或返回错误 path。若把 master 交给 service，它就能派生签名私钥，
Candidate A 会直接失效，所以这个“省事”方案不允许。

对应架构图见英文文档 §2。当前 benchmark 故意不测网络，以免把 public-cache transport
与密码学成本混为一个数字。

## 3. 隔离方式

`qlab-remote-auth-mobile-bench` 是独立 research static library；没有任何 shipping
`qumbra-*` crate 依赖它。ABI 只接受 D12..D16，在后台线程同步执行，支持 progress/cancel，
成功时才写固定 152-byte result，且不会跨 ABI 传递需要释放的 allocation。

iOS 使用独立 `QumbraAuthBench` target 和 `dev.qumbra.remote-auth-bench` bundle ID；
Android 使用独立 `authbench` APK 和 `dev.qumbra.remoteauthbench` ID，并且没有
`INTERNET` permission。两者都不链接正式钱包 FFI，也不会用现有钱包 test target 做真机测试。

## 4. Evidence 与真机流程

两端导出 `qlab-remote-auth-mobile-bench-v1` JSON，记录 qlab/shell Git revision、
`source_trees_clean`、硬件/OS、内存、低功耗和 thermal 状态、所有阶段的 monotonic timing、
固定 byte sizes、selected indices、root 与 intent digest。iOS 内存指标是 process
`physical_footprint`；Android 是 PSS，JSON 会明确标注 metric kind。
当前 Fisher-Yates schedule 的精确 allocation（`2^D × 4` bytes）也单独记录；只有
Merkle frontier 是 `O(D)`。

可接受 evidence 必须满足 `source_trees_clean = true`；dirty build 会标记 `+dirty`。
同一深度在所有设备上的 root、intent digest 与静态 byte counts 必须完全一致。

D12 的 committed control 是 `selected_indices = [3322, 507]`、
`root = c8c3a1582bd6c57ad4b3e878d807e105e48c39e5998ca61ff06fde8ced17a086`、
`intent_digest = 993a54c86ea3725afa30e98cf270fd3686f6c224615939c480a5308826434739`。
CI 会通过同一 benchmark path 重算；不匹配属于 correctness failure，不是性能样本。

每台设备先从 D12 开始，在低功耗关闭且 thermal 为 nominal/light 时运行两次并保留原始 JSON。
只有当前深度完成、可取消、未进入 serious/critical thermal、未被 OS 终止，才继续下一深度，
直到 D16 或首次失败。降温后再做重复；throttle、OOM、取消都必须作为 evidence 记录，不能丢弃。

首轮至少覆盖现有 iPhone 15 Pro Max 和一台有代表性的受支持 Android 真机。能跑完不等于自动
选为网络常量；还需要 supported-device floor 和 Larry 的明确 gate。若某深度失败，正确结论是
选更低深度或修改构造，而不是把授权 master 搬到 backend。

## 5. 尚未解决

工具本身不解决 production key hierarchy、crash-safe reservation、restore、multi-device
allocation、public-cache API、proving envelope 最小化、AIR/wire/node、genesis/re-mint 或
shared prover 部署。Agent session 不运行本地 Rust tests；已写的 unit/ABI pin tests 交给 CI。
任何物理 iPhone 上都不得运行钱包 test suite。
