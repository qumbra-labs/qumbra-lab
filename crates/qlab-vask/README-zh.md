# Qumbra 交易所/VASP 工具包

> [English](README.md)

交易所以尊重隐私的充值流程上线 QMB 所需的一切:**验证充值方的披露、只对验
证通过者入账、其余按名拒绝。** Qumbra 是单一均匀的屏蔽资金池——没有透明
地址类型可以强制充值走过去——所以执法点移到入账时刻:充值方用一个 STARK
证明*"这笔金额为 v 的充值打到了你的地址"*,交易所只对附带可验证证明的充值
入账。与 Zcash ZIP 320 TEX 地址相同的商业结果(拒绝匿名充值的能力,正是它
扛过了 2023 年 Binance 的最后通牒),而共识面为零
(`qumbra-design/ecosystem-and-adoption.md` §4、`auditable-privacy.md` §4)。

状态:私有 lab 参考实现(跟踪:lab #483)。工具包任何部分的对外发布是另一
件事(#203 跟踪器);这里还没有任何东西是已发布的 API。

## 工具包里有什么

| 部件 | 位置 | 是什么 |
|---|---|---|
| 验证库 | 本 crate(`qlab-vask`) | 信封解析 + STARK 验证,无 I/O,配置钉定 |
| C ABI | `include/qvask.h` + `src/lib.rs` | 4 个函数、7 个稳定结果码,头文件与源码由测试双向互锁 |
| 参考绑定 | `bindings/python/` | 头文件的 ctypes 镜像 + fixture 冒烟测试 |
| 黄金 fixture | `fixtures/` | 已提交的解析拒绝向量 + 一个 CI 铸造的真实信封(`golden-envelope-v1.bin`) |
| 入账参考服务 | `../qumbra-credit-ref` | 可运行的 HTTP 服务:充值→验证→入账的完整决策路径 |
| 确认策略 | `../../docs/kit-confirmation-policy.md` | 充值何时可安全入账:**已最终确定 = 可入账** |
| 托管审计文档 | `../../docs/kit-custody-audit.md` | 对交易所自有钱包的常设 fvk 审计安排 |

工具包实现的规范:`qumbra-design/wallet-interop-spec.md` §3(披露信封 + 验
证规则),投递方式为**带外**(#483 阶段 0 裁定:充值披露是充值方→交易所
的双边对象——钱包以文件/二维码/粘贴导出,交易所充值界面接收;链上不承载
任何东西)。

## 流程

```
充值方钱包                         链                        交易所
  1. 发送充值 ───────────────────► 挖出 … 最终确定
  2. 构建披露信封
     (证明:该充值处的 cm 打开为
      金额 v,收款方是你的地址)
  3. 把信封交给交易所 ─────────────────────────────────► 4. peek:声明字段
     (上传/二维码/粘贴——带外)                          5. 是我们的地址?金额?
                                                          6. 充值已最终确定?
                                                          7. 对已承诺 cm 做
                                                             STARK 验证
                                                          8. 以 cm 为键入账一次
                                                             ——或按名拒绝
```

第 4–8 步就是 `qumbra-credit-ref` 本身;单独的第 7 步就是本库。

## 三种接入方式,从最小开始

**1. 链接 C ABI**(`include/qvask.h`)——链访问与充值记录都在你自己手里;
库只回答"这个信封对这个已承诺 commitment 验证通过吗":

```c
qvask_claim_t claim;             /* tx_ref、value、addr_commitment、output_index */
char *reason = NULL;
int32_t rc = qvask_envelope_peek(env, env_len, &claim);      /* 还不跑 STARK    */
/* …… 用声明匹配你的充值记录,在你的已最终确定视图上读出 cm             */
rc = qvask_verify(env, env_len, chain_cm, &claim, &reason);  /* 约 26 ms        */
```

FRI 配置钉定在**库内部**(调用方无法用参数削弱验证器——配置变更就是新的
`qvask_abi_version()`)。验证是纯函数:无句柄、无状态,靠无状态天然线程安
全;唯一跨出边界的分配是 `reason`,用 `qvask_string_free` 释放。规范的规
则 1(充值存在且**已最终确定**)刻意留在 ABI 的你那一侧。

**2. 抄决策引擎**——`qumbra-credit-ref/src/lib.rs` 的 `try_credit` 是完整
决策路径(peek → 我方地址闸 → 最终性读取 → 轻客户端扫描 → 对每个候选的已
承诺 cm 验证 → 只入账一次),在调用方提供的 fetch 之上,约 80 行可读完。

**3. 直接跑参考服务**:

```sh
qumbra-credit-ref --listen 127.0.0.1:8484 \
                  --upstream http://<node>:<discovery-port> \
                  --keys ./exchange.keys
# POST /v1/credit   body = 原始信封 → 200 入账 | 4xx/503 命名拒绝
# GET  /v1/status   addr_commitment + 已入账计数
```

参考实现的边界,明说:无 TLS(放在你自己的边缘后面)、无限流器、单一充值
地址、内存态的只入账一次集合——每一项都在 crate 文档中写明及其生产方向。

## 拒绝即 API

每个非入账应答都是稳定的命名码,可机器匹配——本 lab 的通行模式。在 ABI:

| 码 | 名称 | 含义 |
|---|---|---|
| 0 | `QVASK_OK` | 声明对你的链上 cm 证明成立 |
| -1 | `QVASK_INVALID_CALL` | NULL/合约违反——从不是对信封的判定 |
| -2 | `QVASK_MALFORMED` | 组帧:截断、尾随字节、varint |
| -3 | `QVASK_UNKNOWN_VERSION` | 未知即拒绝,从不忽略(规范规则 3) |
| -4 | `QVASK_UNKNOWN_CLAIM_TYPE` | 未知即拒绝,从不忽略 |
| -5 | `QVASK_PROOF_DECODE` | 证明字节不是证明结构 |
| -6 | `QVASK_PROOF_INVALID` | STARK 拒绝;`reason` 说明原因 |

在服务侧,决定是 4xx **绝不 5xx**,恰好两种无法作答的情况是 503:
`envelope-*`(上面五种)、`not-our-address` 422、`deposit-not-found` 404、
`nothing-finalized`/`not-finalized`/`already-credited` 409(前两个是"等最
终性后重试",第三个是以已承诺 cm 为键的只入账一次规则)、`proof-refused`
422、`scan-incomplete`/`upstream-unavailable` 503。令牌与状态码表由测试锁
定(`qumbra-credit-ref/src/lib.rs`)。

## 数字,连同其测量基础

| 数字 | 值 | 基础 |
|---|---|---|
| 信封大小 | **150,695 B**(约 147 KiB) | 已提交的 V1 黄金 fixture:钉定 b16/q20/g22/a16 配置下 postcard 序列化的证明(`fixtures/README.md`——注意旧文档里流传的"~122 KB"是 bincode 证明大小,编解码器弄错了) |
| 验证 | **26.0 ms** | b16/q20/g22,Apple M5 Max,复现两次(`docs/disclosure-run1.md`/`-run2.md`)——单线程约 40 次/秒,远超任何充值速率 |
| 充值方出证明 | 0.59–0.99 s | 同一测试机与同批运行,每次运行 1 个计时样本 |
| 充值 → 可入账 | 约 2.5–11.5 分钟 | 由 devnet 最终性钉定常量推出的算术,不是测量——`docs/kit-confirmation-policy.md` §4 |

信封是"上传"量级的对象,不是 memo:上面的带外流程是正式设计,不是变通。

## 确认策略,一句话

**当充值高度 ≤ 已最终确定头(`GET /v1/anchors`)时入账,绝不按确认深度**
——BFT 最终性不可逆且为分钟级,参考实现的 `not-finalized` 拒绝就是等待本
身。依据、机制、延迟算术与失败方向:`docs/kit-confirmation-policy.md`。

## 托管,一句话

入账主机只需要**入账方向**的查看密钥材料(`Ivk` 级或单个分散化 `dk`),审
计方拿按账户划定的常设 `Fvk`(看得到一切,动不了分毫),花费密钥永不触碰
边缘主机——阶梯、每一级能与不能看到什么、以及轮换纪律:
`docs/kit-custody-audit.md`。

## 版本纪律

- `qvask_abi_version()` = **1**;启动时对照你头文件副本里的
  `QVASK_ABI_VERSION` 检查。
- 信封格式 `ver 0x01`,声明类型 `0x01`(sent-payment)。未知值一律拒绝——
  交易所在钱的问题上绝不猜。
- 验证器与链的公开共识验证器(`qumbra-circuit`)共享整个证明栈(域、FRI、
  哈希)——同一血统,更小的陈述(阶段 0 调研 §1.4)。
