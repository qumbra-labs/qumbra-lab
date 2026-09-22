# W3 第二阶段 — 形状 P 实测，第 4 次运行——复现（lab #700，PR #701）

> [English](w3-run4.md) · 第 3 次：[`w3-run3-zh.md`](w3-run3-zh.md) · 构建笔记（仅英文）：[`w3-build-notes.md`](w3-build-notes.md)
>
> 英文版为技术细节的权威版本；本文是翻译，不是分叉。

同一台架、同一版本（`20723c9`）、同一二进制、与 `w3-run3-zh.md` 相同的调用（环境块见彼处）。日期：2026-09-22 23:41 +08（P b4）、23:42 +08（金丝雀第二样本）；锁持有者 `QUM-182`。

```sh
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p   --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p19 --only b4 --power AC   # 金丝雀第二样本（在 ./w3-logs/scoped.sh 内，同一把锁）
```

## 第 4 次运行

| 形状 | 通道 | 置换（程序/容量） | 宽度 | log_height | 最大次数 | prove ms | verify ms | 定宽 B | postcard B | 峰值 footprint GB | 最大 RSS GB | swaps | real s | user s | sys s | 指令数 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **形状 P** | b4/q43/g22/fp16/a16 | 212/341 | 774 | 20 | 4 | **3757.3** | 19.3 | **312,677** | 362,290 | **15.106** | **15.323** | 0 | 16.28 | 157.03 | 26.02 | 2.31e12 |
| 形状 P | b2/q86/g22/fp16/a16 | — | 774 | 20 | 4 | **未测**——p3-uni-stark 0.6.1 中 4 分块 AIR 不存在该通道（`w3-run3-zh.md` §2；由 `l2shape_b2_is_not_a_lane_for_a_degree_4_air` 钉住） | | | | | | | | | | |
| 金丝雀：P AIR 全空 @ 2^19 | b4/q43/g22/fp16/a16 | 0/170 | 774 | 19 | 4 | 1743.8 | 17.4 | 300,293 | 297,9xx | 7.389 | 7.679 | 0 | 7.42 | 95.73 | 6.46 | 1.41e12 |

## 与第 3 次的对比

| 行 | 第 3 次 | 第 4 次 | Δ | ±1 % 内？ |
|---|---|---|---|---|
| P b4 峰值 footprint（GB） | 15.062 | 15.106 | +0.3 % | ✅ |
| P b4 最大 RSS（GB） | 15.324 | 15.323 | −0.01 % | ✅ |
| P b4 定宽字节 | 312,677 | 312,677 | 0 | ✅ 逐字节相同 |
| P b4 postcard 字节 | 362,133 | 362,290 | +0.04 % | varint 噪声，与第一阶段相同 |
| P b4 prove（3 取优） | 3.555 s | 3.757 s | +5.7 % | 非门槛数字；两者都低于 20 s 五倍 |
| P b4 verify（3 取优） | 21.5 ms | 19.3 ms | | |
| P b4 `sys` | 40.30 s | 26.02 s | | 都高于第一阶段的 user 8–12 %；指令数持平——15 GB 下的页回收工作，不是争用（第 3 次 §5） |
| 金丝雀 footprint（GB） | 7.562 | 7.389 | −2.3 % | 金丝雀不是门槛行（只决定 2^20 的启动：7.4–7.6 × 2 < 32 ✓）；最大 RSS 7.675 / 7.679 相差 0.05 %——又是第一阶段的度量发现 |

**结转（各取较大样本）：b4/q43/g22 峰值 footprint 15.11 GB、最大 RSS 15.32 GB——在 ≤ 16 GB 门槛内 5.6 % / 4.2 %；prove 3.56–3.76 s 对 ≤ 20 s。** 门槛按 L2 通道判定；b2 对 4 次 AIR 不可用，形状 P 的 L2 通道默认且按实测为 **b4**，这个余量是 W3 产出的最薄的一个数字。它是真实的余量：两个样本，均无交换，复现到 0.3 %。

## 范围内测试运行（第一阶段裁定 §4——一次运行，测量之后，同一版本）

```sh
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- ./w3-logs/scoped.sh
#  (a) cargo test --release -p qlab-bench -- --test-threads=1 l2shape_shape_p_prove_verify_and_tampered_pv_b4 l2shape_b2_is_not_a_lane_for_a_degree_4_air
#  (c) cargo test --release -p qlab-air -p qlab-note --no-fail-fast -- --test-threads=1
#      cargo test --release -p qlab-bench --no-fail-fast -- --test-threads=1 l2 --skip l2shape_shape_p_prove_verify_and_tampered_pv_b4
```

| crate / 步骤 | 通过 | 失败 | 忽略 | 时间 |
|---|---|---|---|---|
| `qlab-air`（lib）——全部 | **95**（37 narrow + 1 reference + 26 `l2::` + **31 `l2p::`**） | 0 | 0 | 2,539.4 s |
| `qlab-note`（lib）——全部 | **39**（35 + 4 `l2note::`） | 0 | 0 | < 0.1 s |
| `qlab-bench`（bin）——过滤 `l2`，`--skip l2shape_shape_p_prove_verify_and_tampered_pv_b4` | **5**（`l2shape::`——通道下限、mock、S b4 往返、S b4 篡改公开值、b2 钉子） | 0 | 0 | 11.6 s |
| (a) 被跳过的 15 GB 测试 + b2 钉子，同一把锁下单独运行 | **2** | 0 | 0 | 5.9 s |
| **合计** | **141** | **0** | 0 | 墙钟 (c1) 2,549 s + (c2) 13 s + (a) 25 s；1 Hz 采样的测试二进制峰值 RSS：**8.0 GB**（c1）、7.8 GB（c2）、**13.8 GB**（a——P 的 prove；bench 的 15.3 GB 才是真实峰值，1 Hz 对 4 s 的 prove 采样不足） |

对账：`qlab-air` 95 = 38（`main`）+ 26（第一阶段）+ 31（第二阶段）；`qlab-note` 39 = 35 + 4；`qlab-bench` 5 = 6 个 `l2shape::` 测试 − 1 个跳过（在 (a) 中运行）。日志中的负项：`FAILED` 0、`panicked at` 0、`^error` 0。`l2p::` 块占 42 分钟中的约 25 分钟（31 个测试，每个都是 2^20 × 774 的 `check_all_constraints`；八路负项各八次）。

- **工作区全套：未跑——运行器离线**（#701 的 `verify-graviton` 任务没有在线运行器；第零阶段裁定 §6 记为欠交，非豁免）。
