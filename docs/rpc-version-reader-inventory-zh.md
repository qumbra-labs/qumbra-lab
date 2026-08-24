# `RPC_VERSION` 读者清单

> [English](rpc-version-reader-inventory.md)

**状态:2026-08-24 针对 `RPC_VERSION = 0x07` 推导而成,服务于 lab [#607](https://github.com/qumbra-labs/qumbra-lab/issues/607)。**
那个 issue 的抱怨是:一次版本提升会打断每一个钱包客户端直到重编,**而没有任何读者清单**。
这就是那份清单。它不是修复,它让下一次提升变成一件可数的事。

🔴 **这里每一行都是搜出来的,不是回忆出来的。** 方法写在下面,好让下一个人重跑一遍,
而不是相信这张表的日期。为什么这一点重要:2026-08-22 一份发版清单写着"七个 app 仓库",
而真实数字在**两个方向上**都不对 —— 其中一项是另一项的 worktree,而有一个读者
(本仓库自己的 CLI)根本不在那张单子上。

---

## 1. 两种版本纪律,只有一种会断

`qlab-node` 的解码器两种都有,而一个面用的是哪一种,决定了一次提升是"重编"还是"故障"。

| | 机制 | 提升时 |
|---|---|---|
| **严格** | `Reader::version()` → `version_in(&[RPC_VERSION])`,一个只有一个元素的清单(`rpc.rs:1485`) | **拒绝**,响亮地,`BadVersion { got: N }` |
| **宽容** | `version_in(READABLE_TELEMETRY_VERSIONS)` —— `&[0x03, 0x04, 0x05, 0x06, RPC_VERSION]`(`telemetry.rs:145`) | 继续读 |

**`/v1/telemetry` 是唯一带兼容清单的面。** 它在 #212 时被给了一份,此后每次提升都被扩过。
其余的面按构造都是严格的 —— 因为按它自己的注释,`Reader::version()` 是"每一处节点侧解码都用的"那一个。

**`Reader` 是 `pub(crate)`。** 仓库外的客户端一个都不用它,每一个都自己手搓了解码,
所以每一个都有自己的版本检查、或者没有。**这就是为什么这份清单没法只从 lab 里推导出来。**

## 2. 仓库外的客户端,以及它们读的面

按仓库用 `grep -rhoE "/v1/[a-z_]+"` 数出,排除 worktree 和构建目录:

| 客户端仓库 | 引用到的面(引用次数) |
|---|---|
| `qumbra-wallet-macos` | `/v1/names` 12 · **`/v1/anchors` 7** · `/v1/tx` 4 |
| `qumbra-wallet-desktop` | `/v1/tx` 2 · `/v1/compact` 2 · `/v1/tree` 1 · `/v1/nullifiers` 1 · **`/v1/anchors` 1** |
| `qumbra-wallet-ios` | `/v1/tx` 10 · **`/v1/anchors` 7** · `/v1/compact` 3 · `/v1/coinbase` 2 |
| `qumbra-wallet-android` | **`/v1/anchors` 35** · `/v1/compact` 19 |
| `qumbra-wallet-extension` | **`/v1/anchors` 8** · `/v1/nullifiers` 5 · `/v1/coinbase` 3 · `/v1/compact` 1 |
| `qumbra-explorer-web` | 无 —— 它读的是 **explorer** 的 JSON,那份自带 `v` 字段,**刻意不用** `RPC_VERSION`(`json.rs:46`) |
| `qumbra-web` | 无 |

**外加一个仓库内的读者,而它容易被忘掉正因为它不是 app:**
`qumbra-wallet`,本仓库自己的 CLI。它在 `0x06 → 0x07` 那次提升上和别的一样断了,
而它不在任何一份 app 仓库枚举里。

## 3. 🔴 可数的答案

**五个客户端读 `/v1/anchors`。它是严格的。一次提升打断这五个,加上那个 CLI。**

那正是 2026-08-22 在 macOS 钱包上产出
`GET /v1/anchors did not decode: BadVersion { got: 7 }` 的那个面 —— #607 可见的那一半 ——
而每个客户端都碰它,因为那是钱包得知"我可以对着哪些锚点出证"的方式。

**`/v1/compact`(4 个客户端)和 `/v1/coinbase` / `/v1/nullifiers`(各 2 个)同样是严格的**,
所以爆炸半径不比 `/v1/anchors` 显示的更窄 —— 是同一批客户端,经由更多的门。

## 4. 所以一次提升要求什么

不是政策,就是那张单子,好让没人需要去记:

```
qumbra-wallet-macos        重编 + 重装
qumbra-wallet-desktop      重编 + 重装   (desktop-linux 是这个仓库的一个分支,不是第六个客户端)
qumbra-wallet-ios          重编 + 重新部署到设备
qumbra-wallet-android      重编
qumbra-wallet-extension    重编
qumbra-wallet(本仓库)     重编 —— 那个没人会列的
```

**还有已发布的节点二进制**:它们本身不读任何东西,但**被**这些客户端读 ——
一个 `RPC_VERSION` 与在跑的舰队不同的已发布版本,会交给用户一个他的钱包说不上话的节点。
那是 lab #614,而 `release skew` 那个 workflow 现在量的正是它。

## 5. 方法,好让这张表可以被重新推导而不是被信任

```sh
# 定义
grep -rn "pub const RPC_VERSION" crates/

# 严格 vs 宽容
grep -rn "version_in(" crates/ | grep -v "fn version_in"

# 每个客户端的面,从 ~/develop/qumbra 跑
for d in qumbra-wallet-*; do
  grep -rhoE "/v1/[a-z_]+" "$d" \
    --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=target --exclude-dir=build \
    | sort | uniq -c | sort -rn
done
```

🔴 **排除 worktree。** 协调者机器上 `ls -d qumbra-wallet-*` 还会列出
`…-android-authbench-copy-evidence`、`…-android-remote-auth-mobile-bench`、
`…-ios-remote-auth-mobile-bench`、`…-macos-confirmed` —— **其中没有一个是客户端**。
数目录,就是"七个 app 仓库"的来历。

## 6. 这份清单**没有**确立什么

* **每个客户端到底检不检那个版本字节,还是无视它。** 上面的计数是对一个**面**的引用,
  不是版本检查的证据。一个读 `/v1/anchors` 却从不看第 0 字节的客户端会**错误解析**而不是拒绝 ——
  **那比 #607 描述的失败更糟**,而这张表分不出这两者。
* **有没有哪个客户端有自己的兼容清单。** `qumbra-explorer-web` 刻意不跟踪 `RPC_VERSION`;
  这里没有任何东西检查过有没有钱包这么做。
* **android / ios / extension 的计数是引用数,不是调用点。** 一个提到 `/v1/anchors` 35 次的
  仓库,可能有 1 个客户端和 34 个测试。

这三条每一条都是一次待做的阅读,不是一个可以填上的猜测。
