# prover 收款钱包：导入付费台账

*英文版：[`prover-payee-wallet.md`](prover-payee-wallet.md)。技术细节以英文版为准。*

Lab #937 的导入工具（在 PR E 之后）。代码：`crates/qumbra-wallet`（`src/openings.rs`、`import-openings` 命令，以及 `src/annulet.rs` 里扫链时的合并）。

## 建收款钱包

在运维自己的机器上建一次，要早于向这个 prover 付费的那条 net：

```sh
qumbra-wallet keygen --dir ~/.qumbra/prover-payee --candidate-a
```

这条命令生成一个新 seed，同时写入钱包的第一份 Candidate A 授权日志（`auth.v1`：generation 0、fresh、active）。全程离线：在本进程里刚生成的 seed 没有在任何地方签过名，所以不需要读链。它打印完整的 version-2 地址 [0] 和对应的短地址，不打印助记词，也不打印 seed。什么时候备份 seed 由你决定，用 `backup --reveal`。

**seed 目录永远不上主机。**
- prover 的机器和它的配置只拿到**完整的** version-2 地址（`QUMBRA_PROVER_ANNULET_PAYEE`）。
- 钱包里这条 net 的 pin（`prover_pins::PINS`，lab #937 PR D）也只拿完整地址。
- 短地址 `qs1…` 是一个哈希，没法校验，所以这两处都不收短地址。

**只用于新钱包。** 如果目录里已经有 seed 或 `auth.v1`，命令会说明原因并拒绝，不写入任何东西。`restore --candidate-a` 同样会被拒绝：恢复出来的 seed 可能在别处签过名，所以它要在 net 上走 `migrate` 的检查流程。

## 为什么会有这个文件要导入

在 format 34 的 net 上，远程 prover 在每笔交易里收费，费用就是交易的第三个输出：asset 0，付给 prover 的收款地址（见 `docs/prover-service-annulet-zh.md` 的「Format 34」一节）。

**诚实的内核**会把这个输出的 discovery 载荷加密给收款方。收款钱包平常跑 `scan --net annulet` 就能找到这个 note，和别的 note 没有区别。

**没这么做的钱包**（恶意的或有 bug 的）会留下一个属于收款方、但收款方扫不出来的 note。

所以服务会记一份**付费台账**：节点接受某次提交后，服务把这笔交易第三个输出的 opening 追加到台账里。

## 文件从哪里来

1. 运维从 prover 的机器上**手工**拷出台账（即服务的 `QUMBRA_PROVER_ANNULET_PAID_LEDGER` 文件），放到收款钱包所在的机器上。
2. 运维在那台机器上导入。

**收款方的 seed 永远不上 prover 的机器。** 那台机器只知道收款地址。

台账能打开 note，要像钱包自己的文件一样保管：只有所有者可读，不进日志，不进 git。

## 导入

```sh
qumbra-wallet import-openings --net annulet --dir WALLET --ledger paid-ledger.txt
```

**前提：** 钱包必须有 Candidate A 的授权 journal（`auth.v1`），没有就按名拒绝。v1 的 net 没有 prover 费用。

**联网：** 导入不联网，什么都不取。

**重复导入：** 同一份台账导入多次是安全的。已经保存过的 opening 会显示 `already-imported`。

### 导入时查什么

**文件第一行**必须是 `qumbra-prover-paid-ledger 1`。否则整个文件被拒（「不是 version 1 的付费台账」），什么都不写。

**其后每一行**各自给出结论，某一行被拒不影响其他行。按下面的顺序检查：

| 检查 | 不通过时的结论 |
|---|---|
| 行长不超过 1 KiB（解析之前就查） | `refused:malformed(length)` |
| 条目版本是 `1` | `refused:entry-version-unknown(<v>)` |
| 字段恰好是 `cm value asset rkm rho rseed shape at`，顺序一致，各自格式正确 | `refused:malformed(<字段>)` |
| `asset=0` | `refused:not-asset-0` |
| 用 opening `(value, 0, rkm, rho, rseed)` 重算出的 cm 等于这一行的 `cm` | `refused:cm-mismatch` |
| `rkm` 属于本钱包：某个已分配地址在 journal 里某一代下的 rkm | `refused:not-this-wallet` |

**最后一行如果没有换行**，说明服务写到一半崩溃了，这一行显示 `skipped:torn-last-line`。服务下次启动时会给这一行补上换行，之后再拷一次文件就能导入。

**`shape` 和 `at`** 只检查格式，不保存，也不影响结论。

**保存下来的内容：** 通过的 opening 写进钱包目录里的 `openings.v1`：
- 先写临时文件再改名替换；创建时设为只有所有者可读写（0600），前提是平台有权限位——Windows 上没有，文件继承所在文件夹的 ACL，和 seed 文件一样；
- 每个 `cm` 只记一次；
- 同时记下每个 opening 归属的地址序号和 generation。

权限只在创建时设置，打开时不检查，和钱包的其他文件一样。

扫链加载这个文件时会逐条复核：地址序号必须是已分配的，opening 在那个地址和 generation 下必须能打开它的 `cm`。手工改过的文件会被按名拒绝，不会去猜。

**输出：** 每行一条，包括行号、`cm` 的前 16 位 hex 和结论；最后是计数：

```
line 2: cm 3f9ac2010b7e4d55… imported
line 3: cm 3f9ac2010b7e4d55… already-imported
line 4: cm - refused:entry-version-unknown(2)
imported 1, already imported 1, refused 1, skipped 0 — membership is checked by `scan --net annulet`, never here
```

**`rho` 和 `rseed` 永远不会打印。**

### 导入时不查什么：是否在链上

opening 的 `cm` 是否真的在链上，是**扫链**要回答的问题，和其他所有 note 一样，在扫链时判定。

**匹配：** `scan --net annulet`（`history` 和 `send` 跑的是同一个验证扫链）只要在服务给出的 compact 流里看到导入的 `cm`，就把这个 note 算作本钱包的，不管能不能解密。共识要求每个输出的 `cm` 都绑定在所属交易的 discovery 条目里，所以即使输出扫不出来，它的 `cm` 也一定在流里。

**位置：** 这个 note 所在的高度和交易一律取自链上，绝不取自文件。验证模式的扫链还会像对待每个 note 一样，拿它去核对区块 body。

**之后：** 这个 note 就和普通 note 一样：
- 花掉后会被扣除；
- 0 值的（价格为 0）进入 zero 桶（看得见，但永远不可花）；
- 扫链本身也解出来的，只算一次。

**没找到的：** 导入了、但扫链在范围内没看到 `cm` 的 opening，只计数，绝不计入余额：

```
imported: 3 opening(s) found on chain; 1 not found in 0..=1204 (counted only, never in a figure)
```

**在不是 Candidate A 的 net 上**，持有导入 opening 的钱包，其扫链会被按名拒绝（`imported_openings`）。
