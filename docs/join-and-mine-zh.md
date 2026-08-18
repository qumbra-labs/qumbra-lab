# 加入 Qumbra 测试网并挖矿

English: [`join-and-mine.md`](./join-and-mine.md) · **技术细节以英文版为准。**

这是项目无法控制的参与者进入 T1 的操作路径。

> **数值已于 2026-08-16 作为 T1 公告包填入**(设计文档 `t1-sg-posture-decision`,顺序:
> Gate A 复测 → 本包 → SG 开放)。它们读自已部署的 fleet,不是猜测:镜像 digest/revision
> 来自 compose pin 及其 OCI 标签回读,种子是 SG 姿态决定的四个**开放**入口(node0 刻意
> 不是入口)。**公告发布(Larry 放行)之前,这些种子监听的端口尚未对公网开放**——在那一刻
> 之前连接被拒是姿态在起作用,不是地址写错。若 fleet 在填写与公告之间又滚了镜像,
> digest/revision 两行在发布时重新核验。

> ### ⚠️ ~8 月 21 日（高度 19,008）前必须更新节点
>
> **早于 release
> [`t1-c5cfff8`](https://github.com/qumbra-labs/qumbra/releases/tag/t1-c5cfff8) 的所有
> 二进制与镜像,都会在高度 19,008 停止跟随主链**
> (约 2026-08-21 早间 +08;高度精确,日期为估计)。这包括 release `t1-91bdee4` 及此前的
> 全部节点镜像。故障是**静默的**:旧节点照常运行、照常挖矿,却走上一条没有 finality 的
> 死叉——边界处不打印任何错误。**更新已就绪:release
> [`t1-c5cfff8`](https://github.com/qumbra-labs/qumbra/releases/tag/t1-c5cfff8)**——边界前
> 更新并重启。若不更新,你的节点将在 19,009 起以 `internal` 类错误拒绝所有诚实区块并走上
> 死叉——那个签名的含义是"该更新了",不是"该调试了"。链的条款(费用表、激活高度、
> commit–reveal)不变——这是软件更新期限,不是规则变更。

## 1. 获取并验证发布版本

节点镜像公开位于 `ghcr.io/qumbra-labs/qumbra-node`。只用 **T1 公告给出的 digest**，绝不
依赖可变 tag。镜像把源码 revision 记录在 OCI 标签
`org.opencontainers.image.revision` 中；必须读回并与公告中的 revision 比较，不能相信 tag
或一次成功的 pull。标签与节点二进制均在 runtime 镜像中
([`deploy/docker/Dockerfile:123-160`](../deploy/docker/Dockerfile#L123-L160))；必须读回是
[lab #224](https://github.com/qumbra-labs/qumbra-lab/issues/224) 的教训。

```sh
IMAGE='ghcr.io/qumbra-labs/qumbra-node@sha256:c7b8b3340d35d7461daaa83acea6a8eef045bdba74d5173f9f059322ec18adbb'
EXPECTED_REV='e0b624596e29dc8a95d1f6715ed061b4247a73e2'

docker pull "$IMAGE"
ACTUAL_REV="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"
test "$ACTUAL_REV" = "$EXPECTED_REV" || {
  echo "wrong image revision: got $ACTUAL_REV, want $EXPECTED_REV" >&2
  exit 1
}
```

公告还会把以下网络身份输入一同发布：

- `genesis.qmb` —— **格式 v4**；
- `expected_genesis_hash` ——
  `138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb`；
- 写入 `dial_peers` 的初始 P2P 种子地址。

格式和哈希已在代码树中钉死
([`genesis.rs:68-77`](../crates/qumbra-node/src/genesis.rs#L68-L77)、
[`genesis.rs:775-779`](../crates/qumbra-node/src/genesis.rs#L775-L779))。分发:`genesis.qmb` 从
**`https://seed.qumbra.org/genesis.qmb`** 下载(deploy PR #150)——务必按上方
`expected_genesis_hash` 逐字节校验;`qumbra-node check` 与启动都会拒绝错误文件,被篡改的
下载无法静默通过。种子列表即下方四个开放入口(`t1-sg-posture-decision`)。

### 备选路径：预编译二进制，不用 Docker（2026-08-17 新增，lab #437）

上面的容器仍然是**可复现的基准路径**，本文编号步骤用的也是它。如果 Docker 本身就是障碍
而不是答案，同样的两个二进制以 tarball 形式发布在公开仓库的 releases 页：

**<https://github.com/qumbra-labs/qumbra/releases>**

> **在第一个版本被切出来之前，那个页面是空的，容器路径是唯一路径。** 发布流水线已经存在
> ([`release-binaries.yml`](../.github/workflows/release-binaries.yml))，由人手动触发；
> 一旦发布，T1 公告会给出对应的 tag。

| 压缩包 | 适用于 |
|---|---|
| `…-linux-x86_64-glibc.tar.gz` | Intel/AMD Linux，glibc 2.36+（Debian 12、Ubuntu 22.04+） |
| `…-linux-aarch64-glibc.tar.gz` | arm64 Linux —— 测试网机队自己跑的就是它 |
| `…-macos-arm64.tar.gz` | Apple Silicon，macOS 11+ |
| `…-windows-x86_64.zip` | Windows 10/11 x64 —— **原生，不需要 WSL2**（lab #478 新增） |

每个包内含 `qumbra-node`、`qumbra-wallet` 和一份 `PROVENANCE.txt`。Windows 那个包是 `.zip`
而不是 `.tar.gz`，里面的二进制带 `.exe` 后缀；除此之外它和其他三个是同一条发布流水线构建、
同一套断言把关的产物。**它从 2026-08-18 之后的第一次发布开始才有** —— release 页上更早的
tag 只有三个包，那是版本新旧的区别，不是文件丢了。

```sh
# 1 —— 从 release 页下载对应平台的 tarball 与 SHA256SUMS，然后：
sha256sum -c SHA256SUMS          # macOS：shasum -a 256 -c SHA256SUMS
tar -xzf qumbra-t1-<shortrev>-<platform>.tar.gz
cd qumbra-t1-<shortrev>-<platform>

# 2 —— 让二进制自己说明它是什么。下面两行都是承重的：
./qumbra-node halt-status
```

```text
  build rev:    <release notes 中给出的源码 revision>
  halt plan:    no halt scheduled
  resumes past: height 8640 (post-halt rules apply above it)
```

`build rev:` 是一个已下载的二进制证明自己来自哪份源码的方式——tarball 没有镜像标签，
所以这一行等价于上面容器路径里对 `org.opencontainers.image.revision` 的回读。如果
`halt plan:` 显示 **ARMED**，那个二进制会在 8,640 停住、无法跟随当前链，不要运行它。CI
拒绝发布 ARMED 产物，所以 release 页上出现 ARMED 二进制意味着该产物并非它所声称的东西。

**仅 macOS：** 这些二进制未签名、未公证。用浏览器下载会打上隔离属性，Gatekeeper 会拒绝
运行。请用 `curl` 下载，或显式清除该属性：
`xattr -d com.apple.quarantine qumbra-node qumbra-wallet`。

### Windows:原生(2026-08-18 新增,lab #478)

`windows-x86_64.zip` 里是 `qumbra-node.exe` 和 `qumbra-wallet.exe`,目标三元组
`x86_64-pc-windows-msvc`,用的是和其他平台完全相同的那份 RandomX C++ 实现。就链关心的
所有意义上,它们和别的平台是同一个二进制:CI 会在 MSVC 构建上跑 RandomX 官方的四组
参考向量,所以 Windows 矿工算出来的哈希就是全网的哈希,不是"差不多"。

从 §2 往下的内容全部照用——同一份 `genesis.qmb`、同样的 `node.toml` 字段、同样的种子
节点。下面只写 Windows **不一样**的地方。

**1. 下载与校验,在 PowerShell 里做。** Windows 没有 `sha256sum`:

```powershell
# 从 release 页下载:你平台对应的 zip,以及 SHA256SUMS
Get-FileHash .\qumbra-t1-<shortrev>-windows-x86_64.zip -Algorithm SHA256
# 把打印出来的哈希和 SHA256SUMS 里对应那行逐字对照——64 个字符都要对
Expand-Archive .\qumbra-t1-<shortrev>-windows-x86_64.zip -DestinationPath .
cd qumbra-t1-<shortrev>-windows-x86_64
.\qumbra-node.exe halt-status
```

`halt-status` 的读法和上面 §1 一样:`build rev:` 要和 release notes 对得上,`halt plan:`
必须是 `no halt scheduled`,不能是 **ARMED**。

**2. 🔴 SmartScreen 会拦你,而且它拦得有道理。** 这些可执行文件**没有签名**——本项目没有
代码签名证书,要不要买是另一件还没人拍板的事。第一次运行任一个二进制,都会看到
*"Windows 已保护你的电脑"*。走法是 **更多信息 → 仍要运行**。Microsoft Defender 也可能仅
凭"名声不够"就把一个 CPU 矿工程序标红。

这里说的是实情,不是让你放心:一个来自私有仓库的未签名二进制,正是 SmartScreen 存在的
理由;而"点掉安全警告"这种建议,你本来就该默认对它保持怀疑。让它在这里成立的唯一理由是
你能自己核对——**先把 SHA-256 和 SHA256SUMS 对上,再点"仍要运行"**,不是反过来。

**3. `node.toml` 里的路径要用单引号。** TOML 的双引号字符串把 `\` 当转义符,所以
`data_dir = "C:\Users\you\qumbra-data"` 要么直接解析报错,要么变成另一个目录。请用 TOML
的**字面量字符串**,或者干脆用正斜杠:

```toml
data_dir = 'C:\Users\you\qumbra-data'          # 字面量字符串——反斜杠就是反斜杠
genesis_file = 'C:\Users\you\genesis.qmb'
# 或者,在 Windows 上同样合法:
# data_dir = "C:/Users/you/qumbra-data"
```

**4. 在你自己开的控制台里跑,用 Ctrl-C 停。** 打开 PowerShell 或 Windows Terminal,在里面
执行 `.\qumbra-node.exe run --config node.toml`——不要双击。**Ctrl-C 才是能可靠触发快照
落盘的停法。** 直接关控制台窗口也会触发落盘,但 Windows 在关窗后只给程序大约五秒,一个
正卡在 RandomX 轮次里的节点可能赶不上。

赶不上也不会丢东西:区块日志每条记录都 fsync,它才是真相来源,快照过期的节点下次启动会
重放日志、到达完全相同的状态。漏掉一次落盘的代价是**下次启动的重放时间**,不是币,也不是
历史。

**5. Windows 上钱包种子文件不是"仅属主可读"。** 在 Linux 和 macOS 上,
`qumbra-wallet keygen` 会把 `wallet.seed` 写成 `0600`。Windows 没有这个模式位,而本次构建
也没有去设 ACL,所以该文件继承所在文件夹的权限——在你自己的用户目录下,通常是你**加上**
SYSTEM 和 Administrators。`keygen` 会把这件事打印出来,而不是宣称一个它并不具备的保护。
想把钱包目录改成仅属主可访问,执行一次:

```powershell
icacls "$env:USERPROFILE\.qumbra-wallet" /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
```

谁能读到这个文件,谁就拥有这个钱包里的每一枚币。

**6. 别让机器睡着。** 把 Windows 电源设置改成不休眠,笔记本插电——睡着的主机不挖矿。

**这次移植不包含**(写出来免得有人去找):没有 Windows 服务封装——想在注销后继续运行,把
`run` 命令注册成一个"不管用户是否登录都运行"的计划任务,那超出本文范围;没有代码签名;
没有 ARM Windows 构建。

### Windows:WSL2

仍然支持,内容不变:管理员 PowerShell 里 `wsl --install`,然后在 Ubuntu 里从本文 §1 开始
照走,用 `linux-x86_64-glibc` 包。挖矿速度几乎无损。有了原生构建之后,WSL2 从"路径"变成
"备选"。

## 2. 作为不挖矿的节点加入

把下载的 `genesis.qmb` 与以下最小 `node.toml` 放在同一目录：

```toml
data_dir = "/data"
listen_addr = "0.0.0.0:9400"
dial_peers = ["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]
genesis_file = "/config/genesis.qmb"
expected_genesis_hash = "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb"
mining = false
```

这些就是加入者需要的字段。`mining` 默认是 false，但上面仍明确写出。**不要**复制机队配置，
也**不要**添加 `committee_key_paths`：公网加入者是只验证节点，不持有委员会签名密钥
([`config.rs:54-94`](../crates/qumbra-node/src/config.rs#L54-L94))。

先在不绑定 socket 的情况下预检确切的 genesis 与配置，再运行节点：

```sh
docker volume create qumbra-data

docker run --rm \
  -v "$PWD:/config:ro" -v qumbra-data:/data \
  --entrypoint /usr/local/bin/qumbra-node \
  "$IMAGE" check --config /config/node.toml

docker run --rm --name qumbra-node \
  -v "$PWD:/config:ro" -v qumbra-data:/data \
  --entrypoint /usr/local/bin/qumbra-node \
  "$IMAGE" run --config /config/node.toml
```

`check` 在不开 listener 的情况下执行与启动相同的字节、格式和哈希门
([`run.rs:226-242`](../crates/qumbra-node/src/run.rs#L226-L242))。文件哈希不同会产生
`WrongGenesisHash`，节点拒绝启动
([`genesis.rs:528-555`](../crates/qumbra-node/src/genesis.rs#L528-L555))。

### 用预编译二进制做同一件事

配置、genesis、种子完全相同，只有调用方式不同。把 `genesis.qmb` 和 `node.toml` 放在解压出
的二进制旁边，`data_dir` 与 `genesis_file` 写成普通路径，而不是容器里的 `/data` 和
`/config`：

```toml
data_dir = "./qumbra-data"
listen_addr = "0.0.0.0:9400"
dial_peers = ["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]
genesis_file = "./genesis.qmb"
expected_genesis_hash = "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb"
mining = false
```

```sh
curl -fsSL https://seed.qumbra.org/genesis.qmb -o genesis.qmb
./qumbra-node check --config node.toml     # 同一个预检，退出码 0 并打印 genesis 哈希
./qumbra-node run   --config node.toml
```

发布流水线在每个产物被允许上传到 release 页之前，都会针对同一个已发布的 genesis 跑一遍
上面这个 `check`——所以到你手上的 tarball 已经在它自己的平台上预检通过了。`run` 会写入
`data_dir`，请在你有权限的目录下运行；本文其余部分——下面的 telemetry 字段、§3 的挖矿、
§4 的钱包——两条路径读法完全一致。

### NAT 是声明，不是发现

**设计上接受仅出站参与。** 在 NAT 后你仍可同步、挖矿和交易，但你的地址永远不会被 gossip，
也不会为任何 peer 提供服务。不要设置 `advertise_addr`。只有当所填 host 与 port 确实能从公网
一路拨通到此节点时才设置它；对容器而言还须发布 P2P 端口，例如 `-p 9400:9400/tcp`。这是
记录在案的 2026-07-26 NAT 决定，不是变通办法
([`config.rs:68-78`](../crates/qumbra-node/src/config.rs#L68-L78)、
[`run.rs:588-595`](../crates/qumbra-node/src/run.rs#L588-L595))。

### 健康加入是什么样

要连续阅读多条 `TELEMETRY`，不要只看一个样本
([`run.rs:1342-1371`](../crates/qumbra-node/src/run.rs#L1342-L1371))：

- `peers=N` 是实时 peer 数：`N > 0` 表示至少一个连接在线；持续 `peers=0` 表示尚未加入任何
  peer。
- `slag=N` 是 fork-choice tip 减去 applied-state tip：加入过程中应向 `0` 下降；`slag=0` 表示
  节点已应用自己选中的链
  ([`run.rs:1017-1034`](../crates/qumbra-node/src/run.rs#L1017-L1034))。
- 对上面的非挖矿配置，`mready=-` 完全正确。启用挖矿后，`unknown` 或 `behind` 表示启动挖矿门
  正在正确拒绝；`synced` 或 `latched` 才允许挖矿。它**不能**证明 `slag=0`
  ([`run.rs:376-421`](../crates/qumbra-node/src/run.rs#L376-L421))。

## 3. 把已加入的节点改成矿工

### 一条命令代替五条（2026-08-18 新增，lab #475）

§2 和 §3 其余部分讲的每一件事——建钱包、备份助记词、导出收款密钥、手写
`node.toml`、下载 genesis——都是 `qumbra-node mine` 替你做的事。节点是同一个节点，
配置是同一份配置；区别只是五步变成一步：

```sh
./qumbra-node mine --dir ~/.qumbra-miner
```

在终端里运行、且该目录还没有钱包时，它会生成一个钱包，在红色横幅下**只打印一次**
助记词，并且**等你按下回车**才继续。请在那一刻把助记词抄到纸上：它不会存放在任何
你能再读回来的地方，而这个节点挖到的每一枚币都付给它。

随后它下载 `genesis.qmb`（仅当目录里还没有时），在**绑定任何端口之前**用本二进制
内置的哈希校验它，把一份普通的 `node.toml` 写进该目录，然后运行它。没有任何隐藏
状态：事后打开 `~/.qumbra-miner/node.toml`，它就是 §2 和 §3 教你手写的那份文件。

| 参数 | 用途 |
|---|---|
| `--yes-i-backed-up` | 无终端环境(systemd unit、容器)下的确认方式。**没有终端又没有这个参数时,`mine` 会拒绝创建钱包**,而不是悄悄创建一个——助记词需要你自己从命令输出里保存下来。 |
| `--rkm <64 位十六进制>` | 付给你已经拥有的密钥。不读、不建、也不查找任何钱包;这就是上面几节讲的手动路径,原样不变。 |
| `--seeds`、`--genesis-url`、`--listen`、`--index` | 覆盖内置默认值(§1 的四个种子节点、`https://seed.qumbra.org/genesis.qmb`、`0.0.0.0:9400`、地址索引 0)。非零的 `--index` 会在运行中被**分配**到钱包里,这样本节点挖到的币始终落在 `scan` 覆盖得到的范围内;上限为 1024,更高的索引请用 `qumbra-wallet address --new` 配合 `--rkm`。 |

钱包落在 `~/.qumbra-miner/wallet`，所以 §4 的每条钱包命令都可以直接对它使用——
`qumbra-wallet backup --dir ~/.qumbra-miner/wallet --reveal` 会再次显示助记词，
`scan` 则读取这个节点挖到的东西。在已准备好的目录上重跑 `mine` 不会改变任何东西，
只是启动节点；如果你手动改过 `node.toml`，它会拒绝而不是覆盖你的修改，并提示改用
`run --config`。

在 Windows 上,这条命令是 PowerShell 里的
`.\qumbra-node.exe mine --dir $HOME\.qumbra-miner`,而且它是原生路径里最短的一条——
`node.toml` 由它自己写,所以 §1 Windows 一节里讲的 TOML 反斜杠坑根本碰不到你。

### 平台边界——2026-08-17 已更正(原:只能用 Linux/glibc),2026-08-18 加入 Windows

> **带日期更正(2026-08-17,lab #437):原生 macOS 挖矿已获准许。** 下方原红字边界的条件
> 是"确定性发行边界尚未激活"——该边界已于 2026-08-12 激活(#299/#303 已关)。高度 8,640
> 之上,`body.coinbase == coinbase_exact(height)` 是纯整数运算的硬共识规则,共识路径碰不到
> libm,原生 macOS 矿工既算不出偏差 coinbase,也造不成历史伤痕。**已实测验证,不止是论证**:
> 一个原生 macOS arm64 构建经公开入口加入 T1,同步后最初 ~100 分钟赢下 40 个被接受并
> finalize 的块(lab #437)。容器仍是铺好的可复现路径;原生构建现在是受支持的替代路径。
>
> **原生 Windows x64 挖矿基于同样的理由获准许(2026-08-18,lab #478)**;而新矿工平台真正
> 引出的"身份一致性"问题,这里用实测而不是论证来回答:每一条 windows CI 腿都会拿 RandomX
> 官方的四组参考向量去比对 MSVC 构建出来的 C++,并且还有一项检查——推荐 flag 集(JIT +
> 硬件 AES)必须与可移植的 `FLAG_DEFAULT` 结果一致,也就是说 Windows 矿工不会因为自己
> CPU 支持什么而算出不同的哈希。🔴 **还不构成证据的部分:目前没有任何一台 Windows 机器
> 在 T1 上挖出过块。** 这一行的断言是"能构建、哈希一致、对已发布 genesis 预检通过",不是
> "已实测验证"——后者是 macOS 有而 Windows 还没有的,两者不该被当成同一个断言来读。
>
> **从源码构建时有一个 flag 性命攸关**:裸 `cargo build -p qumbra-node` 产出 ARMED 变体,
> 会在 8,640 停机、无法跟上今天的链。必须带
> `--features qumbra-node/rule-boundary-resume` 构建,并用 `qumbra-node check` 确认——
> `halt plan:` 行必须是 `no halt scheduled`,不能是 `ARMED`。**§1 中发布的 tarball 已经
> 带着这个 flag 构建**,且 CI 拒绝发布没带的产物,所以只有自己编译时才需要操心这个 flag。

原边界文字存档:*在确定性发行边界被公开确认已激活之前,只能在 Linux/glibc 上挖矿……实测
macOS 矿工在特定高度计算出的 coinbase 会与 glibc 相差 ±1 bessel
([lab #303](https://github.com/qumbra-labs/qumbra-lab/issues/303));当时的共识接受这些值,
每个这样的块都成为 [lab #299](https://github.com/qumbra-labs/qumbra-lab/issues/299) 激活
规则必须 grandfather 的永久伤痕。*

从应接收 coinbase 的钱包派生付款身份：

```sh
qumbra-wallet miner-rkm --dir "$HOME/.qumbra-wallet"
```

该命令从已分配地址 index 派生（默认 index 0），并打印节点所需的准确 64 位十六进制
`miner_rkm = "…"` 行
([`qumbra-wallet/main.rs:147-175`](../crates/qumbra-wallet/src/main.rs#L147-L175))。把它粘进
`node.toml`，只改变以下挖矿字段：

```toml
mining = true
miner_rkm = "[qumbra-wallet miner-rkm 打印的 64 个十六进制字符]"
```

启动时必须找到下面这条完全一致的行，以证明配置生效：

```text
miner payout: coinbase notes paid to the configured miner_rkm
```

如果看到下面的警告，立即停止挖矿并修正配置：有效块正在付给无法花费的占位身份，收益无法找回
([`run.rs:596-612`](../crates/qumbra-node/src/run.rs#L596-L612))。

```text
⚠️  NO miner_rkm CONFIGURED: ... Every coin this node mines is BURNED.
```

### 🔴 尚未解决的首次启动静默

曾有一次观察到：配置了 `miner_rkm` 的节点在首次启动、第一条日志出现之前，**约 57 分钟保持
100% CPU 且完全静默**。问题尚未解决
([lab #300](https://github.com/qumbra-labs/qumbra-lab/issues/300))。它不一定卡死：若进程仍活着、
一个核心被打满但没有日志，就让它继续运行。重启不能修复这条路径，只会丢掉已经花掉的工作；
等待第一条日志。

### 收益、成熟、节奏与胜率

- 赢下一个块会向钱包支付**区块补贴的 65%（包括整数舍入余数）加全部交易费**
  ([`emission.rs:27-30`](../crates/qlab-node/src/emission.rs#L27-L30)、
  [`coinbase.rs:133-139`](../crates/qlab-node/src/coinbase.rs#L133-L139))。
- Coinbase 再经过 **144 个块**才可花费。按目标约为三小时，但这不是墙上时钟承诺
  ([`emission.rs:47-55`](../crates/qlab-node/src/emission.rs#L47-L55))。
- 全网目标为**每块 75 秒**，用 **LWMA-120** 每块重定难度；可部署二进制使用真实 RandomX，
  不是 Keccak 模拟占位
  ([`params_devnet.rs:16-49`](../crates/qlab-devnet/src/params_devnet.rs#L16-L49)、
  [`pow.rs:66-100`](../crates/qlab-devnet/src/pow.rs#L66-L100))。
- 这是 solo mining，不是矿池，更不是每 75 秒给你一笔奖励。你的期望份额等于你的有效 RandomX
  工作量除以当前所有竞争工作量。公开面只暴露当前难度，不暴露机队总算力，因此本文无法诚实地
  报出个人胜率。要预期随机波动，也可能长时间一块不中。

## 4. 钱包快速开始 —— 五条命令

参数和单位以 CLI 自带帮助为准
([`qumbra-wallet/main.rs:43-66`](../crates/qumbra-wallet/src/main.rs#L43-L66))。以下五条命令
覆盖最短用户旅程；替换 `RECIPIENT_QADDR`，并记住 `--amount` 的单位是 **bessel**
（`100,000,000` bessel = `1 QMB`；
[`emission.rs:34-35`](../crates/qlab-node/src/emission.rs#L34-L35)）。
第 3 条命令使用 `curl` 和 `jq`；完整命令参考请运行 `qumbra-wallet --help`。

**在 Windows 上**，同样这五条命令在 PowerShell 里跑，把 `qumbra-wallet` 换成
`.\qumbra-wallet.exe`；`--dir` 用 `$HOME` 或 `$env:USERPROFILE` 都可以。第 3 条需要换成
PowerShell 的写法（默认没有 `jq`）：
`$TIP = (Invoke-RestMethod https://explorer.qumbra.org/v1/health.json).chain.tip_height`。

```sh
# 1 —— 创建钱包；命令会打印 address [0]
qumbra-wallet keygen --dir "$HOME/.qumbra-wallet"

# 2 —— 在私密终端备份 Qumbra 助记词
qumbra-wallet backup --dir "$HOME/.qumbra-wallet" --reveal

# 把完整 address [0] 粘贴到 https://faucet.qumbra.org，等待 grant。

# 3 —— 获取余额声明所针对的高度
TIP="$(curl -fsS https://explorer.qumbra.org/v1/health.json | jq -r '.chain.tip_height')"

# 4 —— 经公开节点边缘发现输出并扣除已花 note
qumbra-wallet scan --dir "$HOME/.qumbra-wallet" \
  --url https://seed.qumbra.org --to "$TIP"

# 5 —— 重新扫描、构造真实证明并提交；省略 --node 时默认等于 --url
qumbra-wallet send --dir "$HOME/.qumbra-wallet" \
  --url https://seed.qumbra.org --scan-to "$TIP" \
  --to RECIPIENT_QADDR --amount 100000000
```

HTTP **429 Too Many Requests 是当前 faucet 限制的预期行为**；不要反复轰击表单。
[Lab #308](https://github.com/qumbra-labs/qumbra-lab/issues/308) 记录了：通过反向代理后，按网络
取 key 的 bucket 目前会被看成共享 bucket，因此可能已被另一位访客用掉。只要该 issue 仍开放，
就按页面给出的窗口之后再试。

## 5. 镜像声明的验证记录

下面的记录只证明 package 路径公开且远程标签读回有效；它**不是** T1 镜像公告。2026-08-10，
未 pull、未使用 registry 凭证：

```text
$ docker buildx imagetools inspect ghcr.io/qumbra-labs/qumbra-node:t0-wan-14
Name:   ghcr.io/qumbra-labs/qumbra-node:t0-wan-14
Digest: sha256:931afa0fe57844f52e5bbb390914ec3116a72c3ff04781b11d8a080dcc4c2f29

$ docker buildx imagetools inspect --format \
  '{{index .Image.Config.Labels "org.opencontainers.image.revision"}}' \
  ghcr.io/qumbra-labs/qumbra-node@sha256:931afa0fe57844f52e5bbb390914ec3116a72c3ff04781b11d8a080dcc4c2f29
e8d52d7b194d3560f70de5d1f26b99b6f37bdd2e
```

不要拿这个历史 T0 digest 替换第 1 节方括号中的 T1 digest。

第 4 节的公开读取也于 2026-08-10 验证：`GET
https://explorer.qumbra.org/v1/health.json` 返回了钉死的 genesis 哈希和数字
`chain.tip_height`，`GET https://seed.qumbra.org/v1/compact?from=6313&to=6313` 则返回 HTTP 200
及 `application/octet-stream`。JSON 字段定义在
[`qumbra-explorer/json.rs:55-80`](../crates/qumbra-explorer/src/json.rs#L55-L80)；高度 `6313`
只是一次样本探测高度，不是网络参数。
