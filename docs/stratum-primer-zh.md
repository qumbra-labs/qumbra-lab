# Stratum 是什么?——两分钟入门

> [English](stratum-primer.md) · 读者:想通过矿池挖 Qumbra 而不想跑节点的人,或读
> [pool-stratum-mapping-zh.md](pool-stratum-mapping-zh.md) 时想先知道底下协议是什么的
> 人。写于 2026-08-19(Larry 问起;答案值得留档)。

**Stratum 是矿机和矿池之间说话的协议。**名字来自拉丁语"地层"——2012 年比特币社区
取的,没什么深意,后来成了事实标准的名字。Qumbra 说的是 Monero 家族的方言,也就是
stock XMRig 内置的那种。

## 怎么工作

一条 TCP 长连接,JSON 行来回:

1. **login**——矿机报到("钱包地址在此,算法 `rx/0`"),矿池回会话 ID 和第一份活;
2. **job**(池→矿机)——一份工作模板:对 Qumbra 就是那个 **97 字节 v5 区块头**
   (叫 blob),外加 share 目标和 RandomX 种子。发活前,池子先往 blob 的 43–46 字节
   写好每连接不同的 **extra-nonce**,保证两台矿机永远不会磨同一片搜索空间;
3. 矿机在自己的窗口(blob 的 39–42 字节)里疯狂试 nonce,算 RandomX 哈希;
4. **submit**(矿机→池)——哈希好到过 share 门槛就交回去。

**share** 是"工作量凭证":难度远低于真出块,所以矿机每隔几秒就能交一份,池子靠数
share 按贡献分账(Qumbra 矿池用 PPLNS 窗口)。偶尔某份 share 好到达到**链上真难度**
——那就是一个区块:池子组装好(收款人列表 coinbase 里带上各矿工的份额)提交上链。

## 为什么对 Qumbra 重要

**stock XMRig 出厂就说 stratum。**route A 的整个赌注是"矿机侧一行代码不改"——所以
T2 的 v5 区块头是按 stratum 的习惯**反着设计**的(nonce 挪到 39–46 字节,正好落进
XMRig 的既定窗口),[#490](https://github.com/qumbra-labs/qumbra-lab/issues/490) 修的
工作量字节选择是同一个赌注的另一半(XMRig 判 share 好坏时读哈希的哪几个字节)。
终局:下载 XMRig,填上 `pool.qumbra.org:3333` 和一个收款地址,你就在挖 Qumbra。

深入阅读:[pool-stratum-mapping-zh.md](pool-stratum-mapping-zh.md)(逐字段协议映射)、
`crates/qumbra-pool/`(矿池实现)、lab #482(施工记录)。
