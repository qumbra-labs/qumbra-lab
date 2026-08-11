# 發行規則邊界 — 啟用程序（lab #299 + #303）

**English version**: [`i299-emission-boundary-activation.md`](i299-emission-boundary-activation.md)
（技術細節以英文版為準。）

> 🔴 **2026-08-11 重新蓋章：邊界從 18,000 改為 8,640。** 見
> [Larry 在 issue #299 的裁決](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)：
> 18,000 背後的十天前置期是為了涵蓋啟用工作，那份工作在 2026-08-10 用了約 10 小時就做完了，
> 剩下的前置期只是壓在 T1 gate 上的純等待。8,640 是 epoch 7 `[8_064, 9_215]` 的旋轉距離點——
> 576 進去、575 到結尾，正好是中點——跟當初把 18,000 放在 epoch 15 的 720 處是同一個判準。
> 格線合法：`8_640 = 8 × 1_080`。以下全部改寫成 **8,640**；機隊先前在 18,000 蓋章武裝的狀態
> （PR #336/#337）已被取代，必須依本程序重建並重新滾動。程式碼那一半與重新推導的 pins 見 R3 PR。

讀者：**T-ops**，以及驗收這次滾動的 coordinator。這是發行規則 baton 的「線上那一半」
—— builder session 做不到的那一半，因為它需要主機權限，還需要一台 Linux/glibc 機器。

它寫在這裡而不是 `qumbra-deploy/OPERATOR.md`，是因為 `qumbra-deploy` 對這個 baton 來說
是 stop point。方便時再併進 `OPERATOR.md` §4；下面的內容不依賴它放在哪裡。

---

## 0. 到底改了什麼，兩句話

`RULE_BOUNDARY_HEIGHT = 8_640` 是在 `binary64` 發行曲線下**最後一個**被挖出並被驗證的
區塊。從 8,641 開始，正式曲線改為精確十進位版本（`qlab_devnet::emission_exact`），且
`body.coinbase == coinbase_exact(height)` 成為**有效性規則** —— 金額不對的區塊會被拒絕，
發送方會被記為 peer fault。

8,640 及以下的一切都**按已記錄的樣子**沿用（grandfathered）：epoch 1 的 −4114 區塊留著，
每一個 glibc-vs-exact 的 ±1 都留著，不重算。

它是**高度，不是日期**。按重新蓋章時實測的節奏（約 48 blocks/h）大約在 **2026-08-12**
到達，誤差是 PoW 波動。請追 tip，不要追日曆。

## 1. 前置條件

| 檢查 | 方法 |
|---|---|
| lab PR 已合併、`main` 帶有 `RULE_BOUNDARY_HEIGHT` | `grep -r RULE_BOUNDARY_HEIGHT crates/qlab-devnet/src/emission_exact.rs` |
| tip **遠低於** 8,640 —— 依裁決的中止線留餘量（見上方 §0，重新蓋章節奏下約 7 小時） | `curl -s https://explorer.qumbra.org/v1/health.json` |
| 四台主機都可連線且 `fid` 一致 | `OPERATOR.md` §3 跨主機檢查 |
| resume 映像在滾 armed 映像**之前**就已建好並推送 | 見 §3 |

🔴 **若 tip 已進入 8,640 的餘量之內而機隊尚未就緒，請在 lab #299 上要求重新蓋章，不要跟
高度賽跑。** 蓋太遠只是多幾天沒有強制的曲線；蓋太近會讓線上網路的 finality 停住。
重新蓋章只在映像建置之前才便宜（常數是編譯進去的），而且新高度必須 **≡ 0 (mod 8)**
（`release.rs` 啟動時會拒絕不在格線上的 halt height，`emission_exact.rs` 在編譯期就會拒絕）。

## 2. 第 0 步 —— pins（先做，且在 glibc 主機上做）

歷史曲線是平台相依的（#303）。三個常數把它產出的值固定下來，讓邊界之上永遠不會再求值任何
浮點數，也讓非 glibc 節點算出相同的帳：

```sh
# 在任一 Linux/glibc 主機上，用 release 映像
qumbra-node emission-pins
```

它會印出三段可直接貼上的內容，以及它跑在哪個主機上。貼到：

- `crates/qlab-node/src/emission.rs` —— `PINNED_S_ATOMIC_AT_BOUNDARY`、
  `PINNED_COMMITTEE_ACCRUAL_AT_BOUNDARY`
- `crates/qlab-node/src/supply.rs` —— `PINNED_EPOCH_EXPECTED`（7 列，epoch 0..=6）

這個指令是**純函數** —— 不讀 data dir、不連網、不看鏈 —— 所以任何人都能重跑比對。請確認
標頭那行寫的是 `linux`；在 macOS 上產生 pin 是這一步唯一可能犯的錯，而且在有陌生人的節點
與機隊不一致之前都看不出來。

不貼 pin 時的 fallback 就是歷史走法，也就是目前 glibc 機隊已經在算的東西 —— 所以
**跳過這一步不會改變目前四台主機上的任何數字，但會讓 T1 的加固沒做完。** 對 T1 它不是選配；
對今天它是選配。

pins 未設定期間，epoch 1 被標註的 `KNOWN-SCAR` 判定也只在 glibc 上跨平台穩定（非 glibc 的
見證者可能算出 −4113/−4115 而顯示 `DIVERGENT`）。把 epoch 1 pin 起來同時修掉這一點。

## 3. 兩個映像都要先建好，才滾任何一個

同一份原始碼產出兩個 binary：

```sh
# ARMED 公告 binary —— 這是 DEFAULT 建置
cargo build --release -p qumbra-node
#   banner: "halt plan: halts at 8640"

# RESUME binary —— 越過邊界的那一個
cargo build --release -p qumbra-node --features rule-boundary-resume
#   banner: "resumes past: height 8640"，revision v1.1-exact-emission
```

🔴 **先建好並推送 resume 映像。** armed 映像會讓網路在 8,640 停住；如果那一刻 resume 映像
還不存在，finality 就會一直停到它存在為止。

## 4. 滾 armed 映像（在高度 8,640 之前）

依 `OPERATOR.md` 一台一台滾。每台主機都把 banner 讀回來：

```
  release:      qumbra-node v1.0 (halts at the emission-rule boundary, lab #299/#303)
  halt plan:    halts at 8640
  revision:     v1.0
```

如果某台沒印出 `halts at 8640`，就是沒拿到新映像 —— 先修好再往下。混合族群在設計上是允許的
（`committee-and-governance` §4），但還在舊映像上的主機會在 8,640 之上繼續挖一條升級後族群
會拒絕的分支。

## 5. 讓網路停在 8,640，然後確認邊界已 finalized

8,640 是 checkpoint cadence 的倍數（8 × 1,080），正是為了讓邊界成為 **finalized** 邊界。
在動任何東西之前：

- 每台主機都報 `final=8640`，且 **`fid` 相同**（`OPERATOR.md` §3）；
- 這裡的 `fid` 分裂是 🔴 STOP 而不是 finding：不要滾 resume 映像，並在 lab #299 上回報。

此時 armed binary 可以自由重啟 —— 它無法越過邊界，所以「重啟以檢查一個已停住的節點」是明確
允許的，並且有測試鎖住。

## 6. 滾 resume 映像

一台一台。每台主機會改寫自己的 halt marker，記下 `v1.1-exact-emission` 為現行 revision，
並記下邊界已 **passed**。之後：

- **pre-rule** binary（任何在這次改動之前建的映像）會被 `UndeclaredResume` 拒絕 —— 這個拒絕
  就是重點，它擋住未升級節點用平台相依的曲線去驗證邊界之上的區塊；
- 之後帶同一個 revision 的日常 release 可以自由啟動，並從 marker 讀取自己的 PoW 規則 domain（#81）。

當 ≥⅔ 的委員會金鑰都在 resume 映像上，finality 就會在 8,640 之上恢復。

## 7. 驗證規則真的生效了

```sh
qumbra-node audit-emission --data-dir /opt/qumbra/data --from 8641
#   exit 0 = 邊界之上每個區塊都提交了 coinbase_exact(height)
```

四台都跑。然後在 operator view 上：

- epoch 7 跨在邊界上（`8_064..=9_215`），它的 expected 側是分段的：已記錄的邊界前前綴，
  加上邊界之上的精確走法。它應該顯示 `AGREED`，而且 **8,064..=8,640 之內任何被沿用的 ±1
  都無法讓它顯示別的** —— 這是刻意的，代表那個前綴裡的單區塊缺陷必須用 `audit-emission` 找，
  而不是用 epoch 那一列；
- epoch 1 顯示 `KNOWN-SCAR −4114` 並附 #299 引用，且**不會**觸發 divergence 退出碼。
  其他任何地方的任何非零總和仍然會。

## 8. 「做完」是什麼樣子

- 四台都在 resume 映像上，`fid` 相同，`final` 在 8,640 之上持續前進；
- 四台的 `audit-emission --from 8641` 都 exit 0；
- pins 已貼上並合併（或在 #299 上明確記錄決定把它延到 T1 之後 —— §2 說明這樣會留下什麼沒做）；
- T1 gate 已解除：**在公開挖礦開放之前，邊界已經越過。**
