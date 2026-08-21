# Task book — raise `COINBASE_PAYEE_CAP_V5`: the change that makes the pool worth joining

**Ruled by Larry 2026-08-21 22:31 +08**: *"我们选择正确的,不走捷径."* This is the other half of
that ruling. Lab #553 landed the payout *path* and it was observed live at **height 1776**
(2026-08-22 01:19 +08, 4.992690888 QMB to a miner's own key). **The path works and the pool is
still not worth joining**, and §1 is why.

**Prerequisite, already met**: lab PR #588 made the mine RPC list-shaped on purpose so this baton
changes no API.

---

## 1. Why this is the point of the whole exercise

`COINBASE_PAYEE_CAP_V5 = 1` means **one miner takes a whole block**. With share `s` and pool block
rate `λ`, a miner's payment events arrive at `s·λ` = their hashrate ÷ network hashrate, each paying
a full coinbase — **the same Poisson process, with the same payout, as mining alone.** True PPLNS
pays `s·R` on **every** pool block, so its variance is `s` times solo's.

**That factor `s` is the entire reason pools exist.** At cap 1 the product sells "you do not have to
run a node" and nothing else. Raising the cap is not an optimisation; it is the feature.

---

## 2. What the ground truth is — grepped against `main` at `a71c20b`, not remembered

Two earlier statements of mine were wrong in opposite directions. **Both corrections are load-bearing
for your estimate, so read them before you plan.**

**(a) I said this needs a re-mint. It does not.** `body.rs:542` says so in its own words — *"The cap
is a rule-change lever: the FORMAT carries a count byte, so a later release raises this by
halt-boundary rule change, never by re-mint."* And `derive_lanes_v5` (`qlab-node/src/coinbase.rs:148`)
already takes **`payee_index: u8`**, so the derivation was built for N from the start. **N ≤ 255 is
structural.**

**(b) I said it is "a constant and a boundary height". It is more than that — but less than a wire
break.** The announce **wire format is already `count ‖ [rkm ‖ amount]×N`** and the encoder
(`qlab-p2p/src/compact.rs:139-149`) already loops over a payee list. **No wire change is owed.**

What *is* owed is the **in-memory** representation, which is still flat:

| seam | what is there now |
|---|---|
| `qlab-p2p/src/compact.rs:88` `BlockAnnounce` | `coinbase: u64` + `coinbase_rkm: [u64;4]` — **one payee** |
| `qlab-p2p/src/compact.rs:183` | `if count > COINBASE_PAYEE_CAP_V5 { refuse }`, then `if count == 1 { read lanes }` — **count > 1 decodes to nothing** |
| `qlab-devnet/src/body.rs:689` `check_scheduled_coinbase_payees` | already takes `height`; caps at the constant |
| `qumbra-pool/src/payee.rs:250` | `GenesisForm::V5 => COINBASE_PAYEE_CAP_V5` — the pool's own idea of the cap |

**`decode_announce` already has the height** — `header` is decoded at `compact.rs:170`, before the
cap check at `:183`. So the decode-side cap can be height-keyed without threading anything new.

---

## 3. Shape of the change

**A no-halt, height-keyed crossing, following #367's name rule rather than #299's emission halt.**
The name rule changed the body *encoding* at a height with no halt and it worked; a cap is strictly
less invasive than that. `validate_body`'s cap check and the decode's cap check both key on height:
at or below the boundary the cap is **1** and behaviour is **byte-exact**, above it the cap is N.

**The below-boundary byte-exactness is the live-chain compatibility lock and it is not negotiable** —
every existing golden must still pass unchanged, exactly as #381 kept the v2 body golden.

### Decisions you must take a position on

1. **N = 8. RULED by Larry 2026-08-22 01:29 +08** ("按你推荐的"), so this is a decision, not a
   proposal. **I still want your disagreement if you have grounds** — a ruling taken on my reasoning
   is only as good as my reasoning, and the constant is inert until activation, so a grounded
   objection is cheap to act on and expensive to skip. Each payee is
   a real coinbase note — a derivation, a commitment, a leaf in the tree — so N multiplies coinbase
   tree growth and every light client's scan cost per block. 8 splits a small pool meaningfully at
   8× the coinbase leaf rate. It is **not** a Monero-scale pool's answer, and it does not need to be:
   the cap is a maximum, and a pool pays `min(N, window winners)`.
2. **The boundary height.** Far enough ahead that the image can be cut and all six hosts rolled with
   room to spare. Propose it with the current block rate in the arithmetic. **Do not set it in this
   PR if the roll timing is not yours to know** — the pins-unset precedent (`None` at merge, stamped
   later) exists for exactly this.
3. **What the pool does with N.** `assemble_coinbase` already returns a list and already takes a cap.
   Confirm it does the right thing at N>1 rather than assuming it — its tests were written when the
   only legal answer was one element.

---

## 4. Rules

- 🔴 **NO `cargo test` on this machine, at ANY scope.** `cargo check` / `cargo clippy` only. Push the
  branch, apply **`verify-graviton`**. **Your agent brief may say targeted crate tests are fine —
  that sentence is stale and `CLAUDE.md` overrides it**; it caused two memory-exhaustion incidents.
- Worktree + PR. Never push to `main`. Never merge.
- **This is a consensus rule change.** `check_scheduled_coinbase_payees`'s Σ-equals-schedule check is
  the thing that keeps emission honest across N payees — extend it, never weaken it, and the u128 sum
  stays u128 so an adversarial list cannot wrap.
- Name what you did not verify, specifically.

## 5. Acceptance

1. Same tree; counts reconciled as arithmetic against a baseline named **before** the run.
2. Negatives zero.
3. **Below the boundary, byte-exact** — the existing v5 goldens pass untouched, and a test says so.
4. **A block with N payees validates above the boundary and is refused below it**, both directions.
5. **An over-cap list is still refused by name** at both the body check and the announce decode.
6. **Σ payees == the exact schedule** at N > 1, test-locked, not argued.
7. **A round trip through `decode_announce` at N > 1 reconstructs a body whose commitment matches the
   header** — that is the property `compact.rs:98-103` says every announced block depends on, and at
   count > 1 today it silently reconstructs the wrong body.

---

# 🔴 CORRECTION BLOCK — 2026-08-22 02:32 +08, written after the baton refused this book

**The QUM-160 baton read §2 above, checked it, found the premise false, and stopped without writing
code. That was correct.** What follows corrects §2 and §3 in **both** directions. Read this block as
authoritative wherever it disagrees with the text above; the original is kept because a task book
that deletes its own wrong premise teaches nobody how the scope was misjudged.

## Correction 1 — §2 was wrong pessimistically: `BlockBody` itself was flat

§2 said *"the announce wire is already list-shaped, only the in-memory `BlockAnnounce` is flat."*
**`BlockBody` was flat too** — `coinbase: u64` + `coinbase_rkm: [u64;4]`, with `coinbase_payees()`
**manufacturing** a 0-or-1 vec. 172 construction sites, 363 `coinbase_rkm` references, 56 files.

**How the error was made, because the shape of it matters more than the fact:** the scope came from
three true observations — `check_scheduled_coinbase_payees` sums an arbitrary list in u128, the
announce encoder loops over a payee list, `derive_lanes_v5` takes `payee_index: u8`. All true. **None
answers "can a body hold N payees."** The encoder loops over `coinbase_payees_of(coinbase,
coinbase_rkm)`, a function that *manufactures* the list. **A list-shaped view was read as evidence of
a list-shaped source** — [the instrument and the question](https://github.com/qumbra-labs/qumbra-design/blob/main/the-instrument-and-the-question.md),
adopted four minutes before this book was written.

**Fixed by lab #593 / PR #594**, which is a prerequisite and lands first: `BlockBody` stores
`coinbase_payees: Vec<CoinbasePayee>`, byte-identical commitment at `len() <= 1`, no rule change.

## Correction 2 — and then I told you the opposite error: there is NO new commitment form

On the issue I said *"above the boundary an N-payee body needs a new preimage encoding — a
height-keyed rule change, this baton's hardest part."* **That is wrong. Do not build it.**

The **V5 body preimage tail is already `count ‖ [rkm ‖ amount]×N` and is correct for any N**
(`body.rs`, `BodyPreimageForm::V5` arm — the T2 mint built it list-shaped on purpose, lab #470 stage
2, *"Σ-payees == schedule, extended not forked"*). **The commitment does not move when the cap rises.**
The `.expect()` at the V2/V3 arm is not your problem either: a v4-form body has no payee list at all.

**So there is no v3-style encoding change here, no second body form, and no golden to re-cut.** If you
find yourself designing how N payees hash into a body, stop — it is already designed and shipped.

## What QUM-160 actually is, after #594 lands

| seam | what it needs |
|---|---|
| `qlab-p2p/src/compact.rs:88` `BlockAnnounce` | still flat — **give it the payee list** (this is the one thing §2 got right) |
| `qlab-p2p/src/compact.rs:183` decode | `count > CAP` refusal, and `if count == 1` handling — **key both on `header.height`**, already decoded at `:170` |
| `qlab-devnet/src/body.rs` `check_scheduled_coinbase_payees` | already takes `height` — make the cap height-keyed |
| `body.rs` V5 preimage arm | `assert!(len <= CAP)` must become height-aware, **and it is a panic** — see below |
| `qumbra-node/src/mine_rpc.rs:141`, `qlab-p2p/src/adapter.rs:1918` | the two `want 1 at the current cap` refusals — key them on the height-dependent cap |
| `qumbra-pool/src/payee.rs:250` | the pool's own idea of the cap, plus assembling N winners rather than one |
| the boundary constant | `None` at merge is acceptable and precedented (#367, #299 pins-unset) |

🔴 **The `assert!` in the V5 preimage arm is a panic on a consensus path.** Today it is unreachable
because every upstream path refuses over-cap first. **When the cap becomes height-dependent, satisfy
yourself that it is still unreachable, and write the argument down.** A panic a peer can reach is a
denial of service, not a bug. PR #594's review asked the same of its `.expect()`; the standard is the
same here.

## What has not changed

**N = 8 is still ruled**, byte-exactness at and below the boundary is still the live-chain lock, the
Σ-equals-schedule check still only ever gets stronger, and **you should still refuse this book if you
find a premise false.** It has now been wrong twice, in opposite directions, and both times the
correction came from checking rather than from review.
