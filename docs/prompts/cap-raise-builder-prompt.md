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

1. **N.** My recommendation is **8**, and I want your disagreement if you have grounds. Each payee is
   a real coinbase note — a derivation, a commitment, a leaf in the tree — so N multiplies coinbase
   tree growth and every light client's scan cost per block. 8 splits a small pool meaningfully at
   8× the coinbase leaf rate. It is **not** a Monero-scale pool's answer, and it does not need to be:
   the cap is a maximum, and a pool pays `min(N, window winners)`. **N is trivially changed before
   activation** — the constant is inert until the boundary — so pick the defensible number and say
   why, do not agonise.
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
