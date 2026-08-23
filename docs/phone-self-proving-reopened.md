# Phone self-proving, re-opened — handoff

**Status: NOT DECIDED. Two measurements are owed before anyone changes a parameter.**
Paired with [`phone-self-proving-reopened-zh.md`](phone-self-proving-reopened-zh.md).

Written 2026-08-23 as a session handoff. Nothing in this document has been built;
every PR from the session that produced it is merged and every worktree is clean.

**2026-08-23 follow-up:** a Qumbra-operated shared prover is a feasible third
branch that keeps b16 and serves every phone. Larry ruled that requiring users
to operate a persistent self-hosted prover is too much friction and is **out of
scope**. The shared service's trust and Internet-security boundary is recorded
in
[`backend-assisted-proving-security.md`](backend-assisted-proving-security.md).

---

## 1. How this came up

Larry, 2026-08-23: **「ios app 上 send 太麻烦了,还要跟 mac prover pair」**

He is right about the friction, and it is worse than "pair once". Measured from
the scripts as they stand:

| step | where |
|---|---|
| run `scripts/run-paired-prover.sh <LAN-name>` | on the Mac, **per send** |
| …which runs `cargo build --release` first | `qumbra-wallet-macos/scripts/run-paired-prover.sh:17` |
| the process **exits after one authenticated request** | `rust/src/bin/qumbra-paired-prover.rs:6,82` |
| scan the QR | on the phone, **per send** |

So it is not a pairing you do once. It is a command you run and a code you scan
**for every single spend**.

## 2. Why the pairing exists — verified, not recalled

A phone cannot prove the consensus config. `qumbra_ffi`'s own header says so
(`crates/qumbra-ffi/include/qumbra_ffi.h:426`) and the source is
[`self-proving-vs-proof-size.md`](https://github.com/qumbra-labs/qumbra-design/blob/main/self-proving-vs-proof-size.md),
branch (b), **decided by Larry 2026-07-17**.

That doc also records **(a) as a standing written fallback**, in its own words:

> flipping to (a) b4/241 KB remains a parameter change, not a redesign, **if
> phone-at-launch is ever re-judged critical** before WHIR matures.

Larry's complaint is that re-judging. Asked to choose, he picked **branch (a):
flip to b4, phone proves locally**.

🔴 **He chose it against an option label I had written wrongly.** My label said
b4 means「彻底不要 Mac」— *no Mac at all*. That is false; see §4. The choice
should be re-confirmed against the corrected trade before it is acted on.

## 3. The numbers in the design doc are stale

The doc's ladder was measured before the T2 mint:

| config | working set | tx | source |
|---|---|---|---|
| b16 (current consensus) | 15.1 GB | 136.9 KB | design doc §1 |
| b8 | 5.2 GB | 171.6 KB | design doc, M3 follow-up |
| b4 | 2.6 GB | 236.4 KB | design doc, M3 follow-up |

Since those were taken, the mint changed the circuit: **width 617 → 643**, and
`CONSENSUS_WIRE_BYTES` **145,609 → 148,625** (`crates/qumbra-node/src/genesis.rs:107`).
So b4's real cost on today's tree is **unmeasured**. The doc even flags its own
gap: b4's RAM figure is *"to be confirmed on hardware in M2 step 2"*, and that
confirmation was never done.

**Measurement 1 (owed): b4 and b8 on the current circuit — working set, wire
bytes, prove time.** Agent sessions may not run `cargo test` on Larry's machine
(CLAUDE.md); this belongs on the rig under `scripts/rig` or on the
`verify-graviton` lane.

## 4. 🔴 b4 does not remove the Mac. It moves the line.

Larry's follow-up question — **「配置低的手机上没法 send?」** — is the one that
changes the deal, and the answer is *correct, they cannot*.

iOS caps an app at roughly half of device RAM; the
[increased-memory-limit entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit)
raises it by an amount Apple does not publish. Against the doc's 2.6 GB:

| device RAM | rough default cap | b4 self-prove |
|---|---|---|
| 4 GB (iPhone 11, SE3) | ~2 GB | **no** |
| 6 GB (13, 14) | ~3 GB | marginal, needs the entitlement |
| 8 GB (15 Pro, 16) | ~4 GB | yes |
| 12 GB (17 Pro) | ~6 GB+ | yes, and b8 too |

Three consequences, and together they are the real trade:

1. **The paired-prover path cannot be deleted.** It stays as the fallback for
   low-memory devices. b4 buys "modern phones need no Mac", not "no one does".
2. **The codebase gets bigger, not smaller** — the channel, the QR, the Mac
   binary all remain, *plus* a local-prove path, *plus* a per-device decision
   about which one to take.
3. **The bill is still paid in full**: 236 KB transactions forever (58 % over
   the ≤150 KB target) and one T2 re-mint or a permanent dual verifier (§5).

## 5. Does T2 have to be re-minted? Not strictly — I overstated that

I told Larry a config flip means a T2 re-mint. **Too absolute.** Verified:

**The genesis hash does move, but that binding does not bite.**
`FrozenParams.consensus_fri` is the string `"b16/q21/g22/fp16/a16"`
(`crates/qumbra-node/src/genesis.rs:236`) and `GenesisFile::hash()` is
keccak256 over the bincode of the whole struct (`genesis.rs:706`). So a **newly
generated** genesis differs — but T2's genesis file on disk does not change and
nodes keep matching their pin.

**The verifier is the hard binding.**

```rust
// crates/qlab-consensus/src/lib.rs:214
pub fn verify_proof(inst: &BucketInstance, pvs: &[Val], proof: &Proof<Config>) -> bool {
    let config = make_config();   // reads the single `pub const CONSENSUS_CFG`
    verify(&config, &inst.air, proof, pvs).is_ok()
}
```

It **takes no height**. A node built at b4 verifies *everything* at b4 — including
T2's existing history, proved at b16 — and rejects the chain on replay from
genesis.

So there are two routes, not one:

**A — re-mint.** One config, clean. T2 restarts from a new genesis. T2 has
already been relaunched once (its tip went 14.6k → 1.2k), and it is a testnet.

**B — height-gate the verifier.** Precedent exists in this repo twice:
`RULE_BOUNDARY_HEIGHT = 8_640` (`crates/qlab-devnet/src/emission_exact.rs:104`)
and `NAME_RULE_BOUNDARY_HEIGHT = Some(19_008)` (`crates/qlab-devnet/src/names.rs:59`).
But both gate *arithmetic*; this would gate **the proof system's construction**.
`verify_proof` would have to learn the height and both configs stay compiled in
**permanently** — every node syncing from genesis replays the b16 era forever.
Node-side cost only; wallets are light clients and verify no STARKs.

My reading: for a testnet whose purpose is to rehearse the launch config, a
re-mint is cheaper than carrying a dual verifier into mainnet. **Larry's call.**

## 6. The app cannot currently tell which path it can take

Verified in `qumbra-wallet-ios` at `8fa64d6`:

- **no `increased-memory-limit` entitlement** is declared (`project.yml` has no
  entitlements block, and there is no `.entitlements` file)
- **nothing calls `os_proc_available_memory()`** or reads `physicalMemory`

So on a device that cannot prove, the app would not refuse — it would start, and
**iOS jetsam would kill it mid-prove.** Nothing is spent (no transaction is
submitted), but the work is lost and it reads to the user as a crash.

**Measurement 2 (owed): the real jetsam headroom on Larry's actual device.**
`os_proc_available_memory()` returns the bytes remaining before the kill. It is
a ten-line probe plus one run on his phone, and it converts *"roughly half, and
the entitlement raises it by an unpublished amount"* into a number.

🔴 **This one is worth doing regardless of the b4 decision.** Even staying on
branch (b), the app should know and say which path it can honour, rather than
discovering it by being killed.

## 7. What a fresh session should do

In order:

1. **Choose against all three real branches, not the old two-way label.**
   - b4: about 236 KB on stale pre-mint data + re-mint/dual verifier + a
     fallback for low-memory devices, in exchange for local independence on
     modern phones.
   - shared b16 backend: 148,625-byte transactions today + no T2 consensus
     change + every phone can send, in exchange for a trusted, privacy-sensitive
     and availability-critical Qumbra service.
   - per-send user Mac: current behavior, rejected as product UX.
2. **Decide the backend trust bar** from the linked security handoff: disclosed
   trusted service, attested confidential worker, or a protocol-level
   phone-held transaction authorization.
3. **Only if b4 remains a contender:** run Measurement 2 (device headroom) and
   Measurement 1 (current-circuit b4/b8) on their prescribed hardware. The
   shared backend does not depend on either measurement.
4. Only after those choices and any required measurements: touch
   `CONSENSUS_CFG`.

**Superseded route:** making the user's Mac prover long-lived remains
technically possible, but Larry ruled user-operated persistent proving too
burdensome. Keep the existing one-shot path as a development tool; do not build
the product around self-hosting unless that ruling is explicitly reopened.

## 8. State at handoff

- Original handoff: `qumbra-lab` `4f54b42`, `qumbra-wallet-ios` `8fa64d6`,
  `qumbra-design` `5983048`
- Shared-backend follow-up inspected `qumbra-lab` `1c5a27b`,
  `qumbra-wallet-macos` `4bdde1d`, and `qumbra-wallet-ios` `e3a9e2d`
- Backend architecture/security handoff: `backend-assisted-proving-security.md`
  and `-zh`
- iOS `ROADMAP.md` / `-zh`: **24 ✅ / 11 ⬜**
- Nothing in this document has been built. `CONSENSUS_CFG` is untouched.
