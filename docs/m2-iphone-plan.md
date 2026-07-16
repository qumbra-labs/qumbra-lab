# M2 — phone-class proving on iPhone: build path + step-0 memory ladder (2026-07-17)

Target restated (performance-budget §3–4): prove the 2×2-bucket tx on a phone
in **≤ 15 s [assumption]**, at a config the network actually accepts —
the consensus FRI config and the phone's abilities are the same decision.

## 0. The finding that reframes M2: memory, not seconds

Plonky3 0.6.1's PCS materializes the full LDE to commit it. At the M1.5c
geometry (402 cols × 2^19 rows, KoalaBear):

| blowup | LDE working set (trace alone) | proof size | provable on iPhone? |
|---|---|---|---|
| 16 (M1.5c recommended, 136.9 KB) | **13.5 GB** | 136.9 KB measured | **no iPhone, period** |
| 8 | 6.7 GB | step-0 cell below | 12 GB-class (17 Pro) with entitlement, maybe |
| 4 | 3.4 GB | step-0 cell below | 8 GB-class Pro with entitlement, maybe |

iOS's jetsam kills apps at roughly **half of device RAM** by default
([measured-in-the-wild numbers](https://github.com/PojavLauncherTeam/PojavLauncher_iOS/issues/97),
[Apple's jetsam docs](https://developer.apple.com/documentation/xcode/identifying-high-memory-use-with-jetsam-event-reports));
the [`com.apple.developer.kernel.increased-memory-limit`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.kernel.increased-memory-limit)
entitlement raises it on supported devices (Apple publishes no exact
numbers — on-device measurement is part of step 1). Even the most
generous plausible limit (~8 GB on a 12 GB iPhone 17 Pro) is far under
the b16 working set.

**Consequence:** the network config must be provable by its weakest
intended prover. If phones must self-prove, the consensus config drops to
b8 or b4 and the proof-size cost of that is exactly what step 0 measures
on the Mac (no phone required). If step 0 says b4/b8 breaches ≤150 KB,
M2 escalates to the performance-budget §4 fallback ladder (relax target /
delegated proving / WHIR-class PCS maturity) — a design decision for the
design repo, not a lab tweak.

Step-0 rig additions (this PR): the `narrow` mode gains the b4/b8 memory-
ladder cells and an `--only <substr>` filter — one config per process,
which both lets `/usr/bin/time -l` attribute peak RSS per config and is
the exact shape a per-launch phone harness needs.

**Step-0 measured (M5 Max, AC; peak RSS via `/usr/bin/time -l`, one config
per process; run outputs in `docs/narrow-M2step0-*.md`):**

| config (all 100 bits) | peak RSS | proof KB | prove (M5 Max) | phone verdict |
|---|---|---|---|---|
| b4/q45/g10/fp16/a16 | 3.9 GB | 266.0 | 0.65 s | fits 8 GB-class w/ entitlement; **proof 77% over target** |
| b4/q40/g20/fp16/a16 | 3.9 GB | 238.5 | 0.76 s | fits; **59% over target** |
| b8/q30/g10/fp16/a16 | 7.6 GB | 190.0 | 1.09 s | marginal even on 12 GB-class; 27% over |
| b8/q27/g19/fp16/a16 | 7.6 GB | 172.7 | 1.10 s | marginal; 15% over |
| b16/q20/g20/fp16/a16 | 15.1 GB | **136.9** | 2.04 s | **no iPhone** |

Two step-0 conclusions, both design-grade:

1. **The 15 s target itself is comfortably safe.** Low-blowup proving is
   *faster* (0.65–1.1 s on the Mac); a phone at 4–8× slower lands at
   3–9 s. M2's original question ("is 15 s reachable?") is answered yes
   before touching a phone.
2. **Self-proving phones and the ≤150 KB tx target collide head-on.**
   The size–memory frontier is monotone: every config a phone can hold
   in RAM produces a proof ≥ 172.7 KB (b8, itself marginal on 12 GB
   devices) or ≥ 238.5 KB (b4, the realistic 8 GB-class point). No FRI
   parameter combination escapes this at 100 conjectured bits — queries
   must rise as blowup falls. Resolving the collision is a design-repo
   decision among: (a) relax the tx target for self-proved transactions
   (~240 KB — Abelian demonstrates ~100 KB-class txs clear markets, and
   the performance doc's PQ-tax section already prices 20–30×); (b)
   delegated/assisted proving (privacy implications — its own doc); (c)
   WHIR-class PCS (the §4 escape hatch — smaller proofs at low blowup,
   external maturity gate); (d) network accepts multiple configs (weakens
   uniformity, anonymity-set fragmentation risk). Device measurements
   (step 1–2) stay worthwhile to pin the real phone constants, but the
   decision above is what M2 actually reports back to the design repo.

## 1. Build path (researched 2026-07)

**Toolchain.** `rustup target add aarch64-apple-ios` — tier-2 target with
std; rayon works (2P+4E cores on current A-series). The whole bench is
already a single self-contained binary, which is the easy case.

**Harness options, in recommendation order:**

1. **cargo-dinghy** ([sonos/dinghy](https://github.com/sonos/dinghy) —
   actively maintained, latest release 2025-12): `cargo dinghy -d iphone
   bench/test` auto-wraps the binary in a signed app, installs, runs via
   lldb. Fastest to first number. Constraint to verify early: whether its
   app wrapper can carry the increased-memory entitlement in the
   provisioning profile — without it, b8 cells will jetsam on an 8 GB
   device.
2. **Hand-rolled bundle + `xcrun devicectl`** (Xcode 15+, iOS 17+;
   [devicectl reference](https://deepwiki.com/cameroncooke/XcodeBuildMCP/10.1-physical-device-tools),
   [worked example](https://lauerman.dev/posts/handmade-ios-part-2/)):
   build the Rust binary, wrap in a minimal `.app` (Info.plist), codesign
   with a development identity + profile carrying the entitlement, then
   `devicectl device install app` / `devicectl device process launch
   --console` — fully scriptable from the Mac, full control over
   entitlements. This is the fallback if dinghy fights the entitlement,
   and likely the end-state harness.
3. **Simulator** (`aarch64-apple-ios-sim`): runs at host-Mac speed —
   useless for numbers, fine for smoke-testing the harness.

**Methodology on device:** one config per launch (`--only`); log
`ProcessInfo.thermalState` before/after each run; cold-start runs,
airplane mode, charger attached and reported per the bench discipline
(rev, device model, iOS version, power/thermal state); best-of-3 within
a launch as on the Mac.

## 2. User-manual items (outside Claude's control, wall-clock unknown)

- **Mac:** Xcode installed + license accepted; your Apple ID added
  (free personal team suffices for on-device dev runs; profiles expire
  every 7 days and need re-signing).
- **iPhone:** the actual model decides the ladder — 8 GB (15/16 Pro
  class) caps at ~b4; 12 GB (17 Pro class) may reach b8. Enable
  Developer Mode, trust the cable.
- **If** the increased-memory entitlement turns out to require a paid
  developer account ($99/yr) on-device: that's your call at that point.

## 3. Work plan (Claude session-hours)

| step | what | estimate |
|---|---|---|
| 0 | memory-ladder cells on the Mac (this PR) | done with this PR |
| 1 | dinghy first, devicectl-bundle fallback; harness + entitlement + thermal logging | ~1–2 session-hours + user manual setup |
| 2 | device matrix (ladder configs × cold runs), report, design-repo M2 write-up (EN+ZH) | ~1–2 session-hours |
| 3 | go/no-go vs §4 fallback ladder if ≤150 KB and phone-RAM collide | analysis, part of step 2's write-up |
