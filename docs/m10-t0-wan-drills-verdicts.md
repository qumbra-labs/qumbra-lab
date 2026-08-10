# M10 T0-WAN scenario drills — coordinator verdicts (adjudicated 2026-08-10)

> [中文版](m10-t0-wan-drills-verdicts-zh.md)

The four M10 scenario drills ran 2026-08-07 on the live T0 net (`t0-wan-13`, genesis
`138e1524…addb`, 6/5/5/5 committee). The **R1 evidence** — raw readings, no verdicts, produced
by the running session — is [`m10-t0-wan-drills-run.md`](m10-t0-wan-drills-run.md) and its
per-drill `FINDINGS.md` in `qumbra-ops/drills-138e1524/`. Under R1 the session that produces
evidence does not rule on it. **This document is that ruling.**

## The bar, and the headline

The R2 STOP-POINT criteria: a finality regression, two checkpoints finalized at one height,
finality advancing without a quorum, or a chain diverging past a finalized checkpoint.

**🟢 All four drills PASS the consensus bar. No R2 STOP-POINT was reached in any of them.**
The 6/5/5/5 topology's quorum claims were **measured, not asserted** across all three regimes:
one member down (finality continues, 16 ≥ 15), two members down (correct stall, 11 < 15, no
slot burned), and a symmetric 2+2 partition (both sub-quorum sides stall, heal by
supersession). **M10 — the internal T0 net — is COMPLETE.**

The drills' real job was to find **four operational defects, none consensus-safety** — every
one on the observability/recovery surface, where an operator is misled while the chain is
correct.

## Per-drill verdicts

**D1 — mining-node restart (node2) · 🟢 PASS (consensus) · 🔴 recovery surface.** node0/1/3
finalized continuously on 16 keys with node2's 5 absent — the 6/5/5/5 promise, no R2. But the
graceful stop did not flush (exit 137, 30 s grace expired, snapshot 26 h stale), so the return
replayed **1,987 records — the first non-zero `blocks.log` replay ever observed** (lab #104's
closing condition, MET), **silent for 15 m 31 s at 100 % CPU** — indistinguishable from #106's
wedge, and misread as a hang until it self-resolved. Defects: **#287** (silent replay needs a
progress line), #286 (see D2). **#104 CLOSED.**

**D2 — late-joiner sync (node3) · 🟢 PASS, clean, and it corrected D1.** Clean stop (exit 0,
flushed, fresh snapshot), down 60 m 39 s, **recovered in 4 s + 44-block peer catch-up in
< 39 s**. `final` advanced on 16 keys throughout the outage — a 5-key absence does not stop
finality, measured. It **refuted D1's finding as filed** (same image, 46 min apart, node3
flushed and node2 did not) → **#286 retitled: the flush is INTERMITTENT, not absent.** The
D1/D2 pair is an unplanned A/B of the stale- and fresh-snapshot recovery paths.

**D3 — committee stall → recovery · 🟢 PASS (the textbook one).** Dropping to **11 keys
(sub-quorum)** froze `final` at 3232 for the 23.5-min hold while `tip` advanced — nothing
finalized on 11 keys, no R2. First live outing of **#87's votes-short discriminant**, read
correctly through **#226's corrected `have=`**. The heal **closed the whole stalled span in
order, burning no slot** (the absent keys had committed to nothing — the sharp contrast with
2026-08-05's burn, where every key had already committed to a variant).

**D4 — 2+2 partition → heal · 🟢 PASS (consensus) · 🔴 the sharpest finding.** Both sides
sub-quorum, `final` frozen at 3264, sides on **separate branches at equal height**, no R2
(divergence behind the finalized head). Heal resumed finality at **3296, skipping the three
slots the partition burned** (#269's mechanism — one burned slot per cadence, produced
deliberately). Two 🔴 operational findings: **the run book's cut-verification is wrong**
(`peers=` never dropped; a silent partition is seen by `stipid` divergence at equal height +
frozen `final` with climbing `stall`, not by the peer count), and **node2 did not converge for
~20 min after the network was whole** — a wedged `ESTABLISHED` TCP socket (191 KB queued) kept
it from re-dialing, and it converged on a *kernel* timeout, not a node decision; every field on
its own telemetry was locally healthy throughout, only cross-host `fid` exposed it (**#289**).

## Aggregate — M10 verdict

**M10 (the internal T0 net) is COMPLETE.** No R2 STOP-POINT across four adversarial scenarios
under real intercontinental latency; the quorum arithmetic behaved exactly as the topology
promised in all three regimes. Finality never regressed, never advanced below quorum, never
double-finalized a height, and no node diverged past a finalized checkpoint.

**The recurring shape across all four is the one this project keeps paying for: a defect on the
*observation* surface while the *observed* system is correct** — a silent replay reading as a
hang (#287), a partitioned/stranded node whose every own field is locally healthy (#289, D4),
a false cut-check in the run book. Each is a case where an operator acting on the instrument
would have made it worse, on a net that was fine. That is precisely why an internal net runs
before a public one.

**Owed out of these drills:**
- lab **#287** (replay progress line) and **#289** (wedged-socket non-convergence) — dispatchable.
- the **run-book cut-verification correction** (T-ops / `qumbra-deploy` drill run book): replace
  "`peers=` drops to 1" with `stipid`-divergence + frozen-`final`-with-climbing-`stall`.
- **#286** stays open as *intermittent flush*; **#104 CLOSED**; **#269** mechanism confirmed.

Nothing here gates T1 — the T1 chain-side gate is the emission boundary (#299/#303). **These
verdicts close M10's last owed item.**
