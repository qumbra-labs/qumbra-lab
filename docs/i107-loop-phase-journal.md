# The `LOOP` journal — reading a degraded main-loop period off one host

[中文](i107-loop-phase-journal-zh.md) · issue [#107](https://github.com/qumbra-labs/qumbra-lab/issues/107) S1 · T1 Gate A / A3

`sample_interval` is 30 s and the `TELEMETRY` emit is a check at the **bottom** of the main loop, so 30 s is a floor on the gap between two telemetry lines and never a cadence: the line appears the next time the loop gets there. `t0-wan-1` reached that floor constantly (median 30.01 s over 3,708 samples). Every image since has never come in below **131 s across 53 samples on four hosts**.

Three hypotheses were argued about that number from the outside — #87's three per-iteration calls, synchronous mining, injected latency — and two were refuted by measurement, because the only instrument anyone had was *the gap itself*, which says the loop was slow and nothing about which part of it was.

This document is how to read the instrument that replaces the argument.

## The two lines

Both go to stdout beside `TELEMETRY` and `ROUND` (the #87 rule: the container log is what is archived and cited, and unlike a scrape target it needs no inbound rule to reach). Both declare `unit=ms` and carry the same field tail, so one `awk` reads either.

### `LOOP kind=slow` — one iteration exceeded the threshold

Emitted **on the spot**, as the iteration ends, carrying that iteration's whole breakdown. Silent on a healthy node. Capped at 20 per telemetry window; the suppressed count is carried on the window line.

```
LOOP kind=slow unit=ms ms=131195.0 phase=pump.dispatch phase_ms=131170.0 frames=6 \
  pump=131174.0 journal=1.0 mine=0.0 boundary=0.0 metrics=0.0 discovery=0.0 submit=0.0 \
  telemetry=0.0 sample=0.0 maintain=20.0 snapshot=0.0 hook=0.0 sleep=0.0 \
  dials=0.0 poll=2.0 ratelimit=0.0 decode=0.0 dispatch=131170.0 sync=0.0 send*=131165.0
```

**`phase=` is the answer this issue has been missing.** It names the dominant phase, and when that phase is the pump it descends into the pump's own split — `pump.dispatch`, not `pump`.

### `LOOP kind=window` — one aggregate per `TELEMETRY` line

Emitted on the telemetry cadence, **always**, beside the sample it explains. This is the load-bearing half for #107: the degraded population was *steadily* slow (min 131 s, median 158–185 s — there is no quiet baseline in it to spike away from), and a threshold-only instrument would have been silent through all 53 samples.

```
LOOP kind=window unit=ms win=30012.0 iters=1482 busy=2210.0 acct=30000.0 unacct=12.0 \
  maxiter=181.0 maxphase=pump.poll maxphase_ms=178.0 frames=812 slow=0 slowsup=0 <same field tail>
```

## Field reference

| field | meaning |
|---|---|
| `ms` / `busy` | work in this iteration / this window. **Excludes the idle back-off.** |
| `win` | measured wall time of the window |
| `acct` | the same window as the sum of its iterations, back-off included |
| `unacct` | `win − acct` — the instrument's blind spot. **See below; this field is a diagnostic, not a rounding note.** |
| `iters` | loop iterations in the window (a quiescent loop turns ~50×/s) |
| `maxiter` / `maxphase` | the worst single iteration and what dominated it |
| `slow` / `slowsup` | slow lines emitted / suppressed by the cap |
| `frames` | frames the pump handled, throttled ones included |

**Run-loop phases**, in the order the loop runs them: `pump` `journal` `mine` `boundary` `metrics` `discovery` `submit` `telemetry` `sample` `maintain` `snapshot` `hook`, then `sleep` (the 20 ms idle back-off, which is *not* work).

**Pump sub-phases**, inside `pump`: `dials` `poll` `ratelimit` `decode` `dispatch` `sync`.

`send*` is an **overlay, not a phase**: time inside `Transport::send`, already counted inside `dispatch` and `sync`. Never add it into a total. It is separated because `TcpTransport::send` holds the `writers` mutex across the write and waits up to `SEND_WRITE_TIMEOUT_MS` (100 ms) for the kernel — one slow peer serialising every other send is the last unmeasured blocking call on the pump path, and this is what tells "the loop was in dispatch" apart from "the loop was in a socket".

## Reading one degraded sample

```sh
# the worst iterations, newest first
grep 'LOOP kind=slow' node.log | sort -t= -k4 -rn | head

# what every window blamed, ranked
grep -o 'maxphase=[a-z.]*' node.log | sort | uniq -c | sort -rn

# the loop period beside its own explanation
grep -E 'TELEMETRY|LOOP kind=window' node.log | tail -20
```

| what `phase=` says | what it means | what it does to the record |
|---|---|---|
| `pump.dispatch` with `send*` ≈ the same number | a socket write blocked the loop | the #289 write timeout is being hit repeatedly; multiplicity, not one call |
| `pump.dispatch` with `send*` ≈ 0 | consensus ingest/validation is the cost | new — no hypothesis in this issue predicted it |
| `pump.ratelimit` | #91's per-frame charge | **confirms the July ranking**, which was never measured |
| `pump.poll` | the inbox mutex | the transport lock-contention hypothesis, confirmed |
| `pump.dials` | applying connector completions | #132 did not finish the job |
| `mine` | synchronous RandomX | refutes the July measurement that ruled mining out — say so loudly |
| `maintain` | the dial pass | #83's ladder, not the pump |
| `snapshot` | the #359 fsync | a cadence cost nobody has priced |
| `hook` | the co-resident faucet's STARK | expected on a faucet host only |

## `unacct` — the blind spot, and why it is a field

Three things live between the phases:

1. the loop condition and the clock reads — nanoseconds;
2. the `println!` of the `LOOP` lines themselves (a phase cannot time its own report);
3. **anything that blocks stdout.**

The third is the one to watch. `println!` takes the stdout lock and writes to a pipe; under `docker logs` or a rate-limiting journald a full pipe blocks the **consensus loop** for as long as the reader takes. Nothing in this issue's history has measured that, and a large `unacct` with small phases is exactly what it would look like. **A window with `unacct` in the tens of seconds is a finding, not noise** — and it would mean the loop period is being set by the log consumer.

## Rolling it to one host

The change is additive journal only:

- **no consensus contact** — `finality.rs`, `recovery.rs`, `committee.rs` untouched;
- **no wire delta** — no `RPC_VERSION` bump, no `MsgType`, no payload change, no `TELEMETRY` field;
- **no config key and no new thread** — the threshold is a compile-time constant with a programmatic setter for tests;
- **no decision reads any of it** — the timings are observation, the same rule `RateStats` and `UnknownStats` follow.

**Volume, at the fleet's shape**: the window line is 1 per `TELEMETRY`, so ~2,880/day/host. Slow lines are silent on a healthy node except for mining, which is bounded by `mine_interval` (~1,150/day) — and on a degraded node they are capped at 20 per 30 s window, i.e. ≤57,600/day in the worst case, with the excess counted rather than printed. A node cannot be made to flood by a peer.

**Cost**: 13 clock reads per iteration plus 3 per frame, tens of nanoseconds each (a vDSO read, no syscall) — measured by `ticktime::tests::instrumentation_costs_tens_of_nanoseconds_per_frame`, which fails if a clock read ever costs a microsecond.

## What this does not answer

It does not say **why** a phase is slow, only which one is. It cannot see time spent inside the kernel on another thread (the reader and connector threads), and it cannot attribute a `poll` cost between "the inbox was big" and "the mutex was held" — for that, `frames` beside `poll` is the discriminator, not `poll` alone.

And it has never run on a WAN host. Every number in this document's examples is either from the issue's own archive or from a targeted test on a laptop.
