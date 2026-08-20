# Store-open fixtures — real production datadirs from the T2 launch

Two stores captured on 2026-08-20, the day T2 launched. Both are **real production
datadirs from real nodes on the live chain**, not synthesised. They exist so the
store-open regression is a CI gate rather than a manual experiment someone has to
remember to re-run.

| fixture | what it is |
|---|---|
| `t2-faucet-panic-0932Z/` | 🔴 **A store the product wrote and then could not reopen.** svc1's faucet node, healthy and serving at tip 248, was recreated by an ordinary `docker compose up -d --force-recreate`. It panicked on open, eleven times in a row. |
| `t2-cbnode-healthy-0919Z/` | The control: svc0's cbnode, same host family, same chain, running normally at tip 233. Opens clean. |
| `t2-guimine-panic-1357Z/` | 🔴 **The same panic from a different kind of node.** An hour-old store created by a user's own `qumbra-node mine` — the desktop wallet's child process — which panicked on the ordinary restart a person causes by quitting and reopening the app. Tip 467, `snapshot.bin` present. |

## The failure the panic fixture reproduces

```
thread 'main' panicked at crates/qlab-node/src/store.rs:446:18:
a retained ancestor path re-inserts in ascending order: UnknownParent
```

Two measurements from the incident that any hypothesis has to satisfy:

* **11 milliseconds** from `opening the node…` to the panic — far too fast to have
  replayed the chain's 250 blocks, consistent with dying inside `rewind_to` on an
  in-memory path rather than during a log walk.
* **Total silence.** The complete log of eleven attempts contains exactly five distinct
  line shapes and no diagnostic of any kind — no `RECOVERY`, no snapshot rejection, no
  `applied_height`, nothing.

That silence is a **contract violation**, not merely an unhelpful message. `persist.rs`
states: *"A snapshot that fails to decode is rejected with its reason
([`SnapshotLoadReject`], lab #408) and the caller falls back to a full, always-correct
genesis replay — reported, not silent."* Here it neither reported nor fell through.

## Provenance, and what was removed

Captured by T-ops during the launch. The panic store was copied **before** the recovery
that followed, so it is the store that actually failed, not a reconstruction.

🔴 **`peers.dat` was deliberately removed from both.** It holds fleet IP addresses and is
not needed to reproduce a store-open failure. Everything remaining is public chain data:
`blocks.log` is the append-only log of accepted blocks and finalizations, `snapshot.bin`
is derived state (commitment leaves, nullifier set, chain pointers, finalized roots), and
`names.bin`/`punishments.dat` are chain-derived sidecars. **No key material is present**
— the faucet's secrets live in `faucet.seed` and `faucet-tickets.secret` outside the data
directory, verified in `qumbra-faucet/src/main.rs` before these were committed.

## One caveat on the pair

The two are **not** a controlled A/B. They come from different nodes (faucet vs cbnode)
and different moments, and the panic store's recreate also delivered new config
(`discovery_addr`, `template_serving`) while cbnode's earlier panic on 2026-08-20 14:31
had no config change at all. The defect plainly exists without a config change, but these
two events are not byte-identical in their trigger — a fix validated against only one of
them is validated against half the evidence.

## Why the third fixture is not redundant

The first two came from **long-lived fleet service nodes** on hosts we operate, so their
shared provenance was a live confound: a reader could reasonably ask whether the defect
belonged to fleet write patterns, uptime, or service-node workloads. This one was created
about an hour before it died, by `qumbra-node mine` on an operator's laptop, mining to a
wallet's own payout key — the path a stranger following the public guide takes. It carries
**32 rewinds, the first at height 37**, which also says rewinds are ordinary rather than
rare, so any running node accumulates them.

It was captured the way the other two were: copied out of the wallet's node directory
**before** anything could overwrite it, and a copy of that copy reproduces the panic on
demand under the pre-fix binary while `claude/i-store-replay-panic` opens it clean
(`RECOVERY restored snapshot at height 467, replayed 0 records, resumed at tip 467`).

`peers.dat` dropped, per the rule above. There is no key material in a datadir: the payout
identity is an `rkm`, a public payee key, and it lives in `node.toml`, which is not part of
the capture.
