# M11 faucet — run notes, measurements, and findings

*EN (authoritative on technical detail) · 中文: [`m11-faucet-run-zh.md`](m11-faucet-run-zh.md)*

Issue [#100](https://github.com/lai3d/qumbra-lab/issues/100). Crate `qlab-faucet` (the lab's 15th).

---

## 1. The headline: constraint two in the task-book was wrong, and the coordinator has ratified the correction

The task-book stated *"throughput is determined by proof speed, not block capacity"*. It is not. Count the faucet's **notes**, not its transactions.

In an *n*×*n* bucket the faucet spends *n* of its own notes and creates *n* outputs, of which *g* leave for recipients and *n − g* return as change:

```
Δ(faucet note count) = −n + (n − g) = −g
```

**Every grant costs exactly one note, in every bucket size.** Three consequences:

1. **No transaction can increase the count.** A self-transaction is 2-in/2-out, i.e. Δ0. So "pre-cut the treasury into many small exact denominations" is not a strategy that exists here — 1→N splitting needs more outputs than inputs, which a fixed equal arity forbids. A **recut** can freely reassign note *values* (sum-preserving); it can never change their *count*.
2. **Bigger buckets amortise proofs, not grants.** An 8×8 could serve 7 recipients on one proof (Δ = −7 for 7 grants, still −1 each). The frozen §5 fee table prices 4×4 and 8×8; only 2×2 has an AIR, so today the amortisation is unavailable — but even with it the note budget does not move.
3. The only inflow is **one coinbase note per block the faucet wins**.

So the sustainable grant rate **is** the note inflow:

| target | notes/min needed | notes/min supplied at 75 s blocks | prover duty cycle @ 2.28 s |
|---|---|---|---|
| 1 grant/min | 1.0 | 0.8 (winning **every** block) | 3.8 % |
| 10 grants/min | 10.0 | 0.8 | 38 % |

The prover could sustain **26.3 grants/min** (60 / 2.28). Note inflow supplies **0.8/min**. **Proof speed is 33× away from being the binding constraint.** Even 1 grant/min is 1.25× over what winning every block supplies, so any rate above ~0.8/min runs off a pre-funded note buffer and drains it.

Coordinator ruling on this issue, 2026-07-29: the premise correction is **accepted**, decision 2 as posed ("pre-cut vs cut-on-demand") was **the wrong question**, and the note-count model is what to build and argue.

## 2. The four decisions, as taken

### 2.1 Anti-abuse: operator-issued single-use tickets are the load-bearing control

Issue #32 made diversified addresses genuinely unlinkable (`rkm = H(nk ‖ D_R ‖ d)`), so one person can mint unlimited mutually-unlinkable addresses and nothing on-chain can join them. The control must therefore be off-chain, and must not smuggle an on-chain identity in.

The decisive fact is that **the threat model is queue occupancy, not depletion.** Service capacity is ~0.8 grants/min, so an attacker does not need to drain the faucet — only to hold that 0.8/min. Attacker cost, not mechanism names:

| control | cost to occupy ~0.8 grants/min indefinitely |
|---|---|
| IP keyed on the exact address | **≈ 0** against IPv6 — one /64 is 2⁶⁴ keys |
| IP keyed on a /24 | ~100 distinct /24s; a rented /16 contains **256** of them, i.e. 256× the budget |
| IP keyed on the /16 | 1× per rented /16, but every honest user behind that /16 is collateral |
| client PoW puzzle | linear in the attacker's cores. To make occupancy cost one core continuously the puzzle must cost ≈75 core-seconds — a whole block interval of honest waiting — and 100 cores still buys 100× |
| operator-issued single-use ticket | the operator's signature. **Not rentable**, because the scarce resource is not a resource |

**Built:** tickets are the control; subnet and global token buckets are an explicitly labelled *anti-accident* pre-filter that stops retry loops and wedged clients and is documented as stopping nothing that is trying. Ticket MAC is a **Keccak prefix-MAC** (`Keccak256(DS ‖ secret ‖ id)[..16]`) — sound over a sponge, unlike the same construction over SHA-2 — reusing `qlab_note::hash::keccak256`. Never on-chain.

**Check order is a security property**, and both directions matter:

- Ticket validity is checked **first**, so a ticketless flood cannot burn the service budget. Test-locked: 10,000 ticketless requests leave the global bucket untouched (`a_ticketless_flood_cannot_burn_the_global_budget`).
- The ticket is burned **last**, after every other check passes, so an honest user who trips a throttle does not lose it (`a_throttle_does_not_consume_the_ticket`).

**Tickets are a toggle** (`TicketPolicy::Required | Disabled`) because "how public is public" was Larry's open call. The coordinator has since ruled tickets on from day one, with the grounds: *an open faucet that is always empty is less open than a working restricted one.* `TicketPolicy::Disabled`'s doc comment states the honest consequence of flipping it rather than leaving it to be discovered.

The **global** bucket refill is **derived, not guessed**: one token per `POW_TARGET_BLOCK_TIME_SECS`, because the sustainable rate *is* one grant per block. Test-locked (`the_global_budget_is_the_block_interval`).

### 2.2 Denomination: no pre-cutting, because pre-cutting is unrepresentable

Position: there is no denomination strategy to choose (§1). What is left is which pair to spend, and that cannot affect the budget at all — Δ is −1 either way. `Inventory::select_pair` therefore optimises the only free variable: the **smallest-sum anchored pair that covers `grant + fee`**. It minimises value moved through a proof, retires the two smallest notes so value does not fragment into a growing tail, and leaves the largest note intact as the reserve that keeps a feasible pair available for as long as *any* single note covers `grant + fee`.

**Provisioning cost at the two rates the task-book asked for**, in notes rather than value, because value is not the constraint (one 50 QMB coinbase note funds five 10 QMB grants of *value* but only **one** grant of *note count*):

| rate | net note drain per block | a 1,000-note buffer lasts |
|---|---|---|
| 1 grant/min (1.25/block) | −0.25 | 4,000 blocks ≈ **3.5 days** |
| 10 grants/min (12.5/block) | −11.5 | 87 blocks ≈ **1.8 hours** |

And a 1,000-note buffer can only be built by **mining 1,000 blocks and not spending** ≈ 20.8 h of wall time at 75 s. That is the provisioning plan: a faucet's buffer is measured in blocks won.

There is one real optimisation the shape permits and this crate does **not** manufacture: if a pair happens to sum to exactly `2·grant + fee`, one transaction can serve two requests with no change output — 2 grants per proof at the same −1 note each. Creating such a pair deliberately costs a recut (1 proof) to save half a proof, so it is a net loss; the code takes it only if the inventory offers it for free.

### 2.3 Proofs: on-demand, because a grant proof cannot exist before its request

This is more fundamental than the window. A grant's statement binds the recipient's `rkm` through `cm_out`, so **there is no grant proof to pre-generate**. The only pre-computable proofs are self-transactions, which are Δ0 and buy nothing. Decision 3's first half dissolves.

The 24 h window (`MAX_ANCHOR_AGE_BLOCKS` = 1,152 = 24×3600/75, `params_devnet.rs:151`) therefore is not a shelf life for a queue that does not exist. It is a **submission deadline** on a proof already built. Handled as:

- bind the **newest** valid anchor (`AnchorLease::acquire`);
- a short **self-imposed lease** of `CHECKPOINT_CADENCE_BLOCKS` = 8 blocks = 10 min, which is 1/144 of the protocol window;
- a **live re-check** immediately before submission (`GrantPlan::is_submittable`) — the load-bearing half;
- on refusal, restore the inputs and give the requester another attempt without costing them their ticket.

Why conservative rather than exact: `/v1/anchors` publishes `roots`, `tip_height`, `finalized_height` and `max_age_blocks` but **no per-root height** (`qlab-node/src/rpc.rs:330`), so a wallet holding a root can establish only "valid right now" and cannot compute its expiry. Adding `(height, root)` pairs is a payload change — a **stop point** — so it is reported (§3, finding 3), not built. `AnchorLease::window_bound_blocks` states the upper bound the wire *does* support, so an operator can see the lease sits inside it rather than trust that it does.

**Rejected alternative, recorded because it is the one pre-generation design that works:** pre-mint notes to faucet-derived addresses and hand out their note secrets as bearer claims. Grants then cost no proof at request time and the anchor window never applies. Rejected because the faucet retains spend authority over every unclaimed note (it can spend one out from under its claimant), the first hop is not private from the faucet, and issuance stops being atomic. It is a custodial voucher scheme wearing a faucet's clothes — and it is how one would reach 10 grants/min if that ever became a requirement.

### 2.4 Key custody, and the loss bound

Spend authorisation on this chain is **inside the proof** — there are no per-spend signatures — so knowledge of `sk` is sufficient to spend, and the loss upper bound on compromise is *every note that key owns, plus every grant until the key is rotated*.

**The honest negative result, because it changes the recommendation: a small hot balance is not achievable here.** Topping a hot key up from a cold one is itself a 2×2 transaction, and by the conservation law each such transaction moves exactly **one** note across (2 cold in → 1 to hot + 1 cold change). Maintaining a hot inventory of *n* notes costs *n* proofs **from the cold key**, which must be online to make them — so "cold" is a fiction the arithmetic does not support.

So the defensible posture is the opposite one:

- **Scope the key.** `FaucetConfig::hd_account` defaults to **1**, not 0: a faucet sharing an HD account with the primary wallet turns a service compromise into a wallet compromise. Test-locked (`the_faucet_key_is_not_account_zero`).
- **Never render it.** `Faucet`'s `Debug` is hand-written and withholds the wallet; `TicketSecret`'s redacts (`the_secret_is_never_rendered`); `PendingRequest`'s truncates the requester's address, because a full address in a log rotation is a standing record of who asked for funds on a privacy chain.
- **Make rotation cheap** by funding from a mining payout address that can be repointed.
- **Stated as a bound:** loss ≤ (blocks mined since rotation) × `coinbase(h)` + accrued change. At a 1,152-block (24 h, one committee epoch) rotation cadence that is one day of emission and one day of service — on testnet, where the value is zero and the real loss is the *service* and a takeover of a public endpoint.

## 3. Findings

### Finding 1 — a coinbase note never enters the commitment tree, so nothing minted is spendable

`Node::apply_state` (`qlab-node/src/node.rs:340`) appends only `tx.commitments`; `Mempool::on_block_connected` records `coinbase_note_commitment(...)` into a *registry*. A mined coinbase note therefore has no leaf, no Merkle witness, and **cannot be spent by a real 2×2 proof today**. The `[devnet-placeholder]` shape is documented in `mempool.rs`'s own module docs, so the boundary is known — but it means the faucet's real funding path (mine → mature → spend) is unimplemented, and constraint four's cold start is currently not "3 hours", it is "never".

**Coordinator escalation (2026-07-29):** because the faucet is consequently the only funding path, and `testnet-plan.md` §3 defines T1 as *"anyone can join, mine, transact"*, `faucet gate + unspendable mined coins = T1 is invitation-only for transacting`. That is a statement about what T1 *is*, and it would have happened as a side effect had nobody said it. This finding is now a **T1 precondition**, not a footnote; the coordinator owns the `testnet-plan` §3 / join-doc labelling and will open the issue.

Not fixed here: a consensus-state change is a stop point.

### Finding 2 — the frozen §2 maturity gate is unreachable from the wallet-facing path

`NodeRpc::submit_tx` calls `self.mempool.admit(tx, vec![], …)` (`qlab-node/src/rpc.rs:287`) — `spends_coinbase` is hard-coded empty, so the 144-block gate can only be reached by a direct `Mempool::admit` caller. It is test-locked (`rejects_immature_coinbase_spend_then_admits_after_maturity`) at a seam nothing in production reaches.

Bound at the seam that *does* exist: `OwnedNote::coinbase_note` carries the origin, and `GrantPlan::spends_coinbase()` computes the declaration a direct mempool caller must pass through (`a_coinbase_funded_grant_declares_its_maturity_obligation`). Not fixed here: a wallet-facing plumbing/payload change is a stop point.

### Finding 3 — `/v1/anchors` cannot express an anchor's deadline

See §2.3. `AnchorSet` carries no per-root height, so the consumer the design says needs it — a wallet planning a multi-second proof — cannot compute when its anchor expires. One field would fix it; that field is a payload change. Reported, not built.

### Finding 4 — a faucet cannot run on a T0-class host

One 2×2 proof peaks at **11.78 GB**. The Phase B-WAN hosts are AWS `t4g.small` = **2 GiB**. A faucet therefore cannot share a host class with the T0 nodes, and cannot prove two grants concurrently below ~24 GB. This is a deployment constraint that follows from the prover, not from this crate, and it belongs in whatever sizes the T1 hosts.

### Finding 5 — the operational one: four concurrent proving tests OOM the rig

Observed as SIGKILL on first run. Mitigated inside this crate with a process-wide prover mutex (see §4), so the workspace suite's memory envelope is unchanged. Recorded because the next crate that proves in more than one test will meet it too.

## 4. Measurements — every number with its caliper

**Rig:** Mac17,6 (Apple silicon, 18 cores), 36 GB RAM, macOS 26.5.2 (build 25F84), AC power. **Build:** `cargo test --release`, rustc 1.95.0, Plonky3 pinned `=0.6.1` per `Cargo.lock` (unchanged by this branch). **Repo rev:** branch `claude/m11-faucet` off `main` at `077b3ff`. **Caveat that applies to every timing below: this machine is shared** with a live network sampler and other agents, so timings are upper-ish bounds, not a quiet-machine benchmark.

| quantity | value | basis |
|---|---|---|
| grant proof, mean | **2.28 s** | n = 4 grants in one process (`consecutive_grants_…`), `--test-threads=1`; min 2.04 s, max 2.54 s |
| …reproduced | **2.27 s** | second run, same rig/rev, n = 4 (min 2.16, max 2.35) |
| the same AIR via `qlab-demo` | 2.00 s, 2.11 s | `./target/release/qlab-demo`, n = 2, same rig/rev — so a grant costs the same as any other 2×2 spend, and this crate adds no proving cost |
| M3's recorded figure | 1.6 s | **a different rig; NOT reproduced here.** Do not difference it against the numbers above |
| grant proof wire | **145,609 B** | asserted in `end_to_end_…`; equals `qlab-consensus`'s `consensus_wire_is_145609_bytes` pin |
| proof peak memory | **11.78 GB** | `peak memory footprint`, `/usr/bin/time -l` on the test binary, `--test-threads=1`, 1 sample. Max RSS 11.90 GB |
| …at default parallelism | **11.78 GB** | identical, because the prover gate serialises. 1 sample |
| `qlab-demo` e2e peak, for comparison | 11.89 GB max RSS | same rig/rev, 1 sample |
| prover ceiling | **26.3 grants/min** | 60 / 2.28 s |
| note inflow ceiling | **0.8 notes/min** | 60 / 75 s, one coinbase note per won block |
| headroom ratio | **33×** | 26.3 / 0.8 |
| acceptance suite wall time | 20.6–23.9 s | `cargo test --release -p qlab-faucet --test acceptance`, 7 tests, 8 real proofs total |

Derived constants that carry their arithmetic in the source: `MAX_QUEUE_DEPTH` = 32 (75 s ÷ 2.28 s = 32.9, floored — one block interval of proof-bound backlog); `FaucetLimits::global_refill_window_ms` = 75,000 (the block interval, i.e. the note-inflow ceiling as a rate); `PROOF_LEASE_BLOCKS` = 8 (`CHECKPOINT_CADENCE_BLOCKS`, 1/144 of the anchor window); `DEFAULT_GRANT_BESSEL` = 10⁹ = 10 QMB `[devnet-placeholder]` (1,000× the 2×2 posted fee, i.e. 1,000 transactions of runway).

## 5. Acceptance items → test names

| item | test |
|---|---|
| e2e: request → tx → node accepts → requester scans it, real proof | `end_to_end_grant_is_scanned_by_the_requester` |
| the control blocks what it claims | `the_abuse_control_blocks_what_it_claims` (+ `policy::tests::the_gate_blocks_what_it_claims_to_block`) |
| …and does not block normal requests | `the_abuse_control_admits_ordinary_requests` (+ `policy::tests::the_gate_admits_ordinary_traffic`) |
| N consecutive grants do not wedge on "no spendable note" | `consecutive_grants_do_not_wedge_and_the_wedge_is_named` |
| an out-of-window proof is rejected, not silently accepted | `an_aged_out_anchor_is_rejected_by_both_the_faucet_and_the_node` |
| the cold start is named, not a mystery stall | `a_faucet_on_an_unfinalized_chain_reports_the_cold_start` |
| the maturity declaration is computed | `a_coinbase_funded_grant_declares_its_maturity_obligation` |

Totals: **36 unit + 7 integration = 43 tests, 0 failed** (`cargo test --release -p qlab-faucet`). `cargo clippy -p qlab-faucet --all-targets` is silent.

Two properties worth naming because the tests are built around them:

- The **positive control** in the anchor-expiry test. Two plans bind the same anchor; the first is submitted and accepted while the anchor is fresh, then the second is aged out and rejected. Without the control, the rejection would not distinguish "the anchor aged out" from "the faucet builds bad transactions".
- The **lease is stricter than the protocol, demonstrated**. Nine blocks after planning, the faucet declines to submit while `is_valid_anchor` is still true — the conservatism from finding 3, exercised rather than asserted.

## 6. What was NOT verified — specifically

**The thing most likely to break, named:** `ChainView::anchor_leaf_count` recovers the anchor's tree prefix by scanning prefix roots newest-first. That is O(leaves) depth-32 folds **per plan**, on a tree that grows forever. At the tested scale (≤ 8 leaves) it is free; at a year of mainnet it is not, and I have not measured where it stops being acceptable or what a real wallet should do instead. **I have not seen this pass at any scale above single digits of leaves.** It exists only because finding 3 removed the cheap route; if the wire ever carries `(height, root)`, this function should be deleted rather than optimised.

Also not verified:

- **The full unfiltered workspace suite.** Not run — the coordinator explicitly took it in an independent review worktree (this issue, 2026-07-29). I ran only `-p qlab-faucet`, plus `cargo check --workspace --all-targets` (clean; the pre-existing `qlab-bench` unused-import warnings are untouched). **A workspace count from me does not exist and should not be inferred.**
- **The 4×4 / 8×8 amortisation claim.** The Δ = −*g* algebra is general, but only 2×2 has an AIR, so "an 8×8 could serve 7 recipients on one proof" is an argument from the arity, not something exercised.
- **Concurrency.** `Faucet` is single-threaded by construction and never proves on more than one request at a time. A deployment that wants a prover thread pool has not been designed, and finding 4 says it needs ~12 GB per slot.
- **Persistence.** The inventory, the spent-ticket set and the queue are all in-memory. A faucet restart loses its note bookkeeping and re-admits every previously-spent ticket. Recovering the inventory from the chain is possible (the change note is encrypted to the faucet's own address, and `end_to_end_…` proves the faucet can scan it back) but **no restore path is implemented or tested**.
- **Any listener.** There is deliberately no socket (crate docs): `testnet-plan.md` §6 keeps public-facing ops hardening as its own row, and binding a hot spending key to a public socket before that row's decisions exist would ship the exposure that row exists to prevent. So nothing here has been exercised against a real HTTP client, malformed requests, slowloris, or TLS termination.
- **The ticket-issuing CLI.** `AbuseGate::issue` is the operator entry point; there is no command, no secret-provisioning procedure, and no rotation procedure. `TicketSecret` is adopted from bytes and this crate never generates, stores, or prints one.
- **Timing side channels on ticket verification.** The tag comparison folds every byte before branching, but `Ticket::issue` runs a Keccak per verification and I have not measured whether the whole path is constant-time. It is behind a rate limiter, which is mitigation, not proof.
- **The prove-time figures on a quiet machine.** The rig is shared; n = 4 per run and reproduced once. Treat 2.28 s as "this rig, this build, under ordinary shared load".
