# Exchange kit — confirmation policy: finalized = creditable (lab #483 stage 3)

> [中文版](kit-confirmation-policy-zh.md)

**Status: stage-3 deliverable of the exchange/VASP kit
([#483](https://github.com/qumbra-labs/qumbra-lab/issues/483); spec:
`qumbra-design/ecosystem-and-adoption.md` §4, `consensus-and-network.md` §4–§6).**
Audience: the exchange integration and risk teams deciding when a QMB deposit is
safe to credit. The companion pieces are the kit README
(`crates/qlab-vask/README.md`) and the custody-audit doc
(`docs/kit-custody-audit.md`). EN is authoritative; line numbers are against
lab `main` at `cf15b11`.

---

## 1. The rule

**Credit a deposit exactly when its block height is ≤ the chain's finalized
head. Nothing else — no confirmation counting, no depth heuristics, no
"probably deep enough".**

Qumbra is a hybrid chain: permissionless PoW produces blocks, and a BFT
finality committee checkpoints them (Crosslink-shape on Ebb-and-Flow;
`consensus-and-network.md` §4). A finalized block is irreversible — consensus
rejects any fork that would reorg past a finalized checkpoint, and the chain's
own transactions anchor only to finalized commitment roots
(`consensus-and-network.md` §6), so the protocol itself already refuses to
build value on unfinalized state. An exchange that credits at finality
inherits that guarantee; an exchange that counts confirmations is re-deriving
a weaker version of it by hand.

This is the design's answer to the depth-regime arms race elsewhere: after its
51 % attacks, ETC exchanges moved to >12,000 confirmations (~2 weeks)
(`ecosystem-and-adoption.md` §4's citation). A rented-hashrate double-spend
against Qumbra dies at the first finalized checkpoint behind the deposit —
griefing near the tip stays possible and profitless; reorging past finality is
not a cost question, it is refused by every honest node.

## 2. What "finalized" means here, mechanically

All committee machinery is lab-real and running on the internal T0 net; the
constants below are **devnet-pinned and testnet-tunable, NOT frozen** — each
carries its source so a change is visible, and none of them changes the rule
in §1, only its latency.

| Fact | Value today | Basis |
|---|---|---|
| Block production | PoW, 75 s target | decided (B2), `qumbra-design/consensus-parameters.md` §2 |
| Committee | 21 ML-DSA-65 keys (genesis-baked) | design N≈20–50, params §4; devnet genesis committee₀ |
| Quorum | ⌊2N/3⌋+1 → **15 of 21** | `qlab-devnet/src/committee.rs:85` |
| Checkpoint cadence | every **8 blocks** (~10 min at target) | `qlab-devnet/src/params_devnet.rs:94`, `[full-M8]`-flagged, not frozen |
| Sign hysteresis | slot signs only once tip ≥ slot+**2** | `params_devnet.rs:106` (issue #269) |
| Degraded-mode threshold | tip − finalized > 16 blocks | `params_devnet.rs:149` |

Checkpoints land on a cadence grid — genesis is waived as a bootstrap act,
then slots at heights 8, 16, 24, … A slot is signed only after the tip clears
the two-block hysteresis (a 2026-08-05 incident burned three consecutive slots
signing into the tip race; #269 is the fix), and finalizes when 15 of the 21
keys sign the same checkpoint variant. **No single node holds quorum** — the
finality an exchange reads is a distributed fact, demonstrated across a
three-continent WAN for 48 h with zero reversions
(`docs/m10-t03-phase-b-wan-run.md`).

## 3. How an integration reads it

The crediting reference (`qumbra-credit-ref`) implements the rule end to end;
an exchange writing its own flow needs exactly these reads:

- **`GET /v1/anchors`** on a node's discovery endpoint
  (`qumbra-node/src/discovery_server.rs:191`) decodes to `AnchorSet`
  (`qlab-node/src/rpc.rs:1113`): `tip_height`, and `finalized_height` as an
  **`Option`** — `None` means the chain has finalized nothing yet and nothing
  is creditable. The reference deliberately scans to *tip* while crediting
  only to *finalized*, so "your deposit is here but not finalized yet" and "no
  such deposit" stay distinguishable answers.
- **Credit iff `deposit_height ≤ finalized_height`**, once per deposit,
  keyed on the deposit's committed commitment `cm`
  (`qumbra-credit-ref/src/lib.rs:247` `try_credit`; the once-only set and the
  two finality refusals are `lib.rs:116`'s `Refusal` variants).
- **The two waiting states are named 409s, not errors**: `nothing-finalized`
  and `not-finalized {deposit_height, finalized}` — a client retries after
  finality reaches the deposit; nothing about the deposit is being judged.
  Statuses are test-locked (`lib.rs:169` `http_status`).

The whole transition is demonstrated against the real finality machinery in
`qumbra-credit-ref/tests/credit_e2e.rs:175`
(`a_deposit_credits_once_after_finality_and_every_refusal_names_itself`,
section (f)): a deposit mined above the finalized head refuses
`not-finalized`, a checkpoint lands on the cadence grid, the same envelope
then credits — and only once.

Operators who monitor rather than integrate: `final=`/`fid` on `/v1/telemetry`
say how high **and what** was finalized (`qlab-node/src/telemetry.rs:26` —
two nodes can agree on height while disagreeing on identity, which is the one
failure worth alarming on), and `dfin` is the durable head that survives a
restart (`telemetry.rs:55`). `qumbra-opview` exists to compare these across
nodes.

## 4. Latency a deposit desk should expect

Arithmetic from the pinned constants, not a measurement: a deposit at height
`h` waits for the first cadence slot `S ≥ h` (0–7 blocks), plus the 2-block
hysteresis, plus vote aggregation. At the 75 s target that is **~2.5 to
~11.5 minutes** from mined to creditable; against the measured WAN block
pacing (mean 86 s over 1,707 intervals, ordinary PoW variance —
`docs/m10-t03-phase-b-wan-run.md`) the practical envelope is a few minutes
wider. Vote aggregation itself is seconds-class and is not the driver; the
cadence is. If a listing conversation needs a shorter number, the honest knob
is the cadence constant (testnet-tunable, §2), not a depth heuristic at the
exchange.

For withdrawal processing the same rule applies in reverse: treat an outbound
transaction as settled when its block is finalized, not when it is mined.

## 5. Failure modes, and which direction this policy fails

**Committee stall.** Ebb-and-Flow's deliberate degradation: if the committee
loses quorum, PoW keeps producing blocks but the finalized head freezes
(degraded mode past 16 blocks of lag, `params_devnet.rs:149`). Under this
policy deposits then **queue at `not-finalized` instead of crediting** — the
failure direction is delay, never a wrongly credited reorg-able deposit. Do
not fall back to depth counting during a stall: a stall is precisely when the
chain is back to probabilistic-only protection, i.e. when depth is worth the
least. The T0 net has paid real tuition here — a 51-minute finality outage on
2026-08-05 (`docs/incident-2026-08-05-finality-night.md`) and a halt-boundary
stall on 2026-08-12 — and in both cases block production continued, nothing
finalized reverted, and a finalized-only desk would have credited nothing
wrong, just later.

**Node divergence.** A single upstream node can be wrong about *what* is
final only if it diverges from the committee — the `fid`-identity check in §3
is the alarm for that; an exchange running two upstream nodes and refusing to
credit while their `fid`s disagree gets the cross-check for the price of one
extra node.

**What this policy does not cover**: the deposit's *contents* (that is the
disclosure envelope's job — kit README §"the flow"), and the exchange's own
custody of received funds (`docs/kit-custody-audit.md`).
