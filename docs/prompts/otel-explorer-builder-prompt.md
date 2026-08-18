# qumbra-explorer OTel adoption — the svc-lane three-piece kit (observability-plan §C.1)

🔶 **SEQUENCING GATE: do not start until explorer front-of-house stage 1 (lab #486) has
MERGED.** Both touch the request-dispatch seam in `crates/qumbra-explorer`; this baton
bases off the post-FoH-s1 main. If dispatched early by mistake: stop, say so on the issue.

Repo: `qumbra-lab`, branch `claude/otel-explorer`, **open a PR — NEVER merge**. Read
`CLAUDE.md` (CI-lane acceptance, `verify-graviton`; 🔴 never run full workspace suites
locally). Read `qumbra-deploy/docs/observability-plan.md` §C/§C.1 + the standards line.

## The work (leaf binary only — `crates/qumbra-explorer`; zero new deps in any qlab-* crate)

Same three-piece kit as the faucet baton (`docs/prompts/otel-faucet-builder-prompt.md` —
read it; do not diverge in shape without grounds):
1. Request span per HTTP request at the dispatch seam; child spans for real stages
   (page build, txlist walk — the R4 incremental-walk cost becomes visible).
   Resource `service.name="qumbra-explorer"`, `service.namespace="qumbra"`.
2. `trace_id=` in the request log line (`trace_id=<32-hex>`, Loki-regex-compatible).
3. Request-latency histogram with exemplars (`prometheus-client`), loopback-only bind.

## One ruled point specific to this binary

`main.rs` currently REFUSES `metrics_addr`/`telemetry_addr` by name (§6.2). **Coordinator
ruling for this baton: the refusal was against PUBLIC listeners; a loopback-only
`metrics_addr` is compatible with §6.2's intent (nothing public is exposed) and is now
ALLOWED — bind must be loopback, non-loopback stays refused by name, and the refusal
message/comment is updated to say exactly that.** Cite this ruling in the code comment
at the seam; the test asserts both halves (loopback accepted, non-loopback refused).

## Everything else

Env-gated export off by default (zero noise without the env — tested), pinned versions,
deps confined to the explorer crate, no wire/RPC/consensus contact, no live VPS-D wiring
(transport is T-ops'). Tests: span tree, trace_id log line, exemplar exposition,
disabled-default negative, the two-halves bind test. CI `verify-graviton`, arithmetic
reconciled vs the then-current main baseline. PR body: three-piece checklist + honest
remainder. Final Multica comment: PR URL + one paragraph.
