# qumbra-faucet OTel adoption — the svc-lane three-piece kit (observability-plan §C.1)

Repo: `qumbra-lab`, branch `claude/otel-faucet`, **open a PR — NEVER merge**. Read `CLAUDE.md`
(CI-lane acceptance, `verify-graviton`; 🔴 never run full workspace suites locally). Read
`qumbra-deploy/docs/observability-plan.md` §C/§C.1 + the standards line — they are the spec;
this baton implements, it does not re-litigate.

## The work (leaf binary only — `crates/qumbra-faucet`; zero new deps in any qlab-* crate)

1. **Request span** at the dispatch seam (`http.rs` — the tiny_http accept/match loop):
   one span per request (`GET /healthz` etc.), OTel SDK (`tracing` + `tracing-opentelemetry`
   + `opentelemetry-otlp`, http/protobuf), resource `service.name="qumbra-faucet"`,
   `service.namespace="qumbra"`. Child spans where the handler does real stages (grant
   path: gate → harvest → prove — spans make the 2 s prove visible as a span, which is
   the whole payoff for this binary).
2. **`trace_id=` in the request log line** — the existing request logging gains the field
   (exact token `trace_id=<32-hex>`, matching the Loki derived-field regex).
3. **Request-latency histogram with exemplars** via the official `prometheus-client`
   crate, served on a **loopback-only** `metrics_addr`-style config field (follow the
   node's config.rs pattern: OPTIONAL, off by default, refuse non-loopback by name —
   same posture the fleet uses). Existing counters (if any) stay as they are.
4. **Env-gated export, off by default**: no `OTEL_EXPORTER_OTLP_ENDPOINT` ⇒ no exporter
   constructed, zero overhead, ZERO error/warn spam (test this: run without the env,
   assert no otel noise in output). This is a hard requirement, not a nicety.
5. Version-pin the new crates; keep the dependency additions confined to
   `crates/qumbra-faucet/Cargo.toml`.

## Tests

- Span emission: an in-process OTLP-shaped or in-memory exporter asserts a request
  produces the span tree (request → grant stages) with the right resource attrs.
- Log line: request handling emits `trace_id=` matching `[0-9a-f]{32}`.
- Exemplar: the histogram's OpenMetrics exposition carries an exemplar with `trace_id`.
- Disabled-default: no env ⇒ no exporter, no log noise (the negative is the point).
- Loopback refusal: non-loopback metrics bind refused by name (mirror the node's test).

## Boundaries

- No wire/RPC/consensus contact; no changes outside `crates/qumbra-faucet` + `Cargo.lock`.
- Do NOT wire live delivery to VPS-D — transport (§A `/v1/traces` edge + §B alloy roll)
  is T-ops', later. This baton = instrumentation + tests, shippable dark.

## Acceptance

CI `verify-graviton`, arithmetic reconciled vs current main baseline (state it). PR body:
span-tree screenshot-or-test-output, the three-piece checklist, honest remainder.
Final Multica comment: PR URL + one paragraph.
