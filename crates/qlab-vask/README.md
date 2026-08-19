# The Qumbra exchange/VASP kit

> [中文版](README-zh.md)

Everything an exchange needs to list QMB with a privacy-respecting deposit
flow: **verify a depositor's disclosure, credit only what verifies, and refuse
the rest by name.** Qumbra is a single uniform shielded pool — there is no
transparent address type to force deposits onto — so the enforcement point
moves to crediting time: the depositor proves *"this deposit of value v went
to your address"* with a STARK, and the exchange credits only deposits that
arrive with a verifying proof. Same business outcome as Zcash's ZIP 320 TEX
addresses (the ability to refuse anonymous deposits, which is what survived
the 2023 Binance ultimatum), with zero consensus surface
(`qumbra-design/ecosystem-and-adoption.md` §4, `auditable-privacy.md` §4).

Status: private lab reference (tracker: lab #483). Publication of any kit
piece is a separate act (#203 tracker); nothing here is a published API yet.

## What is in the kit

| Piece | Where | What it is |
|---|---|---|
| verifier library | this crate (`qlab-vask`) | envelope parse + STARK verify, no I/O, pinned config |
| C ABI | `include/qvask.h` + `src/lib.rs` | 4 functions, 7 stable result codes, header pinned to source by tests in both directions |
| reference binding | `bindings/python/` | ctypes mirror of the header + fixture smoke test |
| golden fixtures | `fixtures/` | committed parse-refusal vectors + a real CI-minted envelope (`golden-envelope-v1.bin`) |
| crediting reference | `../qumbra-credit-ref` | runnable HTTP service: the whole deposit→verify→credit decision path |
| confirmation policy | `../../docs/kit-confirmation-policy.md` | when a deposit is safe to credit: **finalized = creditable** |
| custody-audit doc | `../../docs/kit-custody-audit.md` | standing-fvk audit arrangements over the exchange's own wallets |

Specs the kit implements: `qumbra-design/wallet-interop-spec.md` §3 (the
disclosure envelope + verification rules) with delivery **out of band** (the
#483 stage-0 ruling: a deposit disclosure is a bilateral depositor→exchange
object — wallet exports it as a file/QR/paste, the exchange's deposit UI
accepts it; nothing rides the chain).

## The flow

```
depositor wallet                   chain                    exchange
  1. send deposit ───────────────► mined … finalized
  2. build disclosure envelope
     (proves: cm at that deposit
      opens to value v, addressed
      to YOUR address)
  3. hand envelope to exchange ─────────────────────────► 4. peek: claim fields
     (upload/QR/paste — out of band)                      5. our address? value?
                                                          6. deposit finalized?
                                                          7. STARK verify vs the
                                                             committed cm
                                                          8. credit once, by cm
                                                             — or refuse by name
```

Steps 4–8 are `qumbra-credit-ref` verbatim; step 7 alone is this library.

## Three ways in, smallest first

**1. Link the C ABI** (`include/qvask.h`) — you keep your own chain access and
deposit records; the library only answers "does this envelope verify against
this committed commitment":

```c
qvask_claim_t claim;             /* tx_ref, value, addr_commitment, output_index */
char *reason = NULL;
int32_t rc = qvask_envelope_peek(env, env_len, &claim);      /* no STARK yet   */
/* ... match claim against your deposit record, read cm on your finalized view */
rc = qvask_verify(env, env_len, chain_cm, &claim, &reason);  /* ~26 ms         */
```

The FRI config is pinned **inside** the library (a caller cannot weaken the
verifier by parameter — a config change is a new `qvask_abi_version()`).
Verification is a pure function: no handles, no state, thread-safe by
statelessness; the only allocation crossing out is `reason`, freed by
`qvask_string_free`. Rule 1 of the spec (the deposit exists and is
**finalized**) deliberately stays on your side of the ABI.

**2. Copy the engine** — `qumbra-credit-ref/src/lib.rs`'s `try_credit` is the
full decision path (peek → our-address gate → finality read → light-client
scan → verify against each candidate's committed cm → once-only credit) over
a caller-supplied fetch, ~80 lines to read.

**3. Run the reference service**:

```sh
qumbra-credit-ref --listen 127.0.0.1:8484 \
                  --upstream http://<node>:<discovery-port> \
                  --keys ./exchange.keys
# POST /v1/credit   body = raw envelope → 200 credited | 4xx/503 named refusal
# GET  /v1/status   addr_commitment + credited count
```

Reference boundaries, stated: no TLS (put it behind your edge), no rate
limiter, one deposit address, in-memory once-only set — each named in the
crate docs with the production direction.

## Refusals are the API

Every non-credit answer is a stable named code, machine-matchable — the house
pattern across the lab. At the ABI:

| code | name | meaning |
|---|---|---|
| 0 | `QVASK_OK` | claim proven against your chain cm |
| -1 | `QVASK_INVALID_CALL` | NULL/contract violation — never a verdict on the envelope |
| -2 | `QVASK_MALFORMED` | framing: truncated, trailing bytes, varint |
| -3 | `QVASK_UNKNOWN_VERSION` | reject-unknown, never ignore (spec rule 3) |
| -4 | `QVASK_UNKNOWN_CLAIM_TYPE` | reject-unknown, never ignore |
| -5 | `QVASK_PROOF_DECODE` | proof bytes are not a proof structure |
| -6 | `QVASK_PROOF_INVALID` | the STARK refused; `reason` says why |

At the service, decisions are 4xx **never 5xx**, and exactly the two
cannot-answer cases are 503: `envelope-*` (the five above), `not-our-address`
422, `deposit-not-found` 404, `nothing-finalized`/`not-finalized`/
`already-credited` 409 (the first two are "retry after finality", the third
is the once-only rule keyed on the committed cm), `proof-refused` 422,
`scan-incomplete`/`upstream-unavailable` 503. Token and status tables are
test-locked (`qumbra-credit-ref/src/lib.rs`).

## The numbers, with their basis

| Figure | Value | Basis |
|---|---|---|
| envelope size | **150,695 B** (~147 KiB) | the committed V1 golden fixture: postcard-serialized proof at the pinned b16/q20/g22/a16 config (`fixtures/README.md` — note the stale "~122 KB" figure floating in older docs is the bincode proof size, wrong codec) |
| verify | **26.0 ms** | b16/q20/g22, Apple M5 Max, reproduced twice (`docs/disclosure-run1.md`/`-run2.md`) — ~40 verifies/s single-thread, far above any deposit rate |
| depositor's prove | 0.59–0.99 s | same rig and runs, 1 timing sample per run |
| deposit → creditable | ~2.5–11.5 min | arithmetic from devnet finality pins, not a measurement — `docs/kit-confirmation-policy.md` §4 |

An envelope is an upload-sized object, not a memo: the out-of-band flow above
is the design of record, not a workaround.

## Confirmation policy, in one line

**Credit when the deposit's height is ≤ the finalized head (`GET /v1/anchors`),
never by confirmation depth** — BFT finality is irreversible and minutes-class,
and the reference's `not-finalized` refusal implements the wait. Grounds,
mechanics, latency arithmetic and failure directions:
`docs/kit-confirmation-policy.md`.

## Custody, in one line

The crediting host needs only **incoming**-viewing key material (`Ivk`-class
or a single diversified `dk`), auditors get a per-account standing `Fvk`
(sees everything, moves nothing), and spend keys never touch an edge host —
the ladder, what each rung can and cannot see, and the rotation discipline:
`docs/kit-custody-audit.md`.

## Version discipline

- `qvask_abi_version()` = **1**; check it at startup against
  `QVASK_ABI_VERSION` in your header copy.
- Envelope format `ver 0x01`, claim type `0x01` (sent-payment). Unknown
  values refuse — an exchange must never guess about money.
- The verifier shares its whole proving stack (field, FRI, hash) with the
  chain's public consensus verifier (`qumbra-circuit`) — same lineage, smaller
  statement (stage-0 survey §1.4).
