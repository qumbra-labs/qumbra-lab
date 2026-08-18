# Exchange/VASP kit — stage 0: survey, crate layout, ABI proposal (lab #483)

**Status: PROPOSAL — coordinator reviews at the stage boundary; nothing here is built beyond
two skeleton crates carrying this inventory's citation tests.** Task: [#483](https://github.com/qumbra-labs/qumbra-lab/issues/483)
stage 0 (Multica QUM-137). Spec: `qumbra-design/ecosystem-and-adoption.md` §4;
`wallet-interop-spec.md` §2–§4; `auditable-privacy.md` §4 (the "Edge" layer — crediting-time
enforcement: the exchange credits only deposits arriving with a verifiable disclosure).

Language pairing: EN-only on the "who acts on it" test — this is a per-baton proposal the
coordinator reads at a review boundary; #483 stage 3 owns the paired (EN+ZH) operator- and
exchange-facing docs.

Line numbers are against `main` at `31e0cbd`.

---

## 1. Inventory — what exists today

### 1.1 The disclosure STARK

- **Crate: `crates/qlab-disclosure`** (four modules — `packing`, `air`, `prove`, `envelope`;
  `src/lib.rs:21-24`). Landed PR #40 (2026-07-22, `docs/milestone-log.md:45`).
- **Statement** (claim 0x01, one on-chain output note; `src/packing.rs:5-21`):

  ```text
  public:  cm               the note commitment on-chain at (tx_ref, output_index)
           value            the disclosed amount
           addr_commitment  Keccak256(recipient's full 1,233-B raw address)
  witness: rkm, rho, rseed  the note opening
           version, d, ek   the recipient address fields
  prove:   cm              == H_commit(value ‖ rkm ‖ rho ‖ rseed)   [qlab-air packing]
       ∧   addr_commitment == Keccak256(version ‖ d ‖ rkm ‖ ek)     [qlab-wallet layout]
  ```

  The shared `rkm` binds "this payment (cm) went to THAT address"; both packings are
  regression-locked byte-for-byte against `qlab_air::narrow::build_bucket` and
  `qlab_wallet::address::Address::to_raw_bytes()` (`packing.rs:1-4`). Circuit: narrow-Keccak
  sponge, **594 cols × 2^16 rows, 12 permutations** (`src/air.rs:94`
  `DISCLOSURE_WIDTH`, `air.rs:1036` `PROGRAM_PERMS`), deg ≤ 3.
- **Envelope format** (wallet-interop §3, binary; `src/envelope.rs:6-11`):
  `ver (u8=0x01) ‖ claim_type (u8=0x01) ‖ tx_ref (32 B) ‖ value (u64 LE) ‖
  addr_commitment (32 B) ‖ output_index (u8) ‖ proof_len (LEB128) ‖ proof_bytes` —
  75 B of framing + the proof. Constants `ENVELOPE_VER` / `CLAIM_SENT_PAYMENT`
  (`envelope.rs:33,35`); parse rejects unknown ver/claim_type and trailing bytes
  (`envelope.rs:147-187`).
- **Verify entry point: `Envelope::verify(chain_cm, log_height, cfg)`**
  (`envelope.rs:193-210`): decodes `proof_bytes` (postcard), rebuilds the public-value vector
  via `pv_vec(cm, addr_commitment, value)` (`air.rs:127`, layout `air.rs:115-118` —
  36 u32 chunks), constructs the witness-free verifier AIR `DisclosureAir::verifier(log_height)`
  (`air.rs:245-251`), and runs `prove::verify` (`src/prove.rs:125-134`) =
  `p3_uni_stark::verify` over the crate's `Config`. Rule 1 (tx exists + finalized) is
  **explicitly the caller's chain lookup** — the crate does not model the chain
  (`envelope.rs:20-22`). The verifier needs three caller-supplied facts: the chain's `cm` at
  `(tx_ref, output_index)`, `log_height = 16`, and the prover's `FriCfg`.
- **Error taxonomy already typed**: `EnvelopeError::{Malformed, UnknownVersion,
  UnknownClaimType, ProofDecode, ProofInvalid}` (`envelope.rs:50-62`).
- **Cost, measured** (`docs/disclosure-run1.md` + `disclosure-run2.md` — Apple M5 Max 36 GiB,
  Plonky3 0.6.1 pinned, AC power, reproduced twice, byte-identical sizes; 1 timing sample per
  config per run):

  | config | proof (fixed) | prove | verify |
  |---|---|---|---|
  | b16/q20/g22 (reference) | **121.9 KB** | 0.59–0.99 s | **26.0 ms** |
  | b32/q18/g10 (smallest) | 114.6 KB | ~0.97 s | 26.8 ms |

  🔴 Two figure corrections for the kit's pitch (reported on #483, 2026-08-18):
  **verify is ~26 ms, not "sub-ms"** — the sub-ms figure in ecosystem §4 / #483 belongs to the
  *consensus* verifier's per-tx cost claim, not this statement — and the envelope is a
  **~122 KB object** (0.89× the 2×2 bucket, PR #40's honest finding: a small STARK still pays
  FRI's width-scaled per-query cost, and the 1,184-B ML-KEM ek is a 10-block sponge). Both
  matter to an exchange API contract; neither threatens a crediting flow (26 ms is nothing
  against a deposit's finality wait).
- **Config drift to resolve at stage 1**: `qlab_disclosure::prove::CONSENSUS_CFG` is
  **b16/q20/g22** (`prove.rs:78-84`) — deliberately left at q20 when the consensus lane moved
  to q21 at B″ (coordinator call recorded in `docs/milestone-log.md:46`: standalone statement,
  a bump would stale the measured 121.9 KB for no security gain; 102-bit conjectured stands).
  The kit V1 must pin **one** named config; proposal: adopt the q20 point as
  `DISCLOSURE_V1_CFG` and record it as the disclosure lane's own constant, decoupled from the
  consensus lane's numbering by design rather than by drift.

### 1.2 The deposit-disclosure memo convention — spec vs deployed wire

wallet-interop **§4** (the convention the kit implements): depositor places a §3 envelope in
the **encrypted memo** of the deposit tx; `memo_type (u8: 0x00 free-text, 0x01
disclosure-envelope) ‖ payload`; exchange decrypts, verifies, credits only on success.
wallet-interop **§2** (the serving wire the exchange's wallet scans): compact groups
`cm 32 ‖ amortized ML-KEM ct 1088 ‖ tag 8 ‖ clue 1`, golden-locked in `qlab-cbserver`
(PR #34; §2's own reference-implementation note).

**🔴 Finding (the stage-0 headline): §4 has no transport on the deployed wire.**

1. **No memo channel exists.** The per-output AEAD plaintext is the fixed 104-B note tuple
   `value ‖ rkm ‖ rho ‖ rseed` (`qlab-note/src/note.rs:16` `NOTE_PLAINTEXT_LEN`), served as
   fixed 120-B AEAD payloads (`qlab-note/src/compact.rs:347` `PAYLOAD_LEN = 120`;
   `qlab-cbserver/src/data.rs:366` `full_payloads`, `codec.rs:136` `encode_full_response`).
   No field in it is a memo; no code in the workspace encodes or decodes §4's `memo_type`
   framing (grep clean); `qumbra-wallet` states it outright — URI label/memo are "DISPLAY
   ONLY: there is no memo on the wire" (`crates/qumbra-wallet/src/main.rs:589`).
2. **The envelope wouldn't fit any plausible memo anyway**: 75 B + 121.9 KB proof vs a 120-B
   payload — three orders of magnitude.
3. **Widening the payload is consensus surface**: the 120-B payloads are *committed* body
   bytes since the mint (#188 (a) — `qlab-cbserver/src/codec.rs:60-67` records the
   relocation), so a memo channel is a wire/payload change = a stop-point, design-side.

The envelope *contents* are sufficient for crediting (value, recipient binding, tx binding,
proof); the *delivery path* named by §4 is what does not exist. Reported on #483 as the
task-book's "spec gap → design-side" case; the e2e sketch (§4 below) is written for the
transport that works today.

### 1.3 What qlab-cbserver / the wallet already encode/decode (the seams the kit reuses)

Of the §4 memo convention itself: **nothing** (see 1.2). What exists is every seam *around*
it — the exchange-side crediting service composes from these without new protocol:

- **Scan (detect the deposit)**: `qlab_cbserver::client::light_client_scan`
  (`client.rs:569`) and the caller-supplied-transport variant `light_client_scan_with`
  (`client.rs:593` — the #297 seam built exactly so a non-lab binary brings its own
  HTTP/TLS; "the scan itself is not duplicated anywhere"). Cap-agnostic paging (#312),
  spent-subtraction via `GET /v1/nullifiers` (#314).
- **Read the chain cm for `Envelope::verify` rule 2**: the committed discovery projection —
  `GET /v1/compact` (compact groups carry `cm` per entry, `qlab-note/src/wire.rs:44-52`) and
  `GET /v1/block/<h>/tx/<i>/full` (`qlab-cbserver/src/server.rs:152-159`) for the payload
  open path (#313).
- **Rule 1 (finalized)**: `/v1/telemetry`'s finalized head + `fid`/`dfin` identity
  (RPC 0x04, #242) — the "finalized = creditable" confirmation-policy note in #483 is
  answerable from the existing wire.
- **Wallet-side**: `qumbra-wallet` scans/opens/spends over these same seams (first-user
  journey, `CLAUDE.md`); it does not build disclosure envelopes today — the "exchange
  deposit" send flow (wallet-interop §4's operational note) is future wallet work, stage-2+.

### 1.4 `qumbra-circuit` — the public extraction, and the kit's lineage to it

Public repo [`qumbra-labs/qumbra-circuit`](https://github.com/qumbra-labs/qumbra-circuit):
`qlab-air` + `qlab-consensus` extracted standalone, README-pinned constants (consensus config
b16/q21/g22/fp16/a16, KoalaBear + degree-4 extension, Keccak-256 FRI Merkle, cap height 3,
2^18 rows, wire 148,625 B), a **committed real proof fixture** + `verify` example, and the
no-prove check path (`cargo test --release --test verify_fixture` — "seven tests, no proving,
the whole open-sourced claim"). Its verify entry: `qlab_consensus::verify_proof`
(lib.rs:214 in the extraction; same function the node's default verifier runs —
`crates/qumbra-node/src/verifier.rs:39,72`).

**Shared lineage, stated**: `qlab-disclosure`'s prover/verifier stack is the SAME field,
extension, FRI-Merkle-hash and DFT stack as `qlab-consensus` — replicated only because
`qlab-bench` is a binary crate (`qlab-disclosure/src/prove.rs:1-5`); its `Config`
(`prove.rs:20-40`) is type-for-type the consensus `Config` shape, and the disclosure AIR
chains the same narrow-Keccak core cross-checked against `qlab_air::reference::keccak_f`
(`packing.rs`). So the kit's verifier is the public verifier's sibling by construction:
same primitives, same `p3_uni_stark::verify`, different (smaller) AIR + PV layout. A later
**public extraction of the kit verifier can mirror `qumbra-circuit`'s exact pattern**
(fixture + verify example + value-locked config test), or land *in* `qumbra-circuit` as a
third crate — either way publication is a #203-tracker act, out of stage-0/1/2 scope.

### 1.5 Test scaffolding carrying a real disclosure envelope today

- **`crates/qlab-bench/src/disclosure.rs` — `end_to_end_wallet_disclosure`** (test module,
  file tail): the full M7 flow — recipient address → sender creates+encrypts a note → detect
  → `Envelope::create` → right-address verifier accepts, wrong-address verifier rejects,
  forged-claim rejected. Also `consensus_config_prove_verify` (the reference-lane point).
- **`crates/qlab-disclosure/src/envelope.rs` — `envelope_roundtrip_and_verify`,
  `reject_unknown_ver_and_type`, `tamper_negatives`** (`envelope.rs:245-303`); prover-level
  `prove_verify_roundtrip` / `wrong_pv_rejected` (`prove.rs:171-188`).
- ⚠️ All of these **prove** (2^16-row STARK each) — they are the CI lane's to run, per the
  memory guardrail; stage 0's citation tests deliberately do not invoke them.
- **What carries real txs against a devnet but NO envelope**: the discovery-serving e2e
  (`crates/qumbra-node/tests/discovery_serving.rs:145` — a recipient finds its output from a
  restarted node's committed discovery over real HTTP), and the faucet's grant flow
  (real 2×2 proof → `announce_tx` → mempool → block). These are the chassis stage 2's demo
  composes with (§4 below); today no devnet-facing test attaches a disclosure envelope
  anywhere, because there is nowhere on the wire to attach it (1.2).

---

## 2. Crate layout proposal

**Proposed: two new crates.**

```
crates/qlab-vask         lib — envelope verification, no I/O, no clock, no chain model
crates/qumbra-credit-ref bin — the HTTP crediting reference service (stage 2)
```

- **`qlab-vask`** ("VASP kit" lib): wraps `qlab-disclosure`'s envelope parse + verify behind
  the kit's stable surface — the named-refusal taxonomy, the pinned V1 config
  (`DISCLOSURE_V1_CFG` + `LOG_HEIGHT = 16` — callers must NOT choose FRI parameters, see §3),
  and (stage 1) the C ABI + pinned header. Verify-only by policy: it re-exports no prover
  entry point, so its public surface stays the sub-second, low-memory path an exchange links.
  Naming follows the house split (`qlab-*` internal libs / `qumbra-*` operator-facing
  binaries); the C ABI does not force a `qumbra-*` name — `qumbra-ffi` is a *product kernel*,
  this is a lab lib with a C header, and the published artifact name is a stage-3/#203
  question.
- **`qumbra-credit-ref`** (stage 2): own bin crate per the #117/#128 precedents — Cargo has
  no per-target deps, so a bin inside `qlab-vask` would put the HTTP/service graph into the
  *library's* dependencies, exactly the coupling #128 refused for `qlab-faucet`/
  `qumbra-faucet`. It consumes `qlab-vask` (verify) + `qlab-cbserver` (scan/full-fetch
  seams, 1.3) and answers credit/refuse with named reasons over the faucet's edge posture
  (4xx-never-5xx `qumbra-faucet/src/http.rs:1051`, startup refusals `config.rs:332`, and the
  #308 lesson: key any limiter on the real client, not the proxy).

**Alternatives priced:**

| alternative | price | verdict |
|---|---|---|
| (a) No new lib — C ABI into `qumbra-ffi` | drags `qlab-disclosure` + its full Plonky3 prover graph into the *wallet kernel's* build and iOS cross-compile; mixes two release cadences and two consumers (a wallet shell vs an exchange backend) behind one header pin | refuse |
| (b) C ABI + kit surface into `qlab-disclosure` itself | the prototype crate (prover included, research-paced) becomes an ABI-stability anchor; every AIR experiment then moves a pinned header; also blurs the verify-only public surface the kit wants | refuse |
| (c) One combined kit crate (lib + service bin) | the #128 dep-graph problem verbatim: the lib's consumers inherit the service's HTTP/runtime deps | refuse |
| (d) Service as a mode of `qumbra-faucet` (edge posture already there) | faucet is keyless-node-coupled and grant-shaped; crediting is verify-shaped; shared posture is a pattern to copy, not a crate to cohabit | refuse |

**Dependency note (stated, not hidden)**: `qlab-vask` → `qlab-disclosure` still *compiles*
the prover (p3-uni-stark ships prove+verify in one crate) — the boundary is API surface, not
compile graph. Splitting `qlab-disclosure` into prove/verify halves would be the purer cut
and is deliberately not proposed: it forks a prototype crate for a compile-time nicety, and
`qumbra-circuit` already demonstrates the same stack verifying standalone at acceptable
weight (its README: verify path = seconds, any machine).

---

## 3. The C ABI surface proposal (stage 1 builds this; stage 0 proposes)

Follows `qumbra-ffi`'s shipped conventions: `int32_t` returns, `0` = success, `-1` = invalid
call (NULL/contract violation), `-2` and below = named refusals with a reason string; every
returned buffer freed by the library's own free functions; NULL out-params refused with `-1`
(#465's "cannot opt out" discipline).

```c
/* qvask.h — pinned to source per #246 (see "Header pin" below). */

/* ABI + envelope-format version this library implements. */
int32_t  qvask_abi_version(void);        /* = 1 */
uint8_t  qvask_envelope_ver(void);       /* = 0x01, mirrors ENVELOPE_VER */

/* Parse WITHOUT verifying: extract the claim fields an exchange matches
 * against its deposit record before paying for verification.
 * Refusals: QVASK_MALFORMED / QVASK_UNKNOWN_VERSION / QVASK_UNKNOWN_CLAIM_TYPE. */
int32_t qvask_envelope_peek(const uint8_t *envelope, size_t envelope_len,
                            qvask_claim_t *claim_out);

typedef struct {
  uint8_t  tx_ref[32];
  uint64_t value;
  uint8_t  addr_commitment[32];
  uint8_t  output_index;
} qvask_claim_t;

/* Verify: rule 2+3 of wallet-interop §3. chain_cm is the commitment the CALLER
 * read at (tx_ref, output_index) on its finalized view — rule 1 stays the
 * caller's, exactly as Envelope::verify has it. log_height and the FRI config
 * are PINNED INSIDE the library (see "No caller-supplied config"). */
int32_t qvask_verify(const uint8_t *envelope, size_t envelope_len,
                     const uint8_t chain_cm[32],
                     qvask_claim_t *claim_out,      /* filled on ANY parse success */
                     char **reason_out);            /* set on refusal; qvask_string_free */

void qvask_string_free(char *s);
```

- **Error taxonomy (named refusals, the house pattern)** — one stable negative code per
  `EnvelopeError` variant (`envelope.rs:50-62`), plus the call-contract code:

  | code | name | meaning |
  |---|---|---|
  | 0 | `QVASK_OK` | verified: claim_out is the proven claim |
  | -1 | `QVASK_INVALID_CALL` | NULL args / contract violation |
  | -2 | `QVASK_MALFORMED` | framing (truncated field, trailing bytes, varint) |
  | -3 | `QVASK_UNKNOWN_VERSION` | §3 rule 3 — reject, never ignore |
  | -4 | `QVASK_UNKNOWN_CLAIM_TYPE` | §3 rule 3 |
  | -5 | `QVASK_PROOF_DECODE` | proof_bytes not a proof structure |
  | -6 | `QVASK_PROOF_INVALID` | rule 2 failed; *reason_out carries the verifier's why |

  Codes and names live in the header as `#define QVASK_*` AND in the crate as `pub const`,
  pinned to each other **in both directions** — the #465 extension of the #246 pin
  (`qumbra-ffi/src/lib.rs:1965` is the precedent test to copy).
- **Memory contract**: all inputs caller-owned, never retained past the call; the only
  library allocation crossing out is `reason_out`, freed by `qvask_string_free` — mirroring
  `qmb_string_free` (`qumbra_ffi.h:9`). No handles, no state, no callbacks: verification is
  a pure function, so the reentrancy/lifetime class of contract the pin test cannot pin
  (#465's argument against callbacks) never arises. Thread-safe by statelessness.
- **No caller-supplied config — a security posture, not a convenience**: `Envelope::verify`
  takes `log_height` + `FriCfg`, and a hostile or sloppy caller handing q=0/g=0 would
  "verify" anything. The ABI pins `DISCLOSURE_V1_CFG` + `LOG_HEIGHT` inside the library and
  exposes only `qvask_abi_version()`; a config change is a new ABI version, the same
  versioned-parameter discipline the chain uses.
- **Extensible lists**: no list crosses the V1 ABI (single claim in, verdict out). If stage
  2+ adds one (e.g. batch verdicts), it crosses in #465's tagged + length-prefixed record
  shape — consumer-side lists skip unknown kinds; this ABI's own *refusal* path stays
  reject-unknown (§3 rule 3 is normative, and a verifier must never guess).
- **Header pin (#246 discipline)**: `qvask.h` hand-maintained beside `lib.rs`, updated in the
  same commit as any declaration; bidirectional tests — every exported fn appears in the
  header and vice versa (`the_header_names_every_exported_function_and_nothing_else`,
  `qumbra-ffi/src/lib.rs:1924`), and the `QVASK_*` code values match name-and-value both
  directions, literals asserted (a renumber that keeps both files in step is still a broken
  consumer).
- **Reference binding** (#483: "one reference binding; more on demand"): propose **Python**
  via `ctypes` — no toolchain beyond the shared library, exercises the ABI as a foreign
  runtime would, and is the lingua franca of exchange backoffice glue. Deferred to stage 1
  acceptance; not load-bearing for this proposal.

---

## 4. The e2e path sketch (what stage 2 demonstrates)

**Preferred path (works against today's devnet, no wire change) — out-of-band envelope:**

```
depositor wallet                    devnet                     qumbra-credit-ref (exchange)
  1. send deposit to exchange addr ──► tx mined, finalized
  2. build §3 envelope for that tx                              (holds the exchange's dk/ivk)
     (tx_ref = REAL txid — post-
      broadcast, O3 sentinel moot)
  3. POST /v1/credit {envelope} ────────────────────────────►  4. peek: claim fields
                                                               5. scan: light_client_scan_with
                                                                  finds the deposit output;
                                                                  full-fetch opens it; read cm
                                                                  at (tx_ref, output_index)
                                                               6. finality check: telemetry
                                                                  dfin/fid ≥ deposit height
                                                               7. qvask_verify(envelope, cm)
                                                               8. 200 credit ‖ 4xx NAMED refusal
```

- Steps 5–6 are entirely 1.3's existing seams; step 7 is the kit lib; the HTTP shell copies
  the faucet's edge posture. The demo chassis is the `discovery_serving.rs` +
  faucet-grant shape: keyless node, real committed discovery, real finality — plus the one
  new ingredient, an envelope built by the depositor-side test harness (1.5's
  `end_to_end_wallet_disclosure` flow, pointed at a devnet tx; its prove step runs on CI's
  iron, or a **golden envelope fixture** rides the repo the way `qumbra-circuit` commits its
  proof fixture — stage 1's "golden disclosure fixtures" per #483).
- Refusal taxonomy the demo must exercise (each a named 4xx): no-such-tx / not-finalized
  (rule 1), cm-mismatch / proof-invalid (rule 2), unknown-ver/claim (rule 3), value-mismatch
  vs the opened output, and deposit-not-addressed-to-us (scan finds nothing).
- **In-memo path (the §4 wording)**: blocked on a design-side memo-channel decision (1.2) —
  a wire/payload change, stop-point class. If it lands later, `qumbra-credit-ref` gains one
  extraction step (memo → envelope) and nothing else changes; the verify core and refusal
  taxonomy are transport-agnostic by construction. Asked on #483 (2026-08-18); the sketch
  above assumes the answer is "out-of-band for stage 2, memo design-side."

---

## 5. What stage 0 ships, and open questions

**Ships**: this doc; skeleton `qlab-vask` (re-exports + citation tests: the 1.1 entry points
exist with the inventoried signatures, the envelope constants and refusal variants are the
ones §3's taxonomy maps, parse-reject paths behave — no proving anywhere) and skeleton
`qumbra-credit-ref` (a main that refuses by name pending stage 2, plus citation tests on the
1.3 seams it will consume).

**For the coordinator at this boundary:**

1. **The §4 transport gap** (1.2, asked on #483): out-of-band for stage 2 + memo design-side?
2. **`DISCLOSURE_V1_CFG` = the measured q20 point** (1.1) — adopt as the kit's named pin?
3. Crate names `qlab-vask` / `qumbra-credit-ref` as proposed (task-book's expected shape)?
4. Reference binding = Python/ctypes at stage 1?
