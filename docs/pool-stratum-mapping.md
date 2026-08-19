# Pool stratum mapping — §4 reading executed (lab #482 stage 0)

> New to stratum entirely? Two-minute primer: [stratum-primer.md](stratum-primer.md).
> [中文版](pool-stratum-mapping-zh.md)

**Status: STAGE-0 DELIVERABLE.** Executes the demand-gated stratum reading that
[pool-payout-axis-brief](https://github.com/qumbra-labs/qumbra-design/blob/main/pool-payout-axis-brief.md)
§4 asked for and that [pool-t1-brief](https://github.com/qumbra-labs/qumbra-design/blob/main/pool-t1-brief.md)
§3's route-A ruling unblocked. Tracker: [lab #482](https://github.com/qumbra-labs/qumbra-lab/issues/482).
Multica: QUM-136.

This document is the mapping table + crate-shape decision + v4-compat note.
The implementable proof is the fixture round-trip in `qlab-stratum`
(`tests/fixture_roundtrip.rs`). **No endpoint, no accounting, no consensus
contact** — those are stages 1–3.

## 0. Premises checked first

| Premise | Tree / brief says | Checked |
|---|---|---|
| No stratum/pool/extranonce code on `main` | lab #356: grep NOT FOUND; M9-N3 "in-node, solo, no template surface" | **HOLDS** — `find`/`grep` on this branch still empty before this PR |
| v5 header offsets (nonce 39–46, version+u48 at 32–38) | pool-t1-brief §3 DECIDED; lab PR #472 `preimage_for(V5)` | **HOLDS** — constants in `qlab-stratum::blob` mirror PR #472; assert-against-merge owed when #472 lands |
| rx/0 bit-identity | lab #356 CLOSED, IDENTICAL | **HOLDS** — layout-independent; not re-measured here |
| Target model = leading-8-BE ≤ `u64::MAX/d` | lab #356 CLEAN; `qlab_devnet::pow::{target_threshold,hash_to_work_value}` | **HOLDS on the scalar shape; 🔴 CORRECTED on byte selection** — see finding 6 / [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490): stock xmrig compares `hash[24..32]` LE, our consensus `hash[0..8]` BE. Ruled: v5 nets move to trailing-8-LE. The pure fns in `qlab-stratum::target` (threshold arithmetic) are byte-selection-agnostic and stand |
| Key-block cadence = Monero mask (2048/64) | `qlab-pow::keyblock`, test-locked | **HOLDS** — pool reuses the schedule; does not fork it |

No row wants a header-layout change. No row says the convention structurally
cannot carry the v5 header. **No STOP-and-report on #482.**

## 1. Convention sources

| Source | What it authorizes |
|---|---|
| [xmrig-proxy `STRATUM.md`](https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM.md) | `login` / `job` / `submit` / `keepalived` shapes |
| [xmrig-proxy `STRATUM_EXT.md`](https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM_EXT.md) | `algo` negotiation; extended job fields |
| xmrig `Job.h` (cited lab #356) | RandomX family: `nonceOffset=39`, `nonceSize=4`; blob window `[43, 408)`; 4- or 8-byte target parse |
| pool-t1-brief §3 | v5 preimage offsets (the ruled header) |
| lab PR #472 `header.rs` | byte-exact v5 preimage (97 B) |
| `qlab-pow::keyblock` | seed-height arithmetic; `is_rotation_height` |

## 2. Mapping table — Monero stratum ↔ Qumbra v5

### 2.1 Transport

| Convention | Qumbra mapping | Fit |
|---|---|---|
| Plain TCP, one JSON-RPC 2.0 object per LF-terminated line | Same. Codec in `qlab-stratum::codec`; listener is stage 1 (`qumbra-pool`) | CLEAN |
| No TLS required by convention | Out of scope for stage 0; ops ruling later | n/a |

### 2.2 `login` (miner → pool)

| Field | Convention | Qumbra mapping | Fit / citation |
|---|---|---|---|
| `login` | payment address / worker id | Pool account id (stage 2 accounting). **Not** an on-chain address at login — under payout axis (c) the pool pays via coinbase payee-list, so login identity is an accounting key the pool assigns / the miner chooses | CLEAN for stratum; accounting is stage 2 |
| `pass` | free-form | Ignored or worker password — pool policy | CLEAN |
| `agent` | miner UA string | Logged; unused by consensus | CLEAN |
| `algo` | e.g. `["rx/0"]` | Require `rx/0` (lab #356 IDENTICAL). Refuse others by name | CLEAN |
| `rigid` | optional rig id | Optional; accounting only | CLEAN |

Login success returns `{ id, job, status: "OK" }` with the first job embedded
(STRATUM.md). Session `id` is echoed on every `submit`.

### 2.3 `job` (pool → miner) — the load-bearing surface

| Field | Convention | Qumbra v5 mapping | Fit / citation |
|---|---|---|---|
| `blob` | hex hashing blob; miner writes nonce at offset 39 | **97-byte hex of `BlockHeader::preimage_for(V5)`**, with pool extra-nonce already written at 43–46 and miner window 39–42 zeroed (or prior). Length 97 ∈ xmrig `[43, 408)` | CLEAN under route A. **DEVIATION from Monero:** blob is our header preimage, not a CryptoNote block hashing blob — same stratum field, different bytes (named; required) |
| `job_id` | opaque string | Pool-generated; ties submit → template | CLEAN |
| `target` | hex; 4-byte compact *or* 8-byte raw | **8-byte LE hex of `u64::MAX / difficulty`** (pool share difficulty). xmrig accepts 8-byte raw; threshold scalar matches | CLEAN on encoding — **but see finding 6 (#490)**: the *hash bytes compared* against this target differ between stock xmrig and pre-#490 consensus. **FINDING:** Monero's common 4-byte compact target is *not* our native encoding — we do not emit it. Decoder accepts 4-byte as zero-extend for fixture inspection only (`target.rs`); never on a live Qumbra job |
| `algo` | `"rx/0"` | Always `"rx/0"` | CLEAN (#356) |
| `height` | block height | `header.height` (u48 on the wire inside the blob; u64 in the JSON field) | CLEAN |
| `seed_hash` | 32-byte hex RandomX key | `pow_seed(...)` → 32-byte key-block header hash at `KeyBlockSchedule::seed_height(height)` | CLEAN (#356) |
| `next_seed_hash` | 32-byte hex; optional; preloads the next dataset | Pure arithmetic the pool computes: when tip approaches a rotation (`is_rotation_height` within the pool's preload window), send the hash of the block at the *next* seed height. **No consensus field** — pool-only | CLEAN-WITH-CAVEAT (#356: MISSING but cheap). Preload window width = pool policy (stage 1) |
| miner nonce window | blob\[39..43\] | Same offsets on v5 preimage | CLEAN (the whole point of route A) |
| pool extra-nonce | Monero: coinbase reserved bytes | **blob\[43..47\]** — high 4 bytes of the u64 nonce. Pool sets per connection before handing the job; miner must not touch | CLEAN under route A. **DEVIATION from Monero:** partition lives in the header nonce high half, not in a coinbase tx — stratum field still absent (extra-nonce is *inside* the blob, not a JSON field), which is how Monero pools also do it |

#### Blob byte map (v5)

```text
 0–31   prev                         (from tip)
32      header format version = 0x05
33–38   height, u48 LE
39–42   miner grind window           ← xmrig writes submit.nonce here
43–46   pool extra-nonce             ← pool sets per connection
47–54   timestamp, u64 LE
55–62   difficulty, u64 LE           (consensus difficulty of the template)
63–94   tx_body_commitment
95      AggregateProofSlot tag 0xA6
96      EpochSupplyAttestation tag 0x59
```

Consensus `header.nonce: u64` = little-endian assembly of `[39..43) ‖ [43..47)`.
Helper: `qlab_stratum::blob::assemble_nonce`.

### 2.4 `submit` (miner → pool)

| Field | Convention | Qumbra mapping | Fit |
|---|---|---|---|
| `id` | session id from login | Same | CLEAN |
| `job_id` | from job | Same; look up template + extranonce | CLEAN |
| `nonce` | 4-byte hex LE | Applied at blob\[39..43\]; combined with stored extranonce → `header.nonce` | CLEAN |
| `result` | 32-byte hex PoW hash | Compared to job target (share) and, on block-level hit, to consensus difficulty | CLEAN |
| `algo` | optional echo | Must be `rx/0` if present | CLEAN |

Share validation (stage 1): rebuild blob with submit nonce, RandomX-hash under
`seed_hash`, check **trailing-8-LE `< job target`** — the [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490)-ruled
v5 predicate, and strict `<` to mirror xmrig's own filter (a `<=` validator would
reject boundary shares xmrig never sends anyway, but mirroring removes the class).
Block candidate (stage 1/2): also ≤ consensus difficulty under the same v5
predicate, then assemble full block and submit to the node.
*(Original stage-0 text said leading-8-BE; corrected 2026-08-18 per #490.)*

### 2.5 Job re-issue and template invalidation

| Event | What rotates | What the pool does | Citation |
|---|---|---|---|
| Tip advances (new parent / height) | `prev`, `height`, `timestamp`, `difficulty`, `tx_body_commitment` (and possibly coinbase body) | Push a new `job` with a fresh `job_id` and blob. Outstanding jobs become **stale** — submits against them fail by name | pool-t1-brief §4 template sketch; M9-N3 tip is the template source |
| Key-block rotation | `seed_hash` (and `next_seed_hash`) | At `KeyBlockSchedule::is_rotation_height(height)`, every live job must carry the new seed. Push new jobs *before* miners hash under the old key at the new height. Dataset reload cost is the miner's | `qlab-pow::keyblock`; #356 CLEAN |
| Pool share-difficulty change | `target` only | Re-issue job (same blob/extranonce allowed; new `job_id` + target) | pool policy |
| Extra-nonce reassignment | blob\[43..47\] | Rare; new job with new extranonce so search spaces stay disjoint | route A |
| Finality / checkpoint advance | does **not** change the PoW preimage | No stratum field. Pool *may* prefer templates whose parent is finalized (policy); not a convention requirement | committee finality is orthogonal to RandomX |

**§4 concern, answered:** key-block rotation maps onto `seed_hash` /
`next_seed_hash` exactly as Monero does; template invalidation is tip-change
(stale job) plus rotation (seed change). Checkpoint cadence is not a stratum
event.

## 3. FINDINGS (convention cannot express / named deviations)

1. **Blob contents ≠ Monero CryptoNote blob.** The stratum `blob` field carries
   our v5 header preimage. Stock xmrig hashes whatever bytes it is given at the
   RandomX `(seed, message)` interface — so this works *because* route A put the
   grind window at offset 39, not because the blob layout matches Monero's.
   Named deviation; required; not a workaround.
2. **Target encoding: 8-byte raw, not 4-byte compact.** Our consensus threshold
   is a full `u64`. Emitting Monero compact would be lossy / differently scaled.
   xmrig accepts 8-byte raw (`Job.cpp` target parse, cited #356). We commit to
   8-byte LE hex. **FINDING:** a pool that blindly copied Monero's 4-byte
   compact emitter would mis-set share difficulty.
3. **Extra-nonce is not a JSON field.** Same as Monero pools (it lives inside
   the blob). Ours lives in header nonce\[4..8) rather than coinbase reserved
   bytes — invisible to stratum, visible to consensus. No convention gap.
4. **`next_seed_hash` is pool-computed.** No Qumbra consensus field. Not a
   finding against the convention — the convention already treats it as
   pool-supplied.
5. **v4 nets remain UNCLEAN for stock xmrig** (lab #356). Stage 0 does not
   claim otherwise — see §5.

6. **🔴 Work-value byte selection (found at coordinator stage-0 review, corrected
   2026-08-18 — [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490)).**
   Stock xmrig's share predicate reads the RandomX hash's **trailing 8 bytes
   little-endian** (`CpuWorker.cpp`: `*reinterpret_cast<uint64_t*>(m_hash + 24)`,
   strict `<`); pre-#490 consensus read the **leading 8 bytes big-endian**
   (`pow.rs::hash_to_work_value`). Same pass-probability, different hashes — a
   pool would reject ~100 % of honest shares and block finds would never be
   submitted. This row was marked CLEAN here and in #356 because both analyses
   traced the scalar shape and the target-hex parse but never *which hash bytes*
   the miner compares. **Ruling (#490): `GenesisForm::V5` nets use trailing-8-LE
   (Monero-congruent); v4/T1 keeps leading-8-BE unchanged.** The consensus-side
   form-keying of `satisfies_target` is #490's own PR, not this baton; stage 1's
   share validator consumes it.

No finding changes §3's premises. No finding wants a further header-layout
change. Finding 6 changes a **consensus predicate** (ruled, #490) but no header
byte, no genesis byte, no target encoding.

## 4. Measurement — fixture round-trip

**Test:** `qlab_stratum` → `fixture_roundtrip::fixture_transcript_round_trips_login_job_submit`.

**Fixture:** `crates/qlab-stratum/fixtures/xmrig_submit_transcript.jsonl` —
hand-built to xmrig-proxy STRATUM.md shapes. **Named deviations** (also in the
fixture's `_comment` line): v5 blob; 8-byte raw target. No public captured
Qumbra↔xmrig transcript exists yet (no pool endpoint exists); stage 3 e2e
replaces this with a live capture.

**What it proves:** login / job / submit lines decode; blob is 97 B with version
`0x05`; miner nonce apply leaves extranonce intact; assembled `u64` nonce matches
the ruled LE layout; target hex ↔ difficulty 1024 round-trips.

**What it does not prove:** RandomX hash correctness (owned by `qlab-pow`,
re-proven every acceptance); live TCP; share accounting. Named, not hidden.

## 5. v4-compat / template-source abstraction

Stage 2 must be testable against today's v4 devnets (N=1 single-payee fallback).
PR #472's `ChainRules { form, halt }` is the selection point — the template
source keys off `form`, never off a free-floating flag.

```text
TemplateSource
  ├─ form: GenesisForm          ← from ChainRules (genesis identity)
  ├─ tip_template() -> Template
  │     V5 → preimage_for(V5) blob; payee-list coinbase (cap per rules)
  │     V4 → preimage_for(V4) blob; N=1 single-payee coinbase (today's form)
  └─ submit_block(block)        ← node RPC; form already baked into codecs
```

Consequences, stated plainly:

- **Stratum-to-stock-xmrig is a v5-only product claim.** On v4, the blob still
  has nonce at offset 56 — #356 UNCLEAN stands. A v4-pointed pool either (a)
  serves no stratum and drives shares via in-process/`qumbra-node mine`
  fixtures, or (b) serves stratum to a patched miner (route B, rejected as
  destination). Stage 2's "testable on v4" means **accounting + payee-list
  assembly with N=1**, not "stock xmrig earns shares on T1".
- **One binary, two nets.** `qumbra-pool` reads the node's genesis form once
  (same posture as `qumbra-node`'s `prepare_with_release`) and builds the
  template source around it. No config switch that could desync from the
  genesis hash (H1).

## 6. Crate-shape decision (with reuse survey)

### 6.1 Proposal

| Crate | Role | Stage |
|---|---|---|
| **`qlab-stratum`** | Protocol lib: blob layout, target encode, login/job/submit codec, fixture tests. **No I/O policy, no TCP, no accounting.** | 0 (this PR) |
| **`qumbra-pool`** | Shipping binary: TCP stratum endpoint + share accounting + template source over node RPC. Depends on `qlab-stratum` + node/RPC clients. | 1+ (not created in stage 0) |

Grounds: the house lib/binary split (`qlab-faucet` / `qumbra-faucet`,
`qlab-node` / `qumbra-node`, `qlab-cbserver` codec vs its `tiny_http` server).
A bin inside `qlab-stratum` would drag listener deps into every consumer of the
codec — the same mechanical reason `qumbra-faucet` is its own crate.

### 6.2 Reuse survey

| Candidate | What it has | Reuse verdict |
|---|---|---|
| `qlab-p2p` | Length-prefixed binary peer wire, gossip, sync, `transport.rs` | **Do not reuse for stratum.** Different protocol family (binary framed P2P ≠ newline JSON-RPC). Stylistic kinship only (versioned reject-unknown). |
| `qlab-cbserver` | `tiny_http` localhost HTTP + golden-locked codec | **Codec discipline yes, server no.** HTTP ≠ stratum TCP. Steal: version-lead / golden-bytes posture, "reference bytes *are* the spec". Do not depend on the crate. |
| `qlab-node::rpc` | HTTP wallet surface over live node state (`tiny_http`) | **Template source consumes it (stage 1); stratum does not share its transport.** Additive RPC for templates (pool-t1-brief §4) may land beside it — still HTTP, still not stratum. |
| `qlab-pow::keyblock` | Seed-height schedule | **Reuse directly** from `qumbra-pool` (not from `qlab-stratum` — keep the protocol lib free of pow deps). |
| `qlab-devnet::pow::{target_threshold,…}` | u64 threshold helpers | **Mirror as pure fns** in `qlab-stratum::target` so the lib stays off the RandomX graph; `qumbra-pool` may call either. |
| `qumbra-faucet` | Thin binary over a tested lib, keyless-host posture | **Shape precedent** for `qumbra-pool` (keyless template host per pool-t1-brief §4 / faucet §6.2). |

### 6.3 What stage 0 ships

- This document (+ `-zh`)
- `crates/qlab-stratum` (codec sketch + fixture tests)
- Workspace membership + README annotated entry
- **Not** `qumbra-pool` (empty binary crate deferred to stage 1 — creating a
  no-op bin now would only burn a crate slot)

## 7. Acceptance cross-walk

| Acceptance item | Evidence |
|---|---|
| Mapping doc EN+ZH | `docs/pool-stratum-mapping.md`, `docs/pool-stratum-mapping-zh.md` |
| Fixture round-trip | `qlab_stratum::tests::fixture_roundtrip::*` |
| Crate-shape + reuse survey | §6 |
| v4-compat / template abstraction | §5 |
| CI (`verify-graviton`) | PR label; arithmetic = `main` baseline + this crate's tests (unit + fixture). Builder does not run the full workspace suite locally (MEMORY GUARDRAIL) |
| No endpoint / accounting / consensus / deploy | Diff confined to `docs/` + `crates/qlab-stratum` + workspace/README wiring |

## 8. Open for stage 1 (not decided here)

- TCP accept loop + per-connection extranonce allocator
- Template RPC shape on the node (additive, off-by-default — pool-t1-brief §4)
- Share-difficulty defaults and stale-job TTL
- Whether `next_seed_hash` preload window is N blocks or wall-clock
