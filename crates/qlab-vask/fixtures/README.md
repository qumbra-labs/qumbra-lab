# qlab-vask golden fixtures (lab #483 stage 1)

Committed test vectors for the wallet-interop §3 envelope surface. Two
classes, with different provenance:

## Parse fixtures (committed here, no prover involved)

Hand-constructed §3 framing (`ver ‖ claim_type ‖ tx_ref 32 ‖ value u64 LE ‖
addr_commitment 32 ‖ output_index ‖ proof_len LEB128 ‖ proof_bytes`); the
proof region is 64 bytes of `0xEE` — deliberately NOT a proof, so these
exercise exactly the parse/peek half of the ABI and nothing can mistake one
for a verifiable envelope. Locked by `the_refusal_fixtures_refuse_by_name` /
`the_abi_peeks_and_names_refusals_over_the_fixtures` (Rust) and
`bindings/python/smoke.py` (the reference binding).

| file | expected | code |
|---|---|---|
| `peek-claim-v1.bin` | peek OK: tx_ref = 00..1f, value = 42000000, addr_commitment = a0..bf, output_index = 7; verify refuses at the proof-decode gate | 0 / -5 |
| `refuse-unknown-version.bin` | ver = 0x02 | -3 QVASK_UNKNOWN_VERSION |
| `refuse-unknown-claim.bin` | claim_type = 0x03 | -4 QVASK_UNKNOWN_CLAIM_TYPE |
| `refuse-truncated.bin` | cut mid-addr_commitment (60 B) | -2 QVASK_MALFORMED |
| `refuse-trailing.bin` | one byte past proof end | -2 QVASK_MALFORMED |
| `refuse-varint-truncated.bin` | proof_len varint continuation byte, then EOF | -2 QVASK_MALFORMED |

## The QVASK_OK fixture (CI-minted, committed)

`golden-envelope-v1.bin` (150,695 B) + `golden-chain-cm-v1.bin` (32 B): a real
envelope at the pinned `DISCLOSURE_V1_CFG` (b16/q20/g22/a16) over the
deterministic instance in `tests/golden_v1.rs`.

- **Provenance**: minted by the `--ignored` generator `mint_golden_fixture_files`
  via `.github/workflows/kit-fixture-mint.yml` on the hosted arm64 lane
  (`qumbra-arm64-8`, aarch64, rustc 1.97.1) — run 32205863216, 2026-08-19.
  Keccak-256 as printed by the generator:
  `golden-envelope-v1.bin` = `c03e8220495944ecde8a2f2d31dd59e5a843f320ee1f87b14b24eefaf823ac55`,
  `golden-chain-cm-v1.bin` = `97669513557a58d6a8329410b3f5aa0148211d8fbc5ce5b72a483e5d3d0c1608`.
- **Standing verification**: `committed_golden_fixture_verifies` runs the
  committed bytes through the real C ABI verify in every suite pass, so a
  drifted or corrupted fixture cannot survive an acceptance run.
- **Re-mint** (a V2 config, a statement change): push a `mint/**` branch — the
  workflow proves once and hands the files back as an artifact; commit them and
  the digest block above in the same commit.
- ⚠️ **Size note (basis matters)**: the envelope is 150,695 B — the widely
  cited "~122 KB" is `docs/disclosure-run1.md`'s **bincode-fixed** proof size
  (121.9 KB), but the §3 envelope serializes the proof with **postcard**
  (141.7 KB in the same table, and this artifact's config carries a16 arity).
  Reported at stage 2 for a design-side figure correction.
