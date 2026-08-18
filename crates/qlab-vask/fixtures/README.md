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

## The QVASK_OK fixture (minted on CI-class iron, NOT yet committed)

`golden-envelope-v1.bin` + `golden-chain-cm-v1.bin`: a real envelope at the
pinned `DISCLOSURE_V1_CFG` (b16/q20/g22) over the deterministic instance in
`tests/golden_v1.rs`. Minting needs one prove of the disclosure STARK, which
the memory guardrail keeps off developer machines — run
`cargo test --release -p qlab-vask --test golden_v1 -- --ignored mint_golden_fixture_files`
on CI-class iron (it writes both files here and prints their Keccak-256
digests), commit the outputs, and un-ignore `committed_golden_fixture_verifies`
in the same commit. Until then, CI's suite still proves the identical path:
`golden_envelope_v1_end_to_end_over_the_abi` builds the same deterministic
envelope in-test and drives it through the full C ABI.
