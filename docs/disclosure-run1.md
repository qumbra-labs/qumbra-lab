# Disclosure-proof measured run 1 (wallet-interop §3)

Selective disclosure-proof STARK — the single-note statement that fills the
[wallet-interop-spec](../../qumbra-design/wallet-interop-spec.md) §3 envelope
(closing the ZIP-311 gap; [auditable-privacy](../../qumbra-design/auditable-privacy.md)
§4 "Selective" layer).

- **hardware**: Apple M5 Max, 36 GiB RAM
- **OS**: macOS 26.5.2
- **qumbra-lab rev**: `1c9871f`
- **prover**: Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **power state**: AC, thermal nominal
- **command**: `cargo run --release -p qlab-bench -- disclosure`

## Statement

For one on-chain output note:

```
public:  cm               the note commitment at (tx_ref, output_index)
         value            the disclosed amount
         addr_commitment  Keccak256(recipient's full raw address)   [§3: 32 B]
witness: rkm, rho, rseed  the note opening
         version, d, ek   the recipient address fields
prove:   cm              == H_commit(value ‖ rkm ‖ rho ‖ rseed)   [qlab-air packing]
     ∧   addr_commitment == Keccak256(version ‖ d ‖ rkm ‖ ek)     [qlab-wallet layout]
```

The shared `rkm` binds "this payment went to THAT address." Both packings are
regression-locked byte-for-byte against `qlab_air::narrow::build_bucket`
(ROLE_ACMOUT `cm`) and `qlab_wallet::address::Address::to_raw_bytes()` — the
STOP-POINT cross-check cleared before any constraint was built.

## Circuit

- narrow-Keccak sponge pipeline reused from the qlab-air M1.5c narrow core
  (z-slice Keccak-f, S/V/U shift registers, in-trace iota-RC ring, program /
  perm-boundary / phase rings — same constraints, cross-checked vs
  `qlab_air::reference::keccak_f`).
- **594 columns × 2^16 rows**; **12 permutations**: 1 (`cm`) + 10 (address
  sponge) + 1 (close/expose the address digest).
- max constraint degree **3** (deg-3 house rule, asserted).
- `rkm` cross-binding: signed 16×16-bit accumulator, CM side aligned (lanes
  1..5), ADDR0 side routed through **free periodic columns** (the address's
  `rkm` is byte-misaligned at raw bytes 17..49).

## Measured

| config | conj. bits | prove ms | verify ms | postcard KB | fixed KB | vs 2×2 bucket (136.4 KB) |
|---|---|---|---|---|---|---|
| b16/q20/g22 (consensus) | 102 | 988.3 | 26.7 | 141.7 | **121.9** | 0.89× |
| b8/q27/g19 | 100 | 335.6 | 31.7 | 178.0 | 153.3 | 1.12× |
| b4/q40/g20 | 100 | 289.7 | 33.3 | 244.9 | 211.1 | 1.55× |
| b32/q18/g10 | 100 | 1034.4 | 27.2 | 133.3 | **114.6** | 0.84× |

- proof size reported twice: postcard (varint campaign codec) and bincode-fixed
  (4 B/field-element, the wire-format proxy — the frontier uses it).
- prove/verify = best of 3 in-process runs.

## Findings

1. **The disclosure proof is NOT ≪ the 2×2 bucket — it is comparable
   (0.84–1.55×).** The interop-spec O2 expectation ("single-note statement ≪
   the 2×2 bucket") is optimistic. At the consensus lane the disclosure is
   **121.9 KB fixed = 0.89×** the bucket's 136.4 KB; the smallest measured point
   (b32) is **114.6 KB = 0.84×**; low-blowup lanes are *larger* than the bucket.

2. **Cause — the ML-KEM ek dominates.** A faithful `addr_commitment =
   Keccak256(full 1,233-byte address)` is a **10-block Keccak sponge** (the
   1,184-byte ML-KEM-768 `ek` is 87% of the preimage). That forces 12 perms →
   **2^16 rows** (well above the task's 2^12–2^14 estimate). Small STARKs pay
   FRI's per-query / opened-value costs, which scale with trace **width**
   (≈constant here, dominated by the 402-column Keccak core) not height — so the
   proof cannot shrink to "tens of KB" while proving the full-address hash
   in-circuit.

3. **Size floor ≈ 115 KB (fixed), far above the ~50 KB the task flagged.** Per
   the task's guidance this is reported as a **finding, not a failure**: the
   `rkm` binding *requires* hashing the full address preimage in-circuit (that
   is what ties `cm` to *that* address), and §3 *defines* `addr_commitment` over
   the full 1,233-byte address, so the 10-block sponge is irreducible for this
   construction.

4. **Prove ≤ ~1 s, verify ~27 ms** — both comfortably inside the ≤3 s laptop
   target. Prove-time varies run-to-run (grind-PoW parallelism jitter, a
   known effect since M1.6); proof **size is deterministic** (see run 2).

## Design implication (for the coordinator / design repo — not a stop-point)

The construction faithfully implements §3, so this is not a spec-conformance
stop-point. But the O2 sizing claim in `wallet-interop-spec.md` §3 should be
revised: a §3 disclosure proof over an ML-KEM address is **bucket-sized, not
≪ the bucket**. Options to actually reach "tens of KB": (a) define
`addr_commitment` over a *shorter* preimage than the full ek-bearing address
(e.g. the short-address hash) — a spec change; (b) a WHIR-class PCS (the
standing squeeze noted throughout M1); (c) accept disclosure proofs are
bucket-sized. Recommendation: revise the O2 note to "comparable to the 2×2
bucket," and record (a)/(b) as the size-reduction watch items.
