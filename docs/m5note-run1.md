# qumbra-lab M5 note-encryption bench

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 4335869
- crypto: ml-kem 0.3.2 (FIPS 203), chacha20poly1305 0.11.0 (pinned)
- power state: AC, warm
- per op: best of 5 timed loops of 20000, single-core (sequential calls)

## Per-note scan compute (single-core)

| op | µs/op | ops/s |
|---|---|---|
| full-FO decap (path a) | 18.540 | 53937 |
| encap (re-encryption proxy) | 15.238 | 65626 |
| **FO-skip decap (path b, decomposition est.)** | **3.302** | **302825** |

- FO-skip compute saved ≈ **82.2%** (UPPER bound); speedup factor ≈ **5.61×**
- INTERPRETATION vs doc's ~40–50%: the FO re-encryption re-expands the ML-KEM matrix Â (a SHAKE-heavy step ABSENT from CPA decryption), so on this portable impl the re-encryption is a larger share of decap than the doc's estimate assumed. This is a decomposition UPPER bound (encap ⪆ re-encryption); a definitive figure needs a real CPA-decap — NOT a doc correction until then.
- absolute throughput: ml-kem is portable pure-Rust (NO NEON/AVX2). The survey's ~10k ops/s A72 and ~70k ops/s M1 numbers were NEON-optimized reference code, so absolute ops/s here run lower than a SIMD build — but still ~5× the A72 phone reference. Compute remains a non-issue (≥100× from the bandwidth bind); bandwidth is the whole game (survey §4).
- CAVEAT: ml-kem 0.3.2 does not expose CPA-decap (pke::decrypt is pub(crate)); path (b) is measured by decomposition, not a from-scratch CPA-decap. A production FO-skip needs a KEM exposing CPA-decap (named remainder).

## Amortized compact-entry bytes/note (wire layout)

| shape | bytes/note | doc reference |
|---|---|---|
| 1-of-1 (unamortized) | 1129 | ~1.1 KB (1,129 B) |
| 2-of-1 (amortized) | 585 | ~600 B (544-B ct share) |
| 4-of-1 | 313 | — |

- layout: cm 32 B + tag 8 B + clue 1 B + ceil(1088/k) ct share; matches note-discovery.md §2 (~600 B amortized, ~1.1 KB unamortized).
