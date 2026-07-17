# qumbra-lab M4 step 0b(ii) increments 2+3: injection routing + FS byte-packing (run 1)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 89996dc (m4route worktree, committed on claude/m4-0bii-inc23)
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, 80% batt, idle rig
- rectangle: **2,685 cols x 2^16** = keccak lane (2,633; 2,233 perms = 540 absorb + 173 challenger + 1,520 compress) + ext-mul bank (12; 28,800 rows) + ext-add bank (12; 28,663 rows) + routing/FS block (28)
- schedule: synthetic, shape-exact (real M3-proof witness is increment 4); routing and FS constraints are REAL (corrupted witness fails — 4 negative unit tests + a native-challenger cross-check)
- routing/FS shape: 18,360 routed opened values (both channels, all 34 slots/absorb-perm); 173 chained digests; 1,376 FS draws = 1,364 emitted challenges + 12 rejected (0.87% vs the expected (2^24−1)/2^31 ≈ 0.78% native rejection rate)

| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 65536 | 455 | 12.1 | 727.2 | 603.1 |
| b16/q20/g20/fp16/a16 | 65536 | 1503 | 7.2 | 423.1 | 350.6 |

## Peak RSS (`/usr/bin/time -l` with `--only`, fresh processes; the shape-report trace build is skipped under `--only` so the freed buffer cannot pollute the high-water mark)

| lane config | peak RSS |
|---|---|
| b4/q40/g20/fp16/a16 | 3.61 GB (3,608,035,328 B) |
| b16/q20/g20/fp16/a16 | 12.28 GB (12,278,267,904 B) |

## Column budget vs the layout plan

| block | plan | realized |
|---|---|---|
| keccak lane | 2,633 | 2,633 |
| ext-mul bank | 12 | 12 |
| ext-add bank | 12 | 12 |
| routing / FS / flags | ~16 | **28** |
| **total** | **2,673** | **2,685** (+12 cols, +0.45% cells) |

The ~16-col allowance did not survive the no-lookup reality: **16 of the
28 routing columns are the FS byte-range bit columns** (each draw row
bit-decomposes one 16-bit digest limb into two range-checked bytes; a
2-row-window AIR without lookups has no cheaper 8-bit range check). The
remaining 12: 2 injection gates, draw accumulator, fs gate, 3 materialized
comparator bit-products (degree control), inverse witness + nonzero flag,
accept, emit gate, chain gate. Injection routing itself costs only the 2
gate columns — the perm-replicated preimage makes routed values same-row
visible, so no M3-style signed accumulator windows were needed.

## Mechanisms (what is now real)

- **Injection routing (increment 2)**: opened values reach both consumers
  under one witness — absorbed as leaf-sponge rate limbs (overwrite-mode
  `PaddingFreeSponge`, value slot v = rate limbs 2v/2v+1, u32-pair-per-lane
  packing) and consumed as 4-limb ext tuples by the banks (channel 0 →
  add-bank b, rows 0..24; channel 1 → mul-bank b, rows 0..10; 34/34 slots
  per absorb perm covered). Byte-decomposition ↔ limb view consistency =
  step-flag-muxed slot constraint, degree 3. Routed word convention:
  `(lo + 2^16·hi) mod p`; byte-string canonicity (the v vs v+p alias) is
  deferred to the transcript-digest binding (increment 4) — an aliased
  encoding changes the digests and fails there.
- **FS byte-packing (increment 3)**: challenger digests → challenge field
  elements with the NATIVE `SerializingChallenger32` convention read from
  the pinned source: pop 4 bytes from the digest end, LE-assemble, mask to
  31 bits, **reject and redraw if masked ≥ p** (KoalaBear canonicity).
  In-circuit: 2 rows per draw (12-draw capacity > the 8-draw digest max),
  digest limbs read from the consuming perm's preimage under an explicit
  chaining constraint (producer output limbs = consumer preimage limbs,
  perm-boundary gated), rejection comparator = top-7-bits product ×
  inverse-witnessed low-24-nonzero flag, accepted draws emitted to the
  mul bank's a operand. `fs_matches_native_challenger` cross-checks the
  emitted sequence against a real `SerializingChallenger32` +
  `HashChallenger<u8, Keccak256Hash, 32>` sampling run (identical values,
  including skipping the 12 rejected draws).

## Verdict vs increment 1 (m4skel: b4 476–561 ms / 3.58 GB / 597.9 KB; b16 1440–1610 ms / 12.16 GB / 347.6 KB)

- prove: inside increment 1's thermal-jitter band at both configs — the
  routing/FS constraints are prove-time free at this scale.
- bytes: fixed +5.2 KB (b4) / +3.0 KB (b16), matching the +28 opened
  columns per query.
- RSS: +0.03 GB (b4) / +0.12 GB (b16) — the +1.05% cells.

## Notes

- A third full-process run (pre-dating a cosmetic `--only` reporting
  tweak, identical prove path) measured b4 = 514 ms / b16 = 1,653 ms —
  inside the same band; recorded here for completeness.
- Tests: 6 new unit tests in `m4route.rs` — positive rectangle check,
  native-challenger cross-check, prove/verify roundtrip, and negatives:
  byte/limb mismatch, tampered digest→challenge, out-of-range packing
  (forged emission of a rejected draw dies on the low-24 nonzero guard),
  forged chain gate.
- Gate/selection columns are witness in this increment; binding them to
  the fixed verification schedule (program ring), the `sample_bits` draw
  variant (mask-only, no rejection), ext-challenge assembly (4 draws →
  one 4-limb tuple), and public binding are increment 4.
- Repo-wide `cargo fmt --check` is NOT clean at the base rev under
  rustfmt 1.9.0-stable (pre-existing diffs in qlab-air/narrow.rs,
  m4price.rs, m4anchor.rs, m4census.rs, narrow_bench.rs — rustfmt version
  drift vs earlier sessions). New/touched files (m4route.rs) are
  fmt-clean; the pre-existing files were left untouched to keep this PR's
  diff scoped.
