# F2: register scheduling and a constrained reference machine

[中文](f2-register-machine-zh.md). Governing record: [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750). Builds on the executable OOD algebra in [PR #754](https://github.com/qumbra-labs/qumbra-lab/pull/754).

The OOD DAG now has a register schedule. A separate **test-only reference AIR**
constrains the same instruction semantics, register reads, writes and holds. This
is a correctness checkpoint, not the final aggregation layout. The full S3/P3/R
schedules are evaluated sparsely against the DAG; their dense AIR traces are not
allocated or proved. The reference AIR is checked on bounded component programs.

## Scheduling

The compiler rejects missing roots and non-topological references. An iterative
depth-first traversal emits reachable nodes in dependency order, loading input and
constant leaves when first needed. Shared nodes execute once; unreachable nodes
are omitted. Last-use analysis releases a source register after that instruction
reads it, allowing the destination to reuse the register. Duplicate operands do
not double-free a register. Exported roots stay live until the terminal row.

For the OOD program, roots are the residual and the trace-next opening point.
Sparse execution checks **every instruction result** against its original DAG node,
then checks that exported registers retain the right values. This runs inside the
existing native/DAG comparison, including synthetic assignments and real-proof
mutation probes. Checking only a final residual would permit accidental aliases
whose effects happen to cancel.

## Reference AIR

The row contains three extension values A/B/C plus the register file, each expressed
as four KoalaBear limbs. Fixed full-period columns encode opcode, source/destination
selection, constants and public-input selection. Those columns are AIR-owned ROM,
not prover-selectable witness flags. The seven instructions are input, constant,
add, subtract, negate, multiply and inverse; padding has its own fixed selector.

- A and B equal the selected current-row registers; absent operands equal zero.
- Arithmetic constrains C, including multiplication modulo `X^4 - 3` and
  `A * C = 1` for inverse. A zero inverse has no satisfying witness.
- Each register is initially zero. Every transition satisfies
  `next_r - r = write_selector * (C - r)`, covering writes and all non-write holds.
- Input instructions bind C to the selected public extension limbs; constants
  bind C to the ROM value. The last row binds exported registers to expected public
  outputs. F2 integration must fix the residual output to zero.
- Padding forces A/B/C to zero and carries registers. The height always includes
  a terminal row after the last instruction, so no final write escapes transition
  constraints.

Inputs here are **component public values**, not authenticated PCS/Fiat–Shamir
wires (F2b-2a below binds them for a test component; the FRI half is still open). This component proves execution of its fixed program on declared inputs.
It does not establish that those inputs came from a proof, that a source tagged
`Public` has been mapped to the original transaction PV, or that a challenge was
derived from the transcript. Those integration bindings remain required.

## Cost accounting

The new `register_schedule` inside `ood_arithmetic` (price mode) or
`ood_algebra.arithmetic` (census mode) is labelled **P**, derived from the compiled
schedule. It includes instruction count, discarded nodes, peak allocated extension
registers, logical input sources, output count, padded rows and raw storage for both
the trace and reference ROM.

For R registers, I input values and K instructions, the reference dimensions are
**[P, source-derived]**:

```text
trace width = 12 + 4R
ROM width   = 12 + 3R + I
height      = next_power_of_two(K + 1)
raw bytes   = 4 * width * height, separately for trace and ROM
```

This includes the full-period ROM cost; it is not free verifier metadata. These
are raw base-field matrices, not prover peak RSS. They exclude LDE, quotient/FRI,
allocator/workspace costs and composition with the hiding PCS/Keccak lane. Dense
construction checks a caller-supplied combined trace-plus-ROM cell budget before
allocating either matrix. The CLI reports the sparse schedule only.

The reference constraints have degree at most three **[P, guarded in CI]**. Four
new tests cover native extension arithmetic, the degree guard, every result limb,
operand reads, write destinations, an unread/unwritten live-register gap, first/last
rows and padding. Coordinated forgeries regenerate an entire trace and matching
outputs for a different input or opcode schedule; the original input/program binding
must still reject them. The zero-inverse probe keeps writes, carries and public output
consistent so the inverse equation itself must reject it. Malformed graph, duplicate
roots and allocation-limit cases are also covered.

## Validation and remaining work

No local tests, proof generation or benchmarks are permitted or run. Local workspace
compilation and scoped Clippy are the preflight checks; complete `verify-graviton`
CI is the acceptance gate. New tests add four to the merged 2730-test baseline;
2734 passed is the expected count **[P, pending CI]**.

Unverified, most likely to fail first: reference AIR regressions and full-shape
sparse register agreement, pending CI; a practical authenticated input-routing/ROM
layout; the full OOD AIR at real dimensions; combined hiding PCS integration and
target-rig memory. `full_ood_air_checked`, `pcs_input_bindings_complete`,
`complete_verifier_layout` and `memory_gate_pass` remain false. No transaction AIR,
consensus parameter, proof fixture, lockfile or deployment changes.

## F2b-2a: transcript-bound inputs

F2b-2a replaces the reference machine's public-limb inputs with inputs bound
**in-circuit** to a replayed Fiat–Shamir transcript of a real **hiding**
uni-stark proof, up to and including the absorption of the opened values. It is a
test-only component (`crates/qlab-bench/src/f2/ood/bind.rs`), scanned row by row
like the reference AIR and never proved. The fixture is a two-column, degree-3
toy AIR proven inside the test on the L2 lane with a seeded hiding config, so CI
replays the same transcript every run. No fixture file is committed.

### What is bound

The component puts three things on one set of rows: a Keccak lane (stock
p3-keccak-air through m4skel's `LaneBuilder`, 24 rows per permutation), the
sponge and Fiat–Shamir binding, and the register machine.

- **Sponge.** The step-0 row of every permutation carries the block's message bits
  `M` and the previous output's rate bits `S`, and the preimage equals `M xor S`
  limb by limb. `S` is the previous permutation's output on interior blocks and
  zero on a flush's first block; the capacity is carried over or starts at zero.
  Which permutation starts a flush is fixed by periodic selectors, not chosen by
  the prover.
- **Transcript order** (checked against p3-uni-stark 0.6.1 `verifier.rs` and
  p3-fri `two_adic_pcs.rs`): F0 = committed degree bits ‖ original degree bits ‖
  preprocessed width 0 ‖ trace cap ‖ PVs, then α is drawn; F1 = D0 ‖ quotient cap
  ‖ randomizer cap, then ζ is drawn; F2 = D1 ‖ randomizer opening (4 extension
  values) ‖ trace local ‖ trace next ‖ quotient chunks. The randomizer opening is
  hashed but never routed, because it does not enter the OOD identity. `zeta_next`
  uses the original domain N (the trace is committed at 2N); the machine's
  next-point root is pinned to `g_N · ζ`.
- **Every rate word of every block** is bound: metadata and padding to constants,
  caps to outer public values as 16-bit limbs, inner PVs to outer PVs, opened
  values to the machine's inputs, and the chaining prefix by a state equality at
  the flush seam.
- **Fiat–Shamir draws.** Draw j reads digest bytes 31−4j … 28−4j (the challenger
  pops its output buffer from the end), masks to 31 bits and rejects values ≥ p.
  The reject bit is determined by inverse-witness zero tests, and a one-hot
  selection gives limb k the k-th *accepted* draw, so a rejected draw advances
  nothing, as in the native redraw. The machine's `Alpha` and `Zeta` inputs equal
  the selected draws on the two digest rows.
- **Machine inputs.** `Public(i)` equals outer PV i, which equals R⁻¹ × its F0 word;
  `Alpha`/`Zeta` come from the draws; `Local`/`Next`/`Quotient` equal R⁻¹ × their F2
  words. The terminal row pins the residual root to zero and the next-point root
  to `g_N · ζ`.
- **Output.** F2's digest D2 is exposed as 16 public limbs. It seeds fri_alpha,
  which is where F2b-2b starts.

### The two traps

1. **Montgomery words.** The challenger serializes `to_unique_u32`, the raw Monty
   word `R·v mod p`. M4 could stay R-scaled throughout because every identity it
   evaluates is linear in the opened values. The OOD identity is not (the toy's
   `x·y·y + x` is not R-homogeneous), so every opened value and inner PV is routed
   as `R⁻¹ · word`. Challenges come out of `from_canonical_unchecked` and enter
   **unscaled** (checked in `serializing_challenger.rs`). The negative test routes
   R-scaled values into the machine and is refused at `bind_opened`; it also
   asserts that the DAG residual on scaled inputs is nonzero.
2. **No randomized equality.** Binding the machine's inputs to the word stream with
   a random linear combination needs a challenge the outer prover cannot predict.
   An inner-proof challenge is known before the outer trace is chosen, and
   p3-uni-stark 0.6.1 is single-phase, so there is no outer challenge to use. Every
   binding here is a deterministic same-row equality: held input columns, constant
   across all rows, equal `R⁻¹ · word` on the step-0 row that carries the word, and
   the machine's input instructions read the same held columns.

**Canonicity.** A word is 32 bits and a field element is below p, so `v` and
`v + p` both satisfy `R⁻¹ · word = v`. Every field word (inner PVs and all opened
values) carries a `< p` comparator: bit 31 clear, and not (bits 24..30 all set and
bits 0..23 nonzero). Caps, digests and constants are compared as 16-bit limbs,
which are exact. The alias negative encodes one opened value as `word + p`, and only
the comparator rejects it.

### Reuse, and what was not reused

Reused: p3-keccak-air through `m4skel::LaneBuilder`, `m4gaterec::keccakf`/`digest_of`,
and the reference machine's constraint core (`machine::eval_machine`, now shared by
both components). Not reused: the M4 gate rectangle itself. It is hard-wired to the
legacy non-hiding config (fixed 2^16 rows, `N_CAPS`/`FLUSH_BYTES` constants, three
opened groups and no randomizer cap), and its draw gadget and canonicity comparator
are wired to that layout's columns. F2b-2a implements the same predicates narrowly.
The canonicity test uses a "popcount(bits 24..30) = 7" zero test instead of M4's
staged 7-bit AND.

**Deviation from the brief: held input columns instead of a prologue.** The brief
suggested rescheduling input reads into a transcript-order prologue with same-row
equalities. This slice instead holds each machine input in four columns that are
constant across all rows. The binding is just as deterministic and needs no
change to the schedule. It costs 4 columns per input (160 for the toy) and is
**not** a claim about the production layout.

### Constraint groups and tests

Constraints are evaluated in 18 named groups (`keccak`, `bits`, `absorb`,
`chain_state`, `flush_chain`, `bind_const`, `bind_cap`, `bind_inner_pv`,
`canonical`, `digest_out`, `fs_reject`, `fs_select`, `fs_bind`, `bind_opened`,
`in_public`, `in_hold`, `machine`, `machine_out`). The test maps each constraint
index to its group by counting on the symbolic builder, and every negative asserts
the group its violation lands in, on the row where that group lives:

| negative | refused at |
|---|---|
| wrong ζ limb (machine recomputed) | `fs_bind`, ζ digest row |
| wrong α (machine recomputed) | `fs_bind`, α digest row |
| different ζ, quotient re-solved to a zero residual, F2/D2 rebuilt | `fs_bind` only; the terminal row is clean |
| skip an accepted draw | `fs_select`, not `fs_bind` |
| randomizer cap absorbed before quotient cap, fully consistent replay | `bind_cap` only, F1 first block; ζ row and terminal row clean |
| opened value poked in the transcript, machine untouched | `bind_opened` |
| trace-next value poked, machine recomputed | `machine_out` (residual pin); every F2 row clean |
| quotient limb poked, machine recomputed (nonzero residual) | `machine_out` |
| R-scaled routing (R⁻¹ missing) | `bind_opened` |
| opened value encoded as `word + p` | `canonical` only |
| F0 metadata word (log_h) forged, consistent replay | `bind_const` only; α/ζ rows and terminal row clean |
| inner PV absorbed ≠ declared PV, consistent replay | `bind_inner_pv` only |
| inner PV encoded as `word + p` | `canonical` only |

The honest test also cross-checks the replay against the native p3 challenger. It
checks the same α and ζ, and that D2's first draw is the verifier's fri_alpha, which
fixes the F2 message order. It then runs a full SAT scan and checks that the
maximum constraint degree is ≤ 3 **[P, guarded in CI]**.

### Dimensions

For the toy transcript **[P, source-derived]**: F0/F1/F2 are 3 + 5 + 5 = 13 lane
permutations (312 rows). Width = 2,633 (Keccak lane) + 2 × 1,088 (M and S bits) +
68 (canonicity) + 72 (eight draws) + 4I (held inputs, I = 40 for the toy) +
12 + 4R (machine). Height = max(next_power_of_two(24 × perms),
next_power_of_two(K + 1)).

### ROM encoding census

`ood_arithmetic.rom_encoding` (price mode), next to `register_schedule`, states both
encodings of the machine's ROM (W_rom columns × H rows) **[P]**. No layout is
chosen in code:

- **periodic**: W_rom·H extension mul + add to evaluate at ζ, and no PCS cost;
- **committed preprocessed**: a 256-byte cap in F0, 16·W_rom bytes of openings in F2,
  ceil((W_rom + 4)/34) leaf permutations plus one input path per query (both per
  query and × 43), W_rom extra fri_alpha terms and W_rom extra DAG input reads.

### Not yet bound (F2b-2b)

fri_alpha, the FRI betas and commit-phase caps, PoW, query indices, the reduced
opening, salted input-Merkle leaves and paths, and the final polynomial. **Nothing
in F2b-2a ties the opened values to the committed caps**; D2 is where that half
starts. A draw window that needs a refill (more than eight draws; probability about
1e-9 per challenge) cannot be satisfied: that is a completeness gap, never a false
accept. `pcs_input_bindings_complete` and `full_ood_air_checked` stay **false**, as
do `complete_verifier_layout` and `memory_gate_pass`.

### Validation

No local tests, proofs or benchmarks were run. `cargo check`, scoped Clippy and
rustfmt are the local preflight; `verify-graviton` CI is the acceptance gate. New
tests: six in `bind.rs` and one in `price.rs`, seven over the base branch
**[P, pending CI]**. Expected new-test runtime is under 30 s on the Graviton lane
**[P]**: one toy hiding proof, about eleven dense traces of roughly 512–1,024 rows ×
5.4k columns, one full scan, and single-row scans for every negative. Unverified,
most likely to fail first: the replay's cross-check against the native challenger
(the byte order of the draws, cap serialization); a count mismatch between the
symbolic and debug builders in phase numbering; the tiny toy height (log 4) on the
hiding PCS.

