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
wires (F2b-2a below binds them for a test component; F2b-2b-i continues the transcript through the FRI challenges; the Merkle and query checks are still open). This component proves execution of its fixed program on declared inputs.
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

Constraints are evaluated in 19 named groups (`keccak`, `bits`, `absorb`,
`chain_state`, `flush_chain`, `bind_const`, `bind_cap`, `bind_inner_pv`,
`canonical`, `digest_out`, `fs_reject`, `fs_select`, `fs_bind`, `bind_opened`,
`in_public`, `in_hold`, `machine`, `machine_out`, and `opened_out`, added by
F2b-2b-ii; see there). The test maps each constraint
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
| exported ζ, a routed opened value, or the randomizer disagrees with the machine's cell / word (F2b-2b-ii) | `opened_out` only, on its row |

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

## F2b-2b-i: FRI transcript

F2b-2b-i continues the **same** Fiat–Shamir transcript past F2, through every FRI
challenge the native verifier draws: fri_alpha, one β per commit round, the
query proof-of-work and every query index. It is Fiat–Shamir only. No Merkle
path, reduced opening, fold or final-polynomial evaluation is checked here; those
are 2b-ii/iii. Like 2a, it is a test-only component
(`crates/qlab-bench/src/f2/ood/fri_fs.rs`), scanned row by row and never proved.

### Native order, checked against source

The challenger is `SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256, 32>>`
with the pinned hiding config (`qlab-consensus` `make_config_from`; L2 lane
`L2_CFG_PROVISIONAL` = b4/q43/g22/fp16/a16, `CAP_HEIGHT` 3, rc = 0). In p3-fri 0.6.1:

1. `two_adic_pcs.rs:696-701` observes the opened values (F2), then
   `verifier.rs:195` draws fri_alpha. That flush's digest is D2, which 2a
   already outputs. D2 is this component's public **input**.
2. `verifier.rs:302-311`, per round: `observe(commit)`, then
   `check_witness(commit_proof_of_work_bits, w)`, then β. The lab pins
   `commit_proof_of_work_bits = 0`, and `check_witness` returns before observing
   anything at 0 bits (p3-challenger `grinding_challenger.rs:41-47`). The commit
   witnesses therefore never enter the transcript. Flush G_r = D_{r−1} ‖ cap_r.
3. `verifier.rs:323` observes the final polynomial (16 coefficients × 4 basis
   limbs), `verifier.rs:334-336` every round's log-arity as a base element, and
   `verifier.rs:339` calls `check_witness(22, w)` = observe(w), then
   `sample_bits(22) == 0`. There is no sample between these observations, so they
   form **one** flush: H = D_{R−1} ‖ final poly ‖ arities ‖ w.
4. `verifier.rs:352-353` draws each of the 43 queries with
   `sample_bits(log_global_max_height)`. `TwoAdicFriFolding` adds zero extra bits
   (`two_adic_pcs.rs:106`).

**`sample_bits` is not the field draw.** It pops four bytes (little-endian, the same
positions as a field draw) and keeps the low `bits` bits, with no 31-bit mask and
no rejection. Two consequences follow. The PoW condition is on the **low** 22 bits
of draw 0 of H's digest; the brief's "leading-zero bits" is corrected here to
trailing. And every query index sits at a fixed (digest, draw) position: query i
is draw i + 1 of the stream that starts at H's digest, so the query phase needs no
selection gadget. When a digest's eight draws are spent, the challenger re-flushes
its input buffer, which then holds exactly the last digest (`hash_challenger.rs`
`flush`). Each refill is Q_w = hash(D_{w−1}), one permutation.

**PoW bits.** Query PoW is 22 bits (nonzero), so the gadget is tested at the
native difficulty. Commit-phase PoW is 0 bits in the pinned config, so there is
nothing to constrain there.

### What is bound

- **Sponge.** The same lane and gadgets as 2a, now shared in `lane.rs` (see below).
  The first flush's chaining prefix is pinned to the D2 public limbs (`seed`, row 0,
  where S = 0); every later prefix is pinned by `flush_chain`.
- **Words.** Padding and the log-arities are limb-exact constants. Caps are outer
  public limbs. Final-polynomial limbs are canonical and equal `R⁻¹ · word` in
  held cells, since the Montgomery trap applies to them as it did to the opened
  values. The PoW witness is canonical.
- **Draws.** fri_alpha (from the D2 window, read on G_0's first block) and each β
  use 2a's reject + one-hot selection. PoW is enforced as 22 zero bits. Each index
  bit equals the corresponding draw bit on the window's digest row.
- **Outputs.** Held cells, constant over all rows, carry fri_alpha, every β, the
  final polynomial and every query-index bit, ready for 2b-ii/iii's path
  selection in the same row space. The same values are also public outputs (tied
  on row 0), so a separate component can consume them by public-value equality.
  That is this slice's equivalent of 2a's D2 output: nothing in the native verifier
  observes anything after the query draws, so no later digest is exposed.

**The fold schedule is a shape constant.** p3's verifier accepts any per-round
log-arity in 1..=max whose sum matches the input height. The layout fixes the
schedule the p3 prover commits to (`price::fri_log_arities`, factored out of the
census so both use one function). A proof folded on another legal schedule is
refused. That is a completeness restriction, never a false accept, and the honest
prover never produces such a proof. The honest test asserts the real proof's
arities equal the layout's.

### Reuse

The sponge lane moved from `bind.rs` into `lane.rs`: pad10*1, the absorb loop, the
draw order, `accepted`/`challenge`, the Keccak column map, the periodic sponge
selectors, the phase-range counter, and the constraint gadgets `bits`, `absorb`,
`chain_state`, `flush_chain`, the `< p` comparator, `fs_reject` and `fs_select`.
Each gadget emits the same constraints in the same order as before, so 2a's
group-by-index negatives are unchanged. 2a's tests are untouched except that the
toy AIR, its proof and the native challenger replay through F2 now come from
`lane::toy` (the same code, shared). What each component binds its words to stays
in the component.

### Constraint groups and tests

Seventeen named groups: `keccak`, `bits`, `absorb`, `chain_state`, `flush_chain`,
`seed`, `bind_const`, `bind_cap`, `canonical`, `fs_reject`, `fs_select`, `fs_bind`,
`bind_final`, `pow`, `fs_index`, `hold`, `cells_out`. The fixture is the same toy AIR
at log height 8 (seeded hiding proof on the L2 lane). At 2a's log 4, the LDE of 2^7
folds only once; at log 8, 2^11 folds by 16 and then by 2, which gives two commit
rounds for the swap negative. D2 comes from 2a's own `Replay` of the same proof,
which exercises the seam between the two components.

Every negative scans **all** rows and asserts that every violation is in the named
group, on the named rows (stricter than 2a's single-row check):

| negative | refused at |
|---|---|
| wrong fri_alpha limb, exposed consistently | `fs_bind` only, D2 row |
| β_0 takes the fifth accepted draw (skip) | `fs_select` only, G_0 digest row |
| round caps absorbed in swapped order; betas, PoW (re-ground by the p3 challenger) and indices all consistent | `bind_cap` only, G_0/G_1 rows |
| transcript absorbs a forged final-poly coefficient, the query phase gets the honest one; PoW re-ground, indices replayed | `bind_final` only |
| final-poly word encoded as `word + p` | `canonical` on its row, plus `pow` on the window row (not re-ground: the native challenger cannot absorb a non-canonical word) |
| PoW witness failing the 22-bit condition, indices replayed from it | `pow` only (the p3 `check_witness` refuses it too) |
| one query-index bit flipped, cells and public index consistent | `fs_index` only |
| a query takes another query's index, transcript untouched | `fs_index` only |
| queries 7.. each take the next draw (skip) | `fs_index` only |

**Scope boundary, asserted.** A final polynomial that the transcript absorbs and
exposes consistently, with PoW re-ground, is **accepted** by this component. Nothing
in Fiat–Shamir can refuse it; 2b-iii's final-polynomial evaluation must. The test
asserts this, so the boundary cannot silently move.

The honest test cross-checks the replay against the native p3 challenger, driven
through the verifier's own observation order. It checks fri_alpha (from 2a's D2),
both betas, and that the proof's PoW witness passes `check_witness(22)` at that
point. A wrong message order through H would pass only by a 2⁻²² coincidence, so
this anchors the order independently of the replay. It also checks all 43 query
indices, the shape (arities [4, 1], two commits and witnesses, 16 coefficients,
43 queries, 11 index bits, six windows), a full SAT scan, and maximum constraint
degree ≤ 3 **[P, guarded in CI]**.

### Dimensions

**[P, source-derived]** For the toy (log 8, R = 2): the flushes are G_0, G_1 (3
permutations each: 8 + 64 words), H (3: 8 + 64 + 2 + 1), and six refills of one
permutation each, 15 permutations in all (360 rows → height 512). Width = 2,633
(Keccak) + 2 × 1,088 (M, S) + 68 (canonicity) + 72 (field draws) + held cells
4(R+1) + 64 + 43 · 11 = 549, giving 5,498. Public values: 16 (D2) + 128R (caps) +
4(R+1) + 64 + 43 = 391.

At shape P (log 20, LDE 2^23): arities [4, 4, 4, 4, 1], so R = 5, 23 index bits,
and 5 × 3 + 3 + 6 = 24 permutations. This matches the census `fs_floor` FRI terms
(R × blocks(32 + cap) + blocks(final ‖ arities ‖ witness) + 5 refills), plus one
permutation. The extra one is the tail refill whose first block carries the last
window's digest bits: a layout cost of reading draws off a successor's M bits, not
a transcript cost. Held cells: 24 + 64 + 43 · 23 = 1,077.

### Not yet bound (2b-ii/iii)

Input and commit-phase Merkle paths, salted leaves, the reduced opening, the folds
(sibling values, β powers) and the final-polynomial evaluation at each query. A
fri_alpha or β window that needs a refill (more than eight field draws, about 1e-9
per challenge) is unsatisfiable. As in 2a, that is a completeness gap and never a
false accept. `pcs_input_bindings_complete`, `full_ood_air_checked`,
`complete_verifier_layout` and `memory_gate_pass` stay **false**.

### Validation

No local tests, proofs or benchmarks were run. The local preflight was
`cargo check --workspace --all-targets`, Clippy on `qlab-bench` (no findings in
`f2/`) and rustfmt; `verify-graviton` CI is the acceptance gate. The slice adds six
tests in `fri_fs.rs` and no others. **[P, pending CI]**: 2769 + 6 = 2775 passed,
0 failed, 15 ignored, reconciled against 2a's acceptance run 36325459774 (main has
not moved since).

Expected new-test runtime **[P]** is 15–40 s on the Graviton lane. It is dominated
by one toy hiding proof at log 8 (including its own 22-bit grind) and two native
22-bit re-grinds (expected 2²² Keccak-256 absorbs each, rayon-parallel). The rest
is about ten 512 × 5,498 traces, one parallel SAT scan, about nine full-trace
violation scans (512 rows each) and one symbolic degree pass. 2a's six tests now
share the lane code and should not change in cost.

Unverified, most likely to break first:

1. The native cross-check itself: the replay's H message order and the refill
   semantics against the p3 challenger (caught by the honest test's `check_witness`
   and index assertions).
2. The fixture's fold schedule: `[4, 1]` assumes every hiding input is committed
   at 2N rows. If a quotient chunk committed lower, the p3 prover would fold to it
   first and the arity assertion fails.
3. The refactor of 2a's gadgets into `lane.rs`: constraint order within a group is
   preserved by construction, but 2a's negatives are the only check.
4. A seed-dependent assumption in a negative: β_0's window must hold at least five
   accepted draws (it fails with probability about 3·10⁻⁷, and deterministically for the fixed seed).

## F2b-2b-ii: input openings

F2b-2b-ii checks, for each FRI query, the three input batches the verifier opens at
the query index, in circuit. That covers the salted leaves, the Merkle paths up to the
committed caps, and the reduced opening the query hands to the first fold. Folding and
the final polynomial are 2b-iii. Like 2a and 2b-i, it is a test-only component
(`crates/qlab-bench/src/f2/ood/open.rs`), scanned row by row and never proved. It adds
no inner-proof claim of its own: every value it authenticates is either a public
input exported by 2a or 2b-i, or a word it hashes into one of those caps.

### Native facts, checked against source

All line numbers are p3 0.6.1 unless stated otherwise.

- **Batch order and points.** uni-stark `verifier.rs:453-510` hands the PCS three
  claims, in order: the randomizer (one matrix, 4 columns, opened at ζ), the trace
  (one matrix, w columns, opened at ζ and at ζ·g_N, where g_N generates the
  *original* N-row domain), and the quotient (8 chunk matrices, 4 columns each,
  opened at ζ). `open_input` walks them in that order (`verifier.rs:640-753`).
- **One height.** The hiding PCS commits every input at 2N rows. `hiding_pcs.rs`
  `commit` (lines 105-131) interleaves the trace with random rows, `get_quotient_ldes`
  (lines 168-256) extends each size-N chunk by `log_blowup + 1`, and the randomizer
  is drawn on the 2N domain (lines 438-458). All matrices therefore sit at
  2^lde rows, with lde = log N + 1 + log_blowup (11 for the toy, 22/23/21 for S/P/R).
  The reduced index is the query index itself (`verifier.rs:687-691`), and there is
  a single reduced opening per query.
- **Leaf serialization.** `hiding_mmcs.rs:169-176` appends each matrix row's
  4-element salt. `mmcs/batch.rs:200-206` hashes every same-height row as one stream,
  row ‖ salt per matrix in matrix order (`hash_iter_slices` flattens,
  `hasher.rs:24-30`). The hasher is `SerializingHasher` over
  `PaddingFreeSponge<KeccakF, 25, 17, 4>` (`qlab-consensus` `lib.rs:58-61`). Field
  elements become their Monty words, packed two per u64 with the low word first,
  and an odd last word stands alone (`p3-field integers.rs:494-507`). The sponge
  **overwrites** the 17 rate lanes of each block. It does not xor them, which is
  unlike the challenger's pad10*1 Keccak. A short final block keeps the previous
  output in its tail lanes, and the digest is lanes 0..3 (`sponge.rs:172-204`).
- **Path.** `CompressionFunctionFromHasher<_, 2, 4>` is one fresh sponge
  permutation over left ‖ right (8 u64) (`compression.rs`). Level t reads bit t of
  the index, current digest on the left when the bit is 0 (`mmcs/batch.rs:210-235`).
  The schedule is binary, and the top `CAP_HEIGHT` = 3 levels are stripped into the
  cap (`mmcs/mod.rs:262-297`). The cap entry is `index >> path`, with
  path = lde − 3.
- **Reduced opening** (`verifier.rs:706-753`). x = GENERATOR ·
  ω_lde^{rev_lde(index)} (bit-reversed index, domain shift = the field generator).
  For each matrix, each point and each column,
  ro += α^k · (p(z) − p(x)) / (z − x), with k a single running counter across all
  three batches (one height, so one counter). z = x is an error (`try_inverse`);
  here it is an unsatisfiable inverse.

### What is bound

- **Sponge, overwrite mode.** The same stock Keccak lane. The M bits of a
  permutation's step-0 row **are** its rate preimage. There are no S bits, since
  nothing is xored in. The capacity carries into an interior leaf block and is zero
  into every other permutation. Leaf words are of four kinds: row values (canonical
  Monty words, `R⁻¹ · word` accumulated), salts (free witness words, hashed and
  nothing else), zeros, and carried tail lanes (equal to the previous output).
- **Path.** On the row that feeds level t, the digest just produced must sit in the
  left child half when the query's index bit t is 0, and in the right half when it
  is 1. The other half is the sibling and is free. The final digest equals the cap
  entry that a one-hot of the top three index bits selects. The caps are 2a's cap
  public values, limb for limb.
- **Reduced opening.** Two running sums over the query's leaf rows collect
  α^k · v, one for the ζ terms (Ax) and one for the ζ·g_N terms (Bx). At the
  segment's last row, ro = (Az − Ax)·inv_A + (Bz − Bx)·inv_B, with
  (ζ − x)·inv_A = 1 and (ζ·g_N − x)·inv_B = 1 as extension products. Az and Bz
  (Σ α^k z_k) and the α powers are computed once per instance in held cells. x is a
  chain of constant factors, one per index bit: bit t multiplies by ω^{2^{lde−1−t}},
  which is exactly the bit-reversal. Every constraint has degree ≤ 3.
- **Outputs.** The per-query reduced openings are held cells (constant over all
  rows) and public outputs, for 2b-iii.

**Uniform layout.** Every query runs the same segment of permutations: randomizer
leaf, randomizer path, trace leaf, trace path, quotient leaf, quotient path. The
per-query values (index bits, cap one-hot, x chain, inverses, ro) are per-row
registers, bound to that query's public index by a segment selector. Periodic
columns therefore scale with leaf roles, levels and queries, not with permutations
(22 for the toy; 96 for S at 43 queries).

### Composition with 2a and 2b-i

The F2b pieces are separate AIRs joined by public values, the same seam 2a's D2
already uses. For this slice, **2a gains one group, `opened_out`**. It exports ζ and
every opened value as public outputs, **from the machine's own cells**. A value the
machine reads leaves from the held input column the machine reads (first row; held
constant). The randomizer opening, which the machine never reads, leaves from its
transcript word (`R⁻¹ · word` on its step-0 row). 2b-i already exports fri_alpha and
the indices. Here those values are public **inputs**, tied to held cells on row 0
(`opened_in`) and to the per-row index bits (`index`). The z-values FRI reads are
therefore the machine's, by an equality on each side of one public value. No second
copy exists that could disagree:

- a z-value handed to FRI that differs from 2a's export: `opened_in`, row 0 (here);
- an export that differs from the machine's cell or word: `opened_out`, on its row
  (in 2a).

The seam test compares the three components' public values slice by slice: caps,
ζ and z-values against 2a's exports of the same proof at log 8, and fri_alpha and
the covered indices against 2b-i's.

### Constraint groups and tests

Twenty named groups: `keccak`, `bits`, `absorb`, `capacity`, `bind_zero`,
`bind_carry`, `bind_child`, `cap`, `canonical`, `accumulate`, `opened_in`, `index`,
`cap_select`, `x_point`, `inverse`, `alpha_pow`, `z_sum`, `reduce`, `hold`,
`ro_out`. The fixture is 2b-i's: the same seeded log-8 toy proof, built once per
test binary, with its indices and fri_alpha. The instance covers two queries whose
cap entries differ. Every negative scans **all** rows and asserts the exact set of
(row, group) violations:

| negative | refused at |
|---|---|
| a salt changed | `cap` only, that batch's cap row |
| a row value changed, a fresh salt chosen, ro re-derived consistently | `cap` only (the leaf is canonical and self-consistent, so nothing refuses it earlier, and nothing lets it through) |
| two siblings swapped | `cap` only |
| child placed on the wrong side, index bit untouched | `bind_child` at that level's feed row, plus `cap` |
| an index bit flipped, placement, x and ro following it | `index` on every row of the segment, plus `cap` on all three batches |
| wrong cap entry selected | `cap_select` on the query's register rows, plus `cap` on all three batches |
| a z-value handed to FRI ≠ 2a's export, Az/ro re-derived (a trace value the machine reads, and the randomizer) | `opened_in` only, row 0 |
| x from the index **without** bit reversal, inverses and ro re-derived | `x_point` only, on the query's register rows |
| a reduced opening poked (held cell and output agreeing) | `reduce` only, the segment's last row |

In 2a, the new negative pokes the exported ζ, a routed opened value and a
randomizer value. Each is refused by `opened_out` alone, on its row. The ζ-digest
row and the terminal row stay clean.

**Native cross-checks** (honest test), for **all 43** queries, not only the two
covered:

- p3's own hiding MMCS (`verify_batch`) accepts each batch's opening at the
  full index;
- the lab's native replay of leaf hashing and path reaches the same cap entry;
- a sequential replica of `open_input`, fed from the proof's opened values in
  uni-stark's order, equals the grouped (Az − Ax)/(ζ − x) + … form the circuit
  computes;
- that value **is** what FRI folds: inserted at `index % 16` among round 0's
  sibling values, p3's commit-phase MMCS accepts the row. This pins the reduced
  opening to the committed codeword, independently of both replicas.

The honest test also runs a SAT scan and checks that the held and public reduced
openings equal the native ones, that the maximum constraint degree is ≤ 3
**[P, guarded in CI]**, and that the toy layout matches `price::input_openings`
(width, height, periodic and public-value counts).

### Dimensions **[P, source-derived]**

Toy (w = 2, log 8, lde 11, path 8, 40 opened terms, 2 queries): per query,
1 + 1 + 2 leaf permutations (8, 6 and 64 elements) + 3 × 8 compressions = 28, giving
56 permutations, 1,344 rows, height 2,048. Width 4,187 = 2,633 (Keccak) + 1,088 (M) +
68 (canonicity) + 8 (accumulators) + 46 (registers, 2·lde + 24) + 344 (held,
16 + 8·40 + 4·2). There are 22 periodic columns and 562 public values.

`f2price` now reports `input_openings` per shape at 43 queries (`price::input_openings`,
pinned by `input_openings_split_the_census`):

| shape | leaf / compress per query | perms per query | leaf / compress × 43 | lane rows (padded) | opened terms | columns | periodic | PVs |
|---|---|---|---|---|---|---|---|---|
| S (w 721, lde 22) | 25 / 57 | 82 | 1,075 / 2,451 | 84,624 (2^17) | 1,478 | 15,877 | 96 | 6,519 |
| P (w 798, lde 23) | 27 / 60 | 87 | 1,161 / 2,580 | 89,784 (2^17) | 1,632 | 17,111 | 99 | 7,135 |
| R (w 734, lde 21) | 25 / 54 | 79 | 1,075 / 2,322 | 81,528 (2^17) | 1,504 | 16,083 | 95 | 6,623 |

**Census cross-check.** Add the FRI commit-phase share (S: 8 leaf and 36 path
permutations per query) to the input share, and S at 43 queries gives
1,075 + 344 = **1,419** leaf and 2,451 + 1,548 = **3,999** path permutations. These
are the census's measured numbers. The test asserts the same split against the census
geometry for all three shapes.

**Reduced-opening arithmetic.** Per query: one extension-by-base product per opened
term (1,478 at S), lde base products for x, two inverse checks and two extension
products. Per instance: terms − 1 extension products for the α powers, and terms for
Az/Bz.

**A layout finding, not a fix.** At L2 widths the dense held tables (α powers and
z-values, 8·terms columns) dominate the width: 11.8k of S's 15.9k columns. A
production layout would keep those tables in rows and index them with a periodic
column, instead of spreading them across width. The count is stated so the lever is
visible; it is not implemented here.

### Not yet bound (2b-iii)

The commit-phase openings (sibling values, FRI Merkle paths), the folds with β, and
the final-polynomial evaluation. The reduced openings are exposed for that component.
`pcs_input_bindings_complete` stays **false** until 2b-iii consumes them, and so do
`complete_verifier_layout` and `memory_gate_pass`.

### Validation

No local tests, proofs or benchmarks were run. The local preflight was
`cargo check --workspace --all-targets --locked`, Clippy on `qlab-bench` (no findings
in `f2/`) and rustfmt. `verify-graviton` CI is the acceptance gate. New tests: five
in `open.rs`, one in `bind.rs` and one in `price.rs`, seven in all. **[P, pending
CI]**: against 2b-i's pending total of 2,775, that is 2,782 passed, 0 failed,
15 ignored.

Expected new-test runtime **[P]** is 10–40 s on the Graviton lane. The proof is
shared with 2b-i's fixture (one per test binary). The rest is 2a's export replay at
log 8, native MMCS and fold checks for 43 queries, about twelve 2,048 × 4,187
traces, one parallel SAT scan, about eleven parallel full-trace violation scans, and
one symbolic degree pass.

Unverified, most likely to break first:

1. The leaf serialization and overwrite semantics, as reproduced in the lab's
   native `Walk` (odd-word packing, the carried tail lanes of the quotient leaf's
   second block). The honest test's root-equals-cap assertion and p3's
   `verify_batch` catch a mismatch.
2. The reduced-opening grouping and term order against the sequential native form,
   and both against the fold. The round-0 commit-phase check is the independent
   anchor.
3. Exact (row, group) sets in the negatives. A negative that trips an extra group
   (for example a padding-row register, or `hold` on a poked held cell) fails loudly
   rather than passing silently; the fix would be to name the extra row, not to
   weaken the assertion.
4. The hand-derived S/P/R counts in the table: `input_openings_split_the_census`
   pins them, so an arithmetic slip fails CI.
