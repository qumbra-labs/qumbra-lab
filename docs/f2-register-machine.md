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
| fri_alpha ≠ 2b-i's export, α powers, Az/Bz and ro re-derived | `opened_in` only, row 0 |
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
*(2b-iii, below, now binds all three; what that does and does not make complete is
stated in its "What remains" paragraph.)*

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

## F2b-2b-iii: FRI folding

F2b-2b-iii is the FRI query phase, in circuit. For each covered query it
authenticates every commit round's salted leaf against that round's cap, checks
that the running value is the committed entry at the query's position, folds the
group at the round's β, and finally requires the final polynomial, evaluated at the
final point, to equal the last folded value. Like the earlier slices, it is a
test-only component (`crates/qlab-bench/src/f2/ood/fold.rs`), scanned row by row and
never proved. Its public inputs are other components' public outputs: the
commit-phase caps, every β, the final polynomial and the indices from 2b-i, and the
reduced openings from 2b-ii.

### Native facts, checked against source

p3 0.6.1, `p3-fri` unless stated otherwise.

- **Order of one query** (`verifier.rs:448-584`, `verify_query`). The chain starts
  from the reduced opening at the global max height (`verifier.rs:470-480`). For
  each round: `index_in_group = index % arity` on the index already shifted by the
  earlier rounds (`508`); evals = the siblings with the running value inserted at
  that position, siblings filling the other slots in order (`509-517`); the index
  shifts by the round's log-arity (`529`); the commit-phase MMCS checks evals at the
  shifted index (`531-541`); then `fold_row` (`543-549`). In circuit terms: round r
  reads query-index bits S_r..S_r+a for the position and bits S_{r+1}.. for the path
  and the fold point, with S_r the sum of the earlier arities.
- **Reduced-opening injection** (`verifier.rs:554-565`). After a fold, native adds
  β^arity · ro for an input committed **at the folded height**. The hiding config
  commits all three batches at one height (2b-ii), so the only reduced opening is
  the starting one: nothing is rolled in later, and the component asserts no
  other height exists by construction (one `ro` per query).
- **Fold formula** (`two_adic_pcs.rs:110-133`, `lagrange_interpolate_at`
  `221-258`). The interpolant at β of the arity-n group at
  xs[i] = s · ω_n^{rev_a(i)} (bit-reversed), s = ω_{h+a}^{rev_h(index′)}, where
  index′ is the shifted index and h the folded log-height. Barycentric, with an early
  return when β equals an x; the interpolant has that value there too, so the two
  agree everywhere.
- **Final point** (`verifier.rs:394-410`). x = ω_lde^{rev_lde(index >> S_R)}, **no
  coset shift** (unlike the input point x = GENERATOR · …). Horner over the final
  polynomial, highest coefficient first, must equal the last folded value.
- **Commit-phase leaves are salted.** `ChallengeMmcs = ExtensionMmcs<Val, E, ValMmcs>`
  (qlab-consensus `lib.rs:90`), and `ValMmcs` is the hiding MMCS. `ExtensionMmcs`
  flattens the n evals to 4n base limbs in basis order (`extension_mmcs.rs:77-82`),
  and `hiding_mmcs.rs:175` appends `SALT_ELEMS` = 4 salt. Sponge, packing and path
  are exactly the input MMCS's (2b-ii). For arity 16 the leaf is 68 words, which is
  exactly two overwrite blocks; for arity 2 it is 12 words in one block; for R's
  last round (arity 8) it is 36 words, so its second block carries tail lanes.

### What is bound

- **Leaves and paths**, reusing 2b-ii's gadgets and leaf-word layout. A leaf's row
  words are canonical Monty words equal to R · G for the round's group registers G
  (`leaf_bind`); salt words are free. Each level's child sits left or right by the
  **same** index-bit cells the index binding pins; the cap entry is always the top
  three index bits (S_{r+1} + path_r = lde − 3), so the cap one-hot is shared with
  2b-ii's form. Each round's root equals the selected entry of **that round's**
  commit-phase cap, taken from the public caps 2b-i absorbs.
- **Position.** A one-hot over bits S_r..S_r+a, built one level per bit (degree 2
  per cell). The selected group entry equals the running value (`select`).
- **Fold, as an inverse DFT.** p(β) = Σ_k d_k u^k, where
  d_k = n⁻¹ Σ_i ω_n^{−rev_a(i)·k} G[i] (base constants, linear in G) and
  u = β · s⁻¹. s⁻¹ is a product of **constant** factors ω_{h+a}^{−2^{h−1−t}}
  selected by the index bits, so **there is no inverse witness anywhere in this
  component**: 1/n is a constant and s⁻¹ is a constant-factor chain. The powers
  u^k are cells, each u^{k+1} = u^k · u.
- **Final polynomial.** x is a constant-factor chain on bits S_R..lde−1; Horner
  cells h_k = h_{k+1} · x + c_k over the held final polynomial; h_0 equals the last
  folded value (`final`).
- **Registers.** Each query's registers are constant over its segment
  (`ctx_hold`), so the group bound on a leaf's step-0 rows is the group every row
  folds. Every constraint has degree ≤ 3 **[P, guarded in CI]**.

### Composition with 2b-i and 2b-ii

β and the final polynomial are held cells bound to their public inputs on row 0
(`inbound`). The index bits and the chain's starting value are pinned on every row
of the query's segment (`index`, `ro_in`). 2b-i's `fri_transcript_rejects_final_poly_forgeries`
shows that a final polynomial absorbed and exported consistently is transcript-valid;
this component is where it is refused. The seam test compares the public values slice
by slice: caps, β, final polynomial and indices against 2b-i's public values of the
same proof, the reduced openings against 2b-ii's outputs.

### Constraint groups and tests

Twenty-four named groups: `keccak`, `bits`, `absorb`, `capacity`, `bind_zero`,
`bind_carry`, `bind_child`, `cap`, `canonical`, `leaf_bind`, `index`, `cap_select`,
`position`, `ro_in`, `select`, `s_inv`, `fold_pow`, `fold`, `final_x`, `horner`,
`final`, `inbound`, `hold`, `ctx_hold`. The fixture is 2b-i's and 2b-ii's: the same
seeded log-8 toy proof, the same two covered queries. Every negative scans **all**
rows and asserts the exact (row, group) set:

| negative | refused at |
|---|---|
| a commit-phase salt changed | `cap` only, that round's cap row |
| two sibling entries poked so the fold is **unchanged** (w_i·δ_i + w_j·δ_j = 0; p3's `fold_row` agrees), a fresh salt | `cap` only, round 0's cap row |
| two siblings swapped, chain re-derived | `cap` on rounds 0 and 1, plus `final` on the query's rows |
| round 1 read with round 0's index shift (position, path, s⁻¹ and fold re-derived) | `position` / `s_inv` where the mis-shifted bits differ, `bind_child` at each level whose side moves, `cap` if the root moves, `final` |
| round 1 folded with round 0's β, powers and fold consistent | `fold_pow` and `final`, on the query's rows |
| the value between rounds poked | `fold` and `select`, on the query's rows |
| the chain not started from 2b-ii's reduced opening | `ro_in` only, the query's segment |
| ro rolled in again after round 0 (native's second-height injection) | `fold` and `final` on the query's rows, plus round 1's `cap` |
| a final-polynomial coefficient forged consistently (the forgery 2b-i accepts) | `final` only, every row |
| a middle cell of the final-x chain poked, index untouched | `final_x` only, the query's rows |
| index bit S_R (the final x's first bit) flipped in the registers alone | `index` on the segment; `final_x` and `s_inv` on the query's rows (both rounds' s⁻¹ read that bit); `bind_child` at the two levels that read it |

For the index-shift negative the expected set is computed from the query's own index
bits, and the test asserts the shift moves at least one bit; the root check uses the
native replay.

**Native cross-checks** (honest test), for **all 43** queries: p3's commit-phase
MMCS (`verify_batch`) accepts every round's group at the shifted index; p3's own
`fold_row` chain, started from 2b-ii's native reduced opening, ends at the value of
the final polynomial at the final point (the check `verify` performs); the circuit's
replica (inverse-DFT folds, constant-chain s⁻¹ and x, the lab's Merkle replay)
reaches the same values, the same Horner result and the same cap entries. The toy
proof itself passed `p3_uni_stark::verify` when it was built. The honest test also
runs a SAT scan, checks degree ≤ 3 and pins the toy layout to `price::query_phase`.

**The production schedule on a real S3 proof.** The toy folds on `[4, 1]` (two
rounds). A second test runs the AIR on the real hiding S3 proof's schedule — four
rounds of arity 16, paths 15/11/7/3, 4,096 rows — for 2 of its 43 queries. It takes
the census test's S3 proof (`f2::s3_fixture`, now a `OnceLock` both tests share, so
CI still proves S3 once per test binary), replays FRI with p3's own challenger and the
reduced openings with 2b-ii's sequential replica, checks p3's commit-phase MMCS,
`fold_row` chain and final check against the circuit replica, runs a SAT scan, and
refuses a value poked between rounds with exactly `fold` + `select` on the query's
rows.

### Dimensions **[P, source-derived]**

Toy (lde 11, arities 16 then 2, paths 4 and 3, final domain 2^6, 16 coefficients,
2 queries): per query 2 + 4 + 1 + 3 = 10 permutations, 20 in all, 480 rows, height
512. Width 4,147 = 2,633 (Keccak) + 1,088 (M) + 68 (canonicity) + 286 (registers) +
72 (held: 2 β + 16 coefficients). There are 15 periodic columns and 338 public
values.

`f2price` now reports `query_phase` per shape at 43 queries (`price::query_phase`,
pinned by `query_phase_splits_the_census`):

| shape | arities | leaf / compress per query | leaf / compress × 43 | lane rows (padded) | columns | periodic | PVs |
|---|---|---|---|---|---|---|---|
| S (lde 22) | 16, 16, 16, 16 | 8 / 36 | 344 / 1,548 | 45,408 (2^16) | 4,657 | 74 | 807 |
| P (lde 23) | 16, 16, 16, 16, 2 | 9 / 43 | 387 / 1,849 | 53,664 (2^16) | 4,690 | 77 | 939 |
| R (lde 21) | 16, 16, 16, 8 | 8 / 33 | 344 / 1,419 | 42,312 (2^16) | 4,573 | 74 | 807 |

**Census cross-check.** S at 43 queries gives **344** leaf and **1,548** path
permutations, the census's measured FRI share (1,419 − 1,075 and 3,999 − 2,451). The
test asserts, for all three shapes, that the input share plus this share is the
census geometry's per-query count.

**Fold arithmetic per query** at arity 16: 29 extension products (u² … u¹⁵ and
Σ d_k u^k), 17 extension-by-base products (u and the position select), the
inverse-DFT combinations (linear, constant coefficients), h base products for s⁻¹;
then 6 base products for x and 15 Horner steps. No inverse witness.

### What remains

2a + 2b-i + 2b-ii + 2b-iii now cover every check the native hiding PCS verifier
makes for one leaf proof, **each in its own AIR**, but they are not yet one verifier:

1. **Composition.** The four components meet only through public values, and the
   equalities between them (D2; caps, ζ, z-values; fri_alpha, β, final polynomial,
   indices; reduced openings) are checked by the test harness, not by a circuit.
   A complete single-leaf verifier needs either one circuit containing all four
   or an explicit seam-check component whose constraints force those equalities.
2. **Query coverage.** The instances cover 2 of 43 queries. Constraint satisfaction
   with all 43 queries at the full S3 size is an F2b-4 acceptance item.
3. **The quotient identity and periodic evaluation** (`full_ood_air_checked`) and
   R-PV are F2b-3 items, untouched here.

`pcs_input_bindings_complete`, `full_ood_air_checked`, `complete_verifier_layout`
and `memory_gate_pass` therefore stay **false**: none of them is literally true of
the code, because nothing yet forces the seams.

### Validation

No local tests, proofs or benchmarks were run. The local preflight was
`cargo check --workspace --all-targets --locked`, Clippy on `qlab-bench` (no findings
in `f2/`) and rustfmt. `verify-graviton` CI is the acceptance gate. New tests: eight
in `fold.rs` and one in `price.rs`, nine in all. **[P, pending CI]**: against 2b-ii's
pending total of 2,782, that is 2,791 passed, 0 failed, 15 ignored.

Expected new-test runtime **[P]** is 5–30 s on the Graviton lane for the toy tests.
The proof and the 2a export are shared with 2b-i's and 2b-ii's fixtures (one per test
binary). The rest is 43 native query chains (two MMCS checks and two `fold_row` each),
about twelve 512 × 4,147 traces, one SAT scan, about twelve parallel full-trace
violation scans, and one symbolic degree pass. The S3 test adds **no prove**: the S3
proof (≈ 26 s, ≈ 14 GiB peak on the rig, ≈ 2.7× the time on Graviton) was already
built once by the census test and is now shared. Its own work is an FS replay, two
reduced openings, two 4,096 × 4,657 traces (~76 MB each), one SAT scan and one
violation scan: **≈ 5–20 s, < 1 GiB above the shared proof [P]**. Whichever of the two
tests runs first pays for the prove.

Unverified, most likely to break first:

1. The inverse-DFT fold against `fold_row`, in particular the bit-reversed sibling
   order and the s⁻¹ exponent. The toy test compares both for all 43 queries, but
   only on the toy's `[4, 1]` schedule. On the production schedule (four rounds of
   arity 16) the comparison, the satisfaction check and one negative cover **2 of the
   43 queries of one S3 proof**; P3's arity-2 fifth round and R's arity-8 last round
   (the only carry-lane leaf) are exercised only through `price::query_phase`'s
   counts, never through the AIR.
2. Exact (row, group) sets, above all the cascading ones (sibling swap, index shift,
   roll-in). An extra group fails loudly; the fix is to name the extra row, not to
   weaken the assertion.
3. The commit-phase leaf serialization (extension limbs in basis order, then salt).
   p3's `verify_batch` and the root-equals-cap assertion catch a mismatch.
4. The hand-derived S/P/R column, periodic and PV counts: the census-split test pins
   them.

## F2b composition C1: transcript, machine and FRI transcript on one lane

Slice 1 of the composition the coordinator recorded on issue #750 ("F2b composition:
two proofs per leaf"). p3 0.6.1 proves a single table, so the four F2b components
become two proofs per leaf. **C1** is 2a (the uni-stark transcript and the register
machine) plus 2b-i (the FRI transcript) as one AIR on one duplex Keccak lane, with
lever **L1**. C2 (2b-ii + 2b-iii) is the next slice. C1 is a test-only component
(`crates/qlab-bench/src/f2/ood/c1.rs`), scanned row by row and never proved. The four
merged components and their tests are unchanged; they remain the regression baseline.

### One lane, one transcript

The flushes run back to back: F0 → α, F1 → ζ, F2 (the opened values) → fri_alpha, then
per commit round G_r → β_r, then H (final polynomial, arities, PoW witness) → PoW and
the query windows, then the refills. Every word order is the one 2a and 2b-i already
pinned against p3 source. **D2 is now internal**: F2's last permutation hands its
digest to G_0's first block through the same `flush_chain` equality every other flush
uses. Nothing about D2 is public, and the 2a→2b-i seam disappears. The honest test
asserts that the lane's F2 digest equals 2a's replay and that fri_alpha, every β and
every index equal 2b-i's outputs for the same proof.

The machine is 2a's, unchanged: held input cells, bound to their transcript words, to
the inner PVs and to the α/ζ draws. The residual is pinned to 0 and the next point to
g_N·ζ on the last row.

### Scheduling: no full-period selectors in the transcript

2a and 2b-i gated every binding with one full-period periodic column per permutation,
plus two sponge columns. The next recursion level evaluates each periodic column at
ζ, so it pays columns × period for them. C1 schedules from the main trace instead, as
m4gate does:

- **Keccak's `step_flags`**, the period-24 ring p3-keccak-air already constrains, give
  each permutation's step-0 row and last row.
- A **perm ring**: one main column per lane permutation, 1 on all 24 rows of the
  permutation it names. The first row holds perm 0, and each permutation's last row
  hands the token on (`ring`). After the last permutation the ring is empty. The ring
  is fully determined by the Keccak flags.

A binding gated by ring cell P_p holds on all 24 rows of permutation p, so the prover
**replicates** that permutation's message and state bits, canonicity witnesses and
draw witnesses on those rows. This keeps every gate at degree 1, the degree the
periodic selectors had. It is sound for the same reason as before: the replicated rows
include the step-0 row, where `absorb` ties the bits to the permutation input. The
chain gates multiply by Keccak's last-row flag. **The only periodic columns left are
the machine ROM's.** They are still full-period: lever L5, not done here, is what would
remove them. Their price is below.

### L1: Az and Bz on the absorb rows

Native `open_input` (p3-fri `verifier.rs:706-753`) weights opened value k by
fri_alpha^k. One counter runs across the randomizer, the trace at ζ and then ζ·g_N,
and the quotient chunks, and that is exactly F2's absorb order (2b-ii's `Geom::term`
and its test pin it). So Az = Σ α^k z_k over the ζ-point terms and Bz, the same sum over
the ζ·g_N terms, are running sums over F2's blocks:

- A block's 34 words cover at most nine terms (j = 0..8). F2 opens with eight chain
  words and 34 ≡ 2 (mod 4), so **even** blocks start on a term boundary (slot s → term
  j = s/4, limb s mod 4). **Odd** blocks start on limb 2 of the term the previous block
  cut: j = (s+2)/4, limb (s+2) mod 4. Two slot maps cover every block. Block 0 is the
  even map with term −2 at j = 0; D1's words sit there, and the masks drop them. The
  maps are checked against the layout when the AIR is built, not trusted.
- Per row, q_j = α^{k0+j}: nine extension cells with q_{j+1} = q_j·α and T = q_8·α.
  q_0 steps on each F2 permutation's last row: to q_8 after an even block (the next
  block resumes the cut term) and to T after an odd one. The anchor q_2 = 1 on F2's
  first block fixes k0 = −2 there (`alpha_chain`).
- pA_j and pB_j are q_j masked by the static point of term k0 + j. They are zero for
  D1's words, for padding and for the other point. The masks are ring sums, so each
  cell is a degree-2 equality (`mask`).
- On each F2 step-0 row, Az += Σ_s pA_{j(s)}·e_{l(s)}·(R⁻¹·word_s), and Bz accumulates
  the same way from pB. Two materialized gates, step-0 ∧ even block and step-0 ∧ odd
  block, keep the update at degree 3 (`gate`, `accumulate`).

This removes C2's 5,912-column α-power and z-value table (S3). The C1→C2 seam carries
Az and Bz (8 values) instead of the 1,478 opened values.

**Why accumulating before fri_alpha is drawn is sound.** fri_alpha is drawn from D2,
**after** the opened values are absorbed, but the sums on F2's rows need it. α lives in
a **held** cell: one value on every row (`hold`), equal to the draw on G_0's first block
(`fs_bind`). Holding makes the α used on F2's rows and the α drawn from D2 the same
cell, so the sums computed on earlier rows use the drawn value. Nothing is circular.
The trace is a static witness, and every constraint is an equality between cells the
prover fixes at once. The draw is a function of D2, D2 is a function of the absorbed
words, and Az and Bz are functions of those same words and that same α. A prover who
puts α′ on F2's rows and the drawn α on the draw row breaks `hold` at the one row
where the cell changes. The negative below shows exactly that.

### The seam C1 exports

`Seam` in `c1.rs` is the C1→C2 seam as values, and `Seam::read` is the
`check_seams`-ready accessor over C1's public values. The inputs are the inner PVs and
every cap (trace, quotient, randomizer, then each commit round), which bind the
absorbed words. The outputs are ζ (from the machine's held cell), fri_alpha (the held
cell), Az and Bz (the accumulators on the last row), every β, the final polynomial and
the 43 query indices. Each is bound on its own draw row or word row, with no held copy.
That is 16 + 4R + 64 + 43 values: 139 at S3. The opened values are **not** exported,
because C2 needs only ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x). The honest test
checks exactly that split for **all 43 queries** against 2b-ii's sequential
`open_input` replica.

### Constraint groups and tests

Twenty-seven named groups: `keccak`, `bits`, `absorb`, `ring`, `chain_state`,
`flush_chain`, `bind_const`, `bind_cap`, `bind_inner_pv`, `canonical`, `fs_reject`,
`fs_select`, `fs_bind`, `bind_final`, `pow`, `fs_index`, `bind_opened`, `in_public`,
`hold`, `machine`, `machine_out`, `alpha_chain`, `mask`, `gate`, `accumulate`,
`cells_out`, `az_out`. Every constraint has degree ≤ 3; the honest test checks this on
the symbolic builder. The fixture is 2b-i's seeded log-8 toy proof (two FRI rounds),
shared with 2b-ii and 2b-iii. Every negative scans **all** rows and asserts the exact
(row, group) set. "Perm rows" means all 24 rows of that permutation.

| negative | refused at |
|---|---|
| wrong ζ limb, machine recomputed on it | `fs_bind` on ζ's draw perm rows + `machine_out` on the last row |
| wrong α limb, machine recomputed on it | `fs_bind` on α's draw perm rows + `machine_out` on the last row |
| wrong fri_alpha, held on every row, exported, sums recomputed with it | `fs_bind` on G_0's first perm rows only |
| **held fri_alpha split**: α′ on F2's rows and in the export, the drawn α from the draw row on | `hold` only, on the one row where the cell changes |
| β_0 takes a skipped accepted draw, exported consistently | `fs_select` on its draw perm rows |
| F1 caps swapped, consistent replay (own ζ, quotient re-solved, F2/D2 rebuilt, own fri_alpha and β, PoW re-ground by p3's challenger, own indices and sums) | `bind_cap` only, on the F1 perms whose cap words moved |
| FRI round caps swapped, consistent replay (own β, PoW re-ground) | `bind_cap` only, on the G_0/G_1 perms whose cap words moved |
| an opened value (trace-local 0) poked in the transcript, machine untouched, everything after F2 replayed and re-ground | `bind_opened` only, on that value's perm rows |
| **that value poked in the Az accumulation only** (transcript and machine honest; Az and the export moved by fri_alpha⁴) | `accumulate` only, on that value's step-0 row |
| **a trace-next term put under the ζ mask** (both sums recomputed and exported) | `mask` only, on that block's perm rows |
| an opened word encoded as word + p | `canonical` on its perm rows + `pow` on window 0's perm rows (D2 moves, PoW not re-ground) |
| PoW witness failing the grind, the rest replayed | `pow` on window 0's perm rows |
| an index bit flipped in the export | `fs_index` on its window's perm rows |
| **Az / Bz output poked** | `az_out` on the last row |
| ζ / fri_alpha output poked | `cells_out` on row 0 |
| a β output poked | `fs_bind` on its draw perm rows |

**Native cross-checks** (honest test): every challenge (α, ζ, fri_alpha, both β) from
p3's own challenger; p3's `check_witness` accepts the PoW; every index equals p3's
`sample_bits`; the lane's F2 digest is 2a's D2; fri_alpha, β and the indices equal 2b-i's
outputs. `Seam::read` of the public values equals the native seam. Az and Bz come from a
source-order `open_input` sum written from the proof's structure, independently of the
layout. For all 43 queries, 2b-ii's native reduced opening equals
(Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x). The test also runs a SAT scan, checks degree
≤ 3, and pins the toy layout to `price::composed_c1_layout`.

### Dimensions **[P, source-derived]**

`price::composed_c1(shape)` is pinned by `composed_c1_pins_the_census`. The lane is
the whole challenger transcript plus one final refill whose first block carries the
last window's digest bits. At S3 that is the census's **206** challenger permutations
+ 1 = 207.

| shape | lane perms (challenger + 1) | lane rows | padded rows | columns | periodic (ROM, full period) | PVs | seam outputs |
|---|---|---|---|---|---|---|---|
| S | 207 (206 + 1) | 4,968 | 2^15 | 11,746 | 2,227 | 1,151 | 139 |
| P | 228 (227 + 1) | 5,472 | 2^15 | 12,655 | 2,593 | 1,295 | 143 |
| R | 209 (208 + 1) | 5,016 | 2^15 | 12,040 | 2,364 | 1,136 | 139 |

The S column split: Keccak 2,633, message and state bits 2,176, canonicity 68, draws
72, perm ring 207, L1 122, held fri_alpha 4, machine inputs 5,248 (1,312 × 4), machine
1,216. The rows are the machine's: the lane fills 4,968 of the 2^15 rows.

**Against the plan** (≈ 12.4k columns × 2^15 at S3): 11,746 × 2^15. C1 does not carry
2b-i's held index bits (43 × 22 = 946 columns at S3). Each index is bound straight from
its draw bits to its output, and C2 re-decomposes it. The ring (207) and L1 (122) are
the additions.

**The ROM's price (L5, deferred).** The verifier of C1 evaluates each full-period ROM
column at ζ: rom columns × 2^15 extension multiplies, **73.0M at S3** (2,227 × 2^15),
85.0M at P3 and 77.5M at R. The sponge selectors the ring replaced would have added
(perms + 2) × 2^15 = 6.85M at S3. The coordinator's "≈ 79M for C1" is the sum of the
two (79.8M). What remains is the ROM alone.

### What C1 does not do

- **C2** (2b-ii + 2b-iii as per-query segments, levers L2 and L3) is the next slice.
  Nothing yet reads C1's `Seam` from C2's public values, so no seam is enforced across
  the two proofs yet. `Seam::read` is the accessor that `check_seams` will use.
- **The machine ROM** stays full-period periodic (L5).
- **Query coverage and full size.** The toy has two FRI rounds and a small machine. C1
  at the full S3 size (2^15 rows) has never been built.

`pcs_input_bindings_complete`, `full_ood_air_checked`, `complete_verifier_layout` and
`memory_gate_pass` stay **false**.

### Validation

No local tests, proofs or benchmarks were run. The local preflight was
`cargo check --workspace --all-targets --locked`, Clippy on `qlab-bench` (no findings
in `f2/`) and rustfmt. `verify-graviton` CI is the acceptance gate. New tests: six in
`c1.rs` and one in `price.rs`, seven in all. **[P, pending CI]**: against 2b-iii's
2,791, that is 2,798 passed, 0 failed, 15 ignored.

Expected new-test runtime **[P]** is 10–45 s on the Graviton lane. It adds **no prove**:
the proof is 2b-i's, shared per test binary. The work is three 22-bit grinds by p3's
parallel `grind` (the two cap swaps and the opened-value poke), eighteen parallel
full-trace violation scans and one SAT scan over a 2^10-row, roughly 5.5k-column trace,
43 native reduced openings, one symbolic degree pass, and the three shape programs
compiled once for the price test.

Unverified, most likely to break first:

1. Exact (row, group) sets under replication. Every perm-gated violation is expected on
   all 24 rows of its permutation. An extra group fails loudly; the fix is to name it,
   not to weaken the assertion.
2. The L1 slot maps and the q_0 step across the cut term. Construction checks the maps
   against the layout, and the 43-query split check exercises the sums end to end, but
   only on the toy's five F2 blocks. S3's F2 (175 blocks) is priced by formula only;
   `Layout::new`'s map check has never run on it.
3. The hand-derived S/P/R pins: machine dimensions from F2b-0's census table, lane
   permutations from the census geometry.

## F2b composition C2 and the seam

Slice 2 of the composition recorded on issue #750. **C2** is 2b-ii (the input-batch
openings and the reduced opening) plus 2b-iii (the commit-phase openings, the folds and
the final polynomial) as one AIR on one overwrite-mode Keccak lane (L4), **one segment
per query**, with levers **L2** and **L3**. It consumes C1's exports through a named
seam. C2 is a test-only component (`crates/qlab-bench/src/f2/ood/c2.rs`, with the seam
in `ood/seam.rs`), scanned row by row and never proved. The four merged components, C1,
and all their tests are unchanged in behaviour. Their layout types are now `pub(super)`
so C2 reuses them instead of copying them.

### Segment and scheduling

Per covered query, the segment is 2b-ii's permutations exactly as `open.rs` lays them
out (randomizer, trace and quotient leaf sponges, three input paths), immediately
followed by 2b-iii's (per round: leaf, then path). Then comes the next query. At S3
that is 82 + 44 = 126 permutations per query, and 43 queries fill 130,032 of 2^17 rows.

**C2 has no periodic column at all.** Keccak's own period-24 `step_flags` give each
permutation's step-0 and last rows. A one-hot **position ring**, one main column per
segment position, is 1 on all 24 rows of the permutation at that position. It
advances on each permutation's last row and wraps to position 0 at a segment end,
unless that segment was the last query's, in which case it empties. A one-hot **query
ring**, one column per covered query, advances at each segment end. Both rings are
fully determined by the Keccak flags. As in C1, a binding gated by a position cell
holds on all 24 rows, so the prover replicates the permutation's message bits and
canonicity witnesses there. The bindings that compare one permutation's output with
the next permutation's input (child placement, capacity and tail-lane carry) and the
cap checks need the last row alone. Their gates (last-row flag × position cell) are
materialized cells, one per index bit that a path level reads and one per cap check,
which keeps those bindings at degree 3 (`gate`).

### Consuming C1's seam

No z-value and no opened value appears in C2. **C2's public values are the seam**
(`seam::Seam`): every cap (trace, quotient, randomizer, each commit round), ζ,
fri_alpha, Az, Bz, every β, the final polynomial and the covered queries' indices.
ζ, fri_alpha, Az, Bz, the betas and the final polynomial are held cells bound on row 0
(`seam_in`). The caps are read by the cap checks, and the indices pin the index bits
through the query ring (`index`). Per query,

  ro = (Az − Ax)/(ζ − x) + (Bz − Bx)/(ζ·g_N − x),

where Ax and Bx are accumulated from the Merkle-authenticated row values in native
`open_input` order. That is the order C1 absorbed the opened values in and weighted
Az and Bz by. Both AIRs read it from **one list, `seam::open_order`**: C1's F2 layout is
built from it, and C2's `Layout::new` checks every input block against it. Each block's
row values must be consecutive terms, a trace column's ζ·g_N term must be its ζ term + w,
and consecutive blocks must step term by term, except across the w ζ·g_N terms after
the trace. So the two sums cannot be taken in different orders.

### L2: incremental fri_alpha powers

2b-ii held one fri_alpha power per opened term, 5,912 columns at S3; L1 had already
removed the matching z-value table. C2 keeps:

- a **held table α^1..α^34**: a leaf block's 34 words carry at most 34 row values;
- a **held α^w**, with w the trace width;
- per row, a **running power p = α^{k0}**, where k0 is the term of the current input
  block's first row value.

The block's row values are consecutive terms, so blk = Σ_i α^i v_i uses the table
(`blk`), Ax += p·blk, and on trace blocks Bx += pw·blk with pw = p·α^w (`accumulate`),
because trace column c's ζ·g_N term is D + w + c. All of it is gated by the step-0 flag.
The rules for p (`alpha_pow`):

- **anchor**: p = 1 on every segment's first block;
- **step**: over a block of n row values, p steps by α^n. After the last trace block it
  steps by α^w·α^n (from pw), which skips the w ζ·g_N terms;
- **hold and reset**: p holds across path permutations and resets to 1 at the segment
  end;
- **α^w pin**: α^w is fixed where the trace terms end, by p·α^n = α^D·α^w on the last
  trace block. The table itself is a first-row chain from fri_alpha.

At S3 the powers cost 136 + 4 held columns and 16 running columns, replacing 5,912.

### L3: the hand-off

The index bits and ro are **one set of register cells**, held over the whole segment
(`handoff`). The same bit cells drive x, the three input paths, the cap one-hot (shared
by every batch and round), the commit-phase paths (bit S_{r+1} + t at round r, level t),
the fold positions, s^-1 and the final x. Input and commit-phase levels that read the
same bit share one gate cell. The reduced opening is computed on the opening part
(`reduce`, on the last input permutation's 24 rows, where Ax and Bx are complete), and
it is the cell the fold chain starts from (`select`, round 0). Nothing is duplicated
between the two parts: 2b-iii's own index bits and cap one-hot (lde + 12 columns) are
gone.

### The seam and `check_seams`

`Seam` is the exact C1→C2 value set, and `SeamShape` gives its one encoding. C1's
public values are its inner PVs followed by this slice, and C2's public values are
exactly the slice, carrying the indices of the query slots it covers. `Seam::read` (C1)
and `Seam::decode` (C2) read it back. **`check_seams(c1, c2) -> Result`** is the
group-by-group equality the next recursion level will state in-circuit, and an error
names the first group that differs. C2's covered slots are a static property of its
layout. **`check_coverage`** asks separately whether C2 covers every query C1 drew. The
production instance covers all 43; the toy instance covers two, and the honest test
asserts that `check_coverage` refuses it.

| group | S3 values | carried as |
|---|---:|---|
| caps (trace, quotient, randomizer, 4 commit rounds) | 7 × 8 digests = 896 limbs | 16-bit limbs |
| ζ | 4 | extension limbs |
| fri_alpha | 4 | extension limbs |
| Az, Bz | 8 | extension limbs |
| β (one per round) | 16 | extension limbs |
| final polynomial | 64 | extension limbs |
| query indices | 43 | one field element each |
| **total** | **1,035** | = C1's 1,151 PVs − 116 inner PVs |

Without the caps, the seam is 139 values at S3, matching C1's seam-output count. The
caps are C1's declared inputs, and C2 reads them from the same encoding.

### Constraint groups and tests

Thirty-two named groups: `keccak`, `bits`, `absorb`, `ring`, `gate`, `capacity`,
`bind_zero`, `bind_carry`, `bind_child`, `cap`, `canonical`, `leaf_bind`, `index`,
`cap_select`, `x_point`, `inverse`, `alpha_pow`, `blk`, `accumulate`, `reduce`,
`position`, `select`, `s_inv`, `fold_pow`, `fold`, `final_x`, `horner`, `final`,
`seam_in`, `hold`, `handoff`, `ctx_hold`. Every constraint has degree ≤ 3, checked on
the symbolic builder for the toy and for S3. The fixture is 2b-i's seeded log-8 toy
proof, with C1's honest seam built from the same proof and a C2 instance covering two
queries whose cap entries differ (2b-ii's choice). Every negative scans **all** rows and
asserts the exact (row, group) set.

"Consequences" means exactly what a consistently re-derived claim cannot hide, computed
from the native replay alone. Every root that misses the seam cap entry its index
selects is refused by `cap` on that check's row. Every query whose last fold misses the
final polynomial is refused by `final` on its register rows.

| negative | refused at |
|---|---|
| input salt changed | `cap` on that batch's cap row |
| input row value changed + fresh salt; Ax, ro and the fold chain re-derived | consequences: the input cap, both commit caps, `final` |
| input siblings swapped | `cap` on that batch's cap row |
| input child on the wrong side, bit untouched | `bind_child` on the feeding row + `cap` |
| index bit 3 flipped for the whole segment, everything following it | `index` on the segment's rows + consequences (all three input caps among them) |
| wrong cap one-hot | `cap_select` on the query's rows + all five cap checks |
| x without bit reversal; inverses, ro and fold chain re-derived | `x_point` on the query's rows + consequences |
| ro poked for the whole segment | `reduce` on the last input perm's rows + `select` on the query's rows |
| commit-phase salt changed | `cap` on round 1's cap row |
| two round-0 siblings moved so the fold is unchanged | `cap` on round 0's cap row only |
| round-0 siblings swapped, chain re-derived | consequences |
| round 1 folded with β_0 | `fold_pow` on the query's rows + `final` |
| the value between rounds poked | `fold` + `select` on the query's rows |
| final polynomial forged (public and held, consistent) | `final` on every row |
| a final-x chain cell poked | `final_x` on the query's rows |
| **Az public value that the held cell does not carry** | `seam_in` on row 0 |
| **Az from C1 differs, C2 consistent on it** (held, public, ro and folds re-derived) | `check_seams` names `az`; in C2, consequences (the forged ro misses the commit-phase leaves) |
| **each seam group tampered on C1's side, then on C2's** | `check_seams` names that group, for all eight groups |
| **a running power duplicated** (query 1's last quotient block reuses the previous block's power; Ax, ro, folds consistent) | `alpha_pow` on the row where p should have stepped + consequences |
| **a running power skipped** (query 0's trace block one power too far, every later block following) | `alpha_pow` on the step into it and on its 24 rows (the α^w pin) + consequences |
| **ro poked between the parts** (the opening part reduces to the honest ro, the fold part starts from ro + 1) | `handoff` on the boundary row + `select` on the fold rows |
| **the fold part's index bit S_R differs from the opening part's** | `handoff` on the boundary row; on the fold rows `index`, `x_point`, `s_inv`, `final_x`; `bind_child` on the two commit-phase levels that read that bit |

**Native cross-checks** (honest tests):

- For **all 43 queries**, C2's block-form Ax/Bx (running powers from the held table)
  equals C1's source-order `open_input` sum, and the split with C1's Az/Bz equals 2b-ii's
  sequential reduced opening.
- The running powers are α^{k0} for the shared term order.
- For the covered queries, the fold chain and final check are p3's (commit-phase MMCS,
  `fold_row`), and every root is the seam's cap entry.
- Beyond those, the honest tests check SAT, degree ≤ 3 and zero periodic columns,
  `check_seams(C1, C2)` passing on the honest pair built from the same proof, and the
  toy layout pinned to `price::composed_c2_layout`.
- **A real S3 production schedule** (25 input leaf perms and 3 × 19 input levels, then
  four arity-16 rounds with paths 15/11/7/3) runs for two queries on the shared census
  proof. The seam comes from p3's challenger and a source-order sum, and ro, Ax/Bx and
  the folds are checked against native code. The test covers SAT, degree ≤ 3 and the
  price pin.

### Dimensions **[P, source-derived]**

`price::composed_c2(shape)` is pinned by `composed_c2_pins_the_census_and_the_plan`. At
43 queries, C2's lane is **every leaf and path permutation of the census geometry**; C1
carries the challenger's. At S3: 43 × (25 + 8) = **1,419** leaf and 43 × (57 + 36) =
**3,999** path permutations.

| shape | perms / query (input + commit) | lane rows | padded rows | columns | periodic | PVs (= seam) |
|---|---|---|---|---|---|---|
| S | 126 (82 + 44) | 130,032 | 2^17 | 5,058 | 0 | 1,035 |
| P | 139 (87 + 52) | 143,448 | 2^18 | 5,107 | 0 | 1,167 |
| R | 120 (79 + 41) | 123,840 | 2^17 | 4,966 | 0 | 1,035 |

The S column split: Keccak 2,633, message bits 1,088, canonicity 68, position and query
rings 169 (126 + 43), last-row gates 26, query registers 818 (26 of them the hand-off),
running cells 24, held seam values 232.

**Against the plan** (≈ 5.0k columns × 2^17 at S3; P3 → 2^18): 5,058 × 2^17 at S3, and
P3 at 2^18. The levers account for the gap to 2b-ii + 2b-iii: L1 and L2 each remove a
5,912-column table, and L3 removes 2b-iii's second index-bit and one-hot set (34
columns). The rings, gates and the 140 held power columns are the additions. With no
periodic column, the next level pays nothing per row for C2's scheduling.

### What C2 does not do

- **In-circuit seam.** `check_seams` is native. The next recursion level states the
  same equalities in-circuit.
- **Full size.** C2 at 43 queries (2^17 rows) has never been built. The S3 test builds
  two queries (2^13 rows).
- **The plan's slice 3 (the selector conversion) and C1's full-period ROM (L5)** are
  not part of this slice. C2 itself already has no periodic column.

`complete_verifier_layout` and `memory_gate_pass` stay **false**.

### Validation

No local tests, proofs or benchmarks were run. The local preflight was
`cargo check --workspace --all-targets --locked`, Clippy on `qlab-bench` (no findings
in `f2/`) and rustfmt. `verify-graviton` CI is the acceptance gate. New tests: eight in
`c2.rs` and one in `price.rs`, nine in all. **[P, pending CI]**: against C1's 2,798,
that is 2,807 passed, 0 failed, 15 ignored.

Expected new-test runtime **[P]** is 20–60 s on the Graviton lane. It adds **no
prove**. The toy proof is 2b-i's and the S3 proof is the census test's, each shared per
test binary; if C2's S3 test runs first, it pays that test's existing ≈ 26 s S3 prove.
The work:

- C1's honest trace, built once;
- twenty-one parallel full-trace violation scans and one SAT scan over a 2^11-row,
  4,395-column trace;
- 43 × 2 native reduced openings and block sums;
- one SAT scan over a 2^13-row, roughly 5.0k-column S3 trace;
- two symbolic degree passes.

Unverified, most likely to break first:

1. Exact (row, group) sets under replication, in particular the "consequences" sets
   derived from the native replay, and the `alpha_pow` row choice (the last row
   before the forged block).
2. The L2 bookkeeping on S3's 22 trace blocks, which has run only in the two-query S3
   test (SAT), never under a negative.
3. The S/P/R pins, which assume the census geometry and the formula mirrors the
   column allocation exactly. The toy and the two-query S3 instance pin the formula to
   the AIR; P and R are formula-only.
