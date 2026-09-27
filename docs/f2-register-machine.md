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
wires. This component proves execution of its fixed program on declared inputs.
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
