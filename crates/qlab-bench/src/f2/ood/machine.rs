//! Reference register machine for the OOD DAG. Full-period ROM is deliberately
//! priced, not hidden: this is a correctness model, not the final F2 layout.
#[cfg(test)]
use p3_air::{Air, BaseAir};
use p3_air::{AirBuilder, WindowAccess};
use p3_field::BasedVectorSpace;
use p3_field::{Field, PrimeCharacteristicRing};
#[cfg(test)]
use p3_matrix::dense::RowMajorMatrix;
use serde_json::{json, Value};

use super::Val;
use super::{require, Id, Input, Op, Result, E};

#[derive(Clone, Copy)]
enum Kind {
    Input(usize),
    Constant(E),
    Add,
    Sub,
    Neg,
    Mul,
    Inverse,
}

impl Kind {
    fn opcode(self) -> usize {
        match self {
            Self::Input(_) => 0,
            Self::Constant(_) => 1,
            Self::Add => 2,
            Self::Sub => 3,
            Self::Neg => 4,
            Self::Mul => 5,
            Self::Inverse => 6,
        }
    }
}

#[derive(Clone)]
struct Step {
    node: Id,
    kind: Kind,
    a: Option<usize>,
    b: Option<usize>,
    dst: usize,
}

fn sources(op: Op) -> Vec<Id> {
    match op {
        Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) => vec![a, b],
        Op::Neg(a) | Op::Inverse(a) => vec![a],
        _ => vec![],
    }
}

#[derive(Clone)]
pub(super) struct Schedule {
    steps: Vec<Step>,
    inputs: Vec<(Id, Input)>,
    outputs: Vec<usize>,
    roots: Vec<Id>,
    registers: usize,
    nodes: usize,
}

impl Schedule {
    pub(super) fn compile(ops: &[Op], roots: &[Id]) -> Result<Self> {
        require(!roots.is_empty(), "machine needs output roots")?;
        require(
            roots.iter().all(|&id| id < ops.len()),
            "machine root out of bounds",
        )?;
        for (id, &op) in ops.iter().enumerate() {
            require(
                sources(op).iter().all(|&src| src < id),
                "DAG is not topological",
            )?;
        }
        // Stable depth-first postorder loads input/constant leaves on demand.
        // An explicit stack avoids recursion depth proportional to alpha folds.
        let mut done = vec![false; ops.len()];
        let mut order = Vec::new();
        let mut stack: Vec<_> = roots.iter().rev().map(|&id| (id, false)).collect();
        while let Some((id, exit)) = stack.pop() {
            if done[id] {
                continue;
            }
            if exit {
                done[id] = true;
                order.push(id);
            } else {
                stack.push((id, true));
                stack.extend(sources(ops[id]).into_iter().rev().map(|src| (src, false)));
            }
        }
        let mut last_use = vec![0; ops.len()];
        for (row, &id) in order.iter().enumerate() {
            for src in sources(ops[id]) {
                last_use[src] = row;
            }
        }
        // Keep outputs live through the terminal row, including duplicate roots.
        for &id in roots {
            last_use[id] = order.len();
        }
        let mut slots = vec![None; ops.len()];
        let mut free = Vec::new();
        let mut registers = 0;
        let mut inputs = Vec::new();
        let mut steps = Vec::new();
        for (row, &id) in order.iter().enumerate() {
            let src = sources(ops[id]);
            let a = src.first().map(|&i| slots[i].expect("scheduled source"));
            let b = src.get(1).map(|&i| slots[i].expect("scheduled source"));
            for (j, &i) in src.iter().enumerate() {
                if last_use[i] == row && !src[..j].contains(&i) {
                    free.push(slots[i].expect("live source"));
                }
            }
            // Operands are read before this instruction writes its destination.
            let dst = free.pop().unwrap_or_else(|| {
                let slot = registers;
                registers += 1;
                slot
            });
            slots[id] = Some(dst);
            let kind = match ops[id] {
                Op::Input(input) => {
                    let index = inputs.len();
                    inputs.push((id, input));
                    Kind::Input(index)
                }
                Op::Constant(c) => Kind::Constant(c),
                Op::Add(..) => Kind::Add,
                Op::Sub(..) => Kind::Sub,
                Op::Neg(_) => Kind::Neg,
                Op::Mul(..) => Kind::Mul,
                Op::Inverse(_) => Kind::Inverse,
            };
            steps.push(Step {
                node: id,
                kind,
                a,
                b,
                dst,
            });
        }
        let outputs = roots
            .iter()
            .map(|&id| slots[id].expect("output scheduled"))
            .collect();
        Ok(Self {
            steps,
            inputs,
            outputs,
            roots: roots.to_vec(),
            registers,
            nodes: ops.len(),
        })
    }

    pub(super) fn height(&self) -> usize {
        // Always a terminal row after the last write. No last-row carry escape.
        (self.steps.len() + 1).next_power_of_two()
    }
    pub(super) fn width(&self) -> usize {
        12 + 4 * self.registers
    }
    /// Extension registers the schedule allocates.
    pub(super) fn registers(&self) -> usize {
        self.registers
    }
    pub(super) fn rom_width(&self) -> usize {
        12 + 3 * self.registers + self.inputs.len()
    }
    /// Machine inputs (extension values): one held input cell each in F2b-2a
    /// and C1.
    pub(super) fn input_count(&self) -> usize {
        self.inputs.len()
    }
    /// Logical input sources in first-use order: input `i` of the machine is
    /// `inputs()[i]`, and its DAG node supplies the honest value.
    pub(super) fn inputs(&self) -> &[(Id, Input)] {
        &self.inputs
    }
    /// Register slot holding each exported root on the terminal row.
    pub(super) fn outputs(&self) -> &[usize] {
        &self.outputs
    }

    /// Full-period ROM at `height` rows (`height >= self.height()`): opcode,
    /// constant limbs, one-hot A/B/destination and input selectors; padding
    /// rows carry only the padding opcode.
    pub(super) fn rom(&self, height: usize) -> Result<Vec<Vec<Val>>> {
        require(
            height >= self.height() && height.is_power_of_two(),
            "machine ROM height",
        )?;
        let mut rom = vec![vec![Val::ZERO; height]; self.rom_width()];
        let r = self.registers;
        for (row, step) in self.steps.iter().enumerate() {
            rom[step.kind.opcode()][row] = Val::ONE;
            if let Kind::Constant(c) = step.kind {
                for (k, &limb) in c.as_basis_coefficients_slice().iter().enumerate() {
                    rom[8 + k][row] = limb;
                }
            }
            if let Some(a) = step.a {
                rom[12 + a][row] = Val::ONE;
            }
            if let Some(b) = step.b {
                rom[12 + r + b][row] = Val::ONE;
            }
            rom[12 + 2 * r + step.dst][row] = Val::ONE;
            if let Kind::Input(i) = step.kind {
                rom[12 + 3 * r + i][row] = Val::ONE;
            }
        }
        rom[7][self.steps.len()..].fill(Val::ONE);
        Ok(rom)
    }

    /// Row-major machine columns (`self.width()` per row) at `height` rows.
    pub(super) fn trace_values(&self, inputs: &[E], height: usize) -> Result<Vec<Val>> {
        require(
            inputs.len() == self.inputs.len(),
            "machine input dimensions",
        )?;
        require(
            height >= self.height() && height.is_power_of_two(),
            "machine trace height",
        )?;
        let width = self.width();
        let mut values = vec![Val::ZERO; height * width];
        let mut registers = vec![E::ZERO; self.registers];
        for row in 0..height {
            let cells = &mut values[row * width..(row + 1) * width];
            for (i, v) in registers.iter().enumerate() {
                cells[12 + 4 * i..16 + 4 * i].copy_from_slice(v.as_basis_coefficients_slice());
            }
            if let Some(step) = self.steps.get(row) {
                let (a, b, c) = self.eval_step(step, &registers, inputs)?;
                for (i, v) in [a, b, c].iter().enumerate() {
                    cells[4 * i..4 * i + 4].copy_from_slice(v.as_basis_coefficients_slice());
                }
                registers[step.dst] = c;
            }
        }
        Ok(values)
    }

    fn eval_step(&self, step: &Step, registers: &[E], inputs: &[E]) -> Result<(E, E, E)> {
        let a = step.a.map_or(E::ZERO, |i| registers[i]);
        let b = step.b.map_or(E::ZERO, |i| registers[i]);
        let c = match step.kind {
            Kind::Input(i) => inputs[i],
            Kind::Constant(c) => c,
            Kind::Add => a + b,
            Kind::Sub => a - b,
            Kind::Neg => -a,
            Kind::Mul => a * b,
            Kind::Inverse => a.try_inverse().ok_or("machine inverse of zero")?,
        };
        Ok((a, b, c))
    }

    /// Check every instruction against the oracle, not only the output: an
    /// accidental register alias may cancel at the final residual.
    pub(super) fn check_values(&self, dag_values: &[E]) -> Result<()> {
        require(dag_values.len() == self.nodes, "machine oracle dimensions")?;
        let inputs: Vec<_> = self.inputs.iter().map(|&(id, _)| dag_values[id]).collect();
        let mut registers = vec![E::ZERO; self.registers];
        for step in &self.steps {
            let (_, _, c) = self.eval_step(step, &registers, &inputs)?;
            require(
                c == dag_values[step.node],
                "register execution differs from DAG",
            )?;
            registers[step.dst] = c;
        }
        for (&slot, &node) in self.outputs.iter().zip(&self.roots) {
            require(
                registers[slot] == dag_values[node],
                "machine output was overwritten",
            )?;
        }
        Ok(())
    }

    pub(super) fn report(&self) -> Value {
        let input_sources: Vec<_> = self
            .inputs
            .iter()
            .map(|(_, input)| format!("{input:?}"))
            .collect();
        json!({"evidence": "P", "source": "reachable DAG, depth-first schedule, last-use register reuse",
            "instructions": self.steps.len(), "discarded_nodes": self.nodes - self.steps.len(),
            "extension_registers": self.registers, "trace_columns": self.width(),
            "padded_rows": self.height(), "public_input_extension_values": self.inputs.len(),
            "output_extension_values": self.outputs.len(), "input_sources": input_sources,
            "reference_rom_columns": self.rom_width(),
            "raw_trace_bytes": self.height() as u64 * self.width() as u64 * 4,
            "raw_reference_rom_bytes": self.height() as u64 * self.rom_width() as u64 * 4,
            "full_ood_air_checked": false, "pcs_input_bindings_complete": false,
            "complete_verifier_layout": false, "memory_gate_pass": false})
    }
}

/// Fully constrained reference component. Inputs and expected outputs are public
/// extension limbs; they are NOT authenticated PCS/FS wires here — `bind.rs`
/// (F2b-2a) runs the same `eval_machine` core on transcript-bound inputs.
/// Full-period ROM binds opcode, addresses, constants and public input index
/// for every row. Dense materialization is bounded by the caller before any
/// allocation.
#[cfg(test)]
#[derive(Clone)]
struct RegisterAir {
    schedule: Schedule,
    rom: Vec<Vec<Val>>,
}

#[cfg(test)]
impl RegisterAir {
    fn new(schedule: Schedule, max_cells: usize) -> Result<Self> {
        let height = schedule.height();
        let cells = height
            .checked_mul(schedule.width() + schedule.rom_width())
            .ok_or("machine allocation overflow")?;
        require(
            cells <= max_cells,
            "reference machine exceeds materialization budget",
        )?;
        let rom = schedule.rom(height)?;
        Ok(Self { schedule, rom })
    }

    fn trace(&self, inputs: &[E]) -> Result<RowMajorMatrix<Val>> {
        let s = &self.schedule;
        Ok(RowMajorMatrix::new(
            s.trace_values(inputs, s.height())?,
            s.width(),
        ))
    }

    fn public_values(&self, inputs: &[E], expected: &[E]) -> Result<Vec<Val>> {
        require(
            inputs.len() == self.schedule.inputs.len()
                && expected.len() == self.schedule.outputs.len(),
            "machine public dimensions",
        )?;
        Ok(inputs
            .iter()
            .chain(expected)
            .flat_map(|v| v.as_basis_coefficients_slice().iter().copied())
            .collect())
    }
}

#[cfg(test)]
impl BaseAir<Val> for RegisterAir {
    fn width(&self) -> usize {
        self.schedule.width()
    }
    fn num_public_values(&self) -> usize {
        4 * (self.schedule.inputs.len() + self.schedule.outputs.len())
    }
    fn num_periodic_columns(&self) -> usize {
        self.rom.len()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.rom.clone()
    }
}

#[cfg(test)]
impl<AB: AirBuilder<F = Val>> Air<AB> for RegisterAir {
    fn eval(&self, builder: &mut AB) {
        let rom: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let s = &self.schedule;
        let inputs: Vec<[AB::Expr; 4]> = (0..s.inputs.len())
            .map(|i| core::array::from_fn(|k| pv[4 * i + k].clone()))
            .collect();
        eval_machine(builder, s, 0, &rom, &inputs);
        let main = builder.main();
        let cur = main.current_slice();
        for k in 0..4 {
            for (i, &slot) in s.outputs.iter().enumerate() {
                builder.when_last_row().assert_eq(
                    cur[12 + 4 * slot + k].into(),
                    pv[4 * (s.inputs.len() + i) + k].clone(),
                );
            }
        }
    }
}

/// The machine's instruction, read and register-file constraints, shared by
/// the public-input reference AIR and F2b-2a's transcript-bound component.
/// Machine columns start at `off`; `rom` is the machine's ROM slice; input `i`
/// limb `k` is `inputs[i][k]` (public limbs here, held input columns there).
/// Output bindings are the caller's: which roots are pinned, and to what, is
/// exactly what differs between the two components.
pub(super) fn eval_machine<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    s: &Schedule,
    off: usize,
    rom: &[AB::Expr],
    inputs: &[[AB::Expr; 4]],
) {
    let main = builder.main();
    let cur = main.current_slice();
    let next = main.next_slice();
    let cv = |i: usize| -> AB::Expr { cur[off + i].into() };
    let nv = |i: usize| -> AB::Expr { next[off + i].into() };
    let r = s.registers;
    // Multiplication in KoalaBear's extension E = F[X]/(X^4 - 3), as in M4.
    let product = |a: usize, b: usize, limb: usize| {
        let mut acc = AB::Expr::ZERO;
        for i in 0..4 {
            for j in 0..4 {
                if (i + j) % 4 == limb {
                    let factor = if i + j >= 4 {
                        Val::from_u32(3)
                    } else {
                        Val::ONE
                    };
                    acc += cv(a + i) * cv(b + j) * factor;
                }
            }
        }
        acc
    };
    for k in 0..4 {
        let read = |base: usize| {
            (0..r)
                .map(|i| rom[base + i].clone() * cv(12 + 4 * i + k))
                .fold(AB::Expr::ZERO, |a, b| a + b)
        };
        builder.assert_eq(cv(k), read(12));
        builder.assert_eq(cv(4 + k), read(12 + r));
        let input = (0..s.inputs.len())
            .map(|i| rom[12 + 3 * r + i].clone() * inputs[i][k].clone())
            .fold(AB::Expr::ZERO, |a, b| a + b);
        builder.assert_zero(rom[0].clone() * (cv(8 + k) - input));
        builder.assert_zero(rom[1].clone() * (cv(8 + k) - rom[8 + k].clone()));
        builder.assert_zero(rom[2].clone() * (cv(8 + k) - cv(k) - cv(4 + k)));
        builder.assert_zero(rom[3].clone() * (cv(8 + k) - cv(k) + cv(4 + k)));
        builder.assert_zero(rom[4].clone() * (cv(8 + k) + cv(k)));
        builder.assert_zero(rom[5].clone() * (cv(8 + k) - product(0, 4, k)));
        builder.assert_zero(rom[6].clone() * (product(0, 8, k) - Val::from_bool(k == 0)));
        builder.assert_zero(rom[7].clone() * cv(8 + k));
        for i in 0..r {
            let col = 12 + 4 * i + k;
            builder.when_first_row().assert_zero(cv(col));
            builder.when_transition().assert_zero(
                nv(col) - cv(col) - rom[12 + 2 * r + i].clone() * (cv(8 + k) - cv(col)),
            );
        }
    }
}

/// [P] F4b-2 lever pricing (lab #782), count-only: the DAG's peak live
/// registers under the current discipline and two others, with nothing built.
///
/// - `current`: [`Schedule::compile`]'s depth-first order, every input
///   loaded into a register (reproduces `Schedule::registers`).
/// - `held_operands`: the same order, but an input is read straight from its
///   held column as an operand and never takes a register.
/// - `streamed`: nothing held; inputs arrive one at a time in `arrival`
///   order (the child's transcript order) and every node runs as soon as its
///   operands exist, constants loading at their first consumer. A greedy
///   schedule, so a better scheduler can only lower it.
pub(super) struct LeverRegisters {
    pub(super) current: usize,
    pub(super) held_operands: usize,
    pub(super) streamed: usize,
}

fn postorder(ops: &[Op], roots: &[Id]) -> Vec<Id> {
    let mut done = vec![false; ops.len()];
    let mut order = Vec::new();
    let mut stack: Vec<_> = roots.iter().rev().map(|&id| (id, false)).collect();
    while let Some((id, exit)) = stack.pop() {
        if done[id] {
            continue;
        }
        if exit {
            done[id] = true;
            order.push(id);
        } else {
            stack.push((id, true));
            stack.extend(sources(ops[id]).into_iter().rev().map(|src| (src, false)));
        }
    }
    order
}

/// Peak registers of the depth-first order; `inputs_take_registers` false
/// is the held-operand discipline.
fn depth_first_peak(ops: &[Op], roots: &[Id], inputs_take_registers: bool) -> usize {
    let order = postorder(ops, roots);
    let mut last_use = vec![0; ops.len()];
    for (row, &id) in order.iter().enumerate() {
        for src in sources(ops[id]) {
            last_use[src] = row;
        }
    }
    for &id in roots {
        last_use[id] = order.len();
    }
    let takes = |id: Id| inputs_take_registers || !matches!(ops[id], Op::Input(_));
    let (mut live, mut peak) = (0usize, 0usize);
    for (row, &id) in order.iter().enumerate() {
        let src = sources(ops[id]);
        for (j, &i) in src.iter().enumerate() {
            if last_use[i] == row && !src[..j].contains(&i) && takes(i) {
                live -= 1;
            }
        }
        if takes(id) {
            live += 1;
            peak = peak.max(live);
        }
    }
    peak
}

/// Peak registers of the greedy streamed schedule.
fn streamed_peak(ops: &[Op], roots: &[Id], arrival: &dyn Fn(Input) -> u64) -> usize {
    let order = postorder(ops, roots);
    let n = ops.len();
    let mut reach = vec![false; n];
    for &id in &order {
        reach[id] = true;
    }
    let distinct = |id: Id| {
        let mut s = sources(ops[id]);
        s.dedup();
        s
    };
    let is_const = |id: Id| matches!(ops[id], Op::Constant(_));
    let mut consumers: Vec<Vec<Id>> = vec![vec![]; n];
    let mut pending = vec![0usize; n];
    let mut uses = vec![0usize; n];
    for &id in &order {
        for s in distinct(id) {
            consumers[s].push(id);
            uses[s] += 1;
            if !is_const(s) {
                pending[id] += 1;
            }
        }
    }
    for &id in roots {
        uses[id] = usize::MAX;
    }
    let (mut live, mut peak) = (0usize, 0usize);
    let mut loaded = vec![false; n];
    let mut ready: std::collections::VecDeque<Id> = order
        .iter()
        .copied()
        .filter(|&id| pending[id] == 0 && !matches!(ops[id], Op::Input(_) | Op::Constant(_)))
        .collect();
    let mut inputs: Vec<Id> = order
        .iter()
        .copied()
        .filter(|&id| matches!(ops[id], Op::Input(_)))
        .collect();
    inputs.sort_by_key(|&id| match ops[id] {
        Op::Input(i) => (arrival(i), id),
        _ => unreachable!(),
    });
    let mut next_input = 0;
    loop {
        // Run everything ready before the next arrival.
        while let Some(id) = ready.pop_front() {
            let src = distinct(id);
            for &s in &src {
                if is_const(s) && !loaded[s] {
                    loaded[s] = true;
                    live += 1;
                }
            }
            peak = peak.max(live);
            for &s in &src {
                uses[s] = uses[s].saturating_sub(1);
                if uses[s] == 0 {
                    live -= 1;
                }
            }
            live += 1;
            peak = peak.max(live);
            for &c in &consumers[id] {
                pending[c] -= 1;
                if pending[c] == 0 {
                    ready.push_back(c);
                }
            }
        }
        let Some(&id) = inputs.get(next_input) else {
            break;
        };
        next_input += 1;
        live += 1;
        peak = peak.max(live);
        for &c in &consumers[id] {
            pending[c] -= 1;
            if pending[c] == 0 {
                ready.push_back(c);
            }
        }
    }
    peak
}

/// The three disciplines' peak registers for `ops` (outputs `roots`).
pub(super) fn lever_registers(
    ops: &[Op],
    roots: &[Id],
    arrival: &dyn Fn(Input) -> u64,
) -> LeverRegisters {
    LeverRegisters {
        current: depth_first_peak(ops, roots, true),
        held_operands: depth_first_peak(ops, roots, false),
        streamed: streamed_peak(ops, roots, arrival),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
    use p3_matrix::Matrix;

    fn ext(n: usize) -> E {
        E::from_basis_coefficients_fn(|i| Val::from_usize(n * 7 + i * 19 + 1))
    }

    fn fixture(seed: usize) -> (RegisterAir, Vec<E>, Vec<E>, Vec<E>) {
        let x = ext(seed);
        let y = ext(seed + 1);
        let c = ext(19);
        // All operations, a repeated operand, two retained outputs and dead leaves.
        let ops = vec![
            Op::Input(Input::Alpha),
            Op::Input(Input::Zeta),
            Op::Constant(c),
            Op::Mul(0, 1),
            Op::Add(3, 2),
            Op::Sub(4, 1),
            Op::Neg(5),
            Op::Inverse(0),
            Op::Mul(6, 7),
            Op::Add(8, 0),
            Op::Mul(9, 9),
            Op::Input(Input::Local(0)),
            Op::Constant(E::ZERO),
        ];
        let mut native = vec![x, y, c];
        native.extend([
            x * y,
            x * y + c,
            x * y + c - y,
            -(x * y + c - y),
            x.inverse(),
        ]);
        native.push(native[6] * native[7]);
        native.push(native[8] + x);
        native.push(native[9] * native[9]);
        native.extend([E::ZERO, E::ZERO]);
        let schedule = Schedule::compile(&ops, &[10, 0]).unwrap();
        schedule.check_values(&native).unwrap();
        let inputs = schedule.inputs.iter().map(|&(id, _)| native[id]).collect();
        let expected = vec![native[10], x];
        (
            RegisterAir::new(schedule, 100_000).unwrap(),
            inputs,
            expected,
            native,
        )
    }

    fn sat(air: &RegisterAir, trace: &RowMajorMatrix<Val>, pv: &[Val]) -> bool {
        qlab_air::l2test::scan(air, trace, pv, None).is_none()
    }

    /// Lab #782 F4b-2's lever counts, on a DAG small enough to schedule by
    /// hand: `t = a·b; u = t + n; r = u·a` with `a, b` local inputs and `n`
    /// a next-row input (arriving after every local one). Depth-first order
    /// a, b, t, n, u, r: three live at n's load (a, t, n) with inputs in
    /// registers; one (t, then u, then r) with inputs as held operands;
    /// streamed, a and b arrive, t runs, then n arrives beside a and t: three.
    #[test]
    fn lever_register_counts_match_a_hand_schedule() {
        let ops = vec![
            Op::Input(Input::Local(0)),
            Op::Input(Input::Local(1)),
            Op::Input(Input::Next(0)),
            Op::Mul(0, 1),
            Op::Add(3, 2),
            Op::Mul(4, 0),
        ];
        let arrival = |i: Input| match i {
            Input::Local(c) => 1 + c as u64,
            Input::Next(c) => 100 + c as u64,
            _ => 0,
        };
        let r = lever_registers(&ops, &[5], &arrival);
        assert_eq!((r.current, r.held_operands, r.streamed), (3, 1, 3));
        assert_eq!(
            r.current,
            Schedule::compile(&ops, &[5]).unwrap().registers()
        );
        // The reference fixture: `current` is the compiled register file.
        let (air, ..) = fixture(5);
        assert!(air.schedule.registers() > 0);
    }

    #[test]
    fn reference_register_air_accepts_native_extension_arithmetic() {
        let basis = <E as BasedVectorSpace<Val>>::ith_basis_element(1).unwrap();
        assert_eq!(
            basis.exp_u64(4),
            E::from(Val::from_u32(3)),
            "extension polynomial drift"
        );
        for seed in [1, 7, 53] {
            let (air, inputs, expected, _) = fixture(seed);
            let trace = air.trace(&inputs).unwrap();
            let pv = air.public_values(&inputs, &expected).unwrap();
            assert!(sat(&air, &trace, &pv));
            assert!(trace.height() > air.schedule.steps.len());
            assert_eq!(air.schedule.steps.len(), 11, "dead leaves eliminated");
            assert!(air.schedule.registers < air.schedule.steps.len());
            assert!(
                air.schedule
                    .steps
                    .iter()
                    .any(|s| s.a == Some(s.dst) || s.b == Some(s.dst)),
                "read-before-write register reuse must be exercised"
            );
            let constraints =
                get_symbolic_constraints::<Val, _>(&air, AirLayout::from_air::<Val>(&air));
            assert!(constraints.iter().all(|c| c.degree_multiple() <= 3));
        }
    }

    #[test]
    fn reference_register_air_rejects_result_read_write_hold_and_tail_tampers() {
        let (air, inputs, expected, _) = fixture(3);
        let trace = air.trace(&inputs).unwrap();
        let pv = air.public_values(&inputs, &expected).unwrap();
        let width = trace.width();
        // Every instruction result limb, including input/constant/inverse.
        for (row, step) in air.schedule.steps.iter().enumerate() {
            for limb in 0..4 {
                for col in [8 + limb, 12 + 4 * step.dst + limb] {
                    let mut bad = trace.clone();
                    // The destination lives in the next row after this write.
                    let at = if col >= 12 { row + 1 } else { row };
                    bad.values[at * width + col] += Val::ONE;
                    assert!(!sat(&air, &bad, &pv), "row {row} col {col}");
                }
            }
            if step.a.is_some() {
                let mut bad = trace.clone();
                bad.values[row * width] += Val::ONE;
                assert!(
                    !sat(&air, &bad, &pv),
                    "operand must read its selected register"
                );
            }
            if step.b.is_some() {
                let mut bad = trace.clone();
                bad.values[row * width + 4] += Val::ONE;
                assert!(!sat(&air, &bad, &pv));
            }
        }
        // A live retained output on a row where it is neither read nor written:
        // the hold constraint, not that row's ALU, must bind this cell.
        let held = air.schedule.outputs[1];
        let row = (1..air.schedule.steps.len() - 1)
            .find(|&row| {
                let s = &air.schedule.steps[row];
                s.a != Some(held)
                    && s.b != Some(held)
                    && s.dst != held
                    && air.schedule.steps[row - 1].dst != held
            })
            .expect("non-read/non-write gap for retained input");
        let mut bad = trace.clone();
        bad.values[row * width + 12 + 4 * held] += Val::ONE;
        assert!(!sat(&air, &bad, &pv));
        for row in [0, trace.height() - 1] {
            let mut bad = trace.clone();
            bad.values[row * width + 12 + 4 * held] += Val::ONE;
            assert!(!sat(&air, &bad, &pv), "initial/terminal binding");
        }
        // Padding cannot hide a late fabricated ALU result.
        let mut bad = trace;
        bad.values[air.schedule.steps.len() * width + 8] += Val::ONE;
        assert!(!sat(&air, &bad, &pv));
    }

    #[test]
    fn reference_register_air_binds_public_inputs_outputs_and_program() {
        let (air, inputs, expected, _) = fixture(11);
        let trace = air.trace(&inputs).unwrap();
        let pv = air.public_values(&inputs, &expected).unwrap();
        for i in 0..pv.len() {
            let mut wrong = pv.clone();
            wrong[i] += Val::ONE;
            assert!(!sat(&air, &trace, &wrong), "public limb {i}");
        }
        // Coordinated forgery: regenerate ALL arithmetic and registers for a
        // different input, and even expose its matching outputs. Original input
        // PVs alone must still reject it (not an accidental stale recurrence).
        let mut other = inputs.clone();
        other[0] += E::ONE;
        let forged = air.trace(&other).unwrap();
        let tail = &forged.values[(forged.height() - 1) * forged.width()..];
        let mut forged_pv = pv.clone();
        for (i, &slot) in air.schedule.outputs.iter().enumerate() {
            forged_pv[4 * (inputs.len() + i)..4 * (inputs.len() + i + 1)]
                .copy_from_slice(&tail[12 + 4 * slot..16 + 4 * slot]);
        }
        assert!(!sat(&air, &forged, &forged_pv));
        // A trace for a different opcode schedule cannot use this AIR's ROM.
        let mut changed = air.schedule.clone();
        let row = changed
            .steps
            .iter()
            .position(|s| matches!(s.kind, Kind::Mul))
            .unwrap();
        changed.steps[row].kind = Kind::Add;
        let other_air = RegisterAir::new(changed, 100_000).unwrap();
        let forged = other_air.trace(&inputs).unwrap();
        let tail = &forged.values[(forged.height() - 1) * forged.width()..];
        for (i, &slot) in air.schedule.outputs.iter().enumerate() {
            forged_pv[4 * (inputs.len() + i)..4 * (inputs.len() + i + 1)]
                .copy_from_slice(&tail[12 + 4 * slot..16 + 4 * slot]);
        }
        assert!(!sat(&air, &forged, &forged_pv));
    }

    #[test]
    fn register_machine_rejects_bad_graphs_zero_inverse_and_oversized_materialization() {
        assert!(Schedule::compile(&[Op::Neg(0)], &[0]).is_err());
        assert!(Schedule::compile(&[Op::Constant(E::ONE)], &[]).is_err());
        assert!(Schedule::compile(&[Op::Constant(E::ONE)], &[1]).is_err());
        let (air, inputs, expected, mut values) = fixture(1);
        assert!(RegisterAir::new(air.schedule.clone(), 1).is_err());
        assert!(air.trace(&[]).is_err());
        assert!(air.public_values(&inputs, &[]).is_err());
        assert!(air.public_values(&[], &expected).is_err());
        values[3] += E::ONE;
        assert!(air.schedule.check_values(&values).is_err());
        let schedule = Schedule::compile(&[Op::Constant(E::ZERO), Op::Inverse(0)], &[1]).unwrap();
        let zero_air = RegisterAir::new(schedule, 1000).unwrap();
        assert!(zero_air.trace(&[]).is_err());
        // Even a hand-filled inverse witness cannot make 0 * inv = 1.
        let mut forged = RowMajorMatrix::new(
            vec![Val::ZERO; zero_air.schedule.height() * zero_air.schedule.width()],
            zero_air.schedule.width(),
        );
        forged.values[zero_air.schedule.width() + 8] = Val::ONE;
        let width = forged.width();
        for row in 2..forged.height() {
            forged.values[row * width + 12] = Val::ONE;
        }
        // Carry and the exposed output agree with the fabricated inverse.
        // Only the inverse relation 0 * 1 != 1 should reject this witness.
        assert!(!sat(
            &zero_air,
            &forged,
            &[Val::ONE, Val::ZERO, Val::ZERO, Val::ZERO]
        ));
        // Duplicate exported roots remain pinned and cannot be freed early.
        let same = Schedule::compile(&[Op::Constant(ext(2)), Op::Neg(0)], &[0, 1, 0]).unwrap();
        same.check_values(&[ext(2), -ext(2)]).unwrap();
    }
}
