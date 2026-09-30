//! Executable algebraic OOD relation, not a recursive verifier AIR.
//! All variable arithmetic is explicit; constants/IDFT are compile-time work.
// F2b-2a: the machine's inputs bound to a replayed hiding transcript (test-only AIR).
#[cfg(test)]
mod bind;
// F2b-2b-iii: the FRI query phase — commit-phase leaves, folds, final
// polynomial. Its layout, walks and constraint gadgets are C2's (F2b-4's
// `f2wrap` builds C2 at full size); its own component AIR is exercised only
// by its tests.
#[cfg_attr(not(test), allow(dead_code))]
mod fold;
// F2b-2b-i: the FRI Fiat–Shamir continuation from D2 (test-only AIR).
#[cfg(test)]
mod fri_fs;
// F2b composition C1: 2a + 2b-i on one lane, plus the L1 Az/Bz sums.
mod c1;
// The Keccak sponge lane both transcript components share.
#[cfg_attr(not(test), allow(dead_code))]
mod lane;
// F2b composition C2: 2b-ii + 2b-iii as per-query segments on one lane.
mod c2;
// F2b-2b-ii's register machine (the OOD identity) and its reference AIR (test-only).
mod machine;
// F2b-2b-ii: the input-batch openings and reduced opening per query. As
// with `fold`, C2 consumes its layout, walks and gadgets.
#[cfg_attr(not(test), allow(dead_code))]
mod open;
// The C1 -> C2 seam, the shared opened-term order, and R-PV's leaf PV widths.
mod seam;
// F2b-4: the full-size C1 and C2 of one real leaf proof (`qlab-bench f2wrap`).
pub(super) mod wrap;

use std::collections::HashMap;
use std::sync::Arc;

use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicAirBuilder, SymbolicExpr,
    SymbolicExpression,
};
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::PolynomialSpace;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_uni_stark::{
    check_periodic_column_lengths, get_log_num_quotient_chunks, recompose_quotient_from_chunks,
    verify_constraints, Proof, StarkGenericConfig, VerifierConstraintFolder,
};
use qlab_consensus::{Challenge as E, Config, Dft, Val, IS_ZK};
use qlab_l2::Shape;
use serde_json::{json, Value};

use super::{require, Result};

type Id = usize;
type Domain = TwoAdicMultiplicativeCoset<Val>;

#[derive(Clone, Copy, Debug)]
enum Input {
    Local(usize),
    Next(usize),
    Public(usize),
    Quotient(usize, usize),
    Alpha,
    Zeta,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Input(Input),
    Constant(E),
    Add(Id, Id),
    Sub(Id, Id),
    Neg(Id),
    Mul(Id, Id),
    // A future AIR must constrain x * inv(x) = 1, not trust this witness.
    Inverse(Id),
}

#[derive(Default)]
struct Dag {
    ops: Vec<Op>,
    shared: HashMap<usize, Id>,
}

impl Dag {
    fn push(&mut self, op: Op) -> Id {
        let id = self.ops.len();
        self.ops.push(op);
        id
    }
    fn constant(&mut self, x: impl Into<E>) -> Id {
        self.push(Op::Constant(x.into()))
    }
    fn pow2(&mut self, mut x: Id, log: usize) -> Id {
        for _ in 0..log {
            x = self.push(Op::Mul(x, x));
        }
        x
    }
    fn vanishing(&mut self, domain: Domain, zeta: Id) -> Id {
        let inv_shift = self.constant(domain.shift().inverse());
        let u = self.push(Op::Mul(zeta, inv_shift));
        let power = self.pow2(u, domain.log_size());
        let one = self.constant(E::ONE);
        self.push(Op::Sub(power, one))
    }
    fn shared_expr(&mut self, x: &Arc<SymbolicExpression<Val>>, env: &Leaves) -> Result<Id> {
        let ptr = Arc::as_ptr(x) as usize;
        if let Some(&id) = self.shared.get(&ptr) {
            return Ok(id);
        }
        let id = self.expr(x, env)?;
        self.shared.insert(ptr, id);
        Ok(id)
    }
    fn expr(&mut self, expr: &SymbolicExpression<Val>, env: &Leaves) -> Result<Id> {
        Ok(match expr {
            SymbolicExpr::Leaf(leaf) => match leaf {
                BaseLeaf::Constant(x) => self.constant(*x),
                BaseLeaf::IsFirstRow => env.selectors[0],
                BaseLeaf::IsLastRow => env.selectors[1],
                BaseLeaf::IsTransition => env.selectors[2],
                BaseLeaf::Variable(v) => {
                    let ids = match v.entry {
                        BaseEntry::Main { offset: 0 } => &env.local,
                        BaseEntry::Main { offset: 1 } => &env.next,
                        BaseEntry::Public => &env.public,
                        BaseEntry::Periodic => &env.periodic,
                        _ => return Err(format!("unsupported OOD source {:?}", v.entry)),
                    };
                    *ids.get(v.index).ok_or("OOD source index out of bounds")?
                }
            },
            SymbolicExpr::Neg { x, .. } => {
                let x = self.shared_expr(x, env)?;
                self.push(Op::Neg(x))
            }
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                let a = self.shared_expr(x, env)?;
                let b = self.shared_expr(y, env)?;
                self.push(match expr {
                    SymbolicExpr::Add { .. } => Op::Add(a, b),
                    SymbolicExpr::Sub { .. } => Op::Sub(a, b),
                    _ => Op::Mul(a, b),
                })
            }
        })
    }
}

/// The AIR dimensions the DAG is compiled for. The L2 shapes supply them from
/// [`Shape`]; F2b-2a's toy AIR supplies its own, so the transcript binding can
/// be exercised on a real hiding proof that CI can afford to generate.
#[derive(Clone, Copy, Debug)]
struct Dims {
    width: usize,
    pv_len: usize,
    log_height: usize,
    /// 1 for a hiding child (`HidingFriPcs`: trace committed at 2N, a
    /// randomizer, chunks doubled), 0 for a non-hiding one
    /// (`qlab_consensus::legacy`, F4b-2's W and gate children).
    zk: usize,
}

impl From<Shape> for Dims {
    fn from(shape: Shape) -> Self {
        Self {
            width: shape.width(),
            pv_len: shape.pv_len(),
            log_height: shape.log_height(),
            zk: IS_ZK,
        }
    }
}

struct Leaves {
    local: Vec<Id>,
    next: Vec<Id>,
    public: Vec<Id>,
    periodic: Vec<Id>,
    // Native selectors are unnormalized. Order: first, last, transition, 1/Z.
    selectors: [Id; 4],
}

/// The domain a verifier program evaluates periodic columns and the next
/// point on. [`Domains::Trace`] is the only correct one: the ORIGINAL trace
/// domain of size N (uni-stark evaluates periodic columns and ζ·g_N on
/// it). The other two are stage-0's "g_N versus the doubled-domain shift"
/// confusions with the committed domain of size 2N, compiled on purpose so
/// F2b-5's negatives can show both the native comparison and C1 refusing
/// them (issue #750).
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum Domains {
    Trace,
    /// Periodic columns interpolated over the 2N-point committed domain.
    PeriodicOn2N,
    /// The next point ζ·g_2N.
    NextOn2N,
}

struct Program {
    /// The child's hiding flag (`Dims::zk`).
    zk: usize,
    schedule: machine::Schedule,
    dag: Dag,
    leaves: Leaves,
    original: Domain,
    chunk_domains: Vec<Domain>,
    folded: Id,
    quotient: Id,
    residual: Id,
    next_point: Id,
}

#[derive(Clone)]
struct Inputs {
    local: Vec<E>,
    next: Vec<E>,
    public: Vec<Val>,
    chunks: Vec<Vec<E>>,
    alpha: E,
    zeta: E,
}

impl Program {
    fn compile<A: Air<SymbolicAirBuilder<Val>>>(shape: Shape, air: &A) -> Result<Self> {
        Self::compile_dims(shape.into(), air)
    }

    fn compile_dims<A: Air<SymbolicAirBuilder<Val>>>(dims: Dims, air: &A) -> Result<Self> {
        Self::compile_on(dims, air, Domains::Trace)
    }

    fn compile_on<A: Air<SymbolicAirBuilder<Val>>>(
        dims: Dims,
        air: &A,
        domains: Domains,
    ) -> Result<Self> {
        let layout = AirLayout::from_air::<Val>(air);
        require(layout.main_width == dims.width, "OOD AIR width mismatch")?;
        require(
            layout.num_public_values == dims.pv_len,
            "OOD AIR PV mismatch",
        )?;
        require(
            layout.preprocessed_width == 0,
            "preprocessed OOD AIR unsupported",
        )?;
        let original = Domain::new(Val::ONE, dims.log_height).ok_or("original domain")?;
        let zk = dims.zk;
        require(zk <= 1, "zk is 0 or 1")?;
        let committed = Domain::new(Val::ONE, dims.log_height + zk).ok_or("committed domain")?;
        let log_q = get_log_num_quotient_chunks::<Val, _>(air, layout, zk);
        if zk == IS_ZK {
            require(log_q + IS_ZK == 3, "expected eight hiding quotient chunks")?;
        }
        let chunk_domains = committed
            .create_disjoint_domain(1 << (dims.log_height + zk + log_q))
            .split_domains(1 << (log_q + zk));
        let periodic = air.periodic_columns();
        check_periodic_column_lengths(&periodic, original.size())
            .map_err(|e| format!("periodic columns: {e:?}"))?;
        require(
            periodic.len() == layout.num_periodic_columns,
            "periodic count mismatch",
        )?;
        let mut dag = Dag::default();
        let local = (0..dims.width)
            .map(|i| dag.push(Op::Input(Input::Local(i))))
            .collect();
        let next = (0..dims.width)
            .map(|i| dag.push(Op::Input(Input::Next(i))))
            .collect();
        let public = (0..dims.pv_len)
            .map(|i| dag.push(Op::Input(Input::Public(i))))
            .collect();
        let alpha = dag.push(Op::Input(Input::Alpha));
        let zeta = dag.push(Op::Input(Input::Zeta));
        let zero = dag.constant(E::ZERO);
        let one = dag.constant(E::ONE);
        let vanishing = dag.vanishing(original, zeta);
        let inv_vanishing = dag.push(Op::Inverse(vanishing));
        let first_denom = dag.push(Op::Sub(zeta, one));
        let first_inv = dag.push(Op::Inverse(first_denom));
        let first = dag.push(Op::Mul(vanishing, first_inv));
        let last_point = dag.constant(original.subgroup_generator().inverse());
        let transition = dag.push(Op::Sub(zeta, last_point));
        let last_inv = dag.push(Op::Inverse(transition));
        let last = dag.push(Op::Mul(vanishing, last_inv));
        let gen = dag.constant(match domains {
            Domains::NextOn2N => committed.subgroup_generator(),
            _ => original.subgroup_generator(),
        });
        let next_point = dag.push(Op::Mul(zeta, gen));
        let mut periodic_ids = Vec::new();
        let mut period_points = HashMap::new();
        let log_domain = match domains {
            Domains::PeriodicOn2N => committed.log_size(),
            _ => dims.log_height,
        };
        for col in periodic {
            let log_period = col.len().trailing_zeros() as usize;
            let point = *period_points
                .entry(log_period)
                .or_insert_with(|| dag.pow2(zeta, log_domain - log_period));
            // Original domain has shift one. Coefficients are public AIR
            // constants; IDFT happens during compilation, never in the witness.
            let coefficients = Dft::default().idft(col);
            let mut value = zero;
            for c in coefficients.into_iter().rev() {
                let c = dag.constant(c);
                let product = dag.push(Op::Mul(value, point));
                value = dag.push(Op::Add(product, c));
            }
            periodic_ids.push(value);
        }
        let leaves = Leaves {
            local,
            next,
            public,
            periodic: periodic_ids,
            selectors: [first, last, transition, inv_vanishing],
        };
        let constraints = get_symbolic_constraints::<Val, _>(air, layout);
        let mut folded = zero;
        for constraint in &constraints {
            let term = dag.expr(constraint, &leaves)?;
            let product = dag.push(Op::Mul(folded, alpha));
            folded = dag.push(Op::Add(product, term));
        }
        let chunk_vanishings: Vec<_> = chunk_domains
            .iter()
            .map(|&d| dag.vanishing(d, zeta))
            .collect();
        let mut quotient = zero;
        for (i, domain) in chunk_domains.iter().enumerate() {
            let mut weight = one;
            for (j, other) in chunk_domains.iter().enumerate() {
                if i != j {
                    let denominator = other.vanishing_poly_at_point(domain.first_point());
                    let inv = denominator
                        .try_inverse()
                        .ok_or("overlapping quotient domains")?;
                    let inv = dag.constant(inv);
                    let factor = dag.push(Op::Mul(chunk_vanishings[j], inv));
                    weight = dag.push(Op::Mul(weight, factor));
                }
            }
            let mut chunk = zero;
            for limb in 0..4 {
                let value = dag.push(Op::Input(Input::Quotient(i, limb)));
                let basis = dag.constant(
                    <E as BasedVectorSpace<Val>>::ith_basis_element(limb)
                        .ok_or("extension basis missing")?,
                );
                let product = dag.push(Op::Mul(value, basis));
                chunk = dag.push(Op::Add(chunk, product));
            }
            let term = dag.push(Op::Mul(weight, chunk));
            quotient = dag.push(Op::Add(quotient, term));
        }
        let lhs = dag.push(Op::Mul(folded, inv_vanishing));
        let residual = dag.push(Op::Sub(lhs, quotient));
        // Arc addresses only identify this compilation's symbolic graph.
        dag.shared.clear();
        let schedule = machine::Schedule::compile(&dag.ops, &[residual, next_point])?;
        Ok(Self {
            zk,
            schedule,
            dag,
            leaves,
            original,
            chunk_domains,
            folded,
            quotient,
            residual,
            next_point,
        })
    }

    fn evaluate(&self, input: &Inputs) -> Result<Vec<E>> {
        require(
            input.local.len() == self.leaves.local.len()
                && input.next.len() == self.leaves.next.len()
                && input.public.len() == self.leaves.public.len()
                && input.chunks.len() == self.chunk_domains.len()
                && input.chunks.iter().all(|c| c.len() == 4),
            "OOD input dimensions",
        )?;
        let mut values: Vec<E> = Vec::with_capacity(self.dag.ops.len());
        for op in &self.dag.ops {
            let value = match *op {
                Op::Constant(c) => c,
                Op::Input(i) => match i {
                    Input::Local(i) => input.local[i],
                    Input::Next(i) => input.next[i],
                    Input::Public(i) => input.public[i].into(),
                    Input::Quotient(i, j) => input.chunks[i][j],
                    Input::Alpha => input.alpha,
                    Input::Zeta => input.zeta,
                },
                Op::Add(a, b) => values[a] + values[b],
                Op::Sub(a, b) => values[a] - values[b],
                Op::Neg(a) => -values[a],
                Op::Mul(a, b) => values[a] * values[b],
                Op::Inverse(a) => values[a].try_inverse().ok_or("OOD inverse of zero")?,
            };
            values.push(value);
        }
        Ok(values)
    }

    fn report(&self) -> Value {
        let mut counts = [0usize; 7];
        for op in &self.dag.ops {
            counts[match op {
                Op::Input(_) => 0,
                Op::Constant(_) => 1,
                Op::Add(..) => 2,
                Op::Sub(..) => 3,
                Op::Neg(_) => 4,
                Op::Mul(..) => 5,
                Op::Inverse(_) => 6,
            }] += 1;
        }
        json!({"evidence": "P", "source": "executable extension-field OOD DAG; pointer sharing only",
            "input_reads": counts[0], "constants": counts[1], "add": counts[2],
            "sub": counts[3], "neg": counts[4], "mul": counts[5], "inverse": counts[6],
            "register_schedule": self.schedule.report(),
            "rom_encoding": super::price::rom_encoding(self.schedule.rom_width(),
                self.schedule.height().trailing_zeros() as usize),
            "nodes": self.dag.ops.len(), "original_log_height": self.original.log_size(),
            "quotient_chunks": self.chunk_domains.len(), "periodic_columns": self.leaves.periodic.len(),
            "complete_verifier_layout": false, "memory_gate_pass": false})
    }
}

/// Compare independent native domain/recomposition/folder routines with the DAG.
fn compare_native<A>(program: &Program, air: &A, inputs: &Inputs) -> Result<Vec<E>>
where
    A: for<'a> Air<VerifierConstraintFolder<'a, Config>>,
{
    compare_native_on::<Config, A>(program, air, inputs)
}

/// [`compare_native`] under any config on this field and PCS domain — the
/// non-hiding (`qlab_consensus::legacy`) children of F4b-2 (lab #782).
fn compare_native_on<SC, A>(program: &Program, air: &A, inputs: &Inputs) -> Result<Vec<E>>
where
    SC: p3_uni_stark::StarkGenericConfig<Challenge = E>,
    SC::Pcs: p3_commit::Pcs<E, SC::Challenger, Domain = Domain>,
    A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    let values = program.evaluate(inputs)?;
    program.schedule.check_values(&values)?;
    let periodic: Vec<E> = air
        .periodic_columns()
        .iter()
        .map(|c| program.original.evaluate_periodic_column_at(c, inputs.zeta))
        .collect();
    for (&id, &expected) in program.leaves.periodic.iter().zip(&periodic) {
        require(values[id] == expected, "periodic DAG/native mismatch")?;
    }
    let sels = program.original.selectors_at_point(inputs.zeta);
    for (&id, expected) in program.leaves.selectors.iter().zip([
        sels.is_first_row,
        sels.is_last_row,
        sels.is_transition,
        sels.inv_vanishing,
    ]) {
        require(values[id] == expected, "selector DAG/native mismatch")?;
    }
    require(
        Some(values[program.next_point]) == program.original.next_point(inputs.zeta),
        "next-point DAG/native mismatch",
    )?;
    let quotient = recompose_quotient_from_chunks::<SC>(
        &program.chunk_domains,
        &inputs.chunks,
        inputs.zeta,
    );
    require(
        values[program.quotient] == quotient,
        "quotient DAG/native mismatch",
    )?;
    // Ask the native folder to verify against the DAG's computed left side.
    // This checks folding even for synthetic inputs with a nonzero residual.
    verify_constraints::<SC, _, ()>(
        air,
        &inputs.local,
        &inputs.next,
        None,
        None,
        &periodic,
        &inputs.public,
        program.original,
        inputs.zeta,
        inputs.alpha,
        values[program.folded] * sels.inv_vanishing,
    )
    .map_err(|e| format!("AIR fold DAG/native mismatch: {e:?}"))?;
    Ok(values)
}

fn proof_inputs(shape: Shape, proof: &Proof<Config>, pvs: &[Val]) -> Result<Inputs> {
    proof_inputs_dims(shape.into(), proof, pvs)
}

fn proof_inputs_dims(dims: Dims, proof: &Proof<Config>, pvs: &[Val]) -> Result<Inputs> {
    require(
        proof.degree_bits == dims.log_height + IS_ZK,
        "OOD proof degree",
    )?;
    require(
        proof.opened_values.preprocessed_local.is_none()
            && proof.opened_values.preprocessed_next.is_none(),
        "unexpected preprocessed OOD values",
    )?;
    let config = crate::f2::f2_config();
    let mut challenger = config.initialise_challenger();
    // uni-stark 0.6.1 prefix: committed degree, original degree, prep width.
    challenger.observe(Val::from_usize(proof.degree_bits));
    challenger.observe(Val::from_usize(dims.log_height));
    challenger.observe(Val::ZERO);
    challenger.observe(proof.commitments.trace.clone());
    challenger.observe_slice(pvs);
    let alpha = challenger.sample_algebra_element();
    challenger.observe(proof.commitments.quotient_chunks.clone());
    challenger.observe(
        proof
            .commitments
            .random
            .clone()
            .ok_or("missing randomizer commitment")?,
    );
    let zeta = challenger.sample_algebra_element();
    Ok(Inputs {
        local: proof.opened_values.trace_local.clone(),
        next: proof
            .opened_values
            .trace_next
            .clone()
            .ok_or("missing next-row opening")?,
        public: pvs.to_vec(),
        chunks: proof.opened_values.quotient_chunks.clone(),
        alpha,
        zeta,
    })
}

/// [`proof_inputs_dims`] for a **non-hiding** child (`qlab_consensus::legacy`,
/// lane `cfg`): the trace committed at N, no randomizer commitment before ζ
/// (p3-uni-stark 0.6.1's verifier with `is_zk = 0`). F4b-2 (lab #782).
fn proof_inputs_legacy(
    dims: Dims,
    proof: &Proof<qlab_consensus::legacy::LegacyNonHidingConfig>,
    pvs: &[Val],
    cfg: &qlab_consensus::FriCfg,
) -> Result<Inputs> {
    use p3_uni_stark::StarkGenericConfig;
    require(dims.zk == 0, "a legacy proof is non-hiding")?;
    require(proof.degree_bits == dims.log_height, "OOD proof degree")?;
    require(
        proof.opened_values.preprocessed_local.is_none()
            && proof.opened_values.preprocessed_next.is_none()
            && proof.opened_values.random.is_none()
            && proof.commitments.random.is_none(),
        "unexpected preprocessed or randomizer values on a non-hiding proof",
    )?;
    let config = qlab_consensus::legacy::make_legacy_config_with(cfg);
    let mut challenger = config.initialise_challenger();
    challenger.observe(Val::from_usize(proof.degree_bits));
    challenger.observe(Val::from_usize(dims.log_height));
    challenger.observe(Val::ZERO);
    challenger.observe(proof.commitments.trace.clone());
    challenger.observe_slice(pvs);
    let alpha = challenger.sample_algebra_element();
    challenger.observe(proof.commitments.quotient_chunks.clone());
    let zeta = challenger.sample_algebra_element();
    Ok(Inputs {
        local: proof.opened_values.trace_local.clone(),
        next: proof
            .opened_values
            .trace_next
            .clone()
            .ok_or("missing next-row opening")?,
        public: pvs.to_vec(),
        chunks: proof.opened_values.quotient_chunks.clone(),
        alpha,
        zeta,
    })
}

/// [P] F4b-2's census of a NON-hiding child's OOD component (a `zk = 0`
/// C1 on lane `cfg`) for any AIR: the DAG, the register machine and C1's
/// size, compiled from the AIR's symbolic constraints; no proof, no trace.
pub(crate) fn ood_census<A: Air<SymbolicAirBuilder<Val>>>(
    width: usize,
    pv_len: usize,
    log_height: usize,
    air: &A,
    cfg: &qlab_consensus::FriCfg,
) -> Result<Value> {
    let program = Program::compile_dims(Dims { width, pv_len, log_height, zk: 0 }, air)?;
    let (perms, rows, cols, rom, c1_pvs) = c1::c1_dims(&program, cfg)?;
    let s = &program.schedule;
    // The child's transcript order for the ζ openings (p3's PCS observes
    // trace local, trace next, then each quotient chunk); PVs, α and ζ are
    // known before flush 2.
    let arrival = |i: Input| -> u64 {
        match i {
            Input::Public(_) | Input::Alpha | Input::Zeta => 0,
            Input::Local(c) => 1 + c as u64,
            Input::Next(c) => (1 << 24) + c as u64,
            Input::Quotient(k, j) => (2 << 24) + ((k as u64) << 12) + j as u64,
        }
    };
    let regs = machine::lever_registers(&program.dag.ops, &[program.residual, program.next_point], &arrival);
    require(regs.current == s.registers(), "lever count must reproduce the compiled register count")?;
    let mut dag = program.report();
    // The DAG report's ROM-encoding block prices F2's HIDING L2-lane PCS
    // geometry; it does not describe a zk = 0 child.
    dag["rom_encoding"] = json!({"omitted": "F2's block prices the hiding L2-lane PCS geometry; not applicable to a zk = 0 child"});
    if let Some(r) = dag.get_mut("register_schedule").and_then(Value::as_object_mut) {
        r.remove("input_sources");
    }
    Ok(json!({"evidence": "P", "zk": 0, "child": {"width": width, "public_values": pv_len, "log_height": log_height},
        "quotient_chunks": program.chunk_domains.len(), "dag": dag,
        "machine": {"registers_width": s.width(), "rom_width": rom, "inputs": s.inputs().len(), "height": s.height(),
            "extension_registers": s.registers()},
        "c1": {"lane_perms": perms, "rows": rows, "columns": cols, "rom_columns": rom, "public_values": c1_pvs},
        "lever_registers": {"current": regs.current, "held_operands": regs.held_operands, "streamed": regs.streamed}}))
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// One FNV-1a step over a 64-bit word, byte by byte.
fn fnv(mut h: u64, word: u64) -> u64 {
    for b in word.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// A structural hash of an AIR's symbolic constraints: every node's kind,
/// operands, variable entry and index, constants' canonical values, in
/// constraint order; shared subtrees are hashed once (memoized on the
/// node), iteratively so a deep sum cannot overflow a test thread's stack.
fn constraint_hash(constraints: &[p3_air::symbolic::SymbolicExpression<Val>]) -> u64 {
    use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
    use p3_field::PrimeField32;
    type Node = SymbolicExpression<Val>;
    let mut memo: HashMap<*const Node, u64> = HashMap::new();
    let kids = |e: &Node| -> Vec<*const Node> {
        match e {
            SymbolicExpr::Leaf(_) => vec![],
            SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
                vec![Arc::as_ptr(x), Arc::as_ptr(y)]
            }
            SymbolicExpr::Neg { x, .. } => vec![Arc::as_ptr(x)],
        }
    };
    let mut total = FNV_OFFSET;
    for c in constraints {
        let root: *const Node = c;
        let mut stack = vec![(root, false)];
        while let Some((p, exit)) = stack.pop() {
            if memo.contains_key(&p) {
                continue;
            }
            // SAFETY: every pointer is `root` or an `Arc` child reached from
            // it; `constraints` owns them all for this whole function.
            let e = unsafe { &*p };
            let ks = kids(e);
            if !exit {
                stack.push((p, true));
                stack.extend(ks.iter().map(|&k| (k, false)));
                continue;
            }
            let (tag, sub) = match e {
                SymbolicExpr::Leaf(l) => match l {
                    BaseLeaf::Variable(v) => {
                        let entry = match v.entry {
                            BaseEntry::Preprocessed { offset } => (1u64 << 32) | offset as u64,
                            BaseEntry::Main { offset } => (2u64 << 32) | offset as u64,
                            BaseEntry::Periodic => 3u64 << 32,
                            BaseEntry::Public => 4u64 << 32,
                        };
                        (1, vec![entry, v.index as u64])
                    }
                    BaseLeaf::IsFirstRow => (2, vec![]),
                    BaseLeaf::IsLastRow => (3, vec![]),
                    BaseLeaf::IsTransition => (4, vec![]),
                    BaseLeaf::Constant(v) => (5, vec![u64::from(v.as_canonical_u32())]),
                },
                SymbolicExpr::Add { .. } => (6, vec![]),
                SymbolicExpr::Sub { .. } => (7, vec![]),
                SymbolicExpr::Neg { .. } => (8, vec![]),
                SymbolicExpr::Mul { .. } => (9, vec![]),
            };
            let mut h = fnv(FNV_OFFSET, tag);
            for w in sub.into_iter().chain(ks.iter().map(|k| memo[k])) {
                h = fnv(h, w);
            }
            memo.insert(p, h);
        }
        total = fnv(total, memo[&root]);
    }
    total
}

/// Lab #782 condition (4): the hiding C1's layout fingerprint for a real L2
/// shape on the L2 lane — width, public values, ROM columns, constraint
/// count and degree, a structural hash of every constraint and a hash of
/// the ROM. The same function on `main` and on F4b-2's tree must print the
/// same object: `zk` must leave F2's hiding path byte-for-byte.
pub(crate) fn hiding_c1_fingerprint(shape: Shape) -> Result<Value> {
    use p3_air::BaseAir;
    fn go<A: Air<SymbolicAirBuilder<Val>>>(shape: Shape, air: &A) -> Result<Value> {
        let program = Program::compile(shape, air)?;
        let c1 = c1::C1Air::new(&program, &crate::f2::F2_LANE, 8 << 30)?;
        let cs = p3_air::symbolic::get_symbolic_constraints::<Val, _>(&c1, p3_air::symbolic::AirLayout::from_air::<Val>(&c1));
        let degree = cs.iter().map(|c| c.degree_multiple()).max().unwrap_or(0);
        Ok(json!({"shape": format!("{shape:?}"), "width": c1.width(), "public_values": c1.num_public_values(),
            "rom_columns": c1.num_periodic_columns(), "constraints": cs.len(), "max_degree": degree,
            "constraint_hash": format!("{:016x}", constraint_hash(&cs)), "rom_hash": format!("{:016x}", c1.rom_hash())}))
    }
    match shape {
        Shape::S => go(shape, &qlab_l2::verifier_air_s()),
        Shape::P => go(shape, &qlab_l2::verifier_air_p()),
        Shape::R => go(shape, &qlab_l2::verifier_air_r()),
    }
}

/// F4b-2 (lab #782): one real non-hiding child's OOD component, built.
pub(crate) struct LegacyOod {
    /// Compile, native agreement, build, scan and prove records.
    pub(crate) report: Value,
    /// C1's exported ζ-openings flush digest (16 u16 limbs).
    pub(crate) f2dig: Vec<Val>,
    /// Every cap C1 re-exposes, as u16 limbs in cap order.
    pub(crate) caps: Vec<Val>,
    /// The inner PVs C1 re-exposes.
    pub(crate) inner_pvs: Vec<Val>,
    /// Every requested stage held (native agreement, scan, prove + verify).
    pub(crate) ok: bool,
}

/// F4b-2 (lab #782): the OOD component of one real **non-hiding** child —
/// the `zk = 0` C1 for `proof` (child lane `child_cfg`). The compiled DAG is
/// first checked against p3's own verifier fold at ζ (residual zero), then
/// C1 is built from the proof; `check` scans every row, `outer` proves and
/// natively verifies it on that lane (non-hiding, as F2's components).
#[allow(clippy::too_many_arguments)]
pub(crate) fn legacy_ood<A>(
    (width, pv_len, log_height): (usize, usize, usize),
    air: &A,
    proof: &Proof<qlab_consensus::legacy::LegacyNonHidingConfig>,
    pvs: &[Val],
    child_cfg: &qlab_consensus::FriCfg,
    check: bool,
    outer: Option<&qlab_consensus::FriCfg>,
    max_cells: usize,
) -> Result<LegacyOod>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, qlab_consensus::legacy::LegacyNonHidingConfig>>,
{
    let dims = Dims { width, pv_len, log_height, zk: 0 };
    let t = std::time::Instant::now();
    let program = Program::compile_dims(dims, air)?;
    let inputs = proof_inputs_legacy(dims, proof, pvs, child_cfg)?;
    let values = compare_native_on::<qlab_consensus::legacy::LegacyNonHidingConfig, A>(&program, air, &inputs)?;
    require(values[program.residual] == E::ZERO, "OOD relation mismatch on an honest child")?;
    let compile_s = t.elapsed().as_secs_f64();
    let (perms, rows, cols, rom, _) = c1::c1_dims(&program, child_cfg)?;
    let t = std::time::Instant::now();
    // X1 (lab #782 review): a trace that will be proved reserves the outer
    // lane's blowup up front, as `m4gate::build_gate_trace` does; a late
    // reserve copies the trace and inflates the peak.
    let reserve = outer.map_or(0, |o| o.log_blowup);
    let c1::Honest { air: c1_air, trace, pvs: c1_pvs, .. } =
        c1::honest_legacy(&program, &inputs, proof, pvs, child_cfg, max_cells, reserve)?;
    let build_s = t.elapsed().as_secs_f64();
    let planned = (cols, rows, rom);
    let f2dig = c1_air.f2dig_limbs(&c1_pvs).ok_or("a zk = 0 C1 exports its F2 digest")?.to_vec();
    let caps = c1_air.cap_limbs(&c1_pvs).to_vec();
    let inner_pvs = c1_pvs[..c1_air.inner_pv_len()].to_vec();
    let mut ok = true;
    let mut report = json!({"evidence": "M", "zk": 0, "dag": program.report(),
        "native_fold_agrees_residual_zero": true, "compile_and_native_seconds": compile_s,
        "c1_p": {"lane_perms": perms, "rows": rows, "columns": cols, "rom_columns": rom},
        "build_seconds": build_s, "extra_capacity_bits": reserve,
        "exposes_every_inner_pv": inner_pvs == pvs});
    ok &= inner_pvs == pvs;
    if check {
        let scan = wrap::scan(&c1_air, &trace, &c1_pvs);
        ok &= scan["pass"] == true;
        report["scan"] = scan;
        // Condition (1)'s one-side negative on C1's side: one exported limb
        // moved, the same trace must no longer satisfy C1.
        let mut moved = c1_pvs.clone();
        let o = c1_air.f2dig_offset().ok_or("a zk = 0 C1 exports its F2 digest")?;
        moved[o + 5] += Val::ONE;
        let neg = wrap::scan(&c1_air, &trace, &moved);
        ok &= neg["pass"] == false;
        report["f2dig_perturbed"] = json!({"limb": 5, "rejected": neg["pass"] == false,
            "violating_rows": neg["violating_rows"], "first_violations": neg["first_violations"]});
    }
    report["component"] = match outer {
        Some(o) => {
            let config = qlab_consensus::legacy::make_legacy_config_with(o);
            let r = wrap::prove_component(&c1_air, trace, &c1_pvs, &config, planned);
            ok &= r["native_verified"] == true;
            r
        }
        None => wrap::built(&c1_air, &trace, planned).0,
    };
    Ok(LegacyOod { report, f2dig, caps, inner_pvs, ok })
}

pub(super) fn verify_relation(shape: Shape, proof: &Proof<Config>, pvs: &[Val]) -> Result<Value> {
    let inputs = proof_inputs(shape, proof, pvs)?;
    fn check<A>(shape: Shape, air: &A, inputs: &Inputs) -> Result<Value>
    where
        A: Air<SymbolicAirBuilder<Val>> + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
    {
        let program = Program::compile(shape, air)?;
        let values = compare_native(&program, air, inputs)?;
        require(values[program.residual] == E::ZERO, "OOD relation mismatch")?;
        Ok(json!({"native_algebra_agrees": true, "residual_zero": true,
            "arithmetic": program.report(), "is_recursive_air": false}))
    }
    match shape {
        Shape::S => check(shape, &qlab_l2::verifier_air_s(), &inputs),
        Shape::P => check(shape, &qlab_l2::verifier_air_p(), &inputs),
        Shape::R => check(shape, &qlab_l2::verifier_air_r(), &inputs),
    }
}

/// [P] The register machine's dimensions for `shape` — what
/// `price::composed_c1` needs from the compiled OOD program.
pub(super) fn machine_dims(shape: Shape) -> Result<super::price::MachineDims> {
    let program = match shape {
        Shape::S => Program::compile(shape, &qlab_l2::verifier_air_s())?,
        Shape::P => Program::compile(shape, &qlab_l2::verifier_air_p())?,
        Shape::R => Program::compile(shape, &qlab_l2::verifier_air_r())?,
    };
    let s = &program.schedule;
    Ok(super::price::MachineDims {
        width: s.width(),
        rom_width: s.rom_width(),
        inputs: s.input_count(),
        height: s.height(),
    })
}

pub(super) fn price(shape: Shape) -> Result<Value> {
    Ok(match shape {
        Shape::S => Program::compile(shape, &qlab_l2::verifier_air_s())?.report(),
        Shape::P => Program::compile(shape, &qlab_l2::verifier_air_p())?.report(),
        Shape::R => Program::compile(shape, &qlab_l2::verifier_air_r())?.report(),
    })
}

#[cfg(test)]
pub(super) fn check_real_mutations(shape: Shape, proof: &Proof<Config>, pvs: &[Val]) {
    fn check<A>(shape: Shape, air: &A, inputs: Inputs)
    where
        A: Air<SymbolicAirBuilder<Val>> + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
    {
        let p = Program::compile(shape, air).unwrap();
        assert_eq!(
            compare_native(&p, air, &inputs).unwrap()[p.residual],
            E::ZERO
        );
        // Every coefficient of every quotient chunk must be used as an
        // extension-valued opening, then multiplied by its extension basis.
        for chunk in 0..8 {
            for limb in 0..4 {
                let mut bad = inputs.clone();
                bad.chunks[chunk][limb] += E::ONE;
                assert_ne!(compare_native(&p, air, &bad).unwrap()[p.residual], E::ZERO);
            }
        }
        // A PV can be metadata unused by the AIR. Check native agreement for
        // each candidate, and require an affected candidate in each input class.
        for kind in 0..5 {
            let count = match kind {
                0 | 1 => inputs.local.len(),
                2 => inputs.public.len(),
                _ => 1,
            };
            let mut affected = false;
            for i in 0..count {
                let mut bad = inputs.clone();
                match kind {
                    0 => bad.local[i] += E::ONE,
                    1 => bad.next[i] += E::ONE,
                    2 => bad.public[i] += Val::ONE,
                    3 => bad.alpha += E::ONE,
                    _ => bad.zeta += E::ONE,
                }
                if compare_native(&p, air, &bad).unwrap()[p.residual] != E::ZERO {
                    affected = true;
                    break;
                }
            }
            assert!(affected, "OOD mutation class {kind} was never consumed");
        }
    }
    let inputs = proof_inputs(shape, proof, pvs).unwrap();
    match shape {
        Shape::S => check(shape, &qlab_l2::verifier_air_s(), inputs),
        Shape::P => check(shape, &qlab_l2::verifier_air_p(), inputs),
        Shape::R => check(shape, &qlab_l2::verifier_air_r(), inputs),
    }
}

/// F2b-5's P3 negatives (`c2::tests::p3_last_round_negatives`), on the P3
/// proof the census test already holds.
#[cfg(test)]
pub(super) fn check_p3_last_round(proof: &Proof<Config>, pvs: &[Val]) {
    c2::tests::p3_last_round_negatives(proof, pvs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_air::symbolic::SymbolicVariable;

    fn extension(n: usize) -> E {
        E::from_basis_coefficients_fn(|i| Val::from_usize(n * 17 + i * 31 + 1))
    }

    fn inputs(shape: Shape, seed: usize) -> Inputs {
        Inputs {
            local: (0..shape.width()).map(|i| extension(i + seed)).collect(),
            next: (0..shape.width())
                .map(|i| extension(i + seed + 1000))
                .collect(),
            public: (0..shape.pv_len())
                .map(|i| Val::from_usize(i + seed))
                .collect(),
            chunks: (0..8)
                .map(|i| (0..4).map(|j| extension(seed + 4 * i + j)).collect())
                .collect(),
            alpha: extension(seed + 7),
            zeta: extension(seed + 13),
        }
    }

    /// Lab #782 F4b-2: the `zk = 0` compile of W's AIR and of `m4gate`'s own
    /// AIR (verifying a K = 16 b4 W) agrees with p3's NON-hiding verifier
    /// algebra at ζ (commit at N, two quotient chunks, no randomizer), on
    /// synthetic inputs; moving every opening moves the residual.
    #[test]
    fn non_hiding_w_and_gate_dags_match_native_ood_algebra() {
        type L = qlab_consensus::legacy::LegacyNonHidingConfig;
        fn check<A>(dims: Dims, air: &A)
        where
            A: Air<SymbolicAirBuilder<Val>> + for<'a> Air<VerifierConstraintFolder<'a, L>>,
        {
            let p = Program::compile_dims(dims, air).unwrap();
            assert_eq!((p.zk, p.chunk_domains.len()), (0, 2));
            for seed in [3, 71] {
                let inputs = Inputs {
                    local: (0..dims.width).map(|i| extension(i + seed)).collect(),
                    next: (0..dims.width).map(|i| extension(i + seed + 5000)).collect(),
                    public: (0..dims.pv_len).map(|i| Val::from_usize(i + seed)).collect(),
                    chunks: (0..2).map(|i| (0..4).map(|j| extension(seed + 4 * i + j)).collect()).collect(),
                    alpha: extension(seed + 7),
                    zeta: extension(seed + 13),
                };
                let values = compare_native_on::<L, A>(&p, air, &inputs).unwrap();
                let mut moved = inputs.clone();
                for v in moved.local.iter_mut().chain(moved.next.iter_mut()) {
                    *v += extension(41);
                }
                let got = compare_native_on::<L, A>(&p, air, &moved).unwrap();
                assert_ne!(got[p.residual], values[p.residual]);
            }
        }
        use crate::f4::wleaf::{WAir, W_PV_LEN, W_WIDTH};
        check(Dims { width: W_WIDTH, pv_len: W_PV_LEN, log_height: 15, zk: 0 }, &WAir::new(1));
        let shape = crate::f4::gate::w_gate_shape(18, crate::f3::bench::Outer::B4);
        let width = crate::m4gate::GateLayout::from_shape(&shape).gate_width;
        let (pv_len, air) = (shape.n_opvs(), crate::m4gate::VerifierGateAir::new_with_shape(shape));
        check(Dims { width, pv_len, log_height: 18, zk: 0 }, &air);
    }

    /// Lab #782 F4b-2, the smallest real zk = 0 child end to end: a
    /// non-hiding proof of the toy (log 8, L2 lane parameters) → the DAG
    /// agrees with p3's own fold at ζ (residual zero) → C1 built from the
    /// proof satisfies every row, refuses one moved F2-digest limb, proves
    /// and verifies; its exported F2 digest and caps are byte-identical to
    /// the `m4gate` walk's flush 2 and caps (condition (1) at toy scale; the
    /// real W is the box's `f4ood --node`).
    #[test]
    fn legacy_toy_ood_component_holds_and_matches_the_query_walk() {
        use super::lane::toy::{toy_legacy_proof, Toy};
        let cfg = crate::f2::F2_LANE;
        let (proof, pvs) = toy_legacy_proof(8);
        let ood = legacy_ood((2, 2, 8), &Toy, &proof, &pvs, &cfg, true, Some(&cfg), 64 << 20).unwrap();
        assert!(ood.ok, "{}", ood.report);
        assert_eq!(ood.report["scan"]["pass"], true);
        assert_eq!(ood.report["f2dig_perturbed"]["rejected"], true);
        assert_eq!(ood.report["component"]["native_verified"], true);
        let limbs = |d: &[u8]| -> Vec<Val> { d.chunks(2).map(|c| Val::from_u32(u32::from(u16::from_le_bytes([c[0], c[1]])))).collect() };
        let sched = crate::m4gaterec::walk_with_cfg(&proof, &pvs, &cfg);
        assert_eq!(ood.f2dig, limbs(&sched.flushes[2].digest), "C1's F2 digest vs the query walk's flush 2");
        let caps: Vec<Val> = sched.caps.iter().flatten().flat_map(|d| (0..16).map(move |j| Val::from_u32(((d[j / 4] >> (16 * (j % 4))) & 0xffff) as u32))).collect();
        assert_eq!(ood.caps, caps, "C1's caps vs the query walk's, limb for limb");
        assert_eq!(ood.inner_pvs, pvs);
    }

    /// Lab #782 condition (4): the hiding C1 of shape S is main's, byte for
    /// byte. The object below was printed by `f4ood --fingerprint s` on
    /// main aaa5753 (a scratch tree carrying only this helper) and on
    /// F4b-2's tree, and the two outputs were identical (PR body).
    #[test]
    fn c1_hiding_layout_fingerprint_is_mains() {
        let fp = hiding_c1_fingerprint(Shape::S).unwrap();
        assert_eq!(
            fp,
            json!({"constraint_hash": "e9f3034b4eec9370", "constraints": 21385, "max_degree": 3,
                "public_values": 1151, "rom_columns": 2227, "rom_hash": "b893fee1ac3e506c",
                "shape": "S", "width": 11746})
        );
    }

    #[test]
    fn all_shape_dags_match_native_ood_algebra_on_synthetic_inputs() {
        fn check<A>(shape: Shape, air: &A)
        where
            A: Air<SymbolicAirBuilder<Val>> + for<'a> Air<VerifierConstraintFolder<'a, Config>>,
        {
            let p = Program::compile(shape, air).unwrap();
            for seed in [1, 29, 113] {
                let inputs = inputs(shape, seed);
                let values = compare_native(&p, air, &inputs).unwrap();
                let wrong_domain = Domain::new(Val::ONE, shape.log_height() + 1).unwrap();
                assert_ne!(
                    values[p.next_point],
                    wrong_domain.next_point(inputs.zeta).unwrap()
                );
                let wrong_periodic: Vec<E> = air
                    .periodic_columns()
                    .iter()
                    .map(|c| wrong_domain.evaluate_periodic_column_at(c, inputs.zeta))
                    .collect();
                assert!(
                    p.leaves
                        .periodic
                        .iter()
                        .zip(wrong_periodic)
                        .any(|(&id, wrong)| values[id] != wrong),
                    "N/2N periodic confusion undetected"
                );
                assert_ne!(
                    values[p.leaves.selectors[3]],
                    wrong_domain.selectors_at_point(inputs.zeta).inv_vanishing
                );
                // Independently poke every extension-valued coefficient and
                // check its exact linear contribution, not just non-equality.
                for i in 0..8 {
                    for j in 0..4 {
                        let mut changed = inputs.clone();
                        changed.chunks[i][j] += extension(37);
                        let got = compare_native(&p, air, &changed).unwrap();
                        let mut unit = vec![vec![E::ZERO; 4]; 8];
                        unit[i][j] = extension(37);
                        let delta = recompose_quotient_from_chunks::<Config>(
                            &p.chunk_domains,
                            &unit,
                            inputs.zeta,
                        );
                        assert_eq!(got[p.residual] - values[p.residual], -delta);
                        assert_ne!(delta, E::ZERO);
                    }
                }
            }
        }
        check(Shape::S, &qlab_l2::verifier_air_s());
        check(Shape::P, &qlab_l2::verifier_air_p());
        check(Shape::R, &qlab_l2::verifier_air_r());
    }

    #[test]
    fn ood_rejects_domain_points_dimensions_and_unsupported_sources() {
        let air = qlab_l2::verifier_air_s();
        let p = Program::compile(Shape::S, &air).unwrap();
        let base = inputs(Shape::S, 1);
        for zeta in [
            Val::ONE,
            p.original.subgroup_generator(),
            p.original.subgroup_generator().inverse(),
        ] {
            let mut bad = base.clone();
            bad.zeta = zeta.into();
            assert!(p.evaluate(&bad).unwrap_err().contains("inverse of zero"));
        }
        for kind in 0..5 {
            let mut bad = base.clone();
            match kind {
                0 => {
                    bad.local.pop();
                }
                1 => {
                    bad.next.push(E::ZERO);
                }
                2 => {
                    bad.public.pop();
                }
                3 => {
                    bad.chunks.pop();
                }
                _ => {
                    bad.chunks[0].pop();
                }
            }
            assert!(p.evaluate(&bad).unwrap_err().contains("dimensions"));
        }
        for source in [
            BaseEntry::Preprocessed { offset: 0 },
            BaseEntry::Main { offset: 2 },
        ] {
            let expr = SymbolicExpression::from(SymbolicVariable::<Val>::new(source, 0));
            assert!(Dag::default().expr(&expr, &p.leaves).is_err());
        }
        assert!(Program::compile(Shape::P, &air).is_err());
    }

    #[test]
    fn symbolic_lowering_preserves_shared_subexpressions() {
        let p = Program::compile(Shape::R, &qlab_l2::verifier_air_r()).unwrap();
        let x = SymbolicExpression::from(SymbolicVariable::<Val>::new(BaseEntry::Public, 0));
        let shared = Arc::new(x.clone() * x);
        let expr = SymbolicExpr::Add {
            x: shared.clone(),
            y: shared,
            degree_multiple: 0,
        };
        let mut dag = p.dag;
        let before = dag.ops.len();
        dag.expr(&expr, &p.leaves).unwrap();
        assert_eq!(
            dag.ops[before..]
                .iter()
                .filter(|o| matches!(o, Op::Mul(..)))
                .count(),
            1
        );
        // End-to-end folding order is checked against the native folder by
        // the synthetic and real-proof checks, with nontrivial alpha.
    }
}
