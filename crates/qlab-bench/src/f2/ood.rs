//! Executable algebraic OOD relation, not a recursive verifier AIR.
//! All variable arithmetic is explicit; constants/IDFT are compile-time work.
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

struct Leaves {
    local: Vec<Id>,
    next: Vec<Id>,
    public: Vec<Id>,
    periodic: Vec<Id>,
    // Native selectors are unnormalized. Order: first, last, transition, 1/Z.
    selectors: [Id; 4],
}

struct Program {
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
        let layout = AirLayout::from_air::<Val>(air);
        require(layout.main_width == shape.width(), "OOD AIR width mismatch")?;
        require(
            layout.num_public_values == shape.pv_len(),
            "OOD AIR PV mismatch",
        )?;
        require(
            layout.preprocessed_width == 0,
            "preprocessed OOD AIR unsupported",
        )?;
        let original = Domain::new(Val::ONE, shape.log_height()).ok_or("original domain")?;
        let committed =
            Domain::new(Val::ONE, shape.log_height() + IS_ZK).ok_or("committed domain")?;
        let log_q = get_log_num_quotient_chunks::<Val, _>(air, layout, IS_ZK);
        require(log_q + IS_ZK == 3, "expected eight hiding quotient chunks")?;
        let chunk_domains = committed
            .create_disjoint_domain(1 << (shape.log_height() + IS_ZK + log_q))
            .split_domains(1 << (log_q + IS_ZK));
        let periodic = air.periodic_columns();
        check_periodic_column_lengths(&periodic, original.size())
            .map_err(|e| format!("periodic columns: {e:?}"))?;
        require(
            periodic.len() == layout.num_periodic_columns,
            "periodic count mismatch",
        )?;
        let mut dag = Dag::default();
        let local = (0..shape.width())
            .map(|i| dag.push(Op::Input(Input::Local(i))))
            .collect();
        let next = (0..shape.width())
            .map(|i| dag.push(Op::Input(Input::Next(i))))
            .collect();
        let public = (0..shape.pv_len())
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
        let gen = dag.constant(original.subgroup_generator());
        let next_point = dag.push(Op::Mul(zeta, gen));
        let mut periodic_ids = Vec::new();
        let mut period_points = HashMap::new();
        for col in periodic {
            let log_period = col.len().trailing_zeros() as usize;
            let point = *period_points
                .entry(log_period)
                .or_insert_with(|| dag.pow2(zeta, shape.log_height() - log_period));
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
        Ok(Self {
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
    let values = program.evaluate(inputs)?;
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
    let quotient = recompose_quotient_from_chunks::<Config>(
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
    verify_constraints::<Config, _, ()>(
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
    require(
        proof.degree_bits == shape.log_height() + IS_ZK,
        "OOD proof degree",
    )?;
    require(
        proof.opened_values.preprocessed_local.is_none()
            && proof.opened_values.preprocessed_next.is_none(),
        "unexpected preprocessed OOD values",
    )?;
    let config = qlab_l2::make_config_l2();
    let mut challenger = config.initialise_challenger();
    // uni-stark 0.6.1 prefix: committed degree, original degree, prep width.
    challenger.observe(Val::from_usize(proof.degree_bits));
    challenger.observe(Val::from_usize(shape.log_height()));
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
