//! Shared test support for the L2 shape tests (`l2::tests`, `l2p::tests`) —
//! lab #700 baton 3: the L2 test block has a lane budget (`qlab-air::l2` +
//! `::l2p` ≤ 12 Graviton minutes) and this module is how the block meets it
//! **without moving a statement**: same AIRs, same widths, same tamper list;
//! only the cost model of *asserting* changes.
//!
//! Three facts from the timed-out lane run (35812033360, stamped console)
//! decided the shape of this module:
//!
//! 1. A perm is 3,072 rows, so the shape-S program fills **70 %** of its 2^19
//!    trace and shape P's **63 %** of 2^20, and the balance close — where most
//!    tampers are refused — sits at perm 118 of 120 / 212 of 214. A
//!    lowest-row-first early exit on a balance tamper therefore still scans
//!    ~70 % of the rows. The scanner here visits the **program's tail first,
//!    then its head**, so a close-row violation is found in the first chunks
//!    and an early-site one (registry, mode) after ~1/8 of the program.
//! 2. A 2^19 `sat` call was ≈ 1.2 s of trace generation + ≈ 15 s of scanning
//!    (`l2_asset_captures_read_the_right_lanes` 1.19 s = generation alone;
//!    `l2_public_value_negatives` 61 s = one generation + four scans). The scan
//!    is compute-bound and row-independent, and the lane runs
//!    `--test-threads=1`, so the scanner runs its rows on rayon: every row
//!    still gets evaluated for a SAT claim, in parallel.
//! 3. The eight `(o1a, o2a, f1)` selector assignments feed the balance
//!    accumulators and carry encodings, which the generator computes in one
//!    row pass — so each assignment regenerates its trace. [`fan_out`] runs
//!    those generations [`ASSIGNMENT_FANOUT`] at a time, each trace dropped
//!    after its scan, bounding the peak (4 × 3.24 GB for P) instead of paying
//!    eight serial generations.
//!
//! The row evaluation is p3-air 0.6.1's `check_constraints` loop verbatim
//! (same builder, same selectors, same wrap-around next row); the module's own
//! tests pin that agreement on small traces, SAT and UNSAT.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use p3_air::{Air, BaseAir, DebugConstraintBuilder};
use p3_field::Field;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::ViewPair;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;

/// Rows per scheduling unit. 2,048 rows is two thirds of a perm: a
/// close-row violation is inside the first tail chunk, and the early-exit
/// check between chunks costs nothing measurable.
pub const ROWS_PER_CHUNK: usize = 2048;

/// Rows between early-exit checks inside a chunk.
const EXIT_CHECK_EVERY: usize = 256;

/// How many selector-assignment traces [`fan_out`] generates at once. Four
/// shape-P traces are 4 × 1,048,576 × 778 × 4 B ≈ 13 GB; with the two module
/// fixtures resident (≈ 3.24 + 1.47 GB) the block peaks ≈ 18 GB on the lane's
/// 30 GB runner — the same class as the 15.3 GB shape-P prover test, and
/// nothing else runs beside it under `--test-threads=1`.
pub const ASSIGNMENT_FANOUT: usize = 4;

/// One violated constraint: the claim behind every negative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub row: usize,
    pub constraint: usize,
    pub label: Option<String>,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "row {} constraint #{}", self.row, self.constraint)?;
        if let Some(l) = &self.label {
            write!(f, " ({l})")?;
        }
        Ok(())
    }
}

/// Evaluate every constraint of `air` on `row` of `main`, exactly as p3-air's
/// `check_constraints` does for that row, returning the row's violations.
fn eval_row<F, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    public_values: &[F],
    periodic: &[Vec<F>],
    row: usize,
) -> Vec<p3_air::ConstraintFailure>
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>>,
{
    let height = main.height();
    let next = (row + 1) % height;
    // SAFETY: `row < height` by construction; `next` is reduced mod `height`.
    let local = unsafe { main.row_slice_unchecked(row) };
    let nxt = unsafe { main.row_slice_unchecked(next) };
    let main_pair = ViewPair::new(
        RowMajorMatrixView::new_row(&*local),
        RowMajorMatrixView::new_row(&*nxt),
    );
    // Neither L2 AIR carries a preprocessed trace (asserted once in `scan`).
    let prep_pair = ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0));
    let periodic_row: Vec<F> = periodic.iter().map(|c| c[row % c.len()]).collect();
    let mut builder = DebugConstraintBuilder::new(
        row,
        main_pair,
        prep_pair,
        public_values,
        F::from_bool(row == 0),
        F::from_bool(row == height - 1),
        F::from_bool(row != height - 1),
        &periodic_row,
    );
    air.eval(&mut builder);
    builder.into_failures()
}

/// The chunk visiting order. With a program-end hint the program's chunks are
/// interleaved tail-first (`last, first, last-1, second, …`) and the padding
/// chunks follow in order; without one, ascending.
fn chunk_order(height: usize, program_end: Option<usize>) -> Vec<usize> {
    let n_total = height.div_ceil(ROWS_PER_CHUNK);
    let n_prog = program_end.map_or(n_total, |e| e.min(height).div_ceil(ROWS_PER_CHUNK));
    let mut order = Vec::with_capacity(n_total);
    if program_end.is_some() {
        for i in 0..n_prog {
            order.push(if i % 2 == 0 { n_prog - 1 - i / 2 } else { i / 2 });
        }
    } else {
        order.extend(0..n_prog);
    }
    order.extend(n_prog..n_total);
    debug_assert_eq!(order.len(), n_total);
    order
}

/// Scan `main` against `air` and return a violated constraint if there is one.
///
/// Stops at the first violation any worker finds (one violated constraint is
/// the whole UNSAT claim); returns `None` only after **every** row has been
/// evaluated (the whole SAT claim). `program_end` is a scheduling hint only —
/// which rows are visited first — and never changes the verdict.
pub fn scan<F, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    public_values: &[F],
    program_end: Option<usize>,
) -> Option<Violation>
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>> + BaseAir<F> + Sync,
{
    let height = main.height();
    assert!(height > 0, "empty trace");
    assert!(
        BaseAir::<F>::preprocessed_trace(air).is_none(),
        "l2test::scan mirrors check_constraints without preprocessed-trace support"
    );
    // The periodic columns once, not once per row (p3's `periodic_values`
    // rebuilds all of them on every row).
    let periodic: Vec<Vec<F>> = BaseAir::<F>::periodic_columns(air);
    let order = chunk_order(height, program_end);

    let next_chunk = AtomicUsize::new(0);
    let found = AtomicBool::new(false);
    let best: Mutex<Option<Violation>> = Mutex::new(None);
    let record = |v: Violation| {
        let mut g = best.lock().unwrap();
        if g.as_ref().is_none_or(|b| v.row < b.row) {
            *g = Some(v);
        }
        found.store(true, Ordering::Release);
    };

    let workers = current_num_threads().max(1);
    (0..workers).into_par_iter().for_each(|_| {
        'chunks: loop {
            if found.load(Ordering::Acquire) {
                break;
            }
            let i = next_chunk.fetch_add(1, Ordering::Relaxed);
            if i >= order.len() {
                break;
            }
            let start = order[i] * ROWS_PER_CHUNK;
            let end = (start + ROWS_PER_CHUNK).min(height);
            for row in start..end {
                if (row - start).is_multiple_of(EXIT_CHECK_EVERY) && found.load(Ordering::Acquire) {
                    break 'chunks;
                }
                let fails = eval_row(air, main, public_values, &periodic, row);
                if let Some(f) = fails.into_iter().next() {
                    record(Violation { row, constraint: f.constraint, label: f.label });
                    break 'chunks;
                }
            }
        }
    });

    best.into_inner().unwrap()
}

/// A SAT claim: every row evaluated (in parallel), `Err` carries the first
/// violation found. Use for `*_satisfies` / `*_holds` / `*_satisfy` and every
/// other positive.
pub fn satisfied<F, A>(air: &A, main: &RowMajorMatrix<F>, public_values: &[F]) -> Result<(), Violation>
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>> + BaseAir<F> + Sync,
{
    scan(air, main, public_values, None).map_or(Ok(()), Err)
}

/// An UNSAT claim: the first violation found, visiting the program's tail
/// first. `None` means the trace satisfies the AIR (every row was evaluated).
pub fn first_violation<F, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    public_values: &[F],
    program_end: usize,
) -> Option<Violation>
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>> + BaseAir<F> + Sync,
{
    scan(air, main, public_values, Some(program_end))
}

/// Panic in `check_constraints`'s own words if the trace does not satisfy the AIR.
pub fn assert_satisfied<F, A>(air: &A, main: &RowMajorMatrix<F>, public_values: &[F], what: &str)
where
    F: Field,
    A: for<'a> Air<DebugConstraintBuilder<'a, F>> + BaseAir<F> + Sync,
{
    if let Err(v) = satisfied(air, main, public_values) {
        panic!("{what}: constraints not satisfied on {v}");
    }
}

/// Map `f` over `items`, at most `cap` at a time in parallel, results in the
/// items' order. Each batch's intermediate values (a generated trace) are
/// dropped before the next batch starts.
pub fn fan_out<T, R, Fn_>(items: Vec<T>, cap: usize, f: Fn_) -> Vec<R>
where
    T: Send,
    R: Send,
    Fn_: Fn(T) -> R + Sync + Send,
{
    assert!(cap >= 1);
    let mut items = items;
    let mut out = Vec::with_capacity(items.len());
    while !items.is_empty() {
        let take = cap.min(items.len());
        let batch: Vec<T> = items.drain(..take).collect();
        out.extend(batch.into_par_iter().map(&f).collect::<Vec<R>>());
    }
    out
}

#[cfg(test)]
mod tests {
    use p3_air::{check_all_constraints, check_constraints};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::l2::{L2ShapeSAir, L2_WIDTH, PV_LEN as S_PV_LEN};
    use crate::l2p::{L2ShapePAir, L2P_WIDTH, PV_LEN as P_PV_LEN};

    type F = KoalaBear;

    /// SAT agreement with p3: a chain-only trace that `check_constraints`
    /// accepts is accepted by `scan` in both visiting orders, for both AIRs.
    #[test]
    fn l2test_scanner_agrees_with_p3_on_a_satisfied_trace() {
        let s = L2ShapeSAir::chain_only(10);
        let ts = s.generate_trace::<F>(0);
        let spv = vec![F::ZERO; S_PV_LEN];
        check_constraints(&s, &ts, &spv);
        assert_eq!(scan(&s, &ts, &spv, None), None);
        assert_eq!(scan(&s, &ts, &spv, Some(700)), None);
        let p = L2ShapePAir::chain_only(10);
        let tp = p.generate_trace::<F>(0);
        let ppv = vec![F::ZERO; P_PV_LEN];
        check_constraints(&p, &tp, &ppv);
        assert_eq!(scan(&p, &tp, &ppv, None), None);
        assert_eq!(scan(&p, &tp, &ppv, Some(700)), None);
    }

    /// UNSAT agreement with p3: on a corrupted trace `scan` reports a
    /// `(row, constraint)` that `check_all_constraints` also reports, in both
    /// visiting orders, for both AIRs — and a public-value tamper likewise.
    #[test]
    fn l2test_scanner_reports_a_violation_p3_reports() {
        fn agree<A>(air: &A, trace: &RowMajorMatrix<F>, pvs: &[F], what: &str)
        where
            A: for<'a> Air<DebugConstraintBuilder<'a, F>> + BaseAir<F> + Sync,
        {
            let report = check_all_constraints(air, trace, pvs, None);
            assert!(!report.is_ok(), "{what}: p3 must see the corruption");
            for order in [None, Some(700), Some(trace.height())] {
                let v = scan(air, trace, pvs, order).unwrap_or_else(|| panic!("{what}: scan missed the corruption"));
                assert!(
                    report.failures.iter().any(|f| f.row == v.row && f.constraint == v.constraint && f.label == v.label),
                    "{what}: scan's {v} is not among p3's failures"
                );
            }
        }
        let s = L2ShapeSAir::chain_only(10);
        let mut ts = s.generate_trace::<F>(0);
        ts.values[517 * L2_WIDTH + 3] += F::ONE; // one Keccak bit, row 517
        agree(&s, &ts, &vec![F::ZERO; S_PV_LEN], "S corrupted cell");
        let p = L2ShapePAir::chain_only(10);
        let mut tp = p.generate_trace::<F>(0);
        tp.values[901 * L2P_WIDTH + 3] += F::ONE;
        agree(&p, &tp, &vec![F::ZERO; P_PV_LEN], "P corrupted cell");
    }

    /// The visiting order is a permutation of every chunk, tail-first inside
    /// the program, padding last.
    #[test]
    fn l2test_chunk_order_is_a_permutation_tail_first() {
        let height = 1 << 19;
        let n = height / ROWS_PER_CHUNK;
        let asc = chunk_order(height, None);
        assert_eq!(asc, (0..n).collect::<Vec<_>>());
        let program_end: usize = 120 * 3072; // shape S
        let n_prog = program_end.div_ceil(ROWS_PER_CHUNK);
        let hinted = chunk_order(height, Some(program_end));
        assert_eq!(hinted.len(), n);
        let mut sorted = hinted.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..n).collect::<Vec<_>>(), "a permutation");
        assert_eq!(hinted[0], n_prog - 1, "the close's chunk first");
        assert_eq!(hinted[1], 0, "then the head");
        assert_eq!(hinted[2], n_prog - 2);
        assert_eq!(&hinted[n_prog..], &(n_prog..n).collect::<Vec<_>>()[..], "padding last, ascending");
    }

    /// `fan_out` returns every result in the items' order whatever the cap.
    #[test]
    fn l2test_fan_out_keeps_order() {
        for cap in [1, 3, 4, 8, 100] {
            let got = fan_out((0..9u32).collect(), cap, |x| x * x);
            assert_eq!(got, (0..9u32).map(|x| x * x).collect::<Vec<_>>(), "cap {cap}");
        }
    }
}
