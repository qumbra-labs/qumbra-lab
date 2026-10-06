//! The determination census (lab #758; #78 class 2 for the consensus AIRs).
//!
//! **The property under test:** the trace — hence every public value — is a
//! function of the statement's declared inputs. The NF double spend (#287,
//! public in lab PR #737) broke exactly this: PBIT on NF rows was read by the
//! Merkle mux but pinned by nothing but booleanity and per-perm constancy, so
//! one note had two satisfying traces with different public `nf`. A
//! set-difference audit calls such a column clean (it is read); a single-cell
//! tamper calls it clean (flipping it alone breaks `eff`); solving backward
//! from the public values calls it clean (a fixed `nf` pins it). Only a
//! **forward** question sees it: *from the declared inputs alone, is the cell
//! determined?*
//!
//! ## Layers (the stage-0 on lab #758, ruled GO)
//!
//! - **L0 — the witness manifest** ([`ManifestEntry`]): the (role, column)
//!   pairs that are statement inputs. Everything else must be determined. The
//!   public values are outputs, never sources.
//! - **L2 — forward determination** ([`Census::run`]): a worklist fixpoint
//!   over the cells of an honest trace. A constraint instance (constraint,
//!   row) whose dependence on the still-undetermined variables — probed by
//!   random substitution, jointly — is on exactly one variable determines it
//!   when it is affine in it, or boolean with one satisfying root; an instance
//!   depending on several boolean cells determines them all when it is a
//!   bit recomposition (superincreasing coefficients).
//! - **The report** ([`Census::report`]): the undetermined cells a constraint
//!   consumes jointly with another variable, as connected components, each
//!   with the public values it reaches; allowances (the narrow family's row-0
//!   warm-up) are tested, not assumed.
//! - **L3 — confirm** ([`Census::pin`], [`Census::repair`]): add a bucket of
//!   cells to the sources (a hypothetical pin) and count what it resolves —
//!   the root ranking; then perturb the bucket and replay the defining
//!   instances the pin recorded, in order, as a generic re-fill. The caller
//!   checks the repaired trace with `l2test::satisfied`.
//!
//! **Disclosure.** Nothing here prints. A caller running this on a real AIR
//! prints counts only where the output is public (the lane); flagged cells
//! are reviewed before any of their detail is published (lab #758).

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use p3_air::symbolic::{
    get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicAirBuilder, SymbolicExpr, SymbolicExpression,
};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One manifest line: on every row of every perm whose role is `role` (or
/// every row, for [`ANY_ROLE`]), the columns `cols` are statement inputs
/// belonging to semantic field `field`.
#[derive(Clone, Debug)]
pub struct ManifestEntry {
    pub role: u32,
    pub cols: Vec<usize>,
    pub field: &'static str,
    /// `true`: a **witness copy** of a value the AIR derives (`nk` at ARKM,
    /// an output ρ tied to `nf` by a bank, the claim's `cm` at MW1). L1 takes
    /// it as given (it cannot see banks); L2 does **not** — a copy must come
    /// out determined through its tie, or the freedom it hides is masked
    /// (a copy declared an input can pin the very value a freedom would
    /// move, from the witness side).
    pub copy: bool,
}

impl ManifestEntry {
    /// A statement input.
    pub fn input(role: u32, cols: Vec<usize>, field: &'static str) -> Self {
        Self { role, cols, field, copy: false }
    }
    /// A witness copy of a derived value.
    pub fn copy(role: u32, cols: Vec<usize>, field: &'static str) -> Self {
        Self { role, cols, field, copy: true }
    }
}

/// The narrow engine's row-0 warm-up allowance (issue #143): the first
/// perm's input state is prover-chosen and fully overridden at the first
/// injecting perm; it must reach no public value and die by that perm's
/// first block. Shared by every AIR on the narrow engine.
pub fn warmup_allowance(rows_per_perm: usize) -> Allowance {
    Allowance { name: "row-0 warm-up (#143)", root_rows: 0..1, max_row: rows_per_perm + 128 }
}

/// A manifest line that holds on every row (a per-trace declaration).
pub const ANY_ROLE: u32 = u32::MAX;

/// The program: the role of every perm (indexed `perm % roles.len()`).
#[derive(Clone, Debug)]
pub struct Program {
    pub rows_per_perm: usize,
    pub roles: Vec<u32>,
}

impl Program {
    pub fn role_of_row(&self, row: usize) -> u32 {
        self.roles[(row / self.rows_per_perm) % self.roles.len()]
    }
}

/// Name a column from an AIR's `audit_col_regions()` table: `NAME+k`.
pub fn col_name(regions: &[(&'static str, usize)], col: usize) -> String {
    match regions.iter().rev().find(|(_, start)| *start <= col) {
        Some((n, start)) if col == *start => n.to_string(),
        Some((n, start)) => format!("{n}+{}", col - start),
        None => format!("col{col}"),
    }
}

/// A named, tested allowance: an undetermined component is allowed when it
/// has a cell on a row in `root_rows`, every cell of it is on a row below
/// `max_row`, and it reaches no public value.
#[derive(Clone, Debug)]
pub struct Allowance {
    pub name: &'static str,
    pub root_rows: Range<usize>,
    pub max_row: usize,
}

// ---------------------------------------------------------------------------
// The constraint compiler
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Node<F> {
    Const(F),
    Main { col: u32, off: u8 },
    Per(u32),
    Pub(u32),
    First,
    Last,
    Trans,
    Add(u32, u32),
    Sub(u32, u32),
    Mul(u32, u32),
    Neg(u32),
}

/// One constraint, flattened: nodes in evaluation order (the last is the
/// root), the main cells it reads as (column, row offset), the public values.
struct Compiled<F> {
    nodes: Vec<Node<F>>,
    reads: Vec<(u32, u8)>,
    pubs: Vec<u32>,
    /// The syntactic target (L1): `[gate ·](X − expr)` with `X` a main cell.
    target: Option<Target>,
}

/// A constraint's syntactic target and what kind of definition it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub col: u32,
    pub off: u8,
    pub kind: TargetKind,
}

/// `Defining`: `X = expr` over other cells; `SelfCarry`: `next X = X`;
/// `Shape`: the constraint reads `X` alone (booleanity, range, a constant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Defining,
    SelfCarry,
    Shape,
    /// `X = pv` (gated): an output bind — it defines the public value, never
    /// the cell (public values are outputs, lab #758).
    PvBind,
}

/// The syntactic target: descend through products (gates) to a
/// `Sub(main leaf, rhs)`.
fn target_of<F>(e: &SymbolicExpression<F>) -> Option<(u32, u8, bool)> {
    match e {
        SymbolicExpr::Sub { x, y, .. } => match x.as_ref() {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset } => {
                    let self_carry = matches!(y.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Variable(w))
                        if w.index == v.index && matches!(w.entry, BaseEntry::Main { offset: o } if o != offset));
                    Some((v.index as u32, offset as u8, self_carry))
                }
                _ => None,
            },
            _ => None,
        },
        SymbolicExpr::Mul { x, y, .. } => target_of(y.as_ref()).or_else(|| target_of(x.as_ref())),
        _ => None,
    }
}

fn compile<F: PrimeField32>(root: &SymbolicExpression<F>) -> Compiled<F> {
    let mut nodes: Vec<Node<F>> = Vec::new();
    let mut memo: HashMap<*const SymbolicExpression<F>, u32> = HashMap::new();
    fn go<F: PrimeField32>(
        e: &SymbolicExpression<F>,
        nodes: &mut Vec<Node<F>>,
        memo: &mut HashMap<*const SymbolicExpression<F>, u32>,
    ) -> u32 {
        let key = e as *const _;
        if let Some(i) = memo.get(&key) {
            return *i;
        }
        let node = match e {
            SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
                BaseEntry::Main { offset } => Node::Main { col: v.index as u32, off: offset as u8 },
                BaseEntry::Periodic => Node::Per(v.index as u32),
                BaseEntry::Public => Node::Pub(v.index as u32),
                BaseEntry::Preprocessed { .. } => panic!("detaudit: no preprocessed columns in the consensus AIRs"),
            },
            SymbolicExpr::Leaf(BaseLeaf::IsFirstRow) => Node::First,
            SymbolicExpr::Leaf(BaseLeaf::IsLastRow) => Node::Last,
            SymbolicExpr::Leaf(BaseLeaf::IsTransition) => Node::Trans,
            SymbolicExpr::Leaf(BaseLeaf::Constant(c)) => Node::Const(*c),
            SymbolicExpr::Add { x, y, .. } => Node::Add(go(x.as_ref(), nodes, memo), go(y.as_ref(), nodes, memo)),
            SymbolicExpr::Sub { x, y, .. } => Node::Sub(go(x.as_ref(), nodes, memo), go(y.as_ref(), nodes, memo)),
            SymbolicExpr::Mul { x, y, .. } => Node::Mul(go(x.as_ref(), nodes, memo), go(y.as_ref(), nodes, memo)),
            SymbolicExpr::Neg { x, .. } => Node::Neg(go(x.as_ref(), nodes, memo)),
        };
        nodes.push(node);
        let i = (nodes.len() - 1) as u32;
        memo.insert(key, i);
        i
    }
    go(root, &mut nodes, &mut memo);
    let raw_target = target_of(root);
    let mut reads: Vec<(u32, u8)> = nodes
        .iter()
        .filter_map(|n| if let Node::Main { col, off } = n { Some((*col, *off)) } else { None })
        .collect();
    reads.sort_unstable();
    reads.dedup();
    let mut pubs: Vec<u32> = nodes.iter().filter_map(|n| if let Node::Pub(i) = n { Some(*i) } else { None }).collect();
    pubs.sort_unstable();
    pubs.dedup();
    let target = raw_target.map(|(col, off, self_carry)| Target {
        col,
        off,
        kind: if self_carry {
            TargetKind::SelfCarry
        } else if reads.len() == 1 && pubs.is_empty() {
            TargetKind::Shape
        } else if reads.len() == 1 {
            TargetKind::PvBind
        } else {
            TargetKind::Defining
        },
    });
    Compiled { nodes, reads, pubs, target }
}

// ---------------------------------------------------------------------------
// Variables and evaluation
// ---------------------------------------------------------------------------

/// A variable: a cell `(row, col)` of the analysed window, a public value,
/// or a cell outside the window (never determinable).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Var {
    Cell { row: u32, col: u32 },
    Pub(u32),
    Outside { row: u32, col: u32 },
}

/// How a variable was determined (for the replay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    Source,
    Affine,
    BoolRoot,
    /// A bit recomposition: the whole group is solved at once.
    Recompose,
    /// A linear system (payload = the group's index): solved at once.
    Linear,
    /// A bounded case split by enumeration (payload = the group's index):
    /// every assignment of the group's booleans, the rest solved per case,
    /// exactly one in range.
    Enum,
}

/// A variable's determination, packed in 4 bytes: the rule in the top three
/// bits, the defining constraint (or linear group) in the low 29;
/// `u32::MAX` = undetermined.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Det(u32);

impl Det {
    const NONE: Det = Det(u32::MAX);
    /// The "constraint" of a source.
    const SRC: u32 = (1 << 29) - 1;
    fn some(rule: Rule, c: u32) -> Det {
        debug_assert!(c <= Self::SRC);
        let r = match rule {
            Rule::Source => 0,
            Rule::Affine => 1,
            Rule::BoolRoot => 2,
            Rule::Recompose => 3,
            Rule::Linear => 4,
            Rule::Enum => 5,
        };
        Det(r << 29 | (c & Self::SRC))
    }
    fn get(self) -> Option<(Rule, u32)> {
        if self == Self::NONE {
            return None;
        }
        let rule = [Rule::Source, Rule::Affine, Rule::BoolRoot, Rule::Recompose, Rule::Linear, Rule::Enum][(self.0 >> 29) as usize];
        Some((rule, self.0 & Self::SRC))
    }
}

struct Ctx<'a, F> {
    values: &'a [F],
    /// Repaired cells (index `row·width + col`) over `values`.
    overlay: Option<&'a HashMap<usize, F>>,
    pvs: &'a [F],
    width: usize,
    height: usize,
    periodic: &'a [Vec<F>],
}

impl<F: PrimeField32> Ctx<'_, F> {
    fn eval(&self, c: &Compiled<F>, row: usize, ov: &[(Var, F)], scratch: &mut Vec<F>) -> F {
        scratch.clear();
        let look = |v: Var| ov.iter().find(|(k, _)| *k == v).map(|(_, x)| *x);
        for n in &c.nodes {
            let x = match *n {
                Node::Const(k) => k,
                Node::Main { col, off } => {
                    let r = (row + off as usize) % self.height;
                    let v = Var::Cell { row: r as u32, col };
                    let vo = Var::Outside { row: r as u32, col };
                    let i = r * self.width + col as usize;
                    look(v)
                        .or_else(|| look(vo))
                        .or_else(|| self.overlay.and_then(|o| o.get(&i).copied()))
                        .unwrap_or(self.values[i])
                }
                Node::Per(i) => {
                    let p = &self.periodic[i as usize];
                    p[row % p.len()]
                }
                Node::Pub(i) => look(Var::Pub(i)).unwrap_or(self.pvs[i as usize]),
                Node::First => F::from_bool(row == 0),
                Node::Last => F::from_bool(row == self.height - 1),
                Node::Trans => F::from_bool(row != self.height - 1),
                Node::Add(a, b) => scratch[a as usize] + scratch[b as usize],
                Node::Sub(a, b) => scratch[a as usize] - scratch[b as usize],
                Node::Mul(a, b) => scratch[a as usize] * scratch[b as usize],
                Node::Neg(a) => -scratch[a as usize],
            };
            scratch.push(x);
        }
        *scratch.last().expect("a constraint has a root")
    }
}

/// xorshift64 — deterministic probes (a census is reproducible).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn field<F: PrimeField32>(&mut self) -> F {
        F::from_u32((self.next() >> 34) as u32 + 3)
    }
}

/// A field element as a signed integer in (−p/2, p/2].
fn signed<F: PrimeField32>(x: F) -> i64 {
    let v = x.as_canonical_u32() as i64;
    let p = F::ORDER_U32 as i64;
    if v > p / 2 { v - p } else { v }
}

/// Whether `Σ a_i·x_i = t` with `0 ≤ x_i ≤ r_i` has at most one solution by
/// digit order: sorted by |a|, each |a_i| exceeds everything below it can
/// reach, and the whole reach stays under p/2 (no wraparound).
fn superincreasing(a: &[i64], r: &[u64], half_p: i128) -> bool {
    let mut idx: Vec<usize> = (0..a.len()).collect();
    idx.sort_by_key(|i| a[*i].abs());
    let mut reach: i128 = 0;
    for i in idx {
        let ai = a[i].abs() as i128;
        if ai == 0 || ai <= reach {
            return false;
        }
        reach += ai * r[i] as i128;
    }
    // Every achievable Σ a·x lies in (−reach, reach): no two collide mod p.
    reach < half_p
}

/// Whether `Σ a_i·x_i = t` over `0 ≤ x_i ≤ r_i` is pinned at an extreme:
/// every coefficient one sign, the reach under p/2, and `t` its minimum or
/// maximum — only one assignment attains it (P3's `Σm_k = 0` over four
/// 16-bit chunks: every chunk 0). [`solve_ranged`] finds it greedily.
fn extremal(a: &[i64], r: &[u64], t: i64, half_p: i128) -> bool {
    if a.contains(&0) || !(a.iter().all(|x| *x > 0) || a.iter().all(|x| *x < 0)) {
        return false;
    }
    let reach: i128 = a.iter().zip(r).map(|(x, r)| *x as i128 * *r as i128).sum();
    if reach.abs() >= half_p {
        return false;
    }
    t == 0 || t as i128 == reach
}

/// Solve `Σ a_i·x_i = t` over `0 ≤ x_i ≤ r_i` (superincreasing): substitute
/// `x = r − y` where `a < 0`, then take digits from the largest |a|.
fn solve_ranged(a: &[i64], r: &[u64], t: i64) -> Option<Vec<u64>> {
    let mut t = t as i128;
    for i in 0..a.len() {
        if a[i] < 0 {
            t -= a[i] as i128 * r[i] as i128;
        }
    }
    let mut idx: Vec<usize> = (0..a.len()).collect();
    idx.sort_by_key(|i| std::cmp::Reverse(a[*i].abs()));
    let mut y = vec![0u64; a.len()];
    for i in idx {
        let ai = a[i].abs() as i128;
        let d = (t / ai).clamp(0, r[i] as i128);
        y[i] = d as u64;
        t -= d * ai;
    }
    if t != 0 {
        return None;
    }
    Some((0..a.len()).map(|i| if a[i] < 0 { r[i] - y[i] } else { y[i] }).collect())
}

// ---------------------------------------------------------------------------
// The census
// ---------------------------------------------------------------------------

/// Enumeration caps (lab #758 R11): a stalled instance's dependents, a
/// group's equations, and its boolean unknowns (2^12 cases at most).
const ENUM_MAX_DEPS: usize = 16;
const ENUM_MAX_EQS: usize = 12;
const ENUM_MAX_BITS: usize = 12;
/// A group with few boolean unknowns may be wider (lab #896 seam T, after the
/// 2026-10-06 box): its case split is at most `2^ENUM_FEW_BITS` cases, so
/// the equation count — not the case count — is the only cost, and a wide
/// near-linear group (shape P's per-row exit edge, 21 equations, which put
/// row 1's amount and the exit recipient past the old cap) is decided rather
/// than skipped. Deciding more groups only adds determinations: each is
/// still sound on a subset of the AIR's equations.
const ENUM_FEW_BITS: usize = 4;
const ENUM_MAX_EQS_FEW_BITS: usize = 32;
/// Wide groups (past `ENUM_MAX_EQS`) tried per enumeration pass. A public
/// value is read on every row, so an ambiguous wide group would otherwise be
/// re-tried on each of a million rows; once its public values are settled
/// later rows' groups shrink, and the first rows decide what can be decided.
const ENUM_WIDE_PER_PASS: usize = 256;

/// Whether enumeration takes a group of `eqs` equations and `bools` boolean
/// unknowns.
fn enum_admits(eqs: usize, bools: usize) -> bool {
    bools <= ENUM_MAX_BITS && (eqs <= ENUM_MAX_EQS || (bools <= ENUM_FEW_BITS && eqs <= ENUM_MAX_EQS_FEW_BITS))
}
/// Solutions kept per group for the log.
pub const ENUM_KEEP: usize = 8;

/// The L2 fixpoint's state over a window `[0, rows)` of an honest trace.
pub struct Census<F> {
    constraints: Vec<Compiled<F>>,
    /// Per column: constraints reading it at offset 0 / offset 1.
    reads_local: Vec<Vec<u32>>,
    reads_next: Vec<Vec<u32>>,
    values: Vec<F>,
    pvs: Vec<F>,
    periodic: Vec<Vec<F>>,
    width: usize,
    height: usize,
    /// Rows analysed: `[0, rows)`.
    pub rows: usize,
    program: Program,
    /// Per window cell, then per public value.
    det: Vec<Det>,
    boolean: Vec<bool>,
    /// Determination order (the replay order), with the defining row.
    order: Vec<(Var, u32)>,
    rng: Rng,
    /// The declared range of each public value (its largest value), where
    /// the verifier constructs it bounded — an audit premise, stated per AIR
    /// by its `audit_pv_bits` with the constructor cited (lab #758).
    pv_max: Option<Vec<u64>>,
    /// The linear systems the elimination step solved (for the replay).
    groups: Vec<LinearGroup>,
    /// Witness-copy cells (window index) with their field and role: each
    /// must come out determined through its tie, or the census is not sound
    /// to read (a copy left free contaminates everything downstream).
    copy_cells: Vec<(usize, &'static str, u32)>,
    /// Rows the elimination sweep visits (default: the window). A confirm
    /// scopes it to its component's rows — a full re-sweep per pin is what
    /// made R3's narrow ranking hit its budget.
    scope: Range<usize>,
    /// Instances left stalled with several dependents, at least one a public
    /// value — the enumeration pass's candidates.
    stuck: Vec<(u32, u32)>,
    /// The groups enumeration solved (for the replay).
    enums: Vec<LinearGroup>,
    /// What enumeration saw: (row, public values involved, solutions) for
    /// every group it could decide, unique or not.
    pub enum_log: Vec<EnumOutcome>,
    /// A confirm's wall-clock budget ([`Census::set_deadline`]): checked
    /// inside the fixpoint and the elimination sweep, so one pin cannot run
    /// unbounded past it (the 2026-10-05/06 box: a 19.5M-cell flag ran > 3 h
    /// past a 900 s budget, which was checked only between attempts).
    deadline: Option<std::time::Instant>,
    /// Set when `deadline` passed during a pin: the pin's result is partial
    /// and the attempt is unconfirmed.
    timed_out: bool,
}

/// One enumerated group's outcome (lab #758 R11).
#[derive(Clone, Debug)]
pub struct EnumOutcome {
    pub row: usize,
    pub pvs: Vec<u32>,
    pub bools: usize,
    pub eqs: usize,
    /// In-range assignments found: 1 = determined; ≥ 2 = a real ambiguity
    /// of the group's equations (a candidate freedom); 0 = probe defect.
    pub solutions: usize,
    /// The public values the solutions do NOT agree on (≥ 2 solutions).
    pub pvs_free: Vec<u32>,
    /// Per public value of the group, its value in each solution found (up
    /// to [`ENUM_KEEP`]); `None` = free in that solution (unread there).
    pub pv_values: Vec<(u32, Vec<Option<u32>>)>,
    /// Why the group was undecidable (then `solutions` is 0 and meaningless).
    pub undecided: Option<String>,
}

/// One solved linear system: its instances and every variable it involved.
#[derive(Clone)]
struct LinearGroup {
    eqs: Vec<(u32, u32)>,
    vars: Vec<Var>,
}

/// One undetermined component, as reported.
#[derive(Clone, Debug, Default)]
pub struct Component {
    pub cells: usize,
    pub min_row: usize,
    pub max_row: usize,
    /// Public values the component reaches (depends on, jointly).
    pub pvs: Vec<u32>,
    /// (column, role) → cell count.
    pub buckets: BTreeMap<(u32, u32), usize>,
    /// The allowance that covers it, if any.
    pub allowed: Option<&'static str>,
    /// Buckets none of whose sampled cells is the syntactic target of an
    /// active defining instance — the freedom's inputs, not its consequences.
    /// Witness copies are kept apart ([`Component::copy_roots`]).
    pub roots: Vec<(u32, u32)>,
    /// Witness-copy buckets that are orientation roots: the freedom's source
    /// when its tie is missing,
    /// downstream of it otherwise. Ranked only when `roots` is empty; never
    /// held in a confirm (a copy must follow its origin).
    pub copy_roots: Vec<(u32, u32)>,
    /// The manifest fields of `copy_roots` — when `roots` is empty, the
    /// freedom *is* an untied copy, and this names the tie that is missing
    /// (what L2b's replay was meant to name, at no extra cost).
    pub untied_fields: Vec<(&'static str, u32)>,
    /// Up to four undetermined cells per bucket (`row·width + col`).
    pub samples: BTreeMap<(u32, u32), Vec<usize>>,
}

/// The census report.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub cells: usize,
    pub determined: usize,
    pub undetermined: usize,
    /// Undetermined cells in classes no defining constraint reads and no
    /// public value reaches (booleanity, range and self-carries only).
    pub unconsumed: usize,
    /// How many such classes (free-but-unread groups: trace malleability).
    pub malleable: usize,
    /// Public values not determined.
    pub pvs_undetermined: Vec<u32>,
    /// Witness copies not re-derived, as (field, role, cells) — only those
    /// **outside every component**: an unsolved tie, the soundness alarm (a
    /// free copy makes everything downstream look free — an earlier revision's
    /// mega-components). **Nonempty ⇒ the census is not sound to read.**
    pub copies_underived: Vec<(&'static str, u32, usize)>,
    /// Witness copies undetermined inside a component: downstream of its
    /// freedom (they move with it) — **or** an unsolved tie that made the
    /// component. Only a `--floor` run (copies as inputs) tells them apart:
    /// a component present only without the floor is one or the other, and
    /// its copy's tie is the first thing to check.
    pub copies_in_components: Vec<(&'static str, u32, usize)>,
    pub components: Vec<Component>,
}

impl Report {
    /// Components no allowance covers — the flags.
    pub fn flags(&self) -> impl Iterator<Item = &Component> {
        self.components.iter().filter(|c| c.allowed.is_none())
    }
}

impl<F: PrimeField32> Census<F> {
    /// Run the L2 fixpoint over rows `[0, rows)` of `trace` (`rows` = the
    /// height for a full census; a prefix for a windowed one, whose last
    /// perm's cells that read past the window stay undetermined — an edge).
    #[allow(clippy::too_many_arguments)]
    pub fn run<A>(
        air: &A,
        trace: RowMajorMatrix<F>,
        pvs: &[F],
        program: Program,
        manifest: &[ManifestEntry],
        rows: usize,
        pv_bits: Option<Vec<u32>>,
    ) -> Self
    where
        A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
    {
        Self::run_with_pv_inputs(air, trace, pvs, program, manifest, rows, pv_bits, &[])
    }

    /// [`Census::run`] with some public values declared **verifier-supplied
    /// inputs** (sources): a block the transaction declares and the node
    /// checks against its own rule — P3's `vPublic` (redeem, amount, asset
    /// per row). Every other public value stays an output. An audit premise,
    /// stated per AIR by its `audit_pv_inputs()` with the node check cited.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_pv_inputs<A>(
        air: &A,
        trace: RowMajorMatrix<F>,
        pvs: &[F],
        program: Program,
        manifest: &[ManifestEntry],
        rows: usize,
        pv_bits: Option<Vec<u32>>,
        pv_inputs: &[usize],
    ) -> Self
    where
        A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
    {
        Self::run_with_holes(air, trace, pvs, program, manifest, rows, pv_bits, pv_inputs, &[])
    }

    /// [`Census::run_with_pv_inputs`] with `holes`: manifest cells left
    /// **not** sources — a binding probe's targets (lab #758 R14), so a later
    /// [`Census::pin_cells_with`] of one of them returns its forward cone.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_holes<A>(
        air: &A,
        trace: RowMajorMatrix<F>,
        pvs: &[F],
        program: Program,
        manifest: &[ManifestEntry],
        rows: usize,
        pv_bits: Option<Vec<u32>>,
        pv_inputs: &[usize],
        holes: &[Var],
    ) -> Self
    where
        A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
    {
        let holes: std::collections::HashSet<usize> =
            holes.iter().filter_map(|v| if let Var::Cell { row, col } = v { Some(*row as usize * trace.width() + *col as usize) } else { None }).collect();
        let width = trace.width();
        let height = trace.height();
        assert!(rows <= height && rows > 0);
        let constraints: Vec<Compiled<F>> = get_symbolic_constraints::<F, A>(air, AirLayout::from_air::<F>(air))
            .iter()
            .map(compile)
            .collect();
        let mut reads_local: Vec<Vec<u32>> = vec![Vec::new(); width];
        let mut reads_next: Vec<Vec<u32>> = vec![Vec::new(); width];
        for (ci, c) in constraints.iter().enumerate() {
            for &(col, off) in &c.reads {
                let list = if off == 0 { &mut reads_local } else { &mut reads_next };
                list[col as usize].push(ci as u32);
            }
        }
        let npv = pvs.len();
        // A windowed census keeps only the rows it reads: the window and the
        // one after it (its last row's `next`).
        let mut values = trace.values;
        if rows < height {
            values.truncate((rows + 1) * width);
            values.shrink_to_fit();
        }
        let mut s = Census {
            constraints,
            reads_local,
            reads_next,
            values,
            pvs: pvs.to_vec(),
            periodic: BaseAir::<F>::periodic_columns(air),
            width,
            height,
            rows,
            program,
            det: vec![Det::NONE; rows * width + npv],
            boolean: vec![false; rows * width],
            order: Vec::new(),
            rng: Rng(0x0758_de7a_0d17_0001),
            pv_max: pv_bits.map(|bits| {
                assert_eq!(bits.len(), npv, "one declared range per public value");
                bits.iter().map(|b| if *b >= 64 { u64::MAX } else { (1u64 << b) - 1 }).collect()
            }),
            groups: Vec::new(),
            copy_cells: Vec::new(),
            scope: 0..rows,
            stuck: Vec::new(),
            enums: Vec::new(),
            enum_log: Vec::new(),
            deadline: None,
            timed_out: false,
        };
        s.find_booleans();
        for row in 0..rows {
            let role = s.program.role_of_row(row);
            for m in manifest.iter().filter(|m| m.copy && (m.role == role || m.role == ANY_ROLE)) {
                for &col in &m.cols {
                    s.copy_cells.push((row * width + col, m.field, role));
                }
            }
        }
        // Sources: the manifest.
        for row in 0..rows {
            let role = s.program.role_of_row(row);
            for m in manifest.iter().filter(|m| !m.copy && (m.role == role || m.role == ANY_ROLE)) {
                for &col in &m.cols {
                    let i = row * width + col;
                    if s.det[i].get().is_none() && !holes.contains(&i) {
                        s.det[i] = Det::some(Rule::Source, Det::SRC);
                    }
                }
            }
        }
        for &i in pv_inputs {
            let j = rows * width + i;
            s.det[j] = Det::some(Rule::Source, Det::SRC);
        }
        s.fixpoint(None);
        // Monotone by construction: elimination only adds to the fixpoint's
        // determinations (the floor) — asserted, since a regression there
        // would read as new freedoms.
        let floor = s.det.iter().filter(|d| d.get().is_some()).count();
        // Linear elimination once the worklist stalls, then on again.
        loop {
            loop {
                let new = s.eliminate();
                if new.is_empty() {
                    break;
                }
                let seed = s.seed_of(&new);
                s.fixpoint(Some(seed));
            }
            // Then the bounded case splits, and on again while they solve.
            let new = s.enumerate();
            if new.is_empty() {
                break;
            }
            let seed = s.seed_of(&new);
            s.fixpoint(Some(seed));
        }
        assert!(s.det.iter().filter(|d| d.get().is_some()).count() >= floor, "elimination lost determinations");
        s
    }

    /// The instances reading any of `vars` (to resume the fixpoint).
    fn seed_of(&self, vars: &[Var]) -> Vec<(u32, u32)> {
        let mut seed = Vec::new();
        for v in vars {
            if let Var::Pub(i) = *v {
                if std::env::var_os("DETAUDIT_NO_LATE_PV").is_some() {
                    continue;
                }
                for (c, k) in self.constraints.iter().enumerate() {
                    if k.pubs.contains(&i) {
                        seed.extend((0..self.rows).map(|r| (c as u32, r as u32)));
                    }
                }
                continue;
            }
            if let Var::Cell { row, col } = *v {
                for &c in &self.reads_local[col as usize] {
                    seed.push((c, row));
                }
                if row > 0 {
                    for &c in &self.reads_next[col as usize] {
                        seed.push((c, row - 1));
                    }
                }
            }
        }
        seed
    }

    /// A variable's range (largest value) when it is bounded: a boolean cell
    /// (1), a public value under the declared premise; `None` = a field
    /// element.
    fn range_of(&self, v: Var) -> Option<u64> {
        match v {
            Var::Cell { .. } if self.is_bool(v) => Some(1),
            Var::Pub(i) => self.pv_max.as_ref().map(|m| m[i as usize]),
            _ => None,
        }
    }

    fn idx(&self, v: Var) -> Option<usize> {
        match v {
            Var::Cell { row, col } => Some(row as usize * self.width + col as usize),
            Var::Pub(i) => Some(self.rows * self.width + i as usize),
            Var::Outside { .. } => None,
        }
    }
    /// Whether `v` is determined (public, for the probes).
    pub fn is_determined(&self, v: Var) -> bool {
        self.is_det(v)
    }

    fn is_det(&self, v: Var) -> bool {
        self.idx(v).is_some_and(|i| self.det[i].get().is_some())
    }
    fn cell(&self, row: usize, col: u32) -> Var {
        if row < self.rows { Var::Cell { row: row as u32, col } } else { Var::Outside { row: row as u32, col } }
    }
    fn ctx(&self) -> Ctx<'_, F> {
        Ctx { values: &self.values, overlay: None, pvs: &self.pvs, width: self.width, height: self.height, periodic: &self.periodic }
    }
    /// The variables instance `(c, row)` reads.
    fn vars_of(&self, c: usize, row: usize) -> Vec<Var> {
        let k = &self.constraints[c];
        let mut out: Vec<Var> = k
            .reads
            .iter()
            .map(|&(col, off)| {
                let r = row + off as usize;
                // A full-height window wraps (p3's `next` of the last row is row 0).
                let r = if self.rows == self.height { r % self.height } else { r };
                self.cell(r, col)
            })
            .collect();
        out.extend(k.pubs.iter().map(|i| Var::Pub(*i)));
        out
    }

    /// Booleans: cells an instance reading only that cell pins to {0, 1}.
    fn find_booleans(&mut self) {
        let mut scratch = Vec::new();
        let singles: Vec<usize> = (0..self.constraints.len())
            .filter(|c| self.constraints[*c].reads.len() == 1 && self.constraints[*c].reads[0].1 == 0 && self.constraints[*c].pubs.is_empty())
            .collect();
        let ctx = self.ctx();
        let mut found = Vec::new();
        for &c in &singles {
            let col = self.constraints[c].reads[0].0;
            for row in 0..self.rows {
                let v = Var::Cell { row: row as u32, col };
                let f = |x: F, s: &mut Vec<F>| ctx.eval(&self.constraints[c], row, &[(v, x)], s);
                if f(F::ZERO, &mut scratch) == F::ZERO && f(F::ONE, &mut scratch) == F::ZERO && f(F::TWO, &mut scratch) != F::ZERO {
                    found.push(row * self.width + col as usize);
                }
            }
        }
        for i in found {
            self.boolean[i] = true;
        }
    }

    /// Worklist fixpoint. `seed`: the instances to start from (an
    /// incremental pin); `None` = the sweep of every instance.
    fn fixpoint(&mut self, seed: Option<Vec<(u32, u32)>>) {
        if self.past_deadline() {
            return;
        }
        let nc = self.constraints.len();
        let mut queued = vec![0u64; (nc * self.rows).div_ceil(64)];
        let mut queue: std::collections::VecDeque<(u32, u32)> = Default::default();
        let mut scratch = Vec::new();
        let sweep = seed.is_none();
        let mut sweep_row = if sweep { 0 } else { self.rows };
        if let Some(seed) = seed {
            for (c, r) in seed {
                let q = r as usize * nc + c as usize;
                if queued[q / 64] >> (q % 64) & 1 == 0 {
                    queued[q / 64] |= 1 << (q % 64);
                    queue.push_back((c, r));
                }
            }
        }
        let mut popped = 0usize;
        loop {
            // Drain the queue first, then advance the sweep one row.
            while let Some((c, r)) = queue.pop_front() {
                popped += 1;
                if popped.is_multiple_of(65_536) && self.past_deadline() {
                    return;
                }
                let q = r as usize * nc + c as usize;
                queued[q / 64] &= !(1 << (q % 64));
                for v in self.process(c as usize, r as usize, &mut scratch) {
                    self.enqueue_dependents(v, sweep_row, &mut queue, &mut queued);
                }
            }
            if !sweep || sweep_row >= self.rows || self.past_deadline() {
                break;
            }
            for c in 0..nc {
                for v in self.process(c, sweep_row, &mut scratch) {
                    self.enqueue_dependents(v, sweep_row, &mut queue, &mut queued);
                }
            }
            sweep_row += 1;
        }
    }

    fn enqueue_dependents(&self, v: Var, sweep_row: usize, queue: &mut std::collections::VecDeque<(u32, u32)>, queued: &mut [u64]) {
        // A public value determined late (a bind behind an eliminated tie)
        // must re-open every instance reading it — a close against it at an
        // earlier row was swept while it was still free (R3: the claim's ρ
        // close against `cnf`).
        if let Var::Pub(i) = v {
            if std::env::var_os("DETAUDIT_NO_LATE_PV").is_some() {
                return; // the pre-R3 behaviour, for the toy's negative check
            }
            let nc = self.constraints.len();
            for c in 0..nc {
                if !self.constraints[c].pubs.contains(&i) {
                    continue;
                }
                for r in 0..self.rows.min(sweep_row + 1) {
                    let q = r * nc + c;
                    if queued[q / 64] >> (q % 64) & 1 == 0 {
                        queued[q / 64] |= 1 << (q % 64);
                        queue.push_back((c as u32, r as u32));
                    }
                }
            }
            return;
        }
        let Var::Cell { row, col } = v else { return };
        let nc = self.constraints.len();
        let row = row as usize;
        let mut push = |c: u32, r: usize| {
            // Rows the sweep has not reached are visited by the sweep itself.
            if r > sweep_row || r >= self.rows {
                return;
            }
            let q = r * nc + c as usize;
            if queued[q / 64] >> (q % 64) & 1 == 0 {
                queued[q / 64] |= 1 << (q % 64);
                queue.push_back((c, r as u32));
            }
        };
        for &c in &self.reads_local[col as usize] {
            push(c, row);
        }
        if row > 0 {
            for &c in &self.reads_next[col as usize] {
                push(c, row - 1);
            }
        } else if self.rows == self.height {
            for &c in &self.reads_next[col as usize] {
                push(c, self.height - 1);
            }
        }
    }

    /// The undetermined variables instance `(c, row)` depends on, probed
    /// jointly: every undetermined variable at a random value, then each
    /// re-drawn alone.
    fn dependents(&mut self, c: usize, row: usize, scratch: &mut Vec<F>) -> Vec<Var> {
        let und: Vec<Var> = self.vars_of(c, row).into_iter().filter(|v| !self.is_det(*v)).collect();
        if und.is_empty() {
            return und;
        }
        let base: Vec<(Var, F)> = und.iter().map(|v| (*v, self.rng.field())).collect();
        let alt: Vec<F> = und.iter().map(|_| self.rng.field()).collect();
        let ctx = self.ctx();
        let k = &self.constraints[c];
        let f0 = ctx.eval(k, row, &base, scratch);
        let mut out = Vec::new();
        for (j, v) in und.iter().enumerate() {
            let mut ov = base.clone();
            ov[j].1 = alt[j];
            if ctx.eval(k, row, &ov, scratch) != f0 {
                out.push(*v);
            }
        }
        out
    }

    /// Process one instance; returns the variables it determined.
    fn process(&mut self, c: usize, row: usize, scratch: &mut Vec<F>) -> Vec<Var> {
        // Cheap exit: every read determined.
        if self.vars_of(c, row).iter().all(|v| self.is_det(*v)) {
            return Vec::new();
        }
        let d = self.dependents(c, row, scratch);
        match d.len() {
            0 => Vec::new(),
            1 => {
                let u = d[0];
                let Some(i) = self.idx(u) else { return Vec::new() };
                match self.solve_one(c, row, u, scratch) {
                    Some(rule) => {
                        self.det[i] = Det::some(rule, c as u32);
                        self.order.push((u, row as u32));
                        vec![u]
                    }
                    None => Vec::new(),
                }
            }
            _ => {
                if self.is_recomposition(c, row, &d, scratch) {
                    for u in &d {
                        let i = self.idx(*u).expect("recomposition cells are in the window");
                        self.det[i] = Det::some(Rule::Recompose, c as u32);
                        self.order.push((*u, row as u32));
                    }
                    d
                } else if let Some(u) = self.case_split(c, row, &d, scratch) {
                    let i = self.idx(u).expect("a dependent is in the window");
                    self.det[i] = Det::some(Rule::Affine, c as u32);
                    self.order.push((u, row as u32));
                    vec![u]
                } else {
                    if d.len() <= ENUM_MAX_DEPS && d.iter().any(|v| matches!(v, Var::Pub(_))) {
                        self.stuck.push((c as u32, row as u32));
                    }
                    Vec::new()
                }
            }
        }
    }

    fn is_bool(&self, v: Var) -> bool {
        match v {
            Var::Cell { row, col } => self.boolean[row as usize * self.width + col as usize],
            _ => false,
        }
    }

    /// The single-variable rules: affine with a nonzero coefficient, or a
    /// boolean with exactly one satisfying root.
    fn solve_one(&self, c: usize, row: usize, u: Var, scratch: &mut Vec<F>) -> Option<Rule> {
        let ctx = self.ctx();
        let k = &self.constraints[c];
        let f = |x: F, s: &mut Vec<F>| ctx.eval(k, row, &[(u, x)], s);
        let (f0, f1, f2) = (f(F::ZERO, scratch), f(F::ONE, scratch), f(F::TWO, scratch));
        if f1 != f0 && f2 - f1 == f1 - f0 {
            return Some(Rule::Affine);
        }
        if self.is_bool(u) && ((f0 == F::ZERO) != (f1 == F::ZERO)) {
            return Some(Rule::BoolRoot);
        }
        None
    }

    /// A recomposition: every dependent variable bounded (a boolean cell, or
    /// a public value under the declared range), the instance affine in them
    /// jointly, and the coefficients superincreasing against the ranges —
    /// a unique solution.
    fn is_recomposition(&self, c: usize, row: usize, d: &[Var], scratch: &mut Vec<F>) -> bool {
        let Some(ranges) = d.iter().map(|v| self.range_of(*v)).collect::<Option<Vec<u64>>>() else { return false };
        let ctx = self.ctx();
        let k = &self.constraints[c];
        let zeros: Vec<(Var, F)> = d.iter().map(|v| (*v, F::ZERO)).collect();
        let base = ctx.eval(k, row, &zeros, scratch);
        let mut coefs = Vec::with_capacity(d.len());
        for j in 0..d.len() {
            let mut ov = zeros.clone();
            ov[j].1 = F::ONE;
            coefs.push(ctx.eval(k, row, &ov, scratch) - base);
        }
        // Joint affinity: all-ones must equal base + Σ coef.
        let ones: Vec<(Var, F)> = d.iter().map(|v| (*v, F::ONE)).collect();
        let sum = coefs.iter().fold(F::ZERO, |a, b| a + *b);
        if ctx.eval(k, row, &ones, scratch) != base + sum {
            return false;
        }
        let a: Vec<i64> = coefs.iter().map(|x| signed(*x)).collect();
        superincreasing(&a, &ranges, (F::ORDER_U32 / 2) as i128) || extremal(&a, &ranges, -signed(base), (F::ORDER_U32 / 2) as i128)
    }

    /// A boolean case split: an instance whose dependents are a bounded
    /// boolean `b` and one other `u`, affine in `u` for each value of `b`,
    /// with the same root either way — `u` is determined whatever `b` is
    /// (P3's `(1 − 2s)·m = t` with `t = 0`: `m = 0` under both signs). The
    /// replay is plain [`Rule::Affine`]: `b` sits at its current value.
    fn case_split(&self, c: usize, row: usize, d: &[Var], scratch: &mut Vec<F>) -> Option<Var> {
        if d.len() != 2 {
            return None;
        }
        let ctx = self.ctx();
        let k = &self.constraints[c];
        for (bi, ui) in [(0, 1), (1, 0)] {
            let (b, u) = (d[bi], d[ui]);
            if self.range_of(b) != Some(1) {
                continue;
            }
            let mut root = None;
            let mut ok = true;
            for bv in [F::ZERO, F::ONE] {
                let f = |x: F, s: &mut Vec<F>| ctx.eval(k, row, &[(b, bv), (u, x)], s);
                let (f0, f1, f2) = (f(F::ZERO, scratch), f(F::ONE, scratch), f(F::TWO, scratch));
                if f1 == f0 || f2 - f1 != f1 - f0 {
                    ok = false;
                    break;
                }
                let x = -f0 * (f1 - f0).inverse();
                if root.is_some_and(|r| r != x) {
                    ok = false;
                    break;
                }
                root = Some(x);
            }
            if ok {
                return Some(u);
            }
        }
        None
    }

    /// The bounded case split by enumeration (lab #758 R11): stalled
    /// instances that read a public value, grouped by shared unknowns; a
    /// group with ≤ [`ENUM_MAX_BITS`] boolean unknowns has every boolean
    /// assignment tried, the other unknowns solved per case by propagation
    /// (an equation with one unknown left, affine in it, the root in range),
    /// and the in-range assignments counted. Exactly one ⇒ every unknown of
    /// the group determined — sound on a subset of the AIR's equations, as
    /// more equations can only remove solutions. Two or more are logged
    /// ([`Census::enum_log`]): a real ambiguity of those equations.
    /// Restricted to public-value groups for cost (the class-2 question is
    /// the public values; a million bit-serial compare rows are not).
    fn enumerate(&mut self) -> Vec<Var> {
        let mut stuck = std::mem::take(&mut self.stuck);
        stuck.sort_unstable_by_key(|(c, r)| (*r, *c));
        stuck.dedup();
        let mut scratch = Vec::new();
        let mut out = Vec::new();
        // One row at a time: a public value is read on every row, and a
        // group spanning rows would be one giant group; per row, each group
        // is a subset of the AIR's equations — sound for uniqueness.
        let mut wide_tried = 0usize;
        let mut at = 0;
        while at < stuck.len() {
            let row = stuck[at].1;
            let end = at + stuck[at..].iter().take_while(|(_, r)| *r == row).count();
            let mut inst: Vec<((u32, u32), Vec<Var>)> = Vec::new();
            for &(c, r) in &stuck[at..end] {
                let d = self.dependents(c as usize, r as usize, &mut scratch);
                if d.len() >= 2 && d.len() <= ENUM_MAX_DEPS {
                    inst.push(((c, r), d));
                }
            }
            at = end;
            // Union this row's instances sharing an unknown.
            let mut parent: Vec<usize> = (0..inst.len()).collect();
            fn find(p: &mut [usize], mut x: usize) -> usize {
                while p[x] != x {
                    p[x] = p[p[x]];
                    x = p[x];
                }
                x
            }
            let mut owner: HashMap<Var, usize> = HashMap::new();
            for (k, (_, d)) in inst.iter().enumerate() {
                for v in d {
                    if let Some(&o) = owner.get(v) {
                        let (a, b) = (find(&mut parent, o), find(&mut parent, k));
                        parent[a] = b;
                    } else {
                        owner.insert(*v, k);
                    }
                }
            }
            let mut groups: std::collections::BTreeMap<usize, Vec<usize>> = Default::default();
            for k in 0..inst.len() {
                let root = find(&mut parent, k);
                groups.entry(root).or_default().push(k);
            }
            for (_, members) in groups {
                let eqs: Vec<(u32, u32)> = members.iter().map(|k| inst[*k].0).collect();
                let mut vars: Vec<Var> = members.iter().flat_map(|k| inst[*k].1.iter().copied()).filter(|v| !self.is_det(*v)).collect();
                vars.sort_unstable_by_key(|v| self.idx(*v));
                vars.dedup();
                // The boolean count is measured before the cap, so a skipped
                // group's log line states it (it used to print 0).
                let n_bools = vars.iter().filter(|v| self.range_of(**v) == Some(1)).count();
                let wide = members.len() > ENUM_MAX_EQS;
                let budget_spent = wide && wide_tried >= ENUM_WIDE_PER_PASS;
                if wide && !budget_spent {
                    wide_tried += 1;
                }
                if !enum_admits(members.len(), n_bools) || budget_spent {
                    let pvs: Vec<u32> = members.iter().flat_map(|k| inst[*k].1.iter()).filter_map(|v| if let Var::Pub(i) = v { Some(*i) } else { None }).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
                    if self.enum_log.iter().filter(|o| o.undecided.is_some()).count() < 32 {
                        let why = if budget_spent {
                            format!("{} equations: the pass's {ENUM_WIDE_PER_PASS} wide groups are spent", members.len())
                        } else {
                            format!(
                                "{} equations, {n_bools} booleans: over the caps ({ENUM_MAX_EQS} equations; {ENUM_MAX_EQS_FEW_BITS} with ≤ {ENUM_FEW_BITS} booleans)",
                                members.len()
                            )
                        };
                        self.enum_log.push(EnumOutcome { row: row as usize, pvs, bools: n_bools, eqs: members.len(), solutions: 0, pvs_free: Vec::new(), pv_values: Vec::new(), undecided: Some(why) });
                    }
                    continue;
                }
                if vars.is_empty() {
                    continue;
                }
                let g = LinearGroup { eqs, vars };
                let pvs = self.pvs.clone();
                let pv_list: Vec<u32> = g.vars.iter().filter_map(|v| if let Var::Pub(i) = v { Some(*i) } else { None }).collect();
                let bools = g.vars.iter().filter(|v| self.range_of(**v) == Some(1)).count();
                let (n, fixed, sols) = match self.enum_group(&g, None, &pvs) {
                    Ok(r) => r,
                    Err(why) => {
                        // Log the substantial ones (a per-row pair is noise).
                        if g.eqs.len() >= 4 && self.enum_log.iter().filter(|o| o.undecided.is_some()).count() < 32 {
                            self.enum_log.push(EnumOutcome { row: row as usize, pvs: pv_list, bools, eqs: g.eqs.len(), solutions: 0, pvs_free: Vec::new(), pv_values: Vec::new(), undecided: Some(why) });
                        }
                        continue;
                    }
                };
                // Log the groups that bear on a public value's fate: every
                // ambiguous one, and the unique ones that settle one.
                let settles_pv = g.vars.iter().zip(&fixed).any(|(v, x)| matches!(v, Var::Pub(_)) && x.is_some());
                // (A group whose public values were all settled meanwhile —
                // registered while one was open — bears on none: not logged.)
                if (n != 1 && !pv_list.is_empty()) || settles_pv {
                    let pvs_free: Vec<u32> = g.vars.iter().zip(&fixed).filter_map(|(v, x)| if let (Var::Pub(i), None) = (v, x) { Some(*i) } else { None }).collect();
                    let pv_values: Vec<(u32, Vec<Option<u32>>)> = g
                        .vars
                        .iter()
                        .enumerate()
                        .filter_map(|(j, v)| if let Var::Pub(i) = v { Some((*i, sols.iter().map(|s| s[j].map(|x| x.as_canonical_u32())).collect())) } else { None })
                        .collect();
                    self.enum_log.push(EnumOutcome { row: row as usize, pvs: pv_list, bools, eqs: g.eqs.len(), solutions: n, pvs_free, pv_values, undecided: None });
                }
                let gi = self.enums.len() as u32;
                let mut any = false;
                for (v, x) in g.vars.iter().zip(&fixed) {
                    let Some(x) = x else { continue };
                    let honest = match *v {
                        Var::Pub(i) => self.pvs[i as usize],
                        Var::Cell { row, col } => self.values[row as usize * self.width + col as usize],
                        Var::Outside { .. } => continue,
                    };
                    assert_eq!(*x, honest, "enumeration fixed a value off the honest trace — PROBE DEFECT");
                    let i = self.idx(*v).expect("an unknown is in the window");
                    self.det[i] = Det::some(Rule::Enum, gi);
                    self.order.push((*v, row));
                    out.push(*v);
                    any = true;
                }
                if any {
                    self.enums.push(g);
                }
            }
        }
        out
    }

    /// Enumerate one group under `overlay`/`pvs`: `None` when the group is
    /// not decidable this way (too many booleans, a non-affine read, or an
    /// unknown left that the equations do read). Else the number of in-range
    /// solutions and, per unknown, its value when every solution agrees on
    /// it (an unknown no equation reads in some case is free there).
    #[allow(clippy::type_complexity)]
    fn enum_group(&self, g: &LinearGroup, overlay: Option<&HashMap<usize, F>>, pvs: &[F]) -> Result<(usize, Vec<Option<F>>, Vec<Vec<Option<F>>>), String> {
        let ctx = Ctx { values: &self.values, overlay, pvs, width: self.width, height: self.height, periodic: &self.periodic };
        let bools: Vec<usize> = (0..g.vars.len()).filter(|j| self.range_of(g.vars[*j]) == Some(1)).collect();
        if bools.len() > ENUM_MAX_BITS {
            return Err(format!("{} booleans > cap {ENUM_MAX_BITS}", bools.len()));
        }
        let reads: Vec<Vec<Var>> = g.eqs.iter().map(|&(c, r)| self.vars_of(c as usize, r as usize)).collect();
        let mut scratch = Vec::new();
        let mut found = 0usize;
        // Per unknown: Some(Some(x)) = x in every solution so far;
        // Some(None) = disagrees or free; None = no solution yet.
        let mut agree: Vec<Option<Option<F>>> = vec![None; g.vars.len()];
        let mut kept: Vec<Vec<Option<F>>> = Vec::new();
        'case: for mask in 0u32..(1 << bools.len()) {
            let mut val: Vec<Option<F>> = vec![None; g.vars.len()];
            for (b, &j) in bools.iter().enumerate() {
                val[j] = Some(F::from_bool(mask >> b & 1 == 1));
            }
            // Propagate: an equation with one unknown left, affine in it.
            loop {
                let mut progress = false;
                for (e, &(c, r)) in g.eqs.iter().enumerate() {
                    let k = &self.constraints[c as usize];
                    let open: Vec<usize> = (0..g.vars.len()).filter(|j| val[*j].is_none() && reads[e].contains(&g.vars[*j])).collect();
                    if open.len() != 1 {
                        continue;
                    }
                    let u = open[0];
                    let mut ov: Vec<(Var, F)> = (0..g.vars.len()).filter_map(|j| val[j].map(|x| (g.vars[j], x))).collect();
                    ov.push((g.vars[u], F::ZERO));
                    let f0 = ctx.eval(k, r as usize, &ov, &mut scratch);
                    ov.last_mut().expect("pushed").1 = F::ONE;
                    let f1 = ctx.eval(k, r as usize, &ov, &mut scratch);
                    ov.last_mut().expect("pushed").1 = F::TWO;
                    let f2 = ctx.eval(k, r as usize, &ov, &mut scratch);
                    if f1 == f0 {
                        if f2 != f0 {
                            return Err(format!("case {mask:#x}: constraint {c} row {r} not affine in {:?}", g.vars[u]));
                        }
                        if f0 != F::ZERO {
                            continue 'case; // violated whatever u is
                        }
                        continue; // u not read under this case
                    }
                    if f2 - f1 != f1 - f0 {
                        return Err(format!("case {mask:#x}: constraint {c} row {r} not affine in {:?}", g.vars[u]));
                    }
                    let x = -f0 * (f1 - f0).inverse();
                    if let Some(max) = self.range_of(g.vars[u]) {
                        if x.as_canonical_u64() > max {
                            continue 'case; // out of range: this case is out
                        }
                    }
                    val[u] = Some(x);
                    progress = true;
                }
                if !progress {
                    break;
                }
            }
            let free: Vec<usize> = (0..g.vars.len()).filter(|j| val[*j].is_none()).collect();
            // An equation with nothing left open must hold now: a case it
            // refutes is out, whatever the free unknowns are (R12: `nz = 0`
            // against a nonzero `Σm` refutes the case while `vpinv`, unread
            // there, is still open).
            let assigned: Vec<(Var, F)> = (0..g.vars.len()).filter_map(|j| val[j].map(|x| (g.vars[j], x))).collect();
            for (e, &(c, r)) in g.eqs.iter().enumerate() {
                if free.iter().any(|j| reads[e].contains(&g.vars[*j])) {
                    continue;
                }
                if ctx.eval(&self.constraints[c as usize], r as usize, &assigned, &mut scratch) != F::ZERO {
                    continue 'case;
                }
            }
            // Unknowns left must be unread under this case: the equations
            // hold at two unrelated values of them (else undecidable).
            for probe in [0x0123_4567u32, 0x0765_4321] {
                let ov: Vec<(Var, F)> = g
                    .vars
                    .iter()
                    .zip(&val)
                    .map(|(v, x)| (*v, x.unwrap_or(F::from_u32(probe))))
                    .collect();
                let holds = g.eqs.iter().all(|&(c, r)| ctx.eval(&self.constraints[c as usize], r as usize, &ov, &mut scratch) == F::ZERO);
                if !holds {
                    if free.is_empty() {
                        continue 'case; // a full assignment that fails
                    }
                    let left: Vec<Var> = free.iter().map(|j| g.vars[*j]).collect();
                    return Err(format!("case {mask:#x}: unknowns read but not isolated {left:?}"));
                }
                if free.is_empty() {
                    break;
                }
            }
            found += 1;
            if kept.len() < ENUM_KEEP {
                kept.push(val.clone());
            }
            for j in 0..g.vars.len() {
                agree[j] = Some(match (agree[j], val[j]) {
                    (None, x) => x,
                    (Some(Some(a)), Some(b)) if a == b => Some(a),
                    _ => None,
                });
            }
        }
        Ok((found, agree.into_iter().map(|a| a.flatten()).collect(), kept))
    }

    /// Whether cell `(row, col)` is the syntactic target of an instance that
    /// actually depends on it (its gate open) and defines it from other cells.
    fn is_derived(&self, row: usize, col: u32, scratch: &mut Vec<F>) -> bool {
        let v = Var::Cell { row: row as u32, col };
        let ctx = self.ctx();
        let honest = self.values[row * self.width + col as usize];
        let probe = honest + F::from_u32(0x0123_4567);
        let is_bool = self.boolean.get(row * self.width + col as usize).copied().unwrap_or(false) || self.boolean_at(row, col);
        let mut check = |c: u32, r: usize| {
            let k = &self.constraints[c as usize];
            if ctx.eval(k, r, &[(v, probe)], scratch) == ctx.eval(k, r, &[], scratch) {
                return false; // gate closed: inactive for this cell
            }
            match k.target {
                Some(t) => t.kind == TargetKind::Defining && t.col == col && r + t.off as usize == row,
                // Untargeted (a recomposition, the theta parity cubic, a zero
                // pin): it defines the cell when the cell is its unique root.
                None => {
                    let f0 = ctx.eval(k, r, &[(v, F::ZERO)], scratch);
                    let f1 = ctx.eval(k, r, &[(v, F::ONE)], scratch);
                    let f2 = ctx.eval(k, r, &[(v, F::TWO)], scratch);
                    (f1 != f0 && f2 - f1 == f1 - f0) || (is_bool && ((f0 == F::ZERO) != (f1 == F::ZERO)))
                }
            }
        };
        if self.reads_local[col as usize].iter().any(|&c| check(c, row)) {
            return true;
        }
        row > 0 && self.reads_next[col as usize].iter().any(|&c| check(c, row - 1))
    }

    /// The linear system of instances `eqs` in unknowns `vars` (every other
    /// cell at its current value — the honest trace under `overlay`, `pvs`):
    /// equalities aliased, the rest eliminated, rows left with bounded
    /// unknowns only solved by recomposition. Returns each unknown's value
    /// where the system determines it.
    fn solve_system(&self, eqs: &[(u32, u32)], vars: &[Var], overlay: Option<&HashMap<usize, F>>, pvs: &[F]) -> Vec<Option<F>> {
        let ctx = Ctx { values: &self.values, overlay, pvs, width: self.width, height: self.height, periodic: &self.periodic };
        let mut scratch = Vec::new();
        let n = vars.len();
        let pos: HashMap<Var, usize> = vars.iter().enumerate().map(|(i, v)| (*v, i)).collect();
        // Linearise every instance in the unknowns it reads.
        let mut rows_lin: Vec<(Vec<(usize, F)>, F)> = Vec::with_capacity(eqs.len());
        for &(c, row) in eqs {
            let (c, row) = (c as usize, row as usize);
            let mine: Vec<usize> = self.vars_of(c, row).into_iter().filter_map(|v| pos.get(&v).copied()).collect();
            let k = &self.constraints[c];
            let zeros: Vec<(Var, F)> = mine.iter().map(|&i| (vars[i], F::ZERO)).collect();
            let base = ctx.eval(k, row, &zeros, &mut scratch);
            let mut terms = Vec::new();
            for (j, &i) in mine.iter().enumerate() {
                let mut ov = zeros.clone();
                ov[j].1 = F::ONE;
                let a = ctx.eval(k, row, &ov, &mut scratch) - base;
                if a != F::ZERO {
                    terms.push((i, a));
                }
            }
            rows_lin.push((terms, base));
        }
        // Alias pure equalities a·x − a·y = 0.
        let mut uf: Vec<usize> = (0..n).collect();
        fn find(u: &mut [usize], mut x: usize) -> usize {
            while u[x] != x {
                u[x] = u[u[x]];
                x = u[x];
            }
            x
        }
        for (terms, base) in &rows_lin {
            if terms.len() == 2 && *base == F::ZERO && terms[0].1 == -terms[1].1 {
                let (a, b) = (find(&mut uf, terms[0].0), find(&mut uf, terms[1].0));
                if a != b {
                    uf[a] = b;
                }
            }
        }
        let rep: Vec<usize> = (0..n).map(|i| find(&mut uf, i)).collect();
        let mut reps: Vec<usize> = rep.clone();
        reps.sort_unstable();
        reps.dedup();
        let mut out = vec![None; n];
        if reps.len() > 600 {
            return out;
        }
        let rpos: HashMap<usize, usize> = reps.iter().enumerate().map(|(i, r)| (*r, i)).collect();
        let m = reps.len();
        // A class's range: the tightest member's.
        let mut range: Vec<Option<u64>> = vec![None; m];
        for i in 0..n {
            if let Some(r) = self.range_of(vars[i]) {
                let k = rpos[&rep[i]];
                range[k] = Some(range[k].map_or(r, |x: u64| x.min(r)));
            }
        }
        // Dense rows over classes: Σ a·x + base = 0.
        let mut mat: Vec<Vec<F>> = Vec::new();
        for (terms, base) in &rows_lin {
            let mut row = vec![F::ZERO; m + 1];
            for &(i, a) in terms {
                row[rpos[&rep[i]]] += a;
            }
            row[m] = *base;
            if row[..m].iter().any(|x| *x != F::ZERO) {
                mat.push(row);
            } else if *base != F::ZERO {
                return out; // inconsistent at this context
            }
        }
        // Eliminate unbounded classes first.
        let mut order: Vec<usize> = (0..m).collect();
        order.sort_by_key(|k| range[*k].is_some());
        let mut piv_row = 0;
        for &col in &order {
            let Some(p) = (piv_row..mat.len()).find(|r| mat[*r][col] != F::ZERO) else { continue };
            mat.swap(piv_row, p);
            let inv = mat[piv_row][col].inverse();
            for x in mat[piv_row].iter_mut() {
                *x *= inv;
            }
            for r in 0..mat.len() {
                if r != piv_row && mat[r][col] != F::ZERO {
                    let f = mat[r][col];
                    for j in 0..=m {
                        let v = mat[piv_row][j];
                        mat[r][j] -= f * v;
                    }
                }
            }
            piv_row += 1;
        }
        let debug = std::env::var_os("DETAUDIT_DEBUG").is_some();
        if debug {
            eprintln!("solve_system: {} eqs, {} vars, {} classes, {} rows after elimination", eqs.len(), n, m, mat.len());
            for (k, r) in reps.iter().enumerate() {
                let members: Vec<String> = (0..n).filter(|i| rep[*i] == *r).take(3).map(|i| format!("{:?}", vars[i])).collect();
                eprintln!("  class {k}: {}", members.join(", "));
            }
            for (terms, base) in &rows_lin {
                eprintln!("  eq {:?} base {}", terms.iter().map(|(i, a)| (format!("{:?}", vars[*i]), signed(*a))).collect::<Vec<_>>(), signed(*base));
            }
            for row in &mat {
                let nz: Vec<String> = (0..m).filter(|k| row[*k] != F::ZERO).map(|k| format!("{}:{}{}", k, signed(row[k]), if range[k].is_some() { "b" } else { "" })).collect();
                eprintln!("  row [{}] rhs {}", nz.join(" "), signed(-row[m]));
            }
        }
        // Read off values: single-unknown rows, and bounded-only rows.
        let mut val: Vec<Option<F>> = vec![None; m];
        loop {
            let mut progress = false;
            for row in &mat {
                let mut rhs = -row[m];
                let mut unk = Vec::new();
                for k in 0..m {
                    if row[k] == F::ZERO {
                        continue;
                    }
                    match val[k] {
                        Some(x) => rhs -= row[k] * x,
                        None => unk.push(k),
                    }
                }
                if unk.len() == 1 {
                    val[unk[0]] = Some(rhs * row[unk[0]].inverse());
                    progress = true;
                } else if unk.len() > 1 && unk.iter().all(|k| range[*k].is_some()) {
                    // A row is fixed only up to a scalar, and elimination
                    // normalises pivots to 1 — so an integer relation like
                    // Σ 2^k·c_k = t can arrive as Σ 2^(k−1)·c_k = t/2 with ½ a
                    // huge field element. Try each unknown's coefficient as
                    // the unit (and the row as is).
                    let r: Vec<u64> = unk.iter().map(|k| range[*k].unwrap()).collect();
                    let scales = std::iter::once(F::ONE).chain(unk.iter().map(|k| row[*k].inverse()));
                    for lam in scales {
                        let a: Vec<i64> = unk.iter().map(|k| signed(lam * row[*k])).collect();
                        if !superincreasing(&a, &r, (F::ORDER_U32 / 2) as i128) {
                            continue;
                        }
                        if let Some(x) = solve_ranged(&a, &r, signed(lam * rhs)) {
                            for (j, k) in unk.iter().enumerate() {
                                val[*k] = Some(F::from_u64(x[j]));
                            }
                            progress = true;
                        }
                        break;
                    }
                }
            }
            if !progress {
                break;
            }
        }
        for i in 0..n {
            out[i] = val[rpos[&rep[i]]];
        }
        out
    }

    /// The elimination step: every stalled instance that is jointly affine in
    /// the undetermined variables it depends on, grouped into connected
    /// systems and solved ([`Census::solve_system`]). Returns what it
    /// determined.
    fn eliminate(&mut self) -> Vec<Var> {
        let mut scratch = Vec::new();
        // (constraint, row, dependents, is a pure equality a·x − a·y).
        let mut pending: Vec<(u32, u32, Vec<Var>, bool)> = Vec::new();
        const CAP: usize = 8_000_000;
        // Only small equations build systems: a bank's transition reads three
        // unknowns, its close one or two, its carries are equalities. A wide
        // equation (the engine's 25-bit slot recompositions, a V-slot birth)
        // would merge every bank into the Keccak state's one giant component
        // and nothing would be solvable under the class cap — an earlier revision's
        // regression. Dropping an equation only loses information (sound).
        const SMALL: usize = 8;
        let mut direct: Vec<Var> = Vec::new();
        let scope = self.scope.start..self.scope.end.min(self.rows);
        'sweep: for row in scope {
            // Dropping the rest of a sweep only loses information (sound).
            if row.is_multiple_of(1024) && self.past_deadline() {
                return Vec::new();
            }
            for c in 0..self.constraints.len() {
                if self.vars_of(c, row).iter().all(|v| self.is_det(*v)) {
                    continue;
                }
                let d = self.dependents(c, row, &mut scratch);
                // A single dependent the worklist missed (it was swept before
                // its last input settled): determine it now — the sweep is a
                // full re-scan, so nothing stays stranded behind an order.
                if d.len() == 1 && std::env::var_os("DETAUDIT_NO_LATE_PV").is_none() {
                    if let Some(i) = self.idx(d[0]) {
                        if let Some(rule) = self.solve_one(c, row, d[0], &mut scratch) {
                            self.det[i] = Det::some(rule, c as u32);
                            self.order.push((d[0], row as u32));
                            direct.push(d[0]);
                        }
                    }
                    continue;
                }
                if d.len() < 2 || d.len() > SMALL || d.iter().any(|v| matches!(v, Var::Outside { .. })) {
                    continue;
                }
                // Joint affinity at a random point.
                let ctx = self.ctx();
                let k = &self.constraints[c];
                let zeros: Vec<(Var, F)> = d.iter().map(|v| (*v, F::ZERO)).collect();
                let base = ctx.eval(k, row, &zeros, &mut scratch);
                let mut lin = base;
                let mut pt = zeros.clone();
                let mut coef = Vec::with_capacity(d.len());
                for j in 0..d.len() {
                    let mut ov = zeros.clone();
                    ov[j].1 = F::ONE;
                    let a = ctx.eval(k, row, &ov, &mut scratch) - base;
                    coef.push(a);
                    let x: F = F::from_u32((j as u32).wrapping_mul(2_654_435_761) >> 3 | 1);
                    pt[j].1 = x;
                    lin += a * x;
                }
                if ctx.eval(k, row, &pt, &mut scratch) != lin {
                    continue;
                }
                let equal = d.len() == 2 && base == F::ZERO && coef[0] == -coef[1] && coef[0] != F::ZERO;
                pending.push((c as u32, row as u32, d, equal));
                if pending.len() >= CAP {
                    break 'sweep;
                }
            }
        }
        // Aliases first (pure equalities), then systems over small equations
        // counted in alias classes.
        let mut ids: HashMap<Var, usize> = HashMap::new();
        for (_, _, d, _) in &pending {
            for v in d {
                let n = ids.len();
                ids.entry(*v).or_insert(n);
            }
        }
        fn find(u: &mut [usize], mut x: usize) -> usize {
            while u[x] != x {
                u[x] = u[u[x]];
                x = u[x];
            }
            x
        }
        let mut alias: Vec<usize> = (0..ids.len()).collect();
        for (_, _, d, equal) in &pending {
            if *equal {
                let (a, b) = (find(&mut alias, ids[&d[0]]), find(&mut alias, ids[&d[1]]));
                if a != b {
                    alias[b] = a;
                }
            }
        }
        const CLASSES_PER_EQ: usize = 4;
        let mut uf: Vec<usize> = (0..ids.len()).collect();
        let mut used = vec![false; pending.len()];
        for (e, (_, _, d, equal)) in pending.iter().enumerate() {
            let mut cls: Vec<usize> = d.iter().map(|v| find(&mut alias, ids[v])).collect();
            cls.sort_unstable();
            cls.dedup();
            if !*equal && cls.len() > CLASSES_PER_EQ {
                continue;
            }
            used[e] = true;
            let a = find(&mut uf, ids[&d[0]]);
            for v in &d[1..] {
                let b = find(&mut uf, ids[v]);
                if a != b {
                    uf[b] = a;
                }
            }
        }
        let mut systems: HashMap<usize, (Vec<(u32, u32)>, Vec<Var>)> = HashMap::new();
        let mut in_system = vec![false; ids.len()];
        for (e, (c, row, d, _)) in pending.iter().enumerate() {
            if !used[e] {
                continue;
            }
            let r = find(&mut uf, ids[&d[0]]);
            systems.entry(r).or_default().0.push((*c, *row));
            for v in d {
                in_system[ids[v]] = true;
            }
        }
        let mut all: Vec<(Var, usize)> = ids.iter().filter(|(_, i)| in_system[**i]).map(|(v, i)| (*v, *i)).collect();
        all.sort_unstable();
        for (v, i) in all {
            let r = find(&mut uf, i);
            systems.entry(r).or_default().1.push(v);
        }
        let mut new = direct;
        let pvs = self.pvs.clone();
        let mut keys: Vec<usize> = systems.keys().copied().collect();
        keys.sort_unstable();
        const REGION: usize = 200;
        for key in keys {
            let (eqs, vars) = &systems[&key];
            let classes = {
                let mut r: Vec<usize> = vars.iter().map(|v| find(&mut alias, ids[v])).collect();
                r.sort_unstable();
                r.dedup();
                r.len()
            };
            // A system within the cap is solved whole; a larger one on bounded
            // neighbourhoods grown from its equations over a bounded unknown
            // (a bank's bits) — sound, a subset that determines a variable
            // determines it in the whole.
            let regions: Vec<(Vec<(u32, u32)>, Vec<Var>)> = if classes <= 600 {
                vec![(eqs.clone(), vars.clone())]
            } else {
                let eq_vars: Vec<Vec<Var>> = eqs
                    .iter()
                    .map(|(c, r)| {
                        self.vars_of(*c as usize, *r as usize).into_iter().filter(|v| ids.contains_key(v) && !self.is_det(*v)).collect()
                    })
                    .collect();
                let mut by_class: HashMap<usize, Vec<usize>> = HashMap::new();
                for (e, vs) in eq_vars.iter().enumerate() {
                    for v in vs {
                        by_class.entry(find(&mut alias, ids[v])).or_default().push(e);
                    }
                }
                let mut seeded = vec![false; eqs.len()];
                let mut out = Vec::new();
                for seed in 0..eqs.len() {
                    if seeded[seed] || !eq_vars[seed].iter().any(|v| self.range_of(*v).is_some()) {
                        continue;
                    }
                    let mut region_eqs = vec![seed];
                    let mut seen_eq: std::collections::HashSet<usize> = [seed].into_iter().collect();
                    let mut seen_cls: std::collections::HashSet<usize> = Default::default();
                    let mut frontier = std::collections::VecDeque::from([seed]);
                    while let Some(e) = frontier.pop_front() {
                        for v in &eq_vars[e] {
                            let c = find(&mut alias, ids[v]);
                            if !seen_cls.insert(c) {
                                continue;
                            }
                            for &e2 in &by_class[&c] {
                                if seen_eq.insert(e2) {
                                    region_eqs.push(e2);
                                    frontier.push_back(e2);
                                }
                            }
                        }
                        if seen_cls.len() >= REGION {
                            break;
                        }
                    }
                    for &e in &region_eqs {
                        seeded[e] = true;
                    }
                    let mut rv: Vec<Var> = region_eqs.iter().flat_map(|e| eq_vars[*e].iter().copied()).collect();
                    rv.sort_unstable();
                    rv.dedup();
                    out.push((region_eqs.iter().map(|e| eqs[*e]).collect(), rv));
                }
                out
            };
            for (reqs, rvars) in regions {
                let sol = self.solve_system(&reqs, &rvars, None, &pvs);
                let got: Vec<Var> = rvars.iter().zip(sol.iter()).filter(|(v, x)| x.is_some() && !self.is_det(**v)).map(|(v, _)| *v).collect();
                if got.is_empty() {
                    continue;
                }
                let g = self.groups.len() as u32;
                self.groups.push(LinearGroup { eqs: reqs, vars: rvars });
                for v in got {
                    let i = self.idx(v).expect("pending variables are in the window");
                    self.det[i] = Det::some(Rule::Linear, g);
                    self.order.push((v, 0));
                    new.push(v);
                }
            }
        }
        new
    }

    // -----------------------------------------------------------------------
    // The report
    // -----------------------------------------------------------------------

    /// Components of the undetermined variables some instance depends on
    /// jointly with another; allowances applied.
    pub fn report(&mut self, allowances: &[Allowance]) -> Report {
        let nvar = self.det.len();
        let mut parent: Vec<u32> = (0..nvar as u32).collect();
        fn find(p: &mut [u32], mut x: u32) -> u32 {
            while p[x as usize] != x {
                p[x as usize] = p[p[x as usize] as usize];
                x = p[x as usize];
            }
            x
        }
        let mut consumed = vec![false; nvar];
        let mut scratch = Vec::new();
        for row in 0..self.rows {
            for c in 0..self.constraints.len() {
                if self.vars_of(c, row).iter().all(|v| self.is_det(*v) || matches!(v, Var::Outside { .. })) {
                    continue;
                }
                // A self-carry (`next X = X`) or a shape constraint relates a
                // free cell only to itself: it spreads a freedom (so it joins
                // the component) but does not consume one.
                let defining = self.constraints[c].target.is_none_or(|t| t.kind == TargetKind::Defining);
                let d: Vec<usize> = self.dependents(c, row, &mut scratch).into_iter().filter_map(|v| self.idx(v)).collect();
                if d.len() >= 2 {
                    if defining {
                        for &x in &d {
                            consumed[x] = true;
                        }
                    }
                    let r0 = find(&mut parent, d[0] as u32);
                    for &x in &d[1..] {
                        let rx = find(&mut parent, x as u32);
                        if rx != r0 {
                            parent[rx as usize] = r0;
                        }
                    }
                }
            }
        }
        let cells = self.rows * self.width;
        let mut rep = Report { cells, ..Default::default() };
        // Classes that hold a consumed cell are components (with any public
        // values joined to them);
        // the rest are free cells nothing reads (malleability, not freedom).
        let mut live: BTreeMap<u32, bool> = BTreeMap::new();
        for i in 0..nvar {
            // A public value alone is not a freedom: undetermined with no
            // free cell behind it means its bind is outside the window.
            if self.det[i].get().is_none() && consumed[i] && i < cells {
                let r = find(&mut parent, i as u32);
                live.insert(r, true);
            }
        }
        let mut comps: BTreeMap<u32, Component> = BTreeMap::new();
        let mut dead: std::collections::BTreeSet<u32> = Default::default();
        for i in 0..nvar {
            if self.det[i].get().is_some() {
                if i < cells {
                    rep.determined += 1;
                }
                continue;
            }
            if i >= cells {
                rep.pvs_undetermined.push((i - cells) as u32);
            } else {
                rep.undetermined += 1;
            }
            let r = find(&mut parent, i as u32);
            if !live.contains_key(&r) {
                if i < cells {
                    rep.unconsumed += 1;
                    dead.insert(r);
                }
                continue;
            }
            let comp = comps.entry(r).or_insert_with(|| Component { min_row: usize::MAX, ..Default::default() });
            if i >= cells {
                comp.pvs.push((i - cells) as u32);
            } else {
                let (row, col) = (i / self.width, i % self.width);
                comp.cells += 1;
                comp.min_row = comp.min_row.min(row);
                comp.max_row = comp.max_row.max(row);
                let key = (col as u32, self.program.role_of_row(row));
                *comp.buckets.entry(key).or_default() += 1;
                let smp = comp.samples.entry(key).or_default();
                if smp.len() < 4 {
                    smp.push(i);
                }
            }
        }
        rep.malleable = dead.len();
        let mut under: BTreeMap<(&'static str, u32), usize> = BTreeMap::new();
        let mut inside: BTreeMap<(&'static str, u32), usize> = BTreeMap::new();
        for &(i, field, role) in &self.copy_cells {
            // Cells of the last window perm reading past the window are an edge.
            if self.det[i].get().is_none() && (self.rows == self.height || i / self.width + self.program.rows_per_perm < self.rows) {
                // A copy lane's cells no defining constraint reads (a W lane
                // off its role's boundary rows) are not a tie at all.
                if !consumed[i] {
                    continue;
                }
                let r = find(&mut parent, i as u32);
                if live.contains_key(&r) {
                    *inside.entry((field, role)).or_default() += 1;
                } else {
                    *under.entry((field, role)).or_default() += 1;
                }
            }
        }
        rep.copies_underived = under.into_iter().map(|((f, r), n)| (f, r, n)).collect();
        rep.copies_in_components = inside.into_iter().map(|((f, r), n)| (f, r, n)).collect();
        // A witness copy is a consequence (its tie), never a root: holding it
        // fixed in a confirm would stop it following its origin.
        let copy_buckets: std::collections::BTreeSet<(u32, u32)> =
            self.copy_cells.iter().map(|&(i, _, role)| ((i % self.width) as u32, role)).collect();
        for mut comp in comps.into_values() {
            let samples = comp.samples.clone();
            let oriented: Vec<(u32, u32)> = samples
                .iter()
                .filter(|(_, cells)| cells.iter().all(|i| !self.is_derived(i / self.width, (i % self.width) as u32, &mut scratch)))
                .map(|(k, _)| *k)
                .collect();
            comp.roots = oriented.iter().copied().filter(|k| !copy_buckets.contains(k)).collect();
            comp.copy_roots = oriented.into_iter().filter(|k| copy_buckets.contains(k)).collect();
            if comp.roots.is_empty() {
                let mut names: Vec<(&'static str, u32)> = self
                    .copy_cells
                    .iter()
                    .filter(|&&(i, _, role)| comp.copy_roots.contains(&((i % self.width) as u32, role)))
                    .map(|&(_, f, role)| (f, role))
                    .collect();
                names.sort_unstable();
                names.dedup();
                comp.untied_fields = names;
            }
            comp.allowed = allowances
                .iter()
                .find(|a| comp.pvs.is_empty() && comp.min_row >= a.root_rows.start && comp.min_row < a.root_rows.end && comp.max_row < a.max_row)
                .map(|a| a.name);
            rep.components.push(comp);
        }
        rep
    }

    // -----------------------------------------------------------------------
    // L3: hypothetical pins and the replay
    // -----------------------------------------------------------------------

    /// The cells of bucket `(col, role)` still undetermined (public).
    pub fn undetermined_in(&self, col: u32, role: u32) -> Vec<Var> {
        self.bucket_cells(col, role)
    }

    /// The cells of bucket `(col, role)` still undetermined.
    fn bucket_cells(&self, col: u32, role: u32) -> Vec<Var> {
        (0..self.rows)
            .filter(|r| self.program.role_of_row(*r) == role)
            .map(|r| Var::Cell { row: r as u32, col })
            .filter(|v| !self.is_det(*v))
            .collect()
    }

    /// Per role: (cells, undetermined) of `cols` on the rows where column
    /// `gate` is nonzero in the honest trace — a copy counted where it is
    /// read, not wherever its role runs (lab #758 R11).
    pub fn undetermined_at_gate(&self, gate: usize, cols: &[usize]) -> std::collections::BTreeMap<u32, (usize, usize, Vec<usize>)> {
        // Per role: (cells, undetermined, the perm indices holding them).
        let mut out: std::collections::BTreeMap<u32, (usize, usize, Vec<usize>)> = Default::default();
        for row in 0..self.rows {
            if self.values[row * self.width + gate] == F::ZERO {
                continue;
            }
            let e = out.entry(self.program.role_of_row(row)).or_default();
            for &col in cols {
                e.0 += 1;
                if !self.is_det(Var::Cell { row: row as u32, col: col as u32 }) {
                    e.1 += 1;
                    let perm = row / self.program.rows_per_perm;
                    if e.2.last() != Some(&perm) {
                        e.2.push(perm);
                    }
                }
            }
        }
        out
    }

    /// The determination state, for undoing a hypothetical pin.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot { det: self.det.clone(), order_len: self.order.len() }
    }
    /// Undo everything since `snap`.
    pub fn restore(&mut self, snap: Snapshot) {
        self.det = snap.det;
        self.order.truncate(snap.order_len);
    }

    /// Pin bucket `(col, role)` as a source and run the fixpoint on from
    /// there. Returns the bucket's cells and the variables the pin resolved,
    /// in determination order. The census keeps them determined until
    /// [`Census::restore`].
    pub fn pin(&mut self, col: u32, role: u32) -> (Vec<Var>, Vec<(Var, u32)>) {
        let cells = self.bucket_cells(col, role);
        let resolved = self.pin_cells(&cells);
        (cells, resolved)
    }

    /// Give later pins a wall-clock `deadline` (`None`: unbounded, the
    /// census's own run) and clear [`Census::timed_out`]. A pin that passes
    /// it stops where it is — its result is partial, never a verdict.
    pub fn set_deadline(&mut self, deadline: Option<std::time::Instant>) {
        self.deadline = deadline;
        self.timed_out = false;
    }

    /// Whether a pin since [`Census::set_deadline`] passed the deadline.
    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    fn past_deadline(&mut self) -> bool {
        if self.deadline.is_some_and(|d| std::time::Instant::now() > d) {
            self.timed_out = true;
        }
        self.timed_out
    }

    /// Scope later elimination sweeps to `rows` (a component's rows, padded
    /// by a perm each side); `None` restores the whole window.
    pub fn set_scope(&mut self, rows: Option<Range<usize>>) {
        self.scope = rows.unwrap_or(0..self.rows);
    }

    /// Pin `cells` as sources and run the fixpoint on from there; returns
    /// what it resolved, in determination order.
    pub fn pin_cells(&mut self, cells: &[Var]) -> Vec<(Var, u32)> {
        self.pin_cells_with(cells, true)
    }

    /// [`Census::pin_cells`], with the elimination rounds optional: the
    /// fixpoint alone carries a pin down its cone (the cheap part); the
    /// elimination sweep — needed only for ties a pin re-opens — is the
    /// expensive part on a large component (R6's S3 merge confirms).
    pub fn pin_cells_with(&mut self, cells: &[Var], eliminate: bool) -> Vec<(Var, u32)> {
        let cells = cells.to_vec();
        let start = self.order.len();
        let mut seed = Vec::new();
        for v in &cells {
            let i = self.idx(*v).expect("bucket cells are in the window");
            self.det[i] = Det::some(Rule::Source, Det::SRC);
            let Var::Cell { row, col } = *v else { unreachable!() };
            for &c in &self.reads_local[col as usize] {
                seed.push((c, row));
            }
            if row > 0 {
                for &c in &self.reads_next[col as usize] {
                    seed.push((c, row - 1));
                }
            }
        }
        self.fixpoint(Some(seed));
        if eliminate {
            loop {
                if self.timed_out {
                    break;
                }
                let new = self.eliminate();
                if new.is_empty() {
                    break;
                }
                let seed = self.seed_of(&new);
                self.fixpoint(Some(seed));
            }
        }
        self.order[start..].to_vec()
    }

    /// L3: perturb `bucket` by `f` (cell value → new value), then replay the
    /// defining instances of `resolved` (what [`Census::pin`] of that bucket
    /// returned; call before [`Census::restore`]) in order, solving each
    /// numerically.
    /// Returns the repair as an overlay of changed cells (`row·width + col`)
    /// and the repaired public values — never a copy of the trace.
    pub fn repair(&self, bucket: &[Var], f: impl Fn(F) -> F, resolved: &[(Var, u32)]) -> Repair<F> {
        self.repair_until(bucket, f, resolved, None).expect("no deadline")
    }

    /// [`Census::repair`] that gives up (`None`) at `deadline` — checked in
    /// the replay loop itself, so one long replay cannot outrun a budget
    /// (R5: L2b's first probe ran 30 min past its 300 s).
    pub fn repair_until(
        &self,
        bucket: &[Var],
        f: impl Fn(F) -> F,
        resolved: &[(Var, u32)],
        deadline: Option<std::time::Instant>,
    ) -> Option<Repair<F>> {
        let mut overlay: HashMap<usize, F> = HashMap::new();
        let mut pvs = self.pvs.clone();
        for v in bucket {
            if let Var::Cell { row, col } = *v {
                let i = row as usize * self.width + col as usize;
                overlay.insert(i, f(self.values[i]));
            }
        }
        let mut scratch = Vec::new();
        let mut done: std::collections::HashSet<Var> = Default::default();
        for (n, &(u, row)) in resolved.iter().enumerate() {
            if n % 4096 == 0 && deadline.is_some_and(|d| std::time::Instant::now() > d) {
                return None;
            }
            if done.contains(&u) {
                continue;
            }
            let Some(i) = self.idx(u) else { continue };
            let Some((rule, c)) = self.det[i].get() else { continue };
            let row = row as usize;
            let k = &self.constraints[c as usize];
            let mut solved: Vec<(Var, F)> = Vec::new();
            {
                let ctx = Ctx { values: &self.values, overlay: Some(&overlay), pvs: &pvs, width: self.width, height: self.height, periodic: &self.periodic };
                match rule {
                    Rule::Source => {}
                    Rule::Affine => {
                        let f0 = ctx.eval(k, row, &[(u, F::ZERO)], &mut scratch);
                        let f1 = ctx.eval(k, row, &[(u, F::ONE)], &mut scratch);
                        // Under a perturbation the coefficient can vanish (a
                        // case-split definer whose boolean left {0, 1}, R14):
                        // no root to take — the cell keeps its value and the
                        // violation check reports the instance.
                        if f1 != f0 {
                            solved.push((u, -f0 * (f1 - f0).inverse()));
                        }
                    }
                    Rule::BoolRoot => {
                        let f0 = ctx.eval(k, row, &[(u, F::ZERO)], &mut scratch);
                        solved.push((u, if f0 == F::ZERO { F::ZERO } else { F::ONE }));
                    }
                    Rule::Recompose => {
                        // The group: every variable this instance determined at once.
                        let group: Vec<Var> = resolved
                            .iter()
                            .filter(|(v, r)| *r as usize == row && self.idx(*v).and_then(|j| self.det[j].get()) == Some((Rule::Recompose, c)))
                            .map(|(v, _)| *v)
                            .collect();
                        let zeros: Vec<(Var, F)> = group.iter().map(|v| (*v, F::ZERO)).collect();
                        let base = ctx.eval(k, row, &zeros, &mut scratch);
                        let mut a = Vec::with_capacity(group.len());
                        let mut r = Vec::with_capacity(group.len());
                        for j in 0..group.len() {
                            let mut ov = zeros.clone();
                            ov[j].1 = F::ONE;
                            a.push(signed(ctx.eval(k, row, &ov, &mut scratch) - base));
                            r.push(self.range_of(group[j]).unwrap_or(1));
                        }
                        if let Some(x) = solve_ranged(&a, &r, -signed(base)) {
                            for (j, v) in group.iter().enumerate() {
                                solved.push((*v, F::from_u64(x[j])));
                            }
                        }
                    }
                    Rule::Enum => {
                        let g = &self.enums[c as usize];
                        if let Ok((n, fixed, _)) = self.enum_group(g, Some(&overlay), &pvs) {
                            if n >= 1 {
                                for (v, x) in g.vars.iter().zip(fixed) {
                                    let det_here = self.idx(*v).and_then(|j| self.det[j].get()) == Some((Rule::Enum, c));
                                    if let (Some(x), true) = (x, det_here) {
                                        solved.push((*v, x));
                                    }
                                }
                            }
                        }
                    }
                    Rule::Linear => {
                        let g = &self.groups[c as usize];
                        let sol = self.solve_system(&g.eqs, &g.vars, Some(&overlay), &pvs);
                        for (v, x) in g.vars.iter().zip(sol) {
                            if let (Some(x), Some(j)) = (x, self.idx(*v)) {
                                if self.det[j].get().map(|d| d.0) == Some(Rule::Linear) {
                                    solved.push((*v, x));
                                }
                            }
                        }
                    }
                }
            }
            for (v, x) in solved {
                match v {
                    Var::Cell { row, col } => {
                        overlay.insert(row as usize * self.width + col as usize, x);
                    }
                    Var::Pub(i) => pvs[i as usize] = x,
                    Var::Outside { .. } => {}
                }
                done.insert(v);
            }
        }
        Some(Repair { overlay, pvs })
    }

    /// Every violated instance of the repaired trace that the repair could
    /// have changed: all rows up to one past the highest changed row (and the
    /// wrap row when row 0 changed), plus every row of each constraint that
    /// reads a changed public value. Exact for a full-height census and a
    /// repair that changes only those — every other instance reads the honest
    /// trace, which satisfies the AIR. **A windowed census checks the changed
    /// public values inside its window only**: its SAT is a window-SAT, and
    /// the full check is the box run's. Returns (constraint, row) pairs, at
    /// most `limit`.
    pub fn violations(&self, rep: &Repair<F>, limit: usize) -> Vec<(usize, usize)> {
        let ctx = Ctx { values: &self.values, overlay: Some(&rep.overlay), pvs: &rep.pvs, width: self.width, height: self.height, periodic: &self.periodic };
        let mut scratch = Vec::new();
        let mut out = Vec::new();
        // The cone: rows from one above the lowest changed row to the highest
        // (every other instance reads only honest cells).
        let top = rep.overlay.keys().map(|i| i / self.width).max().unwrap_or(0);
        let bottom = rep.overlay.keys().map(|i| i / self.width).min().unwrap_or(0).saturating_sub(1);
        let mut rows: Vec<usize> = (bottom..=top.min(self.height - 1)).collect();
        if rep.overlay.keys().any(|i| i / self.width == 0) {
            rows.push(self.height - 1);
        }
        let changed_pvs: Vec<u32> = (0..self.pvs.len()).filter(|i| rep.pvs[*i] != self.pvs[*i]).map(|i| i as u32).collect();
        for c in 0..self.constraints.len() {
            let reads_changed_pv = self.constraints[c].pubs.iter().any(|p| changed_pvs.contains(p));
            // A windowed census holds only its window: a changed public value
            // is checked there, and the rest of the trace is the box run's.
            let pv_rows = if self.rows == self.height { self.height } else { self.rows };
            let it: Box<dyn Iterator<Item = usize>> =
                if reads_changed_pv { Box::new(0..pv_rows) } else { Box::new(rows.iter().copied()) };
            for row in it {
                if ctx.eval(&self.constraints[c], row, &[], &mut scratch) != F::ZERO {
                    out.push((c, row));
                    if out.len() >= limit {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// The repaired trace as a full matrix (a copy), for an independent check
    /// such as p3's `check_constraints`. Full-height censuses only.
    pub fn materialize(&self, rep: &Repair<F>) -> Option<(RowMajorMatrix<F>, Vec<F>)> {
        if self.rows != self.height {
            return None;
        }
        let mut values = self.values.clone();
        for (i, x) in &rep.overlay {
            values[*i] = *x;
        }
        Some((RowMajorMatrix::new(values, self.width), rep.pvs.clone()))
    }

    /// The honest value of trace cell `i` (`row·width + col`).
    pub fn value(&self, i: usize) -> F {
        self.values[i]
    }
    /// The honest public values.
    pub fn pvs(&self) -> &[F] {
        &self.pvs
    }
    /// A constraint's symbolic shape, for a report line: its target (column,
    /// `next` or local, kind) and every cell and public value it reads — so
    /// no one maps a constraint index by hand.
    pub fn describe_constraint(&self, c: usize) -> String {
        let k = &self.constraints[c];
        let t = match k.target {
            Some(t) => format!("target col{}{} ({:?})", t.col, if t.off == 1 { "′" } else { "" }, t.kind),
            None => "untargeted".to_string(),
        };
        let reads: Vec<String> = k.reads.iter().map(|(col, off)| format!("col{col}{}", if *off == 1 { "′" } else { "" })).collect();
        let pubs = if k.pubs.is_empty() { String::new() } else { format!(", pv {:?}", k.pubs) };
        format!("c{c}: {t}; reads [{}]{pubs}", reads.join(" "))
    }

    /// `true` when perturbing every cell a constraint reads changes it on
    /// some sampled row: **implied** (live, but redundant on this trace);
    /// `false`: **inert** (nothing on this trace moves it — its gate is
    /// closed, or it reads only constants).
    pub fn is_live_somewhere(&self, c: usize, offsets: &[usize]) -> bool {
        let rpp = self.program.rows_per_perm;
        let perms = self.height / rpp;
        let mut last: BTreeMap<u32, usize> = BTreeMap::new();
        for p in 0..perms {
            last.insert(self.program.role_of_row(p * rpp), p);
        }
        let ctx = self.ctx();
        let mut scratch = Vec::new();
        let mut rng = Rng(0x0758_11fe);
        let k = &self.constraints[c];
        last.values()
            .flat_map(|p| offsets.iter().map(move |o| p * rpp + o))
            .chain([0, self.height - 1])
            .filter(|r| *r < self.height)
            .any(|row| {
                let honest = ctx.eval(k, row, &[], &mut scratch);
                let ov: Vec<(Var, F)> = k
                    .reads
                    .iter()
                    .map(|&(col, off)| (Var::Cell { row: ((row + off as usize) % self.height) as u32, col }, rng.field()))
                    .collect();
                ctx.eval(k, row, &ov, &mut scratch) != honest
            })
    }

    /// Indices of the constraints reading exactly these columns (local).
    pub fn constraints_reading_exactly(&self, cols: &[usize]) -> Vec<usize> {
        let mut want: Vec<(u32, u8)> = cols.iter().map(|c| (*c as u32, 0u8)).collect();
        want.sort_unstable();
        (0..self.constraints.len()).filter(|c| self.constraints[*c].reads == want).collect()
    }

    /// Rows per perm.
    pub fn rows_per_perm(&self) -> usize {
        self.program.rows_per_perm
    }
    /// The trace width.
    pub fn width(&self) -> usize {
        self.width
    }
    /// The role of a row.
    pub fn role_of_row(&self, row: usize) -> u32 {
        self.program.role_of_row(row)
    }
}

/// A saved determination state ([`Census::snapshot`]).
pub struct Snapshot {
    det: Vec<Det>,
    order_len: usize,
}

/// A repair: the changed cells over the honest trace, and the public values.
pub struct Repair<F> {
    pub overlay: HashMap<usize, F>,
    pub pvs: Vec<F>,
}

// ---------------------------------------------------------------------------
// L1: the static role census (the resident guard)
// ---------------------------------------------------------------------------

/// One L1 flag: in perms of `role`, column `col` is **consumed** (an active
/// defining constraint targeting another cell depends on it) on some sampled
/// row where it is **not defined** — no active constraint targeting it (or
/// untargeted, like a recomposition or a zero pin) has it as a unique root
/// given the rest of its row, and no carry spreads a definition to it — and
/// it is not a manifest input. PBIT on NF rows before lab PR #737 is the
/// shape: bool + per-perm constancy only, consumed by `eff`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct L1Flag {
    pub col: u32,
    pub role: u32,
    /// A sampled row where it is consumed and undefined.
    pub row: usize,
    /// The first constraint (index in `get_symbolic_constraints` order) that
    /// consumes it on that row — the evidence a triage cites.
    pub reader: u32,
}

impl<F: PrimeField32> Census<F> {
    /// L1 over the whole program, without the L2 fixpoint: for each role,
    /// its **last** occurrence's perm (never the leading dummy, whose row 0
    /// is the #143 warm-up), rounds 0, 1 and 23 (the boundary round, a
    /// generic one, the closing one — the only three row structures a narrow
    /// -engine perm has). Build with [`Census::for_l1`].
    pub fn l1(&mut self, manifest: &[ManifestEntry]) -> Vec<L1Flag> {
        self.l1_with_stats(manifest).0
    }

    /// [`Census::l1`] plus the probe's own counts — (roles sampled, consumed
    /// (column, role) pairs, defined (column, role) pairs) — so a zero-flag
    /// result can be told apart from a probe that looked at nothing.
    pub fn l1_with_stats(&mut self, manifest: &[ManifestEntry]) -> (Vec<L1Flag>, (usize, usize, usize)) {
        // A narrow-engine perm has three row structures: the boundary round,
        // a generic one, the closing one.
        let offsets: Vec<usize> = [0usize, 1, 23].iter().flat_map(|q| (128 * q)..(128 * (q + 1))).collect();
        self.l1_core(manifest, &offsets)
    }

    /// L1 over explicit row offsets within each role's last perm (a non-
    /// narrow-engine AIR, e.g. the toy rig: every row).
    pub fn l1_rows(&mut self, manifest: &[ManifestEntry], offsets: &[usize]) -> Vec<L1Flag> {
        self.l1_core(manifest, offsets).0
    }

    fn l1_core(&mut self, manifest: &[ManifestEntry], offsets: &[usize]) -> (Vec<L1Flag>, (usize, usize, usize)) {
        let (mut n_consumed, mut n_defined) = (0usize, 0usize);
        let rpp = self.program.rows_per_perm;
        let perms = self.height / rpp;
        let mut last: BTreeMap<u32, usize> = BTreeMap::new();
        // The last occurrence of each role (a later dummy replaces the leading
        // one, whose row 0 is the #143 warm-up).
        for p in 0..perms {
            last.insert(self.program.role_of_row(p * rpp), p);
        }
        let mut scratch = Vec::new();
        let mut flags = Vec::new();
        for (&role, &p) in &last {
            let manifest_cols: Vec<usize> = manifest
                .iter()
                .filter(|m| m.role == role || m.role == ANY_ROLE)
                .flat_map(|m| m.cols.iter().copied())
                .collect();
            let base = p * rpp;
            let rows: Vec<usize> = offsets.iter().map(|o| base + o).filter(|r| *r < self.height).collect();
            // Per sampled row: (defined, consumed) per column.
            let w = self.width;
            let mut defined = vec![false; rows.len() * w];
            let mut consumed = vec![false; rows.len() * w];
            let mut reader = vec![u32::MAX; rows.len() * w];
            let mut carried = vec![false; rows.len() * w]; // a self-carry links row i to row i+1
            for (ri, &row) in rows.iter().enumerate() {
                for (r, off) in [(row, 0u8), (row.wrapping_sub(1), 1u8)] {
                    if r >= self.height {
                        continue;
                    }
                    for c in 0..self.constraints.len() {
                        let k = &self.constraints[c];
                        if !k.reads.iter().any(|&(_, o)| o == off) {
                            continue;
                        }
                        let ctx = self.ctx();
                        let honest = ctx.eval(k, r, &[], &mut scratch);
                        for &(col, o) in k.reads.iter().filter(|(_, o)| *o == off) {
                            let v = Var::Cell { row: row as u32, col };
                            let x = self.values[row * w + col as usize];
                            let bump = ctx.eval(k, r, &[(v, x + F::from_u32(0x0246_8ace))], &mut scratch);
                            if bump == honest {
                                continue; // gate closed at this row: inactive for this cell
                            }
                            let i = ri * w + col as usize;
                            match k.target {
                                Some(t) if t.col == col && t.off == o => match t.kind {
                                    TargetKind::Defining => defined[i] = true,
                                    TargetKind::SelfCarry if o == 1 => {
                                        if ri > 0 && rows[ri - 1] + 1 == row {
                                            carried[(ri - 1) * w + col as usize] = true;
                                        }
                                    }
                                    _ => {}
                                },
                                // A carry's source side or a shape constraint on
                                // another cell spreads, it does not consume.
                                Some(t) if t.kind != TargetKind::Defining => {}
                                Some(_) => {
                                    consumed[i] = true;
                                    if reader[i] == u32::MAX {
                                        reader[i] = c as u32;
                                    }
                                }
                                None => {
                                    // Untargeted: defines the cell when it is its unique root.
                                    let f0 = ctx.eval(k, r, &[(v, F::ZERO)], &mut scratch);
                                    let f1 = ctx.eval(k, r, &[(v, F::ONE)], &mut scratch);
                                    let f2 = ctx.eval(k, r, &[(v, F::TWO)], &mut scratch);
                                    let affine = f1 != f0 && f2 - f1 == f1 - f0;
                                    let bool_root = self.boolean_at(row, col) && ((f0 == F::ZERO) != (f1 == F::ZERO));
                                    if affine || bool_root {
                                        defined[i] = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Spread definitions along self-carries, both ways, to a fixpoint.
            loop {
                let mut changed = false;
                for ri in 0..rows.len().saturating_sub(1) {
                    for col in 0..w {
                        if carried[ri * w + col] && defined[ri * w + col] != defined[(ri + 1) * w + col] {
                            defined[ri * w + col] = true;
                            defined[(ri + 1) * w + col] = true;
                            changed = true;
                        }
                    }
                }
                if !changed {
                    break;
                }
            }
            for col in 0..w {
                if (0..rows.len()).any(|ri| consumed[ri * w + col]) {
                    n_consumed += 1;
                }
                if (0..rows.len()).any(|ri| defined[ri * w + col]) {
                    n_defined += 1;
                }
                if manifest_cols.contains(&col) {
                    continue;
                }
                if let Some(ri) = (0..rows.len()).find(|ri| consumed[ri * w + col] && !defined[ri * w + col]) {
                    flags.push(L1Flag { col: col as u32, role, row: rows[ri], reader: reader[ri * w + col] });
                }
            }
        }
        flags.sort();
        (flags, (last.len(), n_consumed, n_defined))
    }

    /// Which constraints the census actually leaned on: the recorded definer
    /// of some variable (affine, boolean root, recomposition), or an equation
    /// of a solved linear system. Call on the base census (before pins).
    pub fn load_bearing(&self) -> Vec<bool> {
        let mut used = vec![false; self.constraints.len()];
        let mut groups = std::collections::BTreeSet::new();
        for d in &self.det {
            match d.get() {
                Some((Rule::Source, _)) | None => {}
                Some((Rule::Linear, g)) => {
                    groups.insert(g);
                }
                Some((Rule::Enum, g)) => {
                    for &(c, _) in &self.enums[g as usize].eqs {
                        used[c as usize] = true;
                    }
                }
                Some((_, c)) => used[c as usize] = true,
            }
        }
        for g in groups {
            for &(c, _) in &self.groups[g as usize].eqs {
                used[c as usize] = true;
            }
        }
        used
    }

    /// Witness-mode coverage (lab #758): the constraints **vacuous on this
    /// trace** — neither load-bearing in the census ([`Census::load_bearing`]:
    /// it defined no variable and sat in no solved system) nor a restriction
    /// on the witness (on no sampled row does perturbing the witness cells it
    /// reads change it — a check on inputs, like narrow's #219 value pin with
    /// `dv = 1`). Rows: each role's last perm at `offsets`, plus the first
    /// and last rows. Call on a full census after [`Census::run`].
    ///
    /// (An earlier rule — witness perturbation alone — called the #737 NF
    /// PBIT pin vacuous: PBIT is a witness only on MERKLE rows, where
    /// `sel(NF) = 0`; on NF rows, where the pin works, it is a derived cell.)
    pub fn vacuous_constraints(&self, offsets: &[usize], manifest: &[ManifestEntry]) -> Vec<usize> {
        let used = self.load_bearing();
        let rpp = self.program.rows_per_perm;
        let perms = self.height / rpp;
        let mut last: BTreeMap<u32, usize> = BTreeMap::new();
        for p in 0..perms {
            last.insert(self.program.role_of_row(p * rpp), p);
        }
        let rows: Vec<usize> = last
            .values()
            .flat_map(|p| offsets.iter().map(move |o| p * rpp + o))
            .chain([0, self.height - 1])
            .filter(|r| *r < self.height)
            .collect();
        let witness = |row: usize, col: u32| {
            let role = self.program.role_of_row(row);
            manifest.iter().any(|m| (m.role == role || m.role == ANY_ROLE) && m.cols.contains(&(col as usize)))
        };
        let ctx = self.ctx();
        let mut scratch = Vec::new();
        let mut rng = Rng(0x0758_7ac0);
        (0..self.constraints.len())
            .filter(|&c| !used[c])
            // In play in a freedom's component (it reads a free variable on a
            // sampled row): not vacuous — the freedom is what it constrains.
            .filter(|&c| {
                // Depends (not merely reads) on a free variable somewhere.
                let k = &self.constraints[c];
                let mut rng = Rng(0x0758_91a7 ^ c as u64);
                let mut scratch = Vec::new();
                let ctx = self.ctx();
                !rows.iter().any(|&row| {
                    if self.rows != self.height {
                        return false;
                    }
                    let free: Vec<Var> = self.vars_of(c, row).into_iter().filter(|v| !self.is_det(*v)).collect();
                    if free.is_empty() {
                        return false;
                    }
                    let honest = ctx.eval(k, row, &[], &mut scratch);
                    free.iter().any(|v| ctx.eval(k, row, &[(*v, rng.field())], &mut scratch) != honest)
                })
            })
            .filter(|&c| {
                let k = &self.constraints[c];
                !rows.iter().any(|&row| {
                    let vs: Vec<Var> = k
                        .reads
                        .iter()
                        .map(|&(col, off)| Var::Cell { row: ((row + off as usize) % self.height) as u32, col })
                        .filter(|v| matches!(v, Var::Cell { row: r, col } if witness(*r as usize, *col)))
                        .collect();
                    if vs.is_empty() {
                        return false;
                    }
                    let honest = ctx.eval(k, row, &[], &mut scratch);
                    let ov: Vec<(Var, F)> = vs.into_iter().map(|v| (v, rng.field())).collect();
                    ctx.eval(k, row, &ov, &mut scratch) != honest
                })
            })
            .collect()
    }

    fn boolean_at(&self, row: usize, col: u32) -> bool {
        // L1 builds no booleans map over the window; re-derive for one cell.
        let mut scratch = Vec::new();
        let ctx = self.ctx();
        let v = Var::Cell { row: row as u32, col };
        self.constraints.iter().any(|k| {
            k.reads.len() == 1
                && k.reads[0] == (col, 0)
                && k.pubs.is_empty()
                && ctx.eval(k, row, &[(v, F::ZERO)], &mut scratch) == F::ZERO
                && ctx.eval(k, row, &[(v, F::ONE)], &mut scratch) == F::ZERO
                && ctx.eval(k, row, &[(v, F::TWO)], &mut scratch) != F::ZERO
        })
    }

    /// A census shell for L1 only: the constraints and the full trace, no
    /// L2 state (rows = 0 analysed).
    pub fn for_l1<A>(air: &A, trace: RowMajorMatrix<F>, pvs: &[F], program: Program) -> Self
    where
        A: BaseAir<F> + Air<SymbolicAirBuilder<F>>,
    {
        let width = trace.width();
        let height = trace.height();
        let constraints: Vec<Compiled<F>> = get_symbolic_constraints::<F, A>(air, AirLayout::from_air::<F>(air))
            .iter()
            .map(compile)
            .collect();
        Census {
            constraints,
            reads_local: vec![Vec::new(); width],
            reads_next: vec![Vec::new(); width],
            values: trace.values,
            pvs: pvs.to_vec(),
            periodic: BaseAir::<F>::periodic_columns(air),
            width,
            height,
            rows: 0,
            program,
            det: Vec::new(),
            boolean: Vec::new(),
            order: Vec::new(),
            rng: Rng(0x0758_0001),
            pv_max: None,
            groups: Vec::new(),
            copy_cells: Vec::new(),
            scope: 0..0,
            stuck: Vec::new(),
            enums: Vec::new(),
            enum_log: Vec::new(),
            deadline: None,
            timed_out: false,
        }
    }
}

// ---------------------------------------------------------------------------
// L2b: the binding census — a field's occurrences must be tied
// ---------------------------------------------------------------------------

/// One binding probe: occurrence `role`/`col` of `field` perturbed alone
/// (bit 0 of its lane, on its perm's first row), everything downstream
/// replayed; `violations` empty means the other occurrences do NOT hold it —
/// the field's copies are untied (the witness-side sibling of class 2).
#[derive(Clone, Debug)]
pub struct BindingProbe {
    pub field: &'static str,
    pub role: u32,
    pub col: usize,
    pub row: usize,
    pub violations: Vec<(usize, usize)>,
    pub pvs_moved: Vec<usize>,
}

impl<F: PrimeField32> Census<F> {
    /// For every manifest field occurring under ≥ 2 roles, perturb each
    /// occurrence alone and replay the base run's determinations after it.
    /// Run on a full-height (or covering) census after [`Census::run`].
    pub fn binding_census(&self, manifest: &[ManifestEntry]) -> Vec<BindingProbe> {
        self.binding_census_budget(manifest, std::time::Duration::MAX, &mut |_| {})
    }

    /// [`Census::binding_census`] under a wall-clock budget, reporting each
    /// probe as it starts (a replay of everything after a row is the whole
    /// trace's work at full height — R4's L2b ran past 1800 s). Probes not
    /// reached are simply absent from the result.
    pub fn binding_census_budget(
        &self,
        manifest: &[ManifestEntry],
        budget: std::time::Duration,
        progress: &mut dyn FnMut(&str),
    ) -> Vec<BindingProbe> {
        let t0 = std::time::Instant::now();
        let mut by_field: BTreeMap<&'static str, Vec<&ManifestEntry>> = BTreeMap::new();
        for m in manifest {
            by_field.entry(m.field).or_default().push(m);
        }
        let rpp = self.program.rows_per_perm;
        let mut out = Vec::new();
        for (field, occ) in by_field {
            let roles: std::collections::BTreeSet<u32> = occ.iter().map(|m| m.role).collect();
            if roles.len() < 2 {
                continue;
            }
            for m in occ {
                if t0.elapsed() > budget {
                    progress(&format!("L2b: budget reached before {field} @ role{}", m.role));
                    return out;
                }
                progress(&format!("L2b: probing {field} @ role{} ({} s elapsed)", m.role, t0.elapsed().as_secs()));
                let Some(perm) = (0..self.rows / rpp).find(|p| self.program.role_of_row(p * rpp) == m.role) else { continue };
                let row = perm * rpp;
                let col = m.cols[0];
                let cell = Var::Cell { row: row as u32, col: col as u32 };
                // Replay everything the base run determined from this row on.
                let resolved: Vec<(Var, u32)> = self
                    .order
                    .iter()
                    .copied()
                    .filter(|(v, _)| matches!(v, Var::Cell { row: r, .. } if *r as usize >= row) || matches!(v, Var::Pub(_)))
                    .collect();
                let Some(rep) = self.repair_until(&[cell], |v| if v == F::ZERO { F::ONE } else { F::ZERO }, &resolved, t0.checked_add(budget)) else {
                    progress(&format!("L2b: budget reached inside {field} @ role{}", m.role));
                    return out;
                };
                let pvs_moved = (0..rep.pvs.len()).filter(|i| rep.pvs[*i] != self.pvs[*i]).collect();
                out.push(BindingProbe { field, role: m.role, col, row, violations: self.violations(&rep, 3), pvs_moved });
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The toy rig: the census's own controls (probes must fail loudly)
// ---------------------------------------------------------------------------

/// A synthetic AIR carrying one of each thing the census must tell apart,
/// so its behaviour is checked off the real AIRs (lab #758 condition (d)):
///
/// - **the planted freedom** — a mux select `s` (column [`toy::S`], behind 70
///   filler columns so a ranking that only tries low columns misses it),
///   bool + constant only, feeding `y = s·x + (1−s)·(x+1)`, bound to PV0;
/// - **a witness copy** `c` of the freedom-affected `y` (bits at rows 0..16,
///   an accumulator bank closed at row [`toy::CLOSE`] against PV4, itself
///   bound to `y` on the last row — determined only after the sweep passed
///   the close), bit 0 read by PV1 — not an
///   input: it must come out tied to `y` (so the freedom reaches PV1 through
///   it), and declared an input it must *mask* the freedom;
/// - **the negative control** — a second copy `c2` whose bank is never
///   closed, read by PV2: under-constrained, it must flag whatever the
///   elimination does;
/// - **a borrow chain** on the last row, `vin − vout − fee − 2^16·carry = 0`
///   against PV3: unique only under the declared PV range;
/// - **a gated read and a carry** of `t`: consumed by nothing (the gate is
///   pinned to zero), carried constant — malleable, never a flag;
/// - **a long chain** `L(r+1) = L(r) + c(r) + F(r)` with a free bit `F` on
///   every row: it links the copy's bank to ~2,000 free unknowns, so the
///   system holding the bank is over the class cap (an earlier regression);
///   the bank must still be solved (on a neighbourhood). The chain itself is
///   a consumed freedom reaching no public value — a flag whose confirm
///   moves no PV.
pub mod toy {
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
    use p3_matrix::dense::RowMajorMatrix;

    use super::{ManifestEntry, Program};

    pub const X: usize = 0;
    pub const S: usize = 71;
    pub const Y: usize = 72;
    pub const C: usize = 73;
    pub const ACC: usize = 74;
    pub const C2: usize = 75;
    pub const ACC2: usize = 76;
    pub const VIN: usize = 77;
    pub const VOUT: usize = 78;
    pub const B: usize = 79; // 3 carry-encoding bits
    pub const T: usize = 82;
    pub const Z: usize = 83;
    pub const U: usize = 84;
    /// A free bit and a running sum over every row: `L(r+1) = L(r) + c(r) +
    /// F(r)` — small equations chaining the copy's bank to ~2 × HEIGHT free
    /// unknowns, so the system holding the bank exceeds the class cap and
    /// must be solved on a bounded neighbourhood (an earlier regression).
    pub const FREE: usize = 85;
    pub const L: usize = 86;
    /// With `mixed`: `M = s + c2`, joining the planted select and the
    /// unclosed copy into ONE component — naming (`untied_fields`) stays
    /// silent there, and the flag must still stand.
    pub const M: usize = 87;
    pub const WIDTH: usize = 88;
    pub const HEIGHT: usize = 1024;
    /// The copy's bank closes here — ~984 rows of aliased carries after its
    /// last bit.
    pub const CLOSE: usize = 1000;

    /// `fixed`: pin `s = 0` (the planted freedom closed). `mixed`: join the
    /// select and the unclosed copy in one component (`M = s + c2`).
    pub struct Rig {
        pub fixed: bool,
        pub mixed: bool,
    }

    impl<F: Field> BaseAir<F> for Rig {
        fn width(&self) -> usize {
            WIDTH
        }
        fn num_public_values(&self) -> usize {
            5
        }
        fn num_periodic_columns(&self) -> usize {
            4
        }
        /// [pw = 2^row on rows 0..16, cl = [row = CLOSE], sel3 = [row = 3],
        /// lo16 = [row < 16]].
        fn periodic_columns(&self) -> Vec<Vec<F>> {
            let pw = (0..HEIGHT).map(|r| if r < 16 { F::from_u32(1 << r) } else { F::ZERO }).collect();
            let cl = (0..HEIGHT).map(|r| F::from_bool(r == CLOSE)).collect();
            let s3 = (0..HEIGHT).map(|r| F::from_bool(r == 3)).collect();
            let lo16 = (0..HEIGHT).map(|r| F::from_bool(r < 16)).collect();
            vec![pw, cl, s3, lo16]
        }
    }

    impl<AB: AirBuilder> Air<AB> for Rig
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let l: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
            let n: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();
            let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
            let per: Vec<AB::Expr> = builder.periodic_values().iter().map(|v| (*v).into()).collect();
            let (pw, cl, sel3, lo16) = (per[0].clone(), per[1].clone(), per[2].clone(), per[3].clone());
            let x = l[X].clone();
            for i in 1..=70 {
                builder.assert_eq(l[i].clone(), x.clone() + AB::Expr::from_u32(i as u32));
            }
            // The planted freedom.
            let s = l[S].clone();
            builder.assert_bool(s.clone());
            builder.assert_eq(l[Y].clone(), s.clone() * x.clone() + (AB::Expr::ONE - s.clone()) * (x.clone() + AB::Expr::ONE));
            builder.when_first_row().assert_eq(l[Y].clone(), pv[0].clone());
            if self.fixed {
                builder.assert_zero(s.clone());
            }
            builder.when_transition().assert_eq(n[S].clone(), s);
            // The copy of y, tied by a bank; and the unclosed one.
            for (c, acc) in [(C, ACC), (C2, ACC2)] {
                builder.assert_bool(l[c].clone());
                builder.when_first_row().assert_zero(l[acc].clone());
                builder.when_transition().assert_eq(n[acc].clone(), l[acc].clone() + pw.clone() * l[c].clone());
            }
            // The bank closes against PV4, which is bound to y on the LAST row
            // — determined only after the sweep has passed the close (R3's
            // ρ-against-cnf shape).
            builder.assert_zero(cl * (l[ACC].clone() - pv[4].clone()));
            builder.when_last_row().assert_eq(l[Y].clone(), pv[4].clone());
            // A copy is 16 bits: zero past them (both lanes).
            builder.assert_zero((AB::Expr::ONE - lo16.clone()) * l[C].clone());
            builder.assert_zero((AB::Expr::ONE - lo16) * l[C2].clone());
            builder.when_first_row().assert_eq(l[C].clone(), pv[1].clone());
            builder.assert_zero(sel3 * (l[C2].clone() - pv[2].clone()));
            // The borrow chain on the last row.
            for k in 0..3 {
                builder.assert_bool(l[B + k].clone());
            }
            let carry = l[B].clone() + l[B + 1].clone() * AB::Expr::TWO + l[B + 2].clone() * AB::Expr::from_u32(4) - AB::Expr::TWO;
            builder.when_last_row().assert_zero(
                l[VIN].clone() - l[VOUT].clone() - pv[3].clone() - AB::Expr::from_u32(1 << 16) * carry,
            );
            // A gated read and a carry of t.
            builder.assert_zero(l[Z].clone());
            builder.assert_eq(l[U].clone(), x + AB::Expr::from_u32(5));
            builder.assert_zero(l[Z].clone() * (l[U].clone() - l[T].clone()));
            builder.when_transition().assert_eq(n[T].clone(), l[T].clone());
            // The chain linking the copy to free unknowns on every row.
            builder.assert_bool(l[FREE].clone());
            builder.when_first_row().assert_zero(l[L].clone());
            builder.when_transition().assert_eq(n[L].clone(), l[L].clone() + l[C].clone() + l[FREE].clone());
            if self.mixed {
                builder.assert_eq(l[M].clone(), l[S].clone() + l[C2].clone());
            }
        }
    }

    /// The honest trace and public values (`s = 0`).
    pub fn trace<F: PrimeField32>() -> (RowMajorMatrix<F>, Vec<F>) {
        let x = |r: usize| 1000 + 7 * r as u32;
        let y16 = x(HEIGHT - 1) + 1; // s = 0; the bank closes against PV4 = y(last row)
        let mut v = Vec::with_capacity(WIDTH * HEIGHT);
        let (mut acc, mut acc2, mut lsum) = (0u32, 0u32, 0u32);
        let c2bits = 0x2a5u32;
        for r in 0..HEIGHT {
            let mut row = vec![F::ZERO; WIDTH];
            row[X] = F::from_u32(x(r));
            for i in 1..=70 {
                row[i] = F::from_u32(x(r) + i as u32);
            }
            row[Y] = F::from_u32(x(r) + 1);
            let c = if r < 16 { (y16 >> r) & 1 } else { 0 };
            let c2 = if r < 16 { (c2bits >> r) & 1 } else { 0 };
            row[C] = F::from_u32(c);
            row[ACC] = F::from_u32(acc);
            row[C2] = F::from_u32(c2);
            row[ACC2] = F::from_u32(acc2);
            if r < 16 {
                acc += c << r;
                acc2 += c2 << r;
            }
            row[VIN] = F::from_u32(10);
            row[VOUT] = F::from_u32(7);
            row[B + 1] = F::ONE; // carry encoding 2 = carry 0
            row[T] = F::from_u32(42);
            row[U] = F::from_u32(x(r) + 5);
            let free = ((r * 7919) >> 3) as u32 & 1;
            row[FREE] = F::from_u32(free);
            row[L] = F::from_u32(lsum);
            row[M] = F::from_u32(c2); // s = 0
            lsum += c + free;
            v.extend(row);
        }
        let pvs = vec![F::from_u32(x(0) + 1), F::from_u32(y16 & 1), F::from_u32(c2bits >> 3 & 1), F::from_u32(3), F::from_u32(y16)];
        (RowMajorMatrix::new(v, WIDTH), pvs)
    }

    /// The rig's inputs: `x`, `vin`, `vout`; with `copy_as_input`, the copy
    /// `c` too (the masking control).
    pub fn manifest(copy_as_input: bool) -> Vec<ManifestEntry> {
        // c2 is a copy whose tie is missing (its bank never closes): L2 must
        // name it; L1, taking copies as given, cannot see it (R3's EP).
        let mut m = vec![ManifestEntry::input(0, vec![X, VIN, VOUT], "x, vin, vout"), ManifestEntry::copy(0, vec![C2], "c2")];
        if copy_as_input {
            m.push(ManifestEntry::input(0, vec![C], "c"));
        } else {
            m.push(ManifestEntry::copy(0, vec![C], "c"));
        }
        m
    }

    /// One perm, one role.
    pub fn program() -> Program {
        Program { rows_per_perm: HEIGHT, roles: vec![0] }
    }

    /// A signed-amount chain (lab #758 R11), P3's balance in miniature:
    /// `d0 + (1 − 2σ)·m0 − 2^16·c0 = 0` and, with `top`, `d1 + c0 + (1 −
    /// 2σ)·m1 = 0` — the top chunk carries nothing out. Public values σ (a
    /// bit), m0, m1 (16-bit); `c0 = b0 + 2·b1 + 4·b2 − 2` from three bits.
    /// Honest: `d = −20`, σ = 0, m = 20, c0 = 0. With `top` that is the only
    /// in-range solution; without it, σ = 1, m0 = 65,516, c0 = −1 is a second
    /// (the wrap the top chunk forbids) — the enumeration must say 2.
    pub struct SignRig {
        pub top: bool,
    }

    pub const SIGN_D0: usize = 0;
    pub const SIGN_D1: usize = 1;
    pub const SIGN_B: usize = 2;
    pub const SIGN_WIDTH: usize = 5;
    pub const SIGN_HEIGHT: usize = 16;

    impl<F: Field> BaseAir<F> for SignRig {
        fn width(&self) -> usize {
            SIGN_WIDTH
        }
        fn num_public_values(&self) -> usize {
            3
        }
        fn num_periodic_columns(&self) -> usize {
            1
        }
        /// [first = [row = 0]].
        fn periodic_columns(&self) -> Vec<Vec<F>> {
            vec![(0..SIGN_HEIGHT).map(|r| F::from_bool(r == 0)).collect()]
        }
    }

    impl<AB: AirBuilder> Air<AB> for SignRig
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let l: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
            let pv: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
            let first = builder.periodic_values()[0].into();
            for k in 0..3 {
                builder.assert_bool(l[SIGN_B + k].clone());
                // The bits live on row 0 only.
                builder.assert_zero((AB::Expr::ONE - first.clone()) * l[SIGN_B + k].clone());
            }
            let sgn = AB::Expr::ONE - AB::Expr::TWO * pv[0].clone();
            let c0 = l[SIGN_B].clone() + l[SIGN_B + 1].clone() * AB::Expr::TWO + l[SIGN_B + 2].clone() * AB::Expr::from_u32(4) - AB::Expr::TWO;
            builder.assert_zero(first.clone() * (l[SIGN_D0].clone() + sgn.clone() * pv[1].clone() - AB::Expr::from_u32(1 << 16) * c0.clone()));
            if self.top {
                builder.assert_zero(first * (l[SIGN_D1].clone() + c0 + sgn * pv[2].clone()));
            } else {
                builder.assert_zero(first * (l[SIGN_D1].clone() + sgn * pv[2].clone()));
            }
        }
    }

    /// The signed chain's honest trace and public values.
    pub fn sign_trace<F: PrimeField32>() -> (RowMajorMatrix<F>, Vec<F>) {
        let mut v = vec![F::ZERO; SIGN_WIDTH * SIGN_HEIGHT];
        v[SIGN_D0] = -F::from_u32(20);
        v[SIGN_B + 1] = F::ONE; // c0 = 0
        (RowMajorMatrix::new(v, SIGN_WIDTH), vec![F::ZERO, F::from_u32(20), F::ZERO])
    }

    /// The signed chain's inputs: `d0`, `d1`.
    pub fn sign_manifest() -> Vec<ManifestEntry> {
        vec![ManifestEntry::input(0, vec![SIGN_D0, SIGN_D1], "d0, d1")]
    }

    /// One perm, one role.
    pub fn sign_program() -> Program {
        Program { rows_per_perm: SIGN_HEIGHT, roles: vec![0] }
    }
}

#[cfg(test)]
mod tests {
    //! The census's controls on the toy rig, resident on the lane.
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::toy::{self, Rig};
    use super::*;

    type F = KoalaBear;

    fn census(fixed: bool, copy_as_input: bool, pv_bits: Option<Vec<u32>>) -> (Census<F>, Report) {
        let (m, pv) = toy::trace::<F>();
        let mut c = Census::run(&Rig { fixed, mixed: false }, m, &pv, toy::program(), &toy::manifest(copy_as_input), toy::HEIGHT, pv_bits);
        let rep = c.report(&[]);
        (c, rep)
    }

    /// Flip one cell of the root and replay: SAT, with these PVs moved. The
    /// root column's other free cells are pinned at their honest values (a
    /// bank summing several free bits needs them to replay its accumulator).
    fn confirm(c: &mut Census<F>, cell: Var, fixed: bool) -> Vec<usize> {
        let snap = c.snapshot();
        let mut resolved = c.pin_cells(&[cell]);
        let Var::Cell { col, .. } = cell else { unreachable!() };
        // The root column's other free cells, then every other free cell of
        // the rig's independent freedoms (the chain's F), at honest values.
        for other in [col as usize, toy::FREE] {
            let rest = c.undetermined_in(other as u32, 0);
            if !rest.is_empty() {
                resolved.extend(c.pin_cells(&rest));
            }
        }
        let rep = c.repair(&[cell], |v| F::ONE - v, &resolved);
        assert!(c.violations(&rep, 1).is_empty(), "the repaired trace satisfies the AIR");
        let (m, pv) = c.materialize(&rep).expect("full height");
        p3_air::check_constraints(&Rig { fixed, mixed: false }, &m, &pv);
        let moved = (0..pv.len()).filter(|i| pv[*i] != c.pvs()[*i]).collect();
        c.restore(snap);
        moved
    }

    fn flag_with<'a>(rep: &'a Report, col: usize) -> Option<&'a Component> {
        rep.flags().find(|f| f.buckets.contains_key(&(col as u32, 0)))
    }

    #[test]
    fn detaudit_rig_flags_the_freedom_and_the_unclosed_copy_only() {
        let (mut c, rep) = census(false, false, Some(vec![16; 5]));
        assert!(rep.copies_underived.is_empty(), "no unsolved tie");
        // Both copies sit inside a component: `c` moves with the free `y`
        // (the select's component), and `c2` is its own flagged, untied
        // component. Neither is outside every component, the alarm case.
        assert_eq!(rep.copies_in_components, vec![("c", 0, 16), ("c2", 0, 16)], "each copy is inside a component");
        assert_eq!(rep.flags().count(), 2, "the planted select (with the chain) and the unclosed copy — nothing else");
        let planted = flag_with(&rep, toy::S).expect("the select is flagged");
        assert_eq!(planted.pvs, vec![0, 1, 4], "it reaches PV0 directly, PV4 through y, and PV1 through the tied copy");
        assert!(planted.buckets.contains_key(&(toy::C as u32, 0)), "the copy moves with it");
        assert!(planted.roots.contains(&(toy::S as u32, 0)), "the select is an orientation root");
        let unclosed = flag_with(&rep, toy::C2).expect("the unclosed copy is flagged");
        assert_eq!(unclosed.pvs, vec![2]);
        assert_eq!(unclosed.untied_fields, vec![("c2", 0)], "L2 names the missing tie");
        // Confirms: one select cell flipped moves y, the tied copy (the linear
        // replay across the aliased chain), PV0 and PV1; one unclosed bit, PV2.
        assert_eq!(confirm(&mut c, Var::Cell { row: 5, col: toy::S as u32 }, false), vec![0, 1, 4]);
        assert_eq!(confirm(&mut c, Var::Cell { row: 3, col: toy::C2 as u32 }, false), vec![2]);
        assert!(rep.unconsumed >= toy::HEIGHT, "t's cells are free but unread");
    }

    #[test]
    fn detaudit_rig_needs_the_pv_range_for_the_borrow_chain() {
        let (_, rep) = census(false, false, None);
        assert_eq!(rep.flags().count(), 3, "without the declared PV range the borrow chain is a third flag");
        assert!(rep.flags().any(|f| f.pvs == vec![3] && f.buckets.contains_key(&(toy::B as u32, 0))));
    }

    #[test]
    fn detaudit_rig_copy_declared_an_input_masks_the_freedom() {
        let (_, rep) = census(false, true, Some(vec![16; 5]));
        assert!(flag_with(&rep, toy::S).is_none(), "the tied copy as a source pins y, hence s — a copy declared an input masks the freedom");
        assert!(flag_with(&rep, toy::C2).is_some());
    }

    /// The enumeration caps: v1's (≤ 12 equations, ≤ 12 booleans) still
    /// admit what they did; a wide group is admitted only with ≤ 4 booleans
    /// (shape P's 21-equation exit-edge group); nothing past 32 equations or
    /// 12 booleans.
    #[test]
    fn detaudit_enum_caps_admit_wide_few_boolean_groups_only() {
        for (eqs, bools, ok) in [
            (12, 12, true),
            (12, 13, false),
            (13, 5, false),
            (21, 0, true),
            (21, 4, true),
            (32, 4, true),
            (33, 0, false),
            (21, 5, false),
        ] {
            assert_eq!(enum_admits(eqs, bools), ok, "{eqs} equations, {bools} booleans");
        }
    }

    /// A confirm's deadline binds inside a pin and a replay (the 2026-10-05/06
    /// box: one attempt ran > 3 h past its 900 s budget, checked only between
    /// attempts): past it, a pin stops and says so, and the replay gives up;
    /// cleared, the same pin resolves what it did before.
    #[test]
    fn detaudit_deadline_binds_inside_a_pin_and_a_replay() {
        let (mut c, _) = census(false, false, Some(vec![16; 5]));
        let cell = c.undetermined_in(toy::S as u32, 0)[0];
        let snap = c.snapshot();
        let full = c.pin_cells(&[cell]);
        c.restore(snap);
        assert!(!c.timed_out() && !full.is_empty(), "unbounded, the pin resolves its cone");

        let past = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        c.set_deadline(Some(past));
        let snap = c.snapshot();
        let partial = c.pin_cells(&[cell]);
        c.restore(snap);
        assert!(c.timed_out(), "a pin past its deadline says so");
        assert!(partial.len() < full.len(), "and stops short ({} of {})", partial.len(), full.len());
        assert!(c.repair_until(&[cell], |v| F::ONE - v, &full, Some(past)).is_none(), "the replay gives up");

        c.set_deadline(None);
        assert!(!c.timed_out(), "clearing the deadline clears the flag");
        let snap = c.snapshot();
        assert_eq!(c.pin_cells(&[cell]).len(), full.len(), "the same pin, unbounded again");
        c.restore(snap);
    }

    /// With the freedom pinned, the copy's bank is over the class cap (the
    /// chain) and must still be solved: every copy re-derived, the control
    /// and the chain flagged, nothing reaching PV0/PV1.
    #[test]
    fn detaudit_rig_with_the_freedom_pinned_solves_the_bank_past_the_cap() {
        let (mut c, rep) = census(true, false, Some(vec![16; 5]));
        assert!(rep.copies_underived.is_empty(), "the tied copy is re-derived on a neighbourhood: {:?}", rep.copies_underived);
        assert!(flag_with(&rep, toy::S).is_none() && flag_with(&rep, toy::C).is_none());
        assert_eq!(flag_with(&rep, toy::C2).expect("the negative control never goes quiet").pvs, vec![2]);
        let chain = flag_with(&rep, toy::FREE).expect("the chain's free bits are a consumed freedom");
        assert!(chain.pvs.is_empty(), "reaching no public value");
        assert_eq!(confirm(&mut c, Var::Cell { row: 9, col: toy::FREE as u32 }, true), Vec::<usize>::new());
    }

    /// Naming is best-effort diagnostics; detection is the flag. With the
    /// select and the unclosed copy in one component there IS a non-copy
    /// root, so `untied_fields` stays silent — and the component is flagged.
    #[test]
    fn detaudit_rig_mixed_component_is_flagged_even_unnamed() {
        let (m, pv) = toy::trace::<F>();
        let mut c = Census::run(&Rig { fixed: false, mixed: true }, m, &pv, toy::program(), &toy::manifest(false), toy::HEIGHT, Some(vec![16; 5]));
        let rep = c.report(&[]);
        let joint = flag_with(&rep, toy::S).expect("flagged");
        assert!(joint.buckets.contains_key(&(toy::C2 as u32, 0)), "one component holds the select and the unclosed copy");
        assert!(joint.roots.contains(&(toy::S as u32, 0)));
        assert!(joint.untied_fields.is_empty(), "a non-copy root silences the naming");
        assert!(joint.pvs.contains(&2), "and it still reaches the copy's public value");
    }

    /// `--vacuous` on the rig: the gated read `z·(u − t)` (z pinned 0) is
    /// vacuous; the zero pin that defines `s` in the fixed rig is not; the
    /// copy's bank close (in a solved linear system) is not.
    #[test]
    fn detaudit_rig_vacuity() {
        let (m, pv) = toy::trace::<F>();
        let c = Census::run(&Rig { fixed: true, mixed: false }, m, &pv, toy::program(), &toy::manifest(false), toy::HEIGHT, Some(vec![16; 5]));
        let v = c.vacuous_constraints(&(0..toy::HEIGHT).collect::<Vec<_>>(), &toy::manifest(false));
        let gated = c.constraints_reading_exactly(&[toy::T, toy::U, toy::Z]);
        assert_eq!(gated.len(), 1);
        assert!(v.contains(&gated[0]), "the gated read is vacuous");
        let s_readers = c.constraints_reading_exactly(&[toy::S]);
        assert!(s_readers.iter().any(|i| !v.contains(i)), "the pin defining s is load-bearing");
        let used = c.load_bearing();
        assert!((0..used.len()).any(|i| used[i] && c.describe_constraint(i).contains(&format!("col{}", toy::ACC))), "the bank is load-bearing");
    }

    #[test]
    fn detaudit_sign_chain_enumeration() {
        use super::toy::{sign_manifest, sign_program, sign_trace, SignRig, SIGN_HEIGHT};
        for (top, want) in [(true, 1usize), (false, 2)] {
            let (m, pv) = sign_trace::<F>();
            let mut c = Census::run(&SignRig { top }, m, &pv, sign_program(), &sign_manifest(), SIGN_HEIGHT, Some(vec![1, 16, 16]));
            let rep = c.report(&[]);
            let g = c.enum_log.iter().find(|g| g.row == 0).expect("the chain's row enumerated");
            assert_eq!(g.solutions, want, "top = {top}: in-range solutions");
            if top {
                assert!(rep.pvs_undetermined.is_empty(), "the unique chain determines σ, m0, m1: {:?}", rep.pvs_undetermined);
            } else {
                assert!(rep.pvs_undetermined.contains(&0) && rep.pvs_undetermined.contains(&1), "the wrap leaves σ and m0 free: {:?}", rep.pvs_undetermined);
            }
        }
    }

    #[test]
    fn detaudit_rig_l1() {
        let (m, pv) = toy::trace::<F>();
        let mut c = Census::for_l1(&Rig { fixed: false, mixed: false }, m, &pv, toy::program());
        let flags = c.l1_rows(&toy::manifest(false), &(0..toy::HEIGHT).collect::<Vec<_>>());
        let cols: Vec<u32> = flags.iter().map(|f| f.col).collect();
        assert_eq!(cols, vec![toy::S as u32, toy::FREE as u32], "L1: the select and the chain's free bit — the copies (tied or not) are given, so a missing tie is L2's to find");
        let (m, pv) = toy::trace::<F>();
        let mut c = Census::for_l1(&Rig { fixed: true, mixed: false }, m, &pv, toy::program());
        let flags = c.l1_rows(&toy::manifest(false), &(0..toy::HEIGHT).collect::<Vec<_>>());
        assert_eq!(flags.iter().map(|f| f.col).collect::<Vec<_>>(), vec![toy::FREE as u32], "the zero pin defines s");
    }
}
