//! Lab #782 F4b-1 — **`qlab-bench f4census`**: the in-circuit verifier work
//! of every child a wrapper-recursion tree verifies, counted from code [P].
//!
//! Children (K = the wrapper's slot count):
//!
//! - **W**, the wrapper leaf: non-hiding (`qlab_consensus::legacy`), proven at
//!   the b2 (`INTERIOR_B2_CFG`) or b4 (`INTERIOR_B4_CFG`) outer lane;
//! - **the members** S / P / R / C and **the deposit-sum proof**: hiding
//!   (`HidingFriPcs`, the trace committed at 2N, salted leaves, a randomizer)
//!   on the L2 lane (`qlab_l2::L2_CFG_PROVISIONAL`);
//! - **rung-1 outputs**: F2's C1 and C2 per member, non-hiding at the rung's
//!   lane.
//!
//! Two layouts price the query component that verifies one child:
//!
//! - **F3's census layout** (`f3::bench::leaf_verify` for a non-hiding child,
//!   F2's `composed_c2_layout` for a hiding one): one component per child
//!   holding every query's Keccak lane rows plus its registers;
//! - **M4's interior layout** ([`m4_layout`]): the measured two-child
//!   interior's shape.
//!
//! Their memory is F2's k-model `peak ≈ K × width × 2^(h−18)` (a planning
//! model, not a bound). Every figure here is [P]; F4b-1's box run measures
//! the W query component so the two layouts become one number.
//!
//! Also: the tree counts for K ∈ {4, 8, 16} (condition (a)), the composed
//! security table (answer 4 / condition (d)) and the inner-rung hash column
//! (answer 3 / condition (e)).
#![cfg_attr(not(test), allow(dead_code))]
use p3_air::symbolic::AirLayout;
use p3_keccak_air::NUM_KECCAK_COLS;
use p3_uni_stark::get_log_num_quotient_chunks;
use qlab_consensus::{FriCfg, Val, CAP_HEIGHT, IS_ZK, SALT_ELEMS};
use qlab_l2::Shape;
use serde_json::{json, Value};

use crate::f3::bench::fri_log_arities;
use crate::m4interior::{INTERIOR_B2_CFG, INTERIOR_B4_CFG};

/// F2's k-model constants (`f2::ood::wrap`).
pub(crate) const K_B2: f64 = 0.002_656_45;
pub(crate) const K_B4: f64 = 0.004_279_69;

/// Conjectured bits per query, 2197-corrected (`l2shape` LANES; the
/// fri-soundness accounting's β(ρ)), and the lanes' grinding.
pub(crate) const BETA_B2: f64 = 0.910;
pub(crate) const BETA_B4: f64 = 1.853;
pub(crate) const GRIND: f64 = 22.0;

/// A lane a proof is committed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    /// Non-hiding b2/q86 (`INTERIOR_B2_CFG`).
    B2,
    /// Non-hiding b4/q43 (`INTERIOR_B4_CFG`).
    B4,
    /// The hiding L2 lane, b4/q43 (`L2_CFG_PROVISIONAL`).
    L2,
}

impl Lane {
    pub(crate) fn cfg(self) -> FriCfg {
        match self {
            Lane::B2 => INTERIOR_B2_CFG,
            Lane::B4 => INTERIOR_B4_CFG,
            Lane::L2 => qlab_l2::L2_CFG_PROVISIONAL,
        }
    }
    pub(crate) fn hiding(self) -> bool {
        self == Lane::L2
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Lane::B2 => "b2/q86/g22 non-hiding",
            Lane::B4 => "b4/q43/g22 non-hiding",
            Lane::L2 => "b4/q43/g22 hiding (L2)",
        }
    }
    /// The k-model constant for a component proven on this lane.
    pub(crate) fn k_model(self) -> f64 {
        match self {
            Lane::B2 => K_B2,
            Lane::B4 | Lane::L2 => K_B4,
        }
    }
    pub(crate) fn beta(self) -> f64 {
        match self {
            Lane::B2 => BETA_B2,
            Lane::B4 | Lane::L2 => BETA_B4,
        }
    }
    /// Conjectured bits: q · β + grind.
    pub(crate) fn bits(self) -> f64 {
        self.cfg().num_queries as f64 * self.beta() + GRIND
    }
}

/// One proof a rung verifies.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Child {
    pub name: String,
    pub width: usize,
    pub pv_len: usize,
    pub log_height: usize,
    /// Quotient chunks as committed (hiding: doubled by `IS_ZK`).
    pub chunks: usize,
    pub lane: Lane,
}

/// What verifying one child costs in-circuit [P].
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Cost {
    pub lde: usize,
    pub arities: Vec<usize>,
    pub queries: usize,
    pub opened_ext: usize,
    pub challenger_perms: usize,
    pub per_query_perms: usize,
    /// One query component covering every query (F3's census layout for a
    /// non-hiding child, F2's C2 layout for a hiding one).
    pub query_columns: usize,
    pub query_rows: usize,
}

impl Cost {
    pub(crate) fn keccak_total(&self) -> usize {
        self.challenger_perms + self.queries * self.per_query_perms
    }
}

/// `peak_GiB ≈ K × cols × 2^(log2(rows) − 18)` at `lane`.
pub(crate) fn gib(lane: Lane, cols: usize, rows: usize) -> f64 {
    lane.k_model() * cols as f64 * 2f64.powi(rows.trailing_zeros() as i32 - 18)
}

/// Count one child's verification. A non-hiding child is `f3::bench::
/// leaf_verify`'s formula at the child's own width and PVs; a hiding child is
/// F2's `composed_c1_layout` flush blocks and `composed_c2_layout` (the
/// randomizer, salted leaves, three input matrices a query, 2N commitment).
pub(crate) fn cost(c: &Child) -> Cost {
    let cfg = c.lane.cfg();
    let hiding = c.lane.hiding();
    let zk = if hiding { IS_ZK } else { 0 };
    let lde = c.log_height + zk + cfg.log_blowup;
    let arities = fri_log_arities(lde, &cfg);
    let rounds = arities.len();
    let final_len = 1usize << cfg.log_final_poly_len;
    let cap_words = (1usize << CAP_HEIGHT) * 8;
    let salt = if hiding { SALT_ELEMS } else { 0 };
    // Opened: (the randomizer's 4 when hiding) + the trace at ζ and ζ·g +
    // each chunk's four base polynomials.
    let terms = if hiding { 4 } else { 0 } + 2 * c.width + 4 * c.chunks;
    // Challenger: pad10*1 over 34-word blocks, one flush per observation.
    let flush = |words: usize| words / 34 + 1;
    let windows = (cfg.num_queries + 1).div_ceil(8);
    let f1 = if hiding { flush(8 + 2 * cap_words) } else { flush(8 + cap_words) };
    let challenger_lane = flush(3 + cap_words + c.pv_len)
        + f1
        + flush(8 + 4 * terms)
        + rounds * flush(8 + cap_words)
        + flush(8 + 4 * final_len + rounds + 1)
        + windows;
    // F2 reports its lane's perms minus the first as challenger perms.
    let challenger = if hiding { challenger_lane - 1 } else { challenger_lane };
    // Query phase: overwrite-mode leaves over 17 u64 lanes a perm.
    let blocks = |u64s: usize| u64s.div_ceil(17);
    let path = lde - CAP_HEIGHT;
    let in_leaf: usize = if hiding {
        [(1, 4), (1, c.width), (c.chunks, 4)].iter().map(|&(m, cols)| blocks((m * (cols + salt)).div_ceil(2))).sum()
    } else {
        blocks(c.width.div_ceil(2)) + blocks((4 * c.chunks).div_ceil(2))
    };
    let in_comp = if hiding { 3 * path } else { 2 * path };
    let (mut fri_leaf, mut fri_comp, mut round_regs) = (0, 0, 0);
    let mut height = lde;
    for &a in &arities {
        let n = 1usize << a;
        let folded = height - a;
        fri_leaf += blocks((4 * n + salt).div_ceil(2));
        fri_comp += folded - CAP_HEIGHT;
        round_regs += 4 * n + (2 * n - 2) + folded + 4 * (n - 1);
        height = folded;
    }
    let per_query = in_leaf + in_comp + fri_leaf + fri_comp;
    let final_bits = cfg.log_blowup + cfg.log_final_poly_len;
    let lane = NUM_KECCAK_COLS + 64 * 17 + 2 * 34;
    let rings = per_query + cfg.num_queries;
    let columns = if hiding {
        // F2's composed_c2_layout.
        let gates = path + 3 + rounds;
        let handoff = lde + 4;
        let registers = handoff + 12 + lde + 8 + round_regs + 4 * rounds + final_bits + 4 * final_len;
        let held = 4 + 4 * 34 + 4 + 8 + 4 * rounds + 4 * final_len;
        lane + rings + gates + registers + 6 * 4 + held
    } else {
        // F3's leaf_verify.
        let gates = path + 2 + rounds;
        let registers = (lde + 4) + 12 + lde + 8 + round_regs + 4 * rounds + final_bits + 4 * final_len;
        let held = 4 + 4 * 34 + 4 + 8 + 4 * rounds + 4 * final_len;
        lane + rings + gates + registers + 6 * 4 + held
    };
    Cost {
        lde,
        arities,
        queries: cfg.num_queries,
        opened_ext: terms,
        challenger_perms: challenger,
        per_query_perms: per_query,
        query_columns: columns,
        query_rows: (24 * cfg.num_queries * per_query).next_power_of_two(),
    }
}

/// Quotient chunks as committed: `2^(log_chunks + zk)`.
fn chunks_of<A: p3_air::Air<p3_air::symbolic::SymbolicAirBuilder<Val>>>(air: &A, hiding: bool) -> usize {
    let zk = if hiding { IS_ZK } else { 0 };
    1usize << (get_log_num_quotient_chunks::<Val, _>(air, AirLayout::from_air::<Val>(air), zk) + zk)
}

/// W at K = `k` on `lane` (B2 or B4).
pub(crate) fn w_child(k: usize, lane: Lane) -> Child {
    let air = super::wleaf::WAir::new(1);
    Child {
        name: format!("W (K = {k})"),
        width: super::wleaf::W_WIDTH,
        pv_len: super::wleaf::W_PV_LEN,
        log_height: super::wleaf::w_height(k).trailing_zeros() as usize,
        chunks: chunks_of(&air, false),
        lane,
    }
}

/// The deposit-sum proof.
pub(crate) fn dep_child() -> Child {
    Child {
        name: "deposit".into(),
        width: super::dep::DEP_WIDTH,
        pv_len: super::dep::DEP_PV_LEN,
        log_height: super::dep::DEP_HEIGHT.trailing_zeros() as usize,
        chunks: chunks_of(&super::dep::DepAir::new(), true),
        lane: Lane::L2,
    }
}

/// A member of shape S / P / R (F2's shapes: 8 hiding chunks at degree 4).
pub(crate) fn member_child(shape: Shape) -> Child {
    Child {
        name: format!("member {shape:?}"),
        width: shape.width(),
        pv_len: shape.pv_len(),
        log_height: shape.log_height(),
        chunks: 8,
        lane: Lane::L2,
    }
}

/// A claim member.
pub(crate) fn claim_child() -> Child {
    use p3_air::BaseAir;
    let air = qlab_l2::claim::verifier_air_claim();
    Child {
        name: "member C (claim)".into(),
        width: BaseAir::<Val>::width(&air),
        pv_len: qlab_air::claim::PV_LEN,
        log_height: qlab_l2::claim::LOG_HEIGHT_CLAIM,
        chunks: chunks_of(&air, true),
        lane: Lane::L2,
    }
}

/// F3's state leaf at `k` (the regression pin: 161 / 167 per query).
pub(crate) fn f3_leaf_child(k: usize, lane: Lane) -> Child {
    Child {
        name: format!("F3 leaf (k = {k})"),
        width: crate::f3::leaf::LEAF_WIDTH,
        pv_len: crate::f3::leaf::LEAF_PV_LEN,
        log_height: match k {
            4 => 16,
            8 => 17,
            _ => 18,
        },
        chunks: 2,
        lane,
    }
}

fn child_json(c: &Child, rung: Lane) -> Value {
    let v = cost(c);
    json!({"child": c.name, "lane": c.lane.label(), "width": c.width, "public_values": c.pv_len,
        "log_height": c.log_height, "chunks": c.chunks, "lde": v.lde, "fri_log_arities": v.arities,
        "queries": v.queries, "opened_ext_elements": v.opened_ext,
        "challenger_keccak_f": v.challenger_perms, "keccak_f_per_query": v.per_query_perms,
        "keccak_f_total": v.keccak_total(),
        "query_component": {"columns": v.query_columns, "padded_rows": v.query_rows,
            "rung_lane": rung.label(), "k_model_gib": (gib(rung, v.query_columns, v.query_rows) * 10.0).round() / 10.0}})
}

// ---------------------------------------------------------------------------
// The tree and its composed security
// ---------------------------------------------------------------------------

/// A tree for K members: rung 1 is one C1/C2 pair per member and one for the
/// deposit proof; W joins at the aggregation; aggregation nodes of `fan_in`
/// children each, until one root.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Tree {
    pub k: usize,
    pub fan_in: usize,
    /// Member and deposit proofs (L2 lane).
    pub base_hiding: usize,
    /// W.
    pub base_w: usize,
    /// C1/C2 proofs of rung 1.
    pub rung1: usize,
    /// Aggregation nodes, per level, the last being the root.
    pub levels: Vec<usize>,
}

impl Tree {
    pub(crate) fn new(k: usize, fan_in: usize) -> Self {
        assert!(fan_in >= 2);
        let rung1 = 2 * (k + 1);
        let mut n = rung1 + 1; // + W
        let mut levels = vec![];
        while n > 1 {
            n = n.div_ceil(fan_in);
            levels.push(n);
        }
        Tree { k, fan_in, base_hiding: k + 1, base_w: 1, rung1, levels }
    }
    pub(crate) fn aggregation(&self) -> usize {
        self.levels.iter().sum()
    }
    /// Every proof whose soundness the root rests on.
    pub(crate) fn total(&self) -> usize {
        self.base_hiding + self.base_w + self.rung1 + self.aggregation()
    }
}

/// Answer 4: ≥ 100 bits composed. The union bound over N proofs asks each for
/// 100 + log2 N conjectured bits; the extra queries per class follow at the
/// class's β. (Conjectured; the fri-soundness accounting's posture.)
pub(crate) fn security_json(t: &Tree, w_lane: Lane, rung_lane: Lane) -> Value {
    let n = t.total();
    let need = 100.0 + (n as f64).log2();
    let composed = |bits: [(usize, f64); 3]| -(bits.iter().map(|(c, b)| *c as f64 * 2f64.powf(-b)).sum::<f64>()).log2();
    let now = composed([
        (t.base_hiding, Lane::L2.bits()),
        (t.base_w, w_lane.bits()),
        (t.rung1 + t.aggregation(), rung_lane.bits()),
    ]);
    let extra = |lane: Lane| ((need - lane.bits()) / lane.beta()).ceil().max(0.0) as usize;
    let (e_l2, e_w, e_r) = (extra(Lane::L2), extra(w_lane), extra(rung_lane));
    let rows = |lane: Lane, e: usize| format!("× {:.3}", (lane.cfg().num_queries + e) as f64 / lane.cfg().num_queries as f64);
    json!({"k": t.k, "fan_in": t.fan_in, "proofs": n,
        "proofs_by_class": {"members_and_deposit": t.base_hiding, "w": t.base_w, "rung1_c1_c2": t.rung1,
            "aggregation": t.aggregation(), "aggregation_levels": t.levels},
        "composed_bits_as_is": (now * 10.0).round() / 10.0,
        "per_proof_bits_needed": (need * 10.0).round() / 10.0,
        "extra_queries": {"l2_lane_members_deposit": e_l2, "w_lane": e_w, "rung_lane": e_r},
        "query_rows_factor": {"l2_lane": rows(Lane::L2, e_l2), "w_lane": rows(w_lane, e_w), "rung_lane": rows(rung_lane, e_r)},
        "lanes": {"w": w_lane.label(), "rungs": rung_lane.label()}})
}

// ---------------------------------------------------------------------------
// The inner-rung hash column (answer 3), [P] only
// ---------------------------------------------------------------------------

/// Poseidon2 over KoalaBear, width 16: one AIR row a permutation (the M1
/// calibration AIR, `crate::QPoseidon2Air`), rate 8 field elements.
pub(crate) fn poseidon2_cols() -> usize {
    use p3_air::BaseAir;
    let air: crate::QPoseidon2Air = p3_poseidon2_air::Poseidon2Air::new(p3_poseidon2_air::RoundConstants::from_rng(
        &mut <rand::rngs::SmallRng as rand::SeedableRng>::seed_from_u64(42),
    ));
    BaseAir::<Val>::width(&air)
}

/// A child's in-circuit hash work if its commitments were Poseidon2 (rate 8
/// elements, 2-to-1 compression in one permutation) instead of Keccak (rate
/// 34 words, 24 rows × `NUM_KECCAK_COLS`): permutations and lane cells.
pub(crate) fn poseidon2_json(c: &Child) -> Value {
    let v = cost(c);
    let hiding = c.lane.hiding();
    let salt = if hiding { SALT_ELEMS } else { 0 };
    let r8 = |elems: usize| elems.div_ceil(8);
    let path = v.lde - CAP_HEIGHT;
    let in_leaf: usize = if hiding {
        [(1, 4), (1, c.width), (c.chunks, 4)].iter().map(|&(m, cols)| r8(m * (cols + salt))).sum()
    } else {
        r8(c.width) + r8(4 * c.chunks)
    };
    let in_comp = if hiding { 3 * path } else { 2 * path };
    let (mut fri_leaf, mut fri_comp) = (0, 0);
    let mut height = v.lde;
    for &a in &v.arities {
        fri_leaf += r8(4 * (1usize << a) + salt);
        fri_comp += height - a - CAP_HEIGHT;
        height -= a;
    }
    let per_query = in_leaf + in_comp + fri_leaf + fri_comp;
    // The transcript absorbs the same words, 8 a permutation.
    let challenger = (v.challenger_perms * 34).div_ceil(8);
    let p2 = challenger + v.queries * per_query;
    let (kc, pc) = (v.keccak_total() * 24 * NUM_KECCAK_COLS, p2 * poseidon2_cols());
    json!({"child": c.name, "evidence": "P",
        "keccak": {"permutations": v.keccak_total(), "lane_cells": kc},
        "poseidon2": {"permutations": p2, "per_query": per_query, "air_columns": poseidon2_cols(), "lane_cells": pc},
        "cell_ratio_keccak_over_poseidon2": ((kc as f64 / pc as f64) * 10.0).round() / 10.0,
        "note": "Poseidon2 committing would apply to rungs L1 never touches; Keccak stays for W, members, deposit and the root (answer 3). Collision/security parity of a 8-element digest is not argued here."})
}

// ---------------------------------------------------------------------------
// M4's interior layout ([`super::gate`]), [P] before the box
// ---------------------------------------------------------------------------

/// W at K = `k` proven on `child`, verified by one `m4gate` component: its
/// lane perms ([`super::gate::perms_p`]), rows, columns, and the k-model at
/// both outer lanes.
pub(crate) fn m4_layout_json(k: usize, child: crate::f3::bench::Outer) -> Value {
    let log_h = super::wleaf::w_height(k).trailing_zeros() as usize;
    let shape = super::gate::w_gate_shape(log_h, child);
    let perms = super::gate::perms_p(&shape);
    let rows = (24 * perms).next_power_of_two();
    let cols = crate::m4gate::GateLayout::from_shape(&shape).gate_width;
    json!({"k": k, "child_lane": child.label(), "evidence": "P", "layout": "m4gate VerifierGateAir, one child",
        "note": "undetermined against F3's layout until measured: the k-model overstates F2's measured C2 by 26–30 % at b2 (F3's layout at F2's empirical slope ≈ 20.4 GiB)",
        "queries": shape.nq, "qslots": shape.qslots(), "lane_perms": perms, "rows": rows, "columns": cols,
        "k_model_gib": {"outer_b2": (gib(Lane::B2, cols, rows) * 10.0).round() / 10.0,
            "outer_b4": (gib(Lane::B4, cols, rows) * 10.0).round() / 10.0}})
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

pub(crate) fn report() -> Value {
    let children = |rung: Lane| -> Vec<Value> {
        let mut v = vec![child_json(&w_child(16, Lane::B2), rung), child_json(&w_child(16, Lane::B4), rung), child_json(&dep_child(), rung)];
        for s in [Shape::S, Shape::P, Shape::R] {
            v.push(child_json(&member_child(s), rung));
        }
        v.push(child_json(&claim_child(), rung));
        v
    };
    let pins: Vec<Value> = [(Lane::B2, 16), (Lane::B4, 16)]
        .iter()
        .map(|(l, k)| {
            let c = cost(&f3_leaf_child(*k, *l));
            json!({"lane": l.label(), "k": k, "keccak_f_per_query": c.per_query_perms, "challenger": c.challenger_perms,
                "query_component": [c.query_columns, c.query_rows]})
        })
        .collect();
    let trees: Vec<Value> = [4, 8, 16]
        .iter()
        .flat_map(|k| {
            [(Lane::B2, Lane::B2), (Lane::B2, Lane::B4)].map(|(w, r)| security_json(&Tree::new(*k, 2), w, r))
        })
        .collect();
    let m4_rows: Vec<Value> = [16, 1]
        .iter()
        .flat_map(|k| [crate::f3::bench::Outer::B2, crate::f3::bench::Outer::B4].map(|o| m4_layout_json(*k, o)))
        .collect();
    let mut p2 = vec![poseidon2_json(&w_child(16, Lane::B2)), poseidon2_json(&dep_child())];
    p2.push(poseidon2_json(&member_child(Shape::P)));
    json!({"mode": "f4census", "issue": 782, "evidence": "P",
        "k_model": {"source": "F2 f2::ood::wrap, peak ≈ K × width × 2^(h−18), fitted on the M4 interior; a planning model",
            "k_b2": K_B2, "k_b4": K_B4},
        "lanes": {"b2": Lane::B2.bits(), "b4": Lane::B4.bits(), "l2": Lane::L2.bits(),
            "source": "q × β + 22, β(b2) = 0.910, β(b4) = 1.853 (l2shape LANES, 2197-corrected)"},
        "f3_pins": pins,
        "w_m4_layout": m4_rows,
        "children_rung_b2": children(Lane::B2),
        "children_rung_b4": children(Lane::B4),
        "trees_fan_in_2": trees,
        "inner_hash_poseidon2": p2})
}

pub(crate) fn run(_args: &[String]) -> Result<(), String> {
    println!("{}", serde_json::to_string_pretty(&report()).expect("json"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f3::bench::{leaf_verify, Outer};

    /// Condition (a): F3's pinned census rows, reproduced by the general
    /// formula at the F3 leaf's width.
    #[test]
    fn f4census_reproduces_f3s_rows() {
        for (lane, outer) in [(Lane::B2, Outer::B2), (Lane::B4, Outer::B4)] {
            for k in [4, 8, 16] {
                let c = cost(&f3_leaf_child(k, lane));
                let f = leaf_verify(f3_leaf_child(k, lane).log_height, 2, outer);
                assert_eq!(
                    (c.lde, &c.arities, c.opened_ext, c.challenger_perms, c.per_query_perms, c.query_columns),
                    (f.lde, &f.arities, f.opened_ext, f.challenger_perms, f.per_query_perms, f.query_columns),
                    "{lane:?} k = {k}"
                );
            }
        }
        assert_eq!(cost(&f3_leaf_child(16, Lane::B2)).per_query_perms, 161);
        assert_eq!(cost(&f3_leaf_child(16, Lane::B4)).per_query_perms, 167);
    }

    /// The hiding branch is F2's C2 layout and C1 flush count.
    #[test]
    fn f4census_hiding_branch_is_f2s() {
        for s in [Shape::S, Shape::P, Shape::R] {
            let c = cost(&member_child(s));
            let f = crate::f2::price::composed_c2(s);
            assert_eq!(c.per_query_perms as u64, f["permutations_per_query"].as_u64().unwrap(), "{s:?}");
            assert_eq!(c.query_columns as u64, f["component_columns"].as_u64().unwrap(), "{s:?}");
            assert_eq!(c.query_rows as u64, f["padded_rows"].as_u64().unwrap(), "{s:?}");
            assert_eq!(c.opened_ext as u64, f["opened_terms"].as_u64().unwrap(), "{s:?}");
        }
    }

    /// The stage-0's hand-applied W and deposit figures (issue #782 §1).
    #[test]
    fn f4census_w_and_deposit() {
        let w2 = cost(&w_child(16, Lane::B2));
        assert_eq!((w2.opened_ext, w2.challenger_perms, w2.per_query_perms, w2.keccak_total()), (6_948, 862, 169, 15_396));
        let w4 = cost(&w_child(16, Lane::B4));
        assert_eq!((w4.challenger_perms, w4.per_query_perms, w4.keccak_total()), (857, 175, 8_382));
        assert_eq!((w2.query_rows, w4.query_rows), (1 << 19, 1 << 18));
        let d = dep_child();
        // Degree 3 under the hiding PCS: 4 chunks, doubled by IS_ZK (the stage-0 guessed 4).
        assert_eq!((d.width, d.log_height, d.chunks), (super::super::dep::DEP_WIDTH, 10, 8));
    }

    /// Condition (a)/(b), tolerance ±5 %: the M4-layout [P] (`perms_p`) against the lane plan
    /// of a REAL W's recorded verification — the verify tests' shared K = 2
    /// b2 proof, walked, not re-proven; no gate trace is built here.
    #[test]
    fn f4census_m4_layout_matches_a_real_w_walk() {
        use crate::f3::bench::Outer;
        let (proof, pvs) = crate::f4::verify::tests::case_w_proof();
        let sched = crate::m4gaterec::walk_with_cfg(proof, &pvs, &Outer::B2.cfg());
        let log_h = super::super::wleaf::w_height(2).trailing_zeros() as usize;
        let shape = super::super::gate::w_gate_shape(log_h, Outer::B2);
        let measured = crate::m4gate::lane_plan(&sched, &shape).0.len();
        let p = super::super::gate::perms_p(&shape);
        eprintln!("W K=2 b2 on the M4 layout: lane_plan {measured} perms, perms_p {p}");
        assert_eq!((24 * measured).next_power_of_two(), (24 * p).next_power_of_two(), "same height");
        assert!(measured.abs_diff(p) * 20 <= measured, "within 5 %: {measured} vs {p}");
        let (leaf, compress, challenger) = sched.native_counts;
        assert!(leaf + compress + challenger > 0);
    }

    /// The box's first W gate cells refused at "fold output": a one-block
    /// last fold leaf (4·2^la words) went through `R_ABS_F16`, whose fresh
    /// count is the quotient's `qw`. W's short last rounds now take their own
    /// role; narrow (16 = qw) and wide (all multi-block) keep none, so their
    /// programs and layouts are unchanged.
    #[test]
    fn f4gate_short_last_fold_round_has_its_own_role() {
        use crate::f3::bench::Outer;
        use crate::m4gate::{qprogram_from_shape, GateShape};
        assert_eq!((GateShape::narrow().ff_words(), GateShape::wide().ff_words()), (None, None));
        assert_eq!((GateShape::narrow().n_roles(), GateShape::wide().n_roles()), (13, 12));
        for (log_h, child, la, ff) in [(15, Outer::B4, 3, 32), (18, Outer::B4, 2, 16), (18, Outer::B2, 2, 16)] {
            let s = super::super::gate::w_gate_shape(log_h, child);
            assert_eq!((*s.log_arities.last().unwrap(), s.ff_words()), (la, Some(ff)), "{log_h} {child:?}");
            let rff = s.r_ff().unwrap();
            assert_eq!((rff as usize, s.n_roles()), (9 + s.n_fri_rounds(), 10 + s.n_fri_rounds()));
            let prog = qprogram_from_shape(&s);
            assert_eq!(prog.iter().filter(|d| **d & 0xf == rff).count(), 1, "one short fold leaf a query");
        }
    }

    /// F4b-1's box: the lane perms `lane_plan` produced for real W children
    /// (issue #782's measurement), reproduced by the census exactly.
    #[test]
    fn f4census_perms_p_matches_the_boxs_lane_counts() {
        use crate::f3::bench::Outer;
        for (log_h, child, lane) in [(15, Outer::B4, 8_380), (18, Outer::B4, 9_200), (18, Outer::B2, 16_214)] {
            assert_eq!(super::super::gate::perms_p(&super::super::gate::w_gate_shape(log_h, child)), lane, "{log_h} {child:?}");
        }
    }

    /// The tree counts and the security table's arithmetic.
    #[test]
    fn f4census_trees() {
        let t = Tree::new(16, 2);
        assert_eq!((t.rung1, t.base_hiding), (34, 17));
        assert_eq!(*t.levels.last().unwrap(), 1, "one root");
        assert_eq!(t.aggregation(), 18 + 9 + 5 + 3 + 2 + 1);
        let s = security_json(&t, Lane::B2, Lane::B4);
        assert!(s["composed_bits_as_is"].as_f64().unwrap() < 100.0);
        assert!(s["extra_queries"]["rung_lane"].as_u64().unwrap() >= 3);
    }
}
