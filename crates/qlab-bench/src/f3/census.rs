//! Lab #767 — `qlab-bench f3census [--k N]…`: the state-transition leaf's
//! symbolic census on the wide lane, from the stage-0 cost model plus ruling
//! (a)'s surface digest. No allocation: this prices, it does not build.
//!
//! Every figure is **[P]**. The width and the per-transaction slot are read
//! off the F3-2b leaf AIR ([`super::leaf`]); the memory is F2's k-model
//! (`peak_GiB ≈ K × width × 2^(h − 18)`, fitted on the legacy M4 interior —
//! a planning model, not a bound).
use qlab_devnet::annulet::L2ShapeTag;

use super::native::{sd_perms, N_DEPTH};

/// Rows per Keccak-f on the wide lane (stock p3-keccak-air).
pub(crate) const ROWS_PER_PERM: usize = 24;
/// The wide lane's Keccak columns (p3-keccak-air 0.6.1).
pub(crate) const KECCAK_COLS: usize = 2_633;
/// F2's k-model constants (`qlab-bench` `f2::ood::wrap`), GiB per col·2^18 rows.
pub(crate) const K_B2: f64 = 0.002_656_45;
pub(crate) const K_B4: f64 = 0.004_279_69;
/// The registry's depth.
const R_DEPTH: usize = qlab_air::l2::REGISTRY_DEPTH;

/// Permutations of one nullifier insert (v1, sequential): low-leaf rewrite
/// `2d + 2` plus append `2d + 1`.
pub(crate) const fn insert_perms() -> usize {
    4 * N_DEPTH + 3
}
/// One commitment append: the empty slot, then the commitment, `2d`.
pub(crate) const fn append_perms() -> usize {
    2 * N_DEPTH
}
/// One shape-R replacement: the new leaf's hash and two depth-16 folds (the
/// old leaf opens from its digest).
pub(crate) const fn replace_perms() -> usize {
    2 * R_DEPTH + 1
}

/// Permutations a transaction of `tag` uses in its slot.
pub(crate) fn tx_perms(tag: L2ShapeTag) -> usize {
    let (nfs, cms, pv_len, write) = match tag {
        L2ShapeTag::S => (3, 2, qlab_air::l2::PV_LEN, 0),
        L2ShapeTag::P => (3, 2, qlab_air::l2p::PV_LEN, 0),
        L2ShapeTag::R => (1, 2, qlab_air::l2r::PV_LEN, replace_perms()),
    };
    nfs * insert_perms() + cms * append_perms() + write + sd_perms(pv_len)
}

/// The slot every transaction occupies (approved deviation 4): the most of
/// each segment any shape uses — 5 SD blocks, 3 inserts, 2 appends, one
/// registry replacement.
pub(crate) fn slot_perms() -> usize {
    SD_SLOT + 3 * insert_perms() + 2 * append_perms() + replace_perms()
}
const SD_SLOT: usize = 5;

/// One leaf's census row.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Row {
    pub k: usize,
    pub perms: usize,
    pub rows: usize,
    pub log_h: u32,
    pub width: usize,
    pub gib_b2: f64,
    pub gib_b4: f64,
}

/// A leaf of `k` transactions: `k` fixed slots, whatever the shapes.
pub(crate) fn row(k: usize) -> Row {
    let perms = k * slot_perms();
    let rows = perms * ROWS_PER_PERM;
    let log_h = rows.next_power_of_two().trailing_zeros();
    let width = super::leaf::LEAF_WIDTH;
    let scale = width as f64 * 2f64.powi(log_h as i32 - 18);
    Row { k, perms, rows, log_h, width, gib_b2: K_B2 * scale, gib_b4: K_B4 * scale }
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let ks: Vec<usize> = match args.iter().position(|a| a == "--k") {
        Some(i) => vec![args.get(i + 1).and_then(|v| v.parse().ok()).ok_or("--k takes a count")?],
        None => vec![4, 8, 16, 32],
    };
    println!(
        "# f3census (lab #767) — memory [P]; width {} = {} keccak + {} leaf columns (the F3-2b AIR); slot {} perms",
        super::leaf::LEAF_WIDTH,
        KECCAK_COLS,
        super::leaf::LEAF_WIDTH - KECCAK_COLS,
        slot_perms()
    );
    println!(
        "# per tx used: S {} / P {} / R {} perms (insert {}, append {}, replace {}, SD S/P/R {}/{}/{})",
        tx_perms(L2ShapeTag::S),
        tx_perms(L2ShapeTag::P),
        tx_perms(L2ShapeTag::R),
        insert_perms(),
        append_perms(),
        replace_perms(),
        sd_perms(qlab_air::l2::PV_LEN),
        sd_perms(qlab_air::l2p::PV_LEN),
        sd_perms(qlab_air::l2r::PV_LEN)
    );
    println!("k | perms | rows | 2^h | width | b2 GiB [P] | b4 GiB [P]");
    for k in ks {
        let r = row(k);
        println!("{} | {} | {} | 2^{} | {} | {:.1} | {:.1}", r.k, r.perms, r.rows, r.log_h, r.width, r.gib_b2, r.gib_b4);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model, pinned to the F3-2b AIR: a slot is 5 SD blocks, 3 inserts,
    /// 2 appends and one replacement — 559 perms, the leaf program's own
    /// count — and every roadmap k fits the 32 GB class at b2 and b4 [P].
    #[test]
    fn f3_census_model() {
        assert_eq!((insert_perms(), append_perms(), replace_perms()), (131, 64, 33));
        assert_eq!(tx_perms(L2ShapeTag::P), 3 * 131 + 2 * 64 + 5);
        assert_eq!(tx_perms(L2ShapeTag::S), 3 * 131 + 2 * 64 + 5);
        assert_eq!(tx_perms(L2ShapeTag::R), 131 + 2 * 64 + 33 + 4);
        assert_eq!(slot_perms(), super::super::leaf::SLOT_PERMS);
        assert_eq!(row(4).width, super::super::leaf::LEAF_WIDTH);
        for (k, log_h) in [(4, 16), (8, 17), (16, 18)] {
            let r = row(k);
            assert_eq!(r.log_h, log_h, "k = {k}");
            assert!(r.gib_b2 < 32.0 && r.gib_b4 < 32.0, "k = {k}: {r:?}");
        }
    }
}
