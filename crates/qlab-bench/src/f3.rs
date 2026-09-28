//! Lab #767 — L2-F3, the state-transition tree (W2′).
//!
//! A state-transition **leaf** proves, for an ordered batch of `k` L2
//! transactions, the old and new roots of the L2's three trees — the
//! nullifier **indexed** tree `N`, the note-commitment append tree `C`, the
//! asset registry `R` — and a **surface digest** `SD` chained over every
//! transaction's full public-value vector, which the batch (validity) tree
//! computes independently from the same leaf PVs; the wrapper checks the two
//! agree. F3 verifies no proof in-circuit.
//!
//! The first slice is the **native reference** the AIR is built against and
//! the negatives are written from ([`native`]), and the symbolic census
//! (`qlab-bench f3census`, [`census`]). F3-2a adds the leaf's 256-bit strict
//! comparator, a 16-limb subtract-with-borrow gadget ([`cmp`]). F3-2b adds
//! the leaf AIR and its trace generator ([`leaf`]), and its fixtures and
//! negatives ([`neg`]: `qlab-bench f3leaf --check`, `f3neg`, `f3vec`). F3-2c
//! adds `f3leaf --prove` and the interior census, `f3census --interior`
//! ([`bench`]).
//!
//! **Where F3 closed (lab #767, 2026-09-28).** The coordinator's box (EC2
//! r7g.2xlarge, two passes per cell, every proof verified natively, degree 3,
//! two quotient chunks) put the worst b2 leaf — k = 16, 2^18 rows — at
//! 6.45 GiB peak (b4: 12.89 GiB), so **the 32 GB-class b2 gate passes** at
//! every roadmap k with room to spare; F2's k-model over-predicts by 7–25 %.
//! **The interior stays census-only:** one C2-class query component per leaf
//! models at 21–26 GiB [P] (the OOD register machine not counted), so an
//! in-circuit interior at this leaf width sits at the 32 GB edge; F4 decides
//! between it and native chain checks (a leaf verifies in 0.02–0.03 s).
//! Measured table and census: issue #767.

pub(crate) mod bench;
pub(crate) mod census;
pub(crate) mod cmp;
pub(crate) mod leaf;
pub(crate) mod neg;
pub(crate) mod native;

/// `qlab-bench f3census | f3leaf | f3neg | f3vec …`.
pub(crate) fn run(mode: &str, args: &[String]) -> Result<(), String> {
    match mode {
        "f3census" => census::run(args),
        "f3leaf" if args.iter().any(|a| a == "--prove") => bench::prove_run(args),
        "f3leaf" => neg::check(args),
        "f3neg" => neg::run(args),
        "f3vec" => neg::vec_run(args),
        other => Err(format!("unknown f3 mode `{other}`")),
    }
}
