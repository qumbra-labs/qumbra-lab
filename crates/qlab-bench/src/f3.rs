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
