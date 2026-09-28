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
//! This first slice is the **native reference** the AIR is built against and
//! the negatives are written from ([`native`]), and the symbolic census
//! (`qlab-bench f3census`, [`census`]). No AIR yet.

pub(crate) mod census;
pub(crate) mod native;

/// `qlab-bench f3census …` — see [`census::run`].
pub(crate) fn run(mode: &str, args: &[String]) -> Result<(), String> {
    match mode {
        "f3census" => census::run(args),
        other => Err(format!("unknown f3 mode `{other}`")),
    }
}
