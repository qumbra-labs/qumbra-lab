//! Lab #775 — L2-F4, the wrapper chain (reading B; Larry's Q2 = A: the
//! enshrined object stays one wrapper proof, and F4b moves the native
//! checks in-circuit).
//!
//! F4-1: the wrapper leaf's native reference ([`native`]), W, the wrapper
//! leaf AIR ([`wleaf`]), its negatives ([`neg`]), and `verify_wrapper`, the
//! native reference verifier ([`verify`]). F4-3: the deposit-sum proof
//! ([`dep`]) and `verify_wrapper`'s V9. F4-4: the measured cell
//! (`f4leaf --prove`, [`bench`]). F4b-1 (lab #782): the recursion census
//! (`f4census`, [`rec`]).
//!
//! **Measured:** the F4-4 box run of all thirteen cells (K ∈ {4, 8, 16} ×
//! {b2, b4}, two passes, plus the per-shape member proofs) is lab issue
//! #775's measurement comment,
//! <https://github.com/qumbra-labs/qumbra-lab/issues/775#issuecomment-5886951895>.

pub(crate) mod bench;
#[cfg(test)]
mod bundle_node;
pub(crate) mod dep;
pub(crate) mod f5box;
pub(crate) mod gate;
pub(crate) mod native;
pub(crate) mod rec;
pub(crate) mod neg;
pub(crate) mod ood;
pub(crate) mod verify;
pub(crate) mod wleaf;

/// `qlab-bench f4leaf --check | f4neg …`.
pub(crate) fn run(mode: &str, args: &[String]) -> Result<(), String> {
    match mode {
        "f4leaf" if args.iter().any(|a| a == "--prove") => bench::prove_run(args),
        "f4leaf" => neg::check(args),
        "f4neg" => neg::run(args),
        "f4dep" => dep::check(args),
        "f4census" => rec::run(args),
        "f4gate" => gate::run(args),
        "f4ood" => ood::run(args),
        other => Err(format!("unknown f4 mode `{other}`")),
    }
}
