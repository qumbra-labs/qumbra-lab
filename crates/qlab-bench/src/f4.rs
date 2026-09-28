//! Lab #775 — L2-F4, the wrapper chain (reading B; Larry's Q2 = A: the
//! enshrined object stays one wrapper proof, and F4b moves the native
//! checks in-circuit).
//!
//! F4-1: the wrapper leaf's native reference ([`native`]), W, the wrapper
//! leaf AIR ([`wleaf`]), its negatives ([`neg`]), and `verify_wrapper`, the
//! native reference verifier ([`verify`]).

pub(crate) mod native;
pub(crate) mod neg;
pub(crate) mod verify;
pub(crate) mod wleaf;

/// `qlab-bench f4leaf --check | f4neg …`.
pub(crate) fn run(mode: &str, args: &[String]) -> Result<(), String> {
    match mode {
        "f4leaf" => neg::check(args),
        "f4neg" => neg::run(args),
        other => Err(format!("unknown f4 mode `{other}`")),
    }
}
