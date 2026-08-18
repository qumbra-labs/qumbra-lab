//! `qumbra-pool` — the T2 pool binary (lab #482 stage 1).
//!
//! Stage-1 first commit: the crate exists so the owed cross-assert can
//! live next to both `qlab-stratum` blob constants and
//! `qlab_devnet::header` v5 constants. The protocol lib cannot take
//! `qlab-devnet` (it must stay off the node/PoW graph); this binary is
//! the first consumer that honestly depends on both.
//!
//! Endpoint, job lifecycle, accounting, and the form-keyed template
//! source land in the following commits. Share-validation consumes
//! #490's exported predicate and waits for that PR to merge.

/// Placeholder so `cargo test -p qumbra-pool` has a lib target on the
/// first commit. Replaced as the binary grows.
pub fn crate_name() -> &'static str {
    "qumbra-pool"
}

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name_is_stable() {
        assert_eq!(super::crate_name(), "qumbra-pool");
    }
}
