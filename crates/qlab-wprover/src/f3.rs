//! F3: the L2 state — the native reference (`native`) and the leaf AIR
//! (`leaf`) the wrapper's members are built and checked with.
pub mod leaf;
pub mod native;

/// The comparison gadget, which moved to `qlab_wrapper::cmp` at F5-1; named
/// here so the moved modules' `crate::f3::cmp` / `super::cmp` paths resolve.
pub mod cmp {
    pub use qlab_wrapper::cmp::*;
}
