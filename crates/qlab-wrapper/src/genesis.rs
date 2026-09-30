//! Lab #785 F5-4a — the wrapper chain's **genesis state**, computed here so
//! consensus can build it: the empty L2 state's roots ([`genesis_roots`]) and
//! the genesis [`Surface`] every V6 node starts from ([`genesis_surface`]).
//!
//! Ported from qlab-bench's native model (`f4::native::WState::genesis`, over
//! `f3::native::L2State::genesis`), which keeps the full trees because the
//! prover needs their paths. This module computes roots only. qlab-bench's
//! `wgenesis_roots_are_the_native_models` test cross-locks the two, with an
//! empty registry and a non-empty one (ruling condition (a)), and qumbra-node
//! asserts [`genesis_surface`] against the V6 rehearsal genesis's pin.
//!
//! The state at genesis:
//! - **`N` and `K`**, the two indexed trees: the single leaf `(0, 2^256 − 1)`
//!   at index 0 ([`nf_leaf_hash`]), so each tree's next index is 1;
//! - **`C`, `AA` and `CH`**, the append trees: empty, next index 0, root the
//!   top of the zero ladder;
//! - **`R`**, the registry: the caller's root (qlab-cbserver's
//!   `RegistryTree`, which this crate does not depend on); an empty registry
//!   is [`empty_registry_root`];
//! - **the supply tree**: every leaf `H(asset ‖ 0)` ([`supply_leaf_state`]);
//! - **`SD`**, `D_cum` and `E_cum`: zero.
use qlab_air::l2p::KEY_MAX;
use qlab_air::narrow::MERKLE_DEPTH;

use crate::hash::{h4, nf_leaf_hash, node, supply_leaf_state, Digest, Roots, WRoots, EMPTY, N_DEPTH, SUPPLY_DEPTH};
use crate::verify::Surface;

/// The chain's wrapper version: ruling Q1's K = 16 on the b2/q91 lane.
pub const CHAIN_VERSION: u32 = 1;

/// `zeros[i]` = the root of an all-empty subtree of height `i` (`zeros[0]`
/// the empty leaf): qlab-cbserver's `tree::zeros`, the node's ladder.
pub fn zeros() -> [Digest; MERKLE_DEPTH + 1] {
    let mut z = [EMPTY; MERKLE_DEPTH + 1];
    for i in 1..=MERKLE_DEPTH {
        z[i] = node(&z[i - 1], &z[i - 1]);
    }
    z
}

/// An indexed tree at genesis: its one leaf `(0, 2^256 − 1)` at index 0.
pub fn indexed_genesis_root() -> Digest {
    let z = zeros();
    (0..N_DEPTH).fold(nf_leaf_hash(&EMPTY, &KEY_MAX), |d, lvl| node(&d, &z[lvl]))
}

/// An empty append tree's root (`C`, `AA`, `CH`).
pub fn empty_append_root() -> Digest {
    zeros()[MERKLE_DEPTH]
}

/// The registry root with no asset registered.
pub fn empty_registry_root() -> Digest {
    zeros()[qlab_air::l2::REGISTRY_DEPTH]
}

/// The supply tree at genesis: every asset's outstanding amount zero.
/// 2^16 leaves; computed once.
pub fn supply_genesis_root() -> Digest {
    static ROOT: std::sync::OnceLock<Digest> = std::sync::OnceLock::new();
    *ROOT.get_or_init(|| {
        let mut level: Vec<Digest> = (0..1u64 << SUPPLY_DEPTH).map(|a| h4(&supply_leaf_state(a, 0))).collect();
        for _ in 0..SUPPLY_DEPTH {
            level = level.chunks_exact(2).map(|p| node(&p[0], &p[1])).collect();
        }
        level[0]
    })
}

/// The empty L2 state's roots over a registry whose root is `registry_root`.
pub fn genesis_roots(registry_root: &Digest) -> WRoots {
    let indexed = indexed_genesis_root();
    let append = empty_append_root();
    WRoots {
        f3: Roots { n: indexed, n_next: 1, c: append, c_next: 0, r: *registry_root, sd: EMPTY },
        k: indexed,
        k_next: 1,
        aa: append,
        aa_next: 0,
        ch: append,
        ch_next: 0,
        sup: supply_genesis_root(),
        d_cum: 0,
        e_cum: 0,
    }
}

/// The chain's origin: [`Surface::genesis`] at [`CHAIN_VERSION`] over
/// [`genesis_roots`]. Its `commitment` is what a V6 genesis pins as
/// `WrapperParams.genesis_surface`.
pub fn genesis_surface(l2_id: u64, registry_root: &Digest) -> Surface {
    Surface::genesis(CHAIN_VERSION, l2_id, genesis_roots(registry_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_genesis_roots_are_distinct_where_the_trees_are() {
        let r = genesis_roots(&empty_registry_root());
        // N and K are the same construction; C, AA and CH likewise.
        assert_eq!(r.f3.n, r.k);
        assert_eq!(r.f3.c, r.aa);
        assert_eq!(r.aa, r.ch);
        // The indexed trees hold a leaf; the append trees and the registry do not.
        assert_ne!(r.f3.n, r.f3.c);
        assert_ne!(r.f3.r, r.f3.c, "depth 16 and depth 32 empties differ");
        assert_ne!(r.sup, EMPTY);
        assert_eq!((r.f3.n_next, r.k_next, r.f3.c_next, r.aa_next, r.ch_next), (1, 1, 0, 0, 0));
    }

    #[test]
    fn the_genesis_surface_binds_l2_id_and_registry() {
        let e = empty_registry_root();
        let s = genesis_surface(1, &e);
        assert_eq!(s.version, CHAIN_VERSION);
        assert_eq!((s.prev, s.newest_anchor, s.exit_cmt), ([0; 4], [0; 4], [0; 4]));
        assert_ne!(s.commitment, genesis_surface(2, &e).commitment);
        assert_ne!(s.commitment, genesis_surface(1, &[1, 0, 0, 0]).commitment);
    }
}
