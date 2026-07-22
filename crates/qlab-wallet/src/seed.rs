//! Versioned HD master seed → spending-key hierarchy (issue #43, part 1).
//!
//! M7 took `sk` as a given 256-bit secret and parked "how is `sk` derived from a
//! master seed" as a future item (m7-wallet-plan §6). This module fills that gap
//! with a **domain-separated Keccak chain** — no BIP-32 (secp256k1 point math is
//! meaningless for a hash/STARK PQ chain) and no HMAC-SHA512; the whole tree is
//! the one conservative permutation the rest of Qumbra already uses
//! (`qlab_air::reference::keccak_f`, via `qlab_note::hash::keccak256`).
//!
//! ## Derivation path
//!
//! A path is written `m / account / role` (two hardened levels — there is no
//! public/non-hardened branch; a PQ chain has no use for xpub-style public
//! derivation, so *every* level mixes the full parent secret):
//!
//! ```text
//! node_master        = Keccak256( DS_HD_MASTER  ‖ [version] ‖ entropy(32) )
//! node_account(a)    = Keccak256( DS_HD_ACCOUNT ‖ node_master ‖ a.to_le_bytes()   )
//! sk(a, role)        = Keccak256( DS_HD_ROLE    ‖ node_account(a) ‖ role.to_le() )
//! ```
//!
//! - `account` (u32) separates independent sub-wallets of one seed (Zcash ZIP-32
//!   account precedent) — each account has its own `nk`/`fvk`/`ivk`/`div_seed`.
//! - `role` (u32) reserves the leaf level for future key roles; today only
//!   [`Role::Spend`] (`0`) is defined and is what [`SpendingKey`] consumes. The
//!   downstream `nk`/`rkm`/`nf` split is NOT an HD level — it is the fixed,
//!   circuit-bound hierarchy already implemented in [`crate::keys`]; the HD tree
//!   only produces the account's root `sk`.
//!
//! The chain is prefix-free by construction: each level absorbs a distinct ASCII
//! domain string, so `node_account` can never be confused with an `sk` leaf or
//! the master node even at colliding index bytes. These are **wallet-only** KDFs
//! (never checked in-circuit), so they use ASCII domain strings à la
//! `qlab-note` — the compact bit-marker convention is reserved for the
//! circuit-bound `nk`/`rkm`/`nf` in [`crate::keys`].
//!
//! ## Byte-for-byte lock
//!
//! Because a seed phrase is the wallet's ONLY backup, the derivation may never
//! silently drift: the tests pin golden `sk` bytes for a fixed seed+path (the
//! same regression discipline as the circuit-bound `nk`/`rkm`/`nf` locks, here
//! a self-consistency golden vector rather than a `build_bucket` cross-check),
//! and an end-to-end lock proves a seed-derived key yields a spendable note
//! against `build_bucket` (see `tests/end_to_end.rs`).

use qlab_note::hash::{digest_from_bytes, keccak256};

use crate::keys::{Lanes, SpendingKey};

/// Current master-seed format version. Leads the master-node absorb, so a future
/// scheme change (different chain, different entropy width) is a clean version
/// bump that produces entirely disjoint keys from a `v1` seed of the same bytes.
pub const SEED_VERSION: u8 = 1;

/// Master-seed entropy width in bytes (256-bit — matches the `sk` width and the
/// note-commitment field size; also the natural 24-word mnemonic size).
pub const ENTROPY_LEN: usize = 32;

/// Domain string for the master node: `Keccak256(DS_HD_MASTER ‖ [version] ‖ entropy)`.
pub const DS_HD_MASTER: &[u8] = b"qumbra:hd:v1:master";
/// Domain string for an account node: `Keccak256(DS_HD_ACCOUNT ‖ parent ‖ account_le)`.
pub const DS_HD_ACCOUNT: &[u8] = b"qumbra:hd:v1:account";
/// Domain string for a role leaf: `Keccak256(DS_HD_ROLE ‖ account_node ‖ role_le)`.
pub const DS_HD_ROLE: &[u8] = b"qumbra:hd:v1:role";

/// A leaf key role — the third HD level. Only [`Role::Spend`] is defined at v1;
/// the enum reserves the level so future roles (e.g. a standalone
/// audit/disclosure key that is NOT derivable from `sk`) get disjoint leaves
/// without a format bump.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Role {
    /// The spending key `sk` — the root of the circuit-bound hierarchy.
    Spend = 0,
}

impl Role {
    /// The little-endian bytes absorbed at the role level.
    fn index(self) -> u32 {
        self as u32
    }
}

/// A versioned HD master seed: 256 bits of entropy plus a scheme version. The
/// entropy is the wallet's root secret — everything (`sk`, `nk`, `div_seed`, all
/// ML-KEM keypairs) descends from it deterministically.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterSeed {
    version: u8,
    entropy: [u8; ENTROPY_LEN],
}

impl MasterSeed {
    /// Wrap raw 256-bit entropy at the current [`SEED_VERSION`].
    pub fn from_entropy(entropy: [u8; ENTROPY_LEN]) -> Self {
        Self { version: SEED_VERSION, entropy }
    }

    /// Wrap entropy at an explicit version (for parsing older/newer seeds; the
    /// derivation only knows `v1` today, so a non-`v1` version derives a disjoint
    /// but well-defined tree via the version byte in the master absorb).
    pub fn with_version(version: u8, entropy: [u8; ENTROPY_LEN]) -> Self {
        Self { version, entropy }
    }

    /// The scheme version byte.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The raw entropy bytes (the value a mnemonic encodes).
    pub fn entropy(&self) -> &[u8; ENTROPY_LEN] {
        &self.entropy
    }

    /// The master node — the chain root. `Keccak256(DS_HD_MASTER ‖ [version] ‖ entropy)`.
    fn master_node(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(DS_HD_MASTER.len() + 1 + ENTROPY_LEN);
        input.extend_from_slice(DS_HD_MASTER);
        input.push(self.version);
        input.extend_from_slice(&self.entropy);
        keccak256(&input)
    }

    /// The account node for account index `a`.
    fn account_node(&self, account: u32) -> [u8; 32] {
        let mut input = Vec::with_capacity(DS_HD_ACCOUNT.len() + 32 + 4);
        input.extend_from_slice(DS_HD_ACCOUNT);
        input.extend_from_slice(&self.master_node());
        input.extend_from_slice(&account.to_le_bytes());
        keccak256(&input)
    }

    /// The raw `sk` bytes at path `m / account / role`.
    pub fn sk_bytes(&self, account: u32, role: Role) -> [u8; 32] {
        let mut input = Vec::with_capacity(DS_HD_ROLE.len() + 32 + 4);
        input.extend_from_slice(DS_HD_ROLE);
        input.extend_from_slice(&self.account_node(account));
        input.extend_from_slice(&role.index().to_le_bytes());
        keccak256(&input)
    }

    /// The spending key `sk` at path `m / account / role`, as circuit lanes.
    pub fn spending_key(&self, account: u32, role: Role) -> SpendingKey {
        SpendingKey::from_lanes(self.spending_key_lanes(account, role))
    }

    /// The `sk` lanes at path `m / account / role` (the `[u64; 4]` the circuit
    /// hierarchy consumes). Convenience for callers that want raw lanes.
    pub fn spending_key_lanes(&self, account: u32, role: Role) -> Lanes {
        digest_from_bytes(&self.sk_bytes(account, role))
    }
}

impl core::fmt::Debug for MasterSeed {
    /// Never print the entropy — a seed is the whole secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MasterSeed")
            .field("version", &self.version)
            .field("entropy", &"<redacted 256-bit>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> MasterSeed {
        // Fixed non-trivial entropy so the golden vectors below are stable.
        let mut e = [0u8; ENTROPY_LEN];
        for (i, b) in e.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
        MasterSeed::from_entropy(e)
    }

    /// GOLDEN LOCK: the derivation is byte-for-byte frozen. A seed phrase is the
    /// only backup, so any drift (domain string, index encoding, chain order)
    /// must break a test. If this vector changes, the change is a BREAKING seed
    /// format change and needs a `SEED_VERSION` bump + a design-repo note.
    #[test]
    fn sk_derivation_is_byte_frozen() {
        let s = seed();
        // Recomputed once and pinned; NOT copied from the implementation blindly
        // — cross-checked by the hand recomputation in `chain_matches_by_hand`.
        let sk = s.sk_bytes(0, Role::Spend);
        let hex: String = sk.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "1a6937e01f20ee0513ff6e6274e6d9e85bb14874cf84c07f4c5847e53780cac4",
            "HD sk derivation drifted — this is a BREAKING seed-format change; \
             bump SEED_VERSION and file a design-repo note before touching this vector"
        );
    }

    /// Independent hand recomputation of the full chain (no reuse of the private
    /// helpers' composition) — locks the exact absorb layout of every level.
    #[test]
    fn chain_matches_by_hand() {
        let s = seed();

        // master
        let mut m = Vec::new();
        m.extend_from_slice(DS_HD_MASTER);
        m.push(SEED_VERSION);
        m.extend_from_slice(s.entropy());
        let node_master = keccak256(&m);

        // account 3
        let mut a = Vec::new();
        a.extend_from_slice(DS_HD_ACCOUNT);
        a.extend_from_slice(&node_master);
        a.extend_from_slice(&3u32.to_le_bytes());
        let node_account = keccak256(&a);

        // role Spend
        let mut r = Vec::new();
        r.extend_from_slice(DS_HD_ROLE);
        r.extend_from_slice(&node_account);
        r.extend_from_slice(&(Role::Spend as u32).to_le_bytes());
        let sk = keccak256(&r);

        assert_eq!(sk, s.sk_bytes(3, Role::Spend), "hand chain == sk_bytes");
        assert_eq!(digest_from_bytes(&sk), s.spending_key_lanes(3, Role::Spend));
    }

    #[test]
    fn accounts_and_versions_are_separated() {
        let s = seed();
        // Distinct accounts → distinct sk.
        assert_ne!(s.sk_bytes(0, Role::Spend), s.sk_bytes(1, Role::Spend));
        // A version bump on the same entropy → a disjoint tree.
        let s2 = MasterSeed::with_version(2, *s.entropy());
        assert_ne!(s.sk_bytes(0, Role::Spend), s2.sk_bytes(0, Role::Spend));
        // Deterministic.
        assert_eq!(s.sk_bytes(7, Role::Spend), seed().sk_bytes(7, Role::Spend));
    }

    #[test]
    fn debug_redacts_entropy() {
        let dbg = format!("{:?}", seed());
        assert!(dbg.contains("redacted"), "entropy must not be printed: {dbg}");
        assert!(!dbg.contains("entropy: [1"), "raw entropy leaked: {dbg}");
    }
}
