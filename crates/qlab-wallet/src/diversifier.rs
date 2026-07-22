//! Diversifier index allocation, persistence, and rotation (issue #43, part 2).
//!
//! Post-#32 the circuit binds `rkm = H(nk ‖ D_R ‖ d)`, so two addresses of one
//! wallet with distinct diversifiers `d` are genuinely unlinkable. This module
//! is the wallet-side **bookkeeping** that lets a wallet actually use that: turn
//! a monotonic index into a diversifier, hand out fresh (rotated) addresses,
//! persist which indices are live, and refuse the reuse/collision footguns.
//!
//! ## Index → diversifier
//!
//! A managed diversifier is a **pseudorandom function of the index**, not the
//! index itself:
//!
//! ```text
//! d(index) = Keccak256( DS_DIV_INDEX ‖ div_seed ‖ index.to_le_bytes() )[..16]
//! ```
//!
//! Using the raw index as `d` would defeat the whole point — an observer holding
//! two addresses of one wallet would see `d = 0, 1, 2, …` and immediately learn
//! they are sequential (and how many the wallet has issued). Hashing under the
//! wallet's `div_seed` makes each `d` look independently random while staying
//! deterministic and reproducible by any holder of `div_seed` (i.e. the wallet,
//! its `fvk`, or its `ivk` — see [`crate::viewing`]).
//!
//! `div_seed` is the same value that seeds each diversified ML-KEM keypair
//! (`viewing::DS_DIV_SEED`), so one secret drives both the `rkm`-side `d` and the
//! encryption-side `dk_d`.
//!
//! ## Ledger — persistence & guards
//!
//! [`DiversifierLedger`] tracks which indices are live and the `d` each maps to.
//! It enforces two invariants at every insertion:
//!
//! - **Reuse guard:** an index is allocated at most once
//!   ([`DiversifierError::IndexAlreadyAllocated`]).
//! - **Collision guard:** no two live indices may bind the *same* `d`
//!   ([`DiversifierError::DiversifierCollision`]) — binding two logical slots to
//!   one on-wire diversifier would make those "addresses" identical/linkable, the
//!   exact footgun the whole diversifier machinery exists to avoid. For derived
//!   `d` a collision is a ~2⁻⁶⁴ hash accident; the guard's real job is catching a
//!   caller who reserves a *manual* `d` (e.g. a legacy/default diversifier) that
//!   clashes with a managed one.
//!
//! The ledger is byte-serializable ([`DiversifierLedger::to_bytes`] /
//! [`from_bytes`](DiversifierLedger::from_bytes)) — the persistence *format*; the
//! storage transport (file, keychain, …) is out of scope, exactly as the
//! short-address [`crate::address::AddressBook`] is a format+interface stub.

use std::collections::BTreeMap;

use qlab_note::hash::keccak256;

use crate::address::{Diversifier, DIV_LEN};

/// Domain string for the index→diversifier PRF (wallet-only KDF).
pub const DS_DIV_INDEX: &[u8] = b"qumbra:wallet:div-index:v1";

/// Ledger serialization format version.
const LEDGER_FORMAT_VERSION: u8 = 1;

/// Derive the diversifier for `index` under this wallet's `div_seed`:
/// `Keccak256(DS_DIV_INDEX ‖ div_seed ‖ index_le)[..16]`. Deterministic and
/// reproducible by any `div_seed` holder.
pub fn diversifier_at_index(div_seed: &[u8; 32], index: u64) -> Diversifier {
    let mut input = Vec::with_capacity(DS_DIV_INDEX.len() + 32 + 8);
    input.extend_from_slice(DS_DIV_INDEX);
    input.extend_from_slice(div_seed);
    input.extend_from_slice(&index.to_le_bytes());
    let h = keccak256(&input);
    let mut d = [0u8; DIV_LEN];
    d.copy_from_slice(&h[..DIV_LEN]);
    Diversifier::from_bytes(d)
}

/// A diversifier-management failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DiversifierError {
    /// The index is already live in the ledger (reuse guard).
    IndexAlreadyAllocated(u64),
    /// The diversifier is already bound to a different live index (collision
    /// guard) — carries the two colliding indices `(existing, attempted)`.
    DiversifierCollision(u64, u64),
    /// [`DiversifierLedger::from_bytes`] got malformed input.
    MalformedLedger,
}

impl core::fmt::Display for DiversifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DiversifierError::IndexAlreadyAllocated(i) => {
                write!(f, "diversifier index {i} is already allocated")
            }
            DiversifierError::DiversifierCollision(a, b) => {
                write!(f, "diversifier collision between indices {a} and {b}")
            }
            DiversifierError::MalformedLedger => write!(f, "malformed diversifier ledger bytes"),
        }
    }
}

impl std::error::Error for DiversifierError {}

/// The persistent record of a wallet's live diversifier indices.
///
/// Holds `index -> d` for every live slot plus a monotonically advancing cursor
/// for [`allocate`](DiversifierLedger::allocate). It is `div_seed`-agnostic — the
/// caller passes `div_seed` when a derivation is needed — so it can be persisted
/// without touching secret material (the stored `d` values are public address
/// components anyway).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiversifierLedger {
    next_index: u64,
    allocated: BTreeMap<u64, [u8; DIV_LEN]>,
}

impl DiversifierLedger {
    /// An empty ledger (cursor at index 0).
    pub fn new() -> Self {
        Self::default()
    }

    /// The next index [`allocate`](Self::allocate) will try.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// How many indices are live.
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Whether `index` is live.
    pub fn is_allocated(&self, index: u64) -> bool {
        self.allocated.contains_key(&index)
    }

    /// The diversifier bound to a live `index`, if any (as recorded — matches
    /// [`diversifier_at_index`] for auto/reserved slots).
    pub fn diversifier_of(&self, index: u64) -> Option<Diversifier> {
        self.allocated.get(&index).copied().map(Diversifier::from_bytes)
    }

    /// Live indices in ascending order.
    pub fn indices(&self) -> impl Iterator<Item = u64> + '_ {
        self.allocated.keys().copied()
    }

    /// The shared insertion path enforcing both guards.
    fn insert(&mut self, index: u64, d: [u8; DIV_LEN]) -> Result<(), DiversifierError> {
        if self.allocated.contains_key(&index) {
            return Err(DiversifierError::IndexAlreadyAllocated(index));
        }
        // Collision guard: refuse a d already bound to a different index.
        if let Some((&other, _)) = self.allocated.iter().find(|(_, &dd)| dd == d) {
            return Err(DiversifierError::DiversifierCollision(other, index));
        }
        self.allocated.insert(index, d);
        if index >= self.next_index {
            self.next_index = index + 1;
        }
        Ok(())
    }

    /// Reserve the next free index (advancing past any already-reserved ones) and
    /// return `(index, d)` where `d = diversifier_at_index(div_seed, index)`.
    /// This is the address-rotation primitive: each call yields a fresh, unused,
    /// unlinkable diversifier.
    pub fn allocate(&mut self, div_seed: &[u8; 32]) -> (u64, Diversifier) {
        loop {
            let index = self.next_index;
            if self.allocated.contains_key(&index) {
                self.next_index += 1;
                continue;
            }
            let d = diversifier_at_index(div_seed, index);
            // Derived-d collision is ~2^-64; if it somehow happens, skip the index
            // rather than fail an infallible allocate.
            match self.insert(index, *d.as_bytes()) {
                Ok(()) => return (index, d),
                Err(_) => {
                    self.next_index += 1;
                    continue;
                }
            }
        }
    }

    /// Reserve a *specific* index, binding its derived diversifier. Errors on the
    /// reuse/collision guards. Use when restoring a known slot or choosing a
    /// non-sequential index deliberately.
    pub fn reserve(&mut self, div_seed: &[u8; 32], index: u64) -> Result<Diversifier, DiversifierError> {
        let d = diversifier_at_index(div_seed, index);
        self.insert(index, *d.as_bytes())?;
        Ok(d)
    }

    /// Reserve a specific index bound to a caller-supplied diversifier `d` — for
    /// tracking a manual/legacy diversifier (e.g. the all-zero
    /// [`Diversifier::default`] canonical address) alongside managed ones. Same
    /// reuse/collision guards; this is where the collision guard earns its keep,
    /// since a manual `d` can clash with a managed slot.
    pub fn reserve_manual(&mut self, index: u64, d: Diversifier) -> Result<(), DiversifierError> {
        self.insert(index, *d.as_bytes())
    }

    /// Serialize to bytes (persistence format):
    /// `version(1) ‖ next_index(8 LE) ‖ count(8 LE) ‖ [index(8 LE) ‖ d(16)]*`,
    /// entries in ascending index order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + self.allocated.len() * (8 + DIV_LEN));
        out.push(LEDGER_FORMAT_VERSION);
        out.extend_from_slice(&self.next_index.to_le_bytes());
        out.extend_from_slice(&(self.allocated.len() as u64).to_le_bytes());
        for (index, d) in &self.allocated {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(d);
        }
        out
    }

    /// Parse bytes produced by [`to_bytes`](Self::to_bytes). Rejects a wrong
    /// version, truncated input, trailing bytes, a duplicate index, or a
    /// stored-in cursor that precedes a stored index.
    pub fn from_bytes(b: &[u8]) -> Result<Self, DiversifierError> {
        if b.len() < 1 + 8 + 8 || b[0] != LEDGER_FORMAT_VERSION {
            return Err(DiversifierError::MalformedLedger);
        }
        let next_index = u64::from_le_bytes(b[1..9].try_into().unwrap());
        let count = u64::from_le_bytes(b[9..17].try_into().unwrap()) as usize;
        let body = &b[17..];
        let entry = 8 + DIV_LEN;
        if body.len() != count * entry {
            return Err(DiversifierError::MalformedLedger);
        }
        let mut allocated = BTreeMap::new();
        for i in 0..count {
            let off = i * entry;
            let index = u64::from_le_bytes(body[off..off + 8].try_into().unwrap());
            let mut d = [0u8; DIV_LEN];
            d.copy_from_slice(&body[off + 8..off + entry]);
            if allocated.insert(index, d).is_some() {
                return Err(DiversifierError::MalformedLedger); // duplicate index
            }
            if index >= next_index {
                return Err(DiversifierError::MalformedLedger); // cursor behind a live index
            }
        }
        Ok(Self { next_index, allocated })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIV_SEED: [u8; 32] = [0x42; 32];

    #[test]
    fn index_diversifier_is_pseudorandom_and_deterministic() {
        // Deterministic.
        assert_eq!(
            diversifier_at_index(&DIV_SEED, 5),
            diversifier_at_index(&DIV_SEED, 5)
        );
        // Not the raw index: index 0/1/2 must NOT be all-zero / tiny sequential.
        let d0 = diversifier_at_index(&DIV_SEED, 0);
        let d1 = diversifier_at_index(&DIV_SEED, 1);
        assert_ne!(d0, d1, "distinct indices -> distinct d");
        assert_ne!(d0.as_bytes(), &[0u8; DIV_LEN], "index 0 is not the zero diversifier");
        assert_ne!(
            &d1.as_bytes()[..8],
            &1u64.to_le_bytes(),
            "d must not leak the raw index"
        );
        // A different div_seed gives different d for the same index.
        assert_ne!(diversifier_at_index(&[7u8; 32], 0), d0);
    }

    #[test]
    fn allocate_is_monotonic_and_unique() {
        let mut led = DiversifierLedger::new();
        let mut seen = std::collections::HashSet::new();
        let mut last = None;
        for _ in 0..64 {
            let (i, d) = led.allocate(&DIV_SEED);
            assert!(seen.insert(*d.as_bytes()), "allocate never repeats a diversifier");
            if let Some(l) = last {
                assert!(i > l, "indices strictly increase");
            }
            last = Some(i);
            // The allocated d matches the pure derivation.
            assert_eq!(d, diversifier_at_index(&DIV_SEED, i));
        }
        assert_eq!(led.allocated_count(), 64);
        assert_eq!(led.next_index(), 64);
    }

    #[test]
    fn reuse_guard_rejects_double_reserve() {
        let mut led = DiversifierLedger::new();
        led.reserve(&DIV_SEED, 10).expect("first reserve ok");
        assert_eq!(
            led.reserve(&DIV_SEED, 10).unwrap_err(),
            DiversifierError::IndexAlreadyAllocated(10),
            "reserving the same index twice is refused"
        );
        // And allocate skips the reserved index.
        led.reserve(&DIV_SEED, 0).unwrap();
        let (i, _) = led.allocate(&DIV_SEED);
        assert_ne!(i, 0);
        assert_ne!(i, 10);
        assert!(!led.is_allocated(9999));
    }

    #[test]
    fn collision_guard_rejects_shared_diversifier() {
        // Two DIFFERENT indices bound to the SAME manual d must be refused — this
        // is the linkability footgun the guard exists to stop.
        let mut led = DiversifierLedger::new();
        let d = Diversifier::from_bytes([0xab; DIV_LEN]);
        led.reserve_manual(3, d).expect("first manual reserve ok");
        match led.reserve_manual(4, d).unwrap_err() {
            DiversifierError::DiversifierCollision(a, b) => {
                assert_eq!((a, b), (3, 4), "reports the colliding index pair");
            }
            e => panic!("expected DiversifierCollision, got {e:?}"),
        }
        // Re-binding the SAME index to the SAME d is a reuse error, not collision.
        assert_eq!(
            led.reserve_manual(3, d).unwrap_err(),
            DiversifierError::IndexAlreadyAllocated(3)
        );
    }

    #[test]
    fn manual_default_diversifier_coexists_with_managed() {
        // The canonical all-zero diversifier (used by the demo) can be tracked at
        // its own index alongside managed pseudorandom ones without collision.
        let mut led = DiversifierLedger::new();
        led.reserve_manual(0, Diversifier::default()).unwrap();
        let (i, d) = led.allocate(&DIV_SEED);
        assert_ne!(i, 0);
        assert_ne!(d, Diversifier::default());
        assert_eq!(led.allocated_count(), 2);
    }

    #[test]
    fn persistence_roundtrips() {
        let mut led = DiversifierLedger::new();
        led.reserve_manual(0, Diversifier::default()).unwrap();
        for _ in 0..5 {
            led.allocate(&DIV_SEED);
        }
        led.reserve(&DIV_SEED, 100).unwrap();

        let bytes = led.to_bytes();
        let back = DiversifierLedger::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(back, led, "ledger survives serialize/deserialize");
        assert_eq!(back.next_index(), led.next_index());
        assert_eq!(back.diversifier_of(100), led.diversifier_of(100));
    }

    #[test]
    fn persistence_rejects_malformed() {
        let mut led = DiversifierLedger::new();
        led.allocate(&DIV_SEED);
        let good = led.to_bytes();

        // Wrong version.
        let mut bad = good.clone();
        bad[0] = 2;
        assert_eq!(DiversifierLedger::from_bytes(&bad).unwrap_err(), DiversifierError::MalformedLedger);
        // Truncated.
        assert_eq!(
            DiversifierLedger::from_bytes(&good[..good.len() - 1]).unwrap_err(),
            DiversifierError::MalformedLedger
        );
        // Trailing garbage.
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(DiversifierLedger::from_bytes(&extra).unwrap_err(), DiversifierError::MalformedLedger);
        // Too short to hold the header.
        assert_eq!(DiversifierLedger::from_bytes(&[1u8]).unwrap_err(), DiversifierError::MalformedLedger);
    }
}
