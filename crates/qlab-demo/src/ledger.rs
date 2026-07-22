//! F4: the value-conservation glue qlab-devnet does not provide — a placeholder
//! supply/coinbase tracker and a persistent (cross-block) nullifier set. Both
//! are documented devnet *extensions* (qlab-devnet enforces only within-block
//! nullifier uniqueness and carries a bare coinbase counter).

use std::collections::HashSet;

/// Placeholder supply accounting: coinbase mints add to supply; fees are treated
/// as removed from circulation (a burn stand-in). Shielded transfers conserve
/// value in-circuit (build_bucket's balance constraint), so they do not move
/// these counters.
#[derive(Debug, Default, Clone)]
pub struct SupplyTracker {
    minted: u64,
    fees_burned: u64,
}

impl SupplyTracker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn mint_coinbase(&mut self, amount: u64) {
        self.minted += amount;
    }
    pub fn record_fee(&mut self, fee: u64) {
        self.fees_burned += fee;
    }
    pub fn minted(&self) -> u64 {
        self.minted
    }
    pub fn circulating(&self) -> u64 {
        self.minted - self.fees_burned
    }
}

/// Persistent nullifier set: `insert` returns `false` if the nullifier was
/// already spent (the cross-block double-spend rejection qlab-devnet lacks).
#[derive(Debug, Default, Clone)]
pub struct NullifierSet {
    seen: HashSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, nf: [u8; 32]) -> bool {
        self.seen.insert(nf)
    }
    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        self.seen.contains(nf)
    }
    pub fn len(&self) -> usize {
        self.seen.len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_tracks_coinbase_and_fees() {
        let mut s = SupplyTracker::new();
        s.mint_coinbase(80_000);
        s.mint_coinbase(40_000);
        assert_eq!(s.minted(), 120_000);
        assert_eq!(s.circulating(), 120_000);
        s.record_fee(1_000); // a fee removes value from circulation (placeholder burn)
        assert_eq!(s.circulating(), 119_000);
        assert_eq!(s.minted(), 120_000, "minting supply is unchanged by fees");
    }

    #[test]
    fn nullifier_set_rejects_double_spend() {
        let mut n = NullifierSet::new();
        let nf = [7u8; 32];
        assert!(n.insert(nf), "first spend lands");
        assert!(!n.insert(nf), "second spend of same nullifier rejected");
        assert!(n.contains(&nf));
        assert_eq!(n.len(), 1);
    }
}
