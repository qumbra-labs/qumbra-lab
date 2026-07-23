//! Inventory-gossip support: a bounded "seen" cache for dedup and the relay
//! policy constants. The message flow (inv → getdata → object → relay-inv) is
//! wired in [`crate::node`]; this module owns the dedup memory so a gossiped
//! object is processed and re-announced at most once per node.

use std::collections::{HashSet, VecDeque};

use qlab_devnet::header::Hash32;

/// Default capacity of the seen-inventory cache (ids). Bounds memory under a
/// flood; oldest ids age out. `[devnet-placeholder]` — a real node tunes this.
pub const DEFAULT_SEEN_CAPACITY: usize = 100_000;

/// Points deducted for a peer sending a structurally-invalid frame (→ ban after
/// enough; see [`crate::peer::BAN_THRESHOLD`]).
pub const PENALTY_MALFORMED: i32 = 100;
/// Points for a peer sending an object that fails validation.
pub const PENALTY_INVALID_OBJECT: i32 = 20;
/// Points for a peer answering `GetData` with `NotFound` on something it inv' d.
pub const PENALTY_WELSHED_INV: i32 = 5;

/// A bounded FIFO set of inventory ids we have already handled. `insert` returns
/// whether the id was newly inserted (i.e. worth processing / relaying).
#[derive(Debug)]
pub struct SeenCache {
    set: HashSet<Hash32>,
    order: VecDeque<Hash32>,
    cap: usize,
}

impl SeenCache {
    pub fn new(cap: usize) -> Self {
        SeenCache { set: HashSet::new(), order: VecDeque::new(), cap: cap.max(1) }
    }

    /// Insert an id; returns `true` if it was not present before.
    pub fn insert(&mut self, id: Hash32) -> bool {
        if !self.set.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }

    pub fn contains(&self, id: &Hash32) -> bool {
        self.set.contains(id)
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl Default for SeenCache {
    fn default() -> Self {
        SeenCache::new(DEFAULT_SEEN_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_reports_novelty() {
        let mut c = SeenCache::new(8);
        assert!(c.insert([1; 32]));
        assert!(!c.insert([1; 32]));
        assert!(c.contains(&[1; 32]));
    }

    #[test]
    fn evicts_oldest_past_capacity() {
        let mut c = SeenCache::new(2);
        c.insert([1; 32]);
        c.insert([2; 32]);
        c.insert([3; 32]); // evicts [1;32]
        assert!(!c.contains(&[1; 32]));
        assert!(c.contains(&[2; 32]));
        assert!(c.contains(&[3; 32]));
        // [1;32] is now "new" again after eviction.
        assert!(c.insert([1; 32]));
    }
}
