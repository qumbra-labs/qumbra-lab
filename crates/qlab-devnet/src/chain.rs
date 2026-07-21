//! Chain state — the block store, cumulative work, and the current tip.
//!
//! 棒 0 provides the core type and heaviest-chain **tip selection by cumulative
//! work** (a block's PoW `difficulty` is its weight). Block *validation* (PoW
//! check, timestamp/height rules) and the mining loop land in 棒 1; committee
//! finality overrides fork choice below a finalized checkpoint in 棒 2–3.
//!
//! Pre-finality fork choice is heaviest chain (total accumulated work), the
//! standard PoW rule; finalized checkpoints will later pin a prefix that fork
//! choice can never abandon (consensus §4/§6 — "no reorg past finality").

use std::collections::HashMap;

use crate::header::{BlockHeader, Hash32};

/// A stored block: its header plus derived bookkeeping. 棒 0 is header-only; the
/// body (real M3 tx proofs) attaches in 棒 5.
#[derive(Clone, Debug)]
struct Entry {
    header: BlockHeader,
    /// Total PoW work from genesis to this block inclusive (Σ difficulty).
    cumulative_work: u128,
}

/// Error inserting a header into the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// A block with this hash is already present.
    Duplicate,
    /// The parent hash is not in the store.
    UnknownParent,
    /// `height` is not `parent.height + 1`.
    BadHeight,
}

/// The devnet chain state: all known blocks keyed by header hash, plus the tip
/// (heaviest-chain head).
#[derive(Clone, Debug)]
pub struct ChainState {
    blocks: HashMap<Hash32, Entry>,
    genesis: Hash32,
    tip: Hash32,
}

impl ChainState {
    /// Start a chain from `genesis` (whose `prev` must be all-zero, `height` 0).
    pub fn new(genesis: BlockHeader) -> Self {
        assert_eq!(genesis.height, 0, "genesis height must be 0");
        assert_eq!(genesis.prev, [0u8; 32], "genesis prev must be ZERO_HASH");
        let hash = genesis.header_hash();
        let entry = Entry {
            header: genesis,
            cumulative_work: genesis.difficulty as u128,
        };
        let mut blocks = HashMap::new();
        blocks.insert(hash, entry);
        Self {
            blocks,
            genesis: hash,
            tip: hash,
        }
    }

    /// Insert a header, linking it to its parent and updating the tip if the new
    /// block extends the heaviest chain. Does NOT yet check PoW validity — that
    /// is 棒 1. Returns the new block's hash on success.
    pub fn insert_header(&mut self, header: BlockHeader) -> Result<Hash32, InsertError> {
        let hash = header.header_hash();
        if self.blocks.contains_key(&hash) {
            return Err(InsertError::Duplicate);
        }
        let parent = self.blocks.get(&header.prev).ok_or(InsertError::UnknownParent)?;
        if header.height != parent.header.height + 1 {
            return Err(InsertError::BadHeight);
        }
        let cumulative_work = parent.cumulative_work + header.difficulty as u128;
        self.blocks.insert(hash, Entry { header, cumulative_work });

        // Heaviest-chain rule: adopt the new block as tip iff it has strictly more
        // cumulative work than the current tip. Ties keep the incumbent (first-seen).
        if cumulative_work > self.tip_work() {
            self.tip = hash;
        }
        Ok(hash)
    }

    /// The genesis block hash.
    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis
    }

    /// The current tip (heaviest-chain head) hash.
    pub fn tip_hash(&self) -> Hash32 {
        self.tip
    }

    /// The tip's height (== number of blocks on the main chain minus 1).
    pub fn tip_height(&self) -> u64 {
        self.blocks[&self.tip].header.height
    }

    /// Total accumulated work at the tip.
    pub fn tip_work(&self) -> u128 {
        self.blocks[&self.tip].cumulative_work
    }

    /// Look up a stored header by hash.
    pub fn header(&self, hash: &Hash32) -> Option<&BlockHeader> {
        self.blocks.get(hash).map(|e| &e.header)
    }

    /// Cumulative work up to and including `hash`, if known.
    pub fn cumulative_work(&self, hash: &Hash32) -> Option<u128> {
        self.blocks.get(hash).map(|e| e.cumulative_work)
    }

    /// Walk back `depth` parent links from `hash`. `depth = 0` returns `hash`
    /// itself; `depth = 1` its parent, etc. `None` if the walk runs off the end
    /// of the known chain (e.g. past genesis) or `hash` is unknown.
    pub fn ancestor(&self, hash: &Hash32, depth: u64) -> Option<Hash32> {
        let mut cur = *hash;
        for _ in 0..depth {
            let entry = self.blocks.get(&cur)?;
            if entry.header.height == 0 {
                return None; // genesis has no parent
            }
            cur = entry.header.prev;
        }
        // Confirm the final hash is actually known.
        self.blocks.contains_key(&cur).then_some(cur)
    }

    /// The main chain (heaviest), genesis → tip inclusive, as a Vec of hashes.
    /// Walks back from the tip along parent links, then reverses.
    pub fn main_chain(&self) -> Vec<Hash32> {
        let mut chain = Vec::with_capacity(self.tip_height() as usize + 1);
        let mut cur = self.tip;
        loop {
            chain.push(cur);
            let entry = &self.blocks[&cur];
            if entry.header.height == 0 {
                break;
            }
            cur = entry.header.prev;
        }
        chain.reverse();
        chain
    }

    /// Number of blocks known to the store (across all forks).
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the store holds only genesis.
    pub fn is_empty(&self) -> bool {
        self.blocks.len() <= 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ZERO_HASH;

    fn genesis() -> BlockHeader {
        BlockHeader::genesis(1_000, 0)
    }

    #[test]
    fn new_chain_tip_is_genesis() {
        let c = ChainState::new(genesis());
        assert_eq!(c.tip_hash(), c.genesis_hash());
        assert_eq!(c.tip_height(), 0);
        assert_eq!(c.tip_work(), 1_000);
        assert!(c.is_empty());
    }

    #[test]
    fn extending_advances_the_tip_and_accumulates_work() {
        let mut c = ChainState::new(genesis());
        let g = c.tip_hash();
        let child = BlockHeader::child_of(c.header(&g).unwrap(), 2, 1_000, ZERO_HASH);
        let ch = c.insert_header(child).unwrap();
        assert_eq!(c.tip_hash(), ch);
        assert_eq!(c.tip_height(), 1);
        assert_eq!(c.tip_work(), 2_000);
    }

    #[test]
    fn duplicate_and_unknown_parent_are_rejected() {
        let mut c = ChainState::new(genesis());
        let g = c.tip_hash();
        let child = BlockHeader::child_of(c.header(&g).unwrap(), 2, 1_000, ZERO_HASH);
        c.insert_header(child).unwrap();
        assert_eq!(c.insert_header(child), Err(InsertError::Duplicate));

        // A header whose parent is not present.
        let orphan = BlockHeader {
            prev: [0xAB; 32],
            height: 1,
            ..genesis()
        };
        assert_eq!(c.insert_header(orphan), Err(InsertError::UnknownParent));
    }

    #[test]
    fn bad_height_is_rejected() {
        let mut c = ChainState::new(genesis());
        let g = c.tip_hash();
        let mut child = BlockHeader::child_of(c.header(&g).unwrap(), 2, 1_000, ZERO_HASH);
        child.height = 5; // should be 1
        assert_eq!(c.insert_header(child), Err(InsertError::BadHeight));
    }

    #[test]
    fn heavier_fork_wins_the_tip() {
        // Build genesis → A (main), then a competing fork from genesis with MORE
        // work; the heavier fork must become the tip even though A came first.
        let mut c = ChainState::new(genesis());
        let g = c.tip_hash();
        let gh = *c.header(&g).unwrap();

        // Block A: difficulty 1_000, extends genesis (cumulative 2_000).
        let a = BlockHeader::child_of(&gh, 2, 1_000, ZERO_HASH);
        let a_hash = c.insert_header(a).unwrap();
        assert_eq!(c.tip_hash(), a_hash);

        // Block B: a competing child of genesis with higher difficulty (3_000 ⇒
        // cumulative 4_000 > A's 2_000). Distinct body commitment ⇒ distinct hash.
        let b = BlockHeader::child_of(&gh, 2, 3_000, [1u8; 32]);
        let b_hash = c.insert_header(b).unwrap();

        assert_ne!(a_hash, b_hash);
        assert_eq!(c.tip_hash(), b_hash, "heaviest chain must win");
        assert_eq!(c.tip_work(), 4_000);
        // A is still stored (a known side fork), just not the tip.
        assert!(c.header(&a_hash).is_some());
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn ancestor_walks_back_parent_links() {
        let mut c = ChainState::new(genesis());
        let g = c.genesis_hash();
        let a = BlockHeader::child_of(c.header(&g).unwrap(), 2, 1_000, [1u8; 32]);
        let a_hash = c.insert_header(a).unwrap();
        let b = BlockHeader::child_of(c.header(&a_hash).unwrap(), 4, 1_000, [2u8; 32]);
        let b_hash = c.insert_header(b).unwrap();

        assert_eq!(c.ancestor(&b_hash, 0), Some(b_hash));
        assert_eq!(c.ancestor(&b_hash, 1), Some(a_hash));
        assert_eq!(c.ancestor(&b_hash, 2), Some(g));
        assert_eq!(c.ancestor(&b_hash, 3), None); // past genesis
    }

    #[test]
    fn main_chain_is_genesis_to_tip() {
        let mut c = ChainState::new(genesis());
        let g = c.genesis_hash();
        let a = BlockHeader::child_of(c.header(&g).unwrap(), 2, 1_000, [1u8; 32]);
        let a_hash = c.insert_header(a).unwrap();
        let b = BlockHeader::child_of(c.header(&a_hash).unwrap(), 4, 1_000, [2u8; 32]);
        let b_hash = c.insert_header(b).unwrap();
        assert_eq!(c.main_chain(), vec![g, a_hash, b_hash]);
    }

    #[test]
    fn equal_work_keeps_the_incumbent_tip() {
        let mut c = ChainState::new(genesis());
        let gh = *c.header(&c.tip_hash()).unwrap();
        let a = BlockHeader::child_of(&gh, 2, 1_000, [0xAA; 32]);
        let a_hash = c.insert_header(a).unwrap();
        // Sibling with identical work but different body ⇒ different hash.
        let b = BlockHeader::child_of(&gh, 2, 1_000, [0xBB; 32]);
        c.insert_header(b).unwrap();
        assert_eq!(c.tip_hash(), a_hash, "ties keep the first-seen tip");
    }
}
