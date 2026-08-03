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

/// Why marking a block as finalized was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeMarkError {
    /// The block hash is not in the store.
    Unknown,
    /// The block does not descend from the current finalized head (would be a
    /// reorg past finality — forbidden).
    NotDescendantOfFinalized,
    /// The block's height does not strictly advance the finalized head.
    NotAdvancing,
}

/// Why reinstating a previously-established finalized head was refused.
///
/// This is deliberately separate from [`FinalizeMarkError`]. A live finalization
/// must strictly advance from the current head; recovery instead proves that one
/// exact point already belongs to the reconstructed main chain, then reinstates
/// it without pretending a new quorum event happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreFinalizedError {
    /// The snapshot names a block absent from the reconstructed store.
    Unknown,
    /// The snapshot's redundant height does not match the stored header.
    HeightMismatch { snapshot: u64, stored: u64 },
    /// The block is known, but is not on the reconstructed main chain.
    NotOnMainChain,
}

/// A finalized point: the block hash and its height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FinalPoint {
    hash: Hash32,
    height: u64,
}

/// The devnet chain state: all known blocks keyed by header hash, the tip
/// (heaviest-chain head), and the finalized head (below which fork choice can
/// never reorg — consensus §4/§6).
#[derive(Clone, Debug)]
pub struct ChainState {
    blocks: HashMap<Hash32, Entry>,
    genesis: Hash32,
    tip: Hash32,
    /// The highest finalized block. Once set, every tip must descend from it.
    finalized: Option<FinalPoint>,
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
            finalized: None,
        }
    }

    /// Insert a header, linking it to its parent and updating the tip if the new
    /// block extends the heaviest chain **and does not conflict with finality**.
    /// Does NOT check PoW validity — that is the validation layer (棒 1). Returns
    /// the new block's hash on success (a stored-but-not-adopted side block is
    /// still `Ok`).
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

        // Heaviest-chain rule, gated by finality: adopt the new block as tip iff
        // it has strictly more cumulative work than the current tip AND it
        // descends from the finalized head. The finality gate is the load-bearing
        // safety property — no reorg past a finalized checkpoint, EVER, no matter
        // how much work a competing branch carries. Ties keep the incumbent.
        if cumulative_work > self.tip_work() && self.descends_from_finalized(&hash) {
            self.tip = hash;
        }
        Ok(hash)
    }

    /// Mark `hash` as the new finalized head. It must be known, strictly higher
    /// than the current finalized head, and descend from it. On success, if the
    /// current tip no longer descends from finality (only possible via out-of-band
    /// misuse), the tip is re-anchored to the finalized block.
    pub fn set_finalized(&mut self, hash: Hash32) -> Result<(), FinalizeMarkError> {
        let height = self.blocks.get(&hash).ok_or(FinalizeMarkError::Unknown)?.header.height;
        if let Some(cur) = self.finalized {
            if height <= cur.height {
                return Err(FinalizeMarkError::NotAdvancing);
            }
            // The new finalized block must descend from the old one.
            if !self.is_descendant_of(&hash, &cur.hash, cur.height) {
                return Err(FinalizeMarkError::NotDescendantOfFinalized);
            }
        }
        self.finalized = Some(FinalPoint { hash, height });
        if !self.descends_from_finalized(&self.tip) {
            self.tip = hash;
        }
        Ok(())
    }

    /// Reinstate a finalized point recorded by a durable snapshot.
    ///
    /// Recovery is not a live finalization: no votes are being judged and there
    /// is no prior in-memory head to advance from. The persisted point is accepted
    /// only when its block exists at the stated height and is an ancestor of the
    /// reconstructed tip. That proof preserves the no-reorg-past-finality invariant
    /// while keeping the operation visibly distinct from [`Self::set_finalized`].
    pub fn restore_finalized(
        &mut self,
        hash: Hash32,
        snapshot_height: u64,
    ) -> Result<(), RestoreFinalizedError> {
        let stored_height = self
            .blocks
            .get(&hash)
            .ok_or(RestoreFinalizedError::Unknown)?
            .header
            .height;
        if stored_height != snapshot_height {
            return Err(RestoreFinalizedError::HeightMismatch {
                snapshot: snapshot_height,
                stored: stored_height,
            });
        }
        if !self.is_descendant_of(&self.tip, &hash, snapshot_height) {
            return Err(RestoreFinalizedError::NotOnMainChain);
        }
        self.finalized = Some(FinalPoint { hash, height: snapshot_height });
        Ok(())
    }

    /// The finalized head hash, if any.
    pub fn finalized_hash(&self) -> Option<Hash32> {
        self.finalized.map(|f| f.hash)
    }

    /// The finalized head height, if any.
    pub fn finalized_height(&self) -> Option<u64> {
        self.finalized.map(|f| f.height)
    }

    /// Whether `block_hash` descends from (or equals) the finalized head. Always
    /// `true` when nothing is finalized yet.
    pub fn descends_from_finalized(&self, block_hash: &Hash32) -> bool {
        match self.finalized {
            None => true,
            Some(f) => self.is_descendant_of(block_hash, &f.hash, f.height),
        }
    }

    /// Whether `descendant` is at or below `ancestor` on the same chain — i.e.
    /// walking back from `descendant` to `ancestor_height` lands on `ancestor`.
    pub fn is_descendant_of(&self, descendant: &Hash32, ancestor: &Hash32, ancestor_height: u64) -> bool {
        let Some(entry) = self.blocks.get(descendant) else {
            return false;
        };
        if entry.header.height < ancestor_height {
            return false;
        }
        self.ancestor(descendant, entry.header.height - ancestor_height) == Some(*ancestor)
    }

    /// The genesis **block header** hash — `keccak256` over the height-0
    /// `BlockHeader`, i.e. the root of this chain's header DAG.
    ///
    /// 🔴 Not the operational "genesis hash" (issue #206). That one is
    /// `qumbra_node::genesis::GenesisFile::hash()` — `keccak256` over the whole
    /// genesis **file** (network name, FROZEN v1.0 params, the 21 committee
    /// keys, and the genesis block) — and it is what `genesis init` prints, what
    /// `expected_genesis_hash` pins, and what `qumbra-deploy/OPERATOR.md`
    /// quotes. The file contains the block, so the two values always differ;
    /// comparing them proves nothing. Named `genesis_hash` before #206.
    pub fn genesis_block_hash(&self) -> Hash32 {
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
        assert_eq!(c.tip_hash(), c.genesis_block_hash());
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
        let g = c.genesis_block_hash();
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
        let g = c.genesis_block_hash();
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

    /// THE load-bearing safety property (consensus §4/§6): once a checkpoint is
    /// finalized, no competing branch — however much PoW work it carries — can
    /// ever reorg the tip past it.
    #[test]
    fn no_reorg_past_finalized_checkpoint_ever() {
        let mut c = ChainState::new(genesis()); // difficulty 1_000
        let gh = *c.header(&c.genesis_block_hash()).unwrap();

        // Main branch A: A1, A2, A3 (each difficulty 1_000).
        let a1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32])).unwrap();
        let a1h = *c.header(&a1).unwrap();
        let a2 = c.insert_header(BlockHeader::child_of(&a1h, 4, 1_000, [0xA2; 32])).unwrap();
        let a2h = *c.header(&a2).unwrap();
        let a3 = c.insert_header(BlockHeader::child_of(&a2h, 6, 1_000, [0xA3; 32])).unwrap();
        assert_eq!(c.tip_hash(), a3);

        // Finalize A2 (height 2).
        c.set_finalized(a2).unwrap();
        assert_eq!(c.finalized_height(), Some(2));

        // A competing fork B from GENESIS carrying astronomically more work, but
        // NOT containing A2. It must never become the tip.
        let b1 = c.insert_header(BlockHeader::child_of(&gh, 2, 10_000_000, [0xB1; 32])).unwrap();
        assert!(!c.descends_from_finalized(&b1));
        assert_eq!(c.tip_hash(), a3, "must NOT reorg past finalized A2, despite B1's work");

        // Extend B further — still never adopted, at any work.
        let b1h = *c.header(&b1).unwrap();
        let b2 = c.insert_header(BlockHeader::child_of(&b1h, 4, 10_000_000, [0xB2; 32])).unwrap();
        assert_eq!(c.tip_hash(), a3, "still no reorg past finality");
        assert!(!c.descends_from_finalized(&b2));

        // Meanwhile the finalized branch keeps growing normally.
        let a3h = *c.header(&a3).unwrap();
        let a4 = c.insert_header(BlockHeader::child_of(&a3h, 8, 1_000, [0xA4; 32])).unwrap();
        assert_eq!(c.tip_hash(), a4);
        assert!(c.descends_from_finalized(&a4));
    }

    #[test]
    fn set_finalized_enforces_advance_and_descent() {
        let mut c = ChainState::new(genesis());
        let gh = *c.header(&c.genesis_block_hash()).unwrap();
        // Unknown block.
        assert_eq!(c.set_finalized([0xEE; 32]), Err(FinalizeMarkError::Unknown));

        // Build A1, A2 and a competing B1, B2 (from genesis, distinct bodies).
        let a1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32])).unwrap();
        let a1h = *c.header(&a1).unwrap();
        let a2 = c.insert_header(BlockHeader::child_of(&a1h, 4, 1_000, [0xA2; 32])).unwrap();
        let b1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xB1; 32])).unwrap();
        let b1h = *c.header(&b1).unwrap();
        let b2 = c.insert_header(BlockHeader::child_of(&b1h, 4, 1_000, [0xB2; 32])).unwrap();

        c.set_finalized(a2).unwrap();
        // Not advancing: A1 is below the finalized height.
        assert_eq!(c.set_finalized(a1), Err(FinalizeMarkError::NotAdvancing));
        // Advancing height but on a different branch (B2 at height 2 == finalized
        // height, so NotAdvancing first); build B3 (height 3) to test descent.
        let b2h = *c.header(&b2).unwrap();
        let b3 = c.insert_header(BlockHeader::child_of(&b2h, 6, 1_000, [0xB3; 32])).unwrap();
        assert_eq!(c.set_finalized(b3), Err(FinalizeMarkError::NotDescendantOfFinalized));
    }

    #[test]
    fn restore_finalized_proves_the_persisted_point_against_the_main_chain() {
        let mut c = ChainState::new(genesis());
        let gh = *c.header(&c.genesis_block_hash()).unwrap();
        let a1 = c
            .insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32]))
            .unwrap();

        c.restore_finalized(a1, 1).unwrap();
        assert_eq!(c.finalized_hash(), Some(a1));
        assert_eq!(c.finalized_height(), Some(1));

        assert_eq!(
            c.restore_finalized([0xEE; 32], 1),
            Err(RestoreFinalizedError::Unknown)
        );
        assert_eq!(
            c.restore_finalized(a1, 2),
            Err(RestoreFinalizedError::HeightMismatch {
                snapshot: 2,
                stored: 1,
            })
        );

        // A known sibling is not the point the reconstructed tip descends from.
        let sibling = c
            .insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xB1; 32]))
            .unwrap();
        assert_eq!(
            c.restore_finalized(sibling, 1),
            Err(RestoreFinalizedError::NotOnMainChain)
        );
    }
}
