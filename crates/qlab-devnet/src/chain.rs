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

use crate::forms::GenesisForm;
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
    /// Pure derived index of the current fork-choice main chain, genesis to tip.
    /// `blocks` + `tip` remain authoritative. Direct extensions append in O(1);
    /// pre-finality reorgs replace only the suffix after the fork point.
    main_chain_by_height: Vec<Hash32>,
    /// The highest finalized block. Once set, every tip must descend from it.
    finalized: Option<FinalPoint>,
    /// The genesis form this chain's block identities are computed under (lab
    /// #470): a block's hash is `header_hash_for(form)`, so a v5 net's links
    /// (`prev` = the parent's v5 hash) resolve. Set at construction; defaults
    /// to v4 through [`ChainState::new`], so every existing chain is unchanged.
    form: GenesisForm,
}

impl ChainState {
    /// Start a chain from `genesis` (whose `prev` must be all-zero, `height` 0).
    /// **v4 identities** — a v5 net starts via [`ChainState::new_for`].
    pub fn new(genesis: BlockHeader) -> Self {
        Self::new_for(GenesisForm::V4, genesis)
    }

    /// [`ChainState::new`] under an explicit genesis form: every block identity
    /// in this chain is its header hash **under that form**.
    pub fn new_for(form: GenesisForm, genesis: BlockHeader) -> Self {
        assert_eq!(genesis.height, 0, "genesis height must be 0");
        assert_eq!(genesis.prev, [0u8; 32], "genesis prev must be ZERO_HASH");
        let hash = genesis.header_hash_for(form);
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
            main_chain_by_height: vec![hash],
            finalized: None,
            form,
        }
    }

    /// The genesis form this chain's identities are keyed under.
    pub fn form(&self) -> GenesisForm {
        self.form
    }

    /// Re-key a **genesis-only** chain to `form` (lab #470): the one legal
    /// moment is between construction and the first non-genesis insert — the
    /// shape `set_chain_rules` needs, because the adapter builds its chain
    /// before the binary installs the rules. Re-keying a chain that already
    /// carries blocks would silently orphan them, so it panics instead.
    pub fn rekey_genesis(&mut self, form: GenesisForm) {
        if form == self.form {
            return;
        }
        assert!(
            self.blocks.len() == 1 && self.finalized.is_none(),
            "rekey_genesis is only legal on a genesis-only chain (have {} blocks)",
            self.blocks.len()
        );
        let genesis = self.blocks[&self.genesis].header;
        *self = Self::new_for(form, genesis);
    }

    /// Insert a header, linking it to its parent and updating the tip if the new
    /// block extends the heaviest chain **and does not conflict with finality**.
    /// Does NOT check PoW validity — that is the validation layer (棒 1). Returns
    /// the new block's hash on success (a stored-but-not-adopted side block is
    /// still `Ok`).
    pub fn insert_header(&mut self, header: BlockHeader) -> Result<Hash32, InsertError> {
        let hash = header.header_hash_for(self.form);
        if self.blocks.contains_key(&hash) {
            return Err(InsertError::Duplicate);
        }
        let parent = self.blocks.get(&header.prev).ok_or(InsertError::UnknownParent)?;
        if header.height != parent.header.height + 1 {
            return Err(InsertError::BadHeight);
        }
        // Lab #708 Q3: an Annulet block weighs 1 (cumulative weight = height)
        // — its difficulty is 0 by rule, so under the L1 weight its tip would
        // never move. Ties cannot arise there: one signer, and a second sealed
        // header at an occupied height is refused at ingest as equivocation.
        let weight = match self.form {
            GenesisForm::V4 | GenesisForm::V5 => header.difficulty as u128,
            GenesisForm::Annulet => 1,
        };
        let cumulative_work = parent.cumulative_work + weight;
        self.blocks.insert(hash, Entry { header, cumulative_work });

        // Heaviest-chain rule, gated by finality: adopt the new block as tip iff
        // it has strictly more cumulative work than the current tip AND it
        // descends from the finalized head. The finality gate is the load-bearing
        // safety property — no reorg past a finalized checkpoint, EVER, no matter
        // how much work a competing branch carries. Ties keep the incumbent.
        if cumulative_work > self.tip_work() && self.descends_from_finalized(&hash) {
            self.adopt_tip(hash);
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
            self.adopt_tip(hash);
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

    /// Look up the current fork-choice main-chain hash at `height` in O(1).
    pub fn main_chain_hash_at(&self, height: u64) -> Option<Hash32> {
        usize::try_from(height)
            .ok()
            .and_then(|height| self.main_chain_by_height.get(height))
            .copied()
    }

    /// The main chain (heaviest), genesis → tip inclusive, as a Vec of hashes.
    /// Clones the maintained height index; single-height readers should use
    /// [`Self::main_chain_hash_at`] to avoid allocating the whole chain.
    pub fn main_chain(&self) -> Vec<Hash32> {
        self.main_chain_by_height.clone()
    }

    /// Change the fork-choice tip and update only the changed index suffix.
    /// Ordinary connected headers append in O(1). A pre-finality reorg walks the
    /// incoming branch only to its fork point, truncates the losing suffix, then
    /// appends the winning suffix; it never rebuilds tip → genesis.
    fn adopt_tip(&mut self, new_tip: Hash32) {
        let new_header = self.blocks.get(&new_tip).expect("adopted tip is stored").header;
        let new_height = usize::try_from(new_header.height).expect("stored height fits address space");
        if new_header.prev == self.tip && new_height == self.main_chain_by_height.len() {
            self.main_chain_by_height.push(new_tip);
            self.tip = new_tip;
            return;
        }

        let mut cursor = new_tip;
        let mut reversed_suffix = Vec::new();
        let fork_height = loop {
            let header = self.blocks.get(&cursor).expect("main-chain candidate is stored").header;
            let height = usize::try_from(header.height).expect("stored height fits address space");
            if self.main_chain_by_height.get(height).copied() == Some(cursor) {
                break height;
            }
            reversed_suffix.push(cursor);
            assert!(header.height > 0, "every stored branch shares genesis");
            cursor = header.prev;
        };

        self.main_chain_by_height.truncate(fork_height + 1);
        reversed_suffix.reverse();
        self.main_chain_by_height.extend(reversed_suffix);
        self.tip = new_tip;

        assert_eq!(self.main_chain_by_height.last().copied(), Some(new_tip));
        assert_eq!(self.main_chain_by_height.len(), new_height + 1);
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
        assert_eq!(c.main_chain_hash_at(0), Some(g));
        assert_eq!(c.main_chain_hash_at(1), Some(a_hash));
        assert_eq!(c.main_chain_hash_at(2), Some(b_hash));
        assert_eq!(c.main_chain_hash_at(3), None);
    }

    /// QUM-111 widened S5: a pre-finality reorg replaces exactly the losing
    /// suffix in the derived O(1) height index; no stale hash remains addressable.
    #[test]
    fn main_chain_height_index_replaces_the_suffix_on_pre_finality_reorg() {
        let mut c = ChainState::new(genesis());
        let g = c.genesis_block_hash();
        let gh = *c.header(&g).unwrap();

        let a1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32])).unwrap();
        let a1h = *c.header(&a1).unwrap();
        let a2 = c.insert_header(BlockHeader::child_of(&a1h, 4, 1_000, [0xA2; 32])).unwrap();
        let a2h = *c.header(&a2).unwrap();
        let a3 = c.insert_header(BlockHeader::child_of(&a2h, 6, 1_000, [0xA3; 32])).unwrap();
        assert_eq!(c.main_chain(), vec![g, a1, a2, a3]);

        // B remains a side branch until B3 takes the cumulative-work lead.
        let b1 = c.insert_header(BlockHeader::child_of(&gh, 2, 900, [0xB1; 32])).unwrap();
        let b1h = *c.header(&b1).unwrap();
        let b2 = c.insert_header(BlockHeader::child_of(&b1h, 4, 900, [0xB2; 32])).unwrap();
        let b2h = *c.header(&b2).unwrap();
        let b3 = c.insert_header(BlockHeader::child_of(&b2h, 6, 2_000, [0xB3; 32])).unwrap();

        let expected = [g, b1, b2, b3];
        assert_eq!(c.main_chain(), expected);
        for (height, hash) in expected.into_iter().enumerate() {
            assert_eq!(c.main_chain_hash_at(height as u64), Some(hash));
        }
        assert_eq!(c.main_chain_hash_at(4), None);
        assert!(!c.main_chain().contains(&a1));
        assert!(!c.main_chain().contains(&a2));
        assert!(!c.main_chain().contains(&a3));
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

    /// The first finalized checkpoint may re-anchor an out-of-band fork-choice
    /// tip to a known side branch. The derived index follows at that same mutation.
    #[test]
    fn first_finalized_side_branch_reanchors_the_main_chain_height_index() {
        let mut c = ChainState::new(genesis());
        let g = c.genesis_block_hash();
        let gh = *c.header(&g).unwrap();
        let a1 = c.insert_header(BlockHeader::child_of(&gh, 2, 1_000, [0xA1; 32])).unwrap();
        let a1h = *c.header(&a1).unwrap();
        let a2 = c.insert_header(BlockHeader::child_of(&a1h, 4, 1_000, [0xA2; 32])).unwrap();
        let b1 = c.insert_header(BlockHeader::child_of(&gh, 2, 500, [0xB1; 32])).unwrap();
        let b1h = *c.header(&b1).unwrap();
        let b2 = c.insert_header(BlockHeader::child_of(&b1h, 4, 500, [0xB2; 32])).unwrap();
        assert_eq!(c.tip_hash(), a2);

        c.set_finalized(b2).unwrap();
        assert_eq!(c.tip_hash(), b2);
        assert_eq!(c.main_chain(), vec![g, b1, b2]);
        assert_eq!(c.main_chain_hash_at(1), Some(b1));
        assert_eq!(c.main_chain_hash_at(2), Some(b2));
        assert!(!c.main_chain().contains(&a1));
        assert!(!c.main_chain().contains(&a2));
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
