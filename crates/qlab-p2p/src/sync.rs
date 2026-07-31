//! Header-first sync state machine + the locator/serving logic it drives.
//!
//! Shape (Bitcoin headers-first, `[devnet-placeholder]` messages): a node behind
//! its peers sends `GetHeaders(locator)`; the peer answers with a `Headers` batch
//! (ancestor-first) built from the first locator hash on its main chain; the
//! syncing node ingests the batch and, if still behind and the batch was full,
//! requests the next one. Bodies/proofs follow via compact-block relay
//! ([`crate::compact`]) once the header chain is known.
//!
//! ```text
//!   Unknown ──peer taller──▶ AwaitingHeaders ──full batch & still behind──┐
//!      ▲                          │                                       │
//!      │ no peer claims a height  │ short batch, still behind → Behind ───┤
//!      │                          │ caught up                             │
//!      └───────── Synced ◀────────┘◀──────────────────────────────────────┘
//! ```

use qlab_devnet::header::{BlockHeader, Hash32, ZERO_HASH};

use crate::codec::Locator;
use crate::n1::ChainView;
use crate::peer::PeerId;

/// Max headers returned in one `Headers` batch (Bitcoin uses 2000).
pub const MAX_HEADERS_PER_BATCH: usize = 2000;

/// The sync state machine's phase.
///
/// # Why there are two non-syncing phases (issue #106)
///
/// This enum used to carry a single `Idle` documented as *"either caught up or no
/// taller peer known yet"* — one variant for two states that differ by everything
/// that matters. **A node that has heard from nobody is not a node that is caught
/// up**, and until this split there was no way to say so: a process cold-started
/// on an empty data dir sat in the same variant a fully-synced node sits in, so
/// anything asking "am I at the network's height?" was answered *yes* on the
/// strength of zero evidence. That is how node0 mined a genesis fork through a
/// restart on the T0 WAN net — the mining gate had no sync condition to read
/// because there was no honest one to read.
///
/// The three non-`AwaitingHeaders` states are now distinct facts:
///
/// - [`SyncPhase::Unknown`] — no ready peer has claimed a height. **Nothing is
///   known**, and in particular "caught up" is not knowable.
/// - [`SyncPhase::Behind`] — a peer's claim was received and we are below it, with
///   no request outstanding (the last batch fell short or did not connect).
/// - [`SyncPhase::Synced`] — we compared our tip against a claim we actually
///   received and are not below it.
///
/// The distinction lives here, on the state machine that owns it, rather than as a
/// second concept beside it: a caller that needs "does this node know where the
/// chain is" reads the phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncPhase {
    /// No ready peer has claimed a height yet, so this node does not know whether
    /// it is caught up. The phase every process starts in, and the phase it
    /// returns to when it has no peer left to ask.
    Unknown,
    /// A `GetHeaders` is outstanding to `peer`, expecting a batch building on our
    /// tip height `from_height`.
    AwaitingHeaders { peer: PeerId, from_height: u64 },
    /// Below the best height a ready peer claimed, with no request outstanding —
    /// the next pass re-anchors and asks again.
    Behind,
    /// Caught up to the best height a ready peer claimed. Reaching this phase
    /// requires a claim to have been received: it is never asserted about a net
    /// this node has not spoken to.
    Synced,
}

impl SyncPhase {
    /// Whether this node has positive evidence that it is at the network's height.
    ///
    /// True for exactly one variant, and that is the point — see the type's note.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncPhase::Synced)
    }
}

/// Holds the current phase.
#[derive(Clone, Debug)]
pub struct SyncState {
    pub phase: SyncPhase,
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState { phase: SyncPhase::Unknown }
    }
}

impl SyncState {
    pub fn new() -> Self {
        SyncState::default()
    }

    /// Whether a `GetHeaders` is currently outstanding.
    pub fn awaiting(&self) -> bool {
        matches!(self.phase, SyncPhase::AwaitingHeaders { .. })
    }
}

/// Build a block locator from our main chain: dense near the tip, then
/// exponentially sparser toward genesis, always ending at genesis. Lets a peer
/// find our highest common ancestor in O(log height) hashes.
pub fn build_locator(view: &dyn ChainView) -> Locator {
    let tip_height = view.tip_height();
    let mut have = Vec::new();
    let mut height = tip_height as i128;
    let mut step: i128 = 1;
    let mut added = 0;
    while height > 0 {
        if let Some(h) = view.main_chain_hash_at(height as u64) {
            have.push(h);
        }
        added += 1;
        if added >= 10 {
            step *= 2; // start doubling the gap after the first 10
        }
        height -= step;
    }
    // Always finish with genesis so there is always a common ancestor.
    have.push(view.genesis_hash());
    Locator { have, stop: ZERO_HASH }
}

/// Answer a `GetHeaders`: find the highest locator hash that is on our main
/// chain (fall back to genesis), then return up to `max` main-chain headers
/// after it, ancestor-first, stopping at the locator's `stop` hash if reached.
pub fn answer_get_headers(view: &dyn ChainView, loc: &Locator, max: usize) -> Vec<BlockHeader> {
    // Highest main-chain height among the locator's `have` hashes.
    let mut start_height = 0u64;
    for h in &loc.have {
        if let Some(height) = main_chain_height_of(view, h) {
            start_height = start_height.max(height);
        }
    }
    let tip = view.tip_height();
    let mut out = Vec::new();
    let mut height = start_height + 1;
    while height <= tip && out.len() < max {
        match view.main_chain_hash_at(height) {
            Some(h) => {
                if let Some(hdr) = view.header(&h) {
                    out.push(hdr);
                }
                if loc.stop != ZERO_HASH && h == loc.stop {
                    break;
                }
            }
            None => break,
        }
        height += 1;
    }
    out
}

/// Height of `hash` iff it is on the current main chain (else `None`).
fn main_chain_height_of(view: &dyn ChainView, hash: &Hash32) -> Option<u64> {
    let hdr = view.header(hash)?;
    // On the main chain iff the main-chain hash at that height equals it.
    if view.main_chain_hash_at(hdr.height) == Some(*hash) {
        Some(hdr.height)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1::StubNode;
    use qlab_devnet::committee::{devnet_committee, CommitteeState};
    use qlab_devnet::params_devnet::BOND_AMOUNT;

    /// Build a StubNode with a linear main chain of `n` blocks past genesis.
    fn chain_node(n: u64) -> StubNode {
        let (committee, _v) = devnet_committee(7);
        let g = BlockHeader::genesis(1000, 0);
        let mut node = StubNode::new(g, CommitteeState::new(committee, BOND_AMOUNT));
        let mut parent = g;
        for i in 0..n {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i + 1) as u8; 32]);
            crate::n1::BlockIngest::ingest_header(&mut node, child);
            parent = child;
        }
        node
    }

    #[test]
    fn locator_is_dense_then_sparse_and_ends_at_genesis() {
        let node = chain_node(50);
        let loc = build_locator(&node);
        // First entry is the tip; last is genesis.
        assert_eq!(loc.have.first().copied(), node.main_chain_hash_at(50));
        assert_eq!(loc.have.last().copied(), Some(node.genesis_hash()));
        // Far fewer than 50 entries thanks to exponential back-off.
        assert!(loc.have.len() < 25, "locator has {} entries", loc.have.len());
    }

    #[test]
    fn answer_returns_headers_after_common_ancestor() {
        let server = chain_node(20);
        // A syncing node that only has genesis builds a locator = [genesis].
        let behind = chain_node(0);
        let loc = build_locator(&behind);
        let batch = answer_get_headers(&server, &loc, MAX_HEADERS_PER_BATCH);
        assert_eq!(batch.len(), 20);
        assert_eq!(batch[0].height, 1);
        assert_eq!(batch[19].height, 20);
    }

    #[test]
    fn answer_respects_max_batch() {
        let server = chain_node(20);
        let behind = chain_node(0);
        let loc = build_locator(&behind);
        let batch = answer_get_headers(&server, &loc, 5);
        assert_eq!(batch.len(), 5);
        assert_eq!(batch[0].height, 1);
        assert_eq!(batch[4].height, 5);
    }

    #[test]
    fn answer_from_partial_locator_continues_after_ancestor() {
        let server = chain_node(20);
        let behind = chain_node(8); // shares blocks 1..=8
        let loc = build_locator(&behind);
        let batch = answer_get_headers(&server, &loc, MAX_HEADERS_PER_BATCH);
        assert_eq!(batch.first().map(|h| h.height), Some(9));
        assert_eq!(batch.last().map(|h| h.height), Some(20));
    }
}
