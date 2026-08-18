//! The block ticker's data: `GET /v1/blocks?from=&to=` (lab #486 scope items
//! 1 + 3 — the live ticker, and the difficulty / block-interval charts).
//!
//! ```text
//!   stored blocks ──▶ BlocksView ──▶ page(from,to) ──▶ json ──▶ GET /v1/blocks
//! ```
//!
//! Per block, the consensus-public header facts plus two body facts: height,
//! block hash, timestamp, difficulty, body commitment, transaction count, and the
//! committed coinbase value. **No server-side chart data**: the difficulty chart
//! and the block-interval distribution are client-computed from `difficulty` and
//! consecutive `timestamp` deltas, and implied hashrate is presentation
//! (difficulty ÷ target interval), computed page-side and labelled as implied —
//! no ring, no projection beyond this list (stage-0 R1).
//!
//! # Memory, stated against #135
//!
//! Unlike `txlist`'s sparse list this view is **dense** — one entry per applied
//! main-chain height — so it grows with the chain: ~100 B per height beside the
//! multi-KB `StoredBlock` the node already retains for every one of those heights
//! (`store.rs` never prunes). That is a small constant fraction of state the
//! process already holds, not a new unbounded class; the *serving* bound is
//! per-page ([`MAX_BLOCKS_HEIGHTS`]), the same shape as every range route here.
//!
//! # The contract it inherits
//!
//! Range/bulk-served only, explicit coverage, one paging rule
//! ([`crate::txlist::next_from_coverage`]). Coverage has teeth on a dense
//! surface too: `covered_to` asserts every height in `[from, covered_to]` is
//! **listed**, so a store gap surfaces as short coverage rather than as a hole a
//! chart would silently interpolate across.

use std::sync::{Arc, Mutex};

use qlab_node::{ChainStore, Hash32, StoredBlock};

use crate::json::num;
use crate::txlist::{hex32, next_from_coverage, Next};

/// The document's own version — its own integer, the standing json.rs argument.
pub const BLOCKS_VERSION: u32 = 1;

/// The most heights one page will carry — the txlist bound, same number, same
/// reasons; ~200 B per block ⇒ ~200 KB worst-case page. `[devnet-placeholder]`,
/// testnet-tunable, NOT frozen.
pub const MAX_BLOCKS_HEIGHTS: u64 = 1024;

/// One block's public facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    pub height: u64,
    /// The block's own hash — full, like `txlist`'s txids: a primary key a
    /// reader cross-references, not an identity *display* field (those are the
    /// 12-hex `fid`/`dfinbh` discipline, which this is deliberately not).
    pub block_hash: Hash32,
    pub timestamp: u64,
    pub difficulty: u64,
    pub body_commitment: Hash32,
    /// Transactions in the block — the coinbase is not one (txlist's rule).
    pub txs: u32,
    /// The committed coinbase value, in bessel. Post-19,008 this is the value
    /// net of name burn, which is what makes the supply story per-block-visible.
    pub coinbase: u64,
}

impl BlockFacts {
    /// Project one stored block. `hash` is the store's own key for it — the walk
    /// already holds it, so nothing is re-hashed here.
    pub fn of(hash: &Hash32, b: &StoredBlock) -> BlockFacts {
        BlockFacts {
            height: b.header.height,
            block_hash: *hash,
            timestamp: b.header.timestamp,
            difficulty: b.header.difficulty,
            body_commitment: b.header.tx_body_commitment,
            txs: b.txs.len() as u32,
            coinbase: b.coinbase,
        }
    }
}

/// The main chain's per-height facts as of the run loop's last refresh — the
/// snapshot discipline, walk and splice rule of [`crate::txlist::TxListView`]
/// (see its `refresh` docs; the rule is the same and not restated).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlocksView {
    /// Ascending by height, dense over what the store could answer for.
    pub blocks: Vec<BlockFacts>,
    pub tip_height: u64,
    pub tip_hash: Option<Hash32>,
}

impl BlocksView {
    /// Re-project from a node's main chain. Returns whether anything changed.
    pub fn refresh<C: ChainStore>(&mut self, chain: &C) -> bool {
        let tip = chain.tip_hash();
        if self.tip_hash == Some(tip) {
            return false;
        }
        let anchor = self.tip_hash;
        let mut fresh: Vec<BlockFacts> = Vec::new();
        let mut hash = tip;
        let mut tip_height = None;
        let mut lowest_walked = None;
        loop {
            let Some(block) = chain.block(&hash) else { break };
            let height = block.header.height;
            if tip_height.is_none() {
                tip_height = Some(height);
            }
            lowest_walked = Some(height);
            fresh.push(BlockFacts::of(&hash, block));
            if height == 0 {
                break;
            }
            let prev = block.header.prev;
            if Some(prev) == anchor {
                break;
            }
            hash = prev;
        }
        let (Some(tip_height), Some(lowest_walked)) = (tip_height, lowest_walked) else {
            return false;
        };
        fresh.reverse();
        self.blocks.retain(|b| b.height < lowest_walked);
        self.blocks.extend(fresh);
        self.tip_height = tip_height;
        self.tip_hash = Some(tip);
        true
    }
}

/// Re-project the shared snapshot if the chain moved — the `txlist` seam.
pub fn refresh_shared<C: ChainStore>(slot: &Mutex<Arc<BlocksView>>, chain: &C) -> bool {
    let current = match slot.lock() {
        Ok(g) => Arc::clone(&g),
        Err(p) => Arc::clone(&p.into_inner()),
    };
    if current.tip_hash == Some(chain.tip_hash()) {
        return false;
    }
    let mut next = (*current).clone();
    if !next.refresh(chain) {
        return false;
    }
    match slot.lock() {
        Ok(mut g) => *g = Arc::new(next),
        Err(p) => *p.into_inner() = Arc::new(next),
    }
    true
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

/// One `/v1/blocks?from=&to=` answer. `covered_to` asserts every height in
/// `[from, covered_to]` is **listed** — dense, so a store gap shortens coverage
/// instead of leaving a hole; `None` = the page describes no height (`from`
/// past the tip), never "no blocks".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlocksPage {
    pub from: u64,
    pub to: u64,
    pub tip_height: u64,
    pub covered_to: Option<u64>,
    pub blocks: Vec<BlockFacts>,
}

/// Build the page for `[from, to]` over a projection.
pub fn page(view: &BlocksView, from: u64, to: u64) -> BlocksPage {
    let ceiling = to.min(view.tip_height);
    if from > ceiling {
        return BlocksPage { from, to, tip_height: view.tip_height, covered_to: None, blocks: Vec::new() };
    }
    let scan_to = ceiling.min(from.saturating_add(MAX_BLOCKS_HEIGHTS - 1));
    // Dense invariant, enforced while emitting: coverage advances exactly as far
    // as the listed heights are consecutive from `from`. A height the view cannot
    // answer for ends the page BELOW it — short coverage, never a hole.
    let start = view.blocks.partition_point(|b| b.height < from);
    let mut blocks: Vec<BlockFacts> = Vec::new();
    let mut expected = from;
    for b in &view.blocks[start..] {
        if b.height > scan_to || b.height != expected {
            break;
        }
        blocks.push(b.clone());
        expected += 1;
    }
    let covered_to = if expected > from {
        Some(expected - 1) // every height in [from, expected-1] is listed
    } else if from > 0 {
        // Nothing listed: the view could not answer for `from` itself. Coverage
        // below the request is the named client refusal (`Next::Stalled`) — the
        // honest verdict when this server genuinely cannot describe the range.
        Some(from - 1)
    } else {
        // `from == 0` unanswerable (unreachable from an observer that applied
        // genesis): there is no "below the request" to point at, and fabricating
        // coverage of height 0 would be a lie — so the page describes no height.
        None
    };
    BlocksPage { from, to, tip_height: view.tip_height, covered_to, blocks }
}

/// The paging rule — delegated whole to the shared implementation.
pub fn next_after(p: &BlocksPage, requested_to: u64) -> Next {
    next_from_coverage(p.from, p.covered_to, p.tip_height, requested_to)
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Serialize one page — hand-rolled, zero new runtime dependencies, the
/// `crate::json` posture.
pub fn document(p: &BlocksPage) -> String {
    let blocks: Vec<String> = p
        .blocks
        .iter()
        .map(|b| {
            format!(
                "{{\"height\":{h},\"block_hash\":\"{bh}\",\"timestamp\":{ts},\
                 \"difficulty\":{d},\"body_commitment\":\"{bc}\",\"txs\":{txs},\
                 \"coinbase\":{cb}}}",
                h = b.height,
                bh = hex32(&b.block_hash),
                ts = b.timestamp,
                d = b.difficulty,
                bc = hex32(&b.body_commitment),
                txs = b.txs,
                cb = b.coinbase,
            )
        })
        .collect();
    format!(
        "{{\"v\":{BLOCKS_VERSION},\
         \"tip_height\":{tip},\
         \"range\":{{\"from\":{from},\"to\":{to},\"covered_to\":{covered}}},\
         \"blocks\":[{blocks}]}}",
        tip = p.tip_height,
        from = p.from,
        to = p.to,
        covered = num(p.covered_to),
        blocks = blocks.join(","),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::{StoredHeader, StoredTx};

    fn h32(first: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = first;
        h
    }

    fn stored_tx(seed: u8) -> StoredTx {
        StoredTx {
            anchor: h32(seed),
            nullifiers: vec![h32(seed ^ 0x40), h32(seed ^ 0x41)],
            commitments: vec![h32(seed ^ 0x80), h32(seed ^ 0x81)],
            bucket_actions: 2,
            fee: 1_000_000,
            proof: vec![seed; 32],
            discovery: vec![0xdd; 16],
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        }
    }

    fn stored_block(height: u64, txs: Vec<StoredTx>) -> qlab_node::StoredBlock {
        qlab_node::StoredBlock {
            header: StoredHeader {
                prev: h32(height.saturating_sub(1) as u8),
                height,
                timestamp: 1_000 + height * 75,
                difficulty: 2_800 + height,
                nonce: 0,
                tx_body_commitment: h32(0xcc),
            },
            txs,
            coinbase: 5_000_000_000 - height,
            coinbase_rkm: [0; 4],
        }
    }

    /// A dense synthetic view over `0..=tip`, hashes keyed by height.
    fn dense_view(tip: u64) -> BlocksView {
        BlocksView {
            blocks: (0..=tip)
                .map(|h| BlockFacts::of(&h32(h as u8), &stored_block(h, if h % 3 == 0 { vec![stored_tx(h as u8)] } else { vec![] })))
                .collect(),
            tip_height: tip,
            tip_hash: Some(h32(0xfe)),
        }
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    // ---- the facts -------------------------------------------------------------

    /// Every field is the stored block's own — projected, never recomputed.
    #[test]
    fn the_facts_are_the_stored_blocks_own() {
        let b = stored_block(7, vec![stored_tx(1), stored_tx(2)]);
        let hash = h32(0x77);
        let f = BlockFacts::of(&hash, &b);
        assert_eq!(f.height, 7);
        assert_eq!(f.block_hash, hash);
        assert_eq!(f.timestamp, b.header.timestamp);
        assert_eq!(f.difficulty, b.header.difficulty);
        assert_eq!(f.body_commitment, b.header.tx_body_commitment);
        assert_eq!(f.txs, 2, "the coinbase is not a transaction");
        assert_eq!(f.coinbase, b.coinbase);
    }

    // ---- the projection ---------------------------------------------------------

    #[test]
    fn refresh_projects_a_dense_chain_and_extends_without_duplicating() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let mut view = BlocksView::default();
        assert!(view.refresh(&chain), "first projection");
        assert_eq!(view.blocks.len(), 1, "genesis is a block too");
        assert!(!view.refresh(&chain), "unchanged tip does no work");

        let mut prev = chain.tip_hash();
        for h in 1..=4u64 {
            let mut b = stored_block(h, if h == 2 { vec![stored_tx(2)] } else { vec![] });
            b.header.prev = prev;
            prev = chain.put_block(b).expect("link");
        }
        assert!(view.refresh(&chain));
        assert_eq!(view.tip_height, 4);
        assert_eq!(
            view.blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4],
            "dense, ascending, nothing duplicated"
        );
        assert_eq!(view.blocks[2].txs, 1, "the tx block carries its count");
        // And the stored hash is the store's own key for that block.
        assert_eq!(chain.block(&view.blocks[4].block_hash).unwrap().header.height, 4);
    }

    /// A reorg replaces the suffix — the abandoned branch's facts leave the list.
    #[test]
    fn a_reorg_replaces_the_suffix() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let genesis = chain.tip_hash();
        let mut a1 = stored_block(1, vec![]);
        a1.header.prev = genesis;
        a1.header.nonce = 1;
        chain.put_block(a1).expect("link");
        let mut view = BlocksView::default();
        view.refresh(&chain);
        let abandoned = view.blocks[1].block_hash;

        let mut b1 = stored_block(1, vec![]);
        b1.header.prev = genesis;
        b1.header.difficulty = 100_000;
        b1.header.nonce = 7;
        let b1h = chain.put_block(b1).expect("link");
        let mut b2 = stored_block(2, vec![]);
        b2.header.prev = b1h;
        b2.header.difficulty = 100_000;
        chain.put_block(b2).expect("link");

        assert!(view.refresh(&chain));
        assert_eq!(view.blocks.len(), 3);
        assert!(view.blocks.iter().all(|b| b.block_hash != abandoned));
    }

    #[test]
    fn the_shared_slot_swaps_only_when_the_chain_moved() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let slot = Mutex::new(Arc::new(BlocksView::default()));
        assert!(refresh_shared(&slot, &chain));
        assert!(!refresh_shared(&slot, &chain));
        let mut b1 = stored_block(1, vec![]);
        b1.header.prev = chain.tip_hash();
        chain.put_block(b1).expect("link");
        assert!(refresh_shared(&slot, &chain));
        assert_eq!(slot.lock().unwrap().blocks.len(), 2);
    }

    // ---- coverage on a dense surface ---------------------------------------------

    /// The ordinary page: dense, clamped to the tip, chart-ready.
    #[test]
    fn a_page_is_dense_over_its_covered_range_and_clamps_to_the_tip() {
        let view = dense_view(50);
        let p = page(&view, 40, u64::MAX);
        assert_eq!(p.covered_to, Some(50), "clamped to the tip");
        assert_eq!(
            p.blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            (40..=50).collect::<Vec<_>>(),
            "every height in the covered range is listed — dense"
        );
        assert_eq!(next_after(&p, u64::MAX), Next::Done);
    }

    #[test]
    fn the_scan_bound_binds_and_a_client_pages_through() {
        let view = dense_view(3000);
        let p = page(&view, 0, 3000);
        assert_eq!(p.blocks.len(), MAX_BLOCKS_HEIGHTS as usize);
        assert_eq!(p.covered_to, Some(MAX_BLOCKS_HEIGHTS - 1));
        assert_eq!(next_after(&p, 3000), Next::Fetch(MAX_BLOCKS_HEIGHTS));
    }

    #[test]
    fn past_the_tip_is_no_coverage() {
        let view = dense_view(10);
        let p = page(&view, 20, 30);
        assert_eq!(p.covered_to, None);
        assert!(p.blocks.is_empty());
        assert_eq!(next_after(&p, 30), Next::NoCoverage);
    }

    /// 🔴 A gap in the view must SHORTEN coverage, never leave a hole a chart
    /// would interpolate across — the dense surface's version of
    /// truncation-reads-as-complete.
    #[test]
    fn a_gap_in_the_view_shortens_coverage_and_never_leaves_a_hole() {
        let mut view = dense_view(50);
        view.blocks.retain(|b| b.height != 45); // inject the gap
        let p = page(&view, 40, 50);
        assert_eq!(p.covered_to, Some(44), "coverage stops below the gap");
        assert_eq!(
            p.blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            (40..=44).collect::<Vec<_>>()
        );
        // And a view that cannot answer for `from` itself stalls the client by
        // name rather than fabricating an empty success.
        let p2 = page(&view, 45, 50);
        assert_eq!(p2.covered_to, Some(44), "coverage below the request");
        assert!(p2.blocks.is_empty());
        assert_eq!(next_after(&p2, 50), Next::Stalled { at: 45 });
    }

    // ---- the document -------------------------------------------------------------

    #[test]
    fn the_document_is_versioned_json_with_full_hashes() {
        let view = dense_view(6);
        let p = page(&view, 5, 6);
        let s = document(&p);
        let v = parse(&s);
        assert_eq!(v["v"], BLOCKS_VERSION);
        assert_eq!(v["tip_height"], 6);
        assert_eq!(v["range"]["covered_to"], 6);
        let b = &v["blocks"][0];
        assert_eq!(b["height"], 5);
        assert_eq!(b["block_hash"].as_str().unwrap().len(), 64, "full hash, txid discipline");
        assert_eq!(b["body_commitment"].as_str().unwrap().len(), 64);
        assert_eq!(b["timestamp"], 1_000 + 5 * 75);
        assert_eq!(b["difficulty"], 2_805);
        assert_eq!(b["coinbase"], 4_999_999_995u64);
    }

    #[test]
    fn absent_coverage_is_null_on_the_wire() {
        let view = dense_view(10);
        let v = parse(&document(&page(&view, 20, 30)));
        assert!(v["range"]["covered_to"].is_null());
    }

    /// The wall, pinned on this surface too: header facts and counts only.
    #[test]
    fn the_document_carries_no_amount_address_or_party_key() {
        let view = dense_view(6);
        let s = document(&page(&view, 0, 6));
        for forbidden in [
            "amount", "address", "recipient", "sender", "balance", "note", "memo", "payload",
            "proof", "anchor", "nullifier", "commitments",
        ] {
            assert!(!s.contains(forbidden), "`{forbidden}` must not appear: {s}");
        }
    }

    // ---- goldens -------------------------------------------------------------------

    const GOLDEN_DIGEST: &str =
        "f60f360b491d594613c786c1adee3154451b6b8fb274100a0919f91c2fe5da37";

    /// The two states the front end renders: the recent tail a ticker reads, and
    /// a request past the tip. (An "empty covered range" golden does not exist
    /// for this surface and cannot: the surface is dense — every covered height
    /// IS a block. Stated so its absence reads as a choice.)
    fn golden_cases() -> Vec<(&'static str, String)> {
        let view = dense_view(60);
        vec![
            ("blocks-recent", document(&page(&view, 49, 60))),
            ("blocks-no-coverage", document(&page(&view, 9_000, 9_100))),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors (see txlist's golden docs;
    /// same discipline, same regeneration asymmetry).
    #[test]
    fn golden_files_match_the_encoder_byte_for_byte() {
        for (name, produced) in golden_cases() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens").join(name);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("golden {name} missing at {}: {e}", path.display()));
            assert_eq!(
                on_disk.trim_end_matches('\n'),
                produced,
                "golden {name} drifted — see this test's docs before updating the file"
            );
        }
    }

    #[test]
    fn the_goldens_decode_and_state_coverage() {
        for (name, produced) in golden_cases() {
            let v = parse(&produced);
            assert_eq!(v["v"], BLOCKS_VERSION, "{name} is versioned");
            assert!(v["range"].get("covered_to").is_some(), "{name} states coverage");
        }
    }

    #[test]
    #[ignore = "writes files; run explicitly when a shape change is intended"]
    fn regenerate_goldens() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens");
        std::fs::create_dir_all(&dir).expect("goldens dir");
        for (name, produced) in golden_cases() {
            std::fs::write(dir.join(name), format!("{produced}\n")).expect("write golden");
            println!("wrote {name}");
        }
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let hex: String =
            qlab_note::hash::keccak256(all.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN_DIGEST = \"{hex}\"");
    }

    #[test]
    fn golden_digest_locks_the_regenerated_files() {
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let digest = qlab_note::hash::keccak256(all.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, GOLDEN_DIGEST,
            "GOLDEN digest — update ONLY with an intentional, documented shape change"
        );
    }
}
