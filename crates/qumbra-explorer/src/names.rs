//! The name-event feed: `GET /v1/names/events?from=&to=` (lab #486 scope item 6,
//! stage-0 §4 design, coordinator-accepted with renews IN).
//!
//! ```text
//!   stored blocks ──▶ NameEventsView ──▶ page(from,to) ──▶ json ──▶ GET /v1/names/events
//! ```
//!
//! # What an event is
//!
//! The three public name operations, projected from the **persisted per-tx
//! riders** (`StoredTx::rider`, lab #367) exactly the way `txlist` projects
//! transaction existence:
//!
//! - a **commit** renders as what it is — an opaque `H(record ‖ salt)`. It proves
//!   someone reserved *something*; no fake decode, no "pending name".
//! - a **reveal** is the first user-visible proof the name service exists: the
//!   name, its record kind, the fee **burned** by the length tier, and the height
//!   the registration runs to. The **bound address is deliberately omitted**
//!   (stage-0 ruling 2): an event feed answers *what happened*, not *resolve this
//!   name* — the node's own `/v1/names` rider projection is the resolve-side
//!   surface, and carrying ~1.2 KB of L1 address per reveal would make this feed's
//!   weight the address book's.
//! - a **renew** is the third public op kind and rides the same feed (ruling 2:
//!   "a public op kind is a public op kind"). No new expiry is stated for it:
//!   a renewal extends from `max(now, current expiry)`, which is registry state,
//!   and this projection deliberately holds none — a guessed expiry would be a
//!   fabricated fact.
//!
//! # The dark ship, and why it backfills
//!
//! Every document carries `boundary_height`
//! ([`qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT`]); below it the feed over any
//! covered range is empty **and that is a fact, not an error** — the page renders
//! the honest empty state ("the name service arms at height 19,008"). Because the
//! feed is chain-derived rather than accumulated in a ring, it **backfills**: an
//! explorer rolled after the boundary still serves every event from the boundary's
//! first block on its next walk, so "data accrues from block one" holds by
//! construction (stage-0 §4, the finding that killed the boundary-timing pressure).
//!
//! # The contract it inherits
//!
//! Range/bulk-served only — no by-name, no by-height-of-one-name form, the D2
//! correlation rule's fifth application (asking about one name tells this server
//! which name you care about; the node's `/v1/names` already refuses
//! resolve-by-name BY NAME). Coverage is explicit ([`NamesPage::covered_to`]),
//! empty-covered ≠ no-coverage, and paging is [`crate::txlist::next_from_coverage`]
//! — one implementation of the #312 rule, shared, not restated.

use std::sync::{Arc, Mutex};

use qlab_devnet::names::{
    decode_rider, name_fee_bessel, NameOp, NAME_RULE_BOUNDARY_HEIGHT, NAME_TERM_BLOCKS,
    RECORD_KIND_L1_ADDRESS, RECORD_KIND_RESERVED_ANNULET,
};
use qlab_node::{ChainStore, Hash32};

use crate::json::{esc, num};
use crate::txlist::{hex32, next_from_coverage, Next};

/// The feed's own version, bumped when this document's **shape** changes — the
/// same posture and the same reject-unknown reader rule as `TXLIST_VERSION`,
/// and deliberately its own integer (three surfaces, three meanings, json.rs's
/// standing argument).
pub const NAMES_VERSION: u32 = 1;

/// The most main-chain heights one page's scan will cover — `txlist`'s bound,
/// same number, same reasons. `[devnet-placeholder]`, testnet-tunable, NOT
/// frozen; the covered range is explicit so this can move without touching a
/// golden or a client.
pub const MAX_NAMES_HEIGHTS: u64 = 1024;

/// The most events one page will carry — the second bound on the same answer.
/// A page never splits a height: all of one height's events travel together
/// (the `MAX_TXLIST_TXS` block-atomicity rule, height-keyed here), with the same
/// single-oversized-height exception so paging always terminates.
pub const MAX_NAMES_EVENTS: usize = 256;

/// One projected name event. `height` is where it landed; the kind carries
/// exactly the public facts stage-0 §4 proposed and the review accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEvent {
    pub height: u64,
    pub kind: EventKind,
}

/// The three public op kinds, with their public facts only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// An opaque reservation: `H(record ‖ salt)`, and honestly nothing more.
    Commit { commit: Hash32 },
    /// The registration: name, record kind, burned fee, and the height the term
    /// runs to (`height + NAME_TERM_BLOCKS` — a fresh registration's expiry is
    /// chain-derivable per event; see `extended_expiry`'s rule in `names.rs`).
    Reveal { name: Vec<u8>, record_kind: u8, fee_burned: u64, expires_height: u64 },
    /// A term extension. Fee burned by the same length tier; the new expiry is
    /// registry state and deliberately not fabricated here.
    Renew { name: Vec<u8>, fee_burned: u64 },
}

impl NameEvent {
    /// Project one decoded rider op at `height`.
    pub fn of(height: u64, op: &NameOp) -> NameEvent {
        let kind = match op {
            NameOp::Commit { commit } => EventKind::Commit { commit: *commit },
            NameOp::Reveal { record, .. } => EventKind::Reveal {
                name: record.name.clone(),
                record_kind: record.kind,
                fee_burned: name_fee_bessel(record.name.len()),
                expires_height: height + NAME_TERM_BLOCKS,
            },
            NameOp::Renew { name } => EventKind::Renew {
                name: name.clone(),
                fee_burned: name_fee_bessel(name.len()),
            },
        };
        NameEvent { height, kind }
    }
}

/// The record kind as a machine name — the reader supplies the words, the same
/// split `json::regime` takes. Both defined kinds are named; anything else is
/// rendered as its byte rather than guessed at (unreachable from stored state:
/// `check_op` admits only the L1 kind at v1, but this encoder must not be
/// breakable by its own input).
fn record_kind_name(kind: u8) -> String {
    match kind {
        RECORD_KIND_L1_ADDRESS => "l1_address".to_string(),
        RECORD_KIND_RESERVED_ANNULET => "reserved_annulet".to_string(),
        other => format!("unknown_0x{other:02x}"),
    }
}

// ---------------------------------------------------------------------------
// The projection
// ---------------------------------------------------------------------------

/// The main chain's name events as of the run loop's last refresh — the same
/// snapshot discipline, walk, and splice rule as [`crate::txlist::TxListView`]
/// (see its `refresh` docs for the three walk endings and the retain-below rule;
/// the reasoning is not restated here because it is the same rule).
///
/// Small by construction: only heights that carry a name op are held, and the
/// chain below the 19,008 boundary holds none at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameEventsView {
    /// Ascending by height; within one height, tx order (block order).
    pub events: Vec<NameEvent>,
    /// The main-chain tip this view was projected at.
    pub tip_height: u64,
    /// The tip hash this view was projected at; `None` = never projected.
    pub tip_hash: Option<Hash32>,
}

impl NameEventsView {
    /// Re-project from a node's main chain. Returns whether anything changed.
    /// Walk and splice are `TxListView::refresh`'s, verbatim in structure.
    pub fn refresh<C: ChainStore>(&mut self, chain: &C) -> bool {
        let tip = chain.tip_hash();
        if self.tip_hash == Some(tip) {
            return false;
        }
        let anchor = self.tip_hash;
        let mut fresh: Vec<NameEvent> = Vec::new();
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
            // Reverse tx order here; the whole walk is reversed below, so block
            // order comes out ascending.
            for tx in block.txs.iter().rev() {
                // A stored rider already passed consensus, so a decode failure is
                // unreachable from applied state; a projection is not the place to
                // invent an error surface for store corruption, so an undecodable
                // rider projects no event (same posture as `esc`: handled, tested
                // reachable-or-not).
                if let Ok(Some(op)) = decode_rider(&tx.rider) {
                    fresh.push(NameEvent::of(height, &op));
                }
            }
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
        self.events.retain(|e| e.height < lowest_walked);
        self.events.extend(fresh);
        self.tip_height = tip_height;
        self.tip_hash = Some(tip);
        true
    }
}

/// Re-project the shared snapshot if the chain moved — `txlist::refresh_shared`'s
/// seam, same rule, same reasons.
pub fn refresh_shared<C: ChainStore>(slot: &Mutex<Arc<NameEventsView>>, chain: &C) -> bool {
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

/// One `/v1/names/events?from=&to=` answer. Coverage semantics are
/// [`crate::txlist::TxListPage::covered_to`]'s, verbatim: every height in
/// `[from, covered_to]` is fully described (its events listed, or absent because
/// it carries none), and `None` means the page describes no height at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamesPage {
    pub from: u64,
    pub to: u64,
    pub tip_height: u64,
    pub covered_to: Option<u64>,
    pub events: Vec<NameEvent>,
}

/// Build the page for `[from, to]` over a projection — the txlist arithmetic
/// with height-atomicity in place of block-atomicity.
pub fn page(view: &NameEventsView, from: u64, to: u64) -> NamesPage {
    let ceiling = to.min(view.tip_height);
    if from > ceiling {
        return NamesPage { from, to, tip_height: view.tip_height, covered_to: None, events: Vec::new() };
    }
    let scan_to = ceiling.min(from.saturating_add(MAX_NAMES_HEIGHTS - 1));
    let mut events: Vec<NameEvent> = Vec::new();
    let mut covered_to = scan_to;
    for e in &view.events {
        if e.height < from {
            continue;
        }
        if e.height > scan_to {
            break;
        }
        // Never a partial height: if starting the NEXT height would cross the
        // bound, the page ends below it — unless that height is the page's first,
        // which is emitted whole so coverage can always advance.
        let starts_new_height = events.last().map(|last| last.height != e.height).unwrap_or(false);
        if events.len() >= MAX_NAMES_EVENTS && starts_new_height {
            covered_to = e.height - 1;
            break;
        }
        events.push(e.clone());
    }
    NamesPage { from, to, tip_height: view.tip_height, covered_to: Some(covered_to), events }
}

/// The paging rule — delegated whole to the shared implementation.
pub fn next_after(p: &NamesPage, requested_to: u64) -> Next {
    next_from_coverage(p.from, p.covered_to, p.tip_height, requested_to)
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// Serialize one page as the versioned JSON document. Hand-rolled, zero new
/// runtime dependencies — `crate::json`'s posture and reasons.
///
/// `boundary_height` rides in **every** document (the dark ship's honesty
/// field): below it an empty covered range is the expected state and the page
/// says why; the constant arriving as `None` on some future net renders `null`,
/// never a fabricated height.
pub fn document(p: &NamesPage) -> String {
    let events: Vec<String> = p
        .events
        .iter()
        .map(|e| match &e.kind {
            EventKind::Commit { commit } => format!(
                "{{\"height\":{h},\"kind\":\"commit\",\"commit\":\"{c}\"}}",
                h = e.height,
                c = hex32(commit),
            ),
            EventKind::Reveal { name, record_kind, fee_burned, expires_height } => format!(
                "{{\"height\":{h},\"kind\":\"reveal\",\"name\":\"{n}\",\
                 \"record_kind\":\"{k}\",\"fee_burned\":{f},\"expires_height\":{x}}}",
                h = e.height,
                n = esc(&String::from_utf8_lossy(name)),
                k = record_kind_name(*record_kind),
                f = fee_burned,
                x = expires_height,
            ),
            EventKind::Renew { name, fee_burned } => format!(
                "{{\"height\":{h},\"kind\":\"renew\",\"name\":\"{n}\",\"fee_burned\":{f}}}",
                h = e.height,
                n = esc(&String::from_utf8_lossy(name)),
                f = fee_burned,
            ),
        })
        .collect();
    format!(
        "{{\"v\":{NAMES_VERSION},\
         \"boundary_height\":{boundary},\
         \"tip_height\":{tip},\
         \"range\":{{\"from\":{from},\"to\":{to},\"covered_to\":{covered}}},\
         \"events\":[{events}]}}",
        boundary = num(NAME_RULE_BOUNDARY_HEIGHT),
        tip = p.tip_height,
        from = p.from,
        to = p.to,
        covered = num(p.covered_to),
        events = events.join(","),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::names::{encode_rider, NameRecord, RIDER_ABSENT};
    use qlab_node::{StoredBlock, StoredHeader, StoredTx};

    fn h32(first: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = first;
        h
    }

    fn stored_tx(seed: u8, rider: Vec<u8>) -> StoredTx {
        StoredTx {
            anchor: h32(seed),
            nullifiers: vec![h32(seed ^ 0x40), h32(seed ^ 0x41)],
            commitments: vec![h32(seed ^ 0x80), h32(seed ^ 0x81)],
            bucket_actions: 2,
            fee: 1_000_000,
            proof: vec![seed; 32],
            discovery: vec![0xdd; 16],
            rider,
        }
    }

    fn rider(op: &NameOp) -> Vec<u8> {
        encode_rider(Some(op))
    }

    fn commit_op(byte: u8) -> NameOp {
        NameOp::Commit { commit: [byte; 32] }
    }

    fn reveal_op(name: &str) -> NameOp {
        NameOp::Reveal {
            record: NameRecord {
                kind: RECORD_KIND_L1_ADDRESS,
                name: name.as_bytes().to_vec(),
                address: vec![0xab; qlab_devnet::names::L1_ADDRESS_LEN],
            },
            salt: [0x5a; 32],
        }
    }

    fn renew_op(name: &str) -> NameOp {
        NameOp::Renew { name: name.as_bytes().to_vec() }
    }

    fn stored_block(height: u64, txs: Vec<StoredTx>) -> StoredBlock {
        StoredBlock {
            header: StoredHeader {
                prev: h32(height.saturating_sub(1) as u8),
                height,
                timestamp: 1_000 + height,
                difficulty: 1,
                nonce: 0,
                tx_body_commitment: h32(0xcc),
            },
            txs,
            coinbase: 5_000_000_000,
            coinbase_rkm: [0; 4],
        }
    }

    fn view_of(tip: u64, blocks: Vec<(u64, Vec<StoredTx>)>) -> NameEventsView {
        let mut events = Vec::new();
        for (h, txs) in blocks {
            for tx in txs {
                if let Ok(Some(op)) = decode_rider(&tx.rider) {
                    events.push(NameEvent::of(h, &op));
                }
            }
        }
        NameEventsView { events, tip_height: tip, tip_hash: Some(h32(0xfe)) }
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    // ---- the projected facts --------------------------------------------------

    /// A commit is an opaque hash and nothing else — no name key, no decode.
    #[test]
    fn a_commit_projects_the_opaque_hash_and_nothing_else() {
        let view = view_of(19_020, vec![(19_012, vec![stored_tx(1, rider(&commit_op(0x9a)))])]);
        let v = parse(&document(&page(&view, 19_000, 19_020)));
        let e = &v["events"][0];
        assert_eq!(e["kind"], "commit");
        assert_eq!(e["height"], 19_012);
        assert_eq!(e["commit"], "9a".repeat(32));
        assert!(e.get("name").is_none(), "a commit reveals no name: {e}");
    }

    /// A reveal carries the four public facts — and the fee is the consensus fee
    /// table's own answer (`name_fee_bessel`, imported, never copied), the
    /// audit-emission posture on money.
    #[test]
    fn a_reveal_carries_name_kind_burned_fee_and_expiry() {
        let view = view_of(19_050, vec![(19_031, vec![stored_tx(2, rider(&reveal_op("larry")))])]);
        let v = parse(&document(&page(&view, 19_000, 19_050)));
        let e = &v["events"][0];
        assert_eq!(e["kind"], "reveal");
        assert_eq!(e["name"], "larry");
        assert_eq!(e["record_kind"], "l1_address");
        assert_eq!(e["fee_burned"], name_fee_bessel(5), "the fee table's answer, imported");
        assert_eq!(e["fee_burned"], 100_000_000, "5+ chars = 1 QMB");
        assert_eq!(
            e["expires_height"],
            19_031 + NAME_TERM_BLOCKS,
            "a fresh registration's term is chain-derivable per event"
        );
    }

    /// 🔴 The bound address is NOT in the feed (stage-0 ruling 2): the reveal's
    /// wire carries a 1,233-byte L1 address and this document must not.
    #[test]
    fn the_bound_address_never_reaches_the_feed() {
        let view = view_of(19_050, vec![(19_031, vec![stored_tx(2, rider(&reveal_op("larry")))])]);
        let s = document(&page(&view, 19_000, 19_050));
        // ("l1_address" the KIND name is on the wire; an "address" KEY must not be.)
        assert!(!s.contains("\"address\""), "no address key: {s}");
        assert!(!s.contains(&"ab".repeat(16)), "no address bytes leak: {s}");
        let v = parse(&s);
        assert!(v["events"][0].get("salt").is_none(), "and no salt either");
    }

    /// A renew carries name + fee and deliberately NO expiry: the new expiry is
    /// registry state (`max(now, current) + term`), and this projection holds no
    /// registry — a guessed height would be a fabricated fact.
    #[test]
    fn a_renew_carries_no_fabricated_expiry() {
        let view = view_of(19_500, vec![(19_400, vec![stored_tx(3, rider(&renew_op("larry")))])]);
        let v = parse(&document(&page(&view, 19_000, 19_500)));
        let e = &v["events"][0];
        assert_eq!(e["kind"], "renew");
        assert_eq!(e["name"], "larry");
        assert_eq!(e["fee_burned"], 100_000_000);
        assert!(e.get("expires_height").is_none(), "no guessed expiry: {e}");
    }

    /// The length tiers reach the feed through the imported table: a 1-char name
    /// burns 2,048 QMB, and one bessel of drift would be a fee-table change.
    #[test]
    fn the_fee_tier_is_the_imported_tables() {
        let view = view_of(19_100, vec![(19_040, vec![stored_tx(4, rider(&reveal_op("a")))])]);
        let v = parse(&document(&page(&view, 19_000, 19_100)));
        assert_eq!(v["events"][0]["fee_burned"], 2_048u64 * 100_000_000);
    }

    // ---- the dark ship ---------------------------------------------------------

    /// 🔴 The pre-boundary state: a covered range with no events is a FACT the
    /// page renders honestly, and `boundary_height` rides in the document so the
    /// page can say why without owning a copy of the constant.
    #[test]
    fn pre_boundary_is_an_honest_empty_covered_range_with_the_boundary_stated() {
        let view = view_of(15_761, vec![]);
        let p = page(&view, 15_000, 15_761);
        assert_eq!(p.covered_to, Some(15_761), "covered, and empty");
        let v = parse(&document(&p));
        assert_eq!(
            v["boundary_height"],
            serde_json::json!(NAME_RULE_BOUNDARY_HEIGHT),
            "the constant, served — the page renders it, never hardcodes it"
        );
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
        assert_eq!(next_after(&p, 15_761), Next::Done);
    }

    /// No-coverage stays distinct from empty-covered here too.
    #[test]
    fn past_the_tip_is_no_coverage_not_an_empty_feed() {
        let view = view_of(100, vec![]);
        let p = page(&view, 200, 300);
        assert_eq!(p.covered_to, None);
        assert_eq!(next_after(&p, 300), Next::NoCoverage);
        assert!(parse(&document(&p))["range"]["covered_to"].is_null());
    }

    // ---- the projection walk ----------------------------------------------------

    /// The walk decodes riders from stored blocks: rider-free txs project nothing,
    /// each op kind projects once, ascending, tx order within a block.
    #[test]
    fn refresh_projects_riders_from_a_chain_and_costs_nothing_until_it_moves() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let mut view = NameEventsView::default();
        assert!(view.refresh(&chain), "first projection");
        assert!(view.events.is_empty());
        assert!(!view.refresh(&chain), "unchanged tip does no work");

        let h0 = chain.tip_hash();
        let mut b1 = stored_block(1, vec![stored_tx(1, RIDER_ABSENT.to_vec())]);
        b1.header.prev = h0;
        let h1 = chain.put_block(b1).expect("link");
        let mut b2 = stored_block(
            2,
            vec![
                stored_tx(2, rider(&commit_op(0x9a))),
                stored_tx(3, rider(&reveal_op("larry"))),
            ],
        );
        b2.header.prev = h1;
        chain.put_block(b2).expect("link");

        assert!(view.refresh(&chain));
        assert_eq!(view.tip_height, 2);
        assert_eq!(view.events.len(), 2, "the rider-free tx projected nothing");
        assert!(matches!(view.events[0].kind, EventKind::Commit { .. }));
        assert!(matches!(view.events[1].kind, EventKind::Reveal { .. }));
        assert_eq!((view.events[0].height, view.events[1].height), (2, 2));
        assert!(!view.refresh(&chain));
    }

    /// A reorg drops the abandoned branch's events — a feed that kept them would
    /// publish registrations the chain no longer carries.
    #[test]
    fn a_reorg_replaces_the_suffix_and_abandoned_events_leave_the_feed() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let genesis = chain.tip_hash();
        let mut a1 = stored_block(1, vec![stored_tx(1, rider(&commit_op(0xa1)))]);
        a1.header.prev = genesis;
        chain.put_block(a1).expect("link");
        let mut view = NameEventsView::default();
        view.refresh(&chain);
        assert_eq!(view.events.len(), 1);

        let mut b1 = stored_block(1, vec![stored_tx(2, rider(&commit_op(0xb1)))]);
        b1.header.prev = genesis;
        b1.header.difficulty = 100;
        b1.header.nonce = 7;
        let b1h = chain.put_block(b1).expect("link");
        let mut b2 = stored_block(2, vec![]);
        b2.header.prev = b1h;
        b2.header.difficulty = 100;
        chain.put_block(b2).expect("link");

        assert!(view.refresh(&chain));
        assert_eq!(view.events.len(), 1);
        assert!(
            matches!(&view.events[0].kind, EventKind::Commit { commit } if commit == &[0xb1; 32]),
            "branch A's commit must not still be served: {:?}",
            view.events
        );
    }

    #[test]
    fn the_shared_slot_swaps_only_when_the_chain_moved() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let slot = Mutex::new(Arc::new(NameEventsView::default()));
        assert!(refresh_shared(&slot, &chain), "first projection");
        assert!(!refresh_shared(&slot, &chain));
        let mut b1 = stored_block(1, vec![stored_tx(1, rider(&renew_op("larry")))]);
        b1.header.prev = chain.tip_hash();
        chain.put_block(b1).expect("link");
        assert!(refresh_shared(&slot, &chain));
        assert_eq!(slot.lock().unwrap().events.len(), 1);
    }

    // ---- paging ----------------------------------------------------------------

    /// The event bound ends a page between heights and never inside one, and the
    /// single-oversized-height edge is served whole so paging terminates.
    #[test]
    fn the_event_bound_is_height_atomic_and_paging_terminates() {
        // Two heights: the first carries MAX_NAMES_EVENTS + 3 commits (oversized),
        // the second carries one more.
        let big: Vec<StoredTx> =
            (0..MAX_NAMES_EVENTS + 3).map(|i| stored_tx(i as u8, rider(&commit_op(i as u8)))).collect();
        let view = view_of(
            19_100,
            vec![(19_010, big), (19_011, vec![stored_tx(0xf0, rider(&commit_op(0xf0)))])],
        );

        let p1 = page(&view, 19_000, 19_100);
        assert_eq!(p1.events.len(), MAX_NAMES_EVENTS + 3, "the oversized height is whole");
        assert_eq!(p1.covered_to, Some(19_010), "and coverage ends below the next height");
        assert_eq!(next_after(&p1, 19_100), Next::Fetch(19_011));

        let p2 = page(&view, 19_011, 19_100);
        assert_eq!(p2.events.len(), 1);
        assert_eq!(p2.covered_to, Some(19_100));
        assert_eq!(next_after(&p2, 19_100), Next::Done);
    }

    /// The scan bound is visible even when the feed is empty — the #309 shape,
    /// pinned here too.
    #[test]
    fn a_scan_bound_truncation_is_visible_even_when_the_feed_is_empty() {
        let view = view_of(23_000, vec![(22_000, vec![stored_tx(9, rider(&commit_op(1)))])]);
        let p = page(&view, 19_008, 23_000);
        assert!(p.events.is_empty(), "the event is above the scan bound");
        assert_eq!(p.covered_to, Some(19_008 + MAX_NAMES_HEIGHTS - 1));
        assert_eq!(next_after(&p, 23_000), Next::Fetch(19_008 + MAX_NAMES_HEIGHTS));
    }

    // ---- the document -----------------------------------------------------------

    /// A hostile name cannot break the document. The N3 grammar makes this
    /// unreachable from applied state — lowercase alnum + '-' only — and the
    /// encoder must be unbreakable anyway (`json::esc`'s standing argument).
    #[test]
    fn a_hostile_name_cannot_break_the_document() {
        let evil = NameEvent {
            height: 19_020,
            kind: EventKind::Renew { name: b"a\"b\\c\nd".to_vec(), fee_burned: 1 },
        };
        let p = NamesPage {
            from: 19_000,
            to: 19_100,
            tip_height: 19_100,
            covered_to: Some(19_100),
            events: vec![evil],
        };
        let v = parse(&document(&p)); // would panic on malformed JSON
        assert_eq!(v["events"][0]["name"], "a\"b\\c\nd", "round-trips verbatim");
    }

    // ---- goldens (the split-decision §4 discipline) ------------------------------

    /// Keccak-256 over the golden documents concatenated, in **source**, so a
    /// blind file regeneration cannot make the goldens pass by itself.
    const GOLDEN_DIGEST: &str =
        "fdc9a79b6decc7b0c3e5e8c6b4f365e60910804e7af20fde6a06390b68df4b8a";

    /// The three states `qumbra-explorer-web` renders (stage 2), same bytes both
    /// sides of the repo boundary: the live post-boundary feed with all three op
    /// kinds; the pre-boundary honest empty state; a request past the tip.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let feed = view_of(
            19_450,
            vec![
                (19_012, vec![stored_tx(0x10, rider(&commit_op(0x9a)))]),
                (19_031, vec![stored_tx(0x11, rider(&reveal_op("larry")))]),
                (19_400, vec![stored_tx(0x12, rider(&renew_op("larry")))]),
            ],
        );
        let pre_boundary = view_of(15_761, vec![]);
        vec![
            ("names-feed", document(&page(&feed, 19_000, 19_450))),
            ("names-empty-covered", document(&page(&pre_boundary, 15_000, 15_761))),
            ("names-no-coverage", document(&page(&pre_boundary, 20_000, 20_100))),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors. Update only with an
    /// intentional, documented shape change; regeneration alone leaves
    /// [`golden_digest_locks_the_regenerated_files`] red on purpose.
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

    /// The goldens must decode in the direction the front end reads them.
    #[test]
    fn the_goldens_decode_and_carry_the_boundary() {
        for (name, produced) in golden_cases() {
            let v = parse(&produced);
            assert_eq!(v["v"], NAMES_VERSION, "{name} is versioned");
            assert!(v.get("boundary_height").is_some(), "{name} states the boundary");
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
