//! The transaction-**existence** view: `GET /v1/txlist?from=&to=` and the client
//! rules that go with it (`qumbra-design/t1-explorer-tx-view-decision.md`,
//! STAMPED 2026-08-10, D1 + D2 + D3; lab issue #326).
//!
//! ```text
//!   stored blocks ──▶ TxListView ──▶ page(from,to) ──▶ json ──▶ GET /v1/txlist
//!                                                                    │
//!                                                       fetched pages ▼
//!                                                    next_after / match_txid
//! ```
//!
//! # D1 — what exists publicly, and nothing more
//!
//! Per block **with transactions**: height and transaction count. Per transaction:
//! its id, its wire bytes, its posted fee, its nullifier count and its commitment
//! count. Those five are not a chosen subset of a richer record — they are the
//! whole of what a shielded transaction publishes, and every one of them is
//! already gossiped to every peer. There is no amount, no address, no party and no
//! linkage in the chain to withhold.
//!
//! The block's transaction count is written by the encoder from `txs.len()` rather
//! than carried as a field: D1 names it, so it is on the wire, but a stored count
//! would be a second source able to disagree with the list beside it.
//!
//! # D2 — bulk-served, matched locally: there is deliberately no lookup by id
//!
//! `/v1/txlist/<txid>` does not exist and is a **404 by shape**, not by policy.
//! A `/tx/<id>` query tells this server which transaction the asker cares about,
//! which is the same correlation surface the nullifier-membership query was
//! refused for at PR #315 decision 3 — one rule, both surfaces. The page fetches
//! ranges and matches a pasted id over what it already holds
//! ([`match_txid`]), so no request this surface answers is parameterized by a
//! transaction id.
//!
//! What that costs the reader is stated rather than hidden: a needle absent from
//! the fetched pages is [`MatchOutcome::NotInFetchedPages`], which is **not** the
//! claim that no such transaction exists. See its docs.
//!
//! # The paging contract, and the one place `/v1/compact`'s does not transfer
//!
//! `/v1/compact` and `/v1/nullifiers` (issue #312 / lab #314) serve every held
//! height in the requested range, **empty ones included**, so their last served
//! height is a sound resume cursor and "the page stopped here" is expressible.
//!
//! D1's list is per block-*with-txs*, so empty blocks are omitted — and the moment
//! they are, `blocks.last()` stops meaning "where the page ended". A page covering
//! 1,024 transaction-free heights is `"blocks":[]`, which is byte-for-byte what
//! *"this chain has never carried a transaction"* looks like. That is the
//! truncation-reads-as-complete shape lab #309 paid for with real money.
//!
//! So coverage is carried **explicitly** and separately from the list:
//! [`TxListPage::covered_to`] is the highest height the scan actually reached, and
//! the invariant is *every height in `[from, covered_to]` is fully described by
//! `blocks`*. A client resumes at `covered_to + 1` ([`next_after`]) and stops when
//! coverage reaches `min(to, tip_height)`; a page that fails to advance coverage
//! is [`Next::Stalled`], a named client refusal and never a silent stop.
//! `covered_to` is absent only when `from` is past the tip — *"this page describes
//! no height"*, which is a different fact from *"no transactions in range"* and
//! must stay different.
//!
//! # D3 — the boundary sentence rides in the document
//!
//! [`BOUNDARY_SENTENCE`] is served with every page and the page renders it
//! verbatim. D3 asks for the sentence to be part of the page; a second
//! hand-written copy on the far side of a repo boundary is a sentence that can
//! drift, and this repo pair has already built two mechanisms (`PUBLISH.manifest`,
//! the shared golden corpus) against exactly that. The page still *shows* it — it
//! just does not *own* it.
//!
//! # Why the figures can be trusted
//!
//! Every field is a projection of a stored block: the id is
//! [`qlab_node::rpc::tx_id`] over the transaction's own declared public surface,
//! the counts are that surface's own lengths, the fee is the posted fee as
//! committed, and the wire size is [`qlab_p2p::codec::encode_tx`] — the canonical
//! encoder itself, never an arithmetic restatement of its framing. There is no
//! second source and no index: the stored chain answers all of D1.

use std::sync::{Arc, Mutex};

use qlab_devnet::body::TxEntry;
use qlab_node::{ChainStore, Hash32, StoredBlock, StoredTx};

/// The projection's own version, bumped when this document's **shape** changes.
///
/// 🔴 Deliberately neither [`crate::json::HEALTH_VERSION`] nor
/// `qlab_node::rpc::RPC_VERSION`, for the reason `json.rs` already records: the
/// three can each move while the others do not, and one integer cannot carry
/// three meanings. A reader that does not know this value must refuse the
/// document and render nothing else — reject-unknown, the posture every
/// versioned surface in this tree takes.
pub const TXLIST_VERSION: u32 = 1;

/// D3, verbatim. Served with every page; the page renders it and does not hold
/// its own copy.
pub const BOUNDARY_SENTENCE: &str = "Qumbra is a single global shielded pool, so this list is \
every public fact a transaction has: that it exists, where it landed, its size, its posted fee \
and how many notes it spent and created. There are no amounts, no addresses, no parties and no \
links between transactions here — not because they are withheld, but because the chain does not \
carry them.";

/// The most main-chain heights one page's scan will cover.
///
/// The same shape and the same number as `qlab_node::MAX_COMPACT_BLOCKS` and
/// `qlab_cbserver::codec::MAX_NULLIFIER_BLOCKS`, because the client paging this
/// stream is paging over the same kind of range: `to` is a client-chosen number
/// and the server's work must be bounded by the server. 1,024 heights is ~21
/// hours of chain at the 75 s target. `[devnet-placeholder]`, testnet-tunable,
/// NOT frozen — the document carries the covered range explicitly, so this bound
/// can move without touching a golden or a client.
pub const MAX_TXLIST_HEIGHTS: u64 = 1024;

/// The most transactions one page will carry, as a second bound on the same
/// answer — a height bound alone is not a size bound, because a busy range's
/// cost is transactions rather than heights.
///
/// **A page never splits a block.** If emitting the next block would cross this
/// bound the scan stops *before* it and coverage ends at the previous height, so
/// the block a client sees is always that block's whole transaction list. The one
/// exception is a single block that exceeds this bound on its own: it is emitted
/// whole anyway, because a page that could not emit it would leave `covered_to`
/// unable to advance and a conforming client would loop on it forever. That is a
/// bound being honest about its own edge, not a bound being ignored.
///
/// `[devnet-placeholder]`, testnet-tunable, NOT frozen.
pub const MAX_TXLIST_TXS: usize = 256;

// ---------------------------------------------------------------------------
// The facts (D1)
// ---------------------------------------------------------------------------

/// One transaction's public existence facts — D1's five, and D1's five only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxFacts {
    /// The **statement** id — `qlab_node::rpc::tx_id` over the declared public
    /// surface, the same id `POST /v1/tx` answers with and the same one a wallet
    /// shows its user after a send. Proof bytes are excluded from it by that
    /// function's design, so the id a sender was given is the id that appears
    /// here.
    pub txid: Hash32,
    /// The canonical wire size, in bytes: `qlab_p2p::codec::encode_tx`'s output
    /// length for this transaction. The encoder, not a restatement of it.
    pub wire_bytes: u64,
    /// The posted fee in bessel, as committed. The per-bucket price is a frozen
    /// public constant, so this is a public fact twice over.
    pub fee: u64,
    /// How many notes this transaction spent.
    pub nullifiers: u32,
    /// How many notes it created.
    pub commitments: u32,
}

impl TxFacts {
    /// Project one stored transaction.
    ///
    /// The wire size is measured by running the canonical encoder, which costs a
    /// transient copy of the proof (~150 KB at the FROZEN 2×2 shape). That is
    /// paid once per transaction when its block is first projected — the walk is
    /// incremental — and it buys the one property an arithmetic length cannot: a
    /// framing change moves this number automatically instead of silently
    /// leaving it stale.
    pub fn of(tx: &StoredTx) -> TxFacts {
        TxFacts {
            txid: qlab_node::rpc::tx_id(
                &tx.anchor,
                &tx.nullifiers,
                &tx.commitments,
                tx.bucket_actions,
                tx.fee,
            ),
            wire_bytes: qlab_p2p::codec::encode_tx(&TxEntry::from(tx)).len() as u64,
            fee: tx.fee,
            nullifiers: tx.nullifiers.len() as u32,
            commitments: tx.commitments.len() as u32,
        }
    }
}

/// One main-chain block **that carries transactions**, with its list.
///
/// A block with no transactions is not one of these: it is absent from the list
/// and accounted for by the page's covered range instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockTxs {
    pub height: u64,
    /// In block order. Never a prefix — see [`MAX_TXLIST_TXS`].
    pub txs: Vec<TxFacts>,
}

impl BlockTxs {
    /// Project a stored block, or `None` when it carries no transactions.
    ///
    /// The coinbase is not a transaction here and contributes nothing: it has no
    /// statement id, no nullifier and no posted fee, and `StoredBlock::txs`
    /// already excludes it. A block whose only content is its coinbase is a block
    /// with no transactions, which is exactly what an outsider asking *"is the
    /// chain carrying traffic"* needs it to be.
    pub fn of(block: &StoredBlock) -> Option<BlockTxs> {
        if block.txs.is_empty() {
            return None;
        }
        Some(BlockTxs {
            height: block.header.height,
            txs: block.txs.iter().map(TxFacts::of).collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// The projection
// ---------------------------------------------------------------------------

/// The main chain's blocks-with-transactions as of the run loop's last refresh.
///
/// Same snapshot discipline as `qumbra_node::discovery_server::DiscoveryView`:
/// the run loop re-projects on its own cadence and the server thread serves what
/// it published, so a reader can never contend with the node loop. What a
/// snapshot can be is **behind** — a reader sees fewer transactions, never
/// different ones, and its next poll sees the rest.
///
/// It is small by construction: only blocks that carry transactions are held, and
/// each transaction costs 32 B of id plus four integers. The live chain's five
/// transaction blocks are ~300 B of view against a multi-gigabyte block store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxListView {
    /// Ascending by height; only blocks with at least one transaction.
    pub blocks: Vec<BlockTxs>,
    /// The main-chain tip this view was projected at — the ceiling every page
    /// clamps to, and the reason a page can say *"there is nothing above here"*
    /// rather than leaving a client to guess.
    pub tip_height: u64,
    /// The tip hash this view was projected at. `None` on a view that has never
    /// been projected, which is distinct from *"projected at genesis"* — the
    /// first is "ask again", the second is a real answer.
    pub tip_hash: Option<Hash32>,
}

impl TxListView {
    /// Re-project from a node's main chain. Returns whether anything changed.
    ///
    /// The walk goes new-tip → down and stops as soon as it can, then splices by
    /// **one uniform rule**: whatever this pass walked, it also re-describes, and
    /// everything strictly below the lowest height it walked is kept as it stood.
    /// That one rule is correct in all three cases the walk can end in, which is
    /// why it is one rule and not three branches:
    ///
    /// - **an extension** (the ordinary case) — the walk meets the hash this view
    ///   was last projected at and stops there, so a steady node pays only for its
    ///   new blocks and everything below is retained;
    /// - **a reorg or a first projection** — the walk reaches genesis, the lowest
    ///   walked height is 0, nothing is retained, and the view is rebuilt;
    /// - 🔴 **a store that does not hold a block on its own tip's ancestry** — the
    ///   walk stops early, and the rule retains the heights below rather than
    ///   dropping them. An earlier draft of this function rebuilt from `fresh`
    ///   alone in every non-extension case, which on this path would have silently
    ///   **deleted every transaction below the gap** from a served list — a
    ///   truncation that reads as "those transactions do not exist". Same shape as
    ///   the bug this whole contract's `covered_to` exists to prevent, one layer
    ///   down; `DiscoveryView::refresh` takes the same retain-below posture.
    ///
    /// A full rebuild is O(chain) and re-runs the encoder over every transaction
    /// on it. That is accepted rather than optimised around: an incremental splice
    /// that tried to be cleverer would have to answer *"which suffix did the reorg
    /// replace"* for a **sparse** list, where the heights that vanished may be
    /// heights this view never held. Rebuilds are bounded in practice by
    /// no-reorg-past-finality, and the cost is a projection walk, not a proof.
    ///
    /// Nothing here decides what the main chain *is*: `chain.tip_hash()` and
    /// `header.prev` do, which is the fork choice the state machine already
    /// committed to.
    pub fn refresh<C: ChainStore>(&mut self, chain: &C) -> bool {
        let tip = chain.tip_hash();
        if self.tip_hash == Some(tip) {
            return false;
        }
        let anchor = self.tip_hash;
        let mut fresh: Vec<BlockTxs> = Vec::new();
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
            if let Some(b) = BlockTxs::of(block) {
                fresh.push(b);
            }
            if height == 0 {
                break;
            }
            let prev = block.header.prev;
            if Some(prev) == anchor {
                // The view's last tip is this tip's ancestor: everything below is
                // already held and correct.
                break;
            }
            hash = prev;
        }
        let (Some(tip_height), Some(lowest_walked)) = (tip_height, lowest_walked) else {
            // The store does not hold its own tip. Nothing to say; leave the view
            // as it stands rather than replacing it with a fabricated empty one.
            return false;
        };
        fresh.reverse();
        self.blocks.retain(|b| b.height < lowest_walked);
        self.blocks.extend(fresh);
        self.tip_height = tip_height;
        self.tip_hash = Some(tip);
        true
    }

    /// Transactions this view holds across every block (accounting / tests).
    pub fn tx_count(&self) -> usize {
        self.blocks.iter().map(|b| b.txs.len()).sum()
    }
}

/// Re-project the shared snapshot if the chain moved; returns whether it swapped.
///
/// The rule lives here rather than in `main.rs` for the reason `json::fingerprint`
/// records about itself: `main.rs` is CLI glue and a rule kept there cannot be
/// tested. An unchanged tip costs one hash comparison and no copy.
pub fn refresh_shared<C: ChainStore>(slot: &Mutex<Arc<TxListView>>, chain: &C) -> bool {
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

/// One `/v1/txlist?from=&to=` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxListPage {
    /// Echo of the request, so a paging client cannot misattribute a response.
    pub from: u64,
    /// Echo of the request.
    pub to: u64,
    /// The main-chain tip the serving view was projected at — the ceiling
    /// [`next_after`] compares against, and the honest answer to a `to` above it.
    pub tip_height: u64,
    /// 🔴 The highest height this page's scan actually reached.
    ///
    /// **The invariant: every height in `[from, covered_to]` is fully described
    /// by [`Self::blocks`]** — listed with its whole transaction list, or absent
    /// because it carries none. This is what makes `"blocks":[]` mean *"no
    /// transactions in the covered range"* instead of *"the page stopped and did
    /// not say so"*, which is the distinction lab #309 exists to preserve and
    /// which an omitted-empties list cannot express any other way.
    ///
    /// `None` means the page describes no height at all — reachable only when
    /// `from` is above the tip. It is emphatically not *"no transactions"*.
    pub covered_to: Option<u64>,
    /// Ascending by height, blocks with transactions only.
    pub blocks: Vec<BlockTxs>,
}

/// Build the page for `[from, to]` over a projection.
///
/// One implementation of the coverage and truncation arithmetic, so a second
/// server (or a test) cannot invent a different page boundary. The caller has
/// already refused an inverted range; see [`crate::http`].
pub fn page(view: &TxListView, from: u64, to: u64) -> TxListPage {
    let ceiling = to.min(view.tip_height);
    if from > ceiling {
        return TxListPage {
            from,
            to,
            tip_height: view.tip_height,
            covered_to: None,
            blocks: Vec::new(),
        };
    }
    // The height bound applies to the scan, not to the emitted list: it is what
    // makes `to = u64::MAX` bounded server work.
    let scan_to = ceiling.min(from.saturating_add(MAX_TXLIST_HEIGHTS - 1));
    let mut blocks: Vec<BlockTxs> = Vec::new();
    let mut emitted = 0usize;
    let mut covered_to = scan_to;
    for b in &view.blocks {
        if b.height < from {
            continue;
        }
        if b.height > scan_to {
            break;
        }
        // Never a partial block. A block that would cross the transaction bound
        // ends the page below itself — unless it is the first, in which case it
        // is emitted whole so coverage can still advance (see MAX_TXLIST_TXS).
        if emitted >= MAX_TXLIST_TXS && !blocks.is_empty() {
            covered_to = b.height - 1;
            break;
        }
        emitted += b.txs.len();
        blocks.push(b.clone());
    }
    TxListPage {
        from,
        to,
        tip_height: view.tip_height,
        covered_to: Some(covered_to),
        blocks,
    }
}

// ---------------------------------------------------------------------------
// The document (D1 + D3 on the wire)
// ---------------------------------------------------------------------------

/// Serialize one page as the versioned JSON document.
///
/// Hand-rolled, **zero new runtime dependencies**, the same posture and the same
/// reasons as [`crate::json`]: every value here is a number, a hex string this
/// module produced, or the one fixed sentence — the crate ships no JSON library
/// and this does not change that.
pub fn document(p: &TxListPage) -> String {
    let blocks: Vec<String> = p
        .blocks
        .iter()
        .map(|b| {
            let txs: Vec<String> = b
                .txs
                .iter()
                .map(|t| {
                    format!(
                        "{{\"txid\":\"{txid}\",\"wire_bytes\":{wire},\"fee\":{fee},\
                         \"nullifiers\":{nf},\"commitments\":{cm}}}",
                        txid = hex32(&t.txid),
                        wire = t.wire_bytes,
                        fee = t.fee,
                        nf = t.nullifiers,
                        cm = t.commitments,
                    )
                })
                .collect();
            // `tx_count` is D1's per-block fact, written from the list beside it
            // rather than carried — one source, so the two cannot disagree.
            format!(
                "{{\"height\":{h},\"tx_count\":{n},\"txs\":[{txs}]}}",
                h = b.height,
                n = b.txs.len(),
                txs = txs.join(","),
            )
        })
        .collect();
    format!(
        "{{\"v\":{TXLIST_VERSION},\
         \"tip_height\":{tip},\
         \"range\":{{\"from\":{from},\"to\":{to},\"covered_to\":{covered}}},\
         \"blocks\":[{blocks}],\
         \"boundary\":\"{boundary}\"}}",
        tip = p.tip_height,
        from = p.from,
        to = p.to,
        covered = p
            .covered_to
            .map(|c| c.to_string())
            .unwrap_or_else(|| "null".into()),
        blocks = blocks.join(","),
        boundary = BOUNDARY_SENTENCE,
    )
}

/// Lower-case hex, the spelling every id on every Qumbra surface uses.
pub fn hex32(h: &Hash32) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The client half (D2): paging, and matching over fetched pages only
// ---------------------------------------------------------------------------

/// What a client does after a page — the whole paging rule, as one function's
/// return type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Request the next page starting at this height.
    Fetch(u64),
    /// The requested range is covered to its end; stop.
    Done,
    /// 🔴 The server's coverage did not reach even the height we asked from, so
    /// the loop would not advance. A named client refusal on purpose: the failure
    /// mode this whole contract exists against is a truncated range that reads as
    /// a complete one, and *silently stopping* is how that gets written.
    Stalled { at: u64 },
    /// The page describes no height at all (`covered_to` absent, i.e. `from` is
    /// past the tip). Not "no transactions" — the client has learned nothing
    /// about the range and must say so.
    NoCoverage,
}

/// The paging rule: given a page and the range the client originally wanted,
/// what happens next.
///
/// Cap-agnostic by construction — it reads the page's own covered range and never
/// infers the server's bound from a full-looking response. That is issue #312's
/// lesson: a client that counts entries against a constant it compiled in stops
/// working the day the server's bound moves, and stops working *silently*.
pub fn next_after(p: &TxListPage, requested_to: u64) -> Next {
    let Some(covered) = p.covered_to else {
        return Next::NoCoverage;
    };
    if covered < p.from {
        return Next::Stalled { at: p.from };
    }
    if covered >= requested_to.min(p.tip_height) {
        return Next::Done;
    }
    Next::Fetch(covered + 1)
}

/// Where a matched transaction is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxHit {
    pub height: u64,
    /// Index within the block, block order.
    pub tx_index: usize,
    pub tx: TxFacts,
}

/// What a client-side search found — three different facts, kept apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchOutcome {
    /// The needle is not a transaction id at all. A different sentence for a
    /// person than "not found", and the page must not conflate them.
    NotATxid,
    /// Found, in the pages the client already holds.
    Found(Vec<TxHit>),
    /// 🔴 Not present in the fetched pages — which is **not** the claim that no
    /// such transaction exists. This surface serves ranges; a client that has
    /// fetched heights 5,000–6,000 has learned nothing about height 12. The page
    /// must say which range it searched, and this variant is what forces it to.
    NotInFetchedPages,
}

/// Match a pasted id against **fetched pages only** (D2).
///
/// There is no server round trip in here and there is no route that would accept
/// one: the whole point of D2 is that the server never learns which transaction
/// the asker cares about. Accepts an optional `0x` prefix, trims surrounding
/// whitespace and is case-insensitive; anything that is not then exactly 64 hex
/// digits is [`MatchOutcome::NotATxid`].
///
/// Prefix matching is deliberately not offered. It would make one answer —
/// *"nothing matched"* — mean two things ("no transaction has this id" and "no
/// transaction has an id starting this way"), and this contract spends its whole
/// design budget on keeping that class of ambiguity out.
pub fn match_txid(pages: &[TxListPage], needle: &str) -> MatchOutcome {
    let n = needle.trim();
    let n = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")).unwrap_or(n);
    if n.len() != 64 || !n.chars().all(|c| c.is_ascii_hexdigit()) {
        return MatchOutcome::NotATxid;
    }
    let needle = n.to_ascii_lowercase();
    let mut hits = Vec::new();
    for p in pages {
        for b in &p.blocks {
            for (i, t) in b.txs.iter().enumerate() {
                if hex32(&t.txid) == needle {
                    hits.push(TxHit {
                        height: b.height,
                        tx_index: i,
                        tx: t.clone(),
                    });
                }
            }
        }
    }
    if hits.is_empty() {
        MatchOutcome::NotInFetchedPages
    } else {
        MatchOutcome::Found(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::body::TxPublic;
    use qlab_devnet::fees::ArityBucket;

    fn h32(first: u8) -> Hash32 {
        let mut h = [0u8; 32];
        h[0] = first;
        h
    }

    /// A stored transaction with a distinguishable surface. `proof` is real bytes
    /// so `wire_bytes` measures something.
    fn stored_tx(seed: u8, fee: u64, n_nf: usize, n_cm: usize, proof_len: usize) -> StoredTx {
        StoredTx {
            anchor: h32(seed),
            nullifiers: (0..n_nf).map(|i| h32(seed ^ (0x40 + i as u8))).collect(),
            commitments: (0..n_cm).map(|i| h32(seed ^ (0x80 + i as u8))).collect(),
            bucket_actions: 2,
            fee,
            proof: vec![seed; proof_len],
            discovery: vec![0xdd; 16],
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        }
    }

    fn stored_block(height: u64, txs: Vec<StoredTx>) -> StoredBlock {
        StoredBlock {
            header: qlab_node::StoredHeader {
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

    fn view_of(tip: u64, blocks: Vec<(u64, Vec<StoredTx>)>) -> TxListView {
        TxListView {
            blocks: blocks
                .into_iter()
                .filter_map(|(h, txs)| BlockTxs::of(&stored_block(h, txs)))
                .collect(),
            tip_height: tip,
            tip_hash: Some(h32(0xfe)),
        }
    }

    fn parse(s: &str) -> serde_json::Value {
        serde_json::from_str(s).expect("the hand-rolled encoder emits real JSON")
    }

    // ---- D1: the facts, and the fact that they are projections ---------------

    /// 🔴 The wire size is the **encoder's** answer, not an arithmetic one. If
    /// `encode_tx`'s framing ever moves, this number moves with it; the test is
    /// what makes that a property rather than a hope.
    #[test]
    fn wire_bytes_is_the_canonical_encoders_own_length() {
        let tx = stored_tx(1, 1_000_000, 2, 2, 4096);
        let facts = TxFacts::of(&tx);
        assert_eq!(
            facts.wire_bytes,
            qlab_p2p::codec::encode_tx(&TxEntry::from(&tx)).len() as u64,
            "measured by running the encoder, never restated"
        );
        assert!(facts.wire_bytes > 4096, "the proof is in there: {facts:?}");
    }

    /// The id is the statement id — the same one a sender was handed at submit —
    /// derived here from the stored surface and nowhere else.
    #[test]
    fn the_txid_is_the_statement_id_over_the_stored_public_surface() {
        let tx = stored_tx(7, 2_000_000, 2, 2, 64);
        let facts = TxFacts::of(&tx);
        let expected = qlab_node::rpc::tx_id(&tx.anchor, &tx.nullifiers, &tx.commitments, 2, tx.fee);
        assert_eq!(facts.txid, expected);

        // And it is the id `POST /v1/tx` answers with: the same function over the
        // same surface, reached through the live type rather than the stored one.
        let entry = TxEntry::from(&tx);
        let p: &TxPublic = &entry.public;
        assert!(matches!(p.bucket, ArityBucket::TwoByTwo));
        assert_eq!(
            facts.txid,
            qlab_node::rpc::tx_id(
                &p.anchor,
                &p.nullifiers,
                &p.commitments,
                p.bucket.logical_actions(),
                p.fee
            )
        );
    }

    #[test]
    fn the_counts_and_the_fee_are_the_declared_surfaces_own() {
        let facts = TxFacts::of(&stored_tx(3, 40_000, 2, 2, 32));
        assert_eq!(facts.nullifiers, 2);
        assert_eq!(facts.commitments, 2);
        assert_eq!(facts.fee, 40_000);
    }

    /// A coinbase-only block is a block with no transactions, and this is how an
    /// outsider's "is the chain carrying traffic" question stays answerable.
    #[test]
    fn a_block_with_no_transactions_is_not_in_the_list_at_all() {
        assert!(BlockTxs::of(&stored_block(11, vec![])).is_none());
        assert!(BlockTxs::of(&stored_block(12, vec![stored_tx(1, 1, 2, 2, 8)])).is_some());
    }

    // ---- the covered range: the #309 / #312 lesson ---------------------------

    /// 🔴 The load-bearing distinction. An empty list over a covered range means
    /// "no transactions here"; the same empty list over an uncovered range would
    /// mean nothing at all. Both are produced and they do not look alike.
    #[test]
    fn an_empty_list_over_a_covered_range_is_a_fact_and_over_an_uncovered_one_is_not() {
        let view = view_of(50, vec![]);

        let covered = page(&view, 0, 50);
        assert_eq!(covered.covered_to, Some(50), "the whole range was scanned");
        assert!(covered.blocks.is_empty());
        assert_eq!(
            next_after(&covered, 50),
            Next::Done,
            "a client stops, having learned there are no txs in 0..=50"
        );

        let past_tip = page(&view, 60, 90);
        assert_eq!(
            past_tip.covered_to, None,
            "nothing was described; this is not 'no transactions'"
        );
        assert!(past_tip.blocks.is_empty());
        assert_eq!(next_after(&past_tip, 90), Next::NoCoverage);
    }

    /// The truncation shape itself: 1,024 transaction-free heights come back as an
    /// empty list, and the covered range is the only thing that stops a client
    /// concluding the chain has never carried a transaction.
    #[test]
    fn a_scan_bound_truncation_is_visible_even_when_the_list_is_empty() {
        // Nothing until well past the height bound.
        let view = view_of(4000, vec![(3000, vec![stored_tx(9, 1_000_000, 2, 2, 8)])]);
        let p = page(&view, 0, 4000);
        assert!(p.blocks.is_empty(), "the txs are above the scan bound");
        assert_eq!(
            p.covered_to,
            Some(MAX_TXLIST_HEIGHTS - 1),
            "and the page says exactly how far it looked"
        );
        assert_eq!(
            next_after(&p, 4000),
            Next::Fetch(MAX_TXLIST_HEIGHTS),
            "a conforming client keeps going"
        );
    }

    #[test]
    fn to_is_clamped_to_the_tip_and_a_client_stops_there() {
        let view = view_of(30, vec![(7, vec![stored_tx(1, 1, 2, 2, 8)])]);
        let p = page(&view, 0, u64::MAX);
        assert_eq!(p.tip_height, 30);
        assert_eq!(p.covered_to, Some(30), "clamped to the tip, not to u64::MAX");
        assert_eq!(next_after(&p, u64::MAX), Next::Done);
    }

    // ---- the transaction bound, and block atomicity --------------------------

    #[test]
    fn the_tx_bound_ends_a_page_between_blocks_and_never_inside_one() {
        // Eight blocks of 64 txs: the bound (256) falls after the fourth.
        let blocks: Vec<(u64, Vec<StoredTx>)> = (1..=8)
            .map(|h| {
                (
                    h as u64,
                    (0..64).map(|i| stored_tx((h * 64 + i) as u8, 1_000, 2, 2, 8)).collect(),
                )
            })
            .collect();
        let view = view_of(8, blocks);
        let p = page(&view, 1, 8);

        assert_eq!(p.blocks.len(), 4, "stopped on the bound");
        assert!(
            p.blocks.iter().all(|b| b.txs.len() == 64),
            "every emitted block carries its WHOLE list"
        );
        assert_eq!(
            p.covered_to,
            Some(4),
            "coverage ends below the block the page declined to start"
        );
        assert_eq!(next_after(&p, 8), Next::Fetch(5));
    }

    /// The edge the bound has to be honest about: one block bigger than the bound
    /// is served whole, because a page that refused it could never advance
    /// coverage and a conforming client would loop on it forever.
    #[test]
    fn a_single_block_larger_than_the_tx_bound_is_served_whole_so_paging_terminates() {
        let big: Vec<StoredTx> = (0..(MAX_TXLIST_TXS + 10))
            .map(|i| stored_tx(i as u8, 1_000, 2, 2, 8))
            .collect();
        let n = big.len();
        let view = view_of(5, vec![(3, big)]);
        let p = page(&view, 0, 5);

        assert_eq!(p.blocks.len(), 1);
        assert_eq!(p.blocks[0].txs.len(), n, "whole, not a prefix");
        assert_eq!(p.covered_to, Some(5));
        assert_eq!(next_after(&p, 5), Next::Done);
    }

    // ---- the client half -----------------------------------------------------

    /// The whole paging loop over a chain shaped like the live one: transaction
    /// blocks at 4913 / 5398 / 5406 / 5417 / 5924 with thousands of empty heights
    /// around and between them. Cap-agnostic: the loop reads coverage and never
    /// counts entries against a compiled-in bound.
    #[test]
    fn the_client_reassembles_the_live_chains_shape_across_pages() {
        let live = [4913u64, 5398, 5406, 5417, 5924];
        let view = view_of(
            6000,
            live.iter()
                .enumerate()
                .map(|(i, h)| (*h, vec![stored_tx(i as u8 + 1, 1_000_000, 2, 2, 128)]))
                .collect(),
        );

        let mut pages = Vec::new();
        let mut from = 0u64;
        let want_to = 6000u64;
        let mut guard = 0;
        loop {
            guard += 1;
            assert!(guard < 100, "the loop must terminate");
            let p = page(&view, from, want_to);
            let next = next_after(&p, want_to);
            pages.push(p);
            match next {
                Next::Fetch(h) => from = h,
                Next::Done => break,
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(guard, 6, "6000 heights at 1024 per page");
        let seen: Vec<u64> = pages
            .iter()
            .flat_map(|p| p.blocks.iter().map(|b| b.height))
            .collect();
        assert_eq!(seen, live.to_vec(), "every tx block, once, in order");
        assert_eq!(
            pages.iter().map(|p| p.blocks.len()).sum::<usize>(),
            5,
            "and nothing duplicated across the page boundaries"
        );
    }

    /// A server that answers with coverage below the request cannot make a client
    /// spin or, worse, stop quietly.
    #[test]
    fn a_page_that_does_not_advance_coverage_is_a_named_refusal() {
        let stalled = TxListPage {
            from: 100,
            to: 200,
            tip_height: 500,
            covered_to: Some(99),
            blocks: Vec::new(),
        };
        assert_eq!(next_after(&stalled, 200), Next::Stalled { at: 100 });
    }

    #[test]
    fn a_pasted_id_matches_over_fetched_pages_and_says_so_when_it_does_not() {
        let tx = stored_tx(0x5a, 1_000_000, 2, 2, 64);
        let want = hex32(&TxFacts::of(&tx).txid);
        let view = view_of(6000, vec![(4913, vec![tx]), (5398, vec![stored_tx(2, 1, 2, 2, 8)])]);
        let pages = vec![page(&view, 4900, 5400)];

        // Found — with where it landed.
        match match_txid(&pages, &want) {
            MatchOutcome::Found(hits) => {
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].height, 4913);
                assert_eq!(hits[0].tx_index, 0);
            }
            other => panic!("expected a hit, got {other:?}"),
        }
        // Whitespace, 0x and case are the shapes a human actually pastes.
        assert!(matches!(
            match_txid(&pages, &format!("  0X{}  ", want.to_ascii_uppercase())),
            MatchOutcome::Found(_)
        ));

        // 🔴 Absent from the fetched pages is NOT "does not exist".
        let absent = "0".repeat(64);
        assert_eq!(
            match_txid(&pages, &absent),
            MatchOutcome::NotInFetchedPages
        );

        // And a needle that is not an id at all is its own answer.
        for junk in ["", "hello", "0x", &"a".repeat(63), &"a".repeat(65), &"z".repeat(64)] {
            assert_eq!(match_txid(&pages, junk), MatchOutcome::NotATxid, "{junk}");
        }
    }

    /// D2, stated as a property of this module rather than of the router: nothing
    /// here takes a transaction id as an input to a request. The matcher's only
    /// argument besides the needle is pages the client already has.
    #[test]
    fn matching_consults_no_server_and_an_empty_client_cache_says_so() {
        assert_eq!(
            match_txid(&[], &"ab".repeat(32)),
            MatchOutcome::NotInFetchedPages,
            "with nothing fetched, the honest answer is 'not in what I have'"
        );
    }

    // ---- the projection ------------------------------------------------------

    #[test]
    fn refresh_projects_a_chain_and_then_costs_nothing_until_it_moves() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let mut view = TxListView::default();
        assert!(view.refresh(&chain), "the first projection always runs");
        assert_eq!(view.tip_height, 0);
        assert!(view.blocks.is_empty());
        assert!(!view.refresh(&chain), "an unchanged tip does no work");

        // Extend with an empty block and then one carrying a transaction.
        let h0 = chain.tip_hash();
        let mut b1 = stored_block(1, vec![]);
        b1.header.prev = h0;
        let h1 = chain.put_block(b1).expect("link");
        let mut b2 = stored_block(2, vec![stored_tx(0x11, 1_000_000, 2, 2, 64)]);
        b2.header.prev = h1;
        chain.put_block(b2).expect("link");

        assert!(view.refresh(&chain), "the tip moved");
        assert_eq!(view.tip_height, 2);
        assert_eq!(view.blocks.len(), 1, "only the block with transactions");
        assert_eq!(view.blocks[0].height, 2);
        assert_eq!(view.tx_count(), 1);
        assert!(!view.refresh(&chain));
    }

    /// The extension fast path must not double-count: a second refresh after a
    /// second transaction block appends rather than re-collecting.
    #[test]
    fn an_extension_appends_and_never_duplicates_what_the_view_already_held() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let mut prev = chain.tip_hash();
        for h in 1..=3u64 {
            let mut b = stored_block(h, vec![stored_tx(h as u8, 1_000, 2, 2, 8)]);
            b.header.prev = prev;
            prev = chain.put_block(b).expect("link");
        }
        let mut view = TxListView::default();
        view.refresh(&chain);
        assert_eq!(view.blocks.len(), 3);

        for h in 4..=5u64 {
            let mut b = stored_block(h, vec![stored_tx(h as u8, 1_000, 2, 2, 8)]);
            b.header.prev = prev;
            prev = chain.put_block(b).expect("link");
        }
        assert!(view.refresh(&chain));
        assert_eq!(view.blocks.len(), 5, "appended, not duplicated");
        assert_eq!(
            view.blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5],
            "and still ascending"
        );
    }

    /// A reorg replaces the suffix rather than appending to it: the walk misses
    /// the old tip, reaches genesis, and the abandoned branch's transaction is
    /// gone from the list. A list that kept it would be publishing a transaction
    /// the chain no longer carries.
    #[test]
    fn a_reorg_replaces_the_suffix_and_the_abandoned_branch_leaves_the_list() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let genesis = chain.tip_hash();

        // Branch A: one block with a transaction, minimum weight.
        let mut a1 = stored_block(1, vec![stored_tx(0xa1, 1_000, 2, 2, 8)]);
        a1.header.prev = genesis;
        chain.put_block(a1).expect("link");
        let mut view = TxListView::default();
        view.refresh(&chain);
        assert_eq!(view.tx_count(), 1, "branch A's transaction is listed");
        let abandoned = view.blocks[0].txs[0].txid;

        // Branch B off genesis, heavier, and two blocks long.
        let mut b1 = stored_block(1, vec![stored_tx(0xb1, 2_000, 2, 2, 8)]);
        b1.header.prev = genesis;
        b1.header.difficulty = 100;
        b1.header.nonce = 7; // a different header, so a different hash
        let b1h = chain.put_block(b1).expect("link");
        let mut b2 = stored_block(2, vec![stored_tx(0xb2, 3_000, 2, 2, 8)]);
        b2.header.prev = b1h;
        b2.header.difficulty = 100;
        chain.put_block(b2).expect("link");
        assert_eq!(chain.tip_height(), 2, "fork choice took the heavier branch");

        assert!(view.refresh(&chain), "the tip moved");
        assert_eq!(view.tip_height, 2);
        assert_eq!(view.blocks.len(), 2, "branch B's two blocks");
        assert!(
            view.blocks.iter().all(|b| b.txs.iter().all(|t| t.txid != abandoned)),
            "the abandoned branch's transaction must not still be served"
        );
    }

    /// 🔴 A store that cannot answer for a block on its own tip's ancestry must not
    /// make the list **shorter**. The walk stops at the gap and everything below is
    /// retained; an earlier draft rebuilt from the walked suffix alone, which would
    /// have silently deleted every transaction below the gap — a truncation that
    /// reads as "those transactions never happened".
    ///
    /// `MemChainStore` cannot produce this state (it inserts the header and the
    /// block together), so the gap is injected by a wrapper that answers `None` for
    /// one hash and delegates everything else.
    #[test]
    fn a_gap_in_the_store_stops_the_walk_and_never_shortens_the_list() {
        struct Gapped<'a> {
            inner: &'a qlab_node::MemChainStore,
            hide: Hash32,
        }
        impl ChainStore for Gapped<'_> {
            fn put_block(
                &mut self,
                _b: StoredBlock,
            ) -> Result<Hash32, qlab_devnet::chain::InsertError> {
                unreachable!("read-only in this test")
            }
            fn genesis_block_hash(&self) -> Hash32 {
                self.inner.genesis_block_hash()
            }
            fn tip_hash(&self) -> Hash32 {
                self.inner.tip_hash()
            }
            fn tip_height(&self) -> u64 {
                self.inner.tip_height()
            }
            fn finalized_hash(&self) -> Option<Hash32> {
                self.inner.finalized_hash()
            }
            fn finalized_height(&self) -> Option<u64> {
                self.inner.finalized_height()
            }
            fn block(&self, hash: &Hash32) -> Option<&StoredBlock> {
                if *hash == self.hide {
                    return None;
                }
                self.inner.block(hash)
            }
            fn contains(&self, hash: &Hash32) -> bool {
                self.inner.contains(hash)
            }
            fn set_finalized(
                &mut self,
                _h: Hash32,
            ) -> Result<(), qlab_devnet::chain::FinalizeMarkError> {
                unreachable!("read-only in this test")
            }
            fn restore_finalized(
                &mut self,
                _h: Hash32,
                _height: u64,
            ) -> Result<(), qlab_devnet::chain::RestoreFinalizedError> {
                unreachable!("read-only in this test")
            }
        }

        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let mut prev = chain.tip_hash();
        let mut hashes = vec![prev];
        for h in 1..=4u64 {
            let mut b = stored_block(h, vec![stored_tx(h as u8, 1_000, 2, 2, 8)]);
            b.header.prev = prev;
            prev = chain.put_block(b).expect("link");
            hashes.push(prev);
        }
        let mut view = TxListView::default();
        view.refresh(&chain);
        assert_eq!(view.tx_count(), 4, "four transactions, one per height");

        // Now hide height 2 and force a re-walk by moving the tip.
        let mut b5 = stored_block(5, vec![stored_tx(5, 1_000, 2, 2, 8)]);
        b5.header.prev = prev;
        chain.put_block(b5).expect("link");
        // The old tip is still an ancestor, so this would take the extension path;
        // hide it too, so the walk has to run past the gap.
        let gapped = Gapped { inner: &chain, hide: hashes[4] };
        let mut from_scratch = TxListView { tip_hash: Some([0xde; 32]), ..view.clone() };

        assert!(from_scratch.refresh(&gapped));
        assert_eq!(from_scratch.tip_height, 5);
        assert_eq!(
            from_scratch.blocks.iter().map(|b| b.height).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5],
            "height 5 freshly walked; 1–4 retained from the previous projection because the \
             walk stopped at the gap and only re-describes what it actually walked. Nothing \
             below a gap is ever dropped."
        );
        assert_eq!(from_scratch.tx_count(), 5, "and no transaction went missing");
    }

    #[test]
    fn the_shared_slot_swaps_only_when_the_chain_moved() {
        let mut chain = qlab_node::MemChainStore::new(stored_block(0, vec![]));
        let slot = Mutex::new(Arc::new(TxListView::default()));
        assert!(refresh_shared(&slot, &chain), "first projection");
        assert!(!refresh_shared(&slot, &chain), "no chain movement, no swap");

        let mut b1 = stored_block(1, vec![stored_tx(1, 1_000, 2, 2, 8)]);
        b1.header.prev = chain.tip_hash();
        chain.put_block(b1).expect("link");
        assert!(refresh_shared(&slot, &chain));
        assert_eq!(slot.lock().unwrap().tx_count(), 1);
    }

    // ---- the document --------------------------------------------------------

    #[test]
    fn the_document_is_versioned_json_carrying_d1s_facts_and_d3s_sentence() {
        let view = view_of(6000, vec![(4913, vec![stored_tx(0x5a, 1_000_000, 2, 2, 64)])]);
        let p = page(&view, 4900, 5000);
        let s = document(&p);
        let v = parse(&s);

        assert_eq!(v["v"], TXLIST_VERSION, "the document is versioned");
        assert_eq!(v["tip_height"], 6000);
        assert_eq!(v["range"]["from"], 4900);
        assert_eq!(v["range"]["to"], 5000);
        assert_eq!(v["range"]["covered_to"], 5000);

        let b = &v["blocks"][0];
        assert_eq!(b["height"], 4913);
        assert_eq!(b["tx_count"], 1, "D1's per-block count, on the wire");
        assert_eq!(
            b["tx_count"].as_u64().unwrap() as usize,
            b["txs"].as_array().unwrap().len(),
            "and derived from the list beside it, so it cannot disagree"
        );

        let t = &b["txs"][0];
        assert_eq!(t["txid"], hex32(&p.blocks[0].txs[0].txid));
        assert_eq!(t["fee"], 1_000_000);
        assert_eq!(t["nullifiers"], 2);
        assert_eq!(t["commitments"], 2);
        assert!(t["wire_bytes"].as_u64().unwrap() > 64);

        assert_eq!(v["boundary"], BOUNDARY_SENTENCE, "D3 rides in the document");
    }

    /// 🔴 D1's exclusion as a **negative** pin over the raw bytes: the document
    /// has no key for anything the chain does not publish, and no such key may
    /// arrive later by accident.
    #[test]
    fn the_document_carries_no_amount_address_or_party_key() {
        let view = view_of(100, vec![(7, vec![stored_tx(1, 1_000_000, 2, 2, 64)])]);
        let s = document(&page(&view, 0, 100));
        // The data half — everything before D3's sentence, which naturally uses
        // the very words this pin forbids ("no amounts, no addresses…") and would
        // otherwise be the one thing that trips it.
        let data = s.split("\"boundary\":\"").next().expect("a data half");
        for forbidden in [
            "amount", "value", "address", "recipient", "sender", "balance", "note", "memo",
            "payload", "proof", "anchor", "nullifier\"", "commitment\"",
        ] {
            assert!(
                !data.contains(forbidden),
                "`{forbidden}` must not appear on this surface: {data}"
            );
        }
        // The counts are counts, and their key names say so.
        let v = parse(&s);
        assert!(v["blocks"][0]["txs"][0]["nullifiers"].is_u64());
        assert!(v["blocks"][0]["txs"][0]["commitments"].is_u64());
    }

    /// `covered_to` is `null` and never a number a `|| 0` could turn into height
    /// zero — the same rule `json::num` records for a height that does not exist.
    #[test]
    fn absent_coverage_is_null_on_the_wire_and_never_a_zero() {
        let view = view_of(10, vec![]);
        let v = parse(&document(&page(&view, 99, 200)));
        assert!(v["range"]["covered_to"].is_null(), "absent, not 0");
        assert_eq!(v["blocks"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn an_empty_page_is_still_a_complete_document() {
        let v = parse(&document(&page(&TxListView::default(), 0, 0)));
        assert_eq!(v["v"], TXLIST_VERSION);
        assert_eq!(v["range"]["covered_to"], 0);
        assert_eq!(v["boundary"], BOUNDARY_SENTENCE);
    }

    // ---- goldens (the explorer-split decision §4 discipline) -----------------

    /// Keccak-256 over the four golden documents concatenated, in **source**, so a
    /// blind file regeneration cannot make the goldens pass by itself.
    const GOLDEN_DIGEST: &str =
        "3fe6ac64951401a4f000c479c3dc7c2c4058ad3b171ac24da5d904ebde62ada8";

    /// The four states `qumbra-explorer-web` renders, and the **same bytes** it
    /// asserts against. One artifact, two directions: a field renamed on either
    /// side of the repo boundary turns one of the two red.
    ///
    /// The shape is the live chain's — transaction blocks at 4913 / 5398 / 5406 /
    /// 5417 / 5924 over 6,000 heights — because the front end's hardest rendering
    /// case is a mostly-empty range, not a dense one.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let live: Vec<(u64, Vec<StoredTx>)> = [4913u64, 5398, 5406, 5417, 5924]
            .iter()
            .enumerate()
            .map(|(i, h)| {
                (
                    *h,
                    vec![stored_tx(0x10 + i as u8, 1_000_000, 2, 2, 256)],
                )
            })
            .collect();
        let view = view_of(6000, live);
        let two_txs = view_of(
            6000,
            vec![(
                5406,
                vec![
                    stored_tx(0x21, 1_000_000, 2, 2, 256),
                    stored_tx(0x22, 2_000_000, 2, 2, 256),
                ],
            )],
        );
        vec![
            // The page a reader lands on: the recent end of the chain, three tx
            // blocks in it.
            ("txlist-recent", document(&page(&view, 5000, 6000))),
            // A block carrying more than one transaction.
            ("txlist-multi-tx-block", document(&page(&two_txs, 5400, 5410))),
            // 🔴 A covered range with nothing in it — the page that must not read
            // as "this chain has no transactions".
            ("txlist-empty-covered", document(&page(&view, 0, 500))),
            // 🔴 A request past the tip: no coverage at all.
            ("txlist-no-coverage", document(&page(&view, 9000, 9100))),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors. Update them only with an
    /// intentional, documented shape change, and note that regenerating is not
    /// enough on its own: [`golden_digest_locks_the_regenerated_files`] pins a
    /// digest in source that a blind regeneration leaves red.
    #[test]
    fn golden_files_match_the_encoder_byte_for_byte() {
        for (name, produced) in golden_cases() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("goldens")
                .join(name);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("golden {name} missing at {}: {e}", path.display()));
            assert_eq!(
                on_disk.trim_end_matches('\n'),
                produced,
                "golden {name} drifted — see this test's docs before updating the file"
            );
        }
    }

    /// The goldens also have to be *readable* in the direction the front end reads
    /// them: parse each file and run the client rules over it. A vector that only
    /// the producer can consume is not a contract.
    #[test]
    fn the_goldens_decode_and_the_client_rules_run_over_them() {
        for (name, produced) in golden_cases() {
            let v = parse(&produced);
            assert_eq!(v["v"], TXLIST_VERSION, "{name} is versioned");
            assert_eq!(v["boundary"], BOUNDARY_SENTENCE, "{name} carries D3");
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
        let hex: String = qlab_note::hash::keccak256(all.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
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
