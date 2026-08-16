//! Coinbase detection — the wallet half of lab #415.
//!
//! ## The defect this closes
//!
//! A scan computes `spendable` from the compact wire, and `CompactBlock` is
//! `{ height, groups }`: it carries no `coinbase_rkm` and never has. The compact
//! wire is a wallet's only source, so **no wallet has ever been able to detect a
//! coinbase note** — a mining-only wallet read `spendable: 0 · complete` forever,
//! on a chain where its own key mined every block. `qumbra-faucet` finds its own
//! coinbase by walking its node's main chain (`harvest.rs`); it can, because it
//! *is* a node, and a wallet by design is not.
//!
//! That is lab #314's shape — a confident figure over a half nobody had — one
//! dimension further out, and #309/#312's shape (an answer that could not know,
//! printed as one that did) one surface over.
//!
//! ## The shape, and the line it does not cross
//!
//! The node serves the coinbase facts each block committed, in bulk over a range
//! (`GET /v1/coinbase`, [`qlab_cbserver::codec::CoinbasePage`]). This module
//! matches those payees against **this wallet's own** `rkm` lanes, locally.
//!
//! 🔴 **There is no "did this key mine anything" query and there must never be
//! one.** The bytes are as public as bytes get — every block prints its payee as
//! a condition of being valid — but a per-key probe would tell the server which
//! miner is asking, which is the same leak `/v1/nullifiers` refuses in its own
//! shape. What a probe adds is the *question*.
//!
//! ## One derivation, not a second formula
//!
//! [`qlab_node::coinbase_note_parts`] is what `apply_state` runs when it appends
//! the leaf, and this module calls it rather than restating it. That is the whole
//! correctness argument, and it is sharper here than it was for the nullifier
//! subtraction: a wrong value produces a wrong commitment, a wrong commitment is
//! in no tree, and the note would be both a wrong balance **and** unspendable —
//! failing at the witness lookup with nothing pointing at the arithmetic.
//!
//! In particular the amount is **not** the emission schedule's value at that
//! height. It is the miner's frozen §3 share of what the block declared, plus
//! that block's fees, less the burned name-fee portion (lab #367) — and on this
//! chain's own history the declared issuance is not always the schedule's either
//! (height 1377, #299's grandfathered scar).
//!
//! ## Coverage is load-bearing here too
//!
//! A coinbase figure is quotable only where the stream reached, and only where
//! the **nullifier** stream also reached: a mined note can be spent like any
//! other, and a coinbase balance that could not subtract spends would re-open
//! lab #314 on the category this module just made visible. Every refusal is
//! named; none of them is a zero.

use qlab_cbserver::codec::BlockCoinbase;
use qlab_node::{coinbase_leaf_appears_at, coinbase_maturity, CoinbaseMaturity};
use qlab_note::note::Note;
use qlab_wallet::Wallet;

use crate::spent::{note_nullifier, SpentSet};

/// The stable token every surface prints when it could not see coinbase — the
/// scan's balance line, and since lab #424 the **send**'s input selection too.
///
/// It exists for the reason `UNAVAILABLE` does in [`crate::view`]: one grep has
/// to cover every surface, or a degradation gets reworded on one of them and
/// stops being findable. Never reword it in a caller; interpolate it.
pub const TRANSACTIONS_ONLY: &str = "TRANSACTIONS ONLY";

/// One bounded response from the coinbase stream — the wallet-side shape of
/// [`qlab_cbserver::codec::CoinbasePage`], field for field, so there is no
/// second reading of that framing here ([`crate::spent::NullifierChunk`]'s
/// discipline).
#[derive(Clone, Debug)]
pub struct CoinbaseChunk {
    /// The server's **echo** of the requested `from`. Checked, not trusted.
    pub from: u64,
    /// The server's echo of the requested `to`.
    pub to: u64,
    /// Every main-chain block the server holds in the range, ascending —
    /// including the ones that mint nothing, which are present with the
    /// `[0; 4]` no-payee sentinel. An omitted height would be
    /// indistinguishable from an unserved one.
    pub blocks: Vec<BlockCoinbase>,
}

/// Where the per-block coinbase facts come from.
/// [`crate::net::HttpCoinbaseSource`] serves it over `GET /v1/coinbase`.
pub trait CoinbaseSource {
    /// One bounded page for `[from, to]`. An `Err` is a transport/decode
    /// failure, verbatim — the caller turns it into the named refusal.
    fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String>;
}

/// Every way coinbase detection refuses, each with its reason named — the same
/// no-boolean-blindness house style as [`crate::spent::SpentRefusal`], whose
/// variants these deliberately mirror one for one. Two streams that refuse in
/// the same vocabulary can be reported in the same sentence.
#[derive(Debug, PartialEq, Eq)]
pub enum CoinbaseRefusal {
    /// The endpoint could not be reached, or its response did not decode. **On a
    /// node that predates this route it is a 404, and that is the honest
    /// answer**: this node cannot tell you what it mined for you. It is also the
    /// state every deployed host is in until it is rolled, which is why the
    /// verdict language stays narrowed unless this succeeds.
    Endpoint { why: String },
    /// The page answers a range nobody asked for. The wire echoes both bounds
    /// precisely so a paging client cannot misattribute a response.
    RangeMismatch { asked: (u64, u64), got: (u64, u64) },
    /// A page carried a height outside the range it answers.
    OutOfRange { height: u64, asked: (u64, u64) },
    /// Heights arrived out of order or repeated. Ascending order is what makes
    /// "covered up to N" a claim rather than a hope.
    NotAscending { previous: u64, height: u64 },
    /// 🔴 A height is **missing** from the middle of the stream. Never tolerated
    /// and never interpolated: a hole is indistinguishable from a block somebody
    /// else mined once it is smoothed over, and that is exactly how a miner's
    /// own block goes missing from their own balance.
    Gap { expected: u64, got: u64 },
    /// The stream does not cover the heights being reported on. Refused rather
    /// than under-counted — a partial coinbase balance reads as a whole one.
    NotCovered { covered: Option<(u64, u64)>, wanted: (u64, u64) },
}

impl std::fmt::Display for CoinbaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoinbaseRefusal::Endpoint { why } => write!(
                f,
                "the coinbase stream could not be read ({why}). This scan cannot see mined \
                 coins — if this wallet mines, its balance below is {TRANSACTIONS_ONLY}"
            ),
            CoinbaseRefusal::RangeMismatch { asked, got } => write!(
                f,
                "coinbase page refused: asked for heights {}..={} and it answered for {}..={}. \
                 The wire echoes both bounds so a page cannot be misattributed",
                asked.0, asked.1, got.0, got.1
            ),
            CoinbaseRefusal::OutOfRange { height, asked } => write!(
                f,
                "coinbase page refused: it carries height {height}, outside the {}..={} it answers",
                asked.0, asked.1
            ),
            CoinbaseRefusal::NotAscending { previous, height } => write!(
                f,
                "coinbase page refused: height {height} follows {previous} — the stream must be \
                 ascending, or 'covered up to N' means nothing"
            ),
            CoinbaseRefusal::Gap { expected, got } => write!(
                f,
                "coinbase stream refused: height {expected} is missing (the next height served \
                 was {got}). A hole is not somebody else's block — refusing to treat 'I was not \
                 told' as 'you did not mine that one'"
            ),
            CoinbaseRefusal::NotCovered { covered, wanted } => write!(
                f,
                "coinbase stream refused: it covers {} but this scan asked about {}..={}. Blocks \
                 in the uncovered span may have paid this wallet, so a mined figure cannot be \
                 quoted for this range",
                match covered {
                    Some((a, b)) => format!("{a}..={b}"),
                    None => "nothing".to_string(),
                },
                wanted.0,
                wanted.1
            ),
        }
    }
}

impl std::error::Error for CoinbaseRefusal {}

/// The chain's per-block coinbase facts over a range, and **how much of that
/// range the stream actually covered** — the second being the part a figure
/// depends on.
///
/// The facts are kept verbatim rather than reduced to "notes that are ours" at
/// fetch time, because the wallet's own key set is a caller's concern and
/// because the same fetched range serves every allocated index.
#[derive(Clone, Debug, Default)]
pub struct MinedChain {
    /// The contiguous height range actually served, or `None` when the endpoint
    /// held no block in the requested range at all.
    pub covered: Option<(u64, u64)>,
    /// Every block in `covered`, ascending — one entry per height.
    pub blocks: Vec<BlockCoinbase>,
}

impl MinedChain {
    /// Does this stream cover every height a report is about?
    ///
    /// `None` means nothing was asked about, so there is nothing to cover.
    /// Both ends matter: an uncovered head hides an early block this wallet
    /// mined, an uncovered tail hides the most recent ones — which is the half
    /// a miner actually watches.
    pub fn covers(&self, wanted: Option<(u64, u64)>) -> Result<(), CoinbaseRefusal> {
        let Some(wanted) = wanted else { return Ok(()) };
        match self.covered {
            Some((from, to)) if from <= wanted.0 && to >= wanted.1 => Ok(()),
            covered => Err(CoinbaseRefusal::NotCovered { covered, wanted }),
        }
    }

    /// The highest height this stream covers — the tip the maturity split is
    /// stated **as of**. `None` when nothing was served.
    ///
    /// It is a lower bound on the chain's real tip by construction (a node only
    /// grows), which is the safe direction: a note reported as maturing may
    /// already have matured, and no note is ever reported spendable before its
    /// leaf exists.
    pub fn as_of(&self) -> Option<u64> {
        self.covered.map(|(_, to)| to)
    }
}

/// Page the coinbase stream over `[from, to]` — the client half of the #312
/// paging contract on a third route, shipped in the same change as the server's
/// bound because a truncated page that read as a complete one is the failure
/// this whole issue is an instance of.
///
/// The loop resumes at the last served height + 1 and stops when a page reaches
/// `to` or when the endpoint serves nothing further. Contiguity is checked as it
/// goes and is also the progress guard: a page that does not continue where the
/// last one ended is a named refusal rather than another lap.
pub fn fetch_coinbase(
    source: &impl CoinbaseSource,
    from: u64,
    to: u64,
) -> Result<MinedChain, CoinbaseRefusal> {
    let mut catch = CoinbaseCatchUp::new(from, to);
    while let Some((from, to)) = catch.want() {
        let page = source.fetch_range(from, to).map_err(|why| CoinbaseRefusal::Endpoint { why })?;
        catch.supply(page)?;
    }
    Ok(catch.finish())
}

/// The page-accumulation half of [`fetch_coinbase`], caller-pumped — **one copy
/// of the paging protocol** ([`crate::spent::SpentCatchUp`]'s shape, lab #399),
/// so a sans-I/O host cannot skip a check the synchronous pump makes.
pub struct CoinbaseCatchUp {
    chain: MinedChain,
    cursor: u64,
    to: u64,
    done: bool,
}

impl CoinbaseCatchUp {
    pub fn new(from: u64, to: u64) -> CoinbaseCatchUp {
        CoinbaseCatchUp { chain: MinedChain::default(), cursor: from, to, done: false }
    }

    /// The `(from, to)` range to ask the endpoint for next, or `None` once the
    /// stream is complete.
    pub fn want(&self) -> Option<(u64, u64)> {
        (!self.done).then_some((self.cursor, self.to))
    }

    /// Feed one page — echo, in-range, ascending and gap-free checks included.
    pub fn supply(&mut self, page: CoinbaseChunk) -> Result<(), CoinbaseRefusal> {
        if self.done {
            return Err(CoinbaseRefusal::Endpoint {
                why: "a page was supplied after the stream completed".into(),
            });
        }
        if (page.from, page.to) != (self.cursor, self.to) {
            return Err(CoinbaseRefusal::RangeMismatch {
                asked: (self.cursor, self.to),
                got: (page.from, page.to),
            });
        }
        if page.blocks.is_empty() {
            self.done = true; // the endpoint holds nothing (further) in the range
            return Ok(());
        }
        for blk in page.blocks {
            let height = blk.height;
            if height < self.cursor || height > self.to {
                return Err(CoinbaseRefusal::OutOfRange { height, asked: (self.cursor, self.to) });
            }
            match self.chain.covered {
                Some((_, prev)) if height <= prev => {
                    return Err(CoinbaseRefusal::NotAscending { previous: prev, height })
                }
                Some((_, prev)) if height != prev + 1 => {
                    return Err(CoinbaseRefusal::Gap { expected: prev + 1, got: height })
                }
                _ => {}
            }
            self.chain.covered = Some((self.chain.covered.map_or(height, |(f, _)| f), height));
            self.chain.blocks.push(blk);
        }
        let (_, last) = self.chain.covered.expect("a non-empty page set it");
        if last >= self.to {
            self.done = true;
        } else {
            self.cursor = last + 1;
        }
        Ok(())
    }

    pub fn finish(self) -> MinedChain {
        self.chain
    }
}

/// One coinbase note this wallet mined, and where it stands.
#[derive(Clone, Debug)]
pub struct MinedNote {
    /// The height whose block minted it — the note's identity, since a coinbase
    /// has no transaction slot (its ρ *is* its height, `qlab_node::coinbase_rho`).
    pub minted_height: u64,
    /// The diversifier index whose `rkm` the block paid.
    pub div_index: u64,
    /// The note itself, reconstructed through the applier's own derivation.
    pub note: Note,
    /// Whether its leaf is in the commitment tree yet, and if not, when — the
    /// frozen §2 delay, answered by `qlab_node::coinbase_maturity` rather than
    /// by a copy of `COINBASE_MATURITY_BLOCKS` here.
    pub maturity: CoinbaseMaturity,
    /// `Some(height)` when the chain has already published this note's
    /// nullifier: it is gone, and the report says so rather than counting it.
    pub spent_height: Option<u64>,
}

impl MinedNote {
    /// Spendable **as far as the tree is concerned**: matured and unspent.
    ///
    /// A lower bound on spendability, not a sufficient condition — a spend also
    /// needs a finalized anchor covering the leaf's height, so a note that just
    /// matured may still be a checkpoint cadence away from being provable
    /// (`qumbra_faucet::harvest::spendable_at_tip` states the same caveat for
    /// the same reason). Reporting it here would need the anchor set, which this
    /// module deliberately does not fetch; the send path refuses with the exact
    /// height if it is asked too early.
    pub fn is_spendable(&self) -> bool {
        self.spent_height.is_none() && matches!(self.maturity, CoinbaseMaturity::Matured { .. })
    }
}

/// This wallet's mined notes over a covered range, partitioned by what can be
/// done with them.
#[derive(Clone, Debug, Default)]
pub struct MinedReport {
    /// Matured, unspent. This is the list a balance adds.
    pub spendable: Vec<MinedNote>,
    /// Mined but not yet matured — real money this wallet owns and cannot spend
    /// yet. **Never folded into the spendable figure**, and never omitted
    /// either: "when can I spend it" is a miner's second question, and a report
    /// that answers only the first invites the conclusion that the coins are
    /// missing.
    pub maturing: Vec<MinedNote>,
    /// Mined and already spent (its nullifier is on the chain). Reported, never
    /// counted — lab #314's rule on this category.
    pub spent: Vec<MinedNote>,
    /// The tip height the split is stated as of — the highest height the
    /// coinbase stream covered.
    pub as_of: u64,
}

impl MinedReport {
    /// The value a caller may credit.
    pub fn spendable_value(&self) -> u128 {
        self.spendable.iter().map(|n| u128::from(n.note.value)).sum()
    }

    /// The value that exists and cannot be spent yet.
    pub fn maturing_value(&self) -> u128 {
        self.maturing.iter().map(|n| u128::from(n.note.value)).sum()
    }

    /// The value already spent out of this range — reported, never credited.
    pub fn spent_value(&self) -> u128 {
        self.spent.iter().map(|n| u128::from(n.note.value)).sum()
    }

    /// The **tip height** at which the earliest maturing note becomes
    /// spendable, if any is outstanding — the number the whole "why can I not
    /// spend this yet" answer is built from.
    pub fn next_maturity(&self) -> Option<u64> {
        self.maturing.iter().map(|n| coinbase_leaf_appears_at(n.minted_height)).min()
    }

    /// Blocks this wallet mined in the covered range, in every state.
    pub fn blocks_mined(&self) -> usize {
        self.spendable.len() + self.maturing.len() + self.spent.len()
    }
}

/// Match `chain`'s payees against the `rkm` of each allocated diversifier index,
/// reconstruct every note this wallet mined, and split it by maturity and by
/// whether the chain has already consumed it.
///
/// `indices` are the wallet's allocated indices — the same set the scan covers,
/// so an address that can receive is an address that can mine. `spent` is the
/// nullifier set already fetched for the balance; a coinbase note's nullifier is
/// derived exactly as a spend derives it ([`crate::spent::note_nullifier`]), so
/// there is no second formula here either.
///
/// 🔴 **The `[0; 4]` payee is never matched, whatever a wallet's key is.** A
/// non-minting block carries it as a sentinel, and treating it as an identity
/// would credit every wallet with genesis.
pub fn match_mined(
    wallet: &Wallet,
    indices: &[u64],
    chain: &MinedChain,
    spent: &SpentSet,
) -> MinedReport {
    let tip = chain.as_of().unwrap_or(0);
    let mut report = MinedReport { as_of: tip, ..MinedReport::default() };
    // One rkm per allocated index, derived once rather than per block.
    let mine: Vec<(u64, [u64; 4])> = indices
        .iter()
        .map(|&idx| (idx, wallet.rkm(wallet.diversifier_at_index(idx))))
        .collect();

    for blk in &chain.blocks {
        if blk.coinbase_rkm == [0u64; 4] {
            continue; // the no-payee sentinel is nobody's, including ours
        }
        let Some(&(div_index, _)) = mine.iter().find(|(_, rkm)| *rkm == blk.coinbase_rkm) else {
            continue; // somebody else's block
        };
        // The applier's own derivation — see the module docs on why a second
        // formula here would be worse than a wrong number.
        let Some(note) = qlab_node::coinbase_note_parts(
            blk.height,
            blk.coinbase_rkm,
            blk.coinbase,
            blk.fees,
            blk.name_burn,
        ) else {
            continue; // a block that minted nothing
        };
        let nf = note_nullifier(wallet, div_index, &note);
        let mined = MinedNote {
            minted_height: blk.height,
            div_index,
            note,
            maturity: coinbase_maturity(blk.height, tip),
            spent_height: spent.height_of(&nf),
        };
        match (mined.spent_height, mined.maturity) {
            (Some(_), _) => report.spent.push(mined),
            (None, CoinbaseMaturity::Matured { .. }) => report.spendable.push(mined),
            (None, CoinbaseMaturity::Immature { .. }) => report.maturing.push(mined),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::MasterSeed;

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([0x41; 32]), 0)
    }

    fn blk(height: u64, rkm: [u64; 4], coinbase: u64) -> BlockCoinbase {
        BlockCoinbase { height, coinbase_rkm: rkm, coinbase, fees: 0, name_burn: 0 }
    }

    /// An honest endpoint over a contiguous chain, serving bounded pages and
    /// recording every `(from, to)` it was asked for.
    struct Honest {
        blocks: Vec<BlockCoinbase>,
        page: usize,
        asked: std::cell::RefCell<Vec<(u64, u64)>>,
    }

    impl Honest {
        fn mined_by(heights: std::ops::RangeInclusive<u64>, rkm: [u64; 4], page: usize) -> Honest {
            Honest {
                blocks: heights.map(|h| blk(h, rkm, 5_000)).collect(),
                page,
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl CoinbaseSource for Honest {
        fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String> {
            self.asked.borrow_mut().push((from, to));
            let blocks = self
                .blocks
                .iter()
                .filter(|b| b.height >= from && b.height <= to)
                .take(self.page)
                .cloned()
                .collect();
            Ok(CoinbaseChunk { from, to, blocks })
        }
    }

    /// The client half of the paging contract: a bounded server is paged until
    /// the range is in hand, resuming from the last height + 1 — #312's rule on
    /// a third route. A single-fetch client would have covered only the first
    /// page and reported the rest of the chain as "you mined nothing there".
    #[test]
    fn the_stream_is_paged_until_the_range_is_in_hand() {
        let src = Honest::mined_by(0..=9, [7; 4], 4);
        let chain = fetch_coinbase(&src, 0, 9).expect("an honest stream pages");
        assert_eq!(chain.covered, Some((0, 9)));
        assert_eq!(chain.blocks.len(), 10, "every block's coinbase arrived");
        assert_eq!(
            *src.asked.borrow(),
            vec![(0, 9), (4, 9), (8, 9)],
            "resume at the last height + 1, never from the start"
        );
        assert_eq!(chain.as_of(), Some(9));
        assert!(chain.covers(Some((0, 9))).is_ok());
    }

    /// 🔴 A stream short of the range refuses rather than under-counting — the
    /// #309/#312 property from the client's side. The endpoint stops at 6 while
    /// the scan asked to 9: named refusal, no number.
    #[test]
    fn a_stream_short_of_the_range_refuses_rather_than_under_counting() {
        let src = Honest::mined_by(0..=6, [7; 4], 100);
        let chain = fetch_coinbase(&src, 0, 9).expect("the pages themselves are well-formed");
        assert_eq!(chain.covered, Some((0, 6)), "it covers what it served, honestly");
        let e = chain.covers(Some((0, 9))).unwrap_err();
        assert_eq!(e, CoinbaseRefusal::NotCovered { covered: Some((0, 6)), wanted: (0, 9) });
        assert!(e.to_string().contains("cannot be quoted"), "{e}");
        // …and covering exactly as far as asked is enough.
        assert!(chain.covers(Some((0, 6))).is_ok());
        assert!(chain.covers(None).is_ok());
    }

    /// A hole is not somebody else's block. Smoothing one over is how a miner's
    /// own block disappears from their own balance, so it is a named refusal.
    #[test]
    fn a_missing_height_is_a_gap_and_never_read_as_another_miners_block() {
        struct Holed;
        impl CoinbaseSource for Holed {
            fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String> {
                Ok(CoinbaseChunk {
                    from,
                    to,
                    blocks: vec![blk(0, [0; 4], 0), blk(2, [7; 4], 5_000)],
                })
            }
        }
        let e = fetch_coinbase(&Holed, 0, 3).unwrap_err();
        assert_eq!(e, CoinbaseRefusal::Gap { expected: 1, got: 2 });
        assert!(e.to_string().contains("not somebody else's block"), "{e}");

        // A hole ACROSS a page boundary is the same fault.
        struct HoledAcrossPages;
        impl CoinbaseSource for HoledAcrossPages {
            fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String> {
                let blocks = if from == 0 {
                    vec![blk(0, [0; 4], 0), blk(1, [7; 4], 5_000)]
                } else {
                    vec![blk(3, [7; 4], 5_000)]
                };
                Ok(CoinbaseChunk { from, to, blocks })
            }
        }
        assert_eq!(
            fetch_coinbase(&HoledAcrossPages, 0, 5).unwrap_err(),
            CoinbaseRefusal::Gap { expected: 2, got: 3 }
        );
    }

    /// The bound echoes are checked, not decorative, and out-of-order heights
    /// are refused — the two ways a page could be misattributed.
    #[test]
    fn a_page_answering_a_different_range_or_going_backwards_is_refused() {
        struct WrongEcho;
        impl CoinbaseSource for WrongEcho {
            fn fetch_range(&self, _: u64, _: u64) -> Result<CoinbaseChunk, String> {
                Ok(CoinbaseChunk { from: 7, to: 9, blocks: vec![] })
            }
        }
        assert_eq!(
            fetch_coinbase(&WrongEcho, 0, 9).unwrap_err(),
            CoinbaseRefusal::RangeMismatch { asked: (0, 9), got: (7, 9) }
        );

        struct Backwards;
        impl CoinbaseSource for Backwards {
            fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String> {
                Ok(CoinbaseChunk {
                    from,
                    to,
                    blocks: vec![blk(0, [0; 4], 0), blk(1, [7; 4], 1), blk(1, [7; 4], 1)],
                })
            }
        }
        assert_eq!(
            fetch_coinbase(&Backwards, 0, 3).unwrap_err(),
            CoinbaseRefusal::NotAscending { previous: 1, height: 1 }
        );
    }

    /// 🔴 **An endpoint that does not serve this route — every node older than
    /// lab #415 — is a named refusal carrying its own words, never an empty
    /// stream.** An empty stream would read as "you mined nothing", which is
    /// the exact sentence this whole issue exists to stop a wallet from saying.
    #[test]
    fn an_absent_route_is_a_refusal_not_an_empty_stream() {
        struct Down;
        impl CoinbaseSource for Down {
            fn fetch_range(&self, _: u64, _: u64) -> Result<CoinbaseChunk, String> {
                Err("non-200 response: HTTP 404".into())
            }
        }
        let e = fetch_coinbase(&Down, 0, 9).unwrap_err();
        assert!(matches!(e, CoinbaseRefusal::Endpoint { .. }));
        assert!(e.to_string().contains("404"), "{e}");
        assert!(e.to_string().contains("TRANSACTIONS ONLY"), "and it says what is lost: {e}");
    }

    /// 🔴 **The acceptance shape, in-process: a wallet whose rkm mined blocks
    /// reads NON-ZERO, split into spendable and maturing.**
    ///
    /// The chain here pays index 0 at heights 1..=3 and pays a stranger
    /// everywhere else. With the tip far above maturity for the first block and
    /// below it for the last, the split is a real one rather than an all-or-
    /// nothing.
    #[test]
    fn a_mining_wallets_own_blocks_are_found_and_split_by_maturity() {
        let w = wallet();
        let mine = w.rkm(w.diversifier_at_index(0));
        let theirs = [0xDEu64, 0xAD, 0xBE, 0xEF];
        assert_ne!(mine, theirs);

        // Block 1 matures at 1 + 144 = 145; block 200 does not, at tip 200.
        let tip = coinbase_leaf_appears_at(1) + 55;
        let mut blocks = vec![blk(0, [0; 4], 0)];
        for h in 1..=tip {
            let payee = if h == 1 || h == 2 || h == tip { mine } else { theirs };
            blocks.push(blk(h, payee, 5_000));
        }
        let chain = MinedChain { covered: Some((0, tip)), blocks };

        let report = match_mined(&w, &[0], &chain, &SpentSet::default());
        assert_eq!(report.as_of, tip, "the split is stated as of the height it was read at");
        assert_eq!(report.blocks_mined(), 3, "three blocks paid this wallet");
        assert_eq!(report.spendable.len(), 2, "the two old ones have leaves");
        assert_eq!(report.maturing.len(), 1, "the newest one does not yet");
        assert!(report.spendable_value() > 0, "🔴 a mining-only wallet reads NON-ZERO");
        assert_eq!(report.maturing_value(), u128::from(report.maturing[0].note.value));
        assert_eq!(
            report.next_maturity(),
            Some(coinbase_leaf_appears_at(tip)),
            "and it says WHEN, which is a miner's second question"
        );

        // The value is the applier's, not the schedule's: 5_000 declared, of
        // which the miner takes the frozen §3 share.
        assert_eq!(
            report.spendable[0].note.value,
            qlab_node::RewardSplit::of(5_000).miner,
            "the whole declared issuance is NOT the miner's"
        );
        // And the note is the one a node would have appended.
        let body = qlab_devnet::body::BlockBody {
            txs: vec![],
            coinbase: 5_000,
            coinbase_rkm: mine,
        };
        assert_eq!(
            Some(report.spendable[0].note.clone()),
            qlab_node::coinbase_note(1, &body),
            "the wallet's reconstruction IS the applier's derivation"
        );
    }

    /// Another miner's blocks are never this wallet's, however tall the chain
    /// gets — and neither is the `[0; 4]` sentinel, which would otherwise credit
    /// every wallet with every non-minting block.
    #[test]
    fn another_miners_blocks_and_the_no_payee_sentinel_are_never_matched() {
        let w = wallet();
        let chain = MinedChain {
            covered: Some((0, 3)),
            blocks: vec![
                blk(0, [0; 4], 0),
                blk(1, [0xDE, 0xAD, 0xBE, 0xEF], 5_000),
                // A block that names the sentinel as a payee while minting: not
                // reachable through `validate_body`, refused here anyway.
                blk(2, [0; 4], 5_000),
                blk(3, [1, 2, 3, 4], 5_000),
            ],
        };
        let report = match_mined(&w, &[0, 1, 2], &chain, &SpentSet::default());
        assert_eq!(report.blocks_mined(), 0, "nothing here is ours");
        assert_eq!(report.spendable_value(), 0);
    }

    /// 🔴 **Lab #314's rule on the new category: a mined note whose nullifier is
    /// on the chain stops being spendable, and is reported rather than dropped.**
    ///
    /// Without this the route would have re-opened, for coinbase, exactly the
    /// defect the nullifier stream was built to close — and a miner who has spent
    /// is the wallet most likely to look.
    #[test]
    fn a_mined_note_that_was_already_spent_is_subtracted_and_named() {
        let w = wallet();
        let mine = w.rkm(w.diversifier_at_index(0));
        let tip = coinbase_leaf_appears_at(2) + 10;
        let mut blocks = vec![blk(0, [0; 4], 0)];
        for h in 1..=tip {
            blocks.push(blk(h, if h <= 2 { mine } else { [9; 4] }, 5_000));
        }
        let chain = MinedChain { covered: Some((0, tip)), blocks };

        // Nothing spent yet: two spendable notes.
        let clean = match_mined(&w, &[0], &chain, &SpentSet::default());
        assert_eq!(clean.spendable.len(), 2);
        let spent_note = clean.spendable[0].clone();
        let nf = note_nullifier(&w, 0, &spent_note.note);

        // The chain publishes the first note's nullifier at some later height.
        let spent = SpentSet::from_parts(Some((0, tip)), [(tip - 1, nf)]);
        let after = match_mined(&w, &[0], &chain, &spent);
        assert_eq!(after.spendable.len(), 1, "one note survives");
        assert_eq!(after.spent.len(), 1, "and the spent one is REPORTED, not dropped");
        assert_eq!(after.spent[0].minted_height, spent_note.minted_height);
        assert_eq!(after.spent[0].spent_height, Some(tip - 1), "the chain's own date");
        assert_eq!(after.spendable_value(), spent_note.note.value as u128);
        assert!(!after.spent[0].is_spendable(), "a spent note is not spendable");
    }

    /// 🔴 **The spend leg (lab #415 task-book item 3), verified rather than
    /// asserted: a detected coinbase note is locatable in the commitment tree
    /// through the existing `/v1/tree/*` endpoints, and the pre-proof spend
    /// path accepts it.**
    ///
    /// Nothing here is a fixture standing in for the chain. A real `MemNode`
    /// mines real blocks paying this wallet's `rkm`; the coinbase leaf is
    /// appended by `apply_state` on the frozen §2 schedule; both routes are
    /// served by the **real** `NodeRpc::route` and decoded by the wallet's own
    /// decoders; and the note is then handed to `send::build_bundle`, the same
    /// function `SelectDriver` calls, which locates it by `position_of` and cuts
    /// an `auth_path` against the anchor.
    ///
    /// What this establishes, exactly: the witness path is **not** coinbase-
    /// specific — a mined note is an ordinary leaf of the ordinary tree, and
    /// nothing between the route and the prover needs to know where it came
    /// from. The value being right is load-bearing and is checked here in the
    /// only way that matters: a wrong value would derive a `cm` that is in no
    /// tree, and `build_bundle` would refuse.
    ///
    /// **What it does NOT establish, and the gap is filed rather than implied:**
    /// `spend::select` still builds its `Spendable` set from `ScanOutcome::notes`
    /// alone, so `qumbra-wallet send` will not choose a mined note however
    /// spendable it is. That is leg 2's baton — a new driver phase with its own
    /// refusal discipline for a 404 on this route — and it is filed as **lab
    /// #424** with this test as the evidence that it is small and known-feasible.
    #[test]
    fn a_mined_note_is_locatable_in_the_tree_and_the_spend_path_accepts_it() {
        use qlab_cbserver::codec::CoinbasePage;
        use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
        use qlab_devnet::header::BlockHeader;
        use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
        use qlab_node::{genesis_block, MemNode, NodeRpc, NodeState, TreeLeaves};
        use qlab_wallet::seed::MasterSeed;

        struct NoTx;
        impl TxVerifier for NoTx {
            fn verify_tx(&self, _: &TxEntry) -> bool {
                unreachable!("this chain carries no transactions")
            }
        }

        let w = Wallet::from_master_seed(&MasterSeed::from_entropy([0x5B; 32]), 0);
        let mine = w.rkm(w.diversifier_at_index(0));

        // ---- A real chain this wallet mined, past the maturity delay. -------
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        let last = coinbase_leaf_appears_at(1) + 2;
        for height in 1..=last {
            let body = BlockBody {
                txs: Vec::new(),
                coinbase: qlab_node::coinbase(height),
                coinbase_rkm: mine,
            };
            let header =
                BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
            let hash = node.apply_block(header, body, &NoTx).expect("block applies");
            node.finalize(hash).expect("finalize, so every root is a valid anchor");
            tip = header;
        }
        let rpc = NodeRpc::new(node);

        // ---- The wallet's side: both routes, its own decoders. --------------
        struct RouteSource<'a>(&'a qlab_node::MemNodeRpc);
        impl CoinbaseSource for RouteSource<'_> {
            fn fetch_range(&self, from: u64, to: u64) -> Result<CoinbaseChunk, String> {
                let bytes = self
                    .0
                    .route(&format!("/v1/coinbase?from={from}&to={to}"))
                    .map_err(|(c, m)| format!("{c} {m}"))?;
                let page = CoinbasePage::from_bytes(&bytes).map_err(|e| format!("{e:?}"))?;
                Ok(CoinbaseChunk { from: page.from, to: page.to, blocks: page.blocks })
            }
        }
        let chain = fetch_coinbase(&RouteSource(&rpc), 0, last).expect("the route answers");
        assert!(chain.covers(Some((0, last))).is_ok());

        let report = match_mined(&w, &[0], &chain, &SpentSet::default());
        assert_eq!(report.blocks_mined() as u64, last, "this wallet mined every block");
        assert!(!report.spendable.is_empty(), "and the early ones have matured");
        let mined = report.spendable[0].clone();
        assert_eq!(mined.minted_height, 1, "the oldest matured note is block 1's");

        // The commitment tree, rebuilt from the served leaf stream — the same
        // `/v1/tree/leaves` paging a spend uses, through the same accumulator.
        let mut catch = crate::sync::TreeCatchUp::new(qlab_cbserver::tree::CommitmentTree::new());
        while let Some(from) = catch.want_from() {
            let bytes = rpc.route(&format!("/v1/tree/leaves?from={from}")).expect("served");
            let page = TreeLeaves::from_bytes(&bytes).expect("the node's own wire");
            catch
                .supply(crate::sync::LeafChunk {
                    from: page.from,
                    total: page.total,
                    leaves: page.leaves,
                })
                .expect("an honest stream");
        }
        let synced = catch.finish();

        // 🔴 The property: the mined note's commitment IS a leaf of that tree.
        let d = w.diversifier_at_index(mined.div_index);
        let inp = w.spend_input(mined.note.value, mined.note.rho, mined.note.rseed, d);
        let (_nk, _nf, cm) = qlab_air::narrow::derive_input(&inp);
        let pos = synced
            .tree
            .position_of(&cm)
            .expect("a mined note's commitment is a leaf of the served tree");

        // …and the witness the spend path cuts folds to the anchor the node
        // itself would accept.
        let anchor_count = synced.tree.len();
        assert!(pos < anchor_count);
        assert_eq!(
            qlab_note::hash::digest_bytes(&synced.tree.root_at(anchor_count)),
            rpc.node().commitment_root(),
            "the rebuilt tree IS the node's tree"
        );

        // The pre-proof spend path accepts it — one function, the one
        // `SelectDriver` calls, with no coinbase-specific branch anywhere in it.
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([0x5C; 32]), 0).address_at_index(0);
        let spendable = crate::send::Spendable {
            div_index: mined.div_index,
            value: mined.note.value,
            rho: mined.note.rho,
            rseed: mined.note.rseed,
        };
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x415);
        let bundle = crate::send::build_bundle(
            &w,
            &[spendable],
            &recipient,
            mined.note.value / 4,
            &synced.tree,
            anchor_count,
            last,
            recipient.short().encode(),
            Some((0, last)),
            Some((0, last)),
            None,
            &mut rng,
        )
        .expect("the witness builds against the anchor — no proof is run here");
        assert_eq!(
            bundle.anchor(),
            qlab_note::hash::digest_bytes(&synced.tree.root_at(anchor_count)),
            "the bundle is anchored at the node's own finalized root"
        );
    }

    /// The maturity threshold is `qlab_node`'s own, at the exact block — not a
    /// copy of 144 here. One block short is `maturing` with the height it
    /// changes at; at the threshold it is spendable.
    #[test]
    fn the_maturity_threshold_is_the_append_schedules_own() {
        let w = wallet();
        let mine = w.rkm(w.diversifier_at_index(0));
        let at = coinbase_leaf_appears_at(1);

        let mined_at_1 = |tip: u64| {
            let mut blocks = vec![blk(0, [0; 4], 0), blk(1, mine, 5_000)];
            for h in 2..=tip {
                blocks.push(blk(h, [9; 4], 5_000));
            }
            let chain = MinedChain { covered: Some((0, tip)), blocks };
            match_mined(&w, &[0], &chain, &SpentSet::default())
        };

        let early = mined_at_1(at - 1);
        assert_eq!(early.spendable.len(), 0, "one block short of maturity, nothing is spendable");
        assert_eq!(early.maturing.len(), 1);
        assert_eq!(early.next_maturity(), Some(at), "and the height it changes at is reported");
        assert_eq!(
            early.maturing[0].maturity,
            CoinbaseMaturity::Immature { leaf_at: at, blocks_remaining: 1 }
        );

        let ready = mined_at_1(at);
        assert_eq!(ready.spendable.len(), 1, "at maturity the leaf exists and the note counts");
        assert_eq!(ready.next_maturity(), None);
        assert_eq!(ready.spendable[0].maturity, CoinbaseMaturity::Matured { leaf_at: at });
    }
}
