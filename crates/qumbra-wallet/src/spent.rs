//! Spent-note subtraction — the wallet half of lab issue #314.
//!
//! ## The defect this closes
//!
//! A scan computes `spendable` from **outputs**. The serving wire deliberately
//! carries no nullifier inside a discovery group (#188 (a) as amended, under
//! #32's `Ivk` boundary), so nothing in the scan path could learn that a note it
//! opened had since been spent. Minutes after the chain's first user send, the
//! sender's own wallet reported the note it had just spent as spendable — 48.99
//! QMB where the truth was 38.99 — **under `verdict: complete`**. Every wallet
//! that had ever spent would have over-quoted forever, and `complete` is exactly
//! the promise the honesty vocabulary exists to keep.
//!
//! ## The shape, and the line it does not cross
//!
//! The node serves the nullifiers each block published, in bulk over a range
//! (`GET /v1/nullifiers`, [`qlab_cbserver::codec::NullifierPage`]). This module derives
//! **this wallet's own** notes' nullifiers from keys only this wallet holds, and
//! matches locally.
//!
//! 🔴 **There is no "is nf X spent" query and there must never be one.** Asking
//! a server about one nullifier tells it which note is yours; the whole point of
//! matching locally is that the server learns a range and an IP and nothing
//! about which of those nullifiers mattered. The bytes themselves leak nothing
//! new — consensus published every one of them in a block body to enforce the
//! double-spend rule — so what a probe would add is the *question*, and the
//! question is the leak.
//!
//! ## One derivation, not a second formula
//!
//! [`note_nullifier`] is the three lines [`crate::send::build_send`] runs to
//! build a spend: `wallet.spend_input(value, ρ, rseed, d)` →
//! `qlab_air::narrow::derive_input(..).1` → `digest_bytes`. That is deliberate
//! and it is the whole correctness argument: if the balance's notion of "this
//! note's nullifier" ever drifted from the spend path's, the subtraction would
//! silently stop matching and the balance would go back to being wrong in the
//! same direction. `derive_input` is also what the AIR itself constrains, so the
//! bytes compared here are the bytes consensus put on the chain.
//! (`the_subtractions_derivation_agrees_with_the_host_mirror` checks it against
//! `qlab_wallet::keys::derive_nf` independently.)
//!
//! ## Coverage is load-bearing, not decorative
//!
//! A balance that could not subtract spends is not quotable — that is the exact
//! lesson of #314, and it is why [`SpentSet`] carries the range it actually
//! covers and why every refusal here is named. A gap, a truncated page believed
//! to be complete, or an endpoint that is simply not there all end in
//! `UNAVAILABLE` with the reason, never in a number.

use std::collections::BTreeMap;

use qlab_air::narrow::derive_input;
use qlab_cbserver::client::LocatedNote;
use qlab_note::hash::digest_bytes;
use qlab_note::note::Note;
use qlab_wallet::Wallet;

/// One bounded response from the nullifier stream — the wallet-side shape of
/// [`qlab_cbserver::codec::NullifierPage`], field for field, so there is no
/// second reading of that framing here (the [`crate::sync::LeafChunk`]
/// discipline).
#[derive(Clone, Debug)]
pub struct NullifierChunk {
    /// The server's **echo** of the requested `from`. Checked, not trusted.
    pub from: u64,
    /// The server's echo of the requested `to`.
    pub to: u64,
    /// `(height, nullifiers)` per main-chain block the server holds in the
    /// range, ascending. A block that spends nothing is present with an empty
    /// list — an omitted height would be indistinguishable from an unserved one.
    pub blocks: Vec<(u64, Vec<[u8; 32]>)>,
}

/// Where the per-block nullifier lists come from.
/// [`crate::net::HttpNullifierSource`] serves it over `GET /v1/nullifiers`.
pub trait NullifierSource {
    /// One bounded page for `[from, to]`. An `Err` is a transport/decode
    /// failure, verbatim — the caller turns it into the named refusal.
    fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String>;
}

/// Every way the spent-subtraction refuses, each with its reason named — the
/// same no-boolean-blindness house style as [`crate::sync::SyncRefusal`].
#[derive(Debug, PartialEq, Eq)]
pub enum SpentRefusal {
    /// The endpoint could not be reached, or its response did not decode. On a
    /// node that predates this route it is a 404, and that is an honest answer:
    /// this node cannot tell you what is spent.
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
    /// and never interpolated: a hole is indistinguishable from "that block
    /// spent nothing" once it is smoothed over, and smoothing it over is
    /// precisely how a spent note stays spendable.
    ///
    /// Only *interior* holes are this refusal. Where the stream **starts** is
    /// the server's business — the reference server's first block is height 1,
    /// and a node may hold nothing below some height — so a leading edge above
    /// the requested `from` is legal and is judged by [`SpentRefusal::NotCovered`]
    /// against the range the outputs actually came from.
    Gap { expected: u64, got: u64 },
    /// The stream does not cover the heights the outputs being subtracted came
    /// from, at one end or the other — so a note could have been spent in a
    /// block this wallet never saw the nullifiers of. Refused rather than
    /// under-subtracted.
    NotCovered { covered: Option<(u64, u64)>, outputs: (u64, u64) },
}

impl std::fmt::Display for SpentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpentRefusal::Endpoint { why } => write!(
                f,
                "the nullifier stream could not be read ({why}). A balance that cannot subtract \
                 spends is not quotable — a note this wallet already spent would still be counted"
            ),
            SpentRefusal::RangeMismatch { asked, got } => write!(
                f,
                "nullifier page refused: asked for heights {}..={} and it answered for {}..={}. \
                 The wire echoes both bounds so a page cannot be misattributed",
                asked.0, asked.1, got.0, got.1
            ),
            SpentRefusal::OutOfRange { height, asked } => write!(
                f,
                "nullifier page refused: it carries height {height}, outside the {}..={} it \
                 answers",
                asked.0, asked.1
            ),
            SpentRefusal::NotAscending { previous, height } => write!(
                f,
                "nullifier page refused: height {height} follows {previous} — the stream must be \
                 ascending, or 'covered up to N' means nothing"
            ),
            SpentRefusal::Gap { expected, got } => write!(
                f,
                "nullifier stream refused: height {expected} is missing (the next height served \
                 was {got}). A hole is not an empty block — refusing to treat 'I was not told' \
                 as 'nothing was spent there'"
            ),
            SpentRefusal::NotCovered { covered, outputs } => write!(
                f,
                "nullifier stream refused: it covers {} but this scan's outputs came from \
                 {}..={}. A note could have been spent in the uncovered blocks, so spendable \
                 cannot be quoted for this range",
                match covered {
                    Some((a, b)) => format!("{a}..={b}"),
                    None => "nothing".to_string(),
                },
                outputs.0,
                outputs.1
            ),
        }
    }
}

impl std::error::Error for SpentRefusal {}

/// The chain's spent nullifiers over a range, **the height each one was
/// published at**, and **how much of that range the stream actually covered** —
/// the last being the part a balance depends on.
///
/// The heights are what makes `history` possible at all (the ledger baton): a
/// spend event's date is the height of the block whose nullifier list carries
/// the note's nullifier, and that block is exactly what this wire already
/// serves. Nothing new is fetched for it — the same pages, one field kept
/// instead of discarded.
#[derive(Clone, Debug, Default)]
pub struct SpentSet {
    /// The contiguous height range actually served, or `None` when the endpoint
    /// held no block in the requested range at all.
    pub covered: Option<(u64, u64)>,
    /// nullifier → the height of the block that published it. **First
    /// occurrence wins**: consensus forbids a nullifier appearing twice on one
    /// chain, so a repeat is a serving fault rather than a fact, and the earlier
    /// height is the one that could possibly be true.
    nullifiers: BTreeMap<[u8; 32], u64>,
}

impl SpentSet {
    /// Build a set from `(height, nullifier)` pairs a caller obtained some other
    /// way — an in-process node, a fixture, a chain reader that is not this HTTP
    /// client.
    ///
    /// 🔴 **`covered` is the caller's claim and is not checked here**, which is
    /// why [`fetch_spent`] exists and is what the CLI uses: over the wire the
    /// coverage has to be *established*, page by page, before it may be
    /// asserted. This constructor is for callers who already know it.
    pub fn from_parts(
        covered: Option<(u64, u64)>,
        nullifiers: impl IntoIterator<Item = (u64, [u8; 32])>,
    ) -> SpentSet {
        let mut map: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for (height, nf) in nullifiers {
            map.entry(nf).or_insert(height);
        }
        SpentSet { covered, nullifiers: map }
    }

    /// Is this nullifier on the chain, within the covered range?
    pub fn contains(&self, nf: &[u8; 32]) -> bool {
        self.nullifiers.contains_key(nf)
    }

    /// The height of the block that published this nullifier, if the covered
    /// range carries it — the chain's own date for a spend.
    pub fn height_of(&self, nf: &[u8; 32]) -> Option<u64> {
        self.nullifiers.get(nf).copied()
    }

    /// How many distinct nullifiers the covered range published (everyone's,
    /// not this wallet's — the wallet never tells the server which are its).
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }

    /// Does this set cover every height an output could have been spent in?
    ///
    /// `outputs` is the height range the scan's outputs actually came from
    /// (`ScanStats::compact_range_served`), not the range the user asked for —
    /// a server holds what it holds at both ends, and refusing an honest scan
    /// for that would make the whole subtraction unusable. `None` means the scan
    /// saw no block at all, so there is nothing to cover and nothing to
    /// subtract.
    ///
    /// A note detected at height `h` can be spent at any height from `h`
    /// onwards, so the covered range must contain the outputs' range at **both**
    /// ends: an uncovered head hides a spend of an early note, an uncovered tail
    /// hides the most recent spends — which is the exact case that produced this
    /// issue.
    pub fn covers_outputs(&self, outputs: Option<(u64, u64)>) -> Result<(), SpentRefusal> {
        let Some(outputs) = outputs else { return Ok(()) };
        match self.covered {
            Some((from, to)) if from <= outputs.0 && to >= outputs.1 => Ok(()),
            covered => Err(SpentRefusal::NotCovered { covered, outputs }),
        }
    }
}

/// Page the nullifier stream over `[from, to]` — the client half of the #312
/// paging contract, shipped in the same change as the server's bound because a
/// truncated page that read as a complete one is exactly the silent failure this
/// whole issue is about.
///
/// The loop resumes at the last served height + 1 and stops when a page reaches
/// `to` or when the endpoint serves nothing further (the honest "I hold no more
/// of that range"). Contiguity is checked as it goes, and it is also the
/// progress guard: a page that does not continue where the last one ended is a
/// named refusal rather than another lap.
///
/// **Where the stream starts is not checked here** — the reference server's
/// first block is height 1 and a node may hold nothing below some height, so a
/// leading edge above `from` is legal. What that costs is judged by
/// [`SpentSet::covers_outputs`] against the range the outputs actually came
/// from, which is the question that matters.
pub fn fetch_spent(
    source: &impl NullifierSource,
    from: u64,
    to: u64,
) -> Result<SpentSet, SpentRefusal> {
    let mut set = SpentSet { covered: None, nullifiers: BTreeMap::new() };
    let mut cursor = from;
    loop {
        let page = source
            .fetch_range(cursor, to)
            .map_err(|why| SpentRefusal::Endpoint { why })?;
        if (page.from, page.to) != (cursor, to) {
            return Err(SpentRefusal::RangeMismatch {
                asked: (cursor, to),
                got: (page.from, page.to),
            });
        }
        if page.blocks.is_empty() {
            break; // the endpoint holds nothing (further) in the range
        }
        for (height, nfs) in &page.blocks {
            let height = *height;
            if height < cursor || height > to {
                return Err(SpentRefusal::OutOfRange { height, asked: (cursor, to) });
            }
            match set.covered {
                Some((_, prev)) if height <= prev => {
                    return Err(SpentRefusal::NotAscending { previous: prev, height })
                }
                Some((_, prev)) if height != prev + 1 => {
                    return Err(SpentRefusal::Gap { expected: prev + 1, got: height })
                }
                _ => {}
            }
            for nf in nfs {
                // First occurrence wins — see the field's doc comment.
                set.nullifiers.entry(*nf).or_insert(height);
            }
            set.covered = Some((set.covered.map_or(height, |(f, _)| f), height));
        }
        let (_, last) = set.covered.expect("a non-empty page set it");
        if last >= to {
            break;
        }
        cursor = last + 1;
    }
    Ok(set)
}

/// This note's nullifier, as the chain would see it — **the spend path's own
/// derivation**, not a second formula.
///
/// `nf = H(nk ‖ ρ)` computed through `qlab_air::narrow::derive_input`, the same
/// call `build_send` makes on the same `TxInput` when it builds the spend the
/// chain then publishes, hashed to its 32-byte wire form by the same
/// `digest_bytes` that `TxPublic::nullifiers` carries. `div_index` is the
/// diversifier the note was received at: `nf` does not bind the diversifier, but
/// `spend_input` needs it and getting it wrong here would be invisible.
pub fn note_nullifier(wallet: &Wallet, div_index: u64, note: &Note) -> [u8; 32] {
    let d = wallet.diversifier_at_index(div_index);
    let inp = wallet.spend_input(note.value, note.rho, note.rseed, d);
    // `derive_input` returns (nk, nf, cm) — position matters, and getting it
    // wrong here is invisible to a test that derives its fixture the same wrong
    // way. `.1` is what `build_send` and `qlab_faucet::grant` take.
    let (_nk, nf, _cm) = derive_input(&inp);
    digest_bytes(&nf)
}

/// A note this wallet opened whose nullifier is on the chain: it is gone, and
/// the wallet must say so rather than counting it.
#[derive(Clone, Debug)]
pub struct SpentNote {
    pub note: LocatedNote,
    /// The nullifier that matched — the wallet's own derivation, and the same
    /// 32 bytes the block published.
    pub nullifier: [u8; 32],
    /// The height of the block whose nullifier list carries it — **the chain's
    /// own date for this spend**, and the only date there is. The wallet's
    /// ledger groups on it (`crate::history`), so it is a fact and not a
    /// decoration.
    pub spent_height: u64,
}

/// One address's notes, partitioned by whether the chain has seen their
/// nullifiers.
#[derive(Clone, Debug, Default)]
pub struct SpentReport {
    /// Still spendable: opened, unshadowed, and **unspent** over the covered
    /// range. This is the list a balance sums.
    pub spendable: Vec<LocatedNote>,
    /// Opened and already spent. Never folded into `spendable`, never summed
    /// into a balance, and never silently dropped — a wallet that spent its own
    /// note must be able to see where it went.
    pub spent: Vec<SpentNote>,
}

impl SpentReport {
    /// The value a caller may credit.
    pub fn spendable_value(&self) -> u128 {
        self.spendable.iter().map(|n| u128::from(n.detected.note.value)).sum()
    }

    /// The value already spent out of this range — reported, never credited.
    pub fn spent_value(&self) -> u128 {
        self.spent.iter().map(|s| u128::from(s.note.detected.note.value)).sum()
    }
}

/// Partition `notes` (a scan's spendable list, for the address at `div_index`)
/// against the chain's published nullifiers.
///
/// Order is preserved within each list, so both read in chain order.
pub fn subtract_spent(
    wallet: &Wallet,
    div_index: u64,
    notes: &[LocatedNote],
    spent: &SpentSet,
) -> SpentReport {
    let mut report = SpentReport::default();
    for note in notes {
        let nullifier = note_nullifier(wallet, div_index, &note.detected.note);
        match spent.height_of(&nullifier) {
            Some(spent_height) => {
                report.spent.push(SpentNote { note: note.clone(), nullifier, spent_height })
            }
            None => report.spendable.push(note.clone()),
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::MasterSeed;

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([0x31; 32]), 0)
    }

    fn nf(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// An honest endpoint over a contiguous chain, serving bounded pages and
    /// recording every `(from, to)` it was asked for.
    struct Honest {
        /// `(height, nullifiers)` for every height the node holds.
        blocks: Vec<(u64, Vec<[u8; 32]>)>,
        page: usize,
        asked: std::cell::RefCell<Vec<(u64, u64)>>,
    }

    impl Honest {
        fn new(heights: std::ops::RangeInclusive<u64>, page: usize) -> Honest {
            Honest {
                blocks: heights.map(|h| (h, vec![nf(h as u8)])).collect(),
                page,
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl NullifierSource for Honest {
        fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
            self.asked.borrow_mut().push((from, to));
            let blocks: Vec<(u64, Vec<[u8; 32]>)> = self
                .blocks
                .iter()
                .filter(|(h, _)| *h >= from && *h <= to)
                .take(self.page)
                .cloned()
                .collect();
            Ok(NullifierChunk { from, to, blocks })
        }
    }

    /// The client half of the paging contract: a bounded server is paged until
    /// the range is in hand, resuming from the last height + 1 — lab issue #312's
    /// rule on a second route. A single-fetch client would have covered only the
    /// first page and reported the rest of the chain as "nothing spent".
    #[test]
    fn the_stream_is_paged_until_the_range_is_in_hand() {
        let src = Honest::new(0..=9, 4);
        let set = fetch_spent(&src, 0, 9).expect("an honest stream pages");
        assert_eq!(set.covered, Some((0, 9)));
        assert_eq!(set.len(), 10, "every block's nullifier arrived");
        assert_eq!(
            *src.asked.borrow(),
            vec![(0, 9), (4, 9), (8, 9)],
            "resume at the last height + 1, never from the start"
        );
        for h in 0..=9u8 {
            assert!(set.contains(&nf(h)));
        }
        assert!(set.covers_outputs(Some((0, 9))).is_ok());
    }

    /// A truncated page must never read as a covered range. Here the endpoint
    /// stops at 6 while the outputs reach 9: refused by name, with no number.
    #[test]
    fn a_stream_short_of_the_outputs_refuses_rather_than_under_subtracting() {
        let src = Honest::new(0..=6, 100);
        let set = fetch_spent(&src, 0, 9).expect("the pages themselves are well-formed");
        assert_eq!(set.covered, Some((0, 6)), "it covers what it served, honestly");
        let e = set.covers_outputs(Some((0, 9))).unwrap_err();
        assert_eq!(e, SpentRefusal::NotCovered { covered: Some((0, 6)), outputs: (0, 9) });
        assert!(e.to_string().contains("cannot be quoted"), "{e}");
        // …and covering exactly as far as the outputs is enough.
        assert!(set.covers_outputs(Some((0, 6))).is_ok());
        assert!(set.covers_outputs(None).is_ok(), "no outputs, nothing to cover");
        // An uncovered HEAD is refused too — a spend of an early note would be
        // just as invisible as a spend of a late one.
        let late = fetch_spent(&Honest::new(4..=9, 100), 0, 9).unwrap();
        assert_eq!(late.covered, Some((4, 9)), "a leading edge above `from` is legal…");
        assert_eq!(
            late.covers_outputs(Some((1, 9))).unwrap_err(),
            SpentRefusal::NotCovered { covered: Some((4, 9)), outputs: (1, 9) },
            "…and is judged against where the outputs actually came from"
        );
        assert!(late.covers_outputs(Some((4, 9))).is_ok());
    }

    /// A hole is not an empty block. Smoothing one over is how a spent note
    /// stays spendable, so it is a named refusal.
    #[test]
    fn a_missing_height_is_a_gap_and_never_read_as_an_empty_block() {
        struct Holed;
        impl NullifierSource for Holed {
            fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
                Ok(NullifierChunk { from, to, blocks: vec![(0, vec![]), (2, vec![nf(2)])] })
            }
        }
        let e = fetch_spent(&Holed, 0, 3).unwrap_err();
        assert_eq!(e, SpentRefusal::Gap { expected: 1, got: 2 });
        assert!(e.to_string().contains("not an empty block"), "{e}");

        // A hole ACROSS a page boundary is the same fault: the second page must
        // continue where the first stopped.
        struct HoledAcrossPages;
        impl NullifierSource for HoledAcrossPages {
            fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
                let blocks = if from == 0 { vec![(0, vec![]), (1, vec![])] } else { vec![(3, vec![nf(3)])] };
                Ok(NullifierChunk { from, to, blocks })
            }
        }
        assert_eq!(
            fetch_spent(&HoledAcrossPages, 0, 5).unwrap_err(),
            SpentRefusal::Gap { expected: 2, got: 3 }
        );
    }

    /// The bound echoes are checked, not decorative — the leaf stream's
    /// misattribution discipline on this wire.
    #[test]
    fn a_page_answering_a_different_range_is_refused() {
        struct WrongEcho;
        impl NullifierSource for WrongEcho {
            fn fetch_range(&self, _from: u64, _to: u64) -> Result<NullifierChunk, String> {
                Ok(NullifierChunk { from: 7, to: 9, blocks: vec![] })
            }
        }
        assert_eq!(
            fetch_spent(&WrongEcho, 0, 9).unwrap_err(),
            SpentRefusal::RangeMismatch { asked: (0, 9), got: (7, 9) }
        );
    }

    /// An out-of-order or repeated height breaks the one claim this set makes.
    #[test]
    fn a_descending_or_repeated_height_is_refused() {
        struct Backwards;
        impl NullifierSource for Backwards {
            fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
                Ok(NullifierChunk {
                    from,
                    to,
                    blocks: vec![(0, vec![]), (1, vec![]), (1, vec![nf(9)])],
                })
            }
        }
        assert_eq!(
            fetch_spent(&Backwards, 0, 3).unwrap_err(),
            SpentRefusal::NotAscending { previous: 1, height: 1 }
        );
    }

    /// An endpoint that is not there at all — a node predating the route answers
    /// 404 — is a named refusal carrying the endpoint's own words, never an
    /// empty set (which would read as "nothing is spent").
    #[test]
    fn an_unreachable_endpoint_is_a_refusal_not_an_empty_set() {
        struct Down;
        impl NullifierSource for Down {
            fn fetch_range(&self, _: u64, _: u64) -> Result<NullifierChunk, String> {
                Err("non-200 response: HTTP/1.1 404 Not Found".into())
            }
        }
        let e = fetch_spent(&Down, 0, 9).unwrap_err();
        assert!(matches!(e, SpentRefusal::Endpoint { .. }));
        assert!(e.to_string().contains("404"), "{e}");
        assert!(e.to_string().contains("not quotable"), "{e}");
    }

    /// A `from` past the chain's tip is an empty page, not an error — and it
    /// covers nothing, which the coverage check then judges.
    #[test]
    fn a_range_the_endpoint_does_not_reach_is_empty_and_covers_nothing() {
        let set = fetch_spent(&Honest::new(0..=3, 100), 8, 9).unwrap();
        assert_eq!(set.covered, None);
        assert!(set.is_empty());
        assert!(set.covers_outputs(None).is_ok());
        assert_eq!(
            set.covers_outputs(Some((8, 9))).unwrap_err(),
            SpentRefusal::NotCovered { covered: None, outputs: (8, 9) }
        );
    }

    /// The height a nullifier was published at travels with it, and a repeat is
    /// resolved to the EARLIER height rather than the later one: consensus
    /// forbids the same nullifier twice on one chain, so a repeat is a serving
    /// fault, and the first occurrence is the only one that could be true.
    #[test]
    fn each_nullifier_carries_the_height_that_published_it_first() {
        let src = Honest::new(0..=5, 100);
        let set = fetch_spent(&src, 0, 5).unwrap();
        for h in 0..=5u8 {
            assert_eq!(set.height_of(&nf(h)), Some(u64::from(h)), "block {h}'s own nullifier");
        }
        assert_eq!(set.height_of(&nf(99)), None, "a nullifier nobody published");

        // The same 32 bytes served at two heights: the earlier one stands.
        struct Repeated;
        impl NullifierSource for Repeated {
            fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
                Ok(NullifierChunk {
                    from,
                    to,
                    blocks: vec![(0, vec![]), (1, vec![nf(7)]), (2, vec![nf(7)])],
                })
            }
        }
        let set = fetch_spent(&Repeated, 0, 2).unwrap();
        assert_eq!(set.height_of(&nf(7)), Some(1));
        assert_eq!(set.len(), 1, "one nullifier, however many times it was served");

        // `from_parts` resolves the same way, for callers holding their own data.
        let built = SpentSet::from_parts(Some((0, 9)), [(4, nf(3)), (9, nf(3)), (5, nf(4))]);
        assert_eq!(built.height_of(&nf(3)), Some(4));
        assert_eq!(built.height_of(&nf(4)), Some(5));
    }

    /// 🔴 **The derivation is the spend path's.** `note_nullifier` runs
    /// `derive_input` on the very `TxInput` `build_send` spends; this checks the
    /// result against `qlab_wallet::keys::derive_nf`, the independent host mirror
    /// — two implementations agreeing, rather than one asserted against itself.
    #[test]
    fn the_subtractions_derivation_agrees_with_the_host_mirror() {
        let w = wallet();
        let note = Note { value: 7_777, rkm: w.rkm(w.diversifier_at_index(3)), rho: [9, 8, 7, 6], rseed: [1, 2, 3, 4] };
        let got = note_nullifier(&w, 3, &note);
        assert_eq!(
            got,
            digest_bytes(&w.nullifier(&note.rho)),
            "the balance's nullifier and the spend's are one derivation"
        );
        // And it does not depend on the diversifier — nf binds (nk, ρ) only, so
        // a note received at another index of the SAME wallet derives the same
        // nullifier. This is why a wrong `div_index` is invisible here and must
        // not be relied on for anything but `spend_input`'s shape.
        assert_eq!(note_nullifier(&w, 11, &note), got);
    }

    /// The subtraction itself: a note whose nullifier is on the chain leaves
    /// `spendable` and appears in `spent` with its value — subtracted, never
    /// silently dropped. A never-spent note is untouched.
    #[test]
    fn a_note_whose_nullifier_is_on_chain_stops_being_spendable() {
        let w = wallet();
        let d = w.diversifier_at_index(0);
        let mk = |value: u64, rho: [u64; 4]| Note { value, rkm: w.rkm(d), rho, rseed: [5, 5, 5, 5] };
        let spent_note = mk(1_000_000_000, [1, 1, 1, 1]);
        let live_note = mk(899_000_000, [2, 2, 2, 2]);
        let located = |n: &Note, h: u64| LocatedNote {
            height: h,
            tx_index: 0,
            recipient_index: 0,
            cm: digest_bytes(&n.commitment()),
            detected: qlab_note::scan::DetectedNote { index: 0, note: n.clone() },
        };
        let notes = vec![located(&spent_note, 5), located(&live_note, 6)];

        // The chain published the first note's nullifier and nothing else.
        struct Chain([u8; 32]);
        impl NullifierSource for Chain {
            fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
                Ok(NullifierChunk {
                    from,
                    to,
                    blocks: (from..=to)
                        .map(|h| (h, if h == 7 { vec![self.0] } else { vec![] }))
                        .collect(),
                })
            }
        }
        let set = fetch_spent(&Chain(note_nullifier(&w, 0, &spent_note)), 0, 9).unwrap();

        let report = subtract_spent(&w, 0, &notes, &set);
        assert_eq!(report.spendable.len(), 1, "one note survives");
        assert_eq!(report.spendable[0].detected.note.rho, live_note.rho);
        assert_eq!(report.spendable_value(), 899_000_000);
        assert_eq!(report.spent.len(), 1, "and the spent one is REPORTED, not dropped");
        assert_eq!(report.spent_value(), 1_000_000_000);
        assert_eq!(report.spent[0].nullifier, note_nullifier(&w, 0, &spent_note));
        // 🔴 The ledger's date: the height of the block whose nullifier list
        // carries it — 7 here, not the note's own height (5). `history` groups on
        // this, so a wrong one would put a send event in the wrong place.
        assert_eq!(report.spent[0].spent_height, 7);
        assert_eq!(report.spent[0].note.height, 5, "…and the note's own height is untouched");

        // 🔴 The negative: a wallet that never spent is unchanged by all of this.
        let never = subtract_spent(&w, 0, &notes[1..], &set);
        assert_eq!(never.spendable.len(), 1);
        assert!(never.spent.is_empty());
        assert_eq!(never.spendable_value(), 899_000_000);
    }
}
