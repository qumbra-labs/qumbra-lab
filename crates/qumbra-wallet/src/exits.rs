//! Exit detection — the wallet half of lab #785 F5-5d.
//!
//! ## The gap this closes
//!
//! A V6 chain's L2 bundle can pay **exits** to L1: each entry of its clear
//! exit list becomes an asset-0 L1 note, appended to the commitment tree by the
//! node's fold (`qlab_node::coinbase::exit_note`). An exit note has no
//! transaction, no ciphertext and no discovery entry — it is a leaf the fold
//! appends — so a scan of `/v1/compact` cannot find it, and before this module
//! no wallet could see money exited to it.
//!
//! ## The shape — [`crate::coinbase`]'s, deliberately
//!
//! The node serves each block's exit facts in bulk over a range (`GET
//! /v1/exits`, [`qlab_cbserver::codec::ExitPage`]); this module matches their
//! `rkm` against **this wallet's own** keys, locally. There is no per-key query
//! and there must never be one — the same reasoning as `/v1/coinbase`: a probe
//! adds the question, and the question is the leak.
//!
//! The note is rebuilt with [`qlab_node::coinbase::exit_note`]`(height, index,
//! rkm, v)`, `index` being the entry's position in the block's list — **the
//! same function, with the same arguments, `apply_state` appended the leaf
//! with.** No second formula: a wrong one would produce a commitment in no
//! tree, which the spend path refuses at the witness lookup.
//!
//! An exit note has **no maturity** (the F5 ruling's Q3: it is an L1 note the
//! moment its block applies); it is spendable once a finalized anchor's root
//! contains its leaf, which the spend path checks, and once the nullifier
//! subtraction says it is not already spent.
//!
//! ## Two callers, weighed as coinbase is (lab #424's ruling)
//!
//! `scan` prints a figure, so an exit stream it could not read narrows the
//! balance's claim, by name. [`crate::driver::SelectDriver`] offers inputs, so
//! an unreadable stream only shrinks the set it selects from and is said out
//! loud — never a refusal, never silent.

use qlab_cbserver::codec::BlockExits;
use qlab_note::note::Note;
use qlab_wallet::Wallet;

use crate::spent::{note_nullifier, SpentSet};

/// One bounded response from the exit stream — [`qlab_cbserver::codec::ExitPage`]
/// field for field.
#[derive(Clone, Debug)]
pub struct ExitChunk {
    /// The server's echo of the requested `from`. Checked, not trusted.
    pub from: u64,
    /// The server's echo of the requested `to`.
    pub to: u64,
    /// Every main-chain block the server holds in the range, ascending — the
    /// ones with no exits included, so a hole is visible.
    pub blocks: Vec<BlockExits>,
}

/// Where the per-block exit facts come from.
/// [`crate::net::HttpExitSource`] serves it over `GET /v1/exits`.
pub trait ExitSource {
    /// One bounded page for `[from, to]`. An `Err` is a transport/decode
    /// failure, verbatim.
    fn fetch_range(&self, from: u64, to: u64) -> Result<ExitChunk, String>;
}

/// Every way exit detection refuses — [`crate::coinbase::CoinbaseRefusal`]'s
/// variants one for one, so the two streams refuse in one vocabulary.
#[derive(Debug, PartialEq, Eq)]
pub enum ExitRefusal {
    /// The endpoint could not be reached or did not decode — on a node that
    /// predates lab #785 F5-5d, a 404, and that is the honest answer.
    Endpoint { why: String },
    RangeMismatch { asked: (u64, u64), got: (u64, u64) },
    OutOfRange { height: u64, asked: (u64, u64) },
    NotAscending { previous: u64, height: u64 },
    /// 🔴 A height missing from the middle: never interpolated — a hole is
    /// indistinguishable from a block that paid nobody once it is smoothed over.
    Gap { expected: u64, got: u64 },
    NotCovered { covered: Option<(u64, u64)>, wanted: (u64, u64) },
}

impl std::fmt::Display for ExitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitRefusal::Endpoint { why } => write!(
                f,
                "the exit stream could not be read ({why}). This scan cannot see L2 exits paid to \
                 this wallet"
            ),
            ExitRefusal::RangeMismatch { asked, got } => write!(
                f,
                "exit page refused: asked for heights {}..={} and it answered for {}..={}",
                asked.0, asked.1, got.0, got.1
            ),
            ExitRefusal::OutOfRange { height, asked } => write!(
                f,
                "exit page refused: it carries height {height}, outside the {}..={} it answers",
                asked.0, asked.1
            ),
            ExitRefusal::NotAscending { previous, height } => write!(
                f,
                "exit page refused: height {height} follows {previous} — the stream must be ascending"
            ),
            ExitRefusal::Gap { expected, got } => write!(
                f,
                "exit stream refused: height {expected} is missing (the next height served was {got})"
            ),
            ExitRefusal::NotCovered { covered, wanted } => write!(
                f,
                "exit stream refused: it covers {} but this scan asked about {}..={}",
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

impl std::error::Error for ExitRefusal {}

/// The chain's per-block exit facts over a range, and how much of the range
/// the stream covered.
#[derive(Clone, Debug, Default)]
pub struct ExitChain {
    /// The contiguous height range served, or `None` when the endpoint held no
    /// block in the requested range at all.
    pub covered: Option<(u64, u64)>,
    /// Every block in `covered`, ascending — one entry per height.
    pub blocks: Vec<BlockExits>,
}

impl ExitChain {
    /// Does this stream cover every height a report is about?
    pub fn covers(&self, wanted: Option<(u64, u64)>) -> Result<(), ExitRefusal> {
        let Some(wanted) = wanted else { return Ok(()) };
        match self.covered {
            Some((from, to)) if from <= wanted.0 && to >= wanted.1 => Ok(()),
            covered => Err(ExitRefusal::NotCovered { covered, wanted }),
        }
    }
}

/// Page the exit stream over `[from, to]` — [`crate::coinbase::fetch_coinbase`]'s
/// loop: resume at the last served height + 1, stop at `to` or when nothing
/// further is served; contiguity checked as it goes.
pub fn fetch_exits(source: &impl ExitSource, from: u64, to: u64) -> Result<ExitChain, ExitRefusal> {
    let mut catch = ExitCatchUp::new(from, to);
    while let Some((from, to)) = catch.want() {
        let page = source.fetch_range(from, to).map_err(|why| ExitRefusal::Endpoint { why })?;
        catch.supply(page)?;
    }
    Ok(catch.finish())
}

/// The page-accumulation half of [`fetch_exits`], caller-pumped — one copy of
/// the paging checks, shared with [`crate::driver::SelectDriver`].
pub struct ExitCatchUp {
    chain: ExitChain,
    cursor: u64,
    to: u64,
    done: bool,
}

impl ExitCatchUp {
    pub fn new(from: u64, to: u64) -> ExitCatchUp {
        ExitCatchUp { chain: ExitChain::default(), cursor: from, to, done: false }
    }

    /// The range to ask for next, or `None` once complete.
    pub fn want(&self) -> Option<(u64, u64)> {
        (!self.done).then_some((self.cursor, self.to))
    }

    /// Feed one page — echo, in-range, ascending and gap-free checks.
    pub fn supply(&mut self, page: ExitChunk) -> Result<(), ExitRefusal> {
        if self.done {
            return Err(ExitRefusal::Endpoint { why: "a page was supplied after the stream completed".into() });
        }
        if (page.from, page.to) != (self.cursor, self.to) {
            return Err(ExitRefusal::RangeMismatch { asked: (self.cursor, self.to), got: (page.from, page.to) });
        }
        if page.blocks.is_empty() {
            self.done = true;
            return Ok(());
        }
        for blk in page.blocks {
            let height = blk.height;
            if height < self.cursor || height > self.to {
                return Err(ExitRefusal::OutOfRange { height, asked: (self.cursor, self.to) });
            }
            match self.chain.covered {
                Some((_, prev)) if height <= prev => return Err(ExitRefusal::NotAscending { previous: prev, height }),
                Some((_, prev)) if height != prev + 1 => return Err(ExitRefusal::Gap { expected: prev + 1, got: height }),
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

    pub fn finish(self) -> ExitChain {
        self.chain
    }
}

/// One exit note this wallet was paid, and whether it is already spent.
#[derive(Clone, Debug)]
pub struct ExitNote {
    /// The height whose bundle carried the exit.
    pub height: u64,
    /// Its position in that block's exit list — with `height`, the note's
    /// identity (its ρ is derived from both).
    pub index: u8,
    /// The diversifier index whose `rkm` the exit paid.
    pub div_index: u64,
    /// The note, rebuilt through the applier's own derivation.
    pub note: Note,
    /// `Some(height)` when the chain has already published its nullifier.
    pub spent_height: Option<u64>,
}

/// This wallet's exit notes over a covered range.
#[derive(Clone, Debug, Default)]
pub struct ExitReport {
    /// Unspent — what a balance adds and selection may spend.
    pub spendable: Vec<ExitNote>,
    /// Already spent: reported, never counted.
    pub spent: Vec<ExitNote>,
}

impl ExitReport {
    pub fn spendable_value(&self) -> u128 {
        self.spendable.iter().map(|n| u128::from(n.note.value)).sum()
    }

    pub fn spent_value(&self) -> u128 {
        self.spent.iter().map(|n| u128::from(n.note.value)).sum()
    }

    /// Exits paid to this wallet in the covered range, either state.
    pub fn count(&self) -> usize {
        self.spendable.len() + self.spent.len()
    }
}

/// Match `chain`'s exits against the `rkm` of each allocated diversifier index,
/// rebuild every note this wallet was paid with
/// [`qlab_node::coinbase::exit_note`], and split it by whether the chain has
/// already consumed it — the nullifier derived exactly as a spend derives it
/// ([`note_nullifier`]).
pub fn match_exits(wallet: &Wallet, indices: &[u64], chain: &ExitChain, spent: &SpentSet) -> ExitReport {
    let mut report = ExitReport::default();
    let mine: Vec<(u64, [u64; 4])> =
        indices.iter().map(|&idx| (idx, wallet.rkm(wallet.diversifier_at_index(idx)))).collect();
    for blk in &chain.blocks {
        for (i, e) in blk.exits.iter().enumerate() {
            let Some(&(div_index, _)) = mine.iter().find(|(_, rkm)| *rkm == e.rkm) else { continue };
            // The list is at most K_exit long on the wire (`ExitPage` refuses
            // more), so the index always fits the derivation's u8.
            let Ok(index) = u8::try_from(i) else { continue };
            let note = qlab_node::coinbase::exit_note(blk.height, index, e.rkm, e.v);
            let nf = note_nullifier(wallet, div_index, &note);
            let exit = ExitNote { height: blk.height, index, div_index, note, spent_height: spent.height_of(&nf) };
            if exit.spent_height.is_some() {
                report.spent.push(exit);
            } else {
                report.spendable.push(exit);
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_cbserver::codec::ExitFact;
    use qlab_wallet::seed::MasterSeed;

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([0x52; 32]), 0)
    }

    struct Pages(Vec<ExitChunk>, std::cell::Cell<usize>);
    impl ExitSource for Pages {
        fn fetch_range(&self, from: u64, to: u64) -> Result<ExitChunk, String> {
            let i = self.1.get();
            self.1.set(i + 1);
            let mut p = self.0.get(i).cloned().ok_or("no more pages")?;
            if (p.from, p.to) == (0, 0) {
                (p.from, p.to) = (from, to);
            }
            Ok(p)
        }
    }

    fn blk(height: u64, exits: Vec<ExitFact>) -> BlockExits {
        BlockExits { height, exits }
    }

    /// Paging resumes at the last height + 1 and a hole is refused by name —
    /// the coinbase stream's contract on the exit stream.
    #[test]
    fn the_exit_stream_pages_and_refuses_a_hole() {
        let ok = Pages(
            vec![
                ExitChunk { from: 0, to: 0, blocks: vec![blk(0, vec![]), blk(1, vec![])] },
                ExitChunk { from: 0, to: 0, blocks: vec![blk(2, vec![]), blk(3, vec![])] },
            ],
            Default::default(),
        );
        let chain = fetch_exits(&ok, 0, 3).unwrap();
        assert_eq!(chain.covered, Some((0, 3)));
        assert!(chain.covers(Some((0, 3))).is_ok());
        assert!(chain.covers(Some((0, 4))).is_err(), "an uncovered tail is named");
        let holed = Pages(vec![ExitChunk { from: 0, to: 0, blocks: vec![blk(0, vec![]), blk(2, vec![])] }], Default::default());
        assert_eq!(fetch_exits(&holed, 0, 2).unwrap_err(), ExitRefusal::Gap { expected: 1, got: 2 });
    }

    /// A wallet finds an exit paid to one of its own `rkm`s, rebuilds the note
    /// the node appended (`exit_note_leaf`'s commitment), ignores another
    /// key's, and moves it to `spent` once its nullifier is on the chain.
    #[test]
    fn match_exits_rebuilds_the_appended_note_and_subtracts_spends() {
        let w = wallet();
        let mine = w.rkm(w.diversifier_at_index(0));
        let chain = ExitChain {
            covered: Some((0, 5)),
            blocks: vec![
                blk(4, vec![]),
                blk(5, vec![ExitFact { rkm: [9, 9, 9, 9], v: 7 }, ExitFact { rkm: mine, v: 40 }]),
            ],
        };
        let none = SpentSet::default();
        let r = match_exits(&w, &[0], &chain, &none);
        assert_eq!(r.spendable.len(), 1, "another key's exit is not this wallet's");
        let n = &r.spendable[0];
        assert_eq!((n.height, n.index, n.div_index, n.note.value), (5, 1, 0, 40));
        assert_eq!(
            qlab_note::hash::digest_bytes(&n.note.commitment()),
            qlab_node::coinbase::exit_note_leaf(5, 1, mine, 40),
            "the leaf apply_state appended"
        );
        assert_eq!(r.spendable_value(), 40);

        let nf = note_nullifier(&w, 0, &n.note);
        let spent = SpentSet::from_parts(Some((0, 9)), [(9, nf)]);
        let r = match_exits(&w, &[0], &chain, &spent);
        assert!(r.spendable.is_empty());
        assert_eq!((r.spent.len(), r.spent[0].spent_height, r.spent_value()), (1, Some(9), 40));
    }
}
