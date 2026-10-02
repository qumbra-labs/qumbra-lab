//! `history --net annulet` — this wallet's own ledger on an Annulet net (lab
//! #831 W1).
//!
//! # What it states, and the one thing it deliberately does not
//!
//! The L1 ledger ([`crate::history`]) reconstructs a send as
//! `inputs − change − posted_fee`. On an Annulet net that identity has no
//! single fee to subtract: a transaction moves **two assets** (the asset sent
//! and asset 0, the fee unit), the fee is an exact-tariff asset-0 note whose
//! value depends on the shape (S, P, R, merge), and the tariff is read from
//! `/v1/annulet/params` rather than a frozen table. So this ledger states, per
//! block in which this wallet spent anything, **the per-asset net**: what of
//! each asset left as inputs, what of it came back in the same block, and the
//! difference. That figure is exact arithmetic over chain facts, and it already
//! says the useful thing — an ordinary send of asset A reads as `A: −amount` and
//! `asset 0: −fee`; a merge reads as `A: 0` and `asset 0: −fee`; a mint the
//! issuer received reads as a receipt.
//!
//! What it never states is **a recipient amount and a fee as separate facts**:
//! a note arriving in the block a spend landed in may be change or may be
//! somebody else's payment, and the chain cannot tell them apart. Saying
//! "sent 400, fee 3" would be that inference presented as a fact. Nor does it
//! state a recipient: `send --net annulet` writes nothing to the wallet dir, so
//! there is no local record to join, and the chain never carries one.
//!
//! # UNAVAILABLE discipline, the L1 ledger's
//!
//! A range whose outputs or nullifiers could not be read leaves the ledger
//! unaccounted, and an unaccounted ledger prints **no totals** — the reasons are
//! named instead. Without the nullifier stream there are receipts only, and the
//! ledger says that in so many words.

use std::collections::{BTreeMap, BTreeSet};

use crate::assets::{AssetIndex, OwnedL2Note};
use crate::vocab::{SpentCoverage, UNAVAILABLE};

/// A note this wallet received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Received {
    /// The block it was committed in; 0 for a genesis note.
    pub height: u64,
    /// The transaction within that block; `None` for a genesis note.
    pub tx_index: Option<u64>,
    pub asset: u16,
    pub value: u64,
    pub div_index: u64,
}

impl L2Received {
    fn of(n: &OwnedL2Note) -> Self {
        Self { height: n.height, tx_index: n.tx_index, asset: n.asset, value: n.note.value, div_index: n.div_index }
    }
}

/// One of this wallet's notes whose nullifier the chain published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Input {
    /// The height the note was **received** at (0 for a genesis note).
    pub received_height: u64,
    pub asset: u16,
    pub value: u64,
    pub div_index: u64,
}

/// One asset's movement in one block: what left as inputs and what came back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetNet {
    pub asset: u16,
    /// The sum of this wallet's inputs of the asset spent in the block.
    pub out: u128,
    /// The sum of this wallet's notes of the asset that arrived in the block.
    pub back: u128,
}

impl AssetNet {
    /// `back − out`, signed: negative is value that left this wallet.
    pub fn net(&self) -> i128 {
        // Each side is a sum of u64s over at most a block's outputs, far below
        // i128::MAX; the conversion cannot fail for any value a chain holds.
        i128::try_from(self.back).expect("a block's sum fits i128") - i128::try_from(self.out).expect("a block's sum fits i128")
    }
}

/// A block in which this wallet spent at least one note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Movement {
    /// The height whose nullifier list carries the inputs.
    pub height: u64,
    pub inputs: Vec<L2Input>,
    /// This wallet's notes committed in the same block — change, or a payment
    /// in; the chain does not say which.
    pub arrived: Vec<L2Received>,
    /// Per asset, ascending: every asset that appears in `inputs` or `arrived`.
    pub by_asset: Vec<AssetNet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L2Event {
    /// A receipt in a block where this wallet spent nothing.
    Received(L2Received),
    Movement(L2Movement),
}

impl L2Event {
    pub fn height(&self) -> u64 {
        match self {
            L2Event::Received(r) => r.height,
            L2Event::Movement(m) => m.height,
        }
    }
}

/// One asset's totals over the range — present only for an accounted ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetTotals {
    pub asset: u16,
    /// Every note of the asset received in range (change included: it is a
    /// note this wallet holds or held).
    pub received: u128,
    /// Every one of those notes the chain shows spent.
    pub spent: u128,
    /// `received − spent` — the same figure `scan --net annulet` prints.
    pub spendable: u128,
}

/// A per-address verdict line, as the caller words it from the scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Verdict {
    pub div_index: u64,
    pub address_short: String,
    pub verdict: String,
}

/// The ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Ledger {
    pub range: (u64, u64),
    pub genesis_hash: [u8; 32],
    pub verdicts: Vec<L2Verdict>,
    pub coverage: SpentCoverage,
    /// Chronological; at one height a receipt never sits beside a movement
    /// (an arrival in a spend's block belongs to the movement).
    pub events: Vec<L2Event>,
    /// 🔴 What this ledger could not account for. Empty is the only state in
    /// which totals exist.
    pub gaps: Vec<String>,
    /// No spend is known — the scan's per-asset index was not built — so
    /// every note renders as a receipt, including any that were spent.
    pub receipts_only: bool,
    /// Ascending by asset.
    pub totals: Option<Vec<AssetTotals>>,
}

/// Build the ledger.
///
/// `owned` is every note the scan made this wallet's (genesis notes included);
/// `index` is the scan's per-asset index, which exists **only** when every
/// address's scan started and the nullifier stream covers what they found
/// (lab #314) — so `None` here means no spend is known and the ledger is
/// receipts only. `upstream_gaps` are the scan's own reasons (an address whose
/// scan never started, outputs detected and not read, notes refused), carried
/// in verbatim so this module never re-derives the scan's verdicts.
pub fn build(
    range: (u64, u64),
    genesis_hash: [u8; 32],
    verdicts: Vec<L2Verdict>,
    owned: &[OwnedL2Note],
    index: Option<&AssetIndex>,
    coverage: &SpentCoverage,
    upstream_gaps: Vec<String>,
) -> L2Ledger {
    let mut gaps = upstream_gaps;
    if let SpentCoverage::Unavailable { why } = coverage {
        gaps.push(format!(
            "spends over heights {}..={}: {why} — without the chain's nullifiers no spend is \
             known, so this ledger shows receipts only",
            range.0, range.1
        ));
    } else if index.is_none() {
        // The nullifiers may be in hand and still not applied: the scan builds
        // its index only when EVERY address's scan started, so one refused row
        // withholds the spends of all of them. Said here in so many words, or a
        // spent note and its change would both read as receipts under a header
        // saying the nullifiers are in hand.
        gaps.push(format!(
            "spends not shown: the per-asset index could not be built ({} scan gap(s) listed \
             here), so no spend is known and this ledger shows receipts only — a note listed \
             as RECEIVED may since have been spent",
            gaps.len()
        ));
    }

    let received: Vec<L2Received> = owned.iter().map(L2Received::of).collect();
    let spent: Vec<(u64, L2Input)> = match index {
        Some(ix) => ix
            .by_asset
            .values()
            .flat_map(|notes| notes.spent.iter())
            .map(|(n, h)| (*h, L2Input { received_height: n.height, asset: n.asset, value: n.note.value, div_index: n.div_index }))
            .collect(),
        None => Vec::new(),
    };

    let movement_heights: BTreeSet<u64> = spent.iter().map(|(h, _)| *h).collect();
    let mut events: Vec<L2Event> = Vec::new();
    for &h in &movement_heights {
        let mut inputs: Vec<L2Input> = spent.iter().filter(|(sh, _)| *sh == h).map(|(_, i)| i.clone()).collect();
        inputs.sort_by_key(|i| (i.asset, i.received_height, i.div_index, i.value));
        let mut arrived: Vec<L2Received> = received.iter().filter(|r| r.height == h).cloned().collect();
        arrived.sort_by_key(|r| (r.asset, r.tx_index, r.div_index, r.value));
        let mut nets: BTreeMap<u16, AssetNet> = BTreeMap::new();
        for i in &inputs {
            nets.entry(i.asset).or_insert(AssetNet { asset: i.asset, out: 0, back: 0 }).out += u128::from(i.value);
        }
        for r in &arrived {
            nets.entry(r.asset).or_insert(AssetNet { asset: r.asset, out: 0, back: 0 }).back += u128::from(r.value);
        }
        events.push(L2Event::Movement(L2Movement { height: h, inputs, arrived, by_asset: nets.into_values().collect() }));
    }
    for r in &received {
        if !movement_heights.contains(&r.height) {
            events.push(L2Event::Received(r.clone()));
        }
    }
    // Chronological, deterministic: two runs over one chain render alike.
    events.sort_by_key(|e| match e {
        L2Event::Received(r) => (r.height, r.tx_index.map_or(0, |t| t + 1), r.asset, r.div_index, r.value),
        L2Event::Movement(m) => (m.height, 0, 0, 0, 0),
    });

    let totals = match (gaps.is_empty(), index) {
        (true, Some(ix)) => {
            let mut by: BTreeMap<u16, AssetTotals> = BTreeMap::new();
            for r in &received {
                by.entry(r.asset).or_insert(AssetTotals { asset: r.asset, received: 0, spent: 0, spendable: 0 }).received +=
                    u128::from(r.value);
            }
            for (_, i) in &spent {
                by.entry(i.asset).or_insert(AssetTotals { asset: i.asset, received: 0, spent: 0, spendable: 0 }).spent +=
                    u128::from(i.value);
            }
            for t in by.values_mut() {
                t.spendable = t.received - t.spent;
                // The call-site contract, not an arithmetic check: `owned` and
                // the index come from one scan, so this cannot fire on the
                // sums above. It fires only if a caller hands `build` an index
                // from a different scan than its `owned` — the one way the
                // ledger and `scan` could disagree about this wallet's money.
                // A release-mode assert, not a debug one (#253).
                let scan_says = ix.by_asset.get(&t.asset).map_or(0, |n| n.spendable_value());
                assert_eq!(t.spendable, scan_says, "asset {}: the ledger's spendable is not the scan's", t.asset);
            }
            Some(by.into_values().collect())
        }
        _ => None,
    };

    L2Ledger { range, genesis_hash, verdicts, coverage: coverage.clone(), events, gaps, receipts_only: index.is_none(), totals }
}

fn asset_label(asset: u16) -> String {
    if asset == 0 {
        "asset 0 (fee units)".into()
    } else {
        format!("asset {asset}")
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn signed(v: i128) -> String {
    if v > 0 {
        format!("+{v}")
    } else {
        v.to_string()
    }
}

/// Render the ledger a person reads.
pub fn render(ledger: &L2Ledger, url: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "history (annulet) of {} address(es) against {url}, heights {}..={}\n",
        ledger.verdicts.len(),
        ledger.range.0,
        ledger.range.1
    ));
    out.push_str(&format!("genesis:  {} (verified against the endpoint)\n", hex(&ledger.genesis_hash)));
    match &ledger.coverage {
        SpentCoverage::Unavailable { why } => out.push_str(&format!("spends:   {UNAVAILABLE} — {why}\n")),
        _ if ledger.receipts_only => out.push_str(&format!(
            "spends:   {UNAVAILABLE} — not applied: the scan is incomplete (gaps below), so this \
             ledger is receipts only\n"
        )),
        SpentCoverage::Covered { range: Some((a, b)) } => {
            out.push_str(&format!("spends:   the chain's nullifiers for {a}..={b} are in hand\n"))
        }
        SpentCoverage::Covered { range: None } => out.push_str("spends:   the endpoint held no block in range\n"),
    }
    let from = ledger.range.0;
    if from > 0 {
        out.push_str(&format!(
            "range:    starts at height {from}: notes received before it are not read, so a spend \
             of one is not shown and the totals below are this range's, not the wallet's \
             balance. Genesis notes (height 0) are read whatever the range\n"
        ));
    }
    for v in &ledger.verdicts {
        out.push_str(&format!("  [{}] {}: {}\n", v.div_index, v.address_short, v.verdict));
    }
    out.push_str(
        "amounts are in each asset's own units; asset 0 is the fee unit, never QMB. A spend is \
         stated as each asset's net — its fee is never separated from its amount — and no \
         recipient is ever shown: the chain does not carry one and `send --net annulet` keeps no \
         local record\n\n",
    );

    if ledger.events.is_empty() {
        if ledger.gaps.is_empty() {
            out.push_str("no events: this wallet neither received nor spent anything in this range\n");
        } else {
            out.push_str(&format!("no events could be read ({} gap(s) below)\n", ledger.gaps.len()));
        }
    }
    for event in &ledger.events {
        match event {
            L2Event::Received(r) => {
                match r.tx_index {
                    None if from > 0 => out.push_str(&format!(
                        "height {}  RECEIVED (genesis note — read although the range starts at {from})\n",
                        r.height
                    )),
                    None => out.push_str(&format!("height {}  RECEIVED (genesis note)\n", r.height)),
                    Some(t) => out.push_str(&format!("height {}  RECEIVED (tx {t})\n", r.height)),
                }
                out.push_str(&format!("    {}: {}\n", asset_label(r.asset), r.value));
                out.push_str(&format!("    address:   [{}]\n", r.div_index));
            }
            L2Event::Movement(m) => {
                out.push_str(&format!("height {}  SPEND\n", m.height));
                for i in &m.inputs {
                    out.push_str(&format!(
                        "    input:     {} {} (received at height {}, address [{}])\n",
                        asset_label(i.asset),
                        i.value,
                        i.received_height,
                        i.div_index
                    ));
                }
                for a in &m.arrived {
                    out.push_str(&format!(
                        "    arrived:   {} {} (tx {}, address [{}])\n",
                        asset_label(a.asset),
                        a.value,
                        a.tx_index.map_or("genesis".to_string(), |t| t.to_string()),
                        a.div_index
                    ));
                }
                for n in &m.by_asset {
                    out.push_str(&format!(
                        "    net:       {} {} (out {}, back {})\n",
                        asset_label(n.asset),
                        signed(n.net()),
                        n.out,
                        n.back
                    ));
                }
                if !m.arrived.is_empty() {
                    out.push_str(
                        "    read as:   one movement per block — a note arriving here may be change \
                         or another party's payment, and the chain cannot say which, so only the \
                         per-asset net is stated\n",
                    );
                }
            }
        }
    }

    out.push('\n');
    match &ledger.totals {
        Some(totals) if totals.is_empty() => out.push_str("totals:   nothing in range\n"),
        Some(totals) => {
            if from > 0 {
                out.push_str(&format!(
                    "totals, per asset over heights {from}..={} only (genesis notes included) — \
                     not the wallet's balance:\n",
                    ledger.range.1
                ));
            } else {
                out.push_str("totals, per asset over this range:\n");
            }
            for t in totals {
                out.push_str(&format!(
                    "  {}: received {}, spent {}, spendable {}\n",
                    asset_label(t.asset),
                    t.received,
                    t.spent,
                    t.spendable
                ));
            }
        }
        None => {
            out.push_str(&format!("totals:   {UNAVAILABLE} — this ledger is not fully accounted:\n"));
            for g in &ledger.gaps {
                out.push_str(&format!("  - {g}\n"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spent::SpentSet;
    use qlab_note::l2note::L2Note;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    use qlab_wallet::Wallet;

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([9u8; ENTROPY_LEN]), 0)
    }

    fn owned(w: &Wallet, idx: u64, value: u64, asset: u64, k: u64, height: u64, tx: Option<u64>) -> OwnedL2Note {
        let note = L2Note { value, asset, rkm: w.rkm(w.diversifier_at_index(idx)), rho: [k; 4], rseed: [k + 1; 4] };
        let mut n = OwnedL2Note::from_genesis(w, idx, [k as u8; 32], note).unwrap();
        n.height = height;
        n.tx_index = tx;
        n
    }

    /// A send of asset 1 with its fee: genesis 1,000 of asset 1 and a 5-unit
    /// fee note; at height 4 both are spent and 600 of asset 1 comes back.
    /// The movement reads `asset 0: −5` and `asset 1: −400`, and the totals
    /// close against the scan's own index.
    #[test]
    fn a_send_reads_as_a_per_asset_net_and_the_totals_close_against_the_index() {
        let w = wallet();
        let usd = owned(&w, 0, 1_000, 1, 10, 0, None);
        let fee = owned(&w, 0, 5, 0, 20, 0, None);
        let change = owned(&w, 0, 600, 1, 30, 4, Some(0));
        let grant = owned(&w, 1, 7, 0, 40, 2, Some(1));
        let notes = vec![usd.clone(), fee.clone(), change.clone(), grant.clone()];
        let set = SpentSet::from_parts(Some((0, 6)), [(4, usd.nullifier(&w)), (4, fee.nullifier(&w))]);
        let index = AssetIndex::build(&w, notes.clone(), &set);
        let cov = SpentCoverage::Covered { range: Some((0, 6)) };

        let l = build((0, 6), [1; 32], Vec::new(), &notes, Some(&index), &cov, Vec::new());

        assert!(l.gaps.is_empty(), "{:?}", l.gaps);
        let heights: Vec<u64> = l.events.iter().map(L2Event::height).collect();
        assert_eq!(heights, vec![0, 0, 2, 4], "two genesis receipts, the grant, then the movement");
        let L2Event::Movement(m) = &l.events[3] else { panic!("height 4 is a movement") };
        assert_eq!(m.inputs.len(), 2);
        assert_eq!(
            m.by_asset.iter().map(|n| (n.asset, n.net())).collect::<Vec<_>>(),
            vec![(0, -5), (1, -400)],
            "the fee and the amount sent, each as its own asset's net"
        );
        assert_eq!(
            l.totals.as_ref().unwrap(),
            &vec![
                AssetTotals { asset: 0, received: 12, spent: 5, spendable: 7 },
                AssetTotals { asset: 1, received: 1_600, spent: 1_000, spendable: 600 },
            ]
        );
        let text = render(&l, "fixture");
        assert!(text.contains("net:       asset 1 -400 (out 1000, back 600)"), "{text}");
        assert!(text.contains("asset 0 (fee units): received 12, spent 5, spendable 7"), "{text}");
    }

    /// 🔴 Without the nullifier stream there is no spend to show, and a
    /// receipts-only ledger must never print totals that read as complete.
    #[test]
    fn without_the_nullifier_stream_it_is_receipts_only_and_prints_no_totals() {
        let w = wallet();
        let notes = vec![owned(&w, 0, 1_000, 1, 10, 0, None), owned(&w, 0, 600, 1, 30, 4, Some(0))];
        let cov = SpentCoverage::Unavailable { why: "GET /v1/nullifiers: connection refused".into() };

        let l = build((0, 6), [1; 32], Vec::new(), &notes, None, &cov, Vec::new());

        assert!(l.totals.is_none());
        assert!(l.events.iter().all(|e| matches!(e, L2Event::Received(_))));
        let text = render(&l, "fixture");
        assert!(text.contains("totals:   UNAVAILABLE"), "{text}");
        assert!(text.contains("receipts only"), "{text}");
    }

    /// A merge (two notes of asset 1 into one, paying a fee) nets asset 1 to
    /// zero: the ledger must not report value leaving that did not.
    #[test]
    fn a_merge_nets_its_asset_to_zero_and_only_the_fee_leaves() {
        let w = wallet();
        let a = owned(&w, 0, 300, 1, 10, 1, Some(0));
        let b = owned(&w, 0, 200, 1, 11, 2, Some(0));
        let fee = owned(&w, 0, 4, 0, 12, 2, Some(1));
        let merged = owned(&w, 0, 500, 1, 13, 5, Some(0));
        let notes = vec![a.clone(), b.clone(), fee.clone(), merged];
        let set = SpentSet::from_parts(Some((0, 5)), [(5, a.nullifier(&w)), (5, b.nullifier(&w)), (5, fee.nullifier(&w))]);
        let index = AssetIndex::build(&w, notes.clone(), &set);

        let l = build((0, 5), [1; 32], Vec::new(), &notes, Some(&index), &SpentCoverage::Covered { range: Some((0, 5)) }, Vec::new());

        let L2Event::Movement(m) = l.events.last().unwrap() else { panic!("the merge is a movement") };
        assert_eq!(m.by_asset.iter().map(|n| (n.asset, n.net())).collect::<Vec<_>>(), vec![(0, -4), (1, 0)]);
    }

    /// H1/H2 (pre-review): one refused row withholds the index while the
    /// nullifiers are in hand — the ledger must say receipts only, not read as
    /// a ledger with no spends; and with nothing owned it must not assert that
    /// nothing happened.
    #[test]
    fn a_withheld_index_under_covered_nullifiers_is_named_and_asserts_no_absence() {
        let w = wallet();
        let cov = SpentCoverage::Covered { range: Some((0, 6)) };
        let row_gap = "outputs for address [1] over heights 0..=6: the scan never started (503)".to_string();
        let notes = vec![owned(&w, 0, 600, 1, 30, 4, Some(0))];

        let l = build((0, 6), [1; 32], Vec::new(), &notes, None, &cov, vec![row_gap.clone()]);
        assert!(l.receipts_only && l.totals.is_none());
        assert!(l.gaps.iter().any(|g| g.starts_with("spends not shown")), "{:?}", l.gaps);
        let text = render(&l, "fixture");
        assert!(text.contains("spends:   UNAVAILABLE — not applied"), "{text}");
        assert!(!text.contains("are in hand"), "{text}");

        let empty = render(&build((0, 6), [1; 32], Vec::new(), &[], None, &cov, vec![row_gap]), "fixture");
        assert!(empty.contains("no events could be read (2 gap(s) below)"), "{empty}");
        assert!(!empty.contains("neither received nor spent"), "{empty}");
    }

    /// H3 (pre-review): a range starting after 0 says what it cannot see, its
    /// totals are labelled as the range's, and a genesis note read anyway says so.
    #[test]
    fn a_range_after_zero_labels_its_totals_and_its_genesis_notes() {
        let w = wallet();
        let notes = vec![owned(&w, 0, 5, 1, 10, 0, None), owned(&w, 0, 9, 0, 11, 7, Some(0))];
        let set = SpentSet::from_parts(Some((5, 9)), []);
        let index = AssetIndex::build(&w, notes.clone(), &set);

        let l = build((5, 9), [1; 32], Vec::new(), &notes, Some(&index), &SpentCoverage::Covered { range: Some((5, 9)) }, Vec::new());

        let text = render(&l, "fixture");
        assert!(text.contains("range:    starts at height 5"), "{text}");
        assert!(text.contains("RECEIVED (genesis note — read although the range starts at 5)"), "{text}");
        assert!(text.contains("over heights 5..=9 only (genesis notes included) — not the wallet's balance"), "{text}");
        let whole = render(&build((0, 9), [1; 32], Vec::new(), &notes, Some(&index), &SpentCoverage::Covered { range: Some((0, 9)) }, Vec::new()), "fixture");
        assert!(!whole.contains("range:    starts at"), "{whole}");
    }

    /// The scan's own reasons are carried in, and any one of them withholds
    /// the totals.
    #[test]
    fn an_upstream_gap_withholds_the_totals() {
        let w = wallet();
        let notes = vec![owned(&w, 0, 9, 0, 10, 1, Some(0))];
        let set = SpentSet::from_parts(Some((0, 3)), []);
        let index = AssetIndex::build(&w, notes.clone(), &set);
        let gap = "outputs for address [1]: the scan never started (404)".to_string();

        let l = build((0, 3), [1; 32], Vec::new(), &notes, Some(&index), &SpentCoverage::Covered { range: Some((0, 3)) }, vec![gap.clone()]);

        assert!(l.totals.is_none());
        assert!(render(&l, "fixture").contains(&gap));
    }
}
