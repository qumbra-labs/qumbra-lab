//! **The Annulet send planner** (lab #720 C2, A4 design #283 Q5): which
//! notes a send spends, which fee notes it splits off first, which notes it
//! merges — pure, over a per-asset index. Moved out of
//! [`crate::annulet_send`] (lab #924) so the browser kernel, which builds
//! without the prover, plans exactly as the CLI does; the CLI re-exports it.

use qlab_air::l2::{L2AuthInput, L2AuthPath};
use qlab_devnet::annulet::L2ShapeTag;
use qlab_wallet::Wallet;
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};

/// The fee tiers a send pays, from the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tiers {
    pub s: u64,
    pub p: u64,
    /// Shape R's tier (lab #728) — a registry write, never a send; carried so
    /// the table is the genesis's whole.
    pub r: u64,
}

impl Tiers {
    pub fn of(&self, shape: L2ShapeTag) -> u64 {
        match shape {
            L2ShapeTag::S => self.s,
            L2ShapeTag::P => self.p,
            L2ShapeTag::R => self.r,
        }
    }
}

/// Why a send cannot be planned — by name ([`crate::annulet_send`]'s
/// `SendRefusal` carries the same variants).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanRefusal {
    /// No single spendable note of `asset` covers `amount` (asset 0: the
    /// amount plus its own S fee).
    NoSingleNoteCovers { asset: u16, amount: u64, largest: u64 },
    /// All of this wallet's spendable `asset` together is below `amount`.
    InsufficientAsset { asset: u16, amount: u64, spendable: u128 },
    /// The plan needs `needed` exact-`tariff` fee notes; the wallet holds
    /// `held` and its asset-0 notes can be split into only `splittable` more.
    FeeNotesShort { tariff: u64, needed: usize, held: usize, splittable: usize },
}

impl std::fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanRefusal::NoSingleNoteCovers { asset, amount, largest } => write!(
                f,
                "no single spendable note of asset {asset} covers {amount} (the largest is {largest})"
            ),
            PlanRefusal::InsufficientAsset { asset, amount, spendable } => write!(
                f,
                "all spendable notes of asset {asset} together hold {spendable}, less than {amount}"
            ),
            PlanRefusal::FeeNotesShort { tariff, needed, held, splittable } => write!(
                f,
                "the plan needs {needed} asset-0 fee note(s) of exactly {tariff}; this wallet holds {held} and \
                 its other asset-0 notes split into {splittable} more"
            ),
        }
    }
}

impl std::error::Error for PlanRefusal {}

/// Where a planned input comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Src {
    /// A note this wallet holds now.
    Held(OwnedL2Note),
    /// Output `out` of plan step `step` — paid to this wallet's address 0,
    /// spendable once that step has landed.
    Made { step: usize, out: usize, value: u64, asset: u16 },
}

impl Src {
    pub fn value(&self) -> u64 {
        match self {
            Src::Held(n) => n.note.value,
            Src::Made { value, .. } => *value,
        }
    }
    /// The first round in which this note can be spent.
    fn ready(&self, steps: &[Step]) -> usize {
        match self {
            Src::Held(_) => 0,
            Src::Made { step, .. } => steps[*step].round + 1,
        }
    }
}

/// One transaction of a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a plan holds a handful of steps
pub enum StepKind {
    /// Shape S, `d3 = 1`: an asset-0 note into an exact-`tariff` fee note and
    /// the rest, both to this wallet, paying the S tier from its own row.
    FeeSplit { source: Src, tariff: u64 },
    /// `d3 = 0`: two notes of the asset into one (to this wallet) plus a
    /// 0-value note of it; slot 3 pays the fee with an exact-tariff note.
    Merge { inputs: [Src; 2], fee: Src },
    /// The payment: `amount` to the payee, the rest back to this wallet.
    /// Asset 0: one note paying its own fee (S, `d3 = 1`). Asset A with one
    /// note: it and the fee note as the two inputs (`d3 = 1`, as C2). Asset A
    /// with two notes: both, and the fee note in slot 3 (`d3 = 0`).
    Pay { inputs: Vec<Src>, fee: Option<Src> },
}

/// A planned transaction: its round (a step spends only notes that landed in
/// an earlier round), its shape and fee, and its two outputs' values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub round: usize,
    pub shape: L2ShapeTag,
    pub fee: u64,
    pub kind: StepKind,
    pub outputs: [u64; 2],
    /// Lab #937: the third output on a format-34 net, as `(value, asset)`.
    /// `None` (every plan today): a zero-value note to this wallet, in the
    /// first input's asset — the builder adds it. `Some` is the prover fee
    /// lab #937 PR D plans (on the asset-0 row, `fee + price` exact); the
    /// builders refuse it by name until then. Ignored on a format-33 net.
    pub third: Option<(u64, u64)>,
}

/// **The one plan a send shows before it proves** (design #283 Q5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendPlan {
    pub asset: u16,
    pub amount: u64,
    pub steps: Vec<Step>,
}

impl SendPlan {
    /// Everything the plan pays, in asset 0.
    pub fn total_fee(&self) -> u64 {
        self.steps.iter().map(|s| s.fee).sum()
    }
    /// Rounds: each waits for the previous one to land.
    pub fn rounds(&self) -> usize {
        self.steps.iter().map(|s| s.round + 1).max().unwrap_or(0)
    }
    pub fn splits(&self) -> usize {
        self.steps.iter().filter(|s| matches!(s.kind, StepKind::FeeSplit { .. })).count()
    }
    pub fn merges(&self) -> usize {
        self.steps.iter().filter(|s| matches!(s.kind, StepKind::Merge { .. })).count()
    }
    /// The payment step (always the last).
    pub fn pay(&self) -> &Step {
        self.steps.last().expect("a plan ends in its payment")
    }
}

impl std::fmt::Display for SendPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vals = |v: &[Src]| v.iter().map(|x| x.value().to_string()).collect::<Vec<_>>().join(" + ");
        writeln!(
            f,
            "plan: send {} of asset {} — {} transaction(s) in {} round(s), total fee {} (asset 0)",
            self.amount,
            self.asset,
            self.steps.len(),
            self.rounds(),
            self.total_fee()
        )?;
        for (i, st) in self.steps.iter().enumerate() {
            let what = match &st.kind {
                StepKind::FeeSplit { source, tariff } => format!(
                    "fee-split  asset-0 note {} → exact {tariff} + {} to self",
                    source.value(),
                    st.outputs[1]
                ),
                StepKind::Merge { inputs, .. } => {
                    format!("merge      {} → {} to self (+ a 0 note), exact fee note in slot 3", vals(inputs), st.outputs[0])
                }
                StepKind::Pay { inputs, fee } => format!(
                    "pay        {} → {} to the payee, {} back{}",
                    vals(inputs),
                    st.outputs[0],
                    st.outputs[1],
                    match fee {
                        Some(_) if inputs.len() == 2 => ", exact fee note in slot 3",
                        Some(_) => ", exact fee note as the second input",
                        None => ", fee from the same note",
                    }
                ),
            };
            writeln!(f, "  [{i}] round {}  shape {:?}  fee {}  {what}", st.round, st.shape, st.fee)?;
        }
        Ok(())
    }
}

pub(crate) fn largest(notes: &[OwnedL2Note]) -> u64 {
    notes.iter().map(|n| n.note.value).max().unwrap_or(0)
}

/// Plan `deficit` exact-`tariff` fee notes from this wallet's asset-0 notes
/// (not the exact ones, which are stock): split the smallest note that can
/// pay a tariff plus its own S fee, earliest-ready first; a split whose rest
/// is itself exact yields two, a rest large enough to split again goes back
/// in the pool for the next round. The steps are appended to `steps`.
fn plan_fee_splits(
    index: &AssetIndex,
    tariff: u64,
    s_tier: u64,
    deficit: usize,
    steps: &mut Vec<Step>,
) -> Result<Vec<Src>, usize> {
    let split_needs = tariff + s_tier;
    let mut pool: Vec<(Src, usize)> =
        index.spendable(0).iter().filter(|n| n.note.value != tariff).map(|n| (Src::Held(n.clone()), 0)).collect();
    let mut made = Vec::new();
    while made.len() < deficit {
        let Some(k) = (0..pool.len())
            .filter(|&k| pool[k].0.value() >= split_needs)
            .min_by_key(|&k| (pool[k].1, pool[k].0.value()))
        else {
            return Err(made.len());
        };
        let (source, round) = pool.swap_remove(k);
        let rest = source.value() - split_needs;
        let step = steps.len();
        steps.push(Step {
            round,
            shape: L2ShapeTag::S,
            fee: s_tier,
            kind: StepKind::FeeSplit { source, tariff },
            outputs: [tariff, rest],
            third: None,
        });
        made.push(Src::Made { step, out: 0, value: tariff, asset: 0 });
        if rest == tariff && made.len() < deficit {
            made.push(Src::Made { step, out: 1, value: rest, asset: 0 });
        } else if rest >= split_needs {
            pool.push((Src::Made { step, out: 1, value: rest, asset: 0 }, round + 1));
        }
    }
    Ok(made)
}

/// **Selection** — pure, over a per-asset index (design #283 Q5).
///
/// - Asset 0: one covering note pays `amount` and its own S fee (C2).
/// - Asset A, one covering note: the smallest, plus one exact-tariff fee note
///   (C2's payment, `d3 = 1`).
/// - Asset A, no covering note: the fewest largest notes that cover the
///   amount; merge the two smallest until two cover it; pay with those two
///   (`d3 = 0`). Every merge and the payment take one exact-tariff note.
///
/// Missing exact notes are fee-split first. Refused by name when the asset
/// is short ([`PlanRefusal::InsufficientAsset`]) or the asset-0 funds cannot
/// make the fee notes ([`PlanRefusal::FeeNotesShort`]).
pub fn plan_send(index: &AssetIndex, asset: u16, amount: u64, shape: L2ShapeTag, tiers: Tiers) -> Result<SendPlan, PlanRefusal> {
    let smallest_covering = |a: u16, need: u64| {
        index.spendable(a).iter().filter(|n| n.note.value >= need).min_by_key(|n| n.note.value).cloned()
    };
    if asset == 0 {
        // The fee comes out of the same note: one input, shape S.
        let need = amount.saturating_add(tiers.s);
        let note = smallest_covering(0, need)
            .ok_or(PlanRefusal::NoSingleNoteCovers { asset, amount: need, largest: largest(index.spendable(0)) })?;
        let change = note.note.value - need;
        let pay = Step {
            round: 0,
            shape: L2ShapeTag::S,
            fee: tiers.s,
            kind: StepKind::Pay { inputs: vec![Src::Held(note)], fee: None },
            outputs: [amount, change],
            third: None,
        };
        return Ok(SendPlan { asset, amount, steps: vec![pay] });
    }
    let tariff = tiers.of(shape);

    // The A notes the payment will consume, and the merges that reduce them
    // to at most two.
    let mut merges: Vec<[Src; 2]> = Vec::new();
    let pay_inputs: Vec<Src> = if let Some(note) = smallest_covering(asset, amount) {
        vec![Src::Held(note)]
    } else {
        let mut notes: Vec<OwnedL2Note> = index.spendable(asset).to_vec();
        notes.sort_by_key(|n| std::cmp::Reverse(n.note.value));
        let mut chosen: Vec<Src> = Vec::new();
        let mut total = 0u128;
        for n in notes {
            if total >= u128::from(amount) {
                break;
            }
            total += u128::from(n.note.value);
            chosen.push(Src::Held(n));
        }
        if total < u128::from(amount) {
            return Err(PlanRefusal::InsufficientAsset { asset, amount, spendable: total });
        }
        // Merge the two smallest until the two largest cover the amount. A
        // merge's output stands in as a placeholder until its step exists.
        let top2 = |v: &[Src]| {
            let mut x: Vec<u64> = v.iter().map(Src::value).collect();
            x.sort_unstable_by(|a, b| b.cmp(a));
            x.iter().take(2).map(|v| u128::from(*v)).sum::<u128>()
        };
        while top2(&chosen) < u128::from(amount) {
            chosen.sort_by_key(Src::value);
            let b = chosen.remove(1);
            let a = chosen.remove(0);
            let value = a.value() + b.value();
            merges.push([a, b]);
            // `step` is the merge's index among the merges; fixed up below.
            chosen.push(Src::Made { step: merges.len() - 1, out: 0, value, asset });
        }
        chosen
    };

    // Exact-tariff fee notes: one per merge and one for the payment.
    let needed = merges.len() + 1;
    let stock: Vec<Src> =
        index.spendable(0).iter().filter(|n| n.note.value == tariff).take(needed).map(|n| Src::Held(n.clone())).collect();
    let mut steps: Vec<Step> = Vec::new();
    let made = plan_fee_splits(index, tariff, tiers.s, needed - stock.len(), &mut steps).map_err(|made| {
        PlanRefusal::FeeNotesShort { tariff, needed, held: stock.len(), splittable: made }
    })?;
    let mut fees: Vec<Src> = stock.into_iter().chain(made).collect();
    fees.sort_by_key(|f| f.ready(&steps));
    let mut fees = fees.into_iter();

    // Merge steps: fix the placeholders up to real step indices.
    let base = steps.len();
    let fix = |src: Src| match src {
        Src::Made { step, out, value, asset: a } if a == asset => Src::Made { step: base + step, out, value, asset: a },
        other => other,
    };
    for [a, b] in merges {
        let (a, b) = (fix(a), fix(b));
        let fee = fees.next().expect("one fee note per merge");
        let round = a.ready(&steps).max(b.ready(&steps)).max(fee.ready(&steps));
        let value = a.value() + b.value();
        steps.push(Step { round, shape, fee: tariff, kind: StepKind::Merge { inputs: [a, b], fee }, outputs: [value, 0], third: None });
    }
    let pay_inputs: Vec<Src> = pay_inputs.into_iter().map(fix).collect();
    let fee = fees.next().expect("one fee note for the payment");
    let round = pay_inputs.iter().chain(std::iter::once(&fee)).map(|x| x.ready(&steps)).max().unwrap_or(0);
    let have: u64 = pay_inputs.iter().map(Src::value).sum();
    steps.push(Step {
        round,
        shape,
        fee: tariff,
        kind: StepKind::Pay { inputs: pay_inputs, fee: Some(fee) },
        outputs: [amount, have - amount],
        third: None,
    });
    Ok(SendPlan { asset, amount, steps })
}


/// A real input: `note` (this wallet's, generation `g`) with the leaf `path`.
pub fn real_input(wallet: &Wallet, note: &OwnedL2Note, path: L2AuthPath) -> L2AuthInput {
    L2AuthInput {
        nk: wallet.nk(),
        value: note.note.value,
        asset: note.note.asset,
        rho: note.note.rho,
        rseed: note.note.rseed,
        d: wallet.diversifier_at_index(note.div_index).lanes(),
        auth: path,
    }
}

/// The leaves an ordinary send must leave unconsumed in its generation:
/// one per spendable note plus two, so the generation can always still be
/// swept. A hard floor ahead of Phase 4's reserve (`2 × unspent + 16`,
/// design 2b §9), which replaces it.
pub const SWEEP_FLOOR_EXTRA: u32 = 2;

/// The real slots — leaves — a plan takes: a fee split 1, a merge 3, a
/// payment 1, 2 or 3 by its inputs and fee note.
pub fn plan_slots(plan: &SendPlan) -> u32 {
    plan.steps
        .iter()
        .map(|s| match &s.kind {
            StepKind::FeeSplit { .. } => 1,
            StepKind::Merge { .. } => 3,
            StepKind::Pay { inputs, fee } => inputs.len() as u32 + u32::from(fee.is_some()),
        })
        .sum()
}
