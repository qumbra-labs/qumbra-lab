//! **`send --net annulet`** (lab #720, L2 C2): a two-asset bundle from the
//! wallet's own notes, with the fee-note discipline.
//!
//! The rules, each refused by name when it cannot be met:
//!
//! - **The fee is an exact-tariff asset-0 note.** A 2×2 bucket pays its fee in
//!   asset 0 and has no fee-change slot, so the fee input is spent whole and
//!   must equal the shape's tariff (`/v1/annulet/params`).
//! - **Fee-split first when there is none.** A single-asset shape-S spend of a
//!   larger asset-0 note into one exact-tariff note plus change, paying its own
//!   S fee from the same input. One fee note per split: the bucket has two
//!   outputs.
//! - **Merge when no one note covers (A4, design #283).** The 3×2 shapes
//!   carry a third input, slot 3, for the fee: an exact-tariff asset-0 note
//!   (`d3 = 0`, the rows carry no fee) or a dummy (`d3 = 1`, the fee from an
//!   asset-0 row, as before). With `d3 = 0` both rows are free to be one
//!   asset, so two A notes merge. The planner ([`plan_send`]) picks the
//!   fewest largest A notes that cover the amount, merges the two smallest
//!   until two cover it, and pays with those two; every merge and the payment
//!   needs one exact-tariff note, and the missing ones are fee-split first.
//!   The whole plan — rounds, transactions, total fee — is shown before
//!   anything is proved. (Before A4 two A notes could not be combined at all:
//!   lab #720 P4.)
//! - **The shape is the asset's.** S for Cloaked (and asset 0), P for Hybrid,
//!   vPublic = 0. What the wallet cannot open itself (a non-empty freeze tree,
//!   a Regulated allowlist) is refused by name; its owner is C3.
//!
//! **Nothing is written to the wallet dir.** The commitment tree is rebuilt in
//! memory; no L1 file (`tree-leaves.v1`, `sends.v1`) is read or written on an
//! Annulet net.

use std::time::{Duration, Instant};

use qlab_devnet::annulet::L2ShapeTag;
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_air::l2p::VPublic;
use qlab_l2spend::{build_p_merge, build_p_with, build_s, build_s_merge, shape_for, Endpoint, Out, Recipient, Served, SpendError};
use qlab_wallet::address::Address;
use rand::rngs::StdRng;

use crate::annulet::{scan_annulet, AnnuletRefusal};
use crate::store::WalletDir;

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

/// Why a send cannot be planned or made — by name.
#[derive(Debug, PartialEq, Eq)]
pub enum SendRefusal {
    /// No single spendable note of `asset` covers the amount (plus the fee,
    /// for asset 0). Notes cannot be merged in 2×2 (lab #720 P4).
    NoSingleNoteCovers { asset: u16, amount: u64, largest: u64 },
    /// No exact-tariff asset-0 note, and none large enough to split one off.
    NoFeeSource { tariff: u64, split_needs: u64 },
    /// A4: all of this wallet's spendable `asset` together is below `amount`.
    InsufficientAsset { asset: u16, amount: u64, spendable: u128 },
    /// A4: the plan needs `needed` exact-`tariff` fee notes; the wallet holds
    /// `held` and its asset-0 notes can be split into only `splittable` more.
    FeeNotesShort { tariff: u64, needed: usize, held: usize, splittable: usize },
    /// The plan was shown and not accepted: nothing was proved.
    PlanDeclined,
    /// The wallet has no quotable balance (the scan or the spends were not
    /// both known — lab #314).
    NoBalance,
    /// The endpoint is not the pinned Annulet chain, or not Annulet at all.
    Form(AnnuletRefusal),
    /// The endpoint's params are for a different genesis than it serves.
    ParamsGenesisMismatch,
    /// The assembly or the node said no.
    Spend(SpendError),
    /// A fee-split was admitted but its note did not appear in the tree.
    SplitNotIncluded { waited_secs: u64 },
    /// This wallet holds no issuer secret for `asset` whose key is the
    /// registry's `issuer_key` (lab #722).
    NotTheIssuer { asset: u16 },
    /// A mint rides an issuer-held note of the asset, and there is none
    /// (lab #722 P3).
    NoIssuerNote { asset: u16 },
    /// The issuer file could not be read.
    Issuer(String),
    /// A registration into a slot that already holds a leaf (C4a, lab #730).
    SlotTaken { asset: u16 },
    /// An update of a slot that holds no leaf.
    SlotEmpty { asset: u16 },
    /// The leaf asked for is not one shape R writes (mode ⇒ roots, asset 0,
    /// a Cloaked asset with a policy list …) — refused before proving.
    LeafRefused(String),
    /// No asset-0 note of at least the R tariff to pay a registry write.
    NoRegistryFeeNote { tariff: u64 },
    /// Another registry write was pooled or landed first: this one binds a
    /// root that is gone. Re-read the slot and write again.
    RegistryRaced(String),
}

impl std::fmt::Display for SendRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendRefusal::NoSingleNoteCovers { asset, amount, largest } => write!(
                f,
                "no single spendable note of asset {asset} covers {amount} (the largest is {largest}). \
                 An L2 2×2 transaction takes one note of the asset plus one asset-0 fee note, and two \
                 notes of a non-fee asset cannot be merged (both inputs would be that asset and nothing \
                 would pay the fee) — a recorded design limit, lab #720 P4. Send at most {largest}"
            ),
            SendRefusal::NoFeeSource { tariff, split_needs } => write!(
                f,
                "no asset-0 note of exactly {tariff} (the fee is paid whole: there is no fee change in \
                 2×2), and no asset-0 note of at least {split_needs} to split one off"
            ),
            SendRefusal::InsufficientAsset { asset, amount, spendable } => write!(
                f,
                "all spendable notes of asset {asset} together hold {spendable}, less than {amount}"
            ),
            SendRefusal::FeeNotesShort { tariff, needed, held, splittable } => write!(
                f,
                "the plan needs {needed} asset-0 fee note(s) of exactly {tariff} (one per merge and one for \
                 the payment — each is spent whole); this wallet holds {held} and its other asset-0 notes \
                 split into {splittable} more"
            ),
            SendRefusal::PlanDeclined => write!(f, "the plan was not accepted; nothing was proved"),
            SendRefusal::NoBalance => write!(
                f,
                "no quotable balance: the scan did not establish both the outputs and the spends"
            ),
            SendRefusal::Form(e) => write!(f, "{e}"),
            SendRefusal::ParamsGenesisMismatch => {
                write!(f, "the endpoint's /v1/annulet/params name a different genesis than it serves")
            }
            SendRefusal::Spend(e) => write!(f, "{e}"),
            SendRefusal::NotTheIssuer { asset } => write!(
                f,
                "this wallet holds no issuer secret for asset {asset} matching the registry's issuer key"
            ),
            SendRefusal::NoIssuerNote { asset } => write!(
                f,
                "a mint rides an issuer-held note of asset {asset} and this wallet holds none (lab #722 P3: \
                 the genesis seeds one; an issuer that spends its last one cannot mint again)"
            ),
            SendRefusal::Issuer(e) => write!(f, "issuer file: {e}"),
            SendRefusal::SlotTaken { asset } => write!(
                f,
                "registry slot {asset} already holds a leaf: a registration writes an empty slot (an issuer \
                 changes its own leaf with `issuer update`)"
            ),
            SendRefusal::SlotEmpty { asset } => {
                write!(f, "registry slot {asset} holds no leaf: register it first")
            }
            SendRefusal::LeafRefused(why) => write!(f, "the registry leaf is refused before proving: {why}"),
            SendRefusal::NoRegistryFeeNote { tariff } => write!(
                f,
                "no asset-0 note of at least {tariff} (the registry-write tariff) to pay with; the change \
                 comes back, so any note that large will do"
            ),
            SendRefusal::RegistryRaced(node) => write!(
                f,
                "another registry write was pooled or landed first, so this one binds a registry root that is \
                 gone ({node}); re-read the slot and write again"
            ),
            SendRefusal::SplitNotIncluded { waited_secs } => write!(
                f,
                "the fee-split was admitted but its note was not in the served tree after {waited_secs} s; \
                 run the send again once it is"
            ),
        }
    }
}

impl std::error::Error for SendRefusal {}

impl From<SpendError> for SendRefusal {
    fn from(e: SpendError) -> Self {
        SendRefusal::Spend(e)
    }
}

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

fn largest(notes: &[OwnedL2Note]) -> u64 {
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
/// is short ([`SendRefusal::InsufficientAsset`]) or the asset-0 funds cannot
/// make the fee notes ([`SendRefusal::FeeNotesShort`]).
pub fn plan_send(index: &AssetIndex, asset: u16, amount: u64, shape: L2ShapeTag, tiers: Tiers) -> Result<SendPlan, SendRefusal> {
    let smallest_covering = |a: u16, need: u64| {
        index.spendable(a).iter().filter(|n| n.note.value >= need).min_by_key(|n| n.note.value).cloned()
    };
    if asset == 0 {
        // The fee comes out of the same note: one input, shape S.
        let need = amount.saturating_add(tiers.s);
        let note = smallest_covering(0, need)
            .ok_or(SendRefusal::NoSingleNoteCovers { asset, amount: need, largest: largest(index.spendable(0)) })?;
        let change = note.note.value - need;
        let pay = Step {
            round: 0,
            shape: L2ShapeTag::S,
            fee: tiers.s,
            kind: StepKind::Pay { inputs: vec![Src::Held(note)], fee: None },
            outputs: [amount, change],
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
            return Err(SendRefusal::InsufficientAsset { asset, amount, spendable: total });
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
        SendRefusal::FeeNotesShort { tariff, needed, held: stock.len(), splittable: made }
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
        steps.push(Step { round, shape, fee: tariff, kind: StepKind::Merge { inputs: [a, b], fee }, outputs: [value, 0] });
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
    });
    Ok(SendPlan { asset, amount, steps })
}

/// The recipient an [`Address`] names.
pub fn recipient_of(addr: &Address) -> Option<Recipient> {
    Some(Recipient { rkm: addr.rkm_lanes(), ek: addr.encapsulation_key()? })
}

/// What a send did.
pub struct SendReport {
    pub plan: SendPlan,
    /// The first fee-split's exact-tariff note, when the plan split one.
    pub split_fee_note: Option<qlab_note::l2note::L2Note>,
    /// The notes the payment created: `[to the recipient, change to this wallet]`.
    pub outputs: [qlab_note::l2note::L2Note; 2],
    pub shape: L2ShapeTag,
}

fn wait_in_tree<E: Endpoint>(served: &Served<E>, cm: &[u64; 4], timeout: Duration) -> Result<(), SendRefusal> {
    let start = Instant::now();
    loop {
        if served.commitment_tree()?.position_of(cm).is_some() {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(SendRefusal::SplitNotIncluded { waited_secs: timeout.as_secs() });
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// What every Annulet spend starts from: the verified endpoint, its tariff,
/// and this wallet's per-asset index (lab #720/#722).
pub struct Session<E: Endpoint> {
    pub served: Served<E>,
    pub tiers: Tiers,
    pub index: AssetIndex,
    pub genesis_hash: [u8; 32],
}

/// Verify the form (and pin), read the tariff (checked against the served
/// genesis), and scan to `scan_to`.
pub fn open_session<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<Session<E>, SendRefusal> {
    let served = Served::new(endpoint);
    let mut fetch = |p: &str| served.endpoint.get(p);
    let report = scan_annulet(w, &mut fetch, 0, scan_to, pin, rng).map_err(SendRefusal::Form)?;
    let params = served.params()?;
    if params.genesis_hash != report.genesis_hash {
        return Err(SendRefusal::ParamsGenesisMismatch);
    }
    let tiers = Tiers { s: params.fee_tier_s, p: params.fee_tier_p, r: params.fee_tier_r };
    let index = report.index.ok_or(SendRefusal::NoBalance)?;
    Ok(Session { served, tiers, index, genesis_hash: report.genesis_hash })
}

/// This wallet's receiving [`Recipient`] (address 0: change, split notes).
pub fn me(w: &WalletDir) -> Recipient {
    recipient_of(&w.wallet().address_at_index(0)).expect("the wallet's own address has an ek")
}

/// **An exact-`tariff` asset-0 fee note**: one the wallet holds, or one
/// split off a larger asset-0 note first (shape S, its own S fee from the same
/// input), waited for until it is in the served tree. Returns the fee note and,
/// when a split was made, the note it minted.
pub fn exact_fee_note<E: Endpoint>(
    w: &WalletDir,
    session: &Session<E>,
    tariff: u64,
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<(OwnedL2Note, Option<qlab_note::l2note::L2Note>), SendRefusal> {
    if let Some(fee) = session.index.spendable(0).iter().find(|n| n.note.value == tariff) {
        return Ok((fee.clone(), None));
    }
    let split_needs = tariff + session.tiers.s;
    let source = session
        .index
        .spendable(0)
        .iter()
        .filter(|n| n.note.value >= split_needs)
        .min_by_key(|n| n.note.value)
        .ok_or(SendRefusal::NoFeeSource { tariff, split_needs })?;
    let wallet = w.wallet();
    let split = build_s(
        &session.served,
        &[&source.spend_input(&wallet)],
        &[
            Out { to: me(w), value: tariff, asset: 0 },
            Out { to: me(w), value: source.note.value - tariff - session.tiers.s, asset: 0 },
        ],
        session.tiers.s,
        rng,
    )?;
    session.served.submit(&split.tx)?;
    let made = split.outputs[0];
    wait_in_tree(&session.served, &made.commitment(), split_wait)?;
    let owned = OwnedL2Note::from_genesis(&wallet, 0, qlab_note::hash::digest_bytes(&made.commitment()), made)
        .expect("the split paid this wallet's address 0");
    Ok((owned, Some(made)))
}

/// **The send**: verify the form (and pin), read the tariff, scan, plan,
/// hand the plan to `on_plan` **before anything is proved** (it returns
/// whether to go on), then run it round by round — each round's notes are
/// waited for in the served tree before the next round spends them.
/// `scan_to` bounds the scan (a balance is a claim about a range).
/// `freeze_keys` is the asset issuer's published freeze list (lab #722; empty
/// for an asset with an empty freeze tree): an address on it is refused before
/// anything is proved.
#[allow(clippy::too_many_arguments)]
pub fn send_annulet<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    amount: u64,
    to: &Address,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    freeze_keys: &[[u64; 4]],
    split_wait: Duration,
    on_plan: &mut dyn FnMut(&SendPlan) -> bool,
    rng: &mut StdRng,
) -> Result<SendReport, SendRefusal> {
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    let shape = shape_for(&leaf);
    let wallet = w.wallet();
    if shape == L2ShapeTag::P
        && qlab_air::l2p::CanonicalFreezeTree::from_keys(freeze_keys).is_frozen(&wallet.rkm(wallet.diversifier_at_index(0)))
    {
        return Err(SendRefusal::Spend(SpendError::Frozen { asset: u64::from(asset) }));
    }
    let plan = plan_send(&session.index, asset, amount, shape, session.tiers)?;
    let recipient = recipient_of(to).ok_or(SendRefusal::Spend(SpendError::Served("the recipient address has no valid ek".into())))?;
    if !on_plan(&plan) {
        return Err(SendRefusal::PlanDeclined);
    }
    let made = run_plan(w, &session, &plan, &recipient, freeze_keys, split_wait, rng)?;
    let split_fee_note = plan
        .steps
        .iter()
        .position(|s| matches!(s.kind, StepKind::FeeSplit { .. }))
        .map(|i| made[i].0[0]);
    let (outputs, shape) = *made.last().expect("a plan ends in its payment");
    Ok(SendReport { plan, split_fee_note, outputs, shape })
}

/// Run `plan` round by round: build, prove and submit each step, then wait
/// until every note a later step spends is in the served tree. Returns each
/// step's output notes and shape, in plan order.
fn run_plan<E: Endpoint>(
    w: &WalletDir,
    session: &Session<E>,
    plan: &SendPlan,
    recipient: &Recipient,
    freeze_keys: &[[u64; 4]],
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<Vec<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>, SendRefusal> {
    let wallet = w.wallet();
    let served = &session.served;
    let s_tier = session.tiers.s;
    let a = u64::from(plan.asset);
    let ctx = qlab_l2spend::PolicyContext { freeze_keys: freeze_keys.to_vec(), ..Default::default() };
    let mut made: Vec<Option<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>> = vec![None; plan.steps.len()];
    let owned = |made: &[Option<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>], src: &Src| -> OwnedL2Note {
        match src {
            Src::Held(n) => n.clone(),
            Src::Made { step, out, .. } => {
                let note = made[*step].expect("a step spends only notes of earlier rounds").0[*out];
                OwnedL2Note::from_genesis(&wallet, 0, qlab_note::hash::digest_bytes(&note.commitment()), note)
                    .expect("a planned note was paid to this wallet's address 0")
            }
        }
    };
    for round in 0..plan.rounds() {
        for (i, st) in plan.steps.iter().enumerate().filter(|(_, s)| s.round == round) {
            let built = match &st.kind {
                StepKind::FeeSplit { source, tariff } => {
                    let src = owned(&made, source);
                    let outs = [
                        Out { to: me(w), value: *tariff, asset: 0 },
                        Out { to: me(w), value: st.outputs[1], asset: 0 },
                    ];
                    build_s(served, &[&src.spend_input(&wallet)], &outs, s_tier, rng)?
                }
                StepKind::Merge { inputs, fee } => {
                    let ins = [owned(&made, &inputs[0]).spend_input(&wallet), owned(&made, &inputs[1]).spend_input(&wallet)];
                    let fee_in = owned(&made, fee).spend_input(&wallet);
                    let outs = [Out { to: me(w), value: st.outputs[0], asset: a }, Out { to: me(w), value: 0, asset: a }];
                    match st.shape {
                        L2ShapeTag::S => build_s_merge(served, [&ins[0], &ins[1]], &outs, st.fee, &fee_in, rng)?,
                        _ => build_p_merge(served, [&ins[0], &ins[1]], &outs, st.fee, [&ctx, &ctx], &fee_in, rng)?,
                    }
                }
                StepKind::Pay { inputs, fee } => {
                    let ins: Vec<_> = inputs.iter().map(|x| owned(&made, x).spend_input(&wallet)).collect();
                    let outs = [
                        Out { to: recipient.clone(), value: st.outputs[0], asset: a },
                        Out { to: me(w), value: st.outputs[1], asset: a },
                    ];
                    match (fee, ins.as_slice()) {
                        // Asset 0: the fee from the same note.
                        (None, [one]) => build_s(served, &[one], &outs, st.fee, rng)?,
                        // C2's payment: one A note, the fee note as input 2.
                        (Some(fee), [one]) => {
                            let fee_in = owned(&made, fee).spend_input(&wallet);
                            match st.shape {
                                L2ShapeTag::S => build_s(served, &[one, &fee_in], &outs, st.fee, rng)?,
                                _ => build_p_with(
                                    served,
                                    [one, &fee_in],
                                    &outs,
                                    st.fee,
                                    [&ctx, &Default::default()],
                                    [VPublic::NONE; 2],
                                    rng,
                                )?,
                            }
                        }
                        // A4: two A notes, the fee note in slot 3.
                        (Some(fee), [x, y]) => {
                            let fee_in = owned(&made, fee).spend_input(&wallet);
                            match st.shape {
                                L2ShapeTag::S => build_s_merge(served, [x, y], &outs, st.fee, &fee_in, rng)?,
                                _ => build_p_merge(served, [x, y], &outs, st.fee, [&ctx, &ctx], &fee_in, rng)?,
                            }
                        }
                        _ => unreachable!("a payment is planned with one or two inputs"),
                    }
                }
            };
            served.submit(&built.tx)?;
            made[i] = Some((built.outputs, built.shape));
        }
        // Every note a later round spends must be in the tree first.
        for later in plan.steps.iter().filter(|s| s.round > round) {
            let srcs: Vec<&Src> = match &later.kind {
                StepKind::FeeSplit { source, .. } => vec![source],
                StepKind::Merge { inputs, fee } => inputs.iter().chain(std::iter::once(fee)).collect(),
                StepKind::Pay { inputs, fee } => inputs.iter().chain(fee.iter()).collect(),
            };
            for src in srcs {
                if let Src::Made { step, out, .. } = src {
                    if plan.steps[*step].round == round {
                        let note = made[*step].expect("made this round").0[*out];
                        wait_in_tree(served, &note.commitment(), split_wait)?;
                    }
                }
            }
        }
    }
    Ok(made.into_iter().map(|m| m.expect("every step ran")).collect())
}

/// The wallet's own transport as an [`Endpoint`]: `http://host:PORT` or
/// `https://host[:port]`, the same TLS path every other command uses.
#[cfg(feature = "net")]
pub struct WalletEndpoint {
    pub url: String,
}

#[cfg(feature = "net")]
impl Endpoint for WalletEndpoint {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        crate::net::http_get(&self.url, path).map_err(|e| e.to_string())
    }
    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        crate::net::http_post_bytes(&self.url, path, body).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_ledger::spent::SpentSet;
    use qlab_note::l2note::L2Note;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    use qlab_wallet::Wallet;

    const TIERS: Tiers = Tiers { s: 1, p: 2, r: 4 };

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([3u8; ENTROPY_LEN]), 0)
    }

    fn index(notes: &[(u64, u64)]) -> AssetIndex {
        let w = wallet();
        let owned = notes
            .iter()
            .enumerate()
            .map(|(k, &(asset, value))| {
                let note = L2Note { value, asset, rkm: w.rkm(w.diversifier_at_index(0)), rho: [k as u64 + 1; 4], rseed: [9; 4] };
                OwnedL2Note::from_genesis(&w, 0, [k as u8; 32], note).unwrap()
            })
            .collect();
        AssetIndex::build(&w, owned, &SpentSet::from_parts(Some((0, 1)), []))
    }

    fn kinds(plan: &SendPlan) -> Vec<(&'static str, usize, u64)> {
        plan.steps
            .iter()
            .map(|s| {
                let k = match s.kind {
                    StepKind::FeeSplit { .. } => "split",
                    StepKind::Merge { .. } => "merge",
                    StepKind::Pay { .. } => "pay",
                };
                (k, s.round, s.fee)
            })
            .collect()
    }

    #[test]
    fn an_asset_zero_send_pays_its_fee_from_the_same_note() {
        let ix = index(&[(0, 5), (0, 20), (0, 8)]);
        let plan = plan_send(&ix, 0, 7, L2ShapeTag::S, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("pay", 0, 1)]);
        match &plan.pay().kind {
            StepKind::Pay { inputs, fee: None } => assert_eq!(inputs[0].value(), 8),
            other => panic!("{other:?}"),
        }
        assert_eq!(plan.pay().outputs, [7, 0]);
        assert_eq!(
            plan_send(&ix, 0, 20, L2ShapeTag::S, TIERS),
            Err(SendRefusal::NoSingleNoteCovers { asset: 0, amount: 21, largest: 20 })
        );
    }

    #[test]
    fn a_policy_asset_takes_one_covering_note_and_an_exact_tariff_fee_note() {
        let ix = index(&[(1, 400), (1, 600), (0, 2), (0, 7)]);
        let plan = plan_send(&ix, 1, 500, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("pay", 0, 2)]);
        match &plan.pay().kind {
            StepKind::Pay { inputs, fee: Some(fee) } => {
                assert_eq!((inputs.len(), inputs[0].value(), fee.value()), (1, 600, 2));
                assert!(matches!(fee, Src::Held(_)), "the held exact note, not a split");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(plan.pay().outputs, [500, 100]);
    }

    /// A4: two notes of a non-fee asset now pay together — both inputs are
    /// the asset and slot 3 pays the fee (`d3 = 0`). No merge is needed when
    /// the two largest already cover.
    #[test]
    fn two_notes_of_a_non_fee_asset_pay_together_with_the_fee_in_slot_3() {
        let ix = index(&[(1, 400), (1, 400), (0, 2)]);
        let plan = plan_send(&ix, 1, 700, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("pay", 0, 2)]);
        match &plan.pay().kind {
            StepKind::Pay { inputs, fee: Some(_) } => assert_eq!(inputs.iter().map(Src::value).collect::<Vec<_>>(), [400, 400]),
            other => panic!("{other:?}"),
        }
        assert_eq!(plan.pay().outputs, [700, 100]);
        // An asset-0 surplus never pays for asset 1: refused by name.
        let ix = index(&[(1, 400), (0, 1_000)]);
        assert_eq!(
            plan_send(&ix, 1, 500, L2ShapeTag::P, TIERS),
            Err(SendRefusal::InsufficientAsset { asset: 1, amount: 500, spendable: 400 })
        );
    }

    /// **Design #283's example: ten 10s → pay 50.** The five largest cover;
    /// three merges (two smallest first) leave two notes that cover; four
    /// exact P-tariff notes are needed (three merges + the payment). The one
    /// asset-0 note is split four times, each split's rest feeding the next.
    #[test]
    fn ten_notes_of_ten_pay_fifty_after_three_merges_and_four_fee_notes() {
        let mut notes = vec![(1u64, 10u64); 10];
        notes.push((0, 100));
        let ix = index(&notes);
        let plan = plan_send(&ix, 1, 50, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!((plan.splits(), plan.merges(), plan.steps.len()), (4, 3, 8), "{plan}");
        // 4 splits × S tier 1 + (3 merges + 1 payment) × P tier 2.
        assert_eq!(plan.total_fee(), 4 + 8, "{plan}");
        // The splits chain on one source: 100 → 2 + 97 → 2 + 94 → 2 + 91 → 2 + 88.
        let rests: Vec<u64> = plan.steps[..4].iter().map(|s| s.outputs[1]).collect();
        assert_eq!(rests, [97, 94, 91, 88]);
        assert_eq!(plan.steps[..4].iter().map(|s| s.round).collect::<Vec<_>>(), [0, 1, 2, 3]);
        // Every merge and the payment spends one exact note, and no step
        // spends a note before the round after the one that made it.
        let mut spent_fees = 0;
        for (i, st) in plan.steps.iter().enumerate() {
            let srcs: Vec<&Src> = match &st.kind {
                StepKind::FeeSplit { source, .. } => vec![source],
                StepKind::Merge { inputs, fee } => {
                    assert_eq!(fee.value(), 2);
                    spent_fees += 1;
                    inputs.iter().chain(std::iter::once(fee)).collect()
                }
                StepKind::Pay { inputs, fee } => {
                    assert_eq!(fee.as_ref().map(Src::value), Some(2));
                    spent_fees += 1;
                    inputs.iter().chain(fee.iter()).collect()
                }
            };
            for src in srcs {
                if let Src::Made { step, .. } = src {
                    assert!(*step < i, "step {i} spends a later step's output");
                    assert!(plan.steps[*step].round < st.round, "step {i} spends a note of its own round");
                }
            }
        }
        assert_eq!(spent_fees, 4);
        // The payment: two notes summing to 50, all of it to the payee.
        let pay = plan.pay();
        match &pay.kind {
            StepKind::Pay { inputs, .. } => assert_eq!(inputs.iter().map(Src::value).sum::<u64>(), 50),
            other => panic!("{other:?}"),
        }
        assert_eq!(pay.outputs, [50, 0]);
        // Only five of the ten notes are touched.
        let held_a = plan
            .steps
            .iter()
            .flat_map(|s| match &s.kind {
                StepKind::Merge { inputs, .. } => inputs.to_vec(),
                StepKind::Pay { inputs, .. } => inputs.clone(),
                StepKind::FeeSplit { .. } => vec![],
            })
            .filter(|x| matches!(x, Src::Held(_)))
            .count();
        assert_eq!(held_a, 5);
        let text = plan.to_string();
        assert!(text.contains("8 transaction(s)") && text.contains("total fee 12"), "{text}");
    }

    /// Held exact notes are spent first (a merge that has one runs in round
    /// 0); a split's fee note is ready the round after the split.
    #[test]
    fn held_exact_notes_come_first() {
        // Three 10s → 25: one merge (10 + 10) then pay 20 + 10. Needs two P
        // notes; holds one; the 5 is split for the other.
        let ix = index(&[(1, 10), (1, 10), (1, 10), (0, 2), (0, 5)]);
        let plan = plan_send(&ix, 1, 25, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("split", 0, 1), ("merge", 0, 2), ("pay", 1, 2)], "{plan}");
        match &plan.steps[1].kind {
            StepKind::Merge { fee, .. } => assert!(matches!(fee, Src::Held(_)), "the held note goes to round 0"),
            other => panic!("{other:?}"),
        }
        match &plan.pay().kind {
            StepKind::Pay { fee: Some(fee), .. } => assert!(matches!(fee, Src::Made { step: 0, out: 0, .. })),
            other => panic!("{other:?}"),
        }
    }

    /// A split whose rest is itself exact yields two fee notes (#283: "a
    /// `d3 = 1` S spend yields two exact notes").
    #[test]
    fn a_split_whose_rest_is_exact_yields_two_fee_notes() {
        // 5 = 2 + 2 + the S tier: one split pays both the merge and the payment.
        let ix = index(&[(1, 10), (1, 10), (1, 10), (0, 5)]);
        let plan = plan_send(&ix, 1, 25, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("split", 0, 1), ("merge", 1, 2), ("pay", 2, 2)], "{plan}");
        assert_eq!(plan.steps[0].outputs, [2, 2]);
        let fees: Vec<Src> = plan
            .steps
            .iter()
            .filter_map(|s| match &s.kind {
                StepKind::Merge { fee, .. } => Some(fee.clone()),
                StepKind::Pay { fee, .. } => fee.clone(),
                StepKind::FeeSplit { .. } => None,
            })
            .collect();
        assert!(matches!(fees[0], Src::Made { step: 0, out: 0, .. }), "{fees:?}");
        assert!(matches!(fees[1], Src::Made { step: 0, out: 1, .. }), "{fees:?}");
        assert_eq!(plan.total_fee(), 1 + 2 + 2);
    }

    #[test]
    fn without_an_exact_tariff_note_the_plan_splits_first_or_refuses() {
        let ix = index(&[(1, 50), (0, 3)]);
        let plan = plan_send(&ix, 1, 50, L2ShapeTag::P, TIERS).unwrap();
        assert_eq!(kinds(&plan), vec![("split", 0, 1), ("pay", 1, 2)]);
        match &plan.steps[0].kind {
            StepKind::FeeSplit { source, tariff } => assert_eq!((source.value(), *tariff), (3, 2)),
            other => panic!("{other:?}"),
        }
        // A 1 is the S tariff, not the P one; 2 < p + s cannot be split.
        let ix = index(&[(1, 50), (0, 1), (0, 2)]);
        assert_eq!(kinds(&plan_send(&ix, 1, 50, L2ShapeTag::S, TIERS).unwrap()), vec![("pay", 0, 1)]);
        assert_eq!(
            plan_send(&index(&[(1, 50), (0, 1)]), 1, 50, L2ShapeTag::P, TIERS),
            Err(SendRefusal::FeeNotesShort { tariff: 2, needed: 1, held: 0, splittable: 0 })
        );
        // A merge tree whose fee notes the asset-0 funds cannot all make.
        let ix = index(&[(1, 10), (1, 10), (1, 10), (0, 3)]);
        let short = plan_send(&ix, 1, 25, L2ShapeTag::P, TIERS);
        assert_eq!(short, Err(SendRefusal::FeeNotesShort { tariff: 2, needed: 2, held: 0, splittable: 1 }));
        let text = short.unwrap_err().to_string();
        assert!(text.contains("2 asset-0 fee note(s) of exactly 2"), "{text}");
    }
}
