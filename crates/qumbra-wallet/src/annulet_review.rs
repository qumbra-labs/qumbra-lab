//! **The review of a Candidate A spend** (lab #924 PR 3c; lab #937 PR D's
//! prover line), rendered from the intent bytes to be signed — moved here
//! from `qumbra-ffi` (lab #937 cut-over, M1) so every shell that signs states
//! the same lines: the kernel's C ABI calls [`render`], and the macOS bridge,
//! which links this crate directly, calls the same function. The text is
//! byte for byte what the kernel rendered before the move (the ffi fixtures
//! replay it).

use qlab_note::hash::digest_bytes;
use qlab_note::l2note::L2Note;
use qlab_remote_auth::annulet::AnnuletIntent;

use crate::asset_view::{render_amount, AssetLabel, AssetList, LeafRefusal};

/// What one step of a plan states, beside its prepared notes.
#[derive(Clone)]
pub struct Review {
    pub step: usize,
    pub steps: usize,
    /// `payment`, or what a preparing step is (`fee split`, `merge`).
    pub kind: &'static str,
    /// Whom an output may pay, by `rkm`: the payee (a payment only) and
    /// this wallet. The review states each output from its prepared note.
    pub payee_rkm: Option<[u64; 4]>,
    pub own_rkm: [u64; 4],
    pub to_short: String,
    pub spends_verified: bool,
    pub names: Names,
    /// Lab #937 PR D: the prover this step pays (format 34) — its payee's
    /// `rkm`, its short address, and this step's price (output 3, asset 0).
    pub prover: Option<([u64; 4], String, u64)>,
    /// Lab #937 PR D: the plan from this step on — transactions, network
    /// fees, prover fees — for the total line (a remote-proved plan of more
    /// than one transaction).
    pub plan_from_here: (usize, u64, u64),
}

/// How the review names the spend's asset (lab #924 PR 3c).
#[derive(Clone)]
pub struct Names {
    pub asset: u16,
    pub label: (AssetLabel, u32, String),
    /// Why the asset's leaf could not be bound to the verified tip, by name:
    /// an endpoint's lie is told apart from data not yet served.
    pub leaf_problem: Option<String>,
    pub list_line: String,
    pub list_short: Option<String>,
}

impl Names {
    /// `units` of `asset`, as the list and the bound leaf allow.
    pub fn amount(&self, units: u64, asset: u64) -> String {
        if asset == 0 {
            return format!("{} fee unit{}", render_amount(u128::from(units), 0), if units == 1 { "" } else { "s" });
        }
        if asset != u64::from(self.asset) {
            return format!("{} base units of QIA #{asset} (not this spend's asset)", render_amount(u128::from(units), 0));
        }
        let (label, decimals, unit) = &self.label;
        let figure = render_amount(u128::from(units), *decimals);
        match label {
            AssetLabel::Listed { name, .. } => format!("{figure} {unit} ({name})"),
            AssetLabel::IssuerChanged { listed_ticker } => format!(
                "{figure} {unit} (listed as {listed_ticker}, but its issuer key changed: name withheld)"
            ),
            AssetLabel::Unconfirmed { listed_ticker } => format!(
                "{figure} {unit} (listed as {listed_ticker}; its issuer could not be confirmed: {}; name withheld)",
                self.leaf_problem.as_deref().unwrap_or("the leaf was not bound")
            ),
            AssetLabel::Unlisted | AssetLabel::FeeUnit => match &self.list_short {
                Some(id) => format!("{figure} {unit} (not on list {id})"),
                None => format!("{figure} {unit} (no list for this network)"),
            },
        }
    }
}

/// The first 4 bytes of `b`, hex: a list's or a signer's short id.
pub fn short(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

/// `list`, if it is the network `genesis`'s.
pub fn own_list<'a>(list: Option<&'a AssetList>, genesis: &[u8; 32]) -> Option<&'a AssetList> {
    list.filter(|l| &l.genesis == genesis)
}

/// The review's line naming the list (its short id) or its absence.
pub fn list_line(list: Option<&AssetList>, genesis: &[u8; 32]) -> String {
    match (list, own_list(list, genesis)) {
        (_, Some(l)) => format!(
            "asset list: {} {}, signed by {}{}",
            l.network,
            short(&l.digest),
            short(&l.signer),
            if l.testnet { " — a test network: test money" } else { "" }
        ),
        (Some(l), None) => format!("asset list: for another network ({}), ignored — assets shown by id", short(&l.genesis)),
        (None, None) => "asset list: none — every asset is unlisted; amounts in base units".to_string(),
    }
}

/// A leaf refusal, by name, for the review.
pub fn leaf_refusal_text(e: &LeafRefusal) -> String {
    match e {
        LeafRefusal::Unavailable { why } => format!("the endpoint did not serve the asset's registry leaf ({why})"),
        LeafRefusal::WrongAsset { got } => format!("the endpoint answered with asset {got}'s leaf"),
        LeafRefusal::PathMismatch => "the endpoint's registry path does not fold to its root".into(),
        LeafRefusal::NotAtVerifiedTip => "the endpoint's registry root is not the verified tip's".into(),
    }
}

/// **How a review names `asset`** (lab #937 cut-over, M1(b): moved from
/// qumbra-ffi so the FFI and the Rust send build it once): from `list` only
/// while it is the network `genesis`'s, and the asset's name only while its
/// registry leaf, bound to the verified tip (`bound`, `None` for asset 0),
/// carries the listed issuer key; otherwise raw base units, saying why.
pub fn names_for(
    asset: u16,
    list: Option<&AssetList>,
    genesis: &[u8; 32],
    bound: Option<Result<qlab_air::l2::RegistryLeaf, LeafRefusal>>,
) -> Names {
    let own = own_list(list, genesis);
    let listed = own.and_then(|l| l.assets.get(&asset));
    let leaf_problem = match &bound {
        Some(Err(e)) => Some(leaf_refusal_text(e)),
        _ => None,
    };
    let bound = bound.and_then(Result::ok);
    Names {
        asset,
        label: crate::asset_view::label_of(asset, listed, bound.as_ref()),
        leaf_problem,
        list_line: list_line(list, genesis),
        list_short: own.map(|l| short(&l.digest)),
    }
}

/// What step `i` of a plan is, by the name the review gives it.
pub fn step_kind(kind: &crate::annulet_plan::StepKind) -> &'static str {
    match kind {
        crate::annulet_plan::StepKind::FeeSplit { .. } => "fee-split",
        crate::annulet_plan::StepKind::Merge { .. } => "merge",
        crate::annulet_plan::StepKind::Pay { .. } => "payment",
    }
}

/// **The review of step `i` of `plan`** (lab #937 cut-over, M1(b): moved
/// from qumbra-ffi): "step i+1 of N", the payee only on the payment
/// (`to_rkm`), the prover (`(payee rkm, short address)`, when one is paid)
/// at this step's price, and the plan from this step on. The FFI prepares one
/// step at a time and calls it with `i = 0`.
#[allow(clippy::too_many_arguments)]
pub fn step_review(
    plan: &crate::annulet_plan::SendPlan,
    i: usize,
    to_rkm: [u64; 4],
    own_rkm: [u64; 4],
    to_short: String,
    spends_verified: bool,
    names: Names,
    prover: Option<([u64; 4], String)>,
) -> Review {
    let step = &plan.steps[i];
    let kind = step_kind(&step.kind);
    let rest = &plan.steps[i..];
    Review {
        step: i + 1,
        steps: plan.steps.len(),
        kind,
        payee_rkm: (kind == "payment").then_some(to_rkm),
        own_rkm,
        to_short,
        spends_verified,
        names,
        prover: prover.zip(step.third).map(|((rkm, short), (v, _))| (rkm, short, v)),
        plan_from_here: (
            rest.len(),
            rest.iter().map(|s| s.fee).sum(),
            rest.iter().filter_map(|s| s.third.map(|(v, _)| v)).fold(0u64, u64::saturating_add),
        ),
    }
}

/// **Render the review from the intent bytes to be signed**: refused unless
/// `shown` are `signing` (the pending intent's bytes); an output is stated
/// only after its note (`outputs`, the prepared notes) is checked to open
/// `intent`'s commitment at that index. No leaf index, no anchor.
pub fn render(
    review: &Review,
    intent: &AnnuletIntent,
    signing: &[u8],
    shown: &[u8],
    outputs: &[L2Note],
) -> Result<String, String> {
    if shown != signing {
        return Err("these are not the bytes this spend would sign".into());
    }
    let i = intent;
    for (k, note) in outputs.iter().enumerate() {
        if digest_bytes(&note.commitment()) != i.commitments[k] {
            return Err(format!("output {k} does not open the intent's commitment"));
        }
    }
    let r = review;
    let mut out = format!("{}\n", r.names.list_line);
    if r.kind == "payment" {
        out.push_str(&format!("step {} of {}: the payment\n", r.step, r.steps));
    } else {
        out.push_str(&format!(
            "step {} of {}: a {} — it prepares the payment; nothing leaves this wallet\n",
            r.step, r.steps, r.kind
        ));
    }
    // Per-asset totals, by where they go — each from the prepared note that
    // opens the intent's commitment, its `rkm` matched to the payee or to
    // this wallet before it is named.
    let mut to_payee: Vec<(u64, u64)> = Vec::new();
    let mut to_self: Vec<(u64, u64)> = Vec::new();
    // Lab #937 PR D: a format-34 step's third output pays the prover —
    // checked here against the admitted payee and this step's price, and
    // named on its own line below.
    let mut prover_line = None;
    for (k, note) in outputs.iter().enumerate() {
        if k == 2 {
            if let Some((rkm, short, price)) = &r.prover {
                if note.rkm != *rkm {
                    return Err(format!("output {k} does not pay the prover's pinned payee"));
                }
                if note.asset != 0 || note.value != *price {
                    return Err(format!(
                        "output {k} pays the prover {} of asset {}, not its price of {price} fee unit(s)",
                        note.value, note.asset
                    ));
                }
                prover_line = Some(format!("prover fee: {} to {short}\n", r.names.amount(*price, 0)));
                continue;
            }
        }
        let bucket = if Some(note.rkm) == r.payee_rkm {
            &mut to_payee
        } else if note.rkm == r.own_rkm {
            &mut to_self
        } else {
            return Err(format!("output {k} pays neither the payee nor this wallet"));
        };
        match bucket.iter_mut().find(|(a, _)| *a == note.asset) {
            Some((_, v)) => *v += note.value,
            None => bucket.push((note.asset, note.value)),
        }
    }
    for (asset, value) in &to_payee {
        out.push_str(&format!("send {} to {}\n", r.names.amount(*value, *asset), r.to_short));
    }
    for (asset, value) in to_self.iter().filter(|(_, v)| *v > 0) {
        out.push_str(&format!("{} returns to this wallet\n", r.names.amount(*value, *asset)));
    }
    out.push_str(&format!("fee: {}\n", r.names.amount(i.fee, 0)));
    if let Some(line) = prover_line {
        out.push_str(&line);
        // A remote-proved plan of more than one transaction: what is left of
        // it, from this step on, at the price fixed for the whole handle.
        let (steps, network, prover) = r.plan_from_here;
        if steps > 1 {
            out.push_str(&format!(
                "this plan from here: {steps} transactions; network fees {network} + prover fees {prover} = {}\n",
                r.names.amount(network.saturating_add(prover), 0)
            ));
        }
    }
    out.push_str(&format!("valid until block {}\n", i.valid_until_height));
    if !r.spends_verified {
        // Design D5: stated beside every plan while it holds.
        out.push_str("note: the notes already spent were taken from the endpoint's word, not verified\n");
    }
    Ok(out)
}
