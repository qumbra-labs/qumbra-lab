//! **Candidate A spends over the C ABI** (lab #924 PR 3, the 4b kernel): the
//! device half of a remote-proved send — the wallet's own authorization
//! keys, the plan, the prepared transaction, the review, the signature, the
//! proving bundle — for the browser extension (and any shell without a
//! synchronous network). The prover is not linked: a bundle leaves this
//! kernel signed and is proved elsewhere (the prover service), which can add
//! a proof and nothing else.
//!
//! **The handles.**
//! - `qmb_auth_*` holds one generation's authorization keys (2^12 ML-DSA-44
//!   key generations, seconds under wasm — built once per handle) and the
//!   `auth.v1` journal **as text**: the CLI's file, byte for byte, which the
//!   shell stores under its own lock.
//! - `qmb_spend_v2_*` is one transaction: the first step of the wallet's plan
//!   (`qumbra_wallet::annulet_plan`, the CLI's planner) over the verified
//!   scan's [`SpendBasis`]. A plan of several steps (fee splits, merges) runs
//!   one transaction per handle; the shell waits for each to land, rescans,
//!   and plans again — recovery by order.
//!
//! **The order, each step refused by name when it cannot be met:**
//! 1. `qmb_spend_v2_new` — the request, the basis, the host's entropy (the
//!    output/discovery seed and one 32-byte draw per dummy slot, from
//!    `crypto.getRandomValues`; this kernel draws none);
//! 2. `qmb_spend_v2_step` / `_supply` / `_supply_err` — the served reads the
//!    plan and the prepare need (`/v1/annulet/params`, the registry, the
//!    commitment tree). Nothing is taken before they are all in: a network
//!    failure costs no leaf;
//! 3. `qmb_auth_take` — the leaves this transaction's real slots use, the
//!    journal advanced **in memory** and returned as text to persist; the
//!    transaction is prepared with them;
//! 4. `qmb_spend_v2_intent` / `qmb_intent_review` — the exact intent bytes to
//!    be signed, and the review rendered from those bytes;
//! 5. `qmb_intent_sign` — only with the journal text the shell **read back
//!    from storage** after step 3, whose cursor covers the taken leaves (the
//!    kernel cannot see storage; it can refuse to sign until shown the
//!    advance is there). Then sign, attach, `ProvingBundle::new` + `check`
//!    (the prover's own lock), export. **One take, one sign**: the handle is
//!    spent after the first sign call, refused or not, its witness and paths
//!    wiped — a refused sign leaves taken leaves unused, never reusable.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::ptr;

use qlab_air::l2::{L2AuthInput, L2AuthPath};
use qlab_air::l2p::VPublic;
use qlab_devnet::annulet::{AuthContext, L2ShapeTag};
use qlab_devnet::forms::L2AuthForm;
use qlab_l2spend::bundle::ProvingBundle;
use qlab_l2spend::v2::{attach, intent_for, prepare_p_v2, prepare_s_v2, sign_locally, FeeIn, LocalAuth, PreparedV2};
use qlab_l2spend::{shape_for, Endpoint, Out, PolicyContext, Recipient, Served};
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_note::hash::digest_bytes;
use qlab_remote_auth::annulet::AnnuletIntent;
use qlab_remote_auth::mldsa;
use qlab_wallet::Wallet;
use qumbra_wallet::annulet_plan::{plan_send, plan_slots, real_input, SendPlan, Src, StepKind, Tiers, SWEEP_FLOOR_EXTRA};
use qumbra_wallet::annulet_verify::{registry_leaf_path, VerifiedAnnulet, VerifiedChain};
use qumbra_wallet::asset_view::{check_leaf_at_verified_tip, label_of, render_amount, AssetLabel, AssetList};
use qumbra_wallet::auth_journal::AuthJournal;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroize;

use crate::{out_string, set_err, WalletState};

// The prover must not reach this kernel: qlab-l2spend is taken without its
// `prove` feature, and a wasm32 build that unified it back on would carry
// qlab-l2 and every STARK crate into the extension. Checked at compile time.
#[cfg(target_arch = "wasm32")]
const _: () = assert!(
    !qlab_l2spend::PROVER_LINKED,
    "qlab-l2spend's `prove` (the prover) reached a wasm32 build of qumbra-ffi"
);

/// The longest journal text accepted: a header and one line per generation;
/// far past any wallet's.
pub const MAX_JOURNAL_TEXT: usize = 64 * 1024;
/// The longest request JSON accepted.
pub const MAX_REQUEST_JSON: usize = 4 * 1024;
/// The largest served answer copied in (the tree's leaf pages are the
/// largest; the transport's general GET cap bounds them).
pub const MAX_SUPPLY_BYTES: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------- the basis

/// What a spend plans from: the verified scan's per-asset index, its pinned
/// genesis and its verified tip (`qmb_annulet_take_basis`).
#[derive(Clone)]
pub struct SpendBasis {
    index: AssetIndex,
    genesis_hash: [u8; 32],
    form: L2AuthForm,
    tip: u64,
    spends_verified: bool,
    /// The verified header chain: a registry leaf the review names is
    /// bound to its tip (lab #924 PR 3c).
    chain: VerifiedChain,
    /// The asset list the scan was given and verified (`verify_asset_list`
    /// at `qmb_annulet_new_v2`) — the review's only source of names and
    /// decimals. Never a host-supplied name table.
    list: Option<AssetList>,
}

impl SpendBasis {
    /// The basis of a finished verified scan, or `None` when it established
    /// no index.
    pub(crate) fn of(v: &VerifiedAnnulet, list: Option<&AssetList>) -> Option<Self> {
        Some(SpendBasis {
            index: v.report().index.clone()?,
            genesis_hash: v.chain().genesis.hash,
            form: v.chain().genesis.l2_auth,
            tip: v.chain().tip(),
            spends_verified: v.spends_verified(),
            chain: v.chain().clone(),
            list: list.cloned(),
        })
    }

    /// The list, if it is this network's.
    fn own_list(&self) -> Option<&AssetList> {
        self.list.as_ref().filter(|l| l.genesis == self.genesis_hash)
    }

    /// The review's line naming the list (its short id) or its absence.
    fn list_line(&self) -> String {
        match (&self.list, self.own_list()) {
            (_, Some(l)) => format!(
                "asset list: {} {}, signed by {}{}",
                l.network,
                short(&l.digest),
                short(&l.signer),
                if l.testnet { " — a test network: test money" } else { "" }
            ),
            (Some(l), None) => format!("asset list: for another network ({}), ignored — assets shown by id", short(&l.genesis)),
            (None, None) => "asset list: none — assets shown by id, in base units".to_string(),
        }
    }
}

/// A leaf refusal, by name, for the review.
fn leaf_refusal_text(e: &qumbra_wallet::asset_view::LeafRefusal) -> String {
    use qumbra_wallet::asset_view::LeafRefusal as L;
    match e {
        L::Unavailable { why } => format!("the endpoint did not serve the asset's registry leaf ({why})"),
        L::WrongAsset { got } => format!("the endpoint answered with asset {got}'s leaf"),
        L::PathMismatch => "the endpoint's registry path does not fold to its root".into(),
        L::NotAtVerifiedTip => "the endpoint's registry root is not the verified tip's".into(),
    }
}

fn short(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

/// # Safety
/// `b` a live basis from `qmb_annulet_take_basis` (or NULL); never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_basis_free(b: *mut SpendBasis) {
    if !b.is_null() {
        drop(Box::from_raw(b));
    }
}

// ---------------------------------------------------------------- the keys

/// One generation's authorization keys and the journal they advance.
pub struct AuthHandle {
    wallet: Wallet,
    journal: AuthJournal,
    generation: u32,
    keys: LocalAuth,
}

unsafe fn text_arg<'a>(what: &str, p: *const c_char, max: usize) -> Result<&'a str, String> {
    if p.is_null() {
        return Err(format!("{what} is NULL"));
    }
    let s = CStr::from_ptr(p).to_str().map_err(|_| format!("{what} is not UTF-8"))?;
    if s.len() > max {
        return Err(format!("{what} is {} B, over the {max} B bound", s.len()));
    }
    Ok(s)
}

/// Open the journal's **active** generation: its keys are built here and
/// must have the root the journal records (the CLI's own check — a journal
/// edited or from another seed is refused before anything is signed).
///
/// **The host is trusted for the journal's freshness** (pilot scope): a
/// shell that hands an OLDER `auth.v1` text — a restored backup, a stale
/// copy — makes this kernel take leaves already spent, which it cannot see.
/// Lab #924 PR 3b's restore adds the cross-check against the chain's landed
/// slots (`landed_next`) at open; until then the shell must pass the text it
/// last persisted.
///
/// # Safety
/// `w` live; `journal_text` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_open(
    w: *const WalletState,
    journal_text: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut AuthHandle {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if w.is_null() {
        set_err(err_out, "NULL wallet".into());
        return ptr::null_mut();
    }
    let opened = (|| {
        let text = text_arg("the journal", journal_text, MAX_JOURNAL_TEXT)?;
        let journal = AuthJournal::from_text(text).map_err(|e| format!("auth.v1: {e}"))?;
        let active = journal.active().clone();
        let wallet = (*w).wallet.clone();
        let keys = LocalAuth::new(&wallet.auth_secret(), active.g, active.next)?;
        if keys.auth_root() != active.auth_root {
            return Err(format!(
                "auth.v1's root for generation {} is not this wallet's tree: the journal was edited or belongs to \
                 another seed — refusing to sign with it",
                active.g
            ));
        }
        Ok(AuthHandle { wallet, journal, generation: active.g, keys })
    })();
    match opened {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// The journal as it stands in this handle (after a take: the advanced one),
/// `auth.v1` text. Free with `qmb_string_free`.
///
/// # Safety
/// `a` live (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_journal(a: *const AuthHandle) -> *mut c_char {
    if a.is_null() {
        return ptr::null_mut();
    }
    out_string((*a).journal.to_text())
}

/// # Safety
/// `a` live (or NULL); never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_free(a: *mut AuthHandle) {
    if !a.is_null() {
        drop(Box::from_raw(a));
    }
}

// ---------------------------------------------------------------- the spend

/// The served reads, answered so far by the host; a miss records the path.
struct Replay<'a> {
    answers: &'a HashMap<String, Result<Vec<u8>, String>>,
    missing: RefCell<Option<String>>,
}

impl Endpoint for &Replay<'_> {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        match self.answers.get(path) {
            Some(answer) => answer.clone(),
            None => {
                self.missing.borrow_mut().get_or_insert_with(|| path.to_string());
                Err(format!("{path}: not fetched yet"))
            }
        }
    }
    fn post(&self, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), String> {
        Err(format!("{path}: this kernel never posts"))
    }
}

/// A prepared transaction waiting for its signature.
struct Signable {
    prepared: PreparedV2,
    intent: AnnuletIntent,
    intent_bytes: Vec<u8>,
    dummies: Vec<mldsa::Key>,
    paths: Vec<L2AuthPath>,
    /// The generation's cursor after the take: a persisted journal must
    /// stand at least here.
    next_after_take: u32,
    generation: u32,
    review: Review,
}

impl Signable {
    fn wipe(&mut self) {
        self.prepared.witness.wipe();
        for p in &mut self.paths {
            p.leaf.zeroize();
            p.siblings.iter_mut().for_each(|s| s.zeroize());
        }
        self.paths.clear();
        self.intent_bytes.zeroize();
    }
}

#[derive(Clone)]
struct Review {
    step: usize,
    steps: usize,
    kind: &'static str,
    /// Whom an output may pay, by `rkm`: the payee (a payment only) and
    /// this wallet. The review states each output from its prepared note.
    payee_rkm: Option<[u64; 4]>,
    own_rkm: [u64; 4],
    to_short: String,
    spends_verified: bool,
    names: Names,
}

/// How the review names the spend's asset (lab #924 PR 3c).
#[derive(Clone)]
struct Names {
    asset: u16,
    label: (AssetLabel, u32, String),
    /// Why the asset's leaf could not be bound to the verified tip, by name:
    /// an endpoint's lie is told apart from data not yet served.
    leaf_problem: Option<String>,
    list_line: String,
    list_short: Option<String>,
}

impl Names {
    /// `units` of `asset`, as the list and the bound leaf allow.
    fn amount(&self, units: u64, asset: u64) -> String {
        if asset == 0 {
            return format!("{} fee units", render_amount(u128::from(units), 0));
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

enum Phase {
    /// Reading what the plan and the prepare need.
    Pumping,
    /// Everything served is in; `slots` leaves to take.
    Ready { slots: usize },
    /// Leaves taken, the transaction prepared, waiting for the signature.
    Taken(Box<Signable>),
    /// Signed once (or refused at the signature): nothing more.
    Spent,
    Refused(String),
}

/// One Candidate A transaction, from its plan to its bundle.
pub struct SpendHandle {
    basis: SpendBasis,
    to: Recipient,
    to_short: String,
    asset: u16,
    amount: u64,
    valid_until: u64,
    seed: [u8; 32],
    dummy_entropy: [[u8; 32]; 2],
    answers: HashMap<String, Result<Vec<u8>, String>>,
    asked: Option<String>,
    phase: Phase,
}

impl Drop for SpendHandle {
    fn drop(&mut self) {
        if let Phase::Taken(s) = &mut self.phase {
            s.wipe();
        }
        self.seed.zeroize();
        self.dummy_entropy.iter_mut().for_each(|e| e.zeroize());
    }
}

/// What an attempt at the transaction got to.
enum Attempt {
    Need(String),
    Refused(String),
}

struct Prepared {
    prepared: PreparedV2,
    intent: AnnuletIntent,
    dummies: Vec<mldsa::Key>,
    paths: Vec<L2AuthPath>,
    review: Review,
}

impl SpendHandle {
    /// Plan and prepare against the answers so far: with `paths` the taken
    /// leaves, without them the next leaves **peeked** (a dry run that finds
    /// what is still to be read and takes nothing).
    fn attempt(&self, auth: &AuthHandle, paths: Option<&[L2AuthPath]>) -> Result<Prepared, Attempt> {
        let replay = Replay { answers: &self.answers, missing: RefCell::new(None) };
        let served = Served::new(&replay);
        let miss = |why: String| match replay.missing.borrow().clone() {
            Some(path) => Attempt::Need(path),
            None => Attempt::Refused(why),
        };
        let b = &self.basis;
        let params = served.params().map_err(|e| miss(e.to_string()))?;
        if params.genesis_hash != b.genesis_hash {
            return Err(Attempt::Refused("the endpoint's /v1/annulet/params name a different genesis than the scan".into()));
        }
        let tiers = Tiers { s: params.fee_tier_s, p: params.fee_tier_p, r: params.fee_tier_r };
        let shape = if self.asset == 0 {
            L2ShapeTag::S
        } else {
            let opening = served.registry(u64::from(self.asset)).map_err(|e| miss(e.to_string()))?;
            shape_for(&opening.leaf)
        };
        // The payment asset's name, from the verified list, only while its
        // leaf — bound to the verified tip — carries the listed issuer key.
        let bound = match self.asset {
            0 => None,
            a => {
                // Unreachable: `served.registry` above already required this
                // answer. Kept so a missing one can never read as bound.
                let answer = self.answers.get(&registry_leaf_path(a)).cloned().unwrap_or_else(|| Err("not read".into()));
                Some(check_leaf_at_verified_tip(&b.chain, a, answer))
            }
        };
        let listed = b.own_list().and_then(|l| l.assets.get(&self.asset));
        let leaf_problem = match &bound {
            Some(Err(e)) => Some(leaf_refusal_text(e)),
            _ => None,
        };
        let bound = bound.and_then(Result::ok);
        let names = Names {
            asset: self.asset,
            label: label_of(self.asset, listed, bound.as_ref()),
            leaf_problem,
            list_line: b.list_line(),
            list_short: b.own_list().map(|l| short(&l.digest)),
        };
        if shape == L2ShapeTag::R {
            return Err(Attempt::Refused("shape R is a registry write, not a spend".into()));
        }

        // The active generation's notes, its keys, its address (the CLI's rule).
        let index = b.index.only_generation(auth.generation);
        let plan = plan_send(&index, self.asset, self.amount, shape, tiers).map_err(|e| Attempt::Refused(e.to_string()))?;
        // The budget is judged before the take; after it the cursor has moved
        // by this step's own leaves, and the plan's whole count would refuse
        // a transaction whose leaves are already spent.
        if paths.is_none() {
            budget(auth, &index, &plan)?;
        }
        let step = plan.steps.first().expect("a plan has its payment");
        let held = |s: &Src| match s {
            Src::Held(n) => Ok(n.clone()),
            Src::Made { .. } => Err(Attempt::Refused("the plan's first step spends a note not yet made".into())),
        };
        let own_root = auth.keys.auth_root();
        let own = own_recipient(&auth.wallet, &own_root);
        let a = u64::from(plan.asset);
        enum Kind {
            One,
            Two,
            TwoAndFee,
        }
        let (kind, notes, outs, fee, step_shape, label): (Kind, Vec<OwnedL2Note>, [Out; 2], u64, L2ShapeTag, &'static str) =
            match &step.kind {
                StepKind::FeeSplit { source, tariff } => (
                    Kind::One,
                    vec![held(source)?],
                    [
                        Out { to: own.clone(), value: *tariff, asset: 0 },
                        Out { to: own.clone(), value: step.outputs[1], asset: 0 },
                    ],
                    tiers.s,
                    L2ShapeTag::S,
                    "fee-split",
                ),
                StepKind::Merge { inputs, fee } => (
                    Kind::TwoAndFee,
                    vec![held(&inputs[0])?, held(&inputs[1])?, held(fee)?],
                    [
                        Out { to: own.clone(), value: step.outputs[0], asset: a },
                        Out { to: own.clone(), value: 0, asset: a },
                    ],
                    step.fee,
                    step.shape,
                    "merge",
                ),
                StepKind::Pay { inputs, fee } => {
                    let outs = [
                        Out { to: self.to.clone(), value: step.outputs[0], asset: a },
                        Out { to: own.clone(), value: step.outputs[1], asset: a },
                    ];
                    match (fee, inputs.as_slice()) {
                        (None, [one]) => (Kind::One, vec![held(one)?], outs, step.fee, L2ShapeTag::S, "payment"),
                        (Some(f), [one]) => (Kind::Two, vec![held(one)?, held(f)?], outs, step.fee, step.shape, "payment"),
                        (Some(f), [x, y]) => {
                            (Kind::TwoAndFee, vec![held(x)?, held(y)?, held(f)?], outs, step.fee, step.shape, "payment")
                        }
                        _ => return Err(Attempt::Refused("a payment is planned with one or two inputs".into())),
                    }
                }
            };
        if let Some(n) = notes.iter().find(|n| n.generation != Some(auth.generation)) {
            return Err(Attempt::Refused(format!(
                "a note of generation {:?} cannot be spent beside generation {}'s keys (one key per transaction)",
                n.generation, auth.generation
            )));
        }
        let paths: Vec<L2AuthPath> = match paths {
            Some(p) if p.len() == notes.len() => p.to_vec(),
            Some(p) => {
                return Err(Attempt::Refused(format!("{} leaves taken for {} real slots", p.len(), notes.len())));
            }
            None => auth
                .keys
                .peek(notes.len())
                .ok_or_else(|| Attempt::Refused(format!("generation {} has no leaves left", auth.generation)))?,
        };
        let taken: Vec<u32> = paths.iter().map(|p| p.leaf_index).collect();
        let real: Vec<L2AuthInput> =
            notes.iter().zip(paths.iter()).map(|(n, p)| real_input(&auth.wallet, n, p.clone())).collect();
        let mut rng = StdRng::from_seed(self.seed);
        let dummy = |k: usize, slot: u8, taken: &[u32]| {
            auth.keys.dummy(&self.dummy_entropy[k], slot, taken).map_err(Attempt::Refused)
        };
        let ctx = PolicyContext::default();
        let vp = [VPublic::NONE; 2];
        let refused = |e: qlab_l2spend::SpendError| miss(e.to_string());
        let (prepared, dummies) = match (step_shape, kind) {
            (L2ShapeTag::S, Kind::One) => {
                let (d2, k2) = dummy(0, 1, &taken)?;
                let (d3, k3) = dummy(1, 2, &[taken.as_slice(), &[d2.auth.leaf_index]].concat())?;
                let p = prepare_s_v2(&served, [&real[0], &d2], true, FeeIn::Dummy(&d3), &outs, fee, &mut rng)
                    .map_err(refused)?;
                (p, vec![k2, k3])
            }
            (L2ShapeTag::S, Kind::Two) => {
                let (d3, k3) = dummy(1, 2, &taken)?;
                let p = prepare_s_v2(&served, [&real[0], &real[1]], false, FeeIn::Dummy(&d3), &outs, fee, &mut rng)
                    .map_err(refused)?;
                (p, vec![k3])
            }
            (L2ShapeTag::S, Kind::TwoAndFee) => {
                let p = prepare_s_v2(&served, [&real[0], &real[1]], false, FeeIn::Exact(&real[2]), &outs, fee, &mut rng)
                    .map_err(refused)?;
                (p, vec![])
            }
            (L2ShapeTag::P, Kind::Two) => {
                let (d3, k3) = dummy(1, 2, &taken)?;
                let p = prepare_p_v2(&served, [&real[0], &real[1]], FeeIn::Dummy(&d3), &outs, fee, [&ctx, &ctx], vp, &mut rng)
                    .map_err(refused)?;
                (p, vec![k3])
            }
            (L2ShapeTag::P, Kind::TwoAndFee) => {
                let p = prepare_p_v2(&served, [&real[0], &real[1]], FeeIn::Exact(&real[2]), &outs, fee, [&ctx, &ctx], vp, &mut rng)
                    .map_err(refused)?;
                (p, vec![])
            }
            (L2ShapeTag::P, Kind::One) => {
                return Err(Attempt::Refused("a one-input shape-P spend has no v2 builder (P proves two real inputs)".into()))
            }
            (L2ShapeTag::R, _) => return Err(Attempt::Refused("shape R is a registry write, not a spend".into())),
        };
        let intent = intent_for(&prepared.tx, b.form.annulet_genesis_format_version(), &b.genesis_hash, self.valid_until, &prepared.auth)
            .map_err(|e| Attempt::Refused(format!("the intent does not rebuild: {e:?}")))?; // debug-ok: a named codec error
        let review = Review {
            step: 1,
            steps: plan.steps.len(),
            kind: label,
            payee_rkm: (label == "payment").then_some(self.to.rkm),
            own_rkm: own.rkm,
            to_short: self.to_short.clone(),
            spends_verified: b.spends_verified,
            names,
        };
        Ok(Prepared { prepared, intent, dummies, paths, review })
    }
}

/// The CLI's budget: every leaf the whole plan takes, and the floor that
/// keeps the generation sweepable (`one per spendable note + 2`) — refused
/// before anything is taken.
fn budget(auth: &AuthHandle, index: &AssetIndex, plan: &SendPlan) -> Result<(), Attempt> {
    let remaining = (1u32 << qlab_air::l2::D_AUTH) - auth.keys.next();
    let needed = plan_slots(plan);
    if needed > remaining {
        return Err(Attempt::Refused(format!(
            "this needs {needed} authorizations and generation {} has {remaining} left; open the next generation",
            auth.generation
        )));
    }
    let notes: u32 = index.by_asset.values().map(|n| n.spendable.len() as u32).sum();
    let floor = notes.saturating_add(SWEEP_FLOOR_EXTRA);
    if remaining - needed < floor {
        return Err(Attempt::Refused(format!(
            "generation {} would keep {} authorizations, below the {floor} needed to sweep its {notes} note(s); open \
             the next generation and send from it",
            auth.generation,
            remaining - needed
        )));
    }
    Ok(())
}

/// This wallet's receiving recipient under `root` (address 0: change, splits).
fn own_recipient(wallet: &Wallet, root: &[u64; 4]) -> Recipient {
    let addr = wallet.address_candidate_a_at_index(0, root);
    Recipient { rkm: addr.rkm_lanes(), ek: addr.encapsulation_key().expect("the wallet's own address has an ek") }
}

/// Start one Candidate A transaction: the first step of the plan that sends
/// `amount` of `asset` to `to` (a version-2 address), planned over `basis`
/// (consumed). `valid_for` is how many blocks past the verified tip it may
/// land — take it from the prover service's `recommended_valid_for_blocks`.
/// `seed32` seeds the outputs and discovery; `dummy_entropy64` is two fresh
/// 32-byte draws for the dummy slots. Both from `crypto.getRandomValues`.
///
/// # Safety
/// `basis` from `qmb_annulet_take_basis` (consumed, even on refusal); `to`
/// NUL-terminated UTF-8; `seed32` 32 and `dummy_entropy64` 64 readable bytes;
/// `err_out` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn qmb_spend_v2_new(
    basis: *mut SpendBasis,
    to: *const c_char,
    asset: u16,
    amount: u64,
    valid_for: u64,
    seed32: *const u8,
    dummy_entropy64: *const u8,
    err_out: *mut *mut c_char,
) -> *mut SpendHandle {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if basis.is_null() {
        set_err(err_out, "NULL basis".into());
        return ptr::null_mut();
    }
    let basis = *Box::from_raw(basis);
    let built = (|| {
        if seed32.is_null() || dummy_entropy64.is_null() {
            return Err("the entropy is NULL".to_string());
        }
        if basis.form != L2AuthForm::CandidateA {
            return Err("this net is not a Candidate A net: its sends are not signed by the wallet's keys".into());
        }
        if amount == 0 {
            return Err("the amount is 0".into());
        }
        if valid_for == 0 || valid_for > qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS {
            return Err(format!(
                "valid_for {valid_for} is outside 1..={}",
                qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS
            ));
        }
        let text = text_arg("the recipient", to, 4096)?;
        let addr = qlab_wallet::address::Address::decode_any(text.trim())
            .ok_or("not a Qumbra address: it does not decode as a full qaddr1… address")?;
        addr.require_version(qlab_wallet::address::ADDRESS_VERSION_CANDIDATE_A).map_err(|e| e.to_string())?;
        let ek = addr.encapsulation_key().ok_or("the recipient address has no valid encapsulation key")?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(std::slice::from_raw_parts(seed32, 32));
        let raw = std::slice::from_raw_parts(dummy_entropy64, 64);
        let mut dummy_entropy = [[0u8; 32]; 2];
        dummy_entropy[0].copy_from_slice(&raw[..32]);
        dummy_entropy[1].copy_from_slice(&raw[32..]);
        Ok(SpendHandle {
            valid_until: basis.tip.saturating_add(valid_for),
            basis,
            to: Recipient { rkm: addr.rkm_lanes(), ek },
            to_short: addr.short().encode(),
            asset,
            amount,
            seed,
            dummy_entropy,
            answers: HashMap::new(),
            asked: None,
            phase: Phase::Pumping,
        })
    })();
    match built {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// Pump the spend: `1` NEED (`*out` the path to GET), `0` READY (all served
/// reads in: `qmb_auth_take` next), `-2` REFUSED (`*out` why; terminal), `-1`
/// misuse (NULL, a step with an answer outstanding, or after READY).
///
/// # Safety
/// `a`, `s` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_step(a: *const AuthHandle, s: *mut SpendHandle, out: *mut *mut c_char) -> i32 {
    if a.is_null() || s.is_null() || out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    let (auth, h) = (&*a, &mut *s);
    match &h.phase {
        Phase::Pumping => {}
        Phase::Refused(why) => {
            *out = out_string(why.clone());
            return -2;
        }
        _ => return -1,
    }
    if h.asked.is_some() {
        return -1;
    }
    match h.attempt(auth, None) {
        Ok(p) => {
            h.phase = Phase::Ready { slots: p.paths.len() };
            0
        }
        Err(Attempt::Need(path)) => {
            h.asked = Some(path.clone());
            *out = out_string(path);
            1
        }
        Err(Attempt::Refused(why)) => {
            h.phase = Phase::Refused(why.clone());
            *out = out_string(why);
            -2
        }
    }
}

/// Answer the outstanding NEED with its body.
///
/// # Safety
/// `s` live (or NULL); `body` `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_supply(s: *mut SpendHandle, body: *const u8, len: usize) {
    if s.is_null() {
        return;
    }
    let answer = if body.is_null() {
        Err("the host supplied no body".to_string())
    } else if len > MAX_SUPPLY_BYTES {
        Err(format!("a {len}-byte answer, over the {MAX_SUPPLY_BYTES} B bound"))
    } else {
        Ok(std::slice::from_raw_parts(body, len).to_vec())
    };
    supply(&mut *s, answer);
}

/// Answer the outstanding NEED with a transport failure.
///
/// # Safety
/// `s` live (or NULL); `reason` NUL-terminated UTF-8 (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_supply_err(s: *mut SpendHandle, reason: *const c_char) {
    if s.is_null() {
        return;
    }
    let why = if reason.is_null() {
        "transport failure".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().chars().take(256).collect()
    };
    supply(&mut *s, Err(why));
}

fn supply(h: &mut SpendHandle, answer: Result<Vec<u8>, String>) {
    // Only a pumping spend takes answers. After READY a stray one is
    // ignored: it must never cost a prepared (and leaf-spending) transaction.
    if !matches!(h.phase, Phase::Pumping) {
        return;
    }
    match h.asked.take() {
        Some(path) => {
            h.answers.insert(path, answer);
        }
        None => h.phase = Phase::Refused("a response with no NEED outstanding".into()),
    }
}

/// **Take the leaves** (READY only, once): this transaction's real slots
/// consume the generation's next leaves, the journal advances in memory,
/// and the transaction is prepared with them. `*out_journal` is the
/// advanced `auth.v1` text — **persist it, then read it back** for
/// `qmb_intent_sign`. Returns 0, or -1 with `*out_journal` the refusal.
///
/// # Safety
/// `a`, `s` live; `out_journal` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_take(a: *mut AuthHandle, s: *mut SpendHandle, out_journal: *mut *mut c_char) -> i32 {
    if a.is_null() || s.is_null() || out_journal.is_null() {
        return -1;
    }
    *out_journal = ptr::null_mut();
    let (auth, h) = (&mut *a, &mut *s);
    let Phase::Ready { slots } = h.phase else {
        *out_journal = out_string("take: the spend is not READY (once, after every served read)".into());
        return -1;
    };
    let mut paths = Vec::with_capacity(slots);
    for _ in 0..slots {
        match auth.keys.take() {
            Some(p) => paths.push(p),
            None => {
                h.phase = Phase::Refused(format!("generation {} is exhausted", auth.generation));
                *out_journal = out_string(format!("generation {} is exhausted", auth.generation));
                return -1;
            }
        }
    }
    let next = auth.keys.next();
    if let Err(e) = auth.journal.advance_mem(auth.generation, next) {
        h.phase = Phase::Refused(format!("auth.v1: {e}"));
        *out_journal = out_string(format!("auth.v1: {e}"));
        return -1;
    }
    // The leaves are spent from here on, whatever follows.
    let text = auth.journal.to_text();
    match h.attempt(auth, Some(&paths)) {
        Ok(p) => {
            let intent_bytes = match p.intent.encode() {
                Ok(b) => b,
                Err(e) => {
                    h.phase = Phase::Refused(format!("the intent does not encode: {e:?}")); // debug-ok: a named codec error
                    *out_journal = out_string(text);
                    return 0;
                }
            };
            h.phase = Phase::Taken(Box::new(Signable {
                prepared: p.prepared,
                intent: p.intent,
                intent_bytes,
                dummies: p.dummies,
                paths: p.paths,
                next_after_take: next,
                generation: auth.generation,
                review: p.review,
            }));
        }
        // Defensive, and reachable only by an internal inconsistency: the
        // final attempt replays the dry run's cached answers with the very
        // leaves it peeked, and the budget is not re-judged. Left untested
        // (no test-only seam in a release export, lab #924 PR 3 ruling);
        // the advanced journal is still returned — the leaves are spent.
        Err(Attempt::Need(path) | Attempt::Refused(path)) => {
            h.phase = Phase::Refused(format!("after the take: {path}"));
        }
    }
    *out_journal = out_string(text);
    0
}

/// The exact intent bytes `qmb_intent_sign` would sign (after the take).
/// Release with `qmb_dealloc(p, len)`; NULL before the take or after sign.
///
/// # Safety
/// `s` live (or NULL); `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_intent(s: *const SpendHandle, out_len: *mut usize) -> *mut u8 {
    if s.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    *out_len = 0;
    match &(*s).phase {
        Phase::Taken(t) => {
            *out_len = t.intent_bytes.len();
            Box::into_raw(t.intent_bytes.clone().into_boxed_slice()) as *mut u8
        }
        _ => ptr::null_mut(),
    }
}

/// Why this handle cannot go on (`-2` from step, or after a take or sign):
/// NULL while it can.
///
/// # Safety
/// `s` live (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_refusal(s: *const SpendHandle) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    match &(*s).phase {
        Phase::Refused(why) => out_string(why.clone()),
        Phase::Spent => out_string("this spend was signed (or refused at the signature) once already".into()),
        _ => ptr::null_mut(),
    }
}


/// Render the review **from the intent bytes to be signed**: refused unless
/// they are this handle's pending intent; an output is stated only after its
/// note is checked to open the intent's commitment at that index. No leaf
/// index, no anchor. Free with `qmb_string_free`.
fn review_text(t: &Signable, bytes: &[u8]) -> Result<String, String> {
    if bytes != t.intent_bytes.as_slice() {
        return Err("these are not the bytes this spend would sign".into());
    }
    let i = &t.intent;
    for (k, note) in t.prepared.outputs.iter().enumerate() {
        if digest_bytes(&note.commitment()) != i.commitments[k] {
            return Err(format!("output {k} does not open the intent's commitment"));
        }
    }
    let r = &t.review;
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
    for (k, note) in t.prepared.outputs.iter().enumerate() {
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
    out.push_str(&format!("valid until block {}\n", i.valid_until_height));
    if !r.spends_verified {
        // Design D5: stated beside every plan while it holds.
        out.push_str("note: the notes already spent were taken from the endpoint's word, not verified\n");
    }
    Ok(out)
}

/// The review of `intent` (from `qmb_spend_v2_intent`), or NULL + `err_out`.
///
/// **Names** (lab #924 PR 3c): the first line names the asset list by its
/// short id (or says there is none, or that it is another network's). The
/// spend's asset is named only from that list — the one the scan verified at
/// `qmb_annulet_new_v2`, never a host-supplied table — and only while its
/// registry leaf, bound to the verified tip, carries the listed issuer key;
/// otherwise its raw base units, saying why ("not on list <id>", "name
/// withheld" with the leaf's refusal by name). Asset 0 is the fee unit.
///
/// **The trust premise:** names come from the list the host's key verified
/// at `qmb_annulet_new_v2`. This kernel does not pin the list signer; a shell
/// must compile in the production list key.
///
/// # Safety
/// `s` live; `intent` `len` readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_intent_review(
    s: *const SpendHandle,
    intent: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if s.is_null() || intent.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let Phase::Taken(t) = &(*s).phase else {
        set_err(err_out, "nothing to review: the spend is not prepared, or was signed".into());
        return ptr::null_mut();
    };
    match review_text(t, std::slice::from_raw_parts(intent, len)) {
        Ok(text) => out_string(text),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// **Sign** `intent` (the bytes reviewed) — only when `persisted_journal`,
/// the `auth.v1` text the shell read back from storage after the take,
/// stands at or past the take for this generation. Then attach, build the
/// [`ProvingBundle`] and run its lock (`check`, the prover's own) on this
/// net; the bundle's bytes are the export, released with
/// `qmb_dealloc(p, len)`. **Once**: whatever the outcome — a NULL argument
/// included — the handle is spent and its witness and paths wiped. NULL +
/// `err_out` on refusal, by name.
///
/// # Safety
/// `a`, `s` live; `intent` `len` readable bytes; `persisted_journal`
/// NUL-terminated UTF-8; `out_len`, `err_out` writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn qmb_intent_sign(
    a: *const AuthHandle,
    s: *mut SpendHandle,
    intent: *const u8,
    len: usize,
    persisted_journal: *const c_char,
    out_len: *mut usize,
    err_out: *mut *mut c_char,
) -> *mut u8 {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if s.is_null() {
        set_err(err_out, "NULL spend".into());
        return ptr::null_mut();
    }
    // One call spends the handle, whatever its arguments: the phase goes to
    // Spent before anything else is looked at.
    let h = &mut *s;
    let mut t = match std::mem::replace(&mut h.phase, Phase::Spent) {
        Phase::Taken(t) => t,
        other => {
            let why = match other {
                Phase::Spent => "this spend was signed (or refused at the signature) once already".to_string(),
                Phase::Refused(why) => why,
                _ => "nothing to sign: take the leaves first".to_string(),
            };
            set_err(err_out, why);
            return ptr::null_mut();
        }
    };
    let signed = if a.is_null() || intent.is_null() || out_len.is_null() {
        Err("NULL argument".to_string())
    } else {
        *out_len = 0;
        sign(&*a, h, &t, std::slice::from_raw_parts(intent, len), persisted_journal)
    };
    t.wipe();
    drop(t);
    match signed {
        Ok(bytes) => {
            *out_len = bytes.len();
            Box::into_raw(bytes.into_boxed_slice()) as *mut u8
        }
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

unsafe fn sign(
    auth: &AuthHandle,
    h: &SpendHandle,
    t: &Signable,
    bytes: &[u8],
    persisted_journal: *const c_char,
) -> Result<Vec<u8>, String> {
    if bytes != t.intent_bytes.as_slice() {
        return Err("these are not the bytes this spend would sign".into());
    }
    let persisted = text_arg("the persisted journal", persisted_journal, MAX_JOURNAL_TEXT)?;
    let persisted = AuthJournal::from_text(persisted).map_err(|e| format!("the persisted auth.v1: {e}"))?;
    let g = persisted.get(t.generation).map_err(|e| format!("the persisted auth.v1: {e}"))?;
    if g.auth_root != auth.keys.auth_root() || g.next < t.next_after_take {
        return Err(format!(
            "the persisted auth.v1 does not show this take (generation {} at {}, the take reached {}): persist the \
             journal from qmb_auth_take and read it back before signing",
            t.generation, g.next, t.next_after_take
        ));
    }
    let dummies: Vec<&mldsa::Key> = t.dummies.iter().collect();
    let section = sign_locally(&t.intent, &auth.keys, &dummies).map_err(|e| format!("signing refused: {e:?}"))?; // debug-ok: a named auth error
    let mut tx = t.prepared.tx.clone();
    attach(&mut tx, &section).map_err(|e| format!("the section does not encode: {e:?}"))?; // debug-ok
    let bundle = ProvingBundle::new(tx, t.prepared.witness.clone()).map_err(|e| e.to_string())?;
    bundle.check(&AuthContext { form: h.basis.form, genesis_hash: h.basis.genesis_hash }).map_err(|e| e.to_string())?;
    Ok(bundle.encode())
}

/// # Safety
/// `s` live (or NULL); never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_free(s: *mut SpendHandle) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}
