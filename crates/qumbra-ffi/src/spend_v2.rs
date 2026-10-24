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
use std::sync::Arc;
use std::ptr;

use qlab_air::l2::{L2AuthInput, L2AuthPath};
use qlab_air::l2p::VPublic;
use qlab_devnet::annulet::{AuthContext, L2ShapeTag};
use qlab_devnet::forms::L2AuthForm;
use qlab_l2spend::bundle::ProvingBundle;
use qlab_l2spend::v2::{attach, intent_for, prepare_p_v2, prepare_s_v2, sign_locally, FeeIn, LocalAuth, PreparedV2};
use qlab_l2spend::{shape_for, Endpoint, Out, PolicyContext, Recipient, Served};
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_remote_auth::annulet::{AnnuletIntent, AuthNet};
use qlab_remote_auth::mldsa;
use qlab_wallet::Wallet;
use qumbra_wallet::annulet_plan::{
    plan_send_paying, plan_slots, real_input, ProverPrice, SendPlan, Src, StepKind, Tiers, SWEEP_FLOOR_EXTRA,
};
use qumbra_wallet::annulet_verify::{registry_leaf_path, VerifiedAnnulet, VerifiedChain};
use qumbra_wallet::asset_view::{check_leaf_at_verified_tip, AssetList};
use qumbra_wallet::annulet_review::{names_for, step_review, Review};
use qumbra_wallet::auth_check::{restore_across, AuthCheck, CheckBasis, CheckStep};
use qumbra_wallet::auth_journal::{AuthJournal, GenState, SweepGate};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroize;

use crate::{out_string, set_err, WalletState};

// Lab #937 PR D: the fixture-pin registry is a test-only feature
// (`qumbra-wallet/fixture-pins`, reached through this crate's dev-dependency
// alone); a wasm32 build that unified it on would let a host-side caller pin
// its own prover. Checked at compile time, as `PROVER_LINKED` below. The one
// exception is the harness-only artifact (`harness-pins`, lab #937 D-C6),
// built under its own name and refused by the packager.
#[cfg(target_arch = "wasm32")]
const _: () = assert!(
    !qumbra_wallet::prover_pins::FIXTURE_PINS || cfg!(feature = "harness-pins"),
    "qumbra-wallet's `fixture-pins` (the test prover pins) reached a wasm32 build of qumbra-ffi"
);

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
    /// Every note the scan made the wallet's (a restore reads their
    /// generations).
    owned: Vec<OwnedL2Note>,
    /// An upper bound on the real tip for a sweep gate: the larger of the
    /// verified tip and the endpoint's stated tip (the CLI's `gate_tip`).
    gate_tip: u64,
    /// The asset list the scan was given and verified (`verify_asset_list`
    /// at `qmb_annulet_new_v2`) — the review's only source of names and
    /// decimals. Never a host-supplied name table.
    list: Option<AssetList>,
    /// Lab #971: the net's authorization derivation, as the scan was given
    /// it (`qmb_annulet_new_v2`): every `qmb_auth_*` on this basis derives so.
    auth_net: AuthNet,
}

impl SpendBasis {
    /// The basis of a finished verified scan, or `None` when it established
    /// no index.
    pub(crate) fn of(v: &VerifiedAnnulet, list: Option<&AssetList>, auth_net: AuthNet) -> Option<Self> {
        Some(SpendBasis {
            index: v.report().index.clone()?,
            genesis_hash: v.chain().genesis.hash,
            form: v.chain().genesis.l2_auth,
            tip: v.chain().tip(),
            spends_verified: v.spends_verified(),
            chain: v.chain().clone(),
            owned: v.report().owned.clone(),
            gate_tip: v.chain().tip().max(v.stated_tip().unwrap_or(0)),
            list: list.cloned(),
            auth_net,
        })
    }
}

/// The basis as JSON, for the host's own display and for fixtures: the
/// network, the verified tip, the gate tip, and every note the scan made the
/// wallet's with its generation (`null` for a v1 note) — the generations a
/// rotated wallet still holds funds under. No key material. NULL for NULL.
///
/// # Safety
/// `b` a live basis (or NULL). Free the result with `qmb_string_free`.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_basis_summary(b: *const SpendBasis) -> *mut c_char {
    if b.is_null() {
        return ptr::null_mut();
    }
    let b = &*b;
    let hex = |x: &[u8]| x.iter().map(|c| format!("{c:02x}")).collect::<String>();
    let owned: Vec<_> = b
        .owned
        .iter()
        .map(|o| {
            serde_json::json!({
                "asset": o.asset,
                "value": o.note.value.to_string(),
                "div_index": o.div_index,
                "height": o.height,
                "tx_index": o.tx_index,
                "cm": hex(&o.cm),
                "generation": o.generation,
            })
        })
        .collect();
    out_string(
        serde_json::json!({
            "genesis": hex(&b.genesis_hash),
            "auth_derivation": b.auth_net.derivation(),
            "tip": b.tip,
            "gate_tip": b.gate_tip,
            "spends_verified": b.spends_verified,
            "owned": owned,
        })
        .to_string(),
    )
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
    /// The generation is sweep-only: it may pay only this wallet's active
    /// generation (lab #924 PR 3b).
    sweep_only: bool,
    /// This wallet's active-generation address 0, re-derived from the
    /// wallet (never taken from a string): what a sweep must pay.
    active_rkm: [u64; 4],
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

/// The keys of generation `g` of `journal`, checked: its root is the
/// wallet's, the active generation's root is re-derived from the wallet and
/// must be the journal's, and a retired generation has none.
fn open_handle(w: &WalletState, journal: AuthJournal, g: u32, net: AuthNet) -> Result<AuthHandle, String> {
    let rec = journal.get(g).map_err(|e| format!("auth.v1: {e}"))?.clone();
    if rec.state == GenState::Retired {
        return Err(format!("generation {g} is retired: nothing of it is spent again"));
    }
    let wallet = w.wallet.clone();
    // The handle's cached tree (PR 3g): the scan or the check built it.
    let tree = w.gen_tree(g, net);
    let keys = LocalAuth::from_tree(tree.master, Arc::clone(&tree.tree), rec.next)?;
    if keys.auth_root() != rec.auth_root {
        return Err(format!(
            "auth.v1's root for generation {g} is not this wallet's tree: the journal was edited or belongs to another \
             seed — refusing to sign with it"
        ));
    }
    let active = journal.active().clone();
    let active_root = w.generation_root(active.g, net);
    if active_root != active.auth_root {
        return Err(format!("auth.v1's active generation {} is not this wallet's tree", active.g));
    }
    let active_rkm = wallet.address_candidate_a_at_index(0, &active_root).rkm_lanes();
    Ok(AuthHandle {
        wallet,
        journal,
        generation: g,
        keys,
        sweep_only: matches!(rec.state, GenState::Sweep { .. }),
        active_rkm,
    })
}

// ---------------------------------------------------------- the open check

/// `qmb_auth_check_finish`: the journal's landed check passed; nothing but
/// `checked_to` moved.
pub const QMB_AUTH_CHECKED: i32 = 0;
/// The journal is older than the chain (a landed leaf above its cursor):
/// **no keys**. The returned journal has the generation's cursor raised
/// above its landed leaves — persist it (so that generation is never used
/// twice, whatever follows), **tell the user** (a backup older than the
/// wallet's spends was restored), then run `qmb_auth_restore_new`: only a
/// restore walks every probe generation, and the lost device may have
/// opened and used later ones.
pub const QMB_AUTH_JOURNAL_STALE: i32 = 1;
/// A sweep-only generation's cursor was raised to its landed floor.
pub const QMB_AUTH_SWEEP_FLOOR_RAISED: i32 = 2;
/// A restore wrote the journal (no generation used: generation 0, fresh).
pub const QMB_AUTH_RESTORED: i32 = 3;
/// A sweep-only generation may not sweep yet (its gate on this net is not
/// reached, or was just recorded): no keys; the journal is returned.
pub const QMB_AUTH_SWEEP_WAITING: i32 = 4;
/// `qmb_auth_first_new` wrote this account's first journal: generation 0,
/// fresh, active (no leaf of any probe generation has landed).
pub const QMB_AUTH_FIRST: i32 = 5;

// The verdicts are `qumbra_wallet::auth_check::CheckStatus` (lab #937
// cut-over): these values are its codes.
const _: () = {
    use qumbra_wallet::auth_check::CheckStatus as S;
    assert!(S::Checked.code() == QMB_AUTH_CHECKED);
    assert!(S::JournalStale.code() == QMB_AUTH_JOURNAL_STALE);
    assert!(S::SweepFloorRaised.code() == QMB_AUTH_SWEEP_FLOOR_RAISED);
    assert!(S::Restored.code() == QMB_AUTH_RESTORED);
    assert!(S::SweepWaiting.code() == QMB_AUTH_SWEEP_WAITING);
    assert!(S::First.code() == QMB_AUTH_FIRST);
};

/// The open-time check (lab #924 PR 3b): every verified body above the
/// journal's `checked_to` on this net, each bound to its verified header,
/// each slot's leaf matched against the generation's own tree — "landed" is
/// judged here, never taken from a node's nullifier list. The judgment is
/// `qumbra_wallet::auth_check` (lab #937 cut-over: moved there so every
/// shell opens its keys by it); this handle is its C pump.
pub struct CheckHandle {
    check: AuthCheck,
    /// Lab #971: the basis's net, whose keys a passed check opens.
    net: AuthNet,
}

fn check_basis(b: &SpendBasis) -> CheckBasis {
    CheckBasis {
        genesis_hash: b.genesis_hash,
        auth_derivation: b.auth_net.derivation(),
        form: b.form,
        chain: b.chain.clone(),
        gate_tip: b.gate_tip,
        owned: b.owned.clone(),
    }
}

unsafe fn check_handle(
    w: *const WalletState,
    basis: *const SpendBasis,
    build: impl FnOnce(&WalletState, &SpendBasis) -> Result<AuthCheck, String>,
    err_out: *mut *mut c_char,
) -> *mut CheckHandle {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if w.is_null() || basis.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let b = &*basis;
    if let Err(e) = qumbra_wallet::auth_check::require_candidate_a(b.form) {
        set_err(err_out, e);
        return ptr::null_mut();
    }
    match build(&*w, b) {
        Ok(check) => Box::into_raw(Box::new(CheckHandle { check, net: b.auth_net })),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// **Open generation `generation` of `journal_text`, checked against the
/// chain**: pump `qmb_auth_check_step` / `_supply` / `_supply_err` over the
/// verified bodies above the journal's `checked_to` on `basis`'s net (the
/// scan's verified chain; `basis` is read, not consumed), then
/// `qmb_auth_check_finish`. The only way to keys: an unchecked open does
/// not exist.
///
/// # Safety
/// `w`, `basis` live; `journal_text` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_new(
    w: *const WalletState,
    journal_text: *const c_char,
    basis: *const SpendBasis,
    generation: u32,
    err_out: *mut *mut c_char,
) -> *mut CheckHandle {
    check_handle(
        w,
        basis,
        |ws, b| {
            let text = text_arg("the journal", journal_text, MAX_JOURNAL_TEXT)?;
            let journal = AuthJournal::from_text(text).map_err(|e| format!("auth.v1: {e}"))?;
            AuthCheck::check(journal, generation, || ws.gen_tree(generation, b.auth_net), &b.index, check_basis(b))
        },
        err_out,
    )
}

/// **Restore**: a wallet with no `auth.v1` (restored from its seed, or new
/// to Candidate A). The same pump over every verified body from height 1,
/// matched against the probe generations' trees (8 trees: seconds natively,
/// much longer under wasm); `qmb_auth_check_finish` writes the journal — a
/// seed that never spent gets generation 0, fresh.
///
/// # Safety
/// `w`, `basis` live; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_restore_new(
    w: *const WalletState,
    basis: *const SpendBasis,
    err_out: *mut *mut c_char,
) -> *mut CheckHandle {
    check_handle(
        w,
        basis,
        |ws, b| {
            let trees =
                (0..qumbra_wallet::auth_journal::PROBE_GENERATIONS).map(|g| ws.gen_tree(g, b.auth_net)).collect();
            Ok(AuthCheck::restore(trees, check_basis(b)))
        },
        err_out,
    )
}

/// **The first journal of an account that has never had one** (lab #924
/// PR 3b): the restore's pump (every verified body, the probe generations'
/// trees); at finish, refused by name if any probe generation has a landed
/// leaf ("this seed has signed: use restore"), else **generation 0, fresh,
/// active** (`QMB_AUTH_FIRST`) — its notes spendable at once.
///
/// **The host's premise:** `first` is only for an account whose host has
/// never persisted an `auth.v1` for it. If a journal ever existed — even one
/// deleted since — the host must use `qmb_auth_restore_new`. The residual
/// risk is the CLI's: a signature exported elsewhere that never landed; for
/// an account created under a receive-only kernel, no device could sign.
///
/// # Safety
/// `w`, `basis` live; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_first_new(
    w: *const WalletState,
    basis: *const SpendBasis,
    err_out: *mut *mut c_char,
) -> *mut CheckHandle {
    check_handle(
        w,
        basis,
        |ws, b| {
            let trees =
                (0..qumbra_wallet::auth_journal::PROBE_GENERATIONS).map(|g| ws.gen_tree(g, b.auth_net)).collect();
            Ok(AuthCheck::first(trees, check_basis(b)))
        },
        err_out,
    )
}

/// Lab #924 PR 3d: whether `new_text` is a monotone advance of
/// `stored_text` (`AuthJournal::advances_from`) — the check a shell that keeps
/// the journal as text runs before it overwrites what it stored. 1: it is
/// (an unchanged journal included); 0: it is not, `*out_why` the first rule
/// broken; -1: a text is NULL, over [`MAX_JOURNAL_TEXT`] or does not parse,
/// `*out_why` which. A pure
/// function of the two texts: no handle, no key material. `out_why` may be
/// NULL; on 1 it is set to NULL.
///
/// # Safety
/// The texts NULL or NUL-terminated; `out_why` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_journal_advances(stored_text: *const c_char, new_text: *const c_char, out_why: *mut *mut c_char) -> i32 {
    if !out_why.is_null() {
        *out_why = ptr::null_mut();
    }
    let parse = |p: *const c_char, which: &str| -> Result<AuthJournal, String> {
        let text = text_arg(&format!("the {which} journal"), p, MAX_JOURNAL_TEXT)?;
        AuthJournal::from_text(text).map_err(|e| format!("the {which} journal does not parse: {e}"))
    };
    let (stored, new) = match (parse(stored_text, "stored"), parse(new_text, "new")) {
        (Ok(s), Ok(n)) => (s, n),
        (Err(e), _) | (_, Err(e)) => {
            set_err(out_why, e);
            return -1;
        }
    };
    match new.advances_from(&stored) {
        Ok(()) => 1,
        Err(why) => {
            set_err(out_why, why);
            0
        }
    }
}

/// Lab #924 PR 3f: an `auth.v1` journal as JSON, for a shell's display and
/// for the generations it scans —
/// `{"active": g, "generations": [{"g", "state": "active"|"sweep"|"retired",
/// "next", "checked": [{"genesis", "height"}], "gates": [{"genesis",
/// "not_before_height"}]}]}`, generations in the text's order, every net's
/// checked height and gate listed (empty lists where there are none). Hashes
/// lowercase hex. A pure function of the text: no handle, no key material
/// (the authorization roots are left out). NULL with `*err_out` set for a
/// NULL, over-long or unparsable text.
///
/// # Safety
/// `journal_text` NULL or NUL-terminated; `err_out` NULL or writable. Free
/// the result with `qmb_string_free`.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_journal_summary(journal_text: *const c_char, err_out: *mut *mut c_char) -> *mut c_char {
    let parsed = text_arg("the journal", journal_text, MAX_JOURNAL_TEXT)
        .and_then(|t| AuthJournal::from_text(t).map_err(|e| format!("the journal does not parse: {e}")));
    match parsed {
        Ok(j) => out_string(journal_summary(&j).to_string()),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// The most journals [`qmb_auth_restore_across`] merges: one per live net,
/// far past any wallet's table.
pub const MAX_RESTORE_NETS: usize = 16;

/// Lab #971: **one key's journal from its restores on every live Candidate A
/// net** (`qumbra_wallet::auth_check::restore_across`) — the journal is per
/// key, so a restore from one net's chain alone can re-offer a leaf landed on
/// another. `journal_texts[0..n]` are the `auth.v1` texts each net's
/// `qmb_auth_restore_new` check finished with. 0 with `*out_journal` the
/// merged text to persist; -1 with `*out_journal` why: `n` of 0 or over
/// [`MAX_RESTORE_NETS`], a NULL, over-long or unparsable text, or two texts
/// that give one generation different roots (not one key's). A pure function
/// of the texts: no handle, no key material.
///
/// # Safety
/// `journal_texts` NULL or `n` readable pointers, each NULL or NUL-terminated;
/// `out_journal` writable. Free `*out_journal` with `qmb_string_free`.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_restore_across(journal_texts: *const *const c_char, n: usize, out_journal: *mut *mut c_char) -> i32 {
    if out_journal.is_null() {
        return -1;
    }
    let merged = (|| {
        if journal_texts.is_null() || n == 0 {
            return Err("a restore across nets needs at least one net's restored journal".to_string());
        }
        if n > MAX_RESTORE_NETS {
            return Err(format!("{n} journals, over the {MAX_RESTORE_NETS} a restore across nets merges"));
        }
        let journals = std::slice::from_raw_parts(journal_texts, n)
            .iter()
            .enumerate()
            .map(|(k, p)| {
                let text = text_arg(&format!("journal {k}"), *p, MAX_JOURNAL_TEXT)?;
                AuthJournal::from_text(text).map_err(|e| format!("journal {k} does not parse: {e}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        restore_across(&journals).map_err(|e| e.to_string())
    })();
    match merged {
        Ok(j) => {
            *out_journal = out_string(j.to_text());
            0
        }
        Err(why) => {
            *out_journal = out_string(why);
            -1
        }
    }
}

fn journal_summary(j: &AuthJournal) -> serde_json::Value {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let checked = j.checked_heights();
    let gens: Vec<serde_json::Value> = j
        .generations()
        .iter()
        .map(|r| {
            let (state, gates) = match &r.state {
                GenState::Active => ("active", Vec::new()),
                GenState::Sweep { gates } => ("sweep", gates.clone()),
                GenState::Retired => ("retired", Vec::new()),
            };
            serde_json::json!({
                "g": r.g,
                "state": state,
                "next": r.next,
                "checked": checked
                    .iter()
                    .filter(|(g, _, _)| *g == r.g)
                    .map(|(_, genesis, h)| serde_json::json!({ "genesis": hex(genesis), "height": h }))
                    .collect::<Vec<_>>(),
                "gates": gates
                    .iter()
                    .map(|x| serde_json::json!({ "genesis": hex(&x.genesis), "not_before_height": x.not_before_height }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({ "active": j.active().g, "generations": gens })
}

/// **The first journal of a wallet born in this process**
/// (`qmb_wallet_new_fresh`): generation 0, fresh, active — offline, no body
/// read, because a seed drawn here has signed nowhere. **Once per handle**:
/// the first call consumes the mark. Returns 0 with
/// `*out_journal` the `auth.v1` text to persist, or -1 with `*out_journal`
/// why: a handle from `qmb_wallet_from_entropy`, `qmb_wallet_restore` or
/// `qmb_wallet_from_parts` is refused by name — its seed came from outside
/// and may have signed (use `qmb_auth_first_new` or `qmb_auth_restore_new`).
///
///
/// Lab #971: the journal is of the net's authorization derivation —
/// `auth_derivation` 1 (`genesis32` may be NULL) or 2 (`genesis32` the net's
/// genesis hash: the journal is that net's alone). Any other derivation, or
/// 2 with a NULL `genesis32`, is refused by name **before** the mark is
/// consumed.
///
/// # Safety
/// `w` live; `genesis32` NULL or 32 readable bytes; `out_journal` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_first_fresh(
    w: *const WalletState,
    auth_derivation: u8,
    genesis32: *const u8,
    out_journal: *mut *mut c_char,
) -> i32 {
    if w.is_null() || out_journal.is_null() {
        return -1;
    }
    let net = match crate::auth_net_arg(auth_derivation, genesis32) {
        Ok(net) => net,
        Err(why) => {
            *out_journal = out_string(why);
            return -1;
        }
    };
    let ws = &*w;
    // Once: the mark is consumed, so a second call — after this handle has
    // signed — is refused like any outside door.
    if !ws.born_here.swap(false, std::sync::atomic::Ordering::AcqRel) {
        *out_journal = out_string(
            "an imported, restored or reopened seed (qmb_wallet_from_entropy / _restore / _from_parts): it may have \
             signed elsewhere — use qmb_auth_first_new or qmb_auth_restore_new"
                .into(),
        );
        return -1;
    }
    *out_journal = out_string(AuthJournal::fresh(ws.generation_root(0, net)).on_net(net).to_text());
    0
}

/// Pump the check: `1` NEED (`*out` the body path), `0` READY (finish),
/// `-2` REFUSED (`*out` why; terminal), `-1` misuse.
///
/// # Safety
/// `c` live; `out` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_step(c: *mut CheckHandle, out: *mut *mut c_char) -> i32 {
    if c.is_null() || out.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    let c = &mut (*c).check;
    if c.is_asking() {
        return -1;
    }
    match c.step() {
        CheckStep::Need(path) => {
            *out = out_string(path);
            1
        }
        CheckStep::Ready => 0,
        CheckStep::Refused(why) => {
            *out = out_string(why);
            -2
        }
    }
}

/// **Lab #936, opt-in:** ask the check's bodies in `/v1/bodies` pages of up
/// to `n` (1 ..= 256) instead of one `/v1/block/{h}/body` per NEED; `0` is
/// the default (one per NEED). Call it before the first
/// [`qmb_auth_check_step`], and only for an endpoint that serves
/// `/v1/bodies`. Each body in a page is bound to its verified header as a
/// single one is; the verdict is the same. `0` set, `-1` misuse or refused
/// (`n` above 256, or a step already taken; `*err_out` why when given).
///
/// # Safety
/// `c` live (or NULL); `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_set_page(c: *mut CheckHandle, n: u32, err_out: *mut *mut c_char) -> i32 {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if c.is_null() {
        return -1;
    }
    match (*c).check.set_page(n as u64) {
        Ok(()) => 0,
        Err(why) => {
            if !err_out.is_null() {
                *err_out = out_string(why);
            }
            -1
        }
    }
}

/// Answer the outstanding NEED with the body.
///
/// # Safety
/// `c` live (or NULL); `body` `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_supply(c: *mut CheckHandle, body: *const u8, len: usize) {
    if c.is_null() {
        return;
    }
    let answer = if body.is_null() {
        Err("the host supplied no body".to_string())
    } else if len > MAX_SUPPLY_BYTES {
        Err(format!("a {len}-byte answer, over the {MAX_SUPPLY_BYTES} B bound"))
    } else {
        Ok(std::slice::from_raw_parts(body, len))
    };
    (*c).check.supply(answer);
}

/// Answer the outstanding NEED with a transport failure: the check is
/// refused (a body this check needs is not optional; retry later — the
/// journal's `checked_to` keeps finished work).
///
/// # Safety
/// `c` live (or NULL); `reason` NUL-terminated UTF-8 (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_supply_err(c: *mut CheckHandle, reason: *const c_char) {
    if c.is_null() {
        return;
    }
    let why = if reason.is_null() {
        "transport failure".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().chars().take(256).collect()
    };
    (*c).check.supply(Err(why));
}

/// **Finish the check** (READY only): the keys, and the journal the shell
/// must persist (`*out_journal`; always set when a handle or WAITING
/// returns). `*out_status` is one of `QMB_AUTH_*`:
/// - CHECKED: the cursor is at or above every landed leaf; `checked_to`
///   moves to the verified tip.
/// - JOURNAL_STALE (an active generation whose cursor is below a landed
///   leaf — the journal is older than the chain): **no keys**; the journal
///   returned has the cursor raised above the landed leaves. Persist it, tell
///   the user, then restore (which walks every probe generation: the lost
///   device may have opened later ones).
/// - SWEEP_FLOOR_RAISED / SWEEP_WAITING for a sweep-only generation.
/// - RESTORED for a restore.
///
/// **Undetectable, inherently**: a journal older than leaves that were taken
/// and signed but have not landed (in flight, or expired unlanded). Those
/// leaves are taken again — the same leaf signs a second, different
/// transaction: a **double use** of the leaf. ML-DSA-44 is a many-time
/// scheme, so neither transaction is forged or put at risk; what breaks is
/// the design's one-leaf-one-use rule and the unlinkability it buys (the
/// two transactions share a leaf). Leaves taken but never signed only waste
/// positions. The shell avoids both by always passing the journal it last
/// persisted.
///
/// # Safety
/// `w`, `c` live; `out_journal`, `out_status` writable; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_finish(
    w: *const WalletState,
    c: *mut CheckHandle,
    out_journal: *mut *mut c_char,
    out_status: *mut i32,
    err_out: *mut *mut c_char,
) -> *mut AuthHandle {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if w.is_null() || c.is_null() || out_journal.is_null() || out_status.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    *out_journal = ptr::null_mut();
    *out_status = -1;
    let (ws, net, c) = (&*w, (*c).net, &mut (*c).check);
    let (journal, g, status) = match c.finish() {
        Ok(x) => x,
        Err(e) => {
            set_err(err_out, e);
            return ptr::null_mut();
        }
    };
    *out_journal = out_string(journal.to_text());
    *out_status = status.code();
    if status == qumbra_wallet::auth_check::CheckStatus::SweepWaiting {
        set_err(err_out, format!("generation {g} may not sweep yet on this net: its gate is not reached"));
        return ptr::null_mut();
    }
    if status == qumbra_wallet::auth_check::CheckStatus::JournalStale {
        set_err(
            err_out,
            format!(
                "the journal is older than the chain (a leaf of generation {g} landed above its cursor): persist the \
                 returned journal, tell the user, then run qmb_auth_restore_new"
            ),
        );
        return ptr::null_mut();
    }
    match open_handle(ws, journal, g, net) {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// **Lab #935: this key's spends the check found landed**, as JSON:
/// `[{"height": N, "tx_id": "<64 hex>", "intent_digest": "<64 hex>",
/// "leaves": K}, …]` in height order, `[]` when none. `tx_id` is the id a
/// prover service returns for the transaction; `intent_digest` the digest
/// the device signed (rebuilt from the transaction as the node does). Each
/// is from a body bound to its verified header. In a check, the spends
/// since the journal's checked height on this net; in a restore or first,
/// the key's whole history here. Valid after [`qmb_auth_check_finish`]
/// returned a journal (any status); before, NULL and `*err_out` why. Free
/// with `qmb_string_free`.
///
/// # Safety
/// `c` live (or NULL); `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_take_landed(c: *const CheckHandle, err_out: *mut *mut c_char) -> *mut c_char {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if c.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let hex = |x: &[u8]| x.iter().map(|b| format!("{b:02x}")).collect::<String>();
    match (*c).check.landed_spends() {
        Ok(spends) => {
            let list: Vec<_> = spends
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "height": s.height,
                        "tx_id": hex(&s.tx_id),
                        "intent_digest": hex(&s.intent_digest),
                        "leaves": s.leaves,
                    })
                })
                .collect();
            out_string(serde_json::Value::Array(list).to_string())
        }
        Err(why) => {
            set_err(err_out, why);
            ptr::null_mut()
        }
    }
}

/// The longest `records_json` [`qmb_remote_settle`] accepts: hex bundles,
/// a few hundred KiB each.
pub const MAX_SETTLE_RECORDS_JSON: usize = 64 * 1024 * 1024;
/// The longest `landed_json` [`qmb_remote_settle`] accepts.
pub const MAX_SETTLE_LANDED_JSON: usize = 4 * 1024 * 1024;

fn hex32_arg(what: &str, v: Option<&serde_json::Value>) -> Result<[u8; 32], String> {
    let s = v.and_then(serde_json::Value::as_str).ok_or_else(|| format!("{what} is not a string"))?;
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("{what} is not 64 lowercase hex digits"));
    }
    let b = crate::names::unhex(s).ok_or_else(|| format!("{what} is not hex"))?;
    Ok(b.try_into().expect("64 hex digits"))
}

fn settle_json(basis: &SpendBasis, records: &str, landed: &str, walked_from: u64, checked_to: u64) -> Result<String, String> {
    use qumbra_wallet::auth_check::LandedSpend;
    use qumbra_wallet::remote_prover::{settle_records, SettleRecord};
    let hex = |x: &[u8]| x.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let records: Vec<serde_json::Value> =
        serde_json::from_str(records).map_err(|e| format!("records_json is not a JSON array: {e}"))?;
    let records = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let key = hex32_arg(&format!("records[{i}].key"), r.get("key"))?;
            let bundle = r
                .get("bundle")
                .and_then(serde_json::Value::as_str)
                .and_then(crate::names::unhex)
                .ok_or_else(|| format!("records[{i}].bundle is not hex"))?;
            let outcome = match r.get("outcome") {
                None | Some(serde_json::Value::Null) => None,
                Some(serde_json::Value::String(l)) => Some(l.clone()),
                Some(_) => return Err(format!("records[{i}].outcome is neither a string nor null")),
            };
            Ok(SettleRecord { key, bundle, outcome })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let landed: Vec<serde_json::Value> =
        serde_json::from_str(landed).map_err(|e| format!("landed_json is not a JSON array: {e}"))?;
    let landed = landed
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let num = |k: &str| l.get(k).and_then(serde_json::Value::as_u64).ok_or_else(|| format!("landed[{i}].{k} is not a number"));
            Ok(LandedSpend {
                height: num("height")?,
                tx_id: hex32_arg(&format!("landed[{i}].tx_id"), l.get("tx_id"))?,
                intent_digest: hex32_arg(&format!("landed[{i}].intent_digest"), l.get("intent_digest"))?,
                leaves: u32::try_from(num("leaves")?).map_err(|_| format!("landed[{i}].leaves is out of range"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let r = settle_records(&records, basis.form, &basis.genesis_hash, &landed, walked_from, checked_to);
    Ok(serde_json::json!({
        "lines": r.lines.iter().map(|(k, o)| serde_json::json!({"key": hex(k), "outcome": o})).collect::<Vec<_>>(),
        "landed": r.landed.iter().map(|(k, h, t)| serde_json::json!({"key": hex(k), "height": h, "tx_id": hex(t)})).collect::<Vec<_>>(),
        "expired": r.expired.iter().map(|(k, v)| serde_json::json!({"key": hex(k), "valid_until": v})).collect::<Vec<_>>(),
        "undecodable": r.undecodable.iter().map(|(k, w)| serde_json::json!({"key": hex(k), "why": w})).collect::<Vec<_>>(),
        "foreign": r.foreign.iter().map(|(k, w)| serde_json::json!({"key": hex(k), "why": w})).collect::<Vec<_>>(),
        "uncovered": r
            .uncovered
            .iter()
            .map(|(k, lo, from)| serde_json::json!({"key": hex(k), "lo": lo, "walked_from": from}))
            .collect::<Vec<_>>(),
    })
    .to_string())
}

/// Lab #989: **settle recorded remote sends from the chain** — the kernel's
/// `remote_prover::settle_records` over the caller's own records, on the
/// basis's net (its form and genesis). `records_json` is
/// `[{"key":"<64 hex>","bundle":"<hex>","outcome":"<line>"|null}, …]`,
/// `landed_json` is [`qmb_auth_check_take_landed`]'s output, `walked_from`
/// the first height that check walked (lab #992: one past the previous
/// checked height in check mode, 0 for a restore or a first) and
/// `checked_to` the finished journal's checked height. Returns
/// `{"lines":[{"key","outcome"}],"landed":[{"key","height","tx_id"}],
/// "expired":[{"key","valid_until"}],"undecodable":[{"key","why"}],
/// "foreign":[{"key","why"}],"uncovered":[{"key","lo","walked_from"}]}`: the
/// caller writes each line as that record's outcome. `foreign` (lab #991) is
/// a record whose auth section does not verify for this basis's genesis —
/// another net's: no line, leave it open. `uncovered` (lab #992) is a record
/// whose walks do not cover its earliest landing height `lo`: no line; a
/// restore of this net settles it. An open line may gain a trailing
/// `unlanded-through <p>` (progress; `pending …` for a record with no
/// outcome) — still open.
/// NULL with `*err_out` on a malformed argument.
///
/// # Safety
/// `basis` live (or NULL); the strings NUL-terminated (or NULL); `err_out`
/// NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_remote_settle(
    basis: *const SpendBasis,
    records_json: *const c_char,
    landed_json: *const c_char,
    walked_from: u64,
    checked_to: u64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if basis.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let run = || -> Result<String, String> {
        let records = text_arg("records_json", records_json, MAX_SETTLE_RECORDS_JSON)?;
        let landed = text_arg("landed_json", landed_json, MAX_SETTLE_LANDED_JSON)?;
        settle_json(&*basis, records, landed, walked_from, checked_to)
    };
    match run() {
        Ok(json) => out_string(json),
        Err(why) => {
            set_err(err_out, why);
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `c` live (or NULL); never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_check_free(c: *mut CheckHandle) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}

/// **Migrate** (`migrate --open-next`): open the next generation as active;
/// the active one becomes sweep-only on `basis`'s net from `gate_tip +
/// 1152`. Returns 0 with `*out_journal` the new journal text to persist (new
/// addresses: sharing shows the latest), or -1 with `*out_journal` why.
///
/// # Safety
/// `w`, `basis` live; `journal_text` NUL-terminated UTF-8; `out_journal` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_auth_open_next(
    w: *const WalletState,
    journal_text: *const c_char,
    basis: *const SpendBasis,
    out_journal: *mut *mut c_char,
) -> i32 {
    if w.is_null() || basis.is_null() || out_journal.is_null() {
        return -1;
    }
    let done = (|| {
        let text = text_arg("the journal", journal_text, MAX_JOURNAL_TEXT)?;
        let mut journal = AuthJournal::from_text(text).map_err(|e| format!("auth.v1: {e}"))?;
        let b = &*basis;
        let next_g = journal.generations().iter().map(|r| r.g).max().expect("non-empty") + 1;
        let gate = SweepGate {
            genesis: b.genesis_hash,
            not_before_height: b.gate_tip.saturating_add(qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS),
        };
        if journal.net() != &b.auth_net {
            return Err("auth.v1 is not of this net's authorization derivation".to_string());
        }
        journal.open_next_mem((*w).generation_root(next_g, b.auth_net), gate).map_err(|e| e.to_string())?;
        Ok::<_, String>(journal.to_text())
    })();
    match done {
        Ok(text) => {
            *out_journal = out_string(text);
            0
        }
        Err(e) => {
            *out_journal = out_string(e);
            -1
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
    /// Lab #937 PR D: the prover this spend pays (format 34), admitted once
    /// by `qmb_spend_v2_prover` against this network's pin — its price is
    /// fixed for every step of the plan; `/info` is never read again.
    prover: Option<Prover>,
}

/// An admitted prover: the advertised price (≤ the pinned maximum) and the
/// pinned payee.
#[derive(Clone)]
struct Prover {
    price: ProverPrice,
    payee: Recipient,
    short: String,
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
        let names = names_for(self.asset, b.list.as_ref(), &b.genesis_hash, bound);
        if shape == L2ShapeTag::R {
            return Err(Attempt::Refused("shape R is a registry write, not a spend".into()));
        }

        // Lab #937 PR D: a format-34 spend pays its prover in the
        // transaction (the third output); this kernel cannot prove, so it
        // builds none unpaid.
        let three = b.form.sp_outputs() == 3;
        if three && self.prover.is_none() {
            return Err(Attempt::Refused(
                "a format-34 spend pays its prover in the transaction: set the prover with qmb_spend_v2_prover first"
                    .into(),
            ));
        }
        let price = self.prover.as_ref().map(|p| p.price);
        // The active generation's notes, its keys, its address (the CLI's rule).
        let index = b.index.only_generation(auth.generation);
        let plan = plan_send_paying(&index, self.asset, self.amount, shape, tiers, price)
            .map_err(|e| Attempt::Refused(e.to_string()))?;
        // The budget is judged before the take; after it the cursor has moved
        // by this step's own leaves, and the plan's whole count would refuse
        // a transaction whose leaves are already spent.
        if paths.is_none() {
            budget(auth, &index, &plan)?;
        }
        // A sweep-only generation pays only this wallet's active generation,
        // its address re-derived from the wallet (lab #924 PR 3b).
        if auth.sweep_only && self.to.rkm != auth.active_rkm {
            return Err(Attempt::Refused(format!(
                "generation {} is sweep-only: it may pay only this wallet's active generation's address",
                auth.generation
            )));
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
                        // A sweep's change goes to the active generation too.
                        Out { to: if auth.sweep_only { self.to.clone() } else { own.clone() }, value: step.outputs[1], asset: a },
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
        // Lab #937 PR D: format 34's third output — the prover's fee at this
        // step's price, to the pinned payee.
        let mut outs: Vec<Out> = outs.to_vec();
        if three {
            let (Some(p), Some((value, asset))) = (&self.prover, step.third) else {
                return Err(Attempt::Refused("a format-34 step without its prover fee".into()));
            };
            outs.push(Out { to: p.payee.clone(), value, asset });
        }
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
        // The kernel's one construction (`step_review`, shared with the Rust
        // send): this handle prepares the plan's first step.
        let review = step_review(
            &plan,
            0,
            self.to.rkm,
            own.rkm,
            self.to_short.clone(),
            b.spends_verified,
            names,
            self.prover.as_ref().map(|p| (p.payee.rkm, p.short.clone())),
        );
        debug_assert_eq!(review.kind, label);
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
    if auth.sweep_only {
        // A sweep empties the generation: no floor to keep (the CLI's rule).
        return Ok(());
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
        match basis.form {
            // Lab #937 PR D: a format-34 spend also pays its prover — set
            // with `qmb_spend_v2_prover` before the first step.
            L2AuthForm::CandidateA | L2AuthForm::CandidateAV3 => {}
            L2AuthForm::None => {
                return Err("this net is not a Candidate A net: its sends are not signed by the wallet's keys".into())
            }
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
            prover: None,
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

/// The longest `/v2/annulet/info` answer accepted.
const MAX_PROVER_INFO: usize = 16 * 1024;

/// **The prover this spend pays** (lab #937 PR D; format 34 only), from the
/// prover service's `/v2/annulet/info` answer `info` (`len` bytes) as the
/// host fetched it. Checked against **this kernel's pin** for the spend's
/// network (`qumbra_wallet::prover_pins`): the genesis hash, the fee asset
/// (0), the payee (the pinned one, by decoded `rkm`) and the price (each
/// shape ≤ the pinned maximum). The advertised price is then **fixed for the
/// whole handle** — every step of the plan pays it, the review's total line
/// sums it, and `/info` is never read again. Call once, before the first
/// `qmb_spend_v2_step`. Returns 0, or -1 with `*err_out` the refusal by name
/// (the handle is unchanged).
///
/// # Safety
/// `s` live; `info` `len` readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_spend_v2_prover(
    s: *mut SpendHandle,
    info: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> i32 {
    if !err_out.is_null() {
        *err_out = ptr::null_mut();
    }
    if s.is_null() || info.is_null() {
        set_err(err_out, "NULL argument".into());
        return -1;
    }
    let h = &mut *s;
    let admitted = (|| {
        if !matches!(h.phase, Phase::Pumping) || h.asked.is_some() || !h.answers.is_empty() {
            return Err("the prover is set before the first step".to_string());
        }
        if h.prover.is_some() {
            return Err("the prover is already set: its price is fixed for this spend".into());
        }
        if h.basis.form.sp_outputs() != 3 {
            return Err("this net is not format 34: its spends carry no third output, so no prover is paid in them".into());
        }
        if len > MAX_PROVER_INFO {
            return Err(format!("a {len}-byte /v2/annulet/info, over the {MAX_PROVER_INFO} B bound"));
        }
        let bytes = std::slice::from_raw_parts(info, len);
        let p = qumbra_wallet::prover_pins::admit(bytes, &h.basis.genesis_hash).map_err(|e| e.to_string())?;
        let ek = p.payee.encapsulation_key().ok_or("the pinned payee has no valid encapsulation key")?;
        Ok(Prover {
            price: p.price,
            payee: Recipient { rkm: p.payee.rkm_lanes(), ek },
            short: p.payee.short().encode(),
        })
    })();
    match admitted {
        Ok(p) => {
            h.prover = Some(p);
            0
        }
        Err(e) => {
            set_err(err_out, e);
            -1
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
    qumbra_wallet::annulet_review::render(&t.review, &t.intent, &t.intent_bytes, bytes, &t.prepared.outputs)
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
