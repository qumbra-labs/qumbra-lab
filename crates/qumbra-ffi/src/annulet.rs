//! **Annulet asset balances over the C ABI** (lab #858 WA2): the verified
//! scan of `qumbra_wallet::annulet_driver` and the asset view of
//! `qumbra_wallet::asset_view`, caller-pumped, for the browser extension (and
//! any shell without a synchronous network).
//!
//! The handle runs the one orchestration in two phases, in the order the
//! macOS bridge's synchronous path fetches: the `AnnuletVerifyDriver`'s
//! `Need`s, then one registry leaf per [`held_assets`] entry. It owns no
//! storage and no transport — the verified-header record comes in as bytes at
//! [`qmb_annulet_new`] and goes out from [`qmb_annulet_take_record`]; every
//! path goes out from [`qmb_annulet_step`] and its answer comes back through
//! [`qmb_annulet_supply`] / [`qmb_annulet_supply_err`].
//!
//! The view crosses as JSON from [`view_json`], **the shared encoder** (issue
//! #858 Q2): byte-for-key the macOS bridge's `AssetViewModel`
//! (`qumbra-wallet-macos` `rust/src/assets.rs` @ e050024), pinned by a test
//! against that repo's XCTest decode literal. `spendsVerified` is always
//! present (design D5).
//!
//! JSON is built through `serde_json::Value`. `serde_json` enters this crate's
//! wasm graph with `qumbra-wallet`'s `verify` feature (new to the graph with
//! WA2, with `qlab-p2p`); no derive is used.

use std::ffi::{c_char, CStr};
use std::ptr;

use qlab_wallet::Wallet;
use qumbra_wallet::annulet_driver::{AnnuletStep, AnnuletVerifyDriver};
use qumbra_wallet::annulet_verify::{encode_chain_cache, registry_leaf_path, VerifiedAnnulet, VerifyRefusal};
use qumbra_wallet::asset_view::{
    asset_view_from, check_leaf_at_verified_tip, held_assets, verify_asset_list, AssetLabel, AssetList, AssetMode,
    AssetView, Balances, FreezeStatus, Leaves, ListKey, ListStatus,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};

use crate::{out_string, set_err, WalletState};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The shared encoder
// ---------------------------------------------------------------------------

fn label_json(label: &AssetLabel) -> Value {
    match label {
        AssetLabel::FeeUnit => json!({"kind": "fee_unit"}),
        AssetLabel::Listed { name, ticker } => json!({"kind": "listed", "name": name, "ticker": ticker}),
        AssetLabel::IssuerChanged { listed_ticker } => json!({"kind": "issuer_changed", "listedTicker": listed_ticker}),
        AssetLabel::Unconfirmed { listed_ticker } => json!({"kind": "unconfirmed", "listedTicker": listed_ticker}),
        AssetLabel::Unlisted => json!({"kind": "unlisted"}),
    }
}

fn mode_json(mode: AssetMode) -> (&'static str, Option<u64>) {
    match mode {
        AssetMode::Cloaked => ("cloaked", None),
        AssetMode::Hybrid => ("hybrid", None),
        AssetMode::Regulated => ("regulated", None),
        AssetMode::Other(raw) => ("other", Some(raw)),
        AssetMode::Unknown => ("unknown", None),
    }
}

fn freeze_json(freeze: &FreezeStatus) -> &'static str {
    match freeze {
        FreezeStatus::NoFreezeList => "no_freeze_list",
        FreezeStatus::NotChecked => "not_checked",
        FreezeStatus::Frozen => "frozen",
        FreezeStatus::NotFrozen => "not_frozen",
        FreezeStatus::Unknown => "unknown",
    }
}

/// **The view as JSON** — the one encoder both shells read. `endpoint` is the
/// host's label for where it fetched (never dereferenced here); `body_cost` is
/// [`VerifiedAnnulet::body_cost`]; `list_source_commit` is carried verbatim,
/// and only when a list labelled the view.
pub fn view_json(endpoint: &str, view: &AssetView, body_cost: (u64, u64), list_source_commit: Option<&str>) -> Value {
    let list = match &view.list {
        ListStatus::Listed { network, digest, signer } => {
            json!({"state": "listed", "network": network, "digest": hex(digest), "signer": hex(signer)})
        }
        ListStatus::NoList => json!({"state": "no_list"}),
        ListStatus::OtherNetwork { list_genesis } => json!({"state": "other_network", "listGenesis": hex(list_genesis)}),
    };
    let list_source_commit = match view.list {
        ListStatus::Listed { .. } => list_source_commit,
        _ => None,
    };
    let balances = match &view.balances {
        Balances::Unavailable { why } => json!({"state": "unavailable", "reason": why}),
        Balances::Figures(rows) => {
            let rows: Vec<Value> = rows
                .iter()
                .map(|row| {
                    let (mode, mode_raw) = mode_json(row.mode);
                    json!({
                        "asset": row.asset,
                        "label": label_json(&row.label),
                        "mode": mode,
                        "modeRaw": mode_raw,
                        // A u128: a JSON number (and Swift's Double) cannot
                        // carry it exactly.
                        "spendable": {
                            "baseUnits": row.spendable.base_units.to_string(),
                            "display": row.spendable.display,
                            "unit": row.spendable.unit,
                        },
                        "spendableNotes": row.spendable_notes,
                        "testnet": row.testnet,
                        "freeze": freeze_json(&row.freeze),
                        "leafProblem": row.leaf_problem,
                    })
                })
                .collect();
            json!({"state": "figures", "rows": rows})
        }
    };
    json!({
        "endpoint": endpoint,
        "genesisHash": hex(&view.genesis_hash),
        "verifiedTip": view.verified_tip,
        "statedTip": view.stated_tip,
        "headersBehind": view.stated_tip.and_then(|s| s.checked_sub(view.verified_tip)).filter(|b| *b > 0),
        "bodiesRecomputed": body_cost.0,
        "bodyBytes": body_cost.1,
        // Required, never optional (design D5).
        "spendsVerified": view.spends_verified,
        "list": list,
        "listSourceCommit": list_source_commit,
        "balances": balances,
    })
}

/// The stable machine key of a refusal: the variant's name in snake_case.
/// Exhaustive — a new variant does not compile without a key, and
/// `every_refusal_has_its_pinned_key` pins each string.
pub fn refusal_key(r: &VerifyRefusal) -> &'static str {
    use VerifyRefusal::*;
    match r {
        NoPin => "no_pin",
        GenesisUnavailable { .. } => "genesis_unavailable",
        GenesisTooLarge { .. } => "genesis_too_large",
        GenesisMismatch { .. } => "genesis_mismatch",
        GenesisInvalid { .. } => "genesis_invalid",
        HeadersUnavailable { .. } => "headers_unavailable",
        HeadersMalformed { .. } => "headers_malformed",
        HeaderGap { .. } => "header_gap",
        HeaderFork { .. } => "header_fork",
        HeaderInvalid { .. } => "header_invalid",
        BodyUnavailable { .. } => "body_unavailable",
        BodyMalformed { .. } => "body_malformed",
        BodyHeaderMismatch { .. } => "body_header_mismatch",
        BodyCommitmentMismatch { .. } => "body_commitment_mismatch",
        ForgedNote { .. } => "forged_note",
        ForgedGenesisNote { .. } => "forged_genesis_note",
        RegistryUnavailable { .. } => "registry_unavailable",
        RegistryWrongAsset { .. } => "registry_wrong_asset",
        RegistryHeightUnverified { .. } => "registry_height_unverified",
        RegistryRootMismatch { .. } => "registry_root_mismatch",
        RegistryPathMismatch { .. } => "registry_path_mismatch",
        ChainCacheInvalid { .. } => "chain_cache_invalid",
        CachedTipForked { .. } => "cached_tip_forked",
        DriverMisuse { .. } => "driver_misuse",
    }
}

/// A refusal as it crosses: `{"refusal": key, "message": Display}`.
pub fn refusal_json(r: &VerifyRefusal) -> Value {
    json!({"refusal": refusal_key(r), "message": r.to_string()})
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

enum Phase {
    Verify(Box<AnnuletVerifyDriver>),
    /// The scan verified; open each held asset's leaf, in `held` order.
    Leaves { v: Box<VerifiedAnnulet>, held: Vec<u16>, leaves: Leaves, pending: Option<u16> },
    /// The view is ready (or taken); stepping again answers -1.
    Done,
    Refused(VerifyRefusal),
}

pub struct AnnuletState {
    wallet: Wallet,
    endpoint: String,
    list: Option<AssetList>,
    list_source_commit: Option<String>,
    rng: StdRng,
    phase: Phase,
    /// Set when DONE is first reported, so a later step answers -1.
    reported: bool,
    view: Option<String>,
    record: Option<Vec<u8>>,
}

/// Bytes from a (pointer, length) pair; `None` for NULL or zero length.
unsafe fn bytes_opt(p: *const u8, len: usize) -> Option<Vec<u8>> {
    (!p.is_null() && len > 0).then(|| std::slice::from_raw_parts(p, len).to_vec())
}

/// Start a verified Annulet asset scan. NULL on a NULL/invalid argument, or
/// with `*err_out` set when the list does not verify. See the header for the
/// contract of every argument.
///
/// # Safety
/// `w` live; `endpoint_label` NUL-terminated UTF-8; `pin32` and `rng_seed32`
/// 32 readable bytes each; `indices` `n_indices` u64s; each (pointer, length)
/// pair readable or NULL; `list_source_commit` NUL-terminated or NULL;
/// `err_out` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn qmb_annulet_new(
    w: *const WalletState,
    endpoint_label: *const c_char,
    pin32: *const u8,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
    record: *const u8,
    record_len: usize,
    list: *const u8,
    list_len: usize,
    list_sig: *const u8,
    sig_len: usize,
    list_key: *const u8,
    key_len: usize,
    list_source_commit: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut AnnuletState {
    if w.is_null() || endpoint_label.is_null() || pin32.is_null() || indices.is_null() || rng_seed32.is_null() {
        return ptr::null_mut();
    }
    let Ok(endpoint) = CStr::from_ptr(endpoint_label).to_str() else { return ptr::null_mut() };
    let commit = if list_source_commit.is_null() {
        None
    } else {
        match CStr::from_ptr(list_source_commit).to_str() {
            Ok(c) => Some(c.to_string()),
            Err(_) => return ptr::null_mut(),
        }
    };
    let list = match (bytes_opt(list, list_len), bytes_opt(list_sig, sig_len), bytes_opt(list_key, key_len)) {
        (None, None, None) => None,
        (Some(bytes), Some(sig), Some(key)) => {
            let Some(key) = ListKey::from_encoded(&key) else {
                set_err(err_out, "the asset-list key does not decode".into());
                return ptr::null_mut();
            };
            match verify_asset_list(&bytes, &sig, &key) {
                Ok(list) => Some(list),
                Err(refusal) => {
                    set_err(err_out, format!("the asset list is refused: {refusal}"));
                    return ptr::null_mut();
                }
            }
        }
        _ => {
            set_err(err_out, "an asset list needs its bytes, its signature and the key — all three or none".into());
            return ptr::null_mut();
        }
    };
    let mut pin = [0u8; 32];
    pin.copy_from_slice(std::slice::from_raw_parts(pin32, 32));
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));
    let allocated = std::slice::from_raw_parts(indices, n_indices).to_vec();
    let wallet = (*w).wallet.clone();
    let driver = AnnuletVerifyDriver::new(wallet.clone(), allocated, pin, from, to, Ok(bytes_opt(record, record_len)));
    Box::into_raw(Box::new(AnnuletState {
        wallet,
        endpoint: endpoint.to_string(),
        list,
        list_source_commit: commit,
        rng: StdRng::from_seed(seed),
        phase: Phase::Verify(Box::new(driver)),
        reported: false,
        view: None,
        record: None,
    }))
}

impl AnnuletState {
    /// One observation: a path, the view, or a refusal.
    fn step(&mut self) -> Result<Option<String>, VerifyRefusal> {
        loop {
            match std::mem::replace(&mut self.phase, Phase::Done) {
                Phase::Verify(mut driver) => match driver.step(&mut self.rng) {
                    AnnuletStep::Need(path) => {
                        self.phase = Phase::Verify(driver);
                        return Ok(Some(path));
                    }
                    AnnuletStep::Done(v) => {
                        let held = held_assets(&v);
                        self.phase = Phase::Leaves { v, held, leaves: Leaves::new(), pending: None };
                    }
                    AnnuletStep::Failed(e) => {
                        self.phase = Phase::Refused(e.clone());
                        return Err(e);
                    }
                },
                Phase::Leaves { v, held, leaves, pending: None } => match held.get(leaves.len()).copied() {
                    Some(asset) => {
                        self.phase = Phase::Leaves { v, held, leaves, pending: Some(asset) };
                        return Ok(Some(registry_leaf_path(asset)));
                    }
                    None => {
                        self.finish(&v, &leaves);
                        return Ok(None);
                    }
                },
                Phase::Leaves { v, held, leaves, pending: Some(asset) } => {
                    self.phase = Phase::Leaves { v, held, leaves, pending: Some(asset) };
                    return Ok(Some(registry_leaf_path(asset)));
                }
                Phase::Done => return Ok(None),
                Phase::Refused(e) => {
                    self.phase = Phase::Refused(e.clone());
                    return Err(e);
                }
            }
        }
    }

    fn supply(&mut self, answer: Result<Vec<u8>, String>) {
        match &mut self.phase {
            Phase::Verify(driver) => driver.supply(answer),
            Phase::Leaves { v, leaves, pending, .. } => match pending.take() {
                Some(asset) => {
                    leaves.insert(asset, check_leaf_at_verified_tip(v.chain(), asset, answer));
                }
                None => self.misuse("a response with no Need outstanding"),
            },
            Phase::Done => self.misuse("a response after the view was ready"),
            Phase::Refused(_) => {}
        }
    }

    fn misuse(&mut self, why: &str) {
        self.phase = Phase::Refused(VerifyRefusal::DriverMisuse { why: why.to_string() });
    }

    fn finish(&mut self, v: &VerifiedAnnulet, leaves: &Leaves) {
        // No freeze lists are fetched in v1 (the macOS bridge's rule): a leaf
        // with a freeze root reads "not checked", never "not frozen".
        let freeze = std::collections::BTreeMap::new();
        let view = asset_view_from(&self.wallet, v, self.list.as_ref(), &freeze, leaves);
        let json = view_json(&self.endpoint, &view, v.body_cost(), self.list_source_commit.as_deref());
        self.view = Some(json.to_string());
        self.record = v.record_to_write().map(|headers| encode_chain_cache(&v.chain().genesis.hash, headers));
        self.phase = Phase::Done;
    }
}

/// Pump the scan one observation forward: `1` NEED (`*out` the path), `0`
/// DONE (take the view and the record), `-2` REFUSED (`*out` the refusal
/// JSON; terminal, repeated on every later step), `-1` NULL handle/`out` or
/// a step after DONE.
///
/// # Safety
/// `s` live (or NULL); `out` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_step(s: *mut AnnuletState, out: *mut *mut c_char) -> i32 {
    if s.is_null() || out.is_null() {
        return -1;
    }
    let st = &mut *s;
    if st.reported {
        return -1;
    }
    match st.step() {
        Ok(Some(path)) => {
            *out = out_string(path);
            1
        }
        Ok(None) => {
            st.reported = true;
            0
        }
        Err(e) => {
            *out = out_string(refusal_json(&e).to_string());
            -2
        }
    }
}

/// Answer the outstanding NEED with bytes (COPIED; a NULL body is a
/// transport error, never a decode of nothing).
///
/// # Safety
/// `s` live (or NULL); `body` `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_supply(s: *mut AnnuletState, body: *const u8, len: usize) {
    if s.is_null() {
        return;
    }
    let answer = if body.is_null() {
        Err("supplied body is NULL".to_string())
    } else {
        Ok(std::slice::from_raw_parts(body, len).to_vec())
    };
    (*s).supply(answer);
}

/// Answer the outstanding NEED with a transport failure, by name.
///
/// # Safety
/// `s` live (or NULL); `reason` NUL-terminated (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_supply_err(s: *mut AnnuletState, reason: *const c_char) {
    if s.is_null() {
        return;
    }
    let reason = if reason.is_null() {
        "transport failed with no reason".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().into_owned()
    };
    (*s).supply(Err(reason));
}

/// The view JSON after DONE — once; NULL before DONE, after a refusal, or on
/// a second call. Free with `qmb_string_free`.
///
/// # Safety
/// `s` live (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_take_view(s: *mut AnnuletState) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    match (*s).view.take() {
        Some(json) => out_string(json),
        None => ptr::null_mut(),
    }
}

/// The verified-header record to store after DONE — once; NULL (and
/// `*out_len = 0`) when there is nothing new to store. Release with
/// `qmb_dealloc(p, len)`.
///
/// # Safety
/// `s` live (or NULL); `out_len` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_take_record(s: *mut AnnuletState, out_len: *mut usize) -> *mut u8 {
    if s.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    match (*s).record.take() {
        Some(bytes) => {
            *out_len = bytes.len();
            Box::into_raw(bytes.into_boxed_slice()) as *mut u8
        }
        None => {
            *out_len = 0;
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `s` must be a live handle from [`qmb_annulet_new`]; never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_annulet_free(s: *mut AnnuletState) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}
