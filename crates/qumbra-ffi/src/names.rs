//! The generic name-service surface — `qmb_name_*` (lab #659, mobile
//! name-service rung 1).
//!
//! The macOS bridge implements name registration as eleven `qmb_macos_name_*`
//! entry points that do their own storage and HTTP. This crate is sans-IO and
//! storage-free, so the promotion is a **capability** port, not a signature
//! port:
//!
//! - **State crosses as a string** — the exact versioned record
//!   [`qumbra_wallet::names::RegisterState::save`] writes. The platform
//!   persists it (Keychain on iOS, per mobile-name-service-brief §3.2: the
//!   salt is registration-critical secret material), and every mutation here
//!   is a pure `state in → state out` function. Losing this string after a
//!   commit loses the registration; the view says so.
//! - **The platform sources the salt** (32 bytes, SecRandomCopyBytes on iOS)
//!   and owns address-index allocation — the same two rules the rest of this
//!   ABI already lives by.
//! - **Network crosses as riders + fetches.** A commit or reveal is an
//!   ordinary spend carrying a rider: `qmb_name_*_rider` here feeds
//!   `qmb_select_new_v2`, and the two chain lookups take the caller's
//!   [`crate::QmbFetchFn`].
//! - **Nothing here completes a registration except chain observation**
//!   (`qmb_name_observe_reveal_over_fetch`) — the wallet-macos#27 rule: a
//!   node's ACCEPT is mempool-level, and clearing state on it is lab #625.
//!   The view carries `discard_safe` so no shell re-derives that verdict.

use std::ffi::{c_char, c_void, CStr};
use std::ptr;

use qumbra_wallet::names::{
    commit_at_height, find_name_commit_height, prepare_registration_parts, renewal_op,
    sync_names, RegisterState, RegisterStep, WalletRegistry,
};

use crate::{fetch_bytes, out_string, set_err, QmbFetchFn, WalletState};

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Minimal JSON string escape — the payloads are ASCII (grammar-checked
/// names, bech32m addresses, fixed English sentences), but a codec must not
/// depend on that staying true.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

unsafe fn state_in(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> Option<RegisterState> {
    if state.is_null() {
        set_err(err_out, "NULL state".into());
        return None;
    }
    let text = match CStr::from_ptr(state).to_str() {
        Ok(t) => t,
        Err(_) => {
            set_err(err_out, "state is not UTF-8".into());
            return None;
        }
    };
    match RegisterState::from_record_str(text) {
        Ok(Some(s)) => Some(s),
        Ok(None) => {
            set_err(err_out, "state holds a header but no record".into());
            None
        }
        Err(e) => {
            set_err(err_out, e.to_string());
            None
        }
    }
}

unsafe fn required_name(
    name: *const c_char,
    err_out: *mut *mut c_char,
) -> Option<String> {
    if name.is_null() {
        set_err(err_out, "NULL name".into());
        return None;
    }
    match CStr::from_ptr(name).to_str() {
        Ok(n) => Some(n.to_string()),
        Err(_) => {
            set_err(err_out, "name is not UTF-8".into());
            None
        }
    }
}

/* --- the state machine, state in → state out ------------------------------ */

/// Begin a registration: grammar check + fresh `RegisterState`. Returns the
/// state record string the platform must persist BEFORE any network request —
/// it holds the only reveal salt. `address_index` is the caller-allocated
/// dedicated address index; `salt32` is 32 platform-sourced entropy bytes.
///
/// # Safety
/// `w` live; `name` NUL-terminated UTF-8; `salt32` points to 32 readable
/// bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_prepare(
    w: *const WalletState,
    name: *const c_char,
    address_index: u64,
    salt32: *const u8,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if w.is_null() || salt32.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let Some(name) = required_name(name, err_out) else {
        return ptr::null_mut();
    };
    let mut salt = [0u8; 32];
    salt.copy_from_slice(std::slice::from_raw_parts(salt32, 32));
    let address = (*w).wallet.address_at_index(address_index).to_raw_bytes();
    match prepare_registration_parts(&name, address, salt) {
        Ok(state) => out_string(state.to_record_string()),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// The registration, rendered: a JSON object the shell displays and never
/// second-guesses. Fields: `name`, `address`, `fingerprint`, `step`,
/// `detail`, `committed_at`, `commit_attempted`, `next_height`,
/// `reveal_closes`, `reveal_fee_qmb`, `reveal_fee_bessel`, `discard_safe`,
/// `has_retained_reveal`. The step vocabulary is the macOS bridge's,
/// including `reveal_submitted` (a retained-but-unconfirmed reveal —
/// wallet-macos#27's state), so every shell tells one story.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_view(
    state: *const c_char,
    tip: u64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    let Some(address) = qlab_wallet::address::Address::from_raw_bytes(&state.record.address)
    else {
        set_err(err_out, "the persisted name address does not decode".into());
        return ptr::null_mut();
    };
    let reveal_fee = qlab_devnet::names::name_fee_for(&state.reveal_op());
    let (step, next_height, reveal_closes, detail) = match state.step(tip) {
        RegisterStep::NeedsCommit if state.commit_attempted => (
            "awaiting_commit_height",
            None,
            None,
            "The commit was submitted. Record its mined height before revealing.".to_string(),
        ),
        RegisterStep::NeedsCommit => (
            "prepared",
            None,
            None,
            "The dedicated address and secret salt are persisted. Post the commit when ready."
                .to_string(),
        ),
        RegisterStep::WaitForWindow { at } => (
            "waiting_for_reveal",
            Some(at),
            state
                .committed_at
                .map(|h| h.saturating_add(qlab_devnet::names::COMMIT_MAX_AGE)),
            format!("The reveal window opens at height {at}."),
        ),
        // wallet-macos#27's step: the reveal was built and submitted once; the
        // exact transaction is retained and only chain observation confirms.
        RegisterStep::RevealNow { closes } if state.reveal_tx.is_some() => (
            "reveal_submitted",
            None,
            Some(closes),
            format!(
                "The reveal was submitted and awaits chain confirmation; the exact transaction is retained for re-posting. The window closes after height {closes}."
            ),
        ),
        RegisterStep::RevealNow { closes } => (
            "reveal_ready",
            None,
            Some(closes),
            format!("Reveal now; the window closes after height {closes}."),
        ),
        RegisterStep::RevealConfirmed { at } => (
            "reveal_confirmed",
            None,
            None,
            format!(
                "The reveal was observed on chain at height {at}. The registration is complete; the retained retry transaction is no longer needed."
            ),
        ),
        RegisterStep::WindowClosed => (
            "window_closed",
            None,
            None,
            "The reveal window closed. This salt must not be reused; discard this expired attempt before starting again."
                .to_string(),
        ),
    };
    let discard_safe = !state.commit_attempted
        || matches!(
            state.step(tip),
            RegisterStep::WindowClosed | RegisterStep::RevealConfirmed { .. }
        );
    let opt = |v: Option<u64>| v.map_or("null".to_string(), |h| h.to_string());
    out_string(format!(
        "{{\"name\":{},\"address\":{},\"fingerprint\":{},\"step\":{},\"detail\":{},\"committed_at\":{},\"commit_attempted\":{},\"next_height\":{},\"reveal_closes\":{},\"reveal_fee_qmb\":{},\"reveal_fee_bessel\":\"{}\",\"discard_safe\":{},\"has_retained_reveal\":{}}}",
        json_str(&state.name),
        json_str(&address.encode()),
        json_str(&address.short().encode()),
        json_str(step),
        json_str(&detail),
        opt(state.committed_at),
        state.commit_attempted,
        opt(next_height),
        opt(reveal_closes),
        json_str(&qlab_wallet::uri::bessel_to_qmb(reveal_fee)),
        reveal_fee,
        discard_safe,
        state.reveal_tx.is_some(),
    ))
}

/// Mark the commit as attempted — call BEFORE handing the commit bundle to
/// the prover/submitter, so a crash between build and answer fails closed
/// (the salt is preserved until the truth is known).
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_mark_commit_attempted(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    if state.commit_attempted || state.committed_at.is_some() {
        set_err(
            err_out,
            "the commit was already attempted; record its mined height instead of building another transaction"
                .into(),
        );
        return ptr::null_mut();
    }
    state.commit_attempted = true;
    out_string(state.to_record_string())
}

/// Record the mined height of the commit (found by the user or by
/// `qmb_name_find_commit_over_fetch`). The reveal window derives from it.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_record_commit(
    state: *const c_char,
    height: u64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    if !state.commit_attempted {
        set_err(err_out, "no commit was attempted; post the commit first".into());
        return ptr::null_mut();
    }
    state.committed_at = Some(height);
    out_string(state.to_record_string())
}

/// Take back the commit claim — the attempt flag and any recorded height —
/// after the user confirms the commit never mined. The salt is preserved; the
/// same commitment can be posted again.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_confirm_commit_absent(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    if state.committed_at.is_none() && !state.commit_attempted {
        set_err(err_out, "there is no commit attempt or recorded height to reset".into());
        return ptr::null_mut();
    }
    if state.reveal_tx.is_some() || state.revealed_at.is_some() {
        set_err(
            err_out,
            "a reveal was already built against this commit; its height cannot be taken back"
                .into(),
        );
        return ptr::null_mut();
    }
    state.committed_at = None;
    state.commit_attempted = false;
    out_string(state.to_record_string())
}

/// The commit rider for `qmb_select_new_v2`, hex-encoded. Pays relay tier
/// only; the burned name fee rides the reveal.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_commit_rider(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    let op = state.commit_op();
    out_string(hex(&qlab_devnet::names::encode_rider(Some(&op))))
}

/// The reveal rider for `qmb_select_new_v2`, hex-encoded. Its burned name fee
/// folds into the bundle's declared fee.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_reveal_rider(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    let op = state.reveal_op();
    out_string(hex(&qlab_devnet::names::encode_rider(Some(&op))))
}

/// Retain the reveal's exact canonical wire bytes — call BEFORE the first
/// POST can answer (wallet-macos#27 / lab #642: the prover's randomness means
/// the same salt does NOT rebuild the same transaction, so these bytes are
/// the only safe retry). Refused when a different reveal is already retained.
///
/// # Safety
/// `state`, `wire_hex` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_record_reveal(
    state: *const c_char,
    wire_hex: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    if wire_hex.is_null() {
        set_err(err_out, "NULL wire_hex".into());
        return ptr::null_mut();
    }
    let Some(wire) = CStr::from_ptr(wire_hex).to_str().ok().and_then(unhex) else {
        set_err(err_out, "wire_hex did not decode as hex".into());
        return ptr::null_mut();
    };
    if wire.is_empty() {
        set_err(err_out, "wire_hex is empty".into());
        return ptr::null_mut();
    }
    if state.committed_at.is_none() || !state.commit_attempted {
        set_err(err_out, "a reveal cannot be retained before its commit is recorded".into());
        return ptr::null_mut();
    }
    if let Some(existing) = state.reveal_tx.as_deref() {
        if existing != wire.as_slice() {
            set_err(
                err_out,
                "a different reveal transaction is already retained; re-post those exact bytes instead of building another"
                    .into(),
            );
            return ptr::null_mut();
        }
    }
    state.reveal_tx = Some(wire);
    out_string(state.to_record_string())
}

/// The retained reveal transaction, hex-encoded, for re-posting verbatim.
/// NULL with `err_out` untouched when none is retained; NULL with `err_out`
/// set when the state itself does not decode.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_reveal_wire(
    state: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    match state.reveal_tx.as_deref() {
        Some(wire) => out_string(hex(wire)),
        None => ptr::null_mut(),
    }
}

/* --- the two chain lookups, over the caller's transport ------------------- */

/// Search `(floor, tip]` for the mined commit and record its height into the
/// state. `floor` is the name-rule activation floor: the boundary height on a
/// v4 net, 0 on a native-names v5 net (T2). Returns the state — updated when
/// found, unchanged when not (not an error: the commit may simply not be
/// mined yet).
///
/// # Safety
/// `state` NUL-terminated UTF-8; `fetch` obeys [`QmbFetchFn`]; `err_out` NULL
/// or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_find_commit_over_fetch(
    state: *const c_char,
    floor: u64,
    tip: u64,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    let Some(fetch) = fetch else {
        set_err(err_out, "NULL fetch".into());
        return ptr::null_mut();
    };
    let qlab_devnet::names::NameOp::Commit { commit } = state.commit_op() else {
        set_err(err_out, "the registration state produced a non-commit operation".into());
        return ptr::null_mut();
    };
    match find_name_commit_height(commit, floor, tip, |path| fetch_bytes(fetch, fetch_ctx, path))
    {
        Ok(Some(height)) => {
            state.committed_at = Some(height);
            out_string(state.to_record_string())
        }
        Ok(None) => out_string(state.to_record_string()),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// Does the chain carry exactly this commit at its recorded height? One GET
/// before proving the reveal settles what a `CommitNotFound` refusal would
/// otherwise cost a full STARK to learn (the macOS bridge paid twice). `1`
/// present, `0` absent, `-1` error (`err_out` set).
///
/// # Safety
/// `state` NUL-terminated UTF-8; `fetch` obeys [`QmbFetchFn`]; `err_out` NULL
/// or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_commit_present_over_fetch(
    state: *const c_char,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> i32 {
    let Some(state) = state_in(state, err_out) else {
        return -1;
    };
    let Some(fetch) = fetch else {
        set_err(err_out, "NULL fetch".into());
        return -1;
    };
    let Some(height) = state.committed_at else {
        set_err(err_out, "the registration has no recorded commit height".into());
        return -1;
    };
    let qlab_devnet::names::NameOp::Commit { commit } = state.commit_op() else {
        set_err(err_out, "the registration state produced a non-commit operation".into());
        return -1;
    };
    match commit_at_height(commit, height, |path| fetch_bytes(fetch, fetch_ctx, path)) {
        Ok(present) => i32::from(present),
        Err(e) => {
            set_err(err_out, e);
            -1
        }
    }
}

/// Sync the chain's name riders and record the reveal's mined height when
/// this exact registration is observed inside its commit window — the ONLY
/// path that completes a registration (wallet-macos#27; the CLI's rule since
/// lab #642). `registry` is the caller-persisted registry cache string, or
/// NULL to start fresh. Returns a JSON object `{"state": "...",
/// "registry": "..."}` — persist both.
///
/// # Safety
/// `state` NUL-terminated UTF-8; `registry` NULL or NUL-terminated UTF-8;
/// `fetch` obeys [`QmbFetchFn`]; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_observe_reveal_over_fetch(
    state: *const c_char,
    registry: *const c_char,
    tip: u64,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(mut state) = state_in(state, err_out) else {
        return ptr::null_mut();
    };
    let Some(fetch) = fetch else {
        set_err(err_out, "NULL fetch".into());
        return ptr::null_mut();
    };
    let mut registry = if registry.is_null() {
        WalletRegistry::default()
    } else {
        let text = match CStr::from_ptr(registry).to_str() {
            Ok(t) => t,
            Err(_) => {
                set_err(err_out, "registry is not UTF-8".into());
                return ptr::null_mut();
            }
        };
        match WalletRegistry::from_record_str(text) {
            Ok(r) => r,
            Err(e) => {
                set_err(err_out, e.to_string());
                return ptr::null_mut();
            }
        }
    };
    if let Err(e) = sync_names(&mut registry, tip, |path| fetch_bytes(fetch, fetch_ctx, path)) {
        set_err(err_out, e);
        return ptr::null_mut();
    }
    if state.revealed_at.is_none() {
        if let Some(at) = registry.observed_reveal_height(&state) {
            state.revealed_at = Some(at);
        }
    }
    out_string(format!(
        "{{\"state\":{},\"registry\":{}}}",
        json_str(&state.to_record_string()),
        json_str(&registry.to_record_string()),
    ))
}

/* --- renewals and activation, pure ---------------------------------------- */

/// The renewal fee for a name, as JSON `{"qmb": "...", "bessel": "..."}` —
/// integer-exact both ways (#303 is standing law on money).
///
/// # Safety
/// `name` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_renewal_fee(
    name: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(name) = required_name(name, err_out) else {
        return ptr::null_mut();
    };
    match renewal_op(&name) {
        Ok(op) => {
            let fee = qlab_devnet::names::name_fee_for(&op);
            out_string(format!(
                "{{\"qmb\":{},\"bessel\":\"{fee}\"}}",
                json_str(&qlab_wallet::uri::bessel_to_qmb(fee)),
            ))
        }
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// The renewal rider for `qmb_select_new_v2`, hex-encoded. Any payer may
/// renew any name; no registration state is involved.
///
/// # Safety
/// `name` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_renewal_rider(
    name: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    let Some(name) = required_name(name, err_out) else {
        return ptr::null_mut();
    };
    match renewal_op(&name) {
        Ok(op) => out_string(hex(&qlab_devnet::names::encode_rider(Some(&op)))),
        Err(e) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
    }
}

/// Is Name Service active at `tip`? `native` nonzero for a v5 net (T2 —
/// active from height 0); zero for a v4 net, where the compile-time rule
/// boundary gates it. `1` active, `0` not.
#[no_mangle]
pub unsafe extern "C" fn qmb_name_active(native: i32, tip: u64) -> i32 {
    if native != 0 {
        return 1;
    }
    let Some(boundary) = qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT else {
        return 0;
    };
    i32::from(qlab_devnet::names::riders_active_above(Some(boundary), tip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    unsafe fn take(p: *mut c_char) -> String {
        assert!(!p.is_null());
        let s = CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::qmb_string_free(p);
        s
    }

    unsafe fn take_err(err: *mut c_char) -> String {
        assert!(!err.is_null(), "refused without saying why");
        take(err)
    }

    fn c(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    unsafe fn wallet() -> *mut WalletState {
        crate::qmb_wallet_from_entropy([0x11u8; 32].as_ptr())
    }

    unsafe fn prepared_state() -> String {
        let w = wallet();
        let mut err = ptr::null_mut();
        let state = qmb_name_prepare(w, c("alice.qmb").as_ptr(), 3, [7u8; 32].as_ptr(), &mut err);
        crate::qmb_wallet_free(w);
        take(state)
    }

    #[test]
    fn prepare_checks_the_grammar_and_round_trips_the_record_format() {
        unsafe {
            let w = wallet();
            let mut err = ptr::null_mut();
            let refused =
                qmb_name_prepare(w, c("No_Caps!").as_ptr(), 0, [7u8; 32].as_ptr(), &mut err);
            assert!(refused.is_null());
            assert!(take_err(err).contains("grammar"));

            let state = prepared_state();
            let decoded = RegisterState::from_record_str(&state).unwrap().unwrap();
            assert_eq!(decoded.name, "alice");
            assert_eq!(decoded.salt, [7u8; 32]);
            assert!(!decoded.commit_attempted);
            crate::qmb_wallet_free(w);
        }
    }

    #[test]
    fn the_view_walks_the_lifecycle_and_never_makes_the_shell_derive_a_verdict() {
        unsafe {
            let state = prepared_state();
            let mut err = ptr::null_mut();
            let view = take(qmb_name_view(c(&state).as_ptr(), 100, &mut err));
            assert!(view.contains("\"step\":\"prepared\""), "{view}");
            assert!(view.contains("\"discard_safe\":true"), "{view}");

            let state = take(qmb_name_mark_commit_attempted(c(&state).as_ptr(), &mut err));
            let view = take(qmb_name_view(c(&state).as_ptr(), 100, &mut err));
            assert!(view.contains("\"step\":\"awaiting_commit_height\""), "{view}");
            assert!(view.contains("\"discard_safe\":false"), "{view}");

            let state = take(qmb_name_record_commit(c(&state).as_ptr(), 100, &mut err));
            let view = take(qmb_name_view(c(&state).as_ptr(), 100, &mut err));
            assert!(view.contains("\"step\":\"waiting_for_reveal\""), "{view}");

            // Inside the window; then a retained reveal is its own step
            // (wallet-macos#27's vocabulary, shared by every shell).
            let view = take(qmb_name_view(c(&state).as_ptr(), 120, &mut err));
            assert!(view.contains("\"step\":\"reveal_ready\""), "{view}");
            assert!(view.contains("\"has_retained_reveal\":false"), "{view}");
            let state =
                take(qmb_name_record_reveal(c(&state).as_ptr(), c("513632").as_ptr(), &mut err));
            let view = take(qmb_name_view(c(&state).as_ptr(), 120, &mut err));
            assert!(view.contains("\"step\":\"reveal_submitted\""), "{view}");
            assert!(view.contains("\"has_retained_reveal\":true"), "{view}");
            assert!(view.contains("\"discard_safe\":false"), "{view}");

            // Past the window unrevealed: dead, and now discardable.
            let closes = 100 + qlab_devnet::names::COMMIT_MAX_AGE;
            let view = take(qmb_name_view(c(&state).as_ptr(), closes + 1, &mut err));
            assert!(view.contains("\"step\":\"window_closed\""), "{view}");
            assert!(view.contains("\"discard_safe\":true"), "{view}");
        }
    }

    #[test]
    fn commit_claims_move_only_along_legal_edges() {
        unsafe {
            let state = prepared_state();
            let mut err = ptr::null_mut();

            // Recording a height before any attempt is refused.
            assert!(qmb_name_record_commit(c(&state).as_ptr(), 5, &mut err).is_null());
            assert!(take_err(err).contains("no commit was attempted"));
            let mut err = ptr::null_mut();

            // Nothing to take back yet.
            assert!(qmb_name_confirm_commit_absent(c(&state).as_ptr(), &mut err).is_null());
            assert!(take_err(err).contains("no commit attempt"));
            let mut err = ptr::null_mut();

            let attempted = take(qmb_name_mark_commit_attempted(c(&state).as_ptr(), &mut err));
            // A second attempt is refused — one commit, one claim.
            assert!(qmb_name_mark_commit_attempted(c(&attempted).as_ptr(), &mut err).is_null());
            assert!(take_err(err).contains("already attempted"));
            let mut err = ptr::null_mut();

            // Attempted-then-absent goes back to the start, salt intact.
            let reset = take(qmb_name_confirm_commit_absent(c(&attempted).as_ptr(), &mut err));
            let a = RegisterState::from_record_str(&attempted).unwrap().unwrap();
            let r = RegisterState::from_record_str(&reset).unwrap().unwrap();
            assert!(!r.commit_attempted && r.committed_at.is_none());
            assert_eq!(a.salt, r.salt);
        }
    }

    #[test]
    fn a_reveal_is_retained_once_and_only_after_its_commit() {
        unsafe {
            let state = prepared_state();
            let mut err = ptr::null_mut();

            // Before the commit is recorded: refused.
            assert!(
                qmb_name_record_reveal(c(&state).as_ptr(), c("aa").as_ptr(), &mut err).is_null()
            );
            assert!(take_err(err).contains("before its commit"));
            let mut err = ptr::null_mut();

            let state = take(qmb_name_mark_commit_attempted(c(&state).as_ptr(), &mut err));
            let state = take(qmb_name_record_commit(c(&state).as_ptr(), 100, &mut err));
            let state =
                take(qmb_name_record_reveal(c(&state).as_ptr(), c("513632").as_ptr(), &mut err));

            // Same bytes again: idempotent. Different bytes: refused — the
            // first build is the only safe retry (lab #642).
            let again =
                take(qmb_name_record_reveal(c(&state).as_ptr(), c("513632").as_ptr(), &mut err));
            assert_eq!(state, again);
            assert!(
                qmb_name_record_reveal(c(&state).as_ptr(), c("99").as_ptr(), &mut err).is_null()
            );
            assert!(take_err(err).contains("already retained"));
            let mut err = ptr::null_mut();

            // The retained bytes come back verbatim; its commit claim is now
            // frozen (a reveal was built against it).
            assert_eq!(take(qmb_name_reveal_wire(c(&state).as_ptr(), &mut err)), "513632");
            assert!(qmb_name_confirm_commit_absent(c(&state).as_ptr(), &mut err).is_null());
            assert!(take_err(err).contains("cannot be taken back"));
        }
    }

    #[test]
    fn reveal_wire_is_null_without_an_error_when_nothing_is_retained() {
        unsafe {
            let state = prepared_state();
            let mut err = ptr::null_mut();
            assert!(qmb_name_reveal_wire(c(&state).as_ptr(), &mut err).is_null());
            assert!(err.is_null(), "no-retained-reveal is not an error");
        }
    }

    #[test]
    fn riders_decode_back_to_the_operations_they_encode() {
        unsafe {
            let state = prepared_state();
            let mut err = ptr::null_mut();
            let commit_rider = take(qmb_name_commit_rider(c(&state).as_ptr(), &mut err));
            let reveal_rider = take(qmb_name_reveal_rider(c(&state).as_ptr(), &mut err));
            let renewal_rider = take(qmb_name_renewal_rider(c("alice").as_ptr(), &mut err));
            let op = |hex: &str| {
                qlab_devnet::names::decode_rider(&unhex(hex).unwrap()).unwrap().unwrap()
            };
            assert!(matches!(op(&commit_rider), qlab_devnet::names::NameOp::Commit { .. }));
            assert!(matches!(op(&reveal_rider), qlab_devnet::names::NameOp::Reveal { .. }));
            assert!(matches!(op(&renewal_rider), qlab_devnet::names::NameOp::Renew { .. }));

            // The reveal rider's burned fee is the one the view quotes.
            let fee = qlab_devnet::names::name_fee_for(&op(&reveal_rider));
            let view = take(qmb_name_view(c(&state).as_ptr(), 0, &mut err));
            assert!(view.contains(&format!("\"reveal_fee_bessel\":\"{fee}\"")), "{view}");
        }
    }

    #[test]
    fn renewal_fee_is_integer_exact_in_both_units() {
        unsafe {
            let mut err = ptr::null_mut();
            let fee = take(qmb_name_renewal_fee(c("alice").as_ptr(), &mut err));
            let bessel = qlab_devnet::names::name_fee_for(
                &renewal_op("alice").unwrap(),
            );
            assert!(fee.contains(&format!("\"bessel\":\"{bessel}\"")), "{fee}");
            assert!(
                fee.contains(&format!(
                    "\"qmb\":{}",
                    json_str(&qlab_wallet::uri::bessel_to_qmb(bessel))
                )),
                "{fee}"
            );
            assert!(qmb_name_renewal_fee(c("No_Caps!").as_ptr(), &mut err).is_null());
            assert!(take_err(err).contains("grammar"));
        }
    }

    #[test]
    fn activation_is_native_or_boundary_gated() {
        unsafe {
            assert_eq!(qmb_name_active(1, 0), 1, "a v5 net is active from height 0");
            if let Some(boundary) = qlab_devnet::names::NAME_RULE_BOUNDARY_HEIGHT {
                assert_eq!(qmb_name_active(0, boundary), 0);
                assert_eq!(qmb_name_active(0, boundary + 1), 1);
            } else {
                assert_eq!(qmb_name_active(0, u64::MAX), 0);
            }
        }
    }

    #[test]
    fn observe_reveal_confirms_exactly_this_registration_and_returns_both_records() {
        unsafe {
            // A state with a recorded commit, and a served /v1/names view that
            // carries this exact registration inside its window.
            let state = prepared_state();
            let mut err = ptr::null_mut();
            let state = take(qmb_name_mark_commit_attempted(c(&state).as_ptr(), &mut err));
            let state = take(qmb_name_record_commit(c(&state).as_ptr(), 100, &mut err));
            let decoded = RegisterState::from_record_str(&state).unwrap().unwrap();

            // Build the registry the sync WOULD produce, then serve it through
            // a fetch that answers one page echoing the requested range.
            let reveal_height = 100 + qlab_devnet::names::COMMIT_MIN_AGE + 1;
            let entry_line = format!(
                "{} {} {} {} {}\n",
                decoded.name,
                decoded.record.kind,
                reveal_height,
                reveal_height + 1_000_000,
                decoded
                    .record
                    .address
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            // Pre-synced registry: synced_to == tip, so the fetch is never
            // consulted — the observation is pure registry arithmetic. (The
            // sync loop itself is qumbra_wallet::names::sync_names, tested in
            // its own crate; a paged fetch fixture here would re-test it.)
            let tip = reveal_height + 2;
            let registry_text = format!(
                "qumbra-wallet names-registry v1\nsynced_to {tip}\n{entry_line}"
            );
            let registry_in = WalletRegistry::from_record_str(&registry_text);
            let registry_text = match registry_in {
                Ok(r) => r.to_record_string(),
                Err(e) => panic!("fixture registry does not decode: {e}"),
            };

            unsafe extern "C" fn no_fetch(
                _ctx: *mut c_void,
                _path: *const c_char,
                _out: *mut *mut u8,
                _len: *mut usize,
                err: *mut *mut c_char,
            ) -> i32 {
                unsafe { *err = out_string("the pre-synced fixture must not fetch".into()) };
                1
            }

            let out = take(qmb_name_observe_reveal_over_fetch(
                c(&state).as_ptr(),
                c(&registry_text).as_ptr(),
                tip,
                Some(no_fetch),
                ptr::null_mut(),
                &mut err,
            ));
            assert!(out.contains("\"state\":"), "{out}");
            assert!(out.contains("\"registry\":"), "{out}");
            assert!(out.contains(&format!("{reveal_height} ")), "{out}");
            // The state inside the envelope is confirmed at the observed height.
            assert!(out.contains(&format!(" {reveal_height} ")), "{out}");
        }
    }
}
