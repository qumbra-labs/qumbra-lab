//! `qumbra-ffi` — the wallet kernel over a hand-written C ABI (issue #246
//! rung A). The Swift shell calls exactly what `include/qumbra_ffi.h`
//! declares; that header is hand-maintained beside this file and a test pins
//! the two to the same function list.
//!
//! # ABI rules, all load-bearing
//!
//! - **Opaque handle.** `QmbWallet*` is a `Box<WalletState>`; key material
//!   never crosses as a side effect. The phrase comes back through exactly one
//!   function (`qmb_wallet_reveal_mnemonic`) — the CLI's `backup --reveal`
//!   discipline at the ABI layer.
//! - **The platform sources entropy.** `qmb_wallet_from_entropy` takes 32
//!   bytes from the caller (SecRandomCopyBytes on iOS); this crate never
//!   invents a seed, so the RNG audit trail is the platform's own.
//! - **Every returned `char*` is freed by `qmb_string_free`**, nothing else.
//!   Every constructor's failure returns NULL with a reason in `err_out`
//!   (also a `qmb_string_free` string).
//! - **Strings in are UTF-8, NUL-terminated; strings out are UTF-8.**
//! - **The scan report crosses pre-rendered** ([`report`]) — Swift colors
//!   words, it never re-derives a verdict.

pub mod report;

use std::collections::VecDeque;
use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;

use qlab_note::kem::Dk;

use qlab_cbserver::client::{
    light_client_scan, light_client_scan_with, ScanConfig, ScanDriver, ScanDriverStep,
    ScanOutcome,
};
use qlab_cbserver::tree::CommitmentTree;
use qlab_wallet::address::Address;
use qlab_wallet::uri::bessel_to_qmb;
use qumbra_wallet::bundle::WitnessBundle;
use qumbra_wallet::driver::{SelectDriver, SelectEndpoint, SelectStep};
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qlab_wallet::Wallet;
use rand::rngs::StdRng;
use rand::SeedableRng;

use report::DivScan;

/// The opaque wallet state behind `QmbWallet*`.
pub struct WalletState {
    seed: MasterSeed,
    wallet: Wallet,
}

/// The HD account, same constant and same reasoning as the CLI's.
const HD_ACCOUNT: u32 = 0;

fn into_handle(seed: MasterSeed) -> *mut WalletState {
    let wallet = Wallet::from_master_seed(&seed, HD_ACCOUNT);
    Box::into_raw(Box::new(WalletState { seed, wallet }))
}

fn out_string(s: String) -> *mut c_char {
    // A NUL inside would truncate; no payload here legitimately contains one.
    CString::new(s).map(CString::into_raw).unwrap_or(ptr::null_mut())
}

fn set_err(err_out: *mut *mut c_char, msg: String) {
    if !err_out.is_null() {
        unsafe { *err_out = out_string(msg) };
    }
}

/// Create a wallet from 32 platform-sourced entropy bytes. Never NULL for a
/// non-NULL input.
///
/// # Safety
/// `entropy32` must point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_from_entropy(entropy32: *const u8) -> *mut WalletState {
    if entropy32.is_null() {
        return ptr::null_mut();
    }
    let mut entropy = [0u8; ENTROPY_LEN];
    entropy.copy_from_slice(std::slice::from_raw_parts(entropy32, ENTROPY_LEN));
    into_handle(MasterSeed::from_entropy(entropy))
}

/// Restore from a Qumbra mnemonic. NULL + `err_out` on refusal — and the
/// refusal names the one fact that matters: this wordlist is deliberately
/// NOT BIP-39 (lab PR #44), and near-matches are not guessed at.
///
/// # Safety
/// `phrase` must be a valid NUL-terminated UTF-8 string; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_restore(
    phrase: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut WalletState {
    if phrase.is_null() {
        set_err(err_out, "phrase is NULL".into());
        return ptr::null_mut();
    }
    let phrase = match CStr::from_ptr(phrase).to_str() {
        Ok(p) => p.trim(),
        Err(_) => {
            set_err(err_out, "phrase is not UTF-8".into());
            return ptr::null_mut();
        }
    };
    match MasterSeed::from_mnemonic(phrase) {
        Ok(seed) => into_handle(seed),
        Err(e) => {
            set_err(
                err_out,
                format!(
                    "not a Qumbra mnemonic ({e:?}). Qumbra's wordlist is deliberately NOT \
                     BIP-39 — a phrase from another wallet cannot restore here."
                ),
            );
            ptr::null_mut()
        }
    }
}

/// Re-open from persisted parts (the Keychain handshake): the version byte and
/// 32 entropy bytes `qmb_wallet_seed_*` returned earlier. An unknown version
/// is refused with a reason, never guessed at.
///
/// # Safety
/// `entropy32` must point to 32 readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_from_parts(
    version: u8,
    entropy32: *const u8,
    err_out: *mut *mut c_char,
) -> *mut WalletState {
    if entropy32.is_null() {
        set_err(err_out, "entropy is NULL".into());
        return ptr::null_mut();
    }
    let mut entropy = [0u8; ENTROPY_LEN];
    entropy.copy_from_slice(std::slice::from_raw_parts(entropy32, ENTROPY_LEN));
    // The version gate, explicit. A mnemonic round-trip does NOT check this —
    // the phrase carries entropy+checksum only, and the version byte is a
    // derivation-domain separator: a wrong byte silently derives a DIFFERENT
    // wallet, which a user reads as vanished funds. Refuse by comparison.
    if version != qlab_wallet::seed::SEED_VERSION {
        set_err(
            err_out,
            format!(
                "stored seed version {version} refused: this binary derives at version {} \
                 only, and a different byte would silently derive a different wallet.",
                qlab_wallet::seed::SEED_VERSION
            ),
        );
        return ptr::null_mut();
    }
    into_handle(MasterSeed::with_version(version, entropy))
}

/// # Safety
/// `w` must be a live handle from a constructor; never used after this call.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_free(w: *mut WalletState) {
    if !w.is_null() {
        drop(Box::from_raw(w));
    }
}

/// Allocate `len` bytes inside the module for a CALLER to write inputs into
/// (phrases, URLs) before calling the ABI — the WASM host has no other way to
/// hand us a string. Pair with [`qmb_dealloc`]; unrelated to
/// [`qmb_string_free`], which frees OUR strings.
#[no_mangle]
pub extern "C" fn qmb_alloc(len: usize) -> *mut u8 {
    let mut v: Vec<u8> = Vec::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `p` must come from [`qmb_alloc`] with the same `len`; never used after.
#[no_mangle]
pub unsafe extern "C" fn qmb_dealloc(p: *mut u8, len: usize) {
    if !p.is_null() {
        drop(Vec::from_raw_parts(p, len.max(1), len.max(1)));
    }
}

/// # Safety
/// `s` must be a string returned by this library; never used after this call.
#[no_mangle]
pub unsafe extern "C" fn qmb_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// The ONLY function that returns key material — the explicit reveal.
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_reveal_mnemonic(w: *const WalletState) -> *mut c_char {
    if w.is_null() {
        return ptr::null_mut();
    }
    out_string((*w).seed.to_mnemonic())
}

/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_seed_version(w: *const WalletState) -> u8 {
    if w.is_null() {
        return u8::MAX;
    }
    (*w).seed.version()
}

/// Copy the 32 entropy bytes into `out32` — for the platform's sealed storage
/// (Keychain under a Secure-Enclave-wrapped key; rung C's business).
///
/// # Safety
/// `w` live; `out32` points to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_seed_entropy(w: *const WalletState, out32: *mut u8) {
    if w.is_null() || out32.is_null() {
        return;
    }
    std::slice::from_raw_parts_mut(out32, ENTROPY_LEN).copy_from_slice((*w).seed.entropy());
}

/// The full bech32m address at a diversifier index (`qaddr1…`, ~2.2 KB).
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_address(w: *const WalletState, index: u64) -> *mut c_char {
    if w.is_null() {
        return ptr::null_mut();
    }
    out_string((*w).wallet.address_at_index(index).encode())
}

/// The short address (`qs1…`) — the human-facing default.
///
/// # Safety
/// `w` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_address_short(
    w: *const WalletState,
    index: u64,
) -> *mut c_char {
    if w.is_null() {
        return ptr::null_mut();
    }
    out_string((*w).wallet.address_at_index(index).short().encode())
}

/// Fetch one scan path — **the transport the shell owns**.
///
/// Exists because the edge is https-only and this crate's socket path is
/// plaintext-only, deliberately (issue #297: TLS in `qlab-cbserver` would link
/// rustls into `qlab-node`, and so into the consensus node). Rather than give
/// iOS its own rustls, the shell lends its transport: `URLSession` on iOS gets
/// https and App Transport Security from the platform, exactly as
/// `qmb_wallet_from_entropy` takes entropy from the platform instead of
/// inventing it. Same argument, different resource.
///
/// Return `0` on success, having stored the body in `*out_body` / `*out_len`.
/// Ownership **transfers to this crate**, which releases it with `free` — so
/// the buffer must come from `malloc` (Swift: `malloc`, or
/// `UnsafeMutableRawPointer.allocate` is NOT interchangeable here).
///
/// Return nonzero on failure, optionally storing a NUL-terminated reason in
/// `*out_err` under the same `malloc`/`free` contract. A failed path is one
/// `Err` inside the scan, which the report renders as UNAVAILABLE rather than
/// as a zero — the whole point of the discipline this ABI serves.
pub type QmbFetchFn = unsafe extern "C" fn(
    ctx: *mut c_void,
    path_and_query: *const c_char,
    out_body: *mut *mut u8,
    out_len: *mut usize,
    out_err: *mut *mut c_char,
) -> i32;

// Declared rather than pulled in via the `libc` crate: this crate is a
// hand-written ABI whose whole claim is that it can be read line by line, and
// one symbol is cheaper to audit than a dependency edge. Same allocator as
// Swift's `malloc` on every Apple platform.
extern "C" {
    fn free(p: *mut c_void);
}

/// The scan, over a caller-supplied transport. `source_label` is what the
/// report NAMES as its source — this crate no longer knows the transport, so
/// it cannot infer it, and a report must say where its numbers came from.
///
/// Otherwise identical to [`qmb_wallet_scan_report`], and provably so: both
/// route into `light_client_scan_with`, so "detected", "opened" and
/// "unopened" cannot drift between the two paths.
///
/// # Safety
/// `w` live; `source_label` NUL-terminated UTF-8; `indices` points to
/// `n_indices` u64s; `rng_seed32` points to 32 readable bytes; `fetch` obeys
/// the contract on [`QmbFetchFn`].
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_scan_report_over_fetch(
    w: *const WalletState,
    source_label: *const c_char,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
) -> *mut c_char {
    if w.is_null() || source_label.is_null() || indices.is_null() || rng_seed32.is_null() {
        return ptr::null_mut();
    }
    let Some(fetch) = fetch else { return ptr::null_mut() };
    let label = match CStr::from_ptr(source_label).to_str() {
        Ok(u) => u,
        Err(_) => return ptr::null_mut(),
    };
    let idxs = std::slice::from_raw_parts(indices, n_indices);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));
    let mut rng = StdRng::from_seed(seed);

    // Bridge the C callback to the closure `light_client_scan_with` wants. A
    // failed fetch becomes an Err(String), which is exactly the contract the
    // socket path produces — so the report cannot tell the two apart, and a
    // transport failure never reads as an empty wallet.
    let mut bridge = |path: &str| -> Result<Vec<u8>, String> {
        let c_path = CString::new(path).map_err(|_| "path contains NUL".to_string())?;
        let mut body: *mut u8 = ptr::null_mut();
        let mut len: usize = 0;
        let mut err: *mut c_char = ptr::null_mut();
        let rc = fetch(fetch_ctx, c_path.as_ptr(), &mut body, &mut len, &mut err);
        if rc != 0 {
            let reason = if err.is_null() {
                format!("fetch failed (rc {rc})")
            } else {
                let s = CStr::from_ptr(err).to_string_lossy().into_owned();
                free(err as *mut c_void);
                s
            };
            if !body.is_null() {
                free(body as *mut c_void);
            }
            return Err(reason);
        }
        if body.is_null() {
            return Err("fetch reported success with no body".to_string());
        }
        let out = std::slice::from_raw_parts(body, len).to_vec();
        free(body as *mut c_void);
        Ok(out)
    };

    let state = &*w;
    let mut scans = Vec::with_capacity(n_indices);
    for &idx in idxs {
        let d = state.wallet.diversifier_at_index(idx);
        let kp = state.wallet.diversified_keypair(&d);
        let short = state.wallet.address_at_index(idx).short().encode();
        match light_client_scan_with(&mut bridge, &kp.dk, from, to, ScanConfig::default(), &mut rng)
        {
            Ok(outcome) => scans.push(DivScan::from_outcome(idx, short, &outcome)),
            Err(e) => scans.push(DivScan {
                index: idx,
                address_short: short,
                completeness: qlab_cbserver::client::Completeness::Complete,
                spendable_bessel: 0,
                shadowed_bessel: 0,
                never_started: Some(e.to_string()),
            }),
        }
    }
    out_string(report::render(&scans, (from, to), label))
}

/// Run the light-client scan for `indices` against `base_url` over
/// `[from, to]` and return the rendered report ([`report::render`] — the
/// UNAVAILABLE discipline, no partial totals). Blocking; the shell calls it
/// off the main thread. `rng_seed32` seeds the decoy rng (platform CSPRNG —
/// decoys are a privacy mechanism, so their randomness is platform-audited
/// too).
///
/// # Safety
/// `w` live; `base_url` NUL-terminated UTF-8; `indices` points to `n_indices`
/// u64s; `rng_seed32` points to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_scan_report(
    w: *const WalletState,
    base_url: *const c_char,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
) -> *mut c_char {
    if w.is_null() || base_url.is_null() || indices.is_null() || rng_seed32.is_null() {
        return ptr::null_mut();
    }
    let url = match CStr::from_ptr(base_url).to_str() {
        Ok(u) => u,
        Err(_) => return ptr::null_mut(),
    };
    let idxs = std::slice::from_raw_parts(indices, n_indices);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));
    let mut rng = StdRng::from_seed(seed);

    let state = &*w;
    let mut scans = Vec::with_capacity(n_indices);
    for &idx in idxs {
        let d = state.wallet.diversifier_at_index(idx);
        let kp = state.wallet.diversified_keypair(&d);
        let short = state.wallet.address_at_index(idx).short().encode();
        match light_client_scan(url, &kp.dk, from, to, ScanConfig::default(), &mut rng) {
            Ok(outcome) => scans.push(DivScan::from_outcome(idx, short, &outcome)),
            Err(e) => scans.push(DivScan {
                index: idx,
                address_short: short,
                completeness: qlab_cbserver::client::Completeness::Complete,
                spendable_bessel: 0,
                shadowed_bessel: 0,
                never_started: Some(e.to_string()),
            }),
        }
    }
    out_string(report::render(&scans, (from, to), url))
}

/* --- the pumpable scan (issue #395) --------------------------------------- */

/// The caller-pumped scan behind `qmb_scan_*` — the browser/WASM shell's path.
///
/// #344's [`qmb_wallet_scan_report_over_fetch`] hands the transport to the
/// shell but calls it SYNCHRONOUSLY, and a browser has no synchronous fetch to
/// put behind that callback. This wrapper inverts control the rest of the way:
/// it owns #350's sans-I/O [`ScanDriver`] (one per diversifier, created in
/// index order) plus the caller-seeded [`StdRng`], and the shell alternates
/// [`qmb_scan_step`] with [`qmb_scan_supply`]/[`qmb_scan_supply_err`] from any
/// async transport. All three scan paths still route into the ONE
/// orchestration, so detected/opened/unopened cannot drift.
///
/// A per-index driver failure folds to the same `never_started` verdict the
/// sync paths produce — one diversifier's transport failure is its verdict,
/// never the report's zero.
pub struct ScanState {
    label: String,
    from: u64,
    to: u64,
    rng: StdRng,
    queue: VecDeque<(u64, String, Dk)>,
    current: Option<(u64, String, ScanDriver)>,
    scans: Vec<DivScan>,
    // Completed outcomes, retained for a subsequent select (lab #400): the
    // notes themselves, not just the rendered verdicts. `qmb_select_new`
    // takes them (a select consumes the scan).
    outcomes: Vec<(u64, ScanOutcome)>,
    done: bool,
}

/// Start a pumped scan over `indices` in `[from, to]`. NULL on NULL/invalid
/// args. `source_label` is what the report NAMES as its source (this library
/// never sees the transport). `rng_seed32` seeds the decoy rng — 32
/// platform-sourced bytes, as everywhere in this ABI.
///
/// # Safety
/// `w` live; `source_label` NUL-terminated UTF-8; `indices` points to
/// `n_indices` u64s; `rng_seed32` points to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn qmb_scan_new(
    w: *const WalletState,
    source_label: *const c_char,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
) -> *mut ScanState {
    if w.is_null() || source_label.is_null() || indices.is_null() || rng_seed32.is_null() {
        return ptr::null_mut();
    }
    let label = match CStr::from_ptr(source_label).to_str() {
        Ok(u) => u.to_string(),
        Err(_) => return ptr::null_mut(),
    };
    let idxs = std::slice::from_raw_parts(indices, n_indices);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));

    let state = &*w;
    let mut queue: VecDeque<(u64, String, Dk)> = idxs
        .iter()
        .map(|&idx| {
            let d = state.wallet.diversifier_at_index(idx);
            let kp = state.wallet.diversified_keypair(&d);
            let short = state.wallet.address_at_index(idx).short().encode();
            (idx, short, kp.dk)
        })
        .collect();
    // The first driver exists from birth, so a response supplied before any
    // step lands in the driver's own "without requesting a path" fault
    // instead of vanishing.
    let current = queue.pop_front().map(|(idx, short, dk)| {
        (idx, short, ScanDriver::new(dk, from, to, ScanConfig::default()))
    });
    Box::into_raw(Box::new(ScanState {
        label,
        from,
        to,
        rng: StdRng::from_seed(seed),
        queue,
        current,
        scans: Vec::new(),
        outcomes: Vec::new(),
        done: false,
    }))
}

/// Pump the scan one observation forward.
///
/// Returns `1` — NEED: `*out` is the path to fetch; answer it with
/// [`qmb_scan_supply`] or [`qmb_scan_supply_err`], then step again. Returns
/// `0` — DONE: `*out` is the rendered report and the handle answers `-1` from
/// here on (the report crosses once). Returns `-1` on a NULL/finished handle
/// or NULL `out`. `*out` strings are freed with `qmb_string_free`.
///
/// # Safety
/// `s` live (or NULL); `out` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_scan_step(s: *mut ScanState, out: *mut *mut c_char) -> i32 {
    if s.is_null() || out.is_null() {
        return -1;
    }
    let st = &mut *s;
    if st.done {
        return -1;
    }
    loop {
        let step = match st.current.as_mut() {
            None => match st.queue.pop_front() {
                Some((idx, short, dk)) => {
                    st.current =
                        Some((idx, short, ScanDriver::new(dk, st.from, st.to, ScanConfig::default())));
                    continue;
                }
                None => {
                    st.done = true;
                    *out = out_string(report::render(&st.scans, (st.from, st.to), &st.label));
                    return 0;
                }
            },
            Some((_, _, driver)) => driver.step(&mut st.rng),
        };
        match step {
            ScanDriverStep::Need(path) => {
                *out = out_string(path);
                return 1;
            }
            ScanDriverStep::Done(outcome) => {
                let (idx, short, _) = st.current.take().expect("stepped without a driver");
                st.scans.push(DivScan::from_outcome(idx, short, &outcome));
                st.outcomes.push((idx, outcome));
            }
            ScanDriverStep::Failed(err) => {
                let (idx, short, _) = st.current.take().expect("stepped without a driver");
                st.scans.push(DivScan {
                    index: idx,
                    address_short: short,
                    completeness: qlab_cbserver::client::Completeness::Complete,
                    spendable_bessel: 0,
                    shadowed_bessel: 0,
                    never_started: Some(err),
                });
            }
        }
    }
}

/// Answer the outstanding NEED with the fetched bytes. The bytes are COPIED —
/// the caller keeps ownership of its buffer (same inbound convention as
/// `qmb_wallet_from_entropy`; a WASM host passes a `qmb_alloc` buffer and
/// `qmb_dealloc`s it afterwards). A NULL body is folded to a transport error,
/// never a decode of nothing.
///
/// # Safety
/// `s` live (or NULL); `body` points to `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_scan_supply(s: *mut ScanState, body: *const u8, len: usize) {
    if s.is_null() {
        return;
    }
    let st = &mut *s;
    let response = if body.is_null() {
        Err("supplied body is NULL".to_string())
    } else {
        Ok(std::slice::from_raw_parts(body, len).to_vec())
    };
    if let Some((_, _, driver)) = st.current.as_mut() {
        driver.supply(response);
    }
}

/// Answer the outstanding NEED with a transport failure. The reason survives
/// into the report (UNAVAILABLE discipline — a transport failure never reads
/// as a zero balance).
///
/// # Safety
/// `s` live (or NULL); `reason` NUL-terminated (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_scan_supply_err(s: *mut ScanState, reason: *const c_char) {
    if s.is_null() {
        return;
    }
    let st = &mut *s;
    let reason = if reason.is_null() {
        "transport failed with no reason".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().into_owned()
    };
    if let Some((_, _, driver)) = st.current.as_mut() {
        driver.supply(Err(reason));
    }
}

/// # Safety
/// `s` must be a live handle from [`qmb_scan_new`]; never used after this call.
#[no_mangle]
pub unsafe extern "C" fn qmb_scan_free(s: *mut ScanState) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}



/// The full address at `index`, as a QR code in SVG — for the Receive screen.
/// Rendered by `qumbra_wallet::qr` (#342's one renderer: EC-L, capacity
/// boundary test-locked; a full qaddr fits v40 with room). 🔴 The caller MUST
/// show the `qs1…` fingerprint beside it — a QR that merely scans is not a
/// verified address (#342 D3). NULL + `err_out` if the payload cannot fit.
///
/// # Safety
/// `w` live; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_address_qr_svg(
    w: *const WalletState,
    index: u64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if w.is_null() {
        set_err(err_out, "wallet is NULL".into());
        return ptr::null_mut();
    }
    let full = (*w).wallet.address_at_index(index).encode();
    match qumbra_wallet::qr::render_svg(&full) {
        Ok(svg) => out_string(svg),
        Err(e) => {
            set_err(err_out, format!("QR refused: {e:?}"));
            ptr::null_mut()
        }
    }
}

/* --- the pumpable select + the witness bundle (lab #400) ------------------ */

/// The caller-pumped phase 1 behind `qmb_select_*` — the browser shell's half
/// of a spend. Born from a FINISHED scan's outcomes (`qmb_select_new` consumes
/// them), pumps `qumbra_wallet::driver::SelectDriver`, and finishes as the
/// serialized `WitnessBundle` the native prover host takes. Key material stays
/// inside the bundle bytes — the review below is the ONLY rendered view, and
/// it exposes the named public facts and nothing else.
pub struct SelectState {
    driver: SelectDriver,
    rng: StdRng,
    bundle: Option<Vec<u8>>,
}

/// Start a select over the outcomes a finished `qmb_scan_t` holds. NULL +
/// `err_out` on refusal — an unfinished or partially-failed scan is refused by
/// name (a spend cannot be built on partial knowledge), and the scan handle's
/// outcomes are CONSUMED (scan again for another select). `held_leaves` is the
/// caller's cached commitment-tree leaves (concatenated 32-byte cms, append
/// order; NULL/0 on first use); `recipient` is the full `qaddr1…` address.
///
/// # Safety
/// `w` and `scan` live; `recipient` NUL-terminated UTF-8; `held_leaves` points
/// to `held_len` readable bytes when non-NULL; `rng_seed32` points to 32
/// readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_select_new(
    w: *const WalletState,
    scan: *mut ScanState,
    recipient: *const c_char,
    amount: u64,
    held_leaves: *const u8,
    held_len: usize,
    rng_seed32: *const u8,
    err_out: *mut *mut c_char,
) -> *mut SelectState {
    if w.is_null() || scan.is_null() || recipient.is_null() || rng_seed32.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    if held_leaves.is_null() && held_len != 0 {
        set_err(err_out, "held_leaves is NULL but held_len is not 0".into());
        return ptr::null_mut();
    }
    if held_len % 32 != 0 {
        set_err(err_out, format!("held_leaves length {held_len} is not a multiple of 32"));
        return ptr::null_mut();
    }
    let scan_state = &mut *scan;
    if !scan_state.done {
        set_err(
            err_out,
            "the scan has not finished — pump it to DONE before selecting".into(),
        );
        return ptr::null_mut();
    }
    if let Some(failed) = scan_state.scans.iter().find(|d| d.never_started.is_some()) {
        set_err(
            err_out,
            format!(
                "index {}'s scan never started — a spend cannot be built on partial knowledge; \
                 scan again",
                failed.index
            ),
        );
        return ptr::null_mut();
    }
    if scan_state.outcomes.is_empty() {
        set_err(err_out, "the scan holds no outcomes — it was already consumed; scan again".into());
        return ptr::null_mut();
    }
    let recipient = match CStr::from_ptr(recipient).to_str().ok().and_then(Address::decode) {
        Some(a) => a,
        None => {
            set_err(err_out, "recipient address did not decode (a full qaddr1… is required)".into());
            return ptr::null_mut();
        }
    };
    let mut held = CommitmentTree::new();
    if held_len > 0 {
        for chunk in std::slice::from_raw_parts(held_leaves, held_len).chunks_exact(32) {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(chunk);
            held.append_bytes(&cm);
        }
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));

    let outcomes = std::mem::take(&mut scan_state.outcomes);
    let to = scan_state.to;
    let driver =
        SelectDriver::new((*w).wallet.clone(), recipient, amount, None, outcomes, held, to);
    Box::into_raw(Box::new(SelectState {
        driver,
        rng: StdRng::from_seed(seed),
        bundle: None,
    }))
}

/// Pump the selection one observation forward.
///
/// Returns `1` — NEED from the SCAN endpoint (`*out` = path); `2` — NEED from
/// the NODE endpoint (`*out` = path; one host normally serves both, the code
/// still says which contract the path belongs to); `0` — DONE: take the bytes
/// with `qmb_select_take_bundle`; `-2` — FAILED by name (`*out` = the reason);
/// `-1` — NULL/invalid call. `*out` strings are freed with `qmb_string_free`.
///
/// # Safety
/// `s` live (or NULL); `out` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_select_step(s: *mut SelectState, out: *mut *mut c_char) -> i32 {
    if s.is_null() || out.is_null() {
        return -1;
    }
    let st = &mut *s;
    if st.bundle.is_some() {
        return 0;
    }
    match st.driver.step(&mut st.rng) {
        SelectStep::Need { endpoint, path } => {
            *out = out_string(path);
            match endpoint {
                SelectEndpoint::Scan => 1,
                SelectEndpoint::Node => 2,
            }
        }
        SelectStep::Done(bundle) => {
            st.bundle = Some(bundle.to_bytes());
            0
        }
        SelectStep::Failed(why) => {
            *out = out_string(why);
            -2
        }
    }
}

/// Answer the outstanding NEED with the fetched bytes (COPIED — the caller
/// keeps its buffer, same convention as `qmb_scan_supply`).
///
/// # Safety
/// `s` live (or NULL); `body` points to `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_select_supply(s: *mut SelectState, body: *const u8, len: usize) {
    if s.is_null() {
        return;
    }
    let response = if body.is_null() {
        Err("supplied body is NULL".to_string())
    } else {
        Ok(std::slice::from_raw_parts(body, len).to_vec())
    };
    (*s).driver.supply(response);
}

/// Answer the outstanding NEED with a transport failure — it becomes the same
/// named refusal the CLI produces.
///
/// # Safety
/// `s` live (or NULL); `reason` NUL-terminated (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_select_supply_err(s: *mut SelectState, reason: *const c_char) {
    if s.is_null() {
        return;
    }
    let reason = if reason.is_null() {
        "transport failed with no reason".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().into_owned()
    };
    (*s).driver.supply(Err(reason));
}

/// Take the serialized witness bundle after DONE — crosses ONCE; NULL before
/// DONE or on a second take. The buffer is released with `qmb_dealloc(p, len)`.
/// The bytes carry spending-key material: hand them to the native prover host
/// and nowhere else, and discard them once the transaction is accepted or
/// known-duplicate.
///
/// # Safety
/// `s` live (or NULL); `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_select_take_bundle(
    s: *mut SelectState,
    out_len: *mut usize,
) -> *mut u8 {
    if s.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    match (*s).bundle.take() {
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
/// `s` must be a live handle from `qmb_select_new`; never used after this call.
#[no_mangle]
pub unsafe extern "C" fn qmb_select_free(s: *mut SelectState) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Render the approval review from DECODED bundle bytes — what the popup shows
/// before "Approve" reads the artifact that will be proved, never form state
/// (the task book's §1.5-2). NULL + `err_out` on a bundle that fails decode or
/// its semantic checks, by name. Only the named public facts are rendered;
/// witness and key bytes never cross.
///
/// # Safety
/// `bytes` points to `len` readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_bundle_review(
    bytes: *const u8,
    len: usize,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if bytes.is_null() {
        set_err(err_out, "bundle bytes are NULL".into());
        return ptr::null_mut();
    }
    let raw = std::slice::from_raw_parts(bytes, len);
    let bundle = match WitnessBundle::from_bytes(raw) {
        Ok(b) => b,
        Err(e) => {
            set_err(err_out, format!("witness bundle refused: {e:?}"));
            return ptr::null_mut();
        }
    };
    let inputs = if bundle.used_dummy() { "1 real + 1 dummy slot" } else { "2 real" };
    out_string(format!(
        "send {} QMB to {}\n  fee:    {} QMB\n  change: {} QMB (returns to this wallet)\n  \
         inputs: {}\n  anchor: selected at chain tip {}\n",
        bessel_to_qmb(bundle.amount()),
        bundle.recipient_short(),
        bessel_to_qmb(bundle.fee()),
        bessel_to_qmb(bundle.change_value()),
        inputs,
        bundle.selected_at_tip(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The shell's side of the fetch contract, exercised for real: malloc'd
    // buffers handed over to the library. Deliberately NOT CString::into_raw —
    // that is Rust's allocator, and this library releases with free(), so
    // mixing them would be undefined behaviour. Swift has the same trap
    // (`malloc`, not `UnsafeMutableRawPointer.allocate`), which is why the
    // header says so and why the test demonstrates it rather than describing it.
    extern "C" {
        fn malloc(n: usize) -> *mut c_void;
    }

    unsafe fn malloc_copy(bytes: &[u8]) -> *mut u8 {
        let p = malloc(bytes.len().max(1)) as *mut u8;
        assert!(!p.is_null());
        ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        p
    }

    /// A transport that always fails, the way a phone with no signal does.
    unsafe extern "C" fn fetch_always_fails(
        ctx: *mut c_void,
        _path: *const c_char,
        _out_body: *mut *mut u8,
        _out_len: *mut usize,
        out_err: *mut *mut c_char,
    ) -> i32 {
        if !ctx.is_null() {
            *(ctx as *mut u32) += 1; // count the calls
        }
        let msg = b"the network is unreachable\0";
        *out_err = malloc_copy(msg) as *mut c_char;
        1
    }

    /// A transport that succeeds but answers with bytes that are not a compact
    /// range — a wrong server, or an edge that returned an error page with 200.
    unsafe extern "C" fn fetch_returns_garbage(
        _ctx: *mut c_void,
        _path: *const c_char,
        out_body: *mut *mut u8,
        out_len: *mut usize,
        _out_err: *mut *mut c_char,
    ) -> i32 {
        let junk = b"<html>404 not found</html>";
        *out_body = malloc_copy(junk);
        *out_len = junk.len();
        0
    }

    unsafe fn scan_over_fetch(f: QmbFetchFn, ctx: *mut c_void) -> String {
        let entropy = [7u8; 32];
        let w = qmb_wallet_from_entropy(entropy.as_ptr());
        assert!(!w.is_null());
        let label = CString::new("https://seed.example.org").unwrap();
        let indices: [u64; 1] = [0];
        let seed = [3u8; 32];
        let out = qmb_wallet_scan_report_over_fetch(
            w,
            label.as_ptr(),
            0,
            10,
            indices.as_ptr(),
            1,
            seed.as_ptr(),
            Some(f),
            ctx,
        );
        assert!(!out.is_null());
        let s = CStr::from_ptr(out).to_str().unwrap().to_string();
        qmb_string_free(out);
        qmb_wallet_free(w);
        s
    }

    /// A transport failure must reach the report as UNAVAILABLE carrying the
    /// shell's own reason — never as a zero. This is the same guarantee the
    /// socket path gives; routing through a caller-supplied transport must not
    /// weaken it, because the shell's transport is the likelier one to fail.
    #[test]
    fn a_failed_shell_transport_renders_unavailable_and_never_a_zero() {
        unsafe {
            let mut calls: u32 = 0;
            let report = scan_over_fetch(fetch_always_fails, &mut calls as *mut u32 as *mut c_void);

            assert!(calls > 0, "the library must actually use the shell's transport");
            assert!(report.contains("UNAVAILABLE"), "{report}");
            assert!(
                report.contains("the network is unreachable"),
                "the shell's own reason must survive into the report: {report}"
            );
            assert!(
                !report.contains("TOTAL spendable: 0"),
                "a transport failure must never render as an empty wallet: {report}"
            );
            // And it must name where it was pointed, since the library can no
            // longer infer the transport.
            assert!(report.contains("https://seed.example.org"), "{report}");
        }
    }

    /// 200-with-nonsense is the failure mode an https edge actually produces —
    /// a captive portal, a proxy error page, the wrong host. It must refuse,
    /// not decode into a confident zero.
    #[test]
    fn a_successful_fetch_of_garbage_is_refused_not_believed() {
        unsafe {
            let report = scan_over_fetch(fetch_returns_garbage, ptr::null_mut());
            assert!(report.contains("UNAVAILABLE"), "{report}");
            assert!(
                !report.contains("TOTAL spendable: 0"),
                "unparseable bytes must not become a zero balance: {report}"
            );
        }
    }

    /// A NULL callback is a programming error in the shell, not a reason to
    /// scan nothing and report success.
    #[test]
    fn a_missing_transport_returns_null_rather_than_an_empty_report() {
        unsafe {
            let entropy = [7u8; 32];
            let w = qmb_wallet_from_entropy(entropy.as_ptr());
            let label = CString::new("http://unused").unwrap();
            let indices: [u64; 1] = [0];
            let seed = [3u8; 32];
            let out = qmb_wallet_scan_report_over_fetch(
                w,
                label.as_ptr(),
                0,
                1,
                indices.as_ptr(),
                1,
                seed.as_ptr(),
                None,
                ptr::null_mut(),
            );
            assert!(out.is_null(), "no transport means no report, not an empty one");
            qmb_wallet_free(w);
        }
    }

    /// Call the ABI the way Swift will: raw pointers, C strings, explicit frees.
    #[test]
    fn the_abi_roundtrips_create_reveal_restore_and_addresses() {
        unsafe {
            let entropy = [9u8; 32];
            let w1 = qmb_wallet_from_entropy(entropy.as_ptr());
            assert!(!w1.is_null());

            let a1 = qmb_wallet_address(w1, 0);
            let a1s = CStr::from_ptr(a1).to_str().unwrap().to_string();
            assert!(a1s.starts_with("qaddr1"), "{a1s}");
            let s1 = qmb_wallet_address_short(w1, 0);
            assert!(CStr::from_ptr(s1).to_str().unwrap().starts_with("qs1"));

            let phrase_ptr = qmb_wallet_reveal_mnemonic(w1);
            let phrase = CStr::from_ptr(phrase_ptr).to_str().unwrap().to_string();

            let mut err: *mut c_char = ptr::null_mut();
            let cphrase = CString::new(phrase).unwrap();
            let w2 = qmb_wallet_restore(cphrase.as_ptr(), &mut err);
            assert!(!w2.is_null(), "restore failed");
            assert!(err.is_null());
            let a2 = qmb_wallet_address(w2, 0);
            assert_eq!(CStr::from_ptr(a2).to_str().unwrap(), a1s, "same seed, same address 0");

            // The Keychain handshake: parts out, wallet back.
            let ver = qmb_wallet_seed_version(w1);
            let mut ent = [0u8; 32];
            qmb_wallet_seed_entropy(w1, ent.as_mut_ptr());
            assert_eq!(ent, entropy);
            let w3 = qmb_wallet_from_parts(ver, ent.as_ptr(), &mut err);
            assert!(!w3.is_null());

            for p in [a1, s1, a2, phrase_ptr] {
                qmb_string_free(p);
            }
            qmb_wallet_free(w1);
            qmb_wallet_free(w2);
            qmb_wallet_free(w3);
        }
    }

    #[test]
    fn a_bip39_phrase_is_refused_across_the_abi_with_the_reason() {
        unsafe {
            let mut err: *mut c_char = ptr::null_mut();
            let phrase = CString::new(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about",
            )
            .unwrap();
            let w = qmb_wallet_restore(phrase.as_ptr(), &mut err);
            assert!(w.is_null());
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_str().unwrap();
            assert!(msg.contains("NOT BIP-39"), "{msg}");
            qmb_string_free(err);
        }
    }

    #[test]
    fn an_unknown_stored_version_is_refused_at_open() {
        unsafe {
            let mut err: *mut c_char = ptr::null_mut();
            let ent = [1u8; 32];
            let w = qmb_wallet_from_parts(0xEE, ent.as_ptr(), &mut err);
            assert!(w.is_null());
            assert!(!err.is_null());
            let msg = CStr::from_ptr(err).to_str().unwrap();
            assert!(msg.contains("version 238 refused"), "{msg}");
            qmb_string_free(err);
        }
    }

    #[test]
    fn a_dead_endpoint_scans_to_the_named_verdict_across_the_abi() {
        unsafe {
            let w = qmb_wallet_from_entropy([3u8; 32].as_ptr());
            let url = CString::new("http://127.0.0.1:1").unwrap();
            let idxs = [0u64];
            let seed = [4u8; 32];
            let r = qmb_wallet_scan_report(w, url.as_ptr(), 0, 8, idxs.as_ptr(), 1, seed.as_ptr());
            assert!(!r.is_null());
            let report = CStr::from_ptr(r).to_str().unwrap();
            assert!(report.contains("never started"), "{report}");
            assert!(report.contains(report::UNAVAILABLE));
            qmb_string_free(r);
            qmb_wallet_free(w);
        }
    }

    /* --- the pumpable scan (issue #395) ---------------------------------- */

    unsafe fn take_out(out: *mut c_char) -> String {
        assert!(!out.is_null());
        let s = CStr::from_ptr(out).to_str().unwrap().to_string();
        qmb_string_free(out);
        s
    }

    unsafe fn pump_new(w: *const WalletState, indices: &[u64]) -> *mut ScanState {
        let label = CString::new("https://seed.example.org").unwrap();
        let seed = [3u8; 32];
        qmb_scan_new(w, label.as_ptr(), 0, 10, indices.as_ptr(), indices.len(), seed.as_ptr())
    }

    /// The pump's first NEED is the compact page — the same path vocabulary
    /// #358's request-path goldens pin, now visible across the ABI.
    #[test]
    fn the_pump_first_asks_for_the_compact_page() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0]);
            assert!(!s.is_null());
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out), 1);
            assert_eq!(take_out(out), "/v1/compact?from=0&to=10");
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// A transport failure supplied by the pump must reach the report as
    /// UNAVAILABLE carrying the shell's own reason — never as a zero. Same
    /// guarantee as the sync paths; the pump must not weaken it.
    #[test]
    fn a_supplied_transport_failure_renders_unavailable_with_the_reason() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0]);
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out), 1);
            qmb_string_free(out);
            let reason = CString::new("the network is unreachable").unwrap();
            qmb_scan_supply_err(s, reason.as_ptr());
            let mut rep: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut rep), 0);
            let report = take_out(rep);
            assert!(report.contains(report::UNAVAILABLE), "{report}");
            assert!(
                report.contains("the network is unreachable"),
                "the shell's own reason must survive into the report: {report}"
            );
            assert!(report.contains("https://seed.example.org"), "{report}");
            assert!(
                !report.contains("TOTAL spendable: 0"),
                "a transport failure must never render as an empty wallet: {report}"
            );
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// 200-with-nonsense — captive portal, proxy error page, wrong host — must
    /// refuse, not decode into a confident zero.
    #[test]
    fn a_garbage_page_is_refused_not_believed() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0]);
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out), 1);
            qmb_string_free(out);
            let junk = b"<html>404 not found</html>";
            qmb_scan_supply(s, junk.as_ptr(), junk.len());
            let mut rep: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut rep), 0);
            let report = take_out(rep);
            assert!(report.contains(report::UNAVAILABLE), "{report}");
            assert!(
                !report.contains("TOTAL spendable: 0"),
                "unparseable bytes must not become a zero balance: {report}"
            );
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// One diversifier's transport failure is ITS verdict; the next index
    /// still scans (its own compact page is asked for afresh), and the total
    /// stays UNAVAILABLE rather than a partial figure.
    #[test]
    fn each_index_gets_its_own_verdict() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0, 1]);
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out), 1);
            qmb_string_free(out);
            let reason = CString::new("index 0 went dark").unwrap();
            qmb_scan_supply_err(s, reason.as_ptr());
            // Index 1 gets its own compact request, not index 0's corpse.
            let mut out2: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out2), 1);
            assert_eq!(take_out(out2), "/v1/compact?from=0&to=10");
            qmb_scan_supply_err(s, reason.as_ptr());
            let mut rep: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut rep), 0);
            let report = take_out(rep);
            assert!(report.contains("[0]") && report.contains("[1]"), "{report}");
            assert!(report.contains(report::UNAVAILABLE), "{report}");
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// NULL args are a programming error in the shell — no handle, no report.
    #[test]
    fn null_arguments_never_scan() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let label = CString::new("x").unwrap();
            let idx: [u64; 1] = [0];
            let seed = [3u8; 32];
            let null_w: *const WalletState = ptr::null();
            assert!(qmb_scan_new(null_w, label.as_ptr(), 0, 1, idx.as_ptr(), 1, seed.as_ptr())
                .is_null());
            assert!(qmb_scan_new(w, ptr::null(), 0, 1, idx.as_ptr(), 1, seed.as_ptr()).is_null());
            assert!(qmb_scan_new(w, label.as_ptr(), 0, 1, ptr::null(), 1, seed.as_ptr()).is_null());
            assert!(qmb_scan_new(w, label.as_ptr(), 0, 1, idx.as_ptr(), 1, ptr::null()).is_null());
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(ptr::null_mut(), &mut out), -1);
            let s = pump_new(w, &[0]);
            assert_eq!(qmb_scan_step(s, ptr::null_mut()), -1);
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// A response nobody asked for is a fault (the driver's own rule), not a
    /// scan — and the fault is SAID in the report rather than swallowed.
    #[test]
    fn a_response_nobody_asked_for_is_a_fault_not_a_scan() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0]);
            let junk = b"unrequested";
            qmb_scan_supply(s, junk.as_ptr(), junk.len());
            let mut rep: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut rep), 0);
            let report = take_out(rep);
            assert!(report.contains("without requesting a path"), "{report}");
            assert!(report.contains(report::UNAVAILABLE), "{report}");
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// The report crosses once; a done pump answers -1, not a second report.
    #[test]
    fn the_report_is_returned_once() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let s = pump_new(w, &[0]);
            let mut out: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut out), 1);
            qmb_string_free(out);
            let reason = CString::new("down").unwrap();
            qmb_scan_supply_err(s, reason.as_ptr());
            let mut rep: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut rep), 0);
            qmb_string_free(rep);
            let mut again: *mut c_char = ptr::null_mut();
            assert_eq!(qmb_scan_step(s, &mut again), -1);
            assert!(again.is_null());
            qmb_scan_free(s);
            qmb_wallet_free(w);
        }
    }

    /// The Receive screen's QR: a real SVG of the full address, across the ABI.
    #[test]
    fn the_address_qr_renders_as_svg() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let mut err: *mut c_char = ptr::null_mut();
            let p = qmb_address_qr_svg(w, 0, &mut err);
            assert!(!p.is_null(), "{:?}", err);
            let svg = CStr::from_ptr(p).to_str().unwrap();
            assert!(svg.starts_with("<svg") || svg.contains("<svg"), "{}", &svg[..60.min(svg.len())]);
            qmb_string_free(p);
            qmb_wallet_free(w);
        }
    }

    /// The hand-maintained header and this file must declare the same ABI.
    #[test]
    fn the_header_names_every_exported_function_and_nothing_else() {
        let header = include_str!("../include/qumbra_ffi.h");
        let src = include_str!("lib.rs");
        let exported: Vec<&str> = src
            .lines()
            .filter_map(|l| {
                let t = l.trim();
                t.strip_prefix("pub unsafe extern \"C\" fn ")
                    .or_else(|| t.strip_prefix("pub extern \"C\" fn "))
                    .and_then(|r| r.split('(').next())
            })
            .collect();
        assert!(!exported.is_empty());
        for f in &exported {
            assert!(header.contains(f), "header is missing `{f}`");
        }
        // And nothing in the header that the source does not export.
        for line in header.lines() {
            if let Some(pos) = line.find("qmb_") {
                let name: String = line[pos..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                // Types, not functions — a closed list on purpose. Widening
                // this to a prefix match would let an undeclared function slip
                // through, which is the one thing this half of the test is for.
                const TYPES: [&str; 4] = ["qmb_wallet_t", "qmb_fetch_fn", "qmb_scan_t", "qmb_select_t"];
                assert!(
                    exported.contains(&name.as_str()) || TYPES.contains(&name.as_str()),
                    "header declares `{name}` which lib.rs does not export"
                );
            }
        }
    }
}
