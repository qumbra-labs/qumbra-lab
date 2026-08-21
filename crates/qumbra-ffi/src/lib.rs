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

pub mod events;
pub mod ledger_blob;
pub mod pairing;
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

/// Call the shell's fetch once, honouring the ownership contract in exactly one
/// place: the buffers come from `malloc` and are released here with `free`.
///
/// Extracted when the ledger entry point arrived, because a second hand-written
/// copy of a cross-allocator contract is how one of them drifts.
///
/// # Safety
/// `fetch` obeys [`QmbFetchFn`]; `ctx` is whatever it expects.
unsafe fn fetch_bytes(
    fetch: QmbFetchFn,
    ctx: *mut c_void,
    path: &str,
) -> Result<Vec<u8>, String> {
    let c_path = CString::new(path).map_err(|_| "path contains NUL".to_string())?;
    let mut body: *mut u8 = ptr::null_mut();
    let mut len: usize = 0;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = fetch(ctx, c_path.as_ptr(), &mut body, &mut len, &mut err);
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
}

/// The nullifier stream over the shell's transport. `qlab-ledger` already asks
/// for this as a trait, so nothing new is invented here — and the WIRE is
/// decoded by its owner (`qlab_cbserver::codec::NullifierPage`), never re-read.
struct ShellNullifiers {
    fetch: QmbFetchFn,
    ctx: *mut c_void,
}

impl qlab_ledger::spent::NullifierSource for ShellNullifiers {
    fn fetch_range(
        &self,
        from: u64,
        to: u64,
    ) -> Result<qlab_ledger::spent::NullifierChunk, String> {
        let path = format!("/v1/nullifiers?from={from}&to={to}");
        let bytes = unsafe { fetch_bytes(self.fetch, self.ctx, &path) }
            .map_err(|e| format!("GET {path}: {e}"))?;
        let page = qlab_cbserver::codec::NullifierPage::from_bytes(&bytes)
            .map_err(|e| format!("GET {path} did not decode: {e:?}"))?;
        Ok(qlab_ledger::spent::NullifierChunk {
            from: page.from,
            to: page.to,
            blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
        })
    }
}

/// The wallet's own ledger — received notes and spends the chain published —
/// rendered, over a caller-supplied transport.
///
/// **Send events refuse their figures here, by design.** Fee attribution needs
/// the posted table from `qlab-devnet`, which cannot cross-compile to iOS, so
/// `None` is passed and such an event reports `UNAVAILABLE` with the reason.
/// That is the honest state, not a placeholder: an unprovable total is worse
/// than an absent one (lab #407).
///
/// There is no local send record on this platform either — `sends.v1` is written
/// by the CLI on the machine that spent — so `log` is `None` and unmatched
/// records cannot arise.
///
/// # Safety
/// As [`qmb_wallet_scan_report_over_fetch`].
/// The ledger, built once for both of its exports.
///
/// 🔴 Extracted rather than copied. This is ~40 lines of scan-per-address,
/// widest-served-range pairing and `history::build`, and a second copy is
/// exactly the drift `qumbra_wallet::report_data`'s own doc comment warns
/// about ("this was ~20 lines in the CLI, and a shell that wanted the ledger
/// would have had to copy them"). The rendered export and the data export must
/// describe the SAME ledger or a shell showing rows and a shell showing the
/// paragraph would disagree about the same wallet.
///
/// `None` on a NULL/invalid argument — the callers turn that into their own
/// null return.
///
/// # Safety
/// As the two exports that call it.
// Nine arguments because it takes exactly what its two C-ABI callers take, and
// bundling them into a struct here would mean building that struct twice at the
// boundary for no reader's benefit.
#[allow(clippy::too_many_arguments)]
unsafe fn build_ledger_over_fetch(
    w: *const WalletState,
    source_label: *const c_char,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
) -> Option<(qlab_ledger::history::Ledger, String)> {
    if w.is_null() || source_label.is_null() || indices.is_null() || rng_seed32.is_null() {
        return None;
    }
    let fetch = fetch?;
    let label = CStr::from_ptr(source_label).to_str().ok()?.to_string();
    let idxs = std::slice::from_raw_parts(indices, n_indices);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(std::slice::from_raw_parts(rng_seed32, 32));
    let mut rng = StdRng::from_seed(seed);
    let state = &*w;

    let mut scans: Vec<qlab_ledger::history::AddressScan> = Vec::with_capacity(n_indices);
    for &idx in idxs {
        let d = state.wallet.diversifier_at_index(idx);
        let kp = state.wallet.diversified_keypair(&d);
        let short = state.wallet.address_at_index(idx).short().encode();
        let mut bridge = |path: &str| fetch_bytes(fetch, fetch_ctx, path);
        let outcome =
            light_client_scan_with(&mut bridge, &kp.dk, from, to, ScanConfig::default(), &mut rng)
                .map_err(|e| e.to_string());
        scans.push(qlab_ledger::history::AddressScan {
            div_index: idx,
            address_short: short,
            outcome,
        });
    }

    // The spends, judged against the range the outputs actually reached — the
    // CLI's own pairing, reused rather than re-matched here.
    let outputs = qlab_ledger::spent::widest_range(
        scans.iter().filter_map(|s| s.outcome.as_ref().ok()).map(|o| o.stats.compact_range_served),
    );
    let source = ShellNullifiers { fetch, ctx: fetch_ctx };
    let (coverage, set) = qlab_ledger::spent::coverage_for(&source, from, to, outputs);

    let ledger = qlab_ledger::history::build(
        &state.wallet,
        &scans,
        set.as_ref(),
        &coverage,
        None,
        (from, to),
        None,
    );
    Some((ledger, label))
}

/// The wallet's own ledger — received notes and spends the chain published —
/// rendered, over a caller-supplied transport.
///
/// **Send events refuse their figures here, by design.** Fee attribution needs
/// the posted table from `qlab-devnet`, which cannot cross-compile to iOS, so
/// `None` is passed and such an event reports `UNAVAILABLE` with the reason.
/// That is the honest state, not a placeholder: an unprovable total is worse
/// than an absent one (lab #407).
///
/// There is no local send record on this platform either — `sends.v1` is written
/// by the CLI on the machine that spent — so `log` is `None` and unmatched
/// records cannot arise.
///
/// # Safety
/// As [`qmb_wallet_scan_report_over_fetch`].
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_ledger_report_over_fetch(
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
    match build_ledger_over_fetch(
        w, source_label, from, to, indices, n_indices, rng_seed32, fetch, fetch_ctx,
    ) {
        Some((ledger, label)) => out_string(qlab_ledger::history::render(&ledger, &label)),
        None => ptr::null_mut(),
    }
}

/// The same ledger as DATA — the tagged blob from [`crate::ledger_blob`], so a
/// native client can build rows instead of displaying a paragraph (lab #556,
/// shape ruled 2026-08-21).
///
/// Identical inputs and identical accounting to
/// [`qmb_wallet_ledger_report_over_fetch`] — both go through one
/// `build_ledger_over_fetch`, so the rows and the paragraph cannot disagree
/// about the same wallet. Every `UNAVAILABLE` decision stays in `qlab-ledger`;
/// this only serializes what it decided.
///
/// `notes` is empty on this path and that is structural rather than an
/// omission: `HistoryData::notes` is produced by the CLI's history flow, which
/// needs a wallet directory and its own networking. A shell reading this blob
/// sees no `QMB_LEDGER_NOTE` records, which is the honest encoding of "there
/// are none" — not of "they were dropped".
///
/// Returns the blob and writes its length to `out_len`; NULL with `*out_len = 0`
/// on a NULL/invalid argument. Free with `qmb_dealloc(p, len)`.
///
/// # Safety
/// As [`qmb_wallet_ledger_report_over_fetch`], plus `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_wallet_ledger_data_over_fetch(
    w: *const WalletState,
    source_label: *const c_char,
    from: u64,
    to: u64,
    indices: *const u64,
    n_indices: usize,
    rng_seed32: *const u8,
    fetch: Option<QmbFetchFn>,
    fetch_ctx: *mut c_void,
    out_len: *mut usize,
) -> *mut u8 {
    if out_len.is_null() {
        return ptr::null_mut();
    }
    *out_len = 0;
    let Some((ledger, _label)) = build_ledger_over_fetch(
        w, source_label, from, to, indices, n_indices, rng_seed32, fetch, fetch_ctx,
    ) else {
        return ptr::null_mut();
    };
    let bytes = ledger_blob::encode_ledger(&ledger, &[]);
    *out_len = bytes.len();
    Box::into_raw(bytes.into_boxed_slice()) as *mut u8
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
    // One bridge, defined once (see `fetch_bytes`).
    let mut bridge = |path: &str| fetch_bytes(fetch, fetch_ctx, path);

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
/// Since lab #424 the SCAN contract carries **two** streams — `/v1/nullifiers`
/// and `/v1/coinbase` — because this wallet's own mined notes are inputs a
/// spend may select. A host that answers the coinbase path with a transport
/// error (every node older than lab #415 answers 404) does NOT fail the select:
/// it proceeds on transaction notes only, per the 2026-08-16 ruling.
///
/// 🔴 **This entry point cannot SHOW that degradation** — it drains no events,
/// and it is kept only because the ABI is additive (lab #432 closed the gap at
/// [`qmb_select_step_events`], which every send surface must use instead). The
/// driver's narration — `Selected`, `Tree`, `Warning`, `CoinbaseUnavailable` —
/// stays QUEUED in the handle when this function pumps it: deferred, never
/// lost, returned whole by the next `qmb_select_step_events` call.
///
/// # Safety
/// `s` live (or NULL); `out` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_select_step(s: *mut SelectState, out: *mut *mut c_char) -> i32 {
    if s.is_null() || out.is_null() {
        return -1;
    }
    select_step_inner(&mut *s, out)
}

/// The one step implementation behind both entry points — the return codes
/// and the `*out` contract cannot drift between them.
unsafe fn select_step_inner(st: &mut SelectState, out: *mut *mut c_char) -> i32 {
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

/// [`qmb_select_step`] plus the driver's narration — lab #432, closing lab
/// #424's guardrail-1 gap on this ABI. Same return codes, same `*out`
/// contract; additionally every call drains the events the driver has emitted
/// (all events queued since the last drain, in order) into `*events_out` /
/// `*events_len` as the tagged, length-prefixed encoding documented in
/// `include/qumbra_ffi.h` and [`events`]. No events → `*events_out = NULL`,
/// `*events_len = 0`.
///
/// The events ride the step return, not a separate pump codepoint, so a
/// consumer of this function cannot forget to collect them — and NULL
/// `events_out`/`events_len` is refused with `-1`, so it cannot opt out
/// either. The buffer is released with `qmb_dealloc(p, len)` (same contract as
/// `qmb_select_take_bundle`).
///
/// 🔴 **The narration contract (lab #424 guardrail 1):** a consumer MUST
/// surface `QMB_EVENT_WARNING` and `QMB_EVENT_COINBASE_UNAVAILABLE` to its
/// user. A shell that drops them ships a send surface whose user can spend
/// from a degraded view and see nothing — the exact harm the ruling's visible-
/// degradation guardrail exists to prevent. An event of an UNKNOWN kind is
/// skipped by its length prefix, never a parse failure — a fifth kind must not
/// break an old consumer.
///
/// # Safety
/// `s` live (or NULL); `out`, `events_out`, `events_len` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_select_step_events(
    s: *mut SelectState,
    out: *mut *mut c_char,
    events_out: *mut *mut u8,
    events_len: *mut usize,
) -> i32 {
    if s.is_null() || out.is_null() || events_out.is_null() || events_len.is_null() {
        return -1;
    }
    let st = &mut *s;
    let rc = select_step_inner(st, out);
    let drained = st.driver.take_events();
    if drained.is_empty() {
        *events_out = ptr::null_mut();
        *events_len = 0;
    } else {
        let blob = events::encode_events(&drained).into_boxed_slice();
        *events_len = blob.len();
        *events_out = Box::into_raw(blob) as *mut u8;
    }
    rc
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



/// Decode a `/v1/anchors` response into the connection facts a wallet surface
/// shows and scans by: TIP height, and the FINALIZED height when the chain
/// has one (`*out_has_finalized = 0` means young-chain-nothing-finalized —
/// said, never guessed as 0). The bytes are decoded by
/// `qlab_node::AnchorSet::from_bytes`, the wire's own codec. Scanning to
/// FINALIZED (the macOS shell's choice) keeps a balance spendable-consistent:
/// a note above the finalized anchor cannot be spent yet anyway. Returns 0 on
/// success; -1 + `err_out` on refusal, by name. (Supersedes `qmb_anchors_tip`,
/// whose only consumer moved with it.)
///
/// # Safety
/// `bytes` points to `len` readable bytes; `out_tip`/`out_has_finalized`/
/// `out_finalized` writable; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_anchors_facts(
    bytes: *const u8,
    len: usize,
    out_tip: *mut u64,
    out_has_finalized: *mut u8,
    out_finalized: *mut u64,
    err_out: *mut *mut c_char,
) -> i32 {
    if bytes.is_null() || out_tip.is_null() || out_has_finalized.is_null() || out_finalized.is_null()
    {
        set_err(err_out, "NULL argument".into());
        return -1;
    }
    let raw = std::slice::from_raw_parts(bytes, len);
    match qlab_node::AnchorSet::from_bytes(raw) {
        Ok(set) => {
            *out_tip = set.tip_height;
            *out_has_finalized = u8::from(set.finalized_height.is_some());
            *out_finalized = set.finalized_height.unwrap_or(0);
            0
        }
        Err(e) => {
            set_err(err_out, format!("GET /v1/anchors did not decode: {e:?}"));
            -1
        }
    }
}

/* --- payment URIs + the history join (roadmap #3/#4) ---------------------- */

/// Parse a `qumbra:` payment URI (#342's codec — the one copy). Returns the
/// FULL `qaddr1…` address; the amount, when the URI carries one, lands in
/// `*out_amount_bessel` with `*out_has_amount = 1` (integer-exact bessel — no
/// float near money). Label and memo are display-only and deliberately do not
/// cross in v1. NULL + `err_out` on refusal, by name — including the
/// short-address-unpayable case.
///
/// # Safety
/// `uri` NUL-terminated UTF-8; `out_amount_bessel`/`out_has_amount` writable;
/// `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_uri_parse(
    uri: *const c_char,
    out_amount_bessel: *mut u64,
    out_has_amount: *mut u8,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if uri.is_null() || out_amount_bessel.is_null() || out_has_amount.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let s = match CStr::from_ptr(uri).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err(err_out, "URI is not UTF-8".into());
            return ptr::null_mut();
        }
    };
    match qlab_wallet::uri::parse(s) {
        Ok(req) => {
            *out_has_amount = u8::from(req.amount_bessel.is_some());
            *out_amount_bessel = req.amount_bessel.unwrap_or(0);
            out_string(req.address.encode())
        }
        Err(e) => {
            // `{e}`, not `{e:?}`: shells put this string in front of the
            // person who pasted the URI, and `UriError`'s Display is written
            // for them ("Ask the payee for their full qaddr1… address"), while
            // its Debug renders the bare variant name and throws that away.
            set_err(err_out, format!("payment URI refused: {e}"));
            ptr::null_mut()
        }
    }
}

/// Build a `qumbra:` payment URI — the encode half of the codec whose decode
/// half is qmb_uri_parse, so a QR a wallet shows and a URI a wallet reads come
/// from one implementation. `address` is a full `qaddr1…`; pass
/// `has_amount = 0` for an amount-less request ("send me some"), which is a
/// real and common shape. NULL + `err_out` on refusal, by name.
///
/// Label and memo do NOT cross in v1, deliberately: qmb_uri_parse does not
/// return them, and a builder that could emit a key the parser drops would make
/// an ABI round-trip lose data silently.
///
/// # Safety
/// `address` NUL-terminated UTF-8; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_uri_build(
    address: *const c_char,
    amount_bessel: u64,
    has_amount: u8,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    if address.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let s = match CStr::from_ptr(address).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err(err_out, "address is not UTF-8".into());
            return ptr::null_mut();
        }
    };
    // Validated by running it through the ABI's OWN parser rather than a second
    // address check here. A bare URI through `uri::parse` classifies exactly
    // what qmb_uri_parse classifies, so the two halves cannot drift and a qs1…
    // fingerprint is refused with the same sentence either way.
    let bare = format!("{}:{s}", qlab_wallet::uri::URI_SCHEME);
    let req = match qlab_wallet::uri::parse(&bare) {
        Ok(req) => req,
        Err(e) => {
            set_err(err_out, format!("payment URI refused: {e}"));
            return ptr::null_mut();
        }
    };
    // Any nonzero is present: a C caller writing `1`, `true` or a bitfield all
    // mean the same thing, and silently reading `2` as absent would drop an
    // amount the caller asked for.
    let amount = (has_amount != 0).then_some(amount_bessel);
    out_string(qlab_wallet::uri::encode(&req.address, amount, None, None))
}

/// Parse a whole-coin decimal QMB string (`"1.5"`) to bessel, EXACTLY — the
/// one decimal-money parser, so no shell has to write one. `0` and
/// `*out_bessel` set on success; `-1` and `err_out` on refusal, by name.
///
/// 🔴 This exists so that a typed amount never goes through a float. `#303`
/// makes money integer-exact with no float reachable; a shell parsing `"1.5"`
/// itself is how a `Double` gets into a spend.
///
/// # Safety
/// `decimal` NUL-terminated UTF-8; `out_bessel` writable; `err_out` NULL or
/// writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_amount_parse(
    decimal: *const c_char,
    out_bessel: *mut u64,
    err_out: *mut *mut c_char,
) -> i32 {
    if decimal.is_null() || out_bessel.is_null() {
        set_err(err_out, "NULL argument".into());
        return -1;
    }
    let s = match CStr::from_ptr(decimal).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_err(err_out, "amount is not UTF-8".into());
            return -1;
        }
    };
    match qlab_wallet::uri::qmb_to_bessel(s) {
        Ok(b) => {
            *out_bessel = b;
            0
        }
        Err(why) => {
            // The core's wording verbatim: it already names the rule broken,
            // and paraphrasing here would be a second source of truth.
            set_err(err_out, format!("amount refused: {why}"));
            -1
        }
    }
}

/// The witness bundle's REAL-input nullifiers, hex, newline-joined — the
/// history join key (roadmap #4): these exact bytes go on-chain when the
/// spend lands, so a record keyed on them can later be marked CONFIRMED by
/// the chain's own nullifier stream. NULL + `err_out` on an undecodable
/// bundle, by name.
///
/// # Safety
/// `bytes` points to `len` readable bytes; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_bundle_nullifiers(
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
    let hex = |nf: [u8; 32]| nf.iter().map(|b| format!("{b:02x}")).collect::<String>();
    out_string(
        bundle.real_nullifiers().into_iter().map(hex).collect::<Vec<_>>().join("\n"),
    )
}

/// The bulk nullifier stream, caller-pumped — the confirmation half of the
/// history join. Same pump vocabulary as scan/select; the accumulation checks
/// are `qumbra_wallet::spent::SpentCatchUp`, the ONE copy shared with the CLI
/// and the select driver.
pub struct SpentState {
    catch: Option<qumbra_wallet::spent::SpentCatchUp>,
    set: Option<qumbra_wallet::spent::SpentSet>,
    fatal: Option<String>,
    pending: Option<(u64, u64)>,
}

/// # Safety
/// Always safe; never NULL.
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_new(from: u64, to: u64) -> *mut SpentState {
    Box::into_raw(Box::new(SpentState {
        catch: Some(qumbra_wallet::spent::SpentCatchUp::new(from, to)),
        set: None,
        fatal: None,
        pending: None,
    }))
}

/// `1` NEED (*out = the page path) · `0` DONE (query with `qmb_spent_contains`)
/// · `-2` FAILED by name (*out) · `-1` invalid call.
///
/// # Safety
/// `s` live (or NULL); `out` writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_step(s: *mut SpentState, out: *mut *mut c_char) -> i32 {
    if s.is_null() || out.is_null() {
        return -1;
    }
    let st = &mut *s;
    if let Some(why) = &st.fatal {
        *out = out_string(why.clone());
        return -2;
    }
    if st.set.is_some() {
        return 0;
    }
    let catch = st.catch.as_ref().expect("live until done");
    match catch.want() {
        Some((from, to)) => {
            st.pending = Some((from, to));
            *out = out_string(format!("/v1/nullifiers?from={from}&to={to}"));
            1
        }
        None => {
            st.set = Some(st.catch.take().expect("live until done").finish());
            0
        }
    }
}

/// # Safety
/// `s` live (or NULL); `body` points to `len` readable bytes (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_supply(s: *mut SpentState, body: *const u8, len: usize) {
    if s.is_null() {
        return;
    }
    let st = &mut *s;
    let Some((from, to)) = st.pending.take() else {
        st.fatal = Some("a page was supplied without a request".into());
        return;
    };
    if body.is_null() {
        st.fatal = Some("supplied body is NULL".into());
        return;
    }
    let raw = std::slice::from_raw_parts(body, len);
    let path = format!("/v1/nullifiers?from={from}&to={to}");
    let page = match qlab_cbserver::codec::NullifierPage::from_bytes(raw) {
        Ok(p) => p,
        Err(e) => {
            st.fatal = Some(format!("GET {path} did not decode: {e:?}"));
            return;
        }
    };
    let chunk = qumbra_wallet::spent::NullifierChunk {
        from: page.from,
        to: page.to,
        blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
    };
    if let Err(e) = st.catch.as_mut().expect("live until done").supply(chunk) {
        st.fatal = Some(e.to_string());
    }
}

/// # Safety
/// `s` live (or NULL); `reason` NUL-terminated (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_supply_err(s: *mut SpentState, reason: *const c_char) {
    if s.is_null() {
        return;
    }
    let st = &mut *s;
    st.pending = None;
    let reason = if reason.is_null() {
        "transport failed with no reason".to_string()
    } else {
        CStr::from_ptr(reason).to_string_lossy().into_owned()
    };
    st.fatal = Some(reason);
}

/// After DONE: `1` if the hex nullifier is on the chain, `0` if not, `-1`
/// before DONE or on malformed hex — an unanswerable question is refused,
/// never guessed at.
///
/// # Safety
/// `s` live (or NULL); `nf_hex` NUL-terminated (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_contains(s: *const SpentState, nf_hex: *const c_char) -> i32 {
    if s.is_null() || nf_hex.is_null() {
        return -1;
    }
    let Some(set) = (*s).set.as_ref() else { return -1 };
    let Ok(hexstr) = CStr::from_ptr(nf_hex).to_str() else { return -1 };
    if hexstr.len() != 64 {
        return -1;
    }
    let mut nf = [0u8; 32];
    for i in 0..32 {
        match u8::from_str_radix(&hexstr[i * 2..i * 2 + 2], 16) {
            Ok(b) => nf[i] = b,
            Err(_) => return -1,
        }
    }
    i32::from(set.contains(&nf))
}

/// # Safety
/// `s` must be a live handle from `qmb_spent_new`; never used after this call.
#[no_mangle]
pub unsafe extern "C" fn qmb_spent_free(s: *mut SpentState) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
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

    /// The ledger over a dead transport must refuse in the same vocabulary the
    /// scan does — and must not render a zero. A wallet that cannot read the
    /// chain does not know that nothing arrived.
    #[test]
    fn the_ledger_over_a_failed_transport_refuses_and_never_shows_a_zero() {
        unsafe {
            let entropy = [7u8; 32];
            let w = qmb_wallet_from_entropy(entropy.as_ptr());
            let label = CString::new("https://seed.example.org").unwrap();
            let indices: [u64; 1] = [0];
            let seed = [3u8; 32];
            let mut calls: u32 = 0;
            let out = qmb_wallet_ledger_report_over_fetch(
                w,
                label.as_ptr(),
                0,
                10,
                indices.as_ptr(),
                1,
                seed.as_ptr(),
                Some(fetch_always_fails),
                &mut calls as *mut u32 as *mut c_void,
            );
            assert!(!out.is_null());
            let report = CStr::from_ptr(out).to_str().unwrap().to_string();
            qmb_string_free(out);
            qmb_wallet_free(w);

            assert!(calls > 0, "the ledger must use the shell's transport");
            assert!(report.contains("UNAVAILABLE"), "{report}");
            assert!(
                report.contains("the network is unreachable"),
                "the shell's own reason must survive: {report}"
            );
            assert!(
                !report.contains("TOTAL spendable: 0"),
                "an unreadable chain must not render as an empty wallet: {report}"
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

    /// Tip AND finalized cross from a REAL AnchorSet encoding; a young chain's
    /// nothing-finalized is SAID (has=0), never guessed as height 0; garbage
    /// refuses by name.
    #[test]
    fn the_anchors_facts_read_from_the_wire_codec() {
        unsafe {
            let set = qlab_node::AnchorSet {
                tip_height: 12345,
                finalized_height: Some(12000),
                max_age_blocks: 64,
                roots: vec![[7u8; 32]],
            };
            let bytes = set.to_bytes();
            let (mut tip, mut has, mut fin): (u64, u8, u64) = (0, 9, 9);
            let mut err: *mut c_char = ptr::null_mut();
            assert_eq!(
                qmb_anchors_facts(bytes.as_ptr(), bytes.len(), &mut tip, &mut has, &mut fin, &mut err),
                0
            );
            assert_eq!((tip, has, fin), (12345, 1, 12000));

            let young = qlab_node::AnchorSet {
                tip_height: 3,
                finalized_height: None,
                max_age_blocks: 64,
                roots: vec![],
            };
            let yb = young.to_bytes();
            assert_eq!(
                qmb_anchors_facts(yb.as_ptr(), yb.len(), &mut tip, &mut has, &mut fin, &mut err),
                0
            );
            assert_eq!((tip, has), (3, 0), "nothing finalized is said, not zeroed");

            let junk = b"nope";
            assert_eq!(
                qmb_anchors_facts(junk.as_ptr(), junk.len(), &mut tip, &mut has, &mut fin, &mut err),
                -1
            );
            assert!(!err.is_null());
            let why = CStr::from_ptr(err).to_str().unwrap();
            assert!(why.contains("did not decode"), "{why}");
            qmb_string_free(err);
        }
    }

    /// A payment URI round-trips: full address out, exact bessel out, and a
    /// URI without an amount says so instead of inventing a zero.
    #[test]
    fn a_payment_uri_parses_across_the_abi() {
        unsafe {
            let w = qmb_wallet_from_entropy([7u8; 32].as_ptr());
            let full_ptr = qmb_wallet_address(w, 0);
            let full = CStr::from_ptr(full_ptr).to_str().unwrap().to_string();
            qmb_string_free(full_ptr);

            let uri = CString::new(format!("qumbra:{full}?amount=1.5")).unwrap();
            let mut amount: u64 = 0;
            let mut has: u8 = 0;
            let mut err: *mut c_char = ptr::null_mut();
            let addr_ptr = qmb_uri_parse(uri.as_ptr(), &mut amount, &mut has, &mut err);
            assert!(!addr_ptr.is_null());
            assert_eq!(CStr::from_ptr(addr_ptr).to_str().unwrap(), full);
            qmb_string_free(addr_ptr);
            assert_eq!((has, amount), (1, 150_000_000), "1.5 QMB, integer-exact");

            let bare = CString::new(format!("qumbra:{full}")).unwrap();
            let addr2 = qmb_uri_parse(bare.as_ptr(), &mut amount, &mut has, &mut err);
            assert!(!addr2.is_null());
            qmb_string_free(addr2);
            assert_eq!(has, 0, "no amount means no amount, not zero");

            let junk = CString::new("bitcoin:1abc").unwrap();
            let refused = qmb_uri_parse(junk.as_ptr(), &mut amount, &mut has, &mut err);
            assert!(refused.is_null());
            assert!(!err.is_null());
            let why = CStr::from_ptr(err).to_str().unwrap();
            assert!(why.contains("refused"), "{why}");
            qmb_string_free(err);
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

    /// The two halves of the codec meet: whatever the builder emits, the
    /// parser reads back — with the amount integer-exact and an absent amount
    /// still absent.
    #[test]
    fn a_built_uri_parses_back_to_what_went_in() {
        unsafe {
            let w = qmb_wallet_from_entropy([11u8; 32].as_ptr());
            let full_ptr = qmb_wallet_address(w, 0);
            let full = CStr::from_ptr(full_ptr).to_str().unwrap().to_string();
            qmb_string_free(full_ptr);
            let addr = CString::new(full.clone()).unwrap();
            let mut err: *mut c_char = ptr::null_mut();

            for &(amount_in, has_in) in &[(150_000_000u64, 1u8), (1, 1), (0, 0), (0, 1)] {
                let uri_ptr = qmb_uri_build(addr.as_ptr(), amount_in, has_in, &mut err);
                assert!(!uri_ptr.is_null(), "build refused a good address");
                let uri = CStr::from_ptr(uri_ptr).to_str().unwrap().to_string();
                qmb_string_free(uri_ptr);
                assert!(uri.starts_with("qumbra:"), "{uri}");

                let back = CString::new(uri.clone()).unwrap();
                let mut amount_out: u64 = 0;
                let mut has_out: u8 = 0;
                let addr_out = qmb_uri_parse(back.as_ptr(), &mut amount_out, &mut has_out, &mut err);
                assert!(!addr_out.is_null(), "the parser refused our own URI: {uri}");
                assert_eq!(CStr::from_ptr(addr_out).to_str().unwrap(), full);
                qmb_string_free(addr_out);
                assert_eq!((has_out, amount_out), (has_in, amount_in), "round-trip lost the amount: {uri}");
            }
            qmb_wallet_free(w);
        }
    }

    /// 🔴 A refusal must carry the SENTENCE, not the variant name. Shells put
    /// this string straight in front of the person who pasted the address, and
    /// `ShortAddressUnpayable` tells them nothing about what to do next.
    #[test]
    fn a_short_address_is_refused_with_the_reason_a_person_can_act_on() {
        unsafe {
            let w = qmb_wallet_from_entropy([13u8; 32].as_ptr());
            let short_ptr = qmb_wallet_address_short(w, 0);
            let short = CStr::from_ptr(short_ptr).to_str().unwrap().to_string();
            qmb_string_free(short_ptr);
            assert!(short.starts_with("qs1"), "{short}");

            let mut err: *mut c_char = ptr::null_mut();
            let addr = CString::new(short.clone()).unwrap();
            assert!(qmb_uri_build(addr.as_ptr(), 0, 0, &mut err).is_null());
            let why = CStr::from_ptr(err).to_str().unwrap().to_string();
            qmb_string_free(err);
            assert!(why.contains("qaddr1"), "must say what to ask for instead: {why}");
            assert!(!why.contains("ShortAddressUnpayable"), "variant name leaked: {why}");

            // And the decode half words it the same way, because both go
            // through the one classifier.
            let mut err2: *mut c_char = ptr::null_mut();
            let uri = CString::new(format!("qumbra:{short}")).unwrap();
            let mut a: u64 = 0;
            let mut h: u8 = 0;
            assert!(qmb_uri_parse(uri.as_ptr(), &mut a, &mut h, &mut err2).is_null());
            let why2 = CStr::from_ptr(err2).to_str().unwrap().to_string();
            qmb_string_free(err2);
            assert_eq!(why, why2, "the two halves must refuse in the same words");
            qmb_wallet_free(w);
        }
    }

    /// Typed decimal QMB, exact — and the refusals that keep a float out.
    #[test]
    fn a_decimal_amount_parses_exactly_or_is_refused_by_name() {
        unsafe {
            let mut out: u64 = 0;
            let mut err: *mut c_char = ptr::null_mut();
            for (text, expect) in [
                ("1.5", 150_000_000u64),
                ("0.00000001", 1),
                ("1", 100_000_000),
                ("0", 0),
                ("184467440737.09551615", u64::MAX),
            ] {
                let c = CString::new(text).unwrap();
                assert_eq!(qmb_amount_parse(c.as_ptr(), &mut out, &mut err), 0, "{text} refused");
                assert_eq!(out, expect, "{text} parsed to the wrong bessel");
            }
            // Every one of these is a way a float or a surprise could get in.
            for text in ["1e3", "-1", "+1", "1_000", "", ".", "1.", ".5", "1.234567891", " 1", "1 "] {
                let c = CString::new(text).unwrap();
                let mut e: *mut c_char = ptr::null_mut();
                assert_eq!(qmb_amount_parse(c.as_ptr(), &mut out, &mut e), -1, "{text:?} accepted");
                assert!(!e.is_null(), "{text:?} refused without saying why");
                qmb_string_free(e);
            }
        }
    }

    /// The same pin as the event kinds, for the ledger blob's kinds (lab #556).
    /// A tag that drifts between the header and `ledger_blob.rs` is a consumer
    /// decoding the wrong row — the failure that is silent until a balance is
    /// wrong.
    #[test]
    fn the_header_and_the_ledger_blob_pin_the_same_kind_values() {
        let header = include_str!("../include/qumbra_ffi.h");
        let src = include_str!("ledger_blob.rs");

        let header_kinds: Vec<(String, u16)> = header
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("#define QMB_LEDGER_")?;
                let mut it = rest.split_whitespace();
                let name = it.next()?.to_string();
                let value = it.next()?.parse().ok()?;
                Some((name, value))
            })
            .collect();
        let src_kinds: Vec<(String, u16)> = src
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("pub const QMB_LEDGER_")?;
                let (name, tail) = rest.split_once(": u16 = ")?;
                let value = tail.trim_end_matches(';').parse().ok()?;
                Some((name.to_string(), value))
            })
            .collect();

        assert!(!header_kinds.is_empty(), "the header declares no ledger kinds");
        assert!(!src_kinds.is_empty(), "ledger_blob.rs declares no ledger kinds");
        // A floor on what the regexes matched, so a rename that makes BOTH
        // sides match nothing cannot pass as agreement.
        assert!(header_kinds.len() >= 10, "expected every ledger kind, got {}", header_kinds.len());
        for (name, value) in &header_kinds {
            assert!(
                src_kinds.contains(&(name.clone(), *value)),
                "header declares QMB_LEDGER_{name} = {value}, ledger_blob.rs does not"
            );
        }
        for (name, value) in &src_kinds {
            assert!(
                header_kinds.contains(&(name.clone(), *value)),
                "ledger_blob.rs declares QMB_LEDGER_{name} = {value}, the header does not"
            );
        }
    }

    /* ── the ledger blob's three-state discipline ─────────────────────────
     *
     * These decode the blob the way a shell must — walk records, skip by
     * length — and assert the states that a careless encoder would flatten.
     * Every one of them is a wrong balance if it regresses.
     */

    fn walk(blob: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let count = u32::from_le_bytes(blob[0..4].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(count);
        let mut p = 4;
        for _ in 0..count {
            let kind = u16::from_le_bytes(blob[p..p + 2].try_into().unwrap());
            let len = u32::from_le_bytes(blob[p + 2..p + 6].try_into().unwrap()) as usize;
            out.push((kind, blob[p + 6..p + 6 + len].to_vec()));
            p += 6 + len;
        }
        assert_eq!(p, blob.len(), "the record lengths must account for every byte");
        out
    }

    fn empty_ledger() -> qlab_ledger::history::Ledger {
        qlab_ledger::history::Ledger {
            range: (10, 20),
            outputs_served: Some((10, 18)),
            events: Vec::new(),
            coverage: qlab_ledger::vocab::SpentCoverage::Covered { range: Some((10, 20)) },
            verdicts: Vec::new(),
            gaps: Vec::new(),
            totals: None,
            current_spendable: None,
            shadowed_total: 0,
            unmatched_records: 0,
        }
    }

    /// 🔴 The rule the whole encoding rests on: no totals means NO RECORD, and
    /// a shell therefore cannot read a zero where the answer is unknown.
    #[test]
    fn a_ledger_without_totals_emits_no_totals_record() {
        let mut led = empty_ledger();
        led.gaps = vec!["one address never answered".into()];
        let blob = ledger_blob::encode_ledger(&led, &[]);
        let records = walk(&blob);

        assert!(
            !records.iter().any(|(k, _)| *k == ledger_blob::QMB_LEDGER_TOTALS),
            "a ledger with a gap has no totals, so it must emit no totals record"
        );
        assert_eq!(
            records.iter().filter(|(k, _)| *k == ledger_blob::QMB_LEDGER_GAP).count(),
            1,
            "and the gap that caused it must be there to say why"
        );

        // With the gap gone and totals present, the record appears — so the
        // absence above is the encoder's decision and not a missing feature.
        led.gaps.clear();
        led.totals = Some(qlab_ledger::history::Totals {
            total_in: 7,
            total_out: 3,
            fees_paid: 1,
            fee_inseparable_events: 0,
        });
        let with = walk(&ledger_blob::encode_ledger(&led, &[]));
        let body = with
            .iter()
            .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_TOTALS)
            .map(|(_, b)| b.clone())
            .expect("totals exist, so the record must be emitted");
        assert_eq!(u128::from_le_bytes(body[0..16].try_into().unwrap()), 7);
        assert_eq!(u128::from_le_bytes(body[16..32].try_into().unwrap()), 3);
        assert_eq!(u128::from_le_bytes(body[32..48].try_into().unwrap()), 1);
    }

    /// 🔴 Covered-with-no-range is a COVERED state, not a failure: the endpoint
    /// held no main-chain block in the range, and a range with no blocks has no
    /// outputs either. Flattening it into unavailable would tell a user their
    /// balance is unknowable when it is simply empty.
    #[test]
    fn the_three_coverage_states_stay_three() {
        use qlab_ledger::vocab::SpentCoverage;
        let cases: Vec<(SpentCoverage, u8, u8)> = vec![
            (SpentCoverage::Covered { range: Some((1, 2)) }, 0, 1),
            (SpentCoverage::Covered { range: None }, 0, 0),
            (SpentCoverage::Unavailable { why: "the stream stopped".into() }, 1, 0),
        ];
        for (coverage, want_state, want_has_range) in cases {
            let mut led = empty_ledger();
            led.coverage = coverage.clone();
            let records = walk(&ledger_blob::encode_ledger(&led, &[]));
            let body = records
                .iter()
                .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_COVERAGE)
                .map(|(_, b)| b.clone())
                .expect("coverage always crosses");
            assert_eq!(body[0], want_state, "state byte for {coverage:?}");
            assert_eq!(body[1], want_has_range, "has_range for {coverage:?}");
            if want_state == 1 {
                let why = String::from_utf8(body[18..].to_vec()).unwrap();
                assert_eq!(why, "the stream stopped", "the reason must cross verbatim");
            }
        }
    }

    /// 🔴 `FeeInseparable` is its own answer. Reading `amount` without the tag
    /// turns "the amount and the fee cannot be separated, but their sum is
    /// exact" into "the fee was zero", which is a lie about money.
    #[test]
    fn the_three_outgoing_states_stay_three() {
        use qlab_ledger::history::{Event, Outgoing, SendEvent};
        let cases: Vec<(Outgoing, u8, u128, u64)> = vec![
            (Outgoing::Exact { amount: 500, fee: 7 }, 0, 500, 7),
            (Outgoing::FeeInseparable { amount_and_fee: 507 }, 1, 507, 0),
            (Outgoing::Unavailable { why: "ambiguous group".into() }, 2, 0, 0),
        ];
        for (outgoing, want_tag, want_amount, want_fee) in cases {
            let mut led = empty_ledger();
            led.events = vec![Event::Send(SendEvent {
                height: 12,
                inputs: Vec::new(),
                inputs_total: 600,
                change: Vec::new(),
                change_total: 93,
                outgoing: outgoing.clone(),
                local: None,
                ambiguous_local: false,
            })];
            let records = walk(&ledger_blob::encode_ledger(&led, &[]));
            let body = records
                .iter()
                .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_SEND)
                .map(|(_, b)| b.clone())
                .expect("a send event must cross");
            // height(8) count(4) inputs_total(16) count(4) change_total(16) = 48
            assert_eq!(body[48], want_tag, "tag for {outgoing:?}");
            assert_eq!(
                u128::from_le_bytes(body[49..65].try_into().unwrap()),
                want_amount,
                "amount for {outgoing:?}"
            );
            assert_eq!(
                u64::from_le_bytes(body[65..73].try_into().unwrap()),
                want_fee,
                "fee for {outgoing:?}"
            );
            if want_tag == 2 {
                assert_eq!(String::from_utf8(body[75..].to_vec()).unwrap(), "ambiguous group");
            }
        }
    }

    /// A shadowed note is reported and never summed, so the flag has to survive
    /// the wire — a shell that cannot see it will add the note to a balance the
    /// owner can never spend from.
    #[test]
    fn a_shadowed_received_note_crosses_as_shadowed() {
        use qlab_ledger::history::{Event, Received};
        let mut led = empty_ledger();
        led.events = vec![
            Event::Received(Received {
                height: 11,
                value: 100,
                div_index: 0,
                address_short: "qs1aaa".into(),
                shadowed: false,
            }),
            Event::Received(Received {
                height: 12,
                value: 200,
                div_index: 1,
                address_short: "qs1bbb".into(),
                shadowed: true,
            }),
        ];
        let records = walk(&ledger_blob::encode_ledger(&led, &[]));
        let rows: Vec<&Vec<u8>> = records
            .iter()
            .filter(|(k, _)| *k == ledger_blob::QMB_LEDGER_RECEIVED)
            .map(|(_, b)| b)
            .collect();
        assert_eq!(rows.len(), 2, "both rows cross, in ledger order");
        assert_eq!(rows[0][24], 0, "the first note is spendable");
        assert_eq!(rows[1][24], 1, "the second is shadowed and must say so");
        assert_eq!(u64::from_le_bytes(rows[1][8..16].try_into().unwrap()), 200);
        assert_eq!(String::from_utf8(rows[1][25..].to_vec()).unwrap(), "qs1bbb");
    }

    /// An unquotable spendable figure is not a spendable figure of zero, and
    /// `unmatched_records` must not be lost — an unjoined local record would
    /// otherwise look like a send that never happened.
    #[test]
    fn the_summary_keeps_unquotable_apart_from_zero() {
        let mut led = empty_ledger();
        led.unmatched_records = 2;
        led.shadowed_total = 40;
        let none = walk(&ledger_blob::encode_ledger(&led, &[]));
        let b = none
            .iter()
            .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_SUMMARY)
            .map(|(_, b)| b.clone())
            .unwrap();
        assert_eq!(b[0], 0, "no spendable figure is quotable");
        assert_eq!(u128::from_le_bytes(b[17..33].try_into().unwrap()), 40, "shadowed_total");
        assert_eq!(u64::from_le_bytes(b[33..41].try_into().unwrap()), 2, "unmatched_records");

        led.current_spendable = Some(0);
        let zero = walk(&ledger_blob::encode_ledger(&led, &[]));
        let b2 = zero
            .iter()
            .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_SUMMARY)
            .map(|(_, b)| b.clone())
            .unwrap();
        assert_eq!(b2[0], 1, "a spendable balance of zero IS quotable");
        assert_eq!(u128::from_le_bytes(b2[1..17].try_into().unwrap()), 0);
        assert_ne!(b[0], b2[0], "unquotable and zero must be distinguishable");
    }

    /// Every verdict variant carries its own counts, and the counts a variant
    /// does not have stay zero rather than borrowing a neighbour's.
    #[test]
    fn each_verdict_variant_carries_only_its_own_counts() {
        use qlab_cbserver::client::Completeness;
        let cases = vec![
            (Completeness::Complete, 0u8, 0u64, 0u64, 0u64),
            (Completeness::Incomplete { detected: 9, opened: 4 }, 1, 9, 4, 0),
            (Completeness::Shadowed { opened: 6, spendable: 5 }, 2, 0, 6, 5),
            (
                Completeness::IncompleteAndShadowed { detected: 9, opened: 6, spendable: 5 },
                3,
                9,
                6,
                5,
            ),
        ];
        for (c, tag, detected, opened, spendable) in cases {
            let mut led = empty_ledger();
            led.verdicts = vec![(3, "qs1ccc".to_string(), c, Some("why".to_string()))];
            let records = walk(&ledger_blob::encode_ledger(&led, &[]));
            let b = records
                .iter()
                .find(|(k, _)| *k == ledger_blob::QMB_LEDGER_VERDICT)
                .map(|(_, b)| b.clone())
                .expect("a verdict must cross");
            assert_eq!(u64::from_le_bytes(b[0..8].try_into().unwrap()), 3, "div_index");
            assert_eq!(b[8], tag, "tag for {c:?}");
            assert_eq!(u64::from_le_bytes(b[9..17].try_into().unwrap()), detected, "detected {c:?}");
            assert_eq!(u64::from_le_bytes(b[17..25].try_into().unwrap()), opened, "opened {c:?}");
            assert_eq!(
                u64::from_le_bytes(b[25..33].try_into().unwrap()),
                spendable,
                "spendable {c:?}"
            );
            // Two length-prefixed strings follow.
            let short_len = u32::from_le_bytes(b[33..37].try_into().unwrap()) as usize;
            assert_eq!(String::from_utf8(b[37..37 + short_len].to_vec()).unwrap(), "qs1ccc");
        }
    }

    /// 🔴 An unknown kind must be skippable by length. This is the property the
    /// blob was chosen for, so it is asserted from the CONSUMER's side: walking
    /// with no knowledge of what a kind means must still reach the end exactly.
    #[test]
    fn an_unknown_kind_is_skippable_by_length() {
        let mut led = empty_ledger();
        led.gaps = vec!["a".into(), "bb".into()];
        let mut blob = ledger_blob::encode_ledger(&led, &["a note".to_string()]);

        // Forge a record with a kind from the future, appended, and bump the count.
        let count = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        blob[0..4].copy_from_slice(&(count + 1).to_le_bytes());
        blob.extend_from_slice(&9999u16.to_le_bytes());
        blob.extend_from_slice(&5u32.to_le_bytes());
        blob.extend_from_slice(b"hello");

        let records = walk(&blob); // walk() asserts it accounts for every byte
        assert_eq!(records.len() as u32, count + 1);
        assert_eq!(records.last().unwrap().0, 9999);
        // And the records a v1 shell DOES know are unaffected by its presence.
        assert_eq!(
            records.iter().filter(|(k, _)| *k == ledger_blob::QMB_LEDGER_GAP).count(),
            2
        );
        assert_eq!(
            records.iter().filter(|(k, _)| *k == ledger_blob::QMB_LEDGER_NOTE).count(),
            1
        );
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
                const TYPES: [&str; 6] = ["qmb_wallet_t", "qmb_fetch_fn", "qmb_scan_t", "qmb_select_t", "qmb_spent_t", "qmb_pair_t"];
                assert!(
                    exported.contains(&name.as_str()) || TYPES.contains(&name.as_str()),
                    "header declares `{name}` which lib.rs does not export"
                );
            }
        }
    }

    /// The #246 pin, extended to the event-kind values (lab #432): the header's
    /// `#define QMB_EVENT_*` list and `events.rs`'s `pub const QMB_EVENT_*`
    /// list must be the same set with the same values, in both directions. The
    /// kind tags are ABI now — a tag that drifts between the two files is a
    /// consumer decoding the wrong event.
    #[test]
    fn the_header_and_the_events_module_pin_the_same_kind_values() {
        let header = include_str!("../include/qumbra_ffi.h");
        let src = include_str!("events.rs");

        let header_kinds: Vec<(String, u16)> = header
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("#define QMB_EVENT_")?;
                let mut it = rest.split_whitespace();
                let name = it.next()?.to_string();
                let value = it.next()?.parse().ok()?;
                Some((name, value))
            })
            .collect();
        let src_kinds: Vec<(String, u16)> = src
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("pub const QMB_EVENT_")?;
                let (name, tail) = rest.split_once(": u16 = ")?;
                let value = tail.trim_end_matches(';').parse().ok()?;
                Some((name.to_string(), value))
            })
            .collect();

        assert!(!header_kinds.is_empty(), "the header declares no event kinds");
        assert!(!src_kinds.is_empty(), "events.rs declares no event kinds");
        for (name, value) in &header_kinds {
            assert!(
                src_kinds.contains(&(name.clone(), *value)),
                "header declares QMB_EVENT_{name} = {value}, events.rs does not"
            );
        }
        for (name, value) in &src_kinds {
            assert!(
                header_kinds.contains(&(name.clone(), *value)),
                "events.rs declares QMB_EVENT_{name} = {value}, the header does not"
            );
        }
        // And the values the ABI already shipped with, by number — a renumber
        // that keeps both files in step is still a broken consumer.
        assert_eq!(crate::events::QMB_EVENT_OTHER, 0);
        assert_eq!(crate::events::QMB_EVENT_SELECTED, 1);
        assert_eq!(crate::events::QMB_EVENT_TREE, 2);
        assert_eq!(crate::events::QMB_EVENT_WARNING, 3);
        assert_eq!(crate::events::QMB_EVENT_COINBASE_UNAVAILABLE, 4);
    }
}

// ── the paired-prover session (see `pairing`) ────────────────────────────────
//
// The pump a shell drives to have one spend proved by the user's own Mac. Same
// shape as `qmb_scan_*`: the kernel owns the protocol, the shell owns the
// socket. Every reason this split falls here rather than in Swift/TS is in
// `pairing.rs`'s header; the load-bearing one is that the client's stated
// obligation is a SHA3-256 check and CryptoKit has no SHA-3.

/// Open a session for one bundle. `uri` is the scanned `qumbra-prover://…`.
///
/// `scan_url`/`node_url` may be NULL for `operation = 0` (inspect) and are
/// REQUIRED for `operation = 1` (prove). Returns NULL with the reason in
/// `*err_out` — a bad pairing URI is the common case and it names itself.
///
/// # Safety
/// `uri`/`request_id` are NUL-terminated UTF-8; `bundle` has `bundle_len` bytes;
/// `err_out` is writable (or NULL).
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_new(
    uri: *const c_char,
    request_id: *const c_char,
    operation: u8,
    bundle: *const u8,
    bundle_len: usize,
    scan_url: *const c_char,
    node_url: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut pairing::Session {
    if uri.is_null() || request_id.is_null() || bundle.is_null() {
        set_err(err_out, "NULL argument".into());
        return ptr::null_mut();
    }
    let as_str = |p: *const c_char| -> Option<String> {
        if p.is_null() {
            None
        } else {
            CStr::from_ptr(p).to_str().ok().map(str::to_string)
        }
    };
    let Some(uri) = as_str(uri) else {
        set_err(err_out, "pairing URI is not UTF-8".into());
        return ptr::null_mut();
    };
    let Some(request_id) = as_str(request_id) else {
        set_err(err_out, "request_id is not UTF-8".into());
        return ptr::null_mut();
    };
    let operation = match operation {
        0 => pairing::Operation::Inspect,
        1 => pairing::Operation::Prove,
        other => {
            set_err(err_out, format!("operation {other} is not inspect(0) or prove(1)"));
            return ptr::null_mut();
        }
    };
    let bundle = std::slice::from_raw_parts(bundle, bundle_len);
    match pairing::Session::new(
        &uri,
        &request_id,
        operation,
        bundle,
        as_str(scan_url).as_deref(),
        as_str(node_url).as_deref(),
    ) {
        Ok(session) => Box::into_raw(Box::new(session)),
        Err(reason) => {
            set_err(err_out, reason);
            ptr::null_mut()
        }
    }
}

/// `host:port` to connect to — parsed from the URI by the kernel, so no shell
/// re-parses it and the secret never crosses this boundary at all.
///
/// # Safety
/// `p` is a live session from [`qmb_pair_new`].
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_endpoint(p: *const pairing::Session) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    out_string((*p).endpoint())
}

/// Hand the session whatever the socket produced — any length, including a
/// partial frame. TCP splits and coalesces; the reassembly is on this side.
///
/// # Safety
/// `p` live; `bytes` has `len` bytes (or `len` is 0).
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_supply(p: *mut pairing::Session, bytes: *const u8, len: usize) {
    if p.is_null() {
        return;
    }
    if bytes.is_null() || len == 0 {
        return;
    }
    (*p).supply(std::slice::from_raw_parts(bytes, len));
}

/// Advance the session.
///
/// ```text
///   1  SEND: write *out (*out_len bytes) to the socket, qmb_dealloc it, step again
///   2  NEED: read from the socket, qmb_pair_supply it, step again
///   0  DONE: take the transaction bytes with qmb_pair_take_artifact
///  -2  FAILED by name: the reason is in *err_out (qmb_string_free)
///  -1  NULL/invalid call
/// ```
///
/// 🔴 A shell MUST show the narration `qmb_pair_take_notes` returns. Proving runs
/// seconds to minutes and a silent minute reads as a hang — the same obligation
/// the select pump's event contract states, for the same reason.
///
/// # Safety
/// `p` live; `out`, `out_len`, `err_out` writable (or NULL for `err_out`).
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_step(
    p: *mut pairing::Session,
    out: *mut *mut u8,
    out_len: *mut usize,
    err_out: *mut *mut c_char,
) -> i32 {
    if p.is_null() || out.is_null() || out_len.is_null() {
        return -1;
    }
    *out = ptr::null_mut();
    *out_len = 0;
    match (*p).step() {
        pairing::Step::Send(frame) => {
            *out_len = frame.len();
            *out = Box::into_raw(frame.into_boxed_slice()) as *mut u8;
            1
        }
        pairing::Step::Need => 2,
        pairing::Step::Done => 0,
        pairing::Step::Failed(reason) => {
            set_err(err_out, reason);
            -2
        }
    }
}

/// The narration since the last call, as one UTF-8 text per line. NULL when
/// there is none — never an empty string, so "nothing to say" and "said
/// nothing" stay distinguishable.
///
/// # Safety
/// `p` is a live session.
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_take_notes(p: *mut pairing::Session) -> *mut c_char {
    if p.is_null() {
        return ptr::null_mut();
    }
    let notes = (*p).take_notes();
    if notes.is_empty() {
        return ptr::null_mut();
    }
    let lines: Vec<String> = notes
        .into_iter()
        .map(|note| match note {
            pairing::Note::Preflight => "checking anchors and nullifiers".to_string(),
            pairing::Note::Progress(text) => text,
            pairing::Note::Inspected(json) => json,
            pairing::Note::ArtifactStart { bytes, chunks } => {
                format!("receiving {bytes} bytes in {chunks} chunks")
            }
        })
        .collect();
    out_string(lines.join("\n"))
}

/// The transaction bytes, once [`qmb_pair_step`] returned 0.
///
/// 🔴 These bytes have already been checked against the length AND the SHA3-256
/// the prover announced — that is this module's whole reason for existing on the
/// ABI. Release with `qmb_dealloc(p, len)`. NULL with `*out_len = 0` when the
/// operation was an inspect, or when they have already been taken.
///
/// # Safety
/// `p` live; `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_take_artifact(
    p: *mut pairing::Session,
    out_len: *mut usize,
) -> *mut u8 {
    if p.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    match (*p).take_artifact() {
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

/// Drop the session. The pairing secret and the session key go with it.
///
/// # Safety
/// `p` came from [`qmb_pair_new`] and is not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn qmb_pair_free(p: *mut pairing::Session) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}
