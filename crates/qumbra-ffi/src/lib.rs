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

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;

use qlab_cbserver::client::{light_client_scan, light_client_scan_with, ScanConfig};
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

    /// The hand-maintained header and this file must declare the same ABI.
    #[test]
    fn the_header_names_every_exported_function_and_nothing_else() {
        let header = include_str!("../include/qumbra_ffi.h");
        let src = include_str!("lib.rs");
        let exported: Vec<&str> = src
            .lines()
            .filter_map(|l| {
                l.trim().strip_prefix("pub unsafe extern \"C\" fn ").and_then(|r| {
                    r.split('(').next()
                })
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
                const TYPES: [&str; 2] = ["qmb_wallet_t", "qmb_fetch_fn"];
                assert!(
                    exported.contains(&name.as_str()) || TYPES.contains(&name.as_str()),
                    "header declares `{name}` which lib.rs does not export"
                );
            }
        }
    }
}
