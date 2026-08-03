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

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use qlab_cbserver::client::{light_client_scan, ScanConfig};
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
                assert!(
                    exported.contains(&name.as_str()) || name == "qmb_wallet_t",
                    "header declares `{name}` which lib.rs does not export"
                );
            }
        }
    }
}
