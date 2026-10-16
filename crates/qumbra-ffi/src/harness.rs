//! **The harness-only kernel** (lab #937 cut-over, D-C6). A release kernel
//! pins its prover per network at compile time (`prover_pins::PINS`) and
//! asserts the test registry off, so it can pay no prover on a fixture chain:
//! a shell's harness could replay a paid format-34 spend only up to the
//! `NotPinned` refusal. This module, behind this crate's `harness-pins`
//! feature (never default; it turns on `qumbra-wallet/fixture-pins`), lets a
//! harness register the pin of a **fixture** chain whose genesis hash it
//! computed, then replay the recorder's paid cases through the same exports a
//! release kernel has.
//!
//! **Never packaged.** The artifact is built under its own name
//! (`scripts/build-harness-wasm.sh` → `qumbra_ffi_harness.wasm`, its own
//! target directory), and every export here carries the `qmb_harness_`
//! prefix: a packager refuses any `.wasm` whose bytes name it
//! (`scripts/refuse-harness-wasm.sh`). Not in `include/qumbra_ffi.h`: no
//! shell calls it.

use std::ffi::{c_char, CStr};

use crate::set_err;

/// Pin `payee` (a full version-2 address) at most `max_s` / `max_p` fee
/// units as the prover of the fixture net whose genesis hash is the 32
/// bytes at `genesis`. Returns 0, or -1 with `*err_out` why (a NULL, a payee
/// that is not UTF-8 or not a version-2 address). A later pin of the same
/// genesis replaces it.
///
/// # Safety
/// `genesis` 32 readable bytes; `payee` NUL-terminated; `err_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn qmb_harness_pin_fixture(
    genesis: *const u8,
    payee: *const c_char,
    max_s: u64,
    max_p: u64,
    err_out: *mut *mut c_char,
) -> i32 {
    if !err_out.is_null() {
        *err_out = std::ptr::null_mut();
    }
    if genesis.is_null() || payee.is_null() {
        set_err(err_out, "NULL argument".into());
        return -1;
    }
    let Ok(payee) = CStr::from_ptr(payee).to_str() else {
        set_err(err_out, "the payee is not UTF-8".into());
        return -1;
    };
    let decoded = qlab_wallet::address::Address::decode_any(payee.trim())
        .ok_or_else(|| "the payee is not an address".to_string())
        .and_then(|a| a.require_version(qlab_wallet::address::ADDRESS_VERSION_CANDIDATE_A).map_err(|e| e.to_string()));
    if let Err(why) = decoded {
        set_err(err_out, why);
        return -1;
    }
    let mut g = [0u8; 32];
    g.copy_from_slice(std::slice::from_raw_parts(genesis, 32));
    qumbra_wallet::prover_pins::pin_fixture(
        g,
        qumbra_wallet::prover_pins::ProverPin {
            payee: payee.trim().to_string(),
            max_price: qumbra_wallet::annulet_plan::ProverPrice { s: max_s, p: max_p },
        },
    );
    0
}
