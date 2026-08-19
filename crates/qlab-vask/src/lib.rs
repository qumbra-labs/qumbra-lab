//! Exchange/VASP kit verifier lib — **stage 1** (lab #483).
//!
//! Verify the wallet-interop §3 deposit-disclosure envelope, no I/O — the
//! library an exchange links to refuse anonymous deposits at crediting time
//! (auditable-privacy §4 "Edge" layer). Inventory, layout grounds and the ABI
//! proposal this implements: `docs/kit-stage0-survey.md` (ratified at the
//! stage-0 boundary, lab #483 2026-08-18).
//!
//! ## What this crate is, and is not
//!
//! - **Verify-only by policy**: it re-exports no prover entry point, so the
//!   public surface stays the low-memory path an exchange links. The compile
//!   graph still carries the prover (p3-uni-stark ships prove+verify together
//!   — survey §2's dependency note, deliberately not oversold).
//! - **No chain model**: wallet-interop §3 rule 1 (tx exists + finalized) is
//!   the caller's chain lookup, exactly as `Envelope::verify` has it. The
//!   caller hands in the `chain_cm` it read at `(tx_ref, output_index)` on its
//!   finalized view; rules 2 and 3 happen here.
//! - **The FRI config is pinned, not a parameter** ([`DISCLOSURE_V1_CFG`]):
//!   `Envelope::verify` takes `log_height` + `FriCfg`, and a hostile or sloppy
//!   caller handing q=0/g=0 would "verify" anything. This crate pins the
//!   measured q20 point and exposes only [`QVASK_ABI_VERSION`]; a config
//!   change is a new ABI version — the chain's own versioned-parameter
//!   discipline.
//! - **The C ABI** (`qvask_*`) lives behind the #246 discipline: the
//!   hand-maintained `include/qvask.h` is pinned to this file in both
//!   directions by tests, function list and refusal-code values alike.
//!
//! Transport is out of scope by design: out-of-band envelope delivery is the
//! design of record (#483 stage-0 ruling — a deposit disclosure is a bilateral
//! depositor→exchange communication), and this library verifies bytes however
//! they arrived.

use std::ffi::{c_char, CString};

use qlab_disclosure::prove::FriCfg;

pub use qlab_disclosure::envelope::{Envelope, EnvelopeError, CLAIM_SENT_PAYMENT, ENVELOPE_VER};

/// The kit's pinned verification point — the disclosure lane's own constant,
/// decoupled from the consensus lane's numbering by design rather than by
/// drift (survey §1.1: `qlab_disclosure::prove::CONSENSUS_CFG` stayed q20 when
/// the consensus lane moved to q21 at B″; milestone-log.md:46 records why).
/// b16/q20/g22 = 102-bit conjectured; measured at this point: proof 121.9 KB
/// fixed, verify 26.0 ms (docs/disclosure-run1/2.md, M5 Max, reproduced
/// twice; recorded design-side at the stage-0 boundary — cite, don't
/// re-measure).
pub const DISCLOSURE_V1_CFG: FriCfg = FriCfg {
    log_blowup: 4,
    num_queries: 20,
    grind_bits: 22,
    log_final_poly_len: 0,
    max_log_arity: 4,
};

/// The disclosure AIR's height, pinned beside the config for the same reason:
/// the prover-side statement is 2^16 rows (survey §1.1), and a caller must
/// not be able to point the verifier at a different schedule.
pub const DISCLOSURE_V1_LOG_HEIGHT: usize = 16;

/// ABI + pinned-parameter version this library implements. Bumps when
/// [`DISCLOSURE_V1_CFG`] / [`DISCLOSURE_V1_LOG_HEIGHT`] / the envelope format
/// under verification / the `qvask_*` surface changes incompatibly.
pub const QVASK_ABI_VERSION: i32 = 1;

// --- the refusal taxonomy (the house pattern: named refusals, stable codes) --
//
// One stable negative code per refusal, mirrored as `#define QVASK_*` in
// include/qvask.h; the two lists are pinned to each other in both directions
// by `the_header_and_the_lib_pin_the_same_refusal_codes`, literals asserted —
// a renumber that keeps both files in step is still a broken consumer.

/// Verified: the claim is proven against the caller's chain cm.
pub const QVASK_OK: i32 = 0;
/// NULL args / contract violation (never a verdict about the envelope).
pub const QVASK_INVALID_CALL: i32 = -1;
/// Framing refused: truncated field, trailing bytes, varint.
pub const QVASK_MALFORMED: i32 = -2;
/// §3 rule 3: unknown envelope version — reject, never ignore.
pub const QVASK_UNKNOWN_VERSION: i32 = -3;
/// §3 rule 3: unknown claim type — reject, never ignore.
pub const QVASK_UNKNOWN_CLAIM_TYPE: i32 = -4;
/// proof_bytes did not deserialize into a proof structure.
pub const QVASK_PROOF_DECODE: i32 = -5;
/// §3 rule 2 failed: the proof does not verify against claim body + chain cm.
pub const QVASK_PROOF_INVALID: i32 = -6;

/// The claim fields an exchange matches against its deposit record — the §3
/// claim-0x01 body plus the tx binding, without the proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub tx_ref: [u8; 32],
    pub value: u64,
    pub addr_commitment: [u8; 32],
    pub output_index: u8,
}

impl Claim {
    fn of(env: &Envelope) -> Claim {
        Claim {
            tx_ref: env.tx_ref,
            value: env.value,
            addr_commitment: env.addr_commitment,
            output_index: env.output_index,
        }
    }
}

/// The kit's named refusals. Every [`EnvelopeError`] variant maps here — the
/// `From` impl matches exhaustively on purpose, so a new variant in
/// qlab-disclosure refuses to compile until this taxonomy decides its code,
/// instead of silently falling through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaskError {
    /// Framing refused (maps [`EnvelopeError::Malformed`]).
    Malformed(&'static str),
    /// §3 rule 3 (maps [`EnvelopeError::UnknownVersion`]).
    UnknownVersion(u8),
    /// §3 rule 3 (maps [`EnvelopeError::UnknownClaimType`]).
    UnknownClaimType(u8),
    /// Proof bytes are not a proof structure (maps [`EnvelopeError::ProofDecode`]).
    ProofDecode,
    /// §3 rule 2 failed; carries the verifier's why (maps [`EnvelopeError::ProofInvalid`]).
    ProofInvalid(String),
}

impl VaskError {
    /// The stable ABI code for this refusal (`QVASK_*`).
    pub fn code(&self) -> i32 {
        match self {
            VaskError::Malformed(_) => QVASK_MALFORMED,
            VaskError::UnknownVersion(_) => QVASK_UNKNOWN_VERSION,
            VaskError::UnknownClaimType(_) => QVASK_UNKNOWN_CLAIM_TYPE,
            VaskError::ProofDecode => QVASK_PROOF_DECODE,
            VaskError::ProofInvalid(_) => QVASK_PROOF_INVALID,
        }
    }

    /// The human-readable reason the ABI hands out through `reason_out`.
    pub fn reason(&self) -> String {
        match self {
            VaskError::Malformed(why) => format!("malformed envelope: {why}"),
            VaskError::UnknownVersion(v) => format!("unknown envelope version 0x{v:02x}"),
            VaskError::UnknownClaimType(t) => format!("unknown claim type 0x{t:02x}"),
            VaskError::ProofDecode => "proof bytes are not a proof structure".to_string(),
            VaskError::ProofInvalid(why) => format!("proof invalid: {why}"),
        }
    }
}

impl From<EnvelopeError> for VaskError {
    fn from(e: EnvelopeError) -> VaskError {
        match e {
            EnvelopeError::Malformed(why) => VaskError::Malformed(why),
            EnvelopeError::UnknownVersion(v) => VaskError::UnknownVersion(v),
            EnvelopeError::UnknownClaimType(t) => VaskError::UnknownClaimType(t),
            EnvelopeError::ProofDecode => VaskError::ProofDecode,
            EnvelopeError::ProofInvalid(why) => VaskError::ProofInvalid(why),
        }
    }
}

impl core::fmt::Display for VaskError {
    // Display IS reason(): the string a C consumer logs through reason_out
    // and the string a Rust consumer logs must be the same string.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl std::error::Error for VaskError {}

/// Parse WITHOUT verifying: extract the claim fields an exchange matches
/// against its deposit record before paying for verification (~26 ms). Full
/// framing checks run (§3 rule 3 included); the STARK does not.
pub fn peek(envelope: &[u8]) -> Result<Claim, VaskError> {
    Ok(Claim::of(&Envelope::from_bytes(envelope)?))
}

/// Verify per wallet-interop §3 rules 2–3 under the pinned
/// [`DISCLOSURE_V1_CFG`] / [`DISCLOSURE_V1_LOG_HEIGHT`]. `chain_cm` is the
/// commitment the caller read at `(tx_ref, output_index)` on its finalized
/// view — rule 1 stays the caller's. Returns the proven claim.
pub fn verify(envelope: &[u8], chain_cm: &[u8; 32]) -> Result<Claim, VaskError> {
    let env = Envelope::from_bytes(envelope)?;
    env.verify(chain_cm, DISCLOSURE_V1_LOG_HEIGHT, &DISCLOSURE_V1_CFG)?;
    Ok(Claim::of(&env))
}

// --- the qvask C ABI (survey §3, ratified; #246 header-pin discipline) ------
//
// Conventions, following qumbra-ffi's shipped ABI: int32_t returns, 0 =
// success, -1 = invalid call, -2 and below = named refusals; every returned
// buffer freed by the library's own free function; NULL out-params refused
// with -1 (#465's "cannot opt out" discipline — a consumer that cannot see
// the refusal reason ships blind refusals). No handles, no state, no
// callbacks: verification is a pure function, so the reentrancy/lifetime
// class of contract the pin test cannot pin never arises. Thread-safe by
// statelessness. All inputs are caller-owned and never retained.

/// The C mirror of [`Claim`] — layout pinned by
/// `the_claim_struct_layout_is_the_header_contract`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QvaskClaim {
    pub tx_ref: [u8; 32],
    pub value: u64,
    pub addr_commitment: [u8; 32],
    pub output_index: u8,
}

impl QvaskClaim {
    fn of(c: &Claim) -> QvaskClaim {
        QvaskClaim {
            tx_ref: c.tx_ref,
            value: c.value,
            addr_commitment: c.addr_commitment,
            output_index: c.output_index,
        }
    }
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// The ABI + pinned-parameter version this library implements (= 1).
#[no_mangle]
pub extern "C" fn qvask_abi_version() -> i32 {
    QVASK_ABI_VERSION
}

/// The envelope format version this library accepts (= 0x01, mirrors
/// `ENVELOPE_VER`; §3 rule 3 refuses anything else by name).
#[no_mangle]
pub extern "C" fn qvask_envelope_ver() -> u8 {
    ENVELOPE_VER
}

/// Parse WITHOUT verifying — see [`peek`]. `claim_out` is written only on
/// `QVASK_OK`. Refusals: `QVASK_MALFORMED` / `QVASK_UNKNOWN_VERSION` /
/// `QVASK_UNKNOWN_CLAIM_TYPE` (framing runs in full, so the proof-bytes
/// region must be present; its *contents* are not touched here).
///
/// # Safety
/// `envelope` must point to `envelope_len` readable bytes; `claim_out` must
/// be a valid, writable `qvask_claim_t`.
#[no_mangle]
pub unsafe extern "C" fn qvask_envelope_peek(
    envelope: *const u8,
    envelope_len: usize,
    claim_out: *mut QvaskClaim,
) -> i32 {
    if envelope.is_null() || claim_out.is_null() {
        return QVASK_INVALID_CALL;
    }
    let bytes = std::slice::from_raw_parts(envelope, envelope_len);
    match peek(bytes) {
        Ok(claim) => {
            *claim_out = QvaskClaim::of(&claim);
            QVASK_OK
        }
        Err(e) => e.code(),
    }
}

/// Verify — see [`verify`]. `chain_cm` is the 32-byte commitment the CALLER
/// read at `(tx_ref, output_index)` on its finalized view (§3 rule 1 stays
/// the caller's). `claim_out` is filled on ANY parse success — `QVASK_OK`,
/// `QVASK_PROOF_DECODE`, `QVASK_PROOF_INVALID` — so a refused claim can
/// still be logged against the deposit record. On refusal `*reason_out` is
/// set to a NUL-terminated reason; free it with `qvask_string_free`. On
/// `QVASK_OK`, `*reason_out` is NULL.
///
/// # Safety
/// `envelope` must point to `envelope_len` readable bytes; `chain_cm` to 32
/// readable bytes; `claim_out` and `reason_out` must be valid and writable.
#[no_mangle]
pub unsafe extern "C" fn qvask_verify(
    envelope: *const u8,
    envelope_len: usize,
    chain_cm: *const u8,
    claim_out: *mut QvaskClaim,
    reason_out: *mut *mut c_char,
) -> i32 {
    if envelope.is_null() || chain_cm.is_null() || claim_out.is_null() || reason_out.is_null() {
        return QVASK_INVALID_CALL;
    }
    *reason_out = std::ptr::null_mut();
    let bytes = std::slice::from_raw_parts(envelope, envelope_len);
    let cm: [u8; 32] = std::slice::from_raw_parts(chain_cm, 32).try_into().unwrap();

    let env = match Envelope::from_bytes(bytes) {
        Ok(env) => env,
        Err(e) => {
            let e = VaskError::from(e);
            *reason_out = to_c_string(e.reason());
            return e.code();
        }
    };
    // Parse succeeded: the claim is real even if the proof is not — fill it
    // before the verdict so a refusal is loggable against the deposit record.
    *claim_out = QvaskClaim::of(&Claim::of(&env));
    match env.verify(&cm, DISCLOSURE_V1_LOG_HEIGHT, &DISCLOSURE_V1_CFG) {
        Ok(()) => QVASK_OK,
        Err(e) => {
            let e = VaskError::from(e);
            *reason_out = to_c_string(e.reason());
            e.code()
        }
    }
}

/// Free a string returned through `reason_out`. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a pointer previously returned by this library through
/// `reason_out`, not yet freed.
#[no_mangle]
pub unsafe extern "C" fn qvask_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod citation_tests {
    //! The stage-0 inventory's citations, kept live (survey §1.1/§5) — now
    //! against the real stage-1 surface where stage 0 asserted proposals.

    use qlab_disclosure::air::{pv_vec, DisclosureAir, DisclosureInstance, PV_LEN};
    use qlab_disclosure::envelope::{Envelope, EnvelopeError, CLAIM_SENT_PAYMENT, ENVELOPE_VER};
    use qlab_disclosure::prove::{verify as stark_verify, DisclosureProof, FriCfg};

    /// Survey §1.1: the inventoried entry points exist with the inventoried
    /// signatures. Pure compile-time citations — nothing here proves.
    #[test]
    fn the_inventoried_entry_points_exist() {
        let _create: fn(&DisclosureInstance, [u8; 32], u8, &FriCfg) -> Envelope =
            Envelope::create;
        let _to_bytes: fn(&Envelope) -> Vec<u8> = Envelope::to_bytes;
        let _from_bytes: fn(&[u8]) -> Result<Envelope, EnvelopeError> = Envelope::from_bytes;
        let _verify: fn(&Envelope, &[u8; 32], usize, &FriCfg) -> Result<(), EnvelopeError> =
            Envelope::verify;
        let _stark_verify: fn(
            &DisclosureAir,
            &DisclosureProof,
            &[u32],
            &FriCfg,
        ) -> Result<(), String> = stark_verify;
        let _verifier_air: fn(usize) -> DisclosureAir = DisclosureAir::verifier;
    }

    /// Survey §1.1: envelope constants are the §3 values the kit pins.
    #[test]
    fn the_envelope_constants_are_the_spec_values() {
        assert_eq!(ENVELOPE_VER, 0x01);
        assert_eq!(CLAIM_SENT_PAYMENT, 0x01);
    }

    /// Survey §1.1: the public-value layout the verifier reconstructs is
    /// 36 u32 chunks (cm 16 ‖ addr 16 ‖ value 4). No trace, no proof.
    #[test]
    fn the_pv_layout_is_36_chunks() {
        assert_eq!(PV_LEN, 36);
        assert_eq!(pv_vec(&[0u64; 4], &[0u64; 4], 0).len(), PV_LEN);
    }

    /// Survey §1.1: the witness-free verifier AIR constructs at the pinned
    /// height without any witness or proving.
    #[test]
    fn the_verifier_air_constructs_witness_free() {
        let _ = DisclosureAir::verifier(crate::DISCLOSURE_V1_LOG_HEIGHT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::mem::{offset_of, size_of};
    use std::ptr;

    fn fixture(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    /// The committed peek fixture's claim fields (fixtures/README.md).
    fn peek_fixture_claim() -> Claim {
        Claim {
            tx_ref: core::array::from_fn(|i| i as u8),
            value: 42_000_000,
            addr_commitment: core::array::from_fn(|i| 0xa0 + i as u8),
            output_index: 7,
        }
    }

    /// The V1 pin is the measured q20 point — the disclosure lane's own
    /// constant (survey §1.1; the consensus lane's numbering moved to q21 at
    /// B″ and this deliberately does not follow it). Literals on purpose: a
    /// drifted pin must fail here, not re-derive itself.
    #[test]
    fn the_v1_pin_is_the_measured_q20_point() {
        assert_eq!(DISCLOSURE_V1_CFG.log_blowup, 4);
        assert_eq!(DISCLOSURE_V1_CFG.num_queries, 20);
        assert_eq!(DISCLOSURE_V1_CFG.grind_bits, 22);
        assert_eq!(DISCLOSURE_V1_CFG.log_final_poly_len, 0);
        assert_eq!(DISCLOSURE_V1_CFG.max_log_arity, 4);
        assert_eq!(DISCLOSURE_V1_CFG.conjectured_bits(), 102);
        assert_eq!(DISCLOSURE_V1_CFG.label(), "b16/q20/g22/a16");
        assert_eq!(DISCLOSURE_V1_LOG_HEIGHT, 16);
        assert_eq!(QVASK_ABI_VERSION, 1);
    }

    /// Every EnvelopeError variant maps to a stable code, exhaustively (the
    /// From impl refuses to compile on a new variant), and the shipped code
    /// values hold by literal — a renumber is a broken consumer.
    #[test]
    fn the_refusal_taxonomy_covers_every_variant_with_stable_codes() {
        assert_eq!(VaskError::from(EnvelopeError::Malformed("x")).code(), -2);
        assert_eq!(VaskError::from(EnvelopeError::UnknownVersion(2)).code(), -3);
        assert_eq!(VaskError::from(EnvelopeError::UnknownClaimType(3)).code(), -4);
        assert_eq!(VaskError::from(EnvelopeError::ProofDecode).code(), -5);
        assert_eq!(
            VaskError::from(EnvelopeError::ProofInvalid("why".into())).code(),
            -6
        );
        assert_eq!(QVASK_OK, 0);
        assert_eq!(QVASK_INVALID_CALL, -1);
    }

    /// peek extracts the claim from the committed fixture without touching
    /// the (garbage) proof bytes; verify on the same bytes refuses at the
    /// proof-decode gate — the "match the deposit record before paying for
    /// verification" split the ABI exists for.
    #[test]
    fn peek_returns_the_claim_without_verifying() {
        let bytes = fixture("peek-claim-v1.bin");
        assert_eq!(peek(&bytes).expect("peek"), peek_fixture_claim());
        assert_eq!(
            verify(&bytes, &[0u8; 32]).unwrap_err(),
            VaskError::ProofDecode
        );
    }

    /// Each committed refusal fixture refuses by its documented name
    /// (fixtures/README.md is the manifest this test locks).
    #[test]
    fn the_refusal_fixtures_refuse_by_name() {
        assert!(matches!(
            peek(&fixture("refuse-unknown-version.bin")),
            Err(VaskError::UnknownVersion(0x02))
        ));
        assert!(matches!(
            peek(&fixture("refuse-unknown-claim.bin")),
            Err(VaskError::UnknownClaimType(0x03))
        ));
        assert!(matches!(
            peek(&fixture("refuse-truncated.bin")),
            Err(VaskError::Malformed(_))
        ));
        assert!(matches!(
            peek(&fixture("refuse-trailing.bin")),
            Err(VaskError::Malformed("trailing bytes"))
        ));
        assert!(matches!(
            peek(&fixture("refuse-varint-truncated.bin")),
            Err(VaskError::Malformed("varint truncated"))
        ));
    }

    /// The ABI refuses NULL args with QVASK_INVALID_CALL — never a verdict.
    #[test]
    fn the_abi_refuses_null_args_with_invalid_call() {
        let bytes = fixture("peek-claim-v1.bin");
        let mut claim = QvaskClaim::of(&peek_fixture_claim());
        let mut reason: *mut c_char = ptr::null_mut();
        let cm = [0u8; 32];
        unsafe {
            assert_eq!(
                qvask_envelope_peek(ptr::null(), 0, &mut claim),
                QVASK_INVALID_CALL
            );
            assert_eq!(
                qvask_envelope_peek(bytes.as_ptr(), bytes.len(), ptr::null_mut()),
                QVASK_INVALID_CALL
            );
            assert_eq!(
                qvask_verify(ptr::null(), 0, cm.as_ptr(), &mut claim, &mut reason),
                QVASK_INVALID_CALL
            );
            assert_eq!(
                qvask_verify(bytes.as_ptr(), bytes.len(), ptr::null(), &mut claim, &mut reason),
                QVASK_INVALID_CALL
            );
            assert_eq!(
                qvask_verify(
                    bytes.as_ptr(),
                    bytes.len(),
                    cm.as_ptr(),
                    ptr::null_mut(),
                    &mut reason
                ),
                QVASK_INVALID_CALL
            );
            // reason_out is an out-param the caller cannot opt out of (#465):
            // a consumer that cannot see the refusal reason ships blind
            // refusals.
            assert_eq!(
                qvask_verify(bytes.as_ptr(), bytes.len(), cm.as_ptr(), &mut claim, ptr::null_mut()),
                QVASK_INVALID_CALL
            );
            // And the free function is NULL-safe, like qmb_string_free.
            qvask_string_free(ptr::null_mut());
        }
    }

    /// The ABI end-to-end on the committed fixtures (no proving): peek fills
    /// the exact claim; verify refuses the garbage proof at -5 WITH the claim
    /// still filled (parse succeeded — the refusal is loggable) and a reason
    /// string the caller frees; framing refusals return their named codes.
    #[test]
    fn the_abi_peeks_and_names_refusals_over_the_fixtures() {
        let bytes = fixture("peek-claim-v1.bin");
        let want = peek_fixture_claim();
        unsafe {
            let mut claim = std::mem::zeroed::<QvaskClaim>();
            assert_eq!(
                qvask_envelope_peek(bytes.as_ptr(), bytes.len(), &mut claim),
                QVASK_OK
            );
            assert_eq!(claim.tx_ref, want.tx_ref);
            assert_eq!(claim.value, want.value);
            assert_eq!(claim.addr_commitment, want.addr_commitment);
            assert_eq!(claim.output_index, want.output_index);

            let mut claim2 = std::mem::zeroed::<QvaskClaim>();
            let mut reason: *mut c_char = ptr::null_mut();
            let cm = [0u8; 32];
            assert_eq!(
                qvask_verify(bytes.as_ptr(), bytes.len(), cm.as_ptr(), &mut claim2, &mut reason),
                QVASK_PROOF_DECODE
            );
            assert_eq!(claim2.tx_ref, want.tx_ref, "claim filled on parse success");
            assert!(!reason.is_null(), "refusals carry a reason");
            let why = CStr::from_ptr(reason).to_str().unwrap();
            assert!(why.contains("proof"), "{why}");
            qvask_string_free(reason);

            let bad = fixture("refuse-unknown-version.bin");
            let mut reason2: *mut c_char = ptr::null_mut();
            let mut claim3 = std::mem::zeroed::<QvaskClaim>();
            assert_eq!(
                qvask_verify(bad.as_ptr(), bad.len(), cm.as_ptr(), &mut claim3, &mut reason2),
                QVASK_UNKNOWN_VERSION
            );
            assert!(!reason2.is_null());
            qvask_string_free(reason2);

            assert_eq!(qvask_abi_version(), 1);
            assert_eq!(qvask_envelope_ver(), 0x01);
        }
    }

    /// qvask_claim_t's layout IS the header's struct, by number — offsets and
    /// size asserted so a field reorder in either file fails here before it
    /// misdecodes in a consumer.
    #[test]
    fn the_claim_struct_layout_is_the_header_contract() {
        assert_eq!(offset_of!(QvaskClaim, tx_ref), 0);
        assert_eq!(offset_of!(QvaskClaim, value), 32);
        assert_eq!(offset_of!(QvaskClaim, addr_commitment), 40);
        assert_eq!(offset_of!(QvaskClaim, output_index), 72);
        assert_eq!(size_of::<QvaskClaim>(), 80);
    }

    /// The #246 pin: the hand-maintained header and this file declare the
    /// same ABI — every exported function appears in the header, and the
    /// header declares nothing this file does not export.
    #[test]
    fn the_header_names_every_exported_function_and_nothing_else() {
        let header = include_str!("../include/qvask.h");
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
        // And nothing in the header that the source does not export — every
        // qvask_ token on every line, not just the first (stricter than the
        // qumbra-ffi original on purpose: a second declaration on a shared
        // line must not slip through).
        const TYPES: [&str; 1] = ["qvask_claim_t"];
        for line in header.lines() {
            let mut rest = line;
            while let Some(pos) = rest.find("qvask_") {
                let name: String = rest[pos..]
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                assert!(
                    exported.contains(&name.as_str()) || TYPES.contains(&name.as_str()),
                    "header declares `{name}` which lib.rs does not export"
                );
                rest = &rest[pos + name.len()..];
            }
        }
    }

    /// The #465 extension of the pin: the header's `#define QVASK_*` list and
    /// this file's `pub const QVASK_*` list are the same set with the same
    /// values, in both directions — plus the shipped values by literal, since
    /// a renumber that keeps both files in step is still a broken consumer.
    #[test]
    fn the_header_and_the_lib_pin_the_same_refusal_codes() {
        let header = include_str!("../include/qvask.h");
        let src = include_str!("lib.rs");

        let header_codes: Vec<(String, i32)> = header
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("#define QVASK_")?;
                let mut it = rest.split_whitespace();
                let name = it.next()?.to_string();
                let value = it.next()?.parse().ok()?;
                Some((name, value))
            })
            .collect();
        let src_codes: Vec<(String, i32)> = src
            .lines()
            .filter_map(|l| {
                let rest = l.trim().strip_prefix("pub const QVASK_")?;
                let (name, tail) = rest.split_once(": i32 = ")?;
                let value = tail.trim_end_matches(';').parse().ok()?;
                Some((name.to_string(), value))
            })
            .collect();

        assert!(!header_codes.is_empty(), "the header declares no codes");
        assert!(!src_codes.is_empty(), "lib.rs declares no codes");
        for (name, value) in &header_codes {
            assert!(
                src_codes.contains(&(name.clone(), *value)),
                "header declares QVASK_{name} = {value}, lib.rs does not"
            );
        }
        for (name, value) in &src_codes {
            assert!(
                header_codes.contains(&(name.clone(), *value)),
                "lib.rs declares QVASK_{name} = {value}, the header does not"
            );
        }
        // The shipped values, by number.
        assert_eq!(QVASK_OK, 0);
        assert_eq!(QVASK_INVALID_CALL, -1);
        assert_eq!(QVASK_MALFORMED, -2);
        assert_eq!(QVASK_UNKNOWN_VERSION, -3);
        assert_eq!(QVASK_UNKNOWN_CLAIM_TYPE, -4);
        assert_eq!(QVASK_PROOF_DECODE, -5);
        assert_eq!(QVASK_PROOF_INVALID, -6);
    }
}
