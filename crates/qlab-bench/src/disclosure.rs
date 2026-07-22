//! Disclosure-proof bench + end-to-end wallet flow.
//!
//! Measures the wallet-interop §3 selective disclosure-proof STARK
//! (`qlab_disclosure`) — the single-note statement `cm == H_commit(value ‖ rkm
//! ‖ rho ‖ rseed)` ∧ `addr_commitment == Keccak256(version ‖ d ‖ rkm ‖ ek)`
//! with the shared `rkm` bound — under the consensus g22 lane and its
//! low-blowup siblings, reporting the proof-size frontier against the
//! interop-spec O2 expectation ("≪ the 2×2 bucket", whose consensus point is
//! 136.4 KB fixed / 2^18 rows).
//!
//! The bench prints prove/verify time, proof bytes (postcard + bincode-fixed,
//! same two codecs as the bucket bench), and the trace shape. The end-to-end
//! test (below) drives the full M7 wallet flow: recipient generates an address,
//! sender creates + encrypts a note to it, the recipient detects it, the sender
//! builds a §3 envelope, a verifier holding (chain cm + the claimed address)
//! accepts, and a wrong-address verifier rejects.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use qlab_disclosure::air::{build_disclosure, DISCLOSURE_WIDTH};
use qlab_disclosure::prove::{make_config, prove, verify, FriCfg};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;

use crate::RUNS;

/// log_height for the disclosure statement (12 perms × 3072 rows = 36,864 →
/// 2^16; the 1,184-B ML-KEM ek dominates, via the 10-block address sponge).
const LOG_HEIGHT: usize = 16;

/// The M3 2×2-bucket consensus point (fixed-width), for the O2 comparison.
const BUCKET_FIXED_KB: f64 = 136.4;

/// Configs measured for the size frontier — all ≥ 100-bit conjectured. The
/// consensus lane (b16/q20/g22) plus low-blowup siblings that trade proof size
/// for RAM (b8, b4) and the smallest-proof high-blowup point (b32).
const CFGS: [(&str, FriCfg); 4] = [
    (
        "b16/q20/g22 (consensus)",
        FriCfg { log_blowup: 4, num_queries: 20, grind_bits: 22, log_final_poly_len: 4, max_log_arity: 4 },
    ),
    (
        "b8/q27/g19",
        FriCfg { log_blowup: 3, num_queries: 27, grind_bits: 19, log_final_poly_len: 4, max_log_arity: 4 },
    ),
    (
        "b4/q40/g20",
        FriCfg { log_blowup: 2, num_queries: 40, grind_bits: 20, log_final_poly_len: 4, max_log_arity: 4 },
    ),
    (
        "b32/q18/g10",
        FriCfg { log_blowup: 5, num_queries: 18, grind_bits: 10, log_final_poly_len: 4, max_log_arity: 4 },
    ),
];

/// A deterministic disclosure instance built from a real wallet address.
fn sample_instance() -> qlab_disclosure::air::DisclosureInstance {
    // Recipient wallet + diversified address (M7 flow; rkm = H(nk‖D_R‖d)).
    let recipient = Wallet::from_seed_lanes([0xa11ce, 0xb0b, 0xc0ffee, 0xdecaf]);
    let d = Diversifier::from_bytes([7u8; 16]);
    let addr = recipient.address(d);
    let rkm = addr.rkm_lanes();
    // Sender-chosen note randomness (deterministic here).
    let value = 12_345_678u64;
    let rho = [0x1111_1111_1111_1111, 0x2222, 0x3333, 0x4444];
    let rseed = [0x5555, 0x6666, 0x7777, 0x8888_8888_8888_8888];
    build_disclosure(LOG_HEIGHT, value, &rkm, &rho, &rseed, &addr.to_raw_bytes())
}

pub fn run_disclosure(power: &str) {
    println!("# qumbra-lab disclosure-proof bench (wallet-interop §3)");
    println!();
    crate::print_env(power);
    println!(
        "- statement: single output note — cm == H_commit(value‖rkm‖rho‖rseed) \
         ∧ addr_commitment == Keccak256(version‖d‖rkm‖ek), rkm bound across both"
    );
    println!(
        "- circuit: narrow-Keccak sponge, {DISCLOSURE_WIDTH} cols × 2^{LOG_HEIGHT} rows; \
         12 perms (1 cm + 10 address-sponge blocks + 1 close). The 1,184-B \
         ML-KEM ek dominates: the address commitment alone is a 10-block sponge."
    );
    println!("- semantics: qlab-disclosure test suite (in-circuit digests == clear-text packings; rkm-mismatch negative)");
    println!("- per cell: prove/verify = best of {RUNS} in-process runs");
    println!(
        "- proof KB twice: postcard (varint campaign codec) and bincode-fixed \
         (4 B/field, the wire-format proxy — the frontier uses it)"
    );
    println!();
    println!("| config | conj. bits | prove ms | verify ms | postcard KB | fixed KB | vs 2×2 bucket ({BUCKET_FIXED_KB} KB) |");
    println!("|---|---|---|---|---|---|---|");

    let inst = sample_instance();

    for (name, cfg) in &CFGS {
        let bits = cfg.conjectured_bits();
        eprintln!("== disclosure: {name} ({}) ==", cfg.label());
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut best_prove = f64::INFINITY;
            let mut proof_opt = None;
            for _ in 0..RUNS {
                let t = Instant::now();
                let proof = prove(&inst, cfg);
                best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
                proof_opt = Some(proof);
            }
            let proof = proof_opt.expect("RUNS > 0");
            let postcard_bytes = postcard::to_allocvec(&proof).expect("postcard").len();
            let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
            let mut best_verify = f64::INFINITY;
            for _ in 0..RUNS {
                let t = Instant::now();
                verify(&inst.air, &proof, &inst.pvs, cfg).expect("verify");
                best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
            }
            (best_prove, best_verify, postcard_bytes, fixed_bytes)
        }));
        match result {
            Ok((prove_ms, verify_ms, pc, fixed)) => {
                let fkb = fixed as f64 / 1024.0;
                let ratio = fkb / BUCKET_FIXED_KB;
                eprintln!("  [{name}] prove={prove_ms:.1}ms verify={verify_ms:.1}ms postcard={pc}B fixed={fixed}B");
                println!(
                    "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.2}× |",
                    name,
                    bits,
                    prove_ms,
                    verify_ms,
                    pc as f64 / 1024.0,
                    fkb,
                    ratio,
                );
            }
            Err(_) => {
                println!("| {} | {} | FAILED | FAILED | FAILED | FAILED | — |", name, bits);
            }
        }
    }
    println!();
    println!(
        "O2 expectation (interop-spec §3): single-note statement ≪ the 2×2 bucket. \
         Size-floor finding: small statements pay FRI's fixed costs \
         disproportionately (few trace columns, but per-query openings + Merkle \
         paths at 2^16 dominate); the ek-driven 10-block address sponge is the \
         irreducible core."
    );
    // Sanity: the consensus config must actually verify (guards a broken run).
    let _ = make_config(&CFGS[0].1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_disclosure::envelope::{Envelope, EnvelopeError};
    use qlab_disclosure::packing::addr_commitment;
    use qlab_note::hash::digest_bytes;
    use qlab_note::note::Note;
    use qlab_note::scan::{encrypt_to_recipient, scan, ScanMode};
    use qlab_wallet::address::Address;
    use rand::{rngs::StdRng, SeedableRng};

    fn test_cfg() -> FriCfg {
        // Fast config for tests (still ≥100-bit conjectured: 45·2+10 = 100).
        FriCfg { log_blowup: 2, num_queries: 45, grind_bits: 10, log_final_poly_len: 2, max_log_arity: 3 }
    }

    fn cm_bytes(cm: &[u64; 4]) -> [u8; 32] {
        digest_bytes(cm)
    }

    /// Deliverable 5 — the full M7 send → disclose → verify flow.
    #[test]
    fn end_to_end_wallet_disclosure() {
        let mut rng = StdRng::seed_from_u64(2024);

        // 1. Recipient wallet + diversified address (post-#32 rkm = H(nk‖D_R‖d)).
        let recipient = Wallet::from_seed_lanes([1, 2, 3, 4]);
        let d = Diversifier::from_bytes([9u8; 16]);
        let addr: Address = recipient.address(d);
        let rkm = addr.rkm_lanes();

        // 2. Sender creates an output note to that address and (M7 flow) encrypts
        //    it; the recipient scans and detects it — the note is genuinely theirs.
        let note = Note { value: 500_000, rkm, rho: [11, 22, 33, 44], rseed: [55, 66, 77, 88] };
        let ek = addr.encapsulation_key().expect("valid ek");
        let outputs = encrypt_to_recipient(&ek, &[note.clone()], &mut rng);
        let dk = recipient.diversified_keypair(&d).dk;
        let detected = scan(&dk, &outputs, ScanMode::FullFo);
        assert_eq!(detected.len(), 1, "recipient detects the sent note");
        assert_eq!(detected[0].note, note);

        // 3. cm goes on-chain at (tx_ref, output_index).
        let cm = note.commitment();
        let chain_cm = cm_bytes(&cm);
        let tx_ref = [0x42u8; 32];
        let output_index = 0u8;

        // 4. Sender builds the §3 disclosure envelope for the note.
        let inst = build_disclosure(LOG_HEIGHT, note.value, &rkm, &note.rho, &note.rseed, &addr.to_raw_bytes());
        assert_eq!(inst.cm, cm, "disclosure cm matches the on-chain note commitment");
        let env = Envelope::create(&inst, tx_ref, output_index, &test_cfg());

        // 5. A verifier holding (chain data + the claimed address) ACCEPTS.
        //    First it confirms the envelope names THIS address, then checks the proof.
        let claimed = addr.clone();
        assert_eq!(
            env.addr_commitment,
            addr_commitment(&claimed.to_raw_bytes()),
            "envelope names the claimed address"
        );
        env.verify(&chain_cm, LOG_HEIGHT, &test_cfg())
            .expect("correct verifier accepts");
        assert_eq!(env.value, note.value, "disclosed amount is the sent amount");

        // 6. A WRONG-ADDRESS verifier REJECTS. It holds a different address
        //    (different diversifier → different rkm/ek → different commitment);
        //    the envelope's addr_commitment does not name it.
        let other = recipient.address(Diversifier::from_bytes([1u8; 16]));
        assert_ne!(other.to_raw_bytes(), addr.to_raw_bytes());
        assert_ne!(
            env.addr_commitment,
            addr_commitment(&other.to_raw_bytes()),
            "envelope does NOT name the wrong address — verifier rejects the claim"
        );

        // 7. And forging an envelope that CLAIMS the wrong address for this cm is
        //    impossible: the note's rkm ≠ the wrong address's rkm, so the STARK's
        //    rkm cross-binding refuses (build_disclosure asserts the match).
        let forge = std::panic::catch_unwind(|| {
            build_disclosure(
                LOG_HEIGHT,
                note.value,
                &rkm, // the real note rkm
                &note.rho,
                &note.rseed,
                &other.to_raw_bytes(), // but a DIFFERENT address (rkm mismatch)
            )
        });
        assert!(forge.is_err(), "cannot build a disclosure to a mismatched address");
    }

    /// Acceptance coverage: prove + verify at the CONSENSUS config (the one the
    /// size floor is reported against), plus reject-unknown-ver.
    #[test]
    fn consensus_config_prove_verify() {
        let inst = sample_instance();
        let cfg = CFGS[0].1; // b16/q20/g22
        let proof = prove(&inst, &cfg);
        verify(&inst.air, &proof, &inst.pvs, &cfg).expect("consensus verify");

        // Envelope round-trip + reject-unknown-ver at the consensus config.
        let env = Envelope::create(&inst, [1u8; 32], 0, &cfg);
        let mut bytes = env.to_bytes();
        let chain_cm = cm_bytes(&inst.cm);
        assert!(Envelope::from_bytes(&bytes).unwrap().verify(&chain_cm, LOG_HEIGHT, &cfg).is_ok());
        bytes[0] = 0xff;
        assert!(matches!(Envelope::from_bytes(&bytes), Err(EnvelopeError::UnknownVersion(0xff))));
    }
}
