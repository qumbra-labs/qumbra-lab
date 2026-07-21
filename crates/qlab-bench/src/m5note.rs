//! M5 note-encryption bench + acceptance tests.
//!
//! Bench mode `m5note`: single-core ML-KEM-768 decap/encap throughput, the
//! FO-skip compute-saving DECOMPOSITION (ml-kem 0.3.2 does not expose CPA-decap
//! — see `qlab_note::kem` — so the saving is estimated as re-encryption ≈
//! encap), and the amortized compact-entry bytes/note, each compared to
//! note-discovery.md / the survey's reference numbers.
//!
//! The `#[cfg(test)]` block is the AUTHORITATIVE M5 acceptance suite: it runs
//! under the full unfiltered `cargo test --release -p qlab-bench`, so the
//! qlab-air commitment cross-check and the round-trip/negative/amortization
//! cases are all seen by the acceptance command (CLAUDE.md bench discipline 5).

use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

use qlab_note::kem::{self, generate_keypair};
use qlab_note::wire::bytes_per_note_amortized;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Throughput batches; best (max throughput) reported, mirroring the repo's
/// best-of-N convention.
const BATCHES: usize = 5;
/// Operations timed per batch.
const OPS: usize = 20_000;

fn cmd_out(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn print_env(power: &str) {
    let cpu = cmd_out("sysctl", &["-n", "machdep.cpu.brand_string"]);
    let mem = cmd_out("sysctl", &["-n", "hw.memsize"]);
    let mem_gb = mem
        .parse::<u64>()
        .map(|b| format!("{} GiB", b >> 30))
        .unwrap_or(mem);
    let os = cmd_out("sw_vers", &["-productVersion"]);
    let rev = cmd_out(
        "git",
        &["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "--short", "HEAD"],
    );
    println!("- hardware: {cpu}, {mem_gb} RAM");
    println!("- OS: macOS {os}");
    println!("- qumbra-lab rev: {rev}");
    println!("- crypto: ml-kem 0.3.2 (FIPS 203), chacha20poly1305 0.11.0 (pinned)");
    println!("- power state: {power}");
}

/// Best per-op time in microseconds over `BATCHES` timed loops of `OPS`.
fn best_us(mut op: impl FnMut()) -> f64 {
    for _ in 0..1000 {
        op(); // warmup
    }
    let mut best = f64::INFINITY;
    for _ in 0..BATCHES {
        let t = Instant::now();
        for _ in 0..OPS {
            op();
        }
        best = best.min(t.elapsed().as_secs_f64());
    }
    1e6 * best / OPS as f64
}

pub fn run_m5note(power: &str) {
    println!("# qumbra-lab M5 note-encryption bench");
    println!();
    print_env(power);
    println!("- per op: best of {BATCHES} timed loops of {OPS}, single-core (sequential calls)");
    println!();

    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let kp = generate_keypair(&mut rng);
    let (ct, _k) = kem::encapsulate(&kp.ek, &mut rng);

    let decap_us = best_us(|| {
        black_box(kem::decapsulate(&kp.dk, black_box(&ct)));
    });
    let encap_us = best_us(|| {
        let (c, _) = kem::encapsulate(&kp.ek, &mut rng);
        black_box(c);
    });

    let decap_per_s = 1e6 / decap_us;
    let encap_per_s = 1e6 / encap_us;
    // FO-skip decomposition: skipped work = re-encryption (K-PKE.Encrypt) ≈
    // encap. encap is a slight UPPER proxy (also does m-sampling + G-hash), so
    // the reported saving is a mild upper bound. CPA-decap ≈ decap − encap.
    let foskip_us = (decap_us - encap_us).max(0.0);
    let foskip_per_s = if foskip_us > 0.0 { 1e6 / foskip_us } else { f64::INFINITY };
    let saved_pct = 100.0 * encap_us / decap_us;
    let speedup = if foskip_us > 0.0 { decap_us / foskip_us } else { f64::INFINITY };

    println!("## Per-note scan compute (single-core)");
    println!();
    println!("| op | µs/op | ops/s |");
    println!("|---|---|---|");
    println!("| full-FO decap (path a) | {decap_us:.3} | {decap_per_s:.0} |");
    println!("| encap (re-encryption proxy) | {encap_us:.3} | {encap_per_s:.0} |");
    println!("| **FO-skip decap (path b, decomposition est.)** | **{foskip_us:.3}** | **{foskip_per_s:.0}** |");
    println!();
    println!(
        "- FO-skip compute saved ≈ **{saved_pct:.1}%** (doc claims ~40–50%); \
         speedup factor ≈ **{speedup:.2}×**"
    );
    println!(
        "- survey reference: ML-KEM-768 decap ~10k ops/s on a low-end phone core \
         (Cortex-A72 NEON); this rig is a fast desktop core — the phone number is \
         the design-relevant one, and confirms compute is a non-issue (≥100× from binding)."
    );
    println!(
        "- CAVEAT: ml-kem 0.3.2 does not expose CPA-decap (pke::decrypt is pub(crate)); \
         path (b) is measured by decomposition, not a from-scratch CPA-decap. A \
         production FO-skip needs a KEM exposing CPA-decap (named remainder)."
    );
    println!();

    println!("## Amortized compact-entry bytes/note (wire layout)");
    println!();
    println!("| shape | bytes/note | doc reference |");
    println!("|---|---|---|");
    println!("| 1-of-1 (unamortized) | {} | ~1.1 KB (1,129 B) |", bytes_per_note_amortized(1));
    println!("| 2-of-1 (amortized) | {} | ~600 B (544-B ct share) |", bytes_per_note_amortized(2));
    println!("| 4-of-1 | {} | — |", bytes_per_note_amortized(4));
    println!();
    println!(
        "- layout: cm 32 B + tag 8 B + clue 1 B + ceil(1088/k) ct share; matches \
         note-discovery.md §2 (~600 B amortized, ~1.1 KB unamortized)."
    );
}

#[cfg(test)]
mod tests {
    use qlab_note::note::{note_commitment, Note};
    use qlab_note::scan::{encrypt_to_recipient, recompute_matches, scan, ScanMode};
    use qlab_note::wire::bytes_per_note_amortized;
    use qlab_note::{hash, kem::generate_keypair};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn note(seed: u64) -> Note {
        let lane = |k: u64| core::array::from_fn::<u64, 4, _>(|i| seed ^ (k << 8) ^ (i as u64 + 1));
        Note {
            value: 777 + seed,
            rkm: lane(1),
            rho: lane(2),
            rseed: lane(3),
        }
    }

    /// Hard-line cross-check, replicated in the acceptance crate: the M5
    /// commitment recompute is byte-identical to what qlab-air's circuit binds.
    #[test]
    fn commitment_matches_qlab_air() {
        use qlab_air::narrow::{build_bucket, TxInput, TxOutput};
        let o0 = note(1);
        let o1 = note(2);
        let fee = 7u64;
        let total = o0.value + o1.value + fee;
        let inputs = [
            TxInput { sk: [1, 2, 3, 4], value: total - 40, rho: [5, 6, 7, 8], rseed: [9, 10, 11, 12] },
            TxInput { sk: [13, 14, 15, 16], value: 40, rho: [17, 18, 19, 20], rseed: [21, 22, 23, 24] },
        ];
        let outputs = [
            TxOutput { value: o0.value, rkm: o0.rkm, rho: o0.rho, rseed: o0.rseed },
            TxOutput { value: o1.value, rkm: o1.rkm, rho: o1.rho, rseed: o1.rseed },
        ];
        let inst = build_bucket(18, &inputs, &outputs, fee);
        assert_eq!(note_commitment(o0.value, &o0.rkm, &o0.rho, &o0.rseed), inst.cm_out[0]);
        assert_eq!(o1.commitment(), inst.cm_out[1]);
    }

    #[test]
    fn roundtrip_both_paths() {
        let mut rng = StdRng::seed_from_u64(100);
        let kp = generate_keypair(&mut rng);
        let n = note(3);
        let out = encrypt_to_recipient(&kp.ek, &[n], &mut rng);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &out, mode);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].note, n);
        }
    }

    #[test]
    fn wrong_key_no_detection() {
        let mut rng = StdRng::seed_from_u64(101);
        let kp = generate_keypair(&mut rng);
        let attacker = generate_keypair(&mut rng);
        let out = encrypt_to_recipient(&kp.ek, &[note(4)], &mut rng);
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            assert!(scan(&attacker.dk, &out, mode).is_empty());
        }
    }

    #[test]
    fn tampered_ct_and_payload_fail() {
        let mut rng = StdRng::seed_from_u64(102);
        let kp = generate_keypair(&mut rng);
        // Tampered ML-KEM ct → tag miss.
        let mut out = encrypt_to_recipient(&kp.ek, &[note(5)], &mut rng);
        out.bundle.ct[42] ^= 0x01;
        assert!(scan(&kp.dk, &out, ScanMode::FoSkip).is_empty());
        // Tampered AEAD payload → Poly1305 rejects.
        let mut out2 = encrypt_to_recipient(&kp.ek, &[note(6)], &mut rng);
        let last = out2.payloads[0].len() - 1;
        out2.payloads[0][last] ^= 0x01;
        assert!(scan(&kp.dk, &out2, ScanMode::FullFo).is_empty());
    }

    #[test]
    fn tampered_cm_fails_recompute() {
        let n = note(7);
        let good = hash::digest_bytes(&n.commitment());
        assert!(recompute_matches(&n, &good));
        let mut bad = good;
        bad[3] ^= 0x80;
        assert!(!recompute_matches(&n, &bad));
    }

    #[test]
    fn amortization_two_of_one() {
        let mut rng = StdRng::seed_from_u64(103);
        let kp = generate_keypair(&mut rng);
        let n0 = note(20);
        let n1 = note(21);
        let out = encrypt_to_recipient(&kp.ek, &[n0, n1], &mut rng);
        assert_eq!(out.bundle.entries.len(), 2);
        assert_eq!(out.bundle.ct.len(), 1088, "one shared ct");
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let found = scan(&kp.dk, &out, mode);
            assert_eq!(found.len(), 2);
            assert_eq!(found[0].note, n0);
            assert_eq!(found[1].note, n1);
        }
    }

    #[test]
    fn bytes_per_note_matches_doc() {
        assert_eq!(bytes_per_note_amortized(1), 1129);
        assert_eq!(bytes_per_note_amortized(2), 585);
    }
}
