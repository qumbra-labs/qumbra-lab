//! `qumbra-node emission-pins` — print the activation pins of the emission-rule
//! boundary as pasteable Rust literals (lab #299 + #303, ruling clause 3).
//!
//! # Why this is a command and not a comment
//!
//! Ruling clause 3 says pre-boundary accounting **pins, it does not recompute**,
//! and the values to pin are the ones the historical `f64` schedule produced *on
//! the platform the chain was mined on*. This rig is Apple silicon; the fleet is
//! Linux/glibc-aarch64; #303 measured them disagreeing. So a builder session
//! cannot produce these numbers — only a glibc host can, and "T-ops computes them
//! at activation" is only an executable instruction if there is something to run.
//!
//! This is that something. It is **pure**: no data dir, no chain, no network. Every
//! pin is a function of the FROZEN constants and [`RULE_BOUNDARY_HEIGHT`] alone,
//! which is what makes them independently reproducible — anyone with the binary can
//! rerun it and compare, and the chain's own attested rows are the second witness.
//!
//! Usage at activation:
//!
//! ```text
//!   # on a Linux/glibc host, from the release image
//!   qumbra-node emission-pins
//!   # paste the three blocks into qlab_node::emission and qlab_node::supply
//! ```
//!
//! The pins do not change any row on a glibc node — the unpinned fallback *is* the
//! historical walk. They change what a **non-glibc** node computes, which is the
//! whole point: T1 invites strangers' hardware, and an audit anchor that depends on
//! the auditor's libc is not an anchor.

use qlab_devnet::params_devnet::EPOCH_LENGTH_BLOCKS;
use qlab_node::emission::{coinbase_pre_boundary, s_atomic_pre_boundary, RewardSplit};
use qlab_node::emission::RULE_BOUNDARY_HEIGHT;

/// One epoch that lies wholly at or below the boundary, with the expected issuance
/// the historical schedule attributes to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochPinRow {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub expected_coinbase: u64,
}

/// The three pins, computed on **this** host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pins {
    /// `S_atomic(RULE_BOUNDARY_HEIGHT + 1)` — every bessel issued through the
    /// boundary block.
    pub s_atomic_at_boundary: u64,
    /// `Σ_{h ≤ RULE_BOUNDARY_HEIGHT} 15 % share` — the committee accrual ledger's
    /// grandfathered prefix.
    pub committee_accrual_at_boundary: u64,
    /// Every epoch whose end is at or below the boundary. The straddling epoch is
    /// **not** here: its prefix is recorded, not pinned as a closed form (rider 2).
    pub epochs: Vec<EpochPinRow>,
}

/// Compute the pins from the frozen constants and the historical schedule.
pub fn compute() -> Pins {
    let boundary = RULE_BOUNDARY_HEIGHT;
    let mut epochs = Vec::new();
    let mut epoch = 0u64;
    loop {
        let start = epoch * EPOCH_LENGTH_BLOCKS;
        let end = start + EPOCH_LENGTH_BLOCKS - 1;
        if end > boundary {
            break;
        }
        // Genesis mints nothing and the first mined block is height 1.
        let first_mint = start.max(1);
        epochs.push(EpochPinRow {
            epoch,
            start_height: start,
            end_height: end,
            expected_coinbase: s_atomic_pre_boundary(end + 1) - s_atomic_pre_boundary(first_mint),
        });
        epoch += 1;
    }
    Pins {
        s_atomic_at_boundary: s_atomic_pre_boundary(boundary + 1),
        committee_accrual_at_boundary: (0..=boundary)
            .map(|h| RewardSplit::of(coinbase_pre_boundary(h)).committee)
            .sum(),
        epochs,
    }
}

/// Render the pins as the exact Rust literals to paste, with the destination of
/// each named. Deliberately verbose: an operator pasting consensus constants should
/// be able to read where each one goes without opening the task book.
pub fn render(pins: &Pins) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# emission-rule activation pins (lab #299 + #303)\n\
         # RULE_BOUNDARY_HEIGHT = {}\n\
         # Run on a Linux/glibc host: these are the HISTORICAL (f64) schedule's\n\
         # values, and #303 measured that they differ between C libraries.\n\
         # This host: {} / {}\n\n",
        RULE_BOUNDARY_HEIGHT,
        std::env::consts::OS,
        std::env::consts::ARCH,
    ));
    out.push_str("// --- paste into crates/qlab-node/src/emission.rs ---\n");
    out.push_str(&format!(
        "pub const PINNED_S_ATOMIC_AT_BOUNDARY: Option<u64> = Some({});\n",
        pins.s_atomic_at_boundary
    ));
    out.push_str(&format!(
        "pub const PINNED_COMMITTEE_ACCRUAL_AT_BOUNDARY: Option<u64> = Some({});\n\n",
        pins.committee_accrual_at_boundary
    ));
    out.push_str("// --- paste into crates/qlab-node/src/supply.rs ---\n");
    out.push_str("pub const PINNED_EPOCH_EXPECTED: &[EpochPin] = &[\n");
    for row in &pins.epochs {
        out.push_str(&format!(
            "    ({}, {}), // heights {}..={}\n",
            row.epoch, row.expected_coinbase, row.start_height, row.end_height
        ));
    }
    out.push_str("];\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary at 18,000 with 1,152-block epochs pins **15** whole epochs
    /// (0..=14) and leaves epoch 15 straddling — the count the stamp corrected from
    /// the ruling's "~5–9 epochs" estimate.
    #[test]
    fn fifteen_whole_epochs_are_pinned_and_the_straddler_is_not() {
        let pins = compute();
        assert_eq!(pins.epochs.len(), 15);
        assert_eq!(pins.epochs[0].epoch, 0);
        assert_eq!(pins.epochs[14].epoch, 14);
        assert_eq!(pins.epochs[14].end_height, 17_279);
        assert!(
            pins.epochs.iter().all(|r| r.end_height <= RULE_BOUNDARY_HEIGHT),
            "a pinned epoch must lie wholly at or below the boundary"
        );
        assert!(
            !pins.epochs.iter().any(|r| r.epoch == 15),
            "epoch 15 straddles; its prefix is recorded, never pinned as a closed form"
        );
    }

    /// The pins are the values the **unpinned fallback** computes on this host — so
    /// pasting the output of this command on the host that produced it is a no-op,
    /// and pasting it from a different libc is exactly the change intended.
    #[test]
    fn the_pins_reproduce_this_hosts_unpinned_behaviour() {
        let pins = compute();
        assert_eq!(pins.s_atomic_at_boundary, qlab_node::emission::s_atomic_at_boundary());
        // Row-for-row against the attestation's own unpinned expected side.
        let ledger_rows = qlab_node::supply_by_epoch(
            (0..=17_279u64).map(|height| qlab_node::SupplyBlock {
                height,
                coinbase: if height == 0 { 0 } else { qlab_node::coinbase(height) },
                fees: 0,
            }),
            EPOCH_LENGTH_BLOCKS,
        )
        .expect("contiguous from genesis");
        assert_eq!(ledger_rows.len(), 15);
        for (row, pin) in ledger_rows.iter().zip(&pins.epochs) {
            assert_eq!(row.epoch, pin.epoch);
            assert_eq!(row.expected_coinbase, pin.expected_coinbase);
        }
    }

    /// The rendered text names every destination and carries the host, because a
    /// pin produced on the wrong platform is the one mistake this command can make.
    #[test]
    fn the_rendered_pins_name_their_destinations_and_the_host() {
        let text = render(&compute());
        assert!(text.contains("PINNED_S_ATOMIC_AT_BOUNDARY: Option<u64> = Some("));
        assert!(text.contains("PINNED_COMMITTEE_ACCRUAL_AT_BOUNDARY: Option<u64> = Some("));
        assert!(text.contains("PINNED_EPOCH_EXPECTED: &[EpochPin] = &["));
        assert!(text.contains("crates/qlab-node/src/emission.rs"));
        assert!(text.contains("crates/qlab-node/src/supply.rs"));
        assert!(text.contains(std::env::consts::OS));
        assert!(text.contains("(14, "), "the last pinned epoch must appear");
    }
}
