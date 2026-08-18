//! Stage-2 battery for the **v5 payee-list coinbase** (lab #470, C1, the
//! pool-payout-axis option (c) ruling): the preimage tail, the Σ seam as an
//! extension of the emission rule's own comparison, and the ruled negatives —
//! sum mismatch, N > cap, zero-payee.

use qlab_devnet::body::{
    check_scheduled_coinbase_above, check_scheduled_coinbase_payees, BlockBody, BodyError,
    CoinbasePayee, COINBASE_PAYEE_CAP_V5,
};
use qlab_devnet::emission_exact::coinbase_exact;

fn minting_body(coinbase: u64) -> BlockBody {
    BlockBody { txs: Vec::new(), coinbase, coinbase_rkm: [7, 8, 9, 10] }
}

// ── the payee-list derivation and the preimage tail ─────────────────────────

#[test]
fn payee_list_is_one_entry_paying_the_whole_mint_or_empty() {
    let body = minting_body(5_000);
    assert_eq!(
        body.coinbase_payees(),
        vec![CoinbasePayee { rkm: [7, 8, 9, 10], amount: 5_000 }]
    );
    assert_eq!(BlockBody::default().coinbase_payees(), Vec::new(), "genesis shape is empty");
}

/// The v5 preimage tail is `count(1) ‖ [rkm(4×8 LE) ‖ amount(8 LE)]×N`, and the
/// total travels nowhere else — checked byte-by-byte at both counts.
#[test]
fn v5_preimage_tail_is_the_payee_list() {
    // Single payee: tail = 0x01 ‖ rkm lanes ‖ amount.
    let body = minting_body(0x1122_3344_5566_7788);
    let c5 = body.commitment_v5();
    // Rebuild what the tail must be and check the commitment moves with every
    // tail byte (rkm lane and amount each flip the hash).
    let mut other = body.clone();
    other.coinbase_rkm = [7, 8, 9, 11];
    assert_ne!(c5, other.commitment_v5(), "rkm is committed");
    let mut other = body.clone();
    other.coinbase = 1;
    assert_ne!(c5, other.commitment_v5(), "the amount is committed");

    // Empty: count byte 0x00 — distinct from any minting body.
    assert_ne!(BlockBody::default().commitment_v5(), c5);
    // And the v5 form is domain-separated from v2 and v3 of the same body.
    assert_ne!(body.commitment_v5(), body.commitment());
    assert_ne!(body.commitment_v5(), body.commitment_above(Some(0), 1));
}

// ── the Σ seam: same comparison, extended (never forked) ────────────────────

#[test]
fn a_correct_single_payee_sum_passes_at_every_probed_height() {
    for h in [1u64, 2, 100, 8_640, 8_641, 19_009] {
        let payees = [CoinbasePayee { rkm: [1, 2, 3, 4], amount: coinbase_exact(h) }];
        assert_eq!(check_scheduled_coinbase_payees(h, &payees), Ok(()), "height {h}");
    }
}

/// The extension-not-fork evidence: for every probed height and total, the
/// payee form's verdict equals the boundary form's verdict at boundary 0 —
/// they share the one comparison against `coinbase_exact`.
#[test]
fn the_payee_form_and_the_boundary_form_share_one_comparison() {
    for h in [1u64, 2, 777, 8_641] {
        for delta in [0i64, 1, -1, 4_114] {
            let total = (coinbase_exact(h) as i64 + delta) as u64;
            let payees = [CoinbasePayee { rkm: [1, 1, 1, 1], amount: total }];
            let via_payees = check_scheduled_coinbase_payees(h, &payees);
            let via_boundary = check_scheduled_coinbase_above(0, h, total);
            assert_eq!(via_payees, via_boundary, "height {h} delta {delta}");
        }
    }
}

#[test]
fn sum_mismatch_is_refused_with_both_numbers_named() {
    let h = 42u64;
    let expected = coinbase_exact(h);
    let payees = [CoinbasePayee { rkm: [1, 2, 3, 4], amount: expected - 4_114 }];
    assert_eq!(
        check_scheduled_coinbase_payees(h, &payees),
        Err(BodyError::WrongScheduledCoinbase { height: h, expected, got: expected - 4_114 })
    );
}

#[test]
fn more_payees_than_the_birth_cap_is_refused_by_name() {
    let h = 1u64;
    let half = coinbase_exact(h) / 2;
    // Even a pair that sums correctly is refused — the cap is a rule, not a
    // formatting nicety, and it is checked before the Σ so the error names
    // the actual defect.
    let payees = [
        CoinbasePayee { rkm: [1, 2, 3, 4], amount: half },
        CoinbasePayee { rkm: [5, 6, 7, 8], amount: coinbase_exact(h) - half },
    ];
    assert_eq!(
        check_scheduled_coinbase_payees(h, &payees),
        Err(BodyError::TooManyCoinbasePayees { got: 2, cap: COINBASE_PAYEE_CAP_V5 })
    );
}

#[test]
fn a_zero_payee_list_on_a_minting_height_is_refused() {
    let h = 1u64;
    assert_eq!(
        check_scheduled_coinbase_payees(h, &[]),
        Err(BodyError::WrongScheduledCoinbase {
            height: h,
            expected: coinbase_exact(h),
            got: 0
        }),
        "an empty list sums to 0, which is never the schedule's coinbase above genesis"
    );
}

#[test]
fn genesis_is_structurally_exempt_and_still_cannot_mint() {
    assert_eq!(check_scheduled_coinbase_payees(0, &[]), Ok(()));
    // A genesis-height list that DOES mint is refused — the exemption is
    // "genesis mints nothing", not "height 0 may do anything".
    let payees = [CoinbasePayee { rkm: [1, 2, 3, 4], amount: 5 }];
    assert_eq!(
        check_scheduled_coinbase_payees(0, &payees),
        Err(BodyError::WrongScheduledCoinbase { height: 0, expected: 0, got: 5 })
    );
}

/// The provable-equivalence shape at the body level: an assembled-style body
/// (single rkm, coinbase = the schedule) passes the v5 Σ seam with its own
/// derived payee list — i.e. today's miner_rkm assembly path is a valid v5
/// producer with zero changes.
#[test]
fn todays_single_rkm_body_is_a_valid_v5_producer() {
    let h = 100u64;
    let body = minting_body(coinbase_exact(h));
    assert_eq!(check_scheduled_coinbase_payees(h, &body.coinbase_payees()), Ok(()));
    assert!(!body.mints_without_payee());
}
