//! **The name-service body-format handoff drill** — the #369 committee-to-halt
//! drill extended to the boundary it did not yet cover (lab #367 arming
//! precondition 4).
//!
//! # What #374 proved, and the gap this closes
//!
//! `qumbra-node/src/run.rs`'s committee-to-halt drill (#374, cases D1/D2/D3)
//! runs a real split committee TO a halt and through it, and proves the three
//! boundary-day defect classes — loop-path finalization (#360), REPUSH islands
//! (#362), and the frozen tip tie (#375) — over the real TCP mesh. But its halt
//! is a **validation-rule** boundary (the emission rule): the committed *bytes*
//! are identical on both sides, only the verdict on them changes.
//!
//! The name boundary is different in kind: it is the **first body-format change
//! (v2 → v3) to cross a halt** rather than a re-mint. Above it, a transaction may
//! carry a name **rider**, and the block body commits under a **different
//! preimage** (`qumbra:body:v3` vs `qumbra:body:v2`) — so the same logical body
//! has a *different commitment* on the two sides. This drill proves that
//! **format** handoff, which #374's cases run on top of but never exercised.
//!
//! # Why the `_above` seams, not a live mesh (the emission-drill discipline)
//!
//! `NAME_RULE_BOUNDARY_HEIGHT` is a compiled-in constant (the pins-unset
//! precedent — never config, never genesis, no runtime override), and the node's
//! apply path reads it through `validate_body_with_names`. So proving the handoff
//! at a *test* boundary is the only way to do it without a real arming roll —
//! exactly as `rule_boundary_drill.rs` uses `check_scheduled_coinbase_above`.
//! Here the seams are [`BlockBody::commitment_above`] and [`validate_body_above`],
//! whose only non-consensus caller is this file; consensus uses
//! `commitment_at` / `validate_body_with_names`, which read the real constant.
//!
//! The test boundary is chosen **below** the emission `RULE_BOUNDARY_HEIGHT` so
//! the emission schedule check is grandfathered (`Ok` for any coinbase), and the
//! bodies mint nothing — isolating the name-format behaviour from every other
//! rule.
//!
//! # The live drill this does not replace
//!
//! The real arming exercise is T-ops's, after Larry stamps the height
//! (`docs/name-boundary-arming.md` §4–6): roll the armed image (halt-status
//! banners `name service: ARMED — … above height {h}`), let the net halt at the
//! stamped boundary, adjudicate the boundary `fid`, roll the resume image, then
//! `audit-names --from <boundary+1>` must report the registry AGREES. The
//! committee finalize/tie/repush machinery under a halt is #374's live coverage;
//! this file proves the v2→v3 format handoff those cases assume.

use std::collections::HashMap;

use qlab_devnet::body::{
    validate_body_above, validate_body_with_names, BlockBody, BodyError, TxEntry, TxPublic,
    TxVerifier,
};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::names::{
    self, commit_hash, name_fee_bessel, NameOp, NameRecord, NameView, L1_ADDRESS_LEN,
    NAME_RULE_BOUNDARY_HEIGHT, RECORD_KIND_L1_ADDRESS,
};

/// A test name boundary, deliberately **below** the emission `RULE_BOUNDARY_HEIGHT`
/// (8,640) so `check_scheduled_coinbase` grandfathers every coinbase and the
/// bodies here can mint nothing — the name format is the only rule under test.
const B: u64 = 200;

const ANCHOR: Hash32 = [0x0F; 32];

/// Accept any proof — the format handoff is orthogonal to proof validity.
struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _entry: &TxEntry) -> bool {
        true
    }
}

/// A `NameView` that reports one commit in a window and no registrations — the
/// minimum a reveal needs to validate above the boundary.
struct View {
    commits: HashMap<Hash32, u64>,
}
impl NameView for View {
    fn commit_included_in(&self, c: &Hash32, lo: u64, hi: u64) -> bool {
        self.commits.get(c).is_some_and(|h| (lo..=hi).contains(h))
    }
    fn registration_expiry(&self, _n: &[u8]) -> Option<u64> {
        None
    }
}

fn is_final(root: &Hash32) -> bool {
    *root == ANCHOR
}

fn record() -> NameRecord {
    NameRecord {
        kind: RECORD_KIND_L1_ADDRESS,
        name: b"alice".to_vec(),
        address: vec![0xAB; L1_ADDRESS_LEN],
    }
}

/// A rider-free 2×2 transaction (placeholder discovery, posted fee).
fn plain_tx(nf: u8) -> TxEntry {
    TxEntry::with_placeholder_discovery(
        b"ok".to_vec(),
        TxPublic {
            anchor: ANCHOR,
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(1); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        },
    )
}

/// The same transaction carrying a name reveal, paying the fee split
/// (relay tier + the burned 5-char name fee).
fn reveal_tx(nf: u8, salt: [u8; 32]) -> TxEntry {
    let mut tx = plain_tx(nf).with_name_op(&NameOp::Reveal { record: record(), salt });
    tx.public.fee = posted_fee(ArityBucket::TwoByTwo) + name_fee_bessel(5);
    tx
}

fn body_of(txs: Vec<TxEntry>) -> BlockBody {
    // coinbase 0: no mint, so no payee/schedule interaction — see B's note.
    BlockBody { txs, coinbase: 0, coinbase_rkm: [0; 4] }
}

/// A header at `height` committing to `body` under the boundary's rule.
fn header_above(boundary: Option<u64>, height: u64, body: &BlockBody) -> BlockHeader {
    BlockHeader {
        height,
        ..BlockHeader::child_of(&BlockHeader::genesis(1, 0), 75, 1, body.commitment_above(boundary, height))
    }
}

// ---------------------------------------------------------------------------
// Phase 1 — the FORMAT handoff: the same body, a different commitment across B
// ---------------------------------------------------------------------------

/// The emission drill's phase-1 analog: the same committed body flips its
/// **commitment form** at the boundary. Below and AT the boundary it is v2;
/// strictly above it is v3 — so a body's identity itself changes across the
/// halt, which is what makes this a format handoff and not a rule handoff.
#[test]
fn the_same_body_commits_v2_at_or_below_the_boundary_and_v3_above() {
    for body in [body_of(vec![plain_tx(1)]), body_of(vec![reveal_tx(1, [7; 32])])] {
        let v2_below = body.commitment_above(Some(B), B - 1);
        let v2_at = body.commitment_above(Some(B), B);
        let v3_above = body.commitment_above(Some(B), B + 1);

        // v2 form is stable at and below the boundary (the live-chain compat lock).
        assert_eq!(v2_below, v2_at, "at/below the boundary is one v2 form");
        // …and the emission-style equality: at/below == the plain `commitment()`.
        assert_eq!(v2_at, body.commitment(), "the v2 form IS the shipped commitment");
        // Strictly above, the form changes — the same bytes, a new commitment.
        assert_ne!(
            v3_above, v2_at,
            "crossing the boundary must move the commitment (v2→v3), or a rider-free \
             v3 body would collide with its v2 self — the cross-version second spelling"
        );
    }
}

// ---------------------------------------------------------------------------
// Phase 2 — the RIDER gate + fee split, through the real validation entry point
// ---------------------------------------------------------------------------

/// A rider-carrying block: refused at and below the boundary
/// (`RiderBeforeBoundary`), accepted strictly above it — the handoff at the
/// entry point every peer's block goes through. This is #374's "committee TO a
/// halt and through it" at the format layer: the crossing itself.
#[test]
fn a_reveal_block_is_refused_at_or_below_the_boundary_and_accepted_above() {
    let salt = [7u8; 32];
    let view = View {
        // A commit inside the reveal's window at B+1 (validate uses [h-MAX, h-MIN]).
        commits: [(commit_hash(&record(), &salt), B + 1 - 8)].into(),
    };
    let body = body_of(vec![reveal_tx(0x60, salt)]);

    // Strictly above: valid — the reveal's commit is in-window and the fee splits.
    validate_body_above(Some(B), &header_above(Some(B), B + 1, &body), &body, &NoTx, is_final, &view)
        .expect("a fee-split reveal with an in-window commit is valid above the boundary");

    // AT the boundary: the gate is strict (riders_active_above is `> b`).
    assert!(matches!(
        validate_body_above(Some(B), &header_above(Some(B), B, &body), &body, &NoTx, is_final, &view),
        Err(BodyError::RiderBeforeBoundary { index: 0 })
    ));
    // Below the boundary: same refusal.
    assert!(matches!(
        validate_body_above(
            Some(B),
            &header_above(Some(B), B - 1, &body),
            &body,
            &NoTx,
            is_final,
            &view
        ),
        Err(BodyError::RiderBeforeBoundary { index: 0 })
    ));
}

/// The fee split is enforced across the handoff: a reveal above the boundary
/// paying only the relay tier is `WrongFee` naming the full `posted + name_fee`.
#[test]
fn the_fee_split_is_enforced_above_the_boundary() {
    let salt = [9u8; 32];
    let view = View { commits: [(commit_hash(&record(), &salt), B + 1 - 8)].into() };
    let mut cheap = reveal_tx(0x61, salt);
    cheap.public.fee = posted_fee(ArityBucket::TwoByTwo); // the name fee omitted
    let body = body_of(vec![cheap]);

    assert!(matches!(
        validate_body_above(Some(B), &header_above(Some(B), B + 1, &body), &body, &NoTx, is_final, &view),
        Err(BodyError::WrongFee { index: 0, expected, .. })
            if expected == posted_fee(ArityBucket::TwoByTwo) + name_fee_bessel(5)
    ));
}

// ---------------------------------------------------------------------------
// Phase 3 — the shipped build is inert: the crossing is impossible on `main`
// ---------------------------------------------------------------------------

/// RETIRED name 2026-08-17: `the_shipped_boundary_makes_the_v3_crossing_impossible`
/// — the inert-at-merge reading (shipped boundary `None` ⇒ the crossing is
/// impossible at EVERY height). At the stamp (19,008, lab #367, arming runbook
/// step 0) the same test carries the armed reading: through the SHIPPED path
/// the v3 crossing stays impossible at every height at or below the stamped
/// boundary — this drill's heights all are, so the refusal asserted here is
/// exactly what the retired version asserted.
#[test]
fn the_stamped_boundary_keeps_the_v3_crossing_impossible_below_it() {
    assert!(
        matches!(NAME_RULE_BOUNDARY_HEIGHT, Some(b) if B + 1 <= b),
        "this drill's heights must sit at/below the stamped boundary \
         (stamped: {NAME_RULE_BOUNDARY_HEIGHT:?})"
    );
    let salt = [7u8; 32];
    let view = View { commits: [(commit_hash(&record(), &salt), B + 1 - 8)].into() };
    let body = body_of(vec![reveal_tx(0x62, salt)]);
    // A header committing the v3 form (as a post-boundary block would) validated
    // under the shipped rule at B + 1 ≤ 19,008: the binding is computed v2, so
    // it mismatches — nothing below the stamp can smuggle a v3 block in.
    let v3_header = header_above(Some(B), B + 1, &body);
    assert!(matches!(
        validate_body_with_names(&v3_header, &body, &NoTx, is_final, &view),
        Err(BodyError::CommitmentMismatch { .. })
    ));
}

/// A rider-free block crosses the drill's test boundary unremarkably at every
/// height — the property arming must preserve: below the stamped boundary the
/// running chain is untouched.
#[test]
fn rider_free_blocks_validate_on_the_shipped_build_across_the_test_boundary() {
    let view = View { commits: HashMap::new() };
    for h in [B - 1, B, B + 1] {
        let body = body_of(vec![plain_tx(h as u8)]);
        // The shipped rule commits v2 at/below the stamped 19,008 and all of
        // this drill's heights sit below it, so a v2-bound header binds.
        let header = BlockHeader {
            height: h,
            ..BlockHeader::child_of(&BlockHeader::genesis(1, 0), 75, 1, body.commitment())
        };
        validate_body_with_names(&header, &body, &NoTx, is_final, &view)
            .unwrap_or_else(|e| panic!("rider-free block at {h} must validate on the shipped build: {e:?}"));
    }
}
