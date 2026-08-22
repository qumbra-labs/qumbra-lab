//! **The emission-rule handoff drill** — the #74 drill discipline applied to the
//! first *real* scheduled rule change (lab #299 + #303, stage 5).
//!
//! # What a drill has to prove here, and why it cannot just mine 18,000 blocks
//!
//! Drills (a)–(d) in `deploy/docker/soak.sh` prove the halt *mechanism*: a
//! population stops at a height, a declared successor resumes past it, an
//! undeclared one is refused, and a cancelled upgrade does not stop anyone. Those
//! run against a real four-node net at `DRILL_HALT_HEIGHT = 16` precisely because
//! the mechanism is height-agnostic.
//!
//! This upgrade adds something the mechanism drills never had to express: **the
//! rules above the boundary differ from the rules below it, on the same committed
//! bytes.** The property to prove is therefore a *handoff*:
//!
//! > the old binary mines a block whose `coinbase` is the historical schedule's
//! > value, and the new binary accepts exactly those bytes below the boundary and
//! > refuses exactly those bytes above it.
//!
//! `RULE_BOUNDARY_HEIGHT` is a compiled-in constant (H1: never config, never
//! genesis, no runtime override), so proving the handoff at a *test* boundary is the
//! only way to do it without 8,640 blocks — hence
//! `check_scheduled_coinbase_above`, whose sole non-consensus caller is this file.
//! Consensus calls `check_scheduled_coinbase`, which reads the real constant.
//!
//! # The live drill this does not replace
//!
//! The activation exercise at the real boundary is T-ops's, after merge, and the
//! sequence is:
//!
//! 1. roll the default (armed) image to all four hosts **before** 8,640 — the
//!    banner prints `halt plan: halts at 8640`, which is the check;
//! 2. let the net reach 8,640 and halt there. It is a cadence multiple, so the
//!    boundary is a *finalized* boundary; `fid` must agree across all four hosts
//!    (`OPERATOR.md` §3) before anything else happens;
//! 3. roll the `--features rule-boundary-resume` image. Its marker rewrite records
//!    `v1.1-exact-emission` as in force, after which a pre-rule binary is refused
//!    (`UndeclaredResume`) — the property this file's release half asserts offline;
//! 4. `qumbra-node audit-emission --data-dir` over `8_641..` must report clean:
//!    every post-boundary block committed `coinbase_exact(height)`.
//!
//! Step 0, before any of it: run `qumbra-node emission-pins` on one host and paste
//! the literals, so nothing above the boundary evaluates `f64` at all.

use qlab_devnet::body::{
    check_scheduled_coinbase, check_scheduled_coinbase_above, validate_body, BlockBody, BodyError,
    TxEntry, TxVerifier,
};
use qlab_devnet::emission_exact::{coinbase_exact, RULE_BOUNDARY_HEIGHT};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::params_devnet::{CHECKPOINT_CADENCE_BLOCKS, GENESIS_DIFFICULTY};
use qlab_node::emission::coinbase_pre_boundary;
use qumbra_node::release::{
    HaltMarker, Release, ReleaseError, DRILL_HALT_HEIGHT, REVISION_V1_0,
    REVISION_V1_1_EXACT_EMISSION,
};

const MINER_RKM: [u64; 4] = [1, 2, 3, 4];

struct NoTx;
impl TxVerifier for NoTx {
    fn verify_tx(&self, _entry: &TxEntry) -> bool {
        true
    }
}

/// A coinbase-only body paying `coinbase`, with the header that commits to it.
fn block_at(height: u64, coinbase: u64) -> (BlockHeader, BlockBody) {
    let body = BlockBody::from_single_payee(Vec::new(), coinbase, MINER_RKM);
    let genesis = BlockHeader::genesis(GENESIS_DIFFICULTY, 0);
    let header = BlockHeader { height, ..BlockHeader::child_of(&genesis, 75, GENESIS_DIFFICULTY, body.commitment()) };
    (header, body)
}

/// The lowest height at which the two schedules actually disagree — **found, not
/// pinned**, because *which* heights disagree is platform-dependent (#303: glibc and
/// Apple libm differ from each other and both differ from the truth). Pinning a
/// height here would make the drill pass on the rig and fail in the Linux image, or
/// the reverse, which is the exact class of bug this whole baton exists to remove.
///
/// The census establishes that such a height exists on any platform: glibc's first
/// `s_atomic` divergence from exact math is `h = 3`, and 99.8 % of heights diverge.
fn first_disagreeing_height() -> u64 {
    (1..20_000u64)
        .find(|&h| coinbase_pre_boundary(h) != coinbase_exact(h))
        .expect(
            "the historical f64 schedule must disagree with exact math somewhere below \
             20,000 — if it does not, this platform's libm is not one the census measured \
             and #303 needs to hear about it",
        )
}

/// **The drill, phase 1: the same committed bytes flip verdict at the boundary.**
///
/// One block, one committed `coinbase` — the value the *old* binary would have paid.
/// Below the test boundary the new binary accepts it (history is grandfathered as
/// recorded); above it, refused by name, with the exact schedule's value in the
/// error so an operator can see both numbers.
#[test]
fn the_old_schedules_block_is_accepted_below_the_test_boundary_and_refused_above() {
    let h = first_disagreeing_height();
    let old_value = coinbase_pre_boundary(h);
    let exact_value = coinbase_exact(h);
    assert_ne!(old_value, exact_value, "the drill needs a height where the rules differ");

    // The old binary's block, at a boundary that puts it BELOW the cut.
    assert_eq!(check_scheduled_coinbase_above(h, h, old_value), Ok(()));
    assert_eq!(check_scheduled_coinbase_above(h + 1, h, old_value), Ok(()));

    // The SAME bytes, at a boundary that puts them ABOVE the cut.
    assert_eq!(
        check_scheduled_coinbase_above(h - 1, h, old_value),
        Err(BodyError::WrongScheduledCoinbase {
            height: h,
            expected: exact_value,
            got: old_value,
        }),
    );
    // And the new binary's own block is accepted there — the handoff is a change of
    // rule, not a refusal of everything above the line.
    assert_eq!(check_scheduled_coinbase_above(h - 1, h, exact_value), Ok(()));
}

/// **Phase 2: the same handoff through the real validation entry point.**
///
/// Phase 1 exercises the rule; this exercises `validate_body`, which is what every
/// peer's block goes through. It uses the *shipped* boundary, so the "old binary's
/// value" is synthesised as an off-by-one — the point being that the entry point,
/// not just the helper, is where the verdict changes.
#[test]
fn validate_body_enforces_the_handoff_at_the_shipped_boundary() {
    let b = RULE_BOUNDARY_HEIGHT;
    // A wrong-schedule block above the boundary: refused through the real path.
    let (header, body) = block_at(b + 1, coinbase_exact(b + 1) - 1);
    assert_eq!(
        validate_body(&header, &body, &NoTx, |_: &Hash32| true),
        Err(BodyError::WrongScheduledCoinbase {
            height: b + 1,
            expected: coinbase_exact(b + 1),
            got: coinbase_exact(b + 1) - 1,
        }),
    );
    // The identical body one height lower is history, and history is accepted.
    let (header_below, body_below) = block_at(b, coinbase_exact(b + 1) - 1);
    assert_eq!(validate_body(&header_below, &body_below, &NoTx, |_: &Hash32| true), Ok(()));
    // The honest post-boundary block passes.
    let (ok_header, ok_body) = block_at(b + 1, coinbase_exact(b + 1));
    assert_eq!(validate_body(&ok_header, &ok_body, &NoTx, |_: &Hash32| true), Ok(()));
    // And the consensus entry point agrees with the parameterised one at the real
    // constant — so the drill seam cannot drift away from what ships.
    for height in [0u64, 1, b - 1, b, b + 1, b + 2] {
        for value in [0u64, 1, coinbase_exact(height.max(1))] {
            assert_eq!(
                check_scheduled_coinbase(height, value),
                check_scheduled_coinbase_above(RULE_BOUNDARY_HEIGHT, height, value),
            );
        }
    }
}

/// **Phase 3: the release-level handoff.** The armed binary halts at the boundary,
/// the declared successor resumes past it and rewrites the marker, and after that a
/// pre-rule binary cannot start. Same shape as drills (a)/(c), asserted offline at
/// `DRILL_HALT_HEIGHT` so it costs no docker net.
#[test]
fn the_two_binary_handoff_refuses_the_pre_rule_binary_after_the_boundary() {
    let armed = Release {
        name: "drill: armed at the rule boundary",
        plan: qlab_devnet::halt::HaltPlan::Armed { height: DRILL_HALT_HEIGHT },
        revision: Some(REVISION_V1_0),
        resumes_from: None,
    };
    let resume = Release {
        name: "drill: exact-emission resume",
        plan: qlab_devnet::halt::HaltPlan::None,
        revision: Some(REVISION_V1_1_EXACT_EMISSION),
        resumes_from: Some(DRILL_HALT_HEIGHT),
    };
    armed.validate().unwrap();
    resume.validate().unwrap();

    // The armed binary halts, writing the marker; the successor is permitted and
    // supersedes it.
    let halted = HaltMarker::for_release(&armed, DRILL_HALT_HEIGHT, true);
    resume.check_against_marker(Some(&halted)).expect("the declared successor may resume");
    assert!(resume.supersedes(&halted));
    let passed = halted.superseded_by(&resume);
    assert!(passed.resumed);
    assert_eq!(passed.revision_id, REVISION_V1_1_EXACT_EMISSION.id);

    // Now the pre-rule binary — v1.0, no declaration, i.e. every image built before
    // the exact schedule existed. It is refused, which is what stops it validating
    // post-boundary blocks under the platform-dependent schedule.
    //
    // The *armed* binary is a deliberate exception and it matters here: it cannot go
    // past the boundary at all (`halt_at() == Some(B)`, not `> B`), so it changes no
    // rule above it and restarting it to inspect a halted node must keep working.
    // That case must NOT be a refusal, and asserting so keeps a future tightening
    // from breaking the one operator action a halted net needs.
    armed
        .check_against_marker(Some(&passed))
        .expect("re-running the armed binary to inspect the node is allowed");
    let plain_pre_rule = Release {
        name: "drill: pre-rule v1.0, no halt",
        plan: qlab_devnet::halt::HaltPlan::None,
        revision: Some(REVISION_V1_0),
        resumes_from: None,
    };
    assert!(matches!(
        plain_pre_rule.check_against_marker(Some(&passed)),
        Err(ReleaseError::UndeclaredResume { .. })
    ));

    // Re-running the successor after the transition is an ordinary restart: no
    // second marker write, no refusal.
    resume.check_against_marker(Some(&passed)).unwrap();
    assert!(!resume.supersedes(&passed), "an ordinary restart costs no fsync");
}

/// The shipped boundary is grid-legal, which is the one structural property a
/// re-stamp could break — `release.rs` refuses an off-grid halt height at startup,
/// so this is the assertion that would fail first if 18,000 were ever changed to a
/// non-multiple of 8.
#[test]
fn the_shipped_boundary_would_survive_the_startup_grid_check() {
    assert_eq!(RULE_BOUNDARY_HEIGHT % CHECKPOINT_CADENCE_BLOCKS, 0);
    let armed = Release {
        name: "shipped-shape armed",
        plan: qlab_devnet::halt::HaltPlan::Armed { height: RULE_BOUNDARY_HEIGHT },
        revision: Some(REVISION_V1_0),
        resumes_from: None,
    };
    armed.validate().expect("8,640 = 8 x 1,080 is on the cadence grid");
}
