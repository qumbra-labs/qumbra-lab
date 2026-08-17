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
//!
//! # Phase 4 — the LIVE CROSSING (added 2026-08-17 as a defect lock, INVERTED
//! # 2026-08-17 by QUM-129 when the defect was fixed)
//!
//! The straddle-drill baton (PR #464) was commissioned to lock the **no-halt**
//! route: a live crossing of the boundary with no halt and no node diverging.
//! It could not, because on `main` the property was false — at the stamped
//! boundary an armed node refused *every* block above 19,008, an empty body
//! with no transactions included, because the apply funnel
//! (`qlab_node::node::check_stored_binding`) and the producer
//! (`qlab_p2p::adapter::NodeAdapter::mine_on_parent`) recomputed the body
//! commitment height-blind while the entry rule demanded the v3 form. PR #464
//! locked that finding as
//! `the_apply_funnel_refuses_every_block_above_the_stamped_boundary`, a test
//! that **asserted the defect** and whose own `else` arm said what to write in
//! its place.
//!
//! QUM-129 height-keyed both call sites, so this file now carries the property
//! rather than the finding: phase 4 is
//! [`the_live_v2_to_v3_crossing_applies_through_the_real_node`], and the two
//! flanking tests that pinned the deadlock and its blast radius are kept, with
//! the deadlock one extended to assert **both layers now agree** on the same
//! block instead of contradicting each other. Phase 5 adds the replay half the
//! finding flagged and could not check: a datadir written across the boundary
//! by a fixed armed binary, and one written above it by an INERT binary.
//!
//! Phases 1–3 above are untouched.

use std::collections::HashMap;

use qlab_devnet::body::{
    validate_body_above, validate_body_with_names, BlockBody, BodyError, TxEntry, TxPublic,
    TxVerifier,
};
use qlab_devnet::emission_exact::{coinbase_exact, RULE_BOUNDARY_HEIGHT};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::names::{
    commit_hash, name_fee_bessel, NameOp, NameRecord, NameView, L1_ADDRESS_LEN,
    NAME_RULE_BOUNDARY_HEIGHT, RECORD_KIND_L1_ADDRESS,
};
use qlab_node::{genesis_block, ChainStore, MemNode, NodeState};

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

// ---------------------------------------------------------------------------
// Phase 4 — the LIVE crossing, through a real node's apply path, at the
//           SHIPPED constant. Since QUM-129 this is the PROPERTY, not a
//           defect lock: the chain crosses 19,008 and keeps producing.
// ---------------------------------------------------------------------------

/// Beyond which stamped boundary this drill stops being an in-suite test. At
/// 19,008 the whole file costs **0.21 s real / 26.5 MiB peak RSS** — basis:
/// `/usr/bin/time -l` on the release test binary, `--test-threads=1`, 1 sample,
/// the coordinator laptop under `scripts/rig`, tree `a4719a2` + PR #464, all 8
/// tests. QUM-129's re-measurement of the same file is in that PR's body; the
/// crossing test now applies three blocks past the boundary instead of failing
/// at the first, which is three blocks of extra work, not a new order.
/// A re-stamp an order of magnitude higher wants a different mechanism, not a
/// slower loop; the assertion below says so out loud rather than letting a
/// future stamp quietly turn the suite into a bench.
const IN_SUITE_BOUNDARY_CEILING: u64 = 200_000;

/// The miner's payout key. Any non-zero value: a minting body must name a payee
/// (issue #101), and above the emission boundary it must mint the scheduled
/// amount (lab #299) — neither rule is under test here, both are satisfied so
/// that the *name* format is the only thing that can refuse a block.
const DRILL_RKM: [u64; 4] = [0xA1, 0xA2, 0xA3, 0xA4];

/// A minimal honest body at `height`: **no transactions at all**. Empty is the
/// point — with no tx there is no rider, no anchor, no fee and no proof, so a
/// refusal cannot be blamed on the rider rules. Coinbase is 0 below the
/// emission boundary and the exact schedule above it.
fn empty_body_at(height: u64) -> BlockBody {
    if height > RULE_BOUNDARY_HEIGHT {
        BlockBody { txs: vec![], coinbase: coinbase_exact(height), coinbase_rkm: DRILL_RKM }
    } else {
        BlockBody { txs: vec![], coinbase: 0, coinbase_rkm: [0; 4] }
    }
}

/// An honest header for `body` as a child of `parent` — one that commits the
/// form the SHIPPED rule requires at its own height ([`BlockBody::commitment_at`]),
/// which is what an armed producer must emit.
fn honest_child(parent: &BlockHeader, body: &BlockBody) -> BlockHeader {
    let header = BlockHeader::child_of(parent, parent.timestamp + 75, 1, [0; 32]);
    BlockHeader { tx_body_commitment: body.commitment_at(header.height), ..header }
}

/// 🟢 **The LIVE CROSSING — the property lab #367 option A rests on.**
///
/// This test is the inversion of PR #464's
/// `the_apply_funnel_refuses_every_block_above_the_stamped_boundary`, which
/// asserted the defect and named this test in its `else` arm. Read the two
/// together: same node, same bodies, same stamped constant — the verdict at
/// `b + 1` is what QUM-129 changed.
///
/// A real [`qlab_node::MemNode`] — the state machine `qumbra-node` runs — is
/// driven from genesis **through** the stamped name boundary on honest empty
/// bodies and honest height-keyed headers:
///
/// | height | body commits | entry rule | apply funnel |
/// |---|---|---|---|
/// | `1 ..= b` (19,008 blocks, incl. the boundary block itself) | v2 | `Ok` | applies |
/// | `b + 1` | **v3** — the form changes mid-chain | `Ok` | **applies** |
/// | `b + 2`, `b + 3` | v3 | `Ok` | applies — production continues |
///
/// The crossing is what makes it a straddle and not a boundary test: the same
/// chain, the same node instance, carries a body-format change at 19,008 → 19,009
/// with **no halt, no restart, no reorg** — and the tip keeps advancing after it.
///
/// The two things it pins that a lower drill boundary could not:
/// 1. the **shipped** constant (`NAME_RULE_BOUNDARY_HEIGHT`), not an `_above`
///    seam — the funnel has no `_above` variant, so a drill boundary is blind
///    to exactly the seam that was broken;
/// 2. **both layers on the same block**: `validate_body_with_names` (entry) and
///    `Node::apply_state`'s `check_stored_binding` (funnel) now compute the
///    same expectation from the same height. Before the fix they computed
///    opposite ones and no block of any shape satisfied both.
///
/// Kept deliberately **rider-free and proof-free** — empty bodies. What crosses
/// here is the *format*, so an acceptance cannot be attributed to (or blamed on)
/// the rider rules; phases 1–2 above cover riders.
///
/// Mutation checks (each one line, each fails here):
/// - revert the funnel to `block.body().commitment()` → `CROSSING` fails: block
///   `b + 1` is refused with `BodyCommitmentMismatch` (this is PR #464's finding
///   restored, and the panic message says so);
/// - key the funnel to a constant height (`commitment_at(0)`) → the same failure;
/// - `NAME_RULE_BOUNDARY_HEIGHT` → `None` → fails loudly at the `.expect` on the
///   stamp rather than passing vacuously;
/// - make `honest_child` commit `commitment()` → fails at the *entry* rule at
///   `b + 1`, which is [`a_v2_committed_block_above_the_stamped_boundary_is_refused_at_the_entry_point`]'s
///   subject seen from this side.
#[test]
fn the_live_v2_to_v3_crossing_applies_through_the_real_node() {
    let b = NAME_RULE_BOUNDARY_HEIGHT
        .expect("the boundary is stamped (lab #367 arming step 0, PR #455) — if it is `None` again this test proves nothing and must be re-derived");
    assert!(
        b <= IN_SUITE_BOUNDARY_CEILING,
        "the stamped boundary moved to {b}, past this drill's in-suite ceiling \
         {IN_SUITE_BOUNDARY_CEILING} — re-derive the mechanism, do not just wait longer"
    );
    let view = View { commits: HashMap::new() };

    // ── below, and AT, the boundary: an ordinary chain, v2 throughout ────────
    let mut node = MemNode::in_memory(genesis_block(1, 0));
    for h in 1..=b {
        let body = empty_body_at(h);
        let parent = node.chain().block(&node.tip_hash()).expect("tip is stored").header();
        let header = honest_child(&parent, &body);
        assert_eq!(header.height, h);
        assert_eq!(
            header.tx_body_commitment,
            body.commitment(),
            "at/below the boundary the honest form IS the v2 form — the live chain is untouched"
        );
        node.apply_block(header, body, &NoTx)
            .unwrap_or_else(|e| panic!("honest block {h} at/below the boundary must apply: {e:?}"));
    }
    assert_eq!(node.tip_height(), b, "the chain reached the boundary block itself");
    let root_at_boundary = node.commitment_root();

    // ── CROSSING: the first block above the boundary, in the honest v3 form ──
    let body = empty_body_at(b + 1);
    let parent = node.chain().block(&node.tip_hash()).expect("tip is stored").header();
    let v3_header = honest_child(&parent, &body);
    assert_ne!(
        v3_header.tx_body_commitment,
        body.commitment(),
        "above the boundary the honest header commits v3, not the v2 form — \
         if these are equal the crossing below proves nothing"
    );
    assert_eq!(v3_header.tx_body_commitment, body.commitment_at(b + 1));

    // The ENTRY point — the rule as designed — accepts it…
    validate_body_with_names(&v3_header, &body, &NoTx, is_final, &view)
        .expect("the armed validation rule accepts the honest v3 form above the boundary");

    // …and so does the APPLY funnel, which is the half PR #464 measured refusing.
    node.apply_block(v3_header, body.clone(), &NoTx).unwrap_or_else(|e| panic!(
        "🔴 the crossing is broken again: the funnel refused the honest v3 block at {} — \
         this is PR #464's finding restored. Check `qlab_node::node::check_stored_binding` \
         is still `commitment_at(block.header.height)`: {e:?}",
        b + 1
    ));
    assert_eq!(node.tip_height(), b + 1, "the chain crossed the boundary");
    assert_ne!(node.commitment_root(), root_at_boundary, "…and state moved with it");

    // ── production continues above the boundary ─────────────────────────────
    for h in (b + 2)..=(b + 3) {
        let body = empty_body_at(h);
        let parent = node.chain().block(&node.tip_hash()).expect("tip is stored").header();
        let header = honest_child(&parent, &body);
        assert_eq!(header.tx_body_commitment, body.commitment_at(h), "v3 above the boundary");
        validate_body_with_names(&header, &body, &NoTx, is_final, &view)
            .unwrap_or_else(|e| panic!("block {h} must pass the entry rule: {e:?}"));
        node.apply_block(header, body, &NoTx)
            .unwrap_or_else(|e| panic!("block {h} above the boundary must apply: {e:?}"));
    }
    assert_eq!(node.tip_height(), b + 3, "the chain keeps producing past the crossing");
}

/// The **INERT stranger's block**, judged from the honest side: a v2-committed
/// body above the boundary is refused at the entry point with
/// `CommitmentMismatch`.
///
/// Before QUM-129 this was one half of a *deadlock* — the entry rule refused
/// the v2 spelling and the funnel refused the v3 one, so nothing could be
/// applied at all. After the fix it is a one-sided refusal of a genuinely wrong
/// block, and it is what an armed node does with a block an un-rolled peer
/// mines above 19,008. `NodeAdapter::mine_on_parent` no longer emits this shape
/// (it commits `commitment_at(parent.height + 1)`), which
/// `qlab_p2p::adapter::tests::the_fixed_producer_mines_across_the_stamped_boundary_and_its_own_node_applies_it`
/// mines end-to-end.
///
/// **Both layers agree on this block post-fix**, which is the property that
/// replaced the deadlock: the entry rule below computes `commitment_at(b + 1)`
/// (asserted here), and the funnel computes the identical value for the identical
/// block — asserted where the funnel is reachable for a block the entry point
/// never admits, i.e. on replay of a log an inert binary wrote:
/// `qlab_node::node::tests::an_inert_written_log_above_the_boundary_is_refused_by_replay`.
///
/// Mutation check: make `commitment_above` ignore its boundary (always v2) and
/// this refusal becomes `Ok(())`.
#[test]
fn a_v2_committed_block_above_the_stamped_boundary_is_refused_at_the_entry_point() {
    let b = NAME_RULE_BOUNDARY_HEIGHT.expect("stamped");
    let view = View { commits: HashMap::new() };
    let body = empty_body_at(b + 1);

    let genesis = BlockHeader::genesis(1, 0);
    let v2_header = BlockHeader {
        height: b + 1,
        ..BlockHeader::child_of(&genesis, 75, 1, body.commitment())
    };
    match validate_body_with_names(&v2_header, &body, &NoTx, is_final, &view) {
        Err(BodyError::CommitmentMismatch { expected, got }) => {
            assert_eq!(expected, body.commitment(), "what the v2 producer committed");
            assert_eq!(got, body.commitment_at(b + 1), "…against the v3 form the rule requires");
        }
        other => panic!("a v2-committed block above the boundary must be refused: {other:?}"),
    }
}

/// The blast radius, pinned from the other side: an **INERT** build — the one
/// every stranger and every un-rolled host is running — is untouched. With the
/// boundary `None`, `commitment_above` is the v2 form at every height, which is
/// exactly what the unconditional funnel recomputes, so an inert node keeps
/// applying blocks straight through 19,008.
///
/// Before QUM-129 this pinned *who the defect hit* — the armed fleet was the
/// side that stopped, the inverse of the outcome lab #367's ruling priced. With
/// the funnel and producer height-keyed, the armed fleet crosses
/// ([`the_live_v2_to_v3_crossing_applies_through_the_real_node`]) and this test
/// keeps the other half honest: an inert build still commits v2 above the
/// stamped height, so it forks rather than follows. That is the
/// `UPDATE-BEFORE-19,008` notice's whole subject, and it is unchanged by the fix.
///
/// Mutation check: make `commitment_above` treat `None` as "v3 above 0" and the
/// first assertion fails.
#[test]
fn an_inert_build_is_untouched_by_the_boundary() {
    let b = NAME_RULE_BOUNDARY_HEIGHT.expect("stamped");
    for body in [empty_body_at(b + 1), body_of(vec![plain_tx(3)])] {
        assert_eq!(
            body.commitment_above(None, b + 1),
            body.commitment(),
            "an inert build commits v2 above the stamped height, so the funnel agrees with it"
        );
        assert_ne!(
            body.commitment_at(b + 1),
            body.commitment(),
            "…and an armed build does not, which is the whole disagreement"
        );
    }
}
