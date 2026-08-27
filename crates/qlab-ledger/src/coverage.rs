//! The height range a scan's outputs actually came from — as a value whose
//! merge **cannot silently widen**.
//!
//! # Why this type exists at all (lab #568)
//!
//! Today a scan's output coverage is an `Option<(u64, u64)>` combined with
//! [`crate::spent::widest_range`], which reduces by `(min, max)`. That is a
//! **hull, not a union**: `0..=100` combined with `200..=300` gives `0..=300`,
//! and the hundred blocks nobody scanned are gone from the value.
//!
//! Within one scan that is harmless — every address is asked for the same range,
//! so the inputs overlap by construction. On a **resume** path it is a defect
//! waiting to happen, and nothing downstream would catch it:
//!
//! | check | what it actually verifies |
//! |---|---|
//! | [`crate::spent::SpentCatchUp::supply`] | contiguity of the **nullifier** stream — which is contiguous |
//! | [`crate::spent::SpentSet::covers_outputs`] | `from <= outputs.0 && to >= outputs.1` — **the two ends only** |
//! | `widest_range` | min/max — it is what discards the gap |
//! | `qumbra_wallet::view::render`'s `range: (u64, u64)` | nothing; a gap is unrepresentable, so it prints as solid |
//!
//! So a resume that merged the old and new served-ranges with `widest_range`
//! would render **`Complete` over a range with unscanned blocks inside it** —
//! the truncation-reads-as-complete family (#312 / #313 / #314) one level up,
//! and the tenth instance of it in this project.
//!
//! Hence: one type, and its merge returns a `Result`. There is no method on
//! [`Coverage`] that produces a wider range than its inputs justify, which is
//! the property the rest of the resume design rests on.
//!
//! # Why it is one interval and not a set of them
//!
//! Because a merge that would leave a hole is refused, a `Coverage` is always
//! either empty or **one contiguous inclusive range**. That is deliberate and it
//! matches what the renderer can express: `render` takes a single `(u64, u64)`,
//! so a non-contiguous coverage has no honest rendering and must not become a
//! value we can hold. Refusing at the merge is how it never does.

use std::fmt;

/// The heights a scan's outputs are known to have come from: nothing, or one
/// contiguous inclusive range.
///
/// `Empty` is a **covered** state, not a failed one — an endpoint that held no
/// main-chain block in the requested range has no outputs in it either, the same
/// distinction [`crate::vocab::SpentCoverage::Covered`] draws with its `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Coverage {
    /// No block was served, so no output could have been missed.
    #[default]
    Empty,
    /// Every height in `from..=to` was served. `from <= to` is an invariant of
    /// the constructors below.
    Range { from: u64, to: u64 },
}

/// Why two coverages could not be merged. Carries both sides and the hole, so
/// the message can say which heights nobody scanned rather than "gap".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageGap {
    pub left: (u64, u64),
    pub right: (u64, u64),
    /// The heights in neither side, inclusive.
    pub missing: (u64, u64),
}

impl fmt::Display for CoverageGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "coverage {}..={} and {}..={} do not meet: heights {}..={} were scanned by neither, \
             so no range spanning them can be called complete",
            self.left.0, self.left.1, self.right.0, self.right.1, self.missing.0, self.missing.1
        )
    }
}

impl std::error::Error for CoverageGap {}

impl Coverage {
    /// One served range. `from > to` is not a range and is taken as [`Self::Empty`]
    /// rather than silently swapped — a caller with reversed bounds served
    /// nothing, and inventing `to..=from` for them would fabricate coverage.
    pub fn range(from: u64, to: u64) -> Coverage {
        if from > to {
            Coverage::Empty
        } else {
            Coverage::Range { from, to }
        }
    }

    /// From the `Option<(u64, u64)>` shape the existing scan path speaks.
    pub fn from_served(served: Option<(u64, u64)>) -> Coverage {
        match served {
            Some((a, b)) => Coverage::range(a, b),
            None => Coverage::Empty,
        }
    }

    /// Back to that shape, for [`crate::spent::SpentSet::covers_outputs`] and
    /// for the renderer.
    pub fn as_served(self) -> Option<(u64, u64)> {
        match self {
            Coverage::Empty => None,
            Coverage::Range { from, to } => Some((from, to)),
        }
    }

    /// The upper edge — the resume watermark, when there is one.
    ///
    /// This is why lab #568 does not add a `u64` called `watermark`: the
    /// watermark is not an independent fact to be kept in step with the
    /// coverage, it is a projection of it, so the two cannot disagree.
    pub fn watermark(self) -> Option<u64> {
        match self {
            Coverage::Empty => None,
            Coverage::Range { to, .. } => Some(to),
        }
    }

    /// Does this coverage contain every height in `from..=to`?
    pub fn contains_range(self, from: u64, to: u64) -> bool {
        match self {
            Coverage::Empty => from > to,
            Coverage::Range { from: a, to: b } => a <= from && b >= to,
        }
    }

    /// Merge two coverages, **refusing** when the result would span heights that
    /// neither side covers.
    ///
    /// Adjacent counts as meeting: `0..=100` and `101..=200` merge to `0..=200`,
    /// because inclusive ranges that touch leave nothing between them. A
    /// one-block hole does not: `0..=100` and `102..=200` is a refusal naming
    /// height 101.
    pub fn merge(self, other: Coverage) -> Result<Coverage, CoverageGap> {
        let (a, b) = match (self, other) {
            (Coverage::Empty, x) | (x, Coverage::Empty) => return Ok(x),
            (Coverage::Range { from: a0, to: a1 }, Coverage::Range { from: b0, to: b1 }) => {
                ((a0, a1), (b0, b1))
            }
        };
        let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
        // `lo.1 + 1 < hi.0` is the gap test. Saturating because lo.1 == u64::MAX
        // means lo already reaches the top and nothing can be beyond it.
        if lo.1.saturating_add(1) < hi.0 {
            return Err(CoverageGap {
                left: lo,
                right: hi,
                missing: (lo.1 + 1, hi.0 - 1),
            });
        }
        Ok(Coverage::Range { from: lo.0, to: lo.1.max(hi.1) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 THE test this type exists for, and the first one written.
    ///
    /// `widest_range` answers `Some((0, 300))` here. That answer is what would
    /// let a resumed scan report `Complete` over heights 101..=199 that nobody
    /// ever fetched. If this test ever passes with a `Coverage::Range` on the
    /// left-hand side, the type has stopped doing its job and the resume path
    /// is unsound.
    #[test]
    fn a_merge_that_would_span_unscanned_heights_is_refused() {
        let old = Coverage::range(0, 100);
        let new = Coverage::range(200, 300);
        let err = old.merge(new).expect_err("a 99-block hole was merged away");
        assert_eq!(err.missing, (101, 199));
        assert_eq!(err.left, (0, 100));
        assert_eq!(err.right, (200, 300));

        // Order must not matter: the caller does not know which side is older.
        let err_rev = new.merge(old).expect_err("reversed order merged the hole away");
        assert_eq!(err_rev.missing, (101, 199));

        // And the sentence names the heights, because "gap" sends the reader
        // measuring by hand.
        let said = err.to_string();
        assert!(said.contains("101..=199"), "{said}");
        assert!(said.contains("neither"), "{said}");
    }

    /// The hull this type replaces, spelled out so the contrast is testable
    /// rather than only argued in a doc comment.
    #[test]
    fn the_hull_the_old_helper_would_have_returned_is_not_reachable_here() {
        let hull = crate::spent::widest_range([Some((0, 100)), Some((200, 300))]);
        assert_eq!(hull, Some((0, 300)), "widest_range is still a hull");
        assert!(
            Coverage::range(0, 100).merge(Coverage::range(200, 300)).is_err(),
            "Coverage must refuse exactly what the hull swallows"
        );
    }

    /// Touching inclusive ranges leave nothing between them, so resuming at
    /// `watermark + 1` — the normal case, on every resume — must not be a gap.
    #[test]
    fn adjacent_ranges_meet() {
        let joined = Coverage::range(0, 100)
            .merge(Coverage::range(101, 200))
            .expect("watermark + 1 is not a hole");
        assert_eq!(joined, Coverage::Range { from: 0, to: 200 });
        assert_eq!(joined.watermark(), Some(200));
    }

    /// One block missing is still missing. The off-by-one here is the whole
    /// difference between this type and the hull.
    #[test]
    fn a_single_missing_height_is_a_gap() {
        let err = Coverage::range(0, 100)
            .merge(Coverage::range(102, 200))
            .expect_err("one unscanned block was merged away");
        assert_eq!(err.missing, (101, 101));
    }

    #[test]
    fn overlapping_and_contained_ranges_merge_without_widening() {
        assert_eq!(
            Coverage::range(0, 150).merge(Coverage::range(100, 200)).unwrap(),
            Coverage::Range { from: 0, to: 200 }
        );
        // Containment must not shrink the outer range either.
        assert_eq!(
            Coverage::range(0, 200).merge(Coverage::range(50, 60)).unwrap(),
            Coverage::Range { from: 0, to: 200 }
        );
    }

    /// Empty is a covered state, not a failure: merging with it is identity, and
    /// it must not be usable to bridge a hole.
    #[test]
    fn empty_is_identity_and_bridges_nothing() {
        let r = Coverage::range(10, 20);
        assert_eq!(Coverage::Empty.merge(r).unwrap(), r);
        assert_eq!(r.merge(Coverage::Empty).unwrap(), r);
        assert_eq!(Coverage::Empty.merge(Coverage::Empty).unwrap(), Coverage::Empty);
        // Empty in the middle cannot join two disjoint ranges.
        let bridged = Coverage::range(0, 100)
            .merge(Coverage::Empty)
            .unwrap()
            .merge(Coverage::range(200, 300));
        assert!(bridged.is_err(), "Empty was used to bridge a 99-block hole");
    }

    #[test]
    fn a_reversed_range_is_empty_not_a_swapped_one() {
        assert_eq!(Coverage::range(200, 100), Coverage::Empty);
        assert_eq!(Coverage::range(200, 100).watermark(), None);
    }

    #[test]
    fn the_top_of_the_range_does_not_overflow() {
        let top = Coverage::range(u64::MAX - 1, u64::MAX);
        // Nothing can lie beyond u64::MAX, so this must be a merge and not a
        // panic from `lo.1 + 1`.
        assert_eq!(
            top.merge(Coverage::range(0, u64::MAX - 2)).unwrap(),
            Coverage::Range { from: 0, to: u64::MAX }
        );
    }

    #[test]
    fn watermark_and_contains_agree_with_the_range() {
        let c = Coverage::range(5, 9);
        assert_eq!(c.watermark(), Some(9));
        assert!(c.contains_range(5, 9));
        assert!(c.contains_range(6, 8));
        assert!(!c.contains_range(4, 9), "an uncovered head is not contained");
        assert!(!c.contains_range(5, 10), "an uncovered tail is not contained");
        assert!(!Coverage::Empty.contains_range(0, 0));
        // An empty range is vacuously contained by Empty — from > to.
        assert!(Coverage::Empty.contains_range(1, 0));
    }

    #[test]
    fn served_round_trips() {
        assert_eq!(Coverage::from_served(Some((3, 7))).as_served(), Some((3, 7)));
        assert_eq!(Coverage::from_served(None).as_served(), None);
        assert_eq!(Coverage::from_served(Some((7, 3))), Coverage::Empty);
    }
}
