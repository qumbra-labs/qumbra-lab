//! Hidden dummy-slot authorization rule.
//!
//! The current AIR guarantees slot 0 is real and hides whether slot 1 is a
//! zero-value off-tree dummy. Candidate A can preserve that shape without a
//! public dummy flag: both slots always carry a valid signature, descriptor,
//! and authorization path. Only note-tree membership for slot 1 remains gated
//! by the existing hidden dummy latch.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenInputShape {
    TwoReal,
    RealAndDummy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotEvidence {
    /// Checked natively by the node before a future STARK verification.
    pub signature_valid: bool,
    /// The future AIR reaches the authorization root from the public leaf.
    pub auth_path_bound: bool,
    /// That root/context is absorbed into this slot's hidden note key material.
    pub auth_root_bound_to_note: bool,
    /// The note commitment reaches the public anchor.
    pub note_membership: bool,
    /// Required for the hidden dummy slot by the existing balance latch.
    pub value_is_zero: bool,
}

pub fn accepts(shape: HiddenInputShape, slots: [SlotEvidence; 2]) -> bool {
    if slots
        .iter()
        .any(|slot| !slot.signature_valid || !slot.auth_path_bound || !slot.auth_root_bound_to_note)
    {
        return false;
    }
    // Slot 0 is never dummy. This is the load-bearing fact that makes an
    // operator-generated ephemeral key in dummy slot 1 harmless: slot 0's
    // note-bound phone signature still covers the complete common intent.
    if !slots[0].note_membership {
        return false;
    }
    match shape {
        HiddenInputShape::TwoReal => slots[1].note_membership,
        HiddenInputShape::RealAndDummy => slots[1].value_is_zero,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real() -> SlotEvidence {
        SlotEvidence {
            signature_valid: true,
            auth_path_bound: true,
            auth_root_bound_to_note: true,
            note_membership: true,
            value_is_zero: false,
        }
    }

    fn dummy() -> SlotEvidence {
        SlotEvidence {
            signature_valid: true,
            auth_path_bound: true,
            auth_root_bound_to_note: true,
            note_membership: false,
            value_is_zero: true,
        }
    }

    #[test]
    fn hidden_dummy_keeps_both_authorizations_and_slot_zero_membership() {
        assert!(accepts(HiddenInputShape::TwoReal, [real(), real()]));
        assert!(accepts(HiddenInputShape::RealAndDummy, [real(), dummy()]));

        let mut missing_signature = dummy();
        missing_signature.signature_valid = false;
        assert!(!accepts(
            HiddenInputShape::RealAndDummy,
            [real(), missing_signature]
        ));

        let mut missing_path = dummy();
        missing_path.auth_path_bound = false;
        assert!(!accepts(
            HiddenInputShape::RealAndDummy,
            [real(), missing_path]
        ));

        assert!(!accepts(HiddenInputShape::RealAndDummy, [dummy(), real()]));
        assert!(!accepts(HiddenInputShape::TwoReal, [real(), dummy()]));

        let mut minting_dummy = dummy();
        minting_dummy.value_is_zero = false;
        assert!(!accepts(
            HiddenInputShape::RealAndDummy,
            [real(), minting_dummy]
        ));
    }
}
