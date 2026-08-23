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
    /// The phone created this slot before signing the one complete intent.
    /// A worker-created dummy signature is valid cryptography but not phone
    /// authorization and therefore cannot satisfy Candidate A.
    pub phone_approved_complete_intent: bool,
    /// The future AIR reaches the authorization root from the public leaf.
    pub auth_path_bound: bool,
    /// That root is absorbed into this slot's hidden note key material.
    pub auth_root_bound_to_note: bool,
    /// The note commitment reaches the public anchor.
    pub note_membership: bool,
    /// Required for the hidden dummy slot by the existing balance latch.
    pub value_is_zero: bool,
}

pub fn accepts(shape: HiddenInputShape, slots: [SlotEvidence; 2]) -> bool {
    if slots.iter().any(|slot| {
        !slot.signature_valid
            || !slot.phone_approved_complete_intent
            || !slot.auth_path_bound
            || !slot.auth_root_bound_to_note
    }) {
        return false;
    }
    // Slot 0 is never dummy. This is the load-bearing fact that makes a
    // phone-generated ephemeral key in dummy slot 1 safe: both descriptors
    // exist before the phone approves the complete common intent.
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
            phone_approved_complete_intent: true,
            auth_path_bound: true,
            auth_root_bound_to_note: true,
            note_membership: true,
            value_is_zero: false,
        }
    }

    fn dummy() -> SlotEvidence {
        SlotEvidence {
            signature_valid: true,
            phone_approved_complete_intent: true,
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

        let mut worker_created_after_phone_signing = dummy();
        worker_created_after_phone_signing.phone_approved_complete_intent = false;
        assert!(!accepts(
            HiddenInputShape::RealAndDummy,
            [real(), worker_created_after_phone_signing]
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

    #[test]
    fn depth_zero_public_keys_fail_delayed_dummy_arity_indistinguishability() {
        let real_a = [0xa1u8; 32];
        let real_b = [0xb1u8; 32];
        let dummy_1 = [0xd1u8; 32];
        let dummy_2 = [0xd2u8; 32];

        // Two one-real spends repeat the always-real slot-0 key while their
        // phone-generated dummy keys do not repeat.
        let one_real_first = [real_a, dummy_1];
        let one_real_later = [real_a, dummy_2];
        assert_eq!(one_real_first[0], one_real_later[0]);
        assert_ne!(one_real_first[1], one_real_later[1]);

        // Once both real keys have appeared in the public history, a two-real
        // spend has two cluster members instead. No boolean flag is needed.
        let observed_real_slot_zero_keys = [real_a, real_b];
        let two_real = [real_a, real_b];
        assert!(two_real
            .iter()
            .all(|key| observed_real_slot_zero_keys.contains(key)));
        assert!(!one_real_first
            .iter()
            .all(|key| observed_real_slot_zero_keys.contains(key)));
    }
}
