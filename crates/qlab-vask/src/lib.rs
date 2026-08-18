//! Exchange/VASP kit verifier lib — **stage 0 skeleton** (lab #483).
//!
//! Verify the wallet-interop §3 deposit-disclosure envelope, no I/O — the
//! library an exchange links to refuse anonymous deposits at crediting time
//! (auditable-privacy §4 "Edge" layer). The full proposal, inventory and
//! priced alternatives: `docs/kit-stage0-survey.md`.
//!
//! Stage 0 deliberately builds nothing: this crate re-exports the inventoried
//! surface and carries the survey's **citation tests** — compile-time
//! assertions that the named entry points exist with the inventoried
//! signatures, plus the parse-refusal paths, none of which invoke the prover
//! (the disclosure STARK's prove tests are the CI lane's; memory guardrail).
//!
//! Stage 1 (not this crate yet): the kit's own named-refusal wrapper, the
//! pinned `DISCLOSURE_V1_CFG`, the `qvask` C ABI + #246-pinned header, and
//! golden disclosure fixtures. Survey §3 is the proposal it builds from.

pub use qlab_disclosure::envelope::{Envelope, EnvelopeError, CLAIM_SENT_PAYMENT, ENVELOPE_VER};

#[cfg(test)]
mod citation_tests {
    //! The stage-0 inventory's citations, as assertions (survey §1.1/§5).

    use qlab_disclosure::air::{pv_vec, DisclosureAir, DisclosureInstance, PV_LEN};
    use qlab_disclosure::envelope::{Envelope, EnvelopeError, CLAIM_SENT_PAYMENT, ENVELOPE_VER};
    use qlab_disclosure::prove::{verify as stark_verify, DisclosureProof, FriCfg, CONSENSUS_CFG};

    /// Survey §1.1: the inventoried entry points exist with the inventoried
    /// signatures. Pure compile-time citations — nothing here proves.
    #[test]
    fn the_inventoried_entry_points_exist() {
        let _create: fn(&DisclosureInstance, [u8; 32], u8, &FriCfg) -> Envelope =
            Envelope::create;
        let _to_bytes: fn(&Envelope) -> Vec<u8> = Envelope::to_bytes;
        let _from_bytes: fn(&[u8]) -> Result<Envelope, EnvelopeError> = Envelope::from_bytes;
        let _verify: fn(&Envelope, &[u8; 32], usize, &FriCfg) -> Result<(), EnvelopeError> =
            Envelope::verify;
        let _stark_verify: fn(
            &DisclosureAir,
            &DisclosureProof,
            &[u32],
            &FriCfg,
        ) -> Result<(), String> = stark_verify;
        let _verifier_air: fn(usize) -> DisclosureAir = DisclosureAir::verifier;
    }

    /// Survey §1.1: envelope constants are the §3 values the kit pins.
    #[test]
    fn the_envelope_constants_are_the_spec_values() {
        assert_eq!(ENVELOPE_VER, 0x01);
        assert_eq!(CLAIM_SENT_PAYMENT, 0x01);
    }

    /// Survey §1.1: the public-value layout the verifier reconstructs is
    /// 36 u32 chunks (cm 16 ‖ addr 16 ‖ value 4). No trace, no proof.
    #[test]
    fn the_pv_layout_is_36_chunks() {
        assert_eq!(PV_LEN, 36);
        assert_eq!(pv_vec(&[0u64; 4], &[0u64; 4], 0).len(), PV_LEN);
    }

    /// Survey §1.1: the witness-free verifier AIR constructs at the
    /// inventoried height without any witness or proving.
    #[test]
    fn the_verifier_air_constructs_witness_free() {
        let _ = DisclosureAir::verifier(16);
    }

    /// Survey §1.1 / §3: the parse-refusal paths behave as inventoried —
    /// §3 rule 3 rejects unknown ver/claim_type rather than ignoring.
    #[test]
    fn parse_refusals_are_named() {
        assert!(matches!(
            Envelope::from_bytes(&[]),
            Err(EnvelopeError::Malformed(_))
        ));
        assert!(matches!(
            Envelope::from_bytes(&[0x02]),
            Err(EnvelopeError::UnknownVersion(0x02))
        ));
        assert!(matches!(
            Envelope::from_bytes(&[0x01, 0x03]),
            Err(EnvelopeError::UnknownClaimType(0x03))
        ));
    }

    /// Survey §3: the proposed qvask refusal taxonomy maps EVERY
    /// EnvelopeError variant. The match is exhaustive on purpose — a new
    /// variant in qlab-disclosure refuses to compile here until the ABI
    /// taxonomy decides its code, instead of silently falling through.
    #[test]
    fn the_refusal_taxonomy_covers_every_variant() {
        fn qvask_code(e: &EnvelopeError) -> i32 {
            match e {
                EnvelopeError::Malformed(_) => -2,
                EnvelopeError::UnknownVersion(_) => -3,
                EnvelopeError::UnknownClaimType(_) => -4,
                EnvelopeError::ProofDecode => -5,
                EnvelopeError::ProofInvalid(_) => -6,
            }
        }
        assert_eq!(qvask_code(&EnvelopeError::ProofDecode), -5);
    }

    /// Survey §1.1: the reference config this crate inherits today is the
    /// measured q20 point (102-bit conjectured; milestone-log.md:46 records
    /// why it stayed q20 when the consensus lane moved to q21). Stage 1's
    /// DISCLOSURE_V1_CFG decision starts from this pin.
    #[test]
    fn the_inherited_reference_config_is_the_measured_q20_point() {
        assert_eq!(CONSENSUS_CFG.log_blowup, 4);
        assert_eq!(CONSENSUS_CFG.num_queries, 20);
        assert_eq!(CONSENSUS_CFG.grind_bits, 22);
        assert!(CONSENSUS_CFG.conjectured_bits() >= 100);
    }
}
