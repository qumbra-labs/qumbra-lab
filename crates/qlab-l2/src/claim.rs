//! The bridge's claim proof (F1, lab #756): prove / verify over
//! [`qlab_air::claim::ClaimAir`] under the L2 lane (ruling Q2: a claim lives
//! on L2 DA, never on the L1 wire).
//!
//! **The verifier owns two public values.** One AIR serves every chain, so
//! the AIR takes the burn address and the fee as public values; a verifier
//! that did not check them would credit another L2's burns, or a fee of its
//! prover's choosing. [`verify_claim`] refuses, by name and before the proof
//! is read, a `rkm_burn` that is not its own chain's and a fee that is not
//! its claim tariff ([`ClaimRefusal`]).
//!
//! Not a [`crate::Shape`]: the claim is not an L2 transaction shape and has
//! no shape digest yet — the asset-0 mint edge's state rule (shape C) is
//! F4/F6's.

use std::sync::OnceLock;

use p3_uni_stark::{prove, verify};

use crate::{make_config_l2, public_values, Config, Proof, Val, L2_CFG};
pub use qlab_air::claim::{
    build_claim, build_claim_with_witness, pv_vec_claim, rkm_burn, BurnNote, ClaimAir, ClaimCredit,
    ClaimInstance, CLAIM_PERMS, CLAIM_WIDTH, PV_A, PV_CM2, PV_CNF, PV_CV, PV_FEE, PV_LEN,
    PV_RKM_BURN,
};

/// log2 of the claim trace height (41 perms → 2^17).
pub const LOG_HEIGHT_CLAIM: usize = qlab_air::claim::CLAIM_LOG_HEIGHT;

/// **`fee_tier_claim` — a labelled PLACEHOLDER**: the fee a claim pays out of
/// its credit (l2-architecture §7 item 4, the claim bootstrap — a first-time
/// depositor holds no asset 0 to pay with). The claim proves `credit = v −
/// fee` against a public fee; the verifier checks that fee against this
/// tariff. Its value is F4/F6's (the Annulet genesis parameters, beside
/// `fee_tier_s` / `_p` / `_r`); this is not it.
pub const FEE_TIER_CLAIM_PLACEHOLDER: u64 = 4;

/// Why a claim was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// The public-value vector is not a claim's length.
    PvLength,
    /// A public value outside its declared range (lab #758: every claim
    /// public value is a 16-bit chunk).
    PvRange,
    /// The claimed burn is to another chain's burn address (or none).
    RkmBurnNotThisChain,
    /// The fee is not this chain's claim tariff.
    FeeNotTheTariff,
    /// The STARK does not verify against the public values.
    Proof,
}

/// The canonical claim program, read off the fixture's builder (every claim
/// builds the same program — `claim_verifier_air_is_instance_independent`).
pub fn canonical_program_claim() -> &'static [u32] {
    static P: OnceLock<Vec<u32>> = OnceLock::new();
    P.get_or_init(|| crate::fixture::claim().air.program.to_vec())
}

/// The witness-free claim AIR a verifier uses.
pub fn verifier_air_claim() -> ClaimAir {
    ClaimAir {
        program: canonical_program_claim().try_into().expect("claim program length"),
        ..ClaimAir::chain_only(LOG_HEIGHT_CLAIM)
    }
}

/// Prove a claim under the L2 lane. Returns the public values alongside the
/// proof.
pub fn prove_claim(inst: &ClaimInstance) -> (Vec<Val>, Proof<Config>) {
    assert_eq!(inst.air.log_height, LOG_HEIGHT_CLAIM, "a claim proves at 2^{LOG_HEIGHT_CLAIM}");
    let pvs = public_values(&inst.pvs);
    let trace = inst.air.generate_trace::<Val>(L2_CFG.log_blowup);
    let proof = prove(&make_config_l2(), &inst.air, trace, &pvs);
    (pvs, proof)
}

/// The verifier's own checks of a claim's public values, before the proof:
/// the length, the burn address of chain `l2_id`, the claim tariff.
pub fn check_claim_surface(pvs: &[Val], l2_id: u64, fee_tier: u64) -> Result<(), ClaimRefusal> {
    if pvs.len() != PV_LEN {
        return Err(ClaimRefusal::PvLength);
    }
    if !crate::pv_in_range(pvs, &qlab_air::claim::audit_pv_bits()) {
        return Err(ClaimRefusal::PvRange);
    }
    let burn = public_values(&pv_vec_claim(&[0; 4], &[0; 4], &[0; 4], &[0; 4], &rkm_burn(l2_id), fee_tier));
    if pvs[PV_RKM_BURN..PV_RKM_BURN + 16] != burn[PV_RKM_BURN..PV_RKM_BURN + 16] {
        return Err(ClaimRefusal::RkmBurnNotThisChain);
    }
    if pvs[PV_FEE..PV_FEE + 4] != burn[PV_FEE..PV_FEE + 4] {
        return Err(ClaimRefusal::FeeNotTheTariff);
    }
    Ok(())
}

/// Verify a claim for chain `l2_id` at claim tariff `fee_tier`: the surface
/// checks, then the STARK against the canonical AIR.
pub fn verify_claim(pvs: &[Val], proof: &Proof<Config>, l2_id: u64, fee_tier: u64) -> Result<(), ClaimRefusal> {
    check_claim_surface(pvs, l2_id, fee_tier)?;
    verify(&make_config_l2(), &verifier_air_claim(), proof, pvs).map_err(|_| ClaimRefusal::Proof)
}

/// The typed claim entry: `u32` PVs, length- and range-checked before the
/// mod-p conversion ([`crate::pv_u32_in_range`]), then [`verify_claim`].
pub fn verify_claim_u32(pvs: &[u32], proof: &Proof<Config>, l2_id: u64, fee_tier: u64) -> Result<(), ClaimRefusal> {
    if pvs.len() != PV_LEN {
        return Err(ClaimRefusal::PvLength);
    }
    if !crate::pv_u32_in_range(pvs, &qlab_air::claim::audit_pv_bits()) {
        return Err(ClaimRefusal::PvRange);
    }
    verify_claim(&public_values(pvs), proof, l2_id, fee_tier)
}

#[cfg(test)]
mod tests {
    use p3_air::symbolic::{get_max_constraint_degree, AirLayout};
    use p3_air::BaseAir;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::fixture::{self, CLAIM_L2_ID};

    /// Geometry of the AIR the verifier uses: width 655, degree 4, 41 perms in
    /// 2^17, 84 public values at the documented offsets.
    #[test]
    fn claim_geometry_is_locked() {
        let air = verifier_air_claim();
        assert_eq!(<ClaimAir as BaseAir<Val>>::width(&air), 655);
        assert_eq!(CLAIM_WIDTH, 655);
        assert_eq!(<ClaimAir as BaseAir<Val>>::num_public_values(&air), 84);
        assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 4);
        assert_eq!((CLAIM_PERMS, LOG_HEIGHT_CLAIM), (41, 17));
        const { assert!(CLAIM_PERMS * qlab_air::l2::ROWS_PER_PERM <= 1 << LOG_HEIGHT_CLAIM) };
        assert_eq!((PV_A, PV_CNF, PV_CV, PV_CM2, PV_RKM_BURN, PV_FEE, PV_LEN), (0, 16, 32, 48, 64, 80, 84));
    }

    /// The verifier's AIR is a function of the program alone: claims of other
    /// notes, values, fees and paths build the canonical program.
    #[test]
    fn claim_verifier_air_is_instance_independent() {
        let note = |v: u64, l2: u64| BurnNote { value: v, rkm: rkm_burn(l2), rho: [v; 4], rseed: [v.wrapping_add(1); 4] };
        let credit = ClaimCredit { rkm: [5; 4], rseed: [6; 4] };
        for (v, l2, fee) in [(1u64, 1u64, 0u64), (u64::MAX, 2, 7), (10, 3, 10)] {
            let inst = build_claim(LOG_HEIGHT_CLAIM, l2, &note(v, l2), &[9; 4], &credit, fee);
            assert_eq!(&inst.air.program[..], canonical_program_claim(), "claim ({v}, {l2}, {fee})");
        }
    }

    /// Q5's refusals, by name, with no proof read: another chain's burn
    /// address, a fee off the tariff, a wrong-length vector.
    #[test]
    fn claim_surface_refusals() {
        let inst = fixture::claim();
        let pvs = public_values(&inst.pvs);
        let tier = FEE_TIER_CLAIM_PLACEHOLDER;
        assert_eq!(check_claim_surface(&pvs, CLAIM_L2_ID, tier), Ok(()));
        assert_eq!(check_claim_surface(&pvs, CLAIM_L2_ID + 1, tier), Err(ClaimRefusal::RkmBurnNotThisChain));
        assert_eq!(check_claim_surface(&pvs, CLAIM_L2_ID, tier + 1), Err(ClaimRefusal::FeeNotTheTariff));
        assert_eq!(check_claim_surface(&pvs, CLAIM_L2_ID, 0), Err(ClaimRefusal::FeeNotTheTariff));
        assert_eq!(check_claim_surface(&pvs[..PV_FEE], CLAIM_L2_ID, tier), Err(ClaimRefusal::PvLength));
        let mut bad = pvs.clone();
        bad[PV_RKM_BURN + 15] += Val::ONE;
        assert_eq!(check_claim_surface(&bad, CLAIM_L2_ID, tier), Err(ClaimRefusal::RkmBurnNotThisChain));
        // Lab #758: a chunk ≥ 2^16 anywhere is refused by name.
        let mut bad = pvs.clone();
        bad[PV_CV + 2] += Val::from_u32(1 << 16);
        assert_eq!(check_claim_surface(&bad, CLAIM_L2_ID, tier), Err(ClaimRefusal::PvRange));
    }

    /// The claim through the real prover under the L2 lane, verified by the
    /// canonical AIR. The same proof is refused for another chain (the burn
    /// address), at another tariff, and with a moved `cnf` / `Cv` / `cm2` —
    /// and, with the surface republished for chain 2, by the STARK itself.
    #[test]
    fn claim_prove_verify_roundtrip() {
        let inst = fixture::claim();
        let tier = FEE_TIER_CLAIM_PLACEHOLDER;
        let (pvs, proof) = prove_claim(&inst);
        assert_eq!(verify_claim(&pvs, &proof, CLAIM_L2_ID, tier), Ok(()), "the honest claim verifies");
        assert_eq!(verify_claim(&pvs, &proof, CLAIM_L2_ID + 1, tier), Err(ClaimRefusal::RkmBurnNotThisChain));
        assert_eq!(verify_claim(&pvs, &proof, CLAIM_L2_ID, tier + 1), Err(ClaimRefusal::FeeNotTheTariff));
        for (what, off) in [("cnf", PV_CNF), ("Cv", PV_CV), ("cm2", PV_CM2), ("A", PV_A)] {
            let mut bad = pvs.clone();
            bad[off + 3] += Val::ONE;
            assert_eq!(verify_claim(&bad, &proof, CLAIM_L2_ID, tier), Err(ClaimRefusal::Proof), "a moved {what}");
        }
        let mut other = pvs.clone();
        let burn2 = public_values(&pv_vec_claim(&[0; 4], &[0; 4], &[0; 4], &[0; 4], &rkm_burn(CLAIM_L2_ID + 1), tier));
        other[PV_RKM_BURN..PV_RKM_BURN + 16].copy_from_slice(&burn2[PV_RKM_BURN..PV_RKM_BURN + 16]);
        assert_eq!(
            verify_claim(&other, &proof, CLAIM_L2_ID + 1, tier),
            Err(ClaimRefusal::Proof),
            "a chain-1 burn republished as chain 2's"
        );
    }
}
