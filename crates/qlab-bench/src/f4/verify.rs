//! Moved to `qlab_wrapper::verify` (lab #785, F5-1); re-exported here so
//! the bench and its tests are unchanged.
#![cfg_attr(not(test), allow(unused_imports))]
pub(crate) use qlab_wrapper::verify::*;
// The test module below reads its parent's imports through `super::*`.
#[cfg(test)]
#[allow(unused_imports)]
use p3_uni_stark::{verify, Proof};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_consensus::{Config, Val};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_l2::public_values;
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::dep::{claim_cvs, dep_chain, verify_dep_u32, DPV_D, DPV_DIG, DPV_N};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::hash::{WRoots, WTag, CLAIM_TAG, M_ABS};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::wleaf::{
    WAir, PV_AA, PV_AAN, PV_ABS, PV_C, PV_CH, PV_CHN, PV_CN, PV_D, PV_DB, PV_E, PV_EXC, PV_K, PV_KN, PV_N, PV_NN, PV_PREV, PV_R, PV_SD, PV_SIDE, PV_SUP,
    W_PV_LEN,
};
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::config::Outer;
#[cfg(test)]
#[allow(unused_imports)]
use qlab_wrapper::hash::{sd_chain_byte, Digest, Roots};

#[cfg(test)]
pub(crate) mod tests {
    //! One real two-slot W proof (b2), shared; the member proofs are stubs
    //! (their real check is `qlab_l2`'s own suite). Every native negative
    //! mutates the bundle or the predecessor and names the refusing check.
    use std::sync::OnceLock;

    use p3_uni_stark::prove;

    use super::super::dep::{prove_dep, DepEntry};
    use super::super::native::{Member, WInputs};
    use super::super::neg::{honest, wfixture, SEED};
    use super::*;

    /// A stub member proof: the member's own PVs, which the stub verifier
    /// compares — so "a proof that fails" is a mismatched stub.
    struct Stub;
    /// The chain the stub members were proven for.
    const STUB_L2_ID: u64 = 7;
    impl MemberVerifier<Vec<u32>> for Stub {
        fn verify(&self, m: &BundleMember<Vec<u32>>, l2_id: u64) -> Result<(), String> {
            if l2_id != STUB_L2_ID {
                return Err("wrong l2_id".into());
            }
            (m.proof == m.pvs).then_some(()).ok_or_else(|| "stub mismatch".into())
        }
    }

    struct Case {
        bundle_pvs: Vec<u32>,
        proof: Proof<LegacyNonHidingConfig>,
        members: Vec<Member>,
        prev: Surface,
        deps: Vec<DepEntry>,
        dep: (Vec<u32>, Proof<Config>),
    }

    const TEST_VERSION: u32 = 0x8002;

    /// The fixture `[S, C]` (a transaction and a claim, condition (a)'s
    /// boundary), proven once; its predecessor surface commits `inp.prev`.
    fn case() -> &'static Case {
        static C: OnceLock<Case> = OnceLock::new();
        C.get_or_init(|| {
            let mut fx = wfixture(&[WTag::P, WTag::C], SEED + 100);
            let pre = Surface::genesis(TEST_VERSION, STUB_L2_ID, fx.rin);
            // Rebuild the leaf with `prev` = the predecessor's commitment.
            let mut st = fx.pre.clone();
            fx.inp = WInputs { prev: pre.commitment, ..fx.inp.clone() };
            let (rin, wit, rout) = st.apply(&fx.inp, &fx.members).unwrap();
            fx.exit_cmt = super::super::native::check_wrapper_leaf(&rin, &fx.inp, &fx.members, &wit).unwrap().1;
            (fx.rin, fx.wit, fx.rout) = (rin, wit, rout);
            let (air, trace, pvs) = honest(&fx);
            let proof = prove(&make_legacy_config_with(&Outer::B2.cfg()), &air, trace, &pvs);
            let bundle_pvs = pvs.iter().map(|v| {
                use p3_field::PrimeField32;
                v.as_canonical_u32()
            }).collect();
            let dep = prove_dep(&fx.deps).expect("the claims' openings fit");
            Case { bundle_pvs, proof, members: fx.members.clone(), prev: pre, deps: fx.deps.clone(), dep }
        })
    }

    /// The shared case's W proof (K = 2, b2) and its PVs — F4b-1's gate
    /// census walks it rather than proving a second W.
    pub(crate) fn case_w_proof() -> (&'static Proof<LegacyNonHidingConfig>, Vec<Val>) {
        let c = case();
        (&c.proof, public_values(&c.bundle_pvs))
    }

    fn bundle(c: &Case) -> Bundle<'_, Vec<u32>> {
        Bundle {
            version: TEST_VERSION,
            w_pvs: c.bundle_pvs.clone(),
            w_proof: &c.proof,
            members: c.members.iter().map(|m| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: m.pvs.clone() }).collect(),
            dep_pvs: c.dep.0.clone(),
            dep_proof: &c.dep.1,
        }
    }

    const ANY: &dyn Fn(&Digest) -> bool = &|_| true;

    /// Lab #785 F5-2: version 1 proves W on `W_V1_CFG` (b2/q91); the
    /// measurement versions keep their lanes (b2/q86, b4/q43), and `B2_CFG`
    /// stays M4's interior lane. The K = 16 bundle is 18 proofs, so each
    /// needs 100 + log₂ 18 = 104.17 bits (rec.rs's accounting): the frozen
    /// L2 lane and W v1 clear it, q86 does not, and the union over 16 + 1
    /// member-lane proofs and W clears 100.
    #[test]
    fn version_1_is_w_v1_and_the_bundle_clears_its_budget() {
        use crate::f4::rec::{BETA_B2, BETA_B4, GRIND};
        use qlab_wrapper::config::{B2_CFG, W_V1_CFG};
        // `FriCfg` has no `PartialEq`; its label spells all five fields.
        let lab = |id: u32| version_cfg(id).map(|c| c.label());
        assert_eq!(lab(1), Some(W_V1_CFG.label()));
        assert_eq!(W_V1_CFG.label(), "b2/q91/g22/fp16/a16");
        for id in [0x8001, 0x8002, 0x8004, 0x8008] {
            assert_eq!(lab(id), Some(B2_CFG.label()), "{id:#x}: measurement only, q86");
        }
        assert_eq!(lab(0x8110), Some(Outer::B4.cfg().label()));
        assert!(version_cfg(2).is_none());
        assert_eq!(B2_CFG.label(), "b2/q86/g22/fp16/a16", "M4's interior lane, unchanged");
        assert_eq!(crate::m4interior::INTERIOR_B2_CFG.label(), B2_CFG.label());
        let need = 100.0 + 18f64.log2();
        let l2 = qlab_l2::L2_CFG_PROVISIONAL.num_queries as f64 * BETA_B4 + GRIND;
        let w = W_V1_CFG.num_queries as f64 * BETA_B2 + GRIND;
        assert!(l2 >= need && w >= need, "{l2} {w} vs {need}");
        assert!(B2_CFG.num_queries as f64 * BETA_B2 + GRIND < need, "q86 alone would not clear the bundle's budget");
        let composed = -(17.0 * 2f64.powf(-l2) + 2f64.powf(-w)).log2();
        assert!(composed >= 100.0, "{composed}");
    }

    #[test]
    fn f4_verify_wrapper_accepts_and_chains() {
        let c = case();
        let s = verify_wrapper(&bundle(c), &c.prev, &Stub, ANY).expect("the honest wrapper");
        assert_eq!(s.prev, c.prev.commitment);
        assert_ne!(s.commitment, c.prev.commitment);
        assert_eq!(s.out.k_next, c.prev.out.k_next + 1, "one claim");
    }

    /// Condition (a): swapping the claim and the transaction across the slot
    /// boundary changes SD's order — refused at V4.
    #[test]
    fn f4_verify_wrapper_negatives() {
        let c = case();
        let mut b = bundle(c);
        b.members.swap(0, 1);
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Sd, "(a) swap across the boundary");

        let mut b = bundle(c);
        b.members[1].pvs[qlab_air::claim::PV_FEE] ^= 1;
        b.members[1].proof = b.members[1].pvs.clone();
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Sd, "a member PV not the one W absorbed");

        let mut b = bundle(c);
        b.members[0].proof[0] ^= 1;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Member(0, "stub mismatch".into()), "V2");

        let mut b = bundle(c);
        b.members.pop();
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Members, "V1");

        let mut b = bundle(c);
        b.version = 0x8004;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Version, "a version the chain is not on");
        let mut on4 = c.prev.clone();
        on4.version = 0x8004;
        assert_eq!(verify_wrapper(&b, &on4, &Stub, ANY).unwrap_err(), VError::Members, "a k = 4 chain given two members");
        b.version = 0x8003;
        on4.version = 0x8003;
        assert_eq!(verify_wrapper(&b, &on4, &Stub, ANY).unwrap_err(), VError::Version, "an unknown version");

        let mut b = bundle(c);
        b.w_pvs[PV_SIDE + PV_C] ^= 1;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::WProof, "V3: W's PVs moved");
        b.w_pvs[PV_SIDE + PV_C] = 1 << 16;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::PvRange, "V0: a 17-bit chunk");

        // V5: a predecessor whose out is not W's in.
        let mut other = c.prev.clone();
        other.out.k_next += 1;
        other.commitment = Surface::commit(other.version, other.l2_id, &other.prev, &other.out, &other.newest_anchor, &other.exit_cmt);
        assert_eq!(verify_wrapper(&bundle(c), &other, &Stub, ANY).unwrap_err(), VError::Thread("k_next"));

        // V6, the replayed-ρ case: a second wrapper built on the same `prev`
        // as an accepted one (so the same fee-note ρ) is checked against the
        // accepted one's surface — its `prev` is not that commitment.
        let accepted = verify_wrapper(&bundle(c), &c.prev, &Stub, ANY).unwrap();
        let mut ahead = accepted.clone();
        ahead.out = c.prev.out;
        assert_eq!(verify_wrapper(&bundle(c), &ahead, &Stub, ANY).unwrap_err(), VError::Prev, "a replayed prev");

        // (g), review R1: a member word p + x at a position W does not capture
        // (a claim's Cv) — refused on the u32, before any reduction; and a
        // 32-bit position (P's vpa) at p.
        use p3_field::PrimeField32;
        let p = Val::ORDER_U32;
        let mut b = bundle(c);
        b.members[1].pvs[qlab_air::claim::PV_CV] += p;
        b.members[1].proof = b.members[1].pvs.clone();
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::MemberPv(1), "(g) p + x");
        let mut b = bundle(c);
        b.members[0].pvs[qlab_air::l2p::PV_VP1 + 5] = p;
        b.members[0].proof = b.members[0].pvs.clone();
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::MemberPv(0), "(g) a 32-bit word at p");

        // (h), review R2: the version and l2_id are the chain's.
        let mut other = c.prev.clone();
        other.version = 0x8004;
        assert_eq!(verify_wrapper(&bundle(c), &other, &Stub, ANY).unwrap_err(), VError::Version, "(h) a bundle version the chain is not on");
        let mut other = c.prev.clone();
        other.l2_id = STUB_L2_ID + 1;
        other.commitment = Surface::commit(other.version, other.l2_id, &other.prev, &other.out, &other.newest_anchor, &other.exit_cmt);
        assert_eq!(verify_wrapper(&bundle(c), &other, &Stub, ANY).unwrap_err(), VError::Member(0, "wrong l2_id".into()), "(h) another chain's l2_id");

        // V8: E_cum above D_cum on W's out (checked before the proof).
        let mut b = bundle(c);
        let d0 = b.w_pvs[PV_SIDE + PV_D + 3];
        b.w_pvs[PV_SIDE + PV_E + 3] = d0 + 1;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::EAboveD, "V8");

        // V7 (F5's stub).
        let absorbed0 = digest_at(&c.bundle_pvs, PV_ABS);
        let not_first: &dyn Fn(&Digest) -> bool = &move |a| *a != absorbed0;
        assert_eq!(verify_wrapper(&bundle(c), &c.prev, &Stub, not_first).unwrap_err(), VError::Anchor(0));
    }

    /// V9, the deposit-sum proof (review S3; conditions (o), (p)). Every
    /// refusal lands before V3, so the synthetic two-claim bundles below
    /// need no W proof of their own.
    #[test]
    fn f4_verify_wrapper_deposit_negatives() {
        let c = case();
        let run = |b: &Bundle<'_, Vec<u32>>| verify_wrapper(b, &c.prev, &Stub, ANY);

        // (p): a 17-bit word, refused before conversion; p + n likewise.
        let mut b = bundle(c);
        b.dep_pvs[DPV_DIG] += 1 << 16;
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::PvRange), "(p) a 17-bit word");
        use p3_field::PrimeField32;
        let mut b = bundle(c);
        b.dep_pvs[DPV_N] += Val::ORDER_U32;
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::PvRange), "(p) p + n");
        // A PV the proof does not carry.
        let mut b = bundle(c);
        b.dep_pvs[DPV_D] ^= 1;
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::Proof), "D_batch moved under the proof");
        // D_batch not W's.
        let mut b = bundle(c);
        b.w_pvs[PV_DB] ^= 1;
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::DBatch), "W's D_batch not the deposits'");
        // (o): n above the claim count — a real proof over one more entry.
        let extra = [c.deps.clone(), vec![DepEntry { v: 9, r_v: [7; 4] }]].concat();
        let (pvs, proof) = prove_dep(&extra).unwrap();
        let mut b = bundle(c);
        (b.dep_pvs, b.dep_proof) = (pvs, &proof);
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::Count), "(o) n > the claim count");
        // A proof over another Cv list of the right length.
        let (pvs, proof) = prove_dep(&[DepEntry { v: c.deps[0].v, r_v: [3; 4] }]).unwrap();
        let mut b = bundle(c);
        (b.dep_pvs, b.dep_proof) = (pvs, &proof);
        assert_eq!(run(&b).unwrap_err(), VError::Dep(DepCheck::Digest), "another Cv list");

        // Two claims: honest V9 passes (the refusal is V3's, a proof this
        // synthetic bundle lacks); reordered, or the last dropped, it refuses.
        let fx = wfixture(&[WTag::C, WTag::C], SEED);
        // One deposit proof per statement (review T2): the in-order and the
        // reordered bundles share the full list's.
        let full = prove_dep(&fx.deps).unwrap();
        let first = prove_dep(&fx.deps[..1]).unwrap();
        let two = |order: [usize; 2], deps: &[DepEntry], dep: &(Vec<u32>, Proof<Config>)| -> Result<Surface, VError> {
            let mut b = bundle(c);
            b.members = order
                .iter()
                .map(|i| {
                    let m = &fx.members[*i];
                    BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: m.pvs.clone() }
                })
                .collect();
            let d: u64 = deps.iter().map(|e| e.v).sum();
            for j in 0..4 {
                b.w_pvs[PV_DB + j] = ((d >> (16 * j)) & 0xffff) as u32;
            }
            b.dep_pvs = dep.0.clone();
            b.dep_proof = &dep.1;
            run(&b)
        };
        assert_eq!(two([0, 1], &fx.deps, &full).unwrap_err(), VError::WProof, "V9 holds for the two claims in order");
        assert_eq!(two([1, 0], &fx.deps, &full).unwrap_err(), VError::Dep(DepCheck::Digest), "claims reordered against the Cv chain");
        assert_eq!(two([0, 1], &fx.deps[..1], &first).unwrap_err(), VError::Dep(DepCheck::Count), "the last Cv dropped");
    }

    /// The versions: 1 is K = 16 at b2; devnet versions carry their k.
    #[test]
    fn f4_versions() {
        assert_eq!(version(1).map(|v| v.0), Some(16));
        assert_eq!(version(0x8002).map(|v| v.0), Some(2));
        assert_eq!(version(2), None);
        assert_eq!(version(0x8110).map(|v| v.1), Some(Outer::B4));
        assert_eq!(version_for(16, Outer::B2), Some(1));
        assert_eq!(version_for(16, Outer::B4), Some(0x8110));
        // One version per (k, lane).
        for (i, a) in VERSIONS.iter().enumerate() {
            assert!(VERSIONS[i + 1..].iter().all(|b| (a.1, a.2) != (b.1, b.2) && a.0 != b.0));
        }
    }
}
