//! Lab #775 F4-1 — `verify_wrapper`, the **native reference verifier** of one
//! wrapper (Larry's Q2 = A: the enshrined object stays l2-architecture §5's
//! single wrapper proof; this bundle verifier is what devnet and the tests
//! use, and F4b moves each of its checks in-circuit).
//!
//! A bundle is W's proof and public values plus its members (L2 transaction
//! and claim proofs with their PV vectors), in the one canonical order
//! (condition (a)). The verifier holds the predecessor's [`Surface`] and
//! checks, in order — each check names the **F4b in-circuit counterpart** it
//! maps onto one-to-one:
//!
//! | # | check | F4b counterpart |
//! |---|---|---|
//! | V0 | the version is the chain's (`prev.version`) and fixes W's `k` and outer config; W's PVs are 16-bit chunks | the wrapper's AIR identity is fixed by `version` inside the recursion |
//! | V1 | exactly `k` members | the recursion's per-slot member count |
//! | V2 | every member's `u32` PVs are inside its AIR's declared widths **before** any mod-p conversion (`qlab_l2::pv_u32_in_range`: a 32-bit position requires `< p`), then its proof verifies through the typed `u32` entries (`qlab_l2::verify_{s,p,r}_u32`, `claim::verify_claim_u32`) for the chain's `l2_id` (`prev.l2_id`) | in-circuit member verification (F2's C1/C2 class) with `check_leaf_pvs`, whose PV words are range-checked limbs |
//! | V3 | W's proof verifies under the version's AIR and config | the wrapper root proof |
//! | V4 | SD over the members' `(tag, PVs)`, in order, from `W.SD_in`, equals `W.SD_out` (F3's MD chain) | the batch side's SD, computed where member proofs are aggregated, equated to W's |
//! | V5 | W's threading-in equals the predecessor's out | stays verifier-side (reading B): a public-input equality |
//! | V6 | `W.prev` is the predecessor's surface commitment | stays verifier-side (reading B) |
//! | V7 | every absorbed root is a genuine recent finalized L1 root | F5's L1 rule; stubbed here as a caller predicate |
//! | V8 | `E_cum ≤ D_cum` on W's out | stays public arithmetic on the surface (F5's L1 rule) |
//! | V9 | the deposit-sum proof ([`super::dep`]): its `u32` PVs are 16-bit words (before conversion), it verifies under the hiding L2 config, its `n` is the bundle's claim count, its `dig` the chain over the claims' `Cv` PVs in bundle order, its `D_batch` W's `PV_DB` | **in-circuit**: the deposit proof's verification (a hiding member proof, V2's class) and `dig`'s recomputation over the claims' `Cv` PVs where the members are aggregated (V4's place); `n` and `D_batch` become equalities between that proof's PVs and the aggregated count / W's own PV. **Nothing of V9 stays verifier-side** |
//!
//! V8 is meaningful only with V9: W takes `D_batch` as a public value, and
//! V9 is what ties it to the claims' deposits (review S3).
//!
//! Member proofs pass through the typed entries only, never a raw
//! field-element path (ruling condition (b): the L2 entries take `u32` PVs
//! via `public_values` and refuse any outside `audit_pv_bits`, lab #758).
#![cfg_attr(not(test), allow(dead_code))]
use p3_uni_stark::{verify, Proof};
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
use qlab_consensus::{Config, Val};
use qlab_l2::public_values;

use super::dep::{claim_cvs, dep_chain, verify_dep_u32, DPV_D, DPV_DIG, DPV_N};
use super::native::{WRoots, WTag, CLAIM_TAG, M_ABS};
use super::wleaf::{
    WAir, PV_AA, PV_AAN, PV_ABS, PV_C, PV_CH, PV_CHN, PV_CN, PV_D, PV_DB, PV_E, PV_EXC, PV_K, PV_KN, PV_N, PV_NN, PV_PREV, PV_R, PV_SD, PV_SIDE, PV_SUP,
    W_PV_LEN,
};
use crate::f3::bench::Outer;
use crate::f3::native::{sd_chain_byte, Digest, Roots};

/// The wrapper statement versions this verifier knows: `(k, outer lane)`.
/// Version 1 is ruling Q1's K = 16 on the decided b2 lane; `0x8000 | k` are
/// devnet/test versions of smaller `k`.
pub(crate) fn version(id: u32) -> Option<(usize, Outer)> {
    VERSIONS.iter().find(|(v, _)| *v == id).map(|(_, k)| (*k, Outer::B2))
}

/// `(version, k)`, every one on the b2 lane.
pub(crate) const VERSIONS: [(u32, usize); 5] = [(1, 16), (0x8001, 1), (0x8002, 2), (0x8004, 4), (0x8008, 8)];
const _: () = {
    let mut i = 0;
    while i < VERSIONS.len() {
        assert!(VERSIONS[i].1 <= super::wleaf::MAX_K);
        assert!(VERSIONS[i].1 <= super::dep::DEP_CAP);
        i += 1;
    }
};

/// The surface commitment's tag in the MD chain (distinct from every slot tag).
pub(crate) const SURFACE_TAG: u8 = 0x10;
/// `state_root`'s tag.
pub(crate) const STATE_ROOT_TAG: u8 = 0x11;

/// Q9 (§5): `state_root = H(N ‖ C ‖ R ‖ CH)` — F3's MD chain under
/// [`STATE_ROOT_TAG`]; `K` (`cnf_root`), `AA` (`anchor_acc`) and the supply
/// root (`supply_cmt`) are separate surface fields, not inside it.
pub(crate) fn state_root(r: &WRoots) -> Digest {
    let mut w: Vec<u32> = Vec::new();
    for d in [&r.f3.n, &r.f3.c, &r.f3.r, &r.ch] {
        w.extend(crate::f3::cmp::limbs(d));
    }
    sd_chain_byte(&[0; 4], STATE_ROOT_TAG, &w).1
}

/// What the verifier keeps of an accepted wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Surface {
    pub version: u32,
    pub l2_id: u64,
    pub prev: Digest,
    pub out: WRoots,
    /// The newest absorbed L1 root (§5's `anchor_acc` pairs it with AA's root).
    pub newest_anchor: Digest,
    /// The batch's exit list commitment (§5's `exit_cmt`).
    pub exit_cmt: Digest,
    pub commitment: Digest,
}

impl Surface {
    /// The surface commitment — F3's MD chain under [`SURFACE_TAG`] over
    /// §5's fields in order (`version`, `l2_id`, `prev`, `state_root`,
    /// `anchor_acc` = AA's root and next index and the newest absorbed root,
    /// `D_cum`, `E_cum`, `exit_cmt`, `cnf_root` = K's root and next index,
    /// `supply_cmt`), then the threading values §5 leaves implicit (`SD`, the
    /// next indices of N, C and CH), which the next wrapper's V5 needs.
    pub(crate) fn commit(version: u32, l2_id: u64, prev: &Digest, out: &WRoots, newest_anchor: &Digest, exit_cmt: &Digest) -> Digest {
        let mut w: Vec<u32> = vec![version];
        let d = |w: &mut Vec<u32>, x: &Digest| w.extend(crate::f3::cmp::limbs(x));
        let u = |w: &mut Vec<u32>, x: u64| w.extend((0..4).map(|j| ((x >> (16 * j)) & 0xffff) as u32));
        u(&mut w, l2_id);
        d(&mut w, prev);
        d(&mut w, &state_root(out));
        d(&mut w, &out.aa);
        u(&mut w, out.aa_next);
        d(&mut w, newest_anchor);
        u(&mut w, out.d_cum);
        u(&mut w, out.e_cum);
        d(&mut w, exit_cmt);
        d(&mut w, &out.k);
        u(&mut w, out.k_next);
        d(&mut w, &out.sup);
        d(&mut w, &out.f3.sd);
        u(&mut w, out.f3.n_next);
        u(&mut w, out.f3.c_next);
        u(&mut w, out.ch_next);
        sd_chain_byte(&[0; 4], SURFACE_TAG, &w).1
    }

    /// A chain's origin: the state at genesis, pinned at the upgrade.
    pub(crate) fn genesis(version: u32, l2_id: u64, out: WRoots) -> Self {
        let (prev, newest_anchor, exit_cmt) = ([0; 4], [0; 4], [0; 4]);
        let commitment = Self::commit(version, l2_id, &prev, &out, &newest_anchor, &exit_cmt);
        Surface { version, l2_id, prev, out, newest_anchor, exit_cmt, commitment }
    }
}

/// One member of a bundle: its tag, PV vector and proof.
pub(crate) struct BundleMember<P> {
    pub tag: WTag,
    pub pvs: Vec<u32>,
    pub proof: P,
}

/// A wrapper as the verifier receives it.
pub(crate) struct Bundle<'a, P> {
    pub version: u32,
    pub w_pvs: Vec<u32>,
    pub w_proof: &'a Proof<LegacyNonHidingConfig>,
    pub members: Vec<BundleMember<P>>,
    /// The deposit-sum proof and its PVs (V9).
    pub dep_pvs: Vec<u32>,
    pub dep_proof: &'a Proof<Config>,
}

/// How member proofs are checked — the real one is [`TypedMembers`]. The
/// chain's `l2_id` comes from the predecessor surface, never the caller.
pub(crate) trait MemberVerifier<P> {
    fn verify(&self, m: &BundleMember<P>, l2_id: u64) -> Result<(), String>;
}

/// V2's real check: the typed L2 entries. (Its entries are `qlab_l2`'s,
/// proven and refused by that crate's own suite; the tests here drive the
/// orchestration through a stub, since an L2 member prove is 7–30 GiB.)
#[allow(dead_code)]
pub(crate) struct TypedMembers {
    pub fee_tier: u64,
}

impl MemberVerifier<Proof<Config>> for TypedMembers {
    fn verify(&self, m: &BundleMember<Proof<Config>>, l2_id: u64) -> Result<(), String> {
        let ok = match m.tag {
            WTag::S => qlab_l2::verify_s_u32(&m.pvs, &m.proof),
            WTag::P => qlab_l2::verify_p_u32(&m.pvs, &m.proof),
            WTag::R => qlab_l2::verify_r_u32(&m.pvs, &m.proof),
            WTag::C => return qlab_l2::claim::verify_claim_u32(&m.pvs, &m.proof, l2_id, self.fee_tier).map_err(|e| format!("{e:?}")),
        };
        ok.then_some(()).ok_or_else(|| "the proof does not verify".into())
    }
}

/// A member's declared PV widths (its AIR's `audit_pv_bits`).
pub(crate) fn member_bits(tag: WTag) -> Vec<u32> {
    match tag {
        WTag::S => qlab_air::l2::audit_pv_bits(),
        WTag::P => qlab_air::l2p::audit_pv_bits(),
        WTag::R => qlab_air::l2r::audit_pv_bits(),
        WTag::C => qlab_air::claim::audit_pv_bits(),
    }
}

/// Why a wrapper is refused, named by check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VError {
    /// V0: an unknown version, or a W PV not a 16-bit chunk / of the wrong count.
    Version,
    PvRange,
    /// V1: not exactly `k` members.
    Members,
    /// V2: member `i`'s PV words outside its AIR's widths (before reduction).
    MemberPv(usize),
    /// V2: member `i`'s proof.
    Member(usize, String),
    /// V3: W's proof.
    WProof,
    /// V4: SD over the members is not W's.
    Sd,
    /// V5: a threading value, named.
    Thread(&'static str),
    /// V6: `prev` is not the predecessor's commitment.
    Prev,
    /// V7: absorbed root `i` is not a genuine recent L1 root.
    Anchor(usize),
    /// V8: `E_cum > D_cum`.
    EAboveD,
    /// V9: the deposit-sum proof, named by check.
    Dep(DepCheck),
}

/// V9's checks, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DepCheck {
    /// A PV word not 16-bit, or the wrong count — before any conversion.
    PvRange,
    /// The proof does not verify.
    Proof,
    /// `n` is not the bundle's claim count.
    Count,
    /// `dig` is not the chain over the claims' `Cv` PVs in order.
    Digest,
    /// `D_batch` is not W's.
    DBatch,
}

fn digest_at(w: &[u32], off: usize) -> Digest {
    core::array::from_fn(|l| (0..4).map(|j| u64::from(w[off + 4 * l + j]) << (16 * j)).sum())
}
fn index_at(w: &[u32], off: usize) -> u64 {
    u64::from(w[off]) | (u64::from(w[off + 1]) << 16)
}
fn u64_at(w: &[u32], off: usize) -> u64 {
    (0..4).map(|j| u64::from(w[off + j]) << (16 * j)).sum()
}

/// W's in or out threading values from its PVs.
pub(crate) fn roots_at(w: &[u32], side: usize) -> WRoots {
    let o = side * PV_SIDE;
    WRoots {
        f3: Roots {
            n: digest_at(w, o + PV_N),
            n_next: index_at(w, o + PV_NN),
            c: digest_at(w, o + PV_C),
            c_next: index_at(w, o + PV_CN),
            r: digest_at(w, o + PV_R),
            sd: digest_at(w, o + PV_SD),
        },
        k: digest_at(w, o + PV_K),
        k_next: index_at(w, o + PV_KN),
        aa: digest_at(w, o + PV_AA),
        aa_next: index_at(w, o + PV_AAN),
        ch: digest_at(w, o + PV_CH),
        ch_next: index_at(w, o + PV_CHN),
        sup: digest_at(w, o + PV_SUP),
        d_cum: u64_at(w, o + PV_D),
        e_cum: u64_at(w, o + PV_E),
    }
}

/// **Verify one wrapper** against its predecessor's surface; on success,
/// its own surface.
pub(crate) fn verify_wrapper<P>(
    b: &Bundle<'_, P>,
    prev: &Surface,
    members: &impl MemberVerifier<P>,
    anchor_ok: &dyn Fn(&Digest) -> bool,
) -> Result<Surface, VError> {
    // V0 — F4b: W's AIR identity fixed by `version` inside the recursion.
    // The version is the chain's: a bundle cannot switch it (review R2).
    if b.version != prev.version {
        return Err(VError::Version);
    }
    let (k, outer) = version(b.version).ok_or(VError::Version)?;
    if b.w_pvs.len() != W_PV_LEN || b.w_pvs.iter().any(|x| *x >= 1 << 16) {
        return Err(VError::PvRange);
    }
    // V8 — stays public arithmetic on the surface (F5's L1 rule); checked
    // first among the surface checks, since it needs no proof.
    {
        let o = roots_at(&b.w_pvs, 1);
        if o.e_cum > o.d_cum {
            return Err(VError::EAboveD);
        }
    }
    // V1 — F4b: the recursion's per-slot member count.
    if b.members.len() != k {
        return Err(VError::Members);
    }
    // V2 — F4b: in-circuit member verification (C1/C2 class) + check_leaf_pvs.
    // The u32 widths first, before anything reduces a word mod p (review R1),
    // then the proof for the chain's l2_id (review R2).
    for (i, m) in b.members.iter().enumerate() {
        if !qlab_l2::pv_u32_in_range(&m.pvs, &member_bits(m.tag)) {
            return Err(VError::MemberPv(i));
        }
        members.verify(m, prev.l2_id).map_err(|e| VError::Member(i, e))?;
    }
    // V9 — F4b: the deposit proof verified in-circuit (V2's class) and `dig`
    // recomputed over the aggregated claims' Cv PVs (V4's place). The words
    // first (condition (p)), then the proof, then its three bindings.
    {
        let d = &b.dep_pvs;
        if d.len() != super::dep::DEP_PV_LEN || d.iter().any(|x| *x >= 1 << 16) {
            return Err(VError::Dep(DepCheck::PvRange));
        }
        if !verify_dep_u32(d, b.dep_proof) {
            return Err(VError::Dep(DepCheck::Proof));
        }
        let cvs = claim_cvs(b.members.iter().filter(|m| m.tag == WTag::C).map(|m| m.pvs.as_slice()));
        if d[DPV_N] as usize != cvs.len() {
            return Err(VError::Dep(DepCheck::Count));
        }
        if digest_at(d, DPV_DIG) != dep_chain(&cvs) {
            return Err(VError::Dep(DepCheck::Digest));
        }
        if u64_at(d, DPV_D) != u64_at(&b.w_pvs, PV_DB) {
            return Err(VError::Dep(DepCheck::DBatch));
        }
    }
    // V3 — F4b: the wrapper root proof.
    let w_vals: Vec<Val> = public_values(&b.w_pvs);
    verify(&make_legacy_config_with(&outer.cfg()), &WAir::new(k), b.w_proof, &w_vals).map_err(|_| VError::WProof)?;
    let (win, wout) = (roots_at(&b.w_pvs, 0), roots_at(&b.w_pvs, 1));
    // V4 — F4b: the batch side's SD, computed where members are aggregated.
    let sd = b.members.iter().fold(win.f3.sd, |h, m| {
        let tag = if m.tag == WTag::C { CLAIM_TAG } else { m.tag.byte() };
        sd_chain_byte(&h, tag, &m.pvs).1
    });
    if sd != wout.f3.sd {
        return Err(VError::Sd);
    }
    // V5 — stays verifier-side (reading B): threading-in = predecessor's out.
    let p = &prev.out;
    let pairs: [(&'static str, bool); 15] = [
        ("N", win.f3.n == p.f3.n),
        ("n_next", win.f3.n_next == p.f3.n_next),
        ("C", win.f3.c == p.f3.c),
        ("c_next", win.f3.c_next == p.f3.c_next),
        ("R", win.f3.r == p.f3.r),
        ("SD", win.f3.sd == p.f3.sd),
        ("K", win.k == p.k),
        ("k_next", win.k_next == p.k_next),
        ("AA", win.aa == p.aa),
        ("aa_next", win.aa_next == p.aa_next),
        ("CH", win.ch == p.ch),
        ("ch_next", win.ch_next == p.ch_next),
        ("supply", win.sup == p.sup),
        ("D_cum", win.d_cum == p.d_cum),
        ("E_cum", win.e_cum == p.e_cum),
    ];
    if let Some((name, _)) = pairs.iter().find(|(_, ok)| !ok) {
        return Err(VError::Thread(name));
    }
    // V6 — stays verifier-side (reading B): the chain link.
    let w_prev = digest_at(&b.w_pvs, PV_PREV);
    if w_prev != prev.commitment {
        return Err(VError::Prev);
    }
    // V7 — F5's L1 rule (stub): absorbed roots are genuine recent finalized roots.
    let absorbed: Vec<Digest> = (0..M_ABS).map(|i| digest_at(&b.w_pvs, PV_ABS + 16 * i)).collect();
    if let Some(i) = absorbed.iter().position(|a| !anchor_ok(a)) {
        return Err(VError::Anchor(i));
    }
    let newest = absorbed[M_ABS - 1];
    let exit_cmt = digest_at(&b.w_pvs, PV_EXC);
    Ok(Surface {
        version: b.version,
        l2_id: prev.l2_id,
        prev: w_prev,
        out: wout,
        newest_anchor: newest,
        exit_cmt,
        commitment: Surface::commit(b.version, prev.l2_id, &w_prev, &wout, &newest, &exit_cmt),
    })
}

#[cfg(test)]
mod tests {
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
        let two = |order: [usize; 2], deps: &[DepEntry]| -> Result<Surface, VError> {
            let (dep_pvs, dep_proof) = prove_dep(deps).unwrap();
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
            b.dep_pvs = dep_pvs;
            b.dep_proof = &dep_proof;
            run(&b)
        };
        assert_eq!(two([0, 1], &fx.deps).unwrap_err(), VError::WProof, "V9 holds for the two claims in order");
        assert_eq!(two([1, 0], &fx.deps).unwrap_err(), VError::Dep(DepCheck::Digest), "claims reordered against the Cv chain");
        assert_eq!(two([0, 1], &fx.deps[..1]).unwrap_err(), VError::Dep(DepCheck::Count), "the last Cv dropped");
    }

    /// The versions: 1 is K = 16 at b2; devnet versions carry their k.
    #[test]
    fn f4_versions() {
        assert_eq!(version(1).map(|v| v.0), Some(16));
        assert_eq!(version(0x8002).map(|v| v.0), Some(2));
        assert_eq!(version(2), None);
    }
}
