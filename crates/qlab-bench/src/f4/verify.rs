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
//! | V0 | the version fixes W's `k` and outer config; W's PVs are 16-bit chunks | the wrapper's AIR identity is fixed by `version` inside the recursion |
//! | V1 | exactly `k` members | the recursion's per-slot member count |
//! | V2 | every member proof verifies through the typed L2 entries (`qlab_l2::verify_{s,p,r}`, `claim::verify_claim`: u32 PVs, range-checked) | in-circuit member verification (F2's C1/C2 class) with `check_leaf_pvs` |
//! | V3 | W's proof verifies under the version's AIR and config | the wrapper root proof |
//! | V4 | SD over the members' `(tag, PVs)`, in order, from `W.SD_in`, equals `W.SD_out` (F3's MD chain) | the batch side's SD, computed where member proofs are aggregated, equated to W's |
//! | V5 | W's threading-in equals the predecessor's out | stays verifier-side (reading B): a public-input equality |
//! | V6 | `W.prev` is the predecessor's surface commitment | stays verifier-side (reading B) |
//! | V7 | every absorbed root is a genuine recent finalized L1 root | F5's L1 rule; stubbed here as a caller predicate |
//!
//! Member proofs pass through the typed entries only, never a raw
//! field-element path (ruling condition (b): the L2 entries take `u32` PVs
//! via `public_values` and refuse any outside `audit_pv_bits`, lab #758).
#![cfg_attr(not(test), allow(dead_code))]
use p3_uni_stark::{verify, Proof};
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
use qlab_consensus::{Config, Val};
use qlab_l2::public_values;

use super::native::{WRoots, WTag, CLAIM_TAG, M_ABS};
use super::wleaf::{WAir, PV_AA, PV_AAN, PV_ABS, PV_C, PV_CN, PV_K, PV_KN, PV_N, PV_NN, PV_PREV, PV_R, PV_SD, PV_SIDE, W_PV_LEN};
use crate::f3::bench::Outer;
use crate::f3::native::{sd_chain_byte, Digest, Roots};

/// The wrapper statement versions this verifier knows: `(k, outer lane)`.
/// Version 1 is ruling Q1's K = 16 on the decided b2 lane; `0x8000 | k` are
/// devnet/test versions of smaller `k`.
pub(crate) fn version(id: u32) -> Option<(usize, Outer)> {
    match id {
        1 => Some((16, Outer::B2)),
        0x8001 | 0x8002 | 0x8004 | 0x8008 => Some(((id & 0xff) as usize, Outer::B2)),
        _ => None,
    }
}

/// The surface commitment's tag in the MD chain (distinct from every slot tag).
pub(crate) const SURFACE_TAG: u8 = 0x10;

/// What the verifier keeps of an accepted wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Surface {
    pub version: u32,
    pub l2_id: u64,
    pub prev: Digest,
    pub out: WRoots,
    /// The newest absorbed L1 root (§5's `anchor_acc` pairs it with AA's root).
    pub newest_anchor: Digest,
    pub commitment: Digest,
}

impl Surface {
    /// F4-1's surface commitment: F3's MD chain under [`SURFACE_TAG`] over the
    /// version, `l2_id`, `prev`, every threading value and the newest
    /// absorbed root. (Q9: `state_root = H(N ‖ C ‖ R ‖ CH)` and §5's field
    /// layout arrive with CH in F4-2; the commitment then covers them.)
    pub(crate) fn commit(version: u32, l2_id: u64, prev: &Digest, out: &WRoots, newest_anchor: &Digest) -> Digest {
        let mut w: Vec<u32> = vec![version, (l2_id & 0xffff) as u32, ((l2_id >> 16) & 0xffff) as u32, ((l2_id >> 32) & 0xffff) as u32, (l2_id >> 48) as u32];
        let d = |w: &mut Vec<u32>, x: &Digest| w.extend(crate::f3::cmp::limbs(x));
        let i = |w: &mut Vec<u32>, x: u64| w.extend([(x & 0xffff) as u32, (x >> 16) as u32]);
        d(&mut w, prev);
        d(&mut w, &out.f3.n);
        i(&mut w, out.f3.n_next);
        d(&mut w, &out.f3.c);
        i(&mut w, out.f3.c_next);
        d(&mut w, &out.f3.r);
        d(&mut w, &out.f3.sd);
        d(&mut w, &out.k);
        i(&mut w, out.k_next);
        d(&mut w, &out.aa);
        i(&mut w, out.aa_next);
        d(&mut w, newest_anchor);
        sd_chain_byte(&[0; 4], SURFACE_TAG, &w).1
    }

    /// A chain's origin: the state at genesis, pinned at the upgrade.
    pub(crate) fn genesis(version: u32, l2_id: u64, out: WRoots) -> Self {
        let (prev, newest_anchor) = ([0; 4], [0; 4]);
        let commitment = Self::commit(version, l2_id, &prev, &out, &newest_anchor);
        Surface { version, l2_id, prev, out, newest_anchor, commitment }
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
}

/// How member proofs are checked — the real one is [`TypedMembers`].
pub(crate) trait MemberVerifier<P> {
    fn verify(&self, m: &BundleMember<P>) -> Result<(), String>;
}

/// V2's real check: the typed L2 entries. (Its entries are `qlab_l2`'s,
/// proven and refused by that crate's own suite; the tests here drive the
/// orchestration through a stub, since an L2 member prove is 7–30 GiB.)
#[allow(dead_code)]
pub(crate) struct TypedMembers {
    pub l2_id: u64,
    pub fee_tier: u64,
}

impl MemberVerifier<Proof<Config>> for TypedMembers {
    fn verify(&self, m: &BundleMember<Proof<Config>>) -> Result<(), String> {
        let pvs = public_values(&m.pvs);
        let ok = match m.tag {
            WTag::S => qlab_l2::verify_s(&pvs, &m.proof),
            WTag::P => qlab_l2::verify_p(&pvs, &m.proof),
            WTag::R => qlab_l2::verify_r(&pvs, &m.proof),
            WTag::C => return qlab_l2::claim::verify_claim(&pvs, &m.proof, self.l2_id, self.fee_tier).map_err(|e| format!("{e:?}")),
        };
        ok.then_some(()).ok_or_else(|| "the proof does not verify".into())
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
}

fn digest_at(w: &[u32], off: usize) -> Digest {
    core::array::from_fn(|l| (0..4).map(|j| u64::from(w[off + 4 * l + j]) << (16 * j)).sum())
}
fn index_at(w: &[u32], off: usize) -> u64 {
    u64::from(w[off]) | (u64::from(w[off + 1]) << 16)
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
    let (k, outer) = version(b.version).ok_or(VError::Version)?;
    if b.w_pvs.len() != W_PV_LEN || b.w_pvs.iter().any(|x| *x >= 1 << 16) {
        return Err(VError::PvRange);
    }
    // V1 — F4b: the recursion's per-slot member count.
    if b.members.len() != k {
        return Err(VError::Members);
    }
    // V2 — F4b: in-circuit member verification (C1/C2 class) + check_leaf_pvs.
    for (i, m) in b.members.iter().enumerate() {
        members.verify(m).map_err(|e| VError::Member(i, e))?;
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
    let pairs: [(&'static str, bool); 10] = [
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
    Ok(Surface {
        version: b.version,
        l2_id: prev.l2_id,
        prev: w_prev,
        out: wout,
        newest_anchor: newest,
        commitment: Surface::commit(b.version, prev.l2_id, &w_prev, &wout, &newest),
    })
}

#[cfg(test)]
mod tests {
    //! One real two-slot W proof (b2), shared; the member proofs are stubs
    //! (their real check is `qlab_l2`'s own suite). Every native negative
    //! mutates the bundle or the predecessor and names the refusing check.
    use std::sync::OnceLock;

    use p3_uni_stark::prove;

    use super::super::native::{Member, WInputs};
    use super::super::neg::{honest, wfixture, SEED};
    use super::*;

    /// A stub member proof: the member's own PVs, which the stub verifier
    /// compares — so "a proof that fails" is a mismatched stub.
    struct Stub;
    impl MemberVerifier<Vec<u32>> for Stub {
        fn verify(&self, m: &BundleMember<Vec<u32>>) -> Result<(), String> {
            (m.proof == m.pvs).then_some(()).ok_or_else(|| "stub mismatch".into())
        }
    }

    struct Case {
        bundle_pvs: Vec<u32>,
        proof: Proof<LegacyNonHidingConfig>,
        members: Vec<Member>,
        prev: Surface,
    }

    const TEST_VERSION: u32 = 0x8002;

    /// The fixture `[S, C]` (a transaction and a claim, condition (a)'s
    /// boundary), proven once; its predecessor surface commits `inp.prev`.
    fn case() -> &'static Case {
        static C: OnceLock<Case> = OnceLock::new();
        C.get_or_init(|| {
            let mut fx = wfixture(&[WTag::S, WTag::C], SEED + 100);
            let pre = Surface::genesis(TEST_VERSION, 7, fx.rin);
            // Rebuild the leaf with `prev` = the predecessor's commitment.
            let mut st = fx.pre.clone();
            fx.inp = WInputs { prev: pre.commitment, ..fx.inp.clone() };
            let (rin, wit, rout) = st.apply(&fx.inp, &fx.members).unwrap();
            (fx.rin, fx.wit, fx.rout) = (rin, wit, rout);
            let (air, trace, pvs) = honest(&fx);
            let proof = prove(&make_legacy_config_with(&Outer::B2.cfg()), &air, trace, &pvs);
            let bundle_pvs = pvs.iter().map(|v| {
                use p3_field::PrimeField32;
                v.as_canonical_u32()
            }).collect();
            Case { bundle_pvs, proof, members: fx.members.clone(), prev: pre }
        })
    }

    fn bundle(c: &Case) -> Bundle<'_, Vec<u32>> {
        Bundle {
            version: TEST_VERSION,
            w_pvs: c.bundle_pvs.clone(),
            w_proof: &c.proof,
            members: c.members.iter().map(|m| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: m.pvs.clone() }).collect(),
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
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Members, "a version with another k");
        b.version = 0x8003;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::Version, "an unknown version");

        let mut b = bundle(c);
        b.w_pvs[PV_SIDE + PV_C] ^= 1;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::WProof, "V3: W's PVs moved");
        b.w_pvs[PV_SIDE + PV_C] = 1 << 16;
        assert_eq!(verify_wrapper(&b, &c.prev, &Stub, ANY).unwrap_err(), VError::PvRange, "V0: a 17-bit chunk");

        // V5: a predecessor whose out is not W's in.
        let mut other = c.prev.clone();
        other.out.k_next += 1;
        other.commitment = Surface::commit(other.version, other.l2_id, &other.prev, &other.out, &other.newest_anchor);
        assert_eq!(verify_wrapper(&bundle(c), &other, &Stub, ANY).unwrap_err(), VError::Thread("k_next"));

        // V6, the replayed-ρ case: a second wrapper built on the same `prev`
        // as an accepted one (so the same fee-note ρ) is checked against the
        // accepted one's surface — its `prev` is not that commitment.
        let accepted = verify_wrapper(&bundle(c), &c.prev, &Stub, ANY).unwrap();
        let mut ahead = accepted.clone();
        ahead.out = c.prev.out;
        assert_eq!(verify_wrapper(&bundle(c), &ahead, &Stub, ANY).unwrap_err(), VError::Prev, "a replayed prev");

        // V7 (F5's stub).
        let absorbed0 = digest_at(&c.bundle_pvs, PV_ABS);
        let not_first: &dyn Fn(&Digest) -> bool = &move |a| *a != absorbed0;
        assert_eq!(verify_wrapper(&bundle(c), &c.prev, &Stub, not_first).unwrap_err(), VError::Anchor(0));
    }

    /// The versions: 1 is K = 16 at b2; devnet versions carry their k.
    #[test]
    fn f4_versions() {
        assert_eq!(version(1).map(|v| v.0), Some(16));
        assert_eq!(version(0x8002).map(|v| v.0), Some(2));
        assert_eq!(version(2), None);
    }
}
