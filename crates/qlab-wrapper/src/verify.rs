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
use p3_uni_stark::{verify, Proof};
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
use qlab_consensus::{Config, Val};
use qlab_l2::public_values;

use crate::dep::{claim_cvs, dep_chain, verify_dep_u32, DPV_D, DPV_DIG, DPV_N};
use crate::hash::{WRoots, WTag, CLAIM_TAG, M_ABS};
use crate::wleaf::{
    WAir, PV_AA, PV_AAN, PV_ABS, PV_C, PV_CH, PV_CHN, PV_CN, PV_D, PV_DB, PV_E, PV_EXC, PV_K, PV_KN, PV_N, PV_NN, PV_PREV, PV_R, PV_SD, PV_SIDE, PV_SUP,
    W_PV_LEN,
};
use crate::config::Outer;
use crate::hash::{sd_chain_byte, Digest, Roots};

/// The wrapper statement versions this verifier knows: `(k, outer lane)`.
/// Version 1 is ruling Q1's K = 16 on the decided b2 lane; `0x8000 | k` are
/// devnet/test versions of smaller `k`; `0x8100 | k` are the F4-4 bench's
/// b4 cells — **measurement only, never a chain version**.
pub fn version(id: u32) -> Option<(usize, Outer)> {
    VERSIONS.iter().find(|(v, _, _)| *v == id).map(|(_, k, o)| (*k, *o))
}

/// The FRI config W is proven and verified under for `id`: version 1 is
/// [`crate::config::W_V1_CFG`] (b2/q91, lab #785 F5-2); every other version
/// is measurement only and keeps its lane's config (b2/q86 or b4/q43).
pub fn version_cfg(id: u32) -> Option<qlab_consensus::FriCfg> {
    let (_, outer) = version(id)?;
    Some(if id == 1 { crate::config::W_V1_CFG } else { outer.cfg() })
}

/// The version a `(k, lane)` bench cell runs under.
pub fn version_for(k: usize, outer: Outer) -> Option<u32> {
    VERSIONS.iter().find(|(_, kk, o)| *kk == k && *o == outer).map(|(v, _, _)| *v)
}

/// `(version, k, outer lane)`.
pub const VERSIONS: [(u32, usize, Outer); 8] = [
    // The chain version: b2 at q91 (`W_V1_CFG`, via `version_cfg`).
    (1, 16, Outer::B2),
    // Measurement only, q86, not the v1 lane (devnet/test versions of smaller k).
    (0x8001, 1, Outer::B2),
    (0x8002, 2, Outer::B2),
    (0x8004, 4, Outer::B2),
    (0x8008, 8, Outer::B2),
    // Measurement only, never a chain version (F4-4's b4 cells).
    (0x8104, 4, Outer::B4),
    (0x8108, 8, Outer::B4),
    (0x8110, 16, Outer::B4),
];
const _: () = {
    let mut i = 0;
    while i < VERSIONS.len() {
        assert!(VERSIONS[i].1 <= crate::wleaf::MAX_K);
        assert!(VERSIONS[i].1 <= crate::dep::DEP_CAP);
        i += 1;
    }
};

/// The surface commitment's tag in the MD chain (distinct from every slot tag).
pub const SURFACE_TAG: u8 = 0x10;
/// `state_root`'s tag.
pub const STATE_ROOT_TAG: u8 = 0x11;

/// Q9 (§5): `state_root = H(N ‖ C ‖ R ‖ CH)` — F3's MD chain under
/// [`STATE_ROOT_TAG`]; `K` (`cnf_root`), `AA` (`anchor_acc`) and the supply
/// root (`supply_cmt`) are separate surface fields, not inside it.
pub fn state_root(r: &WRoots) -> Digest {
    let mut w: Vec<u32> = Vec::new();
    for d in [&r.f3.n, &r.f3.c, &r.f3.r, &r.ch] {
        w.extend(crate::cmp::limbs(d));
    }
    sd_chain_byte(&[0; 4], STATE_ROOT_TAG, &w).1
}

/// What the verifier keeps of an accepted wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
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
    pub fn commit(version: u32, l2_id: u64, prev: &Digest, out: &WRoots, newest_anchor: &Digest, exit_cmt: &Digest) -> Digest {
        let mut w: Vec<u32> = vec![version];
        let d = |w: &mut Vec<u32>, x: &Digest| w.extend(crate::cmp::limbs(x));
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
    pub fn genesis(version: u32, l2_id: u64, out: WRoots) -> Self {
        let (prev, newest_anchor, exit_cmt) = ([0; 4], [0; 4], [0; 4]);
        let commitment = Self::commit(version, l2_id, &prev, &out, &newest_anchor, &exit_cmt);
        Surface { version, l2_id, prev, out, newest_anchor, exit_cmt, commitment }
    }
}

/// One member of a bundle: its tag, PV vector and proof.
pub struct BundleMember<P> {
    pub tag: WTag,
    pub pvs: Vec<u32>,
    pub proof: P,
}

/// A wrapper as the verifier receives it.
pub struct Bundle<'a, P> {
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
pub trait MemberVerifier<P> {
    fn verify(&self, m: &BundleMember<P>, l2_id: u64) -> Result<(), String>;
}

/// V2's real check: the typed L2 entries. (Its entries are `qlab_l2`'s,
/// proven and refused by that crate's own suite; the tests here drive the
/// orchestration through a stub, since an L2 member prove is 7–30 GiB.)
#[allow(dead_code)]
pub struct TypedMembers {
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
pub fn member_bits(tag: WTag) -> Vec<u32> {
    match tag {
        WTag::S => qlab_air::l2::audit_pv_bits(),
        WTag::P => qlab_air::l2p::audit_pv_bits(),
        WTag::R => qlab_air::l2r::audit_pv_bits(),
        WTag::C => qlab_air::claim::audit_pv_bits(),
    }
}

/// Why a wrapper is refused, named by check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VError {
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
pub enum DepCheck {
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

pub fn digest_at(w: &[u32], off: usize) -> Digest {
    core::array::from_fn(|l| (0..4).map(|j| u64::from(w[off + 4 * l + j]) << (16 * j)).sum())
}
fn index_at(w: &[u32], off: usize) -> u64 {
    u64::from(w[off]) | (u64::from(w[off + 1]) << 16)
}
fn u64_at(w: &[u32], off: usize) -> u64 {
    (0..4).map(|j| u64::from(w[off + j]) << (16 * j)).sum()
}

/// W's in or out threading values from its PVs.
pub fn roots_at(w: &[u32], side: usize) -> WRoots {
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
pub fn verify_wrapper<P>(
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
    let (k, _) = version(b.version).ok_or(VError::Version)?;
    let w_cfg = version_cfg(b.version).ok_or(VError::Version)?;
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
        if d.len() != crate::dep::DEP_PV_LEN || d.iter().any(|x| *x >= 1 << 16) {
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
    verify(&make_legacy_config_with(&w_cfg), &WAir::new(k), b.w_proof, &w_vals).map_err(|_| VError::WProof)?;
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
