//! Lab #775 F4 — **W, the wrapper leaf AIR**: F3's state leaf
//! (`crate::f3::leaf`), extended with the claim slot, the L1-anchor
//! accumulator, CH, the supply tree, the exit list and the sequencer fee
//! note. It proves [`super::native::check_wrapper_leaf`].
//!
//! **The program.** A prologue, `k` slots, an epilogue, then `PAD`:
//!
//! ```text
//!   prologue (127 perms):
//!     absorb   H(a0,a1), H(a2,a3), their parent; one pair path over AA's
//!              levels 2..31 (60): the four roots as one aligned subtree,
//!              its old side the empty subtree zeros[2] (aa_next ≡ 0 mod 4)
//!     history  C_in appended to CH (64)
//!   slot ×k (661 perms):
//!     F3's slot    SD 5 | inserts 3 × 131 | appends 2 × 64 | registry 33
//!     vPublic ×2   old leaf, new leaf, supply pair path (34 each; P only)
//!     exits ×2     the exit chain's steps (P redeems on asset 0)
//!     anchor       32: a transaction's anchor opened in CH, a claim's in AA
//!   epilogue (67 perms): ρ(prev), rseed(prev), the fee note, its append to C
//! ```
//!
//! **The claim slot** (tag `C`, SD word 0 = `0x04`): insert 0 is its `cnf`,
//! committed to `K` (not `N`); append 0 is its `cm2`; its anchor opens in
//! `AA` (`A ≠ 0`); its fee chunks add into the fee accumulator. Inserts 1–2,
//! append 1, SD block 4, the registry and the `vPublic` segments are off for
//! a claim.
//!
//! **The fee note** is appended in every wrapper (value 0 with no claims):
//! `cm = H(value ‖ 0 ‖ rkm_seq ‖ ρ ‖ rseed)` with `value` the accumulator
//! normalized to four 16-bit limbs (carries ≤ 5 bits: at most 31 claims per
//! leaf), `ρ`/`rseed` the two domain-tagged perms over the `prev` PV.
//!
//! **D/E**: `D_out = D_in + D_batch` (FeeRho row) and `E_out = E_in + Σ
//! exits` (FeeRseed row), u64 limbs with 6-bit carries and no carry out.
//! `D_batch` is a W public value; the deposit-sum proof ([`super::dep`])
//! binds it to the claims' `Cv`s at the verifier (V9).
//!
//! Degree 3 throughout, by the same device as F3: every flag a data
//! constraint needs is a materialized column.
#![cfg_attr(not(test), allow(dead_code))]
use std::ops::Range;

use p3_air::Air;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{generate_trace_rows, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::dense::RowMajorMatrix;
use qlab_consensus::Val;

use super::native::{fee_seed_state, Member, SlotWitness, WInputs, WRoots, WTag, WWitness, CLAIM_TAG, M_ABS};
use crate::f3::cmp::{self, limbs, LT_WIDTH};
use crate::f3::leaf::{inv_or_zero, mux, nf_leaf_state, node_state, out4, pv_digest};
use crate::f3::native::{sd_chain_byte, Digest, EMPTY};
pub(crate) use qlab_wrapper::wleaf::*;

/// W's public values.
pub(crate) fn w_pvs(rin: &WRoots, rout: &WRoots, inp: &WInputs, fee: u64, exit_cmt: &Digest) -> Vec<Val> {
    let mut v = Vec::with_capacity(W_PV_LEN);
    let d = |v: &mut Vec<Val>, x: &Digest| v.extend(limbs(x).iter().map(|l| Val::from_u32(*l)));
    let i = |v: &mut Vec<Val>, x: u64| v.extend([Val::from_u32((x & 0xffff) as u32), Val::from_u32((x >> 16) as u32)]);
    let u = |v: &mut Vec<Val>, x: u64| v.extend((0..4).map(|j| Val::from_u32(((x >> (16 * j)) & 0xffff) as u32)));
    for r in [rin, rout] {
        d(&mut v, &r.f3.n);
        i(&mut v, r.f3.n_next);
        d(&mut v, &r.f3.c);
        i(&mut v, r.f3.c_next);
        d(&mut v, &r.f3.r);
        d(&mut v, &r.f3.sd);
        d(&mut v, &r.k);
        i(&mut v, r.k_next);
        d(&mut v, &r.aa);
        i(&mut v, r.aa_next);
        d(&mut v, &r.ch);
        i(&mut v, r.ch_next);
        d(&mut v, &r.sup);
        u(&mut v, r.d_cum);
        u(&mut v, r.e_cum);
    }
    d(&mut v, &inp.prev);
    d(&mut v, &inp.rkm_seq);
    for a in &inp.absorbed {
        d(&mut v, a);
    }
    u(&mut v, fee);
    u(&mut v, inp.d_batch);
    d(&mut v, exit_cmt);
    debug_assert_eq!(v.len(), W_PV_LEN);
    v
}

#[derive(Clone)]
pub(crate) struct PermPlan {
    pub pre: [u64; 25],
    pub cols: Vec<Val>,
}

impl PermPlan {
    pub(crate) fn get(&self, col: usize) -> Val {
        self.cols[col - PLAN_BASE]
    }
    pub(crate) fn set(&mut self, col: usize, v: Val) {
        self.cols[col - PLAN_BASE] = v;
    }
}

#[derive(Clone)]
pub(crate) struct Plan {
    pub perms: Vec<PermPlan>,
    pub pad: PermPlan,
}

#[derive(Clone)]
struct Regs {
    n: Digest,
    nn: u64,
    c: Digest,
    cn: u64,
    r: Digest,
    sd: Digest,
    k: Digest,
    kn: u64,
    aa: Digest,
    aan: u64,
    nf: [Digest; INSERTS],
    cm: [Digest; APPENDS],
    rt: Digest,
    nrt: Digest,
    asset: u64,
    anc: Digest,
    hi: Digest,
    na: Digest,
    nb: Digest,
    sib: Digest,
    bit: bool,
    acc: Val,
    pw: Val,
    rcnt: u64,
    tag: WTag,
    left: i64,
    fe: [u64; 4],
    rho: Digest,
    rsd: Digest,
    fcb: [u32; 3],
    ch: Digest,
    chn: u64,
    sup: Digest,
    vs: [u32; 2],
    vm: [u64; 2],
    va: [u32; 2],
    oldv: u64,
    scb: [u32; 3],
    ea: [u64; 4],
    exc: Digest,
    ecb: [u32; 3],
    d_in: u64,
    e_in: u64,
    d_batch: u64,
}

fn put_digest(cols: &mut [Val], at: usize, d: &Digest) {
    for (j, l) in limbs(d).iter().enumerate() {
        cols[at - PLAN_BASE + j] = Val::from_u32(*l);
    }
}

/// One slot's witness view, uniform over transactions and claims.
struct SlotView<'a> {
    member: &'a Member,
    inserts: Vec<crate::f3::native::InsertWitness>,
    appends: Vec<crate::f3::native::AppendWitness>,
    write: Option<crate::f3::native::RegistryWrite>,
    anchor: Option<qlab_air::narrow::MerkleWitness>,
    vp: [super::native::VpWitness; 2],
}

fn slot_view<'a>(m: &'a Member, w: &'a SlotWitness, ex: &'a super::native::SlotExtra) -> SlotView<'a> {
    match w {
        SlotWitness::Tx(t) => {
            SlotView { member: m, inserts: t.inserts.clone(), appends: t.appends.clone(), write: t.write, anchor: Some(ex.anchor_path), vp: ex.vp }
        }
        SlotWitness::Claim(c) => {
            SlotView { member: m, inserts: vec![c.insert], appends: vec![c.append], write: None, anchor: Some(c.anchor_path), vp: ex.vp }
        }
    }
}

/// A `vPublic` row's new outstanding, as the witness implies (wrapping: a
/// malicious witness still renders; the AIR refuses it).
fn vp_new(old: u64, s: u32, m: u64, va: u32) -> u64 {
    if va == 0 {
        old
    } else if s == 0 {
        old.wrapping_add(m)
    } else {
        old.wrapping_sub(m)
    }
}

fn limb(x: u64, j: usize) -> u64 {
    (x >> (16 * j)) & 0xffff
}

/// Build W's plan from a witness, without validating it.
pub(crate) fn build_plan(rin: &WRoots, inp: &WInputs, members: &[Member], w: &WWitness) -> Plan {
    let k = members.len();
    assert!(k >= 1 && w.slots.len() == k);
    let prog = program();
    let mut g = Regs {
        n: rin.f3.n,
        nn: rin.f3.n_next,
        c: rin.f3.c,
        cn: rin.f3.c_next,
        r: rin.f3.r,
        sd: rin.f3.sd,
        k: rin.k,
        kn: rin.k_next,
        aa: rin.aa,
        aan: rin.aa_next,
        nf: [EMPTY; INSERTS],
        cm: [EMPTY; APPENDS],
        rt: EMPTY,
        nrt: EMPTY,
        asset: 0,
        anc: EMPTY,
        hi: EMPTY,
        na: EMPTY,
        nb: EMPTY,
        sib: EMPTY,
        bit: false,
        acc: Val::ZERO,
        pw: Val::ONE,
        rcnt: 0,
        tag: members[0].tag,
        left: k as i64 - 1,
        fe: [0; 4],
        rho: EMPTY,
        rsd: EMPTY,
        fcb: [0; 3],
        ch: rin.ch,
        chn: rin.ch_next,
        sup: rin.sup,
        vs: [0; 2],
        vm: [0; 2],
        va: [0; 2],
        oldv: 0,
        scb: [0; 3],
        ea: [0; 4],
        exc: EMPTY,
        ecb: [0; 3],
        d_in: rin.d_cum,
        e_in: rin.e_cum,
        d_batch: inp.d_batch,
    };
    let mut perms: Vec<PermPlan> = Vec::new();
    let views: Vec<SlotView> = members.iter().zip(&w.slots).zip(&w.extra).map(|((m, s), e)| slot_view(m, s, e)).collect();
    let run = |s: Seg, g: &mut Regs, view: Option<&SlotView>, blocks: &[[u64; 25]], perms: &mut Vec<PermPlan>| {
        for i in 0..s.len() {
            let side = if s.is_pair_bulk() { i % 2 } else { 0 };
            let (level, path_a) = pair_level(s, i);
            if let Some(lvl) = level {
                if path_a {
                    let (sib, bit) = path_at(s, view, w, lvl);
                    g.sib = sib;
                    g.bit = bit;
                }
            }
            match s {
                Seg::SupOld(k) => g.oldv = view.map_or(0, |v| v.vp[k].old_out),
                Seg::SupNew(k) => {
                    // The addition a + mm = r's carries (mint: old + m = new;
                    // redeem: new + m = old; asset 0: m counts as 0).
                    let new = vp_new(g.oldv, g.vs[k], g.vm[k], g.va[k]);
                    let a = if g.vs[k] == 1 { new } else { g.oldv };
                    let mm = if g.va[k] == 0 { 0 } else { g.vm[k] };
                    let mut c = 0u64;
                    for j in 0..3 {
                        c = (limb(a, j) + limb(mm, j) + c) >> 16;
                        g.scb[j] = c as u32;
                    }
                }
                Seg::FeeRho | Seg::FeeRseed => {
                    let (x, y): (Vec<u64>, Vec<u64>) = if s == Seg::FeeRho {
                        ((0..4).map(|j| limb(g.d_in, j)).collect(), (0..4).map(|j| limb(g.d_batch, j)).collect())
                    } else {
                        ((0..4).map(|j| limb(g.e_in, j)).collect(), g.ea.to_vec())
                    };
                    let mut c = 0u64;
                    for j in 0..3 {
                        c = (x[j] + y[j] + c) >> 16;
                        g.ecb[j] = c as u32;
                    }
                }
                _ => {}
            }
            if let Seg::FeeNote = s {
                // Normalize the accumulator into the value limbs; the carries.
                let mut c = 0u64;
                for j in 0..3 {
                    let t = g.fe[j] + c;
                    c = t >> 16;
                    g.fcb[j] = c as u32;
                }
            }
            let pre = perm_input(s, i, g, view, blocks, perms, inp);
            if let Seg::LeafOld(_) = s {
                g.hi = pre[4..8].try_into().expect("four lanes");
            }
            let rem = s.len() - 1 - i;
            perms.push(PermPlan { pre, cols: snapshot(s, rem, side, g) });
            let out = out4(&pre);
            step(s, side, out, g, &pre, view);
        }
    };
    // Slot 0's surface registers hold from the first row (they change only
    // at a slot boundary), so they are set before the prologue.
    set_surface(&mut g, &members[0]);
    for s in &prog[..SLOT_BASE] {
        run(*s, &mut g, None, &[], &mut perms);
    }
    for view in &views {
        let m = view.member;
        set_surface(&mut g, m);
        let pvs = &m.pvs;
        let (blocks, _) = sd_chain_byte(&g.sd, m.tag.byte(), pvs);
        for s in &prog[SLOT_BASE..EPI_BASE] {
            run(*s, &mut g, Some(view), &blocks, &mut perms);
        }
    }
    for s in &prog[EPI_BASE..] {
        run(*s, &mut g, None, &[], &mut perms);
    }
    let pad = PermPlan { pre: [0; 25], cols: snapshot(Seg::Pad, 0, 0, &g) };
    Plan { perms, pad }
}

/// A slot's surface registers and tag, from its member's PVs (unvalidated).
fn set_surface(g: &mut Regs, m: &Member) {
    use qlab_air::{claim, l2, l2p, l2r};
    {
        g.tag = m.tag;
        let pvs = &m.pvs;
        g.nf = [EMPTY; INSERTS];
        g.cm = [EMPTY; APPENDS];
        g.rt = EMPTY;
        g.nrt = EMPTY;
        g.asset = 0;
        g.anc = pv_digest(pvs, 0);
        g.vs = [0; 2];
        g.vm = [0; 2];
        g.va = [0; 2];
        if m.tag == WTag::P {
            for k in 0..2 {
                let (sg, amt, vpa) = super::native::vp_row(pvs, k);
                (g.vs[k], g.vm[k], g.va[k]) = (sg, amt, vpa);
            }
        }
        match m.tag {
            WTag::R => {
                g.nf[0] = pv_digest(pvs, l2r::PV_NF);
                g.cm = [pv_digest(pvs, l2r::PV_CM), pv_digest(pvs, l2r::PV_CM_SEED)];
                g.rt = pv_digest(pvs, l2r::PV_OLD_ROOT);
                g.nrt = pv_digest(pvs, l2r::PV_NEW_ROOT);
                g.asset = u64::from(pvs.get(l2r::PV_ASSET).copied().unwrap_or(0) & 0xffff);
            }
            WTag::C => {
                g.nf[0] = pv_digest(pvs, claim::PV_CNF);
                g.cm[0] = pv_digest(pvs, claim::PV_CM2);
                g.rt = g.r;
            }
            t => {
                let nf3 = if t == WTag::S { l2::PV_NF3 } else { l2p::PV_NF3 };
                g.nf = [pv_digest(pvs, l2::PV_NF1), pv_digest(pvs, l2::PV_NF2), pv_digest(pvs, nf3)];
                g.cm = [pv_digest(pvs, l2::PV_CM1), pv_digest(pvs, l2::PV_CM2)];
                g.rt = pv_digest(pvs, l2::PV_REGROOT);
            }
        }
    }
}

fn pair_level(s: Seg, i: usize) -> (Option<usize>, bool) {
    match s {
        Seg::Pair(PathId::Abs, Part::Bulk) => (Some(ABS_LEVELS + i / 2), i.is_multiple_of(2)),
        Seg::Pair(_, Part::Bulk) => (Some(i / 2), i.is_multiple_of(2)),
        Seg::Pair(_, Part::L30) => (Some(30 + i / 2), i.is_multiple_of(2)),
        Seg::Pair(p, Part::LastA) => (Some(p.depth() - 1), true),
        Seg::Pair(p, Part::LastB) => (Some(p.depth() - 1), false),
        Seg::Anch(APart::Low) => (Some(i), true),
        Seg::Anch(APart::L30) => (Some(30), true),
        Seg::Anch(APart::Last) => (Some(31), true),
        _ => (None, false),
    }
}

fn path_at(s: Seg, view: Option<&SlotView>, w: &WWitness, lvl: usize) -> (Digest, bool) {
    let get = |p: &qlab_air::narrow::MerkleWitness| (p.siblings[lvl], p.path_bits[lvl]);
    let r = match s {
        Seg::Pair(PathId::Mid(i), _) => view.and_then(|v| v.inserts.get(i)).map(|x| get(&x.low_path)),
        Seg::Pair(PathId::New(i), _) => view.and_then(|v| v.inserts.get(i)).map(|x| get(&x.new_path)),
        Seg::Pair(PathId::C(j), _) => view.and_then(|v| v.appends.get(j)).map(|x| get(&x.path)),
        Seg::Pair(PathId::R, _) => view.and_then(|v| v.write.as_ref()).map(|x| (x.path.siblings[lvl], x.path.path_bits[lvl])),
        // Levels ≥ 2 of the first root's path are the subtree's.
        Seg::Pair(PathId::Abs, _) => Some(get(&w.absorbs[0].path)),
        Seg::Pair(PathId::Hist, _) => Some(get(&w.hist.path)),
        Seg::Pair(PathId::Sup(k), _) => view.map(|v| (v.vp[k].path.siblings[lvl], v.vp[k].path.path_bits[lvl])),
        Seg::Pair(PathId::Fee, _) => Some(get(&w.fee.path)),
        Seg::Anch(_) => view.and_then(|v| v.anchor.as_ref()).map(get),
        _ => None,
    };
    r.unwrap_or((EMPTY, false))
}

fn perm_input(s: Seg, i: usize, g: &Regs, view: Option<&SlotView>, blocks: &[[u64; 25]], perms: &[PermPlan], inp: &WInputs) -> [u64; 25] {
    let on = s.active(g.tag);
    let ins = |i: usize| view.and_then(|v| v.inserts.get(i)).filter(|_| on);
    match s {
        Seg::AbsNode(j) => {
            let a = &inp.absorbed;
            match j {
                0 => node_state(&a[0], &a[1]),
                1 => node_state(&a[2], &a[3]),
                _ => node_state(&g.nb, &g.na),
            }
        }
        Seg::Sd(b) => {
            if on {
                blocks.get(b).copied().unwrap_or([0; 25])
            } else {
                [0; 25]
            }
        }
        Seg::LeafOld(i) => ins(i).map_or(nf_leaf_state(&EMPTY, &EMPTY), |x| nf_leaf_state(&x.low.0, &x.low.1)),
        Seg::LeafMid(i) => {
            let lo: Digest = perms.last().expect("LEAF_OLD precedes").pre[..4].try_into().expect("four lanes");
            nf_leaf_state(&lo, &ins(i).map_or(EMPTY, |x| x.key))
        }
        Seg::LeafNew(i) => nf_leaf_state(&ins(i).map_or(EMPTY, |x| x.key), &g.hi),
        Seg::Pair(_, _) => {
            let (_, a) = pair_level(s, i);
            let x = if a { &g.na } else { &g.nb };
            let (l, r) = mux(g.bit, x, &g.sib);
            node_state(&l, &r)
        }
        Seg::Anch(_) => {
            let (l, r) = mux(g.bit, &g.na, &g.sib);
            node_state(&l, &r)
        }
        Seg::RegLeaf => match (view.and_then(|v| v.write.as_ref()), g.tag) {
            (Some(rw), WTag::R) => rw.leaf.state(),
            _ => [0; 25],
        },
        Seg::SupOld(k) if on => super::native::supply_leaf_state(u64::from(g.va[k]), g.oldv),
        Seg::SupNew(k) if on => super::native::supply_leaf_state(u64::from(g.va[k]), vp_new(g.oldv, g.vs[k], g.vm[k], g.va[k])),
        Seg::Exit(k) if on && xf(g, k) => super::native::exit_state(&g.exc, &view.map_or(EMPTY, |v| v.vp[k].exit_rkm), g.vm[k]),
        Seg::SupOld(_) | Seg::SupNew(_) | Seg::Exit(_) => [0; 25],
        Seg::FeeRho => fee_seed_state(&inp.prev, 1),
        Seg::FeeRseed => fee_seed_state(&inp.prev, 2),
        Seg::FeeNote => {
            let mut st = [0u64; 25];
            st[0] = fee_value(g);
            st[1] = 0;
            st[2..6].copy_from_slice(&inp.rkm_seq);
            st[6..10].copy_from_slice(&g.rho);
            st[10..14].copy_from_slice(&g.rsd);
            st[14] = 1;
            st[16] = 1 << 63;
            st
        }
        Seg::Pad => [0; 25],
    }
}

/// Row `k` is an exit: a P slot's `vPublic` redeem on asset 0.
fn xf(g: &Regs, k: usize) -> bool {
    g.tag == WTag::P && g.va[k] == 0 && g.vs[k] == 1
}

/// The accumulator as a u64 (the normalized value; wraps past 2^64 — the AIR refuses that).
fn fee_value(g: &Regs) -> u64 {
    (0..4).fold(0u128, |a, j| a + (u128::from(g.fe[j]) << (16 * j))) as u64
}

fn snapshot(s: Seg, rem: usize, side: usize, g: &Regs) -> Vec<Val> {
    let mut cols = vec![Val::ZERO; PLAN_WIDTH];
    let put = |cols: &mut Vec<Val>, col: usize, v: Val| cols[col - PLAN_BASE] = v;
    put(&mut cols, SEG_OFF + s.idx(), Val::ONE);
    let rv = Val::from_u32(rem as u32);
    put(&mut cols, REM, rv);
    put(&mut cols, Z, Val::from_bool(rem == 0));
    put(&mut cols, ZINV, inv_or_zero(rv));
    let lv = if g.left >= 0 { Val::from_u32(g.left as u32) } else { -Val::from_u32((-g.left) as u32) };
    put(&mut cols, LEFT, lv);
    put(&mut cols, ZL, Val::from_bool(g.left == 0));
    put(&mut cols, ZLINV, inv_or_zero(lv));
    put(&mut cols, SIDE, Val::from_u32(side as u32));
    let t = TAGS.iter().position(|x| *x == g.tag).expect("a tag");
    put(&mut cols, TAG_OFF + t, Val::ONE);
    put_digest(&mut cols, N_OFF, &g.n);
    put(&mut cols, NN, Val::from_u32(g.nn as u32));
    put_digest(&mut cols, C_OFF, &g.c);
    put(&mut cols, CN, Val::from_u32(g.cn as u32));
    put_digest(&mut cols, R_OFF, &g.r);
    put_digest(&mut cols, SD_OFF, &g.sd);
    put_digest(&mut cols, K_OFF, &g.k);
    put(&mut cols, KN, Val::from_u32(g.kn as u32));
    put_digest(&mut cols, AA_OFF, &g.aa);
    put(&mut cols, AAN, Val::from_u32(g.aan as u32));
    for i in 0..INSERTS {
        put_digest(&mut cols, NF_OFF + 16 * i, &g.nf[i]);
    }
    for j in 0..APPENDS {
        put_digest(&mut cols, CM_OFF + 16 * j, &g.cm[j]);
    }
    put_digest(&mut cols, RT_OFF, &g.rt);
    put_digest(&mut cols, NRT_OFF, &g.nrt);
    let av = Val::from_u32(g.asset as u32);
    put(&mut cols, ASSET, av);
    put(&mut cols, AINV, inv_or_zero(av));
    put_digest(&mut cols, ANC_OFF, &g.anc);
    let asum: u32 = limbs(&g.anc).iter().sum();
    put(&mut cols, ANINV, inv_or_zero(Val::from_u32(asum)));
    put_digest(&mut cols, HI_OFF, &g.hi);
    put_digest(&mut cols, NA_OFF, &g.na);
    put_digest(&mut cols, NB_OFF, &g.nb);
    put_digest(&mut cols, SIB_OFF, &g.sib);
    put(&mut cols, BIT, Val::from_bool(g.bit));
    put(&mut cols, ACC, g.acc);
    put(&mut cols, PW, g.pw);
    put(&mut cols, BP, if g.bit { g.pw } else { Val::ZERO });
    put(&mut cols, RCNT, Val::from_u32(g.rcnt as u32));
    for j in 0..4 {
        put(&mut cols, FE_OFF + j, Val::from_u32(g.fe[j] as u32));
    }
    put_digest(&mut cols, RHO_OFF, &g.rho);
    put_digest(&mut cols, RSD_OFF, &g.rsd);
    if s == Seg::FeeNote {
        for j in 0..3 {
            for b in 0..5 {
                put(&mut cols, FCB_OFF + 5 * j + b, Val::from_u32((g.fcb[j] >> b) & 1));
            }
        }
    }
    put_digest(&mut cols, CH_OFF, &g.ch);
    put(&mut cols, CHN, Val::from_u32(g.chn as u32));
    put_digest(&mut cols, SUP_OFF, &g.sup);
    for k in 0..2 {
        put(&mut cols, VS_OFF + k, Val::from_u32(g.vs[k]));
        for j in 0..4 {
            put(&mut cols, VM_OFF + 4 * k + j, Val::from_u32(limb(g.vm[k], j) as u32));
        }
        let va = Val::from_u32(g.va[k]);
        put(&mut cols, VA_OFF + k, va);
        put(&mut cols, ZV_OFF + k, Val::from_bool(g.va[k] == 0));
        put(&mut cols, ZVINV_OFF + k, inv_or_zero(va));
        put(&mut cols, XF_OFF + k, Val::from_bool(xf(g, k)));
        put(&mut cols, KX_OFF + k, Val::from_bool(s == Seg::Exit(k) && xf(g, k)));
        put(&mut cols, KSN_OFF + k, Val::from_bool(s == Seg::SupNew(k) && g.tag == WTag::P));
        put(&mut cols, KSU_OFF + k, Val::from_bool(s == Seg::Pair(PathId::Sup(k), Part::LastB) && g.tag == WTag::P));
        put(&mut cols, MZ_OFF + k, Val::from_bool(g.va[k] == 0 && g.vs[k] == 0));
    }
    for j in 0..4 {
        put(&mut cols, OLDV_OFF + j, Val::from_u32(limb(g.oldv, j) as u32));
        put(&mut cols, EA_OFF + j, Val::from_u32(g.ea[j] as u32));
    }
    if matches!(s, Seg::SupNew(_)) {
        for j in 0..3 {
            put(&mut cols, SCB_OFF + j, Val::from_u32(g.scb[j]));
        }
    }
    if matches!(s, Seg::FeeRho | Seg::FeeRseed) {
        for j in 0..3 {
            for b in 0..6 {
                put(&mut cols, ECB_OFF + 6 * j + b, Val::from_u32((g.ecb[j] >> b) & 1));
            }
        }
    }
    put_digest(&mut cols, EXC_OFF, &g.exc);
    put(&mut cols, KCH, Val::from_bool(g.tag != WTag::C && s == Seg::Anch(APart::Last)));
    let on = s.active(g.tag);
    let tx = matches!(g.tag, WTag::S | WTag::P | WTag::R);
    let cl = g.tag == WTag::C;
    put(&mut cols, ON, Val::from_bool(on));
    put(&mut cols, KPA, Val::from_bool(s.is_pair_bulk() && side == 0));
    put(&mut cols, KPB, Val::from_bool(s.is_pair_bulk() && side == 1));
    put(&mut cols, KCMP, Val::from_bool(on && matches!(s, Seg::LeafMid(_) | Seg::LeafNew(_))));
    put(&mut cols, KNC, Val::from_bool(on && tx && matches!(s, Seg::Pair(PathId::Mid(_) | PathId::New(_), Part::LastB))));
    put(&mut cols, KNI, Val::from_bool(on && tx && matches!(s, Seg::Pair(PathId::New(_), Part::LastB))));
    put(&mut cols, KKC, Val::from_bool(cl && matches!(s, Seg::Pair(PathId::Mid(0) | PathId::New(0), Part::LastB))));
    put(&mut cols, KKI, Val::from_bool(cl && s == Seg::Pair(PathId::New(0), Part::LastB)));
    let kcc = s == Seg::Pair(PathId::C(0), Part::LastB) || (s == Seg::Pair(PathId::C(1), Part::LastB) && on) || s == Seg::Pair(PathId::Fee, Part::LastB);
    put(&mut cols, KCC, Val::from_bool(kcc));
    put(&mut cols, KR, Val::from_bool(g.tag == WTag::R && s == Seg::Pair(PathId::R, Part::LastB)));
    put(&mut cols, KAN, Val::from_bool(cl && s == Seg::Anch(APart::Last)));
    put(&mut cols, KFE, Val::from_bool(cl && s == Seg::Sd(fee_pos(0).0)));
    put(&mut cols, W, Val::from_bool(rem == 0 && s.idx() == SLOT_LAST));
    let sdc = matches!(s, Seg::Sd(b) if b + 1 < SD_BLOCKS && Seg::Sd(b + 1).active(g.tag));
    put(&mut cols, SDC, Val::from_bool(sdc));
    put(&mut cols, SDF, Val::from_bool(matches!(s, Seg::Sd(b) if sd_final(b, g.tag))));
    cols
}

/// The perm's last-row transition.
fn step(s: Seg, side: usize, out: Digest, g: &mut Regs, pre: &[u64; 25], view: Option<&SlotView>) {
    let _ = view;
    let on = s.active(g.tag);
    let tx = matches!(g.tag, WTag::S | WTag::P | WTag::R);
    let to_c0 = Seg::Pair(PathId::New(INSERTS - 1), Part::LastB);
    let to_c1 = Seg::Pair(PathId::C(0), Part::LastB);
    let reset = |g: &mut Regs| {
        g.acc = Val::ZERO;
        g.pw = Val::ONE;
    };
    match s {
        Seg::Sd(b) => {
            if sd_final(b, g.tag) {
                g.sd = out;
            }
            if g.tag == WTag::C && b == fee_pos(0).0 {
                for j in 0..4 {
                    let (_, l, m) = fee_pos(j);
                    g.fe[j] += (pre[l] >> (16 * m)) & 0xffff;
                }
            }
        }
        Seg::LeafOld(_) => g.na = out,
        Seg::LeafMid(_) => {
            g.nb = out;
            reset(g);
        }
        Seg::LeafNew(_) => {
            g.na = EMPTY;
            g.nb = out;
            reset(g);
        }
        Seg::Anch(_) => g.na = out,
        Seg::AbsNode(0) => g.nb = out,
        Seg::AbsNode(1) => g.na = out,
        Seg::AbsNode(_) => {
            // The subtree's root on the B side; the A side opens the empty
            // subtree the four slots were.
            g.nb = out;
            g.na = abs_old_side();
        }
        Seg::Pair(p, part) => {
            let a = match part {
                Part::Bulk | Part::L30 => side == 0,
                Part::LastA => true,
                Part::LastB => false,
            };
            let to_abs = p == PathId::Abs && part == Part::LastB;
            if a {
                g.na = out;
            } else if s != to_c0 && s != to_c1 && !to_abs {
                g.nb = out;
            }
            if matches!(part, Part::Bulk | Part::L30) && !a {
                if g.bit {
                    g.acc += g.pw;
                }
                g.pw = g.pw.double();
            }
            if part == Part::LastB {
                match p {
                    PathId::Mid(_) if on && tx => g.n = out,
                    PathId::New(_) if on && tx => {
                        g.n = out;
                        g.nn += 1;
                    }
                    PathId::Mid(0) if g.tag == WTag::C => g.k = out,
                    PathId::New(0) if g.tag == WTag::C => {
                        g.k = out;
                        g.kn += 1;
                    }
                    PathId::C(j) if j == 0 || on => {
                        g.c = out;
                        g.cn += 1;
                    }
                    PathId::Fee => {
                        g.c = out;
                        g.cn += 1;
                    }
                    PathId::Abs => {
                        g.aa = out;
                        g.aan += M_ABS as u64;
                    }
                    PathId::Hist => {
                        g.ch = out;
                        g.chn += 1;
                    }
                    PathId::Sup(_) if g.tag == WTag::P => g.sup = out,
                    PathId::R if g.tag == WTag::R => g.r = out,
                    _ => {}
                }
                if s == to_c0 {
                    g.na = EMPTY;
                    g.nb = g.cm[0];
                    reset(g);
                }
                if s == to_c1 {
                    g.na = EMPTY;
                    g.nb = g.cm[1];
                    reset(g);
                }
                if p == PathId::Abs {
                    // Then C_in into CH.
                    g.na = EMPTY;
                    g.nb = g.c;
                    reset(g);
                }
            }
        }
        Seg::RegLeaf => {
            g.nb = out;
            g.na = EMPTY;
            reset(g);
        }
        Seg::SupOld(_) => g.na = out,
        Seg::SupNew(_) => {
            g.nb = out;
            reset(g);
        }
        Seg::Exit(k) => {
            if xf(g, k) {
                g.exc = out;
                for j in 0..4 {
                    g.ea[j] += limb(g.vm[k], j);
                }
            }
            if k == 1 {
                // The anchor path starts from the slot's anchor.
                g.na = g.anc;
            }
        }
        Seg::FeeRho => g.rho = out,
        Seg::FeeRseed => g.rsd = out,
        Seg::FeeNote => {
            g.na = EMPTY;
            g.nb = out;
            reset(g);
        }
        Seg::Pad => {}
    }
    if s == Seg::Anch(APart::Last) {
        g.rcnt += u64::from(g.tag == WTag::R);
        g.left -= 1;
    }
}

/// Render the plan.
pub(crate) fn render(plan: &Plan) -> RowMajorMatrix<Val> {
    let inputs: Vec<[u64; 25]> = plan.perms.iter().map(|p| p.pre).collect();
    let keccak = generate_trace_rows::<Val>(inputs, 0);
    let height = keccak.values.len() / NUM_KECCAK_COLS;
    let mut values = Val::zero_vec(height * W_WIDTH);
    for (r, row) in values.chunks_exact_mut(W_WIDTH).enumerate() {
        row[..NUM_KECCAK_COLS].copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
        let p = plan.perms.get(r / NUM_ROUNDS).unwrap_or(&plan.pad);
        row[PLAN_BASE..].copy_from_slice(&p.cols);
        if r % NUM_ROUNDS == 0 && p.get(KCMP) == Val::ONE {
            let (x, y): (Digest, Digest) = (p.pre[..4].try_into().expect("four lanes"), p.pre[4..8].try_into().expect("four lanes"));
            cmp::fill(&mut row[CMP_OFF..CMP_OFF + LT_WIDTH], &cmp::lt_raw(&limbs(&x), &limbs(&y)));
        }
    }
    RowMajorMatrix::new(values, W_WIDTH)
}

/// The fee note's value the witness implies (Σ fee over claims).
pub(crate) fn fee_of(members: &[Member]) -> u64 {
    members
        .iter()
        .filter(|m| m.tag == WTag::C)
        .map(|m| (0..4).map(|j| u64::from(m.pvs[qlab_air::claim::PV_FEE + j] & 0xffff) << (16 * j)).sum::<u64>())
        .fold(0u64, |a, f| a.wrapping_add(f))
}

const _: () = assert!(CLAIM_TAG == 0x04);

pub(crate) fn failures_at(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize) -> Vec<usize> {
    use p3_air::DebugConstraintBuilder;
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::ViewPair;
    use p3_matrix::Matrix;
    let height = trace.height();
    let next = (row + 1) % height;
    let local = trace.row_slice(row).expect("a row");
    let nxt = trace.row_slice(next).expect("a row");
    let main = ViewPair::new(RowMajorMatrixView::new_row(&*local), RowMajorMatrixView::new_row(&*nxt));
    let prep = ViewPair::new(RowMajorMatrixView::new(&[], 0), RowMajorMatrixView::new(&[], 0));
    let mut builder = DebugConstraintBuilder::new(
        row,
        main,
        prep,
        pvs,
        Val::from_bool(row == 0),
        Val::from_bool(row == height - 1),
        Val::from_bool(row != height - 1),
        &[],
    );
    air.eval(&mut builder);
    builder.into_failures().into_iter().map(|f| f.constraint).collect()
}

pub(crate) fn phases_at(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val], row: usize, ranges: &[Range<usize>]) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = failures_at(air, trace, pvs, row).into_iter().map(|c| phase_of(ranges, c)).collect();
    v.dedup();
    v
}

pub(crate) fn first_violation(air: &WAir, trace: &RowMajorMatrix<Val>, pvs: &[Val]) -> Option<(usize, Vec<&'static str>)> {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use p3_matrix::Matrix;
    use p3_maybe_rayon::prelude::*;
    const CHUNK: usize = 1024;
    let height = trace.height();
    let best = AtomicUsize::new(usize::MAX);
    (0..height.div_ceil(CHUNK)).into_par_iter().for_each(|ch| {
        for row in ch * CHUNK..((ch + 1) * CHUNK).min(height) {
            if row >= best.load(Ordering::Relaxed) {
                return;
            }
            if !failures_at(air, trace, pvs, row).is_empty() {
                best.fetch_min(row, Ordering::Relaxed);
                return;
            }
        }
    });
    let row = best.into_inner();
    (row != usize::MAX).then(|| (row, phases_at(air, trace, pvs, row, &phase_ranges(air))))
}
