//! Lab #775 F4-1 — W's fixtures and its negatives, shared by the tests and
//! `qlab-bench f4neg`. The claim is F3's house standard: a malicious witness
//! or plan, generated as an honest one would be ([`build_plan`] never
//! validates), is scanned in full, and its **lowest** violated row is the
//! named binding row, refused there by the named constraint group.
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use qlab_air::l2::RegistryLeaf;
use qlab_air::narrow::MerkleWitness;
use qlab_cbserver::tree::CommitmentTree;
use qlab_consensus::Val;
use qlab_devnet::annulet::L2ShapeTag;

use super::native::*;
use super::wleaf::*;
use crate::f3::native::{synth_tx, synth_write, AppendWitness, Digest, IndexedTree, InsertWitness, Rng, EMPTY};

/// A wrapper leaf's inputs and the state before it.
#[derive(Clone)]
pub(crate) struct WFixture {
    pub rin: WRoots,
    pub inp: WInputs,
    pub members: Vec<Member>,
    pub wit: WWitness,
    pub rout: WRoots,
    pub exit_cmt: Digest,
    pub pre: WState,
    /// The prefill's claim (its `cnf` is in `K`).
    pub pre_claim: Member,
}

/// Every fixture claim pays this fee (a claim's fee is the chain's tariff):
/// `0x1_FFFF` — ≥ 2^16, and two of them carry out of limb 0 (condition (i)).
pub(crate) const CLAIM_FEE: u64 = 0x1_ffff;
/// The prefill's deposit total, and each fixture wrapper's.
pub(crate) const PRE_D: u64 = 1_000_000;
/// The prefill mints this much of asset [`ASSET`].
pub(crate) const PRE_MINT: u64 = 1000;
pub(crate) const ASSET: u32 = 5;
/// A P member's default `vPublic` rows: a mint and a redeem of [`ASSET`].
pub(crate) const P_ROWS: [(u32, u64, u32); 2] = [(0, 250, ASSET), (1, 100, ASSET)];

/// A wrapper over `kinds`, on a state that already holds one prefill wrapper
/// (an S and a P transaction and a claim: every tree past its genesis,
/// [`PRE_MINT`] of [`ASSET`] outstanding, `D_cum` = [`PRE_D`]). Transactions
/// anchor at this wrapper's `C_in` (in `CH` after its prologue); claims at
/// its absorbed roots; P members carry `p_rows`.
pub(crate) fn wfixture_rows(kinds: &[WTag], seed: u64, p_rows: [(u32, u64, u32); 2]) -> WFixture {
    let mut rng = Rng(seed);
    let mut s = WState::genesis(&[RegistryLeaf::cloaked(0)]);
    let pre_inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()), d_batch: PRE_D };
    let (rr, c0) = (s.l2.r.root(), s.l2.c.root());
    let pre_claim = synth_claim(&mut rng, &pre_inp.absorbed[0], CLAIM_FEE);
    let pre_members = [
        tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c0, NO_VP),
        tx_member(&synth_tx(&mut rng, L2ShapeTag::P, &rr), &c0, [(0, PRE_MINT, ASSET), (0, 0, 0)]),
        pre_claim.clone(),
    ];
    s.apply(&pre_inp, &pre_members).expect("the prefill wrapper");
    let pre = s.clone();
    let inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()), d_batch: PRE_D };
    let c_in = s.l2.c.root();
    let mut work = s.l2.clone();
    let mut members = Vec::new();
    let mut asset = 7;
    for (i, k) in kinds.iter().enumerate() {
        let m = match k {
            WTag::C => synth_claim(&mut rng, &inp.absorbed[i % M_ABS], CLAIM_FEE),
            WTag::R => {
                asset += 1;
                let t = synth_write(&mut rng, &work, RegistryLeaf::cloaked(asset - 1));
                work.apply_tx(&t).expect("a valid write");
                tx_member(&t, &c_in, NO_VP)
            }
            t => {
                let tx = synth_tx(&mut rng, t.shape().unwrap(), &work.r.root());
                work.apply_tx(&tx).expect("a valid transaction");
                tx_member(&tx, &c_in, p_rows)
            }
        };
        members.push(m);
    }
    let (rin, wit, rout) = s.apply(&inp, &members).expect("the fixture wrapper");
    let exit_cmt = check_wrapper_leaf(&rin, &inp, &members, &wit).expect("its check").1;
    WFixture { rin, inp, members, wit, rout, exit_cmt, pre, pre_claim }
}

/// [`wfixture_rows`] with the default P rows.
pub(crate) fn wfixture(kinds: &[WTag], seed: u64) -> WFixture {
    wfixture_rows(kinds, seed, P_ROWS)
}

/// The fixture's public values.
pub(crate) fn fx_pvs(fx: &WFixture) -> Vec<Val> {
    w_pvs(&fx.rin, &fx.rout, &fx.inp, fee_of(&fx.members), &fx.exit_cmt)
}

/// The honest trace and PVs.
pub(crate) fn honest(fx: &WFixture) -> (WAir, RowMajorMatrix<Val>, Vec<Val>) {
    let plan = build_plan(&fx.rin, &fx.inp, &fx.members, &fx.wit);
    (WAir::new(fx.members.len()), render(&plan), fx_pvs(fx))
}

#[derive(Debug)]
pub(crate) struct Neg {
    pub name: &'static str,
    pub row: usize,
    pub phase: &'static str,
    pub got: Option<(usize, Vec<&'static str>)>,
}

impl Neg {
    pub(crate) fn holds(&self) -> bool {
        matches!(&self.got, Some((r, ph)) if *r == self.row && ph.contains(&self.phase))
    }
}

pub(crate) fn s0(slot: usize, seg: Seg, i: usize) -> usize {
    row_of(perm_at(slot, seg, i), 0)
}
pub(crate) fn s23(slot: usize, seg: Seg, i: usize) -> usize {
    row_of(perm_at(slot, seg, i), 23)
}

fn judge(
    name: &'static str,
    fx: &WFixture,
    tamper: impl FnOnce(&mut Plan, &mut Vec<Val>),
    retouch: impl FnOnce(&mut RowMajorMatrix<Val>),
    row: usize,
    phase: &'static str,
) -> Neg {
    let mut plan = build_plan(&fx.rin, &fx.inp, &fx.members, &fx.wit);
    let mut pvs = fx_pvs(fx);
    tamper(&mut plan, &mut pvs);
    let mut trace = render(&plan);
    retouch(&mut trace);
    let got = first_violation(&WAir::new(fx.members.len()), &trace, &pvs);
    Neg { name, row, phase, got }
}

fn witness(name: &'static str, fx: WFixture, row: usize, phase: &'static str) -> Neg {
    judge(name, &fx, |_, _| {}, |_| {}, row, phase)
}

fn forge_insert(tree: &IndexedTree, key: &Digest, low_index: u64, low: Option<(Digest, Digest)>) -> InsertWitness {
    let low = low.unwrap_or(tree.leaves()[low_index as usize]);
    let low_path = tree.path(low_index);
    let mut t = tree.clone();
    t.put(low_index, (low.0, *key));
    let new_index = t.next_index();
    InsertWitness { key: *key, low_index, low, low_path, new_index, new_path: t.path(new_index) }
}

fn leaf_ending_at(tree: &IndexedTree, key: &Digest) -> u64 {
    tree.leaves().iter().position(|l| l.1 == *key).expect("a leaf ending at the key") as u64
}

fn empty_slot_path(tree: &CommitmentTree, pos: u64) -> MerkleWitness {
    let mut t = tree.clone();
    while t.len() <= pos {
        t.append(EMPTY);
    }
    t.auth_path(pos, pos + 1)
}

fn set_digest_pvs(pvs: &mut [u32], off: usize, d: &Digest) {
    pvs[off..off + 16].copy_from_slice(&qlab_air::narrow::pv_chunks(d));
}

fn claim_mut(fx: &mut WFixture, slot: usize) -> &mut ClaimWitness {
    match &mut fx.wit.slots[slot] {
        SlotWitness::Claim(c) => c,
        SlotWitness::Tx(_) => panic!("slot {slot} is not a claim"),
    }
}

fn tx_mut(fx: &mut WFixture, slot: usize) -> &mut crate::f3::native::TxWitness {
    match &mut fx.wit.slots[slot] {
        SlotWitness::Tx(t) => t,
        SlotWitness::Claim(_) => panic!("slot {slot} is not a transaction"),
    }
}

fn each_perm(plan: &mut Plan, from: usize, f: impl Fn(&mut PermPlan)) {
    for p in plan.perms.iter_mut().skip(from) {
        f(p);
    }
    f(&mut plan.pad);
}

const C: WTag = WTag::C;
const P: WTag = WTag::P;
const S: WTag = WTag::S;
pub(crate) const SEED: u64 = 0x775_f4b0;

pub(crate) type Case = (&'static str, fn() -> Neg);

fn ml(i: usize) -> Seg {
    Seg::Pair(PathId::Mid(i), Part::LastB)
}
fn cl(j: usize) -> Seg {
    Seg::Pair(PathId::C(j), Part::LastB)
}

/// Every negative: the claim slot, the anchor accumulator, the fee note,
/// then F3's transaction-slot negatives ported onto W.
pub(crate) fn cases() -> Vec<Case> {
    vec![
        ("w1 claim double-spend across wrappers", neg_double_claim),
        ("w2 claim cnf twice in one wrapper", neg_claim_dup),
        ("w3 claim anchor not in AA", neg_anchor_forged),
        ("w4 claim anchor zero", neg_anchor_zero),
        ("w5 claim cm2 at a skipped index", neg_cm2_skip),
        ("w6 fee note value != sum of fees", neg_fee_value),
        ("w7 fee note nonzero with no claims", neg_fee_no_claims),
        ("w8 a claim fee not accumulated", neg_fee_acc),
        ("w9 absorbed root at a skipped index", neg_absorb_skip),
        ("w10 K threading gap", neg_k_gap),
        ("w11 a claim declared a transaction", neg_claim_as_tx),
        ("w12 activate a claim's gated-off insert", neg_claim_insert1),
        ("w13 claim cnf into N, not K", neg_cnf_into_n),
        ("w14 fee note rho not H(prev)", neg_fee_rho),
        ("f3/1 tx double insert (N)", neg_tx_double_insert),
        ("f3/3b tx forged low leaf", neg_tx_forged_leaf),
        ("f3/5 tx append index skipped", neg_tx_append_skip),
        ("f3/8 tx key not the surface's", neg_tx_key),
        ("f3/9 tx shape-tag swap", neg_tx_tag_swap),
        ("f3/10 tx N threading gap", neg_tx_n_gap),
        ("f3/cap path bit 30", neg_tx_bit30),
        ("f3/3 free hi at NEW", neg_tx_free_hi),
        ("f3/idle comparator cell non-boolean", neg_idle_cmp),
        ("pv: K in", neg_pv_k_in),
        ("pv: fee", neg_pv_fee),
        ("j asset id >= 2^16", neg_asset_id_wide),
        ("k tx anchor = this wrapper's C_out", neg_anchor_c_out),
        ("k tx anchor opened against AA", neg_tx_anchor_in_aa),
        ("k claim anchor opened against CH", neg_claim_anchor_in_ch),
        ("k KCH/KAN swapped on a tx", neg_kch_kan_swap),
        ("l vPublic mint on asset 0", neg_asset0_mint),
        ("l supply overflow", neg_supply_overflow),
        ("l supply underflow", neg_supply_underflow),
        ("l E overflow", neg_e_overflow),
        ("m exit v not the row's amount", neg_exit_v),
        ("m exit_cmt PV not the chain", neg_exit_cmt_pv),
        ("i wrong fee carry", neg_wrong_carry),
        ("R6 KAN off for a claim", neg_kan_off),
        ("R6 KFE off for a claim", neg_kfe_off),
        ("R6 registry on for a claim", neg_registry_on_claim),
    ]
}

fn anch_last() -> Seg {
    Seg::Anch(APart::Last)
}

/// (j): a `vPublic` asset id ≥ 2^16 — its word's high limb is nonzero, so
/// the capture refuses it where SD absorbs it.
fn neg_asset_id_wide() -> Neg {
    let mut fx = wfixture(&[P], SEED + 30);
    fx.members[0].pvs[qlab_air::l2p::PV_VP1 + 5] = (1 << 16) | ASSET;
    let b = (2 + qlab_air::l2p::PV_VP1 + 5) / 26;
    witness("j asset id >= 2^16", fx, s0(0, Seg::Sd(b), 0), "sd_capture")
}

/// (k): a transaction anchored at this wrapper's own `C_out`, which is not
/// in CH until the next wrapper's prologue.
fn neg_anchor_c_out() -> Neg {
    let mut fx = wfixture(&[S], SEED + 31);
    let c_out = fx.rout.f3.c;
    set_digest_pvs(&mut fx.members[0].pvs, 0, &c_out);
    witness("k tx anchor = this wrapper's C_out", fx, s23(0, anch_last(), 0), "anchor")
}

/// (k): a transaction anchored at an absorbed L1 root, opened in AA.
fn neg_tx_anchor_in_aa() -> Neg {
    let mut fx = wfixture(&[S], SEED + 32);
    let a = fx.inp.absorbed[0];
    set_digest_pvs(&mut fx.members[0].pvs, 0, &a);
    let mut aa = fx.pre.aa.clone();
    let idx = aa.len();
    for r in &fx.inp.absorbed {
        aa.append(*r);
    }
    fx.wit.extra[0].anchor_index = idx;
    fx.wit.extra[0].anchor_path = aa.auth_path(idx, aa.len());
    witness("k tx anchor opened against AA", fx, s23(0, anch_last(), 0), "anchor")
}

/// (k): a claim anchored at `C_in`, opened in CH.
fn neg_claim_anchor_in_ch() -> Neg {
    let mut fx = wfixture(&[C], SEED + 33);
    let c_in = fx.rin.f3.c;
    set_digest_pvs(&mut fx.members[0].pvs, qlab_air::claim::PV_A, &c_in);
    let mut ch = fx.pre.ch.clone();
    let idx = ch.append(c_in);
    let cw = claim_mut(&mut fx, 0);
    cw.anchor_index = idx;
    cw.anchor_path = ch.auth_path(idx, ch.len());
    witness("k claim anchor opened against CH", fx, s23(0, anch_last(), 0), "anchor")
}

/// (k): the transaction's CH check swapped for the claim's AA check.
fn neg_kch_kan_swap() -> Neg {
    let fx = wfixture(&[S], SEED + 34);
    judge(
        "k KCH/KAN swapped on a tx",
        &fx,
        |plan, _| {
            let p = &mut plan.perms[perm_at(0, anch_last(), 0)];
            p.set(KCH, Val::ZERO);
            p.set(KAN, Val::ONE);
        },
        |_| {},
        s0(0, anch_last(), 0),
        "flags",
    )
}

/// (l): a `vPublic` mint on asset 0.
fn neg_asset0_mint() -> Neg {
    let mut fx = wfixture(&[P], SEED + 35);
    let base = qlab_air::l2p::PV_VP1;
    (fx.members[0].pvs[base], fx.members[0].pvs[base + 1], fx.members[0].pvs[base + 5]) = (0, 7, 0);
    witness("l vPublic mint on asset 0", fx, s0(0, Seg::SupNew(0), 0), "supply")
}

fn set_row(m: &mut Member, k: usize, sgn: u32, amt: u64, vpa: u32) {
    let base = qlab_air::l2p::PV_VP1 + 6 * k;
    m.pvs[base] = sgn;
    for j in 0..4 {
        m.pvs[base + 1 + j] = ((amt >> (16 * j)) & 0xffff) as u32;
    }
    m.pvs[base + 5] = vpa;
}

/// (l): a mint past 2^64 − 1 outstanding.
fn neg_supply_overflow() -> Neg {
    let mut fx = wfixture(&[P], SEED + 36);
    set_row(&mut fx.members[0], 0, 0, u64::MAX, ASSET);
    witness("l supply overflow", fx, s0(0, Seg::SupNew(0), 0), "supply")
}

/// (l): a redeem of more than is outstanding.
fn neg_supply_underflow() -> Neg {
    let mut fx = wfixture(&[P], SEED + 37);
    set_row(&mut fx.members[0], 1, 1, 1 << 40, ASSET);
    witness("l supply underflow", fx, s0(0, Seg::SupNew(1), 0), "supply")
}

/// (l): two asset-0 redeems whose sum passes 2^64: E_out has no u64 form.
fn neg_e_overflow() -> Neg {
    let mut fx = wfixture_rows(&[P], SEED + 38, [(1, 40, 0), (0, 0, 0)]);
    set_row(&mut fx.members[0], 0, 1, u64::MAX, 0);
    set_row(&mut fx.members[0], 1, 1, 5, 0);
    witness("l E overflow", fx, s0(0, Seg::FeeRseed, 0), "de")
}

/// (m): an exit step hashing an amount that is not the row's.
fn neg_exit_v() -> Neg {
    let fx = wfixture_rows(&[P], SEED + 39, [(1, 40, 0), (0, 0, 0)]);
    judge(
        "m exit v not the row's amount",
        &fx,
        |plan, _| plan.perms[perm_at(0, Seg::Exit(0), 0)].pre[8] += 1,
        |_| {},
        s0(0, Seg::Exit(0), 0),
        "exits",
    )
}

/// (m): an `exit_cmt` PV that is not the chain over the synthetic list.
fn neg_exit_cmt_pv() -> Neg {
    let fx = wfixture_rows(&[P], SEED + 40, [(1, 40, 0), (0, 0, 0)]);
    judge("m exit_cmt PV not the chain", &fx, |_, pvs| pvs[PV_EXC] += Val::ONE, |_| {}, w_height(1) - 1, "last")
}

/// (i): two claims whose fees carry out of limb 0; the carry bit withheld.
fn neg_wrong_carry() -> Neg {
    let fx = wfixture(&[C, C], SEED + 41);
    judge(
        "i wrong fee carry",
        &fx,
        |plan, _| {
            let p = &mut plan.perms[perm_at(1, Seg::FeeNote, 0)];
            let b = p.get(FCB_OFF);
            p.set(FCB_OFF, Val::ONE - b);
        },
        |_| {},
        s0(1, Seg::FeeNote, 0),
        "fee_note",
    )
}

/// R6: a claim's AA check switched off.
fn neg_kan_off() -> Neg {
    let fx = wfixture(&[C], SEED + 42);
    judge("R6 KAN off for a claim", &fx, |plan, _| plan.perms[perm_at(0, anch_last(), 0)].set(KAN, Val::ZERO), |_| {}, s0(0, anch_last(), 0), "flags")
}

/// R6: a claim's fee accumulation switched off.
fn neg_kfe_off() -> Neg {
    let fx = wfixture(&[C], SEED + 43);
    judge("R6 KFE off for a claim", &fx, |plan, _| plan.perms[perm_at(0, Seg::Sd(3), 0)].set(KFE, Val::ZERO), |_| {}, s0(0, Seg::Sd(3), 0), "flags")
}

/// R6: the registry segment switched on for a claim.
fn neg_registry_on_claim() -> Neg {
    let fx = wfixture(&[C], SEED + 44);
    judge("R6 registry on for a claim", &fx, |plan, _| plan.perms[perm_at(0, Seg::RegLeaf, 0)].set(ON, Val::ONE), |_| {}, s0(0, Seg::RegLeaf, 0), "flags")
}

/// w1: a claim whose `cnf` is already in K (the prefill's): the prover opens
/// the genuine leaf `(lo, cnf)` and must then hash `(cnf, cnf)` — refused at
/// the strict compare on LEAF_NEW.
fn neg_double_claim() -> Neg {
    let mut fx = wfixture(&[C], SEED);
    let cnf = pv_digest_of(&fx.pre_claim.pvs, qlab_air::claim::PV_CNF);
    set_digest_pvs(&mut fx.members[0].pvs, qlab_air::claim::PV_CNF, &cnf);
    let k = fx.pre.k.clone();
    claim_mut(&mut fx, 0).insert = forge_insert(&k, &cnf, leaf_ending_at(&k, &cnf), None);
    witness("w1 claim double-spend across wrappers", fx, s0(0, Seg::LeafNew(0), 0), "cmp")
}

/// w2: the same `cnf` in both claims of one wrapper.
fn neg_claim_dup() -> Neg {
    let mut fx = wfixture(&[C, C], SEED + 1);
    let cnf = pv_digest_of(&fx.members[0].pvs, qlab_air::claim::PV_CNF);
    set_digest_pvs(&mut fx.members[1].pvs, qlab_air::claim::PV_CNF, &cnf);
    let mut k = fx.pre.k.clone();
    k.insert(&cnf).unwrap();
    claim_mut(&mut fx, 1).insert = forge_insert(&k, &cnf, leaf_ending_at(&k, &cnf), None);
    witness("w2 claim cnf twice in one wrapper", fx, s0(1, Seg::LeafNew(0), 0), "cmp")
}

/// w3: a claim anchored at a root never absorbed, opened with a genuine path.
fn neg_anchor_forged() -> Neg {
    let mut fx = wfixture(&[C], SEED + 2);
    let stray = Rng(99).digest();
    set_digest_pvs(&mut fx.members[0].pvs, qlab_air::claim::PV_A, &stray);
    witness("w3 claim anchor not in AA", fx, s23(0, Seg::Anch(APart::Last), 0), "anchor")
}

/// w4: a zero anchor opened at an empty slot of AA — its fold IS AA's root;
/// only `A ≠ 0` refuses it.
fn neg_anchor_zero() -> Neg {
    let mut fx = wfixture(&[C], SEED + 3);
    set_digest_pvs(&mut fx.members[0].pvs, qlab_air::claim::PV_A, &EMPTY);
    let mut aa = fx.pre.aa.clone();
    for r in &fx.inp.absorbed {
        aa.append(*r);
    }
    let pos = aa.len();
    let cw = claim_mut(&mut fx, 0);
    cw.anchor_index = pos;
    cw.anchor_path = empty_slot_path(&aa, pos);
    witness("w4 claim anchor zero", fx, s0(0, Seg::Anch(APart::Last), 0), "anchor")
}

/// w5: a claim's `cm2` appended into the empty slot after the running index.
fn neg_cm2_skip() -> Neg {
    let mut fx = wfixture(&[C], SEED + 4);
    let c = fx.rin.f3.c_next;
    let tree = fx.pre.l2.c.clone();
    claim_mut(&mut fx, 0).append = AppendWitness { index: c + 1, path: empty_slot_path(&tree, c + 1) };
    witness("w5 claim cm2 at a skipped index", fx, s0(0, cl(0), 0), "root_c")
}

/// w6: the fee note's value one more than Σ fee (PV kept honest).
fn neg_fee_value() -> Neg {
    let fx = wfixture(&[C], SEED + 5);
    let k = fx.members.len() - 1;
    judge("w6 fee note value != sum of fees", &fx, move |plan, _| plan.perms[perm_at(k, Seg::FeeNote, 0)].pre[0] += 1, |_| {}, s0(k, Seg::FeeNote, 0), "fee_note")
}

/// w7: a wrapper with no claims whose fee note (and fee PV) says 1.
fn neg_fee_no_claims() -> Neg {
    let fx = wfixture(&[S], SEED + 6);
    judge(
        "w7 fee note nonzero with no claims",
        &fx,
        |plan, pvs| {
            plan.perms[perm_at(0, Seg::FeeNote, 0)].pre[0] = 1;
            pvs[PV_FEE] = Val::ONE;
        },
        |_| {},
        s0(0, Seg::FeeNote, 0),
        "fee_note",
    )
}

/// w8: a claim's fee chunks left out of the accumulator.
fn neg_fee_acc() -> Neg {
    let fx = wfixture(&[C], SEED + 7);
    let from = perm_at(0, Seg::Sd(3), 0) + 1;
    judge(
        "w8 a claim fee not accumulated",
        &fx,
        move |plan, _| {
            each_perm(plan, from, |p| {
                for j in 0..4 {
                    p.set(FE_OFF + j, Val::ZERO);
                }
            })
        },
        |_| {},
        s23(0, Seg::Sd(3), 0),
        "fee_acc",
    )
}

/// w9: absorbed root 1 appended into the slot after the running index.
fn neg_absorb_skip() -> Neg {
    let mut fx = wfixture(&[S], SEED + 8);
    let n = fx.rin.aa_next;
    let mut aa = fx.pre.aa.clone();
    aa.append(fx.inp.absorbed[0]);
    fx.wit.absorbs[1] = AppendWitness { index: n + 2, path: empty_slot_path(&aa, n + 2) };
    witness("w9 absorbed root at a skipped index", fx, s0(0, Seg::Pair(PathId::Abs(1), Part::LastB), 0), "root_aa")
}

/// w10: slot 2 starts from a K that slot 1 did not end on.
fn neg_k_gap() -> Neg {
    let fx = wfixture(&[C, C], SEED + 9);
    let old = fx.rin.k;
    let from = perm_at(1, Seg::Sd(0), 0);
    judge(
        "w10 K threading gap",
        &fx,
        move |plan, _| {
            each_perm(plan, from, |p| {
                for (j, l) in crate::f3::cmp::limbs(&old).iter().enumerate() {
                    p.set(K_OFF + j, Val::from_u32(*l));
                }
            })
        },
        |_| {},
        s23(0, Seg::Anch(APart::Last), 0),
        "root_k",
    )
}

/// w11: a claim's PV vector declared a shape-S transaction.
fn neg_claim_as_tx() -> Neg {
    let mut fx = wfixture(&[C], SEED + 10);
    fx.members[0].tag = S;
    witness("w11 a claim declared a transaction", fx, s0(0, Seg::Sd(0), 0), "sd")
}

/// w12: insert 1 switched on in a claim slot.
fn neg_claim_insert1() -> Neg {
    let fx = wfixture(&[C], SEED + 11);
    judge(
        "w12 activate a claim's gated-off insert",
        &fx,
        |plan, _| plan.perms[perm_at(0, Seg::LeafOld(1), 0)].set(ON, Val::ONE),
        |_| {},
        s0(0, Seg::LeafOld(1), 0),
        "flags",
    )
}

/// w13: a claim's cnf committed to N instead of K (the commit flag moved).
fn neg_cnf_into_n() -> Neg {
    let fx = wfixture(&[C], SEED + 12);
    judge(
        "w13 claim cnf into N, not K",
        &fx,
        |plan, _| {
            let p = &mut plan.perms[perm_at(0, ml(0), 0)];
            p.set(KNC, Val::ONE);
            p.set(KKC, Val::ZERO);
        },
        |_| {},
        s0(0, ml(0), 0),
        "flags",
    )
}

/// w14: the fee note's ρ not `H(prev)` (a replayed ρ from another `prev`).
fn neg_fee_rho() -> Neg {
    let fx = wfixture(&[C], SEED + 13);
    let k = fx.members.len() - 1;
    judge(
        "w14 fee note rho not H(prev)",
        &fx,
        move |plan, _| plan.perms[perm_at(k, Seg::FeeRho, 0)].pre[0] ^= 1,
        |_| {},
        s0(k, Seg::FeeRho, 0),
        "fee_seed",
    )
}

/// F3 (1) on W: a transaction nullifier already in N.
fn neg_tx_double_insert() -> Neg {
    let mut fx = wfixture(&[P], SEED + 14);
    let n = fx.pre.l2.n.clone();
    let key = n.leaves()[1].0;
    set_digest_pvs(&mut fx.members[0].pvs, qlab_air::l2::PV_NF1, &key);
    tx_mut(&mut fx, 0).inserts[0] = forge_insert(&n, &key, leaf_ending_at(&n, &key), None);
    witness("f3/1 tx double insert (N)", fx, s0(0, Seg::LeafNew(0), 0), "cmp")
}

/// F3 (3b) on W.
fn neg_tx_forged_leaf() -> Neg {
    let mut fx = wfixture(&[P], SEED + 15);
    let n = fx.pre.l2.n.clone();
    let key = pv_digest_of(&fx.members[0].pvs, qlab_air::l2::PV_NF1);
    let right = tx_mut(&mut fx, 0).inserts[0].low_index;
    tx_mut(&mut fx, 0).inserts[0] = forge_insert(&n, &key, right, Some((EMPTY, qlab_air::l2p::KEY_MAX)));
    witness("f3/3b tx forged low leaf", fx, s0(0, ml(0), 0), "root_n")
}

/// F3 (5) on W.
fn neg_tx_append_skip() -> Neg {
    let mut fx = wfixture(&[S], SEED + 16);
    let c = fx.rin.f3.c_next;
    let tree = fx.pre.l2.c.clone();
    tx_mut(&mut fx, 0).appends[0] = AppendWitness { index: c + 1, path: empty_slot_path(&tree, c + 1) };
    witness("f3/5 tx append index skipped", fx, s0(0, cl(0), 0), "root_c")
}

/// F3 (8) on W.
fn neg_tx_key() -> Neg {
    let mut fx = wfixture(&[S], SEED + 17);
    tx_mut(&mut fx, 0).inserts[0].key[0] ^= 1;
    witness("f3/8 tx key not the surface's", fx, s0(0, Seg::LeafMid(0), 0), "leaf_key")
}

/// F3 (9) on W.
fn neg_tx_tag_swap() -> Neg {
    let mut fx = wfixture(&[P], SEED + 18);
    fx.members[0].tag = S;
    witness("f3/9 tx shape-tag swap", fx, s0(0, Seg::Sd(0), 0), "sd")
}

/// F3 (10) on W.
fn neg_tx_n_gap() -> Neg {
    let fx = wfixture(&[S, S], SEED + 19);
    let old = fx.rin.f3.n;
    let from = perm_at(1, Seg::Sd(0), 0);
    judge(
        "f3/10 tx N threading gap",
        &fx,
        move |plan, _| {
            each_perm(plan, from, |p| {
                for (j, l) in crate::f3::cmp::limbs(&old).iter().enumerate() {
                    p.set(N_OFF + j, Val::from_u32(*l));
                }
            })
        },
        |_| {},
        s23(0, Seg::Anch(APart::Last), 0),
        "root_n",
    )
}

/// F3's index cap on W.
fn neg_tx_bit30() -> Neg {
    let mut fx = wfixture(&[S], SEED + 20);
    tx_mut(&mut fx, 0).inserts[0].low_path.path_bits[30] = true;
    witness("f3/cap path bit 30", fx, s0(0, Seg::Pair(PathId::Mid(0), Part::L30), 0), "bit_cap")
}

/// F3's approval-3 negative on W.
fn neg_tx_free_hi() -> Neg {
    let fx = wfixture(&[S], SEED + 21);
    judge(
        "f3/3 free hi at NEW",
        &fx,
        |plan, _| plan.perms[perm_at(0, Seg::LeafNew(0), 0)].pre[4] ^= 1,
        |_| {},
        s0(0, Seg::LeafNew(0), 0),
        "leaf_hi",
    )
}

/// F3's obligation-1 negative on W.
fn neg_idle_cmp() -> Neg {
    let fx = wfixture(&[S], SEED + 22);
    let row = 1;
    judge("f3/idle comparator cell non-boolean", &fx, |_, _| {}, move |t| t.values[row * W_WIDTH + CMP_OFF] = Val::TWO, row, "cmp")
}

fn neg_pv_k_in() -> Neg {
    let fx = wfixture(&[C], SEED + 23);
    judge("pv: K in", &fx, |_, pvs| pvs[PV_K] += Val::ONE, |_| {}, 0, "first")
}

/// The fee PV one off the fee note's value.
fn neg_pv_fee() -> Neg {
    let fx = wfixture(&[C], SEED + 24);
    let k = fx.members.len() - 1;
    judge("pv: fee", &fx, |_, pvs| pvs[PV_FEE] += Val::ONE, |_| {}, s0(k, Seg::FeeNote, 0), "fee_note")
}

fn pv_digest_of(pvs: &[u32], off: usize) -> Digest {
    crate::f3::leaf::pv_digest(pvs, off)
}

/// `qlab-bench f4neg [--only a-b]`.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let all = cases();
    let (a, b) = match args.iter().position(|x| x == "--only") {
        Some(i) => {
            let r = args.get(i + 1).ok_or("--only takes a-b")?;
            let (a, b) = r.split_once('-').ok_or("--only takes a-b")?;
            (a.parse::<usize>().map_err(|e| e.to_string())?, b.parse::<usize>().map_err(|e| e.to_string())?)
        }
        None => (1, all.len()),
    };
    let (mut bad, mut ran) = (0, 0);
    for (i, (_, f)) in all.iter().enumerate().filter(|(i, _)| (a..=b).contains(&(i + 1))) {
        let n = f();
        let ok = n.holds();
        ran += 1;
        bad += usize::from(!ok);
        println!("{} {:2} {:42} want row {:6} {:12} got {:?}", if ok { "ok  " } else { "MISS" }, i + 1, n.name, n.row, n.phase, n.got);
    }
    println!("# f4neg {a}-{b}: {}/{ran} refused at their binding row", ran - bad);
    if bad > 0 {
        return Err(format!("{bad} negative(s) missed"));
    }
    Ok(())
}

/// `qlab-bench f4leaf --check [--kinds SPRC…]`: an honest W, scanned in full.
pub(crate) fn check(args: &[String]) -> Result<(), String> {
    let spec = args.iter().position(|a| a == "--kinds").and_then(|i| args.get(i + 1)).map_or("C", String::as_str);
    let kinds: Vec<WTag> = spec
        .chars()
        .map(|c| match c {
            'S' => Ok(WTag::S),
            'P' => Ok(WTag::P),
            'R' => Ok(WTag::R),
            'C' => Ok(WTag::C),
            o => Err(format!("unknown kind {o}")),
        })
        .collect::<Result<_, _>>()?;
    if kinds.is_empty() {
        return Err("--kinds needs at least one".into());
    }
    let fx = wfixture(&kinds, SEED);
    let t = std::time::Instant::now();
    let (air, trace, pvs) = honest(&fx);
    let gen = t.elapsed();
    let v = first_violation(&air, &trace, &pvs);
    println!(
        "# f4leaf --check kinds={spec}: {} rows x {} cols; gen {:.2?}, scan {:.2?}; {}",
        trace.height(),
        trace.width(),
        gen,
        t.elapsed() - gen,
        match &v {
            None => "every row holds".to_string(),
            Some((r, ph)) => format!("VIOLATED at row {r} (perm {}, round {}): {ph:?}", r / 24, r % 24),
        }
    );
    v.map_or(Ok(()), |_| Err("the honest W does not hold".into()))
}

#[cfg(test)]
mod tests {
    //! W's lane tests: shared small fixtures (K ≤ 2), full scans in parallel.
    use p3_air::symbolic::{get_max_constraint_degree, AirLayout};

    use super::*;

    /// W's width, read off the named `f4leaf --check` runs.
    const W_WIDTH_PIN: usize = 3_479;

    /// The program: 20 prologue, 65 slot and 7 epilogue segments in ring
    /// order; 320 + 661 + 67 perms; width pinned from the named runs;
    /// degree 3; every constraint group non-empty; the carries cover
    /// `MAX_CLAIMS`.
    #[test]
    fn f4w_program_width_and_degree() {
        let prog = program();
        assert_eq!(prog.len(), PAD);
        assert!(prog.iter().enumerate().all(|(i, s)| s.idx() == i));
        let sum = |r: std::ops::Range<usize>| prog[r].iter().map(|s| s.len()).sum::<usize>();
        assert_eq!((sum(0..SLOT_BASE), sum(SLOT_BASE..EPI_BASE), sum(EPI_BASE..PAD)), (PRO_PERMS, SLOT_PERMS, EPI_PERMS));
        assert_eq!(slot_program().len(), SLOT_SEGS);
        assert_eq!(W_WIDTH, W_WIDTH_PIN);
        let air = WAir::new(2);
        assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 3);
        assert!(phase_ranges(&air).iter().all(|r| !r.is_empty()), "every group emits");
        assert_eq!((w_height(1), w_height(2)), (1 << 15, 1 << 16));
    }

    /// Honest wrappers hold: every kind alone, and the two-slot mixes that
    /// thread K and C across a slot boundary.
    #[test]
    fn f4w_honest_wrappers_hold() {
        for kinds in [&[C][..], &[S], &[P], &[WTag::R], &[S, C], &[C, C], &[P, C]] {
            let fx = wfixture(kinds, SEED);
            let (air, trace, pvs) = honest(&fx);
            assert_eq!(first_violation(&air, &trace, &pvs), None, "{kinds:?}");
        }
        // An asset-0 redeem: an exit into E and the exit list; the supply
        // root does not move for it (condition (l)).
        let fx = wfixture_rows(&[P], SEED, [(1, 40, 0), (0, 0, 0)]);
        let (air, trace, pvs) = honest(&fx);
        assert_eq!(first_violation(&air, &trace, &pvs), None, "the exit wrapper");
        assert_eq!((fx.rout.e_cum, fx.rout.sup), (fx.rin.e_cum + 40, fx.rin.sup));
        assert_ne!(fx.exit_cmt, EMPTY);
        // (i): the two claims' fees carry out of limb 0.
        const { assert!(2 * (CLAIM_FEE & 0xffff) >= 1 << 16) };
    }

    /// Every negative, including the four two-slot ones (2, 10, 20, 37).
    #[test]
    fn f4w_negatives_refuse_at_their_binding_rows() {
        let cases = cases();
        assert_eq!(cases.len(), 40);
        let missed: Vec<String> = cases
            .iter()
            .map(|(_, f)| f())
            .filter(|n| !n.holds())
            .map(|n| format!("{}: want row {} {}, got {:?}", n.name, n.row, n.phase, n.got))
            .collect();
        assert!(missed.is_empty(), "{missed:#?}");
    }
}
