//! Lab #767 F3-2b — the leaf's fixtures and its negatives, shared by the
//! tests and `qlab-bench f3neg`.
//!
//! A negative is a malicious witness — or a malicious plan, where the lie is
//! a register the prover controls — run through the same generator as an
//! honest leaf ([`build_plan`] never validates), then scanned in full. The
//! claim is the house standard: the **lowest** violated row is the binding
//! row named here, and the named constraint group is violated there.
use p3_field::PrimeCharacteristicRing;
use qlab_air::l2::RegistryLeaf;
use qlab_air::l2p::KEY_MAX;
use qlab_air::narrow::MerkleWitness;
use qlab_cbserver::registry::RegistryTree;
use qlab_cbserver::tree::CommitmentTree;
use qlab_consensus::Val;
use qlab_devnet::annulet::L2ShapeTag;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use super::leaf::*;
use super::native::*;

/// A leaf's inputs and the state before it.
#[derive(Clone)]
pub(crate) struct Fixture {
    pub rin: Roots,
    pub txs: Vec<TxSurface>,
    pub wits: Vec<TxWitness>,
    pub rout: Roots,
    /// The state at `rin`.
    pub pre: L2State,
    /// The registry before the prefill's write (a superseded root).
    pub stale_r: RegistryTree,
}

/// A leaf over `shapes`, on a state that already holds one S transaction and
/// one registry write (asset 6), so every tree is past its genesis. R
/// transactions write assets 7, 8, …
pub(crate) fn fixture(shapes: &[L2ShapeTag], seed: u64) -> Fixture {
    let mut rng = Rng(seed);
    let mut s = L2State::genesis(&[RegistryLeaf::cloaked(0)]);
    let stale_r = s.r.clone();
    let t0 = synth_tx(&mut rng, L2ShapeTag::S, &s.r.root());
    let w6 = synth_write(&mut rng, &s, RegistryLeaf::cloaked(6));
    s.apply_leaf(&[t0, w6]).expect("the prefill leaf");
    let pre = s.clone();
    let mut work = s.clone();
    let mut txs = Vec::new();
    let mut asset = 7;
    for tag in shapes {
        let tx = match tag {
            L2ShapeTag::R => {
                asset += 1;
                synth_write(&mut rng, &work, RegistryLeaf::cloaked(asset - 1))
            }
            _ => synth_tx(&mut rng, *tag, &work.r.root()),
        };
        work.apply_tx(&tx).expect("a valid fixture transaction");
        txs.push(tx);
    }
    let (rin, wits, rout) = s.apply_leaf(&txs).expect("the fixture leaf");
    Fixture { rin, txs, wits, rout, pre, stale_r }
}

/// The trace and PVs of a fixture, honest.
pub(crate) fn honest(fx: &Fixture) -> (LeafAir, RowMajorMatrix<Val>, Vec<Val>) {
    let plan = build_plan(&fx.rin, &fx.txs, &fx.wits);
    (LeafAir::new(fx.txs.len()), render(&plan), leaf_pvs(&fx.rin, &fx.rout))
}

/// One negative's verdict.
#[derive(Debug)]
pub(crate) struct Neg {
    pub name: &'static str,
    /// The binding row and the group that must refuse there.
    pub row: usize,
    pub phase: &'static str,
    /// The lowest violated row and its groups (`None`: the trace holds).
    pub got: Option<(usize, Vec<&'static str>)>,
}

impl Neg {
    pub(crate) fn holds(&self) -> bool {
        matches!(&self.got, Some((r, ph)) if *r == self.row && ph.contains(&self.phase))
    }
}

/// Step-0 row of segment `seg`'s `i`-th perm in `slot`.
pub(crate) fn s0(slot: usize, seg: Seg, i: usize) -> usize {
    row_of(perm_at(slot, seg, i), 0)
}

/// Last row of that perm.
pub(crate) fn s23(slot: usize, seg: Seg, i: usize) -> usize {
    row_of(perm_at(slot, seg, i), 23)
}

/// Generate, tamper, scan.
fn judge(
    name: &'static str,
    fx: &Fixture,
    tamper: impl FnOnce(&mut Plan, &mut Vec<Val>),
    retouch: impl FnOnce(&mut RowMajorMatrix<Val>),
    row: usize,
    phase: &'static str,
) -> Neg {
    let mut plan = build_plan(&fx.rin, &fx.txs, &fx.wits);
    let mut pvs = leaf_pvs(&fx.rin, &fx.rout);
    tamper(&mut plan, &mut pvs);
    let mut trace = render(&plan);
    retouch(&mut trace);
    let air = LeafAir::new(fx.txs.len());
    let got = first_violation(&air, &trace, &pvs);
    Neg { name, row, phase, got }
}

fn witness(name: &'static str, fx: Fixture, row: usize, phase: &'static str) -> Neg {
    judge(name, &fx, |_, _| {}, |_| {}, row, phase)
}

/// An insert witness for `key` opening leaf `low_index` of `tree` as it is
/// (or `low` in its place), whatever it brackets.
fn forge_insert(tree: &IndexedTree, key: &Digest, low_index: u64, low: Option<(Digest, Digest)>) -> InsertWitness {
    let genuine = tree.leaves()[low_index as usize];
    let low = low.unwrap_or(genuine);
    let low_path = tree.path(low_index);
    let mut t = tree.clone();
    t.put(low_index, (low.0, *key));
    let new_index = t.next_index();
    InsertWitness { key: *key, low_index, low, low_path, new_index, new_path: t.path(new_index) }
}

/// The index of the leaf whose `hi` is `key`, and of the one bracketing it.
fn leaf_ending_at(tree: &IndexedTree, key: &Digest) -> u64 {
    tree.leaves().iter().position(|l| l.1 == *key).expect("a leaf ending at the key") as u64
}

/// The path of slot `pos` in `tree` with every slot up to it empty.
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

/// Tamper every perm of `slots` and the pad with `f`.
fn each_perm(plan: &mut Plan, from_perm: usize, f: impl Fn(&mut PermPlan)) {
    for p in plan.perms.iter_mut().skip(from_perm) {
        f(p);
    }
    f(&mut plan.pad);
}

const P: L2ShapeTag = L2ShapeTag::P;
const R: L2ShapeTag = L2ShapeTag::R;
const S: L2ShapeTag = L2ShapeTag::S;
pub(crate) const SEED: u64 = 0x767_f3b0;

/// One negative, run on demand.
pub(crate) type Case = (&'static str, fn() -> Neg);

fn mid_last(i: usize) -> Seg {
    Seg::Pair(PathId::Mid(i), Part::LastB)
}
fn c_last(j: usize) -> Seg {
    Seg::Pair(PathId::C(j), Part::LastB)
}
const R_LAST: Seg = Seg::Pair(PathId::R, Part::LastB);

/// Every negative, in the #767 ruling's order: §5 (1)–(8), ruling (d)'s (9)
/// and (10), then the approval conditions and the F3-2a obligations.
pub(crate) fn cases() -> Vec<Case> {
    vec![
        ("1 double insert across leaves", neg_double_insert),
        ("2 batch-internal duplicate", neg_batch_duplicate),
        ("3a genuine non-bracketing low leaf", neg_wrong_low_leaf),
        ("3b forged low leaf", neg_forged_low_leaf),
        ("4 stale root N", neg_stale_n),
        ("4 stale root C", neg_stale_c),
        ("4 stale root R", neg_stale_r),
        ("5 append order swap", neg_append_swap),
        ("5 append index skipped", neg_append_skip),
        ("6 write not in the surface", neg_write_unbound),
        ("6 old leaf does not open", neg_old_leaf),
        ("6 stale registry read", neg_stale_read),
        ("7 append into a non-empty slot", neg_nonempty_slot),
        ("8 inserted key not the surface's", neg_key_not_surface),
        ("9 shape-tag swap", neg_tag_swap),
        ("10 threading gap", neg_threading_gap),
        ("cap: path bit 30", neg_bit30),
        ("3: free lo at MID", neg_free_lo),
        ("3: free hi at NEW", neg_free_hi),
        ("4: activate a gated-off insert (R)", neg_activate),
        ("4: S declared R", neg_s_as_r),
        ("idle comparator cell non-boolean", neg_idle_cmp),
        ("key register limb out of range", neg_key_range),
        ("pv: N in", neg_pv_in),
        ("pv: SD out", neg_pv_out),
        ("boundary: declared k != slots", neg_k_mismatch),
        ("boundary: ends before PAD", neg_ends_early),
    ]
}

/// (1) A double insert across leaves: K is already in N. The prover opens the
/// leaf (lo, K) — genuine, so the old root checks — and must then hash
/// (K, K): the strict K < hi fails on LEAF_NEW.
fn neg_double_insert() -> Neg {
    let mut fx = fixture(&[P, R], SEED);
    let k = fx.pre.n.leaves()[1].0; // a key the prefill inserted
    set_digest_pvs(&mut fx.txs[0].pvs, qlab_air::l2::PV_NF1, &k);
    fx.wits[0].inserts[0] = forge_insert(&fx.pre.n, &k, leaf_ending_at(&fx.pre.n, &k), None);
    witness("1 double insert across leaves", fx, s0(0, Seg::LeafNew(0), 0), "cmp")
}

/// (2) A batch-internal duplicate: tx 2's first nullifier is tx 1's.
fn neg_batch_duplicate() -> Neg {
    let mut fx = fixture(&[P, P], SEED + 1);
    let k = fx.txs[0].nullifiers().unwrap()[0];
    set_digest_pvs(&mut fx.txs[1].pvs, qlab_air::l2::PV_NF1, &k);
    let mut after = fx.pre.clone();
    after.apply_tx(&fx.txs[0]).unwrap();
    fx.wits[1].inserts[0] = forge_insert(&after.n, &k, leaf_ending_at(&after.n, &k), None);
    witness("2 batch-internal duplicate", fx, s0(1, Seg::LeafNew(0), 0), "cmp")
}

/// (3a) A genuine low leaf that does not bracket K.
fn neg_wrong_low_leaf() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 2);
    let k = fx.txs[0].nullifiers().unwrap()[0];
    let right = fx.wits[0].inserts[0].low_index;
    let j = (0..fx.pre.n.next_index()).find(|j| *j != right).unwrap();
    let (lo, _) = fx.pre.n.leaves()[j as usize];
    let row = if qlab_air::l2p::key_lt(&lo, &k) { s0(0, Seg::LeafNew(0), 0) } else { s0(0, Seg::LeafMid(0), 0) };
    fx.wits[0].inserts[0] = forge_insert(&fx.pre.n, &k, j, None);
    witness("3a genuine non-bracketing low leaf", fx, row, "cmp")
}

/// (3b) A forged leaf that brackets K but is not in N.
fn neg_forged_low_leaf() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 3);
    let k = fx.txs[0].nullifiers().unwrap()[0];
    let right = fx.wits[0].inserts[0].low_index;
    fx.wits[0].inserts[0] = forge_insert(&fx.pre.n, &k, right, Some((EMPTY, KEY_MAX)));
    witness("3b forged low leaf", fx, s0(0, mid_last(0), 0), "root_n")
}

/// (4) Stale N: insert 2's witness from before insert 1 moved N.
fn neg_stale_n() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 4);
    let k = fx.txs[0].nullifiers().unwrap()[1];
    let j = fx.pre.n.low_leaf_of(&k).unwrap();
    fx.wits[0].inserts[1] = forge_insert(&fx.pre.n, &k, j, None);
    witness("4 stale root N", fx, s0(0, mid_last(1), 0), "root_n")
}

/// (4) Stale C: append 2 at the right index, its path from before append 1.
fn neg_stale_c() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 5);
    let c = fx.rin.c_next;
    fx.wits[0].appends[1] = AppendWitness { index: c + 1, path: empty_slot_path(&fx.pre.c, c + 1) };
    witness("4 stale root C", fx, s0(0, c_last(1), 0), "root_c")
}

/// (4) Stale R: the write opened in the registry before the prefill's write.
fn neg_stale_r() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 6);
    let stale = fx.stale_r.clone();
    let rw = fx.wits[1].write.as_mut().unwrap();
    rw.path = stale.opening_at(rw.leaf.asset as u16);
    witness("4 stale root R", fx, s0(1, R_LAST, 0), "root_r")
}

/// (5) Append order: the commitment registers swapped against the surface.
fn neg_append_swap() -> Neg {
    let fx = fixture(&[P, R], SEED + 7);
    judge(
        "5 append order swap",
        &fx,
        |plan, _| {
            each_perm(plan, 0, |p| {
                for j in 0..16 {
                    let (a, b) = (p.get(CM_OFF + j), p.get(CM_OFF + 16 + j));
                    p.set(CM_OFF + j, b);
                    p.set(CM_OFF + 16 + j, a);
                }
            })
        },
        |_| {},
        s0(0, Seg::Sd(1), 0),
        "sd_capture",
    )
}

/// (5) An index skipped: append 1 into the empty slot after the running index.
fn neg_append_skip() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 8);
    let c = fx.rin.c_next;
    fx.wits[0].appends[0] = AppendWitness { index: c + 1, path: empty_slot_path(&fx.pre.c, c + 1) };
    witness("5 append index skipped", fx, s0(0, c_last(0), 0), "root_c")
}

/// (6) A registry write the surface does not authorize: a leaf the PV's
/// new_root does not fold from.
fn neg_write_unbound() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 9);
    fx.wits[1].write.as_mut().unwrap().leaf.mode ^= 1;
    witness("6 write not in the surface", fx, s23(1, R_LAST, 0), "root_r")
}

/// (6) The old leaf does not open against the running R.
fn neg_old_leaf() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 10);
    fx.wits[1].write.as_mut().unwrap().old_digest[0] ^= 1;
    witness("6 old leaf does not open", fx, s0(1, R_LAST, 0), "root_r")
}

/// (6) An S/P read of a registry root that is not the running R.
fn neg_stale_read() -> Neg {
    let mut fx = fixture(&[R, S], SEED + 11);
    let stale = fx.rin.r;
    set_digest_pvs(&mut fx.txs[1].pvs, qlab_air::l2::PV_REGROOT, &stale);
    witness("6 stale registry read", fx, s0(1, R_LAST, 0), "reg_read")
}

/// (7) An append into a non-empty slot: the last filled one.
fn neg_nonempty_slot() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 12);
    let c = fx.rin.c_next;
    fx.wits[0].appends[0] = AppendWitness { index: c - 1, path: fx.pre.c.auth_path(c - 1, c) };
    witness("7 append into a non-empty slot", fx, s0(0, c_last(0), 0), "root_c")
}

/// (8) A nullifier inserted that is not the surface's (approval condition 3:
/// K ≠ the SD-absorbed chunk).
fn neg_key_not_surface() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 13);
    fx.wits[0].inserts[0].key[0] ^= 1;
    witness("8 inserted key not the surface's", fx, s0(0, Seg::LeafMid(0), 0), "leaf_key")
}

/// (9) SD over a shape-tag swap: a P vector declared S.
fn neg_tag_swap() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 14);
    fx.txs[0].tag = S;
    witness("9 shape-tag swap", fx, s0(0, Seg::Sd(0), 0), "sd")
}

/// (10) A threading gap: slot 2 starts from an N that slot 1 did not end on.
fn neg_threading_gap() -> Neg {
    let fx = fixture(&[P, R], SEED + 15);
    let old = fx.rin.n;
    judge(
        "10 threading gap",
        &fx,
        |plan, _| {
            each_perm(plan, SLOT_PERMS, |p| {
                for (j, l) in super::cmp::limbs(&old).iter().enumerate() {
                    p.set(N_OFF + j, Val::from_u32(*l));
                }
            })
        },
        |_| {},
        s23(0, R_LAST, 0),
        "root_n",
    )
}

/// Approval 2: path bit 30 set (an index ≥ 2^30).
fn neg_bit30() -> Neg {
    let mut fx = fixture(&[P, R], SEED + 16);
    fx.wits[0].inserts[0].low_path.path_bits[30] = true;
    witness("cap: path bit 30", fx, s0(0, Seg::Pair(PathId::Mid(0), Part::L30), 0), "bit_cap")
}

/// Approval 3: a free lo′ at LEAF_MID.
fn neg_free_lo() -> Neg {
    let fx = fixture(&[P, R], SEED + 17);
    judge(
        "3: free lo at MID",
        &fx,
        |plan, _| plan.perms[perm_at(0, Seg::LeafMid(0), 0)].pre[0] ^= 1,
        |_| {},
        s23(0, Seg::LeafOld(0), 0),
        "leaf_lo",
    )
}

/// Approval 3: a free hi′ at LEAF_NEW.
fn neg_free_hi() -> Neg {
    let fx = fixture(&[P, R], SEED + 17);
    judge(
        "3: free hi at NEW",
        &fx,
        |plan, _| plan.perms[perm_at(0, Seg::LeafNew(0), 0)].pre[4] ^= 1,
        |_| {},
        s0(0, Seg::LeafNew(0), 0),
        "leaf_hi",
    )
}

/// Approval 4: activating a gated-off insert on an R transaction.
fn neg_activate() -> Neg {
    let fx = fixture(&[P, R], SEED + 18);
    judge(
        "4: activate a gated-off insert (R)",
        &fx,
        |plan, _| plan.perms[perm_at(1, Seg::LeafOld(1), 0)].set(ON, Val::ONE),
        |_| {},
        s0(1, Seg::LeafOld(1), 0),
        "flags",
    )
}

/// Approval 4: an S transaction declared R (to skip two inserts).
fn neg_s_as_r() -> Neg {
    let mut fx = fixture(&[S], SEED + 19);
    fx.txs[0].tag = R;
    witness("4: S declared R", fx, s0(0, Seg::Sd(0), 0), "sd")
}

/// Obligation 1: a non-boolean comparator cell on an idle row.
fn neg_idle_cmp() -> Neg {
    let fx = fixture(&[P, R], SEED + 20);
    let row = s0(0, Seg::Sd(0), 0) + 1;
    judge(
        "idle comparator cell non-boolean",
        &fx,
        |_, _| {},
        move |t| t.values[row * LEAF_WIDTH + CMP_OFF] = Val::TWO,
        row,
        "cmp",
    )
}

/// Obligation 2: a key register limb out of range (≥ 2^16).
fn neg_key_range() -> Neg {
    let fx = fixture(&[P, R], SEED + 21);
    judge(
        "key register limb out of range",
        &fx,
        |plan, _| {
            each_perm(plan, 0, |p| {
                let v = p.get(NF_OFF) + Val::from_u32(1 << 16);
                p.set(NF_OFF, v);
            })
        },
        |_| {},
        s0(0, Seg::Sd(0), 0),
        "sd_capture",
    )
}

/// The public surface: a wrong N in.
fn neg_pv_in() -> Neg {
    let fx = fixture(&[P, R], SEED + 22);
    judge("pv: N in", &fx, |_, pvs| pvs[PV_N] += Val::ONE, |_| {}, 0, "first")
}

/// The public surface: a wrong SD out.
fn neg_pv_out() -> Neg {
    let fx = fixture(&[P, R], SEED + 22);
    judge("pv: SD out", &fx, |_, pvs| pvs[PV_SIDE + PV_SD] += Val::ONE, |_| {}, leaf_height(2) - 1, "last")
}

/// Boundary (a), F3-2b review: a two-slot trace checked as a three-slot
/// leaf. The AIR seeds `LEFT = k − 1` on the first row; the trace's is 1.
fn neg_k_mismatch() -> Neg {
    let fx = fixture(&[P, R], SEED + 23);
    let plan = build_plan(&fx.rin, &fx.txs, &fx.wits);
    let trace = render(&plan);
    let pvs = leaf_pvs(&fx.rin, &fx.rout);
    let got = first_violation(&LeafAir::new(3), &trace, &pvs);
    Neg { name: "boundary: declared k != slots", row: 0, phase: "first", got }
}

/// Boundary (b), F3-2b review: a two-slot leaf whose trace stops at 2^14
/// rows, inside slot 2 — every earlier row consistent, the last row neither
/// PAD nor the declared surface out.
fn neg_ends_early() -> Neg {
    let fx = fixture(&[P, R], SEED + 24);
    let short = 1 << 14;
    judge(
        "boundary: ends before PAD",
        &fx,
        |_, _| {},
        move |t| t.values.truncate(short * LEAF_WIDTH),
        short - 1,
        "last",
    )
}

/// `qlab-bench f3neg [--only a-b]`: the negatives (1-based, inclusive
/// range), one line each; an error on any miss.
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
    let mut bad = 0;
    let mut ran = 0;
    for (i, (_, f)) in all.iter().enumerate().filter(|(i, _)| (a..=b).contains(&(i + 1))) {
        let n = f();
        let ok = n.holds();
        ran += 1;
        bad += usize::from(!ok);
        println!("{} {:2} {:40} want row {:6} {:12} got {:?}", if ok { "ok  " } else { "MISS" }, i + 1, n.name, n.row, n.phase, n.got);
    }
    println!("# f3neg {a}-{b}: {}/{ran} refused at their binding row", ran - bad);
    if bad > 0 {
        return Err(format!("{bad} negative(s) missed"));
    }
    Ok(())
}

/// `qlab-bench f3leaf --check [--shapes PSR… | --k N]`: an honest leaf over
/// the given shapes (default `P`), scanned in full.
pub(crate) fn check(args: &[String]) -> Result<(), String> {
    let shapes = super::bench::shapes_arg(args)?;
    let spec: String = shapes.iter().map(|t| format!("{t:?}")).collect();
    let k = shapes.len();
    let fx = fixture(&shapes, SEED);
    let t = std::time::Instant::now();
    let (air, trace, pvs) = honest(&fx);
    let gen = t.elapsed();
    let v = first_violation(&air, &trace, &pvs);
    println!(
        "# f3leaf --check k={k} shapes={spec}: {} rows x {} cols; gen {:.2?}, scan {:.2?}; {}",
        trace.height(),
        trace.width(),
        gen,
        t.elapsed() - gen,
        match &v {
            None => "every row holds".to_string(),
            Some((r, ph)) => format!("VIOLATED at row {r} (perm {}, round {}): {ph:?}", r / 24, r % 24),
        }
    );
    v.map_or(Ok(()), |_| Err("the honest leaf does not hold".into()))
}

/// The SD test vectors (approval condition 1(a)): the fixture leaf `[P, R]`
/// at [`SEED`] — `SD` in (the prefill leaf's chain from zero), after its P
/// transaction, and out — as the four lanes in hex.
pub(crate) fn sd_vectors() -> [Digest; 3] {
    let fx = fixture(&[P, R], SEED);
    let after_p = sd_step(&fx.rin.sd, P, &fx.txs[0].pvs);
    [fx.rin.sd, after_p, sd_step(&after_p, R, &fx.txs[1].pvs)]
}

pub(crate) fn hex(d: &Digest) -> String {
    d.iter().map(|l| format!("{l:016x}")).collect::<Vec<_>>().join(" ")
}

/// `qlab-bench f3vec`: print [`sd_vectors`].
pub(crate) fn vec_run(_args: &[String]) -> Result<(), String> {
    for (name, d) in ["sd_in", "after_p", "sd_out"].iter().zip(sd_vectors()) {
        println!("{name:8} {}", hex(&d));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The leaf's lane tests. Every trace here is k ≤ 2 (2^14–2^15 rows); the
    //! scans are p3's row loop in parallel.
    use p3_air::symbolic::{get_max_constraint_degree, AirLayout};

    use super::*;
    use crate::f3::cmp::LT_WIDTH;

    /// The program and the shape: 51 segments in ring order, 560 perms a
    /// slot (the census's count), width 3,225 (lab #785 F5-4d: one SD block
    /// more, 50 → 51, 559 → 560, 3,224 → 3,225), degree 3 (b2 is a lane), and
    /// every constraint group non-empty.
    #[test]
    fn f3leaf_program_width_and_degree() {
        let prog = slot_program();
        assert_eq!(prog.len(), NSEG);
        assert_eq!((NSEG, SLOT_PERMS), (51, 560));
        assert_eq!(prog[..SD_BLOCKS], (0..SD_BLOCKS).map(Seg::Sd).collect::<Vec<_>>()[..]);
        assert_eq!(prog[SD_BLOCKS], Seg::LeafOld(0));
        assert_eq!(prog[NSEG - 1], Seg::Pair(PathId::R, Part::LastB));
        assert!(prog.iter().enumerate().all(|(i, s)| s.idx() == i));
        assert_eq!(prog.iter().map(|s| s.len()).sum::<usize>(), SLOT_PERMS);
        assert_eq!(super::super::census::slot_perms(), SLOT_PERMS);
        assert_eq!(LEAF_WIDTH, 3_225);
        let air = LeafAir::new(2);
        assert_eq!(get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air)), 3);
        assert!(phase_ranges(&air).iter().all(|r| !r.is_empty()), "every group emits");
        assert_eq!(leaf_height(2), 1 << 15);
    }

    /// Honest leaves hold: each shape alone, and two-slot mixes that thread R
    /// before and after a read.
    #[test]
    fn f3leaf_honest_leaves_hold() {
        for shapes in [&[P][..], &[S], &[R], &[P, R], &[R, S]] {
            let fx = fixture(shapes, SEED);
            let (air, trace, pvs) = honest(&fx);
            assert_eq!(first_violation(&air, &trace, &pvs), None, "{shapes:?}");
        }
    }

    /// Obligation 1 and approval 4(a): the comparator's cells are nonzero
    /// only on the active LEAF_MID / LEAF_NEW step-0 rows (the generator
    /// zero-fills every other row; `cmp_idle` refuses anything else), and an
    /// inactive segment moves no running register.
    #[test]
    fn f3leaf_idle_cells_and_inactive_segments() {
        let fx = fixture(&[P, R], SEED);
        let (_, trace, _) = honest(&fx);
        let col = |row: usize, c: usize| trace.values[row * LEAF_WIDTH + c];
        let live: Vec<usize> = (0..trace.height()).filter(|r| (0..LT_WIDTH).any(|i| col(*r, CMP_OFF + i) != Val::ZERO)).collect();
        let mut want: Vec<usize> = [(0, 0), (0, 1), (0, 2), (1, 0)]
            .iter()
            .flat_map(|(s, i)| [s0(*s, Seg::LeafMid(*i), 0), s0(*s, Seg::LeafNew(*i), 0)])
            .collect();
        want.sort();
        assert_eq!(live, want, "P: three inserts; R: one");
        let regs = |row: usize, off: usize, n: usize| (off..off + n).map(|c| col(row, c)).collect::<Vec<_>>();
        // Slot 1 is R: inserts 2 and 3 are off — N and n_next do not move.
        let (a, b) = (s0(1, Seg::LeafOld(1), 0), s23(1, R_LAST, 0));
        assert_eq!((regs(a, N_OFF, 16), col(a, NN)), (regs(b, N_OFF, 16), col(b, NN)));
        // R's SD block 4 is off: SD moved at block 3's end and stays.
        let (sd3, sd4, ins) = (s0(1, Seg::Sd(3), 0), s0(1, Seg::Sd(4), 0), s0(1, Seg::LeafOld(0), 0));
        assert_ne!(regs(sd3, SD_OFF, 16), regs(sd4, SD_OFF, 16));
        assert_eq!(regs(sd4, SD_OFF, 16), regs(ins, SD_OFF, 16));
        // Slot 0 is P: its registry segment is off — R does not move.
        assert_eq!(regs(s0(0, Seg::RegLeaf, 0), R_OFF, 16), regs(s0(1, Seg::Sd(0), 0), R_OFF, 16));
    }

    /// Approval 1(a): the SD test vectors — the fixture leaf `[P, R]`'s SD in,
    /// after its P transaction (six blocks since lab #785 F5-4d), and out (after its R, four
    /// blocks) — natively and in the AIR's trace and public values. The
    /// literals are `qlab-bench f3vec`'s output.
    #[test]
    fn f3leaf_sd_vectors() {
        const SD_IN: Digest = [0x2e14bf6b332aa7b0, 0x153cf3d726326217, 0x4fd48521c7bae5fb, 0xe7b0935ef4961c3e];
        const AFTER_P: Digest = [0x4648ef13d0b6e74f, 0xdc1073de28246423, 0x2e083b862b002575, 0xc74bd36d2b5f23d5];
        const SD_OUT: Digest = [0xc5feb7bf2e2b0a93, 0xc2f4d8cac6a7e75c, 0xfb6455911a040a71, 0x0d5dc862ea5ab067];
        assert_eq!(sd_vectors(), [SD_IN, AFTER_P, SD_OUT], "native");
        let fx = fixture(&[P, R], SEED);
        assert_eq!((fx.rin.sd, fx.rout.sd), (SD_IN, SD_OUT), "the native leaf");
        let (air, trace, pvs) = honest(&fx);
        assert_eq!(first_violation(&air, &trace, &pvs), None);
        let sd_at = |row: usize| -> Vec<Val> { (0..16).map(|j| trace.values[row * LEAF_WIDTH + SD_OFF + j]).collect() };
        let as_vals = |d: &Digest| -> Vec<Val> { super::super::cmp::limbs(d).iter().map(|l| Val::from_u32(*l)).collect() };
        assert_eq!(sd_at(0), as_vals(&SD_IN), "the AIR's SD in");
        assert_eq!(sd_at(s0(1, Seg::Sd(0), 0)), as_vals(&AFTER_P), "the AIR's SD after P");
        assert_eq!(pvs[PV_SIDE + PV_SD..PV_SIDE + PV_SD + 16].to_vec(), as_vals(&SD_OUT), "the AIR's SD out");
    }

    /// §5 (1)–(8), ruling (d)'s (9)–(10), the approval conditions and the
    /// F3-2a obligations: each malicious trace's **lowest** violated row is
    /// its binding row, refused there by the named group.
    #[test]
    fn f3leaf_negatives_refuse_at_their_binding_rows() {
        let cases = cases();
        assert_eq!(cases.len(), 27);
        let missed: Vec<String> = cases
            .iter()
            .map(|(_, f)| f())
            .filter(|n| !n.holds())
            .map(|n| format!("{}: want row {} {}, got {:?}", n.name, n.row, n.phase, n.got))
            .collect();
        assert!(missed.is_empty(), "{missed:#?}");
    }
}
