//! Lab #775 F4-1 — the wrapper leaf's native reference: the claim slot, the
//! L1-anchor accumulator, the sequencer fee note, and the leaf's statement
//! ([`check_wrapper_leaf`]) that the W AIR mirrors and the negatives target.
//!
//! **The slot sequence (ruling condition (a)).** A wrapper's members — L2
//! transactions (S/P/R) and deposit claims (tag [`CLAIM_TAG`]) — form ONE
//! sequence: bundle order = W's slot order = SD order.
//!
//! **A claim slot** (F1's claim PVs, issue #756): inserts its `cnf` into the
//! claim-nullifier indexed tree `K` (F3's insert, strict gap), appends its
//! credited note `cm2` to `C` (F3's append), and opens its L1 anchor `A` in
//! the L1-anchor accumulator `AA` (a membership path; `A ≠ 0`).
//!
//! **Anchor absorption.** Before its slots, every wrapper appends exactly
//! [`M_ABS`] absorbed L1 roots to `AA` (the count a devnet placeholder, ruling
//! Q8). That they are genuine recent finalized L1 roots is the enshrined
//! rule's check (F5), stubbed in [`super::verify`].
//!
//! **The sequencer fee note (ruling condition (e), option 1).** After its
//! slots, every wrapper appends ONE asset-0 note — value `F_batch = Σ fee`
//! over its claims (0 with none), recipient the public `rkm_seq`,
//! `ρ = H("qumbra:l2-claimfee:v1"; prev)`, `rseed = H("qumbra:l2-claimfee-rseed:v1"; prev)`.
//! **Public by design**, as an L1 coinbase is: value, `rkm_seq`, `ρ` and
//! `rseed` are derivable by anyone. **Its nullifier is not:** an L2 note's
//! nullifier is `nf = H(nk ‖ ρ)` (`qlab_air::l2::derive_input_l2`) with `nk`
//! the spend key's hash, and the only public image of `nk` is
//! `rkm = H(nk ‖ D_R ‖ d)` — so deriving the fee note's nullifier from its
//! public fields is a Keccak preimage search. Only the sequencer can spend or
//! recognize its spend.
//!
//! **The invariant it closes, scoped to bridged value in.** A claim credits
//! `cm2.value = v − fee` (F1's claim proof), the deposit-sum proof (F4-3)
//! proves `D_batch = Σ v`, and W binds the fee note's value to `Σ fee` — so
//! the asset-0 value claims create on L2 is exactly `Σ(v − fee) + Σ fee =
//! D_batch` per wrapper, and `D_cum` in total. **L2 transaction fees are
//! outside this invariant**: F6 adds the tx-fee flows (the Phase-0 fee unit,
//! qQMB after F6).
//!
//! **Limits:** every append structure (`N`, `C`, `K`, `AA`) stops at
//! [`INDEX_CAP`] = 2^30 (inherited, Larry 2026-09-29).
// The W AIR is this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use qlab_air::l2::{l2_cm, RegistryLeaf};
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
use qlab_air::reference::keccak_f;
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::L2ShapeTag;

use crate::f3::native::{
    append, apply_append, apply_insert, sd_chain_byte, AppendError, AppendWitness, Digest, IndexedTree, InsertWitness,
    L2State, NfError, Roots, StError, TxSurface, TxWitness, EMPTY, INDEX_CAP,
};

/// A deposit claim's slot tag (SD's word 0).
pub(crate) const CLAIM_TAG: u8 = 0x04;
/// L1 roots absorbed per wrapper (ruling Q8: a devnet placeholder).
pub(crate) const M_ABS: usize = 4;

/// A slot's kind: an L2 transaction shape or a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WTag {
    S,
    P,
    R,
    C,
}

impl WTag {
    pub(crate) const ALL: [WTag; 4] = [WTag::S, WTag::P, WTag::R, WTag::C];
    pub(crate) fn byte(self) -> u8 {
        match self {
            WTag::S => L2ShapeTag::S.byte(),
            WTag::P => L2ShapeTag::P.byte(),
            WTag::R => L2ShapeTag::R.byte(),
            WTag::C => CLAIM_TAG,
        }
    }
    pub(crate) fn pv_len(self) -> usize {
        match self {
            WTag::S => qlab_air::l2::PV_LEN,
            WTag::P => qlab_air::l2p::PV_LEN,
            WTag::R => qlab_air::l2r::PV_LEN,
            WTag::C => qlab_air::claim::PV_LEN,
        }
    }
    pub(crate) fn shape(self) -> Option<L2ShapeTag> {
        match self {
            WTag::S => Some(L2ShapeTag::S),
            WTag::P => Some(L2ShapeTag::P),
            WTag::R => Some(L2ShapeTag::R),
            WTag::C => None,
        }
    }
    pub(crate) fn of(tag: L2ShapeTag) -> Self {
        match tag {
            L2ShapeTag::S => WTag::S,
            L2ShapeTag::P => WTag::P,
            L2ShapeTag::R => WTag::R,
        }
    }
}

/// One member of the sequence: its tag and full public-value vector (and an
/// R write's leaf, as F3).
#[derive(Clone, Debug)]
pub(crate) struct Member {
    pub tag: WTag,
    pub pvs: Vec<u32>,
    pub write: Option<RegistryLeaf>,
}

impl Member {
    pub(crate) fn tx(t: &TxSurface) -> Self {
        Member { tag: WTag::of(t.tag), pvs: t.pvs.clone(), write: t.write }
    }
    fn as_tx(&self) -> Option<TxSurface> {
        self.tag.shape().map(|tag| TxSurface { tag, pvs: self.pvs.clone(), write: self.write })
    }
    fn digest_at(&self, off: usize) -> Result<Digest, WError> {
        let c = self.pvs.get(off..off + 16).ok_or(WError::Surface)?;
        if c.iter().any(|x| *x >= 1 << 16) {
            return Err(WError::Surface);
        }
        Ok(core::array::from_fn(|l| (0..4).map(|j| (c[4 * l + j] as u64) << (16 * j)).sum()))
    }
    /// A claim's fee: four 16-bit chunks, little-endian.
    fn fee(&self) -> Result<u64, WError> {
        let c = self.pvs.get(qlab_air::claim::PV_FEE..qlab_air::claim::PV_FEE + 4).ok_or(WError::Surface)?;
        if c.iter().any(|x| *x >= 1 << 16) {
            return Err(WError::Surface);
        }
        Ok((0..4).map(|j| (c[j] as u64) << (16 * j)).sum())
    }
}

/// Why a wrapper leaf is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WError {
    /// An F3 transaction step.
    Tx(StError),
    /// A claim's `cnf` insert (a double claim has no gap).
    Cnf(NfError),
    /// A claim's `cm2`, an absorbed root, or the fee note's append.
    Append(AppendError),
    /// A claim anchor that does not open in `AA`, or is zero.
    Anchor,
    /// A PV vector of the wrong length, or a chunk ≥ 2^16.
    Surface,
    /// The witnesses do not match the members.
    Shape,
    /// More members than the leaf's slots, or a second R.
    Capacity,
    /// The fee sum overflows u64.
    FeeOverflow,
}

/// The running state a wrapper leaf threads: F3's six plus `K` (the claim
/// nullifiers, `cnf_root`) and `AA` (the L1-anchor accumulator).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WRoots {
    pub f3: Roots,
    pub k: Digest,
    pub k_next: u64,
    pub aa: Digest,
    pub aa_next: u64,
}

/// A claim slot's witnesses.
#[derive(Clone, Copy)]
pub(crate) struct ClaimWitness {
    pub insert: InsertWitness,
    pub append: AppendWitness,
    /// `A`'s leaf index in `AA` and its path.
    pub anchor_index: u64,
    pub anchor_path: MerkleWitness,
}

impl std::fmt::Debug for ClaimWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClaimWitness {{ anchor_index: {} }}", self.anchor_index)
    }
}

impl std::fmt::Debug for WWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WWitness {{ slots: {} }}", self.slots.len())
    }
}

/// One slot's witnesses.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SlotWitness {
    Tx(TxWitness),
    Claim(ClaimWitness),
}

/// A wrapper leaf's public inputs besides the members.
#[derive(Clone, Debug)]
pub(crate) struct WInputs {
    /// The predecessor's surface commitment.
    pub prev: Digest,
    /// The sequencer's raw recipient key (the fee note's `rkm`).
    pub rkm_seq: Digest,
    /// The L1 roots this wrapper absorbs.
    pub absorbed: [Digest; M_ABS],
}

/// A wrapper leaf's witnesses, in [`check_wrapper_leaf`]'s order.
#[derive(Clone)]
pub(crate) struct WWitness {
    pub absorbs: [AppendWitness; M_ABS],
    pub slots: Vec<SlotWitness>,
    pub fee: AppendWitness,
}

/// The fee note's `ρ` and `rseed`: one domain-tagged Keccak-f each over
/// `prev` — `prev` in lanes 0..4, the kind in lane 4 (1 = ρ, 2 = rseed),
/// the domain `"qumbra:l2-claimfee:v1"` in capacity lanes 21..24, which no
/// node, leaf, registry or SD block sets.
pub(crate) fn fee_seed_state(prev: &Digest, kind: u64) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(prev);
    st[4] = kind;
    st[8] = 1;
    st[16] = 1 << 63;
    let dom = fee_domain_lanes();
    st[21..24].copy_from_slice(&dom);
    st
}

/// `"qumbra:l2-claimfee:v1"` as three little-endian lanes (zero-padded).
pub(crate) fn fee_domain_lanes() -> [u64; 3] {
    let mut b = [0u8; 24];
    b[..21].copy_from_slice(b"qumbra:l2-claimfee:v1");
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes")))
}

pub(crate) fn fee_rho(prev: &Digest) -> Digest {
    keccak_f(&fee_seed_state(prev, 1))[..4].try_into().expect("four lanes")
}
pub(crate) fn fee_rseed(prev: &Digest) -> Digest {
    keccak_f(&fee_seed_state(prev, 2))[..4].try_into().expect("four lanes")
}

/// The fee note's commitment: an asset-0 L2 note (`qlab_air::l2::l2_cm`).
pub(crate) fn fee_note_cm(value: u64, rkm_seq: &Digest, prev: &Digest) -> Digest {
    l2_cm(value, 0, rkm_seq, &fee_rho(prev), &fee_rseed(prev))
}

/// The wrapper's L2 state: F3's three trees and SD, plus `K` and `AA`.
#[derive(Clone)]
pub(crate) struct WState {
    pub l2: L2State,
    pub k: IndexedTree,
    pub aa: CommitmentTree,
}

impl WState {
    pub(crate) fn genesis(registry: &[RegistryLeaf]) -> Self {
        WState { l2: L2State::genesis(registry), k: IndexedTree::genesis(), aa: CommitmentTree::new() }
    }

    pub(crate) fn roots(&self) -> WRoots {
        WRoots { f3: self.l2.roots(), k: self.k.root(), k_next: self.k.next_index(), aa: self.aa.root(), aa_next: self.aa.len() }
    }

    /// Apply one wrapper leaf: absorb, the slots in order, the fee note.
    /// Returns `(roots in, witnesses, roots out)`; on error the state is
    /// left as it was.
    pub(crate) fn apply(&mut self, inp: &WInputs, members: &[Member]) -> Result<(WRoots, WWitness, WRoots), WError> {
        if members.iter().filter(|m| m.tag == WTag::R).count() > 1 {
            return Err(WError::Capacity);
        }
        let before = self.clone();
        let rin = self.roots();
        let r = (|| {
            let absorbs = core::array::from_fn(|i| append(&mut self.aa, &inp.absorbed[i]));
            let mut slots = Vec::new();
            let mut fee = 0u64;
            for m in members {
                match m.as_tx() {
                    Some(tx) => slots.push(SlotWitness::Tx(self.l2.apply_tx(&tx).map_err(WError::Tx)?)),
                    None => {
                        if m.pvs.len() != WTag::C.pv_len() {
                            return Err(WError::Surface);
                        }
                        let cnf = m.digest_at(qlab_air::claim::PV_CNF)?;
                        let cm2 = m.digest_at(qlab_air::claim::PV_CM2)?;
                        let a = m.digest_at(qlab_air::claim::PV_A)?;
                        let anchor_index = (0..self.aa.len()).find(|i| self.aa.leaf(*i) == a).ok_or(WError::Anchor)?;
                        let anchor_path = self.aa.auth_path(anchor_index, self.aa.len());
                        let insert = self.k.insert(&cnf).map_err(WError::Cnf)?;
                        let app = append(&mut self.l2.c, &cm2);
                        fee = fee.checked_add(m.fee()?).ok_or(WError::FeeOverflow)?;
                        self.l2.sd = sd_chain_byte(&self.l2.sd, CLAIM_TAG, &m.pvs).1;
                        slots.push(SlotWitness::Claim(ClaimWitness { insert, append: app, anchor_index, anchor_path }));
                    }
                }
            }
            let fee_w = append(&mut self.l2.c, &fee_note_cm(fee, &inp.rkm_seq, &inp.prev));
            Ok(WWitness { absorbs, slots, fee: fee_w })
        })();
        match r {
            Ok(w) => {
                let rout = self.roots();
                assert_eq!(check_wrapper_leaf(&rin, inp, members, &w), Ok(rout), "the reference and its check agree");
                Ok((rin, w, rout))
            }
            Err(e) => {
                *self = before;
                Err(e)
            }
        }
    }
}

/// Fold `leaf` along `path`.
fn fold(path: &MerkleWitness, leaf: &Digest) -> Digest {
    path.fold_root(leaf)
}

fn bits_ok(path: &MerkleWitness, index: u64) -> bool {
    index < INDEX_CAP && (0..MERKLE_DEPTH).all(|i| path.path_bits[i] == ((index >> i) & 1 == 1))
}

/// **The wrapper leaf's statement, natively.** From `rin`: absorb the
/// [`M_ABS`] roots into `AA`; thread every member in order (a transaction by
/// F3's `check_leaf`, a claim by its `cnf` insert into `K`, its `cm2` append
/// to `C`, its anchor's membership in `AA`, and its SD step under
/// [`CLAIM_TAG`]); append the fee note `cm(Σ fee, rkm_seq, ρ(prev),
/// rseed(prev))` to `C`. The W AIR proves exactly this.
pub(crate) fn check_wrapper_leaf(rin: &WRoots, inp: &WInputs, members: &[Member], w: &WWitness) -> Result<WRoots, WError> {
    if members.len() != w.slots.len() {
        return Err(WError::Shape);
    }
    if members.iter().filter(|m| m.tag == WTag::R).count() > 1 {
        return Err(WError::Capacity);
    }
    let mut s = *rin;
    for (root, a) in inp.absorbed.iter().zip(&w.absorbs) {
        (s.aa, s.aa_next) = apply_append(&s.aa, s.aa_next, root, a).map_err(WError::Append)?;
    }
    let mut fee = 0u64;
    for (m, sw) in members.iter().zip(&w.slots) {
        match (m.as_tx(), sw) {
            (Some(tx), SlotWitness::Tx(tw)) => {
                s.f3 = crate::f3::native::check_leaf(&s.f3, std::slice::from_ref(&tx), std::slice::from_ref(tw)).map_err(WError::Tx)?;
            }
            (None, SlotWitness::Claim(cw)) => {
                if m.pvs.len() != WTag::C.pv_len() {
                    return Err(WError::Surface);
                }
                let (cnf, cm2, a) = (
                    m.digest_at(qlab_air::claim::PV_CNF)?,
                    m.digest_at(qlab_air::claim::PV_CM2)?,
                    m.digest_at(qlab_air::claim::PV_A)?,
                );
                if a == EMPTY || !bits_ok(&cw.anchor_path, cw.anchor_index) || fold(&cw.anchor_path, &a) != s.aa {
                    return Err(WError::Anchor);
                }
                if cw.insert.key != cnf {
                    return Err(WError::Shape);
                }
                (s.k, s.k_next) = apply_insert(&s.k, s.k_next, &cw.insert).map_err(WError::Cnf)?;
                (s.f3.c, s.f3.c_next) = apply_append(&s.f3.c, s.f3.c_next, &cm2, &cw.append).map_err(WError::Append)?;
                fee = fee.checked_add(m.fee()?).ok_or(WError::FeeOverflow)?;
                s.f3.sd = sd_chain_byte(&s.f3.sd, CLAIM_TAG, &m.pvs).1;
            }
            _ => return Err(WError::Shape),
        }
    }
    let cm_fee = fee_note_cm(fee, &inp.rkm_seq, &inp.prev);
    (s.f3.c, s.f3.c_next) = apply_append(&s.f3.c, s.f3.c_next, &cm_fee, &w.fee).map_err(WError::Append)?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A synthetic claim surface anchored at `a`: fresh `cnf`, `Cv`, `cm2`, the
/// burn address, and `fee` (four chunks). Range, not semantics, is what W
/// reads; a real claim proof binds these (F1).
pub(crate) fn synth_claim(rng: &mut crate::f3::native::Rng, a: &Digest, fee: u64) -> Member {
    use qlab_air::claim::{PV_A, PV_CM2, PV_CNF, PV_CV, PV_FEE, PV_LEN, PV_RKM_BURN};
    let mut pvs = vec![0u32; PV_LEN];
    for (off, d) in [(PV_A, *a), (PV_CNF, rng.digest()), (PV_CV, rng.digest()), (PV_CM2, rng.digest()), (PV_RKM_BURN, rng.digest())] {
        pvs[off..off + 16].copy_from_slice(&pv_chunks(&d));
    }
    for j in 0..4 {
        pvs[PV_FEE + j] = ((fee >> (16 * j)) & 0xffff) as u32;
    }
    Member { tag: WTag::C, pvs, write: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f3::native::{synth_tx, Rng};

    fn fresh() -> (WState, Rng, WInputs) {
        let mut rng = Rng(0x775_f4f4_0001);
        let inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()) };
        (WState::genesis(&[RegistryLeaf::cloaked(0)]), rng, inp)
    }

    /// A mixed sequence threads, and the fee note carries Σ fee.
    #[test]
    fn f4_wrapper_leaf_threads_claims_and_the_fee_note() {
        let (mut s, mut rng, inp) = fresh();
        let rr = s.l2.r.root();
        let members = vec![
            Member::tx(&synth_tx(&mut rng, L2ShapeTag::P, &rr)),
            synth_claim(&mut rng, &inp.absorbed[1], 7),
            synth_claim(&mut rng, &inp.absorbed[3], 1 << 40),
            Member::tx(&synth_tx(&mut rng, L2ShapeTag::S, &rr)),
        ];
        let (rin, w, rout) = s.apply(&inp, &members).unwrap();
        assert_eq!(check_wrapper_leaf(&rin, &inp, &members, &w), Ok(rout));
        assert_eq!(rout.aa_next, rin.aa_next + M_ABS as u64);
        assert_eq!(rout.k_next, rin.k_next + 2, "one cnf per claim");
        assert_eq!(rout.f3.n_next, rin.f3.n_next + 6, "3 per S/P");
        assert_eq!(rout.f3.c_next, rin.f3.c_next + 2 + 2 + 2 + 1, "S/P 2 each, a claim 1, the fee note 1");
        // The fee note is the last leaf of C, with value Σ fee.
        assert_eq!(s.l2.c.leaf(rout.f3.c_next - 1), fee_note_cm(7 + (1 << 40), &inp.rkm_seq, &inp.prev));
    }

    /// Condition (e): the fee note is appended in every wrapper — with no
    /// claims its value is 0, and C's root is the one that note folds to.
    #[test]
    fn f4_fee_note_every_wrapper_and_its_value() {
        let (mut s, mut rng, inp) = fresh();
        let rr = s.l2.r.root();
        let members = vec![Member::tx(&synth_tx(&mut rng, L2ShapeTag::S, &rr))];
        let (_, w, rout) = s.apply(&inp, &members).unwrap();
        assert_eq!(s.l2.c.leaf(rout.f3.c_next - 1), fee_note_cm(0, &inp.rkm_seq, &inp.prev));
        assert_eq!(w.fee.path.fold_root(&fee_note_cm(0, &inp.rkm_seq, &inp.prev)), rout.f3.c);
        assert_ne!(w.fee.path.fold_root(&fee_note_cm(1, &inp.rkm_seq, &inp.prev)), rout.f3.c, "a nonzero note with no claims");
    }

    /// A claim double-spend across wrappers and inside one wrapper: the second
    /// `cnf` has no gap in K.
    #[test]
    fn f4_neg_double_claim() {
        let (mut s, mut rng, inp) = fresh();
        let c1 = synth_claim(&mut rng, &inp.absorbed[0], 1);
        s.apply(&inp, std::slice::from_ref(&c1)).unwrap();
        let mut again = c1.clone();
        again.pvs[qlab_air::claim::PV_CM2] ^= 1;
        let inp2 = WInputs { prev: rng.digest(), ..inp.clone() };
        assert_eq!(s.clone().apply(&inp2, &[again.clone()]).unwrap_err(), WError::Cnf(NfError::NotInGap));
        let (mut t, mut rng2, inp3) = fresh();
        let d = synth_claim(&mut rng2, &inp3.absorbed[0], 1);
        assert_eq!(t.apply(&inp3, &[d.clone(), d]).unwrap_err(), WError::Cnf(NfError::NotInGap));
    }

    /// A claim anchored at a root never absorbed, or at zero.
    #[test]
    fn f4_neg_claim_anchor() {
        let (mut s, mut rng, inp) = fresh();
        let stray = rng.digest();
        assert_eq!(s.clone().apply(&inp, &[synth_claim(&mut rng, &stray, 1)]).unwrap_err(), WError::Anchor);
        assert_eq!(s.apply(&inp, &[synth_claim(&mut rng, &EMPTY, 1)]).unwrap_err(), WError::Anchor);
    }

    /// The fee note's ρ and rseed are distinct, domain-separated, and move
    /// with `prev`; two wrappers share a ρ only if they share `prev`.
    #[test]
    fn f4_fee_seeds() {
        let mut rng = Rng(9);
        let (p, q) = (rng.digest(), rng.digest());
        assert_ne!(fee_rho(&p), fee_rseed(&p));
        assert_ne!(fee_rho(&p), fee_rho(&q));
        assert_eq!(fee_domain_lanes()[0].to_le_bytes(), *b"qumbra:l");
        let st = fee_seed_state(&p, 1);
        assert!(st[17..21].iter().all(|l| *l == 0) && st[21] != 0, "capacity lanes 21..24 carry the domain");
    }
}
