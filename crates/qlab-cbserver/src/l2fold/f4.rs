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
//! Q8). `AA` grows only by these, so `aa_next ≡ 0 (mod 4)` always: the four
//! are one aligned depth-2 subtree, which W proves with a single path. That they are genuine recent finalized L1 roots is the enshrined
//! rule's check (F5), stubbed in [`super::verify`].
//!
//! **The sequencer fee note (ruling condition (e), option 1).** After its
//! slots, every wrapper appends ONE asset-0 note — value `F_batch = Σ fee`
//! over its claims (0 with none), recipient the public `rkm_seq`,
//! `ρ` and `rseed` two Keccak-f calls over `prev` under the one domain
//! `"qumbra:l2-claimfee:v1"`, told apart by a kind lane (1 = ρ, 2 = rseed;
//! [`fee_seed_state`]).
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
//! **F4-2: CH, the supply vector, D/E and exits.**
//!
//! - **CH, the C-root history (ruling Q4: per wrapper).** Each wrapper's
//!   prologue appends its `C_in` — the predecessor's `C_out` — to `CH`
//!   before any slot runs; every transaction's `anchor` (PV 0) must open in
//!   that post-prologue `CH`. So a note appended in wrapper n is spendable
//!   from wrapper n + 1 and **never earlier** (a wallet-visible latency: the
//!   wrapper that appends a note must land first). A claim's anchor opens in
//!   `AA` instead; the two are never interchangeable.
//! - **The supply vector (`supply_cmt`, §6.4).** A depth-[`SUPPLY_DEPTH`]
//!   tree over asset ids whose every leaf exists from genesis as
//!   `H(asset ‖ outstanding)` ([`supply_leaf_state`]) — so an update always
//!   opens a real old leaf. **Asset ids are < 2^16** (the P circuit's `vpa`
//!   is a 32-bit PV; W refuses a `vPublic` row whose id is ≥ 2^16). The
//!   65,536-leaf width is a **devnet placeholder**, revisited at the shape
//!   freeze with the registry's asset-id width. Each P `vPublic` row
//!   `(s, m, vpa)` sets `outstanding ± m` (u64; overflow and underflow
//!   refused); `m = 0` changes nothing.
//! - **Asset 0 (bridged qQMB)** never moves the supply tree (its supply is
//!   the public `D_cum − E_cum`): a `vPublic` **redeem on asset 0 is an
//!   exit** (it lands in `E` and in the exit list), and a `vPublic` **mint
//!   on asset 0 is refused**.
//! - **D/E.** `D_cum += D_batch` (a W public value the deposit-sum proof
//!   binds, F4-3) and `E_cum += Σ exits`, both u64 with overflow refused;
//!   `E_cum ≤ D_cum` is `verify_wrapper`'s public check.
//! - **The exit list (`exit_cmt`, Q3 = (c)).** An MD chain from zero over the
//!   batch's exits `(rkm, v)`, in slot order ([`exit_state`]). An exit is a
//!   P row's `e_k` — a redeem of asset 0 of a **nonzero** amount (a
//!   zero-amount redeem chains nothing) — and its `rkm` is the member's
//!   `PV_XRKM`, one recipient per transaction (lab #785 F5-4d), which W
//!   captures and binds; every P member's recipient words must be 16-bit.
//!
//! **Limits:** every append structure (`N`, `C`, `K`, `AA`, `CH`) stops at
//! [`INDEX_CAP`] = 2^30 (inherited, Larry 2026-09-29).
// The W AIR is this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use qlab_air::l2::{RegistryLeaf, RegistryWitness};
// Lab #860 R1: `pv_chunks` is the fixtures' and tests' (they stayed in qlab-wprover).
#[allow(unused_imports)]
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
use crate::tree::CommitmentTree;
use qlab_devnet::annulet::L2ShapeTag;

use super::f3::{
    append, apply_append, apply_insert, sd_chain_byte, AppendError, AppendWitness, Digest, IndexedTree, InsertWitness,
    L2State, NfError, StError, TxSurface, TxWitness, EMPTY, INDEX_CAP,
};

// Lab #785 F5-1: the wrapper-state types and domain-tagged states moved to qlab-wrapper.
#[cfg_attr(not(test), allow(unused_imports))]
pub use qlab_wrapper::hash::{
    exit_state, fee_domain_lanes, fee_rho, fee_rseed, fee_seed_state, h4,
    supply_leaf_state, WRoots, WTag, CLAIM_TAG, M_ABS, SUPPLY_DEPTH,
};

/// The fee note's commitment: an asset-0 L2 note (`qlab_air::l2::l2_cm`).
/// Back from qlab-wrapper (lab #785 F5-4a, review Y2): only the prover uses it.
pub fn fee_note_cm(value: u64, rkm_seq: &Digest, prev: &Digest) -> Digest {
    qlab_air::l2::l2_cm(value, 0, rkm_seq, &fee_rho(prev), &fee_rseed(prev))
}

/// The `WTag` ↔ `L2ShapeTag` conversion, kept on this side so qlab-wrapper
/// carries no qlab-devnet edge (lab #785 review Y1). `WTag::byte` writes the
/// shape bytes out; `wtag_bytes_are_the_shape_tags` pins them equal.
pub trait WTagShape {
    fn shape(self) -> Option<L2ShapeTag>;
}

impl WTagShape for WTag {
    fn shape(self) -> Option<L2ShapeTag> {
        match self {
            WTag::S => Some(L2ShapeTag::S),
            WTag::P => Some(L2ShapeTag::P),
            WTag::R => Some(L2ShapeTag::R),
            WTag::C => None,
        }
    }
}

/// [`WTag`] of an L2 transaction shape (was `WTag::of`).
pub fn wtag_of(tag: L2ShapeTag) -> WTag {
    match tag {
        L2ShapeTag::S => WTag::S,
        L2ShapeTag::P => WTag::P,
        L2ShapeTag::R => WTag::R,
    }
}

/// One member of the sequence: its tag and full public-value vector (and an
/// R write's leaf, as F3).
#[derive(Clone, Debug)]
pub struct Member {
    pub tag: WTag,
    pub pvs: Vec<u32>,
    pub write: Option<RegistryLeaf>,
}

impl Member {
    pub fn tx(t: &TxSurface) -> Self {
        Member { tag: wtag_of(t.tag), pvs: t.pvs.clone(), write: t.write }
    }
    fn as_tx(&self) -> Option<TxSurface> {
        self.tag.shape().map(|tag| TxSurface { tag, pvs: self.pvs.clone(), write: self.write })
    }
    pub fn digest_at(&self, off: usize) -> Result<Digest, WError> {
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
pub enum WError {
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
    /// A transaction anchor that does not open in `CH`, or is zero.
    TxAnchor,
    /// A `vPublic` row: asset id ≥ 2^16, a sign not 0/1, supply overflow or
    /// underflow.
    Supply,
    /// A `vPublic` mint on asset 0.
    AssetZeroMint,
    /// `D_cum` or `E_cum` overflows u64.
    Counter,
    /// `aa_next` not a multiple of [`M_ABS`]: the absorbed roots are one
    /// aligned subtree of `AA` (F4-3's absorb).
    AbsAlign,
}

/// A claim slot's witnesses.
#[derive(Clone, Copy)]
pub struct ClaimWitness {
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
pub enum SlotWitness {
    Tx(TxWitness),
    Claim(ClaimWitness),
}

/// A wrapper leaf's public inputs besides the members.
#[derive(Clone, Debug)]
pub struct WInputs {
    /// The predecessor's surface commitment.
    pub prev: Digest,
    /// The sequencer's raw recipient key (the fee note's `rkm`).
    pub rkm_seq: Digest,
    /// The L1 roots this wrapper absorbs.
    pub absorbed: [Digest; M_ABS],
    /// The batch's deposit total (the deposit-sum proof binds it, F4-3).
    pub d_batch: u64,
}

/// One P `vPublic` row's witness: the asset's outstanding before and its
/// opening in the supply tree. An exit's `rkm` is no witness (lab #785
/// F5-4d-2): it is the member's `PV_XRKM`, which W captures.
#[derive(Clone, Copy)]
pub struct VpWitness {
    pub old_out: u64,
    pub path: RegistryWitness,
}

/// A slot's F4-2 witnesses: a transaction's anchor opening in `CH` (unused
/// for a claim) and its two `vPublic` rows (P only).
#[derive(Clone, Copy)]
pub struct SlotExtra {
    pub anchor_index: u64,
    pub anchor_path: MerkleWitness,
    pub vp: [VpWitness; 2],
}

/// A wrapper leaf's witnesses, in [`check_wrapper_leaf`]'s order.
#[derive(Clone)]
pub struct WWitness {
    pub absorbs: [AppendWitness; M_ABS],
    /// `C_in`'s append to `CH`.
    pub hist: AppendWitness,
    pub slots: Vec<SlotWitness>,
    pub extra: Vec<SlotExtra>,
    pub fee: AppendWitness,
}

/// The supply tree: every asset's outstanding, every level materialized.
#[derive(Clone)]
pub struct SupplyTree {
    out: Vec<u64>,
    levels: Vec<Vec<Digest>>,
}

impl SupplyTree {
    /// Every leaf `H(asset ‖ 0)`; computed once and cached.
    pub fn genesis() -> Self {
        static G: std::sync::OnceLock<SupplyTree> = std::sync::OnceLock::new();
        G.get_or_init(|| {
            let n = 1usize << SUPPLY_DEPTH;
            let mut levels = vec![(0..n as u64).map(|a| h4(&supply_leaf_state(a, 0))).collect::<Vec<Digest>>()];
            for l in 0..SUPPLY_DEPTH {
                let below = &levels[l];
                let up = (0..below.len() / 2).map(|i| super::f3::node_pub(&below[2 * i], &below[2 * i + 1])).collect();
                levels.push(up);
            }
            SupplyTree { out: vec![0; n], levels }
        })
        .clone()
    }
    pub fn root(&self) -> Digest {
        self.levels[SUPPLY_DEPTH][0]
    }
    pub fn outstanding(&self, asset: u64) -> u64 {
        self.out[asset as usize]
    }
    pub fn path(&self, asset: u64) -> RegistryWitness {
        let mut siblings = [[0u64; 4]; SUPPLY_DEPTH];
        let mut path_bits = [false; SUPPLY_DEPTH];
        for l in 0..SUPPLY_DEPTH {
            let i = (asset >> l) as usize;
            siblings[l] = self.levels[l][i ^ 1];
            path_bits[l] = i & 1 == 1;
        }
        RegistryWitness { siblings, path_bits }
    }
    pub fn set(&mut self, asset: u64, out: u64) {
        self.out[asset as usize] = out;
        let mut d = h4(&supply_leaf_state(asset, out));
        let mut i = asset as usize;
        self.levels[0][i] = d;
        for l in 0..SUPPLY_DEPTH {
            let sib = self.levels[l][i ^ 1];
            d = if i & 1 == 1 { super::f3::node_pub(&sib, &d) } else { super::f3::node_pub(&d, &sib) };
            i >>= 1;
            self.levels[l + 1][i] = d;
        }
    }
}

/// A P row's `(s, m, vpa)`. Total: a word past a short vector reads 0 (the
/// native checks refuse a P member of the wrong length first; the plan
/// generator renders whatever it is given).
pub fn vp_row(pvs: &[u32], k: usize) -> (u32, u64, u32) {
    let base = qlab_air::l2p::PV_VP1 + 6 * k;
    let at = |i: usize| pvs.get(i).copied().unwrap_or(0);
    let m = (0..4).map(|j| u64::from(at(base + 1 + j) & 0xffff) << (16 * j)).sum();
    (at(base), m, at(base + 5))
}

/// The wrapper's L2 state: F3's three trees and SD, plus `K`, `AA`, `CH`, the
/// supply tree and the two counters.
#[derive(Clone)]
pub struct WState {
    pub l2: L2State,
    pub k: IndexedTree,
    pub aa: CommitmentTree,
    pub ch: CommitmentTree,
    pub sup: SupplyTree,
    pub d_cum: u64,
    pub e_cum: u64,
}

impl WState {
    pub fn genesis(registry: &[RegistryLeaf]) -> Self {
        WState {
            l2: L2State::genesis(registry),
            k: IndexedTree::genesis(),
            aa: CommitmentTree::new(),
            ch: CommitmentTree::new(),
            sup: SupplyTree::genesis(),
            d_cum: 0,
            e_cum: 0,
        }
    }

    pub fn roots(&self) -> WRoots {
        WRoots {
            f3: self.l2.roots(),
            k: self.k.root(),
            k_next: self.k.next_index(),
            aa: self.aa.root(),
            aa_next: self.aa.len(),
            ch: self.ch.root(),
            ch_next: self.ch.len(),
            sup: self.sup.root(),
            d_cum: self.d_cum,
            e_cum: self.e_cum,
        }
    }

    /// Apply one wrapper leaf: absorb, the slots in order, the fee note.
    /// Returns `(roots in, witnesses, roots out)`; on error the state is
    /// left as it was.
    ///
    /// **The sequencer prefilters with this** (review S8): a member whose own
    /// proof verifies can still make W unsatisfiable — a P row with `m = 0`
    /// and `vpa ≥ 2^16`, or a `vPublic` mint on asset 0 — and this refuses
    /// exactly those, so a batch it accepts is one W can prove.
    pub fn apply(&mut self, inp: &WInputs, members: &[Member]) -> Result<(WRoots, WWitness, WRoots), WError> {
        if members.iter().filter(|m| m.tag == WTag::R).count() > 1 {
            return Err(WError::Capacity);
        }
        if !self.aa.len().is_multiple_of(M_ABS as u64) {
            return Err(WError::AbsAlign);
        }
        let before = self.clone();
        let rin = self.roots();
        let r = (|| {
            let absorbs = core::array::from_fn(|i| append(&mut self.aa, &inp.absorbed[i]));
            let c_in = self.l2.c.root();
            let hist = append(&mut self.ch, &c_in);
            let mut slots = Vec::new();
            let mut extra = Vec::new();
            let mut fee = 0u64;
            let mut e_batch = 0u64;
            for m in members {
                let mut ex = SlotExtra { anchor_index: 0, anchor_path: self.ch.auth_path(0, self.ch.len()), vp: [VpWitness { old_out: 0, path: self.sup.path(0) }; 2] };
                if m.tag != WTag::C {
                    let a = m.digest_at(0)?;
                    if a == EMPTY {
                        return Err(WError::TxAnchor);
                    }
                    ex.anchor_index = (0..self.ch.len()).find(|i| self.ch.leaf(*i) == a).ok_or(WError::TxAnchor)?;
                    ex.anchor_path = self.ch.auth_path(ex.anchor_index, self.ch.len());
                }
                if m.tag == WTag::P {
                    if m.pvs.len() != WTag::P.pv_len() {
                        return Err(WError::Surface);
                    }
                    m.digest_at(qlab_air::l2p::PV_XRKM)?;
                    for k in 0..2 {
                        let (sgn, amt, vpa) = vp_row(&m.pvs, k);
                        if sgn > 1 || vpa >= 1 << SUPPLY_DEPTH {
                            return Err(WError::Supply);
                        }
                        let a = if vpa == 0 { 0 } else { u64::from(vpa) };
                        let old = self.sup.outstanding(a);
                        ex.vp[k] = VpWitness { old_out: old, path: self.sup.path(a) };
                        if vpa == 0 {
                            if sgn == 0 && amt != 0 {
                                return Err(WError::AssetZeroMint);
                            }
                            if sgn == 1 {
                                e_batch = e_batch.checked_add(amt).ok_or(WError::Counter)?;
                            }
                        } else {
                            let new = if sgn == 0 { old.checked_add(amt) } else { old.checked_sub(amt) }.ok_or(WError::Supply)?;
                            self.sup.set(a, new);
                        }
                    }
                }
                extra.push(ex);
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
            self.d_cum = self.d_cum.checked_add(inp.d_batch).ok_or(WError::Counter)?;
            self.e_cum = self.e_cum.checked_add(e_batch).ok_or(WError::Counter)?;
            Ok(WWitness { absorbs, hist, slots, extra, fee: fee_w })
        })();
        match r {
            Ok(w) => {
                let rout = self.roots();
                assert_eq!(check_wrapper_leaf(&rin, inp, members, &w).map(|r| r.0), Ok(rout), "the reference and its check agree");
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

/// The **test fixtures'** exit recipient: an arbitrary deterministic nonzero
/// value (the member's `cm1` chunks, low lane forced odd), written into P's
/// `PV_XRKM` by [`tx_member`] when a row exits. Since lab #785 F5-4d-2 the
/// recipient is the P proof's public value, one per transaction, and W binds
/// its exit steps to it; nothing here is a free witness any more.
pub fn fixture_xrkm(pvs: &[u32]) -> Digest {
    let off = qlab_air::l2::PV_CM1;
    let mut d: Digest = core::array::from_fn(|l| (0..4).map(|j| u64::from(pvs.get(off + 4 * l + j).copied().unwrap_or(0) & 0xffff) << (16 * j)).sum::<u64>());
    d[0] |= 1;
    d
}

/// Whether P row `(sgn, amt, vpa)` is an exit: P's `e_k` — a redeem of
/// asset 0 of a nonzero amount (lab #785 F5-4d).
pub fn is_exit(sgn: u32, amt: u64, vpa: u32) -> bool {
    sgn == 1 && vpa == 0 && amt != 0
}

/// **The wrapper leaf's statement, natively.** From `rin`: absorb the
/// [`M_ABS`] roots into `AA`; append `C_in` to `CH`; thread every member in
/// order — a transaction by F3's `check_leaf`, its anchor's membership in
/// `CH`, and (P) its two `vPublic` rows against the supply tree or the exit
/// list; a claim by its `cnf` insert into `K`, its `cm2` append to `C`, its
/// anchor's membership in `AA`, its SD step under [`CLAIM_TAG`]; append the
/// fee note to `C`; add `D_batch` to `D_cum` and the exits to `E_cum`.
/// Returns the roots out and the batch's `exit_cmt`. The W AIR proves exactly
/// this.
pub fn check_wrapper_leaf(rin: &WRoots, inp: &WInputs, members: &[Member], w: &WWitness) -> Result<(WRoots, Digest), WError> {
    if members.len() != w.slots.len() || members.len() != w.extra.len() {
        return Err(WError::Shape);
    }
    if members.iter().filter(|m| m.tag == WTag::R).count() > 1 {
        return Err(WError::Capacity);
    }
    let mut s = *rin;
    if !s.aa_next.is_multiple_of(M_ABS as u64) {
        return Err(WError::AbsAlign);
    }
    for (root, a) in inp.absorbed.iter().zip(&w.absorbs) {
        (s.aa, s.aa_next) = apply_append(&s.aa, s.aa_next, root, a).map_err(WError::Append)?;
    }
    (s.ch, s.ch_next) = apply_append(&s.ch, s.ch_next, &s.f3.c, &w.hist).map_err(WError::Append)?;
    let (mut fee, mut e_batch, mut exc) = (0u64, 0u64, EMPTY);
    for ((m, sw), ex) in members.iter().zip(&w.slots).zip(&w.extra) {
        if m.tag != WTag::C {
            let a = m.digest_at(0)?;
            if a == EMPTY || !bits_ok(&ex.anchor_path, ex.anchor_index) || fold(&ex.anchor_path, &a) != s.ch {
                return Err(WError::TxAnchor);
            }
        }
        if m.tag == WTag::P {
            if m.pvs.len() != WTag::P.pv_len() {
                return Err(WError::Surface);
            }
            // V5 (lab #785 F5-4d-2): the recipient's words are 16-bit on every
            // P member, as W's capture forces — never more permissive than the
            // circuit.
            m.digest_at(qlab_air::l2p::PV_XRKM)?;
            for (k, vw) in ex.vp.iter().enumerate() {
                let (sgn, amt, vpa) = vp_row(&m.pvs, k);
                if sgn > 1 || vpa >= 1 << SUPPLY_DEPTH {
                    return Err(WError::Supply);
                }
                let a = u64::from(vpa);
                let bits: Vec<bool> = (0..SUPPLY_DEPTH).map(|i| (a >> i) & 1 == 1).collect();
                if vw.path.path_bits.to_vec() != bits || vw.path.fold_root(&h4(&supply_leaf_state(a, vw.old_out))) != s.sup {
                    return Err(WError::Supply);
                }
                let new = if vpa == 0 {
                    if sgn == 0 && amt != 0 {
                        return Err(WError::AssetZeroMint);
                    }
                    if is_exit(sgn, amt, vpa) {
                        e_batch = e_batch.checked_add(amt).ok_or(WError::Counter)?;
                        exc = h4(&exit_state(&exc, &m.digest_at(qlab_air::l2p::PV_XRKM)?, amt));
                    }
                    vw.old_out
                } else if sgn == 0 {
                    vw.old_out.checked_add(amt).ok_or(WError::Supply)?
                } else {
                    vw.old_out.checked_sub(amt).ok_or(WError::Supply)?
                };
                s.sup = vw.path.fold_root(&h4(&supply_leaf_state(a, new)));
            }
        }
        match (m.as_tx(), sw) {
            (Some(tx), SlotWitness::Tx(tw)) => {
                s.f3 = super::f3::check_leaf(&s.f3, std::slice::from_ref(&tx), std::slice::from_ref(tw)).map_err(WError::Tx)?;
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
    s.d_cum = s.d_cum.checked_add(inp.d_batch).ok_or(WError::Counter)?;
    s.e_cum = s.e_cum.checked_add(e_batch).ok_or(WError::Counter)?;
    Ok((s, exc))
}
