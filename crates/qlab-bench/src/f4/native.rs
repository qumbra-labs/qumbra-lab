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
//!   batch's exits `(rkm, v)`, in slot order ([`exit_state`]). **`rkm` is a
//!   stub:** L2 transactions carry no L1 recipient yet (Larry's Q3, decided
//!   at the shape freeze), so it is a witness bound to nothing but the chain.
//!
//! **Limits:** every append structure (`N`, `C`, `K`, `AA`, `CH`) stops at
//! [`INDEX_CAP`] = 2^30 (inherited, Larry 2026-09-29).
// The W AIR is this module's non-test consumer.
#![cfg_attr(not(test), allow(dead_code))]
use qlab_air::l2::{RegistryLeaf, RegistryWitness};
use qlab_air::narrow::{pv_chunks, MerkleWitness, MERKLE_DEPTH};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::L2ShapeTag;

use crate::f3::native::{
    append, apply_append, apply_insert, sd_chain_byte, AppendError, AppendWitness, Digest, IndexedTree, InsertWitness,
    L2State, NfError, StError, TxSurface, TxWitness, EMPTY, INDEX_CAP,
};

// Lab #785 F5-1: the wrapper-state types and domain-tagged states moved to qlab-wrapper.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use qlab_wrapper::hash::{
    exit_state, fee_domain_lanes, fee_rho, fee_rseed, fee_seed_state, h4,
    supply_leaf_state, WRoots, WTag, CLAIM_TAG, M_ABS, SUPPLY_DEPTH,
};

/// The fee note's commitment: an asset-0 L2 note (`qlab_air::l2::l2_cm`).
/// Back from qlab-wrapper (lab #785 F5-4a, review Y2): only the prover uses it.
pub(crate) fn fee_note_cm(value: u64, rkm_seq: &Digest, prev: &Digest) -> Digest {
    qlab_air::l2::l2_cm(value, 0, rkm_seq, &fee_rho(prev), &fee_rseed(prev))
}

/// The `WTag` ↔ `L2ShapeTag` conversion, kept on this side so qlab-wrapper
/// carries no qlab-devnet edge (lab #785 review Y1). `WTag::byte` writes the
/// shape bytes out; `wtag_bytes_are_the_shape_tags` pins them equal.
pub(crate) trait WTagShape {
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
pub(crate) fn wtag_of(tag: L2ShapeTag) -> WTag {
    match tag {
        L2ShapeTag::S => WTag::S,
        L2ShapeTag::P => WTag::P,
        L2ShapeTag::R => WTag::R,
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
        Member { tag: wtag_of(t.tag), pvs: t.pvs.clone(), write: t.write }
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
    /// The batch's deposit total (the deposit-sum proof binds it, F4-3).
    pub d_batch: u64,
}

/// One P `vPublic` row's witness: the asset's outstanding before and its
/// opening in the supply tree. An exit's `rkm` is no witness (lab #785
/// F5-4d-2): it is the member's `PV_XRKM`, which W captures.
#[derive(Clone, Copy)]
pub(crate) struct VpWitness {
    pub old_out: u64,
    pub path: RegistryWitness,
}

/// A slot's F4-2 witnesses: a transaction's anchor opening in `CH` (unused
/// for a claim) and its two `vPublic` rows (P only).
#[derive(Clone, Copy)]
pub(crate) struct SlotExtra {
    pub anchor_index: u64,
    pub anchor_path: MerkleWitness,
    pub vp: [VpWitness; 2],
}

/// A wrapper leaf's witnesses, in [`check_wrapper_leaf`]'s order.
#[derive(Clone)]
pub(crate) struct WWitness {
    pub absorbs: [AppendWitness; M_ABS],
    /// `C_in`'s append to `CH`.
    pub hist: AppendWitness,
    pub slots: Vec<SlotWitness>,
    pub extra: Vec<SlotExtra>,
    pub fee: AppendWitness,
}

/// The supply tree: every asset's outstanding, every level materialized.
#[derive(Clone)]
pub(crate) struct SupplyTree {
    out: Vec<u64>,
    levels: Vec<Vec<Digest>>,
}

impl SupplyTree {
    /// Every leaf `H(asset ‖ 0)`; computed once and cached.
    pub(crate) fn genesis() -> Self {
        static G: std::sync::OnceLock<SupplyTree> = std::sync::OnceLock::new();
        G.get_or_init(|| {
            let n = 1usize << SUPPLY_DEPTH;
            let mut levels = vec![(0..n as u64).map(|a| h4(&supply_leaf_state(a, 0))).collect::<Vec<Digest>>()];
            for l in 0..SUPPLY_DEPTH {
                let below = &levels[l];
                let up = (0..below.len() / 2).map(|i| crate::f3::native::node_pub(&below[2 * i], &below[2 * i + 1])).collect();
                levels.push(up);
            }
            SupplyTree { out: vec![0; n], levels }
        })
        .clone()
    }
    pub(crate) fn root(&self) -> Digest {
        self.levels[SUPPLY_DEPTH][0]
    }
    pub(crate) fn outstanding(&self, asset: u64) -> u64 {
        self.out[asset as usize]
    }
    pub(crate) fn path(&self, asset: u64) -> RegistryWitness {
        let mut siblings = [[0u64; 4]; SUPPLY_DEPTH];
        let mut path_bits = [false; SUPPLY_DEPTH];
        for l in 0..SUPPLY_DEPTH {
            let i = (asset >> l) as usize;
            siblings[l] = self.levels[l][i ^ 1];
            path_bits[l] = i & 1 == 1;
        }
        RegistryWitness { siblings, path_bits }
    }
    pub(crate) fn set(&mut self, asset: u64, out: u64) {
        self.out[asset as usize] = out;
        let mut d = h4(&supply_leaf_state(asset, out));
        let mut i = asset as usize;
        self.levels[0][i] = d;
        for l in 0..SUPPLY_DEPTH {
            let sib = self.levels[l][i ^ 1];
            d = if i & 1 == 1 { crate::f3::native::node_pub(&sib, &d) } else { crate::f3::native::node_pub(&d, &sib) };
            i >>= 1;
            self.levels[l + 1][i] = d;
        }
    }
}

/// A P row's `(s, m, vpa)`. Total: a word past a short vector reads 0 (the
/// native checks refuse a P member of the wrong length first; the plan
/// generator renders whatever it is given).
pub(crate) fn vp_row(pvs: &[u32], k: usize) -> (u32, u64, u32) {
    let base = qlab_air::l2p::PV_VP1 + 6 * k;
    let at = |i: usize| pvs.get(i).copied().unwrap_or(0);
    let m = (0..4).map(|j| u64::from(at(base + 1 + j) & 0xffff) << (16 * j)).sum();
    (at(base), m, at(base + 5))
}

/// The wrapper's L2 state: F3's three trees and SD, plus `K`, `AA`, `CH`, the
/// supply tree and the two counters.
#[derive(Clone)]
pub(crate) struct WState {
    pub l2: L2State,
    pub k: IndexedTree,
    pub aa: CommitmentTree,
    pub ch: CommitmentTree,
    pub sup: SupplyTree,
    pub d_cum: u64,
    pub e_cum: u64,
}

impl WState {
    pub(crate) fn genesis(registry: &[RegistryLeaf]) -> Self {
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

    pub(crate) fn roots(&self) -> WRoots {
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
    pub(crate) fn apply(&mut self, inp: &WInputs, members: &[Member]) -> Result<(WRoots, WWitness, WRoots), WError> {
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
pub(crate) fn fixture_xrkm(pvs: &[u32]) -> Digest {
    let off = qlab_air::l2::PV_CM1;
    let mut d: Digest = core::array::from_fn(|l| (0..4).map(|j| u64::from(pvs.get(off + 4 * l + j).copied().unwrap_or(0) & 0xffff) << (16 * j)).sum::<u64>());
    d[0] |= 1;
    d
}

/// Whether P row `(sgn, amt, vpa)` is an exit: P's `e_k` — a redeem of
/// asset 0 of a nonzero amount (lab #785 F5-4d).
pub(crate) fn is_exit(sgn: u32, amt: u64, vpa: u32) -> bool {
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
pub(crate) fn check_wrapper_leaf(rin: &WRoots, inp: &WInputs, members: &[Member], w: &WWitness) -> Result<(WRoots, Digest), WError> {
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
    s.d_cum = s.d_cum.checked_add(inp.d_batch).ok_or(WError::Counter)?;
    s.e_cum = s.e_cum.checked_add(e_batch).ok_or(WError::Counter)?;
    Ok((s, exc))
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A synthetic claim surface anchored at `a`: fresh `cnf`, `Cv`, `cm2`, the
/// burn address, and `fee` (four chunks). Range, not semantics, is what W
/// reads; a real claim proof binds these (F1).
pub(crate) fn synth_claim(rng: &mut crate::f3::native::Rng, a: &Digest, fee: u64) -> Member {
    synth_claim_open(rng, a, fee).0
}

/// [`synth_claim`] with its value commitment's opening: `Cv` is
/// `claim_cv(v, r_v)` for a 40-bit `v ≥ fee` (so a deposit proof over the
/// fixture's claims exists).
pub(crate) fn synth_claim_open(rng: &mut crate::f3::native::Rng, a: &Digest, fee: u64) -> (Member, super::dep::DepEntry) {
    use qlab_air::claim::{PV_A, PV_CM2, PV_CNF, PV_CV, PV_FEE, PV_LEN, PV_RKM_BURN};
    let mut pvs = vec![0u32; PV_LEN];
    let cnf = rng.digest();
    let r_v = rng.digest();
    let open = super::dep::DepEntry { v: fee + (r_v[0] >> 24), r_v };
    let cv = qlab_air::claim::claim_cv(open.v, &r_v);
    for (off, d) in [(PV_A, *a), (PV_CNF, cnf), (PV_CV, cv), (PV_CM2, rng.digest()), (PV_RKM_BURN, rng.digest())] {
        pvs[off..off + 16].copy_from_slice(&pv_chunks(&d));
    }
    for j in 0..4 {
        pvs[PV_FEE + j] = ((fee >> (16 * j)) & 0xffff) as u32;
    }
    (Member { tag: WTag::C, pvs, write: None }, open)
}

/// A transaction member valid against a wrapper whose `C_in` is `c_in`: its
/// anchor set to `c_in` (so it opens in `CH`) and, for P, its `vPublic` rows
/// set to `rows` (`(s, m, vpa)` each; `(0, 0, 0)` = no `vPublic`).
pub(crate) fn tx_member(t: &TxSurface, c_in: &Digest, rows: [(u32, u64, u32); 2]) -> Member {
    let mut m = Member::tx(t);
    m.pvs[..16].copy_from_slice(&pv_chunks(c_in));
    if m.tag == WTag::P {
        for (k, (sgn, amt, vpa)) in rows.iter().enumerate() {
            let base = qlab_air::l2p::PV_VP1 + 6 * k;
            m.pvs[base] = *sgn;
            for j in 0..4 {
                m.pvs[base + 1 + j] = ((amt >> (16 * j)) & 0xffff) as u32;
            }
            m.pvs[base + 5] = *vpa;
        }
        // P's canonical recipient (lab #785 F5-4d): nonzero exactly when a
        // row exits.
        let exits = rows.iter().any(|(sgn, amt, vpa)| is_exit(*sgn, *amt, *vpa));
        let xrkm = if exits { pv_chunks(&fixture_xrkm(&m.pvs)) } else { [0; 16] };
        m.pvs[qlab_air::l2p::PV_XRKM..qlab_air::l2p::PV_XRKM + 16].copy_from_slice(&xrkm);
    }
    m
}

/// No `vPublic` on either row.
pub(crate) const NO_VP: [(u32, u64, u32); 2] = [(0, 0, 0); 2];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f3::native::{synth_tx, Rng};

    fn fresh() -> (WState, Rng, WInputs) {
        let mut rng = Rng(0x775_f4f4_0001);
        let inp = WInputs { prev: rng.digest(), rkm_seq: rng.digest(), absorbed: core::array::from_fn(|_| rng.digest()), d_batch: 0 };
        (WState::genesis(&[RegistryLeaf::cloaked(0)]), rng, inp)
    }

    /// Lab #785 review Y1: qlab-wrapper's `WTag::byte` writes the shape
    /// bytes out rather than reading qlab-devnet's `L2ShapeTag`; they must
    /// stay the same bytes, the conversion must round-trip, and the claim
    /// tag must be none of them.
    #[test]
    fn wtag_bytes_are_the_shape_tags() {
        for tag in [L2ShapeTag::S, L2ShapeTag::P, L2ShapeTag::R] {
            let w = wtag_of(tag);
            assert_eq!(w.byte(), tag.byte(), "{tag:?}");
            assert_eq!(w.shape(), Some(tag));
            assert_eq!(L2ShapeTag::from_byte(w.byte()), Some(tag));
        }
        assert_eq!(WTag::C.shape(), None);
        assert_eq!(L2ShapeTag::from_byte(WTag::C.byte()), None, "the claim tag is no shape's byte");
        assert_eq!(WTag::ALL.map(WTag::byte), [0x01, 0x02, 0x03, CLAIM_TAG]);
    }

    /// Lab #785 F5-4a (ruling condition (a)): qlab-wrapper's genesis port
    /// computes this model's roots, over an empty registry and a non-empty
    /// one, tree by tree; the zero ladder is the node's; the digest-bytes
    /// mapping is qlab-note's.
    #[test]
    fn wgenesis_roots_are_the_native_models() {
        use qlab_cbserver::registry::RegistryTree;
        use qlab_wrapper::genesis as g;
        use qlab_wrapper::verify::Surface;
        assert_eq!(g::zeros(), qlab_cbserver::tree::zeros());
        assert_eq!(g::indexed_genesis_root(), IndexedTree::genesis().root());
        assert_eq!(g::supply_genesis_root(), SupplyTree::genesis().root());
        assert_eq!(g::empty_registry_root(), RegistryTree::from_leaves(&[]).unwrap().root());
        for reg in [vec![], vec![RegistryLeaf::cloaked(0)]] {
            let model = WState::genesis(&reg).roots();
            let r = RegistryTree::from_leaves(&reg).unwrap().root();
            assert_eq!(g::genesis_roots(&r), model, "registry of {}", reg.len());
            assert_eq!(g::genesis_surface(7, &r), Surface::genesis(g::CHAIN_VERSION, 7, model));
        }
        let mut rng = Rng(0x785_f54a);
        for _ in 0..8 {
            let d = rng.digest();
            assert_eq!(qlab_wrapper::codec::digest_to_bytes(&d), qlab_note::hash::digest_bytes(&d));
            assert_eq!(qlab_wrapper::codec::digest_from_bytes(&qlab_note::hash::digest_bytes(&d)), d);
        }
    }

    /// Lab #785 F5-4a (pre-review P3): `qlab_wrapper::codec::exit_chain`
    /// over the clear list is this model's `exit_cmt` — three exits, two
    /// rows of one P member then one of the next, in slot and row order.
    #[test]
    fn exit_chain_is_the_models_exit_cmt() {
        use qlab_wrapper::codec::{exit_chain, exit_sum, Exit};
        let (mut s, mut rng, mut inp) = fresh();
        inp.d_batch = 1000;
        let a = p_member(&mut rng, &s, [(1, 40, 0), (1, 2, 0)]);
        let b = p_member(&mut rng, &s, [(1, 7, 0), (0, 0, 0)]);
        let members = [a.clone(), b.clone()];
        let (rin, w, rout) = s.apply(&inp, &members).unwrap();
        let exc = check_wrapper_leaf(&rin, &inp, &members, &w).unwrap().1;
        // One recipient per transaction (lab #785 F5-4d): a's two exits pay
        // the same `rkm`, two chain entries.
        let xr = |m: &Member| m.digest_at(qlab_air::l2p::PV_XRKM).unwrap();
        assert_ne!(xr(&a), xr(&b));
        let list = [
            Exit { rkm: xr(&a), v: 40 },
            Exit { rkm: xr(&a), v: 2 },
            Exit { rkm: xr(&b), v: 7 },
        ];
        assert_eq!(exit_chain(&list), exc);
        assert_eq!(exit_sum(&list), Some(rout.e_cum - rin.e_cum));
        let mut swapped = list;
        swapped.swap(0, 1);
        assert_ne!(exit_chain(&swapped), exc, "order binds");
    }

    /// A mixed sequence threads, and the fee note carries Σ fee.
    #[test]
    fn f4_wrapper_leaf_threads_claims_and_the_fee_note() {
        let (mut s, mut rng, inp) = fresh();
        let (rr, c_in) = (s.l2.r.root(), s.l2.c.root());
        let members = vec![
            tx_member(&synth_tx(&mut rng, L2ShapeTag::P, &rr), &c_in, NO_VP),
            synth_claim(&mut rng, &inp.absorbed[1], 7),
            synth_claim(&mut rng, &inp.absorbed[3], 1 << 40),
            tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_in, NO_VP),
        ];
        let (rin, w, rout) = s.apply(&inp, &members).unwrap();
        assert_eq!(check_wrapper_leaf(&rin, &inp, &members, &w).map(|r| r.0), Ok(rout));
        assert_eq!(rout.ch_next, rin.ch_next + 1, "C_in appended to CH");
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
        let (rr, c_in) = (s.l2.r.root(), s.l2.c.root());
        let members = vec![tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_in, NO_VP)];
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

    fn p_member(rng: &mut Rng, s: &WState, rows: [(u32, u64, u32); 2]) -> Member {
        tx_member(&synth_tx(rng, L2ShapeTag::P, &s.l2.r.root()), &s.l2.c.root(), rows)
    }

    /// Ruling Q4 / condition (k): a transaction anchored at the wrapper's own
    /// `C_out` is refused (that root is not in CH until the next prologue);
    /// the next wrapper accepts it.
    #[test]
    fn f4_ch_latency() {
        let (mut s, mut rng, inp) = fresh();
        let rr = s.l2.r.root();
        let t0 = tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &s.l2.c.root(), NO_VP);
        let pre = s.clone();
        let (_, _, rout) = s.apply(&inp, std::slice::from_ref(&t0)).unwrap();
        let c_out = rout.f3.c;
        let mut early = pre.clone();
        let t1 = tx_member(&synth_tx(&mut rng, L2ShapeTag::S, &rr), &c_out, NO_VP);
        assert_eq!(early.apply(&inp, &[t0, t1.clone()]).unwrap_err(), WError::TxAnchor, "not spendable in its own wrapper");
        let inp2 = WInputs { prev: rng.digest(), ..inp.clone() };
        assert!(s.apply(&inp2, &[t1]).is_ok(), "spendable in the next");
    }

    /// Q5 and condition (l): mint and redeem move an asset's outstanding;
    /// asset 0 never moves the tree — its redeem is an exit into E, its mint
    /// is refused; overflow, underflow, an asset id ≥ 2^16 and a sign ≥ 2
    /// refuse; so does a counter overflow.
    #[test]
    fn f4_supply_and_exit_rules() {
        let (mut s, mut rng, mut inp) = fresh();
        inp.d_batch = 1000;
        let m = p_member(&mut rng, &s, [(0, 500, 9), (1, 200, 9)]);
        s.apply(&inp, &[m]).unwrap();
        assert_eq!(s.sup.outstanding(9), 300);
        let sup0 = s.sup.root();
        let m = p_member(&mut rng, &s, [(1, 40, 0), (0, 0, 0)]);
        let (rin, w, rout) = s.apply(&inp, std::slice::from_ref(&m)).unwrap();
        assert_eq!((rout.e_cum, rout.sup), (rin.e_cum + 40, sup0), "an asset-0 redeem is an exit, not a supply move");
        let exc = check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&m), &w).unwrap().1;
        assert_eq!(exc, h4(&exit_state(&EMPTY, &m.digest_at(qlab_air::l2p::PV_XRKM).unwrap(), 40)), "the exit list binds (rkm, v)");
        // Lab #785 F5-4d-2: a zero-amount asset-0 redeem is no exit (P's
        // `e_k`): nothing chains, E does not move, and the fixture's recipient
        // PV is zero; with an exit beside it, only that one chains.
        let z = p_member(&mut rng, &s, [(1, 0, 0), (0, 0, 0)]);
        assert_eq!(z.digest_at(qlab_air::l2p::PV_XRKM).unwrap(), EMPTY);
        let (rin, w, rout) = s.apply(&inp, std::slice::from_ref(&z)).unwrap();
        assert_eq!(rout.e_cum, rin.e_cum);
        assert_eq!(check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&z), &w).unwrap().1, EMPTY, "no exit chained");
        let z2 = p_member(&mut rng, &s, [(1, 0, 0), (1, 2, 0)]);
        let (rin, w, _) = s.apply(&inp, std::slice::from_ref(&z2)).unwrap();
        let xr = z2.digest_at(qlab_air::l2p::PV_XRKM).unwrap();
        assert_eq!(check_wrapper_leaf(&rin, &inp, std::slice::from_ref(&z2), &w).unwrap().1, h4(&exit_state(&EMPTY, &xr, 2)));
        for (rows, err) in [
            ([(0, 7, 0), (0, 0, 0)], WError::AssetZeroMint),
            ([(1, 301, 9), (0, 0, 0)], WError::Supply),
            ([(0, u64::MAX, 9), (0, 0, 0)], WError::Supply),
            ([(0, 1, 1 << 16), (0, 0, 0)], WError::Supply),
            ([(2, 1, 9), (0, 0, 0)], WError::Supply),
            ([(1, 1 << 63, 0), (1, 1 << 63, 0)], WError::Counter),
        ] {
            let m = p_member(&mut rng, &s, rows);
            assert_eq!(s.clone().apply(&inp, &[m]).unwrap_err(), err, "{rows:?}");
        }
        let mut over = s.clone();
        over.d_cum = u64::MAX;
        let m = p_member(&mut rng, &s, NO_VP);
        assert_eq!(over.apply(&inp, &[m]).unwrap_err(), WError::Counter, "D_cum overflow");
    }

    /// The supply tree: genesis leaves are `H(asset ‖ 0)`, paths fold to the
    /// root, and a set moves exactly its leaf.
    #[test]
    fn f4_supply_tree() {
        let mut t = SupplyTree::genesis();
        let r0 = t.root();
        let p = t.path(12);
        assert_eq!(p.fold_root(&h4(&supply_leaf_state(12, 0))), r0);
        t.set(12, 77);
        assert_eq!(p.fold_root(&h4(&supply_leaf_state(12, 77))), t.root());
        assert_eq!(t.path(13).fold_root(&h4(&supply_leaf_state(13, 0))), t.root());
    }

    /// Review T1: the native refusals of the subtree absorb's alignment and
    /// of a short P member — each from both paths, the state untouched, no
    /// panic.
    #[test]
    fn f4_native_align_and_short_p_refusals() {
        use super::super::neg::{wfixture, SEED};
        let fx = wfixture(&[WTag::S], SEED);
        let mut rin = fx.rin;
        rin.aa_next += 1;
        assert_eq!(check_wrapper_leaf(&rin, &fx.inp, &fx.members, &fx.wit).unwrap_err(), WError::AbsAlign);
        let mut st = fx.pre.clone();
        append(&mut st.aa, &[9; 4]);
        let before = st.roots();
        assert_eq!(st.apply(&fx.inp, &fx.members).unwrap_err(), WError::AbsAlign);
        assert_eq!(st.roots(), before, "a refused wrapper leaves the state as it was");

        let fx = wfixture(&[WTag::P], SEED);
        let mut short = fx.members.clone();
        short[0].pvs.pop();
        assert_eq!(check_wrapper_leaf(&fx.rin, &fx.inp, &short, &fx.wit).unwrap_err(), WError::Surface);
        let mut st = fx.pre.clone();
        assert_eq!(st.apply(&fx.inp, &short).unwrap_err(), WError::Surface);
    }
}
