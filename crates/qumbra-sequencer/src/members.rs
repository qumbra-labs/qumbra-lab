//! Lab #785 F5-6 (1) — **real members over a real state**: the claims, the
//! transactions and the native wrapper statement f5box proves, built from the
//! box node's L1 tree and the wrapper state the chain's bundles left behind.
//!
//! Every member is an instance of the circuit the node verifies it with — a
//! claim of `qlab_air::claim`, shapes S, P and R of `qlab_air::{l2, l2p, l2r}`
//! — over witnesses taken from the trees themselves:
//!
//! - **a claim** opens a burn note (a coinbase paid to `rkm_burn(l2_id)`) in
//!   the L1 tree at the newest absorbed root, pays the genesis claim fee, and
//!   credits `v − fee` to this run's L2 key;
//! - **a transaction** spends one note this run owns, at the wrapper's `C_in`
//!   (the root the prologue appends to `CH`), its second input slot a dummy
//!   (#219 on L2) and slot 3 a dummy fee input; S and P open asset 0 under the
//!   registry root **at their slot** (a member after the R reads the written
//!   registry), R registers the lowest free asset slot as a Cloaked asset;
//! - **the first P** carries the exit: an asset-0 redeem of `exit.v` paid to
//!   `exit.rkm` (F5-4d's edge).
//!
//! [`plan`] builds them in slot order, then applies the whole wrapper to a
//! copy of the state with the native statement (`WState::apply`, which
//! asserts `check_wrapper_leaf` agrees) — the sequencer's prefilter. A plan
//! that comes back `Ok` is a wrapper W can prove, over members the node's
//! verifiers can check.
//!
//! **The key schedule.** Everything private is derived from one run seed:
//! `lanes(label, wrapper, slot) = Keccak256(DOMAIN ‖ seed ‖ label ‖ wrapper ‖
//! slot)` — the L2 spend key, each credit's `rseed`, each claim's `r_v`, each
//! dummy. A rehearsal key, in the clear by design (Q-6-1's synthetic state):
//! nothing it holds is anyone's money but the rehearsal's. `wrapper` is the
//! wrapper's own position in the chain, `AA`'s length over [`M_ABS`] (every
//! wrapper absorbs exactly four roots), never a caller's count: a wrapper
//! planned on a state that already applied it is at a new position, so it can
//! never reuse a dummy's nullifier.
use qlab_air::claim::{build_claim_with_witness, claim_cnf, BurnNote, ClaimCredit, ClaimInstance};
use qlab_air::l2::{
    build_bucket_l2_dummy1, derive_input_l2, dummy_fee_input, l2_cm, FeeSlot, L2BucketInstance, L2TxInput, L2TxOutput,
    RegistryLeaf,
};
use qlab_air::l2p::{
    build_bucket_l2p_exit_with_witnesses, derive_rkm_l2, dummy_allow_witness, CanonicalFreezeTree, L2PBucketInstance,
    L2PolicyInput, VPublic,
};
use qlab_air::l2r::{build_shape_r_with_witnesses, L2ShapeRInstance, RegistryWrite, SeedOutput};
use qlab_air::narrow::{derive_output_rho, off_tree_witness};
use qlab_cbserver::registry::RegistryTree;
use qlab_consensus::{Config, Proof};
use qlab_wrapper::codec::{exit_chain, Exit};
use qlab_wrapper::hash::WRoots;
use qlab_wrapper::verify::Surface;

use super::chain::{Anchor, Burn, ChainView};
use qlab_wprover::f3::native::Digest;
use qlab_wprover::f4::dep::DepEntry;
use qlab_wprover::f4::native::{fee_rho, fee_rseed, Member, WInputs, WState, WTag, WWitness, M_ABS};

/// The key schedule's domain.
const DOMAIN: &[u8] = b"qumbra:f5box:v1";

/// The fee every f5box transaction pays (bessel): S, P and R carry no fee
/// rule (no tariff check exists for them, lab #785 census); a fixed nonzero
/// value keeps the asset-0 fee path in use.
pub const TX_FEE: u64 = 10_000;

/// This run's L2 diversifier: every note f5box owns is at one `rkm`.
const D: [u64; 2] = [1, 0];

/// The run's private schedule.
#[derive(Clone)]
pub struct Keys {
    seed: [u8; 32],
}

impl Keys {
    pub fn from_text(seed: &str) -> Self {
        Keys { seed: qlab_devnet::hash::keccak256(seed.as_bytes()) }
    }

    /// From a 32-byte seed — the sequencer's filler wallet (lab #847 S5:
    /// `key::filler_seed`), never a run seed in the clear.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Keys { seed }
    }

    /// `Keccak256(DOMAIN ‖ seed ‖ label ‖ wrapper ‖ slot)` as four lanes.
    pub fn lanes(&self, label: &str, wrapper: u64, slot: u64) -> Digest {
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&self.seed);
        msg.extend_from_slice(&(label.len() as u64).to_le_bytes());
        msg.extend_from_slice(label.as_bytes());
        msg.extend_from_slice(&wrapper.to_le_bytes());
        msg.extend_from_slice(&slot.to_le_bytes());
        qlab_wrapper::codec::digest_from_bytes(&qlab_devnet::hash::keccak256(&msg))
    }

    fn sk(&self) -> Digest {
        self.lanes("sk", 0, 0)
    }

    /// An asset-0 note of this run's, as a spend input.
    pub fn input(&self, n: &Owned) -> L2TxInput {
        L2TxInput { sk: self.sk(), value: n.value, asset: 0, rho: n.rho, rseed: n.rseed, d: D }
    }

    /// This run's L2 recipient key (every credit, every change output, the
    /// sequencer fee note).
    pub fn rkm(&self) -> Digest {
        derive_rkm_l2(&self.input(&Owned { value: 0, rho: [0; 4], rseed: [0; 4] }))
    }

    /// **A seed claim's credit `rseed`** (lab #847 S3b):
    /// `Keccak256(DOMAIN ‖ seed ‖ SEED_CREDIT ‖ cnf)` — bound to the claim's
    /// cnf, so the sequencer recomputes it from the claim's own public values
    /// and recognises its credit without keeping any record of the claims
    /// `seed` made.
    pub fn seed_rseed(&self, cnf: &Digest) -> Digest {
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&self.seed);
        msg.extend_from_slice(&(SEED_CREDIT.len() as u64).to_le_bytes());
        msg.extend_from_slice(SEED_CREDIT.as_bytes());
        msg.extend_from_slice(&qlab_wrapper::codec::digest_to_bytes(cnf));
        qlab_wrapper::codec::digest_from_bytes(&qlab_devnet::hash::keccak256(&msg))
    }

    /// The credit `seed` gives the claim of a burn whose cnf is `cnf`: this
    /// key's `rkm`, [`Keys::seed_rseed`].
    pub fn seed_credit(&self, cnf: &Digest) -> ClaimCredit {
        ClaimCredit { rkm: self.rkm(), rseed: self.seed_rseed(cnf) }
    }
}

/// The label of a seed claim's credit `rseed` (lab #847 S3b).
pub const SEED_CREDIT: &str = "seed-credit";

/// **Whether a claim credits this sequencer** (lab #847 S3b): the note a seed
/// claim creates — `value − fee` to `keys.rkm()`, ρ = its cnf, rseed
/// [`Keys::seed_rseed`] — if its `cm2` is exactly that note's commitment,
/// else `None`. A wallet's claim never matches: its rseed is the wallet's,
/// and the seed is the sequencer's. Seed claims take S2's path unchanged
/// (intake's checks, its dedupe, the queue's states); only here, at plan
/// time, does the sequencer see that one is its own.
pub fn own_credit(pvs: &[u32], value: u64, keys: &Keys) -> Option<Owned> {
    let m = Member { tag: WTag::C, pvs: pvs.to_vec(), write: None };
    let cnf = m.digest_at(qlab_air::claim::PV_CNF).ok()?;
    let cm2 = m.digest_at(qlab_air::claim::PV_CM2).ok()?;
    let value = value.checked_sub(qlab_l2spend::claim_fee_of(pvs))?;
    let n = Owned { value, rho: cnf, rseed: keys.seed_rseed(&cnf) };
    (n.cm(keys) == cm2).then_some(n)
}

/// An asset-0 L2 note this run owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owned {
    pub value: u64,
    pub rho: Digest,
    pub rseed: Digest,
}

impl Owned {
    pub fn cm(&self, keys: &Keys) -> Digest {
        l2_cm(self.value, 0, &keys.rkm(), &self.rho, &self.rseed)
    }
}

/// One built member: its circuit instance.
#[allow(clippy::large_enum_variant)]
pub enum Inst {
    S(L2BucketInstance),
    P(L2PBucketInstance),
    /// With the leaf it writes (bound through `new_root`, not a PV).
    R(L2ShapeRInstance, RegistryLeaf),
    C(ClaimInstance),
    /// Lab #831 W3c: a claim proven elsewhere — a depositor's claim file
    /// (`qumbra-wallet deposit claim`): its public values and its proof, as
    /// `bincode` bytes already verified when the file was taken.
    Proven { pvs: Vec<u32>, proof: Vec<u8> },
}

impl Inst {
    pub fn tag(&self) -> WTag {
        match self {
            Inst::S(_) => WTag::S,
            Inst::P(_) => WTag::P,
            Inst::R(..) => WTag::R,
            Inst::C(_) | Inst::Proven { .. } => WTag::C,
        }
    }

    pub fn pvs(&self) -> &[u32] {
        match self {
            Inst::S(i) => &i.pvs,
            Inst::P(i) => &i.pvs,
            Inst::R(i, _) => &i.pvs,
            Inst::C(i) => &i.pvs,
            Inst::Proven { pvs, .. } => pvs,
        }
    }

    /// The member W threads.
    pub fn member(&self) -> Member {
        let write = match self {
            Inst::R(_, leaf) => Some(*leaf),
            _ => None,
        };
        Member { tag: self.tag(), pvs: self.pvs().to_vec(), write }
    }

    /// Prove it under the L2 lane (7–31 GiB; box only). A claim proven
    /// elsewhere is not proven again: its proof is the file's.
    pub fn prove(&self) -> Proof<Config> {
        match self {
            Inst::S(i) => qlab_l2::prove_s(i).1,
            Inst::P(i) => qlab_l2::prove_p(i).1,
            Inst::R(i, _) => qlab_l2::prove_r(i).1,
            Inst::C(i) => qlab_l2::claim::prove_claim(i).1,
            Inst::Proven { proof, .. } => bincode::deserialize(proof).expect("a claim file's proof decoded when it was taken"),
        }
    }
}

/// The chain facts a plan is built against.
pub struct Chain<'a> {
    pub view: &'a ChainView,
    pub l2_id: u64,
    /// The genesis claim tariff (`WrapperParams::claim_fee_tier`).
    pub fee_tier: u64,
}

/// What to build.
pub struct Ask<'a> {
    /// The slot order (`default_kinds(16)`, or sixteen claims).
    pub kinds: &'a [WTag],
    /// The burns a claim may take, in order (already-claimed ones are skipped
    /// by their `cnf`).
    pub burns: &'a [Burn],
    /// The notes a transaction may spend, in order (spent ones are skipped by
    /// their nullifier).
    pub owned: &'a [Owned],
    /// Paid by the first P, if any.
    pub exit: Option<Exit>,
}

/// A built wrapper: the members, the native statement and what it moves.
pub struct Plan {
    pub insts: Vec<Inst>,
    pub members: Vec<Member>,
    /// Each claim's value opening, in claim order (the deposit-sum proof's).
    pub deps: Vec<DepEntry>,
    pub inp: WInputs,
    pub exits: Vec<Exit>,
    /// The absorbed roots, oldest first (`absorbed[M_ABS − 1]` the newest).
    pub absorbed: [Anchor; M_ABS],
    /// The burns claimed, in claim order.
    pub claimed: Vec<Burn>,
    /// The owned notes spent, in slot order.
    pub spent: Vec<Owned>,
    /// The notes this wrapper creates for this run (credits, change; for a
    /// sequencer wrapper, each filler's two outputs and the fee note).
    pub credited: Vec<Owned>,
    /// Lab #847 S3: per slot, whether the member is sequencer padding (an S
    /// filler) rather than traffic — the manifest marks it `filler: true`.
    pub filler: Vec<bool>,
    pub rin: WRoots,
    pub wit: WWitness,
    pub rout: WRoots,
    pub exit_cmt: Digest,
}

/// Why a plan is refused — every one named, none a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The node serves no valid anchor (nothing finalized yet).
    NoAnchor,
    /// The served anchors and the served leaves disagree.
    Chain(String),
    /// Fewer claimable burns under the newest anchor than the claims need.
    Burns { need: usize, have: usize },
    /// Fewer unspent owned notes than the transactions need.
    Notes { need: usize, have: usize },
    /// A burn worth less than the claim fee.
    BurnBelowFee { height: u64, value: u64, fee: u64 },
    /// The first P's note cannot pay the fee and the exit.
    ExitAboveNote { note: u64, fee: u64, exit: u64 },
    /// An exit with nowhere to ride: no P in the slot order.
    ExitWithoutP,
    /// More than one R in the slot order (v1 allows one per wrapper).
    SecondR,
    /// A transaction's note cannot pay the fee.
    NoteBelowFee { value: u64 },
    /// The registry has no free slot for R.
    RegistryFull,
    /// The native wrapper statement refuses the batch.
    Wrapper(String),
    /// Lab #831 W3c: a claim file was given and the wrapper has no claim slot.
    NoClaimSlot,
    /// Lab #831 W3c: the claim file opens its burn under a root no wrapper
    /// has absorbed and this one does not absorb.
    ClaimAnchorNotAbsorbed { root: Digest },
    /// Lab #847 S4/S3: claims plus spendable sequencer notes (one per
    /// filler) short of K = 16 — `have` counts both — or more claims than a
    /// wrapper holds (the caller's mistake).
    WrongCount { have: usize, need: usize },
    /// Lab #847 S3: no claim — a wrapper of padding alone is never planned.
    NoClaim,
}

/// A wrapper's member count (wrapper version 1's K, lab #785 Q1).
pub const K: usize = 16;

/// **The member kinds a posting pass may emit** (lab #847, the Q4 condition
/// of design `l2-read-path-decision`): claims, and S3's S fillers —
/// **never R**. The node's derived L2 index (lab #860, R1) cannot follow a
/// registry write from the wire, so one R member would block every exit
/// until format v2. [`plan`] (f5box's general planner) can still plan R;
/// the pass never calls it — `lib.rs`'s `the_pass_plans_no_r_member` holds
/// that — and [`pass_members_ok`] refuses anything else before proving.
pub const PASS_MEMBER_TAGS: [WTag; 2] = [WTag::C, WTag::S];

/// **A filler's fee: 0** (lab #847 S3, ruled 2026-10-03). S, P and R carry no
/// tariff yet (lab #785 census), and W's fee note sums the **claims'** fees
/// only — a nonzero S fee under [`FeeSlot::Dummy`] is destroyed with no
/// recipient, so every filler would burn it from the sequencer's balance.
/// At 0 a filler moves no value: change = input, a zero second output, both
/// to `rkm_seq`. **When F6 defines the tx tariff** this becomes the tariff,
/// paid into F6's fee flow, and the sequencer's notes shrink by it per
/// filler — the filler budget then needs funding, which this constant hides.
pub const FILLER_FEE: u64 = 0;

/// Every member's tag is one [`PASS_MEMBER_TAGS`] allows; else the first one
/// that is not, by slot and tag.
pub fn pass_members_ok(members: &[Member]) -> Result<(), String> {
    match members.iter().position(|m| !PASS_MEMBER_TAGS.contains(&m.tag)) {
        None => Ok(()),
        Some(i) => Err(format!(
            "member {i} is {}: a posting pass emits only {} members (lab #847 Q4: no R in v0/v1) — not proving",
            crate::state::tag_name(members[i].tag),
            PASS_MEMBER_TAGS.map(crate::state::tag_name).join(", ")
        )),
    }
}

/// The notes in `owned` the next wrapper may spend: in C at its `C_in`,
/// nullifier not yet in N — each once, **largest value first** (stable, so
/// equal values keep `owned`'s order). Every filler mints a zero-valued
/// note; this keeps those last, so value-bearing notes carry the fillers
/// and the zero ones are drawn only when nothing else is left.
pub fn spendable(state: &WState, keys: &Keys, owned: &[Owned]) -> Vec<Owned> {
    let c_count = state.l2.c.len();
    let mut out: Vec<Owned> = Vec::new();
    for n in owned {
        let in_c = state.l2.c.position_of(&n.cm(keys)).is_some_and(|p| p < c_count);
        if in_c && state.l2.n.low_leaf_of(&derive_input_l2(&keys.input(n)).1).is_some() && !out.contains(n) {
            out.push(*n);
        }
    }
    out.sort_by_key(|n| std::cmp::Reverse(n.value));
    out
}

/// **One filler** (lab #847 S3): an S self-transfer of the owned note `n`,
/// in `slot` of the wrapper at position `wrapper` — `n` whole to `rkm_seq`
/// as change, a zero-valued second output to `rkm_seq`, [`FILLER_FEE`]
/// (0), the #219 dummy in the second input slot. It moves no value and
/// leaves the sequencer one note richer. Returns the member and the two
/// notes it creates, both the sequencer's.
pub fn filler(state: &WState, keys: &Keys, wrapper: u64, slot: usize, n: &Owned) -> Result<(Inst, [Owned; 2]), PlanError> {
    let lane = |label: &str| keys.lanes(label, wrapper, slot as u64);
    let reg = &state.l2.r;
    let (c_in, c_count) = (state.l2.c.root(), state.l2.c.len());
    let pos = state.l2.c.position_of(&n.cm(keys)).filter(|p| *p < c_count).ok_or(PlanError::Notes { need: 1, have: 0 })?;
    let real = keys.input(n);
    let real_w = state.l2.c.auth_path(pos, c_count);
    let dummy = L2TxInput { sk: lane("filler-dummy-sk"), value: 0, asset: 0, rho: lane("filler-dummy-rho"), rseed: lane("filler-dummy-rseed"), d: [0, 0] };
    let me = keys.rkm();
    let change = n.value.checked_sub(FILLER_FEE).ok_or(PlanError::NoteBelowFee { value: n.value })?;
    let out = |value: u64, label: &str| L2TxOutput { value, asset: 0, rkm: me, rho: [0; 4], rseed: lane(label) };
    let outputs = [out(change, "filler-out0"), out(0, "filler-out1")];
    let leaf0 = *reg.leaf(0).expect("asset 0's leaf is in every registry (lab #785 F-A)");
    let w0 = reg.witness(0).expect("asset 0's leaf is in every registry");
    let inst = build_bucket_l2_dummy1(
        qlab_l2::LOG_HEIGHT_S,
        &real,
        &real_w,
        &dummy,
        &off_tree_witness(),
        &outputs,
        FILLER_FEE,
        c_in,
        &[leaf0, leaf0],
        &[w0, w0],
        reg.root(),
        &FeeSlot::Dummy { input: dummy_fee_input(&lane("filler-fee-dummy")) },
    );
    let nf0 = inst.nf[0];
    let made = [0, 1].map(|j| Owned { value: outputs[j].value, rho: derive_output_rho(&nf0, j), rseed: outputs[j].rseed });
    Ok((Inst::S(inst), made))
}

/// **Lab #847 S4 + S3: a wrapper of wallets' claims, filled to K** — every
/// claim file intake verified, in the order given, then one [`filler`] per
/// remaining slot from the sequencer's own spendable notes (`owned`, in
/// order). `absorbed` is the four roots this wrapper absorbs, oldest first,
/// chosen by the caller (the loop picks them under the record-covered
/// height); every claim's anchor must be one of them or a root an earlier
/// wrapper absorbed. Refused by name with [`PlanError::WrongCount`] when
/// claims and spendable notes together are short of [`K`], or the claims
/// alone exceed it, and by the native statement exactly as [`plan`] runs it.
/// The sequencer's fee note goes to `keys` (the filler wallet, lab #847 S5);
/// [`Plan::credited`] carries it, each filler's two outputs, and the credit
/// of every claim that is the sequencer's own ([`own_credit`], S3b's seed
/// claims) — the notes the next wrapper may spend once this one lands.
pub fn plan_claims(
    state: &WState,
    prev: &Surface,
    absorbed: [Anchor; M_ABS],
    files: Vec<qlab_l2spend::ClaimFile>,
    owned: &[Owned],
    keys: &Keys,
) -> Result<Plan, PlanError> {
    if files.is_empty() {
        return Err(PlanError::NoClaim);
    }
    let notes = spendable(state, keys, owned);
    let n_fill = K.saturating_sub(files.len());
    if files.len() > K || notes.len() < n_fill {
        return Err(PlanError::WrongCount { have: files.len() + notes.len().min(n_fill), need: K });
    }
    let roots = absorbed.map(|a| a.root);
    let mut insts = Vec::with_capacity(K);
    let mut deps = Vec::with_capacity(K);
    let mut d_batch = 0u64;
    let mut own = Vec::new();
    for file in files {
        own.extend(own_credit(&file.pvs, file.value, keys));
        let member = Member { tag: WTag::C, pvs: file.pvs.clone(), write: None };
        let anchor = member.digest_at(qlab_air::claim::PV_A).map_err(|e| PlanError::Wrapper(format!("a claim's anchor: {e:?}")))?; // debug-ok: a PV read error, no opening
        let absorbed_before = (0..state.aa.len()).any(|i| state.aa.leaf(i) == anchor);
        if !absorbed_before && !roots.contains(&anchor) {
            return Err(PlanError::ClaimAnchorNotAbsorbed { root: anchor });
        }
        d_batch = d_batch.checked_add(file.value).ok_or(PlanError::Wrapper("D_batch overflows u64".into()))?;
        deps.push(DepEntry { v: file.value, r_v: file.r_v });
        insts.push(Inst::Proven { pvs: file.pvs, proof: file.proof });
    }
    let n_claims = insts.len();
    let wrapper = state.aa.len() / M_ABS as u64;
    let mut credited = own;
    for (j, n) in notes[..n_fill].iter().enumerate() {
        let (inst, made) = filler(state, keys, wrapper, n_claims + j, n)?;
        insts.push(inst);
        credited.extend(made);
    }
    let members: Vec<Member> = insts.iter().map(Inst::member).collect();
    let inp = WInputs { prev: prev.commitment, rkm_seq: keys.rkm(), absorbed: roots, d_batch };
    let (rin, wit, rout, exit_cmt) = statement(state, &inp, &members, &[])?;
    // W's fee note: Σ the claims' fees to rkm_seq, ρ and rseed public over
    // `prev` — the sequencer's to spend like any owned note.
    credited.push(Owned { value: qlab_wprover::f4::wleaf::fee_of(&members), rho: fee_rho(&inp.prev), rseed: fee_rseed(&inp.prev) });
    let mut filler_slots = vec![false; n_claims];
    filler_slots.resize(K, true);
    Ok(Plan {
        insts,
        members,
        deps,
        inp,
        exits: Vec::new(),
        absorbed,
        claimed: Vec::new(),
        spent: notes[..n_fill].to_vec(),
        credited,
        filler: filler_slots,
        rin,
        wit,
        rout,
        exit_cmt,
    })
}

/// The policy input of an asset-0 note at `rkm` under `reg`: Cloaked, the
/// empty canonical freeze tree, the dummy allowlist path, no issuer secret —
/// `qlab_l2spend::policy_input`'s Cloaked arm.
fn asset0_policy(reg: &RegistryTree, rkm: &Digest) -> L2PolicyInput {
    L2PolicyInput {
        leaf: *reg.leaf(0).expect("asset 0's leaf is in every registry (lab #785 F-A)"),
        reg_witness: reg.witness(0).expect("asset 0's leaf is in every registry"),
        freeze: CanonicalFreezeTree::empty().opening_for(rkm).expect("the empty freeze tree freezes no key"),
        allow: dummy_allow_witness(),
        isk: [0; 4],
    }
}

/// Build the wrapper `ask` names on `state`, whose surface is `prev`.
pub fn plan(state: &WState, prev: &Surface, chain: &Chain, keys: &Keys, ask: &Ask) -> Result<Plan, PlanError> {
    if ask.exit.is_some() && !ask.kinds.contains(&WTag::P) {
        return Err(PlanError::ExitWithoutP);
    }
    if ask.kinds.iter().filter(|t| **t == WTag::R).count() > 1 {
        return Err(PlanError::SecondR);
    }
    let wrapper = state.aa.len() / M_ABS as u64;
    // The absorbed roots: the four newest distinct anchors, oldest first,
    // the newest repeated when fewer exist. Every claim opens at the newest.
    let anchors = chain.view.anchors().map_err(PlanError::Chain)?;
    let newest = *anchors.first().ok_or(PlanError::NoAnchor)?;
    let mut absorbed: Vec<Anchor> = anchors.iter().take(M_ABS).rev().copied().collect();
    while absorbed.len() < M_ABS {
        absorbed.push(newest);
    }
    let absorbed: [Anchor; M_ABS] = absorbed.try_into().expect("exactly M_ABS");

    // The burns: in the tree under the newest anchor, never claimed.
    let n_claims = ask.kinds.iter().filter(|t| **t == WTag::C).count();
    let fresh_cnf = |b: &Burn| state.k.low_leaf_of(&claim_cnf(&b.cm, &b.note.rseed)).is_some();
    let burns: Vec<Burn> = ask.burns.iter().filter(|b| b.pos < newest.count && fresh_cnf(b)).take(n_claims).copied().collect();
    if burns.len() < n_claims {
        return Err(PlanError::Burns { need: n_claims, have: burns.len() });
    }

    // The notes: in C at the wrapper's `C_in`, never spent.
    let (c_in, c_count) = (state.l2.c.root(), state.l2.c.len());
    let n_tx = ask.kinds.len() - n_claims;
    let spendable = |n: &Owned| {
        let input = keys.input(n);
        state.l2.c.position_of(&n.cm(keys)).is_some_and(|p| p < c_count)
            && state.l2.n.low_leaf_of(&derive_input_l2(&input).1).is_some()
    };
    let notes: Vec<Owned> = ask.owned.iter().filter(|n| spendable(n)).take(n_tx).copied().collect();
    if notes.len() < n_tx {
        return Err(PlanError::Notes { need: n_tx, have: notes.len() });
    }

    let me = keys.rkm();
    let mut reg = state.l2.r.clone();
    let (mut burn_i, mut note_i) = (0usize, 0usize);
    let mut exit_left = ask.exit;
    // Everything but the native statement; `Plan` is assembled after it.
    let mut insts: Vec<Inst> = Vec::new();
    let mut deps: Vec<DepEntry> = Vec::new();
    let mut exits: Vec<Exit> = Vec::new();
    let (mut claimed, mut spent, mut credited) = (Vec::new(), Vec::new(), Vec::new());
    let mut d_batch = 0u64;
    let slot_keys = |label: &str, slot: usize| keys.lanes(label, wrapper, slot as u64);
    // A transaction's second input slot (#219): value 0, asset 0, off-tree.
    let dummy = |slot: usize| L2TxInput {
        sk: slot_keys("dummy-sk", slot),
        value: 0,
        asset: 0,
        rho: slot_keys("dummy-rho", slot),
        rseed: slot_keys("dummy-rseed", slot),
        d: [0, 0],
    };
    let fee_slot = |slot: usize| FeeSlot::Dummy { input: dummy_fee_input(&slot_keys("fee-dummy", slot)) };
    let to_me = |value: u64, slot: usize, j: usize| L2TxOutput {
        value,
        asset: 0,
        rkm: me,
        rho: [0; 4],
        rseed: slot_keys(if j == 0 { "out0" } else { "out1" }, slot),
    };

    for (slot, kind) in ask.kinds.iter().enumerate() {
        let inst = match kind {
            WTag::C => {
                let b = burns[burn_i];
                burn_i += 1;
                if b.note.value < chain.fee_tier {
                    return Err(PlanError::BurnBelowFee { height: b.height, value: b.note.value, fee: chain.fee_tier });
                }
                let r_v = slot_keys("r_v", slot);
                let credit = ClaimCredit { rkm: me, rseed: slot_keys("credit", slot) };
                let path = chain.view.tree.auth_path(b.pos, newest.count);
                let note: BurnNote = b.note;
                let inst = build_claim_with_witness(
                    qlab_l2::claim::LOG_HEIGHT_CLAIM,
                    &qlab_air::claim::rkm_burn(chain.l2_id),
                    &note,
                    &path,
                    newest.root,
                    &r_v,
                    &credit,
                    chain.fee_tier,
                );
                deps.push(DepEntry { v: b.note.value, r_v });
                d_batch = d_batch.checked_add(b.note.value).ok_or(PlanError::Wrapper("D_batch overflows u64".into()))?;
                credited.push(Owned { value: b.note.value - chain.fee_tier, rho: inst.cnf, rseed: credit.rseed });
                claimed.push(b);
                Inst::C(inst)
            }
            WTag::S | WTag::P => {
                let n = notes[note_i];
                note_i += 1;
                let real = keys.input(&n);
                let real_w = state.l2.c.auth_path(state.l2.c.position_of(&n.cm(keys)).expect("spendable"), c_count);
                let exit = if *kind == WTag::P { exit_left.take() } else { None };
                let exit_v = exit.map_or(0, |e| e.v);
                let change = n
                    .value
                    .checked_sub(TX_FEE)
                    .ok_or(PlanError::NoteBelowFee { value: n.value })?
                    .checked_sub(exit_v)
                    .ok_or(PlanError::ExitAboveNote { note: n.value, fee: TX_FEE, exit: exit_v })?;
                let outputs = [to_me(change, slot, 0), to_me(0, slot, 1)];
                let dummy = dummy(slot);
                let inst = if *kind == WTag::S {
                    let leaf0 = *reg.leaf(0).expect("asset 0's leaf");
                    let w0 = reg.witness(0).expect("asset 0's leaf");
                    Inst::S(build_bucket_l2_dummy1(
                        qlab_l2::LOG_HEIGHT_S,
                        &real,
                        &real_w,
                        &dummy,
                        &off_tree_witness(),
                        &outputs,
                        TX_FEE,
                        c_in,
                        &[leaf0, leaf0],
                        &[w0, w0],
                        reg.root(),
                        &fee_slot(slot),
                    ))
                } else {
                    let policy = [asset0_policy(&reg, &derive_rkm_l2(&real)), asset0_policy(&reg, &derive_rkm_l2(&dummy))];
                    let vp = [exit.map_or(VPublic::NONE, |e| VPublic::redeem(e.v)), VPublic::NONE];
                    let mut inst = build_bucket_l2p_exit_with_witnesses(
                        qlab_l2::LOG_HEIGHT_P,
                        &[real.clone(), dummy],
                        &outputs,
                        TX_FEE,
                        &[real_w, off_tree_witness()],
                        c_in,
                        &policy,
                        reg.root(),
                        vp,
                        &fee_slot(slot),
                        exit.map_or([0; 4], |e| e.rkm),
                    );
                    inst.air.dv = true;
                    if let Some(e) = exit {
                        exits.push(e);
                    }
                    Inst::P(inst)
                };
                let nf0 = match &inst {
                    Inst::S(i) => i.nf[0],
                    Inst::P(i) => i.nf[0],
                    _ => unreachable!(),
                };
                if change > 0 {
                    credited.push(Owned { value: change, rho: derive_output_rho(&nf0, 0), rseed: outputs[0].rseed });
                }
                spent.push(n);
                inst
            }
            WTag::R => {
                let n = notes[note_i];
                note_i += 1;
                let change = n.value.checked_sub(TX_FEE).ok_or(PlanError::NoteBelowFee { value: n.value })?;
                let fee_in = keys.input(&n);
                let w = state.l2.c.auth_path(state.l2.c.position_of(&n.cm(keys)).expect("spendable"), c_count);
                let asset = (1u16..=u16::MAX).find(|a| reg.leaf(*a).is_none()).ok_or(PlanError::RegistryFull)?;
                let leaf = RegistryLeaf::cloaked(u64::from(asset));
                let write = RegistryWrite { isk: [0; 4], old_leaf: None, new_leaf: leaf, opening: reg.opening_at(asset) };
                let seed = SeedOutput { rkm: me, rseed: slot_keys("seed", slot) };
                let out0 = to_me(change, slot, 0);
                let inst = build_shape_r_with_witnesses(qlab_l2::LOG_HEIGHT_R, &fee_in, &w, c_in, &out0, TX_FEE, &write, &seed);
                reg.apply_update(leaf).map_err(|e| PlanError::Wrapper(format!("registry write: {e:?}")))?; // debug-ok: a registry write error, no opening
                if change > 0 {
                    credited.push(Owned { value: change, rho: inst.nf, rseed: out0.rseed });
                }
                spent.push(n);
                Inst::R(inst, leaf)
            }
        };
        insts.push(inst);
    }

    let members: Vec<Member> = insts.iter().map(Inst::member).collect();
    let inp = WInputs { prev: prev.commitment, rkm_seq: me, absorbed: absorbed.map(|a| a.root), d_batch };
    let (rin, wit, rout, exit_cmt) = statement(state, &inp, &members, &exits)?;
    let filler = vec![false; insts.len()];
    Ok(Plan { insts, members, deps, inp, exits, absorbed, claimed, spent, credited, filler, rin, wit, rout, exit_cmt })
}

/// The native statement, on a copy of `state`: the sequencer's prefilter —
/// apply the members, check the wrapper leaf, and require `exits` to chain
/// to the `exit_cmt` it states.
fn statement(state: &WState, inp: &WInputs, members: &[Member], exits: &[Exit]) -> Result<(WRoots, WWitness, WRoots, Digest), PlanError> {
    let mut st = state.clone();
    let (rin, wit, rout) = st.apply(inp, members).map_err(|e| PlanError::Wrapper(format!("{e:?}")))?; // debug-ok: WError: unit and value-free variants only
    let exit_cmt = qlab_wprover::f4::native::check_wrapper_leaf(&rin, inp, members, &wit)
        .map_err(|e| PlanError::Wrapper(format!("{e:?}")))? // debug-ok: WError: unit and value-free variants only
        .1;
    if exit_chain(exits) != exit_cmt {
        return Err(PlanError::Wrapper("the exit list does not chain to W's exit_cmt".into()));
    }
    Ok((rin, wit, rout, exit_cmt))
}

/// **Lab #831 W2: a member built elsewhere, in `slot`** — the wallet's exit
/// P, assembled by `qlab_l2spend::exit_instance` — and the native statement
/// re-run over the result exactly as [`plan`] runs it. `exits` is the new
/// wrapper's exit list in slot order. The swapped slot's change credit (the
/// one whose commitment is the old member's first output) is replaced by
/// `credit`, the new member's change as this run's keys own it — or dropped
/// when `None` — so a later plan spending from the result finds every credit
/// it names. `spent` stays `base`'s: the lane swaps in a member that spends
/// the same note. Test-only: f5box itself never takes a foreign member.
#[cfg(any(test, feature = "test-support"))]
pub fn reseal(state: &WState, mut base: Plan, slot: usize, inst: Inst, exits: Vec<Exit>, keys: &Keys, credit: Option<Owned>) -> Result<Plan, PlanError> {
    let old_change = match &base.insts[slot] {
        Inst::S(i) => Some(i.cm_out[0]),
        Inst::P(i) => Some(i.cm_out[0]),
        _ => None,
    };
    let at = old_change.and_then(|cm| base.credited.iter().position(|c| c.cm(keys) == cm));
    match (at, credit) {
        (Some(k), Some(c)) => base.credited[k] = c,
        (Some(k), None) => {
            base.credited.remove(k);
        }
        (None, Some(c)) => base.credited.push(c),
        (None, None) => {}
    }
    base.insts[slot] = inst;
    base.members = base.insts.iter().map(Inst::member).collect();
    let (rin, wit, rout, exit_cmt) = statement(state, &base.inp, &base.members, &exits)?;
    Ok(Plan { exits, rin, wit, rout, exit_cmt, ..base })
}

/// **Swap claim slot `slot`'s member for `inst`** (lab #831 W3b/W3c), with
/// everything a claim moves besides its member: its deposit-sum opening `dep`
/// replaces the slot's (`deps`), the batch total `d_batch` is recomputed from
/// the openings, the old claim's credit leaves `credited` (the new credit is
/// its depositor's, not this run's), and the burn it claims replaces the
/// slot's in `claimed` — or leaves it, for a claim whose burn f5box cannot see
/// (`burn: None`, a depositor's claim file). Then the native statement,
/// exactly as [`plan`] runs it.
///
/// Dropping a burn from `claimed` is safe: outside the tests nothing reads
/// `claimed` positionally — the manifest and `--check` only list it — and the
/// state file does not track burns (a burn's claim is known to the wrapper by
/// its `cnf`, which the member's PVs carry).
fn swap_claim(state: &WState, mut base: Plan, slot: usize, inst: Inst, dep: DepEntry, burn: Option<Burn>, keys: &Keys) -> Result<Plan, PlanError> {
    let Inst::C(old) = &base.insts[slot] else { return Err(PlanError::Wrapper(format!("slot {slot} is not a claim f5box built"))) };
    let old_credit = old.cm2;
    let ci = base.insts[..slot].iter().filter(|i| i.tag() == WTag::C).count();
    base.deps[ci] = dep;
    match burn {
        Some(b) => base.claimed[ci] = b,
        None => {
            base.claimed.remove(ci);
        }
    }
    base.credited.retain(|c| c.cm(keys) != old_credit);
    base.inp.d_batch = base
        .deps
        .iter()
        .try_fold(0u64, |a, d| a.checked_add(d.v))
        .ok_or(PlanError::Wrapper("D_batch overflows u64".into()))?;
    base.insts[slot] = inst;
    base.members = base.insts.iter().map(Inst::member).collect();
    let exits = std::mem::take(&mut base.exits);
    let (rin, wit, rout, exit_cmt) = statement(state, &base.inp, &base.members, &exits)?;
    Ok(Plan { exits, rin, wit, rout, exit_cmt, ..base })
}

/// **Lab #831 W3b: a claim built elsewhere, in claim `slot`** — the wallet's
/// claim instance, with the burn it claims. Test-only; the box takes a claim
/// FILE through [`take_claim_file`].
#[cfg(any(test, feature = "test-support"))]
pub fn reseal_claim(
    state: &WState,
    base: Plan,
    slot: usize,
    inst: ClaimInstance,
    dep: DepEntry,
    burn: Burn,
    keys: &Keys,
) -> Result<Plan, PlanError> {
    swap_claim(state, base, slot, Inst::C(inst), dep, Some(burn), keys)
}

/// **Lab #831 W3c: a depositor's claim file, as this wrapper's first claim.**
/// The file's public values and proof become the member, its `(v, r_v)` the
/// deposit-sum opening; the claim f5box planned for that slot is dropped (its
/// burn stays claimable by a later wrapper). Refused by name when the plan has
/// no claim slot, or when the claim's anchor is a root neither absorbed before
/// nor by this wrapper — a wrapper takes a claim only under a root in `AA`;
/// the depositor rebuilds it at a newer anchor (`deposit claim
/// --anchor-count`). The proof is verified by the caller before this, so an
/// unprovable file never costs an hour of proving the rest.
pub fn take_claim_file(state: &WState, base: Plan, file: qlab_l2spend::ClaimFile, keys: &Keys) -> Result<Plan, PlanError> {
    let slot = base.insts.iter().position(|i| matches!(i, Inst::C(_))).ok_or(PlanError::NoClaimSlot)?;
    let member = Member { tag: WTag::C, pvs: file.pvs.clone(), write: None };
    let anchor = member.digest_at(qlab_air::claim::PV_A).map_err(|e| PlanError::Wrapper(format!("the claim file's anchor: {e:?}")))?; // debug-ok: a PV read error, no opening
    let absorbed_before = (0..state.aa.len()).any(|i| state.aa.leaf(i) == anchor);
    if !absorbed_before && !base.inp.absorbed.contains(&anchor) {
        return Err(PlanError::ClaimAnchorNotAbsorbed { root: anchor });
    }
    let dep = DepEntry { v: file.value, r_v: file.r_v };
    swap_claim(state, base, slot, Inst::Proven { pvs: file.pvs, proof: file.proof }, dep, None, keys)
}

/// **Which claim the native statement refuses** (lab #847 S4), by
/// elimination: the statement applies members in order, so the first prefix
/// `WState::apply` refuses ends at the culprit. `None` when every prefix
/// applies (the refusal is the whole wrapper's — the leaf check — not one
/// item's). Native work only, no proving; the inputs are `plan_claims`'s.
pub fn first_refused(
    state: &WState,
    prev: &Surface,
    absorbed: &[Anchor; M_ABS],
    files: &[qlab_l2spend::ClaimFile],
    keys: &Keys,
) -> Option<usize> {
    let members: Vec<Member> = files.iter().map(|f| Member { tag: WTag::C, pvs: f.pvs.clone(), write: None }).collect();
    let roots = absorbed.map(|a| a.root);
    (1..=members.len())
        .find(|&n| {
            // Each prefix carries its own deposit total, as a wrapper of n would.
            let d_batch = files[..n].iter().try_fold(0u64, |a, f| a.checked_add(f.value));
            d_batch.is_none_or(|d_batch| {
                let inp = WInputs { prev: prev.commitment, rkm_seq: keys.rkm(), absorbed: roots, d_batch };
                state.clone().apply(&inp, &members[..n]).is_err()
            })
        })
        .map(|n| n - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::tests::{w3c_chain, W3C_CLAIM};
    use crate::state::RunState;

    fn w3c_file() -> qlab_l2spend::ClaimFile {
        let c = w3c_chain();
        qlab_l2spend::decode_claim_artifact(W3C_CLAIM, &c.genesis, c.claim_fee_tier).unwrap()
    }

    fn anchor_of(file: &qlab_l2spend::ClaimFile) -> Anchor {
        let root = Member { tag: WTag::C, pvs: file.pvs.clone(), write: None }.digest_at(qlab_air::claim::PV_A).unwrap();
        Anchor { count: 0, root }
    }

    /// Any count but K is refused by name — S4 plans no fillers, and takes
    /// no more than a wrapper holds.
    #[test]
    fn not_k_claims_is_refused() {
        let (state, prev) = RunState::new([0; 32], 1, "t").replay().unwrap();
        let f = w3c_file();
        let a = anchor_of(&f);
        let keys = Keys::from_seed([1; 32]);
        for n in [K - 1, K + 1] {
            let err = plan_claims(&state, &prev, [a; M_ABS], vec![f.clone(); n], &[], &keys).err().unwrap();
            assert_eq!(err, PlanError::WrongCount { have: n, need: K });
        }
    }

    /// A claim whose anchor this wrapper does not absorb (and no earlier one
    /// did) is refused by name, before the native statement.
    #[test]
    fn a_claim_under_an_unabsorbed_root_is_refused() {
        let (state, prev) = RunState::new([0; 32], 1, "t").replay().unwrap();
        let f = w3c_file();
        let a = anchor_of(&f);
        let other = Anchor { count: 0, root: [7; 4] };
        let err = plan_claims(&state, &prev, [other; M_ABS], vec![f; K], &[], &Keys::from_seed([1; 32])).err().unwrap();
        assert_eq!(err, PlanError::ClaimAnchorNotAbsorbed { root: a.root });
    }

    /// A pass emits claims and S fillers, never R (nor P): the guard passes
    /// such a member list and names the first other member.
    #[test]
    fn a_pass_emits_only_its_member_tags() {
        assert_eq!(PASS_MEMBER_TAGS, [WTag::C, WTag::S]);
        assert!(!PASS_MEMBER_TAGS.contains(&WTag::R));
        let c = Member { tag: WTag::C, pvs: w3c_file().pvs, write: None };
        let mut ok = vec![c.clone(); K];
        ok[9] = Member { tag: WTag::S, ..c.clone() };
        assert_eq!(pass_members_ok(&ok), Ok(()));
        for (t, name) in [(WTag::R, "R"), (WTag::P, "P")] {
            let mut ms = ok.clone();
            ms[5] = Member { tag: t, ..c.clone() };
            let err = pass_members_ok(&ms).unwrap_err();
            assert!(err.starts_with(&format!("member 5 is {name}:")) && err.contains("only C, S members"), "{err}");
        }
    }

    /// `n` sequencer notes in C, as earlier wrappers would have left them.
    fn seeded(n: usize, keys: &Keys) -> (WState, Surface, Vec<Owned>) {
        let (mut state, prev) = RunState::new([0; 32], 1, "t").replay().unwrap();
        let owned: Vec<Owned> = (0..n as u64).map(|i| Owned { value: 1_000 * i, rho: [i + 1, 2, 3, 4], rseed: [i + 1, 5, 6, 7] }).collect();
        for o in &owned {
            qlab_wprover::f3::native::append(&mut state.l2.c, &o.cm(keys));
        }
        (state, prev, owned)
    }

    /// A filler moves no value: its two outputs (change = the input whole, a
    /// zero) sum to the note it spends, and after the native statement both
    /// are spendable by the sequencer while the spent note is not — so the
    /// sequencer's owned total is unchanged and its note count grows by one.
    #[test]
    fn a_filler_moves_no_value() {
        assert_eq!(FILLER_FEE, 0);
        let keys = Keys::from_seed([1; 32]);
        let (state, prev, owned) = seeded(2, &keys);
        let n = owned[1];
        assert_eq!(n.value, 1_000);
        let (inst, made) = filler(&state, &keys, 0, 3, &n).unwrap();
        assert_eq!(made.map(|m| m.value), [1_000, 0]);
        let m = inst.member();
        assert_eq!(m.tag, WTag::S);
        let inp = WInputs { prev: prev.commitment, rkm_seq: keys.rkm(), absorbed: [[9, 9, 9, 9]; M_ABS], d_batch: 0 };
        let mut after = state.clone();
        after.apply(&inp, &[m]).unwrap();
        assert_eq!(spendable(&after, &keys, &[n]), Vec::<Owned>::new(), "the spent note is spent");
        assert_eq!(spendable(&after, &keys, &made), made.to_vec(), "both outputs are the sequencer's to spend");
    }

    /// One claim filled to K: fifteen S fillers from fifteen owned notes,
    /// marked as such; the credits are every filler output plus the fee
    /// note, all spendable once the wrapper applies, and their total is the
    /// notes spent plus the claim's fee. One note short is refused by name.
    #[test]
    fn one_claim_is_filled_to_k() {
        let keys = Keys::from_seed([1; 32]);
        let (state, prev, owned) = seeded(K - 1, &keys);
        let f = w3c_file();
        let a = anchor_of(&f);
        let err = plan_claims(&state, &prev, [a; M_ABS], vec![f.clone()], &owned[..K - 2], &keys).err().unwrap();
        assert_eq!(err, PlanError::WrongCount { have: K - 1, need: K });
        let err = plan_claims(&state, &prev, [a; M_ABS], Vec::new(), &owned, &keys).err().unwrap();
        assert_eq!(err, PlanError::NoClaim, "never a wrapper of padding alone");
        let p = plan_claims(&state, &prev, [a; M_ABS], vec![f], &owned, &keys).unwrap();
        assert_eq!(p.members.iter().map(|m| m.tag).collect::<Vec<_>>(), [vec![WTag::C], vec![WTag::S; K - 1]].concat());
        assert_eq!(p.filler, [vec![false], vec![true; K - 1]].concat());
        assert_eq!(pass_members_ok(&p.members), Ok(()));
        let mut by_value = owned.clone();
        by_value.reverse();
        assert_eq!(p.spent, by_value, "largest first");
        assert_eq!(p.credited.len(), 2 * (K - 1) + 1, "two outputs per filler and the fee note");
        let fee = qlab_wprover::f4::wleaf::fee_of(&p.members);
        let total = |ns: &[Owned]| ns.iter().map(|n| n.value).sum::<u64>();
        assert_eq!(total(&p.credited), total(&owned) + fee);
        let mut after = state.clone();
        after.apply(&p.inp, &p.members).unwrap();
        assert_eq!(spendable(&after, &keys, &p.credited), p.credited, "every credit is the sequencer's to spend");
        assert!(spendable(&after, &keys, &owned).is_empty());
    }

    /// Zero-valued notes (one per filler) are drawn last: spendable orders
    /// by value, largest first, stably; a spent or unknown note is never
    /// offered, nor one listed twice.
    #[test]
    fn spendable_draws_zero_notes_last() {
        let keys = Keys::from_seed([1; 32]);
        let (state, _, owned) = seeded(4, &keys);
        // owned values: 0, 1000, 2000, 3000; a stranger's note is not in C.
        let stranger = Owned { value: 9_000, rho: [8; 4], rseed: [8; 4] };
        let listed = [owned[0], owned[2], stranger, owned[1], owned[3], owned[2]];
        let got: Vec<u64> = spendable(&state, &keys, &listed).iter().map(|n| n.value).collect();
        assert_eq!(got, [3_000, 2_000, 1_000, 0]);
    }

    /// A claim built with `seed`'s credit is recognised from its public values
    /// alone, as the note it creates; the same burn claimed to anyone else's
    /// key — or to this key with any other rseed, or under another seed — is
    /// not. Both ways, so a wallet's claim can never be counted as ours.
    #[test]
    fn a_seed_claim_is_recognised_and_a_foreign_one_never() {
        use qlab_air::claim::{l1_cm, rkm_burn};
        let keys = Keys::from_seed([1; 32]);
        let note = BurnNote { value: 5_000, rkm: rkm_burn(1), rho: [1; 4], rseed: [2; 4] };
        let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
        let mut tree = qlab_cbserver::tree::CommitmentTree::new();
        tree.append(cm);
        let cnf = claim_cnf(&cm, &note.rseed);
        let fee = 4;
        let claim = |credit: &ClaimCredit| qlab_l2spend::claim_instance(&tree, 1, &note, 1, &[5; 4], credit, fee).unwrap().pvs;
        let ours = claim(&keys.seed_credit(&cnf));
        assert_eq!(own_credit(&ours, note.value, &keys), Some(Owned { value: note.value - fee, rho: cnf, rseed: keys.seed_rseed(&cnf) }));
        assert_eq!(own_credit(&ours, note.value + 1, &keys), None, "a stated value that is not the claim's");
        assert_eq!(own_credit(&ours, note.value, &Keys::from_seed([2; 32])), None, "another sequencer's seed");
        let wallet = claim(&ClaimCredit { rkm: [3; 4], rseed: [4; 4] });
        assert_eq!(own_credit(&wallet, note.value, &keys), None, "a wallet's claim");
        let our_key_other_rseed = claim(&ClaimCredit { rkm: keys.rkm(), rseed: [4; 4] });
        assert_eq!(own_credit(&our_key_other_rseed, note.value, &keys), None, "our rkm but not the seed rseed");
    }

    /// Elimination names the culprit: with sixteen copies of one claim, the
    /// first applies and the second repeats its cnf — item 1.
    #[test]
    fn elimination_names_the_repeated_claim() {
        let (state, prev) = RunState::new([0; 32], 1, "t").replay().unwrap();
        let f = w3c_file();
        let a = anchor_of(&f);
        assert_eq!(first_refused(&state, &prev, &[a; M_ABS], &vec![f; K], &Keys::from_seed([1; 32])), Some(1));
    }

    /// Sixteen copies of one claim get past the cheap checks and reach the
    /// native statement — the sequencer's prefilter — which refuses the
    /// batch (it repeats one cnf sixteen times). Intake's dedupe is a
    /// convenience; this refusal, and the node's, are the guarantee. The test
    /// pins that the refusal comes from the statement, not which check fires.
    #[test]
    fn the_native_statement_refuses_a_repeated_claim() {
        let (state, prev) = RunState::new([0; 32], 1, "t").replay().unwrap();
        let f = w3c_file();
        let a = anchor_of(&f);
        let err = plan_claims(&state, &prev, [a; M_ABS], vec![f; K], &[], &Keys::from_seed([1; 32])).err().unwrap();
        assert!(matches!(err, PlanError::Wrapper(_)), "{err:?}");
    }
}
