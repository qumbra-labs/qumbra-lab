//! F5-6 (1) lane tests: f5box's chain client and member builders over a real
//! V6 chain (`MemNode`, every coinbase paid to `rkm_burn(1)`, real committee
//! records, served through the node's own route cores), each wrapper checked
//! by the native statement. No member is proven here (7–31 GiB each); one
//! instance of each shape is scanned against its own AIR instead.
use std::sync::OnceLock;

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::committee::{Checkpoint, Committee, Validator};
use qlab_devnet::finality_record::FinalityRecord;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_node::{anchor_set, genesis_block_v6, ChainStore, MemNode, NodeState, V6Setup};
use qlab_wrapper::codec::{digest_to_bytes, exit_chain, stated_surface, Exit};
use qlab_wrapper::genesis::genesis_surface;
use qlab_wrapper::verify::Surface;
use qumbra_node::bundle::WrapperRule;
use qumbra_node::discovery_server::{respond_coinbase, respond_leaves, DiscoveryView, LeavesView};
use qumbra_node::genesis_v6::{v6_genesis_registry, v6_genesis_registry_root, GenesisFileV6, WrapperParams, REHEARSAL_GENESIS_SURFACE};

use super::chain::{self, ChainView, Get};
use super::members::{plan, Ask, Chain, Inst, Keys, Plan, PlanError, TX_FEE};
use crate::f4::bench::default_kinds;
use crate::f4::native::{WState, WTag};
use crate::f4::wleaf::{fee_of, w_pvs};

const NET_ID: Hash32 = [0x6b; 32];
/// The exit recipient: any nonzero L1 `rkm`.
const EXIT: Exit = Exit { rkm: [0x0e71_0001, 0x0e71_0002, 0x0e71_0003, 0x0e71_0004], v: 1_000_000 };

fn params() -> WrapperParams {
    WrapperParams::rehearsal()
}

fn form() -> GenesisForm {
    GenesisFileV6::new_rehearsal().forms().0
}

/// Every block's transactions (none) verify.
struct NoTxs;
impl TxVerifier for NoTxs {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

/// A V6 chain whose every coinbase pays `rkm_burn(l2_id)`, a record of each
/// cadence height carried by the next block and finalized locally there.
struct Box6 {
    node: MemNode,
    validators: Vec<Validator>,
}

impl Box6 {
    fn new() -> Self {
        let validators: Vec<Validator> = (0..21u8).map(|i| Validator::from_seed(i as usize, [i ^ 0x5e; 32])).collect();
        let committee0 = Committee::from_keys(validators.iter().map(Validator::verifying_key).collect());
        let rule = WrapperRule::from_params(NET_ID, &params()).expect("the rehearsal parameters");
        let node = MemNode::in_memory_v6(genesis_block_v6(8, 0), V6Setup { committee0, wrapper: Some(rule.into_setup()) });
        Box6 { node, validators }
    }

    /// Mine up to `height`, recording every eighth.
    fn mine_to(&mut self, height: u64) {
        let burn = qlab_air::claim::rkm_burn(params().l2_id);
        while self.node.tip_height() < height {
            let parent = self.node.chain().block(&self.node.tip_hash()).expect("the tip").header();
            let (h, record) = (parent.height + 1, parent.height > 0 && parent.height.is_multiple_of(8));
            let mut body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(h), burn);
            if record {
                let cp = Checkpoint::new(parent.height, self.node.tip_hash(), self.node.tip_hash());
                body.finality = FinalityRecord { cp, votes: self.validators[..15].iter().map(|v| v.sign_checkpoint(&cp)).collect() }.encode();
            }
            let header = BlockHeader::child_of_for(GenesisForm::V5, &parent, parent.timestamp + 75, 8, body.commitment_v6());
            let recorded = self.node.tip_hash();
            self.node.apply_block(header, body, &NoTxs).expect("the block applies");
            if record {
                assert!(self.node.finalize(recorded).expect("finalize").is_recorded());
            }
        }
    }

    /// The node's served routes, through the server's own socket-free cores.
    fn view(&self) -> ChainView {
        chain::read(&Routes::of(&self.node)).expect("the chain reads")
    }
}

/// `/v1/anchors`, `/v1/tree/leaves`, `/v1/coinbase` over a snapshot.
struct Routes {
    anchors: Vec<u8>,
    leaves: LeavesView,
    discovery: DiscoveryView,
}

impl Routes {
    fn of(node: &MemNode) -> Self {
        let mut discovery = DiscoveryView::default();
        discovery.refresh(node.chain());
        Routes {
            anchors: anchor_set(node).to_bytes(),
            leaves: LeavesView { leaves: node.commitments_ordered().to_vec() },
            discovery,
        }
    }
}

impl Get for Routes {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let r = match route {
            "/v1/anchors" => Ok(self.anchors.clone()),
            "/v1/tree/leaves" => respond_leaves(&self.leaves, query),
            "/v1/coinbase" => respond_coinbase(&self.discovery, query),
            other => return Err(format!("no route {other}")),
        };
        r.map_err(|(code, why)| format!("{path}: {code} {why}"))
    }
}

/// A server that lies in one stream: f5box must refuse, by name.
enum Lie {
    /// `/v1/coinbase` holds heights `0..100` only.
    ShortCoinbase,
    /// `/v1/tree/leaves` answers an empty page under its own total.
    EmptyLeafPage,
    /// `/v1/tree/leaves` serves more leaves than its total.
    LeavesPastTotal,
}

struct Lying(Routes, Lie);

impl Get for Lying {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        let real = self.0.get(path)?;
        if !path.starts_with("/v1/tree/leaves") {
            return Ok(real);
        }
        let mut page = qlab_node::TreeLeaves::from_bytes(&real).expect("the real page decodes");
        match self.1 {
            Lie::EmptyLeafPage => page.leaves.clear(),
            Lie::LeavesPastTotal => page.total = 3,
            Lie::ShortCoinbase => {}
        }
        Ok(page.to_bytes())
    }
}

/// The run: the chain at four tips, and both wrappers planned on it.
struct Run {
    /// Nothing recorded yet (tip 7).
    early: ChainView,
    /// Eight burns matured, record 152 (tip 153).
    short: ChainView,
    /// Sixteen matured, record 160 (tip 161): the deposit.
    deposit_view: ChainView,
    /// Twenty-four matured, record 168 (tip 169): the mix.
    mix_view: ChainView,
    keys: Keys,
    state0: WState,
    prev0: Surface,
    deposit: Plan,
    state1: WState,
    prev1: Surface,
    mix: Plan,
    /// After the mix.
    state2: WState,
    /// The tip-169 routes, for the lying-server cases.
    routes: Routes,
}

fn chain_of(view: &ChainView) -> Chain<'_> {
    Chain { view, l2_id: params().l2_id, fee_tier: params().claim_fee_tier }
}

/// The surface a wrapper states (what `verify_wrapper` returns on success).
fn surface_after(p: &Plan) -> Surface {
    let pvs: Vec<u32> = w_pvs(&p.rin, &p.rout, &p.inp, fee_of(&p.members), &p.exit_cmt)
        .iter()
        .map(p3_field::PrimeField32::as_canonical_u32)
        .collect();
    stated_surface(1, params().l2_id, &pvs).expect("16-bit PVs")
}

fn run() -> &'static Run {
    static R: OnceLock<Run> = OnceLock::new();
    R.get_or_init(|| {
        let mut b = Box6::new();
        b.mine_to(7);
        let early = b.view();
        b.mine_to(153);
        let short = b.view();
        b.mine_to(161);
        let deposit_view = b.view();
        b.mine_to(169);
        let mix_view = b.view();
        let routes = Routes::of(&b.node);

        let keys = Keys::from_text("f5box lane");
        let state0 = WState::genesis(&v6_genesis_registry());
        let prev0 = genesis_surface(params().l2_id, &v6_genesis_registry_root());
        let claims = vec![WTag::C; 16];
        let burns = deposit_view.burns(form(), params().l2_id).expect("the burns");
        let ask = Ask { kinds: &claims, burns: &burns, owned: &[], exit: None };
        let deposit = plan(&state0, &prev0, &chain_of(&deposit_view), &keys, &ask).expect("the deposit plans");
        let mut state1 = state0.clone();
        state1.apply(&deposit.inp, &deposit.members).expect("and applies");
        let prev1 = surface_after(&deposit);

        let kinds = default_kinds(16);
        let burns = mix_view.burns(form(), params().l2_id).expect("the burns");
        let ask = Ask { kinds: &kinds, burns: &burns, owned: &deposit.credited, exit: Some(EXIT) };
        let mix = plan(&state1, &prev1, &chain_of(&mix_view), &keys, &ask).expect("the mix plans");
        let mut state2 = state1.clone();
        state2.apply(&mix.inp, &mix.members).expect("and applies");
        Run { early, short, deposit_view, mix_view, keys, state0, prev0, deposit, state1, prev1, mix, state2, routes }
    })
}

/// The absorbed roots are the four newest served anchors, oldest first, at
/// exactly `counts`; every claim opens at the newest.
fn assert_absorbed(p: &Plan, view: &ChainView, counts: [u64; 4]) {
    assert_eq!(p.absorbed.map(|a| a.count), counts);
    let served: Vec<Hash32> = view.anchors.roots[..4].iter().rev().copied().collect();
    assert_eq!(p.absorbed.map(|a| digest_to_bytes(&a.root)).to_vec(), served, "the four newest served roots, oldest first");
    for a in &p.absorbed {
        assert_eq!(view.tree.root_at(a.count), a.root);
    }
    let newest = p.absorbed[3];
    for (inst, burn) in p.insts.iter().filter_map(|i| if let Inst::C(c) = i { Some(c) } else { None }).zip(&p.claimed) {
        assert_eq!(inst.anchor, newest.root);
        assert_eq!(inst.cm, burn.cm, "the claim opens the burn's leaf");
        assert!(burn.pos < newest.count);
    }
}

/// The genesis the run threads from is the pinned rehearsal surface, and
/// every burn the chain matured is found: the coinbase stream, the form and
/// the leaf stream agree on every commitment.
#[test]
fn f5box_reads_the_burns_the_chain_appended() {
    let r = run();
    assert_eq!(r.prev0.commitment, REHEARSAL_GENESIS_SURFACE);
    assert_eq!(r.prev0.out, r.state0.roots());
    // Heights 1..=24 have matured by tip 169 (leaf at h + 144), in order.
    let burns = r.mix_view.burns(form(), params().l2_id).expect("the burns");
    assert_eq!(burns.iter().map(|b| b.height).collect::<Vec<_>>(), (1..=25).collect::<Vec<_>>());
    assert_eq!(burns.iter().map(|b| b.pos).collect::<Vec<_>>(), (0..25).collect::<Vec<_>>());
    assert!(burns.iter().all(|b| b.note.rkm == qlab_air::claim::rkm_burn(params().l2_id)));
    // The younger ones are named with the height their leaf appears at.
    let young = r.mix_view.immature_burns(params().l2_id);
    assert_eq!(young.first(), Some(&(26, 170)));
    assert_eq!(young.len(), 169 - 25);
    // Under any other form the first matured burn rebuilds to no leaf, and
    // the read says which: the form is load-bearing, and a miss is named.
    let e = r.mix_view.burns(GenesisForm::V4, params().l2_id).unwrap_err();
    assert!(e.contains("minted at 1 "), "{e}");
}

/// The deposit: sixteen claims at the genesis surface, every absorbed root a
/// served anchor, `D_batch` the burns' sum, sixteen credits to this run.
#[test]
fn f5box_the_deposit_is_sixteen_claims_over_the_served_tree() {
    let r = run();
    let p = &r.deposit;
    assert!(p.members.iter().all(|m| m.tag == WTag::C) && p.members.len() == 16);
    assert_absorbed(p, &r.deposit_view, [13, 14, 15, 16]);
    let sum: u64 = p.claimed.iter().map(|b| b.note.value).sum();
    assert_eq!(p.inp.d_batch, sum);
    assert_eq!((p.rout.d_cum, p.rout.e_cum), (sum, 0));
    assert_eq!(p.inp.prev, REHEARSAL_GENESIS_SURFACE);
    assert_eq!(p.credited.len(), 16);
    for (c, b) in p.credited.iter().zip(&p.claimed) {
        assert_eq!(c.value, b.note.value - params().claim_fee_tier);
    }
    // The claims' surfaces pass the verifier's own pre-proof checks: the
    // chain's burn address and the genesis tariff.
    for m in &p.members {
        let pvs = qlab_l2::public_values(&m.pvs);
        assert_eq!(qlab_l2::claim::check_claim_surface(&pvs, params().l2_id, params().claim_fee_tier), Ok(()));
    }
    assert!(p.exits.is_empty() && p.exit_cmt == [0; 4]);
    assert_eq!(r.state1.roots(), p.rout);
    // Every credit is a real note: its commitment is in C after the deposit.
    for c in &p.credited {
        assert!(r.state1.l2.c.position_of(&c.cm(&r.keys)).is_some(), "credit {c:?} is in C");
    }
}

/// The mix: `default_kinds(16)` over the deposit's notes — R moves the
/// registry and only the member after it reads the new root, every
/// transaction anchors at the wrapper's `C_in`, the first P pays the exit and
/// nothing else exits, four fresh burns are claimed.
#[test]
fn f5box_the_mix_spends_the_deposit_and_pays_the_exit() {
    let r = run();
    let p = &r.mix;
    assert_eq!(p.members.iter().map(|m| m.tag).collect::<Vec<_>>(), default_kinds(16));
    assert_eq!(p.inp.prev, r.prev1.commitment);
    assert_absorbed(p, &r.mix_view, [21, 22, 23, 24]);
    let c_in = r.state1.l2.c.root();
    let (reg_before, reg_after) = (r.state1.l2.r.root(), p.rout.f3.r);
    assert_ne!(reg_before, reg_after, "R wrote the registry");
    for (slot, inst) in p.insts.iter().enumerate() {
        let (anchor, regroot) = match inst {
            Inst::S(i) => (i.anchor, Some(i.registry_root)),
            Inst::P(i) => (i.anchor, Some(i.registry_root)),
            Inst::R(i, _) => (i.anchor, None),
            Inst::C(_) => continue,
        };
        assert_eq!(anchor, c_in, "slot {slot} anchors at C_in");
        if let Some(root) = regroot {
            assert_eq!(root, if slot < 1 { reg_before } else { reg_after }, "slot {slot} reads the registry at its slot");
        }
    }
    // The exit: the first P only, asset 0 redeemed to the recipient.
    assert_eq!(p.exits, vec![EXIT]);
    assert_eq!(p.exit_cmt, exit_chain(&[EXIT]));
    assert_eq!(p.rout.e_cum, EXIT.v);
    assert!(p.rout.e_cum <= p.rout.d_cum);
    let Inst::P(first) = &p.insts[0] else { panic!("slot 0 is P") };
    assert_eq!(&first.pvs[qlab_air::l2p::PV_XRKM..qlab_air::l2p::PV_XRKM + 16], &qlab_air::narrow::pv_chunks(&EXIT.rkm)[..]);
    // Twelve spends, four claims of burns the deposit did not take.
    assert_eq!(p.spent.len(), 12);
    assert_eq!(p.spent, r.deposit.credited[..12]);
    assert_eq!(p.claimed.iter().map(|b| b.height).collect::<Vec<_>>(), vec![17, 18, 19, 20]);
    // Change: every spend returns `v − fee` (− the exit, slot 0) to this run,
    // as a real note — its commitment is the one the member published, and
    // it is in C after the mix (S/P change, R change and the claim credits).
    assert_eq!(p.credited[0].cm(&r.keys), first.cm_out[0], "slot 0's change is its first output");
    assert_eq!(p.credited[0].value, r.deposit.credited[0].value - TX_FEE - EXIT.v);
    assert_eq!(p.credited.len(), 12 + 4);
    for c in &p.credited {
        assert!(r.state2.l2.c.position_of(&c.cm(&r.keys)).is_some(), "credit {c:?} is in C");
    }
}

/// A plan that cannot be built is refused by name, and the state it was
/// asked on is untouched.
#[test]
fn f5box_plan_refusals_are_named() {
    let r = run();
    let claims = vec![WTag::C; 16];
    let ask = |burns: &'static [super::chain::Burn]| Ask { kinds: &claims, burns, owned: &[], exit: None };
    let leak = |v: Vec<super::chain::Burn>| -> &'static [super::chain::Burn] { Box::leak(v.into_boxed_slice()) };

    // Nothing recorded: no anchor.
    let burns = leak(r.early.burns(form(), params().l2_id).unwrap());
    let e = plan(&r.state0, &r.prev0, &chain_of(&r.early), &r.keys, &ask(burns)).err();
    assert_eq!(e, Some(PlanError::NoAnchor));
    // Record 152 covers eight matured burns: sixteen claims cannot be built.
    let burns = leak(r.short.burns(form(), params().l2_id).unwrap());
    let e = plan(&r.state0, &r.prev0, &chain_of(&r.short), &r.keys, &ask(burns)).err();
    assert_eq!(e, Some(PlanError::Burns { need: 16, have: 8 }));
    // A burn is claimed once: on the post-deposit state the sixteen are spent
    // claims, and only the four the deposit's anchor did not cover remain.
    let burns = leak(r.mix_view.burns(form(), params().l2_id).unwrap());
    let e = plan(&r.state1, &r.prev1, &chain_of(&r.mix_view), &r.keys, &ask(burns)).err();
    assert_eq!(e, Some(PlanError::Burns { need: 16, have: 8 }));
    // The mix needs twelve notes; the genesis state owns none.
    let kinds = default_kinds(16);
    let a = Ask { kinds: &kinds, burns, owned: &r.deposit.credited, exit: Some(EXIT) };
    assert_eq!(plan(&r.state0, &r.prev0, &chain_of(&r.mix_view), &r.keys, &a).err(), Some(PlanError::Notes { need: 12, have: 0 }));
    // A note is spent once: after the mix, its twelve spent notes are gone.
    let e = plan(&r.state2, &surface_after(&r.mix), &chain_of(&r.mix_view), &r.keys, &a).err();
    assert_eq!(e, Some(PlanError::Notes { need: 12, have: 4 }));
    // An exit the first P's note cannot pay.
    let big = Exit { v: r.deposit.credited[0].value, ..EXIT };
    let a = Ask { exit: Some(big), ..a };
    let e = plan(&r.state1, &r.prev1, &chain_of(&r.mix_view), &r.keys, &a).err();
    assert_eq!(e, Some(PlanError::ExitAboveNote { note: r.deposit.credited[0].value, fee: TX_FEE, exit: big.v }));
    // An exit with no P to carry it; two writes in one wrapper.
    let a = Ask { kinds: &claims, burns, owned: &[], exit: Some(EXIT) };
    assert_eq!(plan(&r.state1, &r.prev1, &chain_of(&r.mix_view), &r.keys, &a).err(), Some(PlanError::ExitWithoutP));
    let two_r = [WTag::R, WTag::P, WTag::R];
    let a = Ask { kinds: &two_r, burns, owned: &r.deposit.credited, exit: None };
    assert_eq!(plan(&r.state1, &r.prev1, &chain_of(&r.mix_view), &r.keys, &a).err(), Some(PlanError::SecondR));
    // The deposit run left its inputs as they were.
    assert_eq!(r.state0.roots(), r.prev0.out);
}

/// One member of each shape, as f5box builds it, satisfies its own AIR on
/// every row: the exit P (dummy slot 1, asset-0 redeem), R (a registration),
/// an S after R (the written registry), a claim over the served L1 tree.
/// What the lane can say about provability short of proving.
#[test]
fn f5box_built_members_satisfy_their_circuits() {
    use qlab_consensus::Val;
    let r = run();
    for slot in [0usize, 1, 3, 5] {
        let inst = &r.mix.insts[slot];
        let pvs = qlab_l2::public_values(inst.pvs());
        let verdict = match inst {
            Inst::P(i) => qlab_air::l2test::satisfied(&i.air, &i.air.generate_trace::<Val>(0), &pvs),
            Inst::R(i, _) => qlab_air::l2test::satisfied(&i.air, &i.air.generate_trace::<Val>(0), &pvs),
            Inst::S(i) => qlab_air::l2test::satisfied(&i.air, &i.air.generate_trace::<Val>(0), &pvs),
            Inst::C(i) => qlab_air::l2test::satisfied(&i.air, &i.air.generate_trace::<Val>(0), &pvs),
        };
        assert!(verdict.is_ok(), "slot {slot} ({:?}): {verdict:?}", inst.tag());
    }
}

/// Every stream must be whole: a server that serves a short coinbase stream,
/// an empty leaf page under its own total, or more leaves than its total is
/// refused by name — never read as a shorter chain.
#[test]
fn f5box_a_short_or_lying_stream_is_refused() {
    let r = run();
    let mut short = Routes { anchors: r.routes.anchors.clone(), leaves: LeavesView { leaves: r.routes.leaves.leaves.clone() }, discovery: r.routes.discovery.clone() };
    short.discovery.blocks.truncate(100);
    let e = chain::read(&Lying(short, Lie::ShortCoinbase)).err().expect("refused");
    assert!(e.contains("/v1/coinbase: an empty page at 100 below the tip 169"), "{e}");
    let again = |lie| Lying(Routes { anchors: r.routes.anchors.clone(), leaves: LeavesView { leaves: r.routes.leaves.leaves.clone() }, discovery: r.routes.discovery.clone() }, lie);
    let e = chain::read(&again(Lie::EmptyLeafPage)).err().expect("refused");
    assert!(e.contains("an empty page at 0 of a total of 25"), "{e}");
    let e = chain::read(&again(Lie::LeavesPastTotal)).err().expect("refused");
    assert!(e.contains("25 leaves past 0 served with a total of 3"), "{e}");
    // The honest routes read whole.
    assert!(chain::read(&r.routes).is_ok());
}
