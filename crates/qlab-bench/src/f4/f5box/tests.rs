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

// ---------------------------------------------------------------------------
// (c)+(d)+(e): the state file, the assembly, the signature, the command
// ---------------------------------------------------------------------------

use super::bundle::{assemble, manifest, rehearsal_signer, self_check, sign, BundleBytes, Proofs, Timings};
use super::run::{burn_rkm_hex, parse, Build, Cmd};
use super::state::{plan_surface, RunState};
use qlab_devnet::body::{BundleRefusal, BundleVerifier};
use qlab_wrapper::codec::{encode_surface, WireBundle};

/// The run's state after the deposit, and after the mix.
fn states() -> (RunState, RunState) {
    let r = run();
    let mut s = RunState::new(NET_ID, params().l2_id, "f5box lane");
    s.push(&r.deposit);
    let one = s.clone();
    s.push(&r.mix);
    (one, s)
}

/// The state file round-trips through its JSON, and replaying it rebuilds
/// exactly the state and surface each next bundle threads from.
#[test]
fn f5box_the_state_file_replays_what_was_built() {
    let r = run();
    let (one, two) = states();
    for (s, state, prev) in [(&one, &r.state1, &r.prev1), (&two, &r.state2, &surface_after(&r.mix))] {
        let back = RunState::from_json(&s.to_json()).expect("round trip");
        assert_eq!(back.to_json(), s.to_json());
        let (st, pv) = back.replay().expect("replays");
        assert_eq!((st.roots(), pv.commitment), (state.roots(), prev.commitment));
    }
    assert_eq!(two.owned.len(), 16 + 16);
    assert_eq!(plan_surface(params().l2_id, &r.deposit).unwrap().commitment, r.prev1.commitment);
    // Written and read back from disk, atomically.
    let dir = std::env::temp_dir().join(format!("f5box-state-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.json");
    two.save(&path).expect("saves");
    assert_eq!(RunState::load(&path).expect("loads").to_json(), two.to_json());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A state file that does not thread is refused by bundle index, never
/// trusted: a member's PV changed, a `prev` changed, an exit dropped, an
/// unknown format.
#[test]
fn f5box_a_tampered_state_file_is_refused() {
    let (_, two) = states();
    let mut bad = two.clone();
    bad.bundles[0].members[3].pvs[qlab_air::claim::PV_CM2] ^= 1;
    let e = bad.replay().err().expect("refused");
    assert!(e.starts_with("bundle 1 does not thread"), "{e}");
    let mut bad = two.clone();
    bad.bundles[1].inp.prev[0] ^= 1;
    assert_eq!(bad.replay().err().as_deref(), Some("bundle 1 does not thread from its predecessor's surface"));
    let mut bad = two.clone();
    bad.bundles[1].exits.clear();
    assert_eq!(bad.replay().err().as_deref(), Some("bundle 1: the exit list does not chain to its exit_cmt"));
    // A reordered wrapper is a different wrapper: it replays, to a surface
    // its successor does not thread from.
    let mut bad = two.clone();
    bad.bundles[0].members.swap(0, 1);
    assert_eq!(bad.replay().err().as_deref(), Some("bundle 1 does not thread from its predecessor's surface"));
    let mut v = two.to_json();
    v["format"] = 2.into();
    assert!(RunState::from_json(&v).unwrap_err().starts_with("state format 2"));
}

/// Stub proofs: a real W-config proof object (the F5-4b fixture's), the
/// deposit-sum proof proven for real (2^10 rows), each member a copy of it.
fn stub_bundle(p: &Plan, net: &Hash32) -> (WireBundle, Vec<u8>) {
    let (dep_pvs, dep) = crate::f4::dep::prove_dep(&p.deps).expect("the openings fit");
    let copy = |q: &qlab_consensus::Proof<qlab_consensus::Config>| -> qlab_consensus::Proof<qlab_consensus::Config> {
        bincode::deserialize(&bincode::serialize(q).unwrap()).unwrap()
    };
    let members = p.insts.iter().map(|_| copy(&dep)).collect();
    let proofs = Proofs { w: crate::f4::bundle_node::w_proof_stub(), dep_pvs, dep, members };
    let mut wb = assemble(p, params().l2_id, proofs).expect("one proof per member");
    sign(&mut wb, &rehearsal_signer(&params()).expect("the rehearsal key"), net).expect("signs");
    let bytes = wb.encode();
    (wb, bytes)
}

/// The assembly through the node's own rule: both bundles, signed by the
/// rehearsal sequencer, pass every check the rule makes before the member
/// proofs — codec, `l2_id`, exit shape, signature, V8, V5–V7 (the served
/// anchors), V1 — and are refused exactly at member 0's stub proof; the
/// proof-free fold accepts them and states the plan's surface, exits and
/// counters; signed for another net, the signature refuses; the manifest's
/// byte parts reconcile to the encoding.
#[test]
fn f5box_the_assembled_bundle_meets_the_node_rule_up_to_the_member_proofs() {
    let r = run();
    let rule = WrapperRule::from_params(NET_ID, &params()).expect("the rule");
    for (p, prev, view) in [(&r.deposit, &r.prev0, &r.deposit_view), (&r.mix, &r.prev1, &r.mix_view)] {
        let (wb, bytes) = stub_bundle(p, &NET_ID);
        assert_eq!(WireBundle::decode(&bytes).expect("decodes").encode(), bytes, "canonical");
        match self_check(&rule, &bytes, prev, view) {
            Err(BundleRefusal::Wrapper(v)) => assert!(v.starts_with("Member(0,"), "refused at {v}"),
            other => panic!("expected the member-0 refusal, got {other:?}"),
        }
        let out = rule.fold_bundle(&encode_surface(prev), &bytes).expect("the fold accepts");
        assert_eq!(out.surface, encode_surface(&plan_surface(params().l2_id, p).unwrap()).to_vec());
        assert_eq!(out.exits, p.exits.iter().map(|e| (digest_to_bytes(&e.rkm), e.v)).collect::<Vec<_>>());
        assert_eq!((out.d_batch, out.e_batch), (p.inp.d_batch, p.exits.iter().map(|e| e.v).sum::<u64>()));
        let (_, other_net) = stub_bundle(p, &[0x6c; 32]);
        assert_eq!(self_check(&rule, &other_net, prev, view).err(), Some(BundleRefusal::Signature));
        let m = manifest(p, &wb, &bytes, &NET_ID, params().wrapper_spacing_blocks, view, &Timings::new());
        assert_eq!(m["bytes"]["total"], bytes.len());
        assert_eq!(m["bytes_reconciled"], true);
        assert_eq!(m["wrapper_spacing_blocks"], 48);
        assert_eq!(BundleBytes::of(&wb).total(), bytes.len());
        assert_eq!(m["members"].as_array().unwrap().len(), 16);
        assert_eq!(m["absorbed"].as_array().unwrap().len(), 4);
        assert_eq!(m["exits"].as_array().unwrap().len(), p.exits.len());
        assert_eq!(m["prev_surface"], super::state::digest_hex(&prev.commitment));
    }
}

/// The command line: every refusal names its flag; the burn rkm prints in
/// the form `miner_rkm` parses back.
#[test]
fn f5box_the_command_line() {
    let a = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
    assert_eq!(parse(&a("--burn-rkm --genesis g")), Ok(Cmd::BurnRkm { genesis: "g".into() }));
    let first = parse(&a("--genesis g --chain http://n --state s --out o --seed lane")).unwrap();
    assert_eq!(
        first,
        Cmd::Build(Build { genesis: "g".into(), chain: "http://n".into(), state: "s".into(), out: "o".into(), seed: Some("lane".into()), exit: None, check: false })
    );
    let hex = burn_rkm_hex(7);
    assert_eq!(qumbra_node::config::rkm_lanes_from_hex(&hex).unwrap(), qlab_air::claim::rkm_burn(7));
    let next = parse(&a(&format!("--next --genesis g --chain c --state s --out o --exit-rkm {hex} --check"))).unwrap();
    let Cmd::Build(b) = next else { panic!() };
    assert_eq!(b.exit, Some(Exit { rkm: qlab_air::claim::rkm_burn(7), v: qlab_devnet::emission_exact::BESSEL_PER_QMB }));
    assert!(b.check && b.seed.is_none());
    for (args, why) in [
        ("--chain c --state s --out o --seed x", "--genesis is required"),
        ("--genesis g --chain c --state s --out o", "the first run needs --seed"),
        ("--next --genesis g --chain c --state s --out o", "--next needs --exit-rkm"),
        ("--genesis g --chain c --state s --out o --seed x --exit-v 5", "--exit-rkm/--exit-v ride the mix"),
        ("--genesis g --chain c --state s --out o --seed x --bogus", "unknown flag --bogus"),
        ("--genesis --chain c", "--genesis takes a value"),
        ("--genesis g --chain c --state s --out o --seed x stray", "stray argument \"stray\""),
        ("--genesis g --chain c --state s --out o --seed x --chain d", "--chain given twice"),
    ] {
        let e = parse(&a(args)).unwrap_err();
        assert!(e.starts_with(why), "{args}: {e}");
    }
    let with_seed = format!("--next --genesis g --chain c --state s --out o --exit-rkm {hex} --seed x");
    assert!(parse(&a(&with_seed)).unwrap_err().starts_with("--next reads the seed"));
    let zero = format!("--next --genesis g --chain c --state s --out o --exit-rkm {hex} --exit-v 0");
    assert!(parse(&a(&zero)).unwrap_err().starts_with("--exit-v must be nonzero"));
    let all_zero = format!("--next --genesis g --chain c --state s --out o --exit-rkm {}", "0".repeat(64));
    assert!(parse(&a(&all_zero)).unwrap_err().starts_with("--exit-rkm"));

    // The argv `main` really hands the mode (box run, 2026-10-01: `stray
    // argument "f5box"`): the mode token leads, and it is not a stray — for
    // every path. A second one is.
    let real = |s: &str| a(&format!("f5box {s}"));
    assert_eq!(parse(&real("--burn-rkm --genesis g")), Ok(Cmd::BurnRkm { genesis: "g".into() }));
    assert_eq!(parse(&real("--genesis g --chain http://n --state s --out o --seed lane")), Ok(first));
    let Cmd::Build(c) = parse(&real("--genesis g --chain c --state s --out o --seed lane --check")).unwrap() else { panic!() };
    assert!(c.check && c.exit.is_none());
    let Cmd::Build(n) = parse(&real(&format!("--next --genesis g --chain c --state s --out o --exit-rkm {hex} --exit-v 7 --check"))).unwrap() else { panic!() };
    assert_eq!((n.exit.map(|e| e.v), n.check, n.seed), (Some(7), true, None));
    assert_eq!(parse(&real("f5box --burn-rkm --genesis g")).unwrap_err(), "stray argument \"f5box\"");
}

/// A **text lint**: no f5box source names the rule's two test-knob calls.
/// The guarantee itself is structural — `wrapper-test-knobs` is enabled only
/// by qlab-bench's dev-dependency (resolver 2), so the release `f5box` binary
/// links a `WrapperRule` without the knobs; this test only keeps a test-build
/// call from creeping into the command's sources.
#[test]
fn f5box_calls_no_rule_knob() {
    let sources = [
        include_str!("mod.rs"),
        include_str!("chain.rs"),
        include_str!("members.rs"),
        include_str!("state.rs"),
        include_str!("bundle.rs"),
        include_str!("run.rs"),
    ];
    for text in sources {
        for knob in [concat!("for_", "version("), concat!("with_", "members(")] {
            assert!(!text.contains(knob), "an f5box source calls `{knob}`");
        }
    }
}

/// `write_atomic` leaves the new bytes and no temp; the state lock is
/// exclusive while held and free once dropped.
#[test]
fn f5box_atomic_writes_and_the_state_lock() {
    use super::state::{write_atomic, StateLock};
    let dir = std::env::temp_dir().join(format!("f5box-lock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("bundle-0.bin");
    write_atomic(&f, b"one").unwrap();
    write_atomic(&f, b"two").unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"two");
    assert!(!dir.join("bundle-0.bin.tmp").exists());
    let state = dir.join("state.json");
    let held = StateLock::take(&state).expect("free");
    assert!(StateLock::take(&state).err().expect("held").contains("another f5box run holds this state"));
    drop(held);
    assert!(StateLock::take(&state).is_ok());
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// Lab #831 W2: the wallet's exit as a wrapper member
// ---------------------------------------------------------------------------

/// **W2's lane condition** (issue #831 ruling Q1): the exit the CLI writes
/// with `send --net annulet --exit-to … --out FILE` is a member the node's
/// rule takes. The exit P is assembled by the wallet's own code
/// (`qlab_l2spend::exit_instance`, what `build_p_exit` proves) against the
/// mix's state — the note the mix's slot 0 spends, the same recipient — and:
///
/// - its instance satisfies shape P's AIR on every row (provable, short of
///   proving);
/// - its `--out` file (stub proof) decodes, and the PVs the file declares —
///   the node's own surface-to-PV mapping — are exactly the instance's;
/// - swapped into the mix's slot 0, the wrapper's native statement accepts
///   it, and the assembled, signed bundle passes the node's rule up to the
///   member proofs (refused at member 0's stub, as every f5box bundle is),
///   while the proof-free fold pays exactly this exit;
/// - a file of another version, or not an exit file, is refused by name.
#[test]
fn w2_the_wallets_exit_is_a_member_the_node_rule_takes() {
    use qlab_l2spend::{decode_exit_artifact, encode_exit_artifact, exit_entry, exit_instance, exit_member_pvs, ArtifactError, ExitAsk, Recipient};
    use rand::SeedableRng;

    let r = run();
    let reg = &r.state1.l2.r;
    let reg0 = qlab_cbserver::registry::RegistryOpening {
        height: 0,
        root: reg.root(),
        leaf: *reg.leaf(0).expect("asset 0's leaf (F-A)"),
        witness: reg.witness(0).expect("asset 0's leaf"),
    };
    let note = r.deposit.credited[0];
    let ask = ExitAsk { value: EXIT.v, to_rkm: EXIT.rkm };
    let mut rng = rand::rngs::StdRng::seed_from_u64(831);
    let ei = exit_instance(&r.state1.l2.c, &reg0, &r.keys.input(&note), ask, r.keys.rkm(), TX_FEE, &mut rng)
        .expect("the wallet assembles the exit");
    assert_eq!(ei.inst.anchor, r.state1.l2.c.root(), "anchored at the wrapper's C_in");
    assert_eq!(ei.outputs[0].value, note.value - TX_FEE - EXIT.v, "the change");

    let pvs = qlab_l2::public_values(&ei.inst.pvs);
    let verdict = qlab_air::l2test::satisfied(&ei.inst.air, &ei.inst.air.generate_trace::<qlab_consensus::Val>(0), &pvs);
    assert!(verdict.is_ok(), "the wallet's exit P satisfies its AIR: {verdict:?}");

    // The `--out` file, with a stub proof in place of the 30 GiB one.
    let (_, stub) = crate::f4::dep::prove_dep(&r.mix.deps).expect("the deposit-sum proof");
    let ek_holder = qlab_wallet::Wallet::from_master_seed(&qlab_wallet::seed::MasterSeed::from_entropy([0x31; qlab_wallet::seed::ENTROPY_LEN]), 0);
    let change_to = Recipient { rkm: r.keys.rkm(), ek: ek_holder.address_at_index(0).encapsulation_key().expect("an ek") };
    let built = exit_entry(&ei, &stub, TX_FEE, &change_to, &mut rng);
    let file = encode_exit_artifact(&built.tx);
    let (tx, surface) = decode_exit_artifact(&file).expect("the file reads back");
    assert_eq!(exit_member_pvs(&tx, &surface), ei.inst.pvs, "the file declares exactly the instance's PVs");
    let mut wrong = file.clone();
    wrong[qlab_l2spend::EXIT_ARTIFACT_MAGIC.len()] = 2;
    assert_eq!(decode_exit_artifact(&wrong).err(), Some(ArtifactError::Version { found: 2, expected: 1 }));
    assert_eq!(decode_exit_artifact(&file[1..]).err(), Some(ArtifactError::NotAnExitFile));

    // Into the mix's slot 0, where f5box's own exit P stood.
    let kinds = default_kinds(16);
    let burns = r.mix_view.burns(form(), params().l2_id).expect("the burns");
    let a = Ask { kinds: &kinds, burns: &burns, owned: &r.deposit.credited, exit: Some(EXIT) };
    let base = plan(&r.state1, &r.prev1, &chain_of(&r.mix_view), &r.keys, &a).expect("the mix plans");
    let wallet_exit = Exit { rkm: ask.to_rkm, v: ask.value };
    let p = super::members::reseal(&r.state1, base, 0, Inst::P(ei.inst), vec![wallet_exit]).expect("the native statement takes it");
    assert_eq!(p.members[0].pvs, exit_member_pvs(&tx, &surface), "member 0 is the file's");
    assert_eq!(p.exit_cmt, exit_chain(&[wallet_exit]));

    let rule = WrapperRule::from_params(NET_ID, &params()).expect("the rule");
    let (_, bytes) = stub_bundle(&p, &NET_ID);
    match self_check(&rule, &bytes, &r.prev1, &r.mix_view) {
        Err(BundleRefusal::Wrapper(v)) => assert!(v.starts_with("Member(0,"), "refused at {v}"),
        other => panic!("expected the member-0 refusal, got {other:?}"),
    }
    let out = rule.fold_bundle(&encode_surface(&r.prev1), &bytes).expect("the fold accepts");
    assert_eq!(out.exits, vec![(digest_to_bytes(&EXIT.rkm), EXIT.v)], "the bundle pays exactly the wallet's exit");
    assert_eq!(out.e_batch, EXIT.v);
}
