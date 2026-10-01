//! Lab #785 F5-4b — **the proven bundle through the node's real rule.**
//!
//! One fixture per run (ruling 5915423092 (c)): a k = 1 wrapper on the
//! measurement version `0x8001` (b2/q86), its one member a claim, threading
//! from the test chain's **genesis surface**, absorbing that chain's real
//! commitment root, with its deposit-sum proof — two proves. The member is a
//! stub (test-only; an L2 member prove is 7–30 GiB), carried on the wire as a
//! real `Proof<Config>` (the deposit proof re-used) so the codec path is the
//! real one; `TypedMembers` first runs through the node path in F5-6 on the box.
//!
//! The rule is `qumbra_node::bundle::WrapperRule` itself, built from the
//! rehearsal `WrapperParams` with the two `wrapper-test-knobs` constructors.
//! Every negative mutates this one fixture; none proves again.
use std::sync::OnceLock;

use ml_dsa::{MlDsa65, Signer, SigningKey};
use p3_field::PrimeField32;
use p3_uni_stark::prove;
use qlab_consensus::legacy::make_legacy_config_with;
use qlab_consensus::{Config, Proof};
use qlab_devnet::body::{BlockBody, BodyError, BundleContext, BundleRefusal, BundleVerifier, TxEntry, TxVerifier};
use qlab_devnet::committee::{Checkpoint, Committee, Validator};
use qlab_devnet::finality_record::FinalityRecord;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_node::{genesis_block_v6, ChainStore, MemNode, NodeError, NodeState, V6Setup};
use qlab_wrapper::codec::{digest_from_bytes, encode_surface, sign_message, Exit, WireBundle, SEQUENCER_SIG_LEN};
use qlab_wrapper::config::Outer;
use qlab_wrapper::genesis::genesis_roots;
use qlab_wrapper::hash::{WTag, M_ABS};
use qlab_wrapper::verify::{BundleMember, MemberVerifier, Surface};
use qlab_wrapper::wleaf::{PV_C, PV_D, PV_E, PV_EXC, PV_PREV, PV_SIDE};
use qumbra_node::bundle::WrapperRule;
use qumbra_node::genesis_v6::{rehearsal_sequencer_seed, v6_genesis_registry, v6_genesis_registry_root, WrapperParams, REHEARSAL_L2_ID};

use super::dep::prove_dep;
use super::native::{check_wrapper_leaf, synth_claim_open, WInputs, WState};
use super::wleaf::{build_plan, render};
use crate::f3::native::Rng;

/// The fixture chain's wrapper version: k = 1, measurement only.
const VERSION: u32 = 0x8001;
/// The net id the fixture's sequencer signs (a stand-in V6 genesis hash).
const NET_ID: Hash32 = [0x5a; 32];
const CLAIM_FEE: u64 = 0x1_ffff;

/// Accepts claim members only — the fixture's stand-in for `TypedMembers`.
struct ClaimStub;
impl<'a> MemberVerifier<&'a Proof<Config>> for ClaimStub {
    fn verify(&self, m: &BundleMember<&'a Proof<Config>>, _: u64) -> Result<(), String> {
        (m.tag == WTag::C).then_some(()).ok_or_else(|| "not a claim".into())
    }
}

/// Every transaction the fixture chain carries (none) verifies.
#[derive(Clone)]
struct NoTxs;
impl TxVerifier for NoTxs {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

fn params() -> WrapperParams {
    WrapperParams::rehearsal()
}

/// The fixture's rule: the node's real `WrapperRule` at version 0x8001 with
/// the claim stub.
fn rule() -> WrapperRule {
    WrapperRule::from_params(NET_ID, &params()).unwrap().for_version(VERSION).with_members(Box::new(ClaimStub))
}

/// Twenty-one committee₀ validators (the test chain's records).
fn validators() -> &'static (Committee, Vec<Validator>) {
    static V: OnceLock<(Committee, Vec<Validator>)> = OnceLock::new();
    V.get_or_init(|| {
        let vs: Vec<Validator> = (0..21u8).map(|i| Validator::from_seed(i as usize, [i ^ 0xb5; 32])).collect();
        (Committee::from_keys(vs.iter().map(Validator::verifying_key).collect()), vs)
    })
}

fn chain_block(parent: &BlockHeader, finality: Vec<u8>, bundle: Vec<u8>) -> (BlockHeader, BlockBody) {
    let height = parent.height + 1;
    let mut body = BlockBody::from_single_payee(vec![], qlab_devnet::emission_exact::coinbase_exact(height), [height; 4]);
    body.finality = finality;
    body.bundle = bundle;
    let header = BlockHeader::child_of_for(GenesisForm::V5, parent, parent.timestamp + 75, 8, body.commitment_v6());
    (header, body)
}

fn tip_header(node: &MemNode) -> BlockHeader {
    node.chain().block(&node.tip_hash()).expect("the tip is held").header()
}

/// A V6 node on the fixture rule, blocks 1–8 applied (no record yet).
fn chain_to_8() -> MemNode {
    let v6 = V6Setup { committee0: validators().0.clone(), wrapper: Some(rule().into_setup()) };
    let mut node = MemNode::in_memory_v6(genesis_block_v6(8, 0), v6);
    for _ in 1..=8 {
        let parent = tip_header(&node);
        let (h, b) = chain_block(&parent, vec![], vec![]);
        node.apply_block(h, b, &NoTxs).unwrap();
    }
    node
}

/// The quorum record for the checkpoint at the node's tip.
fn record_at_tip(node: &MemNode) -> Vec<u8> {
    let (_, vs) = validators();
    let cp = Checkpoint::new(node.tip_height(), node.tip_hash(), node.tip_hash());
    FinalityRecord { cp, votes: (0..15).map(|i| vs[i].sign_checkpoint(&cp)).collect() }.encode()
}

/// The proven wrapper, once per run, and its canonical bundle bytes.
struct Fixture {
    wire: Vec<u8>,
    /// The genesis surface the fixture threads from (the chain's).
    genesis: Surface,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        // The chain's commitment root, absorbed four times: the empty tree's,
        // recorded at every height of `chain_to_8`.
        let root = digest_from_bytes(&chain_to_8().commitment_root());
        let genesis = Surface::genesis(VERSION, REHEARSAL_L2_ID, genesis_roots(&v6_genesis_registry_root()));
        let mut rng = Rng(0x785_f54b);
        let mut s = WState::genesis(&v6_genesis_registry());
        assert_eq!(s.roots(), genesis.out, "the fixture starts at the chain's genesis state");
        let (claim, open) = synth_claim_open(&mut rng, &root, CLAIM_FEE);
        let inp = WInputs { prev: genesis.commitment, rkm_seq: rng.digest(), absorbed: [root; M_ABS], d_batch: open.v };
        let members = vec![claim];
        let (rin, wit, _) = s.apply(&inp, &members).expect("the fixture wrapper applies");
        let exit_cmt = check_wrapper_leaf(&rin, &inp, &members, &wit).expect("its check").1;
        let plan = build_plan(&rin, &inp, &members, &wit);
        let pvs = super::wleaf::w_pvs(&rin, &s.roots(), &inp, super::wleaf::fee_of(&members), &exit_cmt);
        let proof = prove(&make_legacy_config_with(&Outer::B2.cfg()), &super::wleaf::WAir::new(1), render(&plan), &pvs);
        let (dep_pvs, dep_proof) = prove_dep(&[open]).expect("the claim's opening fits");
        let copy = |p: &Proof<Config>| -> Proof<Config> { bincode::deserialize(&bincode::serialize(p).unwrap()).unwrap() };
        let mut wb = WireBundle {
            version: VERSION,
            l2_id: REHEARSAL_L2_ID,
            w_pvs: pvs.iter().map(|v| v.as_canonical_u32()).collect(),
            w_proof: proof,
            dep_pvs,
            dep_proof: copy(&dep_proof),
            members: members.iter().map(|m| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: copy(&dep_proof) }).collect(),
            exits: vec![],
            sig: Box::new([0; SEQUENCER_SIG_LEN]),
        };
        sign(&mut wb, &NET_ID);
        Fixture { wire: wb.encode(), genesis }
    })
}

/// Sign `wb` as the rehearsal sequencer, for `net`.
fn sign(wb: &mut WireBundle, net: &Hash32) {
    let sk = SigningKey::<MlDsa65>::from_seed(&rehearsal_sequencer_seed().into());
    let stated = wb.stated_surface().expect("16-bit PVs");
    let sig = sk.sign(&sign_message(net, wb.l2_id, &stated.commitment)).encode();
    wb.sig.copy_from_slice(sig.as_slice());
}

/// The fixture decoded, mutated by `f`, re-signed (unless `f` returns false),
/// re-encoded.
fn mutated(f: impl FnOnce(&mut WireBundle) -> bool) -> Vec<u8> {
    let mut wb = WireBundle::decode(&fixture().wire).unwrap();
    if f(&mut wb) {
        sign(&mut wb, &NET_ID);
    }
    wb.encode()
}

fn genesis_bytes() -> Vec<u8> {
    encode_surface(&fixture().genesis).to_vec()
}

/// The height the rule-level negatives judge at.
const AT: u64 = 100;

/// A header at `height` (the rule reads only the height; V7 is the context's).
fn header_at(height: u64) -> BlockHeader {
    BlockHeader { height, ..BlockHeader::genesis_for(GenesisForm::V5, 8, 0) }
}

/// The rule at a block where the absorbed roots are valid, the chain at its
/// genesis surface, no earlier bundle.
fn judge(rule: &WrapperRule, bytes: &[u8]) -> Result<qlab_devnet::body::BundleOutcome, BundleRefusal> {
    let surface = genesis_bytes();
    let ctx = BundleContext { surface: &surface, last_bundle_height: None, anchor_ok: &|_| true };
    rule.verify_bundle(&header_at(AT), bytes, &ctx)
}

fn wrapper(check: &str) -> Result<qlab_devnet::body::BundleOutcome, BundleRefusal> {
    Err(BundleRefusal::Wrapper(check.into()))
}

/// Through the node: the bundle in the block BEFORE the record covering its
/// absorbed root is refused at V7; carried in the block WITH that record it
/// is accepted, the chain's surface becomes the stated one and the fold's
/// outcome is the rule's (ruling 5915423092's two added tests).
#[test]
fn f5_4b_the_proven_bundle_through_the_node_path() {
    let fx = fixture();
    let mut node = chain_to_8();
    let parent = tip_header(&node);
    let (h, b) = chain_block(&parent, vec![], fx.wire.clone());
    let err = node.apply_block(h, b, &NoTxs).unwrap_err();
    assert!(
        matches!(&err, NodeError::Body(BodyError::Bundle { refusal: BundleRefusal::Wrapper(c) }) if c == "Anchor(0)"),
        "before the record: V7, {err:?}"
    );
    assert_eq!(node.last_bundle_height(), None);

    let record = record_at_tip(&node);
    let prior = node.wrapper_surface().to_vec();
    let (h, b) = chain_block(&parent, record, fx.wire.clone());
    node.apply_block(h, b, &NoTxs).expect("with the record: accepted");
    assert_eq!(node.last_bundle_height(), Some(9));
    let stated = WireBundle::decode(&fx.wire).unwrap().stated_surface().unwrap();
    assert_eq!(node.wrapper_surface(), &encode_surface(&stated)[..]);

    // fold == verify on the accepted bundle.
    let r = rule();
    let ctx = BundleContext { surface: &prior, last_bundle_height: None, anchor_ok: &|_| true };
    let verified = r.verify_bundle(&h, &fx.wire, &ctx).unwrap();
    assert_eq!(r.fold_bundle(&prior, &fx.wire), Ok(verified.clone()));
    assert_eq!(r.bundle_surface(&fx.wire), Ok(verified.surface.clone()));
    // F5-4c Q1: the prefix read states the same surface from the first bytes.
    let prefix = 12 + 4 * qlab_wrapper::wleaf::W_PV_LEN;
    assert_eq!(qlab_wrapper::codec::stated_surface_prefix(&fx.wire[..prefix]), Ok(Some(stated.clone())));
    assert_eq!((verified.d_batch, verified.e_batch, verified.exits.len()), (stated.out.d_cum, 0, 0));
}

/// Every refusal the fixture can reach, each named, in the rule's order —
/// including the multi-fault case (a bad signature over a bad proof reports
/// the signature) and the production rule refusing the measurement version.
#[test]
fn f5_4b_bundle_rule_negatives() {
    let fx = fixture();
    let r = rule();
    assert!(judge(&r, &fx.wire).is_ok(), "the honest fixture");

    // 1. The codec, the #793 class included.
    assert!(matches!(judge(&r, &fx.wire[..fx.wire.len() - 1]), Err(BundleRefusal::Codec(_))));
    // 2. l2_id.
    assert_eq!(judge(&r, &mutated(|w| { w.l2_id = 2; true })), Err(BundleRefusal::L2Id { got: 2, want: REHEARSAL_L2_ID }));
    // 3. Spacing: 47 refused, 48 passes.
    let surface = genesis_bytes();
    for (last, want) in [(AT - 47, Err(BundleRefusal::Spacing { since: 47, need: 48 })), (AT - 48, Ok(()))] {
        let ctx = BundleContext { surface: &surface, last_bundle_height: Some(last), anchor_ok: &|_| true };
        let got = r.verify_bundle(&header_at(AT), &fx.wire, &ctx).map(|_| ());
        assert_eq!(got, want, "last bundle at {last}");
    }
    // 4. Exit shape (before the signature, which does not cover the list).
    let e = Exit { rkm: [1, 0, 0, 0], v: 1 };
    assert_eq!(judge(&r, &mutated(|w| { w.exits = vec![e; 9]; false })), Err(BundleRefusal::TooManyExits { n: 9, k_exit: 8 }));
    assert_eq!(judge(&r, &mutated(|w| { w.exits = vec![Exit { rkm: [0; 4], v: 1 }]; false })), Err(BundleRefusal::ZeroExitRkm { index: 0 }));
    assert_eq!(judge(&r, &mutated(|w| { w.exits = vec![Exit { v: 0, ..e }]; false })), Err(BundleRefusal::ZeroExitValue { index: 0 }));
    // 5. No stated surface: a W word past 16 bits.
    assert_eq!(judge(&r, &mutated(|w| { w.w_pvs[0] = 1 << 16; false })), Err(BundleRefusal::NoStatedSurface));
    // 6. The signature: a flipped byte, another net's id, another key, and
    // the multi-fault case (bad signature AND bad proof).
    assert_eq!(judge(&r, &mutated(|w| { w.sig[7] ^= 1; false })), Err(BundleRefusal::Signature));
    assert_eq!(judge(&r, &mutated(|w| { sign(w, &[0xa5; 32]); false })), Err(BundleRefusal::Signature), "signed for another net");
    let mut launch = params();
    launch.sequencer_key = Validator::from_seed(0, [0x11; 32]).verifying_key().encode().to_vec();
    let launch_rule = WrapperRule::from_params(NET_ID, &launch).unwrap().for_version(VERSION).with_members(Box::new(ClaimStub));
    assert_eq!(judge(&launch_rule, &fx.wire), Err(BundleRefusal::Signature), "the rehearsal key on a launch-keyed chain");
    assert_eq!(
        judge(&r, &mutated(|w| { w.w_pvs[PV_SIDE + PV_E] ^= 1; sign(w, &NET_ID); w.sig[0] ^= 1; false })),
        Err(BundleRefusal::Signature),
        "multi-fault: the signature is judged first"
    );
    // 7. verify_wrapper: the production rule refuses 0x8001 at V0 (condition (c)).
    let production = WrapperRule::from_params(NET_ID, &params()).unwrap();
    assert_eq!(judge(&production, &fx.wire), wrapper("Version"));
    // …V3 (a re-signed PV change), V8 native (E_cum above D_cum, re-signed),
    // V7 (a root the record rule refuses), V5 (a predecessor off W's in).
    assert_eq!(judge(&r, &mutated(|w| { w.w_pvs[PV_SIDE + PV_C] ^= 1; true })), wrapper("WProof"));
    assert_eq!(judge(&r, &mutated(|w| { w.w_pvs[PV_SIDE + PV_E + 3] = 0xffff; true })), wrapper("EAboveD"));
    let ctx = BundleContext { surface: &surface, last_bundle_height: None, anchor_ok: &|_| false };
    assert_eq!(r.verify_bundle(&header_at(AT), &fx.wire, &ctx), wrapper("Anchor(0)"));
    let mut off = fx.genesis.clone();
    off.out.k_next += 1;
    off.commitment = Surface::commit(off.version, off.l2_id, &off.prev, &off.out, &off.newest_anchor, &off.exit_cmt);
    let off = encode_surface(&off).to_vec();
    let ctx = BundleContext { surface: &off, last_bundle_height: None, anchor_ok: &|_| true };
    assert_eq!(r.verify_bundle(&header_at(AT), &fx.wire, &ctx), wrapper("Thread(\"k_next\")"));
    // The chain's own surface undecodable: this node's state, named.
    let ctx = BundleContext { surface: &[1, 2, 3], last_bundle_height: None, anchor_ok: &|_| true };
    assert_eq!(r.verify_bundle(&header_at(AT), &fx.wire, &ctx), Err(BundleRefusal::SurfaceState));
    // 9. An exit list that does not chain to W's exit_cmt (EMPTY here) — F5-4c
    // lifted 4b's blanket exit refusal, so the chain check is what refuses.
    assert_eq!(judge(&r, &mutated(|w| { w.exits = vec![e]; false })), Err(BundleRefusal::ExitCommitment));
    assert_eq!(r.fold_bundle(&surface, &mutated(|w| { w.exits = vec![e]; false })), Err(BundleRefusal::ExitCommitment));
    // The fold refuses the verify path's refusals where it can judge (no proof, no signature).
    assert_eq!(r.fold_bundle(&off, &fx.wire), wrapper("Thread(\"k_next\")"));
    assert_eq!(r.fold_bundle(&surface, &mutated(|w| { w.l2_id = 2; false })), Err(BundleRefusal::L2Id { got: 2, want: REHEARSAL_L2_ID }));
}

fn put_u64(w: &mut [u32], off: usize, x: u64) {
    for j in 0..4 {
        w[off + j] = ((x >> (16 * j)) & 0xffff) as u32;
    }
}

fn put_digest(w: &mut [u32], off: usize, d: &qlab_wrapper::hash::Digest) {
    for (l, lane) in d.iter().enumerate() {
        put_u64(w, off + 4 * l, *lane);
    }
}

/// Pre-review Q3: the fold has no proof to lean on, so the three checks that
/// are belts on the verify path (W binds them) are reachable here — each
/// refused by name on the fixture's bytes with W's words edited.
#[test]
fn f5_4b_fold_only_negatives() {
    let fx = fixture();
    let r = rule();
    let surface = genesis_bytes();
    // exit_cmt not the (empty) list's chain.
    assert_eq!(r.fold_bundle(&surface, &mutated(|w| { w.w_pvs[PV_EXC] = 1; false })), Err(BundleRefusal::ExitCommitment));
    // ΔE = 5 with no exits: Σv ≠ ΔE.
    assert_eq!(r.fold_bundle(&surface, &mutated(|w| { put_u64(&mut w.w_pvs, PV_SIDE + PV_E, 5); false })), Err(BundleRefusal::ExitSum));
    // D_cum moving backwards: a predecessor above the out side's D_cum, which
    // W's in side and prev link are edited to match.
    let stated_d = WireBundle::decode(&fx.wire).unwrap().stated_surface().unwrap().out.d_cum;
    let mut prev = fx.genesis.clone();
    prev.out.d_cum = stated_d + 1000;
    prev.commitment = Surface::commit(prev.version, prev.l2_id, &prev.prev, &prev.out, &prev.newest_anchor, &prev.exit_cmt);
    let bytes = mutated(|w| {
        put_u64(&mut w.w_pvs, PV_D, prev.out.d_cum);
        put_digest(&mut w.w_pvs, PV_PREV, &prev.commitment);
        false
    });
    assert_eq!(r.fold_bundle(&encode_surface(&prev), &bytes), Err(BundleRefusal::Counters));
}

/// Pre-review Q4: the real rule on replay and on snapshot resume — the
/// fixture chain on a disk-backed node, reopened both ways, re-derives the
/// live surface and last bundle height (the fold on replay; the walk-back's
/// `bundle_surface` on the snapshot path, nothing replayed).
#[test]
fn f5_4b_the_proven_bundle_survives_replay_and_snapshot_resume() {
    let fx = fixture();
    let dir = std::env::temp_dir().join(format!("qlab-f5-4b-resume-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let setup = || V6Setup { committee0: validators().0.clone(), wrapper: Some(rule().into_setup()) };
    let live = {
        let mut node = MemNode::open_v6(&dir, genesis_block_v6(8, 0), setup()).unwrap();
        for _ in 1..=8 {
            let (h, b) = chain_block(&tip_header(&node), vec![], vec![]);
            node.apply_block(h, b, &NoTxs).unwrap();
        }
        let record = record_at_tip(&node);
        let (h, b) = chain_block(&tip_header(&node), record, fx.wire.clone());
        node.apply_block(h, b, &NoTxs).expect("accepted");
        (node.tip_hash(), node.wrapper_surface().to_vec(), node.last_bundle_height())
    };
    assert_eq!(live.2, Some(9));
    let replayed = MemNode::open_v6(&dir, genesis_block_v6(8, 0), setup()).expect("full replay");
    assert_eq!(replayed.recovery_report().snapshot_height, None);
    assert_eq!((replayed.tip_hash(), replayed.wrapper_surface().to_vec(), replayed.last_bundle_height()), live);
    replayed.save_snapshot().unwrap();
    let resumed = MemNode::open_v6(&dir, genesis_block_v6(8, 0), setup()).expect("snapshot resume");
    assert_eq!((resumed.recovery_report().snapshot_height, resumed.recovery_report().replayed_records), (Some(9), 0));
    assert_eq!((resumed.tip_hash(), resumed.wrapper_surface().to_vec(), resumed.last_bundle_height()), live);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lab #785 F5-5b — **the bundle path end to end on the proven fixture**,
/// over two real `NodeAdapter`s on the fixture rule: before any record the
/// bundle is not valid at the tip (refused, uncharged); after A finalizes 8
/// and block 9 carries the record, the operator route admits it on A, A
/// advertises it, B asks, verifies and holds it, B's template carries it, B
/// mines block 10 with it and A applies that block over the wire — both
/// slots clear and both surfaces become the stated one.
#[test]
fn f5_5b_the_proven_bundle_through_the_slot_gossip_and_template() {
    use std::sync::Arc;

    use qlab_devnet::committee::CommitteeState;
    use qlab_devnet::node::SimConfig;
    use qlab_devnet::pow::KeccakPow;
    use qlab_p2p::adapter::NodeAdapter;
    use qlab_p2p::n1::{BlockIngest, BundleAdmit, ChainView, IngestOutcome};
    use qlab_p2p::peer::PeerId;
    use qlab_p2p::transport::{InProcHub, InProcTransport};
    use qlab_p2p::P2pNode;

    type Node = P2pNode<InProcTransport, NodeAdapter<KeccakPow, NoTxs>>;
    fn run(nodes: &mut [&mut Node], rounds: u64, base_ms: u64) -> u64 {
        let mut now = base_ms;
        for _ in 0..rounds {
            now += 10;
            for n in nodes.iter_mut() {
                n.tick(now);
            }
        }
        now
    }

    let fx = fixture();
    let (committee, vs) = validators();
    let sim = SimConfig { block_time_secs: 2, genesis_difficulty: 8, mine_nonce_budget: 5_000_000, ..SimConfig::default() };
    let adapter = || {
        let committee = CommitteeState::new(committee.clone(), qlab_devnet::params_devnet::BOND_AMOUNT);
        NodeAdapter::new_v6(committee, KeccakPow, NoTxs, sim.clone(), Some(rule().into_setup()))
    };
    let hub = InProcHub::new();
    let mut a: Node = P2pNode::new(InProcTransport::new(PeerId(1), Arc::clone(&hub)), adapter(), [1; 32]);
    let mut b: Node = P2pNode::new(InProcTransport::new(PeerId(2), Arc::clone(&hub)), adapter(), [2; 32]);
    hub.link(PeerId(1), PeerId(2));
    a.add_peer(PeerId(2), None);
    b.add_peer(PeerId(1), None);
    let mut now = run(&mut [&mut a, &mut b], 50, 0);
    assert_eq!(
        a.node().state().commitment_root(),
        chain_to_8().commitment_root(),
        "the fixture absorbed the root this chain records"
    );

    for _ in 0..8 {
        let (h, body) = a.node_mut().mine_block().expect("mine");
        assert_eq!(a.node_mut().ingest_block(h, body.clone()), IngestOutcome::Accepted);
        assert_eq!(b.node_mut().ingest_block(h, body), IngestOutcome::Accepted);
    }
    assert!(
        matches!(a.submit_bundle(fx.wire.clone(), false), BundleAdmit::Refused { charged: false, .. }),
        "no record covers the absorbed root yet: V7 is this node's judgment, not the sender's fault"
    );
    assert!(a.node().held_bundle_slot().is_none());

    let hash8 = a.node().main_chain_hash_at(8).expect("height 8");
    let cp8 = Checkpoint::new(8, hash8, hash8);
    a.announce_checkpoint(cp8, (0..15).map(|i| vs[i].sign_checkpoint(&cp8)).collect());
    let (h9, body9) = a.node_mut().mine_block().expect("mine 9");
    assert!(!body9.finality.is_empty() && body9.bundle.is_empty(), "block 9 carries the record, no bundle");
    assert_eq!(a.announce_block_body(h9, body9, 1), IngestOutcome::Accepted);
    now = run(&mut [&mut a, &mut b], 200, now);
    assert_eq!(b.node().tip_height(), 9);

    assert!(matches!(a.submit_bundle(fx.wire.clone(), false), BundleAdmit::Admitted(_)), "the operator route");
    now = run(&mut [&mut a, &mut b], 200, now);
    assert_eq!(b.node().held_bundle_slot().map(|h| h.bytes.clone()), Some(fx.wire.clone()), "gossiped and verified on B");

    let (h10, body10) = b.node_mut().mine_block().expect("mine 10");
    assert_eq!(body10.bundle, fx.wire, "B's template carries the held bundle");
    assert_eq!(b.announce_block_body(h10, body10, 2), IngestOutcome::Accepted);
    run(&mut [&mut a, &mut b], 300, now);
    assert_eq!((a.node().tip_height(), a.node().tip_hash()), (10, b.node().tip_hash()), "A applied B's bundle block");
    let stated = WireBundle::decode(&fx.wire).unwrap().stated_surface().unwrap();
    for n in [&a, &b] {
        assert!(n.node().held_bundle_slot().is_none(), "a bundle block clears the slot");
        assert_eq!(n.node().state().wrapper_surface(), &encode_surface(&stated)[..]);
        assert_eq!(n.node().state().last_bundle_height(), Some(10));
    }
}

/// F-A (lab #785 F5-4a): the node's V6 genesis registry is the registry
/// every F3/F4 fixture starts from — asset 0's Cloaked leaf — and the
/// native model over it is the node's genesis surface.
#[test]
fn the_v6_genesis_registry_is_the_fixtures() {
    use qlab_air::l2::RegistryLeaf;
    assert_eq!(v6_genesis_registry(), vec![RegistryLeaf::cloaked(0)]);
    let native = WState::genesis(&v6_genesis_registry()).roots();
    assert_eq!(native, genesis_roots(&v6_genesis_registry_root()));
    let surface = WrapperRule::genesis_surface_bytes(REHEARSAL_L2_ID);
    assert_eq!(surface, encode_surface(&Surface::genesis(1, REHEARSAL_L2_ID, native)).to_vec());
}
