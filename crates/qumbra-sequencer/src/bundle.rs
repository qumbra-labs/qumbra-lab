//! Lab #785 F5-6 (1) — **a plan, proven and signed**: every member under its
//! own circuit, W at version 1 (`W_V1_CFG`, b2/q91, `WAir::new(16)`), the
//! deposit-sum proof, the canonical bytes, the rehearsal sequencer's
//! signature — then the node's own rule over the result, before anything is
//! written.
//!
//! **The self-check is the production rule** (`WrapperRule::from_params` on
//! the genesis's parameters, typed members at the genesis tariff — no test
//! knob): the bytes are judged as the box node will judge them, with two
//! inputs the node owns and f5box can only approximate — V7's anchor rule is
//! the served anchor set (local finality; the node reads the record), and
//! spacing is the node's (the first bundle is free; f5box passes none).
use std::time::Instant;

use ml_dsa::{MlDsa65, Signer, SigningKey};
use p3_field::PrimeField32;
use qlab_consensus::legacy::{make_legacy_config_with, LegacyNonHidingConfig};
use qlab_consensus::{Config, Proof};
use qlab_devnet::body::{BundleContext, BundleOutcome, BundleRefusal, BundleVerifier};
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_wrapper::codec::{digest_to_bytes, encode_surface, sign_message, WireBundle, SEQUENCER_SIG_LEN};
use qlab_wrapper::genesis::CHAIN_VERSION;
use qlab_wrapper::verify::{BundleMember, Surface};
use qumbra_node::bundle::WrapperRule;
use qumbra_node::genesis_v6::WrapperParams;
use serde_json::{json, Value};

use super::chain::ChainView;
use super::members::Plan;
use super::state::digest_hex;
use qlab_wprover::f4::dep::prove_dep;
use qlab_wprover::f4::wleaf::{build_plan, fee_of, first_violation, render, w_pvs, WAir};

/// Wall seconds per step, in order.
pub type Timings = Vec<(String, f64)>;

/// The proofs of a plan.
pub struct Proofs {
    pub w: Proof<LegacyNonHidingConfig>,
    pub dep_pvs: Vec<u32>,
    pub dep: Proof<Config>,
    pub members: Vec<Proof<Config>>,
}

/// W's public values for `p`, as the wire carries them.
pub fn w_pvs_u32(p: &Plan) -> Vec<u32> {
    w_pvs(&p.rin, &p.rout, &p.inp, fee_of(&p.members), &p.exit_cmt).iter().map(PrimeField32::as_canonical_u32).collect()
}

/// Prove everything `p` needs, members first (the heaviest, one at a time),
/// then W — after a full scan of its honest trace, so an unsatisfiable W is
/// refused by row rather than proven into garbage — then the deposit-sum
/// proof. `log` hears each step as it starts.
pub fn prove(p: &Plan, timings: &mut Timings, log: &mut dyn FnMut(&str)) -> Result<Proofs, String> {
    let cfg = qlab_wrapper::verify::version_cfg(CHAIN_VERSION).ok_or("no lane for the chain version")?;
    let mut members = Vec::with_capacity(p.insts.len());
    for (i, inst) in p.insts.iter().enumerate() {
        log(&format!("member {i} ({:?})", inst.tag())); // debug-ok: a member tag, a unit enum
        let t = Instant::now();
        members.push(inst.prove());
        timings.push((format!("member_{i}_{:?}", inst.tag()), t.elapsed().as_secs_f64())); // debug-ok: a member tag, a unit enum
    }
    log("W: plan, render, scan");
    let t = Instant::now();
    let k = p.members.len();
    let air = WAir::new(k);
    let trace = render(&build_plan(&p.rin, &p.inp, &p.members, &p.wit));
    let pvs = w_pvs(&p.rin, &p.rout, &p.inp, fee_of(&p.members), &p.exit_cmt);
    if let Some((row, phases)) = first_violation(&air, &trace, &pvs) {
        return Err(format!("W does not hold at row {row}: {phases:?} — not proving")); // debug-ok: constraint phase names from first_violation, no witness values
    }
    timings.push(("w_trace_and_scan".into(), t.elapsed().as_secs_f64()));
    log("W: prove");
    let t = Instant::now();
    let w = p3_uni_stark::prove(&make_legacy_config_with(&cfg), &air, trace, &pvs);
    timings.push(("w_prove".into(), t.elapsed().as_secs_f64()));
    log("deposit-sum proof");
    let t = Instant::now();
    let (dep_pvs, dep) = prove_dep(&p.deps).ok_or("the claims' openings do not fit a deposit-sum proof")?;
    timings.push(("dep_prove".into(), t.elapsed().as_secs_f64()));
    Ok(Proofs { w, dep_pvs, dep, members })
}

/// The canonical bundle of `p` with `proofs`, unsigned.
pub fn assemble(p: &Plan, l2_id: u64, proofs: Proofs) -> Result<WireBundle, String> {
    if proofs.members.len() != p.insts.len() {
        return Err(format!("{} member proofs for {} members", proofs.members.len(), p.insts.len()));
    }
    Ok(WireBundle {
        version: CHAIN_VERSION,
        l2_id,
        w_pvs: w_pvs_u32(p),
        w_proof: proofs.w,
        dep_pvs: proofs.dep_pvs,
        dep_proof: proofs.dep,
        members: p
            .members
            .iter()
            .zip(proofs.members)
            .map(|(m, proof)| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof })
            .collect(),
        exits: p.exits.clone(),
        sig: Box::new([0; SEQUENCER_SIG_LEN]),
    })
}

/// The rehearsal sequencer's signing key, refused unless `params` names its
/// verifying half: f5box signs only for a genesis that trusts the in-code
/// rehearsal key (Q-6-1: a rehearsal genesis, no secret).
pub fn rehearsal_signer(params: &WrapperParams) -> Result<SigningKey<MlDsa65>, String> {
    if params.sequencer_key != qumbra_node::genesis_v6::rehearsal_sequencer_key() {
        return Err("this genesis's sequencer key is not the in-code rehearsal key; f5box signs only for a rehearsal genesis".into());
    }
    Ok(SigningKey::<MlDsa65>::from_seed(&qumbra_node::genesis_v6::rehearsal_sequencer_seed().into()))
}

/// The message the sequencer signs for `wb` on `net`; `None` when W's PVs
/// state no surface (a PV word past 16 bits).
pub fn signed_message(wb: &WireBundle, net: &Hash32) -> Option<Vec<u8>> {
    let stated = wb.stated_surface()?;
    Some(sign_message(net, wb.l2_id, &stated.commitment))
}

/// Sign `wb` for `net`. An error, never a panic: it runs after the proofs.
pub fn sign(wb: &mut WireBundle, sk: &SigningKey<MlDsa65>, net: &Hash32) -> Result<(), String> {
    let msg = signed_message(wb, net).ok_or("W's public values state no surface: nothing to sign")?;
    wb.sig.copy_from_slice(sk.sign(&msg).encode().as_slice());
    Ok(())
}

/// The node's rule over `bytes`, at the block after the served tip, threading
/// from `prev`, every absorbed root judged against the served anchor set.
pub fn self_check(rule: &WrapperRule, bytes: &[u8], prev: &Surface, view: &ChainView) -> Result<BundleOutcome, BundleRefusal> {
    let surface = encode_surface(prev);
    let anchor_ok = |root: &Hash32| view.anchors.roots.contains(root);
    let ctx = BundleContext { surface: &surface, last_bundle_height: None, anchor_ok: &anchor_ok };
    let header = BlockHeader { height: view.anchors.tip_height + 1, ..BlockHeader::genesis_for(GenesisForm::V5, 8, 0) };
    rule.verify_bundle(&header, bytes, &ctx)
}

/// The manifest: everything a reader needs to check the bundle against the
/// chain without decoding it — the absorbed roots, every member's tag and PV
/// digest, the burns claimed and the notes spent, the exit, the signed
/// message's digest, byte counts per part and in total, and the timings.
///
/// It never panics — it runs after the proofs. The byte parts are computed
/// from the codec's layout, independently of `encode()`; `bytes_reconciled`
/// says whether they sum to the encoding, and the command refuses a bundle
/// whose parts do not.
pub fn manifest(p: &Plan, wb: &WireBundle, bytes: &[u8], net: &Hash32, spacing: u64, view: &ChainView, timings: &Timings) -> Value {
    let pv_digest = |pvs: &[u32]| {
        let le: Vec<u8> = pvs.iter().flat_map(|w| w.to_le_bytes()).collect();
        hex(&qlab_devnet::hash::keccak256(&le))
    };
    let member_bytes: Vec<usize> = wb.members.iter().map(|m| proof_len(&m.proof)).collect();
    let parts = BundleBytes::of(wb);
    let stated = wb.stated_surface().map(|s| digest_hex(&s.commitment));
    let signed = signed_message(wb, net).map(|m| hex(&qlab_devnet::hash::keccak256(&m)));
    json!({
        "mode": "f5box", "issue": 785, "version": wb.version, "l2_id": wb.l2_id,
        "net_id": hex(net),
        "prev_surface": digest_hex(&p.inp.prev),
        "stated_surface": stated,
        "signed_message_keccak": signed,
        "wrapper_spacing_blocks": spacing,
        "chain": {"tip": view.anchors.tip_height, "finalized_local": view.anchors.finalized_height, "leaves": view.tree.len(),
            "self_check_cannot_see": "the self-check is the node's rule over these bytes, but with three inputs the node owns: spacing (last_bundle_height = None — post no sooner than wrapper_spacing_blocks after the previous bundle's block); the chain's real surface (V5/V6 thread from the replayed state file, which can be ahead of the chain); and the finality record (V7 judged against /v1/anchors, the node's local finality — the node may answer 422 until a record covers the absorbed roots; retry)"},
        "absorbed": p.absorbed.iter().map(|a| json!({"root": digest_hex(&a.root), "leaf_count": a.count})).collect::<Vec<_>>(),
        "members": p.members.iter().enumerate().map(|(i, m)| {
            let mut row = json!({
                "slot": i, "tag": format!("{:?}", m.tag), "pv_words": m.pvs.len(), "pv_keccak": pv_digest(&m.pvs), "proof_bytes": member_bytes[i], // debug-ok: a member tag, a unit enum
            });
            // Lab #847 S3: padding is marked, traffic is not (an f5box
            // manifest, which plans no fillers, is unchanged).
            if p.filler.get(i).copied().unwrap_or(false) {
                row["filler"] = json!(true);
            }
            row
        }).collect::<Vec<_>>(),
        "claimed_burns": p.claimed.iter().map(|b| json!({
            "minted_height": b.height, "leaf_height": qlab_node::coinbase_leaf_appears_at(b.height), "leaf_pos": b.pos, "value": b.note.value,
            "cm": hex(&digest_to_bytes(&b.cm)),
        })).collect::<Vec<_>>(),
        "spent_notes": p.spent.len(),
        "credited_notes": p.credited.len(),
        "d_batch": p.inp.d_batch, "d_cum": p.rout.d_cum, "e_cum": p.rout.e_cum,
        "exits": p.exits.iter().map(|e| json!({"rkm": digest_hex(&e.rkm), "v": e.v})).collect::<Vec<_>>(),
        "exit_cmt": digest_hex(&p.exit_cmt),
        "bytes": parts.json(),
        "bytes_reconciled": parts.total() == bytes.len(),
        "timings_seconds": timings.iter().map(|(k, v)| json!({"step": k, "seconds": v})).collect::<Vec<_>>(),
    })
}

/// A proof's encoded length (bincode, the codec's own form).
fn proof_len<T: serde::Serialize>(p: &T) -> usize {
    bincode::serialized_size(p).expect("a proof serializes") as usize
}

/// The canonical bytes, by part (`qlab_wrapper::codec`'s layout): every
/// byte is in exactly one part, so the parts sum to the encoding.
pub struct BundleBytes {
    /// `version ‖ l2_id`, the two proof lengths, `n_members`, each member's
    /// tag and proof length, `n_exits`.
    pub framing: usize,
    pub w_pvs: usize,
    pub w_proof: usize,
    pub dep_pvs: usize,
    pub dep_proof: usize,
    pub member_pvs: usize,
    pub member_proofs: usize,
    pub exits: usize,
    pub sig: usize,
}

impl BundleBytes {
    pub fn of(wb: &WireBundle) -> Self {
        BundleBytes {
            framing: 4 + 8 + 4 + 4 + 1 + 5 * wb.members.len() + 1,
            w_pvs: 4 * wb.w_pvs.len(),
            w_proof: proof_len(&wb.w_proof),
            dep_pvs: 4 * wb.dep_pvs.len(),
            dep_proof: proof_len(&wb.dep_proof),
            member_pvs: 4 * wb.members.iter().map(|m| m.pvs.len()).sum::<usize>(),
            member_proofs: wb.members.iter().map(|m| proof_len(&m.proof)).sum(),
            exits: 40 * wb.exits.len(),
            sig: SEQUENCER_SIG_LEN,
        }
    }

    pub fn total(&self) -> usize {
        self.framing + self.w_pvs + self.w_proof + self.dep_pvs + self.dep_proof + self.member_pvs + self.member_proofs + self.exits + self.sig
    }

    fn json(&self) -> Value {
        json!({
            "framing": self.framing, "w_pvs": self.w_pvs, "w_proof": self.w_proof, "dep_pvs": self.dep_pvs,
            "dep_proof": self.dep_proof, "member_pvs": self.member_pvs, "member_proofs": self.member_proofs,
            "exits": self.exits, "sig": self.sig, "total": self.total(),
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
