//! Lab #896 seam E4: the **v2** (Candidate A) builders, the Annulet intent
//! and the authorization section's attachment.
//!
//! A v2 spend proves with `nk` and an authorization path per slot instead of
//! `sk` (design `remote-proving-authorization-shape-annulet` §2). The builders
//! take [`L2AuthInput`]s exactly as the device hands them over (real inputs
//! and device-made dummies alike) and derive nothing from a wallet key: key
//! derivation and addresses are seam G's. They return the transaction with its
//! `auth` absent; the device then signs [`intent_for`] of it and the section is
//! put in with [`attach`].
//!
//! [`intent_for`] rebuilds the intent from the transaction's decoded fields
//! and canonical re-encodings (§6), so the node and the device compute it with
//! one function. [`LocalAuth`] and [`sign_locally`] are the single-party
//! signer for callers that hold their own key (tests, faucet, sequencer).

use qlab_air::l2::{
    derive_input_l2_v2, FeeSlotV2, L2AuthInput, L2AuthPath, L2TxOutput, RegistryLeaf, RegistryWitness,
    D_AUTH,
};
use qlab_air::l2p::{L2PolicyInput, VPublic};
use qlab_air::narrow::{off_tree_witness, pv_chunks, MerkleWitness};
use qlab_cbserver::registry::{RegistryOpening, RegistrySlotOpening};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::{L2ShapeTag, L2Surface, RegistryWriteSurface, VPublicTerm};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_note::compact::encode_committed_discovery_with_width;
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::l2note::{L2Note, L2_PAYLOAD_LEN};
use qlab_remote_auth::annulet::{
    auth_master, draw_dummy, leaf_key, AnnuletAuthSection, AnnuletIntent, AuthError, AuthTree,
    Cursor,
};
use qlab_remote_auth::intent::AuthDescriptor;
use qlab_remote_auth::{mldsa, Hash32};

use crate::{
    discovery_for, l2_outputs, unproved_entry, output_notes, policy_input, random_d4, Endpoint, Out,
    PolicyContext, Recipient, Served, SpendError,
};

/// An assembled v2 spend (shape S or P), its `auth` still absent.
pub struct BuiltV2 {
    pub tx: TxEntry,
    /// The proof's public values (v2: the leaf PVs appended).
    pub pvs: Vec<u32>,
    /// One descriptor per slot, in slot order (the fee slot last): each
    /// slot's leaf index and the leaf its PVs carry.
    pub auth: Vec<AuthDescriptor>,
    pub outputs: [L2Note; 2],
    pub shape: L2ShapeTag,
}

/// An assembled v2 registry write (shape R), its `auth` still absent.
pub struct BuiltRV2 {
    pub tx: TxEntry,
    pub pvs: Vec<u32>,
    /// The fee input's slot.
    pub auth: Vec<AuthDescriptor>,
    pub output: L2Note,
    pub seed: L2Note,
    pub new_root: [u8; 32],
}

/// **Lab #924 5A-D1: a v2 S/P spend before its proof** — what the device
/// computes (every field the intent binds) and the witness a prover needs.
/// [`prove_prepared`] completes it; `qlab_l2spend::bundle` carries it to a
/// prover that is not this process.
pub struct PreparedV2 {
    /// The transaction with its `proof` empty and its `auth` absent.
    pub tx: TxEntry,
    pub pvs: Vec<u32>,
    pub auth: Vec<AuthDescriptor>,
    pub outputs: [L2Note; 2],
    pub shape: L2ShapeTag,
    pub witness: SpendWitness,
}

/// The shape-specific part of a [`SpendWitness`].
#[derive(Clone)]
pub enum ShapeWitness {
    /// Shape S: the two registry openings and `dv`.
    S { reg_leaves: [RegistryLeaf; 2], reg_witnesses: [RegistryWitness; 2], dv: bool },
    /// Shape P: the two rows' policy inputs and `vPublic` terms.
    P { policy: [L2PolicyInput; 2], vp: [VPublic; 2] },
}

/// **Everything the AIR's instance is built from** for one v2 S/P spend —
/// no key material: `nk` (not `sk`), each slot's public authorization leaf
/// and path, the openings, the outputs the device drew, the fee. A P row's
/// `isk` is here only while the witness stays on the device; the bundle
/// encoding has no field for it.
#[derive(Clone)]
pub struct SpendWitness {
    pub inputs: [L2AuthInput; 2],
    pub witnesses: [MerkleWitness; 2],
    pub outputs: [L2TxOutput; 2],
    pub fee: u64,
    pub anchor: [u64; 4],
    pub registry_root: [u64; 4],
    pub fee_slot: FeeSlotV2,
    pub shape: ShapeWitness,
}

impl SpendWitness {
    /// The shape this witness proves.
    pub fn shape_tag(&self) -> L2ShapeTag {
        match self.shape {
            ShapeWitness::S { .. } => L2ShapeTag::S,
            ShapeWitness::P { .. } => L2ShapeTag::P,
        }
    }

    fn instance_s(&self) -> qlab_air::l2::L2BucketInstanceV2 {
        let ShapeWitness::S { reg_leaves, reg_witnesses, dv } = &self.shape else {
            unreachable!("instance_s on a shape-S witness")
        };
        qlab_air::l2::build_bucket_l2_v2(
            qlab_l2::v2::log_height(qlab_l2::Shape::S),
            &self.inputs,
            &self.outputs,
            self.fee,
            &self.witnesses,
            self.anchor,
            reg_leaves,
            reg_witnesses,
            self.registry_root,
            &self.fee_slot,
            *dv,
        )
    }

    fn instance_p(&self) -> qlab_air::l2p::L2PBucketInstance {
        let ShapeWitness::P { policy, vp } = &self.shape else {
            unreachable!("instance_p on a shape-P witness")
        };
        qlab_air::l2p::build_bucket_l2p_v2(
            qlab_l2::v2::log_height(qlab_l2::Shape::P),
            &self.inputs,
            &self.outputs,
            self.fee,
            &self.witnesses,
            self.anchor,
            policy,
            self.registry_root,
            *vp,
            &self.fee_slot,
            [0; 4],
            false,
        )
    }

    /// The instance's public values, without proving.
    pub fn pvs(&self) -> Vec<u32> {
        self.statement().pvs
    }

    /// What the instance states, without proving: its PVs, anchor, three
    /// nullifiers (the inputs', then slot 3's) and two output commitments.
    pub fn statement(&self) -> WitnessStatement {
        match self.shape {
            ShapeWitness::S { .. } => {
                let i = self.instance_s();
                WitnessStatement { pvs: i.pvs, anchor: i.anchor, nullifiers: i.nf, commitments: i.cm_out }
            }
            ShapeWitness::P { .. } => {
                let i = self.instance_p();
                WitnessStatement {
                    pvs: i.pvs,
                    anchor: i.anchor,
                    nullifiers: [i.nf[0], i.nf[1], i.nf3],
                    commitments: i.cm_out,
                }
            }
        }
    }

    /// Prove the instance: its public values and the serialized proof.
    pub fn prove(&self) -> (Vec<u32>, Vec<u8>) {
        let (pvs, proof) = match self.shape {
            ShapeWitness::S { .. } => {
                let inst = self.instance_s();
                let (_, proof) = qlab_l2::v2::prove_s(&inst.air, &inst.pvs);
                (inst.pvs, proof)
            }
            ShapeWitness::P { .. } => {
                let inst = self.instance_p();
                let (_, proof) = qlab_l2::v2::prove_p(&inst.air, &inst.pvs);
                (inst.pvs, proof)
            }
        };
        (pvs, bincode::serialize(&proof).expect("a proof serializes"))
    }
}

/// What a [`SpendWitness`] states ([`SpendWitness::statement`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessStatement {
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub nullifiers: [[u64; 4]; 3],
    pub commitments: [[u64; 4]; 2],
}

/// **Lab #924: prove a [`PreparedV2`] here.** The proof goes into the
/// prepared transaction, nothing else changes — the instance rebuilt from the
/// witness must state the prepared PVs (asserted: one process built both).
pub fn prove_prepared(p: PreparedV2) -> BuiltV2 {
    let (pvs, proof) = p.witness.prove();
    assert_eq!(pvs, p.pvs, "the witness proves the PVs the prepared transaction states");
    let mut tx = p.tx;
    tx.proof = proof;
    BuiltV2 { tx, pvs: p.pvs, auth: p.auth, outputs: p.outputs, shape: p.shape }
}

/// Slot 3 of a v2 S/P spend, as the device made it: an exact-fee asset-0
/// note (`d3 = 0`, its witness read from the served tree) or a dummy whose
/// `nk`/`ρ`/`rseed` and throwaway auth tree come from device entropy
/// (`d3 = 1`, [`LocalAuth::dummy`] / seam A's `draw_dummy`).
#[derive(Clone, Copy)]
pub enum FeeIn<'a> {
    Exact(&'a L2AuthInput),
    Dummy(&'a L2AuthInput),
}

/// A v2 input's note commitment.
fn cm_of_v2(input: &L2AuthInput) -> [u64; 4] {
    derive_input_l2_v2(input).2
}

fn witness_of_v2(tree: &CommitmentTree, input: &L2AuthInput) -> Result<MerkleWitness, SpendError> {
    let pos = tree.position_of(&cm_of_v2(input)).ok_or_else(|| {
        SpendError::Served("an input note is not in the served commitment tree".into())
    })?;
    Ok(tree.auth_path(pos, tree.len()))
}

fn fee_slot_v2(tree: &CommitmentTree, fee_in: FeeIn, fee: u64) -> Result<FeeSlotV2, SpendError> {
    Ok(match fee_in {
        FeeIn::Exact(note) => {
            if note.asset != 0 || note.value != fee {
                return Err(SpendError::FeeNoteNotExact {
                    value: note.value,
                    asset: note.asset,
                    fee,
                });
            }
            FeeSlotV2::Exact {
                input: note.clone(),
                witness: witness_of_v2(tree, note)?,
            }
        }
        FeeIn::Dummy(dummy) => FeeSlotV2::Dummy {
            input: dummy.clone(),
        },
    })
}

/// The descriptor of one slot, its leaf checked against the PVs' copy.
fn descriptor(path: &L2AuthPath, pvs: &[u32], at: usize) -> AuthDescriptor {
    assert_eq!(
        pvs[at..at + 16],
        pv_chunks(&path.leaf),
        "the slot's leaf is the one its PVs carry"
    );
    AuthDescriptor::MlDsa44 {
        leaf_index: path.leaf_index,
        leaf: digest_bytes(&path.leaf),
    }
}

fn descriptors(shape: qlab_l2::Shape, paths: &[&L2AuthPath], pvs: &[u32]) -> Vec<AuthDescriptor> {
    paths
        .iter()
        .enumerate()
        .map(|(k, p)| descriptor(p, pvs, qlab_l2::v2::pv_leaf(shape, k)))
        .collect()
}

// ---------------------------------------------------------------- shape S

/// **A v2 shape-S spend** (Cloaked assets): `inputs` are the device's two
/// slot inputs; with `dv` the second is a device-made dummy (value 0, asset
/// 0, off-tree) and only the first is real. Proves at 2^20.
pub fn build_s_v2<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2AuthInput; 2],
    dv: bool,
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    rng: &mut R,
) -> Result<BuiltV2, SpendError> {
    Ok(prove_prepared(prepare_s_v2(served, inputs, dv, fee_in, outs, fee, rng)?))
}

/// **Lab #924 5A-D1: the device half of [`build_s_v2`].** Everything the
/// transaction states — anchor, nullifiers, output commitments, fee, surface,
/// discovery — and the PVs, with the proof left empty; the witness a prover
/// needs travels in [`PreparedV2::witness`]. Draws from `rng` exactly as
/// [`build_s_v2`] does (outputs, then discovery): the prove between them
/// draws nothing from it.
pub fn prepare_s_v2<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2AuthInput; 2],
    dv: bool,
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    rng: &mut R,
) -> Result<PreparedV2, SpendError> {
    let tree = served.commitment_tree()?;
    let regs = [
        served.registry(inputs[0].asset)?,
        served.registry(inputs[1].asset)?,
    ];
    assemble_s_v2(&tree, &regs, inputs, dv, fee_in, outs, fee, rng)
}

#[allow(clippy::too_many_arguments)]
fn assemble_s_v2<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    regs: &[RegistryOpening; 2],
    inputs: [&L2AuthInput; 2],
    dv: bool,
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    rng: &mut R,
) -> Result<PreparedV2, SpendError> {
    assert!(
        !(dv && matches!(fee_in, FeeIn::Exact(_))),
        "an exact slot-3 fee note is built with two real inputs"
    );
    // `build_bucket_l2_v2` asserts this; the device supplies the dummy, so it
    // is refused here by name rather than reaching that panic.
    if dv && (inputs[1].value != 0 || inputs[1].asset != 0) {
        return Err(SpendError::DummyNotEmpty {
            value: inputs[1].value,
            asset: inputs[1].asset,
        });
    }
    if regs[0].root != regs[1].root {
        return Err(SpendError::RegistryMoved);
    }
    let anchor = tree.root();
    let outputs = l2_outputs(outs, rng);
    let fee_slot = fee_slot_v2(tree, fee_in, fee)?;
    let witnesses = [
        witness_of_v2(tree, inputs[0])?,
        if dv {
            off_tree_witness()
        } else {
            witness_of_v2(tree, inputs[1])?
        },
    ];
    let witness = SpendWitness {
        inputs: [inputs[0].clone(), inputs[1].clone()],
        witnesses,
        outputs,
        fee,
        anchor,
        registry_root: regs[0].root,
        fee_slot: fee_slot.clone(),
        shape: ShapeWitness::S {
            reg_leaves: [regs[0].leaf, regs[1].leaf],
            reg_witnesses: [regs[0].witness, regs[1].witness],
            dv,
        },
    };
    let inst = witness.instance_s();
    let auth = descriptors(
        qlab_l2::Shape::S,
        &[&inputs[0].auth, &inputs[1].auth, &fee_slot.input().auth],
        &inst.pvs,
    );
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, outs, rng);
    let surface = L2Surface {
        shape: L2ShapeTag::S,
        registry_root: digest_bytes(&inst.registry_root),
        vpublic: None,
        write: None,
        exit_rkm: [0; 32],
    };
    let nf = [inst.nf[0], inst.nf[1]];
    let tx = unproved_entry(&anchor, &nf, &inst.nf[2], &inst.cm_out, fee, surface, discovery);
    Ok(PreparedV2 {
        tx,
        pvs: inst.pvs,
        auth,
        outputs: notes,
        shape: L2ShapeTag::S,
        witness,
    })
}

// ---------------------------------------------------------------- shape P

/// **A v2 shape-P spend** of two real inputs, each input's policy built from
/// its served opening and [`PolicyContext`] against the input's **v2** `rkm`,
/// and a `vPublic` per row (as v1's `build_p_with`). Proves at 2^20.
#[allow(clippy::too_many_arguments)]
pub fn build_p_v2<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2AuthInput; 2],
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<BuiltV2, SpendError> {
    Ok(prove_prepared(prepare_p_v2(served, inputs, fee_in, outs, fee, ctx, vp, rng)?))
}

/// **Lab #924 5A-D1: the device half of [`build_p_v2`]** — as
/// [`prepare_s_v2`]. An issuer row (a non-zero `isk` or `vPublic`) prepares
/// as before but never leaves the device: its witness does not encode.
#[allow(clippy::too_many_arguments)]
pub fn prepare_p_v2<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    inputs: [&L2AuthInput; 2],
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<PreparedV2, SpendError> {
    let tree = served.commitment_tree()?;
    let regs = [
        served.registry(inputs[0].asset)?,
        served.registry(inputs[1].asset)?,
    ];
    policies_then_p_v2(&tree, &regs, inputs, fee_in, outs, fee, ctx, vp, rng)
}

/// The policies from the openings (keyed by each input's v2 `rkm`), then P.
#[allow(clippy::too_many_arguments)]
fn policies_then_p_v2<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    regs: &[RegistryOpening; 2],
    inputs: [&L2AuthInput; 2],
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<PreparedV2, SpendError> {
    if regs[0].root != regs[1].root {
        return Err(SpendError::RegistryMoved);
    }
    let rkm = |i: &L2AuthInput| derive_input_l2_v2(i).1;
    let policy = [
        policy_input(&regs[0], &rkm(inputs[0]), ctx[0])?,
        policy_input(&regs[1], &rkm(inputs[1]), ctx[1])?,
    ];
    assemble_p_v2(
        tree,
        inputs,
        fee_in,
        outs,
        fee,
        policy,
        regs[0].root,
        vp,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_p_v2<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    inputs: [&L2AuthInput; 2],
    fee_in: FeeIn,
    outs: &[Out; 2],
    fee: u64,
    policy: [L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    rng: &mut R,
) -> Result<PreparedV2, SpendError> {
    let anchor = tree.root();
    let outputs = l2_outputs(outs, rng);
    let fee_slot = fee_slot_v2(tree, fee_in, fee)?;
    let witness = SpendWitness {
        inputs: [inputs[0].clone(), inputs[1].clone()],
        witnesses: [witness_of_v2(tree, inputs[0])?, witness_of_v2(tree, inputs[1])?],
        outputs,
        fee,
        anchor,
        registry_root,
        fee_slot: fee_slot.clone(),
        shape: ShapeWitness::P { policy, vp },
    };
    let inst = witness.instance_p();
    let auth = descriptors(
        qlab_l2::Shape::P,
        &[&inputs[0].auth, &inputs[1].auth, &fee_slot.input().auth],
        &inst.pvs,
    );
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, outs, rng);
    let term = |k: usize| {
        if vp[k].amount == 0 {
            VPublicTerm::NONE
        } else {
            VPublicTerm {
                redeem: vp[k].redeem,
                amount: vp[k].amount,
                asset: inputs[k].asset as u16,
            }
        }
    };
    let surface = L2Surface {
        shape: L2ShapeTag::P,
        registry_root: digest_bytes(&registry_root),
        vpublic: Some([term(0), term(1)]),
        write: None,
        exit_rkm: [0; 32],
    };
    let tx = unproved_entry(&anchor, &inst.nf, &inst.nf3, &inst.cm_out, fee, surface, discovery);
    Ok(PreparedV2 {
        tx,
        pvs: inst.pvs,
        auth,
        outputs: notes,
        shape: L2ShapeTag::P,
        witness,
    })
}

// ---------------------------------------------------------------- shape R

/// **A v2 shape-R registry write**: v1's `build_r` with the fee input a v2
/// input (one slot). Proves at 2^19.
pub fn build_r_v2<E: Endpoint, R: rand::CryptoRng>(
    served: &Served<E>,
    fee_input: &L2AuthInput,
    change: &Recipient,
    fee: u64,
    new_leaf: RegistryLeaf,
    isk: [u64; 4],
    rng: &mut R,
) -> Result<BuiltRV2, SpendError> {
    let tree = served.commitment_tree()?;
    let slot = served.registry_slot(new_leaf.asset)?;
    assemble_r_v2(&tree, &slot, fee_input, change, fee, new_leaf, isk, rng)
}

#[allow(clippy::too_many_arguments)]
fn assemble_r_v2<R: rand::CryptoRng>(
    tree: &CommitmentTree,
    slot: &RegistrySlotOpening,
    fee_input: &L2AuthInput,
    change: &Recipient,
    fee: u64,
    new_leaf: RegistryLeaf,
    isk: [u64; 4],
    rng: &mut R,
) -> Result<BuiltRV2, SpendError> {
    let change_value = fee_input
        .value
        .checked_sub(fee)
        .ok_or(SpendError::FeeExceedsInput {
            have: fee_input.value,
            fee,
        })?;
    let anchor = tree.root();
    let write = qlab_air::l2r::RegistryWrite {
        isk,
        old_leaf: slot.leaf,
        new_leaf,
        opening: slot.witness,
    };
    let out = L2TxOutput {
        value: change_value,
        asset: 0,
        rkm: change.rkm,
        rho: [0; 4],
        rseed: random_d4(rng),
    };
    let seed = qlab_air::l2r::SeedOutput {
        rkm: change.rkm,
        rseed: random_d4(rng),
    };
    let v2 = qlab_air::l2r::build_shape_r_v2_with_witnesses(
        qlab_l2::v2::log_height(qlab_l2::Shape::R),
        fee_input,
        &witness_of_v2(tree, fee_input)?,
        anchor,
        &out,
        fee,
        &write,
        &seed,
    );
    let inst = v2.inst;
    if inst.old_root != slot.root {
        return Err(SpendError::RegistryMoved);
    }
    assert_eq!(v2.leaf, fee_input.auth.leaf, "R's leaf is the fee input's");
    let (_, proof) = qlab_l2::v2::prove_r(&inst.air, &inst.pvs);
    let auth = descriptors(qlab_l2::Shape::R, &[&fee_input.auth], &inst.pvs);
    // As v1: the change takes the nullifier as its ρ, the seed output 1's.
    let note = L2Note {
        value: out.value,
        asset: 0,
        rkm: out.rkm,
        rho: inst.nf,
        rseed: out.rseed,
    };
    assert_eq!(
        note.commitment(),
        inst.cm_out,
        "the change note is the one the proof commits"
    );
    let seed_note = L2Note {
        value: 0,
        asset: new_leaf.asset,
        rkm: seed.rkm,
        rho: qlab_air::narrow::derive_output_rho(&inst.nf, 1),
        rseed: seed.rseed,
    };
    assert_eq!(
        seed_note.commitment(),
        inst.cm_seed,
        "the seed note is the one the proof commits"
    );
    let mut bundles = Vec::new();
    let mut payloads = Vec::new();
    for n in [&note, &seed_note] {
        let enc =
            qlab_note::scan::encrypt_notes_to_recipient(&change.ek, std::slice::from_ref(n), rng);
        bundles.push(enc.bundle);
        payloads.extend(enc.payloads);
    }
    let discovery = encode_committed_discovery_with_width(&bundles, &payloads, L2_PAYLOAD_LEN);
    let new_root = digest_bytes(&inst.new_root);
    let surface = L2Surface {
        shape: L2ShapeTag::R,
        registry_root: digest_bytes(&inst.old_root),
        vpublic: None,
        write: Some(RegistryWriteSurface {
            new_root,
            leaf_lanes: new_leaf.state()[..15].try_into().expect("15 lanes"),
        }),
        exit_rkm: [0; 32],
    };
    let tx = TxEntry {
        auth: qlab_devnet::annulet::L2_AUTH_ABSENT.to_vec(),
        proof: bincode::serialize(&proof).expect("a proof serializes"),
        public: TxPublic {
            anchor: digest_bytes(&anchor),
            nullifiers: vec![digest_bytes(&inst.nf)],
            commitments: vec![digest_bytes(&inst.cm_out), digest_bytes(&inst.cm_seed)],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        discovery,
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: surface.encode(),
    };
    Ok(BuiltRV2 {
        tx,
        pvs: inst.pvs,
        auth,
        output: note,
        seed: seed_note,
        new_root,
    })
}

// ---------------------------------------------------------------- the intent

// `intent_for` lives in `qlab-devnet::annulet` (below the node's consensus
// points, which cannot depend on this crate); re-exported for the device side.
pub use qlab_devnet::annulet::{intent_for, IntentError};

/// Put the signed section into `tx.auth` (replacing the absent marker).
pub fn attach(tx: &mut TxEntry, section: &AnnuletAuthSection) -> Result<(), AuthError> {
    tx.auth = section.encode()?;
    Ok(())
}

// ---------------------------------------------------------------- local signing

/// The single-party signer: one key's generation-`g` authorization master,
/// its AIR-form tree at `D_AUTH` and its cursor, all on this machine. For
/// callers that hold their own key (tests, faucet, sequencer); a remote-proving
/// wallet does the same steps on the device.
pub struct LocalAuth {
    master: Hash32,
    tree: AuthTree,
    cursor: Cursor,
}

impl LocalAuth {
    /// `sk`'s generation-`generation` keys, the cursor at `next` (persisted by
    /// the caller via [`LocalAuth::next`]). Builds the tree: `2^D_AUTH`
    /// ML-DSA-44 key generations.
    pub fn new(sk: &Hash32, generation: u32, next: u32) -> Result<Self, String> {
        let master = auth_master(sk, generation);
        let depth = D_AUTH as u8;
        Ok(Self {
            tree: AuthTree::build(&master, depth)?,
            cursor: Cursor::new(&master, depth, next)?,
            master,
        })
    }

    /// The tree's root as lanes: what an address's v2 `rkm` binds.
    pub fn auth_root(&self) -> [u64; 4] {
        digest_from_bytes(&self.tree.root())
    }

    /// The cursor position to persist.
    pub fn next(&self) -> u32 {
        self.cursor.next()
    }

    /// Consume the next leaf for a real slot and return its path, or `None`
    /// when the generation is exhausted.
    pub fn take(&mut self) -> Option<L2AuthPath> {
        let index = self.cursor.take()?;
        Some(self.path(index))
    }

    fn path(&self, index: u32) -> L2AuthPath {
        let siblings = self.tree.path(index);
        L2AuthPath {
            leaf: digest_from_bytes(&self.tree.leaf(index)),
            leaf_index: index,
            siblings: core::array::from_fn(|k| digest_from_bytes(&siblings[k])),
        }
    }

    /// A device-made dummy for slot `slot` (value 0, asset 0, off-tree) and
    /// its ephemeral key. `entropy` must be fresh from the OS CSPRNG per slot;
    /// `taken` is the leaf indices this transaction's other slots use.
    pub fn dummy(
        &self,
        entropy: &Hash32,
        slot: u8,
        taken: &[u32],
    ) -> Result<(L2AuthInput, mldsa::Key), String> {
        let d = draw_dummy(entropy, slot, &self.cursor, taken)?;
        let input = L2AuthInput {
            nk: digest_from_bytes(&d.nk),
            value: 0,
            asset: 0,
            rho: digest_from_bytes(&d.rho),
            rseed: digest_from_bytes(&d.rseed),
            d: [0, 0],
            auth: L2AuthPath {
                leaf: digest_from_bytes(&d.descriptor.leaf()),
                leaf_index: d.leaf_index,
                siblings: core::array::from_fn(|k| digest_from_bytes(&d.auth_path[k])),
            },
        };
        assert_eq!(
            digest_bytes(&input.auth.root()),
            d.auth_root,
            "seam A's fold is the AIR's"
        );
        Ok((input, d.key))
    }
}

/// Sign `intent` slot by slot: a slot whose descriptor one of `dummies`
/// makes is signed with that ephemeral key, every other slot with `auth`'s
/// leaf key at the slot's index. A slot neither can sign is refused as
/// [`AuthError::LeafMismatch`] before anything is signed.
pub fn sign_locally(
    intent: &AnnuletIntent,
    auth: &LocalAuth,
    dummies: &[&mldsa::Key],
) -> Result<AnnuletAuthSection, AuthError> {
    enum SlotKey<'a> {
        Dummy(&'a mldsa::Key),
        Leaf(mldsa::Key),
    }
    let mut slot_keys = Vec::with_capacity(intent.auth.len());
    for (slot, d) in intent.auth.iter().enumerate() {
        let index = d.leaf_index();
        if let Some(k) = dummies.iter().find(|k| k.descriptor(index) == *d) {
            slot_keys.push(SlotKey::Dummy(k));
            continue;
        }
        let k = leaf_key(&auth.master, index);
        if k.descriptor(index) != *d {
            return Err(AuthError::LeafMismatch { slot });
        }
        slot_keys.push(SlotKey::Leaf(k));
    }
    let keys: Vec<&mldsa::Key> = slot_keys
        .iter()
        .map(|k| match k {
            SlotKey::Dummy(k) => *k,
            SlotKey::Leaf(k) => k,
        })
        .collect();
    AnnuletAuthSection::sign(intent, &keys)
}

#[cfg(test)]
mod tests;
