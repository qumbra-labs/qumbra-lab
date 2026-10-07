//! **The proving bundle** (lab #924 5A-D1; design
//! `remote-proving-authorization-shape-annulet`, "Who holds what").
//!
//! What a device hands a prover that is not itself: the Candidate A S or P
//! transaction **with its proof empty and its signed authorization section
//! attached**, and the [`SpendWitness`] the AIR instance is built from. The
//! device has computed everything the intent binds — nullifiers, output
//! commitments, fee, anchor, registry root, discovery, the validity height —
//! and signed it before the bundle leaves; the prover's only freedom is the
//! proof, and a proof of anything else fails the node's PV binding.
//!
//! **What it never carries.** No `sk`, no seed, no ML-DSA leaf secret (the
//! section holds signatures and verifying keys; the witness holds `nk`, the
//! public leaves and their paths), and **no issuer secret**: the encoding has
//! no field for a P row's `isk`, and a witness with a non-zero `isk` or a
//! non-zero `vPublic` term does not encode. That is also the service's issuer
//! refusal (5A-D3): an issuer operation stays on the device.
//!
//! **The encoding** is fixed-width and decoded whole, at an exact length:
//! a domain tag, a version, the shape, the transaction (the Annulet tx wire,
//! `qlab_p2p::codec`, behind a bounded length), then the witness lanes. Every
//! count and depth is fixed by the shape, so the decoder allocates nothing a
//! length prefix did not first bound; the prover service's byte ceiling is
//! the outer wall, this decoder the inner one.

use qlab_air::l2::{
    FeeSlotV2, L2AuthInput, L2AuthPath, L2TxOutput, RegistryLeaf, RegistryWitness, D_AUTH,
    REGISTRY_DEPTH,
};
use qlab_air::l2p::{FreezeOpening, L2PolicyInput, PolicyWitness, VPublic, POLICY_DEPTH};
use qlab_air::narrow::{MerkleWitness, MERKLE_DEPTH};
use qlab_devnet::annulet::{
    auth_shape, intent_for, AuthContext, L2ShapeTag, L2Surface, L2_AUTH_ABSENT,
};
use qlab_devnet::body::TxEntry;
use qlab_devnet::forms::L2AuthForm;
use qlab_note::hash::digest_bytes;
use qlab_remote_auth::annulet::AnnuletAuthSection;

use crate::v2::{ShapeWitness, SpendWitness};

/// The bundle's domain tag, first on the wire.
pub const BUNDLE_DOMAIN: &[u8] = b"qumbra:remote-auth:annulet-bundle:v1";
/// The bundle format version.
pub const BUNDLE_VERSION: u16 = 1;
/// The most bytes the transaction section may claim: a v2 S/P transaction
/// with an empty proof is its surface, three nullifiers, two commitments, the
/// discovery group (two 256-B payloads plus KEM ciphertexts) and a
/// three-slot ML-DSA-44 section — well under this.
pub const MAX_BUNDLE_TX_BYTES: usize = 64 * 1024;

/// Why a bundle was refused — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// The bytes are not a bundle: wrong domain, version, shape, a bad length
    /// or a field out of range. Names the field.
    Malformed(String),
    /// Shape R, or a P row with an issuer secret or a non-zero `vPublic`:
    /// issuer operations are not delegated (design "Issuer authority is out of
    /// scope for delegation"; 5A-D3).
    IssuerShape(String),
    /// The transaction already carries a proof.
    ProofPresent,
    /// The transaction carries no authorization section.
    AuthMissing,
    /// The witness does not state the transaction's public fields: the named
    /// field differs.
    StatementMismatch(&'static str),
    /// The section does not verify against the intent rebuilt from the
    /// transaction (the node's own check, run before any proving).
    Unauthorized(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Malformed(why) => write!(f, "not a proving bundle: {why}"),
            BundleError::IssuerShape(why) => {
                write!(f, "an issuer operation is not delegated: {why}")
            }
            BundleError::ProofPresent => {
                write!(f, "the bundle's transaction already carries a proof")
            }
            BundleError::AuthMissing => write!(
                f,
                "the bundle's transaction carries no authorization section"
            ),
            BundleError::StatementMismatch(what) => {
                write!(f, "the witness does not state the transaction's {what}")
            }
            BundleError::Unauthorized(why) => {
                write!(f, "the authorization section does not verify: {why}")
            }
        }
    }
}

impl std::error::Error for BundleError {}

/// **A proving bundle**: the unproved, signed transaction and its witness.
#[derive(Clone)]
pub struct ProvingBundle {
    tx: TxEntry,
    witness: SpendWitness,
}

impl ProvingBundle {
    /// A bundle of `tx` (proof empty, section attached) and `witness`.
    /// Refuses, by name, what a bundle may never be: a proved transaction,
    /// one without a section, and an issuer operation.
    pub fn new(tx: TxEntry, witness: SpendWitness) -> Result<Self, BundleError> {
        if !tx.proof.is_empty() {
            return Err(BundleError::ProofPresent);
        }
        if tx.auth == L2_AUTH_ABSENT || tx.auth.is_empty() {
            return Err(BundleError::AuthMissing);
        }
        holder_only(&witness)?;
        Ok(ProvingBundle { tx, witness })
    }

    /// The unproved, signed transaction.
    pub fn tx(&self) -> &TxEntry {
        &self.tx
    }

    /// The witness.
    pub fn witness(&self) -> &SpendWitness {
        &self.witness
    }

    /// The shape (S or P).
    pub fn shape(&self) -> L2ShapeTag {
        self.witness.shape_tag()
    }

    /// The wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend_from_slice(BUNDLE_DOMAIN);
        w.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
        w.push(shape_code(self.shape()));
        let tx = qlab_p2p::codec::encode_tx_annulet(&self.tx);
        assert!(
            tx.len() <= MAX_BUNDLE_TX_BYTES,
            "a v2 S/P transaction fits the bound"
        );
        w.extend_from_slice(&(tx.len() as u32).to_le_bytes());
        w.extend_from_slice(&tx);
        put_witness(&mut w, &self.witness);
        w
    }

    /// Decode a bundle, whole, at an exact length. Every refusal names its
    /// field; nothing is allocated from an unchecked length.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        let mut r = Rd { b: bytes, at: 0 };
        if r.take(BUNDLE_DOMAIN.len(), "domain")? != BUNDLE_DOMAIN {
            return Err(BundleError::Malformed("the domain tag".into()));
        }
        let version = u16::from_le_bytes(r.take(2, "version")?.try_into().expect("2 bytes"));
        if version != BUNDLE_VERSION {
            return Err(BundleError::Malformed(format!(
                "version {version}, expected {BUNDLE_VERSION}"
            )));
        }
        let shape = match r.u8("shape")? {
            0 => L2ShapeTag::S,
            1 => L2ShapeTag::P,
            2 => {
                return Err(BundleError::IssuerShape(
                    "shape R (a registry write)".into(),
                ))
            }
            other => return Err(BundleError::Malformed(format!("shape code {other}"))),
        };
        let tx_len = r.u32("tx length")? as usize;
        if tx_len > MAX_BUNDLE_TX_BYTES {
            return Err(BundleError::Malformed(format!(
                "a {tx_len}-byte transaction, over {MAX_BUNDLE_TX_BYTES}"
            )));
        }
        let tx_bytes = r.take(tx_len, "tx")?;
        let tx = qlab_p2p::codec::decode_tx_annulet_with(tx_bytes, L2AuthForm::CandidateA)
            .map_err(|e| BundleError::Malformed(format!("the transaction: {e:?}")))?; // debug-ok: a named codec error
        if tx.public.nullifiers.len() != 3 || tx.public.commitments.len() != 2 {
            return Err(BundleError::Malformed(
                "an S/P transaction states 3 nullifiers and 2 commitments".into(),
            ));
        }
        let surface = L2Surface::decode(&tx.l2)
            .ok()
            .flatten()
            .ok_or_else(|| BundleError::Malformed("the transaction's surface".into()))?;
        if surface.shape != shape {
            return Err(BundleError::Malformed(
                "the surface's shape is not the bundle's".into(),
            ));
        }
        let witness = get_witness(&mut r, shape)?;
        if r.at != bytes.len() {
            return Err(BundleError::Malformed(format!(
                "{} trailing bytes",
                bytes.len() - r.at
            )));
        }
        ProvingBundle::new(tx, witness)
    }

    /// **The worker's lock, before any proving** (lab #924 B3): the witness
    /// must state exactly the transaction's public fields — anchor,
    /// nullifiers, commitments, registry root, fee, a P transaction's zero
    /// `vPublic` — and the section must verify against the intent rebuilt
    /// from the transaction on the net `ctx` names (the node's own rebuild,
    /// `qlab_devnet::annulet::intent_for`). The validity height is not judged
    /// here: the worker does not know the tip; the node does.
    pub fn check(&self, ctx: &AuthContext) -> Result<(), BundleError> {
        let st = self.witness.statement();
        let p = &self.tx.public;
        if p.anchor != digest_bytes(&st.anchor) {
            return Err(BundleError::StatementMismatch("anchor"));
        }
        if p.nullifiers.iter().ne(st
            .nullifiers
            .iter()
            .map(digest_bytes)
            .collect::<Vec<_>>()
            .iter())
        {
            return Err(BundleError::StatementMismatch("nullifiers"));
        }
        if p.commitments.iter().ne(st
            .commitments
            .iter()
            .map(digest_bytes)
            .collect::<Vec<_>>()
            .iter())
        {
            return Err(BundleError::StatementMismatch("output commitments"));
        }
        if p.fee != self.witness.fee {
            return Err(BundleError::StatementMismatch("fee"));
        }
        let surface = L2Surface::decode(&self.tx.l2)
            .ok()
            .flatten()
            .ok_or(BundleError::StatementMismatch("surface"))?;
        if surface.registry_root != digest_bytes(&self.witness.registry_root) {
            return Err(BundleError::StatementMismatch("registry root"));
        }
        if let Some(terms) = surface.vpublic {
            if terms.iter().any(|t| t.amount != 0) {
                return Err(BundleError::IssuerShape("a non-zero vPublic term".into()));
            }
        }
        let section = AnnuletAuthSection::decode(auth_shape(surface.shape), &self.tx.auth)
            .map_err(|e| BundleError::Unauthorized(format!("{e:?}")))?; // debug-ok: a named auth error
                                                                        // The section's leaves are the slots' leaves the witness proves.
        let leaves = self.slot_paths();
        if section.slots.len() != leaves.len()
            || section.slots.iter().zip(&leaves).any(|(s, p)| {
                s.descriptor.leaf_index() != p.leaf_index
                    || s.descriptor.leaf() != digest_bytes(&p.leaf)
            })
        {
            return Err(BundleError::StatementMismatch("authorization leaves"));
        }
        let descriptors: Vec<_> = section.slots.iter().map(|s| s.descriptor).collect();
        let intent = intent_for(
            &self.tx,
            ctx.genesis_format(),
            &ctx.genesis_hash,
            section.valid_until_height,
            &descriptors,
        )
        .map_err(|e| BundleError::Unauthorized(format!("the intent does not rebuild: {e:?}")))?; // debug-ok
        section
            .verify_intent(&intent)
            .map_err(|e| BundleError::Unauthorized(format!("{e:?}")))?; // debug-ok
        Ok(())
    }

    /// Check ([`Self::check`]), then prove: the transaction with its proof.
    /// The proof is the only thing this adds.
    pub fn prove(&self, ctx: &AuthContext) -> Result<TxEntry, BundleError> {
        self.check(ctx)?;
        let (_, proof) = self.witness.prove();
        let mut tx = self.tx.clone();
        tx.proof = proof;
        Ok(tx)
    }

    fn slot_paths(&self) -> [&L2AuthPath; 3] {
        let w = &self.witness;
        [
            &w.inputs[0].auth,
            &w.inputs[1].auth,
            &w.fee_slot.input().auth,
        ]
    }
}

/// An issuer operation never becomes a bundle.
fn holder_only(w: &SpendWitness) -> Result<(), BundleError> {
    if let ShapeWitness::P { policy, vp } = &w.shape {
        if policy.iter().any(|p| p.isk != [0; 4]) {
            return Err(BundleError::IssuerShape(
                "a P row with an issuer secret".into(),
            ));
        }
        if vp.iter().any(|v| v.amount != 0 || v.redeem) {
            return Err(BundleError::IssuerShape("a non-zero vPublic term".into()));
        }
    }
    Ok(())
}

fn shape_code(s: L2ShapeTag) -> u8 {
    match s {
        L2ShapeTag::S => 0,
        L2ShapeTag::P => 1,
        L2ShapeTag::R => 2,
    }
}

// ---------------------------------------------------------------- the lanes

fn put_u64(w: &mut Vec<u8>, x: u64) {
    w.extend_from_slice(&x.to_le_bytes());
}
fn put_lanes(w: &mut Vec<u8>, l: &[u64; 4]) {
    l.iter().for_each(|x| put_u64(w, *x));
}
fn put_bool(w: &mut Vec<u8>, b: bool) {
    w.push(u8::from(b));
}

fn put_auth_input(w: &mut Vec<u8>, i: &L2AuthInput) {
    put_lanes(w, &i.nk);
    put_u64(w, i.value);
    put_u64(w, i.asset);
    put_lanes(w, &i.rho);
    put_lanes(w, &i.rseed);
    put_u64(w, i.d[0]);
    put_u64(w, i.d[1]);
    put_lanes(w, &i.auth.leaf);
    w.extend_from_slice(&i.auth.leaf_index.to_le_bytes());
    i.auth.siblings.iter().for_each(|s| put_lanes(w, s));
}
fn put_merkle(w: &mut Vec<u8>, m: &MerkleWitness) {
    m.siblings.iter().for_each(|s| put_lanes(w, s));
    m.path_bits.iter().for_each(|b| put_bool(w, *b));
}
fn put_output(w: &mut Vec<u8>, o: &L2TxOutput) {
    put_u64(w, o.value);
    put_u64(w, o.asset);
    put_lanes(w, &o.rkm);
    put_lanes(w, &o.rho);
    put_lanes(w, &o.rseed);
}
fn put_leaf(w: &mut Vec<u8>, l: &RegistryLeaf) {
    put_u64(w, l.asset);
    put_lanes(w, &l.issuer_key);
    put_u64(w, l.mode);
    put_lanes(w, &l.freeze_root);
    put_lanes(w, &l.allow_root);
    put_u64(w, l.flags);
}
fn put_reg_witness(w: &mut Vec<u8>, r: &RegistryWitness) {
    r.siblings.iter().for_each(|s| put_lanes(w, s));
    r.path_bits.iter().for_each(|b| put_bool(w, *b));
}
fn put_policy_witness(w: &mut Vec<u8>, p: &PolicyWitness) {
    p.siblings.iter().for_each(|s| put_lanes(w, s));
    p.path_bits.iter().for_each(|b| put_bool(w, *b));
}

/// The witness lanes. A P row's `isk` has no field (the encoder runs only on
/// a witness [`holder_only`] passed, so it is zero; the decoder sets zero).
fn put_witness(w: &mut Vec<u8>, s: &SpendWitness) {
    s.inputs.iter().for_each(|i| put_auth_input(w, i));
    s.witnesses.iter().for_each(|m| put_merkle(w, m));
    s.outputs.iter().for_each(|o| put_output(w, o));
    put_u64(w, s.fee);
    put_lanes(w, &s.anchor);
    put_lanes(w, &s.registry_root);
    match &s.fee_slot {
        FeeSlotV2::Exact { input, witness } => {
            w.push(0);
            put_auth_input(w, input);
            put_merkle(w, witness);
        }
        FeeSlotV2::Dummy { input } => {
            w.push(1);
            put_auth_input(w, input);
        }
    }
    match &s.shape {
        ShapeWitness::S {
            reg_leaves,
            reg_witnesses,
            dv,
        } => {
            reg_leaves.iter().for_each(|l| put_leaf(w, l));
            reg_witnesses.iter().for_each(|r| put_reg_witness(w, r));
            put_bool(w, *dv);
        }
        ShapeWitness::P { policy, .. } => {
            for p in policy {
                put_leaf(w, &p.leaf);
                put_reg_witness(w, &p.reg_witness);
                put_lanes(w, &p.freeze.key_lo);
                put_lanes(w, &p.freeze.key_hi);
                put_policy_witness(w, &p.freeze.witness);
                put_policy_witness(w, &p.allow);
            }
        }
    }
}

struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], BundleError> {
        if self.b.len() - self.at < n {
            return Err(BundleError::Malformed(format!("truncated at {what}")));
        }
        let s = &self.b[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self, what: &str) -> Result<u8, BundleError> {
        Ok(self.take(1, what)?[0])
    }
    fn u32(&mut self, what: &str) -> Result<u32, BundleError> {
        Ok(u32::from_le_bytes(
            self.take(4, what)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self, what: &str) -> Result<u64, BundleError> {
        Ok(u64::from_le_bytes(
            self.take(8, what)?.try_into().expect("8 bytes"),
        ))
    }
    fn lanes(&mut self, what: &str) -> Result<[u64; 4], BundleError> {
        Ok([
            self.u64(what)?,
            self.u64(what)?,
            self.u64(what)?,
            self.u64(what)?,
        ])
    }
    fn bool(&mut self, what: &str) -> Result<bool, BundleError> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(BundleError::Malformed(format!(
                "{what}: {other} is not a bit"
            ))),
        }
    }
    fn auth_input(&mut self) -> Result<L2AuthInput, BundleError> {
        let nk = self.lanes("nk")?;
        let value = self.u64("value")?;
        let asset = self.u64("asset")?;
        let rho = self.lanes("rho")?;
        let rseed = self.lanes("rseed")?;
        let d = [self.u64("d")?, self.u64("d")?];
        let leaf = self.lanes("auth leaf")?;
        let leaf_index = self.u32("leaf index")?;
        if (leaf_index as u64) >> D_AUTH != 0 {
            return Err(BundleError::Malformed(format!(
                "leaf index {leaf_index} is past depth {D_AUTH}"
            )));
        }
        let mut siblings = [[0u64; 4]; D_AUTH];
        for s in siblings.iter_mut() {
            *s = self.lanes("auth sibling")?;
        }
        Ok(L2AuthInput {
            nk,
            value,
            asset,
            rho,
            rseed,
            d,
            auth: L2AuthPath {
                leaf,
                leaf_index,
                siblings,
            },
        })
    }
    fn merkle(&mut self) -> Result<MerkleWitness, BundleError> {
        let mut siblings = [[0u64; 4]; MERKLE_DEPTH];
        for s in siblings.iter_mut() {
            *s = self.lanes("merkle sibling")?;
        }
        let mut path_bits = [false; MERKLE_DEPTH];
        for b in path_bits.iter_mut() {
            *b = self.bool("merkle path bit")?;
        }
        Ok(MerkleWitness {
            siblings,
            path_bits,
        })
    }
    fn output(&mut self) -> Result<L2TxOutput, BundleError> {
        Ok(L2TxOutput {
            value: self.u64("output value")?,
            asset: self.u64("output asset")?,
            rkm: self.lanes("output rkm")?,
            rho: self.lanes("output rho")?,
            rseed: self.lanes("output rseed")?,
        })
    }
    fn leaf(&mut self) -> Result<RegistryLeaf, BundleError> {
        Ok(RegistryLeaf {
            asset: self.u64("registry asset")?,
            issuer_key: self.lanes("issuer key")?,
            mode: self.u64("mode")?,
            freeze_root: self.lanes("freeze root")?,
            allow_root: self.lanes("allow root")?,
            flags: self.u64("flags")?,
        })
    }
    fn reg_witness(&mut self) -> Result<RegistryWitness, BundleError> {
        let mut siblings = [[0u64; 4]; REGISTRY_DEPTH];
        for s in siblings.iter_mut() {
            *s = self.lanes("registry sibling")?;
        }
        let mut path_bits = [false; REGISTRY_DEPTH];
        for b in path_bits.iter_mut() {
            *b = self.bool("registry path bit")?;
        }
        Ok(RegistryWitness {
            siblings,
            path_bits,
        })
    }
    fn policy_witness(&mut self, what: &str) -> Result<PolicyWitness, BundleError> {
        let mut siblings = [[0u64; 4]; POLICY_DEPTH];
        for s in siblings.iter_mut() {
            *s = self.lanes(what)?;
        }
        let mut path_bits = [false; POLICY_DEPTH];
        for b in path_bits.iter_mut() {
            *b = self.bool(what)?;
        }
        Ok(PolicyWitness {
            siblings,
            path_bits,
        })
    }
}

fn get_witness(r: &mut Rd<'_>, shape: L2ShapeTag) -> Result<SpendWitness, BundleError> {
    let inputs = [r.auth_input()?, r.auth_input()?];
    let witnesses = [r.merkle()?, r.merkle()?];
    let outputs = [r.output()?, r.output()?];
    let fee = r.u64("fee")?;
    let anchor = r.lanes("anchor")?;
    let registry_root = r.lanes("registry root")?;
    let fee_slot = match r.u8("fee slot")? {
        0 => FeeSlotV2::Exact {
            input: r.auth_input()?,
            witness: r.merkle()?,
        },
        1 => FeeSlotV2::Dummy {
            input: r.auth_input()?,
        },
        other => return Err(BundleError::Malformed(format!("fee slot code {other}"))),
    };
    let shape = match shape {
        L2ShapeTag::S => {
            let reg_leaves = [r.leaf()?, r.leaf()?];
            let reg_witnesses = [r.reg_witness()?, r.reg_witness()?];
            let dv = r.bool("dv")?;
            ShapeWitness::S {
                reg_leaves,
                reg_witnesses,
                dv,
            }
        }
        L2ShapeTag::P => {
            let mut row = || -> Result<L2PolicyInput, BundleError> {
                let leaf = r.leaf()?;
                let reg_witness = r.reg_witness()?;
                let key_lo = r.lanes("freeze key")?;
                let key_hi = r.lanes("freeze key")?;
                let witness = r.policy_witness("freeze sibling")?;
                let allow = r.policy_witness("allow sibling")?;
                Ok(L2PolicyInput {
                    leaf,
                    reg_witness,
                    freeze: FreezeOpening {
                        key_lo,
                        key_hi,
                        witness,
                    },
                    allow,
                    isk: [0; 4],
                })
            };
            let policy = [row()?, row()?];
            ShapeWitness::P {
                policy,
                vp: [VPublic::NONE; 2],
            }
        }
        L2ShapeTag::R => unreachable!("refused at the shape byte"),
    };
    Ok(SpendWitness {
        inputs,
        witnesses,
        outputs,
        fee,
        anchor,
        registry_root,
        fee_slot,
        shape,
    })
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
