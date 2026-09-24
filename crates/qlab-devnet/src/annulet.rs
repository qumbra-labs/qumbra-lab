//! The Annulet (Qumbra L2) chain form — lab issue #706 (l2-roadmap B1).
//!
//! Everything the Annulet form adds to the devnet chain types lives here, so
//! the L1 forms' modules only ever *refuse* Annulet values, never interpret
//! them:
//!
//! - [`HeaderExt`] — the header fields only an Annulet header carries
//!   (`l1_anchor`, `registry_root`), attached to [`crate::header::BlockHeader`]
//!   as `ext`; [`HeaderExt::NONE`] on every L1 header.
//! - [`L2_SURFACE_ABSENT`] — the canonical "no L2 surface" encoding of
//!   [`crate::body::TxEntry::l2`], under the #367 rider discipline (bytes,
//!   canonical, absence is `[0x00]`, never an empty `Vec`).
//!
//! **Nothing here depends on `qlab-l2`** (lab #706 P7): `qumbra-ffi`'s iOS and
//! wasm builds depend on this crate, and `qlab-l2` would pull the prover stack
//! into them. The shape tag is local; `qumbra-node` cross-locks it against
//! `qlab_l2::Shape`.

/// The Annulet-only header fields (lab #706 Q3, layout (H-a)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnuletHeaderFields {
    /// Height of the finalized L1 checkpoint this block reads (informational
    /// at Phase 0 — monotone only; B2).
    pub l1_anchor_height: u64,
    /// Root of that L1 checkpoint.
    pub l1_anchor_root: [u8; 32],
    /// The asset-registry root **after** this block (lab #706 Q6); every
    /// transaction's L2 surface binds the **parent** header's root.
    pub registry_root: [u8; 32],
}

/// The per-form header extension. L1 headers carry [`HeaderExt::NONE`]; the
/// v4/v5 serializers refuse anything else by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderExt {
    /// An L1 (v4/v5) header: no extension.
    L1,
    /// An Annulet header's extra fields.
    Annulet(AnnuletHeaderFields),
}

impl HeaderExt {
    /// The extension every L1 header carries.
    pub const NONE: HeaderExt = HeaderExt::L1;
}

/// The canonical encoding of "this transaction carries no L2 surface" —
/// every L1 transaction's [`crate::body::TxEntry::l2`].
pub const L2_SURFACE_ABSENT: &[u8] = &[0x00];

// ---------------------------------------------------------------------------
// The L2 transaction surface (lab #706 Q4)
// ---------------------------------------------------------------------------

use crate::body::{BlockBody, BodyError, TxEntry, TxVerifier};
use crate::fees::ArityBucket;
use crate::hash::keccak256;
use crate::header::{BlockHeader, Hash32};

/// The shape of an L2 transaction on the wire. **Local to `qlab-devnet`**
/// (P7); `qumbra-node/tests/annulet_shape_crosslock.rs` locks it 1:1 against
/// `qlab_l2::Shape`. The byte doubles as the surface's version (Q4 ruling): a
/// new shape, or a changed surface layout, is a new tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum L2ShapeTag {
    /// Shape S — sovereign (Cloaked) assets.
    S,
    /// Shape P — policy (Hybrid / Regulated) assets, with `vPublic`.
    P,
    /// Shape R — a registry write (lab #728): one slot registered or
    /// updated, with its own 1-in / 1-out fee spend.
    R,
}

impl L2ShapeTag {
    /// The wire byte: `0x01` S, `0x02` P, `0x03` R.
    pub const fn byte(self) -> u8 {
        match self {
            L2ShapeTag::S => 0x01,
            L2ShapeTag::P => 0x02,
            L2ShapeTag::R => 0x03,
        }
    }
    /// The inverse of [`Self::byte`]; any other byte is unknown.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(L2ShapeTag::S),
            0x02 => Some(L2ShapeTag::P),
            0x03 => Some(L2ShapeTag::R),
            _ => None,
        }
    }
}

/// One `vPublic` term of a shape-P transaction (row `k` = input `k`'s asset):
/// public issuance, the only place an asset's amount is ever visible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VPublicTerm {
    /// `true` = redeem (−amount), `false` = mint (+amount).
    pub redeem: bool,
    pub amount: u64,
    /// The asset revealed when `amount ≠ 0` — a 16-bit registry index;
    /// 0 when `amount = 0`.
    pub asset: u16,
}

impl VPublicTerm {
    /// The canonical "no issuance on this row".
    pub const NONE: VPublicTerm = VPublicTerm { redeem: false, amount: 0, asset: 0 };
}

/// A transaction's L2 surface: what an L2 proof binds beyond the L1 public
/// values (anchor / nullifiers / commitments / fee live in `TxPublic`).
///
/// **Registry-root binding (Q6):** `registry_root` must equal the **parent**
/// header's `registry_root`. B4's verifier enforces it (it holds the chain);
/// this codec only carries the value. For shape R it is the write's
/// **old** root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2Surface {
    pub shape: L2ShapeTag,
    pub registry_root: Hash32,
    /// `Some` exactly for shape P (the two rows' terms), `None` for S and R.
    pub vpublic: Option<[VPublicTerm; 2]>,
    /// `Some` exactly for shape R (lab #728): the write — the root after it
    /// and the new leaf, whole. `None` for S and P.
    pub write: Option<RegistryWriteSurface>,
}

/// The registry write an R surface carries (lab #728 Q1): the root after the
/// write, and the new leaf's 15 lanes in `RegistryLeaf::state()[..15]` order
/// — `asset ‖ issuer_key[4] ‖ mode ‖ freeze_root[4] ‖ allow_root[4] ‖ flags`,
/// the order B3's served opening already uses. The written slot is lane 0.
///
/// The node applies the leaf to its own tree and requires the result to be
/// `new_root`; the proof binds `new_root` to the leaf the circuit hashed, so
/// the leaf written is the leaf proven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryWriteSurface {
    pub new_root: Hash32,
    pub leaf_lanes: [u64; 15],
}

impl RegistryWriteSurface {
    /// The written slot — the new leaf's asset lane.
    pub fn asset(&self) -> u64 {
        self.leaf_lanes[0]
    }
}

/// Encoded surface lengths: S = tag ‖ root; P = S ‖ 2 × (redeem ‖ amount ‖ asset).
pub const L2_SURFACE_LEN_S: usize = 1 + 32;
/// See [`L2_SURFACE_LEN_S`].
pub const L2_SURFACE_LEN_P: usize = L2_SURFACE_LEN_S + 2 * (1 + 8 + 2);
/// R = tag ‖ old root ‖ new root ‖ the new leaf's 15 lanes (u64 LE) — 185 B.
pub const L2_SURFACE_LEN_R: usize = L2_SURFACE_LEN_S + 32 + 15 * 8;

/// Why an L2 surface was refused. Canonicity is byte-level (the rider rule):
/// a surface decodes only if re-encoding reproduces its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L2SurfaceError {
    /// Empty bytes — absence is `[0x00]`, never zero-length.
    Empty,
    /// The first byte is not a known shape tag (nor the absent marker).
    UnknownShape { got: u8 },
    /// Wrong total length for the shape.
    WrongLength { got: usize, want: usize },
    /// A `redeem` byte other than 0/1.
    BadRedeemByte { got: u8 },
    /// A zero-amount term with a sign or an asset set — a second encoding of
    /// "no issuance".
    NonCanonicalZeroTerm { row: usize },
}

impl L2Surface {
    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(L2_SURFACE_LEN_R);
        out.push(self.shape.byte());
        out.extend_from_slice(&self.registry_root);
        match (self.shape, &self.vpublic, &self.write) {
            (L2ShapeTag::S, None, None) => {}
            (L2ShapeTag::P, Some(terms), None) => {
                for t in terms {
                    out.push(t.redeem as u8);
                    out.extend_from_slice(&t.amount.to_le_bytes());
                    out.extend_from_slice(&t.asset.to_le_bytes());
                }
            }
            (L2ShapeTag::R, None, Some(w)) => {
                out.extend_from_slice(&w.new_root);
                for lane in &w.leaf_lanes {
                    out.extend_from_slice(&lane.to_le_bytes());
                }
            }
            // A locally-built surface whose parts do not match its shape is a
            // program error (the decoder cannot produce one).
            (shape, v, w) => panic!("L2 surface shape {shape:?} with vpublic {v:?} and write {w:?} (lab #706/#728)"),
        }
        out
    }

    /// Decode `bytes`: `Ok(None)` for the absent marker `[0x00]`,
    /// `Ok(Some(_))` for a canonical surface, `Err` otherwise.
    pub fn decode(bytes: &[u8]) -> Result<Option<L2Surface>, L2SurfaceError> {
        let (&tag, rest) = bytes.split_first().ok_or(L2SurfaceError::Empty)?;
        if bytes == L2_SURFACE_ABSENT {
            return Ok(None);
        }
        let shape = L2ShapeTag::from_byte(tag).ok_or(L2SurfaceError::UnknownShape { got: tag })?;
        let want = match shape {
            L2ShapeTag::S => L2_SURFACE_LEN_S,
            L2ShapeTag::P => L2_SURFACE_LEN_P,
            L2ShapeTag::R => L2_SURFACE_LEN_R,
        };
        if bytes.len() != want {
            return Err(L2SurfaceError::WrongLength { got: bytes.len(), want });
        }
        let registry_root: Hash32 = rest[..32].try_into().expect("length checked");
        let vpublic = match shape {
            L2ShapeTag::S | L2ShapeTag::R => None,
            L2ShapeTag::P => {
                let mut terms = [VPublicTerm::NONE; 2];
                for (row, term) in terms.iter_mut().enumerate() {
                    let at = 32 + row * 11;
                    let redeem = match rest[at] {
                        0 => false,
                        1 => true,
                        got => return Err(L2SurfaceError::BadRedeemByte { got }),
                    };
                    let amount = u64::from_le_bytes(rest[at + 1..at + 9].try_into().expect("len"));
                    let asset = u16::from_le_bytes(rest[at + 9..at + 11].try_into().expect("len"));
                    if amount == 0 && (redeem || asset != 0) {
                        return Err(L2SurfaceError::NonCanonicalZeroTerm { row });
                    }
                    *term = VPublicTerm { redeem, amount, asset };
                }
                Some(terms)
            }
        };
        let write = match shape {
            L2ShapeTag::S | L2ShapeTag::P => None,
            L2ShapeTag::R => {
                let new_root: Hash32 = rest[32..64].try_into().expect("length checked");
                let leaf_lanes: [u64; 15] = core::array::from_fn(|i| {
                    let at = 64 + 8 * i;
                    u64::from_le_bytes(rest[at..at + 8].try_into().expect("len"))
                });
                Some(RegistryWriteSurface { new_root, leaf_lanes })
            }
        };
        Ok(Some(L2Surface { shape, registry_root, vpublic, write }))
    }
}

// ---------------------------------------------------------------------------
// Fees (lab #706 Q7) — genesis parameters, never code constants
// ---------------------------------------------------------------------------

/// The L2 posted-price table, in asset-0 (fee-unit) base units. **Carried in
/// the Annulet genesis file** (`l2_params`), so the numbers are a genesis
/// choice. The devnet fixture's values (S = 1, P = 2) are **placeholders**
/// pending C2/B4's tariff with the fee-split design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2FeeTable {
    pub tier_s: u64,
    pub tier_p: u64,
    /// Shape R's tier (lab #728) — a labelled placeholder until the pilot
    /// prices it; the only price on exhausting the registry's slots.
    pub tier_r: u64,
}

impl L2FeeTable {
    /// The posted fee for a transaction of `shape` — exact, like the L1's.
    pub fn posted_fee_l2(&self, shape: L2ShapeTag) -> u64 {
        match shape {
            L2ShapeTag::S => self.tier_s,
            L2ShapeTag::P => self.tier_p,
            L2ShapeTag::R => self.tier_r,
        }
    }
}

// ---------------------------------------------------------------------------
// The Annulet body form
// ---------------------------------------------------------------------------

/// Domain of the Annulet body-commitment preimage.
pub const BODY_PREIMAGE_DOMAIN_ANNULET: &[u8] = b"qumbra:body:annulet:v1";

/// The Annulet body commitment. The per-transaction region is the v5 one
/// (explicit arity counts, the bucket's wire discriminant, length-prefixed
/// proof and discovery) with the **L2 surface** in the place the name rider
/// takes on L1; there is **no coinbase tail** — the L2 has no block reward,
/// and a body with a coinbase payee is refused before this is computed.
pub fn body_commitment_annulet(body: &BlockBody) -> Hash32 {
    let mut buf = BODY_PREIMAGE_DOMAIN_ANNULET.to_vec();
    for tx in &body.txs {
        buf.extend_from_slice(&tx.public.anchor);
        assert!(tx.public.nullifiers.len() <= u8::MAX as usize);
        buf.push(tx.public.nullifiers.len() as u8);
        for nf in &tx.public.nullifiers {
            buf.extend_from_slice(nf);
        }
        assert!(tx.public.commitments.len() <= u8::MAX as usize);
        buf.push(tx.public.commitments.len() as u8);
        for cm in &tx.public.commitments {
            buf.extend_from_slice(cm);
        }
        buf.push(tx.public.bucket.wire_discriminant());
        buf.extend_from_slice(&tx.public.fee.to_le_bytes());
        for field in [&tx.proof, &tx.discovery, &tx.l2] {
            buf.extend_from_slice(&(field.len() as u64).to_le_bytes());
            buf.extend_from_slice(field);
        }
    }
    keccak256(&buf)
}

/// One fee-unit note the Annulet genesis mints to the faucet (lab #706 Q5):
/// its commitment and its 128-B discovery payload
/// (`qlab_note::l2note::L2_PAYLOAD_LEN`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisNote {
    pub cm: Hash32,
    pub payload: Vec<u8>,
}

/// Domain of the Annulet **genesis** body commitment.
pub const GENESIS_BODY_DOMAIN_ANNULET: &[u8] = b"qumbra:body:annulet:genesis:v1";

/// The Annulet genesis body commitment: the empty body's Annulet commitment,
/// then the genesis notes (`count u32 ‖ [cm ‖ payload]×N`). Genesis notes are
/// valid **only at height 0** — no later body can carry them, because no body
/// type but this one has a place for them. Applying them to the commitment
/// tree is B3's (state); this is the commitment the genesis header binds.
///
/// # Panics
///
/// On a payload that is not exactly `L2_PAYLOAD_LEN` bytes (a locally-built
/// genesis; the loader refuses it as an error first).
pub fn genesis_body_commitment_annulet(notes: &[GenesisNote]) -> Hash32 {
    let mut buf = GENESIS_BODY_DOMAIN_ANNULET.to_vec();
    buf.extend_from_slice(&body_commitment_annulet(&BlockBody::default()));
    buf.extend_from_slice(&(notes.len() as u32).to_le_bytes());
    for n in notes {
        assert_eq!(n.payload.len(), qlab_note::l2note::L2_PAYLOAD_LEN, "genesis note payload width");
        buf.extend_from_slice(&n.cm);
        buf.extend_from_slice(&n.payload);
    }
    keccak256(&buf)
}

/// **The Annulet discovery rule** for one transaction (lab #714): the L1's
/// §4 rules at the L2 payload width — the committed region decodes exactly at
/// 128-B payloads, re-encodes to itself, and describes exactly the declared
/// commitments — plus **rule (ii)**: every payload is an encrypted entry, so
/// a zero AEAD tag (a `GenesisPlaintext`, valid only at height 0) is refused
/// by name.
pub fn check_tx_discovery_annulet(index: usize, tx: &TxEntry) -> Result<(), BodyError> {
    use qlab_note::compact::{decode_committed_discovery_with_width, encode_committed_discovery_with_width};
    let width = crate::forms::GenesisForm::Annulet.discovery_payload_len();
    let (recipients, payloads) = decode_committed_discovery_with_width(&tx.discovery, width)
        .map_err(|err| BodyError::DiscoveryMalformed { index, err })?;
    if encode_committed_discovery_with_width(&recipients, &payloads, width) != tx.discovery {
        return Err(BodyError::DiscoveryNotCanonical { index });
    }
    crate::body::check_discovery_binds(index, &recipients, tx)?;
    if let Some(entry) = payloads.iter().position(|p| qlab_note::compact::payload_tag_is_zero(p)) {
        return Err(BodyError::GenesisPlaintextInBody { index, entry });
    }
    Ok(())
}

/// A **fixture** discovery group for an Annulet transaction (tests and
/// benches only; a real transaction encrypts its outputs): one recipient with
/// a zero ciphertext, one entry per commitment, and 128-B payloads whose tag
/// is nonzero — so it passes [`check_tx_discovery_annulet`] structurally.
pub fn placeholder_discovery_annulet(commitments: &[Hash32]) -> Vec<u8> {
    use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};
    let width = crate::forms::GenesisForm::Annulet.discovery_payload_len();
    let entries = commitments.iter().map(|cm| CompactEntry { cm: *cm, tag: [0u8; 8], clue: ClueSlot::Empty }).collect();
    qlab_note::compact::encode_committed_discovery_with_width(
        &[RecipientBundle { ct: [0u8; qlab_note::kem::CT_LEN], entries }],
        &vec![vec![0xA5u8; width]; commitments.len()],
        width,
    )
}

/// **The Annulet body rule** (lab #706). Cheap checks first:
///
/// 1. no coinbase payee (no block reward);
/// 2. the header binds [`body_commitment_annulet`];
/// 3. per transaction: anchor final; name rider absent (no name service);
///    L2 surface present and canonical; bucket 2×2 with exactly 2 nullifiers
///    and 2 commitments; `fee == posted_fee_l2(shape)`; no nullifier repeated
///    in the block; the discovery group is canonical at the 128-B payload
///    width, binds the declared commitments, and carries no genesis plaintext
///    ([`check_tx_discovery_annulet`], lab #714); the surface's
///    `registry_root` is the header's — which
///    B2's header rule has proved equal to the **parent's** (lab #712, the
///    §5 ruling); the proof verifies (B4's `L2Verifier` in the node).
///
/// **Not here, by name:** the sequencer signature (B2) and the
/// outstanding-supply rule, which needs chain state (the node's, over
/// [`annulet_supply_delta`]).
pub fn validate_body_annulet<V, F>(
    header: &BlockHeader,
    body: &BlockBody,
    verifier: &V,
    is_anchor_final: F,
    fees: &L2FeeTable,
) -> Result<(), BodyError>
where
    V: TxVerifier,
    F: Fn(&Hash32) -> bool,
{
    if !body.coinbase_payees.is_empty() {
        return Err(BodyError::CoinbaseOnAnnulet { got: body.coinbase_payees.len() });
    }
    let got = body_commitment_annulet(body);
    if header.tx_body_commitment != got {
        return Err(BodyError::CommitmentMismatch { expected: header.tx_body_commitment, got });
    }
    let header_root = match header.ext {
        HeaderExt::Annulet(ext) => Some(ext.registry_root),
        _ => None,
    };
    // Lab #728: the header's root is the registry AFTER this block. Every
    // surface binds the root BEFORE it — the parent's — which is the header
    // root when the block writes nothing, and the (one) write's old root when
    // it does. The node ties that pre-block root to its own tree on apply.
    let pre_root = match annulet_registry_write(body)? {
        None => header_root,
        Some((i, old_root, w)) => {
            if Some(w.new_root) != header_root {
                return Err(BodyError::L2RegistryWriteRootMismatch { index: i });
            }
            Some(old_root)
        }
    };
    let mut seen_nf = std::collections::HashSet::new();
    for (i, tx) in body.txs.iter().enumerate() {
        if !is_anchor_final(&tx.public.anchor) {
            return Err(BodyError::AnchorNotFinal { index: i });
        }
        if tx.rider != crate::names::RIDER_ABSENT {
            return Err(BodyError::RiderBeforeBoundary { index: i });
        }
        let surface = L2Surface::decode(&tx.l2)
            .map_err(|err| BodyError::L2SurfaceMalformed { index: i, err })?
            .ok_or(BodyError::L2SurfaceMissing { index: i })?;
        check_l2_arity(&tx.public, surface.shape, i)?;
        if Some(surface.registry_root) != pre_root {
            return Err(BodyError::L2RegistryRootStale { index: i });
        }
        let expected = fees.posted_fee_l2(surface.shape);
        if tx.public.fee != expected {
            return Err(BodyError::WrongFee { index: i, expected, got: tx.public.fee });
        }
        for nf in &tx.public.nullifiers {
            if !seen_nf.insert(*nf) {
                return Err(BodyError::DoubleSpendInBlock { index: i });
            }
        }
        check_tx_discovery_annulet(i, tx)?;
        if !verifier.verify_tx(tx) {
            return Err(BodyError::ProofInvalid { index: i });
        }
    }
    Ok(())
}

/// **The per-block supply delta** (lab #712, Q2): the net public issuance of
/// a body, per asset — `+amount` for a mint term, `−amount` for a redeem
/// term, summed over every surface's `vPublic` (shape P; shape S has none).
/// A pure function of committed data (the body commitment binds every
/// surface), so it is derived, never stored twice. Zero nets are dropped.
/// Undecodable surfaces contribute nothing — a validated body has none.
pub fn annulet_supply_delta(body: &BlockBody) -> std::collections::BTreeMap<u16, i128> {
    let mut delta = std::collections::BTreeMap::new();
    for tx in &body.txs {
        let Ok(Some(surface)) = L2Surface::decode(&tx.l2) else { continue };
        for term in surface.vpublic.iter().flatten() {
            if term.amount == 0 {
                continue;
            }
            let signed = if term.redeem { -(term.amount as i128) } else { term.amount as i128 };
            *delta.entry(term.asset).or_insert(0i128) += signed;
        }
    }
    delta.retain(|_, v| *v != 0);
    delta
}

/// Lab #728 Q2: every Annulet surface declares the 2×2 bucket (the L1
/// type's only L2 value — the Annulet prices by shape); the SHAPE gates the
/// counts: S/P spend two and make two, R spends one and makes one. The one
/// rule the body check and the mempool both apply (`index` names the tx).
pub fn check_l2_arity(public: &crate::body::TxPublic, shape: L2ShapeTag, index: usize) -> Result<(), BodyError> {
    if public.bucket != ArityBucket::TwoByTwo {
        return Err(BodyError::L2NotTwoByTwo { index });
    }
    let (want_nf, want_cm) = match shape {
        L2ShapeTag::S | L2ShapeTag::P => (2, 2),
        L2ShapeTag::R => (1, 1),
    };
    if public.nullifiers.len() != want_nf || public.commitments.len() != want_cm {
        return Err(match shape {
            L2ShapeTag::S | L2ShapeTag::P => BodyError::L2NotTwoByTwo { index },
            L2ShapeTag::R => BodyError::L2RegistryWriteArity { index },
        });
    }
    Ok(())
}

/// A body's registry write (lab #728): `(tx index, the root it was proven
/// against, the write)` for its one shape-R transaction, `None` when it has
/// none, and a second R refused by index. The one scan both
/// [`validate_body_annulet`] and the node's apply read, so the two cannot
/// disagree about which transaction writes.
pub fn annulet_registry_write(body: &BlockBody) -> Result<Option<(usize, Hash32, RegistryWriteSurface)>, BodyError> {
    let mut found = None;
    for (i, tx) in body.txs.iter().enumerate() {
        let Ok(Some(surface)) = L2Surface::decode(&tx.l2) else { continue };
        let Some(write) = surface.write else { continue };
        if found.is_some() {
            return Err(BodyError::L2SecondRegistryWrite { index: i });
        }
        found = Some((i, surface.registry_root, write));
    }
    Ok(found)
}

/// Convenience for fixtures and B2's producer: an L2 transaction entry with
/// its surface encoded.
pub fn with_surface(mut tx: TxEntry, surface: &L2Surface) -> TxEntry {
    tx.l2 = surface.encode();
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::TxPublic;

    struct OkProof;
    impl TxVerifier for OkProof {
        fn verify_tx(&self, e: &TxEntry) -> bool {
            e.proof == b"ok"
        }
    }

    const FINAL: Hash32 = [0x0F; 32];
    const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2, tier_r: 4 };

    fn s_surface() -> L2Surface {
        L2Surface { shape: L2ShapeTag::S, registry_root: [0x44; 32], vpublic: None, write: None }
    }

    fn p_surface() -> L2Surface {
        L2Surface {
            shape: L2ShapeTag::P,
            registry_root: [0x44; 32],
            vpublic: Some([VPublicTerm::NONE, VPublicTerm { redeem: false, amount: 100, asset: 7 }]),
            write: None,
        }
    }

    fn l2_tx(nf: u8, surface: &L2Surface) -> TxEntry {
        let public = TxPublic {
            anchor: FINAL,
            nullifiers: vec![[nf; 32], [nf.wrapping_add(1); 32]],
            commitments: vec![[nf.wrapping_add(2); 32], [nf.wrapping_add(3); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: FEES.posted_fee_l2(surface.shape),
        };
        let discovery = placeholder_discovery_annulet(&public.commitments);
        TxEntry {
            proof: b"ok".to_vec(),
            public,
            discovery,
            rider: crate::names::RIDER_ABSENT.to_vec(),
            l2: surface.encode(),
        }
    }

    fn header_for(body: &BlockBody) -> BlockHeader {
        BlockHeader::genesis_annulet(
            AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [0x44; 32] },
            body_commitment_annulet(body),
            0,
        )
    }

    fn check(body: &BlockBody) -> Result<(), BodyError> {
        validate_body_annulet(&header_for(body), body, &OkProof, |r| *r == FINAL, &FEES)
    }

    /// Lab #712 (the §5 ruling): a surface whose registry root is not the
    /// header's (= the parent's, by B2's header rule) is refused by name.
    #[test]
    fn a_surface_naming_another_registry_root_is_refused() {
        let good = BlockBody::new(vec![l2_tx(1, &s_surface())], vec![]);
        assert_eq!(check(&good), Ok(()));
        let stale = L2Surface { registry_root: [0x45; 32], ..s_surface() };
        let body = BlockBody::new(vec![l2_tx(1, &s_surface()), l2_tx(9, &stale)], vec![]);
        assert_eq!(check(&body), Err(BodyError::L2RegistryRootStale { index: 1 }));
    }

    /// Lab #714: the Annulet discovery rule — 128-B payloads, canonical,
    /// binding, and no genesis plaintext past height 0 — each refused by name.
    #[test]
    fn the_annulet_discovery_rule_refuses_each_violation_by_name() {
        use qlab_note::compact::{encode_committed_discovery, PAYLOAD_LEN};
        use qlab_note::wire::{ClueSlot, CompactEntry, RecipientBundle};
        assert_eq!(check(&BlockBody::new(vec![l2_tx(1, &s_surface())], vec![])), Ok(()));
        let bundle = |cms: &[Hash32]| RecipientBundle {
            ct: [0u8; qlab_note::kem::CT_LEN],
            entries: cms.iter().map(|cm| CompactEntry { cm: *cm, tag: [0; 8], clue: ClueSlot::Empty }).collect(),
        };
        // The L1's 120-B payload width is not the Annulet's.
        let mut l1w = l2_tx(1, &s_surface());
        l1w.discovery = encode_committed_discovery(&[bundle(&l1w.public.commitments)], &vec![vec![0xA5; PAYLOAD_LEN]; 2]);
        assert!(matches!(
            check(&BlockBody::new(vec![l1w], vec![])),
            Err(BodyError::DiscoveryMalformed { index: 0, .. })
        ));
        // Rule (ii): a zero-tag (genesis plaintext) payload past height 0.
        let mut zt = l2_tx(1, &s_surface());
        let width = qlab_note::l2note::L2_PAYLOAD_LEN;
        let mut genesis_like = vec![0xA5u8; width];
        genesis_like[width - 16..].fill(0);
        zt.discovery = qlab_note::compact::encode_committed_discovery_with_width(
            &[bundle(&zt.public.commitments)],
            &[vec![0xA5; width], genesis_like],
            width,
        );
        assert_eq!(
            check(&BlockBody::new(vec![zt], vec![])),
            Err(BodyError::GenesisPlaintextInBody { index: 0, entry: 1 })
        );
        // A group that does not describe the declared commitments.
        let mut nb = l2_tx(1, &s_surface());
        nb.discovery = placeholder_discovery_annulet(&[[0x77; 32], [0x78; 32]]);
        assert!(matches!(
            check(&BlockBody::new(vec![nb], vec![])),
            Err(BodyError::DiscoveryDoesNotBind { index: 0, .. })
        ));
        // The mempool's dispatcher agrees with the block rule on each form.
        let good = l2_tx(1, &s_surface());
        assert_eq!(crate::body::check_tx_discovery_for(crate::forms::GenesisForm::Annulet, 0, &good), Ok(()));
        assert!(crate::body::check_tx_discovery_for(crate::forms::GenesisForm::V5, 0, &good).is_err());
    }

    /// Lab #712 Q2: the per-block supply delta is the signed sum of every
    /// surface's vPublic terms, per asset; zero nets are dropped.
    #[test]
    fn the_supply_delta_sums_vpublic_terms_per_asset() {
        let t = |redeem, amount, asset| VPublicTerm { redeem, amount, asset };
        let p = |a: VPublicTerm, b: VPublicTerm| L2Surface { vpublic: Some([a, b]), ..p_surface() };
        let body = BlockBody::new(
            vec![
                l2_tx(1, &p(t(false, 100, 7), t(false, 5, 9))),
                l2_tx(9, &p(t(true, 30, 7), VPublicTerm::NONE)),
                l2_tx(17, &p(t(true, 5, 9), VPublicTerm::NONE)),
                l2_tx(25, &s_surface()),
            ],
            vec![],
        );
        let d = annulet_supply_delta(&body);
        assert_eq!(d.get(&7), Some(&70));
        assert_eq!(d.get(&9), None, "a zero net is dropped");
        assert_eq!(d.len(), 1);
        let big = BlockBody::new(vec![l2_tx(1, &p(t(true, u64::MAX, 3), t(true, u64::MAX, 3)))], vec![]);
        assert_eq!(annulet_supply_delta(&big).get(&3), Some(&(-2 * u64::MAX as i128)), "no overflow");
    }

    #[test]
    fn surfaces_round_trip_at_their_lengths() {
        for (s, len) in [(s_surface(), 33usize), (p_surface(), 55)] {
            let b = s.encode();
            assert_eq!(b.len(), len);
            assert_eq!(L2Surface::decode(&b), Ok(Some(s)));
        }
        assert_eq!((L2_SURFACE_LEN_S, L2_SURFACE_LEN_P), (33, 55));
        assert_eq!(L2Surface::decode(L2_SURFACE_ABSENT), Ok(None));
        assert_eq!((L2ShapeTag::S.byte(), L2ShapeTag::P.byte()), (0x01, 0x02));
    }

    #[test]
    fn non_canonical_surfaces_are_refused_by_name() {
        assert_eq!(L2Surface::decode(&[]), Err(L2SurfaceError::Empty));
        assert_eq!(L2Surface::decode(&[0x04; 33]), Err(L2SurfaceError::UnknownShape { got: 0x04 }));
        let mut s = s_surface().encode();
        s.push(0);
        assert_eq!(L2Surface::decode(&s), Err(L2SurfaceError::WrongLength { got: 34, want: 33 }));
        let mut p = p_surface().encode();
        p[33] = 2; // row 0 redeem byte
        assert_eq!(L2Surface::decode(&p), Err(L2SurfaceError::BadRedeemByte { got: 2 }));
        let mut z = p_surface().encode();
        z[33] = 1; // row 0: amount 0 with the redeem sign set
        assert_eq!(L2Surface::decode(&z), Err(L2SurfaceError::NonCanonicalZeroTerm { row: 0 }));
        let mut z = p_surface().encode();
        z[33 + 9] = 7; // row 0: amount 0 naming an asset
        assert_eq!(L2Surface::decode(&z), Err(L2SurfaceError::NonCanonicalZeroTerm { row: 0 }));
    }

    /// A registry write (lab #728): old root `[0x44;32]` (the fixture
    /// header's), new root `new_root`, asset-9 leaf lanes.
    fn r_surface(new_root: Hash32) -> L2Surface {
        let mut leaf_lanes = [0u64; 15];
        leaf_lanes[0] = 9;
        leaf_lanes[1] = 0x1111;
        leaf_lanes[5] = 1;
        L2Surface {
            shape: L2ShapeTag::R,
            registry_root: [0x44; 32],
            vpublic: None,
            write: Some(RegistryWriteSurface { new_root, leaf_lanes }),
        }
    }

    /// An R transaction: one nullifier, one commitment, at tier R.
    fn r_tx(nf: u8, surface: &L2Surface) -> TxEntry {
        let mut t = l2_tx(nf, surface);
        t.public.nullifiers.truncate(1);
        t.public.commitments.truncate(1);
        t.discovery = placeholder_discovery_annulet(&t.public.commitments);
        t
    }

    /// A header whose post-block registry root is `root`.
    fn check_at(body: &BlockBody, root: Hash32) -> Result<(), BodyError> {
        let h = BlockHeader::genesis_annulet(
            AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: root },
            body_commitment_annulet(body),
            0,
        );
        validate_body_annulet(&h, body, &OkProof, |r| *r == FINAL, &FEES)
    }

    /// Lab #728 Q1: the R surface round-trips at 185 B, and S and P are
    /// **byte-identical** to their pre-R encodings (hard-coded here).
    #[test]
    fn the_r_surface_round_trips_and_s_and_p_bytes_do_not_move() {
        let r = r_surface([0x55; 32]);
        let b = r.encode();
        assert_eq!(b.len(), L2_SURFACE_LEN_R);
        assert_eq!(b[0], 0x03);
        assert_eq!(&b[1..33], &[0x44; 32]);
        assert_eq!(&b[33..65], &[0x55; 32]);
        assert_eq!(&b[65..73], &9u64.to_le_bytes(), "lane 0 = the written slot");
        assert_eq!(L2Surface::decode(&b), Ok(Some(r)));
        assert_eq!(r.write.unwrap().asset(), 9);
        let mut s = vec![0x01u8];
        s.extend_from_slice(&[0x44; 32]);
        assert_eq!(s_surface().encode(), s, "S bytes unchanged");
        let mut p = vec![0x02u8];
        p.extend_from_slice(&[0x44; 32]);
        p.extend_from_slice(&[0u8; 11]);
        p.push(0);
        p.extend_from_slice(&100u64.to_le_bytes());
        p.extend_from_slice(&7u16.to_le_bytes());
        assert_eq!(p_surface().encode(), p, "P bytes unchanged");
        let mut short = b.clone();
        short.pop();
        assert_eq!(L2Surface::decode(&short), Err(L2SurfaceError::WrongLength { got: 184, want: 185 }));
    }

    /// Lab #728 Q3/Q4: a block carrying one registry write — the write binds
    /// the pre-block root, the header carries the post-block root, and the S
    /// transaction beside it binds the pre-block root too.
    #[test]
    fn a_block_with_one_registry_write_passes_and_each_misuse_is_refused_by_name() {
        let new = [0x55; 32];
        let one = BlockBody::new(vec![r_tx(1, &r_surface(new)), l2_tx(9, &s_surface())], vec![]);
        assert_eq!(check_at(&one, new), Ok(()));
        // The header must carry the write's new root.
        assert_eq!(check_at(&one, [0x44; 32]), Err(BodyError::L2RegistryWriteRootMismatch { index: 0 }));
        // A second write in the block.
        let two = BlockBody::new(vec![r_tx(1, &r_surface(new)), r_tx(9, &r_surface(new))], vec![]);
        assert_eq!(check_at(&two, new), Err(BodyError::L2SecondRegistryWrite { index: 1 }));
        // An S transaction binding the post-block root is stale.
        let stale_s = L2Surface { registry_root: new, ..s_surface() };
        let bad = BlockBody::new(vec![r_tx(1, &r_surface(new)), l2_tx(9, &stale_s)], vec![]);
        assert_eq!(check_at(&bad, new), Err(BodyError::L2RegistryRootStale { index: 1 }));
        // A write that spends two notes.
        let wide = BlockBody::new(vec![l2_tx(1, &r_surface(new))], vec![]);
        assert_eq!(check_at(&wide, new), Err(BodyError::L2RegistryWriteArity { index: 0 }));
        // An S transaction with R's arity is still an S arity error.
        let narrow_s = BlockBody::new(vec![r_tx(1, &s_surface())], vec![]);
        assert_eq!(check_at(&narrow_s, [0x44; 32]), Err(BodyError::L2NotTwoByTwo { index: 0 }));
        // R pays tier R.
        let mut cheap = r_tx(1, &r_surface(new));
        cheap.public.fee = FEES.tier_s;
        let body = BlockBody::new(vec![cheap], vec![]);
        assert_eq!(check_at(&body, new), Err(BodyError::WrongFee { index: 0, expected: FEES.tier_r, got: FEES.tier_s }));
    }

    #[test]
    fn a_valid_annulet_body_passes() {
        let body = BlockBody::new(vec![l2_tx(1, &s_surface()), l2_tx(9, &p_surface())], vec![]);
        assert_eq!(check(&body), Ok(()));
        assert_eq!(check(&BlockBody::default()), Ok(()), "an empty body is a valid Annulet body");
    }

    #[test]
    fn the_annulet_body_rule_refuses_each_violation_by_name() {
        let body = |txs: Vec<TxEntry>| BlockBody::new(txs, vec![]);
        let mut no_surface = l2_tx(1, &s_surface());
        no_surface.l2 = L2_SURFACE_ABSENT.to_vec();
        assert_eq!(check(&body(vec![no_surface])), Err(BodyError::L2SurfaceMissing { index: 0 }));
        let mut bad_surface = l2_tx(1, &s_surface());
        bad_surface.l2.push(0);
        assert!(matches!(check(&body(vec![bad_surface])), Err(BodyError::L2SurfaceMalformed { index: 0, .. })));
        let mut rider = l2_tx(1, &s_surface());
        rider.rider = vec![0x01, 0x02];
        assert_eq!(check(&body(vec![rider])), Err(BodyError::RiderBeforeBoundary { index: 0 }));
        let mut fee = l2_tx(1, &p_surface());
        fee.public.fee = 1; // the S tier on a P transaction
        assert_eq!(check(&body(vec![fee])), Err(BodyError::WrongFee { index: 0, expected: 2, got: 1 }));
        let mut one_in = l2_tx(1, &s_surface());
        one_in.public.nullifiers.pop();
        assert_eq!(check(&body(vec![one_in])), Err(BodyError::L2NotTwoByTwo { index: 0 }));
        assert_eq!(
            check(&body(vec![l2_tx(1, &s_surface()), l2_tx(2, &s_surface())])),
            Err(BodyError::DoubleSpendInBlock { index: 1 }),
            "tx 1's first nullifier is tx 0's second"
        );
        let mut bad_proof = l2_tx(1, &s_surface());
        bad_proof.proof = b"no".to_vec();
        assert_eq!(check(&body(vec![bad_proof])), Err(BodyError::ProofInvalid { index: 0 }));
        let mut stale = l2_tx(1, &s_surface());
        stale.public.anchor = [0xEE; 32];
        assert_eq!(check(&body(vec![stale])), Err(BodyError::AnchorNotFinal { index: 0 }));
        let paid = BlockBody::new(vec![], vec![crate::body::CoinbasePayee { rkm: [1; 4], amount: 5 }]);
        assert_eq!(check(&paid), Err(BodyError::CoinbaseOnAnnulet { got: 1 }));
        // The binding: a header over a different body.
        let good = body(vec![l2_tx(1, &s_surface())]);
        let other = body(vec![l2_tx(5, &s_surface())]);
        assert!(matches!(
            validate_body_annulet(&header_for(&other), &good, &OkProof, |r| *r == FINAL, &FEES),
            Err(BodyError::CommitmentMismatch { .. })
        ));
    }

    /// The surface, proof and discovery are all inside the commitment, and
    /// the Annulet commitment is not an L1 commitment of the same body.
    #[test]
    fn the_annulet_commitment_binds_the_surface_and_differs_from_l1() {
        let a = BlockBody::new(vec![l2_tx(1, &s_surface())], vec![]);
        let mut changed = l2_tx(1, &s_surface());
        changed.l2 = L2Surface { registry_root: [0x45; 32], ..s_surface() }.encode();
        let b = BlockBody::new(vec![changed], vec![]);
        assert_ne!(body_commitment_annulet(&a), body_commitment_annulet(&b));
        let empty = BlockBody::default();
        assert_ne!(body_commitment_annulet(&empty), empty.commitment_v5());
        assert_ne!(body_commitment_annulet(&empty), empty.commitment());
    }

    #[test]
    fn the_genesis_commitment_binds_every_note() {
        let note = |b: u8| GenesisNote { cm: [b; 32], payload: vec![b; qlab_note::l2note::L2_PAYLOAD_LEN] };
        let none = genesis_body_commitment_annulet(&[]);
        let one = genesis_body_commitment_annulet(&[note(1)]);
        let two = genesis_body_commitment_annulet(&[note(1), note(2)]);
        let swapped = genesis_body_commitment_annulet(&[note(2), note(1)]);
        assert!(none != one && one != two && two != swapped);
        assert_ne!(none, body_commitment_annulet(&BlockBody::default()), "the genesis domain is its own");
    }

    /// The empty-body commitments, hard-coded: the named `annulet_goldens`
    /// run and an independent Python Keccak-256 agreed before pinning.
    #[test]
    fn annulet_empty_body_goldens() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&body_commitment_annulet(&BlockBody::default())), GOLDEN_ANNULET_EMPTY_BODY);
        assert_eq!(hex(&genesis_body_commitment_annulet(&[])), GOLDEN_ANNULET_EMPTY_GENESIS);
    }

    const GOLDEN_ANNULET_EMPTY_BODY: &str = "75dc7b561922b13da146bddeac8bc8e5d845cfff605cdcf94ade8993eaae52be";
    const GOLDEN_ANNULET_EMPTY_GENESIS: &str = "3ad958aa3bdcb443ab80a6ca45de2900fe60ecb208d90b7ef3eb42002be1d253";

    // ── the seal and the header rule (lab #708) ──────────────────────────────

    use crate::chain::ChainState;
    use crate::validation::{validate_sealed_header_annulet, ValidationError};

    const SEQ_SEED: [u8; 32] = [0x5E; 32];

    fn ext(anchor: u64) -> AnnuletHeaderFields {
        AnnuletHeaderFields { l1_anchor_height: anchor, l1_anchor_root: [0; 32], registry_root: [0x44; 32] }
    }

    fn genesis_chain() -> (ChainState, BlockHeader) {
        let g = BlockHeader::genesis_annulet(ext(0), [0x22; 32], 0);
        (ChainState::new_for(crate::forms::GenesisForm::Annulet, g), g)
    }

    #[test]
    fn a_seal_round_trips_on_the_wire_and_verifies() {
        let key = SequencerKey::from_seed(SEQ_SEED);
        let (_, g) = genesis_chain();
        let sealed = key.seal(BlockHeader::child_of_annulet(&g, 10, ext(0), [0x66; 32]));
        let bytes = sealed.encode();
        assert_eq!(bytes.len(), SEALED_HEADER_LEN_ANNULET);
        assert_eq!(SEALED_HEADER_LEN_ANNULET, 3462);
        assert_eq!(SealedHeader::decode(&bytes), Ok(sealed.clone()));
        assert!(sealed.verifies_under(&key.verifying_key()));
        assert_eq!(sealed.id(), sealed.header.header_hash_for(crate::forms::GenesisForm::Annulet), "the id ignores the seal");
        assert_eq!(key.seal(sealed.header), sealed, "deterministic signer (crate default)");
        assert_eq!(SealedHeader::decode(&bytes[..153]), Err(SealedHeaderError::WrongLength { got: 153 }), "a bare preimage is not a sealed header");
    }

    #[test]
    fn a_seal_does_not_verify_under_another_key_or_over_another_header() {
        let key = SequencerKey::from_seed(SEQ_SEED);
        let other = SequencerKey::from_seed([0x5F; 32]);
        let (_, g) = genesis_chain();
        let h1 = BlockHeader::child_of_annulet(&g, 10, ext(0), [0x66; 32]);
        let sealed = key.seal(h1);
        assert!(!sealed.verifies_under(&other.verifying_key()), "wrong key");
        // Replayed at another height: same seal, header moved one height up.
        let mut replay = sealed.clone();
        replay.header.height += 1;
        assert!(!replay.verifies_under(&key.verifying_key()), "a seal replayed at another height");
        // Over another registry root.
        let mut rr = sealed.clone();
        rr.header.ext = HeaderExt::Annulet(AnnuletHeaderFields { registry_root: [0x45; 32], ..ext(0) });
        assert!(!rr.verifies_under(&key.verifying_key()), "a seal over a different registry root");
        let mut junk = sealed;
        junk.sig[100] ^= 1;
        assert!(!junk.verifies_under(&key.verifying_key()), "a corrupted seal");
    }

    #[test]
    fn the_sealed_header_rule_accepts_a_good_child_and_refuses_each_violation() {
        let key = SequencerKey::from_seed(SEQ_SEED);
        let vk = key.verifying_key();
        let (chain, g) = genesis_chain();
        let good = BlockHeader::child_of_annulet(&g, 10, ext(3), [0x66; 32]);
        assert_eq!(validate_sealed_header_annulet(&chain, &key.seal(good), &vk), Ok(()));
        let check = |h: BlockHeader| validate_sealed_header_annulet(&chain, &key.seal(h), &vk);
        let mut t = good;
        t.timestamp = 0;
        assert_eq!(check(t), Ok(()), "equal timestamps are allowed");
        let g2 = BlockHeader { timestamp: 20, ..g };
        let (chain2, _) = (ChainState::new_for(crate::forms::GenesisForm::Annulet, g2), ());
        let c2 = BlockHeader::child_of_annulet(&g2, 19, ext(0), [0x66; 32]);
        assert_eq!(validate_sealed_header_annulet(&chain2, &key.seal(c2), &vk), Err(ValidationError::NonMonotonicTimestamp));
        let mut h = good;
        h.height = 2;
        assert_eq!(check(h), Err(ValidationError::BadHeight));
        let mut p = good;
        p.prev = [9; 32];
        assert_eq!(check(p), Err(ValidationError::UnknownParent));
        let rr = BlockHeader { ext: HeaderExt::Annulet(AnnuletHeaderFields { registry_root: [0x45; 32], ..ext(3) }), ..good };
        assert_eq!(check(rr), Err(ValidationError::RegistryRootChanged));
        // Anchor regression needs a parent with a non-zero anchor.
        let mut chain3 = chain.clone();
        let parent = key.seal(good);
        chain3.insert_header(parent.header).unwrap();
        let back = BlockHeader::child_of_annulet(&parent.header, 11, ext(2), [0x67; 32]);
        assert_eq!(
            validate_sealed_header_annulet(&chain3, &key.seal(back), &vk),
            Err(ValidationError::AnchorRegressed { parent: 3, got: 2 })
        );
        // The seal itself: a header sealed by another key.
        let other = SequencerKey::from_seed([0x5F; 32]);
        assert_eq!(validate_sealed_header_annulet(&chain, &other.seal(good), &vk), Err(ValidationError::BadSeal));
    }

    /// The header-only rule refuses an Annulet header by name: it cannot be
    /// judged without its seal.
    #[test]
    fn the_header_only_rule_requires_the_seal_on_an_annulet_net() {
        use crate::forms::{ChainRules, GenesisForm};
        use crate::halt::RuleSchedule;
        let (chain, g) = genesis_chain();
        let child = BlockHeader::child_of_annulet(&g, 10, ext(0), [0x66; 32]);
        let rules = ChainRules { form: GenesisForm::Annulet, halt: RuleSchedule::V1_0 };
        assert_eq!(
            crate::validation::validate_header_under(
                &chain,
                &crate::pow::KeccakPow,
                &child,
                75,
                qlab_pow::keyblock::KeyBlockSchedule::default(),
                &rules,
            ),
            Err(ValidationError::SealRequired)
        );
    }

    /// Q3: each Annulet block weighs 1, so the tip advances with height —
    /// under the L1 weight (difficulty 0) it would never leave genesis.
    #[test]
    fn the_annulet_tip_advances_one_block_at_a_time() {
        let key = SequencerKey::from_seed(SEQ_SEED);
        let (mut chain, g) = genesis_chain();
        let mut parent = g;
        for h in 1..=5u64 {
            let child = key.seal(BlockHeader::child_of_annulet(&parent, 10 * h, ext(0), [h as u8; 32])).header;
            let id = chain.insert_header(child).unwrap();
            assert_eq!(chain.tip_hash(), id, "height {h}: the tip moves");
            assert_eq!(chain.tip_height(), h);
            parent = child;
        }
        assert_eq!(chain.tip_work(), 5, "cumulative weight = height");
    }

    /// The seal goldens (lab #708), from the named `annulet_seal_goldens`
    /// run; the digests were re-hashed independently in Python from the wire
    /// hex, which also re-built the 153-B preimage field by field.
    ///
    /// - **Load-bearing:** the fixture key's seal over the B1 fixture header
    ///   verifies, the wire is 3,462 B, round-trips, and its id is B1's id.
    /// - **Valid only while the crate's default signer stays deterministic**
    ///   (ml-dsa 0.1.1's `Signer`): the signature and wire digests. A move to
    ///   hedged signing changes them without changing the rule — re-pin then;
    ///   the verification golden must not move.
    #[test]
    fn the_seal_goldens() {
        use crate::header::{AggregateProofSlot, EpochSupplyAttestation};
        let h = BlockHeader {
            prev: [0x11; 32],
            height: 0x0000_6655_4433_2211,
            timestamp: 0x8877_6655_4433_2211,
            difficulty: 0,
            nonce: 0,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
            ext: HeaderExt::Annulet(AnnuletHeaderFields {
                l1_anchor_height: 0x0102_0304_0506_0708,
                l1_anchor_root: [0x33; 32],
                registry_root: [0x44; 32],
            }),
        };
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let key = SequencerKey::from_seed([0x5E; 32]);
        let sealed = key.seal(h);
        let wire = sealed.encode();
        // Load-bearing.
        assert!(sealed.verifies_under(&key.verifying_key()));
        assert_eq!(wire.len(), SEALED_HEADER_LEN_ANNULET);
        assert_eq!(wire.len(), 3462);
        assert_eq!(SealedHeader::decode(&wire).unwrap(), sealed);
        assert_eq!(hex(&sealed.id()), "1bc6fce1c82cfb364d7649cc610c2c8835e8b5c43f4af9f27d3da4c6c4d88b97");
        assert_eq!(
            hex(&keccak256(key.verifying_key().encode().as_slice())),
            "263cee4046d7f19124c65e62a17fe6893300508a4119c26d17e39fbd711381df",
            "the fixture sequencer key"
        );
        // Deterministic-signer goldens.
        assert_eq!(hex(&keccak256(&sealed.sig[..])), "e02a1bd09b1fc70240e41a73bffeef01d8a25d0c2e9b5db16eb0e1d6d739fc43");
        assert_eq!(hex(&keccak256(&wire)), "9ed2e2dcd6b8127376bb287b6db1ebff65860d8321ca5d200a2f3a05b9238ee4");
        // Framing refusals.
        assert_eq!(SealedHeader::decode(&wire[..3461]), Err(SealedHeaderError::WrongLength { got: 3461 }));
        let mut bad = wire.clone();
        bad[32] = 0x05;
        assert!(matches!(SealedHeader::decode(&bad), Err(SealedHeaderError::Preimage(_))));
    }

    #[test]
    #[should_panic(expected = "genesis note payload width")]
    fn a_genesis_note_payload_must_be_128_bytes() {
        let _ = genesis_body_commitment_annulet(&[GenesisNote { cm: [1; 32], payload: vec![0; 120] }]);
    }
}

// ---------------------------------------------------------------------------
// The seal (lab #708 Q2): the sequencer's signature, beside the header
// ---------------------------------------------------------------------------

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey, B32};

/// ML-DSA-65 signature length (FIPS 204), the seal's width.
pub const ANNULET_SIG_LEN: usize = 3309;

/// An Annulet `Header` message / `Headers` stride: the 153-B preimage ‖ the
/// 3,309-B seal.
pub const SEALED_HEADER_LEN_ANNULET: usize = crate::header::HEADER_PREIMAGE_LEN_ANNULET + ANNULET_SIG_LEN;

/// The sequencer's signing key. Derived from a 32-byte seed exactly as a
/// committee [`crate::committee::Validator`] is (`SigningKey::from_seed`), so
/// the genesis `sequencer_key` (B1) and this key agree.
pub struct SequencerKey {
    signing_key: SigningKey<MlDsa65>,
}

impl SequencerKey {
    /// Derive from a seed (a key file in the datadir, the committee-key
    /// convention — never config/env inline, lab #708 Q6).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed: B32 = seed.into();
        Self { signing_key: SigningKey::<MlDsa65>::from_seed(&seed) }
    }

    /// The verifying key a genesis pins.
    pub fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        self.signing_key.verifying_key()
    }

    /// Seal `header`: sign [`BlockHeader::annulet_signing_message`]. ml-dsa
    /// 0.1.1's `Signer` is the **deterministic** variant, so a seal is
    /// reproducible — a property of the crate's default, not of the rule (a
    /// hedged signer's seals verify just the same).
    pub fn seal(&self, header: BlockHeader) -> SealedHeader {
        let sig: Signature<MlDsa65> = self.signing_key.sign(&header.annulet_signing_message());
        let enc = sig.encode();
        let mut bytes = [0u8; ANNULET_SIG_LEN];
        bytes.copy_from_slice(enc.as_slice());
        SealedHeader { header, sig: Box::new(bytes) }
    }
}

/// Decode a genesis-pinned sequencer verifying key.
pub fn decode_sequencer_key(bytes: &[u8]) -> Option<VerifyingKey<MlDsa65>> {
    let e = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
    Some(VerifyingKey::<MlDsa65>::decode(&e))
}

/// An Annulet header with its seal. `BlockHeader` stays `Copy` and its
/// size unchanged; the seal travels beside it (lab #708 Q2) and is **not**
/// part of the block id (`keccak(preimage)`, B1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedHeader {
    pub header: BlockHeader,
    pub sig: Box<[u8; ANNULET_SIG_LEN]>,
}

/// Why a sealed-header wire unit did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealedHeaderError {
    WrongLength { got: usize },
    Preimage(crate::header::AnnuletPreimageError),
}

impl SealedHeader {
    /// Wire bytes: `preimage (153) ‖ sig (3,309)` = 3,462 B.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.header.preimage_for(crate::forms::GenesisForm::Annulet);
        out.extend_from_slice(&self.sig[..]);
        out
    }

    /// Parse the wire unit (length, then the preimage). The signature bytes
    /// are carried as-is; whether they verify is [`Self::verifies_under`]'s
    /// question, asked by validation.
    pub fn decode(bytes: &[u8]) -> Result<SealedHeader, SealedHeaderError> {
        if bytes.len() != SEALED_HEADER_LEN_ANNULET {
            return Err(SealedHeaderError::WrongLength { got: bytes.len() });
        }
        let (pre, sig) = bytes.split_at(crate::header::HEADER_PREIMAGE_LEN_ANNULET);
        let header = BlockHeader::from_annulet_preimage(pre).map_err(SealedHeaderError::Preimage)?;
        Ok(SealedHeader { header, sig: Box::new(sig.try_into().expect("length checked")) })
    }

    /// The block id (the unsigned preimage's hash).
    pub fn id(&self) -> Hash32 {
        self.header.header_hash_for(crate::forms::GenesisForm::Annulet)
    }

    /// `true` iff the seal is a valid ML-DSA-65 signature by `key` over this
    /// header's signing message.
    pub fn verifies_under(&self, key: &VerifyingKey<MlDsa65>) -> bool {
        let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(&self.sig[..]) else { return false };
        let Some(sig) = Signature::<MlDsa65>::decode(&enc) else { return false };
        key.verify(&self.header.annulet_signing_message(), &sig).is_ok()
    }
}
