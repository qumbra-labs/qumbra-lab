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
}

impl L2ShapeTag {
    /// The wire byte: `0x01` S, `0x02` P.
    pub const fn byte(self) -> u8 {
        match self {
            L2ShapeTag::S => 0x01,
            L2ShapeTag::P => 0x02,
        }
    }
    /// The inverse of [`Self::byte`]; any other byte is unknown.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(L2ShapeTag::S),
            0x02 => Some(L2ShapeTag::P),
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
/// this codec only carries the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2Surface {
    pub shape: L2ShapeTag,
    pub registry_root: Hash32,
    /// `Some` exactly for shape P (the two rows' terms), `None` for S.
    pub vpublic: Option<[VPublicTerm; 2]>,
}

/// Encoded surface lengths: S = tag ‖ root; P = S ‖ 2 × (redeem ‖ amount ‖ asset).
pub const L2_SURFACE_LEN_S: usize = 1 + 32;
/// See [`L2_SURFACE_LEN_S`].
pub const L2_SURFACE_LEN_P: usize = L2_SURFACE_LEN_S + 2 * (1 + 8 + 2);

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
        let mut out = Vec::with_capacity(L2_SURFACE_LEN_P);
        out.push(self.shape.byte());
        out.extend_from_slice(&self.registry_root);
        match (self.shape, &self.vpublic) {
            (L2ShapeTag::S, None) => {}
            (L2ShapeTag::P, Some(terms)) => {
                for t in terms {
                    out.push(t.redeem as u8);
                    out.extend_from_slice(&t.amount.to_le_bytes());
                    out.extend_from_slice(&t.asset.to_le_bytes());
                }
            }
            // A locally-built surface whose vPublic does not match its shape
            // is a program error (the decoder cannot produce one).
            (shape, v) => panic!("L2 surface shape {shape:?} with vpublic {v:?} (lab #706)"),
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
        };
        if bytes.len() != want {
            return Err(L2SurfaceError::WrongLength { got: bytes.len(), want });
        }
        let registry_root: Hash32 = rest[..32].try_into().expect("length checked");
        let vpublic = match shape {
            L2ShapeTag::S => None,
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
        Ok(Some(L2Surface { shape, registry_root, vpublic }))
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
}

impl L2FeeTable {
    /// The posted fee for a transaction of `shape` — exact, like the L1's.
    pub fn posted_fee_l2(&self, shape: L2ShapeTag) -> u64 {
        match shape {
            L2ShapeTag::S => self.tier_s,
            L2ShapeTag::P => self.tier_p,
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

/// Who validates the Annulet discovery group. Not B1: the L1 discovery
/// codec frames 120-B payloads, the L2's are 128-B, and the form-keyed framing
/// is B5's. Until then [`validate_body_annulet`] commits the bytes (above) but
/// does not judge them — named here so the gap cannot be forgotten.
pub const ANNULET_DISCOVERY_RULE_OWNER: &str = "B5";

/// **The Annulet body rule** (lab #706). Cheap checks first:
///
/// 1. no coinbase payee (no block reward);
/// 2. the header binds [`body_commitment_annulet`];
/// 3. per transaction: anchor final; name rider absent (no name service);
///    L2 surface present and canonical; bucket 2×2 with exactly 2 nullifiers
///    and 2 commitments; `fee == posted_fee_l2(shape)`; no nullifier repeated
///    in the block; the surface's `registry_root` is the header's — which
///    B2's header rule has proved equal to the **parent's** (lab #712, the
///    §5 ruling); the proof verifies (B4's `L2Verifier` in the node).
///
/// **Not here, by name:** the sequencer signature (B2), the discovery group
/// ([`ANNULET_DISCOVERY_RULE_OWNER`]), and the outstanding-supply rule, which
/// needs chain state (the node's, over [`annulet_supply_delta`]).
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
        if tx.public.bucket != ArityBucket::TwoByTwo
            || tx.public.nullifiers.len() != 2
            || tx.public.commitments.len() != 2
        {
            return Err(BodyError::L2NotTwoByTwo { index: i });
        }
        if Some(surface.registry_root) != header_root {
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
    const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2 };

    fn s_surface() -> L2Surface {
        L2Surface { shape: L2ShapeTag::S, registry_root: [0x44; 32], vpublic: None }
    }

    fn p_surface() -> L2Surface {
        L2Surface {
            shape: L2ShapeTag::P,
            registry_root: [0x44; 32],
            vpublic: Some([VPublicTerm::NONE, VPublicTerm { redeem: false, amount: 100, asset: 7 }]),
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
        TxEntry {
            proof: b"ok".to_vec(),
            public,
            discovery: vec![0x00],
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
        assert_eq!(L2Surface::decode(&[0x03; 33]), Err(L2SurfaceError::UnknownShape { got: 0x03 }));
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
