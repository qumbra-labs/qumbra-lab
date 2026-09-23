//! The block header — core type of the devnet chain.
//!
//! Fields (per the M6 mandate): parent hash, height, PoW fields (difficulty +
//! nonce), a tx-body commitment, and two **RESERVED** fields that activate with
//! rung-1 aggregation and are **not computed** at devnet:
//!   - [`AggregateProofSlot`] — the reserved block-level aggregate-proof slot
//!     (performance-budget §5: launch rung 0 with the slot reserved).
//!   - [`EpochSupplyAttestation`] — the reserved epoch supply-attestation field
//!     (performance-budget §9: activated with rung 1).
//!
//! Both reserved fields are zero-sized markers that still contribute a fixed
//! domain tag to the header preimage, so the header layout accounts for them now
//! and *activating* them later is a real, deliberate format change rather than a
//! silent addition.

use crate::annulet::{AnnuletHeaderFields, HeaderExt};
use crate::body::BlockBody;
use crate::forms::GenesisForm;
use crate::hash::keccak256;

/// A 256-bit hash (Keccak-256 digest), the header/block identity type.
pub type Hash32 = [u8; 32];

/// The all-zero hash — the parent of the genesis header.
pub const ZERO_HASH: Hash32 = [0u8; 32];

/// The v4 header preimage/wire length: 32 (prev) + 8×4 (height, timestamp,
/// difficulty, nonce) + 32 (body commitment) + 2 (reserved tags).
pub const HEADER_PREIMAGE_LEN_V4: usize = 98;

/// The v5 header preimage/wire length: 32 (prev) + 1 (header format version)
/// + 6 (u48 height) + 8 (nonce) + 8 (timestamp) + 8 (difficulty) + 32 (body
/// commitment) + 2 (reserved tags). One byte shorter than v4 — the length
/// difference is itself the structural discriminator between the two forms
/// (a header of the wrong form is refused by length, by name, never misparsed).
pub const HEADER_PREIMAGE_LEN_V5: usize = 97;

/// The header format version byte a v5 preimage carries at offset 32.
pub const HEADER_VERSION_BYTE_V5: u8 = 0x05;

/// The Annulet header preimage length (lab #706 Q3): 32 (prev) + 1 (version
/// `0x20`) + 6 (u48 height) + 8 (timestamp) + 8 (l1_anchor_height) + 32
/// (l1_anchor_root) + 32 (registry_root) + 32 (body commitment) + 2 (reserved
/// tag bytes). Distinct by length from v4's 98 and v5's 97, so a header of the
/// wrong form is refused by length, never misparsed.
pub const HEADER_PREIMAGE_LEN_ANNULET: usize = 153;

/// The header format version byte an Annulet preimage carries at offset 32 —
/// the Annulet genesis `format_version` (32), by symmetry with v5's `0x05`.
pub const HEADER_VERSION_BYTE_ANNULET: u8 = 0x20;

/// The two reserved tag bytes an Annulet preimage ends with (offsets 151–152):
/// fixed `0x00 0x00` (lab #706 ruling). The L1's rung-1 reservations
/// ([`AggregateProofSlot`], [`EpochSupplyAttestation`]) are L1 fields; an
/// Annulet header reserves its own two bytes and activating either is a
/// header-version change.
pub const ANNULET_RESERVED_TAGS: [u8; 2] = [0x00, 0x00];

/// Domain of the message the sequencer signs (lab #706 Q3):
/// `ANNULET_HEADER_SIGNING_DOMAIN ‖ preimage`. The block id hashes the
/// unsigned preimage only — ML-DSA signing is hedged, so an id over the
/// signature would let the signer mint a second id for the same block.
pub const ANNULET_HEADER_SIGNING_DOMAIN: &[u8] = b"qumbra:annulet:header:v1";

/// The largest height a v5 header can carry (u48). At 75 s blocks this is
/// ~669 million years of chain — the bound is generous, not a constraint.
pub const V5_MAX_HEIGHT: u64 = (1 << 48) - 1;

/// RESERVED aggregate-proof slot in the block header.
///
/// performance-budget §5: "launch at rung 0 with a reserved aggregate-proof slot
/// in the block header; rung 1 is the first post-launch milestone." **Not
/// computed at devnet** — this zero-sized marker reserves the field's identity
/// and its hash-preimage space now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AggregateProofSlot;

impl AggregateProofSlot {
    /// Domain tag written into the header preimage for this reserved field.
    pub const PREIMAGE_TAG: u8 = 0xA6;
}

/// RESERVED epoch supply-attestation field in the block header.
///
/// performance-budget §9: "every ~10k blocks an aggregate proof asserts
/// Σ(minted) − Σ(burned) = expected … Reserved field in the block format at
/// launch; activated with rung 1." **Not computed at devnet.**
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EpochSupplyAttestation;

impl EpochSupplyAttestation {
    /// Domain tag written into the header preimage for this reserved field.
    pub const PREIMAGE_TAG: u8 = 0x59;
}

/// A devnet block header.
///
/// 棒 0 is header-only (no body); block bodies carry real M3 tx proofs in 棒 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Hash of the parent header. [`ZERO_HASH`] for genesis.
    pub prev: Hash32,
    /// Block height. Genesis = 0.
    pub height: u64,
    /// Block timestamp (sim seconds — see `params_devnet::SIM_BLOCK_TIME_SECS`).
    pub timestamp: u64,
    /// PoW difficulty this block was mined against (also its fork-choice weight).
    pub difficulty: u64,
    /// PoW nonce — the field the miner varies (棒 1).
    pub nonce: u64,
    /// Commitment to the block body (the tx set). 棒 0 has no body, so this is
    /// caller-supplied; 棒 5 binds it to the real tx-proof set.
    pub tx_body_commitment: Hash32,
    /// RESERVED — see [`AggregateProofSlot`]. Not computed at devnet.
    pub aggregate_proof: AggregateProofSlot,
    /// RESERVED — see [`EpochSupplyAttestation`]. Not computed at devnet.
    pub epoch_supply_attestation: EpochSupplyAttestation,
    /// The per-form extension (lab #706): [`HeaderExt::NONE`] on every L1
    /// header — the v4/v5 preimages do not contain it and refuse anything
    /// else; an Annulet header carries its anchor and registry root here.
    pub ext: HeaderExt,
}

impl BlockHeader {
    /// The canonical **v4** byte preimage that [`Self::header_hash`] hashes.
    /// Fixed field order and widths; the two RESERVED fields each contribute
    /// their fixed domain tag so the reserved space is bound by the hash.
    ///
    /// 🔴 Since lab #470 this is **the v4 form, not the whole rule**: a v5-form
    /// net (genesis format v5) hashes [`Self::preimage_for`]`(GenesisForm::V5)`
    /// instead. Calling this directly asserts "v4, regardless of net" and is
    /// correct for the live T1 net, tests, and the v4 goldens — the same
    /// convention as `BlockBody::commitment()` vs `commitment_at`.
    pub fn preimage(&self) -> Vec<u8> {
        self.assert_l1_ext("v4");
        let mut buf = Vec::with_capacity(HEADER_PREIMAGE_LEN_V4);
        buf.extend_from_slice(&self.prev);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.difficulty.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&self.tx_body_commitment);
        buf.push(AggregateProofSlot::PREIMAGE_TAG);
        buf.push(EpochSupplyAttestation::PREIMAGE_TAG);
        buf
    }

    /// The canonical byte preimage under `form` — **the shipped rule** (lab
    /// #470 stage 1, the pool-t1-brief §3 C2 ruling). This is simultaneously
    /// the header-hash preimage, the PoW message, and the wire form, exactly
    /// as the single-serializer discipline always held; the form only chooses
    /// the layout.
    ///
    /// v5 layout (97 bytes; ruled offsets 32–46, tail keeps v4's order):
    ///
    /// ```text
    ///   0–31   prev (32)
    ///   32     header format version = 0x05
    ///   33–38  height, u48 LE (v5 headers refuse heights above 2^48−1)
    ///   39–46  nonce, u64 LE — low 4 bytes (39–42) = the xmrig-compatible
    ///          miner grind window; high 4 (43–46) = the pool extra-nonce
    ///   47–54  timestamp, u64 LE
    ///   55–62  difficulty, u64 LE
    ///   63–94  tx_body_commitment (32)
    ///   95     AggregateProofSlot::PREIMAGE_TAG   (0xA6)
    ///   96     EpochSupplyAttestation::PREIMAGE_TAG (0x59)
    /// ```
    ///
    /// # Panics
    ///
    /// Encoding a v5 preimage for a height above [`V5_MAX_HEIGHT`] panics:
    /// headers are locally built (mining) or already decode-checked (wire), so
    /// an out-of-range height here is a program error, not peer input.
    pub fn preimage_for(&self, form: GenesisForm) -> Vec<u8> {
        match form {
            GenesisForm::V4 => self.preimage(),
            GenesisForm::V5 => {
                self.assert_l1_ext("v5");
                assert!(
                    self.height <= V5_MAX_HEIGHT,
                    "v5 header height {} exceeds u48 (locally-built headers only)",
                    self.height
                );
                let mut buf = Vec::with_capacity(HEADER_PREIMAGE_LEN_V5);
                buf.extend_from_slice(&self.prev);
                buf.push(HEADER_VERSION_BYTE_V5);
                buf.extend_from_slice(&self.height.to_le_bytes()[..6]);
                buf.extend_from_slice(&self.nonce.to_le_bytes());
                buf.extend_from_slice(&self.timestamp.to_le_bytes());
                buf.extend_from_slice(&self.difficulty.to_le_bytes());
                buf.extend_from_slice(&self.tx_body_commitment);
                buf.push(AggregateProofSlot::PREIMAGE_TAG);
                buf.push(EpochSupplyAttestation::PREIMAGE_TAG);
                buf
            }
            GenesisForm::Annulet => self.preimage_annulet(),
        }
    }

    /// An L1 (v4/v5) header carries no extension; one that does is a program
    /// error (the v4/v5 wire decoders never produce one), refused by name.
    fn assert_l1_ext(&self, form: &str) {
        assert!(
            matches!(self.ext, HeaderExt::L1),
            "a {form} header carries no Annulet extension (lab #706): got {:?}",
            self.ext
        );
    }

    /// The **Annulet** preimage (lab #706 Q3, 153 bytes):
    ///
    /// ```text
    ///   0–31    prev (32)
    ///   32      header format version = 0x20
    ///   33–38   height, u48 LE
    ///   39–46   timestamp, u64 LE
    ///   47–54   l1_anchor_height, u64 LE
    ///   55–86   l1_anchor_root (32)
    ///   87–118  registry_root (32) — the root AFTER this block
    ///   119–150 tx_body_commitment (32)
    ///   151–152 ANNULET_RESERVED_TAGS (0x00 0x00)
    /// ```
    ///
    /// No difficulty and no nonce: an Annulet block is sealed by the
    /// sequencer's signature over [`Self::annulet_signing_message`] (B2).
    ///
    /// # Panics
    ///
    /// On a header without an Annulet extension, with a non-zero `difficulty`
    /// or `nonce`, or with a height above u48 — each a locally-built header
    /// that is wrong for this form (the wire decoder refuses them as errors).
    fn preimage_annulet(&self) -> Vec<u8> {
        let HeaderExt::Annulet(ext) = self.ext else {
            panic!("an Annulet header must carry HeaderExt::Annulet (lab #706): got {:?}", self.ext)
        };
        assert!(
            self.difficulty == 0 && self.nonce == 0,
            "an Annulet header has no PoW fields: difficulty {} nonce {} must be 0 (lab #706)",
            self.difficulty,
            self.nonce
        );
        assert!(
            self.height <= V5_MAX_HEIGHT,
            "Annulet header height {} exceeds u48 (locally-built headers only)",
            self.height
        );
        let mut buf = Vec::with_capacity(HEADER_PREIMAGE_LEN_ANNULET);
        buf.extend_from_slice(&self.prev);
        buf.push(HEADER_VERSION_BYTE_ANNULET);
        buf.extend_from_slice(&self.height.to_le_bytes()[..6]);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&ext.l1_anchor_height.to_le_bytes());
        buf.extend_from_slice(&ext.l1_anchor_root);
        buf.extend_from_slice(&ext.registry_root);
        buf.extend_from_slice(&self.tx_body_commitment);
        buf.extend_from_slice(&ANNULET_RESERVED_TAGS);
        debug_assert_eq!(buf.len(), HEADER_PREIMAGE_LEN_ANNULET);
        buf
    }

    /// The message the Annulet sequencer signs:
    /// [`ANNULET_HEADER_SIGNING_DOMAIN`] ‖ the Annulet preimage.
    pub fn annulet_signing_message(&self) -> Vec<u8> {
        let mut m = ANNULET_HEADER_SIGNING_DOMAIN.to_vec();
        m.extend_from_slice(&self.preimage_annulet());
        m
    }

    /// The header hash (Keccak-256 of the canonical **v4** preimage) — the
    /// block identity and the value the PoW check hashes on a v4 net. See
    /// [`Self::preimage`]'s note: v5-form callers use [`Self::header_hash_for`].
    pub fn header_hash(&self) -> Hash32 {
        keccak256(&self.preimage())
    }

    /// The header hash under `form` — the block identity on a net of that form.
    pub fn header_hash_for(&self, form: GenesisForm) -> Hash32 {
        keccak256(&self.preimage_for(form))
    }

    /// Construct the genesis header at the given difficulty. `prev = ZERO_HASH`,
    /// `height = 0`, `nonce = 0` (genesis carries no PoW), and
    /// `tx_body_commitment` = the commitment of the **genesis body**, which is
    /// [`BlockBody::default()`] — no premine, fair launch (protocol-spec §9).
    ///
    /// # Genesis binds its own body (issue #115, closing issue #77 F1)
    ///
    /// Until the 2026-07-31 mint this field was pinned to [`ZERO_HASH`] while the
    /// genesis body committed to `keccak256(coinbase_le ‖ rkm_le)` — so genesis
    /// was **the one block that did not satisfy the header/body binding** that
    /// [`crate::body::check_body_binding`] (issue #79) holds every other block to,
    /// and `qlab_node::node::check_stored_binding` carried an explicit height-0
    /// exemption to let it through. That exemption existed because genesis
    /// *predated* the binding, not because genesis should be exempt: while it was
    /// there, "this genesis is not the body it claims" was not an expressible
    /// property. It is now deleted, and genesis is checked like any other block.
    ///
    /// The pin to a *stronger* check still holds and is unchanged — every node
    /// pins `expected_genesis_hash` and refuses to start against a different
    /// genesis (`deploy/README.md`, `qumbra-node check`). The binding is a second,
    /// independent gate over the same ground, and it is the one that survives a
    /// caller assembling a genesis by hand or a corrupted disk replay.
    ///
    /// 🔴 **This moved the genesis hash, hence the network identity.** It was
    /// taken at a genesis mint precisely because the identity was moving anyway;
    /// at any other time it would be a gratuitous network-identity change. See
    /// `qumbra_node::genesis::GenesisFile` for the before/after values.
    ///
    /// *If you change what the genesis body is*, this constructor must change with
    /// it — but it can no longer fail silently: a genesis header committing to a
    /// body it was not paired with is rejected at the first binding check, which
    /// is the whole point of deleting the exemption.
    pub fn genesis(difficulty: u64, timestamp: u64) -> Self {
        Self::genesis_for(GenesisForm::V4, difficulty, timestamp)
    }

    /// [`Self::genesis`] under an explicit genesis form (lab #470 stage 4a):
    /// the empty genesis body is bound under **that form's** commitment — on a
    /// v5 net that is `BlockBody::default().commitment_v5()`, the value the
    /// stage-3 golden pre-registered (`82c2707b…7ea5`) as what a v5 genesis
    /// header must bind.
    ///
    /// # Panics
    ///
    /// On [`GenesisForm::Annulet`]: an Annulet genesis header carries its
    /// registry root and anchor, which this signature cannot supply — use
    /// [`Self::genesis_annulet`].
    pub fn genesis_for(form: GenesisForm, difficulty: u64, timestamp: u64) -> Self {
        let tx_body_commitment = match form {
            GenesisForm::V4 => BlockBody::default().commitment(),
            GenesisForm::V5 => BlockBody::default().commitment_v5(),
            GenesisForm::Annulet => panic!(
                "an Annulet genesis header carries its registry root: use \
                 BlockHeader::genesis_annulet (lab #706)"
            ),
        };
        Self { ext: crate::annulet::HeaderExt::NONE,
            prev: ZERO_HASH,
            height: 0,
            timestamp,
            difficulty,
            nonce: 0,
            // The genesis body is the empty body — bound here, not exempted
            // (issue #115), under the net's form.
            tx_body_commitment,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    /// Construct an unmined child of `parent` (nonce = 0; 棒 1 mines it). The
    /// caller supplies the body commitment and the difficulty for this block.
    /// **v4 form** — `prev` is the parent's v4 header hash; a v5 net links via
    /// [`Self::child_of_for`].
    pub fn child_of(
        parent: &BlockHeader,
        timestamp: u64,
        difficulty: u64,
        tx_body_commitment: Hash32,
    ) -> Self {
        Self::child_of_for(GenesisForm::V4, parent, timestamp, difficulty, tx_body_commitment)
    }

    /// [`Self::child_of`] under an explicit form: `prev` is the parent's hash
    /// **under that form** — on one net every header is one form, so the
    /// parent's form and the child's are the same value.
    ///
    /// # Panics
    ///
    /// On [`GenesisForm::Annulet`] — an Annulet child carries its own anchor
    /// and registry root; use [`Self::child_of_annulet`].
    pub fn child_of_for(
        form: GenesisForm,
        parent: &BlockHeader,
        timestamp: u64,
        difficulty: u64,
        tx_body_commitment: Hash32,
    ) -> Self {
        match form {
            GenesisForm::V4 | GenesisForm::V5 => {}
            GenesisForm::Annulet => panic!(
                "an Annulet child carries its anchor and registry root: use \
                 BlockHeader::child_of_annulet (lab #706)"
            ),
        }
        Self { ext: crate::annulet::HeaderExt::NONE,
            prev: parent.header_hash_for(form),
            height: parent.height + 1,
            timestamp,
            difficulty,
            nonce: 0,
            tx_body_commitment,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    /// The Annulet genesis header (lab #706): height 0, no PoW fields, the
    /// genesis registry root and (unset) anchor in `ext`, binding the Annulet
    /// genesis body's commitment.
    pub fn genesis_annulet(ext: AnnuletHeaderFields, tx_body_commitment: Hash32, timestamp: u64) -> Self {
        Self {
            prev: ZERO_HASH,
            height: 0,
            timestamp,
            difficulty: 0,
            nonce: 0,
            tx_body_commitment,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
            ext: HeaderExt::Annulet(ext),
        }
    }

    /// An unsealed Annulet child of `parent`: `prev` is the parent's Annulet
    /// id, height + 1, no PoW fields.
    pub fn child_of_annulet(
        parent: &BlockHeader,
        timestamp: u64,
        ext: AnnuletHeaderFields,
        tx_body_commitment: Hash32,
    ) -> Self {
        Self {
            prev: parent.header_hash_for(GenesisForm::Annulet),
            height: parent.height + 1,
            timestamp,
            difficulty: 0,
            nonce: 0,
            tx_body_commitment,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
            ext: HeaderExt::Annulet(ext),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_genesis() -> BlockHeader {
        BlockHeader::genesis(1_000, 0)
    }

    #[test]
    fn header_hash_is_deterministic() {
        let h = sample_genesis();
        assert_eq!(h.header_hash(), h.header_hash());
    }

    #[test]
    fn nonce_changes_the_hash() {
        let mut h = sample_genesis();
        let h0 = h.header_hash();
        h.nonce = 1;
        assert_ne!(h0, h.header_hash(), "PoW hash must depend on the nonce");
    }

    #[test]
    fn preimage_binds_the_reserved_field_tags() {
        // The two reserved fields occupy the last two preimage bytes with their
        // fixed domain tags — their identity is hashed even though they carry no
        // value at devnet.
        let pre = sample_genesis().preimage();
        let n = pre.len();
        assert_eq!(pre[n - 2], AggregateProofSlot::PREIMAGE_TAG);
        assert_eq!(pre[n - 1], EpochSupplyAttestation::PREIMAGE_TAG);
        // The two reserved fields are distinguishable (distinct domain tags).
        assert_ne!(
            AggregateProofSlot::PREIMAGE_TAG,
            EpochSupplyAttestation::PREIMAGE_TAG
        );
    }

    #[test]
    fn preimage_has_fixed_width() {
        // 32 (prev) + 8*4 (height,timestamp,difficulty,nonce) + 32 (body) + 2 (tags).
        assert_eq!(sample_genesis().preimage().len(), 32 + 32 + 32 + 2);
    }

    #[test]
    fn genesis_binds_its_own_body() {
        // issue #115: genesis is no longer the one block that fails the
        // header/body binding. Its commitment IS the genesis body's commitment.
        let g = sample_genesis();
        assert_eq!(g.tx_body_commitment, BlockBody::default().commitment());
        assert_ne!(
            g.tx_body_commitment, ZERO_HASH,
            "ZERO_HASH is the pre-#115 value the height-0 exemption existed for"
        );
    }

    #[test]
    fn child_links_to_parent_and_increments_height() {
        let g = sample_genesis();
        let c = BlockHeader::child_of(&g, 2, 1_000, [7u8; 32]);
        assert_eq!(c.prev, g.header_hash());
        assert_eq!(c.height, 1);
        assert_eq!(c.tx_body_commitment, [7u8; 32]);
    }

    // ── v5 form (lab #470 stage 1, pool-t1-brief §3 C2) ──────────────────────

    /// A fixture header with every field byte distinguishable, so the offset
    /// assertions below cannot pass by coincidence.
    fn v5_fixture() -> BlockHeader {
        BlockHeader { ext: crate::annulet::HeaderExt::NONE,
            prev: [0x11; 32],
            height: 0x0000_6655_4433_2211,       // 6 significant LE bytes
            timestamp: 0x8877_6655_4433_2211,
            difficulty: 0xAA99_8877_6655_4433,
            nonce: 0xCCBB_AA99_8877_6655,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    #[test]
    fn v4_preimage_is_byte_identical_through_preimage_for() {
        // The v4 arm of the form-keyed serializer IS the old serializer — the
        // golden lock for "no v4 byte moved".
        let h = v5_fixture();
        assert_eq!(h.preimage(), h.preimage_for(GenesisForm::V4));
        assert_eq!(h.header_hash(), h.header_hash_for(GenesisForm::V4));
        assert_eq!(h.preimage().len(), HEADER_PREIMAGE_LEN_V4);
    }

    #[test]
    fn v5_preimage_layout_is_the_ruled_one() {
        let h = v5_fixture();
        let p = h.preimage_for(GenesisForm::V5);
        assert_eq!(p.len(), HEADER_PREIMAGE_LEN_V5);
        assert_eq!(&p[0..32], &[0x11; 32], "prev at 0–31");
        assert_eq!(p[32], HEADER_VERSION_BYTE_V5, "format version byte at 32");
        assert_eq!(&p[33..39], &0x0000_6655_4433_2211u64.to_le_bytes()[..6], "u48 height at 33–38");
        assert_eq!(&p[39..47], &0xCCBB_AA99_8877_6655u64.to_le_bytes(), "nonce u64 at 39–46");
        assert_eq!(&p[47..55], &0x8877_6655_4433_2211u64.to_le_bytes(), "timestamp at 47–54");
        assert_eq!(&p[55..63], &0xAA99_8877_6655_4433u64.to_le_bytes(), "difficulty at 55–62");
        assert_eq!(&p[63..95], &[0x22; 32], "body commitment at 63–94");
        assert_eq!(p[95], AggregateProofSlot::PREIMAGE_TAG);
        assert_eq!(p[96], EpochSupplyAttestation::PREIMAGE_TAG);
    }

    #[test]
    fn v5_miner_and_extra_nonce_windows_are_the_stratum_ruling() {
        // The C2 ruling's whole point: xmrig's compiled-in grind window
        // (offset 39, width 4) lands on the nonce's LOW 4 bytes, and the HIGH
        // 4 (43–46) are the pool's extra-nonce — each varies exactly its own
        // window and nothing else.
        let h = v5_fixture();
        let base = h.preimage_for(GenesisForm::V5);

        let mut low = h;
        low.nonce ^= 0x0000_0000_FFFF_FFFF; // flip the miner-ground half
        let p_low = low.preimage_for(GenesisForm::V5);
        assert_ne!(&p_low[39..43], &base[39..43], "low 4 = the xmrig window");
        assert_eq!(&p_low[43..47], &base[43..47], "extra-nonce untouched");
        assert_eq!(&p_low[..39], &base[..39]);
        assert_eq!(&p_low[47..], &base[47..]);

        let mut high = h;
        high.nonce ^= 0xFFFF_FFFF_0000_0000; // flip the pool extra-nonce half
        let p_high = high.preimage_for(GenesisForm::V5);
        assert_eq!(&p_high[39..43], &base[39..43], "miner window untouched");
        assert_ne!(&p_high[43..47], &base[43..47], "high 4 = the extra-nonce");
        assert_eq!(&p_high[..39], &base[..39]);
        assert_eq!(&p_high[47..], &base[47..]);
    }

    #[test]
    fn v5_and_v4_forms_of_one_header_differ_in_length_and_hash() {
        let h = v5_fixture();
        assert_eq!(h.preimage_for(GenesisForm::V4).len(), 98);
        assert_eq!(h.preimage_for(GenesisForm::V5).len(), 97);
        assert_ne!(h.header_hash_for(GenesisForm::V4), h.header_hash_for(GenesisForm::V5));
    }

    #[test]
    #[should_panic(expected = "exceeds u48")]
    fn v5_preimage_refuses_a_height_above_u48() {
        let mut h = v5_fixture();
        h.height = V5_MAX_HEIGHT + 1;
        let _ = h.preimage_for(GenesisForm::V5);
    }

    /// The stage-3 pre-registered tripwire (lab #470): a v5 genesis header
    /// binds the empty body's v5 commitment — `82c2707b…7ea5` — and the v4
    /// constructor is byte-identical to what it always was.
    #[test]
    fn genesis_for_binds_each_forms_empty_body() {
        let v4 = BlockHeader::genesis(1_000, 0);
        assert_eq!(v4, BlockHeader::genesis_for(GenesisForm::V4, 1_000, 0));
        let v5 = BlockHeader::genesis_for(GenesisForm::V5, 1_000, 0);
        assert_eq!(v5.tx_body_commitment, BlockBody::default().commitment_v5());
        let hex: String =
            v5.tx_body_commitment.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "82c2707bdf9790b25ef44355cb44cfd7faa6aba28d5db184b57edf83e7ba7ea5");
        assert_ne!(v5.tx_body_commitment, v4.tx_body_commitment);
    }

    #[test]
    fn v5_child_links_via_the_v5_parent_hash() {
        let g = sample_genesis();
        let c = BlockHeader::child_of_for(GenesisForm::V5, &g, 2, 1_000, [7u8; 32]);
        assert_eq!(c.prev, g.header_hash_for(GenesisForm::V5));
        assert_ne!(c.prev, g.header_hash(), "a v5 link is not the v4 hash");
        assert_eq!(c.height, 1);
    }

    // ── Annulet form (lab #706, l2-roadmap B1) ────────────────────────────────

    /// A fixture Annulet header with every field byte distinguishable.
    fn annulet_fixture() -> BlockHeader {
        BlockHeader {
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
        }
    }

    #[test]
    fn annulet_preimage_layout_is_the_ruled_one() {
        let p = annulet_fixture().preimage_for(GenesisForm::Annulet);
        assert_eq!(p.len(), HEADER_PREIMAGE_LEN_ANNULET);
        assert_eq!(p.len(), 153);
        assert_eq!(&p[0..32], &[0x11; 32], "prev at 0–31");
        assert_eq!(p[32], 0x20, "version byte at 32");
        assert_eq!(HEADER_VERSION_BYTE_ANNULET as u32, crate::forms::ANNULET_GENESIS_FORMAT_VERSION);
        assert_eq!(&p[33..39], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], "u48 height at 33–38");
        assert_eq!(&p[39..47], &0x8877_6655_4433_2211u64.to_le_bytes(), "timestamp at 39–46");
        assert_eq!(&p[47..55], &0x0102_0304_0506_0708u64.to_le_bytes(), "l1_anchor_height at 47–54");
        assert_eq!(&p[55..87], &[0x33; 32], "l1_anchor_root at 55–86");
        assert_eq!(&p[87..119], &[0x44; 32], "registry_root at 87–118");
        assert_eq!(&p[119..151], &[0x22; 32], "body commitment at 119–150");
        assert_eq!(&p[151..153], &[0x00, 0x00], "reserved tag bytes at 151–152");
    }

    #[test]
    fn the_three_header_forms_differ_in_length() {
        assert_eq!(
            [HEADER_PREIMAGE_LEN_V4, HEADER_PREIMAGE_LEN_V5, HEADER_PREIMAGE_LEN_ANNULET],
            [98, 97, 153]
        );
    }

    #[test]
    #[should_panic(expected = "carries no Annulet extension")]
    fn a_v4_preimage_refuses_an_annulet_ext() {
        let _ = annulet_fixture().preimage_for(GenesisForm::V4);
    }

    #[test]
    #[should_panic(expected = "carries no Annulet extension")]
    fn a_v5_preimage_refuses_an_annulet_ext() {
        let _ = annulet_fixture().preimage_for(GenesisForm::V5);
    }

    #[test]
    #[should_panic(expected = "must carry HeaderExt::Annulet")]
    fn an_annulet_preimage_refuses_an_l1_header() {
        let _ = v5_fixture().preimage_for(GenesisForm::Annulet);
    }

    #[test]
    #[should_panic(expected = "no PoW fields")]
    fn an_annulet_preimage_refuses_a_nonce() {
        let mut h = annulet_fixture();
        h.nonce = 1;
        let _ = h.preimage_for(GenesisForm::Annulet);
    }

    #[test]
    #[should_panic(expected = "no PoW fields")]
    fn an_annulet_preimage_refuses_a_difficulty() {
        let mut h = annulet_fixture();
        h.difficulty = 1;
        let _ = h.preimage_for(GenesisForm::Annulet);
    }

    #[test]
    fn the_annulet_signing_message_is_domain_then_preimage() {
        let h = annulet_fixture();
        let m = h.annulet_signing_message();
        assert_eq!(&m[..ANNULET_HEADER_SIGNING_DOMAIN.len()], b"qumbra:annulet:header:v1");
        assert_eq!(&m[ANNULET_HEADER_SIGNING_DOMAIN.len()..], &h.preimage_for(GenesisForm::Annulet)[..]);
    }

    #[test]
    fn an_annulet_child_links_via_the_annulet_id() {
        let g = BlockHeader::genesis_annulet(
            AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [0x44; 32] },
            [0x22; 32],
            0,
        );
        let ext = AnnuletHeaderFields { l1_anchor_height: 3, l1_anchor_root: [0x55; 32], registry_root: [0x44; 32] };
        let c = BlockHeader::child_of_annulet(&g, 10, ext, [0x66; 32]);
        assert_eq!(c.prev, g.header_hash_for(GenesisForm::Annulet));
        assert_eq!((c.height, c.difficulty, c.nonce), (1, 0, 0));
        assert_eq!(c.ext, HeaderExt::Annulet(ext));
    }

    #[test]
    #[should_panic(expected = "use BlockHeader::child_of_annulet")]
    fn child_of_for_refuses_the_annulet_form_by_name() {
        let _ = BlockHeader::child_of_for(GenesisForm::Annulet, &annulet_fixture(), 1, 0, [0; 32]);
    }

    #[test]
    #[should_panic(expected = "use BlockHeader::genesis_annulet")]
    fn genesis_for_refuses_the_annulet_form_by_name() {
        let _ = BlockHeader::genesis_for(GenesisForm::Annulet, 0, 0);
    }

    /// The Annulet id and signing-message digest of the fixture, hard-coded
    /// (lab #706): computed by the named `annulet_goldens` run AND,
    /// independently, by a Python Keccak-256 over the hand-assembled 153-B
    /// preimage — both agreed before pinning.
    #[test]
    fn annulet_header_goldens() {
        let h = annulet_fixture();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&h.header_hash_for(GenesisForm::Annulet)), GOLDEN_ANNULET_HEADER_ID);
        assert_eq!(hex(&crate::hash::keccak256(&h.annulet_signing_message())), GOLDEN_ANNULET_SIGNING_DIGEST);
    }

    const GOLDEN_ANNULET_HEADER_ID: &str = "1bc6fce1c82cfb364d7649cc610c2c8835e8b5c43f4af9f27d3da4c6c4d88b97";
    const GOLDEN_ANNULET_SIGNING_DIGEST: &str = "2d00955ca3683eac7ecaa83eabbfb18c0d717e42231f40fd6dfcff474116c9e3";
}
