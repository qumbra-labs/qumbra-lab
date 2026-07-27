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

use crate::hash::keccak256;

/// A 256-bit hash (Keccak-256 digest), the header/block identity type.
pub type Hash32 = [u8; 32];

/// The all-zero hash — the parent of the genesis header.
pub const ZERO_HASH: Hash32 = [0u8; 32];

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
}

impl BlockHeader {
    /// The canonical byte preimage that [`Self::header_hash`] hashes. Fixed field
    /// order and widths; the two RESERVED fields each contribute their fixed
    /// domain tag so the reserved space is bound by the hash.
    pub fn preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 8 * 4 + 32 + 2);
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

    /// The header hash (Keccak-256 of the canonical preimage) — the block identity
    /// and the value the PoW check hashes.
    pub fn header_hash(&self) -> Hash32 {
        keccak256(&self.preimage())
    }

    /// Construct the genesis header at the given difficulty. `prev = ZERO_HASH`,
    /// `height = 0`, `nonce = 0` (genesis carries no PoW), empty body commitment.
    ///
    /// # 🔴 T1: the next genesis mint must commit to its body (issue #77 F1)
    ///
    /// `tx_body_commitment` is pinned to [`ZERO_HASH`] here, but an empty body
    /// commits to `keccak256(coinbase_le)` — so **the genesis block is the one
    /// block that does not satisfy the header/body binding**, and it is the one
    /// explicit exemption in `qlab_node`'s state-mutation guard.
    ///
    /// *Why the exemption is safe:* not because "it is only genesis", but because
    /// genesis is covered by a **stronger** check — every node pins
    /// `expected_genesis_hash` in its config and refuses to start against any
    /// other genesis (`deploy/README.md`, `qumbra-node check`). The binding
    /// protects blocks that arrive from the network; genesis never does.
    ///
    /// *Why it was not fixed:* setting this to `BlockBody::default().commitment()`
    /// changes the genesis hash, hence the network identity — the T0 net is pinned
    /// to `4a75b3b8…c2c3`. That is a new-network decision, and Larry's alone.
    ///
    /// *The requirement:* **when T1's genesis is minted, set this to the real
    /// commitment of the genesis body and delete the height-0 exemption in
    /// `qlab_node::node::check_stored_binding`.** A new network is exactly the
    /// moment the change is free.
    pub fn genesis(difficulty: u64, timestamp: u64) -> Self {
        Self {
            prev: ZERO_HASH,
            height: 0,
            timestamp,
            difficulty,
            nonce: 0,
            // 🔴 T1: see the doc comment above — must become the real body
            // commitment at the next genesis mint (issue #77 F1).
            tx_body_commitment: ZERO_HASH,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        }
    }

    /// Construct an unmined child of `parent` (nonce = 0; 棒 1 mines it). The
    /// caller supplies the body commitment and the difficulty for this block.
    pub fn child_of(
        parent: &BlockHeader,
        timestamp: u64,
        difficulty: u64,
        tx_body_commitment: Hash32,
    ) -> Self {
        Self {
            prev: parent.header_hash(),
            height: parent.height + 1,
            timestamp,
            difficulty,
            nonce: 0,
            tx_body_commitment,
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
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
    fn child_links_to_parent_and_increments_height() {
        let g = sample_genesis();
        let c = BlockHeader::child_of(&g, 2, 1_000, [7u8; 32]);
        assert_eq!(c.prev, g.header_hash());
        assert_eq!(c.height, 1);
        assert_eq!(c.tx_body_commitment, [7u8; 32]);
    }
}
