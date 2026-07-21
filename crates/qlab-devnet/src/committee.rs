//! The finality committee and its checkpoint votes (consensus-and-network.md §5).
//!
//! A small (N≈20) committee of validators with **transparent self-bonded stake**
//! signs checkpoints with **ML-DSA-65** — no aggregation needed at this N, which
//! is exactly why §3(b)'s missing-aggregation wall doesn't apply. This module
//! provides:
//!   - [`Committee`] — the ordered set of N ML-DSA-65 *public* keys and the
//!     ⅔-quorum threshold.
//!   - [`Validator`] — a validator's signing side (secret key). Devnet keys are
//!     derived deterministically from config seeds; real validators generate
//!     their own. No hand-rolled crypto — see the crate `ml-dsa` dependency.
//!   - [`Checkpoint`] / [`Vote`] — what is finalized and a single signed vote.
//!
//! Membership is **static** here (genesis committee). Epoch-boundary membership
//! changes (committee-governance §2) and equivocation/jail (§3) are 棒 3.

use ml_dsa::{B32, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::header::Hash32;

/// A committee member's ML-DSA-65 public (verifying) key.
pub type MemberKey = VerifyingKey<MlDsa65>;
/// An ML-DSA-65 signature over a checkpoint.
pub type MemberSig = Signature<MlDsa65>;

/// Domain-separation prefix bound into every checkpoint signing message, so a
/// committee signature can never be replayed as any other ML-DSA message.
pub const CHECKPOINT_DOMAIN: &[u8] = b"qumbra:devnet:checkpoint:v1";

/// The ⅔-quorum threshold for a committee of `n`: `floor(2n/3) + 1` — **strictly
/// more than two thirds**, the Byzantine-safe quorum for a finality gadget
/// tolerating `f < n/3` faults (consensus §4/§5). E.g. n=20 → 14, n=21 → 15.
pub fn quorum_threshold(n: usize) -> usize {
    (2 * n) / 3 + 1
}

/// The finality committee: an ordered list of N ML-DSA-65 public keys. A
/// validator's *index* into this list identifies its votes.
#[derive(Clone)]
pub struct Committee {
    members: Vec<MemberKey>,
}

impl Committee {
    /// Build a committee from an ordered list of member public keys.
    pub fn from_keys(members: Vec<MemberKey>) -> Self {
        Self { members }
    }

    /// The number of members, N.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// This committee's ⅔-quorum threshold (see the free [`quorum_threshold`]).
    pub fn quorum_threshold(&self) -> usize {
        quorum_threshold(self.members.len())
    }

    /// The member public key at committee index `idx`.
    pub fn member(&self, idx: usize) -> Option<&MemberKey> {
        self.members.get(idx)
    }

    /// Verify that `vote` is a valid signature by its claimed signer over `cp`.
    /// `false` if the signer index is out of range or the signature is invalid.
    pub fn verify_vote(&self, cp: &Checkpoint, vote: &Vote) -> bool {
        match self.members.get(vote.signer) {
            Some(key) => key.verify(&cp.signing_message(), &vote.signature).is_ok(),
            None => false,
        }
    }
}

/// A committee validator's signing side — holds the ML-DSA-65 secret key.
///
/// Devnet keys come from deterministic seeds ([`Validator::from_seed`]); real
/// validators generate their own and publish only the verifying key.
pub struct Validator {
    /// This validator's index into the [`Committee`] member list.
    pub index: usize,
    signing_key: SigningKey<MlDsa65>,
}

impl Validator {
    /// Derive a validator deterministically from a 32-byte seed (devnet only).
    pub fn from_seed(index: usize, seed: [u8; 32]) -> Self {
        let seed: B32 = seed.into();
        Self {
            index,
            signing_key: SigningKey::<MlDsa65>::from_seed(&seed),
        }
    }

    /// This validator's public key, for inclusion in a [`Committee`].
    pub fn verifying_key(&self) -> MemberKey {
        self.signing_key.verifying_key()
    }

    /// Sign `cp`, producing this validator's [`Vote`]. Uses ML-DSA's deterministic
    /// signing variant (via the `Signer` trait), so votes are reproducible in the
    /// sim; production validators may prefer the hedged variant.
    pub fn sign_checkpoint(&self, cp: &Checkpoint) -> Vote {
        Vote {
            signer: self.index,
            signature: self.signing_key.sign(&cp.signing_message()),
        }
    }
}

/// A checkpoint the committee finalizes: the block being made irreversible, plus
/// the commitment **root** anchors reference against it (consensus §6).
///
/// Devnet note: `root` is the note-commitment-tree root finalized at `height`
/// (transaction-model §4 / consensus §6). The devnet does not build the tree, so
/// in 棒 2 callers pass the block hash as a stand-in; 棒 5 binds the real M3
/// anchor root here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// Block height being finalized.
    pub height: u64,
    /// Hash of the block being finalized.
    pub block_hash: Hash32,
    /// The finalized commitment root anchors may reference (§6).
    pub root: Hash32,
}

impl Checkpoint {
    /// Build a checkpoint. In 棒 2 `root` is typically the block hash (stand-in);
    /// 棒 5 supplies the real commitment root.
    pub fn new(height: u64, block_hash: Hash32, root: Hash32) -> Self {
        Self { height, block_hash, root }
    }

    /// The domain-separated byte string committee members sign:
    /// `CHECKPOINT_DOMAIN ‖ height_le ‖ block_hash ‖ root`.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 8 + 32 + 32);
        m.extend_from_slice(CHECKPOINT_DOMAIN);
        m.extend_from_slice(&self.height.to_le_bytes());
        m.extend_from_slice(&self.block_hash);
        m.extend_from_slice(&self.root);
        m
    }
}

/// A single committee member's signed vote for a checkpoint.
pub struct Vote {
    /// The signer's committee index.
    pub signer: usize,
    /// The signer's ML-DSA-65 signature over the checkpoint's signing message.
    pub signature: MemberSig,
}

/// Build a deterministic devnet committee of `n` validators plus their signing
/// sides. Seeds are domain-separated per index so the keys are distinct and
/// reproducible. **Devnet only** — real committees are provisioned per
/// committee-governance §1 (incentivized candidate-net), not from seeds.
pub fn devnet_committee(n: usize) -> (Committee, Vec<Validator>) {
    let validators: Vec<Validator> = (0..n)
        .map(|i| {
            // Seed = a fixed tag with the index folded in (distinct per validator).
            let mut seed = [0u8; 32];
            seed[0] = 0x9c; // "qumbra committee" tag byte
            seed[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            Validator::from_seed(i, seed)
        })
        .collect();
    let keys = validators.iter().map(|v| v.verifying_key()).collect();
    (Committee::from_keys(keys), validators)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_checkpoint() -> Checkpoint {
        Checkpoint::new(8, [0x11; 32], [0x22; 32])
    }

    #[test]
    fn quorum_threshold_is_strictly_over_two_thirds() {
        // Pure arithmetic — no keygen, so cheap even in debug.
        let cases = [(1usize, 1usize), (3, 3), (4, 3), (7, 5), (20, 14), (21, 15), (50, 34)];
        for (n, want) in cases {
            assert_eq!(quorum_threshold(n), want, "N={n}");
            // strictly more than 2/3 of N, and one fewer is not.
            assert!(3 * want > 2 * n, "N={n}: {want} must be > 2N/3");
            assert!(3 * (want - 1) <= 2 * n, "N={n}: {} must be ≤ 2N/3", want - 1);
        }
    }

    #[test]
    fn from_seed_is_deterministic_and_distinct() {
        let a1 = Validator::from_seed(0, [7u8; 32]);
        let a2 = Validator::from_seed(0, [7u8; 32]);
        let b = Validator::from_seed(1, [8u8; 32]);
        // Same seed ⇒ same public key (encoded bytes equal).
        assert_eq!(
            a1.verifying_key().encode().to_vec(),
            a2.verifying_key().encode().to_vec()
        );
        // Different seed ⇒ different public key.
        assert_ne!(
            a1.verifying_key().encode().to_vec(),
            b.verifying_key().encode().to_vec()
        );
    }

    #[test]
    fn valid_vote_verifies_wrong_signer_or_message_does_not() {
        let (committee, validators) = devnet_committee(4);
        let cp = sample_checkpoint();

        // A real vote from validator 2 verifies.
        let vote = validators[2].sign_checkpoint(&cp);
        assert_eq!(vote.signer, 2);
        assert!(committee.verify_vote(&cp, &vote));

        // ML-DSA-65 signature is 3309 bytes (FIPS-204 / design §5).
        assert_eq!(vote.signature.encode().to_vec().len(), 3309);

        // Same signature attributed to the wrong signer index fails.
        let forged = Vote { signer: 0, signature: validators[2].sign_checkpoint(&cp).signature };
        assert!(!committee.verify_vote(&cp, &forged));

        // A vote for a different checkpoint does not verify against `cp`.
        let other = Checkpoint::new(9, [0x11; 32], [0x22; 32]);
        let vote_other = validators[2].sign_checkpoint(&other);
        assert!(!committee.verify_vote(&cp, &vote_other));

        // Signer index out of range fails cleanly (no panic).
        let oob = Vote { signer: 99, signature: validators[2].sign_checkpoint(&cp).signature };
        assert!(!committee.verify_vote(&cp, &oob));
    }

    #[test]
    fn signing_message_is_domain_separated_and_binds_fields() {
        let cp = sample_checkpoint();
        let m = cp.signing_message();
        assert!(m.starts_with(CHECKPOINT_DOMAIN));
        // Changing any field changes the message.
        assert_ne!(m, Checkpoint::new(9, [0x11; 32], [0x22; 32]).signing_message());
        assert_ne!(m, Checkpoint::new(8, [0x33; 32], [0x22; 32]).signing_message());
        assert_ne!(m, Checkpoint::new(8, [0x11; 32], [0x44; 32]).signing_message());
    }
}
