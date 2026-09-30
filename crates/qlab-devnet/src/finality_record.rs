//! **The finality record** (lab #785 F5-3, Larry's Q-L5): a committee quorum
//! vote set carried in a block body, so that *finality as the chain records
//! it* is a pure function of the chain and every node, live or replaying,
//! answers anchor validity identically.
//!
//! ## Format
//!
//! Byte for byte the `CheckpointVotes` / `Checkpoint` gossip body
//! (`qlab-p2p`'s `encode_checkpoint_msg`, cross-locked by a test there):
//!
//! ```text
//! height u64 LE ‖ block_hash [32] ‖ root [32] ‖ varint n ‖ n × (varint signer ‖ varint 3309 ‖ ML-DSA-65 signature [3309])
//! ```
//!
//! 15 votes are 49,753 bytes. The **canonical** form is enforced on decode,
//! and a record decodes only if it re-encodes to the same bytes:
//! - `QUORUM ≤ n ≤ N` votes, signers **strictly ascending** (so distinct),
//!   each `< N`;
//! - every signature length exactly [`SIG_LEN`];
//! - `root == block_hash` — the devnet stand-in both checkpoint proposers use
//!   today (`qlab-p2p`'s adapter builds `Checkpoint::new(h, hash, hash)`);
//!   pinned here so a record cannot carry a second, unchecked 32-byte field;
//! - shortest varints, no trailing bytes.
//!
//! ## Validity ([`FinalityRecord::check`])
//!
//! For a record in block B at height H, with parent's recorded finality
//! `CR(parent)` (the height of the latest record in B's ancestry):
//! 1. the checkpoint height is a cadence height, non-zero;
//! 2. **monotone**: it is strictly above `CR(parent)` when one exists;
//! 3. **ancestor**: its `block_hash` is B's ancestor at that height (so the
//!    height is below H);
//! 4. **quorum**: every carried signature verifies over the unchanged
//!    checkpoint signing message against **genesis committee₀, by genesis
//!    index** — and there are at least `QUORUM` of them.
//!
//! ## The roster premise, and what it means (lab #785 ruling Q1)
//!
//! Records verify against committee₀ as the genesis file lists it, **with
//! jail and tombstone status not applied**. Those statuses are node-local
//! today: jail comes from each node's own participation window and tombstones
//! from gossiped evidence plus a local ledger (`qlab-p2p`'s `punish` module:
//! "agreement needs the evidence on chain, which is a payload change and a
//! separate decision"). A chain-only verifier therefore has committee₀ and
//! nothing else. Safety is the BFT argument: two conflicting records at one
//! height need at least 9 members of 21 to sign both.
//!
//! **Consequence: recorded finality and local finality can differ.** The
//! record governs **anchor validity only** ([`anchor_ok`]); fork choice keeps
//! the node's local finality (`FinalityTracker`, `ChainState::set_finalized`),
//! unchanged. A member a node has jailed locally still signs a valid record.
//!
//! ## The anchor rule ([`anchor_ok`])
//!
//! A commitment root is a valid anchor in block B at height H iff it was the
//! commitment root after **some** ancestor height `h` with `h ≤ CR(B)` and
//! `H − h ≤ MAX_ANCHOR_AGE_BLOCKS` (a root repeats across output-free blocks,
//! so the height tested is the newest one under the ceiling — review M4) — the
//! window measured from **B's own height**, never a node's tip, and finality
//! read from the **record**, never a node's pointer. No record in the
//! ancestry, no valid anchor. Transaction anchors and a wrapper bundle's
//! absorbed roots (V7) read the same rule.
use ml_dsa::{EncodedSignature, MlDsa65, Signature};
use qlab_note::compact::{read_varint, write_varint};

use crate::committee::{Checkpoint, Committee, Vote};
use crate::finality::is_checkpoint_height;
use crate::header::Hash32;
use crate::params_devnet::{
    CHECKPOINT_CADENCE_BLOCKS, FROZEN_COMMITTEE_SIZE, FROZEN_QUORUM, MAX_ANCHOR_AGE_BLOCKS,
};

/// ML-DSA-65 signature length (FIPS 204), as the gossip codec carries it.
pub const SIG_LEN: usize = 3309;

/// A finality record: one checkpoint and a quorum of committee₀ signatures.
#[derive(Clone)]
pub struct FinalityRecord {
    /// The checkpoint the quorum signed.
    pub cp: Checkpoint,
    /// The votes, signers strictly ascending.
    pub votes: Vec<Vote>,
}

impl std::fmt::Debug for FinalityRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signers: Vec<usize> = self.votes.iter().map(|v| v.signer).collect();
        f.debug_struct("FinalityRecord")
            .field("cp", &self.cp)
            .field("signers", &signers)
            .finish()
    }
}

/// Why a record is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Truncated, over-long, a padded varint, or trailing bytes.
    Malformed(&'static str),
    /// Fewer than the quorum or more than the committee.
    VoteCount { got: usize },
    /// Signers not strictly ascending (a duplicate, or out of order).
    SignerOrder,
    /// A signer index outside committee₀.
    SignerRange { signer: usize },
    /// A signature length other than [`SIG_LEN`].
    SigLen { got: usize },
    /// `root` is not `block_hash` (the pinned devnet stand-in).
    Root,
    /// The bytes decode but are not the canonical encoding of what they decode to.
    NotCanonical,
    /// Not a cadence height (or height 0).
    NotCadence { height: u64 },
    /// Not strictly above the ancestry's recorded finality.
    NotMonotone { height: u64, prior: u64 },
    /// The checkpoint's block is not this block's ancestor at that height.
    NotAncestor { height: u64 },
    /// A carried signature does not verify against committee₀.
    BadSignature { signer: usize },
}

impl FinalityRecord {
    /// The canonical bytes (the gossip body's).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72 + 1 + self.votes.len() * (SIG_LEN + 3));
        out.extend_from_slice(&self.cp.height.to_le_bytes());
        out.extend_from_slice(&self.cp.block_hash);
        out.extend_from_slice(&self.cp.root);
        write_varint(&mut out, self.votes.len() as u64);
        for v in &self.votes {
            write_varint(&mut out, v.signer as u64);
            let sig = v.signature.encode();
            write_varint(&mut out, sig.len() as u64);
            out.extend_from_slice(&sig);
        }
        out
    }

    /// Decode, refusing anything but the canonical form (module doc).
    pub fn decode(b: &[u8]) -> Result<Self, RecordError> {
        let take = |pos: &mut usize, n: usize, what: &'static str| -> Result<&[u8], RecordError> {
            let s = b.get(*pos..*pos + n).ok_or(RecordError::Malformed(what))?;
            *pos += n;
            Ok(s)
        };
        let vint = |pos: &mut usize, what: &'static str| {
            read_varint(b, pos).map_err(|_| RecordError::Malformed(what))
        };
        let mut pos = 0;
        let height = u64::from_le_bytes(take(&mut pos, 8, "height")?.try_into().expect("8 bytes"));
        let block_hash: Hash32 = take(&mut pos, 32, "block_hash")?
            .try_into()
            .expect("32 bytes");
        let root: Hash32 = take(&mut pos, 32, "root")?.try_into().expect("32 bytes");
        if root != block_hash {
            return Err(RecordError::Root);
        }
        let n = vint(&mut pos, "vote count")?;
        if n < FROZEN_QUORUM as u64 || n > FROZEN_COMMITTEE_SIZE as u64 {
            return Err(RecordError::VoteCount {
                got: n.min(usize::MAX as u64) as usize,
            });
        }
        let mut votes = Vec::with_capacity(n as usize);
        let mut last: Option<usize> = None;
        for _ in 0..n {
            let signer = vint(&mut pos, "signer")?;
            if signer >= FROZEN_COMMITTEE_SIZE as u64 {
                return Err(RecordError::SignerRange {
                    signer: signer as usize,
                });
            }
            let signer = signer as usize;
            if last.is_some_and(|l| signer <= l) {
                return Err(RecordError::SignerOrder);
            }
            last = Some(signer);
            let len = vint(&mut pos, "signature length")?;
            if len != SIG_LEN as u64 {
                return Err(RecordError::SigLen {
                    got: len.min(usize::MAX as u64) as usize,
                });
            }
            let raw = take(&mut pos, SIG_LEN, "signature")?;
            let enc = EncodedSignature::<MlDsa65>::try_from(raw)
                .map_err(|_| RecordError::Malformed("signature"))?;
            let signature =
                Signature::<MlDsa65>::decode(&enc).ok_or(RecordError::Malformed("signature"))?;
            votes.push(Vote { signer, signature });
        }
        if pos != b.len() {
            return Err(RecordError::Malformed("trailing bytes"));
        }
        let rec = Self {
            cp: Checkpoint::new(height, block_hash, root),
            votes,
        };
        if rec.encode() != b {
            return Err(RecordError::NotCanonical);
        }
        Ok(rec)
    }

    /// The canonical-form rules a record must satisfy however it was built
    /// (lab #785 PR #789 review K1): `QUORUM ≤ n ≤ N`, signers strictly
    /// ascending and `< N`, `root == block_hash`. [`Self::decode`] enforces
    /// them on the way in; [`Self::check`] re-asserts them, so a record built
    /// by hand (the fields are public) cannot pass rule 4 with one signature
    /// repeated.
    pub fn structural(&self) -> Result<(), RecordError> {
        let n = self.votes.len();
        if !(FROZEN_QUORUM..=FROZEN_COMMITTEE_SIZE).contains(&n) {
            return Err(RecordError::VoteCount { got: n });
        }
        let mut last: Option<usize> = None;
        for v in &self.votes {
            if v.signer >= FROZEN_COMMITTEE_SIZE {
                return Err(RecordError::SignerRange { signer: v.signer });
            }
            if last.is_some_and(|l| v.signer <= l) {
                return Err(RecordError::SignerOrder);
            }
            last = Some(v.signer);
        }
        if self.cp.root != self.cp.block_hash {
            return Err(RecordError::Root);
        }
        Ok(())
    }

    /// Rules 1–4 (module doc), after [`Self::structural`]. `prior` is
    /// `CR(parent)`: the height of the latest record in the parent's ancestry,
    /// if any. `ancestor_at(h)` is the hash of this block's ancestor at height
    /// `h` (`None` at or above its own height). `committee0` is the genesis
    /// committee, by genesis index.
    ///
    /// **This does not verify `ancestor_at`'s contract.** Rule 3 is only as
    /// good as the caller's ancestry lookup: it must answer from the chain
    /// this block extends (never the node's current tip) and return `None`
    /// at or above the block's own height.
    pub fn check(
        &self,
        prior: Option<u64>,
        ancestor_at: impl Fn(u64) -> Option<Hash32>,
        committee0: &Committee,
    ) -> Result<(), RecordError> {
        self.structural()?;
        let h = self.cp.height;
        if !is_checkpoint_height(h, CHECKPOINT_CADENCE_BLOCKS) {
            return Err(RecordError::NotCadence { height: h });
        }
        if let Some(p) = prior {
            if h <= p {
                return Err(RecordError::NotMonotone {
                    height: h,
                    prior: p,
                });
            }
        }
        if ancestor_at(h) != Some(self.cp.block_hash) {
            return Err(RecordError::NotAncestor { height: h });
        }
        // Rule 4: `structural` bounded the count to [QUORUM, N] and the
        // signers to distinct indices < N; every carried signature must verify.
        for v in &self.votes {
            if !committee0.verify_vote(&self.cp, v) {
                return Err(RecordError::BadSignature { signer: v.signer });
            }
        }
        Ok(())
    }
}

/// The recorded finality after a block: its own record's height if it carries
/// one, else the parent's.
///
/// Taking the own record's height unconditionally relies on **rule 2**
/// (monotone): only a record that passed [`FinalityRecord::check`] against
/// `prior` may be passed as `own`, so its height is strictly above `prior`
/// and recorded finality never moves backwards (review K4).
pub fn recorded_after(prior: Option<u64>, own: Option<&FinalityRecord>) -> Option<u64> {
    own.map(|r| r.cp.height).or(prior)
}

/// **The anchor rule** (module doc) for one height: a root that was the
/// commitment root after height `root_h` is a valid anchor in a block at
/// `block_h` whose recorded finality (its own record included) is `recorded`.
/// A root held at several heights is valid iff this holds for some one of
/// them — the newest under the ceiling is the only candidate worth testing
/// (`body::v6_anchor_ok`, review M4).
///
/// `root_h < block_h` is implied whenever the caller passes a finality its
/// rules produced (a record names an ancestor, so `recorded < block_h`); the
/// guard is kept so the function is correct on any input and the
/// subtraction below cannot underflow (review K4).
pub fn anchor_ok(root_h: u64, block_h: u64, recorded: Option<u64>) -> bool {
    recorded.is_some_and(|f| root_h <= f)
        && root_h < block_h
        && block_h - root_h <= MAX_ANCHOR_AGE_BLOCKS
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    use super::*;
    use crate::committee::{CommitteeState, Validator};

    fn seed(i: usize) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(b"f5-3-rec");
        s[8] = i as u8;
        s
    }

    pub(crate) struct Fx {
        pub(crate) committee: Committee,
        pub(crate) validators: Vec<Validator>,
        pub(crate) cp: Checkpoint,
    }

    /// Twenty-one rehearsal committee keys and one checkpoint (built once).
    pub(crate) fn fx() -> &'static Fx {
        static F: OnceLock<Fx> = OnceLock::new();
        F.get_or_init(|| {
            let validators: Vec<Validator> = (0..FROZEN_COMMITTEE_SIZE)
                .map(|i| Validator::from_seed(i, seed(i)))
                .collect();
            let committee =
                Committee::from_keys(validators.iter().map(Validator::verifying_key).collect());
            let hash = [0xab; 32];
            Fx {
                committee,
                validators,
                cp: Checkpoint::new(16, hash, hash),
            }
        })
    }

    pub(crate) fn record(signers: &[usize]) -> FinalityRecord {
        let f = fx();
        FinalityRecord {
            cp: f.cp,
            votes: signers
                .iter()
                .map(|&i| f.validators[i].sign_checkpoint(&f.cp))
                .collect(),
        }
    }

    pub(crate) fn quorum() -> Vec<usize> {
        (0..FROZEN_QUORUM).collect()
    }

    /// The chain the fixture checkpoint lives on: height 16 is `cp.block_hash`.
    fn chain(h: u64) -> Option<Hash32> {
        (h == 16).then_some([0xab; 32])
    }

    #[test]
    fn record_round_trips_at_the_pinned_size_and_checks() {
        // Size, computed (review K2): 72 checkpoint bytes, a 1-byte count, and
        // per vote a 1-byte signer, the 2-byte length varint and the signature.
        let size = |n: usize| 72 + 1 + n * (1 + 2 + SIG_LEN);
        let r = record(&quorum());
        let b = r.encode();
        assert_eq!(b.len(), size(15));
        assert_eq!(size(15), 49_753, "the figure the F5-3 plan quotes");
        let d = FinalityRecord::decode(&b).unwrap();
        assert_eq!(d.encode(), b);
        assert_eq!(d.check(None, chain, &fx().committee), Ok(()));
        assert_eq!(d.check(Some(8), chain, &fx().committee), Ok(()));
        let all = record(&(0..FROZEN_COMMITTEE_SIZE).collect::<Vec<_>>()).encode();
        assert_eq!(all.len(), size(21));
        assert!(FinalityRecord::decode(&all).is_ok());
    }

    #[test]
    fn record_decode_refuses_every_non_canonical_form() {
        let good = record(&quorum()).encode();
        let under = record(&(0..FROZEN_QUORUM - 1).collect::<Vec<_>>()).encode();
        assert_eq!(
            FinalityRecord::decode(&under).unwrap_err(),
            RecordError::VoteCount { got: 14 }
        );
        // Out of order / duplicate signers.
        let mut order = quorum();
        order.swap(3, 4);
        assert_eq!(
            FinalityRecord::decode(&record(&order).encode()).unwrap_err(),
            RecordError::SignerOrder
        );
        let mut dup = quorum();
        dup[5] = 4;
        assert_eq!(
            FinalityRecord::decode(&record(&dup).encode()).unwrap_err(),
            RecordError::SignerOrder
        );
        // root ≠ block_hash.
        let mut r = record(&quorum());
        r.cp.root = [0xcd; 32];
        assert_eq!(
            FinalityRecord::decode(&r.encode()).unwrap_err(),
            RecordError::Root
        );
        // Trailing byte; truncation.
        let mut t = good.clone();
        t.push(0);
        assert_eq!(
            FinalityRecord::decode(&t).unwrap_err(),
            RecordError::Malformed("trailing bytes")
        );
        assert!(matches!(
            FinalityRecord::decode(&good[..good.len() - 1]),
            Err(RecordError::Malformed(_))
        ));
        // A padded varint for the vote count (0x8f 0x00 means 15 too).
        let mut padded = good[..72].to_vec();
        padded.extend([0x8f, 0x00]);
        padded.extend_from_slice(&good[73..]);
        assert!(matches!(
            FinalityRecord::decode(&padded),
            Err(RecordError::Malformed(_))
        ));
        // A signature length other than 3309.
        let mut sl = good.clone();
        sl[74] = 0xec; // 3309 = 0xed 0x19 → 0xec 0x19 = 3308
        assert_eq!(
            FinalityRecord::decode(&sl).unwrap_err(),
            RecordError::SigLen { got: 3308 }
        );
        // A signer index ≥ 21.
        let mut sr = good.clone();
        sr[73 + 14 * 3312] = 21;
        assert_eq!(
            FinalityRecord::decode(&sr).unwrap_err(),
            RecordError::SignerRange { signer: 21 }
        );
    }

    /// Review K1: `check` stands on its own — a record built by hand, not
    /// decoded, with one member's signature repeated fifteen times would pass
    /// a "15 valid signatures" count; `structural` refuses it first.
    #[test]
    fn a_hand_built_record_repeating_one_signature_is_refused() {
        let f = fx();
        let one = f.validators[0].sign_checkpoint(&f.cp);
        let rec = FinalityRecord { cp: f.cp, votes: (0..FROZEN_QUORUM).map(|_| one.clone()).collect() };
        assert_eq!(rec.check(None, chain, &f.committee), Err(RecordError::SignerOrder));
        let mut high = record(&quorum());
        high.votes[14].signer = FROZEN_COMMITTEE_SIZE;
        assert_eq!(high.check(None, chain, &f.committee), Err(RecordError::SignerRange { signer: 21 }));
        let mut root = record(&quorum());
        root.cp.root = [0xcd; 32];
        assert_eq!(root.check(None, chain, &f.committee), Err(RecordError::Root));
        let big = FinalityRecord { cp: f.cp, votes: (0..22).map(|i| f.validators[i % 21].sign_checkpoint(&f.cp)).collect() };
        assert_eq!(big.check(None, chain, &f.committee), Err(RecordError::VoteCount { got: 22 }));
    }

    /// Review K3: more than 21 votes, a signature length above 3309, and the
    /// re-encode guard.
    #[test]
    fn record_decode_refuses_more_votes_and_longer_signatures() {
        let f = fx();
        let mut votes: Vec<Vote> = (0..FROZEN_COMMITTEE_SIZE).map(|i| f.validators[i].sign_checkpoint(&f.cp)).collect();
        votes.push(Vote { signer: 21, signature: votes[0].signature.clone() });
        let over = FinalityRecord { cp: f.cp, votes }.encode();
        assert_eq!(FinalityRecord::decode(&over).unwrap_err(), RecordError::VoteCount { got: 22 });
        // The first vote's length varint 3309 = 0xed 0x19 → 3310 = 0xee 0x19,
        // with one extra byte so the declared length is present.
        let good = record(&quorum()).encode();
        let mut long = good[..74].to_vec();
        long.extend([0xee, 0x19]);
        long.extend_from_slice(&good[76..76 + SIG_LEN]);
        long.push(0);
        long.extend_from_slice(&good[76 + SIG_LEN..]);
        assert_eq!(FinalityRecord::decode(&long).unwrap_err(), RecordError::SigLen { got: 3310 });
    }

    /// Review K3, `NotCanonical`: the guard is re-encode-and-compare, and no
    /// decodable non-canonical input is known (ML-DSA's decoder refuses
    /// malformed hints, the varints are canonical-only). So the guarantee is
    /// stated as a property instead: across a sweep of single-byte mutations
    /// of a valid record, every mutation either fails to decode or decodes to
    /// a record whose encoding is exactly the mutated bytes. A decoder that
    /// silently normalised would fail here.
    #[test]
    fn every_decodable_mutation_re_encodes_to_itself() {
        let good = record(&quorum()).encode();
        let mut decoded = 0;
        for pos in (0..good.len()).step_by(97).chain(76..76 + 64) {
            for delta in [0x01u8, 0x80] {
                let mut m = good.clone();
                m[pos] ^= delta;
                if let Ok(r) = FinalityRecord::decode(&m) {
                    decoded += 1;
                    assert_eq!(r.encode(), m, "byte {pos} ^ {delta:#x} decoded to a different encoding");
                }
            }
        }
        assert!(decoded > 0, "the sweep must reach bytes the decoder accepts (signature bodies)");
    }

    #[test]
    fn record_check_refuses_each_rule() {
        let c = &fx().committee;
        let r = record(&quorum());
        // Rule 1: cadence.
        let mut nc = r.clone();
        nc.cp = Checkpoint::new(12, [0xab; 32], [0xab; 32]);
        assert_eq!(
            nc.check(None, |_| Some([0xab; 32]), c),
            Err(RecordError::NotCadence { height: 12 })
        );
        // Rule 2: monotone.
        assert_eq!(
            r.check(Some(16), chain, c),
            Err(RecordError::NotMonotone {
                height: 16,
                prior: 16
            })
        );
        assert_eq!(
            r.check(Some(24), chain, c),
            Err(RecordError::NotMonotone {
                height: 16,
                prior: 24
            })
        );
        // Rule 3: ancestor.
        assert_eq!(
            r.check(None, |_| Some([0x11; 32]), c),
            Err(RecordError::NotAncestor { height: 16 })
        );
        assert_eq!(
            r.check(None, |_| None, c),
            Err(RecordError::NotAncestor { height: 16 })
        );
        // Rule 4: a forged signature (member 3's slot carries member 20's).
        let mut forged = r.clone();
        forged.votes[3].signature = fx().validators[20].sign_checkpoint(&fx().cp).signature;
        assert_eq!(
            forged.check(None, chain, c),
            Err(RecordError::BadSignature { signer: 3 })
        );
        // A signature over a different checkpoint.
        let mut other = r.clone();
        let cp2 = Checkpoint::new(24, [0xab; 32], [0xab; 32]);
        other.votes[0] = fx().validators[0].sign_checkpoint(&cp2);
        assert_eq!(
            other.check(None, chain, c),
            Err(RecordError::BadSignature { signer: 0 })
        );
    }

    /// Ruling Q1's premise, pinned: a member this node has jailed (or even
    /// tombstoned) locally still signs a valid record — records verify against
    /// committee₀ with local status not applied.
    #[test]
    fn a_locally_jailed_members_signature_still_counts_in_a_record() {
        let mut st = CommitteeState::new(fx().committee.clone(), 1);
        assert!(st.jail(2, 1_000));
        assert!(st.tombstone(7, 0));
        assert!(
            !st.is_active(2, 16) && !st.is_active(7, 16),
            "locally inactive"
        );
        let r = record(&quorum());
        assert!(r.votes.iter().any(|v| v.signer == 2) && r.votes.iter().any(|v| v.signer == 7));
        assert_eq!(r.check(None, chain, st.committee()), Ok(()));
    }

    #[test]
    fn anchor_rule_reads_the_record_and_the_blocks_own_height() {
        // No record in the ancestry: no anchor.
        assert!(!anchor_ok(8, 20, None));
        // At or below the recorded height, within the window from the block.
        assert!(anchor_ok(16, 20, Some(16)));
        assert!(anchor_ok(1, 1 + MAX_ANCHOR_AGE_BLOCKS, Some(16)));
        assert!(
            !anchor_ok(1, 2 + MAX_ANCHOR_AGE_BLOCKS, Some(16)),
            "aged out, measured from the block"
        );
        // Above the recorded finality: not yet an anchor.
        assert!(!anchor_ok(17, 20, Some(16)));
        // Never at or above the block itself.
        assert!(!anchor_ok(20, 20, Some(24)));
        // The recorded finality carries forward and a block's own record counts.
        assert_eq!(recorded_after(Some(8), None), Some(8));
        let r = record(&quorum());
        assert_eq!(recorded_after(Some(8), Some(&r)), Some(16));
    }
}
