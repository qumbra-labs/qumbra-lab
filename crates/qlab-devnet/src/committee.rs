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
//! This module owns the committee *keys, status, and vote crypto*. Membership
//! *changes* — admission / exit / forced removal at epoch boundaries
//! (committee-governance §2) — live in [`crate::epoch`] (M9-N5), which wraps a
//! [`CommitteeState`] per epoch. Equivocation/jail penalties (§3) live in
//! [`crate::ebbflow`]. Within an epoch, per-member status (jail/tombstone) applies
//! immediately for quorum; the roster only shrinks at the next boundary.

use ml_dsa::{B32, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::header::Hash32;

/// A committee member's ML-DSA-65 public (verifying) key.
pub type MemberKey = VerifyingKey<MlDsa65>;
/// An ML-DSA-65 signature over a checkpoint.
pub type MemberSig = Signature<MlDsa65>;

/// Domain-separation prefix bound into every checkpoint signing message, so a
/// committee signature can never be replayed as any other ML-DSA message.
///
/// **Production domain string** (M9-N5): `b"qumbra:checkpoint:v1"` — the
/// `devnet:` segment is dropped. protocol-spec §7 carried the devnet placeholder
/// `b"qumbra:devnet:checkpoint:v1"` with the production string flagged
/// `[full-M8: production domain string + checkpoint cadence]`; N5 promotes the
/// production form (committee-over-network is the section that binds it). The
/// design-repo §7 correction is owed. Domain change ⇒ every pre-N5 vote/checkpoint
/// signature is deliberately non-verifiable against a post-N5 committee (versioned
/// break, §0 discipline).
pub const CHECKPOINT_DOMAIN: &[u8] = b"qumbra:checkpoint:v1";

/// How many leading digest bytes make up a printed checkpoint **identity**
/// (issue #84). Six — 48 bits — chosen for a reason that is not collision
/// resistance:
///
/// * **Collision is a non-argument here.** The identity separates the handful of
///   checkpoint variants that can exist at one height on one net. Even counting
///   every checkpoint a devnet produces in a year (~5×10⁴ at an 8-block cadence),
///   the birthday probability of *any* accidental pair matching at 48 bits is
///   ~10⁻⁵, and of two variants at the *same height* matching, ~10⁻¹⁴. Thirty-two
///   bits would also have sufficed.
/// * **48 bits is the widest prefix that survives a Prometheus round trip.**
///   Exposition values are float64, whose mantissa is 53 bits, so a 48-bit integer
///   is carried *exactly* by a scrape while a 64-bit one is silently rounded. That
///   makes [`Checkpoint::id_hex`] and the `qumbra_*_checkpoint_id` gauges two
///   spellings of one number: `printf '%012x'` converts the gauge into the log
///   field. A wider identity would have broken that correspondence, and an
///   operator who cannot line up the log with the scrape has two instruments that
///   disagree for no reason.
///
/// **Devnet-grade, tunable, NOT frozen** — nothing in consensus reads it. It is a
/// display width for an observability field, and widening it changes only what a
/// log line prints (and would cost the float64 correspondence above).
pub const CHECKPOINT_ID_BYTES: usize = 6;

/// The printed form of "no checkpoint" — the same sentinel the `TELEMETRY` line
/// already uses for `final=`, `age_s=` and `halt=`. **Absence is printed, never
/// omitted**: a positional `key=value` line whose keys come and go forces every
/// parser to special-case it, and that special case is what gets skipped.
pub const CHECKPOINT_ID_ABSENT: &str = "-";

/// Render a [`Checkpoint::identity`] value as the canonical zero-padded lowercase
/// hex field, or [`CHECKPOINT_ID_ABSENT`] for `None`.
pub fn checkpoint_id_hex(id: Option<u64>) -> String {
    match id {
        Some(v) => format!("{v:0width$x}", width = CHECKPOINT_ID_BYTES * 2),
        None => CHECKPOINT_ID_ABSENT.to_string(),
    }
}

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

    /// The ordered member key list (used by the epoch machinery to reseal a roster
    /// at a boundary — see [`crate::epoch`]).
    pub fn keys(&self) -> &[MemberKey] {
        &self.members
    }

    /// Verify that `vote` is a valid signature by its claimed signer over `cp`.
    /// `false` if the signer index is out of range or the signature is invalid.
    pub fn verify_vote(&self, cp: &Checkpoint, vote: &Vote) -> bool {
        match self.members.get(vote.signer) {
            Some(key) => key.verify(&cp.signing_message(), &vote.signature).is_ok(),
            None => false,
        }
    }

    /// Whether `vote.signature` is a valid checkpoint signature by **any** member of
    /// this committee, ignoring the claimed `vote.signer` index.
    ///
    /// Issue #164: after an epoch-boundary reseal two honest nodes can disagree about
    /// which key sits at index `i`. Each then sees the other's correct vote fail
    /// [`Self::verify_vote`] at the claimed index, while the signature still belongs
    /// to a key on their own roster — just at a different slot. That case is
    /// roster-positional, not a forgery.
    pub fn any_member_signed(&self, cp: &Checkpoint, vote: &Vote) -> bool {
        let msg = cp.signing_message();
        self.members.iter().any(|k| k.verify(&msg, &vote.signature).is_ok())
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

    /// **The checkpoint's identity** (issue #84): the first [`CHECKPOINT_ID_BYTES`]
    /// bytes of `keccak256(signing_message())`, big-endian, as an integer.
    ///
    /// It is taken over [`Self::signing_message`] and *not* over the struct fields,
    /// which is the whole point: the signing message is the exact byte string the
    /// committee's ML-DSA keys commit to, so two nodes reporting the same identity
    /// have provably been asked to sign the same thing. Hashing the fields
    /// separately would create a second serialization of `(height, block_hash,
    /// root)` that could drift from the signed one — and a divergence between the
    /// two encodings would present as "the identities match" while the signatures
    /// were over different bytes, i.e. exactly the failure this field exists to
    /// make visible, made invisible again.
    ///
    /// The hash is [`crate::hash::keccak256`], the consensus hash (performance-
    /// budget §2), cross-checked against an independent implementation there. No
    /// new primitive and no second encoding are introduced by this field.
    ///
    /// This is **observability only**. Nothing in consensus reads it: the quorum
    /// rule, `try_finalize` and vote verification all continue to work on the
    /// signing message itself.
    pub fn identity(&self) -> u64 {
        let d = crate::hash::keccak256(&self.signing_message());
        d[..CHECKPOINT_ID_BYTES].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
    }

    /// [`Self::identity`] as the canonical 12-char lowercase hex log field.
    pub fn id_hex(&self) -> String {
        checkpoint_id_hex(Some(self.identity()))
    }
}

/// A single committee member's signed vote for a checkpoint.
#[derive(Clone)]
pub struct Vote {
    /// The signer's committee index.
    pub signer: usize,
    /// The signer's ML-DSA-65 signature over the checkpoint's signing message.
    pub signature: MemberSig,
}

/// A committee member's operational status. Membership is fixed within an epoch
/// (committee-governance §2); status changes here model the §3 penalties within
/// the devnet. (Real membership set changes only at epoch boundaries; the devnet
/// applies status immediately for simplicity — noted in the plan doc.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Signing normally.
    Active,
    /// Jailed for downtime until `until_height` (NO slash); auto-readmitted after.
    Jailed { until_height: u64 },
    /// Permanently removed for equivocation (tombstone). Never re-admitted.
    Tombstoned,
}

/// The committee's mutable operational state: the (fixed) key set plus per-member
/// status, self-bond, and cumulative slash (committee-governance §3). Placeholder
/// bond/slash amounts live in `params_devnet`.
#[derive(Clone)]
pub struct CommitteeState {
    committee: Committee,
    status: Vec<MemberStatus>,
    bond: Vec<u64>,
    slashed: Vec<u64>,
}

impl CommitteeState {
    /// All members Active, each with an equal placeholder self-bond `bond_each`.
    pub fn new(committee: Committee, bond_each: u64) -> Self {
        let n = committee.size();
        Self {
            status: vec![MemberStatus::Active; n],
            bond: vec![bond_each; n],
            slashed: vec![0; n],
            committee,
        }
    }

    /// Reassemble a committee state from explicit per-member parts. Used by the
    /// epoch machinery ([`crate::epoch`]) to seal the next epoch's roster at a
    /// boundary, carrying surviving members' status/bond/slash forward exactly.
    /// Panics if the parts' lengths disagree with the committee size.
    pub fn from_parts(
        committee: Committee,
        status: Vec<MemberStatus>,
        bond: Vec<u64>,
        slashed: Vec<u64>,
    ) -> Self {
        let n = committee.size();
        assert!(
            status.len() == n && bond.len() == n && slashed.len() == n,
            "CommitteeState::from_parts length mismatch (n={n})"
        );
        Self { committee, status, bond, slashed }
    }

    /// The underlying (fixed) key set.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// N (total membership; quorum is over N — membership is fixed within an epoch).
    pub fn size(&self) -> usize {
        self.committee.size()
    }

    /// The ⅔-quorum threshold over the full membership N.
    pub fn quorum_threshold(&self) -> usize {
        self.committee.quorum_threshold()
    }

    /// Status of member `idx`, if in range.
    pub fn status(&self, idx: usize) -> Option<MemberStatus> {
        self.status.get(idx).copied()
    }

    /// Remaining self-bond of member `idx`, if in range.
    pub fn bond(&self, idx: usize) -> Option<u64> {
        self.bond.get(idx).copied()
    }

    /// Cumulative amount slashed from member `idx`, if in range.
    pub fn slashed(&self, idx: usize) -> Option<u64> {
        self.slashed.get(idx).copied()
    }

    /// Whether member `idx` may sign at `height`: Active, or Jailed whose term has
    /// elapsed (`height >= until_height`). Tombstoned is never active.
    pub fn is_active(&self, idx: usize, height: u64) -> bool {
        match self.status.get(idx) {
            Some(MemberStatus::Active) => true,
            Some(MemberStatus::Jailed { until_height }) => height >= *until_height,
            _ => false,
        }
    }

    /// Count of members that may sign at `height`.
    pub fn active_count(&self, height: u64) -> usize {
        (0..self.size()).filter(|&i| self.is_active(i, height)).count()
    }

    /// Tombstone member `idx` for equivocation: permanent removal + slash `amount`
    /// from its bond (committee-governance §3). Idempotent; returns `true` if this
    /// call newly tombstoned the member.
    pub fn tombstone(&mut self, idx: usize, amount: u64) -> bool {
        if idx >= self.size() || self.status[idx] == MemberStatus::Tombstoned {
            return false;
        }
        let slash = amount.min(self.bond[idx]);
        self.bond[idx] -= slash;
        self.slashed[idx] += slash;
        self.status[idx] = MemberStatus::Tombstoned;
        true
    }

    /// Jail member `idx` for downtime until `until_height` — **no slash**
    /// (committee-governance §3). A tombstoned member cannot be jailed. Returns
    /// `true` if applied.
    pub fn jail(&mut self, idx: usize, until_height: u64) -> bool {
        if idx >= self.size() || self.status[idx] == MemberStatus::Tombstoned {
            return false;
        }
        self.status[idx] = MemberStatus::Jailed { until_height };
        true
    }
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
    fn checkpoint_domain_is_production_string() {
        // N5 promoted the domain to its production form; the `devnet:` segment is
        // gone. Golden-lock the exact bytes so any future drift is a deliberate,
        // versioned wire break (§0 discipline) — a silent change would invalidate
        // every committee signature on the network.
        assert_eq!(CHECKPOINT_DOMAIN, b"qumbra:checkpoint:v1");
        assert!(!CHECKPOINT_DOMAIN.windows(7).any(|w| w == b"devnet:"));
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

    // ---- issue #84: the checkpoint's identity --------------------------------

    /// **The identity is a function of the signed bytes and nothing else.**
    /// Recomputed here from `keccak256(signing_message())` by hand, so a future
    /// refactor that quietly starts hashing the struct fields (or a different
    /// digest) fails rather than producing a plausible number.
    #[test]
    fn identity_is_the_digest_prefix_of_the_signing_message() {
        let cp = sample_checkpoint();
        let d = crate::hash::keccak256(&cp.signing_message());
        let expect =
            d[..CHECKPOINT_ID_BYTES].iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        assert_eq!(cp.identity(), expect);
        // …and the printed field is that integer, zero-padded, nothing else.
        assert_eq!(cp.id_hex(), format!("{expect:012x}"));
    }

    /// **The acceptance property, at the level of the value itself**: equal
    /// checkpoints are byte-identical identities, and a change in *any* of the
    /// three signed fields moves it. `block_hash` is the one that matters — two
    /// nodes finalizing different blocks at the same height is the split.
    #[test]
    fn identity_separates_variants_and_agrees_on_equals() {
        let cp = Checkpoint::new(3776, [0x11; 32], [0x22; 32]);
        // Same (height, block_hash, root) built independently ⇒ same identity.
        assert_eq!(cp.identity(), Checkpoint::new(3776, [0x11; 32], [0x22; 32]).identity());
        assert_eq!(cp.id_hex(), Checkpoint::new(3776, [0x11; 32], [0x22; 32]).id_hex());
        // The 3776-shaped case: same height, different block ⇒ different identity.
        assert_ne!(cp.identity(), Checkpoint::new(3776, [0x33; 32], [0x22; 32]).identity());
        // And the other two fields bind too.
        assert_ne!(cp.identity(), Checkpoint::new(3777, [0x11; 32], [0x22; 32]).identity());
        assert_ne!(cp.identity(), Checkpoint::new(3776, [0x11; 32], [0x44; 32]).identity());
    }

    /// The printed field is **fixed-width lowercase hex or the `-` sentinel** — a
    /// parser may rely on exactly those two shapes. The zero-padding case is the
    /// one that silently breaks a fixed-width reader if `{:x}` is ever used raw.
    #[test]
    fn id_hex_is_fixed_width_or_the_absent_sentinel() {
        for id in [0u64, 1, 0xff, 0x0000_4cc8_904e, (1u64 << 48) - 1] {
            let s = checkpoint_id_hex(Some(id));
            assert_eq!(s.len(), CHECKPOINT_ID_BYTES * 2, "fixed width: {s}");
            assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{s}");
            assert_eq!(u64::from_str_radix(&s, 16).unwrap(), id, "round-trips: {s}");
        }
        assert_eq!(checkpoint_id_hex(None), CHECKPOINT_ID_ABSENT);
        assert_eq!(CHECKPOINT_ID_ABSENT, "-", "same sentinel as final=/age_s=/halt=");
    }

    /// The identity fits in 48 bits, which is what makes it survive a Prometheus
    /// float64 exposition value unrounded — the property that lets the log field
    /// and the `/metrics` gauge be the same number in two spellings.
    #[test]
    fn identity_is_exact_in_a_float64_exposition_value() {
        assert!(CHECKPOINT_ID_BYTES * 8 <= 53, "float64 mantissa is 53 bits");
        for h in 0u64..64 {
            let id = Checkpoint::new(h, [h as u8; 32], [0x22; 32]).identity();
            assert!(id < (1u64 << (CHECKPOINT_ID_BYTES * 8)));
            // The scrape round trip: u64 → f64 → u64 must be lossless.
            assert_eq!(id as f64 as u64, id, "gauge value must not round");
        }
    }
}
