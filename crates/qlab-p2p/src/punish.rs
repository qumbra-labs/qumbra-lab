//! **Durable committee punishments** (issue #133) — the on-disk ledger of
//! equivocation evidence a node has adjudicated, and the restart replay that puts
//! its tombstones back.
//!
//! ## The defect this closes, and the one it does NOT
//!
//! `qumbra-node` rebuilds its committee from genesis on every startup, and
//! `CommitteeState`'s `status` / `bond` / `slashed` had no persisted form even in
//! principle. So a member that had been **proven** to equivocate — tombstoned,
//! permanently, under FROZEN §4 — came back **Active with a full bond** on the next
//! restart, and its votes counted toward quorum again on that node and no other. The
//! ledger here makes the punishment durable.
//!
//! **It does not make committee views agree, and nothing in this module should be
//! read as claiming it does.** Evidence is push-once gossip with no inventory kind
//! and no getdata path, and it is not in blocks (`StoredBlock` is header / txs /
//! coinbase / coinbase_rkm), so a replay cannot re-derive a punishment and a node
//! that was offline when the conflicting pair was observed never learns of it at
//! all. Two nodes that saw different evidence still disagree about who may sign —
//! and after this change they disagree *durably*. Agreement needs the evidence on
//! chain, which is a payload change and a separate decision.
//!
//! ## What is persisted: the evidence, not the verdict
//!
//! Each record is an [`EquivocationEvidence`] — the two conflicting checkpoints and
//! the two ML-DSA-65 signatures. Persisting the *derived status* would have been
//! smaller (a few bytes per member), and it was rejected:
//!
//! * **A verdict cannot be checked; evidence can.** This is a node-local file with
//!   no consensus behind it. A status-only ledger means any byte that reaches this
//!   file is believed: an operator, a bug, or a stray write can tombstone an honest
//!   member with a full bond, and the node will exclude it from quorum forever with
//!   nothing to appeal to. An evidence ledger is re-adjudicated on every load by the
//!   same two signature checks the live path runs ([`verify_equivocation`]), so a
//!   record that is not a real equivocation by a real member cannot survive the
//!   load, let alone take effect.
//! * **The bond and slash are re-derived, not restored.** Replay runs the same
//!   frozen rule ([`equivocation_slash`]) against the same starting bond, so
//!   `(status, bond, slashed)` comes back identical without three numbers on disk
//!   that could disagree with each other or with the rule.
//! * **The cost is bounded and small.** One record is ~6.8 KB (2 × 72 B checkpoint
//!   + 2 × 3,309 B signature), and a member can be tombstoned once, so the ledger is
//!   bounded by the roster: ~142 KB at N=21.
//!
//! ## Where it lives, and why not in `persist.rs`
//!
//! A **separate versioned file**, `punishments.dat`, alongside `peers.dat` and
//! `finalizer-*.state` — not a `LogRecord` variant and not a `Snapshot` field:
//!
//! * **`Snapshot` is wrong because it is allowed to vanish.** `load_snapshot`
//!   returns `Ok(None)` for a missing, torn, or version-mismatched snapshot and the
//!   caller rebuilds from the log — correct for *derived* state, catastrophic for
//!   state that cannot be re-derived. A punishment carried on the snapshot would be
//!   silently dropped by exactly the fallback #133 is a complaint about. It is also
//!   only written on graceful shutdown, so a crash would lose it.
//! * **`LogRecord` is wrong because the log is the block chain's own history.** Its
//!   records are replayed into `Node::apply_state`, which knows nothing about
//!   committees, and a punishment is not an event on the chain — putting it there
//!   would assert exactly the on-chain status this change explicitly does not have.
//! * **A separate file is the shape the repo already uses for this exact problem**:
//!   node-local, non-derivable, safety-load-bearing, versioned, reject-unknown, and
//!   refusing rather than falling through when it cannot be honoured.
//!
//! The record body is [`crate::codec::encode_evidence_msg`] **verbatim** — the same
//! bytes the `Evidence` gossip message carries. This is a reuse, not a second
//! encoding: two serializations of one object is how they drift.
//!
//! ## Failure posture: refuse, never start fresh
//!
//! Every way this file can be unusable ends in a refusal to open, because the
//! alternative is the fallback that restores a proven misbehaver to good standing:
//!
//! | condition | result |
//! |---|---|
//! | file absent, fresh data dir | zero punishments, reported |
//! | file absent, data dir already holds chain history | zero punishments, **reported loudly** — a pre-#133 datadir cannot be known to be clean |
//! | unknown format version | **refuse to open** |
//! | truncated / trailing bytes / undecodable record | **refuse to open** |
//! | a record that does not verify against this node's committee | **refuse to open** |

use std::io;
use std::path::{Path, PathBuf};

use qlab_devnet::ebbflow::{equivocation_slash, verify_equivocation, EquivocationEvidence, EvidenceError};
use qlab_devnet::epoch::EpochCommittee;

use crate::codec::{decode_evidence_msg, encode_evidence_msg, DecodeError};
use crate::varint::{read_varint, write_varint};

/// On-disk format version for the punishment ledger. Independent of the P2P
/// protocol version and of `qlab_node::FORMAT_VERSION` — this is a node-local
/// durability artifact. **Reject-unknown** on load (§0 discipline).
pub const PUNISHMENT_FORMAT_VERSION: u8 = 1;

/// The punishment ledger's file name, under the node's data dir.
pub const PUNISHMENT_FILE: &str = "punishments.dat";

/// The temp name the ledger is written to before the atomic rename.
const PUNISHMENT_TMP: &str = "punishments.dat.tmp";

/// Hard entry cap on a loaded ledger. A member can be tombstoned once and rosters
/// are N≈21, so any file claiming more records than this is malformed rather than
/// large — and the count varint is read before any allocation, so the cap has to
/// exist for the count to be safe to trust.
pub const MAX_PUNISHMENT_RECORDS: u64 = 1_024;

/// Why a punishment ledger could not be honoured. Every variant is a **refusal to
/// open**, never a fall-through to an empty ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// A format version this binary does not implement (reject-unknown).
    BadVersion { got: u8 },
    /// Ran out of bytes while reading `what`.
    Truncated { what: &'static str },
    /// Bytes remained after the last record (reject-trailing).
    Trailing { remaining: usize },
    /// The record count varint was malformed or absurd.
    BadCount { got: u64 },
    /// Record `index` did not decode.
    Record { index: usize, err: DecodeError },
    /// Record `index` decoded but is **not a valid equivocation** by a member of
    /// this node's committee — a corrupted ledger, or a data dir carried across a
    /// genesis/committee change. Either way the punishments in it are unusable and
    /// starting without them would silently restore a possibly-guilty member.
    Unverified { index: usize, err: EvidenceError },
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LedgerError::BadVersion { got } => write!(
                f,
                "{PUNISHMENT_FILE}: format version {got} is not version \
                 {PUNISHMENT_FORMAT_VERSION}, which this binary implements"
            ),
            LedgerError::Truncated { what } => {
                write!(f, "{PUNISHMENT_FILE}: truncated while reading {what}")
            }
            LedgerError::Trailing { remaining } => {
                write!(f, "{PUNISHMENT_FILE}: {remaining} trailing byte(s) after the last record")
            }
            LedgerError::BadCount { got } => write!(
                f,
                "{PUNISHMENT_FILE}: record count {got} exceeds the {MAX_PUNISHMENT_RECORDS} cap"
            ),
            LedgerError::Record { index, err } => {
                write!(f, "{PUNISHMENT_FILE}: record {index} does not decode ({err})")
            }
            LedgerError::Unverified { index, err } => write!(
                f,
                "{PUNISHMENT_FILE}: record {index} is not a verified equivocation by a member of \
                 this node's committee ({err:?})"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

impl LedgerError {
    /// The refusal as the `InvalidData` I/O error the open path returns, carrying the
    /// operator instruction. Matches `qlab_node::persist::read_records`' posture for
    /// an unusable block log: name the file, name the version, say what to do.
    pub fn to_io(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{self}. This committee-punishment ledger cannot be honoured, and starting \
                 without it would restore a possibly-tombstoned member to Active with a full \
                 bond. Re-sync this data dir; do not start against it."
            ),
        )
    }
}

/// Path of the punishment ledger under `dir`.
pub fn path(dir: &Path) -> PathBuf {
    dir.join(PUNISHMENT_FILE)
}

/// Encode a ledger: `version(1) ‖ n(varint) ‖ [len(varint) ‖ evidence(len)]×n`.
///
/// The record body is [`encode_evidence_msg`] byte-for-byte — the `Evidence` gossip
/// body — so there is exactly one serialization of an equivocation in the tree. The
/// per-record length prefix is what makes the list walkable without the reader
/// needing to know a signature's length.
pub fn encode(records: &[EquivocationEvidence]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(PUNISHMENT_FORMAT_VERSION);
    write_varint(&mut out, records.len() as u64);
    for ev in records {
        let body = encode_evidence_msg(ev);
        write_varint(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
    }
    out
}

/// Decode a ledger, rejecting an unknown version, an absurd count, an undecodable
/// record, and trailing bytes. **Signature verification is not done here** — it
/// needs the roster that owned each record's height, so it happens in [`replay`].
pub fn decode(bytes: &[u8]) -> Result<Vec<EquivocationEvidence>, LedgerError> {
    let mut pos = 0usize;
    let v = *bytes.get(pos).ok_or(LedgerError::Truncated { what: "version" })?;
    pos += 1;
    if v != PUNISHMENT_FORMAT_VERSION {
        return Err(LedgerError::BadVersion { got: v });
    }
    let n = read_varint(bytes, &mut pos).map_err(|_| LedgerError::Truncated { what: "count" })?;
    if n > MAX_PUNISHMENT_RECORDS {
        return Err(LedgerError::BadCount { got: n });
    }
    let mut out = Vec::with_capacity(n as usize);
    for index in 0..n as usize {
        let len = read_varint(bytes, &mut pos)
            .map_err(|_| LedgerError::Truncated { what: "record length" })?
            as usize;
        let end = pos.checked_add(len).ok_or(LedgerError::Truncated { what: "record" })?;
        let body = bytes.get(pos..end).ok_or(LedgerError::Truncated { what: "record" })?;
        pos = end;
        out.push(decode_evidence_msg(body).map_err(|err| LedgerError::Record { index, err })?);
    }
    if pos != bytes.len() {
        return Err(LedgerError::Trailing { remaining: bytes.len() - pos });
    }
    Ok(out)
}

/// Atomically persist the ledger: temp file → fsync → rename over the live file.
///
/// The whole ledger is rewritten rather than appended to, deliberately. An append
/// can tear, and tolerating a torn trailing record is precisely the tolerance that
/// let a whole populated block log read as empty before issue #101 narrowed it. At
/// ~6.8 KB per record and ≤ N records there is nothing to gain by appending, and a
/// rename is atomic on the same filesystem, so a crash at any point leaves either
/// the previous ledger or the new one and never a partial third thing.
pub fn save(dir: &Path, records: &[EquivocationEvidence]) -> io::Result<()> {
    use std::io::Write;
    let bytes = encode(records);
    let tmp = dir.join(PUNISHMENT_TMP);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path(dir))
}

/// Load the ledger at `dir`. A **missing** file is an empty ledger (`Ok(None)`);
/// every other problem is a [`LedgerError`] and the caller must refuse to open.
///
/// `None` vs `Some(vec![])` is the distinction the caller reports on: an absent file
/// on a data dir that already holds chain history is a pre-#133 data dir, whose
/// punishment history is unknowable rather than known-empty.
pub fn load(dir: &Path) -> Result<Option<Vec<EquivocationEvidence>>, io::Error> {
    let p = path(dir);
    if !p.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&p)?;
    decode(&bytes).map(Some).map_err(|e| e.to_io())
}

/// What a restart found in the ledger and what it did with it (issue #133's
/// "a counter, whichever way it goes").
///
/// **Every field is reported even when it is zero.** The silence after a restart is
/// what made this class of defect invisible five times over: a node that restored
/// nothing and a node that had nothing to restore printed the same thing, which was
/// nothing at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PunishmentRestore {
    /// How many records the ledger held.
    pub records: usize,
    /// Committee indices this restart newly tombstoned, in replay order.
    pub tombstoned: Vec<usize>,
    /// The data dir already held chain history but carried **no** ledger — i.e. it
    /// was written by a binary predating this change, so whether a punishment was
    /// ever applied against it is unknowable. Not an error, but not silence either.
    pub ledger_absent_on_populated_datadir: bool,
}

impl PunishmentRestore {
    /// The one-line operator form. Printed unconditionally, zero included.
    pub fn summary_line(&self) -> String {
        let who = if self.tombstoned.is_empty() {
            "-".to_string()
        } else {
            self.tombstoned.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
        };
        format!(
            "committee punishments: {} record(s) on disk, {} tombstone(s) restored (members {who})",
            self.records,
            self.tombstoned.len()
        )
    }
}

/// Re-adjudicate `records` against `ec` and re-apply their tombstones, returning the
/// indices newly tombstoned.
///
/// ## Why the epoch machinery is advanced record by record
///
/// A punishment names a member by its **index into the roster that owned the
/// checkpoint's height**, and `qlab_devnet::epoch` reindexes at every boundary — a
/// tombstoned member is dropped from the roster at the next boundary (forced exit,
/// §2), which shifts every higher index down by one. So replaying every record
/// against the genesis roster and *then* advancing to the tip would apply the right
/// punishment to the wrong member as soon as one boundary had been crossed.
///
/// Instead each record advances the machinery to its own slot first, so the roster
/// it is applied to is the roster that was live when the live node applied it. That
/// reproduces the live path exactly, including its accepted prototype boundary
/// (`apply_evidence` verifies against `state_for_height` and punishes the *current*
/// roster at the same index, which is sound because cadence 8 ≪ epoch length 1,152
/// means an equivocator is a current member).
///
/// Two consequences worth naming:
///
/// * **Records are replayed in ascending height.** `advance_to` is monotone, so an
///   out-of-order record could not seal backwards; the caller sorts.
/// * **Advancement is clamped to `tip`.** A checkpoint may be up to a cadence above
///   this node's tip, and letting a punishment push the epoch machinery past the
///   chain would leave the node in an epoch its own tip has not reached.
///
/// Double-application is impossible: `CommitteeState::tombstone` is idempotent and
/// returns `false` for a member already tombstoned, so a duplicated record neither
/// slashes twice nor is counted twice here.
pub fn replay(
    ec: &mut EpochCommittee,
    records: &[EquivocationEvidence],
    tip: u64,
) -> Result<Vec<usize>, LedgerError> {
    let mut tombstoned = Vec::new();
    for (index, ev) in records.iter().enumerate() {
        ec.advance_to(ev.cp_a.height.min(tip));
        let signer = {
            let committee = ec.state_for_height(ev.cp_a.height).committee();
            verify_equivocation(ev, committee)
        }
        .map_err(|err| LedgerError::Unverified { index, err })?;
        // Re-DERIVED, not restored: the same frozen rule against the same starting
        // bond, so `(status, bond, slashed)` comes back identical to the live path's
        // without the ledger carrying three numbers that could contradict it.
        let slash = equivocation_slash(ec.state().bond(signer).unwrap_or(0));
        if ec.state_mut().tombstone(signer, slash) {
            tombstoned.push(signer);
        }
    }
    Ok(tombstoned)
}

/// Sort key for a deterministic replay order: ascending slot, then signer.
pub fn sort_records(records: &mut [EquivocationEvidence]) {
    records.sort_by_key(|ev| (ev.cp_a.height, ev.vote_a.signer));
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::committee::{devnet_committee, Checkpoint, CommitteeState, MemberStatus};
    use qlab_devnet::epoch::EpochSchedule;
    use qlab_devnet::params_devnet::BOND_AMOUNT;

    /// Conflicting evidence at `slot` from `signer`, signed by the real key so it
    /// verifies against the committee `devnet_committee` returns.
    fn evidence(
        validators: &[qlab_devnet::committee::Validator],
        signer: usize,
        slot: u64,
    ) -> EquivocationEvidence {
        signed_by(&validators[signer], slot)
    }

    /// Conflicting evidence at `slot` signed by `v`, claiming `v.index` — the shape a
    /// foreign key produces when the ledger outlives the committee that made it.
    fn signed_by(v: &qlab_devnet::committee::Validator, slot: u64) -> EquivocationEvidence {
        let tag = v.index as u8;
        let cp_a = Checkpoint::new(slot, [0xA0 + tag; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(slot, [0xB0 + tag; 32], [0xBB; 32]);
        EquivocationEvidence {
            vote_a: v.sign_checkpoint(&cp_a),
            cp_a,
            vote_b: v.sign_checkpoint(&cp_b),
            cp_b,
        }
    }

    fn eq(a: &EquivocationEvidence, b: &EquivocationEvidence) -> bool {
        // `Vote` has no PartialEq; compare via the one canonical encoding.
        encode_evidence_msg(a) == encode_evidence_msg(b)
    }

    /// The refusal, or a panic naming what got through. `EquivocationEvidence` has
    /// neither `Debug` nor `PartialEq` (its `Vote` has neither), so an `Ok` cannot be
    /// printed — the count is what is diagnostic anyway.
    fn refusal(r: Result<Vec<EquivocationEvidence>, LedgerError>) -> LedgerError {
        match r {
            Err(e) => e,
            Ok(v) => panic!("must refuse, but decoded {} record(s)", v.len()),
        }
    }

    #[test]
    fn ledger_round_trips_including_empty() {
        let (_c, validators) = devnet_committee(7);
        let empty: Vec<EquivocationEvidence> = Vec::new();
        assert!(decode(&encode(&empty)).unwrap().is_empty());
        // An empty ledger is still a versioned two-byte file, not a zero-byte one:
        // "no punishments" has to be a statement, not an absence.
        assert_eq!(encode(&empty), vec![PUNISHMENT_FORMAT_VERSION, 0]);

        let records = vec![evidence(&validators, 3, 8), evidence(&validators, 5, 16)];
        let back = decode(&encode(&records)).expect("round-trips");
        assert_eq!(back.len(), 2);
        assert!(eq(&back[0], &records[0]) && eq(&back[1], &records[1]));
        // One record is the two checkpoints plus two ML-DSA-65 signatures.
        let one = encode(&records[..1]);
        assert!(one.len() > 2 * 3_309, "a record carries both signatures: {}", one.len());
    }

    /// **Acceptance: a ledger this binary does not understand is refused, not
    /// ignored.** Every rejection path is exercised in one place because they are one
    /// property — the file is either honoured exactly or the node does not start.
    #[test]
    fn an_unreadable_ledger_is_refused_never_treated_as_empty() {
        let (_c, validators) = devnet_committee(7);
        let good = encode(&[evidence(&validators, 2, 8)]);

        // Unknown version.
        let mut bad = good.clone();
        bad[0] = PUNISHMENT_FORMAT_VERSION + 1;
        assert_eq!(refusal(decode(&bad)), LedgerError::BadVersion { got: 2 });

        // Trailing byte.
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(refusal(decode(&extra)), LedgerError::Trailing { remaining: 1 });

        // Truncated body.
        assert!(matches!(
            refusal(decode(&good[..good.len() - 1])),
            LedgerError::Truncated { .. } | LedgerError::Record { .. }
        ));

        // Empty file: not even a version byte.
        assert_eq!(refusal(decode(&[])), LedgerError::Truncated { what: "version" });

        // An absurd count is rejected before any allocation.
        let mut huge = vec![PUNISHMENT_FORMAT_VERSION];
        write_varint(&mut huge, MAX_PUNISHMENT_RECORDS + 1);
        assert_eq!(
            refusal(decode(&huge)),
            LedgerError::BadCount { got: MAX_PUNISHMENT_RECORDS + 1 }
        );

        // A record whose bytes are corrupt (flip a signature byte) fails to decode
        // or fails to verify — never silently becomes a different punishment.
        let mut corrupt = good.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        match decode(&corrupt) {
            Err(LedgerError::Record { index: 0, .. }) => {}
            Ok(records) => {
                let (c, _v) = devnet_committee(7);
                let mut ec =
                    EpochCommittee::genesis(EpochSchedule::new(8), CommitteeState::new(c, BOND_AMOUNT));
                assert!(
                    matches!(replay(&mut ec, &records, 8), Err(LedgerError::Unverified { .. })),
                    "a corrupt signature must not adjudicate"
                );
            }
            Err(other) => panic!("unexpected: {other:?}"),
        }
    }

    /// Evidence signed by a **key that is not in this node's committee** — a data dir
    /// carried across a genesis/committee change, or a hand-written ledger — does not
    /// adjudicate, and replay refuses rather than starting the node with a roster it
    /// cannot vouch for.
    ///
    /// The foreign key is built from a *different seed at the same index* on purpose.
    /// `devnet_committee(n)` derives key `i` from the index alone, so member 2 of a
    /// 7-committee and member 2 of a 9-committee are the same key — using two sizes
    /// here would have produced a test that passed for the wrong reason.
    #[test]
    fn evidence_from_a_foreign_committee_refuses_rather_than_starting_clean() {
        let foreign = qlab_devnet::committee::Validator::from_seed(2, [0x77; 32]);
        let records = vec![signed_by(&foreign, 8)];
        let (mine, _v) = devnet_committee(7);
        let mut ec =
            EpochCommittee::genesis(EpochSchedule::new(8), CommitteeState::new(mine, BOND_AMOUNT));
        assert_eq!(
            replay(&mut ec, &records, 8),
            Err(LedgerError::Unverified { index: 0, err: EvidenceError::InvalidSignature })
        );
    }

    /// **Acceptance (decision 3): a restored punishment lands at the right boundary,
    /// on the right member, once.**
    ///
    /// The control is what makes this a test rather than an assertion: a committee
    /// that was punished mid-epoch-0 and then advanced to the boundary, versus one
    /// rebuilt from genesis and replayed from the ledger. After the boundary the
    /// roster has *shrunk* (forced exit) and every higher index has shifted down, so
    /// a replay that applied the punishment at the wrong time would produce a
    /// different roster size, a different quorum, and a different key at the shifted
    /// index — and would then read every honest peer's votes as forged.
    #[test]
    fn replay_reproduces_a_boundary_crossing_committee_exactly() {
        let sched = EpochSchedule::new(8); // small epoch so the test crosses one
        let (committee, validators) = devnet_committee(5); // quorum 4
        let ev = evidence(&validators, 2, 3); // punished at height 3, epoch 0

        // The control: a node that never restarted. Punish mid-epoch, then cross.
        let mut live = EpochCommittee::genesis(
            sched,
            CommitteeState::new(committee.clone(), BOND_AMOUNT),
        );
        let slash = equivocation_slash(live.state().bond(2).unwrap());
        assert!(live.state_mut().tombstone(2, slash));
        live.advance_to(8);

        // The restart: a fresh genesis committee plus the ledger.
        let mut restored =
            EpochCommittee::genesis(sched, CommitteeState::new(committee, BOND_AMOUNT));
        assert_eq!(replay(&mut restored, &[ev], 8).unwrap(), vec![2]);
        restored.advance_to(8);

        assert_eq!(restored.current_epoch(), live.current_epoch(), "same epoch");
        assert_eq!(restored.state().size(), live.state().size(), "same roster size");
        assert_eq!(restored.state().size(), 4, "the tombstoned member left at the boundary");
        assert_eq!(
            restored.state().quorum_threshold(),
            live.state().quorum_threshold(),
            "same quorum — the thing a divergence here would corrupt"
        );
        // The reindexed roster is key-for-key identical, which is what stops a
        // restarted node reading an honest peer's vote as forged.
        for i in 0..restored.state().size() {
            assert_eq!(
                restored.state().committee().member(i).unwrap().encode().to_vec(),
                live.state().committee().member(i).unwrap().encode().to_vec(),
                "member {i} must be the same key on both sides"
            );
            assert_eq!(restored.state().status(i), live.state().status(i));
            assert_eq!(restored.state().bond(i), live.state().bond(i));
            assert_eq!(restored.state().slashed(i), live.state().slashed(i));
        }
    }

    /// **The test that makes the per-record epoch advance load-bearing, rather than
    /// merely defensible.**
    ///
    /// Two punishments, one on each side of a boundary. The second names its signer by
    /// the **epoch-1** index, which is not the epoch-0 index of the same key: the first
    /// tombstone left the roster at the boundary (forced exit, §2) and every higher
    /// index shifted down by one. A replay that adjudicated every record against the
    /// genesis roster would therefore read the second record's signature against a
    /// different member's key entirely — and, because `verify_equivocation` is two
    /// signature checks and not a name lookup, it would come out as *unverified* and
    /// the node would refuse to start on a ledger it wrote itself.
    ///
    /// The control is the live node again: same two punishments in the same order
    /// without a restart.
    #[test]
    fn a_punishment_after_a_boundary_is_adjudicated_against_the_roster_that_owned_it() {
        let sched = EpochSchedule::new(8);
        let (committee, validators) = devnet_committee(5); // 0..4

        // Live: tombstone member 2 in epoch 0, cross into epoch 1 (roster shrinks to
        // 4 and reindexes: old 3 → new 2, old 4 → new 3), then tombstone the member
        // now at index 3 — which is validator 4's key.
        let mut live =
            EpochCommittee::genesis(sched, CommitteeState::new(committee.clone(), BOND_AMOUNT));
        let first = evidence(&validators, 2, 3); // epoch 0, index 2
        let slash2 = equivocation_slash(live.state().bond(2).unwrap());
        assert!(live.state_mut().tombstone(2, slash2));
        live.advance_to(8);
        assert_eq!(live.state().size(), 4);
        // Sanity that the shift really happened — index 3 is validator 4's key now.
        assert_eq!(
            live.state().committee().member(3).unwrap().encode().to_vec(),
            validators[4].verifying_key().encode().to_vec(),
            "the boundary reindexed the roster; the test depends on it"
        );
        // The second record is signed by validator 4 but CLAIMS index 3, which is what
        // an epoch-1 vote from that member looks like.
        let second = {
            let cp_a = Checkpoint::new(9, [0xC4; 32], [0xCC; 32]);
            let cp_b = Checkpoint::new(9, [0xD4; 32], [0xDD; 32]);
            let mut v_a = validators[4].sign_checkpoint(&cp_a);
            let mut v_b = validators[4].sign_checkpoint(&cp_b);
            v_a.signer = 3;
            v_b.signer = 3;
            EquivocationEvidence { vote_a: v_a, cp_a, vote_b: v_b, cp_b }
        };
        assert_eq!(verify_equivocation(&second, live.state().committee()), Ok(3));
        let slash3 = equivocation_slash(live.state().bond(3).unwrap());
        assert!(live.state_mut().tombstone(3, slash3));

        // Restart: replay both records from the ledger onto a fresh genesis roster.
        let mut restored =
            EpochCommittee::genesis(sched, CommitteeState::new(committee, BOND_AMOUNT));
        let mut records = vec![second, first];
        sort_records(&mut records); // the ledger is replayed in slot order
        assert_eq!(replay(&mut restored, &records, 9).unwrap(), vec![2, 3]);
        restored.advance_to(9);

        assert_eq!(restored.current_epoch(), live.current_epoch());
        assert_eq!(restored.state().size(), live.state().size());
        for i in 0..restored.state().size() {
            assert_eq!(
                restored.state().committee().member(i).unwrap().encode().to_vec(),
                live.state().committee().member(i).unwrap().encode().to_vec(),
                "member {i}"
            );
            assert_eq!(restored.state().status(i), live.state().status(i), "member {i} status");
            assert_eq!(restored.state().bond(i), live.state().bond(i), "member {i} bond");
            assert_eq!(restored.state().slashed(i), live.state().slashed(i), "member {i} slash");
        }
        // And the member punished in epoch 1 is the one that was actually punished:
        // validator 4's key, not validator 3's.
        assert_eq!(
            restored.state().status(3),
            Some(MemberStatus::Tombstoned),
            "the epoch-1 punishment landed on the member the evidence names"
        );
    }

    /// A duplicated record neither slashes twice nor reports twice — `tombstone` is
    /// idempotent, and replay reports only what it newly applied.
    #[test]
    fn a_duplicated_record_does_not_double_apply() {
        let (committee, validators) = devnet_committee(5);
        let ev = evidence(&validators, 1, 8);
        let mut ec = EpochCommittee::genesis(
            EpochSchedule::new(1_152),
            CommitteeState::new(committee, BOND_AMOUNT),
        );
        let applied = replay(&mut ec, &[ev.clone(), ev], 8).unwrap();
        assert_eq!(applied, vec![1], "reported once");
        assert_eq!(ec.state().status(1), Some(MemberStatus::Tombstoned));
        assert_eq!(
            ec.state().slashed(1),
            Some(equivocation_slash(BOND_AMOUNT)),
            "slashed exactly once"
        );
    }

    /// Advancement is clamped to the tip: a punishment for a slot above this node's
    /// chain must not push the epoch machinery past the chain it belongs to.
    #[test]
    fn a_punishment_above_the_tip_does_not_advance_the_epoch_past_it() {
        let (committee, validators) = devnet_committee(5);
        let ev = evidence(&validators, 3, 40); // slot 40, five epochs up at len 8
        let mut ec =
            EpochCommittee::genesis(EpochSchedule::new(8), CommitteeState::new(committee, BOND_AMOUNT));
        replay(&mut ec, &[ev], 3).expect("verifies"); // tip is 3 → epoch 0
        assert_eq!(ec.current_epoch(), 0, "the epoch machinery never runs ahead of the tip");
        assert_eq!(ec.state().status(3), Some(MemberStatus::Tombstoned));
    }

    #[test]
    fn save_load_round_trips_and_a_missing_file_is_none() {
        let dir = std::env::temp_dir().join(format!("qlab-p2p-i133-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::remove_file(path(&dir)).ok();
        assert!(load(&dir).unwrap().is_none(), "a missing ledger is None, not empty");

        let (_c, validators) = devnet_committee(7);
        let records = vec![evidence(&validators, 4, 24)];
        save(&dir, &records).unwrap();
        let back = load(&dir).unwrap().expect("present");
        assert!(eq(&back[0], &records[0]));
        // No temp file is left behind by the atomic write.
        assert!(!dir.join(PUNISHMENT_TMP).exists());

        // An unreadable ledger surfaces as InvalidData, carrying the operator note.
        std::fs::write(path(&dir), [0xFE, 0x00]).unwrap();
        let err = match load(&dir) {
            Err(e) => e,
            Ok(_) => panic!("an unknown-version ledger must refuse, not load"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("Re-sync this data dir"), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn summary_line_states_zero_rather_than_omitting_it() {
        let none = PunishmentRestore::default();
        assert_eq!(
            none.summary_line(),
            "committee punishments: 0 record(s) on disk, 0 tombstone(s) restored (members -)"
        );
        let some = PunishmentRestore { records: 2, tombstoned: vec![3, 7], ..Default::default() };
        assert!(some.summary_line().contains("2 tombstone(s) restored (members 3,7)"));
    }
}
