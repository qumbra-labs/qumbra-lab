//! Node **telemetry** for finality-stall observability (M10-T0-2, issue #63).
//!
//! The Crosslink feature-net stall (design §4 status, 2026-07-24) was painful in
//! part because an operator had no first-class read of *how badly* finality had
//! fallen behind. This module is the operator surface: a single versioned
//! [`Telemetry`] snapshot carrying the finality regime plus the numbers a stall
//! runbook (and the T0-3 soak monitor) actually watch — stall depth, how long
//! finality has been stuck, peers, mempool, heights, and epoch.
//!
//! Wire discipline mirrors the N6 surfaces ([`crate::rpc::NodeStatus`]): a
//! [`RPC_VERSION`] lead version byte, little-endian fixed fields, and
//! reject-unknown-version / reject-trailing on decode (§0). Peer count and epoch
//! are **injected** from the P2P layer (they are not node-state — the N1 traits do
//! not carry them), so the node-owned half is assembled from live state and the
//! network half is stamped in by the p2p glue via
//! [`crate::rpc::NodeRpc::set_net_facts`].
//!
//! # Checkpoint identity (issue #117, wire `0x02`)
//!
//! `final=` says how *high* a node finalized and never *what*, so two nodes that
//! finalized different checkpoints at one height printed identical telemetry.
//! #110 put the identity on the `TELEMETRY` log line and on `/metrics`; this wire
//! carries it too, because it is the operator surface and checkpoint identity is
//! the operator's most severe question. Mirroring the log line:
//!
//! - [`Telemetry::finalized_id`] (`fid`) — **what** this node finalized.
//! - [`Telemetry::signed`] (`sslot`/`sid`) — what this node's own committee keys
//!   are committed to, and at which slot. A minority that signed a different
//!   variant still finalizes the majority's, so a split shows up *here* while
//!   `final` and `fid` still agree everywhere.
//! - [`Telemetry::tip_difficulty`] (`diff`) — a **fourth** field beyond the three
//!   the #117 decision named, added because the operator view that decision exists
//!   to serve is required to render difficulty per node and no wire carried it.
//!   Riding the same version bump costs nothing extra; shipping a column that
//!   could only say `-` would.
//!
//! Like peer count and epoch, they are **injected**: they live in the committee
//! finality tracker and the never-double-sign ledgers, not in [`crate::Node`].
//! A composition that does not inject them reports them absent, which is the
//! truth about that composition rather than a zero standing in for one.
//!
//! Appending them is a breaking change on a reject-unknown-version wire — that is
//! deliberate (§0: a truncated or stale read fails loudly instead of misparsing),
//! and it is why [`RPC_VERSION`] went `0x01` → `0x02`. Issue #121 adds only the
//! publishable committee aggregates (never signer identities) and the supply
//! attestation, moving the wire to `0x03`. An old reader is *supposed* to fail
//! against a new node.

use qlab_cbserver::codec::{write_varint, CodecError};
use qlab_devnet::committee::checkpoint_id_hex;
use qlab_devnet::ebbflow::FinalityStatus;
use qlab_devnet::halt::regime as halt_regime;

use crate::rpc::{Reader, RPC_VERSION};
use crate::supply::SupplyEpoch;

/// Wire discriminant for [`FinalityStatus::Final`].
const STATUS_FINAL: u8 = 0;
/// Wire discriminant for [`FinalityStatus::Degraded`].
const STATUS_DEGRADED: u8 = 1;
/// Wire discriminant for [`FinalityStatus::Halting`] (halt-height upgrade, #74).
const STATUS_HALTING: u8 = 2;
/// Wire discriminant for [`FinalityStatus::Halted`].
const STATUS_HALTED: u8 = 3;

/// The `sid=` token when a node's own held keys are committed to *different*
/// checkpoints at the same slot (issue #84). Distinguishable from an identity by
/// length and by not being hex; see [`LocalCommitment::id_field`].
///
/// *(Moved here from `qumbra-node`'s run loop by issue #117 so the wire, the log
/// line and any reader share one definition; `qumbra_node::run` re-exports it.)*
pub const LOCAL_COMMITMENT_SPLIT: &str = "split";

/// What a node's own committee keys are committed to at one slot (issue #84).
///
/// The slot reported is the highest any held key has committed to, which is
/// deliberately **not** the finalized height: at a split, the minority still
/// finalizes the majority's checkpoint, so the two nodes agree on `final` (and on
/// `fid`) and differ only here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalCommitment {
    /// The highest slot any held key has committed to.
    pub slot: u64,
    /// The identity every held key that committed to `slot` agrees on, or `None`
    /// when they disagree — this node's key set is split across two variants.
    pub id: Option<u64>,
}

impl LocalCommitment {
    /// The `sid=` field: the identity hex, or [`LOCAL_COMMITMENT_SPLIT`] when this
    /// node's own held keys are committed to different checkpoints for one slot.
    ///
    /// `split` is reachable — a key restored from a ledger written on one history
    /// refuses to re-sign while a key with no ledger signs the new one — and it is
    /// this node equivocating against itself across its own key set. Picking one of
    /// the two to print would be the exact failure #84 exists to remove: a line
    /// that looks healthy while the thing it describes is not.
    pub fn id_field(&self) -> String {
        match self.id {
            Some(id) => checkpoint_id_hex(Some(id)),
            None => LOCAL_COMMITMENT_SPLIT.to_string(),
        }
    }
}

/// **The one comparison of the two chain views this node holds** (issue #130): the
/// height the *state machine* has applied bodies up to, against the height *fork
/// choice* has headers up to.
///
/// It exists as a type because three surfaces need the same verdict and this repo
/// has ruled three times in one week that a second copy of a derivation is the
/// defect, not the convenience (#116, #102, #125):
///
/// - [`SupplyCoverage`] — a supply figure is publishable only at zero lag (#126);
/// - the `TELEMETRY` line's `stip=` / `slag=` fields and the `/metrics` gauges,
///   which is how an operator sees the lag at all;
/// - `qlab_p2p::adapter::NodeAdapter::state_lag`, which is the **duty gate**: while
///   this is nonzero the node refuses to mine or to admit a transaction, because
///   both would be acting on a view it knows is stale.
///
/// `fork_choice_tip` is always ≥ `state_tip` in a healthy node — headers land in
/// fork choice first and the body follows — so the difference is measured
/// saturating and a nonsensical pair reads as zero rather than underflowing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateLag {
    /// Highest height whose **body** this node has applied to state.
    pub state_tip: u64,
    /// Highest height whose **header** fork choice holds.
    pub fork_choice_tip: u64,
}

impl StateLag {
    pub fn new(state_tip: u64, fork_choice_tip: u64) -> Self {
        Self { state_tip, fork_choice_tip }
    }

    /// How many blocks the state machine trails fork choice by; 0 when the two
    /// views agree.
    pub fn blocks(&self) -> u64 {
        self.fork_choice_tip.saturating_sub(self.state_tip)
    }

    /// Whether the state machine is behind its own chain — the predicate every
    /// duty refusal keys on. One definition, so a duty cannot be refused on one
    /// reading while a figure is published on another.
    pub fn is_lagging(&self) -> bool {
        self.blocks() > 0
    }
}

/// Whether the supply ledger covers the same tip as fork choice.
///
/// The supply rows are derived from bodies the state machine has applied, while
/// [`Telemetry::tip_height`] is fork choice. Issue #130 established that those
/// views can disagree permanently on a late joiner. A partial ledger must
/// therefore be rendered as unavailable, never as supply agreement or a supply
/// violation.
///
/// The verdict is [`StateLag::is_lagging`] — see [`Telemetry::supply_lag`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyCoverage {
    /// The last applied supply row reaches the fork-choice tip.
    Complete,
    /// The views disagree, or this composition supplied no ledger rows.
    Unavailable {
        state_tip: Option<u64>,
        fork_choice_tip: u64,
    },
}

/// A single observability snapshot of a node's finality health.
///
/// `stall_depth` and `last_finalized_age_secs` are the two the runbook keys on:
/// the former is the *height* gap (tip − finalized), the latter the *chain-time*
/// gap in seconds since the last finalized checkpoint — the same stall seen in the
/// two units an operator reasons in ("how many blocks behind" vs "how long stuck").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Telemetry {
    /// The Ebb-and-Flow finality regime (frozen §4 semantics, read here).
    pub finality_status: FinalityStatus,
    /// Fork-choice tip height.
    pub tip_height: u64,
    /// Finalized head height, if anything is finalized.
    pub finalized_height: Option<u64>,
    /// Stall depth = `tip − finalized` (or `tip` if nothing is finalized).
    pub stall_depth: u64,
    /// Chain-time seconds since the last finalized checkpoint (tip block timestamp
    /// − finalized block timestamp). Derived from block timestamps, so it is
    /// deterministic — no wall clock.
    ///
    /// **0, and rendered `-`, while there is no finalized checkpoint to measure
    /// from** — nothing finalized (S8) *or* the finalized head still genesis
    /// (issue #73). Genesis is finalized as a bootstrap act, not by a checkpoint
    /// round (`is_checkpoint_height`: genesis is never a slot), and its timestamp
    /// is the `0` placeholder — differencing a `WallClock` tip against it printed
    /// the whole Unix epoch (`age_s=1785352360` on every node of a fresh net).
    /// See [`Self::age_field`], the one rendering rule for this field.
    pub last_finalized_age_secs: u64,
    /// Connected peer count (injected from the P2P layer).
    pub peer_count: u64,
    /// Pending mempool size.
    pub mempool_size: u64,
    /// Current committee epoch (injected from the P2P/committee layer).
    pub epoch: u64,
    /// Roster size of the current committee.
    ///
    /// This is deliberately an aggregate. Per-signer participation belongs on the
    /// operator's loopback `/metrics` and in the `ROUND` journal, never on this
    /// public wire (issue #121).
    pub committee_size: u64,
    /// Active committee members (roster minus tombstoned/jailed).
    pub committee_active: u64,
    /// Quorum threshold currently in force, read from committee state.
    pub committee_quorum: u64,
    /// Scheduled-issuance attestation grouped by epoch, from genesis through the
    /// state machine's applied tip. Each row compares integer bessel at zero
    /// tolerance.
    ///
    /// Consumers must use [`Self::supply_coverage`] before rendering or acting on
    /// these rows: the state tip may trail the fork-choice `tip_height`.
    pub supply: Vec<SupplyEpoch>,
    /// **The identity of the finalized checkpoint** (`fid`, issue #117), or `None`
    /// when nothing is finalized *or* when the composition serving this snapshot
    /// does not carry a committee finality tracker to read it from.
    ///
    /// Injected via [`Self::with_checkpoint`] — see the module docs. Two nodes
    /// reporting the same `finalized_height` with different `finalized_id` is two
    /// different checkpoints at one height: the R2 stop condition, and the reason
    /// this field exists.
    pub finalized_id: Option<u64>,
    /// **What this node's own committee keys are committed to** (`sslot`/`sid`,
    /// issue #117), or `None` when it holds no committee keys, has committed to
    /// nothing, or the composition does not inject it.
    pub signed: Option<LocalCommitment>,
    /// The tip block's PoW difficulty (issue #117), or `None` when the tip header
    /// is not available to the composition serving this snapshot.
    ///
    /// Already on the `TELEMETRY` log line as `diff=` (Phase B-lite amendment-1
    /// item 4, so the LWMA retarget trace is visible over a soak) and on
    /// `/metrics`, but on no wire — and #117's operator view is required to render
    /// it per node. Carried here inside the same `0x02` bump rather than shipping a
    /// column that could only ever say `-`; see the PR for why this is a fourth
    /// field beside the three the decision named.
    pub tip_difficulty: Option<u64>,
}

impl Telemetry {
    /// Assemble a snapshot from the node-owned facts + the injected network facts.
    /// `max_lag` is the degraded-mode threshold
    /// ([`qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS`]); the finality
    /// regime and stall depth are derived from it exactly as the adapter's
    /// `finality_status` does — this module never re-defines the frozen rule.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        tip_height: u64,
        finalized_height: Option<u64>,
        last_finalized_age_secs: u64,
        mempool_size: u64,
        peer_count: u64,
        epoch: u64,
        max_lag: u64,
    ) -> Self {
        Self::assemble_with_halt(
            tip_height,
            finalized_height,
            last_finalized_age_secs,
            mempool_size,
            peer_count,
            epoch,
            max_lag,
            None,
        )
    }

    /// [`Self::assemble`], halt-aware (issue #74). `halt_at` is the running
    /// release's halt height, if it carries one; when a halt governs, the regime is
    /// `Halting`/`Halted` instead of the ordinary Ebb-and-Flow pair. The rule comes
    /// from [`qlab_devnet::halt::regime`] — this module never re-defines it.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble_with_halt(
        tip_height: u64,
        finalized_height: Option<u64>,
        last_finalized_age_secs: u64,
        mempool_size: u64,
        peer_count: u64,
        epoch: u64,
        max_lag: u64,
        halt_at: Option<u64>,
    ) -> Self {
        let finality_status = halt_regime(tip_height, finalized_height, max_lag, halt_at);
        let stall_depth = match finalized_height {
            Some(fh) => tip_height.saturating_sub(fh),
            None => tip_height,
        };
        Self {
            finality_status,
            tip_height,
            finalized_height,
            stall_depth,
            last_finalized_age_secs,
            peer_count,
            mempool_size,
            epoch,
            committee_size: 0,
            committee_active: 0,
            committee_quorum: 0,
            supply: Vec::new(),
            finalized_id: None,
            signed: None,
            tip_difficulty: None,
        }
    }

    /// Stamp in the public committee aggregates (issue #121).
    ///
    /// There is intentionally no signer list in this type, so neither the wire nor
    /// any consumer can accidentally turn it into an availability map.
    pub fn with_committee(
        mut self,
        committee_size: u64,
        committee_active: u64,
        committee_quorum: u64,
    ) -> Self {
        self.committee_size = committee_size;
        self.committee_active = committee_active;
        self.committee_quorum = committee_quorum;
        self
    }

    /// Stamp in the public per-epoch supply attestation (issue #121).
    pub fn with_supply(mut self, supply: Vec<SupplyEpoch>) -> Self {
        self.supply = supply;
        self
    }

    /// The one availability rule for supply figures.
    ///
    /// This mirrors [`Self::age_field`]'s refusal discipline: figures are
    /// publishable only when the applied state ledger and fork choice name the
    /// same tip height. The existing `0x03` payload already carries both heights
    /// (`tip_height` and the last supply row's `end_height`), so this rule needs
    /// no wire change.
    pub fn supply_coverage(&self) -> SupplyCoverage {
        match self.supply_lag() {
            Some(lag) if !lag.is_lagging() => SupplyCoverage::Complete,
            // Either the ledger trails fork choice, or this composition supplied no
            // rows at all — `state_tip` keeps those two apart for the reader.
            other => SupplyCoverage::Unavailable {
                state_tip: other.map(|lag| lag.state_tip),
                fork_choice_tip: self.tip_height,
            },
        }
    }

    /// The [`StateLag`] this snapshot can see, or `None` when it carries no supply
    /// rows to read an applied height from.
    ///
    /// The last supply row's `end_height` **is** the state machine's applied tip:
    /// the ledger is fed from applied bodies (`qumbra_node::run::RunningNode::telemetry`
    /// walks it to `state_chain.tip_height()`), so the `0x03` payload already carries
    /// both heights of the comparison and no wire bump is needed to publish it.
    pub fn supply_lag(&self) -> Option<StateLag> {
        self.supply.last().map(|row| StateLag::new(row.end_height, self.tip_height))
    }

    /// Stamp in the checkpoint-identity half (issue #117), the way
    /// [`crate::rpc::NodeRpc::set_net_facts`] stamps in peers/epoch: these live in
    /// the committee finality tracker and the never-double-sign ledgers, which
    /// [`crate::Node`] does not own.
    ///
    /// Leaving them unset is honest, not a gap — it says "this composition cannot
    /// see the identity", which is different from "there is no identity", and a
    /// reader that needs the distinction has it.
    pub fn with_checkpoint(
        mut self,
        finalized_id: Option<u64>,
        signed: Option<LocalCommitment>,
    ) -> Self {
        self.finalized_id = finalized_id;
        self.signed = signed;
        self
    }

    /// Stamp in the tip block's PoW difficulty (issue #117) — the `diff=` field of
    /// the `TELEMETRY` line, which lives in the header chain rather than in the
    /// finality state.
    pub fn with_tip_difficulty(mut self, difficulty: Option<u64>) -> Self {
        self.tip_difficulty = difficulty;
        self
    }

    /// The `diff=` field: the tip block's difficulty, or `-` when unavailable.
    pub fn diff_field(&self) -> String {
        self.tip_difficulty.map(|d| d.to_string()).unwrap_or_else(|| "-".to_string())
    }

    /// The `age_s=` field: `-` while there is no finalized **checkpoint** to
    /// measure an age from, else [`Self::last_finalized_age_secs`].
    ///
    /// `-` covers two states an operator must not read a number in: nothing
    /// finalized at all (S8, PR #72), and the finalized head still genesis
    /// (issue #73) — the bootstrap finalization every fresh net starts from, which
    /// is not a checkpoint round and whose `timestamp = 0` placeholder is not a
    /// time. The rule keys on `finalized_height == Some(0)` rather than on the
    /// timestamp because height 0 IS genesis on every net, and height is what this
    /// wire carries — so the log line, `qumbra-opview` and any other reader derive
    /// the same `-` from the same snapshot (the #117 discipline).
    pub fn age_field(&self) -> String {
        match self.finalized_height {
            None | Some(0) => "-".to_string(),
            Some(_) => self.last_finalized_age_secs.to_string(),
        }
    }

    /// The `fid=` field: the finalized checkpoint's identity as the canonical
    /// 12-char lowercase hex, or `-` when absent — the same rendering as the
    /// `TELEMETRY` log line (#84), from the same helper.
    pub fn fid_field(&self) -> String {
        checkpoint_id_hex(self.finalized_id)
    }

    /// The `sslot=` field: the slot this node's keys last committed to, or `-`.
    pub fn sslot_field(&self) -> String {
        self.signed.map(|c| c.slot.to_string()).unwrap_or_else(|| "-".to_string())
    }

    /// The `sid=` field: the signed identity hex, `-` when this node holds no
    /// committee keys or has committed to nothing, or
    /// [`LOCAL_COMMITMENT_SPLIT`] when its own keys disagree.
    pub fn sid_field(&self) -> String {
        match self.signed {
            None => checkpoint_id_hex(None),
            Some(c) => c.id_field(),
        }
    }

    /// `version(0x03) ‖ finality(u8) ‖ tip(8 LE) ‖ has_final(u8) ‖
    /// [final_height(8 LE) if has] ‖ stall_depth(8) ‖ age_secs(8) ‖
    /// peer_count(8) ‖ mempool_size(8) ‖ epoch(8) ‖`
    /// `has_fid(u8) ‖ [finalized_id(8 LE) if has] ‖ has_signed(u8) ‖`
    /// `[signed_slot(8 LE) ‖ has_signed_id(u8) ‖ [signed_id(8 LE) if has] if has] ‖`
    /// `has_diff(u8) ‖ [tip_difficulty(8 LE) if has] ‖`
    /// `committee_size(8 LE) ‖ committee_active(8 LE) ‖ committee_quorum(8 LE) ‖`
    /// `n_supply(varint) ‖ n × (epoch ‖ start_height ‖ end_height ‖`
    /// `measured_coinbase ‖ expected_coinbase ‖ fees)` (all entry fields u64 LE).
    ///
    /// The `0x02` tail (issue #117) nests `sid` **inside** `sslot`'s presence, so
    /// "an identity with no slot" is not representable on the wire: a signed
    /// identity without the slot it was signed at is not a fact anyone can act on.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RPC_VERSION);
        out.push(match self.finality_status {
            FinalityStatus::Final => STATUS_FINAL,
            FinalityStatus::Degraded => STATUS_DEGRADED,
            FinalityStatus::Halting => STATUS_HALTING,
            FinalityStatus::Halted => STATUS_HALTED,
        });
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        match self.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&self.stall_depth.to_le_bytes());
        out.extend_from_slice(&self.last_finalized_age_secs.to_le_bytes());
        out.extend_from_slice(&self.peer_count.to_le_bytes());
        out.extend_from_slice(&self.mempool_size.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        // ---- issue #117: the checkpoint-identity tail ----
        match self.finalized_id {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id.to_le_bytes());
            }
            None => out.push(0),
        }
        match self.signed {
            Some(c) => {
                out.push(1);
                out.extend_from_slice(&c.slot.to_le_bytes());
                match c.id {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(&id.to_le_bytes());
                    }
                    // The `split` state: this node's own keys are committed to two
                    // different variants at one slot, so there is no single identity
                    // to encode. Absent-with-a-slot IS the signal.
                    None => out.push(0),
                }
            }
            None => out.push(0),
        }
        match self.tip_difficulty {
            Some(d) => {
                out.push(1);
                out.extend_from_slice(&d.to_le_bytes());
            }
            None => out.push(0),
        }
        // ---- issue #121: publishable committee aggregates only --------------
        out.extend_from_slice(&self.committee_size.to_le_bytes());
        out.extend_from_slice(&self.committee_active.to_le_bytes());
        out.extend_from_slice(&self.committee_quorum.to_le_bytes());
        write_varint(&mut out, self.supply.len() as u64);
        for row in &self.supply {
            out.extend_from_slice(&row.epoch.to_le_bytes());
            out.extend_from_slice(&row.start_height.to_le_bytes());
            out.extend_from_slice(&row.end_height.to_le_bytes());
            out.extend_from_slice(&row.measured_coinbase.to_le_bytes());
            out.extend_from_slice(&row.expected_coinbase.to_le_bytes());
            out.extend_from_slice(&row.fees.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Telemetry, CodecError> {
        let mut r = Reader::new(b);
        r.version()?;
        let finality_status = match r.u8()? {
            STATUS_FINAL => FinalityStatus::Final,
            STATUS_DEGRADED => FinalityStatus::Degraded,
            STATUS_HALTING => FinalityStatus::Halting,
            STATUS_HALTED => FinalityStatus::Halted,
            // Unknown finality discriminant: reject rather than silently coerce
            // (§0 reject-unknown, applied to the status byte as well).
            got => return Err(CodecError::BadVersion { got }),
        };
        let tip_height = r.u64()?;
        let finalized_height = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let stall_depth = r.u64()?;
        let last_finalized_age_secs = r.u64()?;
        let peer_count = r.u64()?;
        let mempool_size = r.u64()?;
        let epoch = r.u64()?;
        // ---- issue #117: the checkpoint-identity tail ----
        let finalized_id = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let signed = if r.u8()? == 1 {
            let slot = r.u64()?;
            let id = if r.u8()? == 1 { Some(r.u64()?) } else { None };
            Some(LocalCommitment { slot, id })
        } else {
            None
        };
        let tip_difficulty = if r.u8()? == 1 { Some(r.u64()?) } else { None };
        let committee_size = r.u64()?;
        let committee_active = r.u64()?;
        let committee_quorum = r.u64()?;
        let n_supply = r.varint()?;
        // Do not preallocate from an untrusted count. A truncated/malicious body
        // fails on the first absent field without turning its varint into a memory
        // allocation request.
        let mut supply = Vec::new();
        for _ in 0..n_supply {
            supply.push(SupplyEpoch {
                epoch: r.u64()?,
                start_height: r.u64()?,
                end_height: r.u64()?,
                measured_coinbase: r.u64()?,
                expected_coinbase: r.u64()?,
                fees: r.u64()?,
            });
        }
        r.finish()?;
        Ok(Telemetry {
            finality_status,
            tip_height,
            finalized_height,
            stall_depth,
            last_finalized_age_secs,
            peer_count,
            mempool_size,
            epoch,
            committee_size,
            committee_active,
            committee_quorum,
            supply,
            finalized_id,
            signed,
            tip_difficulty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS as MAX_LAG;

    #[test]
    fn telemetry_roundtrips_both_regimes() {
        // Within lag ⇒ Final.
        let t = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        assert_eq!(t.finality_status, FinalityStatus::Final);
        assert_eq!(t.stall_depth, 4);
        assert_eq!(Telemetry::from_bytes(&t.to_bytes()).unwrap(), t);

        // Lag beyond threshold ⇒ Degraded (the stall the runbook fires on).
        let d = Telemetry::assemble(100, Some(8), 6900, 2, 5, 1, MAX_LAG);
        assert_eq!(d.finality_status, FinalityStatus::Degraded);
        assert_eq!(d.stall_depth, 92);
        assert_eq!(Telemetry::from_bytes(&d.to_bytes()).unwrap(), d);

        // Nothing finalized ⇒ Degraded, depth = tip, no finalized height.
        let n = Telemetry::assemble(5, None, 200, 0, 1, 0, MAX_LAG);
        assert_eq!(n.finality_status, FinalityStatus::Degraded);
        assert_eq!(n.stall_depth, 5);
        assert_eq!(n.finalized_height, None);
        assert_eq!(Telemetry::from_bytes(&n.to_bytes()).unwrap(), n);
    }

    /// Issue #73: `age_field` is the one rendering rule for `age_s=`, and it
    /// refuses to state an age in BOTH no-checkpoint states — nothing finalized
    /// (S8) and finalized-at-genesis — while a real finalized height renders the
    /// number. The wire encoding is untouched: the same fields round-trip, only
    /// the value carried while the head is genesis changes.
    #[test]
    fn age_field_is_dash_until_a_real_checkpoint_finalizes() {
        // Nothing finalized (S8): `-`.
        let none = Telemetry::assemble(5, None, 0, 0, 1, 0, MAX_LAG);
        assert_eq!(none.age_field(), "-");

        // Finalized head still genesis (#73): `-`, never a number — this is the
        // state every fresh net boots into (`final=0` until slot 8 finalizes).
        let genesis = Telemetry::assemble(1, Some(0), 0, 0, 1, 0, MAX_LAG);
        assert_eq!(genesis.age_field(), "-");
        assert_eq!(Telemetry::from_bytes(&genesis.to_bytes()).unwrap(), genesis);

        // First non-genesis checkpoint: the field speaks, in chain-time seconds.
        let real = Telemetry::assemble(10, Some(8), 150, 0, 1, 0, MAX_LAG);
        assert_eq!(real.age_field(), "150");
    }

    /// Issue #74: the halt regimes ride the SAME status field (extended, not
    /// forked), round-trip on the wire, and are derived from the halt rule rather
    /// than re-defined here.
    #[test]
    fn telemetry_roundtrips_halting_and_halted() {
        const H: u64 = 16;
        // Tip at H, H not finalized yet ⇒ Halting.
        let halting = Telemetry::assemble_with_halt(H, Some(8), 600, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(halting.finality_status, FinalityStatus::Halting);
        assert_eq!(Telemetry::from_bytes(&halting.to_bytes()).unwrap(), halting);
        assert_eq!(halting.to_bytes()[1], STATUS_HALTING);

        // H finalized ⇒ Halted, stall depth 0 (the boundary IS the tip).
        let halted = Telemetry::assemble_with_halt(H, Some(H), 0, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(halted.finality_status, FinalityStatus::Halted);
        assert_eq!(halted.stall_depth, 0);
        assert_eq!(Telemetry::from_bytes(&halted.to_bytes()).unwrap(), halted);
        assert_eq!(halted.to_bytes()[1], STATUS_HALTED);

        // Below H the halt does not govern — ordinary Ebb-and-Flow.
        let pre = Telemetry::assemble_with_halt(10, Some(8), 150, 0, 3, 0, MAX_LAG, Some(H));
        assert_eq!(pre.finality_status, FinalityStatus::Final);

        // A node with no halt scheduled is byte-identical to the pre-#74 surface.
        let a = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        let b = Telemetry::assemble_with_halt(20, Some(16), 300, 3, 7, 1, MAX_LAG, None);
        assert_eq!(a, b);
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn telemetry_rejects_bad_version_and_trailing_and_bad_status() {
        let t = Telemetry::assemble(20, Some(16), 300, 3, 7, 1, MAX_LAG);
        let good = t.to_bytes();

        // Unknown version byte.
        let mut bad_ver = good.clone();
        bad_ver[0] = 9;
        assert!(matches!(
            Telemetry::from_bytes(&bad_ver),
            Err(CodecError::BadVersion { got: 9 })
        ));

        // Unknown finality-status discriminant (byte 1).
        let mut bad_status = good.clone();
        bad_status[1] = 9;
        assert!(matches!(
            Telemetry::from_bytes(&bad_status),
            Err(CodecError::BadVersion { got: 9 })
        ));

        // Trailing byte.
        let mut extra = good.clone();
        extra.push(0);
        assert!(matches!(
            Telemetry::from_bytes(&extra),
            Err(CodecError::TrailingBytes { .. })
        ));

        // Truncation.
        assert!(Telemetry::from_bytes(&good[..good.len() - 1]).is_err());
    }

    // ---- issue #117: the checkpoint-identity tail ---------------------------

    /// The pre-#117 `0x01` encoding, hand-rolled. This is what a node built before
    /// this change emits and what a reader built before it expects — kept here as a
    /// literal so the rejection test cannot drift with the encoder it is testing.
    fn v1_payload(t: &Telemetry) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x01);
        out.push(match t.finality_status {
            FinalityStatus::Final => STATUS_FINAL,
            FinalityStatus::Degraded => STATUS_DEGRADED,
            FinalityStatus::Halting => STATUS_HALTING,
            FinalityStatus::Halted => STATUS_HALTED,
        });
        out.extend_from_slice(&t.tip_height.to_le_bytes());
        match t.finalized_height {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&t.stall_depth.to_le_bytes());
        out.extend_from_slice(&t.last_finalized_age_secs.to_le_bytes());
        out.extend_from_slice(&t.peer_count.to_le_bytes());
        out.extend_from_slice(&t.mempool_size.to_le_bytes());
        out.extend_from_slice(&t.epoch.to_le_bytes());
        out
    }

    /// `Telemetry` keeps the #117 identity states intact at `0x03`: absent,
    /// present, and the `split` case where a node's own keys are committed to two
    /// variants at one slot.
    #[test]
    fn telemetry_roundtrips_checkpoint_identity_at_0x03() {
        let base = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 2, MAX_LAG);

        // Nothing injected: the composition cannot see the identity. Fields render
        // as absent, exactly like the `TELEMETRY` log line's `-`.
        assert_eq!(base.finalized_id, None);
        assert_eq!(base.signed, None);
        assert_eq!(base.fid_field(), "-");
        assert_eq!(base.sslot_field(), "-");
        assert_eq!(base.sid_field(), "-");
        assert_eq!(Telemetry::from_bytes(&base.to_bytes()).unwrap(), base);
        assert_eq!(base.to_bytes()[0], RPC_VERSION);
        assert_eq!(RPC_VERSION, 0x03, "the ratified issue #121 bump");

        // Fully populated: finalized identity + this node's own signed variant.
        let full = base
            .clone()
            .with_checkpoint(Some(0x3f1a_9c2b_0d41), Some(LocalCommitment { slot: 3776, id: Some(0x3f1a_9c2b_0d41) }))
            .with_tip_difficulty(Some(1_048_576));
        assert_eq!(full.diff_field(), "1048576");
        assert_eq!(base.diff_field(), "-", "absent until injected");
        assert_eq!(full.fid_field(), "3f1a9c2b0d41");
        assert_eq!(full.sslot_field(), "3776");
        assert_eq!(full.sid_field(), "3f1a9c2b0d41");
        assert_eq!(Telemetry::from_bytes(&full.to_bytes()).unwrap(), full);

        // The split: a slot, and deliberately no identity for it.
        let split = base
            .clone()
            .with_checkpoint(Some(0x3f1a_9c2b_0d41), Some(LocalCommitment { slot: 3776, id: None }));
        assert_eq!(split.sslot_field(), "3776");
        assert_eq!(split.sid_field(), LOCAL_COMMITMENT_SPLIT);
        assert_eq!(Telemetry::from_bytes(&split.to_bytes()).unwrap(), split);

        // A verify-only node: it finalized something, but holds no keys, so it has
        // signed nothing. Distinct on the wire from the split above.
        let verify_only = base.clone().with_checkpoint(Some(0x3f1a_9c2b_0d41), None);
        assert_eq!(verify_only.sslot_field(), "-");
        assert_eq!(verify_only.sid_field(), "-");
        assert_eq!(Telemetry::from_bytes(&verify_only.to_bytes()).unwrap(), verify_only);
        assert_ne!(
            verify_only.to_bytes(),
            split.to_bytes(),
            "`no keys` and `my keys disagree` must not encode alike — one is fine and one is a finding"
        );
    }

    /// **Acceptance (#121): committee aggregates round-trip at `0x03`, while the
    /// immediately preceding `0x02` wire is rejected on its version byte.**
    #[test]
    fn committee_aggregates_roundtrip_at_0x03_and_0x02_is_rejected() {
        let t = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 3, MAX_LAG)
            .with_committee(21, 19, 15)
            .with_supply(vec![SupplyEpoch {
                epoch: 3,
                start_height: 3456,
                end_height: 3776,
                measured_coinbase: 1_234_567,
                expected_coinbase: 1_234_567,
                fees: 890,
            }]);
        let bytes = t.to_bytes();
        assert_eq!(bytes[0], 0x03);
        assert_eq!(Telemetry::from_bytes(&bytes).unwrap(), t);
        assert_eq!(
            (t.epoch, t.committee_size, t.committee_active, t.committee_quorum),
            (3, 21, 19, 15),
        );
        assert_eq!(t.supply.len(), 1);
        assert_eq!(t.supply[0].divergence_bessel(), 0);
        assert_eq!(t.supply_coverage(), SupplyCoverage::Complete);

        let mut old = bytes;
        old[0] = 0x02;
        assert!(matches!(
            Telemetry::from_bytes(&old),
            Err(CodecError::BadVersion { got: 2 })
        ));
    }

    #[test]
    fn supply_coverage_refuses_a_state_tip_behind_fork_choice_without_a_wire_change() {
        let partial = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG)
            .with_supply(vec![SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 4,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
            }]);
        assert_eq!(
            partial.supply_coverage(),
            SupplyCoverage::Unavailable {
                state_tip: Some(4),
                fork_choice_tip: 14,
            }
        );

        let decoded = Telemetry::from_bytes(&partial.to_bytes()).unwrap();
        assert_eq!(decoded.supply_coverage(), partial.supply_coverage());
        assert_eq!(decoded.to_bytes()[0], 0x03, "coverage uses fields already on v3");
    }

    /// **Acceptance (#130 (a)): `SupplyCoverage` and the state-lag figures are one
    /// comparison, not two.**
    ///
    /// #126 already derived "the applied ledger does not reach fork choice" here.
    /// (a) needs the same comparison as a number on `TELEMETRY` and `/metrics`, and
    /// this repo has ruled derive-don't-restate three times in one week (#116, #102,
    /// #125). So [`StateLag`] is the single definition and `supply_coverage` is
    /// expressed in terms of it — this test fails if either grows its own copy.
    #[test]
    fn supply_coverage_and_state_lag_are_the_same_comparison() {
        let partial = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG).with_supply(vec![
            SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 4,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
            },
        ]);
        let lag = StateLag::new(4, 14);
        assert_eq!(lag.blocks(), 10);
        assert!(lag.is_lagging());
        // The coverage verdict is the lag verdict, on the same two heights.
        assert_eq!(partial.supply_lag(), Some(lag));
        assert_eq!(
            partial.supply_coverage(),
            SupplyCoverage::Unavailable { state_tip: Some(4), fork_choice_tip: 14 }
        );

        // Agreement is a zero lag, and vice versa — one predicate, both readings.
        let complete = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG).with_supply(vec![
            SupplyEpoch {
                epoch: 0,
                start_height: 0,
                end_height: 14,
                measured_coinbase: 123,
                expected_coinbase: 123,
                fees: 0,
            },
        ]);
        assert_eq!(complete.supply_lag(), Some(StateLag::new(14, 14)));
        assert!(!complete.supply_lag().unwrap().is_lagging());
        assert_eq!(complete.supply_coverage(), SupplyCoverage::Complete);

        // No ledger rows ⇒ no lag can be computed, and coverage is Unavailable for
        // that reason rather than for a disagreement. The two are different facts.
        let no_rows = Telemetry::assemble(14, Some(8), 75, 0, 3, 0, MAX_LAG);
        assert_eq!(no_rows.supply_lag(), None);
        assert_eq!(
            no_rows.supply_coverage(),
            SupplyCoverage::Unavailable { state_tip: None, fork_choice_tip: 14 }
        );
    }

    /// A state tip can never exceed fork choice (fork choice is where headers land
    /// first), and if arithmetic ever says otherwise the answer is zero rather than
    /// an underflow — the `saturating_sub` discipline #73/#87 already apply to every
    /// other derived gap on this surface.
    #[test]
    fn state_lag_never_underflows_and_zero_is_not_lagging() {
        assert_eq!(StateLag::new(14, 4).blocks(), 0);
        assert!(!StateLag::new(14, 4).is_lagging());
        assert_eq!(StateLag::new(0, 0).blocks(), 0);
        assert!(!StateLag::new(0, 0).is_lagging());
        assert!(StateLag::new(0, 1).is_lagging());
    }

    /// **Acceptance (#117): a `0x01` payload is REJECTED, not best-effort parsed.**
    ///
    /// This is the property the version byte exists for. A stale reader against a
    /// new node, or a new reader against a stale node, must fail loudly rather than
    /// return a snapshot whose identity half is silently absent — which would read
    /// exactly like "this node finalized nothing", the healthiest-looking possible
    /// rendering of an unknown.
    #[test]
    fn a_v1_telemetry_payload_is_rejected_not_best_effort_parsed() {
        let t = Telemetry::assemble(3776, Some(3776), 75, 0, 3, 2, MAX_LAG);
        let old = v1_payload(&t);

        // The old encoding is genuinely the prefix of the new one — i.e. the failure
        // mode being guarded against is real and not hypothetical.
        assert_eq!(&t.to_bytes()[1..old.len()], &old[1..], "v2 appends, it does not reshuffle");
        assert!(t.to_bytes().len() > old.len());

        assert!(
            matches!(Telemetry::from_bytes(&old), Err(CodecError::BadVersion { got: 1 })),
            "a 0x01 payload must be rejected on the version byte"
        );

        // And the tail is not optional: a current-version-stamped payload that
        // stops where v1 stopped is truncated, not "current with the tail absent".
        let mut stamped = old.clone();
        stamped[0] = RPC_VERSION;
        assert!(
            matches!(Telemetry::from_bytes(&stamped), Err(CodecError::Truncated { .. })),
            "the versioned tails are mandatory at 0x03"
        );
    }
}
