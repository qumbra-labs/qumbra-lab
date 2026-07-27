//! Node **telemetry** for finality-stall observability (M10-T0-2, issue #63).
//!
//! The Crosslink feature-net stall (design §4 status, 2026-07-24) was painful in
//! part because an operator had no first-class read of *how badly* finality had
//! fallen behind. This module is the operator surface: a single versioned
//! [`Telemetry`] snapshot carrying the finality regime plus the numbers a stall
//! runbook (and the T0-3 soak monitor) actually watch — stall depth, how long
//! finality has been stuck, peers, mempool, heights, and epoch.
//!
//! Wire discipline mirrors the N6 surfaces ([`crate::rpc::NodeStatus`]): a `0x01`
//! lead version byte, little-endian fixed fields, and reject-unknown-version /
//! reject-trailing on decode (§0). Peer count and epoch are **injected** from the
//! P2P layer (they are not node-state — the N1 traits do not carry them), so the
//! node-owned half is assembled from live state and the network half is stamped in
//! by the p2p glue via [`crate::rpc::NodeRpc::set_net_facts`].

use qlab_cbserver::codec::CodecError;
use qlab_devnet::ebbflow::FinalityStatus;
use qlab_devnet::halt::regime as halt_regime;

use crate::rpc::{Reader, RPC_VERSION};

/// Wire discriminant for [`FinalityStatus::Final`].
const STATUS_FINAL: u8 = 0;
/// Wire discriminant for [`FinalityStatus::Degraded`].
const STATUS_DEGRADED: u8 = 1;
/// Wire discriminant for [`FinalityStatus::Halting`] (halt-height upgrade, #74).
const STATUS_HALTING: u8 = 2;
/// Wire discriminant for [`FinalityStatus::Halted`].
const STATUS_HALTED: u8 = 3;

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
    /// − finalized block timestamp; measured from genesis if nothing is finalized).
    /// Derived from block timestamps, so it is deterministic — no wall clock.
    pub last_finalized_age_secs: u64,
    /// Connected peer count (injected from the P2P layer).
    pub peer_count: u64,
    /// Pending mempool size.
    pub mempool_size: u64,
    /// Current committee epoch (injected from the P2P/committee layer).
    pub epoch: u64,
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
        }
    }

    /// `version(0x01) ‖ finality(u8) ‖ tip(8 LE) ‖ has_final(u8) ‖
    /// [final_height(8 LE) if has] ‖ stall_depth(8) ‖ age_secs(8) ‖
    /// peer_count(8) ‖ mempool_size(8) ‖ epoch(8)`.
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
        bad_ver[0] = 2;
        assert!(matches!(
            Telemetry::from_bytes(&bad_ver),
            Err(CodecError::BadVersion { got: 2 })
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
}
