//! **Send-path stall detection** (issue #289) — the signal that separates a
//! connection the kernel still calls `ESTABLISHED` from a connection that is
//! actually carrying our bytes.
//!
//! ## The defect this closes
//!
//! Drill D4 (2+2 partition → heal, 2026-08-07) left node2 twenty minutes behind
//! the rest of the net *after the network was whole again*. `iptables -j DROP` is
//! silent, so the partition-era sockets stayed `ESTABLISHED` with ~191 KB stuck in
//! their send queues; [`crate::addrman`] counts a live handle as a peer it already
//! has, so nothing re-dialed. Convergence arrived when the **kernel** gave up on
//! the socket — not on any decision the node made — and every field on node2's own
//! TELEMETRY read healthy throughout (`slag=0 mready=synced peers=6 dialable=3/3`).
//!
//! ## The signal is *no progress*, not *slowness*
//!
//! This module holds one small state machine per connection, and its whole
//! discipline is in [`SendProgress::observe`]:
//!
//! * bytes the kernel **accepted** restart the window, however few and however
//!   slowly they arrive — a merely-slow WAN link never trips this;
//! * a backlog that drains to empty clears the state entirely;
//! * only a backlog that sits with **zero** accepted bytes for
//!   [`SEND_STALL_WINDOW_MS`] is a stall.
//!
//! A false close on a healthy link is its own liveness cost, so the bias is
//! deliberately toward leaving connections alone. What a stall verdict costs when
//! it *is* wrong is one reconnect through the existing ladder: the address stays
//! `dialable`, its backoff is untouched, and the peer is never scored — a dead
//! path is not misbehaviour (the S5 / `is_peer_fault` discipline).
//!
//! ## No clock of its own
//!
//! Every entry point takes `now_ms` from the caller, exactly like
//! [`crate::addrman`]. That is what makes the decision unit-testable without a
//! wedged socket, which is the only way this defect can be tested at all — the
//! condition it detects took a live intercontinental partition to produce once.

/// **How long one write may block the node loop when the kernel send buffer is
/// full.** `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// Before #289 the send path was `write_all` with no timeout at all: a socket
/// whose peer had stopped reading could park the node's main loop for as long as
/// the kernel was willing to retransmit. Any finite value is an improvement; this
/// one is chosen *shorter* than the WAN RTT deliberately (Phase B-WAN measured
/// 68–223 ms across the four hosts, `docs/m10-t03-phase-b-wan-run.md`). A full
/// send buffer takes at least a round trip to open up, and the node loop is not
/// where we want to wait for it: 100 ms is long enough that an ordinary
/// congestion pause still completes inline, and short enough that the remainder
/// lands in the backlog and the loop keeps its cadence — which is also what makes
/// the backlog a *measurement* rather than an accident.
///
/// It only binds when the buffer is full. A healthy socket never reaches it.
pub const SEND_WRITE_TIMEOUT_MS: u64 = 100;

/// **How long a connection may hold undelivered bytes with zero progress before
/// it is no longer a serving path.** `[devnet-placeholder]` testnet-tunable, NOT
/// frozen.
///
/// Bounded from below by what an honest link does: a routing blip or a peer's GC
/// pause produces seconds of zero progress, and a recovering link inside TCP's
/// RTO backoff can produce tens. 120 s is ~540× the worst RTT measured on the T0
/// net (223 ms) and 1.6× the 75 s block cadence, so a peer that takes even one
/// block's worth of our traffic per cadence never trips it. Any accepted byte
/// restarts the window, so "slow" cannot accumulate into "stalled".
///
/// Bounded from above by the incident: D4's heal was at 16:32:53 and the wedged
/// socket did not disappear until 16:51:32 — the kernel's own give-up took about
/// nineteen minutes. At 120 s this node decides in a ninth of that, and it decides
/// rather than waiting.
pub const SEND_STALL_WINDOW_MS: u64 = 120_000;

/// **How many undelivered bytes count as a backlog.** `[devnet-placeholder]`
/// testnet-tunable, NOT frozen.
///
/// One byte, and the reason is that the kernel has already applied the real
/// threshold. Nothing reaches this backlog until the socket refused it with its
/// whole send buffer full for [`SEND_WRITE_TIMEOUT_MS`]; a node holding *any*
/// undelivered byte for two minutes has a peer that is not reading. Raising this
/// would buy extra conservatism at the price of the quiet node — the participant
/// with least to gossip is the one whose backlog stays smallest, and it is exactly
/// the T1 participant #289 is worried about.
pub const SEND_STALL_MIN_BACKLOG_BYTES: u64 = 1;

/// **Maximum undelivered bytes held for one peer.** `[devnet-placeholder]`
/// testnet-tunable, NOT frozen.
///
/// 2 × [`crate::wire::MAX_PAYLOAD`], the same shape and the same reason as
/// [`crate::transport::MAX_INBOX_BYTES_PER_PEER`] on the receive side: one legal
/// maximum-size frame can never be refused by its own arrival. Past the cap whole
/// frames are dropped rather than queued — a full queue is congestion, not proof
/// of malice, and the connection carries on until the *window* rules on it. The
/// backlog never holds a partial frame it did not already start sending, so
/// dropping at this boundary cannot desynchronise the peer's framing.
pub const MAX_SEND_BACKLOG_BYTES_PER_PEER: u64 = 16 * 1024 * 1024;

/// One connection's send-progress state — the send-side half of "is this socket
/// carrying anything".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendProgress {
    /// Bytes handed to us that the kernel has not taken.
    backlog: u64,
    /// When the current zero-progress window started. `None` whenever the backlog
    /// is empty — nothing undelivered is not a stall, it is an idle socket.
    stalled_since_ms: Option<u64>,
    /// Whole frames refused because the backlog was at its cap (ops only, never
    /// a scoring input).
    dropped_frames: u64,
}

impl SendProgress {
    pub fn new() -> Self {
        SendProgress::default()
    }

    /// Record the outcome of one write attempt: `accepted` bytes taken by the
    /// kernel, `backlog` bytes still undelivered afterwards.
    ///
    /// The three-way rule is the whole policy — see the module docs.
    pub fn observe(&mut self, now_ms: u64, accepted: u64, backlog: u64) {
        self.backlog = backlog;
        if backlog == 0 {
            // Fully delivered: there is nothing to be stalled about.
            self.stalled_since_ms = None;
        } else if accepted > 0 || self.stalled_since_ms.is_none() {
            // Progress restarts the window; so does the first byte that fails to
            // go out. "Slow" therefore never accumulates into "stalled".
            self.stalled_since_ms = Some(now_ms);
        }
    }

    /// Record a whole frame refused at the backlog cap.
    pub fn note_dropped_frame(&mut self) {
        self.dropped_frames = self.dropped_frames.saturating_add(1);
    }

    /// Undelivered bytes held for this connection.
    pub fn backlog(&self) -> u64 {
        self.backlog
    }

    /// Whole frames refused at the cap over this connection's life.
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }

    /// How long this connection has held a backlog without the kernel taking a
    /// single byte. `0` when there is nothing undelivered.
    pub fn stalled_for_ms(&self, now_ms: u64) -> u64 {
        match self.stalled_since_ms {
            Some(t) => now_ms.saturating_sub(t),
            None => 0,
        }
    }

    /// **The decision.** A connection is stalled when it holds at least
    /// [`SEND_STALL_MIN_BACKLOG_BYTES`] and has made no progress for `window_ms`.
    ///
    /// `window_ms` is a parameter rather than the constant so the transport can be
    /// re-tuned (and so tests do not have to wait two minutes for a verdict).
    pub fn is_stalled(&self, now_ms: u64, window_ms: u64) -> bool {
        self.backlog >= SEND_STALL_MIN_BACKLOG_BYTES
            && matches!(self.stalled_since_ms, Some(t) if now_ms.saturating_sub(t) >= window_ms)
    }
}

/// The journal line a dropped connection leaves behind (issue #289).
///
/// A stall is invisible from inside the node that suffers it — that is the
/// finding, not a detail of it — so the drop must say what it saw. `addr` is the
/// remote endpoint when the transport knows one.
pub fn stall_line(peer: u64, addr: Option<&str>, backlog: u64, stalled_ms: u64) -> String {
    let addr = addr.unwrap_or("unknown");
    format!("SENDSTALL peer={peer} addr={addr} backlog={backlog} ms={stalled_ms} action=drop")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backlog_that_never_moves_is_stalled_at_the_window_and_not_before() {
        let mut p = SendProgress::new();
        // t=0: 191 KB offered, the kernel takes none of it (D4's socket).
        p.observe(0, 0, 191_846);
        assert!(!p.is_stalled(0, SEND_STALL_WINDOW_MS));
        assert!(
            !p.is_stalled(SEND_STALL_WINDOW_MS - 1, SEND_STALL_WINDOW_MS),
            "one millisecond short of the window is not a verdict"
        );
        assert!(p.is_stalled(SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
        assert_eq!(p.backlog(), 191_846);
        assert_eq!(p.stalled_for_ms(SEND_STALL_WINDOW_MS), SEND_STALL_WINDOW_MS);
    }

    #[test]
    fn any_accepted_byte_restarts_the_window() {
        // The task's central constraint: the signal is no-progress, not slowness.
        // This socket is pathologically slow — one byte per window — and must
        // never be dropped.
        let mut p = SendProgress::new();
        let mut now = 0u64;
        p.observe(now, 0, 1_000_000);
        for _ in 0..10 {
            now += SEND_STALL_WINDOW_MS - 1;
            assert!(!p.is_stalled(now, SEND_STALL_WINDOW_MS));
            p.observe(now, 1, 999_999);
            assert!(
                !p.is_stalled(now, SEND_STALL_WINDOW_MS),
                "a single accepted byte is progress and restarts the clock"
            );
        }
        // …and the moment progress stops, the window runs from *that* point.
        assert!(!p.is_stalled(now + SEND_STALL_WINDOW_MS - 1, SEND_STALL_WINDOW_MS));
        assert!(p.is_stalled(now + SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
    }

    #[test]
    fn a_drained_backlog_clears_the_state_entirely() {
        let mut p = SendProgress::new();
        p.observe(0, 0, 4_096);
        assert!(p.is_stalled(SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
        // The link comes back and the queue empties.
        p.observe(SEND_STALL_WINDOW_MS, 4_096, 0);
        assert!(!p.is_stalled(SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
        assert_eq!(p.stalled_for_ms(SEND_STALL_WINDOW_MS), 0, "no window is running");
        // A fresh backlog starts a fresh window rather than inheriting the old one.
        p.observe(SEND_STALL_WINDOW_MS, 0, 10);
        assert!(!p.is_stalled(SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
        assert!(p.is_stalled(2 * SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
    }

    #[test]
    fn an_idle_socket_is_never_stalled() {
        // Nothing offered, nothing owed: the detector must not fire on a quiet
        // connection, which is most of them on a low-traffic net.
        let mut p = SendProgress::new();
        p.observe(0, 0, 0);
        assert!(!p.is_stalled(10 * SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
        p.observe(1_000, 512, 0);
        assert!(!p.is_stalled(10 * SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS));
    }

    #[test]
    fn the_backlog_cap_is_one_frame_wider_than_a_maximum_size_frame() {
        // Same shape and reason as the receive side: a legal maximum-size frame
        // can never be refused by its own arrival.
        assert_eq!(MAX_SEND_BACKLOG_BYTES_PER_PEER, 2 * crate::wire::MAX_PAYLOAD as u64);
        assert!(
            SEND_STALL_WINDOW_MS > 100 * SEND_WRITE_TIMEOUT_MS,
            "the verdict must be a window, never a single refused write"
        );
    }

    #[test]
    fn the_journal_line_names_what_was_seen() {
        assert_eq!(
            stall_line(7, Some("18.202.166.126:9444"), 191_846, 121_000),
            "SENDSTALL peer=7 addr=18.202.166.126:9444 backlog=191846 ms=121000 action=drop"
        );
        assert_eq!(
            stall_line(3, None, 64, 120_000),
            "SENDSTALL peer=3 addr=unknown backlog=64 ms=120000 action=drop"
        );
    }
}
