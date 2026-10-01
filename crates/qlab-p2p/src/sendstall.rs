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
//! ## The signal is a drain floor per window (lab #785 F5-5a, W3)
//!
//! This module holds one small state machine per connection, and its whole
//! discipline is in [`SendProgress::observe`]:
//!
//! * a backlog must drain at least [`SEND_DRAIN_FLOOR_BYTES`] per
//!   [`SEND_STALL_WINDOW_MS`]; reaching the floor restarts the window — a
//!   merely-slow WAN link (any rate above ≈ 550 B/s) never trips this;
//! * a backlog that drains to empty clears the state entirely;
//! * a backlog that does not reach the floor within one window is a stall.
//!
//! *(Until F5-5a the rule was "any accepted byte restarts the window" — the
//! signal was no-progress, not slowness. With the node-wide send budget that
//! became an attack: a reader accepting one byte per window pinned a full
//! per-peer backlog forever and, four of them, the whole budget. The floor is
//! far below any honest link and far above a trickle.)*
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
pub const MAX_SEND_BACKLOG_BYTES_PER_PEER: u64 = 32 * 1024 * 1024;

/// **Maximum undelivered bytes held across ALL peers** (lab #785 F5-5a, Q-C5).
/// `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// The per-peer cap bounds one queue; nothing bounded the sum, so a node serving
/// bundle blocks to every connected peer could hold `peers ×` 32 MiB. 128 MiB is
/// four peers' worth of full backlogs. At it the transport sheds the
/// connection holding the most backlog (W3) rather than refuse a healthy
/// peer's frame; a frame larger than the whole cap is refused whole.
/// F5-6 measures node RSS serving bundle blocks before it is called safe.
pub const MAX_SEND_BACKLOG_BYTES_TOTAL: u64 = 128 * 1024 * 1024;

/// **The bytes a backlog must drain per [`SEND_STALL_WINDOW_MS`]** (lab #785
/// F5-5a, W3). `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// 64 KiB per two minutes is ≈ 550 B/s — orders of magnitude below any link
/// that carries this protocol at all, and far above a reader that trickles a
/// byte at a time to keep a 32 MiB backlog pinned.
pub const SEND_DRAIN_FLOOR_BYTES: u64 = 64 * 1024;
const _: () = assert!(MAX_SEND_BACKLOG_BYTES_TOTAL >= MAX_SEND_BACKLOG_BYTES_PER_PEER);

/// One connection's send-progress state — the send-side half of "is this socket
/// carrying anything".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendProgress {
    /// Bytes handed to us that the kernel has not taken.
    backlog: u64,
    /// When the current window started. `None` whenever the backlog is empty —
    /// nothing undelivered is not a stall, it is an idle socket.
    stalled_since_ms: Option<u64>,
    /// Bytes drained in the current window (lab #785 F5-5a): reaching
    /// [`SEND_DRAIN_FLOOR_BYTES`] restarts the window.
    drained_in_window: u64,
    /// When the kernel last accepted any byte (the node-wide shed's tie-break:
    /// oldest first). `None` if it never has.
    last_accept_ms: Option<u64>,
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
        if accepted > 0 {
            self.last_accept_ms = Some(now_ms);
        }
        if backlog == 0 {
            // Fully delivered: there is nothing to be stalled about.
            self.stalled_since_ms = None;
            self.drained_in_window = 0;
            return;
        }
        if self.stalled_since_ms.is_none() {
            // The first byte that fails to go out opens a window.
            self.stalled_since_ms = Some(now_ms);
            self.drained_in_window = 0;
        }
        self.drained_in_window = self.drained_in_window.saturating_add(accepted);
        if self.drained_in_window >= SEND_DRAIN_FLOOR_BYTES {
            // The floor met: a fresh window (lab #785 F5-5a, W3).
            self.stalled_since_ms = Some(now_ms);
            self.drained_in_window = 0;
        }
    }

    /// When the kernel last accepted a byte of this connection's (lab #785
    /// F5-5a); `None` if never.
    pub fn last_accept_ms(&self) -> Option<u64> {
        self.last_accept_ms
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

    /// How long this connection's current window has run without draining the
    /// floor. `0` when there is nothing undelivered.
    pub fn stalled_for_ms(&self, now_ms: u64) -> u64 {
        match self.stalled_since_ms {
            Some(t) => now_ms.saturating_sub(t),
            None => 0,
        }
    }

    /// **The decision.** A connection is stalled when it holds at least
    /// [`SEND_STALL_MIN_BACKLOG_BYTES`] and has not drained
    /// [`SEND_DRAIN_FLOOR_BYTES`] within `window_ms`.
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

    /// Lab #785 F5-5a, W3 — the inversion of #289's "any accepted byte
    /// restarts the window": a reader trickling a byte just inside every
    /// window is stalled when the first window closes without the floor.
    #[test]
    fn a_one_byte_per_window_reader_is_stalled() {
        let mut p = SendProgress::new();
        p.observe(0, 0, 1_000_000);
        p.observe(SEND_STALL_WINDOW_MS - 1, 1, 999_999);
        assert!(!p.is_stalled(SEND_STALL_WINDOW_MS - 1, SEND_STALL_WINDOW_MS));
        assert!(p.is_stalled(SEND_STALL_WINDOW_MS, SEND_STALL_WINDOW_MS), "one byte is not the floor");
        assert_eq!(p.last_accept_ms(), Some(SEND_STALL_WINDOW_MS - 1));
        assert_eq!(SEND_DRAIN_FLOOR_BYTES, 64 * 1024);
    }

    /// Lab #785 F5-5a, W3: a slow but honest link — the floor drained in
    /// every window, in small pieces — is never stalled, however long the
    /// backlog lasts; partial drains add up within a window.
    #[test]
    fn draining_the_floor_each_window_is_never_stalled() {
        let mut p = SendProgress::new();
        let (mut now, mut backlog) = (0u64, 40 * SEND_DRAIN_FLOOR_BYTES);
        p.observe(now, 0, backlog);
        for _ in 0..20 {
            for _ in 0..4 {
                now += SEND_STALL_WINDOW_MS / 5;
                backlog -= SEND_DRAIN_FLOOR_BYTES / 4;
                p.observe(now, SEND_DRAIN_FLOOR_BYTES / 4, backlog);
                assert!(!p.is_stalled(now, SEND_STALL_WINDOW_MS), "at {now}");
            }
        }
        assert!(p.backlog() > 0, "still owed, never stalled");
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
