//! Dual transport: an in-process simulator and a real `std::net` TCP transport,
//! behind one [`Transport`] trait. No async runtime — TCP uses blocking reader
//! threads plus short-lived outbound connector threads. Readers are unblocked on
//! shutdown by `TcpStream::shutdown`; connectors may finish their kernel wait
//! later but never hold up the node loop or shutdown. The same poll/step
//! [`crate::node::P2pNode`] logic drives both transports.
//!
//! A "frame" here is one whole envelope byte-buffer (`MAGIC ‖ header ‖ payload`).
//! The transport moves frames; framing/validation is [`crate::wire`]. Delivery is
//! non-blocking on the receive side: [`Transport::poll`] drains everything that
//! has arrived since the last call, so a node's `tick()` is deterministic.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::peer::PeerId;
use crate::sendstall::{
    SendProgress, MAX_SEND_BACKLOG_BYTES_PER_PEER, SEND_STALL_WINDOW_MS, SEND_WRITE_TIMEOUT_MS,
};
use crate::wire::{FrameHeader, HEADER_LEN};

/// Transport-level errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// No route/link/socket to the target peer.
    NotConnected(PeerId),
    /// Underlying I/O failure (message rendered to a string — transports differ).
    Io(String),
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransportError::NotConnected(p) => write!(f, "peer {p:?} not connected"),
            TransportError::Io(e) => write!(f, "transport io: {e}"),
        }
    }
}
impl std::error::Error for TransportError {}

/// Result of starting an outbound dial.
///
/// A real TCP connect may sit in the kernel's SYN retry loop for minutes. The
/// transport therefore owns that wait and reports [`Pending`](DialStart::Pending)
/// immediately; the node later collects the result through
/// [`Transport::poll_dials`]. Deterministic transports may complete inline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialStart {
    Connected(PeerId),
    Pending,
    Failed(TransportError),
}

/// One connection reported stalled by [`Transport::stalled_peers`] (issue #289),
/// with the evidence that produced the verdict.
///
/// `backlog` is the number `ss` calls `Send-Q` — 191,846 bytes on D4's wedged
/// socket — and `stalled_ms` is how long none of it moved. Both are carried on
/// the report because they are only true at the instant of the verdict, and
/// because the operator has no other way to see them: this condition is invisible
/// on the node's own TELEMETRY, which is the finding #289 actually reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallReport {
    pub peer: PeerId,
    pub backlog: u64,
    pub stalled_ms: u64,
}

/// One outbound dial that completed after [`DialStart::Pending`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialCompletion {
    pub addr: String,
    pub elapsed_ms: u64,
    pub result: Result<PeerId, TransportError>,
}

/// Which side opened a connection (issue #459).
///
/// **We dialed it** vs **it arrived**, decided by the socket that produced the
/// handle and never re-derived afterwards. The distinction is the whole of #459:
/// [`DialCompletion`] already journals every outbound open, and until this type
/// existed there was no fact anywhere in the process that an inbound one had
/// happened at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnDirection {
    /// This node accepted the connection.
    In,
    /// This node dialed out.
    Out,
}

impl ConnDirection {
    /// The `dir=` token on the journal line.
    pub fn token(self) -> &'static str {
        match self {
            ConnDirection::In => "in",
            ConnDirection::Out => "out",
        }
    }
}

/// Why a session ended (issue #459) — the `why=` token on the close line.
///
/// Three outcomes and not two, because "the peer hung up" and "we dropped it"
/// are different operational events and an operator reading a close line at 3am
/// should not have to correlate it with a `SENDSTALL` line to tell them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The remote closed cleanly — the socket returned end-of-file.
    Eof,
    /// The read failed: a reset, a timeout, or a frame this build refused
    /// ([`read_frame`] fails the connection on a malformed header).
    Err,
    /// **We** closed it — [`Transport::disconnect`], which today has exactly one
    /// caller ([`crate::node::P2pNode::drop_stalled_connections`], issue #289).
    Evicted,
}

impl CloseReason {
    /// The `why=` token on the journal line.
    pub fn token(self) -> &'static str {
        match self {
            CloseReason::Eof => "eof",
            CloseReason::Err => "err",
            CloseReason::Evicted => "evicted",
        }
    }
}

/// **One connection-lifecycle fact the node loop has not journalled yet**
/// (issue #459).
///
/// Same shape of contract as [`DialCompletion`]: the transport records the fact
/// on whichever thread observed it (the acceptor, or a reader thread at EOF) and
/// the *node loop* drains and prints it, so the ordering of the journal is the
/// loop's and no log line is ever emitted from a socket thread.
///
/// `addr` is `Option` everywhere for one reason: `getpeername` can fail on a
/// socket that died between accept and inspection. An unknown address is printed
/// as `addr=unknown`, following [`crate::sendstall::stall_line`] — the line still
/// exists, which is the property #459 is about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnEvent {
    /// An inbound connection the accept path admitted, past the inbound cap.
    Accepted { peer: PeerId, addr: Option<String> },
    /// An inbound connection **refused at the cap** — closed at accept, never
    /// registered, no reader thread. Its own event because a node at its cap and
    /// a node nobody is dialing look identical without it.
    Capped { addr: Option<String>, cap: usize },
    /// A session ended, in either direction.
    Closed {
        peer: PeerId,
        addr: Option<String>,
        dir: ConnDirection,
        held_ms: u64,
        why: CloseReason,
    },
    /// Events dropped because the buffer between two drains filled
    /// ([`MAX_BUFFERED_CONN_EVENTS`]).
    ///
    /// 🔴 **Synthesised at drain time so a bounded buffer can never read as a
    /// quiet network.** Silent truncation presenting as completeness is a pattern
    /// this repo has been bitten by repeatedly (the light-client scan, #309/#312,
    /// was the ninth instance and the first found by a user's real money).
    Lost { count: u64 },
}

/// A frame mover. Send delivers one whole frame to a peer; poll drains all
/// frames received since the last call (with the local peer handle they came
/// from). Both are non-blocking.
pub trait Transport {
    fn send(&self, to: PeerId, frame: &[u8]) -> Result<(), TransportError>;
    fn poll(&self) -> Vec<(PeerId, Vec<u8>)>;
    /// Peers currently reachable through this transport.
    fn peers(&self) -> Vec<PeerId>;

    /// Start an **outbound** connection to `addr` without waiting on network I/O
    /// (issue #83, #107). This is the mechanism half of auto-connect — the policy
    /// (whom to dial, how often, under which cap) is [`crate::addrman`].
    ///
    /// A transport that returns [`DialStart::Pending`] must later publish exactly
    /// one [`DialCompletion`] from [`Transport::poll_dials`]. Both shipped
    /// transports implement this contract, so policy remains shared between the
    /// deterministic simulator and real sockets.
    fn dial(&self, addr: &str) -> DialStart {
        DialStart::Failed(TransportError::Io(format!("transport cannot dial {addr}")))
    }

    /// Drain outbound dial completions. Deterministic transports complete in
    /// [`Transport::dial`] and have nothing to report here.
    fn poll_dials(&self) -> Vec<DialCompletion> {
        Vec::new()
    }

    /// **Drain connection-lifecycle events** (issue #459) — accepts, capped-out
    /// refusals, and session closes, for the node loop to journal.
    ///
    /// Exactly [`Transport::poll_dials`]'s contract, and for the same reason: the
    /// facts happen on the acceptor and reader threads, and the journal is the
    /// node loop's. A transport with no accept path reports nothing, which keeps
    /// every deterministic in-process sim byte-identical in its output.
    fn poll_conn_events(&self) -> Vec<ConnEvent> {
        Vec::new()
    }

    /// **The live handles this transport ACCEPTED**, or `None` when it cannot
    /// know (issue #459).
    ///
    /// `None` is the honest answer for [`InProcTransport`]: the hub links two
    /// nodes symmetrically and the accepting side observes no event, so a
    /// direction reported there would be invented. The caller must render that as
    /// unknown rather than folding it into "outbound" — `pin=0` on a node holding
    /// four inbound sessions is a worse lie than `pin=-`.
    fn inbound_peers(&self) -> Option<Vec<PeerId>> {
        None
    }

    /// The remote endpoint behind a local handle, if this transport knows one
    /// (issue #91). Read-only, additive, and **not** a reachability claim — a
    /// dialable address is still only earned by a successful outbound dial (#86).
    ///
    /// This exists so [`crate::ratelimit`] can key a budget on something an
    /// attacker cannot change by reconnecting. Returning `None` is always safe:
    /// the limiter falls back to the handle.
    fn peer_addr(&self, _id: PeerId) -> Option<String> {
        None
    }

    /// Frames the transport dropped because its receive queue was full
    /// (issue #91, gap 2). Zero on a transport that cannot drop.
    fn dropped_frames(&self) -> u64 {
        0
    }

    /// **Connections that are open but are not carrying our bytes** (issue #289):
    /// each has held an undelivered backlog with zero progress for the transport's
    /// stall window ([`crate::sendstall`]).
    ///
    /// This is a *liveness* signal, not a fault: the peer may be blameless and
    /// usually is — a silently dropped path (`iptables -j DROP`, a dead router)
    /// leaves the socket `ESTABLISHED` on both sides with nobody at fault. The
    /// caller's only sanctioned response is to close the connection and let
    /// [`crate::addrman`]'s existing ladder re-dial. **Never a scoring input.**
    ///
    /// Transports without a send queue (the in-process hub) have nothing to
    /// report and return empty, which keeps every deterministic sim unchanged.
    ///
    /// The report carries its own evidence rather than making the caller ask
    /// again: the numbers are read under the transport's lock at the moment of
    /// the verdict, and a second call would be a different instant.
    fn stalled_peers(&self) -> Vec<StallReport> {
        Vec::new()
    }

    /// Close one connection. Idempotent — a handle that is already gone is a
    /// no-op. This is the only action [`Transport::stalled_peers`] licenses.
    fn disconnect(&self, _id: PeerId) {}
}

// ==========================================================================
// In-process transport
// ==========================================================================

/// A shared in-process network hub: per-peer inboxes + a link (adjacency) set so
/// tests can wire arbitrary topologies and simulate partition/heal. Fully
/// deterministic — no threads, no timing.
#[derive(Default)]
pub struct InProcHub {
    inboxes: Mutex<HashMap<PeerId, Vec<(PeerId, Vec<u8>)>>>,
    links: Mutex<HashSet<(PeerId, PeerId)>>,
    /// Address → node handle, for [`Transport::dial`] (issue #83). A node that
    /// never calls [`InProcHub::bind_addr`] is **undialable** — the in-process
    /// model of the outbound-only participant T1 accepts.
    addrs: Mutex<HashMap<String, PeerId>>,
}

impl InProcHub {
    pub fn new() -> Arc<InProcHub> {
        Arc::new(InProcHub::default())
    }

    /// Register a node's inbox.
    pub fn register(&self, id: PeerId) {
        self.inboxes.lock().unwrap().entry(id).or_default();
    }

    /// Declare `id` reachable at `addr` — the in-process equivalent of binding a
    /// listener. Only bound nodes can be dialed.
    pub fn bind_addr(&self, addr: &str, id: PeerId) {
        self.addrs.lock().unwrap().insert(addr.to_string(), id);
    }

    /// Resolve a bound address, if any.
    fn resolve(&self, addr: &str) -> Option<PeerId> {
        self.addrs.lock().unwrap().get(addr).copied()
    }

    /// Connect `a` and `b` bidirectionally (both can send to each other).
    pub fn link(&self, a: PeerId, b: PeerId) {
        let mut l = self.links.lock().unwrap();
        l.insert((a, b));
        l.insert((b, a));
    }

    /// Cut the link both ways (partition).
    pub fn unlink(&self, a: PeerId, b: PeerId) {
        let mut l = self.links.lock().unwrap();
        l.remove(&(a, b));
        l.remove(&(b, a));
    }

    fn linked(&self, a: PeerId, b: PeerId) -> bool {
        self.links.lock().unwrap().contains(&(a, b))
    }

    fn deliver(&self, from: PeerId, to: PeerId, frame: &[u8]) -> Result<(), TransportError> {
        if !self.linked(from, to) {
            return Err(TransportError::NotConnected(to));
        }
        let mut boxes = self.inboxes.lock().unwrap();
        let inbox = boxes.get_mut(&to).ok_or(TransportError::NotConnected(to))?;
        inbox.push((from, frame.to_vec()));
        Ok(())
    }

    fn drain(&self, id: PeerId) -> Vec<(PeerId, Vec<u8>)> {
        let mut boxes = self.inboxes.lock().unwrap();
        boxes.get_mut(&id).map(std::mem::take).unwrap_or_default()
    }

    /// The address `id` bound itself at, if any — the in-process analogue of a
    /// remote socket address. A node that never called [`InProcHub::bind_addr`]
    /// (the outbound-only participant) has none, exactly as it has no address on a
    /// real net.
    fn addr_of(&self, id: PeerId) -> Option<String> {
        self.addrs
            .lock()
            .unwrap()
            .iter()
            .find(|(_, &p)| p == id)
            .map(|(a, _)| a.clone())
    }

    fn neighbours(&self, id: PeerId) -> Vec<PeerId> {
        let l = self.links.lock().unwrap();
        let mut v: Vec<PeerId> = l.iter().filter(|(a, _)| *a == id).map(|(_, b)| *b).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// One node's endpoint onto an [`InProcHub`].
pub struct InProcTransport {
    id: PeerId,
    hub: Arc<InProcHub>,
}

impl InProcTransport {
    /// Attach a node with local id `id` to `hub` (registers its inbox).
    pub fn new(id: PeerId, hub: Arc<InProcHub>) -> Self {
        hub.register(id);
        InProcTransport { id, hub }
    }

    pub fn id(&self) -> PeerId {
        self.id
    }
}

impl Transport for InProcTransport {
    fn send(&self, to: PeerId, frame: &[u8]) -> Result<(), TransportError> {
        self.hub.deliver(self.id, to, frame)
    }
    fn poll(&self) -> Vec<(PeerId, Vec<u8>)> {
        self.hub.drain(self.id)
    }
    fn peers(&self) -> Vec<PeerId> {
        self.hub.neighbours(self.id)
    }
    fn peer_addr(&self, id: PeerId) -> Option<String> {
        self.hub.addr_of(id)
    }
    /// Close = cut the link both ways, the in-process model of dropping a socket.
    /// The hub keeps no send queue, so this transport never *reports* a stall
    /// ([`Transport::stalled_peers`] stays empty here); it can still be told to
    /// close a connection, which is what makes the node's own decision testable
    /// on the deterministic transport.
    fn disconnect(&self, id: PeerId) {
        self.hub.unlink(self.id, id);
    }
    /// Dial = resolve the bound address and link both ways. An address nobody
    /// bound is unreachable, exactly as a node behind a router is.
    fn dial(&self, addr: &str) -> DialStart {
        match self.hub.resolve(addr) {
            Some(target) if target != self.id => {
                self.hub.link(self.id, target);
                DialStart::Connected(target)
            }
            Some(_) => {
                DialStart::Failed(TransportError::Io("refusing to dial self".to_string()))
            }
            None => DialStart::Failed(TransportError::Io(format!("no route to {addr}"))),
        }
    }
}

// ==========================================================================
// TCP transport
// ==========================================================================

/// Read exactly one framed message from a blocking stream: the fixed header,
/// then the declared body. A malformed header (bad magic / oversize) is a fatal
/// `InvalidData` error that ends the connection.
fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; HEADER_LEN];
    stream.read_exact(&mut hdr)?;
    let fh = FrameHeader::parse(&hdr)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut frame = Vec::with_capacity(HEADER_LEN + fh.payload_len as usize);
    frame.extend_from_slice(&hdr);
    let mut body = vec![0u8; fh.payload_len as usize];
    stream.read_exact(&mut body)?;
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Maximum bytes held in the receive queue across **all** peers (issue #91,
/// gap 2). `[devnet-placeholder]` testnet-tunable, NOT frozen.
///
/// [`crate::wire::MAX_PAYLOAD`] bounds one frame; nothing bounded the *pile*. The
/// reader threads push as fast as the sockets deliver while `poll` only drains on
/// the node's tick, so a peer that sends faster than we process grew this queue
/// without limit — a per-message cap says nothing about concurrent or cumulative
/// use. 64 MiB is 8 maximum-size frames, against a measured ~262 MiB steady RSS
/// per node on the 2 GB T0 hosts (Phase B-WAN).
pub const MAX_INBOX_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum queued bytes attributable to any **one** peer. `[devnet-placeholder]`
/// testnet-tunable, NOT frozen. Fixed at 2 × [`crate::wire::MAX_PAYLOAD`] so a
/// single legal maximum-size frame can never be refused by its own arrival, and so
/// one peer cannot consume the whole global budget and starve the rest.
pub const MAX_INBOX_BYTES_PER_PEER: u64 = 16 * 1024 * 1024;

/// The receive queue, with the byte accounting that bounds it.
#[derive(Default)]
struct Inbox {
    frames: Vec<(PeerId, Vec<u8>)>,
    bytes: u64,
    per_peer: HashMap<PeerId, u64>,
}

/// One connection's write half **plus the backlog the kernel would not take**
/// (issue #289).
///
/// Before this the send path was `write_all` straight into the socket with no
/// timeout, which has two consequences and the incident needed both: a peer that
/// stops reading can park the node loop indefinitely, and — because nothing is
/// ever queued in user space — the node has **no measurement at all** of a socket
/// that is open but not moving. `ss` could see 191 KB stuck in the send queue;
/// the node could not.
///
/// The backlog only ever holds bytes the kernel refused after waiting
/// [`SEND_WRITE_TIMEOUT_MS`], and it is drained in order, so frames neither
/// interleave nor reorder. Frames are refused whole at
/// [`MAX_SEND_BACKLOG_BYTES_PER_PEER`] rather than truncated, so the peer's
/// framing cannot desynchronise.
struct PeerWriter {
    stream: TcpStream,
    /// Undelivered bytes, oldest first.
    pending: Vec<u8>,
    progress: SendProgress,
}

impl PeerWriter {
    fn new(stream: TcpStream) -> PeerWriter {
        PeerWriter { stream, pending: Vec::new(), progress: SendProgress::new() }
    }

    /// Queue one whole frame (or refuse it at the cap) and then hand the kernel
    /// as much of the backlog as it will take.
    fn send_frame(&mut self, now_ms: u64, frame: &[u8]) -> Result<(), TransportError> {
        if self.pending.len() as u64 + frame.len() as u64 > MAX_SEND_BACKLOG_BYTES_PER_PEER {
            // Congestion, not malice — the same boundary the receive queue draws.
            // The frame is dropped whole; the connection stays up and the stall
            // *window* is what rules on it.
            self.progress.note_dropped_frame();
        } else {
            self.pending.extend_from_slice(frame);
        }
        self.flush(now_ms)
    }

    /// Push the backlog at the socket once, recording what the kernel accepted.
    /// A short write is normal here and is **progress**, not failure.
    fn flush(&mut self, now_ms: u64) -> Result<(), TransportError> {
        let mut accepted = 0usize;
        let mut fatal: Option<TransportError> = None;
        while accepted < self.pending.len() {
            match self.stream.write(&self.pending[accepted..]) {
                Ok(0) => {
                    fatal = Some(TransportError::Io("socket accepted no bytes".to_string()));
                    break;
                }
                Ok(n) => accepted += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // SO_SNDTIMEO expiry: the buffer is full and stayed full. Keep the
                // remainder and let the window decide — one slow write is not a
                // verdict.
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e) => {
                    fatal = Some(TransportError::Io(e.to_string()));
                    break;
                }
            }
        }
        self.pending.drain(..accepted);
        self.progress.observe(now_ms, accepted as u64, self.pending.len() as u64);
        match fatal {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

struct TcpShared {
    inbox: Mutex<Inbox>,
    writers: Mutex<HashMap<PeerId, PeerWriter>>,
    running: AtomicBool,
    next_id: AtomicU64,
    /// Handles of connections we **accepted** (as opposed to dialed), so the
    /// inbound cap counts the right half (issue #83, scope 6).
    inbound: Mutex<HashSet<PeerId>>,
    /// Maximum simultaneous inbound connections; over it, a connection is closed
    /// at accept rather than absorbed.
    inbound_cap: AtomicU64,
    /// What is known about each live connection: remote endpoint (issue #91 — the
    /// accept path used to discard this, which left an inbound connection with no
    /// stable identity to key a rate budget on), which side opened it, and when
    /// (issue #459 — a close line without a duration cannot distinguish a peer
    /// that stayed an hour from one that hung up on the handshake).
    conns: Mutex<HashMap<PeerId, ConnMeta>>,
    /// Handles [`Transport::disconnect`] closed, so the reader thread that is
    /// about to observe the shutdown reports [`CloseReason::Evicted`] rather than
    /// attributing our own decision to the peer. Written **before** the socket is
    /// shut down, so the reader cannot lose the race.
    evicting: Mutex<HashSet<PeerId>>,
    /// Connection-lifecycle events awaiting the node loop (issue #459).
    conn_events: Mutex<Vec<ConnEvent>>,
    /// Events refused by [`MAX_BUFFERED_CONN_EVENTS`] since the last drain.
    conn_events_lost: AtomicU64,
    /// Frames refused because the receive queue was full.
    dropped: AtomicU64,
    /// Addresses with a connector thread currently waiting in DNS/TCP setup.
    dialing: Mutex<HashSet<String>>,
    /// Completed outbound connects, consumed by the main loop without waiting.
    dial_completions: Mutex<Vec<DialCompletion>>,
    /// This transport's monotonic origin. The send path needs a clock and the
    /// [`Transport`] trait deliberately has none (its callers pass `now_ms` where
    /// a *decision* is made); a socket's write outcome is a fact about real time,
    /// so it is timed here rather than fabricated from the node's logical clock.
    epoch: Instant,
    /// No-progress window before a connection is reported stalled (issue #289).
    /// Defaults to [`SEND_STALL_WINDOW_MS`]; tunable for tests / testnets.
    stall_window_ms: AtomicU64,
}

/// What the transport knows about one live connection.
struct ConnMeta {
    /// The remote endpoint, when `getpeername` answered.
    addr: Option<String>,
    /// Which side opened it.
    dir: ConnDirection,
    /// [`TcpShared::now_ms`] at registration — the base for the close line's
    /// `ms=`.
    opened_ms: u64,
}

/// **How many connection events may wait between two node-loop drains**
/// (issue #459). `[devnet-placeholder]`, testnet-tunable, NOT frozen.
///
/// The bound exists because the producer is the network and the consumer is one
/// call per `maintain` pass, and the measured main-loop period on the deployed
/// hosts has been as bad as 131 s (#107). 256 is ~2 events/s across a whole bad
/// pass, comfortably past anything the four-peer mesh does and far short of what
/// a connect flood on a public 9444 could do — which is why exceeding it emits
/// [`ConnEvent::Lost`] instead of quietly dropping the tail.
pub const MAX_BUFFERED_CONN_EVENTS: usize = 256;

impl TcpShared {
    fn alloc_id(&self) -> PeerId {
        PeerId(self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    /// Buffer one connection event for the node loop, or count it lost.
    fn note_conn_event(&self, ev: ConnEvent) {
        let mut buf = self.conn_events.lock().unwrap();
        if buf.len() >= MAX_BUFFERED_CONN_EVENTS {
            drop(buf);
            self.conn_events_lost.fetch_add(1, Ordering::SeqCst);
            return;
        }
        buf.push(ev);
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }

    /// Queue one received frame, or drop it if either byte bound is reached.
    /// Dropping is the whole response: the connection stays up (a full queue is
    /// congestion, not proof of malice — the same boundary [`crate::ratelimit`]
    /// draws), and the sender will find out through the protocol, not a ban.
    fn queue_frame(&self, id: PeerId, frame: Vec<u8>) {
        let len = frame.len() as u64;
        let mut inbox = self.inbox.lock().unwrap();
        let mine = inbox.per_peer.get(&id).copied().unwrap_or(0);
        if inbox.bytes + len > MAX_INBOX_BYTES || mine + len > MAX_INBOX_BYTES_PER_PEER {
            drop(inbox);
            self.dropped.fetch_add(1, Ordering::SeqCst);
            return;
        }
        inbox.bytes += len;
        *inbox.per_peer.entry(id).or_insert(0) += len;
        inbox.frames.push((id, frame));
    }

    /// Live inbound connections (an entry is dropped when its reader thread exits).
    fn inbound_live(&self) -> usize {
        let writers = self.writers.lock().unwrap();
        self.inbound.lock().unwrap().iter().filter(|id| writers.contains_key(id)).count()
    }
}

/// A real TCP transport over `std::net`. Owns an acceptor thread (for inbound
/// connections) and one reader thread per connection; each reader pushes whole
/// frames into a shared inbox that [`Transport::poll`] drains.
pub struct TcpTransport {
    shared: Arc<TcpShared>,
    local_addr: SocketAddr,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl TcpTransport {
    /// Bind a listener (`"127.0.0.1:0"` for an ephemeral port) and start
    /// accepting. Use [`TcpTransport::local_addr`] to learn the chosen port.
    pub fn bind(addr: &str) -> io::Result<TcpTransport> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let shared = Arc::new(TcpShared {
            inbox: Mutex::new(Inbox::default()),
            writers: Mutex::new(HashMap::new()),
            running: AtomicBool::new(true),
            next_id: AtomicU64::new(1),
            inbound: Mutex::new(HashSet::new()),
            inbound_cap: AtomicU64::new(crate::addrman::MAX_INBOUND as u64),
            conns: Mutex::new(HashMap::new()),
            evicting: Mutex::new(HashSet::new()),
            conn_events: Mutex::new(Vec::new()),
            conn_events_lost: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            dialing: Mutex::new(HashSet::new()),
            dial_completions: Mutex::new(Vec::new()),
            epoch: Instant::now(),
            stall_window_ms: AtomicU64::new(SEND_STALL_WINDOW_MS),
        });
        let mut threads = Vec::new();

        // Acceptor: nonblocking listener + short sleep so it notices shutdown.
        listener.set_nonblocking(true)?;
        {
            let shared = Arc::clone(&shared);
            let handle = std::thread::spawn(move || {
                while shared.running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, peer_addr)) => {
                            // Inbound cap (scope 6): at the limit the connection is
                            // CLOSED here — refused, not absorbed. No reader thread,
                            // no writer entry, no peer-table row.
                            //
                            // Issue #459: it does leave a record now. A node at its
                            // cap and a node nobody is dialing produced identical
                            // logs — which is to say, no log at all — and the two
                            // want opposite operator responses.
                            let cap = shared.inbound_cap.load(Ordering::SeqCst) as usize;
                            if shared.inbound_live() >= cap {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                drop(stream);
                                shared.note_conn_event(ConnEvent::Capped {
                                    addr: Some(peer_addr.to_string()),
                                    cap,
                                });
                                continue;
                            }
                            TcpTransport::register_stream(&shared, stream, true);
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            threads.push(handle);
        }

        Ok(TcpTransport { shared, local_addr, threads: Mutex::new(threads) })
    }

    /// The bound local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Dial a peer; returns the local handle for the new connection.
    pub fn connect(&self, addr: &str) -> io::Result<PeerId> {
        let stream = TcpStream::connect(addr)?;
        Ok(TcpTransport::register_stream(&self.shared, stream, false))
    }

    /// Spawn one connector. The closure seam makes the non-blocking contract
    /// testable without depending on a particular OS route or SYN timeout.
    fn start_dial_with<F>(&self, addr: &str, connect: F) -> DialStart
    where
        F: FnOnce(String) -> io::Result<TcpStream> + Send + 'static,
    {
        if !self.shared.running.load(Ordering::SeqCst) {
            return DialStart::Failed(TransportError::Io("transport is shut down".to_string()));
        }

        let addr = addr.to_string();
        {
            let mut dialing = self.shared.dialing.lock().unwrap();
            if !dialing.insert(addr.clone()) {
                return DialStart::Pending;
            }
        }

        let shared = Arc::clone(&self.shared);
        let dial_addr = addr.clone();
        let spawned = std::thread::Builder::new().name("qlab-p2p-dial".to_string()).spawn(move || {
            let started = Instant::now();
            let result = match connect(dial_addr.clone()) {
                Ok(stream) if shared.running.load(Ordering::SeqCst) => {
                    Ok(TcpTransport::register_stream(&shared, stream, false))
                }
                Ok(stream) => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    Err(TransportError::Io("transport shut down during dial".to_string()))
                }
                Err(e) => Err(TransportError::Io(e.to_string())),
            };
            let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            shared.dialing.lock().unwrap().remove(&dial_addr);
            shared
                .dial_completions
                .lock()
                .unwrap()
                .push(DialCompletion { addr: dial_addr, elapsed_ms, result });
        });
        if let Err(e) = spawned {
            self.shared.dialing.lock().unwrap().remove(&addr);
            return DialStart::Failed(TransportError::Io(format!(
                "spawn connector for {addr}: {e}"
            )));
        }
        DialStart::Pending
    }

    /// Set the maximum simultaneous **inbound** connections (issue #83, scope 6).
    /// Defaults to [`crate::addrman::MAX_INBOUND`]. Testnet-tunable, NOT frozen.
    pub fn set_inbound_cap(&self, cap: usize) {
        self.shared.inbound_cap.store(cap as u64, Ordering::SeqCst);
    }

    /// Live inbound connections (ops / tests).
    pub fn inbound_count(&self) -> usize {
        self.shared.inbound_live()
    }

    /// Bytes currently sitting in the receive queue (ops / tests).
    pub fn queued_bytes(&self) -> u64 {
        self.shared.inbox.lock().unwrap().bytes
    }

    /// Undelivered **outbound** bytes held for one peer (ops / tests) — the number
    /// `ss` calls `Send-Q` and that the node could not see before issue #289.
    pub fn backlog_bytes(&self, id: PeerId) -> u64 {
        self.shared.writers.lock().unwrap().get(&id).map(|w| w.progress.backlog()).unwrap_or(0)
    }

    /// Re-tune the no-progress window (tests / testnet). Deliberately programmatic
    /// rather than a config key: like the rate limits, this number should move
    /// because a measurement said so.
    pub fn set_send_stall_window_ms(&self, ms: u64) {
        self.shared.stall_window_ms.store(ms, Ordering::SeqCst);
    }

    /// Try once to drain every backlog. Called before a stall verdict so a link
    /// that recovered while we had nothing to say still clears its window — the
    /// alternative is a false close on a socket that came back quietly.
    fn drain_backlogs(&self) {
        let now = self.shared.now_ms();
        let mut writers = self.shared.writers.lock().unwrap();
        for w in writers.values_mut() {
            if w.progress.backlog() > 0 {
                let _ = w.flush(now);
            }
        }
    }

    /// Register a connected stream: store its write half, spawn a reader thread,
    /// and return the local peer handle. `inbound` records which half of the
    /// connection budget it consumes.
    fn register_stream(shared: &Arc<TcpShared>, stream: TcpStream, inbound: bool) -> PeerId {
        let id = shared.alloc_id();
        // On macOS/BSD an accepted socket inherits the listener's non-blocking
        // flag; force blocking so the reader thread's `read_exact` waits for the
        // next frame instead of erroring `WouldBlock` and exiting the thread.
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_nodelay(true);
        // Issue #289: bound how long one write may hold the node loop. `SO_SNDTIMEO`
        // and not non-blocking mode, because the reader thread's blocking
        // `read_exact` shares this socket through `try_clone` (a `dup`, so
        // `O_NONBLOCK` would follow it) — the send timeout does not.
        let _ = stream.set_write_timeout(Some(Duration::from_millis(SEND_WRITE_TIMEOUT_MS)));
        let writer = stream.try_clone().expect("clone tcp stream for writing");
        shared.writers.lock().unwrap().insert(id, PeerWriter::new(writer));
        if inbound {
            shared.inbound.lock().unwrap().insert(id);
        }
        // Remember who this is (issue #91). The accept path previously dropped the
        // peer address on the floor, so an inbound peer had no identity that
        // survived its socket — and a rate budget keyed on something that does not
        // survive the socket is reset by reconnecting.
        let addr = stream.peer_addr().ok().map(|p| p.to_string());
        let dir = if inbound { ConnDirection::In } else { ConnDirection::Out };
        let opened_ms = shared.now_ms();
        shared
            .conns
            .lock()
            .unwrap()
            .insert(id, ConnMeta { addr: addr.clone(), dir, opened_ms });
        // Issue #459. Only the inbound half is announced here: an outbound open is
        // already journalled by `DIAL`, from the completion the connector thread
        // publishes, and a second line for the same event would double-count every
        // dial in an operator's grep.
        if inbound {
            shared.note_conn_event(ConnEvent::Accepted { peer: id, addr });
        }

        let reader_shared = Arc::clone(shared);
        let mut read_stream = stream;
        let handle = std::thread::spawn(move || {
            let why = loop {
                match read_frame(&mut read_stream) {
                    Ok(frame) => {
                        if !reader_shared.running.load(Ordering::SeqCst) {
                            break CloseReason::Eof;
                        }
                        reader_shared.queue_frame(id, frame);
                    }
                    // EOF, shutdown, or malformed frame. `read_exact` reports a
                    // clean hang-up as `UnexpectedEof`; everything else — reset,
                    // timeout, a header this build refused — is a failure, and the
                    // two are different enough operationally to keep apart.
                    Err(e) => {
                        break if e.kind() == io::ErrorKind::UnexpectedEof {
                            CloseReason::Eof
                        } else {
                            CloseReason::Err
                        };
                    }
                }
            };
            // Connection gone: drop the write half so sends fail fast, and free
            // the inbound slot it held.
            reader_shared.writers.lock().unwrap().remove(&id);
            reader_shared.inbound.lock().unwrap().remove(&id);
            let meta = reader_shared.conns.lock().unwrap().remove(&id);
            // Our own `disconnect` beat the peer to it: report what we did, not
            // what the socket looked like afterwards.
            let why = if reader_shared.evicting.lock().unwrap().remove(&id) {
                CloseReason::Evicted
            } else {
                why
            };
            if let Some(meta) = meta {
                reader_shared.note_conn_event(ConnEvent::Closed {
                    peer: id,
                    addr: meta.addr,
                    dir: meta.dir,
                    held_ms: reader_shared.now_ms().saturating_sub(meta.opened_ms),
                    why,
                });
            }
        });
        // The reader-thread handle is intentionally detached from `threads`: it
        // exits when the socket is shut down (see `shutdown`).
        std::mem::forget(handle);
        id
    }

    /// Stop all threads and close all sockets. Idempotent; also run on drop.
    pub fn shutdown(&self) {
        self.shared.running.store(false, Ordering::SeqCst);
        // Shut down every socket so blocking reader threads unblock and exit.
        for (_, w) in self.shared.writers.lock().unwrap().drain() {
            let _ = w.stream.shutdown(std::net::Shutdown::Both);
        }
        for h in self.threads.lock().unwrap().drain(..) {
            let _ = h.join();
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, to: PeerId, frame: &[u8]) -> Result<(), TransportError> {
        let now = self.shared.now_ms();
        let mut writers = self.shared.writers.lock().unwrap();
        let w = writers.get_mut(&to).ok_or(TransportError::NotConnected(to))?;
        // Serialised by the writers lock, so frames never interleave on a socket —
        // and now bounded in time as well: a peer that stopped reading costs one
        // `SEND_WRITE_TIMEOUT_MS`, not the node loop (issue #289).
        w.send_frame(now, frame)
    }
    fn poll(&self) -> Vec<(PeerId, Vec<u8>)> {
        // Draining releases the whole byte budget in one step, so the accounting
        // measures what is *queued*, never a lifetime total.
        std::mem::take(&mut *self.shared.inbox.lock().unwrap()).frames
    }
    fn peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = self.shared.writers.lock().unwrap().keys().copied().collect();
        v.sort();
        v
    }
    fn dial(&self, addr: &str) -> DialStart {
        self.start_dial_with(addr, TcpStream::connect)
    }
    fn poll_dials(&self) -> Vec<DialCompletion> {
        std::mem::take(&mut *self.shared.dial_completions.lock().unwrap())
    }
    fn peer_addr(&self, id: PeerId) -> Option<String> {
        self.shared.conns.lock().unwrap().get(&id).and_then(|c| c.addr.clone())
    }
    /// Issue #459. Anything the bound refused since the last drain is appended as
    /// a [`ConnEvent::Lost`], so the journal reports its own truncation rather
    /// than letting a dropped tail read as a quiet network.
    fn poll_conn_events(&self) -> Vec<ConnEvent> {
        let mut events = std::mem::take(&mut *self.shared.conn_events.lock().unwrap());
        let lost = self.shared.conn_events_lost.swap(0, Ordering::SeqCst);
        if lost > 0 {
            events.push(ConnEvent::Lost { count: lost });
        }
        events
    }
    fn inbound_peers(&self) -> Option<Vec<PeerId>> {
        let writers = self.shared.writers.lock().unwrap();
        let mut v: Vec<PeerId> =
            self.shared.inbound.lock().unwrap().iter().copied().filter(|id| writers.contains_key(id)).collect();
        v.sort();
        Some(v)
    }
    fn dropped_frames(&self) -> u64 {
        self.shared.dropped.load(Ordering::SeqCst)
    }
    /// Issue #289. Every backlog is offered to the kernel one more time first, so
    /// a link that came back while we were quiet clears its window instead of
    /// being closed on stale evidence.
    fn stalled_peers(&self) -> Vec<StallReport> {
        self.drain_backlogs();
        let now = self.shared.now_ms();
        let window = self.shared.stall_window_ms.load(Ordering::SeqCst);
        let writers = self.shared.writers.lock().unwrap();
        let mut v: Vec<StallReport> = writers
            .iter()
            .filter(|(_, w)| w.progress.is_stalled(now, window))
            .map(|(id, w)| StallReport {
                peer: *id,
                backlog: w.progress.backlog(),
                stalled_ms: w.progress.stalled_for_ms(now),
            })
            .collect();
        v.sort_by_key(|r| r.peer);
        v
    }
    fn disconnect(&self, id: PeerId) {
        let writer = self.shared.writers.lock().unwrap().remove(&id);
        if let Some(w) = writer {
            // Marked BEFORE the shutdown: the reader thread reads this flag on
            // its way out, so the close is attributed to us and not to the peer
            // (issue #459). Doing it after would be a race we would lose most of
            // the time on a loopback socket.
            self.shared.evicting.lock().unwrap().insert(id);
            // Unblocks the reader thread, which then clears the rest of this
            // handle's rows (inbound slot, remote address) exactly as it does for
            // a peer that hung up on us.
            let _ = w.stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Envelope, MsgType};

    #[test]
    fn inproc_delivers_only_over_links() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let b = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        let c = InProcTransport::new(PeerId(3), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));

        let frame = Envelope::new(MsgType::Ping, vec![1, 2, 3]).encode();
        a.send(PeerId(2), &frame).unwrap();
        // No link 1↔3 → not connected.
        assert_eq!(a.send(PeerId(3), &frame), Err(TransportError::NotConnected(PeerId(3))));

        let got = b.poll();
        assert_eq!(got, vec![(PeerId(1), frame)]);
        assert!(c.poll().is_empty());
    }

    #[test]
    fn inproc_partition_and_heal() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let b = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));
        let f = Envelope::new(MsgType::Ping, vec![]).encode();

        hub.unlink(PeerId(1), PeerId(2));
        assert!(a.send(PeerId(2), &f).is_err());
        hub.link(PeerId(1), PeerId(2));
        a.send(PeerId(2), &f).unwrap();
        assert_eq!(b.poll().len(), 1);
    }

    #[test]
    fn inproc_dial_resolves_bound_addresses_only() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let _b = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.bind_addr("b:9333", PeerId(2));

        assert_eq!(a.dial("b:9333"), DialStart::Connected(PeerId(2)));
        assert!(a.send(PeerId(2), &Envelope::new(MsgType::Ping, vec![]).encode()).is_ok());
        // An address nobody bound is unreachable — the outbound-only participant.
        assert!(matches!(a.dial("nat:9333"), DialStart::Failed(_)));
        assert!(
            matches!(a.dial("a-self:9333"), DialStart::Failed(_)),
            "unbound self address is not dialable"
        );
    }

    #[test]
    fn tcp_dial_never_waits_for_the_connector() {
        use std::sync::mpsc;
        use std::time::Duration;

        let transport = TcpTransport::bind("127.0.0.1:0").unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            release_tx.send(()).unwrap();
        });

        let call_started = Instant::now();
        let outcome = transport.start_dial_with("blackhole.invalid:1", move |_| {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Err(io::Error::new(io::ErrorKind::TimedOut, "synthetic SYN timeout"))
        });
        assert_eq!(outcome, DialStart::Pending, "the main loop gets control back immediately");
        assert!(
            call_started.elapsed() < Duration::from_millis(500),
            "dial waited for the connector instead of returning Pending"
        );
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("the connector thread started");
        assert!(
            transport.poll_dials().is_empty(),
            "a blocked connector does not fabricate a completion"
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        let completion = loop {
            if let Some(done) = transport.poll_dials().pop() {
                break done;
            }
            assert!(Instant::now() < deadline, "connector never reported its result");
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(completion.addr, "blackhole.invalid:1");
        assert!(matches!(completion.result, Err(TransportError::Io(ref e)) if e.contains("synthetic SYN timeout")));
    }

    #[test]
    fn tcp_inbound_cap_refuses_a_flood_rather_than_absorbing_it() {
        // Acceptance item 3: over the cap the listener CLOSES the connection at
        // accept — no reader thread, no writer entry, nothing to absorb.
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        server.set_inbound_cap(2);
        let addr = server.local_addr().to_string();

        let mut accepted_streams = Vec::new();
        for _ in 0..12 {
            if let Ok(s) = TcpStream::connect(&addr) {
                accepted_streams.push(s);
            }
        }
        // Give the acceptor time to process the burst.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(server.inbound_count(), 2, "only the cap is held");
        assert!(server.peers().len() <= 2, "refused sockets never become peers");

        // A slot freed by a disconnect is reusable.
        drop(accepted_streams);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let fresh = TcpTransport::bind("127.0.0.1:0").unwrap();
        let _ = fresh.connect(&addr).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(server.inbound_count() >= 1, "the cap is a live count, not a lifetime total");

        server.shutdown();
        fresh.shutdown();
    }

    /// Issue #459. The buffer between two node-loop drains is bounded, and the
    /// bound is reachable: a connect flood on a public port is exactly the
    /// condition it exists for, and it is also exactly the condition where a
    /// silently dropped tail would read as *nothing happened*.
    #[test]
    fn an_overflowing_conn_journal_reports_its_own_truncation() {
        let shared = bare_shared();
        let over = 5;
        for i in 0..(MAX_BUFFERED_CONN_EVENTS + over) {
            shared.note_conn_event(ConnEvent::Accepted {
                peer: PeerId(i as u64),
                addr: Some(format!("10.0.0.1:{i}")),
            });
        }
        let transport = TcpTransport {
            shared: Arc::clone(&shared),
            local_addr: "127.0.0.1:1".parse().unwrap(),
            threads: Mutex::new(Vec::new()),
        };
        let drained = transport.poll_conn_events();
        assert_eq!(drained.len(), MAX_BUFFERED_CONN_EVENTS + 1, "the cap plus one Lost record");
        assert_eq!(
            drained.last(),
            Some(&ConnEvent::Lost { count: over as u64 }),
            "the tail is counted, never silently dropped"
        );
        // The counter resets with the drain: the next report is about the next
        // window, not a lifetime total an operator would double-count.
        assert!(transport.poll_conn_events().is_empty());
    }

    #[test]
    fn tcp_dial_counts_as_outbound_not_inbound() {
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let _pid = client.connect(&server.local_addr().to_string()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(client.inbound_count(), 0, "the dialer's own connection is outbound");
        assert_eq!(server.inbound_count(), 1);
        server.shutdown();
        client.shutdown();
    }

    /// A bare `TcpShared` with no sockets, so the queue accounting can be driven
    /// directly instead of by pushing 64 MiB through loopback.
    fn bare_shared() -> Arc<TcpShared> {
        Arc::new(TcpShared {
            inbox: Mutex::new(Inbox::default()),
            writers: Mutex::new(HashMap::new()),
            running: AtomicBool::new(true),
            next_id: AtomicU64::new(1),
            inbound: Mutex::new(HashSet::new()),
            inbound_cap: AtomicU64::new(crate::addrman::MAX_INBOUND as u64),
            conns: Mutex::new(HashMap::new()),
            evicting: Mutex::new(HashSet::new()),
            conn_events: Mutex::new(Vec::new()),
            conn_events_lost: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            dialing: Mutex::new(HashSet::new()),
            dial_completions: Mutex::new(Vec::new()),
            epoch: Instant::now(),
            stall_window_ms: AtomicU64::new(SEND_STALL_WINDOW_MS),
        })
    }

    #[test]
    fn the_receive_queue_accepts_up_to_its_global_bound_and_refuses_past_it() {
        // Issue #91 gap 2: MAX_PAYLOAD bounds one frame, nothing bounded the pile.
        let shared = bare_shared();
        let chunk = 1024 * 1024usize; // 1 MiB per frame
        let fit = (MAX_INBOX_BYTES / chunk as u64) as usize;
        // Spread across enough peers that the per-peer bound is not what binds.
        for i in 0..fit {
            shared.queue_frame(PeerId(i as u64), vec![0u8; chunk]);
        }
        assert_eq!(shared.inbox.lock().unwrap().bytes, MAX_INBOX_BYTES, "exactly at the bound");
        assert_eq!(shared.dropped.load(Ordering::SeqCst), 0, "nothing refused up to the bound");

        shared.queue_frame(PeerId(9999), vec![0u8; 1]);
        assert_eq!(shared.dropped.load(Ordering::SeqCst), 1, "one byte past it is refused");
        assert_eq!(shared.inbox.lock().unwrap().bytes, MAX_INBOX_BYTES, "and nothing was queued");

        // Draining releases the whole budget — the bound is on what is queued, not
        // on a lifetime total.
        let drained = std::mem::take(&mut *shared.inbox.lock().unwrap()).frames;
        assert_eq!(drained.len(), fit);
        shared.queue_frame(PeerId(1), vec![0u8; chunk]);
        assert_eq!(shared.inbox.lock().unwrap().bytes, chunk as u64);
    }

    #[test]
    fn one_peer_cannot_consume_the_whole_receive_queue() {
        // The fairness half: without a per-peer bound, one sender fills the global
        // budget and every other peer's frames are refused as collateral.
        let shared = bare_shared();
        let chunk = 1024 * 1024usize;
        let fit = (MAX_INBOX_BYTES_PER_PEER / chunk as u64) as usize;
        for _ in 0..fit {
            shared.queue_frame(PeerId(1), vec![0u8; chunk]);
        }
        assert_eq!(shared.dropped.load(Ordering::SeqCst), 0, "at the per-peer bound, all accepted");
        shared.queue_frame(PeerId(1), vec![0u8; 1]);
        assert_eq!(shared.dropped.load(Ordering::SeqCst), 1, "past it, refused");

        // A different peer is unaffected — its own budget is untouched.
        shared.queue_frame(PeerId(2), vec![0u8; chunk]);
        assert_eq!(shared.dropped.load(Ordering::SeqCst), 1, "the neighbour still gets through");
        assert!(shared.inbox.lock().unwrap().per_peer[&PeerId(2)] == chunk as u64);
    }

    #[test]
    fn tcp_reports_the_remote_address_of_an_accepted_connection() {
        // Issue #91: accept used to discard this, leaving an inbound peer with no
        // identity that outlives its socket.
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let cid = client.connect(&server.local_addr().to_string()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));

        let accepted = server.peers();
        assert_eq!(accepted.len(), 1);
        let remote = server.peer_addr(accepted[0]).expect("the accept path kept the address");
        assert!(remote.starts_with("127.0.0.1:"), "got {remote}");
        assert!(client.peer_addr(cid).is_some(), "and the dialer knows its side too");

        server.shutdown();
        client.shutdown();
    }

    #[test]
    fn inproc_reports_a_bound_peers_address_and_none_for_an_unbound_one() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let _b = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        let _c = InProcTransport::new(PeerId(3), Arc::clone(&hub));
        hub.bind_addr("b:9333", PeerId(2));
        assert_eq!(a.peer_addr(PeerId(2)), Some("b:9333".to_string()));
        // The outbound-only participant has no address, on this transport as on a
        // real net — the rate limiter falls back to the handle.
        assert_eq!(a.peer_addr(PeerId(3)), None);
    }

    // ================= send-path stalls (issue #289) =================

    /// A frame big enough to fill kernel buffers in a handful of writes.
    fn fat_frame() -> Vec<u8> {
        Envelope::new(MsgType::Ping, vec![0xab; 1024 * 1024]).encode()
    }

    /// Push frames at `pid` until the kernel stops taking them, or give up.
    /// Returns the backlog reached.
    fn fill_until_backlog(t: &TcpTransport, pid: PeerId, max_frames: usize) -> u64 {
        let frame = fat_frame();
        for _ in 0..max_frames {
            let _ = t.send(pid, &frame);
            if t.backlog_bytes(pid) > 0 {
                break;
            }
        }
        t.backlog_bytes(pid)
    }

    #[test]
    fn a_peer_that_stops_reading_produces_a_backlog_a_stall_verdict_and_recovers_from_it() {
        // Issue #289's mechanism on a real socket. The listener is bound and never
        // accepted: the kernel completes the handshake, so the connection is
        // ESTABLISHED on both sides and nobody is reading — which is exactly what
        // an `iptables -j DROP` partition leaves behind, and what the node had no
        // way to observe.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let pid = client.connect(&target).unwrap();

        let backlog = fill_until_backlog(&client, pid, 40);
        assert!(backlog > 0, "the socket never refused a byte; buffers larger than expected");

        // A backlog alone is NOT a verdict — that is the whole "no progress, not
        // slowness" rule, at the transport this time.
        client.set_send_stall_window_ms(10 * 60_000);
        assert!(client.stalled_peers().is_empty(), "inside the window, nothing is dropped");

        client.set_send_stall_window_ms(1);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let reports = client.stalled_peers();
        assert_eq!(reports.len(), 1, "past the window the wedged socket is named");
        assert_eq!(reports[0].peer, pid);
        assert!(reports[0].backlog > 0, "and the report carries the Send-Q the node could not see");

        // Now the peer starts reading again — a route that came back. The verdict
        // must evaporate on its own: a false close costs a reconnect, and the
        // detector is supposed to be biased against that.
        let (stream, _) = listener.accept().unwrap();
        let reader = std::thread::spawn(move || {
            let mut s = stream;
            let mut buf = vec![0u8; 256 * 1024];
            let deadline = Instant::now() + std::time::Duration::from_secs(10);
            while Instant::now() < deadline {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if client.stalled_peers().is_empty() {
                break;
            }
            assert!(Instant::now() < deadline, "a reading peer never cleared the stall");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(client.backlog_bytes(pid), 0, "the backlog drained rather than being dropped");

        client.shutdown();
        let _ = reader.join();
    }

    #[test]
    fn a_peer_that_keeps_reading_never_builds_a_backlog() {
        // The false-positive side: a healthy socket under real load must produce
        // no backlog at all, so no window length can make it a stall.
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        client.set_send_stall_window_ms(1);
        let pid = client.connect(&server.local_addr().to_string()).unwrap();

        let frame = fat_frame();
        for _ in 0..16 {
            client.send(pid, &frame).expect("a reading peer accepts every frame");
            // Drain the receive side so the *inbox* bound is not what is under test.
            let _ = server.poll();
            assert_eq!(client.backlog_bytes(pid), 0, "nothing was ever refused");
            assert!(client.stalled_peers().is_empty(), "and no verdict at any window");
        }

        server.shutdown();
        client.shutdown();
    }

    #[test]
    fn a_dropped_connection_is_gone_from_the_peer_set() {
        // `disconnect` is the only action a stall verdict licenses; it must be a
        // real close, so the addrman's live-handle reconcile sees the address free.
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let pid = client.connect(&server.local_addr().to_string()).unwrap();
        assert_eq!(client.peers(), vec![pid]);

        client.disconnect(pid);
        assert!(client.peers().is_empty(), "the handle is gone immediately, not eventually");
        client.disconnect(pid); // idempotent
        assert_eq!(
            client.send(pid, &Envelope::new(MsgType::Ping, vec![]).encode()),
            Err(TransportError::NotConnected(pid))
        );

        server.shutdown();
        client.shutdown();
    }

    #[test]
    fn the_in_process_transport_reports_no_stalls_and_still_closes_on_request() {
        // Deterministic sims are unchanged by #289: the hub has no send queue, so
        // it never produces a verdict — but it can be told to close, which is what
        // makes the node's decision testable without a socket.
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let b = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));
        assert!(a.stalled_peers().is_empty());

        a.disconnect(PeerId(2));
        assert!(a.stalled_peers().is_empty());
        assert!(a.send(PeerId(2), &Envelope::new(MsgType::Ping, vec![]).encode()).is_err());
        assert!(b.poll().is_empty());
    }

    #[test]
    fn the_send_backlog_refuses_whole_frames_at_its_cap() {
        // Frame-aligned refusal: a truncated frame in the backlog would
        // desynchronise the peer's framing, which is worse than a dropped message.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();
        let pid = client.connect(&target).unwrap();
        assert!(fill_until_backlog(&client, pid, 40) > 0, "buffers larger than expected");

        let frame = fat_frame();
        for _ in 0..20 {
            let _ = client.send(pid, &frame);
        }
        let backlog = client.backlog_bytes(pid);
        assert!(backlog <= MAX_SEND_BACKLOG_BYTES_PER_PEER, "backlog {backlog} exceeded its cap");
        assert!(
            backlog + frame.len() as u64 > MAX_SEND_BACKLOG_BYTES_PER_PEER,
            "backlog {backlog} should be within one frame of the cap"
        );
        // At the cap the next frames are refused **whole**: the backlog neither
        // grows nor gains a truncated frame that would desynchronise the peer.
        for _ in 0..4 {
            let _ = client.send(pid, &frame);
        }
        assert_eq!(client.backlog_bytes(pid), backlog, "frames are refused, not truncated in");

        client.shutdown();
        drop(listener);
    }

    #[test]
    fn tcp_round_trip_over_loopback() {
        let server = TcpTransport::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().to_string();
        let client = TcpTransport::bind("127.0.0.1:0").unwrap();

        let cid = client.connect(&server_addr).unwrap();
        let frame = Envelope::new(MsgType::Version, vec![9, 8, 7]).encode();
        client.send(cid, &frame).unwrap();

        // Poll the server until the frame arrives (reader thread is async to us).
        let mut got = Vec::new();
        for _ in 0..200 {
            got = server.poll();
            if !got.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(got.len(), 1, "server received exactly one frame");
        assert_eq!(got[0].1, frame);

        server.shutdown();
        client.shutdown();
    }
}
