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
use std::time::Instant;

use crate::peer::PeerId;
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

/// One outbound dial that completed after [`DialStart::Pending`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialCompletion {
    pub addr: String,
    pub elapsed_ms: u64,
    pub result: Result<PeerId, TransportError>,
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

struct TcpShared {
    inbox: Mutex<Inbox>,
    writers: Mutex<HashMap<PeerId, TcpStream>>,
    running: AtomicBool,
    next_id: AtomicU64,
    /// Handles of connections we **accepted** (as opposed to dialed), so the
    /// inbound cap counts the right half (issue #83, scope 6).
    inbound: Mutex<HashSet<PeerId>>,
    /// Maximum simultaneous inbound connections; over it, a connection is closed
    /// at accept rather than absorbed.
    inbound_cap: AtomicU64,
    /// Remote endpoint per handle (issue #91) — the accept path used to discard
    /// this, which left an inbound connection with no stable identity to key a
    /// rate budget on.
    remote_addrs: Mutex<HashMap<PeerId, String>>,
    /// Frames refused because the receive queue was full.
    dropped: AtomicU64,
    /// Addresses with a connector thread currently waiting in DNS/TCP setup.
    dialing: Mutex<HashSet<String>>,
    /// Completed outbound connects, consumed by the main loop without waiting.
    dial_completions: Mutex<Vec<DialCompletion>>,
}

impl TcpShared {
    fn alloc_id(&self) -> PeerId {
        PeerId(self.next_id.fetch_add(1, Ordering::SeqCst))
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
            remote_addrs: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
            dialing: Mutex::new(HashSet::new()),
            dial_completions: Mutex::new(Vec::new()),
        });
        let mut threads = Vec::new();

        // Acceptor: nonblocking listener + short sleep so it notices shutdown.
        listener.set_nonblocking(true)?;
        {
            let shared = Arc::clone(&shared);
            let handle = std::thread::spawn(move || {
                while shared.running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _peer_addr)) => {
                            // Inbound cap (scope 6): at the limit the connection is
                            // CLOSED here — refused, not absorbed. No reader thread,
                            // no writer entry, no peer-table row.
                            let cap = shared.inbound_cap.load(Ordering::SeqCst) as usize;
                            if shared.inbound_live() >= cap {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                drop(stream);
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
        let writer = stream.try_clone().expect("clone tcp stream for writing");
        shared.writers.lock().unwrap().insert(id, writer);
        if inbound {
            shared.inbound.lock().unwrap().insert(id);
        }
        // Remember who this is (issue #91). The accept path previously dropped the
        // peer address on the floor, so an inbound peer had no identity that
        // survived its socket — and a rate budget keyed on something that does not
        // survive the socket is reset by reconnecting.
        if let Ok(peer) = stream.peer_addr() {
            shared.remote_addrs.lock().unwrap().insert(id, peer.to_string());
        }

        let reader_shared = Arc::clone(shared);
        let mut read_stream = stream;
        let handle = std::thread::spawn(move || {
            loop {
                match read_frame(&mut read_stream) {
                    Ok(frame) => {
                        if !reader_shared.running.load(Ordering::SeqCst) {
                            break;
                        }
                        reader_shared.queue_frame(id, frame);
                    }
                    Err(_) => break, // EOF, shutdown, or malformed frame
                }
            }
            // Connection gone: drop the write half so sends fail fast, and free
            // the inbound slot it held.
            reader_shared.writers.lock().unwrap().remove(&id);
            reader_shared.inbound.lock().unwrap().remove(&id);
            reader_shared.remote_addrs.lock().unwrap().remove(&id);
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
        for (_, s) in self.shared.writers.lock().unwrap().drain() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        for h in self.threads.lock().unwrap().drain(..) {
            let _ = h.join();
        }
    }
}

impl Transport for TcpTransport {
    fn send(&self, to: PeerId, frame: &[u8]) -> Result<(), TransportError> {
        let writers = self.shared.writers.lock().unwrap();
        let mut stream = writers.get(&to).ok_or(TransportError::NotConnected(to))?;
        // Serialised by the writers lock, so frames never interleave on a socket.
        stream.write_all(frame).map_err(|e| TransportError::Io(e.to_string()))?;
        stream.flush().map_err(|e| TransportError::Io(e.to_string()))
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
        self.shared.remote_addrs.lock().unwrap().get(&id).cloned()
    }
    fn dropped_frames(&self) -> u64 {
        self.shared.dropped.load(Ordering::SeqCst)
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
            remote_addrs: Mutex::new(HashMap::new()),
            dropped: AtomicU64::new(0),
            dialing: Mutex::new(HashSet::new()),
            dial_completions: Mutex::new(Vec::new()),
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
