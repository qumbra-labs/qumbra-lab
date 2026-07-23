//! Dual transport: an in-process simulator and a real `std::net` TCP transport,
//! behind one [`Transport`] trait. No async runtime — TCP uses blocking reader
//! threads, unblocked on shutdown by `TcpStream::shutdown` (matching the stack's
//! sync posture; the same poll/step [`crate::node::P2pNode`] logic drives both).
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

/// A frame mover. Send delivers one whole frame to a peer; poll drains all
/// frames received since the last call (with the local peer handle they came
/// from). Both are non-blocking.
pub trait Transport {
    fn send(&self, to: PeerId, frame: &[u8]) -> Result<(), TransportError>;
    fn poll(&self) -> Vec<(PeerId, Vec<u8>)>;
    /// Peers currently reachable through this transport.
    fn peers(&self) -> Vec<PeerId>;
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
}

impl InProcHub {
    pub fn new() -> Arc<InProcHub> {
        Arc::new(InProcHub::default())
    }

    /// Register a node's inbox.
    pub fn register(&self, id: PeerId) {
        self.inboxes.lock().unwrap().entry(id).or_default();
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

struct TcpShared {
    inbox: Mutex<Vec<(PeerId, Vec<u8>)>>,
    writers: Mutex<HashMap<PeerId, TcpStream>>,
    running: AtomicBool,
    next_id: AtomicU64,
}

impl TcpShared {
    fn alloc_id(&self) -> PeerId {
        PeerId(self.next_id.fetch_add(1, Ordering::SeqCst))
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
            inbox: Mutex::new(Vec::new()),
            writers: Mutex::new(HashMap::new()),
            running: AtomicBool::new(true),
            next_id: AtomicU64::new(1),
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
                            TcpTransport::register_stream(&shared, stream);
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
        Ok(TcpTransport::register_stream(&self.shared, stream))
    }

    /// Register a connected stream: store its write half, spawn a reader thread,
    /// and return the local peer handle.
    fn register_stream(shared: &Arc<TcpShared>, stream: TcpStream) -> PeerId {
        let id = shared.alloc_id();
        // On macOS/BSD an accepted socket inherits the listener's non-blocking
        // flag; force blocking so the reader thread's `read_exact` waits for the
        // next frame instead of erroring `WouldBlock` and exiting the thread.
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_nodelay(true);
        let writer = stream.try_clone().expect("clone tcp stream for writing");
        shared.writers.lock().unwrap().insert(id, writer);

        let reader_shared = Arc::clone(shared);
        let mut read_stream = stream;
        let handle = std::thread::spawn(move || {
            loop {
                match read_frame(&mut read_stream) {
                    Ok(frame) => {
                        if !reader_shared.running.load(Ordering::SeqCst) {
                            break;
                        }
                        reader_shared.inbox.lock().unwrap().push((id, frame));
                    }
                    Err(_) => break, // EOF, shutdown, or malformed frame
                }
            }
            // Connection gone: drop the write half so sends fail fast.
            reader_shared.writers.lock().unwrap().remove(&id);
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
        std::mem::take(&mut *self.shared.inbox.lock().unwrap())
    }
    fn peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = self.shared.writers.lock().unwrap().keys().copied().collect();
        v.sort();
        v
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
