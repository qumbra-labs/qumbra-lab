//! Peer management: identity, the peer table, handshake payloads, scoring, ban.
//!
//! `[devnet-placeholder]` shape (§10). The [`PeerId`] is a **local** connection
//! handle owned by the transport; the **network identity** a peer advertises in
//! its handshake is a separate [`NodeId`]. The handshake reject-unknown-version
//! guarantee is enforced one layer down, at [`crate::wire`] decode — a frame at
//! the wrong protocol version never reaches peer logic.

use std::collections::HashMap;

use qlab_devnet::header::Hash32;

use crate::codec::{DecodeError, Reader};
use crate::varint::{read_varint, write_varint};

/// A local handle to one transport connection. Not a network identity — see
/// [`NodeId`]. Assigned by the transport; unique within one process/transport.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct PeerId(pub u64);

/// A peer's advertised network identity (32 bytes; e.g. a hash of its static
/// key). Opaque to this layer.
pub type NodeId = Hash32;

/// Score at or below which a peer is banned.
pub const BAN_THRESHOLD: i32 = -100;
/// Starting score for a fresh peer.
pub const INITIAL_SCORE: i32 = 0;

/// Handshake / connection lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Connected at the transport level; no `Version` seen yet.
    Connected,
    /// We sent our `Version`, awaiting the peer's `VerAck`.
    VersionSent,
    /// Handshake complete both ways — normal messaging allowed.
    Ready,
    /// Banned; frames from this peer are dropped and it should be disconnected.
    Banned,
}

/// The `Version` handshake payload (`[devnet-placeholder]`):
/// `node_id(32) ‖ services(u64 LE) ‖ tip_height(u64 LE) ‖ ua_len(varint) ‖ ua`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionMsg {
    pub node_id: NodeId,
    pub services: u64,
    pub tip_height: u64,
    pub user_agent: String,
}

impl VersionMsg {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.services.to_le_bytes());
        out.extend_from_slice(&self.tip_height.to_le_bytes());
        let ua = self.user_agent.as_bytes();
        write_varint(&mut out, ua.len() as u64);
        out.extend_from_slice(ua);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<VersionMsg, DecodeError> {
        let mut r = Reader::new(buf);
        let node_id = r.hash32("version.node_id")?;
        let services = r.u64_le("version.services")?;
        let tip_height = r.u64_le("version.tip_height")?;
        let ua_len = r.varint()? as usize;
        let ua_bytes = r.rest(ua_len, "version.user_agent")?;
        r.finish()?;
        let user_agent = String::from_utf8(ua_bytes).map_err(|_| DecodeError::Varint)?;
        Ok(VersionMsg { node_id, services, tip_height, user_agent })
    }
}

/// The `Addr` payload: a list of peer addresses (`n(varint) ‖ [len(varint) ‖
/// utf8]*`). Addresses are opaque strings (`host:port`) at prototype grade.
pub fn encode_addrs(addrs: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, addrs.len() as u64);
    for a in addrs {
        let b = a.as_bytes();
        write_varint(&mut out, b.len() as u64);
        out.extend_from_slice(b);
    }
    out
}

/// Decode an `Addr` payload.
pub fn decode_addrs(buf: &[u8]) -> Result<Vec<String>, DecodeError> {
    let mut pos = 0usize;
    let n = read_varint(buf, &mut pos)? as usize;
    let mut addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let len = read_varint(buf, &mut pos)? as usize;
        if pos + len > buf.len() {
            return Err(DecodeError::Truncated { what: "addr" });
        }
        let s = String::from_utf8(buf[pos..pos + len].to_vec()).map_err(|_| DecodeError::Varint)?;
        pos += len;
        addrs.push(s);
    }
    if pos != buf.len() {
        return Err(DecodeError::Trailing { remaining: buf.len() - pos });
    }
    Ok(addrs)
}

/// Per-peer bookkeeping.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: PeerId,
    pub state: PeerState,
    pub node_id: Option<NodeId>,
    pub tip_height: u64,
    pub services: u64,
    pub score: i32,
    pub addr: Option<String>,
}

impl PeerInfo {
    fn new(id: PeerId, addr: Option<String>) -> Self {
        PeerInfo {
            id,
            state: PeerState::Connected,
            node_id: None,
            tip_height: 0,
            services: 0,
            score: INITIAL_SCORE,
            addr,
        }
    }
}

/// The set of peers this node knows, with handshake state and scores.
#[derive(Clone, Debug, Default)]
/// The peer table tracks **connections**. The address **book** is
/// [`crate::addrman::AddrManager`] — deliberately not here (issue #83): a table
/// of live connections cannot distinguish "connected to us" from "we can dial
/// it", and only the latter may be gossiped (S2). The old `addr_book`/
/// `remember_addr` pair, which recorded every peer that completed a handshake,
/// was removed rather than left in place: a second book that admits
/// merely-connected addresses is exactly the thing S2 forbids serving.
pub struct PeerTable {
    peers: HashMap<PeerId, PeerInfo>,
}

impl PeerTable {
    pub fn new() -> Self {
        PeerTable::default()
    }

    /// Register a freshly-connected peer.
    pub fn add(&mut self, id: PeerId, addr: Option<String>) {
        self.peers.entry(id).or_insert_with(|| PeerInfo::new(id, addr));
    }

    /// Drop a peer (disconnected).
    pub fn remove(&mut self, id: PeerId) {
        self.peers.remove(&id);
    }

    pub fn get(&self, id: PeerId) -> Option<&PeerInfo> {
        self.peers.get(&id)
    }

    pub fn get_mut(&mut self, id: PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(&id)
    }

    pub fn contains(&self, id: PeerId) -> bool {
        self.peers.contains_key(&id)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Record the peer's advertised `Version` and move it toward `Ready`.
    pub fn on_version(&mut self, id: PeerId, v: &VersionMsg) {
        if let Some(p) = self.peers.get_mut(&id) {
            p.node_id = Some(v.node_id);
            p.tip_height = v.tip_height;
            p.services = v.services;
            // Connected → VersionSent are both awaiting completion; a VerAck flips
            // to Ready (see `on_verack`).
            if p.state == PeerState::Connected {
                p.state = PeerState::VersionSent;
            }
        }
    }

    /// Mark the peer's handshake complete.
    pub fn on_verack(&mut self, id: PeerId) {
        if let Some(p) = self.peers.get_mut(&id) {
            if p.state != PeerState::Banned {
                p.state = PeerState::Ready;
            }
        }
    }

    /// Whether a peer has completed the handshake.
    pub fn is_ready(&self, id: PeerId) -> bool {
        self.peers.get(&id).map(|p| p.state == PeerState::Ready).unwrap_or(false)
    }

    pub fn is_banned(&self, id: PeerId) -> bool {
        self.peers.get(&id).map(|p| p.state == PeerState::Banned).unwrap_or(false)
    }

    /// All peers that have completed the handshake.
    pub fn ready_peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> =
            self.peers.values().filter(|p| p.state == PeerState::Ready).map(|p| p.id).collect();
        v.sort();
        v
    }

    /// The highest tip height advertised by any ready peer (sync target).
    pub fn best_height(&self) -> Option<u64> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Ready)
            .map(|p| p.tip_height)
            .max()
    }

    /// Penalize a misbehaving peer; auto-bans at [`BAN_THRESHOLD`].
    /// Returns `true` if this call banned the peer.
    pub fn penalize(&mut self, id: PeerId, points: i32) -> bool {
        if let Some(p) = self.peers.get_mut(&id) {
            p.score -= points;
            if p.score <= BAN_THRESHOLD && p.state != PeerState::Banned {
                p.state = PeerState::Banned;
                return true;
            }
        }
        false
    }

    /// Force-ban a peer (e.g. on a fatal protocol violation).
    pub fn ban(&mut self, id: PeerId) {
        if let Some(p) = self.peers.get_mut(&id) {
            p.state = PeerState::Banned;
        }
    }

    /// Every peer handle currently in the table, ready or not.
    pub fn all_peers(&self) -> Vec<PeerId> {
        let mut v: Vec<PeerId> = self.peers.keys().copied().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_round_trips() {
        let v = VersionMsg {
            node_id: [7; 32],
            services: 0x01,
            tip_height: 12345,
            user_agent: "qlab-p2p/0.0.0".to_string(),
        };
        assert_eq!(VersionMsg::decode(&v.encode()).unwrap(), v);
    }

    #[test]
    fn version_rejects_trailing() {
        let v = VersionMsg { node_id: [0; 32], services: 0, tip_height: 0, user_agent: String::new() };
        let mut b = v.encode();
        b.push(0);
        assert!(VersionMsg::decode(&b).is_err());
    }

    #[test]
    fn addrs_round_trip() {
        let addrs = vec!["127.0.0.1:8000".to_string(), "10.0.0.1:9".to_string()];
        assert_eq!(decode_addrs(&encode_addrs(&addrs)).unwrap(), addrs);
    }

    #[test]
    fn handshake_flow_reaches_ready() {
        let mut t = PeerTable::new();
        let id = PeerId(1);
        t.add(id, Some("host:1".into()));
        assert_eq!(t.get(id).unwrap().state, PeerState::Connected);
        let v = VersionMsg { node_id: [1; 32], services: 1, tip_height: 9, user_agent: "x".into() };
        t.on_version(id, &v);
        assert_eq!(t.get(id).unwrap().state, PeerState::VersionSent);
        assert_eq!(t.get(id).unwrap().tip_height, 9);
        t.on_verack(id);
        assert!(t.is_ready(id));
        assert_eq!(t.best_height(), Some(9));
    }

    #[test]
    fn penalize_bans_at_threshold() {
        let mut t = PeerTable::new();
        let id = PeerId(2);
        t.add(id, None);
        assert!(!t.penalize(id, 50));
        assert!(!t.is_banned(id));
        assert!(t.penalize(id, 60)); // total -110 ≤ -100
        assert!(t.is_banned(id));
    }
}
