//! [`P2pNode`] — the integrator. It owns a [`Transport`], an N1 [`NodeState`]
//! (stubbed), a [`PeerTable`], the gossip dedup cache, and the sync state
//! machine, and drives them all from a single non-blocking [`P2pNode::tick`]:
//! drain the transport, dispatch each frame, emit responses. The same logic runs
//! over the in-process and TCP transports, so tests are deterministic in-process
//! and identical over the socket.

use std::collections::{HashMap, HashSet};

use qlab_devnet::committee::{Checkpoint, Vote};
use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::ebbflow::EquivocationEvidence;
use qlab_devnet::header::{BlockHeader, Hash32};

use crate::codec::{
    checkpoint_id, decode_checkpoint_msg, decode_evidence_msg, decode_headers, decode_inv,
    decode_locator, decode_tx, encode_checkpoint_msg, encode_evidence_msg, encode_headers,
    encode_inv, encode_locator, encode_tx, evidence_id, tx_id, InvItem, InvKind,
};
use crate::compact::{
    decode_announce, decode_block_txn, decode_get_block_txn, encode_announce, encode_block_txn,
    encode_get_block_txn, reconstruct, short_id, BlockAnnounce, BlockTxn, GetBlockTxn, PrefilledTx,
    Reconstruct,
};
use crate::gossip::{
    SeenCache, PENALTY_INVALID_OBJECT, PENALTY_MALFORMED, PENALTY_WELSHED_INV,
};
use crate::n1::{IngestOutcome, NodeState};
use crate::peer::{NodeId, PeerId, PeerTable, VersionMsg};
use crate::sync::{build_locator, answer_get_headers, SyncPhase, SyncState, MAX_HEADERS_PER_BATCH};
use crate::transport::Transport;
use crate::wire::{Envelope, MsgType};

/// Service-bits placeholder advertised in the handshake (`[devnet-placeholder]`).
pub const SERVICE_FULL: u64 = 0x01;

/// A running P2P node: transport + node-state + peers + gossip + sync.
pub struct P2pNode<T: Transport, N: NodeState> {
    transport: T,
    node: N,
    peers: PeerTable,
    node_id: NodeId,
    user_agent: String,
    seen: SeenCache,
    sync: SyncState,
    version_sent: HashSet<PeerId>,
    /// Full block bodies this node can serve (originated or fully reconstructed),
    /// keyed by header hash — backs `GetBlockTxn` answering. Stores the ordered
    /// txs and the body's coinbase counter (needed to rebuild the exact body).
    blocks: HashMap<Hash32, (Vec<TxEntry>, u64)>,
    /// Announcements awaiting missing transactions (block hash → announce).
    pending_blocks: HashMap<Hash32, BlockAnnounce>,
    /// Finalized checkpoints + their votes, keyed by checkpoint id — so a
    /// `GetData(Checkpoint)` can be re-served (checkpoints, unlike headers/txs,
    /// are not reconstructable from other state).
    checkpoints: HashMap<Hash32, (Checkpoint, Vec<Vote>)>,
}

impl<T: Transport, N: NodeState> P2pNode<T, N> {
    /// Build a node over `transport` and `node`, advertising `node_id`.
    pub fn new(transport: T, node: N, node_id: NodeId) -> Self {
        P2pNode {
            transport,
            node,
            peers: PeerTable::new(),
            node_id,
            user_agent: format!("qlab-p2p/{}", env!("CARGO_PKG_VERSION")),
            seen: SeenCache::default(),
            sync: SyncState::new(),
            version_sent: HashSet::new(),
            blocks: HashMap::new(),
            pending_blocks: HashMap::new(),
            checkpoints: HashMap::new(),
        }
    }

    // --- read-only accessors (tests / callers) ---
    pub fn node(&self) -> &N {
        &self.node
    }
    pub fn node_mut(&mut self) -> &mut N {
        &mut self.node
    }
    pub fn peers(&self) -> &PeerTable {
        &self.peers
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn sync_phase(&self) -> &SyncPhase {
        &self.sync.phase
    }

    // --- outbound framing helpers ---
    fn send(&self, to: PeerId, msg_type: MsgType, payload: Vec<u8>) {
        let frame = Envelope::new(msg_type, payload).encode();
        let _ = self.transport.send(to, &frame); // peer-gone is benign
    }

    /// Announce one inventory item to every ready peer except `except`.
    fn relay_inv(&self, item: InvItem, except: Option<PeerId>) {
        let payload = encode_inv(&[item]);
        for pid in self.peers.ready_peers() {
            if Some(pid) != except {
                self.send(pid, MsgType::Inv, payload.clone());
            }
        }
    }

    fn ensure_version_sent(&mut self, to: PeerId) {
        if self.version_sent.insert(to) {
            let v = VersionMsg {
                node_id: self.node_id,
                services: SERVICE_FULL,
                tip_height: self.node.tip_height(),
                user_agent: self.user_agent.clone(),
            };
            self.send(to, MsgType::Version, v.encode());
        }
    }

    /// Register a peer we dialed and open the handshake.
    pub fn add_peer(&mut self, id: PeerId, addr: Option<String>) {
        self.peers.add(id, addr);
        self.ensure_version_sent(id);
    }

    // --- local origination ---

    /// Ingest a locally-produced transaction and announce it.
    pub fn announce_tx(&mut self, tx: TxEntry) {
        let id = tx_id(&tx);
        if self.node.ingest_tx(tx).should_relay() {
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Tx, id }, None);
        }
    }

    /// Ingest a locally-produced header and announce it.
    pub fn announce_header(&mut self, header: BlockHeader) {
        let id = header.header_hash();
        if self.node.ingest_header(header).should_relay() {
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Block, id }, None);
        }
    }

    /// Ingest a locally-finalized checkpoint and announce it.
    pub fn announce_checkpoint(&mut self, cp: Checkpoint, votes: Vec<Vote>) {
        let id = checkpoint_id(&cp);
        let stored = (cp, votes.clone());
        if self.node.ingest_checkpoint(cp, votes).should_relay() {
            self.checkpoints.insert(id, stored);
            self.seen.insert(id);
            self.relay_inv(InvItem { kind: InvKind::Checkpoint, id }, None);
        }
    }

    /// Announce a full block (header + ordered body) via compact relay: store the
    /// body, ingest the header, and push a `BlockAnnounce` to ready peers with a
    /// fresh salt nonce (slot 0 prefilled as the coinbase-position tx).
    pub fn announce_block(
        &mut self,
        header: BlockHeader,
        txs: Vec<TxEntry>,
        coinbase: u64,
        nonce: u64,
    ) {
        let bh = header.header_hash();
        self.blocks.insert(bh, (txs.clone(), coinbase));
        let _ = self.node.ingest_block(header, BlockBody { txs: txs.clone(), coinbase });
        self.seen.insert(bh);

        let (prefilled, short_ids) = build_announce_parts(&txs, nonce);
        let ann = BlockAnnounce { header, nonce, coinbase, short_ids, prefilled };
        let payload = encode_announce(&ann);
        for pid in self.peers.ready_peers() {
            self.send(pid, MsgType::BlockAnnounce, payload.clone());
        }
    }

    // --- the driver ---

    /// Process everything that has arrived since the last call. Returns the
    /// number of frames handled (0 ⇒ quiescent, for test loops).
    pub fn tick(&mut self) -> usize {
        let frames = self.transport.poll();
        let n = frames.len();
        for (from, frame) in frames {
            if self.peers.is_banned(from) {
                continue;
            }
            if !self.peers.contains(from) {
                // Inbound connection we have not registered yet.
                self.peers.add(from, None);
            }
            match Envelope::decode(&frame) {
                Ok(env) => self.dispatch(from, env),
                Err(_) => {
                    // Malformed frame at the wire layer → strong penalty.
                    self.peers.penalize(from, PENALTY_MALFORMED);
                }
            }
        }
        self.maybe_start_sync();
        n
    }

    fn dispatch(&mut self, from: PeerId, env: Envelope) {
        match env.msg_type {
            MsgType::Version => self.on_version(from, &env.payload),
            MsgType::VerAck => self.on_verack(from),
            MsgType::Ping => self.send(from, MsgType::Pong, env.payload),
            MsgType::Pong => {}
            MsgType::GetAddr => {
                let addrs: Vec<String> = self.peers.addr_book().to_vec();
                self.send(from, MsgType::Addr, crate::peer::encode_addrs(&addrs));
            }
            MsgType::Addr => { /* prototype: no auto-connect */ }
            MsgType::Inv => self.on_inv(from, &env.payload),
            MsgType::GetData => self.on_getdata(from, &env.payload),
            MsgType::NotFound => {
                self.peers.penalize(from, PENALTY_WELSHED_INV);
            }
            MsgType::Tx => self.on_tx(from, &env.payload),
            MsgType::Header => self.on_header(from, &env.payload),
            MsgType::Checkpoint => self.on_checkpoint(from, &env.payload),
            MsgType::Evidence => self.on_evidence(from, &env.payload),
            MsgType::GetHeaders => self.on_get_headers(from, &env.payload),
            MsgType::Headers => self.on_headers(from, &env.payload),
            MsgType::CmpctBlock => self.on_cmpct_block(from, &env.payload),
            MsgType::BlockAnnounce => self.on_block_announce(from, &env.payload),
            MsgType::GetBlockTxn => self.on_get_block_txn(from, &env.payload),
            MsgType::BlockTxn => self.on_block_txn(from, &env.payload),
        }
    }

    // --- handshake ---

    fn on_version(&mut self, from: PeerId, payload: &[u8]) {
        match VersionMsg::decode(payload) {
            Ok(v) => {
                self.peers.on_version(from, &v);
                self.ensure_version_sent(from); // reply with our Version if new
                self.send(from, MsgType::VerAck, vec![]);
            }
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
            }
        }
    }

    fn on_verack(&mut self, from: PeerId) {
        self.peers.on_verack(from);
    }

    // --- inventory gossip ---

    fn on_inv(&mut self, from: PeerId, payload: &[u8]) {
        let items = match decode_inv(payload) {
            Ok(i) => i,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let mut want = Vec::new();
        for it in items {
            if self.already_have(&it) {
                continue;
            }
            want.push(it);
        }
        if !want.is_empty() {
            self.send(from, MsgType::GetData, encode_inv(&want));
        }
    }

    fn already_have(&self, it: &InvItem) -> bool {
        match it.kind {
            InvKind::Tx => self.node.has_tx(&it.id) || self.seen.contains(&it.id),
            InvKind::Block => self.node.has_header(&it.id) || self.seen.contains(&it.id),
            InvKind::Checkpoint => self.node.has_checkpoint(&it.id) || self.seen.contains(&it.id),
        }
    }

    fn on_getdata(&mut self, from: PeerId, payload: &[u8]) {
        let items = match decode_inv(payload) {
            Ok(i) => i,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let mut not_found = Vec::new();
        for it in items {
            match it.kind {
                InvKind::Tx => match self.node.get_tx(&it.id) {
                    Some(tx) => self.send(from, MsgType::Tx, encode_tx(&tx)),
                    None => not_found.push(it),
                },
                InvKind::Block => match self.node.header(&it.id) {
                    Some(h) => self.send(from, MsgType::Header, crate::codec::encode_header(&h)),
                    None => not_found.push(it),
                },
                InvKind::Checkpoint => match self.checkpoints.get(&it.id) {
                    Some((cp, votes)) => {
                        self.send(from, MsgType::Checkpoint, encode_checkpoint_msg(cp, votes))
                    }
                    None => not_found.push(it),
                },
            }
        }
        if !not_found.is_empty() {
            self.send(from, MsgType::NotFound, encode_inv(&not_found));
        }
    }

    // --- gossip payloads ---

    fn on_tx(&mut self, from: PeerId, payload: &[u8]) {
        let tx = match decode_tx(payload) {
            Ok(t) => t,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = tx_id(&tx);
        match self.node.ingest_tx(tx) {
            IngestOutcome::Accepted => {
                self.seen.insert(id);
                self.relay_inv(InvItem { kind: InvKind::Tx, id }, Some(from));
            }
            IngestOutcome::Rejected(_) => {
                self.peers.penalize(from, PENALTY_INVALID_OBJECT);
            }
            _ => {}
        }
    }

    fn on_header(&mut self, from: PeerId, payload: &[u8]) {
        let header = match crate::codec::decode_header(payload) {
            Ok(h) => h,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = header.header_hash();
        match self.node.ingest_header(header) {
            IngestOutcome::Accepted => {
                self.seen.insert(id);
                self.relay_inv(InvItem { kind: InvKind::Block, id }, Some(from));
            }
            IngestOutcome::Orphan => {
                // Missing ancestors → kick off header-first sync from this peer.
                self.start_sync_with(from);
            }
            IngestOutcome::Rejected(_) => {
                self.peers.penalize(from, PENALTY_INVALID_OBJECT);
            }
            IngestOutcome::Duplicate => {}
        }
    }

    fn on_checkpoint(&mut self, from: PeerId, payload: &[u8]) {
        let (cp, votes) = match decode_checkpoint_msg(payload) {
            Ok(cv) => cv,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        // Committee-over-network equivocation path: a checkpoint's votes may reveal
        // a signer that already signed a conflicting checkpoint at this slot. Detect
        // it, apply the automated tombstone locally, and gossip the evidence so the
        // whole network converges — BEFORE finalizing, so the tombstoned vote can no
        // longer count toward this checkpoint's quorum.
        for ev in self.node.observe_votes(&cp, &votes) {
            self.punish_and_gossip_evidence(ev);
        }
        let id = checkpoint_id(&cp);
        let stored = (cp, votes.clone());
        match self.node.ingest_checkpoint(cp, votes) {
            IngestOutcome::Accepted => {
                self.checkpoints.insert(id, stored);
                self.seen.insert(id);
                self.relay_inv(InvItem { kind: InvKind::Checkpoint, id }, Some(from));
            }
            IngestOutcome::Rejected(_) => {
                self.peers.penalize(from, PENALTY_INVALID_OBJECT);
            }
            _ => {}
        }
    }

    // --- committee: equivocation evidence gossip (M9-N5) ---

    /// Apply verified evidence locally and, if it was valid and not already seen,
    /// gossip it to every ready peer so the whole network tombstones the signer.
    fn punish_and_gossip_evidence(&mut self, ev: EquivocationEvidence) {
        if self.node.apply_evidence(&ev).is_none() {
            return; // did not verify — nothing to relay
        }
        let id = evidence_id(&ev);
        if self.seen.insert(id) {
            let payload = encode_evidence_msg(&ev);
            for pid in self.peers.ready_peers() {
                self.send(pid, MsgType::Evidence, payload.clone());
            }
        }
    }

    /// Gossip locally-held equivocation evidence (e.g. produced off-network).
    pub fn announce_evidence(&mut self, ev: EquivocationEvidence) {
        self.punish_and_gossip_evidence(ev);
    }

    fn on_evidence(&mut self, from: PeerId, payload: &[u8]) {
        let ev = match decode_evidence_msg(payload) {
            Ok(e) => e,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let id = evidence_id(&ev);
        if !self.seen.insert(id) {
            return; // already handled — dedup re-gossip
        }
        match self.node.apply_evidence(&ev) {
            Some(_signer) => {
                // Valid → relay onward to every ready peer except the sender.
                let payload = encode_evidence_msg(&ev);
                for pid in self.peers.ready_peers() {
                    if pid != from {
                        self.send(pid, MsgType::Evidence, payload.clone());
                    }
                }
            }
            None => {
                // Evidence that does not verify is an invalid object.
                self.peers.penalize(from, PENALTY_INVALID_OBJECT);
            }
        }
    }

    /// This node's Ebb-and-Flow regime (Final vs degraded probabilistic PoW),
    /// observed over the network.
    pub fn finality_status(&self) -> qlab_devnet::ebbflow::FinalityStatus {
        self.node.finality_status()
    }

    // --- header-first sync ---

    fn maybe_start_sync(&mut self) {
        if self.sync.awaiting() {
            return;
        }
        let best = self.peers.best_height().unwrap_or(0);
        if best > self.node.tip_height() {
            // Sync from the tallest ready peer.
            if let Some(peer) = self.tallest_ready_peer() {
                self.start_sync_with(peer);
            }
        } else {
            self.sync.phase = SyncPhase::Synced;
        }
    }

    fn tallest_ready_peer(&self) -> Option<PeerId> {
        self.peers
            .ready_peers()
            .into_iter()
            .filter_map(|p| self.peers.get(p).map(|info| (p, info.tip_height)))
            .max_by_key(|(_, h)| *h)
            .map(|(p, _)| p)
    }

    fn start_sync_with(&mut self, peer: PeerId) {
        if !self.peers.is_ready(peer) {
            return;
        }
        let loc = build_locator(&self.node);
        self.send(peer, MsgType::GetHeaders, encode_locator(&loc));
        self.sync.phase =
            SyncPhase::AwaitingHeaders { peer, from_height: self.node.tip_height() };
    }

    fn on_get_headers(&mut self, from: PeerId, payload: &[u8]) {
        let loc = match decode_locator(payload) {
            Ok(l) => l,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let batch = answer_get_headers(&self.node, &loc, MAX_HEADERS_PER_BATCH);
        self.send(from, MsgType::Headers, encode_headers(&batch));
    }

    fn on_headers(&mut self, from: PeerId, payload: &[u8]) {
        let batch = match decode_headers(payload) {
            Ok(b) => b,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let batch_len = batch.len();
        let mut accepted = 0;
        for h in batch {
            let id = h.header_hash();
            match self.node.ingest_header(h) {
                IngestOutcome::Accepted => {
                    accepted += 1;
                    self.seen.insert(id);
                    self.relay_inv(InvItem { kind: InvKind::Block, id }, Some(from));
                }
                IngestOutcome::Duplicate => {}
                // An orphan mid-batch means the batch didn't connect; stop and let
                // the next locator round re-anchor.
                IngestOutcome::Orphan | IngestOutcome::Rejected(_) => break,
            }
        }

        // Advance the state machine.
        let still_behind = self.peers.best_height().unwrap_or(0) > self.node.tip_height();
        if batch_len == MAX_HEADERS_PER_BATCH && still_behind && accepted > 0 {
            // Full batch and more to go → request the next one.
            let loc = build_locator(&self.node);
            self.send(from, MsgType::GetHeaders, encode_locator(&loc));
            self.sync.phase =
                SyncPhase::AwaitingHeaders { peer: from, from_height: self.node.tip_height() };
        } else {
            self.sync.phase =
                if still_behind { SyncPhase::Idle } else { SyncPhase::Synced };
        }
    }

    // --- compact-block relay ---

    // (1) §5 compact blocks: relayed opaquely (the stub has no note store), with
    // dedup so each propagates once.
    fn on_cmpct_block(&mut self, from: PeerId, payload: &[u8]) {
        // Validate framing by decoding (inherits §5 reject-* guarantees); a
        // malformed payload penalizes the sender.
        if crate::compact::decode_cmpct_relay(payload).is_err() {
            self.peers.penalize(from, PENALTY_MALFORMED);
            return;
        }
        let id = qlab_devnet::hash::keccak256(payload);
        if self.seen.insert(id) {
            for pid in self.peers.ready_peers() {
                if pid != from {
                    self.send(pid, MsgType::CmpctBlock, payload.to_vec());
                }
            }
        }
    }

    // (2) §7 BIP-152 block relay.
    fn on_block_announce(&mut self, from: PeerId, payload: &[u8]) {
        let ann = match decode_announce(payload) {
            Ok(a) => a,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let bh = ann.header.header_hash();
        if self.blocks.contains_key(&bh) {
            return; // already have the full body
        }
        let candidates = self.node.all_txs();
        match reconstruct(&ann, &candidates) {
            Reconstruct::Complete(txs) => self.complete_block(bh, ann, txs, Some(from)),
            Reconstruct::Missing(indexes) => {
                self.pending_blocks.insert(bh, ann);
                self.send(
                    from,
                    MsgType::GetBlockTxn,
                    encode_get_block_txn(&GetBlockTxn { block_hash: bh, indexes }),
                );
            }
        }
    }

    fn on_get_block_txn(&mut self, from: PeerId, payload: &[u8]) {
        let req = match decode_get_block_txn(payload) {
            Ok(r) => r,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let Some((body, _coinbase)) = self.blocks.get(&req.block_hash) else {
            return; // we don't have that block's body
        };
        let txs: Vec<TxEntry> =
            req.indexes.iter().filter_map(|&i| body.get(i as usize).cloned()).collect();
        self.send(
            from,
            MsgType::BlockTxn,
            encode_block_txn(&BlockTxn { block_hash: req.block_hash, txs }),
        );
    }

    fn on_block_txn(&mut self, from: PeerId, payload: &[u8]) {
        let bt = match decode_block_txn(payload) {
            Ok(b) => b,
            Err(_) => {
                self.peers.penalize(from, PENALTY_MALFORMED);
                return;
            }
        };
        let Some(ann) = self.pending_blocks.remove(&bt.block_hash) else {
            return;
        };
        // Add the supplied txs to our mempool, then re-reconstruct.
        for tx in &bt.txs {
            let _ = self.node.ingest_tx(tx.clone());
        }
        let candidates = self.node.all_txs();
        match reconstruct(&ann, &candidates) {
            Reconstruct::Complete(txs) => self.complete_block(bt.block_hash, ann, txs, Some(from)),
            Reconstruct::Missing(_) => { /* still missing; give up this round */ }
        }
    }

    /// Finish a reconstructed/announced block: store the body, ingest the header,
    /// and re-announce to other peers.
    fn complete_block(
        &mut self,
        bh: Hash32,
        ann: BlockAnnounce,
        txs: Vec<TxEntry>,
        except: Option<PeerId>,
    ) {
        self.blocks.insert(bh, (txs.clone(), ann.coinbase));
        let _ = self
            .node
            .ingest_block(ann.header, BlockBody { txs, coinbase: ann.coinbase });
        self.seen.insert(bh);
        let payload = encode_announce(&ann);
        for pid in self.peers.ready_peers() {
            if Some(pid) != except {
                self.send(pid, MsgType::BlockAnnounce, payload.clone());
            }
        }
    }
}

/// Build the `(prefilled, short_ids)` for a `BlockAnnounce`: slot 0 (the
/// coinbase position) is prefilled; the rest are short ids under `nonce`.
fn build_announce_parts(txs: &[TxEntry], nonce: u64) -> (Vec<PrefilledTx>, Vec<[u8; 6]>) {
    let mut prefilled = Vec::new();
    let mut short_ids = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        if i == 0 {
            prefilled.push(PrefilledTx { index: 0, tx: tx.clone() });
        } else {
            short_ids.push(short_id(nonce, &tx_id(tx)));
        }
    }
    (prefilled, short_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::n1::{BlockIngest, ChainView, CommitteeControl, StubNode, TxPool};
    use crate::transport::{InProcHub, InProcTransport};
    use qlab_devnet::body::TxPublic;
    use qlab_devnet::committee::{devnet_committee, CommitteeState, MemberStatus, Validator};
    use qlab_devnet::ebbflow::{EquivocationEvidence, FinalityStatus};
    use qlab_devnet::epoch::{EpochCommittee, EpochSchedule};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::finality::next_checkpoint_height;
    use qlab_devnet::params_devnet::BOND_AMOUNT;
    use std::sync::Arc;

    /// Verified equivocation evidence: `signer` signed two conflicting checkpoints
    /// at `height` (distinct block hashes ⇒ distinct signing messages).
    fn conflicting_evidence(
        validators: &[Validator],
        signer: usize,
        height: u64,
    ) -> EquivocationEvidence {
        let a = Checkpoint::new(height, [0xA0 + signer as u8; 32], [0xA0; 32]);
        let b = Checkpoint::new(height, [0xB0 + signer as u8; 32], [0xB0; 32]);
        EquivocationEvidence {
            vote_a: validators[signer].sign_checkpoint(&a),
            cp_a: a,
            vote_b: validators[signer].sign_checkpoint(&b),
            cp_b: b,
        }
    }

    type InProcP2p = P2pNode<InProcTransport, StubNode>;

    fn genesis() -> BlockHeader {
        BlockHeader::genesis(1000, 0)
    }

    fn stub() -> StubNode {
        let (committee, _v) = devnet_committee(7);
        StubNode::new(genesis(), CommitteeState::new(committee, BOND_AMOUNT))
    }

    fn tx(seed: u8) -> TxEntry {
        TxEntry {
            proof: vec![seed; 32],
            public: TxPublic {
                anchor: [seed; 32],
                nullifiers: vec![[seed; 32]],
                commitments: vec![[seed.wrapping_add(9); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: 1_000_000,
            },
        }
    }

    /// Drive a set of nodes to quiescence (no frames moved in a full round).
    fn run(nodes: &mut [InProcP2p]) {
        for _ in 0..1000 {
            let mut moved = 0;
            for n in nodes.iter_mut() {
                moved += n.tick();
            }
            if moved == 0 {
                break;
            }
        }
    }

    /// A fully-connected mesh of `n` in-process nodes; returns the nodes and hub.
    fn mesh(n: u64) -> (Vec<InProcP2p>, Arc<InProcHub>) {
        let hub = InProcHub::new();
        let mut nodes = Vec::new();
        for i in 0..n {
            let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
            nodes.push(P2pNode::new(t, stub(), [i as u8 + 1; 32]));
        }
        // Link every pair and introduce peers to each other.
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    hub.link(PeerId(i + 1), PeerId(j + 1));
                }
            }
        }
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    nodes[i as usize].add_peer(PeerId(j + 1), None);
                }
            }
        }
        (nodes, hub)
    }

    #[test]
    fn handshake_reaches_ready_both_ways() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        assert!(nodes[0].peers().is_ready(PeerId(2)));
        assert!(nodes[1].peers().is_ready(PeerId(1)));
    }

    #[test]
    fn tx_gossip_propagates_across_mesh() {
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes); // complete handshakes
        let t = tx(42);
        let id = tx_id(&t);
        nodes[0].announce_tx(t);
        run(&mut nodes);
        for n in &nodes {
            assert!(n.node().has_tx(&id), "each node received the tx");
        }
    }

    #[test]
    fn header_gossip_propagates() {
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);
        let h = BlockHeader::child_of(&genesis(), 75, 1000, [1; 32]);
        let id = h.header_hash();
        nodes[0].announce_header(h);
        run(&mut nodes);
        for n in &nodes {
            assert!(n.node().has_header(&id));
        }
    }

    #[test]
    fn checkpoint_gossip_propagates_and_finalizes() {
        // All nodes share one committee so votes verify everywhere.
        let (committee, validators) = devnet_committee(7); // quorum 5
        let hub = InProcHub::new();
        let mut nodes: Vec<InProcP2p> = (0..3)
            .map(|i| {
                let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
                let node = StubNode::new(
                    genesis(),
                    CommitteeState::new(committee.clone(), BOND_AMOUNT),
                );
                P2pNode::new(t, node, [i as u8 + 1; 32])
            })
            .collect();
        for i in 0..3u64 {
            for j in 0..3u64 {
                if i != j {
                    hub.link(PeerId(i + 1), PeerId(j + 1));
                }
            }
        }
        for i in 0..3usize {
            for j in 0..3u64 {
                if i as u64 != j {
                    nodes[i].add_peer(PeerId(j + 1), None);
                }
            }
        }
        run(&mut nodes);

        let cp = Checkpoint::new(2, [0xAB; 32], [0xAB; 32]);
        let votes: Vec<Vote> =
            validators[..5].iter().map(|v: &Validator| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(2));
        }
    }

    #[test]
    fn header_first_sync_catches_up_a_behind_node() {
        // Node 0 already has a 30-block chain; node 1 starts at genesis.
        let hub = InProcHub::new();
        let t0 = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let mut server = P2pNode::new(t0, stub(), [1; 32]);
        let mut parent = genesis();
        for i in 0..30u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            server.node_mut().ingest_header(child);
            parent = child;
        }
        assert_eq!(server.node().tip_height(), 30);

        let t1 = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        let mut behind = P2pNode::new(t1, stub(), [2; 32]);

        hub.link(PeerId(1), PeerId(2));
        server.add_peer(PeerId(2), None);
        behind.add_peer(PeerId(1), None);

        let mut nodes = vec![server, behind];
        run(&mut nodes);

        assert_eq!(nodes[1].node().tip_height(), 30, "behind node synced to tip");
        assert_eq!(nodes[1].node().chain().tip_hash(), nodes[0].node().chain().tip_hash());
        assert_eq!(*nodes[1].sync_phase(), SyncPhase::Synced);
    }

    #[test]
    fn compact_block_relay_reconstructs_from_mempool() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        // Both nodes already hold t1, t2 in their mempools; node 0 announces a
        // block over them + a prefilled coinbase.
        let coinbase = tx(0);
        let t1 = tx(1);
        let t2 = tx(2);
        for n in nodes.iter_mut() {
            n.node_mut().ingest_tx(t1.clone());
            n.node_mut().ingest_tx(t2.clone());
        }
        let header = BlockHeader::child_of(&genesis(), 75, 1000, [7; 32]);
        let bh = header.header_hash();
        nodes[0].announce_block(header, vec![coinbase, t1, t2], 0, 0xABCD);
        run(&mut nodes);
        // Node 1 reconstructed and ingested the header.
        assert!(nodes[1].node().has_header(&bh));
    }

    #[test]
    fn compact_block_relay_fetches_missing_tx() {
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);
        let coinbase = tx(0);
        let t1 = tx(1);
        let t2 = tx(2);
        // Only node 0 has t2; node 1 must GetBlockTxn it.
        nodes[0].node_mut().ingest_tx(t1.clone());
        nodes[0].node_mut().ingest_tx(t2.clone());
        nodes[1].node_mut().ingest_tx(t1.clone());
        let header = BlockHeader::child_of(&genesis(), 75, 1000, [8; 32]);
        let bh = header.header_hash();
        nodes[0].announce_block(header, vec![coinbase, t1, t2.clone()], 0, 0x1234);
        run(&mut nodes);
        assert!(nodes[1].node().has_header(&bh), "header ingested after fetching missing tx");
        assert!(nodes[1].node().has_tx(&tx_id(&t2)), "missing tx fetched into mempool");
    }

    #[test]
    fn malformed_frame_penalizes_sender() {
        let hub = InProcHub::new();
        let a = InProcTransport::new(PeerId(1), Arc::clone(&hub));
        let t1 = InProcTransport::new(PeerId(2), Arc::clone(&hub));
        hub.link(PeerId(1), PeerId(2));
        let mut node = P2pNode::new(t1, stub(), [2; 32]);
        node.add_peer(PeerId(1), None);
        // Send junk that is not a valid envelope.
        a.send(PeerId(2), &[0xFF; 20]).unwrap();
        node.tick();
        assert!(node.peers().get(PeerId(1)).unwrap().score < 0, "sender penalized");
    }

    // ── M9-N5: committee over network ───────────────────────────────────────

    /// Equivocation evidence path: one node holds proof that a member double-signed
    /// a slot; announcing it tombstones that member on EVERY node — the automated
    /// slash executing across the network with no human in the path (committee-gov
    /// §3).
    #[test]
    fn equivocation_evidence_gossip_tombstones_whole_network() {
        // mesh() builds independent-but-deterministic committees → identical keys,
        // so `validators` from a fresh build verify on every node.
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        nodes[0].announce_evidence(conflicting_evidence(&validators, 3, 8));
        run(&mut nodes);

        for (i, n) in nodes.iter().enumerate() {
            assert!(n.node().is_tombstoned(3), "node {i} tombstoned the equivocator");
        }
    }

    /// A node that receives two conflicting checkpoints for the same slot detects
    /// the equivocation itself (no pre-packaged evidence) and gossips it, so the
    /// whole network converges on the tombstone.
    #[test]
    fn conflicting_checkpoints_auto_detected_and_propagated() {
        let (_c, validators) = devnet_committee(7); // quorum 5
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Two checkpoints at height 8 with different block hashes; signer 3 is in
        // both vote sets (it equivocates). Node 1 originates one, node 2 the other;
        // node 0 receives both and detects.
        let cp_a = Checkpoint::new(8, [0xAA; 32], [0xAA; 32]);
        let cp_b = Checkpoint::new(8, [0xBB; 32], [0xBB; 32]);
        let votes_a: Vec<Vote> =
            [0, 1, 2, 3, 4].iter().map(|&s| validators[s].sign_checkpoint(&cp_a)).collect();
        let votes_b: Vec<Vote> =
            [3, 5, 6, 0, 1].iter().map(|&s| validators[s].sign_checkpoint(&cp_b)).collect();
        nodes[1].announce_checkpoint(cp_a, votes_a);
        nodes[2].announce_checkpoint(cp_b, votes_b);
        run(&mut nodes);

        // Signer 3 (in both) is tombstoned everywhere via the auto-detected evidence.
        for (i, n) in nodes.iter().enumerate() {
            assert!(n.node().is_tombstoned(3), "node {i} converged on the tombstone");
        }
    }

    /// NEGATIVE — tombstoned votes MUST NOT count toward quorum, over the network
    /// (frozen §4). With 3 of 7 tombstoned, a checkpoint carrying all 7 votes has
    /// only 4 that count (< quorum 5) and finalizes nowhere.
    #[test]
    fn tombstoned_vote_excluded_from_quorum_over_network() {
        let (_c, validators) = devnet_committee(7); // quorum 5
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);

        // Tombstone signers 0,1,2 network-wide via gossiped evidence.
        for s in [0usize, 1, 2] {
            nodes[0].announce_evidence(conflicting_evidence(&validators, s, 90 + s as u64));
        }
        run(&mut nodes);
        for n in &nodes {
            for s in [0, 1, 2] {
                assert!(n.node().is_tombstoned(s));
            }
        }

        // A checkpoint at height 2 signed by ALL 7: the 3 tombstoned are dropped,
        // leaving 4 < 5. (announce_checkpoint won't relay a non-finalizing cp, so
        // feed both nodes directly.)
        let cp = Checkpoint::new(2, [0x22; 32], [0x22; 32]);
        let votes: Vec<Vote> = validators.iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes.clone());
        nodes[1].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(
                n.node().finality().finalized_height(),
                None,
                "node {i}: tombstoned votes must not reach quorum"
            );
        }
    }

    /// NEGATIVE — a checkpoint that does not strictly advance the finalized height
    /// is rejected over the network; finality stays where it was.
    #[test]
    fn non_advancing_checkpoint_rejected_over_network() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Finalize height 8 across the network.
        let cp8 = Checkpoint::new(8, [8; 32], [8; 32]);
        let v8: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp8)).collect();
        nodes[0].announce_checkpoint(cp8, v8);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(8));
        }
        let counts: Vec<usize> = nodes.iter().map(|n| n.node().finality().count()).collect();

        // A lower checkpoint (height 4) with a valid quorum must NOT advance.
        let cp4 = Checkpoint::new(4, [4; 32], [4; 32]);
        let v4: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp4)).collect();
        nodes[0].announce_checkpoint(cp4, v4.clone());
        nodes[1].announce_checkpoint(cp4, v4);
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.node().finality().finalized_height(), Some(8), "node {i} unchanged");
            assert_eq!(n.node().finality().count(), counts[i], "no extra checkpoint recorded");
        }
    }

    /// Ebb-and-Flow over the network: with no committee finality the mesh runs in
    /// degraded probabilistic mode; a checkpoint near the tip restores Final on
    /// every node (consensus §4).
    #[test]
    fn finality_degrades_and_recovers_over_network() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(3);
        run(&mut nodes);

        // Grow a 20-block chain by gossip; nothing finalized ⇒ degraded everywhere.
        let mut parent = genesis();
        for i in 0..20u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.finality_status(), FinalityStatus::Degraded, "no finality ⇒ degraded");
        }

        // Finalize the tip → Final on every node.
        let tip_h = nodes[0].node().tip_height();
        let tip_hash = nodes[0].node().chain().tip_hash();
        let cp = Checkpoint::new(tip_h, tip_hash, tip_hash);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.finality_status(), FinalityStatus::Final, "finality resumes cleanly");
        }
    }

    /// Checkpoint cadence over the network: driving finalization on the 8-block
    /// grid (`next_checkpoint_height`) lands finality on the largest slot ≤ tip.
    #[test]
    fn checkpoints_follow_the_8_block_cadence() {
        let (_c, validators) = devnet_committee(7);
        let (mut nodes, _hub) = mesh(2);
        run(&mut nodes);

        let mut parent = genesis();
        for i in 0..20u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);

        let cadence = qlab_devnet::params_devnet::CHECKPOINT_CADENCE_BLOCKS; // 8
        let mut finalized: Option<u64> = None;
        while let Some(h) = next_checkpoint_height(finalized, nodes[0].node().tip_height(), cadence) {
            let bh = nodes[0].node().chain().main_chain()[h as usize];
            let cp = Checkpoint::new(h, bh, bh);
            let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
            nodes[0].announce_checkpoint(cp, votes);
            run(&mut nodes);
            finalized = Some(h);
        }
        // Tip 20 → slots 8, 16 finalize; 24 is not reached.
        assert_eq!(finalized, Some(16));
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(16));
        }
    }

    /// Epoch membership machinery over the network: the committee advances epochs
    /// as the gossiped chain crosses boundaries (committee-gov §2). Uses a small
    /// epoch so a short chain crosses one.
    #[test]
    fn epoch_advances_with_the_chain_over_network() {
        let (committee, validators) = devnet_committee(7);
        let sched = EpochSchedule::new(8); // small epoch: boundary at height 8
        let hub = InProcHub::new();
        let mut nodes: Vec<InProcP2p> = (0..2)
            .map(|i| {
                let t = InProcTransport::new(PeerId(i + 1), Arc::clone(&hub));
                let ec = EpochCommittee::genesis(
                    sched,
                    CommitteeState::new(committee.clone(), BOND_AMOUNT),
                );
                P2pNode::new(t, StubNode::with_epoch(genesis(), ec), [i as u8 + 1; 32])
            })
            .collect();
        hub.link(PeerId(1), PeerId(2));
        nodes[0].add_peer(PeerId(2), None);
        nodes[1].add_peer(PeerId(1), None);
        run(&mut nodes);

        // Grow the chain to height 10 (crosses the height-8 boundary) via gossip.
        let mut parent = genesis();
        for i in 0..10u64 {
            let child = BlockHeader::child_of(&parent, (i + 1) * 75, 1000, [(i as u8) + 1; 32]);
            nodes[0].announce_header(child);
            parent = child;
        }
        run(&mut nodes);
        for (i, n) in nodes.iter().enumerate() {
            assert_eq!(n.node().committee().current_epoch(), 1, "node {i} sealed epoch 0");
            // No membership change was staged, so the epoch-1 roster is the genesis
            // set intact — all members Active.
            let st = n.node().committee().state();
            for idx in 0..st.size() {
                assert_eq!(st.status(idx), Some(MemberStatus::Active));
            }
        }

        // A checkpoint in epoch 1 still finalizes against the (unchanged) committee.
        let bh = nodes[0].node().chain().main_chain()[8];
        let cp = Checkpoint::new(8, bh, bh);
        let votes: Vec<Vote> = validators[..5].iter().map(|v| v.sign_checkpoint(&cp)).collect();
        nodes[0].announce_checkpoint(cp, votes);
        run(&mut nodes);
        for n in &nodes {
            assert_eq!(n.node().finality().finalized_height(), Some(8));
        }
    }
}
