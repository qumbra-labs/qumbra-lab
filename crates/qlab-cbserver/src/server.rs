//! The §2 endpoints over localhost HTTP (`tiny_http`), in-memory.
//!
//! Endpoints (wallet-interop-spec §2):
//! - `GET /v1/compact?from=<height>&to=<height>` — range-stream of compact
//!   groups per block ([`crate::codec::encode_compact_response`]).
//! - `GET /v1/nullifiers?from=<height>&to=<height>` — the per-block nullifier
//!   lists a wallet subtracts its own spent notes against
//!   ([`crate::codec::NullifierPage`], lab issue #314). **Bulk over a range
//!   only** — a per-nullifier probe would tell this server which notes are the
//!   asker's, so there is no such form and must never be one. Without this
//!   route a wallet pointed at the reference server can quote no balance at
//!   all, because a figure that cannot subtract spends is not quotable.
//! - `GET /v1/coinbase?from=<height>&to=<height>` — the per-block coinbase facts
//!   a mining wallet matches its own `rkm` against
//!   ([`crate::codec::CoinbasePage`], lab #415). **Bulk over a range only.**
//!   Without this route the compact wire is a wallet's only source and it
//!   carries no `coinbase_rkm`, so a mining-only wallet reads `0` forever — the
//!   figure being wrong in the safe direction is not a defence, because it is
//!   printed under `complete`.
//! - `GET /v1/block/<height>/tx/<index>/full` — full ciphertext fetch on a scan
//!   match ([`crate::codec::encode_full_response`]).
//! - `GET /v1/tree/frontier?at=<height>` — commitment-tree frontier for witness
//!   maintenance ([`crate::tree::Frontier::to_bytes`]).
//!
//! **Trust posture / Tor OUT of scope.** This binds `127.0.0.1:0` and serves
//! localhost only — no external network. Per §2 the server serves consensus
//! data verbatim and can neither forge nor decrypt; it DOES observe requester
//! IP / height ranges / full-fetch pattern (documented; the decoy over-fetch
//! mitigation lives client-side, see [`crate::client`]). No persistence — a
//! reference server serves, it does not store.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use tiny_http::{Method, Response, Server};

use crate::codec::{encode_compact_response, encode_full_response, CoinbasePage, NullifierPage};
use crate::data::Devnet;

/// A running server: bound address + the worker thread. Drop-safe via
/// [`ServerHandle::shutdown`].
pub struct ServerHandle {
    addr: SocketAddr,
    server: Arc<Server>,
    thread: Option<JoinHandle<()>>,
    /// Total requests served (for tests/reports).
    served: Arc<AtomicU64>,
}

impl ServerHandle {
    /// Base URL, e.g. `http://127.0.0.1:54321`.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn requests_served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// Stop the server and join the worker thread.
    pub fn shutdown(mut self) {
        self.server.unblock();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Start the reference server on `127.0.0.1:0` (an ephemeral localhost port),
/// serving `devnet`. Returns once the socket is bound.
pub fn serve(devnet: Arc<Devnet>) -> ServerHandle {
    let server = Arc::new(Server::http("127.0.0.1:0").expect("bind localhost ephemeral port"));
    let addr = server
        .server_addr()
        .to_ip()
        .expect("tcp listener has an ip address");
    let served = Arc::new(AtomicU64::new(0));

    let worker_server = Arc::clone(&server);
    let worker_served = Arc::clone(&served);
    let thread = std::thread::spawn(move || {
        for request in worker_server.incoming_requests() {
            worker_served.fetch_add(1, Ordering::Relaxed);
            // GET only.
            if *request.method() != Method::Get {
                let _ = request.respond(Response::from_string("method not allowed").with_status_code(405));
                continue;
            }
            let url = request.url().to_string();
            let response = route(&devnet, &url);
            let _ = match response {
                Ok(bytes) => request.respond(Response::from_data(bytes)),
                Err((code, msg)) => request.respond(Response::from_string(msg).with_status_code(code)),
            };
        }
    });

    ServerHandle { addr, server, thread: Some(thread), served }
}

type RouteResult = Result<Vec<u8>, (u16, &'static str)>;

/// Pure routing/handler logic (URL → response bytes), exposed for direct unit
/// testing without a socket.
pub fn route(devnet: &Devnet, url: &str) -> RouteResult {
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (url, ""),
    };
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();

    match segs.as_slice() {
        // /v1/compact?from=&to=
        ["v1", "compact"] => {
            let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
            let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
            if to < from {
                return Err((400, "'to' < 'from'"));
            }
            Ok(encode_compact_response(&devnet.compact_range(from, to)))
        }
        // /v1/nullifiers?from=&to= — the per-block nullifier lists a wallet
        // subtracts its own spent notes against (lab issue #314). Bulk over a
        // range; there is deliberately no per-nullifier membership form, because
        // "is nf X spent" would tell this server which notes are the asker's.
        ["v1", "nullifiers"] => {
            let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
            let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
            if to < from {
                return Err((400, "'to' < 'from'"));
            }
            Ok(NullifierPage::page(devnet.nullifier_range(from, to), from, to).to_bytes())
        }
        // /v1/coinbase?from=&to= — the per-block coinbase facts a mining wallet
        // matches its own rkm against (lab #415). Bulk over a range; there is
        // deliberately no `?rkm=` form, because asking "did this key mine
        // anything" is the question `/v1/nullifiers` refuses in its own shape.
        ["v1", "coinbase"] => {
            let from = query_u64(query, "from").ok_or((400, "missing/invalid 'from'"))?;
            let to = query_u64(query, "to").ok_or((400, "missing/invalid 'to'"))?;
            if to < from {
                return Err((400, "'to' < 'from'"));
            }
            Ok(CoinbasePage::page(devnet.coinbase_range(from, to), from, to).to_bytes())
        }
        // /v1/block/<height>/tx/<index>/full
        ["v1", "block", h, "tx", i, "full"] => {
            let height = h.parse::<u64>().map_err(|_| (400, "invalid height"))?;
            let index = i.parse::<u64>().map_err(|_| (400, "invalid tx index"))?;
            let payloads = devnet
                .full_payloads(height, index)
                .ok_or((404, "no such (height, tx)"))?;
            Ok(encode_full_response(&payloads))
        }
        // /v1/tree/frontier?at=<height>
        ["v1", "tree", "frontier"] => {
            let at = query_u64(query, "at").ok_or((400, "missing/invalid 'at'"))?;
            let count = devnet.leaves_at(at);
            Ok(devnet.tree.frontier_at(count).to_bytes())
        }
        _ => Err((404, "unknown endpoint")),
    }
}

/// Parse `key=<u64>` from a `&`-separated query string.
fn query_u64(query: &str, key: &str) -> Option<u64> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key {
                return v.parse::<u64>().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_compact_response, decode_full_response};
    use crate::data::GenParams;
    use crate::tree::Frontier;

    fn devnet() -> Arc<Devnet> {
        Arc::new(Devnet::generate(GenParams::default()))
    }

    #[test]
    fn route_compact_range() {
        let d = devnet();
        let bytes = route(&d, "/v1/compact?from=1&to=3").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height, 1);
        assert_eq!(blocks[0].groups.len(), GenParams::default().txs_per_block as usize);
    }

    #[test]
    fn route_full_and_frontier() {
        let d = devnet();
        // tx 0 of block 1 is a 2-of-1 to our wallet → one recipient, two payloads.
        let full = route(&d, "/v1/block/1/tx/0/full").unwrap();
        let per_recipient = decode_full_response(&full).unwrap();
        assert_eq!(per_recipient.len(), 1);
        assert_eq!(per_recipient[0].len(), 2, "2-of-1 → two AEAD payloads");

        let front = route(&d, "/v1/tree/frontier?at=2").unwrap();
        let f = Frontier::from_bytes(&front).unwrap();
        assert_eq!(f.root(), d.tree.root_at(d.leaves_at(2)), "served frontier reconstructs the tree root");
    }

    /// The reference server serves the nullifier stream too (lab issue #314) —
    /// the projection is the block's own `TxPublic::nullifiers`, and every
    /// height in range is present so a client can tell coverage from silence.
    ///
    /// Without this route a wallet pointed here quotes **no** balance: the
    /// spend-subtraction is required, not optional, and its absence is honestly
    /// reported as `UNAVAILABLE` rather than papered over with a number.
    #[test]
    fn route_nullifier_range() {
        let d = devnet();
        let bytes = route(&d, "/v1/nullifiers?from=1&to=3").unwrap();
        let page = crate::codec::NullifierPage::from_bytes(&bytes).expect("the served wire");
        assert_eq!((page.from, page.to), (1, 3), "the echoes are the request's");
        assert_eq!(page.blocks.len(), 3, "every held height in range");
        for (i, blk) in page.blocks.iter().enumerate() {
            assert_eq!(blk.height, 1 + i as u64, "ascending and contiguous");
            let stored = d.block(blk.height).expect("held");
            let committed: Vec<[u8; 32]> = stored
                .body
                .txs
                .iter()
                .flat_map(|t| t.public.nullifiers.iter().copied())
                .collect();
            assert_eq!(
                blk.nullifiers, committed,
                "the served list IS the block's own nullifier section, in block order"
            );
        }
        // A range past the tip is an empty page, not an error.
        let beyond = crate::codec::NullifierPage::from_bytes(
            &route(&d, "/v1/nullifiers?from=9000&to=9001").unwrap(),
        )
        .unwrap();
        assert!(beyond.blocks.is_empty());
    }

    /// The reference server serves the coinbase stream too (lab #415) — the
    /// projection is the block's own body fields, and every height in range is
    /// present so a client can tell coverage from silence.
    ///
    /// Without this route a mining-only wallet pointed here reads `0` under
    /// `complete`: the compact wire it would otherwise be scanning carries no
    /// `coinbase_rkm` at all, so the note category is not merely missing from
    /// the answer, it is absent from the question.
    #[test]
    fn route_coinbase_range() {
        let d = devnet();
        let bytes = route(&d, "/v1/coinbase?from=1&to=3").unwrap();
        let page = crate::codec::CoinbasePage::from_bytes(&bytes).expect("the served wire");
        assert_eq!((page.from, page.to), (1, 3), "the echoes are the request's");
        assert_eq!(page.blocks.len(), 3, "every held height in range");
        for (i, blk) in page.blocks.iter().enumerate() {
            let height = 1 + i as u64;
            assert_eq!(blk.height, height, "ascending and contiguous");
            let stored = d.block(height).expect("held");
            assert_eq!(
                blk.coinbase_rkm, stored.body.coinbase_rkm,
                "the served payee IS the block's own coinbase_rkm"
            );
            assert_eq!(blk.coinbase, stored.body.coinbase);
            assert_eq!(blk.fees, stored.body.total_fees());
            assert_eq!(blk.name_burn, stored.body.total_name_burn());
        }
        assert!(!page.is_truncated(), "three of three is not a short answer");

        // A range past the tip is an empty page, not an error.
        let beyond = crate::codec::CoinbasePage::from_bytes(
            &route(&d, "/v1/coinbase?from=9000&to=9001").unwrap(),
        )
        .unwrap();
        assert!(beyond.blocks.is_empty());

        // 🔴 A devnet one miner mined: every block pays the same rkm, which is
        // the shape a mining-only wallet actually meets.
        let mine = [0x11u64, 0x22, 0x33, 0x44];
        let mined = Devnet::generate(GenParams { miner_rkm: Some(mine), ..GenParams::default() });
        let all = crate::codec::CoinbasePage::from_bytes(
            &route(&mined, "/v1/coinbase?from=0&to=99").unwrap(),
        )
        .unwrap();
        assert!(all.blocks.iter().all(|b| b.coinbase_rkm == mine), "one payee, every block");
    }

    #[test]
    fn route_errors() {
        let d = devnet();
        assert_eq!(route(&d, "/v1/compact?from=5&to=1"), Err((400, "'to' < 'from'")));
        // The nullifier route's bounds refuse exactly like the compact route's —
        // never an empty success, which a wallet would subtract nothing against
        // and then quote as a balance.
        assert_eq!(route(&d, "/v1/nullifiers?from=5&to=1"), Err((400, "'to' < 'from'")));
        assert_eq!(route(&d, "/v1/nullifiers?to=1"), Err((400, "missing/invalid 'from'")));
        assert_eq!(route(&d, "/v1/nullifiers?from=1"), Err((400, "missing/invalid 'to'")));
        // 🔴 And there is no per-nullifier membership form: a probe is a 404 by
        // shape, so it cannot be answered by accident.
        assert!(matches!(route(&d, "/v1/nullifier?nf=a1a1"), Err((404, _))));
        assert!(matches!(route(&d, "/v1/nullifiers/a1a1"), Err((404, _))));
        // The coinbase route's bounds refuse identically (lab #415), and — the
        // part that matters — there is no per-key form: `?rkm=` cannot be
        // answered by accident because the path itself is a 404 by shape.
        assert_eq!(route(&d, "/v1/coinbase?from=5&to=1"), Err((400, "'to' < 'from'")));
        assert_eq!(route(&d, "/v1/coinbase?to=1"), Err((400, "missing/invalid 'from'")));
        assert_eq!(route(&d, "/v1/coinbase?from=1"), Err((400, "missing/invalid 'to'")));
        assert!(matches!(route(&d, "/v1/coinbase/abcd"), Err((404, _))));
        assert!(matches!(route(&d, "/v1/miner?rkm=a1a1"), Err((404, _))));
        assert_eq!(route(&d, "/v1/compact?to=1"), Err((400, "missing/invalid 'from'")));
        assert!(matches!(route(&d, "/v1/block/999/tx/0/full"), Err((404, _))));
        assert!(matches!(route(&d, "/v1/nope"), Err((404, _))));
    }

    #[test]
    fn end_to_end_over_localhost_socket() {
        let d = devnet();
        let handle = serve(Arc::clone(&d));
        let base = handle.base_url();
        assert!(base.starts_with("http://127.0.0.1:"));
        let bytes = crate::client::http_get(&base, "/v1/compact?from=1&to=2").unwrap();
        let blocks = decode_compact_response(&bytes).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(handle.requests_served() >= 1);
        handle.shutdown();
    }
}
