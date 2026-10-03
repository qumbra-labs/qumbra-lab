//! **The intake listener** (lab #847 S2): `POST /v1/intake` and
//! `GET /v1/intake/<id>`, loopback only — `operator_addr`'s posture (Q1 (a)):
//! wallets reach it through a tunnel the operator sets up; a non-loopback
//! address is refused by name before anything binds.
//!
//! `POST /v1/intake` takes an artifact's raw bytes:
//!
//! | answer | when |
//! |---|---|
//! | 202 `{"v":1,"id":…,"kind":…,"replay":false}` | verified and queued |
//! | 202 `{"v":1,"id":…,"kind":…,"replay":true}` | these exact bytes were admitted before — the same id, so a wallet that lost the first answer recovers |
//! | 409 `{"v":1,"error":"conflict","key":"cnf"\|"nullifier","existing":…}` | different bytes on a key already admitted; `existing` is the held item's id |
//! | 400 `{"v":1,"error":"refused","why":…}` | not an artifact, another chain, or a proof that does not verify |
//! | 411 / 413 | no `Content-Length`, or one above [`MAX_ARTIFACT_BYTES`] — decided before the body is read |
//! | 503 `{"v":1,"error":"queue full"}` | the pending queue is at its bound; nothing recorded |
//!
//! `GET /v1/intake/<id>` answers `{"v":1,"id":…,"state":"queued"|"unknown"}`
//! — S4 adds `planned` and `landed`; a wallet's reader treats a state it does
//! not know as "not landed".
//!
//! No answer and no log line carries an artifact's bytes, a `cnf` opening,
//! `v` or `r_v`: ids, kinds and key *names* only.

use std::io::Read;
use std::net::SocketAddr;

use crate::intake::{classify, hex32, parse_hex32, verify, Chain};
use crate::queue::{Decision, Queue};

/// The largest artifact the listener reads: 1 MiB. The largest today is an
/// exit file, about the size of a P member (401,862 B in the F5-6 bundle)
/// plus its tx wire; a claim file is 327,202 B (W3c). About 2.5× headroom
/// over the larger, and a body above it is refused from `Content-Length`
/// alone, before one byte is read.
pub const MAX_ARTIFACT_BYTES: usize = 1 << 20;

/// The route.
pub const INTAKE_PATH: &str = "/v1/intake";

/// The version every JSON answer carries.
pub const INTAKE_ROUTE_VERSION: u32 = 1;

/// A loopback socket address, or a refusal naming why (Q1: intake is
/// reached through a tunnel, never exposed).
pub fn loopback(addr: &str) -> Result<SocketAddr, String> {
    let a: SocketAddr = addr.parse().map_err(|_| format!("--listen {addr:?} is not an ip:port address"))?;
    if !a.ip().is_loopback() {
        return Err(format!(
            "--listen {addr} is not a loopback address — intake is loopback only; reach it through a tunnel (lab #847 Q1)"
        ));
    }
    Ok(a)
}

/// JSON string escaping for the one free-text field (`why`).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// An intake: the chain it serves and the queue it holds.
pub struct Intake {
    pub chain: Chain,
    pub queue: Queue,
}

impl Intake {
    /// `POST /v1/intake` over a body already read: `(status, json)`. Cheap
    /// answers first (decode, replay, conflict, full); the proof last.
    pub fn post(&mut self, body: &[u8]) -> (u16, String) {
        let v = INTAKE_ROUTE_VERSION;
        let c = match classify(body, &self.chain) {
            Ok(c) => c,
            Err(why) => return (400, format!(r#"{{"v":{v},"error":"refused","why":{}}}"#, json_str(&why))),
        };
        match self.queue.decide(&c, body.len() as u64) {
            Decision::Replay { id, kind } => {
                return (202, format!(r#"{{"v":{v},"id":"{}","kind":"{}","replay":true}}"#, hex32(&id), kind.name()))
            }
            Decision::Conflict { existing, key_name } => {
                return (409, format!(r#"{{"v":{v},"error":"conflict","key":"{key_name}","existing":"{}"}}"#, hex32(&existing)))
            }
            Decision::Full => return (503, format!(r#"{{"v":{v},"error":"queue full"}}"#)),
            Decision::Fresh => {}
        }
        if let Err(why) = verify(&c, &self.chain) {
            return (400, format!(r#"{{"v":{v},"error":"refused","why":{}}}"#, json_str(&why)));
        }
        match self.queue.admit(&c, body) {
            Ok(()) => (202, format!(r#"{{"v":{v},"id":"{}","kind":"{}","replay":false}}"#, hex32(&c.id), c.kind.name())),
            Err(why) => (500, format!(r#"{{"v":{v},"error":"not recorded","why":{}}}"#, json_str(&why))),
        }
    }

    /// `GET /v1/intake/<id>`: `(status, json)`.
    pub fn status(&self, id: &str) -> (u16, String) {
        let v = INTAKE_ROUTE_VERSION;
        let Some(id) = parse_hex32(id) else {
            return (400, format!(r#"{{"v":{v},"error":"an id is 64 lower-case hex digits"}}"#));
        };
        let state = self.queue.item(&id).map_or("unknown", |i| i.state.name());
        (200, format!(r#"{{"v":{v},"id":"{}","state":"{state}"}}"#, hex32(&id)))
    }
}

/// Serve `intake` on `addr` (loopback, checked) until the process ends.
/// One request at a time: admission appends to one index, in order.
pub fn serve(addr: SocketAddr, mut intake: Intake) -> Result<(), String> {
    let server = tiny_http::Server::http(addr).map_err(|e| format!("intake listener {addr}: {e}"))?;
    eprintln!("INTAKE listening on {addr} (loopback; {} items held)", intake.queue.items().count());
    for mut req in server.incoming_requests() {
        let path = req.url().split('?').next().unwrap_or("").to_string();
        let (status, body) = match (req.method(), path.as_str()) {
            (tiny_http::Method::Post, INTAKE_PATH) => match req.body_length() {
                None => (411, format!(r#"{{"v":{INTAKE_ROUTE_VERSION},"error":"Content-Length required"}}"#)),
                Some(n) if n > MAX_ARTIFACT_BYTES => {
                    (413, format!(r#"{{"v":{INTAKE_ROUTE_VERSION},"error":"too large","limit":{MAX_ARTIFACT_BYTES}}}"#))
                }
                Some(n) => {
                    let mut buf = Vec::with_capacity(n);
                    match req.as_reader().take(n as u64).read_to_end(&mut buf) {
                        Ok(got) if got == n => {
                            let (s, b) = intake.post(&buf);
                            eprintln!("INTAKE POST -> {s} {b}");
                            (s, b)
                        }
                        _ => (400, format!(r#"{{"v":{INTAKE_ROUTE_VERSION},"error":"the body is shorter than its Content-Length"}}"#)),
                    }
                }
            },
            (tiny_http::Method::Get, p) if p.starts_with("/v1/intake/") => intake.status(&p["/v1/intake/".len()..]),
            _ => (404, format!(r#"{{"v":{INTAKE_ROUTE_VERSION},"error":"not found: POST {INTAKE_PATH} or GET {INTAKE_PATH}/<id>"}}"#)),
        };
        let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static header");
        let _ = req.respond(tiny_http::Response::from_string(body).with_status_code(status).with_header(header));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::{id_of, tests::w3c_chain, tests::W3C_CLAIM};

    fn intake(name: &str) -> (Intake, std::path::PathBuf) {
        let d = std::env::temp_dir().join(format!("qseq-intake-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        (Intake { chain: w3c_chain(), queue: Queue::open(&d).unwrap() }, d)
    }

    /// The real claim: queued, then replayed with the same id; its status
    /// reads queued; an unknown id reads unknown. No answer carries the
    /// deposit amount.
    #[test]
    fn post_queue_replay_and_status() {
        let (mut i, d) = intake("post");
        let id = hex32(&id_of(W3C_CLAIM));
        let (s, b) = i.post(W3C_CLAIM);
        assert_eq!((s, b.as_str()), (202, format!(r#"{{"v":1,"id":"{id}","kind":"claim","replay":false}}"#).as_str()));
        let (s, b) = i.post(W3C_CLAIM);
        assert_eq!((s, b), (202, format!(r#"{{"v":1,"id":"{id}","kind":"claim","replay":true}}"#)));
        assert_eq!(i.status(&id), (200, format!(r#"{{"v":1,"id":"{id}","state":"queued"}}"#)));
        let other = hex32(&[3; 32]);
        assert_eq!(i.status(&other), (200, format!(r#"{{"v":1,"id":"{other}","state":"unknown"}}"#)));
        assert_eq!(i.status("XYZ").0, 400);
        for body in [i.post(W3C_CLAIM).1, i.status(&id).1] {
            assert!(!body.contains("50000000") && !body.contains("49999996"), "an answer named the amount: {body}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A refusal is a 400 naming why, and records nothing.
    #[test]
    fn a_refusal_records_nothing() {
        let (mut i, d) = intake("refuse");
        let mut flipped = W3C_CLAIM.to_vec();
        let at = flipped.len() / 2;
        flipped[at] ^= 1;
        let (s, b) = i.post(&flipped);
        assert_eq!(s, 400, "{b}");
        assert!(b.starts_with(r#"{"v":1,"error":"refused","why":"claim file refused"#), "{b}");
        assert_eq!(i.queue.items().count(), 0);
        assert_eq!(i.post(b"junk").0, 400);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn only_loopback_binds() {
        assert!(loopback("127.0.0.1:8090").is_ok());
        assert!(loopback("[::1]:8090").is_ok());
        assert!(loopback("0.0.0.0:8090").unwrap_err().contains("not a loopback address"));
        assert!(loopback("10.0.0.5:8090").unwrap_err().contains("not a loopback address"));
        assert!(loopback("localhost:8090").unwrap_err().contains("not an ip:port"));
    }

    /// Over a real socket: the 413 is decided from Content-Length alone, a
    /// POST round-trips, a different file on the same cnf is a 409 naming
    /// the held item, the status route answers — and no response, of any
    /// kind, carries the deposit amount.
    #[test]
    fn the_listener_answers_over_a_socket() {
        use std::io::Write;
        let (i, d) = intake("socket");
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        std::thread::spawn(move || serve(addr, i));
        let req = |raw: Vec<u8>| -> String {
            for _ in 0..50 {
                if let Ok(mut s) = std::net::TcpStream::connect(addr) {
                    s.write_all(&raw).unwrap();
                    let mut out = String::new();
                    let _ = s.read_to_string(&mut out);
                    return out;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            panic!("the listener never came up");
        };
        let big = format!("POST /v1/intake HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", MAX_ARTIFACT_BYTES + 1);
        assert!(req(big.into_bytes()).starts_with("HTTP/1.1 413"));
        let mut post = format!("POST /v1/intake HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", W3C_CLAIM.len()).into_bytes();
        post.extend_from_slice(W3C_CLAIM);
        let answer = req(post);
        assert!(answer.starts_with("HTTP/1.1 202"), "{answer}");
        let id = hex32(&id_of(W3C_CLAIM));
        let status = req(format!("GET /v1/intake/{id} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").into_bytes());
        assert!(status.contains(r#""state":"queued""#), "{status}");
        // The last byte is r_v's: the file still decodes, its id moves, its
        // cnf (from the public values) does not — a 409, decided before any
        // proof work, naming the item that holds the cnf.
        let mut twin = W3C_CLAIM.to_vec();
        *twin.last_mut().unwrap() ^= 1;
        let mut post = format!("POST /v1/intake HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", twin.len()).into_bytes();
        post.extend_from_slice(&twin);
        let conflict = req(post);
        assert!(conflict.starts_with("HTTP/1.1 409"), "{conflict}");
        assert!(conflict.contains(&format!(r#""error":"conflict","key":"cnf","existing":"{id}""#)), "{conflict}");
        for r in [&answer, &status, &conflict] {
            assert!(!r.contains("50000000") && !r.contains("49999996"), "a response named the amount: {r}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
