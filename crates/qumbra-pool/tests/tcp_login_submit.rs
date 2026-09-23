//! Real TCP: login → job → submit against a loopback listener.
//! Targeted debug; no RandomX, no node.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{AggregateProofSlot, BlockHeader, EpochSupplyAttestation};
use qlab_stratum::blob::{extranonce_of, miner_nonce_of, V5_BLOB_LEN};
use qlab_stratum::codec::{decode_line, DecodedLine};
use qlab_stratum::types::{LoginParams, LoginResult, StratumRequest, SubmitParams};
use qumbra_pool::endpoint::serve;
use qumbra_pool::template::{HeldTemplateSource, Template};
use qumbra_pool::{
    ConnGuard, JobOutbox, ListenLimits, Pool, REASON_CONNECTION_CAP, REASON_LINE_TOO_LONG,
    REASON_PER_IP, REASON_REQUEST_TIMEOUT, TemplateWatch, WatchAction,
};

fn sample_template() -> Template {
    sample_template_at(100)
}

fn sample_template_at(height: u64) -> Template {
    Template {
        form: GenesisForm::V5,
        header: BlockHeader { ext: qlab_devnet::annulet::HeaderExt::NONE,
            prev: [0x11; 32],
            height,
            timestamp: 1_785_000_000,
            difficulty: 256,
            nonce: 0,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        },
        seed_hash: [0x33; 32],
        next_seed_hash: None,
        body: None,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn tcp_login_job_submit_round_trips() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool =
        Arc::new(Pool::new(1024, Box::new(HeldTemplateSource::new(sample_template()))).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let pool_t = Arc::clone(&pool);
    let outbox = Arc::new(JobOutbox::new());
    let guard_t = Arc::new(ConnGuard::new(ListenLimits::default()));
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox, guard_t));

    // Retry connect — the accept loop sleeps 20 ms on WouldBlock.
    let mut stream = None;
    for _ in 0..50 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut stream = stream.expect("connect to pool");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.set_nodelay(true).unwrap();

    let login = StratumRequest::login(
        1,
        &LoginParams {
            login: "alice".into(),
            pass: "x".into(),
            agent: Some("XMRig/6.21.0".into()),
            algo: Some(vec!["rx/0".into()]),
            rigid: None,
        },
    )
    .unwrap();
    let line = qlab_stratum::codec::encode_request(&login).unwrap();
    stream.write_all(line.as_bytes()).unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).unwrap();
    let DecodedLine::Response(resp) = decode_line(&resp_line).unwrap() else {
        panic!("expected login response, got {resp_line}");
    };
    let result: LoginResult = resp.parse_login_result().unwrap();
    assert_eq!(result.status, "OK");
    let blob = hex_decode(&result.job.blob);
    assert_eq!(blob.len(), V5_BLOB_LEN);
    assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
    assert_ne!(extranonce_of(&blob).unwrap(), [0, 0, 0, 0]);

    let submit = StratumRequest::submit(
        2,
        &SubmitParams {
            id: result.id.clone(),
            job_id: result.job.job_id.clone(),
            nonce: "d0030040".into(),
            result: "00".repeat(32),
            algo: Some("rx/0".into()),
        },
    )
    .unwrap();
    stream
        .write_all(
            qlab_stratum::codec::encode_request(&submit)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    stream.flush().unwrap();
    resp_line.clear();
    reader.read_line(&mut resp_line).unwrap();
    let DecodedLine::Response(resp) = decode_line(&resp_line).unwrap() else {
        panic!("expected submit response, got {resp_line}");
    };
    assert!(resp.error.is_none());
    assert_eq!(resp.result.unwrap()["status"], "OK");
    assert_eq!(pool.ledger_snapshot().accepted_count("alice"), 1);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}

/// The test lab #545 exists for: a real socket, a login, a tip move, and
/// a `job` notification on the wire with the new height. A unit test of
/// `replace_template`'s return value cannot catch the discarded-Ok bug.
#[test]
fn tcp_tip_change_pushes_job_notify_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Arc::new(
        Pool::new(
            1024,
            Box::new(HeldTemplateSource::new(sample_template_at(100))),
        )
        .unwrap(),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let pool_t = Arc::clone(&pool);
    let outbox = Arc::new(JobOutbox::new());
    let guard_t = Arc::new(ConnGuard::new(ListenLimits::default()));
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox, guard_t));

    let mut stream = None;
    for _ in 0..50 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut stream = stream.expect("connect to pool");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.set_nodelay(true).unwrap();

    let login = StratumRequest::login(
        1,
        &LoginParams {
            login: "alice".into(),
            pass: "x".into(),
            agent: Some("XMRig/6.21.0".into()),
            algo: Some(vec!["rx/0".into()]),
            rigid: None,
        },
    )
    .unwrap();
    stream
        .write_all(
            qlab_stratum::codec::encode_request(&login)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).unwrap();
    let DecodedLine::Response(resp) = decode_line(&resp_line).unwrap() else {
        panic!("expected login response, got {resp_line}");
    };
    let result: LoginResult = resp.parse_login_result().unwrap();
    assert_eq!(result.status, "OK");
    assert_eq!(result.job.height, Some(100));
    let login_job = result.job.job_id.clone();

    let pushed = pool
        .replace_template(Box::new(HeldTemplateSource::new(sample_template_at(101))))
        .unwrap();
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].1.height, Some(101));
    assert_ne!(pushed[0].1.job_id, login_job);

    resp_line.clear();
    reader
        .read_line(&mut resp_line)
        .expect("job notify must arrive on the wire after tip change");
    let DecodedLine::Request(req) = decode_line(&resp_line).unwrap() else {
        panic!("expected job notification, got {resp_line}");
    };
    assert_eq!(req.method, "job");
    assert_eq!(req.params.get("height").and_then(|v| v.as_u64()), Some(101));
    let new_id = req
        .params
        .get("job_id")
        .and_then(|v| v.as_str())
        .expect("job_id");
    assert_ne!(new_id, login_job);

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}

/// The lab #598 property: the honest refusal still reaches the miner, but
/// the same registered socket receives the recovery job without a reconnect.
#[test]
fn tcp_template_gap_holds_session_and_recovers_without_reconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool =
        Arc::new(Pool::new(1024, Box::new(HeldTemplateSource::new(sample_template()))).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let pool_t = Arc::clone(&pool);
    let outbox = Arc::new(JobOutbox::new());
    let guard_t = Arc::new(ConnGuard::new(ListenLimits::default()));
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox, guard_t));

    let mut stream = None;
    for _ in 0..50 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut stream = stream.expect("connect to pool");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.set_nodelay(true).unwrap();

    let login = StratumRequest::login(
        1,
        &LoginParams {
            login: "alice".into(),
            pass: "x".into(),
            agent: Some("XMRig/6.21.0".into()),
            algo: Some(vec!["rx/0".into()]),
            rigid: None,
        },
    )
    .unwrap();
    stream
        .write_all(
            qlab_stratum::codec::encode_request(&login)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).unwrap();
    let DecodedLine::Response(_) = decode_line(&resp_line).unwrap() else {
        panic!("expected login response, got {resp_line}");
    };

    pool.suspend_work(
        "template-unavailable: 3 consecutive poll failures (max 3) / 3000ms since last good template (max 3000ms)",
    );

    resp_line.clear();
    let n = reader
        .read_line(&mut resp_line)
        .expect("named stop must arrive on the wire");
    assert!(n > 0, "connection closed without naming the stall");
    let DecodedLine::Response(resp) = decode_line(&resp_line).unwrap() else {
        panic!("expected error response, got {resp_line}");
    };
    let err = resp.error.expect("named stall");
    assert!(
        err.message.contains("3 consecutive poll failures"),
        "got {}",
        err.message
    );
    assert!(
        err.message.contains("3000ms since last good template"),
        "got {}",
        err.message
    );

    let jobs = pool
        .replace_template(Box::new(HeldTemplateSource::new(sample_template_at(101))))
        .unwrap();
    assert_eq!(
        jobs.len(),
        1,
        "the same session must remain registered during suspension"
    );

    resp_line.clear();
    let n = reader
        .read_line(&mut resp_line)
        .expect("recovery job must arrive on the held socket");
    assert!(n > 0, "held socket closed before recovery");
    let DecodedLine::Request(req) = decode_line(&resp_line).unwrap() else {
        panic!("expected recovery job notification, got {resp_line}");
    };
    assert_eq!(req.method, "job");
    assert_eq!(req.params.get("height").and_then(|v| v.as_u64()), Some(101));

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}

/// The hold is bounded: the real watch verdict crosses the pool/outbox/socket
/// seam and ends the session after a sustained outage so the miner can fail over.
#[test]
fn tcp_sustained_template_gap_eventually_disconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool =
        Arc::new(Pool::new(1024, Box::new(HeldTemplateSource::new(sample_template()))).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let pool_t = Arc::clone(&pool);
    let outbox = Arc::new(JobOutbox::new());
    let guard_t = Arc::new(ConnGuard::new(ListenLimits::default()));
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox, guard_t));

    let mut stream = connect(addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let login = StratumRequest::login(
        1,
        &LoginParams {
            login: "alice".into(),
            pass: "x".into(),
            agent: Some("XMRig/6.21.0".into()),
            algo: Some(vec!["rx/0".into()]),
            rigid: None,
        },
    )
    .unwrap();
    stream
        .write_all(
            qlab_stratum::codec::encode_request(&login)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    stream.flush().unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let DecodedLine::Response(_) = decode_line(&line).unwrap() else {
        panic!("expected login response, got {line}");
    };

    let watch = TemplateWatch::new(1, Duration::from_millis(1), Duration::from_millis(100));
    let first = watch.record_err().expect("failure threshold suspends");
    assert!(matches!(first, WatchAction::Suspend(_)));
    pool.apply_watch_action(first);
    line.clear();
    reader.read_line(&mut line).expect("named suspension");
    assert!(line.contains("1 consecutive poll failures"), "got: {line}");

    thread::sleep(Duration::from_millis(150));
    let terminal = watch.record_err().expect("sustained bound disconnects");
    assert!(matches!(terminal, WatchAction::Disconnect(_)));
    pool.apply_watch_action(terminal);
    line.clear();
    let n = reader.read_line(&mut line).expect("named terminal refusal");
    assert!(n > 0, "disconnect must name the sustained outage first");
    assert!(line.contains("2 consecutive poll failures"), "got: {line}");
    line.clear();
    assert_eq!(reader.read_line(&mut line).unwrap(), 0, "session must end");

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}

fn spawn_guarded(
    limits: ListenLimits,
) -> (
    SocketAddr,
    Arc<AtomicBool>,
    Arc<ConnGuard>,
    thread::JoinHandle<std::io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool =
        Arc::new(Pool::new(1024, Box::new(HeldTemplateSource::new(sample_template()))).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let outbox = Arc::new(JobOutbox::new());
    let guard = Arc::new(ConnGuard::new(limits));
    let guard_t = Arc::clone(&guard);
    let server = thread::spawn(move || serve(listener, pool, stop_t, outbox, guard_t));
    (addr, stop, guard, server)
}

fn connect(addr: SocketAddr) -> TcpStream {
    for _ in 0..50 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Ok(s) => {
                s.set_nodelay(true).unwrap();
                return s;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    panic!("connect to pool at {addr}");
}

fn wait_live(guard: &ConnGuard, n: u32) {
    for _ in 0..100 {
        if guard.snapshot().live == n {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("live != {n}: {:?}", guard.snapshot());
}

fn named_error_message(stream: &TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .expect("named refusal must arrive on the wire");
    assert!(n > 0, "connection closed without naming the refusal");
    let DecodedLine::Response(resp) = decode_line(&line).unwrap() else {
        panic!("expected error response, got {line}");
    };
    resp.error.expect("named refusal").message
}

/// The first of the three attacks: past the cap, refuse by name, count it,
/// and do not spawn a handler thread for the overflow (live stays at the cap).
#[test]
fn tcp_connection_flood_past_the_cap_is_named_and_counted() {
    let limits = ListenLimits::from_parts(
        2,
        Some(2),
        4096,
        Duration::from_secs(30),
        Some(Duration::from_secs(30)),
    );
    let (addr, stop, guard, server) = spawn_guarded(limits);
    let _a = connect(addr);
    let _b = connect(addr);
    wait_live(&guard, 2);

    let overflow = connect(addr);
    let msg = named_error_message(&overflow);
    assert!(msg.starts_with(REASON_CONNECTION_CAP), "got {msg}");
    let snap = guard.snapshot();
    assert_eq!(snap.live, 2, "overflow must not occupy a slot: {snap:?}");
    assert!(
        snap.refused_connection_cap >= 1,
        "flood must be counted: {snap:?}"
    );
    assert_eq!(snap.refused_per_ip, 0, "{snap:?}");

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(overflow);
    let _ = server.join();
}

/// Same source IP, per-IP cap of 1: the second connection is its own
/// named refusal, not the global cap.
#[test]
fn tcp_per_ip_cap_is_its_own_named_refusal() {
    let limits = ListenLimits::from_parts(
        8,
        Some(1),
        4096,
        Duration::from_secs(30),
        Some(Duration::from_secs(30)),
    );
    let (addr, stop, guard, server) = spawn_guarded(limits);
    let _held = connect(addr);
    wait_live(&guard, 1);

    let overflow = connect(addr);
    let msg = named_error_message(&overflow);
    assert!(msg.starts_with(REASON_PER_IP), "got {msg}");
    let snap = guard.snapshot();
    assert_eq!(snap.live, 1, "{snap:?}");
    assert!(snap.refused_per_ip >= 1, "{snap:?}");
    assert_eq!(snap.refused_connection_cap, 0, "{snap:?}");

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(overflow);
    let _ = server.join();
}

/// The second of the three attacks: a client that never sends `\n` and
/// fills past the line bound is refused by name, not buffered forever.
#[test]
fn tcp_unterminated_line_is_named_and_counted() {
    let limits = ListenLimits::from_parts(
        8,
        Some(8),
        32,
        Duration::from_secs(30),
        Some(Duration::from_secs(30)),
    );
    let (addr, stop, guard, server) = spawn_guarded(limits);
    let mut stream = connect(addr);
    stream.write_all(&[b'x'; 64]).unwrap();
    stream.flush().unwrap();
    let msg = named_error_message(&stream);
    assert!(msg.starts_with(REASON_LINE_TOO_LONG), "got {msg}");
    let snap = guard.snapshot();
    assert!(
        snap.refused_line_too_long >= 1,
        "unterminated line must be counted: {snap:?}"
    );

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}

/// The third of the three attacks: one byte every 150 ms, slower than the
/// 100 ms per-read timeout, no newline. The read timeout must not close
/// the socket; the request deadline must.
#[test]
fn tcp_trickling_client_is_request_timeout_not_read_timeout() {
    let limits = ListenLimits::from_parts(
        8,
        Some(8),
        4096,
        Duration::from_millis(400),
        Some(Duration::from_secs(5)),
    );
    let (addr, stop, guard, server) = spawn_guarded(limits);
    let mut stream = connect(addr);
    stream
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    stream.write_all(b"{").unwrap();
    stream.flush().unwrap();
    let t0 = Instant::now();
    let mut got = String::new();
    loop {
        thread::sleep(Duration::from_millis(150));
        let _ = stream.write_all(b"x");
        let _ = stream.flush();
        let mut buf = [0u8; 512];
        match stream.read(&mut buf) {
            Ok(0) => panic!("eof without a named request-timeout, so far: {got:?}"),
            Ok(n) => {
                got.push_str(&String::from_utf8_lossy(&buf[..n]));
                if got.contains(REASON_REQUEST_TIMEOUT) {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if t0.elapsed() > Duration::from_secs(2) {
                    panic!("trickle was not refused; elapsed {:?}", t0.elapsed());
                }
            }
            Err(e) => panic!("trickle read: {e}"),
        }
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(300),
        "request-timeout fired too fast to be distinct from the 100 ms read timeout: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "request-timeout took too long: {elapsed:?}"
    );
    let snap = guard.snapshot();
    assert!(
        snap.refused_request_timeout >= 1,
        "trickle must be counted as request-timeout: {snap:?}"
    );
    assert_eq!(
        snap.refused_connection_timeout, 0,
        "first byte arrived; this is a request timeout, not a connect-and-hold: {snap:?}"
    );

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}
