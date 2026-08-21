//! Real TCP: login → job → submit against a loopback listener.
//! Targeted debug; no RandomX, no node.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::{AggregateProofSlot, BlockHeader, EpochSupplyAttestation};
use qlab_stratum::blob::{extranonce_of, miner_nonce_of, V5_BLOB_LEN};
use qlab_stratum::codec::{decode_line, DecodedLine};
use qlab_stratum::types::{LoginParams, LoginResult, StratumRequest, SubmitParams};
use qumbra_pool::endpoint::serve;
use qumbra_pool::template::{HeldTemplateSource, Template};
use qumbra_pool::{JobOutbox, Pool};

fn sample_template() -> Template {
    sample_template_at(100)
}

fn sample_template_at(height: u64) -> Template {
    Template {
        form: GenesisForm::V5,
        header: BlockHeader {
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
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox));

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
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox));

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

/// A stall must name itself on the wire and drop the connection rather
/// than leave the miner hashing a job the pool will reject.
#[test]
fn tcp_template_unavailable_is_named_then_disconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pool =
        Arc::new(Pool::new(1024, Box::new(HeldTemplateSource::new(sample_template()))).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_t = Arc::clone(&stop);
    let pool_t = Arc::clone(&pool);
    let outbox = Arc::new(JobOutbox::new());
    let server = thread::spawn(move || serve(listener, pool_t, stop_t, outbox));

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
        err.message.starts_with("template-unavailable:"),
        "got {}",
        err.message
    );

    resp_line.clear();
    let eof = reader.read_line(&mut resp_line).unwrap();
    assert_eq!(eof, 0, "connection must drop after naming the stall");

    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(stream);
    let _ = server.join();
}
