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
use qumbra_pool::Pool;

fn sample_template() -> Template {
    Template {
        form: GenesisForm::V5,
        header: BlockHeader {
            prev: [0x11; 32],
            height: 100,
            timestamp: 1_785_000_000,
            difficulty: 256,
            nonce: 0,
            tx_body_commitment: [0x22; 32],
            aggregate_proof: AggregateProofSlot,
            epoch_supply_attestation: EpochSupplyAttestation,
        },
        seed_hash: [0x33; 32],
        next_seed_hash: None,
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
    let server = thread::spawn(move || serve(listener, pool_t, stop_t));

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
