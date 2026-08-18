//! Fixture round-trip: a hand-built xmrig-shaped login → job → submit transcript
//! through the codec + blob helpers, proving the §4 mapping is implementable
//! byte-for-byte.
//!
//! The fixture is **hand-built to the Monero stratum convention** (xmrig-proxy
//! STRATUM.md). Named deviations from a live Monero capture:
//! 1. `job.blob` is a Qumbra **v5** 97-byte header preimage, not a CryptoNote blob.
//! 2. `target` is **8-byte LE raw** (`u64::MAX/difficulty`), not 4-byte compact.
//!
//! No local mining farm; no RandomX invocation — this test only checks the
//! mapping surface the pool must speak.

use qlab_stratum::blob::{
    apply_miner_nonce, check_v5_blob, extranonce_of, miner_nonce_of, nonce_u64_of, V5_BLOB_LEN,
    V5_EXTRANONCE_OFF, V5_MINER_NONCE_OFF,
};
use qlab_stratum::codec::{decode_line, DecodedLine};
use qlab_stratum::target::{encode_target_le_hex, parse_target_hex, target_from_difficulty};
use qlab_stratum::types::{Job, LoginResult, SubmitParams};

const FIXTURE: &str = include_str!("../fixtures/xmrig_submit_transcript.jsonl");

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn fixture_lines() -> Vec<&'static str> {
    FIXTURE
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.contains("\"_comment\""))
        .collect()
}

#[test]
fn fixture_transcript_round_trips_login_job_submit() {
    let lines = fixture_lines();
    assert_eq!(lines.len(), 5, "login req, login resp, job notif, submit, submit ok");

    // 1. login request
    let login_req = match decode_line(lines[0]).unwrap() {
        DecodedLine::Request(r) => r,
        other => panic!("line0: {other:?}"),
    };
    assert_eq!(login_req.method, "login");
    let login_params = login_req.parse_login_params().unwrap();
    assert_eq!(login_params.algo.as_ref().unwrap(), &vec!["rx/0".to_string()]);

    // 2. login response carrying the initial job
    let login_resp = match decode_line(lines[1]).unwrap() {
        DecodedLine::Response(r) => r,
        other => panic!("line1: {other:?}"),
    };
    let login_result: LoginResult = login_resp.parse_login_result().unwrap();
    assert_eq!(login_result.status, "OK");
    assert_eq!(login_result.id, "sess-fixture-0001");
    check_job(&login_result.job);

    // 3. job notification (same job re-pushed — tip/seed unchanged in fixture)
    let job_notif = match decode_line(lines[2]).unwrap() {
        DecodedLine::Request(r) => r,
        other => panic!("line2: {other:?}"),
    };
    assert_eq!(job_notif.method, "job");
    let job: Job = serde_json::from_value(job_notif.params).unwrap();
    check_job(&job);
    assert_eq!(job.job_id, login_result.job.job_id);

    // 4. submit — apply miner nonce into the blob and assemble the u64
    let submit_req = match decode_line(lines[3]).unwrap() {
        DecodedLine::Request(r) => r,
        other => panic!("line3: {other:?}"),
    };
    assert_eq!(submit_req.method, "submit");
    let submit: SubmitParams = submit_req.parse_submit_params().unwrap();
    assert_eq!(submit.id, login_result.id);
    assert_eq!(submit.job_id, job.job_id);
    assert_eq!(submit.nonce, "d0030040");
    assert_eq!(hex_decode(&submit.result).len(), 32);

    let mut blob = hex_decode(&job.blob);
    assert_eq!(blob.len(), V5_BLOB_LEN);
    check_v5_blob(&blob).unwrap();

    // Before apply: miner window is zero; extranonce is the pool partition.
    assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
    assert_eq!(extranonce_of(&blob).unwrap(), [0x04, 0x03, 0x02, 0x01]);
    assert_eq!(&blob[V5_EXTRANONCE_OFF..V5_EXTRANONCE_OFF + 4], &[0x04, 0x03, 0x02, 0x01]);

    let miner_nonce = hex_decode(&submit.nonce);
    apply_miner_nonce(&mut blob, &miner_nonce).unwrap();
    assert_eq!(&blob[V5_MINER_NONCE_OFF..V5_MINER_NONCE_OFF + 4], &miner_nonce[..]);
    // Extranonce must survive the miner write — that is the whole partition claim.
    assert_eq!(extranonce_of(&blob).unwrap(), [0x04, 0x03, 0x02, 0x01]);

    let assembled = nonce_u64_of(&blob).unwrap();
    assert_eq!(
        assembled, 0x0102_0304_4000_03d0,
        "miner LE ‖ extranonce LE → consensus u64 nonce"
    );

    // Target on the job is exactly difficulty 1024's threshold.
    let target = parse_target_hex(&job.target).unwrap();
    assert_eq!(target, target_from_difficulty(1024).unwrap());
    assert_eq!(job.target, encode_target_le_hex(target));

    // 5. submit OK
    let submit_ok = match decode_line(lines[4]).unwrap() {
        DecodedLine::Response(r) => r,
        other => panic!("line4: {other:?}"),
    };
    assert!(submit_ok.error.is_none());
    assert_eq!(
        submit_ok.result.unwrap()["status"].as_str().unwrap(),
        "OK"
    );
}

fn check_job(job: &Job) {
    let blob = hex_decode(&job.blob);
    assert_eq!(blob.len(), V5_BLOB_LEN, "v5 blob is 97 bytes");
    check_v5_blob(&blob).unwrap();
    assert_eq!(job.algo.as_deref(), Some("rx/0"));
    assert_eq!(job.height, Some(123_456));
    assert_eq!(hex_decode(job.seed_hash.as_ref().unwrap()).len(), 32);
    assert_eq!(hex_decode(job.next_seed_hash.as_ref().unwrap()).len(), 32);
    // 8-byte raw target, not 4-byte compact
    assert_eq!(hex_decode(&job.target).len(), 8);
}

#[test]
fn reencode_preserves_submit_bytes() {
    // Decode → re-encode the submit line; the semantic fields must survive.
    // (Key order may differ; we compare parsed structs, not raw JSON.)
    let lines = fixture_lines();
    let DecodedLine::Request(req) = decode_line(lines[3]).unwrap() else {
        panic!("expected submit request");
    };
    let params = req.parse_submit_params().unwrap();
    let again = qlab_stratum::types::StratumRequest::submit(2, &params).unwrap();
    let line = qlab_stratum::codec::encode_request(&again).unwrap();
    let DecodedLine::Request(req2) = decode_line(&line).unwrap() else {
        panic!("re-encode failed");
    };
    assert_eq!(req2.parse_submit_params().unwrap(), params);
}
