//! Stage 3 e2e drill (lab #482): XMRig-convention protocol lines driven
//! against `qumbra-pool` over an in-process [`DevnetTemplateSource`].
//!
//! Fixtures only — no mining software is installed or run. Named
//! deviations from a live Monero capture: v5 header preimage as `blob`,
//! 8-byte raw target. Adversarial shares are refused **by name**.

use qlab_devnet::forms::GenesisForm;
use qlab_stratum::blob::{extranonce_of, miner_nonce_of, V5_BLOB_LEN};
use qlab_stratum::codec::encode_request;
use qlab_stratum::types::{LoginParams, LoginResult, StratumRequest, SubmitParams};
use qumbra_pool::hasher::FixedHasher;
use qumbra_pool::payee::AssembledCoinbase;
use qumbra_pool::pool::Outgoing;
use qumbra_pool::template::DevnetTemplateSource;
use qumbra_pool::TemplateSource;
use qumbra_pool::{
    Pool, ShareStatus, ERR_BAD_ALGO, ERR_DUPLICATE, ERR_LOW_DIFF, ERR_UNCLEAN_V4, ERR_UNKNOWN_JOB,
};

const AGENT: &str = "XMRig/6.21.0 (stage3-fixture)";

fn pool_v5() -> Pool {
    Pool::new(1024, Box::new(DevnetTemplateSource::v5_tip(256))).unwrap()
}

fn login_line(login: &str, algo: Option<Vec<String>>) -> String {
    encode_request(
        &StratumRequest::login(
            1,
            &LoginParams {
                login: login.into(),
                pass: "x".into(),
                agent: Some(AGENT.into()),
                algo,
                rigid: None,
            },
        )
        .unwrap(),
    )
    .unwrap()
}

fn submit_line(sid: &str, job_id: &str, nonce: &str, result: &str, algo: Option<&str>) -> String {
    encode_request(
        &StratumRequest::submit(
            2,
            &SubmitParams {
                id: sid.into(),
                job_id: job_id.into(),
                nonce: nonce.into(),
                result: result.into(),
                algo: algo.map(str::to_string),
            },
        )
        .unwrap(),
    )
    .unwrap()
}

fn reply_err_code(out: &[Outgoing]) -> Option<i64> {
    let Outgoing::Reply(resp) = &out[0] else {
        panic!("expected reply");
    };
    resp.error.as_ref().map(|e| e.code)
}

fn reply_err_msg(out: &[Outgoing]) -> String {
    let Outgoing::Reply(resp) = &out[0] else {
        panic!("expected reply");
    };
    resp.error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default()
}

fn reply_ok(out: &[Outgoing]) -> bool {
    let Outgoing::Reply(resp) = &out[0] else {
        return false;
    };
    resp.error.is_none()
        && resp
            .result
            .as_ref()
            .and_then(|v| v.get("status"))
            .and_then(|s| s.as_str())
            == Some("OK")
}

fn login_ok(pool: &Pool, miner: &str) -> (String, LoginResult) {
    let mut sid = None;
    let out = pool
        .handle_line(&mut sid, &login_line(miner, Some(vec!["rx/0".into()])))
        .unwrap();
    let Outgoing::Reply(resp) = &out[0] else {
        panic!("expected login reply");
    };
    (sid.unwrap(), resp.parse_login_result().unwrap())
}

/// Clean path: XMRig login → job (v5 blob) → submit (block-class hash)
/// → PPLNS credit → assembled V5 N=1 payee coinbase.
#[test]
fn e2e_login_job_submit_pplns_v5_payee() {
    let pool = pool_v5();
    pool.register_account("alice", [1, 0, 0, 0]);
    let (sid, login) = login_ok(&pool, "alice");
    assert_eq!(login.status, "OK");
    let job = &login.job;
    let blob = qumbra_pool::hexutil::decode(&job.blob).unwrap();
    assert_eq!(blob.len(), V5_BLOB_LEN);
    assert_eq!(miner_nonce_of(&blob).unwrap(), [0, 0, 0, 0]);
    assert_ne!(extranonce_of(&blob).unwrap(), [0, 0, 0, 0]);
    assert_eq!(job.algo.as_deref(), Some("rx/0"));
    assert_eq!(job.height, Some(1), "devnet tip is genesis+1");

    // All-zero result: FixedHasher::zeros matches; work value 0 is a
    // block candidate under any consensus difficulty (satisfies_target_for <=).
    let mut s = Some(sid.clone());
    let out = pool
        .handle_line(
            &mut s,
            &submit_line(
                &sid,
                &job.job_id,
                "d0030040",
                &"00".repeat(32),
                Some("rx/0"),
            ),
        )
        .unwrap();
    assert!(reply_ok(&out), "clean submit must be OK");
    assert_eq!(pool.ledger_snapshot().accepted_count("alice"), 1);
    assert_eq!(pool.pplns_len(), 1);
    let rec = pool
        .ledger_snapshot()
        .records()
        .iter()
        .find(|r| r.status == ShareStatus::Accepted)
        .unwrap()
        .clone();
    assert!(
        rec.block_candidate,
        "zero hash is a consensus block find; payee assembly is owed"
    );

    match pool.assemble_now().unwrap() {
        AssembledCoinbase::V5 { payees } => {
            assert_eq!(payees.len(), 1);
            assert_eq!(payees[0].rkm, [1, 0, 0, 0]);
            assert!(payees[0].amount > 0, "height 1 mints");
        }
        other => panic!("expected V5 payee list, got {other:?}"),
    }
}

#[test]
fn e2e_refuses_stale_by_name() {
    let pool = pool_v5();
    let (sid, login) = login_ok(&pool, "alice");
    let old_job = login.job.job_id.clone();
    pool.replace_template(Box::new(DevnetTemplateSource::v5_tip(256)))
        .unwrap();
    let mut s = Some(sid.clone());
    let out = pool
        .handle_line(
            &mut s,
            &submit_line(&sid, &old_job, "aabbccdd", &"00".repeat(32), Some("rx/0")),
        )
        .unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_UNKNOWN_JOB));
    assert!(
        reply_err_msg(&out).contains("stale"),
        "stale must be named, got {}",
        reply_err_msg(&out)
    );
    assert_eq!(
        pool.ledger_snapshot().records().last().unwrap().status,
        ShareStatus::Stale
    );
}

#[test]
fn e2e_refuses_dup_by_name() {
    let pool = pool_v5();
    let (sid, login) = login_ok(&pool, "alice");
    let mut s = Some(sid.clone());
    let line = submit_line(
        &sid,
        &login.job.job_id,
        "d0030040",
        &"00".repeat(32),
        Some("rx/0"),
    );
    assert!(reply_ok(&pool.handle_line(&mut s, &line).unwrap()));
    let out = pool.handle_line(&mut s, &line).unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_DUPLICATE));
    assert!(reply_err_msg(&out)
        .to_ascii_lowercase()
        .contains("duplicate"));
}

#[test]
fn e2e_refuses_low_diff_by_name() {
    let pool = Pool::new_with_hasher(
        1024,
        Box::new(DevnetTemplateSource::v5_tip(256)),
        Box::new(FixedHasher { digest: [0xFF; 32] }),
        [9, 0, 0, 0],
    )
    .unwrap();
    let (sid, login) = login_ok(&pool, "alice");
    let mut s = Some(sid.clone());
    let out = pool
        .handle_line(
            &mut s,
            &submit_line(
                &sid,
                &login.job.job_id,
                "01020304",
                &"ff".repeat(32),
                Some("rx/0"),
            ),
        )
        .unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_LOW_DIFF));
    assert!(
        reply_err_msg(&out)
            .to_ascii_lowercase()
            .contains("low difficulty"),
        "low-diff must be named, got {}",
        reply_err_msg(&out)
    );
    assert_eq!(
        pool.ledger_snapshot().records().last().unwrap().status,
        ShareStatus::LowDifficulty
    );
}

#[test]
fn e2e_refuses_wrong_net_by_name() {
    let pool = Pool::new(1024, Box::new(DevnetTemplateSource::v4_tip(256))).unwrap();
    let mut sid = None;
    let out = pool
        .handle_line(&mut sid, &login_line("alice", Some(vec!["rx/0".into()])))
        .unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_UNCLEAN_V4));
    assert!(
        reply_err_msg(&out).contains("v4-net-unclean-for-stock-xmrig"),
        "wrong-net must be named, got {}",
        reply_err_msg(&out)
    );
    assert!(sid.is_none());
}

#[test]
fn e2e_refuses_wrong_algo_by_name() {
    let pool = pool_v5();
    let mut sid = None;
    let out = pool
        .handle_line(&mut sid, &login_line("alice", Some(vec!["cn/r".into()])))
        .unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_BAD_ALGO));
    assert!(reply_err_msg(&out).contains("rx/0"));

    let (sid, login) = login_ok(&pool, "alice");
    let mut s = Some(sid.clone());
    let out = pool
        .handle_line(
            &mut s,
            &submit_line(
                &sid,
                &login.job.job_id,
                "d0030040",
                &"00".repeat(32),
                Some("cn/r"),
            ),
        )
        .unwrap();
    assert_eq!(reply_err_code(&out), Some(ERR_BAD_ALGO));
}

#[test]
fn e2e_devnet_source_is_form_keyed() {
    let v5 = DevnetTemplateSource::v5_tip(256).current();
    let v4 = DevnetTemplateSource::v4_tip(256).current();
    assert_eq!(v5.form, GenesisForm::V5);
    assert_eq!(v4.form, GenesisForm::V4);
    assert!(v5.serves_stock_xmrig());
    assert!(!v4.serves_stock_xmrig());
    assert_eq!(v5.header.height, 1);
    assert_ne!(
        v5.header.header_hash_for(GenesisForm::V5),
        v4.header.header_hash_for(GenesisForm::V4)
    );
}
