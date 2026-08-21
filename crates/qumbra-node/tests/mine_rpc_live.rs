//! Lab #511 live lane (G4 definition of done).
//!
//! Two legs:
//! 1. The node RPC itself: `GET /v1/mine/template` (gated) then a Keccak-ground
//!    `POST /v1/mine/block` through the real run loop advances the tip.
//! 2. The stage-3 harness over a **real** node (not `DevnetTemplateSource`):
//!    login → job from the node → block-class share → POST → tip advances.
//!
//! ## 🔴 Every wait in this file is bounded and fails by name (lab #547)
//!
//! `RunningNode::run_until` returns only when the shutdown flag is set, and
//! in every test here the flag is set by the client thread once it is done.
//! A client that *panics* instead therefore never sets it: the node loop
//! spins, and because cargo's harness buffers a test's output until the test
//! finishes, the panic message is captured and never printed. Lab #547's
//! first CI run is what that costs — `suite` cancelled at
//! `timeout-minutes: 120`, two hours of paid runner, no verdict, and the
//! only trace anywhere in the log was `Terminate orphan process: pid (8165)
//! (mine_rpc_live-…)` in the cleanup step.
//!
//! So no test drives the node loop directly. [`spawn_leg`] catches the
//! client's panic and sets the flag on both paths, and [`drive`] stops the
//! loop on a [`LEG_BUDGET`] deadline it owns itself. A failure in this file
//! is a named assertion, never a hang.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qlab_devnet::forms::GenesisForm;
use qlab_devnet::pow::{satisfies_target_for, KeccakPow, PowEngine};
use qlab_p2p::codec::decode_header;
use qlab_stratum::blob::apply_miner_nonce;
use qlab_stratum::codec::encode_request;
use qlab_stratum::types::{LoginParams, StratumRequest, SubmitParams};
use qumbra_node::config::NodeConfig;
use qumbra_node::genesis::GenesisFile;
use qumbra_node::mine_rpc::{
    header_hex, rkm_hex, MineBlockWire, MineTemplateWire, TEMPLATE_SERVING_DISABLED,
};
use qumbra_node::run::{DevnetRehearsalVerifier, RunningNode};
use qumbra_pool::hasher::KeccakShareHasher;
use qumbra_pool::pool::Outgoing;
use qumbra_pool::template::HeldTemplateSource;
use qumbra_pool::{NodeRpcClient, PayeeRefusal, Pool, PoolError};

/// The one wallet this harness owns — the node's `miner_rkm` **and** the
/// pool's `payout_rkm`.
///
/// `GET /v1/mine/template` has no payee parameter, so the body the pool
/// receives always names the **node's** own `miner_rkm`. A pool configured
/// to pay anywhere else cannot submit a block it owns, and since lab #547 it
/// refuses to try — so one value for both fields is the only configuration
/// in which this harness was ever meaningful.
///
/// Before this it was two: the node paid `[1,2,3,4]` and the pool's
/// `payout_rkm` was the hardcoded `[9,0,0,0]` that #523 removed from
/// production. That is a node paying one identity while the pool owns
/// another, which is precisely the arrangement lab #547 exists to make
/// impossible, and the payee gate refused it — correctly, at
/// `Pool::new_with_hasher`.
const RIG_RKM: [u64; 4] = [1, 2, 3, 4];

/// A structurally fine key nobody here owns. Used only as the *wrong*
/// `payout_rkm`, in
/// [`a_payout_rkm_the_live_template_does_not_pay_refuses_at_startup`].
const STRANGER_RKM: [u64; 4] = [0xd2c0_2c7c, 2, 3, 4];

/// Alice's PPLNS identity, and deliberately **not** [`RIG_RKM`]: on today's
/// RPC the coinbase payee is the node's key whoever mined the share, so a
/// miner's registered rkm is a share-accounting identity here and not a
/// payee. Keeping the two distinct is what keeps that visible.
const ALICE_RKM: [u64; 4] = [1, 0, 0, 0];

fn rig_t2(tag: &str) -> (NodeConfig, GenesisFile, std::path::PathBuf) {
    let base = std::env::temp_dir().join(format!("qmb_mine_rpc_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let genesis = GenesisFile::new_t2();
    let gpath = base.join("genesis.qmb");
    genesis.write(&gpath).unwrap();
    let keys = genesis.write_committee_key_files(base.join("keys")).unwrap();
    let config = NodeConfig {
        data_dir: base.join("data"),
        listen_addr: "127.0.0.1:0".to_string(),
        dial_peers: vec![],
        advertise_addr: None,
        genesis_file: gpath,
        committee_key_paths: keys,
        mining: false,
        expected_genesis_hash: Some(genesis.hash_hex()),
        metrics_addr: None,
        telemetry_addr: None,
        discovery_addr: None,
        miner_rkm: Some(rkm_hex(&RIG_RKM)),
        template_serving: false,
    };
    (config, genesis, base)
}

fn http_get(addr: std::net::SocketAddr, path: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&raw[..sep])
        .lines()
        .next()
        .unwrap()
        .to_string();
    (status, raw[sep + 4..].to_vec())
}

fn http_post(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> (String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = String::from_utf8_lossy(&raw[..sep])
        .lines()
        .next()
        .unwrap()
        .to_string();
    (
        status,
        String::from_utf8_lossy(&raw[sep + 4..]).to_string(),
    )
}

fn grind_v5(wire: &MineTemplateWire) -> (qlab_devnet::header::BlockHeader, [u8; 32]) {
    let mut header = qlab_devnet::header::BlockHeader {
        prev: hex32(&wire.prev),
        height: wire.height,
        timestamp: wire.timestamp,
        difficulty: wire.difficulty,
        nonce: 0,
        tx_body_commitment: hex32(&wire.tx_body_commitment),
        aggregate_proof: qlab_devnet::header::AggregateProofSlot,
        epoch_supply_attestation: qlab_devnet::header::EpochSupplyAttestation,
    };
    let pow = KeccakPow;
    for nonce in 0..500_000u64 {
        header.nonce = nonce;
        let hash = pow.pow_hash(GenesisForm::V5, &header, &[]);
        if satisfies_target_for(&hash, header.difficulty, GenesisForm::V5) {
            return (header, hash);
        }
    }
    panic!("no Keccak nonce in 500k tries at difficulty {}", wire.difficulty);
}

fn hex32(s: &str) -> [u8; 32] {
    let v = qumbra_node::genesis::hex_decode(s).expect("hex");
    assert_eq!(v.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// How long a client leg gets before [`drive`] stops the node loop and fails.
///
/// Basis: the longest leg here is a 500 000-nonce Keccak grind at the T2
/// genesis difficulty plus one node-loop iteration per HTTP round trip —
/// sub-second in `--release` (the acceptance lane) and tens of seconds in an
/// unoptimised debug build, so 180 s is that with a wide margin. What the
/// number really has to be is *far under the CI job's 120-minute cap*, which
/// is the wall this file hit once already: any failure now costs three
/// minutes of runner and names itself.
const LEG_BUDGET: Duration = Duration::from_secs(180);

/// Grace after the node loop exits for a leg that has already set the
/// shutdown flag to actually return. The flag is stored in [`spawn_leg`]
/// immediately before the thread ends, so this is microseconds in practice;
/// the bound exists so a healthy leg is never called stuck.
const LEG_JOIN_GRACE: Duration = Duration::from_secs(5);

/// A client leg that reports its own verdict, so a failure can never present
/// as a hang. See this file's header for what that cost once.
struct Leg {
    handle: std::thread::JoinHandle<Result<(), String>>,
}

/// Spawn `body` as this test's client leg.
///
/// The shutdown flag is set on **both** exits — success and panic — which is
/// the whole point: `run_until` only stops on that flag, so a leg that dies
/// without setting it hangs the test rather than failing it. The panic is
/// carried out as a `String` so [`drive`] can put the real reason (a payee
/// refusal, a grind that found nothing) in the failing assertion's message.
fn spawn_leg<F>(shutdown: &Arc<AtomicBool>, body: F) -> Leg
where
    F: FnOnce() + Send + 'static,
{
    let done = Arc::clone(shutdown);
    Leg {
        handle: std::thread::spawn(move || {
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
                .map_err(describe_panic);
            done.store(true, Ordering::SeqCst);
            out
        }),
    }
}

fn describe_panic(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panicked with a payload that is neither &str nor String".to_string()
    }
}

/// Run the node loop until `leg` finishes or [`LEG_BUDGET`] elapses, then
/// turn the leg's outcome into this test's verdict.
///
/// The deadline is enforced from the loop's own per-iteration hook
/// (`run_until_with`), because the hook cannot make the loop exit — only the
/// flag can — so the harness sets the flag itself. That keeps the bound on
/// *this* side of the client: it holds even for a leg that is genuinely
/// blocked rather than panicking, which is the case a `catch_unwind` alone
/// would still hang on.
fn drive(
    node: &mut RunningNode<KeccakPow, DevnetRehearsalVerifier>,
    shutdown: &Arc<AtomicBool>,
    leg: Leg,
    what: &str,
) {
    let deadline = Instant::now() + LEG_BUDGET;
    let expired = Arc::new(AtomicBool::new(false));
    {
        let expired = Arc::clone(&expired);
        let flag = Arc::clone(shutdown);
        node.run_until_with(shutdown, move |_| {
            if Instant::now() >= deadline && !flag.load(Ordering::SeqCst) {
                expired.store(true, Ordering::SeqCst);
                flag.store(true, Ordering::SeqCst);
            }
        });
    }
    let grace = Instant::now() + LEG_JOIN_GRACE;
    while !leg.handle.is_finished() && Instant::now() < grace {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        leg.handle.is_finished(),
        "leg-still-running: `{what}` was still executing {}s after login-to-verdict; the \
         harness deadline stopped the node loop, the leg did not. Nothing in this file \
         waits without a bound (lab #547).",
        LEG_BUDGET.as_secs()
    );
    match leg.handle.join() {
        Ok(Ok(())) => assert!(
            !expired.load(Ordering::SeqCst),
            "leg-over-budget: `{what}` succeeded, but only after the harness deadline of \
             {}s had already stopped the node loop",
            LEG_BUDGET.as_secs()
        ),
        Ok(Err(msg)) => panic!("leg-failed: `{what}` — {msg}"),
        Err(_) => panic!("leg-failed: `{what}` — the leg's panic payload could not be recovered"),
    }
}

/// Gate off → named UNAVAILABLE, not a 404 that invites retrying elsewhere.
#[test]
fn template_serving_off_is_unavailable_by_name() {
    let (config, genesis, base) = rig_t2("gate-off");
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let leg = spawn_leg(&shutdown, move || {
        let (status, body) = http_get(addr, "/v1/mine/template");
        assert!(status.contains("503"), "{status}");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("template-serving-disabled"),
            "UNAVAILABLE token, got {text}"
        );
        assert_eq!(text.trim(), TEMPLATE_SERVING_DISABLED);
    });
    drive(&mut node, &shutdown, leg, "gated template GET");
    let _ = std::fs::remove_dir_all(&base);
}

/// Node-only live path: assemble (no grind) → we grind → POST → tip advances.
#[test]
fn live_template_then_submit_advances_tip() {
    let (mut config, genesis, base) = rig_t2("submit");
    config.template_serving = true;
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    assert_eq!(node.tip_height(), 0);
    node.set_mine_interval(Duration::from_secs(3600));
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let leg = spawn_leg(&shutdown, move || {
        let (status, body) = http_get(addr, "/v1/mine/template");
        assert!(status.contains("200"), "{status} {}", String::from_utf8_lossy(&body));
        let wire: MineTemplateWire = serde_json::from_slice(&body).unwrap();
        assert_eq!(wire.form, "v5");
        assert_eq!(wire.height, 1);
        assert_eq!(wire.nonce, 0);
        assert_eq!(
            wire.coinbase_rkm,
            rkm_hex(&RIG_RKM),
            "the served template pays the node's configured miner_rkm, not a placeholder"
        );
        let (header, _) = grind_v5(&wire);
        let post = MineBlockWire {
            form: "v5".into(),
            header: header_hex(GenesisForm::V5, &header),
            coinbase: wire.coinbase,
            coinbase_rkm: wire.coinbase_rkm,
            txs: wire.txs,
        };
        let (status, text) = http_post(addr, "/v1/mine/block", &serde_json::to_vec(&post).unwrap());
        assert!(status.contains("202"), "{status} {text}");
        assert!(text.starts_with("accepted "), "{text}");
    });
    drive(&mut node, &shutdown, leg, "template → grind → POST");
    assert_eq!(node.tip_height(), 1, "POST must take the own-mined ingest path");
    let _ = std::fs::remove_dir_all(&base);
}

/// Stage-3 live-node leg: pool over the real node, not a fictional template.
#[test]
fn e2e_live_node_login_job_submit_advances_tip() {
    let (mut config, genesis, base) = rig_t2("pool-live");
    config.template_serving = true;
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    node.set_mine_interval(Duration::from_secs(3600));
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let url = format!("http://{addr}");
    let shutdown = Arc::new(AtomicBool::new(false));
    let leg = spawn_leg(&shutdown, move || {
        let rpc = NodeRpcClient::parse(&url).unwrap();
        let template = rpc.fetch_template().expect("live template");
        assert_eq!(template.form, GenesisForm::V5);
        assert_eq!(template.header.height, 1);
        let body = template.body.as_ref().expect("live template carries the body");
        assert_eq!(
            body.coinbase_rkm, RIG_RKM,
            "the payee the pool is about to accept is the node's own miner_rkm — the fixture \
             is only meaningful when that is also the pool's payout_rkm (lab #547)"
        );
        let pool = Pool::new_with_hasher(
            1,
            Box::new(HeldTemplateSource::new(template.clone())),
            Box::new(KeccakShareHasher),
            RIG_RKM,
        )
        .expect("payout_rkm is the payee the node pays, so the payee gate passes");
        pool.set_submitter(Arc::new(rpc));
        pool.register_account("alice", ALICE_RKM);
        let mut sid = None;
        let login_line = encode_request(
            &StratumRequest::login(
                1,
                &LoginParams {
                    login: "alice".into(),
                    pass: "x".into(),
                    agent: Some("XMRig/6.21.0 (g4-live)".into()),
                    algo: Some(vec!["rx/0".into()]),
                    rigid: None,
                },
            )
            .unwrap(),
        )
        .unwrap();
        let out = pool.handle_line(&mut sid, &login_line).unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("login reply");
        };
        let login = resp.parse_login_result().unwrap();
        let job = &login.job;
        let blob0 = qumbra_pool::hexutil::decode(&job.blob).unwrap();
        let mut found = None;
        for n in 0u32..500_000 {
            let nonce = n.to_le_bytes();
            let mut blob = blob0.clone();
            apply_miner_nonce(&mut blob, &nonce).unwrap();
            let hash = qlab_devnet::hash::keccak256(&blob);
            if qumbra_pool::share::is_block_candidate(
                &hash,
                template.header.difficulty,
                GenesisForm::V5,
            ) {
                found = Some((nonce, hash));
                break;
            }
        }
        let (nonce, hash) = found.expect("Keccak grind found a block");
        let submit = encode_request(
            &StratumRequest::submit(
                2,
                &SubmitParams {
                    id: sid.clone().unwrap(),
                    job_id: job.job_id.clone(),
                    nonce: qumbra_pool::hexutil::encode(&nonce),
                    result: qumbra_pool::hexutil::encode(&hash),
                    algo: Some("rx/0".into()),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let mut s = sid.clone();
        let out = pool.handle_line(&mut s, &submit).unwrap();
        let Outgoing::Reply(resp) = &out[0] else {
            panic!("submit reply");
        };
        assert!(resp.error.is_none(), "submit {:?}", resp.error);
        assert!(
            !pool.is_unavailable(),
            "the payee gate must not have suspended work: {:?}",
            pool.counters().work_unavailable
        );
    });
    drive(&mut node, &shutdown, leg, "pool login → block-class share → POST");
    assert_eq!(node.tip_height(), 1, "pool POST must advance the real node tip");
    let _ = std::fs::remove_dir_all(&base);
}

/// 🔴 The mismatch this file itself carried, now asserted instead of hung
/// (lab #547 review). A pool whose `payout_rkm` is not the payee the live
/// node puts in the template refuses **at startup, by name** — before a
/// listener is bound and before any miner spends a hash.
///
/// It lives here rather than in `qumbra-pool`'s unit tests because only a
/// real node's template can show *which* key the gate is checking against:
/// the node's own configured `miner_rkm`, not a value a fixture chose.
#[test]
fn a_payout_rkm_the_live_template_does_not_pay_refuses_at_startup() {
    let (mut config, genesis, base) = rig_t2("payout-mismatch");
    config.template_serving = true;
    let mut node =
        RunningNode::start(&config, &genesis, KeccakPow, DevnetRehearsalVerifier).unwrap();
    node.set_mine_interval(Duration::from_secs(3600));
    let addr = node.start_discovery_endpoint("127.0.0.1:0").unwrap();
    let url = format!("http://{addr}");
    let shutdown = Arc::new(AtomicBool::new(false));
    let leg = spawn_leg(&shutdown, move || {
        let rpc = NodeRpcClient::parse(&url).unwrap();
        let template = rpc.fetch_template().expect("live template");
        let Err(err) = Pool::new_with_hasher(
            1,
            Box::new(HeldTemplateSource::new(template)),
            Box::new(KeccakShareHasher),
            STRANGER_RKM,
        ) else {
            panic!("a payout_rkm the node does not pay must refuse before any miner logs in");
        };
        assert!(
            matches!(&err, PoolError::Payee(PayeeRefusal::Unowned { rkm }) if *rkm == RIG_RKM),
            "the refusal must name the payee the node actually served, got: {err}"
        );
        assert!(
            err.to_string().contains("unowned-coinbase-payee"),
            "refused by token, got: {err}"
        );
    });
    drive(&mut node, &shutdown, leg, "payout_rkm mismatch startup refusal");
    assert_eq!(node.tip_height(), 0, "nothing was submitted");
    let _ = std::fs::remove_dir_all(&base);
}

/// decode_header of a v5 preimage we just served is the same header.
#[test]
fn template_header_decodes_under_v5() {
    let wire = MineTemplateWire {
        form: "v5".into(),
        prev: "11".repeat(32),
        height: 1,
        timestamp: 75,
        difficulty: 256,
        nonce: 0,
        tx_body_commitment: "22".repeat(32),
        seed_hash: "33".repeat(32),
        next_seed_hash: None,
        coinbase: 1,
        coinbase_rkm: rkm_hex(&RIG_RKM),
        txs: vec![],
    };
    let header = qlab_devnet::header::BlockHeader {
        prev: hex32(&wire.prev),
        height: 1,
        timestamp: 75,
        difficulty: 256,
        nonce: 0,
        tx_body_commitment: hex32(&wire.tx_body_commitment),
        aggregate_proof: qlab_devnet::header::AggregateProofSlot,
        epoch_supply_attestation: qlab_devnet::header::EpochSupplyAttestation,
    };
    let bytes = qlab_p2p::codec::encode_header(GenesisForm::V5, &header);
    assert_eq!(decode_header(GenesisForm::V5, &bytes).unwrap(), header);
}
