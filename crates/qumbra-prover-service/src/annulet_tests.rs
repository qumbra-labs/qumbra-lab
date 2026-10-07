//! The Annulet API with a stand-in prover and node (lab #924 5A-D3/D4):
//! admission refuses by name, quota and in-flight hold, idempotency keys on
//! the intent, the job URL is the capability, and only the bundle's
//! transaction plus a proof is ever submitted. The bundles are real (signed
//! S/P fixtures, decoded and checked for real); nothing here proves — the
//! real child's one S prove is `tests/annulet_worker.rs`.

use std::cell::Cell;
use std::sync::OnceLock;

use qlab_l2spend::fixtures::{signed_bundle, signed_bundles, GENESIS_HASH, VALID_UNTIL};

use super::*;
use crate::token::{mint, verifying_key};

const SEED: Hash32 = [0x5c; 32];
const T0: u64 = 1_800_000_000;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(T0) };
}

fn clock() -> u64 {
    NOW.with(|c| c.get())
}

fn bundle_s() -> &'static ProvingBundle {
    static B: OnceLock<ProvingBundle> = OnceLock::new();
    B.get_or_init(|| signed_bundle(L2ShapeTag::S))
}

fn bundle_p() -> &'static ProvingBundle {
    static B: OnceLock<ProvingBundle> = OnceLock::new();
    B.get_or_init(|| signed_bundle(L2ShapeTag::P))
}

fn token(id: u8, net: Hash32, per_day: u16) -> String {
    let claims = Claims {
        key_id: 1,
        token_id: [id; 16],
        genesis_hash: net,
        not_before: T0 - 60,
        not_after: T0 + 20 * 86_400,
        per_day,
    };
    format!("Bearer {}", mint(&SEED, &claims).unwrap())
}

fn config(net: Hash32, queue: usize, ttl: Duration) -> AnnuletConfig {
    AnnuletConfig {
        genesis_hash: net,
        slot_secs: 10,
        queue_capacity: queue,
        prove_timeout: Duration::from_secs(300),
        result_ttl: ttl,
        per_day_default: 3,
        node_url: "https://node.invalid".into(),
        relay_url: None,
        scratch: PathBuf::from("/nonexistent"),
        tokens: TokenKeys::parse(&format!("1 {}", hex(&verifying_key(&SEED)))).unwrap(),
        deny_file: None,
    }
}

/// What the stand-in prover answers.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// The bundle's transaction plus a 4-byte "proof".
    Honest,
    /// The same with the fee changed.
    Tampered,
    Fail(&'static str),
}

struct FakeProver {
    answer: Answer,
    hold: AtomicBool,
    calls: Mutex<u32>,
}

impl FakeProver {
    fn new(answer: Answer, hold: bool) -> Arc<Self> {
        Arc::new(Self {
            answer,
            hold: AtomicBool::new(hold),
            calls: Mutex::new(0),
        })
    }
    fn release(&self) {
        self.hold.store(false, Ordering::Release);
    }
}

impl AnnuletProver for FakeProver {
    fn prove(&self, bundle: &[u8], cancel: &AtomicBool) -> Result<Vec<u8>, &'static str> {
        *self.calls.lock().unwrap() += 1;
        while self.hold.load(Ordering::Acquire) {
            if cancel.load(Ordering::Acquire) {
                return Err("cancelled");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut tx = ProvingBundle::decode(bundle)
            .expect("the server sends checked bundles")
            .tx()
            .clone();
        tx.proof = vec![1, 2, 3, 4];
        match self.answer {
            Answer::Honest => {}
            Answer::Tampered => tx.public.fee += 1,
            Answer::Fail(code) => return Err(code),
        }
        Ok(qlab_p2p::codec::encode_tx_annulet(&tx))
    }
}

#[derive(Default)]
struct FakeNode {
    refuse: Option<&'static str>,
    got: Mutex<Vec<Vec<u8>>>,
}

impl Submitter for FakeNode {
    fn submit(&self, wire: &[u8]) -> Result<(), String> {
        self.got.lock().unwrap().push(wire.to_vec());
        match self.refuse {
            Some(code) => Err(code.into()),
            None => Ok(()),
        }
    }
    fn relay(&self, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
}

fn api(prover: Arc<FakeProver>, node: Arc<FakeNode>) -> AnnuletApi {
    AnnuletApi::with_clock(
        config(GENESIS_HASH, 2, Duration::from_secs(60)),
        prover,
        node,
        clock,
    )
}

fn cap_of(v: &AnnuletJobView) -> &str {
    v.job_url.strip_prefix("/v2/annulet/jobs/").unwrap()
}

fn wait(api: &AnnuletApi, v: &AnnuletJobView, until: &[&str]) -> AnnuletJobView {
    let started = Instant::now();
    loop {
        let now = api.get(cap_of(v)).unwrap();
        if until.contains(&now.state) {
            return now;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "stuck in {}",
            now.state
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn admit(
    api: &AnnuletApi,
    auth: &str,
    bundle: &ProvingBundle,
) -> Result<(AnnuletJobView, bool), ApiError> {
    let claims = api.authorize(Some(auth))?;
    api.submit(&claims, bundle.encode())
}

#[test]
fn info_states_the_pins_and_the_validity_to_sign_with() {
    let a = api(FakeProver::new(Answer::Honest, false), Arc::default());
    let info = a.info();
    assert_eq!(info.genesis_format, 33);
    assert_eq!(info.genesis_hash, hex(&GENESIS_HASH));
    assert_eq!(info.shapes, ["S", "P"]);
    assert_eq!(info.d_auth, 12);
    // (queue 2 + the running job) × 300 s + 60 s of submission, at 10 s a slot.
    assert_eq!(info.recommended_valid_for_blocks, 96);
}

#[test]
fn an_honest_bundle_is_proved_and_submitted_and_its_tx_id_returned() {
    for bundle in [bundle_s(), bundle_p()] {
        let node = Arc::new(FakeNode::default());
        let a = api(FakeProver::new(Answer::Honest, false), Arc::clone(&node));
        let (v, created) = admit(&a, &token(1, GENESIS_HASH, 0), bundle).unwrap();
        assert!(created);
        assert_eq!(v.job_url.len(), "/v2/annulet/jobs/".len() + 64);
        let done = wait(&a, &v, &["submitted", "failed", "refused"]);
        assert_eq!(done.state, "submitted", "{:?}", done.refusal);
        let got = node.got.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "submitted once");
        let tx = proof_added(&qlab_p2p::codec::encode_tx_annulet(bundle.tx()), &got[0]).unwrap();
        assert_eq!(done.tx_id, Some(hex(&qlab_p2p::codec::tx_id(&tx))));
        assert!(done.expires_in_secs.is_some());
        let claims = a.authorize_only(Some(&token(1, GENESIS_HASH, 0))).unwrap();
        assert_eq!(
            a.quota(&claims),
            QuotaView {
                per_day: 3,
                used_today: 1,
                in_flight: false
            }
        );
    }
}

#[test]
fn a_token_is_refused_by_name_and_counted_without_its_id() {
    let a = api(FakeProver::new(Answer::Honest, false), Arc::default());
    assert_eq!(
        a.authorize(None).err().map(|e| (e.status, e.code)),
        Some((401, "unauthorized"))
    );
    assert_eq!(
        a.authorize(Some("Basic x")).err().map(|e| e.code),
        Some("unauthorized")
    );
    assert_eq!(
        a.authorize(Some(&token(1, [0x6f; 32], 0)))
            .err()
            .map(|e| e.code),
        Some("token-wrong-net")
    );
    NOW.with(|c| c.set(T0 + 21 * 86_400));
    assert_eq!(
        a.authorize(Some(&token(1, GENESIS_HASH, 0)))
            .err()
            .map(|e| e.code),
        Some("token-expired")
    );
    NOW.with(|c| c.set(T0));
    let counts = a.drain_refusals();
    assert!(counts.iter().all(|((who, _), _)| who == "-"), "{counts:?}");
    assert_eq!(counts.iter().map(|(_, n)| n).sum::<u64>(), 4);
    assert!(a.drain_refusals().is_empty(), "drained");
}

#[test]
fn one_job_in_flight_per_token_and_a_daily_quota() {
    let prover = FakeProver::new(Answer::Honest, true);
    let a = api(Arc::clone(&prover), Arc::default());
    let t = token(2, GENESIS_HASH, 2);
    let (v, _) = admit(&a, &t, bundle_s()).unwrap();
    assert_eq!(
        a.authorize(Some(&t)).err().map(|e| (e.status, e.code)),
        Some((429, "token-busy"))
    );
    prover.release();
    wait(&a, &v, &["submitted"]);
    // Second job of the day (the P bundle: another intent).
    let (v, _) = admit(&a, &t, bundle_p()).unwrap();
    wait(&a, &v, &["submitted"]);
    assert_eq!(
        a.authorize(Some(&t)).err().map(|e| (e.status, e.code)),
        Some((429, "quota-exhausted"))
    );
    // The refusals carry the token's short tag, not its id.
    let counts = a.drain_refusals();
    let tag = token_tag(&[2; 16]);
    assert!(
        counts.contains(&((tag.clone(), "token-busy"), 1))
            && counts.contains(&((tag, "quota-exhausted"), 1)),
        "{counts:?}"
    );
    assert!(counts
        .iter()
        .all(|((who, _), _)| !who.contains(&hex(&[2u8; 16]))));
    // The next UTC day.
    NOW.with(|c| c.set(T0 + 86_400));
    assert!(a.authorize(Some(&t)).is_ok());
    NOW.with(|c| c.set(T0));
}

#[test]
fn the_intent_is_the_idempotency_key() {
    let node = Arc::new(FakeNode::default());
    let a = api(FakeProver::new(Answer::Honest, false), Arc::clone(&node));
    let t = token(3, GENESIS_HASH, 0);
    let (v, created) = admit(&a, &t, bundle_s()).unwrap();
    assert!(created);
    wait(&a, &v, &["submitted"]);
    // The same signed transaction again: the same job, nothing re-proved,
    // nothing counted.
    let (again, created) = admit(&a, &t, bundle_s()).unwrap();
    assert!(!created);
    assert_eq!(again.job_url, v.job_url);
    assert_eq!(node.got.lock().unwrap().len(), 1);
    let claims = a.authorize_only(Some(&t)).unwrap();
    assert_eq!(a.quota(&claims).used_today, 1);
    // Another token cannot take it over.
    assert_eq!(
        admit(&a, &token(4, GENESIS_HASH, 0), bundle_s())
            .err()
            .map(|e| (e.status, e.code)),
        Some((409, "intent-in-flight"))
    );
}

#[test]
fn a_failed_job_may_be_retried_and_the_node_s_refusal_is_its_code() {
    let node = Arc::new(FakeNode {
        refuse: Some("node-refused:expired"),
        ..FakeNode::default()
    });
    let a = api(FakeProver::new(Answer::Honest, false), Arc::clone(&node));
    let t = token(5, GENESIS_HASH, 0);
    let (v, _) = admit(&a, &t, bundle_s()).unwrap();
    let done = wait(&a, &v, &["failed"]);
    assert_eq!(done.refusal.as_deref(), Some("node-refused:expired"));
    assert_eq!(done.tx_id, None);
    let (retry, created) = admit(&a, &t, bundle_s()).unwrap();
    assert!(created, "a job that ended without a transaction is retried");
    assert_ne!(retry.job_url, v.job_url);
}

#[test]
fn a_bundle_is_refused_by_name_before_it_is_queued() {
    let prover = FakeProver::new(Answer::Honest, false);
    let a = api(Arc::clone(&prover), Arc::default());
    let t = token(6, GENESIS_HASH, 0);
    let claims = a.authorize(Some(&t)).unwrap();
    let code = |bytes: Vec<u8>| a.submit(&claims, bytes).err().map(|e| (e.status, e.code));
    assert_eq!(code(Vec::new()), Some((413, "bundle-too-large")));
    assert_eq!(
        code(vec![0; MAX_ANNULET_BUNDLE_BYTES + 1]),
        Some((413, "bundle-too-large"))
    );
    assert_eq!(
        code(b"not a bundle".to_vec()),
        Some((400, "bundle-malformed"))
    );
    let mut r = bundle_s().encode();
    r[qlab_l2spend::bundle::BUNDLE_DOMAIN.len() + 2] = 2;
    assert_eq!(code(r), Some((403, "issuer-shape")));
    let mut w = bundle_s().witness().clone();
    w.fee += 1;
    let lying = ProvingBundle::new(bundle_s().tx().clone(), w)
        .unwrap()
        .encode();
    assert_eq!(code(lying), Some((422, "statement-mismatch")));
    let mut tx = bundle_s().tx().clone();
    *tx.auth.last_mut().unwrap() ^= 1;
    let unsigned = ProvingBundle::new(tx, bundle_s().witness().clone())
        .unwrap()
        .encode();
    assert_eq!(code(unsigned), Some((422, "unauthorized-section")));
    assert_eq!(
        *prover.calls.lock().unwrap(),
        0,
        "nothing reached the prover"
    );
    assert_eq!(
        a.quota(&claims).used_today,
        0,
        "a refusal is not an admitted job"
    );
    assert_eq!(a.drain_refusals().iter().map(|(_, n)| n).sum::<u64>(), 6);
}

#[test]
fn a_bundle_for_another_net_is_unauthorized_here() {
    let other = [0x6f; 32];
    let a = AnnuletApi::with_clock(
        config(other, 2, Duration::from_secs(60)),
        FakeProver::new(Answer::Honest, false),
        Arc::new(FakeNode::default()),
        clock,
    );
    assert_eq!(
        admit(&a, &token(7, other, 0), bundle_s())
            .err()
            .map(|e| e.code),
        Some("unauthorized-section")
    );
}

#[test]
fn a_prover_s_other_transaction_is_never_submitted() {
    let node = Arc::new(FakeNode::default());
    let a = api(FakeProver::new(Answer::Tampered, false), Arc::clone(&node));
    let (v, _) = admit(&a, &token(8, GENESIS_HASH, 0), bundle_s()).unwrap();
    assert_eq!(
        wait(&a, &v, &["failed"]).refusal.as_deref(),
        Some("proof-mismatch")
    );
    assert!(node.got.lock().unwrap().is_empty());
    let a = api(
        FakeProver::new(Answer::Fail("worker-timeout"), false),
        Arc::clone(&node),
    );
    let (v, _) = admit(&a, &token(8, GENESIS_HASH, 0), bundle_s()).unwrap();
    assert_eq!(
        wait(&a, &v, &["failed"]).refusal.as_deref(),
        Some("worker-timeout")
    );
    assert!(node.got.lock().unwrap().is_empty());
}

/// Three S bundles of one spend signed at three validity heights: three
/// distinct intents.
fn three_intents() -> &'static [ProvingBundle] {
    static B: OnceLock<Vec<ProvingBundle>> = OnceLock::new();
    B.get_or_init(|| {
        signed_bundles(
            L2ShapeTag::S,
            &[VALID_UNTIL + 1, VALID_UNTIL + 2, VALID_UNTIL + 3],
        )
    })
}

#[test]
fn the_queue_is_bounded_and_a_queued_job_cancels() {
    let prover = FakeProver::new(Answer::Honest, true);
    let node = Arc::new(FakeNode::default());
    let a = AnnuletApi::with_clock(
        config(GENESIS_HASH, 1, Duration::from_secs(60)),
        Arc::clone(&prover) as Arc<dyn AnnuletProver>,
        Arc::clone(&node) as Arc<dyn Submitter>,
        clock,
    );
    let [x, y, z] = three_intents() else {
        unreachable!()
    };
    let (running, _) = admit(&a, &token(9, GENESIS_HASH, 0), x).unwrap();
    wait(&a, &running, &["proving"]);
    let (queued, _) = admit(&a, &token(10, GENESIS_HASH, 0), y).unwrap();
    assert_eq!((queued.state, queued.queue_position), ("queued", Some(1)));
    let full = admit(&a, &token(11, GENESIS_HASH, 0), z);
    assert_eq!(
        full.err().map(|e| (e.status, e.code)),
        Some((503, "prover-busy"))
    );
    let claims = a.authorize_only(Some(&token(11, GENESIS_HASH, 0))).unwrap();
    assert_eq!(
        a.quota(&claims).used_today,
        0,
        "a busy refusal is not an admitted job"
    );

    assert_eq!(a.cancel(cap_of(&queued)).unwrap().state, "cancelled");
    prover.release();
    wait(&a, &running, &["submitted"]);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        *prover.calls.lock().unwrap(),
        1,
        "the cancelled job was never proved"
    );
    assert_eq!(a.get(cap_of(&queued)).unwrap().state, "cancelled");
    assert_eq!(node.got.lock().unwrap().len(), 1);
}

#[test]
fn a_proving_job_cancels_and_is_never_submitted() {
    let prover = FakeProver::new(Answer::Honest, true);
    let node = Arc::new(FakeNode::default());
    let a = api(Arc::clone(&prover), Arc::clone(&node));
    let (v, _) = admit(&a, &token(15, GENESIS_HASH, 0), &three_intents()[0]).unwrap();
    wait(&a, &v, &["proving"]);
    assert_eq!(a.cancel(cap_of(&v)).unwrap().state, "cancelled");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(a.get(cap_of(&v)).unwrap().state, "cancelled");
    assert!(node.got.lock().unwrap().is_empty());
}

#[test]
fn the_job_url_is_a_capability_that_expires() {
    let a = AnnuletApi::with_clock(
        config(GENESIS_HASH, 2, Duration::from_millis(300)),
        FakeProver::new(Answer::Honest, false),
        Arc::new(FakeNode::default()),
        clock,
    );
    let (v, _) = admit(&a, &token(14, GENESIS_HASH, 0), bundle_s()).unwrap();
    wait(&a, &v, &["submitted"]);
    assert_eq!(
        a.get("0".repeat(64).as_str()).err().map(|e| e.code),
        Some("job-not-found")
    );
    assert_eq!(
        a.get("not-a-cap").err().map(|e| e.code),
        Some("job-not-found")
    );
    assert_eq!(
        a.get(&cap_of(&v).to_uppercase()).err().map(|e| e.code),
        Some("job-not-found")
    );
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(
        a.get(cap_of(&v)).err().map(|e| e.code),
        Some("job-not-found"),
        "gone after the TTL"
    );
    // A finished job does not cancel.
    let (v, _) = admit(&a, &token(14, GENESIS_HASH, 0), bundle_s()).unwrap();
    wait(&a, &v, &["submitted"]);
    assert_eq!(a.cancel(cap_of(&v)).unwrap().state, "submitted");
}

#[test]
fn proof_added_takes_the_bundle_s_transaction_plus_a_proof_only() {
    let wire = qlab_p2p::codec::encode_tx_annulet(bundle_s().tx());
    let mut tx = bundle_s().tx().clone();
    assert_eq!(
        proof_added(&wire, &wire).err(),
        Some("proof-mismatch"),
        "no proof"
    );
    tx.proof = vec![9];
    assert!(proof_added(&wire, &qlab_p2p::codec::encode_tx_annulet(&tx)).is_ok());
    *tx.discovery.last_mut().unwrap() ^= 1;
    assert_eq!(
        proof_added(&wire, &qlab_p2p::codec::encode_tx_annulet(&tx)).err(),
        Some("proof-mismatch")
    );
    assert_eq!(proof_added(&wire, b"garbage").err(), Some("proof-mismatch"));
}

#[test]
fn the_child_s_frames_are_bounded_before_allocation() {
    let mut big = vec![0u8];
    big.extend_from_slice(&((MAX_ANNULET_TX_BYTES as u32) + 1).to_le_bytes());
    assert_eq!(
        read_framed(big.as_slice()).err(),
        Some("worker-output-too-large")
    );
    let mut long_code = vec![1u8];
    long_code.extend_from_slice(&65u32.to_le_bytes());
    assert_eq!(
        read_framed(long_code.as_slice()).err(),
        Some("worker-output-too-large")
    );
    assert_eq!(
        read_framed([7u8, 0, 0, 0, 0].as_slice()).err(),
        Some("worker-output-kind-unknown")
    );
    let mut trailing = frame(1, b"bundle-refused");
    trailing.push(0);
    assert_eq!(
        read_framed(trailing.as_slice()).err(),
        Some("worker-output-trailing")
    );
    assert_eq!(
        read_framed(frame(0, b"tx").as_slice()),
        Ok((0, b"tx".to_vec()))
    );
    assert_eq!(
        worker_code(b"selected nullifier deadbeef was spent"),
        "worker-error-unknown"
    );
}

#[test]
fn the_child_refuses_a_bad_frame_without_proving() {
    let framed = |b: &[u8]| {
        let mut f = (b.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(b);
        f
    };
    assert_eq!(
        annulet_worker_once(framed(b"").as_slice(), &GENESIS_HASH).err(),
        Some("bundle-refused")
    );
    assert_eq!(
        annulet_worker_once(framed(b"nope").as_slice(), &GENESIS_HASH).err(),
        Some("bundle-refused")
    );
    let over = ((MAX_ANNULET_BUNDLE_BYTES + 1) as u32).to_le_bytes();
    assert_eq!(
        annulet_worker_once(over.as_slice(), &GENESIS_HASH).err(),
        Some("bundle-refused")
    );
    assert_eq!(
        annulet_worker_once([1u8, 0].as_slice(), &GENESIS_HASH).err(),
        Some("worker-protocol-refused")
    );
    // A real bundle for another net: refused by the lock, before any prove.
    let other = framed(&bundle_s().encode());
    assert_eq!(
        annulet_worker_once(other.as_slice(), &[0x6f; 32]).err(),
        Some("bundle-refused")
    );
}

#[test]
fn a_node_s_answer_becomes_a_code_not_echoed_text() {
    let code = sanitize(b"refused: Expired (valid_until 40 < 41)\n<script>");
    assert!(code.starts_with("refused:-expired"), "{code}");
    assert!(
        code.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-:_".contains(&b)),
        "{code}"
    );
    assert_eq!(sanitize(b""), "unnamed");
    assert!(sanitize(&[b'a'; 200]).len() <= 48);
}
