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
        l2_auth: qlab_devnet::forms::L2AuthForm::CandidateA,
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
        v3: None,
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
    let admission = api.authorize(Some(auth))?;
    api.submit(&admission, bundle.encode())
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
    let admission = a.authorize(Some(&t)).unwrap();
    let claims = *admission.claims().unwrap();
    let code = |bytes: Vec<u8>| {
        a.submit(&admission, bytes)
            .err()
            .map(|e| (e.status, e.code))
    };
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

    // F2: a cancelled queued job leaves the queue at once — the next
    // token's upload is admitted while the first job still proves.
    let cancelled = a.cancel(cap_of(&queued)).unwrap();
    assert_eq!(
        (cancelled.state, cancelled.queue_position),
        ("cancelled", None)
    );
    let (next, created) = admit(&a, &token(11, GENESIS_HASH, 0), z).unwrap();
    assert!(created);
    assert_eq!((next.state, next.queue_position), ("queued", Some(1)));
    prover.release();
    wait(&a, &running, &["submitted"]);
    wait(&a, &next, &["submitted"]);
    assert_eq!(
        *prover.calls.lock().unwrap(),
        2,
        "the cancelled job was never proved"
    );
    assert_eq!(a.get(cap_of(&queued)).unwrap().state, "cancelled");
    assert_eq!(node.got.lock().unwrap().len(), 2);
}

/// F3: an admitted upload holds its token's one reading slot until the
/// admission drops; the HTTP layer's refusals count under the token's tag.
#[test]
fn an_upload_holds_its_token_s_reading_slot() {
    let a = api(FakeProver::new(Answer::Honest, false), Arc::default());
    let t = token(16, GENESIS_HASH, 0);
    let reading = a.authorize(Some(&t)).unwrap();
    assert_eq!(
        a.authorize(Some(&t)).err().map(|e| (e.status, e.code)),
        Some((429, "token-busy"))
    );
    assert!(
        a.authorize(Some(&token(17, GENESIS_HASH, 0))).is_ok(),
        "other tokens are not held up"
    );
    a.count_refusal(reading.who(), "upload-deadline");
    drop(reading);
    assert!(
        a.authorize(Some(&t)).is_ok(),
        "the slot frees when the read ends"
    );
    let tag = token_tag(&[16; 16]);
    let counts = a.drain_refusals();
    assert!(
        counts.contains(&((tag.clone(), "upload-deadline"), 1)),
        "{counts:?}"
    );
    assert!(counts.contains(&((tag, "token-busy"), 1)), "{counts:?}");
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
        annulet_worker_once(framed(b"").as_slice(), &GENESIS_HASH, L2AuthForm::CandidateA).err(),
        Some("bundle-refused")
    );
    assert_eq!(
        annulet_worker_once(framed(b"nope").as_slice(), &GENESIS_HASH, L2AuthForm::CandidateA).err(),
        Some("bundle-refused")
    );
    let over = ((MAX_ANNULET_BUNDLE_BYTES + 1) as u32).to_le_bytes();
    assert_eq!(
        annulet_worker_once(over.as_slice(), &GENESIS_HASH, L2AuthForm::CandidateA).err(),
        Some("bundle-refused")
    );
    assert_eq!(
        annulet_worker_once([1u8, 0].as_slice(), &GENESIS_HASH, L2AuthForm::CandidateA).err(),
        Some("worker-protocol-refused")
    );
    // A real bundle for another net: refused by the lock, before any prove.
    let other = framed(&bundle_s().encode());
    assert_eq!(
        annulet_worker_once(other.as_slice(), &[0x6f; 32], L2AuthForm::CandidateA).err(),
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

/// Lab #924 PR 3g: an Annulet node link is https, or plain http under the
/// mode's own acknowledgement — never the L1 experiment's.
#[test]
fn a_plain_http_node_link_needs_the_annulet_acknowledgement() {
    let name = "QUMBRA_PROVER_ANNULET_NODE_URL";
    let plain = "http://54.210.95.232:39603";
    assert!(annulet_node_url(name, "https://annulet-testnet.qumbra.org", None).is_ok());
    let refused = annulet_node_url(name, plain, None).unwrap_err();
    assert!(refused.contains(ANNULET_PLAIN_HTTP_VAR) && refused.contains(ANNULET_PLAIN_HTTP_ACK), "{refused}");
    assert!(
        annulet_node_url(name, plain, Some("I_UNDERSTAND_NODE_HTTP_IS_PRIVATE_AND_VALUELESS")).is_err(),
        "the L1 experiment's acknowledgement does not open the Annulet link"
    );
    assert!(annulet_node_url(name, plain, Some(ANNULET_PLAIN_HTTP_ACK)).is_ok());
    assert!(annulet_node_url(name, "ftp://x", Some(ANNULET_PLAIN_HTTP_ACK)).is_err());
}

/// Lab #937 PR B (review F2), PR E: the service's net fails closed at
/// startup. Unset or 33 is served (`/info` then says 33), and 34 since PR E;
/// anything else is not a Candidate A Annulet.
#[test]
fn the_genesis_format_is_33_or_34_and_nothing_else() {
    use crate::annulet::annulet_genesis_form;
    use qlab_devnet::forms::L2AuthForm;
    assert_eq!(annulet_genesis_form(None), Ok(L2AuthForm::CandidateA));
    assert_eq!(annulet_genesis_form(Some("33")), Ok(L2AuthForm::CandidateA));
    assert_eq!(annulet_genesis_form(Some("34")), Ok(L2AuthForm::CandidateAV3));
    for bad in ["32", "35", "5", "x", ""] {
        assert!(annulet_genesis_form(Some(bad)).is_err(), "{bad}");
    }
    // `/info` reports the configured net's format, never a hard-coded one.
    let a = api(FakeProver::new(Answer::Honest, false), Arc::default());
    assert_eq!(a.info().genesis_format, L2AuthForm::CandidateA.annulet_genesis_format_version());
}

/// Lab #937 PR C (review F4): this service serves format 33; a three-output
/// (format-34, version-2) bundle is refused **by name** — `422
/// outputs-not-the-nets` — before anything reaches the prover, and is not an
/// admitted job.
#[test]
fn a_three_output_bundle_is_refused_by_name_on_a_format_33_service() {
    let prover = FakeProver::new(Answer::Honest, false);
    let a = api(Arc::clone(&prover), Arc::default());
    let v3 = qlab_l2spend::fixtures::signed_bundle_v3(L2ShapeTag::S);
    let Err(e) = admit(&a, &token(9, GENESIS_HASH, 0), &v3) else { panic!("a v3 bundle is admitted on a 33 service") };
    assert_eq!((e.status, e.code), (422, "outputs-not-the-nets"));
    assert_eq!(*prover.calls.lock().unwrap(), 0, "nothing reached the prover");
}

// ------------------------------------------------- format 34 (lab #937 PR E)

use crate::annulet_v3::{prover_fee, ChainFollow, ProverPrice, PAID_LEDGER_HEADER};
use qumbra_wallet::spent::NullifierChunk;

/// The v3 fixtures' output 3: the fee-bank spend (S) pays `[0x43; 4]` 3
/// units; the P v3 spend pays `[0x43; 4]` 0 units; the S v3 spend pays
/// `[0x33; 4]` 0 units. Every one is asset 0.
const PAYEE_RKM: [u64; 4] = [0x43; 4];

/// The pinned node as the follow sees it: a tip, the blocks' nullifiers,
/// pages of at most `page` blocks, and a switch that takes it down.
struct FakeChain {
    blocks: Mutex<Vec<(u64, Vec<[u8; 32]>)>>,
    down: AtomicBool,
    page: usize,
}

impl FakeChain {
    /// Blocks 1..=`tip`, `landed` in the last one.
    fn new(tip: u64, landed: &[[u8; 32]]) -> Arc<Self> {
        let mut blocks: Vec<_> = (1..=tip).map(|h| (h, vec![[h as u8; 32]])).collect();
        if let Some(last) = blocks.last_mut() {
            last.1.extend_from_slice(landed);
        }
        Arc::new(Self { blocks: Mutex::new(blocks), down: AtomicBool::new(false), page: 2 })
    }
    fn push(&self, nullifiers: &[[u8; 32]]) {
        let mut b = self.blocks.lock().unwrap();
        let next = b.len() as u64 + 1;
        b.push((next, nullifiers.to_vec()));
    }
}

impl ChainFollow for FakeChain {
    fn tip(&self) -> Result<u64, String> {
        if self.down.load(Ordering::Acquire) {
            return Err("node-unreachable".into());
        }
        Ok(self.blocks.lock().unwrap().len() as u64)
    }
    fn nullifiers(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
        if self.down.load(Ordering::Acquire) {
            return Err("node-unreachable".into());
        }
        let blocks = self.blocks.lock().unwrap();
        let blocks = blocks.iter().filter(|(h, _)| (from..=to).contains(h)).take(self.page).cloned().collect();
        Ok(NullifierChunk { from, to, blocks })
    }
}

/// A fresh ledger path of this process's.
fn ledger_path(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("qumbra-paid-ledger-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn config_v3(chain: Arc<FakeChain>, price: ProverPrice, ledger: &std::path::Path) -> AnnuletConfig {
    let mut c = config(GENESIS_HASH, 2, Duration::from_secs(60));
    c.l2_auth = L2AuthForm::CandidateAV3;
    c.slot_secs = 1;
    c.tokens = TokenKeys::default();
    c.v3 = Some(V3Config {
        payee: "qaddr-fixture-payee".into(),
        payee_rkm: PAYEE_RKM,
        price,
        ledger: Arc::new(PaidLedger::open(ledger).unwrap()),
        follow: chain,
    });
    c
}

fn api_v3(
    prover: Arc<FakeProver>,
    node: Arc<FakeNode>,
    chain: Arc<FakeChain>,
    price: ProverPrice,
    ledger: &std::path::Path,
) -> AnnuletApi {
    AnnuletApi::with_clock(config_v3(chain, price, ledger), prover, node, clock)
}

/// Until the follow has caught up.
fn wait_ready(a: &AnnuletApi) {
    let started = Instant::now();
    while a.ready().is_err() {
        assert!(started.elapsed() < Duration::from_secs(20), "the follow never caught up");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn admit_ip(a: &AnnuletApi, ip: &str, bundle: &ProvingBundle) -> Result<(AnnuletJobView, bool), ApiError> {
    let admission = a.authorize_ip(Some(ip))?;
    a.submit(&admission, bundle.encode())
}

fn code<T>(r: Result<T, ApiError>) -> Option<(u16, &'static str)> {
    r.err().map(|e| (e.status, e.code))
}

fn fee_bank() -> &'static [ProvingBundle] {
    static B: OnceLock<Vec<ProvingBundle>> = OnceLock::new();
    B.get_or_init(|| {
        qlab_l2spend::fixtures::signed_bundles_fee_bank(&[VALID_UNTIL, VALID_UNTIL + 1, VALID_UNTIL + 2])
    })
}

fn v3(shape: L2ShapeTag) -> &'static ProvingBundle {
    static S: OnceLock<ProvingBundle> = OnceLock::new();
    static P: OnceLock<ProvingBundle> = OnceLock::new();
    let cell = if shape == L2ShapeTag::S { &S } else { &P };
    cell.get_or_init(|| qlab_l2spend::fixtures::signed_bundle_v3(shape))
}

/// Lab #937 PR E (D4): on format 34 output 3 pays the payee at least the
/// shape's price, read from the witness — else `402`, by name, before
/// anything reaches the prover. More than the price is accepted.
#[test]
fn a_format_34_bundle_pays_the_payee_its_price_or_is_refused_402() {
    // S 3 and P 0: the fee-bank spend pays exactly 3, the P spend 0.
    let prover = FakeProver::new(Answer::Honest, false);
    let at = ledger_path("fee-ok");
    let a = api_v3(Arc::clone(&prover), Arc::default(), FakeChain::new(3, &[]), ProverPrice { s: 3, p: 0 }, &at);
    wait_ready(&a);
    let (v, created) = admit_ip(&a, "198.51.100.1", &fee_bank()[0]).unwrap();
    assert!(created);
    assert_eq!(wait(&a, &v, &["submitted", "failed"]).state, "submitted");
    // The P spend shares the fee-bank spend's signer and notes — its
    // nullifiers — so it gets a service of its own (on `a` it is 409
    // `nullifier-in-flight`, rightly).
    let at = ledger_path("fee-ok-p");
    let a = api_v3(Arc::clone(&prover), Arc::default(), FakeChain::new(3, &[]), ProverPrice { s: 3, p: 0 }, &at);
    wait_ready(&a);
    let (v, _) = admit_ip(&a, "198.51.100.2", v3(L2ShapeTag::P)).unwrap();
    assert_eq!(wait(&a, &v, &["submitted", "failed"]).state, "submitted");

    // S 4 and P 1: both short; the S v3 spend pays another key — missing.
    let prover = FakeProver::new(Answer::Honest, false);
    let at = ledger_path("fee-short");
    let a = api_v3(Arc::clone(&prover), Arc::default(), FakeChain::new(3, &[]), ProverPrice { s: 4, p: 1 }, &at);
    wait_ready(&a);
    assert_eq!(code(admit_ip(&a, "198.51.100.3", &fee_bank()[0])), Some((402, "prover-fee-short")));
    assert_eq!(code(admit_ip(&a, "198.51.100.4", v3(L2ShapeTag::P))), Some((402, "prover-fee-short")));
    assert_eq!(code(admit_ip(&a, "198.51.100.5", v3(L2ShapeTag::S))), Some((402, "prover-fee-missing")));
    // A format-33 (two-output) bundle has no output 3: the lock refuses it.
    assert_eq!(code(admit_ip(&a, "198.51.100.6", bundle_s())), Some((422, "outputs-not-the-nets")));
    assert_eq!(*prover.calls.lock().unwrap(), 0, "nothing reached the prover");

    // The rule itself: the payee's `rkm`, asset 0, at least the price.
    let out = |rkm, asset, value| qlab_air::l2::L2TxOutput { value, asset, rkm, rho: [0; 4], rseed: [0; 4] };
    assert_eq!(prover_fee(Some(&out(PAYEE_RKM, 0, 5)), &PAYEE_RKM, 4), Ok(()));
    assert_eq!(prover_fee(Some(&out(PAYEE_RKM, 0, 4)), &PAYEE_RKM, 4), Ok(()));
    assert_eq!(code(prover_fee(Some(&out(PAYEE_RKM, 0, 3)), &PAYEE_RKM, 4)), Some((402, "prover-fee-short")));
    assert_eq!(code(prover_fee(Some(&out(PAYEE_RKM, 7, 9)), &PAYEE_RKM, 4)), Some((402, "prover-fee-missing")));
    assert_eq!(code(prover_fee(Some(&out([0x44; 4], 0, 9)), &PAYEE_RKM, 4)), Some((402, "prover-fee-missing")));
    assert_eq!(code(prover_fee(None, &PAYEE_RKM, 0)), Some((402, "prover-fee-missing")));
}

/// Lab #937 PR E (D4, the ruling's IP conditions): on format 34 admission
/// keys on `X-Qumbra-Client-IP` — absent or not an IP is `400`; one live job
/// and one upload per IP (`429 ip-busy`), an IPv4-mapped address as its IPv4
/// and IPv6 by /64; another IP is admitted; the refusal counts never carry
/// the IP; the intent stays the idempotency key, its IP the submitter.
#[test]
fn on_format_34_admission_keys_on_the_client_ip() {
    let prover = FakeProver::new(Answer::Honest, true);
    let at = ledger_path("ip");
    let a = api_v3(Arc::clone(&prover), Arc::default(), FakeChain::new(1, &[]), ProverPrice { s: 3, p: 0 }, &at);
    assert!(a.admits_by_ip());
    wait_ready(&a);
    for bad in [None, Some(""), Some("not-an-ip"), Some("203.0.113.7:443"), Some("203.0.113.7, 10.0.0.1")] {
        assert_eq!(code(a.authorize_ip(bad)), Some((400, "client-ip-unknown")), "{bad:?}");
    }
    let (v, _) = admit_ip(&a, "203.0.113.7", &fee_bank()[0]).unwrap();
    assert_eq!(code(a.authorize_ip(Some("203.0.113.7"))), Some((429, "ip-busy")));
    assert_eq!(code(a.authorize_ip(Some("::ffff:203.0.113.7"))), Some((429, "ip-busy")), "IPv4-mapped is the IPv4");
    assert!(a.authorize_ip(Some("203.0.113.8")).is_ok(), "another IP is not held up");

    // A reading slot per IP; an IPv6 /64 is one IP.
    let reading = a.authorize_ip(Some("2001:db8:1:2::1")).unwrap();
    assert_eq!(code(a.authorize_ip(Some("2001:db8:1:2:ffff::9"))), Some((429, "ip-busy")));
    assert!(a.authorize_ip(Some("2001:db8:1:3::1")).is_ok(), "another /64");
    drop(reading);
    assert!(a.authorize_ip(Some("2001:db8:1:2:ffff::9")).is_ok(), "the slot frees when the read ends");

    // The intent is the idempotency key: its IP gets the job back, another
    // IP is refused.
    prover.release();
    wait(&a, &v, &["submitted"]);
    let (again, created) = admit_ip(&a, "203.0.113.7", &fee_bank()[0]).unwrap();
    assert!(!created);
    assert_eq!(again.job_url, v.job_url);
    assert_eq!(code(admit_ip(&a, "203.0.113.9", &fee_bank()[0])), Some((409, "intent-in-flight")));

    let counts = a.drain_refusals();
    assert!(counts.iter().any(|((_, c), _)| *c == "ip-busy"), "{counts:?}");
    // Each refusal is counted under `-` or an 8-hex-digit tag of the salted
    // key — never an address.
    assert!(
        counts
            .iter()
            .all(|((who, _), _)| who == "-" || (who.len() == 8 && who.bytes().all(|b| b.is_ascii_hexdigit()))),
        "{counts:?}"
    );
}

/// Lab #937 PR E (the ruling): on format 34 the token configuration is not
/// read — a token file left configured is ignored, not refused — and `/quota`
/// is not served; on 33 the keys file stays required.
#[test]
fn the_token_configuration_is_ignored_on_34_and_required_on_33() {
    let (_, deny, ignored) =
        token_config(L2AuthForm::CandidateAV3, Some("/nonexistent/keys".into()), Some("/nonexistent/deny".into()))
            .expect("34 reads no token file");
    assert_eq!((deny, ignored), (None, true));
    let (_, _, ignored) = token_config(L2AuthForm::CandidateAV3, None, None).unwrap();
    assert!(!ignored);
    let e = token_config(L2AuthForm::CandidateA, None, None).err().unwrap();
    assert!(e.contains("QUMBRA_PROVER_TOKEN_KEYS_FILE is required"), "{e}");
    let e = token_config(L2AuthForm::CandidateA, Some("/nonexistent/keys".into()), None).err().unwrap();
    assert!(e.contains("could not be read"), "{e}");
    // The 33 service admits by token; the 34 one by IP.
    assert!(!api(FakeProver::new(Answer::Honest, false), Arc::default()).admits_by_ip());
}

/// Lab #937 PR E: `/info` on format 34 carries what the kernel's
/// `prover_pins::admit` checks — `fee_asset` 0, `price: {"S", "P"}`, the
/// payee — and on 33 none of them.
#[test]
fn info_on_format_34_carries_what_the_kernel_pins_and_33_s_does_not() {
    let at = ledger_path("info");
    let a = api_v3(
        FakeProver::new(Answer::Honest, false),
        Arc::default(),
        FakeChain::new(1, &[]),
        ProverPrice { s: 2, p: 3 },
        &at,
    );
    let info = serde_json::to_value(a.info()).unwrap();
    assert_eq!(info["genesis_format"], 34);
    assert_eq!(info["fee_asset"], 0);
    assert_eq!(info["price"], serde_json::json!({"S": 2, "P": 3}));
    assert_eq!(info["payee"], "qaddr-fixture-payee");
    assert_eq!(info["genesis_hash"], hex(&GENESIS_HASH));
    let info = serde_json::to_value(api(FakeProver::new(Answer::Honest, false), Arc::default()).info()).unwrap();
    for absent in ["fee_asset", "price", "payee"] {
        assert!(info.get(absent).is_none(), "{absent} on a format-33 /info");
    }
}

/// Lab #937 PR E: format 34's startup configuration refuses by name — the
/// payee (a full version-2 address), the prices, the ledger (created 0600
/// with its version header; an existing one must be 0600 and start with it).
#[test]
fn the_format_34_configuration_refuses_by_name_at_startup() {
    use crate::annulet_v3::{payee_rkm, PAID_LEDGER_VAR, PAYEE_VAR, PRICE_P_VAR, PRICE_S_VAR};
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    let w = qlab_wallet::Wallet::from_master_seed(&MasterSeed::from_entropy([7; ENTROPY_LEN]), 0);
    let v2 = w.address_candidate_a_at_index(0, &[1, 2, 3, 4]);
    let v1 = w.address_at_index(0).encode();
    assert_eq!(payee_rkm(&format!(" {} ", v2.encode())), Ok(v2.rkm_lanes()));
    let s = |x: &str| Some(x.to_string());
    let chain: Arc<dyn ChainFollow> = FakeChain::new(1, &[]);
    let at = ledger_path("startup");
    let try_ = |payee: Option<String>, ps: Option<String>, pp: Option<String>, ledger: Option<String>| {
        V3Config::from_values(payee, ps, pp, ledger, Arc::clone(&chain)).err().unwrap_or_default()
    };
    let l = at.to_str().map(str::to_string);
    let refusals = [
        (try_(None, s("1"), s("1"), l.clone()), format!("{PAYEE_VAR} is required on format 34")),
        (try_(s("qaddr1nope"), s("1"), s("1"), l.clone()), format!("{PAYEE_VAR} is not an address")),
        (try_(s(&v1), s("1"), s("1"), l.clone()), format!("{PAYEE_VAR} must be a full version-2 address")),
        (try_(s(&v2.encode()), None, s("1"), l.clone()), format!("{PRICE_S_VAR} is required on format 34")),
        (try_(s(&v2.encode()), s("1"), s("-1"), l.clone()), format!("{PRICE_P_VAR} must be a whole number")),
        (try_(s(&v2.encode()), s("1"), s("1"), None), format!("{PAID_LEDGER_VAR} is required on format 34")),
    ];
    for (got, want) in refusals {
        assert!(got.contains(&want), "{got:?} does not name {want:?}");
    }
    assert!(!at.exists(), "nothing created before the configuration is whole");
    // Created 0600 with its header; reopened as it is.
    let ok = V3Config::from_values(s(&v2.encode()), s("2"), s("3"), l.clone(), Arc::clone(&chain)).unwrap();
    assert_eq!((ok.payee_rkm, ok.price), (v2.rkm_lanes(), ProverPrice { s: 2, p: 3 }));
    assert_eq!(std::fs::read_to_string(&at).unwrap(), format!("{PAID_LEDGER_HEADER}\n"));
    assert!(PaidLedger::open(&at).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&at).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = PaidLedger::open(&at).err().unwrap();
        assert!(e.contains("owner only (0600)"), "{e}");
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&at, "something else\n").unwrap();
    let e = PaidLedger::open(&at).err().unwrap();
    assert!(e.contains("not a version-1 paid ledger"), "{e}");
    let _ = std::fs::remove_file(&at);
}

/// Lab #937 PR E (D4): a nullifier that landed — the follow's set, paged
/// from height 1 — is `409 nullifier-landed`; one claimed by a live or
/// submitted job here is `409 nullifier-in-flight`; the follow keeps up as
/// blocks land. Nothing refused reaches the prover.
#[test]
fn landed_and_in_flight_nullifiers_are_refused_409() {
    let nf = fee_bank()[0].tx().public.nullifiers[0];
    let prover = FakeProver::new(Answer::Honest, false);
    let at = ledger_path("landed");
    let a = api_v3(Arc::clone(&prover), Arc::default(), FakeChain::new(5, &[nf]), ProverPrice { s: 3, p: 0 }, &at);
    wait_ready(&a);
    assert_eq!(a.inner.follow.as_ref().unwrap().size(), (6, 5), "five blocks over pages of two, one more nullifier");
    assert_eq!(code(admit_ip(&a, "192.0.2.1", &fee_bank()[0])), Some((409, "nullifier-landed")));
    assert_eq!(*prover.calls.lock().unwrap(), 0);

    let prover = FakeProver::new(Answer::Honest, true);
    let chain = FakeChain::new(1, &[]);
    let at = ledger_path("in-flight");
    let a = api_v3(Arc::clone(&prover), Arc::default(), Arc::clone(&chain), ProverPrice { s: 3, p: 0 }, &at);
    wait_ready(&a);
    let [x, y, z] = fee_bank() else { unreachable!() };
    let (v, _) = admit_ip(&a, "192.0.2.2", x).unwrap();
    assert_eq!(code(admit_ip(&a, "192.0.2.3", y)), Some((409, "nullifier-in-flight")), "queued");
    prover.release();
    wait(&a, &v, &["submitted"]);
    assert_eq!(code(admit_ip(&a, "192.0.2.3", y)), Some((409, "nullifier-in-flight")), "submitted, not yet landed");
    // It lands: the follow sees it, and the refusal says so.
    chain.push(&x.tx().public.nullifiers);
    let started = Instant::now();
    while a.inner.follow.as_ref().unwrap().size().1 < 2 {
        assert!(started.elapsed() < Duration::from_secs(20), "the follow did not advance");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(code(admit_ip(&a, "192.0.2.4", z)), Some((409, "nullifier-landed")));
    assert_eq!(*prover.calls.lock().unwrap(), 1, "only the first was proved");
}

/// Lab #937 PR E (the ruling: fail loudly): until the follow has caught up,
/// admission is `503 nullifiers-catching-up`; once the node is unreachable
/// for more than a slot, `503 nullifiers-stale` — and `ready()`, which is
/// what `/healthz` reports, says the same. A node that skips a height or
/// serves none is an error, not a gap; a tip below the followed height empties
/// the set, which is rebuilt from height 1.
#[test]
fn the_nullifier_follow_fails_loudly() {
    let chain = FakeChain::new(2, &[]);
    chain.down.store(true, Ordering::Release);
    let at = ledger_path("loud");
    let a = api_v3(
        FakeProver::new(Answer::Honest, false),
        Arc::default(),
        Arc::clone(&chain),
        ProverPrice { s: 3, p: 0 },
        &at,
    );
    std::thread::sleep(Duration::from_millis(1_200));
    assert_eq!(code(a.ready()), Some((503, "nullifiers-catching-up")));
    assert_eq!(code(admit_ip(&a, "192.0.2.10", &fee_bank()[0])), Some((503, "nullifiers-catching-up")));
    chain.down.store(false, Ordering::Release);
    wait_ready(&a);
    chain.down.store(true, Ordering::Release);
    let started = Instant::now();
    while a.ready().is_ok() {
        assert!(started.elapsed() < Duration::from_secs(20), "an unreachable node never made the follow stale");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(code(a.ready()), Some((503, "nullifiers-stale")));
    assert_eq!(code(admit_ip(&a, "192.0.2.11", &fee_bank()[0])), Some((503, "nullifiers-stale")));

    // What the follow will not paper over.
    struct Lying(u64, Vec<(u64, Vec<[u8; 32]>)>);
    impl ChainFollow for Lying {
        fn tip(&self) -> Result<u64, String> {
            Ok(self.0)
        }
        fn nullifiers(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
            Ok(NullifierChunk { from, to, blocks: self.1.clone() })
        }
    }
    let f = NullifierFollow::new(Duration::from_secs(1));
    let e = f.poll(&Lying(3, vec![(1, vec![]), (3, vec![])])).unwrap_err();
    assert!(e.contains("skips height 2"), "{e}");
    let f = NullifierFollow::new(Duration::from_secs(1));
    assert!(f.poll(&Lying(2, vec![])).unwrap_err().contains("served no block at height 1"));
    // A tip regression: the set is emptied and rebuilt from height 1, not
    // held at 503 until the chain regrows past the old height.
    let f = NullifierFollow::new(Duration::from_secs(1));
    f.poll(&Lying(2, vec![(1, vec![[1; 32]]), (2, vec![[2; 32]])])).unwrap();
    assert_eq!(f.size(), (2, 2));
    let e = f.poll(&Lying(1, vec![(1, vec![[9; 32]])])).unwrap_err();
    assert!(e.contains("below the followed height 2: rebuilding"), "{e}");
    assert_eq!(f.size(), (0, 0));
    assert_eq!(code(f.readiness()), Some((503, "nullifiers-catching-up")));
    f.poll(&Lying(1, vec![(1, vec![[9; 32]])])).unwrap();
    assert_eq!(f.size(), (1, 1), "rebuilt from the node's chain, the old height-2 nullifier gone");
    assert_eq!(f.check(&[[2; 32]]), Ok(()));
    assert_eq!(code(f.check(&[[9; 32]])), Some((409, "nullifier-landed")));
    assert_eq!(code(NullifierFollow::new(Duration::from_secs(1)).readiness()), Some((503, "nullifiers-catching-up")));
}

/// Lab #937 PR E (D5): an accepted submission appends exactly one line —
/// the entry version, then output 3's opening (`cm` as on chain, value,
/// `rkm`, `rho`, `rseed`, shape, time) — under the version header, and the
/// file stays 0600. A submission the node refuses, and a bundle admission
/// refuses, write nothing.
#[test]
fn an_accepted_submission_writes_one_ledger_line_and_a_refused_one_none() {
    let lanes = |l: &[u64; 4]| l.iter().map(|x| hex(&x.to_le_bytes())).collect::<String>();
    let at = ledger_path("ledger");
    let a = api_v3(
        FakeProver::new(Answer::Honest, false),
        Arc::default(),
        FakeChain::new(1, &[]),
        ProverPrice { s: 3, p: 0 },
        &at,
    );
    wait_ready(&a);
    let b = &fee_bank()[0];
    let (v, _) = admit_ip(&a, "192.0.2.20", b).unwrap();
    assert_eq!(wait(&a, &v, &["submitted", "failed"]).state, "submitted");
    let text = std::fs::read_to_string(&at).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert_eq!(lines[0], PAID_LEDGER_HEADER);
    let o = &b.witness().outputs[2];
    // ρ is the kernel's, from the first nullifier — not the witness's (lab #958).
    let nf0 = &b.tx().public.nullifiers[0];
    let nf0: [u64; 4] = core::array::from_fn(|i| u64::from_le_bytes(nf0[i * 8..i * 8 + 8].try_into().unwrap()));
    let want = format!(
        "1 cm={} value=3 asset=0 rkm={} rho={} rseed={} shape=S at=",
        hex(&b.tx().public.commitments[2]),
        lanes(&PAYEE_RKM),
        lanes(&qlab_air::l2::derive_output_rho_l2(&nf0, 2)),
        lanes(&o.rseed),
    );
    assert!(lines[1].starts_with(&want), "{}\nwant {want}…", lines[1]);
    assert!(lines[1]["at=".len() + lines[1].find("at=").unwrap()..].parse::<u64>().is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&at).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // The node refuses it: no line. A 402: no line.
    let at = ledger_path("ledger-refused");
    let node = Arc::new(FakeNode { refuse: Some("node-refused:expired"), ..FakeNode::default() });
    let a = api_v3(FakeProver::new(Answer::Honest, false), node, FakeChain::new(1, &[]), ProverPrice { s: 3, p: 1 }, &at);
    wait_ready(&a);
    let (v, _) = admit_ip(&a, "192.0.2.21", b).unwrap();
    assert_eq!(wait(&a, &v, &["submitted", "failed"]).state, "failed");
    assert_eq!(code(admit_ip(&a, "192.0.2.22", v3(L2ShapeTag::P))), Some((402, "prover-fee-short")));
    assert_eq!(std::fs::read_to_string(&at).unwrap(), format!("{PAID_LEDGER_HEADER}\n"));
}

/// Lab #958: **the paid ledger's round trip into the payee's wallet.** A
/// real kernel-built v3 S bundle whose output 3 pays a real wallet's address
/// goes through the service's ledger path, and that wallet's import
/// (`qumbra_wallet::openings::check_ledger`) takes the row: `Imported`, its
/// `cm` the transaction's third commitment. The negative twin: the same row
/// with the witness's placeholder ρ — what the ledger wrote before #958 —
/// is refused `cm-mismatch`.
#[test]
fn a_paid_ledger_row_imports_into_the_payees_wallet_and_the_witness_rho_does_not() {
    use std::collections::HashSet;

    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    use qlab_wallet::Wallet;
    use qumbra_wallet::auth_journal::generation_root;
    use qumbra_wallet::openings::{check_ledger, LineRefusal, Verdict};

    let lanes = |l: &[u64; 4]| l.iter().map(|x| hex(&x.to_le_bytes())).collect::<String>();
    let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([0x58; ENTROPY_LEN]), qumbra_wallet::store::HD_ACCOUNT);
    let root = generation_root(&wallet, 0);
    let addr = wallet.address_candidate_a_at_index(0, &root);
    let payee = qlab_l2spend::Recipient {
        rkm: addr.rkm_lanes(),
        ek: addr.encapsulation_key().expect("a Candidate A address carries an ek"),
    };
    let b = qlab_l2spend::fixtures::signed_bundle_fee_bank_to(payee);

    let at = ledger_path("round-trip");
    let mut c = config_v3(FakeChain::new(1, &[]), ProverPrice { s: 3, p: 0 }, &at);
    c.v3.as_mut().expect("a format-34 config").payee_rkm = addr.rkm_lanes();
    let a = AnnuletApi::with_clock(c, FakeProver::new(Answer::Honest, false), Arc::<FakeNode>::default(), clock);
    wait_ready(&a);
    let (v, _) = admit_ip(&a, "192.0.2.30", &b).unwrap();
    assert_eq!(wait(&a, &v, &["submitted", "failed"]).state, "submitted");
    let ledger = std::fs::read_to_string(&at).unwrap();
    let _ = std::fs::remove_file(&at);
    let cm = b.tx().public.commitments[2];
    assert_eq!(ledger.lines().count(), 2, "{ledger}");
    assert!(ledger.lines().nth(1).unwrap().starts_with(&format!("1 cm={} value=3 ", hex(&cm))), "{ledger}");

    // The payee's wallet imports it: the note it rebuilds is the one on chain.
    let generations = [(0u32, root)];
    let (verdicts, added) = check_ledger(&ledger, &wallet, &[0], &generations, &HashSet::new()).unwrap();
    let got: Vec<Verdict> = verdicts.iter().map(|v| v.verdict.clone()).collect();
    assert_eq!(got, vec![Verdict::Imported], "{ledger}");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].cm, cm);
    assert!(b.tx().public.commitments.contains(&added[0].cm), "the row's cm is one the transaction states");
    assert_eq!((added[0].note.value, added[0].note.asset, added[0].note.rkm), (3, 0, addr.rkm_lanes()));

    // The negative twin: the witness's placeholder ρ in the same row.
    let witness_rho = b.witness().outputs[2].rho;
    assert_ne!(witness_rho, added[0].note.rho, "the witness's ρ is not the chain's");
    let placeholder = ledger.replace(
        &format!(" rho={} ", lanes(&added[0].note.rho)),
        &format!(" rho={} ", lanes(&witness_rho)),
    );
    assert_ne!(placeholder, ledger);
    let (verdicts, added) = check_ledger(&placeholder, &wallet, &[0], &generations, &HashSet::new()).unwrap();
    let got: Vec<Verdict> = verdicts.iter().map(|v| v.verdict.clone()).collect();
    assert_eq!(got, vec![Verdict::Refused(LineRefusal::CmMismatch)], "{placeholder}");
    assert!(added.is_empty());
}

/// Lab #937 PR E (pre-review): a torn last line — a crash mid-write — never
/// swallows the next entry. Reopening closes it with a newline, so the next
/// append starts its own line: the reader skips one malformed line and every
/// whole entry still parses.
#[test]
fn a_torn_ledger_line_never_swallows_the_next_entry() {
    use crate::annulet_v3::PaidEntry;
    let at = ledger_path("torn");
    drop(PaidLedger::open(&at).unwrap());
    let torn = "1 cm=00ff value=3 asse";
    let mut f = std::fs::OpenOptions::new().append(true).open(&at).unwrap();
    std::io::Write::write_all(&mut f, torn.as_bytes()).unwrap();
    drop(f);
    let ledger = PaidLedger::open(&at).unwrap();
    let out3 = qlab_air::l2::L2TxOutput { value: 7, asset: 0, rkm: PAYEE_RKM, rho: [1; 4], rseed: [2; 4] };
    let entry = PaidEntry::of(&out3, &[0xcd; 32], [0xab; 32], L2ShapeTag::P);
    ledger.append(&entry, 1_800_000_000).unwrap();
    let text = std::fs::read_to_string(&at).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines, [PAID_LEDGER_HEADER, torn, entry.line(1_800_000_000).trim_end()], "{text}");
    assert!(text.ends_with('\n'));
    // Every whole entry parses: version, then the eight fields.
    let whole: Vec<&str> = lines[1..].iter().copied().filter(|l| l.split(' ').count() == 9).collect();
    assert_eq!(whole.len(), 1);
    assert!(whole[0].starts_with(&format!("1 cm={} value=7 asset=0 ", hex(&[0xab; 32]))));
    assert!(whole[0].ends_with("shape=P at=1800000000"));
    // A clean ledger is left as it is on reopen.
    drop(PaidLedger::open(&at).unwrap());
    assert_eq!(std::fs::read_to_string(&at).unwrap(), text);
    let _ = std::fs::remove_file(&at);
}
