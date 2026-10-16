//! Lab #937 cut-over (D-C7, D-C8): **a remote-proved send on format 34**,
//! end to end through `send_annulet_remote` against the fixture chain and a
//! scripted prover service. Nothing proves: the service is a script that
//! runs the bundle's own lock (`ProvingBundle::check`, the prover's), checks
//! output 3 pays it, and answers like the real one. The wallet never POSTs
//! a transaction to the node — the service submits.

#[path = "common/mod.rs"]
mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use common::*;
use qlab_devnet::annulet::AuthContext;
use qlab_l2spend::bundle::ProvingBundle;
use qumbra_wallet::annulet_send::{send_annulet_remote, RemoteHooks};
use qumbra_wallet::auth_journal::{generation_root, AuthJournal};
use qumbra_wallet::remote_prover::{Event, ProverTransport, RECORD_DIR};
use rand::rngs::StdRng;
use rand::SeedableRng;

const SEED: u8 = 0x6A;
const RECIPIENT: u8 = 0x6B;
const PROVER: u8 = 0x6C;
const CAP: &str = "/v2/annulet/jobs/00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const TX: &str = "cd00000000000000000000000000000000000000000000000000000000000000";

/// The fixture chain as the wallet's endpoint: reads answered, and any POST
/// is a failure — on format 34 the service submits, never the wallet.
struct Fx<'a>(&'a Endpoint);

impl qlab_l2spend::Endpoint for Fx<'_> {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        self.0.fetch(path)
    }
    fn post(&self, path: &str, _body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        panic!("the wallet POSTed {path} itself: a remote-proved send never submits");
    }
}

fn v2(seed: u8, tag: &str) -> qlab_wallet::address::Address {
    let d = wallet_dir(tag, seed);
    let w = d.wallet();
    let a = w.address_candidate_a_at_index(0, &generation_root(&w, 0));
    let _ = std::fs::remove_dir_all(&d.dir);
    a
}

/// The scripted service: `/info` with `payee` at S 1 / P 2, then each POST
/// and GET answered from `answers` in order. Every POSTed body is kept and
/// run through the prover's own lock on `genesis`'s format-34 net.
struct Service {
    info: Vec<u8>,
    genesis: [u8; 32],
    answers: VecDeque<(u16, String)>,
    posted: RefCell<Vec<Vec<u8>>>,
}

impl ProverTransport for Service {
    fn call(&mut self, method: &str, path: &str, body: Option<&[u8]>, _max: usize) -> Result<(u16, Vec<u8>), String> {
        if (method, path) == ("GET", "/v2/annulet/info") {
            return Ok((200, self.info.clone()));
        }
        if method == "POST" {
            assert_eq!(path, "/v2/annulet/jobs");
            let bytes = body.expect("a bundle").to_vec();
            let b = ProvingBundle::decode(&bytes).expect("a bundle");
            b.check(&AuthContext::candidate_a_v3(self.genesis)).expect("the prover's own lock accepts it");
            assert!(b.tx().proof.is_empty(), "the wallet never proves a remote-proved step");
            self.posted.borrow_mut().push(bytes);
        } else {
            assert_eq!((method, path), ("GET", CAP), "a job is read by its capability");
        }
        let (status, body) = self.answers.pop_front().expect("the script has an answer");
        Ok((status, body.into_bytes()))
    }
}

fn view(state: &str, tx: Option<&str>) -> String {
    let tx = tx.map(|t| format!(r#","tx_id":"{t}""#)).unwrap_or_default();
    format!(r#"{{"protocol_version":1,"job_url":"{CAP}","state":"{state}"{tx}}}"#)
}

struct Setup {
    w: qumbra_wallet::store::WalletDir,
    ep: Endpoint,
    to: qlab_wallet::address::Address,
    prover: qlab_wallet::address::Address,
}

/// A format-34 chain paying `W`'s v2 address 0 one asset-0 note of 50, its
/// prover pinned (fixture pins) to `P` at most S 2 / P 4.
fn setup(tag: &str) -> Setup {
    let w = wallet_dir(tag, SEED);
    let wallet = w.wallet();
    let root = generation_root(&wallet, 0);
    AuthJournal::fresh(root).save(&w.dir).unwrap();
    let a2 = wallet.address_candidate_a_at_index(0, &root);
    let file = genesis_v3(&a2, vec![note_to(&a2, 50, 0, 30)]);
    let prover = v2(PROVER, &format!("{tag}_prover"));
    qumbra_wallet::prover_pins::pin_fixture(
        file.hash(),
        qumbra_wallet::prover_pins::ProverPin {
            payee: prover.encode(),
            max_price: qumbra_wallet::annulet_plan::ProverPrice { s: 2, p: 4 },
        },
    );
    let ep = Endpoint::new(file, &[], None, Lie::None);
    Setup { w, ep, to: v2(RECIPIENT, &format!("{tag}_to")), prover }
}

fn info(genesis: &[u8; 32], payee: &str) -> Vec<u8> {
    let hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
    format!(r#"{{"protocol_version":1,"genesis_format":34,"genesis_hash":"{hex}","fee_asset":0,"price":{{"S":1,"P":2}},"payee":"{payee}","slot_secs":10}}"#)
        .into_bytes()
}

fn next_of(w: &qumbra_wallet::store::WalletDir) -> u32 {
    AuthJournal::load(&w.dir).unwrap().unwrap().active().next
}

type Sent = Result<qumbra_wallet::annulet_send::RemoteSendReport, String>;
type Ran = (Sent, Vec<(usize, Event)>, Vec<u64>);

fn run(s: &Setup, svc: &mut Service) -> Ran {
    let (r, events, shown, _) = run_reviewed(s, svc, true);
    (r, events, shown)
}

type Reviews = Vec<(usize, Result<String, String>, Vec<qlab_note::l2note::L2Note>)>;

/// [`run`], every step's review (rendered by the kernel) kept, each answered
/// `approve`.
fn run_reviewed(
    s: &Setup,
    svc: &mut Service,
    approve: bool,
) -> (Sent, Vec<(usize, Event)>, Vec<u64>, Reviews) {
    let mut rng = StdRng::seed_from_u64(0x937c);
    let mut events = Vec::new();
    let mut shown = Vec::new();
    let mut reviews = Vec::new();
    let r = send_annulet_remote(
        &s.w,
        Fx(&s.ep),
        0,
        10,
        &s.to,
        u64::MAX,
        s.ep.file.hash(),
        &[],
        Duration::from_secs(1),
        RemoteHooks {
            transport: svc,
            sleep: &mut |_| {},
            events: &mut |i, e| events.push((i, e)),
            review: &mut |i, r| {
                // The text is the kernel's renderer over the very bytes the
                // step signs; any other bytes are refused by it.
                assert_eq!(r.signing, r.intent.encode().unwrap(), "the signing bytes are the intent's");
                let direct = qumbra_wallet::annulet_review::render(&r.review, &r.intent, &r.signing, &r.signing, &r.outputs);
                assert_eq!(r.render(), direct);
                let mut other = r.signing.clone();
                other[0] ^= 1;
                assert!(qumbra_wallet::annulet_review::render(&r.review, &r.intent, &r.signing, &other, &r.outputs).is_err());
                reviews.push((i, r.render(), r.outputs.clone()));
                approve
            },
            list: None,
        },
        &mut |plan, p| {
            shown.push(p.price.s);
            shown.push(plan.prover_fees());
            true
        },
        &mut rng,
    )
    .map_err(|e| e.to_string());
    (r, events, shown, reviews)
}

/// D-C7: the admitted price is planned and shown before anything is taken;
/// the one S step pays the prover its 1 in output 3; the signed bundle is
/// recorded before its upload; a not-now answer re-sends the same bytes; the
/// service's submission is the send's result.
#[test]
fn a_remote_proved_send_pays_its_prover_and_the_service_submits() {
    let s = setup("rs_ok");
    let genesis = s.ep.file.hash();
    let mut svc = Service {
        info: info(&genesis, &s.prover.encode()),
        genesis,
        answers: VecDeque::from([
            (503, r#"{"error":"prover-busy"}"#.to_string()),
            (202, view("queued", None)),
            (200, view("proving", None)),
            (200, view("submitted", Some(TX))),
        ]),
        posted: RefCell::new(Vec::new()),
    };
    let (r, events, shown) = run(&s, &mut svc);
    let report = r.expect("submitted");
    assert_eq!(shown, vec![1, 1], "the admitted S price and the plan's prover fees, shown before the take");
    assert_eq!(report.tx_ids.len(), 1);
    assert_eq!(report.tx_ids[0][0], 0xcd);
    assert_eq!(report.plan.steps.len(), 1);
    let posted = svc.posted.borrow();
    assert_eq!(posted.len(), 2, "not now, then the same bundle again");
    assert_eq!(posted[0], posted[1], "byte-identical");
    let b = ProvingBundle::decode(&posted[0]).unwrap();
    let o3 = &b.witness().outputs[2];
    assert_eq!((o3.value, o3.asset, o3.rkm), (1, 0, s.prover.rkm_lanes()), "output 3 pays the prover its S price");
    assert_eq!(report.outputs[0].value, 10);
    assert_eq!(report.outputs[1].value, 50 - 10 - 1 - 1, "change: the amount, the S tier and the S price paid");
    // Recorded before the upload, kept after it, its end noted beside it.
    let nf: String = b.tx().public.nullifiers[0].iter().map(|x| format!("{x:02x}")).collect();
    let rec = s.w.dir.join(RECORD_DIR).join(format!("{nf}.bundle"));
    assert_eq!(std::fs::read(&rec).unwrap(), posted[0]);
    assert!(std::fs::read_to_string(rec.with_extension("outcome")).unwrap().starts_with("submitted cd00"));
    assert!(events.iter().any(|(i, e)| *i == 0 && matches!(e, Event::NotNow { status: 503, .. })));
    assert_eq!(next_of(&s.w), 1, "one leaf taken");
    let _ = std::fs::remove_dir_all(&s.w.dir);
}

/// D-C8: a definitive refusal ends the send — the take stands (the journal
/// never rolls back), the record stays with its outcome.
#[test]
fn a_definitive_refusal_fails_the_send_and_keeps_the_take() {
    let s = setup("rs_402");
    let genesis = s.ep.file.hash();
    let mut svc = Service {
        info: info(&genesis, &s.prover.encode()),
        genesis,
        answers: VecDeque::from([(402, r#"{"error":"prover-fee-short"}"#.to_string())]),
        posted: RefCell::new(Vec::new()),
    };
    let (r, ..) = run(&s, &mut svc);
    let why = r.err().expect("refused");
    assert!(why.contains("HTTP 402 prover-fee-short"), "{why}");
    assert_eq!(next_of(&s.w), 1, "the leaf stays used");
    let dir = s.w.dir.join(RECORD_DIR);
    let outcomes: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "outcome").then(|| std::fs::read_to_string(p).unwrap())
        })
        .collect();
    assert_eq!(outcomes, vec!["failed 402 prover-fee-short\n".to_string()]);
    let _ = std::fs::remove_dir_all(&s.w.dir);
}

/// A service whose payee is not the pin is refused by name before anything
/// is planned, taken, recorded or uploaded.
#[test]
fn a_service_that_is_not_the_pin_is_refused_before_the_take() {
    let s = setup("rs_payee");
    let genesis = s.ep.file.hash();
    let mut svc = Service {
        info: info(&genesis, &s.to.encode()),
        genesis,
        answers: VecDeque::new(),
        posted: RefCell::new(Vec::new()),
    };
    let (r, events, shown) = run(&s, &mut svc);
    let why = r.err().expect("refused");
    assert!(why.contains("not this network's pinned payee"), "{why}");
    assert!(shown.is_empty() && events.is_empty() && svc.posted.borrow().is_empty());
    assert_eq!(next_of(&s.w), 0, "nothing taken");
    assert!(!s.w.dir.join(RECORD_DIR).exists(), "nothing recorded");
    let _ = std::fs::remove_dir_all(&s.w.dir);
}

/// Lab #937 cut-over (M1(b)): each step's review is the kernel's, rendered
/// from the intent the step then signs — before it is signed. Approved: the
/// text names the payment, the prover's fee at its price and the step; the
/// review's bytes are the intent's encoding, and the uploaded bundle carries
/// exactly the outputs the review was rendered from.
#[test]
fn each_step_is_reviewed_before_it_is_signed_and_the_review_is_the_kernels() {
    let s = setup("rs_review");
    let genesis = s.ep.file.hash();
    let mut svc = Service {
        info: info(&genesis, &s.prover.encode()),
        genesis,
        answers: VecDeque::from([(202, view("queued", None)), (200, view("submitted", Some(TX)))]),
        posted: RefCell::new(Vec::new()),
    };
    let (r, _, _, reviews) = run_reviewed(&s, &mut svc, true);
    r.expect("submitted");
    assert_eq!(reviews.len(), 1, "one step, one review");
    let (i, text, outputs) = &reviews[0];
    assert_eq!(*i, 0);
    let text = text.as_ref().expect("the review renders");
    assert!(text.contains("step 1 of 1: the payment"), "{text}");
    assert!(text.contains(&format!("prover fee: 1 fee unit to {}", s.prover.short().encode())), "{text}");
    assert!(text.contains("send 10 fee units to "), "{text}");
    assert!(text.lines().next().unwrap().starts_with("asset list: none"), "no list was given: {text}");
    let posted = svc.posted.borrow();
    let b = ProvingBundle::decode(&posted[0]).unwrap();
    let sent: Vec<_> = b.witness().outputs.iter().map(|o| (o.value, o.asset, o.rkm)).collect();
    let reviewed: Vec<_> = outputs.iter().map(|o| (o.value, o.asset, o.rkm)).collect();
    assert_eq!(sent, reviewed, "the bundle carries the outputs the review was rendered from");
    let _ = std::fs::remove_dir_all(&s.w.dir);
}

/// A review the shell refuses refuses the step by name: nothing is signed,
/// recorded or uploaded (no POST reaches the service, no record file), and
/// the leaves the step took stay used.
#[test]
fn a_refused_review_signs_records_and_uploads_nothing() {
    let s = setup("rs_review_no");
    let genesis = s.ep.file.hash();
    let mut svc = Service {
        info: info(&genesis, &s.prover.encode()),
        genesis,
        answers: VecDeque::new(),
        posted: RefCell::new(Vec::new()),
    };
    let (r, events, _, reviews) = run_reviewed(&s, &mut svc, false);
    let why = r.err().expect("refused");
    assert!(why.contains("step 1 of 1 refused at review"), "{why}");
    assert_eq!(reviews.len(), 1, "the review was shown");
    assert!(svc.posted.borrow().is_empty(), "nothing uploaded");
    assert!(events.is_empty(), "no upload was begun");
    let dir = s.w.dir.join(RECORD_DIR);
    assert!(!dir.exists() || std::fs::read_dir(&dir).unwrap().next().is_none(), "nothing recorded");
    assert_eq!(next_of(&s.w), 1, "the leaf the step took stays used");
    let _ = std::fs::remove_dir_all(&s.w.dir);
}
