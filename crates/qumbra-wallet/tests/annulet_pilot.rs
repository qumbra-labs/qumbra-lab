//! **L2-E1 — the stablecoin pilot on Phase 0** (lab #740): the whole issuer
//! lifecycle, end to end, on the three-node Annulet harness under the real
//! `L2Verifier`, through the wallet's own verbs — with every node's
//! `/v1/attest` (the explorer's own code) and supply ledger agreeing with the
//! expected outstanding figure after **every** step.
//!
//! A Phase-0 stablecoin pilot is **a sidechain that reads L1 anchors**
//! (l2-own-circuit-decision §4): a single sequencer, the L2 circuit family,
//! the registry, no bridge and no QMB on L2. Here the L1 anchor fields are
//! genesis-static; no live L1 is read.
//!
//! The asset is `pUSD-test` (asset id 21): a **test** instrument with a
//! **simulated** issuer and a **simulated** order — no real issuer, regulator
//! or currency is represented. Hybrid, runtime freeze, redeem closed
//! (issuer-mediated).
//!
//! - step 1: register `pUSD-test` at runtime (R)
//! - steps 2–4: mint 3 × 200 → A on the seed (3 P)
//! - step 5: mint 150 → F (P)
//! - step 6: A pays B 500 with a merge: 200+200, then 400+200 (2 P, d3 = 0)
//! - step 7: B pays A 100 with fee-split-and-pay (S + P)
//! - step 8: freeze F on a simulated order (R)
//! - step 9: F refused — by the wallet before proving, and a hand-forged spend
//!   under the pre-freeze leaf refused by the node (1 P proved, not admitted)
//! - steps 10–11: redeem on request: A → I 150 (P), then I redeems 150 (P)
//!
//! 2 R + 11 P + 1 S proves. Too heavy for the suite's 100-min target, so it
//! runs as its own named job (`verify-pilot`) behind the `pilot` feature —
//! not `#[ignore]`: the prefilter compiles it on every PR.
//!
//! **Evidence.** With `PILOT_EVIDENCE_OUT=<file>` set, one JSON object per
//! step is appended (JSON lines): the CLI-equivalent command, the sequencer
//! height, every node's attested outstanding figure, and per transaction the
//! proof / wire / discovery bytes and a **test-process** verify time
//! (`L2Verifier::check` re-run here, not the sequencer's admission path).
//! `scripts/annulet-pilot-render.py` renders the evidence pack from it.

use std::collections::HashSet;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_air::l2::{L2TxInput, RegistryLeaf, MODE_HYBRID};
use qlab_air::l2p::{dummy_allow_witness, freeze_key_of, CanonicalFreezeTree, L2PolicyInput, VPublic};
use qlab_devnet::body::TxEntry;
use qlab_l2spend::{prove_p_with_policies, Out, Recipient, SpendError};
use qlab_note::l2note::L2Note;
use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
use qumbra_faucet::annulet::served;
use qumbra_faucet::devnet_harness::{Net, Probe, View};
use qumbra_node::annulet_genesis::{devnet, AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord};
use qumbra_wallet::annulet_send::{open_session, send_annulet, SendPlan, SendRefusal, WalletEndpoint};
use qumbra_wallet::issuer::{issuer_mint, issuer_register, issuer_update, redeem, LeafPolicy};
use qumbra_wallet::store::WalletDir;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// `pUSD-test` — the pilot asset's registry index (Larry's default, lab #740).
const PUSD: u16 = 21;
const TIERS: AnnuletParams = AnnuletParams { fee_tier_s: 1, fee_tier_p: 2, fee_tier_r: 4, slot_secs: 10, max_empty_slots: 6 };

fn wallet(tag: &str, seed: u8) -> WalletDir {
    let dir = std::env::temp_dir().join(format!("qmb_e1_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
}

fn rkm0(w: &WalletDir) -> [u64; 4] {
    w.wallet().address_at_index(0).rkm_lanes()
}

fn note(w: &WalletDir, value: u64, asset: u64, k: u64) -> L2Note {
    L2Note { value, asset, rkm: rkm0(w), rho: [0xE1, k, 1, 2], rseed: [0xE1, k, 3, 4] }
}

fn recipient(w: &WalletDir) -> Recipient {
    Recipient { rkm: rkm0(w), ek: w.wallet().address_at_index(0).encapsulation_key().unwrap() }
}

/// Every transaction any node has applied, deduplicated by tx id — collected
/// by the harness probe from the node's main chain, so the test sees exactly
/// what was sealed.
#[derive(Default)]
struct Sealed {
    seen: HashSet<[u8; 32]>,
    txs: Vec<(u64, [u8; 32], TxEntry)>,
}

fn tx_id(t: &TxEntry) -> [u8; 32] {
    let p = &t.public;
    qlab_node::rpc::tx_id(&p.anchor, &p.nullifiers, &p.commitments, p.bucket.logical_actions(), p.fee)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The evidence writer: JSON lines to `PILOT_EVIDENCE_OUT`, or nothing.
struct Evidence {
    out: Option<std::fs::File>,
    reported: usize,
    since: Instant,
}

impl Evidence {
    fn open() -> Self {
        let out = std::env::var_os("PILOT_EVIDENCE_OUT").map(|p| {
            std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(p).expect("PILOT_EVIDENCE_OUT is writable")
        });
        Evidence { out, reported: 0, since: Instant::now() }
    }
    fn write(&mut self, v: serde_json::Value) {
        if let Some(f) = self.out.as_mut() {
            writeln!(f, "{v}").expect("evidence line");
        }
    }
}

#[test]
fn the_pusd_test_pilot_runs_end_to_end_with_the_attestation_agreeing_at_every_step() {
    let (issuer, a, b, f) = (wallet("issuer", 0x71), wallet("a", 0x72), wallet("b", 0x73), wallet("f", 0x74));
    // Genesis: asset 0 only. Exact P-tariff notes for every P fee the plan
    // pays (so no fee-split happens except step 7's), a change-bearing note
    // for the issuer's two R writes, and a non-exact note for B.
    let mut notes = vec![note(&issuer, 10, 0, 1)];
    notes.extend((0..5).map(|k| note(&issuer, 2, 0, 10 + k))); // 4 mints + the redeem
    notes.extend((0..3).map(|k| note(&a, 2, 0, 20 + k))); // merge, pay, A → I
    notes.push(note(&b, 7, 0, 30)); // 7 = 2 + 4 + the S tier: step 7 splits it
    notes.push(note(&f, 2, 0, 40)); // the forged spend's fee input
    let g = AnnuletGenesisFile::assemble(
        "annulet-e1-pilot",
        TIERS,
        devnet::SEQUENCER_SEED,
        vec![RegistryLeafRecord::asset_zero()],
        notes.iter().map(GenesisNoteRecord::of).collect(),
        0,
    );
    let issuance = qlab_node::asset_supply::genesis_issuance(&g.notes()).unwrap();
    let sealed: Arc<Mutex<Sealed>> = Arc::default();
    let sealed2 = sealed.clone();
    let probe: Probe = Arc::new(move |n: &qlab_node::MemNode| {
        let mut s = sealed2.lock().unwrap();
        for blk in qlab_node::rpc::main_chain_of(n) {
            let h = blk.header.height;
            for t in blk.body().txs {
                let id = tx_id(&t);
                if s.seen.insert(id) {
                    s.txs.push((h, id, t));
                }
            }
        }
        qumbra_explorer::attest::attest_document(n, &issuance)
    });
    let net = Net::start_probed(&g, "e1", Some(probe));
    net.wait_connected();
    let pin = Some(g.hash());
    let urls: Vec<String> = net.served.iter().map(|u| format!("http://{u}")).collect();
    let at = |i: usize| WalletEndpoint { url: urls[i].clone() };
    let wait = Duration::from_secs(60);
    let mut rng = StdRng::seed_from_u64(740);
    let mut ev = Evidence::open();

    let supply = |v: &View| v.supplies.iter().find(|(x, _)| *x == PUSD).map_or(0, |(_, s)| *s);
    // One step's record: every node's /v1/attest agrees with that node and
    // states `expect`; the node ledgers state it too; the transactions sealed
    // since the last record are measured and written out.
    let record = |ev: &mut Evidence, n: usize, what: &str, cmd: &str, v: &[View; 3], expect: i128| {
        let docs: Vec<serde_json::Value> =
            net.probes().iter().map(|d| serde_json::from_str(d).expect("/v1/attest is JSON")).collect();
        let mut attested = Vec::new();
        for (i, d) in docs.iter().enumerate() {
            assert_eq!(d["node_agrees"], true, "step {n} ({what}): node {i}'s /v1/attest disagrees: {}", d["node_divergences"]);
            let out = d["assets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["asset"] == PUSD)
                .map_or("0".to_string(), |r| r["outstanding"].as_str().unwrap().to_string());
            assert_eq!(out, expect.to_string(), "step {n} ({what}): node {i} attests {out}, expected {expect}");
            attested.push(out);
        }
        for (i, x) in v.iter().enumerate() {
            assert_eq!(supply(x), expect, "step {n} ({what}): node {i}'s supply ledger");
        }
        let s = sealed.lock().unwrap();
        let mut txs = Vec::new();
        for (h, id, t) in &s.txs[ev.reported..] {
            let t0 = Instant::now();
            let ok = qumbra_node::verifier::L2Verifier.check(t).is_ok();
            let verify_ms = t0.elapsed().as_secs_f64() * 1e3;
            assert!(ok, "step {n} ({what}): a sealed transaction re-verifies");
            let shape = qlab_devnet::annulet::L2Surface::decode(&t.l2).ok().flatten().map(|x| format!("{:?}", x.shape));
            txs.push(serde_json::json!({
                "height": h,
                "tx_id": hex(id),
                "shape": shape,
                "nullifiers": t.public.nullifiers.len(),
                "fee": t.public.fee,
                "proof_bytes": t.proof.len(),
                "discovery_bytes": t.discovery.len(),
                "wire_bytes": qlab_p2p::codec::encode_tx_annulet(t).len(),
                "verify_ms_test_process": (verify_ms * 100.0).round() / 100.0,
            }));
        }
        let reported_now = s.txs.len();
        drop(s);
        ev.reported = reported_now;
        // Wall time since the previous record: the step's proves, submits and
        // settle waits together, on the lane's clock (test process).
        let step_wall_ms = ev.since.elapsed().as_millis();
        eprintln!("PILOT step {n} ({what}): {} tx, wall {:.1} s", txs.len(), step_wall_ms as f64 / 1e3);
        ev.write(serde_json::json!({
            "step": n,
            "what": what,
            "command": cmd,
            "height": v[0].state_tip,
            "nullifiers": v[0].nullifiers,
            "attested_outstanding": attested,
            "expected_outstanding": expect.to_string(),
            "step_wall_ms": step_wall_ms,
            "txs": txs,
        }));
        ev.since = Instant::now();
    };

    // 0. Genesis.
    let v = net.settle_spends(0, "genesis");
    record(&mut ev, 0, "genesis", "(genesis: asset 0 only)", &v, 0);

    // 1. Register pUSD-test at runtime: Hybrid, empty freeze tree, redeem closed.
    let hybrid = LeafPolicy { mode: Some(MODE_HYBRID), redeem_open: Some(false), ..Default::default() };
    let t_r = Instant::now();
    let reg = issuer_register(&issuer, at(0), PUSD, &hybrid, v[0].state_tip, pin, &mut rng).expect("registers pUSD-test");
    let r1_ms = t_r.elapsed().as_millis();
    eprintln!("PILOT R prove+submit (register): {:.1} s", r1_ms as f64 / 1e3);
    assert_eq!((reg.seed.asset, reg.seed.value), (u64::from(PUSD), 0), "the R seed: a 0-value note of the asset");
    let v = net.settle_spends(1, "register");
    record(&mut ev, 1, "register pUSD-test (Hybrid, redeem closed)", "qumbra-wallet issuer register --asset 21 --mode hybrid --net annulet", &v, 0);

    // 2–5. Mint 3 × 200 → A, then 150 → F — each on the issuer's re-armed seed.
    let to_a = a.wallet().address_at_index(0);
    let to_f = f.wallet().address_at_index(0);
    let mut expect: i128 = 0;
    let mut nf = 1;
    for (n, (to, amt, who)) in [(&to_a, 200u64, "A"), (&to_a, 200, "A"), (&to_a, 200, "A"), (&to_f, 150, "F")].into_iter().enumerate() {
        let tip = net.views()[1].state_tip;
        let m = issuer_mint(&issuer, at(1), PUSD, amt, to, &[], tip, pin, wait, &mut rng).expect("the issuer mints on the seed");
        assert!(m.split_fee_note.is_none(), "an exact P note was held");
        assert!(m.rearmed, "every mint re-arms the issuer");
        expect += i128::from(amt);
        nf += 3;
        let v = net.settle_spends(nf, "mint");
        record(
            &mut ev,
            2 + n,
            &format!("mint {amt} → {who}"),
            &format!("qumbra-wallet issuer mint --asset 21 --amount {amt} --to <{who}> --net annulet"),
            &v,
            expect,
        );
    }

    // 6. A pays B 500 — no single note covers: the planner merges, then pays.
    let to_b = b.wallet().address_at_index(0);
    let mut shown: Option<SendPlan> = None;
    let tip = net.views()[2].state_tip;
    let rep = send_annulet(&a, at(2), PUSD, 500, &to_b, tip, pin, &[], wait, &mut |p: &SendPlan| {
        eprintln!("{p}");
        shown = Some(p.clone());
        true
    }, &mut rng)
    .expect("A pays B 500 after a merge");
    let plan = shown.expect("the plan is shown before proving");
    assert_eq!((plan.merges(), plan.splits(), plan.steps.len()), (1, 0, 2), "{plan}");
    assert_eq!(rep.outputs[0].value, 500);
    nf += 6;
    let v = net.settle_spends(nf, "A → B 500");
    record(&mut ev, 6, "A pays B 500 (merge 200+200, then pay 400+200)", "qumbra-wallet send --net annulet --asset 21 --amount 500 --to <B>", &v, expect);

    // 7. B pays A 100 — B holds no exact P note: fee-split (S), then pay (P).
    let tip = net.views()[0].state_tip;
    let rep = send_annulet(&b, at(0), PUSD, 100, &to_a, tip, pin, &[], wait, &mut |p: &SendPlan| {
        eprintln!("{p}");
        true
    }, &mut rng)
    .expect("B pays A 100 with a fee-split");
    assert_eq!((rep.plan.splits(), rep.plan.merges()), (1, 0), "{}", rep.plan);
    nf += 6;
    let v = net.settle_spends(nf, "B → A 100");
    record(&mut ev, 7, "B pays A 100 (fee-split, then pay)", "qumbra-wallet send --net annulet --asset 21 --amount 100 --to <A>", &v, expect);

    // 8. Freeze F on a simulated order: the issuer publishes F's freeze key.
    let keys = vec![freeze_key_of(&rkm0(&f))];
    let freeze = LeafPolicy { freeze_keys: Some(keys.clone()), ..Default::default() };
    let tip = net.views()[1].state_tip;
    let t_r = Instant::now();
    issuer_update(&issuer, at(1), PUSD, &freeze, false, tip, pin, &mut rng).expect("publishes the freeze root");
    let r2_ms = t_r.elapsed().as_millis();
    eprintln!("PILOT R prove+submit (freeze): {:.1} s", r2_ms as f64 / 1e3);
    nf += 1;
    let v = net.settle_spends(nf, "freeze F");
    record(&mut ev, 8, "freeze F (simulated order)", "qumbra-wallet issuer freeze --asset 21 --add <F> --net annulet", &v, expect);

    // 9. F is refused — by the wallet, before anything is proved…
    let tip = net.views()[2].state_tip;
    let refused = send_annulet(&f, at(2), PUSD, 50, &to_a, tip, pin, &keys, wait, &mut |_| true, &mut rng);
    assert!(
        matches!(refused, Err(SendRefusal::Spend(SpendError::Frozen { asset })) if asset == u64::from(PUSD)),
        "the wallet refuses a frozen holder: {:?}",
        refused.err()
    );
    // …and a spend F hand-forges under the PRE-freeze leaf (an empty freeze
    // tree) proves, but binds a registry root no node holds: the node refuses.
    let seq = served(net.served[0]);
    let real = seq.registry(u64::from(PUSD)).unwrap();
    let forged_leaf = RegistryLeaf { freeze_root: CanonicalFreezeTree::empty().root, ..real.leaf };
    let forged_root = real.witness.fold_root(&forged_leaf.hash());
    let zero = seq.registry(0).unwrap();
    let fs = open_session(&f, at(0), tip, pin, &mut rng).expect("F scans");
    let f_pusd = fs.index.spendable(PUSD)[0].clone();
    let f_fee = fs.index.spendable(0).iter().find(|n| n.note.value == 2).expect("F's fee note").clone();
    let fw = f.wallet();
    let input = |n: &L2Note| {
        let l1 = fw.spend_input(n.value, n.rho, n.rseed, fw.diversifier_at_index(0));
        L2TxInput { sk: l1.sk, value: n.value, asset: n.asset, rho: n.rho, rseed: n.rseed, d: l1.d }
    };
    let empty = CanonicalFreezeTree::empty();
    let policy = [
        L2PolicyInput {
            leaf: forged_leaf,
            reg_witness: real.witness,
            freeze: empty.opening_for(&rkm0(&f)).unwrap(),
            allow: dummy_allow_witness(),
            isk: [0; 4],
        },
        L2PolicyInput {
            leaf: zero.leaf,
            reg_witness: zero.witness,
            freeze: empty.opening_for(&rkm0(&f)).unwrap(),
            allow: dummy_allow_witness(),
            isk: [0; 4],
        },
    ];
    let forged = prove_p_with_policies(
        &seq.commitment_tree().unwrap(),
        [&input(&f_pusd.note), &input(&f_fee.note)],
        &[Out { to: recipient(&a), value: 50, asset: u64::from(PUSD) }, Out { to: recipient(&f), value: 100, asset: u64::from(PUSD) }],
        2,
        policy,
        forged_root,
        [VPublic::NONE; 2],
        &mut rng,
    )
    .expect("the forged instance proves: the AIR checks paths, the node checks roots");
    let verdict = seq.submit(&forged.tx);
    let node_refusal = match &verdict {
        Err(SpendError::Refused(why)) => why.clone(),
        other => panic!("the node must refuse a spend under a stale leaf: {other:?}"),
    };
    eprintln!("PILOT node refusal: {node_refusal}");
    std::thread::sleep(Duration::from_secs(2));
    let v = net.settle_spends(nf, "nothing moved");
    record(&mut ev, 9, "F refused (wallet: Frozen before proving; node: stale-leaf spend refused)", "qumbra-wallet send --net annulet --asset 21 --amount 50 --to <A> --freeze-list <published>", &v, expect);
    ev.write(serde_json::json!({ "step": 9, "node_refusal": node_refusal, "wallet_refusal": "Frozen" }));

    // 10. Redeem on request: A sends 150 to the issuer, who burns it.
    let to_i = issuer.wallet().address_at_index(0);
    let tip = net.views()[2].state_tip;
    send_annulet(&a, at(2), PUSD, 150, &to_i, tip, pin, &keys, wait, &mut |_| true, &mut rng).expect("A sends 150 to the issuer");
    nf += 3;
    let v = net.settle_spends(nf, "A → I 150");
    record(&mut ev, 10, "A sends 150 to the issuer (redeem request)", "qumbra-wallet send --net annulet --asset 21 --amount 150 --to <issuer> --freeze-list <published>", &v, expect);
    let tip = net.views()[0].state_tip;
    redeem(&issuer, at(0), PUSD, 150, &keys, tip, pin, wait, &mut rng).expect("the issuer redeems 150");
    expect -= 150;
    nf += 3;
    let v = net.settle_spends(nf, "redeem 150");
    record(&mut ev, 11, "the issuer redeems 150", "qumbra-wallet issuer redeem --asset 21 --amount 150 --freeze-list <published> --net annulet", &v, expect);

    // The final ledger, per holder: A 200 + 200 − 500 + 100 − 150 … counted
    // from the notes each wallet actually holds.
    assert_eq!(expect, 600);
    let held = |w: &WalletDir| -> u128 {
        let s = open_session(w, at(1), net.views()[1].state_tip, pin, &mut StdRng::seed_from_u64(1)).expect("scan");
        s.index.spendable(PUSD).iter().map(|n| u128::from(n.note.value)).sum()
    };
    let (ha, hb, hf, hi) = (held(&a), held(&b), held(&f), held(&issuer));
    assert_eq!((ha, hb, hf, hi), (50, 400, 150, 0), "A 600−500+100−150, B 500−100, F frozen 150, the issuer burned what it got");
    assert_eq!(ha + hb + hf + hi, 600, "held = outstanding");
    ev.write(serde_json::json!({ "r_prove_submit_ms": [r1_ms, r2_ms] }));
    ev.write(serde_json::json!({ "final": { "A": ha.to_string(), "B": hb.to_string(), "F_frozen": hf.to_string(), "issuer": hi.to_string(), "outstanding": "600" } }));

    for d in [&issuer.dir, &a.dir, &b.dir, &f.dir] {
        let _ = std::fs::remove_dir_all(d);
    }
}
