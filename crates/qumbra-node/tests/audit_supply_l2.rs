//! `qumbra-node audit-supply-l2` (lab #726, L2-D1) over a real on-disk
//! Annulet chain: a mock-proved chain of mints and a redeem is written through
//! the node's own `apply_sealed_block`, then audited from the data dir alone —
//! the figures, a claim that reproduces (exit 0), a **tampered claim caught by
//! name** (exit 1), and the cannot-run paths (exit 2).

use qlab_devnet::annulet::{
    body_commitment_annulet, AnnuletHeaderFields, L2ShapeTag, L2Surface, SequencerKey, VPublicTerm,
};
use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::header::BlockHeader;
use qlab_node::asset_supply::{AttestDocument, LABEL};
use qlab_node::{MemNode, NodeState};
use qumbra_node::annulet_genesis::{registry_leaves, AnnuletGenesisFile};
use qumbra_node::audit_supply_l2::{
    audit_supply_l2, audit_with_claim, EXIT_CANNOT_RUN, EXIT_CLEAN, EXIT_DIVERGENT,
};

/// The mock proof verifier (the node's own tests use the same one; the
/// supply fold never reads a proof).
struct OkProof;
impl TxVerifier for OkProof {
    fn verify_tx(&self, e: &TxEntry) -> bool {
        e.proof == b"ok"
    }
}

fn ext(g: &AnnuletGenesisFile) -> AnnuletHeaderFields {
    let h = &g.genesis_header;
    AnnuletHeaderFields {
        l1_anchor_height: h.l1_anchor_height,
        l1_anchor_root: h.l1_anchor_root,
        registry_root: h.registry_root,
    }
}

/// A P transaction carrying `terms`, mock-proved, at the P tier.
fn p_tx(n: &MemNode, g: &AnnuletGenesisFile, nf: u8, terms: [VPublicTerm; 2]) -> TxEntry {
    let mut t = TxEntry {
        proof: b"ok".to_vec(),
        public: TxPublic {
            anchor: n.commitment_root(),
            nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32]],
            commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: g.params.fee_tier_p,
        },
        discovery: Vec::new(),
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: L2Surface { shape: L2ShapeTag::P, registry_root: g.genesis_header.registry_root, vpublic: Some(terms), write: None }
            .encode(),
    };
    t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
    t
}

fn term(redeem: bool, amount: u64, asset: u16) -> [VPublicTerm; 2] {
    [VPublicTerm::NONE, VPublicTerm { redeem, amount, asset }]
}

/// A data dir holding: h1 mint 1,000 of asset 7; h2 mint 250 of asset 7;
/// h3 redeem 400 of asset 7. Outstanding 850.
fn chain_dir(tag: &str) -> (std::path::PathBuf, AnnuletGenesisFile) {
    let dir = std::env::temp_dir().join(format!("qumbra-audit-supply-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let g = AnnuletGenesisFile::fixture();
    let key = SequencerKey::from_seed([0x5E; 32]);
    let mut n = MemNode::open_annulet(
        &dir,
        g.genesis_block_header(),
        &g.notes(),
        g.params.fee_table(),
        &registry_leaves(&g.registry_genesis),
    )
    .expect("open the fixture chain");
    let mut parent = g.genesis_block_header();
    for (i, terms) in [term(false, 1_000, 7), term(false, 250, 7), term(true, 400, 7)].into_iter().enumerate() {
        let body = BlockBody::new(vec![p_tx(&n, &g, 10 + 2 * i as u8, terms)], vec![]);
        let sealed = key.seal(BlockHeader::child_of_annulet(
            &parent,
            parent.timestamp + 10,
            ext(&g),
            body_commitment_annulet(&body),
        ));
        n.apply_sealed_block(&sealed, body, &OkProof).expect("apply");
        parent = sealed.header;
    }
    assert_eq!(n.outstanding_supplies().get(&7), Some(&850), "precondition: the node's own state");
    drop(n);
    (dir, g)
}

#[test]
fn the_audit_recomputes_the_figures_from_the_data_dir_alone() {
    let (dir, g) = chain_dir("figures");
    let r = audit_with_claim(&dir, &g, None).expect("runs");
    assert_eq!(r.ledger.tip_height, 3);
    assert_eq!(r.ledger.outstanding().get(&7), Some(&850));
    assert_eq!(r.exit_code(), EXIT_CLEAN);
    let out = r.format_output();
    assert!(out.contains("ASSET asset=7 minted=1250 redeemed=400 outstanding=850"), "{out}");
    // The fixture genesis's four fee-unit notes (tier S = 1 each), recomputed
    // from their public plaintext payloads.
    assert_eq!(r.ledger.genesis.get(&0), Some(&4));
    assert!(out.contains("GENESIS asset=0 issued=4"), "{out}");
    assert!(out.contains("issuance ≠ reserves"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// 🔴 The ruling's test: the served document round-trips as JSON and
/// reproduces (exit 0); the same document with one figure tampered is caught
/// **by name** (exit 1).
#[test]
fn a_tampered_claimed_document_is_caught_by_name() {
    let (dir, g) = chain_dir("claimed");
    let honest: AttestDocument = audit_with_claim(&dir, &g, None).unwrap().ledger.document(Vec::new());
    assert_eq!(honest.label, LABEL);

    // Through the file path the CLI reads: the honest claim reproduces.
    let claim_path = dir.with_extension("attest.json");
    let genesis_path = dir.with_extension("genesis.bin");
    std::fs::write(&genesis_path, g.to_bytes()).unwrap();
    std::fs::write(&claim_path, serde_json::to_string(&honest).unwrap()).unwrap();
    let ok = audit_supply_l2(&dir, &genesis_path, Some(&claim_path)).expect("runs");
    assert_eq!(ok.exit_code(), EXIT_CLEAN, "{}", ok.format_output());

    // Three figures tampered — an outstanding total, a flow, a genesis row:
    // each named, exit 1.
    let mut tampered = honest.clone();
    tampered.assets.iter_mut().find(|r| r.asset == 7).unwrap().outstanding = "900".into();
    tampered.flows.iter_mut().find(|r| r.height == 2).unwrap().minted = "300".into();
    tampered.genesis.iter_mut().find(|r| r.asset == 0).unwrap().issued = "5".into();
    std::fs::write(&claim_path, serde_json::to_string(&tampered).unwrap()).unwrap();
    let bad = audit_supply_l2(&dir, &genesis_path, Some(&claim_path)).expect("runs");
    assert_eq!(bad.exit_code(), EXIT_DIVERGENT);
    let out = bad.format_output();
    assert!(out.contains("DIVERGENT asset 7: claimed"), "{out}");
    assert!(out.contains("DIVERGENT flow height=2 asset=7: claimed"), "{out}");
    assert!(out.contains("DIVERGENT genesis asset 0: claimed"), "{out}");
    assert!(out.contains("does NOT reproduce: 3 divergence(s)"), "{out}");

    for p in [&claim_path, &genesis_path] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Exit 2: a genesis that is not an Annulet genesis, and a claim that is not
/// an attestation document, are refused before anything is compared.
#[test]
fn what_cannot_run_is_refused_by_name() {
    let (dir, g) = chain_dir("cannot");
    let genesis_path = dir.with_extension("genesis.bin");
    std::fs::write(&genesis_path, b"not a genesis").unwrap();
    let e = audit_supply_l2(&dir, &genesis_path, None).unwrap_err();
    assert!(e.to_string().contains("not an Annulet genesis"), "{e}");

    std::fs::write(&genesis_path, g.to_bytes()).unwrap();
    let claim_path = dir.with_extension("attest.json");
    std::fs::write(&claim_path, "{\"v\":1}").unwrap();
    let e = audit_supply_l2(&dir, &genesis_path, Some(&claim_path)).unwrap_err();
    assert!(e.to_string().contains("not an attestation document"), "{e}");
    assert_eq!(EXIT_CANNOT_RUN, 2);

    for p in [&claim_path, &genesis_path] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
