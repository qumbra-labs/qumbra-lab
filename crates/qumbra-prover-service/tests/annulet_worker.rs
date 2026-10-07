//! **The real child, end to end** (lab #924 5A-D3): the service's own
//! process prover spawns this binary's `annulet-worker` — environment
//! cleared, core dumps off — hands it a signed S bundle, and gets back the
//! bundle's transaction with a proof that verifies against the bundle's PVs.
//! **One S prove** (about 50 s / 29 GiB on the r7g lane). The refusal paths
//! run the same child and prove nothing.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use qlab_devnet::annulet::L2ShapeTag;
use qlab_l2spend::fixtures::{signed_bundle, GENESIS_HASH};
use qumbra_prover_service::annulet::{proof_added, AnnuletProcessProver, AnnuletProver};

fn prover() -> AnnuletProcessProver {
    AnnuletProcessProver {
        executable: env!("CARGO_BIN_EXE_qumbra-prover-service").into(),
        genesis_hash: GENESIS_HASH,
        scratch: std::env::temp_dir(),
        timeout: Duration::from_secs(900),
    }
}

#[test]
fn the_child_proves_a_signed_s_bundle_and_changes_nothing_else() {
    let bundle = signed_bundle(L2ShapeTag::S);
    let wire = prover()
        .prove(&bundle.encode(), &AtomicBool::new(false))
        .expect("the child proves an honest bundle");
    let tx = proof_added(&qlab_p2p::codec::encode_tx_annulet(bundle.tx()), &wire)
        .expect("the bundle's transaction plus a proof, nothing else");
    let proof: qlab_l2::Proof<qlab_l2::Config> =
        bincode::deserialize(&tx.proof).expect("the proof decodes");
    assert!(
        qlab_l2::v2::verify_s_u32(&bundle.witness().pvs(), &proof),
        "the proof verifies against the bundle's PVs"
    );
}

#[test]
fn the_child_refuses_without_proving() {
    // Not a bundle.
    assert_eq!(
        prover().prove(b"not a bundle", &AtomicBool::new(false)),
        Err("bundle-refused")
    );
    // A real bundle for another net: the lock refuses before any prove.
    let other = AnnuletProcessProver {
        genesis_hash: [0x6f; 32],
        ..prover()
    };
    assert_eq!(
        other.prove(
            &signed_bundle(L2ShapeTag::S).encode(),
            &AtomicBool::new(false)
        ),
        Err("bundle-refused")
    );
}

#[test]
fn the_worker_subcommand_refuses_without_its_protocol_tag() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qumbra-prover-service"))
        .arg("annulet-worker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(&[0; 4]);
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "nothing is answered without the tag");
}
