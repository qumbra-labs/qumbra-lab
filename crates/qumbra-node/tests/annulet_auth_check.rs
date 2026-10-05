//! Lab #896 seam E2: a format-33 (Candidate A) Annulet genesis through the
//! node's loaders and the REAL binary's `check`, which prints the axis. An L1
//! loader refuses it by name, as it refuses format 32. Nothing starts a node.

use std::path::{Path, PathBuf};
use std::process::Command;

use qlab_devnet::forms::L2AuthForm;
use qlab_node::annulet_genesis::{
    AnnuletGenesisFile, AnnuletParams, GenesisNoteRecord, RegistryLeafRecord,
};
use qumbra_node::annulet_genesis::{load_any, AnyGenesis};
use qumbra_node::genesis::{GenesisError, GenesisFile};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

fn genesis(auth: L2AuthForm) -> AnnuletGenesisFile {
    let note = qlab_note::l2note::L2Note {
        value: 1,
        asset: 0,
        rkm: [0xFA0C_E701, 0xFA0C_E702, 0xFA0C_E703, 0xFA0C_E704],
        rho: [0x6E0A_0000, 1, 2, 3],
        rseed: [0x5EED_0000, 4, 5, 6],
    };
    AnnuletGenesisFile::assemble_with_auth(
        "annulet-e2-check",
        AnnuletParams {
            fee_tier_s: 1,
            fee_tier_p: 2,
            fee_tier_r: 4,
            slot_secs: 10,
            max_empty_slots: 6,
        },
        [0x5E; 32],
        vec![RegistryLeafRecord::asset_zero()],
        vec![GenesisNoteRecord::of(&note)],
        0,
        auth,
    )
}

fn stage(tag: &str, g: &AnnuletGenesisFile) -> PathBuf {
    let base = std::env::temp_dir().join(format!("i896_e2_check_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("genesis.qmb"), g.to_bytes()).unwrap();
    let cfg = format!(
        "data_dir = \"{data}\"\nlisten_addr = \"127.0.0.1:0\"\ndial_peers = []\ngenesis_file = \"{gen}\"\n\
         committee_key_paths = []\nmining = false\nexpected_genesis_hash = \"{hash}\"\n",
        data = base.join("data").display(),
        gen = base.join("genesis.qmb").display(),
        hash = g.hash_hex(),
    );
    std::fs::write(base.join("node.toml"), cfg).unwrap();
    base
}

fn check(base: &Path) -> String {
    let out = Command::new(bin())
        .args([
            "check",
            "--config",
            base.join("node.toml").to_str().unwrap(),
        ])
        .output()
        .expect("spawn qumbra-node check");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "check: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

#[test]
fn load_any_dispatches_format_33_to_the_annulet_loader() {
    let g = genesis(L2AuthForm::CandidateA);
    match load_any(&g.to_bytes()).expect("format 33 loads") {
        AnyGenesis::Annulet(file) => {
            assert_eq!(*file, g);
            assert_eq!(file.l2_auth(), Ok(L2AuthForm::CandidateA));
        }
        AnyGenesis::L1(_) | AnyGenesis::V6(_) => panic!("format 33 is an Annulet genesis"),
    }
}

#[test]
fn an_l1_loader_refuses_format_33_by_name() {
    let g = genesis(L2AuthForm::CandidateA);
    assert!(matches!(
        GenesisFile::from_bytes(&g.to_bytes()),
        Err(GenesisError::AnnuletGenesisNotServed)
    ));
}

#[test]
fn check_prints_the_l2_auth_axis() {
    for (tag, auth, want) in [
        ("v1", L2AuthForm::None, "none"),
        ("v2", L2AuthForm::CandidateA, "candidate-a"),
    ] {
        let g = genesis(auth);
        let base = stage(tag, &g);
        let out = check(&base);
        assert!(
            out.contains(&format!("genesis hash: {}", g.hash_hex())),
            "{out}"
        );
        assert!(
            out.lines()
                .any(|l| l.trim() == format!("l2 auth:      {want}")),
            "{tag}: {out}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
