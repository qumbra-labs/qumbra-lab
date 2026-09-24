//! Read-only per-asset supply audit of an Annulet chain — lab issue #726
//! (L2-D1): the do-it-yourself half of the explorer's attestation.
//!
//! It reconstructs the main chain through [`MemNode::open_annulet`] — the same
//! path the live node uses — folds every body's public `vPublic` terms with
//! `qlab_node::asset_supply`, and prints the per-asset figures. With
//! `--claimed <file>` it reads a served attestation document (the explorer's
//! `/v1/attest`) and names every figure that does not reproduce, by asset and
//! height. It observes; it never writes the data dir.
//!
//! What a clean run means: the claimed figures are what the public block
//! bodies say. It does **not** mean the issuer holds reserves (issuance ≠
//! reserves), and nothing here is a consensus commitment.
//!
//! Exit codes, test-locked, the `audit-emission` contract: 0 clean, 1 the
//! claim does not reproduce, 2 cannot run.

use std::fmt;
use std::path::{Path, PathBuf};

use qlab_node::asset_supply::{genesis_issuance, AssetLedger, AttestDocument};
use qlab_node::{main_chain_of, MemNode};

use crate::annulet_genesis::{registry_leaves, AnnuletGenesisFile};

pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_DIVERGENT: u8 = 1;
pub const EXIT_CANNOT_RUN: u8 = 2;

/// Why the audit could not run.
#[derive(Debug)]
pub enum SupplyAuditError {
    Usage(String),
    Genesis { path: PathBuf, reason: String },
    UnreadableLog { path: PathBuf, reason: String },
    Claimed { path: PathBuf, reason: String },
}

impl fmt::Display for SupplyAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(r) => write!(f, "usage: {r}"),
            Self::Genesis { path, reason } => write!(f, "genesis {}: {reason}", path.display()),
            Self::UnreadableLog { path, reason } => write!(f, "data dir {}: {reason}", path.display()),
            Self::Claimed { path, reason } => write!(f, "claimed document {}: {reason}", path.display()),
        }
    }
}

/// What a run found.
#[derive(Clone, Debug)]
pub struct SupplyReport {
    pub ledger: AssetLedger,
    /// `None` without `--claimed`; `Some(names)` with it (empty = reproduces).
    pub divergences: Option<Vec<String>>,
}

impl SupplyReport {
    pub fn exit_code(&self) -> u8 {
        match &self.divergences {
            Some(d) if !d.is_empty() => EXIT_DIVERGENT,
            _ => EXIT_CLEAN,
        }
    }

    /// The stdout body: the per-asset figures, then each divergence, then one
    /// summary line — never silent.
    pub fn format_output(&self) -> String {
        let mut lines = vec![format!(
            "recomputed from public block bodies to height {} — issuance ≠ reserves; not a consensus commitment",
            self.ledger.tip_height
        )];
        for (asset, issued) in &self.ledger.genesis {
            lines.push(format!("GENESIS asset={asset} issued={issued}"));
        }
        for (asset, f) in self.ledger.totals() {
            lines.push(format!(
                "ASSET asset={asset} minted={} redeemed={} outstanding={}",
                f.minted,
                f.redeemed,
                f.net()
            ));
        }
        match &self.divergences {
            None => lines.push("no --claimed document: figures only".to_string()),
            Some(d) if d.is_empty() => lines.push("claimed document reproduces: 0 divergences".to_string()),
            Some(d) => {
                for m in d {
                    lines.push(format!("DIVERGENT {m}"));
                }
                lines.push(format!("claimed document does NOT reproduce: {} divergence(s)", d.len()));
            }
        }
        lines.join("\n")
    }
}

/// Run the audit over an already-parsed claim (the testable core).
pub fn audit_with_claim(
    data_dir: &Path,
    genesis: &AnnuletGenesisFile,
    claimed: Option<&AttestDocument>,
) -> Result<SupplyReport, SupplyAuditError> {
    let node = MemNode::open_annulet(
        data_dir,
        genesis.genesis_block_header(),
        &genesis.notes(),
        genesis.params.fee_table(),
        &registry_leaves(&genesis.registry_genesis),
    )
    .map_err(|e| SupplyAuditError::UnreadableLog {
        path: data_dir.to_path_buf(),
        reason: format!("could not open the persisted Annulet chain: {e}"),
    })?;
    let chain = main_chain_of(&node);
    let tip = chain.iter().map(|b| b.header.height).max().unwrap_or(0);
    let bodies: Vec<(u64, qlab_devnet::body::BlockBody)> =
        chain.iter().map(|b| (b.header.height, b.body())).collect();
    let issuance = genesis_issuance(&genesis.notes()).map_err(|reason| SupplyAuditError::Genesis {
        path: PathBuf::from("<genesis notes>"),
        reason,
    })?;
    let ledger = AssetLedger::fold(tip, bodies.iter().map(|(h, b)| (*h, b))).with_genesis(issuance);
    let divergences = claimed.map(|c| ledger.compare_claimed(c));
    Ok(SupplyReport { ledger, divergences })
}

/// Run the audit from paths: `--data-dir`, `--genesis`, optional `--claimed`.
pub fn audit_supply_l2(
    data_dir: &Path,
    genesis_path: &Path,
    claimed_path: Option<&Path>,
) -> Result<SupplyReport, SupplyAuditError> {
    if !data_dir.is_dir() {
        return Err(SupplyAuditError::UnreadableLog {
            path: data_dir.to_path_buf(),
            reason: "not a directory".into(),
        });
    }
    let bytes = std::fs::read(genesis_path).map_err(|e| SupplyAuditError::Genesis {
        path: genesis_path.to_path_buf(),
        reason: e.to_string(),
    })?;
    let genesis = AnnuletGenesisFile::from_bytes(&bytes).map_err(|e| SupplyAuditError::Genesis {
        path: genesis_path.to_path_buf(),
        reason: format!("not an Annulet genesis: {e:?}"),
    })?;
    genesis.verify(None).map_err(|e| SupplyAuditError::Genesis {
        path: genesis_path.to_path_buf(),
        reason: format!("does not verify: {e:?}"),
    })?;
    let claimed = match claimed_path {
        None => None,
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| SupplyAuditError::Claimed { path: p.to_path_buf(), reason: e.to_string() })?;
            let doc: AttestDocument = serde_json::from_str(&text).map_err(|e| SupplyAuditError::Claimed {
                path: p.to_path_buf(),
                reason: format!("not an attestation document: {e}"),
            })?;
            Some(doc)
        }
    };
    audit_with_claim(data_dir, &genesis, claimed.as_ref())
}

/// `--data-dir DIR --genesis FILE [--claimed FILE]`.
pub fn parse_args(args: &[String]) -> Result<(PathBuf, PathBuf, Option<PathBuf>), SupplyAuditError> {
    let (mut dir, mut genesis, mut claimed) = (None, None, None);
    let mut i = 0;
    while i < args.len() {
        let slot = match args[i].as_str() {
            "--data-dir" => &mut dir,
            "--genesis" => &mut genesis,
            "--claimed" => &mut claimed,
            other => return Err(SupplyAuditError::Usage(format!("unknown argument {other}"))),
        };
        let v = args
            .get(i + 1)
            .ok_or_else(|| SupplyAuditError::Usage(format!("{} requires a path", args[i])))?;
        *slot = Some(PathBuf::from(v));
        i += 2;
    }
    Ok((
        dir.ok_or_else(|| SupplyAuditError::Usage("--data-dir is required".into()))?,
        genesis.ok_or_else(|| SupplyAuditError::Usage("--genesis is required".into()))?,
        claimed,
    ))
}
