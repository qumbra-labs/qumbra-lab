//! `qumbra-node audit-names` — read-only name-registry + burn reconciliation
//! (lab #367; the `audit-emission` pattern: every consensus change ships its
//! auditor).
//!
//! Reconstructs the main chain through [`MemNode::open`] — the node's own
//! restart path, no second log reader — then **re-derives the registry from
//! the committed riders alone**, re-running the stage-2 rules (`check_op`),
//! the fee split, and the burn sum over every audited block. Three things can
//! come out:
//!
//! 1. a **violation** — a rider the rules refuse, a fee that does not equal
//!    `posted + name_fee`, or a rider on the wrong side of the boundary;
//! 2. a **registry divergence** — the re-derived registry differs from the
//!    one the node restored (sidecar path vs log path disagreeing is exactly
//!    the class of defect an auditor exists to catch);
//! 3. the clean report: registrations, total burn, exit 0.
//!
//! Exit codes are `audit-emission`'s contract: 0 clean · 1 findings · 2 the
//! tool could not run.

use std::fmt;
use std::path::{Path, PathBuf};

use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::names::{
    self, check_op, decode_rider, name_fee_for, riders_active_above, NameOp,
};
use qlab_node::name_registry::NameRegistry;
use qlab_node::{genesis_block, main_chain_of, MemNode, NodeState, StoredBlock};

use crate::genesis::T0_GENESIS_DIFFICULTY;

/// Process exit codes (the `audit-emission` contract).
pub const EXIT_CLEAN: u8 = 0;
/// See [`EXIT_CLEAN`].
pub const EXIT_FINDINGS: u8 = 1;
/// See [`EXIT_CLEAN`].
pub const EXIT_CANNOT_RUN: u8 = 2;

/// One finding, locatable by (height, tx).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameViolation {
    pub height: u64,
    pub tx_index: usize,
    /// What was wrong, in the refusing layer's own words.
    pub what: String,
}

impl NameViolation {
    pub fn format_line(&self) -> String {
        format!("height {:>8}  tx {:>3}  {}", self.height, self.tx_index, self.what)
    }
}

/// The audit's result.
#[derive(Clone, Debug)]
pub struct NamesAuditReport {
    pub from: u64,
    pub to: u64,
    pub tip: u64,
    /// Names with an entry in the re-derived registry (current or lapsed).
    pub registrations: usize,
    /// Total bessel burned by name fees over the audited interval.
    pub burned: u64,
    pub violations: Vec<NameViolation>,
    /// `false` when the node's restored registry differs from the re-derived
    /// one — reported as a finding of its own.
    pub registry_agrees: bool,
}

impl NamesAuditReport {
    pub fn exit_code(&self) -> u8 {
        if self.violations.is_empty() && self.registry_agrees {
            EXIT_CLEAN
        } else {
            EXIT_FINDINGS
        }
    }

    pub fn format_output(&self) -> String {
        let mut out = String::new();
        for v in &self.violations {
            out.push_str(&v.format_line());
            out.push('\n');
        }
        out.push_str(&format!(
            "audit-names [{}..={}] of tip {}: {} registration(s), {} bessel burned, \
             {} violation(s), registry {}\n",
            self.from,
            self.to,
            self.tip,
            self.registrations,
            self.burned,
            self.violations.len(),
            if self.registry_agrees { "AGREES" } else { "DIVERGES from the node's restored copy" },
        ));
        out
    }
}

/// Why the tool could not run (exit 2).
#[derive(Debug)]
pub enum AuditError {
    BadDir { path: PathBuf, reason: String },
    UnreadableLog { path: PathBuf, reason: String },
    IntervalBeyondTip { from: u64, to: u64, tip: u64, reason: String },
    Usage(String),
}

impl AuditError {
    pub fn reason(&self) -> &str {
        match self {
            Self::BadDir { reason, .. }
            | Self::UnreadableLog { reason, .. }
            | Self::IntervalBeyondTip { reason, .. } => reason,
            Self::Usage(reason) => reason,
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason())
    }
}

impl std::error::Error for AuditError {}

/// The core, pure over a block slice so the rule coverage is testable without
/// a datadir: re-derive the registry over `blocks` (which must start at the
/// chain's genesis to be meaningful), auditing heights in `[from, to]` under
/// `boundary` (pass `names::NAME_RULE_BOUNDARY_HEIGHT` outside drills).
pub fn audit_blocks(
    blocks: &[StoredBlock],
    boundary: Option<u64>,
    from: u64,
    to: u64,
) -> (NameRegistry, u64, Vec<NameViolation>) {
    let mut registry = NameRegistry::default();
    let mut burned = 0u64;
    let mut violations = Vec::new();

    for block in blocks {
        let h = block.header.height;
        let audited = h >= from && h <= to;
        let mut pending: std::collections::HashSet<Vec<u8>> = Default::default();
        for (i, tx) in block.txs.iter().enumerate() {
            let op = match decode_rider(&tx.rider) {
                Ok(op) => op,
                Err(e) => {
                    if audited {
                        violations.push(NameViolation {
                            height: h,
                            tx_index: i,
                            what: format!("rider does not decode: {e:?}"),
                        });
                    }
                    continue;
                }
            };
            let Some(op) = op else { continue };
            if audited {
                if !riders_active_above(boundary, h) {
                    violations.push(NameViolation {
                        height: h,
                        tx_index: i,
                        what: format!("rider before the boundary ({boundary:?})"),
                    });
                }
                let bucket = ArityBucket::for_arity(
                    tx.nullifiers.len() as u32,
                    tx.commitments.len() as u32,
                )
                .unwrap_or(ArityBucket::TwoByTwo);
                let expected_fee = posted_fee(bucket) + name_fee_for(&op);
                if tx.fee != expected_fee {
                    violations.push(NameViolation {
                        height: h,
                        tx_index: i,
                        what: format!(
                            "fee split: declared {} != posted + name fee {expected_fee}",
                            tx.fee
                        ),
                    });
                }
                if let Err(e) = check_op(&registry, h, &op, &pending) {
                    violations.push(NameViolation {
                        height: h,
                        tx_index: i,
                        what: format!("rule: {e:?}"),
                    });
                }
                burned += name_fee_for(&op);
            }
            if let NameOp::Reveal { record, .. } = &op {
                pending.insert(record.name.clone());
            }
        }
        // Fold the block into the registry AFTER rule-checking it (the rules
        // read the state as of the block's parent, same as validation).
        if let Err((i, e)) = registry.apply_block_riders(h, &block.txs) {
            if audited {
                violations.push(NameViolation {
                    height: h,
                    tx_index: i,
                    what: format!("registry apply refused: {e:?}"),
                });
            }
        }
    }
    (registry, burned, violations)
}

/// Open `data_dir` the way the node does and audit `[from, to]`
/// (defaults 0..=tip) under the shipped boundary.
pub fn audit_names(
    data_dir: &Path,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<NamesAuditReport, AuditError> {
    if !data_dir.is_dir() {
        return Err(AuditError::BadDir {
            path: data_dir.to_path_buf(),
            reason: format!("not a directory: {}", data_dir.display()),
        });
    }
    let genesis = genesis_block(T0_GENESIS_DIFFICULTY, 0);
    let node = MemNode::open(data_dir, genesis).map_err(|e| AuditError::UnreadableLog {
        path: data_dir.to_path_buf(),
        reason: format!("could not open persisted chain at {}: {e}", data_dir.display()),
    })?;

    let tip = node.tip_height();
    let from = from.unwrap_or(0);
    let to = to.unwrap_or(tip);
    if from > to || to > tip {
        return Err(AuditError::IntervalBeyondTip {
            from,
            to,
            tip,
            reason: format!("bad interval [{from}..={to}] against tip {tip}"),
        });
    }

    let chain = main_chain_of(&node);
    let (registry, burned, violations) =
        audit_blocks(&chain, names::NAME_RULE_BOUNDARY_HEIGHT, from, to);

    // The reconciliation: the registry the node restored (sidecar or replay)
    // must equal the one re-derived from the committed riders alone — two
    // paths, one truth. Compared over the whole chain, so only meaningful
    // when the audit covered it; a partial-interval audit still re-derives
    // from genesis (blocks before `from` fold in unaudited), so the compare
    // holds regardless of the interval.
    let registry_agrees = &registry == node.names();

    Ok(NamesAuditReport {
        from,
        to,
        tip,
        registrations: registry.len(),
        burned,
        violations,
        registry_agrees,
    })
}

/// CLI arg parsing — `--data-dir DIR [--from H] [--to H]`, the
/// `audit-emission` flags verbatim.
pub fn parse_args(args: &[String]) -> Result<(PathBuf, Option<u64>, Option<u64>), AuditError> {
    let mut data_dir: Option<PathBuf> = None;
    let mut from: Option<u64> = None;
    let mut to: Option<u64> = None;
    let mut i = 0;
    let want = |v: Option<&String>, what: &str| {
        v.cloned().ok_or_else(|| AuditError::Usage(format!("{what} requires a value")))
    };
    let num = |v: &str, what: &str| {
        v.parse::<u64>().map_err(|_| AuditError::Usage(format!("{what}: not a height: {v}")))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(want(args.get(i + 1), "--data-dir")?));
                i += 2;
            }
            "--from" => {
                from = Some(num(&want(args.get(i + 1), "--from")?, "--from")?);
                i += 2;
            }
            "--to" => {
                to = Some(num(&want(args.get(i + 1), "--to")?, "--to")?);
                i += 2;
            }
            other => return Err(AuditError::Usage(format!("unknown flag: {other}"))),
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| AuditError::Usage("--data-dir is required".into()))?;
    Ok((data_dir, from, to))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::names::{
        commit_hash, encode_rider, name_fee_bessel, NameRecord, L1_ADDRESS_LEN,
        RECORD_KIND_L1_ADDRESS,
    };
    use qlab_node::{StoredHeader, StoredTx};

    fn block(height: u64, txs: Vec<StoredTx>) -> StoredBlock {
        StoredBlock {
            header: StoredHeader {
                prev: [height.wrapping_sub(1) as u8; 32],
                height,
                timestamp: height * 75,
                difficulty: 1,
                nonce: 0,
                tx_body_commitment: [0; 32],
            },
            txs,
            coinbase: 0,
            coinbase_rkm: [1, 2, 3, 4],
        }
    }

    fn tx(op: Option<&NameOp>, fee: u64) -> StoredTx {
        StoredTx {
            anchor: [0x0F; 32],
            nullifiers: vec![[1; 32]],
            commitments: vec![[2; 32]],
            bucket_actions: 2,
            fee,
            proof: vec![],
            discovery: vec![0x00],
            rider: encode_rider(op),
        }
    }

    fn record() -> NameRecord {
        NameRecord {
            kind: RECORD_KIND_L1_ADDRESS,
            name: b"alice".to_vec(),
            address: vec![0xAB; L1_ADDRESS_LEN],
        }
    }

    const B: Option<u64> = Some(8_640);
    const RELAY: u64 = 1_000_000;

    #[test]
    fn a_clean_lifecycle_audits_clean_and_sums_the_burn() {
        let r = record();
        let salt = [7u8; 32];
        let commit = NameOp::Commit { commit: commit_hash(&r, &salt) };
        let reveal = NameOp::Reveal { record: r, salt };
        let renew = NameOp::Renew { name: b"alice".to_vec() };
        let blocks = vec![
            block(9_000, vec![tx(Some(&commit), RELAY)]),
            block(9_100, vec![tx(Some(&reveal), RELAY + name_fee_bessel(5))]),
            block(9_200, vec![tx(Some(&renew), RELAY + name_fee_bessel(5))]),
        ];
        let (reg, burned, violations) = audit_blocks(&blocks, B, 0, u64::MAX);
        assert_eq!(violations, vec![], "clean chain");
        assert_eq!(reg.len(), 1);
        assert_eq!(burned, 2 * name_fee_bessel(5), "reveal + renew burn; commit burns nothing");
    }

    #[test]
    fn each_violation_class_is_found_and_named() {
        let r = record();
        let salt = [7u8; 32];
        let reveal = NameOp::Reveal { record: r, salt };

        // (a) rider before the boundary.
        let (_, _, v) =
            audit_blocks(&[block(100, vec![tx(Some(&NameOp::Commit { commit: [9; 32] }), RELAY)])], B, 0, u64::MAX);
        assert!(v.iter().any(|x| x.what.contains("before the boundary")), "{v:?}");

        // (b) fee split violation: reveal paying relay only.
        let (_, _, v) = audit_blocks(&[block(9_100, vec![tx(Some(&reveal), RELAY)])], B, 0, u64::MAX);
        assert!(v.iter().any(|x| x.what.contains("fee split")), "{v:?}");

        // (c) rule violation: reveal with no commit anywhere.
        assert!(v.iter().any(|x| x.what.contains("CommitNotFound")), "{v:?}");

        // (d) undecodable rider bytes.
        let mut garbled = tx(None, RELAY);
        garbled.rider = vec![0x01, 0x01];
        let (_, _, v) = audit_blocks(&[block(9_100, vec![garbled])], B, 0, u64::MAX);
        assert!(v.iter().any(|x| x.what.contains("does not decode")), "{v:?}");
    }

    #[test]
    fn interval_bounds_scope_the_findings_but_not_the_registry() {
        let r = record();
        let salt = [7u8; 32];
        let blocks = vec![
            block(9_000, vec![tx(Some(&NameOp::Commit { commit: commit_hash(&r, &salt) }), RELAY)]),
            block(9_100, vec![tx(Some(&NameOp::Reveal { record: r, salt }), RELAY + name_fee_bessel(5))]),
        ];
        // Audit only a later window: no violations reported, but the registry
        // still re-derives from genesis so the compare stays meaningful.
        let (reg, burned, violations) = audit_blocks(&blocks, B, 10_000, 20_000);
        assert_eq!(violations, vec![]);
        assert_eq!(burned, 0, "burn is an audited-interval sum");
        assert_eq!(reg.len(), 1, "the registry is whole-chain regardless of the interval");
    }
}
