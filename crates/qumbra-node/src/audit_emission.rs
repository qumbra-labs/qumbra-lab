//! Read-only emission audit: walk a node's persisted main chain and report every
//! height whose committed payee total differs from the schedule
//! ([`qlab_node::emission::coinbase_for`] of the opened node's [`GenesisForm`]).
//!
//! This is the localization tool for lab issue #299 / QUM-82. It **observes**;
//! it never changes consensus, never writes the data dir, and never reimplements
//! log reading — the chain is reconstructed through [`MemNode::open`], the same
//! path the live node uses at restart.

use std::fmt;
use std::path::{Path, PathBuf};

use qlab_devnet::forms::GenesisForm;
use qlab_node::emission::coinbase_for;
use qlab_node::{genesis_block, main_chain_of, MemNode, NodeState, StoredBlock};

use crate::genesis::T0_GENESIS_DIFFICULTY;

/// Process exit codes for `qumbra-node audit-emission` (test-locked).
pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_MISMATCH: u8 = 1;
pub const EXIT_CANNOT_RUN: u8 = 2;

/// One height where the committed coinbase is not the schedule value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub height: u64,
    pub committed: u64,
    pub expected: u64,
    /// `committed as i128 − expected as i128`.
    pub delta: i128,
    /// Full 32-byte header hash of the mismatched block.
    pub hash: [u8; 32],
}

impl Mismatch {
    /// `MISMATCH height=… committed=… expected=… delta=… hash=ab12cd34…`
    pub fn format_line(&self) -> String {
        format!(
            "MISMATCH height={} committed={} expected={} delta={} hash={}",
            self.height,
            self.committed,
            self.expected,
            self.delta,
            short_hash(&self.hash),
        )
    }
}

/// Outcome of a successful audit run (the tool ran; mismatches may still exist).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    /// Inclusive start of the audited height interval (after genesis skip).
    pub from: u64,
    /// Inclusive end of the audited height interval.
    pub to: u64,
    /// Tip height of the reconstructed main chain.
    pub tip: u64,
    /// Whether height 0 was requested and reported as skipped genesis.
    pub skipped_genesis: bool,
    pub mismatches: Vec<Mismatch>,
    /// `--payee` tally, when one was asked for (`qumbra-deploy` #143).
    ///
    /// Separate from `mismatches` on purpose: a mismatch is a **defect**, this is an
    /// **attribution**. A block paying an unexpected key is not wrong — the schedule
    /// says how much, never to whom — so folding them would make one exit code mean
    /// two things.
    pub payee: Option<PayeeTally>,
}

/// How much of the audited interval a given `coinbase_rkm` was paid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayeeTally {
    /// The key asked about, as circuit lanes.
    pub rkm: [u64; 4],
    /// Canonical blocks in the interval whose payee list contains that key.
    pub blocks: u64,
    /// Their matching payee amounts summed, in bessel. The MINER's share is a
    /// fraction of this (`RewardSplit`), not this number — raw so the split stays
    /// in one place.
    pub coinbase_bessel: u128,
    /// Canonical blocks in the interval, so `blocks` has a denominator. Without one,
    /// "42 blocks" cannot be read as a share — and a share read without its
    /// denominator is how #143 was argued wrongly twice.
    pub blocks_in_interval: u64,
}

impl AuditReport {
    pub fn sum_of_deltas(&self) -> i128 {
        self.mismatches.iter().map(|m| m.delta).sum()
    }

    pub fn exit_code(&self) -> u8 {
        if self.mismatches.is_empty() {
            EXIT_CLEAN
        } else {
            EXIT_MISMATCH
        }
    }

    /// Summary line — always emitted, never silent on a clean chain.
    pub fn format_summary(&self) -> String {
        let n = self.mismatches.len();
        if n == 0 {
            format!("audited {}..={}: 0 mismatches", self.from, self.to)
        } else {
            format!(
                "audited {}..={}: {} mismatch{}, sum of deltas {}",
                self.from,
                self.to,
                n,
                if n == 1 { "" } else { "es" },
                self.sum_of_deltas(),
            )
        }
    }

    /// Full stdout body: optional genesis-skip line, one MISMATCH per hit, summary.
    pub fn format_output(&self) -> String {
        let mut lines = Vec::new();
        if self.skipped_genesis {
            lines.push("skipped genesis".to_string());
        }
        for m in &self.mismatches {
            lines.push(m.format_line());
        }
        if let Some(t) = &self.payee {
            let hex: String =
                t.rkm.iter().flat_map(|l| l.to_le_bytes()).map(|b| format!("{b:02x}")).collect();
            lines.push(format!(
                "payee {hex}: {} of {} canonical block(s) in {}..={} paid it, {} bessel committed",
                t.blocks, t.blocks_in_interval, self.from, self.to, t.coinbase_bessel
            ));
            if t.blocks == 0 {
                lines.push(
                    "  0 here means NO canonical block in this interval carried that \
                     coinbase_rkm — a fact about the chain, unlike a wallet scan's 0 (lab \
                     #415: the compact wire carries no coinbase_rkm, so a wallet cannot see \
                     coinbase at all)."
                        .to_string(),
                );
            }
        }
        lines.push(self.format_summary());
        lines.join("\n")
    }
}

/// Why the tool could not run (exit 2). Each variant has a named reason string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// `--data-dir` is missing or not a directory.
    BadDir { path: PathBuf, reason: String },
    /// The block log could not be opened / decoded / replayed.
    UnreadableLog { path: PathBuf, reason: String },
    /// `--from` or `--to` is past the reconstructed tip (or the interval is empty
    /// because the tip is below the requested floor).
    IntervalBeyondTip {
        from: u64,
        to: u64,
        tip: u64,
        reason: String,
    },
    /// Flag parse / usage errors that keep the tool from starting.
    Usage(String),
}

impl AuditError {
    pub fn reason(&self) -> &str {
        match self {
            Self::BadDir { reason, .. }
            | Self::UnreadableLog { reason, .. }
            | Self::IntervalBeyondTip { reason, .. }
            | Self::Usage(reason) => reason,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::BadDir { .. } => "bad_dir",
            Self::UnreadableLog { .. } => "unreadable_log",
            Self::IntervalBeyondTip { .. } => "interval_beyond_tip",
            Self::Usage(_) => "usage",
        }
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name(), self.reason())
    }
}

impl std::error::Error for AuditError {}

/// Open `data_dir` the way the node does, walk the main chain over
/// `[from, to]` (defaults: 1..=tip), and compare each committed coinbase to
/// [`coinbase_for`] of the opened node's genesis form (lab #520).
///
/// Height 0 is outside the audit by definition: genesis carries `coinbase == 0`
/// while `coinbase(0) = 5×10⁹`. When the requested interval includes 0 it is
/// reported as `skipped genesis`, not as a mismatch.
pub fn audit_emission(
    data_dir: &Path,
    from: Option<u64>,
    to: Option<u64>,
    payee: Option<[u64; 4]>,
) -> Result<AuditReport, AuditError> {
    if !data_dir.exists() {
        return Err(AuditError::BadDir {
            path: data_dir.to_path_buf(),
            reason: format!("data dir does not exist: {}", data_dir.display()),
        });
    }
    if !data_dir.is_dir() {
        return Err(AuditError::BadDir {
            path: data_dir.to_path_buf(),
            reason: format!("data dir is not a directory: {}", data_dir.display()),
        });
    }

    // Same genesis the T0 binary hands `NodeAdapter::open` (difficulty baked into
    // the genesis file). A foreign-net data dir fails open with a named reason.
    // Form-aware comparison happens after open via `node.form()` (lab #520);
    // the CLI still opens the v4 genesis block — a T2 data dir needs
    // [`audit_emission_for`] with the genesis file consensus loaded.
    let genesis = genesis_block(T0_GENESIS_DIFFICULTY, 0);
    audit_emission_for(GenesisForm::V4, genesis, data_dir, from, to, payee)
}

/// [`audit_emission`] under an explicit genesis form and genesis block
/// (lab #520). The expected schedule is [`coinbase_for`] of `form` — v4 the
/// boundary-grandfathered function, v5 `coinbase_exact` at every height ≥ 1
/// — taken from the same [`GenesisForm`] consensus dispatches on.
pub fn audit_emission_for(
    form: GenesisForm,
    genesis: qlab_node::StoredBlock,
    data_dir: &Path,
    from: Option<u64>,
    to: Option<u64>,
    payee: Option<[u64; 4]>,
) -> Result<AuditReport, AuditError> {
    let node = MemNode::open_for(form, data_dir, genesis).map_err(|e| AuditError::UnreadableLog {
        path: data_dir.to_path_buf(),
        reason: format!("could not open persisted chain at {}: {e}", data_dir.display()),
    })?;
    let tip = node.tip_height();
    let from_req = from.unwrap_or(1);
    let to_req = to.unwrap_or(tip);

    if from_req > tip {
        return Err(AuditError::IntervalBeyondTip {
            from: from_req,
            to: to_req,
            tip,
            reason: format!("--from {from_req} is beyond tip {tip}"),
        });
    }
    if to_req > tip {
        return Err(AuditError::IntervalBeyondTip {
            from: from_req,
            to: to_req,
            tip,
            reason: format!("--to {to_req} is beyond tip {tip}"),
        });
    }
    if from_req > to_req {
        return Err(AuditError::IntervalBeyondTip {
            from: from_req,
            to: to_req,
            tip,
            reason: format!("empty interval: --from {from_req} > --to {to_req}"),
        });
    }

    // Genesis is never audited as a mismatch (issue #299): the payee total is 0 by
    // construction while coinbase(0) = 5e9. Accept --from 0 and skip height 0.
    let skipped_genesis = from_req == 0;
    let audit_from = if skipped_genesis {
        if to_req == 0 {
            // Interval is exactly {0}: nothing to compare; clean.
            return Ok(AuditReport {
                from: 0,
                to: 0,
                tip,
                skipped_genesis: true,
                mismatches: Vec::new(),
                payee: payee.map(|rkm| PayeeTally {
                    rkm,
                    blocks: 0,
                    coinbase_bessel: 0,
                    blocks_in_interval: 0,
                }),
            });
        }
        1
    } else {
        from_req
    };

    let chain = main_chain_of(&node);
    let mut mismatches = Vec::new();
    let mut payee_blocks = 0u64;
    let mut payee_bessel = 0u128;
    let mut blocks_in_interval = 0u64;
    for block in &chain {
        let h = block.header.height;
        if h < audit_from || h > to_req {
            continue;
        }
        blocks_in_interval += 1;
        if let Some(want) = payee {
            let body = block.body();
            if let Some(paid) = body.coinbase_payees.iter().find(|p| p.rkm == want) {
                payee_blocks += 1;
                payee_bessel += u128::from(paid.amount);
            }
        }
        if let Some(m) = mismatch_at(form, block) {
            mismatches.push(m);
        }
    }

    Ok(AuditReport {
        payee: payee.map(|rkm| PayeeTally {
            rkm,
            blocks: payee_blocks,
            coinbase_bessel: payee_bessel,
            blocks_in_interval,
        }),
        from: if skipped_genesis { 0 } else { audit_from },
        to: to_req,
        tip,
        skipped_genesis,
        mismatches,
    })
}

fn mismatch_at(form: GenesisForm, block: &StoredBlock) -> Option<Mismatch> {
    let height = block.header.height;
    if height == 0 {
        return None;
    }
    let committed = block.coinbase;
    let expected = coinbase_for(form, height);
    if committed == expected {
        return None;
    }
    let delta = committed as i128 - expected as i128;
    let hash = block.header().header_hash();
    Some(Mismatch {
        height,
        committed,
        expected,
        delta,
        hash,
    })
}

/// First 8 hex chars + ellipsis, matching the task-book example `ab12cd34…`.
fn short_hash(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8 + '…'.len_utf8());
    for b in &hash[..4] {
        s.push_str(&format!("{b:02x}"));
    }
    s.push('…');
    s
}

/// Parse CLI args after `audit-emission`. Returns `(data_dir, from, to)`.
pub fn parse_args(args: &[String]) -> Result<(PathBuf, Option<u64>, Option<u64>), AuditError> {
    let mut data_dir: Option<PathBuf> = None;
    let mut from: Option<u64> = None;
    let mut to: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    AuditError::Usage("--data-dir requires a path".into())
                })?;
                data_dir = Some(PathBuf::from(v));
                i += 2;
            }
            "--from" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    AuditError::Usage("--from requires a height".into())
                })?;
                from = Some(parse_u64(v, "--from")?);
                i += 2;
            }
            "--to" => {
                let v = args.get(i + 1).ok_or_else(|| {
                    AuditError::Usage("--to requires a height".into())
                })?;
                to = Some(parse_u64(v, "--to")?);
                i += 2;
            }
            // #422's flag is extracted by the CALLER (cmd_audit_emission, which
            // parses the hex with the node's own rkm function). This parser must
            // step over the pair, not reject it — rejecting here made `--payee`
            // unreachable from the CLI since the day it merged: parse_args runs
            // first and errored before the caller ever looked for the flag.
            "--payee" => {
                args.get(i + 1).ok_or_else(|| {
                    AuditError::Usage("--payee requires a 64-hex key".into())
                })?;
                i += 2;
            }
            other => {
                return Err(AuditError::Usage(format!(
                    "unknown argument `{other}` (expected --data-dir / --from / --to / --payee)"
                )));
            }
        }
    }
    let data_dir = data_dir.ok_or_else(|| {
        AuditError::Usage("audit-emission requires --data-dir <dir>".into())
    })?;
    Ok((data_dir, from, to))
}

fn parse_u64(s: &str, flag: &str) -> Result<u64, AuditError> {
    s.parse::<u64>()
        .map_err(|_| AuditError::Usage(format!("{flag} expects a non-negative integer, got `{s}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
    use qlab_devnet::header::BlockHeader;
    use qlab_node::emission::{coinbase, coinbase_exact};
    use qlab_node::{genesis_block, ChainStore, MemNode, NodeState, StoredBlock, StoredHeader};

    /// Any proof is accepted — this tool never exercises verification.
    struct AcceptAll;
    impl TxVerifier for AcceptAll {
        fn verify_tx(&self, _: &TxEntry) -> bool {
            true
        }
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        p.push(format!(
            "qumbra-audit-emission-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Miner rkm — non-zero so `validate_body` accepts a non-zero coinbase.
    const RKM: [u64; 4] = [1, 2, 3, 4];

    fn open_fresh(dir: &Path) -> MemNode {
        MemNode::open(dir, genesis_block(T0_GENESIS_DIFFICULTY, 0)).unwrap()
    }

    /// Extend the tip with a coinbase-only block at the given scheduled (or wrong) amount.
    fn extend(node: &mut MemNode, committed_coinbase: u64) -> [u8; 32] {
        let parent = node
            .chain()
            .block(&node.tip_hash())
            .expect("tip block")
            .header();
        let height = parent.height + 1;
        let body = BlockBody::from_single_payee(vec![], committed_coinbase, RKM);
        let header = BlockHeader::child_of(
            &parent,
            height,
            T0_GENESIS_DIFFICULTY,
            body.commitment(),
        );
        node.apply_block(header, body, &AcceptAll).unwrap()
    }

    #[test]
    fn payee_counts_the_blocks_that_paid_a_key_and_says_so_honestly_when_none_did() {
        let dir = temp_dir("payee");
        {
            let mut node = open_fresh(&dir);
            for h in 1..=5 {
                extend(&mut node, coinbase(h));
            }
        }

        // The key every fixture block pays: 5 of 5, with the denominator present so
        // the number can be read as a share.
        let hit = audit_emission(&dir, None, None, Some(RKM)).unwrap().payee.unwrap();
        assert_eq!(hit.blocks, 5);
        assert_eq!(hit.blocks_in_interval, 5);
        assert_eq!(hit.coinbase_bessel, (1..=5).map(|h| u128::from(coinbase(h))).sum::<u128>());

        // A key nothing paid. This zero is a FACT ABOUT THE CHAIN — the whole reason
        // the flag exists (qumbra-deploy #143): a wallet scan's 0 could not be, since
        // the compact wire carries no coinbase_rkm at all (lab #415).
        let mut other = RKM;
        other[0] ^= 1;
        let miss = audit_emission(&dir, None, None, Some(other)).unwrap();
        let t = miss.payee.unwrap();
        assert_eq!(t.blocks, 0);
        assert_eq!(t.blocks_in_interval, 5, "the denominator survives a zero");
        assert_eq!(t.coinbase_bessel, 0);
        let out = miss.format_output();
        assert!(out.contains("NO canonical block"), "a zero must say what it means: {out}");
        assert!(out.contains("#415"), "and point at why a wallet's 0 differs: {out}");

        // Attribution never changes the audit's verdict: a key nobody paid is not a
        // defect, and the exit code must not learn about payees.
        assert_eq!(miss.exit_code(), EXIT_CLEAN);
        assert!(miss.mismatches.is_empty());
    }

    #[test]
    fn clean_chain_reports_zero_mismatches_and_exit_0() {
        let dir = temp_dir("clean");
        {
            let mut node = open_fresh(&dir);
            for h in 1..=5 {
                extend(&mut node, coinbase(h));
            }
            // Drop the node so the log is fully flushed before re-open.
        }
        let report = audit_emission(&dir, None, None, None).unwrap();
        assert_eq!(report.tip, 5);
        assert_eq!(report.from, 1);
        assert_eq!(report.to, 5);
        assert!(report.mismatches.is_empty());
        assert_eq!(report.exit_code(), EXIT_CLEAN);
        assert_eq!(report.format_summary(), "audited 1..=5: 0 mismatches");
        assert!(!report.format_output().contains("MISMATCH"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_adjacent_height_substitution_is_localized() {
        // One block commits coinbase(h+1) at height h — the #299 k=1 shape.
        let dir = temp_dir("k1");
        let bad_height = 3u64;
        {
            let mut node = open_fresh(&dir);
            for h in 1..=5 {
                let committed = if h == bad_height {
                    coinbase(h + 1) // adjacent-height substitution
                } else {
                    coinbase(h)
                };
                extend(&mut node, committed);
            }
        }
        let report = audit_emission(&dir, None, None, None).unwrap();
        assert_eq!(report.exit_code(), EXIT_MISMATCH);
        assert_eq!(report.mismatches.len(), 1);
        let m = &report.mismatches[0];
        assert_eq!(m.height, bad_height);
        assert_eq!(m.committed, coinbase(bad_height + 1));
        assert_eq!(m.expected, coinbase(bad_height));
        assert_eq!(m.delta, coinbase(bad_height + 1) as i128 - coinbase(bad_height) as i128);
        // The adjacent step is negative (schedule decays), matching #299's −4114 shape.
        assert!(m.delta < 0, "decay means coinbase(h+1) < coinbase(h); got {}", m.delta);
        assert_eq!(report.sum_of_deltas(), m.delta);
        let line = m.format_line();
        assert!(line.starts_with("MISMATCH height=3 "));
        assert!(line.contains(&format!("committed={}", m.committed)));
        assert!(line.contains(&format!("expected={}", m.expected)));
        assert!(line.contains(&format!("delta={}", m.delta)));
        assert!(line.contains("hash=") && line.ends_with('…'));
        assert_eq!(
            report.format_summary(),
            format!("audited 1..=5: 1 mismatch, sum of deltas {}", m.delta)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn genesis_is_skipped_not_reported_as_mismatch() {
        let dir = temp_dir("genesis");
        {
            let mut node = open_fresh(&dir);
            extend(&mut node, coinbase(1));
        }
        // Explicit --from 0: height 0 must be "skipped genesis", not a MISMATCH,
        // even though coinbase(0) = 5e9 while the body's payee total is 0.
        let report = audit_emission(&dir, Some(0), None, None).unwrap();
        assert!(report.skipped_genesis);
        assert!(report.mismatches.is_empty());
        assert_eq!(report.exit_code(), EXIT_CLEAN);
        let out = report.format_output();
        assert!(out.starts_with("skipped genesis\n"));
        assert!(out.contains("0 mismatches"));
        assert!(!out.contains("MISMATCH"));
        // Interval exactly {0}:
        let only0 = audit_emission(&dir, Some(0), Some(0), None).unwrap();
        assert!(only0.skipped_genesis);
        assert!(only0.mismatches.is_empty());
        assert_eq!(only0.exit_code(), EXIT_CLEAN);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exit_2_bad_dir() {
        let missing = std::env::temp_dir().join(format!(
            "qumbra-audit-emission-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        let err = audit_emission(&missing, None, None, None).unwrap_err();
        assert_eq!(err.name(), "bad_dir");
        assert!(err.reason().contains("does not exist"));
    }

    #[test]
    fn exit_2_interval_beyond_tip() {
        let dir = temp_dir("beyond");
        {
            let mut node = open_fresh(&dir);
            for h in 1..=3 {
                extend(&mut node, coinbase(h));
            }
        }
        let err = audit_emission(&dir, Some(10), None, None).unwrap_err();
        assert_eq!(err.name(), "interval_beyond_tip");
        assert!(err.reason().contains("--from 10"));

        let err = audit_emission(&dir, Some(1), Some(99), None).unwrap_err();
        assert_eq!(err.name(), "interval_beyond_tip");
        assert!(err.reason().contains("--to 99"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exit_2_unreadable_log_empty_dir_with_from_default() {
        // An empty data dir opens as tip=0; default --from 1 is beyond tip.
        let dir = temp_dir("empty");
        let err = audit_emission(&dir, None, None, None).unwrap_err();
        assert_eq!(err.name(), "interval_beyond_tip");
        let _ = std::fs::remove_dir_all(&dir);
    }

        #[test]
    fn parse_args_steps_over_payee_the_caller_extracts() {
        // The defect this pins: --payee was rejected as unknown by THIS parser
        // before cmd_audit_emission (which owns the flag) ever saw it — so the
        // #422 feature was CLI-unreachable from merge day. Found live 2026-08-18
        // trying to attribute hel1's first blocks.
        let args: Vec<String> = ["--data-dir", "/tmp/x", "--payee", "ab", "--from", "7"]
            .iter().map(|s| s.to_string()).collect();
        let (dir, from, to) = parse_args(&args).expect("--payee must not be rejected here");
        assert_eq!(dir, std::path::PathBuf::from("/tmp/x"));
        assert_eq!(from, Some(7));
        assert_eq!(to, None);
        // and the missing-value shape still errors by name
        let bad: Vec<String> = ["--data-dir", "/tmp/x", "--payee"].iter().map(|s| s.to_string()).collect();
        assert!(parse_args(&bad).is_err());
    }

    #[test]
    fn parse_args_requires_data_dir_and_accepts_bounds() {
        let err = parse_args(&[]).unwrap_err();
        assert_eq!(err.name(), "usage");

        let (dir, from, to) = parse_args(&[
            "--data-dir".into(),
            "/tmp/x".into(),
            "--from".into(),
            "10".into(),
            "--to".into(),
            "20".into(),
        ])
        .unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/x"));
        assert_eq!(from, Some(10));
        assert_eq!(to, Some(20));
    }

    #[test]
    fn short_hash_is_eight_hex_plus_ellipsis() {
        let h = [0xabu8, 0x12, 0xcd, 0x34, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(short_hash(&h), "ab12cd34…");
    }

    // --- lab #520: per-block expected is form-aware ---------------------------

    fn stub_block(height: u64, committed: u64) -> StoredBlock {
        StoredBlock {
            header: StoredHeader {
                prev: [0u8; 32],
                height,
                timestamp: 0,
                difficulty: T0_GENESIS_DIFFICULTY,
                nonce: 0,
                tx_body_commitment: [0u8; 32],
            },
            txs: vec![],
            coinbase: committed,
            coinbase_rkm: RKM,
        }
    }

    /// A v5 block minted at `coinbase_exact` is MATCH; a planted delta is
    /// DIVERGENT with the right number. v4 below the boundary still uses the
    /// grandfathered function.
    #[test]
    fn mismatch_at_is_form_aware_and_v5_exact_is_match() {
        let exact = stub_block(7, coinbase_exact(7));
        assert!(
            mismatch_at(GenesisForm::V5, &exact).is_none(),
            "a v5 block at the exact schedule must not mismatch"
        );
        let wrong = stub_block(7, coinbase_exact(7) + 3);
        let m = mismatch_at(GenesisForm::V5, &wrong).expect("the alarm must still fire");
        assert_eq!(m.height, 7);
        assert_eq!(m.expected, coinbase_exact(7));
        assert_eq!(m.delta, 3);
        assert!(mismatch_at(GenesisForm::V4, &stub_block(7, coinbase(7))).is_none());
    }
}
