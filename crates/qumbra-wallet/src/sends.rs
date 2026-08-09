//! `sends.v1` — the wallet's **local memory of its own sends**, and the one
//! thing in the history ledger that is not a chain fact.
//!
//! ```text
//!   <dir>/sends.v1   0600, versioned, reject-unknown, APPEND-ONLY
//! ```
//!
//! # Why this file exists, and what it is not allowed to become
//!
//! The chain can tell this wallet everything about its history except one
//! field: **who it paid.** A transaction's outputs are ML-KEM ciphertexts
//! addressed to their recipients, and the sender keeps no key that reopens
//! them — that is the privacy property working, not a gap to be closed. So the
//! recipient is recorded locally at send time or it is not recorded at all,
//! and [`crate::history`] renders the difference in the ledger itself:
//! `recipient: qmbs1… (local record)` versus `recipient: not recorded`.
//!
//! 🔴 **Restore-from-mnemonic never recovers this file.** The mnemonic carries
//! the seed, and the seed re-derives every key, every address and — through the
//! chain — every note. It cannot re-derive a memory. A wallet restored onto a
//! new machine has a complete, honest, chain-derived ledger with every
//! `recipient:` line reading `not recorded`, and that is the correct outcome
//! rather than a degraded one.
//!
//! # The join key is the declared nullifiers, not the tx id and not the height
//!
//! The task book for this baton said to join on tx/height. Neither is
//! available on the chain-derived side, and the reasons are structural rather
//! than incidental (reported on the tracking issue before this was built):
//!
//! - `GET /v1/nullifiers` serves **per-block** nullifier lists. There is no
//!   per-transaction grouping on that wire, so a chain-derived send event never
//!   learns which transaction inside the block published which nullifier. A
//!   tx-id join would need a new server route, which is a stop point for this
//!   baton.
//! - The only height a wallet can know at send time is the node's tip when it
//!   built (`VerifiedAnchor::tip_height`). The height the transaction is
//!   **mined** at is strictly later and unknowable then, so a height join
//!   mislabels every send whose block was not the very next one.
//!
//! What *is* exact: the nullifiers the send declared. The wallet knows them at
//! build time, they are precisely what the chain publishes, and they are what
//! the chain-derived side already matches on. So [`SendRecord::nullifiers`] is
//! the join key and the rest of the record is display. The tx id and the
//! submitted-at tip height are still recorded — they are what a person quotes
//! when arguing with a node — they are just not what the join runs on.
//!
//! # Written before the socket, not after
//!
//! The statement tx id is computable locally (`qlab_node::rpc::tx_id` over the
//! declared public surface), so the record is appended **before** `POST /v1/tx`
//! rather than after its answer. A send whose POST never completed is the case
//! where a user most needs to know what they sent, and it is exactly the case
//! an after-the-answer write would lose.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The local send-log file inside the wallet dir.
pub const SENDS_FILE: &str = "sends.v1";

/// The header line this binary writes and the ONLY one it reads.
pub const SENDS_HEADER: &str = "qumbra-wallet sends v1";

/// One recorded send. Every field is what this wallet knew at build time; none
/// of it is read back from the chain, and the ledger labels all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRecord {
    /// The statement tx id, derived locally from the declared public surface —
    /// the same id `POST /v1/tx` answers with (checked against the node's own
    /// answer when one arrives).
    pub txid: [u8; 32],
    /// The serving node's **tip** height when this was submitted. 🔴 Not the
    /// height it was mined at, which is strictly later and unknowable here.
    pub submitted_at_tip: u64,
    /// The amount sent to the recipient, in bessel — the wallet's own figure.
    pub amount: u64,
    /// The posted fee that was declared.
    pub fee: u64,
    /// The recipient's **short** address form, as the sender typed it in.
    pub recipient_short: String,
    /// 🔴 The join key: the nullifiers this send declared on the wire.
    pub nullifiers: Vec<[u8; 32]>,
}

/// Every way the send log refuses. Reject-unknown throughout: a file this
/// binary does not understand is never guessed at, never migrated silently, and
/// never partially believed.
#[derive(Debug)]
pub enum SendLogError {
    Io(io::Error),
    /// A header this binary does not know.
    BadHeader { path: PathBuf, got: String },
    /// A record line this binary cannot read — an unknown leading token, an
    /// unknown or missing key, or a value that does not parse.
    BadRecord { path: PathBuf, line: usize, why: String },
}

impl std::fmt::Display for SendLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendLogError::Io(e) => write!(f, "send log I/O: {e}"),
            SendLogError::BadHeader { path, got } => write!(
                f,
                "unreadable send log {}: header {got:?}; this binary knows `{SENDS_HEADER}` only. \
                 It records only LOCAL enrichment — the recipient of your own past sends — so the \
                 safe fix is moving it aside: the ledger degrades to chain-only, which is complete \
                 and honest, and no funds are at stake",
                path.display()
            ),
            SendLogError::BadRecord { path, line, why } => write!(
                f,
                "unreadable send log {} at line {line}: {why}. Refusing to read a file this binary \
                 only partly understands — a half-read send log would put a confident \
                 `recipient:` label on the wrong event",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SendLogError {}

impl From<io::Error> for SendLogError {
    fn from(e: io::Error) -> Self {
        SendLogError::Io(e)
    }
}

/// The whole log, in the order it was appended.
#[derive(Clone, Debug, Default)]
pub struct SendLog {
    pub records: Vec<SendRecord>,
}

impl SendLog {
    /// Read the log from a wallet dir.
    ///
    /// `Ok(None)` is the **absent file**, which is every wallet that has never
    /// sent from this binary and every wallet restored from a mnemonic. It is
    /// an ordinary state, not a failure: the ledger degrades to chain-only and
    /// says so.
    pub fn load(dir: &Path) -> Result<Option<SendLog>, SendLogError> {
        let path = dir.join(SENDS_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(parse(&path, &text)?))
    }

    /// Append one record, creating the file (0600, with its header) if needed.
    ///
    /// Append-only: nothing here rewrites or reorders what is already on disk,
    /// so a crash mid-write costs at most the record being written and the
    /// reject-unknown parse catches a torn line rather than believing it.
    pub fn append(dir: &Path, record: &SendRecord) -> Result<(), SendLogError> {
        let path = dir.join(SENDS_FILE);
        let fresh = !path.exists();
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        #[cfg(unix)]
        if fresh {
            use std::os::unix::fs::PermissionsExt;
            // Same discipline as `wallet.seed`: this file names who this wallet
            // paid, which is nobody else's business on a shared machine.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        if fresh {
            writeln!(f, "{SENDS_HEADER}")?;
        }
        writeln!(f, "{}", encode_record(record))?;
        Ok(())
    }

    /// Records whose declared nullifiers intersect `spent` — the join
    /// [`crate::history`] runs, and the whole reason nullifiers are recorded.
    ///
    /// An intersection of one is enough and is exact: a send declares this
    /// wallet's own note nullifiers, and those are the same 32-byte values the
    /// block publishes and the ledger groups on.
    pub fn matching<'a>(&'a self, spent: &[[u8; 32]]) -> Vec<&'a SendRecord> {
        self.records
            .iter()
            .filter(|r| r.nullifiers.iter().any(|nf| spent.contains(nf)))
            .collect()
    }
}

fn encode_record(r: &SendRecord) -> String {
    let nfs: Vec<String> = r.nullifiers.iter().map(hex32).collect();
    format!(
        "send txid={} tip={} amount={} fee={} to={} nf={}",
        hex32(&r.txid),
        r.submitted_at_tip,
        r.amount,
        r.fee,
        r.recipient_short,
        nfs.join(",")
    )
}

fn parse(path: &Path, text: &str) -> Result<SendLog, SendLogError> {
    let mut lines = text.lines().enumerate();
    match lines.next() {
        Some((_, h)) if h == SENDS_HEADER => {}
        other => {
            return Err(SendLogError::BadHeader {
                path: path.to_path_buf(),
                got: other.map(|(_, h)| h.to_string()).unwrap_or_default(),
            })
        }
    }
    let mut records = Vec::new();
    for (i, line) in lines {
        let line_no = i + 1;
        if line.is_empty() {
            continue;
        }
        records.push(parse_record(path, line_no, line)?);
    }
    Ok(SendLog { records })
}

fn parse_record(path: &Path, line: usize, text: &str) -> Result<SendRecord, SendLogError> {
    let bad = |why: String| SendLogError::BadRecord { path: path.to_path_buf(), line, why };
    let mut fields = text.split(' ');
    match fields.next() {
        Some("send") => {}
        other => {
            return Err(bad(format!(
                "record kind {other:?} is not one this binary knows (it knows `send`)"
            )))
        }
    }
    let (mut txid, mut tip, mut amount, mut fee, mut to, mut nfs) =
        (None, None, None, None, None, None);
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| bad(format!("field {field:?} is not key=value")))?;
        match key {
            "txid" => {
                txid = Some(parse_hex32(value).ok_or_else(|| bad("txid is not 32 hex bytes".into()))?)
            }
            "tip" => {
                tip = Some(value.parse::<u64>().map_err(|_| bad(format!("tip {value:?}")))?)
            }
            "amount" => {
                amount = Some(value.parse::<u64>().map_err(|_| bad(format!("amount {value:?}")))?)
            }
            "fee" => fee = Some(value.parse::<u64>().map_err(|_| bad(format!("fee {value:?}")))?),
            "to" => to = Some(value.to_string()),
            "nf" => {
                let mut out = Vec::new();
                for h in value.split(',').filter(|s| !s.is_empty()) {
                    out.push(
                        parse_hex32(h).ok_or_else(|| bad(format!("nullifier {h:?} is not 32 hex bytes")))?,
                    );
                }
                if out.is_empty() {
                    return Err(bad("a send declares at least one nullifier".into()));
                }
                nfs = Some(out);
            }
            // 🔴 Reject-unknown, and this is the load-bearing arm: a later
            // format's extra field would otherwise be read as a v1 record with
            // a silently missing meaning.
            other => {
                return Err(bad(format!(
                    "unknown field `{other}`; this binary reads txid/tip/amount/fee/to/nf only"
                )))
            }
        }
    }
    Ok(SendRecord {
        txid: txid.ok_or_else(|| bad("no txid".into()))?,
        submitted_at_tip: tip.ok_or_else(|| bad("no tip".into()))?,
        amount: amount.ok_or_else(|| bad("no amount".into()))?,
        fee: fee.ok_or_else(|| bad("no fee".into()))?,
        recipient_short: to.ok_or_else(|| bad("no to".into()))?,
        nullifiers: nfs.ok_or_else(|| bad("no nf".into()))?,
    })
}

/// Lowercase hex of 32 bytes — the same rendering as [`crate::sync::hex32`],
/// which is where a person reads a root; kept identical so one eye can compare
/// them.
pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_wallet_sends_{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn record(seed: u8) -> SendRecord {
        SendRecord {
            txid: [seed; 32],
            submitted_at_tip: 1234 + u64::from(seed),
            amount: 100_000_000,
            fee: 1_000_000,
            recipient_short: format!("qmbs1short{seed}"),
            nullifiers: vec![[seed.wrapping_add(1); 32], [seed.wrapping_add(2); 32]],
        }
    }

    /// The absent file is a STATE, not a failure — every wallet that has never
    /// sent, and every wallet restored from a mnemonic, is in it.
    #[test]
    fn an_absent_file_is_none_and_never_an_error() {
        let d = tmp("absent");
        assert!(SendLog::load(&d).unwrap().is_none());
    }

    #[test]
    fn records_append_round_trip_and_the_file_is_owner_only() {
        let d = tmp("append");
        SendLog::append(&d, &record(1)).unwrap();
        SendLog::append(&d, &record(2)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join(SENDS_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "it names who this wallet paid");
        }

        let log = SendLog::load(&d).unwrap().expect("the file is there");
        assert_eq!(log.records, vec![record(1), record(2)], "append order, byte-faithful");

        // The header is written exactly once, by the create.
        let text = std::fs::read_to_string(d.join(SENDS_FILE)).unwrap();
        assert_eq!(text.matches(SENDS_HEADER).count(), 1);
        assert_eq!(text.lines().count(), 3);
    }

    /// 🔴 Reject-unknown, on all three surfaces: an unknown header, an unknown
    /// record kind, and an unknown field. None of them is guessed at, and the
    /// refusal names the safe fix.
    #[test]
    fn an_unknown_header_kind_or_field_is_refused_not_guessed() {
        let d = tmp("unknown");

        std::fs::write(d.join(SENDS_FILE), "qumbra-wallet sends v9\n").unwrap();
        let e = SendLog::load(&d).unwrap_err();
        assert!(matches!(e, SendLogError::BadHeader { .. }), "{e}");
        let msg = e.to_string();
        assert!(msg.contains("sends v1"), "{msg}");
        assert!(msg.contains("no funds are at stake"), "{msg}");

        std::fs::write(
            d.join(SENDS_FILE),
            format!("{SENDS_HEADER}\nreceive txid={} tip=1 amount=1 fee=1 to=x nf={}\n", "aa".repeat(32), "bb".repeat(32)),
        )
        .unwrap();
        let e = SendLog::load(&d).unwrap_err();
        assert!(matches!(e, SendLogError::BadRecord { line: 2, .. }), "{e}");
        assert!(e.to_string().contains("it knows `send`"), "{e}");

        std::fs::write(
            d.join(SENDS_FILE),
            format!(
                "{SENDS_HEADER}\nsend txid={} tip=1 amount=1 fee=1 to=x nf={} memo=hi\n",
                "aa".repeat(32),
                "bb".repeat(32)
            ),
        )
        .unwrap();
        let e = SendLog::load(&d).unwrap_err();
        assert!(e.to_string().contains("unknown field `memo`"), "{e}");
        assert!(e.to_string().contains("wrong event"), "{e}");

        // A torn last line (a crash mid-append) is caught the same way, rather
        // than being believed as a shorter record.
        std::fs::write(
            d.join(SENDS_FILE),
            format!("{SENDS_HEADER}\nsend txid={} tip=1 amount=1 fee=1 to=x\n", "aa".repeat(32)),
        )
        .unwrap();
        assert!(SendLog::load(&d).unwrap_err().to_string().contains("no nf"));
    }

    /// The join is the nullifiers, and an intersection of one is enough.
    #[test]
    fn the_join_runs_on_declared_nullifiers_and_nothing_else() {
        let log = SendLog { records: vec![record(1), record(9)] };

        // The chain published only ONE of record(1)'s two declared nullifiers
        // in this wallet's own spent set — the other is the #219 dummy slot's,
        // which is a real nullifier of an invented note and belongs to nobody.
        let matched = log.matching(&[[2u8; 32]]);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0], &record(1));

        assert!(log.matching(&[[0xEE; 32]]).is_empty(), "a spend this wallet never recorded");
        assert!(log.matching(&[]).is_empty());

        // Neither tx id nor height is consulted — deliberately (see the module
        // docs): a record whose tip height and txid are nothing like the event's
        // still joins on the bytes the chain actually published.
        let mut drifted = record(1);
        drifted.submitted_at_tip = 999_999;
        drifted.txid = [0x5A; 32];
        let log = SendLog { records: vec![drifted.clone()] };
        assert_eq!(log.matching(&[[2u8; 32], [3u8; 32]]), vec![&drifted]);
    }
}
