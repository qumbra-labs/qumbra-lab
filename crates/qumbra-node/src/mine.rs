//! `qumbra-node mine --dir DIR` — zero-to-mining in one command (lab #475).
//!
//! Before this, a stranger who wanted to mine walked five manual steps —
//! `qumbra-wallet keygen` → `backup --reveal` → `miner-rkm` → hand-write a
//! `node.toml` → `qumbra-node run` — and all three outside-miner deployments
//! walked them by hand. This module folds those five into one command **without
//! inventing a sixth kind of node**: the last thing it does is write a plain
//! `node.toml` into `DIR` and hand it to the ordinary `run` path, so a
//! `mine`-born machine is a hand-configured machine and every tool that reads a
//! node config keeps working.
//!
//! ```text
//!   qumbra-node mine --dir DIR [--seeds a,b,…] [--genesis-url URL]
//!                              [--rkm 64hex] [--yes-i-backed-up]
//!                              [--index N] [--listen ADDR]
//! ```
//!
//! # The four things it does, and the rule each one bends around
//!
//! **1. Wallet — never silently.** With no wallet in `DIR`, one is generated
//! **through the `qumbra-wallet` kernel** ([`qumbra_wallet::store`]), its
//! mnemonic is printed exactly once behind a red banner, and the run does not
//! proceed until the operator confirms — Enter on a tty, [`BACKED_UP_FLAG`]
//! without one. Non-interactive **and** unflagged is a refusal, not a default:
//! an auto-created wallet accrues real rewards, and Bitcoin Core's
//! auto-`wallet.dat` era is the cautionary record. The seed is written by the
//! wallet kernel and this process keeps only the public `miner_rkm` (see
//! [`WalletOutcome`]). `--rkm` skips all of it — that is today's manual path,
//! unchanged and untouched.
//!
//! **2. Network identity — baked, verified, overridable.** The four T1 seeds,
//! the pinned genesis hash and the genesis URL are constants here
//! ([`T1_SEEDS`], [`T1_EXPECTED_GENESIS_HASH`], [`T1_GENESIS_URL`]). Genesis is
//! downloaded only if absent and is verified **before anything binds** — a
//! wrong file is refused by name, by URL, and by both hashes, and is never
//! written to disk. See [`verify_genesis_bytes`] for what "byte-verified"
//! means here, which is stricter than a hash comparison.
//!
//! **3. Config — transparent.** [`render_node_toml`] emits the same key set the
//! manual path documents (`docs/join-and-mine.md` §3). No hidden state, no
//! private sidecar: everything this command decided is readable in `DIR`.
//!
//! **4. Idempotent, and never destructive.** Re-running `mine` on a prepared
//! directory rewrites nothing and starts the node. If `node.toml` is there but
//! differs from what `mine` would write — an operator's hand edit — the command
//! **refuses and names both remedies** rather than overwriting the edit.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use crate::config::{rkm_lanes_from_hex, NodeConfig};
use crate::genesis::GenesisFile;

/// The four **public** T1 entry points, from `t1-sg-posture-decision` via
/// `docs/join-and-mine.md` §1 (node0 is deliberately not one of them).
///
/// 🔴 **Baking these into the binary is a real coupling and it is worth saying
/// out loud**: a fleet address change is now a rebuild, not a doc edit. That is
/// the trade a defaults-in-the-binary command makes, and `--seeds` is the
/// escape hatch for anyone who needs a different set before the next release.
pub const T1_SEEDS: [&str; 4] =
    ["18.202.166.126:9444", "18.141.177.109:9444", "52.194.224.123:9444", "52.5.0.21:9444"];

/// The T1 genesis hash — the value `expected_genesis_hash` carries in every
/// config on the live net.
///
/// **The task book said "the tree already pins it"; it did not.** Before lab
/// #475 this string existed only inside a `#[cfg(test)]` assertion
/// (`genesis::tests::genesis_hash_is_pinned`), a commented-out line in
/// `qumbra-node.example.toml`, and `release-binaries.yml`'s environment — no
/// constant any code could read. `mine_bakes_the_hash_this_trees_genesis_actually_has`
/// below is what keeps this literal and the tree's own genesis construction
/// from drifting apart silently.
pub const T1_EXPECTED_GENESIS_HASH: &str =
    "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb";

/// Where `genesis.qmb` is fetched from when `DIR` does not already have one
/// (`docs/join-and-mine.md` §1, deploy PR #150).
pub const T1_GENESIS_URL: &str = "https://seed.qumbra.org/genesis.qmb";

/// The P2P listen address a `mine`-born config binds — the same one the joiner
/// config in `docs/join-and-mine.md` §2 uses.
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:9400";

/// The wallet subdirectory `mine` creates inside `DIR`.
///
/// A subdirectory rather than `DIR` itself for two reasons: `qumbra-wallet
/// --dir DIR/wallet` then works verbatim for `backup` / `scan` / `send`, and
/// the seed does not sit beside a `node.toml` that operators copy between hosts
/// and paste into issues. A wallet an operator already made *flat* in `DIR` is
/// still found and used — see [`ensure_wallet`] — so this never generates a
/// second wallet for a directory that already has one.
pub const WALLET_SUBDIR: &str = "wallet";

/// The genesis file name inside `DIR`.
pub const GENESIS_FILE_NAME: &str = "genesis.qmb";

/// The config file name `mine` writes inside `DIR`, then hands to `run`.
pub const CONFIG_FILE_NAME: &str = "node.toml";

/// The node data directory inside `DIR`.
pub const DATA_SUBDIR: &str = "data";

/// The non-interactive backup confirmation. Spelled out rather than `--yes`
/// because it is the one flag here that asserts something about the operator
/// rather than about the machine.
pub const BACKED_UP_FLAG: &str = "--yes-i-backed-up";

/// The ceiling on a fetched `genesis.qmb`, headers included (review finding 1).
///
/// 🔴 **Why a node binary needs this and the wallet did not.** The fetch runs
/// through `qumbra_wallet::net`, whose read was `read_to_end` with no bound —
/// fine for a wallet talking to a server its operator picked, and not fine once
/// the same read lives in the **consensus node binary**: whoever serves this URL
/// could stream until the miner's process died, before any verification ran.
///
/// 4 MiB against a real genesis of ~41 KB is ~100× headroom, so this cannot
/// refuse an artifact the chain actually publishes —
/// `the_genesis_ceiling_has_two_orders_of_magnitude_of_headroom` holds that
/// margin against the tree's own genesis rather than against a remembered
/// number.
///
/// **This cannot become another truncation-reads-as-complete** (the pattern this
/// repo has now paid for nine times): the ceiling produces a **refusal**, never a
/// short body handed onward. Even if it somehow did, a clipped file cannot pass
/// [`verify_genesis_bytes`] — the pinned hash is over the whole canonical
/// encoding — so the failure mode on this path is a named stop, and there is no
/// partial-success verdict available for it to be mistaken for.
pub const MAX_GENESIS_BYTES: usize = 4 * 1024 * 1024;

/// The largest `--index` `mine` will derive a payout key at (review finding 2).
///
/// `mine` allocates every index up to the one it is asked for, so an unbounded
/// value is an unbounded write. The cap exists so that fixing one denial of
/// service does not introduce another: `--index 18446744073709551615` is a typo,
/// not a request. A miner who genuinely wants a high index allocates it with
/// `qumbra-wallet address --new` and passes the key with `--rkm`.
pub const MAX_MINE_INDEX: u64 = 1024;

/// Why `mine` refused. Every variant names the file, URL or flag involved —
/// a refusal an operator cannot act on is a refusal that gets worked around.
#[derive(Debug)]
pub enum MineError {
    Usage(String),
    Io(std::io::Error),
    Wallet(String),
    /// No tty and no [`BACKED_UP_FLAG`]. **Nothing was generated.**
    NoBackupConfirmation,
    /// The download or the file on disk is not a genesis file at all.
    GenesisUndecodable { source: String, why: String },
    /// It decodes, but its bytes are not the canonical encoding of what they
    /// decode to — trailing bytes, or a re-encoding that differs. See
    /// [`verify_genesis_bytes`].
    GenesisNotCanonical { source: String, got_len: usize, canonical_len: usize },
    /// It decodes canonically and is a *different net*.
    GenesisWrongHash { source: String, got: String, want: String },
    /// The fetch itself failed.
    GenesisFetch { url: String, why: String },
    /// `DIR/node.toml` exists and is not what this command would write.
    ConfigWouldBeOverwritten { path: PathBuf },
}

impl std::fmt::Display for MineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MineError::Usage(m) => write!(f, "{m}"),
            MineError::Io(e) => write!(f, "{e}"),
            MineError::Wallet(m) => write!(f, "wallet: {m}"),
            MineError::NoBackupConfirmation => write!(
                f,
                "refusing to create a wallet with nobody watching. This command would generate \
                 a NEW wallet, print its mnemonic once, and start mining real rewards into it — \
                 and stdin is not a terminal, so there is nobody to show the mnemonic to. Run it \
                 on a terminal, or pass {BACKED_UP_FLAG} to say you will capture the mnemonic \
                 from this command's output yourself. Nothing was generated."
            ),
            MineError::GenesisUndecodable { source, why } => write!(
                f,
                "{source} is not a Qumbra genesis file ({why}). Nothing was written and no \
                 socket was opened."
            ),
            MineError::GenesisNotCanonical { source, got_len, canonical_len } => write!(
                f,
                "{source} decodes as a genesis file but its {got_len} bytes are not the \
                 canonical encoding of what they decode to ({canonical_len} bytes). A genesis \
                 file is identified by the hash of its canonical bytes, so a non-canonical one \
                 is refused rather than re-serialized into agreement. Nothing was written."
            ),
            MineError::GenesisWrongHash { source, got, want } => write!(
                f,
                "{source} is a genesis file for a DIFFERENT NET and is refused.\n  \
                 it hashes to: {got}\n  this binary expects: {want}\n\
                 Nothing was written and no socket was opened. If you meant to join another \
                 net, point --genesis-url at its file and put its own genesis.qmb in place \
                 yourself — this command will not mine onto a chain it cannot name."
            ),
            MineError::GenesisFetch { url, why } => write!(
                f,
                "could not fetch the genesis file from {url}: {why}. Download it yourself and \
                 put it at DIR/{GENESIS_FILE_NAME} — this command verifies a file that is \
                 already there exactly as it verifies one it downloaded."
            ),
            MineError::ConfigWouldBeOverwritten { path } => write!(
                f,
                "{} already exists and is not what `mine` would write — it has been edited, or \
                 written by a different invocation. This command will not overwrite an \
                 operator's config. Either run `qumbra-node run --config {}` to keep those \
                 edits, or delete the file and re-run `mine` to regenerate it.",
                path.display(),
                path.display()
            ),
        }
    }
}

impl std::error::Error for MineError {}

impl From<std::io::Error> for MineError {
    fn from(e: std::io::Error) -> Self {
        MineError::Io(e)
    }
}

/// A parsed `mine` command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MineArgs {
    pub dir: PathBuf,
    pub seeds: Vec<String>,
    pub genesis_url: String,
    /// `Some` ⇒ the manual path: no wallet is read, created, or looked for.
    pub rkm: Option<String>,
    pub backed_up: bool,
    pub index: u64,
    pub listen_addr: String,
}

impl MineArgs {
    /// Parse `mine`'s own flags. Unknown flags are refused rather than ignored,
    /// the same posture `NodeConfig`'s `deny_unknown_fields` takes: a typo that
    /// silently does nothing is worse than one that stops you.
    pub fn parse(args: &[String]) -> Result<MineArgs, MineError> {
        let mut dir: Option<PathBuf> = None;
        let mut seeds: Option<Vec<String>> = None;
        let mut genesis_url = T1_GENESIS_URL.to_string();
        let mut rkm: Option<String> = None;
        let mut backed_up = false;
        let mut index: u64 = 0;
        let mut listen_addr = DEFAULT_LISTEN_ADDR.to_string();

        let mut i = 0usize;
        while i < args.len() {
            let a = args[i].as_str();
            // A value-taking flag with no value is a usage error, never a
            // silent fall-through onto the next flag.
            let value = |name: &str| -> Result<String, MineError> {
                args.get(i + 1)
                    .cloned()
                    .filter(|v| !v.starts_with("--"))
                    .ok_or_else(|| MineError::Usage(format!("{name} needs a value")))
            };
            match a {
                "--dir" => {
                    dir = Some(PathBuf::from(value("--dir")?));
                    i += 2;
                }
                "--seeds" => {
                    let raw = value("--seeds")?;
                    let list: Vec<String> = raw
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if list.is_empty() {
                        return Err(MineError::Usage(
                            "--seeds needs at least one host:port (comma-separated)".into(),
                        ));
                    }
                    seeds = Some(list);
                    i += 2;
                }
                "--genesis-url" => {
                    genesis_url = value("--genesis-url")?;
                    i += 2;
                }
                "--rkm" => {
                    let hex = value("--rkm")?;
                    // Refused HERE, by the node's own parser, rather than at
                    // startup: a truncated paste is the likely operator error
                    // and this is the moment they are still looking.
                    rkm_lanes_from_hex(&hex).map_err(|e| MineError::Usage(format!("--rkm {e}")))?;
                    rkm = Some(hex);
                    i += 2;
                }
                "--index" => {
                    let v = value("--index")?;
                    index = v.parse().map_err(|_| {
                        MineError::Usage(format!("--index needs a number, got `{v}`"))
                    })?;
                    // Bounded because `mine` ALLOCATES up to this index (see
                    // `ensure_wallet`): unbounded here would be an unbounded
                    // write, i.e. a second denial of service introduced while
                    // closing the first.
                    if index > MAX_MINE_INDEX {
                        return Err(MineError::Usage(format!(
                            "--index {index} is above the {MAX_MINE_INDEX} `mine` allocates up \
                             to. Allocate the index you want with `qumbra-wallet address --new` \
                             and pass its key with --rkm."
                        )));
                    }
                    i += 2;
                }
                "--listen" => {
                    listen_addr = value("--listen")?;
                    i += 2;
                }
                BACKED_UP_FLAG => {
                    backed_up = true;
                    i += 1;
                }
                "--config" => {
                    return Err(MineError::Usage(
                        "`mine` writes its own config into --dir; if you already have one, run \
                         `qumbra-node run --config FILE` instead"
                            .into(),
                    ))
                }
                // The run path's own flags, forwarded verbatim by `main`.
                "--rehearsal-verifier" => i += 1,
                "--sample-interval-secs" | "--snapshot-interval-secs" => i += 2,
                other => {
                    return Err(MineError::Usage(format!(
                        "unknown flag `{other}` for `mine` (see `qumbra-node --help`)"
                    )))
                }
            }
        }

        Ok(MineArgs {
            dir: dir.ok_or_else(|| MineError::Usage("mine requires --dir DIR".into()))?,
            seeds: seeds.unwrap_or_else(|| T1_SEEDS.iter().map(|s| s.to_string()).collect()),
            genesis_url,
            rkm,
            backed_up,
            index,
            listen_addr,
        })
    }
}

/// What the wallet step did. The mnemonic is deliberately **not** a field here:
/// it is shown to the operator inside [`ensure_wallet`] and never returned, so
/// no caller can accidentally log, format or store it. What leaves the wallet
/// step is the public `miner_rkm` and nothing else — item 4 of the task book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletOutcome {
    /// `--rkm`: no wallet was read, created, or looked for.
    Bypassed { rkm_hex: String },
    Existing { dir: PathBuf, rkm_hex: String },
    Created { dir: PathBuf, rkm_hex: String },
}

impl WalletOutcome {
    pub fn rkm_hex(&self) -> &str {
        match self {
            WalletOutcome::Bypassed { rkm_hex }
            | WalletOutcome::Existing { rkm_hex, .. }
            | WalletOutcome::Created { rkm_hex, .. } => rkm_hex,
        }
    }
}

/// The red banner printed above a freshly generated mnemonic. A stable token
/// (`BACK THIS UP`) so an operator, a test and a support thread can all grep
/// for the same string.
pub const BACKUP_BANNER: &str = "🔴 BACK THIS UP NOW — THIS IS THE ONLY TIME IT IS SHOWN";

/// Find or create the wallet whose rkm this node will mine to.
///
/// Ordering, and it is load-bearing:
///
/// 1. `--rkm` short-circuits before anything looks at the disk.
/// 2. A wallet already in `DIR` (flat) or `DIR/wallet` is **opened, never
///    replaced** — the "existing wallet" acceptance path.
/// 3. Otherwise: refuse first if there is nobody to show a mnemonic to, then
///    generate through the wallet kernel, show the mnemonic once, and gate.
///
/// `interactive` is the caller's answer to "is stdin a terminal" — injected
/// rather than read here so the whole gate is testable without a pty.
pub fn ensure_wallet<R: BufRead, W: Write>(
    args: &MineArgs,
    interactive: bool,
    input: &mut R,
    out: &mut W,
) -> Result<WalletOutcome, MineError> {
    if let Some(hex) = &args.rkm {
        writeln!(
            out,
            "wallet:   not touched — --rkm was given, so this is the manual path exactly as \
             before (no wallet is read, created, or looked for)"
        )?;
        return Ok(WalletOutcome::Bypassed { rkm_hex: hex.clone() });
    }

    let flat = args.dir.clone();
    let nested = args.dir.join(WALLET_SUBDIR);
    let existing = if flat.join(qumbra_wallet::store::SEED_FILE).exists() {
        Some(flat)
    } else if nested.join(qumbra_wallet::store::SEED_FILE).exists() {
        Some(nested.clone())
    } else {
        None
    };

    if let Some(dir) = existing {
        let mut w = qumbra_wallet::store::WalletDir::open(&dir)
            .map_err(|e| MineError::Wallet(e.to_string()))?;
        let rkm_hex = qumbra_wallet::store::miner_rkm_hex(&w.wallet(), args.index);
        writeln!(
            out,
            "wallet:   {} (existing — nothing generated, nothing printed)",
            dir.display()
        )?;
        allocate_payout_index(&mut w, args.index, out)?;
        return Ok(WalletOutcome::Existing { dir, rkm_hex });
    }

    // 🔴 Refuse BEFORE minting. A wallet generated where nobody can see its
    // mnemonic is the failure this gate exists to prevent, and generating one
    // and then erroring would leave exactly that on disk.
    if !interactive && !args.backed_up {
        return Err(MineError::NoBackupConfirmation);
    }

    let mut gate_err: Option<std::io::Error> = None;
    let created = qumbra_wallet::store::create_from_os_entropy_gated(&nested, |mnemonic| {
        // One write of the phrase, one confirmation, and the write comes first
        // so a gate that never returns still leaves the operator with the words.
        let shown = (|| -> std::io::Result<()> {
            writeln!(out)?;
            writeln!(out, "{BACKUP_BANNER}")?;
            writeln!(
                out,
                "A new wallet was generated for this miner. Every coin it mines is paid to it, \
                 and this phrase is the ONLY way to recover them. Write it on paper. It is not \
                 stored anywhere you can read it back from."
            )?;
            writeln!(out)?;
            writeln!(out, "    {mnemonic}")?;
            writeln!(out)?;
            out.flush()
        })();
        if let Err(e) = shown {
            gate_err = Some(e);
            return false;
        }
        if args.backed_up {
            let _ = writeln!(
                out,
                "({BACKED_UP_FLAG} was passed — proceeding without asking. The phrase above is \
                 in this command's output and nowhere else.)"
            );
            return true;
        }
        let asked = (|| -> std::io::Result<bool> {
            write!(out, "Press Enter once you have written it down: ")?;
            out.flush()?;
            let mut line = String::new();
            // 0 bytes = EOF, i.e. nobody answered. A gate that treats silence
            // as consent is not a gate.
            Ok(input.read_line(&mut line)? > 0)
        })();
        match asked {
            Ok(answered) => answered,
            Err(e) => {
                gate_err = Some(e);
                false
            }
        }
    })
    .map_err(|e| MineError::Wallet(e.to_string()))?;

    if let Some(e) = gate_err {
        return Err(MineError::Io(e));
    }

    match created {
        qumbra_wallet::store::GatedCreate::Refused => Err(MineError::NoBackupConfirmation),
        qumbra_wallet::store::GatedCreate::Created(mut w) => {
            let rkm_hex = qumbra_wallet::store::miner_rkm_hex(&w.wallet(), args.index);
            writeln!(out, "wallet:   {} (NEW — back up the phrase above)", nested.display())?;
            writeln!(
                out,
                "          read it again any time with: qumbra-wallet backup --dir {} --reveal",
                nested.display()
            )?;
            allocate_payout_index(&mut w, args.index, out)?;
            Ok(WalletOutcome::Created { dir: nested, rkm_hex })
        }
    }
}

/// Make sure the wallet has **allocated** the index its coinbase is paid at
/// (review finding 2).
///
/// 🔴 **Structural rather than advisory, and that is the whole choice.**
/// `qumbra-wallet miner-rkm` prints a note when the index is not in the
/// allocated set — *"allocate it (`address --new`) so scans cover the coinbase
/// identity"* — and `mine` reproduced the hazard it warns about with no note at
/// all: a freshly created wallet has only index 0, so `mine --index 3` paid an
/// identity **this wallet's own scan does not cover**. A miner would have found
/// out by not finding their money.
///
/// Allocating costs nothing and changes nothing about the money: the diversifier
/// is index-deterministic ([`qumbra_wallet::store::miner_rkm_hex`]'s note), so
/// the payout key is byte-identical whether or not the index is allocated. This
/// is the same write `qumbra-wallet address --new` performs, and it is
/// idempotent — the default index 0 is always already allocated, so the ordinary
/// path does not write at all.
///
/// The `--index` cap ([`MAX_MINE_INDEX`]) is what keeps this loop bounded.
fn allocate_payout_index<W: Write>(
    w: &mut qumbra_wallet::store::WalletDir,
    index: u64,
    out: &mut W,
) -> Result<(), MineError> {
    if w.allocated.contains(&index) {
        return Ok(());
    }
    // Drive the cursor by its own rule — `allocate_next` allocates max+1 — and
    // terminate on the MAX, never on containment. A hand-edited `addresses.v1`
    // with a gap (`[0, 5]`, asked for 3) would spin forever on a
    // `while !contains` loop, because max only ever climbs away from the hole.
    while w.allocated.iter().max().copied().unwrap_or(0) < index {
        w.allocate_next().map_err(|e| MineError::Wallet(e.to_string()))?;
    }
    if !w.allocated.contains(&index) {
        return Err(MineError::Wallet(format!(
            "this wallet's address cursor does not contain index {index} and cannot reach it — \
             it has a gap, so it was not written by this tool. Allocate the index with \
             `qumbra-wallet address --new`, or pass the payout key directly with --rkm."
        )));
    }
    writeln!(
        out,
        "wallet:   allocated address index {index} — the coinbase identity is now inside what \
         this wallet's own scan covers"
    )?;
    Ok(())
}

/// What the genesis step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenesisOutcome {
    AlreadyPresent { path: PathBuf, hash: String },
    Downloaded { path: PathBuf, url: String, bytes: usize, hash: String },
}

/// Verify candidate genesis bytes against a pinned hash, **before** they are
/// written anywhere or anything binds.
///
/// Three checks, and the middle one is why this is not just a hash comparison:
///
/// 1. the bytes decode as a [`GenesisFile`];
/// 2. **they are the canonical encoding of what they decode to.** The pinned
///    hash is `keccak256` over `bincode::serialize(&file)`, not over the file
///    on disk, so bytes with a different framing — trailing padding, a
///    re-encoding — could decode to the right net and still not be the bytes
///    this net publishes. Re-serializing and comparing closes that gap, and
///    means "byte-verified" is literally true;
/// 3. the canonical bytes hash to the pin, and the file passes the same
///    structural `verify_startup` the ordinary run path applies.
///
/// `source` is what the refusal will name — a URL or a path.
pub fn verify_genesis_bytes(
    bytes: &[u8],
    expected_hash: &str,
    source: &str,
) -> Result<String, MineError> {
    let file = GenesisFile::from_bytes(bytes).map_err(|e| MineError::GenesisUndecodable {
        source: source.to_string(),
        why: e.to_string(),
    })?;
    let canonical = file.to_bytes();
    if canonical != bytes {
        return Err(MineError::GenesisNotCanonical {
            source: source.to_string(),
            got_len: bytes.len(),
            canonical_len: canonical.len(),
        });
    }
    file.verify_startup(Some(expected_hash)).map_err(|e| match e {
        crate::genesis::GenesisError::WrongGenesisHash { got, want } => {
            MineError::GenesisWrongHash { source: source.to_string(), got, want }
        }
        other => MineError::GenesisUndecodable {
            source: source.to_string(),
            why: other.to_string(),
        },
    })?;
    Ok(file.hash_hex())
}

/// Put a verified genesis file at `path`, downloading it only if it is absent.
///
/// A file already there is verified too, and by the same function — an operator
/// who dropped the wrong `genesis.qmb` into `DIR` gets the same refusal, by
/// name, that a tampered download gets. `fetch` is injected so the whole of
/// this is testable without a network.
pub fn ensure_genesis<F, W>(
    path: &Path,
    url: &str,
    expected_hash: &str,
    fetch: F,
    out: &mut W,
) -> Result<GenesisOutcome, MineError>
where
    F: FnOnce(&str) -> std::io::Result<Vec<u8>>,
    W: Write,
{
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let hash = verify_genesis_bytes(&bytes, expected_hash, &path.display().to_string())?;
        writeln!(out, "genesis:  {} (already present, verified {hash})", path.display())?;
        return Ok(GenesisOutcome::AlreadyPresent { path: path.to_path_buf(), hash });
    }

    writeln!(out, "genesis:  not in {} — downloading {url}", path.display())?;
    let bytes = fetch(url)
        .map_err(|e| MineError::GenesisFetch { url: url.to_string(), why: e.to_string() })?;
    // Verified BEFORE the write: a refused download must not leave a file
    // behind for the next run to find and trust.
    let hash = verify_genesis_bytes(&bytes, expected_hash, url)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, &bytes)?;
    writeln!(out, "genesis:  {} bytes verified {hash} → {}", bytes.len(), path.display())?;
    Ok(GenesisOutcome::Downloaded {
        path: path.to_path_buf(),
        url: url.to_string(),
        bytes: bytes.len(),
        hash,
    })
}

/// Everything [`render_node_toml`] needs. A struct rather than seven arguments
/// because the test that compares this against the manual path's key set reads
/// better when the inputs are named.
pub struct ConfigInputs<'a> {
    pub data_dir: &'a Path,
    pub listen_addr: &'a str,
    pub seeds: &'a [String],
    pub genesis_file: &'a Path,
    pub expected_genesis_hash: &'a str,
    pub miner_rkm: &'a str,
}

/// The `node.toml` a `mine`-born machine runs on.
///
/// **The same key set the manual path documents** (`docs/join-and-mine.md` §3:
/// `data_dir`, `listen_addr`, `dial_peers`, `genesis_file`,
/// `expected_genesis_hash`, `mining`, `miner_rkm`) — nothing extra, nothing
/// hidden, nothing this binary reads that the file does not say. The header
/// comment is a comment: `NodeConfig` never sees it, and a config with the
/// header stripped is byte-for-byte a hand-written one.
pub fn render_node_toml(i: &ConfigInputs) -> String {
    let peers = i
        .seeds
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "# qumbra-node config — written by `qumbra-node mine` (lab #475).\n\
         # Ordinary node config: nothing here is special to `mine`, and\n\
         # `qumbra-node run --config <this file>` is what `mine` does next.\n\
         data_dir = \"{data_dir}\"\n\
         listen_addr = \"{listen}\"\n\
         dial_peers = [{peers}]\n\
         genesis_file = \"{genesis}\"\n\
         expected_genesis_hash = \"{hash}\"\n\
         mining = true\n\
         miner_rkm = \"{rkm}\"\n",
        data_dir = i.data_dir.display(),
        listen = i.listen_addr,
        peers = peers,
        genesis = i.genesis_file.display(),
        hash = i.expected_genesis_hash,
        rkm = i.miner_rkm,
    )
}

/// Write the config, or refuse to clobber a different one.
///
/// Re-running `mine` on a directory it prepared is a no-op that starts the
/// node; re-running it on a directory whose config somebody edited stops and
/// says so. The comparison is on the whole file, so even a comment change
/// counts as an edit — the conservative direction.
pub fn write_config<W: Write>(
    path: &Path,
    rendered: &str,
    out: &mut W,
) -> Result<(), MineError> {
    if path.exists() {
        let existing = std::fs::read_to_string(path)?;
        if existing == rendered {
            writeln!(out, "config:   {} (unchanged)", path.display())?;
            return Ok(());
        }
        return Err(MineError::ConfigWouldBeOverwritten { path: path.to_path_buf() });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, rendered)?;
    writeln!(out, "config:   {} (written)", path.display())?;
    Ok(())
}

/// The prepared directory: everything `mine` decided, plus the path it is about
/// to hand to the ordinary `run` path.
#[derive(Debug)]
pub struct Prepared {
    pub config_path: PathBuf,
    pub wallet: WalletOutcome,
    pub genesis: GenesisOutcome,
}

/// Wallet → genesis → config, in that order, with nothing bound.
///
/// The order is the task book's and it is not arbitrary: the genesis check is
/// the one that can refuse on a *network identity* mismatch, and it happens
/// before a config exists, which happens before `run` opens a socket.
pub fn prepare<R: BufRead, W: Write>(
    args: &MineArgs,
    interactive: bool,
    fetch: impl FnOnce(&str) -> std::io::Result<Vec<u8>>,
    input: &mut R,
    out: &mut W,
) -> Result<Prepared, MineError> {
    std::fs::create_dir_all(&args.dir)?;
    writeln!(out, "qumbra-node mine — preparing {}", args.dir.display())?;

    let wallet = ensure_wallet(args, interactive, input, out)?;

    let genesis_path = args.dir.join(GENESIS_FILE_NAME);
    let genesis =
        ensure_genesis(&genesis_path, &args.genesis_url, T1_EXPECTED_GENESIS_HASH, fetch, out)?;

    let data_dir = args.dir.join(DATA_SUBDIR);
    let rendered = render_node_toml(&ConfigInputs {
        data_dir: &data_dir,
        listen_addr: &args.listen_addr,
        seeds: &args.seeds,
        genesis_file: &genesis_path,
        expected_genesis_hash: T1_EXPECTED_GENESIS_HASH,
        miner_rkm: wallet.rkm_hex(),
    });
    // The config this command writes must be one this binary can read. A
    // rendering bug that produced an unparseable file would otherwise surface
    // as a confusing failure inside `run`, one stage further from its cause.
    NodeConfig::from_toml(&rendered)
        .map_err(|e| MineError::Usage(format!("generated config does not parse: {e}")))?;

    let config_path = args.dir.join(CONFIG_FILE_NAME);
    write_config(&config_path, &rendered, out)?;

    writeln!(out, "miner:    coinbase paid to {}", wallet.rkm_hex())?;
    writeln!(out, "seeds:    {}", args.seeds.join(", "))?;
    writeln!(out, "starting the ordinary run path on {}", config_path.display())?;
    Ok(Prepared { config_path, wallet, genesis })
}

/// Fetch a whole URL over the workspace's one HTTP client
/// (`qumbra_wallet::net`, rustls under a hand-rolled HTTP/1.1).
///
/// That client takes `(base_url, path_and_query)`; this splits a full URL into
/// the two. `https://host/a/b` → `("https://host", "/a/b")`.
pub fn http_fetch(url: &str) -> std::io::Result<Vec<u8>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!(
            "genesis URL must start with http:// or https:// — got `{url}`"
        )))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    // Bounded (review finding 1): a node binary must not read an unbounded
    // stream from whoever answers this URL. See [`MAX_GENESIS_BYTES`] for why
    // the ceiling cannot become a silent truncation.
    qumbra_wallet::net::http_get_limited(
        &format!("{scheme}://{authority}"),
        &path,
        Some(MAX_GENESIS_BYTES),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_mine_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn args_for(dir: &Path) -> MineArgs {
        MineArgs {
            dir: dir.to_path_buf(),
            seeds: T1_SEEDS.iter().map(|s| s.to_string()).collect(),
            genesis_url: T1_GENESIS_URL.to_string(),
            rkm: None,
            backed_up: false,
            index: 0,
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
        }
    }

    fn real_genesis_bytes() -> Vec<u8> {
        GenesisFile::new_devnet_t0().to_bytes()
    }

    // ── the baked defaults ───────────────────────────────────────────────────

    /// 🔴 The constant this command bakes and the genesis this tree actually
    /// builds are the same net. Without this, `T1_EXPECTED_GENESIS_HASH` is a
    /// literal that can silently outlive the constants it describes — and the
    /// only symptom would be every `mine` host refusing the real genesis file.
    #[test]
    fn mine_bakes_the_hash_this_trees_genesis_actually_has() {
        assert_eq!(GenesisFile::new_devnet_t0().hash_hex(), T1_EXPECTED_GENESIS_HASH);
    }

    /// 🔴 **Review finding 3, closed at the axis that matters.** The baked
    /// defaults are transcribed from `docs/join-and-mine.md`, and until this
    /// test nothing compared them to it — the acceptance-(c) test below builds
    /// its "hand-written" side in Rust, so a doc that drifted (or a
    /// transcription typo made in the first place) was invisible.
    ///
    /// This reads the published guide itself and asserts the three values a
    /// joiner copies out of it are the three this binary bakes. It cannot cover
    /// the seeds *rotating on the fleet* — that needs a live peer and is named
    /// in the PR — but it does cover this binary disagreeing with the document
    /// strangers are told to follow.
    #[test]
    fn the_baked_defaults_are_the_values_the_join_docs_publish() {
        const GUIDE: &str = include_str!("../../../docs/join-and-mine.md");

        // The published joiner config lines, read as text: the doc is the
        // source and this test is the reader, never the other way round.
        let dial = GUIDE
            .lines()
            .find(|l| l.trim_start().starts_with("dial_peers ="))
            .expect("the guide publishes a dial_peers line");
        for seed in T1_SEEDS {
            assert!(dial.contains(seed), "the guide's dial_peers omits the baked seed {seed}");
        }
        assert_eq!(
            dial.matches(':').count(),
            T1_SEEDS.len(),
            "the guide lists exactly the four baked seeds and no fifth: {dial}"
        );

        let listen = GUIDE
            .lines()
            .find(|l| l.trim_start().starts_with("listen_addr ="))
            .expect("the guide publishes a listen_addr line");
        assert!(
            listen.contains(DEFAULT_LISTEN_ADDR),
            "the guide's listen_addr is not what mine binds: {listen}"
        );

        assert!(
            GUIDE.contains(T1_EXPECTED_GENESIS_HASH),
            "the guide does not publish the genesis hash this binary pins"
        );
        assert!(
            GUIDE.contains(T1_GENESIS_URL),
            "the guide does not publish the genesis URL this binary fetches"
        );
    }

    /// The four T1 entry points, in the shape `dial_peers` needs. Not a
    /// tautology: a seed that lost its port would parse as a config and fail at
    /// dial time on four hosts at once.
    #[test]
    fn the_baked_seeds_are_four_host_port_pairs() {
        assert_eq!(T1_SEEDS.len(), 4);
        for s in T1_SEEDS {
            let (host, port) = s.rsplit_once(':').unwrap_or_else(|| panic!("{s} has no port"));
            assert!(!host.is_empty(), "{s}");
            assert!(port.parse::<u16>().is_ok(), "{s} has a non-numeric port");
        }
        let mut sorted = T1_SEEDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "four DISTINCT seeds");
    }

    // ── argument parsing ─────────────────────────────────────────────────────

    #[test]
    fn defaults_are_the_t1_identity_and_dir_is_required() {
        let a = MineArgs::parse(&["--dir".into(), "/tmp/x".into()]).expect("parse");
        assert_eq!(a.seeds, T1_SEEDS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a.genesis_url, T1_GENESIS_URL);
        assert_eq!(a.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(a.index, 0);
        assert!(a.rkm.is_none());
        assert!(!a.backed_up);
        assert!(matches!(MineArgs::parse(&[]), Err(MineError::Usage(_))));
    }

    #[test]
    fn every_default_is_overridable_by_flag() {
        let a = MineArgs::parse(&[
            "--dir".into(),
            "/tmp/x".into(),
            "--seeds".into(),
            "1.2.3.4:9444, 5.6.7.8:9444".into(),
            "--genesis-url".into(),
            "http://example.invalid/g.qmb".into(),
            "--listen".into(),
            "0.0.0.0:9999".into(),
            "--index".into(),
            "3".into(),
            BACKED_UP_FLAG.into(),
        ])
        .expect("parse");
        assert_eq!(a.seeds, vec!["1.2.3.4:9444".to_string(), "5.6.7.8:9444".to_string()]);
        assert_eq!(a.genesis_url, "http://example.invalid/g.qmb");
        assert_eq!(a.listen_addr, "0.0.0.0:9999");
        assert_eq!(a.index, 3);
        assert!(a.backed_up);
    }

    /// A bad `--rkm` is refused at parse, where the operator is still looking,
    /// and by the node's OWN parser rather than a second copy of it.
    #[test]
    fn a_bad_rkm_is_refused_at_parse_by_the_nodes_own_parser() {
        for bad in ["dead", &"0".repeat(64), "zz"] {
            let e = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--rkm".into(), bad.into()]);
            assert!(matches!(e, Err(MineError::Usage(_))), "{bad} must be refused");
        }
        let good = "0100000000000000020000000000000003000000000000000400000000000000";
        let a = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--rkm".into(), good.into()])
            .expect("a valid rkm parses");
        assert_eq!(a.rkm.as_deref(), Some(good));
    }

    #[test]
    fn unknown_flags_and_missing_values_are_refused_never_ignored() {
        assert!(matches!(
            MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--halt-height".into()]),
            Err(MineError::Usage(_))
        ));
        assert!(matches!(MineArgs::parse(&["--dir".into()]), Err(MineError::Usage(_))));
        // `--config` is refused by name: `mine` writes its own.
        let e = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--config".into(), "c".into()]);
        match e {
            Err(MineError::Usage(m)) => assert!(m.contains("run --config"), "{m}"),
            other => panic!("expected a usage refusal, got {other:?}"),
        }
    }

    // ── the backup gate ──────────────────────────────────────────────────────

    /// Acceptance (e): non-interactive without the flag REFUSES, and — the half
    /// that matters — leaves nothing behind. A wallet generated here would be a
    /// wallet accruing rewards that nobody has the phrase for.
    #[test]
    fn non_interactive_without_the_flag_refuses_and_generates_nothing() {
        let d = tmp("noninteractive");
        let args = args_for(&d);
        let mut out = Vec::new();
        let err = ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out)
            .expect_err("must refuse");
        assert!(matches!(err, MineError::NoBackupConfirmation));
        let msg = err.to_string();
        assert!(msg.contains(BACKED_UP_FLAG), "the refusal names the flag: {msg}");
        assert!(msg.contains("Nothing was generated"), "{msg}");
        assert!(!d.join(WALLET_SUBDIR).join(qumbra_wallet::store::SEED_FILE).exists());
        assert!(
            String::from_utf8_lossy(&out).find(BACKUP_BANNER).is_none(),
            "no mnemonic may be printed on the refusal path"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Acceptance (a), the gate half: the mnemonic is printed ONCE behind the
    /// banner, the prompt is written, and the run only proceeds because the
    /// answer was read. The mnemonic is the wallet's real phrase — asserted by
    /// restoring from it — and it appears exactly once in the output.
    #[test]
    fn an_interactive_run_prints_the_mnemonic_once_and_waits_for_the_answer() {
        let d = tmp("interactive");
        let args = args_for(&d);
        let mut out = Vec::new();
        let mut input = Cursor::new(b"\n".to_vec());
        let outcome = ensure_wallet(&args, true, &mut input, &mut out).expect("gate answered");
        let text = String::from_utf8(out).expect("utf-8");

        assert!(text.contains(BACKUP_BANNER), "{text}");
        assert!(text.contains("Press Enter once you have written it down"), "{text}");

        let w = qumbra_wallet::store::WalletDir::open(&d.join(WALLET_SUBDIR)).expect("wallet");
        let phrase = qumbra_wallet::store::reveal_mnemonic(&w);
        assert_eq!(text.matches(&phrase).count(), 1, "the phrase is printed exactly once");
        assert_eq!(
            outcome,
            WalletOutcome::Created {
                dir: d.join(WALLET_SUBDIR),
                rkm_hex: qumbra_wallet::store::miner_rkm_hex(&w.wallet(), 0),
            }
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// EOF is not consent. A gate that treated an empty stdin as "yes" would be
    /// the non-interactive path with extra steps.
    #[test]
    fn eof_at_the_prompt_is_a_refusal_and_writes_no_seed() {
        let d = tmp("eof");
        let args = args_for(&d);
        let mut out = Vec::new();
        let err = ensure_wallet(&args, true, &mut Cursor::new(Vec::new()), &mut out)
            .expect_err("EOF must refuse");
        assert!(matches!(err, MineError::NoBackupConfirmation));
        assert!(!d.join(WALLET_SUBDIR).join(qumbra_wallet::store::SEED_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The non-interactive path that IS allowed: the flag stands in for the
    /// Enter, the phrase is still printed exactly once, and it is still real.
    #[test]
    fn the_backed_up_flag_replaces_the_prompt_and_still_prints_the_phrase_once() {
        let d = tmp("flagged");
        let mut args = args_for(&d);
        args.backed_up = true;
        let mut out = Vec::new();
        ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out).expect("flag accepted");
        let text = String::from_utf8(out).expect("utf-8");
        let w = qumbra_wallet::store::WalletDir::open(&d.join(WALLET_SUBDIR)).expect("wallet");
        assert_eq!(text.matches(&qumbra_wallet::store::reveal_mnemonic(&w)).count(), 1);
        assert!(!text.contains("Press Enter"), "no prompt when the flag answered it: {text}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Acceptance (b): an existing wallet is opened, never regenerated, and
    /// nothing is printed. Also covers the flat layout — a wallet an operator
    /// made themselves at `DIR` is found, so `mine` cannot create a second one.
    #[test]
    fn an_existing_wallet_is_used_and_never_regenerated_in_either_layout() {
        for (tag, sub) in [("existing_nested", Some(WALLET_SUBDIR)), ("existing_flat", None)] {
            let d = tmp(tag);
            let wdir = match sub {
                Some(s) => d.join(s),
                None => d.clone(),
            };
            let w = qumbra_wallet::store::WalletDir::create(
                &wdir,
                qlab_wallet::seed::MasterSeed::from_entropy([0x5A; 32]),
            )
            .expect("seed the fixture wallet");
            let want = qumbra_wallet::store::miner_rkm_hex(&w.wallet(), 0);
            let before = std::fs::read(wdir.join(qumbra_wallet::store::SEED_FILE)).unwrap();

            let args = args_for(&d);
            let mut out = Vec::new();
            let outcome = ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out)
                .expect("an existing wallet needs no gate");
            assert_eq!(outcome, WalletOutcome::Existing { dir: wdir.clone(), rkm_hex: want });
            let text = String::from_utf8(out).unwrap();
            assert!(!text.contains(BACKUP_BANNER), "nothing is printed for an existing wallet");
            assert_eq!(
                std::fs::read(wdir.join(qumbra_wallet::store::SEED_FILE)).unwrap(),
                before,
                "the seed file is untouched"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    /// Acceptance (c): `--rkm` does not read, create, or look for a wallet —
    /// the manual path, unchanged. Proven on a directory that HAS a wallet: the
    /// bypass must not quietly prefer it.
    #[test]
    fn the_rkm_path_never_touches_a_wallet_even_when_one_is_there() {
        let d = tmp("rkm_bypass");
        qumbra_wallet::store::WalletDir::create(
            &d.join(WALLET_SUBDIR),
            qlab_wallet::seed::MasterSeed::from_entropy([0x11; 32]),
        )
        .expect("fixture wallet");
        let mut args = args_for(&d);
        let manual = "0100000000000000020000000000000003000000000000000400000000000000";
        args.rkm = Some(manual.to_string());
        let mut out = Vec::new();
        let outcome = ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out)
            .expect("the manual path needs nothing");
        assert_eq!(outcome, WalletOutcome::Bypassed { rkm_hex: manual.to_string() });
        assert_eq!(outcome.rkm_hex(), manual, "the operator's key, not the wallet's");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── genesis ──────────────────────────────────────────────────────────────

    /// Acceptance (d): a wrong download is refused BY NAME — the URL, the hash
    /// it has, and the hash this binary expects — and no file is written, so
    /// the next run cannot find it and trust it.
    #[test]
    fn a_wrong_genesis_download_is_refused_by_name_and_never_written() {
        let d = tmp("wrong_genesis");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(GENESIS_FILE_NAME);

        // A real, structurally valid genesis file for a DIFFERENT net: same
        // shape, different network name, therefore a different hash. That is a
        // much closer forgery than random bytes, and the one worth refusing.
        let mut other = GenesisFile::new_devnet_t0();
        other.network = format!("{}-imposter", other.network);
        let bytes = other.to_bytes();

        let mut out = Vec::new();
        let err = ensure_genesis(
            &path,
            "https://evil.invalid/genesis.qmb",
            T1_EXPECTED_GENESIS_HASH,
            |_| Ok(bytes.clone()),
            &mut out,
        )
        .expect_err("a different net must be refused");
        match &err {
            MineError::GenesisWrongHash { source, got, want } => {
                assert_eq!(source, "https://evil.invalid/genesis.qmb");
                assert_eq!(want, T1_EXPECTED_GENESIS_HASH);
                assert_eq!(got, &other.hash_hex());
            }
            other => panic!("expected GenesisWrongHash, got {other:?}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("https://evil.invalid/genesis.qmb"), "{msg}");
        assert!(msg.contains("DIFFERENT NET"), "{msg}");
        assert!(msg.contains("no socket was opened"), "{msg}");
        assert!(!path.exists(), "a refused download must not be written");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Trailing bytes decode to the right net under bincode and would pass a
    /// naive hash-of-the-decoded-struct check. They do not pass this one.
    #[test]
    fn non_canonical_bytes_are_refused_even_when_they_decode_to_the_right_net() {
        let mut bytes = real_genesis_bytes();
        let canonical_len = bytes.len();
        bytes.extend_from_slice(b"trailing");
        let err = verify_genesis_bytes(&bytes, T1_EXPECTED_GENESIS_HASH, "the probe")
            .expect_err("padded bytes are not this file");
        match err {
            MineError::GenesisNotCanonical { got_len, canonical_len: c, .. } => {
                assert_eq!(got_len, canonical_len + 8);
                assert_eq!(c, canonical_len);
            }
            other => panic!("expected GenesisNotCanonical, got {other:?}"),
        }
    }

    #[test]
    fn bytes_that_are_not_a_genesis_file_at_all_are_refused_by_source() {
        let err = verify_genesis_bytes(b"<html>404</html>", T1_EXPECTED_GENESIS_HASH, "the URL")
            .expect_err("an error page is not a genesis file");
        assert!(matches!(err, MineError::GenesisUndecodable { .. }));
        assert!(err.to_string().contains("the URL"), "{err}");
    }

    /// The good download: verified, then written, then reported — and the file
    /// on disk is byte-identical to what was verified.
    #[test]
    fn a_correct_download_is_verified_then_written_and_reused_next_time() {
        let d = tmp("good_genesis");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(GENESIS_FILE_NAME);
        let bytes = real_genesis_bytes();

        let mut out = Vec::new();
        let first =
            ensure_genesis(&path, T1_GENESIS_URL, T1_EXPECTED_GENESIS_HASH, |url| {
                assert_eq!(url, T1_GENESIS_URL);
                Ok(bytes.clone())
            }, &mut out)
            .expect("the real file verifies");
        assert!(matches!(first, GenesisOutcome::Downloaded { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        // Second run: no fetch at all. The closure panics if it is called.
        let second = ensure_genesis(
            &path,
            T1_GENESIS_URL,
            T1_EXPECTED_GENESIS_HASH,
            |_| panic!("a present genesis file must not be re-downloaded"),
            &mut out,
        )
        .expect("the present file verifies");
        assert!(matches!(second, GenesisOutcome::AlreadyPresent { .. }));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A wrong file an operator dropped in by hand gets the same refusal a
    /// tampered download gets — the check is on the bytes, not on where they
    /// came from.
    #[test]
    fn a_wrong_genesis_already_on_disk_is_refused_by_path() {
        let d = tmp("wrong_on_disk");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(GENESIS_FILE_NAME);
        let mut other = GenesisFile::new_devnet_t0();
        other.network = format!("{}-imposter", other.network);
        std::fs::write(&path, other.to_bytes()).unwrap();

        let mut out = Vec::new();
        let err = ensure_genesis(
            &path,
            T1_GENESIS_URL,
            T1_EXPECTED_GENESIS_HASH,
            |_| panic!("must not download over a file that is already there"),
            &mut out,
        )
        .expect_err("a wrong file on disk is still a wrong file");
        assert!(err.to_string().contains(&path.display().to_string()), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── the config ───────────────────────────────────────────────────────────

    /// The written config is a config this binary reads, and it carries exactly
    /// the manual path's key set — no more (nothing hidden) and no less
    /// (nothing a hand-written miner config has that this one lacks).
    #[test]
    fn the_written_config_parses_and_carries_the_manual_paths_key_set() {
        let seeds: Vec<String> = T1_SEEDS.iter().map(|s| s.to_string()).collect();
        let rkm = "0100000000000000020000000000000003000000000000000400000000000000";
        let text = render_node_toml(&ConfigInputs {
            data_dir: Path::new("/m/data"),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new("/m/genesis.qmb"),
            expected_genesis_hash: T1_EXPECTED_GENESIS_HASH,
            miner_rkm: rkm,
        });
        let cfg = NodeConfig::from_toml(&text).expect("mine writes a config this binary reads");
        assert_eq!(cfg.data_dir, PathBuf::from("/m/data"));
        assert_eq!(cfg.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(cfg.dial_peers, seeds);
        assert_eq!(cfg.genesis_file, PathBuf::from("/m/genesis.qmb"));
        assert_eq!(cfg.expected_genesis_hash.as_deref(), Some(T1_EXPECTED_GENESIS_HASH));
        assert!(cfg.mining);
        assert_eq!(cfg.miner_rkm.as_deref(), Some(rkm));
        assert_eq!(cfg.miner_rkm_lanes().unwrap(), Some([1, 2, 3, 4]));

        // The key set, literally: `docs/join-and-mine.md` §3's miner config.
        let keys: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
            .map(|l| l.split('=').next().unwrap().trim())
            .collect();
        assert_eq!(
            keys,
            vec![
                "data_dir",
                "listen_addr",
                "dial_peers",
                "genesis_file",
                "expected_genesis_hash",
                "mining",
                "miner_rkm"
            ]
        );
        // No committee keys: a public miner is not a signing node
        // (`docs/join-and-mine.md` §2).
        assert!(cfg.committee_key_paths.is_empty());
        // Discovery is untouched, so it keeps the on-by-default loopback bind a
        // recipient needs. A `mine` host that silently stopped serving it would
        // be a chain that hands discovery to nobody.
        assert_eq!(cfg.discovery_bind(), Some(crate::discovery_server::DEFAULT_DISCOVERY_ADDR));
    }

    /// 🔴 Acceptance (c) as an equality rather than a description. The task book
    /// asks for "byte-identical behavior to today's manual config"; for a config
    /// that means every value the node reads, so this writes out the miner
    /// config `docs/join-and-mine.md` §3 describes — §2's joiner config with the
    /// two mining fields added — and asserts it parses to the same `NodeConfig`
    /// as the one `mine --rkm` generates. The files differ by `mine`'s header
    /// comment, which `NodeConfig` never sees, and a test that compared the
    /// FILES would be pinning a comment.
    ///
    /// **Renamed in the review follow-up.** It used to say
    /// `…_from_the_join_docs`, which claimed more than it asserts: the
    /// hand-written side is built here in Rust, not read from the guide, so doc
    /// drift was invisible to it. That axis is covered on its own now by
    /// `the_baked_defaults_are_the_values_the_join_docs_publish`; this test's
    /// job is the equality, and its name now says only that.
    #[test]
    fn the_rkm_config_equals_an_equivalently_hand_written_config() {
        let rkm = "0100000000000000020000000000000003000000000000000400000000000000";
        let seeds: Vec<String> = T1_SEEDS.iter().map(|s| s.to_string()).collect();

        // `docs/join-and-mine.md` §3: §2's joiner config with the two mining
        // fields changed, written by hand in whatever order the operator likes.
        let hand = format!(
            "mining = true\n\
             miner_rkm = \"{rkm}\"\n\
             data_dir = \"/m/data\"\n\
             listen_addr = \"{DEFAULT_LISTEN_ADDR}\"\n\
             dial_peers = [{peers}]\n\
             genesis_file = \"/m/genesis.qmb\"\n\
             expected_genesis_hash = \"{T1_EXPECTED_GENESIS_HASH}\"\n",
            peers = seeds.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
        );
        let generated = render_node_toml(&ConfigInputs {
            data_dir: Path::new("/m/data"),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new("/m/genesis.qmb"),
            expected_genesis_hash: T1_EXPECTED_GENESIS_HASH,
            miner_rkm: rkm,
        });
        assert_eq!(
            NodeConfig::from_toml(&hand).expect("the documented config parses"),
            NodeConfig::from_toml(&generated).expect("the generated config parses"),
            "a mine-born node must be indistinguishable from a hand-configured one"
        );
    }

    /// Re-running `mine` on its own directory is a no-op; re-running it over a
    /// hand-edited config REFUSES rather than destroying the edit.
    #[test]
    fn a_hand_edited_config_is_never_overwritten_but_an_identical_one_is_a_no_op() {
        let d = tmp("config_guard");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(CONFIG_FILE_NAME);
        let mut out = Vec::new();

        write_config(&path, "mining = true\n", &mut out).expect("first write");
        write_config(&path, "mining = true\n", &mut out).expect("identical is a no-op");
        assert!(String::from_utf8_lossy(&out).contains("unchanged"));

        let err = write_config(&path, "mining = false\n", &mut out).expect_err("must refuse");
        assert!(matches!(err, MineError::ConfigWouldBeOverwritten { .. }));
        assert!(err.to_string().contains("run --config"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "mining = true\n", "edit survives");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── the whole preparation ────────────────────────────────────────────────

    /// Acceptance (a), the end of it: a fresh directory reaches a config whose
    /// `miner_rkm` **is the wallet kernel's own derivation for the wallet that
    /// was just created**, with `mining = true`, and the genesis it pins is the
    /// verified one. This is the assertion the task book asks for; what it does
    /// NOT assert is a block being mined — see the PR body.
    #[test]
    fn a_fresh_dir_prepares_a_mining_config_whose_rkm_is_the_wallets_own() {
        let d = tmp("prepare_fresh");
        let mut args = args_for(&d);
        args.backed_up = true;
        let bytes = real_genesis_bytes();
        let mut out = Vec::new();

        let prepared = prepare(
            &args,
            false,
            |url| {
                assert_eq!(url, T1_GENESIS_URL);
                Ok(bytes.clone())
            },
            &mut Cursor::new(Vec::new()),
            &mut out,
        )
        .expect("prepare");

        let w = qumbra_wallet::store::WalletDir::open(&d.join(WALLET_SUBDIR)).expect("wallet");
        let want = qumbra_wallet::store::miner_rkm_hex(&w.wallet(), 0);

        let cfg = NodeConfig::load(&prepared.config_path).expect("the written config loads");
        assert!(cfg.mining, "a mine-born config mines");
        assert_eq!(cfg.miner_rkm.as_deref(), Some(want.as_str()), "the rkm is the wallet's");
        assert_eq!(prepared.wallet.rkm_hex(), want);
        assert_eq!(cfg.dial_peers, T1_SEEDS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(cfg.expected_genesis_hash.as_deref(), Some(T1_EXPECTED_GENESIS_HASH));
        assert_eq!(cfg.genesis_file, d.join(GENESIS_FILE_NAME));
        assert_eq!(cfg.data_dir, d.join(DATA_SUBDIR));

        // The genesis the config pins is on disk and verifies — the run path
        // would load exactly this.
        let loaded = GenesisFile::load(&cfg.genesis_file).expect("genesis loads");
        loaded.verify_startup(cfg.expected_genesis_hash.as_deref()).expect("and verifies");

        // Idempotent: a second prepare changes nothing and downloads nothing.
        let mut out2 = Vec::new();
        let again = prepare(
            &args,
            false,
            |_| panic!("nothing to download on a prepared dir"),
            &mut Cursor::new(Vec::new()),
            &mut out2,
        )
        .expect("re-prepare");
        assert_eq!(again.wallet.rkm_hex(), want, "no second wallet");
        assert!(String::from_utf8_lossy(&out2).contains("unchanged"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Acceptance (c) at the config level: the `--rkm` path writes the same
    /// config a hand-configured miner has, carrying the operator's own key, and
    /// no wallet is created anywhere in the directory.
    #[test]
    fn the_rkm_path_writes_the_operators_key_and_creates_no_wallet() {
        let d = tmp("prepare_rkm");
        let mut args = args_for(&d);
        let manual = "0100000000000000020000000000000003000000000000000400000000000000";
        args.rkm = Some(manual.to_string());
        let bytes = real_genesis_bytes();
        let mut out = Vec::new();

        let prepared =
            prepare(&args, false, |_| Ok(bytes.clone()), &mut Cursor::new(Vec::new()), &mut out)
                .expect("prepare");
        let cfg = NodeConfig::load(&prepared.config_path).expect("config loads");
        assert_eq!(cfg.miner_rkm.as_deref(), Some(manual));
        assert!(!d.join(WALLET_SUBDIR).exists(), "no wallet directory is created at all");
        assert!(!d.join(qumbra_wallet::store::SEED_FILE).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Acceptance (d) at the command level: the refusal happens with no config
    /// written, so nothing downstream — including `run` — can be reached.
    #[test]
    fn a_wrong_genesis_stops_the_whole_command_before_a_config_exists() {
        let d = tmp("prepare_wrong_genesis");
        let mut args = args_for(&d);
        args.backed_up = true;
        let mut other = GenesisFile::new_devnet_t0();
        other.network = format!("{}-imposter", other.network);
        let bytes = other.to_bytes();
        let mut out = Vec::new();

        let err =
            prepare(&args, false, |_| Ok(bytes.clone()), &mut Cursor::new(Vec::new()), &mut out)
                .expect_err("a different net stops the command");
        assert!(matches!(err, MineError::GenesisWrongHash { .. }));
        assert!(!d.join(CONFIG_FILE_NAME).exists(), "no config is written");
        assert!(!d.join(GENESIS_FILE_NAME).exists(), "no genesis is written");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── the URL split under the one HTTP client ──────────────────────────────

    // ── review finding 1: the fetch is bounded, and bounded fail-closed ──────

    /// The ceiling must be so far above the real artifact that it can never
    /// refuse a genesis file this chain actually publishes. Held against the
    /// tree's own genesis rather than against a number somebody wrote down: a
    /// format change that grew the file 16× would fail here, while there is
    /// still 6× of room left, instead of failing on every miner's first run.
    #[test]
    fn the_genesis_ceiling_has_two_orders_of_magnitude_of_headroom() {
        let real = real_genesis_bytes().len();
        assert!(real > 0);
        assert!(
            real * 16 < MAX_GENESIS_BYTES,
            "genesis is {real} B against a {MAX_GENESIS_BYTES} B ceiling — the margin has \
             eroded; raise the ceiling deliberately rather than discovering it on a miner"
        );
    }

    /// 🔴 **The ceiling cannot re-enter the truncation-reads-as-complete class**
    /// — the pattern this repo has paid for nine times (lab #312 found the ninth
    /// with live money). Two independent reasons, and this test locks the
    /// second, which is the one that survives a mistake in the first:
    ///
    /// 1. the ceiling **refuses**; it never hands a short body onward. There is
    ///    no partial-success verdict on this path to be mistaken for a complete
    ///    one — `ensure_genesis` gets an `Err` and the command stops;
    /// 2. even if a truncated body somehow reached verification, it **cannot
    ///    pass**: the pin is a hash over the whole canonical encoding, so every
    ///    prefix of the real genesis is refused by name.
    ///
    /// That is what makes the bound safe to add. A cap on a *paged* wire would
    /// be the dangerous shape; a cap on a hash-pinned single artifact is
    /// fail-closed by construction.
    #[test]
    fn a_truncated_genesis_is_refused_by_the_pin_not_accepted_as_short() {
        let full = real_genesis_bytes();
        for cut in [1usize, 64, full.len() / 2, full.len() - 1] {
            let err = verify_genesis_bytes(&full[..cut], T1_EXPECTED_GENESIS_HASH, "the probe")
                .expect_err("no prefix of the genesis file is the genesis file");
            // Undecodable or non-canonical — never Ok, and never a wrong-hash
            // ACCEPT. Which of the two it is depends on where the cut lands.
            assert!(
                matches!(
                    err,
                    MineError::GenesisUndecodable { .. }
                        | MineError::GenesisNotCanonical { .. }
                        | MineError::GenesisWrongHash { .. }
                ),
                "cut at {cut} produced {err:?}"
            );
        }
    }

    /// An over-ceiling fetch surfaces as a *named* refusal that reaches the
    /// operator with the URL attached, and — the property that matters — no
    /// file is written for the next run to find and trust.
    #[test]
    fn an_over_ceiling_fetch_is_reported_against_its_url_and_writes_nothing() {
        let d = tmp("fetch_ceiling");
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join(GENESIS_FILE_NAME);
        let mut out = Vec::new();

        let err = ensure_genesis(
            &path,
            "https://hostile.invalid/genesis.qmb",
            T1_EXPECTED_GENESIS_HASH,
            |_| {
                // What `net::http_get_limited` returns once the ceiling trips.
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("response exceeds this route's {MAX_GENESIS_BYTES}-byte ceiling"),
                ))
            },
            &mut out,
        )
        .expect_err("an over-ceiling response must not become a genesis file");
        let msg = err.to_string();
        assert!(matches!(err, MineError::GenesisFetch { .. }), "{err:?}");
        assert!(msg.contains("https://hostile.invalid/genesis.qmb"), "{msg}");
        assert!(msg.contains("ceiling"), "the reason reaches the operator: {msg}");
        assert!(!path.exists(), "nothing is written");
        let _ = std::fs::remove_dir_all(&d);
    }

    // ── review finding 2: the payout index is allocated, not merely used ─────

    /// 🔴 A non-zero `--index` used to pay an identity this wallet's own scan
    /// does not cover, silently — the exact hazard `qumbra-wallet miner-rkm`
    /// prints a note about, reproduced with no note. `mine` allocates it now,
    /// and the payout key is unchanged by the allocation (the diversifier is
    /// index-deterministic), which is what makes the fix free.
    #[test]
    fn a_non_zero_index_is_allocated_so_the_wallets_own_scan_covers_it() {
        let d = tmp("index_alloc");
        let mut args = args_for(&d);
        args.backed_up = true;
        args.index = 3;
        let mut out = Vec::new();

        let outcome = ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out)
            .expect("created + allocated");

        let w = qumbra_wallet::store::WalletDir::open(&d.join(WALLET_SUBDIR)).expect("wallet");
        assert!(w.allocated.contains(&3), "index 3 is allocated: {:?}", w.allocated);
        assert_eq!(w.allocated, vec![0, 1, 2, 3], "and the cursor stayed contiguous");
        assert_eq!(
            outcome.rkm_hex(),
            qumbra_wallet::store::miner_rkm_hex(&w.wallet(), 3),
            "allocation does not move the payout key"
        );
        assert!(String::from_utf8_lossy(&out).contains("allocated address index 3"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The same for a wallet the operator already had, and the two things that
    /// must NOT change while it happens: the seed is untouched, and index 0 —
    /// the ordinary path — writes nothing at all.
    #[test]
    fn allocating_on_an_existing_wallet_leaves_the_seed_alone_and_index_zero_writes_nothing() {
        let d = tmp("index_alloc_existing");
        let wdir = d.join(WALLET_SUBDIR);
        qumbra_wallet::store::WalletDir::create(
            &wdir,
            qlab_wallet::seed::MasterSeed::from_entropy([0x77; 32]),
        )
        .expect("fixture wallet");
        let seed_before = std::fs::read(wdir.join(qumbra_wallet::store::SEED_FILE)).unwrap();
        let cursor_before =
            std::fs::read(wdir.join(qumbra_wallet::store::ADDR_FILE)).unwrap();

        // index 0 is always already allocated: no write, and nothing said.
        let args = args_for(&d);
        let mut out = Vec::new();
        ensure_wallet(&args, false, &mut Cursor::new(Vec::new()), &mut out).expect("existing");
        assert_eq!(
            std::fs::read(wdir.join(qumbra_wallet::store::ADDR_FILE)).unwrap(),
            cursor_before,
            "the default path must not touch the cursor"
        );
        assert!(!String::from_utf8_lossy(&out).contains("allocated address index"));

        // index 2 allocates, and still never touches key material.
        let mut args2 = args_for(&d);
        args2.index = 2;
        let mut out2 = Vec::new();
        ensure_wallet(&args2, false, &mut Cursor::new(Vec::new()), &mut out2).expect("existing");
        let w = qumbra_wallet::store::WalletDir::open(&wdir).expect("wallet");
        assert!(w.allocated.contains(&2));
        assert_eq!(
            std::fs::read(wdir.join(qumbra_wallet::store::SEED_FILE)).unwrap(),
            seed_before,
            "the seed file is untouched by allocation"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The cap that keeps the fix from being a second denial of service: `mine`
    /// allocates *up to* the index, so an unbounded `--index` is an unbounded
    /// write. A typo is refused at parse, naming the escape hatch.
    #[test]
    fn an_index_above_the_cap_is_refused_at_parse_and_names_the_way_round_it() {
        let at_cap = MineArgs::parse(&[
            "--dir".into(),
            "/tmp/x".into(),
            "--index".into(),
            MAX_MINE_INDEX.to_string(),
        ])
        .expect("the cap itself is allowed");
        assert_eq!(at_cap.index, MAX_MINE_INDEX);

        for over in [MAX_MINE_INDEX + 1, u64::MAX] {
            let e = MineArgs::parse(&[
                "--dir".into(),
                "/tmp/x".into(),
                "--index".into(),
                over.to_string(),
            ]);
            match e {
                Err(MineError::Usage(m)) => {
                    assert!(m.contains("--rkm"), "the refusal names the escape hatch: {m}");
                    assert!(m.contains(&MAX_MINE_INDEX.to_string()), "{m}");
                }
                other => panic!("--index {over} must be refused, got {other:?}"),
            }
        }
    }

    /// `http_fetch` only splits a URL; the transport is `qumbra_wallet::net`.
    /// This pins the split, which is the part that can be wrong without a
    /// network to notice it.
    #[test]
    fn a_malformed_genesis_url_is_refused_before_any_socket() {
        let e = http_fetch("seed.qumbra.org/genesis.qmb").expect_err("no scheme");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("http://"), "{e}");
        // A scheme the client does not speak is refused by the client itself,
        // by name, and still before any socket.
        let e = http_fetch("ftp://seed.qumbra.org/genesis.qmb").expect_err("bad scheme");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}
