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
//!   qumbra-node mine --dir DIR [--net t1|t2] [--genesis-hash 64hex]
//!                              [--seeds a,b,…] [--genesis-url URL]
//!                              [--rkm 64hex] [--yes-i-backed-up]
//!                              [--index N] [--listen ADDR]
//!   qumbra-node mine --print-net          what net is this binary built for?
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
//! **2. Network identity — selected, verified, overridable.** The seeds, the
//! genesis URL and the pinned genesis hash come from a [`NetProfile`]
//! ([`NET_T1`], [`NET_T2`]) **selected** at build time by the release lane's own
//! `NET` — never a hardwired constant of one net. That distinction is lab #527:
//! the published T2 binary carried T1's pin, downloaded the correct T2 genesis
//! and refused it. [`resolve_identity`] is the selection order and
//! [`STAMPED_GENESIS_HASH`] is the path that needs no Rust literal at all.
//! Genesis is downloaded only if absent and is verified **before anything
//! binds** — a wrong file is refused by name, by URL, and by both hashes, and is
//! never written to disk. See [`verify_genesis_bytes`] for what "byte-verified"
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

/// The four **public** entry points, from `t1-sg-posture-decision` via
/// `docs/join-and-mine.md` §1 (node0 is deliberately not one of them).
///
/// **One list for both nets, and that is a fact about the fleet rather than a
/// simplification.** The cutover repointed the bare service names; it did not
/// move the hosts (`select-release-net.sh`'s `DIAL_PEERS_BOTH`, lab #516). They
/// are still a field of [`NetProfile`] so that a net which *does* move them has
/// somewhere to say so without another edit here.
///
/// 🔴 **Baking these into the binary is a real coupling and it is worth saying
/// out loud**: a fleet address change is now a rebuild, not a doc edit. That is
/// the trade a defaults-in-the-binary command makes, and `--seeds` is the
/// escape hatch for anyone who needs a different set before the next release.
pub const PUBLIC_SEEDS: [&str; 4] =
    ["18.202.166.126:9444", "18.141.177.109:9444", "52.194.224.123:9444", "52.5.0.21:9444"];

/// Where `genesis.qmb` is fetched from when `DIR` does not already have one
/// (`docs/join-and-mine.md` §1, deploy PR #150).
///
/// One URL for both nets **because the bare name is what moved** at cutover
/// (naming §7 as amended, and the reason `select-release-net.sh` must fetch this
/// URL rather than trust it): the same address served T1's genesis before the
/// cutover and T2's after. A binary that pins only the URL and not the hash
/// would therefore silently change nets; that is exactly why the hash is pinned
/// beside it.
pub const PUBLISHED_GENESIS_URL: &str = "https://seed.qumbra.org/genesis.qmb";

/// One net's public identity — everything a joiner must agree with before it
/// binds a socket.
///
/// # Why this is a table and not three constants (lab #527)
///
/// It was three constants, all named `T1_*`, and the T2 release shipped
/// carrying them: the published `t2-644a129` binary downloaded the correct T2
/// genesis and refused it, naming T1's hash as what "this binary expects". The
/// refusal was right — the *pin* was a compile-time constant of one net in a
/// binary the release lane had already parameterised for two (lab #516
/// parameterised the tag, the smoke and the dial peers; `mine` was not in that
/// list).
///
/// The shape that fixes it is the one the release lane already has: an identity
/// **selected** per net rather than hardwired, so an artifact tagged `t2-*`
/// cannot carry T1 identity. See [`resolve_identity`] for the selection order
/// and [`STAMPED_GENESIS_HASH`] for the path that needs no Rust literal at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetProfile {
    /// The net's name, as the release lane spells it (`t1`, `t2`).
    pub net: &'static str,
    /// keccak256 over the canonical encoding of the genesis this net publishes.
    pub genesis_hash: &'static str,
    pub genesis_url: &'static str,
    pub seeds: [&'static str; 4],
}

/// T1 — retired, kept reachable. `select-release-net.sh` can still cut a `t1-*`
/// release and this is the identity such a binary must carry.
pub const NET_T1: NetProfile = NetProfile {
    net: "t1",
    genesis_hash: "138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb",
    genesis_url: PUBLISHED_GENESIS_URL,
    seeds: PUBLIC_SEEDS,
};

/// T2 — the live net.
///
/// 🔴 **This value cannot be derived from anything in this tree, and that is the
/// whole lesson of lab #527.** The live T2 genesis was minted at the launch
/// ceremony from OS-random committee keys
/// ([`GenesisFile::new_t2_with_committee_seeds`]), so the in-tree rehearsal mint
/// [`GenesisFile::new_t2`] hashes to a *different* value — a third number that
/// tracks neither this constant nor the live net. Any test that pins this to an
/// in-tree mint is asserting a falsehood; the guard that keeps it honest is
/// `the_net_table_is_the_release_lanes_net_table`, which compares it to
/// `select-release-net.sh` — the one file in this repo that is checked against
/// the file actually served at [`PUBLISHED_GENESIS_URL`], on every release cut.
pub const NET_T2: NetProfile = NetProfile {
    net: "t2",
    genesis_hash: "d1dad4ea2bc5bfc4880ecf25206d182cddeacc12b0f65eca1a1ce2f27a93e2f3",
    genesis_url: PUBLISHED_GENESIS_URL,
    seeds: PUBLIC_SEEDS,
};

/// Every net this binary can name. Both directions of this list are checked
/// against `select-release-net.sh`: a net the lane can cut and this table does
/// not know is a failure, and so is the reverse.
pub const KNOWN_NETS: [NetProfile; 2] = [NET_T1, NET_T2];

/// The net a build that was **not** cut by the release lane targets.
///
/// Tied by test to `release-binaries.yml`'s own `net:` dispatch default, so a
/// developer's `cargo build` and an unattended release cut cannot disagree about
/// which net is current. A cutover changes this word here and there; the test is
/// what makes forgetting either half loud.
pub const DEFAULT_NET: &str = "t2";

/// The net this binary was built for, stamped at compile time by the release
/// lane (`.github/workflows/release-binaries.yml`) via `QUMBRA_NET` — the same
/// `NET` its preflight resolved through `scripts/select-release-net.sh`.
///
/// Same mechanism as [`crate::release::BUILD_REV`], and for the same reason: the
/// artifact must be able to say what it is. Absent ⇒ [`DEFAULT_NET`].
pub const BUILT_FOR_NET: &str = match option_env!("QUMBRA_NET") {
    Some(net) => net,
    None => DEFAULT_NET,
};

/// The genesis hash the release lane stamped into this binary via
/// `QUMBRA_GENESIS_HASH`.
///
/// 🔴 **This is the path on which a new net needs no Rust literal.** The lane's
/// preflight does not read this hash off a shelf: `select-release-net.sh`
/// downloads the genesis actually being served at [`PUBLISHED_GENESIS_URL`],
/// keccak256s it, and refuses the cut by name unless it matches the pin for the
/// selected net. So a stamped value is, transitively, the identity of the file
/// every joiner will download — measured at cut time, not remembered from one.
///
/// `None` for every build that is not a release build, which is the honest
/// answer and the one [`resolve_identity`] falls back from.
pub const STAMPED_GENESIS_HASH: Option<&str> = option_env!("QUMBRA_GENESIS_HASH");

/// Where the genesis pin this run enforces came from.
///
/// Carried and **printed**, not just used. The lab #527 reproduction was a
/// stranger reading `this binary expects: 138e15…` with no way to ask *why* it
/// expected that — the value had exactly one possible origin and the output
/// still could not name it. Now the line above the refusal says which of four
/// places the number came from, which is the difference between "this build is
/// stale" and "I typo'd a flag".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinSource {
    /// `--genesis-hash HEX` — the operator said so.
    Flag,
    /// `--net NAME` — this binary's table entry for a net named on the command line.
    NetFlag,
    /// `QUMBRA_GENESIS_HASH`, stamped by the release lane's preflight.
    ReleaseStamp,
    /// This binary's built-in table entry for [`BUILT_FOR_NET`].
    BuiltInTable,
}

impl PinSource {
    /// A sentence an operator can act on, naming the mechanism and the lever.
    pub fn describe(&self, net: &str) -> String {
        match self {
            PinSource::Flag => "--genesis-hash on this command line".to_string(),
            PinSource::NetFlag => format!("--net {net}, from this binary's net table"),
            PinSource::ReleaseStamp => {
                format!("stamped into this binary by the release lane for net {net}")
            }
            PinSource::BuiltInTable => format!(
                "this binary's built-in table for net {net} (not a release build; \
                 override with --net or --genesis-hash)"
            ),
        }
    }
}

/// The network identity a `mine` run holds itself to, and where each half of it
/// came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetIdentity {
    pub net: String,
    pub genesis_hash: String,
    pub genesis_url: String,
    pub seeds: Vec<String>,
    pub pin_source: PinSource,
}

impl NetIdentity {
    /// The `--print-net` report: what this binary is built for, in the shape the
    /// release lane's artifact gate greps
    /// (`.github/workflows/scripts/assert-release-artifacts.sh`).
    pub fn report(&self) -> String {
        format!(
            "qumbra-node mine — baked network identity\n\
             net: {net}\n\
             genesis hash: {hash}\n\
             genesis url: {url}\n\
             seeds: {seeds}\n\
             pin source: {src}\n",
            net = self.net,
            hash = self.genesis_hash,
            url = self.genesis_url,
            seeds = self.seeds.join(", "),
            src = self.pin_source.describe(&self.net),
        )
    }
}

/// This binary's table entry for `net`, if it has one.
pub fn profile_for(net: &str) -> Option<NetProfile> {
    KNOWN_NETS.into_iter().find(|p| p.net == net)
}

/// The net names this binary knows, for a refusal that tells you what to type.
pub fn known_net_names() -> String {
    KNOWN_NETS.iter().map(|p| p.net).collect::<Vec<_>>().join(", ")
}

/// A 64-hex genesis hash, lowercased, or a usage error that says what was wrong.
fn parse_genesis_hash(hex: &str) -> Result<String, MineError> {
    let lowered = hex.to_ascii_lowercase();
    if lowered.len() != 64 || !lowered.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(MineError::Usage(format!(
            "--genesis-hash needs 64 hex characters (keccak256 over the genesis file's \
             canonical encoding), got {} character(s)",
            hex.len()
        )));
    }
    Ok(lowered)
}

/// The one internally-inconsistent state a built binary can be in: the release
/// lane stamped one genesis hash for [`BUILT_FOR_NET`] and this binary's own net
/// table holds a different one.
///
/// Neither value can be preferred from inside the process — the stamp is the
/// more recent measurement, the table is the more reviewed one — so it is a
/// refusal. It is also unreachable through the verify lane, where
/// `the_net_table_is_the_release_lanes_net_table` is red for any tree in this
/// state; this is the runtime half, for a build that never ran it.
fn stamp_disagreement() -> Option<MineError> {
    let stamped = STAMPED_GENESIS_HASH?;
    let table = profile_for(BUILT_FOR_NET)?;
    if stamped.eq_ignore_ascii_case(table.genesis_hash) {
        return None;
    }
    Some(MineError::Usage(format!(
        "this binary is internally inconsistent about net {net}: the release lane stamped \
         {stamped} into it, and its own net table says {table}. One of the two is describing a \
         different net, and this command will not guess which. Rebuild from a tree whose net \
         table agrees with .github/workflows/scripts/select-release-net.sh, or pass \
         --genesis-hash explicitly.",
        net = BUILT_FOR_NET,
        table = table.genesis_hash,
    )))
}

/// Resolve the net identity this run will enforce, highest precedence first.
///
/// 1. `--genesis-hash HEX` — an explicit operator pin. Wins over everything,
///    including a release stamp: someone joining a net this binary predates has
///    no other lever, and refusing them would recreate lab #527 from the other
///    side.
/// 2. `--net NAME` — this binary's table entry for a named net.
/// 3. [`STAMPED_GENESIS_HASH`] — what the release lane measured off the
///    published genesis at cut time.
/// 4. This binary's table entry for [`BUILT_FOR_NET`].
///
/// # The one case that refuses
///
/// A release stamp for a net this table **also** knows, whose hashes disagree,
/// is a tree whose Rust table and whose release lane describe different nets. It
/// cannot be resolved here — either value is defensible from inside the process
/// — so it is refused by name rather than silently preferred. It is also
/// unreachable through the verify lane, because
/// `the_net_table_is_the_release_lanes_net_table` is red for any tree in that
/// state; this is the runtime half of that guard, for a build that never ran it.
///
/// A stamp for a net the table does **not** know is accepted, and is the path on
/// which adding a net requires no Rust edit at all.
pub fn resolve_identity(
    net_flag: Option<&str>,
    hash_flag: Option<&str>,
) -> Result<NetIdentity, MineError> {
    // The internal-consistency refusal, applied once and to every path that
    // would otherwise have to choose between the stamp and the table. `--net t1`
    // on a t2 binary is exempt (nothing about t2 is being believed), and
    // `--genesis-hash` is exempt because it supplies the answer the two
    // disagreed about — which is what its refusal text promises.
    if hash_flag.is_none() && net_flag.is_none_or(|n| n == BUILT_FOR_NET) {
        if let Some(e) = stamp_disagreement() {
            return Err(e);
        }
    }

    let (net, profile, mut genesis_hash, mut pin_source) = match net_flag {
        Some(name) => {
            let profile = profile_for(name).ok_or_else(|| {
                MineError::Usage(format!(
                    "--net {name} is not a net this binary knows (it knows: {}). Join it with \
                     --genesis-hash <64hex> --genesis-url <URL> --seeds <host:port,…> instead — \
                     no rebuild needed.",
                    known_net_names()
                ))
            })?;
            (name.to_string(), Some(profile), profile.genesis_hash.to_string(), PinSource::NetFlag)
        }
        None => {
            let profile = profile_for(BUILT_FOR_NET);
            match (STAMPED_GENESIS_HASH, profile) {
                (Some(stamped), _) => (
                    BUILT_FOR_NET.to_string(),
                    profile,
                    stamped.to_ascii_lowercase(),
                    PinSource::ReleaseStamp,
                ),
                (None, Some(p)) => (
                    BUILT_FOR_NET.to_string(),
                    Some(p),
                    p.genesis_hash.to_string(),
                    PinSource::BuiltInTable,
                ),
                (None, None) => {
                    return Err(MineError::Usage(format!(
                        "this binary was built for net {BUILT_FOR_NET}, which it has no genesis \
                         pin for: QUMBRA_NET was set at build time and QUMBRA_GENESIS_HASH was \
                         not, and {BUILT_FOR_NET} is not in this binary's net table ({}). Pass \
                         --net or --genesis-hash, or rebuild with both stamps.",
                        known_net_names()
                    )))
                }
            }
        }
    };

    if let Some(hex) = hash_flag {
        genesis_hash = parse_genesis_hash(hex)?;
        pin_source = PinSource::Flag;
    }

    let (genesis_url, seeds) = match profile {
        Some(p) => (
            p.genesis_url.to_string(),
            p.seeds.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        ),
        // A net known only by its stamp still gets the published defaults; both
        // are overridable and the URL is the one that moved at cutover anyway.
        None => (
            PUBLISHED_GENESIS_URL.to_string(),
            PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        ),
    };

    Ok(NetIdentity { net, genesis_hash, genesis_url, seeds, pin_source })
}

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
    /// The net this run joins — resolved by [`resolve_identity`], never a
    /// compile-time constant of one net (lab #527).
    pub net: String,
    pub seeds: Vec<String>,
    pub genesis_url: String,
    /// The genesis pin this run enforces, at the fetch **and** in the config it
    /// writes. Both sites read this one field; before lab #527 they read the
    /// same hardwired constant twice, and a fix that covered one would have left
    /// the other wrong.
    pub genesis_hash: String,
    pub pin_source: PinSource,
    /// `Some` ⇒ the manual path: no wallet is read, created, or looked for.
    pub rkm: Option<String>,
    pub backed_up: bool,
    pub index: u64,
    pub listen_addr: String,
}

/// What a `mine` command line asks for. `--print-net` is the one invocation that
/// does not prepare a directory, so it is not a [`MineArgs`] with a field set —
/// it does not have a `--dir` at all, and modelling it as one would mean either
/// a fake path or an `Option` every other caller has to unwrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MinePlan {
    /// `--print-net`: report the baked identity and exit. Binds nothing, writes
    /// nothing, reads no wallet, touches no disk.
    PrintNet(NetIdentity),
    Prepare(Box<MineArgs>),
}

/// Everything a `mine` command line can say, before `--dir`'s requirement is
/// applied — the shape both [`MineArgs::parse`] and [`parse_mine`] resolve from.
struct RawArgs {
    dir: Option<PathBuf>,
    net_flag: Option<String>,
    hash_flag: Option<String>,
    seeds: Option<Vec<String>>,
    genesis_url: Option<String>,
    rkm: Option<String>,
    backed_up: bool,
    index: u64,
    listen_addr: String,
    print_net: bool,
}

impl MineArgs {
    /// Parse `mine`'s own flags for a run that prepares a directory.
    ///
    /// `--print-net` is a usage error here by construction — it has no `--dir`
    /// and produces no [`MineArgs`]. Callers that must accept it use
    /// [`parse_mine`], which returns a [`MinePlan`].
    pub fn parse(args: &[String]) -> Result<MineArgs, MineError> {
        match parse_mine(args)? {
            MinePlan::Prepare(a) => Ok(*a),
            MinePlan::PrintNet(_) => Err(MineError::Usage(
                "--print-net reports this binary's baked network identity and exits; it does not \
                 prepare a directory"
                    .into(),
            )),
        }
    }
}

/// Parse `mine`'s own flags. Unknown flags are refused rather than ignored,
/// the same posture `NodeConfig`'s `deny_unknown_fields` takes: a typo that
/// silently does nothing is worse than one that stops you.
pub fn parse_mine(args: &[String]) -> Result<MinePlan, MineError> {
    let raw = parse_raw(args)?;
    let identity = resolve_identity(raw.net_flag.as_deref(), raw.hash_flag.as_deref())?;

    if raw.print_net {
        // Deliberately permissive about the rest of the line: `--print-net`
        // answers "what is this binary" and must not need a wallet, a dir, or a
        // reachable network to answer it.
        return Ok(MinePlan::PrintNet(identity));
    }

    Ok(MinePlan::Prepare(Box::new(MineArgs {
        dir: raw.dir.ok_or_else(|| MineError::Usage("mine requires --dir DIR".into()))?,
        net: identity.net,
        seeds: raw.seeds.unwrap_or(identity.seeds),
        genesis_url: raw.genesis_url.unwrap_or(identity.genesis_url),
        genesis_hash: identity.genesis_hash,
        pin_source: identity.pin_source,
        rkm: raw.rkm,
        backed_up: raw.backed_up,
        index: raw.index,
        listen_addr: raw.listen_addr,
    })))
}

fn parse_raw(args: &[String]) -> Result<RawArgs, MineError> {
    let mut raw = RawArgs {
        dir: None,
        net_flag: None,
        hash_flag: None,
        seeds: None,
        genesis_url: None,
        rkm: None,
        backed_up: false,
        index: 0,
        listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
        print_net: false,
    };

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
                raw.dir = Some(PathBuf::from(value("--dir")?));
                i += 2;
            }
            "--net" => {
                raw.net_flag = Some(value("--net")?);
                i += 2;
            }
            "--genesis-hash" => {
                // Validated here, by the parser, for the same reason `--rkm` is:
                // this is the moment the operator is still looking at the paste.
                raw.hash_flag = Some(parse_genesis_hash(&value("--genesis-hash")?)?);
                i += 2;
            }
            "--print-net" => {
                raw.print_net = true;
                i += 1;
            }
            "--seeds" => {
                let raw_seeds = value("--seeds")?;
                let list: Vec<String> = raw_seeds
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if list.is_empty() {
                    return Err(MineError::Usage(
                        "--seeds needs at least one host:port (comma-separated)".into(),
                    ));
                }
                raw.seeds = Some(list);
                i += 2;
            }
            "--genesis-url" => {
                raw.genesis_url = Some(value("--genesis-url")?);
                i += 2;
            }
            "--rkm" => {
                let hex = value("--rkm")?;
                // Refused HERE, by the node's own parser, rather than at
                // startup: a truncated paste is the likely operator error
                // and this is the moment they are still looking.
                rkm_lanes_from_hex(&hex).map_err(|e| MineError::Usage(format!("--rkm {e}")))?;
                raw.rkm = Some(hex);
                i += 2;
            }
            "--index" => {
                let v = value("--index")?;
                raw.index = v
                    .parse()
                    .map_err(|_| MineError::Usage(format!("--index needs a number, got `{v}`")))?;
                // Bounded because `mine` ALLOCATES up to this index (see
                // `ensure_wallet`): unbounded here would be an unbounded
                // write, i.e. a second denial of service introduced while
                // closing the first.
                if raw.index > MAX_MINE_INDEX {
                    return Err(MineError::Usage(format!(
                        "--index {} is above the {MAX_MINE_INDEX} `mine` allocates up to. \
                         Allocate the index you want with `qumbra-wallet address --new` and pass \
                         its key with --rkm.",
                        raw.index
                    )));
                }
                i += 2;
            }
            "--listen" => {
                raw.listen_addr = value("--listen")?;
                i += 2;
            }
            BACKED_UP_FLAG => {
                raw.backed_up = true;
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

    Ok(raw)
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
         data_dir = {data_dir}\n\
         listen_addr = \"{listen}\"\n\
         dial_peers = [{peers}]\n\
         genesis_file = {genesis}\n\
         expected_genesis_hash = \"{hash}\"\n\
         mining = true\n\
         miner_rkm = \"{rkm}\"\n",
        data_dir = toml_path(&i.data_dir),
        listen = i.listen_addr,
        peers = peers,
        genesis = toml_path(&i.genesis_file),
        hash = i.expected_genesis_hash,
        rkm = i.miner_rkm,
    )
}

/// Render a filesystem path as a TOML string that survives being read back.
///
/// 🔴 **THIS IS A WINDOWS CORRECTNESS FIX, FOUND BY THE lab #478 CI LEG.**
///
/// `render_node_toml` used to interpolate paths into TOML *basic* strings
/// (`data_dir = "…"`). A basic string treats `\` as an escape introducer, and a
/// Windows path is nothing but backslashes — so
/// `data_dir = "C:\Users\RUNNER~1\AppData\..."` made `\U` a unicode escape and
/// the file `mine` had just written **failed to parse**:
///
/// ```text
/// generated config does not parse: TOML parse error at line 4, column 17
///   |
/// 4 | data_dir = "C:\Users\RUNNER~1\AppData\Local\Temp\qmb_mine_prepare_fresh\data"
///   |                 ^ invalid unicode 8-digit hex code
/// ```
///
/// i.e. **`qumbra-node mine` could not work at all on Windows.** Not a test
/// artifact — `prepare` writes the config and reads it back, and a real user's
/// `%USERPROFILE%` path fails identically. It is the same trap the join doc warns
/// human config-writers about; the generator walked straight into it.
///
/// A TOML **literal** string (single quotes) takes its bytes verbatim, which is
/// exactly right for a path — and is identical TOML on every platform, so the
/// unix output changes only its quote character.
///
/// The one thing a literal string cannot hold is a single quote (TOML gives it no
/// escape), so a path containing `'` falls back to a basic string with `\` and
/// `"` escaped. Rare, legal on both unix and Windows, and silently corrupting if
/// unhandled.
fn toml_path(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    if s.contains('\'') || s.chars().any(|c| c.is_control()) {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        format!("'{s}'")
    }
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
    // Printed BEFORE the genesis step, so that a wrong-net refusal has the
    // provenance of the number it refused on the line above it. Lab #527 was
    // diagnosed in five minutes from a refusal that named both hashes; it would
    // have been diagnosed in one from a refusal that also named where the
    // expected hash came from.
    writeln!(
        out,
        "net:      {} — genesis pinned to {}\n          (pin source: {})",
        args.net,
        args.genesis_hash,
        args.pin_source.describe(&args.net)
    )?;

    let wallet = ensure_wallet(args, interactive, input, out)?;

    let genesis_path = args.dir.join(GENESIS_FILE_NAME);
    let genesis =
        ensure_genesis(&genesis_path, &args.genesis_url, &args.genesis_hash, fetch, out)?;

    let data_dir = args.dir.join(DATA_SUBDIR);
    let rendered = render_node_toml(&ConfigInputs {
        data_dir: &data_dir,
        listen_addr: &args.listen_addr,
        seeds: &args.seeds,
        genesis_file: &genesis_path,
        expected_genesis_hash: &args.genesis_hash,
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

    /// The fixture pins **T1** deliberately, and it is worth one sentence: T1 is
    /// the only net whose live identity this tree can also *mint*
    /// (`new_devnet_t0()`), so it is the only net whose end-to-end `prepare`
    /// path can be exercised offline with bytes that actually verify. Every
    /// test below that hands `real_genesis_bytes()` to `prepare` depends on
    /// that, and `an_in_tree_mint_is_not_a_live_nets_identity` is the assertion
    /// that stops anyone reading this coincidence as a general rule.
    fn args_for(dir: &Path) -> MineArgs {
        MineArgs {
            dir: dir.to_path_buf(),
            net: NET_T1.net.to_string(),
            seeds: PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect(),
            genesis_url: PUBLISHED_GENESIS_URL.to_string(),
            genesis_hash: NET_T1.genesis_hash.to_string(),
            pin_source: PinSource::NetFlag,
            rkm: None,
            backed_up: false,
            index: 0,
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
        }
    }

    fn real_genesis_bytes() -> Vec<u8> {
        GenesisFile::new_devnet_t0().to_bytes()
    }

    // ── the net table, and what it is allowed to be checked against ─────────

    /// The release lane's net dispatch, read as text. `select-release-net.sh` is
    /// the only file in this repo whose per-net genesis pin is checked against
    /// the file **actually served** at the published URL — it downloads it,
    /// keccak256s it, and refuses the cut by name on a mismatch. So it is the
    /// closest thing to the live net that an offline test can reach, and this
    /// parser is how the Rust table is held to it.
    const SELECT_RELEASE_NET: &str =
        include_str!("../../../.github/workflows/scripts/select-release-net.sh");

    /// `T1_GENESIS_HASH=…` / `T2_GENESIS_HASH=…` → `("t1", "138e…")`.
    fn script_net_pins() -> Vec<(String, String)> {
        SELECT_RELEASE_NET
            .lines()
            .filter_map(|l| l.split_once('='))
            .filter_map(|(k, v)| {
                let name = k.strip_suffix("_GENESIS_HASH")?;
                // `EXPECTED_HASH="$T1_GENESIS_HASH"` and friends are references,
                // not definitions; only a bare 64-hex literal defines a pin.
                let v = v.trim();
                let is_pin = v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit());
                is_pin.then(|| (name.to_ascii_lowercase(), v.to_string()))
            })
            .collect()
    }

    /// 🔴 **This test replaces the one lab #527 proved could not fail.**
    ///
    /// The guard here used to be `assert_eq!(GenesisFile::new_devnet_t0()
    /// .hash_hex(), T1_EXPECTED_GENESIS_HASH)` — a compiled-in constant compared
    /// against an artifact this same tree mints. Both sides are in-tree, so both
    /// move together or (as happened) neither moves while the live net moves
    /// underneath them. It stayed green through the entire T1→T2 cutover and
    /// through the release cut that shipped a T2 binary carrying T1's pin.
    ///
    /// What it is pinned to now is the release lane's own per-net table, in
    /// **both directions**:
    ///
    /// - every net the lane can cut must exist here with the same hash — so a
    ///   cutover that updates the script and forgets this file is red;
    /// - every net here must exist in the script — so a hand-edited Rust literal
    ///   for a net the lane has never heard of is also red.
    ///
    /// The remaining gap is stated rather than papered over: this is agreement
    /// with a *script*, and the script's own agreement with the live net is
    /// established at release time, not here. Closing that fully needs a network
    /// fetch, which is `smoke-release-artifacts.sh`'s job and cannot be a unit
    /// test. See the PR body.
    #[test]
    fn the_net_table_is_the_release_lanes_net_table() {
        let script = script_net_pins();
        assert!(
            script.len() >= 2,
            "parsed {} pins out of select-release-net.sh — the parser has lost the file's shape, \
             which would make this test vacuous",
            script.len()
        );

        for (net, hash) in &script {
            let profile = profile_for(net).unwrap_or_else(|| {
                panic!(
                    "select-release-net.sh can cut net {net} and this binary's net table cannot \
                     name it. A `mine` from such a build pins the wrong net's genesis — lab #527."
                )
            });
            assert_eq!(
                profile.genesis_hash, hash,
                "net {net}: this binary pins {} and the release lane pins {hash}",
                profile.genesis_hash
            );
        }

        for profile in KNOWN_NETS {
            assert!(
                script.iter().any(|(net, _)| net == profile.net),
                "this binary's net table names {} and select-release-net.sh does not — a pin \
                 nothing checks against the published genesis is exactly the shape lab #527 was",
                profile.net
            );
        }

        // The URL and the seeds are the other two thirds of an identity, and the
        // script is the same single source for both.
        assert!(
            SELECT_RELEASE_NET.contains(&format!("GENESIS_URL_DEFAULT={PUBLISHED_GENESIS_URL}")),
            "the release lane's default genesis URL is not the one this binary fetches"
        );
        let peers = SELECT_RELEASE_NET
            .lines()
            .find(|l| l.starts_with("DIAL_PEERS_BOTH="))
            .expect("the script defines DIAL_PEERS_BOTH");
        for seed in PUBLIC_SEEDS {
            assert!(peers.contains(seed), "the release lane's dial peers omit {seed}");
        }
        assert_eq!(
            peers.matches(':').count(),
            PUBLIC_SEEDS.len(),
            "the lane lists exactly the seeds this binary bakes and no more: {peers}"
        );
    }

    /// 🔴 **The tripwire that stops the old guard being restored.**
    ///
    /// `mine`'s pin for T1 happens to equal `GenesisFile::new_devnet_t0()
    /// .hash_hex()`. That is a **coincidence of T1 having been deployed from the
    /// mint in this tree**, and it is the entire reason the old guard looked
    /// sound. T2 shows what it was worth: the live T2 genesis was minted at the
    /// launch ceremony from OS-random committee keys (`new_t2_with_committee_
    /// seeds`, lab #506), so the in-tree rehearsal mint `new_t2()` hashes to a
    /// third value that tracks neither the live net nor this table.
    ///
    /// If this test ever fails, someone has re-minted `new_t2()` into agreement
    /// with the live net — which cannot happen without the ceremony's secret
    /// keys, so the likelier reading is that one of the two values was edited to
    /// make a test pass.
    #[test]
    fn an_in_tree_mint_is_not_a_live_nets_identity() {
        assert_eq!(
            GenesisFile::new_devnet_t0().hash_hex(),
            NET_T1.genesis_hash,
            "T1 was deployed from this tree's own T0 mint — if this ever stops being true, the \
             offline `prepare` tests that use real_genesis_bytes() need a different fixture"
        );
        assert_ne!(
            GenesisFile::new_t2().hash_hex(),
            NET_T2.genesis_hash,
            "the in-tree T2 mint is the REHEARSAL mint; the live T2 genesis carries ceremony \
             keys. A guard pinning mine's T2 constant to new_t2() would be asserting a \
             falsehood — see this test's doc comment and lab #527."
        );
    }

    /// The net a plain `cargo build` targets is the net the release lane cuts by
    /// default. Two words in two files; this is what makes forgetting either
    /// half loud instead of silent.
    #[test]
    fn the_default_net_is_the_net_the_release_lane_cuts_by_default() {
        const WORKFLOW_RAW: &str = include_str!("../../../.github/workflows/release-binaries.yml");
        // 🔴 Normalise line endings before matching. `include_str!` embeds the file
        // as checked out, and a Windows checkout is CRLF by default — so a pattern
        // ending in `\n` finds nothing there and this test panics on its own
        // `expect` rather than on the property it guards. It did exactly that on
        // the windows leg, invisibly, behind an unrelated red (2026-08-20).
        let workflow = WORKFLOW_RAW.replace("\r\n", "\n");
        let workflow = workflow.as_str();
        assert!(
            profile_for(DEFAULT_NET).is_some(),
            "DEFAULT_NET is {DEFAULT_NET}, which this binary's net table cannot name"
        );
        // The `net:` dispatch input's default, read out of the workflow's own
        // choice block rather than remembered here.
        let net_input = workflow
            .split("      net:\n")
            .nth(1)
            .expect("release-binaries.yml declares a `net:` dispatch input");
        let default_line = net_input
            .lines()
            .find(|l| l.trim_start().starts_with("default:"))
            .expect("the `net:` input declares a default");
        assert!(
            default_line.trim() == format!("default: {DEFAULT_NET}"),
            "release-binaries.yml cuts `{}` by default and this binary defaults to {DEFAULT_NET}",
            default_line.trim()
        );
    }

    /// A build stamped with `QUMBRA_NET` for a net this table cannot name is
    /// only safe if it was also stamped with the hash. Un-stamped builds — every
    /// `cargo build`, every test — must land on a net this table knows.
    #[test]
    fn an_unstamped_build_resolves_to_a_net_it_can_name() {
        if STAMPED_GENESIS_HASH.is_none() {
            let id = resolve_identity(None, None).expect("an unstamped build must resolve");
            assert_eq!(id.net, BUILT_FOR_NET);
            assert_eq!(id.pin_source, PinSource::BuiltInTable);
            assert_eq!(id.genesis_hash, profile_for(BUILT_FOR_NET).unwrap().genesis_hash);
        }
    }

    // ── the baked defaults ───────────────────────────────────────────────────

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
        for seed in PUBLIC_SEEDS {
            assert!(dial.contains(seed), "the guide's dial_peers omits the baked seed {seed}");
        }
        assert_eq!(
            dial.matches(':').count(),
            PUBLIC_SEEDS.len(),
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

        // 🔴 The **selected** net's hash, not a T1 constant. This assertion was
        // red on `main` from 2026-08-19 (`2384283` rebased the guide on T2,
        // leaving only the elided `138e1524…addb` in the retirement note) until
        // this change — a guard whose two sides genuinely could disagree,
        // disagreeing ~19 h before the T2 cut. It went red rather than blind;
        // the shape was right and nothing read it.
        let id = resolve_identity(None, None).expect("this build resolves an identity");
        assert!(
            GUIDE.contains(&id.genesis_hash),
            "the guide does not publish the genesis hash this binary pins ({} for net {})",
            id.genesis_hash,
            id.net
        );
        assert!(
            GUIDE.contains(&id.genesis_url),
            "the guide does not publish the genesis URL this binary fetches"
        );

        // The ZH half is a translation of the same operator instructions, and a
        // joiner who reads it copies the same hash out of it. It carried the
        // launch-ceremony placeholder for a day after the EN half was filled
        // (#525 / #526 / #528), so "the EN one is checked" was not enough.
        const GUIDE_ZH: &str = include_str!("../../../docs/join-and-mine-zh.md");
        assert!(
            GUIDE_ZH.contains(&id.genesis_hash),
            "the ZH join guide does not publish the genesis hash this binary pins"
        );
        assert!(
            GUIDE_ZH.contains(&id.genesis_url),
            "the ZH join guide does not publish the genesis URL this binary fetches"
        );
    }

    /// The four T1 entry points, in the shape `dial_peers` needs. Not a
    /// tautology: a seed that lost its port would parse as a config and fail at
    /// dial time on four hosts at once.
    #[test]
    fn the_baked_seeds_are_four_host_port_pairs() {
        assert_eq!(PUBLIC_SEEDS.len(), 4);
        for s in PUBLIC_SEEDS {
            let (host, port) = s.rsplit_once(':').unwrap_or_else(|| panic!("{s} has no port"));
            assert!(!host.is_empty(), "{s}");
            assert!(port.parse::<u16>().is_ok(), "{s} has a non-numeric port");
        }
        let mut sorted = PUBLIC_SEEDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "four DISTINCT seeds");
    }

    // ── argument parsing ─────────────────────────────────────────────────────

    /// The defaults are **this build's** net, not a hardwired one. On an
    /// un-stamped build that is `DEFAULT_NET`; on a release build it is whatever
    /// the lane stamped, which is the whole point of lab #527.
    #[test]
    fn defaults_are_the_built_for_nets_identity_and_dir_is_required() {
        let a = MineArgs::parse(&["--dir".into(), "/tmp/x".into()]).expect("parse");
        let id = resolve_identity(None, None).expect("this build resolves an identity");
        assert_eq!(a.net, id.net);
        assert_eq!(a.genesis_hash, id.genesis_hash);
        assert_eq!(a.seeds, PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a.genesis_url, PUBLISHED_GENESIS_URL);
        assert_eq!(a.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(a.index, 0);
        assert!(a.rkm.is_none());
        assert!(!a.backed_up);
        assert!(matches!(MineArgs::parse(&[]), Err(MineError::Usage(_))));
    }

    /// 🔴 **The lab #527 regression, at the parse layer.** `--net t2` must pin
    /// T2's genesis and `--net t1` must pin T1's — the two must not be the same
    /// number, which is the single assertion the shipped binary would have
    /// failed.
    #[test]
    fn net_selects_the_pin_and_the_two_nets_are_not_the_same_pin() {
        let t1 = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--net".into(), "t1".into()])
            .expect("parse t1");
        let t2 = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--net".into(), "t2".into()])
            .expect("parse t2");
        assert_eq!(t1.net, "t1");
        assert_eq!(t1.genesis_hash, NET_T1.genesis_hash);
        assert_eq!(t1.pin_source, PinSource::NetFlag);
        assert_eq!(t2.net, "t2");
        assert_eq!(t2.genesis_hash, NET_T2.genesis_hash);
        assert_ne!(
            t1.genesis_hash, t2.genesis_hash,
            "a binary that pins the same genesis for both nets is the #527 defect itself"
        );
    }

    /// An unknown net is refused by name and the refusal says what to type
    /// instead — including the no-rebuild path, because "wait for a release" is
    /// what #527 cost a stranger four hours of.
    #[test]
    fn an_unknown_net_is_refused_by_name_and_names_the_alternative() {
        let e = MineArgs::parse(&["--dir".into(), "/tmp/x".into(), "--net".into(), "t9".into()]);
        match e {
            Err(MineError::Usage(m)) => {
                assert!(m.contains("t9"), "{m}");
                assert!(m.contains("t1, t2"), "{m}");
                assert!(m.contains("--genesis-hash"), "{m}");
            }
            other => panic!("expected a usage refusal, got {other:?}"),
        }
    }

    /// `--genesis-hash` outranks everything, so a binary can join a net it
    /// predates without a rebuild. It is validated at parse, like `--rkm`.
    #[test]
    fn genesis_hash_overrides_every_baked_pin_and_is_validated_at_parse() {
        let want = "a".repeat(64);
        let a = MineArgs::parse(&[
            "--dir".into(),
            "/tmp/x".into(),
            "--net".into(),
            "t1".into(),
            "--genesis-hash".into(),
            want.to_uppercase(),
        ])
        .expect("parse");
        assert_eq!(a.genesis_hash, want, "and it is lowercased");
        assert_eq!(a.pin_source, PinSource::Flag);

        for bad in ["dead", &"z".repeat(64), &"a".repeat(63)] {
            assert!(
                matches!(
                    MineArgs::parse(&[
                        "--dir".into(),
                        "/tmp/x".into(),
                        "--genesis-hash".into(),
                        bad.into()
                    ]),
                    Err(MineError::Usage(_))
                ),
                "{bad} must be refused at parse"
            );
        }
    }

    /// `--print-net` needs no `--dir`, and it reports the net it would have
    /// used. This is what `assert-release-artifacts.sh` greps, so the shape of
    /// the report is load-bearing, not cosmetic.
    #[test]
    fn print_net_reports_the_baked_identity_without_a_dir() {
        match parse_mine(&["--print-net".into()]).expect("parse") {
            MinePlan::PrintNet(id) => {
                let expected = resolve_identity(None, None).expect("resolves");
                assert_eq!(id, expected);
                let report = id.report();
                assert!(report.contains(&format!("net: {}", id.net)), "{report}");
                assert!(
                    report.contains(&format!("genesis hash: {}", id.genesis_hash)),
                    "{report}"
                );
                assert!(report.contains("pin source:"), "{report}");
            }
            MinePlan::Prepare(_) => panic!("--print-net must not prepare a directory"),
        }
        // …and it can still be asked about another net.
        match parse_mine(&["--print-net".into(), "--net".into(), "t1".into()]).expect("parse") {
            MinePlan::PrintNet(id) => assert_eq!(id.genesis_hash, NET_T1.genesis_hash),
            MinePlan::Prepare(_) => panic!("--print-net must not prepare a directory"),
        }
        // `MineArgs::parse` is the prepare-only door and says so.
        assert!(matches!(MineArgs::parse(&["--print-net".into()]), Err(MineError::Usage(_))));
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
            "--net".into(),
            "t1".into(),
            "--genesis-hash".into(),
            "b".repeat(64),
            "--listen".into(),
            "0.0.0.0:9999".into(),
            "--index".into(),
            "3".into(),
            BACKED_UP_FLAG.into(),
        ])
        .expect("parse");
        assert_eq!(a.seeds, vec!["1.2.3.4:9444".to_string(), "5.6.7.8:9444".to_string()]);
        assert_eq!(a.genesis_url, "http://example.invalid/g.qmb");
        // The identity's own two levers, overridden together: this is the
        // no-rebuild path onto a net the binary has never heard of.
        assert_eq!(a.genesis_hash, "b".repeat(64));
        assert_eq!(a.net, "t1");
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
            NET_T1.genesis_hash,
            |_| Ok(bytes.clone()),
            &mut out,
        )
        .expect_err("a different net must be refused");
        match &err {
            MineError::GenesisWrongHash { source, got, want } => {
                assert_eq!(source, "https://evil.invalid/genesis.qmb");
                assert_eq!(want, NET_T1.genesis_hash);
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
        let err = verify_genesis_bytes(&bytes, NET_T1.genesis_hash, "the probe")
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
        let err = verify_genesis_bytes(b"<html>404</html>", NET_T1.genesis_hash, "the URL")
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
            ensure_genesis(&path, PUBLISHED_GENESIS_URL, NET_T1.genesis_hash, |url| {
                assert_eq!(url, PUBLISHED_GENESIS_URL);
                Ok(bytes.clone())
            }, &mut out)
            .expect("the real file verifies");
        assert!(matches!(first, GenesisOutcome::Downloaded { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        // Second run: no fetch at all. The closure panics if it is called.
        let second = ensure_genesis(
            &path,
            PUBLISHED_GENESIS_URL,
            NET_T1.genesis_hash,
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
            PUBLISHED_GENESIS_URL,
            NET_T1.genesis_hash,
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
        let seeds: Vec<String> = PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect();
        let rkm = "0100000000000000020000000000000003000000000000000400000000000000";
        let text = render_node_toml(&ConfigInputs {
            data_dir: Path::new("/m/data"),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new("/m/genesis.qmb"),
            expected_genesis_hash: NET_T1.genesis_hash,
            miner_rkm: rkm,
        });
        let cfg = NodeConfig::from_toml(&text).expect("mine writes a config this binary reads");
        assert_eq!(cfg.data_dir, PathBuf::from("/m/data"));
        assert_eq!(cfg.listen_addr, DEFAULT_LISTEN_ADDR);
        assert_eq!(cfg.dial_peers, seeds);
        assert_eq!(cfg.genesis_file, PathBuf::from("/m/genesis.qmb"));
        assert_eq!(cfg.expected_genesis_hash.as_deref(), Some(NET_T1.genesis_hash));
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
        let seeds: Vec<String> = PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect();

        // `docs/join-and-mine.md` §3: §2's joiner config with the two mining
        // fields changed, written by hand in whatever order the operator likes.
        let hand = format!(
            "mining = true\n\
             miner_rkm = \"{rkm}\"\n\
             data_dir = \"/m/data\"\n\
             listen_addr = \"{DEFAULT_LISTEN_ADDR}\"\n\
             dial_peers = [{peers}]\n\
             genesis_file = \"/m/genesis.qmb\"\n\
             expected_genesis_hash = \"{hash}\"\n",
            peers = seeds.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
            hash = NET_T1.genesis_hash,
        );
        let generated = render_node_toml(&ConfigInputs {
            data_dir: Path::new("/m/data"),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new("/m/genesis.qmb"),
            expected_genesis_hash: NET_T1.genesis_hash,
            miner_rkm: rkm,
        });
        assert_eq!(
            NodeConfig::from_toml(&hand).expect("the documented config parses"),
            NodeConfig::from_toml(&generated).expect("the generated config parses"),
            "a mine-born node must be indistinguishable from a hand-configured one"
        );
    }

    /// 🔴 **Lab #478, found by the windows CI leg: a generated config with a
    /// Windows path did not parse, so `mine` could not work on Windows at all.**
    ///
    /// A TOML *basic* string treats `\` as an escape introducer, so
    /// `data_dir = "C:\Users\..."` reads `\U` as a unicode escape and the file
    /// `prepare` had just written was rejected by its own read-back.
    ///
    /// This test runs on **every** platform on purpose. The defect is a property
    /// of the string the generator emits, not of the OS it runs on, so pinning it
    /// only under `cfg(windows)` would leave the regression invisible to the
    /// arm64 bar — which is exactly how it got here.
    #[test]
    fn a_windows_path_round_trips_through_the_generated_config() {
        let rkm = "0100000000000000020000000000000003000000000000000400000000000000";
        let seeds: Vec<String> = PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect();
        // The literal shape that failed on the runner, backslashes and all.
        let data = r"C:\Users\RUNNER~1\AppData\Local\Temp\qmb_mine\data";
        let genesis = r"C:\Users\RUNNER~1\AppData\Local\Temp\qmb_mine\genesis.qmb";

        let generated = render_node_toml(&ConfigInputs {
            data_dir: Path::new(data),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new(genesis),
            expected_genesis_hash: NET_T1.genesis_hash,
            miner_rkm: rkm,
        });
        let cfg = NodeConfig::from_toml(&generated).unwrap_or_else(|e| {
            panic!("a generated config must parse — that is the whole defect: {e}\n{generated}")
        });
        // Parsing is not enough: the bytes must survive, or `mine` would run
        // against a *different* directory than the one it prepared.
        assert_eq!(cfg.data_dir, Path::new(data), "the path must round-trip verbatim");
        assert_eq!(cfg.genesis_file, Path::new(genesis));
    }

    /// The one input a TOML literal string cannot carry is a single quote, so the
    /// generator falls back to an escaped basic string. Legal on both unix and
    /// Windows, and silently corrupting if unhandled.
    #[test]
    fn a_path_containing_a_quote_still_round_trips() {
        let rkm = "0100000000000000020000000000000003000000000000000400000000000000";
        let seeds: Vec<String> = PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect();
        let data = r"/home/o'brien\odd/data";
        let generated = render_node_toml(&ConfigInputs {
            data_dir: Path::new(data),
            listen_addr: DEFAULT_LISTEN_ADDR,
            seeds: &seeds,
            genesis_file: Path::new("/m/genesis.qmb"),
            expected_genesis_hash: NET_T1.genesis_hash,
            miner_rkm: rkm,
        });
        let cfg = NodeConfig::from_toml(&generated)
            .unwrap_or_else(|e| panic!("quoted-path config must parse: {e}\n{generated}"));
        assert_eq!(cfg.data_dir, Path::new(data));
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
                assert_eq!(url, PUBLISHED_GENESIS_URL);
                Ok(bytes.clone())
            },
            &mut Cursor::new(Vec::new()),
            &mut out,
        )
        .expect("prepare");

        // Lab #527: the run says which net it is joining and where the pin came
        // from, above the point where a wrong genesis would be refused. The
        // reproduction on the shipped binary printed both hashes and no way to
        // tell why the expected one was expected.
        let text = String::from_utf8(out.clone()).expect("utf-8");
        assert!(text.contains("net:      t1 — genesis pinned to"), "{text}");
        assert!(text.contains(NET_T1.genesis_hash), "{text}");
        assert!(text.contains("pin source:"), "{text}");

        let w = qumbra_wallet::store::WalletDir::open(&d.join(WALLET_SUBDIR)).expect("wallet");
        let want = qumbra_wallet::store::miner_rkm_hex(&w.wallet(), 0);

        let cfg = NodeConfig::load(&prepared.config_path).expect("the written config loads");
        assert!(cfg.mining, "a mine-born config mines");
        assert_eq!(cfg.miner_rkm.as_deref(), Some(want.as_str()), "the rkm is the wallet's");
        assert_eq!(prepared.wallet.rkm_hex(), want);
        assert_eq!(cfg.dial_peers, PUBLIC_SEEDS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(cfg.expected_genesis_hash.as_deref(), Some(NET_T1.genesis_hash));
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
            let err = verify_genesis_bytes(&full[..cut], NET_T1.genesis_hash, "the probe")
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
            NET_T1.genesis_hash,
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
