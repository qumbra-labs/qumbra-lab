//! **The faucet's Annulet mode** (lab #716, B6).
//!
//! An Annulet faucet's stock is the devnet genesis's fee-unit notes (B5's
//! `GET /v1/genesis/notes`), one grant each: a grant is a shape-S spend of
//! one whole stock note to the requester's `rkm` (plus a zero change output),
//! so there is **no change tracking and no harvest loop**. It refuses to run
//! against an L1 form ([`AnnuletFaucet::start`]).
//!
//! The spend assembly it runs on — served witnesses → instance → real prove
//! → the transaction → `POST /v1/tx` — was built here in B6 and promoted to
//! `qlab-l2spend` in C2 (lab #720), which the wallet shares.
//!
//! **On a Candidate A genesis** (format 33, lab #896 H) the stock is paid to
//! the dev key's v2 `rkm`, so a grant is a v2 shape-S spend: the stock note in
//! slot 1 with a leaf of the key's generation-0 tree, device dummies in slots
//! 2 and 3 (`dv`, `d3 = 1`), the intent signed here and attached before
//! `POST /v1/tx`. The leaf cursor lives in an `auth.v1` journal in the
//! faucet's own directory, under the wallet's rules: the advance is persisted
//! before anything is proved, and the faucet holds `auth.lock` for its whole
//! life. Grants go to **version 2** addresses only.

use std::io::Read;
use std::net::SocketAddr;

use std::path::{Path, PathBuf};

use qlab_air::l2::{L2AuthInput, L2TxInput};
use qlab_devnet::forms::GenesisForm;
use qlab_l2spend::v2::{attach, build_s_v2, intent_for, sign_locally, FeeIn, LocalAuth};
use qlab_remote_auth::annulet::journal::{generation_root, AuthJournal, AuthLock, JournalError};
pub use qlab_l2spend::{Built, Endpoint, Out, PlainHttp, Recipient, SpendError};
use qlab_note::hash::digest_bytes;
use qlab_note::kem::Ek;
use qlab_note::l2note::L2Note;

/// The served surfaces over plain HTTP (the faucet's own node, the harness).
pub type Served = qlab_l2spend::Served<PlainHttp>;

/// Served surfaces at a socket address.
pub fn served(addr: SocketAddr) -> Served {
    qlab_l2spend::Served::new(PlainHttp { addr })
}

/// An L2 spend key: the circuit's `sk` and diversifier `d` (its `rkm` is
/// `H(nk ‖ D ‖ d)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendKey {
    pub sk: [u64; 4],
    pub d: [u64; 2],
}

impl SpendKey {
    pub fn rkm(&self) -> [u64; 4] {
        qlab_air::l2p::derive_rkm_l2(&L2TxInput { sk: self.sk, value: 0, asset: 0, rho: [0; 4], rseed: [0; 4], d: self.d })
    }

    /// The key's `nk` (`H(sk ‖ D_N)`).
    pub fn nk(&self) -> [u64; 4] {
        qlab_air::l2::derive_input_l2(&L2TxInput { sk: self.sk, value: 0, asset: 0, rho: [0; 4], rseed: [0; 4], d: self.d }).0
    }

    /// The key's authorization secret, by the wallet's rule
    /// (`qlab_wallet::Wallet::auth_secret`: the `sk` lanes as bytes).
    pub fn auth_secret(&self) -> [u8; 32] {
        digest_bytes(&self.sk)
    }

    /// The key's Candidate A `rkm` under the authorization root `auth_root`
    /// (`H(nk ‖ D_R ‖ d ‖ auth_root)`).
    pub fn rkm_v2(&self, auth_root: &[u64; 4]) -> [u64; 4] {
        qlab_air::l2::l2_rkm_v2(&self.nk(), &self.d, auth_root)
    }
}

/// A note this key can spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedNote {
    pub note: L2Note,
    pub key: SpendKey,
}

impl OwnedNote {
    /// The circuit input spending this note. Panics if the key does not own it.
    pub fn input(&self) -> L2TxInput {
        assert_eq!(self.key.rkm(), self.note.rkm, "the spend key owns the note");
        let n = &self.note;
        L2TxInput { sk: self.key.sk, value: n.value, asset: n.asset, rho: n.rho, rseed: n.rseed, d: self.key.d }
    }

    /// The nullifier spending this note publishes (the circuit's `nf`).
    pub fn nullifier(&self) -> [u8; 32] {
        digest_bytes(&qlab_air::l2::derive_input_l2(&self.input()).1)
    }
}

/// Why the Annulet faucet could not proceed — by name.
#[derive(Debug)]
pub enum AnnuletError {
    /// The node runs an L1 chain: the Annulet faucet refuses to start.
    NotAnnulet,
    /// The spend assembly or the node said no.
    Spend(SpendError),
    /// Every stock note is spent.
    StockExhausted,
    /// The Candidate A journal refused (locked, malformed, exhausted, I/O).
    Journal(JournalError),
    /// A Candidate A faucet with no journal whose key has already spent
    /// stock on this chain: its used leaves are unknown, so it refuses to
    /// sign rather than risk reusing one.
    JournalLost { spent: usize },
    /// The journal in the faucet's directory is not this key's
    /// generation-0 journal.
    JournalForeign(String),
    /// Signing or attaching the authorization section failed.
    Auth(String),
}

impl From<JournalError> for AnnuletError {
    fn from(e: JournalError) -> Self {
        AnnuletError::Journal(e)
    }
}

impl From<SpendError> for AnnuletError {
    fn from(e: SpendError) -> Self {
        AnnuletError::Spend(e)
    }
}

impl std::fmt::Display for AnnuletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnuletError::NotAnnulet => write!(f, "the node runs an L1 chain; the Annulet faucet refuses to start (lab #716)"),
            AnnuletError::Spend(e) => write!(f, "{e}"),
            AnnuletError::StockExhausted => write!(f, "every genesis stock note is spent"),
            AnnuletError::Journal(e) => write!(f, "the faucet's authorization journal: {e}"),
            AnnuletError::JournalLost { spent } => write!(
                f,
                "the faucet has no authorization journal, but {spent} of its stock note(s) are already spent on \
                 this chain: the leaves they used are unknown, so the faucet refuses to sign (lab #896 H)"
            ),
            AnnuletError::JournalForeign(why) => write!(f, "the authorization journal is not this faucet's: {why}"),
            AnnuletError::Auth(why) => write!(f, "authorization: {why}"),
        }
    }
}

impl std::error::Error for AnnuletError {}

/// **The Annulet faucet**: genesis stock, one whole note per grant.
///
/// Its stock is the genesis notes its key owns, less every one whose
/// nullifier the chain already carries — so a restarted faucet never
/// re-offers a note it granted before (the L1 faucet's #310, by construction).
pub struct AnnuletFaucet {
    served: Served,
    key: SpendKey,
    change: Recipient,
    stock: Vec<L2Note>,
    next: usize,
    fee_s: u64,
    /// `Some` on a Candidate A genesis.
    v2: Option<CandidateA>,
}

/// How many blocks a faucet grant's authorization stays valid past the
/// node's tip: the wallet's default (`qumbra-wallet --valid-for`), well
/// under the consensus cap `MAX_AUTH_VALIDITY_BLOCKS`.
pub const GRANT_VALIDITY_BLOCKS: u64 = 256;

/// The Candidate A half of a faucet: the journal under its lock (held for
/// the faucet's life), the generation-0 keys, and the net it signs for.
struct CandidateA {
    lock: AuthLock,
    dir: PathBuf,
    journal: AuthJournal,
    keys: LocalAuth,
    genesis_hash: [u8; 32],
    genesis_format: u32,
}

impl AnnuletFaucet {
    /// Start against a node: refuses by name unless `form` is Annulet, then
    /// reads its stock from the node — the genesis notes this key owns whose
    /// nullifiers are not on chain.
    pub fn start(served: Served, form: GenesisForm, key: SpendKey, change_ek: Ek, fee_s: u64) -> Result<Self, AnnuletError> {
        match form {
            GenesisForm::V4 | GenesisForm::V5 => return Err(AnnuletError::NotAnnulet),
            GenesisForm::Annulet => {}
        }
        let rkm = key.rkm();
        let spent = served.spent_nullifiers()?;
        let stock = served
            .genesis_notes()?
            .1
            .into_iter()
            .filter(|n| n.rkm == rkm && n.asset == 0)
            .filter(|n| !spent.contains(&OwnedNote { note: *n, key }.nullifier()))
            .collect();
        Ok(Self { served, key, change: Recipient { rkm, ek: change_ek }, stock, next: 0, fee_s, v2: None })
    }

    /// Start a **Candidate A** faucet (lab #896 H): the stock is the genesis
    /// notes paid to the key's generation-0 v2 `rkm` whose v2 nullifiers are
    /// not on chain, and grants are signed with that generation's leaves,
    /// their cursor kept in `dir`'s `auth.v1` under `auth.lock` (held until
    /// the faucet drops).
    ///
    /// Refuses by name: another holder of the lock; a journal that is not
    /// this key's generation-0 journal; and a missing journal when any of
    /// the key's stock is already spent on chain (its used leaves would be
    /// unknown).
    pub fn start_v2(
        served: Served,
        key: SpendKey,
        change_ek: Ek,
        fee_s: u64,
        dir: &Path,
        genesis_hash: [u8; 32],
        genesis_format: u32,
    ) -> Result<Self, AnnuletError> {
        std::fs::create_dir_all(dir).map_err(JournalError::Io)?;
        let lock = AuthLock::acquire(dir)?;
        let secret = key.auth_secret();
        let root = generation_root(&secret, 0);
        let rkm = key.rkm_v2(&root);
        let nk = key.nk();
        let spent = served.spent_nullifiers()?;
        let (_, genesis) = served.genesis_notes()?;
        let mine: Vec<L2Note> = genesis.into_iter().filter(|n| n.rkm == rkm && n.asset == 0).collect();
        let nf = |n: &L2Note| digest_bytes(&qlab_air::l2::l2_nf(&nk, &n.rho));
        let journal = match AuthJournal::load(dir)? {
            Some(j) => {
                let g0 = j.get(0).map_err(|e| AnnuletError::JournalForeign(e.to_string()))?;
                if g0.auth_root != root || j.active().g != 0 {
                    return Err(AnnuletError::JournalForeign(
                        "its generation 0 is not this key's tree, or another generation is active".into(),
                    ));
                }
                j
            }
            None => {
                let used = mine.iter().filter(|n| spent.contains(&nf(n))).count();
                if used > 0 {
                    return Err(AnnuletError::JournalLost { spent: used });
                }
                let j = AuthJournal::fresh(root);
                j.save(dir)?;
                j
            }
        };
        let keys = LocalAuth::new(&secret, 0, journal.active().next).map_err(AnnuletError::Auth)?;
        let stock = mine.into_iter().filter(|n| !spent.contains(&nf(n))).collect();
        Ok(Self {
            served,
            key,
            change: Recipient { rkm, ek: change_ek },
            stock,
            next: 0,
            fee_s,
            v2: Some(CandidateA { lock, dir: dir.to_path_buf(), journal, keys, genesis_hash, genesis_format }),
        })
    }

    /// The address version this faucet grants to: 2 on a Candidate A
    /// genesis, 1 otherwise.
    pub fn address_version(&self) -> u8 {
        match self.v2 {
            Some(_) => qlab_wallet::address::ADDRESS_VERSION_CANDIDATE_A,
            None => qlab_wallet::address::ADDRESS_VERSION,
        }
    }

    /// The Candidate A cursor position (`None` on a v1 faucet).
    pub fn auth_next(&self) -> Option<u32> {
        self.v2.as_ref().map(|a| a.keys.next())
    }

    /// Stock notes not yet granted by this process.
    pub fn stock_left(&self) -> usize {
        self.stock.len() - self.next
    }

    /// Grant one stock note (less the S fee) to `to`: build, prove, submit.
    /// Returns the granted note (the recipient's to find and spend).
    pub fn grant<R: rand::CryptoRng>(&mut self, to: &Recipient, rng: &mut R) -> Result<L2Note, AnnuletError> {
        let note = *self.stock.get(self.next).ok_or(AnnuletError::StockExhausted)?;
        if self.v2.is_some() {
            return self.grant_v2(note, to, rng);
        }
        let input = OwnedNote { note, key: self.key }.input();
        let outs = [
            Out { to: to.clone(), value: note.value - self.fee_s, asset: 0 },
            Out { to: self.change.clone(), value: 0, asset: 0 },
        ];
        let built = qlab_l2spend::build_s(&self.served, &[&input], &outs, self.fee_s, rng)?;
        self.served.submit(&built.tx)?;
        self.next += 1;
        Ok(built.outputs[0])
    }
}

impl AnnuletFaucet {
    /// A Candidate A grant: take a leaf and **persist the advance**, then
    /// build and prove the v2 S (stock note + two device dummies), sign the
    /// intent, attach, submit.
    fn grant_v2<R: rand::CryptoRng>(&mut self, note: L2Note, to: &Recipient, rng: &mut R) -> Result<L2Note, AnnuletError> {
        let tip = self.served.stated_tip()?;
        let a = self.v2.as_mut().expect("a Candidate A faucet");
        let path = a.keys.take().ok_or(JournalError::Exhausted { g: 0 })?;
        a.journal.advance(&a.lock, &a.dir, 0, a.keys.next())?;
        let input = L2AuthInput {
            nk: self.key.nk(),
            value: note.value,
            asset: note.asset,
            rho: note.rho,
            rseed: note.rseed,
            d: self.key.d,
            auth: path,
        };
        let taken = [input.auth.leaf_index];
        let (d2, k2) = a.keys.dummy(&entropy(), 1, &taken).map_err(AnnuletError::Auth)?;
        let (d3, k3) = a.keys.dummy(&entropy(), 2, &[taken[0], d2.auth.leaf_index]).map_err(AnnuletError::Auth)?;
        let outs = [
            Out { to: to.clone(), value: note.value - self.fee_s, asset: 0 },
            Out { to: self.change.clone(), value: 0, asset: 0 },
        ];
        let mut built = build_s_v2(&self.served, [&input, &d2], true, FeeIn::Dummy(&d3), &outs, self.fee_s, rng)?;
        let intent = intent_for(&built.tx, a.genesis_format, &a.genesis_hash, tip + GRANT_VALIDITY_BLOCKS, &built.auth)
            .map_err(|e| AnnuletError::Auth(format!("the intent does not rebuild: {e:?}")))?; // debug-ok: a named codec error
        let section = sign_locally(&intent, &a.keys, &[&k2, &k3])
            .map_err(|e| AnnuletError::Auth(format!("signing refused: {e:?}")))?; // debug-ok: a named auth error, no key
        attach(&mut built.tx, &section).map_err(|e| AnnuletError::Auth(format!("the section does not encode: {e:?}")))?; // debug-ok: a named codec error
        self.served.submit(&built.tx)?;
        self.next += 1;
        Ok(built.outputs[0])
    }
}

/// Fresh OS entropy for one dummy slot.
fn entropy() -> [u8; 32] {
    use rand::Rng;
    let mut e = [0u8; 32];
    rand::rng().fill_bytes(&mut e);
    e
}

/// The grant route of the Annulet faucet's HTTP surface.
pub const GRANT_PATH: &str = "/v1/annulet/grant";

/// **The Annulet faucet's HTTP surface** (lab #716): `POST /v1/annulet/grant`
/// with an address string as the body grants one stock note to the address's
/// `(rkm, ek)`; `GET /` answers the stock left. Grants are serialized (one
/// prove at a time). The address is the wallet's existing encoding; which
/// `rkm` it carries is the wallet's business — an L2-spendable one is
/// `H(nk ‖ D ‖ d)`, which every wallet address already is (lab #718).
///
/// **No tickets and no rate limit**: the devnet's stock is a fixed 16 grants,
/// and the page says so. Returns the bound address; the server thread lives
/// as long as the process.
pub fn serve_grants(
    listen: &str,
    faucet: std::sync::Arc<std::sync::Mutex<AnnuletFaucet>>,
) -> std::io::Result<SocketAddr> {
    let server = tiny_http::Server::http(listen).map_err(|e| std::io::Error::other(e.to_string()))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| std::io::Error::other("the grant listener is not an IP socket"))?;
    std::thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let (code, body) = grant_verdict(&mut request, &faucet);
            let _ = request.respond(tiny_http::Response::from_string(body).with_status_code(code));
        }
    });
    Ok(addr)
}

fn grant_verdict(
    request: &mut tiny_http::Request,
    faucet: &std::sync::Mutex<AnnuletFaucet>,
) -> (u16, String) {
    let lock = || faucet.lock().unwrap_or_else(|p| p.into_inner());
    match (request.method(), request.url()) {
        (tiny_http::Method::Get, "/") => (
            200,
            format!(
                "Annulet devnet faucet (lab #716): {} grant(s) of genesis stock left; POST an address to {GRANT_PATH}.\n",
                lock().stock_left()
            ),
        ),
        (tiny_http::Method::Post, GRANT_PATH) => {
            let mut text = String::new();
            if request.as_reader().take(16 * 1024).read_to_string(&mut text).is_err() {
                return (400, "refused: body-unreadable".into());
            }
            // A v1 faucet keeps the strict (version-1) decoder; a Candidate A
            // faucet takes version 2 only (lab #896 G, QG1) — a v1 address
            // on this net would make a note nobody can spend.
            let want = lock().address_version();
            let Some(address) = qlab_wallet::address::Address::decode_any(text.trim()) else {
                return (400, "refused: address-undecodable".into());
            };
            if address.require_version(want).is_err() {
                return (400, format!("refused: address-version (this net takes version {want} addresses)\n"));
            }
            let Some(ek) = address.encapsulation_key() else {
                return (400, "refused: address-ek-invalid".into());
            };
            let to = Recipient { rkm: address.rkm_lanes(), ek };
            match lock().grant(&to, &mut rand::rng()) {
                Ok(note) => (200, format!("granted value={} cm={}\n", note.value, hex(&digest_bytes(&note.commitment())))),
                Err(AnnuletError::StockExhausted) => (503, "unavailable: stock-exhausted\n".into()),
                Err(e) => (502, format!("refused: {e}\n")),
            }
        }
        _ => (404, "not found\n".into()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
