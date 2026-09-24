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

use std::io::Read;
use std::net::SocketAddr;

use qlab_air::l2::L2TxInput;
use qlab_devnet::forms::GenesisForm;
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
        Ok(Self { served, key, change: Recipient { rkm, ek: change_ek }, stock, next: 0, fee_s })
    }

    /// Stock notes not yet granted by this process.
    pub fn stock_left(&self) -> usize {
        self.stock.len() - self.next
    }

    /// Grant one stock note (less the S fee) to `to`: build, prove, submit.
    /// Returns the granted note (the recipient's to find and spend).
    pub fn grant<R: rand::CryptoRng>(&mut self, to: &Recipient, rng: &mut R) -> Result<L2Note, AnnuletError> {
        let note = *self.stock.get(self.next).ok_or(AnnuletError::StockExhausted)?;
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
            let Some(address) = qlab_wallet::address::Address::decode(text.trim()) else {
                return (400, "refused: address-undecodable".into());
            };
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
