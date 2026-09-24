//! **The faucet's Annulet mode, and the L2 spend assembly it runs on**
//! (lab #716, B6).
//!
//! An Annulet faucet's stock is the devnet genesis's fee-unit notes (B5's
//! `GET /v1/genesis/notes`), one grant each: a grant is a shape-S spend of
//! one whole stock note to the requester's `rkm` (plus a zero change output),
//! so there is **no change tracking and no harvest loop**. It refuses to run
//! against an L1 form ([`AnnuletFaucet::start`]).
//!
//! The spend assembly — served witnesses (commitment tree, registry
//! openings) → instance → real prove → the transaction with its encrypted
//! discovery group → `POST /v1/tx` — is also what the journey harness uses to
//! send `USDT-test` (shape P). It is the wallet side of an L2 spend, built
//! here because the faucet needs it first; **C2 promotes it into the wallet**.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use qlab_air::l2::{L2TxInput, L2TxOutput, RegistryLeaf, RegistryWitness};
use qlab_air::l2p::{PolicyAsset, VPublic};
use qlab_air::narrow::MerkleWitness;
use qlab_cbserver::registry::{decode_genesis_notes, decode_registry_opening, RegistryOpening};
use qlab_cbserver::tree::CommitmentTree;
use qlab_devnet::annulet::{L2ShapeTag, L2Surface, VPublicTerm};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::ArityBucket;
use qlab_devnet::forms::GenesisForm;
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::kem::Ek;
use qlab_note::l2note::{GenesisPlaintext, L2Note, L2_PAYLOAD_LEN};
use qlab_note::wire::RecipientBundle;
use rand::Rng;

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

/// Where an output goes: its `rkm` and the discovery key it is encrypted to.
#[derive(Clone)]
pub struct Recipient {
    pub rkm: [u64; 4],
    pub ek: Ek,
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

    /// The note's commitment as served (lane-major bytes).
    pub fn cm(&self) -> [u8; 32] {
        digest_bytes(&self.note.commitment())
    }
}

/// Why an Annulet faucet or spend could not proceed — by name.
#[derive(Debug)]
pub enum AnnuletError {
    /// The node runs an L1 chain: the Annulet faucet refuses to start.
    NotAnnulet,
    /// A served answer was missing or did not decode.
    Served(String),
    /// The node refused the transaction (its named verdict).
    Refused(String),
    /// Every stock note is spent.
    StockExhausted,
}

impl std::fmt::Display for AnnuletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnnuletError::NotAnnulet => write!(f, "the node runs an L1 chain; the Annulet faucet refuses to start (lab #716)"),
            AnnuletError::Served(e) => write!(f, "served data: {e}"),
            AnnuletError::Refused(e) => write!(f, "the node refused the transaction: {e}"),
            AnnuletError::StockExhausted => write!(f, "every genesis stock note is spent"),
        }
    }
}

impl std::error::Error for AnnuletError {}

/// A node's served discovery endpoint.
#[derive(Clone, Copy, Debug)]
pub struct Served {
    pub addr: SocketAddr,
}

impl Served {
    fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), AnnuletError> {
        let io = |e: std::io::Error| AnnuletError::Served(format!("{method} {path}: {e}"));
        let mut s = TcpStream::connect(self.addr).map_err(io)?;
        write!(s, "{method} {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
            .map_err(io)?;
        s.write_all(body).map_err(io)?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(io)?;
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| AnnuletError::Served(format!("{path}: no header block")))?
            + 4;
        let status = std::str::from_utf8(raw.get(9..12).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| AnnuletError::Served(format!("{path}: no status")))?;
        Ok((status, raw[split..].to_vec()))
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, AnnuletError> {
        match self.request("GET", path, &[])? {
            (200, body) => Ok(body),
            (code, body) => Err(AnnuletError::Served(format!("{path}: {code} {}", String::from_utf8_lossy(&body)))),
        }
    }

    /// The whole commitment tree, rebuilt from the served leaves.
    pub fn commitment_tree(&self) -> Result<CommitmentTree, AnnuletError> {
        let mut tree = CommitmentTree::new();
        loop {
            let page = qlab_node::TreeLeaves::from_bytes(&self.get(&format!("/v1/tree/leaves?from={}", tree.len()))?)
                .map_err(|e| AnnuletError::Served(format!("tree leaves: {e:?}")))?;
            if page.leaves.is_empty() {
                return Ok(tree);
            }
            for leaf in &page.leaves {
                tree.append_bytes(leaf);
            }
            if tree.len() >= page.total {
                return Ok(tree);
            }
        }
    }

    /// The registry opening of `asset` (with the root it was computed against).
    pub fn registry(&self, asset: u64) -> Result<RegistryOpening, AnnuletError> {
        decode_registry_opening(&self.get(&format!("/v1/registry/{asset}"))?)
            .map_err(|e| AnnuletError::Served(format!("registry {asset}: {e:?}")))
    }

    /// The genesis notes this node's genesis file carries.
    pub fn genesis_notes(&self) -> Result<Vec<L2Note>, AnnuletError> {
        let (_, notes) = decode_genesis_notes(&self.get("/v1/genesis/notes")?)
            .map_err(|e| AnnuletError::Served(format!("genesis notes: {e:?}")))?;
        notes
            .iter()
            .map(|n| GenesisPlaintext::open(&n.payload.0).ok_or_else(|| AnnuletError::Served("a genesis note does not open".into())))
            .collect()
    }

    /// **The recipient's detection** over heights `[from, to]`: every L2 note
    /// `dk` opens, read the way a light wallet reads it — `/v1/compact` for
    /// the bundles, `/v1/block/{h}/tx/{i}/full` for the 128-B payloads of the
    /// groups it holds, each opened note's commitment checked against the
    /// served cm.
    pub fn detect(&self, dk: &qlab_note::kem::Dk, from: u64, to: u64) -> Result<Vec<L2Note>, AnnuletError> {
        let blocks = qlab_cbserver::codec::decode_compact_response(&self.get(&format!("/v1/compact?from={from}&to={to}"))?)
            .map_err(|e| AnnuletError::Served(format!("compact: {e:?}")))?;
        let mut found = Vec::new();
        for block in &blocks {
            for group in &block.groups {
                let mut full: Option<Vec<Vec<Vec<u8>>>> = None;
                for (r, bundle) in group.recipients.iter().enumerate() {
                    if full.is_none() {
                        let body = self.get(&format!("/v1/block/{}/tx/{}/full", block.height, group.tx_index))?;
                        full = Some(
                            qlab_cbserver::codec::decode_full_response(&body)
                                .map_err(|e| AnnuletError::Served(format!("full: {e:?}")))?,
                        );
                    }
                    let payloads = &full.as_ref().expect("fetched above")[r];
                    for d in qlab_cbserver::client::open_served_l2(dk, bundle, payloads) {
                        if digest_bytes(&d.note.commitment()) != bundle.entries[d.index].cm {
                            return Err(AnnuletError::Served("an opened note is not the served cm".into()));
                        }
                        found.push(d.note);
                    }
                }
            }
        }
        Ok(found)
    }

    /// Every nullifier the node's main chain has published (`/v1/nullifiers`,
    /// paged until a page ends short of the request).
    pub fn spent_nullifiers(&self) -> Result<std::collections::HashSet<[u8; 32]>, AnnuletError> {
        let mut spent = std::collections::HashSet::new();
        let mut from = 0u64;
        loop {
            let page = qlab_cbserver::codec::NullifierPage::from_bytes(
                &self.get(&format!("/v1/nullifiers?from={from}&to={}", u64::MAX))?,
            )
            .map_err(|e| AnnuletError::Served(format!("nullifiers: {e:?}")))?;
            for b in &page.blocks {
                spent.extend(b.nullifiers.iter().copied());
            }
            if page.blocks.is_empty() || page.to == u64::MAX || page.to < from {
                return Ok(spent);
            }
            from = page.to + 1;
        }
    }

    /// Submit a transaction on the Annulet tx wire. `202 accepted` and
    /// `200 duplicate` (already pending — retry-safe by the route's design)
    /// are both success; everything else is the node's named refusal.
    pub fn submit(&self, tx: &TxEntry) -> Result<(), AnnuletError> {
        let wire = qlab_p2p::codec::encode_tx_annulet(tx);
        match self.request("POST", "/v1/tx", &wire)? {
            (202, _) | (200, _) => Ok(()),
            (_, body) => Err(AnnuletError::Refused(String::from_utf8_lossy(&body).into_owned())),
        }
    }
}

/// The witness of an owned note in `tree` (the tree's current root anchors it).
fn witness_of(tree: &CommitmentTree, note: &OwnedNote) -> Result<MerkleWitness, AnnuletError> {
    let lanes = note.note.commitment();
    let pos = tree
        .position_of(&lanes)
        .ok_or_else(|| AnnuletError::Served("an input note is not in the served commitment tree".into()))?;
    Ok(tree.auth_path(pos, tree.len()))
}

/// The output notes a built instance commits, with the circuit's `rho`s
/// (`derive_output_rho(nf₀, j)`), each checked against the instance's cm.
fn output_notes(outputs: &[L2TxOutput; 2], nf0: &[u64; 4], cm_out: &[[u64; 4]; 2]) -> [L2Note; 2] {
    core::array::from_fn(|j| {
        let o = &outputs[j];
        let n = L2Note {
            value: o.value,
            asset: o.asset,
            rkm: o.rkm,
            rho: qlab_air::narrow::derive_output_rho(nf0, j),
            rseed: o.rseed,
        };
        assert_eq!(n.commitment(), cm_out[j], "output {j}: the note is the one the proof commits");
        n
    })
}

/// The discovery group: output `j` encrypted to `to[j]`, one bundle each
/// (D4 order), at the L2 payload width.
fn discovery_for<R: rand::CryptoRng>(notes: &[L2Note; 2], to: &[Recipient; 2], rng: &mut R) -> Vec<u8> {
    let mut bundles: Vec<RecipientBundle> = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for j in 0..2 {
        let out = qlab_note::scan::encrypt_notes_to_recipient(&to[j].ek, &notes[j..=j], rng);
        bundles.push(out.bundle);
        payloads.extend(out.payloads);
    }
    qlab_note::compact::encode_committed_discovery_with_width(&bundles, &payloads, L2_PAYLOAD_LEN)
}

fn random_d4<R: Rng>(rng: &mut R) -> [u64; 4] {
    [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()]
}

/// An assembled L2 transaction and the output notes it creates.
pub struct Built {
    pub tx: TxEntry,
    pub outputs: [L2Note; 2],
}

fn entry(
    proof: &qlab_l2::Proof<qlab_l2::Config>,
    anchor: &[u64; 4],
    nf: &[[u64; 4]; 2],
    cm_out: &[[u64; 4]; 2],
    fee: u64,
    surface: L2Surface,
    discovery: Vec<u8>,
) -> TxEntry {
    TxEntry {
        proof: bincode::serialize(proof).expect("a proof serializes"),
        public: TxPublic {
            anchor: digest_bytes(anchor),
            nullifiers: nf.iter().map(digest_bytes).collect(),
            commitments: cm_out.iter().map(digest_bytes).collect(),
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        discovery,
        rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
        l2: surface.encode(),
    }
}

/// **A shape-S spend of one note** (the faucet grant): the whole of `input`
/// less `fee` to `to`, a zero change output to `change`, the second input slot
/// a dummy. Proves (≈ 7 GB, seconds).
pub fn build_s_single<R: rand::CryptoRng>(
    served: &Served,
    input: &OwnedNote,
    to: &Recipient,
    change: &Recipient,
    fee: u64,
    rng: &mut R,
) -> Result<Built, AnnuletError> {
    let tree = served.commitment_tree()?;
    let w = witness_of(&tree, input)?;
    let anchor = tree.root();
    let reg = served.registry(input.note.asset)?;
    let reg0 = served.registry(0)?;
    let real = input.input();
    let dummy = L2TxInput { sk: random_d4(rng), value: 0, asset: 0, rho: random_d4(rng), rseed: random_d4(rng), d: [0, 0] };
    let outputs = [
        L2TxOutput { value: input.note.value - fee, asset: input.note.asset, rkm: to.rkm, rho: [0; 4], rseed: random_d4(rng) },
        L2TxOutput { value: 0, asset: 0, rkm: change.rkm, rho: [0; 4], rseed: random_d4(rng) },
    ];
    let leaves: [RegistryLeaf; 2] = [reg.leaf, reg0.leaf];
    let wits: [RegistryWitness; 2] = [reg.witness, reg0.witness];
    let inst = qlab_air::l2::build_bucket_l2_dummy1(
        qlab_l2::LOG_HEIGHT_S,
        &real,
        &w,
        &dummy,
        &qlab_air::narrow::off_tree_witness(),
        &outputs,
        fee,
        anchor,
        &leaves,
        &wits,
        reg.root,
    );
    let (_, proof) = qlab_l2::prove_s(&inst);
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, &[to.clone(), change.clone()], rng);
    let surface = L2Surface { shape: L2ShapeTag::S, registry_root: digest_bytes(&reg.root), vpublic: None };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.cm_out, fee, surface, discovery), outputs: notes })
}

/// **A shape-P spend** of two owned notes (e.g. a `USDT-test` note and an
/// asset-0 fee note), with `vPublic = 0`: output 0 is `(to, value, asset)`,
/// output 1 is the rest of input 1's asset less `fee` back to `change`. The
/// policy of each input's asset is the caller's (`PolicyAsset`, the object
/// the registry leaf was built from). Proves (≈ 15 GB, seconds).
#[allow(clippy::too_many_arguments)]
pub fn build_p_send<R: rand::CryptoRng>(
    served: &Served,
    inputs: [&OwnedNote; 2],
    policies: [&PolicyAsset; 2],
    to: &Recipient,
    change: &Recipient,
    fee: u64,
    rng: &mut R,
) -> Result<Built, AnnuletError> {
    let tree = served.commitment_tree()?;
    let witnesses = [witness_of(&tree, inputs[0])?, witness_of(&tree, inputs[1])?];
    let anchor = tree.root();
    let regs = [served.registry(inputs[0].note.asset)?, served.registry(inputs[1].note.asset)?];
    let policy = [
        policies[0]
            .policy_input_for(&inputs[0].note.rkm, regs[0].witness)
            .ok_or_else(|| AnnuletError::Served("input 0: frozen or not allowlisted".into()))?,
        policies[1]
            .policy_input_for(&inputs[1].note.rkm, regs[1].witness)
            .ok_or_else(|| AnnuletError::Served("input 1: frozen or not allowlisted".into()))?,
    ];
    let outputs = [
        L2TxOutput {
            value: inputs[0].note.value,
            asset: inputs[0].note.asset,
            rkm: to.rkm,
            rho: [0; 4],
            rseed: random_d4(rng),
        },
        L2TxOutput {
            value: inputs[1].note.value - fee,
            asset: inputs[1].note.asset,
            rkm: change.rkm,
            rho: [0; 4],
            rseed: random_d4(rng),
        },
    ];
    let inst = qlab_air::l2p::build_bucket_l2p_with_witnesses(
        qlab_l2::LOG_HEIGHT_P,
        &[inputs[0].input(), inputs[1].input()],
        &outputs,
        fee,
        &witnesses,
        anchor,
        &policy,
        regs[0].root,
        [VPublic::NONE; 2],
    );
    let (_, proof) = qlab_l2::prove_p(&inst);
    let notes = output_notes(&outputs, &inst.nf[0], &inst.cm_out);
    let discovery = discovery_for(&notes, &[to.clone(), change.clone()], rng);
    let surface = L2Surface {
        shape: L2ShapeTag::P,
        registry_root: digest_bytes(&regs[0].root),
        vpublic: Some([VPublicTerm::NONE; 2]),
    };
    Ok(Built { tx: entry(&proof, &anchor, &inst.nf, &inst.cm_out, fee, surface, discovery), outputs: notes })
}

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
        let owned = OwnedNote { note, key: self.key };
        let built = build_s_single(&self.served, &owned, to, &self.change, self.fee_s, rng)?;
        self.served.submit(&built.tx)?;
        self.next += 1;
        Ok(built.outputs[0])
    }
}

/// A served cm as the lanes a commitment tree holds.
pub fn cm_lanes(cm: &[u8; 32]) -> [u64; 4] {
    digest_from_bytes(cm)
}

/// The grant route of the Annulet faucet's HTTP surface.
pub const GRANT_PATH: &str = "/v1/annulet/grant";

/// **The Annulet faucet's HTTP surface** (lab #716): `POST /v1/annulet/grant`
/// with an address string as the body grants one stock note to the address's
/// `(rkm, ek)`; `GET /` answers the stock left. Grants are serialized (one
/// prove at a time). The address is the wallet's existing encoding; which
/// `rkm` it carries is the wallet's business — an L2-spendable one is
/// `H(nk ‖ D ‖ d)`, and no user wallet derives it yet (C1).
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
