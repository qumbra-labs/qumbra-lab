//! The mobile client half of the **paired-prover channel** — the session a
//! phone opens to the user's own Mac to have one spend proved.
//!
//! ## Why this lives in the kernel and not in the shell
//!
//! The server half already exists (`qumbra-wallet-macos`'s
//! `qumbra-paired-prover`, specified in that repo's `docs/mobile-paired-prover.md`)
//! and this module is its counterpart. Three of the four reasons it is here
//! rather than in Swift/TS are the usual ones — one implementation, not one per
//! shell; the secret never crosses into shell memory; a refusal carries the
//! kernel's own words. The fourth is specific and decides it outright:
//!
//! 🔴 **The client's stated obligation is a SHA3-256 check** — the spec requires
//! it to *"verify byte length and SHA3-256 before exact-byte submission"*. Apple's
//! CryptoKit has no SHA-3 (SHA-2 only), so an iOS shell **cannot** discharge that
//! obligation itself. A shell that cannot verify the artifact must not be the
//! thing deciding whether the artifact is the transaction.
//!
//! ## The shape: a pump, not a cipher
//!
//! This is deliberately NOT "seal/open on the ABI with the state machine in the
//! shell". Frame reassembly, counter discipline and the AAD are the
//! security-critical core, and a second copy of them per shell is a second place
//! to get them wrong. So the shell owns the socket and nothing else, and this
//! module is a pump in the same shape as [`crate::ScanState`]:
//!
//! ```text
//! Session::new(uri)?          -> the endpoint to connect to
//! loop { match step() {
//!     Send(frame) => write frame to the socket
//!     Need        => read whatever the socket gives, supply() it
//!     Done        => take_artifact()
//!     Failed(why) => show why
//! } }
//! ```
//!
//! `supply` accepts **any** number of bytes: TCP splits and coalesces freely, and
//! the reassembly belongs on this side of the boundary.
//!
//! ## The wire, transcribed from the server implementation
//!
//! Read from `qumbra-paired-prover.rs` rather than from its prose, because a doc
//! can drift and the bytes cannot:
//!
//! ```text
//! URI        qumbra-prover://HOST:PORT?v=1&secret=<64 hex>
//! handshake  "QMBPAIR\0" || version:u8 || server_nonce:16     (25 bytes, plaintext)
//! key        SHA3-256(b"qumbra-wallet/paired-prover/key/v1\0" || secret || server_nonce)
//! frame      counter:u64le || ciphertext_len:u32le || ChaCha20-Poly1305(ct||tag)
//! nonce      direction:4 || counter:u64le                      (12 bytes)
//! aad        magic:8 || version:u8 || server_nonce:16 || direction:4 || counter:u64le
//! direction  client→Mac "MOBI"   Mac→client "DESK"
//! ```
//!
//! 🔴 The directions are **mirrored** from the server's names: the server *reads*
//! with `MOBI` and *writes* with `DESK`, so this client *writes* `MOBI` and
//! *reads* `DESK`. Getting that backwards is the classic bug in this shape and it
//! fails only against a real peer — which is why `tests/paired_prover_interop.rs`
//! talks to the real server rather than to a second copy of this file.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use sha3::{Digest, Sha3_256};

/// The protocol version this client speaks. A server announcing anything else is
/// refused **by number**, because a version handshake whose mismatch is reported
/// as "handshake failed" has thrown away the one fact it exists to carry.
pub const PROTOCOL_VERSION: u8 = 1;

const HANDSHAKE_MAGIC: &[u8; 8] = b"QMBPAIR\0";
const KEY_DOMAIN: &[u8] = b"qumbra-wallet/paired-prover/key/v1\0";
/// The handshake is `magic || version || nonce` = 8 + 1 + 16.
pub const HANDSHAKE_BYTES: usize = 25;
const CLIENT_DIRECTION: &[u8; 4] = b"MOBI";
const SERVER_DIRECTION: &[u8; 4] = b"DESK";
/// The server's own bound, mirrored: it refuses a frame outside `16..=128 MiB`
/// before decrypting, so a client that would send one is refused here instead of
/// on the wire.
const MIN_FRAME_BYTES: usize = 16;
const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;

/// Where a pairing URI says to connect, and the secret it carried.
///
/// `Debug` is implemented by hand: the derived one would print the secret, and a
/// pairing secret is spend authority for the transaction it proves.
#[derive(Clone)]
pub struct PairingUri {
    pub host: String,
    pub port: u16,
    pub secret: [u8; 32],
}

impl std::fmt::Debug for PairingUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingUri")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PairingUri {
    /// Parse `qumbra-prover://HOST:PORT?v=N&secret=<64 hex>`.
    ///
    /// Every refusal names what was wrong. A URI is pasted or scanned from a
    /// camera, so "invalid" without a reason leaves a user with no next move.
    pub fn parse(uri: &str) -> Result<Self, String> {
        let rest = uri
            .strip_prefix("qumbra-prover://")
            .ok_or_else(|| "not a qumbra-prover:// pairing URI".to_string())?;
        let (authority, query) = rest
            .split_once('?')
            .ok_or_else(|| "pairing URI has no ?v=…&secret=… query".to_string())?;

        // Host and port. IPv6 is not accepted, and that is the server's own
        // constraint rather than an omission here: it refuses to advertise
        // anything but "one DNS name, .local name, or IPv4 address".
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "pairing URI needs HOST:PORT".to_string())?;
        if host.is_empty() {
            return Err("pairing URI has an empty host".to_string());
        }
        if host.contains(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | ':')) {
            return Err(format!(
                "pairing host `{host}` contains a character the server never advertises"
            ));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| format!("pairing port `{port}` is not a port number"))?;
        if port == 0 {
            return Err("pairing port 0 is not a port a server listens on".to_string());
        }

        // Exactly the two expected keys, each once. An unexpected key is refused
        // rather than ignored: a URI carrying something this client does not
        // understand is a URI from a peer it does not understand.
        let mut version: Option<u8> = None;
        let mut secret_hex: Option<&str> = None;
        for pair in query.split('&') {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| format!("query part `{pair}` is not key=value"))?;
            match key {
                "v" => {
                    if version.is_some() {
                        return Err("pairing URI repeats v=".to_string());
                    }
                    version = Some(
                        value
                            .parse()
                            .map_err(|_| format!("pairing version `{value}` is not a number"))?,
                    );
                }
                "secret" => {
                    if secret_hex.is_some() {
                        return Err("pairing URI repeats secret=".to_string());
                    }
                    secret_hex = Some(value);
                }
                other => return Err(format!("pairing URI carries unknown key `{other}`")),
            }
        }

        let version = version.ok_or_else(|| "pairing URI has no v=".to_string())?;
        if version != PROTOCOL_VERSION {
            return Err(format!(
                "pairing URI announces protocol v{version}; this build speaks v{PROTOCOL_VERSION}"
            ));
        }
        let secret_hex = secret_hex.ok_or_else(|| "pairing URI has no secret=".to_string())?;
        if secret_hex.len() != 64 {
            return Err(format!(
                "pairing secret is {} hex characters; a 32-byte secret is 64",
                secret_hex.len()
            ));
        }
        let mut secret = [0u8; 32];
        for (i, byte) in secret.iter_mut().enumerate() {
            let pair = &secret_hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(pair, 16)
                .map_err(|_| format!("pairing secret is not hex at character {}", i * 2))?;
        }
        Ok(Self {
            host: host.to_string(),
            port,
            secret,
        })
    }

    /// `host:port`, for whatever the shell's socket layer takes.
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The per-connection key and the two counters, derived once the server's
/// handshake has been read.
struct Keyed {
    cipher: ChaCha20Poly1305,
    server_nonce: [u8; 16],
    /// Frames this client has written. Mirrors the server's `receive_counter`.
    send_counter: u64,
    /// Frames this client has read. Mirrors the server's `send_counter`.
    receive_counter: u64,
}

fn frame_nonce(direction: &[u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(direction);
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn frame_aad(server_nonce: &[u8; 16], direction: &[u8; 4], counter: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(37);
    aad.extend_from_slice(HANDSHAKE_MAGIC);
    aad.push(PROTOCOL_VERSION);
    aad.extend_from_slice(server_nonce);
    aad.extend_from_slice(direction);
    aad.extend_from_slice(&counter.to_le_bytes());
    aad
}

/// The session key, exposed so a test can pin the derivation against an
/// independently computed digest rather than against this file's own round trip.
pub fn derive_key(secret: &[u8; 32], server_nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(KEY_DOMAIN);
    hasher.update(secret);
    hasher.update(server_nonce);
    hasher.finalize().into()
}

impl Keyed {
    fn new(secret: &[u8; 32], server_nonce: [u8; 16]) -> Self {
        let key = derive_key(secret, &server_nonce);
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&key).expect("SHA3-256 is a 32-byte key"),
            server_nonce,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    /// One complete frame — `counter || len || ciphertext` — ready to write.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let counter = self.send_counter;
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(frame_nonce(CLIENT_DIRECTION, counter)),
                Payload {
                    msg: plaintext,
                    aad: &frame_aad(&self.server_nonce, CLIENT_DIRECTION, counter),
                },
            )
            .map_err(|_| "cannot encrypt a request frame".to_string())?;
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&ciphertext.len()) {
            // Unreachable for any plaintext this client builds, and checked
            // anyway: the server refuses such a frame before decrypting, so
            // sending one would read to the user as an authentication failure.
            return Err(format!(
                "a {}-byte frame is outside the accepted range",
                ciphertext.len()
            ));
        }
        let mut frame = Vec::with_capacity(12 + ciphertext.len());
        frame.extend_from_slice(&counter.to_le_bytes());
        frame.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        frame.extend_from_slice(&ciphertext);
        self.send_counter += 1;
        Ok(frame)
    }

    fn open(&mut self, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if counter != self.receive_counter {
            return Err(format!(
                "server frame counter {counter} is not the expected {}",
                self.receive_counter
            ));
        }
        let plaintext = self
            .cipher
            .decrypt(
                &Nonce::from(frame_nonce(SERVER_DIRECTION, counter)),
                Payload {
                    msg: ciphertext,
                    aad: &frame_aad(&self.server_nonce, SERVER_DIRECTION, counter),
                },
            )
            .map_err(|_| "server frame authentication failed".to_string())?;
        self.receive_counter += 1;
        Ok(plaintext)
    }
}

/// What the pump wants next.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Write these bytes to the socket, then step again.
    Send(Vec<u8>),
    /// Read whatever the socket has and hand it to [`Session::supply`].
    Need,
    /// The verified transaction bytes are ready — [`Session::take_artifact`].
    Done,
    /// Refused, with the reason. Terminal.
    Failed(String),
}

/// What the client asked the server to do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Operation {
    /// Decode the bundle and describe it. No proving, no funds — the operation
    /// an interop check can use.
    Inspect,
    /// Prove it, and stream back the transaction bytes.
    Prove,
}

impl Operation {
    fn wire(self) -> &'static str {
        match self {
            Operation::Inspect => "inspect",
            Operation::Prove => "prove",
        }
    }
}

/// What the server said, in the order it said it — narration the shell must be
/// able to show, because proving takes minutes and a silent minute reads as a
/// hang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// `preflight`: the server is re-checking anchors and nullifiers.
    Preflight,
    /// `progress`: free-text narration.
    Progress(String),
    /// `inspected`: the metadata JSON, verbatim.
    Inspected(String),
    /// The artifact is `bytes` long and will arrive in `chunks` pieces.
    ArtifactStart { bytes: usize, chunks: usize },
}

enum Phase {
    /// Waiting for `magic || version || nonce`.
    Handshake,
    /// The request frame has not been written yet.
    Request,
    /// Reading response frames.
    Responses,
    Done,
    Failed,
}

/// One paired-prover session: connect, prove one bundle, take the bytes.
pub struct Session {
    uri: PairingUri,
    request_id: String,
    operation: Operation,
    bundle_hex: String,
    scan_url: Option<String>,
    node_url: Option<String>,

    phase: Phase,
    keyed: Option<Keyed>,
    /// Bytes from the socket that have not yet formed a complete frame. TCP
    /// splits and coalesces, so this is the reassembly buffer — and it is on this
    /// side of the ABI so no shell has to own it.
    inbox: Vec<u8>,

    notes: Vec<Note>,
    expected_bytes: Option<usize>,
    expected_chunks: Option<usize>,
    expected_digest: Option<String>,
    chunks: Vec<Option<Vec<u8>>>,
    artifact: Option<Vec<u8>>,
}

/// Redacting by hand, like [`PairingUri`]'s. A derived `Debug` would print
/// `bundle_hex` — the witness bundle, which the FFI header calls SPENDING-KEY
/// MATERIAL — into whatever a caller logged. The compile error that made this
/// necessary (a test's `expect_err` wanting `Debug`) was worth the reminder.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("endpoint", &self.uri.endpoint())
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("bundle_hex", &"<redacted>")
            .field("artifact", &self.artifact.as_ref().map(Vec::len))
            .finish()
    }
}

impl Session {
    /// A session over `uri`, for one bundle.
    ///
    /// `scan_url`/`node_url` are required for [`Operation::Prove`] — the server
    /// re-validates against live anchors before it allocates STARK work — and
    /// unused for [`Operation::Inspect`].
    pub fn new(
        uri: &str,
        request_id: &str,
        operation: Operation,
        bundle: &[u8],
        scan_url: Option<&str>,
        node_url: Option<&str>,
    ) -> Result<Self, String> {
        let uri = PairingUri::parse(uri)?;
        if request_id.is_empty() || request_id.len() > 128 {
            return Err("request_id must be 1 to 128 characters".to_string());
        }
        if bundle.is_empty() {
            return Err("there is no bundle to prove".to_string());
        }
        if operation == Operation::Prove && (scan_url.is_none() || node_url.is_none()) {
            return Err("proving needs both a scan endpoint and a node endpoint".to_string());
        }
        Ok(Self {
            uri,
            request_id: request_id.to_string(),
            operation,
            bundle_hex: hex_lower(bundle),
            scan_url: scan_url.map(str::to_string),
            node_url: node_url.map(str::to_string),
            phase: Phase::Handshake,
            keyed: None,
            inbox: Vec::new(),
            notes: Vec::new(),
            expected_bytes: None,
            expected_chunks: None,
            expected_digest: None,
            chunks: Vec::new(),
            artifact: None,
        })
    }

    /// `host:port` to connect to.
    pub fn endpoint(&self) -> String {
        self.uri.endpoint()
    }

    /// Hand over whatever the socket produced — any length, including zero.
    pub fn supply(&mut self, bytes: &[u8]) {
        self.inbox.extend_from_slice(bytes);
    }

    /// Narration produced so far, drained.
    pub fn take_notes(&mut self) -> Vec<Note> {
        std::mem::take(&mut self.notes)
    }

    /// The verified transaction bytes, once [`Step::Done`].
    pub fn take_artifact(&mut self) -> Option<Vec<u8>> {
        self.artifact.take()
    }

    pub fn step(&mut self) -> Step {
        match self.advance() {
            Ok(step) => step,
            Err(why) => {
                self.phase = Phase::Failed;
                Step::Failed(why)
            }
        }
    }

    fn advance(&mut self) -> Result<Step, String> {
        loop {
            match self.phase {
                Phase::Failed => return Err("this session already failed".to_string()),
                Phase::Done => return Ok(Step::Done),

                Phase::Handshake => {
                    if self.inbox.len() < HANDSHAKE_BYTES {
                        return Ok(Step::Need);
                    }
                    let head: Vec<u8> = self.inbox.drain(..HANDSHAKE_BYTES).collect();
                    if &head[..8] != HANDSHAKE_MAGIC {
                        // Not a plaintext oracle: this says the peer is not a
                        // paired prover, which is a fact the user needs, and it
                        // reveals nothing a network observer did not just see.
                        return Err(
                            "the peer did not answer as a Qumbra paired prover".to_string()
                        );
                    }
                    if head[8] != PROTOCOL_VERSION {
                        return Err(format!(
                            "the prover speaks protocol v{}; this build speaks v{PROTOCOL_VERSION}",
                            head[8]
                        ));
                    }
                    let mut server_nonce = [0u8; 16];
                    server_nonce.copy_from_slice(&head[9..25]);
                    self.keyed = Some(Keyed::new(&self.uri.secret, server_nonce));
                    self.phase = Phase::Request;
                }

                Phase::Request => {
                    let request = self.request_json();
                    let keyed = self.keyed.as_mut().expect("keyed after handshake");
                    let frame = keyed.seal(request.as_bytes())?;
                    self.phase = Phase::Responses;
                    return Ok(Step::Send(frame));
                }

                Phase::Responses => {
                    // One complete frame, or ask for more bytes.
                    if self.inbox.len() < 12 {
                        return Ok(Step::Need);
                    }
                    let counter = u64::from_le_bytes(self.inbox[..8].try_into().unwrap());
                    let length =
                        u32::from_le_bytes(self.inbox[8..12].try_into().unwrap()) as usize;
                    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&length) {
                        return Err(format!(
                            "server frame length {length} is outside the accepted range"
                        ));
                    }
                    if self.inbox.len() < 12 + length {
                        return Ok(Step::Need);
                    }
                    let frame: Vec<u8> = self.inbox.drain(..12 + length).collect();
                    let keyed = self.keyed.as_mut().expect("keyed in responses");
                    let plaintext = keyed.open(counter, &frame[12..])?;
                    if self.handle_response(&plaintext)? {
                        self.phase = Phase::Done;
                        return Ok(Step::Done);
                    }
                }
            }
        }
    }

    fn request_json(&self) -> String {
        // Hand-built rather than serde-derived: this crate carries no serde, the
        // object is five flat fields, and every value here is either a fixed
        // token or something already validated (hex, a URL, a bounded id).
        let mut json = String::with_capacity(self.bundle_hex.len() + 256);
        json.push('{');
        json.push_str(&format!("\"version\":{PROTOCOL_VERSION},"));
        json.push_str(&format!(
            "\"request_id\":\"{}\",",
            escape_json(&self.request_id)
        ));
        json.push_str(&format!("\"operation\":\"{}\",", self.operation.wire()));
        json.push_str(&format!("\"bundle_hex\":\"{}\"", self.bundle_hex));
        if let Some(url) = &self.scan_url {
            json.push_str(&format!(",\"scan_url\":\"{}\"", escape_json(url)));
        }
        if let Some(url) = &self.node_url {
            json.push_str(&format!(",\"node_url\":\"{}\"", escape_json(url)));
        }
        json.push('}');
        json
    }

    /// `Ok(true)` when the session is finished.
    fn handle_response(&mut self, plaintext: &[u8]) -> Result<bool, String> {
        let text = std::str::from_utf8(plaintext)
            .map_err(|_| "a server frame was not UTF-8 JSON".to_string())?;
        let event = json_string(text, "event")
            .ok_or_else(|| "a server frame carried no event".to_string())?;

        match event.as_str() {
            "error" => Err(json_string(text, "reason")
                .unwrap_or_else(|| "the prover refused without a reason".to_string())),
            "preflight" => {
                self.notes.push(Note::Preflight);
                Ok(false)
            }
            "progress" => {
                self.notes.push(Note::Progress(
                    json_string(text, "message").unwrap_or_else(|| text.to_string()),
                ));
                Ok(false)
            }
            "inspected" => {
                self.notes.push(Note::Inspected(text.to_string()));
                Ok(true)
            }
            "artifact_start" => {
                let bytes = json_number(text, "byte_length")
                    .ok_or_else(|| "artifact_start carried no byte_length".to_string())?;
                let chunks = json_number(text, "chunk_count")
                    .ok_or_else(|| "artifact_start carried no chunk_count".to_string())?;
                let digest = json_string(text, "sha3_256")
                    .ok_or_else(|| "artifact_start carried no sha3_256".to_string())?;
                if bytes == 0 || chunks == 0 {
                    return Err("the prover announced an empty artifact".to_string());
                }
                self.expected_bytes = Some(bytes);
                self.expected_chunks = Some(chunks);
                self.expected_digest = Some(digest);
                self.chunks = vec![None; chunks];
                self.notes.push(Note::ArtifactStart { bytes, chunks });
                Ok(false)
            }
            "artifact_chunk" => {
                let index = json_number(text, "index")
                    .ok_or_else(|| "artifact_chunk carried no index".to_string())?;
                let hex = json_string(text, "hex")
                    .ok_or_else(|| "artifact_chunk carried no hex".to_string())?;
                let total = self
                    .expected_chunks
                    .ok_or_else(|| "a chunk arrived before artifact_start".to_string())?;
                if index >= total {
                    return Err(format!(
                        "chunk index {index} is outside the announced {total}"
                    ));
                }
                if self.chunks[index].is_some() {
                    return Err(format!("chunk {index} arrived twice"));
                }
                self.chunks[index] = Some(decode_hex(&hex)?);
                Ok(false)
            }
            "complete" => {
                self.finish()?;
                Ok(true)
            }
            other => {
                // Forward compatibility, the same rule the event blob states: an
                // unknown event is narrated, never fatal, so a future server
                // message cannot break a shipped shell.
                self.notes
                    .push(Note::Progress(format!("unrecognised event `{other}`")));
                Ok(false)
            }
        }
    }

    /// 🔴 The client's stated obligation: *"verify byte length and SHA3-256
    /// before exact-byte submission/persistence."* Every one of these refusals
    /// is a transaction NOT submitted, which is the correct outcome for bytes
    /// that are not provably the artifact the prover announced.
    fn finish(&mut self) -> Result<(), String> {
        if self.operation == Operation::Inspect {
            return Ok(());
        }
        let expected_bytes = self
            .expected_bytes
            .ok_or_else(|| "the prover completed without announcing an artifact".to_string())?;
        let expected_digest = self
            .expected_digest
            .clone()
            .ok_or_else(|| "the prover completed without announcing a digest".to_string())?;

        let mut artifact = Vec::with_capacity(expected_bytes);
        for (index, chunk) in self.chunks.iter().enumerate() {
            let chunk = chunk
                .as_ref()
                .ok_or_else(|| format!("chunk {index} never arrived"))?;
            artifact.extend_from_slice(chunk);
        }
        if artifact.len() != expected_bytes {
            return Err(format!(
                "the artifact is {} bytes; the prover announced {expected_bytes}",
                artifact.len()
            ));
        }
        let digest = hex_lower(&Sha3_256::digest(&artifact));
        if digest != expected_digest.to_ascii_lowercase() {
            return Err(format!(
                "the artifact hashes to {digest}; the prover announced {expected_digest}"
            ));
        }
        self.artifact = Some(artifact);
        Ok(())
    }
}

// ── small helpers: hex, and just enough JSON to read a flat object ──────────
//
// A dependency-free reader for a flat object of strings and numbers, which is
// exactly what this protocol's frames are. Nothing here recurses, and a value it
// cannot read is an absence its caller refuses by name — never a default.

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("hex payload has an odd length".to_string());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for i in (0..text.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| format!("hex payload is not hex at character {i}"))?,
        );
    }
    Ok(out)
}

fn escape_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The string value of a top-level `"key": "…"`, with escapes undone.
fn json_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut at = text.find(&needle)? + needle.len();
    let bytes = text.as_bytes();
    while at < bytes.len() && (bytes[at] as char).is_whitespace() {
        at += 1;
    }
    if at >= bytes.len() || bytes[at] != b':' {
        return None;
    }
    at += 1;
    while at < bytes.len() && (bytes[at] as char).is_whitespace() {
        at += 1;
    }
    if at >= bytes.len() || bytes[at] != b'"' {
        return None;
    }
    at += 1;
    let mut out = String::new();
    let mut chars = text[at..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'u' => {
                    let mut code = 0u32;
                    for _ in 0..4 {
                        code = code * 16 + chars.next()?.to_digit(16)?;
                    }
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

/// The unsigned integer value of a top-level `"key": N`.
fn json_number(text: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    let mut at = text.find(&needle)? + needle.len();
    let bytes = text.as_bytes();
    while at < bytes.len() && (bytes[at] as char).is_whitespace() {
        at += 1;
    }
    if at >= bytes.len() || bytes[at] != b':' {
        return None;
    }
    at += 1;
    while at < bytes.len() && (bytes[at] as char).is_whitespace() {
        at += 1;
    }
    let start = at;
    while at < bytes.len() && bytes[at].is_ascii_digit() {
        at += 1;
    }
    if at == start {
        return None;
    }
    text[start..at].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "qumbra-prover://my-mac.local:43191?v=1&secret=\
                       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn a_good_uri_parses_and_keeps_its_secret_out_of_debug() {
        let uri = PairingUri::parse(URI).expect("the server's own URI shape");
        assert_eq!(uri.host, "my-mac.local");
        assert_eq!(uri.port, 43191);
        assert_eq!(uri.secret[0], 0x00);
        assert_eq!(uri.secret[31], 0x1f);
        assert_eq!(uri.endpoint(), "my-mac.local:43191");
        // A pairing secret is spend authority. It must not be one `dbg!` away
        // from a log file.
        let shown = format!("{uri:?}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(!shown.contains("0001020304"), "the secret leaked into Debug: {shown}");
    }

    /// Every refusal names its reason. A URI arrives from a camera, so "invalid"
    /// with no cause leaves the user nothing to do.
    #[test]
    fn every_bad_uri_is_refused_by_name() {
        let cases: &[(&str, &str)] = &[
            ("https://mac:1?v=1&secret=00", "qumbra-prover"),
            ("qumbra-prover://mac:43191", "query"),
            ("qumbra-prover://:43191?v=1&secret=00", "empty host"),
            ("qumbra-prover://mac:0?v=1&secret=00", "port 0"),
            ("qumbra-prover://mac:70000?v=1&secret=00", "not a port number"),
            ("qumbra-prover://mac:43191?v=1", "no secret"),
            ("qumbra-prover://mac:43191?secret=00", "no v="),
            // The version handshake's whole purpose is that a mismatch says WHICH.
            ("qumbra-prover://mac:43191?v=2&secret=00", "v2"),
            ("qumbra-prover://mac:43191?v=1&secret=abc", "64"),
            ("qumbra-prover://mac:43191?v=1&extra=1&secret=00", "unknown key"),
        ];
        for (uri, expect) in cases {
            let err = PairingUri::parse(uri).expect_err(uri);
            assert!(
                err.contains(expect),
                "`{uri}` refused with `{err}`, which does not mention `{expect}`"
            );
        }
        // A 64-character non-hex secret reaches the hex loop rather than the
        // length check — a different refusal, and it must still name itself.
        let sixty_four_non_hex = format!("qumbra-prover://mac:1?v=1&secret={}", "z".repeat(64));
        assert!(PairingUri::parse(&sixty_four_non_hex)
            .expect_err("non-hex")
            .contains("not hex"));
    }

    /// 🔴 The KDF, pinned to a digest computed **outside this codebase**.
    ///
    /// `python3 -c "import hashlib; print(hashlib.sha3_256(
    ///   b'qumbra-wallet/paired-prover/key/v1\0' + bytes(range(32))
    ///   + bytes([0xA0+i for i in range(16)])).hexdigest())"`
    ///
    /// The point is that it is Python's SHA-3 and not this tree's: a round trip
    /// through `derive_key` twice would agree with itself while both halves
    /// drifted, which is the shape of guard lab #527 was fixed for.
    #[test]
    fn the_session_key_matches_an_independently_computed_digest() {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = 0xA0 + i as u8;
        }
        assert_eq!(
            hex_lower(&derive_key(&secret, &nonce)),
            "ea2f689e33cb69ad63de8ed453af81be8c4efc07dd2fe444b79a4bf8b18eb624"
        );
    }

    /// The AAD and nonce layouts, byte for byte against the server's own
    /// construction. These are transcribed constants, so a test that recomputes
    /// them from the same helpers would be vacuous — the literals are the check.
    #[test]
    fn the_frame_nonce_and_aad_are_the_wire_layouts() {
        assert_eq!(
            frame_nonce(b"MOBI", 1),
            [b'M', b'O', b'B', b'I', 1, 0, 0, 0, 0, 0, 0, 0]
        );
        let aad = frame_aad(&[0xAA; 16], b"DESK", 258);
        assert_eq!(&aad[..8], b"QMBPAIR\0");
        assert_eq!(aad[8], 1);
        assert_eq!(&aad[9..25], &[0xAA; 16]);
        assert_eq!(&aad[25..29], b"DESK");
        assert_eq!(&aad[29..], &258u64.to_le_bytes());
        assert_eq!(aad.len(), 37);
    }

    fn session() -> Session {
        Session::new(URI, "req-1", Operation::Inspect, &[1, 2, 3], None, None).unwrap()
    }

    fn handshake() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HANDSHAKE_MAGIC);
        bytes.push(PROTOCOL_VERSION);
        bytes.extend_from_slice(&[0x77; 16]);
        bytes
    }

    /// TCP splits and coalesces. Byte-at-a-time is the pathological delivery and
    /// the reassembly lives on this side of the ABI precisely so no shell has to
    /// get it right.
    #[test]
    fn the_handshake_reassembles_from_one_byte_at_a_time() {
        let mut s = session();
        let bytes = handshake();
        for (i, byte) in bytes.iter().enumerate() {
            if i > 0 {
                assert_eq!(s.step(), Step::Need, "asked to send before {i} bytes arrived");
            }
            s.supply(&[*byte]);
        }
        match s.step() {
            Step::Send(frame) => {
                assert_eq!(&frame[..8], &0u64.to_le_bytes(), "the first frame is counter 0");
                let len = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
                assert_eq!(frame.len(), 12 + len);
                assert!(len >= MIN_FRAME_BYTES);
            }
            other => panic!("expected the request frame, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_is_not_a_paired_prover_is_refused_before_anything_is_sent() {
        let mut s = session();
        s.supply(&[0u8; HANDSHAKE_BYTES]);
        match s.step() {
            Step::Failed(why) => assert!(why.contains("paired prover"), "{why}"),
            other => panic!("a wrong magic must refuse, got {other:?}"),
        }
    }

    #[test]
    fn a_server_on_another_protocol_version_is_refused_by_number() {
        let mut s = session();
        let mut bytes = handshake();
        bytes[8] = 9;
        s.supply(&bytes);
        match s.step() {
            Step::Failed(why) => {
                assert!(why.contains("v9"), "the refusal must name the version: {why}");
                assert!(why.contains("v1"), "and the one this build speaks: {why}");
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    /// A frame length the server itself would refuse before decrypting must be
    /// refused here too, or a bad length reads to the user as an authentication
    /// failure — a much more alarming sentence than the truth.
    #[test]
    fn an_out_of_range_frame_length_is_refused_as_a_length() {
        let mut s = session();
        s.supply(&handshake());
        assert!(matches!(s.step(), Step::Send(_)));
        let mut frame = 0u64.to_le_bytes().to_vec();
        frame.extend_from_slice(&4u32.to_le_bytes()); // below the 16-byte floor
        frame.extend_from_slice(&[0; 4]);
        s.supply(&frame);
        match s.step() {
            Step::Failed(why) => assert!(why.contains("outside the accepted range"), "{why}"),
            other => panic!("expected a length refusal, got {other:?}"),
        }
    }

    /// Replay and reordering: the counter must be exact. A forged frame cannot
    /// reach this check (the AEAD refuses first), but a REPLAYED real one can,
    /// and it is the counter that stops it.
    #[test]
    fn a_replayed_server_frame_is_refused_by_counter() {
        let mut keyed = Keyed::new(&[3u8; 32], [0x77; 16]);
        // Stand in for the server: same key, same layouts, the other direction.
        let seal_as_server = |k: &ChaCha20Poly1305, counter: u64, msg: &[u8]| -> Vec<u8> {
            k.encrypt(
                &Nonce::from(frame_nonce(SERVER_DIRECTION, counter)),
                Payload { msg, aad: &frame_aad(&[0x77; 16], SERVER_DIRECTION, counter) },
            )
            .unwrap()
        };
        let first = seal_as_server(&keyed.cipher, 0, b"{\"event\":\"preflight\"}");
        assert!(keyed.open(0, &first).is_ok(), "counter 0 opens once");
        let err = keyed.open(0, &first).expect_err("the same frame must not open twice");
        assert!(err.contains("counter 0 is not the expected 1"), "{err}");
    }

    /// The artifact contract: length AND digest, both checked, before any bytes
    /// are handed over as a transaction.
    #[test]
    fn the_artifact_is_refused_unless_length_and_digest_both_match() {
        let payload = b"the transaction bytes".to_vec();
        let digest = hex_lower(&Sha3_256::digest(&payload));

        // The honest path.
        let mut s = Session::new(URI, "r", Operation::Prove, &[9], Some("https://a"), Some("https://b")).unwrap();
        s.expected_bytes = Some(payload.len());
        s.expected_chunks = Some(1);
        s.expected_digest = Some(digest.clone());
        s.chunks = vec![Some(payload.clone())];
        s.finish().expect("matching length and digest");
        assert_eq!(s.take_artifact().as_deref(), Some(payload.as_slice()));

        // A truthful digest over the wrong length is still refused.
        let mut short = Session::new(URI, "r", Operation::Prove, &[9], Some("https://a"), Some("https://b")).unwrap();
        short.expected_bytes = Some(payload.len() + 1);
        short.expected_chunks = Some(1);
        short.expected_digest = Some(digest);
        short.chunks = vec![Some(payload.clone())];
        let err = short.finish().expect_err("a length mismatch must refuse");
        assert!(err.contains("announced"), "{err}");
        assert!(short.take_artifact().is_none(), "a refused artifact must not be takeable");

        // Right length, wrong digest — the tampering case.
        let mut wrong = Session::new(URI, "r", Operation::Prove, &[9], Some("https://a"), Some("https://b")).unwrap();
        wrong.expected_bytes = Some(payload.len());
        wrong.expected_chunks = Some(1);
        wrong.expected_digest = Some("00".repeat(32));
        wrong.chunks = vec![Some(payload)];
        let err = wrong.finish().expect_err("a digest mismatch must refuse");
        assert!(err.contains("hashes to"), "{err}");
        assert!(wrong.take_artifact().is_none());

        // A hole in the middle is named by index rather than silently shortening
        // the artifact — the truncation-reads-as-complete class.
        let mut gap = Session::new(URI, "r", Operation::Prove, &[9], Some("https://a"), Some("https://b")).unwrap();
        gap.expected_bytes = Some(4);
        gap.expected_chunks = Some(2);
        gap.expected_digest = Some("00".repeat(32));
        gap.chunks = vec![Some(vec![1, 2]), None];
        assert!(gap.finish().expect_err("a missing chunk").contains("chunk 1 never arrived"));
    }

    /// Proving needs both endpoints — the server re-validates against live
    /// anchors before allocating STARK work, so a request without them is a
    /// wasted round trip and a confusing refusal from the far end.
    #[test]
    fn proving_without_endpoints_is_refused_locally() {
        let err = Session::new(URI, "r", Operation::Prove, &[1], None, None).expect_err("no urls");
        assert!(err.contains("scan endpoint"), "{err}");
        // Inspect does not need them.
        assert!(Session::new(URI, "r", Operation::Inspect, &[1], None, None).is_ok());
    }

    #[test]
    fn the_request_json_is_the_shape_the_server_deserialises() {
        let s = Session::new(URI, "req-7", Operation::Prove, &[0xAB, 0xCD], Some("https://s"), Some("https://n")).unwrap();
        let json = s.request_json();
        assert!(json.contains("\"version\":1"), "{json}");
        assert!(json.contains("\"request_id\":\"req-7\""), "{json}");
        assert!(json.contains("\"operation\":\"prove\""), "{json}");
        assert!(json.contains("\"bundle_hex\":\"abcd\""), "{json}");
        assert!(json.contains("\"scan_url\":\"https://s\""), "{json}");
        assert!(json.contains("\"node_url\":\"https://n\""), "{json}");
    }

    /// An unknown event is narrated and survivable — the same forward-compat rule
    /// the event blob states, so a future server message cannot brick a shipped
    /// shell.
    #[test]
    fn an_unknown_server_event_is_narrated_not_fatal() {
        let mut s = session();
        assert_eq!(s.handle_response(b"{\"event\":\"weather\"}"), Ok(false));
        assert!(matches!(s.take_notes().first(), Some(Note::Progress(m)) if m.contains("weather")));
    }

    #[test]
    fn the_json_readers_do_not_confuse_a_key_for_a_value() {
        // A value that CONTAINS a key name must not be mistaken for that key.
        let text = "{\"event\":\"progress\",\"message\":\"event: byte_length\",\"byte_length\":7}";
        assert_eq!(json_string(text, "event").as_deref(), Some("progress"));
        assert_eq!(json_number(text, "byte_length"), Some(7));
        assert_eq!(json_string(text, "absent"), None);
        assert_eq!(json_number(text, "message"), None, "a string is not a number");
        assert_eq!(
            json_string("{\"a\":\"x\\\"y\\nz\"}", "a").as_deref(),
            Some("x\"y\nz"),
            "escapes must be undone"
        );
    }
}
