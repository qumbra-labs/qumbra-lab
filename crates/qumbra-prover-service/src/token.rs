//! **Prover admission tokens** (lab #924 5A-D3, S3): bearer tokens the
//! issuer signs with ML-DSA-44 and the prover verifies with public keys only —
//! the prover box holds no minting secret. The gateway's portal mints them
//! later with [`mint`]; for the pilot the operator mints them with
//! `qumbra-prover-service mint-token` on their own machine.
//!
//! **Wire form**: `qpt1.` ‖ base64url(payload ‖ signature), the payload fixed
//! width ([`PAYLOAD_BYTES`]):
//!
//! | field         | bytes | meaning                                          |
//! |---------------|-------|--------------------------------------------------|
//! | `key_id`      | 1     | which issuer key signed (rotation)               |
//! | `token_id`    | 16    | random; quota, in-flight and revocation key on it |
//! | `genesis_hash`| 32    | the one net this token admits to                 |
//! | `not_before`  | 8 LE  | unix seconds                                     |
//! | `not_after`   | 8 LE  | unix seconds; at most [`MAX_TOKEN_DAYS`] later   |
//! | `per_day`     | 2 LE  | admitted jobs per UTC day; 0 = the operator's    |
//! | `flags`       | 2 LE  | reserved, zero                                   |
//!
//! The signature is ML-DSA-44 (FIPS 204, deterministic, `qlab-remote-auth`'s
//! context) over `keccak256(TOKEN_DOMAIN ‖ payload)`. The issuer's key is the
//! "leaf" `key_id` of a one-key set: its descriptor binds `key_id` and the
//! verifying key exactly as an authorization leaf binds its index and key.

use std::collections::{HashMap, HashSet};

use qlab_remote_auth::intent::AuthDescriptor;
use qlab_remote_auth::mldsa::{self, SIGNATURE_BYTES, VERIFYING_KEY_BYTES};
use qlab_remote_auth::tree::mldsa_leaf;
use qlab_remote_auth::{keccak256, Hash32};
use qlab_wallet::uri::{b64url_decode, b64url_encode};

/// The token's signing domain.
pub const TOKEN_DOMAIN: &[u8] = b"qumbra:prover-token:v1";
/// The wire prefix.
pub const TOKEN_PREFIX: &str = "qpt1.";
/// The payload's fixed width.
pub const PAYLOAD_BYTES: usize = 1 + 16 + 32 + 8 + 8 + 2 + 2;
/// The longest validity a token may state.
pub const MAX_TOKEN_DAYS: u64 = 30;
/// The longest token string accepted before any decoding.
pub const MAX_TOKEN_CHARS: usize =
    TOKEN_PREFIX.len() + (PAYLOAD_BYTES + SIGNATURE_BYTES).div_ceil(3) * 4;

/// What a token states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claims {
    pub key_id: u8,
    pub token_id: [u8; 16],
    pub genesis_hash: Hash32,
    pub not_before: u64,
    pub not_after: u64,
    pub per_day: u16,
}

impl Claims {
    fn payload(&self) -> [u8; PAYLOAD_BYTES] {
        let mut p = [0u8; PAYLOAD_BYTES];
        p[0] = self.key_id;
        p[1..17].copy_from_slice(&self.token_id);
        p[17..49].copy_from_slice(&self.genesis_hash);
        p[49..57].copy_from_slice(&self.not_before.to_le_bytes());
        p[57..65].copy_from_slice(&self.not_after.to_le_bytes());
        p[65..67].copy_from_slice(&self.per_day.to_le_bytes());
        p
    }

    fn from_payload(p: &[u8; PAYLOAD_BYTES]) -> Result<Self, &'static str> {
        if p[67..69] != [0, 0] {
            return Err("token-malformed");
        }
        let u64_at = |at: usize| u64::from_le_bytes(p[at..at + 8].try_into().expect("8 bytes"));
        Ok(Claims {
            key_id: p[0],
            token_id: p[1..17].try_into().expect("16 bytes"),
            genesis_hash: p[17..49].try_into().expect("32 bytes"),
            not_before: u64_at(49),
            not_after: u64_at(57),
            per_day: u16::from_le_bytes([p[65], p[66]]),
        })
    }
}

fn digest(payload: &[u8; PAYLOAD_BYTES]) -> Hash32 {
    keccak256(&[TOKEN_DOMAIN, payload])
}

fn descriptor(key_id: u8, verifying_key: &[u8]) -> AuthDescriptor {
    AuthDescriptor::MlDsa44 {
        leaf_index: u32::from(key_id),
        leaf: mldsa_leaf(u32::from(key_id), verifying_key),
    }
}

/// The issuer's verifying key for `seed` — one line of the prover's key file
/// is `key_id` and this, hex.
pub fn verifying_key(seed: &Hash32) -> Vec<u8> {
    mldsa::Key::from_seed(*seed).verifying_key_bytes()
}

/// Mint a token: `claims` signed by the issuer key `seed`. Refuses a
/// validity window the prover would refuse.
pub fn mint(seed: &Hash32, claims: &Claims) -> Result<String, &'static str> {
    if claims.not_after <= claims.not_before
        || claims.not_after - claims.not_before > MAX_TOKEN_DAYS * 86_400
    {
        return Err("token-window-invalid");
    }
    let payload = claims.payload();
    let signature = mldsa::Key::from_seed(*seed).sign(&digest(&payload));
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(&signature);
    Ok(format!("{TOKEN_PREFIX}{}", b64url_encode(&bytes)))
}

/// The prover's view: the issuer keys it trusts (public) and the revoked
/// token ids.
#[derive(Default)]
pub struct TokenKeys {
    keys: HashMap<u8, Vec<u8>>,
    denied: HashSet<[u8; 16]>,
}

impl TokenKeys {
    /// Parse the key file: one `key_id verifying_key_hex` per line; blank
    /// lines and `#` comments skipped.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut keys = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, hex) = line
                .split_once(char::is_whitespace)
                .ok_or(format!("token key line {}: `key_id hex`", n + 1))?;
            let id: u8 = id
                .parse()
                .map_err(|_| format!("token key line {}: key_id is 0..=255", n + 1))?;
            let vk = hex_decode(hex.trim())
                .ok_or(format!("token key line {}: the key is not hex", n + 1))?;
            if vk.len() != VERIFYING_KEY_BYTES {
                return Err(format!(
                    "token key line {}: an ML-DSA-44 key is {VERIFYING_KEY_BYTES} bytes",
                    n + 1
                ));
            }
            if keys.insert(id, vk).is_some() {
                return Err(format!("token key line {}: key_id {id} twice", n + 1));
            }
        }
        if keys.is_empty() {
            return Err("the token key file names no key".into());
        }
        Ok(Self {
            keys,
            denied: HashSet::new(),
        })
    }

    /// Replace the revocation list: one token id (32 hex) per line.
    pub fn set_denied(&mut self, text: &str) -> Result<(), String> {
        let mut denied = HashSet::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let id = hex_decode(line)
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .ok_or(format!("token deny line {}: a token id is 32 hex", n + 1))?;
            denied.insert(id);
        }
        self.denied = denied;
        Ok(())
    }

    /// Verify a bearer token for the net `genesis_hash` at unix time `now`.
    /// Every refusal is a fixed code; nothing is decoded before the length
    /// check.
    pub fn verify(
        &self,
        token: &str,
        genesis_hash: &Hash32,
        now: u64,
    ) -> Result<Claims, &'static str> {
        if token.len() > MAX_TOKEN_CHARS {
            return Err("token-malformed");
        }
        let body = token.strip_prefix(TOKEN_PREFIX).ok_or("token-malformed")?;
        let bytes = b64url_decode(body).map_err(|_| "token-malformed")?;
        if bytes.len() != PAYLOAD_BYTES + SIGNATURE_BYTES {
            return Err("token-malformed");
        }
        let payload: [u8; PAYLOAD_BYTES] =
            bytes[..PAYLOAD_BYTES].try_into().expect("length checked");
        let claims = Claims::from_payload(&payload)?;
        let vk = self.keys.get(&claims.key_id).ok_or("token-key-unknown")?;
        if !mldsa::verify(
            &descriptor(claims.key_id, vk),
            vk,
            &bytes[PAYLOAD_BYTES..],
            &digest(&payload),
        ) {
            return Err("token-signature-invalid");
        }
        if claims.not_after <= claims.not_before
            || claims.not_after - claims.not_before > MAX_TOKEN_DAYS * 86_400
        {
            return Err("token-window-invalid");
        }
        if now < claims.not_before || now >= claims.not_after {
            return Err("token-expired");
        }
        if claims.genesis_hash != *genesis_hash {
            return Err("token-wrong-net");
        }
        if self.denied.contains(&claims.token_id) {
            return Err("token-revoked");
        }
        Ok(claims)
    }
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Hash32 = [0x7a; 32];
    const NET: Hash32 = [0x33; 32];
    const NOW: u64 = 1_800_000_000;

    fn claims() -> Claims {
        Claims {
            key_id: 3,
            token_id: [0x11; 16],
            genesis_hash: NET,
            not_before: NOW - 60,
            not_after: NOW + 86_400,
            per_day: 5,
        }
    }

    fn keys() -> TokenKeys {
        TokenKeys::parse(&format!("# issuer\n3 {}\n", hex(&verifying_key(&SEED)))).unwrap()
    }

    #[test]
    fn a_minted_token_verifies_and_states_its_claims() {
        let token = mint(&SEED, &claims()).unwrap();
        assert!(token.len() <= MAX_TOKEN_CHARS, "{} chars", token.len());
        assert_eq!(keys().verify(&token, &NET, NOW), Ok(claims()));
    }

    #[test]
    fn a_token_is_refused_by_name() {
        let token = mint(&SEED, &claims()).unwrap();
        let k = keys();
        assert_eq!(k.verify(&token, &[0x34; 32], NOW), Err("token-wrong-net"));
        assert_eq!(k.verify(&token, &NET, NOW + 86_400), Err("token-expired"));
        assert_eq!(k.verify(&token, &NET, NOW - 61), Err("token-expired"));
        // Another issuer key under the same key_id.
        let forged = mint(&[0x7b; 32], &claims()).unwrap();
        assert_eq!(k.verify(&forged, &NET, NOW), Err("token-signature-invalid"));
        // An unknown key_id.
        let other = mint(
            &SEED,
            &Claims {
                key_id: 4,
                ..claims()
            },
        )
        .unwrap();
        assert_eq!(k.verify(&other, &NET, NOW), Err("token-key-unknown"));
        // A payload byte changed after signing (per_day raised).
        let mut bytes = b64url_decode(token.strip_prefix(TOKEN_PREFIX).unwrap()).unwrap();
        bytes[65] = 200;
        let raised = format!("{TOKEN_PREFIX}{}", b64url_encode(&bytes));
        assert_eq!(k.verify(&raised, &NET, NOW), Err("token-signature-invalid"));
        // Reserved flags.
        bytes[65] = 5;
        bytes[67] = 1;
        let flagged = format!("{TOKEN_PREFIX}{}", b64url_encode(&bytes));
        assert_eq!(k.verify(&flagged, &NET, NOW), Err("token-malformed"));
        // Shape.
        assert_eq!(k.verify("qpt2.AAAA", &NET, NOW), Err("token-malformed"));
        assert_eq!(
            k.verify(&format!("{token}AAAA"), &NET, NOW),
            Err("token-malformed")
        );
        assert_eq!(
            k.verify(&"a".repeat(MAX_TOKEN_CHARS + 1), &NET, NOW),
            Err("token-malformed")
        );
        // Revoked.
        let mut k = keys();
        k.set_denied(&hex(&[0x11; 16])).unwrap();
        assert_eq!(k.verify(&token, &NET, NOW), Err("token-revoked"));
    }

    #[test]
    fn the_validity_window_is_bounded_at_both_ends() {
        let long = Claims {
            not_after: NOW - 60 + MAX_TOKEN_DAYS * 86_400 + 1,
            ..claims()
        };
        assert_eq!(mint(&SEED, &long), Err("token-window-invalid"));
        let empty = Claims {
            not_after: NOW - 60,
            ..claims()
        };
        assert_eq!(mint(&SEED, &empty), Err("token-window-invalid"));
    }

    #[test]
    fn the_key_file_is_parsed_strictly() {
        let vk = hex(&verifying_key(&SEED));
        assert!(TokenKeys::parse("").is_err());
        assert!(TokenKeys::parse("3 abcd").is_err());
        assert!(TokenKeys::parse(&format!("300 {vk}")).is_err());
        assert!(TokenKeys::parse(&format!("3 {vk}\n3 {vk}")).is_err());
        assert!(keys().set_denied("zz").is_err());
    }
}
