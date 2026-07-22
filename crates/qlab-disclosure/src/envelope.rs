//! The wallet-interop-spec §3 selective disclosure-proof envelope.
//!
//! §3 fixes the *container and verification rules* (the proof system inside is
//! this crate's [`crate::air`]). The binary envelope is:
//!
//! ```text
//!   ver (u8=0x01) ‖ claim_type (u8: 0x01 = sent-payment)
//!     ‖ tx_ref (32 B txid)
//!     ‖ claim_body
//!     ‖ proof_len (LEB128 varint) ‖ proof_bytes
//! ```
//!
//! For claim 0x01, `claim_body = value (u64 LE) ‖ recipient_addr_commitment
//! (32 B) ‖ output_index (u8)`. The recipient is identified by *commitment*, so
//! the envelope leaks nothing about the address to third parties — only a
//! verifier who already holds the claimed address can recompute the hash.
//!
//! ## Verification rules (§3, normative)
//!
//! 1. `tx_ref` exists on-chain and is finalized — supplied to [`Envelope::verify`]
//!    as the caller's chain lookup (`chain_cm` = the commitment the node reads at
//!    `(tx_ref, output_index)`); this crate does not model the chain.
//! 2. `proof_bytes` verifies against the claim body and the on-chain public data
//!    (the cm), under the versioned proof system.
//! 3. Verifiers MUST reject unknown `ver` / `claim_type` rather than ignore them.

use qlab_note::hash::digest_from_bytes;

use crate::air::{pv_vec, DisclosureAir, DisclosureInstance};
use crate::prove::{prove, verify as stark_verify, DisclosureProof, FriCfg};

/// Envelope version this crate produces and accepts.
pub const ENVELOPE_VER: u8 = 0x01;
/// Claim type 0x01 = "sent-payment" (the only claim in scope).
pub const CLAIM_SENT_PAYMENT: u8 = 0x01;

/// A parsed §3 disclosure envelope (claim 0x01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub ver: u8,
    pub claim_type: u8,
    pub tx_ref: [u8; 32],
    pub value: u64,
    pub addr_commitment: [u8; 32],
    pub output_index: u8,
    pub proof_bytes: Vec<u8>,
}

/// Errors surfaced by envelope parsing / verification (§3 rule violations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Byte stream too short / malformed framing.
    Malformed(&'static str),
    /// Rule 3: unknown envelope version.
    UnknownVersion(u8),
    /// Rule 3: unknown claim type.
    UnknownClaimType(u8),
    /// The proof bytes did not deserialize into a valid proof structure.
    ProofDecode,
    /// Rule 2: the proof failed to verify against the claim body + chain cm.
    ProofInvalid(String),
}

impl core::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for EnvelopeError {}

fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, EnvelopeError> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf
            .get(*pos)
            .ok_or(EnvelopeError::Malformed("varint truncated"))?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(EnvelopeError::Malformed("varint overflow"));
        }
    }
    Ok(result)
}

impl Envelope {
    /// Prove a disclosure instance and pack the §3 envelope. `tx_ref` /
    /// `output_index` bind the claim to the specific on-chain output.
    pub fn create(
        inst: &DisclosureInstance,
        tx_ref: [u8; 32],
        output_index: u8,
        cfg: &FriCfg,
    ) -> Envelope {
        let proof = prove(inst, cfg);
        let proof_bytes = postcard::to_allocvec(&proof).expect("proof serialization");
        let mut addr_commitment = [0u8; 32];
        for i in 0..4 {
            addr_commitment[i * 8..i * 8 + 8].copy_from_slice(&inst.addr_commitment[i].to_le_bytes());
        }
        Envelope {
            ver: ENVELOPE_VER,
            claim_type: CLAIM_SENT_PAYMENT,
            tx_ref,
            value: inst.value,
            addr_commitment,
            output_index,
            proof_bytes,
        }
    }

    /// Serialize to the §3 binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(75 + self.proof_bytes.len());
        out.push(self.ver);
        out.push(self.claim_type);
        out.extend_from_slice(&self.tx_ref);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.addr_commitment);
        out.push(self.output_index);
        write_varint(&mut out, self.proof_bytes.len() as u64);
        out.extend_from_slice(&self.proof_bytes);
        out
    }

    /// Parse the §3 binary format. Rejects unknown `ver` / `claim_type`
    /// (rule 3) and malformed framing.
    pub fn from_bytes(buf: &[u8]) -> Result<Envelope, EnvelopeError> {
        let mut pos = 0usize;
        let take = |buf: &[u8], pos: &mut usize, n: usize| -> Result<Vec<u8>, EnvelopeError> {
            let end = *pos + n;
            let s = buf
                .get(*pos..end)
                .ok_or(EnvelopeError::Malformed("truncated field"))?
                .to_vec();
            *pos = end;
            Ok(s)
        };
        let ver = *buf.first().ok_or(EnvelopeError::Malformed("empty"))?;
        pos += 1;
        if ver != ENVELOPE_VER {
            return Err(EnvelopeError::UnknownVersion(ver));
        }
        let claim_type = *buf.get(pos).ok_or(EnvelopeError::Malformed("no claim_type"))?;
        pos += 1;
        if claim_type != CLAIM_SENT_PAYMENT {
            return Err(EnvelopeError::UnknownClaimType(claim_type));
        }
        let tx_ref: [u8; 32] = take(buf, &mut pos, 32)?.try_into().unwrap();
        let value = u64::from_le_bytes(take(buf, &mut pos, 8)?.try_into().unwrap());
        let addr_commitment: [u8; 32] = take(buf, &mut pos, 32)?.try_into().unwrap();
        let output_index = *buf.get(pos).ok_or(EnvelopeError::Malformed("no output_index"))?;
        pos += 1;
        let proof_len = read_varint(buf, &mut pos)? as usize;
        let proof_bytes = take(buf, &mut pos, proof_len)?;
        if pos != buf.len() {
            return Err(EnvelopeError::Malformed("trailing bytes"));
        }
        Ok(Envelope {
            ver,
            claim_type,
            tx_ref,
            value,
            addr_commitment,
            output_index,
            proof_bytes,
        })
    }

    /// Verify per §3 rules. `chain_cm` is the commitment the caller reads at
    /// `(tx_ref, output_index)` on the finalized chain (rule 1 is the caller's
    /// responsibility — here it becomes the public `cm` the proof is checked
    /// against). `log_height` / `cfg` must match what the prover used.
    pub fn verify(&self, chain_cm: &[u8; 32], log_height: usize, cfg: &FriCfg) -> Result<(), EnvelopeError> {
        // Rule 3 (defensive — also enforced in from_bytes).
        if self.ver != ENVELOPE_VER {
            return Err(EnvelopeError::UnknownVersion(self.ver));
        }
        if self.claim_type != CLAIM_SENT_PAYMENT {
            return Err(EnvelopeError::UnknownClaimType(self.claim_type));
        }
        let proof: DisclosureProof =
            postcard::from_bytes(&self.proof_bytes).map_err(|_| EnvelopeError::ProofDecode)?;
        // Rule 2: public values = (cm from chain, addr_commitment + value from
        // the claim body). The proof binds all three; a lie in any fails here.
        let cm = digest_from_bytes(chain_cm);
        let addr = digest_from_bytes(&self.addr_commitment);
        let pvs = pv_vec(&cm, &addr, self.value);
        let air = DisclosureAir::verifier(log_height);
        stark_verify(&air, &proof, &pvs, cfg).map_err(EnvelopeError::ProofInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::build_disclosure;
    use qlab_note::kem::generate_keypair;
    use qlab_wallet::address::{Address, Diversifier};
    use rand::{rngs::StdRng, SeedableRng};

    fn cfg() -> FriCfg {
        FriCfg {
            log_blowup: 2,
            num_queries: 45,
            grind_bits: 10,
            log_final_poly_len: 2,
            max_log_arity: 3,
        }
    }

    fn instance() -> (DisclosureInstance, [u8; 32]) {
        let mut rng = StdRng::seed_from_u64(3);
        let kp = generate_keypair(&mut rng);
        let rkm = [0x11u64, 0x22, 0x33, 0x44];
        let addr = Address::new(Diversifier::from_bytes([5u8; 16]), rkm, &kp.ek);
        let inst = build_disclosure(16, 42_000, &rkm, &[1, 1, 1, 1], &[2, 2, 2, 2], &addr.to_raw_bytes());
        // chain cm (as bytes) = the instance's cm.
        let mut chain_cm = [0u8; 32];
        for i in 0..4 {
            chain_cm[i * 8..i * 8 + 8].copy_from_slice(&inst.cm[i].to_le_bytes());
        }
        (inst, chain_cm)
    }

    #[test]
    fn envelope_roundtrip_and_verify() {
        let (inst, chain_cm) = instance();
        let env = Envelope::create(&inst, [9u8; 32], 1, &cfg());
        // Binary round-trips.
        let bytes = env.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, env);
        // Verifies against the correct chain cm.
        parsed.verify(&chain_cm, 16, &cfg()).expect("verify");
    }

    #[test]
    fn reject_unknown_ver_and_type() {
        let (inst, _) = instance();
        let env = Envelope::create(&inst, [0u8; 32], 0, &cfg());
        let mut b = env.to_bytes();
        b[0] = 0x02; // unknown version
        assert!(matches!(Envelope::from_bytes(&b), Err(EnvelopeError::UnknownVersion(2))));
        let mut b2 = env.to_bytes();
        b2[1] = 0x03; // unknown claim type
        assert!(matches!(Envelope::from_bytes(&b2), Err(EnvelopeError::UnknownClaimType(3))));
    }

    #[test]
    fn tamper_negatives() {
        let (inst, chain_cm) = instance();
        let env = Envelope::create(&inst, [1u8; 32], 0, &cfg());

        // Wrong value in the claim body → proof invalid.
        let mut e_val = env.clone();
        e_val.value ^= 1;
        assert!(matches!(
            e_val.verify(&chain_cm, 16, &cfg()),
            Err(EnvelopeError::ProofInvalid(_))
        ));

        // Wrong addr_commitment in the claim body → proof invalid.
        let mut e_addr = env.clone();
        e_addr.addr_commitment[0] ^= 1;
        assert!(matches!(
            e_addr.verify(&chain_cm, 16, &cfg()),
            Err(EnvelopeError::ProofInvalid(_))
        ));

        // Wrong chain cm (verifier reads a different output) → proof invalid.
        let mut bad_cm = chain_cm;
        bad_cm[0] ^= 1;
        assert!(matches!(
            env.verify(&bad_cm, 16, &cfg()),
            Err(EnvelopeError::ProofInvalid(_))
        ));

        // Tampered proof bytes → decode error or proof invalid.
        let mut e_proof = env.clone();
        let n = e_proof.proof_bytes.len();
        e_proof.proof_bytes[n / 2] ^= 0xff;
        assert!(e_proof.verify(&chain_cm, 16, &cfg()).is_err());
    }
}
