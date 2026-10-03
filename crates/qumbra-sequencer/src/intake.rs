//! **Intake** (lab #847 S2): what a wallet hands the sequencer, read and
//! verified on arrival.
//!
//! Two artifacts, both the wallet's own strict codecs (`qlab_l2spend`):
//!
//! - a **claim file** (`qumbra:l2-claim\0`, lab #831 W3b/W3c) — decoded
//!   against this chain's genesis and claim tier, its `l2_id` this chain's,
//!   its proof verified under the claim AIR (`verify_claim_u32`) — exactly
//!   f5box's `read_claim_file`;
//! - an **exit file** (`qumbra:l2-exit\0`, W2) — decoded against this genesis
//!   (exactly one asset-0 exit, a 3×2 shape-P transaction), its proof verified
//!   by the node's own L2 verifier (`qumbra_node::verifier::L2Verifier`).
//!
//! Each yields its **dedupe keys**: a claim's `cnf` (the burn's claim
//! nullifier, `PV_CNF`), an exit's three nullifiers. Whether a wrapper can
//! absorb an item's anchor is not judged here — that is plan time (S4), where
//! an item that does not fit yet is held, not dropped.
//!
//! **What intake never says.** An item is named by its id (Keccak-256 of the
//! artifact bytes) and its kind; a refusal by the reason and, for a key, the
//! key's *name*. A claim file carries the deposit-sum opening `(v, r_v)` —
//! the deposit amount — and none of `v`, `r_v` or the artifact's bytes is
//! ever logged, echoed or answered.
//!
//! **Safety split.** Intake's dedupe saves plan slots and gives a wallet a
//! stable id to recover with; it is a convenience. The double-spend guarantee
//! is the chain's: `WState::apply` refuses a repeated `cnf` or nullifier at
//! plan time, and the node's bundle rule refuses it again — so it holds even
//! if intake's disk is lost. The sequencer's own fillers (S3) never pass
//! through intake and are never in its index.

use qlab_air::claim::PV_CNF;
use qlab_wprover::f4::native::{Member, WTag};
use qlab_wrapper::codec::digest_to_bytes;

/// What an artifact is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Claim,
    Exit,
}

impl Kind {
    /// The kind's name on every surface (`"claim"` / `"exit"`).
    pub fn name(self) -> &'static str {
        match self {
            Kind::Claim => "claim",
            Kind::Exit => "exit",
        }
    }

    /// The inverse of [`Self::name`].
    pub fn from_name(s: &str) -> Option<Kind> {
        match s {
            "claim" => Some(Kind::Claim),
            "exit" => Some(Kind::Exit),
            _ => None,
        }
    }

    /// The name of the key a duplicate of this kind collides on.
    pub fn key_name(self) -> &'static str {
        match self {
            Kind::Claim => "cnf",
            Kind::Exit => "nullifier",
        }
    }
}

/// The chain an intake serves, from its V6 genesis (never from flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain {
    /// The V6 genesis hash both artifacts bind.
    pub genesis: [u8; 32],
    pub l2_id: u64,
    /// The genesis claim tariff every claim's `PV_FEE` must equal.
    pub claim_fee_tier: u64,
}

impl Chain {
    /// From the V6 genesis file the node runs.
    pub fn of(genesis: &qumbra_node::genesis_v6::GenesisFileV6) -> Chain {
        Chain { genesis: genesis.hash(), l2_id: genesis.wrapper.l2_id, claim_fee_tier: genesis.wrapper.claim_fee_tier }
    }
}

/// An artifact that decoded: its id, kind and dedupe keys. Its proof is not
/// checked yet — [`verify`] does that, after the cheap checks (a replay, a
/// collision, a full queue) have had their chance to answer first.
#[derive(Clone)]
pub struct Candidate {
    pub id: [u8; 32],
    pub kind: Kind,
    pub keys: Vec<[u8; 32]>,
    proof: Proof,
}

#[derive(Clone)]
enum Proof {
    Claim { pvs: Vec<u32>, proof: Vec<u8> },
    Exit(Box<qlab_devnet::body::TxEntry>),
}

/// Its id, kind and key count — never the proof or the keys themselves.
impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate").field("id", &hex32(&self.id)).field("kind", &self.kind).field("keys", &self.keys.len()).finish()
    }
}

/// The Keccak-256 of an artifact's bytes: its id everywhere.
pub fn id_of(bytes: &[u8]) -> [u8; 32] {
    qlab_devnet::hash::keccak256(bytes)
}

/// Lower-case hex of a 32-byte id or key.
pub fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Exactly 64 lower-case hex digits, or `None`.
pub fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode an artifact against `chain`: which kind, its id, its keys. Refused
/// by name for anything that is neither, or that the kind's codec refuses.
/// The messages name the reason only — never a value from the file.
pub fn classify(bytes: &[u8], chain: &Chain) -> Result<Candidate, String> {
    let id = id_of(bytes);
    if bytes.starts_with(qlab_l2spend::CLAIM_ARTIFACT_MAGIC) {
        let file = qlab_l2spend::decode_claim_artifact(bytes, &chain.genesis, chain.claim_fee_tier)
            .map_err(|e| format!("claim file refused: {e}"))?;
        if file.l2_id != chain.l2_id {
            return Err(format!("claim file refused: a claim to L2 {}, and this chain bridges L2 {}", file.l2_id, chain.l2_id));
        }
        let cnf = Member { tag: WTag::C, pvs: file.pvs.clone(), write: None }
            .digest_at(PV_CNF)
            .map_err(|e| format!("claim file refused: its cnf does not read: {e:?}"))?;
        Ok(Candidate { id, kind: Kind::Claim, keys: vec![digest_to_bytes(&cnf)], proof: Proof::Claim { pvs: file.pvs, proof: file.proof } })
    } else if bytes.starts_with(qlab_l2spend::EXIT_ARTIFACT_MAGIC) {
        let (tx, _) =
            qlab_l2spend::decode_exit_artifact(bytes, &chain.genesis).map_err(|e| format!("exit file refused: {e}"))?;
        let keys = tx.public.nullifiers.clone();
        Ok(Candidate { id, kind: Kind::Exit, keys, proof: Proof::Exit(Box::new(tx)) })
    } else {
        Err("neither a claim file nor an exit file (the magic matches neither)".into())
    }
}

/// Verify a candidate's proof: a claim under the claim AIR for this chain's
/// `l2_id` and tier; an exit by the node's L2 verifier. The expensive check,
/// run last.
pub fn verify(c: &Candidate, chain: &Chain) -> Result<(), String> {
    match &c.proof {
        Proof::Claim { pvs, proof } => {
            let proof: qlab_consensus::Proof<qlab_consensus::Config> =
                bincode::deserialize(proof).map_err(|_| "claim file refused: its proof does not decode".to_string())?;
            qlab_l2::claim::verify_claim_u32(pvs, &proof, chain.l2_id, chain.claim_fee_tier)
                .map_err(|e| format!("claim file refused: its proof does not verify ({e:?})"))
        }
        Proof::Exit(tx) => qumbra_node::verifier::L2Verifier
            .check(tx)
            .map_err(|e| format!("exit file refused: its proof does not verify ({e:?})")),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A real claim file: the W3c box run's (lab #831, 2026-10-03), on the V6
    /// rehearsal chain — a rehearsal wallet's 0.5 QMB deposit, nobody's
    /// money. The one checked-in artifact with a real proof, so the lane
    /// verifies without proving.
    pub(crate) const W3C_CLAIM: &[u8] = include_bytes!("../tests/fixtures/w3c-deposit.claim");

    /// The chain that file was built on: the V6 rehearsal genesis, L2 1,
    /// claim tier 4 (its header and the run's /v1/l2).
    pub(crate) fn w3c_chain() -> Chain {
        let mut genesis = [0u8; 32];
        genesis.copy_from_slice(&W3C_CLAIM[17..49]);
        Chain { genesis, l2_id: 1, claim_fee_tier: 4 }
    }

    #[test]
    fn the_real_claim_classifies_and_verifies() {
        let chain = w3c_chain();
        let c = classify(W3C_CLAIM, &chain).expect("the W3c claim decodes");
        assert_eq!((c.kind, c.keys.len(), c.id), (Kind::Claim, 1, id_of(W3C_CLAIM)));
        verify(&c, &chain).expect("the W3c claim's proof verifies");
    }

    /// Refusals by name, each from the same fixture changed in one place;
    /// none echoes a value from the file.
    #[test]
    fn a_wrong_chain_tier_or_l2_or_a_flipped_proof_is_refused_by_name() {
        let chain = w3c_chain();
        let other = Chain { genesis: [7; 32], ..chain };
        assert!(classify(W3C_CLAIM, &other).unwrap_err().contains("claim file refused"));
        let tier = Chain { claim_fee_tier: 5, ..chain };
        assert!(classify(W3C_CLAIM, &tier).unwrap_err().contains("claim file refused"));
        let l2 = Chain { l2_id: 2, ..chain };
        assert!(classify(W3C_CLAIM, &l2).unwrap_err().contains("this chain bridges L2 2"));
        // A byte deep in the proof: decodes, does not verify (or does not
        // decode) — refused either way, before anything is queued.
        let mut flipped = W3C_CLAIM.to_vec();
        let at = flipped.len() / 2;
        flipped[at] ^= 1;
        let refused = classify(&flipped, &chain).and_then(|c| verify(&c, &chain));
        let err = refused.unwrap_err();
        assert!(err.starts_with("claim file refused"), "{err}");
        assert!(!err.contains("50000000"), "a refusal never names the deposit amount: {err}");
    }

    #[test]
    fn neither_kind_and_a_truncated_exit_are_refused() {
        let chain = w3c_chain();
        assert!(classify(b"hello", &chain).unwrap_err().contains("neither a claim file nor an exit file"));
        let mut exit = qlab_l2spend::EXIT_ARTIFACT_MAGIC.to_vec();
        exit.push(1);
        assert!(classify(&exit, &chain).unwrap_err().starts_with("exit file refused"));
    }

    #[test]
    fn ids_and_hex_round_trip() {
        let id = id_of(b"x");
        assert_eq!(parse_hex32(&hex32(&id)), Some(id));
        assert_eq!(parse_hex32(&hex32(&id).to_uppercase()), None);
        assert_eq!(parse_hex32("00"), None);
        assert_eq!(Kind::from_name(Kind::Exit.name()), Some(Kind::Exit));
    }
}
