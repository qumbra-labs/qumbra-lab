//! The serializable boundary between spend selection and proving.
//!
//! A [`WitnessBundle`] is **spend authority for exactly one transaction**. It
//! carries the selected notes' spending witnesses, the finalized anchor, both
//! output plaintexts, and their already-sealed discovery bytes. That is the
//! minimum shape which lets a prover host do its one job with no wallet dir,
//! network, or key material from anywhere else.
//!
//! The format is versioned and reject-unknown. Its trailing checksum catches a
//! truncated or accidentally edited handoff; it is deliberately not described
//! as authentication — every secret needed to recompute it is in the same
//! artifact, because the browser extension and its native host are one trust
//! domain. The semantic checks are the load-bearing half: a decoded bundle must
//! still prove that phase 1 established an allowed scan verdict and complete
//! nullifier coverage, and its inputs, paths, outputs, balance, anchor and
//! discovery group must agree with one another before a real STARK is started.

use qlab_air::narrow::{derive_input, derive_output_rho, MerkleWitness, TxInput, TxOutput};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_note::compact::decode_committed_discovery;
use qlab_note::hash::digest_bytes;
use zeroize::Zeroize;

/// Fixed discriminator. A version byte follows it.
pub const WITNESS_BUNDLE_MAGIC: &[u8; 8] = b"QMBWITN\0";
/// The only witness-bundle schema this binary reads.
pub const WITNESS_BUNDLE_VERSION: u8 = 1;

const CHECKSUM_LEN: usize = 32;
const CHECKSUM_DOMAIN: &[u8] = b"qumbra:witness-bundle:v1";

/// A pre-proof spend handoff.
///
/// No `Debug`: this value contains spending-key material. Use [`Self::to_bytes`]
/// only across the user's local trusted boundary, and discard it once its
/// transaction is accepted or known duplicate.
#[derive(Clone)]
pub struct WitnessBundle {
    pub(crate) inputs: [TxInput; 2],
    pub(crate) witnesses: [MerkleWitness; 2],
    pub(crate) outputs: [TxOutput; 2],
    pub(crate) anchor: [u64; 4],
    pub(crate) discovery: Vec<u8>,
    /// Canonical name-service rider bytes selected with the outputs and fee.
    /// Absence is the codec's one-byte `[0x00]`, never an empty vector.
    pub(crate) rider: Vec<u8>,
    pub(crate) real_inputs: u8,
    pub(crate) amount: u64,
    pub(crate) fee: u64,
    pub(crate) change_value: u64,
    pub(crate) anchor_tip_height: u64,
    pub(crate) recipient_short: String,
    // The phase-1 receipt. These are facts established by the scan and bulk
    // nullifier fetch, not guesses reconstructed by the prover host.
    pub(crate) allowed_scan_verdicts_only: bool,
    pub(crate) output_range: Option<(u64, u64)>,
    pub(crate) spent_covered: Option<(u64, u64)>,
}

impl Zeroize for WitnessBundle {
    fn zeroize(&mut self) {
        // Keep this list in lockstep with every field on `WitnessBundle`.
        // `witness_bundle_zeroize_clears_typed_spend_authority` is the
        // regression guard for additions to this manual implementation.
        for input in &mut self.inputs {
            input.sk.zeroize();
            input.value.zeroize();
            input.rho.zeroize();
            input.rseed.zeroize();
            input.d.zeroize();
        }
        for witness in &mut self.witnesses {
            witness.siblings.zeroize();
            witness.path_bits.fill(false);
        }
        for output in &mut self.outputs {
            output.value.zeroize();
            output.rkm.zeroize();
            output.rho.zeroize();
            output.rseed.zeroize();
        }
        self.anchor.zeroize();
        self.discovery.zeroize();
        self.rider.zeroize();
        self.real_inputs.zeroize();
        self.amount.zeroize();
        self.fee.zeroize();
        self.change_value.zeroize();
        self.anchor_tip_height.zeroize();
        self.recipient_short.zeroize();
        self.allowed_scan_verdicts_only = false;
        if let Some((from, to)) = self.output_range.as_mut() {
            from.zeroize();
            to.zeroize();
        }
        self.output_range = None;
        if let Some((from, to)) = self.spent_covered.as_mut() {
            from.zeroize();
            to.zeroize();
        }
        self.spent_covered = None;
    }
}

impl Drop for WitnessBundle {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl WitnessBundle {
    /// The finalized root this bundle proves membership against, on wire.
    pub fn anchor(&self) -> [u8; 32] {
        digest_bytes(&self.anchor)
    }

    /// The chain tip at which phase 1 selected the anchor.
    pub fn selected_at_tip(&self) -> u64 {
        self.anchor_tip_height
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn recipient_short(&self) -> &str {
        &self.recipient_short
    }

    pub fn used_dummy(&self) -> bool {
        self.real_inputs == 1
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn change_value(&self) -> u64 {
        self.change_value
    }

    /// The REAL inputs' nullifiers — public since the extension's history
    /// join (roadmap #4): these exact bytes go on-chain the moment the spend
    /// lands, so reading them here leaks nothing the chain does not.
    pub fn real_nullifiers(&self) -> Vec<[u8; 32]> {
        self.inputs[..usize::from(self.real_inputs)]
            .iter()
            .map(|input| digest_bytes(&derive_input(input).1))
            .collect()
    }

    pub(crate) fn output_range(&self) -> Option<(u64, u64)> {
        self.output_range
    }

    /// Serialize the versioned artifact. The checksum covers magic, version and
    /// every payload byte.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(WITNESS_BUNDLE_MAGIC);
        out.push(WITNESS_BUNDLE_VERSION);
        out.push(u8::from(self.allowed_scan_verdicts_only));
        put_range(&mut out, self.output_range);
        put_range(&mut out, self.spent_covered);
        out.push(self.real_inputs);
        put_u64(&mut out, self.amount);
        put_u64(&mut out, self.fee);
        put_u64(&mut out, self.change_value);
        put_u64(&mut out, self.anchor_tip_height);
        put_lanes(&mut out, &self.anchor);
        for input in &self.inputs {
            put_input(&mut out, input);
        }
        for witness in &self.witnesses {
            put_witness(&mut out, witness);
        }
        for output in &self.outputs {
            put_output(&mut out, output);
        }
        put_bytes(&mut out, self.recipient_short.as_bytes());
        put_bytes(&mut out, &self.discovery);
        put_bytes(&mut out, &self.rider);
        let checksum = checksum(&out);
        out.extend_from_slice(&checksum);
        out
    }

    /// Decode, reject an unknown schema, verify the checksum, then re-establish
    /// every internal invariant phase 2 relies on before returning a typed
    /// bundle.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() < WITNESS_BUNDLE_MAGIC.len() + 1 + CHECKSUM_LEN {
            return Err(BundleError::Malformed(
                "record is shorter than its header and checksum".into(),
            ));
        }
        if &bytes[..WITNESS_BUNDLE_MAGIC.len()] != WITNESS_BUNDLE_MAGIC {
            return Err(BundleError::Malformed(
                "witness-bundle magic is absent".into(),
            ));
        }
        let version = bytes[WITNESS_BUNDLE_MAGIC.len()];
        if version != WITNESS_BUNDLE_VERSION {
            return Err(BundleError::UnknownVersion(version));
        }
        let split = bytes.len() - CHECKSUM_LEN;
        let (encoded, got_checksum) = bytes.split_at(split);
        if checksum(encoded).as_slice() != got_checksum {
            return Err(BundleError::ChecksumMismatch);
        }

        let mut r = Reader::new(&encoded[WITNESS_BUNDLE_MAGIC.len() + 1..]);
        let allowed_scan_verdicts_only = r.bool("phase-1 scan gate")?;
        let output_range = r.range("scan output range")?;
        let spent_covered = r.range("phase-1 nullifier coverage")?;
        let real_inputs = r.u8("real input count")?;
        let amount = r.u64("amount")?;
        let fee = r.u64("fee")?;
        let change_value = r.u64("change")?;
        let anchor_tip_height = r.u64("anchor tip height")?;
        let anchor = r.lanes("anchor")?;
        let inputs = [r.input("input 0")?, r.input("input 1")?];
        let witnesses = [r.witness("witness 0")?, r.witness("witness 1")?];
        let outputs = [r.output("output 0")?, r.output("output 1")?];
        let recipient_short = String::from_utf8(r.bytes("recipient short")?.to_vec())
            .map_err(|_| BundleError::Malformed("recipient short is not UTF-8".into()))?;
        let discovery = r.bytes("discovery")?.to_vec();
        let rider = r.bytes("name-service rider")?.to_vec();
        r.finish()?;

        let bundle = Self {
            inputs,
            witnesses,
            outputs,
            anchor,
            discovery,
            rider,
            real_inputs,
            amount,
            fee,
            change_value,
            anchor_tip_height,
            recipient_short,
            allowed_scan_verdicts_only,
            output_range,
            spent_covered,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub(crate) fn validate(&self) -> Result<(), BundleError> {
        if !self.allowed_scan_verdicts_only {
            return Err(BundleError::PhaseOneVerdictMissing);
        }
        let outputs = self
            .output_range
            .ok_or(BundleError::NullifierCoverageMissing {
                covered: self.spent_covered,
                outputs: self.output_range,
            })?;
        match self.spent_covered {
            Some((from, to)) if from <= outputs.0 && to >= outputs.1 => {}
            covered => {
                return Err(BundleError::NullifierCoverageMissing {
                    covered,
                    outputs: self.output_range,
                })
            }
        }
        if !matches!(self.real_inputs, 1 | 2) {
            return Err(BundleError::Malformed(format!(
                "real input count {}; the frozen bucket accepts 1 or 2",
                self.real_inputs
            )));
        }
        let name_op = qlab_devnet::names::decode_rider(&self.rider).map_err(|e| {
            BundleError::Malformed(format!("name-service rider does not decode: {e:?}"))
        })?;
        if qlab_devnet::names::encode_rider(name_op.as_ref()) != self.rider {
            return Err(BundleError::Malformed(
                "name-service rider is not canonically encoded".into(),
            ));
        }
        let expected_fee = posted_fee(ArityBucket::TwoByTwo)
            .checked_add(name_op.as_ref().map_or(0, qlab_devnet::names::name_fee_for))
            .ok_or_else(|| BundleError::Malformed("posted fee plus name fee overflows".into()))?;
        if self.fee != expected_fee {
            return Err(BundleError::Malformed(format!(
                "fee {} is not the posted 2x2 fee plus the name-service fee {expected_fee}",
                self.fee,
            )));
        }
        if self.outputs[0].value != self.amount || self.outputs[1].value != self.change_value {
            return Err(BundleError::Malformed(
                "output values do not match amount/change metadata".into(),
            ));
        }
        let total_in = self.inputs[..usize::from(self.real_inputs)]
            .iter()
            .try_fold(0u64, |sum, input| sum.checked_add(input.value))
            .ok_or_else(|| BundleError::Malformed("input value sum overflows".into()))?;
        let total_out = self
            .amount
            .checked_add(self.change_value)
            .and_then(|v| v.checked_add(self.fee))
            .ok_or_else(|| BundleError::Malformed("output value sum overflows".into()))?;
        if total_in != total_out {
            return Err(BundleError::Malformed(format!(
                "balance does not close: inputs {total_in}, outputs+fee {total_out}"
            )));
        }
        if self.real_inputs == 1 && self.inputs[1].value != 0 {
            return Err(BundleError::Malformed(
                "dummy input carries non-zero value".into(),
            ));
        }
        for i in 0..usize::from(self.real_inputs) {
            let cm = derive_input(&self.inputs[i]).2;
            if self.witnesses[i].fold_root(&cm) != self.anchor {
                return Err(BundleError::Malformed(format!(
                    "input {i}'s Merkle witness does not fold to the declared anchor"
                )));
            }
        }
        let nf0 = derive_input(&self.inputs[0]).1;
        for (i, output) in self.outputs.iter().enumerate() {
            if output.rho != derive_output_rho(&nf0, i) {
                return Err(BundleError::Malformed(format!(
                    "output {i}'s rho is not derived from input 0's nullifier"
                )));
            }
        }
        let (recipients, payloads) = decode_committed_discovery(&self.discovery)
            .map_err(|e| BundleError::Malformed(format!("discovery bytes do not decode: {e:?}")))?;
        if recipients.len() != 2
            || recipients
                .iter()
                .any(|recipient| recipient.entries.len() != 1)
            || payloads.len() != 2
        {
            return Err(BundleError::Malformed(
                "discovery is not recipient-major 1+1 for the frozen two outputs".into(),
            ));
        }
        for (i, recipient) in recipients.iter().enumerate() {
            let output = &self.outputs[i];
            let note = qlab_note::note::Note {
                value: output.value,
                rkm: output.rkm,
                rho: output.rho,
                rseed: output.rseed,
            };
            if recipient.entries[0].cm != digest_bytes(&note.commitment()) {
                return Err(BundleError::Malformed(format!(
                    "discovery commitment {i} does not bind output {i}"
                )));
            }
        }
        Ok(())
    }
}

/// A named witness-bundle refusal. Every arm happens before the real prove.
#[derive(Debug, PartialEq, Eq)]
pub enum BundleError {
    UnknownVersion(u8),
    ChecksumMismatch,
    PhaseOneVerdictMissing,
    NullifierCoverageMissing {
        covered: Option<(u64, u64)>,
        outputs: Option<(u64, u64)>,
    },
    Malformed(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::UnknownVersion(v) => write!(
                f,
                "witness-bundle-version-unknown: version {v}; this binary knows version {WITNESS_BUNDLE_VERSION} only"
            ),
            BundleError::ChecksumMismatch => write!(
                f,
                "witness-bundle-checksum-mismatch: the serialized handoff is truncated or changed"
            ),
            BundleError::PhaseOneVerdictMissing => write!(
                f,
                "witness-bundle-scan-verdict-unchecked: phase 1 did not establish Complete/Shadowed for every scanned address"
            ),
            BundleError::NullifierCoverageMissing { covered, outputs } => write!(
                f,
                "witness-bundle-nullifier-coverage-missing: phase 1 recorded coverage {covered:?} for scan outputs {outputs:?}"
            ),
            BundleError::Malformed(why) => write!(f, "witness-bundle-malformed: {why}"),
        }
    }
}

impl std::error::Error for BundleError {}

fn checksum(encoded: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(CHECKSUM_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(CHECKSUM_DOMAIN);
    preimage.extend_from_slice(encoded);
    qlab_devnet::hash::keccak256(&preimage)
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_lanes(out: &mut Vec<u8>, lanes: &[u64; 4]) {
    for lane in lanes {
        put_u64(out, *lane);
    }
}

fn put_range(out: &mut Vec<u8>, range: Option<(u64, u64)>) {
    match range {
        Some((from, to)) => {
            out.push(1);
            put_u64(out, from);
            put_u64(out, to);
        }
        None => out.push(0),
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("witness-bundle field exceeds u32::MAX");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_input(out: &mut Vec<u8>, input: &TxInput) {
    put_lanes(out, &input.sk);
    put_u64(out, input.value);
    put_lanes(out, &input.rho);
    put_lanes(out, &input.rseed);
    for lane in input.d {
        put_u64(out, lane);
    }
}

fn put_witness(out: &mut Vec<u8>, witness: &MerkleWitness) {
    for sibling in &witness.siblings {
        put_lanes(out, sibling);
    }
    for bit in witness.path_bits {
        out.push(u8::from(bit));
    }
}

fn put_output(out: &mut Vec<u8>, output: &TxOutput) {
    put_u64(out, output.value);
    put_lanes(out, &output.rkm);
    put_lanes(out, &output.rho);
    put_lanes(out, &output.rseed);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize, name: &str) -> Result<&'a [u8], BundleError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| BundleError::Malformed(format!("{name} length overflows")))?;
        let got = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| BundleError::Malformed(format!("record ends inside {name}")))?;
        self.pos = end;
        Ok(got)
    }

    fn u8(&mut self, name: &str) -> Result<u8, BundleError> {
        Ok(self.take(1, name)?[0])
    }

    fn bool(&mut self, name: &str) -> Result<bool, BundleError> {
        match self.u8(name)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(BundleError::Malformed(format!("{name} boolean is {other}"))),
        }
    }

    fn u64(&mut self, name: &str) -> Result<u64, BundleError> {
        Ok(u64::from_le_bytes(self.take(8, name)?.try_into().unwrap()))
    }

    fn lanes(&mut self, name: &str) -> Result<[u64; 4], BundleError> {
        let mut lanes = [0u64; 4];
        for lane in &mut lanes {
            *lane = self.u64(name)?;
        }
        Ok(lanes)
    }

    fn range(&mut self, name: &str) -> Result<Option<(u64, u64)>, BundleError> {
        match self.u8(name)? {
            0 => Ok(None),
            1 => {
                let from = self.u64(name)?;
                let to = self.u64(name)?;
                if from > to {
                    return Err(BundleError::Malformed(format!(
                        "{name} begins at {from} after it ends at {to}"
                    )));
                }
                Ok(Some((from, to)))
            }
            other => Err(BundleError::Malformed(format!(
                "{name} option tag is {other}"
            ))),
        }
    }

    fn bytes(&mut self, name: &str) -> Result<&'a [u8], BundleError> {
        let len = u32::from_le_bytes(self.take(4, name)?.try_into().unwrap()) as usize;
        self.take(len, name)
    }

    fn input(&mut self, name: &str) -> Result<TxInput, BundleError> {
        Ok(TxInput {
            sk: self.lanes(name)?,
            value: self.u64(name)?,
            rho: self.lanes(name)?,
            rseed: self.lanes(name)?,
            d: [self.u64(name)?, self.u64(name)?],
        })
    }

    fn witness(&mut self, name: &str) -> Result<MerkleWitness, BundleError> {
        let mut siblings = [[0u64; 4]; qlab_air::narrow::MERKLE_DEPTH];
        for sibling in &mut siblings {
            *sibling = self.lanes(name)?;
        }
        let mut path_bits = [false; qlab_air::narrow::MERKLE_DEPTH];
        for bit in &mut path_bits {
            *bit = self.bool(name)?;
        }
        Ok(MerkleWitness {
            siblings,
            path_bits,
        })
    }

    fn output(&mut self, name: &str) -> Result<TxOutput, BundleError> {
        Ok(TxOutput {
            value: self.u64(name)?,
            rkm: self.lanes(name)?,
            rho: self.lanes(name)?,
            rseed: self.lanes(name)?,
        })
    }

    fn finish(self) -> Result<(), BundleError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(BundleError::Malformed(format!(
                "{} trailing payload bytes",
                self.bytes.len() - self.pos
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_air::narrow::derive_input;
    use qlab_cbserver::tree::CommitmentTree;
    use qlab_wallet::seed::MasterSeed;
    use qlab_wallet::Wallet;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn bundle() -> WitnessBundle {
        bundle_with_name_op(None)
    }

    fn bundle_with_name_op(name_op: Option<&qlab_devnet::names::NameOp>) -> WitnessBundle {
        let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([0x31; 32]), 0);
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([0x32; 32]), 0).address_at_index(0);
        let note = crate::send::Spendable {
            div_index: 0,
            value: 1_000_000_000,
            rho: [3; 4],
            rseed: [5; 4],
        };
        let input = wallet.spend_input(
            note.value,
            note.rho,
            note.rseed,
            wallet.diversifier_at_index(0),
        );
        let mut tree = CommitmentTree::new();
        tree.append(derive_input(&input).2);
        crate::send::build_bundle(
            &wallet,
            &[note],
            &recipient,
            4_000_000,
            &tree,
            tree.len(),
            9,
            recipient.short().encode(),
            Some((2, 9)),
            Some((0, 9)),
            name_op,
            &mut StdRng::seed_from_u64(0x351),
        )
        .expect("a valid phase-1 bundle")
    }

    #[test]
    fn witness_bundle_v1_round_trips_byte_for_byte_and_rejects_unknown_versions() {
        let b = bundle();
        let bytes = b.to_bytes();
        let back = WitnessBundle::from_bytes(&bytes).expect("v1 decodes");
        assert_eq!(back.to_bytes(), bytes, "one canonical encoding");
        assert_eq!(back.anchor(), b.anchor());
        assert_eq!(back.real_nullifiers(), b.real_nullifiers());

        let mut future = bytes;
        future[WITNESS_BUNDLE_MAGIC.len()] = 0x7f;
        assert_eq!(
            WitnessBundle::from_bytes(&future)
                .err()
                .expect("future version refuses"),
            BundleError::UnknownVersion(0x7f),
        );
    }

    #[test]
    fn witness_bundle_zeroize_clears_typed_spend_authority() {
        let mut bundle = bundle();
        bundle.zeroize();

        assert!(bundle.inputs.iter().all(|input| {
            input.sk == [0; 4]
                && input.value == 0
                && input.rho == [0; 4]
                && input.rseed == [0; 4]
                && input.d == [0; 2]
        }));
        assert!(bundle.witnesses.iter().all(|witness| {
            witness.siblings == [[0; 4]; qlab_air::narrow::MERKLE_DEPTH]
                && witness.path_bits == [false; qlab_air::narrow::MERKLE_DEPTH]
        }));
        assert!(bundle.outputs.iter().all(|output| {
            output.value == 0
                && output.rkm == [0; 4]
                && output.rho == [0; 4]
                && output.rseed == [0; 4]
        }));
        assert_eq!(bundle.anchor, [0; 4]);
        assert!(bundle.discovery.is_empty());
        assert!(bundle.rider.is_empty());
        assert!(bundle.recipient_short.is_empty());
        assert_eq!(bundle.real_inputs, 0);
        assert_eq!(bundle.amount, 0);
        assert_eq!(bundle.fee, 0);
        assert_eq!(bundle.change_value, 0);
        assert_eq!(bundle.anchor_tip_height, 0);
        assert!(!bundle.allowed_scan_verdicts_only);
        assert_eq!(bundle.output_range, None);
        assert_eq!(bundle.spent_covered, None);
    }

    #[test]
    fn name_service_rider_is_selected_and_round_trips_with_its_fee() {
        use qlab_devnet::names::{encode_rider, name_fee_for, NameOp};

        let op = NameOp::Renew {
            name: b"alice".to_vec(),
        };
        let bundle = bundle_with_name_op(Some(&op));
        let expected_fee = posted_fee(ArityBucket::TwoByTwo) + name_fee_for(&op);
        assert_eq!(bundle.fee, expected_fee);
        assert_eq!(bundle.rider, encode_rider(Some(&op)));
        assert_eq!(
            bundle.outputs[1].value,
            1_000_000_000 - bundle.amount - expected_fee,
            "the rider fee changes phase-1 output construction"
        );

        let encoded = bundle.to_bytes();
        let decoded = WitnessBundle::from_bytes(&encoded).expect("rider-carrying v1 decodes");
        assert_eq!(
            decoded.to_bytes(),
            encoded,
            "rider encoding stays canonical"
        );
        assert_eq!(decoded.rider, encode_rider(Some(&op)));

        let mut mismatched = decoded;
        mismatched.rider = qlab_devnet::names::encode_rider(None);
        let err = WitnessBundle::from_bytes(&mismatched.to_bytes())
            .err()
            .expect("a rider and its selected fee cannot be separated");
        assert!(err.to_string().contains("name-service fee"), "{err}");
    }

    #[test]
    fn serialized_witness_bundle_detects_any_accidental_edit() {
        let mut bytes = bundle().to_bytes();
        bytes[WITNESS_BUNDLE_MAGIC.len() + 7] ^= 1;
        assert_eq!(
            WitnessBundle::from_bytes(&bytes)
                .err()
                .expect("edit refuses"),
            BundleError::ChecksumMismatch
        );
    }

    /// Hazard (c), first half: phase 2 cannot be handed bytes that omit the
    /// Complete/Shadowed receipt. The fields are private, so this test's direct
    /// mutation stands in for a hand-built serialized artifact.
    #[test]
    fn hand_built_bundle_cannot_bypass_the_complete_or_shadowed_gate() {
        let mut hand_built = bundle();
        hand_built.allowed_scan_verdicts_only = false;
        let err = WitnessBundle::from_bytes(&hand_built.to_bytes())
            .err()
            .expect("missing gate refuses");
        assert_eq!(err, BundleError::PhaseOneVerdictMissing);
        assert!(err.to_string().contains("scan-verdict-unchecked"));
    }

    /// Hazard (c), second half: #314's bulk nullifier coverage is part of the
    /// typed handoff, and a hand-built artifact cannot omit it and reach prove.
    #[test]
    fn hand_built_bundle_cannot_bypass_nullifier_coverage() {
        let mut hand_built = bundle();
        hand_built.spent_covered = Some((2, 8));
        let err = WitnessBundle::from_bytes(&hand_built.to_bytes())
            .err()
            .expect("coverage gap refuses");
        assert_eq!(
            err,
            BundleError::NullifierCoverageMissing {
                covered: Some((2, 8)),
                outputs: Some((2, 9)),
            }
        );
        assert!(err.to_string().contains("nullifier-coverage-missing"));
    }

    #[test]
    fn a_hand_built_path_that_does_not_reach_the_anchor_is_refused_before_proof() {
        let mut hand_built = bundle();
        hand_built.witnesses[0].siblings[0][0] ^= 1;
        let err = WitnessBundle::from_bytes(&hand_built.to_bytes())
            .err()
            .expect("bad path refuses");
        assert!(
            err.to_string()
                .contains("does not fold to the declared anchor"),
            "{err}"
        );
    }
}
