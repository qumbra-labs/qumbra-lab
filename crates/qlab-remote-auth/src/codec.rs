//! Canonical fixed two-slot authorization-section codec for the spike.
//!
//! There are no attacker-controlled lengths. The scheme tag fixes every
//! following field width, unknown schemes are refused, and decode consumes the
//! entire input. This section is not appended to today's transaction wire.

use crate::{
    intent::{AuthDescriptor, Intent, Scheme, INPUT_SLOTS},
    mldsa, wots,
};

pub const MAGIC: &[u8; 4] = b"QRA1";
pub const VERSION: u16 = 1;
const HEADER_BYTES: usize = 4 + 2 + 1 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    MlDsa44 {
        descriptor: AuthDescriptor,
        verifying_key: Vec<u8>,
        signature: Vec<u8>,
    },
    WotsSha2 {
        descriptor: AuthDescriptor,
        signature: Vec<u8>,
    },
}

impl Slot {
    pub fn descriptor(&self) -> AuthDescriptor {
        match self {
            Slot::MlDsa44 { descriptor, .. } | Slot::WotsSha2 { descriptor, .. } => *descriptor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSection {
    pub scheme: Scheme,
    pub slots: [Slot; INPUT_SLOTS],
}

impl AuthSection {
    pub fn new(scheme: Scheme, slots: [Slot; INPUT_SLOTS]) -> Result<Self, String> {
        let section = Self { scheme, slots };
        section.validate_shape()?;
        Ok(section)
    }

    fn validate_shape(&self) -> Result<(), String> {
        for (index, slot) in self.slots.iter().enumerate() {
            if !slot.descriptor().matches_scheme(self.scheme) {
                return Err(format!(
                    "authorization descriptor {index} does not match the section scheme"
                ));
            }
            match (self.scheme, slot) {
                (
                    Scheme::MlDsa44,
                    Slot::MlDsa44 {
                        verifying_key,
                        signature,
                        ..
                    },
                ) if verifying_key.len() == mldsa::VERIFYING_KEY_BYTES
                    && signature.len() == mldsa::SIGNATURE_BYTES => {}
                (
                    Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex,
                    Slot::WotsSha2 { signature, .. },
                ) if signature.len() == wots::SIGNATURE_BYTES => {}
                (
                    Scheme::MlDsa44,
                    Slot::MlDsa44 {
                        verifying_key,
                        signature,
                        ..
                    },
                ) => {
                    return Err(format!(
                        "ML-DSA slot {index} has key/signature lengths {}/{}; expected {}/{}",
                        verifying_key.len(),
                        signature.len(),
                        mldsa::VERIFYING_KEY_BYTES,
                        mldsa::SIGNATURE_BYTES
                    ));
                }
                (
                    Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex,
                    Slot::WotsSha2 { signature, .. },
                ) => {
                    return Err(format!(
                        "WOTS+ slot {index} has signature length {}; expected {}",
                        signature.len(),
                        wots::SIGNATURE_BYTES
                    ));
                }
                _ => return Err(format!("slot {index} does not match the section scheme")),
            }
        }
        Ok(())
    }

    pub fn encoded_len_for(scheme: Scheme) -> usize {
        let payload = match scheme {
            Scheme::MlDsa44 => mldsa::VERIFYING_KEY_BYTES + mldsa::SIGNATURE_BYTES,
            Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex => wots::SIGNATURE_BYTES,
        };
        HEADER_BYTES + INPUT_SLOTS * (AuthDescriptor::encoded_len_for(scheme) + payload)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(Self::encoded_len_for(self.scheme));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.push(self.scheme as u8);
        out.push(INPUT_SLOTS as u8);
        for slot in &self.slots {
            encode_descriptor(&mut out, self.scheme, slot.descriptor());
            match slot {
                Slot::MlDsa44 {
                    verifying_key,
                    signature,
                    ..
                } => {
                    out.extend_from_slice(verifying_key);
                    out.extend_from_slice(signature);
                }
                Slot::WotsSha2 { signature, .. } => out.extend_from_slice(signature),
            }
        }
        assert_eq!(out.len(), Self::encoded_len_for(self.scheme));
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        if r.take(4, "magic")? != MAGIC {
            return Err("authorization section has the wrong magic".into());
        }
        let version = u16::from_le_bytes(r.array("version")?);
        if version != VERSION {
            return Err(format!(
                "authorization section version {version} is not supported"
            ));
        }
        let scheme_byte = r.byte("scheme")?;
        let scheme = Scheme::from_u8(scheme_byte)
            .ok_or_else(|| format!("authorization scheme {scheme_byte} is not supported"))?;
        let slots = r.byte("slot count")? as usize;
        if slots != INPUT_SLOTS {
            return Err(format!(
                "authorization section has {slots} slots; expected {INPUT_SLOTS}"
            ));
        }
        if bytes.len() != Self::encoded_len_for(scheme) {
            return Err(format!(
                "authorization section has {} bytes; scheme {:?} requires exactly {}",
                bytes.len(),
                scheme,
                Self::encoded_len_for(scheme)
            ));
        }

        let mut decoded = Vec::with_capacity(INPUT_SLOTS);
        for _ in 0..INPUT_SLOTS {
            let descriptor = decode_descriptor(&mut r, scheme)?;
            let slot = match scheme {
                Scheme::MlDsa44 => Slot::MlDsa44 {
                    descriptor,
                    verifying_key: r
                        .take(mldsa::VERIFYING_KEY_BYTES, "ML-DSA verifying key")?
                        .to_vec(),
                    signature: r.take(mldsa::SIGNATURE_BYTES, "ML-DSA signature")?.to_vec(),
                },
                Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex => Slot::WotsSha2 {
                    descriptor,
                    signature: r.take(wots::SIGNATURE_BYTES, "WOTS+ signature")?.to_vec(),
                },
            };
            decoded.push(slot);
        }
        r.finish()?;
        let slots: [Slot; INPUT_SLOTS] = decoded
            .try_into()
            .map_err(|_| "authorization section did not contain exactly two slots".to_string())?;
        Self::new(scheme, slots)
    }

    /// Node-side order for the spike: compare the complete signed surface,
    /// then verify both signatures. A future node must do this before STARK
    /// verification.
    pub fn verify_intent(&self, intent: &Intent) -> Result<(), String> {
        self.validate_shape()?;
        intent.validate_shape()?;
        if self.scheme != intent.scheme {
            return Err("authorization section and intent use different schemes".into());
        }
        for (index, slot) in self.slots.iter().enumerate() {
            if slot.descriptor() != intent.auth[index] {
                return Err(format!(
                    "authorization descriptor {index} differs from the signed intent"
                ));
            }
        }
        let digest = intent.digest();
        for (index, slot) in self.slots.iter().enumerate() {
            let valid = match slot {
                Slot::MlDsa44 {
                    descriptor,
                    verifying_key,
                    signature,
                } => mldsa::verify(descriptor, verifying_key, signature, &digest),
                Slot::WotsSha2 {
                    descriptor,
                    signature,
                } => wots::verify(descriptor, signature, &digest),
            };
            if !valid {
                return Err(format!("authorization signature {index} is invalid"));
            }
        }
        Ok(())
    }
}

fn encode_descriptor(out: &mut Vec<u8>, scheme: Scheme, descriptor: AuthDescriptor) {
    match (scheme, descriptor) {
        (Scheme::MlDsa44, AuthDescriptor::MlDsa44 { leaf_index, leaf }) => {
            out.extend_from_slice(&leaf_index.to_le_bytes());
            out.extend_from_slice(&leaf);
        }
        (
            Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex,
            AuthDescriptor::WotsSha2 {
                public_seed,
                leaf_index,
                leaf,
            },
        ) => {
            out.extend_from_slice(&public_seed);
            out.extend_from_slice(&leaf_index.to_le_bytes());
            out.extend_from_slice(&leaf);
        }
        _ => unreachable!("section shape was validated before encoding"),
    }
}

fn decode_descriptor(r: &mut Reader<'_>, scheme: Scheme) -> Result<AuthDescriptor, String> {
    match scheme {
        Scheme::MlDsa44 => Ok(AuthDescriptor::MlDsa44 {
            leaf_index: u32::from_le_bytes(r.array("leaf index")?),
            leaf: r.array("authorization leaf")?,
        }),
        Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex => Ok(AuthDescriptor::WotsSha2 {
            public_seed: r.array("WOTS+ public seed")?,
            leaf_index: u32::from_le_bytes(r.array("leaf index")?),
            leaf: r.array("authorization leaf")?,
        }),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, len: usize, field: &str) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| format!("{field} length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| format!("authorization section is truncated at {field}"))?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self, field: &str) -> Result<[u8; N], String> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| format!("{field} has the wrong width"))
    }

    fn byte(&mut self, field: &str) -> Result<u8, String> {
        Ok(self.take(1, field)?[0])
    }

    fn finish(&self) -> Result<(), String> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(format!(
                "authorization section has {} trailing bytes",
                self.bytes.len() - self.position
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{intent::fixture_intent, mldsa::Key, wots};

    use super::*;

    fn mldsa_fixture() -> (Intent, AuthSection) {
        let keys = [Key::from_seed([1u8; 32]), Key::from_seed([2u8; 32])];
        let descriptors = [keys[0].descriptor(4), keys[1].descriptor(6)];
        let intent = fixture_intent(Scheme::MlDsa44, descriptors);
        let digest = intent.digest();
        let slots = std::array::from_fn(|i| Slot::MlDsa44 {
            descriptor: descriptors[i],
            verifying_key: keys[i].verifying_key_bytes(),
            signature: keys[i].sign(&digest),
        });
        (intent, AuthSection::new(Scheme::MlDsa44, slots).unwrap())
    }

    fn wots_fixture(scheme: Scheme) -> (Intent, AuthSection) {
        let secret_seeds = [[7u8; 32], [8u8; 32]];
        let contexts = [[9u8; 32], [10u8; 32]];
        let indices = [11, 12];
        let descriptors =
            std::array::from_fn(|i| wots::descriptor(&secret_seeds[i], contexts[i], indices[i]));
        let intent = fixture_intent(scheme, descriptors);
        let digest = intent.digest();
        let slots = std::array::from_fn(|i| Slot::WotsSha2 {
            descriptor: descriptors[i],
            signature: wots::sign(&digest, &secret_seeds[i], &contexts[i], indices[i]).encode(),
        });
        (intent, AuthSection::new(scheme, slots).unwrap())
    }

    #[test]
    fn exact_lengths_and_round_trip_are_canonical() {
        assert_eq!(AuthSection::encoded_len_for(Scheme::MlDsa44), 7_544);
        assert_eq!(
            AuthSection::encoded_len_for(Scheme::WotsSha2Stateful),
            4_432
        );
        assert_eq!(
            AuthSection::encoded_len_for(Scheme::WotsSha2RandomIndex),
            4_432
        );
        let (_, section) = mldsa_fixture();
        let bytes = section.encode().unwrap();
        assert_eq!(&bytes[8..12], &4u32.to_le_bytes());
        let decoded = AuthSection::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(AuthSection::decode(&trailing).is_err());
        assert!(AuthSection::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut unknown = bytes;
        unknown[6] = 0xff;
        assert!(AuthSection::decode(&unknown)
            .unwrap_err()
            .contains("not supported"));
    }

    #[test]
    fn a_worker_changed_intent_is_refused_before_any_proof_seam() {
        let (intent, section) = mldsa_fixture();
        section.verify_intent(&intent).unwrap();

        let mut changed = intent.clone();
        changed.commitments[1][0] ^= 1;
        assert!(section
            .verify_intent(&changed)
            .unwrap_err()
            .contains("invalid"));

        let mut changed = intent;
        let AuthDescriptor::MlDsa44 { leaf, .. } = &mut changed.auth[0] else {
            unreachable!()
        };
        leaf[0] ^= 1;
        assert!(section
            .verify_intent(&changed)
            .unwrap_err()
            .contains("descriptor 0"));
    }

    #[test]
    fn both_wots_safety_contracts_round_trip_but_cannot_be_substituted() {
        let (stateful_intent, stateful) = wots_fixture(Scheme::WotsSha2Stateful);
        let (random_intent, random) = wots_fixture(Scheme::WotsSha2RandomIndex);
        stateful.verify_intent(&stateful_intent).unwrap();
        random.verify_intent(&random_intent).unwrap();
        assert_eq!(
            AuthSection::decode(&stateful.encode().unwrap()).unwrap(),
            stateful
        );
        assert_eq!(
            AuthSection::decode(&random.encode().unwrap()).unwrap(),
            random
        );
        assert!(stateful.verify_intent(&random_intent).is_err());
        assert!(random.verify_intent(&stateful_intent).is_err());
    }
}
