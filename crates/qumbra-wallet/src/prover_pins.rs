//! **The remote prover a wallet pays, pinned per network** (lab #937 PR D,
//! ruling D2). A format-34 spend that a remote prover proves pays it inside
//! the transaction — its third output, asset 0, to the prover's payee. The
//! payee and the **most** the wallet will pay per transaction are the
//! wallet's, compiled in per network (keyed by genesis hash), never the
//! service's: the service advertises `{genesis_hash, fee_asset, price:{S,P},
//! payee}` at `/v2/annulet/info`, and [`admit`] refuses, by name, a service
//! whose payee is not the pinned one (compared by the decoded `rkm`, never
//! as a string) or whose price is above the pinned maximum. A swapped or
//! hostile service can neither redirect nor reprice; the advertised price
//! (≤ the maximum) is what is paid, and the review shows it every time.
//!
//! **Production pins** ([`PINS`]): none yet — the format-34 network has no
//! genesis; the cut-over runbook adds its pin and releases the kernel.
//!
//! **Fixture pins** ([`pin_fixture`]): behind the `fixture-pins` feature,
//! which only test builds enable (`qumbra-ffi`'s dev-dependency; resolver 2
//! keeps it out of every normal build, and a wasm32 build asserts it off at
//! compile time).

use crate::annulet_plan::ProverPrice;
use qlab_wallet::address::{Address, ADDRESS_VERSION_CANDIDATE_A};

/// One network's pinned prover: its payee's **full** version-2 address (a
/// short `qs1…` address is a hash and cannot be checked) and the most this
/// wallet pays per transaction, per shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverPin {
    pub payee: String,
    pub max_price: ProverPrice,
}

/// The production pins: `(genesis hash, payee address, max S, max P)`.
/// Empty until the format-34 genesis exists (lab #937 cut-over).
pub const PINS: &[([u8; 32], &str, u64, u64)] = &[];

/// Whether this build carries the fixture-pin registry — `false` in every
/// release build (asserted at compile time on wasm32 by `qumbra-ffi`).
pub const FIXTURE_PINS: bool = cfg!(feature = "fixture-pins");

#[cfg(feature = "fixture-pins")]
static FIXTURES: std::sync::Mutex<Vec<([u8; 32], ProverPin)>> = std::sync::Mutex::new(Vec::new());

/// Test builds only: pin `pin` for the network `genesis` (a fixture chain's
/// genesis hash is computed at test time, so its pin is too).
#[cfg(feature = "fixture-pins")]
pub fn pin_fixture(genesis: [u8; 32], pin: ProverPin) {
    let mut f = FIXTURES.lock().expect("the fixture pins");
    f.retain(|(g, _)| *g != genesis);
    f.push((genesis, pin));
}

/// The pinned prover of the network `genesis`, if any.
pub fn pinned(genesis: &[u8; 32]) -> Option<ProverPin> {
    if let Some((_, payee, s, p)) = PINS.iter().find(|(g, ..)| g == genesis) {
        return Some(ProverPin { payee: (*payee).to_string(), max_price: ProverPrice { s: *s, p: *p } });
    }
    #[cfg(feature = "fixture-pins")]
    if let Some((_, pin)) = FIXTURES.lock().expect("the fixture pins").iter().find(|(g, _)| g == genesis) {
        return Some(pin.clone());
    }
    None
}

/// Why a service is not paid — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProverRefusal {
    /// This build pins no prover for the network.
    NotPinned { genesis: [u8; 32] },
    /// The advertisement is not the expected JSON.
    Malformed(String),
    /// The service serves another network.
    OtherNetwork,
    /// The service asks to be paid in an asset other than 0.
    FeeAsset { asset: u64 },
    /// The service's payee is not this network's pinned payee.
    NotThePinnedPayee,
    /// The service asks more than this wallet pays for a shape.
    OverMax { shape: char, asked: u64, max: u64 },
    /// The pinned payee itself does not decode (a build defect).
    BadPin(String),
}

impl std::fmt::Display for ProverRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProverRefusal::NotPinned { genesis } => write!(
                f,
                "no prover is pinned for this network (genesis {}…): this wallet pays no prover here",
                genesis[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            ProverRefusal::Malformed(why) => write!(f, "the prover's /v2/annulet/info is malformed: {why}"),
            ProverRefusal::OtherNetwork => write!(f, "the prover serves another network (its genesis hash is not this one's)"),
            ProverRefusal::FeeAsset { asset } => {
                write!(f, "the prover asks to be paid in asset {asset}; a prover is paid in asset 0")
            }
            ProverRefusal::NotThePinnedPayee => write!(f, "the prover's payee is not this network's pinned payee"),
            ProverRefusal::OverMax { shape, asked, max } => write!(
                f,
                "the prover asks {asked} fee unit(s) for shape {shape}, above this wallet's maximum of {max}"
            ),
            ProverRefusal::BadPin(why) => write!(f, "this network's pinned payee does not decode: {why}"),
        }
    }
}

impl std::error::Error for ProverRefusal {}

/// A service this wallet will pay: the advertised price (each ≤ the pinned
/// maximum), fixed for every transaction it proves, and the pinned payee.
#[derive(Clone)]
pub struct AdmittedProver {
    pub price: ProverPrice,
    pub payee: Address,
}

/// Check the service's `/v2/annulet/info` advertisement `info` against the
/// pin of the network `genesis`. The JSON's prover fields:
/// `{"genesis_hash": hex, "fee_asset": 0, "price": {"S": n, "P": n}, "payee": "qaddr1…"}`
/// (other fields ignored).
#[cfg(feature = "verify")]
pub fn admit(info: &[u8], genesis: &[u8; 32]) -> Result<AdmittedProver, ProverRefusal> {
    let pin = pinned(genesis).ok_or(ProverRefusal::NotPinned { genesis: *genesis })?;
    let pinned_payee = Address::decode_any(pin.payee.trim()).ok_or_else(|| ProverRefusal::BadPin("not an address".into()))?;
    pinned_payee
        .require_version(ADDRESS_VERSION_CANDIDATE_A)
        .map_err(|e| ProverRefusal::BadPin(e.to_string()))?;
    let v: serde_json::Value = serde_json::from_slice(info).map_err(|e| ProverRefusal::Malformed(e.to_string()))?;
    let field = |k: &str| v.get(k).ok_or_else(|| ProverRefusal::Malformed(format!("no `{k}`")));
    let hash = field("genesis_hash")?.as_str().ok_or_else(|| ProverRefusal::Malformed("`genesis_hash` is not a string".into()))?;
    let want: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
    if !hash.eq_ignore_ascii_case(&want) {
        return Err(ProverRefusal::OtherNetwork);
    }
    let fee_asset = field("fee_asset")?.as_u64().ok_or_else(|| ProverRefusal::Malformed("`fee_asset` is not a number".into()))?;
    if fee_asset != 0 {
        return Err(ProverRefusal::FeeAsset { asset: fee_asset });
    }
    let payee = field("payee")?.as_str().ok_or_else(|| ProverRefusal::Malformed("`payee` is not a string".into()))?;
    let advertised = Address::decode_any(payee.trim()).ok_or(ProverRefusal::NotThePinnedPayee)?;
    if advertised.rkm_lanes() != pinned_payee.rkm_lanes() {
        return Err(ProverRefusal::NotThePinnedPayee);
    }
    let price = field("price")?;
    let of = |k: &str| {
        price
            .get(k)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| ProverRefusal::Malformed(format!("`price.{k}` is not a number")))
    };
    let asked = ProverPrice { s: of("S")?, p: of("P")? };
    for (shape, a, max) in [('S', asked.s, pin.max_price.s), ('P', asked.p, pin.max_price.p)] {
        if a > max {
            return Err(ProverRefusal::OverMax { shape, asked: a, max });
        }
    }
    Ok(AdmittedProver { price: asked, payee: pinned_payee })
}

#[cfg(all(test, feature = "verify", feature = "fixture-pins"))]
mod tests {
    use super::*;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    use qlab_wallet::Wallet;

    fn v2_address(seed: u8) -> Address {
        let w = Wallet::from_master_seed(&MasterSeed::from_entropy([seed; ENTROPY_LEN]), 0);
        w.address_candidate_a_at_index(0, &[1, 2, 3, 4])
    }

    fn info(genesis: &[u8; 32], fee_asset: u64, s: u64, p: u64, payee: &str) -> Vec<u8> {
        let hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
        format!(r#"{{"genesis_hash":"{hex}","fee_asset":{fee_asset},"price":{{"S":{s},"P":{p}}},"payee":"{payee}"}}"#)
            .into_bytes()
    }

    /// Lab #937 PR D (D2): the pinned payee and maximum decide; the
    /// advertised price (≤ the maximum) is what is paid. Every refusal by
    /// name: no pin, another network, a non-zero fee asset, another payee
    /// (by `rkm`), a price over the maximum, malformed JSON.
    #[test]
    fn a_prover_is_admitted_only_on_its_pin() {
        let genesis = [0x9a; 32];
        let payee = v2_address(1).encode();
        pin_fixture(genesis, ProverPin { payee: payee.clone(), max_price: ProverPrice { s: 2, p: 3 } });
        let ok = admit(&info(&genesis, 0, 1, 3, &payee), &genesis).expect("admitted");
        assert_eq!(ok.price, ProverPrice { s: 1, p: 3 }, "the advertised price, not the maximum");
        assert_eq!(ok.payee.rkm_lanes(), v2_address(1).rkm_lanes());
        assert!(matches!(admit(&info(&genesis, 0, 1, 1, &payee), &[0x9b; 32]), Err(ProverRefusal::NotPinned { .. })));
        let mut other = genesis;
        other[0] ^= 1;
        assert_eq!(admit(&info(&other, 0, 1, 1, &payee), &genesis).err(), Some(ProverRefusal::OtherNetwork));
        assert_eq!(admit(&info(&genesis, 7, 1, 1, &payee), &genesis).err(), Some(ProverRefusal::FeeAsset { asset: 7 }));
        let stranger = v2_address(2).encode();
        assert_eq!(admit(&info(&genesis, 0, 1, 1, &stranger), &genesis).err(), Some(ProverRefusal::NotThePinnedPayee));
        assert_eq!(
            admit(&info(&genesis, 0, 3, 1, &payee), &genesis).err(),
            Some(ProverRefusal::OverMax { shape: 'S', asked: 3, max: 2 })
        );
        assert_eq!(
            admit(&info(&genesis, 0, 2, 4, &payee), &genesis).err(),
            Some(ProverRefusal::OverMax { shape: 'P', asked: 4, max: 3 })
        );
        assert!(matches!(admit(b"{", &genesis), Err(ProverRefusal::Malformed(_))));
        assert!(matches!(admit(br#"{"genesis_hash":1}"#, &genesis), Err(ProverRefusal::Malformed(_))));
    }

    #[test]
    fn production_pins_are_empty_until_the_format_34_genesis() {
        assert!(PINS.is_empty());
        const { assert!(FIXTURE_PINS) };
    }
}
