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
//! **Production pins** ([`PINS`]): one, **annulet-testnet-3** (the format-34
//! production genesis `024ed17b…`, minted at the lab #937 cut-over), served at
//! `https://annulet-prover.qumbra.org`, at most S 2 / P 4. Format 34 is frozen
//! (docs/annulet-format-34-freeze.md); the pin is the cut-over's, not the freeze's.
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

/// The production pins: `(genesis hash, payee address, max S, max P,
/// auth_derivation)`. Added at the cut-over, not the freeze
/// (docs/annulet-format-34-freeze.md, "Not frozen here"). Lab #971: the last
/// field is the net's authorization derivation (1: the master has no genesis
/// in it; 2: per genesis); annulet-testnet-3 is 1, and every registered
/// generation there keeps its keys.
pub const PINS: &[([u8; 32], &str, u64, u64, u8)] = &[(TESTNET_3_GENESIS, TESTNET_3_PAYEE, 2, 4, 1)];

/// **annulet-testnet-3**'s genesis hash (format 34, lab #937 cut-over M2),
/// `024ed17be2634a59dfb061e123356b9d1798d8e067d7097248915537431c8b70`.
const TESTNET_3_GENESIS: [u8; 32] = [
        0x02, 0x4e, 0xd1, 0x7b, 0xe2, 0x63, 0x4a, 0x59,
        0xdf, 0xb0, 0x61, 0xe1, 0x23, 0x35, 0x6b, 0x9d,
        0x17, 0x98, 0xd8, 0xe0, 0x67, 0xd7, 0x09, 0x72,
        0x48, 0x91, 0x55, 0x37, 0x43, 0x1c, 0x8b, 0x70,
    ];

/// **annulet-testnet-3**'s prover payee: the full version-2 address of the
/// operator's payee wallet (D-C3; its seed never leaves the operator's
/// machine). Paid at most S 2 / P 4 (D-C2).
const TESTNET_3_PAYEE: &str = "qaddr1qfsrps9thfm5ekc9uq8745pd8cgkr7rwc5xln5gjluvtclun9vdfgzwgxc7jdpgehjunxm3rxa9v47qa648fv0ppcjqcw50rflg8kqre5gwneggxqqezxmpfkc9yznhmcwhradd5lgt6x84grmm0qt9ppysqp34hagvh0gf4ewvzhwjmq9kcdcrqgnp3pcfsg86mt29fq90yfqzpydskvtejfkumvqsg0yw4sswprzpzlcj308ffptc5qfagfutxssf234m4d0j5zn89h9g5ed66vq5s2j0rgsjkklmlg9ctqzvlhxrxvyct3vghqetrssys9hywht42gkqe5dk6zes3ny8p0ec0wwcztkucnpv4kxxdugcynr9wcrpygeeut62cjt4a9s40p9pafjn9xcf299x88gkvzxf80zy4ttp8u9umqg72ymsskp96acdlz95443n3t3pg4j9r9ph4j46j3daqpms2thu80xhrsjfgqffjgjssvlfx4z9j0t04xjjspaumlzd8h2hhfzv3wm08h9pp8ytm0ppmm7wtvvqmj9djdsv7tq4780nuuphgtrdtkac2wc9q34m70rumud82gz86jj2s2k738wdqnp2uezcgq40s88z47f3s3ee3h9dczzt34dnw25klmjszljrc0xznesekj370cghz6sd36cy9sqwz2ecznnkqj4pncnynrstjjam87k9fxk6aj3egf08duz5n0wvs9t92twz430zgaxxtc2g75v9sjd8rpspq2gvd6k0d299d3ytsn0kktmuft2zrafy5nge3qmevnta4hmmptqx69qgxl3a3efzgm68z0chhkpfnyy0ut9t8xwcvt4ser0cv8n9d7ugygfnr4vtpqetj9ydydf4vueccs9twgdcqn7p8he6w5ff26edhmy2hnfdk0hgnpj8jy6l60tqxcdm0zrtc98zz3vsaka4ddvq4ewcejduquky2tvwcwzpu7jqtz26wqrmmxt48pql752ymqjehrgycpqffcfr6tc4wc4dttwq72cy54vthpdtn3003frhuz2xuu7uk5gcqxvt6yltscay55zmec2rctcfjnd2s0e0982h4v4lw3acv68x80km2hnp95hpdmj3w7nq4fcx88gfmhy6sptwsc54spsxqjuxpc2chkqzrxkkp2qjetwzxggehhhux39xhjuqhfsew7y4f8pve7lwqvl6r99uehj3wr2a74jp3wsqzfqgksnjswu9canzls29fk2sc4fsjvn5s4yg65s68ruq96dn5k76cxn6ptxzrzwewp8pv9jfnskw2wchv6qff2jtcn5298dzm5r2xs22jd0x3czq2kcs9wce2hha32d4jej8wpg9zhv9gs4gszq4xcf3zhqd8jyrr9jpq7uw4fh0zxj6tua3z5aarq0p3cykvg0v4333juxguhxt05vf6uv93xu6c3tprsvp96q38d5s5wpgf3463gwlhtquqcd4kyk64r2dr50apjypu6xppug9xyxyu6qhreqencqjg0snv0kcsyy4eu49rz3x0y4faewphzq3thsgvnkwpqju4yw2853txpacfrnmyp2g2ca4pvwdk9shz3zuvuc5nyxv4jc8t26q0sexd3del72nsr5rf84gwjrclj2uw5vkqc7j9ympqgrdukcd5yd46xtqzz09m4fmt4gvhr96umjuv69ajrdvj5vwyjsc2vc33w79m32g3w27xwa4zrtk2hw0483fajzwfeknk5pg8x3sjz8hpdph4p5zk4jyn52pqgu4tdpzhye7fm5va56snzrrmxku8s2l9z2z3edqpthm3plm2xmjl9gjhxxa4d26s22cmyezsx0tqgkxtyc0757afaurtmf6y0qju5dfea2y6daky8a3463tnw2gmhr5hky7wxfd3tvzxryx3ak9lhtjs4dh6gd4apavyemf8c9npq727acn";

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
    if let Some((_, payee, s, p, _)) = PINS.iter().find(|(g, ..)| g == genesis) {
        return Some(ProverPin { payee: (*payee).to_string(), max_price: ProverPrice { s: *s, p: *p } });
    }
    #[cfg(feature = "fixture-pins")]
    if let Some((_, pin)) = FIXTURES.lock().expect("the fixture pins").iter().find(|(g, _)| g == genesis) {
        return Some(pin.clone());
    }
    None
}

/// Lab #971: the pinned net's authorization derivation (1 or 2), or `None`
/// for a genesis this build pins nothing for (a shell's own net table
/// decides then).
pub fn pinned_auth_derivation(genesis: &[u8; 32]) -> Option<u8> {
    PINS.iter().find(|(g, ..)| g == genesis).map(|(.., d)| *d)
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

    /// Lab #937 cut-over: the one production pin is annulet-testnet-3's —
    /// its genesis hash, a payee that decodes as a Candidate A (version-2)
    /// address, the maximum S 2 / P 4 — and a service advertising the
    /// deployed price S 1 / P 2 with that payee is admitted at that price,
    /// while S 3 is refused by name. The pin at hand: no network.
    #[test]
    fn the_production_pin_is_annulet_testnet_3s() {
        const { assert!(FIXTURE_PINS) };
        assert_eq!(PINS.len(), 1);
        let (genesis, payee, s, p, d) = PINS[0];
        let hex: String = genesis.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "024ed17be2634a59dfb061e123356b9d1798d8e067d7097248915537431c8b70");
        assert_eq!((s, p), (2, 4), "D-C2: at most S 2 / P 4");
        // Lab #971: annulet-testnet-3 stays on derivation 1.
        assert_eq!(d, 1);
        assert_eq!(pinned_auth_derivation(&genesis), Some(1));
        assert_eq!(pinned_auth_derivation(&[0x9a; 32]), None, "an unpinned net: the shell's table decides");
        let decoded = Address::decode_any(payee).expect("the pinned payee decodes");
        decoded.require_version(ADDRESS_VERSION_CANDIDATE_A).expect("a version-2 address");
        let ok = admit(&info(&genesis, 0, 1, 2, payee), &genesis).expect("the deployed price is admitted");
        assert_eq!(ok.price, ProverPrice { s: 1, p: 2 });
        assert_eq!(ok.payee.rkm_lanes(), decoded.rkm_lanes());
        assert_eq!(
            admit(&info(&genesis, 0, 3, 2, payee), &genesis).err(),
            Some(ProverRefusal::OverMax { shape: 'S', asked: 3, max: 2 })
        );
    }
}
