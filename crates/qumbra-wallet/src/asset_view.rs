//! **What a wallet shows for its Annulet assets** (lab #850, AD2): the signed
//! asset list, and the shell-neutral view model every GUI wallet renders.
//!
//! Design: `qumbra-design` `wallet-assets-decision.md` (D1–D4, decided
//! 2026-10-03). The rules this module is written to:
//!
//! - **An asset is `(genesis hash, asset id)`, never a name.** The registry
//!   leaf has no name or decimals lane, so names come from a **signed asset
//!   list** (D1): ML-DSA-65 over [`ASSET_LIST_DOMAIN`] ‖ the list's bytes,
//!   one list per network keyed by genesis hash (D3).
//! - **The list pins the issuer key** (D2). A listed name is shown only while
//!   the chain's leaf carries the listed `issuer_key`; otherwise the row says
//!   [`AssetLabel::IssuerChanged`] and keeps its balance.
//! - **An unlisted asset is still shown**, as [`AssetLabel::Unlisted`] in raw
//!   base units — its decimals are never guessed.
//! - **Every figure comes from a [`VerifiedAnnulet`]** — the view model has no
//!   other input for balances, so an unverified scan cannot reach it (#850
//!   condition (c)). Its spend side is not verified (lab #853), and
//!   [`AssetView::spends_verified`] carries that to the shell, which must
//!   render it.
//! - **Leaves are opened at the verified tip** (the AD2 ruling): an opening is
//!   accepted only if its path folds to the registry root in the verified tip
//!   header, whatever height the node names.
//! - **Exact money**: amounts are integers in base units; the display string
//!   is rendered here, never in floating point, never in a shell.

use std::collections::BTreeMap;

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};
use qlab_air::l2::{RegistryLeaf, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED};
use qlab_air::l2p::CanonicalFreezeTree;
use qlab_devnet::annulet::HeaderExt;
use qlab_node::annulet_genesis::h32;

use crate::annulet_verify::{VerifiedAnnulet, VerifiedChain};
use crate::store::WalletDir;

/// The signature domain: an asset list's signature is over this ‖ its bytes.
pub const ASSET_LIST_DOMAIN: &[u8] = b"qumbra:asset-list:v1\0";

/// The only list version this build reads.
pub const ASSET_LIST_VERSION: u64 = 1;

/// The most decimals a listed asset may declare (u128 base units still
/// render exactly at 38 digits; 18 is the widest real token convention).
pub const MAX_DECIMALS: u32 = 18;

// ---------------------------------------------------------------------------
// The signed asset list
// ---------------------------------------------------------------------------

/// One listed asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedAsset {
    pub id: u16,
    /// The registry leaf's `issuer_key`, as the list pins it (D2).
    pub issuer_key: [u64; 4],
    pub name: String,
    pub ticker: String,
    pub decimals: u32,
    /// Test money — shown as such on every surface.
    pub testnet: bool,
}

/// A verified asset list for one network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetList {
    pub network: String,
    /// The genesis hash this list is for.
    pub genesis: [u8; 32],
    pub assets: BTreeMap<u16, ListedAsset>,
    /// keccak of the list's bytes — what a settings view shows as "which list".
    pub digest: [u8; 32],
    /// keccak of the encoded verifying key that signed it — "signed by whom".
    pub signer: [u8; 32],
}

/// Why an asset list was refused — by name; a refused list is no list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListRefusal {
    /// The signature does not decode, or does not verify under the key.
    BadSignature,
    /// The bytes are not JSON of the list's shape.
    Malformed { why: String },
    /// A version this build does not read.
    UnknownVersion { got: u64 },
}

impl std::fmt::Display for ListRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListRefusal::BadSignature => write!(f, "the asset list's signature does not verify under the list key"),
            ListRefusal::Malformed { why } => write!(f, "the asset list is malformed: {why}"),
            ListRefusal::UnknownVersion { got } => {
                write!(f, "asset list version {got}; this build reads only {ASSET_LIST_VERSION}")
            }
        }
    }
}

impl std::error::Error for ListRefusal {}

/// A list-signing verifying key.
#[derive(Clone, Debug)]
pub struct ListKey {
    vk: VerifyingKey<MlDsa65>,
    fingerprint: [u8; 32],
}

impl ListKey {
    /// From an encoded ML-DSA-65 verifying key (1,952 B) — how a shell
    /// compiles in the production key (D3: Larry's, held offline).
    pub fn from_encoded(bytes: &[u8]) -> Option<Self> {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
        Some(ListKey { vk: VerifyingKey::<MlDsa65>::decode(&enc), fingerprint: qlab_devnet::hash::keccak256(bytes) })
    }

    /// keccak of the encoded key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
}

/// **The TEST list key** (lab #850 condition (e)) — **NOT the production list
/// key**, and not to be compiled into a release shell as a trusted key: its
/// seed is in this source file, so anyone can sign a list with it. It exists
/// so the lane can sign and verify fixture lists; the production key is
/// Larry's offline ML-DSA-65 key (D3) and swapping it in is his step.
pub mod test_list_key {
    use ml_dsa::{Keypair, MlDsa65, Signer, SigningKey, B32};

    /// The fixed seed the lane re-derives the test pair from.
    pub const ASSET_LIST_TEST_SEED: [u8; 32] = *b"qumbra-asset-list-TEST-key-v1\0\0\0";

    /// keccak of the test verifying key's encoding — pinned so a change of
    /// derivation is a red test, not a silent new key. From the named
    /// `ad_goldens` run; the lane recomputes it.
    pub const ASSET_LIST_TEST_KEY_FINGERPRINT: &str = "a926a297aa958568fa8b4441a2f1c306f6b02634ed89d890f65cab4140d01263";

    fn signing() -> SigningKey<MlDsa65> {
        let seed: B32 = ASSET_LIST_TEST_SEED.into();
        SigningKey::<MlDsa65>::from_seed(&seed)
    }

    /// The test verifying key.
    pub fn verifying() -> super::ListKey {
        let enc = signing().verifying_key().encode();
        super::ListKey::from_encoded(enc.as_slice()).expect("a derived key encodes")
    }

    /// Sign `list` with the test key — **tests and fixtures only**; the
    /// signing half is never written to disk.
    pub fn sign(list: &[u8]) -> Vec<u8> {
        let mut msg = super::ASSET_LIST_DOMAIN.to_vec();
        msg.extend_from_slice(list);
        let sig: ml_dsa::Signature<MlDsa65> = signing().sign(&msg);
        sig.encode().as_slice().to_vec()
    }
}

/// Verify `sig` over `bytes` under `key`, then parse the list strictly
/// (unknown keys, duplicate or unordered ids, out-of-range fields refused).
pub fn verify_asset_list(bytes: &[u8], sig: &[u8], key: &ListKey) -> Result<AssetList, ListRefusal> {
    let enc = EncodedSignature::<MlDsa65>::try_from(sig).map_err(|_| ListRefusal::BadSignature)?;
    let sig = Signature::<MlDsa65>::decode(&enc).ok_or(ListRefusal::BadSignature)?;
    let mut msg = ASSET_LIST_DOMAIN.to_vec();
    msg.extend_from_slice(bytes);
    key.vk.verify(&msg, &sig).map_err(|_| ListRefusal::BadSignature)?;
    let mut list = parse_asset_list(bytes)?;
    list.signer = key.fingerprint;
    Ok(list)
}

fn malformed(why: impl Into<String>) -> ListRefusal {
    ListRefusal::Malformed { why: why.into() }
}

fn only_keys(obj: &serde_json::Map<String, serde_json::Value>, allowed: &[&str], what: &str) -> Result<(), ListRefusal> {
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(malformed(format!("unknown key `{k}` in {what}"))),
        None => Ok(()),
    }
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], ListRefusal> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(malformed(format!("{what} must be 64 lowercase hex characters")));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked hex");
    }
    Ok(out)
}

fn lanes(b: &[u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes")))
}

/// Parse a list's bytes (no signature check — [`verify_asset_list`] is the
/// entry point; this is its second half).
fn parse_asset_list(bytes: &[u8]) -> Result<AssetList, ListRefusal> {
    use serde_json::Value;
    let v: Value = serde_json::from_slice(bytes).map_err(|e| malformed(e.to_string()))?;
    let obj = v.as_object().ok_or_else(|| malformed("the list is not an object"))?;
    only_keys(obj, &["v", "network", "genesis", "assets"], "the list")?;
    let version = obj.get("v").and_then(Value::as_u64).ok_or_else(|| malformed("`v` must be an integer"))?;
    if version != ASSET_LIST_VERSION {
        return Err(ListRefusal::UnknownVersion { got: version });
    }
    let network = obj.get("network").and_then(Value::as_str).ok_or_else(|| malformed("`network` must be a string"))?;
    let genesis = hex32(obj.get("genesis").and_then(Value::as_str).ok_or_else(|| malformed("`genesis` missing"))?, "`genesis`")?;
    let entries = obj.get("assets").and_then(Value::as_array).ok_or_else(|| malformed("`assets` must be an array"))?;
    let mut assets = BTreeMap::new();
    let mut last: Option<u16> = None;
    for (i, e) in entries.iter().enumerate() {
        let what = format!("asset entry {i}");
        let o = e.as_object().ok_or_else(|| malformed(format!("{what} is not an object")))?;
        only_keys(o, &["id", "issuer_key", "name", "ticker", "decimals", "testnet"], &what)?;
        let id = o.get("id").and_then(Value::as_u64).ok_or_else(|| malformed(format!("{what}: `id` missing")))?;
        let id = u16::try_from(id).ok().filter(|&id| id != 0).ok_or_else(|| {
            malformed(format!("{what}: `id` {id} is not 1..=65535 (asset 0 is the fee unit, never listed)"))
        })?;
        if last.is_some_and(|l| id <= l) {
            return Err(malformed(format!("{what}: ids must be strictly ascending (got {id})")));
        }
        last = Some(id);
        let issuer_key = lanes(&hex32(
            o.get("issuer_key").and_then(Value::as_str).ok_or_else(|| malformed(format!("{what}: `issuer_key` missing")))?,
            "`issuer_key`",
        )?);
        let name = o.get("name").and_then(Value::as_str).ok_or_else(|| malformed(format!("{what}: `name` missing")))?;
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(malformed(format!("{what}: `name` must be 1..=64 printable characters")));
        }
        let ticker = o.get("ticker").and_then(Value::as_str).ok_or_else(|| malformed(format!("{what}: `ticker` missing")))?;
        if ticker.is_empty() || ticker.len() > 12 || !ticker.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-') {
            return Err(malformed(format!("{what}: `ticker` must be 1..=12 of [A-Za-z0-9.-]")));
        }
        let decimals = o
            .get("decimals")
            .and_then(Value::as_u64)
            .filter(|&d| d <= u64::from(MAX_DECIMALS))
            .ok_or_else(|| malformed(format!("{what}: `decimals` must be 0..={MAX_DECIMALS}")))? as u32;
        let testnet = o.get("testnet").and_then(Value::as_bool).ok_or_else(|| malformed(format!("{what}: `testnet` must be a boolean")))?;
        assets.insert(id, ListedAsset { id, issuer_key, name: name.to_string(), ticker: ticker.to_string(), decimals, testnet });
    }
    Ok(AssetList {
        network: network.to_string(),
        genesis,
        assets,
        digest: qlab_devnet::hash::keccak256(bytes),
        signer: [0; 32],
    })
}

// ---------------------------------------------------------------------------
// Registry leaves at the verified tip
// ---------------------------------------------------------------------------

/// Why a leaf could not be bound to the verified tip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeafRefusal {
    /// The opening could not be read or decoded.
    Unavailable { why: String },
    /// An opening for another asset than asked.
    WrongAsset { got: u64 },
    /// The path does not fold to the root the opening names.
    PathMismatch,
    /// The opening's root is not the verified tip's: the registry moved (or
    /// the node lies). A rescan reads both at one moment.
    NotAtVerifiedTip,
}

/// The leaf of `asset`, opened **at the verified tip**: the opening's path
/// must fold to the registry root in the verified tip header, whatever height
/// the node names (the registry writes at most one leaf a block, so a node
/// ahead of the scan usually still answers at that root).
pub fn leaf_at_verified_tip<F>(fetch: &mut F, chain: &VerifiedChain, asset: u16) -> Result<RegistryLeaf, LeafRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let bytes = fetch(&format!("/v1/registry/{asset}")).map_err(|why| LeafRefusal::Unavailable { why })?;
    let opening = qlab_cbserver::registry::decode_registry_opening(&bytes)
        .map_err(|e| LeafRefusal::Unavailable { why: format!("{e:?}") })?;
    if opening.leaf.asset != u64::from(asset) {
        return Err(LeafRefusal::WrongAsset { got: opening.leaf.asset });
    }
    if opening.witness.fold_root(&opening.leaf.hash()) != opening.root {
        return Err(LeafRefusal::PathMismatch);
    }
    let tip = chain.header(chain.tip()).expect("the tip is verified");
    let HeaderExt::Annulet(ext) = tip.ext else { return Err(LeafRefusal::NotAtVerifiedTip) };
    if h32(&opening.root) != ext.registry_root {
        return Err(LeafRefusal::NotAtVerifiedTip);
    }
    Ok(opening.leaf)
}

// ---------------------------------------------------------------------------
// The view model
// ---------------------------------------------------------------------------

/// Which list labelled this view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListStatus {
    /// A verified list for this network: its digest and its signer's key
    /// fingerprint — what a settings view shows as the trust root.
    Listed { network: String, digest: [u8; 32], signer: [u8; 32] },
    /// No list was given; every asset is unlisted.
    NoList,
    /// The list given is for another genesis: ignored, every asset unlisted.
    OtherNetwork { list_genesis: [u8; 32] },
}

/// How a row is named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetLabel {
    /// Asset 0, the network's fee unit (never listed; whole units).
    FeeUnit,
    /// Listed, and the chain's issuer key is the listed one.
    Listed { name: String, ticker: String },
    /// Listed, but the chain's issuer key is not the listed one (D2): the
    /// name is withheld until a new list ships; the balance stays.
    IssuerChanged { listed_ticker: String },
    /// Listed, but the leaf could not be bound to the verified tip, so the
    /// issuer cannot be confirmed: the name is withheld, the balance stays.
    Unconfirmed { listed_ticker: String },
    /// Not on the list: "asset #N", raw base units.
    Unlisted,
}

/// The asset's mode, from its verified leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetMode {
    Cloaked,
    Hybrid,
    Regulated,
    /// A mode lane this build does not know.
    Other(u64),
    /// The leaf could not be bound to the verified tip.
    Unknown,
}

/// Whether this wallet's notes of the asset are frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreezeStatus {
    /// The leaf's freeze root is the empty tree's: nothing is frozen.
    NoFreezeList,
    /// The leaf carries a freeze root, and no list matching it was given.
    NotChecked,
    /// A freeze list matching the leaf's root names one of this wallet's
    /// addresses that holds the asset.
    Frozen,
    /// A freeze list matching the leaf's root names none of them.
    NotFrozen,
    /// The leaf could not be bound, so its freeze root is unknown.
    Unknown,
}

/// An exact amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Amount {
    /// The integer the chain holds.
    pub base_units: u128,
    /// The rendered figure: grouped integer part, all `decimals` digits
    /// after the point (none for 0 decimals or an unlisted asset).
    pub display: String,
    /// What the figure is in: the ticker, "fee units", or
    /// "base units of asset #N".
    pub unit: String,
}

/// One asset this wallet holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRow {
    pub asset: u16,
    pub label: AssetLabel,
    pub mode: AssetMode,
    pub spendable: Amount,
    pub spendable_notes: usize,
    pub testnet: bool,
    pub freeze: FreezeStatus,
    /// Why the leaf could not be bound, when it could not.
    pub leaf_problem: Option<String>,
}

/// The balances, or why there are none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Balances {
    /// Never a zero: the scan could not read both the outputs and the spends.
    Unavailable { why: String },
    Figures(Vec<AssetRow>),
}

/// **The view model** a GUI wallet renders for one Annulet network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetView {
    pub genesis_hash: [u8; 32],
    /// The highest sealed header verified — "as of" for every figure.
    pub verified_tip: u64,
    /// The endpoint's own word on its tip, for a freshness line.
    pub stated_tip: Option<u64>,
    /// **`false` today (lab #853)**: the spends subtracted are the endpoint's
    /// list, so a figure can be overstated. A shell must say so.
    pub spends_verified: bool,
    pub list: ListStatus,
    pub balances: Balances,
}

fn group_thousands(digits: &str) -> String {
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Render `units` exactly at `decimals` (integers only — no float anywhere).
pub fn render_amount(units: u128, decimals: u32) -> String {
    if decimals == 0 {
        return group_thousands(&units.to_string());
    }
    let scale = 10u128.pow(decimals);
    let (int, frac) = (units / scale, units % scale);
    format!("{}.{:0width$}", group_thousands(&int.to_string()), frac, width = decimals as usize)
}

fn mode_of(leaf: &RegistryLeaf) -> AssetMode {
    match leaf.mode {
        MODE_CLOAKED => AssetMode::Cloaked,
        MODE_HYBRID => AssetMode::Hybrid,
        MODE_REGULATED => AssetMode::Regulated,
        other => AssetMode::Other(other),
    }
}

/// **Build the view** from a verified scan: open each held asset's leaf at the
/// verified tip, label it from `list` (if it is this network's), check
/// `freeze_lists` (keys per asset, used only when their root is the leaf's),
/// and render every amount exactly.
pub fn asset_view<F>(
    w: &WalletDir,
    v: &VerifiedAnnulet,
    list: Option<&AssetList>,
    freeze_lists: &BTreeMap<u16, Vec<[u64; 4]>>,
    fetch: &mut F,
) -> AssetView
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let report = v.report();
    let genesis_hash = report.genesis_hash;
    let (list_status, list) = match list {
        None => (ListStatus::NoList, None),
        Some(l) if l.genesis != genesis_hash => (ListStatus::OtherNetwork { list_genesis: l.genesis }, None),
        Some(l) => (ListStatus::Listed { network: l.network.clone(), digest: l.digest, signer: l.signer }, Some(l)),
    };
    let balances = match &report.index {
        None => Balances::Unavailable {
            why: "the scan could not read both this wallet's outputs and the spends over the range".to_string(),
        },
        Some(index) => {
            let wallet = w.wallet();
            let mut rows = Vec::new();
            for (&asset, notes) in &index.by_asset {
                let units = notes.spendable_value();
                if units == 0 && notes.spendable.is_empty() {
                    continue;
                }
                let leaf = if asset == 0 { None } else { Some(leaf_at_verified_tip(fetch, v.chain(), asset)) };
                let leaf_problem = match &leaf {
                    Some(Err(e)) => Some(format!("{e:?}")),
                    _ => None,
                };
                let bound = leaf.as_ref().and_then(|l| l.as_ref().ok());
                let listed = list.and_then(|l| l.assets.get(&asset));
                let (label, decimals, unit, testnet) = match (asset, listed) {
                    (0, _) => (AssetLabel::FeeUnit, 0, "fee units".to_string(), false),
                    (_, Some(e)) if bound.is_some_and(|leaf| leaf.issuer_key == e.issuer_key) => (
                        AssetLabel::Listed { name: e.name.clone(), ticker: e.ticker.clone() },
                        e.decimals,
                        e.ticker.clone(),
                        e.testnet,
                    ),
                    (_, Some(e)) if bound.is_some() => (
                        AssetLabel::IssuerChanged { listed_ticker: e.ticker.clone() },
                        0,
                        format!("base units of asset #{asset}"),
                        e.testnet,
                    ),
                    (_, Some(e)) => (
                        AssetLabel::Unconfirmed { listed_ticker: e.ticker.clone() },
                        0,
                        format!("base units of asset #{asset}"),
                        e.testnet,
                    ),
                    (_, None) => (AssetLabel::Unlisted, 0, format!("base units of asset #{asset}"), false),
                };
                let mode = match (asset, bound) {
                    (0, _) => AssetMode::Cloaked,
                    (_, Some(leaf)) => mode_of(leaf),
                    (_, None) => AssetMode::Unknown,
                };
                let freeze = match (asset, bound) {
                    (0, _) => FreezeStatus::NoFreezeList,
                    (_, None) => FreezeStatus::Unknown,
                    (_, Some(leaf)) if leaf.freeze_root == CanonicalFreezeTree::empty().root => FreezeStatus::NoFreezeList,
                    (_, Some(leaf)) => match freeze_lists.get(&asset) {
                        Some(keys) => {
                            let tree = CanonicalFreezeTree::from_keys(keys);
                            if tree.root != leaf.freeze_root {
                                FreezeStatus::NotChecked
                            } else if notes
                                .spendable
                                .iter()
                                .any(|n| tree.is_frozen(&wallet.rkm(wallet.diversifier_at_index(n.div_index))))
                            {
                                FreezeStatus::Frozen
                            } else {
                                FreezeStatus::NotFrozen
                            }
                        }
                        None => FreezeStatus::NotChecked,
                    },
                };
                rows.push(AssetRow {
                    asset,
                    label,
                    mode,
                    spendable: Amount { base_units: units, display: render_amount(units, decimals), unit },
                    spendable_notes: notes.spendable.len(),
                    testnet,
                    freeze,
                    leaf_problem,
                });
            }
            Balances::Figures(rows)
        }
    };
    AssetView {
        genesis_hash,
        verified_tip: v.chain().tip(),
        stated_tip: v.stated_tip(),
        spends_verified: v.spends_verified(),
        list: list_status,
        balances,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_render_exactly_with_grouping() {
        assert_eq!(render_amount(0, 6), "0.000000");
        assert_eq!(render_amount(1, 6), "0.000001");
        assert_eq!(render_amount(1_000_400_000_000, 6), "1,000,400.000000");
        assert_eq!(render_amount(999, 0), "999");
        assert_eq!(render_amount(1_000, 0), "1,000");
        assert_eq!(render_amount(u128::MAX, 18), "340,282,366,920,938,463,463.374607431768211455");
    }
}
