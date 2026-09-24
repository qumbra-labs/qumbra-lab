//! **`qumbra-wallet issuer …`** (lab #722, L2 C3): an asset issuer's keys,
//! its mint and redeem, and the freeze list it publishes.
//!
//! - **The issuer secret lives in the wallet dir** (`issuer.v1`, 0600, one
//!   line per asset), never in a node. A wallet that never runs `issuer` has
//!   no such file: its dir is byte-identical to before.
//! - **Mint** is a shape-P transaction with `vPublic = +v` on the row of an
//!   issuer-held note of the asset (a mint rides an input row, so the issuer
//!   needs one — the genesis seeds a 0-value note when needed), with the
//!   issuer secret proving `issuer_key = H(isk ‖ D_I)`. **Redeem** is
//!   `vPublic = −v` from an issuer-held note (or a holder's, without `isk`,
//!   when the asset is `redeem_open`). Both pay an exact-tariff fee note.
//! - **The freeze list is public as key hashes** `H(rkm ‖ D_FRZ)`: the issuer
//!   publishes the sorted list, and every wallet rebuilds the canonical tree
//!   and its own non-membership opening from it. Anyone who already knows a
//!   holder's `rkm` can test whether it is frozen; anyone who does not learns
//!   nothing from the list. `freeze add/remove` prints the new root, and with
//!   `--publish` puts it on chain as a registry update (C4a, lab #730).
//! - **Registry writes** (C4a, lab #730; shape R): `register` puts a new
//!   asset's leaf into an empty slot (permissionless; the issuer secret is
//!   generated and written to `issuer.v1` **before** the write is submitted,
//!   so a landed registration is never orphaned), `update` rewrites a leaf the
//!   wallet holds the issuer secret for (policy roots, redeem flag, mode, a key
//!   rotation). Every write pays one asset-0 note of at least the R tariff and
//!   gets change back, plus A3's seed: a 0-value note of the asset, which is
//!   what a first mint rides on. A slot is read before anything is proved: a
//!   taken slot, an empty one, or a key this wallet does not hold is refused
//!   by name, never proved.
//! - **The allow list** (Regulated) is published like the freeze list, as
//!   credential hashes `H(rkm ‖ D_CRED)` (`qumbra allow-list v1`).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use qlab_air::l2::{RegistryLeaf, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED};
use qlab_air::l2p::{cred_of, freeze_key_of, issuer_key_of, CanonicalAllowTree, CanonicalFreezeTree, VPublic, FLAG_REDEEM_OPEN};
use qlab_l2spend::{build_p_with, Endpoint, Out, PolicyContext, SpendError};
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_wallet::address::Address;
use rand::rngs::StdRng;

use crate::annulet_send::{exact_fee_note, me, open_session, recipient_of, SendRefusal, Session};
use crate::store::WalletDir;

pub const ISSUER_FILE: &str = "issuer.v1";
const ISSUER_HEADER: &str = "qumbra-wallet issuer v1";
const KEY_LIST_HEADER: &str = "qumbra freeze-list v1";
const ALLOW_LIST_HEADER: &str = "qumbra allow-list v1";

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A root or key as served bytes, hex.
pub fn lanes_hex(l: &[u64; 4]) -> String {
    hex32(&digest_bytes(l))
}

/// The issuer secrets this wallet holds, by asset. `next` holds a rotation's
/// new secret between its submission and the chain showing it (C4a Q4): the
/// secret in force is whichever of the two matches the served leaf.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerFile {
    pub keys: BTreeMap<u16, [u64; 4]>,
    pub next: BTreeMap<u16, [u64; 4]>,
}

impl IssuerFile {
    /// `Ok(None)` when this wallet holds no issuer secret at all.
    pub fn load(dir: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(dir.join(ISSUER_FILE)) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let mut lines = text.lines();
        if lines.next() != Some(ISSUER_HEADER) {
            return Err(format!("{ISSUER_FILE}: unknown header (this binary reads `{ISSUER_HEADER}` only)"));
        }
        let (mut keys, mut next) = (BTreeMap::new(), BTreeMap::new());
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (asset, kind, isk) = match parts.as_slice() {
                ["asset", a, kind @ ("isk" | "next"), k] => (a.parse::<u16>().ok(), *kind, unhex32(k)),
                _ => (None, "", None),
            };
            match (asset, isk) {
                (Some(a), Some(k)) if kind == "isk" => {
                    keys.insert(a, digest_from_bytes(&k));
                }
                (Some(a), Some(k)) => {
                    next.insert(a, digest_from_bytes(&k));
                }
                _ => return Err(format!("{ISSUER_FILE}: unparsable line {line:?}")),
            }
        }
        Ok(Some(Self { keys, next }))
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        let mut text = format!("{ISSUER_HEADER}\n");
        for (a, k) in &self.keys {
            text.push_str(&format!("asset {a} isk {}\n", hex32(&digest_bytes(k))));
        }
        for (a, k) in &self.next {
            text.push_str(&format!("asset {a} next {}\n", hex32(&digest_bytes(k))));
        }
        let path = dir.join(ISSUER_FILE);
        let tmp = dir.join(format!("{ISSUER_FILE}.tmp"));
        std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
    }

    /// Record a rotation's new secret for `asset` (before the update is
    /// submitted). Refuses while another rotation is pending that the chain
    /// has not shown — key material is never replaced silently.
    pub fn set_next(dir: &Path, asset: u16, isk: [u64; 4]) -> Result<(), String> {
        let mut file = Self::load(dir)?.unwrap_or_default();
        if !file.keys.contains_key(&asset) {
            return Err(format!("{ISSUER_FILE} holds no issuer secret for asset {asset} to rotate"));
        }
        if let Some(pending) = file.next.get(&asset) {
            if *pending != isk {
                return Err(format!(
                    "{ISSUER_FILE} already holds a pending rotation for asset {asset}; it is promoted once the \
                     chain shows it (run an update or a mint), and refusing to overwrite it"
                ));
            }
        }
        file.next.insert(asset, isk);
        file.save(dir)
    }

    /// The secret whose key the chain shows for `asset` — the current one, or
    /// a pending rotation's, which is then **promoted** (written back as the
    /// current secret). `None`: this wallet holds neither.
    pub fn isk_for_key(dir: &Path, asset: u16, issuer_key: &[u64; 4]) -> Result<Option<[u64; 4]>, String> {
        let Some(mut file) = Self::load(dir)? else { return Ok(None) };
        if let Some(k) = file.keys.get(&asset).filter(|k| issuer_key_of(k) == *issuer_key) {
            return Ok(Some(*k));
        }
        match file.next.get(&asset).copied().filter(|k| issuer_key_of(k) == *issuer_key) {
            Some(k) => {
                file.keys.insert(asset, k);
                file.next.remove(&asset);
                file.save(dir)?;
                Ok(Some(k))
            }
            None => Ok(None),
        }
    }

    /// Record `isk` for `asset`. Refuses to overwrite an existing secret —
    /// key material is never replaced silently.
    pub fn add(dir: &Path, asset: u16, isk: [u64; 4]) -> Result<(), String> {
        let mut file = Self::load(dir)?.unwrap_or_default();
        if file.keys.contains_key(&asset) {
            return Err(format!("{ISSUER_FILE} already holds an issuer secret for asset {asset}; refusing to overwrite it"));
        }
        file.keys.insert(asset, isk);
        file.save(dir)
    }

    pub fn isk(&self, asset: u16) -> Option<[u64; 4]> {
        self.keys.get(&asset).copied()
    }
}

/// Parse a published freeze-key list (`qumbra freeze-list v1`, one key hex per line).
pub fn read_key_list(text: &str) -> Result<Vec<[u64; 4]>, String> {
    let mut lines = text.lines();
    if lines.next() != Some(KEY_LIST_HEADER) {
        return Err(format!("a freeze list starts with `{KEY_LIST_HEADER}`"));
    }
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| unhex32(l).map(|b| digest_from_bytes(&b)).ok_or_else(|| format!("unparsable freeze key {l:?}")))
        .collect()
}

/// Write a freeze-key list in the published form (sorted, canonical).
pub fn write_key_list(keys: &[[u64; 4]]) -> String {
    let tree = CanonicalFreezeTree::from_keys(keys);
    let mut out = format!("{KEY_LIST_HEADER}\n");
    for k in &tree.keys {
        out.push_str(&lanes_hex(k));
        out.push('\n');
    }
    out
}

/// `issuer freeze add/remove`: the list with `addr`'s key added (or removed),
/// and the new canonical root. The root is local until a registry transaction
/// publishes it (A2/C4).
pub fn freeze_update(keys: &[[u64; 4]], addr: &Address, add: bool) -> (Vec<[u64; 4]>, [u64; 4]) {
    let k = freeze_key_of(&addr.rkm_lanes());
    let mut next: Vec<[u64; 4]> = keys.iter().copied().filter(|x| *x != k).collect();
    if add {
        next.push(k);
    }
    let tree = CanonicalFreezeTree::from_keys(&next);
    (tree.keys, tree.root)
}

/// Parse a published allow list (`qumbra allow-list v1`, one credential hash
/// hex per line).
pub fn read_allow_list(text: &str) -> Result<Vec<[u64; 4]>, String> {
    let mut lines = text.lines();
    if lines.next() != Some(ALLOW_LIST_HEADER) {
        return Err(format!("an allow list starts with `{ALLOW_LIST_HEADER}`"));
    }
    lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| unhex32(l).map(|b| digest_from_bytes(&b)).ok_or_else(|| format!("unparsable credential {l:?}")))
        .collect()
}

/// Write an allow list in the published form (sorted, canonical).
pub fn write_allow_list(creds: &[[u64; 4]]) -> String {
    let tree = CanonicalAllowTree::from_creds(creds);
    let mut out = format!("{ALLOW_LIST_HEADER}\n");
    for c in &tree.creds {
        out.push_str(&lanes_hex(c));
        out.push('\n');
    }
    out
}

/// `issuer allow add/remove`: the list with `addr`'s credential added (or
/// removed), and the new canonical root.
pub fn allow_update(creds: &[[u64; 4]], addr: &Address, add: bool) -> (Vec<[u64; 4]>, [u64; 4]) {
    let c = cred_of(&addr.rkm_lanes());
    let mut next: Vec<[u64; 4]> = creds.iter().copied().filter(|x| *x != c).collect();
    if add {
        next.push(c);
    }
    let tree = CanonicalAllowTree::from_creds(&next);
    (tree.creds, tree.root)
}

/// A registry leaf's policy, as the issuer asks for it (C4a Q2). `None`
/// keeps what the served leaf has (an update) or takes the mode's default
/// (a registration: an empty canonical freeze tree for Hybrid/Regulated).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafPolicy {
    pub mode: Option<u64>,
    /// The published freeze list (its canonical root becomes `freeze_root`).
    pub freeze_keys: Option<Vec<[u64; 4]>>,
    /// The published allow list (Regulated only).
    pub allow_creds: Option<Vec<[u64; 4]>>,
    pub redeem_open: Option<bool>,
}

/// `cloaked` / `hybrid` / `regulated` → the mode lane.
pub fn parse_mode(s: &str) -> Option<u64> {
    match s {
        "cloaked" => Some(MODE_CLOAKED),
        "hybrid" => Some(MODE_HYBRID),
        "regulated" => Some(MODE_REGULATED),
        _ => None,
    }
}

fn mode_name(m: u64) -> &'static str {
    match m {
        MODE_CLOAKED => "Cloaked",
        MODE_HYBRID => "Hybrid",
        _ => "Regulated",
    }
}

/// The leaf `policy` makes of `base` (the served leaf, or an empty one of
/// `asset` for a registration), with shape R's `mode ⇒ roots` checked here so
/// a leaf the circuit would refuse is never proved.
pub fn leaf_with(base: RegistryLeaf, policy: &LeafPolicy, issuer_key: [u64; 4]) -> Result<RegistryLeaf, SendRefusal> {
    let refuse = |why: String| Err(SendRefusal::LeafRefused(why));
    if base.asset == 0 {
        return refuse("asset 0 (the fee unit) is pinned at genesis and never writable".into());
    }
    let mode = policy.mode.unwrap_or(base.mode);
    let mut leaf = RegistryLeaf { issuer_key, mode, ..base };
    let redeem_open = policy.redeem_open.unwrap_or(base.flags & FLAG_REDEEM_OPEN != 0);
    match mode {
        MODE_CLOAKED => {
            if policy.freeze_keys.is_some() || policy.allow_creds.is_some() {
                return refuse("a Cloaked asset has no freeze or allow list (mode ⇒ roots)".into());
            }
            if policy.redeem_open == Some(true) {
                return refuse("a Cloaked asset carries no flags; redeem-open is a policy-asset flag".into());
            }
            leaf.freeze_root = [0; 4];
            leaf.allow_root = [0; 4];
            leaf.flags = 0;
        }
        MODE_HYBRID | MODE_REGULATED => {
            leaf.freeze_root = match &policy.freeze_keys {
                Some(keys) => CanonicalFreezeTree::from_keys(keys).root,
                None if base.mode == MODE_CLOAKED => CanonicalFreezeTree::empty().root,
                None => base.freeze_root,
            };
            leaf.allow_root = match (mode, &policy.allow_creds) {
                (MODE_HYBRID, Some(_)) => {
                    return refuse("a Hybrid asset has no allow list (mode ⇒ roots); use regulated".into())
                }
                (MODE_HYBRID, None) => [0; 4],
                (_, Some(creds)) => CanonicalAllowTree::from_creds(creds).root,
                (_, None) if base.mode == MODE_REGULATED => base.allow_root,
                (_, None) => {
                    return refuse(format!(
                        "a Regulated asset needs its allow list (--allow-list); the served leaf is {}",
                        mode_name(base.mode)
                    ))
                }
            };
            leaf.flags = if redeem_open { FLAG_REDEEM_OPEN } else { 0 };
        }
        m => return refuse(format!("mode {m} is not cloaked (0), hybrid (1) or regulated (2)")),
    }
    Ok(leaf)
}

/// What a registry write did.
#[derive(Clone, Debug)]
pub struct RegistryReport {
    /// The leaf written.
    pub leaf: RegistryLeaf,
    /// The registry root after it (header bytes).
    pub new_root: [u8; 32],
    /// The fee change, back to this wallet.
    pub change: qlab_note::l2note::L2Note,
    /// A3's seed: a 0-value note of the asset, to this wallet — what a first
    /// mint rides on.
    pub seed: qlab_note::l2note::L2Note,
}

/// The one write path (C4a Q3): the smallest asset-0 note of at least the R
/// tariff pays (the change comes back — no exact-tariff split), the write is
/// proved and submitted, and a race with another write is named.
fn registry_write<E: Endpoint>(
    w: &WalletDir,
    session: &Session<E>,
    leaf: RegistryLeaf,
    isk: [u64; 4],
    rng: &mut StdRng,
) -> Result<RegistryReport, SendRefusal> {
    let tariff = session.tiers.r;
    let fee = session
        .index
        .spendable(0)
        .iter()
        .filter(|n| n.note.value >= tariff)
        .min_by_key(|n| n.note.value)
        .cloned()
        .ok_or(SendRefusal::NoRegistryFeeNote { tariff })?;
    let built = qlab_l2spend::build_r(&session.served, &fee.spend_input(&w.wallet()), &me(w), tariff, leaf, isk, rng)?;
    match session.served.submit(&built.tx) {
        Ok(()) => Ok(RegistryReport { leaf, new_root: built.new_root, change: built.output, seed: built.seed }),
        Err(SpendError::Refused(node)) if is_registry_race(&node) => Err(SendRefusal::RegistryRaced(node)),
        Err(e) => Err(e.into()),
    }
}

/// The node's refusals that mean "another write got there first": a write
/// already pooled, or a surface bound to a root the chain has moved past.
fn is_registry_race(node: &str) -> bool {
    node.contains("registry write is already pooled") || node.contains("L2RegistryRootStale")
}

/// **Register** `asset` (C4a): a leaf of `policy` into an empty slot. The
/// issuer secret is this wallet's for the asset if it already holds one (a
/// retried registration), else a fresh one, written to `issuer.v1` before
/// anything is submitted.
pub fn issuer_register<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    policy: &LeafPolicy,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<RegistryReport, SendRefusal> {
    use rand::Rng as _;
    if policy.mode.is_none() {
        return Err(SendRefusal::LeafRefused("a registration names its mode (cloaked, hybrid or regulated)".into()));
    }
    let empty = RegistryLeaf { asset: u64::from(asset), issuer_key: [0; 4], mode: MODE_CLOAKED, freeze_root: [0; 4], allow_root: [0; 4], flags: 0 };
    leaf_with(empty, policy, [0; 4])?; // refuse a bad policy before touching the network
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    if session.served.registry_slot(u64::from(asset))?.leaf.is_some() {
        return Err(SendRefusal::SlotTaken { asset });
    }
    let held = IssuerFile::load(&w.dir).map_err(SendRefusal::Issuer)?.and_then(|f| f.isk(asset));
    let isk = match held {
        Some(k) => k,
        None => {
            let k = [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];
            IssuerFile::add(&w.dir, asset, k).map_err(SendRefusal::Issuer)?;
            k
        }
    };
    let leaf = leaf_with(empty, policy, issuer_key_of(&isk))?;
    registry_write(w, &session, leaf, isk, rng)
}

/// **Update** `asset`'s leaf (C4a): the policy changes asked for, over the
/// served leaf, proved with the issuer secret in force; `rotate_key` moves
/// the leaf to a fresh secret, recorded as `issuer.v1`'s pending `next`
/// before submission and promoted once the chain shows it.
#[allow(clippy::too_many_arguments)]
pub fn issuer_update<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    policy: &LeafPolicy,
    rotate_key: bool,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<RegistryReport, SendRefusal> {
    use rand::Rng as _;
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let served = session.served.registry_slot(u64::from(asset))?.leaf.ok_or(SendRefusal::SlotEmpty { asset })?;
    let isk = IssuerFile::isk_for_key(&w.dir, asset, &served.issuer_key)
        .map_err(SendRefusal::Issuer)?
        .ok_or(SendRefusal::NotTheIssuer { asset })?;
    // The policy is checked before a rotation's secret is recorded.
    let leaf = leaf_with(served, policy, served.issuer_key)?;
    let leaf = if rotate_key {
        let next = [rng.next_u64(), rng.next_u64(), rng.next_u64(), rng.next_u64()];
        IssuerFile::set_next(&w.dir, asset, next).map_err(SendRefusal::Issuer)?;
        RegistryLeaf { issuer_key: issuer_key_of(&next), ..leaf }
    } else {
        leaf
    };
    if leaf == served {
        return Err(SendRefusal::LeafRefused("the update changes nothing in the served leaf".into()));
    }
    registry_write(w, &session, leaf, isk, rng)
}

/// What an issuance did.
pub struct IssueReport {
    pub outputs: [qlab_note::l2note::L2Note; 2],
    pub split_fee_note: Option<qlab_note::l2note::L2Note>,
}

/// **Mint** `amount` of `asset` to `to`, on the row of an issuer-held note of
/// the asset, with the issuer secret from `issuer.v1`.
#[allow(clippy::too_many_arguments)]
pub fn issuer_mint<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    amount: u64,
    to: &Address,
    freeze_keys: &[[u64; 4]],
    scan_to: u64,
    pin: Option<[u8; 32]>,
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<IssueReport, SendRefusal> {
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    // The secret in force (a pending rotation the chain now shows is promoted).
    let isk = IssuerFile::isk_for_key(&w.dir, asset, &leaf.issuer_key)
        .map_err(SendRefusal::Issuer)?
        .ok_or(SendRefusal::NotTheIssuer { asset })?;
    let base = session.index.spendable(asset).iter().min_by_key(|n| n.note.value).cloned().ok_or(SendRefusal::NoIssuerNote { asset })?;
    let recipient = recipient_of(to).ok_or(SendRefusal::Issuer("the recipient address has no valid ek".into()))?;
    let (fee, split) = exact_fee_note(w, &session, session.tiers.p, split_wait, rng)?;
    let wallet = w.wallet();
    let a = u64::from(asset);
    let outs = [Out { to: recipient, value: amount, asset: a }, Out { to: me(w), value: base.note.value, asset: a }];
    let ctx = PolicyContext { freeze_keys: freeze_keys.to_vec(), isk, ..Default::default() };
    let built = build_p_with(
        &session.served,
        [&base.spend_input(&wallet), &fee.spend_input(&wallet)],
        &outs,
        session.tiers.p,
        [&ctx, &PolicyContext::default()],
        [VPublic::mint(amount), VPublic::NONE],
        rng,
    )?;
    session.served.submit(&built.tx)?;
    Ok(IssueReport { outputs: built.outputs, split_fee_note: split })
}

/// **Redeem** `amount` of `asset` from a note this wallet holds: with the
/// issuer secret (an issuer redeem), or without one when the asset is
/// `redeem_open` (a holder's redeem). The burned amount leaves the
/// outstanding supply.
#[allow(clippy::too_many_arguments)]
pub fn redeem<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    amount: u64,
    freeze_keys: &[[u64; 4]],
    scan_to: u64,
    pin: Option<[u8; 32]>,
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<IssueReport, SendRefusal> {
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    let redeem_open = leaf.flags & FLAG_REDEEM_OPEN != 0;
    let isk = match IssuerFile::isk_for_key(&w.dir, asset, &leaf.issuer_key).map_err(SendRefusal::Issuer)? {
        Some(k) => k,
        None if redeem_open => [0; 4],
        None => return Err(SendRefusal::NotTheIssuer { asset }),
    };
    let note = session
        .index
        .spendable(asset)
        .iter()
        .filter(|n| n.note.value >= amount)
        .min_by_key(|n| n.note.value)
        .cloned()
        .ok_or(SendRefusal::NoSingleNoteCovers { asset, amount, largest: 0 })?;
    let (fee, split) = exact_fee_note(w, &session, session.tiers.p, split_wait, rng)?;
    let wallet = w.wallet();
    let a = u64::from(asset);
    let outs = [Out { to: me(w), value: note.note.value - amount, asset: a }, Out { to: me(w), value: 0, asset: 0 }];
    let ctx = PolicyContext { freeze_keys: freeze_keys.to_vec(), isk, ..Default::default() };
    let built = build_p_with(
        &session.served,
        [&note.spend_input(&wallet), &fee.spend_input(&wallet)],
        &outs,
        session.tiers.p,
        [&ctx, &PolicyContext::default()],
        [VPublic::redeem(amount), VPublic::NONE],
        rng,
    )?;
    session.served.submit(&built.tx)?;
    Ok(IssueReport { outputs: built.outputs, split_fee_note: split })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_issuer_file_round_trips_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("qmb_c3_issuer_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(IssuerFile::load(&dir), Ok(None), "no file: not an issuer");
        IssuerFile::add(&dir, 2, [1, 2, 3, 4]).unwrap();
        IssuerFile::add(&dir, 7, [5, 6, 7, 8]).unwrap();
        let f = IssuerFile::load(&dir).unwrap().unwrap();
        assert_eq!((f.isk(2), f.isk(7), f.isk(9)), (Some([1, 2, 3, 4]), Some([5, 6, 7, 8]), None));
        assert!(IssuerFile::add(&dir, 2, [9; 4]).is_err(), "never overwritten");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(ISSUER_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_freeze_list_round_trips_and_updates_its_canonical_root() {
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        let w = qlab_wallet::Wallet::from_master_seed(&MasterSeed::from_entropy([4u8; ENTROPY_LEN]), 0);
        let (a, b) = (w.address_at_index(0), w.address_at_index(1));
        let (one, root1) = freeze_update(&[], &a, true);
        let (two, root2) = freeze_update(&one, &b, true);
        assert_eq!(read_key_list(&write_key_list(&two)).unwrap(), two);
        assert_eq!(CanonicalFreezeTree::from_keys(&two).root, root2);
        assert!(CanonicalFreezeTree::from_keys(&two).is_frozen(&a.rkm_lanes()));
        let (back, root_back) = freeze_update(&two, &b, false);
        assert_eq!((back, root_back), (one, root1), "remove undoes add");
        assert!(read_key_list("not a list").is_err());
    }

    /// C4a Q4: a rotation's secret is pending as `next` until the chain shows
    /// it, then promoted; a second pending rotation is refused; an old binary's
    /// parser would refuse the `next` line by name (the header is unchanged).
    #[test]
    fn a_rotation_is_pending_until_the_chain_shows_it() {
        let dir = std::env::temp_dir().join(format!("qmb_c4a_issuer_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (old, new) = ([1u64, 2, 3, 4], [5u64, 6, 7, 8]);
        assert!(IssuerFile::set_next(&dir, 2, new).is_err(), "nothing to rotate");
        IssuerFile::add(&dir, 2, old).unwrap();
        IssuerFile::set_next(&dir, 2, new).unwrap();
        IssuerFile::set_next(&dir, 2, new).unwrap(); // the same pending secret: idempotent
        assert!(IssuerFile::set_next(&dir, 2, [9; 4]).is_err(), "a second pending rotation is refused");
        let text = std::fs::read_to_string(dir.join(ISSUER_FILE)).unwrap();
        assert!(text.contains("asset 2 isk ") && text.contains("asset 2 next "), "{text}");
        // The chain still shows the old key: the old secret, nothing promoted.
        assert_eq!(IssuerFile::isk_for_key(&dir, 2, &issuer_key_of(&old)), Ok(Some(old)));
        assert_eq!(IssuerFile::load(&dir).unwrap().unwrap().next.get(&2), Some(&new));
        // A key this wallet never held.
        assert_eq!(IssuerFile::isk_for_key(&dir, 2, &issuer_key_of(&[7; 4])), Ok(None));
        // The chain shows the new key: promoted.
        assert_eq!(IssuerFile::isk_for_key(&dir, 2, &issuer_key_of(&new)), Ok(Some(new)));
        let f = IssuerFile::load(&dir).unwrap().unwrap();
        assert_eq!((f.isk(2), f.next.get(&2)), (Some(new), None));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(ISSUER_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_allow_list_round_trips_and_updates_its_canonical_root() {
        use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
        let w = qlab_wallet::Wallet::from_master_seed(&MasterSeed::from_entropy([5u8; ENTROPY_LEN]), 0);
        let (a, b) = (w.address_at_index(0), w.address_at_index(1));
        let (one, root1) = allow_update(&[], &a, true);
        let (two, root2) = allow_update(&one, &b, true);
        assert_eq!(read_allow_list(&write_allow_list(&two)).unwrap(), two);
        assert_eq!(CanonicalAllowTree::from_creds(&two).root, root2);
        assert!(CanonicalAllowTree::from_creds(&two).witness_for(&cred_of(&a.rkm_lanes())).is_some());
        assert_eq!(allow_update(&two, &b, false), (one, root1), "remove undoes add");
        assert!(read_allow_list(&write_key_list(&two)).is_err(), "a freeze list is not an allow list");
    }

    /// C4a Q2/Q7: `mode ⇒ roots` is enforced before proving, each leg by
    /// name; a mode change rewrites the roots the new mode implies.
    #[test]
    fn leaf_policy_keeps_mode_implies_roots() {
        let key = [3u64; 4];
        let blank = |asset: u64| RegistryLeaf { asset, issuer_key: [0; 4], mode: MODE_CLOAKED, freeze_root: [0; 4], allow_root: [0; 4], flags: 0 };
        let p = |mode: u64| LeafPolicy { mode: Some(mode), ..Default::default() };
        let refused = |r: Result<RegistryLeaf, SendRefusal>| matches!(r, Err(SendRefusal::LeafRefused(_)));
        // Registrations.
        let c = leaf_with(blank(11), &p(MODE_CLOAKED), key).unwrap();
        assert_eq!((c.freeze_root, c.allow_root, c.flags, c.issuer_key), ([0; 4], [0; 4], 0, key));
        let h = leaf_with(blank(12), &p(MODE_HYBRID), key).unwrap();
        assert_eq!((h.freeze_root, h.allow_root), (CanonicalFreezeTree::empty().root, [0; 4]), "an empty canonical freeze tree");
        assert!(refused(leaf_with(blank(13), &p(MODE_REGULATED), key)), "Regulated needs its allow list");
        let creds = vec![[1u64, 2, 3, 4]];
        let r = leaf_with(blank(13), &LeafPolicy { allow_creds: Some(creds.clone()), ..p(MODE_REGULATED) }, key).unwrap();
        assert_eq!(r.allow_root, CanonicalAllowTree::from_creds(&creds).root);
        assert!(refused(leaf_with(blank(0), &p(MODE_HYBRID), key)), "asset 0");
        assert!(refused(leaf_with(blank(11), &LeafPolicy { freeze_keys: Some(vec![]), ..p(MODE_CLOAKED) }, key)));
        assert!(refused(leaf_with(blank(11), &LeafPolicy { redeem_open: Some(true), ..p(MODE_CLOAKED) }, key)));
        assert!(refused(leaf_with(blank(12), &LeafPolicy { allow_creds: Some(creds.clone()), ..p(MODE_HYBRID) }, key)));
        assert!(refused(leaf_with(blank(12), &p(3), key)), "mode 3");
        // Updates: Hybrid → Regulated keeps the freeze root, adds the allow root.
        let frozen = LeafPolicy { freeze_keys: Some(vec![[9u64; 4]]), redeem_open: Some(true), ..Default::default() };
        let h2 = leaf_with(h, &frozen, key).unwrap();
        assert_eq!((h2.freeze_root, h2.flags), (CanonicalFreezeTree::from_keys(&[[9u64; 4]]).root, FLAG_REDEEM_OPEN));
        let r2 = leaf_with(h2, &LeafPolicy { allow_creds: Some(creds.clone()), ..p(MODE_REGULATED) }, key).unwrap();
        assert_eq!((r2.freeze_root, r2.allow_root, r2.flags), (h2.freeze_root, r.allow_root, FLAG_REDEEM_OPEN));
        // … and back to Cloaked drops every root and flag.
        let c2 = leaf_with(r2, &p(MODE_CLOAKED), key).unwrap();
        assert_eq!((c2.freeze_root, c2.allow_root, c2.flags, c2.asset), ([0; 4], [0; 4], 0, 12));
    }
}
