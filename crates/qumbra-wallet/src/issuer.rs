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
//!   nothing from the list. `freeze add/remove` prints the new root; putting a
//!   new root on chain needs registry transactions (A2/C4), so until then the
//!   root in force is the one the genesis carries.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use qlab_air::l2p::{freeze_key_of, issuer_key_of, CanonicalFreezeTree, VPublic};
use qlab_l2spend::{build_p_with, Endpoint, Out, PolicyContext};
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_wallet::address::Address;
use rand::rngs::StdRng;

use crate::annulet_send::{exact_fee_note, me, open_session, recipient_of, SendRefusal};
use crate::store::WalletDir;

pub const ISSUER_FILE: &str = "issuer.v1";
const ISSUER_HEADER: &str = "qumbra-wallet issuer v1";
const KEY_LIST_HEADER: &str = "qumbra freeze-list v1";

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

/// The issuer secrets this wallet holds, by asset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerFile {
    pub keys: BTreeMap<u16, [u64; 4]>,
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
        let mut keys = BTreeMap::new();
        for line in lines.filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let (asset, isk) = match parts.as_slice() {
                ["asset", a, "isk", k] => (a.parse::<u16>().ok(), unhex32(k)),
                _ => (None, None),
            };
            match (asset, isk) {
                (Some(a), Some(k)) => {
                    keys.insert(a, digest_from_bytes(&k));
                }
                _ => return Err(format!("{ISSUER_FILE}: unparsable line {line:?}")),
            }
        }
        Ok(Some(Self { keys }))
    }

    /// Record `isk` for `asset`. Refuses to overwrite an existing secret —
    /// key material is never replaced silently.
    pub fn add(dir: &Path, asset: u16, isk: [u64; 4]) -> Result<(), String> {
        let mut file = Self::load(dir)?.unwrap_or_default();
        if file.keys.contains_key(&asset) {
            return Err(format!("{ISSUER_FILE} already holds an issuer secret for asset {asset}; refusing to overwrite it"));
        }
        file.keys.insert(asset, isk);
        let mut text = format!("{ISSUER_HEADER}\n");
        for (a, k) in &file.keys {
            text.push_str(&format!("asset {a} isk {}\n", hex32(&digest_bytes(k))));
        }
        let path = dir.join(ISSUER_FILE);
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        }
        Ok(())
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
    let isk = IssuerFile::load(&w.dir).map_err(SendRefusal::Issuer)?.and_then(|f| f.isk(asset)).ok_or(SendRefusal::NotTheIssuer { asset })?;
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    if issuer_key_of(&isk) != leaf.issuer_key {
        return Err(SendRefusal::NotTheIssuer { asset });
    }
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
    let isk = IssuerFile::load(&w.dir).map_err(SendRefusal::Issuer)?.and_then(|f| f.isk(asset));
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    let redeem_open = leaf.flags & qlab_air::l2p::FLAG_REDEEM_OPEN != 0;
    let isk = match isk {
        Some(k) if issuer_key_of(&k) == leaf.issuer_key => k,
        _ if redeem_open => [0; 4],
        _ => return Err(SendRefusal::NotTheIssuer { asset }),
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
}
