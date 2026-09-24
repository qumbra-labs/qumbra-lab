//! **`send --net annulet`** (lab #720, L2 C2): a two-asset bundle from the
//! wallet's own notes, with the fee-note discipline.
//!
//! The rules, each refused by name when it cannot be met:
//!
//! - **The fee is an exact-tariff asset-0 note.** A 2×2 bucket pays its fee in
//!   asset 0 and has no fee-change slot, so the fee input is spent whole and
//!   must equal the shape's tariff (`/v1/annulet/params`).
//! - **Fee-split first when there is none.** A single-asset shape-S spend of a
//!   larger asset-0 note into one exact-tariff note plus change, paying its own
//!   S fee from the same input. One fee note per split: the bucket has two
//!   outputs.
//! - **One covering note per asset.** A transfer of asset A ≠ 0 takes one A
//!   input and the fee note, so the most it can move is its largest single A
//!   note. Two A notes cannot be merged at all: both inputs would be A, and
//!   nothing would pay the asset-0 fee. This is a recorded design-level limit
//!   (lab #720 P4), not a wallet choice.
//! - **The shape is the asset's.** S for Cloaked (and asset 0), P for Hybrid,
//!   vPublic = 0. What the wallet cannot open itself (a non-empty freeze tree,
//!   a Regulated allowlist) is refused by name; its owner is C3.
//!
//! **Nothing is written to the wallet dir.** The commitment tree is rebuilt in
//! memory; no L1 file (`tree-leaves.v1`, `sends.v1`) is read or written on an
//! Annulet net.

use std::time::{Duration, Instant};

use qlab_devnet::annulet::L2ShapeTag;
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_air::l2p::VPublic;
use qlab_l2spend::{build_p_with, build_s, shape_for, Endpoint, Out, Recipient, Served, SpendError};
use qlab_wallet::address::Address;
use rand::rngs::StdRng;

use crate::annulet::{scan_annulet, AnnuletRefusal};
use crate::store::WalletDir;

/// The fee tiers a send pays, from the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tiers {
    pub s: u64,
    pub p: u64,
}

impl Tiers {
    pub fn of(&self, shape: L2ShapeTag) -> u64 {
        match shape {
            L2ShapeTag::S => self.s,
            L2ShapeTag::P => self.p,
        }
    }
}

/// Why a send cannot be planned or made — by name.
#[derive(Debug, PartialEq, Eq)]
pub enum SendRefusal {
    /// No single spendable note of `asset` covers the amount (plus the fee,
    /// for asset 0). Notes cannot be merged in 2×2 (lab #720 P4).
    NoSingleNoteCovers { asset: u16, amount: u64, largest: u64 },
    /// No exact-tariff asset-0 note, and none large enough to split one off.
    NoFeeSource { tariff: u64, split_needs: u64 },
    /// The wallet has no quotable balance (the scan or the spends were not
    /// both known — lab #314).
    NoBalance,
    /// The endpoint is not the pinned Annulet chain, or not Annulet at all.
    Form(AnnuletRefusal),
    /// The endpoint's params are for a different genesis than it serves.
    ParamsGenesisMismatch,
    /// The assembly or the node said no.
    Spend(SpendError),
    /// A fee-split was admitted but its note did not appear in the tree.
    SplitNotIncluded { waited_secs: u64 },
    /// This wallet holds no issuer secret for `asset` whose key is the
    /// registry's `issuer_key` (lab #722).
    NotTheIssuer { asset: u16 },
    /// A mint rides an issuer-held note of the asset, and there is none
    /// (lab #722 P3).
    NoIssuerNote { asset: u16 },
    /// The issuer file could not be read.
    Issuer(String),
}

impl std::fmt::Display for SendRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendRefusal::NoSingleNoteCovers { asset, amount, largest } => write!(
                f,
                "no single spendable note of asset {asset} covers {amount} (the largest is {largest}). \
                 An L2 2×2 transaction takes one note of the asset plus one asset-0 fee note, and two \
                 notes of a non-fee asset cannot be merged (both inputs would be that asset and nothing \
                 would pay the fee) — a recorded design limit, lab #720 P4. Send at most {largest}"
            ),
            SendRefusal::NoFeeSource { tariff, split_needs } => write!(
                f,
                "no asset-0 note of exactly {tariff} (the fee is paid whole: there is no fee change in \
                 2×2), and no asset-0 note of at least {split_needs} to split one off"
            ),
            SendRefusal::NoBalance => write!(
                f,
                "no quotable balance: the scan did not establish both the outputs and the spends"
            ),
            SendRefusal::Form(e) => write!(f, "{e}"),
            SendRefusal::ParamsGenesisMismatch => {
                write!(f, "the endpoint's /v1/annulet/params name a different genesis than it serves")
            }
            SendRefusal::Spend(e) => write!(f, "{e}"),
            SendRefusal::NotTheIssuer { asset } => write!(
                f,
                "this wallet holds no issuer secret for asset {asset} matching the registry's issuer key"
            ),
            SendRefusal::NoIssuerNote { asset } => write!(
                f,
                "a mint rides an issuer-held note of asset {asset} and this wallet holds none (lab #722 P3: \
                 the genesis seeds one; an issuer that spends its last one cannot mint again)"
            ),
            SendRefusal::Issuer(e) => write!(f, "issuer file: {e}"),
            SendRefusal::SplitNotIncluded { waited_secs } => write!(
                f,
                "the fee-split was admitted but its note was not in the served tree after {waited_secs} s; \
                 run the send again once it is"
            ),
        }
    }
}

impl std::error::Error for SendRefusal {}

impl From<SpendError> for SendRefusal {
    fn from(e: SpendError) -> Self {
        SendRefusal::Spend(e)
    }
}

/// What a send will spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Asset 0: one note, its own fee, a dummy second input (shape S).
    FeeAsset { note: OwnedL2Note },
    /// Asset A ≠ 0: one covering A note plus an exact-tariff fee note.
    WithFeeNote { note: OwnedL2Note, fee: OwnedL2Note, shape: L2ShapeTag },
    /// No exact-tariff fee note: split one off `source` first (shape S), then
    /// send `note` with it.
    SplitFirst { note: OwnedL2Note, source: OwnedL2Note, shape: L2ShapeTag },
}

fn largest(notes: &[OwnedL2Note]) -> u64 {
    notes.iter().map(|n| n.note.value).max().unwrap_or(0)
}

/// **Selection** — pure, over a per-asset index. The smallest covering note
/// is chosen (least change); the fee note is exactly the tariff.
pub fn plan_send(index: &AssetIndex, asset: u16, amount: u64, shape: L2ShapeTag, tiers: Tiers) -> Result<Plan, SendRefusal> {
    let smallest_covering = |a: u16, need: u64, not: Option<&OwnedL2Note>| {
        index
            .spendable(a)
            .iter()
            .filter(|n| n.note.value >= need && Some(*n) != not)
            .min_by_key(|n| n.note.value)
            .cloned()
    };
    if asset == 0 {
        // The fee comes out of the same note: one input, shape S.
        let need = amount.saturating_add(tiers.s);
        return smallest_covering(0, need, None)
            .map(|note| Plan::FeeAsset { note })
            .ok_or(SendRefusal::NoSingleNoteCovers { asset, amount: need, largest: largest(index.spendable(0)) });
    }
    let note = smallest_covering(asset, amount, None).ok_or(SendRefusal::NoSingleNoteCovers {
        asset,
        amount,
        largest: largest(index.spendable(asset)),
    })?;
    let tariff = tiers.of(shape);
    if let Some(fee) = index.spendable(0).iter().find(|n| n.note.value == tariff) {
        return Ok(Plan::WithFeeNote { note, fee: fee.clone(), shape });
    }
    let split_needs = tariff + tiers.s;
    match smallest_covering(0, split_needs, None) {
        Some(source) => Ok(Plan::SplitFirst { note, source, shape }),
        None => Err(SendRefusal::NoFeeSource { tariff, split_needs }),
    }
}

/// The recipient an [`Address`] names.
pub fn recipient_of(addr: &Address) -> Option<Recipient> {
    Some(Recipient { rkm: addr.rkm_lanes(), ek: addr.encapsulation_key()? })
}

/// What a send did.
pub struct SendReport {
    pub plan: Plan,
    /// The fee-split's nullifiers-free summary: the exact-tariff note it made.
    pub split_fee_note: Option<qlab_note::l2note::L2Note>,
    /// The notes the send created: `[to the recipient, change to this wallet]`.
    pub outputs: [qlab_note::l2note::L2Note; 2],
    pub shape: L2ShapeTag,
}

fn wait_in_tree<E: Endpoint>(served: &Served<E>, cm: &[u64; 4], timeout: Duration) -> Result<(), SendRefusal> {
    let start = Instant::now();
    loop {
        if served.commitment_tree()?.position_of(cm).is_some() {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(SendRefusal::SplitNotIncluded { waited_secs: timeout.as_secs() });
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// What every Annulet spend starts from: the verified endpoint, its tariff,
/// and this wallet's per-asset index (lab #720/#722).
pub struct Session<E: Endpoint> {
    pub served: Served<E>,
    pub tiers: Tiers,
    pub index: AssetIndex,
    pub genesis_hash: [u8; 32],
}

/// Verify the form (and pin), read the tariff (checked against the served
/// genesis), and scan to `scan_to`.
pub fn open_session<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<Session<E>, SendRefusal> {
    let served = Served::new(endpoint);
    let mut fetch = |p: &str| served.endpoint.get(p);
    let report = scan_annulet(w, &mut fetch, 0, scan_to, pin, rng).map_err(SendRefusal::Form)?;
    let params = served.params()?;
    if params.genesis_hash != report.genesis_hash {
        return Err(SendRefusal::ParamsGenesisMismatch);
    }
    let tiers = Tiers { s: params.fee_tier_s, p: params.fee_tier_p };
    let index = report.index.ok_or(SendRefusal::NoBalance)?;
    Ok(Session { served, tiers, index, genesis_hash: report.genesis_hash })
}

/// This wallet's receiving [`Recipient`] (address 0: change, split notes).
pub fn me(w: &WalletDir) -> Recipient {
    recipient_of(&w.wallet().address_at_index(0)).expect("the wallet's own address has an ek")
}

/// **An exact-`tariff` asset-0 fee note**: one the wallet holds, or one
/// split off a larger asset-0 note first (shape S, its own S fee from the same
/// input), waited for until it is in the served tree. Returns the fee note and,
/// when a split was made, the note it minted.
pub fn exact_fee_note<E: Endpoint>(
    w: &WalletDir,
    session: &Session<E>,
    tariff: u64,
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<(OwnedL2Note, Option<qlab_note::l2note::L2Note>), SendRefusal> {
    if let Some(fee) = session.index.spendable(0).iter().find(|n| n.note.value == tariff) {
        return Ok((fee.clone(), None));
    }
    let split_needs = tariff + session.tiers.s;
    let source = session
        .index
        .spendable(0)
        .iter()
        .filter(|n| n.note.value >= split_needs)
        .min_by_key(|n| n.note.value)
        .ok_or(SendRefusal::NoFeeSource { tariff, split_needs })?;
    let wallet = w.wallet();
    let split = build_s(
        &session.served,
        &[&source.spend_input(&wallet)],
        &[
            Out { to: me(w), value: tariff, asset: 0 },
            Out { to: me(w), value: source.note.value - tariff - session.tiers.s, asset: 0 },
        ],
        session.tiers.s,
        rng,
    )?;
    session.served.submit(&split.tx)?;
    let made = split.outputs[0];
    wait_in_tree(&session.served, &made.commitment(), split_wait)?;
    let owned = OwnedL2Note::from_genesis(&wallet, 0, qlab_note::hash::digest_bytes(&made.commitment()), made)
        .expect("the split paid this wallet's address 0");
    Ok((owned, Some(made)))
}

/// **The send**: verify the form (and pin), read the tariff, scan, plan,
/// fee-split if needed, then prove and submit the transfer. `scan_to` bounds
/// the scan (a balance is a claim about a range). `freeze_keys` is the
/// asset issuer's published freeze list (lab #722; empty for an asset with an
/// empty freeze tree): an address on it is refused before anything is proved.
#[allow(clippy::too_many_arguments)]
pub fn send_annulet<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    asset: u16,
    amount: u64,
    to: &Address,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    freeze_keys: &[[u64; 4]],
    split_wait: Duration,
    rng: &mut StdRng,
) -> Result<SendReport, SendRefusal> {
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    let leaf = session.served.registry(u64::from(asset))?.leaf;
    let shape = shape_for(&leaf);
    let wallet = w.wallet();
    if shape == L2ShapeTag::P
        && qlab_air::l2p::CanonicalFreezeTree::from_keys(freeze_keys).is_frozen(&wallet.rkm(wallet.diversifier_at_index(0)))
    {
        return Err(SendRefusal::Spend(SpendError::Frozen { asset: u64::from(asset) }));
    }
    let tiers = session.tiers;
    let plan = plan_send(&session.index, asset, amount, shape, tiers)?;
    let recipient = recipient_of(to).ok_or(SendRefusal::Spend(SpendError::Served("the recipient address has no valid ek".into())))?;
    let a = u64::from(asset);
    let served = &session.served;

    let (split_fee_note, built) = match &plan {
        Plan::FeeAsset { note } => {
            let input = note.spend_input(&wallet);
            let outs = [
                Out { to: recipient, value: amount, asset: 0 },
                Out { to: me(w), value: note.note.value - amount - tiers.s, asset: 0 },
            ];
            (None, build_s(served, &[&input], &outs, tiers.s, rng)?)
        }
        Plan::WithFeeNote { note, shape, .. } | Plan::SplitFirst { note, shape, .. } => {
            let tariff = tiers.of(*shape);
            let (fee_note, split_note) = exact_fee_note(w, &session, tariff, split_wait, rng)?;
            let inputs = [note.spend_input(&wallet), fee_note.spend_input(&wallet)];
            let outs = [
                Out { to: recipient, value: amount, asset: a },
                Out { to: me(w), value: note.note.value - amount, asset: a },
            ];
            let built = match shape {
                L2ShapeTag::S => build_s(served, &[&inputs[0], &inputs[1]], &outs, tariff, rng)?,
                L2ShapeTag::P => {
                    let ctx = qlab_l2spend::PolicyContext { freeze_keys: freeze_keys.to_vec(), ..Default::default() };
                    build_p_with(served, [&inputs[0], &inputs[1]], &outs, tariff, [&ctx, &Default::default()], [VPublic::NONE; 2], rng)?
                }
            };
            (split_note, built)
        }
    };
    served.submit(&built.tx)?;
    Ok(SendReport { plan, split_fee_note, outputs: built.outputs, shape: built.shape })
}

/// The wallet's own transport as an [`Endpoint`]: `http://host:PORT` or
/// `https://host[:port]`, the same TLS path every other command uses.
#[cfg(feature = "net")]
pub struct WalletEndpoint {
    pub url: String,
}

#[cfg(feature = "net")]
impl Endpoint for WalletEndpoint {
    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        crate::net::http_get(&self.url, path).map_err(|e| e.to_string())
    }
    fn post(&self, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        crate::net::http_post_bytes(&self.url, path, body).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_ledger::spent::SpentSet;
    use qlab_note::l2note::L2Note;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};
    use qlab_wallet::Wallet;

    const TIERS: Tiers = Tiers { s: 1, p: 2 };

    fn wallet() -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([3u8; ENTROPY_LEN]), 0)
    }

    fn index(notes: &[(u64, u64)]) -> AssetIndex {
        let w = wallet();
        let owned = notes
            .iter()
            .enumerate()
            .map(|(k, &(asset, value))| {
                let note = L2Note { value, asset, rkm: w.rkm(w.diversifier_at_index(0)), rho: [k as u64 + 1; 4], rseed: [9; 4] };
                OwnedL2Note::from_genesis(&w, 0, [k as u8; 32], note).unwrap()
            })
            .collect();
        AssetIndex::build(&w, owned, &SpentSet::from_parts(Some((0, 1)), []))
    }

    #[test]
    fn an_asset_zero_send_pays_its_fee_from_the_same_note() {
        let ix = index(&[(0, 5), (0, 20), (0, 8)]);
        assert!(matches!(plan_send(&ix, 0, 7, L2ShapeTag::S, TIERS), Ok(Plan::FeeAsset { note }) if note.note.value == 8));
        assert_eq!(
            plan_send(&ix, 0, 20, L2ShapeTag::S, TIERS),
            Err(SendRefusal::NoSingleNoteCovers { asset: 0, amount: 21, largest: 20 })
        );
    }

    #[test]
    fn a_policy_asset_takes_one_covering_note_and_an_exact_tariff_fee_note() {
        let ix = index(&[(1, 400), (1, 600), (0, 2), (0, 7)]);
        match plan_send(&ix, 1, 500, L2ShapeTag::P, TIERS).unwrap() {
            Plan::WithFeeNote { note, fee, shape } => {
                assert_eq!((note.note.value, fee.note.value, shape), (600, 2, L2ShapeTag::P));
            }
            other => panic!("{other:?}"),
        }
    }

    /// No cross-asset balancing, and no merge: two 400s do not cover 700.
    #[test]
    fn two_notes_of_a_non_fee_asset_never_combine() {
        let ix = index(&[(1, 400), (1, 400), (0, 2)]);
        assert_eq!(
            plan_send(&ix, 1, 700, L2ShapeTag::P, TIERS),
            Err(SendRefusal::NoSingleNoteCovers { asset: 1, amount: 700, largest: 400 })
        );
        let text = SendRefusal::NoSingleNoteCovers { asset: 1, amount: 700, largest: 400 }.to_string();
        assert!(text.contains("cannot be merged") && text.contains("lab #720 P4"), "{text}");
        // An asset-0 surplus never pays for asset 1.
        let ix = index(&[(1, 400), (0, 1_000)]);
        assert!(matches!(plan_send(&ix, 1, 500, L2ShapeTag::P, TIERS), Err(SendRefusal::NoSingleNoteCovers { asset: 1, .. })));
    }

    #[test]
    fn without_an_exact_tariff_note_the_plan_splits_first_or_refuses() {
        let ix = index(&[(1, 50), (0, 3)]);
        match plan_send(&ix, 1, 50, L2ShapeTag::P, TIERS).unwrap() {
            Plan::SplitFirst { source, shape, .. } => assert_eq!((source.note.value, shape), (3, L2ShapeTag::P)),
            other => panic!("{other:?}"),
        }
        // A 1 is the S tariff, not the P one; 2 < p + s cannot be split.
        let ix = index(&[(1, 50), (0, 1), (0, 2)]);
        assert!(matches!(plan_send(&ix, 1, 50, L2ShapeTag::S, TIERS), Ok(Plan::WithFeeNote { .. })));
        assert_eq!(
            plan_send(&index(&[(1, 50), (0, 1)]), 1, 50, L2ShapeTag::P, TIERS),
            Err(SendRefusal::NoFeeSource { tariff: 2, split_needs: 3 })
        );
    }
}
