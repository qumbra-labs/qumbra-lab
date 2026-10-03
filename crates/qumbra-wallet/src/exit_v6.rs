//! **`exit --net v6`** (lab #860 R3): an L2 → L1 exit on a V6 chain — the
//! wallet's half of the bridge round trip.
//!
//! A V6 node serves the L2 state it derives from its stored bundles (R1,
//! `/v1/l2/…`) and each landed bundle's raw bytes (R2, `/v1/bundle/{h}`).
//! Design D3 makes the index a **hint stream**: before anything is proved,
//! the wallet takes the anchor from the index, fetches that one bundle, binds
//! its bytes to the index's id (`keccak == id`), reads W's stated public
//! values, and requires the served leaves (truncated to the bundle's
//! `c_next`) and the asset-0 registry opening to fold to the C and R roots
//! the bundle states ([`check_anchor`]). A lying index costs a refusal by
//! name, never a ≈ 30 GiB proof.
//!
//! **Which note.** V6 v1 has no L2 note discovery (design D1 — bundles carry
//! no ciphertexts). The wallet's L2 notes are the credits of its own claims,
//! which it **derives** from the pending deposits its L1 scan sets aside
//! ([`claim_credit`]: value less the claim tier, ρ = the claim's `cnf`, rseed
//! from `claim_blinds`, address 0 — exactly what `deposit claim` credits). A
//! credit counts when its commitment is among the anchor's leaves (claimed
//! and landed) and its nullifier is not among the served nullifiers — a hint
//! too: nullifier completeness is not verified (the #853 class), and the
//! plan says so.
//!
//! **Full-note exits only** ([`pick_credit`]): a partial exit would leave an
//! L2 change note under a random rseed, which a wallet restored from its
//! mnemonic could never find on V6 v1. **The fee is [`EXIT_FEE_V6`] = 0.**
//!
//! The exit file is `encode_exit_artifact` bound to the V6 genesis — the
//! sequencer intake's `classify` reads it unchanged. Until the sequencer
//! plans exits (lab #860 R3b) an exit handed to it is **held**, not landed.

use std::collections::HashSet;

use qlab_air::claim::{claim_cnf, l1_cm};
use qlab_cbserver::registry::RegistryOpening;
use qlab_cbserver::tree::CommitmentTree;
use qlab_ledger::assets::OwnedL2Note;
use qlab_ledger::deposits::{SetAside, SetAsideKind};
use qlab_note::hash::digest_bytes;
use qlab_note::l2note::L2Note;
use qlab_wallet::Wallet;
use qlab_wrapper::hash::WRoots;

/// **The fee of a V6 exit: 0** (lab #860, ruled 2026-10-04). No P tariff
/// exists (lab #785's census), and W's fee note sums the claims' fees only,
/// so a nonzero exit fee would be destroyed with no recipient. **When F6
/// defines the tx tariff** this becomes the tariff, and a full-note exit then
/// pays out the note's value less it.
pub const EXIT_FEE_V6: u64 = 0;

/// Why a V6 exit was not built — every one named, before any proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitV6Refusal {
    /// `/v1/l2/index` names no landed bundle yet.
    NoBundleYet,
    /// The index stopped folding (an R member, a torn store): its reason.
    IndexFrozen(String),
    /// The anchor bundle's bytes do not decode to W's stated values.
    NotABundle(String),
    /// The served leaves do not fold to the C root the bundle states.
    TreeRootMismatch,
    /// The index moved past the anchor between reads.
    IndexMoved { anchor: u64, now: u64 },
    /// The registry opening does not fold to the R root the bundle states.
    RegistryRootMismatch,
    /// No landed, unspent credit of this wallet's own claims.
    NoCredit,
    /// `--amount` names part of a note: refused (no change on V6 v1).
    PartialExit { amount: u64, note: u64 },
}

impl std::fmt::Display for ExitV6Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExitV6Refusal::NoBundleYet => write!(f, "no bundle has landed on this chain yet: there is no L2 state to exit from"),
            ExitV6Refusal::IndexFrozen(why) => write!(f, "the node's L2 index is frozen ({why}): refusing to anchor an exit to it"),
            ExitV6Refusal::NotABundle(why) => write!(f, "the anchor bundle does not decode to its stated values: {why}"),
            ExitV6Refusal::TreeRootMismatch => {
                write!(f, "the served L2 leaves do not fold to the C root the anchor bundle states — refusing before any proof")
            }
            ExitV6Refusal::IndexMoved { anchor, now } => write!(
                f,
                "the index moved under this read (anchor bundle at {anchor}, registry opening at {now}); rerun"
            ),
            ExitV6Refusal::RegistryRootMismatch => {
                write!(f, "the served asset-0 registry opening does not fold to the R root the anchor bundle states")
            }
            ExitV6Refusal::NoCredit => write!(
                f,
                "no landed, unspent credit of this wallet's claims: a claim's credit is spendable once its bundle has landed"
            ),
            ExitV6Refusal::PartialExit { amount, note } => write!(
                f,
                "--amount {amount} is part of a {note}-bessel note: V6 v1 has no L2 note discovery (design D1), so the \
                 change would be an L2 note a restored wallet can never find; format v2 brings discovery. Exit the whole \
                 note (--amount {note}, or omit --amount)"
            ),
        }
    }
}

impl std::error::Error for ExitV6Refusal {}

/// The out-side roots a landed bundle states (its W public values, read
/// without decoding a proof): the C root, `c_next` and the registry root R.
pub fn bundle_roots(bytes: &[u8]) -> Result<WRoots, ExitV6Refusal> {
    let stated = qlab_wrapper::codec::stated_pvs(bytes).map_err(|e| ExitV6Refusal::NotABundle(format!("{e:?}")))?;
    if stated.w_pvs.len() < qlab_wrapper::wleaf::W_PV_LEN {
        return Err(ExitV6Refusal::NotABundle(format!("{} W public values, fewer than {}", stated.w_pvs.len(), qlab_wrapper::wleaf::W_PV_LEN)));
    }
    Ok(qlab_wrapper::verify::roots_at(&stated.w_pvs, 1))
}

/// D3's check, before any proof: `tree` (the served leaves, `c_next` of
/// them) folds to the bundle's C, and `reg0` (the asset-0 opening, served at
/// index height `reg0.height`) to its R, at the anchor's own height.
pub fn check_anchor(tree: &CommitmentTree, reg0: &RegistryOpening, anchor_height: u64, out: &WRoots) -> Result<(), ExitV6Refusal> {
    if tree.len() != out.f3.c_next || tree.root() != out.f3.c {
        return Err(ExitV6Refusal::TreeRootMismatch);
    }
    if reg0.height != anchor_height {
        return Err(ExitV6Refusal::IndexMoved { anchor: anchor_height, now: reg0.height });
    }
    if reg0.root != out.f3.r {
        return Err(ExitV6Refusal::RegistryRootMismatch);
    }
    Ok(())
}

/// The L2 note a claim of `deposit` credits to this wallet — what
/// `deposit claim` builds: value less the claim tier, asset 0, address 0's
/// `rkm`, ρ = the claim's `cnf`, rseed from `claim_blinds`. `None` for a
/// deposit worth no more than the tier (its claim is refused).
pub fn claim_credit(wallet: &Wallet, deposit: &SetAside, l2_id: u64, tier: u64) -> Option<OwnedL2Note> {
    let burn_rkm = qlab_ledger::deposits::burn_rkm(l2_id);
    let cm = l1_cm(deposit.note.value, &burn_rkm, &deposit.note.rho, &deposit.note.rseed);
    let (_, rseed) = wallet.claim_blinds(&cm);
    let value = deposit.note.value.checked_sub(tier).filter(|v| *v > 0)?;
    let rkm = wallet.rkm(wallet.diversifier_at_index(0));
    let note = L2Note { value, asset: 0, rkm, rho: claim_cnf(&cm, &deposit.note.rseed), rseed };
    let cm2 = qlab_air::l2::l2_cm(value, 0, &rkm, &note.rho, &note.rseed);
    Some(OwnedL2Note { note, asset: 0, div_index: 0, height: deposit.height, tx_index: Some(deposit.tx_index), cm: digest_bytes(&cm2) })
}

/// The credits of this wallet's pending deposits to `l2_id`, oldest first.
pub fn credits(wallet: &Wallet, set_aside: &[SetAside], l2_id: u64, tier: u64) -> Vec<OwnedL2Note> {
    let mut deposits: Vec<&SetAside> =
        set_aside.iter().filter(|s| s.kind == SetAsideKind::PendingDeposit { l2_id }).collect();
    deposits.sort_by_key(|s| (s.height, s.tx_index, s.cm));
    deposits.iter().filter_map(|d| claim_credit(wallet, d, l2_id, tier)).collect()
}

/// The credit to exit, whole: landed (its commitment among `tree`'s leaves),
/// not spent (its nullifier not in `spent`), and — with `amount` — exactly
/// that value. Oldest first.
pub fn pick_credit(
    credits: &[OwnedL2Note],
    tree: &CommitmentTree,
    spent: &HashSet<[u8; 32]>,
    wallet: &Wallet,
    amount: Option<u64>,
) -> Result<OwnedL2Note, ExitV6Refusal> {
    let usable: Vec<&OwnedL2Note> = credits
        .iter()
        .filter(|c| tree.position_of(&qlab_note::hash::digest_from_bytes(&c.cm)).is_some() && !spent.contains(&c.nullifier(wallet)))
        .collect();
    match amount {
        None => usable.first().map(|c| (*c).clone()).ok_or(ExitV6Refusal::NoCredit),
        Some(a) => match usable.iter().find(|c| c.note.value == a) {
            Some(c) => Ok((*c).clone()),
            None => match usable.first() {
                Some(c) => Err(ExitV6Refusal::PartialExit { amount: a, note: c.note.value }),
                None => Err(ExitV6Refusal::NoCredit),
            },
        },
    }
}

/// The anchor the index names: the height and id of the last bundle it
/// folded — refused by name when it names none or is frozen.
pub fn anchor_of(index: &qlab_ledger::deposits::L2IndexAnswer) -> Result<(u64, [u8; 32]), ExitV6Refusal> {
    if let Some(why) = &index.refused {
        return Err(ExitV6Refusal::IndexFrozen(why.clone()));
    }
    match (index.height, index.bundle_id) {
        (Some(h), Some(id)) => Ok((h, id)),
        _ => Err(ExitV6Refusal::NoBundleYet),
    }
}

/// The intake's answer to a handed-over exit file: 202 (new or a replay) or
/// 409 (its nullifiers already held) is taken — and HELD until the sequencer
/// plans exits (R3b); anything else is the intake's refusal, named.
pub fn intake_verdict(status: u16, body: &[u8]) -> Result<String, String> {
    let body = String::from_utf8_lossy(body);
    match status {
        202 | 409 => Ok(format!(
            "the intake took it ({status}: {}) — HELD: the sequencer does not plan exits until lab #860 R3b lands",
            body.trim()
        )),
        _ => Err(format!("the intake refused the exit ({status}: {})", body.trim())),
    }
}

/// A planned V6 exit: the credit spent whole, the anchor bundle it was
/// checked against, and the instance to prove.
pub struct ExitV6Plan {
    pub credit: OwnedL2Note,
    pub anchor_height: u64,
    pub anchor_id: [u8; 32],
    pub c_next: u64,
    pub ei: qlab_l2spend::ExitInstance,
}

/// **Plan a V6 exit, proving nothing**: the anchor from `/v1/l2/index`, its
/// bundle bound to the id, D3's check of the served leaves and registry
/// opening against the bundle's stated roots, the credit picked whole, and
/// the instance built at that anchor. Every refusal is by name.
#[allow(clippy::too_many_arguments)]
pub fn plan<E: qlab_l2spend::Endpoint, R: rand::CryptoRng>(
    served: &qlab_l2spend::Served<E>,
    wallet: &Wallet,
    set_aside: &[SetAside],
    l2_id: u64,
    tier: u64,
    to_rkm: [u64; 4],
    amount: Option<u64>,
    rng: &mut R,
) -> Result<ExitV6Plan, String> {
    let index = qlab_ledger::deposits::parse_l2_index(&served.endpoint.get("/v1/l2/index")?)?;
    let (height, id) = anchor_of(&index).map_err(|e| e.to_string())?;
    let bytes = crate::v6_bundle::fetch_bundle(&mut |p: &str| served.endpoint.get(p), height, id).map_err(|e| e.to_string())?;
    let out = bundle_roots(&bytes).map_err(|e| e.to_string())?;
    let tree = served.commitment_tree_at(out.f3.c_next).map_err(|e| format!("{e:?}"))?;
    let reg0 = served.registry(0).map_err(|e| format!("{e:?}"))?;
    check_anchor(&tree, &reg0, height, &out).map_err(|e| e.to_string())?;
    let spent = served.spent_nullifiers().map_err(|e| format!("{e:?}"))?;
    let credit = pick_credit(&credits(wallet, set_aside, l2_id, tier), &tree, &spent, wallet, amount).map_err(|e| e.to_string())?;
    let ask = qlab_l2spend::ExitAsk { value: credit.note.value - EXIT_FEE_V6, to_rkm };
    let change = wallet.rkm(wallet.diversifier_at_index(0));
    let ei = qlab_l2spend::exit_instance(&tree, &reg0, &credit.spend_input(wallet), ask, change, EXIT_FEE_V6, rng)
        .map_err(|e| format!("{e:?}"))?;
    Ok(ExitV6Plan { credit, anchor_height: height, anchor_id: id, c_next: out.f3.c_next, ei })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::MasterSeed;

    fn wallet(k: u8) -> Wallet {
        Wallet::from_master_seed(&MasterSeed::from_entropy([k; 32]), crate::store::HD_ACCOUNT)
    }

    fn deposit(value: u64, k: u64) -> SetAside {
        let note = qlab_note::note::Note { value, rkm: qlab_ledger::deposits::burn_rkm(1), rho: [k; 4], rseed: [k + 1; 4] };
        let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
        SetAside { kind: SetAsideKind::PendingDeposit { l2_id: 1 }, div_index: 0, height: 10 + k, tx_index: 0, cm: digest_bytes(&cm), note }
    }

    /// **The credit round trip (mandatory, lab #860 R3 condition 2):** the
    /// note this wallet derives for a deposit is exactly the one the claim it
    /// would build credits — `claim_instance`'s cm2, with the same blinds and
    /// the same credit as `deposit claim`.
    #[test]
    fn a_derived_credit_is_the_claims_cm2() {
        let w = wallet(7);
        let d = deposit(50_000, 1);
        let tier = 4;
        let credit = claim_credit(&w, &d, 1, tier).unwrap();
        let cm = l1_cm(d.note.value, &d.note.rkm, &d.note.rho, &d.note.rseed);
        let mut tree = CommitmentTree::new();
        tree.append(cm);
        let (r_v, rseed) = w.claim_blinds(&cm);
        let burn = qlab_air::claim::BurnNote { value: d.note.value, rkm: d.note.rkm, rho: d.note.rho, rseed: d.note.rseed };
        let credit_to = qlab_air::claim::ClaimCredit { rkm: w.rkm(w.diversifier_at_index(0)), rseed };
        let inst = qlab_l2spend::claim_instance(&tree, 1, &burn, 1, &r_v, &credit_to, tier).unwrap();
        assert_eq!(credit.cm, digest_bytes(&inst.cm2), "the derived credit is the claim's cm2");
        assert_eq!((credit.note.value, credit.note.rho), (50_000 - tier, inst.cnf));
        assert_eq!(credit.note.rkm, w.rkm(w.diversifier_at_index(0)));
        assert_ne!(claim_credit(&wallet(8), &d, 1, tier).unwrap().cm, credit.cm, "another wallet's blinds");
        assert_eq!(claim_credit(&w, &deposit(4, 2), 1, tier), None, "worth no more than the tier: no credit");
    }

    /// Only landed, unspent credits are exits; whole notes only — a partial
    /// amount is refused by name; the oldest usable credit by default.
    #[test]
    fn a_credit_is_picked_whole_landed_and_unspent() {
        let w = wallet(7);
        let all = credits(&w, &[deposit(30_000, 3), deposit(50_000, 1), deposit(70_000, 5)], 1, 4);
        assert_eq!(all.iter().map(|c| c.note.value).collect::<Vec<_>>(), [49_996, 29_996, 69_996], "oldest first");
        let mut tree = CommitmentTree::new();
        tree.append([9; 4]);
        for c in &all[..2] {
            tree.append(qlab_note::hash::digest_from_bytes(&c.cm));
        }
        let none = HashSet::new();
        assert_eq!(pick_credit(&all, &tree, &none, &w, None).unwrap().note.value, 49_996);
        assert_eq!(pick_credit(&all, &tree, &none, &w, Some(29_996)).unwrap().note.value, 29_996);
        assert_eq!(
            pick_credit(&all, &tree, &none, &w, Some(10_000)),
            Err(ExitV6Refusal::PartialExit { amount: 10_000, note: 49_996 })
        );
        assert!(ExitV6Refusal::PartialExit { amount: 1, note: 2 }.to_string().contains("no L2 note discovery (design D1)"));
        assert_eq!(pick_credit(&all, &tree, &none, &w, Some(69_996)), Err(ExitV6Refusal::PartialExit { amount: 69_996, note: 49_996 }), "not landed");
        let spent: HashSet<[u8; 32]> = [all[0].nullifier(&w), all[1].nullifier(&w)].into_iter().collect();
        assert_eq!(pick_credit(&all, &tree, &spent, &w, None), Err(ExitV6Refusal::NoCredit));
    }

    /// The planned instance is built at the checked anchor: its anchor is
    /// the tree's root at `c_next`, its registry root the opening's, and it
    /// exits the credit whole at fee 0.
    #[test]
    fn the_exit_instance_is_built_whole_at_the_anchor() {
        let w = wallet(7);
        let all = credits(&w, &[deposit(50_000, 1)], 1, 4);
        let mut tree = CommitmentTree::new();
        tree.append([9; 4]);
        tree.append(qlab_note::hash::digest_from_bytes(&all[0].cm));
        let reg = qlab_cbserver::registry::RegistryTree::from_leaves(&[qlab_air::l2::RegistryLeaf::cloaked(0)]).unwrap();
        let reg0 = qlab_cbserver::registry::decode_registry_opening(&qlab_cbserver::registry::encode_registry_opening(&reg, 40, 0).unwrap()).unwrap();
        let credit = pick_credit(&all, &tree, &HashSet::new(), &w, None).unwrap();
        let to = qlab_wallet::address::Address::decode(&wallet(9).address_at_index(0).encode()).unwrap().rkm_lanes();
        assert_eq!(to, wallet(9).rkm(wallet(9).diversifier_at_index(0)), "--exit-to's address decodes to its rkm");
        let ask = qlab_l2spend::ExitAsk { value: credit.note.value - EXIT_FEE_V6, to_rkm: to };
        let mut rng = rand::rng();
        let ei = qlab_l2spend::exit_instance(&tree, &reg0, &credit.spend_input(&w), ask, w.rkm(w.diversifier_at_index(0)), EXIT_FEE_V6, &mut rng).unwrap();
        assert_eq!((ei.inst.anchor, ei.inst.registry_root), (tree.root(), reg0.root));
        assert_eq!(ei.ask.value, 49_996, "the whole credit at fee 0");
    }

    /// The intake's answer: taken (and said HELD) or refused by name.
    #[test]
    fn the_intake_answer_is_taken_and_held_or_named() {
        let taken = intake_verdict(202, br#"{"v":1,"id":"ab","kind":"exit","replay":false}"#).unwrap();
        assert!(taken.contains("HELD") && taken.contains("R3b"), "{taken}");
        assert!(intake_verdict(409, b"conflict").unwrap().contains("HELD"));
        assert_eq!(intake_verdict(400, br#"{"error":"refused","why":"x"}"#).unwrap_err(), r#"the intake refused the exit (400: {"error":"refused","why":"x"})"#);
    }

    /// The index's answer: a landed bundle is the anchor; none yet, or a
    /// frozen index, is refused by name.
    #[test]
    fn the_index_names_the_anchor_or_is_refused() {
        use qlab_ledger::deposits::L2IndexAnswer;
        let ok = L2IndexAnswer { height: Some(244), bundle_id: Some([3; 32]), refused: None };
        assert_eq!(anchor_of(&ok), Ok((244, [3; 32])));
        assert_eq!(anchor_of(&L2IndexAnswer { height: None, bundle_id: None, refused: None }), Err(ExitV6Refusal::NoBundleYet));
        let frozen = L2IndexAnswer { refused: Some("an R member at 300".into()), ..ok };
        assert_eq!(anchor_of(&frozen), Err(ExitV6Refusal::IndexFrozen("an R member at 300".into())));
        assert!(ExitV6Refusal::IndexFrozen("x".into()).to_string().contains("frozen"));
    }

    /// D3's refusals, by name, before any proof: leaves that do not fold to
    /// the bundle's C (or are not `c_next` of them), an opening at another
    /// index height, an opening that does not fold to R.
    #[test]
    fn the_anchor_check_refuses_by_name() {
        let mut tree = CommitmentTree::new();
        tree.append([1; 4]);
        tree.append([2; 4]);
        let reg = qlab_cbserver::registry::RegistryTree::from_leaves(&[qlab_air::l2::RegistryLeaf::cloaked(0)]).unwrap();
        let reg0 = qlab_cbserver::registry::decode_registry_opening(&qlab_cbserver::registry::encode_registry_opening(&reg, 40, 0).unwrap()).unwrap();
        let mut out = qlab_wrapper::verify::roots_at(&vec![0u32; qlab_wrapper::wleaf::W_PV_LEN], 1);
        out.f3.c = tree.root();
        out.f3.c_next = 2;
        out.f3.r = reg0.root;
        assert_eq!(check_anchor(&tree, &reg0, 40, &out), Ok(()));
        let mut short = out;
        short.f3.c_next = 3;
        assert_eq!(check_anchor(&tree, &reg0, 40, &short), Err(ExitV6Refusal::TreeRootMismatch));
        let mut other_c = out;
        other_c.f3.c = [7; 4];
        assert_eq!(check_anchor(&tree, &reg0, 40, &other_c), Err(ExitV6Refusal::TreeRootMismatch));
        assert_eq!(check_anchor(&tree, &reg0, 39, &out), Err(ExitV6Refusal::IndexMoved { anchor: 39, now: 40 }));
        let mut other_r = out;
        other_r.f3.r = [7; 4];
        assert_eq!(check_anchor(&tree, &reg0, 40, &other_r), Err(ExitV6Refusal::RegistryRootMismatch));
        assert!(matches!(bundle_roots(b"not a bundle"), Err(ExitV6Refusal::NotABundle(_))));
    }
}
