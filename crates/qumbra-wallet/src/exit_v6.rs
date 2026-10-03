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
//! the bundle states ([`check_anchor`]). An index that disagrees with its
//! own bundle costs a refusal by name before any proof. **What this does
//! not establish**: the id and the bytes both come from the same node, so
//! `keccak == id` is self-consistency, not authenticity — the anchor
//! bundle's L1 inclusion is not verified by this wallet (follow-up R3c, lab #886: check
//! it against the L1 block body the wallet's scan already reads). A node
//! that fabricates a consistent bundle, leaves and opening passes here and
//! wastes a ≈ 30 GiB proof; the chain then refuses the exit — a lying node
//! can waste a proof, never funds.
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
    /// No landed, unspent credit of this wallet's own claims at claim tier
    /// `tier`.
    NoCredit { tier: u64 },
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
            ExitV6Refusal::NoCredit { tier } => write!(
                f,
                "no landed, unspent credit of this wallet's claims matches at claim tier {tier}: a credit is spendable once \
                 its claim's bundle has landed; if the claim landed under another tier, nothing here can find it"
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
    tier: u64,
) -> Result<OwnedL2Note, ExitV6Refusal> {
    let usable: Vec<&OwnedL2Note> = credits
        .iter()
        .filter(|c| tree.position_of(&qlab_note::hash::digest_from_bytes(&c.cm)).is_some() && !spent.contains(&c.nullifier(wallet)))
        .collect();
    match amount {
        None => usable.first().map(|c| (*c).clone()).ok_or(ExitV6Refusal::NoCredit { tier }),
        Some(a) => match usable.iter().find(|c| c.note.value == a) {
            Some(c) => Ok((*c).clone()),
            None => match usable.first() {
                Some(c) => Err(ExitV6Refusal::PartialExit { amount: a, note: c.note.value }),
                None => Err(ExitV6Refusal::NoCredit { tier }),
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
        202 => Ok(format!(
            "the intake took it (202: {}) — HELD: the sequencer does not plan exits until lab #860 R3b lands",
            body.trim()
        )),
        409 => Ok(format!(
            "already held by the intake (409 — a replay or an earlier submission: {}) — HELD: the sequencer does not \
             plan exits until lab #860 R3b lands",
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
    change_to: &qlab_l2spend::Recipient,
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
    let spent = served.spent_nullifiers().map_err(|e| {
        format!(
            "{e:?} (a /v1/l2/nullifiers page past this wallet's ceiling of {} nullifiers per height reads as a transport error)",
            crate::annulet_verify::MAX_L2_NULLIFIERS_PER_HEIGHT
        )
    })?;
    let credit = pick_credit(&credits(wallet, set_aside, l2_id, tier), &tree, &spent, wallet, amount, tier).map_err(|e| e.to_string())?;
    let ask = qlab_l2spend::ExitAsk { value: credit.note.value - EXIT_FEE_V6, to_rkm };
    // The change (0 at a whole-note exit) goes to the same recipient the
    // entry is assembled for — one source for both.
    let ei = qlab_l2spend::exit_instance(&tree, &reg0, &credit.spend_input(wallet), ask, change_to.rkm, EXIT_FEE_V6, rng)
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
        assert_eq!(pick_credit(&all, &tree, &none, &w, None, 4).unwrap().note.value, 49_996);
        assert_eq!(pick_credit(&all, &tree, &none, &w, Some(29_996), 4).unwrap().note.value, 29_996);
        assert_eq!(
            pick_credit(&all, &tree, &none, &w, Some(10_000), 4),
            Err(ExitV6Refusal::PartialExit { amount: 10_000, note: 49_996 })
        );
        assert!(ExitV6Refusal::PartialExit { amount: 1, note: 2 }.to_string().contains("no L2 note discovery (design D1)"));
        assert_eq!(pick_credit(&all, &tree, &none, &w, Some(69_996), 4), Err(ExitV6Refusal::PartialExit { amount: 69_996, note: 49_996 }), "not landed");
        let spent: HashSet<[u8; 32]> = [all[0].nullifier(&w), all[1].nullifier(&w)].into_iter().collect();
        assert_eq!(pick_credit(&all, &tree, &spent, &w, None, 4), Err(ExitV6Refusal::NoCredit { tier: 4 }));
        assert!(ExitV6Refusal::NoCredit { tier: 4 }.to_string().contains("at claim tier 4") , "the tier is named");
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
        let credit = pick_credit(&all, &tree, &HashSet::new(), &w, None, 4).unwrap();
        let to = qlab_wallet::address::Address::decode(&wallet(9).address_at_index(0).encode()).unwrap().rkm_lanes();
        assert_eq!(to, wallet(9).rkm(wallet(9).diversifier_at_index(0)), "--exit-to's address decodes to its rkm");
        let ask = qlab_l2spend::ExitAsk { value: credit.note.value - EXIT_FEE_V6, to_rkm: to };
        let mut rng = rand::rng();
        let ei = qlab_l2spend::exit_instance(&tree, &reg0, &credit.spend_input(&w), ask, w.rkm(w.diversifier_at_index(0)), EXIT_FEE_V6, &mut rng).unwrap();
        assert_eq!((ei.inst.anchor, ei.inst.registry_root), (tree.root(), reg0.root));
        assert_eq!(ei.ask.value, 49_996, "the whole credit at fee 0");
    }

    /// A fake V6 node: the index, one bundle frame stating `out`, the leaves,
    /// the asset-0 opening and an empty nullifier page — and the frame's id.
    struct FakeV6 {
        index: String,
        frame: Vec<u8>,
        leaves: Vec<[u8; 32]>,
        reg: Vec<u8>,
        nulls: Vec<u8>,
    }
    impl qlab_l2spend::Endpoint for &FakeV6 {
        fn get(&self, path: &str) -> Result<Vec<u8>, String> {
            if path == "/v1/l2/index" {
                Ok(self.index.clone().into_bytes())
            } else if path.starts_with("/v1/bundle/") {
                Ok(self.frame.clone())
            } else if path.starts_with("/v1/l2/tree/leaves") {
                Ok(qlab_node::TreeLeaves { from: 0, total: self.leaves.len() as u64, leaves: self.leaves.clone() }.to_bytes())
            } else if path == "/v1/l2/registry/0" {
                Ok(self.reg.clone())
            } else if path.starts_with("/v1/l2/nullifiers") {
                Ok(self.nulls.clone())
            } else {
                Err(format!("not served: {path}"))
            }
        }
        fn post(&self, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), String> {
            Err("no".into())
        }
    }

    fn put_digest(w: &mut [u32], off: usize, d: &[u64; 4]) {
        for (l, lane) in d.iter().enumerate() {
            for j in 0..4 {
                w[off + 4 * l + j] = ((lane >> (16 * j)) & 0xffff) as u32;
            }
        }
    }

    /// `plan` end to end over a fake node: the index's bundle (a real frame
    /// stating the served tree's C at c_next and the opening's R) checks, the
    /// wallet's credit is found among the leaves, and the instance is built
    /// at that anchor, whole at fee 0. An index naming another id is refused
    /// by name, before any tree is read.
    #[test]
    fn plan_checks_the_anchor_and_builds_the_exit() {
        use qlab_wrapper::wleaf::{PV_C, PV_CN, PV_R, PV_SIDE, W_PV_LEN};
        let w = wallet(7);
        let d = deposit(50_000, 1);
        let credit = claim_credit(&w, &d, 1, 4).unwrap();
        let leaves = vec![[9u8; 32], credit.cm];
        let mut tree = CommitmentTree::new();
        for l in &leaves {
            tree.append_bytes(l);
        }
        let reg = qlab_cbserver::registry::RegistryTree::from_leaves(&[qlab_air::l2::RegistryLeaf::cloaked(0)]).unwrap();
        let reg_bytes = qlab_cbserver::registry::encode_registry_opening(&reg, 244, 0).unwrap();
        let reg_root = qlab_cbserver::registry::decode_registry_opening(&reg_bytes).unwrap().root;
        let mut pvs = vec![0u32; W_PV_LEN];
        put_digest(&mut pvs, PV_SIDE + PV_C, &tree.root());
        pvs[PV_SIDE + PV_CN] = 2;
        put_digest(&mut pvs, PV_SIDE + PV_R, &reg_root);
        let frame = qlab_wrapper::codec::encode_frame(&qlab_wrapper::codec::FrameParts {
            version: 1,
            l2_id: 1,
            w_pvs: &pvs,
            w_proof: &[],
            dep_pvs: &[],
            dep_proof: &[],
            members: &[],
            exits: &[],
            sig: &[0u8; qlab_wrapper::codec::SEQUENCER_SIG_LEN],
        });
        let id = qlab_devnet::hash::keccak256(&frame);
        let hexid: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let node = FakeV6 {
            index: format!(r#"{{"v":1,"height":244,"bundle_id":"{hexid}","refused":null}}"#),
            frame,
            leaves,
            reg: reg_bytes,
            nulls: qlab_cbserver::codec::NullifierPage { from: 0, to: 244, blocks: vec![] }.to_bytes(),
        };
        let me = crate::annulet_send::recipient_of(&w.address_at_index(0)).unwrap();
        let to = wallet(9).rkm(wallet(9).diversifier_at_index(0));
        let mut rng = rand::rng();
        let p = plan(&qlab_l2spend::Served::v6(&node), &w, std::slice::from_ref(&d), 1, 4, to, &me, None, &mut rng).unwrap();
        assert_eq!((p.anchor_height, p.anchor_id, p.c_next), (244, id, 2));
        assert_eq!((p.credit.cm, p.ei.ask.value), (credit.cm, 49_996));
        assert_eq!((p.ei.inst.anchor, p.ei.inst.registry_root), (tree.root(), reg_root));
        assert_eq!(me.rkm, w.rkm(w.diversifier_at_index(0)), "the change recipient is address 0 — one source");
        let lying = FakeV6 { index: node.index.replace(&hexid, &"ab".repeat(32)), ..node };
        let err = plan(&qlab_l2spend::Served::v6(&lying), &w, &[d], 1, 4, to, &me, None, &mut rng).err().unwrap();
        assert!(err.contains("the bundle served for height 244 hashes to"), "the id mismatch is named: {err}");
    }

    /// The intake's answer: taken (and said HELD) or refused by name.
    #[test]
    fn the_intake_answer_is_taken_and_held_or_named() {
        let taken = intake_verdict(202, br#"{"v":1,"id":"ab","kind":"exit","replay":false}"#).unwrap();
        assert!(taken.contains("HELD") && taken.contains("R3b"), "{taken}");
        let again = intake_verdict(409, b"conflict").unwrap();
        assert!(again.starts_with("already held by the intake (409") && again.contains("HELD"), "{again}");
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
