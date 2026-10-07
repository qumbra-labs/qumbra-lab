//! **What a Candidate A wallet's authorizations did on chain** (lab #896 G,
//! moved here lean for the browser kernel — lab #924 PR 3b): a verified
//! body's binding to its header, the slots of a transaction's section, the
//! cursor position above a generation's landed leaves, and the journal a
//! restore writes. Pure over verified bodies; the CLI (`annulet_v2`) and the
//! kernel (`qumbra-ffi`) both call it, so "landed" means one thing.
//!
//! **"Landed" is judged from verified bodies, never a node's word**: each
//! body bound to its verified header, each slot's leaf matched against the
//! generation's own tree (a dummy's leaf never matches).

use qlab_devnet::body::{BlockBody, TxEntry};
use qlab_devnet::forms::L2AuthForm;
use qlab_devnet::header::BlockHeader;
use qlab_ledger::assets::OwnedL2Note;
use qlab_remote_auth::annulet::{auth_master, AuthTree, Cursor, D_AUTH};
use qlab_remote_auth::Hash32;
use qlab_wallet::Wallet;

use crate::auth_journal::{generation_root, AuthJournal, GenState, Generation, JournalError, SweepGate};

/// A wallet's landed slots `(leaf_index, leaf)` per generation.
pub type LandedByGeneration = std::collections::BTreeMap<u32, Vec<(u32, [u8; 32])>>;

/// Why a served body was not bound to its verified header.
#[derive(Debug)]
pub enum BodyRefusal {
    /// The answer does not decode on this net's wire.
    Decode(String),
    /// The served header is not the verified one.
    Header,
    /// The body's counts are out of bounds.
    Counts(crate::annulet_verify::VerifyRefusal),
    /// The body is not the one the header commits to.
    Commitment,
}

impl std::fmt::Display for BodyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyRefusal::Decode(e) => write!(f, "does not decode: {e}"),
            BodyRefusal::Header => write!(f, "its served header is not the verified one"),
            BodyRefusal::Counts(e) => write!(f, "{e}"),
            BodyRefusal::Commitment => write!(f, "is not the one its verified header commits to"),
        }
    }
}

/// Bind served `bytes` for `height` to the verified `header`: the chain's
/// frame, the header itself, the counts (before the commitment's byte
/// asserts), then the recomputed `tx_body_commitment`.
pub fn bind_body(header: &BlockHeader, l2_auth: L2AuthForm, height: u64, bytes: &[u8]) -> Result<BlockBody, BodyRefusal> {
    let wire = qlab_p2p::compact::WireForm {
        form: qlab_devnet::forms::GenesisForm::Annulet,
        sections: qlab_devnet::forms::BodySections::None,
        l2_auth,
    };
    let ann = qlab_p2p::served::decode_body_answer(wire, height, bytes).map_err(|e| BodyRefusal::Decode(e.to_string()))?;
    if ann.header != *header {
        return Err(BodyRefusal::Header);
    }
    let body = qlab_p2p::served::body_of(&ann);
    crate::annulet_verify::check_body_counts(height, &body).map_err(BodyRefusal::Counts)?;
    if qlab_devnet::annulet::body_commitment_annulet_for(&body, l2_auth) != header.tx_body_commitment {
        return Err(BodyRefusal::Commitment);
    }
    Ok(body)
}

/// Every slot `(leaf_index, leaf)` of a transaction's auth section, or
/// `None` when it carries no readable one.
pub fn slots_of(tx: &TxEntry) -> Option<Vec<(u32, [u8; 32])>> {
    use qlab_devnet::annulet::L2Surface;
    use qlab_remote_auth::annulet::AnnuletAuthSection;
    let Ok(Some(surface)) = L2Surface::decode(&tx.l2) else { return None };
    let section = AnnuletAuthSection::decode(qlab_devnet::annulet::auth_shape(surface.shape), &tx.auth).ok()?;
    Some(section.slots.iter().map(|s| (s.descriptor.leaf_index(), s.descriptor.leaf())).collect())
}

/// The slots of `body` whose leaf is `tree`'s at that index — a
/// generation's landed leaves in one block.
pub fn landed_in(tree: &AuthTree, body: &BlockBody) -> Vec<(u32, [u8; 32])> {
    body.txs
        .iter()
        .flat_map(|tx| slots_of(tx).unwrap_or_default())
        .filter(|(index, leaf)| (*index as usize) < (1usize << D_AUTH) && tree.leaf(*index) == *leaf)
        .collect()
}

/// The cursor position above every slot of `landed` that is a leaf of the
/// generation whose master is `master` and tree `tree`: `max(position) + 1`,
/// or 0 if none. The cursor is a private permutation, so this is a
/// position, not a leaf index.
pub fn landed_next_with(master: &Hash32, tree: &AuthTree, landed: &[(u32, [u8; 32])]) -> u32 {
    let mine: std::collections::BTreeSet<u32> = landed
        .iter()
        .filter(|(index, leaf)| (*index as usize) < (1usize << D_AUTH) && tree.leaf(*index) == *leaf)
        .map(|(index, _)| *index)
        .collect();
    if mine.is_empty() {
        return 0;
    }
    // Walk the permutation until every landed leaf has been drawn.
    let mut cursor = Cursor::new(master, D_AUTH, 0).expect("position 0");
    let mut left = mine;
    while !left.is_empty() {
        let index = cursor.take().expect("every leaf index is in the permutation");
        left.remove(&index);
    }
    cursor.next()
}

/// [`landed_next_with`] for `wallet`'s generation `g` (builds its tree).
pub fn landed_next(wallet: &Wallet, g: u32, landed: &[(u32, [u8; 32])]) -> u32 {
    let master = auth_master(&wallet.auth_secret(), g);
    let tree = AuthTree::build(&master, D_AUTH).expect("D_AUTH is a valid depth");
    landed_next_with(&master, &tree, landed)
}

/// **The journal a restore writes** (§9) for a wallet with no `auth.v1`: no
/// generation it has used is ever resumed. Used = the verified scan found a
/// note of it (`owned`) or a landed transaction carries one of its leaves
/// (`used`). With none, generation 0 fresh. Otherwise every used generation
/// with notes is sweep-only (gated on `genesis` at `gate_tip +
/// MAX_AUTH_VALIDITY_BLOCKS`), a used one without is retired, each at a
/// cursor above its landed positions, and `g* + 1` opens active.
pub fn restore_generations(
    wallet: &Wallet,
    owned: &[OwnedL2Note],
    used: &LandedByGeneration,
    genesis: &Hash32,
    gate_tip: u64,
) -> Result<AuthJournal, JournalError> {
    let top = owned.iter().filter_map(|n| n.generation).chain(used.keys().copied()).max();
    let probed = crate::auth_journal::PROBE_GENERATIONS;
    match top {
        None => Ok(AuthJournal::fresh(generation_root(wallet, 0))),
        Some(g_star) if g_star + 1 >= probed => Err(JournalError::ProbeExhausted { probed }),
        Some(g_star) => {
            let gate = SweepGate {
                genesis: *genesis,
                not_before_height: gate_tip.saturating_add(qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS),
            };
            let mut gens = Vec::new();
            for g in 0..=g_star {
                let has_notes = owned.iter().any(|n| n.generation == Some(g));
                let landed = used.get(&g);
                if !has_notes && landed.is_none() {
                    continue;
                }
                gens.push(Generation {
                    g,
                    next: landed.map_or(0, |slots| landed_next(wallet, g, slots)),
                    auth_root: generation_root(wallet, g),
                    state: if has_notes { GenState::Sweep { gates: vec![gate] } } else { GenState::Retired },
                });
            }
            gens.push(Generation { g: g_star + 1, next: 0, auth_root: generation_root(wallet, g_star + 1), state: GenState::Active });
            AuthJournal::from_generations(gens)
        }
    }
}
