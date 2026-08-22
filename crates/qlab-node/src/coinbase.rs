//! The coinbase note (issue #101) — how a mined coin becomes a spendable note.
//!
//! ## What this replaces
//!
//! Before this module the block's coinbase had a "commitment" that was not a note
//! commitment: `keccak256(b"qumbra:devnet:coinbase-note:v1" ‖ height ‖ total)`,
//! domain-separated *precisely so it could never collide with a real note*. It
//! went into a registry and never into the commitment tree — and appending it
//! would not have helped, because the 2×2 circuit cannot open it. That function
//! is deleted, not deprecated: there is one kind of coinbase note now, and after
//! this module it is an ordinary note.
//!
//! A real note is `(value, rkm, ρ, rseed)` with `cm = H(value ‖ rkm ‖ ρ ‖ rseed)`
//! in the circuit's exact lane packing and **no domain string**
//! ([`qlab_note::note::note_commitment`]). To mint one for a miner you need the
//! miner's `rkm`, which no block carried — hence [`BlockBody::coinbase_rkm`].
//!
//! ## The derivation (consensus rules, ratified on issue #101)
//!
//! ```text
//!   value = RewardSplit::of(body.coinbase_total()).miner + body.total_fees()
//!   rkm   = body.coinbase_payees[0].rkm                      (raw, from the block)
//!   ρ     = H(b"qumbra:coinbase-note-rho:v1"   ‖ height_le ‖ rkm_le)
//!   rseed = H(b"qumbra:coinbase-note-rseed:v1" ‖ height_le ‖ rkm_le)
//!   cm    = note_commitment(value, rkm, ρ, rseed)            ← the tree leaf
//! ```
//!
//! Everything here is a **pure function of `(height, body)`**. That is the
//! property `open == replay` needs: a replaying node recomputes the identical
//! leaf from the identical block, with no access to node state, no clock and no
//! randomness.
//!
//! ### Why the opening is public, and why that is not a leak
//!
//! `tokenomics-and-issuance.md:116` — the coinbase note *"carries public value at
//! creation and enters the pool as an ordinary note after a maturity delay …
//! one-hop transparency, then gone."* A publicly reconstructible opening is
//! therefore the **supply-audit anchor** (`performance-budget` §9), not a privacy
//! defect. Privacy arrives when the note is spent into the pool, not when it is
//! created. Determinism also buys wallet-loss recovery: a miner who lost
//! everything but their spend key can rebuild the note from chain data, whereas a
//! random `rseed` would leave coins permanently unspendable that still count
//! against the audit equation.
//!
//! ### ρ: "tx-position derivation", for a thing with no tx position
//!
//! `transaction-model-and-anonymity-set.md:61` fixes ρ *"with tx-position
//! derivation for coinbase-like issuance"* and stops. A coinbase has no tx slot,
//! so its position **is** its height — exactly one coinbase per height, per
//! branch. `rkm` is in the preimage because `nf = Keccak(nk ‖ ρ)`
//! ([`qlab_air::narrow::derive_input`]) binds only `nk` and ρ: including `rkm`
//! makes a miner's coinbase nullifier depend on the address they were paid at
//! rather than on the height alone.
//!
//! ### The uniqueness claim, stated at the strength that actually holds
//!
//! One coinbase per height **per branch** — not per height. Two sibling blocks at
//! the same height may carry the same `coinbase_rkm` (a miner that finds two
//! nonces; an attacker that pays the honest miner's `rkm` to grief them), and
//! then the two preimages are equal. Because `nf` binds only `(nk, ρ)`, two
//! siblings paying the same miner with *different fee totals* yield **different
//! commitments and the same nullifier**.
//!
//! This is harmless and is left as-is deliberately: only one branch is canonical,
//! and the losing branch's issuance was never spendable. It is written down
//! because the ratification's "exactly one coinbase per height" is a stronger
//! claim than what holds, and the next reader should not build on it. Killing it
//! outright would mean binding the block hash into the preimage, which would make
//! the note underivable from the body and move it behind PoW grinding — a bad
//! trade for a collision confined to branches that lose.
//!
//! ## Value: what the note is worth, and one honest divergence
//!
//! [`coinbase_note_value`] is the miner's frozen §3 share (65 %, absorbing the
//! rounding remainder) plus the block's fees, which are paid to the miner —
//! less the burned name-fee portion (lab #367), the one part of a declared
//! fee that is NOT the miner's. The committee (15 %) and treasury (20 %) shares are **not**
//! minted: no payout path for them exists (they are accrual accounting —
//! `recovery::committee_accrual_finalized`), so minting them would require naming
//! recipients this baton has none for. The consequence is stated rather than
//! hidden: `Σ minted notes = 0.65·S(h) + fees`, not `S(h)`, so the §9 supply
//! attestation balances against a stated relation and not against `S(h)` directly
//! until those payout paths exist.
//!
//! **The divergence:** this is *not* [`crate::mempool::BlockTemplate::miner_take`],
//! which additionally subtracts the §6 quadratic weight penalty. The penalty
//! depends on the governor's effective median — node state the *applier* does not
//! reconstruct — and using it here would make block application depend on the
//! weight governor, or force the body to declare the penalty (another format
//! change). The penalty is 0 everywhere inside the 10 MB free zone, so on any net
//! we run the two agree; they are still not the same expression, and
//! [`crate::mempool::BlockTemplate`] carries the same note this module derives so
//! the assembler and the applier can never disagree about the leaf.

use qlab_devnet::body::BlockBody;
use qlab_devnet::hash::keccak256;
use qlab_note::hash::{digest_bytes, digest_from_bytes};
use qlab_note::note::Note;

use crate::emission::RewardSplit;
use crate::store::Hash32;

/// Domain string for a coinbase note's ρ. **Fresh** — deliberately not
/// `qumbra:devnet:coinbase-note:v1`, which belonged to the deleted placeholder
/// commitment; reusing it would make the two indistinguishable in exactly the
/// situation where telling them apart matters.
pub const COINBASE_RHO_DOMAIN: &[u8] = b"qumbra:coinbase-note-rho:v1";

/// Domain string for a coinbase note's `rseed`. See [`COINBASE_RHO_DOMAIN`].
pub const COINBASE_RSEED_DOMAIN: &[u8] = b"qumbra:coinbase-note-rseed:v1";

/// Domain string for a **v5-form** coinbase note's ρ (lab #470 stage 2). The
/// v5 preimage carries the payee **index** so two payees sharing one `rkm` at
/// one height still derive distinct ρ — the coordinator's condition: the index
/// lands in the FORMAT now, while the birth cap is 1, so raising the cap stays
/// a rule change forever. A fresh domain (not a length pun on the v1 string)
/// so the two derivations can never be confused for each other.
pub const COINBASE_RHO_DOMAIN_V5: &[u8] = b"qumbra:coinbase-note-rho:v2";

/// Domain string for a v5-form coinbase note's `rseed`. See
/// [`COINBASE_RHO_DOMAIN_V5`].
pub const COINBASE_RSEED_DOMAIN_V5: &[u8] = b"qumbra:coinbase-note-rseed:v2";

/// `H(domain ‖ height_le ‖ rkm_le)` as circuit lanes — the shared shape of both
/// the ρ and the `rseed` rule.
fn derive_lanes(domain: &[u8], height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    let mut buf = Vec::with_capacity(domain.len() + 8 + 32);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&height.to_le_bytes());
    for lane in rkm {
        buf.extend_from_slice(&lane.to_le_bytes());
    }
    digest_from_bytes(&keccak256(&buf))
}

/// The coinbase note's ρ at `height` for payee `rkm`.
pub fn coinbase_rho(height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes(COINBASE_RHO_DOMAIN, height, rkm)
}

/// The coinbase note's `rseed` at `height` for payee `rkm`.
pub fn coinbase_rseed(height: u64, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes(COINBASE_RSEED_DOMAIN, height, rkm)
}

/// `H(domain ‖ height_le ‖ payee_index ‖ rkm_le)` — the v5 shape of
/// [`derive_lanes`]: one extra byte, the payee index, between height and rkm.
fn derive_lanes_v5(domain: &[u8], height: u64, payee_index: u8, rkm: &[u64; 4]) -> [u64; 4] {
    let mut buf = Vec::with_capacity(domain.len() + 8 + 1 + 32);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&height.to_le_bytes());
    buf.push(payee_index);
    for lane in rkm {
        buf.extend_from_slice(&lane.to_le_bytes());
    }
    digest_from_bytes(&keccak256(&buf))
}

/// The **v5-form** coinbase note ρ at `height` for the payee at `payee_index`
/// (lab #470 stage 2). At the birth cap the index is always 0; the format
/// carries it so per-height ρ uniqueness survives the cap raise.
pub fn coinbase_rho_v5(height: u64, payee_index: u8, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes_v5(COINBASE_RHO_DOMAIN_V5, height, payee_index, rkm)
}

/// The v5-form coinbase note `rseed`. See [`coinbase_rho_v5`].
pub fn coinbase_rseed_v5(height: u64, payee_index: u8, rkm: &[u64; 4]) -> [u64; 4] {
    derive_lanes_v5(COINBASE_RSEED_DOMAIN_V5, height, payee_index, rkm)
}

/// The value the coinbase note carries: the miner's frozen §3 share of the
/// block's scheduled emission plus the block's fees **minus the burned
/// name-fee portion** (lab #367). See the module docs for why the
/// committee/treasury shares are not minted and why the §6 weight penalty is
/// not subtracted here.
///
/// The subtraction is the burn's whole mechanism: the fee-split rule made a
/// registering tx declare `posted_fee + name_fee`, and the name half simply
/// never enters any note — no burn address, no extra machinery, supply
/// arithmetic only (N2). Rider-free bodies subtract zero, so every
/// pre-boundary coinbase value — i.e. the entire live chain — is unchanged,
/// and `value_is_the_miner_share_plus_fees` still passes untouched, which is
/// the compat lock this seam wants.
pub fn coinbase_note_value(body: &BlockBody) -> u64 {
    coinbase_note_value_parts(body.coinbase_total(), body.total_fees(), body.total_name_burn())
}

/// [`coinbase_note_value`]'s arithmetic over the three body facts it is a
/// function of — **the one expression**, so a caller holding those facts without
/// the body around them computes the same value rather than a copy of it.
///
/// ## Why this seam exists (lab #415)
///
/// A wallet is not a node, so it can never hold a `BlockBody`; before lab #415
/// it could not see a coinbase note at all. The route that fixes that serves
/// `(height, coinbase_rkm, coinbase, fees, name_burn)` — the block's own facts,
/// no derivation on the serving path — and the wallet reconstructs the note by
/// calling **this** function. That is deliberate and it is the whole correctness
/// argument: a wallet whose idea of "what the miner took" drifted from the
/// applier's would derive a different `cm`, and a different `cm` is not a leaf of
/// the commitment tree — so the note would read as a wrong balance *and* be
/// unspendable, with nothing pointing at the arithmetic.
///
/// 🔴 **The schedule alone is not this number.** `emission::coinbase(h)` is the
/// whole issuance; the miner takes the frozen §3 share of it, **plus the block's
/// fees**, less the burned name-fee portion (lab #367). A reader tempted to
/// substitute `coinbase(height)` here should note that it is also wrong on this
/// chain's own history at height 1377, whose committed coinbase is not the
/// schedule's (#299's grandfathered scar, below `RULE_BOUNDARY_HEIGHT`).
pub fn coinbase_note_value_parts(coinbase: u64, total_fees: u64, total_name_burn: u64) -> u64 {
    RewardSplit::of(coinbase)
        .miner
        .saturating_add(total_fees)
        .saturating_sub(total_name_burn)
}

/// The coinbase note minted by `body` at `height`, or `None` if the block mints
/// nothing (`coinbase == 0` — genesis, and synthetic bodies in tests).
///
/// A block with `coinbase > 0` and no payee never reaches here: `validate_body`
/// rejects it (`BodyError::MissingCoinbasePayee`). The `rkm == [0; 4]` guard is
/// kept anyway so this function cannot mint an unspendable leaf even if it is
/// ever called off that path.
///
/// 🔴 **This is the v4 note. A holder reconstructing its own coinbase must call
/// [`coinbase_note_for`] with the form its chain is keyed under** — v5 derives ρ
/// and rseed under a `:v2` domain carrying the payee index, so the note this
/// returns is not in a v5 chain's tree, has no witness, and cannot be spent. Lab
/// #559 is what that costs: the T2 faucet funded its entire inventory this way
/// and could not pay a single grant.
pub fn coinbase_note(height: u64, body: &BlockBody) -> Option<Note> {
    let (amount, rkm) = body.single_payee_parts()?;
    coinbase_note_parts(
        height,
        rkm,
        amount,
        body.total_fees(),
        body.total_name_burn(),
    )
}

/// [`coinbase_note`] over the five block facts the note is a function of — the
/// derivation a holder who is **not a node** runs (lab #415).
///
/// `qumbra-wallet` calls exactly this on the `(height, coinbase_rkm, coinbase,
/// fees, name_burn)` tuples `GET /v1/coinbase` serves, so the note a wallet
/// reconstructs is the note `apply_state` appended, by construction rather than
/// by two implementations agreeing. Same `None` cases as [`coinbase_note`], and
/// they are the same two lines: a block that mints nothing, or one with no payee.
pub fn coinbase_note_parts(
    height: u64,
    rkm: [u64; 4],
    coinbase: u64,
    total_fees: u64,
    total_name_burn: u64,
) -> Option<Note> {
    if coinbase == 0 || rkm == [0u64; 4] {
        return None;
    }
    Some(Note {
        value: coinbase_note_value_parts(coinbase, total_fees, total_name_burn),
        rkm,
        rho: coinbase_rho(height, &rkm),
        rseed: coinbase_rseed(height, &rkm),
    })
}

/// The **v5-form** coinbase note (lab #470 stage 2): identical VALUE arithmetic
/// to [`coinbase_note_parts`] — literally the same
/// [`coinbase_note_value_parts`] call, which is the provable-equivalence
/// requirement of the payout-axis ruling ("the single-payee v5 block's
/// semantics must be provably equivalent to today's single-rkm payout") — with
/// the v5 ρ/rseed derivations, which carry the payee index. `None` cases
/// unchanged.
pub fn coinbase_note_parts_v5(
    height: u64,
    payee_index: u8,
    rkm: [u64; 4],
    coinbase: u64,
    total_fees: u64,
    total_name_burn: u64,
) -> Option<Note> {
    if coinbase == 0 || rkm == [0u64; 4] {
        return None;
    }
    Some(Note {
        value: coinbase_note_value_parts(coinbase, total_fees, total_name_burn),
        rkm,
        rho: coinbase_rho_v5(height, payee_index, &rkm),
        rseed: coinbase_rseed_v5(height, payee_index, &rkm),
    })
}

/// The commitment-tree leaf for `body`'s coinbase note at `height` — the real
/// `note_commitment`, on-wire lane-major bytes, ready for
/// `CommitmentStore::append`. `None` exactly when [`coinbase_note`] is `None`.
///
/// **This is the leaf `height` *mints*, not the leaf `height` *appends*.** Since
/// issue #102 those are different heights: see [`matures_coinbase_minted_at`].
///
/// 🔴 The **v4** leaf — see [`coinbase_note`]'s warning and use
/// [`coinbase_note_leaf_for`] off the v4 path.
pub fn coinbase_note_leaf(height: u64, body: &BlockBody) -> Option<Hash32> {
    coinbase_note(height, body).map(|n| digest_bytes(&n.commitment()))
}

/// The single payee a v5 body pays: the birth cap is 1, so the payee index of
/// the selected payee's `rkm` is 0 wherever a v5 coinbase note is derived (lab #470).
///
/// Named because it is the one number that has to be the same in the node's
/// append path and in every holder's reconstruction — a literal `0` in two files
/// is the shape lab #559 was.
pub const V5_SINGLE_PAYEE_INDEX: u8 = 0;

/// [`coinbase_note`] under an explicit genesis form — **the derivation a holder
/// runs** (lab #559).
///
/// This exists because [`coinbase_note_leaf_for`] did not have a note
/// counterpart, so a holder wanting the note itself had only the v4
/// [`coinbase_note`] to call. `qumbra-faucet`'s harvest called exactly that, and
/// on the v5 net it funded every note with a v4 ρ/rseed: same value, different
/// commitment, no leaf in the tree, no witness, no spend — an inventory of value
/// it could never move. The faucet page reported it as a maturity wait that
/// nothing would clear.
///
/// So the form-aware note is the primitive and the leaf is derived **from it**
/// below, rather than the two being computed side by side. There is one
/// derivation per form and the leaf cannot drift from the note again.
///
/// This is the `&BlockBody` face of [`coinbase_note_parts_for`], which is where
/// the `match form` actually lives — a holder that has the block reads this one,
/// a holder that has only the five served facts reads that one, and neither is a
/// second dispatch to keep in step (lab #566).
pub fn coinbase_note_for(
    form: qlab_devnet::forms::GenesisForm,
    height: u64,
    body: &BlockBody,
) -> Option<Note> {
    let (amount, rkm) = body.single_payee_parts()?;
    coinbase_note_parts_for(
        form,
        height,
        rkm,
        amount,
        body.total_fees(),
        body.total_name_burn(),
    )
}

/// [`coinbase_note_parts`] under an explicit genesis form — **the derivation a
/// holder who is not a node runs** (lab #566), and the ONE `match form` for the
/// coinbase note in this tree.
///
/// ## Why this shape exists and the `&BlockBody` one was not enough
///
/// [`coinbase_note_for`] takes the block. A wallet does not have the block and
/// never will: the compact wire carries no `coinbase_rkm`, so a wallet reads the
/// five facts off `GET /v1/coinbase` ([`qlab_cbserver::codec::BlockCoinbase`])
/// and holds nothing else about that height. With no parts-level dispatcher its
/// only reachable derivation was the **v4** [`coinbase_note_parts`], which is
/// exactly what `qumbra-wallet` called — on a v5 chain that is a commitment in
/// no tree, and lab #566 is the transaction-level witness: 131 matured notes a
/// wallet had mined, none of them in the tree, `send` refusing at the witness
/// lookup rather than proving against the wrong anchor.
///
/// ## The payee index is not the caller's to pass
///
/// It is [`V5_SINGLE_PAYEE_INDEX`] — the birth cap is 1, so the payee index of
/// `coinbase_rkm` is 0 wherever a v5 coinbase note is derived. Taking it as a
/// parameter here would hand every holder a number to get wrong, and a literal
/// `0` in two files is the shape lab #559 was. Raising the cap stays a rule
/// change: it moves this function, not its call sites.
///
/// **No new arithmetic.** Both arms are the functions that already existed and
/// are already tested against each other
/// (`v4_and_v5_agree_on_the_value_and_disagree_on_the_commitment`); this only
/// chooses between them. Writing a third formula here would be the
/// defect lab #566 is about, reproduced in the place that was supposed to fix it.
pub fn coinbase_note_parts_for(
    form: qlab_devnet::forms::GenesisForm,
    height: u64,
    rkm: [u64; 4],
    coinbase: u64,
    total_fees: u64,
    total_name_burn: u64,
) -> Option<Note> {
    match form {
        qlab_devnet::forms::GenesisForm::V4 => {
            coinbase_note_parts(height, rkm, coinbase, total_fees, total_name_burn)
        }
        qlab_devnet::forms::GenesisForm::V5 => coinbase_note_parts_v5(
            height,
            V5_SINGLE_PAYEE_INDEX,
            rkm,
            coinbase,
            total_fees,
            total_name_burn,
        ),
    }
}

/// [`coinbase_note_leaf`] under an explicit genesis form (lab #470 stage 4a):
/// the v5 leaf comes from the v5 note derivation (payee index 0 at the birth
/// cap) — same value arithmetic, v5 lanes.
///
/// The leaf of [`coinbase_note_for`]'s note, since lab #559 — see there.
pub fn coinbase_note_leaf_for(
    form: qlab_devnet::forms::GenesisForm,
    height: u64,
    body: &BlockBody,
) -> Option<Hash32> {
    coinbase_note_for(form, height, body).map(|n| digest_bytes(&n.commitment()))
}

// ---------------------------------------------------------------------------
// The maturity append schedule (issue #102, option (b))
// ---------------------------------------------------------------------------

/// The height whose coinbase note a block at `height` appends to the commitment
/// tree, or `None` when the block is younger than the maturity delay and so
/// matures nothing.
///
/// **This is the single statement of the frozen §2 rule's enforcement.** Before
/// issue #102 the schedule was the identity — a block appended its *own*
/// coinbase leaf — and maturity was a mempool policy check against a submitter's
/// declaration, which was bypassable three separate ways (an honest-but-silent
/// `vec![]`, the hardcoded `vec![]` on the P2P path, and an in-memory registry
/// that is empty after every restart). None of those is a hole any more, because
/// there is nothing left to declare: an immature coinbase note **has no leaf in
/// any anchor this chain will accept**, therefore no membership witness against
/// one, therefore no spend that verifies. That beats `refused-by-policy` because it
/// holds against a submitter who lies, a peer that bypasses the mempool, and a node
/// that just restarted — none of which is being asked anything.
///
/// **Stated that way on purpose, because the short version is false.** "An immature
/// spend is unprovable" is not true in general: an attacker can append the leaf to a
/// tree of their own, take a genuine witness against it, and produce a perfectly
/// valid proof of a true statement about *that* tree — and the production verifier
/// accepts it. `qumbra-node`'s
/// `a_forged_anchor_carrying_a_real_proof_is_rejected_at_the_block_path` does exactly
/// this and asserts the acceptance. What is actually true is narrower and stronger:
/// **their proof is fine and their anchor is the lie**, and the anchor is checked by
/// `validate_body` on every block from every peer, with no mempool involved. Anyone
/// reading "unprovable rather than refused-by-policy" anywhere in this tree should
/// read that test — it is the difference between the slogan and the property.
///
/// Every consumer of the schedule calls this rather than restating `height − 144`:
/// [`crate::node::Node::apply_state`] to append, [`crate::rpc::NodeRpc`]'s anchor
/// reconstruction to count, and `qumbra_faucet::NodeView`'s to do the same for a
/// node that composes no RPC. That third one was a live off-by-144 until the full
/// suite caught it — restating a *sliding* rule is the shape issue #116 was filed
/// about, and #116 named only the first two because it was written about the RPC.
pub fn matures_coinbase_minted_at(height: u64) -> Option<u64> {
    height.checked_sub(crate::emission::COINBASE_MATURITY_BLOCKS)
}

/// The height at whose application the coinbase minted at `minted_height` enters
/// the commitment tree — the inverse of [`matures_coinbase_minted_at`], and the
/// first height whose root can serve as an anchor for spending it.
pub fn coinbase_leaf_appears_at(minted_height: u64) -> u64 {
    minted_height + crate::emission::COINBASE_MATURITY_BLOCKS
}

/// The coinbase leaf a block at `height` appends, given a lookup for the body of
/// its own ancestor at a given height. `None` when the block matures nothing —
/// it is below the delay, its ancestor is unreachable, or that ancestor minted
/// nothing (genesis).
///
/// The `ancestor_body` closure is what keeps this replay-identical: it must
/// resolve heights against **this block's own ancestry**, never against a
/// height-indexed side table, so the answer follows whichever chain the block is
/// on. See `Node::apply_state` for why nothing may be persisted here.
pub fn matured_coinbase_leaf<F>(height: u64, ancestor_body: F) -> Option<Hash32>
where
    F: FnOnce(u64) -> Option<BlockBody>,
{
    matured_coinbase_leaf_for(qlab_devnet::forms::GenesisForm::V4, height, ancestor_body)
}

/// [`matured_coinbase_leaf`] under an explicit genesis form (lab #470 4a).
pub fn matured_coinbase_leaf_for<F>(
    form: qlab_devnet::forms::GenesisForm,
    height: u64,
    ancestor_body: F,
) -> Option<Hash32>
where
    F: FnOnce(u64) -> Option<BlockBody>,
{
    let minted_at = matures_coinbase_minted_at(height)?;
    coinbase_note_leaf_for(form, minted_at, &ancestor_body(minted_at)?)
}

/// Whether a coinbase note minted at a given height has entered the commitment
/// tree yet — and if not, when it will.
///
/// **This type exists because option (b) would otherwise make an immature
/// coinbase indistinguishable from a note that never existed.** Before #102 a
/// holder got `MempoolError::ImmatureCoinbase` — a wrong answer, but a legible
/// one. Under (b) the leaf is simply absent, and "absent" is the same signal a
/// wallet gets for a commitment that was never minted at all. An absence that
/// reads as a healthy empty state is this repository's most-repeated defect
/// (#104, #106, #113, #130, and #102's own fail-open), so the absence is given a
/// reason at the one place a holder can ask.
///
/// Asking costs nothing in privacy, and that is the whole difference from the
/// declaration this replaces. The declaration leaked because it bound a *spend*
/// to a *coinbase*; this names only a block height, which every node already has
/// in plaintext along with the payee's `coinbase_rkm`. Nothing about a spend is
/// stated, or even implied — the question is identical whether or not the asker
/// intends to spend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoinbaseMaturity {
    /// The leaf entered the tree when `leaf_at` was applied, so every root from
    /// that height onward contains it and a membership witness exists. If a
    /// witness still cannot be built, the note genuinely does not exist.
    Matured {
        /// The height whose application appended the leaf.
        leaf_at: u64,
    },
    /// The leaf does not exist yet. Its absence is the maturity rule, not a
    /// missing note, and it will be appended when `leaf_at` is applied.
    Immature {
        /// The height whose application will append the leaf.
        leaf_at: u64,
        /// Blocks the tip must still advance before then.
        blocks_remaining: u64,
    },
}

/// Answer [`CoinbaseMaturity`] for a coinbase minted at `minted_height` against
/// a chain whose tip is `tip_height`. Pure — both inputs are public chain facts.
pub fn coinbase_maturity(minted_height: u64, tip_height: u64) -> CoinbaseMaturity {
    let leaf_at = coinbase_leaf_appears_at(minted_height);
    match leaf_at.checked_sub(tip_height) {
        None | Some(0) => CoinbaseMaturity::Matured { leaf_at },
        Some(blocks_remaining) => CoinbaseMaturity::Immature { leaf_at, blocks_remaining },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::coinbase;
    use qlab_devnet::body::{TxEntry, TxPublic};
    use qlab_devnet::fees::{posted_fee, ArityBucket};

    const RKM_A: [u64; 4] = [0x1111, 0x2222, 0x3333, 0x4444];
    const RKM_B: [u64; 4] = [0x5555, 0x6666, 0x7777, 0x8888];

    fn fee_tx(nf: u8) -> TxEntry {
        TxEntry::with_placeholder_discovery(vec![0u8; 8], TxPublic {
            anchor: [0x0F; 32],
            nullifiers: vec![[nf; 32]],
            commitments: vec![[nf.wrapping_add(1); 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
            })
    }

    fn body_at(height: u64, rkm: [u64; 4], n_txs: u8) -> BlockBody {
        BlockBody::from_single_payee((0..n_txs).map(fee_tx).collect(), coinbase(height), rkm)
    }

    /// The whole point of the module: what it mints is a **real note**, openable
    /// by the 2×2 circuit — not the deleted placeholder digest. Locked against
    /// `qlab_note::note_commitment`, which is itself regression-locked to
    /// `qlab_air::narrow::build_bucket`'s `cm_out`.
    #[test]
    fn the_minted_leaf_is_a_real_note_commitment() {
        let body = body_at(700, RKM_A, 0);
        let note = coinbase_note(700, &body).expect("a minting block mints a note");
        let leaf = coinbase_note_leaf(700, &body).expect("and therefore has a leaf");
        assert_eq!(leaf, digest_bytes(&note.commitment()));
        assert_eq!(
            note.commitment(),
            qlab_note::note::note_commitment(note.value, &note.rkm, &note.rho, &note.rseed),
        );
    }

    /// Pure function of `(height, body)` — the property `open == replay` rests
    /// on. Same inputs, same leaf, every time and on every node.
    #[test]
    fn derivation_is_deterministic() {
        let body = body_at(700, RKM_A, 2);
        assert_eq!(coinbase_note_leaf(700, &body), coinbase_note_leaf(700, &body));
        let same = body_at(700, RKM_A, 2);
        assert_eq!(coinbase_note_leaf(700, &same), coinbase_note_leaf(700, &body));
    }

    /// Height separates notes, and so does the payee. Both matter: height is what
    /// the uniqueness argument rests on within a branch, and `rkm` is what binds
    /// the note (and, through ρ, its nullifier) to who was paid.
    #[test]
    fn height_and_payee_each_separate_the_note() {
        let a = body_at(700, RKM_A, 0);
        let b = body_at(701, RKM_A, 0);
        let c = body_at(700, RKM_B, 0);
        assert_ne!(coinbase_note_leaf(700, &a), coinbase_note_leaf(701, &b), "height separates");
        assert_ne!(coinbase_note_leaf(700, &a), coinbase_note_leaf(700, &c), "payee separates");
        // ρ and rseed are separate derivations under separate domains — a
        // collision between them would silently weaken the note.
        assert_ne!(coinbase_rho(700, &RKM_A), coinbase_rseed(700, &RKM_A));
        assert_ne!(COINBASE_RHO_DOMAIN, COINBASE_RSEED_DOMAIN);
        // Neither domain reuses the tag of the object #101 deleted.
        for d in [COINBASE_RHO_DOMAIN, COINBASE_RSEED_DOMAIN] {
            assert_ne!(d, b"qumbra:devnet:coinbase-note:v1");
        }
    }

    /// The value rule: frozen §3 miner share of the scheduled emission, plus the
    /// block's fees, which are the miner's and never burned.
    #[test]
    fn value_is_the_miner_share_plus_fees() {
        let h = 700;
        let empty = body_at(h, RKM_A, 0);
        assert_eq!(coinbase_note_value(&empty), RewardSplit::of(coinbase(h)).miner);
        let two = body_at(h, RKM_A, 2);
        assert_eq!(
            coinbase_note_value(&two),
            RewardSplit::of(coinbase(h)).miner + 2 * posted_fee(ArityBucket::TwoByTwo),
        );
        // And it is strictly less than the whole emission — the committee and
        // treasury shares are deliberately not minted (module docs).
        assert!(coinbase_note_value(&empty) < coinbase(h));
    }

    /// Lab #367: the burned name-fee portion never enters the coinbase note.
    /// A registering tx declares `posted + name_fee`; the miner collects only
    /// the posted half — and a rider-free body subtracts zero, which is why
    /// the test above did not move.
    #[test]
    fn the_name_burn_never_enters_the_coinbase_note() {
        use qlab_devnet::names::{self, NameOp, NameRecord};
        let h = 700;
        let mut body = body_at(h, RKM_A, 1);
        let op = NameOp::Reveal {
            record: NameRecord {
                kind: names::RECORD_KIND_L1_ADDRESS,
                name: b"alice".to_vec(),
                address: vec![0xAB; names::L1_ADDRESS_LEN],
            },
            salt: [7; 32],
        };
        body.txs[0].rider = names::encode_rider(Some(&op));
        body.txs[0].public.fee = posted_fee(ArityBucket::TwoByTwo) + names::name_fee_bessel(5);
        assert_eq!(body.total_name_burn(), names::name_fee_bessel(5));
        assert_eq!(
            coinbase_note_value(&body),
            RewardSplit::of(coinbase(h)).miner + posted_fee(ArityBucket::TwoByTwo),
            "the miner's take is exactly what a rider-free tx would have paid"
        );
    }

    /// 🔴 **One derivation per form, and the leaf is the note's own commitment**
    /// (lab #559). The form-aware leaf used to be computed beside the form-aware
    /// note instead of from it, and the note had no form-aware constructor at all —
    /// which is how `qumbra-faucet` came to fund an entire v5 inventory under the v4
    /// ρ/rseed: 268 notes held on T2, none of them a leaf of the tree, none
    /// spendable, and a page reporting it as a maturity wait.
    #[test]
    fn the_form_aware_leaf_is_the_form_aware_notes_own_commitment() {
        use qlab_devnet::forms::GenesisForm;
        let body = body_at(700, RKM_A, 2);
        for form in [GenesisForm::V4, GenesisForm::V5] {
            let note = coinbase_note_for(form, 700, &body).expect("a minting block");
            assert_eq!(
                coinbase_note_leaf_for(form, 700, &body),
                Some(digest_bytes(&note.commitment())),
                "{form:?}: the leaf must be this form's note, not a second formula"
            );
        }
    }

    /// 🔴 **The two forms are different notes of the same money**, and that is why
    /// deriving under the wrong one is unrecoverable rather than approximate: the
    /// value is identical (the payout-axis ruling's provable-equivalence
    /// requirement), the commitment is not — `:v2` domain plus the payee index in
    /// the preimage. A holder on the wrong form holds notes the tree never had.
    #[test]
    fn v4_and_v5_agree_on_the_value_and_disagree_on_the_commitment() {
        use qlab_devnet::forms::GenesisForm;
        let body = body_at(700, RKM_A, 2);
        let v4 = coinbase_note_for(GenesisForm::V4, 700, &body).expect("mints");
        let v5 = coinbase_note_for(GenesisForm::V5, 700, &body).expect("mints");
        assert_eq!(v4.value, v5.value, "the money is the same in both forms");
        assert_ne!(v4.rho, v5.rho, "v5 ρ carries the payee index under a :v2 domain");
        assert_ne!(v4.rseed, v5.rseed);
        assert_ne!(
            v4.commitment(),
            v5.commitment(),
            "so a v4-derived note is not a leaf of a v5 chain's tree"
        );
    }

    /// 🔴 **The holder's property, for BOTH forms: the five facts `/v1/coinbase`
    /// serves reconstruct the note the applier appended, and its leaf.**
    ///
    /// This is the invariant lab #566 broke and the one that had no test.
    /// `qlab-node`'s own coverage checked `coinbase_note_for` (the block face) and
    /// v4-vs-v5 separation, and `rpc.rs` checked the served facts on a **v4**
    /// chain only — so nothing anywhere asserted that the *parts* face and the
    /// *body* face agree under a given form. That is exactly the seam a wallet
    /// sits on: it has the five scalars and never the block.
    ///
    /// Both directions are asserted per form, which is what makes it a check and
    /// not a restatement: within a form the two faces agree, and across forms the
    /// same five facts give different commitments. A `coinbase_note_parts_for`
    /// that ignored its `form` argument would pass the first and fail the second.
    #[test]
    fn the_served_five_facts_reconstruct_the_appended_note_under_either_form() {
        use qlab_devnet::forms::GenesisForm;
        let body = body_at(700, RKM_A, 2);
        // The five facts, exactly as `coinbase_page` projects them off the block.
        let (cb, rkm) = body.single_payee_parts().expect("current-cap fixture");
        let (h, fees, burn) = (700u64, body.total_fees(), body.total_name_burn());
        for form in [GenesisForm::V4, GenesisForm::V5] {
            let from_parts =
                coinbase_note_parts_for(form, h, rkm, cb, fees, burn).expect("mints");
            let from_body = coinbase_note_for(form, h, &body).expect("mints");
            assert_eq!(
                from_parts, from_body,
                "{form:?}: a holder with the served facts must derive the applier's own note"
            );
            assert_eq!(
                digest_bytes(&from_parts.commitment()),
                coinbase_note_leaf_for(form, h, &body).expect("mints"),
                "{form:?}: …and therefore the leaf the tree actually got"
            );
        }
        // Across forms the same facts are different notes — so the dispatch is
        // load-bearing and not decoration.
        assert_ne!(
            coinbase_note_parts_for(GenesisForm::V4, h, rkm, cb, fees, burn)
                .expect("mints")
                .commitment(),
            coinbase_note_parts_for(GenesisForm::V5, h, rkm, cb, fees, burn)
                .expect("mints")
                .commitment(),
            "a form-blind dispatcher would make these equal and every holder on the \
             other net unspendable"
        );
    }

    /// A block that mints nothing mints no note — this is what exempts genesis,
    /// which carries `coinbase == 0`. And a payee-less body cannot produce a leaf
    /// even if this function is reached off the validation path.
    #[test]
    fn no_mint_and_no_payee_yield_no_note() {
        let genesis = BlockBody::default();
        assert_eq!(coinbase_note(0, &genesis), None);
        assert_eq!(coinbase_note_leaf(0, &genesis), None);
        let payeeless = BlockBody::from_single_payee(Vec::new(), 5_000, [0; 4]);
        assert_eq!(coinbase_note(1, &payeeless), None);
    }

    /// The sibling-fork collision, pinned as a *known* property rather than left
    /// to be rediscovered. Two blocks at the same height paying the same miner
    /// with different fee totals: **different commitments, same nullifier**,
    /// because `nf = Keccak(nk ‖ ρ)` binds neither value nor rseed. Harmless —
    /// only one branch is canonical — but the ratified "exactly one coinbase per
    /// height" is not the claim that holds; "per height per branch" is.
    #[test]
    fn siblings_at_one_height_share_rho_and_therefore_a_nullifier() {
        let lean = body_at(700, RKM_A, 0);
        let fat = body_at(700, RKM_A, 3);
        let a = coinbase_note(700, &lean).unwrap();
        let b = coinbase_note(700, &fat).unwrap();
        assert_ne!(a.value, b.value, "different fee totals");
        assert_ne!(a.commitment(), b.commitment(), "so the leaves differ");
        // …but ρ is identical, and the nullifier is a function of (nk, ρ) alone.
        assert_eq!(a.rho, b.rho, "same height + same payee ⇒ same ρ");
        assert_eq!(a.rseed, b.rseed);
    }

    // ── the v5 form (lab #470 stage 2, C1) ──────────────────────────────────

    /// The payout-axis ruling's provable-equivalence requirement, proven at
    /// the value: a v5 single-payee note carries EXACTLY the value the v4
    /// derivation pays for the same block facts — same miner share, same
    /// fees, same burn — because both call the one `coinbase_note_value_parts`.
    #[test]
    fn v5_note_value_is_byte_equal_to_v4s() {
        let (h, rkm, cb, fees, burn) = (7u64, [3u64, 1, 4, 1], 5_000_000_000u64, 123u64, 45u64);
        let v4 = coinbase_note_parts(h, rkm, cb, fees, burn).unwrap();
        let v5 = coinbase_note_parts_v5(h, 0, rkm, cb, fees, burn).unwrap();
        assert_eq!(v4.value, v5.value, "the equivalence the ruling requires");
        assert_eq!(v4.rkm, v5.rkm);
        // …while the lane derivations are deliberately domain-separated:
        assert_ne!(v4.rho, v5.rho, "v5 ρ is a different domain + carries the index");
        assert_ne!(v4.rseed, v5.rseed);
    }

    /// The coordinator's stage-2 condition: the payee INDEX is in the v5
    /// format now — two payees sharing one rkm at one height derive distinct
    /// ρ and rseed, so the cap raise stays a rule change forever.
    #[test]
    fn v5_payee_index_separates_same_rkm_same_height() {
        let rkm = [9u64, 9, 9, 9];
        assert_ne!(coinbase_rho_v5(50, 0, &rkm), coinbase_rho_v5(50, 1, &rkm));
        assert_ne!(coinbase_rseed_v5(50, 0, &rkm), coinbase_rseed_v5(50, 1, &rkm));
        // And the index does not bleed across heights or keys.
        assert_ne!(coinbase_rho_v5(50, 0, &rkm), coinbase_rho_v5(51, 0, &rkm));
        assert_ne!(coinbase_rho_v5(50, 0, &rkm), coinbase_rho_v5(50, 0, &[9, 9, 9, 8]));
    }

    #[test]
    fn v5_none_cases_match_v4s() {
        // Mints nothing / names nobody — the same two refusals, both forms.
        assert!(coinbase_note_parts_v5(7, 0, [1, 2, 3, 4], 0, 5, 0).is_none());
        assert!(coinbase_note_parts_v5(7, 0, [0, 0, 0, 0], 100, 5, 0).is_none());
    }
}
