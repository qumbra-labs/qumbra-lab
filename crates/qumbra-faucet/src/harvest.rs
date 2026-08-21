//! Where the faucet's money comes from, and where the frozen §2 maturity gate is
//! honoured.
//!
//! Since issue #101 a mined coinbase note is a real note with a real tree leaf, and
//! `qlab_node::coinbase_note_for(form, height, body)` re-derives it **from chain data
//! alone** — that is the deterministic ρ/rseed rule's whole purpose. So the faucet's
//! funding needs no side channel: it walks its own node's main chain, and every block
//! whose `coinbase_rkm` is the faucet's own `rkm` is one note it owns.
//!
//! **`form` is not decoration** (lab #559). v5 derives ρ and rseed under a `:v2`
//! domain with the payee index in the preimage, so the v4 and v5 notes of one block
//! carry the same value and different commitments. The form comes from the node whose
//! chain is being walked, because that is the form its `apply_state` appended leaves
//! under; deriving under any other one funds notes that have no leaf, and a note with
//! no leaf has no witness and cannot be spent — at any height, by any wait.
//!
//! ## The maturity delay, and what this file still owes it
//!
//! `COINBASE_MATURITY_BLOCKS` = 144 (frozen §2) delays spending fresh coinbase.
//!
//! **Issue #102 changed who enforces this, and this module got smaller as a
//! result.** It used to carry the *only* live enforcement of the frozen rule in the
//! tree. The mempool's gate needed a submitter-supplied declaration of the coinbase
//! notes a transaction spent, and both submission seams hardcoded an empty one
//! (`NodeRpc::submit_tx` and `NodeAdapter::ingest_tx` each passed `vec![]`), so the
//! gate was unreachable from the wallet RPC *and* from the wire — the finding this
//! crate's baton reported as "#102 is one seam wider than #102 records". The faucet
//! therefore applied the threshold itself, at the funding boundary, because it was
//! the one place that knew a note's minted height.
//!
//! That declaration is now deleted, and with it the leak that condemned it: naming
//! the coinbase notes a transaction spends links the spend to the coinbase, on a
//! chain whose whole privacy claim is one global shielded pool with no transparent
//! tier. Maturity is enforced by the commitment tree instead — the coinbase leaf is
//! appended 144 blocks late, so an immature note has no leaf, no membership witness,
//! and no provable spend. It binds a lying submitter, a peer bypassing the mempool,
//! and a restarted node identically, none of which the declaration did.
//!
//! **What remains here is economics, not enforcement.** A grant proof costs a
//! measured ~2.3 s and a slot and a fee, so the faucet still checks
//! [`spendable_at_tip`] before funding a note into the inventory — not because an
//! immature spend would be *admitted* (it cannot be built), but because building one
//! and failing would burn the proving time and tell the operator nothing. The
//! refusal carries a height (qumbra-faucet §6.2).
//!
//! The threshold is no longer a duplicated constant either: [`spendable_at_tip`]
//! delegates to [`qlab_node::coinbase_leaf_appears_at`], the same function the append
//! schedule uses, so there is one statement of the rule and this file quotes it.

use std::collections::HashSet;

use qlab_faucet::{Faucet, OwnedNote};
use qlab_node::{coinbase_note_for, coinbase_note_leaf_for, ChainStore, MemNode, NodeState};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;
// `NodeState::is_spent` is the chain's authority on spent-ness (lab #310).

/// The earliest tip height at which a coinbase note minted at `minted_height` can
/// be spent — now the height at which its leaf enters the commitment tree.
///
/// **This moved by one block at issue #102, and the reconciliation is deliberate
/// rather than an edit to match new behaviour.** It used to return
/// `minted + 144 − 1`, derived from the mempool policy gate: `Mempool::admit`
/// admitted when `prospective_height ≥ minted + 144` and `prospective_height` is
/// `tip + 1`, so `tip ≥ minted + 143` sufficed. That gate is gone. What binds now
/// is that the leaf is appended while applying block `minted + 144`
/// ([`qlab_node::coinbase_leaf_appears_at`]), and no earlier root contains it — so
/// the tip must actually *reach* `minted + 144`. One block later, and it is the
/// real constraint rather than a restatement of a removed one.
///
/// **It is a lower bound, not a sufficient condition.** A spend also needs an
/// anchor, and `Node::is_valid_anchor` requires the anchor's height to be
/// *finalized* (and within `MAX_ANCHOR_AGE_BLOCKS`). So the true earliest spend is
/// when finality covers `minted + 144`, which lags the tip by up to a checkpoint
/// cadence. The faucet does not need the exact moment — it needs never to prove
/// against a leaf that cannot exist — so it waits for this height and then lets the
/// anchor check speak for itself. A caller that wants the sufficient condition must
/// consult `finalized_height`, not this function.
pub fn spendable_at_tip(minted_height: u64) -> u64 {
    qlab_node::coinbase_leaf_appears_at(minted_height)
}

/// What one harvest pass did, and what it is still waiting for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HarvestReport {
    /// Notes funded into the faucet by this pass (matured since the last one).
    pub funded: usize,
    /// Matured coinbase notes whose nullifiers are already on-chain, so they were
    /// **not** funded (lab issue #310). A restarted process re-walks the chain with
    /// an empty `seen` set; without this subtraction it re-includes notes it has
    /// already spent, and every later dispense double-spends until the retry budget
    /// burns.
    pub skipped_spent: usize,
    /// Coinbase notes this node has mined that are **not yet mature**, so are not
    /// yet in the inventory. This is the `notes_maturing` the status page shows.
    pub maturing: usize,
    /// The **tip height** at which the earliest outstanding immature note becomes
    /// spendable ([`spendable_at_tip`]), if any is outstanding. This is the number the
    /// whole "why can I not have funds yet" answer is built from, and it is the fact
    /// `qlab-faucet` structurally cannot compute (see the module docs).
    pub next_maturity: Option<u64>,
}

/// Walk `node`'s main chain, fund every **matured, unspent** coinbase note paid to
/// this wallet at `d` that the faucet does not already know about, and report what
/// is still maturing.
///
/// `seen` is the set of coinbase-note commitments already funded (or already known
/// spent); it is the caller's, so a restarted process that has re-derived its
/// inventory does not double-count. Funding twice would put two `OwnedNote`s with
/// the same `cm` in the inventory, and `select_pair` would happily choose both —
/// a self-inflicted double-spend attempt that the node's nullifier set would refuse
/// and that would cost a proof to discover.
///
/// **Spent notes are subtracted, not re-funded (lab issue #310).** A restart
/// begins with an empty `seen` and re-walks every matured coinbase paying this
/// `rkm`. Notes whose nullifiers are already in the consensus set are marked
/// `seen` and counted in [`HarvestReport::skipped_spent`], never funded: the chain
/// is the authority on spent-ness, and the wallet derives the nullifier the same
/// way a spend does (`Wallet::nullifier` over ρ). Without this check the inventory
/// re-includes already-spent notes, every dispense double-spends, and the retry
/// budget burns while the page still says ready.
///
/// O(tip) per call: it re-walks the chain. That is deliberate at lab scale and it is
/// the honest cost of having no per-height note index; a T1-scale faucet would keep
/// a cursor. Called on the node loop's tick, so the loop pays it — see
/// `qumbra_node::run::RunningNode::run_until_with`.
pub fn harvest_matured(
    faucet: &mut Faucet,
    node: &MemNode,
    wallet: &Wallet,
    d: Diversifier,
    seen: &mut HashSet<[u8; 32]>,
) -> HarvestReport {
    let mine = wallet.rkm(d);
    let tip = node.tip_height();
    // 🔴 **The form this node's identities are keyed under, read from the node**
    // (lab #559). It is not a parameter and not a constant here: `apply_state`
    // appends `matured_coinbase_leaf_for(self.form, …)`, so a holder deriving the
    // same note under any other form computes a commitment the tree does not
    // contain. On T2 (v5) that was every note this faucet ever funded — value it
    // held, counted, and could never witness or spend.
    let form = node.form();
    let chain = node.chain();
    let mut report = HarvestReport::default();

    for hash in chain.chain().main_chain() {
        let Some(block) = chain.block(&hash) else { continue };
        let height = block.header.height;
        let body = block.body();
        if body.coinbase_rkm != mine {
            continue; // someone else's block, or an unconfigured burn payout
        }
        let Some(leaf) = coinbase_note_leaf_for(form, height, &body) else {
            continue; // a non-minting block (genesis)
        };
        if seen.contains(&leaf) {
            continue;
        }
        // The frozen §2 delay. No longer a gate this code has to *impose* — since
        // issue #102 an immature coinbase has no tree leaf, so a grant built on one
        // could not be proved even if the faucet tried. What remains here is the
        // faucet declining to waste ~2.3 s of proving on a note it can see is not
        // spendable yet, and reporting a height instead (qumbra-faucet §6.2).
        let at = spendable_at_tip(height);
        if tip < at {
            report.maturing += 1;
            report.next_maturity = Some(report.next_maturity.map_or(at, |m: u64| m.min(at)));
            continue;
        }
        let Some(note) = coinbase_note_for(form, height, &body) else { continue };
        // Lab #310: the chain knows which notes are spent. Derive the nullifier
        // the way a spend does, and skip any whose nf is already permanent.
        let nf = qlab_note::hash::digest_bytes(&wallet.nullifier(&note.rho));
        if node.is_spent(&nf) {
            seen.insert(leaf);
            report.skipped_spent += 1;
            continue;
        }
        faucet.fund(OwnedNote::from_coinbase(wallet, note.value, note.rho, note.rseed, d, height));
        seen.insert(leaf);
        report.funded += 1;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
    use qlab_devnet::header::BlockHeader;
    use qlab_devnet::params_devnet::GENESIS_DIFFICULTY;
    use qlab_faucet::{FaucetConfig, FaucetLimits, TicketPolicy, TicketSecret};
    use qlab_devnet::forms::GenesisForm;
    use qlab_node::{coinbase, genesis_block, CommitmentStore, COINBASE_MATURITY_BLOCKS};

    struct NoTx;
    impl TxVerifier for NoTx {
        fn verify_tx(&self, _: &TxEntry) -> bool {
            unreachable!("fixture blocks carry no transactions")
        }
    }

    fn faucet_for(wallet: &Wallet) -> Faucet {
        Faucet::new(
            wallet.clone(),
            Diversifier::default(),
            TicketSecret::from_bytes([0x33; 32]),
            FaucetConfig {
                limits: FaucetLimits {
                    ticket_policy: TicketPolicy::Disabled,
                    ..FaucetLimits::unlimited()
                },
                ..FaucetConfig::default()
            },
        )
    }

    /// Mine `n` blocks paying `rkm`, finalizing each so anchors exist.
    fn mine(node: &mut MemNode, tip: &mut BlockHeader, n: u64, rkm: [u64; 4]) {
        for _ in 0..n {
            let height = tip.height + 1;
            let body = BlockBody { txs: Vec::new(), coinbase: coinbase(height), coinbase_rkm: rkm };
            let header =
                BlockHeader::child_of(tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
            let hash = node.apply_block(header, body, &NoTx).expect("applies");
            node.finalize(hash).expect("finalize");
            *tip = header;
        }
    }

    /// Mine `n` blocks on a **v5** chain paying `rkm`, finalizing each. The v4
    /// helper above cannot be reused: v5 has its own header layout, its own body
    /// commitment and the exact emission from height 0 (`GenesisForm::V5`).
    fn mine_v5(node: &mut MemNode, tip: &mut BlockHeader, n: u64, rkm: [u64; 4]) {
        for _ in 0..n {
            let height = tip.height + 1;
            let body = BlockBody {
                txs: Vec::new(),
                coinbase: qlab_node::coinbase_for(GenesisForm::V5, height),
                coinbase_rkm: rkm,
            };
            let header = BlockHeader::child_of_for(
                GenesisForm::V5,
                tip,
                height * 75,
                GENESIS_DIFFICULTY,
                body.commitment_v5(),
            );
            let hash = node.apply_block(header, body, &NoTx).expect("applies");
            node.finalize(hash).expect("finalize");
            *tip = header;
        }
    }

    /// 🔴 **A harvested note's commitment must be the leaf the node appended — on
    /// the net the faucet is actually deployed to.**
    ///
    /// Every other test in this module runs on `GenesisForm::V4`, which is why this
    /// property has never been checked where it can fail. `apply_state` appends
    /// `matured_coinbase_leaf_for(self.form, …)`, and v5's ρ/rseed derivations carry
    /// the payee index under a `:v2` domain string — so on a v5 net the v4
    /// derivation this module calls produces a commitment that is not in the tree.
    /// The note is funded, counted as held, and can never be witnessed or spent.
    #[test]
    fn a_v5_chains_harvested_note_is_the_leaf_the_node_appended() {
        let wallet = Wallet::from_seed_lanes([0x1230_0000_0000_0007; 4]);
        let d = Diversifier::default();
        let genesis = qlab_node::genesis_block_for(GenesisForm::V5, GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory_for(GenesisForm::V5, genesis.clone());
        let mut tip = genesis.header();
        let mut faucet = faucet_for(&wallet);
        let mut seen = HashSet::new();

        // Block 1 pays the faucet; grow to the height its leaf is appended at.
        mine_v5(&mut node, &mut tip, 1, wallet.rkm(d));
        let at = spendable_at_tip(1);
        let to_mine = at - node.tip_height();
        mine_v5(&mut node, &mut tip, to_mine, [0xBB; 4]);
        assert_eq!(node.tip_height(), at);

        let report = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(report.funded, 1, "the matured coinbase is funded: {report:?}");

        let note = &faucet.inventory().notes()[0];
        assert!(
            node.commitments().tree().position_of(&note.cm).is_some(),
            "the funded note's commitment is not a leaf of the v5 chain's tree — it \
             can never be witnessed, so the faucet holds value it can never spend"
        );

        // …and the end the operator reads: the page says **ready**, not a maturity
        // height that nothing clears. This is the assertion the live T2 page failed
        // for its whole life (lab #559): 268 notes held, `grants confirmed 0`.
        let view = crate::view::NodeView(&node);
        let availability = crate::state::classify(&faucet, &view, report.next_maturity, 0);
        assert!(
            matches!(availability, crate::state::Availability::Ready { grants } if grants >= 1),
            "a v5 faucet holding a matured, witnessable note must be servable, got \
             {availability:?}"
        );
    }

    /// 🔴 The gate: an immature note is counted and named, never funded. One block
    /// later it is funded exactly once.
    #[test]
    fn a_coinbase_note_is_funded_at_maturity_and_not_one_block_before() {
        let wallet = Wallet::from_seed_lanes([0x1230_0000_0000_0001; 4]);
        let d = Diversifier::default();
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        let mut faucet = faucet_for(&wallet);
        let mut seen = HashSet::new();

        // Block 1 pays the faucet; nothing else does. Grow to one block SHORT of
        // the threshold.
        mine(&mut node, &mut tip, 1, wallet.rkm(d));
        let target = spendable_at_tip(1);
        mine(&mut node, &mut tip, target - 1 - 1, [0xBB; 4]);
        assert_eq!(node.tip_height(), target - 1);

        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r.funded, 0, "one block short of maturity, nothing is funded");
        assert_eq!(r.maturing, 1);
        assert_eq!(r.next_maturity, Some(target), "and the height it changes at is reported");
        assert_eq!(faucet.inventory().len(), 0);

        // One more block and the prospective spend reaches maturity exactly.
        mine(&mut node, &mut tip, 1, [0xBB; 4]);
        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r.funded, 1, "at maturity the note is funded");
        assert_eq!(r.maturing, 0);
        assert_eq!(r.next_maturity, None);
        assert_eq!(faucet.inventory().len(), 1);

        // …and only once, however many times the pass runs.
        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r.funded, 0, "a second pass must not fund the same note again");
        assert_eq!(faucet.inventory().len(), 1);
    }

    /// The harvested note is the one the node actually appended: its commitment is
    /// a leaf of the live tree, and the declaration it carries is that leaf. If this
    /// drifts, the faucet builds witnesses that fold to nothing.
    #[test]
    fn the_harvested_note_is_the_leaf_the_node_appended() {
        let wallet = Wallet::from_seed_lanes([0x1230_0000_0000_0002; 4]);
        let d = Diversifier::default();
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        let mut faucet = faucet_for(&wallet);
        let mut seen = HashSet::new();

        mine(&mut node, &mut tip, 2, wallet.rkm(d));
        mine(&mut node, &mut tip, COINBASE_MATURITY_BLOCKS + 1, [0xCC; 4]);
        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r.funded, 2, "both matured notes funded");

        let tree = node.commitments().tree();
        for note in faucet.inventory().notes() {
            assert!(
                tree.position_of(&note.cm).is_some(),
                "a harvested note must be a leaf of the live tree"
            );
            // A harvested note carries the height it was minted at, not a declaration
            // of its commitment (issue #102) — the height is what maturity is a
            // function of, and it is what lets the holder ask why a leaf is missing.
            let minted_at =
                note.coinbase_minted_at.expect("a harvested note records its minted height");
            assert_eq!(
                qlab_node::coinbase_maturity(minted_at, node.tip_height()),
                qlab_node::CoinbaseMaturity::Matured {
                    leaf_at: qlab_node::coinbase_leaf_appears_at(minted_at)
                },
                "the faucet only funds notes whose leaf has actually landed"
            );
        }
    }

    /// 🔴 **The funding threshold is the append schedule's own threshold**, asserted
    /// against the commitment tree itself rather than against a restatement of it.
    ///
    /// **This replaces `the_funding_threshold_is_the_mempools_own`, and the thing it
    /// checks against changed because the enforcement did.** That test asserted the
    /// mempool refused with `ImmatureCoinbase` one block below the threshold and only
    /// `ProofInvalid` at it — a real cross-check against the gate that existed, but
    /// that gate was reachable only because the test called `Mempool::admit` directly
    /// and passed the declaration by hand. Production passed `vec![]` on both seams,
    /// so what this test pinned was never what a node did.
    ///
    /// The check that survives the change is stronger: at `spendable_at_tip` the note
    /// **has a tree leaf**, and one block earlier it **has none**. That is the
    /// property a spend actually depends on, it is the same one a peer bypassing the
    /// mempool is bound by, and it cannot be satisfied by declaring anything.
    ///
    /// The one-block move is deliberate — see [`spendable_at_tip`].
    #[test]
    fn the_funding_threshold_is_the_append_schedules_own() {
        let miner = Wallet::from_seed_lanes([0x1230_0000_0000_0005; 4]);
        let d = Diversifier::default();
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();

        mine(&mut node, &mut tip, 1, miner.rkm(d));
        let minted_at = 1u64;
        let body = BlockBody {
            txs: Vec::new(),
            coinbase: coinbase(minted_at),
            coinbase_rkm: miner.rkm(d),
        };
        let cb = coinbase_note_leaf_for(GenesisForm::V4, minted_at, &body)
            .expect("a minting block");
        let cm = qlab_note::hash::digest_from_bytes(&cb);

        // The threshold this module funds at is the append schedule's, not a copy.
        let at = spendable_at_tip(minted_at);
        assert_eq!(at, qlab_node::coinbase_leaf_appears_at(minted_at));

        // One block short: no leaf, so no witness, so nothing to fund.
        let to_mine = at - 1 - node.tip_height();
        mine(&mut node, &mut tip, to_mine, [0xDD; 4]);
        assert_eq!(node.tip_height(), at - 1);
        assert!(
            node.commitments().tree().position_of(&cm).is_none(),
            "one block below spendable_at_tip the leaf must not exist"
        );
        let mut faucet = faucet_for(&miner);
        let mut seen = HashSet::new();
        let early = harvest_matured(&mut faucet, &node, &miner, d, &mut seen);
        assert_eq!(early.funded, 0, "and the harvester funds nothing");
        assert_eq!(early.maturing, 1);
        assert_eq!(early.next_maturity, Some(at), "it reports the height, not a silent wait");

        // At the threshold: the leaf exists, and that is the tip the harvester funds at.
        mine(&mut node, &mut tip, 1, [0xDD; 4]);
        assert_eq!(node.tip_height(), at);
        assert!(
            node.commitments().tree().position_of(&cm).is_some(),
            "at spendable_at_tip the leaf is in the tree"
        );
        assert_eq!(harvest_matured(&mut faucet, &node, &miner, d, &mut seen).funded, 1);
    }

    /// Blocks paying somebody else are not the faucet's money, however tall the
    /// chain gets. The `coinbase_rkm` filter is the whole ownership test — #101's
    /// second acceptance item is that only the payout key derives the minted note.
    #[test]
    fn another_miners_blocks_are_never_harvested() {
        let wallet = Wallet::from_seed_lanes([0x1230_0000_0000_0003; 4]);
        let other = Wallet::from_seed_lanes([0x1230_0000_0000_0004; 4]);
        let d = Diversifier::default();
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();
        let mut faucet = faucet_for(&wallet);
        let mut seen = HashSet::new();

        mine(&mut node, &mut tip, COINBASE_MATURITY_BLOCKS + 4, other.rkm(d));
        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r, HarvestReport::default(), "no notes, none maturing, no next maturity");
        assert_eq!(faucet.inventory().len(), 0);
    }

    /// 🔴 **Lab #310 mechanism 1, proved without a STARK.** A matured coinbase
    /// note whose nullifier is already on-chain must not re-enter the inventory.
    ///
    /// This is the post-restart failure mode: `seen` starts empty, harvest walks
    /// every matured coinbase paying the faucet's rkm, and without the nullifier
    /// check it re-funds notes the process has already spent. The chain is the
    /// authority — we inject the nullifier via a body the node applies (AcceptAll
    /// verifier, no real proof), then re-walk as a restarted process would.
    #[test]
    fn harvest_skips_notes_whose_nullifiers_are_already_on_chain() {
        use qlab_devnet::body::TxPublic;
        use qlab_devnet::fees::ArityBucket;
        use qlab_node::coinbase_note as cb_note;

        struct AcceptAll;
        impl TxVerifier for AcceptAll {
            fn verify_tx(&self, _: &TxEntry) -> bool {
                true
            }
        }

        let wallet = Wallet::from_seed_lanes([0x1230_0000_0000_0310; 4]);
        let d = Diversifier::default();
        let rkm = wallet.rkm(d);
        let genesis = genesis_block(GENESIS_DIFFICULTY, 0);
        let mut node = MemNode::in_memory(genesis.clone());
        let mut tip = genesis.header();

        // Two coinbase notes paying the faucet, matured.
        mine(&mut node, &mut tip, 2, rkm);
        mine(&mut node, &mut tip, COINBASE_MATURITY_BLOCKS + 1, [0xEE; 4]);

        // Derive the nullifier of the height-1 coinbase the way a spend does.
        let body1 = {
            let hash = *node
                .chain()
                .chain()
                .main_chain()
                .iter()
                .find(|h| node.chain().block(h).is_some_and(|b| b.header.height == 1))
                .expect("height 1 on main chain");
            node.chain().block(&hash).expect("block").body().clone()
        };
        let note1 = cb_note(1, &body1).expect("minting body");
        let nf1 = qlab_note::hash::digest_bytes(&wallet.nullifier(&note1.rho));
        assert!(!node.is_spent(&nf1), "precondition: note is not yet spent");

        // Mark it spent by applying a body that carries its nullifier. AcceptAll
        // skips the STARK; apply_state still inserts the nullifier permanently.
        // Anchor against the newest finalized root so validate_body accepts it.
        let anchor = node.commitment_root();
        {
            let height = tip.height + 1;
            let cms = [[0xCD; 32], [0xEF; 32]];
            let fake = TxEntry::with_placeholder_discovery(
                b"ok".to_vec(),
                TxPublic {
                    anchor,
                    nullifiers: vec![nf1, [0xAB; 32]],
                    commitments: cms.to_vec(),
                    bucket: ArityBucket::TwoByTwo,
                    fee: qlab_devnet::fees::posted_fee(ArityBucket::TwoByTwo),
                },
            );
            let body = BlockBody {
                txs: vec![fake],
                coinbase: coinbase(height),
                coinbase_rkm: [0xEE; 4],
            };
            let header =
                BlockHeader::child_of(&tip, height * 75, GENESIS_DIFFICULTY, body.commitment());
            let hash = node.apply_block(header, body, &AcceptAll).expect("applies");
            node.finalize(hash).expect("finalize");
            tip = header;
        }
        assert!(node.is_spent(&nf1), "nullifier is now permanent — the chain says spent");
        let _ = tip;

        // Restart path: empty seen, empty inventory, re-walk the chain.
        let mut faucet = faucet_for(&wallet);
        let mut seen = HashSet::new();
        let r = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(
            r.skipped_spent, 1,
            "the spent coinbase must be counted as skipped, not funded: {r:?}"
        );
        assert_eq!(r.funded, 1, "the unspent sibling is still funded: {r:?}");
        assert_eq!(faucet.inventory().len(), 1, "inventory holds only the live note");
        // And a second pass does not re-count the spent one.
        let r2 = harvest_matured(&mut faucet, &node, &wallet, d, &mut seen);
        assert_eq!(r2.skipped_spent, 0, "seen remembers the spent leaf");
        assert_eq!(r2.funded, 0);
        assert_eq!(faucet.inventory().len(), 1);
    }
}
