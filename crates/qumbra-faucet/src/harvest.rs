//! Where the faucet's money comes from, and where the frozen §2 maturity gate is
//! honoured.
//!
//! Since issue #101 a mined coinbase note is a real note with a real tree leaf, and
//! `qlab_node::coinbase_note(height, body)` re-derives it **from chain data alone**
//! — that is the deterministic ρ/rseed rule's whole purpose. So the faucet's funding
//! needs no side channel: it walks its own node's main chain, and every block whose
//! `coinbase_rkm` is the faucet's own `rkm` is one note it owns.
//!
//! ## The maturity gate, and why it lives here rather than in the core
//!
//! `COINBASE_MATURITY_BLOCKS` = 144 (frozen §2) gates spending fresh coinbase.
//! Enforcing it should be the mempool's job, and it *is* — `Mempool::admit` takes
//! the coinbase notes a transaction declares it spends, and
//! `GrantPlan::spends_coinbase` computes exactly that declaration. But **both**
//! submission seams in this tree hardcode an empty declaration:
//!
//! - `qlab_node::rpc::NodeRpc::submit_tx` → `mempool.admit(tx, vec![], …)`
//! - `qlab_p2p::adapter::NodeAdapter::ingest_tx` → `mempool.admit(tx, vec![], …)`
//!
//! so the gate is unreachable from the wallet RPC *and* from the wire. That is issue
//! #102, and this baton found it is one seam wider than #102 records.
//!
//! Nor can `qlab-faucet` enforce it: `OwnedNote::coinbase_note` carries a note's
//! *commitment* but not the *height* it was minted at, and maturity is a function of
//! the height. Only a funder that watched the block go by knows it.
//!
//! **So the gate is applied at the funding boundary**, at exactly the mempool's own
//! threshold and not one block either side of it. `Mempool::admit` compares the
//! **prospective** height — `tip + 1`, the earliest block a submission can land in —
//! against `minted_height + 144`, so a note is spendable once
//! `tip + 1 ≥ minted_height + 144`, i.e. once the tip reaches
//! [`spendable_at_tip`]`(minted_height)`. `Faucet::fund` is called then and not
//! before. Every note in the inventory is therefore mature by construction, no
//! immature spend is ever built (and a grant proof costs a measured ~2.3 s, so
//! refusing before proving is not a nicety), and nothing rides on a gate that would
//! not have fired.
//!
//! Reproducing the threshold rather than asking the mempool for it is a duplication,
//! and the one test that matters about it asserts the two agree
//! ([`tests::the_funding_threshold_is_the_mempools_own`]).
//!
//! The alternative — submit undeclared, let the immature spend through, because
//! block validation never checks maturity either — would make a browser demo work
//! today by riding #102. It is not taken.

use std::collections::HashSet;

use qlab_faucet::{Faucet, OwnedNote};
use qlab_node::{coinbase_note, coinbase_note_leaf, ChainStore, MemNode, NodeState};
use qlab_wallet::address::Diversifier;
use qlab_wallet::Wallet;

/// The tip height at which a coinbase note minted at `minted_height` becomes
/// spendable — the mempool's frozen §2 threshold, restated in the units the faucet
/// and the status page work in.
///
/// `Mempool::admit` admits when `prospective_height ≥ minted + COINBASE_MATURITY_BLOCKS`
/// and `prospective_height` is `tip + 1`, so the tip must reach
/// `minted + COINBASE_MATURITY_BLOCKS − 1`.
pub fn spendable_at_tip(minted_height: u64) -> u64 {
    minted_height + qlab_node::COINBASE_MATURITY_BLOCKS - 1
}

/// What one harvest pass did, and what it is still waiting for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HarvestReport {
    /// Notes funded into the faucet by this pass (matured since the last one).
    pub funded: usize,
    /// Coinbase notes this node has mined that are **not yet mature**, so are not
    /// yet in the inventory. This is the `notes_maturing` the status page shows.
    pub maturing: usize,
    /// The **tip height** at which the earliest outstanding immature note becomes
    /// spendable ([`spendable_at_tip`]), if any is outstanding. This is the number the
    /// whole "why can I not have funds yet" answer is built from, and it is the fact
    /// `qlab-faucet` structurally cannot compute (see the module docs).
    pub next_maturity: Option<u64>,
}

/// Walk `node`'s main chain, fund every **matured** coinbase note paid to this
/// wallet at `d` that the faucet does not already know about, and report what is
/// still maturing.
///
/// `seen` is the set of coinbase-note commitments already funded (or already spent);
/// it is the caller's, so a restarted process that has re-derived its inventory does
/// not double-count. Funding twice would put two `OwnedNote`s with the same `cm` in
/// the inventory, and `select_pair` would happily choose both — a self-inflicted
/// double-spend attempt that the node's nullifier set would refuse and that would
/// cost a proof to discover.
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
    let chain = node.chain();
    let mut report = HarvestReport::default();

    for hash in chain.chain().main_chain() {
        let Some(block) = chain.block(&hash) else { continue };
        let height = block.header.height;
        let body = block.body();
        if body.coinbase_rkm != mine {
            continue; // someone else's block, or an unconfigured burn payout
        }
        let Some(leaf) = coinbase_note_leaf(height, &body) else {
            continue; // a non-minting block (genesis)
        };
        if seen.contains(&leaf) {
            continue;
        }
        // 🔴 The frozen §2 gate, at the boundary that can see the height.
        let at = spendable_at_tip(height);
        if tip < at {
            report.maturing += 1;
            report.next_maturity = Some(report.next_maturity.map_or(at, |m: u64| m.min(at)));
            continue;
        }
        let Some(note) = coinbase_note(height, &body) else { continue };
        faucet.fund(OwnedNote::from_coinbase(wallet, note.value, note.rho, note.rseed, d, leaf));
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
            let cb = note.coinbase_note.expect("a harvested note declares its coinbase origin");
            assert_eq!(
                cb,
                qlab_note::hash::digest_bytes(&note.cm),
                "the declaration is the leaf itself"
            );
        }
    }

    /// 🔴 **The funding threshold is the mempool's own threshold**, asserted against
    /// `Mempool::admit` itself rather than against a restatement of it.
    ///
    /// This is the test that makes the whole "honour the gate at the funding
    /// boundary" argument checkable: at [`spendable_at_tip`] the mempool's frozen §2
    /// gate no longer refuses the note (only the absent proof does), and one block
    /// earlier it refuses with `ImmatureCoinbase`. If `COINBASE_MATURITY_BLOCKS` or
    /// the mempool's prospective-height rule ever moves, this fails rather than the
    /// faucet quietly funding an immature note.
    #[test]
    fn the_funding_threshold_is_the_mempools_own() {
        use qlab_devnet::fees::{posted_fee, ArityBucket};
        use qlab_devnet::body::TxPublic;
        use qlab_node::{Mempool, MempoolError};

        struct RejectAll;
        impl TxVerifier for RejectAll {
            fn verify_tx(&self, _: &TxEntry) -> bool {
                false
            }
        }

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
        let cb = coinbase_note_leaf(minted_at, &body).expect("a minting block");
        let mut mp = Mempool::default();
        mp.record_coinbase_note(cb, minted_at);

        let candidate = |anchor| TxEntry {
            proof: Vec::new(),
            public: TxPublic {
                anchor,
                nullifiers: vec![[0x51; 32], [0x52; 32]],
                commitments: vec![[0x53; 32], [0x54; 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: posted_fee(ArityBucket::TwoByTwo),
            },
        };

        // One block short of the threshold this module funds at.
        let at = spendable_at_tip(minted_at);
        let to_mine = at - 1 - node.tip_height();
        mine(&mut node, &mut tip, to_mine, [0xDD; 4]);
        assert_eq!(node.tip_height(), at - 1);
        let err = mp
            .admit(candidate(node.commitment_root()), vec![cb], &node, &RejectAll)
            .unwrap_err();
        assert!(
            matches!(err, MempoolError::ImmatureCoinbase { .. }),
            "one block below spendable_at_tip the mempool must still refuse, got {err:?}"
        );

        // At the threshold, the maturity gate no longer refuses — the absent proof
        // does, which is how we know the gate was passed rather than skipped.
        mine(&mut node, &mut tip, 1, [0xDD; 4]);
        assert_eq!(node.tip_height(), at);
        assert_eq!(
            mp.admit(candidate(node.commitment_root()), vec![cb], &node, &RejectAll),
            Err(MempoolError::ProofInvalid),
            "at spendable_at_tip the frozen §2 gate is satisfied"
        );

        // …and that is exactly the tip at which the harvester funds it.
        let mut faucet = faucet_for(&miner);
        let mut seen = HashSet::new();
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
}
