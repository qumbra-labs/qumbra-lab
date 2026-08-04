//! Data source: a `qlab-devnet` chain populated with **real** `qlab-note`
//! encrypted notes. Pre-generated once (deterministic seed), then reused.
//!
//! Composition (honest about what is real vs placeholder):
//! - **Real**: every note is ML-KEM-768-encapsulated + ChaCha20-Poly1305-sealed
//!   by `qlab_note::scan::encrypt_to_recipient`; every `cm`/`tag` is the ratified
//!   wire object; the commitment tree uses qlab-air's consensus node hash.
//! - **Real devnet structure**: blocks are `qlab_devnet` headers chained by
//!   `header_hash`, with `BlockBody`/`TxEntry`/`TxPublic` carrying the real cm
//!   bytes, bound into the header via `BlockBody::commitment()`, inserted into a
//!   real `ChainState`.
//! - **Placeholder**: the STARK proof bytes in each `TxEntry` are opaque. The
//!   compact-block layer serves *note-discovery* artifacts — orthogonal to proof
//!   verification (a full node would verify proofs at block-validation time; the
//!   discovery server serves consensus data verbatim). This is documented, not a
//!   spec gap.
//!
//! A known "our wallet" keypair is planted in a subset of outputs so the scan
//! flow has real matches; the rest go to decoy recipients.

use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
use qlab_devnet::chain::ChainState;
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_note::hash::digest_bytes;
use qlab_note::kem::{generate_keypair, Ek, Keypair};
use qlab_note::note::Note;
use qlab_note::scan::{encrypt_to_recipient, EncryptedOutputs};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::codec::{CompactBlock, CompactGroup};
use crate::tree::CommitmentTree;

/// One recipient bundle's encryption artifacts, stored for serving.
pub struct StoredRecipient {
    pub enc: EncryptedOutputs,
    /// `true` if these outputs were sent to *our* wallet (a planted match).
    pub ours: bool,
}

/// One transaction: its recipient bundles.
pub struct StoredTx {
    pub recipients: Vec<StoredRecipient>,
}

/// One block: the devnet header/body plus the per-tx encryption artifacts.
pub struct StoredBlock {
    pub height: u64,
    pub header: BlockHeader,
    pub body: BlockBody,
    pub txs: Vec<StoredTx>,
}

/// Generation parameters.
#[derive(Clone, Copy)]
pub struct GenParams {
    pub n_blocks: u64,
    pub txs_per_block: u64,
    /// PoW difficulty stamped on each header (fork-choice weight; not mined here).
    pub difficulty: u64,
    pub seed: u64,
}

impl Default for GenParams {
    fn default() -> Self {
        Self { n_blocks: 8, txs_per_block: 6, difficulty: 1_000, seed: 0xC0FFEE }
    }
}

/// The pre-generated devnet + its serving indices.
pub struct Devnet {
    pub blocks: Vec<StoredBlock>,
    pub tree: CommitmentTree,
    pub chain: ChainState,
    /// The wallet the light-client scans for.
    pub our: Keypair,
    /// Cumulative leaf count of the tree at the end of each height (height→count).
    leaves_at_end_of_height: Vec<(u64, u64)>,
    /// Total notes planted to `our` wallet (the expected match count).
    pub expected_matches: usize,
}

fn rand_lane(rng: &mut StdRng) -> [u64; 4] {
    core::array::from_fn(|_| rng.next_u64())
}

fn note(rng: &mut StdRng) -> Note {
    Note {
        value: 1 + (rng.next_u64() % 1_000_000),
        rkm: rand_lane(rng),
        rho: rand_lane(rng),
        rseed: rand_lane(rng),
    }
}

impl Devnet {
    /// Generate a fresh devnet deterministically from `params`.
    pub fn generate(params: GenParams) -> Self {
        let mut rng = StdRng::seed_from_u64(params.seed);

        // Our wallet + a handful of decoy recipients.
        let our = generate_keypair(&mut rng);
        let decoys: Vec<Keypair> = (0..4).map(|_| generate_keypair(&mut rng)).collect();

        let mut tree = CommitmentTree::new();
        let mut blocks = Vec::new();
        let mut leaves_at_end_of_height = Vec::new();
        let mut expected_matches = 0usize;

        let genesis = BlockHeader::genesis(params.difficulty, 0);
        let mut chain = ChainState::new(genesis);
        let mut parent = genesis;

        for height in 1..=params.n_blocks {
            // Anchor = the finalized root as of the start of this block.
            let anchor: Hash32 = digest_bytes(&tree.root());
            let mut stored_txs = Vec::new();
            let mut body_txs = Vec::new();

            for tx_i in 0..params.txs_per_block {
                let mut recipients = Vec::new();
                let mut tx_commitments: Vec<Hash32> = Vec::new();
                let mut tx_nullifiers: Vec<Hash32> = Vec::new();

                // Recipient mix (deterministic, exercises 1-of-1 and 2-of-1):
                //  - tx 0 of every block: 2-of-1 to OUR wallet (a matched 2-of-1).
                //  - tx 1 of every block: 1-of-1 to OUR wallet (a matched 1-of-1).
                //  - other txs: decoys, alternating 2-of-1 and 1-of-1.
                let plan: Vec<(bool, usize)> = match tx_i {
                    0 => vec![(true, 2)],
                    1 => vec![(true, 1)],
                    _ => {
                        let k = if tx_i % 2 == 0 { 2 } else { 1 };
                        vec![(false, k)]
                    }
                };

                for (ours, k) in plan {
                    let ek: &Ek = if ours {
                        &our.ek
                    } else {
                        &decoys[(tx_i as usize) % decoys.len()].ek
                    };
                    let notes: Vec<Note> = (0..k).map(|_| note(&mut rng)).collect();
                    let enc = encrypt_to_recipient(ek, &notes, &mut rng);
                    // Feed the real cm bytes into the tree (append order == wire order).
                    for e in &enc.bundle.entries {
                        tree.append_bytes(&e.cm);
                        tx_commitments.push(e.cm);
                    }
                    // A synthetic nullifier per output (unique — no double-spend).
                    for _ in 0..k {
                        tx_nullifiers.push(digest_bytes(&rand_lane(&mut rng)));
                    }
                    if ours {
                        expected_matches += k;
                    }
                    recipients.push(StoredRecipient { enc, ours });
                }

                let public = TxPublic {
                    anchor,
                    nullifiers: tx_nullifiers,
                    commitments: tx_commitments,
                    bucket: ArityBucket::TwoByTwo,
                    fee: posted_fee(ArityBucket::TwoByTwo),
                };
                // Opaque placeholder proof — the discovery server never opens it.
                let proof = format!("devnet-proof:h{height}:tx{tx_i}").into_bytes();
                // Issue #188: the discovery group is now part of the body, and
                // these bundles are the real ML-KEM/AEAD artifacts, so the
                // generated chain commits to exactly what it serves.
                let bundles: Vec<_> =
                    recipients.iter().map(|r| r.enc.bundle.clone()).collect();
                // Issue #188 (a): the AEAD payloads are COMMITTED now, so the
                // fixture's body carries them in D4 order rather than keeping
                // them only in the served side table.
                let payloads: Vec<Vec<u8>> =
                    recipients.iter().flat_map(|r| r.enc.payloads.clone()).collect();
                body_txs.push(TxEntry::new(proof, public, &bundles, &payloads));
                stored_txs.push(StoredTx { recipients });
            }

            // A synthetic minting block needs a payee (issue #101): a body with
            // `coinbase > 0` and `coinbase_rkm == [0; 4]` is rejected, and this
            // fixture's headers must commit to bodies a node would accept.
            let coinbase_rkm = [height, height ^ 0xA5, height ^ 0x5A, height ^ 0xFF];
            let body = BlockBody { txs: body_txs, coinbase: height, coinbase_rkm };
            let header = BlockHeader::child_of(&parent, height, params.difficulty, body.commitment());
            chain
                .insert_header(header)
                .expect("chained child header inserts cleanly");
            parent = header;

            leaves_at_end_of_height.push((height, tree.len()));
            blocks.push(StoredBlock { height, header, body, txs: stored_txs });
        }

        Devnet {
            blocks,
            tree,
            chain,
            our,
            leaves_at_end_of_height,
            expected_matches,
        }
    }

    /// Assemble a `Devnet` from externally-built REAL blocks/notes — the
    /// composition entry point for a driver (e.g. qlab-demo) that produces its
    /// own Alice→Bob transaction rather than the self-generated `generate` mix.
    /// `leaves_at_end_of_height` is `(height, cumulative_tree_len)` per block in
    /// ascending height (the same invariant `generate` maintains internally).
    /// Additive: existing `generate`/serving behaviour is unchanged.
    pub fn from_parts(
        blocks: Vec<StoredBlock>,
        tree: CommitmentTree,
        chain: ChainState,
        our: Keypair,
        expected_matches: usize,
        leaves_at_end_of_height: Vec<(u64, u64)>,
    ) -> Self {
        Devnet { blocks, tree, chain, our, leaves_at_end_of_height, expected_matches }
    }

    /// The block stored at `height` (heights are 1..=n_blocks; genesis is 0).
    pub fn block(&self, height: u64) -> Option<&StoredBlock> {
        if height == 0 || height as usize > self.blocks.len() {
            return None;
        }
        Some(&self.blocks[(height - 1) as usize])
    }

    pub fn tip_height(&self) -> u64 {
        self.blocks.len() as u64
    }

    /// Leaf count of the commitment tree at the end of block `height` (for
    /// `/v1/tree/frontier?at=height`). Heights ≥ tip clamp to the full tree.
    pub fn leaves_at(&self, height: u64) -> u64 {
        if height == 0 {
            return 0;
        }
        let mut count = 0;
        for (h, c) in &self.leaves_at_end_of_height {
            if *h <= height {
                count = *c;
            } else {
                break;
            }
        }
        count
    }

    /// Build the `[from, to]` (inclusive) range of compact blocks for
    /// `/v1/compact`. Heights outside the chain are skipped.
    pub fn compact_range(&self, from: u64, to: u64) -> Vec<CompactBlock> {
        let mut out = Vec::new();
        for height in from..=to {
            let Some(blk) = self.block(height) else { continue };
            let groups = blk
                .txs
                .iter()
                .enumerate()
                .map(|(tx_index, tx)| CompactGroup {
                    tx_index: tx_index as u64,
                    recipients: tx.recipients.iter().map(|r| r.enc.bundle.clone()).collect(),
                })
                .collect();
            out.push(CompactBlock { height, groups });
        }
        out
    }

    /// The full-fetch payloads for one `(height, tx_index)`: per-recipient AEAD
    /// ciphertext lists (index-aligned with the compact entries).
    pub fn full_payloads(&self, height: u64, tx_index: u64) -> Option<Vec<Vec<Vec<u8>>>> {
        let blk = self.block(height)?;
        let tx = blk.txs.get(tx_index as usize)?;
        Some(tx.recipients.iter().map(|r| r.enc.payloads.clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_note::scan::{scan, ScanMode};

    #[test]
    fn devnet_generates_deterministically() {
        let a = Devnet::generate(GenParams::default());
        let b = Devnet::generate(GenParams::default());
        assert_eq!(a.tip_height(), b.tip_height());
        assert_eq!(a.tree.root(), b.tree.root(), "same seed → same tree root");
        assert_eq!(a.expected_matches, b.expected_matches);
        assert!(a.expected_matches > 0, "some notes are planted to our wallet");
    }

    #[test]
    fn chain_is_well_formed() {
        let d = Devnet::generate(GenParams::default());
        assert_eq!(d.chain.tip_height(), d.tip_height());
        // Every stored block's header binds its body commitment.
        for blk in &d.blocks {
            assert_eq!(blk.header.tx_body_commitment, blk.body.commitment());
            assert_eq!(blk.header.height, blk.height);
        }
    }

    #[test]
    fn planted_notes_are_really_ours_and_decoys_are_not() {
        let d = Devnet::generate(GenParams::default());
        let mut found = 0;
        for blk in &d.blocks {
            for tx in &blk.txs {
                for r in &tx.recipients {
                    let hits = scan(&d.our.dk, &r.enc, ScanMode::FullFo);
                    if r.ours {
                        assert_eq!(hits.len(), r.enc.bundle.entries.len(), "our bundle fully detected");
                        found += hits.len();
                    } else {
                        assert!(hits.is_empty(), "decoy bundle must not detect for our key");
                    }
                }
            }
        }
        assert_eq!(found, d.expected_matches, "scan finds exactly the planted notes");
    }

    #[test]
    fn from_parts_reconstructs_equivalent_devnet() {
        let g = Devnet::generate(GenParams::default());
        // Re-derive leaves_at_end_of_height via the public leaves_at() over heights.
        let leaves: Vec<(u64, u64)> = (1..=g.tip_height()).map(|h| (h, g.leaves_at(h))).collect();
        let root = g.tree.root();
        let tip = g.tip_height();
        let expected = g.expected_matches;
        // Move g's parts into a fresh Devnet.
        let d = Devnet::from_parts(g.blocks, g.tree, g.chain, g.our, expected, leaves);
        assert_eq!(d.tip_height(), tip);
        assert_eq!(d.tree.root(), root);
        assert_eq!(d.leaves_at(tip), d.tree.len());
        assert_eq!(d.expected_matches, expected);
        // Serving still works.
        assert!(!d.compact_range(1, tip).is_empty());
    }

    #[test]
    fn leaves_at_is_monotone_and_matches_tree() {
        let d = Devnet::generate(GenParams::default());
        let mut prev = 0;
        for h in 1..=d.tip_height() {
            let c = d.leaves_at(h);
            assert!(c >= prev, "leaf count monotone in height");
            prev = c;
        }
        assert_eq!(d.leaves_at(d.tip_height()), d.tree.len(), "final count == tree size");
        assert_eq!(d.leaves_at(0), 0);
    }
}
