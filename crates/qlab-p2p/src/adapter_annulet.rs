//! The Annulet (sequencer) half of [`NodeAdapter`] (lab #708, B2a).
//!
//! An Annulet adapter judges headers **with their seal**: `ingest_sealed_*`
//! validate the seal and the header rule (`validate_sealed_header_annulet`),
//! refuse **equivocation** (a second sealed header at an occupied height —
//! with one signer and final-on-acceptance there is no fork to choose, so a
//! second header is misbehaviour, logged loudly and kept as evidence), and
//! apply blocks through the node's sealed path, which finalizes each on
//! acceptance. The L1 entry points (`ingest_header` / `ingest_block`) answer an
//! Annulet adapter with `Ignored(UNSEALED_ON_ANNULET_REASON)`.
//!
//! [`NodeAdapter::seal_next_block`] is the producer's synchronous step —
//! assemble from the pool, seal, and apply **through the same ingest path a
//! follower runs**, so producer and follower validate identically. The slot
//! loop that calls it on a cadence, the wire, the log record and `run` are
//! B2b's.
//!
//! **Committee machinery is off on Annulet**, by name, not only by the empty
//! committee (the finality-consumer trace on lab #708): checkpoint votes are
//! `Stale` before the tally, checkpoint fast-sync is `Ignored`, and the
//! `ChainView` finality every telemetry surface reads is the fork-choice
//! pointer (final = tip), not the never-fed committee tracker. The `run`-side
//! consumers (the round ledger, the boundary checkpoint, the committee
//! gauges) get their Annulet arms with `run` (B2b).

use super::*;
use ml_dsa::{MlDsa65, VerifyingKey};
use qlab_devnet::annulet::{
    body_commitment_annulet, AnnuletHeaderFields, GenesisNote, HeaderExt, L2FeeTable, SealedHeader,
    SequencerKey,
};
use qlab_devnet::committee::{Committee, CommitteeState};
use qlab_devnet::validation::validate_sealed_header_annulet;
use qlab_node::ChainStore as _;

/// The [`IngestOutcome::Rejected`] reason for an equivocation.
pub const EQUIVOCATION_REASON: &str = "equivocation: a second sealed header at an occupied height";

impl<P: PowEngine, V: TxVerifier + Clone> NodeAdapter<P, V> {
    /// A new **Annulet** adapter (lab #708), in memory: the genesis header
    /// (binding `genesis_notes`), the genesis L2 fee table and the
    /// genesis-pinned sequencer key. The committee is empty — an Annulet net
    /// has none.
    pub fn annulet(
        genesis_header: BlockHeader,
        genesis_notes: &[GenesisNote],
        fees: L2FeeTable,
        sequencer_key: VerifyingKey<MlDsa65>,
        pow: P,
        verifier: V,
        sim: SimConfig,
    ) -> Self {
        let state = MemNode::in_memory_annulet(genesis_header, genesis_notes, fees);
        let committee = EpochCommittee::genesis(
            EpochSchedule::new(EPOCH_LENGTH_BLOCKS),
            CommitteeState::new(Committee::from_keys(Vec::new()), 0),
        );
        let mut me = Self::assemble_on(GenesisForm::Annulet, genesis_header, committee, pow, verifier, sim, state);
        me.sequencer_key = Some(sequencer_key);
        // Genesis is final on acceptance (Q4) — the adapter's own fork-choice
        // view agrees with the node's.
        let g = me.chain.genesis_block_hash();
        me.chain.set_finalized(g).expect("genesis is final on acceptance (lab #708 Q4)");
        me
    }

    /// Refused equivocations so far: `(height, kept id, refused id)`.
    pub fn equivocations(&self) -> &[(u64, Hash32, Hash32)] {
        &self.equivocations
    }

    /// Ingest a sealed header (lab #708): the seal and the header rule, then
    /// the equivocation check, then fork choice (weight 1).
    pub fn ingest_sealed_header(&mut self, sealed: &SealedHeader) -> IngestOutcome {
        let key = match (self.rules.form, &self.sequencer_key) {
            (GenesisForm::Annulet, Some(key)) => key.clone(),
            (GenesisForm::V4 | GenesisForm::V5 | GenesisForm::Annulet, _) => {
                return IngestOutcome::Rejected("sealed header on a net without a sequencer");
            }
        };
        let id = sealed.id();
        if self.chain.header(&id).is_some() {
            return IngestOutcome::Duplicate;
        }
        if self.chain.header(&sealed.header.prev).is_none() {
            return IngestOutcome::Orphan;
        }
        if let Err(e) = validate_sealed_header_annulet(&self.chain, sealed, &key) {
            return IngestOutcome::Rejected(Self::header_reject_reason(&e));
        }
        // A validly sealed header at an occupied height is equivocation: the
        // one signer signed two blocks at one height. Kept as evidence and
        // refused (slashing waits for the sequencer committee, Phase 1).
        if let Some(kept) = self.chain.main_chain_hash_at(sealed.header.height) {
            self.equivocations.push((sealed.header.height, kept, id));
            eprintln!(
                "EQUIVOCATION height={} kept={} refused={} — the sequencer signed two blocks at one height (lab #708)",
                sealed.header.height,
                hex8(&kept),
                hex8(&id)
            );
            return IngestOutcome::Rejected(EQUIVOCATION_REASON);
        }
        self.insert_validated_header(sealed.header)
    }

    /// Ingest a sealed block: the header (if new), then the body through the
    /// node's sealed apply path (B1's Annulet body rule, the state funnel,
    /// final on acceptance), then the pool reconciles.
    pub fn ingest_sealed_block(&mut self, sealed: &SealedHeader, body: BlockBody) -> IngestOutcome {
        let id = sealed.id();
        if self.chain.header(&id).is_none() {
            match self.ingest_sealed_header(sealed) {
                IngestOutcome::Accepted => {}
                other => return other,
            }
        }
        if self.state.chain().contains(&id) {
            return IngestOutcome::Duplicate;
        }
        match self.state.apply_sealed_block(sealed, body.clone(), &self.verifier) {
            Ok(_) => {
                self.mempool.on_block_connected_above(
                    self.rules.form.rider_admit_boundary(),
                    &body,
                    &self.state,
                    self.state.names(),
                );
                if self.chain.set_finalized(id).is_err() {
                    return IngestOutcome::Rejected("annulet final-on-acceptance refused by fork choice");
                }
                IngestOutcome::Accepted
            }
            Err(NodeError::Body(e)) => match Self::body_fault_class(&e) {
                BodyFault::Intrinsic(why) => IngestOutcome::Rejected(why),
                BodyFault::Positional(why) => IngestOutcome::Ignored(why),
            },
            Err(NodeError::NotExtendingTip { .. }) => IngestOutcome::Orphan,
            Err(e) => {
                self.metrics.observe_body_refusal(e.refusal_reason(), sealed.header.height);
                IngestOutcome::Ignored("annulet apply refused by this node")
            }
        }
    }

    /// **The producer's step** (lab #708; the slot loop is B2b's): assemble a
    /// body from the pool (no coinbase — the L2 has none), build the child of
    /// the tip with the parent's anchor and registry root (the anchor source
    /// is a stub at Phase 0; no runtime registry updates until A2), seal it,
    /// and apply it **through [`Self::ingest_sealed_block`]** — the path every
    /// follower runs. Returns the sealed header and body to relay.
    pub fn seal_next_block(&mut self, key: &SequencerKey, timestamp: u64) -> Result<(SealedHeader, BlockBody), String> {
        if self.sequencer_key.as_ref() != Some(&key.verifying_key()) {
            return Err("this key is not the genesis sequencer key".into());
        }
        let parent = *self.chain.header(&self.chain.tip_hash()).ok_or("no tip")?;
        let HeaderExt::Annulet(pext) = parent.ext else {
            return Err("the tip is not an Annulet header".into());
        };
        let template = self.mempool.assemble(&self.state, SOAK_EFFECTIVE_MEDIAN, [0; 4]);
        let body = BlockBody::new(template.body.txs, Vec::new());
        let ext = AnnuletHeaderFields {
            l1_anchor_height: pext.l1_anchor_height,
            l1_anchor_root: pext.l1_anchor_root,
            registry_root: pext.registry_root,
        };
        let header =
            BlockHeader::child_of_annulet(&parent, timestamp.max(parent.timestamp), ext, body_commitment_annulet(&body));
        let sealed = key.seal(header);
        match self.ingest_sealed_block(&sealed, body.clone()) {
            IngestOutcome::Accepted => Ok((sealed, body)),
            other => Err(format!("the producer's own block was not accepted: {other:?}")),
        }
    }

    /// The sealed header at `height` on the main chain, for serving (`None`
    /// for genesis, which is unsealed, and for unknown heights).
    pub fn sealed_header_at(&self, height: u64) -> Option<SealedHeader> {
        let id = self.chain.main_chain_hash_at(height)?;
        self.state.chain().block(&id)?.sealed_header()
    }
}

fn hex8(h: &Hash32) -> String {
    h[..4].iter().map(|b| format!("{b:02x}")).collect()
}
