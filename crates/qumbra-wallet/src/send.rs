//! The send path — WRITTEN ahead of the mint, acceptance deferred to it
//! (t1-readiness-plan §3: "write against the dummy-capable interface so C3
//! does not rewrite it" — C3's circuit half merged as lab PR #252, so this is
//! written against the REAL latch, not a guess).
//!
//! What this module does: select inputs → build the frozen 2×2 bucket
//! (via [`build_bucket_dummy1`] when one real note suffices — the #219
//! mechanism) → **prove for real** (`qlab_consensus::prove_bucket`, ~2 s /
//! ~12 GB release) → encrypt outputs to their owners (ML-KEM, the #188 (a)
//! payloads) → assemble the [`TxEntry`] the wire commits to.
//!
//! What it deliberately does NOT do: **submit.** This module ends at the
//! canonical wire bytes (`qlab_p2p::codec::encode_tx`); getting them into the
//! net is [`crate::net::submit_tx`]'s job, over `POST /v1/tx`. ⚠️ An earlier
//! version of this header claimed
//! "§6.2 refused `POST /v1/tx`" — **the design repo contains no such
//! refusal** (what §6.2 rules is topological: a committee-key host exposes
//! nothing beyond P2P). The submission route was an undecided seam, and it is
//! now DECIDED: `t1-wallet-send-seams-decision.md`, STAMPED 2026-08-06,
//! A1 — `POST /v1/tx` on the stamped keyless public host (issues #275/#276).

use qlab_air::narrow::{
    build_bucket_dummy1, build_bucket_with_witnesses, derive_input, derive_output_rho,
    off_tree_witness, MerkleWitness, TxInput, TxOutput,
};
use qlab_cbserver::tree::CommitmentTree;
use qlab_consensus::{prove_bucket, LOG_HEIGHT};
use qlab_devnet::body::{TxEntry, TxPublic};
use qlab_devnet::fees::{posted_fee, ArityBucket};
use qlab_note::hash::digest_bytes;
use qlab_note::scan::encrypt_to_recipient;
use qlab_wallet::address::Address;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;
use rand::{CryptoRng, SeedableRng};

/// One note this wallet can spend: the plaintext plus the diversifier index it
/// was received under (the `d` that made its `rkm`).
#[derive(Clone)]
pub struct Spendable {
    pub div_index: u64,
    pub value: u64,
    pub rho: [u64; 4],
    pub rseed: [u64; 4],
}

pub struct SendArtifact {
    pub entry: TxEntry,
    pub wire_bytes: Vec<u8>,
    pub fee: u64,
    pub used_dummy: bool,
    pub prove_secs: f64,
    pub change_value: u64,
    /// The public values the prover produced, and the three lane-form surfaces
    /// they must equal when rebuilt from the declared entry — the seam
    /// `qumbra_node::verifier` reconstructs on the wire path.
    pub pvs: Vec<qlab_consensus::Val>,
    pub declared_anchor: [u64; 4],
    pub declared_nf: [[u64; 4]; 2],
    pub declared_cm: [[u64; 4]; 2],
}

/// Build + PROVE a spend of `amount` to `recipient`, change to this wallet's
/// address [0]. `tree` must be the chain's commitment tree at `anchor_count`
/// leaves, and `anchor_count`'s root must be one the network accepts as an
/// **anchor** — the caller owns that correspondence.
///
/// On a real net [`crate::sync::sync_and_select`] is what establishes it, and
/// it is not a formality: a valid anchor is a *finalized* root, so the count
/// here is generally **not** the count the leaf stream just served (issue
/// #276). Passing the freshly-synced tip count builds a perfectly valid proof
/// of a statement the node will refuse as `anchor-not-valid`.
#[allow(clippy::too_many_arguments)]
pub fn build_send(
    wallet: &Wallet,
    notes: &[Spendable],
    recipient: &Address,
    amount: u64,
    tree: &CommitmentTree,
    anchor_count: u64,
    rng: &mut StdRng,
) -> Result<SendArtifact, String> {
    build_send_with_rider(wallet, notes, recipient, amount, tree, anchor_count, rng, None)
}

/// [`build_send`] carrying a name-service rider (lab #367). The op raises the
/// declared fee by its burned name-fee half — the fee is already a public
/// input the proof binds, so a bigger fee is just more value the balance
/// equation must cover: **zero circuit change**, in this function's own code
/// as in the design. The rider itself is committed bytes on the entry; the
/// proof neither sees nor needs it (N5).
#[allow(clippy::too_many_arguments)]
pub fn build_send_with_rider(
    wallet: &Wallet,
    notes: &[Spendable],
    recipient: &Address,
    amount: u64,
    tree: &CommitmentTree,
    anchor_count: u64,
    rng: &mut StdRng,
    name_op: Option<&qlab_devnet::names::NameOp>,
) -> Result<SendArtifact, String> {
    let fee = posted_fee(ArityBucket::TwoByTwo)
        + name_op.map_or(0, qlab_devnet::names::name_fee_for);
    let need = amount.checked_add(fee).ok_or("amount overflows")?;

    // Coin selection: fewest notes that cover amount+fee, largest first. The
    // frozen bucket moves AT MOST two real notes; more means consolidating
    // first, and this refusal says so instead of silently spending wrong.
    let mut sorted: Vec<&Spendable> = notes.iter().collect();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));
    let (chosen, used_dummy): (Vec<&Spendable>, bool) = if sorted
        .first()
        .is_some_and(|n| n.value >= need)
    {
        (vec![sorted[0]], true)
    } else if sorted.len() >= 2 && sorted[0].value.checked_add(sorted[1].value).is_some_and(|s| s >= need)
    {
        (vec![sorted[0], sorted[1]], false)
    } else {
        let have: u64 = sorted.iter().map(|n| n.value).sum();
        return Err(format!(
            "cannot cover {need} bessel (amount {amount} + posted fee {fee}) from spendable \
             notes summing {have}. The frozen 2×2 bucket moves at most TWO notes per \
             transaction — if the total covers it but no two notes do, consolidate to \
             yourself first."
        ));
    };

    // Real inputs + their tree witnesses.
    let mut inputs: Vec<TxInput> = Vec::with_capacity(2);
    let mut witnesses: Vec<MerkleWitness> = Vec::with_capacity(2);
    for n in &chosen {
        let d = wallet.diversifier_at_index(n.div_index);
        let inp = wallet.spend_input(n.value, n.rho, n.rseed, d);
        // `derive_input` returns (nk, nf, cm) — position matters, and getting it
        // wrong here is invisible to a test that builds its tree the same wrong
        // way (see the module test's history in the PR).
        let (_nk, _nf, cm) = derive_input(&inp);
        let pos = tree.position_of(&cm).ok_or_else(|| {
            "a spendable note's commitment is not in the supplied tree — the tree and the \
             scan disagree; refusing rather than proving against the wrong anchor"
                .to_string()
        })?;
        // The note is in the tree, but is it inside the ANCHOR? `auth_path`
        // would happily cut a path for a leaf past `anchor_count`, and the
        // result folds to something that is not the anchor root — a perfectly
        // well-formed proof of a false statement, which costs ~3 s and ~12 GB
        // to produce and comes back `refused: proof-invalid` with no hint that
        // the real problem was finality. A wallet whose note landed in a block
        // the chain has not finalized yet is in an ordinary, temporary state
        // and deserves to be told so (issue #276).
        if pos >= anchor_count {
            return Err(format!(
                "this note is at tree position {pos}, which is outside the anchor at \
                 {anchor_count} leaves — its block is not finalized yet. A witness can only be \
                 built against a finalized anchor, so this spend is not possible YET; it becomes \
                 possible with no action once finality advances past that block. Refusing here \
                 rather than proving a statement the chain would reject."
            ));
        }
        witnesses.push(tree.auth_path(pos, anchor_count));
        inputs.push(inp);
    }

    let total_in: u64 = chosen.iter().map(|n| n.value).sum();
    let change_value = total_in - need;
    let anchor_lanes = tree.root_at(anchor_count);

    // Outputs: recipient first, change-to-self second (D4 recipient-major).
    // ρ′ per #215 (i) option 4 — derived from slot 0's nullifier; rseed random
    // (option (a): it TRAVELS in the AEAD payload).
    let nf0 = derive_input(&inputs[0]).1; // (nk, nf, cm) — nf is .1, as qlab_faucet::grant does
    let change_d = wallet.diversifier_at_index(0);
    let out_rho = [derive_output_rho(&nf0, 0), derive_output_rho(&nf0, 1)];
    let out_rseed = [rand_lanes(rng), rand_lanes(rng)];
    let outputs = [
        TxOutput {
            value: amount,
            rkm: recipient.rkm_lanes(),
            rho: out_rho[0],
            rseed: out_rseed[0],
        },
        TxOutput {
            value: change_value,
            rkm: wallet.rkm(change_d),
            rho: out_rho[1],
            rseed: out_rseed[1],
        },
    ];

    // Build — the dummy path is the #219 mechanism, real since lab PR #252.
    let inst = if used_dummy {
        let dummy = invented_dummy(rng);
        build_bucket_dummy1(
            LOG_HEIGHT,
            &inputs[0],
            &witnesses[0],
            &dummy,
            &off_tree_witness(),
            &outputs,
            fee,
            anchor_lanes,
        )
    } else {
        build_bucket_with_witnesses(
            LOG_HEIGHT,
            &[inputs[0].clone(), inputs[1].clone()],
            &outputs,
            fee,
            &[witnesses[0], witnesses[1]],
            anchor_lanes,
        )
    };

    // PROVE. Real STARK — the desktop-class step (~2 s / ~12 GB release).
    let t = std::time::Instant::now();
    let (pvs, proof) = prove_bucket(&inst);
    let prove_secs = t.elapsed().as_secs_f64();
    let proof_bytes = bincode::serialize(&proof).map_err(|e| e.to_string())?;

    // The cm seam, asserted at construction (the grant.rs lesson: assert, not
    // debug_assert — a silent release-mode seam failure surfaces three layers
    // later as DiscoveryDoesNotBind).
    let recipient_note = qlab_note::note::Note {
        value: amount,
        rkm: recipient.rkm_lanes(),
        rho: out_rho[0],
        rseed: out_rseed[0],
    };
    let change_note = qlab_note::note::Note {
        value: change_value,
        rkm: wallet.rkm(change_d),
        rho: out_rho[1],
        rseed: out_rseed[1],
    };
    assert_eq!(inst.cm_out[0], recipient_note.commitment(), "recipient cm seam");
    assert_eq!(inst.cm_out[1], change_note.commitment(), "change cm seam");

    // Encrypt each output to its owner — the #188 (a) discovery payloads,
    // recipient-major, same order as `commitments`.
    let recipient_ek = recipient
        .encapsulation_key()
        .ok_or("recipient address carries no ML-KEM encapsulation key")?;
    let to_recipient = encrypt_to_recipient(&recipient_ek, &[recipient_note], rng);
    let self_ek = wallet.diversified_keypair(&change_d).ek;
    let to_self = encrypt_to_recipient(&self_ek, &[change_note], rng);

    let entry = TxEntry::new(
        proof_bytes,
        TxPublic {
            anchor: digest_bytes(&anchor_lanes),
            nullifiers: vec![digest_bytes(&inst.nf[0]), digest_bytes(&inst.nf[1])],
            commitments: vec![digest_bytes(&inst.cm_out[0]), digest_bytes(&inst.cm_out[1])],
            bucket: ArityBucket::TwoByTwo,
            fee,
        },
        &[to_recipient.bundle.clone(), to_self.bundle.clone()],
        &[to_recipient.payloads, to_self.payloads].concat(),
    );
    let entry = match name_op {
        Some(op) => entry.with_name_op(op),
        None => entry,
    };
    let wire_bytes = qlab_p2p::codec::encode_tx(&entry);

    Ok(SendArtifact {
        entry,
        wire_bytes,
        fee,
        used_dummy,
        prove_secs,
        change_value,
        pvs,
        declared_anchor: anchor_lanes,
        declared_nf: [inst.nf[0], inst.nf[1]],
        declared_cm: [inst.cm_out[0], inst.cm_out[1]],
    })
}

/// A dummy input per the #219 ruling: prover-invented sk/ρ/rseed, value 0 —
/// its nullifier is a real nullifier of an invented note (Orchard's
/// construction), bound by ROLE_BNF2 so a relay cannot rewrite it.
fn invented_dummy<R: CryptoRng>(rng: &mut R) -> TxInput {
    let d4 = rand_lanes(rng);
    TxInput {
        sk: rand_lanes(rng),
        value: 0,
        rho: rand_lanes(rng),
        rseed: rand_lanes(rng),
        d: [d4[0], d4[1]],
    }
}

/// The same byte-fill idiom `qlab_faucet::grant` uses — `fill_bytes`, not a
/// numeric `random()`, so the lane bytes come from the CSPRNG directly.
fn rand_lanes<R: CryptoRng>(rng: &mut R) -> [u64; 4] {
    core::array::from_fn(|_| {
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    })
}

/// OS-seeded rng for the binary's call path (tests seed deterministically).
pub fn os_rng() -> StdRng {
    use rand::Rng;
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    StdRng::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::MasterSeed;

    /// A note whose block is not finalized yet is IN the local tree but OUTSIDE
    /// the anchor. Refused by name, before the prove — because `auth_path`
    /// would otherwise cut a path past `anchor_count` and produce a
    /// well-formed proof of a false statement, at ~3 s and ~12 GB, whose only
    /// symptom would be `refused: proof-invalid` (issue #276).
    ///
    /// No prove happens on this path, so this test is NOT release-gated.
    #[test]
    fn a_note_outside_the_anchor_is_refused_before_any_proof() {
        let mut rng = StdRng::seed_from_u64(0x0AC7);
        let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([31u8; 32]), 0);
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([32u8; 32]), 0).address_at_index(0);

        let note =
            Spendable { div_index: 0, value: 10_000_000, rho: [3, 3, 3, 3], rseed: [5, 5, 5, 5] };
        let d = wallet.diversifier_at_index(0);
        let inp = wallet.spend_input(note.value, note.rho, note.rseed, d);
        let (_nk, _nf, cm) = derive_input(&inp);

        // Two earlier leaves are finalized; this note is the third, in a block
        // finality has not reached — so the anchor is at 2 and the note is at 2.
        let mut tree = CommitmentTree::new();
        tree.append([1, 1, 1, 1]);
        tree.append([2, 2, 2, 2]);
        tree.append(cm);
        assert_eq!(tree.position_of(&cm), Some(2));

        let err = match build_send(&wallet, &[note], &recipient, 4_000_000, &tree, 2, &mut rng) {
            Err(e) => e,
            Ok(_) => panic!("a note outside the anchor must refuse, not prove"),
        };
        assert!(err.contains("position 2"), "{err}");
        assert!(err.contains("outside the anchor at 2 leaves"), "{err}");
        assert!(err.contains("not finalized yet"), "{err}");
        assert!(err.contains("not possible YET"), "the state is temporary and says so: {err}");
    }

    /// One real spend, end to end, through the merged post-mint circuit: build a
    /// tree, put a note this wallet owns in it, send half of it to a stranger,
    /// PROVE (real STARK), and check every seam the wire will check.
    ///
    /// Release-only: `prove_bucket` is a ~2 s / ~12 GB job (the bar runs
    /// `--release --test-threads=1`; a debug run would be minutes and is not
    /// what any consumer executes).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "real prove — release only, per the bench discipline")]
    fn one_real_spend_builds_proves_and_binds_its_seams() {
        let mut rng = StdRng::seed_from_u64(0x5E4D);
        let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([11u8; 32]), 0);
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([22u8; 32]), 0).address_at_index(0);

        // A note this wallet owns, placed in a tree the way the chain would.
        let note = Spendable {
            div_index: 0,
            value: 10_000_000,
            rho: [7, 7, 7, 7],
            rseed: [9, 9, 9, 9],
        };
        let d = wallet.diversifier_at_index(0);
        let inp = wallet.spend_input(note.value, note.rho, note.rseed, d);
        // `derive_input` returns (nk, nf, cm) — position matters, and getting it
        // wrong here is invisible to a test that builds its tree the same wrong
        // way (see the module test's history in the PR).
        let (_nk, _nf, cm) = derive_input(&inp);
        let mut tree = CommitmentTree::new();
        tree.append(cm);
        let count = tree.len();

        let fee = posted_fee(ArityBucket::TwoByTwo);
        let amount = 4_000_000;
        let art = match build_send(
            &wallet, &[note.clone()], &recipient, amount, &tree, count, &mut rng,
        ) {
            Ok(a) => a,
            Err(e) => panic!("a single covering note must spend via the dummy slot: {e}"),
        };

        // The #219 mechanism is what made this legal at all.
        assert!(art.used_dummy, "one real note ⇒ slot 1 is the dummy");
        assert_eq!(art.fee, fee);
        assert_eq!(art.change_value, note.value - amount - fee, "balance closes exactly");
        assert!(art.prove_secs > 0.0);

        // The wire object: two nullifiers, two commitments, the frozen bucket.
        assert_eq!(art.entry.public.nullifiers.len(), 2);
        assert_eq!(art.entry.public.commitments.len(), 2);
        assert_eq!(art.entry.public.bucket, ArityBucket::TwoByTwo);
        assert!(!art.wire_bytes.is_empty());

        // 🔴 The proof must verify against the DECLARED surface — exactly what
        // `qumbra_node::verifier` reconstructs on the wire path: PVs from the
        // declared anchor/nf/cm/fee, then `verify_proof`. Rebuilt here from the
        // entry's own public fields, so a mismatch between what was proved and
        // what is declared fails at construction rather than at a node.
        let declared_u32 = qlab_air::narrow::pv_vec(
            &art.declared_anchor,
            &art.declared_nf[0],
            &art.declared_nf[1],
            &art.declared_cm[0],
            &art.declared_cm[1],
            art.fee,
        );
        let proved_u32: Vec<u32> = art
            .pvs
            .iter()
            .map(|v| <qlab_consensus::Val as p3_field::PrimeField32>::as_canonical_u32(v))
            .collect();
        assert_eq!(declared_u32, proved_u32, "proved surface == declared surface");
    }

    #[test]
    fn two_notes_that_cannot_cover_are_refused_with_the_bucket_reason() {
        let mut rng = StdRng::seed_from_u64(1);
        let wallet = Wallet::from_master_seed(&MasterSeed::from_entropy([3u8; 32]), 0);
        let recipient =
            Wallet::from_master_seed(&MasterSeed::from_entropy([4u8; 32]), 0).address_at_index(0);
        let tree = CommitmentTree::new();
        let small = |v| Spendable { div_index: 0, value: v, rho: [1, 1, 1, 1], rseed: [2, 2, 2, 2] };
        let err = match build_send(
            &wallet,
            &[small(10), small(10), small(10_000_000)],
            &recipient,
            5_000_000,
            &tree,
            0,
            &mut rng,
        ) {
            Err(e) => e,
            Ok(_) => panic!("an empty tree cannot witness anything"),
        };
        // The largest covers, so selection takes the dummy path and then fails on
        // the TREE, not on coverage — the honest refusal for an empty tree.
        assert!(err.contains("not in the supplied tree"), "{err}");
    }
}
