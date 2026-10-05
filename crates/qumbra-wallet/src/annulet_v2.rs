//! Lab #896 seam G: **Candidate A sends** — the v2 shapes, signed by this
//! wallet's own authorization keys (design `remote-proving-authorization-
//! shape-annulet` §2, §5, §6, §9).
//!
//! Every Annulet write on a Candidate A net (`L2AuthForm::CandidateA`, read
//! from the pinned genesis) runs here; a v1 net keeps [`crate::annulet_send`]
//! byte for byte. Per transaction:
//!
//! 1. its real inputs are all of **one generation** — the active one for an
//!    ordinary send (§5: one key per transaction; the planner works on the
//!    active generation's notes only, and a sweep-only generation's notes
//!    move only through `migrate`);
//! 2. one leaf per real slot is taken from that generation's cursor and the
//!    advance is **persisted to `auth.v1` before anything is proved or
//!    signed** (fail-closed, under the journal's lock);
//! 3. dummy slots are drawn from fresh OS entropy and consume nothing;
//! 4. the v2 builder proves; `intent_for` rebuilds the intent from the
//!    transaction (valid until the verified tip + [`DEFAULT_VALIDITY_BLOCKS`]);
//!    `sign_locally` signs every slot; the section is attached and the
//!    transaction submitted.

use qlab_air::l2::{L2AuthInput, L2AuthPath};
use qlab_air::l2p::VPublic;
use qlab_devnet::annulet::{L2ShapeTag, MAX_AUTH_VALIDITY_BLOCKS};
use qlab_l2spend::v2::{attach, build_p_v2, build_s_v2, intent_for, sign_locally, BuiltV2, FeeIn, LocalAuth};
use qlab_l2spend::{Endpoint, Out, PolicyContext, Recipient, Served, SpendError};
use qlab_ledger::assets::OwnedL2Note;
use qlab_remote_auth::annulet::D_AUTH;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;

use crate::annulet_send::{SendRefusal, Session};
use crate::auth_journal::{generation_root, AuthJournal, AuthLock, GenState, Generation, JournalError, SweepGate};
use crate::store::WalletDir;

/// The validity a Candidate A transaction is signed with: it may land up to
/// this many blocks past the verified tip (design 2b §10 decided 4, Phase 4's
/// suggested default). Well inside the consensus cap.
pub const DEFAULT_VALIDITY_BLOCKS: u64 = 256;
const _: () = assert!(DEFAULT_VALIDITY_BLOCKS <= MAX_AUTH_VALIDITY_BLOCKS);

/// A refusal of the Candidate A layer, folded into [`SendRefusal`].
impl From<JournalError> for SendRefusal {
    fn from(e: JournalError) -> Self {
        SendRefusal::Auth(e.to_string())
    }
}

/// What a Candidate A write holds for its whole run: the journal under its
/// lock, the active generation's keys, the net, and the validity it signs.
pub struct AuthRun {
    lock: AuthLock,
    journal: AuthJournal,
    /// The generation every real input of this run is taken from.
    pub generation: u32,
    keys: LocalAuth,
    genesis_hash: [u8; 32],
    genesis_format: u32,
    /// The last height the run's transactions may land at.
    pub valid_until: u64,
}

impl AuthRun {
    /// Open the active generation's keys for a run on `session`'s net. A
    /// wallet with no journal is a restored (or new-to-Candidate-A) one: it
    /// is migrated first ([`restore_journal`]).
    pub fn open<E: Endpoint>(w: &WalletDir, session: &Session<E>, validity: u64) -> Result<Self, SendRefusal> {
        if validity == 0 || validity > MAX_AUTH_VALIDITY_BLOCKS {
            return Err(SendRefusal::Auth(format!(
                "a validity of {validity} blocks is outside 1..={MAX_AUTH_VALIDITY_BLOCKS} (the consensus cap)"
            )));
        }
        let lock = AuthLock::acquire(&w.dir)?;
        let wallet = w.wallet();
        let journal = match AuthJournal::load(&w.dir)? {
            Some(j) => j,
            None => restore_journal(&lock, w, &wallet, &session.owned, &session.genesis_hash, session.tip)?,
        };
        let (g, next) = (journal.active().g, journal.active().next);
        Self::for_generation(lock, journal, &wallet, g, next, session, validity)
    }

    fn for_generation<E: Endpoint>(
        lock: AuthLock,
        journal: AuthJournal,
        wallet: &Wallet,
        g: u32,
        next: u32,
        session: &Session<E>,
        validity: u64,
    ) -> Result<Self, SendRefusal> {
        let keys = LocalAuth::new(&wallet.auth_secret(), g, next).map_err(SendRefusal::Auth)?;
        assert_eq!(
            keys.auth_root(),
            journal.get(g)?.auth_root,
            "the journal's cached root is the generation's tree"
        );
        Ok(AuthRun {
            lock,
            journal,
            generation: g,
            keys,
            genesis_hash: session.genesis_hash,
            genesis_format: session.l2_auth.annulet_genesis_format_version(),
            valid_until: session.tip + validity,
        })
    }

    /// The active generation's root: what this wallet's change and its new
    /// addresses bind.
    pub fn auth_root(&self) -> [u64; 4] {
        self.keys.auth_root()
    }

    /// Take one leaf per real slot and **persist the advance** before the
    /// caller proves or signs anything.
    fn take(&mut self, dir: &std::path::Path, n: usize) -> Result<Vec<L2AuthPath>, SendRefusal> {
        let mut paths = Vec::with_capacity(n);
        for _ in 0..n {
            paths.push(self.keys.take().ok_or(JournalError::Exhausted { g: self.generation })?);
        }
        self.journal.advance(&self.lock, dir, self.generation, self.keys.next())?;
        Ok(paths)
    }

    /// A dummy slot `slot` (0-based) beside the taken leaves `taken`, from
    /// fresh OS entropy.
    fn dummy(&self, slot: u8, taken: &[u32]) -> Result<(L2AuthInput, qlab_remote_auth::mldsa::Key), SendRefusal> {
        use rand::Rng;
        let mut entropy = [0u8; 32];
        rand::rng().fill_bytes(&mut entropy);
        self.keys.dummy(&entropy, slot, taken).map_err(SendRefusal::Auth)
    }

    /// Rebuild the intent, sign every slot, attach the section, submit.
    fn sign_and_submit<E: Endpoint>(
        &self,
        served: &Served<E>,
        mut built: BuiltV2,
        dummies: &[&qlab_remote_auth::mldsa::Key],
    ) -> Result<BuiltV2, SendRefusal> {
        let intent = intent_for(&built.tx, self.genesis_format, &self.genesis_hash, self.valid_until, &built.auth)
            .map_err(|e| SendRefusal::Auth(format!("the intent does not rebuild: {e:?}")))?; // debug-ok: a named codec error, no opening
        let section = sign_locally(&intent, &self.keys, dummies)
            .map_err(|e| SendRefusal::Auth(format!("signing refused: {e:?}")))?; // debug-ok: a named auth error, no key
        attach(&mut built.tx, &section).map_err(|e| SendRefusal::Auth(format!("the section does not encode: {e:?}")))?; // debug-ok
        served.submit(&built.tx)?;
        Ok(built)
    }
}

/// A real input: `note` (this wallet's, generation `g`) with the leaf `path`.
pub fn real_input(wallet: &Wallet, note: &OwnedL2Note, path: L2AuthPath) -> L2AuthInput {
    L2AuthInput {
        nk: wallet.nk(),
        value: note.note.value,
        asset: note.note.asset,
        rho: note.note.rho,
        rseed: note.note.rseed,
        d: wallet.diversifier_at_index(note.div_index).lanes(),
        auth: path,
    }
}

/// This wallet's change recipient on a Candidate A net: address 0 of the
/// active generation.
pub fn me_v2(wallet: &Wallet, auth_root: &[u64; 4]) -> Recipient {
    let addr = wallet.address_candidate_a_at_index(0, auth_root);
    Recipient { rkm: addr.rkm_lanes(), ek: addr.encapsulation_key().expect("the wallet's own address has an ek") }
}

/// The shape-S / shape-P transaction a v1 call made, in v2 terms: which
/// slots are real inputs (all of the run's generation) and what slot 3 is.
pub enum V2Spend<'a> {
    /// One real input paying its own fee: slot 2 a dummy (`dv`), slot 3 a
    /// dummy (S only — v1's `build_s(&[one])`).
    One(&'a OwnedL2Note),
    /// Two real inputs, slot 3 a dummy (v1's `build_s(&[x, fee])` /
    /// `build_p_with([x, fee])`).
    Two([&'a OwnedL2Note; 2]),
    /// Two real inputs and an exact fee note in slot 3 (v1's `*_merge`).
    TwoAndFee([&'a OwnedL2Note; 2], &'a OwnedL2Note),
}

/// Build, prove, sign and submit one Candidate A S or P spend.
#[allow(clippy::too_many_arguments)]
pub fn spend_v2<E: Endpoint>(
    w: &WalletDir,
    run: &mut AuthRun,
    served: &Served<E>,
    shape: L2ShapeTag,
    spend: V2Spend<'_>,
    outs: &[Out; 2],
    fee: u64,
    ctx: &PolicyContext,
    rng: &mut StdRng,
) -> Result<BuiltV2, SendRefusal> {
    let wallet = w.wallet();
    let notes: Vec<&OwnedL2Note> = match &spend {
        V2Spend::One(a) => vec![*a],
        V2Spend::Two(xs) => xs.to_vec(),
        V2Spend::TwoAndFee(xs, f) => vec![xs[0], xs[1], *f],
    };
    for n in &notes {
        if n.generation != Some(run.generation) {
            return Err(SendRefusal::Auth(format!(
                "a note of generation {:?} cannot be spent beside generation {}'s keys (one key per transaction)",
                n.generation, run.generation
            )));
        }
    }
    let paths = run.take(&w.dir, notes.len())?;
    let taken: Vec<u32> = paths.iter().map(|p| p.leaf_index).collect();
    let real: Vec<L2AuthInput> = notes.iter().zip(paths).map(|(n, p)| real_input(&wallet, n, p)).collect();
    let built = match (shape, &spend) {
        (L2ShapeTag::S, V2Spend::One(_)) => {
            let (d2, k2) = run.dummy(1, &taken)?;
            let (d3, k3) = run.dummy(2, &[taken.as_slice(), &[d2.auth.leaf_index]].concat())?;
            let b = build_s_v2(served, [&real[0], &d2], true, FeeIn::Dummy(&d3), outs, fee, rng)?;
            return run.sign_and_submit(served, b, &[&k2, &k3]);
        }
        (L2ShapeTag::S, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            let b = build_s_v2(served, [&real[0], &real[1]], false, FeeIn::Dummy(&d3), outs, fee, rng)?;
            return run.sign_and_submit(served, b, &[&k3]);
        }
        (L2ShapeTag::S, V2Spend::TwoAndFee(..)) => {
            build_s_v2(served, [&real[0], &real[1]], false, FeeIn::Exact(&real[2]), outs, fee, rng)?
        }
        (L2ShapeTag::P, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            let b = build_p_v2(
                served,
                [&real[0], &real[1]],
                FeeIn::Dummy(&d3),
                outs,
                fee,
                [ctx, &PolicyContext::default()],
                [VPublic::NONE; 2],
                rng,
            )?;
            return run.sign_and_submit(served, b, &[&k3]);
        }
        (L2ShapeTag::P, V2Spend::TwoAndFee(..)) => build_p_v2(
            served,
            [&real[0], &real[1]],
            FeeIn::Exact(&real[2]),
            outs,
            fee,
            [ctx, ctx],
            [VPublic::NONE; 2],
            rng,
        )?,
        (L2ShapeTag::P, V2Spend::One(_)) => {
            return Err(SendRefusal::Spend(SpendError::Served(
                "a one-input shape-P spend has no v2 builder (P proves two real inputs)".into(),
            )))
        }
        (L2ShapeTag::R, _) => {
            return Err(SendRefusal::Spend(SpendError::Served("shape R is a registry write, not a spend".into())))
        }
    };
    run.sign_and_submit(served, built, &[])
}

/// **Restore → migrate** (§9) for a wallet with no `auth.v1`: the
/// generations its verified scan found notes in (`owned`, spent or not) are
/// never resumed. The highest generation with notes is `g*`; `g* + 1` opens
/// as the active one; every generation `≤ g*` with unspent notes becomes
/// sweep-only, gated on this net at `tip + MAX_AUTH_VALIDITY_BLOCKS` (by
/// which every authorization exported before the loss has expired), and
/// every generation with only spent notes retires. A wallet with no notes at
/// all has exported nothing, so it starts at generation 0.
///
/// The swept generations' cursors restart **above** every position a landed
/// spend used — rebuilt by [`landed_next`] when the sweep runs; until then
/// the journal holds them at 0 and the sweep gate keeps them unsigned.
pub fn restore_journal(
    lock: &AuthLock,
    w: &WalletDir,
    wallet: &Wallet,
    owned: &[OwnedL2Note],
    genesis: &[u8; 32],
    tip: u64,
) -> Result<AuthJournal, SendRefusal> {
    let top = owned.iter().filter_map(|n| n.generation).max();
    let probed = crate::auth_journal::PROBE_GENERATIONS;
    let journal = match top {
        None => AuthJournal::fresh(generation_root(wallet, 0)),
        Some(g_star) if g_star + 1 >= probed => {
            return Err(JournalError::ProbeExhausted { probed }.into());
        }
        Some(g_star) => {
            let gate = SweepGate { genesis: *genesis, not_before_height: tip + MAX_AUTH_VALIDITY_BLOCKS };
            let mut gens = Vec::new();
            for g in 0..=g_star {
                let notes: Vec<&OwnedL2Note> = owned.iter().filter(|n| n.generation == Some(g)).collect();
                if notes.is_empty() {
                    continue;
                }
                gens.push(Generation {
                    g,
                    next: 0,
                    auth_root: generation_root(wallet, g),
                    state: GenState::Sweep { gates: vec![gate] },
                });
            }
            gens.push(Generation { g: g_star + 1, next: 0, auth_root: generation_root(wallet, g_star + 1), state: GenState::Active });
            AuthJournal::from_generations(gens)?
        }
    };
    journal.save(&w.dir)?;
    let _ = lock;
    Ok(journal)
}

/// The cursor position above every leaf of generation `g` that this
/// wallet's **landed** spends used: `max(position) + 1` over the real slots
/// (a slot whose descriptor leaf is the generation tree's leaf at its index;
/// dummies live in their own throwaway trees), or 0 if none. The cursor is a
/// private permutation, so this is a position, not a leaf index.
pub fn landed_next(wallet: &Wallet, g: u32, landed_slots: &[(u32, [u8; 32])]) -> u32 {
    use qlab_remote_auth::annulet::{auth_master, AuthTree, Cursor};
    let master = auth_master(&wallet.auth_secret(), g);
    let tree = AuthTree::build(&master, D_AUTH).expect("D_AUTH is a valid depth");
    let mine: Vec<u32> = landed_slots
        .iter()
        .filter(|(index, leaf)| (*index as usize) < (1usize << D_AUTH) && tree.leaf(*index) == *leaf)
        .map(|(index, _)| *index)
        .collect();
    if mine.is_empty() {
        return 0;
    }
    // Walk the permutation until every landed leaf has been drawn.
    let mut cursor = Cursor::new(&master, D_AUTH, 0).expect("position 0");
    let mut left: std::collections::BTreeSet<u32> = mine.into_iter().collect();
    while !left.is_empty() {
        let index = cursor.take().expect("every leaf index is in the permutation");
        left.remove(&index);
    }
    cursor.next()
}

/// The root of generation `g` for `wallet` — re-exported for the CLI.
pub fn root_of(wallet: &Wallet, g: u32) -> [u64; 4] {
    generation_root(wallet, g)
}

/// Run `plan` on a Candidate A net under `run`'s generation: v1's
/// [`crate::annulet_send`] round structure, each step a v2 spend. Notes a
/// later step spends (fee splits, merges) are paid to the run generation's
/// own address 0, so every input of every step is one generation's; the
/// payment pays `recipient` and returns its change to `change` — the active
/// generation's address, also when the run is a sweep of an older one.
#[allow(clippy::too_many_arguments)]
pub fn run_plan_v2<E: Endpoint>(
    w: &WalletDir,
    run: &mut AuthRun,
    session: &Session<E>,
    plan: &crate::annulet_send::SendPlan,
    recipient: &Recipient,
    change: &Recipient,
    freeze_keys: &[[u64; 4]],
    split_wait: std::time::Duration,
    rng: &mut StdRng,
) -> Result<Vec<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>, SendRefusal> {
    use crate::annulet_send::{wait_in_tree, Src, StepKind};
    let wallet = w.wallet();
    let served = &session.served;
    let s_tier = session.tiers.s;
    let a = u64::from(plan.asset);
    let ctx = PolicyContext { freeze_keys: freeze_keys.to_vec(), ..Default::default() };
    let own_root = run.auth_root();
    let own = me_v2(&wallet, &own_root);
    let gens = [(run.generation, own_root)];
    let mut made: Vec<Option<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>> = vec![None; plan.steps.len()];
    let owned = |made: &[Option<([qlab_note::l2note::L2Note; 2], L2ShapeTag)>], src: &Src| -> OwnedL2Note {
        match src {
            Src::Held(n) => n.clone(),
            Src::Made { step, out, .. } => {
                let note = made[*step].expect("a step spends only notes of earlier rounds").0[*out];
                OwnedL2Note::from_genesis_v2(&wallet, 0, qlab_note::hash::digest_bytes(&note.commitment()), note, &gens)
                    .expect("a planned note was paid to the run generation's address 0")
            }
        }
    };
    for round in 0..plan.rounds() {
        for (i, st) in plan.steps.iter().enumerate().filter(|(_, s)| s.round == round) {
            let built = match &st.kind {
                StepKind::FeeSplit { source, tariff } => {
                    let src = owned(&made, source);
                    let outs = [
                        Out { to: own.clone(), value: *tariff, asset: 0 },
                        Out { to: own.clone(), value: st.outputs[1], asset: 0 },
                    ];
                    spend_v2(w, run, served, L2ShapeTag::S, V2Spend::One(&src), &outs, s_tier, &ctx, rng)?
                }
                StepKind::Merge { inputs, fee } => {
                    let (x, y, f) = (owned(&made, &inputs[0]), owned(&made, &inputs[1]), owned(&made, fee));
                    let outs = [
                        Out { to: own.clone(), value: st.outputs[0], asset: a },
                        Out { to: own.clone(), value: 0, asset: a },
                    ];
                    spend_v2(w, run, served, st.shape, V2Spend::TwoAndFee([&x, &y], &f), &outs, st.fee, &ctx, rng)?
                }
                StepKind::Pay { inputs, fee } => {
                    let ins: Vec<OwnedL2Note> = inputs.iter().map(|x| owned(&made, x)).collect();
                    let outs = [
                        Out { to: recipient.clone(), value: st.outputs[0], asset: a },
                        Out { to: change.clone(), value: st.outputs[1], asset: a },
                    ];
                    match (fee, ins.as_slice()) {
                        (None, [one]) => spend_v2(w, run, served, L2ShapeTag::S, V2Spend::One(one), &outs, st.fee, &ctx, rng)?,
                        (Some(fee), [one]) => {
                            let f = owned(&made, fee);
                            spend_v2(w, run, served, st.shape, V2Spend::Two([one, &f]), &outs, st.fee, &ctx, rng)?
                        }
                        (Some(fee), [x, y]) => {
                            let f = owned(&made, fee);
                            spend_v2(w, run, served, st.shape, V2Spend::TwoAndFee([x, y], &f), &outs, st.fee, &ctx, rng)?
                        }
                        _ => unreachable!("a payment is planned with one or two inputs"),
                    }
                }
            };
            made[i] = Some((built.outputs, built.shape));
        }
        // Every note a later round spends must be in the tree first.
        for later in plan.steps.iter().filter(|s| s.round > round) {
            let srcs: Vec<&Src> = match &later.kind {
                StepKind::FeeSplit { source, .. } => vec![source],
                StepKind::Merge { inputs, fee } => inputs.iter().chain(std::iter::once(fee)).collect(),
                StepKind::Pay { inputs, fee } => inputs.iter().chain(fee.iter()).collect(),
            };
            for src in srcs {
                if let Src::Made { step, out, .. } = src {
                    if plan.steps[*step].round == round {
                        let note = made[*step].expect("made this round").0[*out];
                        wait_in_tree(served, &note.commitment(), split_wait)?;
                    }
                }
            }
        }
    }
    Ok(made.into_iter().map(|m| m.expect("every step ran")).collect())
}
