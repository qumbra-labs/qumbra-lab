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

    pub(crate) fn for_generation<E: Endpoint>(
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

    /// Rebuild the intent from `tx`, sign every slot, attach the section.
    /// Nothing is submitted here.
    pub(crate) fn sign(
        &self,
        tx: &mut qlab_devnet::body::TxEntry,
        auth: &[qlab_remote_auth::intent::AuthDescriptor],
        dummies: &[&qlab_remote_auth::mldsa::Key],
    ) -> Result<(), SendRefusal> {
        let intent = intent_for(tx, self.genesis_format, &self.genesis_hash, self.valid_until, auth)
            .map_err(|e| SendRefusal::Auth(format!("the intent does not rebuild: {e:?}")))?; // debug-ok: a named codec error, no opening
        let section = sign_locally(&intent, &self.keys, dummies)
            .map_err(|e| SendRefusal::Auth(format!("signing refused: {e:?}")))?; // debug-ok: a named auth error, no key
        attach(tx, &section).map_err(|e| SendRefusal::Auth(format!("the section does not encode: {e:?}"))) // debug-ok
    }

    /// Take one leaf of the run's generation for a single real slot (a
    /// registry write's fee input), persisted before anything is proved.
    pub(crate) fn take_one(&mut self, dir: &std::path::Path) -> Result<L2AuthPath, SendRefusal> {
        Ok(self.take(dir, 1)?.remove(0))
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
    let built = build_spend_v2(w, run, served, shape, spend, outs, fee, [ctx, &PolicyContext::default()], [VPublic::NONE; 2], rng)?;
    served.submit(&built.tx)?;
    Ok(built)
}

/// Build, prove and sign one Candidate A S or P spend, **not** submitted (an
/// issuer service records an attempt before it leaves the machine). `ctx`
/// and `vp` are the two rows' policy contexts and `vPublic` (P only; a
/// `TwoAndFee` P uses `ctx[0]` for both rows, as v1's merge does).
#[allow(clippy::too_many_arguments)]
pub fn build_spend_v2<E: Endpoint>(
    w: &WalletDir,
    run: &mut AuthRun,
    served: &Served<E>,
    shape: L2ShapeTag,
    spend: V2Spend<'_>,
    outs: &[Out; 2],
    fee: u64,
    ctx: [&PolicyContext; 2],
    vp: [VPublic; 2],
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
            let mut b = build_s_v2(served, [&real[0], &d2], true, FeeIn::Dummy(&d3), outs, fee, rng)?;
            run.sign(&mut b.tx, &b.auth.clone(), &[&k2, &k3])?;
            return Ok(b);
        }
        (L2ShapeTag::S, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            let mut b = build_s_v2(served, [&real[0], &real[1]], false, FeeIn::Dummy(&d3), outs, fee, rng)?;
            run.sign(&mut b.tx, &b.auth.clone(), &[&k3])?;
            return Ok(b);
        }
        (L2ShapeTag::S, V2Spend::TwoAndFee(..)) => {
            build_s_v2(served, [&real[0], &real[1]], false, FeeIn::Exact(&real[2]), outs, fee, rng)?
        }
        (L2ShapeTag::P, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            let mut b = build_p_v2(served, [&real[0], &real[1]], FeeIn::Dummy(&d3), outs, fee, ctx, vp, rng)?;
            run.sign(&mut b.tx, &b.auth.clone(), &[&k3])?;
            return Ok(b);
        }
        (L2ShapeTag::P, V2Spend::TwoAndFee(..)) => {
            build_p_v2(served, [&real[0], &real[1]], FeeIn::Exact(&real[2]), outs, fee, [ctx[0], ctx[0]], vp, rng)?
        }
        (L2ShapeTag::P, V2Spend::One(_)) => {
            return Err(SendRefusal::Spend(SpendError::Served(
                "a one-input shape-P spend has no v2 builder (P proves two real inputs)".into(),
            )))
        }
        (L2ShapeTag::R, _) => {
            return Err(SendRefusal::Spend(SpendError::Served("shape R is a registry write, not a spend".into())))
        }
    };
    let mut built = built;
    run.sign(&mut built.tx, &built.auth.clone(), &[])?;
    Ok(built)
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

/// The `(leaf_index, leaf)` of every slot of every landed transaction that
/// spent one of `spent` (generation `g`'s spent notes with their heights) —
/// read from the served bodies, whose Candidate A frame carries each
/// transaction's auth section. [`landed_next`] keeps the real slots.
pub fn landed_slots<E: Endpoint>(
    served: &Served<E>,
    wallet: &Wallet,
    spent: &[(OwnedL2Note, u64)],
) -> Result<Vec<(u32, [u8; 32])>, SendRefusal> {
    use qlab_devnet::annulet::L2Surface;
    use qlab_remote_auth::annulet::AnnuletAuthSection;
    let mut heights: std::collections::BTreeMap<u64, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
    for (n, h) in spent {
        heights.entry(*h).or_default().push(n.nullifier(wallet));
    }
    let mut out = Vec::new();
    for (h, nfs) in heights {
        let bytes = served
            .endpoint
            .get(&format!("/v1/block/{h}/body"))
            .map_err(|why| SendRefusal::Auth(format!("block {h}'s body is unavailable: {why}")))?;
        let ann = qlab_p2p::served::decode_body_answer(qlab_p2p::compact::WireForm::ANNULET_AUTH, h, &bytes)
            .map_err(|e| SendRefusal::Auth(format!("block {h}'s body does not decode: {e}")))?;
        for tx in qlab_p2p::served::body_of(&ann).txs {
            if !tx.public.nullifiers.iter().any(|nf| nfs.contains(nf)) {
                continue;
            }
            let shape = match L2Surface::decode(&tx.l2) {
                Ok(Some(s)) => qlab_devnet::annulet::auth_shape(s.shape),
                _ => return Err(SendRefusal::Auth(format!("a landed spend at height {h} has no surface"))),
            };
            let section = AnnuletAuthSection::decode(shape, &tx.auth)
                .map_err(|e| SendRefusal::Auth(format!("a landed spend at height {h} has no readable auth section: {e:?}")))?; // debug-ok
            out.extend(section.slots.iter().map(|s| (s.descriptor.leaf_index(), s.descriptor.leaf())));
        }
    }
    Ok(out)
}

/// What [`migrate`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrateReport {
    /// The journal was created by this run (a restored or new wallet).
    pub initialized: bool,
    /// The active generation after the run.
    pub active: u32,
    /// Generations swept by this run, with the transactions each took.
    pub swept: Vec<(u32, usize)>,
    /// Generations that must wait: `(g, not_before_height)`.
    pub waiting: Vec<(u32, u64)>,
    /// Generations retired by this run (nothing left to spend).
    pub retired: Vec<u32>,
}

/// **`migrate`** (§9): set the journal up if the wallet has none (restore →
/// migrate); with `open_next`, open a new active generation, the old one
/// becoming sweep-only on this net from `tip + MAX_AUTH_VALIDITY_BLOCKS`;
/// then sweep every sweep-only generation whose gate on this net has passed
/// to the active generation's address 0 — non-zero assets first through the
/// ordinary planner (fee notes from the swept generation), then each asset-0
/// note on its own (paying its own fee). A sweep's cursor starts above every
/// position the generation's landed spends used ([`landed_next`]).
#[allow(clippy::too_many_arguments)]
pub fn migrate<E: Endpoint>(
    w: &WalletDir,
    endpoint: E,
    scan_to: u64,
    pin: Option<[u8; 32]>,
    open_next: bool,
    split_wait: std::time::Duration,
    rng: &mut StdRng,
) -> Result<MigrateReport, SendRefusal> {
    use crate::annulet_send::{open_session, plan_send};
    let session = open_session(w, endpoint, scan_to, pin, rng)?;
    if session.l2_auth != qlab_devnet::forms::L2AuthForm::CandidateA {
        return Err(SendRefusal::Auth("migrate is for a Candidate A net; this one is not".into()));
    }
    let wallet = w.wallet();
    let lock = AuthLock::acquire(&w.dir)?;
    let (mut journal, initialized) = match AuthJournal::load(&w.dir)? {
        Some(j) => (j, false),
        None => (restore_journal(&lock, w, &wallet, &session.owned, &session.genesis_hash, session.tip)?, true),
    };
    if open_next {
        let next_g = journal.generations().iter().map(|r| r.g).max().expect("non-empty") + 1;
        let gate = SweepGate { genesis: session.genesis_hash, not_before_height: session.tip + MAX_AUTH_VALIDITY_BLOCKS };
        journal.open_next(&lock, &w.dir, generation_root(&wallet, next_g), gate)?;
    }
    let active_root = journal.active().auth_root;
    let to_active = me_v2(&wallet, &active_root);
    let mut report = MigrateReport { initialized, active: journal.active().g, swept: Vec::new(), waiting: Vec::new(), retired: Vec::new() };
    let sweeps: Vec<u32> = journal
        .generations()
        .iter()
        .filter(|r| matches!(r.state, GenState::Sweep { .. }))
        .map(|r| r.g)
        .collect();
    drop(lock);
    for g in sweeps {
        // Each generation under the lock, on the journal as it is on disk now.
        let lock = AuthLock::acquire(&w.dir)?;
        let mut j = AuthJournal::load(&w.dir)?.expect("written above");
        let index = session.index.only_generation(g);
        let spendable: Vec<OwnedL2Note> = index.by_asset.values().flat_map(|n| n.spendable.iter().cloned()).collect();
        if spendable.is_empty() {
            j.retire(&lock, &w.dir, g)?;
            report.retired.push(g);
            continue;
        }
        match j.sweep_allowed(g, &session.genesis_hash, session.tip) {
            Ok(()) => {}
            Err(JournalError::SweepNotYet { not_before_height, .. }) => {
                report.waiting.push((g, not_before_height));
                continue;
            }
            Err(JournalError::SweepNoGate { .. }) => {
                let h = session.tip + MAX_AUTH_VALIDITY_BLOCKS;
                j.add_gate(&lock, &w.dir, g, SweepGate { genesis: session.genesis_hash, not_before_height: h })?;
                report.waiting.push((g, h));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        // The cursor above every landed own leaf of g.
        let spent: Vec<(OwnedL2Note, u64)> = index.by_asset.values().flat_map(|n| n.spent.iter().cloned()).collect();
        let landed = landed_slots(&session.served, &wallet, &spent)?;
        let floor = landed_next(&wallet, g, &landed);
        let next = j.get(g)?.next.max(floor);
        j.advance(&lock, &w.dir, g, next)?;
        let mut run = AuthRun::for_generation(lock, j, &wallet, g, next, &session, DEFAULT_VALIDITY_BLOCKS)?;
        let mut txs = 0usize;
        // Non-zero assets: the planner, paying the active generation.
        for (&asset, notes) in &index.by_asset {
            if asset == 0 || notes.spendable.is_empty() {
                continue;
            }
            let amount: u64 = notes.spendable.iter().map(|n| n.note.value).sum();
            let leaf = session.served.registry(u64::from(asset))?.leaf;
            let shape = qlab_l2spend::shape_for(&leaf);
            let plan = plan_send(&index, asset, amount, shape, session.tiers)?;
            txs += plan.steps.len();
            run_plan_v2(w, &mut run, &session, &plan, &to_active, &to_active, &[], split_wait, rng)?;
        }
        // Asset 0, note by note, each paying its own S fee. A note the fee
        // would consume whole is left (dust) and reported by the next scan.
        // Note: the planner above may have spent some asset-0 notes as fees;
        // the session's index predates that, so a fresh scan is the next
        // migrate's job — this pass sweeps only notes it did not just spend.
        if index.by_asset.keys().all(|a| *a == 0) {
            for n in index.spendable(0) {
                if n.note.value <= session.tiers.s {
                    continue;
                }
                let outs = [
                    Out { to: to_active.clone(), value: n.note.value - session.tiers.s, asset: 0 },
                    Out { to: to_active.clone(), value: 0, asset: 0 },
                ];
                spend_v2(w, &mut run, &session.served, L2ShapeTag::S, V2Spend::One(n), &outs, session.tiers.s, &PolicyContext::default(), rng)?;
                txs += 1;
            }
        }
        report.swept.push((g, txs));
    }
    Ok(report)
}

// ---------------------------------------------------------------- issuer

/// **An exact-`tariff` asset-0 fee note of the run's generation** (v1's
/// `exact_fee_note`): one held, or split off a larger one (shape S, its own
/// fee), waited for in the served tree.
pub fn exact_fee_note_v2<E: Endpoint>(
    w: &WalletDir,
    run: &mut AuthRun,
    session: &Session<E>,
    tariff: u64,
    split_wait: std::time::Duration,
    rng: &mut StdRng,
) -> Result<(OwnedL2Note, Option<qlab_note::l2note::L2Note>), SendRefusal> {
    let index = session.index.only_generation(run.generation);
    if let Some(fee) = index.spendable(0).iter().find(|n| n.note.value == tariff) {
        return Ok((fee.clone(), None));
    }
    let split_needs = tariff + session.tiers.s;
    let source = index
        .spendable(0)
        .iter()
        .filter(|n| n.note.value >= split_needs)
        .min_by_key(|n| n.note.value)
        .cloned()
        .ok_or(SendRefusal::NoFeeSource { tariff, split_needs })?;
    let wallet = w.wallet();
    let root = run.auth_root();
    let own = me_v2(&wallet, &root);
    let outs = [
        Out { to: own.clone(), value: tariff, asset: 0 },
        Out { to: own, value: source.note.value - tariff - session.tiers.s, asset: 0 },
    ];
    let split = spend_v2(w, run, &session.served, L2ShapeTag::S, V2Spend::One(&source), &outs, session.tiers.s, &PolicyContext::default(), rng)?;
    let made = split.outputs[0];
    crate::annulet_send::wait_in_tree(&session.served, &made.commitment(), split_wait)?;
    let owned = OwnedL2Note::from_genesis_v2(&wallet, 0, qlab_note::hash::digest_bytes(&made.commitment()), made, &[(run.generation, root)])
        .expect("the split paid the run generation's address 0");
    Ok((owned, Some(made)))
}

/// **A Candidate A registry write** (v1's `registry_write`): the smallest
/// active-generation asset-0 note of at least the R tariff pays; one leaf is
/// taken for its one slot; built, signed and **not** submitted.
pub fn build_registry_write_v2<E: Endpoint>(
    w: &WalletDir,
    run: &mut AuthRun,
    session: &Session<E>,
    leaf: qlab_air::l2::RegistryLeaf,
    isk: [u64; 4],
    rng: &mut StdRng,
) -> Result<qlab_l2spend::v2::BuiltRV2, SendRefusal> {
    let tariff = session.tiers.r;
    let index = session.index.only_generation(run.generation);
    let fee = index
        .spendable(0)
        .iter()
        .filter(|n| n.note.value >= tariff)
        .min_by_key(|n| n.note.value)
        .cloned()
        .ok_or(SendRefusal::NoRegistryFeeNote { tariff })?;
    let wallet = w.wallet();
    let path = run.take_one(&w.dir)?;
    let change = me_v2(&wallet, &run.auth_root());
    let mut built = qlab_l2spend::v2::build_r_v2(&session.served, &real_input(&wallet, &fee, path), &change, tariff, leaf, isk, rng)?;
    run.sign(&mut built.tx, &built.auth.clone(), &[])?;
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};

    fn wallet_dir(tag: &str, seed: u8) -> WalletDir {
        let dir = std::env::temp_dir().join(format!("qmb_g_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        WalletDir::create(&dir, MasterSeed::from_entropy([seed; ENTROPY_LEN])).unwrap()
    }

    /// A note of generation `g` at address 0 (only its generation and value
    /// matter to the journal's restore rule).
    fn note_of(w: &Wallet, g: u32, value: u64, k: u8) -> OwnedL2Note {
        let root = generation_root(w, g);
        let rkm = w.address_candidate_a_at_index(0, &root).rkm_lanes();
        let note = qlab_note::l2note::L2Note { value, asset: 0, rkm, rho: [k as u64; 4], rseed: [k as u64 + 1; 4] };
        OwnedL2Note::from_genesis_v2(w, 0, [k; 32], note, &[(g, root)]).expect("its own v2 note")
    }

    /// The journal's cached root is the tree `LocalAuth` signs with: the
    /// address a wallet hands out is the one its keys can spend.
    #[test]
    fn generation_root_is_local_auths() {
        let w = wallet_dir("root", 3);
        let wallet = w.wallet();
        for g in [0u32, 1] {
            let la = LocalAuth::new(&wallet.auth_secret(), g, 0).unwrap();
            assert_eq!(generation_root(&wallet, g), la.auth_root(), "generation {g}");
        }
        assert_ne!(generation_root(&wallet, 0), generation_root(&wallet, 1));
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// A v2 note is owned only under its own generation's root, and the
    /// generation is recorded; `only_generation` keeps exactly its notes.
    #[test]
    fn notes_are_owned_per_generation() {
        let w = wallet_dir("own", 4);
        let wallet = w.wallet();
        let n1 = note_of(&wallet, 1, 5, 1);
        assert_eq!(n1.generation, Some(1));
        let root0 = generation_root(&wallet, 0);
        assert!(
            OwnedL2Note::from_genesis_v2(&wallet, 0, [1; 32], n1.note, &[(0, root0)]).is_err(),
            "not generation 0's"
        );
        assert!(OwnedL2Note::from_genesis(&wallet, 0, [1; 32], n1.note).is_err(), "not a v1 note");
        let set = qlab_ledger::spent::SpentSet::from_parts(Some((0, 0)), Vec::<(u64, [u8; 32])>::new());
        let index = qlab_ledger::assets::AssetIndex::build(&wallet, vec![note_of(&wallet, 0, 7, 2), n1], &set);
        assert_eq!(index.only_generation(1).spendable(0).len(), 1);
        assert_eq!(index.only_generation(1).spendable(0)[0].note.value, 5);
        assert_eq!(index.only_generation(0).spendable(0)[0].note.value, 7);
        assert!(index.only_generation(2).spendable(0).is_empty());
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// §9: a restored wallet never resumes. Notes in generations 0 and 2 →
    /// generation 3 active; 0 and 2 sweep-only on this net from tip + cap;
    /// generation 1 (no notes) is not recorded. No notes at all → generation
    /// 0, fresh. Notes in the last probed generation → refused by name.
    #[test]
    fn restore_opens_the_generation_above_every_one_with_notes() {
        let w = wallet_dir("restore", 5);
        let wallet = w.wallet();
        let lock = AuthLock::acquire(&w.dir).unwrap();
        let genesis = [0x33; 32];
        let owned = [note_of(&wallet, 0, 1, 1), note_of(&wallet, 2, 1, 2)];
        let j = restore_journal(&lock, &w, &wallet, &owned, &genesis, 500).unwrap();
        assert_eq!(j.active().g, 3);
        assert_eq!(j.active().next, 0);
        assert_eq!(j.active().auth_root, generation_root(&wallet, 3));
        let gate = vec![SweepGate { genesis, not_before_height: 500 + MAX_AUTH_VALIDITY_BLOCKS }];
        assert_eq!(j.get(0).unwrap().state, GenState::Sweep { gates: gate.clone() });
        assert_eq!(j.get(2).unwrap().state, GenState::Sweep { gates: gate });
        assert!(j.get(1).is_err(), "a generation with no notes is not recorded");
        assert_eq!(AuthJournal::load(&w.dir).unwrap(), Some(j), "persisted");
        std::fs::remove_file(w.dir.join(crate::auth_journal::AUTH_FILE)).unwrap();

        let fresh = restore_journal(&lock, &w, &wallet, &[], &genesis, 500).unwrap();
        assert_eq!(fresh.active().g, 0, "no notes: nothing was ever exported");
        assert_eq!(fresh.generations().len(), 1);

        let last = crate::auth_journal::PROBE_GENERATIONS - 1;
        let edge = [note_of(&wallet, last, 1, 9)];
        assert!(matches!(
            restore_journal(&lock, &w, &wallet, &edge, &genesis, 500),
            Err(SendRefusal::Auth(why)) if why.contains("last of the")
        ));
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// The sweep cursor restarts above the highest **position** a landed own
    /// leaf holds in the private permutation — not above the highest leaf
    /// index. A slot whose leaf is not the generation's (a dummy's) is
    /// ignored.
    #[test]
    fn landed_next_is_a_permutation_position() {
        use qlab_remote_auth::annulet::{auth_master, AuthTree, Cursor};
        let w = wallet_dir("landed", 6);
        let wallet = w.wallet();
        let master = auth_master(&wallet.auth_secret(), 0);
        let tree = AuthTree::build(&master, D_AUTH).unwrap();
        let mut c = Cursor::new(&master, D_AUTH, 0).unwrap();
        let drawn: Vec<u32> = (0..5).map(|_| c.take().unwrap()).collect();
        assert_eq!(landed_next(&wallet, 0, &[]), 0);
        // Positions 1 and 3 landed (out of order), plus a dummy slot.
        let landed = [
            (drawn[3], tree.leaf(drawn[3])),
            (drawn[1], tree.leaf(drawn[1])),
            (drawn[0], [0xEE; 32]),
        ];
        assert_eq!(landed_next(&wallet, 0, &landed), 4, "position 3 + 1, whatever the indices");
        // Only position 1 landed: the cursor restarts at 2.
        assert_eq!(landed_next(&wallet, 0, &[(drawn[1], tree.leaf(drawn[1]))]), 2);
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// A Candidate A address is version 2 and binds the generation's root.
    #[test]
    fn me_v2_pays_the_generations_address_0() {
        let w = wallet_dir("me", 7);
        let wallet = w.wallet();
        let root = generation_root(&wallet, 0);
        let r = me_v2(&wallet, &root);
        let a = wallet.address_candidate_a_at_index(0, &root);
        assert_eq!(a.version, qlab_wallet::address::ADDRESS_VERSION_CANDIDATE_A);
        assert_eq!(r.rkm, a.rkm_lanes());
        assert_ne!(r.rkm, wallet.address_at_index(0).rkm_lanes(), "not the v1 address");
        let _ = std::fs::remove_dir_all(&w.dir);
    }
}
