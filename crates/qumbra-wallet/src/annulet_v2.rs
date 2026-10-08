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
//! 4. the v2 builder prepares the transaction, its proof still empty;
//!    `intent_for` rebuilds the intent from it (valid until the verified
//!    tip plus [`DEFAULT_VALIDITY_BLOCKS`]); `sign_locally` signs every slot and the
//!    section is attached — **signed before it is proved** (the intent never
//!    covers the proof);
//! 5. the prover fills the proof — in this process, or (lab #924 seam G
//!    split) a worker handed a [`ProvingBundle`] ([`prepare_v2`] →
//!    [`prove_bundle_v2`] → [`assemble_and_submit`]) — and the transaction is
//!    submitted.

use qlab_air::l2::{L2AuthInput, L2AuthPath};
use qlab_air::l2p::VPublic;
use qlab_devnet::annulet::{AuthContext, L2ShapeTag, MAX_AUTH_VALIDITY_BLOCKS};
use qlab_devnet::body::TxEntry;
use qlab_l2spend::bundle::ProvingBundle;
use qlab_l2spend::v2::{
    attach, intent_for, prepare_p_v2, prepare_s_v2, prove_prepared, sign_locally, BuiltV2, FeeIn, LocalAuth,
    PreparedV2,
};
use qlab_l2spend::{Endpoint, Out, PolicyContext, Recipient, Served, SpendError};
use qlab_ledger::assets::OwnedL2Note;
use qlab_remote_auth::annulet::D_AUTH;
use qlab_wallet::Wallet;
use rand::rngs::StdRng;

use crate::annulet_send::{SendRefusal, Session};
use crate::auth_journal::{generation_root, AuthJournal, AuthLock, GenState, JournalError, SweepGate};
use crate::store::WalletDir;
pub use crate::annulet_landed::{landed_next, restore_generations, slots_of, LandedByGeneration};

/// The validity a Candidate A transaction is signed with: it may land up to
/// this many blocks past the verified tip (design 2b §10 decided 4, Phase 4's
/// suggested default). Well inside the consensus cap.
pub const DEFAULT_VALIDITY_BLOCKS: u64 = 256;
const _: () = assert!(DEFAULT_VALIDITY_BLOCKS <= MAX_AUTH_VALIDITY_BLOCKS);

/// The validity this process signs with: [`DEFAULT_VALIDITY_BLOCKS`] unless
/// the CLI's `--valid-for N` set it ([`set_valid_for`]) for this one command.
static VALID_FOR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(DEFAULT_VALIDITY_BLOCKS);

/// Set the validity this process's Candidate A writes sign with (the CLI's
/// `--valid-for`). Checked against the consensus cap when a run opens.
pub fn set_valid_for(blocks: u64) {
    VALID_FOR.store(blocks, std::sync::atomic::Ordering::Relaxed);
}

/// The validity a run signs with now.
pub fn valid_for() -> u64 {
    VALID_FOR.load(std::sync::atomic::Ordering::Relaxed)
}

/// A validity in `1..=MAX_AUTH_VALIDITY_BLOCKS`, or refused by name — every
/// run (an ordinary send, an issuer write, a sweep) checks it.
pub fn check_validity(validity: u64) -> Result<(), SendRefusal> {
    if validity == 0 || validity > MAX_AUTH_VALIDITY_BLOCKS {
        return Err(SendRefusal::Auth(format!(
            "a validity of {validity} blocks is outside 1..={MAX_AUTH_VALIDITY_BLOCKS} (the consensus cap)"
        )));
    }
    Ok(())
}

pub use crate::annulet_plan::SWEEP_FLOOR_EXTRA;

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
    auth_ctx: AuthContext,
    /// The last height the run's transactions may land at.
    pub valid_until: u64,
}

impl AuthRun {
    /// Open the active generation's keys for a run on `session`'s net. A
    /// wallet with no journal is a restored (or new-to-Candidate-A) one: it
    /// is migrated first ([`restore_journal`]).
    pub fn open<E: Endpoint>(w: &WalletDir, session: &Session<E>, validity: u64) -> Result<Self, SendRefusal> {
        check_validity(validity)?;
        let lock = AuthLock::acquire(&w.dir)?;
        let wallet = w.wallet();
        let journal = match AuthJournal::load(&w.dir)? {
            Some(j) => j,
            None => {
                let used = landed_generations(session, &wallet)?;
                restore_journal(&lock, w, &wallet, &session.owned, &used, &session.genesis_hash, session.gate_tip)?
            }
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
        check_validity(validity)?;
        let keys = LocalAuth::new(&wallet.auth_secret(), g, next).map_err(SendRefusal::Auth)?;
        if keys.auth_root() != journal.get(g)?.auth_root {
            return Err(SendRefusal::Auth(format!(
                "auth.v1's root for generation {g} is not this wallet's tree: the journal was edited or belongs to \
                 another seed — refusing to sign with it"
            )));
        }
        Ok(AuthRun {
            lock,
            journal,
            generation: g,
            keys,
            genesis_hash: session.genesis_hash,
            genesis_format: session.l2_auth.annulet_genesis_format_version(),
            auth_ctx: AuthContext { form: session.l2_auth, genesis_hash: session.genesis_hash },
            valid_until: session.tip.saturating_add(validity),
        })
    }

    /// The active generation's root: what this wallet's change and its new
    /// addresses bind.
    pub fn auth_root(&self) -> [u64; 4] {
        self.keys.auth_root()
    }

    /// The net this run signs for, as a prover's lock checks it.
    pub fn auth_context(&self) -> AuthContext {
        self.auth_ctx
    }

    /// Unconsumed leaves left in the run's generation.
    pub fn remaining(&self) -> u32 {
        (1u32 << D_AUTH) - self.keys.next()
    }

    /// Refuse, before anything is taken, a run that needs `needed` real
    /// slots when fewer remain; and for an ordinary send (`keep = Some(n)`,
    /// `n` the generation's spendable notes) one that would leave fewer than
    /// `n + SWEEP_FLOOR_EXTRA`, so the generation can still be swept.
    pub fn check_budget(&self, needed: u32, keep: Option<u32>) -> Result<(), SendRefusal> {
        let remaining = self.remaining();
        if needed > remaining {
            return Err(SendRefusal::Auth(format!(
                "this needs {needed} authorizations and generation {} has {remaining} left; run `qumbra-wallet \
                 migrate --open-next`",
                self.generation
            )));
        }
        if let Some(notes) = keep {
            let floor = notes.saturating_add(SWEEP_FLOOR_EXTRA);
            if remaining - needed < floor {
                return Err(SendRefusal::Auth(format!(
                    "generation {} would keep {} authorizations, below the {floor} needed to sweep its {notes} \
                     note(s); run `qumbra-wallet migrate --open-next` and send from the new generation",
                    self.generation,
                    remaining - needed
                )));
            }
        }
        Ok(())
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

pub use crate::annulet_plan::real_input;

/// This wallet's change recipient on a Candidate A net: address 0 of the
/// active generation.
pub fn me_v2(wallet: &Wallet, auth_root: &[u64; 4]) -> Recipient {
    let addr = wallet.address_candidate_a_at_index(0, auth_root);
    Recipient { rkm: addr.rkm_lanes(), ek: addr.encapsulation_key().expect("the wallet's own address has an ek") }
}

/// Every input of one transaction is of generation `g` — the run's keys
/// (design 2b §5: one key per transaction), refused by name otherwise.
pub fn one_generation(notes: &[&OwnedL2Note], g: u32) -> Result<(), SendRefusal> {
    match notes.iter().find(|n| n.generation != Some(g)) {
        None => Ok(()),
        Some(n) => Err(SendRefusal::Auth(format!(
            "a note of generation {:?} cannot be spent beside generation {g}'s keys (one key per transaction)",
            n.generation
        ))),
    }
}

pub use crate::annulet_plan::plan_slots;

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
///
/// A holder spend runs the seam G chain in this process — [`prepare_v2`],
/// [`prove_bundle_v2`] (the bundle's lock, then the proof), [`assemble_v2`]
/// — so the CLI path checks what a remote prover checks. An issuer
/// operation ([`is_issuer_operation`]) never becomes a bundle: it is
/// prepared, signed and proved here directly.
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
    if is_issuer_operation(ctx, vp) {
        return Ok(prove_prepared(prepare_signed(w, run, served, shape, spend, outs, fee, ctx, vp, rng)?));
    }
    let prepared = prepare_v2(w, run, served, shape, spend, outs, fee, ctx, vp, rng)?;
    let proved = prove_bundle_v2(&prepared.bundle, &run.auth_context())?;
    assemble_v2(prepared, proved)
}

/// An issuer operation: a P row with an issuer secret, or a non-zero
/// `vPublic` term. It is not delegated (design "Issuer authority is out of
/// scope for delegation"; lab #924 5A-D3).
pub fn is_issuer_operation(ctx: [&PolicyContext; 2], vp: [VPublic; 2]) -> bool {
    ctx.iter().any(|c| c.isk != [0; 4]) || vp.iter().any(|v| v.amount != 0 || v.redeem)
}

/// **Lab #924 seam G, the device half**: everything [`build_spend_v2`] does
/// but the proof — leaves taken and persisted, dummies drawn, the
/// transaction prepared and **signed** — handed out as a [`ProvingBundle`]
/// for a prover that is not this process. A holder spend only: an issuer
/// operation (a P row with an issuer secret or a non-zero `vPublic`) is
/// refused **before any leaf is taken** and stays on [`build_spend_v2`]'s
/// in-process path.
#[allow(clippy::too_many_arguments)]
pub fn prepare_v2<E: Endpoint>(
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
) -> Result<PreparedSpendV2, SendRefusal> {
    if is_issuer_operation(ctx, vp) {
        return Err(SendRefusal::Auth(
            "an issuer operation (an issuer secret or a non-zero vPublic) is not delegated to a prover".into(),
        ));
    }
    let p = prepare_signed(w, run, served, shape, spend, outs, fee, ctx, vp, rng)?;
    let bundle = ProvingBundle::new(p.tx, p.witness).map_err(|e| SendRefusal::Auth(e.to_string()))?;
    Ok(PreparedSpendV2 { bundle, pvs: p.pvs, auth: p.auth, outputs: p.outputs, shape: p.shape })
}

/// A prepared, signed spend: the bundle a prover is handed and what the
/// device keeps to accept the proved transaction back.
#[derive(Clone)]
pub struct PreparedSpendV2 {
    pub bundle: ProvingBundle,
    pub pvs: Vec<u32>,
    pub auth: Vec<qlab_remote_auth::intent::AuthDescriptor>,
    /// The output notes: two (format 33) or three (format 34, the third a
    /// zero-value note to this wallet — [`prepare_signed`]).
    pub outputs: Vec<qlab_note::l2note::L2Note>,
    pub shape: L2ShapeTag,
}

/// **The worker half**: the bundle's lock ([`ProvingBundle::check`] — the
/// witness states the transaction and the section verifies on the net `ctx`
/// names), then the proof. The proved transaction, nothing else changed.
pub fn prove_bundle_v2(bundle: &ProvingBundle, ctx: &AuthContext) -> Result<TxEntry, SendRefusal> {
    bundle.prove(ctx).map_err(|e| SendRefusal::Auth(e.to_string()))
}

/// **The device's acceptance**: `proved` must be the bundle's transaction
/// with a proof added and nothing else changed — every other wire byte, the
/// signed section included — before it is submitted. (The node verifies the
/// proof against the PVs the section's intent binds.)
pub fn assemble_v2(prepared: PreparedSpendV2, proved: TxEntry) -> Result<BuiltV2, SendRefusal> {
    // The wire encoder asserts a surface and no rider: refuse a prover's
    // transaction without them by name, before encoding it.
    if proved.rider != qlab_devnet::names::RIDER_ABSENT || proved.l2 == qlab_devnet::annulet::L2_SURFACE_ABSENT {
        return Err(SendRefusal::Auth(
            "the prover returned a transaction with a rider or without its surface — not submitted".into(),
        ));
    }
    let mut stripped = proved.clone();
    stripped.proof = Vec::new();
    if proved.proof.is_empty()
        || qlab_p2p::codec::encode_tx_annulet(&stripped) != qlab_p2p::codec::encode_tx_annulet(prepared.bundle.tx())
    {
        return Err(SendRefusal::Auth(
            "the prover returned a transaction other than the bundle's with a proof added — not submitted".into(),
        ));
    }
    Ok(BuiltV2 { tx: proved, pvs: prepared.pvs, auth: prepared.auth, outputs: prepared.outputs, shape: prepared.shape })
}

/// [`assemble_v2`], then submit.
pub fn assemble_and_submit<E: Endpoint>(
    served: &Served<E>,
    prepared: PreparedSpendV2,
    proved: TxEntry,
) -> Result<BuiltV2, SendRefusal> {
    let built = assemble_v2(prepared, proved)?;
    served.submit(&built.tx)?;
    Ok(built)
}

/// Take, draw the dummies, prepare and sign: the proof still empty.
#[allow(clippy::too_many_arguments)]
fn prepare_signed<E: Endpoint>(
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
) -> Result<PreparedV2, SendRefusal> {
    let wallet = w.wallet();
    let notes: Vec<&OwnedL2Note> = match &spend {
        V2Spend::One(a) => vec![*a],
        V2Spend::Two(xs) => xs.to_vec(),
        V2Spend::TwoAndFee(xs, f) => vec![xs[0], xs[1], *f],
    };
    one_generation(&notes, run.generation)?;
    let paths = run.take(&w.dir, notes.len())?;
    let taken: Vec<u32> = paths.iter().map(|p| p.leaf_index).collect();
    let real: Vec<L2AuthInput> = notes.iter().zip(paths).map(|(n, p)| real_input(&wallet, n, p)).collect();
    // Lab #937: on a format-34 net every S/P spend carries a third output.
    // Here it is a zero-value note (D3: an ordinary note, indistinguishable
    // from a paying one) to where this spend's change goes — `outs[1].to`,
    // the active generation's change address, never the run generation's
    // (a sweep must not leave a note behind in the generation it empties) —
    // in input 1's asset: the AIR binds output 3's asset to an input's
    // (`o3a`). The wallet never spends a zero-value note
    // (`AssetIndex::zero`). The prover-fee third output is lab #937 PR D's.
    let outs: Vec<Out> = match run.auth_context().form.sp_outputs() {
        2 => outs.to_vec(),
        3 => {
            let mut v = outs.to_vec();
            v.push(Out { to: outs[1].to.clone(), value: 0, asset: real[0].asset });
            v
        }
        n => unreachable!("an S/P spend carries two or three outputs, not {n}"),
    };
    let outs = outs.as_slice();
    let (mut prepared, keys) = match (shape, &spend) {
        (L2ShapeTag::S, V2Spend::One(_)) => {
            let (d2, k2) = run.dummy(1, &taken)?;
            let (d3, k3) = run.dummy(2, &[taken.as_slice(), &[d2.auth.leaf_index]].concat())?;
            (prepare_s_v2(served, [&real[0], &d2], true, FeeIn::Dummy(&d3), outs, fee, rng)?, vec![k2, k3])
        }
        (L2ShapeTag::S, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            (prepare_s_v2(served, [&real[0], &real[1]], false, FeeIn::Dummy(&d3), outs, fee, rng)?, vec![k3])
        }
        (L2ShapeTag::S, V2Spend::TwoAndFee(..)) => {
            (prepare_s_v2(served, [&real[0], &real[1]], false, FeeIn::Exact(&real[2]), outs, fee, rng)?, vec![])
        }
        (L2ShapeTag::P, V2Spend::Two(_)) => {
            let (d3, k3) = run.dummy(2, &taken)?;
            (prepare_p_v2(served, [&real[0], &real[1]], FeeIn::Dummy(&d3), outs, fee, ctx, vp, rng)?, vec![k3])
        }
        (L2ShapeTag::P, V2Spend::TwoAndFee(..)) => (
            prepare_p_v2(served, [&real[0], &real[1]], FeeIn::Exact(&real[2]), outs, fee, [ctx[0], ctx[0]], vp, rng)?,
            vec![],
        ),
        (L2ShapeTag::P, V2Spend::One(_)) => {
            return Err(SendRefusal::Spend(SpendError::Served(
                "a one-input shape-P spend has no v2 builder (P proves two real inputs)".into(),
            )))
        }
        (L2ShapeTag::R, _) => {
            return Err(SendRefusal::Spend(SpendError::Served("shape R is a registry write, not a spend".into())))
        }
    };
    let dummies: Vec<&qlab_remote_auth::mldsa::Key> = keys.iter().collect();
    run.sign(&mut prepared.tx, &prepared.auth.clone(), &dummies)?;
    Ok(prepared)
}

/// **Restore → migrate** (§9) for a wallet with no `auth.v1`: no generation
/// it has used is ever resumed. A generation is **used** if the verified
/// scan found a note of it (`owned`, spent or not) or if a landed
/// transaction carries one of its leaves (`used`, from
/// [`landed_generations`] — this catches a generation whose notes sit at
/// addresses the restored wallet has not allocated). `g*` is the highest used
/// generation; `g* + 1` opens as the active one; every used generation with
/// notes becomes sweep-only, gated on this net at `gate_tip +
/// MAX_AUTH_VALIDITY_BLOCKS` (`gate_tip` an upper bound on the real tip, by
/// which every authorization exported before the loss has expired). A wallet
/// with no used generation starts at generation 0.
///
/// **What stays undetectable, inherently:** a generation that exported an
/// authorization which never landed, and holds no note this scan sees. And,
/// as for v1, notes at diversifier indices the restored wallet has not
/// allocated are not scanned (the wallet's existing restore limitation).
///
/// Every used generation's cursor is recorded **above** every position its
/// landed spends used ([`landed_next`] over the slots `used` carries for it),
/// so the journal a restore writes states the positions the chain shows. A
/// generation with notes is sweep-only; a used one with none left is
/// retired, its position kept (a leaf of it is never drawn again). The sweep
/// still takes `max(journal, landed_next)` as its floor.
pub fn restore_journal(
    lock: &AuthLock,
    w: &WalletDir,
    wallet: &Wallet,
    owned: &[OwnedL2Note],
    used: &LandedByGeneration,
    genesis: &[u8; 32],
    gate_tip: u64,
) -> Result<AuthJournal, SendRefusal> {
    let journal = restore_generations(wallet, owned, used, genesis, gate_tip)?;
    journal.save(&w.dir)?;
    let _ = lock;
    Ok(journal)
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
) -> Result<Vec<(Vec<qlab_note::l2note::L2Note>, L2ShapeTag)>, SendRefusal> {
    use crate::annulet_send::{wait_in_tree, Src, StepKind};
    let wallet = w.wallet();
    let served = &session.served;
    let s_tier = session.tiers.s;
    let a = u64::from(plan.asset);
    let ctx = PolicyContext { freeze_keys: freeze_keys.to_vec(), ..Default::default() };
    // Every leaf the plan takes, before step 1: a split must not land and
    // leave the payment without one.
    run.check_budget(plan_slots(plan), None)?;
    let own_root = run.auth_root();
    let own = me_v2(&wallet, &own_root);
    let gens = [(run.generation, own_root)];
    let mut made: Vec<Option<(Vec<qlab_note::l2note::L2Note>, L2ShapeTag)>> = vec![None; plan.steps.len()];
    let owned = |made: &[Option<(Vec<qlab_note::l2note::L2Note>, L2ShapeTag)>], src: &Src| -> OwnedL2Note {
        match src {
            Src::Held(n) => n.clone(),
            Src::Made { step, out, .. } => {
                let note = made[*step].as_ref().expect("a step spends only notes of earlier rounds").0[*out];
                OwnedL2Note::from_genesis_v2(&wallet, 0, qlab_note::hash::digest_bytes(&note.commitment()), note, &gens)
                    .expect("a planned note was paid to the run generation's address 0")
            }
        }
    };
    for round in 0..plan.rounds() {
        for (i, st) in plan.steps.iter().enumerate().filter(|(_, s)| s.round == round) {
            // Lab #937: a planned third output (the prover fee) is PR D's;
            // until then the third output is prepare_signed's zero-value
            // self note, and a plan naming one is refused by name.
            if st.third.is_some() {
                return Err(SendRefusal::Auth("a planned third output (a prover fee) is not built here yet (lab #937 PR D)".into()));
            }
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
                        let note = made[*step].as_ref().expect("made this round").0[*out];
                        wait_in_tree(served, &note.commitment(), split_wait)?;
                    }
                }
            }
        }
    }
    Ok(made.into_iter().map(|m| m.expect("every step ran")).collect())
}

/// The body of block `height`, **bound to the verified header**: decoded in
/// the Candidate A frame, its header the verified one, its counts within the
/// commitment's bytes, and its `tx_body_commitment` recomputed. A sweep
/// floor or a restore's used generations rest on it, so an endpoint's word
/// is never enough.
pub fn verified_body<E: Endpoint>(session: &Session<E>, height: u64) -> Result<qlab_devnet::body::BlockBody, SendRefusal> {
    let header = session
        .chain
        .header(height)
        .ok_or_else(|| SendRefusal::Auth(format!("height {height} is above the verified tip")))?;
    let bytes = session
        .served
        .endpoint
        .get(&format!("/v1/block/{height}/body"))
        .map_err(|why| SendRefusal::Auth(format!("block {height}'s body is unavailable: {why}")))?;
    bind_body(&header, session.chain.genesis.l2_auth, height, &bytes)
}

/// [`verified_body`]'s binding of served `bytes` to the verified `header`
/// ([`crate::annulet_landed::bind_body`], refusals in this module's terms).
pub fn bind_body(
    header: &qlab_devnet::header::BlockHeader,
    l2_auth: qlab_devnet::forms::L2AuthForm,
    height: u64,
    bytes: &[u8],
) -> Result<qlab_devnet::body::BlockBody, SendRefusal> {
    use crate::annulet_landed::BodyRefusal;
    crate::annulet_landed::bind_body(header, l2_auth, height, bytes).map_err(|e| match e {
        BodyRefusal::Counts(v) => SendRefusal::Verify(v),
        other => SendRefusal::Auth(format!("block {height}'s body {other}")),
    })
}


/// The `(leaf_index, leaf)` of every slot of every landed transaction that
/// spent one of `spent` (a generation's spent notes with their heights),
/// read from **verified** bodies ([`verified_body`]). [`landed_next`] keeps
/// the real slots.
pub fn landed_slots<E: Endpoint>(
    session: &Session<E>,
    wallet: &Wallet,
    spent: &[(OwnedL2Note, u64)],
) -> Result<Vec<(u32, [u8; 32])>, SendRefusal> {
    let mut heights: std::collections::BTreeMap<u64, Vec<[u8; 32]>> = std::collections::BTreeMap::new();
    for (n, h) in spent {
        heights.entry(*h).or_default().push(n.nullifier(wallet));
    }
    let mut out = Vec::new();
    for (h, nfs) in heights {
        for tx in verified_body(session, h)?.txs {
            if tx.public.nullifiers.iter().any(|nf| nfs.contains(nf)) {
                // A spend of ours with no readable section would silently
                // lower the sweep floor: refused by name, never skipped.
                let slots = slots_of(&tx).ok_or_else(|| {
                    SendRefusal::Auth(format!("a landed spend of this wallet at height {h} has no readable auth section"))
                })?;
                out.extend(slots);
            }
        }
    }
    Ok(out)
}


/// The probe generations (`0 .. PROBE_GENERATIONS`) whose leaves appear in
/// any landed transaction on the verified chain, each with the slots that
/// matched it — hash compares against each generation's tree, no
/// decryption; a dummy's leaf never matches. One verified body per block, so
/// a restore reads the whole chain once.
pub fn landed_generations<E: Endpoint>(session: &Session<E>, wallet: &Wallet) -> Result<LandedByGeneration, SendRefusal> {
    use qlab_remote_auth::annulet::{auth_master, AuthTree};
    let trees: Vec<(u32, AuthTree)> = (0..crate::auth_journal::PROBE_GENERATIONS)
        .map(|g| (g, AuthTree::build(&auth_master(&wallet.auth_secret(), g), D_AUTH).expect("D_AUTH is a valid depth")))
        .collect();
    let mut used = LandedByGeneration::new();
    for h in 1..=session.chain.tip() {
        for tx in verified_body(session, h)?.txs {
            // Not ours to judge here: a transaction with no readable section
            // has no leaf of any generation of this wallet.
            for (index, leaf) in slots_of(&tx).unwrap_or_default() {
                if (index as usize) >= (1usize << D_AUTH) {
                    continue;
                }
                for (g, tree) in &trees {
                    if tree.leaf(index) == leaf {
                        used.entry(*g).or_default().push((index, leaf));
                    }
                }
            }
        }
    }
    Ok(used)
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
    /// Swept generations whose asset-0 notes this run left: a generation
    /// holding other assets too sweeps those first (their fees come from its
    /// asset-0 notes), and its asset 0 on the next `migrate`.
    pub asset0_left: Vec<u32>,
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
    if !session.l2_auth.has_auth() {
        return Err(SendRefusal::Auth("migrate is for a Candidate A net; this one is not".into()));
    }
    let wallet = w.wallet();
    let lock = AuthLock::acquire(&w.dir)?;
    let (mut journal, initialized) = match AuthJournal::load(&w.dir)? {
        Some(j) => (j, false),
        None => {
            let used = landed_generations(&session, &wallet)?;
            (restore_journal(&lock, w, &wallet, &session.owned, &used, &session.genesis_hash, session.gate_tip)?, true)
        }
    };
    if open_next {
        let next_g = journal.generations().iter().map(|r| r.g).max().expect("non-empty") + 1;
        let gate = SweepGate {
            genesis: session.genesis_hash,
            not_before_height: session.gate_tip.saturating_add(MAX_AUTH_VALIDITY_BLOCKS),
        };
        journal.open_next(&lock, &w.dir, generation_root(&wallet, next_g), gate)?;
    }
    let active_root = journal.active().auth_root;
    let to_active = me_v2(&wallet, &active_root);
    let mut report = MigrateReport {
        initialized,
        active: journal.active().g,
        swept: Vec::new(),
        waiting: Vec::new(),
        retired: Vec::new(),
        asset0_left: Vec::new(),
    };
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
        let mut j = AuthJournal::load(&w.dir)?
            .ok_or_else(|| SendRefusal::Auth("auth.v1 disappeared while migrating".into()))?;
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
                let h = session.gate_tip.saturating_add(MAX_AUTH_VALIDITY_BLOCKS);
                j.add_gate(&lock, &w.dir, g, SweepGate { genesis: session.genesis_hash, not_before_height: h })?;
                report.waiting.push((g, h));
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        // The cursor above every landed own leaf of g.
        let spent: Vec<(OwnedL2Note, u64)> = index.by_asset.values().flat_map(|n| n.spent.iter().cloned()).collect();
        let landed = landed_slots(&session, &wallet, &spent)?;
        let floor = landed_next(&wallet, g, &landed);
        let next = j.get(g)?.next.max(floor);
        j.advance(&lock, &w.dir, g, next)?;
        let mut run = AuthRun::for_generation(lock, j, &wallet, g, next, &session, valid_for())?;
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
        // Asset 0, note by note, each paying its own S fee. No up-front budget
        // check here: each note takes one leaf, and a generation that runs out
        // fails by name (`Exhausted`) at that note, nothing half-signed. A note the fee
        // would consume whole is left (dust) and reported by the next scan.
        // Note: the planner above may have spent some asset-0 notes as fees;
        // the session's index predates that, so a fresh scan is the next
        // migrate's job — this pass sweeps only notes it did not just spend.
        if !index.by_asset.keys().all(|a| *a == 0) && !index.spendable(0).is_empty() {
            report.asset0_left.push(g);
        }
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
    /// generation 1 (no notes, no landed leaf) is not recorded. No notes at
    /// all → generation 0, fresh. A generation seen through landed leaves is
    /// recorded at its landed floor (retired when it holds no note). Notes in
    /// the last probed generation → refused by name.
    #[test]
    fn restore_opens_the_generation_above_every_one_with_notes() {
        let w = wallet_dir("restore", 5);
        let wallet = w.wallet();
        let lock = AuthLock::acquire(&w.dir).unwrap();
        let genesis = [0x33; 32];
        let owned = [note_of(&wallet, 0, 1, 1), note_of(&wallet, 2, 1, 2)];
        let none = LandedByGeneration::new();
        let j = restore_journal(&lock, &w, &wallet, &owned, &none, &genesis, 500).unwrap();
        assert_eq!(j.active().g, 3);
        assert_eq!(j.active().next, 0);
        assert_eq!(j.active().auth_root, generation_root(&wallet, 3));
        let gate = vec![SweepGate { genesis, not_before_height: 500 + MAX_AUTH_VALIDITY_BLOCKS }];
        assert_eq!(j.get(0).unwrap().state, GenState::Sweep { gates: gate.clone() });
        assert_eq!(j.get(2).unwrap().state, GenState::Sweep { gates: gate });
        assert!(j.get(1).is_err(), "a generation with no notes is not recorded");
        assert_eq!(AuthJournal::load(&w.dir).unwrap(), Some(j), "persisted");
        std::fs::remove_file(w.dir.join(crate::auth_journal::AUTH_FILE)).unwrap();

        let fresh = restore_journal(&lock, &w, &wallet, &[], &none, &genesis, 500).unwrap();
        assert_eq!(fresh.active().g, 0, "no notes: nothing was ever exported");
        assert_eq!(fresh.generations().len(), 1);
        std::fs::remove_file(w.dir.join(crate::auth_journal::AUTH_FILE)).unwrap();

        // A generation seen only through its landed leaves (its notes at an
        // unallocated address, or spent) is used too: notes in 0 with two
        // landed leaves, three leaves landed in 4 → generation 5 active; 0
        // sweep-only and 4 retired, each at its landed floor — not 0.
        let leaves = |g: u32, n: usize| -> Vec<(u32, [u8; 32])> {
            let mut la = LocalAuth::new(&wallet.auth_secret(), g, 0).unwrap();
            (0..n)
                .map(|_| {
                    let p = la.take().unwrap();
                    (p.leaf_index, qlab_note::hash::digest_bytes(&p.leaf))
                })
                .collect()
        };
        let landed: LandedByGeneration = [(0, leaves(0, 2)), (4, leaves(4, 3))].into();
        let j = restore_journal(&lock, &w, &wallet, &owned[..1], &landed, &genesis, 500).unwrap();
        assert_eq!(j.active().g, 5, "the generation above every used one");
        assert_eq!((j.get(0).unwrap().next, j.get(4).unwrap().next), (2, 3), "the landed floors");
        assert!(matches!(j.get(0).unwrap().state, GenState::Sweep { .. }));
        assert_eq!(j.get(4).unwrap().state, GenState::Retired, "no note of 4 to sweep: retired at its floor");
        assert!(j.get(1).is_err());
        std::fs::remove_file(w.dir.join(crate::auth_journal::AUTH_FILE)).unwrap();

        // Lab #937: a zero-value note (a format-34 third output) is never
        // swept. Generation 0 holds only one and has landed leaves → retired,
        // not sweep-only; generation 2 holds only one and nothing landed →
        // not recorded, yet the active generation still opens above it (its
        // address was handed out).
        let zeros = [note_of(&wallet, 0, 0, 7), note_of(&wallet, 2, 0, 8)];
        let landed: LandedByGeneration = [(0, leaves(0, 1))].into();
        let j = restore_journal(&lock, &w, &wallet, &zeros, &landed, &genesis, 500).unwrap();
        assert_eq!(j.get(0).unwrap().state, GenState::Retired, "only a zero-value note: nothing to sweep");
        assert!(j.get(2).is_err(), "only a zero-value note and nothing landed: not recorded");
        assert_eq!(j.active().g, 3);
        std::fs::remove_file(w.dir.join(crate::auth_journal::AUTH_FILE)).unwrap();

        let last =crate::auth_journal::PROBE_GENERATIONS - 1;
        let edge = [note_of(&wallet, last, 1, 9)];
        assert!(matches!(
            restore_journal(&lock, &w, &wallet, &edge, &none, &genesis, 500),
            Err(SendRefusal::Auth(why)) if why.contains("last of the")
        ));
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// Lab #937: a zero-value note (a format-34 third output, a merge's empty
    /// output) is never an input: the planner picks none — not as a payment
    /// note, not merged, not as a fee note, not split — and the sweep floor
    /// `check_budget` keeps does not count it.
    #[test]
    fn zero_value_notes_are_never_planned_nor_budgeted() {
        use crate::annulet_plan::{plan_send, StepKind, Tiers};
        use qlab_ledger::assets::AssetIndex;
        use qlab_ledger::spent::SpentSet;
        let w = wallet_dir("zero", 9);
        let wallet = w.wallet();
        let tiers = Tiers { s: 3, p: 5, r: 7 };
        let of = |value: u64, asset: u64, k: u8| {
            let mut n = note_of(&wallet, 0, value, k);
            n.note.asset = asset;
            OwnedL2Note::from_genesis_v2(&wallet, 0, [k; 32], n.note, &[(0, generation_root(&wallet, 0))]).unwrap()
        };
        let notes = vec![of(50, 7, 1), of(40, 7, 2), of(30, 7, 3), of(0, 7, 4), of(0, 7, 5), of(0, 0, 6), of(20, 0, 7)];
        let index = AssetIndex::build(&wallet, notes, &SpentSet::from_parts(Some((0, 9)), [])).only_generation(0);
        assert_eq!(index.zero.len(), 3, "seen");

        // 120 of asset 7: all three non-zero notes, one merge, the fee notes
        // split from the 20 — never a zero-value note anywhere.
        let plan = plan_send(&index, 7, 120, L2ShapeTag::S, tiers).unwrap();
        let held: Vec<u64> = plan
            .steps
            .iter()
            .flat_map(|s| match &s.kind {
                StepKind::FeeSplit { source, .. } => vec![source.clone()],
                StepKind::Merge { inputs, fee } => vec![inputs[0].clone(), inputs[1].clone(), fee.clone()],
                StepKind::Pay { inputs, fee } => inputs.iter().cloned().chain(fee.clone()).collect(),
            })
            .filter_map(|src| match src {
                crate::annulet_plan::Src::Held(n) => Some(n.note.value),
                _ => None,
            })
            .collect();
        assert!(!held.is_empty() && !held.contains(&0), "no zero-value note is planned: {held:?}");
        assert!(plan_send(&index, 7, 121, L2ShapeTag::S, tiers).is_err(), "120 is all of asset 7 there is");

        // The sweep floor counts the four non-zero notes, not the three zeros.
        let notes: u32 = index.by_asset.values().map(|n| n.spendable.len() as u32).sum();
        assert_eq!(notes, 4);
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

    /// One key per transaction: a note of another generation (or a v1
    /// note) beside the run's generation is refused by name.
    #[test]
    fn a_mixed_generation_spend_is_refused_by_name() {
        let w = wallet_dir("mix", 8);
        let wallet = w.wallet();
        let (a, b) = (note_of(&wallet, 0, 3, 1), note_of(&wallet, 1, 3, 2));
        assert!(one_generation(&[&a], 0).is_ok());
        assert!(matches!(one_generation(&[&a, &b], 0), Err(SendRefusal::Auth(why)) if why.contains("one key per transaction")));
        let mut v1 = a.clone();
        v1.generation = None;
        assert!(one_generation(&[&v1], 0).is_err(), "a v1 note under v2 keys");
        let _ = std::fs::remove_dir_all(&w.dir);
    }

    /// The body binding refuses, by name and without proving anything: a
    /// served body whose auth byte was changed (its commitment no longer the
    /// verified header's), and a transaction listing 256 nullifiers — refused
    /// by the served frame's decoder (lab #911's per-transaction cap) before a
    /// body is built. `check_body_counts` stays locked on an in-memory body
    /// (one that never crossed the wire), before the commitment's byte assert
    /// could run.
    #[test]
    fn a_served_body_is_bound_to_its_verified_header() {
        use qlab_devnet::annulet::{body_commitment_annulet_for, AnnuletHeaderFields, SequencerKey};
        use qlab_devnet::body::BlockBody;
        use qlab_devnet::forms::L2AuthForm;
        use qlab_devnet::header::BlockHeader;
        use qlab_p2p::codec::WireHeader;
        use qlab_p2p::compact::WireForm;
        let axis = L2AuthForm::CandidateA;
        let ext = AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: [7; 32] };
        let key = SequencerKey::from_seed([0x5E; 32]);
        let genesis = BlockHeader::genesis_annulet(ext, [1; 32], 0);
        let mut tx = qlab_p2p::served::fixture::tx();
        tx.auth = vec![0xA7; 40];
        let body = BlockBody { txs: vec![tx.clone()], ..BlockBody::default() };
        let header = BlockHeader::child_of_annulet(&genesis, 10, ext, body_commitment_annulet_for(&body, axis));
        let answer = |body: BlockBody| {
            let ann = qlab_p2p::node::whole_block_announce(WireHeader::Sealed(key.seal(header)), body);
            qlab_p2p::served::encode_body_answer(WireForm::ANNULET_AUTH, 1, &ann).expect("encodes")
        };
        let bound = bind_body(&header, axis, 1, &answer(body.clone())).expect("the honest body binds");
        assert_eq!(body_commitment_annulet_for(&bound, axis), header.tx_body_commitment);
        assert_eq!(bound.txs[0].auth, tx.auth, "the auth section rides the served body");

        let mut tampered = tx.clone();
        tampered.auth[3] ^= 1;
        let refused = bind_body(&header, axis, 1, &answer(BlockBody { txs: vec![tampered], ..BlockBody::default() }));
        assert!(matches!(&refused, Err(SendRefusal::Auth(why)) if why.contains("commits to")), "{:?}", refused.err());

        let mut wide = tx.clone();
        wide.public.nullifiers = (0..256u32).map(|i| [i as u8; 32]).collect();
        let wide_body = BlockBody { txs: vec![wide], ..BlockBody::default() };
        let refused = bind_body(&header, axis, 1, &answer(wide_body.clone()));
        assert!(
            matches!(&refused, Err(SendRefusal::Auth(why)) if why.contains("TooManyEntries")),
            "{:?}",
            refused.err()
        );
        assert!(
            matches!(
                crate::annulet_verify::check_body_counts(1, &wide_body),
                Err(crate::annulet_verify::VerifyRefusal::BodyMalformed { why, .. }) if why.contains("255")
            ),
            "the in-memory count check still refuses 256"
        );
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
