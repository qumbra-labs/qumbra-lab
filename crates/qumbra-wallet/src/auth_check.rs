//! **The open-time check of a Candidate A journal** (lab #924 PR 3b),
//! moved here from `qumbra-ffi` (lab #937 cut-over, M1) so every shell
//! opens its keys by the same judgment: the kernel's C ABI is a thin pump
//! over [`AuthCheck`], and the macOS bridge, which links this crate
//! directly, runs the same one. Verdicts and refusal texts are byte for byte
//! what the kernel judged before the move (the ffi fixtures replay them).
//!
//! Three modes, each a pump over the **verified** bodies of a scan's chain
//! (each bound to its verified header; "landed" is judged here, never taken
//! from a node's nullifier list):
//! - [`AuthCheck::check`] — open generation `g` of a journal: the bodies
//!   above its `checked_to` on this net, matched against `g`'s tree; the
//!   cursor rises above every landed leaf (an active generation whose cursor
//!   had to rise is [`CheckStatus::JournalStale`]: no keys).
//! - [`AuthCheck::restore`] — a wallet with no journal: every body from
//!   height 1, matched against the probe generations' trees; the journal is
//!   rebuilt from what landed and what the scan holds.
//! - [`AuthCheck::first`] — the first journal of an account that never had
//!   one: the restore's pump; refused if the seed has signed (a probe
//!   generation's leaf landed) or opened a later generation (a note at
//!   generation > 0), else generation 0, fresh, active.

use std::sync::Arc;

use qlab_devnet::forms::L2AuthForm;
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};

use crate::annulet_landed::{bind_body, landed_in, landed_next_with, restore_generations_with, GenTree, LandedByGeneration};
use crate::annulet_verify::VerifiedChain;
use crate::auth_journal::{AuthJournal, GenState, JournalError, SweepGate};

/// What a check reads of the verified scan.
#[derive(Clone)]
pub struct CheckBasis {
    pub genesis_hash: [u8; 32],
    pub form: L2AuthForm,
    /// The verified header chain: every body is bound to it.
    pub chain: VerifiedChain,
    /// An upper bound on the real tip for a sweep gate (the CLI's
    /// `gate_tip`).
    pub gate_tip: u64,
    /// Every note the scan made the wallet's (a restore reads their
    /// generations; `first` refuses a note at generation > 0).
    pub owned: Vec<OwnedL2Note>,
}

/// The net is a Candidate A net (format 33 or 34), or refused by name.
pub fn require_candidate_a(form: L2AuthForm) -> Result<(), String> {
    match form {
        // Lab #937 PR D: format 34 (three-output spends) as format 33.
        L2AuthForm::CandidateA | L2AuthForm::CandidateAV3 => Ok(()),
        L2AuthForm::None => Err("this net is not a Candidate A net".into()),
    }
}

/// The finished check's verdict (the kernel's `QMB_AUTH_*`, [`CheckStatus::code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// The cursor is at or above every landed leaf; `checked_to` moved to
    /// the verified tip.
    Checked,
    /// The journal is older than the chain (a landed leaf above its
    /// cursor): **no keys**. The journal has the cursor raised — persist it,
    /// tell the user, then restore.
    JournalStale,
    /// A sweep-only generation's cursor was raised to its landed floor.
    SweepFloorRaised,
    /// A restore wrote the journal.
    Restored,
    /// A sweep-only generation may not sweep yet: no keys; persist the
    /// journal.
    SweepWaiting,
    /// `first` wrote this account's first journal: generation 0, fresh.
    First,
}

impl CheckStatus {
    /// The kernel's `QMB_AUTH_*` value.
    pub const fn code(self) -> i32 {
        match self {
            CheckStatus::Checked => 0,
            CheckStatus::JournalStale => 1,
            CheckStatus::SweepFloorRaised => 2,
            CheckStatus::Restored => 3,
            CheckStatus::SweepWaiting => 4,
            CheckStatus::First => 5,
        }
    }

    /// Keys may be opened on this verdict.
    pub fn opens(self) -> bool {
        !matches!(self, CheckStatus::JournalStale | CheckStatus::SweepWaiting)
    }
}

/// One pump step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckStep {
    /// GET this path (a block body) and [`AuthCheck::supply`] it.
    Need(String),
    /// Every body is in: [`AuthCheck::finish`].
    Ready,
    /// Terminal, by name.
    Refused(String),
}

enum CheckMode {
    Check { g: u32, journal: AuthJournal },
    Restore,
    First,
}

/// The open-time check (module doc).
pub struct AuthCheck {
    mode: CheckMode,
    basis: CheckBasis,
    /// Shared with the shell's tree cache: never rebuilt here.
    trees: Vec<Arc<GenTree>>,
    landed: LandedByGeneration,
    at: u64,
    asked: bool,
    refused: Option<String>,
    /// Lab #936: bodies per NEED — 0 asks one `/v1/block/{h}/body` at a time
    /// (the default; every recorded fixture's NEED sequence), `n` asks a
    /// `/v1/bodies` page of up to `n` ([`AuthCheck::set_page`]).
    page: u64,
    /// The last height the outstanding page NEED asked for.
    asked_to: u64,
    /// A step has been taken: the page size is fixed from here.
    started: bool,
}

/// The most bodies one page NEED asks for: the served page's own bound.
pub const MAX_CHECK_PAGE: u64 = qlab_p2p::served::MAX_BODIES_PAGE as u64;

impl AuthCheck {
    fn new(mode: CheckMode, basis: CheckBasis, trees: Vec<Arc<GenTree>>, from: u64) -> AuthCheck {
        AuthCheck {
            mode,
            basis,
            trees,
            landed: LandedByGeneration::new(),
            at: from,
            asked: false,
            refused: None,
            page: 0,
            asked_to: 0,
            started: false,
        }
    }

    /// **Lab #936, opt-in:** ask the bodies in `/v1/bodies` pages of up to
    /// `n` (1 ..= [`MAX_CHECK_PAGE`]) instead of one per NEED; 0 restores the
    /// default. Each body in a page is bound exactly as a single one is —
    /// header, counts, commitment — and judged in height order, so the
    /// verdict is the per-block check's. Set before the first step: a shell
    /// turns pages on only for an endpoint it knows serves the route (no
    /// fallback that would read a transient error as "not served").
    pub fn set_page(&mut self, n: u64) -> Result<(), String> {
        if n > MAX_CHECK_PAGE {
            return Err(format!("a page of {n} bodies exceeds {MAX_CHECK_PAGE}"));
        }
        if self.started {
            return Err("the page size is set before the first step".to_string());
        }
        self.page = n;
        Ok(())
    }

    /// **Open generation `generation` of `journal`, checked against the
    /// chain.** `tree` yields that generation's tree (from the shell's
    /// cache; asked for only once the journal's record passes, so a
    /// refused open builds no tree); `index` is the scan's (a retired
    /// generation is opened only when a note of it arrived — it is revived,
    /// sweep-only).
    pub fn check(
        journal: AuthJournal,
        generation: u32,
        tree: impl FnOnce() -> Arc<GenTree>,
        index: &AssetIndex,
        basis: CheckBasis,
    ) -> Result<AuthCheck, String> {
        let rec = journal.get(generation).map_err(|e| format!("auth.v1: {e}"))?;
        // A retired generation is opened only to be revived: a note of it
        // arrived (a published address is still paid). Without one, refused.
        let holds = index.only_generation(generation).by_asset.values().any(|n| !n.spendable.is_empty());
        if rec.state == GenState::Retired && !holds {
            return Err(format!("generation {generation} is retired and holds nothing: nothing of it is spent again"));
        }
        let tree = tree();
        if tree.root() != rec.auth_root {
            return Err(format!("auth.v1's root for generation {generation} is not this wallet's tree"));
        }
        // Beyond the verified tip (a node that rolled back, an edited
        // backup): walk everything again — the cursor only rises.
        let checked = journal.checked_to(generation, &basis.genesis_hash);
        let from = if checked > basis.chain.tip() { 1 } else { checked.saturating_add(1) };
        Ok(AuthCheck::new(CheckMode::Check { g: generation, journal }, basis, vec![tree], from))
    }

    /// **Restore**: a wallet with no `auth.v1`. `trees` are the probe
    /// generations' (`0 .. PROBE_GENERATIONS`).
    pub fn restore(trees: Vec<Arc<GenTree>>, basis: CheckBasis) -> AuthCheck {
        AuthCheck::new(CheckMode::Restore, basis, trees, 1)
    }

    /// **The first journal of an account that has never had one.** `trees`
    /// are the probe generations'; `trees[0]` is generation 0's.
    ///
    /// **The shell's premise:** `first` is only for an account whose shell
    /// has never persisted an `auth.v1` for it. If a journal ever existed —
    /// even one deleted since — use [`AuthCheck::restore`].
    pub fn first(trees: Vec<Arc<GenTree>>, basis: CheckBasis) -> AuthCheck {
        AuthCheck::new(CheckMode::First, basis, trees, 1)
    }

    /// The next step of the pump.
    pub fn step(&mut self) -> CheckStep {
        if let Some(why) = &self.refused {
            return CheckStep::Refused(why.clone());
        }
        if self.asked {
            return CheckStep::Refused("a step with an answer outstanding".into());
        }
        self.started = true;
        if self.at > self.basis.chain.tip() {
            return CheckStep::Ready;
        }
        self.asked = true;
        if self.page == 0 {
            return CheckStep::Need(format!("/v1/block/{}/body", self.at));
        }
        self.asked_to = self.basis.chain.tip().min(self.at.saturating_add(self.page - 1));
        CheckStep::Need(format!("{}?from={}&to={}", qlab_p2p::served::BODIES_PATH, self.at, self.asked_to))
    }

    /// A step was asked with an answer outstanding (the kernel's misuse).
    pub fn is_asking(&self) -> bool {
        self.asked && self.refused.is_none()
    }

    /// Answer the outstanding [`CheckStep::Need`]: the body's bytes, or why
    /// it could not be read (the check is then refused — a body it needs is
    /// not optional; the journal's `checked_to` keeps finished work).
    pub fn supply(&mut self, answer: Result<&[u8], String>) {
        if self.refused.is_some() {
            return;
        }
        if !self.asked {
            self.refused = Some("a response with no NEED outstanding".into());
            return;
        }
        self.asked = false;
        if self.page > 0 {
            return self.supply_page(answer);
        }
        let h = self.at;
        let bound = answer.map_err(|why| format!("block {h}'s body is unavailable: {why}"));
        if let Err(why) = bound.and_then(|bytes| self.judge(h, bytes)) {
            self.refused = Some(why);
        }
    }

    /// Lab #936: a `/v1/bodies` page — split, then each body judged at its
    /// height in order exactly as [`AuthCheck::supply`] judges one. A short
    /// page moves `at` past what it held and the next step asks on from
    /// there; an empty page is the body at `at` missing.
    fn supply_page(&mut self, answer: Result<&[u8], String>) {
        let from = self.at;
        let wire = qlab_p2p::compact::WireForm {
            form: qlab_devnet::forms::GenesisForm::Annulet,
            sections: qlab_devnet::forms::BodySections::None,
            l2_auth: self.basis.form,
        };
        let judged = answer
            .map_err(|why| format!("block {from}'s body is unavailable: {why}"))
            .and_then(|bytes| {
                let bodies = qlab_p2p::served::split_bodies_page(wire, from, bytes)
                    .map_err(|e| format!("the bodies page from {from} is refused: {e}"))?;
                if bodies.is_empty() {
                    return Err(format!("block {from}'s body is unavailable: the endpoint served an empty page"));
                }
                let asked = (self.asked_to - from + 1) as usize;
                if bodies.len() > asked {
                    return Err(format!(
                        "the bodies page from {from} holds {} bodies, {asked} were asked",
                        bodies.len()
                    ));
                }
                for (i, bytes) in bodies.into_iter().enumerate() {
                    self.judge(from + i as u64, bytes)?;
                }
                Ok(())
            });
        if let Err(why) = judged {
            self.refused = Some(why);
        }
    }

    /// Bind the body at `h` (= `at`) to its verified header and take its
    /// landed leaves; `at` moves past it.
    fn judge(&mut self, h: u64, bytes: &[u8]) -> Result<(), String> {
        debug_assert_eq!(h, self.at);
        let header = self.basis.chain.header(h).ok_or_else(|| format!("height {h} is above the verified tip"))?;
        let body = bind_body(&header, self.basis.form, h, bytes).map_err(|e| format!("block {h}'s body {e}"))?;
        for t in &self.trees {
            let hits = landed_in(&t.tree, &body);
            if !hits.is_empty() {
                self.landed.entry(t.g).or_default().extend(hits);
            }
        }
        self.at += 1;
        Ok(())
    }

    /// **Finish** (after [`CheckStep::Ready`], once): the journal to
    /// persist, the generation to open, and the verdict. Whatever the
    /// outcome, the check is spent.
    pub fn finish(&mut self) -> Result<(AuthJournal, u32, CheckStatus), String> {
        if let Some(why) = &self.refused {
            return Err(why.clone());
        }
        if self.asked || self.at <= self.basis.chain.tip() {
            return Err("finish: the check is not READY".into());
        }
        let b = &self.basis;
        let tip = b.chain.tip();
        let gate = SweepGate {
            genesis: b.genesis_hash,
            not_before_height: b.gate_tip.saturating_add(qlab_devnet::annulet::MAX_AUTH_VALIDITY_BLOCKS),
        };
        let trees = &self.trees;
        let landed = &self.landed;
        let finished = (|| match std::mem::replace(&mut self.mode, CheckMode::Restore) {
            CheckMode::Check { g, mut journal } => {
                let t = &trees[0];
                let floor = landed_next_with(&t.master, &t.tree, landed.get(&g).map_or(&[][..], |v| v.as_slice()));
                let rec = journal.get(g).map_err(|e| e.to_string())?.clone();
                let raised = floor > rec.next;
                if raised {
                    journal.advance_mem(g, floor).map_err(|e| e.to_string())?;
                }
                journal.set_checked_mem(g, &b.genesis_hash, tip).map_err(|e| e.to_string())?;
                match rec.state {
                    // Older than the chain. Not opened here: this check matched
                    // only g's tree, and a later generation the lost device may
                    // have opened and used was never looked at. The raised cursor
                    // goes back to be persisted; a restore does the rest.
                    GenState::Active if raised => Ok((journal, g, CheckStatus::JournalStale)),
                    GenState::Active => Ok((journal, g, CheckStatus::Checked)),
                    GenState::Sweep { .. } => match journal.sweep_allowed(g, &b.genesis_hash, b.chain.tip()) {
                        Ok(()) => Ok((journal, g, if raised { CheckStatus::SweepFloorRaised } else { CheckStatus::Checked })),
                        Err(JournalError::SweepNoGate { .. }) => {
                            journal.add_gate_mem(g, gate).map_err(|e| e.to_string())?;
                            Ok((journal, g, CheckStatus::SweepWaiting))
                        }
                        Err(JournalError::SweepNotYet { .. }) => Ok((journal, g, CheckStatus::SweepWaiting)),
                        Err(e) => Err(e.to_string()),
                    },
                    // Revived (the check was let in only because it holds notes):
                    // sweep-only with a new gate — waiting, no keys.
                    GenState::Retired => {
                        journal.revive_mem(g, gate).map_err(|e| e.to_string())?;
                        Ok((journal, g, CheckStatus::SweepWaiting))
                    }
                }
            }
            CheckMode::First => {
                // A note at generation > 0 means an address of a generation only
                // `open_next` makes: a journal existed.
                if let Some(g) = b.owned.iter().filter_map(|n| n.generation).find(|g| *g > 0) {
                    return Err(format!("this seed opened generation {g} (a note is paid to it): use restore"));
                }
                if let Some((g, _)) = landed.iter().find(|(_, slots)| !slots.is_empty()) {
                    return Err(format!(
                        "this seed has signed (a leaf of generation {g} has landed on this net): use restore"
                    ));
                }
                let mut journal = AuthJournal::fresh(trees[0].root());
                journal.set_checked_mem(0, &b.genesis_hash, tip).map_err(|e| e.to_string())?;
                Ok((journal, 0, CheckStatus::First))
            }
            CheckMode::Restore => {
                let mut journal = restore_generations_with(trees, &b.owned, landed, &b.genesis_hash, b.gate_tip)
                    .map_err(|e| format!("restore: {e}"))?;
                let gens: Vec<u32> = journal.generations().iter().map(|r| r.g).collect();
                for g in gens {
                    journal.set_checked_mem(g, &b.genesis_hash, tip).map_err(|e| e.to_string())?;
                }
                let active = journal.active().g;
                Ok((journal, active, CheckStatus::Restored))
            }
        })();
        self.refused = Some("this check was finished".into());
        finished
    }
}

/// Why [`restore_across`] refused, by name.
#[derive(Debug)]
pub enum RestoreAcrossError {
    /// No journal was given: there is no net to restore from.
    Empty,
    /// Two journals give generation `g` different authorization roots: they
    /// are not one key's restores (another seed, or another derivation).
    MixedKeys { g: u32 },
    /// The merged records do not form a journal.
    Journal(JournalError),
}

impl std::fmt::Display for RestoreAcrossError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RestoreAcrossError::Empty => write!(f, "a restore across nets needs at least one net's restored journal"),
            RestoreAcrossError::MixedKeys { g } => write!(
                f,
                "the restored journals give generation {g} different authorization roots: they are not one key's"
            ),
            RestoreAcrossError::Journal(e) => write!(f, "the merged journal is refused: {e}"),
        }
    }
}

impl std::error::Error for RestoreAcrossError {}

/// **One key's journal from its restores on every live Candidate A net**
/// (lab #971). The journal is per key, not per net (one `(sk, g)` cursor
/// serves every net), so a restore that read one net's chain is blind to
/// leaves landed on another; `journals` are [`AuthCheck::restore`]'s results,
/// one per net, and the merge is what every one of them allows:
/// - the active generation is the highest of theirs, `G` — above every
///   generation any net saw a note or a landed leaf in, so fresh (next 0) in
///   every restore;
/// - each generation below `G` takes the highest cursor any net has for it,
///   and is sweep-only if any net found notes in it (each net's gates kept,
///   one per genesis, the later wait where two name the same net), else
///   retired. A net's own active generation below `G` (nothing of it on that
///   net) contributes only its cursor; named by no other net with a cursor
///   of 0, it is left out, as a restore leaves out a generation with nothing;
/// - every net's `checked` heights are kept for the generations kept.
///
/// One journal comes back unchanged. Empty input and two roots for one
/// generation are refused by name.
pub fn restore_across(journals: &[AuthJournal]) -> Result<AuthJournal, RestoreAcrossError> {
    use crate::auth_journal::Generation;
    use std::collections::BTreeMap;

    /// One generation as the nets name it.
    struct Named {
        auth_root: [u64; 4],
        next: u32,
        /// Set when any net says sweep-only.
        gates: Option<Vec<SweepGate>>,
        /// A net names it other than as its own active generation.
        used: bool,
    }

    let top = journals.iter().map(|j| j.active().g).max().ok_or(RestoreAcrossError::Empty)?;
    let mut merged: BTreeMap<u32, Named> = BTreeMap::new();
    for j in journals {
        for r in j.generations() {
            let e = merged.entry(r.g).or_insert(Named { auth_root: r.auth_root, next: 0, gates: None, used: false });
            if e.auth_root != r.auth_root {
                return Err(RestoreAcrossError::MixedKeys { g: r.g });
            }
            e.next = e.next.max(r.next);
            match &r.state {
                GenState::Active => {}
                GenState::Retired => e.used = true,
                GenState::Sweep { gates } => {
                    e.used = true;
                    let kept = e.gates.get_or_insert_with(Vec::new);
                    for gate in gates {
                        match kept.iter_mut().find(|k| k.genesis == gate.genesis) {
                            Some(k) => k.not_before_height = k.not_before_height.max(gate.not_before_height),
                            None => kept.push(*gate),
                        }
                    }
                }
            }
        }
    }
    let gens: Vec<Generation> = merged
        .into_iter()
        .filter_map(|(g, Named { auth_root, next, gates, used })| {
            let state = if g == top {
                GenState::Active
            } else if let Some(gates) = gates {
                GenState::Sweep { gates }
            } else if used || next > 0 {
                GenState::Retired
            } else {
                return None;
            };
            // The active generation is fresh in every restore (its cursor is
            // 0 in each); the maximum is kept anyway, so no cursor moves back.
            Some(Generation { g, next, auth_root, state })
        })
        .collect();
    let mut out = AuthJournal::from_generations(gens).map_err(RestoreAcrossError::Journal)?;
    for j in journals {
        for (g, genesis, height) in j.checked_heights() {
            if out.get(g).is_ok() {
                out.set_checked_mem(g, &genesis, height).map_err(RestoreAcrossError::Journal)?;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verdicts keep the kernel's `QMB_AUTH_*` values (qumbra-ffi
    /// asserts the same at compile time), and only two of them withhold keys.
    #[test]
    fn verdict_codes_are_the_kernels() {
        let all = [
            (CheckStatus::Checked, 0, true),
            (CheckStatus::JournalStale, 1, false),
            (CheckStatus::SweepFloorRaised, 2, true),
            (CheckStatus::Restored, 3, true),
            (CheckStatus::SweepWaiting, 4, false),
            (CheckStatus::First, 5, true),
        ];
        for (s, code, opens) in all {
            assert_eq!((s.code(), s.opens()), (code, opens), "{s:?}");
        }
    }

    #[test]
    fn only_a_candidate_a_net_is_checked() {
        assert!(require_candidate_a(L2AuthForm::CandidateA).is_ok());
        assert!(require_candidate_a(L2AuthForm::CandidateAV3).is_ok());
        assert_eq!(require_candidate_a(L2AuthForm::None).err().as_deref(), Some("this net is not a Candidate A net"));
    }

    /// Lab #971: restored journals built as records, no tree built (the
    /// merge reads records only), so these run in milliseconds.
    mod across {
        use super::super::*;
        use crate::auth_journal::Generation;

        const NET_A: [u8; 32] = [0xa1; 32];
        const NET_B: [u8; 32] = [0xb2; 32];

        fn root(g: u32) -> [u64; 4] {
            [0x5eed, u64::from(g), 7, 9]
        }

        fn gen(g: u32, next: u32, state: GenState) -> Generation {
            Generation { g, next, auth_root: root(g), state }
        }

        fn gate(genesis: [u8; 32], not_before_height: u64) -> SweepGate {
            SweepGate { genesis, not_before_height }
        }

        fn journal(gens: Vec<Generation>, checked: &[(u32, [u8; 32], u64)]) -> AuthJournal {
            let mut j = AuthJournal::from_generations(gens).unwrap();
            for (g, genesis, h) in checked {
                j.set_checked_mem(*g, genesis, *h).unwrap();
            }
            j
        }

        /// The leaf a send takes next: the active generation's cursor.
        fn offered(j: &AuthJournal) -> (u32, u32) {
            (j.active().g, j.active().next)
        }

        /// Whether `leaf` is one `j` records as consumed.
        fn consumed_in(j: &AuthJournal, (g, pos): (u32, u32)) -> bool {
            j.get(g).is_ok_and(|r| pos < r.next)
        }

        /// #971's counterexample: net A has seen nothing of this seed (its
        /// restore is generation 0, fresh), net B has three of generation 0's
        /// leaves landed (its restore retires 0 and opens 1). A's restore
        /// alone offers a leaf B consumed; the merge does not.
        #[test]
        fn the_971_counterexample_reuses_without_the_merge_and_not_with_it() {
            let a = journal(vec![gen(0, 0, GenState::Active)], &[(0, NET_A, 40)]);
            let b = journal(
                vec![gen(0, 3, GenState::Retired), gen(1, 0, GenState::Active)],
                &[(0, NET_B, 90), (1, NET_B, 90)],
            );
            assert!(consumed_in(&b, offered(&a)), "without the merge, A offers a leaf B consumed");
            for inputs in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
                let m = restore_across(&inputs).unwrap();
                assert_eq!(offered(&m), (1, 0));
                assert!(!consumed_in(&b, offered(&m)) && !consumed_in(&a, offered(&m)));
                assert_eq!(m.get(0).unwrap().next, 3);
                assert_eq!(m.get(0).unwrap().state, GenState::Retired);
                // Every net's checked heights kept for the generations kept.
                assert_eq!(m.checked_to(0, &NET_A), 40);
                assert_eq!(m.checked_to(0, &NET_B), 90);
                assert_eq!(m.checked_to(1, &NET_B), 90);
                assert_eq!(m.checked_to(1, &NET_A), 0, "A never checked generation 1");
            }
        }

        /// The merged cursor is at or above every net's, and the active
        /// generation is above every generation any net found used.
        #[test]
        fn the_merge_takes_every_cursor_and_opens_above_every_net() {
            let a = journal(
                vec![
                    gen(0, 5, GenState::Retired),
                    gen(1, 2, GenState::Sweep { gates: vec![gate(NET_A, 100)] }),
                    gen(2, 0, GenState::Active),
                ],
                &[],
            );
            let b = journal(
                vec![gen(0, 9, GenState::Retired), gen(3, 4, GenState::Retired), gen(4, 0, GenState::Active)],
                &[],
            );
            let c = journal(vec![gen(1, 7, GenState::Retired), gen(2, 0, GenState::Active)], &[]);
            let inputs = [a, b, c];
            let m = restore_across(&inputs).unwrap();
            assert_eq!(m.active().g, 4);
            for j in &inputs {
                for r in j.generations() {
                    assert!(m.get(r.g).map_or(r.next == 0, |x| x.next >= r.next), "g {} below a net's cursor", r.g);
                    if r.state != GenState::Active {
                        assert!(m.active().g > r.g, "active not above a used generation {}", r.g);
                    }
                }
            }
            assert_eq!(m.get(0).unwrap().next, 9);
            // Sweep wins over retired; the other nets' cursor still counts.
            assert_eq!(m.get(1).unwrap().next, 7);
            assert_eq!(m.get(1).unwrap().state, GenState::Sweep { gates: vec![gate(NET_A, 100)] });
            // A's and C's active generation 2: no net used it, so it is left out.
            assert!(m.get(2).is_err());
        }

        /// Sweep gates are kept per genesis; two for one net keep the later wait.
        #[test]
        fn sweep_gates_are_unioned_per_genesis() {
            let a = journal(
                vec![gen(0, 1, GenState::Sweep { gates: vec![gate(NET_A, 50)] }), gen(1, 0, GenState::Active)],
                &[],
            );
            let b = journal(
                vec![gen(0, 1, GenState::Sweep { gates: vec![gate(NET_B, 70)] }), gen(1, 0, GenState::Active)],
                &[],
            );
            let b_later = journal(
                vec![gen(0, 0, GenState::Sweep { gates: vec![gate(NET_B, 80)] }), gen(1, 0, GenState::Active)],
                &[],
            );
            let m = restore_across(&[a, b, b_later]).unwrap();
            assert_eq!(m.get(0).unwrap().state, GenState::Sweep { gates: vec![gate(NET_A, 50), gate(NET_B, 80)] });
            assert!(m.sweep_allowed(0, &NET_A, 50).is_ok());
            assert!(m.sweep_allowed(0, &NET_B, 79).is_err());
        }

        /// One net's restore comes back as it went in, text for text.
        #[test]
        fn a_single_journal_comes_back_unchanged() {
            let j = journal(
                vec![
                    gen(0, 4, GenState::Retired),
                    gen(1, 2, GenState::Sweep { gates: vec![gate(NET_A, 60), gate(NET_B, 61)] }),
                    gen(2, 0, GenState::Active),
                ],
                &[(0, NET_A, 30), (1, NET_A, 30), (2, NET_A, 30)],
            );
            let m = restore_across(std::slice::from_ref(&j)).unwrap();
            assert_eq!(m, j);
            assert_eq!(m.to_text(), j.to_text());
            let fresh = AuthJournal::fresh(root(0));
            assert_eq!(restore_across(std::slice::from_ref(&fresh)).unwrap(), fresh);
        }

        #[test]
        fn no_journal_and_two_keys_are_refused_by_name() {
            let e = restore_across(&[]).unwrap_err();
            assert!(matches!(e, RestoreAcrossError::Empty));
            assert_eq!(e.to_string(), "a restore across nets needs at least one net's restored journal");

            let mine = journal(vec![gen(0, 1, GenState::Retired), gen(1, 0, GenState::Active)], &[]);
            let other = AuthJournal::from_generations(vec![Generation {
                g: 1,
                next: 0,
                auth_root: [1, 2, 3, 4],
                state: GenState::Active,
            }])
            .unwrap();
            let e = restore_across(&[mine, other]).unwrap_err();
            assert!(matches!(e, RestoreAcrossError::MixedKeys { g: 1 }), "{e:?}");
            assert!(e.to_string().contains("generation 1 different authorization roots"), "{e}");
        }
    }
}
