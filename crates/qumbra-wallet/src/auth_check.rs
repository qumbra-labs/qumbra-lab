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
}
