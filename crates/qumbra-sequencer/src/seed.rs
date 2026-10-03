//! **`seed`** (lab #847 S3b): the sequencer's first L2 notes, from its own
//! L1 burns.
//!
//! A filler (S3) spends a sequencer note that is already in C, so before the
//! sequencer holds any, every wrapper needs 16 real claims. `seed` makes the
//! notes the fillers start from: `count` claims whose credits are the
//! sequencer's own, each of a burn made from the sequencer's own L1 wallet.
//! A claim anyone else makes that credits `rkm_seq` would carry an rseed the
//! sequencer cannot know — a note it could never spend — so only the
//! sequencer can make these.
//!
//! **The L1 wallet** is the S5 key file's fourth derivation
//! ([`crate::key::l1_seed`], domain `qumbra:sequencer:l1-wallet:v1`), held
//! **in memory only**: the `WalletDir` the shared wallet flow takes is built
//! around it, and `--out/l1-wallet/` (0700) holds only what that flow caches
//! — the scan cache, the tree sync, the local send record. **No seed file is
//! ever written there**, and one found there is refused by name. The operator
//! funds the wallet's address (on the box from coinbase, as F5-6 did; on a
//! real chain, a runbook step).
//!
//! **The burns** go through the wallet's own spend flow
//! (`qumbra_wallet::spend::execute_opened`) — the same select, proof and
//! submit as `qumbra-wallet deposit`, never a second copy of it. One burn per
//! L1 transaction (the flow pays one recipient, plus change), so `count`
//! burns are `count` L1 proofs (≈ 31 GiB each), **sequential, each mined
//! before the next** — the next selection reads the chain, and would pick
//! the same unmined inputs. A rerun counts the deposits already made and
//! burns only the shortfall.
//!
//! **The claims** are built as `qumbra-wallet deposit claim` builds them
//! (`qlab_l2spend::claim_instance` / `prove_claim` / `encode_claim_artifact`,
//! `r_v` from the L1 wallet's `claim_blinds`), except for the credit:
//! `keys.seed_credit(cnf)` — the filler wallet's `rkm` and a cnf-bound rseed
//! ([`crate::members::Keys::seed_rseed`]), which the pass recognises from the
//! claim's public values alone ([`crate::members::own_credit`]). Each file is
//! written to `--out/claims/` and POSTed to the intake (`--intake`), where it
//! takes S2's path unchanged — the same checks, dedupe and states as a
//! wallet's claim. A refused POST leaves the file in place and names it.
//!
//! **`--plan`** prints the shortfall, the funded balance, the proof budget
//! and the expected wall time, and proves nothing; `seed` refuses by name
//! when the wallet cannot fund the shortfall.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use qlab_air::claim::{claim_cnf, l1_cm, BurnNote};
use qlab_cbserver::tree::CommitmentTree;
use qlab_l2spend::{ClaimError, Endpoint};
use qlab_ledger::deposits::{SetAside, SetAsideKind};
use qlab_wallet::seed::MasterSeed;
use qlab_wallet::Wallet;
use qumbra_node::genesis_v6::GenesisFileV6;
use qumbra_wallet::store::{WalletDir, SEED_FILE};

use crate::intake::Chain;
use crate::key::SequencerKey;
use crate::members::Keys;
use crate::server::INTAKE_PATH;

/// The default number of seed claims: one wrapper's worth of fillers next
/// to a single real claim (K − 1).
pub const DEFAULT_COUNT: usize = crate::members::K - 1;

/// The budget `--plan` quotes, per proof — cited, not measured here: an L1
/// transaction ≈ 31 GiB / ≈ 30 s on the box (the hiding-PCS L1 lane), a
/// claim ≈ 3.17 GiB / ≈ 6 s (F5-6, `logs/f5-6-box-20261001`), a block every
/// ≈ 75 s (the box's pace). S6 measures them.
pub const L1_PROOF_GIB: f64 = 31.0;
pub const L1_PROOF_SECS: u64 = 30;
pub const CLAIM_PROOF_GIB: f64 = 3.17;
pub const CLAIM_PROOF_SECS: u64 = 6;
pub const BLOCK_SECS: u64 = 75;

/// One `seed` run.
pub struct Seed {
    pub genesis: GenesisFileV6,
    pub key: SequencerKey,
    /// The node's discovery listener, as a URL (`/v1/tree/leaves`,
    /// `/v1/anchors`, `/v1/l2`, `POST /v1/tx`).
    pub node: String,
    /// The compact/scan endpoint (usually the same host).
    pub scan: String,
    /// The intake listener; `None` writes the claim files only.
    pub intake: Option<SocketAddr>,
    pub out: PathBuf,
    pub count: usize,
    /// Each burn's value (bessel): above the claim tier, so the claim
    /// credits something.
    pub burn: u64,
    pub plan: bool,
    pub poll_secs: u64,
    pub max_wait_secs: u64,
}

/// The L1 wallet, in memory, around `dir` (created 0700). Refused by name
/// when a seed file is there: this wallet's seed is never on disk.
pub fn l1_wallet(dir: &Path, key: &SequencerKey) -> Result<WalletDir, String> {
    if dir.join(SEED_FILE).exists() {
        return Err(format!(
            "{}: a wallet seed file is here, and `seed` never writes one — refusing to use or overwrite it. \
             Remove it if you know where it came from",
            dir.join(SEED_FILE).display()
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(WalletDir { dir: dir.to_path_buf(), seed: MasterSeed::from_entropy(*key.l1_seed), allocated: vec![0] })
}

/// How many burns are still to make: `count` less the deposits already
/// pending.
pub fn shortfall(count: usize, pending: usize) -> usize {
    count.saturating_sub(pending)
}

/// What the shortfall costs: the funding it needs, and the plan's words.
pub fn plan_text(shortfall: usize, pending: usize, claims_to_make: usize, burn: u64, fee: u64, funded: Option<u128>) -> String {
    let need = u128::from(burn.saturating_add(fee)) * shortfall as u128;
    let funded_line = match funded {
        Some(f) => format!("{f} bessel spendable (needs {need})"),
        None => "UNAVAILABLE — the scan could not quote a spendable figure".into(),
    };
    let secs = shortfall as u64 * (L1_PROOF_SECS + BLOCK_SECS) + claims_to_make as u64 * CLAIM_PROOF_SECS;
    format!(
        "seed plan: {pending} deposit(s) already pending; {shortfall} burn(s) of {burn} bessel to make (fee {fee} each), \
         one per L1 transaction, each mined before the next (a burn left in flight by an earlier run is waited \
         for, never burned again; a burn whose inputs are not finalized yet waits for finality — fund the wallet \
         with one note per burn so no burn waits on another's change); {claims_to_make} claim(s) to prove.\n  \
         funded: {funded_line}\n  \
         budget: {shortfall} L1 proof(s) at ≈ {L1_PROOF_GIB} GiB / ≈ {L1_PROOF_SECS} s, {claims_to_make} claim proof(s) at \
         ≈ {CLAIM_PROOF_GIB} GiB / ≈ {CLAIM_PROOF_SECS} s, one block (≈ {BLOCK_SECS} s) per burn — ≈ {} min wall",
        secs.div_ceil(60)
    )
}

/// The claim `seed` makes of one pending deposit: the wallet's own burn,
/// opened under the root at `anchor_count`, `r_v` from the L1 wallet's
/// `claim_blinds`, credited to the filler wallet with the cnf-bound rseed.
/// Returns the instance and its `r_v`, or the builder's own refusal.
pub fn seed_claim(
    tree: &CommitmentTree,
    anchor_count: u64,
    deposit: &SetAside,
    l2_id: u64,
    fee: u64,
    wallet: &Wallet,
    keys: &Keys,
) -> Result<(qlab_air::claim::ClaimInstance, [u64; 4]), ClaimError> {
    let note = BurnNote {
        value: deposit.note.value,
        rkm: qlab_ledger::deposits::burn_rkm(l2_id),
        rho: deposit.note.rho,
        rseed: deposit.note.rseed,
    };
    let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
    let (r_v, _) = wallet.claim_blinds(&cm);
    let credit = keys.seed_credit(&claim_cnf(&cm, &note.rseed));
    let inst = qlab_l2spend::claim_instance(tree, anchor_count, &note, l2_id, &r_v, &credit, fee)?;
    Ok((inst, r_v))
}

/// Why a pending deposit was not claimed this run, in words an operator can
/// act on: only a burn above the newest finalized anchor is a wait — every
/// other refusal is named as what it is, so nobody waits for an anchor that
/// would never help.
pub fn skip_reason(height: u64, e: &ClaimError) -> String {
    match e {
        ClaimError::AboveAnchor { .. } => format!(
            "the deposit at height {height} is not yet under a finalized anchor ({e}) — a rerun claims it once one covers it"
        ),
        _ => format!("the deposit at height {height} cannot be claimed: {e}"),
    }
}

/// The pending deposits to `l2_id` among `set_aside`, oldest first.
pub fn pending(set_aside: &[SetAside], l2_id: u64) -> Vec<SetAside> {
    let mut p: Vec<SetAside> =
        set_aside.iter().filter(|s| s.kind == SetAsideKind::PendingDeposit { l2_id }).cloned().collect();
    p.sort_by_key(|s| (s.height, s.tx_index, s.cm));
    p
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A claim file's path: one per burn, named by the burn's commitment.
pub fn claim_path(out: &Path, deposit: &SetAside) -> PathBuf {
    out.join("claims").join(format!("{}.claim", hex(&deposit.cm)))
}

/// The marker beside a claim file that the intake took it (202 or 409).
pub fn taken_path(claim: &Path) -> PathBuf {
    let mut p = claim.as_os_str().to_owned();
    p.push(".taken");
    PathBuf::from(p)
}

/// The claim files under `--out/claims/` not yet marked taken, in name
/// order — every one is POSTed again on every run until the intake takes it.
pub fn untaken(out: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = out.join("claims");
    let Ok(rd) = std::fs::read_dir(&dir) else { return Ok(Vec::new()) };
    let mut files: Vec<PathBuf> = rd
        .map(|e| e.map(|e| e.path()).map_err(|e| format!("{}: {e}", dir.display())))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "claim") && !taken_path(p).exists())
        .collect();
    files.sort();
    Ok(files)
}

/// Whether a send refusal is the wallet's "not spendable YET": the money is
/// held, in notes whose block is not finalized (`BuildRefusal::
/// NotYetFinalized`), or a selected note is past the finalized anchor
/// (`OutsideAnchor`). Both are pre-proof and clear with no action once
/// finality advances; `seed` waits on them. Pinned against the wallet's own
/// texts by a test, so a reworded refusal fails here, not on the box.
pub fn is_finality_wait(why: &str) -> bool {
    why.contains("not spendable YET") || why.contains("not possible YET")
}

/// The in-flight burn record: written after the burn is proved and before
/// it is POSTed (the spend flow's pre-submit hook), holding how many
/// deposits were pending before it; cleared once the scan shows more. A
/// rerun that finds it waits for that burn instead of proving another.
pub fn inflight_path(out: &Path) -> PathBuf {
    out.join("burn-in-flight")
}

impl Seed {
    fn chain(&self) -> Chain {
        Chain::of(&self.genesis)
    }

    /// The node's tip, from `/v1/anchors`.
    fn tip(&self) -> Result<u64, String> {
        Ok(crate::chain::read(&crate::chain::Http { base: self.node.clone() })?.anchors.tip_height)
    }

    /// Scan the L1 wallet: its pending deposits to this L2, and its
    /// spendable figure (`None` when the scan cannot quote one).
    fn scan(&self, w: &WalletDir, to: u64) -> (Vec<SetAside>, Option<u128>) {
        let form = self.genesis.forms().0;
        let r = qumbra_wallet::scan::scan_report(w, &self.scan, 0, to, form);
        let tx: Option<u128> = r.scans.iter().map(|d| d.spendable_bessel).sum();
        let mined: u128 = r.coinbase.as_ref().map_or(0, |m| m.spendable.iter().map(|n| u128::from(n.note.value)).sum());
        (pending(&r.set_aside, self.chain().l2_id), tx.map(|t| t + mined))
    }

    /// Poll until more than `before` deposits are pending, bounded by
    /// `--max-wait`; the count reached, or a named refusal.
    fn wait_mined(&self, w: &WalletDir, before: usize, what: &str) -> Result<usize, String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(self.max_wait_secs);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(self.poll_secs));
            let (now, _) = self.scan(w, self.tip()?);
            if now.len() > before {
                return Ok(now.len());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "{what} was posted but not seen mined within {} s — rerun `seed` once it is (it waits for it, never \
                     burning again). If the node dropped it, remove {} and rerun",
                    self.max_wait_secs,
                    inflight_path(&self.out).display()
                ));
            }
        }
    }

    /// The run: wait for a burn a previous run left in flight, plan, burn
    /// the shortfall (each mined before the next), claim every pending
    /// deposit without a claim file, and hand every untaken claim file to
    /// the intake.
    ///
    /// A fresh `--out` forgets which claims were made: it re-proves them,
    /// and the intake answers the repeats 409 (the same cnf) — no harm, only
    /// the proofs' cost.
    pub fn run(&self) -> Result<(), String> {
        let chain = self.chain();
        let route = qumbra_wallet::deposit::check_bridge(
            &qumbra_wallet::deposit::fetch_l2(&self.node)
                .map_err(|e| format!("the node did not say which L2 its chain bridges ({e}); refusing to burn"))?,
            chain.l2_id,
            &chain.genesis,
        )?;
        if route.claim_fee_tier != chain.claim_fee_tier {
            return Err(format!(
                "the node's claim tier {} is not the genesis file's {}: refusing to build claims either would refuse",
                route.claim_fee_tier, chain.claim_fee_tier
            ));
        }
        if self.burn <= chain.claim_fee_tier {
            return Err(format!("--burn {} is not above the claim tier {}: its claim would credit nothing", self.burn, chain.claim_fee_tier));
        }
        let w = l1_wallet(&self.out.join("l1-wallet"), &self.key)?;
        let wallet = w.wallet();
        let keys = Keys::from_seed(*self.key.filler_seed);
        let fee = qlab_devnet::fees::posted_fee(qlab_devnet::fees::ArityBucket::TwoByTwo);
        let inflight = inflight_path(&self.out);
        let (mut deposits, mut funded) = self.scan(&w, self.tip()?);
        if let Ok(text) = std::fs::read_to_string(&inflight) {
            let before: usize = text.trim().parse().map_err(|_| format!("{}: not a deposit count", inflight.display()))?;
            if deposits.len() <= before {
                println!("seed: a burn from an earlier run is in flight ({}); waiting for it before anything else", inflight.display());
                if !self.plan {
                    self.wait_mined(&w, before, "the earlier run's burn")?;
                    (deposits, funded) = self.scan(&w, self.tip()?);
                }
            }
            if deposits.len() > before {
                let _ = std::fs::remove_file(&inflight);
            }
        }
        let short = shortfall(self.count, deposits.len());
        let unclaimed = deposits.iter().filter(|d| !claim_path(&self.out, d).exists()).count();
        println!("seed: L1 wallet address {}", wallet.address_at_index(0).encode());
        println!("{}", plan_text(short, deposits.len(), unclaimed + short, self.burn, fee, funded));
        let need = u128::from(self.burn.saturating_add(fee)) * short as u128;
        match funded {
            _ if short == 0 => {}
            Some(f) if f >= need => {}
            Some(f) => {
                return Err(format!(
                    "the L1 wallet holds {f} spendable bessel and {short} burn(s) need {need}: fund its address \
                     (above) and rerun — nothing was burned"
                ))
            }
            None => return Err("the L1 wallet's spendable figure is UNAVAILABLE (the scan was incomplete): refusing to burn".into()),
        }
        if self.plan {
            println!(
                "--plan: nothing burned, proved or posted — only the wallet directory ({}) was created",
                w.dir.display()
            );
            return Ok(());
        }

        // The burns, one per transaction, each mined before the next. The
        // in-flight record goes down after the proof and before the POST.
        let burn_to = qumbra_wallet::deposit::burn_address(&wallet, chain.l2_id);
        let mut have = deposits.len();
        for i in 0..short {
            // A burn whose inputs are held but not finalized yet (the
            // previous burn's change, a fund note in a recent block) is a
            // wait, not a failure: the wallet refuses it before any proof,
            // and this polls until finality passes them, bounded by
            // `--max-wait`.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(self.max_wait_secs);
            loop {
                let tip = self.tip()?;
                let req = qumbra_wallet::spend::SendRequest {
                    dir: &w.dir,
                    url: &self.scan,
                    node_url: &self.node,
                    recipient: &burn_to,
                    contact_name: None,
                    amount: self.burn,
                    scan_to: tip,
                    no_submit: false,
                    name_op: None,
                    form: self.genesis.forms().0,
                };
                let mut sink = |s: qumbra_wallet::spend::SendStep| eprintln!("SEED burn {}: {s:?}", i + 1); // debug-ok: SendStep is the flow's progress — counts, roots, timings, the node's answer; no opening
                let mut record = |_: &[u8]| crate::state::write_atomic(&inflight, have.to_string().as_bytes());
                match qumbra_wallet::spend::execute_opened_with_pre_submit(&req, &w, &mut sink, &mut record) {
                    Ok(_) => break,
                    Err(qumbra_wallet::spend::SendError::Refused(why)) if is_finality_wait(&why) => {
                        if std::time::Instant::now() >= deadline {
                            return Err(format!(
                                "burn {} of {short}: its inputs were still not finalized after {} s — {why}",
                                i + 1,
                                self.max_wait_secs
                            ));
                        }
                        let fin = crate::chain::read(&crate::chain::Http { base: self.node.clone() })
                            .ok()
                            .and_then(|v| v.anchors.finalized_height)
                            .map_or("none".to_string(), |h| h.to_string());
                        println!("seed: burn {} of {short} waits for finality (tip {tip}, finalized {fin}): its inputs are not finalized yet", i + 1);
                        std::thread::sleep(std::time::Duration::from_secs(self.poll_secs));
                    }
                    Err(e) => return Err(format!("burn {} of {short}: {e}", i + 1)),
                }
            }
            have = self.wait_mined(&w, have, &format!("burn {} of {short}", i + 1))?;
            let _ = std::fs::remove_file(&inflight);
        }

        // The claims: every pending deposit without a file.
        let (deposits, _) = self.scan(&w, self.tip()?);
        let todo: Vec<&SetAside> = deposits.iter().filter(|d| !claim_path(&self.out, d).exists()).collect();
        let mut problems = Vec::new();
        if !todo.is_empty() {
            std::fs::create_dir_all(self.out.join("claims")).map_err(|e| format!("{}: {e}", self.out.display()))?;
            let (synced, newest) = qumbra_wallet::sync::sync_and_select(
                &w.dir,
                &qumbra_wallet::net::HttpLeafSource::new(self.node.as_str()),
                &qumbra_wallet::net::HttpAnchorSource::new(self.node.as_str()),
            )
            .map_err(|e| format!("the L1 tree or its anchor: {e}"))?;
            for d in todo {
                let (inst, r_v) = match seed_claim(&synced.tree, newest.count, d, chain.l2_id, chain.claim_fee_tier, &wallet, &keys) {
                    Ok(c) => c,
                    Err(e) => {
                        problems.push(skip_reason(d.height, &e));
                        continue;
                    }
                };
                let proof = qlab_l2spend::prove_claim(&inst);
                let bytes = qlab_l2spend::encode_claim_artifact(&chain.genesis, chain.l2_id, &inst.pvs, &proof, d.note.value, &r_v);
                let path = claim_path(&self.out, d);
                crate::state::write_atomic(&path, &bytes)?;
                println!("seed: wrote {}", path.display());
            }
        }

        // Every claim file not yet taken — this run's and any an earlier run
        // wrote but never handed over — goes to the intake.
        if let Some(addr) = self.intake {
            for path in untaken(&self.out)? {
                let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                match (qlab_l2spend::PlainHttp { addr }).post(INTAKE_PATH, &bytes) {
                    Ok((202 | 409, _)) => {
                        crate::state::write_atomic(&taken_path(&path), b"")?;
                        println!("seed: the intake took {}", path.display());
                    }
                    Ok((status, body)) => problems.push(format!("{} ({status}: {})", path.display(), String::from_utf8_lossy(&body))),
                    Err(e) => problems.push(format!("{} ({e})", path.display())),
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(format!("{} item(s) not done — every file written stays in place, a rerun retries: {}", problems.len(), problems.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The finality wait is recognised from the wallet's own refusal texts —
    /// the two "not YET" ones — and no other refusal is mistaken for it.
    #[test]
    fn a_not_yet_final_refusal_is_a_wait() {
        use qumbra_wallet::send::BuildRefusal;
        assert!(is_finality_wait(&BuildRefusal::NotYetFinalized { need: 51, finalized_have: 0, total_have: 2_199 }.to_string()));
        assert!(is_finality_wait(&BuildRefusal::OutsideAnchor { pos: 20, anchor_count: 18 }.to_string()));
        for other in [
            BuildRefusal::CannotCover { need: 51, amount: 50, fee: 1, have: 7 },
            BuildRefusal::NotInTree,
            BuildRefusal::Other("a recipient with no encapsulation key".into()),
        ] {
            assert!(!is_finality_wait(&other.to_string()), "{other}");
        }
    }

    #[test]
    fn the_shortfall_counts_what_is_already_pending() {
        assert_eq!(shortfall(15, 0), 15);
        assert_eq!(shortfall(15, 4), 11);
        assert_eq!(shortfall(15, 15), 0);
        assert_eq!(shortfall(15, 20), 0);
        let text = plan_text(11, 4, 15, 50_000, 10, Some(1));
        assert!(text.contains("11 burn(s) of 50000 bessel") && text.contains("needs 550110") && text.contains("11 L1 proof(s)"), "{text}");
        assert!(plan_text(1, 0, 1, 5, 1, None).contains("UNAVAILABLE"));
    }

    /// The L1 wallet's directory holds no seed: a seed file there is refused
    /// by name, never read or overwritten; the directory is created 0700.
    #[cfg(unix)]
    #[test]
    fn the_l1_wallet_never_has_a_seed_file() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("qseq-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        use ml_dsa::Keypair;
        let vk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[0x5e; 32].into()).verifying_key().encode().to_vec();
        let key = crate::key::from_seed([0x5e; 32], &qumbra_node::genesis_v6::WrapperParams::v1(1, vk, [0; 4])).unwrap();
        let w = l1_wallet(&d, &key).unwrap();
        assert!(!d.join(SEED_FILE).exists(), "no seed file written");
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(w.wallet().address_at_index(0).to_raw_bytes(), Wallet::from_master_seed(&MasterSeed::from_entropy(*key.l1_seed), qumbra_wallet::store::HD_ACCOUNT).address_at_index(0).to_raw_bytes());
        std::fs::write(d.join(SEED_FILE), b"x").unwrap();
        let err = l1_wallet(&d, &key).err().unwrap();
        assert!(err.contains("seed file") && err.contains(SEED_FILE), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A seed claim is the sequencer's: what `seed` builds for a pending
    /// deposit, the pass recognises from the claim's public values as a note
    /// it owns — value less the tier, ρ its cnf — and nothing else does.
    #[test]
    fn a_seed_claim_credits_the_filler_wallet() {
        let l1 = Wallet::from_master_seed(&MasterSeed::from_entropy([7; 32]), qumbra_wallet::store::HD_ACCOUNT);
        let keys = Keys::from_seed([1; 32]);
        let note = qlab_note::note::Note { value: 50_000, rkm: qlab_ledger::deposits::burn_rkm(1), rho: [1; 4], rseed: [2; 4] };
        let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
        let mut tree = CommitmentTree::new();
        tree.append([9; 4]);
        tree.append(cm);
        let deposit = SetAside {
            kind: SetAsideKind::PendingDeposit { l2_id: 1 },
            div_index: 0,
            height: 3,
            tx_index: 0,
            cm: qlab_note::hash::digest_bytes(&cm),
            note,
        };
        let (inst, r_v) = seed_claim(&tree, 2, &deposit, 1, 4, &l1, &keys).unwrap();
        assert_eq!(r_v, l1.claim_blinds(&cm).0, "r_v is the L1 wallet's, as `deposit claim` derives it");
        let own = crate::members::own_credit(&inst.pvs, note.value, &keys).expect("the pass recognises it");
        assert_eq!((own.value, own.rho), (note.value - 4, claim_cnf(&cm, &note.rseed)));
        assert_eq!(crate::members::own_credit(&inst.pvs, note.value, &Keys::from_seed([2; 32])), None);
        assert!(claim_path(Path::new("/o"), &deposit).ends_with(format!("claims/{}.claim", hex(&deposit.cm))));

        // A burn past the newest finalized anchor is a wait, named as one;
        // any other refusal is named as what it is, never as a wait.
        let err = seed_claim(&tree, 1, &deposit, 1, 4, &l1, &keys).err().unwrap();
        assert_eq!(err, ClaimError::AboveAnchor { pos: 1, anchor_count: 1 });
        let wait = skip_reason(3, &err);
        assert!(wait.contains("not yet under a finalized anchor") && wait.contains("rerun"), "{wait}");
        let below = skip_reason(3, &seed_claim(&tree, 2, &deposit, 1, 50_000, &l1, &keys).err().unwrap());
        assert!(below.contains("cannot be claimed") && !below.contains("rerun"), "{below}");
    }

    /// Every claim file not marked taken is handed over again on each run;
    /// a taken one, or anything that is not a claim file, never is.
    #[test]
    fn untaken_claims_are_handed_over_again() {
        let d = std::env::temp_dir().join(format!("qseq-untaken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(untaken(&d).unwrap(), Vec::<PathBuf>::new(), "no claims dir yet");
        let c = d.join("claims");
        std::fs::create_dir_all(&c).unwrap();
        for f in ["b.claim", "a.claim", "c.claim", "notes.txt"] {
            std::fs::write(c.join(f), b"x").unwrap();
        }
        std::fs::write(taken_path(&c.join("c.claim")), b"").unwrap();
        assert_eq!(untaken(&d).unwrap(), vec![c.join("a.claim"), c.join("b.claim")]);
        let _ = std::fs::remove_dir_all(&d);
    }
}
