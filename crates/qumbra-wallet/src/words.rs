//! One wording for a [`SendStep`](crate::spend::SendStep), shared by the two
//! surfaces that must agree: the desktop window and the browser popup (which
//! receives these strings over the prover host's pipe and displays them
//! verbatim — the popup's job is to show text, never to decide what a step
//! means).
//!
//! Hoisted from `qumbra-wallet-desktop`'s `core.rs` on the prover-host rung
//! (lab #400): the host is `word_for`'s THIRD caller, and rendering in JS
//! would have been the fourth copy of a reduction this project has already
//! watched diverge three times. The library still gives `SendStep` no
//! `Display`, deliberately — the CLI keeps its own stderr wording, and this
//! function stays one surface family's choice, not the type's.

use crate::spend::SendStep;

/// Integer-exact bessel → QMB, the one money formatter (#303 is standing law
/// on money; no float is reachable from here).
pub fn qmb(bessel: u64) -> String {
    qlab_wallet::uri::bessel_to_qmb(bessel)
}

/// The window's — and the popup's — wording for a step.
pub fn word_for(step: &SendStep) -> String {
    use SendStep as S;
    match step {
        S::Resolved { recipient_short, contact } => match contact {
            // Paying the wrong person is the one mistake with no undo, so a
            // contact ALWAYS shows the address it resolved to.
            Some(name) => format!("paying contact “{name}” → {recipient_short}"),
            None => format!("paying {recipient_short}"),
        },
        // Lab #424: loud, and first — a user must never take a completed send as
        // proof that their mined coins were in view.
        S::CoinbaseUnavailable { why } => format!("🔴 {why}"),
        S::Selected { spendable, skipped_spent, mined } => {
            let mut t = format!("{spendable} spendable note(s) selected");
            if *mined > 0 {
                t.push_str(&format!(", {mined} of them matured coinbase this wallet mined"));
            }
            if *skipped_spent > 0 {
                t.push_str(&format!(
                    "; {skipped_spent} already-spent skipped (their nullifiers are on the chain)"
                ));
            }
            t
        }
        S::Tree { held, fetched, anchor_count, node_tip, anchor_behind, .. } => {
            let mut t = format!(
                "tree synced: {held} leaves ({fetched} new); anchor at {anchor_count}, node tip {node_tip}"
            );
            if *anchor_behind > 0 {
                t.push_str(&format!(
                    " — the anchor trails by {anchor_behind}, which is normal: a witness must be \
                     built against a FINALIZED root"
                ));
            }
            t
        }
        S::Proving => "proving — a real STARK, several seconds and gigabytes. Not hung.".into(),
        S::Built { amount, fee, change, prove_secs, used_dummy } => format!(
            "built: {amount} bessel ({} QMB), fee {fee} ({} QMB), change {change} ({} QMB) — \
             proved in {prove_secs:.2} s{}",
            qmb(*amount),
            qmb(*fee),
            qmb(*change),
            if *used_dummy { " (single real note + dummy slot)" } else { "" }
        ),
        S::Recorded => format!(
            "recipient recorded locally in {} — NOT on the chain, and a restore from your \
             mnemonic will not bring it back",
            crate::sends::SENDS_FILE
        ),
        S::Warning(w) => format!("⚠️ {w}"),
        S::Submitting => "submitting…".into(),
        S::Answered { status, body } => format!("node [{status}]: {body}"),
    }
}
