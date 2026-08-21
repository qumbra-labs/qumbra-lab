//! **Structural guard: nobody outside `qlab-node` derives a coinbase note under a
//! hard-coded genesis form** (lab #559).
//!
//! The defect this exists to prevent has already happened once, and it was total
//! rather than partial. `Node::apply_state` appends
//! `matured_coinbase_leaf_for(self.form, …)`; `qumbra-faucet`'s harvest called the
//! v4 `coinbase_note` / `coinbase_note_leaf`. v5 derives ρ and rseed under a `:v2`
//! domain with the payee index in the preimage, so the two forms produce the same
//! *value* and a different *commitment*. On T2 the faucet therefore funded every
//! note it ever held with a `cm` that is not in the commitment tree: no leaf, no
//! witness, no spend, at any height, by any wait. The page reported it as a
//! maturity wait whose promised height receded every time the chain reached it.
//!
//! The fix added `coinbase_note_for(form, …)` and doc warnings on the v4 twins. A
//! doc warning is not a guard — **nobody read the last one** — so the rule is a
//! test: outside the crate that defines them, the v4 entry points are not called
//! from production code, only their `_for` counterparts.
//!
//! Same idiom as `qlab_devnet::emission_exact::tests::the_module_source_contains_no_float`:
//! a lint nobody runs in the acceptance suite is a comment, so the source is read
//! and the property is asserted. Scope is deliberate:
//!
//! * **`src/` only.** A `tests/` file may legitimately build v4 fixtures.
//! * **Above the first `#[cfg(test)]` only.** Test code inside a `src` file is
//!   allowed to name the v4 derivation for the same reason.
//! * **Comment text stripped**, because the prose necessarily talks about v4.

use std::fs;
use std::path::{Path, PathBuf};

/// The v4-only entry points. A holder on any other form that calls one of these
/// computes a commitment its chain's tree does not contain.
///
/// The trailing `(` is load-bearing: it is what keeps `coinbase_note_for(`,
/// `coinbase_note_leaf_for(` and `coinbase_note_parts_v5(` — the correct calls —
/// from matching their own prefixes.
const V4_ONLY: [&str; 3] = ["coinbase_note(", "coinbase_note_leaf(", "coinbase_note_parts("];

/// Production sites outside `qlab-node` that still call a v4 entry point, each with
/// the issue that closes it.
///
/// 🔴 **This list only shrinks.** An entry whose file no longer calls one is a stale
/// exemption and fails the test below, so a fix cannot land while quietly leaving a
/// hole open behind it.
const ALLOWED: [(&str, &str); 1] = [(
    "qumbra-wallet/src/coinbase.rs",
    "lab #566 — the wallet's coinbase scan needs the form from RPC net facts, which \
     is a different change from #559's",
)];

/// The crate that defines the derivations, and therefore the one place the v4 names
/// are ordinary code.
const OWNER: &str = "qlab-node";

fn crates_dir() -> PathBuf {
    // …/crates/qlab-node → …/crates
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives under crates/")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, recursively.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The lines of `src` that are production code and not comment text, as
/// `(1-based line number, code)`.
fn production_code(src: &str) -> Vec<(usize, String)> {
    let code = src.split("#[cfg(test)]").next().unwrap_or("");
    code.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.split("//").next().unwrap_or("").to_string()))
        .collect()
}

/// `crate-relative/path.rs` — the key `ALLOWED` is written in, and what a failure
/// message can be pasted from.
fn key(path: &Path, crates: &Path) -> String {
    path.strip_prefix(crates)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn v4_calls_in(path: &Path) -> Vec<(usize, String, &'static str)> {
    let Ok(src) = fs::read_to_string(path) else { return Vec::new() };
    let mut out = Vec::new();
    for (n, code) in production_code(&src) {
        for pattern in V4_ONLY {
            if code.contains(pattern) {
                out.push((n, code.trim().to_string(), pattern));
            }
        }
    }
    out
}

/// 🔴 The rule: outside `qlab-node`, production code calls the form-aware
/// derivations or nothing at all.
#[test]
fn only_qlab_node_derives_a_coinbase_note_under_a_hard_coded_form() {
    let crates = crates_dir();
    let mut offenders = Vec::new();
    for entry in fs::read_dir(&crates).expect("crates/ is readable").flatten() {
        let dir = entry.path();
        if !dir.is_dir() || dir.file_name().is_some_and(|n| n == OWNER) {
            continue;
        }
        let mut files = Vec::new();
        rs_files(&dir.join("src"), &mut files);
        files.sort();
        for file in files {
            let k = key(&file, &crates);
            if ALLOWED.iter().any(|(allowed, _)| *allowed == k) {
                continue;
            }
            for (line, code, pattern) in v4_calls_in(&file) {
                offenders.push(format!("{k}:{line} calls `{pattern}` — {code}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these sites derive a coinbase note under a hard-coded genesis form:\n  {}\n\n\
         Call `coinbase_note_for(form, …)` / `coinbase_note_leaf_for(form, …)` with the \
         form of the chain being read — `Node::form()` has it. v5's ρ and rseed carry the \
         payee index under a `:v2` domain, so a note derived under the wrong form has no \
         leaf in the tree, no membership witness and no spend: it is value the holder can \
         see and can never move (lab #559). If a site genuinely cannot know its form yet, \
         add it to ALLOWED with the issue that closes it.",
        offenders.join("\n  ")
    );
}

/// 🔴 …and the exemption list cannot rot: an entry whose file has been fixed must be
/// deleted, not left standing as a hole the next reader assumes is still needed.
#[test]
fn every_allowed_exemption_is_still_being_used() {
    let crates = crates_dir();
    for (allowed, why) in ALLOWED {
        let path = crates.join(allowed);
        assert!(path.exists(), "ALLOWED names a file that does not exist: {allowed} ({why})");
        assert!(
            !v4_calls_in(&path).is_empty(),
            "{allowed} no longer derives a coinbase note under a hard-coded form — delete \
             its ALLOWED entry ({why}), because a stale exemption is a hole nobody is \
             looking at any more."
        );
    }
}
