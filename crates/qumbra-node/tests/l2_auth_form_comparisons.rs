//! The `L2AuthForm::CandidateA` comparison lock (lab #937 PR B, the
//! coordinator's ruling on design A).
//!
//! Format 34 is a new axis value, `L2AuthForm::CandidateAV3`, beside format
//! 33's `CandidateA`. Every exhaustive `match` learned it at compile time; a
//! **comparison** against `CandidateA` did not — `form == CandidateA` is
//! silently `false` on a format-34 net and routes it into whatever the `else`
//! does (the v1 path, or no refusal at all). PR B converted the eleven such
//! sites (to `has_auth()`, `sp_outputs()`, or an exhaustive `match` that names
//! format 34's answer). This test keeps them converted: outside the explicit
//! [`ALLOWED`] list, nothing in `crates/` — source, tests, examples — compares
//! against `L2AuthForm::CandidateA` with `==`, `!=` or `matches!`.
//!
//! Say what you mean instead: `form.has_auth()` (formats 33 and 34),
//! `form.sp_outputs()` (2 or 3), or `match form { … }` with every arm.
//!
//! The scanner reuses `genesis_form_exhaustive`'s lexer (string literals and
//! line comments blanked) and checks itself against synthetic violations
//! first; it also proves it looked (the variant is named well over twenty
//! times in the workspace).

use std::path::{Path, PathBuf};

/// The explicit allowlist: `(path suffix under crates/, the trimmed code
/// line, the reason)`. Empty at PR B: every site was converted. An entry that
/// no longer matches a line fails the test, so the list cannot rot.
const ALLOWED: &[(&str, &str, &str)] = &[];

/// Blank out string-literal contents and line comments, carrying an open
/// string across lines (`"…\` continuations). A banned shape inside a string
/// is data, not code — the synthetic samples in this very file are the case
/// that taught it (the first lane run flagged its own self-test strings).
/// Raw strings (`r"…"`, `r#"…"#`) are not modelled; none in this workspace
/// spells a banned shape, and the self-test would show one that did.
fn code_lines(text: &str) -> Vec<String> {
    let mut in_str = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut code = String::with_capacity(line.len());
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if in_str {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == '"' {
                    in_str = false;
                    code.push('"');
                }
                i += 1;
                continue;
            }
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                break;
            }
            if c == '\'' && chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'\'') {
                code.push_str("' '");
                i += 3;
                continue;
            }
            if c == '"' {
                in_str = true;
                code.push('"');
                i += 1;
                continue;
            }
            code.push(c);
            i += 1;
        }
        out.push(code);
    }
    out
}


/// A comparison against the `CandidateA` variant: `== L2AuthForm::CandidateA`,
/// `!=`, either side, or `matches!(…, …L2AuthForm::CandidateA…)` — but not
/// `CandidateAV3`.
fn has_candidate_a_comparison(code: &str) -> bool {
    const V: &str = "L2AuthForm::CandidateA";
    let b = code.as_bytes();
    let mut from = 0;
    while let Some(off) = code[from..].find(V) {
        let i = from + off;
        let r = i + V.len();
        // Not `CandidateAV3` (or any longer identifier).
        if r < b.len() && (b[r].is_ascii_alphanumeric() || b[r] == b'_') {
            from = r;
            continue;
        }
        let mut l = i;
        while l > 0 && (b[l - 1].is_ascii_alphanumeric() || b[l - 1] == b'_' || b[l - 1] == b':') {
            l -= 1;
        }
        let before = code[..l].trim_end();
        let after = code[r..].trim_start();
        if before.ends_with("==") || before.ends_with("!=") || after.starts_with("==") || after.starts_with("!=") {
            return true;
        }
        // `matches!(x, L2AuthForm::CandidateA)` (also `… | L2AuthForm::CandidateA`).
        if let Some(m) = code[..i].rfind("matches!(") {
            if !code[m..i].contains(')') {
                return true;
            }
        }
        from = r;
    }
    false
}

/// Every offending line of `text` (1-based line, trimmed code).
fn scan(text: &str) -> (Vec<(usize, String)>, usize) {
    let mut out = Vec::new();
    let mut named = 0;
    for (i, c) in code_lines(text).iter().enumerate() {
        named += c
            .match_indices("L2AuthForm::CandidateA")
            .filter(|(i, m)| {
                let r = i + m.len();
                !c[r..].starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
            })
            .count();
        if has_candidate_a_comparison(c) {
            out.push((i + 1, c.trim().to_string()));
        }
    }
    (out, named)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read_dir") {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The scanner catches each banned shape and passes each legal one.
#[test]
fn the_candidate_a_scanner_catches_what_it_bans() {
    for (src, what) in [
        ("if session.l2_auth == qlab_devnet::forms::L2AuthForm::CandidateA {}\n", "=="),
        ("if b.form != L2AuthForm::CandidateA {\n", "!="),
        ("let x = L2AuthForm::CandidateA == f;\n", "== on the left"),
        ("if matches!(f, L2AuthForm::CandidateA) {}\n", "matches!"),
        ("if matches!(f, L2AuthForm::None | L2AuthForm::CandidateA) {}\n", "matches! with an or-pattern"),
    ] {
        assert!(!scan(src).0.is_empty(), "the scanner missed {what}");
    }
    let good = concat!(
        "match f {\n    L2AuthForm::None => 0,\n    L2AuthForm::CandidateA => 1,\n    L2AuthForm::CandidateAV3 => 2,\n}\n",
        "if f == L2AuthForm::CandidateAV3 {}\n",
        "if f.has_auth() {}\n",
        "let s = \"if f == L2AuthForm::CandidateA {}\";\n",
        "// if f == L2AuthForm::CandidateA {}\n",
        "AuthContext { form: L2AuthForm::CandidateA, genesis_hash }\n",
    );
    let (v, named) = scan(good);
    assert!(v.is_empty(), "false positives: {v:?}");
    // `CandidateA` in the match arm and the struct literal; not `CandidateAV3`,
    // not the string, not the comment.
    assert_eq!(named, 2, "the scanner counts the exact variant in code only");
}

/// Nothing in `crates/` compares against `L2AuthForm::CandidateA` outside
/// [`ALLOWED`]; every allowlist entry still names a real line; and the scan
/// saw the workspace.
#[test]
fn no_bare_candidate_a_comparisons() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(files.len() > 200, "the scan must see the workspace; saw {} files", files.len());
    let mut bad = Vec::new();
    let mut used = vec![false; ALLOWED.len()];
    let mut named = 0;
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        let (v, n) = scan(&text);
        named += n;
        let path = f.to_string_lossy().replace('\\', "/");
        for (line, code) in v {
            match ALLOWED.iter().position(|(p, c, _)| path.ends_with(p) && code == *c) {
                Some(k) => used[k] = true,
                None => bad.push(format!("{}:{line} `{code}`", f.display())),
            }
        }
    }
    assert!(named >= 20, "only {named} mentions of L2AuthForm::CandidateA scanned — the scanner is blind");
    let stale: Vec<_> = ALLOWED.iter().zip(&used).filter(|(_, u)| !**u).map(|(a, _)| a.0).collect();
    assert!(stale.is_empty(), "allowlist entries that match nothing: {stale:?}");
    assert!(
        bad.is_empty(),
        "compare the L2 axis by meaning — has_auth(), sp_outputs(), or an exhaustive match (lab #937):\n{}",
        bad.join("\n")
    );
}
