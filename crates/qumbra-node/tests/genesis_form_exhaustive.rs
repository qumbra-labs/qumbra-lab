//! The `GenesisForm` exhaustiveness lock (lab #706, the B1 stage-0 ruling's
//! P3 grep-lock, the first acceptance item the coordinator reads).
//!
//! Every per-form decision in this workspace must be an **exhaustive `match`
//! over [`GenesisForm`]** so that adding a form (as #706 added `Annulet`) fails
//! to compile at every site until someone decides that site's answer. Two
//! shapes defeat the compiler and are therefore banned everywhere — source,
//! tests, examples:
//!
//! 1. a wildcard or binding catch-all arm (`_ =>`, `other =>`) in a `match`
//!    whose arms name `GenesisForm` variants;
//! 2. an `==` / `!=` comparison against a `GenesisForm` variant — the shape of
//!    the three sites #706 converted (`supply.rs`, `qlab-p2p/src/node.rs`,
//!    `qumbra-pool/src/template.rs`), each of which would have routed an
//!    Annulet net silently into an L1 arm.
//!
//! `matches!(form, GenesisForm::X)` stays legal: it names its pattern, and its
//! `false` is the caller's explicit decision.
//!
//! The scanner is lexical (line comments stripped, brace depth tracked), and it
//! checks itself first against synthetic violations — a scan that found nothing
//! because it looked at nothing must fail, not pass.

use std::path::{Path, PathBuf};

fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn is_variant_path_at(s: &str, i: usize) -> bool {
    // `GenesisForm::X` possibly prefixed by `a::b::`.
    s[i..].starts_with("GenesisForm::")
}

/// `== GenesisForm::X`, `!= …`, `GenesisForm::X ==`, `GenesisForm::X !=`.
fn has_variant_comparison(code: &str) -> bool {
    let mut from = 0;
    while let Some(off) = code[from..].find("GenesisForm::") {
        let i = from + off;
        // Walk left over a path prefix (`qlab_devnet::forms::`).
        let mut l = i;
        let b = code.as_bytes();
        while l > 0 && (b[l - 1].is_ascii_alphanumeric() || b[l - 1] == b'_' || b[l - 1] == b':') {
            l -= 1;
        }
        let before = code[..l].trim_end();
        // Walk right over the variant name.
        let mut r = i + "GenesisForm::".len();
        while r < b.len() && (b[r].is_ascii_alphanumeric() || b[r] == b'_') {
            r += 1;
        }
        let after = code[r..].trim_start();
        if before.ends_with("==") || before.ends_with("!=") || after.starts_with("==") || after.starts_with("!=") {
            return true;
        }
        from = r;
        debug_assert!(is_variant_path_at(code, i));
    }
    false
}

/// A match arm whose pattern is a `GenesisForm` variant (`X =>` or `X |`).
fn is_form_arm(code: &str) -> bool {
    let s = code.trim_start().trim_start_matches('|').trim_start();
    let Some(i) = s.find("GenesisForm::") else { return false };
    let prefix = &s[..i];
    if !prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') {
        return false;
    }
    let mut r = i + "GenesisForm::".len();
    let b = s.as_bytes();
    while r < b.len() && (b[r].is_ascii_alphanumeric() || b[r] == b'_') {
        r += 1;
    }
    let rest = s[r..].trim_start();
    rest.starts_with("=>") || rest.starts_with('|')
}

/// `_ =>` / `other =>` / `x if … =>` — a catch-all arm.
fn is_catch_all_arm(code: &str) -> bool {
    let s = code.trim();
    let ident_end = s.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(s.len());
    if ident_end == 0 {
        return false;
    }
    let ident = &s[..ident_end];
    let lower_or_underscore = ident.starts_with('_') || ident.chars().next().is_some_and(|c| c.is_ascii_lowercase());
    if !lower_or_underscore {
        return false;
    }
    let rest = s[ident_end..].trim_start();
    rest.starts_with("=>") || (rest.starts_with("if ") && rest.contains("=>"))
}

#[derive(Debug, PartialEq)]
struct Violation {
    line: usize,
    kind: &'static str,
    text: String,
}

/// Scan one file's text. Returns the violations and how many form-match
/// blocks were examined.
fn scan(text: &str) -> (Vec<Violation>, usize) {
    let lines: Vec<&str> = text.lines().map(strip_comment).collect();
    let mut out = Vec::new();
    for (i, c) in lines.iter().enumerate() {
        if has_variant_comparison(c) {
            out.push(Violation { line: i + 1, kind: "comparison", text: c.trim().to_string() });
        }
    }
    let depth_delta = |s: &str| s.matches('{').count() as i64 - s.matches('}').count() as i64;
    let mut blocks = std::collections::BTreeSet::new();
    for (i, c) in lines.iter().enumerate() {
        if !is_form_arm(c) {
            continue;
        }
        // The line opening the enclosing block.
        let mut d = 0i64;
        let mut open = i;
        while open > 0 {
            open -= 1;
            d -= depth_delta(lines[open]);
            if d < 0 {
                break;
            }
        }
        if !blocks.insert(open) {
            continue;
        }
        let mut d = 0i64;
        for (k, line) in lines.iter().enumerate().skip(open) {
            if k > open && d == 1 && is_catch_all_arm(line) {
                out.push(Violation { line: k + 1, kind: "catch-all arm", text: line.trim().to_string() });
            }
            d += depth_delta(line);
            if k > open && d <= 0 {
                break;
            }
        }
    }
    (out, blocks.len())
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
fn the_scanner_catches_what_it_bans() {
    let bad_wild = "match form {\n    GenesisForm::V4 => 1,\n    _ => 2,\n}\n";
    let bad_bind = "match f {\n    qlab_devnet::forms::GenesisForm::V5 => 1,\n    other => 2,\n}\n";
    let bad_eq = "if self.form == GenesisForm::V4 && x {}\n";
    let bad_ne = "let y = qlab_devnet::forms::GenesisForm::V5 != f;\n";
    for (src, what) in [(bad_wild, "wildcard"), (bad_bind, "binding"), (bad_eq, "=="), (bad_ne, "!=")] {
        assert!(!scan(src).0.is_empty(), "the scanner missed a {what}");
    }
    let good = "match form {\n    GenesisForm::V4 => 1,\n    GenesisForm::V5 | GenesisForm::Annulet => {\n        match n { 1 => 2, _ => 3 }\n    }\n}\nlet b = matches!(f, GenesisForm::V5);\nmatch s { \"v4\" => Ok(GenesisForm::V4), other => Err(other) }\n";
    let (v, blocks) = scan(good);
    assert!(v.is_empty(), "false positives: {v:?}");
    assert_eq!(blocks, 1, "exactly one form match in the legal sample");
}

/// The workspace has no catch-all arm over `GenesisForm` and no comparison
/// against a variant — and the scan actually looked at the ~30 form matches
/// the Annulet arm was added to.
#[test]
fn genesis_form_is_matched_exhaustively_everywhere() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(files.len() > 200, "the scan must see the workspace; saw {} files", files.len());
    let mut all = Vec::new();
    let mut blocks = 0;
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read source");
        let (v, b) = scan(&text);
        blocks += b;
        all.extend(v.into_iter().map(|v| format!("{}:{} {} `{}`", f.display(), v.line, v.kind, v.text)));
    }
    assert!(blocks >= 30, "only {blocks} GenesisForm match blocks scanned — the scanner is blind");
    assert!(all.is_empty(), "GenesisForm must be matched exhaustively (lab #706):\n{}", all.join("\n"));
}
