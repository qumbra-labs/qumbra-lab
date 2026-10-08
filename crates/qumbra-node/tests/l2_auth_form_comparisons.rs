//! The `L2AuthForm::CandidateA` comparison lock (lab #937 PR B, the
//! coordinator's ruling on design A, hardened in review F1).
//!
//! Format 34 is a new axis value, `L2AuthForm::CandidateAV3`, beside format
//! 33's `CandidateA`. Every exhaustive `match` learned it at compile time; a
//! **comparison** against `CandidateA` did not — `form == CandidateA` is
//! silently `false` on a format-34 net and routes it into whatever the `else`
//! does. PR B converted the eleven such sites (to `has_auth()`, `sp_outputs()`,
//! or an exhaustive `match` that names format 34's answer). This test keeps
//! them converted, over every `.rs` file in `crates/` — source, tests,
//! examples — outside the explicit [`ALLOWED`] list:
//!
//! 1. **No way to spell the variant but `L2AuthForm::CandidateA` (or
//!    `Self::CandidateA`).** Banned: any `use` that imports from or renames the
//!    type (`L2AuthForm::*`, `L2AuthForm::{…}`, `L2AuthForm::CandidateA`,
//!    `L2AuthForm as X`, `pub use` included) and `type X = L2AuthForm`. So a
//!    bare `CandidateA` can never be this variant (the faucet's unrelated
//!    `struct CandidateA` stays legal).
//! 2. **No comparison naming the variant**, scanned per *segment* of the
//!    file (the code between `;`, `{`, `}` and `=>`, across lines): a segment
//!    naming it may not contain `==` / `!=` (which also catches
//!    `x == Some(L2AuthForm::CandidateA)`), may not hold it in a `matches!`
//!    **pattern** (multi-line included; an argument of the matched expression
//!    is fine), and may not hold it on the pattern side of a `let`
//!    (`if let`, `while let`, `let … else`).
//!
//! `assert_eq!` / `assert_ne!` are test assertions naming the exact expected
//! value, not routing, and stay legal; so do match arms, struct fields,
//! arguments and `let x = L2AuthForm::CandidateA`.
//!
//! Say what you mean instead: `form.has_auth()` (formats 33 and 34),
//! `form.sp_outputs()` (2 or 3), or `match form { … }` with every arm.
//!
//! The scanner blanks string literals and line comments (the
//! `genesis_form_exhaustive` lexer), checks itself against one synthetic
//! sample per bypass first, and proves it looked (the variant is named well
//! over twenty times in the workspace). Its algorithm was previewed over the
//! workspace in Python before it reached the lane (lab #937 PR B's body).

use std::path::{Path, PathBuf};

/// The explicit allowlist: `(path suffix under crates/, the violation's
/// whitespace-normalized text, the reason)`. Empty: every site was
/// converted. An entry that no longer matches fails the test.
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


fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Byte offsets of the variant: `L2AuthForm::CandidateA` (any path prefix)
/// or `Self::CandidateA`, never `CandidateAV3` or a longer identifier.
fn variant_offsets(code: &str) -> Vec<usize> {
    const TAIL: &str = "::CandidateA";
    let b = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = code[from..].find(TAIL) {
        let i = from + off;
        let r = i + TAIL.len();
        from = r;
        if r < b.len() && is_ident(b[r]) {
            continue;
        }
        for head in ["L2AuthForm", "Self"] {
            if i >= head.len() && &b[i - head.len()..i] == head.as_bytes() {
                let s = i - head.len();
                if s == 0 || !is_ident(b[s - 1]) {
                    out.push(s);
                }
            }
        }
    }
    out
}

/// `word` at `i`, bounded by non-identifier bytes.
fn word_at(s: &str, i: usize, word: &str) -> bool {
    let b = s.as_bytes();
    s[i..].starts_with(word)
        && (i == 0 || !is_ident(b[i - 1]))
        && (i + word.len() >= b.len() || !is_ident(b[i + word.len()]))
}

fn find_word(s: &str, word: &str) -> Option<usize> {
    (0..s.len()).find(|&i| s.is_char_boundary(i) && word_at(s, i, word))
}

/// Every `use` / `type` statement whole: `(offset, keyword, text up to ;)`.
fn statements(code: &str) -> Vec<(usize, &'static str, &str)> {
    let mut out = Vec::new();
    let mut line_start = 0;
    for line in code.split_inclusive('\n') {
        let mut i = line_start + (line.len() - line.trim_start().len());
        let rest = &code[i..];
        if let Some(r) = rest.strip_prefix("pub") {
            if r.starts_with('(') {
                i += 3 + r.find(')').map_or(0, |k| k + 1);
            } else {
                i += 3;
            }
            i += code[i..].len() - code[i..].trim_start().len();
        }
        for kw in ["use", "type"] {
            if word_at(code, i, kw) {
                let end = code[i..].find(';').map_or(code.len(), |k| i + k + 1);
                out.push((i, kw, &code[i..end]));
            }
        }
        line_start += line.len();
    }
    out
}

/// The segments: code between `;`, `{`, `}` and `=>`, with their offsets.
fn segments(code: &str) -> Vec<(usize, &str)> {
    let b = code.as_bytes();
    let (mut out, mut start, mut i) = (Vec::new(), 0, 0);
    while i < b.len() {
        if matches!(b[i], b';' | b'{' | b'}') {
            out.push((start, &code[start..i]));
            start = i + 1;
        } else if b[i] == b'=' && b.get(i + 1) == Some(&b'>') {
            out.push((start, &code[start..i]));
            start = i + 2;
            i += 1;
        }
        i += 1;
    }
    out.push((start, &code[start..]));
    out
}

/// The first lone `=` in `seg` at or after `from` (not `==`, `=>`, `!=`,
/// `<=`, `>=`).
fn single_eq(seg: &str, from: usize) -> Option<usize> {
    let b = seg.as_bytes();
    (from..b.len()).find(|&j| {
        b[j] == b'='
            && !matches!(b.get(j + 1), Some(b'=' | b'>'))
            && !(j > 0 && matches!(b[j - 1], b'=' | b'!' | b'<' | b'>'))
    })
}

/// `pos` lies in the pattern of a `matches!(expr, pattern)` in `seg`: after
/// the first comma at the macro's own depth, before its closing parenthesis.
fn in_matches_pattern(seg: &str, pos: usize) -> bool {
    let b = seg.as_bytes();
    let mut from = 0;
    while let Some(off) = seg[from..].find("matches!") {
        let m = from + off;
        from = m + 1;
        if m > 0 && is_ident(b[m - 1]) {
            continue;
        }
        let mut i = m + "matches!".len();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if b.get(i) != Some(&b'(') {
            continue;
        }
        let (mut depth, mut comma) = (0i32, None);
        while i < b.len() {
            match b[i] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b',' if depth == 1 && comma.is_none() => comma = Some(i),
                _ => {}
            }
            i += 1;
        }
        if comma.is_some_and(|c| c < pos && pos < i) {
            return true;
        }
    }
    false
}

fn line_of(code: &str, at: usize) -> usize {
    code[..at].matches('\n').count() + 1
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Every violation in `text` as `(line, kind, normalized text)`, and how
/// many times the variant is named in code.
fn scan(text: &str) -> (Vec<(usize, &'static str, String)>, usize) {
    let code = code_lines(text).join("\n");
    let mut out = Vec::new();
    for (at, kw, st) in statements(&code) {
        let names_type = |follow: &dyn Fn(&str) -> bool| {
            let mut from = 0;
            while let Some(off) = st[from..].find("L2AuthForm") {
                let i = from + off;
                from = i + 1;
                if word_at(st, i, "L2AuthForm") && follow(st[i + "L2AuthForm".len()..].trim_start()) {
                    return true;
                }
            }
            false
        };
        let bad = match kw {
            "use" => names_type(&|rest: &str| rest.starts_with("::") || (rest.starts_with("as") && word_at(rest, 0, "as"))),
            _ => st.find('=').is_some_and(|e| find_word(&st[e..], "L2AuthForm").is_some()),
        };
        if bad {
            out.push((line_of(&code, at), if kw == "use" { "import" } else { "alias" }, squash(st)));
        }
    }
    let mut named = 0;
    for (start, seg) in segments(&code) {
        let hits = variant_offsets(seg);
        named += hits.len();
        for h in hits {
            let kind = if seg.contains("==") || seg.contains("!=") {
                Some("comparison")
            } else if in_matches_pattern(seg, h) {
                Some("matches! pattern")
            } else {
                find_word(seg, "let").and_then(|l| match single_eq(seg, l + 3) {
                    Some(e) if h > e => None,
                    _ => Some("let pattern"),
                })
            };
            if let Some(kind) = kind {
                out.push((line_of(&code, start + h), kind, squash(seg)));
                break;
            }
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

/// The scanner catches each banned shape — one sample per bypass the review
/// named — and passes each legal one.
#[test]
fn the_candidate_a_scanner_catches_what_it_bans() {
    let bad = [
        ("glob import", "use qlab_devnet::forms::L2AuthForm::*;\n"),
        ("brace import", "use qlab_devnet::forms::L2AuthForm::{CandidateA, None as N};\n"),
        ("variant import", "use qlab_devnet::forms::L2AuthForm::CandidateA;\n"),
        ("alias import in a group", "use qlab_devnet::forms::{GenesisForm, L2AuthForm as F};\n"),
        ("multi-line group import", "use qlab_devnet::forms::{\n    GenesisForm,\n    L2AuthForm::{CandidateA},\n};\n"),
        ("pub use alias", "pub(crate) use crate::forms::L2AuthForm as Axis;\n"),
        ("type alias", "type Axis = qlab_devnet::forms::L2AuthForm;\n"),
        ("==", "if f == L2AuthForm::CandidateA { x() }\n"),
        ("!= path-qualified", "if b.form != qlab_devnet::forms::L2AuthForm::CandidateA {\n"),
        ("== on the left", "let x = L2AuthForm::CandidateA == f;\n"),
        ("Self:: in an impl", "fn v2(self) -> bool { self == Self::CandidateA }\n"),
        ("Some(..) ==", "if self.l2_auth() == Some(L2AuthForm::CandidateA) { y() }\n"),
        ("multi-line matches!", "let v = matches!(\n    form,\n    L2AuthForm::CandidateA\n);\n"),
        ("matches! or-pattern", "if matches!(f, L2AuthForm::None | L2AuthForm::CandidateA) {}\n"),
        ("if let", "if let L2AuthForm::CandidateA = f { z() }\n"),
        ("while let", "while let Some(L2AuthForm::CandidateA) = it.next() {}\n"),
        ("let-else", "let L2AuthForm::CandidateA = f else { return };\n"),
    ];
    for (what, src) in bad {
        assert!(!scan(src).0.is_empty(), "the scanner missed: {what}");
    }
    let good = concat!(
        "use qlab_devnet::forms::{GenesisForm, L2AuthForm};\n",
        "use qlab_devnet::forms::L2AuthForm;\n",
        "type Pair = (GenesisForm, u8);\n",
        "match f {\n    L2AuthForm::None => 0,\n    L2AuthForm::CandidateA => 1,\n    L2AuthForm::CandidateAV3 => 2,\n}\n",
        "if f == L2AuthForm::CandidateAV3 {}\n",
        "let ctx = AuthContext { form: L2AuthForm::CandidateA, genesis_hash };\n",
        "let a = L2AuthForm::CandidateA;\n",
        "assert_eq!(x.l2_auth(), Ok(L2AuthForm::CandidateA));\n",
        "assert!(matches!(decode(&b, L2AuthForm::CandidateA), Err(E::Bad)));\n",
        "let (v, log) = select_verifier(false, GenesisForm::Annulet, L2AuthForm::CandidateA);\n",
        "let s = \"if f == L2AuthForm::CandidateA {}\";\n",
        "// if f == L2AuthForm::CandidateA {}\n",
        "struct CandidateA { x: u8 }\nlet c = CandidateA { x: 1 };\n",
    );
    let (v, named) = scan(good);
    assert!(v.is_empty(), "false positives: {v:?}");
    // The arm, the struct field, the `let`, the assert, the `matches!`
    // argument, the call argument — not `CandidateAV3`, the string, the
    // comment or the faucet's struct.
    assert_eq!(named, 6, "the scanner counts the exact variant in code only");
}

/// Nothing in `crates/` imports, aliases or compares `L2AuthForm::CandidateA`
/// outside [`ALLOWED`]; every allowlist entry still names a real violation;
/// and the scan saw the workspace.
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
        for (line, kind, code) in v {
            match ALLOWED.iter().position(|(p, c, _)| path.ends_with(p) && code == *c) {
                Some(k) => used[k] = true,
                None => bad.push(format!("{}:{line} {kind} `{code}`", f.display())),
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
