//! **qumbra-sequencer** — the V6 sequencer (lab #847).
//!
//! S1b: f5box's library half, moved verbatim out of qlab-bench under the same
//! module names (`chain`, `members`, `bundle`, `state`), so the sibling paths
//! the modules use (`super::chain`, …) are unchanged. The edits are
//! `pub(crate)` → `pub`, `crate::f3`/`crate::f4` → `qlab_wprover::f3`/`f4`,
//! and `cfg(test)` → `cfg(any(test, feature = "test-support"))` for the
//! helpers the bench's lane drives. qlab-bench keeps f5box's CLI (`run`) and
//! its tests and re-exports these modules at their old paths.
//!
//! - [`chain`]: what the sequencer reads from an L1 node.
//! - [`members`]: the wrapper plan — the sequencer's prefilter.
//! - [`bundle`]: prove, assemble, sign, self-check, manifest.
//! - [`state`]: the replayed run state, written atomically under a lock.
//!
//! S2 (intake): [`intake`] reads and verifies a wallet's claim or exit file,
//! [`queue`] holds what was admitted, [`server`] is the loopback listener.
//! Intake's dedupe is a convenience; the double-spend guarantee is the
//! chain's (`WState::apply` and the node's bundle rule) — see [`intake`].
pub mod bundle;
pub mod chain;
pub mod intake;
pub mod key;
pub mod members;
pub mod pass;
pub mod queue;
pub mod seed;
pub mod server;
pub mod state;
pub mod work;

#[cfg(test)]
mod tests {
    /// Every source of this crate, by name.
    const SOURCES: [(&str, &str); 13] = [
        ("bundle.rs", include_str!("bundle.rs")),
        ("chain.rs", include_str!("chain.rs")),
        ("intake.rs", include_str!("intake.rs")),
        ("key.rs", include_str!("key.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("main.rs", include_str!("main.rs")),
        ("members.rs", include_str!("members.rs")),
        ("queue.rs", include_str!("queue.rs")),
        ("seed.rs", include_str!("seed.rs")),
        ("server.rs", include_str!("server.rs")),
        ("state.rs", include_str!("state.rs")),
        ("pass.rs", include_str!("pass.rs")),
        ("work.rs", include_str!("work.rs")),
    ];

    /// A **text lint** (the `f5box_calls_no_rule_knob` shape): outside test
    /// code no source of this crate Debug-formats a claim file, a
    /// deposit-sum opening or a plan — `ClaimFile` and `DepEntry` derive
    /// Debug while holding `v` and `r_v`, and a `Plan` holds both — nor a
    /// sequencer note (`Owned` derives Debug with its `rho` and `rseed`). The
    /// guarantee is review; this keeps a `{file:?}` from creeping in.
    #[test]
    fn no_source_debug_formats_an_opening() {
        let names = ["file", "files", "dep", "deps", "plan", "p", "claim", "draft", "owned", "n", "notes", "credited"];
        for (path, text) in SOURCES {
            let code = text.split("#[cfg(test)]\nmod tests").next().unwrap_or(text);
            for n in names {
                for pat in [format!("{{{n}:?}}"), format!("{{{n}:#?}}"), format!("\", {n})"), format!("\", &{n})")] {
                    let hit = code.match_indices(&pat).any(|(i, _)| {
                        // `"…{:?}", p)` only matters after a Debug placeholder.
                        !pat.starts_with('"') || code[..i].rsplit('\n').next().is_some_and(|line| line.contains(":?}"))
                    });
                    assert!(!hit, "{path} Debug-formats `{n}` outside tests ({pat})");
                }
            }
        }
    }

    /// The name list above catches the obvious spellings; this catches the
    /// rest: every Debug placeholder outside test code carries a
    /// `// debug-ok: <why>` marker on its line, so a new one is a reviewed
    /// one — the reviewer reads the reason, not a guess at the type.
    #[test]
    fn every_debug_format_is_marked() {
        for (path, text) in SOURCES {
            let code = text.split("#[cfg(test)]\nmod tests").next().unwrap_or(text);
            for (i, line) in code.lines().enumerate() {
                if (line.contains(":?}") || line.contains(":#?}")) && !line.trim_start().starts_with("//") {
                    let why = line.split("// debug-ok:").nth(1).map(str::trim).unwrap_or("");
                    assert!(!why.is_empty(), "{path}:{}: a Debug format with no `// debug-ok: <why>`", i + 1);
                }
            }
        }
    }

    /// Lab #847's Q4 condition, as text: outside tests, the pass's sources
    /// (`pass.rs`, `work.rs`, `main.rs`) never name an R member and never call
    /// the general planner — only `plan_claims`, whose members are all C —
    /// and `work.rs` checks [`crate::members::pass_members_ok`] before proving.
    #[test]
    fn the_pass_plans_no_r_member() {
        for (path, text) in SOURCES.iter().filter(|(p, _)| ["pass.rs", "work.rs", "main.rs"].contains(p)) {
            let code = text.split("#[cfg(test)]\nmod tests").next().unwrap_or(text);
            for bad in ["WTag::R", "Inst::R", "members::plan(", "plan(&", " plan("] {
                assert!(!code.contains(bad), "{path} names `{bad}` outside tests");
            }
        }
        let work = include_str!("work.rs");
        let (before, after) = work.split_once("pass_members_ok(&plan.members)?;").expect("work.rs checks the pass's member tags");
        assert!(before.contains("plan_claims(") && after.contains("prove(&plan,"), "the check sits between planning and proving");
    }

    /// Lab #860 R3b: the only P a posting pass carries is a wallet's exit
    /// file's (`Inst::ProvenExit`). Outside tests, the pass's sources build no
    /// `Inst::P` of their own (nor glob-import `Inst`'s variants), and the
    /// members functions `run` reaches — `plan_claims`, `filler`,
    /// `own_credit` — build a P only as `Inst::ProvenExit`. A text lint, the
    /// guarantee being review: `pass_members_ok` checks tags, and a P tag
    /// cannot tell a `ProvenExit` from an `Inst::P`.
    #[test]
    fn the_pass_builds_no_p_of_its_own() {
        let forbidden = ["Inst::P(", "Inst::P (", "Inst::P{", "Inst::P {", "Inst::*"];
        for (path, text) in SOURCES.iter().filter(|(p, _)| ["pass.rs", "work.rs", "main.rs"].contains(p)) {
            let code = text.split("#[cfg(test)]\nmod tests").next().unwrap_or(text);
            for bad in forbidden {
                assert!(!code.contains(bad), "{path} names `{bad}` outside tests");
            }
        }
        let members = include_str!("members.rs");
        let body_of = |name: &str| {
            let start = members.find(name).unwrap_or_else(|| panic!("{name}"));
            &members[start..start + members[start..].find("\n}\n").expect("its end")]
        };
        for f in ["pub fn plan_claims(", "pub fn filler(", "pub fn own_credit("] {
            let body = body_of(f);
            for bad in forbidden {
                assert!(!body.contains(bad), "{f}… names `{bad}`");
            }
        }
        assert!(body_of("pub fn plan_claims(").contains("Inst::ProvenExit {"), "plan_claims carries the wallet's exit");
        assert!(!members.contains("use Inst::*") && !members.contains("use self::Inst::*"));
    }

    /// The binary's `run` drives the one real [`crate::work::RealWork`], whose
    /// draft calls the real prover, and nothing in the crate outside tests
    /// defines another `Work` — the stub seam exists only in `pass`'s tests
    /// (the `f5box_calls_no_rule_knob` shape).
    #[test]
    fn run_names_the_real_prover() {
        let main = include_str!("main.rs");
        let work = include_str!("work.rs");
        assert!(main.contains("work::RealWork::open("), "main.rs's run must build RealWork");
        assert!(work.contains("prove(&plan, &mut timings, &mut log)"), "RealWork must call bundle::prove");
        for (path, text) in SOURCES {
            let code = text.split("#[cfg(test)]\nmod tests").next().unwrap_or(text);
            let impls = code.matches("impl Work for ").count();
            let want = usize::from(path == "work.rs");
            assert_eq!(impls, want, "{path}: {impls} `impl Work` outside tests");
        }
    }
}
