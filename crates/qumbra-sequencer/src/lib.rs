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
pub mod server;
pub mod state;
pub mod work;

#[cfg(test)]
mod tests {
    /// Every source of this crate, by name.
    const SOURCES: [(&str, &str); 12] = [
        ("bundle.rs", include_str!("bundle.rs")),
        ("chain.rs", include_str!("chain.rs")),
        ("intake.rs", include_str!("intake.rs")),
        ("key.rs", include_str!("key.rs")),
        ("lib.rs", include_str!("lib.rs")),
        ("main.rs", include_str!("main.rs")),
        ("members.rs", include_str!("members.rs")),
        ("queue.rs", include_str!("queue.rs")),
        ("server.rs", include_str!("server.rs")),
        ("state.rs", include_str!("state.rs")),
        ("pass.rs", include_str!("pass.rs")),
        ("work.rs", include_str!("work.rs")),
    ];

    /// A **text lint** (the `f5box_calls_no_rule_knob` shape): outside test
    /// code no source of this crate Debug-formats a claim file, a
    /// deposit-sum opening or a plan — `ClaimFile` and `DepEntry` derive
    /// Debug while holding `v` and `r_v`, and a `Plan` holds both. The
    /// guarantee is review; this keeps a `{file:?}` from creeping in.
    #[test]
    fn no_source_debug_formats_an_opening() {
        let names = ["file", "files", "dep", "deps", "plan", "p", "claim", "draft"];
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
