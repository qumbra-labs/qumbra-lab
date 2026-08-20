//! The startup entry line — printed before ANY work (lab #300).
//!
//! On the 2026-08-08 `t0-wan-14` roll, node3 spent ~57 minutes between process
//! start and its first log line: one thread, state R, zero syscalls, and from
//! the operator's chair indistinguishable from a hang (or from #287's replay
//! silence, except the discriminator — an open `blocks.log` — read the other
//! way). Whatever those CPU-minutes were, the defect the operator *experienced*
//! was the silence: nothing in this binary said "I am alive" until every
//! pre-banner stage had finished.
//!
//! This module makes silence-before-the-banner structurally impossible for the
//! `run` subcommand: [`announce_then`] writes the entry line and flushes it
//! **before** invoking the work it wraps, and `run_node` routes its config load
//! through [`announce_then_load`] as its first act. The ordering is locked by
//! tests here (the loader observes the line already written) and by the
//! `tests/startup_entry.rs` integration test through the real binary (the line
//! appears even when the config file does not exist — i.e. before config load
//! can have happened).
//!
//! The line carries the release name + revision identifier rather than
//! `CARGO_PKG_VERSION`: every crate in this workspace is version `0.0.0`, while
//! the release/revision pair is what the fleet's images are banner-verified by
//! (#74/#81) — it is the identity an operator can actually act on. Both are
//! compile-time constants, so the line costs nothing that could itself become
//! a silent region.

use std::io::Write;

use crate::config::{ConfigError, NodeConfig};
use crate::release::RELEASE;

/// The first line `qumbra-node run` prints: binary name, release, revision,
/// config path. Pure formatting over compile-time constants — the one thing it
/// must never do is compute.
pub fn entry_line(config_path: &str) -> String {
    let revision = match RELEASE.revision {
        Some(r) => r.id,
        None => "-",
    };
    format!(
        "qumbra-node starting — release: {}; revision: {revision}; config: {config_path}",
        RELEASE.name
    )
}

/// Write the entry line, flush it, THEN run `work`. The seam that makes
/// "banner before any work" a testable property instead of a code-review hope:
/// the caller cannot get its config (or anything else) out of this function
/// without the line having been written first.
///
/// Write/flush errors are swallowed — the line exists for the operator, not for
/// control flow, and a broken stdout must not stop a node from starting (same
/// posture as `qlab_node::replay_progress`).
pub fn announce_then<W, T, E, F>(out: &mut W, config_path: &str, work: F) -> Result<T, E>
where
    W: Write,
    F: FnOnce() -> Result<T, E>,
{
    // The journal stamp rides at the write site (lab #512), keeping
    // `entry_line` itself pure formatting over compile-time constants.
    let _ = writeln!(out, "{} {}", qlab_devnet::journal::utc_stamp(), entry_line(config_path));
    let _ = out.flush();
    work()
}

/// [`announce_then`] over the real config load — what `run_node` calls as its
/// first statement, before `NodeConfig::load` and everything downstream of it.
pub fn announce_then_load<W: Write>(
    out: &mut W,
    config_path: &str,
) -> Result<NodeConfig, ConfigError> {
    announce_then(out, config_path, || NodeConfig::load(config_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A writer whose buffer stays readable by the test WHILE `announce_then`
    /// still holds the writer — that shared view is what lets the injected work
    /// closure observe the buffer's state at the moment work begins.
    #[derive(Clone)]
    struct SharedBuf(Rc<RefCell<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn entry_line_carries_identity_and_config_path() {
        let line = entry_line("/etc/qumbra/node.toml");
        assert!(line.starts_with("qumbra-node starting"), "line: {line}");
        assert!(line.contains(RELEASE.name), "release name missing: {line}");
        assert!(line.contains("/etc/qumbra/node.toml"), "config path missing: {line}");
        // The revision identifier (or `-` for a revisionless release) is what an
        // operator cross-checks against the deploy record — it must be present.
        match RELEASE.revision {
            Some(r) => assert!(line.contains(r.id), "revision id missing: {line}"),
            None => assert!(line.contains("revision: -"), "revision placeholder missing: {line}"),
        }
    }

    /// The ordering property itself (lab #300): when the wrapped work runs, the
    /// entry line has ALREADY left the writer. Not "the line is written at some
    /// point" — written first, observed from inside the work closure.
    #[test]
    fn the_entry_line_is_written_before_the_work_runs() {
        let buf = SharedBuf(Rc::new(RefCell::new(Vec::new())));
        let peek = buf.clone();
        let mut writer = buf.clone();
        let result: Result<u8, ()> = announce_then(&mut writer, "cfg.toml", || {
            let seen = String::from_utf8_lossy(&peek.0.borrow()).into_owned();
            assert!(
                seen.contains("qumbra-node starting"),
                "work ran before the entry line was written; writer held: {seen:?}"
            );
            assert!(seen.ends_with('\n'), "entry line not newline-terminated: {seen:?}");
            Ok(7)
        });
        assert_eq!(result, Ok(7));
    }

    /// A config load that FAILS still leaves the entry line behind — the exact
    /// operational shape of lab #300: whatever goes slow or wrong after process
    /// start, the operator has one line proving the process is alive and naming
    /// the config it is about to read.
    #[test]
    fn a_failing_config_load_still_leaves_the_entry_line() {
        let buf = SharedBuf(Rc::new(RefCell::new(Vec::new())));
        let mut writer = buf.clone();
        let result = announce_then_load(&mut writer, "/nonexistent/i300/node.toml");
        assert!(result.is_err(), "a missing config must still be an error");
        let out = String::from_utf8_lossy(&buf.0.borrow()).into_owned();
        assert!(
            out.contains("qumbra-node starting"),
            "entry line must precede (and so survive) the failed load: {out:?}"
        );
        assert!(out.contains("/nonexistent/i300/node.toml"), "config path missing: {out:?}");
    }
}
