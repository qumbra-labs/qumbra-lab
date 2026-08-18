//! Graceful-shutdown signalling — **one seam, two platform mechanisms** (lab #478).
//!
//! Everything downstream of here is unchanged: [`crate::run::P2pNode::run_until`]
//! polls an `AtomicBool`, and when it flips it emits the open rounds, writes the
//! snapshot and writes `peers.dat`. This module's whole job is arming whatever the
//! host OS calls "the user asked this process to stop" so that flag flips, and —
//! on Windows only — **holding the process alive long enough for the flush to
//! finish**.
//!
//! ─────────────────────────────────────────────────────────────────────────────
//! # Unix: unchanged, `ctrlc` with `termination`
//!
//! SIGINT + SIGTERM + SIGHUP, exactly as issue #145 built and #238 made
//! structural (`tests/ctrlc_pairing.rs`). The handler stores an `AtomicBool` and
//! nothing else, because a unix signal handler must stay async-signal-safe.
//!
//! ─────────────────────────────────────────────────────────────────────────────
//! # Windows: `SetConsoleCtrlHandler`, and why `ctrlc` alone is NOT enough here
//!
//! `ctrlc` builds on Windows and its `termination` feature is a **no-op** there —
//! there are no signals to arm. What it registers is one `SetConsoleCtrlHandler`
//! routine that releases a semaphore and **returns `TRUE` immediately**
//! (`ctrlc-3.5.2/src/platform/windows/mod.rs`). For `CTRL_C_EVENT` and
//! `CTRL_BREAK_EVENT` that is the right shape: the process is not being killed,
//! so returning at once and letting the main loop notice the flag is correct.
//!
//! For `CTRL_CLOSE_EVENT` — the user clicked the console window's ✕, the case the
//! task book names alongside Ctrl-C — it is **not**. Windows terminates the
//! process as soon as the handler returns, or when its grace window expires,
//! whichever comes first. A handler that returns in microseconds therefore
//! converts a window-close into something much closer to `SIGKILL` than to
//! `SIGTERM`: the flag is set, and the loop never gets a turn to read it.
//!
//! So on Windows this binary registers **its own** handler and `ctrlc` is not a
//! dependency at all (`Cargo.toml` scopes it to `cfg(unix)`). One mechanism, not
//! two racing ones — handlers are called most-recently-registered first and the
//! first `TRUE` ends the chain, so keeping both would have left `ctrlc`'s
//! permanently unreachable and its waiting thread parked forever.
//!
//! The handler's behaviour, by event:
//!
//! | event | what it means | what we do |
//! |---|---|---|
//! | `CTRL_C_EVENT`, `CTRL_BREAK_EVENT` | user interrupt; process keeps running | set the flag, return at once |
//! | `CTRL_CLOSE_EVENT` | console window closed; **process dies on return** | set the flag, then BLOCK until the flush reports done or [`CLOSE_GRACE`] elapses |
//! | `CTRL_LOGOFF_EVENT`, `CTRL_SHUTDOWN_EVENT` | session/machine going away; same deal | same as close |
//!
//! ## 🔴 What the grace window does and does not buy — read before trusting it
//!
//! [`CLOSE_GRACE`] is **4.5 s**, chosen to sit inside the ~5 s Windows allows a
//! console control handler before it terminates the process regardless. That is a
//! platform budget, not ours, and it is not negotiable from here.
//!
//! Two honest consequences:
//!
//! 1. **A flush that needs longer than the window is still lost.** The loop's own
//!    iteration has to fit in there too — it polls the flag once per turn, and a
//!    mining turn is a RandomX hash batch, not a poll. On a busy miner a
//!    window-close can still land outside the budget.
//! 2. **Losing it costs replay time, not data.** `snapshot.bin` is a cache; the
//!    block log is the source of truth and is fsync'd per record
//!    (`qlab_node::persist::append_record`). A node killed with a stale snapshot
//!    replays from the log and reaches exactly the state a graceful stop would
//!    have written — which is the property `tests/sigkill_replay.rs` already
//!    pins on unix. So this window is a **latency** optimisation for the operator,
//!    and the correctness of the datadir does not rest on it.
//!
//! Ctrl-C has no such budget: nothing is killing the process, so the flush takes
//! as long as it takes. **Ctrl-C is the reliable stop on Windows and the docs say
//! so** — the ✕ is best-effort by the platform's own rules.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The line the startup banner prints so an operator knows which stop signals
/// this build actually listens for. Platform-specific because the honest answer
/// is.
pub const fn stop_signals_line() -> &'static str {
    #[cfg(unix)]
    {
        "(SIGINT/SIGTERM/SIGHUP to shut down — snapshot + peers.dat flushed on exit)"
    }
    #[cfg(windows)]
    {
        "(Ctrl-C or Ctrl-Break to shut down — snapshot + peers.dat flushed on exit. \
Closing the console window also flushes, but Windows caps that at ~5 s; prefer Ctrl-C.)"
    }
    #[cfg(not(any(unix, windows)))]
    {
        "(no console stop handler is armed on this platform — stop this process and replay the log)"
    }
}

/// Arm the platform's stop mechanism and hand back the flag the event loop polls.
///
/// Call once. A second call is a programming error on unix (`ctrlc` refuses a
/// second handler) and would re-register on Windows.
pub fn install() -> Result<Arc<AtomicBool>, Box<dyn std::error::Error>> {
    let flag = Arc::new(AtomicBool::new(false));
    imp::arm(Arc::clone(&flag))?;
    Ok(flag)
}

/// Tell the platform layer that the graceful-shutdown flush has finished.
///
/// Unix: a no-op — nothing is waiting.
///
/// Windows: releases a console handler blocked in [`CLOSE_GRACE`], so a
/// window-close returns to the OS as soon as the snapshot is actually on disk
/// instead of always burning the full window. **Call it after `run_until`
/// returns and before printing the closing line**, so the process is allowed to
/// die at the earliest honest moment.
pub fn flush_complete() {
    imp::flush_complete();
}

#[cfg(unix)]
mod imp {
    use super::*;

    pub fn arm(flag: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
        // ctrlc with the `termination` feature (Cargo.toml): SIGINT + SIGTERM +
        // SIGHUP. The handler must stay async-signal-safe — only an AtomicBool
        // store, nothing else. SIGHUP is accepted as graceful stop: this binary
        // has no config-reload path, and a terminal hangup that would otherwise
        // kill the process mid-loop is exactly the case where a flush is wanted
        // (issue #145).
        ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))?;
        Ok(())
    }

    pub fn flush_complete() {}
}

#[cfg(windows)]
pub use imp::{handle_console_event, CLOSE_GRACE};

#[cfg(windows)]
mod imp {
    use super::*;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
        CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    const TRUE_: BOOL = 1;
    const FALSE_: BOOL = 0;

    /// How long a close/logoff/shutdown handler will wait for the flush.
    ///
    /// Windows gives a console control handler roughly **5 s** before killing the
    /// process regardless of what the handler is doing. 4.5 s leaves margin for
    /// the handler to actually return inside that budget; going higher does not
    /// buy time, it only moves who does the killing.
    pub const CLOSE_GRACE: Duration = Duration::from_millis(4_500);

    /// How often the waiting handler re-reads the flush flag. Small enough that a
    /// fast flush is not rounded up to a visible pause, large enough that the
    /// wait is not a spin.
    const POLL: Duration = Duration::from_millis(10);

    static REQUESTED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    static FLUSHED: AtomicBool = AtomicBool::new(false);

    pub fn arm(flag: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
        // Ignore a second `install()`: the first flag is the one the loop holds.
        let _ = REQUESTED.set(flag);
        // SAFETY: `os_handler` is a plain `extern "system"` fn with the signature
        // `PHANDLER_ROUTINE` requires, and it outlives the process.
        let ok = unsafe { SetConsoleCtrlHandler(Some(os_handler), TRUE_) };
        if ok == FALSE_ {
            return Err(Box::new(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn flush_complete() {
        FLUSHED.store(true, Ordering::SeqCst);
    }

    unsafe extern "system" fn os_handler(event: u32) -> BOOL {
        let Some(flag) = REQUESTED.get() else {
            // Nothing armed the flag, so there is no graceful path to protect.
            // Say "not handled" and let the default terminate.
            return FALSE_;
        };
        if handle_console_event(event, flag, &FLUSHED, CLOSE_GRACE) {
            TRUE_
        } else {
            FALSE_
        }
    }

    /// The handler's whole decision, lifted out of the `extern "system"` shim so
    /// it can be **executed by a test** rather than only reasoned about.
    ///
    /// Returns `true` for "this process handled the event" — the value the OS
    /// reads as `TRUE`.
    ///
    /// Blocking here is the entire mechanism for the close/logoff/shutdown
    /// events: Windows terminates the process when this returns, so returning
    /// early is the same as declining to flush. See the module docs for what the
    /// deadline can and cannot promise.
    pub fn handle_console_event(
        event: u32,
        requested: &AtomicBool,
        flushed: &AtomicBool,
        grace: Duration,
    ) -> bool {
        match event {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                // The process is NOT being torn down. Set the flag and get out of
                // the way; the loop owns the rest and has no deadline.
                requested.store(true, Ordering::SeqCst);
                true
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                requested.store(true, Ordering::SeqCst);
                let deadline = Instant::now() + grace;
                while !flushed.load(Ordering::SeqCst) {
                    if Instant::now() >= deadline {
                        // Out of budget. Returning is what kills us, but the block
                        // log is fsync'd per record, so the datadir is intact and
                        // the next start replays. Nothing is printed: stdout is
                        // attached to a console that is already going away.
                        return true;
                    }
                    std::thread::sleep(POLL);
                }
                true
            }
            // Not a stop event we know how to honour — decline so the default
            // handling applies rather than silently swallowing it.
            _ => false,
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;

    pub fn arm(_flag: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    pub fn flush_complete() {}
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    /// Ctrl-C must not block: the process is not being killed, so holding the
    /// handler would only delay the console's prompt for no gain.
    #[test]
    fn ctrl_c_sets_the_flag_and_returns_immediately() {
        for event in [CTRL_C_EVENT, CTRL_BREAK_EVENT] {
            let requested = AtomicBool::new(false);
            let flushed = AtomicBool::new(false); // deliberately never set
            let t0 = Instant::now();
            let handled = handle_console_event(
                event,
                &requested,
                &flushed,
                Duration::from_secs(30),
            );
            let waited = t0.elapsed();
            assert!(handled, "event {event} must report handled");
            assert!(requested.load(Ordering::SeqCst), "event {event} must request shutdown");
            assert!(
                waited < Duration::from_millis(500),
                "event {event} waited {waited:?} — Ctrl-C must not wait on the flush"
            );
        }
    }

    /// The close path is the whole point: it must hold the process until the
    /// flush says it is done, and then return promptly rather than burning the
    /// rest of the window.
    #[test]
    fn a_console_close_waits_for_the_flush_and_returns_as_soon_as_it_lands() {
        for event in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
            let requested = std::sync::Arc::new(AtomicBool::new(false));
            let flushed = std::sync::Arc::new(AtomicBool::new(false));

            let r = std::sync::Arc::clone(&requested);
            let f = std::sync::Arc::clone(&flushed);
            let waiter = std::thread::spawn(move || {
                let t0 = Instant::now();
                let handled =
                    handle_console_event(event, &r, &f, Duration::from_secs(30));
                (handled, t0.elapsed())
            });

            // The flag must be visible to the loop well before the flush lands.
            let armed_by = Instant::now() + Duration::from_secs(5);
            while !requested.load(Ordering::SeqCst) {
                assert!(Instant::now() < armed_by, "shutdown was never requested");
                std::thread::sleep(Duration::from_millis(5));
            }

            std::thread::sleep(Duration::from_millis(200));
            assert!(!waiter.is_finished(), "event {event} returned before the flush");

            flushed.store(true, Ordering::SeqCst);
            let (handled, waited) = waiter.join().expect("waiter thread");
            assert!(handled, "event {event} must report handled");
            assert!(
                waited < Duration::from_secs(5),
                "event {event} returned {waited:?} after the flush landed — it should be prompt"
            );
        }
    }

    /// And it must give up. A flush that never completes cannot be allowed to
    /// hold the handler past the OS budget — Windows would kill us anyway, and
    /// the only thing an over-long wait changes is who reports it.
    #[test]
    fn a_close_gives_up_at_the_deadline_when_the_flush_never_lands() {
        let requested = AtomicBool::new(false);
        let flushed = AtomicBool::new(false);
        let grace = Duration::from_millis(300);
        let t0 = Instant::now();
        let handled =
            handle_console_event(CTRL_CLOSE_EVENT, &requested, &flushed, grace);
        let waited = t0.elapsed();
        assert!(handled);
        assert!(waited >= grace, "gave up early: {waited:?} < {grace:?}");
        assert!(
            waited < grace + Duration::from_secs(2),
            "overshot the deadline by too much: {waited:?}"
        );
    }

    /// The budget must stay inside the platform's ~5 s, or the wait is decorative.
    #[test]
    fn the_grace_window_stays_inside_the_windows_budget() {
        assert!(
            CLOSE_GRACE < Duration::from_secs(5),
            "CLOSE_GRACE {CLOSE_GRACE:?} is not inside the ~5 s Windows allows a console \
             control handler — the OS would kill the process mid-flush regardless"
        );
    }

    /// An event we do not recognise must not be swallowed.
    #[test]
    fn an_unknown_event_is_declined_rather_than_absorbed() {
        let requested = AtomicBool::new(false);
        let flushed = AtomicBool::new(false);
        let handled =
            handle_console_event(0xDEAD_BEEF, &requested, &flushed, Duration::from_secs(30));
        assert!(!handled);
        assert!(!requested.load(Ordering::SeqCst));
    }
}
