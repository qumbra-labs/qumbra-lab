//! `qumbra-prover-host` — the native-messaging prover (the browser shell's
//! phase 2+3; task book `qumbra-wallet-desktop/docs/prover-host-rung.md` §2).
//!
//! A **pure prover**: no wallet dir, no seed, no disk state. The extension
//! builds the witness bundle (it holds the keys — direction (b)); this process
//! takes the bundle over Chrome's framed stdio pipe, fetches fresh public
//! chain facts, proves on the user's own machine (~3 s / ~12 GB), submits
//! host-side (the proof never crosses back through the 1 MB-capped pipe), and
//! streams the same step words the desktop window shows
//! ([`qumbra_wallet::words::word_for`] — its third caller).
//!
//! # The frame protocol
//!
//! Chrome native messaging: 4-byte little-endian length, then that many bytes
//! of UTF-8 JSON. 🔴 **stdout IS the protocol** — nothing but frames goes
//! there (a test pins it); everything human goes to stderr.
//!
//! First frame each way is the handshake: `{"op":"hello","v":N}`. A version
//! mismatch refuses, naming both versions and which artifact is older.
//!
//! Then one job per connection:
//! `{"op":"prove_and_submit","bundle_b64":…,"scan_url":…,"node_url":…}`
//! answered by `{"op":"step","words":…}` frames and exactly one terminal
//! frame: `accepted` / `duplicate` (typed, never collapsed), `refused` (by
//! name, cheap, nothing was proved unless said), or `incomplete` — which is
//! NOT a refusal: the POST did not complete and the transaction MAY HAVE
//! LANDED; the wording is the library's own, verbatim.
//!
//! # One prove at a time
//!
//! A second in-flight spend is ~24 GB — refused by name. Chrome spawns one
//! host process per port, so the guard is cross-process: an atomic
//! `mkdir`-based lock (the `scripts/rig` shape) holding the owner's pid;
//! a lock whose pid is gone is reaped, so a crashed prove cannot wedge
//! spending forever.

use std::io::{Read, Write};

use qlab_wallet::uri::b64url_decode;
use qumbra_wallet::bundle::WitnessBundle;
use qumbra_wallet::spend::{preflight_urls, prove, submit, SendError};
use qumbra_wallet::words::word_for;
use serde_json::{json, Value};

/// The pipe protocol this binary speaks. Bump on any frame-shape change.
const PROTOCOL: u64 = 1;

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    if let Err(e) = run(&mut input, &mut output) {
        eprintln!("qumbra-prover-host: {e}");
        std::process::exit(1);
    }
}

fn run(input: &mut impl Read, output: &mut impl Write) -> Result<(), String> {
    // ---- handshake, version first (task book §4) ---------------------------
    let hello = read_frame(input)?;
    let theirs = hello.get("v").and_then(Value::as_u64).unwrap_or(0);
    if hello.get("op").and_then(Value::as_str) != Some("hello") || theirs == 0 {
        write_frame(output, &json!({"op": "refused", "why": "the first frame must be a hello carrying a protocol version"}))?;
        return Ok(());
    }
    if theirs != PROTOCOL {
        let older = if theirs < PROTOCOL { "the extension" } else { "this host" };
        write_frame(output, &json!({
            "op": "refused",
            "why": format!(
                "protocol mismatch: extension speaks v{theirs}, host speaks v{PROTOCOL} — {older} \
                 is older; update it. The two artifacts install separately, so skew is normal \
                 and refusing it is the feature."
            ),
        }))?;
        return Ok(());
    }
    write_frame(output, &json!({"op": "hello", "v": PROTOCOL}))?;

    // ---- one job ------------------------------------------------------------
    let job = read_frame(input)?;
    if job.get("op").and_then(Value::as_str) != Some("prove_and_submit") {
        write_frame(output, &json!({"op": "refused", "why": "unknown op — this host proves and submits, nothing else"}))?;
        return Ok(());
    }
    let (Some(bundle_b64), Some(scan_url), Some(node_url)) = (
        job.get("bundle_b64").and_then(Value::as_str),
        job.get("scan_url").and_then(Value::as_str),
        job.get("node_url").and_then(Value::as_str),
    ) else {
        write_frame(output, &json!({"op": "refused", "why": "prove_and_submit needs bundle_b64, scan_url and node_url"}))?;
        return Ok(());
    };

    // ---- one prove at a time, cross-process --------------------------------
    let _lock = match ProveLock::take() {
        Ok(lock) => lock,
        Err(why) => {
            write_frame(output, &json!({"op": "refused", "why": why}))?;
            return Ok(());
        }
    };

    // ---- decode the bundle (its own version + checksum + semantic refusals) -
    let bytes = match b64url_decode(bundle_b64) {
        Ok(b) => b,
        Err(e) => {
            write_frame(output, &json!({"op": "refused", "why": format!("bundle_b64 did not decode: {e}")}))?;
            return Ok(());
        }
    };
    let bundle = match WitnessBundle::from_bytes(&bytes) {
        Ok(b) => b,
        Err(e) => {
            write_frame(output, &json!({"op": "refused", "why": format!("witness bundle refused: {e:?}")}))?;
            return Ok(());
        }
    };

    // ---- phase 2 + 3, streaming the window's own words ---------------------
    // The sink buffers into a RefCell; frames flush between phases. A step
    // callback that wrote frames directly would borrow the writer inside the
    // prover's callback — buffering keeps the writer single-threaded.
    let steps: std::cell::RefCell<Vec<Value>> = std::cell::RefCell::new(Vec::new());
    let push = |step: qumbra_wallet::spend::SendStep| {
        steps.borrow_mut().push(json!({"op": "step", "words": word_for(&step)}));
    };

    let current = match preflight_urls(scan_url, node_url) {
        Ok(c) => c,
        Err(e) => {
            write_frame(output, &json!({"op": "refused", "why": e.to_string()}))?;
            return Ok(());
        }
    };
    let mut on_prove = |step| push(step);
    let art = match prove(&bundle, &current, &mut on_prove) {
        Ok(a) => a,
        Err(e) => {
            for s in steps.borrow_mut().drain(..) {
                write_frame(output, &s)?;
            }
            write_frame(output, &json!({"op": "refused", "why": e.to_string()}))?;
            return Ok(());
        }
    };
    for s in steps.borrow_mut().drain(..) {
        write_frame(output, &s)?;
    }
    let mut on_submit = |step| push(step);
    match submit(node_url, &art.wire_bytes, &mut on_submit) {
        Ok(answer) => {
            for s in steps.borrow_mut().drain(..) {
                write_frame(output, &s)?;
            }
            write_frame(output, &json!({
                "op": "answered",
                "status": answer.status,
                "body": answer.body,
            }))?;
        }
        Err(SendError::Incomplete { why, .. }) => {
            for s in steps.borrow_mut().drain(..) {
                write_frame(output, &s)?;
            }
            // NOT a refusal — the transaction may have landed. The extension
            // may hand the SAME bundle back: an already-pending transaction
            // answers `duplicate`, which is safe.
            write_frame(output, &json!({"op": "incomplete", "why": why}))?;
        }
        Err(e) => {
            for s in steps.borrow_mut().drain(..) {
                write_frame(output, &s)?;
            }
            write_frame(output, &json!({"op": "refused", "why": e.to_string()}))?;
        }
    }
    Ok(())
}

/* --- framing --------------------------------------------------------------- */

fn read_frame(input: &mut impl Read) -> Result<Value, String> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).map_err(|e| format!("pipe closed reading a frame length: {e}"))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(format!("inbound frame of {len} bytes exceeds Chrome's own 64 MiB cap"));
    }
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf).map_err(|e| format!("pipe closed mid-frame: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("frame is not JSON: {e}"))
}

fn write_frame(output: &mut impl Write, v: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(v).map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        // Chrome kills a host whose frame exceeds 1 MB — never send one.
        return Err(format!("outbound frame of {} bytes would exceed the 1 MB cap", bytes.len()));
    }
    output
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|()| output.write_all(&bytes))
        .and_then(|()| output.flush())
        .map_err(|e| format!("stdout closed: {e}"))
}

/* --- the one-prove-at-a-time lock ------------------------------------------ */

/// `mkdir`-atomic lock with a pid inside (the `scripts/rig` shape). Reaps a
/// holder whose process is gone, so a crashed prove cannot wedge spending.
struct ProveLock {
    dir: std::path::PathBuf,
}

impl ProveLock {
    fn path() -> std::path::PathBuf {
        // Env-overridable so tests (and unusual platforms) can isolate; the
        // default is one lock per machine, which is the point.
        std::env::var_os("QUMBRA_PROVER_LOCK")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("qumbra-prover-host.lock"))
    }

    fn take() -> Result<ProveLock, String> {
        let dir = Self::path();
        for _ in 0..2 {
            match std::fs::create_dir(&dir) {
                Ok(()) => {
                    let _ = std::fs::write(dir.join("pid"), std::process::id().to_string());
                    return Ok(ProveLock { dir });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = std::fs::read_to_string(dir.join("pid"))
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok());
                    match holder {
                        Some(pid) if process_alive(pid) => {
                            return Err(format!(
                                "another spend is proving right now (pid {pid}) — one prove at a \
                                 time: each is ~12 GB, and a second click is not a second wallet"
                            ));
                        }
                        _ => {
                            // Stale: the holder is gone. Reap and retry once.
                            let _ = std::fs::remove_dir_all(&dir);
                        }
                    }
                }
                Err(e) => return Err(format!("prove lock unavailable: {e}")),
            }
        }
        Err("prove lock contended — try again".into())
    }
}

impl Drop for ProveLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // Signal 0: existence check, no signal delivered. ESRCH ⇒ gone.
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true // no cheap probe; err on refusing (the stale case self-heals on reboot)
}

// One symbol, declared rather than a `libc` dependency edge — the same trade
// `qumbra-ffi` makes for `free`.
#[cfg(unix)]
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}
