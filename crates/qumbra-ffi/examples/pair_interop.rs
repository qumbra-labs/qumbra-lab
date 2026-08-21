//! Prove that this client's framing interoperates with the REAL Mac prover.
//!
//! ## Why this exists as an example and not a test
//!
//! It needs two things CI cannot give it: a running `qumbra-paired-prover`, which
//! is a macOS binary, and this lab's acceptance lane is arm64 Linux. As an
//! `--example` it is **compiled** by `cargo test --workspace` — so it cannot rot
//! — and **never run** by it. Running it is a human act, on purpose.
//!
//! ## Why a self-round-trip would not do
//!
//! `pairing.rs`'s unit tests seal with one half of this module and open with the
//! other. That catches an inconsistent change and misses a **consistent wrong
//! one** — most importantly the direction bytes. The server reads `MOBI` and
//! writes `DESK`; a client that had them backwards would encrypt and decrypt its
//! own frames perfectly and fail only against a real peer. This is the check that
//! sees that, and it is the same shape of guard lab #527 was fixed for: pin
//! against something that moves independently, not against yourself.
//!
//! ## Why an invalid bundle is the right input
//!
//! `operation = inspect` decodes the bundle and describes it. Handing it garbage
//! means the Mac authenticates the frame, decodes the JSON, and *then* refuses
//! the bundle — so the whole channel is exercised and the STARK prover is never
//! allocated. **No wallet, no notes, no money, no proving time.**
//!
//! 🔴 So an `error` response **is a PASS**. The frame was authenticated before
//! its JSON was read: if the key, the nonce layout, the AAD or the direction
//! bytes disagreed, the Mac would have refused with
//! `client frame authentication failed` and told us nothing we could decrypt.
//!
//! ## Running it
//!
//! Terminal 1, in `qumbra-wallet-macos`:
//!
//! ```text
//! scripts/run-paired-prover.sh 127.0.0.1
//! ```
//!
//! It prints a `qumbra-prover://…` URI and exits after ONE request, so a second
//! attempt needs a restart (by design — every session gets a fresh secret).
//!
//! Terminal 2, here:
//!
//! ```text
//! cargo run --release -p qumbra-ffi --example pair_interop -- '<the URI>'
//! ```
//!
//! Quote the URI: it contains `&`, which a shell would otherwise read as
//! "background this".

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use qumbra_ffi::pairing::{Operation, Session, Step};

/// Generous, and deliberately not the server's 30 s: that timeout covers its
/// handshake I/O, not proving. Nothing here proves, but a reader that gives up
/// early would report a network problem as a protocol problem.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

fn main() {
    let Some(uri) = std::env::args().nth(1) else {
        eprintln!(
            "usage: cargo run --release -p qumbra-ffi --example pair_interop -- '<qumbra-prover URI>'\n\
             \n\
             Start the host first, in the qumbra-wallet-macos checkout:\n\
             \x20   scripts/run-paired-prover.sh 127.0.0.1\n\
             \n\
             Quote the URI — it contains & and a shell would background the command."
        );
        std::process::exit(64);
    };

    // The bundle is INTENTIONALLY not a bundle. See this file's header: the
    // channel is what is under test, and a real bundle would cost a wallet, real
    // notes, and minutes of proving to prove nothing extra.
    let nonsense_bundle = b"this is deliberately not a witness bundle";

    let mut session = match Session::new(
        &uri,
        "interop-check",
        Operation::Inspect,
        nonsense_bundle,
        None,
        None,
    ) {
        Ok(session) => session,
        Err(why) => {
            // Never echo the URI back: it carries the pairing secret, which is
            // spend authority for the transaction it would prove.
            eprintln!("✗ the pairing URI was refused before any connection: {why}");
            std::process::exit(2);
        }
    };

    let endpoint = session.endpoint();
    println!("connecting to {endpoint} (the URI's secret is not printed)");
    let mut socket = match TcpStream::connect(&endpoint) {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("✗ cannot reach {endpoint}: {e}");
            eprintln!("  is the host running, and is the port the one it printed?");
            std::process::exit(2);
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(READ_TIMEOUT)) {
        eprintln!("✗ cannot set a read timeout: {e}");
        std::process::exit(2);
    }

    let mut buf = [0u8; 64 * 1024];
    loop {
        match session.step() {
            Step::Send(frame) => {
                if let Err(e) = socket.write_all(&frame).and_then(|_| socket.flush()) {
                    eprintln!("✗ cannot write a frame: {e}");
                    std::process::exit(2);
                }
                println!("→ sent {} bytes (one sealed frame)", frame.len());
            }
            Step::Need => match socket.read(&mut buf) {
                Ok(0) => {
                    eprintln!(
                        "✗ the host closed the connection with the exchange unfinished.\n\
                         \x20  It refuses an unauthenticated peer WITHOUT replying, deliberately\n\
                         \x20  (no plaintext oracle), so this is the shape a framing disagreement\n\
                         \x20  takes from this side. Check the host's stderr: it names what it saw."
                    );
                    std::process::exit(1);
                }
                Ok(n) => {
                    println!("← read {n} bytes");
                    session.supply(&buf[..n]);
                }
                Err(e) => {
                    eprintln!("✗ cannot read: {e}");
                    std::process::exit(2);
                }
            },
            Step::Done => {
                // Narration first: it carries the host's own words.
                for note in session.take_notes() {
                    println!("   host: {note:?}");
                }
                println!(
                    "\n✅ PASS — the channel interoperates.\n\
                     \x20  The handshake, the SHA3-256 key derivation, the frame counters, the\n\
                     \x20  nonce and AAD layouts and the DIRECTION BYTES all agree with the real\n\
                     \x20  host. A self-round-trip could not have shown this."
                );
                return;
            }
            Step::Failed(why) => {
                for note in session.take_notes() {
                    println!("   host: {note:?}");
                }
                // 🔴 The distinction this whole check exists to draw.
                if why.contains("authentication failed") {
                    eprintln!(
                        "\n✗ FAIL — {why}\n\
                         \x20  A frame did not authenticate, so the two sides disagree about the\n\
                         \x20  channel itself. In order of likelihood:\n\
                         \x20    1. the direction bytes (this client must WRITE MOBI, READ DESK);\n\
                         \x20    2. the AAD field order (magic|version|server_nonce|direction|counter);\n\
                         \x20    3. the KDF input order (domain|secret|server_nonce)."
                    );
                    std::process::exit(1);
                }
                // Anything the host said in an ENCRYPTED frame is a pass: the
                // frame authenticated before its JSON was read.
                println!(
                    "\n✅ PASS — the host answered inside an authenticated frame, and its answer\n\
                     \x20  was:\n\
                     \x20    {why}\n\
                     \x20  That refusal is the EXPECTED one: the bundle is deliberately nonsense.\n\
                     \x20  Reaching it means the handshake, the key derivation, the counters, the\n\
                     \x20  nonce/AAD layouts and the direction bytes all agree — a wrong one of\n\
                     \x20  those would have failed authentication instead, with nothing readable."
                );
                return;
            }
        }
    }
}
