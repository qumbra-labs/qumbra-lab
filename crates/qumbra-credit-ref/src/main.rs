//! `qumbra-credit-ref` — the runnable crediting reference (lab #483 stage 2).
//!
//! ```text
//! qumbra-credit-ref --listen 127.0.0.1:8484 \
//!                   --upstream http://127.0.0.1:8422 \
//!                   --keys ./exchange.keys
//! ```
//!
//! `--upstream` is a node's discovery endpoint (`qumbra-node`'s
//! `discovery_addr`). `--keys` is a two-line devnet-grade key file:
//!
//! ```text
//! seed = 21,22,23,24            # four u64 lanes, decimal or 0x-hex
//! diversifier = 2c2c…2c         # 32 hex chars (16 bytes)
//! ```
//!
//! Every bad start refuses BY NAME before binding anything (the faucet's
//! startup-refusal posture). Custody is devnet-grade by declaration — the
//! seed derives the viewing key in-process; production custody (standing
//! fvk/ivk) is #483 stage 3's documentation surface.

use std::net::TcpListener;
use std::process::exit;

use qlab_wallet::address::Diversifier;
use qumbra_credit_ref::http::serve;
use qumbra_credit_ref::{CreditEngine, ExchangeKeys};

fn refuse(name: &str, detail: &str) -> ! {
    eprintln!("qumbra-credit-ref: REFUSED to start [{name}]: {detail}");
    exit(2);
}

fn parse_lane(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_keys_file(text: &str) -> Result<([u64; 4], Diversifier), (&'static str, String)> {
    let mut seed: Option<[u64; 4]> = None;
    let mut d: Option<Diversifier> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(("keys-file-malformed", format!("not a key = value line: {line:?}")));
        };
        match k.trim() {
            "seed" => {
                let lanes: Vec<u64> =
                    v.split(',').map_while(parse_lane).collect();
                if lanes.len() != 4 || v.split(',').count() != 4 {
                    return Err((
                        "keys-file-malformed",
                        "seed must be exactly four u64 lanes (decimal or 0x-hex), comma-separated"
                            .into(),
                    ));
                }
                seed = Some([lanes[0], lanes[1], lanes[2], lanes[3]]);
            }
            "diversifier" => {
                let hexs = v.trim();
                if hexs.len() != 32 || !hexs.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err((
                        "keys-file-malformed",
                        "diversifier must be exactly 32 hex chars (16 bytes)".into(),
                    ));
                }
                let mut bytes = [0u8; 16];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = u8::from_str_radix(&hexs[i * 2..i * 2 + 2], 16).unwrap();
                }
                d = Some(Diversifier::from_bytes(bytes));
            }
            other => {
                return Err(("keys-file-malformed", format!("unknown key {other:?}")));
            }
        }
    }
    match (seed, d) {
        (Some(s), Some(d)) => Ok((s, d)),
        (None, _) => Err(("keys-file-malformed", "missing `seed = …` line".into())),
        (_, None) => Err(("keys-file-malformed", "missing `diversifier = …` line".into())),
    }
}

fn main() {
    let mut listen: Option<String> = None;
    let mut upstream: Option<String> = None;
    let mut keys_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut take = |name: &str| {
            args.next().unwrap_or_else(|| refuse("bad-args", &format!("{name} needs a value")))
        };
        match a.as_str() {
            "--listen" => listen = Some(take("--listen")),
            "--upstream" => upstream = Some(take("--upstream")),
            "--keys" => keys_path = Some(take("--keys")),
            other => refuse(
                "bad-args",
                &format!("unknown argument {other:?}; the surface is --listen --upstream --keys"),
            ),
        }
    }
    let Some(listen) = listen else { refuse("bad-args", "--listen <addr:port> is required") };
    let Some(upstream) = upstream else {
        refuse("bad-args", "--upstream <http://host:port> is required")
    };
    let Some(keys_path) = keys_path else { refuse("bad-args", "--keys <file> is required") };

    if !upstream.starts_with("http://") {
        // The engine's transport seam accepts anything; THIS shell's fetch is
        // qlab-cbserver's plaintext client, so refuse other schemes by name
        // rather than failing opaquely at first credit (#297: no scheme guessing).
        refuse("upstream-scheme", "this reference shell speaks plaintext http:// only");
    }

    let text = std::fs::read_to_string(&keys_path)
        .unwrap_or_else(|e| refuse("keys-file-unreadable", &format!("{keys_path}: {e}")));
    let (seed, d) = parse_keys_file(&text).unwrap_or_else(|(name, detail)| refuse(name, &detail));

    let engine = CreditEngine::new(ExchangeKeys::from_seed_lanes(seed, d));
    let commitment: String =
        engine.keys_addr_commitment().iter().map(|b| format!("{b:02x}")).collect();

    let listener = TcpListener::bind(&listen)
        .unwrap_or_else(|e| refuse("listen-unbindable", &format!("{listen}: {e}")));
    println!(
        "qumbra-credit-ref: serving on {} (upstream {upstream})\n\
         deposit addr_commitment {commitment}\n\
         POST /v1/credit (raw §3 envelope) | GET /v1/status",
        listener.local_addr().map(|a| a.to_string()).unwrap_or(listen)
    );
    serve(listener, engine, upstream);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keys file parses exactly its documented shape and refuses the rest
    /// by name.
    #[test]
    fn the_keys_file_parses_and_refuses_by_name() {
        let (seed, _) =
            parse_keys_file("# c\nseed = 1,2,0x3,4\ndiversifier = 2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c\n")
                .unwrap();
        assert_eq!(seed, [1, 2, 3, 4]);

        for (bad, why) in [
            ("seed = 1,2,3\ndiversifier = 2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c", "three lanes"),
            ("seed = 1,2,3,4\ndiversifier = 2c2c", "short diversifier"),
            ("seed = 1,2,3,4", "missing diversifier"),
            ("diversifier = 2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c", "missing seed"),
            ("seed = 1,2,3,4\nspend_key = 5", "unknown key"),
            ("just words", "not key = value"),
        ] {
            assert!(parse_keys_file(bad).is_err(), "{why} must refuse");
        }
    }
}
