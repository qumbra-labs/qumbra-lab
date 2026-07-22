//! The light-client scan flow + the normative decoy over-fetch mitigation.
//!
//! Flow (note-discovery §2):
//! 1. range-fetch `/v1/compact` → decode compact groups;
//! 2. decap once per `(tx, recipient)`, tag-filter the entries (cheap, no full
//!    payloads yet) to decide which `(height, tx)` to full-fetch;
//! 3. for each matched `(height, tx)`: `/full` fetch → reconstruct the
//!    `EncryptedOutputs` (compact bundle + fetched payloads) → run the ratified
//!    `qlab_note::scan::scan` (FullFo default) which AEAD-decrypts and, on
//!    FoSkip, recomputes `cm` and compares to the on-wire value;
//! 4. **decoy over-fetch**: per matched fetch, issue ≥1 randomized decoy
//!    `/full` fetches (discarded) — the §2 fetch-after-match side-channel
//!    mitigation, behind [`DecoyPolicy`].
//!
//! The HTTP client is a dependency-free std `TcpStream` GET (we own both ends,
//! localhost, fixed response shapes) — recorded in the plan doc.

use std::io::{Read, Write};
use std::net::TcpStream;

use qlab_note::kem::Dk;
use qlab_note::scan::{scan, DetectedNote, EncryptedOutputs, ScanMode};
use rand::rngs::StdRng;
use rand::Rng;

use crate::codec::{decode_compact_response, decode_full_response};

/// Decoy over-fetch policy (the §2 trust-posture mitigation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecoyPolicy {
    /// No decoys (baseline; leaks the exact matched-fetch pattern).
    Off,
    /// Per matched fetch, issue a randomized number of decoy fetches in `1..=max`
    /// (spec: "≥1 per matched fetch, randomized"). `max` ≥ 1.
    PerMatch { max: usize },
}

/// Configuration for a scan run.
#[derive(Clone, Copy)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub decoy: DecoyPolicy,
}

impl Default for ScanConfig {
    fn default() -> Self {
        // FullFo is the ratified default; decoys on at the minimum rate.
        Self { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } }
    }
}

/// A detected note located within the chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocatedNote {
    pub height: u64,
    pub tx_index: u64,
    pub recipient_index: usize,
    pub detected: DetectedNote,
}

/// Observable outcome of a scan (drives the report + the fetch-count test).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanStats {
    /// Total bytes of the `/v1/compact` range response.
    pub compact_bytes: usize,
    /// `/full` fetches that followed a real tag match.
    pub matched_fetches: usize,
    /// `/full` fetches issued as decoys.
    pub decoy_fetches: usize,
    /// Notes detected and authenticated.
    pub notes_found: usize,
}

/// Result of a scan.
pub struct ScanOutcome {
    pub notes: Vec<LocatedNote>,
    pub stats: ScanStats,
}

/// Run the light-client scan against `base_url` over `[from, to]`.
pub fn light_client_scan(
    base_url: &str,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> std::io::Result<ScanOutcome> {
    let compact = http_get(base_url, &format!("/v1/compact?from={from}&to={to}"))?;
    let mut stats = ScanStats { compact_bytes: compact.len(), ..Default::default() };
    let blocks = decode_compact_response(&compact)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))?;

    // The (height, n_txs) space, for randomized decoy targeting.
    let tx_space: Vec<(u64, u64)> = blocks
        .iter()
        .map(|b| (b.height, b.groups.len() as u64))
        .filter(|(_, n)| *n > 0)
        .collect();

    let mut notes = Vec::new();

    for block in &blocks {
        for group in &block.groups {
            // Tag pre-filter: any entry in this tx matches our key?
            let matched = group
                .recipients
                .iter()
                .any(|bundle| bundle_has_tag_match(dk, bundle));
            if !matched {
                continue;
            }

            // Matched: full-fetch the payloads for this (height, tx).
            let full = http_get(
                base_url,
                &format!("/v1/block/{}/tx/{}/full", block.height, group.tx_index),
            )?;
            stats.matched_fetches += 1;
            let payloads_per_recipient = decode_full_response(&full)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))?;

            // Authenticate via the ratified scan (per recipient).
            for (ri, bundle) in group.recipients.iter().enumerate() {
                let Some(payloads) = payloads_per_recipient.get(ri) else { continue };
                let enc = EncryptedOutputs { bundle: bundle.clone(), payloads: payloads.clone() };
                for detected in scan(dk, &enc, config.mode) {
                    notes.push(LocatedNote {
                        height: block.height,
                        tx_index: group.tx_index,
                        recipient_index: ri,
                        detected,
                    });
                }
            }

            // Decoy over-fetch (§2 mitigation) — randomized targets, discarded.
            if let DecoyPolicy::PerMatch { max } = config.decoy {
                let max = max.max(1);
                let n_decoys = 1 + (rng.next_u64() as usize % max); // 1..=max
                for _ in 0..n_decoys {
                    if tx_space.is_empty() {
                        break;
                    }
                    let (h, n_tx) = tx_space[rng.next_u64() as usize % tx_space.len()];
                    let ti = rng.next_u64() % n_tx;
                    let _ = http_get(base_url, &format!("/v1/block/{h}/tx/{ti}/full"))?;
                    stats.decoy_fetches += 1;
                }
            }
        }
    }

    stats.notes_found = notes.len();
    Ok(ScanOutcome { notes, stats })
}

/// Does any entry in `bundle` produce a detection-tag match under `dk`? (The
/// cheap pre-filter that decides whether to full-fetch.)
fn bundle_has_tag_match(dk: &Dk, bundle: &qlab_note::wire::RecipientBundle) -> bool {
    use qlab_note::derive::detection_tag;
    use qlab_note::hash::digest_from_bytes;
    use qlab_note::kem::decapsulate;
    let k = decapsulate(dk, &bundle.ct);
    bundle
        .entries
        .iter()
        .any(|e| detection_tag(&k, &digest_from_bytes(&e.cm)) == e.tag)
}

/// Minimal dependency-free HTTP/1.1 GET over `TcpStream`. `base_url` is
/// `http://host:port`; returns the response body bytes. Uses `Connection: close`
/// and reads to EOF (fixed, small localhost responses).
pub fn http_get(base_url: &str, path_and_query: &str) -> std::io::Result<Vec<u8>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "base_url must be http://"))?;
    let mut stream = TcpStream::connect(authority)?;
    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    // Split headers/body at the first CRLFCRLF.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no HTTP header terminator"))?;
    let header = &raw[..sep];
    let raw_body = &raw[sep + 4..];

    // Status line: "HTTP/1.1 200 OK".
    let status_ok = header
        .split(|&b| b == b'\n')
        .next()
        .map(|line| line.windows(3).any(|w| w == b"200"))
        .unwrap_or(false);
    if !status_ok {
        let status = String::from_utf8_lossy(header.split(|&b| b == b'\n').next().unwrap_or(b""));
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("non-200 response: {status}"),
        ));
    }

    // tiny_http replies with `Transfer-Encoding: chunked` — de-chunk if present.
    let header_lc = header.to_ascii_lowercase();
    let chunked = header_lc
        .windows(b"transfer-encoding: chunked".len())
        .any(|w| w == b"transfer-encoding: chunked");
    if chunked {
        dechunk(raw_body)
    } else {
        Ok(raw_body.to_vec())
    }
}

/// Decode an HTTP/1.1 `Transfer-Encoding: chunked` body:
/// repeated `<hex-size>\r\n<size bytes>\r\n`, terminated by a `0\r\n` chunk.
fn dechunk(mut b: &[u8]) -> std::io::Result<Vec<u8>> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed chunked body");
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n").ok_or_else(bad)?;
        // Chunk-size may carry `;ext` — take the hex prefix only.
        let size_tok = &b[..line_end];
        let hex_end = size_tok
            .iter()
            .position(|&c| c == b';')
            .unwrap_or(size_tok.len());
        let size_str = std::str::from_utf8(&size_tok[..hex_end]).map_err(|_| bad())?;
        let size = usize::from_str_radix(size_str.trim(), 16).map_err(|_| bad())?;
        b = &b[line_end + 2..];
        if size == 0 {
            break;
        }
        if b.len() < size + 2 {
            return Err(bad());
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..]; // skip the trailing CRLF
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Devnet, GenParams};
    use crate::server::serve;
    use std::sync::Arc;

    fn fresh() -> (Arc<Devnet>, crate::server::ServerHandle) {
        let d = Arc::new(Devnet::generate(GenParams::default()));
        let h = serve(Arc::clone(&d));
        (d, h)
    }

    #[test]
    fn scan_finds_exactly_the_planted_notes_both_modes() {
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let (d, handle) = fresh();
            let mut rng = StdRng::seed_from_u64(1);
            let cfg = ScanConfig { mode, decoy: DecoyPolicy::Off };
            let out = light_client_scan(&handle.base_url(), &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
                .expect("scan runs");
            assert_eq!(
                out.notes.len(),
                d.expected_matches,
                "{mode:?}: found all planted notes over localhost"
            );
            assert_eq!(out.stats.notes_found, d.expected_matches);
            handle.shutdown();
        }
    }

    #[test]
    fn decoy_fetches_at_least_one_per_match_when_on_and_zero_when_off() {
        // OFF: no decoys, matched_fetches == number of matched (height,tx).
        let (d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(7);
        let off = light_client_scan(
            &handle.base_url(),
            &d.our.dk,
            1,
            d.tip_height(),
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off },
            &mut rng,
        )
        .unwrap();
        assert_eq!(off.stats.decoy_fetches, 0, "decoys off → zero decoy fetches");
        assert!(off.stats.matched_fetches > 0, "there are real matches to fetch");
        handle.shutdown();

        // ON: ≥1 decoy per matched fetch.
        let (d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(7);
        let on = light_client_scan(
            &handle.base_url(),
            &d.our.dk,
            1,
            d.tip_height(),
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 3 } },
            &mut rng,
        )
        .unwrap();
        assert_eq!(on.stats.matched_fetches, off.stats.matched_fetches, "same real matches");
        assert!(
            on.stats.decoy_fetches >= on.stats.matched_fetches,
            "≥1 decoy per matched fetch ({} decoys vs {} matches)",
            on.stats.decoy_fetches,
            on.stats.matched_fetches
        );
        assert!(
            on.stats.decoy_fetches <= on.stats.matched_fetches * 3,
            "≤ max decoys per matched fetch"
        );
        // Decoys must not change what is found.
        assert_eq!(on.stats.notes_found, off.stats.notes_found);
        handle.shutdown();
    }

    #[test]
    fn wrong_key_finds_nothing() {
        let (_d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(3);
        let stranger = qlab_note::kem::generate_keypair(&mut StdRng::seed_from_u64(999));
        let out = light_client_scan(
            &handle.base_url(),
            &stranger.dk,
            1,
            8,
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off },
            &mut rng,
        )
        .unwrap();
        assert_eq!(out.notes.len(), 0, "a stranger's key detects nothing");
        assert_eq!(out.stats.matched_fetches, 0, "no matches → no full fetches");
        handle.shutdown();
    }
}

// Re-export SeedableRng for the tests' StdRng::seed_from_u64 usage.
#[cfg(test)]
use rand::SeedableRng;
