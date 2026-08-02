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
//!
//! ## 🔴 Step 2 and step 3 no longer answer to the same authority (issue #188)
//!
//! Since baton 1 the compact bundle of step 2 is **in the block body and covered
//! by `tx_body_commitment`**. The AEAD payload of step 3 is not: D2 commits
//! `ct ‖ cm ‖ tag ‖ clue_len` and the ~585 B/note the design priced is
//! `1088/2 + 41`, with no payload in it. So a scan now has **two halves with
//! different guarantees** — detection is answerable from chain data alone, and
//! opening depends on somebody choosing to serve bytes no consensus rule obliges
//! them to hold. Against a `qumbra-node`, whose `/v1/compact` is the whole
//! surface, step 3 is a 404 by design.
//!
//! A scan flow that reports only [`ScanOutcome::notes`] therefore collapses two
//! answers a wallet must never confuse:
//!
//! | truth | old report | now |
//! |---|---|---|
//! | this key was paid nothing here | `notes: []` | `notes: []`, [`Completeness::Complete`] |
//! | this key was paid, and the payload could not be had | `Err(io)` or `notes: []` | `notes: []` + [`ScanOutcome::unopened`], [`Completeness::Incomplete`] |
//!
//! Every output the committed bundle says is ours and this scan did not open is
//! recorded in [`ScanOutcome::unopened`] with its chain coordinates and a reason.
//! **A failed `/full` fetch is no longer fatal to the whole scan**: it is one
//! output's outcome, not the run's, so a wallet against a node that serves no
//! payloads still gets the complete list of what it owns and where.

use std::io::{Read, Write};
use std::net::TcpStream;

use qlab_note::kem::Dk;
use qlab_note::scan::{detect_matches, scan, DetectedNote, EncryptedOutputs, ScanMode};
use qlab_note::wire::CM_LEN;
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

/// Why an output the committed discovery says is ours did not become a note.
///
/// Every variant is about the **payload**, because the payload is the half that
/// is not on the chain. None of them can mean "the detection was wrong": the tag
/// and the `cm` it binds are consensus-committed bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Unopened {
    /// The `/full` fetch did not complete — transport failure, a non-200, or a
    /// response that did not decode. Against a `qumbra-node` this is a 404 and it
    /// is the **honest** answer: the AEAD payload is not in the block body, so no
    /// node is obliged to hold it (issue #188, `discovery_server`'s module docs).
    PayloadUnavailable(String),
    /// The fetch completed and carried no payload at this recipient index — the
    /// server's payload list is shorter than the committed bundle it belongs to.
    PayloadMissing,
    /// A payload was returned for this output and did not authenticate under this
    /// key (AEAD tag, or the `FoSkip` commitment recompute).
    PayloadRejected,
}

/// An output located on the chain that this scan could not turn into a note.
///
/// The coordinates are the committed ones, so this is a claim a wallet can show
/// its user and re-check against any other node: *"height `h`, transaction `t`,
/// output `o`, commitment `cm` — the chain says this is yours and I could not
/// read it."*
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnopenedOutput {
    pub height: u64,
    pub tx_index: u64,
    pub recipient_index: usize,
    /// Index within the recipient bundle — the same index [`LocatedNote`]'s
    /// `detected.index` carries.
    pub output_index: usize,
    /// The committed note commitment this output was detected on.
    pub cm: [u8; CM_LEN],
    pub why: Unopened,
}

/// Whether a scan saw everything the chain says this key owns.
///
/// 🔴 This is the distinction a wallet UI must render, and it is why
/// `notes.is_empty()` is not a question a wallet may ask on its own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Completeness {
    /// Every output detected in the committed discovery was opened and
    /// authenticated. An empty `notes` under this verdict means **nothing was
    /// paid to this key in this range**, and says so on the chain's authority.
    Complete,
    /// `detected` outputs are this key's by the committed discovery, and only
    /// `opened` of them became notes. An empty `notes` under this verdict means
    /// **something is here and this scan could not read it** — never "no notes".
    Incomplete { detected: usize, opened: usize },
}

/// Observable outcome of a scan (drives the report + the fetch-count test).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanStats {
    /// Total bytes of the `/v1/compact` range response.
    pub compact_bytes: usize,
    /// Outputs whose **committed** tag matched this key — detection, decided from
    /// chain data alone and before any fetch. `notes_found` can only ever be a
    /// subset of this, and the difference is [`ScanOutcome::unopened`].
    pub detected_outputs: usize,
    /// `/full` fetches that followed a real tag match.
    pub matched_fetches: usize,
    /// `/full` fetches issued as decoys.
    pub decoy_fetches: usize,
    /// Notes detected and authenticated.
    pub notes_found: usize,
}

/// Result of a scan.
pub struct ScanOutcome {
    /// Outputs opened and authenticated.
    pub notes: Vec<LocatedNote>,
    /// Outputs detected on the chain and **not** opened. Never folded into
    /// `notes`, and never silently dropped — see [`Completeness`].
    pub unopened: Vec<UnopenedOutput>,
    pub stats: ScanStats,
}

impl ScanOutcome {
    /// Did this scan see everything the committed discovery says is ours?
    pub fn completeness(&self) -> Completeness {
        if self.unopened.is_empty() {
            Completeness::Complete
        } else {
            Completeness::Incomplete {
                detected: self.stats.detected_outputs,
                opened: self.notes.len(),
            }
        }
    }
}

/// Run the light-client scan against `base_url` over `[from, to]`.
///
/// `Err` is reserved for a scan that **never started**: only the `/v1/compact`
/// range fetch and its decode are fatal, because without the committed bytes
/// there is nothing to report at all. A `/full` fetch that fails is one output's
/// outcome and lands in [`ScanOutcome::unopened`].
pub fn light_client_scan(
    base_url: &str,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> std::io::Result<ScanOutcome> {
    let mut fetch = |path: &str| http_get(base_url, path).map_err(|e| e.to_string());
    scan_over(&mut fetch, dk, from, to, config, rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// The light-client scan flow, run **fully in-process** against a `&Devnet`
/// via `crate::server::route` — no socket, no `TcpStream`. Behaviourally
/// identical to [`light_client_scan`] (it *is* the same function, over a
/// different fetch); this is the composition path for an in-process driver
/// (qlab-demo) under a no-networking constraint.
pub fn scan_local(
    devnet: &crate::data::Devnet,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> ScanOutcome {
    let mut fetch = |path: &str| {
        crate::server::route(devnet, path).map_err(|(code, msg)| format!("{code} {msg}"))
    };
    // The reference server answers every well-formed internal URL this function
    // builds, so the fatal arm is unreachable here — kept as an `expect` rather
    // than a silent empty outcome for exactly that reason.
    scan_over(&mut fetch, dk, from, to, config, rng).expect("in-process compact range must resolve")
}

/// The scan itself, over any fetch. One implementation so the socket path and the
/// in-process path cannot drift on what counts as detected, opened or unopened.
fn scan_over<F>(
    fetch: &mut F,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> Result<ScanOutcome, String>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let compact = fetch(&format!("/v1/compact?from={from}&to={to}"))?;
    let mut stats = ScanStats { compact_bytes: compact.len(), ..Default::default() };
    let blocks = decode_compact_response(&compact).map_err(|e| format!("{e:?}"))?;

    // The (height, n_txs) space, for randomized decoy targeting.
    let tx_space: Vec<(u64, u64)> = blocks
        .iter()
        .map(|b| (b.height, b.groups.len() as u64))
        .filter(|(_, n)| *n > 0)
        .collect();

    let mut notes = Vec::new();
    let mut unopened = Vec::new();

    for block in &blocks {
        for group in &block.groups {
            // ---- Detection. Decided from the committed bytes alone, before any
            // fetch, and recorded whether or not the fetch that follows works.
            let detected: Vec<(usize, Vec<usize>)> = group
                .recipients
                .iter()
                .enumerate()
                .map(|(ri, bundle)| (ri, detect_matches(dk, bundle)))
                .filter(|(_, hits)| !hits.is_empty())
                .collect();
            if detected.is_empty() {
                continue;
            }
            stats.detected_outputs += detected.iter().map(|(_, h)| h.len()).sum::<usize>();

            // The committed coordinates of one detected output. Built from the
            // block and the group, never from anything the `/full` fetch returned.
            let located = |ri: usize, oi: usize, why: Unopened| UnopenedOutput {
                height: block.height,
                tx_index: group.tx_index,
                recipient_index: ri,
                output_index: oi,
                cm: group.recipients[ri].entries[oi].cm,
                why,
            };

            // ---- Opening. Everything below this line depends on bytes no
            // consensus rule obliges anybody to hold.
            let path = format!("/v1/block/{}/tx/{}/full", block.height, group.tx_index);
            let fetched = fetch(&path);
            stats.matched_fetches += 1;
            let payloads_per_recipient = match &fetched {
                Ok(bytes) => decode_full_response(bytes)
                    .map_err(|e| format!("undecodable /full response: {e:?}")),
                Err(e) => Err(e.clone()),
            };

            match payloads_per_recipient {
                Err(why) => {
                    // The whole transaction is unreadable: every detected output
                    // is reported, with the reason, rather than the scan ending.
                    for (ri, hits) in &detected {
                        for &oi in hits {
                            unopened.push(located(
                                *ri,
                                oi,
                                Unopened::PayloadUnavailable(why.clone()),
                            ));
                        }
                    }
                }
                Ok(payloads_per_recipient) => {
                    for (ri, hits) in &detected {
                        let (opened, missing) = match payloads_per_recipient.get(*ri) {
                            Some(payloads) => {
                                let enc = EncryptedOutputs {
                                    bundle: group.recipients[*ri].clone(),
                                    payloads: payloads.clone(),
                                };
                                // `scan` re-runs the same tag comparison, so what it
                                // returns is a subset of `hits` by construction.
                                let found = scan(dk, &enc, config.mode);
                                let idx: Vec<usize> = found.iter().map(|d| d.index).collect();
                                for detected in found {
                                    notes.push(LocatedNote {
                                        height: block.height,
                                        tx_index: group.tx_index,
                                        recipient_index: *ri,
                                        detected,
                                    });
                                }
                                (idx, false)
                            }
                            None => (Vec::new(), true),
                        };
                        for &oi in hits {
                            if !opened.contains(&oi) {
                                let why = if missing {
                                    Unopened::PayloadMissing
                                } else {
                                    Unopened::PayloadRejected
                                };
                                unopened.push(located(*ri, oi, why));
                            }
                        }
                    }
                }
            }

            // Decoy over-fetch (§2 mitigation) — randomized targets, discarded.
            // A decoy's *result* is discarded by construction, so its failure is
            // discarded too: a 404 on a decoy must not decide a real scan's fate.
            if let DecoyPolicy::PerMatch { max } = config.decoy {
                let max = max.max(1);
                let n_decoys = 1 + (rng.next_u64() as usize % max); // 1..=max
                for _ in 0..n_decoys {
                    if tx_space.is_empty() {
                        break;
                    }
                    let (h, n_tx) = tx_space[rng.next_u64() as usize % tx_space.len()];
                    let ti = rng.next_u64() % n_tx;
                    let _ = fetch(&format!("/v1/block/{h}/tx/{ti}/full"));
                    stats.decoy_fetches += 1;
                }
            }
        }
    }

    stats.notes_found = notes.len();
    Ok(ScanOutcome { notes, unopened, stats })
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
            // A server that serves both halves opens everything it detected, so
            // the verdict is Complete — the counterweight that keeps
            // `Incomplete` from being what this code always says.
            assert_eq!(out.stats.detected_outputs, d.expected_matches, "{mode:?}");
            assert!(out.unopened.is_empty(), "{mode:?}: {:?}", out.unopened);
            assert_eq!(out.completeness(), Completeness::Complete, "{mode:?}");
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
    fn scan_local_matches_socket_scan_and_finds_planted_notes() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(1);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_local(&d, &d.our.dk, 1, d.tip_height(), cfg, &mut rng);
        assert_eq!(out.notes.len(), d.expected_matches, "socket-free scan finds all planted notes");
        assert_eq!(out.stats.notes_found, d.expected_matches);
        assert!(out.stats.matched_fetches > 0);
    }

    #[test]
    fn scan_local_wrong_key_finds_nothing() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(3);
        let stranger = qlab_note::kem::generate_keypair(&mut StdRng::seed_from_u64(999));
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_local(&d, &stranger.dk, 1, d.tip_height(), cfg, &mut rng);
        assert_eq!(out.notes.len(), 0);
        assert_eq!(out.stats.matched_fetches, 0);
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
        // 🔴 And it says so on the chain's authority: nothing was detected, so the
        // empty result is a *complete* answer and not a failed one.
        assert_eq!(out.stats.detected_outputs, 0);
        assert!(out.unopened.is_empty());
        assert_eq!(out.completeness(), Completeness::Complete);
        handle.shutdown();
    }

    // ---- issue #188 (3/4): an incomplete scan is never an empty one -----------

    /// Serve `/v1/compact` from the reference server and answer every `/full`
    /// with `err`. This is a `qumbra-node`'s shape: the committed compact bundle
    /// is served from the block, and the AEAD payload — which is not in any block
    /// — is a 404.
    fn compact_only<'a>(
        devnet: &'a Devnet,
        err: &'a str,
    ) -> impl FnMut(&str) -> Result<Vec<u8>, String> + 'a {
        move |path: &str| {
            if path.starts_with("/v1/compact") {
                crate::server::route(devnet, path).map_err(|(c, m)| format!("{c} {m}"))
            } else {
                Err(err.to_string())
            }
        }
    }

    /// 🔴 **The distinction, in isolation.** A wallet that matches a committed tag
    /// and cannot complete the fetch reports *something other than "no notes"*.
    ///
    /// Three separate claims, because two of them would pass on an accident:
    /// the detected count is right, the unopened list carries the chain
    /// coordinates of every one of them, and the verdict is `Incomplete`.
    #[test]
    fn a_detected_output_whose_payload_cannot_be_fetched_is_reported_not_dropped() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(41);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = compact_only(&d, "non-200 response: HTTP/1.1 404 Not Found");
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
            .expect("the compact half still resolves, so the scan runs");

        assert!(d.expected_matches > 0, "the fixture plants something to lose");
        assert_eq!(
            out.stats.detected_outputs, d.expected_matches,
            "detection is answered from committed bytes and does not need the payload"
        );
        assert_eq!(out.notes.len(), 0, "nothing could be opened");
        assert_eq!(
            out.completeness(),
            Completeness::Incomplete { detected: d.expected_matches, opened: 0 },
            "🔴 a scan that could not complete must not read as a scan that found nothing"
        );
        assert_eq!(out.unopened.len(), d.expected_matches);
        for u in &out.unopened {
            assert!(
                matches!(u.why, Unopened::PayloadUnavailable(ref e) if e.contains("404")),
                "the reason names what actually happened: {:?}",
                u.why
            );
            assert!(u.height >= 1, "a chain coordinate a wallet can re-check elsewhere");
            assert_ne!(u.cm, [0u8; CM_LEN], "the committed commitment travels with it");
        }
        // The commitments reported unopened are exactly the ones the same fixture
        // opens when the payloads are served — no set is invented and none is lost.
        let (d2, handle) = fresh();
        let mut rng2 = StdRng::seed_from_u64(41);
        let good = light_client_scan(&handle.base_url(), &d2.our.dk, 1, d2.tip_height(), cfg, &mut rng2)
            .expect("scan");
        handle.shutdown();
        let mut lost: Vec<[u8; CM_LEN]> = out.unopened.iter().map(|u| u.cm).collect();
        let mut opened: Vec<[u8; CM_LEN]> = good
            .notes
            .iter()
            .map(|n| qlab_note::hash::digest_bytes(&n.detected.note.commitment()))
            .collect();
        lost.sort();
        opened.sort();
        assert_eq!(lost, opened, "the unopened set is the set that would have been opened");
    }

    /// A `/full` that answers 200 with a **shorter** payload list than the
    /// committed bundle it belongs to. The old flow's `else { continue }` dropped
    /// exactly this case in silence — a 200 that means nothing is the same absence
    /// as a 404, and it is now named separately because the two want different
    /// operator responses.
    #[test]
    fn a_short_full_response_is_payload_missing_and_not_an_empty_wallet() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(42);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            if path.starts_with("/v1/compact") {
                crate::server::route(&d, path).map_err(|(c, m)| format!("{c} {m}"))
            } else {
                // Well-formed, decodable, and carrying nobody's payloads.
                Ok(crate::codec::encode_full_response(&[]))
            }
        };
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng).expect("scan");
        assert_eq!(out.notes.len(), 0);
        assert_eq!(out.unopened.len(), d.expected_matches);
        assert!(out.unopened.iter().all(|u| u.why == Unopened::PayloadMissing), "{:?}", out.unopened);
        assert!(matches!(out.completeness(), Completeness::Incomplete { opened: 0, .. }));
    }

    /// A payload that arrives and does not authenticate. Distinct from both
    /// absences above: the bytes were served and the wallet refused them, which is
    /// the one case where the *server* is the suspect rather than the topology.
    #[test]
    fn a_tampered_payload_is_reported_rejected_rather_than_missing() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(43);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            let bytes = crate::server::route(&d, path).map_err(|(c, m)| format!("{c} {m}"))?;
            if path.starts_with("/v1/compact") {
                return Ok(bytes);
            }
            let mut payloads = crate::codec::decode_full_response(&bytes).expect("reference bytes");
            for recipient in payloads.iter_mut() {
                for p in recipient.iter_mut() {
                    if let Some(last) = p.last_mut() {
                        *last ^= 0x01; // break the Poly1305 tag, keep the shape
                    }
                }
            }
            Ok(crate::codec::encode_full_response(&payloads))
        };
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng).expect("scan");
        assert_eq!(out.notes.len(), 0, "a tampered payload authenticates nothing");
        assert_eq!(out.unopened.len(), d.expected_matches);
        assert!(
            out.unopened.iter().all(|u| u.why == Unopened::PayloadRejected),
            "{:?}",
            out.unopened
        );
    }

    /// A decoy fetch that fails must not decide a real scan's fate. Its result is
    /// discarded by construction, and before this the `?` on it aborted a scan
    /// that had already succeeded — which on a `qumbra-node` (every `/full` is a
    /// 404) is every scan with a match in it.
    #[test]
    fn a_failing_decoy_fetch_does_not_end_the_scan() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(44);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 3 } };
        let mut fetch = compact_only(&d, "connection refused");
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
            .expect("a failing decoy is not a failed scan");
        assert!(out.stats.decoy_fetches >= out.stats.matched_fetches, "decoys still issued");
        assert_eq!(out.stats.detected_outputs, d.expected_matches);
        assert_eq!(out.unopened.len(), d.expected_matches);
    }
}

// Re-export SeedableRng for the tests' StdRng::seed_from_u64 usage.
#[cfg(test)]
use rand::SeedableRng;
