//! Live probes against the **public https edge** (issue #297) — every test here
//! is `#[ignore]`d and none runs under the acceptance bar.
//!
//! They exist because the one thing the sealed suite structurally cannot cover
//! is a real TLS handshake against a real certificate chain: this workspace has
//! no TLS *server* and adding one (plus a test CA) to prove the client would be
//! a larger change than the client itself. So the handshake is evidence rather
//! than a gate, and this file is how that evidence is re-derived instead of
//! being taken on a builder's word:
//!
//! ```sh
//! cargo test -p qumbra-wallet --test live_edge -- --ignored --nocapture
//! ```
//!
//! They talk to the network and to somebody else's uptime, so they are **not**
//! part of the suite and must never become part of it.

use qumbra_wallet::net::{submit_tx, SubmitClass};

/// The deployed wallet-facing endpoint, https-only by decision
/// (`qumbra-design/t1-public-host-decision.md`).
const EDGE: &str = "https://seed.qumbra.org";

/// `POST /v1/tx` over TLS reaches the node and comes back with the node's own
/// typed vocabulary — which is the whole point of doing TLS *under* the
/// hand-rolled HTTP/1.1 rather than replacing it with an HTTP client.
///
/// The body is deliberately not a transaction: the property under test is that
/// the exchange **completes over TLS** and that a refusal arrives with its own
/// words, not that anything is accepted. A malformed body is refused at decode,
/// before any pool or relay work, so this costs the live net a parse.
#[test]
#[ignore = "network: talks to the live https edge"]
fn the_submit_verb_completes_over_tls_and_the_node_answers_in_its_own_words() {
    let answer = submit_tx(EDGE, b"not a transaction").expect("the exchange completes over TLS");
    println!("status={} body={:?} class={:?}", answer.status, answer.body, answer.class());
    assert!(
        !answer.is_in_flight(),
        "garbage must not be in flight: {} {}",
        answer.status,
        answer.body
    );
    assert_eq!(
        answer.class(),
        SubmitClass::Refused,
        "a malformed body is a named refusal, not a transport failure: {} {}",
        answer.status,
        answer.body
    );
}

/// A `Connection: close` GET over TLS returns a decodable body — the leaf
/// source's transport, end to end, against the real edge.
#[test]
#[ignore = "network: talks to the live https edge"]
fn the_anchor_source_reads_the_live_edge_over_tls() {
    use qumbra_wallet::sync::AnchorSource;
    let anchors = qumbra_wallet::net::HttpAnchorSource::new(EDGE).anchors().expect("anchors");
    println!(
        "tip={} finalized={:?} roots={} max_age={}",
        anchors.tip_height,
        anchors.finalized_height,
        anchors.roots.len(),
        anchors.max_age_blocks
    );
    assert!(anchors.tip_height > 0, "a live chain has a tip");
}

/// **The refusal must be loud.** An https URL whose certificate does not check
/// out fails with the certificate's own reason, and there is no fallback to
/// plaintext (#297 stop point: an http-fallback-on-TLS-failure path is refused
/// by decision).
///
/// `badssl.com` is a third-party service and this test depends on it, which is
/// the second reason this file is ignored by default.
#[test]
#[ignore = "network: talks to badssl.com, a third party"]
fn a_certificate_that_does_not_check_out_is_refused_by_its_own_reason() {
    for (host, expected) in [
        ("https://expired.badssl.com", "expired"),
        ("https://wrong.host.badssl.com", "not valid for name"),
        ("https://self-signed.badssl.com", "UnknownIssuer"),
    ] {
        let e = submit_tx(host, b"x").expect_err("a bad certificate is never a success");
        let msg = e.to_string();
        println!("{host} -> {msg}");
        assert!(msg.contains("TLS handshake"), "{host}: {msg}");
        assert!(msg.contains(expected), "{host}: the reason must survive to the user — {msg}");
    }
}
