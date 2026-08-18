//! Exchange crediting-flow reference service — **stage 0 skeleton** (lab
//! #483, `docs/kit-stage0-survey.md` §4).
//!
//! Stage 2 builds the runnable service: consume a wallet-interop §3
//! disclosure envelope (out-of-band `POST /v1/credit` per the survey's e2e
//! sketch, pending the coordinator's §4-transport answer on #483), scan the
//! chain for the deposit with the exchange's own keys, verify via qlab-vask,
//! and answer credit / refuse with NAMED reasons over the faucet's edge
//! posture (4xx never 5xx).
//!
//! Until then this binary refuses by name — the house pattern — rather than
//! pretending to serve.

fn main() {
    eprintln!(
        "qumbra-credit-ref: NOT BUILT — stage 2 of lab #483. \
         Stage 0 reserved this crate and its seams; see docs/kit-stage0-survey.md §4."
    );
    std::process::exit(2);
}

#[cfg(test)]
mod citation_tests {
    //! Stage-0 citations (survey §1.3): the seams the crediting flow will
    //! consume exist with the inventoried signatures. Nothing here proves,
    //! opens a socket, or touches a chain.

    use qlab_cbserver::client::{light_client_scan, ScanConfig, ScanOutcome};
    use qlab_cbserver::codec::decode_full_response;
    use qlab_note::compact::PAYLOAD_LEN;
    use qlab_note::kem::Dk;
    use rand::rngs::StdRng;

    /// Survey §1.3: the scan entry the service reuses (detect the deposit,
    /// rule-1 groundwork) exists with the inventoried signature. The
    /// caller-supplied-transport variant `light_client_scan_with` is generic
    /// over its fetch and is cited by name in the survey; the concrete
    /// socket-path wrapper is the pinnable citation here.
    #[test]
    fn the_scan_seam_exists() {
        let _scan: fn(
            &str,
            &Dk,
            u64,
            u64,
            ScanConfig,
            &mut StdRng,
        ) -> std::io::Result<ScanOutcome> = light_client_scan;
    }

    /// Survey §1.3: the full-fetch decode the service uses to read a matched
    /// deposit's payloads exists.
    #[test]
    fn the_full_fetch_decode_seam_exists() {
        let _decode: fn(&[u8]) -> Result<Vec<Vec<Vec<u8>>>, qlab_cbserver::codec::CodecError> =
            decode_full_response;
    }

    /// Survey §1.2 (the memo-gap finding's constant): the per-output AEAD
    /// payload on the deployed wire is fixed 120 B — no memo channel. If this
    /// ever moves, the §4-transport question must be re-read before stage 2
    /// relies on out-of-band delivery.
    #[test]
    fn the_payload_is_fixed_120_bytes_no_memo_channel() {
        assert_eq!(PAYLOAD_LEN, 120);
    }
}
