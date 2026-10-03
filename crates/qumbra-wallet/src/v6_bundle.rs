//! **One V6 wrapper bundle, fetched and bound to its id** (lab #860 R2;
//! `l2-read-path-decision` D3): a wallet anchoring an exit to a landed bundle
//! fetches that bundle's raw bytes from `GET /v1/bundle/{height}` and accepts
//! them only if they hash to the id it expects — the id the chain committed
//! (the block's `BundleRef`, `/v1/wrapper`'s `last_bundle_id`, or
//! `/v1/l2/index`'s `bundle_id`). A lying index then costs a refusal, never a
//! proof built on the wrong roots.

/// The route's prefix (`qumbra_node::discovery_server::BUNDLE_PATH_PREFIX`).
pub const BUNDLE_PATH_PREFIX: &str = "/v1/bundle/";

/// Why a bundle was refused — by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleFetchRefusal {
    /// The endpoint did not answer with the bytes.
    Unavailable { height: u64, why: String },
    /// Longer than the V6 body bound (`MAX_V6_BODY_BYTES`).
    TooLarge { height: u64, got: usize },
    /// The bytes do not hash to the expected id.
    BundleIdMismatch { height: u64, want: [u8; 32], got: [u8; 32] },
}

impl std::fmt::Display for BundleFetchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        match self {
            BundleFetchRefusal::Unavailable { height, why } => write!(f, "GET {BUNDLE_PATH_PREFIX}{height}: {why}"),
            BundleFetchRefusal::TooLarge { height, got } => write!(
                f,
                "the bundle at height {height} is {got} B, over the V6 body bound of {} B",
                qlab_devnet::body::MAX_V6_BODY_BYTES
            ),
            BundleFetchRefusal::BundleIdMismatch { height, want, got } => write!(
                f,
                "the bundle served for height {height} hashes to {}, not the expected id {}",
                hex(got),
                hex(want)
            ),
        }
    }
}

impl std::error::Error for BundleFetchRefusal {}

/// Fetch the bundle at `height` and bind it to `expected_id` (keccak of the
/// bytes); the bytes, or a refusal by name. Pass a fetch that bounds the
/// route on the wire — `net::verified_scan_fetch` does, through
/// `annulet_verify::response_ceiling` (the V6 body bound + head slack); the
/// [`BundleFetchRefusal::TooLarge`] check here is belt and braces for any
/// other fetch.
pub fn fetch_bundle<F>(fetch: &mut F, height: u64, expected_id: [u8; 32]) -> Result<Vec<u8>, BundleFetchRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let bytes = fetch(&format!("{BUNDLE_PATH_PREFIX}{height}"))
        .map_err(|why| BundleFetchRefusal::Unavailable { height, why })?;
    if bytes.len() > qlab_devnet::body::MAX_V6_BODY_BYTES {
        return Err(BundleFetchRefusal::TooLarge { height, got: bytes.len() });
    }
    let got = qlab_devnet::hash::keccak256(&bytes);
    if got != expected_id {
        return Err(BundleFetchRefusal::BundleIdMismatch { height, want: expected_id, got });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_flip_is_refused_by_name_and_the_honest_bytes_pass() {
        let bytes = b"a wrapper bundle".to_vec();
        let id = qlab_devnet::hash::keccak256(&bytes);
        let mut honest = |p: &str| {
            assert_eq!(p, "/v1/bundle/48");
            Ok(bytes.clone())
        };
        assert_eq!(fetch_bundle(&mut honest, 48, id), Ok(bytes.clone()));
        let mut flipped = |_: &str| {
            let mut b = bytes.clone();
            b[3] ^= 1;
            Ok(b)
        };
        match fetch_bundle(&mut flipped, 48, id) {
            Err(BundleFetchRefusal::BundleIdMismatch { height: 48, want, .. }) => assert_eq!(want, id),
            other => panic!("expected BundleIdMismatch, got {other:?}"),
        }
        let mut down = |_: &str| Err("503 unavailable".to_string());
        assert!(matches!(fetch_bundle(&mut down, 48, id), Err(BundleFetchRefusal::Unavailable { height: 48, .. })));
        let mut huge = |_: &str| Ok(vec![0u8; qlab_devnet::body::MAX_V6_BODY_BYTES + 1]);
        assert!(matches!(fetch_bundle(&mut huge, 48, id), Err(BundleFetchRefusal::TooLarge { height: 48, .. })));
    }
}
