//! Lab #785 F5-4c-1 — the **bridge document**: a V6 chain's QMB bridged in
//! (`ΔD`) and out (`ΔE`) per epoch, the cumulative `D_cum` / `E_cum`, and
//! `circulating = emission − burned − D_cum + E_cum` — read off the in-process
//! node's bridge ledger (`qumbra_node::bridge`, the rows `/v1/supply/bridge`
//! serves).
//!
//! **A document of its own, not a key in the health page**, on the attest
//! precedent (lab #726): off V6 it says it does not apply and carries no
//! figures, so no reader can mistake "no bridge" for "nothing bridged". The
//! health page's goldens do not move. `circulating` is written only when the
//! supply rows cover the tip (the health page's coverage rule); otherwise the
//! string `UNAVAILABLE`, never a number.

use qlab_node::bridge_wire::BridgeView;
use qlab_node::telemetry::SupplyCoverage;
use qlab_node::Telemetry;

/// The route.
pub const BRIDGE_PATH: &str = "/v1/bridge";

/// The document for a chain with no bridge (every non-V6 net).
pub fn not_v6() -> String {
    format!(
        "{{\"v\":1,\"available\":false,\"why\":\"{BRIDGE_PATH} exists only on a V6 chain: \
         this chain has no L2 bridge\"}}"
    )
}

/// The bridge document: `view` is the node's bridge ledger (`None` off V6;
/// `Some(Err(why))` when the ledger refused — said as itself, review S3), `t`
/// its telemetry (for the emission and burn the attestation needs).
/// `circulating` needs the supply rows to cover the tip AND the bridge rows to
/// cover the same tip (review S2); otherwise the token.
pub fn bridge_document(view: Option<Result<&BridgeView, String>>, t: &Telemetry) -> String {
    let v = match view {
        None => return not_v6(),
        Some(Err(why)) => {
            return format!("{{\"v\":1,\"available\":false,\"why\":\"the bridge ledger refused: {}\"}}", crate::json::esc(&why))
        }
        Some(Ok(v)) => v,
    };
    let circulating = (matches!(t.supply_coverage(), SupplyCoverage::Complete) && v.covered_height == t.tip_height)
        .then(|| {
            let emission = t.supply.iter().try_fold(0u64, |a, e| a.checked_add(e.measured_coinbase))?;
            let burned = t.supply.iter().try_fold(0u64, |a, e| a.checked_add(e.burned))?;
            v.circulating(emission, burned)
        })
        .flatten()
        .map_or_else(|| format!("\"{}\"", crate::json::UNAVAILABLE), |c| c.to_string());
    let epochs: Vec<String> = v
        .rows
        .iter()
        .map(|r| {
            format!(
                "{{\"epoch\":{},\"start_height\":{},\"end_height\":{},\"bridged_in\":{},\"bridged_out\":{}}}",
                r.epoch, r.start_height, r.end_height, r.bridged_in, r.bridged_out
            )
        })
        .collect();
    format!(
        "{{\"v\":1,\"available\":true,\"covered_height\":{},\"d_cum\":{},\"e_cum\":{},\"circulating\":{circulating},\
         \"epochs\":[{}]}}",
        v.covered_height,
        v.d_cum,
        v.e_cum,
        epochs.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_node::bridge_wire::BridgeRow;
    use qlab_node::supply::SupplyEpoch;

    fn view() -> BridgeView {
        BridgeView {
            covered_height: 14,
            d_cum: 1_000,
            e_cum: 40,
            rows: vec![BridgeRow { epoch: 0, start_height: 0, end_height: 14, bridged_in: 1_000, bridged_out: 40 }],
        }
    }

    fn covered() -> Telemetry {
        Telemetry::assemble(14, Some(8), Some(75), 0, 3, 1, qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS).with_supply(vec![SupplyEpoch {
            epoch: 0,
            start_height: 1,
            end_height: 14,
            measured_coinbase: 10_000,
            expected_coinbase: 10_000,
            fees: 0,
            burned: 100,
        }])
    }

    /// Off V6 the document says it does not apply and carries no figure.
    #[test]
    fn off_v6_the_bridge_document_is_not_available() {
        let v: serde_json::Value = serde_json::from_str(&bridge_document(None, &covered())).unwrap();
        assert_eq!(v["available"], false);
        // A refusing ledger says so, as itself.
        let v: serde_json::Value = serde_json::from_str(&bridge_document(Some(Err("CounterDecrease { height: 7 }".into())), &covered())).unwrap();
        assert!(v["why"].as_str().unwrap().contains("CounterDecrease"), "{v}");
        assert_eq!(v["available"], false);
        assert!(v.get("d_cum").is_none() && v.get("epochs").is_none(), "{v}");
    }

    /// On V6: the rows, the pair, and the checked attestation; with the
    /// supply rows not covering the tip, `circulating` is the token.
    #[test]
    fn on_v6_the_bridge_document_carries_rows_and_the_attestation() {
        let v: serde_json::Value = serde_json::from_str(&bridge_document(Some(Ok(&view())), &covered())).unwrap();
        assert_eq!((v["available"].clone(), v["d_cum"].clone(), v["e_cum"].clone()), (true.into(), 1000.into(), 40.into()));
        assert_eq!(v["circulating"], 10_000 - 100 - 1_000 + 40);
        assert_eq!(v["epochs"][0]["bridged_out"], 40);
        let lagging = Telemetry::assemble(20, Some(8), Some(75), 0, 3, 1, qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS).with_supply(covered().supply);
        let v: serde_json::Value = serde_json::from_str(&bridge_document(Some(Ok(&view())), &lagging)).unwrap();
        assert_eq!(v["circulating"], crate::json::UNAVAILABLE);
        // Review S2: supply covered, but the bridge rows cover another height.
        let behind = BridgeView { covered_height: 13, ..view() };
        let v: serde_json::Value = serde_json::from_str(&bridge_document(Some(Ok(&behind)), &covered())).unwrap();
        assert_eq!(v["circulating"], crate::json::UNAVAILABLE);
    }

    // -----------------------------------------------------------------------
    // Goldens — the reader half lives in `qumbra-explorer-web` (lab #833)
    // -----------------------------------------------------------------------

    /// Keccak-256 over the golden documents concatenated, in **source**, so a
    /// blind file regeneration cannot make the goldens pass by itself.
    const GOLDEN_DIGEST: &str = "6047c2c16ef2b19450819115192dc69e2a9ee042b4b196286d990443043c0d4b";

    /// Two epochs, so the page's table has more than one row to order.
    fn golden_view() -> BridgeView {
        BridgeView {
            covered_height: 14,
            d_cum: 1_000,
            e_cum: 40,
            rows: vec![
                BridgeRow { epoch: 0, start_height: 0, end_height: 7, bridged_in: 600, bridged_out: 0 },
                BridgeRow { epoch: 1, start_height: 8, end_height: 14, bridged_in: 400, bridged_out: 40 },
            ],
        }
    }

    /// Every state the page renders: the attestation checked, the same rows
    /// with `circulating` refused (supply rows behind the tip), a refusing
    /// ledger, and a chain with no bridge.
    fn golden_cases() -> Vec<(&'static str, String)> {
        let lagging = Telemetry::assemble(20, Some(8), Some(75), 0, 3, 1, qlab_devnet::params_devnet::DEGRADED_MODE_LAG_BLOCKS)
            .with_supply(covered().supply);
        vec![
            ("bridge-v6", bridge_document(Some(Ok(&golden_view())), &covered())),
            ("bridge-circulating-unavailable", bridge_document(Some(Ok(&golden_view())), &lagging)),
            ("bridge-refused", bridge_document(Some(Err("CounterDecrease { height: 7 }".into())), &covered())),
            ("bridge-not-v6", not_v6()),
        ]
    }

    /// 🔴 GOLDEN — the checked-in files ARE the vectors, and
    /// `qumbra-explorer-web/fixtures/` holds the same bytes. Update them only
    /// with an intentional, documented shape change; regenerating is not
    /// enough on its own, since [`golden_digest_locks_the_regenerated_files`]
    /// pins a digest in source.
    #[test]
    fn golden_files_match_the_encoder_byte_for_byte() {
        for (name, produced) in golden_cases() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens").join(name);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("golden {name} missing at {}: {e}", path.display()));
            assert_eq!(
                on_disk.trim_end_matches('\n'),
                produced,
                "golden {name} drifted — see this test's docs before updating the file"
            );
        }
    }

    /// The goldens read back in the front end's direction: real JSON, a
    /// version, `available`; a document that does not apply says why and
    /// carries no figures; `circulating` is a number or the token, never
    /// anything else.
    #[test]
    fn the_goldens_decode_and_say_whether_they_apply() {
        for (name, produced) in golden_cases() {
            let v: serde_json::Value = serde_json::from_str(&produced).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(v["v"], 1, "{name} is versioned");
            if v["available"] == true {
                assert!(v["epochs"].is_array(), "{name} carries its rows");
                let c = &v["circulating"];
                assert!(c.is_u64() || *c == crate::json::UNAVAILABLE, "{name}: circulating is {c}");
            } else {
                assert_eq!(v["available"], false, "{name} states available");
                assert!(v["why"].as_str().is_some_and(|w| !w.is_empty()), "{name} says why");
                assert!(v.get("epochs").is_none(), "{name} carries no figures");
            }
        }
    }

    #[test]
    #[ignore = "writes files; run explicitly when a shape change is intended"]
    fn regenerate_goldens() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("goldens");
        std::fs::create_dir_all(&dir).expect("goldens dir");
        for (name, produced) in golden_cases() {
            std::fs::write(dir.join(name), format!("{produced}\n")).expect("write golden");
            println!("wrote {name}");
        }
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let hex: String = qlab_note::hash::keccak256(all.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        println!("GOLDEN_DIGEST = \"{hex}\"");
    }

    #[test]
    fn golden_digest_locks_the_regenerated_files() {
        let all: String = golden_cases().into_iter().map(|(_, s)| s).collect();
        let hex: String = qlab_note::hash::keccak256(all.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN_DIGEST, "GOLDEN digest — update ONLY with an intentional, documented shape change");
    }
}
