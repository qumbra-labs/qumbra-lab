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
}
