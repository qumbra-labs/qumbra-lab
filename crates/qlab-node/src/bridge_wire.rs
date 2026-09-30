//! Lab #785 F5-4c-1 — **`GET /v1/supply/bridge`**, the V6 bridge's supply
//! columns: per epoch, the QMB bridged in (`ΔD`, deposits claimed on the L2)
//! and out (`ΔE`, exits materialized as L1 notes), and the tip's cumulative
//! `D_cum` / `E_cum`, from which `circulating = emission − burned − D_cum +
//! E_cum`.
//!
//! **A route of its own, not a telemetry tail** (ruling on issue #785): the
//! telemetry version is the global `RPC_VERSION`, and `Reader::version` is an
//! equality check, so a tail would have broken every deployed wallet against
//! an upgraded T1/V5 node. A pure route addition bumps nothing (the PR #315
//! rule). Only a V6 node serves it; everywhere else it is 404, which readers
//! render as unavailable — never as zero (no bridge is not "nothing bridged").
//!
//! ```text
//! ver u8 = 1 ‖ covered_height u64 ‖ d_cum u64 ‖ e_cum u64 ‖ n u32
//!   ‖ n × (epoch u64 ‖ start_height u64 ‖ end_height u64 ‖ bridged_in u64 ‖ bridged_out u64)
//! ```
//!
//! Little-endian. `covered_height` is the last height the rows cover — a reader
//! compares it with the tip it knows, as the telemetry supply rows' coverage
//! rule does. The decoder is total (the #793 discipline): every read is
//! checked, the row count is capped by the bytes present before anything is
//! allocated, and no decoded integer passes through `as` (issue #795).

/// The payload's own version byte (independent of `RPC_VERSION`).
pub const BRIDGE_WIRE_VERSION: u8 = 1;

/// The route.
pub const BRIDGE_PATH: &str = "/v1/supply/bridge";

const HEADER_LEN: usize = 1 + 8 + 8 + 8 + 4;
const ROW_LEN: usize = 5 * 8;

/// A checked cursor over the payload.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], BridgeWireError> {
        if n > self.0.len() {
            return Err(BridgeWireError::Truncated(what));
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u64(&mut self, what: &'static str) -> Result<u64, BridgeWireError> {
        Ok(u64::from_le_bytes(self.take(8, what)?.try_into().expect("8 bytes")))
    }
}

/// One epoch's bridge movement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BridgeRow {
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    /// `Σ ΔD` over the epoch's bundles.
    pub bridged_in: u64,
    /// `Σ ΔE` over the epoch's bundles.
    pub bridged_out: u64,
}

/// What `/v1/supply/bridge` serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeView {
    pub covered_height: u64,
    pub d_cum: u64,
    pub e_cum: u64,
    pub rows: Vec<BridgeRow>,
}

/// Why a bridge payload was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeWireError {
    /// The leading byte is not [`BRIDGE_WIRE_VERSION`].
    Version(u8),
    /// The input ended inside `what`.
    Truncated(&'static str),
    /// More rows declared than the bytes can hold.
    RowCount(u32),
    /// Bytes after the last row.
    Trailing,
}

impl BridgeView {
    /// The canonical bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = u32::try_from(self.rows.len()).expect("fewer than 2^32 epochs");
        let mut v = Vec::with_capacity(HEADER_LEN + ROW_LEN * self.rows.len());
        v.push(BRIDGE_WIRE_VERSION);
        for x in [self.covered_height, self.d_cum, self.e_cum] {
            v.extend_from_slice(&x.to_le_bytes());
        }
        v.extend_from_slice(&n.to_le_bytes());
        for r in &self.rows {
            for x in [r.epoch, r.start_height, r.end_height, r.bridged_in, r.bridged_out] {
                v.extend_from_slice(&x.to_le_bytes());
            }
        }
        v
    }

    /// Decode, refusing anything but exactly the canonical layout.
    pub fn from_bytes(b: &[u8]) -> Result<Self, BridgeWireError> {
        let mut r = Cursor(b);
        let ver = r.take(1, "version")?[0];
        if ver != BRIDGE_WIRE_VERSION {
            return Err(BridgeWireError::Version(ver));
        }
        let covered_height = r.u64("covered_height")?;
        let d_cum = r.u64("d_cum")?;
        let e_cum = r.u64("e_cum")?;
        let n = u32::from_le_bytes(r.take(4, "row count")?.try_into().expect("4 bytes"));
        let n_rows = usize::try_from(n).map_err(|_| BridgeWireError::RowCount(n))?;
        if n_rows.checked_mul(ROW_LEN).is_none_or(|need| need > r.0.len()) {
            return Err(BridgeWireError::RowCount(n));
        }
        let mut rows = Vec::with_capacity(n_rows);
        for _ in 0..n_rows {
            rows.push(BridgeRow {
                epoch: r.u64("row")?,
                start_height: r.u64("row")?,
                end_height: r.u64("row")?,
                bridged_in: r.u64("row")?,
                bridged_out: r.u64("row")?,
            });
        }
        if !r.0.is_empty() {
            return Err(BridgeWireError::Trailing);
        }
        Ok(BridgeView { covered_height, d_cum, e_cum, rows })
    }

    /// `circulating = emission − burned + E_cum − D_cum`, checked; `None` on
    /// any overflow or underflow (a reader shows it as unavailable). `E_cum`
    /// is added before `D_cum` is subtracted: both are cumulative, so after
    /// deposit → exit → deposit `D_cum` alone can exceed what is left of
    /// emission on a healthy bridge (review S1).
    pub fn circulating(&self, emission: u64, burned: u64) -> Option<u64> {
        emission.checked_sub(burned)?.checked_add(self.e_cum)?.checked_sub(self.d_cum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> BridgeView {
        BridgeView {
            covered_height: 2400,
            d_cum: 1_000,
            e_cum: 40,
            rows: vec![
                BridgeRow { epoch: 0, start_height: 0, end_height: 1151, bridged_in: 600, bridged_out: 0 },
                BridgeRow { epoch: 1, start_height: 1152, end_height: 2303, bridged_in: 400, bridged_out: 40 },
                BridgeRow { epoch: 2, start_height: 2304, end_height: 2400, bridged_in: 0, bridged_out: 0 },
            ],
        }
    }

    #[test]
    fn the_bridge_wire_round_trips_at_its_exact_length() {
        let v = view();
        let b = v.to_bytes();
        assert_eq!(b.len(), HEADER_LEN + 3 * ROW_LEN);
        assert_eq!(b[0], BRIDGE_WIRE_VERSION);
        assert_eq!(BridgeView::from_bytes(&b), Ok(v));
        let empty = BridgeView { covered_height: 0, d_cum: 0, e_cum: 0, rows: vec![] };
        assert_eq!(BridgeView::from_bytes(&empty.to_bytes()), Ok(empty));
    }

    /// Every refusal, named — the #793 class included: a row count far past
    /// the bytes refuses before any allocation.
    #[test]
    fn the_bridge_wire_refuses_every_malformation() {
        let b = view().to_bytes();
        assert_eq!(BridgeView::from_bytes(&[]), Err(BridgeWireError::Truncated("version")));
        let mut v2 = b.clone();
        v2[0] = 2;
        assert_eq!(BridgeView::from_bytes(&v2), Err(BridgeWireError::Version(2)));
        assert_eq!(BridgeView::from_bytes(&b[..HEADER_LEN - 1]), Err(BridgeWireError::Truncated("row count")));
        assert_eq!(BridgeView::from_bytes(&b[..b.len() - 1]), Err(BridgeWireError::RowCount(3)));
        let mut huge = b.clone();
        huge[HEADER_LEN - 4..HEADER_LEN].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(BridgeView::from_bytes(&huge), Err(BridgeWireError::RowCount(u32::MAX)));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(BridgeView::from_bytes(&long), Err(BridgeWireError::Trailing));
    }

    /// The attestation is checked arithmetic: an underflow is `None`, never a
    /// wrapped figure.
    #[test]
    fn circulating_is_checked() {
        let v = view();
        assert_eq!(v.circulating(10_000, 100), Some(10_000 - 100 - 1_000 + 40));
        assert_eq!(v.circulating(500, 0), None, "D_cum above emission");
        assert_eq!(v.circulating(100, 200), None, "burned above emission");
        let big = BridgeView { e_cum: u64::MAX, ..view() };
        assert_eq!(big.circulating(u64::MAX, 0), None, "overflow");
        // Review S1: deposit 100, exit 100, deposit 100 on emission 100 — D_cum
        // 200 exceeds emission, and the true figure is 0, not unavailable.
        let cycled = BridgeView { d_cum: 200, e_cum: 100, ..view() };
        assert_eq!(cycled.circulating(100, 0), Some(0));
    }
}
