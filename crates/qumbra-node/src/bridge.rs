//! Lab #785 F5-4c-1 — the **bridge supply ledger** a V6 node serves on
//! `/v1/supply/bridge` ([`qlab_node::bridge_wire`]): per epoch, the QMB bridged
//! in (`ΔD`) and out (`ΔE`), from the applied main chain.
//!
//! Each bundle-carrying block's cumulative counters come from the bundle's
//! **prefix alone** ([`qlab_wrapper::codec::stated_surface_prefix`] — kilobytes,
//! no proof decoded; the 4c ruling's Q1), and a row's movement is the
//! difference of consecutive stated counters. Every bundle on the applied
//! chain was folded, and the fold refuses a counter moving backwards, so a
//! decrease here is a broken invariant — named ([`BridgeError::CounterDecrease`]),
//! never absorbed; so is an overflow.
//!
//! The ledger is contiguous from genesis and knows the hash it last absorbed,
//! so a reorg below it is detected ([`BridgeLedger::is_in_sync_with`]) and
//! answered with a rebuild — the supply ledger's discipline (lab #299 §4).
use qlab_devnet::header::Hash32;
use qlab_node::bridge_wire::{BridgeRow, BridgeView};

/// Why the bridge ledger refused a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    /// Not the next height, or not a child of the last absorbed block.
    NotContiguous { height: u64 },
    /// The bundle's prefix does not decode.
    Undecodable { height: u64, why: String },
    /// A W word past 16 bits: the bundle states no surface.
    NoStatedSurface { height: u64 },
    /// `D_cum` or `E_cum` below the previous bundle's.
    CounterDecrease { height: u64 },
    /// A row sum overflowed.
    Overflow { height: u64 },
}

/// The bridge's per-epoch rows over the applied main chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeLedger {
    epoch_length: u64,
    next_height: u64,
    head: Option<Hash32>,
    d_cum: u64,
    e_cum: u64,
    rows: Vec<BridgeRow>,
}

impl BridgeLedger {
    /// An empty ledger; the first push is genesis (height 0).
    pub fn new(epoch_length: u64) -> Self {
        assert!(epoch_length > 0, "an epoch has blocks");
        BridgeLedger { epoch_length, next_height: 0, head: None, d_cum: 0, e_cum: 0, rows: Vec::new() }
    }

    /// Absorb the next main-chain block: its height, identity, parent and
    /// bundle bytes (empty when it carries none).
    pub fn push(&mut self, height: u64, hash: Hash32, prev: Hash32, bundle: &[u8]) -> Result<(), BridgeError> {
        if height != self.next_height || (height > 0 && self.head != Some(prev)) {
            return Err(BridgeError::NotContiguous { height });
        }
        // Compute everything first; commit only once nothing can fail, so a
        // refusal leaves the ledger exactly as it was.
        let (cum, din, dout) = if bundle.is_empty() {
            ((self.d_cum, self.e_cum), 0, 0)
        } else {
            let stated = qlab_wrapper::codec::stated_surface_prefix(bundle)
                .map_err(|e| BridgeError::Undecodable { height, why: format!("{e:?}") })?
                .ok_or(BridgeError::NoStatedSurface { height })?;
            let din = stated.out.d_cum.checked_sub(self.d_cum).ok_or(BridgeError::CounterDecrease { height })?;
            let dout = stated.out.e_cum.checked_sub(self.e_cum).ok_or(BridgeError::CounterDecrease { height })?;
            ((stated.out.d_cum, stated.out.e_cum), din, dout)
        };
        let epoch = height / self.epoch_length;
        let current = self.rows.last().filter(|r| r.epoch == epoch).copied();
        let base = current.unwrap_or(BridgeRow { epoch, start_height: height, end_height: height, bridged_in: 0, bridged_out: 0 });
        let row = BridgeRow {
            end_height: height,
            bridged_in: base.bridged_in.checked_add(din).ok_or(BridgeError::Overflow { height })?,
            bridged_out: base.bridged_out.checked_add(dout).ok_or(BridgeError::Overflow { height })?,
            ..base
        };
        if current.is_some() {
            *self.rows.last_mut().expect("current is the last row") = row;
        } else {
            self.rows.push(row);
        }
        (self.d_cum, self.e_cum) = cum;
        self.next_height = height + 1;
        self.head = Some(hash);
        Ok(())
    }

    /// The next height this ledger expects.
    pub fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Whether the ledger's last absorbed block is still `main_chain`'s block
    /// at that height (a reorg below the ledger answers `false`).
    pub fn is_in_sync_with(&self, main_chain: &[Hash32]) -> bool {
        match self.next_height.checked_sub(1) {
            None => true,
            Some(last) => usize::try_from(last).ok().and_then(|i| main_chain.get(i)).copied() == self.head,
        }
    }

    /// What `/v1/supply/bridge` serves.
    pub fn view(&self) -> BridgeView {
        BridgeView {
            covered_height: self.next_height.saturating_sub(1),
            d_cum: self.d_cum,
            e_cum: self.e_cum,
            rows: self.rows.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wrapper::wleaf::{PV_D, PV_E, PV_SIDE, W_PV_LEN};

    /// A bundle prefix stating out-side counters `(d, e)` (16-bit chunks);
    /// the tail after the prefix is irrelevant to the ledger.
    fn bundle(d: u64, e: u64) -> Vec<u8> {
        let mut w = vec![0u32; W_PV_LEN];
        for j in 0..4 {
            w[PV_SIDE + PV_D + j] = ((d >> (16 * j)) & 0xffff) as u32;
            w[PV_SIDE + PV_E + j] = ((e >> (16 * j)) & 0xffff) as u32;
        }
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes());
        w.iter().for_each(|x| b.extend_from_slice(&x.to_le_bytes()));
        b.extend_from_slice(&[0xee; 16]);
        b
    }

    fn h(n: u64) -> Hash32 {
        let mut x = [0u8; 32];
        x[..8].copy_from_slice(&n.to_le_bytes());
        x
    }

    /// Three epochs of length 4: bundles at 2 (D 100), 5 (D 150, E 30) and 9
    /// (D 150, E 40); rows are the differences, per epoch; the cumulative pair
    /// is the last bundle's.
    #[test]
    fn rows_are_differences_of_consecutive_stated_counters() {
        let mut l = BridgeLedger::new(4);
        for n in 0..=10u64 {
            let b = match n {
                2 => bundle(100, 0),
                5 => bundle(150, 30),
                9 => bundle(150, 40),
                _ => vec![],
            };
            l.push(n, h(n), if n == 0 { [0; 32] } else { h(n - 1) }, &b).unwrap();
        }
        let v = l.view();
        assert_eq!((v.covered_height, v.d_cum, v.e_cum), (10, 150, 40));
        let rows: Vec<_> = v.rows.iter().map(|r| (r.epoch, r.start_height, r.end_height, r.bridged_in, r.bridged_out)).collect();
        assert_eq!(rows, vec![(0, 0, 3, 100, 0), (1, 4, 7, 50, 30), (2, 8, 10, 0, 10)]);
        assert!(l.is_in_sync_with(&(0..=10).map(h).collect::<Vec<_>>()));
        assert!(!l.is_in_sync_with(&(0..=9).map(h).chain([[9; 32]]).collect::<Vec<_>>()), "a reorged tip");
    }

    /// Every refusal named: a gap, a wrong parent, a prefix that does not
    /// decode, a wide word, and a counter moving backwards.
    #[test]
    fn the_bridge_ledger_refuses_by_name() {
        let mut l = BridgeLedger::new(4);
        l.push(0, h(0), [0; 32], &[]).unwrap();
        assert_eq!(l.push(2, h(2), h(1), &[]), Err(BridgeError::NotContiguous { height: 2 }));
        assert_eq!(l.push(1, h(1), [7; 32], &[]), Err(BridgeError::NotContiguous { height: 1 }));
        assert!(matches!(l.push(1, h(1), h(0), &[1, 2, 3]), Err(BridgeError::Undecodable { height: 1, .. })));
        let mut wide = bundle(5, 0);
        wide[12..16].copy_from_slice(&(1u32 << 16).to_le_bytes());
        assert_eq!(l.push(1, h(1), h(0), &wide), Err(BridgeError::NoStatedSurface { height: 1 }));
        l.push(1, h(1), h(0), &bundle(100, 10)).unwrap();
        assert_eq!(l.push(2, h(2), h(1), &bundle(90, 10)), Err(BridgeError::CounterDecrease { height: 2 }));
        assert_eq!(l.push(2, h(2), h(1), &bundle(100, 5)), Err(BridgeError::CounterDecrease { height: 2 }));
        // A refusal leaves the ledger as it was: the next push still extends it.
        let before = l.clone();
        assert!(l.push(2, h(2), h(1), &bundle(90, 10)).is_err());
        assert_eq!(l, before, "compute first, commit last");
        l.push(2, h(2), h(1), &bundle(120, 10)).unwrap();
        assert_eq!((l.view().d_cum, l.view().rows[0].bridged_in), (120, 120));
    }
}
