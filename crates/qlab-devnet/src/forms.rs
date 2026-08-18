//! Genesis-format keying — the value type of the ONE selection point (lab #470,
//! T2 mint combo stage 0).
//!
//! ## The law this type encodes
//!
//! `main` serves two nets from one tree: **T1** (live, public, genesis format
//! v4) and **T2** (the mint this baton builds, genesis format v5). Every T2
//! consensus format — header layout, body-commitment form, coinbase form, rule
//! schedule — is keyed off **the genesis file's format version**, selected
//! exactly once at genesis load and fanned out from there. Per-call-site
//! version sniffing is a stop-point by the task book; call sites receive this
//! value (or a rules object carrying it) as an argument, the way the `_above`
//! seams already receive their boundary.
//!
//! ## Why the selector is sound against H1
//!
//! H1 (`run.rs`, `release.rs`) says consensus boundaries are unreachable from
//! config/CLI/environment. The genesis format version does not weaken that: it
//! is a field of the genesis file, which is inside the genesis hash — the
//! network identity every node pins as `expected_genesis_hash` and refuses to
//! start without. An operator cannot select forms any more freely than they
//! can select which network they are on, because it is the same choice.
//!
//! ## Stage 0 status
//!
//! This type and its mapping are the whole stage-0 plumbing: no consumer reads
//! it yet, and no behavior changes on a v4 genesis. Consumers arrive per
//! stage — header form (stage 1), coinbase form (stage 2), body form + rule
//! schedule (stage 3), the v5 loader itself (stage 4). The coordinator reviews
//! the keying design before stage 1 begins.

/// The consensus form set a genesis file selects. One value, chosen at genesis
/// load, fanning out to header-form, body-form, coinbase-form and
/// rule-schedule choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisForm {
    /// Genesis format **v4** — the live T1 net (`138e1524…addb`): 98-byte
    /// header (nonce at offset 56), body v2 below/at the name boundary and v3
    /// above it, single-`rkm` coinbase, f64 emission below the emission
    /// boundary with the glibc pins and the height-1377 scar above genesis.
    /// Byte-identical to today's `main` — every existing golden is the lock.
    V4,
    /// Genesis format **v5** — T2 (lab #470): stratum-compatible header
    /// (version byte + u48 height at 32–38, nonce u64 at 39–46), one body
    /// form from height 0 carrying the C3 hygiene batch, payee-list coinbase
    /// with the cap at 1, and exact emission + the name rule native from
    /// height 0 — no boundary, no pins, no scar.
    V5,
}

impl GenesisForm {
    /// Map a genesis file's `format_version` to its form set. `None` for
    /// versions this tree does not serve (v1–v3 are refused-with-a-reason
    /// history; anything above 5 is a later tree's business).
    pub fn from_genesis_format_version(v: u32) -> Option<GenesisForm> {
        match v {
            4 => Some(GenesisForm::V4),
            5 => Some(GenesisForm::V5),
            _ => None,
        }
    }

    /// The genesis-file `format_version` this form set is keyed to.
    pub fn genesis_format_version(self) -> u32 {
        match self {
            GenesisForm::V4 => 4,
            GenesisForm::V5 => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_exactly_v4_and_v5_and_nothing_else() {
        assert_eq!(GenesisForm::from_genesis_format_version(4), Some(GenesisForm::V4));
        assert_eq!(GenesisForm::from_genesis_format_version(5), Some(GenesisForm::V5));
        for v in [0u32, 1, 2, 3, 6, 7, u32::MAX] {
            assert_eq!(GenesisForm::from_genesis_format_version(v), None, "v{v} must not map");
        }
    }

    #[test]
    fn round_trips_through_the_format_version() {
        for form in [GenesisForm::V4, GenesisForm::V5] {
            assert_eq!(
                GenesisForm::from_genesis_format_version(form.genesis_format_version()),
                Some(form)
            );
        }
    }
}
