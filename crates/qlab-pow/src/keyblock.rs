//! The RandomX **key-block rotation** schedule.
//!
//! RandomX is keyed: the VM's program and dataset derive from a *key* (the
//! ~256 MiB cache is a pure function of it). Rehashing that key every block would
//! be ruinous, so RandomX chains rotate the key only on a fixed cadence and seed
//! it from a *past* block's hash — the "key block". Between rotations, every
//! header hashes under one key, which is exactly what [`crate::RandomXHasher`]'s
//! memoization is built for.
//!
//! We follow Monero's shape (`rx_seedheight`): the key for a block at `height` is
//! seeded by the hash of the block at [`key_seed_height`], which is the start of
//! the current **epoch** of `epoch` blocks, offset back by a `lag` so that the
//! seed block is already deeply buried (and thus agreed upon) before it takes
//! effect. This module owns only the *height* schedule (pure arithmetic); mapping
//! a seed height to the actual block hash needs the chain and lives in the devnet.
//!
//! ## Parameter status
//!
//! `epoch` and `lag` are **testnet-tunable and NOT frozen** (protocol-spec §10 —
//! full-M8 freezes them at v1.1). The defaults quote Monero for provenance
//! ([`KeyBlockSchedule::MONERO_EPOCH_BLOCKS`] = 2048,
//! [`KeyBlockSchedule::MONERO_EPOCH_LAG`] = 64); they are prototype choices, not
//! Qumbra proposals.

/// The height of the block whose hash seeds the RandomX key for a block at
/// `height`, given an `epoch` length and a `lag`.
///
/// - During the initial `epoch + lag` blocks there is no buried seed yet, so the
///   schedule pins **height 0** (the genesis block's hash is the bootstrap key).
/// - Afterwards the seed height is the largest multiple of `epoch` at or below
///   `height - lag - 1` — i.e. the start of the epoch that ended at least `lag`
///   blocks before `height`.
///
/// `epoch == 0` disables rotation (always returns 0 — one fixed key forever),
/// which is a convenience for tests, not a real operating mode.
///
/// For a power-of-two `epoch` this is bit-for-bit Monero's
/// `(height - lag - 1) & ~(epoch - 1)`; the division form here also handles
/// non-power-of-two epochs.
pub fn key_seed_height(height: u64, epoch: u64, lag: u64) -> u64 {
    if epoch == 0 || height <= epoch + lag {
        return 0;
    }
    ((height - lag - 1) / epoch) * epoch
}

/// A RandomX key-block cadence: `epoch` blocks per key, seed buried by `lag`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyBlockSchedule {
    /// Blocks per key epoch.
    pub epoch: u64,
    /// How many blocks the seed block is buried behind the epoch boundary before
    /// its key takes effect.
    pub lag: u64,
}

impl KeyBlockSchedule {
    /// Monero's RandomX seed-epoch length (`RANDOMX_SEEDHASH_EPOCH_BLOCKS`).
    pub const MONERO_EPOCH_BLOCKS: u64 = 2048;
    /// Monero's RandomX seed lag (`RANDOMX_SEEDHASH_EPOCH_LAG`).
    pub const MONERO_EPOCH_LAG: u64 = 64;

    /// Construct a schedule.
    pub const fn new(epoch: u64, lag: u64) -> Self {
        Self { epoch, lag }
    }

    /// The seed (key-block) height for a block at `height` under this schedule.
    pub fn seed_height(&self, height: u64) -> u64 {
        key_seed_height(height, self.epoch, self.lag)
    }

    /// Whether the seed height *changes* going from `height - 1` to `height`
    /// (i.e. `height` is the first block of a new RandomX key). Height 0 is not a
    /// rotation (it is the bootstrap).
    pub fn is_rotation_height(&self, height: u64) -> bool {
        height > 0 && self.seed_height(height) != self.seed_height(height - 1)
    }
}

impl Default for KeyBlockSchedule {
    /// Monero-shape defaults (2048 / 64). Testnet-tunable, NOT frozen.
    fn default() -> Self {
        Self::new(Self::MONERO_EPOCH_BLOCKS, Self::MONERO_EPOCH_LAG)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const E: u64 = 2048; // epoch
    const L: u64 = 64; // lag

    #[test]
    fn warmup_pins_genesis_seed_until_epoch_plus_lag() {
        // Every block up to and including epoch+lag has no buried seed ⇒ height 0.
        for h in 0..=(E + L) {
            assert_eq!(key_seed_height(h, E, L), 0, "height {h} must seed from genesis");
        }
    }

    #[test]
    fn first_rotation_is_one_block_after_epoch_plus_lag() {
        // The first non-genesis seed appears at epoch+lag+1 and points at `epoch`.
        assert_eq!(key_seed_height(E + L, E, L), 0);
        assert_eq!(key_seed_height(E + L + 1, E, L), E);
    }

    #[test]
    fn seed_height_is_always_a_multiple_of_epoch() {
        for h in [0, 1, E, E + L + 1, 3 * E, 5 * E + L + 7, 100 * E + 3] {
            assert_eq!(key_seed_height(h, E, L) % E, 0, "seed for {h} not on an epoch boundary");
        }
    }

    #[test]
    fn seed_height_is_monotone_non_decreasing_in_height() {
        let mut prev = 0;
        for h in 0..(6 * E) {
            let s = key_seed_height(h, E, L);
            assert!(s >= prev, "seed height went backwards at {h}: {s} < {prev}");
            assert!(s <= h, "seed height {s} cannot exceed the block height {h}");
            prev = s;
        }
    }

    #[test]
    fn lag_delays_the_rotation_by_exactly_lag_blocks() {
        // The epoch boundary at 2*E would rotate at height 2*E without lag; with a
        // lag of L the new seed (=2*E... no: seed of the epoch STARTING at E) takes
        // effect L+1 blocks after the boundary the seed epoch closed.
        // Concretely: seed jumps to `E` at height E+L+1, and to `2E` at height 2E+L+1.
        assert_eq!(key_seed_height(2 * E + L, E, L), E);
        assert_eq!(key_seed_height(2 * E + L + 1, E, L), 2 * E);
    }

    #[test]
    fn within_an_epoch_the_seed_is_constant() {
        // Across a full epoch window [2E+L+1, 3E+L] the seed is fixed at 2E.
        for h in (2 * E + L + 1)..=(3 * E + L) {
            assert_eq!(key_seed_height(h, E, L), 2 * E, "seed not constant within epoch at {h}");
        }
        // The very next block flips to 3E.
        assert_eq!(key_seed_height(3 * E + L + 1, E, L), 3 * E);
    }

    #[test]
    fn zero_epoch_disables_rotation() {
        for h in [0, 1, 10_000, u64::MAX] {
            assert_eq!(key_seed_height(h, 0, L), 0);
        }
    }

    #[test]
    fn matches_monero_bitmask_form_for_power_of_two_epoch() {
        // For a power-of-two epoch, our division form must equal Monero's mask.
        let monero = |h: u64| -> u64 {
            if h <= E + L { 0 } else { (h - L - 1) & !(E - 1) }
        };
        for h in 0..(8 * E) {
            assert_eq!(key_seed_height(h, E, L), monero(h), "mismatch vs Monero mask at {h}");
        }
    }

    #[test]
    fn schedule_struct_wraps_the_free_fn_and_defaults_to_monero() {
        let s = KeyBlockSchedule::default();
        assert_eq!(s.epoch, 2048);
        assert_eq!(s.lag, 64);
        for h in [0, E + L, E + L + 1, 3 * E + 5] {
            assert_eq!(s.seed_height(h), key_seed_height(h, E, L));
        }
    }

    #[test]
    fn is_rotation_height_flags_only_the_boundaries() {
        let s = KeyBlockSchedule::new(E, L);
        // The two known flip points are rotations…
        assert!(s.is_rotation_height(E + L + 1));
        assert!(s.is_rotation_height(2 * E + L + 1));
        // …neighbours are not, and neither is genesis.
        assert!(!s.is_rotation_height(0));
        assert!(!s.is_rotation_height(E + L));
        assert!(!s.is_rotation_height(E + L + 2));
    }

    #[test]
    fn non_power_of_two_epoch_still_lands_on_multiples() {
        let e = 1000u64;
        let l = 30u64;
        assert_eq!(key_seed_height(e + l, e, l), 0);
        assert_eq!(key_seed_height(e + l + 1, e, l), e);
        assert_eq!(key_seed_height(3 * e + l + 1, e, l), 3 * e);
        for h in [e + l + 1, 2 * e + l, 7 * e + 3] {
            assert_eq!(key_seed_height(h, e, l) % e, 0);
        }
    }
}
