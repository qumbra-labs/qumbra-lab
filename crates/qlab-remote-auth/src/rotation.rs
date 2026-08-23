//! Candidate private ML-DSA leaf-selection order.
//!
//! Sequential public indices leak an ordinal. Independent random draws can
//! repeat. This research helper instead deterministically shuffles every index
//! with a private per-address seed, so each position is random-looking and no
//! index repeats before exhaustion. Production persistence, restore, and
//! multi-device allocation remain explicit product gates.

use crate::{keccak256, Hash32};

const ORDER_DOMAIN: &[u8] = b"qumbra:remote-auth:mldsa44-order:spike-v1";
pub const MAX_MEASURABLE_DEPTH: u8 = 24;

pub fn selection_order(address_seed: &Hash32, depth: u8) -> Result<Vec<u32>, String> {
    if depth == 0 || depth > MAX_MEASURABLE_DEPTH {
        return Err(format!(
            "ML-DSA rotation depth must be in 1..={MAX_MEASURABLE_DEPTH}"
        ));
    }
    let count = 1usize << depth;
    let mut order: Vec<u32> = (0..count as u32).collect();
    let mut counter = 0u64;
    for upper in (2..=count).rev() {
        let index = draw_below(address_seed, &mut counter, upper as u64) as usize;
        order.swap(upper - 1, index);
    }
    Ok(order)
}

fn draw_below(address_seed: &Hash32, counter: &mut u64, upper: u64) -> u64 {
    debug_assert!(upper > 0);
    // Lemire's multiply-and-reject mapping is uniform over [0, upper) when the
    // input is uniform over all u64 values. Keccak supplies the private stream.
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let block = keccak256(&[ORDER_DOMAIN, address_seed, &counter.to_le_bytes()]);
        *counter = counter
            .checked_add(1)
            .expect("a practical address tree cannot exhaust the u64 stream");
        let random = u64::from_le_bytes(block[..8].try_into().unwrap());
        let product = (random as u128) * (upper as u128);
        if product as u64 >= threshold {
            return (product >> 64) as u64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_order_is_a_non_sequential_permutation_without_replacement() {
        let order = selection_order(&[0x42; 32], 12).unwrap();
        assert_eq!(order.len(), 4_096);
        assert_ne!(order[..16], (0u32..16).collect::<Vec<_>>());

        let mut sorted = order;
        sorted.sort_unstable();
        assert_eq!(sorted, (0u32..4_096).collect::<Vec<_>>());
    }

    #[test]
    fn address_seed_separates_orders_and_invalid_depths_are_refused() {
        assert_ne!(
            selection_order(&[1u8; 32], 8).unwrap(),
            selection_order(&[2u8; 32], 8).unwrap()
        );
        assert!(selection_order(&[0u8; 32], 0).is_err());
        assert!(selection_order(&[0u8; 32], MAX_MEASURABLE_DEPTH + 1).is_err());
    }
}
