//! The mining loop: search for a nonce whose PoW hash meets the difficulty target.
//!
//! Deliberately trivial — vary `header.nonce`, re-hash via the [`PowEngine`], and
//! stop at the first nonce satisfying [`crate::pow::satisfies_target`]. With the
//! Keccak placeholder and the low sim difficulties in `params_devnet`, a valid
//! nonce is found in a handful of iterations. A real RandomX-class engine would
//! slot in behind the same trait with no change here.

use crate::header::BlockHeader;
use crate::pow::{satisfies_target, PowEngine};

/// Mine `header` in place-ish: try nonces `0..nonce_budget`, returning the header
/// with the first satisfying nonce set, or `None` if the budget is exhausted.
///
/// `header.difficulty` fixes the target; the miner never changes it (difficulty
/// is a consensus input, checked by validation). The returned header differs from
/// the input only in `nonce`.
pub fn mine<P: PowEngine>(pow: &P, mut header: BlockHeader, nonce_budget: u64) -> Option<BlockHeader> {
    for nonce in 0..nonce_budget {
        header.nonce = nonce;
        if satisfies_target(&pow.pow_hash(&header), header.difficulty) {
            return Some(header);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::KeccakPow;

    #[test]
    fn mines_a_valid_block_at_low_difficulty() {
        let pow = KeccakPow;
        let header = BlockHeader::genesis(8, 0);
        let mined = mine(&pow, header, 1_000_000).expect("must mine at difficulty 8");
        assert!(satisfies_target(&pow.pow_hash(&mined), mined.difficulty));
        // Difficulty and structural fields are untouched — only the nonce moved.
        assert_eq!(mined.difficulty, header.difficulty);
        assert_eq!(mined.height, header.height);
        assert_eq!(mined.prev, header.prev);
    }

    #[test]
    fn exhausted_budget_returns_none() {
        let pow = KeccakPow;
        // Astronomically high difficulty ⇒ a tiny nonce budget cannot find a hit.
        let header = BlockHeader::genesis(u64::MAX, 0);
        assert!(mine(&pow, header, 4).is_none());
    }
}
