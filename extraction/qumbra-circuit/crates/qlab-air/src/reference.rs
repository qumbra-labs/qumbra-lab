//! Reference Keccak-f[1600], bit-for-bit the FIPS 202 permutation.
//!
//! Used by the narrow AIR's tests as the semantic authority: the trace's
//! materialized states must advance by exactly these rounds. The reference
//! itself is cross-checked against the published `p3-keccak` permutation
//! in tests, so a transcription error here cannot silently self-validate.
//!
//! State convention: flat `[u64; 25]`, lane (x, y) at index `x + 5*y`,
//! bit z of a lane at `(lane >> z) & 1` — the standard convention shared
//! by `p3-keccak` / tiny-keccak.

/// Rho rotation offsets, lane (x, y) at index `x + 5*y`.
pub const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, // y = 0
    36, 44, 6, 55, 20, // y = 1
    3, 10, 43, 25, 39, // y = 2
    41, 45, 15, 21, 8, // y = 3
    18, 2, 61, 56, 14, // y = 4
];

/// Iota round constants for the 24 rounds of Keccak-f[1600].
pub const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// One Keccak round: theta, rho, pi, chi, iota with round constant `rc`.
pub fn round(a: &[u64; 25], rc: u64) -> [u64; 25] {
    // Theta.
    let mut c = [0u64; 5];
    for (x, cx) in c.iter_mut().enumerate() {
        *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    let mut d = [0u64; 5];
    for (x, dx) in d.iter_mut().enumerate() {
        *dx = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    let mut at = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            at[x + 5 * y] = a[x + 5 * y] ^ d[x];
        }
    }
    // Rho + pi: B[y, (2x + 3y) % 5] = rotl(A[x, y], RHO[x, y]).
    let mut b = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let l = x + 5 * y;
            b[y + 5 * ((2 * x + 3 * y) % 5)] = at[l].rotate_left(RHO[l]);
        }
    }
    // Chi.
    let mut out = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            out[x + 5 * y] =
                b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
    }
    // Iota.
    out[0] ^= rc;
    out
}

/// Merkle node hash as the narrow AIR instantiates it: Keccak-256 with
/// the ORIGINAL pad10*1 (Ethereum-style), single 512-bit block of
/// left(256) || right(256); digest = lanes 0..4 of the permuted state.
/// Returns the full output state (the AIR chains states, not digests).
pub fn merkle_node_state(left: &[u64; 4], right: &[u64; 4]) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(left);
    st[4..8].copy_from_slice(right);
    st[8] = 1; // pad10*1: bit 512
    st[16] = 1 << 63; // pad10*1: bit 1087
    keccak_f(&st)
}

/// Full Keccak-f[1600]: 24 rounds.
pub fn keccak_f(a: &[u64; 25]) -> [u64; 25] {
    let mut s = *a;
    for rc in RC {
        s = round(&s, rc);
    }
    s
}

#[cfg(test)]
mod tests {
    use p3_symmetric::Permutation;

    use super::*;

    /// The reference must agree with the published p3-keccak permutation
    /// on a batch of pseudo-random states (and the zero state).
    #[test]
    fn reference_matches_p3_keccak() {
        let mut state = [0u64; 25];
        for trial in 0..50u64 {
            let expected = {
                let mut s = state;
                p3_keccak::KeccakF.permute_mut(&mut s);
                s
            };
            assert_eq!(keccak_f(&state), expected, "trial {trial}");
            // Derive the next input from the output, decorated so inputs
            // aren't pure fixed-point chains.
            state = expected;
            state[0] ^= 0x9e3779b97f4a7c15u64.wrapping_mul(trial + 1);
        }
    }
}
