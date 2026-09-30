//! The wrapper's hash-level primitives: digests, the node and leaf Keccak-f
//! states, F3's surface-digest (SD) chain, and F4's wrapper-state types and
//! domain-tagged states (claim-fee seeds, supply leaf, exit chain). Moved from
//! qlab-bench's `f3::native`, `f3::leaf` and `f4::native` (lab #785, F5-1),
//! unchanged; the prover-only trace helpers went back to qlab-bench in F5-4a
//! (review Y2).
use std::borrow::Borrow;

use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS};
use qlab_air::narrow::MERKLE_DEPTH;
use qlab_air::reference::{keccak_f, merkle_node_state};

// f3/native
pub type Digest = [u64; 4];

/// The nullifier tree's depth (ruling Q2): the commitment tree's.
pub const N_DEPTH: usize = MERKLE_DEPTH;

/// An unused slot (both append trees): the zero digest, the node's convention.
pub const EMPTY: Digest = [0; 4];

/// Both append trees' leaf-count limit: indices stay below 2^30 < p.
pub const INDEX_CAP: u64 = 1 << 30;

/// The nullifier-tree leaf `H(lo ‖ hi)`: one Keccak-f block, domain marker at
/// lane 8 bit 4 — distinct from the node hash's pad (bit 0) and the freeze
/// leaf's marker (bit 3), so no nullifier leaf is ever a node or a freeze leaf.
pub fn nf_leaf_hash(lo: &Digest, hi: &Digest) -> Digest {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(lo);
    st[4..8].copy_from_slice(hi);
    st[8] = 1 << 4;
    st[16] = 1 << 63;
    keccak_f(&st)[..4].try_into().expect("four lanes")
}

/// The consensus node hash (for F4's supply tree).
pub fn node_pub(l: &Digest, r: &Digest) -> Digest {
    node(l, r)
}

pub fn node(l: &Digest, r: &Digest) -> Digest {
    merkle_node_state(l, r)[..4].try_into().expect("four lanes")
}

/// The chain's domain (ruling (a)): capacity lanes 17–18 of every block.
pub const SD_DOMAIN: &[u8; 16] = b"qumbra:l2-sd:v1\0";

/// Message words per block: rate lanes 4..17, two little-endian `u32` words
/// per lane (lanes 0..4 carry the chaining value).
pub const SD_BLOCK_WORDS: usize = 26;

/// The first message lane.
pub const SD_LANE_MSG: usize = 4;

/// Capacity lanes: the domain (17, 18), the block index (19), the final flag (20).
pub const SD_LANE_DOMAIN: usize = 17;

pub const SD_LANE_INDEX: usize = 19;

pub const SD_LANE_FINAL: usize = 20;

/// The domain as the two capacity lanes it occupies.
pub fn sd_domain_lanes() -> [u64; 2] {
    [
        u64::from_le_bytes(SD_DOMAIN[..8].try_into().expect("8 bytes")),
        u64::from_le_bytes(SD_DOMAIN[8..].try_into().expect("8 bytes")),
    ]
}

/// qlab-bench's `f3::native::sd_words` for any slot tag byte (F4's claim slot is `0x04`).
pub fn sd_words_byte(tag: u8, pvs: &[u32]) -> Vec<u32> {
    let mut w = vec![u32::from(tag), pvs.len() as u32];
    w.extend_from_slice(pvs);
    w
}

/// qlab-bench's `f3::native::sd_chain` for any slot tag byte — the one construction F4 extends.
pub fn sd_chain_byte(prev: &Digest, tag: u8, pvs: &[u32]) -> (Vec<[u64; 25]>, Digest) {
    let words = sd_words_byte(tag, pvs);
    let n = words.len().div_ceil(SD_BLOCK_WORDS);
    let dom = sd_domain_lanes();
    let mut h = *prev;
    let mut blocks = Vec::with_capacity(n);
    for b in 0..n {
        let mut st = [0u64; 25];
        st[..4].copy_from_slice(&h);
        for w in 0..SD_BLOCK_WORDS {
            let v = u64::from(words.get(SD_BLOCK_WORDS * b + w).copied().unwrap_or(0));
            st[SD_LANE_MSG + w / 2] |= v << (32 * (w % 2));
        }
        st[SD_LANE_DOMAIN] = dom[0];
        st[SD_LANE_DOMAIN + 1] = dom[1];
        st[SD_LANE_INDEX] = b as u64;
        st[SD_LANE_FINAL] = u64::from(b + 1 == n);
        blocks.push(st);
        h = keccak_f(&st)[..4].try_into().expect("four lanes");
    }
    (blocks, h)
}

/// Permutations one step costs: its blocks.
pub const fn sd_perms(pv_len: usize) -> usize {
    (2 + pv_len).div_ceil(SD_BLOCK_WORDS)
}

/// The running state a leaf threads: every root, both next indices, `SD`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Roots {
    pub n: Digest,
    pub n_next: u64,
    pub c: Digest,
    pub c_next: u64,
    pub r: Digest,
    pub sd: Digest,
}

// f3/leaf
/// Keccak lane column indices (standard lane = x + 5y).
#[derive(Clone)]
pub struct KeccakIdx {
    pub step0: usize,
    pub fin: usize,
    pub pre: [[usize; 4]; 25],
    pub out: [[usize; 4]; 25],
}

pub fn keccak_idx() -> KeccakIdx {
    let idx: Vec<usize> = (0..NUM_KECCAK_COLS).collect();
    let map: &KeccakCols<usize> = idx[..].borrow();
    KeccakIdx {
        step0: map.step_flags[0],
        fin: map.step_flags[NUM_ROUNDS - 1],
        pre: core::array::from_fn(|lane| map.preimage[lane / 5][lane % 5]),
        out: core::array::from_fn(|lane| core::array::from_fn(|l| map.a_prime_prime_prime(lane / 5, lane % 5, l))),
    }
}

pub fn out4(st: &[u64; 25]) -> Digest {
    keccak_f(st)[..4].try_into().expect("four lanes")
}

/// A PV digest, chunk by chunk (masked: the plan never validates; the AIR does).
pub fn pv_digest(pvs: &[u32], off: usize) -> Digest {
    core::array::from_fn(|l| (0..4).map(|j| (u64::from(pvs.get(off + 4 * l + j).copied().unwrap_or(0)) & 0xffff) << (16 * j)).sum())
}

// f4/native
/// A deposit claim's slot tag (SD's word 0).
pub const CLAIM_TAG: u8 = 0x04;

/// L1 roots absorbed per wrapper (ruling Q8: a devnet placeholder).
pub const M_ABS: usize = 4;

/// A slot's kind: an L2 transaction shape or a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WTag {
    S,
    P,
    R,
    C,
}

impl WTag {
    pub const ALL: [WTag; 4] = [WTag::S, WTag::P, WTag::R, WTag::C];
    /// SD's word 0. The three shape bytes are the L2 shape tags' wire bytes
    /// (qlab-devnet's `L2ShapeTag::byte`), written out here so this crate has
    /// no qlab-devnet edge (lab #785 review Y1; the precedent is qlab-devnet
    /// keeping its own shape tag, lab #706 P7). qlab-bench pins the two
    /// mappings equal byte for byte.
    pub fn byte(self) -> u8 {
        match self {
            WTag::S => 0x01,
            WTag::P => 0x02,
            WTag::R => 0x03,
            WTag::C => CLAIM_TAG,
        }
    }
    pub fn pv_len(self) -> usize {
        match self {
            WTag::S => qlab_air::l2::PV_LEN,
            WTag::P => qlab_air::l2p::PV_LEN,
            WTag::R => qlab_air::l2r::PV_LEN,
            WTag::C => qlab_air::claim::PV_LEN,
        }
    }
}

/// The running state a wrapper leaf threads: F3's six plus `K` (the claim
/// nullifiers, `cnf_root`), `AA` (the L1-anchor accumulator), `CH` (the
/// C-root history), the supply tree's root and `D_cum`/`E_cum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WRoots {
    pub f3: Roots,
    pub k: Digest,
    pub k_next: u64,
    pub aa: Digest,
    pub aa_next: u64,
    pub ch: Digest,
    pub ch_next: u64,
    pub sup: Digest,
    pub d_cum: u64,
    pub e_cum: u64,
}

/// The fee note's `ρ` and `rseed`: one domain-tagged Keccak-f each over
/// `prev` — `prev` in lanes 0..4, the kind in lane 4 (1 = ρ, 2 = rseed),
/// the domain `"qumbra:l2-claimfee:v1"` in capacity lanes 21..24, which no
/// node, leaf, registry or SD block sets.
pub fn fee_seed_state(prev: &Digest, kind: u64) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(prev);
    st[4] = kind;
    st[8] = 1;
    st[16] = 1 << 63;
    let dom = fee_domain_lanes();
    st[21..24].copy_from_slice(&dom);
    st
}

/// `"qumbra:l2-claimfee:v1"` as three little-endian lanes (zero-padded).
pub fn fee_domain_lanes() -> [u64; 3] {
    let mut b = [0u8; 24];
    b[..21].copy_from_slice(b"qumbra:l2-claimfee:v1");
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes")))
}

pub fn fee_rho(prev: &Digest) -> Digest {
    keccak_f(&fee_seed_state(prev, 1))[..4].try_into().expect("four lanes")
}

pub fn fee_rseed(prev: &Digest) -> Digest {
    keccak_f(&fee_seed_state(prev, 2))[..4].try_into().expect("four lanes")
}

/// The supply tree's depth — asset ids < 2^16 (a devnet placeholder).
pub const SUPPLY_DEPTH: usize = qlab_air::l2::REGISTRY_DEPTH;

pub fn domain3(s: &[u8]) -> [u64; 3] {
    let mut b = [0u8; 24];
    b[..s.len()].copy_from_slice(s);
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes")))
}

/// `"qumbra:l2-supply:v1"` in capacity lanes 21..24.
pub fn supply_domain_lanes() -> [u64; 3] {
    domain3(b"qumbra:l2-supply:v1")
}

/// `"qumbra:l2-exits:v1"` in capacity lanes 21..24.
pub fn exit_domain_lanes() -> [u64; 3] {
    domain3(b"qumbra:l2-exits:v1")
}

/// A supply leaf `H(asset ‖ outstanding)`: lanes 0/1, the node pad (lanes
/// 8, 16), the domain in capacity lanes 21..24.
pub fn supply_leaf_state(asset: u64, out: u64) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[0] = asset;
    st[1] = out;
    st[8] = 1;
    st[16] = 1 << 63;
    st[21..24].copy_from_slice(&supply_domain_lanes());
    st
}

pub fn h4(st: &[u64; 25]) -> Digest {
    keccak_f(st)[..4].try_into().expect("four lanes")
}

/// One exit-chain step `H(prev ‖ rkm ‖ v)`: lanes 0..4, 4..8, 8; pad lanes
/// 9, 16; the domain in capacity lanes 21..24.
pub fn exit_state(prev: &Digest, rkm: &Digest, v: u64) -> [u64; 25] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(prev);
    st[4..8].copy_from_slice(rkm);
    st[8] = v;
    st[9] = 1;
    st[16] = 1 << 63;
    st[21..24].copy_from_slice(&exit_domain_lanes());
    st
}
