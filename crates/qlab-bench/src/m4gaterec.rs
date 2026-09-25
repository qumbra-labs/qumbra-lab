//! M4 step 0b(ii) increment 4, stage 1: the verification RECORDER.
//!
//! Everything the gate rectangle proves is driven by one real M3 consensus
//! proof. This module obtains that proof deterministically (m4census's
//! instance), then extracts the complete verification schedule:
//!
//!   - every keccak-f permutation the verifier performs (leaf-sponge
//!     absorptions, Merkle 2-to-1 compressions, challenger blocks), with
//!     full input/output states and semantic tags;
//!   - the challenger byte stream, segmented and labeled (which bytes are
//!     caps, inner public values, zeta openings, final-poly coefficients,
//!     PoW witnesses, ...), with flush/block boundaries;
//!   - every Fiat-Shamir draw (field draws with the mask-31 + reject
//!     convention, `sample_bits` draws with the mask-only convention),
//!     tagged with its purpose and its consumer block;
//!   - per-query data: the sampled index, opened rows, Merkle paths,
//!     fold arities/siblings/betas, and the cap digests.
//!
//! Correctness of the walk is not assumed: `record_native` runs the REAL
//! `p3_uni_stark::verify` under counting/recording adapters (the m4census
//! pattern extended to record inputs, not just counts), and the tests
//! assert that the walk's permutation schedule reproduces the native
//! call sequence exactly (same states, same order, per channel) and that
//! the walk's draw model reproduces a real `SerializingChallenger32` run.
//!
//! The walk additionally schedules IN-CIRCUIT-ONLY permutations that the
//! native verifier does not perform: per commitment, a 7-permutation
//! Merkle-cap collapse (the consensus MMCS uses cap_height = 3, so the
//! committed "root" is 8 digests; the rectangle collapses them to a
//! single root once and extends each query path by 3 levels, which is
//! the column-cheapest sound way to compare path ends against a cap
//! without a 768-limb register file). These extra perms are tagged so
//! the cross-check can exclude them.

use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use p3_uni_stark::{prove, Proof};
use qlab_air::narrow::{build_bucket, BucketInstance, TxInput, TxOutput};

use crate::m4gate::FLUSH_BLOCKS;
use crate::{FriCfg, Val};
// Re-gated by the re-mint: M4 records the legacy non-hiding proof shape.
use qlab_consensus::legacy::{make_legacy_config_with as make_config_with, LegacyNonHidingConfig as Config};

pub(crate) type Ext = BinomialExtensionField<Val, 4>;

// The consensus config, trace height, and Merkle cap height are now the
// single-source values from `qlab-consensus` (issue #38). Re-exported here so
// the many `crate::m4gaterec::{CONSENSUS_CFG, LOG_HEIGHT, CAP_HEIGHT}` consumers
// (m4gate's `NQ`/`GRIND_BITS` derive from CONSENSUS_CFG; m6devnet; the recorder
// config below) keep resolving unchanged — and every lane now agrees byte-for-
// byte with what qlab-consensus (and thus qlab-demo / qlab-node) proves.
//
// This intentionally still diverges from m4census's g20 (a historical step-0a
// census config the design doc records as b16/q20/g20; its keccak-f count is
// grind- and query-independent per perm, so that census still stands — hence
// m4census keeps its own local const).
pub(crate) use qlab_consensus::{CAP_HEIGHT, CONSENSUS_CFG, LOG_HEIGHT};

pub(crate) const CAP_LEN: usize = 1 << CAP_HEIGHT;

// ---------------------------------------------------------------------------
// Deterministic instance + proof (m4census's exact instance)
// ---------------------------------------------------------------------------

pub(crate) fn bucket_instance() -> (BucketInstance, Vec<Val>) {
    bucket_instance_seeded(0xfeed_face_cafe_beef)
}

/// Build a bucket instance from a PRNG `seed`. The default `bucket_instance`
/// (m4census's instance) uses `0xfeed_face_cafe_beef`; a distinct seed drives
/// distinct note randomness (sk/rho/rseed/rkm) — hence distinct commitments,
/// nullifiers, and public values — while keeping the same 2-in/2-out shape and
/// a balanced ledger (80 000 in = 79 000 out + 1 000 fee). Used by the M4
/// interior's DISTINCT second child so its leaf proof's opvs differ from the
/// first's (a symmetry-bug guard the two-child PR-gate requires).
pub(crate) fn bucket_instance_seeded(seed: u64) -> (BucketInstance, Vec<Val>) {
    let mut x = seed;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mk_in = |value: u64, rnd: &mut dyn FnMut() -> u64| TxInput {
        sk: [rnd(), rnd(), rnd(), rnd()],
        value,
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
        d: [0, 0], // default diversifier (issue #32; keeps rnd stream stable)
    };
    let mk_out = |value: u64, rnd: &mut dyn FnMut() -> u64| TxOutput {
        value,
        rkm: [rnd(), rnd(), rnd(), rnd()],
        rho: [rnd(), rnd(), rnd(), rnd()],
        rseed: [rnd(), rnd(), rnd(), rnd()],
    };
    let inputs = [mk_in(50_000, &mut rnd), mk_in(30_000, &mut rnd)];
    let outputs = [mk_out(60_000, &mut rnd), mk_out(19_000, &mut rnd)];
    let inst = build_bucket(LOG_HEIGHT, &inputs, &outputs, 1_000);
    let pvs: Vec<Val> = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
    (inst, pvs)
}

/// Prove the M3 bucket once at the consensus config. Deterministic up to
/// the parallel-grind PoW witness (known since M1.6); the schedule adapts
/// to whatever proof is produced, so grind jitter is harmless.
pub(crate) fn consensus_proof() -> (BucketInstance, Vec<Val>, Proof<Config>) {
    consensus_proof_seeded(0xfeed_face_cafe_beef)
}

/// `consensus_proof` from an explicit PRNG `seed` (see `bucket_instance_seeded`).
pub(crate) fn consensus_proof_seeded(seed: u64) -> (BucketInstance, Vec<Val>, Proof<Config>) {
    let (inst, pvs) = bucket_instance_seeded(seed);
    let config = make_config_with(&CONSENSUS_CFG);
    let trace = inst.air.generate_trace::<Val>(CONSENSUS_CFG.log_blowup);
    let proof = prove(&config, &inst.air, trace, &pvs);
    (inst, pvs, proof)
}

// ---------------------------------------------------------------------------
// Keccak / sponge / digest primitives (native semantics, replayed)
// ---------------------------------------------------------------------------

pub(crate) fn keccakf(st: &[u64; 25]) -> [u64; 25] {
    let mut s = *st;
    KeccakF {}.permute_mut(&mut s);
    s
}

/// Digest = first 32 bytes (LE lanes 0..4) of a permuted state.
pub(crate) fn digest_of(out: &[u64; 25]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for l in 0..4 {
        d[8 * l..8 * l + 8].copy_from_slice(&out[l].to_le_bytes());
    }
    d
}

/// Digest as 4 u64 lanes.
pub(crate) fn digest_lanes(out: &[u64; 25]) -> [u64; 4] {
    core::array::from_fn(|l| out[l])
}

// ---------------------------------------------------------------------------
// Schedule types
// ---------------------------------------------------------------------------

/// One permutation of the rectangle's keccak lane, in lane order.
#[derive(Clone)]
pub(crate) struct PermRec {
    pub input: [u64; 25],
    pub output: [u64; 25],
    pub role: Role,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Role {
    /// Challenger keccak-256 block (tiny-keccak XOR-absorb semantics).
    Chal {
        flush: usize,
        /// Block index within the flush. Block 0 XORs into the zero state;
        /// later blocks XOR into the previous block's output (the in-lane
        /// XOR gadget binds those boundaries).
        block: usize,
        /// The 136 raw message bytes of this block (padding included for
        /// the final block).
        msg: [u8; 136],
    },
    /// Leaf-sponge absorb block (overwrite mode, u64-packed u32 words).
    /// `words` are the new rate words (2 per u64 lane); a partial final
    /// block leaves the remaining rate and all capacity lanes carried
    /// from the previous block's output. `first` blocks start from the
    /// zero state.
    Absorb {
        leaf: LeafTag,
        block: usize,
        first: bool,
        words: Vec<u32>,
    },
    /// Merkle 2-to-1 compression: preimage lanes 0..4 and 4..8 are the
    /// children, lanes 8..25 zero.
    Compress { tag: CompressTag },
    /// Stock padding permutation (generator-provided), unconstrained.
    Pad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeafTag {
    /// Main-trace row opening (one value per trace column) for query `q`.
    Trace { q: usize },
    /// Quotient batch row opening (16 mats x 4 values) for query `q`.
    Quotient { q: usize },
    /// FRI commit-phase arity-group opening (arity ext values, flattened
    /// to base) for query `q`, fold round `r`.
    Fold { q: usize, r: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompressTag {
    /// Input/fold Merkle path level. `dir` = this level's index bit
    /// (0 => running digest is the left child).
    Path {
        q: usize,
        batch: BatchTag,
        level: usize,
        dir: bool,
        /// True for the 3 in-circuit-only levels above the native cap.
        cap_ext: bool,
    },
    /// In-circuit-only cap-collapse node for `commitment`; `node` in
    /// 0..7 orders the tree bottom-up: 0..4 = level 0 pairs, 4..6 =
    /// level 1, 6 = root.
    Collapse { commitment: usize, node: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BatchTag {
    Trace,
    Quotient,
    Fold { r: usize },
}

/// One 4-byte Fiat-Shamir draw.
#[derive(Clone, Debug)]
pub(crate) struct DrawRec {
    /// Flush whose digest this draw reads.
    pub flush: usize,
    /// Draw index within that digest (0..8; group = 7 - j).
    pub j: usize,
    /// The 4 digest bytes, in digest order (group 4g..4g+4).
    pub bytes: [u8; 4],
    pub kind: DrawKind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum DrawKind {
    /// Field draw: mask 31 bits, reject if >= p. `masked` is the masked
    /// value; `accept` per the native rule; accepted draws are coefficient
    /// `coeff` of the ext challenge `chal`.
    Field {
        masked: u32,
        accept: bool,
        chal: ChalTag,
        coeff: usize,
    },
    /// sample_bits draw: mask to `bits` low bits, no rejection.
    Bits {
        bits: usize,
        value: u32,
        purpose: BitsTag,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChalTag {
    Alpha,
    Zeta,
    FriAlpha,
    Beta { r: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BitsTag {
    QueryPow,
    QueryIndex { q: usize },
}

/// One challenger flush: the hash of `msg` (which begins with the
/// previous flush's digest, except for flush 0).
#[derive(Clone)]
pub(crate) struct FlushRec {
    pub msg: Vec<u8>,
    pub digest: [u8; 32],
    /// Index of the first lane perm of this flush.
    pub first_perm: usize,
    pub n_blocks: usize,
}

/// Labeled segments of the observed byte stream (excluding chaining
/// digests), for transcript pinning and word extraction.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ObsLabel {
    DegreeBits,
    BaseDegreeBits,
    PreprocessedWidth,
    TraceCap,
    Pvs,
    QuotientCap,
    /// Zeta-opening group g (0 = trace@zeta, 1 = trace@zeta_next,
    /// 2 = quotient chunks@zeta).
    ZetaVals {
        group: usize,
    },
    FriCap {
        r: usize,
    },
    FinalPoly,
    LogArities,
    QueryPowWitness,
}

#[derive(Clone)]
pub(crate) struct ObsSeg {
    pub label: ObsLabel,
    pub bytes: Vec<u8>,
    /// Byte offset within the full observation stream (chaining digests
    /// excluded; offsets are within the concatenation of observed bytes).
    pub offset: usize,
}

/// The observation stream in the NATIVE challenger's typed units, for the
/// cross-check replay (a real SerializingChallenger32 only accepts typed
/// observations).
#[derive(Clone, Copy)]
pub(crate) enum NatObs {
    /// One base-field element (4 bytes, `to_unique_u32` LE).
    V(Val),
    /// One cap digest (4 u64 lanes, 32 bytes LE).
    Digest([u64; 4]),
}

impl NatObs {
    pub(crate) fn len(&self) -> usize {
        match self {
            NatObs::V(_) => 4,
            NatObs::Digest(_) => 32,
        }
    }
}

/// Per-query record.
#[derive(Clone)]
pub(crate) struct QueryRec {
    /// The 22-bit sampled index.
    pub index: usize,
    /// Reduced-opening denominators and inverses: (zeta - x), (zeta*g - x)
    /// with x = GENERATOR * g_22^{rev_22(index)}.
    pub x: Ext,
    pub inv_z: Ext,
    pub inv_zn: Ext,
    /// Fold rounds.
    pub folds: Vec<FoldRec>,
    /// The final-poly evaluation point x_fin = g_22^{rev_22(final index)}
    /// (the index after all fold shifts, reversed at final height).
    pub x_fin: Ext,
    /// folded_eval entering the final-poly comparison.
    pub final_eval: Ext,
    /// The reduced opening entering fold round 0.
    pub ro: Ext,
}

#[derive(Clone)]
pub(crate) struct FoldRec {
    pub log_arity: usize,
    /// Index (pre-shift) low bits: position of the running eval in the group.
    pub index_in_group: usize,
    /// The full arity-group evaluations (running eval at index_in_group,
    /// siblings elsewhere).
    pub evals: Vec<Ext>,
    /// Folded output of this round.
    pub folded: Ext,
    /// Subgroup start s (fold interpolation offset) and 1/(2s).
    pub s: Ext,
    pub inv_2s: Ext,
    pub beta: Ext,
}

pub(crate) struct Schedule {
    pub perms: Vec<PermRec>,
    pub flushes: Vec<FlushRec>,
    pub draws: Vec<DrawRec>,
    pub obs: Vec<ObsSeg>,
    pub queries: Vec<QueryRec>,
    /// Ext challenges in draw order (alpha, zeta, fri_alpha, betas..).
    pub alpha: Ext,
    pub zeta: Ext,
    pub zeta_next: Ext,
    pub fri_alpha: Ext,
    pub betas: Vec<Ext>,
    /// Caps in commitment order: trace, quotient, fri rounds...
    pub caps: Vec<Vec<[u64; 4]>>,
    /// Collapsed single roots per commitment (in-circuit only).
    pub roots: Vec<[u64; 4]>,
    /// PZ group combinations (ascending fri_alpha powers over the observed
    /// zeta-opening groups).
    pub pz: [Ext; 3],
    /// fri_alpha^width, fri_alpha^(2·width) (group offsets — derived from the
    /// matrix, never a literal; #234).
    pub alpha_off: [Ext; 2],
    pub log_arities: Vec<usize>,
    /// The observation stream in native typed units (replay cross-check).
    pub nat_obs: Vec<NatObs>,
    /// Native-census cross-check: (leaf, compress, challenger) keccak-f
    /// counts of the walk, EXCLUDING in-circuit-only perms.
    pub native_counts: (usize, usize, usize),
}

// ---------------------------------------------------------------------------
// Transcript model
// ---------------------------------------------------------------------------

/// Replays HashChallenger<u8, Keccak256Hash, 32> + SerializingChallenger32
/// semantics while recording flushes, blocks, draws, and labeled segments.
struct Transcript {
    input_buf: Vec<u8>,
    output_rem: usize, // bytes remaining in the current digest window
    flushes: Vec<FlushRec>,
    perms: Vec<PermRec>,
    draws: Vec<DrawRec>,
    obs: Vec<ObsSeg>,
    nat: Vec<NatObs>,
    obs_offset: usize,
}

impl Transcript {
    fn new() -> Self {
        Self {
            input_buf: vec![],
            output_rem: 0,
            flushes: vec![],
            perms: vec![],
            draws: vec![],
            obs: vec![],
            nat: vec![],
            obs_offset: 0,
        }
    }

    fn observe(&mut self, label: ObsLabel, bytes: &[u8], nat: &[NatObs]) {
        // observe clears any buffered output.
        self.output_rem = 0;
        debug_assert_eq!(bytes.len(), nat.iter().map(NatObs::len).sum::<usize>());
        self.obs.push(ObsSeg {
            label,
            bytes: bytes.to_vec(),
            offset: self.obs_offset,
        });
        self.nat.extend_from_slice(nat);
        self.obs_offset += bytes.len();
        self.input_buf.extend_from_slice(bytes);
    }

    fn observe_val(&mut self, label: ObsLabel, v: Val) {
        self.observe(label, &v.to_unique_u32().to_le_bytes(), &[NatObs::V(v)]);
    }

    fn observe_vals(&mut self, label: ObsLabel, vs: &[Val]) {
        let mut bytes = Vec::with_capacity(4 * vs.len());
        let mut nat = Vec::with_capacity(vs.len());
        for v in vs {
            bytes.extend_from_slice(&v.to_unique_u32().to_le_bytes());
            nat.push(NatObs::V(*v));
        }
        self.observe(label, &bytes, &nat);
    }

    fn observe_exts(&mut self, label: ObsLabel, es: &[Ext]) {
        let mut bytes = Vec::with_capacity(16 * es.len());
        let mut nat = Vec::with_capacity(4 * es.len());
        for e in es {
            let cs: &[Val] = e.as_basis_coefficients_slice();
            for c in cs {
                bytes.extend_from_slice(&c.to_unique_u32().to_le_bytes());
                nat.push(NatObs::V(*c));
            }
        }
        self.observe(label, &bytes, &nat);
    }

    fn observe_cap(&mut self, label: ObsLabel, cap: &[[u64; 4]]) {
        let mut bytes = Vec::with_capacity(cap.len() * 32);
        let mut nat = Vec::with_capacity(cap.len());
        for digest in cap {
            for lane in digest {
                bytes.extend_from_slice(&lane.to_le_bytes());
            }
            nat.push(NatObs::Digest(*digest));
        }
        self.observe(label, &bytes, &nat);
    }

    /// Keccak-256 the input buffer (tiny-keccak v256 semantics: rate 136,
    /// 0x01 domain byte, 0x80 final byte), recording each block perm.
    fn flush(&mut self) {
        let msg = core::mem::take(&mut self.input_buf);
        // Padded message: 10*1 padding always adds at least one byte, so
        // n_blocks = msg.len()/136 + 1.
        let n_blocks = msg.len() / 136 + 1;
        let mut padded = msg.clone();
        padded.resize(n_blocks * 136, 0);
        padded[msg.len()] ^= 0x01;
        padded[n_blocks * 136 - 1] ^= 0x80;

        let flush_idx = self.flushes.len();
        let first_perm = self.perms.len();
        let mut st = [0u64; 25];
        for b in 0..n_blocks {
            let mut blk = [0u8; 136];
            blk.copy_from_slice(&padded[b * 136..(b + 1) * 136]);
            for (l, chunk) in blk.chunks(8).enumerate() {
                st[l] ^= u64::from_le_bytes(chunk.try_into().unwrap());
            }
            let out = keccakf(&st);
            self.perms.push(PermRec {
                input: st,
                output: out,
                role: Role::Chal {
                    flush: flush_idx,
                    block: b,
                    msg: blk,
                },
            });
            st = out;
        }
        let digest = digest_of(&st);
        self.flushes.push(FlushRec {
            msg,
            digest,
            first_perm,
            n_blocks,
        });
        // Chaining: input buffer restarts with the digest.
        self.input_buf = digest.to_vec();
        self.output_rem = 32;
    }

    /// Pop one 4-byte group (native pop-from-end order).
    fn draw4(&mut self) -> (usize, usize, [u8; 4]) {
        if self.output_rem == 0 {
            self.flush();
        }
        assert!(self.output_rem % 4 == 0, "draws must stay 4-byte aligned");
        let flush = self.flushes.len() - 1;
        let g = self.output_rem / 4 - 1;
        let j = 7 - g;
        let d = &self.flushes[flush].digest;
        let bytes = [d[4 * g], d[4 * g + 1], d[4 * g + 2], d[4 * g + 3]];
        self.output_rem -= 4;
        (flush, j, bytes)
    }

    /// Native field sample: mask 31 bits, reject-resample if >= p.
    fn sample_field(&mut self, chal: ChalTag, coeff: usize) -> Val {
        loop {
            let (flush, j, bytes) = self.draw4();
            let raw = u32::from_le_bytes([bytes[3], bytes[2], bytes[1], bytes[0]]);
            let masked = raw & 0x7fff_ffff;
            let accept = masked < Val::ORDER_U32;
            self.draws.push(DrawRec {
                flush,
                j,
                bytes,
                kind: DrawKind::Field {
                    masked,
                    accept,
                    chal,
                    coeff,
                },
            });
            if accept {
                return Val::from_u32(masked);
            }
        }
    }

    fn sample_ext(&mut self, chal: ChalTag) -> Ext {
        Ext::from_basis_coefficients_fn(|i| self.sample_field(chal, i))
    }

    /// Native sample_bits: mask to low `bits` bits, no rejection.
    fn sample_bits(&mut self, bits: usize, purpose: BitsTag) -> usize {
        let (flush, j, bytes) = self.draw4();
        let raw = u32::from_le_bytes([bytes[3], bytes[2], bytes[1], bytes[0]]);
        let value = raw & ((1u32 << bits) - 1);
        self.draws.push(DrawRec {
            flush,
            j,
            bytes,
            kind: DrawKind::Bits {
                bits,
                value,
                purpose,
            },
        });
        value as usize
    }
}

// ---------------------------------------------------------------------------
// Leaf sponge / compress replays
// ---------------------------------------------------------------------------

/// PaddingFreeSponge<KeccakF, 25, 17, 4> over the u64 stream of packed u32
/// values (SerializingHasher packs value pairs LE into u64 lanes). Records
/// each block perm and returns the digest lanes.
fn absorb_leaf(perms: &mut Vec<PermRec>, leaf: LeafTag, values: &[u32]) -> [u64; 4] {
    let words: Vec<u64> = values
        .chunks(2)
        .map(|c| c[0] as u64 | ((*c.get(1).unwrap_or(&0) as u64) << 32))
        .collect();
    let mut st = [0u64; 25];
    for (b, chunk) in words.chunks(17).enumerate() {
        st[..chunk.len()].copy_from_slice(chunk);
        let out = keccakf(&st);
        perms.push(PermRec {
            input: st,
            output: out,
            role: Role::Absorb {
                leaf,
                block: b,
                first: b == 0,
                words: values[b * 34..(b * 34 + 2 * chunk.len()).min(values.len())].to_vec(),
            },
        });
        st = out;
    }
    digest_lanes(&st)
}

/// CompressionFunctionFromHasher<Sponge, 2, 4>: one perm over the 8
/// concatenated child lanes.
fn compress(perms: &mut Vec<PermRec>, tag: CompressTag, l: [u64; 4], r: [u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&l);
    st[4..8].copy_from_slice(&r);
    let out = keccakf(&st);
    perms.push(PermRec {
        input: st,
        output: out,
        role: Role::Compress { tag },
    });
    digest_lanes(&out)
}

fn reverse_bits_len(x: usize, bits: usize) -> usize {
    let mut r = 0usize;
    for i in 0..bits {
        r |= ((x >> i) & 1) << (bits - 1 - i);
    }
    r
}

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Ext -> flattened base values (basis coefficient order), as
/// `ExtensionMmcs::flatten_to_base` / `observe_algebra_element` do.
fn ext_to_u32s(e: &Ext) -> [u32; 4] {
    let s: &[Val] = e.as_basis_coefficients_slice();
    core::array::from_fn(|i| s[i].to_unique_u32())
}

/// Record the uni-stark FRI-verification transcript of the M3 consensus proof.
pub(crate) fn walk(proof: &Proof<Config>, pvs: &[Val]) -> Schedule {
    walk_with_cfg(proof, pvs, &CONSENSUS_CFG)
}

/// Record the uni-stark FRI-verification transcript of ANY `Proof<Config>` at
/// the given FRI config. The body reads all shape from the proof itself
/// (widths, arities, opened-value counts, query count from the config), so it
/// is AIR-agnostic — used both for the M3 consensus proof (`walk`) and for the
/// leaf's own wide `VerifierGateAir` proof (M4 step 1's interior-node input,
/// via `m4treerec`). Only the four FRI parameters come from `cfg`.
pub(crate) fn walk_with_cfg(proof: &Proof<Config>, pvs: &[Val], cfg: &FriCfg) -> Schedule {
    let degree_bits = proof.degree_bits;
    let log_blowup = cfg.log_blowup;
    let n_queries = cfg.num_queries;
    let grind_bits = cfg.grind_bits;
    let log_fp = cfg.log_final_poly_len;

    let mut t = Transcript::new();

    // --- uni-stark preamble --------------------------------------------
    t.observe_val(ObsLabel::DegreeBits, Val::from_usize(degree_bits));
    t.observe_val(ObsLabel::BaseDegreeBits, Val::from_usize(degree_bits));
    t.observe_val(ObsLabel::PreprocessedWidth, Val::from_usize(0));
    let trace_cap: Vec<[u64; 4]> = cap_lanes(&proof.commitments.trace);
    t.observe_cap(ObsLabel::TraceCap, &trace_cap);
    t.observe_vals(ObsLabel::Pvs, pvs);
    let alpha = t.sample_ext(ChalTag::Alpha);
    let quotient_cap: Vec<[u64; 4]> = cap_lanes(&proof.commitments.quotient_chunks);
    t.observe_cap(ObsLabel::QuotientCap, &quotient_cap);
    let zeta = t.sample_ext(ChalTag::Zeta);
    let g_trace = Val::two_adic_generator(degree_bits);
    let zeta_next = zeta * g_trace;

    // --- pcs.verify: observe all zeta openings --------------------------
    let ov = &proof.opened_values;
    let trace_next = ov.trace_next.as_ref().expect("bucket AIR uses next row");
    t.observe_exts(ObsLabel::ZetaVals { group: 0 }, &ov.trace_local);
    t.observe_exts(ObsLabel::ZetaVals { group: 1 }, trace_next);
    let quot_flat: Vec<Ext> = ov.quotient_chunks.iter().flatten().copied().collect();
    t.observe_exts(ObsLabel::ZetaVals { group: 2 }, &quot_flat);

    // --- verify_fri ------------------------------------------------------
    let fri = &proof.opening_proof;
    let fri_alpha = t.sample_ext(ChalTag::FriAlpha);

    let log_arities: Vec<usize> = fri.query_proofs[0]
        .commit_phase_openings
        .iter()
        .map(|s| s.log_arity as usize)
        .collect();
    let total_red: usize = log_arities.iter().sum();
    let log_max = total_red + log_blowup + log_fp;
    assert_eq!(log_max, degree_bits + log_blowup, "height cross-check");

    let mut fri_caps: Vec<Vec<[u64; 4]>> = vec![];
    let mut betas = vec![];
    for (r, comm) in fri.commit_phase_commits.iter().enumerate() {
        let cap = cap_lanes(comm);
        t.observe_cap(ObsLabel::FriCap { r }, &cap);
        fri_caps.push(cap);
        // commit_proof_of_work_bits = 0: check_witness returns true
        // without observing or sampling.
        betas.push(t.sample_ext(ChalTag::Beta { r }));
    }
    assert_eq!(fri.final_poly.len(), 1 << log_fp);
    t.observe_exts(ObsLabel::FinalPoly, &fri.final_poly);
    let arity_vals: Vec<Val> = log_arities.iter().map(|&la| Val::from_usize(la)).collect();
    t.observe_vals(ObsLabel::LogArities, &arity_vals);
    // Query PoW: observe witness, then sample_bits(grind) must be 0.
    t.observe_val(ObsLabel::QueryPowWitness, fri.query_pow_witness);
    let pow = t.sample_bits(grind_bits, BitsTag::QueryPow);
    assert_eq!(pow, 0, "query PoW check");

    // --- queries ----------------------------------------------------------
    // The challenger side (index draws) is interleaved with Merkle/fold
    // work in the native verifier, but the native verifier's hashing per
    // query happens strictly after its index draw, so recording the
    // index draws in order then walking each query reproduces the native
    // keccak call order (draws don't hash unless a flush is needed).
    let mut indices = vec![];
    for q in 0..n_queries {
        indices.push(t.sample_bits(log_max, BitsTag::QueryIndex { q }));
    }

    // Native-count bookkeeping: everything recorded so far + query walks
    // below are native; collapse perms are added afterwards.
    let mut perms = core::mem::take(&mut t.perms);
    // Trailing consumer block: the last flush's digest is read (draws) from
    // the preimage of the perm that consumes it. If the final draws' flush
    // has no successor block in the native schedule, the rectangle needs
    // one chained continuation block so the digest is preimage-visible.
    // (Handled by the lowering, not here; the draw records carry flush ids.)

    let n_chal = perms.len();

    // --- in-circuit-only: cap collapses (computed before queries so the
    // cap-extended paths can assert against the collapsed roots; the
    // recorder appends them to `collapse_perms` and the schedule keeps
    // them separate from the native sequence) -------------------------------
    let mut caps = vec![trace_cap.clone(), quotient_cap.clone()];
    caps.extend(fri_caps.iter().cloned());
    let mut collapse_perms = vec![];
    let mut roots = vec![];
    for (c, cap) in caps.iter().enumerate() {
        assert_eq!(cap.len(), CAP_LEN);
        let mut lvl0 = vec![];
        for i in 0..4 {
            lvl0.push(compress(
                &mut collapse_perms,
                CompressTag::Collapse {
                    commitment: c,
                    node: i,
                },
                cap[2 * i],
                cap[2 * i + 1],
            ));
        }
        let b0 = compress(
            &mut collapse_perms,
            CompressTag::Collapse {
                commitment: c,
                node: 4,
            },
            lvl0[0],
            lvl0[1],
        );
        let b1 = compress(
            &mut collapse_perms,
            CompressTag::Collapse {
                commitment: c,
                node: 5,
            },
            lvl0[2],
            lvl0[3],
        );
        roots.push(compress(
            &mut collapse_perms,
            CompressTag::Collapse {
                commitment: c,
                node: 6,
            },
            b0,
            b1,
        ));
    }

    let width = ov.trace_local.len();
    let quot_chunks = ov.quotient_chunks.len();
    let ext_d = 4usize;

    let g22 = Val::two_adic_generator(log_max);
    let shift = Val::GENERATOR;

    let mut queries = vec![];
    for (q, &index) in indices.iter().enumerate() {
        let qp = &fri.query_proofs[q];

        // -- input batches: trace, quotient ------------------------------
        assert_eq!(qp.input_proof.len(), 2, "trace + quotient batches");
        let trace_row: &Vec<Val> = &qp.input_proof[0].opened_values[0];
        assert_eq!(trace_row.len(), width);
        let quot_rows: &Vec<Vec<Val>> = &qp.input_proof[1].opened_values;
        assert_eq!(quot_rows.len(), quot_chunks);

        // Leaf digests + paths.
        let trace_vals: Vec<u32> = trace_row.iter().map(|v| v.to_unique_u32()).collect();
        let digest = absorb_leaf(&mut perms, LeafTag::Trace { q }, &trace_vals);
        walk_path(
            &mut perms,
            q,
            BatchTag::Trace,
            index,
            digest,
            &qp.input_proof[0].opening_proof,
            &trace_cap,
            roots[0],
        );

        let quot_vals: Vec<u32> = quot_rows
            .iter()
            .flatten()
            .map(|v| v.to_unique_u32())
            .collect();
        assert_eq!(quot_vals.len(), quot_chunks * ext_d);
        let qdigest = absorb_leaf(&mut perms, LeafTag::Quotient { q }, &quot_vals);
        walk_path(
            &mut perms,
            q,
            BatchTag::Quotient,
            index,
            qdigest,
            &qp.input_proof[1].opening_proof,
            &quotient_cap,
            roots[1],
        );

        // -- reduced opening ---------------------------------------------
        let rev_idx = reverse_bits_len(index, log_max);
        let x_base = shift * g22.exp_u64(rev_idx as u64);
        let x = Ext::from(x_base);
        let inv_z = (zeta - x).inverse();
        let inv_zn = (zeta_next - x).inverse();

        // ro = inv_z * (PX-style combination) computed the native way:
        // running alpha powers over (trace@zeta, trace@zeta_next, quotient).
        let mut ro = Ext::ZERO;
        let mut alpha_pow = Ext::ONE;
        for (i, &pv) in trace_row.iter().enumerate() {
            ro += alpha_pow * (ov.trace_local[i] - Ext::from(pv)) * inv_z;
            alpha_pow *= fri_alpha;
        }
        for (i, &pv) in trace_row.iter().enumerate() {
            ro += alpha_pow * (trace_next[i] - Ext::from(pv)) * inv_zn;
            alpha_pow *= fri_alpha;
        }
        for (m, row) in quot_rows.iter().enumerate() {
            for (k, &pv) in row.iter().enumerate() {
                ro += alpha_pow * (ov.quotient_chunks[m][k] - Ext::from(pv)) * inv_z;
                alpha_pow *= fri_alpha;
            }
        }

        // -- fold rounds ----------------------------------------------------
        let mut folded = ro;
        let mut idx = index;
        let mut log_h = log_max;
        let mut folds = vec![];
        for (r, step) in qp.commit_phase_openings.iter().enumerate() {
            let log_arity = step.log_arity as usize;
            let arity = 1 << log_arity;
            let index_in_group = idx % arity;
            let mut evals = vec![Ext::ZERO; arity];
            evals[index_in_group] = folded;
            let mut si = 0;
            for (jj, e) in evals.iter_mut().enumerate() {
                if jj != index_in_group {
                    *e = step.sibling_values[si];
                    si += 1;
                }
            }
            let log_folded = log_h - log_arity;
            idx >>= log_arity;

            // Fold leaf (ExtensionMmcs flattens to base) + path.
            let flat: Vec<u32> = evals.iter().flat_map(ext_to_u32s).collect();
            let fdigest = absorb_leaf(&mut perms, LeafTag::Fold { q, r }, &flat);
            walk_path(
                &mut perms,
                q,
                BatchTag::Fold { r },
                idx,
                fdigest,
                &step.opening_proof,
                &fri_caps[r],
                roots[2 + r],
            );

            // Native fold_row: Lagrange interpolation at beta over
            // xs[j] = s * g_arity^{rev(j)}; equivalently log_arity
            // sequential binary folds. We record s and 1/(2s) for the
            // in-circuit binary-fold decomposition and compute the folded
            // value with the decomposition, cross-checked against the
            // final-poly identity at the end of the walk.
            let s_base = Val::two_adic_generator(log_folded + log_arity)
                .exp_u64(reverse_bits_len(idx, log_folded) as u64);
            let s = Ext::from(s_base);
            let inv_2s = (s_base * Val::from_u32(2)).inverse();
            let beta = betas[r];

            // Binary-fold decomposition over bit-reversed-ordered evals:
            // level l folds pairs (2i, 2i+1) of the current vector with
            // gamma_l = beta^{2^l} / (2 * s^{2^l}) and per-pair static
            // constant K_i = g_arity^{-2^l * rev(i-th pair position)}...
            // Concretely, with points x_j = s * g^{rev_la(j)} (g = the
            // 2^la-th root), pair (2i, 2i+1) sits at (+y, -y) with
            // y = s_l * g_l^{rev(i)} where s_l = s^{2^l}, g_l = g^{2^l}
            // (both bit-reversal-compatible), and folds to
            //   (e_lo + e_hi)/2 + beta_l * (e_lo - e_hi) / (2 y).
            let mut cur = evals.clone();
            let mut beta_l = beta;
            let mut s_l = Ext::from(s_base);
            let g_ar = Val::two_adic_generator(log_arity);
            let mut g_l = g_ar;
            let mut la_rem = log_arity;
            while cur.len() > 1 {
                let half = cur.len() / 2;
                let mut nxt_v = vec![Ext::ZERO; half];
                for i in 0..half {
                    let lo = cur[2 * i];
                    let hi = cur[2 * i + 1];
                    // y_i = s_l * g_l^{rev_{la_rem-1}(i)}
                    let y = s_l * g_l.exp_u64(reverse_bits_len(i, la_rem - 1) as u64);
                    let inv_2y = (y * Ext::from(Val::from_u32(2))).inverse();
                    nxt_v[i] = (lo + hi).halve() + beta_l * (lo - hi) * inv_2y;
                }
                cur = nxt_v;
                beta_l = beta_l * beta_l;
                s_l = s_l * s_l;
                g_l = g_l * g_l;
                la_rem -= 1;
            }
            folded = cur[0];

            folds.push(FoldRec {
                log_arity,
                index_in_group,
                evals,
                folded,
                s,
                inv_2s: Ext::from(inv_2s),
                beta,
            });
            log_h = log_folded;
        }
        assert_eq!(log_h, log_blowup + log_fp, "final fold height");

        // -- final poly ------------------------------------------------------
        let x_fin_base = g22.exp_u64(reverse_bits_len(idx, log_max) as u64);
        let x_fin = Ext::from(x_fin_base);
        let mut eval = Ext::ZERO;
        for c in fri.final_poly.iter().rev() {
            eval = eval * x_fin + *c;
        }
        assert_eq!(eval, folded, "final poly check must pass on a real proof");

        queries.push(QueryRec {
            index,
            x,
            inv_z,
            inv_zn,
            folds,
            x_fin,
            final_eval: folded,
            ro,
        });
    }

    // Native counts (cap-extension and collapse perms are in-circuit-only).
    let mut n_leaf = 0;
    let mut n_compress = 0;
    for p in &perms {
        match p.role {
            Role::Absorb { .. } => n_leaf += 1,
            Role::Compress {
                tag: CompressTag::Path { cap_ext: false, .. },
            } => n_compress += 1,
            _ => {}
        }
    }
    let native_counts = (n_leaf, n_compress, n_chal);

    // Append the in-circuit-only collapse perms after the native sequence
    // (the lane lowering reorders perms as it needs).
    perms.extend(collapse_perms);

    // --- PZ group combinations (ascending fri_alpha powers) ------------------
    let pz_group = |vals: &[Ext]| -> Ext {
        let mut acc = Ext::ZERO;
        let mut pow = Ext::ONE;
        for v in vals {
            acc += pow * *v;
            pow *= fri_alpha;
        }
        acc
    };
    let quot_flat: Vec<Ext> = ov.quotient_chunks.iter().flatten().copied().collect();
    let pz = [
        pz_group(&ov.trace_local),
        pz_group(trace_next),
        pz_group(&quot_flat),
    ];
    let alpha_off = [
        fri_alpha.exp_u64(width as u64),
        fri_alpha.exp_u64(2 * width as u64),
    ];
    // Cross-check the PZ/PX split against the native ro for every query:
    // ro = inv_z*(PZ0 - PX0) + inv_zn*a^w*(PZ1 - PX1) + inv_z*a^2w*(PZ2 - PX2)
    for (q, qr) in queries.iter().enumerate() {
        let qp = &fri.query_proofs[q];
        let trace_row: &Vec<Val> = &qp.input_proof[0].opened_values[0];
        let quot_rows: &Vec<Vec<Val>> = &qp.input_proof[1].opened_values;
        let px_t = pz_group(&trace_row.iter().map(|v| Ext::from(*v)).collect::<Vec<_>>());
        let px_q = pz_group(
            &quot_rows
                .iter()
                .flatten()
                .map(|v| Ext::from(*v))
                .collect::<Vec<_>>(),
        );
        let ro2 = qr.inv_z * (pz[0] - px_t)
            + qr.inv_zn * alpha_off[0] * (pz[1] - px_t)
            + qr.inv_z * alpha_off[1] * (pz[2] - px_q);
        assert_eq!(ro2, qr.ro, "PZ/PX split must reproduce the native ro");
    }

    Schedule {
        perms,
        flushes: t.flushes,
        draws: t.draws,
        obs: t.obs,
        nat_obs: t.nat,
        queries,
        alpha,
        zeta,
        zeta_next,
        fri_alpha,
        betas,
        caps,
        roots,
        pz,
        alpha_off,
        log_arities,
        native_counts,
    }
}

/// Cap commitment (MerkleCap<Val, [u64; 4]>) -> digest lanes.
fn cap_lanes(cap: &p3_symmetric::MerkleCap<Val, [u64; 4]>) -> Vec<[u64; 4]> {
    cap.roots().to_vec()
}

/// Walk one Merkle path: native levels against the proof siblings, then
/// the 3 in-circuit cap-extension levels (siblings from the collapse
/// tree recomputed locally). Asserts the native portion ends on the
/// committed cap element and the extension ends on the collapsed root.
#[allow(clippy::too_many_arguments)]
fn walk_path(
    perms: &mut Vec<PermRec>,
    q: usize,
    batch: BatchTag,
    mut index: usize,
    mut digest: [u64; 4],
    siblings: &[[u64; 4]],
    cap: &[[u64; 4]],
    root: [u64; 4],
) {
    for (level, sib) in siblings.iter().enumerate() {
        let dir = index & 1 == 1; // true => running digest is the right child
        let (l, r) = if dir { (*sib, digest) } else { (digest, *sib) };
        digest = compress(
            perms,
            CompressTag::Path {
                q,
                batch,
                level,
                dir,
                cap_ext: false,
            },
            l,
            r,
        );
        index >>= 1;
    }
    assert_eq!(
        digest, cap[index],
        "native path must land on the committed cap element"
    );
    // Cap extension: 3 more levels to the true root. Siblings are the
    // collapse-tree nodes (recomputed here; the rectangle witnesses them
    // and they are sound as ordinary path siblings).
    let n_levels = siblings.len();
    let mut layer: Vec<[u64; 4]> = cap.to_vec();
    for ext in 0..CAP_HEIGHT {
        let sib = layer[index ^ 1];
        let dir = index & 1 == 1;
        let (l, r) = if dir { (sib, digest) } else { (digest, sib) };
        digest = compress(
            perms,
            CompressTag::Path {
                q,
                batch,
                level: n_levels + ext,
                dir,
                cap_ext: true,
            },
            l,
            r,
        );
        index >>= 1;
        layer = layer
            .chunks(2)
            .map(|p| {
                let mut st = [0u64; 25];
                st[..4].copy_from_slice(&p[0]);
                st[4..8].copy_from_slice(&p[1]);
                digest_lanes(&keccakf(&st))
            })
            .collect();
    }
    assert_eq!(
        digest, root,
        "cap-extended path must reach the collapsed root"
    );
}

// ---------------------------------------------------------------------------
// Native recording cross-check (m4census pattern, recording inputs)
// ---------------------------------------------------------------------------

pub(crate) mod native {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{
        CompressionFunctionFromHasher, CryptographicHasher, CryptographicPermutation,
        PaddingFreeSponge, Permutation, SerializingHasher,
    };
    use p3_uni_stark::{verify, StarkConfig};

    use super::*;
    use crate::{Challenge, Dft};

    /// Records every SCALAR [u64; 25] permute input in call order.
    /// Packed (SIMD) calls only occur on the prover side; recording is
    /// done around `verify`, which is scalar (asserted via the flag).
    #[derive(Clone)]
    pub(crate) struct RecKeccakF {
        pub log: Arc<Mutex<Vec<[u64; 25]>>>,
        pub saw_packed: Arc<AtomicBool>,
    }

    impl Permutation<[u64; 25]> for RecKeccakF {
        fn permute_mut(&self, input: &mut [u64; 25]) {
            self.log.lock().unwrap().push(*input);
            KeccakF {}.permute_mut(input);
        }
    }
    impl CryptographicPermutation<[u64; 25]> for RecKeccakF {}

    impl<T: Clone + Send + Sync, const N: usize> Permutation<[[T; N]; 25]> for RecKeccakF
    where
        KeccakF: Permutation<[[T; N]; 25]>,
    {
        fn permute_mut(&self, input: &mut [[T; N]; 25]) {
            self.saw_packed.store(true, Ordering::Relaxed);
            KeccakF {}.permute_mut(input);
        }
    }
    impl<T: Clone + Send + Sync, const N: usize> CryptographicPermutation<[[T; N]; 25]> for RecKeccakF where
        KeccakF: CryptographicPermutation<[[T; N]; 25]>
    {
    }

    /// Records every challenger hash call (input, digest).
    #[derive(Clone)]
    pub(crate) struct RecByteHash {
        pub log: Arc<Mutex<Vec<(Vec<u8>, [u8; 32])>>>,
    }

    impl CryptographicHasher<u8, [u8; 32]> for RecByteHash {
        fn hash_iter<I>(&self, input: I) -> [u8; 32]
        where
            I: IntoIterator<Item = u8>,
        {
            let buf: Vec<u8> = input.into_iter().collect();
            let d = Keccak256Hash.hash_iter(buf.clone());
            self.log.lock().unwrap().push((buf, d));
            d
        }
    }

    type RSponge = PaddingFreeSponge<RecKeccakF, 25, 17, 4>;
    type RFieldHash = SerializingHasher<RSponge>;
    type RCompress = CompressionFunctionFromHasher<RSponge, 2, 4>;
    type RValMmcs = MerkleTreeMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        RFieldHash,
        RCompress,
        2,
        4,
    >;
    type RChallengeMmcs = ExtensionMmcs<Val, Challenge, RValMmcs>;
    type RChallenger = SerializingChallenger32<Val, HashChallenger<u8, RecByteHash, 32>>;
    type RPcs = TwoAdicFriPcs<Val, Dft, RValMmcs, RChallengeMmcs>;
    type RConfig = StarkConfig<RPcs, Challenge, RChallenger>;

    pub(crate) struct NativeRecord {
        /// Leaf-sponge scalar perm inputs, in call order.
        pub leaf: Vec<[u64; 25]>,
        /// Compression scalar perm inputs, in call order.
        pub compress: Vec<[u64; 25]>,
        /// Challenger hash calls (input bytes, digest), in call order.
        pub hashes: Vec<(Vec<u8>, [u8; 32])>,
    }

    /// Run the REAL verifier under recording adapters.
    pub(crate) fn record_verify(
        inst: &BucketInstance,
        pvs: &[Val],
        proof: &Proof<Config>,
    ) -> NativeRecord {
        let leaf_log = Arc::new(Mutex::new(vec![]));
        let compress_log = Arc::new(Mutex::new(vec![]));
        let hash_log = Arc::new(Mutex::new(vec![]));
        let saw_packed = Arc::new(AtomicBool::new(false));

        let leaf_perm = RecKeccakF {
            log: leaf_log.clone(),
            saw_packed: saw_packed.clone(),
        };
        let compress_perm = RecKeccakF {
            log: compress_log.clone(),
            saw_packed: saw_packed.clone(),
        };
        let byte_hash = RecByteHash {
            log: hash_log.clone(),
        };
        let field_hash = RFieldHash::new(PaddingFreeSponge::new(leaf_perm));
        let compress = RCompress::new(PaddingFreeSponge::new(compress_perm));
        let val_mmcs = RValMmcs::new(field_hash, compress, super::CAP_HEIGHT);
        let challenge_mmcs = RChallengeMmcs::new(val_mmcs.clone());
        let challenger = RChallenger::from_hasher(vec![], byte_hash);
        let fri_params = FriParameters {
            log_blowup: CONSENSUS_CFG.log_blowup,
            log_final_poly_len: CONSENSUS_CFG.log_final_poly_len,
            max_log_arity: CONSENSUS_CFG.max_log_arity,
            num_queries: CONSENSUS_CFG.num_queries,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: CONSENSUS_CFG.grind_bits,
            mmcs: challenge_mmcs,
        };
        let pcs = RPcs::new(Dft::default(), val_mmcs, fri_params);
        let config = RConfig::new(pcs, challenger);

        // Round-trip the proof into the recording config's proof type.
        let bytes = postcard::to_allocvec(proof).expect("serialize");
        let rproof: p3_uni_stark::Proof<RConfig> =
            postcard::from_bytes(&bytes).expect("deserialize");
        verify(&config, &inst.air, &rproof, pvs).expect("native verify must accept");
        assert!(
            !saw_packed.load(Ordering::Relaxed),
            "verify-side hashing must be scalar for the recording to be exact"
        );

        // The config still holds adapter clones; read the logs via lock.
        let leaf = leaf_log.lock().unwrap().clone();
        let compress = compress_log.lock().unwrap().clone();
        let hashes = hash_log.lock().unwrap().clone();
        NativeRecord {
            leaf,
            compress,
            hashes,
        }
    }

    /// Drive a real SerializingChallenger32 with the walk's observation
    /// stream (in native typed units) and return all sampled values in
    /// the walk's draw order (accepted field draws, bits draws).
    pub(crate) fn native_challenger_draws(sched: &super::Schedule) -> (Vec<u32>, Vec<usize>) {
        use p3_challenger::{CanObserve, CanSample, CanSampleBits};
        use p3_symmetric::Hash;

        let mut ch =
            SerializingChallenger32::<Val, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
                vec![],
                Keccak256Hash,
            );
        let mut fields = vec![];
        let mut bits = vec![];
        let mut nat_iter = sched.nat_obs.iter().peekable();
        let mut fed_bytes = 0usize;
        // Replay: before each draw, feed the typed observations belonging
        // to flushes up to and including the one the draw reads (the
        // native challenger flushes lazily on sample). FlushRec.msg
        // lengths (minus the 32-byte chaining prefix for flushes > 0)
        // tell how many observed-stream bytes each flush consumed.
        for d in &sched.draws {
            let target: usize = sched.flushes[..=d.flush]
                .iter()
                .enumerate()
                .map(|(i, f)| f.msg.len() - if i == 0 { 0 } else { 32 })
                .sum();
            while fed_bytes < target {
                let n = nat_iter.next().expect("obs stream exhausted early");
                match n {
                    super::NatObs::V(v) => ch.observe(*v),
                    super::NatObs::Digest(d) => {
                        ch.observe(Hash::<Val, u64, 4>::from(*d));
                    }
                }
                fed_bytes += n.len();
            }
            assert_eq!(fed_bytes, target, "obs stream misaligned with flushes");
            match d.kind {
                DrawKind::Field { masked, accept, .. } => {
                    if accept {
                        // The native sampler internally skips rejected
                        // draws; call sample() once per accepted draw.
                        let v: Val = ch.sample();
                        assert_eq!(v, Val::from_u32(masked), "native field draw");
                        fields.push(masked);
                    }
                }
                DrawKind::Bits {
                    bits: nbits, value, ..
                } => {
                    let v = ch.sample_bits(nbits);
                    assert_eq!(v, value as usize, "native bits draw");
                    bits.push(v);
                }
            }
        }
        (fields, bits)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    /// The consensus proof is expensive (a full 2^18 × trace-width prove at b16);
    /// share it across tests.
    pub(crate) fn shared() -> &'static (BucketInstance, Vec<Val>, Proof<Config>) {
        static CELL: OnceLock<(BucketInstance, Vec<Val>, Proof<Config>)> = OnceLock::new();
        CELL.get_or_init(consensus_proof)
    }

    /// The walk reproduces the native verifier's keccak workload exactly:
    /// per channel, same call count, same inputs, same order.
    #[test]
    fn walk_matches_native_hashing() {
        let (inst, pvs, proof) = shared();
        let rec = native::record_verify(inst, pvs, proof);
        let sched = walk(proof, pvs);

        // Challenger: the walk's flushes must equal the native hash calls.
        assert_eq!(sched.flushes.len(), rec.hashes.len(), "flush count");
        for (i, (f, (msg, digest))) in sched.flushes.iter().zip(&rec.hashes).enumerate() {
            assert_eq!(&f.msg, msg, "flush {i} message");
            assert_eq!(&f.digest, digest, "flush {i} digest");
        }

        // Leaf sponge: walk absorb perms in order must equal native.
        let walk_leaf: Vec<[u64; 25]> = sched
            .perms
            .iter()
            .filter(|p| matches!(p.role, Role::Absorb { .. }))
            .map(|p| p.input)
            .collect();
        assert_eq!(walk_leaf.len(), rec.leaf.len(), "leaf perm count");
        for (i, (w, n)) in walk_leaf.iter().zip(&rec.leaf).enumerate() {
            assert_eq!(w, n, "leaf perm {i}");
        }

        // Compress: native portion only (collapse + cap-extension levels
        // are in-circuit-only).
        let walk_compress: Vec<[u64; 25]> = sched
            .perms
            .iter()
            .filter(|p| {
                matches!(
                    p.role,
                    Role::Compress {
                        tag: CompressTag::Path { cap_ext: false, .. }
                    }
                )
            })
            .map(|p| p.input)
            .collect();
        assert_eq!(walk_compress.len(), rec.compress.len(), "compress count");
        for (i, (w, n)) in walk_compress.iter().zip(&rec.compress).enumerate() {
            assert_eq!(w, n, "compress perm {i}");
        }

        // Census cross-check. Step 0a (q20) recorded 2,233 total: 540 leaf +
        // 1,520 compress + 173 challenger. B″ (issue #41) q20→q21 adds one
        // query's verification work: +27 leaf-sponge + 76 path-compress perms
        // (challenger UNCHANGED — the 21st index sample_bits draw fits the
        // existing squeeze buffer, no new keccak block) → 2,336 total.
        //
        // Issue #215 (i) + #219 then widened the inner trace 617 → 643, and the
        // delta lands entirely on the **challenger**: 173 → 179, i.e. exactly
        // F2's block growth (148 → 154), since flush 2 observes the zeta
        // openings and one keccak block is one permutation. Leaf and compress do
        // not move — they are driven by the query COUNT and the Merkle path
        // depth, neither of which the width touches. Total 2,342.
        let (leaf, compress, chal) = sched.native_counts;
        assert_eq!(leaf, 567, "census leaf (q21: 540 + 27; width-independent)");
        assert_eq!(compress, 1_596, "census compress (q21: 1520 + 76; width-independent)");
        assert_eq!(
            chal,
            173 + (FLUSH_BLOCKS[2] - 148),
            "census challenger — 173 at tw=617, plus F2's block growth since"
        );
        assert_eq!(chal, 179, "census challenger at tw=643");
        assert_eq!(leaf + compress + chal, 2_342, "census total (q21, tw=643)");
    }

    /// The walk's draw model reproduces a real SerializingChallenger32
    /// driven with the same observations.
    #[test]
    fn walk_matches_native_challenger() {
        let (_, pvs, proof) = shared();
        let sched = walk(proof, pvs);
        let (fields, bits) = native::native_challenger_draws(&sched);
        let expect_fields: Vec<u32> = sched
            .draws
            .iter()
            .filter_map(|d| match d.kind {
                DrawKind::Field {
                    masked,
                    accept: true,
                    ..
                } => Some(masked),
                _ => None,
            })
            .collect();
        assert_eq!(fields, expect_fields, "accepted field draw sequence");
        let expect_bits: Vec<usize> = sched
            .draws
            .iter()
            .filter_map(|d| match d.kind {
                DrawKind::Bits { value, .. } => Some(value as usize),
                _ => None,
            })
            .collect();
        assert_eq!(bits, expect_bits, "bits draw sequence");
        // The PoW draw must be zero (the proof carries a valid witness).
        assert_eq!(
            sched
                .draws
                .iter()
                .find_map(|d| match d.kind {
                    DrawKind::Bits {
                        purpose: BitsTag::QueryPow,
                        value,
                        ..
                    } => Some(value),
                    _ => None,
                })
                .unwrap(),
            0
        );
    }

    /// Ext-challenge assembly semantics: the walk's per-coefficient draws
    /// assemble into the challenges the native challenger produces (this
    /// is the "4 accepted draws -> one 4-limb tuple" rule, including
    /// rejection skipping).
    #[test]
    fn ext_challenges_assemble() {
        let (_, pvs, proof) = shared();
        let sched = walk(proof, pvs);
        for (tag, expect) in [
            (ChalTag::Alpha, sched.alpha),
            (ChalTag::Zeta, sched.zeta),
            (ChalTag::FriAlpha, sched.fri_alpha),
            (ChalTag::Beta { r: 0 }, sched.betas[0]),
        ] {
            let coeffs: Vec<u32> = sched
                .draws
                .iter()
                .filter_map(|d| match d.kind {
                    DrawKind::Field {
                        masked,
                        accept: true,
                        chal,
                        ..
                    } if chal == tag => Some(masked),
                    _ => None,
                })
                .collect();
            assert_eq!(coeffs.len(), 4, "{tag:?} coefficient count");
            let assembled = Ext::from_basis_coefficients_fn(|i| Val::from_u32(coeffs[i]));
            assert_eq!(assembled, expect, "{tag:?} assembly");
        }
    }

    /// TEMP probe: print the exact shape constants the gate lowering
    /// hard-codes (per-query absorb/path structure, flush layout, draws).
    #[test]
    fn probe_shape() {
        let (_, pvs, proof) = shared();
        let sched = walk(proof, pvs);
        eprintln!("log_arities = {:?}", sched.log_arities);
        // Per-query absorb blocks + words, per batch.
        let q0: Vec<&PermRec> = sched
            .perms
            .iter()
            .filter(|p| {
                matches!(
                    p.role,
                    Role::Absorb {
                        leaf: LeafTag::Trace { q: 0 } | LeafTag::Quotient { q: 0 } | LeafTag::Fold { q: 0, .. },
                        ..
                    }
                )
            })
            .collect();
        let mut counts: Vec<(String, usize)> = vec![];
        for p in &q0 {
            if let Role::Absorb { leaf, words, .. } = &p.role {
                let key = format!("{leaf:?}");
                if let Some(last) = counts.last_mut() {
                    if last.0 == key {
                        last.1 += 1;
                        eprintln!("  {key} block words {}", words.len());
                        continue;
                    }
                }
                eprintln!("  {key} block words {}", words.len());
                counts.push((key, 1));
            }
        }
        eprintln!("q0 absorb blocks per leaf: {counts:?}");
        // Path levels per batch for q0 (native + capext).
        let mut lv: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
        for p in &sched.perms {
            if let Role::Compress {
                tag: CompressTag::Path { q: 0, batch, cap_ext, .. },
            } = p.role
            {
                let e = lv.entry(format!("{batch:?}")).or_default();
                if cap_ext {
                    e.1 += 1;
                } else {
                    e.0 += 1;
                }
            }
        }
        eprintln!("q0 path levels (native, capext): {lv:?}");
        // Flush structure.
        for (i, f) in sched.flushes.iter().enumerate() {
            eprintln!(
                "flush {i}: msg {} B, {} blocks, first_perm {}",
                f.msg.len(),
                f.n_blocks,
                f.first_perm
            );
        }
        for o in &sched.obs {
            eprintln!("obs {:?}: offset {}, {} B", o.label, o.offset, o.bytes.len());
        }
        // Draws by flush.
        let mut cur = usize::MAX;
        let mut line = String::new();
        for d in &sched.draws {
            if d.flush != cur {
                if !line.is_empty() {
                    eprintln!("{line}");
                }
                cur = d.flush;
                line = format!("draws from flush {cur}:");
            }
            let k = match d.kind {
                DrawKind::Field { accept, chal, coeff, .. } => {
                    format!(" F({chal:?},{coeff},{})", if accept { "A" } else { "R" })
                }
                DrawKind::Bits { bits, purpose, .. } => format!(" B({purpose:?},{bits})"),
            };
            line.push_str(&k);
        }
        eprintln!("{line}");
        eprintln!(
            "total perms {}, chal {}, width {}, pvs {}",
            sched.perms.len(),
            sched.flushes.iter().map(|f| f.n_blocks).sum::<usize>(),
            proof.opened_values.trace_local.len(),
            pvs.len()
        );
    }

    /// Shape sanity: one collapsed root per commitment (the per-path
    /// root-landing asserts live inside `walk_path` and fire during
    /// every `walk`), all keccak perms internally consistent, and the
    /// lane fits 2^16 with the collapse overhead included.
    #[test]
    fn schedule_shape() {
        let (_, pvs, proof) = shared();
        let sched = walk(proof, pvs);
        assert_eq!(sched.roots.len(), sched.caps.len());
        assert_eq!(sched.caps.len(), 2 + sched.betas.len());
        for (i, p) in sched.perms.iter().enumerate() {
            assert_eq!(keccakf(&p.input), p.output, "perm {i} input/output");
        }
        // Authoritative lane budget: the recorded schedule must LOWER into the
        // 2^16-row leaf rectangle, i.e. `lane_plan` perms × 24 ≤ 2^16 (2,730
        // perms). NOTE: `sched.perms.len()` is the recorder's raw working set — a
        // SUPERSET of the rectangle (cap-extension/collapse perms fold into the
        // query program, and lane_plan adds trailer + flush-2-duplicate blocks),
        // so it is NOT the fit metric. B″ (issue #41) q21: 2,756 recorder perms
        // but 2,485 lane perms → 2^16 (was 2,382 lane perms at q20). Cross-checked
        // by `m4gate::tests::b2prime_fitcheck_leaf_2p16` and build_gate_trace's own
        // height assert.
        let rect_perms = crate::m4gate::lane_plan(&sched, &crate::m4gate::GateShape::narrow()).0.len();
        assert!(
            rect_perms * 24 <= 65_536,
            "leaf rectangle overflow: {rect_perms} lane perms (2^16 cap = 2,730 perms)"
        );
        eprintln!(
            "schedule: {} recorder perms → {} lane perms (native {:?}), {} flushes, {} draws",
            sched.perms.len(),
            rect_perms,
            sched.native_counts,
            sched.flushes.len(),
            sched.draws.len(),
        );
    }
}
