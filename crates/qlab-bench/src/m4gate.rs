//! M4 step 0b(ii) increment 4: the GATE RECTANGLE — one AIR that verifies
//! a real M3 consensus proof's complete FRI/PCS opening layer.
//!
//! Composes the keccak lane (stock p3-keccak-air through the LaneBuilder),
//! the ext-mul/ext-add banks, and the inc-2/3 routing/FS machinery into a
//! single 2^16-row rectangle driven by the Stage-1 recorder's schedule
//! (`m4gaterec::walk`), with every gate column BOUND — the prover cannot
//! choose which rows route, draw, or fold.
//!
//! # What is verified in-circuit
//!
//! - **Transcript**: the full `HashChallenger<u8, Keccak256, 32>` byte
//!   stream. Flush blocks are lane perms; block 0 of each flush starts
//!   from the zero state (preimage = message, directly readable); interior
//!   blocks XOR-absorb, so their message words are recovered bit-wise
//!   (witnessed preimage/previous-output bits, cross-checked against the
//!   lane's 16-bit limbs) — the XOR register file. Every observed byte is
//!   bound: caps and inner public values to OUTER public values, zeta
//!   openings and the final poly to the arithmetic that consumes them,
//!   degree bits / log-arities / padding to constants. Chaining (flush
//!   k+1's first 32 bytes = flush k's digest) is a perm-boundary limb
//!   equality, exactly inc-3's chain gate.
//! - **Fiat–Shamir**: the inc-3 draw gadget (2 rows/draw, mask-31,
//!   reject-if->=p) extended with the `sample_bits` variant (mask to n
//!   bits, no rejection; the PoW draw must be zero, the 20 query-index
//!   draws load the index registers). A 29-slot one-hot GROUP ring walks
//!   [alpha, zeta, fri_alpha, beta0..3, pow, idx0..19, DONE]; a 4-slot
//!   COEF ring assembles 4 accepted draws into one 4-limb ext challenge
//!   (rejected draws advance nothing — the native redraw). The
//!   refill/observe interlock (NEED = "required group complete",
//!   FSFULL = "all 8 window draws taken") pins the flush schedule to the
//!   native lazy-flush automaton, and the last-row anchor (all 20 query
//!   blocks completed) forces the whole program to execute.
//! - **Merkle openings**: leaf sponges (overwrite mode: fresh rate limbs
//!   are the routed opened values, carried limbs equal the previous
//!   output — per-role fresh counts), path compressions whose chained
//!   child is muxed by the query-index bit for that level, and the final
//!   level compared against the committed CAP (outer public values, 8-way
//!   mux on index bits 19..21 — uniform across batches because
//!   cum_arity + tree_height = 22 for every batch). No cap collapse and
//!   no cap-extension perms: with the cap public, comparing against the
//!   selected cap element is free.
//! - **FRI arithmetic**: running fri_alpha-power sums over the transcript
//!   zeta openings (S0/S1/S2 + alpha offsets captured at fixed stream
//!   positions), per-query leaf sums (PX), the reduced opening
//!   ro = inv_z(S0-PX0) + inv_zn(S1-a^617 PX0) + inv_z(S2-a^1234 PX2),
//!   binary-fold decomposition per commit round (B_{l+1} = 2 B_l^2 ladder,
//!   one degree-<=5 constraint per fold pair), and the final-poly Horner
//!   evaluation compared against the last folded value. Inverses are
//!   witnessed and checked (x * x^-1 = 1, one mul row each) — cheaper at
//!   equal soundness than the layout doc's 60-element product chain
//!   (~180 rows); the chain only saves prover FIELD work, which the
//!   witness generator does natively anyway.
//! - **Canonicity** (the inc-2 deferral, closed): leaf-side word aliases
//!   (v vs v+p byte encodings) change the leaf digest and die on the
//!   public cap — the digest binding inc-2 predicted. Transcript-side
//!   value words (zeta openings, final poly) are NOT digest-protected —
//!   an alias there is a free FS grinding bit — so every consumed word
//!   carries an explicit < p comparator (top-byte bit decomposition +
//!   nonzero-witness, the FS gadget's comparator generalized to 32 bits).
//!   Outer public values are canonical by interface contract; the PoW
//!   witness word is left free (an alias is just another grind candidate
//!   and still pays the 2^-20 check).
//!
//! # What is NOT yet in the rectangle
//!
//! The quotient-identity half of the verifier (evaluating the inner AIR's
//! 873 symbolic constraints at zeta and checking the quotient relation --
//! alpha's consumer, priced by step 0b(i)'s constraint-DAG census) is not
//! wired; the rectangle verifies the complete PCS/FRI opening layer. That
//! subsystem is mechanical bank work (the 0b(i) DAG walk gives the exact
//! op list) and is the stated remainder for the tree prototype.
//!
//! # Degree discipline
//!
//! Max constraint degree 5 (quotient degree 4, four chunks — the same
//! shape the M3 consensus bucket ships). This is a deliberate relaxation
//! of inc-2/3's degree-3 discipline: at degree 5 the gate products
//! (selector x step-flag x content) need no materialization columns, and
//! the M3 precedent already priced 4-chunk quotients at the consensus
//! config.

use std::collections::HashMap;
use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_uni_stark::{prove, verify};

use crate::m4gaterec::{
    self, digest_lanes, keccakf, BatchTag, ChalTag, CompressTag, DrawKind, LeafTag, Role,
    Schedule, CONSENSUS_CFG,
};
use crate::m4skel::LaneBuilder;
use crate::{make_config_with, pc_len, FriCfg, Val, RUNS};

pub(crate) type Ext = BinomialExtensionField<Val, 4>;

// ---------------------------------------------------------------------------
// Fixed shape constants (ground truth from the Stage-1 recorder; the
// lowering asserts the live schedule matches them).
// ---------------------------------------------------------------------------

/// KoalaBear modulus.
const P: u32 = 0x7f00_0001;
/// KoalaBear extension: x^4 - 3.
const EXT_W: u32 = 3;

/// Inner trace width (opened row length).
const TW: usize = 617;
/// Quotient opened words (4 chunks x 4 base values).
const QW: usize = 16;
/// Inner public values.
const N_PVS: usize = 84;
/// Queries and index bits. DERIVED from `CONSENSUS_CFG.num_queries` (not
/// hardcoded), mirroring `GRIND_BITS` below — B″ (issue #41) bumped it 20 → 21
/// to restore ~100-bit conjectured under the 2197-corrected accounting, and
/// this tracks automatically so the narrow const chain (IDXR width, GRP ring,
/// QSEL counter, and thus `GATE_WIDTH`) can never silently drift from the
/// config that actually produces the M3 proof the leaf gate verifies. A query
/// bump changes the FS transcript AND the rectangle shape (the #22/B′ lesson).
const NQ: usize = CONSENSUS_CFG.num_queries;
const LOG_MAX: usize = 22;
/// Query-PoW grind bits: the PoW draw's low GRIND_BITS bits must be zero.
/// DERIVED from `CONSENSUS_CFG.grind_bits` (not hardcoded) so the gate's
/// in-circuit PoW replay can never silently drift from the config that
/// actually grinds the inner M3 proof — B′ (issue #22) bumped it 20 → 22 and
/// this tracks automatically. (The PoW byte-packing gadget loops
/// `grind_bits - 16` times, so a mismatch would desync the recorded schedule.)
const GRIND_BITS: usize = CONSENSUS_CFG.grind_bits;
/// Fold rounds: log arities and cumulative shifts.
const LOG_ARITIES: [usize; 4] = [4, 4, 4, 2];
const CUM: [usize; 5] = [0, 4, 8, 12, 14];
/// Native path levels per batch (tree height - cap height 3).
const PATH_LEVELS: [usize; 6] = [19, 19, 15, 11, 7, 5];
/// Leaf absorb blocks per batch: (fresh word counts per block).
/// trace: 18 x 34 + 5; quot: 16; fold r<3: 34 + 30; fold3: 16.
const N_CAPS: usize = 6;
const CAP_LEN: usize = 8;

/// Observation flush block counts (F0..F7).
const FLUSH_BLOCKS: [usize; 8] = [5, 3, 148, 3, 3, 3, 3, 3];
/// Flush message byte lengths (F0 has no 32-byte chain prefix).
const FLUSH_BYTES: [usize; 8] = [604, 288, 20_032, 288, 288, 288, 288, 308];

/// Draw groups: 0 alpha, 1 zeta, 2 fri_alpha, 3..7 beta0..3, 7 pow,
/// 8..(8+NQ) idx0..(NQ-1), then DONE. G_DONE / N_GROUPS derive from NQ so a
/// query bump (B″, issue #41) shifts the DONE slot and widens the GRP ring
/// automatically (matches `GateShape::n_groups()` = 5 + n_fri_rounds + nq).
const G_ALPHA: usize = 0;
const G_ZETA: usize = 1;
const G_FRIALPHA: usize = 2;
const G_BETA0: usize = 3;
const G_POW: usize = 7;
const G_IDX0: usize = 8;
const G_DONE: usize = G_IDX0 + NQ;
const N_GROUPS: usize = G_DONE + 1;
/// Field-draw challenge count (alpha, zeta, fri_alpha, betas).
const N_CHALS: usize = 7;

/// GROUPREQ per flush-ring entry: the GROUP-ring head that must be present
/// at the last block of the *producing* obs flush F(k-1) before obs flush
/// F(k) may start (k = ring head = next unstarted obs flush). F0 starts at
/// row 0 (never via the boundary rule).
///
/// Timing note (the inc-4 correction): draws are hosted on the *consumer*
/// flush's block 0 -- its chained preimage[0..16] == the producer's digest,
/// so the FS gadget squeezes the producer's digest right there. The group
/// that gates F(k) is therefore drawn *during* F(k)'s own block 0 and is
/// never "complete" before F(k) starts. What is invariant is that exactly
/// k-1 groups have been drawn by the last block of F(k-1): the head is at
/// group k-1. Hence GROUPREQ[k] = k-1 for k = 1..7 (alpha .. beta3), which
/// the honest witness reproduces (see `need`, ~line 1803). The EXH entry
/// keeps G_DONE: it is read only at F7's last block, where the head == 7
/// != DONE, so NEEDL == 0 there and the post-F7 refill gate (which requires
/// NEEDL == 0) still holds.
const GROUPREQ: [usize; 9] = [
    usize::MAX, // F0: unreachable via boundary
    G_ALPHA,
    G_ZETA,
    G_FRIALPHA,
    G_BETA0,
    G_BETA0 + 1,
    G_BETA0 + 2,
    G_BETA0 + 3,
    G_DONE, // EXH
];
const N_FLUSH_ENTRIES: usize = 9; // F0..F7 + EXH

/// Query program length in perms (per query).
const QSLOTS: usize = 103;

// ---------------------------------------------------------------------------
// Inner-proof shape (M4 step 1 stage 2: narrow leaf vs wide interior)
// ---------------------------------------------------------------------------

/// The shape parameters of the *inner* proof this verifier circuit checks.
///
/// The uni-stark FRI verification algorithm is identical for the M3 *narrow*
/// consensus proof (what the leaf gate verifies) and a leaf's *wide* proof
/// (what an aggregation interior node verifies) — only these shape numbers
/// differ. `narrow()` reproduces the const block above verbatim (the shipped
/// leaf gate); `wide()` is the interior target, read from `m4treerec` /
/// `docs/m4tree-step1a-run1.md`. Everything downstream (`GateLayout`, the
/// column-offset chain, `eval`, `qprogram`, `lane_plan`) is being migrated to
/// read this struct instead of the top-of-file `const`s — see
/// `docs/m4-interior-circuit-stage2-plan.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GateShape {
    /// Inner trace width = opened row length (`TW`).
    pub(crate) tw: usize,
    /// Quotient opened base values per query (`QW`).
    pub(crate) qw: usize,
    /// Inner public values (`N_PVS`).
    pub(crate) n_pvs: usize,
    /// FRI queries + index-bit count (`NQ`).
    pub(crate) nq: usize,
    /// Index bit width = log2(inner LDE domain) = inner degree_bits + log_blowup
    /// (`LOG_MAX`).
    pub(crate) log_max: usize,
    /// Query-PoW grind bits (`GRIND_BITS`).
    pub(crate) grind_bits: usize,
    /// Per-round FRI fold log-arities (`LOG_ARITIES`).
    pub(crate) log_arities: Vec<usize>,
    /// Merkle cap size 2^cap_height (`CAP_LEN`).
    pub(crate) cap_len: usize,
    /// Inner-proof FRI blowup bits: `log_max = inner_degree_bits + log_blowup`.
    /// Narrow M3 commits at b16 (`log_blowup = 4`, inner deg bits 18); wide
    /// leaf commits at b4 (`log_blowup = 2`, inner deg bits 16). Drives
    /// `g_trace = two_adic_generator(log_max - log_blowup)`.
    pub(crate) log_blowup: usize,
    /// Whether this shape hosts the interior merge lane (棒 3): the `wide()`
    /// interior appends a keccak merge sponge over the two children's opvs and
    /// needs the merge region-pin / sponge-phase / digest-carry columns. The
    /// shipped leaf `narrow()` never merges, so its layout omits them entirely →
    /// narrow gate_width unchanged → byte-identical.
    pub(crate) merge_lane: bool,
}

impl GateShape {
    /// The M3 narrow consensus proof — the shipped leaf gate. Reproduces the
    /// const block above verbatim.
    pub(crate) fn narrow() -> Self {
        Self {
            tw: 617,
            qw: 16,
            n_pvs: 84,
            nq: NQ, // = CONSENSUS_CFG.num_queries (q21 post-B″, issue #41)
            log_max: 22,
            grind_bits: GRIND_BITS, // = CONSENSUS_CFG.grind_bits (g22 post-B′)
            log_arities: vec![4, 4, 4, 2],
            cap_len: 8,
            log_blowup: 4, // b16
            merge_lane: false,
        }
    }

    /// A leaf's wide `VerifierGateAir` proof (2^16 x 3,626, committed at the
    /// aggregation config b4/q40/g22/fp16/a16 — g22 post-B′) — the interior
    /// node's inner proof. Values from `m4treerec::AGG_CFG` + `docs/m4tree-step1a-run1.md`:
    /// 3,626-col rows, 40 queries, 8 quotient words, 3 arity-16 FRI rounds,
    /// inner LDE 2^(16+2)=2^18, and inner public values = the leaf gate's own
    /// outer public-value count `N_OPVS` (852 = 6*8*16 + 84).
    pub(crate) fn wide() -> Self {
        Self {
            // The interior verifies a LEAF proof whose committed trace width is
            // the narrow gate rectangle width. Derive it (not hardcode 3626) so
            // any gate-column addition — csel (2b), degree-reduction cols, merge
            // cols (棒 3) — auto-tracks into the interior's opened-row width.
            tw: GATE_WIDTH,
            qw: 8,
            n_pvs: N_OPVS, // the leaf gate's opvs become the interior's inner PVs
            nq: crate::m4treerec::AGG_CFG.num_queries, // = leaf lane queries (q43 post-B″, issue #41)
            log_max: 18,
            grind_bits: crate::m4treerec::AGG_CFG.grind_bits, // g22 post-B′ (derived from the leaf's config)
            log_arities: vec![4, 4, 4],
            cap_len: 8,
            log_blowup: 2, // b4 (AGG_CFG)
            merge_lane: true,
        }
    }

    /// Merge-lane permutation count (棒 3): child-L opvs sponge + child-R opvs
    /// sponge + one root perm. Each child sponge hashes that child's OWN opvs =
    /// the interior's inner public values (`n_pvs` — e.g. the leaf's 852), NOT
    /// the interior's outer `n_opvs`; `n_pvs·4` bytes at rate 136 (pad10*1 →
    /// `bytes/136 + 1` blocks). 0 for shapes without a merge lane. Must equal
    /// `m4interior::merge_perm_inputs(..).len()`.
    pub(crate) fn merge_perms(&self) -> usize {
        if !self.merge_lane {
            return 0;
        }
        let blocks = self.n_pvs * 4 / 136 + 1;
        2 * blocks + 1
    }

    /// Number of FRI commit-phase rounds.
    pub(crate) fn n_fri_rounds(&self) -> usize {
        self.log_arities.len()
    }

    /// Commitment caps: trace + quotient + one per FRI round (`N_CAPS`).
    pub(crate) fn n_caps(&self) -> usize {
        2 + self.n_fri_rounds()
    }

    /// Merkle cap height = log2(cap_len).
    pub(crate) fn cap_height(&self) -> usize {
        self.cap_len.trailing_zeros() as usize
    }

    /// Cumulative fold shifts with a leading 0 (`CUM`): len = n_rounds + 1.
    pub(crate) fn cum(&self) -> Vec<usize> {
        let mut c = Vec::with_capacity(self.n_fri_rounds() + 1);
        let mut acc = 0;
        c.push(0);
        for &a in &self.log_arities {
            acc += a;
            c.push(acc);
        }
        c
    }

    /// Native Merkle path levels per batch = tree height - cap height
    /// (`PATH_LEVELS`): trace, quotient (both at the LDE domain), then one per
    /// FRI round at its folded domain.
    pub(crate) fn path_levels(&self) -> Vec<usize> {
        let ch = self.cap_height();
        let cum = self.cum();
        let mut pl = vec![self.log_max - ch, self.log_max - ch];
        for r in 0..self.n_fri_rounds() {
            pl.push(self.log_max - cum[r + 1] - ch);
        }
        pl
    }

    // -- shape-varying transcript / draw-schedule counts (derived per
    //    docs/m4-1b-wide-params-investigation.md; each reproduces its narrow
    //    module const, verified by `gate_shape_derived_counts_narrow`). --

    /// Field-draw challenges: alpha, zeta, fri_alpha, one beta per round
    /// (`N_CHALS` = 3 + n_fri_rounds).
    pub(crate) fn n_chals(&self) -> usize {
        3 + self.n_fri_rounds()
    }

    /// Draw-group ring size: alpha, zeta, fri_alpha, betas, pow, then `nq` index
    /// groups + DONE (`N_GROUPS` = 5 + n_fri_rounds + nq).
    pub(crate) fn n_groups(&self) -> usize {
        5 + self.n_fri_rounds() + self.nq
    }

    /// PoW draw-group index (`G_POW` = 3 + n_fri_rounds).
    pub(crate) fn g_pow(&self) -> usize {
        3 + self.n_fri_rounds()
    }

    /// First query-index draw-group (`G_IDX0` = 4 + n_fri_rounds).
    pub(crate) fn g_idx0(&self) -> usize {
        4 + self.n_fri_rounds()
    }

    /// DONE draw-group index (`G_DONE` = 4 + n_fri_rounds + nq).
    pub(crate) fn g_done(&self) -> usize {
        4 + self.n_fri_rounds() + self.nq
    }

    /// Query-program role selectors (`N_ROLES` = 9 + n_fri_rounds, from the
    /// per-round R_PLAST_F* vocabulary).
    pub(crate) fn n_roles(&self) -> usize {
        9 + self.n_fri_rounds()
    }

    /// Micro-code selectors (`N_MICROS` = 6 + 3·n_fri_rounds, from the per-round
    /// M_S / M_B / M_FHI families).
    pub(crate) fn n_micros(&self) -> usize {
        6 + 3 * self.n_fri_rounds()
    }

    /// Absorb-round selector width (`DRND` width = 2 + n_fri_rounds: T, Q,
    /// F0..F(n-1)).
    pub(crate) fn drnd_width(&self) -> usize {
        2 + self.n_fri_rounds()
    }

    /// M_FHI higher-round fold gates (`N_FHG` = Σ(2^(la−1)−1)).
    pub(crate) fn n_fhg(&self) -> usize {
        self.log_arities.iter().map(|&la| (1usize << (la - 1)) - 1).sum()
    }

    /// Flush-entry count = observation flushes + 1 EXH (`N_FLUSH_ENTRIES`
    /// = 5 + n_fri_rounds).
    pub(crate) fn n_flush_entries(&self) -> usize {
        (4 + self.n_fri_rounds()) + 1
    }

    /// Pre-padding challenger flush message byte lengths (`FLUSH_BYTES`), one
    /// per observation flush = 4 + n_fri_rounds entries: F0 (deg/trace-cap/PVs),
    /// F1 (quot cap), F2 (zeta openings), one per FRI-round cap, then the final
    /// (final-poly + log-arities + PoW). fp_len = 16 (fp16, both shapes).
    pub(crate) fn flush_bytes(&self) -> Vec<usize> {
        let n = self.n_fri_rounds();
        let cap = self.cap_len;
        let mut v = Vec::with_capacity(4 + n);
        v.push(12 + cap * 32 + self.n_pvs * 4); // F0
        v.push(32 + cap * 32); // F1 (quotient cap)
        v.push(32 + 16 * (2 * self.tw + self.qw)); // F2 zeta openings (16·opened/query)
        for _ in 0..n {
            v.push(32 + cap * 32); // FRI-round cap
        }
        v.push(32 + 16 * 16 + n * 4 + 4); // final
        v
    }

    /// Challenger flush block counts (`FLUSH_BLOCKS`): bytes/136 + 1 (rate 136,
    /// +1 for the always-present 10*1 pad).
    pub(crate) fn flush_blocks(&self) -> Vec<usize> {
        self.flush_bytes().iter().map(|&b| b / 136 + 1).collect()
    }

    /// Obs-shape selectors (`N_SHAPES_OBS`): one per distinct block mosaic —
    /// each obs flush contributes its block count, except the zeta-opening flush
    /// (index 2) whose uniform interior collapses first/mid/last → 3.
    pub(crate) fn n_shapes_obs(&self) -> usize {
        self.flush_blocks()
            .iter()
            .enumerate()
            .map(|(f, &blk)| if f == 2 && blk >= 3 { 3 } else { blk })
            .sum()
    }

    /// Per-flush-entry required draw-group head (`GROUPREQ`): `groupreq[k] = k-1`
    /// for obs flushes 1..n_obs, and `g_done` for the trailing EXH entry.
    /// Length `n_flush_entries` (= n_obs + 1). Narrow `[MAX,0,1,2,3,4,5,6,G_DONE]`.
    pub(crate) fn groupreq(&self) -> Vec<usize> {
        let n_obs = self.n_obs_flushes();
        let mut v = Vec::with_capacity(n_obs + 1);
        v.push(usize::MAX);
        for k in 1..n_obs {
            v.push(k - 1);
        }
        v.push(self.g_done());
        v
    }

    /// Outer-PV offset of the D3 F0 digest = the cap-limb block's length.
    pub(crate) fn opv_f0dig(&self) -> usize {
        self.n_caps() * self.cap_len * 16
    }

    /// Outer-PV offset of the inner public values (`OPV_PVS` for narrow = 784):
    /// after the cap limbs AND the D3 F0 digest.
    pub(crate) fn opv_pvs(&self) -> usize {
        self.opv_f0dig() + F0DIG_LIMBS
    }

    /// Outer public-value count: `n_caps · cap_len · 16` cap limbs + the
    /// `F0DIG_LIMBS` F0 digest (D3) + `n_pvs` inner public values
    /// (`N_OPVS` for narrow = 768 + 16 + 84 = 868).
    pub(crate) fn n_opvs(&self) -> usize {
        self.opv_pvs() + self.n_pvs
    }

    /// Observation flush count = `4 + n_fri_rounds` (alpha, zeta, fri_alpha,
    /// one per FRI-round cap, and the final-poly/PoW flush). Narrow 8, wide 7.
    pub(crate) fn n_obs_flushes(&self) -> usize {
        4 + self.n_fri_rounds()
    }

    // -- shape-parametrized query-program micro / role codes (narrow reproduces
    //    the M_* / R_* module consts). Numbering: 6 fixed micros
    //    (NONE,X1,INV,RO,FIN,HORN) interleaved with the 3·n round-keyed families
    //    S/B/FHI, so `m_fin`/`m_horn` land right after `m_fhi(n-1)`. --

    /// Round `r` s-chain micro code (`M_S0..` = 4 + r).
    pub(crate) fn m_s(&self, r: usize) -> u32 {
        (4 + r) as u32
    }
    /// Round `r` B-ladder micro code (`M_B0..` = 4 + n + r).
    pub(crate) fn m_b(&self, r: usize) -> u32 {
        (4 + self.n_fri_rounds() + r) as u32
    }
    /// Round `r` higher-fold micro code (`M_FHI0..` = 4 + 2n + r).
    pub(crate) fn m_fhi(&self, r: usize) -> u32 {
        (4 + 2 * self.n_fri_rounds() + r) as u32
    }
    /// Final x_fin-chain micro code (`M_FIN` = 4 + 3n).
    pub(crate) fn m_fin(&self) -> u32 {
        (4 + 3 * self.n_fri_rounds()) as u32
    }
    /// Final-poly Horner micro code (`M_HORN` = 5 + 3n).
    pub(crate) fn m_horn(&self) -> u32 {
        (5 + 3 * self.n_fri_rounds()) as u32
    }
    /// Round `r` last-path role code (`R_PLAST_F0..` = 9 + r).
    pub(crate) fn r_plast_f(&self, r: usize) -> u32 {
        (9 + r) as u32
    }

    /// Fresh u32 words in the trace leaf's LAST absorb block = `tw mod 34`,
    /// with a full block (34) when `tw` is a rate multiple. Narrow 617 → 5
    /// (odd → high-half pad), wide 3626 → 22 (even → no pad). Drives the
    /// `R_ABS_C5` (trace-last) sponge-carry / asm-range machinery.
    pub(crate) fn trace_last_fresh(&self) -> usize {
        let m = self.tw % 34;
        if m == 0 {
            34
        } else {
            m
        }
    }

    /// Reduced-opening dup-phase capture geometry (slice 1b-B2).
    ///
    /// The F2-duplicate hash chain re-runs flush-2's zeta-value pipeline
    /// (`fri_alpha` is drawn from F2's digest, so the value accumulation must
    /// be replayed). Each opened value serializes to 4 u32 words; a keccak
    /// block absorbs the rate = 34 u32 words = 17 value-rows (the asm routes 2
    /// words/row); and flush-2's message opens with a 32-byte digest prefix (8
    /// words = 4 value-rows) that occupies dup block 0's rows 0..3, so values
    /// start at row 4. Hence after `v` values have been consumed the running
    /// index sits at global value-row `g = 4 + 2*v`, i.e. dup block `g/17`, row
    /// `g%17`. BLKCNT starts at `N = flush_blocks[2]` on dup block 0 and
    /// decrements one per block, so BLKCNT on that block reads `N - g/17`.
    ///
    /// Zeta openings = 3 groups: group 0 = trace_local (`tw` values), group 1 =
    /// trace_next (`tw` values), group 2 = quotient (`qw` values). The three
    /// group-boundary snapshots are therefore at cumulative value counts `tw`
    /// (A0), `2*tw` (A1) and `2*tw+qw` (A2, the chain end = block `N-1`).
    ///
    /// Returns `[(block, row_in_perm, blkcnt); 3]` = `[A0, A1, A2]`. Narrow
    /// (`tw=617,qw=16,N=148`) reproduces the old literals `A0=(72,14,76)`,
    /// `A1=(145,7,3)`, `A2=(147,5,1)`; wide (`tw=3626,qw=8,N=855`) yields
    /// `A0=(426,14,429)`, `A1=(853,7,2)`, `A2=(854,6,1)`.
    pub(crate) fn dup_captures(&self) -> [(usize, usize, u32); 3] {
        let n = self.flush_blocks()[2];
        let rpb = 17usize; // value-rows per absorb block (34 rate words / 2 words per row)
        let pre = 4usize; // flush-2's 32-byte digest prefix = 8 words = 4 value-rows
        let at = |v: usize| {
            let g = pre + 2 * v;
            (g / rpb, g % rpb, (n - g / rpb) as u32)
        };
        let caps = [at(self.tw), at(2 * self.tw), at(2 * self.tw + self.qw)];
        debug_assert_eq!(caps[2].0, n - 1, "A2 (end) capture must land on the last dup block");
        debug_assert_eq!(caps[2].2, 1, "A2 (end) capture BLKCNT must equal BLKLAST target");
        caps
    }

    /// Per-round fold-path source height `lf[r] = log_max - cum[r+1]` (the
    /// folded LDE domain log-height; narrow `[18,14,10,8]`).
    pub(crate) fn lf(&self) -> Vec<usize> {
        let cum = self.cum();
        (0..self.n_fri_rounds()).map(|r| self.log_max - cum[r + 1]).collect()
    }

    /// Block-index one-hot width (`BIDX` width): must give a distinct slot to
    /// every block of the largest flush that uses per-block `bidxsel` — i.e.
    /// every obs flush EXCEPT F2 (index 2), which is handled specially via
    /// `f2sel`+`blklast`. `= max(non-F2 flush_blocks) + 1` (the +1 is the
    /// saturation sink). Narrow: max(5,3,3,3,3,3,3)+1 = 6; wide F0=28 → 29.
    /// (Wide F0's 28 distinct-Pv blocks each need their own shsel selector, so
    /// bidx must address all of them — the 1b-B5 fix.)
    pub(crate) fn bidx_width(&self) -> usize {
        let fb = self.flush_blocks();
        let m = fb
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != 2)
            .map(|(_, &b)| b)
            .max()
            .unwrap_or(0);
        m + 1
    }

    /// Per-query program length in perms (`QSLOTS`): trace leaf+path, quotient
    /// leaf+path, and per fold round a leaf (4·2^la ext words) + path. Leaf
    /// perms = ceil(words/34) (keccak rate 34 u32 words/block).
    pub(crate) fn qslots(&self) -> usize {
        let ceil34 = |n: usize| (n + 33) / 34;
        let pl = self.path_levels();
        let mut q = ceil34(self.tw) + pl[0] + ceil34(self.qw) + pl[1];
        for (r, &la) in self.log_arities.iter().enumerate() {
            q += ceil34(4 * (1usize << la)) + pl[2 + r];
        }
        q
    }
}

// ---------------------------------------------------------------------------
// Word binding tables (transcript mosaics)
// ---------------------------------------------------------------------------

/// What one u32 word of a challenger block is bound to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum WordBind {
    /// Chain-digest word (bound by the chain gate at limb level; the word
    /// constraint is skipped).
    Chain,
    /// Constant word (degree bits, padding, log arities...).
    Const(u32),
    /// Cap word: OPV[i] + 2^16 * OPV[i+1] (two 16-bit cap limbs).
    Cap(usize),
    /// Inner public value word: OPV[i] (one u32 word whose value is the
    /// 16-bit pv chunk).
    Pv(usize),
    /// Zeta-opening / final-poly word: consumed by the asm pipeline
    /// (bound by consumption + the < p canonicity comparator).
    Val,
    /// Free word (PoW witness).
    Free,
}

/// Block shapes: the distinct challenger block roles. Blocks of one shape
/// share the same word mosaic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Shape {
    Obs { flush: usize, block: usize },
    /// F2 interior blocks 1..146 (uniform: 34 value words).
    F2Mid,
    /// Refill / trailer: pad32(digest) single-block flush.
    Refill,
}

/// Issue #24 (D3): the exposed F0-digest width, in u16 field limbs (a 32-byte
/// keccak digest, same encoding as the cap limbs and the 棒 3 merge root).
///
/// F0 is the challenger's FIRST observation flush — `deg_bits ‖ base_deg_bits ‖
/// preprocessed_width ‖ trace cap ‖ inner public values` — so its digest is a
/// commitment to the whole claimed public surface. It is exposed as public
/// values (issue #21's R2) and is non-hollow only because D3 also binds F0's
/// absorbed INPUT words to those same public values (see `eval`).
pub(crate) const F0DIG_LIMBS: usize = 16;

/// Outer public value layout: 6 caps x 8 digests x 16 limbs, the 16-limb F0
/// digest (D3), then the 84 inner public values.
///
/// The digest sits BETWEEN the caps and the inner PVs, not at the tail: the
/// 棒 3-3 epoch Σfee rider reads each child's fee as the LAST `EPOCH_FEE_LIMBS`
/// of its opvs half (M3 fee = the inner-PV tail = the opvs tail), an invariant
/// `m4interior`'s const-assert glues to the M3 layout. Appending f0dig would
/// have silently moved the fee off the tail.
pub(crate) const OPV_CAPS: usize = 0;
pub(crate) const OPV_F0DIG: usize = N_CAPS * CAP_LEN * 16;
pub(crate) const OPV_PVS: usize = OPV_F0DIG + F0DIG_LIMBS;
pub(crate) const N_OPVS: usize = OPV_PVS + N_PVS;

fn cap_limb_opv(cap: usize, digest: usize, limb: usize) -> usize {
    OPV_CAPS + (cap * CAP_LEN + digest) * 16 + limb
}

/// The word mosaic of one shape: 34 bindings (words 0..34).
/// `content_words` = words carrying message content (the rest is padding
/// already encoded as Const bindings).
pub(crate) fn shape_mosaic(shape: &GateShape, shape_kind: Shape) -> Vec<WordBind> {
    use WordBind::*;
    let flush_bytes = shape.flush_bytes();
    let flush_blocks = shape.flush_blocks();
    let n_obs = shape.n_obs_flushes();
    let final_f = n_obs - 1; // = 3 + n_fri_rounds (narrow 7, wide 6)
    let cap = shape.cap_len;
    let n_pvs = shape.n_pvs;
    let tw = shape.tw;
    let qw = shape.qw;
    // Inner-proof degree bits = log_max - log_blowup (narrow 18, wide 16).
    let deg_bits = (shape.log_max - shape.log_blowup) as u32;
    // OPV base of the inner public values (after the cap limbs and, since D3,
    // the exposed F0 digest).
    let opv_pvs = shape.opv_pvs();
    // Build the full flush content-word streams once, then slice.
    // Flush content words (chain prefix included for f > 0).
    let flush_words = |f: usize| -> Vec<WordBind> {
        let mut w = vec![];
        if f > 0 {
            w.extend([Chain; 8]);
        }
        let mv = |x: u32| crate::Val::from_u32(x).to_unique_u32();
        if f == 0 {
            w.push(Const(mv(deg_bits))); // degree bits (transcript encoding)
            w.push(Const(mv(deg_bits))); // base degree bits
            w.push(Const(mv(0))); // preprocessed width
            for d in 0..cap {
                for l in 0..8 {
                    w.push(Cap(cap_limb_opv(0, d, 2 * l)));
                }
            }
            // All n_pvs inner public values ride F0's content stream and are
            // distributed across F0's blocks by pad_words + block slicing
            // below (narrow 84 over 5 blocks, wide 852 over 28).
            for i in 0..n_pvs {
                w.push(Pv(opv_pvs + i));
            }
        } else if f == 1 {
            for d in 0..cap {
                for l in 0..8 {
                    w.push(Cap(cap_limb_opv(1, d, 2 * l)));
                }
            }
        } else if f == 2 {
            // Zeta openings: 2 opened rows (tw values each) + qw quotient
            // values, 4 words per ext value: 4*(2*tw + qw) words.
            w.extend(std::iter::repeat(Val).take(4 * (2 * tw + qw)));
        } else if f == final_f {
            w.extend(std::iter::repeat(Val).take(64)); // final poly (16 ext, fp16)
            for &la in &shape.log_arities {
                w.push(Const(mv(la as u32)));
            }
            w.push(Free); // pow witness
        } else {
            // FRI-round cap flushes (obs flush f in 3..final_f):
            // commitment 2 + (f - 3).
            let c = 2 + (f - 3);
            for d in 0..cap {
                for l in 0..8 {
                    w.push(Cap(cap_limb_opv(c, d, 2 * l)));
                }
            }
        }
        assert_eq!(w.len() * 4, flush_bytes[f], "flush {f} byte count");
        w
    };
    let pad_words = |content: &[WordBind], msg_bytes: usize, blocks: usize| -> Vec<WordBind> {
        // Append the 10*1 padding as Const words over the padded tail.
        let total_words = blocks * 34;
        let mut w = content.to_vec();
        // 0x01 at msg_bytes (word-aligned in this schedule: all flush
        // lengths are multiples of 4).
        assert_eq!(msg_bytes % 4, 0);
        assert_eq!(w.len() * 4, msg_bytes);
        let last = total_words - 1;
        while w.len() < total_words {
            w.push(Const(0));
        }
        let first_pad = msg_bytes / 4;
        if first_pad == last {
            w[last] = Const(0x8000_0000 | 0x01);
        } else {
            w[first_pad] = Const(0x01);
            w[last] = Const(0x8000_0000);
        }
        w
    };
    match shape_kind {
        Shape::Obs { flush, block } => {
            let content = flush_words(flush);
            let padded = pad_words(&content, flush_bytes[flush], flush_blocks[flush]);
            padded[block * 34..(block + 1) * 34].to_vec()
        }
        Shape::F2Mid => {
            // words 34..68 of flush 2 == uniform Val x34 (any interior
            // block; asserted uniform below).
            let content = flush_words(2);
            let padded = pad_words(&content, flush_bytes[2], flush_blocks[2]);
            let mid = padded[34..68].to_vec();
            for b in 1..flush_blocks[2] - 1 {
                assert!(
                    padded[b * 34..(b + 1) * 34].iter().all(|x| *x == Val),
                    "F2 interior must be uniform"
                );
            }
            assert!(mid.iter().all(|x| *x == Val));
            mid
        }
        Shape::Refill => {
            let mut w = vec![Chain; 8];
            w.push(Const(0x01));
            while w.len() < 34 {
                w.push(Const(0));
            }
            w[33] = Const(0x8000_0000);
            w
        }
    }
}

/// The distinct shapes that get selector columns: F0B0..B4, F1B0..B2,
/// F2B0 + F2Mid + F2Blast, F3..F6 B0..B2, F7B0..B2, Refill.
pub(crate) fn shape_list(shape: &GateShape) -> Vec<Shape> {
    let fb = shape.flush_blocks();
    let n_obs = shape.n_obs_flushes();
    let mut v = vec![];
    for b in 0..fb[0] {
        v.push(Shape::Obs { flush: 0, block: b });
    }
    for b in 0..fb[1] {
        v.push(Shape::Obs { flush: 1, block: b });
    }
    v.push(Shape::Obs { flush: 2, block: 0 });
    v.push(Shape::F2Mid);
    v.push(Shape::Obs {
        flush: 2,
        block: fb[2] - 1,
    });
    for f in 3..n_obs {
        for b in 0..fb[f] {
            v.push(Shape::Obs { flush: f, block: b });
        }
    }
    v.push(Shape::Refill);
    v
}


/// SHSEL slot of shape_list()[i] (Refill has its own column). Identity: the
/// list is emitted in slot order, so no shape geometry is needed here.
fn shsel_index_of(i: usize) -> usize {
    i
}

pub(crate) fn n_shapes(shape: &GateShape) -> usize {
    shape_list(shape).len() // narrow 27
}

// ---------------------------------------------------------------------------
// Column map. Chained offsets; every block documented at its definition.
// ---------------------------------------------------------------------------

/// Ext-mul bank: a[0..4] b[4..8] c[8..12].
pub(crate) const MUL_OFF: usize = NUM_KECCAK_COLS;
/// Ext-add bank: a[0..4] b[4..8] c[8..12].
pub(crate) const ADD_OFF: usize = NUM_KECCAK_COLS + 12;
/// Gate block base.
const GB: usize = NUM_KECCAK_COLS + 24;

// -- routed words + canonicity ------------------------------------------------
/// Routed word values for this row's two u32 words (limbs 4r..4r+2 and
/// 4r+2..4r+4): direct blocks read the replicated preimage, XOR blocks
/// the recovered message.
const W0C: usize = GB;
const W1C: usize = W0C + 1;
/// Canonicity: hi-limb bit decomposition per word (16 bits each), the
/// top-7 partial products, and low-part nonzero witnesses. Active on
/// value-consuming rows only (asm carry rows).
const HB0: usize = W1C + 1; // 16
const HB1: usize = HB0 + 16; // 16
const TA0: usize = HB1 + 16; // hb8..11 product, word 0
const TOPA0: usize = TA0 + 1; // ta0 * hb12*hb13*hb14
const TA1: usize = TOPA0 + 1;
const TOPA1: usize = TA1 + 1;
const LBNZ0: usize = TOPA1 + 1; // low-byte-of-hi nonzero flag + inverse
const LBI0: usize = LBNZ0 + 1;
const LONZ0: usize = LBI0 + 1; // lo-limb nonzero flag + inverse
const LOI0: usize = LONZ0 + 1;
const LBNZ1: usize = LOI0 + 1;
const LBI1: usize = LBNZ1 + 1;
const LONZ1: usize = LBI1 + 1;
const LOI1: usize = LONZ1 + 1;

// -- XOR-absorb register file ------------------------------------------------
/// Previous perm's output limbs (rate), captured at the boundary into an
/// interior (XOR) block, held across its 24 rows.
const OREG: usize = LOI1 + 1; // 68
/// Witnessed preimage / previous-output bits for this row's 4 rate limbs.
const PBIT: usize = OREG + 68; // 64
const OBIT: usize = PBIT + 64; // 64

// -- FS draw gadget (inc-3 + sample_bits) -------------------------------------
const FSBITS: usize = OBIT + 64; // 16: draw-limb byte bits
const FSACC: usize = FSBITS + 16; // odd row: draw's low 16 bits
const FSP3A: usize = FSACC + 1;
const FSP3B: usize = FSP3A + 1;
const FST7: usize = FSP3B + 1;
const FSINV: usize = FST7 + 1;
const FSNZ: usize = FSINV + 1;
const FSACCEPT: usize = FSNZ + 1;
const FSGATE: usize = FSACCEPT + 1;
const FSODD: usize = FSGATE + 1; // fs * odd-row (materialized)
const FSFULL: usize = FSODD + 1; // per-perm: all 8 window draws taken

// -- draw scheduling ----------------------------------------------------------
/// 29-slot one-hot group ring (left-rotating; active group g reads
/// GRP[(29 - g) % 29]).
const GRP: usize = FSFULL + 1; // 29
const COEF: usize = GRP + N_GROUPS; // 4: ext coefficient ring
const CURCH: usize = COEF + 4; // 4: in-flight challenge limbs
const CROT: usize = CURCH + 4; // coef rotation gate
const GROT: usize = CROT + 1; // group rotation gate

// -- challenge / index registers ----------------------------------------------
const CHAL: usize = GROT + 1; // 7 x 4 (alpha, zeta, fri_alpha, beta0..3)
const FA2: usize = CHAL + 4 * N_CHALS; // fri_alpha^2
const ZNREG: usize = FA2 + 4; // zeta * g_trace
const IDXR: usize = ZNREG + 4; // NQ query indices (q21 post-B″)

// -- flush automaton ----------------------------------------------------------
const FRING: usize = IDXR + NQ; // 8-slot one-hot: current obs flush
const BLKCNT: usize = FRING + 8;
const BLKLAST: usize = BLKCNT + 1; // BLKCNT == 1 comparator + inverse
const BLKINV: usize = BLKLAST + 1;
const BIDX: usize = BLKINV + 1; // 6: block index one-hot, saturating
const CMPA: usize = BIDX + 6; // BLKCNT == N-block_A0 (zeta-vals group-0 end; narrow 76)
const CMPAI: usize = CMPA + 1;
const CMPB: usize = CMPAI + 1; // BLKCNT == N-block_A1 (group-1 end, F2-gated; narrow 3)
const CMPBI: usize = CMPB + 1;
const NEEDL: usize = CMPBI + 1; // BLKLAST * (required group reached)
const REFSEL: usize = NEEDL + 1; // refill/trailer perm flag
const SHSEL: usize = REFSEL + 1; // 26 obs-shape selectors

// -- phases / query scheduling --------------------------------------------
const N_SHAPES_OBS: usize = 26;
const PHC: usize = SHSEL + N_SHAPES_OBS;
const PHQ: usize = PHC + 1;
const QSEL: usize = PHQ + 1; // (NQ+1)-slot one-hot query counter (q21 → 22 slots)
const QCNT: usize = QSEL + NQ + 1; // query-slot countdown 103..1
const QCW: usize = QCNT + 1; // QCNT == 1 comparator + inverse
const QCWI: usize = QCW + 1;

// -- query program ring ---------------------------------------------------
const PR: usize = QCWI + 1; // 103 limbs, one 15-bit descriptor each
const PD: usize = PR + QSLOTS; // 15: head bit decomposition
const RSEL: usize = PD + 15; // 13 role selectors
const MLO: usize = RSEL + N_ROLES; // 8: micro-code low-3-bit selectors
const MHI: usize = MLO + 8; // 4: micro-code high-2-bit selectors
const MSEL: usize = MHI + 4; // 18 micro selectors
const DLO: usize = MSEL + N_MICROS; // 8: dparam low-3-bit selectors
const DHI: usize = DLO + 8; // 3: dparam bit-3..4 selectors
const DRND: usize = DHI + 3; // 6: absorb-round selectors (T,Q,F0..3)
const DBIT: usize = DRND + 6; // this perm's path direction bit
const GLC: usize = DBIT + 1; // chained-child-left gate (pathish * (1-dbit))
const GRC: usize = GLC + 1; // chained-child-right gate
const CAPS8: usize = GRC + 1; // 8: cap-element selectors (idx bits 19..21)

// -- per-query index bits ---------------------------------------------------
const IDXB: usize = CAPS8 + 8; // 22

// -- asm pipeline -----------------------------------------------------------
const CZ2: usize = IDXB + LOG_MAX; // F2 value-carry rows
const CZ7: usize = CZ2 + 1; // F7 final-poly-carry rows
const CF: usize = CZ7 + 1; // fold-leaf carry rows
const CX0: usize = CF + 1; // PX carry (word 0) rows
const CX1: usize = CX0 + 1; // PX carry (word 1) rows
const POS: usize = CX1 + 1; // 2: value-half position ring
const CONSZ: usize = POS + 2; // CZ2 * pos1 (zeta-value completion)
const CONSF: usize = CONSZ + 1; // CF * pos1 (fold-value completion)
const ASM0: usize = CONSF + 1; // captured value words 0..2
const ASM1: usize = ASM0 + 1;
const VC: usize = ASM1 + 1; // 16: value-counter one-hot (fold leaves)
const VCE: usize = VC + 16; // sum of even VC slots
const PBUF: usize = VCE + 1; // 4: previous (even) value buffer
const HIT: usize = PBUF + 4; // 1 iff current value index == idx_in_group
const GPB: usize = HIT + 1; // 4: this round's group-position index bits
const LFS: usize = GPB + 4; // leaf-start selector (per perm)

// -- running-sum / arithmetic registers (ext = 4 limbs) ------------------------
const PREG: usize = LFS + 1; // 4: running fri_alpha power
const PZACC: usize = PREG + 4; // 4: running sum (PZ in chal, PX in query)
const A0R: usize = PZACC + 4; // 4: running sum at group-0 end
const A1R: usize = A0R + 4;
const A2R: usize = A1R + 4;
const P0R: usize = A2R + 4; // preg at group-0 end = fri_alpha^tw (narrow ^617)
const P1R: usize = P0R + 4; // preg at group-1 end = fri_alpha^(2*tw) (narrow ^1234)
const PX0R: usize = P1R + 4; // trace-leaf PX
const FPREG: usize = PX0R + 4; // 16 x 4: final poly coefficients
const SCR: usize = FPREG + 64; // 8 x 4: fold scratch
const BREG: usize = SCR + 32; // 4 x 4: per-level fold coefficients
const INV2S: usize = BREG + 16; // witnessed 1/(2s)
const INVZ: usize = INV2S + 4;
const INVZN: usize = INVZ + 4;
const XREG: usize = INVZN + 4; // query LDE point x
const XFIN: usize = XREG + 4; // final-poly evaluation point
const RUNEV: usize = XFIN + 4; // running fold evaluation

// -- hash-transport duplicate of flush 2 (PZ pipeline host) --------------------
/// fri_alpha is drawn from flush 2's digest, so the zeta-opening values
/// cannot be consumed at flush 2's own rows. An N=flush_blocks[2]-block (narrow
/// 148) duplicate hash
/// chain placed after the trailer (once fri_alpha is registered) re-hashes
/// a witness message; its digest must equal the captured flush-2 digest,
/// which by collision resistance pins the message to the native one. The
/// value pipeline (and the < p canonicity comparator) runs on the
/// duplicate; flush 2's own interior blocks need no binding at all.
const F2DIG: usize = RUNEV + 4; // 16: flush-2 digest limbs
const PHD: usize = F2DIG + 16; // duplicate-phase flag
const CMPC: usize = PHD + 1; // BLKCNT == N=flush_blocks[2] comparator (dup first block; narrow 148)
const CMPCI: usize = CMPC + 1;
const CZD: usize = CMPCI + 1; // dup value-carry rows

// -- degree-reduction materialized products (Phase 1a) -----------------------
// Current-row materializations of high-degree gate products. Each is pinned by
// a global deg<=3 defining constraint in `eval` and filled by the derived-
// column pass in `build_gate_trace` (a pure function of already-filled current-
// row columns). Introduced to bring every constraint to deg <= 3 (the house
// rule since M1.5b) so the calibration bench runs at the consensus quotient
// degree rather than the deg-6 the raw flush automaton would force.
const CHLIVE: usize = CZD + 1; // phc * (1 - REFSEL)
const F2SEL: usize = CHLIVE + 1; // ringsel(2) * (1 - bidxsel(0))
const PG_A: usize = F2SEL + 1; // ringsel(7) * grpdone * phc
const PHG: usize = PG_A + 1; // phasegate = sf(23) * BLKLAST * PG_A
const PHDEND: usize = PHG + 1; // sf(23) * PHD * BLKLAST
const CONT: usize = PHDEND + 1; // sf(23) * phc * (1 - BLKLAST)
const EG_A: usize = CONT + 1; // phq * QCW * ring(QSEL, NQ-1)
const ENDG: usize = EG_A + 1; // endgate = sf(23) * EG_A
const XSEL: usize = ENDG + 1; // xorsel (current row)
const QADV: usize = XSEL + 1; // sf(23) * phq * QCW
const CFULL: usize = QADV + 1; // sf(23) * consumersel * (1 - FSFULL)
// Query-selector decode products (Phase 1a family 2): raw bit-products so the
// phq-gated selector defs (RSEL/MLO/DBIT) stay deg <= 3.
const M3: usize = CFULL + 1; // 8: 3-bit product PD10..12 (MLO without phq)
const RLO: usize = M3 + 8; // 4: PD0/PD1 pair products (RSEL low)
const RHI: usize = RLO + 4; // 4: PD2/PD3 pair products (RSEL high)
const DMUX: usize = RHI + 4; // dparam-selected idx-bit mux (DBIT)
const SNL: usize = DMUX + 1; // 4: M_S chain gate = msel * (1 - sf(lf)) per round
// Fold-pipeline decode/gate products (Phase 1a family 3).
const GLO: usize = SNL + 4; // 4: GPB0/GPB1 pair products (HIT low)
const GHI: usize = GLO + 4; // 4: GPB2/GPB3 pair products (HIT high)
const GF: usize = GHI + 4; // 4: round-0 fold gate = CONSF * DRND[2+rf]
const BPM: usize = GF + 4; // 4: extmul(BREG, PBUF - v) for the round-0 fold
const N_FHG: usize = 22; // M_FHI fold gates (3 rounds x 7 pairs + 1)
const FHG: usize = BPM + 4; // 22: M_FHI fold gate = msel_rf * sf(r)
const PREGA: usize = FHG + N_FHG; // 4: preg * fri_alpha (PX word-1 accumulation)
// Reduced-opening capture-phase gates (endpoint pin START): PHD·comparator so
// the A/P register captures (deg-1 use) stay deg <= 3.
const CPA: usize = PREGA + 4; // PHD·CMPA  (A0/P0 capture: dup block_A0; narrow 72)
const CPB: usize = CPA + 1; // PHD·CMPB  (A1/P1 capture: dup block_A1; narrow 145)
const CPL: usize = CPB + 1; // PHD·BLKLAST (A2 capture: dup last block N-1; narrow 147)
// Final-poly capture (endpoint pin END): FPI = 16-slot one-hot counter over the
// F7 final-poly coefficients; CONSZ7 = CZ7·POS1 its completion flag.
const CONSZ7: usize = CPL + 1; // CZ7 · POS1 (final-poly value completion)
const FPI: usize = CONSZ7 + 1; // 16: final-poly coefficient index one-hot
const CSEL: usize = FPI + 16; // 1: child-boundary re-anchor selector (2b)
const FRGM: usize = CSEL + 1; // 1: fring-rotation gate sf(23)·b0next (2b-iii)
const BCBD: usize = FRGM + 1; // 1: blkcnt update delta (2b-iii)
// -- interior per-child opvs routing (2d) ------------------------------------
// `CHI` is the running child selector (0 across child L's rows, 1 across child
// R's), derived from `csel` by a pinned transition (chi_next = chi + csel_next)
// with chi[0]=0. `CC` (cap_len cols) materializes `chi·caps8` so the cap
// comparison can select each child's OWN half of the doubled `opvsL ++ opvsR`
// public values at deg ≤ 3. Both are INERT for narrow / single-wide
// (n_children = 1): unpinned, unread, filled 0 — narrow byte-identical.
const CHI: usize = BCBD + 1; // 1: running child selector (interior only)
const CC: usize = CHI + 1; // CAP_LEN: materialized chi·caps8 (cap-half select)

// -- R1 (issue #21) canonicity binding ---------------------------------------
// Appended at the gate-block tail so no existing offset shifts. The consumed
// word Wxc is a field-reduced KoalaBear element (v and v+p collapse), so the
// `< p` comparator cannot act on Wxc directly; it acts on a range-FORCED 32-bit
// digit split. `HBx` (16 hi bits) already exist; `CANON_LOx` are the 16 lo bits,
// and `Wxc == Σ CANON_LOx·2^i + 2^16·Σ HBx·2^i` binds the split to the value.
// `TOP7_x` materializes "word bits 24..30 all set" at deg 3 (TOPAx·hb13·hb14),
// so the reject product `TOP7·lo_nonzero` stays deg 3. Active on casm value rows.
const CANON_LO0: usize = CC + CAP_LEN; // 16: word-0 low 16 bits
const CANON_LO1: usize = CANON_LO0 + 16; // 16: word-1 low 16 bits
const TOP7_0: usize = CANON_LO1 + 16; // word-0 bits 24..30 all-set flag
const TOP7_1: usize = TOP7_0 + 1; // word-1 bits 24..30 all-set flag

const GATE_COLS: usize = TOP7_1 + 1 - GB;
pub(crate) const GATE_WIDTH: usize = TOP7_1 + 1;

/// Runtime mirror of the column-offset chain above, computed from a
/// [`GateShape`] instead of the top-of-file `const`s. `from_shape(narrow())`
/// reproduces every const above byte-for-byte (asserted by
/// `gate_layout_narrow_reproduces_consts`); the eventual `wide()` layout drives
/// the interior verifier. Slice 1a-i-b of the stage-2 re-parametrization: this
/// struct exists and is verified, but `eval`/builders are migrated to read it
/// in slice 1a-ii (until then the fields are unused — hence `dead_code`).
///
/// Every shape-varying offset is now driven by `GateShape` methods (slice
/// 1b-1): `nq` (IDXR/QSEL), `log_max` (IDXB), `n_fhg` (FHG), and the derived
/// counts `n_groups`/`n_chals`/`n_roles`/`n_micros`/`n_shapes_obs`/`qslots`/
/// `drnd_width` (formulas + wide confirmation in
/// `docs/m4-1b-wide-params-investigation.md`). `from_shape(narrow())`
/// reproduces every const (test) and `from_shape(wide())` now produces the
/// correct wide *offsets*. **Still narrow-only (slice 1b-2+):** the AIR's
/// `eval` and the trace builders (`Regs`, `qprogram`, `gate_consts`,
/// `lane_plan`, `write_row`, `build_gate_trace`) still read the narrow module
/// consts and the narrow generators, so *building a wide trace* is not wired
/// yet — only the layout arithmetic is wide-ready.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct GateLayout {
    pub(crate) mul_off: usize,
    pub(crate) add_off: usize,
    pub(crate) gb: usize,
    pub(crate) w0c: usize,
    pub(crate) w1c: usize,
    pub(crate) hb0: usize,
    pub(crate) hb1: usize,
    pub(crate) ta0: usize,
    pub(crate) topa0: usize,
    pub(crate) ta1: usize,
    pub(crate) topa1: usize,
    pub(crate) lbnz0: usize,
    pub(crate) lbi0: usize,
    pub(crate) lonz0: usize,
    pub(crate) loi0: usize,
    pub(crate) lbnz1: usize,
    pub(crate) lbi1: usize,
    pub(crate) lonz1: usize,
    pub(crate) loi1: usize,
    pub(crate) oreg: usize,
    pub(crate) pbit: usize,
    pub(crate) obit: usize,
    pub(crate) fsbits: usize,
    pub(crate) fsacc: usize,
    pub(crate) fsp3a: usize,
    pub(crate) fsp3b: usize,
    pub(crate) fst7: usize,
    pub(crate) fsinv: usize,
    pub(crate) fsnz: usize,
    pub(crate) fsaccept: usize,
    pub(crate) fsgate: usize,
    pub(crate) fsodd: usize,
    pub(crate) fsfull: usize,
    pub(crate) grp: usize,
    pub(crate) coef: usize,
    pub(crate) curch: usize,
    pub(crate) crot: usize,
    pub(crate) grot: usize,
    pub(crate) chal: usize,
    pub(crate) fa2: usize,
    pub(crate) znreg: usize,
    pub(crate) idxr: usize,
    pub(crate) fring: usize,
    pub(crate) blkcnt: usize,
    pub(crate) blklast: usize,
    pub(crate) blkinv: usize,
    pub(crate) bidx: usize,
    pub(crate) bidx_width: usize,
    pub(crate) cmpa: usize,
    pub(crate) cmpai: usize,
    pub(crate) cmpb: usize,
    pub(crate) cmpbi: usize,
    pub(crate) needl: usize,
    pub(crate) refsel: usize,
    pub(crate) shsel: usize,
    pub(crate) phc: usize,
    pub(crate) phq: usize,
    pub(crate) qsel: usize,
    pub(crate) qcnt: usize,
    pub(crate) qcw: usize,
    pub(crate) qcwi: usize,
    pub(crate) pr: usize,
    pub(crate) pd: usize,
    pub(crate) rsel: usize,
    pub(crate) mlo: usize,
    pub(crate) mhi: usize,
    pub(crate) msel: usize,
    pub(crate) dlo: usize,
    pub(crate) dhi: usize,
    pub(crate) drnd: usize,
    pub(crate) dbit: usize,
    pub(crate) glc: usize,
    pub(crate) grc: usize,
    pub(crate) caps8: usize,
    pub(crate) idxb: usize,
    pub(crate) cz2: usize,
    pub(crate) cz7: usize,
    pub(crate) cf: usize,
    pub(crate) cx0: usize,
    pub(crate) cx1: usize,
    pub(crate) pos: usize,
    pub(crate) consz: usize,
    pub(crate) consf: usize,
    pub(crate) asm0: usize,
    pub(crate) asm1: usize,
    pub(crate) vc: usize,
    pub(crate) vce: usize,
    pub(crate) pbuf: usize,
    pub(crate) hit: usize,
    pub(crate) gpb: usize,
    pub(crate) lfs: usize,
    pub(crate) preg: usize,
    pub(crate) pzacc: usize,
    pub(crate) a0r: usize,
    pub(crate) a1r: usize,
    pub(crate) a2r: usize,
    pub(crate) p0r: usize,
    pub(crate) p1r: usize,
    pub(crate) px0r: usize,
    pub(crate) fpreg: usize,
    pub(crate) scr: usize,
    pub(crate) breg: usize,
    pub(crate) inv2s: usize,
    pub(crate) invz: usize,
    pub(crate) invzn: usize,
    pub(crate) xreg: usize,
    pub(crate) xfin: usize,
    pub(crate) runev: usize,
    pub(crate) f2dig: usize,
    pub(crate) phd: usize,
    pub(crate) cmpc: usize,
    pub(crate) cmpci: usize,
    pub(crate) czd: usize,
    pub(crate) chlive: usize,
    pub(crate) f2sel: usize,
    pub(crate) pg_a: usize,
    pub(crate) phg: usize,
    pub(crate) phdend: usize,
    pub(crate) cont: usize,
    pub(crate) eg_a: usize,
    pub(crate) endg: usize,
    pub(crate) xsel: usize,
    pub(crate) qadv: usize,
    pub(crate) cfull: usize,
    pub(crate) m3: usize,
    pub(crate) rlo: usize,
    pub(crate) rhi: usize,
    pub(crate) dmux: usize,
    pub(crate) snl: usize,
    pub(crate) glo: usize,
    pub(crate) ghi: usize,
    pub(crate) gf: usize,
    pub(crate) bpm: usize,
    pub(crate) n_fhg: usize,
    pub(crate) fhg: usize,
    pub(crate) prega: usize,
    pub(crate) cpa: usize,
    pub(crate) cpb: usize,
    pub(crate) cpl: usize,
    pub(crate) consz7: usize,
    pub(crate) fpi: usize,
    /// Child-boundary re-anchor selector (2b): 1 on the first row of each child's
    /// first perm (row 0 for single-child; row 0 and 24*nL for the two-child
    /// interior). Constraint-pinned (option B, completion-gated) so a prover
    /// cannot re-anchor mid-child. Appended last → narrow offsets unchanged.
    pub(crate) csel: usize,
    /// 2b-iii degree-reduction (deg-3 boundary carries): `frgm` = sf(23)·b0next
    /// (the fring-rotation gate), `bcbd` = the blkcnt update delta. Materialized
    /// so their `(1-csel_next)`-gated carries stay ≤ deg 3.
    pub(crate) frgm: usize,
    pub(crate) bcbd: usize,
    /// Interior per-child opvs routing (2d): `chi` = running child selector
    /// (0 = child L rows, 1 = child R rows), `cc` (cap_len cols) = materialized
    /// `chi·caps8` for the cap-half select. Inert for narrow / single-wide.
    pub(crate) chi: usize,
    pub(crate) cc: usize,
    /// Interior merge lane (棒 3-2), WIDE-ONLY (absent for narrow → gate_width
    /// unchanged → byte-identical). `mreg` = monotone merge-region flag (1 on the
    /// last `24·nm` rows, where the merge sponge perms sit); `mcnt` = running
    /// count of `mreg` pinned `== 24·nm` at `last_row`, positively forcing the
    /// region to be exactly those rows (so a prover cannot shrink/move it).
    pub(crate) mreg: usize,
    pub(crate) mcnt: usize,
    /// 棒 3-2b capacity chain (WIDE-ONLY). The merge is 3 independent sub-sponges
    /// (childL / childR / root) whose input capacity resets to 0 at each start
    /// and chains from the previous perm's output otherwise. `meq`/`minv` (3 pairs)
    /// are equality comparators pinning the sub-sponge-start rows via `mcnt ∈
    /// {1, 24·kL+1, 24·(kL+kR)+1}`; `mrst = Σ meq` (reset flag); `mcont` =
    /// materialized chain gate `sf(23)·mreg·(1−next mrst)` (keeps the chain deg ≤3).
    pub(crate) meq: usize,
    pub(crate) minv: usize,
    pub(crate) mrst: usize,
    pub(crate) mcont: usize,
    /// 棒 3-2c dL carry (WIDE-ONLY, 16 limbs): the child-L sub-sponge digest is
    /// produced ~kR perms before the root perm consumes it, so it is captured at
    /// the childL→childR boundary and freeze-carried to the root perm. (dR is
    /// adjacent to the root perm, bound directly by the boundary transition.)
    pub(crate) dlr: usize,
    /// Issue #24 (D0) merge-block one-hot selector ring (WIDE-ONLY, `merge_perms()`
    /// columns). `msh + p` fires on exactly merge perm `p`'s rows (0-indexed from
    /// the region start), so `eval` can bind merge perm `p`'s absorbed rate to
    /// `pv(opvs)` at the FIXED indices for block `p` — the constraint-level message
    /// binding (D1) that closes the PR #23/#25 keccak-preimage-resistance caveat.
    /// POSITIVELY pinned (unlike a `csel`-style self-destructing anchor): a one-hot
    /// `Σ msh == mreg` + start-edge anchor to slot 0 + forward rotation + a
    /// `when_last_row` anchor to the root slot, so DROPPING the ring (all-zero) is
    /// UNSAT (the last-row anchor fires), not a silent binding vanish.
    pub(crate) msh: usize,
    /// Materialized msh rotation gate `sf(23)·mreg·(1 − eq_end)` (WIDE-ONLY): fires
    /// at every in-region perm boundary except the root perm's last row, advancing
    /// the one-hot by one slot. Materialized so the rotation stays deg ≤ 3.
    pub(crate) mrot: usize,
    /// R1 (issue #21) canonicity binding (all shapes; gate-block tail). `canon_lo0`
    /// / `canon_lo1` = the 16 low bits of the consumed words 0/1; `top7_0` /
    /// `top7_1` = materialized "word bits 24..30 all set" flags. See the const
    /// chain above for the soundness argument.
    pub(crate) canon_lo0: usize,
    pub(crate) canon_lo1: usize,
    pub(crate) top7_0: usize,
    pub(crate) top7_1: usize,
    pub(crate) gate_cols: usize,
    pub(crate) gate_width: usize,
}

#[allow(dead_code)]
impl GateLayout {
    /// Compute the column layout for a given inner-proof shape. Mirrors the
    /// `const` chain (lines ~382–584) exactly; `from_shape(&GateShape::narrow())`
    /// == every const above.
    pub(crate) fn from_shape(s: &GateShape) -> GateLayout {
        let nq = s.nq;
        let log_max = s.log_max;
        let n_fhg = s.n_fhg();

        // -- keccak-adjacent banks + gate base --
        let mul_off = NUM_KECCAK_COLS;
        let add_off = NUM_KECCAK_COLS + 12;
        let gb = NUM_KECCAK_COLS + 24;
        // -- routed words + canonicity --
        let w0c = gb;
        let w1c = w0c + 1;
        let hb0 = w1c + 1;
        let hb1 = hb0 + 16;
        let ta0 = hb1 + 16;
        let topa0 = ta0 + 1;
        let ta1 = topa0 + 1;
        let topa1 = ta1 + 1;
        let lbnz0 = topa1 + 1;
        let lbi0 = lbnz0 + 1;
        let lonz0 = lbi0 + 1;
        let loi0 = lonz0 + 1;
        let lbnz1 = loi0 + 1;
        let lbi1 = lbnz1 + 1;
        let lonz1 = lbi1 + 1;
        let loi1 = lonz1 + 1;
        // -- XOR-absorb register file --
        let oreg = loi1 + 1;
        let pbit = oreg + 68;
        let obit = pbit + 64;
        // -- FS draw gadget --
        let fsbits = obit + 64;
        let fsacc = fsbits + 16;
        let fsp3a = fsacc + 1;
        let fsp3b = fsp3a + 1;
        let fst7 = fsp3b + 1;
        let fsinv = fst7 + 1;
        let fsnz = fsinv + 1;
        let fsaccept = fsnz + 1;
        let fsgate = fsaccept + 1;
        let fsodd = fsgate + 1;
        let fsfull = fsodd + 1;
        // -- draw scheduling --
        let grp = fsfull + 1;
        let coef = grp + s.n_groups();
        let curch = coef + 4;
        let crot = curch + 4;
        let grot = crot + 1;
        // -- challenge / index registers --
        let chal = grot + 1;
        let fa2 = chal + 4 * s.n_chals();
        let znreg = fa2 + 4;
        let idxr = znreg + 4;
        // -- flush automaton --
        let fring = idxr + nq; // IDXR width = nq
        let blkcnt = fring + 8;
        let blklast = blkcnt + 1;
        let blkinv = blklast + 1;
        let bidx = blkinv + 1;
        let bidx_width = s.bidx_width();
        let cmpa = bidx + bidx_width;
        let cmpai = cmpa + 1;
        let cmpb = cmpai + 1;
        let cmpbi = cmpb + 1;
        let needl = cmpbi + 1;
        let refsel = needl + 1;
        let shsel = refsel + 1;
        // -- phases / query scheduling --
        let phc = shsel + s.n_shapes_obs();
        let phq = phc + 1;
        let qsel = phq + 1;
        let qcnt = qsel + nq + 1;
        let qcw = qcnt + 1;
        let qcwi = qcw + 1;
        // -- query program ring --
        let pr = qcwi + 1;
        let pd = pr + s.qslots();
        let rsel = pd + 15;
        let mlo = rsel + s.n_roles();
        let mhi = mlo + 8;
        let msel = mhi + 4;
        let dlo = msel + s.n_micros();
        let dhi = dlo + 8;
        let drnd = dhi + 3;
        let dbit = drnd + s.drnd_width();
        let glc = dbit + 1;
        let grc = glc + 1;
        let caps8 = grc + 1;
        // -- per-query index bits --
        let idxb = caps8 + 8;
        // -- asm pipeline --
        let cz2 = idxb + log_max;
        let cz7 = cz2 + 1;
        let cf = cz7 + 1;
        let cx0 = cf + 1;
        let cx1 = cx0 + 1;
        let pos = cx1 + 1;
        let consz = pos + 2;
        let consf = consz + 1;
        let asm0 = consf + 1;
        let asm1 = asm0 + 1;
        let vc = asm1 + 1;
        let vce = vc + 16;
        let pbuf = vce + 1;
        let hit = pbuf + 4;
        let gpb = hit + 1;
        let lfs = gpb + 4;
        // -- running-sum / arithmetic registers --
        let preg = lfs + 1;
        let pzacc = preg + 4;
        let a0r = pzacc + 4;
        let a1r = a0r + 4;
        let a2r = a1r + 4;
        let p0r = a2r + 4;
        let p1r = p0r + 4;
        let px0r = p1r + 4;
        let fpreg = px0r + 4;
        let scr = fpreg + 64;
        let breg = scr + 32;
        let inv2s = breg + 16;
        let invz = inv2s + 4;
        let invzn = invz + 4;
        let xreg = invzn + 4;
        let xfin = xreg + 4;
        let runev = xfin + 4;
        // -- flush-2 duplicate --
        let f2dig = runev + 4;
        let phd = f2dig + 16;
        let cmpc = phd + 1;
        let cmpci = cmpc + 1;
        let czd = cmpci + 1;
        // -- degree-reduction materialized products --
        let chlive = czd + 1;
        let f2sel = chlive + 1;
        let pg_a = f2sel + 1;
        let phg = pg_a + 1;
        let phdend = phg + 1;
        let cont = phdend + 1;
        let eg_a = cont + 1;
        let endg = eg_a + 1;
        let xsel = endg + 1;
        let qadv = xsel + 1;
        let cfull = qadv + 1;
        let m3 = cfull + 1;
        let rlo = m3 + 8;
        let rhi = rlo + 4;
        let dmux = rhi + 4;
        let snl = dmux + 1;
        let glo = snl + 4;
        let ghi = glo + 4;
        let gf = ghi + 4;
        let bpm = gf + 4;
        let fhg = bpm + 4;
        let prega = fhg + n_fhg;
        let cpa = prega + 4;
        let cpb = cpa + 1;
        let cpl = cpb + 1;
        let consz7 = cpl + 1;
        let fpi = consz7 + 1;
        let csel = fpi + 16;
        let frgm = csel + 1;
        let bcbd = frgm + 1;
        let chi = bcbd + 1;
        let cc = chi + 1;
        // 棒 3-2 merge-lane columns, WIDE-ONLY: mreg + mcnt (3-2a region pin) +
        // meq[3]/minv[3]/mrst/mcont (3-2b capacity chain). narrow (merge_lane
        // false) adds 0 width and leaves the offsets unused (eval / fill touch
        // them only when n_children > 1, i.e. the wide interior).
        let mreg = cc + s.cap_len;
        let mcnt = mreg + 1;
        let meq = mcnt + 1;
        let minv = meq + 4;
        let mrst = minv + 4;
        let mcont = mrst + 1;
        let dlr = mcont + 1;
        // Issue #24 (D0): the merge-block one-hot ring (`msh`, one column per merge
        // perm) + its materialized rotation gate (`mrot`). WIDE-ONLY.
        let msh = dlr + 16;
        let mrot = msh + s.merge_perms();
        // mreg,mcnt,meq[4],minv[4],mrst,mcont,dlr[16] = 28; + msh[nm] + mrot.
        let merge_cols = if s.merge_lane { 28 + s.merge_perms() + 1 } else { 0 };
        // -- R1 (issue #21) canonicity binding, gate-block tail --
        let canon_lo0 = cc + s.cap_len + merge_cols;
        let canon_lo1 = canon_lo0 + 16;
        let top7_0 = canon_lo1 + 16;
        let top7_1 = top7_0 + 1;
        let gate_cols = top7_1 + 1 - gb;
        let gate_width = top7_1 + 1;

        GateLayout {
            mul_off, add_off, gb, w0c, w1c, hb0, hb1, ta0, topa0, ta1, topa1,
            lbnz0, lbi0, lonz0, loi0, lbnz1, lbi1, lonz1, loi1, oreg, pbit, obit,
            fsbits, fsacc, fsp3a, fsp3b, fst7, fsinv, fsnz, fsaccept, fsgate,
            fsodd, fsfull, grp, coef, curch, crot, grot, chal, fa2, znreg, idxr,
            fring, blkcnt, blklast, blkinv, bidx, bidx_width, cmpa, cmpai, cmpb, cmpbi, needl,
            refsel, shsel, phc, phq, qsel, qcnt, qcw, qcwi, pr, pd, rsel, mlo, mhi,
            msel, dlo, dhi, drnd, dbit, glc, grc, caps8, idxb, cz2, cz7, cf, cx0,
            cx1, pos, consz, consf, asm0, asm1, vc, vce, pbuf, hit, gpb, lfs, preg,
            pzacc, a0r, a1r, a2r, p0r, p1r, px0r, fpreg, scr, breg, inv2s, invz,
            invzn, xreg, xfin, runev, f2dig, phd, cmpc, cmpci, czd, chlive, f2sel,
            pg_a, phg, phdend, cont, eg_a, endg, xsel, qadv, cfull, m3, rlo, rhi,
            dmux, snl, glo, ghi, gf, bpm, n_fhg, fhg, prega, cpa, cpb, cpl, consz7,
            fpi, csel, frgm, bcbd, chi, cc, mreg, mcnt, meq, minv, mrst, mcont, dlr,
            msh, mrot,
            canon_lo0, canon_lo1, top7_0, top7_1, gate_cols, gate_width,
        }
    }
}

/// Flat M_FHI gate index for round `rf`, pair row `r`: the M_FHI family handles
/// `2^(la-1)-1` binary-fold pairs per round (level 0 is the round-0 leaf fold).
/// `= Σ_{r'<rf}(2^(la_{r'}-1)-1) + r`; the last index is `n_fhg - 1`. Narrow
/// `[4,4,4,2]` gives `rf*7+r` for rf<3 and 21 for the final (la=2) round.
fn fhg_index(log_arities: &[usize], rf: usize, r: usize) -> usize {
    log_arities[..rf]
        .iter()
        .map(|&la| (1usize << (la - 1)) - 1)
        .sum::<usize>()
        + r
}

/// Diagnostic helper (relay debugging): map a column index to its region
/// name. Used by the `dump_constraint` / `dump_trace` tests to translate a
/// failing constraint's referenced columns into human-readable regions.
#[cfg(test)]
pub(crate) fn colname(x: usize) -> &'static str {
    if x < NUM_KECCAK_COLS {
        return "KECCAK";
    }
    let table: &[(usize, &str)] = &[
        (MUL_OFF, "MUL"), (ADD_OFF, "ADD"), (W0C, "W0C"), (W1C, "W1C"),
        (HB0, "HB0"), (HB1, "HB1"), (TA0, "TA0"), (TOPA0, "TOPA0"), (TA1, "TA1"),
        (TOPA1, "TOPA1"), (LBNZ0, "LBNZ0"), (LBI0, "LBI0"), (LONZ0, "LONZ0"),
        (LOI0, "LOI0"), (LBNZ1, "LBNZ1"), (LBI1, "LBI1"), (LONZ1, "LONZ1"),
        (LOI1, "LOI1"), (OREG, "OREG"), (PBIT, "PBIT"), (OBIT, "OBIT"),
        (FSBITS, "FSBITS"), (FSACC, "FSACC"), (FSP3A, "FSP3A"), (FSP3B, "FSP3B"),
        (FST7, "FST7"), (FSINV, "FSINV"), (FSNZ, "FSNZ"), (FSACCEPT, "FSACCEPT"),
        (FSGATE, "FSGATE"), (FSODD, "FSODD"), (FSFULL, "FSFULL"),
        (GRP, "GRP"), (COEF, "COEF"), (CURCH, "CURCH"), (CROT, "CROT"), (GROT, "GROT"),
        (CHAL, "CHAL"), (FA2, "FA2"), (ZNREG, "ZNREG"), (IDXR, "IDXR"),
        (FRING, "FRING"), (BLKCNT, "BLKCNT"), (BLKLAST, "BLKLAST"), (BLKINV, "BLKINV"),
        (BIDX, "BIDX"), (CMPA, "CMPA"), (CMPAI, "CMPAI"), (CMPB, "CMPB"), (CMPBI, "CMPBI"),
        (NEEDL, "NEEDL"), (REFSEL, "REFSEL"), (SHSEL, "SHSEL"), (PHC, "PHC"), (PHQ, "PHQ"),
        (QSEL, "QSEL"), (QCNT, "QCNT"), (QCW, "QCW"), (QCWI, "QCWI"),
        (PR, "PR"), (PD, "PD"), (RSEL, "RSEL"), (MLO, "MLO"), (MHI, "MHI"), (MSEL, "MSEL"),
        (DLO, "DLO"), (DHI, "DHI"), (DRND, "DRND"), (DBIT, "DBIT"), (GLC, "GLC"), (GRC, "GRC"),
        (CAPS8, "CAPS8"), (IDXB, "IDXB"), (CZ2, "CZ2"), (CZ7, "CZ7"), (CF, "CF"),
        (CX0, "CX0"), (CX1, "CX1"), (POS, "POS"), (CONSZ, "CONSZ"), (CONSF, "CONSF"),
        (ASM0, "ASM0"), (ASM1, "ASM1"), (VC, "VC"), (VCE, "VCE"), (PBUF, "PBUF"),
        (HIT, "HIT"), (GPB, "GPB"), (LFS, "LFS"), (PREG, "PREG"), (PZACC, "PZACC"),
        (A0R, "A0R"), (A1R, "A1R"), (A2R, "A2R"), (P0R, "P0R"), (P1R, "P1R"), (PX0R, "PX0R"),
        (FPREG, "FPREG"), (SCR, "SCR"), (BREG, "BREG"), (INV2S, "INV2S"), (INVZ, "INVZ"),
        (INVZN, "INVZN"), (XREG, "XREG"), (XFIN, "XFIN"), (RUNEV, "RUNEV"),
        (F2DIG, "F2DIG"), (PHD, "PHD"), (CMPC, "CMPC"), (CMPCI, "CMPCI"), (CZD, "CZD"),
        (CHLIVE, "CHLIVE"), (F2SEL, "F2SEL"), (PG_A, "PG_A"), (PHG, "PHG"),
        (PHDEND, "PHDEND"), (CONT, "CONT"), (EG_A, "EG_A"), (ENDG, "ENDG"),
        (XSEL, "XSEL"), (QADV, "QADV"), (CFULL, "CFULL"),
        (M3, "M3"), (RLO, "RLO"), (RHI, "RHI"), (DMUX, "DMUX"), (SNL, "SNL"),
        (GLO, "GLO"), (GHI, "GHI"), (GF, "GF"), (BPM, "BPM"), (FHG, "FHG"),
        (PREGA, "PREGA"), (CPA, "CPA"), (CPB, "CPB"), (CPL, "CPL"),
        (CONSZ7, "CONSZ7"), (FPI, "FPI"),
        // The table used to stop at FPI, so every column past it reported
        // "FPI" — which mislabelled the whole 2b/2d/R1 tail. Kept current.
        (CSEL, "CSEL"), (FRGM, "FRGM"), (BCBD, "BCBD"), (CHI, "CHI"), (CC, "CC"),
        (CANON_LO0, "CANON_LO0"), (CANON_LO1, "CANON_LO1"),
        (TOP7_0, "TOP7_0"), (TOP7_1, "TOP7_1"),
    ];
    let mut best = ("?", 0usize);
    for &(off, nm) in table {
        if off <= x && off >= best.1 {
            best = (nm, off);
        }
    }
    best.0
}

// -- query-program roles -------------------------------------------------------
const R_NONE: u32 = 0;
const R_ABS_F34: u32 = 1; // first block, 34 fresh words
const R_ABS_F16: u32 = 2; // first+last block, 16 fresh words
const R_ABS_C34: u32 = 3; // continuation, 34 fresh
const R_ABS_C5: u32 = 4; // continuation, 5 fresh (trace last)
const R_ABS_C30: u32 = 5; // continuation, 30 fresh (fold last)
const R_PATH: u32 = 6;
const R_PLAST_T: u32 = 7; // last path level + cap compare, per batch
const R_PLAST_Q: u32 = 8;
const R_PLAST_F0: u32 = 9;
const R_PLAST_F1: u32 = 10;
const R_PLAST_F2: u32 = 11;
const R_PLAST_F3: u32 = 12;
const N_ROLES: usize = 13;

// -- micro-blocks ---------------------------------------------------------------
const M_NONE: u32 = 0;
const M_X1: u32 = 1; // x = GEN * g22^rev22(idx): 22 chained muls
const M_INV: u32 = 2; // zx/inv_z, znx/inv_zn
const M_RO: u32 = 3; // reduced-opening assembly -> RUNEV
const M_S0: u32 = 4; // s chain, round 0 (18 muls + inv2s witness)
const M_S1: u32 = 5;
const M_S2: u32 = 6;
const M_S3: u32 = 7;
const M_B0: u32 = 8; // B ladder, round 0
const M_B1: u32 = 9;
const M_B2: u32 = 10;
const M_B3: u32 = 11;
const M_FHI0: u32 = 12; // higher fold levels, round 0 -> RUNEV
const M_FHI1: u32 = 13;
const M_FHI2: u32 = 14;
const M_FHI3: u32 = 15;
const M_FIN: u32 = 16; // x_fin chain
const M_HORN: u32 = 17; // final-poly Horner + compare
const N_MICROS: usize = 18;

const fn desc(role: u32, dparam: u32, micro: u32) -> u32 {
    role | (dparam << 4) | (micro << 10)
}

/// Absorb-round codes carried in dparam (drive DRND).
const D_T: u32 = 0;
const D_Q: u32 = 1;
const D_F: [u32; 4] = [2, 3, 4, 5];

/// The per-query program, shape-parametrized (slice 1b-2). Length `s.qslots()`.
/// `qprogram_from_shape(&narrow())` reproduces the old 103-slot `[u32; QSLOTS]`
/// byte-for-byte: the fold-round loop is driven by `n_fri_rounds`, path lengths
/// by `path_levels`, leaf blocks by `ceil(words/34)`, and the round-keyed
/// micro/role vocabulary by the `GateShape::m_*`/`r_plast_f` helpers.
pub(crate) fn qprogram_from_shape(s: &GateShape) -> Vec<u32> {
    let n = s.n_fri_rounds();
    let pl = s.path_levels();
    let cum = s.cum();
    let cap_h = s.cap_height();
    // Every batch's last native path level is the top non-cap index bit.
    let plast_dp = (s.log_max - cap_h - 1) as u32;
    let ceil34 = |x: usize| (x + 33) / 34;
    let mut p: Vec<u32> = vec![];

    // Absorb blocks for a leaf of `nw` fresh words under dparam `dp`. The
    // last-block role is chosen by LEAF CONTEXT (`last_role`), not by matching
    // the remainder literal: the trace leaf's last block is R_ABS_C5 whatever
    // its fresh count (narrow 5, wide 22), the fold leaf's last block is
    // R_ABS_C30. A single-block leaf (nb <= 1: quotient, or a short fold round
    // whose 4·2^la ≤ 34) is always R_ABS_F16.
    let emit_leaf = |p: &mut Vec<u32>, nw: usize, dp: u32, last_role: u32| {
        let nb = ceil34(nw);
        if nb <= 1 {
            // Single (first+last) block.
            p.push(desc(R_ABS_F16, dp, M_NONE));
        } else {
            p.push(desc(R_ABS_F34, dp, M_NONE));
            for _ in 0..nb - 2 {
                p.push(desc(R_ABS_C34, dp, M_NONE));
            }
            p.push(desc(last_role, dp, M_NONE));
        }
    };

    // trace leaf + path (l0 = x-chain, l1 = inverses).
    emit_leaf(&mut p, s.tw, D_T, R_ABS_C5);
    for l in 0..pl[0] - 1 {
        let micro = match l {
            0 => M_X1,
            1 => M_INV,
            _ => M_NONE,
        };
        p.push(desc(R_PATH, l as u32, micro));
    }
    p.push(desc(R_PLAST_T, plast_dp, M_NONE));

    // quotient leaf + path (l0 = round-0 s-chain, l1 = B-ladder, l2 = M_RO).
    emit_leaf(&mut p, s.qw, D_Q, R_ABS_F16);
    for l in 0..pl[1] - 1 {
        let micro = match l {
            0 => s.m_s(0),
            1 => s.m_b(0),
            2 => M_RO,
            _ => M_NONE,
        };
        p.push(desc(R_PATH, l as u32, micro));
    }
    p.push(desc(R_PLAST_Q, plast_dp, M_NONE));

    // fold rounds: leaf (4·2^la ext words) + path. Round r's path hosts the
    // higher-fold (l0), then the NEXT round's s-chain + B-ladder (l1/l2), except
    // the last round which hosts the final x_fin-chain + Horner.
    //
    // END-pin placement (Option A, slice 1b-B3 part 2): M_HORN pins the
    // fold-chain END (`RUNEV == Horner(final_poly, x_fin)`) and MUST land after
    // the last round's M_FHI so RUNEV is final. It needs an interior slot in the
    // last round. The narrow last round has 4 interior slots (l=0..3), so
    // M_FHI@l0 / M_FIN@l1 / M_HORN@l2 all fit. The wide last round is short
    // (path_levels=3 → interior slots l=0,1 only): there is no room for both
    // M_FIN and M_HORN after M_FHI. `M_FIN` (x_fin = ∏ over query index bits) has
    // NO fold-chain dependency — its eval keys only on its own micro selector,
    // reads the carried index bits, and writes the carried `xfin` register, which
    // nothing overwrites before M_HORN consumes it — so we relocate it to a spare
    // M_NONE interior slot in an earlier fold round (round 0, l=3) while keeping
    // M_HORN at the last round's l1 (still after last-round M_FHI). Narrow keeps
    // its `last_has_fin` room and is byte-identical (fin_reloc = None).
    let last_slots = pl[2 + n - 1] - 1; // interior slots in the last fold round
    let last_has_fin = last_slots >= 3;
    // When the last round is too short for M_FIN, host it on an earlier round's
    // spare interior slot (round 0, l=3 — the first M_NONE past M_FHI/M_S/M_B).
    let fin_reloc: Option<(usize, usize)> = if last_has_fin { None } else { Some((0, 3)) };
    for r in 0..n {
        let la = s.log_arities[r];
        emit_leaf(&mut p, 4 * (1usize << la), D_F[r], R_ABS_C30);
        let levels = pl[2 + r];
        let sh = cum[r + 1] as u32;
        for l in 0..levels - 1 {
            let micro = match l {
                0 => s.m_fhi(r),
                1 => {
                    if r < n - 1 {
                        s.m_s(r + 1)
                    } else if last_has_fin {
                        s.m_fin()
                    } else {
                        // Wide short last round: M_HORN directly after M_FHI.
                        s.m_horn()
                    }
                }
                2 => {
                    if r < n - 1 {
                        s.m_b(r + 1)
                    } else {
                        s.m_horn()
                    }
                }
                _ => {
                    if fin_reloc == Some((r, l)) {
                        s.m_fin()
                    } else {
                        M_NONE
                    }
                }
            };
            p.push(desc(R_PATH, sh + l as u32, micro));
        }
        p.push(desc(s.r_plast_f(r), plast_dp, M_NONE));
    }
    assert_eq!(p.len(), s.qslots(), "query program length");
    p
}

// ---------------------------------------------------------------------------
// Keccak-lane column helpers (pinned p3-keccak-air 0.6.1 layout; the
// positive tests fail on any drift). preimage starts after step_flags(24)
// + export(1); a_prime_prime after +preimage(100)+a(100)+c(320)+
// c_prime(320)+a_prime(1600).
// ---------------------------------------------------------------------------

/// Preimage limb i (full state, 0..100).
const fn pcol(i: usize) -> usize {
    25 + i
}
/// Round-output limb i (full state, 0..100): a_prime_prime_prime.
const fn ocol(i: usize) -> usize {
    const APP: usize = 24 + 1 + 100 + 100 + 320 + 320 + 1600;
    if i < 4 {
        APP + 100 + 64 + i // a_prime_prime_prime_0_0_limbs
    } else {
        APP + i
    }
}

/// One-hot ring read: active index g of an N-slot left-rotating ring
/// pinned [1,0,..] sits at column (N - g) % N.
const fn ring_at(base: usize, n: usize, g: usize) -> usize {
    base + (n - g % n) % n
}

// ---------------------------------------------------------------------------
// Field constant tables (shared by eval and lowering)
// ---------------------------------------------------------------------------

pub(crate) struct GateConsts {
    /// g_{log_max}^(2^(log_max-1-k)) for k in 0..log_max (x / x_fin chains).
    pub kx: Vec<Val>,
    /// s-chain constants per round: sk[r][k] = g_(lf+la)^(2^(lf-1-k)).
    pub sk: Vec<Vec<Val>>,
    /// Fold constants k_fold[r][l][i] = g_l^(-rev_(la-l-1)(i)),
    /// g_l = two_adic_generator(la_r)^(2^l).
    pub kf: Vec<Vec<Vec<Val>>>,
    pub gen: Val,
    pub g_trace: Val,
    pub half: Val,
    /// Flush block counts for BLKCNT reloads (one per obs flush).
    pub flush_blocks: Vec<usize>,
}

fn rev_bits(x: usize, bits: usize) -> usize {
    let mut r = 0;
    for i in 0..bits {
        r |= ((x >> i) & 1) << (bits - 1 - i);
    }
    r
}

/// Shape-parametrized field constants (slice 1b-2). `gate_consts_from_shape(&narrow())`
/// reproduces the shipped narrow generators byte-for-byte (`kx` length `log_max`,
/// per-round `lf = log_max - cum[r+1]`, `g_trace = two_adic(log_max - log_blowup)`).
pub(crate) fn gate_consts_from_shape(s: &GateShape) -> GateConsts {
    let log_max = s.log_max;
    let n = s.n_fri_rounds();
    let lf = s.lf();
    let g_lm = Val::two_adic_generator(log_max);
    let kx = (0..log_max).map(|k| g_lm.exp_power_of_2(log_max - 1 - k)).collect();
    let sk = (0..n)
        .map(|r| {
            let g = Val::two_adic_generator(lf[r] + s.log_arities[r]);
            (0..lf[r]).map(|k| g.exp_power_of_2(lf[r] - 1 - k)).collect()
        })
        .collect();
    let kf = (0..n)
        .map(|r| {
            let la = s.log_arities[r];
            let g_ar = Val::two_adic_generator(la);
            (0..la)
                .map(|l| {
                    let g_l = g_ar.exp_power_of_2(l);
                    let pairs = 1 << (la - l - 1);
                    (0..pairs)
                        .map(|i| g_l.exp_u64(rev_bits(i, la - l - 1) as u64).inverse())
                        .collect()
                })
                .collect()
        })
        .collect();
    GateConsts {
        kx,
        sk,
        kf,
        gen: Val::GENERATOR,
        g_trace: Val::two_adic_generator(log_max - s.log_blowup),
        half: Val::from_u32(2).inverse(),
        flush_blocks: s.flush_blocks(),
    }
}

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub(crate) struct VerifierGateAir {
    pub program: Vec<u32>,
    pub consts: GateConsts,
    /// Inner-proof shape this circuit verifies (narrow leaf today; a future
    /// slice instantiates `wide()` for the interior node).
    pub(crate) shape: GateShape,
    /// Column layout derived from `shape`; `eval` reads every column offset
    /// from here instead of the top-of-file `const`s.
    pub(crate) layout: GateLayout,
    /// Number of child proofs verified in one rectangle (2d). `1` = the leaf /
    /// single-wide gate (byte-identical to pre-2d); `> 1` = the interior node,
    /// which takes `n_children · n_opvs` public values (`opvsL ++ opvsR ++ …`)
    /// and routes each child's cap comparison to its own half via `chi`/`cc`.
    pub(crate) n_children: usize,
    /// log2(trace height) — used ONLY by the merge lane (棒 3-2) to pin the
    /// merge-region row count at `last_row`. A power-of-2 height is not a
    /// multiple of the 24-row keccak perm, so the trace's last perm is truncated
    /// (an `h mod 24`-row tail after the last full perm); the merge region is the
    /// suffix from the perm-aligned merge start, so its row count at last_row is
    /// `(h mod 24) + 24·merge_perms()`. The two-child wide interior is height
    /// 2^19. 0 for non-merge shapes (unused there).
    pub(crate) log_height: usize,
}

impl VerifierGateAir {
    pub(crate) fn new() -> Self {
        Self::new_with_shape(GateShape::narrow())
    }

    /// The M4 interior node: a `wide()`-shape verifier over TWO stacked children
    /// with per-child opvs routing enabled (2d) + the 棒 3 merge lane. Height is
    /// 2^19 (two ~8,360-perm children + the ~53-perm merge sponge, padded).
    pub(crate) fn new_interior() -> Self {
        Self { n_children: 2, log_height: 19, ..Self::new_with_shape(GateShape::wide()) }
    }

    /// Build a verifier gate for an arbitrary inner-proof `shape`, deriving the
    /// column layout, query program, and field constants from it (slice 1b-2:
    /// all three are now shape-parametrized, so `new_with_shape(wide())` is
    /// self-consistent).
    pub(crate) fn new_with_shape(shape: GateShape) -> Self {
        let layout = GateLayout::from_shape(&shape);
        let program = qprogram_from_shape(&shape);
        let consts = gate_consts_from_shape(&shape);
        Self {
            program,
            consts,
            shape,
            layout,
            n_children: 1,
            log_height: 0,
        }
    }
}

impl<F: Field> BaseAir<F> for VerifierGateAir {
    fn width(&self) -> usize {
        self.layout.gate_width
    }
    fn num_public_values(&self) -> usize {
        // Interior (n_children > 1): the two consumed child opvs halves + the
        // 棒 3 merge root (§2 exposed binding value) + the 棒 3-3 epoch Σfee rider.
        let merge = if self.n_children > 1 {
            crate::m4interior::MERGE_ROOT_LIMBS + crate::m4interior::EPOCH_FEE_LIMBS
        } else {
            0
        };
        self.shape.n_opvs() * self.n_children + merge
    }
}

/// Constraint-emission context: closures over the builder plus the shared
/// index helpers, so each subsystem below reads like the design note.
impl<AB: AirBuilder> Air<AB> for VerifierGateAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Keccak lane (stock AIR at column offset 0).
        {
            let mut lane = LaneBuilder {
                inner: builder,
                off: 0,
                width: NUM_KECCAK_COLS,
            };
            KeccakAir {}.eval(&mut lane);
        }

        let main = builder.main();
        let cur = main.current_slice();
        let nxt = main.next_slice();
        let cv = |i: usize| -> AB::Expr { cur[i].into() };
        let nv = |i: usize| -> AB::Expr { nxt[i].into() };
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|v| (*v).into()).collect();
        let pv = |i: usize| -> AB::Expr { pvs[i].clone() };
        let sf = |r: usize| -> AB::Expr { cv(r) };
        let c = |x: u32| AB::Expr::from(AB::F::from_u32(x));
        let cf = |x: Val| AB::Expr::from(AB::F::from_u32(x.to_unique_u32()));

        // --- arithmetic banks (inc-1, unchanged) --------------------------
        {
            let w = c(EXT_W);
            let a = |k: usize| cv(self.layout.mul_off + k);
            let b = |k: usize| cv(self.layout.mul_off + 4 + k);
            let cc = |k: usize| cv(self.layout.mul_off + 8 + k);
            for k in 0..4 {
                let mut acc = AB::Expr::ZERO;
                for i in 0..4 {
                    for j in 0..4 {
                        if i + j == k {
                            acc = acc + a(i) * b(j);
                        } else if i + j == k + 4 {
                            acc = acc + w.clone() * a(i) * b(j);
                        }
                    }
                }
                builder.assert_eq(acc, cc(k));
            }
            for k in 0..4 {
                builder.assert_eq(cv(self.layout.add_off + k) + cv(self.layout.add_off + 4 + k), cv(self.layout.add_off + 8 + k));
            }
        }

        // Ext-mul helper: (x (x) y)_k over F[x^4 - W], for column-vector x
        // at offset xo and column-vector y at offset yo.
        let extmul = |xo: usize, yo: usize, k: usize| -> AB::Expr {
            let w = c(EXT_W);
            let mut acc = AB::Expr::ZERO;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        acc = acc + cv(xo + i) * cv(yo + j);
                    } else if i + j == k + 4 {
                        acc = acc + w.clone() * cv(xo + i) * cv(yo + j);
                    }
                }
            }
            acc
        };

        // =====================================================================
        // Query program ring + role/micro/dparam selectors
        // =====================================================================
        let phq = cv(self.layout.phq);
        let phc = cv(self.layout.phc);
        builder.assert_bool(phq.clone());
        builder.assert_bool(phc.clone());

        // ---------------------------------------------------------------------
        // Degree-reduction: pin the materialized gate products (deg <= 3 each).
        // These replace the high-degree flush-automaton products below so every
        // constraint stays within the house deg-3 budget. Filled by the derived
        // pass in `build_gate_trace`.
        // ---------------------------------------------------------------------
        {
            let ring_fring = |f: usize| cv(ring_at(self.layout.fring, 8, f));
            // self.layout.chlive = phc * (1 - self.layout.refsel)
            builder.assert_eq(cv(self.layout.chlive), phc.clone() * (AB::Expr::ONE - cv(self.layout.refsel)));
            // self.layout.f2sel = ringsel(2) * (1 - bidxsel(0))
            builder.assert_eq(cv(self.layout.f2sel), ring_fring(2) * (AB::Expr::ONE - cv(self.layout.bidx)));
            // self.layout.pg_a = ringsel(final obs flush) * grpdone * phc
            // (final obs flush index = 3 + n_fri_rounds; narrow 7, wide 6).
            builder.assert_eq(
                cv(self.layout.pg_a),
                ring_fring(self.consts.flush_blocks.len() - 1)
                    * cv(ring_at(self.layout.grp, self.shape.n_groups(), self.shape.g_done()))
                    * phc.clone(),
            );
            // self.layout.phg (phasegate) = sf(23) * self.layout.blklast * self.layout.pg_a
            builder.assert_eq(cv(self.layout.phg), sf(23) * cv(self.layout.blklast) * cv(self.layout.pg_a));
            // self.layout.phdend = sf(23) * self.layout.phd * self.layout.blklast
            builder.assert_eq(cv(self.layout.phdend), sf(23) * cv(self.layout.phd) * cv(self.layout.blklast));
            // self.layout.cont = sf(23) * phc * (1 - self.layout.blklast)
            builder.assert_eq(cv(self.layout.cont), sf(23) * phc.clone() * (AB::Expr::ONE - cv(self.layout.blklast)));
            // self.layout.eg_a = phq * self.layout.qcw * ring(self.layout.qsel, self.shape.nq-1); self.layout.endg (endgate) = sf(23) * self.layout.eg_a
            builder.assert_eq(
                cv(self.layout.eg_a),
                phq.clone() * cv(self.layout.qcw) * cv(ring_at(self.layout.qsel, self.shape.nq + 1, self.shape.nq - 1)),
            );
            builder.assert_eq(cv(self.layout.endg), sf(23) * cv(self.layout.eg_a));
            // self.layout.xsel = phd*(1-self.layout.cmpc) + sum of obs/dup interior self.layout.shsel (xorsel).
            {
                let mut xs = cv(self.layout.phd) * (AB::Expr::ONE - cv(self.layout.cmpc));
                for f in 0..self.consts.flush_blocks.len() {
                    if f == 2 {
                        continue;
                    }
                    for b in 1..self.consts.flush_blocks[f] {
                        xs = xs + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, b));
                    }
                }
                builder.assert_eq(cv(self.layout.xsel), xs);
            }
            // self.layout.qadv = sf(23) * phq * self.layout.qcw
            builder.assert_eq(cv(self.layout.qadv), sf(23) * phq.clone() * cv(self.layout.qcw));
            // self.layout.cfull = sf(23) * consumersel * (1 - self.layout.fsfull)
            {
                let mut cs = cv(self.layout.refsel);
                for f in 1..self.consts.flush_blocks.len() {
                    cs = cs + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
                }
                builder.assert_eq(cv(self.layout.cfull), sf(23) * cs * (AB::Expr::ONE - cv(self.layout.fsfull)));
            }
        }

        // Ring pin + rotation (one limb per perm while in query phase).
        for i in 0..self.shape.qslots() {
            builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.pr + i) - (c(self.program[i]))));
        }
        {
            let g = sf(23) * phq.clone();
            let mut t = builder.when_transition();
            for i in 0..self.shape.qslots() {
                t.assert_eq(
                    nv(self.layout.pr + i),
                    cv(self.layout.pr + i) + g.clone() * (cv(self.layout.pr + (i + 1) % self.shape.qslots()) - cv(self.layout.pr + i)),
                );
            }
        }
        // Head decomposition: 15 bool bits = self.layout.pr[0].
        for k in 0..15 {
            builder.assert_bool(cv(self.layout.pd + k));
        }
        {
            let mut acc = AB::Expr::ZERO;
            for k in 0..15 {
                acc = acc + cv(self.layout.pd + k) * c(1 << k);
            }
            builder.assert_eq(acc, cv(self.layout.pr));
        }
        // Literal helper over a bit column: bit b of code j.
        let lit = |col: usize, on: bool| -> AB::Expr {
            if on {
                cv(col)
            } else {
                AB::Expr::ONE - cv(col)
            }
        };
        // Degree-reduction (family 2): materialize the raw bit-products used by
        // the phq-gated selector defs so those stay deg <= 3.
        // RLO_j = pair(PD0,PD1); RHI_j = pair(PD2,PD3); M3_a = 3-bit(PD10..12).
        for j in 0..4 {
            builder.assert_eq(cv(self.layout.rlo + j), lit(self.layout.pd, j & 1 == 1) * lit(self.layout.pd + 1, j & 2 == 2));
            builder.assert_eq(cv(self.layout.rhi + j), lit(self.layout.pd + 2, j & 1 == 1) * lit(self.layout.pd + 3, j & 2 == 2));
        }
        for a in 0..8 {
            builder.assert_eq(
                cv(self.layout.m3 + a),
                lit(self.layout.pd + 10, a & 1 == 1) * lit(self.layout.pd + 11, a & 2 == 2) * lit(self.layout.pd + 12, a & 4 == 4),
            );
        }
        // Role selectors: RSEL_r = phq * self.layout.rlo[r&3] * self.layout.rhi[(r>>2)&3]  (deg 3).
        for r in 0..self.shape.n_roles() {
            builder.assert_eq(
                cv(self.layout.rsel + r),
                phq.clone() * cv(self.layout.rlo + (r & 3)) * cv(self.layout.rhi + ((r >> 2) & 3)),
            );
        }
        // Micro selectors: MLO_a = phq * self.layout.m3[a]; MHI_b = 2-bit(PD13..14);
        // MSEL_m = self.layout.mlo * self.layout.mhi  (all deg <= 3).
        for a in 0..8 {
            builder.assert_eq(cv(self.layout.mlo + a), phq.clone() * cv(self.layout.m3 + a));
        }
        for b in 0..4 {
            let e = lit(self.layout.pd + 13, b & 1 == 1) * lit(self.layout.pd + 14, b & 2 == 2);
            builder.assert_eq(cv(self.layout.mhi + b), e);
        }
        for m in 0..self.shape.n_micros() {
            builder.assert_eq(cv(self.layout.msel + m), cv(self.layout.mlo + (m & 7)) * cv(self.layout.mhi + (m >> 3)));
        }
        // dparam selectors: DLO_a (PD4..6), DHI_b (PD7..8, b < 3).
        for a in 0..8 {
            let e = lit(self.layout.pd + 4, a & 1 == 1) * lit(self.layout.pd + 5, a & 2 == 2) * lit(self.layout.pd + 6, a & 4 == 4);
            builder.assert_eq(cv(self.layout.dlo + a), e);
        }
        for b in 0..3 {
            let e = lit(self.layout.pd + 7, b & 1 == 1) * lit(self.layout.pd + 8, b & 2 == 2);
            builder.assert_eq(cv(self.layout.dhi + b), e);
        }
        // Absorb-round selectors from dparam values 0..5.
        let absany = cv(self.layout.rsel + R_ABS_F34 as usize)
            + cv(self.layout.rsel + R_ABS_F16 as usize)
            + cv(self.layout.rsel + R_ABS_C34 as usize)
            + cv(self.layout.rsel + R_ABS_C5 as usize)
            + cv(self.layout.rsel + R_ABS_C30 as usize);
        // DRND_j = absany * self.layout.dlo[j]  (self.layout.dlo[j] is the same 3-bit product; deg 2).
        // Loop bound = drnd_width (narrow 6, wide 5 = 2 + n_fri_rounds); j=6 on
        // wide would write drnd+5 = dbit (OOB), corrupting dbit's own constraint.
        for j in 0..self.shape.drnd_width() {
            builder.assert_eq(cv(self.layout.drnd + j), absany.clone() * cv(self.layout.dlo + j));
        }
        // Leaf-start selector.
        builder.assert_eq(
            cv(self.layout.lfs),
            cv(self.layout.rsel + R_ABS_F34 as usize) + cv(self.layout.rsel + R_ABS_F16 as usize),
        );

        // =====================================================================
        // Query scheduling: self.layout.qsel ring, self.layout.qcnt countdown, phase handoff/exit
        // =====================================================================
        for i in 0..=self.shape.nq {
            builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.qsel + i) - (if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO })));
        }
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.qcnt) - (c(self.shape.qslots() as u32))));
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.phc) - AB::Expr::ONE));
        builder.assert_zero(cv(self.layout.csel) * cv(self.layout.phq));
        // =====================================================================
        // Child-boundary re-anchor selector (2b, option B: completion-gated).
        // self.layout.csel = 1 on the first row of each child's first perm (row 0
        // for a single child; row 0 and 24*nL for the two-child interior). It
        // DRIVES the per-child re-anchor of the automaton (the first-row anchors
        // and the cross-perm carries key on it, added in 2b-ii/iii). Soundness:
        // csel is boolean, pinned to 1 at trace row 0, and may only RISE where
        // the previous perm completed a child's query phase (self.layout.endg =
        // sf(23)*eg_a, which fires exactly once per child at the last query's
        // last block r=23). A prover therefore cannot set csel=1 mid-child to
        // truncate that child's verification: csel_next requires endg on the
        // current row, and endg is 0 everywhere except the genuine child end.
        // (The final qsel→nq rotation is the boundary transition itself and is
        // suppressed there, so `qsel==nq` is NOT a usable signal — endg is.)
        // Narrow (single child) has csel=1 only at row 0 (≡ first_row), so the
        // existing constraint verdicts are unchanged.
        builder.assert_bool(cv(self.layout.csel));
        builder.when_first_row().assert_one(cv(self.layout.csel));
        {
            let mut t = builder.when_transition();
            t.assert_zero(nv(self.layout.csel) * (AB::Expr::ONE - cv(self.layout.endg)));
        }
        // self.layout.qcw comparator: self.layout.qcnt == 1.
        builder.assert_bool(cv(self.layout.qcw));
        builder.assert_zero((cv(self.layout.qcnt) - AB::Expr::ONE) * cv(self.layout.qcw));
        builder.assert_eq(
            cv(self.layout.qcw) + (cv(self.layout.qcnt) - AB::Expr::ONE) * cv(self.layout.qcwi),
            AB::Expr::ONE,
        );
        // The last-row anchor: all 20 query blocks must have completed.
        builder
            .when_last_row()
            .assert_one(cv(ring_at(self.layout.qsel, self.shape.nq + 1, self.shape.nq)));
        {
            // self.layout.qcnt: decrement per perm during query phase, reload on wrap.
            let dec = sf(23) * phq.clone();
            let mut t = builder.when_transition();
            t.assert_eq(
                nv(self.layout.qcnt),
                cv(self.layout.qcnt)
                    + dec.clone()
                        * ((AB::Expr::ONE - cv(self.layout.qcw)) * (-AB::Expr::ONE)
                            + cv(self.layout.qcw) * c(self.shape.qslots() as u32 - 1)),
            );
            // self.layout.qsel rotation on block wrap. (self.layout.qadv = sf(23)*phq*self.layout.qcw = dec*self.layout.qcw.)
            // 2b-iii: suppressed at the child boundary (csel_next) — the one-hot
            // reaches slot nq at a child's end but child R must re-anchor slot 0.
            let g = cv(self.layout.qadv);
            for i in 0..=self.shape.nq {
                t.assert_zero(
                    (AB::Expr::ONE - nv(self.layout.csel))
                        * (nv(self.layout.qsel + i)
                            - cv(self.layout.qsel + i)
                            - g.clone() * (cv(self.layout.qsel + (i + 1) % (self.shape.nq + 1)) - cv(self.layout.qsel + i))),
                );
            }
        }

        // =====================================================================
        // Per-query index bits: decomposition of the active query's index
        // register (continuous binding; no load events needed).
        // =====================================================================
        for k in 0..self.shape.log_max {
            builder.assert_bool(cv(self.layout.idxb + k));
        }
        {
            let mut recompose = AB::Expr::ZERO;
            for k in 0..self.shape.log_max {
                recompose = recompose + cv(self.layout.idxb + k) * c(1 << k);
            }
            let mut sel = AB::Expr::ZERO;
            for q in 0..self.shape.nq {
                sel = sel + cv(ring_at(self.layout.qsel, self.shape.nq + 1, q)) * cv(self.layout.idxr + q);
            }
            builder.assert_zero(phq.clone() * (recompose - sel));
        }
        // Path direction bit: self.layout.dbit = pathish * idx bit selected by dparam.
        let pathish = cv(self.layout.rsel + R_PATH as usize)
            + (R_PLAST_T..=self.shape.r_plast_f(self.shape.n_fri_rounds() - 1))
                .map(|r| cv(self.layout.rsel + r as usize))
                .fold(AB::Expr::ZERO, |a, e| a + e);
        {
            // self.layout.dmux = sum_k self.layout.dlo[k&7]*self.layout.dhi[k>>3]*self.layout.idxb[k] (deg 3); self.layout.dbit = pathish*self.layout.dmux.
            let mut mux = AB::Expr::ZERO;
            for k in 0..(self.shape.log_max - self.shape.cap_height()) {
                mux = mux + cv(self.layout.dlo + (k & 7)) * cv(self.layout.dhi + (k >> 3)) * cv(self.layout.idxb + k);
            }
            builder.assert_eq(cv(self.layout.dmux), mux);
            builder.assert_eq(cv(self.layout.dbit), pathish.clone() * cv(self.layout.dmux));
        }
        builder.assert_eq(cv(self.layout.glc), pathish.clone() * (AB::Expr::ONE - cv(self.layout.dbit)));
        builder.assert_eq(cv(self.layout.grc), pathish.clone() * cv(self.layout.dbit));
        // Cap-element selectors from the top cap_height idx bits (positions
        // log_max-cap_height .. log_max; narrow 19..21, wide 15..17).
        let capb = self.shape.log_max - self.shape.cap_height();
        for j in 0..8 {
            let e = lit(self.layout.idxb + capb, j & 1 == 1)
                * lit(self.layout.idxb + capb + 1, j & 2 == 2)
                * lit(self.layout.idxb + capb + 2, j & 4 == 4);
            builder.assert_eq(cv(self.layout.caps8 + j), e);
        }

        // =====================================================================
        // Merkle structure: absorb shapes, sponge carries, path chaining,
        // cap comparison against outer public values.
        // =====================================================================
        // First blocks: untouched rate + capacity limbs are zero.
        for i in 68..100 {
            builder.assert_zero(cv(self.layout.rsel + R_ABS_F34 as usize) * cv(pcol(i)));
        }
        // Single-block leaf (R_ABS_F16, qw fresh words): limbs 0..2·qw are the
        // message, everything above is zero. Narrow qw=16 → 32..100, wide qw=8
        // → 16..100.
        for i in (2 * self.shape.qw)..100 {
            builder.assert_zero(cv(self.layout.rsel + R_ABS_F16 as usize) * cv(pcol(i)));
        }
        // Compression preimages: lanes 8..25 zero.
        for i in 32..100 {
            builder.assert_zero(pathish.clone() * cv(pcol(i)));
        }
        {
            let mut t = builder.when_transition();
            // Continuation carries (consumer-role keyed, producer's last row).
            for i in 68..100 {
                t.assert_zero(
                    sf(23) * nv(self.layout.rsel + R_ABS_C34 as usize) * (nv(pcol(i)) - cv(ocol(i))),
                );
            }
            // C5 (trace last block): `f = trace_last_fresh` fresh u32 words =
            // limbs 0..2f. The overwrite-mode sponge packs 2 words per u64
            // lane, so when f is ODD the last word fills a lane's low half
            // while its high half [2f, 2f+2) is an unused zero pad; only limbs
            // [pad_hi, 100) carry the producer's output. Pin the pad half to
            // zero (else a prover could smuggle a word there) and carry from
            // pad_hi. Narrow f=5 (odd) → pad 10..12, carry 12..100; wide f=22
            // (even) → no pad, carry 44..100.
            let f = self.shape.trace_last_fresh();
            let pad_lo = 2 * f;
            let pad_hi = 2 * f + 2 * (f & 1);
            for i in pad_lo..pad_hi {
                t.assert_zero(sf(23) * nv(self.layout.rsel + R_ABS_C5 as usize) * nv(pcol(i)));
            }
            for i in pad_hi..100 {
                t.assert_zero(sf(23) * nv(self.layout.rsel + R_ABS_C5 as usize) * (nv(pcol(i)) - cv(ocol(i))));
            }
            for i in 60..100 {
                t.assert_zero(
                    sf(23) * nv(self.layout.rsel + R_ABS_C30 as usize) * (nv(pcol(i)) - cv(ocol(i))),
                );
            }
            // Path chaining: the chained child mux (left when the consumed
            // index bit is 0, right when 1); sibling half is free witness.
            for m in 0..16 {
                t.assert_zero(sf(23) * nv(self.layout.glc) * (nv(pcol(m)) - cv(ocol(m))));
                t.assert_zero(sf(23) * nv(self.layout.grc) * (nv(pcol(16 + m)) - cv(ocol(m))));
            }
        }
        // Interior per-child opvs routing (2d). `route` only for n_children > 1;
        // narrow / single-wide are byte-identical (chi/cc unpinned + unread).
        // `chi` is the running child selector: 0 across child L, 1 across child
        // R. Pinned bool, chi[row 0] = 0, and a transition `chi_next = chi +
        // csel_next` that rises exactly at the (soundness-pinned) child boundary
        // — so chi is fully determined, not prover-chosen. `cc[j] = chi·caps8[j]`
        // is materialized so the cap-half select below stays deg ≤ 3.
        let route = self.n_children > 1;
        let n_opvs = self.shape.n_opvs();
        if route {
            builder.assert_bool(cv(self.layout.chi));
            builder.when_first_row().assert_zero(cv(self.layout.chi));
            builder
                .when_transition()
                .assert_zero(nv(self.layout.chi) - cv(self.layout.chi) - nv(self.layout.csel));
            for j in 0..self.shape.cap_len {
                builder.assert_zero(
                    cv(self.layout.cc + j) - cv(self.layout.chi) * cv(self.layout.caps8 + j),
                );
            }
            // 棒 3-2 merge-region pin (positively forces the last 24·nm rows to be
            // the merge sponge, so the merge-binding constraints — 棒 3-2b/c —
            // cannot be dodged by dropping the region). `mreg` monotone 0→1;
            // `mcnt` running count of mreg, pinned == 24·nm at last_row.
            // Region is the SUFFIX from the (perm-aligned) merge start to the
            // trace end, so its row count at last_row is 24·nm plus the truncated
            // tail `h mod 24` (a power-of-2 height is not a multiple of 24). The
            // tail rows are inert for the chain/reset (step-flag 23 never fires in
            // a <24-row perm), so folding them into mreg is harmless.
            let nmr = ((1usize << self.log_height) % 24 + 24 * self.shape.merge_perms()) as u32;
            builder.assert_bool(cv(self.layout.mreg));
            builder.when_first_row().assert_zero(cv(self.layout.mreg));
            builder.when_first_row().assert_eq(cv(self.layout.mcnt), cv(self.layout.mreg));
            builder.when_last_row().assert_eq(cv(self.layout.mcnt), c(nmr));
            {
                let mut t = builder.when_transition();
                // monotone: once mreg = 1 it stays 1 (merge region is a suffix).
                t.assert_zero(cv(self.layout.mreg) * (AB::Expr::ONE - nv(self.layout.mreg)));
                // running count: mcnt_next = mcnt + mreg_next.
                t.assert_zero(nv(self.layout.mcnt) - cv(self.layout.mcnt) - nv(self.layout.mreg));
            }
            // 棒 3-2b capacity chain — the merge is 3 independent keccak sub-sponges
            // (childL kL perms, childR kR, root 1). Each sub-sponge's input
            // capacity (lanes 17..25 = limbs 68..100) resets to 0 at its start and
            // chains from the previous perm's output otherwise. Since keccak-f is a
            // PERMUTATION (invertible), the chain is what makes hitting pv(root) a
            // sponge-preimage problem — without it the root binding (3-2c) would be
            // vacuous. Comparator thresholds on mcnt (merge perm p's row 0 has
            // mcnt = 24·p + 1): the 3 sub-sponge STARTS {1, 24·kL+1, 24·(kL+kR)+1}
            // → the reset flag `mrst`, plus a 4th `24·nm` = the root perm's LAST
            // row (`eq_end` = meq[3]) → suppresses the (nonexistent) forward chain
            // from the last sub-sponge into the inert tail perm.
            let nm = self.shape.merge_perms();
            let kl = (nm - 1) / 2;
            let thresholds =
                [1u32, (24 * kl + 1) as u32, (24 * (nm - 1) + 1) as u32, (24 * nm) as u32];
            let mut rst = AB::Expr::ZERO;
            for (k, tk) in thresholds.iter().enumerate() {
                let eq = cv(self.layout.meq + k);
                let diff = cv(self.layout.mcnt) - c(*tk);
                builder.assert_bool(eq.clone());
                builder.assert_zero(eq.clone() * diff.clone()); // eq=1 ⇒ mcnt==tk
                builder.assert_eq(eq.clone() + diff * cv(self.layout.minv + k), AB::Expr::ONE);
                if k < 3 {
                    rst = rst + eq; // sub-sponge starts only
                }
            }
            builder.assert_eq(cv(self.layout.mrst), rst); // mrst = Σ (first 3 meq)
            // Reset: input capacity == 0 at each sub-sponge start.
            for i in 68..100 {
                builder.assert_zero(cv(self.layout.mrst) * cv(pcol(i)));
            }
            // mcont = merge-continue gate = sf(23)·mreg·(1 − next-row mrst − eq_end):
            // fires at a merge perm boundary INTERNAL to a multi-perm sub-sponge —
            // suppressed where the next perm is a reset (mrst_next, sub-sponge
            // boundary) or where this is the root perm's last row (eq_end, no
            // forward chain into the tail). Materialized (next-row dependent) so the
            // chain stays deg ≤ 3.
            builder.when_transition().assert_eq(
                cv(self.layout.mcont),
                sf(23)
                    * cv(self.layout.mreg)
                    * (AB::Expr::ONE - nv(self.layout.mrst) - cv(self.layout.meq + 3)),
            );
            // Chain: next perm's input capacity == this perm's output capacity.
            for i in 68..100 {
                builder
                    .when_transition()
                    .assert_zero(cv(self.layout.mcont) * (nv(pcol(i)) - cv(ocol(i))));
            }
            // 棒 3-2c — tree-merge digest binding: root = keccak(dL ‖ dR), dL/dR =
            // the child sub-sponge digests. `meq[1]`=childR-start, `meq[2]`=root-
            // start, `meq[3]`=root-end (root perm's r=23). Digest limbs are the
            // output/input rate limbs 0..16 (first 4 lanes = 32 bytes).
            //
            // dL carry: child L's last perm output (captured at the childL→childR
            // boundary, gate sf(23)·meq1_next) is freeze-held in `dlr` to the root
            // perm (child R sits between them).
            for m in 0..16 {
                let cap = sf(23) * nv(self.layout.meq + 1); // childL→childR boundary
                builder
                    .when_transition()
                    .assert_zero(cap.clone() * (nv(self.layout.dlr + m) - cv(ocol(m))));
                builder.when_transition().assert_zero(
                    (AB::Expr::ONE - cap) * (nv(self.layout.dlr + m) - cv(self.layout.dlr + m)),
                );
            }
            // Root perm input rate: [0..16] == dL (carried), [16..32] == dR (child
            // R's last perm output, ADJACENT → bound by the childR→root boundary
            // transition). Root start = meq[2].
            for m in 0..16 {
                builder.assert_zero(
                    cv(self.layout.meq + 2) * (cv(pcol(m)) - cv(self.layout.dlr + m)),
                );
                builder.when_transition().assert_zero(
                    sf(23) * nv(self.layout.meq + 2) * (nv(pcol(16 + m)) - cv(ocol(m))),
                );
            }
            // Root squeeze: root perm output digest (limbs 0..16 at r=23 = eq_end =
            // meq[3]) == the interior's exposed merge root pv[2·n_opvs + m]. This is
            // the load-bearing bind: with the capacity chain (3-2b) making the merge
            // a real sponge, hitting the fixed pv(root) forces (preimage resistance)
            // the sponge inputs = the honest opvs.
            for m in 0..16 {
                builder.assert_zero(
                    cv(self.layout.meq + 3) * (cv(ocol(m)) - pv(2 * n_opvs + m)),
                );
            }
            // 棒 3-3 (M4 step 2): epoch Σfee rider. The exposed root pv
            // `Σfee[j] = feeL[j] + feeR[j]`, where each child's fee limbs are the
            // TAIL of its opvs half (M3 fee = PV_FEE..PV_LEN, the inner-PV tail →
            // the opvs tail → the pv-half tail). feeL = pv(n_opvs - fl + j),
            // feeR = pv(2·n_opvs - fl + j); the rider sits after the merge root at
            // pv(2·n_opvs + MERGE_ROOT_LIMBS + j). Bound at the root perm's last
            // row (meq[3]) alongside the root squeeze; deg 1 (a witness-flag times
            // a pv-linear form). feeL/feeR are the interior's inner PVs, bound to
            // the verified children via the child challenger absorption — so a
            // faked child fee (or a tampered exposed sum) is UNSAT.
            let fl = crate::m4interior::EPOCH_FEE_LIMBS;
            let sfee_base = 2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS;
            for j in 0..fl {
                let fee_l = pv(n_opvs - fl + j);
                let fee_r = pv(2 * n_opvs - fl + j);
                builder.assert_zero(
                    cv(self.layout.meq + 3) * (pv(sfee_base + j) - fee_l - fee_r),
                );
            }
            // =============================================================
            // Issue #24 (D0): the msh one-hot selector ring — the mechanism
            // (designed once, applied by D1/D2/D3). `msh + p` fires on exactly
            // merge perm p's 24 rows so a per-block message binding can read
            // `pv` at the FIXED index for block p (a `pv(i)` index MUST be a
            // compile-time constant — it cannot be indexed by a trace value, so
            // the merge perms' data-dependent rows need a one-hot to carry the
            // constant into `eval`). POSITIVELY PINNED (the csel-vs-msh
            // difference the plan flags): csel's absence self-destructs the
            // phase automaton, but msh's absence would merely make the binding
            // VANISH silently → the ring must be FORCED to exist.
            // (a) each slot boolean.
            for p in 0..nm {
                builder.assert_bool(cv(self.layout.msh + p));
            }
            // (b) in-region one-hot: exactly one active slot while mreg = 1 (and
            //     zero outside). On the inert truncated tail past the root perm
            //     the ring freezes at the root slot, so `Σ == mreg` holds there.
            {
                let mut s = AB::Expr::ZERO;
                for p in 0..nm {
                    s = s + cv(self.layout.msh + p);
                }
                builder.assert_eq(s, cv(self.layout.mreg));
            }
            // (c) start anchor: at the mreg 0→1 edge the ring points at slot 0
            //     (the first merge perm = child-L block 0). `medge` ∈ {0,1} by
            //     mreg monotonicity.
            let medge = nv(self.layout.mreg) - cv(self.layout.mreg);
            {
                let mut t = builder.when_transition();
                for p in 0..nm {
                    let want = if p == 0 { AB::Expr::ONE } else { AB::Expr::ZERO };
                    t.assert_zero(medge.clone() * (nv(self.layout.msh + p) - want));
                }
            }
            // (d) rotation gate: mrot = sf(23)·mreg·(1 − eq_end), materialized so
            //     the rotation stays deg ≤ 3. Fires at every in-region perm
            //     boundary except the root perm's last row (eq_end = meq[3]) — so
            //     the ring advances continuously across the sub-sponge boundaries
            //     (unlike the capacity chain, which resets there) and does NOT
            //     rotate forward into the inert tail.
            builder.when_transition().assert_eq(
                cv(self.layout.mrot),
                sf(23) * cv(self.layout.mreg) * (AB::Expr::ONE - cv(self.layout.meq + 3)),
            );
            // (e) rotation: away from the start edge, hold the one-hot within a
            //     perm and shift it forward one slot (active p → p+1) when mrot
            //     fires. `(1 − medge)` cedes the edge transition to (c).
            {
                let mut t = builder.when_transition();
                for q in 0..nm {
                    let prev = (q + nm - 1) % nm;
                    t.assert_zero(
                        (AB::Expr::ONE - medge.clone())
                            * (nv(self.layout.msh + q)
                                - cv(self.layout.msh + q)
                                - cv(self.layout.mrot)
                                    * (cv(self.layout.msh + prev) - cv(self.layout.msh + q))),
                    );
                }
            }
            // (f) POSITIVE PIN (end anchor): at last_row the ring points at the
            //     root slot (nm − 1). DROPPING the whole ring (all-zero) violates
            //     THIS → UNSAT — the ring's existence is forced, not optional.
            builder.when_last_row().assert_one(cv(self.layout.msh + (nm - 1)));

            // =============================================================
            // Issue #24 (D1): merge preimage → pv(opvs) MESSAGE BINDING.
            // For each child sponge perm p, bind its absorbed rate block (34
            // values × two u16 preimage limbs each) to the child's inner public
            // values at the FIXED index for block p, gated by `msh[p]·sf(0)` (the
            // perm's input row). This upgrades the interior root bind from
            // computational — hitting pv(root) ⇒ honest inputs BY KECCAK PREIMAGE
            // RESISTANCE, the PR #23/#25 caveat — to an UNCONDITIONAL
            // constraint-level bind, and (binding every inner PV) closes the R2
            // "inner PVs unbound" gap for the interior. The merge sponge is
            // OVERWRITE-mode (m4interior::sponge_overwrite): the preimage rate
            // limbs ARE the message block (no XOR recovery), and KeccakAir
            // range-bounds them to u16, so the pair-recompose is sound.
            //
            // Issue #24 (D2): extend the message binding to the fee TAIL
            // [np − EPOCH_FEE_LIMBS, np) — the Σfee rider's input summands (M3
            // fee = PV_FEE..PV_LEN = the inner-PV tail). With this the PR #25
            // boundary CLOSES: `interior_epoch_fee_boundary` inverts from
            // documented-SAT to UNSAT (a consistent feeL+Σfee tamper now breaks
            // the fee-tail binding). D1 bound [0, np); D2 removes the exclusion
            // so ALL inner PVs — incl. the fee tail — are bound.
            {
                // The plain field element rr = R (monty_rr): pv(inner) == v·R and
                // the absorbed value recompose == canonical v, so recompose·rr ==
                // pv. NB use `c(rr.as_canonical_u32())`, NOT `cf(rr)` — `cf` would
                // re-encode rr into its Monty WORD (R²), the wrong factor.
                let rr = c(monty_rr().as_canonical_u32());
                let opv_inner = self.shape.opv_pvs(); // OPV_PVS (past caps + D3 f0dig)
                let np = self.shape.n_pvs;
                let msg_bytes = np * 4;
                let padded_len = kl * 136; // per-child padded message length (kl blocks)
                // child-L sponge = region perms 0..kl (block = p, pv half [0..n_opvs));
                // child-R sponge = kl..2kl (block = p-kl, pv half [n_opvs..2n_opvs)).
                // The root perm (2kl) carries dL‖dR, bound by 棒 3-2c — not here.
                for p in 0..(2 * kl) {
                    let (half, block) = if p < kl { (0usize, p) } else { (n_opvs, p - kl) };
                    let gate = cv(self.layout.msh + p) * sf(0);
                    for j in 0..34 {
                        let idx = 34 * block + j;
                        let lane = j / 2;
                        let lb = 4 * lane + 2 * (j % 2); // low limb; +1 = high limb (rate < 68)
                        let recompose = cv(pcol(lb)) + cv(pcol(lb + 1)) * c(1 << 16);
                        if idx < np {
                            // value == inner_pvs[idx]; pv slot == inner_pvs[idx]·rr.
                            // (D1: idx < np−fee; D2: extended through the fee tail.)
                            let target = pv(half + opv_inner + idx);
                            builder.assert_zero(gate.clone() * (recompose * rr.clone() - target));
                        } else {
                            // padding position: pin the two limbs to the fixed
                            // pad10*1 constants over the child message tail.
                            let padval = |bi: usize| -> u32 {
                                if bi == msg_bytes {
                                    0x01
                                } else if bi == padded_len - 1 {
                                    0x80
                                } else {
                                    0
                                }
                            };
                            let mut v = 0u32;
                            for k in 0..4 {
                                v |= padval(4 * idx + k) << (8 * k);
                            }
                            builder.assert_zero(gate.clone() * (cv(pcol(lb)) - c(v & 0xffff)));
                            builder.assert_zero(gate.clone() * (cv(pcol(lb + 1)) - c(v >> 16)));
                        }
                    }
                }
            }
        }
        // Cap comparison at the last path level of each batch (trace, quotient,
        // then one per FRI round). Shape-driven so wide (3 rounds) skips F3. For
        // the interior each child's caps must match ITS OWN half of the doubled
        // `opvsL ++ opvsR` public values: `pvL + chi·(pvR - pvL)`, folded through
        // the materialized `cc = chi·caps8` to keep the constraint deg ≤ 3.
        let plast_roles: Vec<u32> = [R_PLAST_T, R_PLAST_Q]
            .into_iter()
            .chain((0..self.shape.n_fri_rounds()).map(|r| self.shape.r_plast_f(r)))
            .collect();
        for (bi, role) in plast_roles.iter().enumerate() {
            for m in 0..16 {
                let mut mux = AB::Expr::ZERO;
                for j in 0..self.shape.cap_len {
                    let idx = cap_limb_opv(bi, j, m);
                    mux = mux + cv(self.layout.caps8 + j) * pv(idx);
                    if route {
                        mux = mux + cv(self.layout.cc + j) * (pv(n_opvs + idx) - pv(idx));
                    }
                }
                builder.assert_zero(sf(23) * cv(self.layout.rsel + *role as usize) * (cv(ocol(m)) - mux));
            }
        }
        // =====================================================================
        // Issue #24 (D3): leaf F0 digest INPUT binding + the exposed `f0dig`.
        //
        // F0 is the challenger's FIRST observation flush and its message is
        // exactly the claimed public surface:
        //     deg_bits ‖ base_deg_bits ‖ preprocessed_width ‖ trace cap ‖ PVs
        // Until D3 NOTHING tied its absorbed words to anything. Two consequences,
        // both closed here: (1) the inner public values rode the outer interface
        // unbound — issue #21's R2, empirically pinned as the `tamper_coverage`
        // SAT-MISS probes, so an aggregator could not trust a leaf's claimed
        // transaction surface; (2) the whole Fiat-Shamir transcript started from
        // a message the prover could choose freely, so the trace cap the queries
        // are checked against and the cap the challenges are derived from were
        // never forced to be the same object.
        //
        // The binding is the resurrected `shape_mosaic` (`WordBind`), one
        // constraint per F0 word, gated by that block's `shsel` and the word's
        // row-in-perm step flag (word j of a block lives at row j/2, `w0c` for
        // even j and `w1c` for odd — the state's u16 limbs pack 2 words/row):
        //   Const(v) -> the fixed transcript constant / the pad10*1 word,
        //   Cap(i)   -> pv(i) + 2^16·pv(i+1)   (a u32 word = two u16 cap limbs),
        //   Pv(i)    -> pv(i) DIRECTLY. Unlike the D1 merge binding there is NO
        //              `rr` factor: `outer_pvs` already carries the inner PVs in
        //              their transcript (Monty-word) encoding, which is exactly
        //              what the challenger absorbed, whereas the merge sponge
        //              hashes canonical u32s.
        //
        // The words come from `w0c`/`w1c`, which D3 pins for the FIRST time —
        // they (and the OREG/PBIT/OBIT XOR register file) were built in inc-4,
        // filled ever since, and never constrained. No new register file and no
        // new columns were needed: `oreg` was already constraint-captured from
        // the previous perm's output rate, and the bit columns were already
        // filled; only these constraints were missing.
        //   - F0 block 0 absorbs into the ZERO state, so its preimage rate IS
        //     the message: `w` recomposes the two u16 preimage limbs directly.
        //   - F0 blocks 1.. are XOR-mode (standard keccak challenger): the AIR's
        //     `preimage` is msg XOR prev-output, so the message is recovered
        //     bit-by-bit as `p + o − 2·p·o` against `oreg`. The 16-bit
        //     decompositions double as range checks, so the recompositions are
        //     sound without leaning on KeccakAir's own limb bounds.
        //
        // Finally the flush's DIGEST (the last F0 block's output rate) is bound
        // to the exposed `f0dig` public values — issue #21's R2, non-hollow only
        // now that the input side is bound. It needs no carry register: producer
        // and consumer are the same row.
        // =====================================================================
        {
            let fb = &self.consts.flush_blocks;
            let n_f0 = fb[0];
            let f0sel = |b: usize| cv(self.layout.shsel + shsel_index(fb, 0, b));
            // 🔴 SCOPE — READ THIS BEFORE TRUSTING `w0c`/`w1c` ANYWHERE ELSE.
            //
            // The two gates below are F0's `shsel` columns and NOTHING ELSE, so
            // the word-recovery constraints in this block pin `w0c`/`w1c` on
            // F0's absorbing perms ONLY. On every other absorbing perm those
            // columns remain exactly as they were before D3 — READ by the asm
            // pipeline (e.g. `pzacc += preg·w0c`) but pinned to the sponge input
            // by nothing:
            //   * the F2 duplicate chain (the zeta openings the fold pipeline
            //     consumes),
            //   * the final-poly flush,
            //   * the per-query leaf absorb blocks.
            //
            // This is deliberate (D3's spec is the F0 binding; issue #24) and it
            // is the trap that comes with a partial fix: after D3 a reader greps
            // `w0c`, finds constraints, and concludes it is pinned — generally.
            // It is not. Unconstrained-everywhere is a gap; constrained-in-one-
            // place-and-looking-general is worse, because the reader stops
            // looking.
            //
            // The gap is issue #78's class (2) ("referenced but under-
            // determined"), including the verified gate-widening correspondence
            // and the counter-pressure that makes single-word tampering already
            // UNSAT. Whether a COORDINATED tamper is caught is open and
            // deliberately unclaimed here — that is #78's reachability triage.
            let gdir = f0sel(0);
            let gxor = (1..n_f0).map(&f0sel).fold(AB::Expr::ZERO, |a, e| a + e);
            // 17 rows x 4 u16 limbs cover the whole 68-limb keccak rate; row r
            // hosts limbs 4r..4r+4 = u32 words 2r (limbs 0,1) and 2r+1 (2,3).
            const RATE_ROWS: usize = 17;
            let rowmux = |base: usize, j: usize| -> AB::Expr {
                (0..RATE_ROWS)
                    .map(|r| sf(r) * cv(base + 4 * r + j))
                    .fold(AB::Expr::ZERO, |a, e| a + e)
            };
            let pmux = |j: usize| rowmux(pcol(0), j);
            let omux = |j: usize| rowmux(self.layout.oreg, j);
            let recomp = |base: usize, j: usize| -> AB::Expr {
                (0..16)
                    .map(|i| cv(base + 16 * j + i) * c(1 << i))
                    .fold(AB::Expr::ZERO, |a, e| a + e)
            };
            // XOR-recovered message limb (deg 2): Σ (p + o − 2·p·o)·2^i.
            let xor_limb = |j: usize| -> AB::Expr {
                (0..16)
                    .map(|i| {
                        let p = cv(self.layout.pbit + 16 * j + i);
                        let o = cv(self.layout.obit + 16 * j + i);
                        (p.clone() + o.clone() - p * o * c(2)) * c(1 << i)
                    })
                    .fold(AB::Expr::ZERO, |a, e| a + e)
            };
            for j in 0..4 {
                // Unconditional booleans: off the XOR rows the fill leaves these
                // columns zero (trap 3 — new/at-last-constrained columns must be
                // zeroed outside their region), so these hold trivially there.
                for i in 0..16 {
                    builder.assert_bool(cv(self.layout.pbit + 16 * j + i));
                    builder.assert_bool(cv(self.layout.obit + 16 * j + i));
                }
                builder.assert_zero(gxor.clone() * (pmux(j) - recomp(self.layout.pbit, j)));
                builder.assert_zero(gxor.clone() * (omux(j) - recomp(self.layout.obit, j)));
            }
            for (wc, lo) in [(self.layout.w0c, 0usize), (self.layout.w1c, 2usize)] {
                builder.assert_zero(
                    gxor.clone() * (cv(wc) - xor_limb(lo) - xor_limb(lo + 1) * c(1 << 16)),
                );
                builder.assert_zero(
                    gdir.clone() * (cv(wc) - pmux(lo) - pmux(lo + 1) * c(1 << 16)),
                );
            }
            // Per-child pv half select for the interior (`chi` = 0 across child
            // L's rows, 1 across child R's — the same running selector the cap
            // comparison uses). Inert (unread) for narrow / single-wide.
            let half = |i: usize| -> AB::Expr {
                if route {
                    pv(i) + cv(self.layout.chi) * (pv(n_opvs + i) - pv(i))
                } else {
                    pv(i)
                }
            };
            for b in 0..n_f0 {
                for (j, bind) in shape_mosaic(&self.shape, Shape::Obs { flush: 0, block: b })
                    .iter()
                    .enumerate()
                {
                    let gate = f0sel(b) * sf(j / 2);
                    let w = cv(if j % 2 == 0 { self.layout.w0c } else { self.layout.w1c });
                    match bind {
                        WordBind::Const(v) => builder.assert_zero(gate * (w - c(*v))),
                        WordBind::Cap(i) => {
                            builder.assert_zero(gate * (w - half(*i) - half(*i + 1) * c(1 << 16)))
                        }
                        WordBind::Pv(i) => builder.assert_zero(gate * (w - half(*i))),
                        // F0 carries no chain prefix, no opened values and no PoW
                        // witness — every word is Const/Cap/Pv. Anything else here
                        // would be an unbound word, so fail loudly rather than
                        // silently skipping it.
                        other => panic!("F0 mosaic word {j} of block {b} is {other:?} — unbindable"),
                    }
                }
            }
            // R2 (issue #21): the exposed public-surface digest. F0's digest is
            // the last F0 block's output rate limbs 0..16.
            for m in 0..16 {
                builder.assert_zero(
                    sf(23)
                        * f0sel(n_f0 - 1)
                        * (cv(ocol(m)) - half(self.shape.opv_f0dig() + m)),
                );
            }
        }
        // =====================================================================
        // Shape selectors: fully determined by the flush automaton (no
        // prover choice = no ghost perms in the challenger phase).
        // =====================================================================
        let ringsel = |f: usize| cv(ring_at(self.layout.fring, 8, f));
        let bidxsel = |b: usize| cv(self.layout.bidx + b);
        let chal_live = cv(self.layout.chlive);
        {
            let shapes = shape_list(&self.shape);
            for (si, sh) in shapes.iter().enumerate() {
                let e = match sh {
                    Shape::Obs { flush: 2, block: 0 } => ringsel(2) * bidxsel(0),
                    Shape::F2Mid => {
                        // self.layout.f2sel = ringsel(2) * (1 - bidxsel(0)); keeps deg <= 3.
                        cv(self.layout.f2sel) * (AB::Expr::ONE - cv(self.layout.blklast))
                    }
                    Shape::Obs { flush: 2, .. } => {
                        // F2 last block.
                        cv(self.layout.f2sel) * cv(self.layout.blklast)
                    }
                    Shape::Obs { flush, block } => ringsel(*flush) * bidxsel(*block),
                    Shape::Refill => continue, // self.layout.refsel is its own column
                };
                builder.assert_eq(cv(self.layout.shsel + shsel_index_of(si)), chal_live.clone() * e);
            }
        }
        builder.assert_bool(cv(self.layout.refsel));
        builder.assert_zero(cv(self.layout.refsel) * (AB::Expr::ONE - phc.clone()));

        // Flush-automaton comparators.
        builder.assert_bool(cv(self.layout.blklast));
        builder.assert_zero((cv(self.layout.blkcnt) - AB::Expr::ONE) * cv(self.layout.blklast));
        builder.assert_eq(
            cv(self.layout.blklast) + (cv(self.layout.blkcnt) - AB::Expr::ONE) * cv(self.layout.blkinv),
            AB::Expr::ONE,
        );
        // CMPA/CMPB fire at the dup-block BLKCNT of the group-0 / group-1
        // reduced-opening boundary; CMPC at the dup-first-block BLKCNT = N.
        // All shape-derived (narrow: 76, 3, 148).
        let dcap = self.shape.dup_captures();
        let n_dup = self.consts.flush_blocks[2] as u32;
        for (cmp, cinv, tgt) in [(self.layout.cmpa, self.layout.cmpai, dcap[0].2), (self.layout.cmpb, self.layout.cmpbi, dcap[1].2), (self.layout.cmpc, self.layout.cmpci, n_dup)] {
            builder.assert_bool(cv(cmp));
            builder.assert_zero((cv(self.layout.blkcnt) - c(tgt)) * cv(cmp));
            builder.assert_eq(cv(cmp) + (cv(self.layout.blkcnt) - c(tgt)) * cv(cinv), AB::Expr::ONE);
        }
        // self.layout.needl = self.layout.blklast * (required group reached for the next obs flush).
        {
            let groupreq = self.shape.groupreq();
            let mut need = AB::Expr::ZERO;
            for f in 0..self.consts.flush_blocks.len() {
                need = need + ringsel(f) * cv(ring_at(self.layout.grp, self.shape.n_groups(), groupreq[f + 1]));
            }
            builder.assert_eq(cv(self.layout.needl), cv(self.layout.blklast) * need);
        }

        // First-row pins for the challenger phase.
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.fring) - AB::Expr::ONE));
        for i in 1..8 {
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.fring + i));
        }
        // blkcnt (flush-automaton block counter) is per-transcript state → must
        // re-anchor to flush_blocks[0] at each child start (csel), not only row 0.
        builder.assert_zero(
            cv(self.layout.csel) * (cv(self.layout.blkcnt) - c(self.consts.flush_blocks[0] as u32)),
        );
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.bidx) - AB::Expr::ONE));
        for i in 1..self.layout.bidx_width {
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.bidx + i));
        }
        builder.assert_zero(cv(self.layout.csel) * cv(self.layout.refsel));
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.grp) - AB::Expr::ONE));
        for i in 1..self.shape.n_groups() {
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.grp + i));
        }
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.coef) - AB::Expr::ONE));
        for i in 1..4 {
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.coef + i));
        }
        builder.assert_zero(cv(self.layout.csel) * cv(self.layout.phd));
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.pos) - AB::Expr::ONE));
        builder.assert_zero(cv(self.layout.csel) * cv(self.layout.pos + 1));
        builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.vc) - AB::Expr::ONE));
        for i in 1..16 {
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.vc + i));
        }
        for k in 0..4 {
            builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.preg + k) - if k == 0 { AB::Expr::ONE } else { AB::Expr::ZERO }));
            builder.assert_zero(cv(self.layout.csel) * cv(self.layout.pzacc + k));
        }

        // =====================================================================
        // Boundary rules (perm transitions in the challenger/dup phases)
        // =====================================================================
        let consumersel = {
            let mut e = cv(self.layout.refsel);
            for f in 1..self.consts.flush_blocks.len() {
                e = e + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
            }
            e
        };
        let b0next = {
            let mut e = AB::Expr::ZERO;
            for f in 1..self.consts.flush_blocks.len() {
                e = e + nv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
            }
            e
        };
        let xorsel = {
            // Obs interior blocks except flush 2, plus dup interior blocks.
            let mut e = cv(self.layout.phd) * (AB::Expr::ONE - cv(self.layout.cmpc));
            for f in 0..self.consts.flush_blocks.len() {
                if f == 2 {
                    continue;
                }
                for b in 1..self.consts.flush_blocks[f] {
                    e = e + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, b));
                }
            }
            e
        };
        // xorsel_next = nv(self.layout.xsel) (materialized current-row xorsel; deg 1).
        let xorsel_next = nv(self.layout.xsel);
        let phasegate = cv(self.layout.phg);
        let phdend = cv(self.layout.phdend);
        let endgate = cv(self.layout.endg);
        {
            let mut t = builder.when_transition();
            // Obs flush start: only the ring successor, only when the
            // required draw group has completed.
            for f in 1..self.consts.flush_blocks.len() {
                let sel = nv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
                t.assert_zero(sf(23) * sel.clone() * (AB::Expr::ONE - ringsel(f - 1)));
                t.assert_zero(sf(23) * sel * (cv(self.layout.blklast) - cv(self.layout.needl)));
            }
            // Mid-flush: no new flush, no refill. (self.layout.cont = sf(23)*phc*(1-self.layout.blklast).)
            t.assert_zero(cv(self.layout.cont) * (b0next.clone() + nv(self.layout.refsel)));
            // Refill: only when the required group is incomplete, and only
            // after a consumer that used its full window.
            t.assert_zero(sf(23) * nv(self.layout.refsel) * cv(self.layout.needl));
            // self.layout.cfull = sf(23) * consumersel * (1 - self.layout.fsfull); keeps deg <= 3.
            t.assert_zero(nv(self.layout.refsel) * cv(self.layout.cfull));
            // self.layout.fring rotation at obs starts. 2b-iii: the gate
            // sf(23)·b0next is materialized as self.layout.frgm (deg 2) so the
            // rotation, suppressed at the child boundary via (1-csel_next), stays
            // deg 3 (fring reaches the last obs flush at a child's end but child R
            // must re-anchor slot 0). Narrow: (1-nv(csel))=1 in every single-child
            // transition → byte-identical.
            t.assert_eq(cv(self.layout.frgm), sf(23) * b0next.clone());
            for i in 0..8 {
                t.assert_zero(
                    (AB::Expr::ONE - nv(self.layout.csel))
                        * (nv(self.layout.fring + i)
                            - cv(self.layout.fring + i)
                            - cv(self.layout.frgm) * (cv(self.layout.fring + (i + 1) % 8) - cv(self.layout.fring + i))),
                );
            }
            // self.layout.bidx: reset on new flush/refill, saturating rotate on
            // continuation, hold otherwise (query/dup phases).
            let newf = sf(23) * (b0next.clone() + nv(self.layout.refsel));
            let cont = cv(self.layout.cont);
            let bw = self.layout.bidx_width;
            for i in 0..bw {
                // saturating shift: slot 0 <- 0, top slot accumulates (sticks),
                // else slot i <- slot i-1. Narrow bw=6 reproduces the old match.
                let rot = if i == 0 {
                    AB::Expr::ZERO
                } else if i == bw - 1 {
                    cv(self.layout.bidx + bw - 2) + cv(self.layout.bidx + bw - 1)
                } else {
                    cv(self.layout.bidx + i - 1)
                };
                t.assert_eq(
                    nv(self.layout.bidx + i),
                    cv(self.layout.bidx + i)
                        + newf.clone()
                            * (if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO } - cv(self.layout.bidx + i))
                        + cont.clone() * (rot - cv(self.layout.bidx + i)),
                );
            }
            // self.layout.blkcnt: reload at obs starts, 1 at refills, decrement on
            // continuation (chal) and during the dup chain, 148 at dup entry.
            let mut reload = AB::Expr::ZERO;
            for f in 1..self.consts.flush_blocks.len() {
                reload = reload
                    + nv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0))
                        * (c(self.consts.flush_blocks[f] as u32) - cv(self.layout.blkcnt));
            }
            let dupdec = sf(23) * cv(self.layout.phd) * (AB::Expr::ONE - cv(self.layout.blklast));
            // 2b-iii: the blkcnt update delta is deg 3 (sf(23)·reload, dupdec).
            // Materialize it as self.layout.bcbd so the carry — suppressed at the
            // child boundary via (1-csel_next) — stays deg 2 (blkcnt holds a stale
            // query-phase value at a child's end but child R re-anchors
            // flush_blocks[0]). Narrow byte-identical (gate factor 1 there).
            t.assert_eq(
                cv(self.layout.bcbd),
                sf(23) * reload
                    + sf(23) * nv(self.layout.refsel) * (AB::Expr::ONE - cv(self.layout.blkcnt))
                    + cont.clone() * (-AB::Expr::ONE)
                    + dupdec * (-AB::Expr::ONE)
                    + phasegate.clone() * (c(self.consts.flush_blocks[2] as u32) - cv(self.layout.blkcnt)),
            );
            t.assert_zero(
                (AB::Expr::ONE - nv(self.layout.csel))
                    * (nv(self.layout.blkcnt) - cv(self.layout.blkcnt) - cv(self.layout.bcbd)),
            );
            // Phase evolution. 2b-iii: suppressed at the child boundary — phc
            // reaches 0 at a child's end (challenger done) but child R re-anchors
            // phc=1; phd/phq reach 0 and agree, gated for robustness (deg 2).
            let ncsel = AB::Expr::ONE - nv(self.layout.csel);
            t.assert_zero(ncsel.clone() * (nv(self.layout.phc) - (phc.clone() - phasegate.clone())));
            t.assert_zero(ncsel.clone() * (nv(self.layout.phd) - (cv(self.layout.phd) + phasegate.clone() - phdend.clone())));
            t.assert_zero(ncsel * (nv(self.layout.phq) - (phq.clone() + phdend.clone() - endgate.clone())));
            // Chain gate: a consumer perm's first 16 preimage limbs are the
            // previous perm's digest.
            let chainsel_next = {
                let mut e = nv(self.layout.refsel);
                for f in 1..self.consts.flush_blocks.len() {
                    e = e + nv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
                }
                e
            };
            for m in 0..16 {
                t.assert_zero(sf(23) * chainsel_next.clone() * (nv(pcol(m)) - cv(ocol(m))));
            }
            // XOR blocks: capacity carries + self.layout.oreg capture of the previous
            // output's rate limbs.
            for i in 68..100 {
                t.assert_zero(sf(23) * xorsel_next.clone() * (nv(pcol(i)) - cv(ocol(i))));
            }
            for i in 0..68 {
                let g = sf(23) * xorsel_next.clone();
                t.assert_eq(
                    nv(self.layout.oreg + i),
                    cv(self.layout.oreg + i) + g * (cv(ocol(i)) - cv(self.layout.oreg + i)),
                );
            }
            // F2 digest capture at flush 2's last block.
            let f2last = sf(23)
                * cv(self.layout.shsel
                    + shsel_index(&self.consts.flush_blocks, 2, self.consts.flush_blocks[2] - 1));
            for m in 0..16 {
                t.assert_eq(
                    nv(self.layout.f2dig + m),
                    cv(self.layout.f2dig + m) + f2last.clone() * (cv(ocol(m)) - cv(self.layout.f2dig + m)),
                );
            }
            // Dup-chain digest binding at the duplicate's last block.
            for m in 0..16 {
                t.assert_zero(phdend.clone() * (cv(ocol(m)) - cv(self.layout.f2dig + m)));
            }
        }
        // Dup first block: fresh keccak-256 state (capacity zero); B0 obs
        // blocks likewise.
        for i in 68..100 {
            builder.assert_zero(cv(self.layout.phd) * cv(self.layout.cmpc) * cv(pcol(i)));
            let mut b0 = cv(self.layout.shsel); // F0B0
            for f in 1..self.consts.flush_blocks.len() {
                b0 = b0 + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
            }
            builder.assert_zero((b0 + cv(self.layout.refsel)) * cv(pcol(i)));
        }
        // =====================================================================
        // FS draw gadget (inc-4): byte-packing + rejection comparator, bound
        // to the sponge digest via limb consistency. Mirrors the proven inc-3
        // gadget in m4route.rs; active on every FS row (self.layout.fsgate = 1), which the
        // witness places on the first 2*ndraws rows of a draw-hosting perm.
        // Draw j occupies row offsets 2j (even) and 2j+1 (odd); it reads
        // digest limbs 2g and 2g+1 for g = 7 - j (pop-from-end byte order).
        // =====================================================================
        {
            let fs = cv(self.layout.fsgate);
            builder.assert_bool(fs.clone());
            let bit = |i: usize| -> AB::Expr { cv(self.layout.fsbits + i) };
            for i in 0..16 {
                builder.assert_bool(bit(i));
            }
            // Byte recompositions (bits 0..8 = draw-low byte = limb high byte;
            // bits 8..16 = draw-high byte = limb low byte).
            let mut b_lo = AB::Expr::ZERO;
            let mut b_hi = AB::Expr::ZERO;
            let mut b_hi_masked = AB::Expr::ZERO; // top byte with bit 7 dropped
            for i in 0..8 {
                let wgt = c(1 << i);
                b_lo = b_lo + wgt.clone() * bit(i);
                b_hi = b_hi + wgt.clone() * bit(8 + i);
                if i < 7 {
                    b_hi_masked = b_hi_masked + wgt * bit(8 + i);
                }
            }
            // Limb consistency: on FS row r (draw j = r/2, g = 7-j), the read
            // limb is preimage limb 2g+1 (even) or 2g (odd); both recompose to
            // limb = b_hi + 2^8 * b_lo. This ties the draw to the real digest.
            let mut limb_mux = AB::Expr::ZERO;
            for r in 0..16 {
                let j = r / 2;
                let m = if r % 2 == 0 { 2 * (7 - j) + 1 } else { 2 * (7 - j) };
                limb_mux = limb_mux + sf(r) * cv(pcol(m));
            }
            builder.assert_zero(fs.clone() * (limb_mux - (b_hi.clone() + c(1 << 8) * b_lo.clone())));
            // Even/odd row selectors within the FS window.
            let mut even_mux = AB::Expr::ZERO;
            let mut odd_mux = AB::Expr::ZERO;
            for j in 0..8 {
                even_mux = even_mux + sf(2 * j);
                odd_mux = odd_mux + sf(2 * j + 1);
            }
            // self.layout.fsodd materialization (fs * odd row) and the even-row ACC load:
            // the odd row's self.layout.fsacc = the draw's low 16 bits, computed on the
            // even row as b_lo + 2^8 * b_hi (even-row bytes = x3, x2).
            builder.assert_eq(cv(self.layout.fsodd), fs.clone() * odd_mux.clone());
            builder.assert_zero(
                fs.clone()
                    * even_mux
                    * (nv(self.layout.fsacc) - (b_lo.clone() + c(1 << 8) * b_hi.clone())),
            );
            // Rejection comparator (materialized bit products, deg <= 3):
            // reject iff bits 24..30 all one AND low-24 bits nonzero.
            builder.assert_eq(cv(self.layout.fsp3a), bit(8) * bit(9) * bit(10));
            builder.assert_eq(cv(self.layout.fsp3b), bit(11) * bit(12) * bit(13));
            builder.assert_eq(cv(self.layout.fst7), cv(self.layout.fsp3a) * cv(self.layout.fsp3b) * bit(14));
            let low24 = cv(self.layout.fsacc) + c(1 << 16) * b_lo.clone();
            builder.assert_eq(cv(self.layout.fsnz), low24.clone() * cv(self.layout.fsinv));
            builder.assert_bool(cv(self.layout.fsnz));
            builder.assert_zero((AB::Expr::ONE - cv(self.layout.fsnz)) * low24);
            builder.assert_zero(fs.clone() * (cv(self.layout.fsaccept) - (AB::Expr::ONE - cv(self.layout.fst7) * cv(self.layout.fsnz))));

            // =================================================================
            // R3 (issue #21): FSGATE schedule-position pin. FS draws are hosted
            // only on the consumer/trailer perms (`consumersel` = refsel +
            // block-0 obs shsel; `lane_plan` classifies obs-flush block-0 perms
            // as Obs{block:0} and the trailer/refills as Refill with refsel=1).
            // Pinning FSGATE off every other perm stops the byte gadget being
            // spuriously activated on a non-digest perm — relocating FS activity
            // while staying locally consistent (the Stage-D residual). The
            // row-WITHIN-a-perm is already pinned by the limb_mux above; the
            // contiguity constraint forbids gapped / shifted draw rows within a
            // hosting perm (draws honestly fill rows 0..2·ndraws as a prefix).
            // =================================================================
            {
                let mut consumersel = cv(self.layout.refsel);
                for f in 1..self.consts.flush_blocks.len() {
                    consumersel = consumersel
                        + cv(self.layout.shsel + shsel_index(&self.consts.flush_blocks, f, 0));
                }
                builder.assert_zero(fs.clone() * (AB::Expr::ONE - consumersel));
                // Contiguous prefix within a perm: FSGATE may not turn back on
                // (0 -> 1) except across a perm boundary (gated out by 1-sf(23)).
                let mut t = builder.when_transition();
                t.assert_zero(
                    (AB::Expr::ONE - sf(23))
                        * nv(self.layout.fsgate)
                        * (AB::Expr::ONE - cv(self.layout.fsgate)),
                );
            }

            // =================================================================
            // Ext-challenge assembly (inc-4): accepted field draws feed the
            // self.layout.coef ring / self.layout.curch limbs; every 4th accepted draw assembles
            // self.layout.chal[grp] and advances the self.layout.grp ring. PoW/query-index (bits) draws
            // run the same byte gadget but sit at grp >= self.shape.g_pow(); the field_grp
            // gate keeps them out of the field assembly, and sample_bits (below)
            // handles the query-index binding.
            // =================================================================
            let masked = cv(self.layout.fsacc) + c(1 << 16) * b_lo + c(1 << 24) * b_hi_masked;
            // A field-challenge group (0..6) is the ring head. Query-index and
            // PoW (bits) draws sit at grp >= self.shape.g_pow() and must NOT drive the
            // challenge assembly even though they run the same byte gadget.
            let field_grp = (0..self.shape.n_chals())
                .map(|g| cv(ring_at(self.layout.grp, self.shape.n_groups(), g)))
                .fold(AB::Expr::ZERO, |a, e| a + e);
            // self.layout.crot = accept, on an odd FS row whose active group is a field
            // challenge. (bits draws set self.layout.crot = 0.)
            builder.assert_bool(cv(self.layout.crot));
            builder.assert_bool(cv(self.layout.grot));
            builder.assert_eq(cv(self.layout.crot), field_grp * cv(self.layout.fsodd) * cv(self.layout.fsaccept));
            // A bits group (PoW or a query index): each is a single draw that
            // completes on its odd row.
            let bits_grp = {
                let mut e = cv(ring_at(self.layout.grp, self.shape.n_groups(), self.shape.g_pow()));
                for q in 0..self.shape.nq {
                    e = e + cv(ring_at(self.layout.grp, self.shape.n_groups(), self.shape.g_idx0() + q));
                }
                e
            };
            // self.layout.grot (advance the group ring): a field challenge's 4th accepted
            // limb (self.layout.crot & coef==3), OR any bits draw's odd row. This fully
            // pins self.layout.grot, which now drives the self.layout.grp-ring rotation below.
            let coef3 = cv(ring_at(self.layout.coef, 4, 3));
            builder.assert_eq(cv(self.layout.grot), cv(self.layout.crot) * coef3 + cv(self.layout.fsodd) * bits_grp.clone());
            // PoW draw (grp = self.shape.g_pow()): the low self.shape.grind_bits of the sampled value
            // must be zero (the grind check). value = self.layout.fsacc (bits 0..16) +
            // self.layout.fsbits[0..self.shape.grind_bits-16] << 16.
            {
                let pow_gate = cv(self.layout.fsodd) * cv(ring_at(self.layout.grp, self.shape.n_groups(), self.shape.g_pow()));
                let mut pow_val = cv(self.layout.fsacc);
                for i in 0..(self.shape.grind_bits - 16) {
                    pow_val = pow_val + cv(self.layout.fsbits + i) * c(1 << (16 + i));
                }
                builder.assert_zero(pow_gate * pow_val);
            }
            // First-row pins: no challenge assembled yet. These are DATA registers
            // assembled/overwritten by each child's own FS draws before use, so they
            // only need the true-row-0 pin (not a per-child csel re-anchor): child R
            // INHERITS child L's final values (2b-iii fill-continuity) and its draws
            // overwrite them — the freeze carries then hold with no gating.
            for k in 0..4 {
                builder.when_first_row().assert_zero(cv(self.layout.curch + k));
            }
            for k in 0..4 * self.shape.n_chals() {
                builder.when_first_row().assert_zero(cv(self.layout.chal + k));
            }
            for q in 0..self.shape.nq {
                builder.when_first_row().assert_zero(cv(self.layout.idxr + q));
            }
            // sample_bits (query indices): value = low self.shape.log_max (=22) bits of
            // the draw = self.layout.fsacc (bits 0..16) + self.layout.fsbits[0..6] << 16. No rejection.
            // The draw sits at grp = self.shape.g_idx0() + q; bind self.layout.idxr[q] on its odd row.
            let idx_val = {
                let mut e = cv(self.layout.fsacc);
                for i in 0..(self.shape.log_max - 16) {
                    e = e + cv(self.layout.fsbits + i) * c(1 << (16 + i));
                }
                e
            };
            {
                let mut t = builder.when_transition();
                // self.layout.grp ring: left-rotate (advance the logical group) on self.layout.grot.
                // This binds the draw-group schedule to the FS gadget, giving
                // the GROUPREQ flush-start gate (Stage A) real teeth.
                // 2b-iii: suppressed at the child boundary (grp reaches g_done at a
                // child's end but child R must re-anchor slot 0).
                for i in 0..self.shape.n_groups() {
                    t.assert_zero(
                        (AB::Expr::ONE - nv(self.layout.csel))
                            * (nv(self.layout.grp + i)
                                - cv(self.layout.grp + i)
                                - cv(self.layout.grot) * (cv(self.layout.grp + (i + 1) % self.shape.n_groups()) - cv(self.layout.grp + i))),
                    );
                }
                // self.layout.coef ring: left-rotate (increment logical coef) on self.layout.crot.
                for i in 0..4 {
                    t.assert_zero(
                        (AB::Expr::ONE - nv(self.layout.csel))
                            * (nv(self.layout.coef + i)
                                - cv(self.layout.coef + i)
                                - cv(self.layout.crot) * (cv(self.layout.coef + (i + 1) % 4) - cv(self.layout.coef + i))),
                    );
                }
                // self.layout.curch: an accepted draw at coef c<3 loads self.layout.curch[c] = masked;
                // slot 3 is never loaded (the 4th limb goes straight to self.layout.chal).
                for cc in 0..3 {
                    let gate = cv(self.layout.crot) * cv(ring_at(self.layout.coef, 4, cc));
                    t.assert_eq(
                        nv(self.layout.curch + cc),
                        cv(self.layout.curch + cc) + gate * (masked.clone() - cv(self.layout.curch + cc)),
                    );
                }
                t.assert_eq(nv(self.layout.curch + 3), cv(self.layout.curch + 3));
                // self.layout.chal[grp] assembly on self.layout.grot: limbs (CURCH0..2, masked) into
                // the self.layout.grp-ring-selected challenge register; carries otherwise.
                for g in 0..self.shape.n_chals() {
                    let gate = cv(self.layout.grot) * cv(ring_at(self.layout.grp, self.shape.n_groups(), g));
                    for k in 0..4 {
                        let asm = if k < 3 { cv(self.layout.curch + k) } else { masked.clone() };
                        t.assert_eq(
                            nv(self.layout.chal + 4 * g + k),
                            cv(self.layout.chal + 4 * g + k) + gate.clone() * (asm - cv(self.layout.chal + 4 * g + k)),
                        );
                    }
                }
                // self.layout.idxr[q] = idx_val on the odd row of query q's bits draw
                // (grp = self.shape.g_idx0() + q); carries otherwise. Ties every FRI query
                // index to the FS-sampled digest bits — no free query choice.
                for q in 0..self.shape.nq {
                    let gate = cv(self.layout.fsodd) * cv(ring_at(self.layout.grp, self.shape.n_groups(), self.shape.g_idx0() + q));
                    t.assert_eq(
                        nv(self.layout.idxr + q),
                        cv(self.layout.idxr + q) + gate * (idx_val.clone() - cv(self.layout.idxr + q)),
                    );
                }
            }
        }

        // =====================================================================
        // Value-carry-row schedule (fold-pipeline foundation, inc-4): bind the
        // asm/PX value-carry selectors to the role/phase schedule + row ranges,
        // then the self.layout.pos half-position toggle and the self.layout.consz/self.layout.consf completion
        // flags. Everything derives from already-bound selectors (self.layout.rsel, self.layout.drnd,
        // self.layout.shsel, self.layout.phd, self.layout.cmpc, self.layout.blklast) + the keccak step-flag row one-hots. This
        // is the bottom layer of the reduced-opening / fold machinery; the
        // arithmetic layers (self.layout.pzacc/self.layout.scr/self.layout.breg/self.layout.runev) build on these selectors.
        // =====================================================================
        {
            let one = || AB::Expr::ONE;
            // Row-range indicators from the step-flag one-hots (sf(r) = cv(r)).
            let rle = |n: usize| (0..=n).map(&sf).fold(AB::Expr::ZERO, |a, e| a + e);
            let rge = |a: usize, b: usize| (a..=b).map(&sf).fold(AB::Expr::ZERO, |x, e| x + e);
            let rsel = |r: u32| cv(self.layout.rsel + r as usize);
            // Per-role asm value ranges (word-0 / word-1 half positions). A
            // block of `f` fresh u32 words routes 2 words/row (word-0 even,
            // word-1 odd), so word-0 fills ceil(f/2) rows → rle(ceil(f/2)-1)
            // and word-1 fills floor(f/2) rows → rle(floor(f/2)-1). Per-role
            // fresh count: F34/C34 = 34 (full rate), C5 = trace_last_fresh,
            // C30 = 30 (fold-last), F16 = qw (single-block leaf). Narrow
            // reproduces (F34/C34 rle16, C5 rle2/rle1, C30 rle14, F16 rle7);
            // wide gets C5 f=22 → rle10/rle10 and F16 qw=8 → rle3/rle3.
            let m0w = |f: usize| (f + 1) / 2 - 1;
            let m1w = |f: usize| f / 2 - 1;
            let tlf = self.shape.trace_last_fresh();
            let qw = self.shape.qw;
            let role_range = |wf: fn(usize) -> usize| {
                rsel(R_ABS_F34) * rle(wf(34))
                    + rsel(R_ABS_C34) * rle(wf(34))
                    + rsel(R_ABS_C5) * rle(wf(tlf))
                    + rsel(R_ABS_C30) * rle(wf(30))
                    + rsel(R_ABS_F16) * rle(wf(qw))
            };
            let m0 = role_range(m0w);
            let m1 = role_range(m1w);
            // dparam split: fold leaves (D_F0..) vs trace/quotient (D_T/D_Q).
            // D_F rounds = drnd[2 .. 2+n_fri_rounds] (narrow 2..6, wide 2..5;
            // drnd+5 on wide = dbit OOB).
            let fold_dp = (0..self.shape.n_fri_rounds())
                .map(|rf| cv(self.layout.drnd + 2 + rf))
                .fold(AB::Expr::ZERO, |a, e| a + e);
            let nonfold_dp = cv(self.layout.drnd) + cv(self.layout.drnd + 1);
            // Query-absorb carry selectors.
            builder.assert_eq(cv(self.layout.cf), fold_dp * m0.clone());
            builder.assert_eq(cv(self.layout.cx0), nonfold_dp.clone() * m0);
            builder.assert_eq(cv(self.layout.cx1), nonfold_dp * m1);
            // Final-flush observation blocks (challenger phase): final-poly
            // carry rows. Final obs flush index = 3 + n_fri_rounds (narrow 7).
            let ff = self.consts.flush_blocks.len() - 1;
            let fb = &self.consts.flush_blocks;
            builder.assert_eq(
                cv(self.layout.cz7),
                cv(self.layout.shsel + shsel_index(fb, ff, 0)) * rge(4, 16)
                    + cv(self.layout.shsel + shsel_index(fb, ff, 1)) * rle(16)
                    + cv(self.layout.shsel + shsel_index(fb, ff, 2)) * rle(1),
            );
            // Duplicate blocks (dup phase): zeta-value carry rows. First block
            // (self.layout.cmpc) rows 4..16 (32-byte digest prefix = 4 rows,
            // then 13 value-rows), middle blocks rows 0..16 (full 17-row rate),
            // last block (self.layout.blklast) rows 0..(row_a2-1) where the A2
            // (end) capture at row_a2 lands one past the last consume. Narrow
            // row_a2=5 → rle(4); wide row_a2=6 → rle(5).
            let dup_last_top = self.shape.dup_captures()[2].1 - 1;
            builder.assert_eq(
                cv(self.layout.czd),
                cv(self.layout.phd) * cv(self.layout.cmpc) * rge(4, 16)
                    + cv(self.layout.phd) * cv(self.layout.blklast) * rle(dup_last_top)
                    + cv(self.layout.phd) * (one() - cv(self.layout.cmpc) - cv(self.layout.blklast)) * rle(16),
            );
            for s in [self.layout.czd, self.layout.cz7, self.layout.cf, self.layout.cx0, self.layout.cx1] {
                builder.assert_bool(cv(s));
            }
            // self.layout.pos: 2-slot half-position ring, toggles on every asm value-carry
            // row (casm = self.layout.czd + self.layout.cz7 + self.layout.cf); self.layout.cx0/self.layout.cx1 are PX rows and do not toggle.
            let casm = cv(self.layout.czd) + cv(self.layout.cz7) + cv(self.layout.cf);
            builder.assert_bool(cv(self.layout.pos));
            builder.assert_bool(cv(self.layout.pos + 1));
            builder.assert_eq(cv(self.layout.pos) + cv(self.layout.pos + 1), one());
            {
                let mut t = builder.when_transition();
                t.assert_eq(nv(self.layout.pos), cv(self.layout.pos) + casm.clone() * (cv(self.layout.pos + 1) - cv(self.layout.pos)));
                t.assert_eq(nv(self.layout.pos + 1), cv(self.layout.pos + 1) + casm * (cv(self.layout.pos) - cv(self.layout.pos + 1)));
            }
            // Completion flags: value fully captured on the pos==1 (word-1) row.
            builder.assert_eq(cv(self.layout.consz), cv(self.layout.czd) * cv(self.layout.pos + 1));
            builder.assert_eq(cv(self.layout.consf), cv(self.layout.cf) * cv(self.layout.pos + 1));

            // self.layout.vc value-counter ring (16-slot one-hot): counts fold leaves
            // within a round. Rotates +1 on self.layout.consf (a completed fold-leaf
            // value, now schedule-bound), resets to slot 0 at each leaf-start
            // (self.layout.lfs on the next perm). First row pinned to slot 0 above.
            for i in 0..16 {
                builder.assert_bool(cv(self.layout.vc + i));
            }
            builder.assert_eq(
                (0..16).map(|i| cv(self.layout.vc + i)).fold(AB::Expr::ZERO, |a, e| a + e),
                one(),
            );
            builder.assert_eq(
                cv(self.layout.vce),
                (0..16).step_by(2).map(|i| cv(self.layout.vc + i)).fold(AB::Expr::ZERO, |a, e| a + e),
            );
            {
                let mut t = builder.when_transition();
                let reset = sf(23) * nv(self.layout.lfs);
                for i in 0..16 {
                    let slot0 = if i == 0 { one() } else { AB::Expr::ZERO };
                    t.assert_eq(
                        nv(self.layout.vc + i),
                        cv(self.layout.vc + i)
                            + cv(self.layout.consf) * (cv(self.layout.vc + (i + 15) % 16) - cv(self.layout.vc + i))
                            + reset.clone() * (slot0 - cv(self.layout.vc + i)),
                    );
                }
            }
            // self.layout.gpb: the fold round's index-in-group bits, muxed from the query
            // index bits self.layout.idxb by the fold-round dparam (D_F0..3 -> self.layout.drnd 2..5).
            // Zero on non-fold-absorb perms.
            for k in 0..4 {
                let mut e = AB::Expr::ZERO;
                for rf in 0..self.shape.n_fri_rounds() {
                    if k < self.shape.log_arities[rf] {
                        e = e + cv(self.layout.drnd + 2 + rf) * cv(self.layout.idxb + self.shape.cum()[rf] + k);
                    }
                }
                builder.assert_bool(cv(self.layout.gpb + k));
                builder.assert_eq(cv(self.layout.gpb + k), e);
            }
        }

        // =====================================================================
        // R1 (issue #21): word canonicity comparator. On value-consuming asm
        // rows (casm = czd+cz7+cf: dup zeta openings, final-poly, fold leaves)
        // the consumed words W0C/W1C must be canonical KoalaBear representatives
        // (< P = 0x7F000001). W0C is field-reduced (v and v+p collapse), so the
        // check binds a range-FORCED 32-bit digit split — HBx (16 hi bits) +
        // CANON_LOx (16 lo bits) — and rejects the split whose integer ≥ P:
        //   Wxc == Σ CANON_LOx[i]·2^i + 2^16·Σ HBx[i]·2^i            (deg 2)
        //   canonical ⟺ bit31 clear AND NOT(bits24..30 all set AND bits0..23≠0)
        // TA/TOPA/TOP7 stage the 7-bit AND (word bits 24..30 = hi bits 8..14) so
        // the reject products TOP7·lbnz, TOP7·lonz stay deg 3. Query trace/
        // quotient openings (cx0/cx1) are Merkle-bound to the canonical public
        // cap, so they need no explicit check. Off-casm rows the columns are 0
        // (buffer is zero-init; only fill_canon writes them), so the
        // unconditional bit-booleans and TA/TOPA/TOP7 defining constraints hold
        // trivially there.
        // =====================================================================
        {
            let casm = cv(self.layout.czd) + cv(self.layout.cz7) + cv(self.layout.cf);
            let words = [
                (self.layout.hb0, self.layout.canon_lo0, self.layout.ta0, self.layout.topa0, self.layout.top7_0, self.layout.lbnz0, self.layout.lbi0, self.layout.lonz0, self.layout.loi0, self.layout.w0c),
                (self.layout.hb1, self.layout.canon_lo1, self.layout.ta1, self.layout.topa1, self.layout.top7_1, self.layout.lbnz1, self.layout.lbi1, self.layout.lonz1, self.layout.loi1, self.layout.w1c),
            ];
            for (hb, lo, ta, topa, top7, lbnz, lbi, lonz, loi, wc) in words {
                // Bit booleans (unconditional; off-casm the columns are 0).
                for i in 0..16 {
                    builder.assert_bool(cv(hb + i));
                    builder.assert_bool(cv(lo + i));
                }
                // Range-forced 32-bit digit split binds the consumed field value.
                let mut recomp = AB::Expr::ZERO;
                for i in 0..16 {
                    recomp = recomp + cv(lo + i) * c(1 << i) + cv(hb + i) * c(1 << (16 + i));
                }
                builder.assert_zero(casm.clone() * (cv(wc) - recomp));
                // Low-part nonzero witnesses. lb = word bits 16..23 = hi bits
                // 0..7 (= hb0..7); lo-part = word bits 0..15 (= CANON_LO).
                let mut lb = AB::Expr::ZERO;
                for i in 0..8 {
                    lb = lb + cv(hb + i) * c(1 << i);
                }
                builder.assert_bool(cv(lbnz));
                builder.assert_eq(cv(lbnz), lb.clone() * cv(lbi));
                builder.assert_zero((AB::Expr::ONE - cv(lbnz)) * lb);
                let mut lov = AB::Expr::ZERO;
                for i in 0..16 {
                    lov = lov + cv(lo + i) * c(1 << i);
                }
                builder.assert_bool(cv(lonz));
                builder.assert_eq(cv(lonz), lov.clone() * cv(loi));
                builder.assert_zero((AB::Expr::ONE - cv(lonz)) * lov);
                // Top-7-set flag (word bits 24..30 = hi bits 8..14), staged deg 3.
                builder.assert_eq(cv(ta), cv(hb + 8) * cv(hb + 9) * cv(hb + 10));
                builder.assert_eq(cv(topa), cv(ta) * cv(hb + 11) * cv(hb + 12));
                builder.assert_eq(cv(top7), cv(topa) * cv(hb + 13) * cv(hb + 14));
                // Canonicity reject (gated by casm): bit31 clear, and not
                // (top-7 all set AND low-24 nonzero).
                builder.assert_zero(casm.clone() * cv(hb + 15));
                builder.assert_zero(casm.clone() * cv(top7) * cv(lbnz));
                builder.assert_zero(casm.clone() * cv(top7) * cv(lonz));
            }
        }

        // =====================================================================
        // M_X1 x-chain (fold-pipeline arithmetic, inc-4): self.layout.xreg (query LDE
        // point) = GEN · ∏_r (kx[r] if idx-bit r else 1), a 22-row mul-bank
        // chain over the query index bits (rows 0..21). Since self.layout.idxb is bound to
        // the sampled digest (Stage E), this pins the query point to the
        // transcript. Native arithmetic (the x-chain is unscaled).
        // =====================================================================
        {
            // Native (unscaled) Val -> constant. Note `cf` above equals
            // `scale` (it round-trips through the Monty limb), so it is wrong
            // for the native x-chain; use the canonical value here.
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let msel_x = cv(self.layout.msel + M_X1 as usize);
            // mul_b = ext_base(bit ? kx[r] : 1): limb0 row-muxed, limbs 1..3 = 0.
            let mut bscalar = AB::Expr::ZERO;
            for r in 0..self.shape.log_max {
                bscalar = bscalar
                    + sf(r) * (AB::Expr::ONE + cv(self.layout.idxb + r) * (cn(self.consts.kx[r]) - AB::Expr::ONE));
            }
            builder.assert_zero(msel_x.clone() * (cv(self.layout.mul_off + 4) - bscalar));
            for k in 1..4 {
                builder.assert_zero(msel_x.clone() * cv(self.layout.mul_off + 4 + k));
            }
            // mul_a at chain row 0 = ext_base(GEN).
            builder.assert_zero(msel_x.clone() * sf(0) * (cv(self.layout.mul_off) - cn(self.consts.gen)));
            for k in 1..4 {
                builder.assert_zero(msel_x.clone() * sf(0) * cv(self.layout.mul_off + k));
            }
            // Chain rows 0..20: next row's mul_a == this row's mul_c.
            let chain = (0..self.shape.log_max - 1).map(&sf).fold(AB::Expr::ZERO, |a, e| a + e);
            let cap = msel_x.clone() * sf(self.shape.log_max - 1);
            let mut t = builder.when_transition();
            for k in 0..4 {
                t.assert_zero(
                    msel_x.clone() * chain.clone() * (nv(self.layout.mul_off + k) - cv(self.layout.mul_off + 8 + k)),
                );
            }
            // self.layout.xreg captures the chain output at row 21, carries elsewhere.
            for k in 0..4 {
                t.assert_zero(cap.clone() * (nv(self.layout.xreg + k) - cv(self.layout.mul_off + 8 + k)));
                t.assert_zero((AB::Expr::ONE - cap.clone()) * (nv(self.layout.xreg + k) - cv(self.layout.xreg + k)));
            }
        }

        // =====================================================================
        // M_FIN x_fin-chain (inc-4): self.layout.xfin (final-poly evaluation point) =
        // ∏_{r<8} (kx[r] if idx-bit (14+r) else 1), an 8-row mul-bank chain
        // (rows 0..7, a starts at ONE). Same shape as M_X1. Native.
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let msel_f = cv(self.layout.msel + self.shape.m_fin() as usize);
            // x_fin chain over the final-poly domain index bits: `fin_bits`
            // (= log_max - cum[n]) rows starting at bit `fin_lo` (= cum[n]).
            // Narrow 8 rows from bit 14; wide 6 rows from bit 12.
            let fin_lo = *self.shape.cum().last().unwrap();
            let fin_bits = self.shape.log_max - fin_lo;
            let mut bscalar = AB::Expr::ZERO;
            for r in 0..fin_bits {
                bscalar = bscalar
                    + sf(r) * (AB::Expr::ONE + cv(self.layout.idxb + fin_lo + r) * (cn(self.consts.kx[r]) - AB::Expr::ONE));
            }
            builder.assert_zero(msel_f.clone() * (cv(self.layout.mul_off + 4) - bscalar));
            for k in 1..4 {
                builder.assert_zero(msel_f.clone() * cv(self.layout.mul_off + 4 + k));
            }
            // mul_a at chain row 0 = ext_base(ONE).
            builder.assert_zero(msel_f.clone() * sf(0) * (cv(self.layout.mul_off) - AB::Expr::ONE));
            for k in 1..4 {
                builder.assert_zero(msel_f.clone() * sf(0) * cv(self.layout.mul_off + k));
            }
            let chain = (0..fin_bits - 1).map(&sf).fold(AB::Expr::ZERO, |a, e| a + e);
            let cap = msel_f.clone() * sf(fin_bits - 1);
            let mut t = builder.when_transition();
            for k in 0..4 {
                t.assert_zero(
                    msel_f.clone() * chain.clone() * (nv(self.layout.mul_off + k) - cv(self.layout.mul_off + 8 + k)),
                );
            }
            for k in 0..4 {
                t.assert_zero(cap.clone() * (nv(self.layout.xfin + k) - cv(self.layout.mul_off + 8 + k)));
                t.assert_zero((AB::Expr::ONE - cap.clone()) * (nv(self.layout.xfin + k) - cv(self.layout.xfin + k)));
            }
        }

        // =====================================================================
        // M_INV (inc-4): witnessed inverses self.layout.invz = 1/(zeta - x) [r=0] and
        // self.layout.invzn = 1/(zeta_next - x) [r=1]. Add bank forms (operand - x) as a-c;
        // mul bank pins the inverse via mul_c == 1. self.layout.invz is fully sound (zeta =
        // self.layout.chal bound, x = self.layout.xreg bound); self.layout.invzn's soundness pends the ZN/trailer
        // binding (self.layout.znreg is still free witness). Native arithmetic.
        // =====================================================================
        {
            let msel_i = cv(self.layout.msel + M_INV as usize);
            let one_k = |k: usize| {
                if k == 0 {
                    AB::Expr::ONE
                } else {
                    AB::Expr::ZERO
                }
            };
            // Same shape for both rows; the operand register differs.
            let inv_row = |b: &mut AB, sel: AB::Expr, operand: usize| {
                for k in 0..4 {
                    b.assert_zero(sel.clone() * (cv(self.layout.add_off + 8 + k) - cv(operand + k)));
                    b.assert_zero(sel.clone() * (cv(self.layout.add_off + 4 + k) - cv(self.layout.xreg + k)));
                    b.assert_zero(sel.clone() * (cv(self.layout.mul_off + k) - cv(self.layout.add_off + k)));
                    b.assert_zero(sel.clone() * (cv(self.layout.mul_off + 8 + k) - one_k(k)));
                }
            };
            inv_row(builder, msel_i.clone() * sf(0), self.layout.chal + 4 * G_ZETA);
            inv_row(builder, msel_i.clone() * sf(1), self.layout.znreg);
            // Capture the inverse witnesses (mul_b) into self.layout.invz / self.layout.invzn.
            let cap_z = msel_i.clone() * sf(0);
            let cap_zn = msel_i * sf(1);
            let mut t = builder.when_transition();
            for k in 0..4 {
                t.assert_zero(cap_z.clone() * (nv(self.layout.invz + k) - cv(self.layout.mul_off + 4 + k)));
                t.assert_zero((AB::Expr::ONE - cap_z.clone()) * (nv(self.layout.invz + k) - cv(self.layout.invz + k)));
                t.assert_zero(cap_zn.clone() * (nv(self.layout.invzn + k) - cv(self.layout.mul_off + 4 + k)));
                t.assert_zero((AB::Expr::ONE - cap_zn.clone()) * (nv(self.layout.invzn + k) - cv(self.layout.invzn + k)));
            }
        }

        // =====================================================================
        // ZN / self.layout.fa2 global relations (inc-4): rather than locate the trailer
        // perm where the witness computes them, pin them directly on every
        // query row (phq) where they are consumed (M_INV, M_RO): ZN =
        // zeta·g_trace (base scalar mult, deg 1) and self.layout.fa2 = fri_alpha² (ext
        // square, deg 2). Both challenges are bound (Stage D/F), so this also
        // completes self.layout.invzn's soundness (M_INV r=1 now uses a pinned ZN).
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            for k in 0..4 {
                builder.assert_zero(
                    phq.clone() * (cv(self.layout.znreg + k) - cn(self.consts.g_trace) * cv(self.layout.chal + 4 * G_ZETA + k)),
                );
                builder.assert_zero(
                    phq.clone()
                        * (cv(self.layout.fa2 + k) - extmul(self.layout.chal + 4 * G_FRIALPHA, self.layout.chal + 4 * G_FRIALPHA, k)),
                );
            }
        }

        // =====================================================================
        // M_S s-chains + self.layout.inv2s (inc-4): per fold round rf, s = ∏_{r<lf}
        // (sk[rf][r] if idx-bit (self.shape.cum()[rf+1]+r) else 1) via a mul-bank chain
        // (rows 0..lf-1, a starts at ONE); then row lf pins self.layout.inv2s = 1/(2s) via
        // mul(2s, inv2s) == 1, where mul_a(lf) = 2·mul_c(lf-1). lf per round =
        // [18,14,10,8]. Native. The mul_b mux hits deg 4 (fold-arith budget).
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let n = self.shape.n_fri_rounds();
            let lfs = self.shape.lf();
            let capture: Vec<(AB::Expr, usize)> = (0..n)
                .map(|rf| (cv(self.layout.msel + self.shape.m_s(rf) as usize) * sf(lfs[rf]), lfs[rf]))
                .collect();
            for rf in 0..n {
                let lf = lfs[rf];
                let msel = cv(self.layout.msel + self.shape.m_s(rf) as usize);
                let not_lf = AB::Expr::ONE - sf(lf);
                // Materialized chain gate SNL_rf = msel * (1 - sf(lf)) keeps the
                // b-mux binding below deg <= 3 (target is deg 2).
                builder.assert_eq(cv(self.layout.snl + rf), msel.clone() * not_lf.clone());
                let snl = cv(self.layout.snl + rf);
                // mul_b limb0 = 1 + idx-bit·(sk-1) on chain rows (0 on row lf).
                let mut target = AB::Expr::ZERO;
                for r in 0..lf {
                    target = target
                        + sf(r)
                            * (AB::Expr::ONE
                                + cv(self.layout.idxb + self.shape.cum()[rf + 1] + r) * (cn(self.consts.sk[rf][r]) - AB::Expr::ONE));
                }
                builder.assert_zero(snl.clone() * (cv(self.layout.mul_off + 4) - target));
                for k in 1..4 {
                    builder.assert_zero(snl.clone() * cv(self.layout.mul_off + 4 + k));
                }
                // mul_a at chain row 0 = ONE.
                builder.assert_zero(msel.clone() * sf(0) * (cv(self.layout.mul_off) - AB::Expr::ONE));
                for k in 1..4 {
                    builder.assert_zero(msel.clone() * sf(0) * cv(self.layout.mul_off + k));
                }
                // mul_c == ONE at row lf (2s · inv2s == 1).
                builder.assert_zero(msel.clone() * sf(lf) * (cv(self.layout.mul_off + 8) - AB::Expr::ONE));
                for k in 1..4 {
                    builder.assert_zero(msel.clone() * sf(lf) * cv(self.layout.mul_off + 8 + k));
                }
            }
            let mut t = builder.when_transition();
            for rf in 0..n {
                let lf = lfs[rf];
                let msel = cv(self.layout.msel + self.shape.m_s(rf) as usize);
                let chain = (0..lf.saturating_sub(1)).map(&sf).fold(AB::Expr::ZERO, |a, e| a + e);
                for k in 0..4 {
                    // Plain chain rows 0..lf-2: next mul_a == this mul_c.
                    t.assert_zero(msel.clone() * chain.clone() * (nv(self.layout.mul_off + k) - cv(self.layout.mul_off + 8 + k)));
                    // Row lf-1 -> lf: mul_a(lf) == 2 · mul_c(lf-1).
                    t.assert_zero(
                        msel.clone()
                            * sf(lf - 1)
                            * (nv(self.layout.mul_off + k) - cv(self.layout.mul_off + 8 + k) * AB::Expr::from(AB::F::TWO)),
                    );
                }
            }
            // self.layout.inv2s capture: mul_b at each round's row lf; carry otherwise.
            let cap_any = capture.iter().fold(AB::Expr::ZERO, |a, (e, _)| a + e.clone());
            for k in 0..4 {
                for (sel, _) in &capture {
                    t.assert_zero(sel.clone() * (nv(self.layout.inv2s + k) - cv(self.layout.mul_off + 4 + k)));
                }
                t.assert_zero((AB::Expr::ONE - cap_any.clone()) * (nv(self.layout.inv2s + k) - cv(self.layout.inv2s + k)));
            }
        }

        // =====================================================================
        // M_B self.layout.breg ladder (inc-4): per fold round rf, breg[0] = beta·inv2s
        // (r=0), then breg[l] = 2·breg[l-1]² (r=1..la-1). la = self.shape.log_arities =
        // [4,4,4,2]. beta = self.layout.chal[G_BETA0+rf] and self.layout.inv2s are both bound, so the
        // ladder is fully pinned. Native. mul_a/mul_b are the operands; the
        // product mul_c is captured into self.layout.breg (with the ×2 for l>0).
        // =====================================================================
        {
            let n = self.shape.n_fri_rounds();
            // Same-row operand bindings.
            for rf in 0..n {
                let la = self.shape.log_arities[rf];
                let msel = cv(self.layout.msel + self.shape.m_b(rf) as usize);
                for k in 0..4 {
                    // r=0: mul_a = beta_rf, mul_b = self.layout.inv2s.
                    builder.assert_zero(
                        msel.clone() * sf(0) * (cv(self.layout.mul_off + k) - cv(self.layout.chal + 4 * (G_BETA0 + rf) + k)),
                    );
                    builder.assert_zero(msel.clone() * sf(0) * (cv(self.layout.mul_off + 4 + k) - cv(self.layout.inv2s + k)));
                    // r=1..la-1: mul_a = mul_b = breg[r-1].
                    for r in 1..la {
                        builder.assert_zero(
                            msel.clone() * sf(r) * (cv(self.layout.mul_off + k) - cv(self.layout.breg + 4 * (r - 1) + k)),
                        );
                        builder.assert_zero(
                            msel.clone() * sf(r) * (cv(self.layout.mul_off + 4 + k) - cv(self.layout.breg + 4 * (r - 1) + k)),
                        );
                    }
                }
            }
            // Captures: breg[0] = mul_c at r=0; breg[l>0] = 2·mul_c at r=l.
            let two = AB::Expr::from(AB::F::TWO);
            let mut t = builder.when_transition();
            for l in 0..4 {
                // Rounds that actually produce level l (l < la_rf).
                let cap = (0..n)
                    .filter(|&rf| l < self.shape.log_arities[rf])
                    .map(|rf| cv(self.layout.msel + self.shape.m_b(rf) as usize) * sf(l))
                    .fold(AB::Expr::ZERO, |a, e| a + e);
                for k in 0..4 {
                    let want = if l == 0 {
                        cv(self.layout.mul_off + 8 + k)
                    } else {
                        two.clone() * cv(self.layout.mul_off + 8 + k)
                    };
                    t.assert_zero(
                        cap.clone() * (nv(self.layout.breg + 4 * l + k) - want.clone())
                            + (AB::Expr::ONE - cap.clone()) * (nv(self.layout.breg + 4 * l + k) - cv(self.layout.breg + 4 * l + k)),
                    );
                }
            }
        }

        // =====================================================================
        // Fold arithmetic — round-0 leaf fold + self.layout.hit + fold-leaf consistency
        // (inc-4). v = the fold leaf value ext(self.layout.asm0,self.layout.asm1,self.layout.w0c,self.layout.w1c). self.layout.pbuf holds
        // the even leaf; on the odd leaf self.layout.scr[i] = (pbuf+v)·half +
        // breg[0]·kf[rf][0][i]·(pbuf-v). self.layout.hit = [self.layout.vc == self.layout.gpb] (one-hot dot with
        // the self.layout.gpb bit pattern, materialized deg 5 so the consistency stays
        // deg 3): at the index-in-group leaf, v == self.layout.runev — the FRI fold
        // consistency tying self.layout.runev to the sponge-bound openings.
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let vexpr = [cv(self.layout.asm0), cv(self.layout.asm1), cv(self.layout.w0c), cv(self.layout.w1c)];
            // self.layout.gpb one-hot decode split into 2-bit pair products so self.layout.hit stays
            // deg 3: self.layout.glo[j] = pair(GPB0,GPB1); self.layout.ghi[j] = pair(GPB2,GPB3).
            let gbit = |col: usize, on: bool| -> AB::Expr {
                if on {
                    cv(col)
                } else {
                    AB::Expr::ONE - cv(col)
                }
            };
            for j in 0..4 {
                builder.assert_eq(cv(self.layout.glo + j), gbit(self.layout.gpb, j & 1 == 1) * gbit(self.layout.gpb + 1, j & 2 == 2));
                builder
                    .assert_eq(cv(self.layout.ghi + j), gbit(self.layout.gpb + 2, j & 1 == 1) * gbit(self.layout.gpb + 3, j & 2 == 2));
            }
            // self.layout.hit = sum_s self.layout.vc[s] · self.layout.glo[s&3] · self.layout.ghi[(s>>2)&3]  (deg 3).
            let mut hit = AB::Expr::ZERO;
            for s in 0..16usize {
                hit = hit + cv(self.layout.vc + s) * cv(self.layout.glo + (s & 3)) * cv(self.layout.ghi + ((s >> 2) & 3));
            }
            builder.assert_eq(cv(self.layout.hit), hit);
            // Fold-leaf consistency: at the index-in-group leaf, v == self.layout.runev.
            for k in 0..4 {
                builder.assert_zero(cv(self.layout.consf) * cv(self.layout.hit) * (vexpr[k].clone() - cv(self.layout.runev + k)));
            }
            // ext-mul of a column-vector (a_off) and an expr-vector (be).
            let extmul_ce = |a_off: usize, be: &[AB::Expr; 4], k: usize| -> AB::Expr {
                let w = c(EXT_W);
                let mut acc = AB::Expr::ZERO;
                for i in 0..4 {
                    for j in 0..4 {
                        if i + j == k {
                            acc = acc + cv(a_off + i) * be[j].clone();
                        } else if i + j == k + 4 {
                            acc = acc + w.clone() * cv(a_off + i) * be[j].clone();
                        }
                    }
                }
                acc
            };
            let pmv = [
                cv(self.layout.pbuf) - vexpr[0].clone(),
                cv(self.layout.pbuf + 1) - vexpr[1].clone(),
                cv(self.layout.pbuf + 2) - vexpr[2].clone(),
                cv(self.layout.pbuf + 3) - vexpr[3].clone(),
            ];
            let half = cn(self.consts.half);
            // self.layout.bpm = extmul(self.layout.breg, self.layout.pbuf - v): the round-0 fold's self.layout.breg·(pbuf-v) ext
            // product, so `computed` below is deg 1 (kept out of the gate).
            for k in 0..4 {
                builder.assert_eq(cv(self.layout.bpm + k), extmul_ce(self.layout.breg, &pmv, k));
            }
            // GF_rf = self.layout.consf * self.layout.drnd[2+rf]: round-0 gate prefix (gate = self.layout.gf * self.layout.vc).
            for rf in 0..self.shape.n_fri_rounds() {
                builder.assert_eq(cv(self.layout.gf + rf), cv(self.layout.consf) * cv(self.layout.drnd + 2 + rf));
            }
            let mut t = builder.when_transition();
            // self.layout.pbuf capture on even fold-value rows (self.layout.consf·self.layout.vce); carry otherwise.
            for k in 0..4 {
                let cap = cv(self.layout.consf) * cv(self.layout.vce);
                t.assert_zero(
                    cap.clone() * (nv(self.layout.pbuf + k) - vexpr[k].clone())
                        + (AB::Expr::ONE - cap) * (nv(self.layout.pbuf + k) - cv(self.layout.pbuf + k)),
                );
            }
            // Round-0 self.layout.scr fold on odd fold-value rows (per round rf, pair i).
            // gate = self.layout.gf[rf]*self.layout.vc[2i+1] (deg 2); computed deg 1 via self.layout.bpm -> deg 3.
            for rf in 0..self.shape.n_fri_rounds() {
                let la = self.shape.log_arities[rf];
                for i in 0..(1usize << (la - 1)) {
                    let gate = cv(self.layout.gf + rf) * cv(self.layout.vc + 2 * i + 1);
                    let kf = cn(self.consts.kf[rf][0][i]);
                    for k in 0..4 {
                        let computed =
                            half.clone() * (cv(self.layout.pbuf + k) + vexpr[k].clone()) + kf.clone() * cv(self.layout.bpm + k);
                        t.assert_zero(gate.clone() * (nv(self.layout.scr + 4 * i + k) - computed));
                    }
                }
            }
        }

        // =====================================================================
        // M_FHI higher-round folds + self.layout.runev threading (inc-4). Per round rf,
        // fold levels 1..: outv = (scr[2i]+scr[2i+1])·half +
        // breg[l]·kf[rf][l][i]·(scr[2i]−scr[2i+1]), written to self.layout.scr[i] (or self.layout.runev
        // on the last pair). self.layout.runev is set at each M_FHI last row and at M_RO
        // r=8 (below), and carries elsewhere — so a flip anywhere breaks the
        // carry or a capture (closes bad_fold together with the leaf
        // consistency and M_RO).
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let half = cn(self.consts.half);
            let extmul_cc = |a_off: usize, lo: usize, hi: usize, k: usize| -> AB::Expr {
                let w = c(EXT_W);
                let mut acc = AB::Expr::ZERO;
                for i in 0..4 {
                    for j in 0..4 {
                        let d = cv(lo + j) - cv(hi + j);
                        if i + j == k {
                            acc = acc + cv(a_off + i) * d;
                        } else if i + j == k + 4 {
                            acc = acc + w.clone() * cv(a_off + i) * d;
                        }
                    }
                }
                acc
            };
            let n = self.shape.n_fri_rounds();
            // The (level, pair) fold schedule of an arity-2^la round: level l has
            // 2^(la-1-l) pairs, for l = 1..la (level 0 is the round-0 leaf fold).
            // la=4 -> [(1,0..3),(2,0..1),(3,0)] (=pairs3); la=2 -> [(1,0)].
            let fold_pairs = |la: usize| -> Vec<(usize, usize)> {
                let mut v = vec![];
                for l in 1..la {
                    for i in 0..(1usize << (la - 1 - l)) {
                        v.push((l, i));
                    }
                }
                v
            };
            // Materialize the per-(round,row) M_FHI fold gate (global, deg 2).
            for rf in 0..n {
                let npairs = (1usize << (self.shape.log_arities[rf] - 1)) - 1;
                for r in 0..npairs {
                    builder.assert_eq(
                        cv(self.layout.fhg + fhg_index(&self.shape.log_arities, rf, r)),
                        cv(self.layout.msel + self.shape.m_fhi(rf) as usize) * sf(r),
                    );
                }
            }
            let mut update = AB::Expr::ZERO; // rows where self.layout.runev is (re)written
            let mut t = builder.when_transition();
            for rf in 0..n {
                let msel = cv(self.layout.msel + self.shape.m_fhi(rf) as usize);
                let pairs = fold_pairs(self.shape.log_arities[rf]);
                let last = pairs.len() - 1;
                for (r, &(l, i)) in pairs.iter().enumerate() {
                    // self.layout.fhg = msel_rf * sf(r) (materialized above, deg 1) so
                    // gate*computed (computed deg 2) stays deg 3.
                    let gate = cv(self.layout.fhg + fhg_index(&self.shape.log_arities, rf, r));
                    let _ = &msel;
                    let lo = self.layout.scr + 4 * (2 * i);
                    let hi = self.layout.scr + 4 * (2 * i + 1);
                    let kf = cn(self.consts.kf[rf][l][i]);
                    let target = if r == last { self.layout.runev } else { self.layout.scr + 4 * i };
                    for k in 0..4 {
                        let computed = half.clone() * (cv(lo + k) + cv(hi + k))
                            + kf.clone() * extmul_cc(self.layout.breg + 4 * l, lo, hi, k);
                        t.assert_zero(gate.clone() * (nv(target + k) - computed));
                    }
                    if r == last {
                        update = update + gate;
                    }
                }
            }
            // self.layout.runev also updates at M_RO r=8 (its capture is in the M_RO block).
            update = update + cv(self.layout.msel + M_RO as usize) * sf(8);
            // self.layout.runev carries on every non-update transition.
            for k in 0..4 {
                t.assert_zero((AB::Expr::ONE - update.clone()) * (nv(self.layout.runev + k) - cv(self.layout.runev + k)));
            }
        }

        // =====================================================================
        // self.layout.pzacc / self.layout.preg accumulation (endpoint pin, START foundation). The
        // reduced-opening numerator accumulates along two mutually-exclusive
        // paths (dup vs query phase), both binding pzacc/preg to the opened
        // values so M_RO's `ro` is value-pinned:
        //   - dup zeta-value rows (self.layout.consz = self.layout.czd·POS1): pzacc += preg·v,
        //     preg *= fri_alpha, with v = ext(self.layout.asm0,self.layout.asm1,self.layout.w0c,self.layout.w1c) (deg 3).
        //   - query PX rows (self.layout.cx0, optionally self.layout.cx1): pzacc += preg·self.layout.w0c (word 0)
        //     and, when self.layout.cx1 (implies self.layout.cx0), += (preg·fri_alpha)·self.layout.w1c (word 1);
        //     preg *= fri_alpha (one word) or fri_alpha² (two words). self.layout.prega =
        //     preg·fri_alpha is materialized so the word-1 term stays deg 3.
        // self.layout.fa2 = fri_alpha² is already bound (Stage D/F). self.layout.cx1 ⊆ self.layout.cx0, so
        // self.layout.cx0·(1-self.layout.cx1) = self.layout.cx0 - self.layout.cx1.
        // =====================================================================
        {
            // ext-mul of the contiguous self.layout.preg vector with an explicit column list.
            let extmul_cols = |a_off: usize, bcols: &[usize; 4], k: usize| -> AB::Expr {
                let w = c(EXT_W);
                let mut acc = AB::Expr::ZERO;
                for i in 0..4 {
                    for j in 0..4 {
                        if i + j == k {
                            acc = acc + cv(a_off + i) * cv(bcols[j]);
                        } else if i + j == k + 4 {
                            acc = acc + w.clone() * cv(a_off + i) * cv(bcols[j]);
                        }
                    }
                }
                acc
            };
            let vcols = [self.layout.asm0, self.layout.asm1, self.layout.w0c, self.layout.w1c];
            let fa_off = self.layout.chal + 4 * G_FRIALPHA;
            // self.layout.prega = preg·fri_alpha (materialized; filled in fill_derived).
            for k in 0..4 {
                builder.assert_eq(cv(self.layout.prega + k), extmul(self.layout.preg, fa_off, k));
            }
            let consz = cv(self.layout.consz);
            let cx0 = cv(self.layout.cx0);
            let cx1 = cv(self.layout.cx1);
            // preg update gate: *fri_alpha when (self.layout.consz or self.layout.cx0&!self.layout.cx1); *fri_alpha²
            // when self.layout.cx1; carry otherwise.
            let gate_fa = consz.clone() + cx0.clone() - cx1.clone();
            // Leaf-start reset (same signal as the self.layout.vc counter): at sf(23)·nv(self.layout.lfs)
            // pzacc->0, preg->ONE, starting the next query's PX accumulation.
            // The reset only fires on a perm's last row, where all accumulation
            // gates are 0, so it composes as an additive deg-3 correction.
            let mut t = builder.when_transition();
            let reset = sf(23) * nv(self.layout.lfs);
            for k in 0..4 {
                // pzacc += self.layout.consz·(preg·v) + self.layout.cx0·preg·self.layout.w0c + self.layout.cx1·(preg·fa)·self.layout.w1c.
                let inc = consz.clone() * extmul_cols(self.layout.preg, &vcols, k)
                    + cx0.clone() * cv(self.layout.preg + k) * cv(self.layout.w0c)
                    + cx1.clone() * cv(self.layout.prega + k) * cv(self.layout.w1c);
                t.assert_zero(nv(self.layout.pzacc + k) - cv(self.layout.pzacc + k) - inc + reset.clone() * cv(self.layout.pzacc + k));
                // preg *= fri_alpha (gate_fa) or fri_alpha² (self.layout.cx1); carry else.
                let preg_reset = if k == 0 { AB::Expr::ONE } else { AB::Expr::ZERO };
                t.assert_zero(
                    nv(self.layout.preg + k)
                        - cv(self.layout.preg + k)
                        - gate_fa.clone() * (extmul(self.layout.preg, fa_off, k) - cv(self.layout.preg + k))
                        - cx1.clone() * (extmul(self.layout.preg, self.layout.fa2, k) - cv(self.layout.preg + k))
                        + reset.clone() * (cv(self.layout.preg + k) - preg_reset),
                );
            }
        }

        // =====================================================================
        // Reduced-opening captures (endpoint pin, START). At fixed transcript
        // positions the running pzacc/preg are snapshotted into the A/P/PX0
        // registers that M_RO consumes; carry otherwise. Capture rows map to
        // existing comparators (dup block_A0 = self.layout.cmpa, block_A1 = self.layout.cmpb, last
        // block N-1 = self.layout.blklast; narrow 72/145/147; trace-leaf end =
        // self.layout.rsel[R_ABS_C5]). self.layout.cpa/self.layout.cpb/self.layout.cpl = self.layout.phd·comparator keep
        // the gates deg 2. The captured value is the pre-consume pzacc = cv().
        // =====================================================================
        {
            builder.assert_eq(cv(self.layout.cpa), cv(self.layout.phd) * cv(self.layout.cmpa));
            builder.assert_eq(cv(self.layout.cpb), cv(self.layout.phd) * cv(self.layout.cmpb));
            builder.assert_eq(cv(self.layout.cpl), cv(self.layout.phd) * cv(self.layout.blklast));
            // Capture rows: the row-in-perm of each group boundary (shape-
            // derived). Narrow reproduces sf(14)/sf(7)/sf(5).
            let dcap = self.shape.dup_captures();
            let ga0 = cv(self.layout.cpa) * sf(dcap[0].1);
            let ga1 = cv(self.layout.cpb) * sf(dcap[1].1);
            let ga2 = cv(self.layout.cpl) * sf(dcap[2].1);
            // PX0 (trace-leaf end) capture: pzacc snapshotted the row AFTER the
            // trace leaf's last fresh word is consumed. The C5 block consumes
            // 2 words/row, so its last consume is row ceil(f/2)-1 and the
            // capture sits at ceil(f/2) = (f+1)/2. Narrow f=5 → row 3 (as
            // before); wide f=22 → row 11.
            let gpx = cv(self.layout.rsel + R_ABS_C5 as usize) * sf((self.shape.trace_last_fresh() + 1) / 2);
            let mut t = builder.when_transition();
            for k in 0..4 {
                t.assert_zero(nv(self.layout.a0r + k) - cv(self.layout.a0r + k) - ga0.clone() * (cv(self.layout.pzacc + k) - cv(self.layout.a0r + k)));
                t.assert_zero(nv(self.layout.p0r + k) - cv(self.layout.p0r + k) - ga0.clone() * (cv(self.layout.preg + k) - cv(self.layout.p0r + k)));
                t.assert_zero(nv(self.layout.a1r + k) - cv(self.layout.a1r + k) - ga1.clone() * (cv(self.layout.pzacc + k) - cv(self.layout.a1r + k)));
                t.assert_zero(nv(self.layout.p1r + k) - cv(self.layout.p1r + k) - ga1.clone() * (cv(self.layout.preg + k) - cv(self.layout.p1r + k)));
                t.assert_zero(nv(self.layout.a2r + k) - cv(self.layout.a2r + k) - ga2.clone() * (cv(self.layout.pzacc + k) - cv(self.layout.a2r + k)));
                t.assert_zero(
                    nv(self.layout.px0r + k) - cv(self.layout.px0r + k) - gpx.clone() * (cv(self.layout.pzacc + k) - cv(self.layout.px0r + k)),
                );
            }
        }

        // =====================================================================
        // Final-poly capture + M_HORN Horner (endpoint pin, END). self.layout.fpreg holds
        // the 16 final-poly coefficients, captured from the self.layout.cz7 value rows
        // (transcript-bound), indexed by the self.layout.fpi one-hot counter. M_HORN then
        // evaluates the poly at self.layout.xfin by Horner and pins the result to self.layout.runev —
        // tying the *end* of the fold chain to the transcript's final poly.
        // =====================================================================
        {
            let cn = |x: Val| AB::Expr::from(AB::F::from_u32(x.as_canonical_u32()));
            let _ = cn;
            // self.layout.consz7 = self.layout.cz7 · POS1.
            builder.assert_eq(cv(self.layout.consz7), cv(self.layout.cz7) * cv(self.layout.pos + 1));
            // self.layout.fpi one-hot: bool, sum==1, first-row slot 0, +1 rotate on self.layout.consz7.
            for i in 0..16 {
                builder.assert_bool(cv(self.layout.fpi + i));
            }
            builder.assert_eq(
                (0..16).map(|i| cv(self.layout.fpi + i)).fold(AB::Expr::ZERO, |a, e| a + e),
                AB::Expr::ONE,
            );
            builder.assert_zero(cv(self.layout.csel) * (cv(self.layout.fpi) - AB::Expr::ONE));
            for i in 1..16 {
                builder.assert_zero(cv(self.layout.csel) * cv(self.layout.fpi + i));
            }
            let vfp = [cv(self.layout.asm0), cv(self.layout.asm1), cv(self.layout.w0c), cv(self.layout.w1c)];
            {
                let mut t = builder.when_transition();
                for i in 0..16 {
                    t.assert_eq(
                        nv(self.layout.fpi + i),
                        cv(self.layout.fpi + i) + cv(self.layout.consz7) * (cv(self.layout.fpi + (i + 15) % 16) - cv(self.layout.fpi + i)),
                    );
                }
                // self.layout.fpreg[s] capture on the self.layout.consz7 row with self.layout.fpi==s; carry else.
                for s in 0..16 {
                    let gate = cv(self.layout.consz7) * cv(self.layout.fpi + s);
                    for k in 0..4 {
                        t.assert_zero(
                            nv(self.layout.fpreg + 4 * s + k)
                                - cv(self.layout.fpreg + 4 * s + k)
                                - gate.clone() * (vfp[k].clone() - cv(self.layout.fpreg + 4 * s + k)),
                        );
                    }
                }
            }
            // M_HORN Horner: rows 0..14. mul_b = self.layout.xfin; mul_a = self.layout.fpreg[15] (r0) or
            // the previous row's add output (threaded); add_a = mul_c; add_b =
            // self.layout.fpreg[14-r]; final add output (r14) == self.layout.runev.
            let mh = cv(self.layout.msel + self.shape.m_horn() as usize);
            let rge = |a: usize, b: usize| (a..=b).map(&sf).fold(AB::Expr::ZERO, |x, e| x + e);
            let rows_all = rge(0, 14);
            for k in 0..4 {
                // mul_b = self.layout.xfin on all Horner rows.
                builder.assert_zero(mh.clone() * rows_all.clone() * (cv(self.layout.mul_off + 4 + k) - cv(self.layout.xfin + k)));
                // mul_a at r0 = self.layout.fpreg[15].
                builder.assert_zero(mh.clone() * sf(0) * (cv(self.layout.mul_off + k) - cv(self.layout.fpreg + 60 + k)));
                // add_a = mul_c (same row).
                builder
                    .assert_zero(mh.clone() * rows_all.clone() * (cv(self.layout.add_off + k) - cv(self.layout.mul_off + 8 + k)));
                // add_b = self.layout.fpreg[14-r] (per-row mux, deg 3).
                for r in 0..15 {
                    builder.assert_zero(
                        mh.clone() * sf(r) * (cv(self.layout.add_off + 4 + k) - cv(self.layout.fpreg + 4 * (14 - r) + k)),
                    );
                }
                // final Horner output == self.layout.runev.
                builder.assert_zero(mh.clone() * sf(14) * (cv(self.layout.add_off + 8 + k) - cv(self.layout.runev + k)));
            }
            {
                // Thread the accumulator: next row's mul_a == this row's add_c.
                let mut t = builder.when_transition();
                for k in 0..4 {
                    t.assert_zero(
                        mh.clone() * rge(0, 13) * (nv(self.layout.mul_off + k) - cv(self.layout.add_off + 8 + k)),
                    );
                }
            }
        }

        // =====================================================================
        // M_RO reduced-opening assembly (endpoint pin, START completion). The
        // 9-row bank schedule assembles `ro` (the round -1 self.layout.runev) from the
        // pinned reduced-opening registers, tying the START of the fold chain
        // to the accumulated openings. NOTE the witness uses `bank_add_c(C,B)`
        // (subtractive: writes add_c=C, add_b=B, add_a=C-B, result = add_a) for
        // rows 2..6 and standard `bank_add(A,B)` for rows 7,8. Bank arithmetic
        // (mul_c=a·b, add_c=a+b) is already constrained; here we pin each row's
        // known operands and thread the intermediates / self.layout.scr scratch. Dataflow:
        //   r0 mul(self.layout.p0r,self.layout.px0r)->SCR0      r1 mul(self.layout.p1r,self.layout.pzacc)->SCR1
        //   r2 addc(self.layout.a0r,self.layout.px0r)=g0; mul(g0,self.layout.invz)->SCR2      [g0=add_a]
        //   r3 addc(self.layout.a1r,self.layout.a0r)=m           [m=add_a -> add_c(r4)]
        //   r4 addc(m,SCR0)=d1; mul(d1,self.layout.invzn)->SCR3       [d1=add_a]
        //   r5 addc(self.layout.a2r,self.layout.a1r)=m           [m=add_a -> add_c(r6)]
        //   r6 addc(m,SCR1)=d2; mul(d2,self.layout.invz)->SCR4        [d2=add_a]
        //   r7 add(SCR2,SCR3)=m          [m=add_c -> add_a(r8)]
        //   r8 add(m,SCR4)=ro -> self.layout.runev   [ro=add_c]
        // =====================================================================
        {
            let mr = cv(self.layout.msel + M_RO as usize);
            let mul_a = |k: usize| cv(self.layout.mul_off + k);
            let mul_b = |k: usize| cv(self.layout.mul_off + 4 + k);
            let add_a = |k: usize| cv(self.layout.add_off + k);
            let add_b = |k: usize| cv(self.layout.add_off + 4 + k);
            let add_c = |k: usize| cv(self.layout.add_off + 8 + k);
            let scr = |i: usize, k: usize| self.layout.scr + 4 * i + k;
            for k in 0..4 {
                // mul_b operands.
                builder.assert_zero(mr.clone() * sf(0) * (mul_b(k) - cv(self.layout.px0r + k)));
                builder.assert_zero(mr.clone() * sf(1) * (mul_b(k) - cv(self.layout.pzacc + k)));
                builder.assert_zero(mr.clone() * sf(2) * (mul_b(k) - cv(self.layout.invz + k)));
                builder.assert_zero(mr.clone() * sf(4) * (mul_b(k) - cv(self.layout.invzn + k)));
                builder.assert_zero(mr.clone() * sf(6) * (mul_b(k) - cv(self.layout.invz + k)));
                // mul_a: registers (r0,r1); same-row add_a intermediate (r2,4,6).
                builder.assert_zero(mr.clone() * sf(0) * (mul_a(k) - cv(self.layout.p0r + k)));
                builder.assert_zero(mr.clone() * sf(1) * (mul_a(k) - cv(self.layout.p1r + k)));
                builder.assert_zero(
                    mr.clone() * (sf(2) + sf(4) + sf(6)) * (mul_a(k) - add_a(k)),
                );
                // add_c operands for the subtractive rows (bank_add_c first arg):
                // r2=self.layout.a0r, r3=self.layout.a1r, r5=self.layout.a2r. (r4,r6 add_c come via threading below.)
                builder.assert_zero(mr.clone() * sf(2) * (add_c(k) - cv(self.layout.a0r + k)));
                builder.assert_zero(mr.clone() * sf(3) * (add_c(k) - cv(self.layout.a1r + k)));
                builder.assert_zero(mr.clone() * sf(5) * (add_c(k) - cv(self.layout.a2r + k)));
                // add_b operands.
                builder.assert_zero(mr.clone() * sf(2) * (add_b(k) - cv(self.layout.px0r + k)));
                builder.assert_zero(mr.clone() * sf(3) * (add_b(k) - cv(self.layout.a0r + k)));
                builder.assert_zero(mr.clone() * sf(4) * (add_b(k) - cv(scr(0, k))));
                builder.assert_zero(mr.clone() * sf(5) * (add_b(k) - cv(self.layout.a1r + k)));
                builder.assert_zero(mr.clone() * sf(6) * (add_b(k) - cv(scr(1, k))));
                builder.assert_zero(mr.clone() * sf(7) * (add_b(k) - cv(scr(3, k))));
                builder.assert_zero(mr.clone() * sf(8) * (add_b(k) - cv(scr(4, k))));
                // r7 is a standard bank_add(SCR2, SCR3): add_a = SCR2.
                builder.assert_zero(mr.clone() * sf(7) * (add_a(k) - cv(scr(2, k))));
            }
            // self.layout.scr scratch carry + capture the bank output on its producing row
            // (SCR0@0 SCR1@1 SCR2@2 SCR3@4 SCR4@6); intermediate threading; and
            // self.layout.runev set are transition constraints.
            let cap_rows = [0usize, 1, 2, 4, 6];
            let mut t = builder.when_transition();
            for k in 0..4 {
                for (i, &cr) in cap_rows.iter().enumerate() {
                    // Gated by mr: only the M_RO perm; folds own self.layout.scr elsewhere.
                    t.assert_zero(
                        mr.clone()
                            * (nv(scr(i, k))
                                - cv(scr(i, k))
                                - sf(cr) * (cv(self.layout.mul_off + 8 + k) - cv(scr(i, k)))),
                    );
                }
                // Subtractive-row result add_a threads into next row's add_c
                // (r3->r4, r5->r6).
                t.assert_zero(
                    mr.clone() * (sf(3) + sf(5)) * (nv(self.layout.add_off + 8 + k) - cv(self.layout.add_off + k)),
                );
                // r7 result add_c threads into r8's add_a.
                t.assert_zero(mr.clone() * sf(7) * (nv(self.layout.add_off + k) - cv(self.layout.add_off + 8 + k)));
                // ro = add_c(r8) -> self.layout.runev.
                t.assert_zero(mr.clone() * sf(8) * (nv(self.layout.runev + k) - cv(self.layout.add_off + 8 + k)));
            }
        }

        // The last-row phase anchor is the self.layout.qsel check emitted above.
        let _ = (cf, pv, xorsel, consumersel);
    }
}

// ---------------------------------------------------------------------------
// Lowering: the complete witness from a Stage-1 Schedule.
// ---------------------------------------------------------------------------

/// Per-perm plan entry.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PInfo {
    /// Obs-flush block (flush = obs ordinal 0..8, block index within it).
    Obs { flush: usize, block: usize },
    /// Refill flush (single chained block) -- includes the trailer.
    Refill,
    /// Flush-2 duplicate block (hash transport).
    Dup { block: usize },
    /// Query-program perm.
    Query { q: usize, slot: usize },
}

/// Shape-selector index of an obs block (must mirror `shape_list`).
///
/// Shape-driven: `flush_blocks` is the per-obs-flush block-count vector (the
/// cached `GateConsts::flush_blocks` in `eval`, `shape.flush_blocks()` in the
/// trace builder). F0 contributes `flush_blocks[0]` distinct slots, F1 its
/// blocks, the zeta flush (index 2) collapses to 3 (block 0 / interior / last),
/// and every later obs flush contributes its block count. Narrow reproduces the
/// old hardcoded `[0,5,8..10,11+(f-3)*3+b]` layout verbatim.
fn shsel_index(flush_blocks: &[usize], flush: usize, block: usize) -> usize {
    let mut base = 0usize;
    for (f, &blk) in flush_blocks.iter().enumerate().take(flush) {
        base += if f == 2 && blk >= 3 { 3 } else { blk };
    }
    if flush == 2 && flush_blocks[2] >= 3 {
        if block == 0 {
            base
        } else if block == flush_blocks[2] - 1 {
            base + 2
        } else {
            base + 1
        }
    } else {
        base + block
    }
}

/// Everything the tests need to corrupt the witness surgically.
pub(crate) struct GateMeta {
    /// Row of the first perm of each query block.
    pub query_rows: Vec<usize>,
    /// (row, masked) of every accepted field draw, walk order.
    pub field_draws: Vec<(usize, u32)>,
    /// Rows of the trailer perm.
    pub trailer_row: usize,
    /// Lane perm count (before padding).
    pub n_perms: usize,
    /// The outer public values.
    pub opvs: Vec<Val>,
}

/// Build the outer public values: n_caps caps x cap_len digests x 16 limbs +
/// the D3 F0 digest + the inner public values (slice 1b-2: shape-driven;
/// narrow = 6x8x16 + 16 + 84).
pub(crate) fn outer_pvs(sched: &Schedule, inner_pvs: &[Val], shape: &GateShape) -> Vec<Val> {
    let mut opvs = Vec::with_capacity(shape.n_opvs());
    assert_eq!(sched.caps.len(), shape.n_caps());
    for cap in &sched.caps {
        assert_eq!(cap.len(), shape.cap_len);
        for d in cap {
            for j in 0..16 {
                opvs.push(Val::from_u32(((d[j / 4] >> (16 * (j % 4))) & 0xffff) as u32));
            }
        }
    }
    assert_eq!(opvs.len(), shape.opv_f0dig());
    // Issue #24 (D3): the F0 digest — keccak-256 of the first observation flush
    // (deg bits ‖ trace cap ‖ inner PVs). Same u16-limb encoding as the caps.
    // The circuit pins it to the last F0 block's output rate limbs, and pins
    // that block's absorbed INPUT words to these same public values — so the
    // exposed digest is a real commitment, not an unbound witness (issue #21 R2).
    for c in sched.flushes[0].digest.chunks(2) {
        opvs.push(Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32));
    }
    assert_eq!(opvs.len(), shape.opv_pvs());
    assert_eq!(inner_pvs.len(), shape.n_pvs);
    // Inner public values ride the outer interface in their transcript
    // encoding (Monty words), matching the absorbed bytes.
    let rr = monty_rr();
    opvs.extend(inner_pvs.iter().map(|v| *v * rr));
    assert_eq!(opvs.len(), shape.n_opvs());
    opvs
}

/// Assemble the lane plan: challenger blocks (native order) + trailer +
/// per-query leaf/path perms (cap-extension and collapse perms dropped),
/// with the perm inputs for the keccak generator.
pub(crate) fn lane_plan(sched: &Schedule, shape: &GateShape) -> (Vec<[u64; 25]>, Vec<PInfo>) {
    let flush_blocks = shape.flush_blocks();
    let flush_bytes = shape.flush_bytes();
    let mut inputs = vec![];
    let mut infos = vec![];

    // Challenger region. Flushes with 32-byte messages after flush 0 are
    // refills (chain-only); everything else is an obs flush whose shape
    // table must match the fixed program.
    let mut obs_ord = 0usize;
    for (f, fl) in sched.flushes.iter().enumerate() {
        let is_refill = f > 0 && fl.msg.len() == 32;
        if is_refill {
            assert_eq!(fl.n_blocks, 1);
        } else {
            assert_eq!(
                fl.n_blocks, flush_blocks[obs_ord],
                "obs flush {obs_ord} block count"
            );
            assert_eq!(fl.msg.len(), flush_bytes[obs_ord], "obs flush {obs_ord} bytes");
        }
        for b in 0..fl.n_blocks {
            let p = &sched.perms[fl.first_perm + b];
            let Role::Chal { flush, block, .. } = &p.role else {
                panic!("chal region role");
            };
            assert_eq!((*flush, *block), (f, b));
            inputs.push(p.input);
            infos.push(if is_refill {
                PInfo::Refill
            } else {
                PInfo::Obs {
                    flush: obs_ord,
                    block: b,
                }
            });
        }
        if !is_refill {
            obs_ord += 1;
        }
    }
    assert_eq!(obs_ord, shape.n_obs_flushes(), "obs flush count");
    // Trailer: pad32(last digest) so the final window is preimage-visible.
    let last_digest = sched.flushes.last().unwrap().digest;
    let mut tr = [0u8; 136];
    tr[..32].copy_from_slice(&last_digest);
    tr[32] ^= 0x01;
    tr[135] ^= 0x80;
    let mut st = [0u64; 25];
    for (l, chunk) in tr.chunks(8).enumerate() {
        st[l] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    inputs.push(st);
    infos.push(PInfo::Refill);

    // Flush-2 duplicate: replay its blocks (the honest witness re-hashes
    // the same message; only the final digest is bound).
    let f2 = &sched.flushes[2];
    for b in 0..f2.n_blocks {
        inputs.push(sched.perms[f2.first_perm + b].input);
        infos.push(PInfo::Dup { block: b });
    }

    // Query region: per query, absorbs + native path levels in walk order.
    let program = qprogram_from_shape(shape);
    let n_chal: usize = sched.flushes.iter().map(|f| f.n_blocks).sum();
    let mut ptr = n_chal;
    for q in 0..shape.nq {
        for slot in 0..shape.qslots() {
            let d = program[slot];
            let role = d & 0xf;
            // Skip the schedule's cap-extension perms (dropped in-lane).
            while let Role::Compress {
                tag: CompressTag::Path { cap_ext: true, .. },
            } = &sched.perms[ptr].role
            {
                ptr += 1;
            }
            let p = &sched.perms[ptr];
            ptr += 1;
            match role {
                1..=5 => {
                    let Role::Absorb { leaf, .. } = &p.role else {
                        panic!("q{q} slot {slot}: expected absorb, got another role");
                    };
                    let expect_round = (d >> 4) & 0x3f;
                    let got = match leaf {
                        LeafTag::Trace { q: lq } => {
                            assert_eq!(*lq, q);
                            D_T
                        }
                        LeafTag::Quotient { q: lq } => {
                            assert_eq!(*lq, q);
                            D_Q
                        }
                        LeafTag::Fold { q: lq, r } => {
                            assert_eq!(*lq, q);
                            D_F[*r]
                        }
                    };
                    assert_eq!(got, expect_round, "q{q} slot {slot} absorb round");
                }
                6..=12 => {
                    let Role::Compress {
                        tag: CompressTag::Path { q: pq, cap_ext: false, .. },
                    } = &p.role
                    else {
                        panic!("q{q} slot {slot}: expected path");
                    };
                    assert_eq!(*pq, q);
                }
                _ => unreachable!(),
            }
            inputs.push(p.input);
            infos.push(PInfo::Query { q, slot });
        }
    }
    // Trailing cap-ext perms of the last query were skipped inside the
    // loop only between slots; drop any remaining.
    while ptr < sched.perms.len() {
        match &sched.perms[ptr].role {
            Role::Compress {
                tag: CompressTag::Path { cap_ext: true, .. },
            }
            | Role::Compress {
                tag: CompressTag::Collapse { .. },
            } => ptr += 1,
            other => panic!("unexpected trailing perm role {other:?}"),
        }
    }
    (inputs, infos)
}

// ---------------------------------------------------------------------------
// Row simulator: mirrors every constraint's transition rule exactly, and
// self-checks captured values against the Stage-1 schedule.
// ---------------------------------------------------------------------------

/// The transcript's value encoding: `to_unique_u32` serializes the raw
/// Monty word, so an observed/absorbed field value v appears in-circuit as
/// the field element with canonical integer R*v mod p — i.e. v * RR where
/// RR = from_u32(ONE.to_unique_u32()). The verification pipeline is
/// R-homogeneous (all identities are linear in the opened values, with
/// challenges and domain constants entering unscaled), so the rectangle
/// operates on the scaled values throughout; only the recorder
/// cross-checks need the explicit factor.
pub(crate) fn monty_rr() -> Val {
    Val::from_u32(Val::ONE.to_unique_u32())
}
fn scale(e: Ext) -> Ext {
    e * ext_base(monty_rr())
}

fn ext_of(v: &[Val; 4]) -> Ext {
    Ext::from_basis_coefficients_fn(|i| v[i])
}
fn ext_base(v: Val) -> Ext {
    Ext::from_basis_coefficients_fn(|i| if i == 0 { v } else { Val::ZERO })
}
fn ext_limbs(e: Ext) -> [Val; 4] {
    let s: &[Val] = e.as_basis_coefficients_slice();
    [s[0], s[1], s[2], s[3]]
}
/// 16-bit limb i (0..100) of a keccak state.
fn st_limb(st: &[u64; 25], i: usize) -> u16 {
    ((st[i / 4] >> (16 * (i % 4))) & 0xffff) as u16
}

#[derive(Clone)]
struct Regs {
    // query program / scheduling
    pr_rot: usize,
    phc: bool,
    phq: bool,
    qsel: usize,
    qcnt: u32,
    // flush automaton
    fring: usize,
    blkcnt: u32,
    bidx: usize, // saturating at bidx_width-1 (narrow 5, wide 28)
    refsel: bool,
    // draw automaton
    phd: bool,
    f2dig: [u16; 16],
    fpi: usize,
    grp: usize,
    coef: usize,
    curch: [u32; 4],
    fsfull: bool,
    // registers (chal len = n_chals, idxr len = nq; scr[8]/breg[4]/fpreg[16]/
    // oreg[68] stay fixed — 2^(max_la-1) / max_la / fp16 / keccak rate — valid
    // while a16 holds for both shapes; see slice 1b-2 notes).
    chal: Vec<Ext>,
    fa2: Ext,
    zn: Ext,
    idxr: Vec<u32>,
    oreg: [u16; 68],
    pos: usize,
    vc: usize,
    asm0: Val,
    asm1: Val,
    pbuf: Ext,
    preg: Ext,
    pzacc: Ext,
    a0: Ext,
    a1: Ext,
    a2: Ext,
    p0: Ext,
    p1: Ext,
    px0: Ext,
    fpreg: [Ext; 16],
    scr: [Ext; 8],
    breg: [Ext; 4],
    inv2s: Ext,
    invz: Ext,
    invzn: Ext,
    xreg: Ext,
    xfin: Ext,
    runev: Ext,
    mchain: Ext, // sim-only: running micro chain value
}

impl Regs {
    fn new(shape: &GateShape) -> Self {
        Regs {
            pr_rot: 0,
            phc: true,
            phq: false,
            qsel: 0,
            qcnt: shape.qslots() as u32,
            fring: 0,
            blkcnt: shape.flush_blocks()[0] as u32,
            bidx: 0,
            refsel: false,
            phd: false,
            f2dig: [0; 16],
            fpi: 0,
            grp: 0,
            coef: 0,
            curch: [0; 4],
            fsfull: false,
            chal: vec![Ext::ZERO; shape.n_chals()],
            fa2: Ext::ZERO,
            zn: Ext::ZERO,
            idxr: vec![0; shape.nq],
            oreg: [0; 68],
            pos: 0,
            vc: 0,
            asm0: Val::ZERO,
            asm1: Val::ZERO,
            pbuf: Ext::ZERO,
            preg: Ext::ONE,
            pzacc: Ext::ZERO,
            a0: Ext::ZERO,
            a1: Ext::ZERO,
            a2: Ext::ZERO,
            p0: Ext::ZERO,
            p1: Ext::ZERO,
            px0: Ext::ZERO,
            fpreg: [Ext::ZERO; 16],
            scr: [Ext::ZERO; 8],
            breg: [Ext::ZERO; 4],
            inv2s: Ext::ZERO,
            invz: Ext::ZERO,
            invzn: Ext::ZERO,
            xreg: Ext::ZERO,
            xfin: Ext::ZERO,
            runev: Ext::ZERO,
            mchain: Ext::ZERO,
        }
    }
}

/// Write one row's register-backed and derived columns.
#[allow(clippy::too_many_arguments)]
fn write_row(
    v: &mut [Val],
    row: usize,
    r: usize,
    regs: &Regs,
    program: &[u32],
    info: Option<&PInfo>,
    layout: &GateLayout,
    shape: &GateShape,
) {
    let qslots = shape.qslots();
    let nq = shape.nq;
    let groupreq = shape.groupreq();
    let base = row * layout.gate_width;
    let w = |v: &mut [Val], col: usize, x: Val| v[base + col] = x;
    let wb = |v: &mut [Val], col: usize, x: bool| v[base + col] = Val::from_bool(x);
    let wu = |v: &mut [Val], col: usize, x: u32| v[base + col] = Val::from_u32(x);
    let we = |v: &mut [Val], col: usize, x: Ext| {
        v[base + col..base + col + 4].copy_from_slice(&ext_limbs(x))
    };

    // Program ring + head decode.
    for i in 0..qslots {
        wu(v, layout.pr + i, program[(i + regs.pr_rot) % qslots]);
    }
    let head = program[regs.pr_rot % qslots];
    for k in 0..15 {
        wb(v, layout.pd + k, (head >> k) & 1 == 1);
    }
    let role = head & 0xf;
    let dparam = (head >> 4) & 0x3f;
    let micro = (head >> 10) & 0x1f;
    // Role / micro / dparam selectors (all zero outside query phase).
    if regs.phq {
        wb(v, layout.rsel + role as usize, true);
        wb(v, layout.mlo + (micro & 7) as usize, true);
        wb(v, layout.msel + micro as usize, true);
        let absany = (1..=5).contains(&role);
        if absany {
            wb(v, layout.drnd + dparam as usize, true);
        }
        wb(v, layout.lfs, role == R_ABS_F34 || role == R_ABS_F16);
    }
    // layout.mhi/layout.dlo/layout.dhi are pure bit products (no phase gate).
    wb(v, layout.mhi + ((micro >> 3) & 3) as usize, true);
    wb(v, layout.dlo + (dparam & 7) as usize, true);
    if (dparam >> 3) < 3 {
        wb(v, layout.dhi + (dparam >> 3) as usize, true);
    }
    wb(v, layout.phc, regs.phc);
    wb(v, layout.phq, regs.phq);
    // layout.qsel / layout.qcnt.
    wb(v, ring_at(layout.qsel, nq + 1, regs.qsel) - layout.qsel + layout.qsel, true);
    wu(v, layout.qcnt, regs.qcnt);
    let qcw = regs.qcnt == 1;
    wb(v, layout.qcw, qcw);
    if !qcw {
        w(
            v,
            layout.qcwi,
            (Val::from_u32(regs.qcnt) - Val::ONE).inverse(),
        );
    }
    // Index bits of the active query.
    let idx = if regs.phq && regs.qsel < nq {
        regs.idxr[regs.qsel]
    } else {
        0
    };
    if regs.phq {
        for k in 0..shape.log_max {
            wb(v, layout.idxb + k, (idx >> k) & 1 == 1);
        }
    }
    // layout.caps8 from the top cap_height idx bits (narrow 19..21, wide 15..17;
    // all-zero bits select element 0). Must match the eval capb = log_max -
    // cap_height (the 1b-B4/B5 fill-side counterpart).
    let capj = ((idx >> (shape.log_max - shape.cap_height())) & 7) as usize;
    wb(v, layout.caps8 + if regs.phq { capj } else { 0 }, true);
    // layout.dbit / layout.glc / layout.grc.
    let pathish =
        regs.phq && (R_PATH..=shape.r_plast_f(shape.n_fri_rounds() - 1)).contains(&role);
    if pathish {
        let dbit = (idx >> dparam) & 1 == 1;
        wb(v, layout.dbit, dbit);
        wb(v, layout.glc, !dbit);
        wb(v, layout.grc, dbit);
    }
    // Flush automaton.
    wb(v, ring_at(layout.fring, 8, regs.fring) - layout.fring + layout.fring, true);
    wu(v, layout.blkcnt, regs.blkcnt);
    let blklast = regs.blkcnt == 1;
    wb(v, layout.blklast, blklast);
    if !blklast {
        w(v, layout.blkinv, (Val::from_u32(regs.blkcnt) - Val::ONE).inverse());
    }
    let dcap = shape.dup_captures();
    for (cmp, inv, tgt) in [(layout.cmpa, layout.cmpai, dcap[0].2), (layout.cmpb, layout.cmpbi, dcap[1].2)] {
        let hit = regs.blkcnt == tgt;
        wb(v, cmp, hit);
        if !hit {
            w(v, inv, (Val::from_u32(regs.blkcnt) - Val::from_u32(tgt)).inverse());
        }
    }
    wb(v, layout.bidx + regs.bidx.min(layout.bidx_width - 1), true);
    wb(v, layout.refsel, regs.refsel);
    // layout.shsel (derived; assert against the plan).
    if regs.phc && !regs.refsel {
        if let Some(PInfo::Obs { flush, block }) = info {
            let fb = shape.flush_blocks();
            let si = shsel_index(&fb, *flush, *block);
            // Consistency of the automaton-derived shape with the plan. BLKCNT
            // counts down from flush_blocks[fring] to 1, so the automaton's
            // block index = flush_blocks[fring] - blkcnt (exact). Post-1b-B5 the
            // bidx one-hot addresses all non-F2 blocks (width = max non-F2
            // flush_blocks + 1), so bidxsel(block) is a valid per-block selector
            // for the wide F0's 28 blocks too (F2's 855 still saturate at the
            // top slot — F2 uses f2sel/blklast, not per-block bidxsel).
            let auto_block = fb[regs.fring] - regs.blkcnt as usize;
            let derived = shsel_index(&fb, regs.fring, auto_block);
            assert_eq!(si, derived, "shape drift at flush {flush} block {block}");
            wb(v, layout.shsel + si, true);
        } else {
            panic!("chal perm without obs info");
        }
    }
    // layout.needl.
    let need = blklast && regs.grp == groupreq[regs.fring + 1];
    wb(v, layout.needl, need);
    // Draw automaton state.
    wb(v, ring_at(layout.grp, shape.n_groups(), regs.grp) - layout.grp + layout.grp, true);
    wb(v, ring_at(layout.coef, 4, regs.coef) - layout.coef + layout.coef, true);
    for k in 0..4 {
        wu(v, layout.curch + k, regs.curch[k]);
    }
    wb(v, layout.fsfull, regs.fsfull);
    // Registers.
    for (i, e) in regs.chal.iter().enumerate() {
        we(v, layout.chal + 4 * i, *e);
    }
    we(v, layout.fa2, regs.fa2);
    we(v, layout.znreg, regs.zn);
    for q in 0..nq {
        wu(v, layout.idxr + q, regs.idxr[q]);
    }
    for i in 0..68 {
        wu(v, layout.oreg + i, regs.oreg[i] as u32);
    }
    wb(v, layout.pos + regs.pos, true);
    wb(v, layout.vc + regs.vc % 16, true);
    wb(v, layout.fpi + regs.fpi % 16, true);
    let mut vce = false;
    if regs.vc % 2 == 0 {
        vce = true;
    }
    wb(v, layout.vce, vce);
    w(v, layout.asm0, regs.asm0);
    w(v, layout.asm1, regs.asm1);
    we(v, layout.pbuf, regs.pbuf);
    we(v, layout.preg, regs.preg);
    we(v, layout.pzacc, regs.pzacc);
    we(v, layout.a0r, regs.a0);
    we(v, layout.a1r, regs.a1);
    we(v, layout.a2r, regs.a2);
    we(v, layout.p0r, regs.p0);
    we(v, layout.p1r, regs.p1);
    we(v, layout.px0r, regs.px0);
    for i in 0..16 {
        we(v, layout.fpreg + 4 * i, regs.fpreg[i]);
    }
    for i in 0..8 {
        we(v, layout.scr + 4 * i, regs.scr[i]);
    }
    for i in 0..4 {
        we(v, layout.breg + 4 * i, regs.breg[i]);
    }
    we(v, layout.inv2s, regs.inv2s);
    we(v, layout.invz, regs.invz);
    we(v, layout.invzn, regs.invzn);
    we(v, layout.xreg, regs.xreg);
    we(v, layout.xfin, regs.xfin);
    we(v, layout.runev, regs.runev);
    for m in 0..16 {
        wu(v, layout.f2dig + m, regs.f2dig[m] as u32);
    }
    wb(v, layout.phd, regs.phd);
    let n_dup = shape.flush_blocks()[2] as u32;
    let cmpc = regs.blkcnt == n_dup;
    wb(v, layout.cmpc, cmpc);
    if !cmpc {
        w(
            v,
            layout.cmpci,
            (Val::from_u32(regs.blkcnt) - Val::from_u32(n_dup)).inverse(),
        );
    }
    let _ = r;
}

// ---------------------------------------------------------------------------
// The builder
// ---------------------------------------------------------------------------

fn bank_mul(v: &mut [Val], row: usize, a: Ext, b: Ext, layout: &GateLayout) -> Ext {
    let c = a * b;
    let base = row * layout.gate_width;
    v[base + layout.mul_off..base + layout.mul_off + 4].copy_from_slice(&ext_limbs(a));
    v[base + layout.mul_off + 4..base + layout.mul_off + 8].copy_from_slice(&ext_limbs(b));
    v[base + layout.mul_off + 8..base + layout.mul_off + 12].copy_from_slice(&ext_limbs(c));
    c
}
fn bank_add(v: &mut [Val], row: usize, a: Ext, b: Ext, layout: &GateLayout) -> Ext {
    let c = a + b;
    let base = row * layout.gate_width;
    v[base + layout.add_off..base + layout.add_off + 4].copy_from_slice(&ext_limbs(a));
    v[base + layout.add_off + 4..base + layout.add_off + 8].copy_from_slice(&ext_limbs(b));
    v[base + layout.add_off + 8..base + layout.add_off + 12].copy_from_slice(&ext_limbs(c));
    c
}
/// Add row with a fixed sum: a = c - b (the bank's subtraction form).
fn bank_add_c(v: &mut [Val], row: usize, c: Ext, b: Ext, layout: &GateLayout) -> Ext {
    let a = c - b;
    let base = row * layout.gate_width;
    v[base + layout.add_off..base + layout.add_off + 4].copy_from_slice(&ext_limbs(a));
    v[base + layout.add_off + 4..base + layout.add_off + 8].copy_from_slice(&ext_limbs(b));
    v[base + layout.add_off + 8..base + layout.add_off + 12].copy_from_slice(&ext_limbs(c));
    a
}

/// Fill one FS draw row (inc-3's fill pattern, gate-block edition).
#[allow(clippy::too_many_arguments)]
fn fill_fs_row(
    v: &mut [Val],
    row: usize,
    lo_byte: u8,
    hi_byte: u8,
    acc: u32,
    odd: bool,
    crot: bool,
    grot: bool,
    layout: &GateLayout,
) {
    let base = row * layout.gate_width;
    for i in 0..8 {
        v[base + layout.fsbits + i] = Val::from_bool((lo_byte >> i) & 1 == 1);
        v[base + layout.fsbits + 8 + i] = Val::from_bool((hi_byte >> i) & 1 == 1);
    }
    v[base + layout.fsacc] = Val::from_u32(acc);
    v[base + layout.fsgate] = Val::ONE;
    v[base + layout.fsodd] = Val::from_bool(odd);
    let p3a = (hi_byte & 0b111) == 0b111;
    let p3b = ((hi_byte >> 3) & 0b111) == 0b111;
    let t7 = p3a && p3b && ((hi_byte >> 6) & 1) == 1;
    v[base + layout.fsp3a] = Val::from_bool(p3a);
    v[base + layout.fsp3b] = Val::from_bool(p3b);
    v[base + layout.fst7] = Val::from_bool(t7);
    let low24 = acc + ((lo_byte as u32) << 16);
    let nz = low24 != 0;
    v[base + layout.fsnz] = Val::from_bool(nz);
    if nz {
        v[base + layout.fsinv] = Val::from_u32(low24).inverse();
    }
    v[base + layout.fsaccept] = Val::from_bool(!(t7 && nz));
    v[base + layout.crot] = Val::from_bool(crot);
    v[base + layout.grot] = Val::from_bool(grot);
}

/// Word canonicity columns for one consumed word (idx 0 or 1). R1 (issue #21):
/// fills the full range-forced 32-bit digit split of `w` (16 hi bits `hb`, 16 lo
/// bits `canon_lo`) plus the top-7-set flag chain (`ta` = hi bits 8..10, `topa`
/// = hi bits 8..12, `top7` = hi bits 8..14, i.e. word bits 24..30) and the
/// low-part nonzero witnesses. Honest words are canonical (`w < P`); the
/// `neg_noncanonical_word` test fills the alias `w+p` directly (bypassing this
/// assert) to exercise the `< p` comparator in `eval`.
fn fill_canon(v: &mut [Val], row: usize, word: usize, w: u32, layout: &GateLayout) {
    assert!(w < P, "honest witness words are canonical");
    fill_canon_raw(v, row, word, w, layout);
}

/// Assert-free core of [`fill_canon`] so negatives can inject a non-canonical
/// representation (`w + p`) that still reduces to the same field element.
fn fill_canon_raw(v: &mut [Val], row: usize, word: usize, w: u32, layout: &GateLayout) {
    let base = row * layout.gate_width;
    let (hb, canon_lo, ta, topa, top7, lbnz, lbi, lonz, loi) = if word == 0 {
        (layout.hb0, layout.canon_lo0, layout.ta0, layout.topa0, layout.top7_0, layout.lbnz0, layout.lbi0, layout.lonz0, layout.loi0)
    } else {
        (layout.hb1, layout.canon_lo1, layout.ta1, layout.topa1, layout.top7_1, layout.lbnz1, layout.lbi1, layout.lonz1, layout.loi1)
    };
    let hi = w >> 16;
    let lo = w & 0xffff;
    for i in 0..16 {
        v[base + hb + i] = Val::from_bool((hi >> i) & 1 == 1);
        v[base + canon_lo + i] = Val::from_bool((lo >> i) & 1 == 1);
    }
    // Top-7 flag chain (word bits 24..30 = hi bits 8..14), staged so each
    // defining constraint stays deg ≤ 3.
    let ta_v = (hi >> 8) & 0x7 == 0x7; // hi bits 8..10
    let topa_v = (hi >> 8) & 0x1f == 0x1f; // hi bits 8..12
    let top7_v = (hi >> 8) & 0x7f == 0x7f; // hi bits 8..14
    v[base + ta] = Val::from_bool(ta_v);
    v[base + topa] = Val::from_bool(topa_v);
    v[base + top7] = Val::from_bool(top7_v);
    // Low-part nonzero witnesses. lb = word bits 16..23 (= hi & 0xff = hb0..7).
    let lb = hi & 0xff;
    v[base + lbnz] = Val::from_bool(lb != 0);
    if lb != 0 {
        v[base + lbi] = Val::from_u32(lb).inverse();
    }
    v[base + lonz] = Val::from_bool(lo != 0);
    if lo != 0 {
        v[base + loi] = Val::from_u32(lo).inverse();
    }
}

fn chal_group(tag: ChalTag) -> usize {
    match tag {
        ChalTag::Alpha => G_ALPHA,
        ChalTag::Zeta => G_ZETA,
        ChalTag::FriAlpha => G_FRIALPHA,
        ChalTag::Beta { r } => G_BETA0 + r,
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_child(
    mut values: &mut [Val],
    row_offset: usize,
    shape: &GateShape,
    layout: &GateLayout,
    consts: &GateConsts,
    program: &[u32],
    sched: &Schedule,
    inputs: &[[u64; 25]],
    outs: &[[u64; 25]],
    infos: &[PInfo],
    hosted: &std::collections::HashMap<usize, Vec<m4gaterec::DrawRec>>,
    chal_expect: &[Ext],
    fpoly: &[Ext],
    fa: Ext,
    zvals: &[Ext],
    dcap: &[(usize, usize, u32); 3],
    n_dup: usize,
    trailer_pi: usize,
    inherit: Option<&Regs>,
    query_rows: &mut Vec<usize>,
    field_draws: &mut Vec<(usize, u32)>,
) -> Regs {
    let n_perms = inputs.len();
    let nq = shape.nq;
    let qslots = shape.qslots();
    let cum = shape.cum();
    let n_rounds = shape.n_fri_rounds();
    let mut regs = Regs::new(shape);
    regs.fsfull = hosted.get(&0).map_or(false, |d| d.len() == 8);
    // 2b-iii fill-continuity: the NON-ANCHORED fold/arith registers are
    // freeze-carried (a `nv==cv` continuity constraint when their update gate is
    // off). At a child boundary child R's csel re-anchor leaves them un-anchored,
    // so a fresh (0) start would break the freeze. Inherit child L's final values
    // instead — harmless (child R's queries overwrite them before use), and the
    // freeze holds with no gating/columns. The ANCHORED fields (scheduling,
    // phase, challenge, vc, preg/pzacc) stay fresh; csel + gated carries own them.
    if let Some(p) = inherit {
        regs.f2dig = p.f2dig;
        regs.oreg = p.oreg;
        regs.fa2 = p.fa2;
        regs.zn = p.zn;
        regs.asm0 = p.asm0;
        regs.asm1 = p.asm1;
        regs.pbuf = p.pbuf;
        regs.a0 = p.a0;
        regs.a1 = p.a1;
        regs.a2 = p.a2;
        regs.p0 = p.p0;
        regs.p1 = p.p1;
        regs.px0 = p.px0;
        regs.fpreg = p.fpreg;
        regs.scr = p.scr;
        regs.breg = p.breg;
        regs.inv2s = p.inv2s;
        regs.invz = p.invz;
        regs.invzn = p.invzn;
        regs.xreg = p.xreg;
        regs.xfin = p.xfin;
        regs.runev = p.runev;
        regs.mchain = p.mchain;
        // Challenge-assembly data registers: inherited (child R's draws reassemble
        // them before the query phase consumes them), row-0-pinned not csel-pinned.
        regs.chal = p.chal.clone();
        regs.idxr = p.idxr.clone();
        regs.curch = p.curch;
    }
    let mut zvi = 0usize;
    // Child-boundary re-anchor selector (2b): 1 on this child's first row.
    // Single child → row 0; interior → row 0 (child L) and 24*nL (child R).
    values[row_offset * layout.gate_width + layout.csel] = Val::ONE;
    for pi in 0..n_perms {
        let info = &infos[pi];
        let base_row = 24 * pi;
        let pre = &inputs[pi];
        let out = &outs[pi];
        let prev_out = if pi > 0 { Some(&outs[pi - 1]) } else { None };

        // Perm-level classification.
        let (is_xor, w_direct) = match info {
            PInfo::Obs { flush, block } => (*block > 0 && *flush != 2, *block == 0),
            PInfo::Refill => (false, true),
            PInfo::Dup { block } => (*block > 0, *block == 0),
            PInfo::Query { slot, .. } => {
                let role = program[*slot] & 0xf;
                (false, (1..=5).contains(&role))
            }
        };
        let (q_role, q_dparam, q_micro, q_q) = match info {
            PInfo::Query { q, slot } => {
                assert_eq!(*slot, regs.pr_rot % qslots, "ring alignment");
                let d = program[*slot];
                (d & 0xf, (d >> 4) & 0x3f, (d >> 10) & 0x1f, *q)
            }
            _ => (0, 0, 0, 0),
        };
        if let PInfo::Query { q, slot } = info {
            if *slot == 0 {
                assert_eq!(regs.qsel, *q, "query counter alignment");
                query_rows.push(row_offset + base_row);
            }
        }
        // Fold round of an absorb slot (dparam 2..6), if any.
        let fold_r = if (1..=5).contains(&q_role) && q_dparam >= 2 {
            Some((q_dparam - 2) as usize)
        } else {
            None
        };
        let qidx = if matches!(info, PInfo::Query { .. }) {
            regs.idxr[q_q] as usize
        } else {
            0
        };

        for r in 0..24 {
            let row = row_offset + base_row + r;
            write_row(&mut values, row, r, &regs, &program, Some(info), &layout, shape);
            // layout.gpb for fold-absorb perms (write over write_row's zeros).
            if let Some(rf) = fold_r {
                let la = shape.log_arities[rf];
                for k in 0..4 {
                    let b = k < la && (qidx >> (cum[rf] + k)) & 1 == 1;
                    values[row * layout.gate_width + layout.gpb + k] = Val::from_bool(b);
                }
                let gp = (qidx >> cum[rf]) & ((1 << la) - 1);
                values[row * layout.gate_width + layout.hit] =
                    Val::from_bool(regs.vc % 16 == gp);
            } else {
                // layout.hit defining constraint with layout.gpb = 0: hit = [vc == 0].
                values[row * layout.gate_width + layout.hit] = Val::from_bool(regs.vc % 16 == 0);
            }

            // --- W words + XOR bits -------------------------------------
            let mut w0v = 0u32;
            let mut w1v = 0u32;
            if r < 17 && (w_direct || is_xor) {
                let limb = |j: usize| -> u16 {
                    let pl = st_limb(pre, 4 * r + j);
                    if is_xor {
                        pl ^ st_limb(prev_out.unwrap(), 4 * r + j)
                    } else {
                        pl
                    }
                };
                w0v = limb(0) as u32 | ((limb(1) as u32) << 16);
                w1v = limb(2) as u32 | ((limb(3) as u32) << 16);
                values[row * layout.gate_width + layout.w0c] = Val::from_u64(w0v as u64);
                values[row * layout.gate_width + layout.w1c] = Val::from_u64(w1v as u64);
                if is_xor {
                    for j in 0..4 {
                        let pl = st_limb(pre, 4 * r + j);
                        let ol = st_limb(prev_out.unwrap(), 4 * r + j);
                        assert_eq!(ol, regs.oreg[4 * r + j], "oreg capture");
                        for i in 0..16 {
                            values[row * layout.gate_width + layout.pbit + 16 * j + i] =
                                Val::from_bool((pl >> i) & 1 == 1);
                            values[row * layout.gate_width + layout.obit + 16 * j + i] =
                                Val::from_bool((ol >> i) & 1 == 1);
                        }
                    }
                }
            }

            // --- carry flags ----------------------------------------------
            let (czd, cz7, cfl, cx0, cx1) = {
                let mut czd = false;
                let mut cz7 = false;
                let mut cfl = false;
                let mut cx0 = false;
                let mut cx1 = false;
                match info {
                    PInfo::Dup { block } => {
                        czd = match *block {
                            0 => (4..=16).contains(&r),
                            b if b == n_dup - 1 => r <= dcap[2].1 - 1,
                            _ => r <= 16,
                        };
                    }
                    // Final obs flush (index 3 + n_fri_rounds; narrow 7, wide 6):
                    // the final-poly value words.
                    PInfo::Obs { flush, block } if *flush == shape.n_obs_flushes() - 1 => {
                        cz7 = match *block {
                            0 => (4..=16).contains(&r),
                            1 => r <= 16,
                            _ => r <= 1,
                        };
                    }
                    PInfo::Query { .. } if (1..=5).contains(&q_role) => {
                        // word-0 fills ceil(f/2) rows (r <= ceil(f/2)-1), word-1
                        // fills floor(f/2) rows (r <= floor(f/2)-1). Mirrors the
                        // eval-side `role_range`. Narrow: F34/C34 f=34→(16,16),
                        // C5 f=5→(2,1), C30 f=30→(14,14), F16 f=16→(7,7).
                        let m0w = |f: usize| (f + 1) / 2 - 1;
                        let m1w = |f: usize| f / 2 - 1;
                        let f = match q_role {
                            R_ABS_F34 | R_ABS_C34 => 34,
                            R_ABS_C5 => shape.trace_last_fresh(),
                            R_ABS_C30 => 30,
                            R_ABS_F16 => shape.qw,
                            _ => 0,
                        };
                        let (m0, m1) = if f == 0 {
                            (false, false)
                        } else {
                            (r <= m0w(f), r <= m1w(f))
                        };
                        if fold_r.is_some() {
                            cfl = m0;
                        } else {
                            cx0 = m0;
                            cx1 = m1;
                        }
                    }
                    _ => {}
                }
                (czd, cz7, cfl, cx0, cx1)
            };
            let b = row * layout.gate_width;
            values[b + layout.czd] = Val::from_bool(czd);
            values[b + layout.cz7] = Val::from_bool(cz7);
            values[b + layout.cf] = Val::from_bool(cfl);
            values[b + layout.cx0] = Val::from_bool(cx0);
            values[b + layout.cx1] = Val::from_bool(cx1);
            let casm = czd || cz7 || cfl;
            values[b + layout.consz] = Val::from_bool(czd && regs.pos == 1);
            values[b + layout.consf] = Val::from_bool(cfl && regs.pos == 1);
            if casm {
                fill_canon(&mut values, row, 0, w0v, &layout);
                fill_canon(&mut values, row, 1, w1v, &layout);
            }

            // --- PZ captures (before this row's consume) ------------------
            if let PInfo::Dup { block } = info {
                // A0/A1/A2 = group-0-end / group-1-end / chain-end reduced-
                // opening snapshots, at shape-derived (block,row). Narrow:
                // (72,14)/(145,7)/(147,5); wide: (426,14)/(853,7)/(854,6).
                let pos = (*block, r);
                if pos == (dcap[0].0, dcap[0].1) {
                    regs.a0 = regs.pzacc;
                    regs.p0 = regs.preg;
                    assert_eq!(zvi, shape.tw, "values consumed at A0 capture");
                    assert_eq!(regs.a0, scale(sched.pz[0]), "A0 capture = PZ0");
                    assert_eq!(regs.p0, sched.alpha_off[0], "P0 capture");
                } else if pos == (dcap[1].0, dcap[1].1) {
                    regs.a1 = regs.pzacc;
                    regs.p1 = regs.preg;
                    assert_eq!(zvi, 2 * shape.tw, "values consumed at A1 capture");
                    assert_eq!(
                        regs.a1 - regs.a0,
                        scale(sched.alpha_off[0] * sched.pz[1]),
                        "A1 span capture"
                    );
                    assert_eq!(regs.p1, sched.alpha_off[1], "P1 capture");
                } else if pos == (dcap[2].0, dcap[2].1) {
                    regs.a2 = regs.pzacc;
                    assert_eq!(zvi, 2 * shape.tw + shape.qw, "values consumed at A2 capture");
                    assert_eq!(
                        regs.a2 - regs.a1,
                        scale(sched.alpha_off[1] * sched.pz[2]),
                        "A2 span capture"
                    );
                }
            }
            // PX0 capture at trace-leaf end: the row after the last fresh word
            // is consumed = ceil(f/2) = (f+1)/2 (narrow 3, wide 11).
            if q_role == R_ABS_C5 && q_dparam == D_T && r == (shape.trace_last_fresh() + 1) / 2 {
                regs.px0 = regs.pzacc;
            }

            // --- asm pipeline -------------------------------------------
            if casm {
                if regs.pos == 0 {
                    regs.asm0 = Val::from_u64(w0v as u64);
                    regs.asm1 = Val::from_u64(w1v as u64);
                    regs.pos = 1;
                } else {
                    let v = Ext::from_basis_coefficients_fn(|i| match i {
                        0 => regs.asm0,
                        1 => regs.asm1,
                        2 => Val::from_u64(w0v as u64),
                        _ => Val::from_u64(w1v as u64),
                    });
                    if czd {
                        assert_eq!(v, zvals[zvi], "dup zeta value {zvi}");
                        zvi += 1;
                        regs.pzacc += regs.preg * v;
                        regs.preg *= fa;
                    } else if cz7 {
                        assert_eq!(v, fpoly[regs.fpi], "final-poly capture");
                        regs.fpreg[regs.fpi] = v;
                        regs.fpi += 1;
                    } else if cfl {
                        let rf = fold_r.unwrap();
                        let fold = &sched.queries[q_q].folds[rf];
                        let vc = regs.vc % 16;
                        assert_eq!(v, scale(fold.evals[vc]), "fold leaf value");
                        if vc == fold.index_in_group {
                            assert_eq!(v, regs.runev, "running eval position");
                        }
                        if vc % 2 == 0 {
                            regs.pbuf = v;
                        } else {
                            let i = vc / 2;
                            let k = ext_base(consts.kf[rf][0][i]);
                            regs.scr[i] = (regs.pbuf + v) * ext_base(consts.half)
                                + regs.breg[0] * k * (regs.pbuf - v);
                        }
                        regs.vc = (regs.vc + 1) % 16;
                    }
                    regs.pos = 0;
                }
            }
            // PX consume.
            if cx0 {
                regs.pzacc += regs.preg * ext_base(Val::from_u64(w0v as u64));
                if cx1 {
                    regs.pzacc += regs.preg * fa * ext_base(Val::from_u64(w1v as u64));
                    regs.preg *= regs.fa2;
                } else {
                    regs.preg *= fa;
                }
            }
            let _ = (out, consts.gen);
            // (FS rows, micro rows, and the boundary handler are emitted in
            // the second half of this loop body, appended below.)

            // --- FS draw rows (consumer perms) -----------------------------
            if let Some(hd) = hosted.get(&pi) {
                assert!(hd.len() <= 8);
                let j = r / 2;
                if j < hd.len() && r < 16 {
                    let d = &hd[j];
                    let [x0, x1, x2, x3] = d.bytes;
                    let g = 7 - j;
                    if r % 2 == 0 {
                        // Limb consistency with the consumer preimage.
                        assert_eq!(
                            st_limb(pre, 2 * g + 1),
                            (x2 as u16) | ((x3 as u16) << 8),
                            "draw limb (even)"
                        );
                        fill_fs_row(&mut values, row, x3, x2, 0, false, false, false, &layout);
                    } else {
                        assert_eq!(
                            st_limb(pre, 2 * g),
                            (x0 as u16) | ((x1 as u16) << 8),
                            "draw limb (odd)"
                        );
                        let acc = (x3 as u32) + ((x2 as u32) << 8);
                        let (crot, grot) = match d.kind {
                            DrawKind::Field { accept, .. } => (accept, accept && regs.coef == 3),
                            DrawKind::Bits { .. } => (false, true),
                        };
                        fill_fs_row(&mut values, row, x1, x0, acc, true, crot, grot, &layout);
                        // Register updates (the odd-row transition).
                        match d.kind {
                            DrawKind::Field {
                                masked,
                                accept,
                                chal,
                                coeff,
                            } => {
                                assert_eq!(chal_group(chal), regs.grp, "draw group");
                                if accept {
                                    assert_eq!(coeff, regs.coef, "draw coefficient");
                                    field_draws.push((row, masked));
                                    if regs.coef < 3 {
                                        regs.curch[regs.coef] = masked;
                                        regs.coef += 1;
                                    } else {
                                        let e = Ext::from_basis_coefficients_fn(|i| {
                                            Val::from_u32(if i < 3 {
                                                regs.curch[i]
                                            } else {
                                                masked
                                            })
                                        });
                                        assert_eq!(e, chal_expect[regs.grp], "challenge value");
                                        regs.chal[regs.grp] = e;
                                        regs.coef = 0;
                                        regs.grp += 1;
                                    }
                                }
                            }
                            DrawKind::Bits { value, purpose, .. } => {
                                match purpose {
                                    m4gaterec::BitsTag::QueryPow => {
                                        assert_eq!(regs.grp, shape.g_pow());
                                        assert_eq!(value, 0, "query PoW");
                                    }
                                    m4gaterec::BitsTag::QueryIndex { q } => {
                                        assert_eq!(regs.grp, shape.g_idx0() + q);
                                        regs.idxr[q] = value;
                                    }
                                }
                                regs.grp += 1;
                            }
                        }
                    }
                }
            }

            // --- micro-blocks (query perms) --------------------------------
            if matches!(info, PInfo::Query { .. }) && q_micro != M_NONE {
                let qr = &sched.queries[q_q];
                match q_micro {
                    M_X1 => {
                        if r < shape.log_max {
                            let bit = (qidx >> r) & 1 == 1;
                            let bmux = ext_base(if bit { consts.kx[r] } else { Val::ONE });
                            let a = if r == 0 {
                                ext_base(consts.gen)
                            } else {
                                regs.mchain
                            };
                            regs.mchain = bank_mul(&mut values, row, a, bmux, &layout);
                            if r == shape.log_max - 1 {
                                assert_eq!(regs.mchain, qr.x, "x chain");
                                regs.xreg = regs.mchain;
                            }
                        }
                    }
                    M_INV => {
                        if r == 0 {
                            let zx = bank_add_c(&mut values, row, regs.chal[G_ZETA], regs.xreg, &layout);
                            let cp = bank_mul(&mut values, row, zx, qr.inv_z, &layout);
                            assert_eq!(cp, Ext::ONE, "inv_z witness");
                            regs.invz = qr.inv_z;
                        } else if r == 1 {
                            let znx = bank_add_c(&mut values, row, regs.zn, regs.xreg, &layout);
                            let cp = bank_mul(&mut values, row, znx, qr.inv_zn, &layout);
                            assert_eq!(cp, Ext::ONE, "inv_zn witness");
                            regs.invzn = qr.inv_zn;
                        }
                    }
                    m if m >= shape.m_s(0) && m < shape.m_s(0) + n_rounds as u32 => {
                        let rf = (m - shape.m_s(0)) as usize;
                        let lf = shape.lf()[rf];
                        if r < lf {
                            let bit = (qidx >> (cum[rf + 1] + r)) & 1 == 1;
                            let bmux =
                                ext_base(if bit { consts.sk[rf][r] } else { Val::ONE });
                            let a = if r == 0 { Ext::ONE } else { regs.mchain };
                            regs.mchain = bank_mul(&mut values, row, a, bmux, &layout);
                        } else if r == lf {
                            let fold = &qr.folds[rf];
                            assert_eq!(regs.mchain, fold.s, "s chain");
                            let a = regs.mchain * ext_base(Val::from_u32(2));
                            let cp = bank_mul(&mut values, row, a, fold.inv_2s, &layout);
                            assert_eq!(cp, Ext::ONE, "inv2s witness");
                            regs.inv2s = fold.inv_2s;
                        }
                    }
                    m if m >= shape.m_b(0) && m < shape.m_b(0) + n_rounds as u32 => {
                        let rf = (m - shape.m_b(0)) as usize;
                        let la = shape.log_arities[rf];
                        if r == 0 {
                            let cb =
                                bank_mul(&mut values, row, regs.chal[G_BETA0 + rf], regs.inv2s, &layout);
                            regs.breg[0] = cb;
                        } else if r < la {
                            let bl = regs.breg[r - 1];
                            let cb = bank_mul(&mut values, row, bl, bl, &layout);
                            regs.breg[r] = cb * ext_base(Val::from_u32(2));
                        }
                    }
                    M_RO => match r {
                        0 => regs.scr[0] = bank_mul(&mut values, row, regs.p0, regs.px0, &layout),
                        1 => regs.scr[1] = bank_mul(&mut values, row, regs.p1, regs.pzacc, &layout),
                        2 => {
                            let g0 = bank_add_c(&mut values, row, regs.a0, regs.px0, &layout);
                            regs.scr[2] = bank_mul(&mut values, row, g0, regs.invz, &layout);
                        }
                        3 => regs.mchain = bank_add_c(&mut values, row, regs.a1, regs.a0, &layout),
                        4 => {
                            let d1 = bank_add_c(&mut values, row, regs.mchain, regs.scr[0], &layout);
                            regs.scr[3] = bank_mul(&mut values, row, d1, regs.invzn, &layout);
                        }
                        5 => regs.mchain = bank_add_c(&mut values, row, regs.a2, regs.a1, &layout),
                        6 => {
                            let d2 = bank_add_c(&mut values, row, regs.mchain, regs.scr[1], &layout);
                            regs.scr[4] = bank_mul(&mut values, row, d2, regs.invz, &layout);
                        }
                        7 => regs.mchain = bank_add(&mut values, row, regs.scr[2], regs.scr[3], &layout),
                        8 => {
                            let ro = bank_add(&mut values, row, regs.mchain, regs.scr[4], &layout);
                            assert_eq!(ro, scale(qr.ro), "reduced opening");
                            regs.runev = ro;
                        }
                        _ => {}
                    },
                    m if m >= shape.m_fhi(0) && m < shape.m_fhi(0) + n_rounds as u32 => {
                        let rf = (m - shape.m_fhi(0)) as usize;
                        // (level, pair) fold schedule of an arity-2^la round:
                        // level l has 2^(la-1-l) pairs for l = 1..la.
                        let la = shape.log_arities[rf];
                        let mut pairs: Vec<(usize, usize)> = vec![];
                        for l in 1..la {
                            for i in 0..(1usize << (la - 1 - l)) {
                                pairs.push((l, i));
                            }
                        }
                        if r < pairs.len() {
                            let (l, i) = pairs[r];
                            let lo = regs.scr[2 * i];
                            let hi = regs.scr[2 * i + 1];
                            let outv = (lo + hi) * ext_base(consts.half)
                                + regs.breg[l] * ext_base(consts.kf[rf][l][i]) * (lo - hi);
                            if r == pairs.len() - 1 {
                                assert_eq!(outv, scale(qr.folds[rf].folded), "fold output");
                                regs.runev = outv;
                            } else {
                                regs.scr[i] = outv;
                            }
                        }
                    }
                    m if m == shape.m_fin() => {
                        // x_fin chain over the final-poly domain index bits:
                        // fin_bits (= log_max - cum[n]) rows from bit fin_lo (= cum[n]).
                        let fin_lo = cum[n_rounds];
                        let fin_bits = shape.log_max - fin_lo;
                        if r < fin_bits {
                            let bit = (qidx >> (fin_lo + r)) & 1 == 1;
                            let bmux = ext_base(if bit { consts.kx[r] } else { Val::ONE });
                            let a = if r == 0 { Ext::ONE } else { regs.mchain };
                            regs.mchain = bank_mul(&mut values, row, a, bmux, &layout);
                            if r == fin_bits - 1 {
                                assert_eq!(regs.mchain, qr.x_fin, "x_fin chain");
                                regs.xfin = regs.mchain;
                            }
                        }
                    }
                    m if m == shape.m_horn() => {
                        if r < 15 {
                            let a = if r == 0 { regs.fpreg[15] } else { regs.mchain };
                            let c1 = bank_mul(&mut values, row, a, regs.xfin, &layout);
                            let c2 = bank_add(&mut values, row, c1, regs.fpreg[14 - r], &layout);
                            regs.mchain = c2;
                            if r == 14 {
                                assert_eq!(c2, scale(qr.final_eval), "final-poly eval");
                                assert_eq!(c2, regs.runev, "final fold compare");
                            }
                        }
                    }
                    _ => {}
                }
            }
            // GLOB micro on the trailer: fa2 and zeta_next.
            if pi == trailer_pi {
                if r == 12 {
                    regs.fa2 =
                        bank_mul(&mut values, row, regs.chal[G_FRIALPHA], regs.chal[G_FRIALPHA], &layout);
                } else if r == 13 {
                    regs.zn =
                        bank_mul(&mut values, row, regs.chal[G_ZETA], ext_base(consts.g_trace), &layout);
                }
            }

            // --- perm boundary ----------------------------------------------
            if r == 23 {
                let next = infos.get(pi + 1);
                let phasegate = regs.phc
                    && regs.refsel
                    && regs.blkcnt == 1
                    && regs.fring == shape.n_obs_flushes() - 1
                    && regs.grp == shape.g_done();
                let phdend = regs.phd && regs.blkcnt == 1;
                if regs.phq {
                    regs.pr_rot = (regs.pr_rot + 1) % qslots;
                    if regs.qcnt == 1 {
                        regs.qcnt = qslots as u32;
                        regs.qsel += 1;
                        if regs.qsel == nq {
                            regs.phq = false;
                        }
                    } else {
                        regs.qcnt -= 1;
                    }
                }
                let next_xor = matches!(next, Some(PInfo::Obs { flush, block }) if *block > 0 && *flush != 2)
                    || matches!(next, Some(PInfo::Dup { block }) if *block > 0);
                if next_xor {
                    for i in 0..68 {
                        regs.oreg[i] = st_limb(out, i);
                    }
                }
                if matches!(info, PInfo::Obs { flush: 2, block } if *block == shape.flush_blocks()[2] - 1) {
                    for m in 0..16 {
                        regs.f2dig[m] = st_limb(out, m);
                    }
                }
                if matches!(info, PInfo::Dup { block } if *block == n_dup - 1) {
                    for m in 0..16 {
                        assert_eq!(st_limb(out, m), regs.f2dig[m], "dup digest binding");
                    }
                }
                match next {
                    Some(PInfo::Obs { flush, block: 0 }) => {
                        assert_eq!(*flush, regs.fring + 1, "obs flush order");
                        regs.fring = *flush;
                        regs.blkcnt = shape.flush_blocks()[*flush] as u32;
                        regs.bidx = 0;
                        regs.refsel = false;
                    }
                    Some(PInfo::Obs { .. }) => {
                        regs.blkcnt -= 1;
                        regs.bidx = (regs.bidx + 1).min(layout.bidx_width - 1);
                    }
                    Some(PInfo::Refill) => {
                        regs.refsel = true;
                        regs.blkcnt = 1;
                        regs.bidx = 0;
                    }
                    Some(PInfo::Dup { block: 0 }) => {
                        assert!(phasegate, "dup phase entry");
                        regs.phc = false;
                        regs.phd = true;
                        regs.refsel = false;
                        regs.blkcnt = n_dup as u32;
                    }
                    Some(PInfo::Dup { .. }) => {
                        regs.blkcnt -= 1;
                    }
                    Some(PInfo::Query { .. }) => {
                        if phdend {
                            regs.phd = false;
                            regs.phq = true;
                        }
                    }
                    None => {}
                }
                if let Some(PInfo::Query { slot, .. }) = next {
                    let role = program[*slot] & 0xf;
                    if role == R_ABS_F34 || role == R_ABS_F16 {
                        regs.pzacc = Ext::ZERO;
                        regs.preg = Ext::ONE;
                        regs.vc = 0;
                        assert_eq!(regs.pos, 0, "asm alignment at leaf start");
                    }
                }
                regs.fsfull = hosted.get(&(pi + 1)).map_or(false, |d| d.len() == 8);
            }
        }
    }

    // Global self-checks against the recorder.
    assert_eq!(regs.qsel, nq, "all query blocks completed");
    assert!(!regs.phq && !regs.phc && !regs.phd, "phases exhausted");
    for (g, e) in chal_expect.iter().enumerate() {
        assert_eq!(regs.chal[g], *e, "challenge register {g}");
    }
    for q in 0..nq {
        assert_eq!(regs.idxr[q] as usize, sched.queries[q].index, "index register {q}");
    }
    assert_eq!(regs.a0, scale(sched.pz[0]), "A0 = PZ group 0");
    assert_eq!(regs.p0, sched.alpha_off[0], "P0 = fri_alpha^tw");
    assert_eq!(
        regs.a1 - regs.a0,
        scale(sched.alpha_off[0] * sched.pz[1]),
        "A1 span"
    );
    assert_eq!(regs.p1, sched.alpha_off[1], "P1 = fri_alpha^(2*tw)");
    assert_eq!(
        regs.a2 - regs.a1,
        scale(sched.alpha_off[1] * sched.pz[2]),
        "A2 span"
    );
    assert_eq!(regs.fpi, 16, "final poly fully captured");
    regs
}

pub(crate) fn build_gate_trace(
    sched: &Schedule,
    inner_pvs: &[Val],
    shape: &GateShape,
    extra_capacity_bits: usize,
) -> (RowMajorMatrix<Val>, GateMeta) {
    // Slice 1b-3: the inner-proof `shape` is now an explicit parameter, so the
    // interior node can pass `GateShape::wide()`. Narrow callers pass
    // `&GateShape::narrow()` and are unchanged.
    let consts = gate_consts_from_shape(shape);
    let program = qprogram_from_shape(shape);
    let layout = GateLayout::from_shape(shape);
    let nq = shape.nq;
    let qslots = shape.qslots();
    let cum = shape.cum();
    let n_rounds = shape.n_fri_rounds();
    let opvs = outer_pvs(sched, inner_pvs, shape);
    let (inputs, infos) = lane_plan(sched, shape);
    let n_perms = inputs.len();
    let outs: Vec<[u64; 25]> = inputs.iter().map(keccakf).collect();

    let keccak = p3_keccak_air::generate_trace_rows::<Val>(inputs.clone(), 0);
    let rows = keccak.height();
    // Shape/perm-driven rectangle height: the keccak lane pads n_perms·24 rows
    // up to the next power of two. Narrow (2,382 perms) -> 2^16; wide
    // single-child (~8,360 perms) -> 2^18.
    let expected_rows = (n_perms * 24).next_power_of_two();
    assert_eq!(rows, expected_rows, "gate rectangle height (n_perms={n_perms})");
    let mut values = Vec::with_capacity((rows << extra_capacity_bits) * layout.gate_width);
    values.resize(rows * layout.gate_width, Val::ZERO);
    for r in 0..rows {
        values[r * layout.gate_width..r * layout.gate_width + NUM_KECCAK_COLS]
            .copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    drop(keccak);

    // Draw hosting: flush f's digest draws live on flush f+1's block 0
    // (or the trailer for the last flush).
    let nf = sched.flushes.len();
    let n_chal_blocks: usize = sched.flushes.iter().map(|f| f.n_blocks).sum();
    let trailer_pi = n_chal_blocks;
    let mut hosted: HashMap<usize, Vec<m4gaterec::DrawRec>> = HashMap::new();
    for d in &sched.draws {
        let cons = if d.flush + 1 < nf {
            sched.flushes[d.flush + 1].first_perm
        } else {
            trailer_pi
        };
        hosted.entry(cons).or_default().push(d.clone());
    }
    let mut chal_expect: Vec<Ext> = vec![sched.alpha, sched.zeta, sched.fri_alpha];
    for r in 0..shape.n_fri_rounds() {
        chal_expect.push(sched.betas[r]);
    }
    assert_eq!(chal_expect.len(), shape.n_chals());
    // Final poly from the labeled obs stream.
    let fpoly: Vec<Ext> = sched
        .obs
        .iter()
        .find(|o| o.label == m4gaterec::ObsLabel::FinalPoly)
        .unwrap()
        .bytes
        .chunks(16)
        .map(|c| {
            Ext::from_basis_coefficients_fn(|i| {
                Val::from_u32(u32::from_le_bytes(c[4 * i..4 * i + 4].try_into().unwrap()))
            })
        })
        .collect();
    assert_eq!(fpoly.len(), 16);
    let fa = sched.fri_alpha;
    // Oracle: the concatenated zeta-opening ext values from the obs stream.
    let zvals: Vec<Ext> = {
        let mut bytes = vec![];
        for g in 0..3 {
            bytes.extend_from_slice(
                &sched
                    .obs
                    .iter()
                    .find(|o| o.label == m4gaterec::ObsLabel::ZetaVals { group: g })
                    .unwrap()
                    .bytes,
            );
        }
        bytes
            .chunks(16)
            .map(|c| {
                Ext::from_basis_coefficients_fn(|i| {
                    Val::from_u32(u32::from_le_bytes(c[4 * i..4 * i + 4].try_into().unwrap()))
                })
            })
            .collect()
    };
    // Reduced-opening dup-phase capture geometry (slice 1b-B2): (block,row,blkcnt)
    // for the group-0/group-1/end boundaries, and the last dup block index.
    let dcap = shape.dup_captures();
    let n_dup = shape.flush_blocks()[2];

    let mut meta = GateMeta {
        query_rows: vec![],
        field_draws: vec![],
        trailer_row: 24 * trailer_pi,
        n_perms,
        opvs: opvs.clone(),
    };

    let regs = emit_child(
        &mut values, 0, shape, &layout, &consts, &program, sched,
        &inputs, &outs, &infos, &hosted, &chal_expect, &fpoly, fa,
        &zvals, &dcap, n_dup, trailer_pi, None,
        &mut meta.query_rows, &mut meta.field_draws,
    );

    // Pad rows: frozen registers.
    for row in 24 * n_perms..rows {
        write_row(&mut values, row, row % 24, &regs, &program, None, &layout, shape);
        // layout.hit defining constraint on pad rows: gpb=0 (write_row zeros it)
        // ⇒ glo=ghi=[1,0,0,0] ⇒ the global HIT constraint reduces to
        // `hit == vc[0]`. write_row never fills hit, and the main perm loop's
        // hit fill (the non-fold else-branch, `hit=[vc%16==0]`) does not run
        // over pad rows — so mirror it here. Narrow's frozen vc lands off slot 0
        // (last fold round has 4 leaves ⇒ vc=4), so this stays 0 = byte-identical;
        // wide's last round has 16 leaves ⇒ vc wraps to 0, so hit must be 1.
        values[row * layout.gate_width + layout.hit] = Val::from_bool(regs.vc % 16 == 0);
    }

    fill_derived(&mut values, &layout, shape);

    (RowMajorMatrix::new(values, layout.gate_width), meta)
}

/// Per-child transcript-derived data consumed by `emit_child` (the setup half of
/// build_gate_trace, factored so the interior builder can derive it once per
/// child). Deterministic in (sched, shape).
struct ChildDerived {
    inputs: Vec<[u64; 25]>,
    infos: Vec<PInfo>,
    outs: Vec<[u64; 25]>,
    hosted: std::collections::HashMap<usize, Vec<m4gaterec::DrawRec>>,
    chal_expect: Vec<Ext>,
    fpoly: Vec<Ext>,
    fa: Ext,
    zvals: Vec<Ext>,
    trailer_pi: usize,
}

fn child_derived(sched: &Schedule, shape: &GateShape) -> ChildDerived {
    let (inputs, infos) = lane_plan(sched, shape);
    let outs: Vec<[u64; 25]> = inputs.iter().map(keccakf).collect();
    let nf = sched.flushes.len();
    let n_chal_blocks: usize = sched.flushes.iter().map(|f| f.n_blocks).sum();
    let trailer_pi = n_chal_blocks;
    let mut hosted: std::collections::HashMap<usize, Vec<m4gaterec::DrawRec>> =
        std::collections::HashMap::new();
    for d in &sched.draws {
        let cons = if d.flush + 1 < nf {
            sched.flushes[d.flush + 1].first_perm
        } else {
            trailer_pi
        };
        hosted.entry(cons).or_default().push(d.clone());
    }
    let mut chal_expect: Vec<Ext> = vec![sched.alpha, sched.zeta, sched.fri_alpha];
    for r in 0..shape.n_fri_rounds() {
        chal_expect.push(sched.betas[r]);
    }
    let to_ext = |bytes: &[u8]| -> Vec<Ext> {
        bytes
            .chunks(16)
            .map(|c| {
                Ext::from_basis_coefficients_fn(|i| {
                    Val::from_u32(u32::from_le_bytes(c[4 * i..4 * i + 4].try_into().unwrap()))
                })
            })
            .collect()
    };
    let fpoly = to_ext(
        &sched
            .obs
            .iter()
            .find(|o| o.label == m4gaterec::ObsLabel::FinalPoly)
            .unwrap()
            .bytes,
    );
    let mut zbytes = vec![];
    for g in 0..3 {
        zbytes.extend_from_slice(
            &sched
                .obs
                .iter()
                .find(|o| o.label == m4gaterec::ObsLabel::ZetaVals { group: g })
                .unwrap()
                .bytes,
        );
    }
    let zvals = to_ext(&zbytes);
    ChildDerived {
        inputs,
        infos,
        outs,
        hosted,
        chal_expect,
        fpoly,
        fa: sched.fri_alpha,
        zvals,
        trailer_pi,
    }
}

/// M4 step 1 stage 2 棒 2: assemble the two-child interior verifier rectangle —
/// child L in rows `0..24*nL`, child R in rows `24*nL..24*(nL+nR)`, one keccak
/// lane over both, padded to 2^19. The `csel` re-anchor (2b) restarts the
/// automaton at each child's first row. For SAME-LEAF children `opvs_l == opvs_r`
/// so a single outer-PV set serves both cap comparisons + F0 PV absorptions
/// (per-child opvs routing for DISTINCT children is 2d). Correctness is checked
/// via `check_constraints`; the full `prove` (RSS gate) is stage 3.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_interior_trace(
    sched_l: &Schedule,
    sched_r: &Schedule,
    opvs_l: &[Val],
    opvs_r: &[Val],
    shape: &GateShape,
    extra_capacity_bits: usize,
) -> (RowMajorMatrix<Val>, GateMeta) {
    let consts = gate_consts_from_shape(shape);
    let program = qprogram_from_shape(shape);
    let layout = GateLayout::from_shape(shape);
    let dcap = shape.dup_captures();
    let n_dup = shape.flush_blocks()[2];

    let cd_l = child_derived(sched_l, shape);
    let cd_r = child_derived(sched_r, shape);
    let nl = cd_l.inputs.len();
    let nr = cd_r.inputs.len();

    // One keccak lane over both children (child L then child R) then the merge
    // sponge (棒 3): child-L opvs digest, child-R opvs digest, root perm. The
    // merge perms are placed at the TRACE END (child L | child R | zero-pad |
    // merge) so the root perm's last row is the rectangle's `last_row` — the
    // clean anchor for the merge-region pin (mreg/mcnt) in `eval` (棒 3-2). The
    // merge perms are valid keccak-f (KeccakAir checks them); their preimages
    // are bound to the public values in 棒 3-2 (eval binding).
    let merge_inputs = crate::m4interior::merge_perm_inputs(opvs_l, opvs_r);
    let nm = merge_inputs.len();
    assert_eq!(nm, shape.merge_perms(), "merge perm count matches shape");
    let real = nl + nr + nm;
    let rows = (real * 24).next_power_of_two();
    let total_perms = rows / 24;
    let zero_pad = total_perms - real; // zero perms BETWEEN child R and merge
    let mut all_inputs = cd_l.inputs.clone();
    all_inputs.extend_from_slice(&cd_r.inputs);
    all_inputs.extend(std::iter::repeat([0u64; 25]).take(zero_pad));
    all_inputs.extend_from_slice(&merge_inputs);
    assert_eq!(all_inputs.len(), total_perms, "lane exactly fills the rectangle");
    let keccak = p3_keccak_air::generate_trace_rows::<Val>(all_inputs, 0);
    assert_eq!(keccak.height(), rows, "no implicit keccak padding (merge is last)");
    // First row of the merge region = the perm-aligned start of the last nm
    // perms. NOT `rows - 24·nm`: a power-of-2 height is not a multiple of 24, so
    // the trace's last perm is truncated (`rows mod 24`-row tail); the merge
    // perms sit at global perm boundaries `24·(total_perms - nm)`, and the mreg
    // suffix extends through the inert tail to last_row.
    let merge_start = 24 * (total_perms - nm);
    let mut values = Vec::with_capacity((rows << extra_capacity_bits) * layout.gate_width);
    values.resize(rows * layout.gate_width, Val::ZERO);
    for r in 0..rows {
        values[r * layout.gate_width..r * layout.gate_width + NUM_KECCAK_COLS]
            .copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    drop(keccak);

    // 2d per-child opvs: the interior's public values are `outer_pvs(L) ++
    // outer_pvs(R)` (each = that child's caps + inner PVs). Child R's cap
    // comparison selects the second half via the `chi`/`cc` routing in `eval`;
    // same-leaf children just have identical halves. Verified against the
    // `new_interior()` AIR (num_public_values = 2·n_opvs).
    let mut opvs = outer_pvs(sched_l, opvs_l, shape);
    opvs.extend(outer_pvs(sched_r, opvs_r, shape));
    // 棒 3: the interior's exposed binding value = the merge root (§2), appended
    // after the two consumed child opvs halves.
    opvs.extend(crate::m4interior::merge_root(opvs_l, opvs_r));
    // 棒 3-3 (M4 step 2): the epoch Σfee rider, appended after the merge root.
    // Each child's fee limbs are the TAIL of that child's opvs half (M3 fee =
    // PV_FEE..PV_LEN, the inner-PV tail). Computed from the ASSEMBLED halves
    // (each already re-scaled by monty_rr in `outer_pvs`), so it matches what the
    // eval binding reads as `pv(feeL) + pv(feeR)`. Wide/interior only.
    if shape.merge_lane {
        let n_opvs = shape.n_opvs();
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        for j in 0..fl {
            let fee_l = opvs[n_opvs - fl + j];
            let fee_r = opvs[2 * n_opvs - fl + j];
            opvs.push(fee_l + fee_r);
        }
    }
    let mut meta = GateMeta {
        query_rows: vec![],
        field_draws: vec![],
        trailer_row: 24 * cd_l.trailer_pi,
        n_perms: nl + nr + nm,
        opvs: opvs.clone(),
    };

    let regs_l = emit_child(
        &mut values, 0, shape, &layout, &consts, &program, sched_l, &cd_l.inputs, &cd_l.outs,
        &cd_l.infos, &cd_l.hosted, &cd_l.chal_expect, &cd_l.fpoly, cd_l.fa, &cd_l.zvals, &dcap,
        n_dup, cd_l.trailer_pi, None, &mut meta.query_rows, &mut meta.field_draws,
    );
    // Child R inherits child L's final non-anchored fold/arith registers so their
    // freeze carries hold across the boundary (2b-iii fill-continuity).
    let regs = emit_child(
        &mut values, 24 * nl, shape, &layout, &consts, &program, sched_r, &cd_r.inputs,
        &cd_r.outs, &cd_r.infos, &cd_r.hosted, &cd_r.chal_expect, &cd_r.fpoly, cd_r.fa,
        &cd_r.zvals, &dcap, n_dup, cd_r.trailer_pi, Some(&regs_l),
        &mut meta.query_rows, &mut meta.field_draws,
    );

    // Pad rows: frozen registers of the last child (mirror build_gate_trace).
    for row in 24 * (nl + nr)..rows {
        write_row(&mut values, row, row % 24, &regs, &program, None, &layout, shape);
        values[row * layout.gate_width + layout.hit] = Val::from_bool(regs.vc % 16 == 0);
    }
    // 2d: `chi` = running child selector. 0 across child L (rows 0..24·nL,
    // already zero-initialized), 1 across child R and the pad tail (rows
    // 24·nL..). The pinned transition `chi_next = chi + csel_next` rises exactly
    // at the csel child boundary (row 24·nL). `cc = chi·caps8` is filled by
    // fill_derived, so chi must be set first.
    for row in (24 * nl)..rows {
        values[row * layout.gate_width + layout.chi] = Val::ONE;
    }
    // 棒 3-2 merge-region pin: `mreg` = 1 on the last 24·nm rows (the merge
    // sponge), `mcnt` = running count of mreg (so mcnt[last_row] == 24·nm). The
    // eval pins mreg monotone + mcnt == 24·nm at last_row, positively forcing the
    // region to be exactly the merge perms (a prover cannot drop/move it).
    if shape.merge_lane {
        let w = layout.gate_width;
        let nm2 = shape.merge_perms();
        let kl = (nm2 - 1) / 2;
        let thresholds =
            [1u32, (24 * kl + 1) as u32, (24 * (nm2 - 1) + 1) as u32, (24 * nm2) as u32];
        let mut cnt = 0u32;
        for row in 0..rows {
            if row >= merge_start {
                cnt += 1;
                values[row * w + layout.mreg] = Val::ONE;
            }
            values[row * w + layout.mcnt] = Val::from_u32(cnt);
            // 棒 3-2b comparators (meq/minv) + reset flag (mrst = first 3 = sub-
            // sponge starts; meq[3] = eq_end = root perm's last row).
            let mcnt_v = Val::from_u32(cnt);
            let mut rst = Val::ZERO;
            for (k, tk) in thresholds.iter().enumerate() {
                let diff = mcnt_v - Val::from_u32(*tk);
                if diff == Val::ZERO {
                    values[row * w + layout.meq + k] = Val::ONE;
                    if k < 3 {
                        rst = Val::ONE;
                    }
                } else {
                    values[row * w + layout.minv + k] = diff.inverse();
                }
            }
            values[row * w + layout.mrst] = rst;
        }
        // 棒 3-2c: dL carry. Captured at the childL→childR boundary (perm kl-1's
        // output → perm kl's row 0), then freeze-held to the root perm. Fill dL
        // for rows from child-R's start (merge_start + 24·kl) onward.
        let (dl, _dr) = crate::m4interior::child_digests(opvs_l, opvs_r);
        let dl_from = merge_start + 24 * kl;
        for row in dl_from..rows {
            for (m, &v) in dl.iter().enumerate() {
                values[row * w + layout.dlr + m] = v;
            }
        }
        // Issue #24 (D0): the msh one-hot ring + its rotation gate mrot. Merge
        // perm p (region-index 0..nm) is the active slot across its 24 rows; the
        // truncated tail past the root perm freezes at the root slot (nm-1) so
        // `Σ msh == mreg` holds there too. mrot fires on each region perm's last
        // row except the root's (no forward rotation into the inert tail).
        for row in merge_start..rows {
            let off = row - merge_start;
            let perm_idx = off / 24;
            let active = if perm_idx < nm2 { perm_idx } else { nm2 - 1 };
            values[row * w + layout.msh + active] = Val::ONE;
            // Rotation boundary: perm's last row (off % 24 == 23) for a non-root
            // region perm. The tail (perm_idx >= nm2) has no 24th row.
            if off % 24 == 23 && perm_idx < nm2 - 1 {
                values[row * w + layout.mrot] = Val::ONE;
            }
        }
    }
    fill_derived(&mut values, &layout, shape);
    (RowMajorMatrix::new(values, layout.gate_width), meta)
}

/// Fill the Phase-1a degree-reduction columns: pure current-row functions of
/// already-filled columns, mirroring the defining constraints in `eval`. Kept
/// as a post-pass so the intricate per-perm witness logic above is untouched.
fn fill_derived(values: &mut [Val], layout: &GateLayout, shape: &GateShape) {
    let w = layout.gate_width;
    let one = Val::ONE;
    let rows = values.len() / w;
    let ring = |base: usize, n: usize, g: usize| base + (n - g % n) % n;
    let flush_blocks = shape.flush_blocks();
    let lfs = shape.lf();
    for r in 0..rows {
        let base = r * w;
        let row = &values[base..base + w];
        let g = |col: usize| row[col];
        // layout.pd-bit literal: on ? bit : (1 - bit).
        let pl = |col: usize, on: bool| if on { row[col] } else { one - row[col] };
        // Family-2 raw bit-products.
        let mut m3 = [Val::ZERO; 8];
        for (a, slot) in m3.iter_mut().enumerate() {
            *slot = pl(layout.pd + 10, a & 1 == 1) * pl(layout.pd + 11, a & 2 == 2) * pl(layout.pd + 12, a & 4 == 4);
        }
        let mut rlo = [Val::ZERO; 4];
        let mut rhi = [Val::ZERO; 4];
        for j in 0..4 {
            rlo[j] = pl(layout.pd, j & 1 == 1) * pl(layout.pd + 1, j & 2 == 2);
            rhi[j] = pl(layout.pd + 2, j & 1 == 1) * pl(layout.pd + 3, j & 2 == 2);
        }
        let mut dmux = Val::ZERO;
        for k in 0..(shape.log_max - shape.cap_height()) {
            dmux += g(layout.dlo + (k & 7)) * g(layout.dhi + (k >> 3)) * g(layout.idxb + k);
        }
        // Family-3 fold gates/products.
        let mut glo = [Val::ZERO; 4];
        let mut ghi = [Val::ZERO; 4];
        for j in 0..4 {
            glo[j] = pl(layout.gpb, j & 1 == 1) * pl(layout.gpb + 1, j & 2 == 2);
            ghi[j] = pl(layout.gpb + 2, j & 1 == 1) * pl(layout.gpb + 3, j & 2 == 2);
        }
        let mut gf = [Val::ZERO; 4];
        for rf in 0..shape.n_fri_rounds() {
            gf[rf] = g(layout.consf) * g(layout.drnd + 2 + rf);
        }
        // layout.bpm = extmul(layout.breg, layout.pbuf - v), v = ext(layout.asm0,layout.asm1,layout.w0c,layout.w1c).
        let w_ext = Val::from_u32(EXT_W);
        let vv = [g(layout.asm0), g(layout.asm1), g(layout.w0c), g(layout.w1c)];
        let pmv = [g(layout.pbuf) - vv[0], g(layout.pbuf + 1) - vv[1], g(layout.pbuf + 2) - vv[2], g(layout.pbuf + 3) - vv[3]];
        let mut bpm = [Val::ZERO; 4];
        for (k, slot) in bpm.iter_mut().enumerate() {
            let mut acc = Val::ZERO;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        acc += g(layout.breg + i) * pmv[j];
                    } else if i + j == k + 4 {
                        acc += w_ext * g(layout.breg + i) * pmv[j];
                    }
                }
            }
            *slot = acc;
        }
        let mut fhg = vec![Val::ZERO; shape.n_fhg()];
        for rf in 0..shape.n_fri_rounds() {
            let npairs = (1usize << (shape.log_arities[rf] - 1)) - 1;
            for r in 0..npairs {
                fhg[fhg_index(&shape.log_arities, rf, r)] =
                    g(layout.msel + shape.m_fhi(rf) as usize) * g(r);
            }
        }
        // layout.prega = extmul(layout.preg, fri_alpha) for the PX word-1 accumulation term.
        let fa_off = layout.chal + 4 * G_FRIALPHA;
        let mut prega = [Val::ZERO; 4];
        for (k, slot) in prega.iter_mut().enumerate() {
            let mut acc = Val::ZERO;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        acc += g(layout.preg + i) * g(fa_off + j);
                    } else if i + j == k + 4 {
                        acc += w_ext * g(layout.preg + i) * g(fa_off + j);
                    }
                }
            }
            *slot = acc;
        }
        let sf23 = g(23);
        let phc = g(layout.phc);
        let phq = g(layout.phq);
        let blklast = g(layout.blklast);
        let chlive = phc * (one - g(layout.refsel));
        let f2sel = g(ring(layout.fring, 8, 2)) * (one - g(layout.bidx));
        // Final obs flush index = 3 + n_fri_rounds (narrow 7, wide 6); the fring
        // ring width stays 8.
        let pg_a = g(ring(layout.fring, 8, flush_blocks.len() - 1))
            * g(ring(layout.grp, shape.n_groups(), shape.g_done()))
            * phc;
        let phg = sf23 * blklast * pg_a;
        let phdend = sf23 * g(layout.phd) * blklast;
        let cont = sf23 * phc * (one - blklast);
        let eg_a = phq * g(layout.qcw) * g(ring(layout.qsel, shape.nq + 1, shape.nq - 1));
        let endg = sf23 * eg_a;
        let mut xsel = g(layout.phd) * (one - g(layout.cmpc));
        for f in 0..flush_blocks.len() {
            if f == 2 {
                continue;
            }
            for b in 1..flush_blocks[f] {
                xsel += g(layout.shsel + shsel_index(&flush_blocks, f, b));
            }
        }
        let qadv = sf23 * phq * g(layout.qcw);
        let mut consumersel = g(layout.refsel);
        for f in 1..flush_blocks.len() {
            consumersel += g(layout.shsel + shsel_index(&flush_blocks, f, 0));
        }
        let cfull = sf23 * consumersel * (one - g(layout.fsfull));
        // row borrow ends; write the derived cells.
        let derived = [
            (layout.chlive, chlive),
            (layout.f2sel, f2sel),
            (layout.pg_a, pg_a),
            (layout.phg, phg),
            (layout.phdend, phdend),
            (layout.cont, cont),
            (layout.eg_a, eg_a),
            (layout.endg, endg),
            (layout.xsel, xsel),
            (layout.qadv, qadv),
            (layout.cfull, cfull),
            (layout.dmux, dmux),
        ];
        for (col, val) in derived {
            values[base + col] = val;
        }
        for a in 0..8 {
            values[base + layout.m3 + a] = m3[a];
        }
        for j in 0..4 {
            values[base + layout.rlo + j] = rlo[j];
            values[base + layout.rhi + j] = rhi[j];
        }
        // SNL_rf = layout.msel[M_S0+rf] * (1 - sf(lfs[rf])).
        for rf in 0..shape.n_fri_rounds() {
            let msel = values[base + layout.msel + shape.m_s(rf) as usize];
            values[base + layout.snl + rf] = msel * (Val::ONE - values[base + lfs[rf]]);
        }
        for j in 0..4 {
            values[base + layout.glo + j] = glo[j];
            values[base + layout.ghi + j] = ghi[j];
            values[base + layout.gf + j] = gf[j];
            values[base + layout.bpm + j] = bpm[j];
        }
        for (f, &val) in fhg.iter().enumerate() {
            values[base + layout.fhg + f] = val;
        }
        for k in 0..4 {
            values[base + layout.prega + k] = prega[k];
        }
        values[base + layout.cpa] = values[base + layout.phd] * values[base + layout.cmpa];
        values[base + layout.cpb] = values[base + layout.phd] * values[base + layout.cmpb];
        values[base + layout.cpl] = values[base + layout.phd] * values[base + layout.blklast];
        values[base + layout.consz7] = values[base + layout.cz7] * values[base + layout.pos + 1];
        // 2d: cc[j] = chi·caps8[j] (cap-half select). chi is pre-filled by the
        // trace builder (0 for single-child / child L, 1 for child R); narrow → 0.
        let chi_v = values[base + layout.chi];
        for j in 0..shape.cap_len {
            values[base + layout.cc + j] = chi_v * values[base + layout.caps8 + j];
        }
    }

    // 2b-iii: materialize the fring-rotation gate (frgm = sf(23)·b0next) and the
    // blkcnt update delta (bcbd) — both next-row-dependent (b0next / nv(shsel),
    // nv(refsel)) — so their (1-csel_next)-gated carries stay ≤ deg 3. The last
    // row has no successor (its transition constraints are inactive) → leave 0.
    for r in 0..rows.saturating_sub(1) {
        let cur = r * w;
        let nxt = (r + 1) * w;
        let sf23 = values[cur + 23];
        let mut b0n = Val::ZERO;
        for f in 1..flush_blocks.len() {
            b0n += values[nxt + layout.shsel + shsel_index(&flush_blocks, f, 0)];
        }
        values[cur + layout.frgm] = sf23 * b0n;
        let blkcnt = values[cur + layout.blkcnt];
        let mut reload = Val::ZERO;
        for f in 1..flush_blocks.len() {
            reload += values[nxt + layout.shsel + shsel_index(&flush_blocks, f, 0)]
                * (Val::from_u32(flush_blocks[f] as u32) - blkcnt);
        }
        let dupdec = sf23 * values[cur + layout.phd] * (one - values[cur + layout.blklast]);
        values[cur + layout.bcbd] = sf23 * reload
            + sf23 * values[nxt + layout.refsel] * (one - blkcnt)
            - values[cur + layout.cont]
            - dupdec
            + values[cur + layout.phg] * (Val::from_u32(flush_blocks[2] as u32) - blkcnt);
        // 棒 3-2b: mcont = merge-continue chain gate = sf(23)·mreg·(1 − next mrst
        // − eq_end), where eq_end = meq[3] (root perm's last row → no forward chain).
        if shape.merge_lane {
            values[cur + layout.mcont] = sf23
                * values[cur + layout.mreg]
                * (one - values[nxt + layout.mrst] - values[cur + layout.meq + 3]);
        }
    }
}

// ---------------------------------------------------------------------------
// Bench mode: the calibration gate. Prove/verify the verifier gate rectangle
// on a REAL M3 consensus proof at the two house lane configs and report the
// leaf cost (prove ms / verify ms / proof KB) against aggregation-rung1 §6's
// <= 10 s / <= 32 GB leaf envelope. Peak RSS via `--only <cfg>` under
// /usr/bin/time -l (m4census RSS-attribution discipline).
// ---------------------------------------------------------------------------

// The two house lane configs, referenced directly from the shipping config
// consts (derive-not-hardcode) so this leaf bench always measures exactly the
// leaf-agg (AGG_CFG = b4/q43) and consensus (CONSENSUS_CFG = b16/q21) lanes —
// both g22 post-B′ (issue #22), queries bumped by B″ (issue #41). Labels are
// display-only.
const LANE_CFGS: [(&str, FriCfg); 2] = [
    ("b4/q43/g22/fp16/a16", crate::m4treerec::AGG_CFG),
    ("b16/q21/g22/fp16/a16", CONSENSUS_CFG),
];

pub(crate) fn run_m4gate(power: &str, only: Option<&str>) {
    use std::time::Instant;
    println!("# qumbra-lab M4 step 0b(ii): the calibration gate (verifier gate rectangle)");
    println!();
    crate::print_env(power);
    // Build the real M3 proof + recorder schedule once (shared across configs).
    let (_inst, pvs, proof) = m4gaterec::consensus_proof();
    let sched = m4gaterec::walk(&proof, &pvs);
    let n_perms = lane_plan(&sched, &GateShape::narrow()).0.len();
    println!(
        "- rectangle: {GATE_WIDTH} cols x 2^16, {n_perms} lane perms; proves-in-circuit \
         a REAL M3 consensus proof with every gate column bound (FS/draw schedule, \
         query program, ext-arith fold pipeline, and both fold-chain endpoints \
         value-pinned). Max constraint degree 3."
    );
    println!();
    println!("| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|---|");
    let air = VerifierGateAir::new();
    for (name, cfg) in &LANE_CFGS {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        let config = make_config_with(cfg);
        eprintln!("== m4gate: {name} ==");
        let mut rows = 0;
        let mut best_prove = f64::INFINITY;
        let mut proof_opt = None;
        let mut opvs = Vec::new();
        for _ in 0..RUNS {
            let (trace, meta) = build_gate_trace(&sched, &pvs, &GateShape::narrow(), cfg.log_blowup);
            rows = trace.height();
            opvs = meta.opvs.clone();
            let t = Instant::now();
            let p = prove(&config, &air, trace, &opvs);
            best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
            proof_opt = Some(p);
        }
        let proof = proof_opt.expect("RUNS > 0");
        let postcard_bytes = pc_len(&proof);
        let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
        let mut best_verify = f64::INFINITY;
        for _ in 0..RUNS {
            let t = Instant::now();
            verify(&config, &air, &proof, &opvs).expect("verify");
            best_verify = best_verify.min(t.elapsed().as_secs_f64() * 1e3);
        }
        println!(
            "| {name} | {rows} | {best_prove:.0} | {best_verify:.1} | {:.1} | {:.1} |",
            postcard_bytes as f64 / 1024.0,
            fixed_bytes as f64 / 1024.0,
        );
    }
    println!();
    println!(
        "Peak RSS: rerun one config under /usr/bin/time -l with --only <cfg>. \
         The gate proves a real M3 transcript with all columns bound (corrupted \
         witness fails -- see the m4gate unit tests, incl. 4 gate-exit negatives \
         and the endpoint-pin negatives); compare prove ms / peak RSS to \
         aggregation-rung1 §6's <= 10 s / <= 32 GB leaf envelope."
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use p3_air::check_constraints;

    use super::*;
    use crate::m4gaterec::{consensus_proof, walk};

    pub(crate) fn shared() -> &'static (Schedule, Vec<Val>, Vec<Ext>) {
        static CELL: OnceLock<(Schedule, Vec<Val>, Vec<Ext>)> = OnceLock::new();
        CELL.get_or_init(|| {
            let (_inst, pvs, proof) = consensus_proof();
            let sched = walk(&proof, &pvs);
            let tl = proof.opened_values.trace_local.clone();
            (sched, pvs, tl)
        })
    }

    /// Wide analogue of `shared()`: cache the interior child's leaf-proof
    /// verification schedule + its opvs once (the ~12 GB leaf `prove` runs a
    /// single time; only the small `Schedule` + opvs are retained). Used by the
    /// wide SAT + negative tests so each re-uses one leaf proof.
    pub(crate) fn wide_shared() -> &'static (Schedule, Vec<Val>) {
        static CELL: OnceLock<(Schedule, Vec<Val>)> = OnceLock::new();
        CELL.get_or_init(|| {
            let (leaf, opvs) = crate::m4treerec::leaf_proof();
            let sched = crate::m4treerec::walk_leaf(&leaf, &opvs);
            (sched, opvs)
        })
    }

    /// Cache the DISTINCT two-child pair (child L = leaf_proof, child R =
    /// leaf_proof_variant) once — both ~12 GB leaf proves run a single time,
    /// only the two small Schedules + opvs are retained. Shared by the distinct
    /// SAT + per-child negative tests (2d-3/2d-4).
    pub(crate) fn wide_shared_distinct() -> &'static (Schedule, Schedule, Vec<Val>, Vec<Val>) {
        static CELL: OnceLock<(Schedule, Schedule, Vec<Val>, Vec<Val>)> = OnceLock::new();
        CELL.get_or_init(|| crate::m4interior::two_child_schedule(true))
    }

    /// B″ (issue #41) FIT-CHECK 1 — the leaf gate rectangle must still fit 2^16
    /// after consensus q20 → q21 (the "+5% consensus-schedule growth"). Measures
    /// the ACTUAL lane-perm count of the narrow gate verifying a q21 M3 proof and
    /// asserts the rectangle stays 2^16. If this fails, STOP and report — do NOT
    /// silently promote the leaf to 2^17 (that is a design-side decision).
    /// Cheap: reuses `shared()`'s one consensus prove; no leaf prove.
    #[test]
    fn b2prime_fitcheck_leaf_2p16() {
        let (sched, _pvs, _tl) = shared();
        let n_perms = lane_plan(sched, &GateShape::narrow()).0.len();
        let rows = (n_perms * 24).next_power_of_two();
        let cap = 1usize << 16;
        let occ = (n_perms * 24) as f64 / cap as f64 * 100.0;
        eprintln!(
            "FIT-CHECK 1 (leaf @ consensus q{}): {} lane perms → {} used rows → rectangle 2^{} \
             (cap 2^16 = {}); occupancy {:.1}% of 2^16",
            GateShape::narrow().nq,
            n_perms,
            n_perms * 24,
            rows.trailing_zeros(),
            cap,
            occ
        );
        assert!(
            rows <= cap,
            "FIT-CHECK 1 FAILED: leaf overflows 2^16 ({} perms × 24 = {} rows → 2^{}). \
             STOP — do not promote to 2^17; report to coordinator (design decision).",
            n_perms,
            n_perms * 24,
            rows.trailing_zeros()
        );
    }

    /// B″ (issue #41) FIT-CHECK 2 — the two-child interior rectangle must still
    /// fit 2^19 after leaf q40 → q43 (the "+7.5% leaf-opening growth": q43 ×
    /// 7,260-value rows + the leaf gate's +3 cols from consensus q21 widening
    /// `wide().tw = GATE_WIDTH`). Measures the ACTUAL interior trace height from
    /// two DISTINCT q43 leaf schedules. If it overflows 2^19, STOP and report —
    /// do NOT silently promote to 2^20. Heavy: two ~12 GB leaf proves (cached).
    #[test]
    fn b2prime_fitcheck_interior_2p19() {
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        // Mirror build_interior_trace's real/rows computation exactly, but from
        // child_derived + merge_perm_inputs directly — this gives the USED perm
        // count (the true occupancy) without the ~7.7 GB full-trace allocation.
        let nl = child_derived(sl, &shape).inputs.len();
        let nr = child_derived(sr, &shape).inputs.len();
        let nm = crate::m4interior::merge_perm_inputs(ol, or).len();
        let real = nl + nr + nm;
        let rows = (real * 24).next_power_of_two();
        let cap = 1usize << 19;
        let occ = (real * 24) as f64 / cap as f64 * 100.0;
        eprintln!(
            "FIT-CHECK 2 (interior @ leaf q{}, leaf width {} cols): {} used perms \
             (childL {} + childR {} + merge {}) → {} used rows → rectangle 2^{} \
             (cap 2^19 = {}); occupancy {:.1}% of 2^19",
            shape.nq,
            GATE_WIDTH,
            real,
            nl,
            nr,
            nm,
            real * 24,
            rows.trailing_zeros(),
            cap,
            occ
        );
        assert!(
            rows <= cap,
            "FIT-CHECK 2 FAILED: interior overflows 2^19 ({} perms × 24 = {} rows → 2^{}). \
             STOP — do not promote to 2^20; report to coordinator (design decision).",
            real,
            real * 24,
            rows.trailing_zeros()
        );
    }

    /// Wide analogue of `is_unsat`: check the mutated wide trace against the
    /// `wide()`-shaped AIR in a spawned thread (panic == UNSAT == caught).
    fn is_unsat_wide(trace: RowMajorMatrix<Val>, opvs: Vec<Val>) -> bool {
        std::thread::spawn(move || {
            check_constraints(&VerifierGateAir::new_with_shape(GateShape::wide()), &trace, &opvs);
        })
        .join()
        .is_err()
    }

    /// `is_unsat_wide` against the interior AIR (`new_interior()`: doubled opvs
    /// + per-child routing). Used by the two-child per-lane negatives (2d-4).
    fn is_unsat_interior(trace: RowMajorMatrix<Val>, opvs: Vec<Val>) -> bool {
        std::thread::spawn(move || {
            check_constraints(&VerifierGateAir::new_interior(), &trace, &opvs);
        })
        .join()
        .is_err()
    }

    /// M4 step 1 stage 2, slice 1a-i: `GateShape::narrow()` must reproduce the
    /// shipped leaf gate's const block byte-for-byte, and `wide()` must carry
    /// the interior target shape from `m4treerec` / the stage-1 run doc. This
    /// pins the narrow->wide parameter mapping before any `eval` rewiring, so a
    /// later slice can migrate the column-offset chain against a verified shape.
    #[test]
    fn gate_shape_narrow_reproduces_consts() {
        let n = GateShape::narrow();
        // Narrow scalars == the const block.
        assert_eq!(n.tw, TW);
        assert_eq!(n.qw, QW);
        assert_eq!(n.n_pvs, N_PVS);
        assert_eq!(n.nq, NQ);
        assert_eq!(n.log_max, LOG_MAX);
        assert_eq!(n.grind_bits, GRIND_BITS);
        assert_eq!(n.cap_len, CAP_LEN);
        assert_eq!(n.log_arities, LOG_ARITIES.to_vec());
        // Narrow derived quantities == the const arrays/scalars.
        assert_eq!(n.n_caps(), N_CAPS);
        assert_eq!(n.cap_height(), 3);
        assert_eq!(n.cum(), CUM.to_vec());
        assert_eq!(n.path_levels(), PATH_LEVELS.to_vec());

        // Wide interior target (from m4treerec::AGG_CFG + stage-1 run doc).
        // tw = the leaf's committed width = GATE_WIDTH (3626 base + gate columns
        // added since: csel etc.), derived so column additions auto-track.
        let w = GateShape::wide();
        assert_eq!(w.tw, GATE_WIDTH, "leaf wide row width = leaf gate width");
        assert_eq!(w.qw, 8, "leaf wide quotient words/query");
        assert_eq!(w.n_pvs, N_OPVS, "interior inner PVs = leaf gate opvs");
        // D3 (issue #24): the leaf's public surface gained the 16-limb F0 digest
        // between the caps and the inner PVs → 852 → 868. This is the ONE place
        // the narrow-byte-identical invariant is deliberately broken.
        assert_eq!(w.n_pvs, 6 * 8 * 16 + F0DIG_LIMBS + 84, "= 868 (was 852 pre-D3)");
        assert_eq!(w.nq, crate::m4treerec::AGG_CFG.num_queries, "aggregation lane queries (q43 post-B″)");
        assert_eq!(w.log_max, 18, "leaf 2^16 committed at b4 -> LDE 2^18");
        assert_eq!(w.log_arities, vec![4, 4, 4], "3 arity-16 FRI rounds");
        assert_eq!(w.n_caps(), 5, "trace + quotient + 3 FRI");
        assert_eq!(w.path_levels(), vec![15, 15, 11, 7, 3], "wide native path levels");
    }

    /// Slice 1a-i-b: `GateLayout::from_shape(&narrow())` must reproduce every
    /// column-offset `const` byte-for-byte, so slice 1a-ii can mechanically
    /// replace `const X` reads in `eval` with `layout.x` with confidence.
    #[test]
    fn gate_layout_narrow_reproduces_consts() {
        let l = GateLayout::from_shape(&GateShape::narrow());
        assert_eq!(l.mul_off, MUL_OFF);
        assert_eq!(l.add_off, ADD_OFF);
        assert_eq!(l.gb, GB);
        assert_eq!(l.w0c, W0C);
        assert_eq!(l.w1c, W1C);
        assert_eq!(l.hb0, HB0);
        assert_eq!(l.hb1, HB1);
        assert_eq!(l.ta0, TA0);
        assert_eq!(l.topa0, TOPA0);
        assert_eq!(l.ta1, TA1);
        assert_eq!(l.topa1, TOPA1);
        assert_eq!(l.lbnz0, LBNZ0);
        assert_eq!(l.lbi0, LBI0);
        assert_eq!(l.lonz0, LONZ0);
        assert_eq!(l.loi0, LOI0);
        assert_eq!(l.lbnz1, LBNZ1);
        assert_eq!(l.lbi1, LBI1);
        assert_eq!(l.lonz1, LONZ1);
        assert_eq!(l.loi1, LOI1);
        assert_eq!(l.oreg, OREG);
        assert_eq!(l.pbit, PBIT);
        assert_eq!(l.obit, OBIT);
        assert_eq!(l.fsbits, FSBITS);
        assert_eq!(l.fsacc, FSACC);
        assert_eq!(l.fsp3a, FSP3A);
        assert_eq!(l.fsp3b, FSP3B);
        assert_eq!(l.fst7, FST7);
        assert_eq!(l.fsinv, FSINV);
        assert_eq!(l.fsnz, FSNZ);
        assert_eq!(l.fsaccept, FSACCEPT);
        assert_eq!(l.fsgate, FSGATE);
        assert_eq!(l.fsodd, FSODD);
        assert_eq!(l.fsfull, FSFULL);
        assert_eq!(l.grp, GRP);
        assert_eq!(l.coef, COEF);
        assert_eq!(l.curch, CURCH);
        assert_eq!(l.crot, CROT);
        assert_eq!(l.grot, GROT);
        assert_eq!(l.chal, CHAL);
        assert_eq!(l.fa2, FA2);
        assert_eq!(l.znreg, ZNREG);
        assert_eq!(l.idxr, IDXR);
        assert_eq!(l.fring, FRING);
        assert_eq!(l.blkcnt, BLKCNT);
        assert_eq!(l.blklast, BLKLAST);
        assert_eq!(l.blkinv, BLKINV);
        assert_eq!(l.bidx, BIDX);
        assert_eq!(l.bidx_width, 6, "narrow bidx one-hot width");
        assert_eq!(l.cmpa, CMPA);
        assert_eq!(l.cmpai, CMPAI);
        assert_eq!(l.cmpb, CMPB);
        assert_eq!(l.cmpbi, CMPBI);
        assert_eq!(l.needl, NEEDL);
        assert_eq!(l.refsel, REFSEL);
        assert_eq!(l.shsel, SHSEL);
        assert_eq!(l.phc, PHC);
        assert_eq!(l.phq, PHQ);
        assert_eq!(l.qsel, QSEL);
        assert_eq!(l.qcnt, QCNT);
        assert_eq!(l.qcw, QCW);
        assert_eq!(l.qcwi, QCWI);
        assert_eq!(l.pr, PR);
        assert_eq!(l.pd, PD);
        assert_eq!(l.rsel, RSEL);
        assert_eq!(l.mlo, MLO);
        assert_eq!(l.mhi, MHI);
        assert_eq!(l.msel, MSEL);
        assert_eq!(l.dlo, DLO);
        assert_eq!(l.dhi, DHI);
        assert_eq!(l.drnd, DRND);
        assert_eq!(l.dbit, DBIT);
        assert_eq!(l.glc, GLC);
        assert_eq!(l.grc, GRC);
        assert_eq!(l.caps8, CAPS8);
        assert_eq!(l.idxb, IDXB);
        assert_eq!(l.cz2, CZ2);
        assert_eq!(l.cz7, CZ7);
        assert_eq!(l.cf, CF);
        assert_eq!(l.cx0, CX0);
        assert_eq!(l.cx1, CX1);
        assert_eq!(l.pos, POS);
        assert_eq!(l.consz, CONSZ);
        assert_eq!(l.consf, CONSF);
        assert_eq!(l.asm0, ASM0);
        assert_eq!(l.asm1, ASM1);
        assert_eq!(l.vc, VC);
        assert_eq!(l.vce, VCE);
        assert_eq!(l.pbuf, PBUF);
        assert_eq!(l.hit, HIT);
        assert_eq!(l.gpb, GPB);
        assert_eq!(l.lfs, LFS);
        assert_eq!(l.preg, PREG);
        assert_eq!(l.pzacc, PZACC);
        assert_eq!(l.a0r, A0R);
        assert_eq!(l.a1r, A1R);
        assert_eq!(l.a2r, A2R);
        assert_eq!(l.p0r, P0R);
        assert_eq!(l.p1r, P1R);
        assert_eq!(l.px0r, PX0R);
        assert_eq!(l.fpreg, FPREG);
        assert_eq!(l.scr, SCR);
        assert_eq!(l.breg, BREG);
        assert_eq!(l.inv2s, INV2S);
        assert_eq!(l.invz, INVZ);
        assert_eq!(l.invzn, INVZN);
        assert_eq!(l.xreg, XREG);
        assert_eq!(l.xfin, XFIN);
        assert_eq!(l.runev, RUNEV);
        assert_eq!(l.f2dig, F2DIG);
        assert_eq!(l.phd, PHD);
        assert_eq!(l.cmpc, CMPC);
        assert_eq!(l.cmpci, CMPCI);
        assert_eq!(l.czd, CZD);
        assert_eq!(l.chlive, CHLIVE);
        assert_eq!(l.f2sel, F2SEL);
        assert_eq!(l.pg_a, PG_A);
        assert_eq!(l.phg, PHG);
        assert_eq!(l.phdend, PHDEND);
        assert_eq!(l.cont, CONT);
        assert_eq!(l.eg_a, EG_A);
        assert_eq!(l.endg, ENDG);
        assert_eq!(l.xsel, XSEL);
        assert_eq!(l.qadv, QADV);
        assert_eq!(l.cfull, CFULL);
        assert_eq!(l.m3, M3);
        assert_eq!(l.rlo, RLO);
        assert_eq!(l.rhi, RHI);
        assert_eq!(l.dmux, DMUX);
        assert_eq!(l.snl, SNL);
        assert_eq!(l.glo, GLO);
        assert_eq!(l.ghi, GHI);
        assert_eq!(l.gf, GF);
        assert_eq!(l.bpm, BPM);
        assert_eq!(l.n_fhg, N_FHG);
        assert_eq!(l.fhg, FHG);
        assert_eq!(l.prega, PREGA);
        assert_eq!(l.cpa, CPA);
        assert_eq!(l.cpb, CPB);
        assert_eq!(l.cpl, CPL);
        assert_eq!(l.consz7, CONSZ7);
        assert_eq!(l.fpi, FPI);
        assert_eq!(l.csel, CSEL);
        assert_eq!(l.frgm, FRGM);
        assert_eq!(l.bcbd, BCBD);
        assert_eq!(l.chi, CHI);
        assert_eq!(l.cc, CC);
        assert_eq!(l.canon_lo0, CANON_LO0);
        assert_eq!(l.canon_lo1, CANON_LO1);
        assert_eq!(l.top7_0, TOP7_0);
        assert_eq!(l.top7_1, TOP7_1);
        assert_eq!(l.gate_cols, GATE_COLS);
        assert_eq!(l.gate_width, GATE_WIDTH);
    }

    /// Slice 1b-1: every shape-varying transcript/draw-schedule count derived by
    /// `GateShape` must reproduce its narrow module const — including the four
    /// (`N_CHALS`/`N_GROUPS`/`N_ROLES`/`N_MICROS`) that were wrongly assumed
    /// fixed. Pins the formulas before `from_shape` and the builders consume them.
    #[test]
    fn gate_shape_derived_counts_narrow() {
        let n = GateShape::narrow();
        assert_eq!(n.n_chals(), N_CHALS);
        assert_eq!(n.n_groups(), N_GROUPS);
        assert_eq!(n.g_pow(), G_POW);
        assert_eq!(n.g_idx0(), G_IDX0);
        assert_eq!(n.g_done(), G_DONE);
        assert_eq!(n.n_roles(), N_ROLES);
        assert_eq!(n.n_micros(), N_MICROS);
        assert_eq!(n.n_flush_entries(), N_FLUSH_ENTRIES);
        assert_eq!(n.n_fhg(), N_FHG);
        assert_eq!(n.drnd_width(), 6);
        assert_eq!(n.flush_bytes(), FLUSH_BYTES.to_vec());
        assert_eq!(n.flush_blocks(), FLUSH_BLOCKS.to_vec());
        assert_eq!(n.n_shapes_obs(), N_SHAPES_OBS);
        assert_eq!(n.qslots(), QSLOTS);
    }

    /// Slice 1b-1: the wide-shape counts match the derived + empirically
    /// confirmed values in `docs/m4-1b-wide-params-investigation.md` (one leaf
    /// prove, 11.88 GB). These drive the interior verifier's layout.
    #[test]
    fn gate_shape_wide_values() {
        let w = GateShape::wide();
        assert_eq!(w.n_fri_rounds(), 3);
        assert_eq!(w.n_chals(), 6);
        assert_eq!(w.n_groups(), 51); // 5 + 3 + 43 (B″ q43; was 48 at q40)
        assert_eq!(w.g_pow(), 6);
        assert_eq!(w.g_idx0(), 7);
        assert_eq!(w.g_done(), 50); // g_idx0 + nq = 7 + 43 (was 47 at q40)
        assert_eq!(w.n_roles(), 12);
        assert_eq!(w.n_micros(), 15);
        assert_eq!(w.n_flush_entries(), 8);
        assert_eq!(w.n_fhg(), 21);
        assert_eq!(w.drnd_width(), 5);
        // F2 = 32 + 16·(2·tw + qw); tw = GATE_WIDTH (3675 = 3672 + B″'s +3 narrow
        // cols from consensus q21: GRP/IDXR/QSEL each +1) → 32 + 16·(2·3675+8) =
        // 117760. All other flushes are tw- and nq-independent (query index draws
        // are sample_bits, not observations, so nq does not touch flush bytes).
        // F0 = 12 + cap·32 + n_pvs·4; D3 (issue #24) raised the interior's inner
        // PV count 852 → 868 (the child leaf's opvs gained the 16-limb f0dig), so
        // F0 grows 3676 → 3740 bytes. F2 is UNCHANGED because D3 added no gate
        // columns (tw = GATE_WIDTH = 3675 either side).
        assert_eq!(w.flush_bytes(), vec![3740, 288, 117760, 288, 288, 288, 304]);
        // F2 blocks = 117760/136 + 1 = 866 (unchanged from tw=3672: +96 bytes is
        // under one 136-byte keccak block). F0 blocks stay 28 as well: 3740/136
        // = 27.5 → 27+1, same as 3676/136 = 27.03 → 27+1 (the +64 bytes do not
        // cross the 27→28 boundary at 3672 bytes).
        assert_eq!(w.flush_blocks(), vec![28, 3, 866, 3, 3, 3, 3]);
        assert_eq!(w.n_shapes_obs(), 46);
        // qslots = ceil34(tw) + pl0 + ceil34(qw) + pl1; tw=3675 makes
        // ceil34(3675)=109 (was 108 at 3672) → one more trace-leaf absorb slot.
        assert_eq!(w.qslots(), 167);
        assert_eq!(w.bidx_width(), 29, "wide F0=28 blocks → bidx must address all + 1 sink");
    }

    /// Issue #24 (D3): the public-surface cascade, test-locked end to end.
    ///
    /// Exposing `f0dig` grows the leaf's outer PVs, which ARE the interior's
    /// inner PVs (`m4gate.rs`'s `wide()`: `n_pvs: N_OPVS`), so the change walks
    /// leaf → interior → merge lane. This test pins every link of that chain
    /// (and, just as importantly, the links that did NOT move) so a later shape
    /// change cannot silently re-cross a keccak-block boundary.
    ///
    /// before → after:
    ///   N_PVS (M3 inner PVs)      84   →   84   (D3 does not touch the M3 proof)
    ///   OPV_F0DIG (narrow)         –   →  768   (new: caps end)
    ///   OPV_PVS (narrow)         768   →  784   (+F0DIG_LIMBS)
    ///   N_OPVS (narrow)          852   →  868
    ///   GATE_WIDTH              3675   → 3675   (no new columns)
    ///   interior n_pvs           852   →  868   (= the leaf's N_OPVS)
    ///   interior n_opvs         1492   → 1524   (5·8·16 + 16 + 868)
    ///   merge_perms()             53   →   53   (see the arithmetic below)
    ///   msh ring width            53   →   53
    ///   interior num_public_values 3004 → 3068  (2·n_opvs + 16 root + 4 Σfee)
    #[test]
    fn d3_public_surface_cascade() {
        let n = GateShape::narrow();
        let w = GateShape::wide();
        // -- leaf --
        assert_eq!(n.n_pvs, 84, "M3 inner PV count is untouched by D3");
        assert_eq!(n.opv_f0dig(), 6 * 8 * 16, "f0dig sits at the end of the caps: 768");
        assert_eq!(n.opv_pvs(), 768 + 16, "inner PVs start after the f0dig block: 784");
        assert_eq!(n.n_opvs(), 868, "leaf public surface 852 → 868");
        assert_eq!((OPV_F0DIG, OPV_PVS, N_OPVS), (768, 784, 868), "consts track the shape");
        assert_eq!(GATE_WIDTH, 3675, "D3 adds NO gate columns (f0dig needs no register)");
        // The Σfee rider's invariant: fee is still the opvs TAIL. This is why
        // f0dig is INSERTED before the inner PVs rather than appended — the
        // rider reads `opvs[n_opvs-EPOCH_FEE_LIMBS..]` and `m4interior`'s
        // const-assert only glues EPOCH_FEE_LIMBS to the M3 PV layout; it
        // cannot see the opvs tail, so an append would have moved the rider's
        // summands onto digest limbs silently. Structural half of the guard
        // (the value-level half is in `d3_f0dig_is_the_digest_of_the_public_surface`).
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        assert!(
            n.n_opvs() - fl >= n.opv_pvs() && n.n_opvs() <= n.opv_pvs() + n.n_pvs,
            "the opvs tail must lie inside the inner-PV block, not on f0dig limbs"
        );
        assert_eq!(n.opv_f0dig() + F0DIG_LIMBS, n.opv_pvs(), "f0dig precedes the inner PVs");
        // -- interior --
        assert_eq!(w.n_pvs, n.n_opvs(), "interior inner PVs = the leaf's opvs");
        assert_eq!(w.opv_f0dig(), 5 * 8 * 16, "wide has 5 caps → 640");
        assert_eq!(w.n_opvs(), 5 * 8 * 16 + 16 + 868, "= 1524 (was 1492)");
        // -- merge lane: the block count is the boundary worth stating --
        // blocks = n_pvs·4/136 + 1 (overwrite sponge, pad10*1 always adds a byte)
        //   before: 852·4 = 3408 bytes → 3408/136 = 25 → 26 blocks
        //   after:  868·4 = 3472 bytes → 3472/136 = 25 → 26 blocks   (25.53 → 25)
        // merge_perms = 2·blocks + 1 → 2·26 + 1 = 53, unchanged. The next
        // boundary is at 3536 bytes (884 values); D3 lands 16 values short of it.
        // The interior's own rectangle width: n_pvs reaches the layout only via
        // `flush_blocks` (→ n_shapes_obs, bidx_width) and `merge_perms`, and all
        // three are unchanged, so the interior rectangle does NOT widen — the
        // load-bearing fact for the b2/q86 32 GB envelope (memory scales with
        // width × height; D3's cost is constraint-eval time, not footprint).
        // (Unchanged by inspection of `from_shape`: its only n_pvs-sensitive
        // inputs are exactly the three quantities asserted here, and all three
        // hold their pre-D3 values.)
        assert_eq!(GateLayout::from_shape(&w).gate_width, 3915, "interior width unchanged");
        assert_eq!(w.n_shapes_obs(), 46, "wide obs-shape count unchanged");
        assert_eq!(w.bidx_width(), 29, "wide block one-hot width unchanged");
        assert_eq!(w.n_pvs * 4, 3472, "merge message bytes per child");
        assert_eq!(w.n_pvs * 4 / 136 + 1, 26, "merge blocks per child (was 26)");
        assert_eq!(w.merge_perms(), 53, "msh ring width unchanged");
        assert_eq!(
            w.merge_perms(),
            crate::m4interior::merge_perm_inputs(
                &vec![Val::ZERO; w.n_pvs],
                &vec![Val::ZERO; w.n_pvs]
            )
            .len(),
            "circuit merge_perms() == the native merge perm count"
        );
        // -- the interior AIR's public-value count --
        assert_eq!(
            <VerifierGateAir as BaseAir<Val>>::num_public_values(&VerifierGateAir::new_interior()),
            2 * w.n_opvs()
                + crate::m4interior::MERGE_ROOT_LIMBS
                + crate::m4interior::EPOCH_FEE_LIMBS,
        );
        assert_eq!(
            <VerifierGateAir as BaseAir<Val>>::num_public_values(&VerifierGateAir::new_interior()),
            3068,
            "interior public values 3004 → 3068"
        );
        assert_eq!(
            <VerifierGateAir as BaseAir<Val>>::num_public_values(&VerifierGateAir::new()),
            868,
            "leaf public values 852 → 868"
        );
    }

    /// TEMP: byte-parse cross-check of the zeta-opening obs stream.
    #[test]
    fn probe_zval_parse() {
        let (sched, _, tl) = shared();
        let bytes = &sched
            .obs
            .iter()
            .find(|o| o.label == m4gaterec::ObsLabel::ZetaVals { group: 0 })
            .unwrap()
            .bytes;
        for k in 0..2 {
            let c = &bytes[16 * k..16 * k + 16];
            let raw: Vec<u32> = (0..4)
                .map(|i| u32::from_le_bytes(c[4 * i..4 * i + 4].try_into().unwrap()))
                .collect();
            let tls: &[Val] = tl[k].as_basis_coefficients_slice();
            let tlc: Vec<u32> = tls.iter().map(|x| x.to_unique_u32()).collect();
            let rt: Vec<u32> = raw
                .iter()
                .map(|x| Val::from_u32(*x).to_unique_u32())
                .collect();
            eprintln!("value {k}: obs u32s {raw:?}");
            eprintln!("value {k}: tl  u32s {tlc:?}");
            eprintln!("value {k}: roundtrip {rt:?}");
        }
        // And the whole group-0 sum three ways.
        let fa = sched.fri_alpha;
        let mut acc = Ext::ZERO;
        let mut pow = Ext::ONE;
        for v in tl.iter() {
            acc += pow * *v;
            pow *= fa;
        }
        eprintln!("sum over trace_local == pz0: {}", acc == sched.pz[0]);
        eprintln!("trace_local len {}", tl.len());
    }

    /// The lowering runs against the real schedule: every internal
    /// self-check (challenge captures, PZ running-sum identity, micro
    /// chains, fold outputs, digest transport, ring alignment) fires
    /// during the build.
    #[test]
    fn gate_lowering_builds() {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let (trace, meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
        assert_eq!(trace.height(), 1 << 16);
        assert_eq!(meta.query_rows.len(), NQ);
        eprintln!(
            "gate rectangle: {} cols x {} rows, {} lane perms",
            trace.width(),
            trace.height(),
            meta.n_perms
        );
    }

    /// Guard the deg-3 house rule (PR #18 review soft spot): the calibration
    /// bench and quotient sizing assume every constraint is degree <= 3. A
    /// silent regression above 3 would misconfigure the prover, so assert it
    /// here permanently rather than only printing it in `dump_constraint`.
    #[test]
    fn constraint_degree_within_budget() {
        use p3_air::symbolic::{get_symbolic_constraints, AirLayout};
        // Both the leaf/narrow AIR and the 2d interior AIR (per-child opvs
        // routing enabled: the deg-3 cap-half mux + deg-2 chi/cc pins) must
        // stay within the deg-3 house rule.
        for (name, air) in [
            ("narrow", VerifierGateAir::new()),
            ("interior", VerifierGateAir::new_interior()),
        ] {
            let layout = AirLayout::from_air::<Val>(&air);
            let cs = get_symbolic_constraints::<Val, _>(&air, layout);
            let max = cs.iter().map(|c| c.degree_multiple()).max().unwrap_or(0);
            assert!(
                max <= 3,
                "{name} verifier gate AIR max constraint degree {max} > 3 (deg-3 \
                 house rule — the bench quotient sizing assumes it; see dump_constraint)"
            );
        }
    }

    /// AUDIT (issue #24 D3 side-find, coordinator-requested): enumerate the
    /// "soft surface" — columns the trace builder WRITES but no constraint ever
    /// READS. Those are exactly the cells a malicious prover is free to choose,
    /// so a filled-but-unreferenced column is either dead weight or a hole.
    ///
    /// D3 exists because four of them (`w0c`/`w1c`/`pbit`/`obit`) had been
    /// filled since inc-4 and referenced by nothing. This test answers "are
    /// there others?" cheaply and permanently:
    ///   - READ set: walk every symbolic constraint's expression DAG and collect
    ///     every main-trace column index (current- and next-row entries).
    ///   - WRITTEN set: build the honest narrow trace and mark every column with
    ///     a nonzero cell. (A column written only zeros is indistinguishable
    ///     from an untouched one and is not a degree of freedom in practice —
    ///     noted as the one gap in this method.)
    /// Diagnostic, not a gate: it PRINTS the list. Turning it into an assertion
    /// is the follow-up audit issue's call, not D3's.
    #[test]
    fn d3_audit_filled_but_unconstrained_columns() {
        use p3_air::symbolic::{
            get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicExpression,
        };
        use std::collections::BTreeSet;
        fn walk(e: &SymbolicExpression<Val>, seen: &mut BTreeSet<usize>) {
            use p3_air::symbolic::SymbolicExpr::*;
            match e {
                Leaf(BaseLeaf::Variable(v)) => {
                    if matches!(v.entry, BaseEntry::Main { .. }) {
                        seen.insert(v.index);
                    }
                }
                Leaf(_) => {}
                Add { x, y, .. } | Sub { x, y, .. } | Mul { x, y, .. } => {
                    walk(x, seen);
                    walk(y, seen);
                }
                Neg { x, .. } => walk(x, seen),
            }
        }
        let air = VerifierGateAir::new();
        let layout = AirLayout::from_air::<Val>(&air);
        let mut read = BTreeSet::new();
        for c in get_symbolic_constraints::<Val, _>(&air, layout) {
            walk(&c, &mut read);
        }
        let (sched, pvs, _) = shared();
        let (trace, _meta) = {
            let _g = heavy_lock();
            build_gate_trace(sched, pvs, &GateShape::narrow(), 0)
        };
        let w = GATE_WIDTH;
        let mut written = vec![false; w];
        for row in 0..trace.height() {
            for cidx in 0..w {
                if trace.values[row * w + cidx] != Val::ZERO {
                    written[cidx] = true;
                }
            }
        }
        let soft: Vec<usize> = (0..w).filter(|c| written[*c] && !read.contains(c)).collect();
        let dead: Vec<usize> = (0..w).filter(|c| !written[*c] && !read.contains(c)).collect();
        eprintln!(
            "column audit (narrow, {w} cols): {} read by constraints, {} written nonzero",
            read.len(),
            written.iter().filter(|x| **x).count()
        );
        eprintln!("FILLED BUT UNCONSTRAINED ({}): ", soft.len());
        let mut runs: Vec<(usize, usize, &str)> = vec![];
        for &cidx in &soft {
            match runs.last_mut() {
                Some(last) if last.1 + 1 == cidx && last.2 == colname(cidx) => last.1 = cidx,
                _ => runs.push((cidx, cidx, colname(cidx))),
            }
        }
        for (a, b, nm) in &runs {
            eprintln!("  {a}..={b} ({}) in region {nm}", b - a + 1);
        }
        eprintln!("neither written nor read ({}):", dead.len());
        for &cidx in &dead {
            eprintln!("  {cidx} in region {}", colname(cidx));
        }
        // Written-all-zero columns: read by a constraint but never carrying
        // data. Listed for completeness — they are not a degree of freedom.
        let zeroed: Vec<usize> = (0..w).filter(|c| !written[*c] && read.contains(c)).collect();
        eprintln!("written-all-zero but constrained ({}): {zeroed:?}", zeroed.len());
    }

    /// Diagnostic (relay debugging): dump a constraint's referenced columns
    /// by region name, and report the first gate-touching constraint index.
    /// Set CIDX=<n> to target a specific constraint (default 4135).
    #[test]
    fn dump_constraint() {
        use p3_air::symbolic::{
            get_symbolic_constraints, AirLayout, BaseEntry, BaseLeaf, SymbolicExpression,
        };
        use std::collections::BTreeSet;
        // WIDE=1 inspects the interior (wide) AIR's constraints — indices differ
        // from narrow because eval loop bounds are shape-driven; used to
        // diagnose the 1b-B* peel-the-onion wide check_constraints failures.
        let shape = if std::env::var("WIDE").is_ok() {
            let s = GateShape::wide();
            eprintln!("WIDE GateLayout = {:?}", GateLayout::from_shape(&s));
            s
        } else {
            GateShape::narrow()
        };
        let air = VerifierGateAir::new_with_shape(shape);
        let layout = AirLayout::from_air::<Val>(&air);
        let cs = get_symbolic_constraints::<Val, _>(&air, layout);
        let (argmax, maxdeg) = cs
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.degree_multiple()))
            .max_by_key(|&(_, d)| d)
            .unwrap();
        eprintln!("total constraints: {} | max degree: {maxdeg} at #{argmax}", cs.len());
        // Count constraints by degree.
        let mut hist = std::collections::BTreeMap::new();
        for c in &cs {
            *hist.entry(c.degree_multiple()).or_insert(0usize) += 1;
        }
        eprintln!("degree histogram: {hist:?}");
        fn collect(
            e: &SymbolicExpression<Val>,
            cur: &mut BTreeSet<usize>,
            nxt: &mut BTreeSet<usize>,
            flags: &mut BTreeSet<&'static str>,
        ) {
            use p3_air::symbolic::SymbolicExpr::*;
            match e {
                Leaf(l) => match l {
                    BaseLeaf::Variable(v) => match v.entry {
                        BaseEntry::Main { offset: 0 } => {
                            cur.insert(v.index);
                        }
                        BaseEntry::Main { .. } => {
                            nxt.insert(v.index);
                        }
                        BaseEntry::Public => {
                            flags.insert("PUB");
                        }
                        _ => {}
                    },
                    BaseLeaf::IsFirstRow => {
                        flags.insert("FIRST");
                    }
                    BaseLeaf::IsLastRow => {
                        flags.insert("LAST");
                    }
                    BaseLeaf::IsTransition => {
                        flags.insert("TRANS");
                    }
                    BaseLeaf::Constant(_) => {}
                },
                Add { x, y, .. } | Sub { x, y, .. } | Mul { x, y, .. } => {
                    collect(x, cur, nxt, flags);
                    collect(y, cur, nxt, flags);
                }
                Neg { x, .. } => collect(x, cur, nxt, flags),
            }
        }
        let target: usize = std::env::var("CIDX")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4135);
        for (i, c) in cs.iter().enumerate() {
            let (mut cur, mut nxt, mut fl) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
            collect(c, &mut cur, &mut nxt, &mut fl);
            if cur.iter().chain(nxt.iter()).any(|&x| x >= NUM_KECCAK_COLS) {
                eprintln!("first gate-touching constraint index: {i}");
                break;
            }
        }
        let c = &cs[target];
        let (mut cur, mut nxt, mut fl) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
        collect(c, &mut cur, &mut nxt, &mut fl);
        eprintln!(
            "constraint #{target}: deg={} flags={:?}\n  cur cols={:?}\n  nxt cols={:?}",
            c.degree_multiple(),
            fl,
            cur.iter().map(|&x| (x, colname(x))).collect::<Vec<_>>(),
            nxt.iter().map(|&x| (x, colname(x))).collect::<Vec<_>>(),
        );

        // Enumerate ALL deg>=4 constraints, collapsed by (deg, region-signature)
        // so the ~200 instances group into their few source expressions.
        let mut groups: std::collections::BTreeMap<(usize, String), (usize, usize)> =
            std::collections::BTreeMap::new();
        for (i, c) in cs.iter().enumerate() {
            let d = c.degree_multiple();
            if d < 4 {
                continue;
            }
            let (mut cur, mut nxt, mut fl) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
            collect(c, &mut cur, &mut nxt, &mut fl);
            let mut regs: BTreeSet<&'static str> = BTreeSet::new();
            for &x in cur.iter() {
                regs.insert(colname(x));
            }
            for &x in nxt.iter() {
                regs.insert(colname(x));
            }
            let sig = format!("{:?} flags={:?}", regs, fl);
            let e = groups.entry((d, sig)).or_insert((0, i));
            e.0 += 1;
        }
        eprintln!("--- deg>=4 constraint groups (deg, count, first_idx, regions) ---");
        for ((d, sig), (n, first)) in &groups {
            eprintln!("deg={d} count={n} first=#{first} {sig}");
        }
    }

    /// Diagnostic (relay debugging): dump the PZACC/PREG accumulator + its
    /// value-carry selectors around a target row (default 7727) to debug the
    /// endpoint-pin accumulation binding. Set DBGROW to move it.
    #[test]
    fn dump_accum() {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let (trace, _meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
        let w = trace.width();
        let val = &trace.values;
        let u = |row: usize, col: usize| -> u32 { val[row * w + col].to_unique_u32() };
        let target: usize = std::env::var("DBGROW").ok().and_then(|s| s.parse().ok()).unwrap_or(7727);
        eprintln!("row: CONSZ CX0 CX1 CONSF POS0 POS1 W0C W1C | PZACC0 PREG0 PREGA0");
        for row in target.saturating_sub(3)..=target + 2 {
            eprintln!(
                "{row}: {} {} {} {} {} {} {} {} | {} {} {}",
                u(row, CONSZ), u(row, CX0), u(row, CX1), u(row, CONSF),
                u(row, POS), u(row, POS + 1), u(row, W0C), u(row, W1C),
                u(row, PZACC), u(row, PREG), u(row, PREGA),
            );
        }
        eprintln!("row: MSEL_RO CF CONSF | SCR0 SCR1 SCR2 SCR3 SCR4 mulc0 addc0");
        for row in target.saturating_sub(3)..=target + 8 {
            eprintln!(
                "{row}: {} {} {} | {} {} {} {} {} {} {}",
                u(row, MSEL + M_RO as usize), u(row, CF), u(row, CONSF),
                u(row, SCR), u(row, SCR + 4), u(row, SCR + 8), u(row, SCR + 12),
                u(row, SCR + 16), u(row, MUL_OFF + 8), u(row, ADD_OFF + 8),
            );
        }
    }

    /// Diagnostic (relay debugging): dump the flush/draw-schedule columns at
    /// every challenger-phase last-block boundary, in logical (de-Monty'd)
    /// units, to eyeball the group-ring / flush-ring timing.
    #[test]
    fn dump_trace() {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let (_ins, infos) = lane_plan(sched, &GateShape::narrow());
        let (trace, _meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
        let w = trace.width();
        let val = trace.values;
        let at = |perm: usize, col: usize| -> u32 { val[(perm * 24 + 23) * w + col].to_unique_u32() };
        let one = Val::ONE.to_unique_u32();
        let ring_head = |perm: usize, base: usize, n: usize| -> i64 {
            (0..n).find(|&g| at(perm, base + g) == one).map(|g| g as i64).unwrap_or(-1)
        };
        let lb = |perm: usize, col: usize| -> u32 { (at(perm, col) == one) as u32 };
        let grp_logical = |perm: usize| -> i64 {
            let s = ring_head(perm, GRP, N_GROUPS);
            if s < 0 { -1 } else { (N_GROUPS as i64 - s) % N_GROUPS as i64 }
        };
        let fring_logical = |perm: usize| -> i64 {
            let s = ring_head(perm, FRING, 8);
            if s < 0 { -1 } else { (8 - s) % 8 }
        };
        eprintln!("LAST-BLOCK perms (challenger): perm info | grpL fringL NEEDL GROUPREQ[fL+1]");
        for perm in 0..340 {
            if lb(perm, BLKLAST) == 1 && lb(perm, REFSEL) == 0 {
                let fl = fring_logical(perm);
                let req = if fl >= 0 && (fl as usize + 1) < GROUPREQ.len() {
                    GROUPREQ[fl as usize + 1] as i64
                } else {
                    -99
                };
                eprintln!(
                    " {perm:3} {:24} | grp={:3} fring={:2} NEEDL={} REQ={}",
                    format!("{:?}", infos[perm]),
                    grp_logical(perm),
                    fl,
                    lb(perm, NEEDL),
                    req,
                );
            }
        }
    }

    /// Coverage probe (relay): tamper representative witness cells and
    /// report which are caught by the current constraint set. Not an
    /// assertion — it prints an UNSAT/SAT map so the report can state
    /// exactly which gate-exit negatives already bind and which await the
    /// ext-arithmetic pipeline.
    #[test]
    fn tamper_coverage() {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let air = VerifierGateAir::new();
        let one = Val::ONE;
        // (label, mutate) -> returns whether check_constraints panics (UNSAT).
        let _ = &air;
        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>, &mut Vec<Val>)| {
            let (mut trace, mut meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
            mutate(&mut trace, &mut meta.opvs);
            let unsat = is_unsat(trace, meta.opvs.clone());
            eprintln!("  [{}] {label}", if unsat { "UNSAT ok" } else { "SAT  MISS" });
        };
        let w = GATE_WIDTH;
        eprintln!("tamper coverage (UNSAT = caught, SAT = not bound):");
        // Neg2 wrong root: corrupt an outer public value (claimed inner cap).
        probe("wrong-root: flip all batch-0 cap limbs", &|_t, opvs| {
            for j in 0..CAP_LEN {
                opvs[cap_limb_opv(0, j, 0)] += one;
            }
        });
        // Neg1 tampered opening: flip a query trace-absorb preimage limb.
        probe("tampered-opening: flip query0 preimage limb 0", &|t, _o| {
            let (sched2, pvs2, _) = shared();
            let (_, m) = build_gate_trace(sched2, pvs2, &GateShape::narrow(), 0);
            let row = m.query_rows[0];
            t.values[row * w + pcol(0)] += one;
        });
        // Neg3 wrong challenge: flip a recorded accepted field draw cell.
        probe("wrong-challenge: flip an accepted field-draw FSACC", &|t, _o| {
            let (sched2, pvs2, _) = shared();
            let (_, m) = build_gate_trace(sched2, pvs2, &GateShape::narrow(), 0);
            let (row, _) = m.field_draws[0];
            t.values[row * w + FSACC] += one;
        });
        // Challenge register directly.
        probe("wrong-challenge: flip CHAL[0] (alpha limb0)", &|t, _o| {
            t.values[23 * w + CHAL] += one;
        });
        // Neg4 bad fold: corrupt a running-fold-eval limb.
        probe("bad-fold: flip RUNEV limb on a query row", &|t, _o| {
            let (sched2, pvs2, _) = shared();
            let (_, m) = build_gate_trace(sched2, pvs2, &GateShape::narrow(), 0);
            let row = m.query_rows[0];
            t.values[row * w + RUNEV] += one;
        });
        // Bank sanity: corrupt a mul-bank output (should be caught).
        probe("bank: flip MUL_OFF+8 (mul output c0)", &|t, _o| {
            t.values[23 * w + MUL_OFF + 8] += one;
        });
        // R2 scope probe: tamper an INNER public value (first inner PV, after the
        // cap limbs and the D3 f0dig block). SAT-MISS here was issue #21's R2
        // finding and issue #24 D3's reason to exist; both now read UNSAT and
        // are additionally locked as asserting negatives (`gate_neg_inner_pv_*`).
        probe("inner-pv: flip opvs[OPV_PVS] (first inner PV)", &|_t, opvs| {
            opvs[OPV_PVS] += one;
        });
        probe("inner-pv: flip opvs[OPV_PVS+40] (mid inner PV)", &|_t, opvs| {
            opvs[OPV_PVS + 40] += one;
        });
    }

    /// D3: the F0 mosaic must be TOTAL for both shapes — every rate word of
    /// every F0 block classified as Const / Cap / Pv, i.e. bindable. `eval`
    /// panics on anything else (an unbound word would be a silent hole), and
    /// the interior's F0 is 28 blocks over 868 inner PVs, so this covers the
    /// wide side without paying for a leaf prove.
    #[test]
    fn d3_f0_mosaic_is_total_for_both_shapes() {
        for (name, shape) in [("narrow", GateShape::narrow()), ("wide", GateShape::wide())] {
            let fb = shape.flush_blocks();
            let (mut consts, mut caps, mut pvs) = (0usize, 0usize, 0usize);
            let mut seen_pv = vec![false; shape.n_pvs];
            let mut seen_cap = vec![false; shape.cap_len * 16];
            for b in 0..fb[0] {
                let mosaic = shape_mosaic(&shape, Shape::Obs { flush: 0, block: b });
                assert_eq!(mosaic.len(), 34, "{name} F0 block {b}");
                for (j, bind) in mosaic.iter().enumerate() {
                    match bind {
                        WordBind::Const(_) => consts += 1,
                        WordBind::Cap(i) => {
                            caps += 1;
                            // Only the TRACE cap (cap 0) rides F0.
                            assert!(*i + 1 < shape.cap_len * 16, "{name}: F0 cap word {j} of {b}");
                            seen_cap[*i] = true;
                            seen_cap[*i + 1] = true;
                        }
                        WordBind::Pv(i) => {
                            pvs += 1;
                            let k = *i - shape.opv_pvs();
                            assert!(!seen_pv[k], "{name}: inner PV {k} bound twice");
                            seen_pv[k] = true;
                        }
                        other => panic!("{name}: F0 block {b} word {j} is {other:?} — unbindable"),
                    }
                }
            }
            assert_eq!(consts + caps + pvs, 34 * fb[0], "{name}: every F0 word classified");
            assert_eq!(pvs, shape.n_pvs, "{name}: every inner PV absorbed exactly once");
            assert!(seen_pv.iter().all(|x| *x), "{name}: an inner PV is never absorbed");
            assert!(seen_cap.iter().all(|x| *x), "{name}: a trace-cap limb is never absorbed");
            assert_eq!(caps, shape.cap_len * 8, "{name}: 8 words per cap digest");
        }
    }

    /// Independent keccak-256 (rate 136, pad10*1). Deliberately NOT the
    /// recorder's `Flusher::flush`, so the `f0dig` honesty check below does not
    /// end up verifying the recorder against itself.
    fn keccak256(bytes: &[u8]) -> [u8; 32] {
        let n_blocks = bytes.len() / 136 + 1;
        let mut msg = bytes.to_vec();
        msg.resize(n_blocks * 136, 0);
        msg[bytes.len()] ^= 0x01;
        msg[n_blocks * 136 - 1] ^= 0x80;
        let mut st = [0u64; 25];
        for blk in msg.chunks(136) {
            for (l, lane) in blk.chunks(8).enumerate() {
                st[l] ^= u64::from_le_bytes(lane.try_into().unwrap());
            }
            st = keccakf(&st);
        }
        let mut d = [0u8; 32];
        for l in 0..4 {
            d[8 * l..8 * l + 8].copy_from_slice(&st[l].to_le_bytes());
        }
        d
    }

    /// D3 PREMISE (issue #24): `shape_mosaic` — the `WordBind` spec written at
    /// inc-4, never called, never validated — must actually describe the
    /// challenger's F0 flush. Every D3 constraint reads this table, so a
    /// one-word disagreement would pin the WRONG public value while still
    /// looking green. Reconstructs F0's padded word stream from the mosaic + the
    /// outer public values and compares it to the recorder's real message,
    /// word for word, as RAW u32s (a stronger statement than the circuit's own
    /// field-reduced form).
    #[test]
    fn d3_f0_mosaic_matches_the_recorded_transcript() {
        let (sched, pvs, _) = shared();
        let shape = GateShape::narrow();
        let opvs = outer_pvs(sched, pvs, &shape);
        let fb = shape.flush_blocks();
        let msg = &sched.flushes[0].msg;
        assert_eq!(msg.len(), shape.flush_bytes()[0], "F0 message length");
        // pad10*1, exactly as the recorder (and the native challenger) do.
        let mut padded = msg.clone();
        padded.resize(fb[0] * 136, 0);
        padded[msg.len()] ^= 0x01;
        padded[fb[0] * 136 - 1] ^= 0x80;
        let mut kinds = (0, 0, 0);
        for b in 0..fb[0] {
            let mosaic = shape_mosaic(&shape, Shape::Obs { flush: 0, block: b });
            assert_eq!(mosaic.len(), 34, "one mosaic entry per rate word");
            for (j, bind) in mosaic.iter().enumerate() {
                let off = (34 * b + j) * 4;
                let word = u32::from_le_bytes(padded[off..off + 4].try_into().unwrap());
                let want = match bind {
                    WordBind::Const(v) => {
                        kinds.0 += 1;
                        *v
                    }
                    // A u32 transcript word = two u16 cap limbs (LE).
                    WordBind::Cap(i) => {
                        kinds.1 += 1;
                        opvs[*i].as_canonical_u32() | (opvs[*i + 1].as_canonical_u32() << 16)
                    }
                    // The inner PVs ride the outer interface in their transcript
                    // (Monty-word) encoding, so the canonical representative of
                    // the public value IS the absorbed word — no `rr` factor,
                    // unlike the D1 merge binding over canonical u32s.
                    WordBind::Pv(i) => {
                        kinds.2 += 1;
                        opvs[*i].as_canonical_u32()
                    }
                    other => panic!("F0 block {b} word {j}: unbindable {other:?}"),
                };
                assert_eq!(word, want, "F0 block {b} word {j} ({bind:?})");
            }
        }
        // Narrow F0 = 3 header consts + 8·8 trace-cap words + 84 PVs + 19 pad.
        assert_eq!(kinds, (22, 64, 84), "(Const, Cap, Pv) word counts");
    }

    /// D3 acceptance (2): the exposed `f0dig` is the honest digest of the
    /// ordered public-value list. The message is re-serialized HERE from the
    /// public values alone — not copied out of the recorder's flush record — so
    /// this pins the semantics a consumer would rely on: "f0dig commits to the
    /// caps and inner PVs this leaf claims".
    #[test]
    fn d3_f0dig_is_the_digest_of_the_public_surface() {
        let (sched, pvs, _) = shared();
        let shape = GateShape::narrow();
        let opvs = outer_pvs(sched, pvs, &shape);
        let deg_bits = shape.log_max - shape.log_blowup;
        let mut bytes = Vec::with_capacity(shape.flush_bytes()[0]);
        // deg_bits ‖ base_deg_bits ‖ preprocessed_width (transcript encoding).
        for v in [deg_bits, deg_bits, 0] {
            bytes.extend_from_slice(&Val::from_usize(v).to_unique_u32().to_le_bytes());
        }
        // trace cap (cap 0): u16 limbs, LE.
        for i in 0..shape.cap_len * 16 {
            bytes.extend_from_slice(&(opvs[i].as_canonical_u32() as u16).to_le_bytes());
        }
        // inner public values, already Monty-encoded in the opvs.
        for i in 0..shape.n_pvs {
            bytes.extend_from_slice(&opvs[shape.opv_pvs() + i].as_canonical_u32().to_le_bytes());
        }
        assert_eq!(bytes.len(), shape.flush_bytes()[0], "re-serialized F0 length");
        let dig = keccak256(&bytes);
        let want: Vec<Val> = dig
            .chunks(2)
            .map(|c| Val::from_u32(u16::from_le_bytes([c[0], c[1]]) as u32))
            .collect();
        assert_eq!(
            &opvs[shape.opv_f0dig()..shape.opv_pvs()],
            &want[..],
            "exposed f0dig != keccak256(public surface)"
        );
        // …and the same digest the recorder's challenger actually produced (so
        // the circuit's flush-output pin and this native recompute agree).
        assert_eq!(dig, sched.flushes[0].digest, "f0dig != the F0 flush digest");

        // VALUE-LEVEL guard for f0dig's PLACEMENT (coordinator §4). The 棒 3-3
        // epoch Σfee rider adds up `opvs[n_opvs - EPOCH_FEE_LIMBS ..]`, trusting
        // that the opvs tail is the M3 fee. Nothing in `m4interior`'s
        // const-assert can see that — it only ties EPOCH_FEE_LIMBS to the M3 PV
        // layout — so had f0dig been APPENDED, the rider would have started
        // summing digest limbs with every test still green. This asserts the
        // tail is the fee by VALUE, so the next person to append to the opvs
        // is stopped by a test rather than by a commit message.
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        let rr = monty_rr();
        for j in 0..fl {
            assert_eq!(
                opvs[shape.n_opvs() - fl + j],
                pvs[qlab_air::narrow::PV_FEE + j] * rr,
                "opvs tail limb {j} must be the M3 fee, not a digest limb"
            );
        }
        assert_eq!(
            qlab_air::narrow::PV_LEN,
            qlab_air::narrow::PV_FEE + fl,
            "M3 fee is the inner-PV tail"
        );
        // …and the guard is not vacuous: under an APPEND layout the tail check
        // would be comparing the first f0dig limbs against the fee, and those
        // are actually distinguishable — so it would fire rather than pass.
        assert!(
            (0..fl)
                .any(|j| opvs[shape.opv_f0dig() + j] != pvs[qlab_air::narrow::PV_FEE + j] * rr),
            "f0dig limbs coincide with the fee values — the tail guard would be vacuous"
        );
    }

    /// Diagnostic (relay): column-accounting breakdown by region.
    #[test]
    fn dump_cols() {
        eprintln!("KECCAK lane: {NUM_KECCAK_COLS}");
        eprintln!("MUL bank: 12  ADD bank: 12");
        eprintln!("gate block (GB..GATE_WIDTH): {}", GATE_WIDTH - GB);
        // Coarse buckets of the gate block.
        let buckets: &[(&str, usize, usize)] = &[
            ("routed-word + canonicity (W0C..OREG)", W0C, OREG),
            ("XOR register file (OREG..FSBITS)", OREG, FSBITS),
            ("FS draw gadget (FSBITS..GRP)", FSBITS, GRP),
            ("draw scheduling (GRP..CHAL)", GRP, CHAL),
            ("challenge/index regs (CHAL..FRING)", CHAL, FRING),
            ("flush automaton (FRING..PHC)", FRING, PHC),
            ("phase/query sched (PHC..PR)", PHC, PR),
            ("query program ring (PR..IDXB)", PR, IDXB),
            ("index bits (IDXB..CZ2)", IDXB, CZ2),
            ("asm pipeline (CZ2..PREG)", CZ2, PREG),
            ("running-sum/arith regs (PREG..F2DIG)", PREG, F2DIG),
            ("dup transport (F2DIG..end)", F2DIG, GATE_WIDTH),
        ];
        let mut tot = 0;
        for (nm, a, b) in buckets {
            eprintln!("  {:42} {:4}", nm, b - a);
            tot += b - a;
        }
        eprintln!("gate block sub-total (W0C..end): {tot}");
        eprintln!("GATE_WIDTH total: {GATE_WIDTH}");
    }

    /// Positive: the rectangle accepts the genuine M3 consensus proof.
    #[test]
    fn gate_rectangle_satisfies() {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let (trace, meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
        check_constraints(&VerifierGateAir::new(), &trace, &meta.opvs);
    }

    /// Run `check_constraints` in a spawned thread and report whether it
    /// panicked (UNSAT). A spawned thread's panic — including rayon worker
    /// panics that propagate into it — is reliably captured by `join()`,
    /// unlike `catch_unwind` on the calling thread, which intermittently lets
    /// the panic escape when many checks run concurrently under `cargo test`.
    fn is_unsat(trace: RowMajorMatrix<Val>, opvs: Vec<Val>) -> bool {
        std::thread::spawn(move || {
            check_constraints(&VerifierGateAir::new(), &trace, &opvs);
        })
        .join()
        .is_err()
    }

    /// Serialize ALL heavy work (trace build + rayon-parallel check) across the
    /// parallel test threads. Each build allocates a ~230 MB trace and
    /// `check_constraints` is itself rayon-parallel; running several at once
    /// oversubscribes memory/CPU and has produced spurious failures. Holding
    /// this guard across the whole build+check body keeps them deterministic.
    fn heavy_lock() -> std::sync::MutexGuard<'static, ()> {
        static LK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Assert a mutated witness is UNSATISFIABLE (some constraint fires). The
    /// mutate closure gets the trace, the outer public values, and (to avoid a
    /// second heavy trace build) the query-row starts and accepted field draws.
    fn assert_unsat(
        mutate: impl Fn(&mut RowMajorMatrix<Val>, &mut Vec<Val>, &[usize], &[(usize, u32)]),
    ) {
        let _g = heavy_lock();
        let (sched, pvs, _) = shared();
        let (mut trace, mut meta) = build_gate_trace(sched, pvs, &GateShape::narrow(), 0);
        let qrows = meta.query_rows.clone();
        let fdraws = meta.field_draws.clone();
        mutate(&mut trace, &mut meta.opvs, &qrows, &fdraws);
        let opvs = meta.opvs.clone();
        assert!(
            is_unsat(trace, opvs),
            "expected UNSAT but constraints were satisfied"
        );
    }

    /// Gate-exit negative 2 (wrong root): a claimed inner Merkle cap that
    /// disagrees with the recomputed path is rejected. BOUND today by the
    /// cap comparison against the outer public values.
    #[test]
    fn gate_neg_wrong_root() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            // Corrupt limb 0 of ALL 8 cap elements of batch 0 (the trace tree):
            // every query's trace-path cap comparison selects one of the 8
            // elements, so whichever it picks is now wrong. Tampering a single
            // element would be proof-index-dependent (the M3 witness, hence the
            // query indices, varies per build) and flake.
            for j in 0..CAP_LEN {
                opvs[cap_limb_opv(0, j, 0)] += Val::ONE;
            }
        });
    }

    /// Gate-exit negative 1 (tampered opening): flipping an opened leaf word
    /// breaks the leaf sponge -> Merkle path -> cap chain. BOUND today by the
    /// keccak lane + path-chaining + cap comparison.
    #[test]
    fn gate_neg_tampered_opening() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + pcol(0)] += Val::ONE;
        });
    }

    // -- D3 (issue #24): the leaf F0 input binding -------------------------
    // Everything below was SAT before D3. The first two are literally the
    // issue #21 R2 SAT-MISS probes (`tamper_coverage`), promoted from a printed
    // map to asserting negatives — they are D3's whole point: a leaf may no
    // longer claim a transaction surface it did not verify.

    /// The first inner public value (M3's anchor limb 0).
    #[test]
    fn gate_neg_inner_pv_first() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[OPV_PVS] += Val::ONE;
        });
    }

    /// A mid-list inner public value (the same probe issue #21 committed).
    #[test]
    fn gate_neg_inner_pv_mid() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[OPV_PVS + 40] += Val::ONE;
        });
    }

    /// The LAST inner public value = the M3 fee tail, i.e. the summand the
    /// 棒 3-3 epoch Σfee rider adds up one level higher.
    #[test]
    fn gate_neg_inner_pv_fee_tail() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[N_OPVS - 1] += Val::ONE;
        });
    }

    /// A SINGLE trace-cap limb. `gate_neg_wrong_root` had to corrupt limb 0 of
    /// all 8 cap elements because the query-phase comparison only checks the
    /// element that proof's query indices happen to select; F0 absorbs every
    /// element of the trace cap unconditionally, so one limb now suffices —
    /// and the transcript can no longer be built over a different cap than the
    /// one the queries are checked against.
    #[test]
    fn gate_neg_f0_single_cap_limb() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[cap_limb_opv(0, 3, 5)] += Val::ONE;
        });
    }

    /// The exposed public-surface digest (issue #21 R2) is pinned to F0's
    /// actual flush output — first limb…
    #[test]
    fn gate_neg_f0dig_first() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[OPV_F0DIG] += Val::ONE;
        });
    }

    /// …and last limb.
    #[test]
    fn gate_neg_f0dig_last() {
        assert_unsat(|_t, opvs, _qr, _fd| {
            opvs[OPV_PVS - 1] += Val::ONE;
        });
    }

    /// The routed-word columns themselves. `w0c`/`w1c` have been FILLED since
    /// inc-4 and constrained by nothing until D3; row 0 of F0 block 0 (lane perm
    /// 0) carries the degree-bits header word.
    #[test]
    fn gate_neg_f0_recovered_word() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, _fd| {
            t.values[W0C] += Val::ONE;
            let _ = w;
        });
    }

    /// The XOR-mode recovery witness. F0 block 1 (lane perm 1, row 24) is the
    /// first XOR block: its message is `preimage XOR oreg`, recovered bit by
    /// bit. A lying bit witness is caught either by the bit boolean or by the
    /// 16-bit recomposition of the preimage limb.
    #[test]
    fn gate_neg_f0_xor_bit() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, _fd| {
            t.values[24 * w + PBIT] += Val::ONE;
        });
    }

    /// Gate-exit negative 3 (wrong challenge). BOUND (inc-4): the FS draw
    /// gadget ties FSBITS/FSACC to the sponge digest (limb consistency), the
    /// comparator fixes accept/reject, and the COEF/CURCH ring assembles
    /// CHAL[grp] from the accepted draws. Two independent tampers are caught:
    ///   (a) flip an accepted field draw's FSACC (byte gadget), and
    ///   (b) flip an assembled challenge limb CHAL[0] (assembly binding).
    #[test]
    fn gate_neg_wrong_challenge_fs() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, fd| {
            let (row, _) = fd[0];
            t.values[row * w + FSACC] += Val::ONE;
        });
    }

    /// R3 (issue #21): FSGATE schedule-position pin. A field draw sits on the
    /// even/odd row pair (2j, 2j+1) of a draw-hosting (consumersel) perm, with
    /// FSGATE=1 on both. De-activating the EVEN half (relocating/shifting the
    /// draw pattern away from its scheduled contiguous prefix) leaves every FS
    /// constraint satisfied on base (fs=0 only *removes* gated enforcement, and
    /// the even row carries no crot/grot), so the witness is otherwise internally
    /// consistent — but the new contiguity pin
    /// `(1-sf(23))·fsgate(next)·(1-fsgate(cur))==0` fires on the induced 0->1
    /// step. Also exercised: the row still reads a real digest limb, so this is a
    /// genuine "moved FS row", not a corrupted one.
    #[test]
    fn gate_neg_fs_row_moved() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, fd| {
            // fd holds accepted field draws at their ODD rows (2j+1); its even
            // partner (2j) is the same draw's first FS row, FSGATE=1 honestly.
            let odd = fd[0].0;
            assert!(odd % 24 >= 1, "field draw not on an even/odd pair");
            t.values[(odd - 1) * w + FSGATE] = Val::ZERO;
        });
    }

    /// R1 (issue #21): word canonicity comparator. Replace one routed word on a
    /// value-consuming (casm) row with its non-canonical alias `w + p` — the same
    /// KoalaBear residue, so the field-reduced W0C column and the range-forced
    /// digit-split binding are unchanged and every other constraint still holds —
    /// but the `< p` comparator rejects the alias's bit pattern (bit 31 set, or
    /// word bits 24..30 all set with bits 0..23 nonzero). A real fired-constraint
    /// negative: on the base circuit the canon columns are unreferenced (SAT);
    /// only the new comparator makes it UNSAT.
    #[test]
    fn gate_neg_noncanonical_word() {
        let w = GATE_WIDTH;
        let layout = GateLayout::from_shape(&GateShape::narrow());
        assert_unsat(move |t, _o, _qr, _fd| {
            let rows = t.values.len() / w;
            let row = (0..rows)
                .find(|&r| {
                    t.values[r * w + CZD] != Val::ZERO
                        || t.values[r * w + CZ7] != Val::ZERO
                        || t.values[r * w + CF] != Val::ZERO
                })
                .expect("a casm value row exists");
            let v = t.values[row * w + W0C].as_canonical_u32();
            assert!(v < P, "honest routed word is canonical");
            // Inject the alias v+p into word 0's canon columns (fill_canon_raw
            // skips the canonicity assert). W0C stays = v (v+p ≡ v mod p), so the
            // digit-split binding still holds and only the comparator fires.
            fill_canon_raw(&mut t.values, row, 0, v + P, &layout);
        });
    }

    #[test]
    fn gate_neg_wrong_challenge_chal() {
        let w = GATE_WIDTH;
        // Flip alpha's limb 0 at a query row (alpha is long since assembled
        // there): breaks the CHAL carry / assembly binding.
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + CHAL] += Val::ONE;
        });
    }

    /// M_X1 x-chain binding (fold-pipeline arithmetic layer 1). BOUND
    /// (inc-4): XREG (the query LDE point) = GEN·∏(kx if idx-bit else 1) via
    /// the mul-bank chain over the (digest-bound) query index bits. Flipping
    /// XREG breaks the chain capture / carry.
    #[test]
    fn gate_neg_xreg_chain() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + XREG] += Val::ONE;
        });
    }

    /// M_INV inverse binding. BOUND (inc-4): INVZ = 1/(zeta - x), pinned by
    /// the mul bank's product == 1 with zeta (CHAL) and x (XREG) both bound.
    /// Flipping INVZ breaks the inverse relation / capture / carry.
    #[test]
    fn gate_neg_invz() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + INVZ] += Val::ONE;
        });
    }

    /// M_B BREG ladder binding. BOUND (inc-4): breg[0] = beta·inv2s, breg[l] =
    /// 2·breg[l-1]², both inputs bound. Flipping a BREG limb breaks the ladder
    /// capture / carry.
    #[test]
    fn gate_neg_breg() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            t.values[qr[0] * w + BREG] += Val::ONE;
        });
    }

    /// ZN global relation. BOUND (inc-4): ZNREG = zeta·g_trace on query rows,
    /// pinned to the bound zeta (this also completes INVZN). Flip ZNREG.
    #[test]
    fn gate_neg_zn() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            t.values[qr[0] * w + ZNREG] += Val::ONE;
        });
    }

    /// M_S INV2S binding. BOUND (inc-4): INV2S = 1/(2s), s the round's
    /// idx-selected product; pinned by the mul bank's product == 1. Flip INV2S.
    #[test]
    fn gate_neg_inv2s() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            t.values[qr[0] * w + INV2S] += Val::ONE;
        });
    }

    /// M_FIN x_fin-chain binding. BOUND (inc-4): XFIN (final-poly eval point)
    /// via the mul-bank chain over the high query index bits. Flipping XFIN
    /// breaks the chain capture / carry.
    #[test]
    fn gate_neg_xfin_chain() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + XFIN] += Val::ONE;
        });
    }

    /// Value-carry-row / VC schedule binding (fold-pipeline foundation).
    /// BOUND (inc-4): the asm/PX carry selectors (CZD/CZ7/CF/CX0/CX1), the POS
    /// half-position toggle, CONSZ/CONSF, and the VC value-counter ring are
    /// tied to the role/phase schedule. Flipping a VC cell breaks the one-hot;
    /// this is the base the reduced-opening / fold arithmetic will build on.
    #[test]
    fn gate_neg_value_schedule() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + VC + 3] += Val::ONE; // break VC one-hot
        });
    }

    /// Draw-group schedule binding (spec §2.1). BOUND (inc-4): the GRP ring
    /// now rotates only on GROT (a completed challenge / bits draw), so a
    /// prover cannot advance the group schedule out of step with the draws.
    /// Flipping a GRP ring cell breaks the rotation carry.
    #[test]
    fn gate_neg_grp_schedule() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, _fd| {
            // Row 60 is mid-F2 (challenger phase); flip the head slot.
            t.values[60 * w + GRP] += Val::ONE;
        });
    }

    /// Wrong query index (spec §2.2 sample_bits). BOUND (inc-4): each FRI
    /// query index IDXR[q] is tied to the FS-sampled digest bits, so a prover
    /// cannot choose favorable queries. Flipping IDXR[0] at a query row breaks
    /// the sample_bits binding / carry.
    #[test]
    fn gate_neg_wrong_query_index() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + IDXR] += Val::ONE;
        });
    }

    /// csel child-boundary pin (2b, option B: completion-gated). On the
    /// single-child narrow trace csel is 1 only at row 0; a prover must not be
    /// able to re-anchor the automaton mid-child. Setting csel=1 on an interior
    /// query row is UNSAT: the transition gate `csel_next·(1-endg)==0` fires
    /// because `endg` (last-query end) is 0 on the row before a query start.
    /// This is the soundness gate the coordinator flagged; it binds before any
    /// two-child trace exists.
    #[test]
    fn gate_neg_csel_narrow() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            t.values[qr[0] * w + CSEL] += Val::ONE;
        });
    }

    /// Gate-exit negative 4 (bad fold). BOUND (inc-4): the FRI fold ladders
    /// (round-0 leaf fold + M_FHI) pin the fold values, the fold-leaf
    /// consistency ties RUNEV to the sponge-bound openings at each round's
    /// index-in-group, and RUNEV carries between the M_FHI / M_RO updates.
    /// Flipping a RUNEV limb breaks the carry / consistency.
    #[test]
    fn gate_neg_bad_fold() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + RUNEV] += Val::ONE;
        });
    }

    /// Endpoint-pin negative (START): tamper the reduced-opening accumulator.
    /// The PZACC accumulation recurrence (pzacc += preg·v, with the leaf-start
    /// reset) must reject a single altered running-sum cell.
    #[test]
    fn gate_neg_pzacc() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + PZACC] += Val::ONE;
        });
    }

    /// Endpoint-pin negative (START): tamper the running fri_alpha power.
    #[test]
    fn gate_neg_preg() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + PREG] += Val::ONE;
        });
    }

    /// Endpoint-pin negative (START): tamper a captured reduced-opening
    /// component. Its capture-or-carry recurrence must reject the change.
    #[test]
    fn gate_neg_capture() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + A0R] += Val::ONE;
        });
    }

    /// Endpoint-pin negative (END): tamper a captured final-poly coefficient.
    /// The FPREG capture-or-carry recurrence + M_HORN Horner must reject it.
    #[test]
    fn gate_neg_fpreg() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, qr, _fd| {
            let row = qr[0];
            t.values[row * w + FPREG] += Val::ONE;
        });
    }

    /// Endpoint-pin negative (START completion): tamper an M_RO reduced-opening
    /// SCR intermediate. The 9-row assembly binding must reject the change.
    #[test]
    fn gate_neg_mro() {
        let w = GATE_WIDTH;
        assert_unsat(move |t, _o, _qr, _fd| {
            // Find an M_RO perm (MSEL slot 3 set on its last row) and flip an
            // SCR intermediate on its capture-carry span.
            let n = t.values.len() / w;
            let mro = MSEL + M_RO as usize;
            let one = Val::ONE;
            for perm in 0..(n / 24) {
                let r23 = perm * 24 + 23;
                if t.values[r23 * w + mro] == one {
                    // Row 3 of this M_RO perm: SCR0 must still hold its capture.
                    t.values[(perm * 24 + 3) * w + SCR] += one;
                    return;
                }
            }
            panic!("no M_RO perm found");
        });
    }

    /// Slice 1b-4 — the wide single-child interior verifier trace SATISFIES its
    /// constraints. Builds a real leaf wide proof (b4/q40, ~12 GB), records its
    /// verification schedule (`walk_leaf`), assembles the interior verifier
    /// trace at `GateShape::wide()` (2^18 × wide width), and `check_constraints`
    /// must pass — the first end-to-end wide correctness signal, and the check
    /// that the Option A `M_HORN` END-pin (`RUNEV == Horner(final_poly, x_fin)`)
    /// and the relocated `M_FIN`/`xfin` carry actually hold on real wide data.
    /// `check_constraints` only (no full prove); the RSS gate is stage 3.
    ///
    /// SAT (2026-07-20, slice 1b-B8): the wide trace BUILDS and the full 2^18
    /// `check_constraints` PASSES — the first end-to-end wide correctness signal.
    /// Peel-the-onion history: B4 M_X1 OOB → B5 (bidx) row-0 shsel → B6 (caps8
    /// fill) row-42216 → B7 (DRND loop/fold_dp) row-44808 → B8 **row 200616
    /// (#5187 fold-leaf HIT-definition)**. B8 root cause: pad rows never filled
    /// `hit` (the main perm loop's non-fold else-branch never runs over pad rows),
    /// while the global HIT constraint reduces to `hit==vc[0]` there; wide's last
    /// fold round has 16 leaves so the frozen `vc` wraps to slot 0 → mismatch
    /// (narrow's 4-leaf last round left vc=4, masking it). Fixed in the pad loop.
    /// `check_constraints` only (no full prove); the RSS gate is stage 3.
    #[test]
    fn interior_single_child_satisfies() {
        let _g = heavy_lock();
        let (leaf, opvs) = crate::m4treerec::leaf_proof();
        let sched = crate::m4treerec::walk_leaf(&leaf, &opvs);
        let (trace, meta) = build_gate_trace(&sched, &opvs, &GateShape::wide(), 0);
        check_constraints(
            &VerifierGateAir::new_with_shape(GateShape::wide()),
            &trace,
            &meta.opvs,
        );
    }

    /// Slice 1b-5: the shape-tied tamper negatives, re-derived for the WIDE
    /// single-child trace (2^18 × wide width). Mirrors the narrow `gate_neg_*`
    /// set but reads the wide `GateLayout` offsets and asserts each single-cell
    /// tamper is UNSAT under the `wide()` AIR — the soundness counterpart to the
    /// 1b-4 SAT signal. Especially exercises the Option-A `M_HORN`/`RUNEV`
    /// END-pin (bad-fold / fpreg / xfin) on real wide data, and the fold-leaf
    /// VC one-hot (the 1b-B8 region). One wide trace is built and cloned per
    /// probe (each `check_constraints` is a full 2^18 pass).
    #[test]
    fn interior_single_child_negatives() {
        let _g = heavy_lock();
        let (sched, opvs) = wide_shared();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;

        let (base_trace, meta) = build_gate_trace(sched, opvs, &shape, 0);
        let qrows = meta.query_rows.clone();
        let fdraws = meta.field_draws.clone();
        let base_opvs = meta.opvs.clone();
        assert!(!qrows.is_empty() && !fdraws.is_empty(), "wide meta populated");
        let q0 = qrows[0];

        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>, &mut Vec<Val>)| {
            let mut trace = base_trace.clone();
            let mut o = base_opvs.clone();
            mutate(&mut trace, &mut o);
            assert!(is_unsat_wide(trace, o), "expected UNSAT (wide): {label}");
        };

        // --- structural / gate-exit ------------------------------------------
        // wrong-root: corrupt cap-0 (trace tree) limb0 across all 8 digests.
        probe("wrong-root: cap0 all-digest limb0", &|_t, o| {
            for j in 0..shape.cap_len {
                o[cap_limb_opv(0, j, 0)] += one;
            }
        });
        // tampered-opening: flip query-0 trace-leaf preimage limb.
        probe("tampered-opening: q0 preimage limb0", &|t, _o| {
            t.values[q0 * w + pcol(0)] += one;
        });
        // wrong-query-index: flip the FS-sampled index register.
        probe("wrong-query-index: IDXR[0]@q0", &|t, _o| {
            t.values[q0 * w + l.idxr] += one;
        });
        // wrong-challenge: flip an accepted field-draw's FSACC.
        probe("wrong-challenge: FSACC@draw0", &|t, _o| {
            t.values[fdraws[0].0 * w + l.fsacc] += one;
        });

        // --- fold-leaf VC schedule (the 1b-B8 region) ------------------------
        probe("value-schedule: VC[3]@q0 (break one-hot)", &|t, _o| {
            t.values[q0 * w + l.vc + 3] += one;
        });

        // --- START endpoint pins (reduced opening) ---------------------------
        probe("pzacc@q0", &|t, _o| {
            t.values[q0 * w + l.pzacc] += one;
        });
        probe("preg@q0", &|t, _o| {
            t.values[q0 * w + l.preg] += one;
        });
        probe("capture A0R@q0", &|t, _o| {
            t.values[q0 * w + l.a0r] += one;
        });
        // M_RO reduced-opening assembly: flip an SCR intermediate on an M_RO perm.
        probe("mro: SCR@row3 of an M_RO perm", &|t, _o| {
            let n = t.values.len() / w;
            let mro = l.msel + M_RO as usize;
            for perm in 0..(n / 24) {
                if t.values[(perm * 24 + 23) * w + mro] == one {
                    t.values[(perm * 24 + 3) * w + l.scr] += one;
                    return;
                }
            }
            panic!("no M_RO perm found (wide)");
        });

        // --- END endpoint pins (Option-A M_HORN / RUNEV soundness) -----------
        probe("bad-fold: RUNEV@q0", &|t, _o| {
            t.values[q0 * w + l.runev] += one;
        });
        probe("fpreg@q0", &|t, _o| {
            t.values[q0 * w + l.fpreg] += one;
        });
        probe("xfin-chain: XFIN@q0", &|t, _o| {
            t.values[q0 * w + l.xfin] += one;
        });
        probe("xreg-chain: XREG@q0", &|t, _o| {
            t.values[q0 * w + l.xreg] += one;
        });
    }

    /// 棒 2 (2c): two child leaf proofs verified in one 2^19 rectangle (row-
    /// stacked, csel re-anchored at the child boundary). Same-leaf children →
    /// single opvs. `check_constraints` must pass (the two-child correctness
    /// signal; ~8 GB raw trace, no prove). Distinct children + per-lane tamper
    /// negatives are 2d.
    ///
    /// SAT (2026-07-20, 2c + 2b-iii): the full 2^19 two-child rectangle passes
    /// `check_constraints`. Child L (rows 0..24·8359) + child R re-anchor at the
    /// csel boundary; the query-phase-end boundary carries are resolved two ways —
    /// anchored automaton families (qsel/fring/grp/coef/blkcnt/phc/phd/phq) gated
    /// with `(1-csel_next)` (fring/blkcnt via materialized frgm/bcbd for deg ≤3);
    /// non-anchored fold/data registers (oreg, fold arith, chal/idxr/curch)
    /// carried by fill-continuity (child R inherits child L's final values).
    #[test]
    fn interior_two_child_satisfies() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = crate::m4interior::two_child_schedule(false);
        let (trace, meta) = build_interior_trace(&sl, &sr, &ol, &or, &GateShape::wide(), 0);
        check_constraints(&VerifierGateAir::new_interior(), &trace, &meta.opvs);
    }

    /// 2d-3 (HARD PR-gate): the two children are DISTINCT leaf proofs (child R
    /// from `leaf_proof_variant` — a different M3 witness → different caps +
    /// inner PVs). Identical children (L == R) can mask cross-wiring / symmetry
    /// bugs; only a distinct pair proves the per-child opvs routing (2d-2)
    /// actually binds child R to the SECOND half of `opvsL ++ opvsR`. Must be
    /// `check_constraints`-SAT (~8 GB raw trace at 2^19; no full prove).
    #[test]
    fn interior_two_child_satisfies_distinct() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let (trace, meta) = build_interior_trace(sl, sr, ol, or, &GateShape::wide(), 0);
        check_constraints(&VerifierGateAir::new_interior(), &trace, &meta.opvs);
    }

    /// 2d-4 (PR-gate): per-child + distinct tamper negatives. Build ONE interior
    /// trace over DISTINCT children, clone-per-probe, and assert each single-cell
    /// tamper is UNSAT under `new_interior()`. Together they prove BOTH lanes are
    /// bound (not just child L) and that the 2d-2 routing binds child R to its
    /// OWN opvs half (a misroute reading child L's half would leave the child-R
    /// opvs tamper SAT):
    ///  (a) child-L opening  — the L lane's query opening is bound;
    ///  (b) child-R opening  — the R lane is bound independently (rows ≥ 24·nL);
    ///  (c) child-R opvs      — child R reads the SECOND half of opvsL ++ opvsR.
    #[test]
    fn interior_two_child_negatives() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;
        let nq = shape.nq;
        let n_opvs = shape.n_opvs();

        let (base_trace, meta) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        let base_opvs = meta.opvs.clone();
        // query_rows records child L's nq queries first (absolute rows < 24·nL),
        // then child R's (rows ≥ 24·nL) — one push per query, in emit order.
        assert_eq!(meta.query_rows.len(), 2 * nq, "both children's queries recorded");
        let qr_l = meta.query_rows[0];
        let qr_r = meta.query_rows[nq];
        assert!(qr_l < qr_r, "child R queries live in the upper row-stacked region");

        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>, &mut Vec<Val>)| {
            let mut trace = base_trace.clone();
            let mut o = base_opvs.clone();
            mutate(&mut trace, &mut o);
            assert!(is_unsat_interior(trace, o), "expected UNSAT (interior): {label}");
        };

        probe("child-L opening: q0 preimage limb0", &|t, _o| {
            t.values[qr_l * w + pcol(0)] += one;
        });
        probe("child-R opening: q0 preimage limb0", &|t, _o| {
            t.values[qr_r * w + pcol(0)] += one;
        });
        probe("child-R opvs: cap0 all-digest limb0 (second half)", &|_t, o| {
            for j in 0..shape.cap_len {
                o[n_opvs + cap_limb_opv(0, j, 0)] += one;
            }
        });
    }

    /// 棒 3-1: the interior's public values carry the merge root
    /// `keccak(keccak(opvsL) ‖ keccak(opvsR))` (§2) appended after the two
    /// consumed child-opvs halves, and the merge sponge perms are valid keccak-f
    /// (check_constraints SAT). This slice lands the NATIVE merge + the exposed
    /// root; the eval binding (merge preimage ↔ pv(opvs), output ↔ pv(root)) is
    /// 棒 3-2, so the root is not yet constraint-bound to opvs here.
    #[test]
    fn interior_merge_native() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let n_opvs = shape.n_opvs();
        let (trace, meta) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        // Public values are [opvsL | opvsR | merge_root | Σfee]; the root slice
        // matches the native merge, and the whole rectangle (incl. the merge
        // perms) is SAT.
        assert_eq!(
            meta.opvs.len(),
            2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS + crate::m4interior::EPOCH_FEE_LIMBS
        );
        assert_eq!(
            &meta.opvs[2 * n_opvs..2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS],
            &crate::m4interior::merge_root(ol, or)[..],
            "interior root == keccak-merge(digest(opvsL), digest(opvsR))"
        );
        check_constraints(&VerifierGateAir::new_interior(), &trace, &meta.opvs);
    }

    /// 棒 3-2a: the merge-region pin (mreg monotone + mcnt == 24·nm at last_row)
    /// positively forces the last 24·nm rows to BE the merge sponge. Tampering
    /// the region (drop a mreg=1 / bump the counter) must be UNSAT — otherwise a
    /// prover could shrink/relocate the region and dodge the merge binding
    /// (棒 3-2b/c). Merge is at the trace end so the root perm's last row is
    /// `last_row`.
    #[test]
    fn interior_neg_merge_region() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;
        let nm = shape.merge_perms();
        let (base, _m) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        let rows = base.values.len() / w;
        let merge_start = 24 * (rows / 24 - nm); // perm-aligned (height not mult of 24)

        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>)| {
            let mut t = base.clone();
            mutate(&mut t);
            let o = _m.opvs.clone();
            assert!(is_unsat_interior(t, o), "expected UNSAT (region): {label}");
        };
        // Drop the merge-region flag on its first row → running-count transition
        // breaks (and mcnt no longer reaches 24·nm at last_row).
        probe("drop mreg at region start", &|t| {
            t.values[merge_start * w + l.mreg] -= one;
        });
        // Bump the region counter at the last row → mcnt != 24·nm.
        probe("bump mcnt at last_row", &|t| {
            t.values[(rows - 1) * w + l.mcnt] += one;
        });
        // Raise mreg early (before the region) → monotone says it must then stay
        // 1, but it's 0 right after → UNSAT (also over-counts mcnt).
        probe("spurious mreg before region", &|t| {
            t.values[(merge_start - 48) * w + l.mreg] += one;
        });
    }

    /// 棒 3-2b: the capacity-chain machinery — sub-sponge-start comparators
    /// (meq/minv → mrst) + the materialized chain gate (mcont) — is constraint-
    /// pinned, not free witness. Tampering it must be UNSAT. (The end-to-end
    /// value soundness — chain actually forces root == keccak(opvs) — is exercised
    /// by the opvs-tamper negative in 棒 3-2c, once the root squeeze is bound.)
    #[test]
    fn interior_neg_merge_chain() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;
        let nm = shape.merge_perms();
        let kl = (nm - 1) / 2;
        let t1 = 24 * kl + 1; // childR sub-sponge start (mcnt)
        let (base, _m) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        let rows = base.values.len() / w;
        let merge_start = 24 * (rows / 24 - nm); // perm-aligned (height not mult of 24)

        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>)| {
            let mut t = base.clone();
            mutate(&mut t);
            assert!(is_unsat_interior(t, _m.opvs.clone()), "expected UNSAT (chain): {label}");
        };
        // Drop the reset flag at the child-R sub-sponge start (mcnt == t1): breaks
        // `mrst == Σ meq` (the comparator still fires meq1 = 1).
        probe("drop mrst at childR sponge start", &|t| {
            t.values[(merge_start + t1 - 1) * w + l.mrst] -= one;
        });
        // Tamper the materialized chain gate on a genuine chain boundary (merge
        // perm 0 r=23, whose next perm is not a reset): breaks the mcont defn.
        probe("tamper mcont on a chain boundary", &|t| {
            t.values[(merge_start + 23) * w + l.mcont] += one;
        });
    }

    /// 棒 3-2c: the tree-merge digest binding. `interior_merge_native` is the
    /// positive (root perm output == pv(root), with dL carried / dR adjacent).
    /// Here the soundness negatives:
    ///  - wrong-merge: a root public value ≠ keccak-merge(opvsL, opvsR) → the root
    ///    squeeze bind fails → UNSAT (the §2 exposed digest is bound in-circuit);
    ///  - tampered dL carry: perturbing the carried child-L digest breaks the
    ///    root perm's input-rate bind → UNSAT (the dL→root link is live).
    #[test]
    fn interior_neg_merge_bind() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;
        let n_opvs = shape.n_opvs();
        let (base, m) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        let rows = base.values.len() / w;
        let root_r0 = 24 * (rows / 24 - 1); // root perm = last full perm

        // wrong-merge: tamper a root public value.
        {
            let mut o = m.opvs.clone();
            o[2 * n_opvs] += one; // root[0] ≠ keccak-merge(dL, dR)
            assert!(is_unsat_interior(base.clone(), o), "wrong merge root must be UNSAT");
        }
        // tampered dL carry at the root perm → input-rate bind fails.
        {
            let mut t = base.clone();
            t.values[root_r0 * w + l.dlr] += one;
            assert!(is_unsat_interior(t, m.opvs.clone()), "tampered dL carry must be UNSAT");
        }
    }

    /// Issue #24 (D0): the msh one-hot selector ring is POSITIVELY PINNED — its
    /// absence is UNSAT, not a silent binding vanish (the csel-vs-msh difference).
    /// This is the mechanism's soundness core: D1/D2/D3 read `msh[p]` to carry the
    /// compile-time block index into `eval`, so if a prover could zero the ring
    /// the message bindings would evaporate. Each probe must be UNSAT.
    #[test]
    fn interior_neg_msh_ring() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let l = GateLayout::from_shape(&shape);
        let w = l.gate_width;
        let one = Val::ONE;
        let nm = shape.merge_perms();
        let (base, m) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        let rows = base.values.len() / w;
        let merge_start = 24 * (rows / 24 - nm); // perm-aligned (height not mult of 24)

        let probe = |label: &str, mutate: &dyn Fn(&mut RowMajorMatrix<Val>)| {
            let mut t = base.clone();
            mutate(&mut t);
            assert!(is_unsat_interior(t, m.opvs.clone()), "expected UNSAT (msh): {label}");
        };
        // (1) DROP THE WHOLE RING (absence). Zero every msh slot on every row →
        //     the last-row root-slot anchor (f) fires AND the in-region one-hot
        //     (b) breaks. THE positive pin: a vanished ring must be UNSAT.
        probe("drop entire msh ring (absence)", &|t| {
            for r in 0..rows {
                for p in 0..nm {
                    t.values[r * w + l.msh + p] = Val::ZERO;
                }
            }
        });
        // (2) Drop the ring on last_row only → the end anchor (f) fails.
        probe("drop msh on last_row (end anchor)", &|t| {
            for p in 0..nm {
                t.values[(rows - 1) * w + l.msh + p] = Val::ZERO;
            }
        });
        // (3) Spurious extra one-hot bit on a merge perm's row → Σ msh = 2 ≠ mreg.
        probe("spurious extra msh bit", &|t| {
            t.values[merge_start * w + l.msh + 5] += one; // slot 0 active + slot 5 spurious
        });
        // (4) Tamper the rotation gate on a genuine rotation boundary (perm 0's
        //     last row, a child-L→child-L boundary) → the mrot definition (d) fails.
        probe("tamper mrot on a rotation boundary", &|t| {
            t.values[(merge_start + 23) * w + l.mrot] += one;
        });
    }

    /// Issue #24 (D1): the merge preimage → pv(opvs) MESSAGE binding is LIVE and
    /// UNCONDITIONAL. Before D1 the interior's inner PVs were unbound (only the
    /// root squeeze bound them, and only computationally via keccak preimage
    /// resistance — the PR #23/#25 caveat). These probes are the analogue of PR
    /// #29's leaf SAT-MISS probes for the interior: tampering an absorbed inner
    /// PV (or its fill-side preimage limb) must now be UNSAT. The fee TAIL is
    /// D2's boundary (`interior_epoch_fee_boundary`), so we tamper NON-fee slots.
    #[test]
    fn interior_neg_merge_msg() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let one = Val::ONE;
        let n_opvs = shape.n_opvs();
        let opv_inner = shape.n_caps() * shape.cap_len * 16; // OPV_PVS
        let (base, m) = build_interior_trace(sl, sr, ol, or, &shape, 0);

        // (1) tamper child-L inner PV 0 (anchor chunk 0) in the exposed opvs →
        //     the msh recompose·rr == pv binding fires. The trace (keccak) is
        //     untouched, so ONLY the D1 message binding can catch this. Was SAT
        //     (SAT-MISS) before D1; must be UNSAT now.
        {
            let mut o = m.opvs.clone();
            o[opv_inner] += one;
            assert!(is_unsat_interior(base.clone(), o), "tamper child-L inner PV must be UNSAT");
        }
        // (2) same for a mid child-R inner PV (second half) — proves both halves
        //     are bound, at a non-fee index (opv_inner + 40 = NF2 chunk 8).
        {
            let mut o = m.opvs.clone();
            o[n_opvs + opv_inner + 40] += one;
            assert!(is_unsat_interior(base.clone(), o), "tamper child-R inner PV must be UNSAT");
        }
    }

    /// 棒 3-3 (M4 step 2): the epoch Σfee rider is exposed and correct — the
    /// root public tail carries `Σfee[j] = feeL[j] + feeR[j]` (each child's fee
    /// limbs are the tail of its opvs half), and the whole rectangle is SAT.
    #[test]
    fn interior_epoch_fee() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let n_opvs = shape.n_opvs();
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        let sfee_base = 2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS;
        let (trace, meta) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        assert_eq!(meta.opvs.len(), sfee_base + fl, "opvs = halves | root | Σfee");
        for j in 0..fl {
            assert_eq!(
                meta.opvs[sfee_base + j],
                meta.opvs[n_opvs - fl + j] + meta.opvs[2 * n_opvs - fl + j],
                "Σfee limb {j} == feeL + feeR"
            );
        }
        check_constraints(&VerifierGateAir::new_interior(), &trace, &meta.opvs);
    }

    /// 棒 3-3 soundness negatives — the SUM binding the circuit provides
    /// (`Σfee == feeL + feeR` over the carried fee slots):
    ///  - tamper the exposed Σfee → the bind fails;
    ///  - tamper a child's fee SOURCE slot alone → the sum no longer holds.
    /// Both must be UNSAT. (Authenticity of the carried fees themselves is the
    /// issue #24 consumer boundary — see `interior_epoch_fee_boundary`.)
    #[test]
    fn interior_neg_epoch_fee() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let one = Val::ONE;
        let n_opvs = shape.n_opvs();
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        let sfee_base = 2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS;
        let (base, m) = build_interior_trace(sl, sr, ol, or, &shape, 0);

        // Tamper the exposed Σfee.
        {
            let mut o = m.opvs.clone();
            o[sfee_base] += one;
            assert!(is_unsat_interior(base.clone(), o), "tampered exposed Σfee must be UNSAT");
        }
        // Tamper a child fee source slot (feeL[0]) only → sum mismatch.
        {
            let mut o = m.opvs.clone();
            o[n_opvs - fl] += one;
            assert!(is_unsat_interior(base.clone(), o), "tampered child fee source must be UNSAT");
        }
    }

    /// 棒 3-3 issue #24 boundary — NOW CLOSED (D2). This test INVERTED: pre-#24
    /// the rider bound `Σfee` only to the carried fee slots, and the carried opvs
    /// were unbound witness, so a CONSISTENT (feeL, Σfee) tamper was SAT — pinned
    /// here as a documented limitation, NOT a negative. D2 extends the D1 msh
    /// message binding through the fee TAIL of each child's inner PVs, so feeL is
    /// now bound to the merge preimage: the consistent tamper breaks the fee-tail
    /// binding → UNSAT. The consumer-side recompute (`m4assembly::consumer_fee_ok`)
    /// stays as belt-and-braces. This is the PR #25 boundary closing in-circuit.
    #[test]
    fn interior_epoch_fee_boundary() {
        let _g = heavy_lock();
        let (sl, sr, ol, or) = wide_shared_distinct();
        let shape = GateShape::wide();
        let one = Val::ONE;
        let n_opvs = shape.n_opvs();
        let fl = crate::m4interior::EPOCH_FEE_LIMBS;
        let sfee_base = 2 * n_opvs + crate::m4interior::MERGE_ROOT_LIMBS;
        let (base, m) = build_interior_trace(sl, sr, ol, or, &shape, 0);
        // Consistent tamper: feeL[0] and Σfee both +1 → the rider SUM still
        // holds, but feeL[0] (= child-L inner PV np−fl) no longer matches the
        // merge preimage → D2's fee-tail message binding fires.
        let mut o = m.opvs.clone();
        o[n_opvs - fl] += one;
        o[sfee_base] += one;
        // UNSAT now (was SAT pre-#24) — the boundary is closed in-circuit.
        assert!(
            is_unsat_interior(base, o),
            "consistent feeL+Σfee tamper must be UNSAT after D2 (PR #25 boundary closed)"
        );
    }
}
