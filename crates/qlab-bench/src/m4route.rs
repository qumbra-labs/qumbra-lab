//! M4 step 0b(ii) increments 2+3: injection routing + FS byte-packing.
//!
//! Extends increment 1's composite rectangle (keccak lane + ext-mul bank +
//! ext-add bank, one 2^16-row AIR) with the two coupled subsystems the
//! layout doc named as the build's real unknowns:
//!
//! **Increment 2 — injection routing.** Opened values (verifier witness)
//! must reach BOTH consumers consistently: the keccak lane as absorbed
//! leaf-sponge words, and the arithmetic banks as 4-limb extension tuples.
//! `PaddingFreeSponge` is overwrite-mode, so an absorbing permutation's
//! preimage rate limbs hold the absorbed words verbatim; the stock keccak
//! AIR replicates the preimage across all 24 rows of a permutation and
//! range-checks its 16-bit limbs (bit recomposition of A). Routing is
//! therefore SAME-ROW cross-lane equality: on row offset `r` of an
//! absorbing perm (selected by the one-hot `step_flags`), a gated
//! constraint binds a bank operand to `pre_lo + 2^16 * pre_hi` at the
//! statically mapped value slot for that row offset. Value slot `v` of a
//! perm occupies rate limbs `2v, 2v+1` (u32 words packed two-per-u64-lane
//! by `SerializingHasher`). Two channels cover all 34 slots per perm:
//! channel 0 (row offsets 0..24 -> slots 0..24) feeds the add bank's `b`
//! operand, channel 1 (row offsets 0..10 -> slots 24..34) feeds the mul
//! bank's `b` operand. This is M3's equality-bank idea collapsed to its
//! cheapest sound form — the perm-replicated preimage makes the producing
//! value visible on the consuming row, so no signed accumulator window is
//! needed.
//!
//! Representation convention: the routed word is `(lo + 2^16 * hi) mod p`.
//! Canonicity of the absorbed byte string (vs the `v + p` alias) is not
//! re-checked here — the native verifier absorbs `to_unique_u32` bytes,
//! and any aliased encoding changes the transcript digests, which the
//! digest chain + challenge binding (this file's FS half + increment 4's
//! public binding) rejects end-to-end.
//!
//! **Increment 3 — FS byte-packing.** Challenges are bytes of challenger
//! digests reinterpreted as field elements. Native semantics
//! (`SerializingChallenger32<KoalaBear, HashChallenger<u8, Keccak256, 32>>`,
//! pinned 0.6.1, read from source): each base-field sample pops 4 bytes
//! from the END of the 32-byte digest buffer, assembles them LE (so draw
//! `j` reads digest byte group `4g..4g+4`, `g = 7 - j`, byte-reversed),
//! masks to the low 31 bits (`log2_ceil(p)`), and REJECTS + redraws if the
//! masked value is >= p = 2^31 - 2^24 + 1. The challenger CHAINS: every
//! flush rehashes the previous digest, so digest k is readable in-lane as
//! the first 16 preimage limbs of challenger perm k+1 (replicated on its
//! 24 rows), with an explicit chaining constraint binding perm k's output
//! limbs to perm k+1's preimage limbs at the perm boundary.
//!
//! The in-circuit convention mirrors the native one exactly:
//!   - one draw = 2 rows of the consuming perm (draw j on row offsets
//!     2j, 2j+1 — 12-draw capacity > the 8-draw digest maximum, so no
//!     schedule can outrun the gadget);
//!   - each row bit-decomposes one digest 16-bit limb into two bytes
//!     (16 bit columns; a bound consistency constraint re-composes the
//!     limb, and the keccak lane's own range-checking makes the byte
//!     split sound without lookups);
//!   - the draw value is accumulated with static per-row-offset weights;
//!     bit 31 is dropped by summing only 7 of the top byte's bits (the
//!     mask step);
//!   - canonicity/rejection: reject iff bits 24..30 are all ones AND the
//!     low 24 bits are nonzero (exactly `masked >= p` for this prime).
//!     The comparator is `t7 * nz` where `t7` is the materialized top-7
//!     bit product and `nz` an inverse-witnessed nonzero flag on the low
//!     24 bits; `accept = 1 - t7*nz`. Accepted draws are emitted to the
//!     mul bank's `a` operand (gated); rejected draws emit nothing —
//!     matching the native redraw, which simply consumes the next draw.
//!
//! For THIS round the rectangle runs a synthetic-but-shape-exact schedule
//! (real M3-proof witness is increment 4): 540 absorbing perms carrying
//! routed words, 173 challenger perms in one chained run with real
//! keccak-f digests (draw acceptance therefore has real rejection
//! statistics), 1,520 compress perms, and the census bank workloads. The
//! routing and FS constraints are REAL constraints — the unit tests
//! include native-challenger cross-checks and corrupted-witness negatives.
//!
//! Gate/selection columns (`g_inj*`, `fs_gate`, `chain_gate`) are witness
//! columns in this increment; binding them to the fixed verification
//! schedule (program ring, M3-style) is increment 4's job, alongside the
//! `sample_bits` variant (query indices; mask-only, no rejection) and
//! ext-challenge assembly (4 accepted draws -> one 4-limb tuple).

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_keccak::KeccakF;
use p3_keccak_air::{input_limb, output_limb, KeccakAir, NUM_KECCAK_COLS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_symmetric::Permutation;
use p3_uni_stark::{prove, verify};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use crate::m4skel::LaneBuilder;
use crate::{pc_len, FriCfg, Val, RUNS};
// Re-gated by the re-mint: M4 runs on the legacy non-hiding config.
use qlab_consensus::legacy::make_legacy_config_with as make_config_with;

// ---------------------------------------------------------------------------
// Column layout
// ---------------------------------------------------------------------------

/// Ext-mul bank: a[0..4] b[4..8] c[8..12] (increment 1's layout).
const MUL_OFF: usize = NUM_KECCAK_COLS;
/// Ext-add bank: a[0..4] b[4..8] c[8..12].
const ADD_OFF: usize = NUM_KECCAK_COLS + 12;
/// Routing/FS block base.
const RB: usize = NUM_KECCAK_COLS + 24;

// Routing/FS block (28 columns; the layout doc budgeted ~16 — the honest
// overshoot is the 16 byte-range bit columns, see the run doc).
/// Injection channel 0 gate: this row's ADD-bank `b` operand consumes the
/// opened value at slot `r` (r = row offset within the absorbing perm).
const G_INJ0: usize = RB;
/// Injection channel 1 gate: MUL-bank `b` consumes slot `24 + r` (r < 10).
const G_INJ1: usize = RB + 1;
/// 16 bit columns: bits 0..8 = HIGH byte of this row's digest limb,
/// bits 8..16 = LOW byte (see the draw/limb orientation note in `eval`).
const BITS: usize = RB + 2;
/// Draw accumulator: on a draw's odd row, holds the low 16 bits of the
/// draw (loaded by the even row's transition constraint).
const ACC: usize = RB + 18;
/// FS gadget gate (1 on the 16 draw rows of a digest-consuming perm).
const FS_GATE: usize = RB + 19;
/// Materialized bit products for the top-7 comparator (degree control).
const P3A: usize = RB + 20; // b8*b9*b10
const P3B: usize = RB + 21; // b11*b12*b13
const T7: usize = RB + 22; // p3a*p3b*b14
/// Inverse witness + nonzero flag for the low-24-bit rejection test.
const INV: usize = RB + 23;
const NZ: usize = RB + 24;
/// accept = 1 - t7*nz (constrained on FS rows).
const ACCEPT: usize = RB + 25;
/// Emission gate = fs_gate * accept * odd-row selector.
const G_EMIT: usize = RB + 26;
/// Challenger chaining gate: on a perm's final row, binds the next perm's
/// first 16 preimage limbs to this perm's first 16 output limbs.
const CHAIN_GATE: usize = RB + 27;

const ROUTE_COLS: usize = 28;
pub(crate) const ROUTE_WIDTH: usize = NUM_KECCAK_COLS + 24 + ROUTE_COLS;

/// KoalaBear modulus.
const P: u32 = 0x7f00_0001;
/// KoalaBear x^4 - 3.
const W: u32 = 3;

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

pub(crate) struct VerifierRouteAir;

impl<F: Field> BaseAir<F> for VerifierRouteAir {
    fn width(&self) -> usize {
        ROUTE_WIDTH
    }
}

impl<AB: AirBuilder> Air<AB> for VerifierRouteAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Keccak lane: the stock AIR through the column-offset adapter.
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
        // On-demand Expr conversion only for the columns actually used
        // (increment 1's +70% lesson: never collect the full width).
        let cv = |i: usize| -> AB::Expr { cur[i].into() };
        let nv = |i: usize| -> AB::Expr { nxt[i].into() };
        // step_flags are the first 24 keccak-lane columns (KeccakCols is
        // repr(C) with step_flags first; the positive tests would fail on
        // any layout drift of the pinned crate).
        let sf = |r: usize| -> AB::Expr { cv(r) };
        let pre = |i: usize| -> AB::Expr { cv(input_limb(i)) };
        let out = |i: usize| -> AB::Expr { cv(output_limb(i)) };

        let two8 = AB::Expr::from(AB::F::from_u32(1 << 8));
        let two16 = AB::Expr::from(AB::F::from_u32(1 << 16));
        let two24 = AB::Expr::from(AB::F::from_u32(1 << 24));
        let w = AB::Expr::from(AB::F::from_u32(W));

        // --- arithmetic banks (increment 1, unchanged) -------------------
        let bank: Vec<AB::Expr> = cur[MUL_OFF..MUL_OFF + 24]
            .iter()
            .map(|v| (*v).into())
            .collect();
        let (a, b, c) = (&bank[0..4], &bank[4..8], &bank[8..12]);
        for k in 0..4 {
            let mut acc = AB::Expr::ZERO;
            for i in 0..4 {
                for j in 0..4 {
                    if i + j == k {
                        acc = acc.clone() + a[i].clone() * b[j].clone();
                    } else if i + j == k + 4 {
                        acc = acc.clone() + w.clone() * a[i].clone() * b[j].clone();
                    }
                }
            }
            builder.assert_eq(acc, c[k].clone());
        }
        let (a, b, c) = (&bank[12..16], &bank[16..20], &bank[20..24]);
        for k in 0..4 {
            builder.assert_eq(a[k].clone() + b[k].clone(), c[k].clone());
        }

        // --- increment 2: injection routing ------------------------------
        // Gates are boolean.
        builder.assert_bool(cv(G_INJ0));
        builder.assert_bool(cv(G_INJ1));
        // Channel 0: row offset r (one-hot step flag) -> value slot r ->
        // rate limbs 2r, 2r+1; consumer = add-bank b as (word, 0, 0, 0).
        let mut word0 = AB::Expr::ZERO;
        for r in 0..24 {
            word0 = word0 + sf(r) * (pre(2 * r) + two16.clone() * pre(2 * r + 1));
        }
        builder.assert_zero(cv(G_INJ0) * (cv(ADD_OFF + 4) - word0));
        for k in 1..4 {
            builder.assert_zero(cv(G_INJ0) * cv(ADD_OFF + 4 + k));
        }
        // Channel 1: row offset r < 10 -> value slot 24 + r; consumer =
        // mul-bank b.
        let mut word1 = AB::Expr::ZERO;
        for r in 0..10 {
            word1 = word1 + sf(r) * (pre(48 + 2 * r) + two16.clone() * pre(49 + 2 * r));
        }
        builder.assert_zero(cv(G_INJ1) * (cv(MUL_OFF + 4) - word1));
        for k in 1..4 {
            builder.assert_zero(cv(G_INJ1) * cv(MUL_OFF + 4 + k));
        }

        // --- increment 3: FS byte-packing --------------------------------
        let fs = cv(FS_GATE);
        builder.assert_bool(fs.clone());
        let bit = |i: usize| -> AB::Expr { cv(BITS + i) };
        for i in 0..16 {
            builder.assert_bool(bit(i));
        }
        // Byte recompositions. Orientation: bits 0..8 hold the HIGH byte
        // of this row's digest limb (= the LOWER-weighted byte of the
        // draw, because sampling pops bytes from the digest's end), bits
        // 8..16 the LOW byte (= the higher-weighted draw byte).
        let mut b_lo = AB::Expr::ZERO; // draw-low byte (limb high byte)
        let mut b_hi = AB::Expr::ZERO; // draw-high byte (limb low byte)
        let mut b_hi_masked = AB::Expr::ZERO; // top byte without bit 7
        for i in 0..8 {
            let wgt = AB::Expr::from(AB::F::from_u32(1 << i));
            b_lo = b_lo + wgt.clone() * bit(i);
            b_hi = b_hi + wgt.clone() * bit(8 + i);
            if i < 7 {
                b_hi_masked = b_hi_masked + wgt * bit(8 + i);
            }
        }
        // Limb consistency: draw j sits on row offsets 2j, 2j+1 and reads
        // digest limbs 2g+1, 2g (g = 7 - j; byte order reversed by the
        // pop-from-end sampling). Both row kinds recompose identically:
        // limb = limb_low_byte + 2^8 * limb_high_byte = b_hi + 2^8 * b_lo.
        let mut limb_mux = AB::Expr::ZERO;
        for r in 0..16 {
            let j = r / 2;
            let m = if r % 2 == 0 {
                2 * (7 - j) + 1
            } else {
                2 * (7 - j)
            };
            limb_mux = limb_mux + sf(r) * pre(m);
        }
        builder.assert_zero(fs.clone() * (limb_mux - (b_hi.clone() + two8 * b_lo.clone())));
        // Draw accumulation: the even row loads the draw's low 16 bits
        // into the odd row's acc.
        let mut even_mux = AB::Expr::ZERO;
        let mut odd_mux = AB::Expr::ZERO;
        for j in 0..8 {
            even_mux = even_mux + sf(2 * j);
            odd_mux = odd_mux + sf(2 * j + 1);
        }
        builder.assert_zero(
            fs.clone()
                * even_mux
                * (nv(ACC) - (b_lo.clone() + AB::Expr::from(AB::F::from_u32(1 << 8)) * b_hi)),
        );
        // Comparator bit products (materialized to keep degree <= 3).
        builder.assert_eq(cv(P3A), bit(8) * bit(9) * bit(10));
        builder.assert_eq(cv(P3B), bit(11) * bit(12) * bit(13));
        builder.assert_eq(cv(T7), cv(P3A) * cv(P3B) * bit(14));
        // Low-24-bit nonzero flag (inverse witness). On the odd row,
        // low24 = acc + 2^16 * b_lo = the draw's low 24 bits.
        let low24 = cv(ACC) + two16.clone() * b_lo.clone();
        builder.assert_eq(cv(NZ), low24.clone() * cv(INV));
        builder.assert_bool(cv(NZ));
        builder.assert_zero((AB::Expr::ONE - cv(NZ)) * low24);
        // accept = 1 - t7*nz, i.e. reject exactly when masked >= p
        // (bits 24..30 all ones AND low 24 bits nonzero) — the native
        // challenger's rejection-resample condition.
        builder.assert_zero(fs.clone() * (cv(ACCEPT) - (AB::Expr::ONE - cv(T7) * cv(NZ))));
        // Emission gate and challenge consumption: the masked draw value
        // (bit 31 dropped via b_hi_masked) lands in the mul bank's a
        // operand as (chal, 0, 0, 0).
        builder.assert_eq(cv(G_EMIT), fs * cv(ACCEPT) * odd_mux);
        let masked = cv(ACC) + two16 * b_lo + two24 * b_hi_masked;
        builder.assert_zero(cv(G_EMIT) * (cv(MUL_OFF) - masked));
        for k in 1..4 {
            builder.assert_zero(cv(G_EMIT) * cv(MUL_OFF + k));
        }
        // Challenger chaining: on a chained perm's final row, the next
        // perm's first 16 preimage limbs equal this perm's first 16
        // output limbs (digest = first 32 bytes; the chained flush
        // rehashes it, and keccak-256 padding leaves bytes 0..32 of the
        // next block untouched).
        builder.assert_bool(cv(CHAIN_GATE));
        for m in 0..16 {
            builder.assert_zero(cv(CHAIN_GATE) * sf(23) * (nv(input_limb(m)) - out(m)));
        }
    }
}

// ---------------------------------------------------------------------------
// Native-semantics helpers (keccak-256 blocks, digests, draws)
// ---------------------------------------------------------------------------

type Ext = BinomialExtensionField<Val, 4>;

/// One padded keccak-256 block (message < 136 bytes): 0x01 domain byte,
/// 0x80 at the rate's last byte — tiny-keccak's Keccak::v256 convention,
/// which `p3_keccak::Keccak256Hash` wraps.
fn pad_block(msg: &[u8]) -> [u64; 25] {
    assert!(msg.len() < 136, "single-block messages only");
    let mut buf = [0u8; 136];
    buf[..msg.len()].copy_from_slice(msg);
    buf[msg.len()] ^= 0x01;
    buf[135] ^= 0x80;
    let mut st = [0u64; 25];
    for (l, lane) in st.iter_mut().take(17).enumerate() {
        *lane = u64::from_le_bytes(buf[8 * l..8 * l + 8].try_into().unwrap());
    }
    st
}

fn keccakf(st: &[u64; 25]) -> [u64; 25] {
    let mut s = *st;
    KeccakF {}.permute_mut(&mut s);
    s
}

/// Digest = first 32 bytes of the permuted state (LE lanes 0..4).
fn digest_of(out: &[u64; 25]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for l in 0..4 {
        d[8 * l..8 * l + 8].copy_from_slice(&out[l].to_le_bytes());
    }
    d
}

#[derive(Clone, Copy, Debug)]
struct Draw {
    /// Digest bytes 4g..4g+4 (g = 7 - j), in digest order.
    bytes: [u8; 4],
    /// 31-bit masked value.
    masked: u32,
    /// masked < p (native: rejected draws are skipped and resampled).
    accept: bool,
}

/// The 8 draws of one digest, in native pop order (group 7 first,
/// bytes reversed within the group).
fn draws_of(d: &[u8; 32]) -> [Draw; 8] {
    core::array::from_fn(|j| {
        let g = 7 - j;
        let bytes = [d[4 * g], d[4 * g + 1], d[4 * g + 2], d[4 * g + 3]];
        let raw = (bytes[3] as u32)
            | ((bytes[2] as u32) << 8)
            | ((bytes[1] as u32) << 16)
            | ((bytes[0] as u32) << 24);
        let masked = raw & 0x7fff_ffff;
        Draw {
            bytes,
            masked,
            accept: masked < P,
        }
    })
}

// ---------------------------------------------------------------------------
// Trace composition
// ---------------------------------------------------------------------------

/// Schedule specification: `absorb` leaf-sponge perms carrying routed
/// opened values, `chal` challenger perms in one chained run, `compress`
/// stock perms, and the bank row counts.
pub(crate) struct RouteSpec {
    pub absorb: usize,
    pub chal: usize,
    pub compress: usize,
    pub mul_rows: usize,
    pub add_rows: usize,
    pub seed: u64,
    pub msg_salt: u64,
}

/// Everything the tests (and the bench shape report) need to know about
/// the generated schedule.
pub(crate) struct RouteMeta {
    /// (odd draw row, masked value) for every accepted, emitted draw.
    pub emitted: Vec<(usize, u32)>,
    /// (odd draw row, masked value) for every rejected draw.
    pub rejected: Vec<(usize, u32)>,
    /// Total opened values routed through the injection channels.
    pub routed_values: usize,
    /// Challenger digests, in chain order.
    pub digests: Vec<[u8; 32]>,
    /// The initial challenger message (native cross-check seed state).
    #[allow(dead_code)] // read by the unit tests only
    pub init_msg: Vec<u8>,
}

fn rnd_ext(rng: &mut SmallRng) -> Ext {
    Ext::from_basis_coefficients_fn(|_| Val::from_u32(rng.next_u32() % P))
}

fn base_ext(v: u32) -> Ext {
    Ext::from_basis_coefficients_fn(|i| if i == 0 { Val::from_u32(v) } else { Val::ZERO })
}

fn write_ext(values: &mut [Val], row: usize, off: usize, e: Ext) {
    values[row * ROUTE_WIDTH + off..row * ROUTE_WIDTH + off + 4]
        .copy_from_slice(e.as_basis_coefficients_slice());
}

/// Fill one FS draw row's routing columns. `lo_byte` goes to bits 0..8
/// (the limb's HIGH byte / the draw's lower-weighted byte for this row),
/// `hi_byte` to bits 8..16. Computes the comparator/inverse witness
/// columns exactly as the constraints demand.
fn fill_fs_row(values: &mut [Val], row: usize, lo_byte: u8, hi_byte: u8, acc: u32, odd: bool) {
    let base = row * ROUTE_WIDTH;
    for i in 0..8 {
        values[base + BITS + i] = Val::from_u32(((lo_byte >> i) & 1) as u32);
        values[base + BITS + 8 + i] = Val::from_u32(((hi_byte >> i) & 1) as u32);
    }
    values[base + ACC] = Val::from_u32(acc);
    values[base + FS_GATE] = Val::ONE;
    let p3a = (hi_byte & 0b111) == 0b111;
    let p3b = ((hi_byte >> 3) & 0b111) == 0b111;
    let t7 = p3a && p3b && ((hi_byte >> 6) & 1) == 1;
    values[base + P3A] = Val::from_bool(p3a);
    values[base + P3B] = Val::from_bool(p3b);
    values[base + T7] = Val::from_bool(t7);
    let low24 = acc + ((lo_byte as u32) << 16);
    let nz = low24 != 0;
    values[base + NZ] = Val::from_bool(nz);
    values[base + INV] = if nz {
        Val::from_u32(low24).inverse()
    } else {
        Val::ZERO
    };
    let accept = !(t7 && nz);
    values[base + ACCEPT] = Val::from_bool(accept);
    values[base + G_EMIT] = Val::from_bool(accept && odd);
}

/// Build the composite trace: keccak lane from the scheduled inputs,
/// banks with the census workloads, routing/FS witness per the schedule.
/// The buffer is allocated at full LDE capacity up front (increment 1's
/// 3x-RSS lesson).
pub(crate) fn build_route_trace(
    spec: &RouteSpec,
    extra_capacity_bits: usize,
) -> (RowMajorMatrix<Val>, RouteMeta) {
    let mut rng = SmallRng::seed_from_u64(spec.seed);

    // Absorbing perms: 34 canonical opened values each, packed two-per-
    // u64-lane across the 17-lane rate (overwrite-mode sponge => the
    // preimage IS the message block). Capacity lanes zero (first block).
    let absorb_vals: Vec<[u32; 34]> = (0..spec.absorb)
        .map(|_| core::array::from_fn(|_| rng.next_u32() % P))
        .collect();
    let mut inputs: Vec<[u64; 25]> = Vec::with_capacity(spec.absorb + spec.chal + spec.compress);
    for v in &absorb_vals {
        let mut st = [0u64; 25];
        for l in 0..17 {
            st[l] = v[2 * l] as u64 | ((v[2 * l + 1] as u64) << 32);
        }
        inputs.push(st);
    }

    // Challenger run: initial 64-byte message, then the chained flushes
    // (each block = pad32(previous digest), exactly HashChallenger's
    // chaining with no interleaved observations).
    let mut init_msg = vec![0u8; 64];
    for (i, chunk) in init_msg.chunks_mut(8).enumerate() {
        let word = rng.next_u64() ^ spec.msg_salt.rotate_left(8 * i as u32);
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    let mut digests = Vec::with_capacity(spec.chal);
    let mut st = pad_block(&init_msg);
    for _ in 0..spec.chal {
        inputs.push(st);
        let d = digest_of(&keccakf(&st));
        digests.push(d);
        st = pad_block(&d);
    }

    // Compress perms: stock random states.
    for _ in 0..spec.compress {
        inputs.push(core::array::from_fn(|_| rng.next_u64()));
    }

    // Keccak lane via the stock generator (pads to a power of two).
    let keccak = p3_keccak_air::generate_trace_rows::<Val>(inputs, 0);
    let rows = keccak.height();
    let mut values = Vec::with_capacity((rows << extra_capacity_bits) * ROUTE_WIDTH);
    values.resize(rows * ROUTE_WIDTH, Val::ZERO);
    for r in 0..rows {
        values[r * ROUTE_WIDTH..r * ROUTE_WIDTH + NUM_KECCAK_COLS]
            .copy_from_slice(&keccak.values[r * NUM_KECCAK_COLS..(r + 1) * NUM_KECCAK_COLS]);
    }
    drop(keccak);

    // Bank operand bindings, keyed by row.
    let mut mul_a_bind: Vec<Option<u32>> = vec![None; rows];
    let mut mul_b_bind: Vec<Option<u32>> = vec![None; rows];
    let mut add_b_bind: Vec<Option<u32>> = vec![None; rows];

    // Injection routing witness: absorbing perm p, row offset r.
    let mut routed_values = 0usize;
    for (p, vals) in absorb_vals.iter().enumerate() {
        for r in 0..24 {
            let row = 24 * p + r;
            assert!(row < spec.add_rows, "ch0 row outside the active add bank");
            values[row * ROUTE_WIDTH + G_INJ0] = Val::ONE;
            add_b_bind[row] = Some(vals[r]);
            routed_values += 1;
            if r < 10 {
                assert!(row < spec.mul_rows, "ch1 row outside the active mul bank");
                values[row * ROUTE_WIDTH + G_INJ1] = Val::ONE;
                mul_b_bind[row] = Some(vals[24 + r]);
                routed_values += 1;
            }
        }
    }

    // FS witness: digest i is consumed on challenger perm i+1 (its
    // preimage carries the digest); chain gates close each producing
    // perm's boundary.
    let mut emitted = Vec::new();
    let mut rejected = Vec::new();
    for i in 0..spec.chal.saturating_sub(1) {
        let producer = spec.absorb + i;
        values[(24 * producer + 23) * ROUTE_WIDTH + CHAIN_GATE] = Val::ONE;
        let consumer_base = 24 * (spec.absorb + i + 1);
        for (j, draw) in draws_of(&digests[i]).iter().enumerate() {
            let [x0, x1, x2, x3] = draw.bytes;
            let row_a = consumer_base + 2 * j;
            let row_b = row_a + 1;
            // Even row: limb 2g+1 = (x2, x3); draw low bits.
            fill_fs_row(&mut values, row_a, x3, x2, 0, false);
            // Odd row: limb 2g = (x0, x1); acc = draw's low 16 bits.
            let acc = (x3 as u32) + ((x2 as u32) << 8);
            fill_fs_row(&mut values, row_b, x1, x0, acc, true);
            if draw.accept {
                assert!(
                    row_b < spec.mul_rows,
                    "emit row outside the active mul bank"
                );
                mul_a_bind[row_b] = Some(draw.masked);
                emitted.push((row_b, draw.masked));
            } else {
                rejected.push((row_b, draw.masked));
            }
        }
    }

    // Bank fill: bound operands where the routing demands them, random
    // self-consistent instances elsewhere.
    for r in 0..rows {
        if r < spec.mul_rows {
            let a = mul_a_bind[r]
                .map(base_ext)
                .unwrap_or_else(|| rnd_ext(&mut rng));
            let b = mul_b_bind[r]
                .map(base_ext)
                .unwrap_or_else(|| rnd_ext(&mut rng));
            write_ext(&mut values, r, MUL_OFF, a);
            write_ext(&mut values, r, MUL_OFF + 4, b);
            write_ext(&mut values, r, MUL_OFF + 8, a * b);
        }
        if r < spec.add_rows {
            let a = rnd_ext(&mut rng);
            let b = add_b_bind[r]
                .map(base_ext)
                .unwrap_or_else(|| rnd_ext(&mut rng));
            write_ext(&mut values, r, ADD_OFF, a);
            write_ext(&mut values, r, ADD_OFF + 4, b);
            write_ext(&mut values, r, ADD_OFF + 8, a + b);
        }
    }

    (
        RowMajorMatrix::new(values, ROUTE_WIDTH),
        RouteMeta {
            emitted,
            rejected,
            routed_values,
            digests,
            init_msg,
        },
    )
}

// ---------------------------------------------------------------------------
// Bench runner
// ---------------------------------------------------------------------------

/// The census-shaped workload: 540 leaf-sponge + 173 challenger + 1,520
/// compress perms (step 0a), 28,800 mul + 28,663 add bank rows (step 0b(i)).
fn bench_spec() -> RouteSpec {
    RouteSpec {
        absorb: 540,
        chal: 173,
        compress: 1520,
        mul_rows: 28_800,
        add_rows: 28_663,
        seed: 0x0b11_5eed,
        msg_salt: 0,
    }
}

const LANE_CFGS: [(&str, FriCfg); 2] = [
    (
        "b4/q40/g20/fp16/a16",
        FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
    (
        "b16/q20/g20/fp16/a16",
        FriCfg {
            log_blowup: 4,
            num_queries: 20,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        },
    ),
];

pub(crate) fn run_m4route(power: &str, only: Option<&str>) {
    println!("# qumbra-lab M4 step 0b(ii) increments 2+3: injection routing + FS byte-packing");
    println!();
    crate::print_env(power);
    println!(
        "- rectangle: {ROUTE_WIDTH} cols x 2^16 = keccak lane ({NUM_KECCAK_COLS}) + \
         ext-mul bank (12) + ext-add bank (12) + routing/FS block ({ROUTE_COLS}); \
         col budget vs the layout plan (2,673 = 2,657 + ~16 routing): \
         routing block realized {ROUTE_COLS} cols -> total {ROUTE_WIDTH} \
         ({:+} cols, {:+.2}% cells) — 16 of the {ROUTE_COLS} are the FS \
         byte-range bit columns (no-lookup AIR)",
        ROUTE_WIDTH as isize - 2_673,
        100.0 * (ROUTE_WIDTH as f64 - 2_673.0) / 2_673.0,
    );
    println!(
        "- schedule (synthetic, shape-exact; real M3-proof witness is \
         increment 4): 540 absorb perms x 34 routed opened values (both \
         injection channels), 173 challenger perms in one chained run \
         (real keccak-f digests, 8 draws each on 172 consuming perms), \
         1,520 compress perms; banks at the 0b(i) census (28,800 mul / \
         28,663 add rows)"
    );
    // With --only, skip the shape-report trace build: its freed buffer
    // stays in the allocator's high-water mark and would pollute the
    // /usr/bin/time -l peak-RSS attribution (m4census precedent).
    if only.is_none() {
        let spec = bench_spec();
        let (_, meta) = build_route_trace(&spec, 0);
        println!(
            "- routing/FS shape: {} routed opened values; {} chained digests; \
             {} FS draws = {} emitted challenges + {} rejected (native \
             rejection rule masked >= p; expected rate (2^24-1)/2^31 ~ 0.78%)",
            meta.routed_values,
            meta.digests.len(),
            meta.emitted.len() + meta.rejected.len(),
            meta.emitted.len(),
            meta.rejected.len(),
        );
    } else {
        println!("(--only set: shape-report trace build skipped for clean RSS attribution)");
    }
    println!();
    println!("| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |");
    println!("|---|---|---|---|---|---|");
    let air = VerifierRouteAir;
    for (name, cfg) in &LANE_CFGS {
        if let Some(f) = only {
            if !name.contains(f) {
                continue;
            }
        }
        let config = make_config_with(cfg);
        eprintln!("== m4route: {name} ==");
        let mut rows = 0;
        let mut best_prove = f64::INFINITY;
        let mut proof_opt = None;
        for _ in 0..RUNS {
            let (trace, _) = build_route_trace(&bench_spec(), cfg.log_blowup);
            rows = trace.height();
            let t = Instant::now();
            let proof = prove(&config, &air, trace, &[]);
            best_prove = best_prove.min(t.elapsed().as_secs_f64() * 1e3);
            proof_opt = Some(proof);
        }
        let proof = proof_opt.expect("RUNS > 0");
        let postcard_bytes = pc_len(&proof);
        let fixed_bytes = bincode::serialize(&proof).expect("bincode").len();
        let mut best_verify = f64::INFINITY;
        for _ in 0..RUNS {
            let t = Instant::now();
            verify(&config, &air, &proof, &[]).expect("verify");
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
         Semantics: routing and FS constraints are real (corrupted witness \
         fails — see the unit tests, incl. a native-challenger cross-check); \
         gate columns are witness in this increment — binding them to the \
         fixed verification schedule, sample_bits draws, ext-challenge \
         assembly, and public binding are increment 4."
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use p3_air::{check_all_constraints, check_constraints};
    use p3_challenger::{CanSample, HashChallenger, SerializingChallenger32};
    use p3_keccak::Keccak256Hash;
    use p3_symmetric::CryptographicHasher;

    use super::*;

    /// 8 perms -> 192 rows -> padded 2^8; all bound rows inside the banks.
    fn small_spec() -> RouteSpec {
        RouteSpec {
            absorb: 2,
            chal: 4,
            compress: 2,
            mul_rows: 160,
            add_rows: 150,
            seed: 42,
            msg_salt: 0,
        }
    }

    /// Positive: consistent routing + packing satisfies every constraint.
    #[test]
    fn routed_rectangle_satisfies() {
        let (trace, meta) = build_route_trace(&small_spec(), 0);
        assert!(!meta.emitted.is_empty(), "schedule must emit challenges");
        assert_eq!(meta.routed_values, 2 * 34, "both channels, both perms");
        check_constraints(&VerifierRouteAir, &trace, &[]);
    }

    /// The FS convention matches the native challenger exactly: digest
    /// chaining is Keccak256Hash re-hashing, and the emitted challenge
    /// sequence equals SerializingChallenger32's sampled base elements
    /// (mask-31-bits + reject-resample, pop-from-digest-end order).
    #[test]
    fn fs_matches_native_challenger() {
        let (_, meta) = build_route_trace(&small_spec(), 0);
        assert_eq!(
            meta.digests[0],
            Keccak256Hash.hash_iter(meta.init_msg.iter().copied()),
            "first digest = keccak-256 of the initial message"
        );
        for i in 1..meta.digests.len() {
            assert_eq!(
                meta.digests[i],
                Keccak256Hash.hash_iter(meta.digests[i - 1].iter().copied()),
                "chained flush {i} rehashes the previous digest"
            );
        }
        let mut ch =
            SerializingChallenger32::<Val, HashChallenger<u8, Keccak256Hash, 32>>::from_hasher(
                meta.init_msg.clone(),
                Keccak256Hash,
            );
        for (k, (_, masked)) in meta.emitted.iter().enumerate() {
            let s: Val = ch.sample();
            assert_eq!(
                s,
                Val::from_u32(*masked),
                "native sample {k} != in-circuit emitted challenge"
            );
        }
    }

    /// Negative 1 (byte/limb mismatch): an injected bank operand that
    /// disagrees with the absorbed limbs must fail. The add-bank row is
    /// kept internally consistent (c = a + b') so ONLY the routing
    /// equality can catch it.
    #[test]
    fn injection_byte_limb_mismatch_detected() {
        let (mut trace, _) = build_route_trace(&small_spec(), 0);
        let row = 5; // absorb perm 0, offset 5: g_inj0 = 1
        assert_eq!(trace.values[row * ROUTE_WIDTH + G_INJ0], Val::ONE);
        trace.values[row * ROUTE_WIDTH + ADD_OFF + 4] += Val::ONE;
        trace.values[row * ROUTE_WIDTH + ADD_OFF + 8] += Val::ONE; // keep c = a + b
        let report = check_all_constraints(&VerifierRouteAir, &trace, &[], Some(10));
        assert!(!report.is_ok(), "byte/limb mismatch not caught");
    }

    /// Negative 2 (tampered digest->challenge): a consumed challenge that
    /// differs from the digest-packed value must fail. The mul row stays
    /// internally consistent so only the emission binding can catch it.
    #[test]
    fn tampered_challenge_detected() {
        let (mut trace, meta) = build_route_trace(&small_spec(), 0);
        let (row, _) = meta.emitted[0];
        let base = row * ROUTE_WIDTH;
        trace.values[base + MUL_OFF] += Val::ONE;
        let a = Ext::from_basis_coefficients_fn(|i| trace.values[base + MUL_OFF + i]);
        let b = Ext::from_basis_coefficients_fn(|i| trace.values[base + MUL_OFF + 4 + i]);
        write_ext(&mut trace.values, row, MUL_OFF + 8, a * b);
        let report = check_all_constraints(&VerifierRouteAir, &trace, &[], Some(10));
        assert!(!report.is_ok(), "tampered challenge not caught");
    }

    /// Negative 3 (out-of-range packing): emitting a draw whose masked
    /// value is >= p must fail. The forgery sets nz = inv = 0 (the only
    /// way to fake accept = 1), which the low24-nonzero guard kills —
    /// exactly the canonicity comparator doing its job.
    #[test]
    fn out_of_range_emission_detected() {
        // Find a salt whose draw window contains a rejection (the small
        // schedule has 24 draws; P(no rejection) ~ 0.83 per salt, so a few
        // tries suffice — the trace is tiny, rebuilding is cheap).
        let mut spec = small_spec();
        let (mut trace, meta) = loop {
            let built = build_route_trace(&spec, 0);
            if !built.1.rejected.is_empty() {
                break built;
            }
            spec.msg_salt += 1;
            assert!(spec.msg_salt < 10_000, "no rejecting salt (p ~ 1e-40)");
        };
        let (row, masked) = meta.rejected[0];
        let base = row * ROUTE_WIDTH;
        // Forge the acceptance path.
        trace.values[base + NZ] = Val::ZERO;
        trace.values[base + INV] = Val::ZERO;
        trace.values[base + ACCEPT] = Val::ONE;
        trace.values[base + G_EMIT] = Val::ONE;
        // Bind the mul row consistently to the forged emission.
        let a = base_ext(masked % P);
        let b = Ext::from_basis_coefficients_fn(|i| trace.values[base + MUL_OFF + 4 + i]);
        write_ext(&mut trace.values, row, MUL_OFF, a);
        write_ext(&mut trace.values, row, MUL_OFF + 8, a * b);
        let report = check_all_constraints(&VerifierRouteAir, &trace, &[], Some(10));
        assert!(!report.is_ok(), "out-of-range emission not caught");
    }

    /// Negative 4 (forged chain): a chain gate asserted across two
    /// unrelated perms must fail the digest-chaining constraint.
    #[test]
    fn forged_chain_gate_detected() {
        let (mut trace, _) = build_route_trace(&small_spec(), 0);
        // Final row of absorb perm 0 -> absorb perm 1 is NOT a chained pair.
        trace.values[23 * ROUTE_WIDTH + CHAIN_GATE] = Val::ONE;
        let report = check_all_constraints(&VerifierRouteAir, &trace, &[], Some(10));
        assert!(!report.is_ok(), "forged chain gate not caught");
    }

    /// The routed rectangle round-trips through the real prover at a
    /// full-security lane config (quotient degree unchanged: all new
    /// constraints are degree <= 3, same as the keccak lane).
    #[test]
    fn prove_verify_roundtrip() {
        let cfg = FriCfg {
            log_blowup: 2,
            num_queries: 40,
            grind_bits: 20,
            log_final_poly_len: 4,
            max_log_arity: 4,
        };
        let config = make_config_with(&cfg);
        let (trace, _) = build_route_trace(&small_spec(), cfg.log_blowup);
        let proof = prove(&config, &VerifierRouteAir, trace, &[]);
        verify(&config, &VerifierRouteAir, &proof, &[]).expect("verify");
    }
}
