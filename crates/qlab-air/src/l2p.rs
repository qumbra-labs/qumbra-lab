//! W3 stage 2 — the L2 transaction circuit family, **shape P** (policy assets:
//! Hybrid / Regulated), lab issue #700, built on the stage-0 and stage-1 rulings.
//!
//! A **new AIR type beside [`crate::l2::L2ShapeSAir`]** — shape S is measured
//! and its width/degree are test-locked, so P is a second fork of the narrow
//! engine (structure for structure, the same discipline `l2.rs` applied to
//! `narrow.rs`), never an edit to S. Pure helpers with identical semantics are
//! imported from `l2` (the registry types, the note block, the input
//! derivation, the fabricated trees) and from `narrow`.
//!
//! ## The statement (l2-own-circuit-decision §2.3, §3; #700 stage-1 ruling)
//!
//! Shape S plus, per input, **always present in the trace** (fixed shape) and
//! gated by the registry leaf's `mode`:
//!
//! - **freeze non-membership**, gadget (a) as RULED: an indexed (sorted) Merkle
//!   tree of depth 20 over frozen **keys** `K = H(rkm ‖ D_FRZ)` (lab #704 Q1:
//!   hashed, so a published freeze list does not hand out addresses). The
//!   prover opens the **low leaf** `(key_lo, key_hi)` and proves
//!   `key_lo < K < key_hi` as two 256-bit comparisons, **bit-serial on
//!   `AFRZ`'s boundary rows** — `K` arrives there as the chained digest
//!   `a[0..4]` (the perms before are `ARKM` → `AFKEY`), `key_lo` rides `W0..3`
//!   and `key_hi` `W5..8`, all three on the same 64 rows. The leaf is
//!   hashed by `AFRZ` and folded by 20 `MERKLE` steps; the fold's root arrives
//!   as the chained digest at **`AREG`'s boundary rows**, where the leaf's
//!   `freeze_root` lanes `W5..8` sit — a same-row bit-serial equality, zero
//!   columns (the census's `AISS` move, applied to the root instead).
//! - **allowlist membership**: `ACRED = H(rkm ‖ D_CRED)` (rkm chained from a
//!   re-derivation `ARKM′`), 20 `MERKLE` steps, the root captured at `BALLOW`'s
//!   boundary and bound to `AREG`'s `allow_root` lanes `W9..12` through **bank 1**
//!   (idle after `ARKM` closes). Off (`mode ≠ Regulated`) ⇒ both legs are gated
//!   out and the path is over a dummy — the trace is still spent.
//! - **`vPublic` per balance row** (row k = input k's asset), public, signed:
//!   `s_k` (0 = mint, 1 = redeem), four 16-bit chunks `m_k`, and `vpa_k`, the
//!   asset id revealed when `m_k ≠ 0` (issuance is public by design). The row's
//!   borrow chain closes on `in − out − [fee] + (1 − 2s)·m = 0`. Under `q`
//!   (one distinct asset) `vPublic₂` must be 0.
//! - **`AISS = H(isk ‖ D_I)`**, one per input, its digest captured at `ARKM`'s
//!   boundary into the **bind bank** and closed against `AREG`'s `issuer_key`
//!   lanes `W0..3` — **required** (`REQ_k`) when the row mints, or redeems an
//!   asset whose `redeem_open` flag is off; otherwise the window is reset
//!   unchecked.
//! - **`mode` read as flags** (ruling): the leaf's `mode` lane is bound bit by
//!   bit to two per-input witness bools `hy_k` (Hybrid, bit 0) / `rg_k`
//!   (Regulated, bit 1), `flags` to `ropen_k` (bit 0 = `redeem_open`); every
//!   other bit is zero. Gates: freeze check ⇔ `hy ∨ rg`; allowlist ⇔ `rg`;
//!   `vPublic ≠ 0 ⇒ hy ∨ rg` — **a Cloaked asset carries `vPublic = 0`**
//!   (the ruling's "Cloaked-with-vPublic=0"; §3.6's "issuer with mint only"
//!   parenthetical is NOT built — recorded in the build notes as a finding).
//!
//! ### Program order (per input `k`; 103 perms each, 214 in all → 2^20)
//!
//! ```text
//! [DUMMY]
//! ANK → NF → BNF_k → AISS → ARKM → AFKEY → AFRZ → 20×MERKLE → AREG → 16×MERKLE → BREG
//!     → ARKM′ → ACRED → 20×MERKLE → BALLOW → ARKM″ → ACM → 32×MERKLE → BANCHOR   (×2)
//! ACMOUT_0 → BCM1 → ARHO → ACMOUT_1 → BCM2 → BAL → END
//! ```
//!
//! **Why three `ARKM`s and how they are bound.** The Keccak chain carries one
//! digest; the freeze key, the credential hash and the note block each
//! need `rkm` chained at their boundary, so `rkm` is derived three times. The
//! second and third (`ROLE_ARKM2`, no bank-1 legs) have free inputs, and their
//! **outputs** are bound to the first's through two sequential equality windows
//! on banks that are idle in the input chain: `rkm@AFKEY − rkm′@ACRED` on the
//! third bank (`EQ3`, idle until the outputs), `rkm′@ACRED − rkm″@ACM` on the
//! bind bank (idle between `BREG` and `BANCHOR`). No new accumulator: every
//! cross-row binding in shape P rides an existing bank's idle span.
//!
//! ### Column accounting over pre-A4 shape S's 702 (+76 → 778; +72 → 774 before lab #704 Q1; A4's P3 +20 → 798; F5-4d's exit edge +6 → 804) — see
//! `l2p_trace_width_is_read_off_the_matrix`, every column named.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

use crate::l2::{
    derive_input_l2_v2, derive_output_rho_l2, fabricated_auth_input, FeeSlotV2, L2AuthInput, L2Version, D_AUTH, ROLE_AAUTH, ROLE_BAUTH, ROLE_NFA, SEL_CODES_V2,
    derive_input_l2, fabricated_registry_tree, l2_cm, L2TxInput, L2TxOutput, RegistryLeaf,
    RegistryWitness, ASSET_BITS, MODE_CLOAKED, MODE_HYBRID, MODE_REGULATED, PV_ANCHOR, PV_CM1,
    PV_CM2, PV_FEE, PV_NF1, PV_NF2, PV_REGROOT, REGISTRY_DEPTH, ROLE_ACM, ROLE_ACMOUT, ROLE_ANK,
    ROLE_AREG, ROLE_ARHO, ROLE_ARKM, ROLE_BAL, ROLE_BANCHOR, ROLE_BCM1, ROLE_BCM2, ROLE_BNF1,
    ROLE_BNF2, ROLE_BREG, ROLE_DUMMY, ROLE_END, ROLE_MERKLE, ROLE_NF, ROLE_BNF3, ROLE_ACMF,
    FeeSlot, dummy_fee_input,
};
use crate::narrow::{
    derive_output_rho, fabricated_shared_tree, fabricated_single_tree, off_tree_witness,
    pv_chunks, MerkleWitness, MERKLE_DEPTH,
};
use crate::reference::{RC, RHO};

// ---------------------------------------------------------------------------
// Column map — the narrow engine verbatim, the M3 machinery at 5-bit codes
// (as `l2.rs`), the ring widened to 53 limbs, then shape S's additions, then
// shape P's.
// ---------------------------------------------------------------------------

const A_OFF: usize = 0;
const C_OFF: usize = 25;
const US_OFF: usize = 30;
const AP_OFF: usize = 55;
const X00_COL: usize = 80;
const S_OFF: usize = 81;
const S_SLOTS: usize = 126;
const V_OFF: usize = S_OFF + S_SLOTS; // 207
const V_SLOTS: usize = 64;
const UV_OFF: usize = V_OFF + V_SLOTS; // 271
const U_OFF: usize = UV_OFF + 25; // 296
const U_SLOTS: usize = 65;
const UU_OFF: usize = U_OFF + U_SLOTS; // 361
const R_OFF: usize = UU_OFF + 10; // 371
const B_OFF: usize = R_OFF + 24; // 395
const PB_OFF: usize = B_OFF + 7; // 402
const PH_OFF: usize = PB_OFF + 24; // 426
/// 63 limbs × 4 slots = 252 program slots: the 252-perm shape-P3 program,
/// an exact fit (A4 added the 38-perm fee chain to P's 214; P's ring was 54
/// limbs, 216 slots, two spare).
const PR_LIMBS: usize = 63;
const PR_OFF: usize = PH_OFF + 4; // 430
const ROLE_BITS: usize = 5;
const D_OFF: usize = PR_OFF + PR_LIMBS; // 493
const RB_OFF: usize = D_OFF + 4 * ROLE_BITS; // 513
const LO_OFF: usize = RB_OFF + ROLE_BITS; // 518
/// Shape S's 16 role selectors + AISS, AFRZ, ACRED, BALLOW, ARKM2, AFKEY,
/// and (A4) BNF3, ACMF.
const NSEL: usize = 24;
const SEL_OFF: usize = LO_OFF + 4; // 522
/// [mrk+nf, ank, arkm+arkm2, acm, acmout, arho, areg, aiss, afrz, acred, afkey, acmf]
const NINJ: usize = 12;
const INJ_OFF: usize = SEL_OFF + NSEL; // 546
const G4_COL: usize = INJ_OFF + NINJ; // 558
const PBIT_COL: usize = G4_COL + 1; // 559
const NW: usize = 15;
const W_OFF: usize = PBIT_COL + 1; // 560
const EQ_OFF: usize = W_OFF + NW; // 575
const EG_OFF: usize = EQ_OFF + 32; // 607
const EP_COL: usize = EG_OFF + 6; // 613
const GWRAP_COL: usize = EP_COL + 1; // 614
const NSE: usize = 8;
const SE_OFF: usize = GWRAP_COL + 1; // 615
const SE_RHO: usize = 6;
const SE_AREG: usize = 7;
const BQ_OFF: usize = SE_OFF + NSE; // 623
const BGCAP_COL: usize = BQ_OFF + 16; // 639
const BGRST_COL: usize = BGCAP_COL + 1; // 640
/// [banchor, bnf1, bnf2, bcm1, bcm2, breg, bnf3 (A4)]
const NBGC: usize = 7;
const BGC_OFF: usize = BGRST_COL + 1;
const BL_OFF: usize = BGC_OFF + NBGC; // 648
const BLC_OFF: usize = BL_OFF + 4; // 652
const BLCLOSE_COL: usize = BLC_OFF + 9; // 661
const INJ3E_COL: usize = BLCLOSE_COL + 1; // 662
const INJ4E_COL: usize = INJ3E_COL + 1; // 663
const EFF_OFF: usize = INJ4E_COL + 1; // 664
const LATCH_COL: usize = EFF_OFF + 25; // 689
const DV_COL: usize = LATCH_COL + 1; // 690
const LDV_COL: usize = DV_COL + 1; // 691
const OM_COL: usize = LDV_COL + 1; // 692
const EQ3_OFF: usize = OM_COL + 1; // 693
const EG3_OFF: usize = EQ3_OFF + 16; // 709
// --- shape S additions (verbatim) ---
const INJRE_COL: usize = EG3_OFF + 3; // 712
const AG_OFF: usize = INJRE_COL + 1; // 713
const AG_IN1: usize = 0;
const AG_IN2: usize = 1;
const AG_O1: usize = 2;
const AG_O2: usize = 3;
const AG_R1: usize = 4;
const AG_R2: usize = 5;
const AC_OFF: usize = AG_OFF + 6; // 719
const SEL2_OFF: usize = AC_OFF + 6; // 725
const S2_O1A: usize = 0;
const S2_O2A: usize = 1;
const S2_F1: usize = 2;
const S2_Q: usize = 3;
const QINV_COL: usize = SEL2_OFF + 4; // 729
const CQ_OFF: usize = QINV_COL + 1; // 730
const SG_OFF: usize = CQ_OFF + 2; // 732
const BL2_OFF: usize = SG_OFF + 2; // 734
const BLC2_OFF: usize = BL2_OFF + 4; // 738
/// Shape S's width, reproduced here with the ring/selector/injection growth:
/// 702 + 22 + 6 + 4 = 734.
const S_END: usize = BLC2_OFF + 9; // 747
// --- shape P additions ---
/// `inj(afrz) · ep` — the comparison's assertion gate (the chained digest on
/// `AFRZ`'s boundary is the freeze key `H(rkm ‖ D_FRZ)`, lab #704 Q1).
const INJ_AFRZE_COL: usize = S_END; // 747
/// `inj(acred) · ep` — the third bank's `−rkm′` leg and the bind bank's `+rkm′`.
const INJ_ACREDE_COL: usize = INJ_AFRZE_COL + 1; // 748
/// `gperm · sel(acred) · ep` — closes and resets the third bank's rkm window.
const CLOSE_CRED_COL: usize = INJ_ACREDE_COL + 1; // 749
/// `bnd · sel(ballow) · ep` — bank 1's `+allow_fold` leg (gated by `ALW`).
const EGB_COL: usize = CLOSE_CRED_COL + 1; // 750
/// `gperm · sel(ballow) · ep` — bank 1's allowlist close.
const EGBC_COL: usize = EGB_COL + 1; // 751
/// `gperm · SE[areg]` — resets the bind bank after the AISS window.
const AREGE_COL: usize = EGBC_COL + 1; // 752
/// `AREGE · RQ` — the AISS window's gated close.
const CRQ_COL: usize = AREGE_COL + 1; // 753
/// `inj(afkey) · ep` — the third bank's `+rkm` leg: `rkm` is the chained
/// digest on `AFKEY`'s boundary (lab #704 Q1 moved the leg here from `AFRZ`,
/// whose boundary now carries the hashed key).
const INJ_AFKEYE_COL: usize = CRQ_COL + 1; // 754
/// Two 256-bit comparisons, bit-serial: `key_lo < K` (block 0) and
/// `K < key_hi` (block 1), `K = H(rkm ‖ D_FRZ)` the freeze key. Per block: 4 running `LT` flags, 4 running `EQ`
/// flags (one per lane, LSB → MSB over z), and 3 materialized lane-combines
/// `C1 = LT1 + EQ1·LT0`, `C2 = LT2 + EQ2·C1`, `C3 = LT3 + EQ3·C2` — `C3` at
/// z = 63 is the 256-bit verdict.
const CMP_OFF: usize = INJ_AFKEYE_COL + 1; // 755
const CMP_BLOCK: usize = 11;
const CMP_LT: usize = 0;
const CMP_EQ: usize = 4;
const CMP_C: usize = 8;
/// Per-input policy witness constants (bool unless noted), each bound
/// in-circuit: `hy`, `rg`, `ropen` (to the leaf's lanes), `nz` (to `Σm`),
/// `vpinv` (field, the nonzero-inverse for `nz`), `REQ = nz·(1 − s·ropen)`;
/// then the two "current input" muxes `RQ` and `ALW`.
const POL_OFF: usize = CMP_OFF + 2 * CMP_BLOCK; // 777
const POL_HY: usize = 0;
const POL_RG: usize = 2;
const POL_ROPEN: usize = 4;
const POL_NZ: usize = 6;
const POL_VPINV: usize = 8;
const POL_REQ: usize = 10;
const POL_RQ: usize = 12;
const POL_ALW: usize = 13;

// --- Shape P3 (A4): the dedicated fee input, as in `l2.rs` ---
/// The fee bank (the fee input's value, four 16-bit chunks), closed at `BAL`
/// against `(1 − d3) · fee`.
const FB_OFF: usize = POL_OFF + 14;
/// `L3` — the fee chain's latch (`BNF3`'s close → the fee chain's `BANCHOR`).
const L3_COL: usize = FB_OFF + 4;
/// `d3` — slot 3 is a dummy (the fee from a row by `f1`) or a real asset-0
/// note worth exactly the fee.
const D3_COL: usize = L3_COL + 1;
/// `L3 · d3` — relaxes the fee chain's anchor bind.
const L3D3_COL: usize = D3_COL + 1;

// --- Lab #785 F5-4d: the asset-0 exit edge ---
/// `z_k = [asset_k = 0]`, per input, bound to the registry leaf's asset lane
/// (`AG_Rk`) at the balance close; held for the whole trace.
const Z_OFF: usize = L3D3_COL + 1;
/// The inverses witnessing `z_k` (0 when the asset is 0).
const ZINV_OFF: usize = Z_OFF + 2;
/// `XE` — this transaction exits: `e_0 + e_1 − e_0·e_1`, `e_k = s_k·z_k·nz_k`
/// (an asset-0 redeem of a nonzero amount). Held.
const XE_COL: usize = ZINV_OFF + 2;
/// `XINV` — the inverse of `Σ xrkm limbs`: an exit's recipient is nonzero.
const XINV_COL: usize = XE_COL + 1;

/// The shape-P3 trace width: P's 778 + 20 (ring +9, two selectors, one
/// injection flag, one bind close, the fee bank, `L3`, `d3`, `L3·d3`), then
/// F5-4d's +6 (`z` ×2, `zinv` ×2, `XE`, `XINV`).
pub const L2P_WIDTH: usize = XINV_COL + 1; // 804
const _: () = assert!(L2P_WIDTH == 804, "the F5-4d census: 798 + 6");

/// Program slots (= perm slots per program period).
pub const PROGRAM_SLOTS: usize = 4 * PR_LIMBS; // 252

// ---------------------------------------------------------------------------
// Version 2 — Candidate A authorization (lab #896 seam C), shape S's v2
// (`l2.rs`, seam B) carried to P. Every v2 column APPENDED after 804; every
// v2 term behind `self.version`, so v1 and `SHAPE_P_DIGEST_V1` are unchanged.
//
// Per input chain the auth path goes BEFORE `AISS` (whose digest `ARKM`'s
// boundary captures into the bind bank, so the two stay adjacent):
//   NFA → BNF_k → AAUTH → (D−1)×MERKLE → BAUTH → AISS → ARKM → AFKEY → …
// All three `rkm` derivations (`ARKM`, `ARKM2` ×2) use v2's message (they
// share `inj(2)`); the second and third are bound to the first by output
// equality as in v1, so the same `auth_root` is forced into each.
// ---------------------------------------------------------------------------

/// v2 program ring: 63 + 9 = 72 limbs, 288 slots (all 288 used at D12).
const PR_LIMBS_V2: usize = 72;
pub const PROGRAM_SLOTS_V2: usize = 4 * PR_LIMBS_V2;
const XR_OFF: usize = L2P_WIDTH; // 804
const XR_LIMBS: usize = PR_LIMBS_V2 - PR_LIMBS;
const SELV2_OFF: usize = XR_OFF + XR_LIMBS; // 813
const SEV2_OFF: usize = SELV2_OFF + 3; // 816
const INJV2_OFF: usize = SEV2_OFF + 3; // 819
const EGN_COL: usize = INJV2_OFF + 2; // 821
const EGL_POS_COL: usize = EGN_COL + 1; // 822
const EGL_CLOSE_COL: usize = EGL_POS_COL + 1; // 823
const EQL_OFF: usize = EGL_CLOSE_COL + 1; // 824: 16
const EGA_POS_COL: usize = EQL_OFF + 16; // 840
const EQA_OFF: usize = EGA_POS_COL + 1; // 841: 16
/// The shape-P v2 trace width.
pub const L2P_WIDTH_V2: usize = EQA_OFF + 16; // 857

// ---------------------------------------------------------------------------
// Version 3 — the third output (lab #937, D1 route 1), shape S's v3 (`l2.rs`)
// carried to P: the same tail, `OM2`, `AG_O3`/`AC_O3`/`o3a`/`SG3`, appended
// after 857. v1 and v2 unchanged.
// ---------------------------------------------------------------------------

/// v3 program ring: 72 + 1 = 73 limbs, 292 slots (291 used at D12).
const PR_LIMBS_V3: usize = PR_LIMBS_V2 + 1;
/// v3 program period.
pub const PROGRAM_SLOTS_V3: usize = 4 * PR_LIMBS_V3;
const XR3_COL: usize = L2P_WIDTH_V2; // 857
const OM2_COL: usize = XR3_COL + 1; // 858
const AG_O3_COL: usize = OM2_COL + 1; // 859
const AC_O3_COL: usize = AG_O3_COL + 1; // 860
const SEL_O3A_COL: usize = AC_O3_COL + 1; // 861
const SG3_COL: usize = SEL_O3A_COL + 1; // 862
/// `o3f` (lab #937 A′): output 3 is charged to the fee bank (shape S's
/// `O3F_COL`, verbatim): the slot-3 fee note pays `fee + v(O3)`.
const O3F_COL: usize = SG3_COL + 1; // 863
/// `AG[o3] · o3f`.
const SF3_COL: usize = O3F_COL + 1; // 864
/// The fee bank's carry encodings (v3): three carries, 2 bits each, `c + 2`.
const FBC_OFF: usize = SF3_COL + 1; // 865: 6
/// The shape-P v3 trace width.
pub const L2P_WIDTH_V3: usize = FBC_OFF + 6; // 871

// Role codes 0..=16 are `l2.rs`'s (re-exported through the imports above);
// 17..=22 are shape P's.
/// `issuer_key = H(isk ‖ D_I)`: isk = W0..4, D_I at lane 4 bit 7, pad at lane 5.
pub const ROLE_AISS: u32 = 17;
/// Freeze low leaf `H(key_lo ‖ key_hi)`: key_lo = W0..4 at lanes 0..4, key_hi
/// = W5..9 at lanes 4..8, leaf marker at lane 8 bit 3 (≠ the Merkle node's
/// pad at bit 0, so a leaf never collides with an interior node). The chained
/// digest `a[0..4]` on its boundary rows is the freeze key
/// `K = H(rkm ‖ D_FRZ)` (from `AFKEY`) — compared, not absorbed.
pub const ROLE_AFRZ: u32 = 18;
/// `cred = H(rkm ‖ D_CRED)`: rkm = chained a[0..4], D_CRED at lane 4 bit 15,
/// pad at lane 5.
pub const ROLE_ACRED: u32 = 19;
/// Allow-fold capture point: no injection; bank 1 captures `a[0..4]` (the
/// depth-20 fold's root) on its boundary rows.
pub const ROLE_BALLOW: u32 = 20;
/// `rkm` re-derivation: `ARKM`'s message, no bank-1 legs.
pub const ROLE_ARKM2: u32 = 21;
/// The freeze key `K = H(rkm ‖ D_FRZ)`: rkm = chained a[0..4], **D_FRZ at
/// lane 4 bit 31**, pad at lane 5 — `ACRED`'s block with the next domain bit
/// (D_I = bit 7, D_CRED = bit 15, D_FRZ = bit 31; lab #704 Q1). The freeze
/// tree is keyed by `K`, never by the raw `rkm`: a published freeze list
/// tells a reader nothing about an address it does not already hold.
pub const ROLE_AFKEY: u32 = 22;

const SEL_CODES: [u32; NSEL] = [
    ROLE_MERKLE,
    ROLE_NF,
    ROLE_ANK,
    ROLE_ARKM,
    ROLE_ACM,
    ROLE_ACMOUT,
    ROLE_BANCHOR,
    ROLE_BNF1,
    ROLE_BNF2,
    ROLE_BCM1,
    ROLE_BCM2,
    ROLE_BAL,
    ROLE_END,
    ROLE_ARHO,
    ROLE_AREG,
    ROLE_BREG,
    ROLE_AISS,
    ROLE_AFRZ,
    ROLE_ACRED,
    ROLE_BALLOW,
    ROLE_ARKM2,
    ROLE_AFKEY,
    ROLE_BNF3,
    ROLE_ACMF,
];
const SEL_ARHO: usize = 13;
const SEL_AREG: usize = 14;
const SEL_BREG: usize = 15;
const SEL_AISS: usize = 16;
const SEL_AFRZ: usize = 17;
const SEL_ACRED: usize = 18;
const SEL_BALLOW: usize = 19;
const SEL_ARKM2: usize = 20;
const SEL_AFKEY: usize = 21;
const SEL_BNF3: usize = 22;
const SEL_ACMF: usize = 23;
const INJ_AISS: usize = 7;
const INJ_AFRZ: usize = 8;
const INJ_ACRED: usize = 9;
const INJ_AFKEY: usize = 10;
const INJ_ACMF: usize = 11;

/// Registry `flags` bit 0: holders may redeem without the issuer key.
pub const FLAG_REDEEM_OPEN: u64 = 1;

/// Public values: shape S's 100, then `vPublic` per balance row: `s` (sign,
/// 1 = redeem), `m` (4 × 16-bit chunks), `vpa` (the asset id, bound when
/// `m ≠ 0`, 0 by convention otherwise).
pub const PV_VP1: usize = 100;
pub const PV_VP2: usize = 106;
/// A4: the fee input's nullifier, appended (every earlier offset holds).
pub const PV_NF3: usize = 112;
/// Lab #785 F5-4d: the exit recipient `rkm` (16 × 16-bit words), appended —
/// zero unless the transaction exits, nonzero when it does. One per
/// transaction (ruling Q-4d-1): both exit rows pay it.
pub const PV_XRKM: usize = 128;
pub const PV_LEN: usize = 144;
/// v2: each slot's public authorization leaf (16 chunks each), appended.
pub const PV_LEAF1: usize = 144;
pub const PV_LEAF2: usize = 160;
pub const PV_LEAF3: usize = 176;
pub const PV_LEN_V2: usize = 192;
/// v3: the third output commitment (16 chunks), appended.
pub const PV_CM3: usize = 192;
pub const PV_LEN_V3: usize = 208;
const fn pv_vp_sign(k: usize) -> usize {
    PV_VP1 + 6 * k
}
const fn pv_vp_chunk(k: usize, j: usize) -> usize {
    PV_VP1 + 6 * k + 1 + j
}
const fn pv_vp_asset(k: usize) -> usize {
    PV_VP1 + 6 * k + 5
}

/// One row's public `vPublic` term.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VPublic {
    /// `true` = redeem (`−amount`), `false` = mint (`+amount`).
    pub redeem: bool,
    pub amount: u64,
}

impl VPublic {
    pub const NONE: VPublic = VPublic { redeem: false, amount: 0 };
    pub fn mint(amount: u64) -> Self {
        Self { redeem: false, amount }
    }
    pub fn redeem(amount: u64) -> Self {
        Self { redeem: true, amount }
    }
}

/// Build the full public-value vector for a shape-P instance. `vpa[k]` is the
/// asset revealed on row k (0 when that row's `vPublic` is 0).
#[allow(clippy::too_many_arguments)]
pub fn pv_vec_l2p(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm1: &[u64; 4],
    cm2: &[u64; 4],
    fee: u64,
    registry_root: &[u64; 4],
    vp: &[VPublic; 2],
    vpa: &[u64; 2],
    nf3: &[u64; 4],
    xrkm: &[u64; 4],
) -> Vec<u32> {
    let mut out = Vec::with_capacity(PV_LEN);
    for d in [anchor, nf1, nf2, cm1, cm2] {
        out.extend_from_slice(&pv_chunks(d));
    }
    for j in 0..4 {
        out.push(((fee >> (16 * j)) & 0xffff) as u32);
    }
    out.extend_from_slice(&pv_chunks(registry_root));
    for k in 0..2 {
        out.push(vp[k].redeem as u32);
        for j in 0..4 {
            out.push(((vp[k].amount >> (16 * j)) & 0xffff) as u32);
        }
        out.push(vpa[k] as u32);
    }
    out.extend_from_slice(&pv_chunks(nf3));
    out.extend_from_slice(&pv_chunks(xrkm));
    assert_eq!(out.len(), PV_LEN);
    out
}

/// v2: [`pv_vec_l2p`] followed by the three slots' authorization leaves.
#[allow(clippy::too_many_arguments)]
pub fn pv_vec_l2p_v2(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm1: &[u64; 4],
    cm2: &[u64; 4],
    fee: u64,
    registry_root: &[u64; 4],
    vp: &[VPublic; 2],
    vpa: &[u64; 2],
    nf3: &[u64; 4],
    xrkm: &[u64; 4],
    leaves: &[[u64; 4]; 3],
) -> Vec<u32> {
    let mut out = pv_vec_l2p(anchor, nf1, nf2, cm1, cm2, fee, registry_root, vp, vpa, nf3, xrkm);
    for leaf in leaves {
        out.extend_from_slice(&pv_chunks(leaf));
    }
    debug_assert_eq!(out.len(), PV_LEN_V2);
    out
}

/// v3: [`pv_vec_l2p_v2`] followed by the third output commitment.
#[allow(clippy::too_many_arguments)]
pub fn pv_vec_l2p_v3(
    anchor: &[u64; 4],
    nf1: &[u64; 4],
    nf2: &[u64; 4],
    cm_out: &[[u64; 4]; 3],
    fee: u64,
    registry_root: &[u64; 4],
    vp: &[VPublic; 2],
    vpa: &[u64; 2],
    nf3: &[u64; 4],
    xrkm: &[u64; 4],
    leaves: &[[u64; 4]; 3],
) -> Vec<u32> {
    let mut out =
        pv_vec_l2p_v2(anchor, nf1, nf2, &cm_out[0], &cm_out[1], fee, registry_root, vp, vpa, nf3, xrkm, leaves);
    out.extend_from_slice(&pv_chunks(&cm_out[2]));
    debug_assert_eq!(out.len(), PV_LEN_V3);
    out
}

/// Freeze-tree depth (l2-own-circuit-decision §3.2; an L2 parameter).
pub const FREEZE_DEPTH: usize = 20;
/// Allowlist depth (§3.4; an L2 parameter).
pub const ALLOW_DEPTH: usize = 20;
/// Policy-tree depth: both are 20 in W3, one witness type serves both.
pub const POLICY_DEPTH: usize = 20;

const fn s_col(d: usize) -> usize {
    S_OFF + d - 1
}
const fn v_col(d: usize) -> usize {
    V_OFF + d - 1
}
const fn u_col(d: usize) -> usize {
    U_OFF + d - 1
}

const fn inv_pi() -> [usize; 25] {
    let mut out = [0usize; 25];
    let mut bx = 0;
    while bx < 5 {
        let mut by = 0;
        while by < 5 {
            let y = bx;
            let x = (3 * (by + 15 - 3 * bx)) % 5;
            out[bx + 5 * by] = x + 5 * y;
            by += 1;
        }
        bx += 1;
    }
    out
}
const INV_PI: [usize; 25] = inv_pi();

// ---------------------------------------------------------------------------
// The AIR
// ---------------------------------------------------------------------------

/// Per-perm-slot witness: 15 generic 64-bit lanes plus the merkle path bit.
#[derive(Clone, Copy)]
pub struct L2PSlotWitness {
    pub w: [u64; NW],
    pub pbit: bool,
}

impl Default for L2PSlotWitness {
    fn default() -> Self {
        Self { w: [0; NW], pbit: false }
    }
}

/// Shape P of the L2 circuit family.
#[cfg_attr(test, derive(Clone))] // the test fan-out needs owned copies; non-test build unchanged
pub struct L2ShapePAir {
    pub log_height: usize,
    /// v1 (today's P3) or v2 (Candidate A authorization).
    pub version: L2Version,
    /// Role per program slot; the period is the length (252 v1, 288 v2).
    pub program: Vec<u32>,
    pub slot_witness: Vec<L2PSlotWitness>,
    pub fee: u64,
    pub dv: bool,
    pub sel_o1a: bool,
    pub sel_o2a: bool,
    pub sel_f1: bool,
    pub sel_q: bool,
    /// Per input: the leaf's mode read as flags (bound bit by bit to the
    /// `mode` lane at `AREG`), and `redeem_open` (bound to `flags` bit 0).
    pub hy: [bool; 2],
    pub rg: [bool; 2],
    pub ropen: [bool; 2],
    /// Per row: the public `vPublic` (the trace needs it for the carries and
    /// for `nz`/`vpinv`).
    pub vp: [VPublic; 2],
    /// A4: slot 3 (the fee input) is a dummy — the fee is charged to a row.
    pub d3: bool,
    /// Lab #785 F5-4d: the two inputs' assets (the trace's `z`/`zinv`) and
    /// the exit recipient (`XE`/`XINV`); the public values carry the recipient.
    pub asset: [u64; 2],
    pub xrkm: [u64; 4],
    /// v3: output 2 (the third) is accounted in row 1. Ignored below v3.
    pub sel_o3a: bool,
    /// v3 (lab #937 A′): output 2 (the third) is charged to the fee bank.
    pub sel_o3f: bool,
}

impl L2ShapePAir {
    /// Every perm slot dummy, pure chaining — the geometry probe / canary.
    pub fn chain_only(log_height: usize) -> Self {
        Self {
            log_height,
            version: L2Version::V1,
            program: vec![ROLE_DUMMY; PROGRAM_SLOTS],
            slot_witness: Vec::new(),
            fee: 0,
            dv: false,
            sel_o1a: true,
            sel_o2a: true,
            sel_f1: true,
            sel_q: true,
            hy: [false; 2],
            rg: [false; 2],
            ropen: [false; 2],
            vp: [VPublic::NONE; 2],
            d3: true,
            asset: [0; 2],
            xrkm: [0; 4],
            sel_o3a: true,
            sel_o3f: false,
        }
    }

    /// The v2 geometry probe: every slot dummy, v2 width and ring.
    pub fn chain_only_v2(log_height: usize) -> Self {
        Self {
            version: L2Version::V2Auth,
            program: vec![ROLE_DUMMY; PROGRAM_SLOTS_V2],
            ..Self::chain_only(log_height)
        }
    }

    /// The v3 geometry probe: every slot dummy, v3 width and ring.
    pub fn chain_only_v3(log_height: usize) -> Self {
        Self {
            version: L2Version::V3,
            program: vec![ROLE_DUMMY; PROGRAM_SLOTS_V3],
            ..Self::chain_only(log_height)
        }
    }

    /// Carries the Candidate A authorization columns (v2 and v3).
    pub fn is_v2(&self) -> bool {
        matches!(self.version, L2Version::V2Auth | L2Version::V3)
    }

    /// Carries the third output (v3).
    pub fn is_v3(&self) -> bool {
        self.version == L2Version::V3
    }

    fn ring_limbs(&self) -> usize {
        match self.version {
            L2Version::V1 => PR_LIMBS,
            L2Version::V2Auth => PR_LIMBS_V2,
            L2Version::V3 => PR_LIMBS_V3,
        }
    }

    fn ring_col(i: usize) -> usize {
        if i < PR_LIMBS {
            PR_OFF + i
        } else if i < PR_LIMBS_V2 {
            XR_OFF + (i - PR_LIMBS)
        } else {
            XR3_COL
        }
    }

    fn pr_limb(&self, i: usize) -> u32 {
        (0..4)
            .map(|j| self.program[(4 * i + j) % self.program.len()] << (ROLE_BITS * j))
            .sum()
    }

    fn rc_bit(t: usize) -> bool {
        let z = t % 64;
        let mrow = (t / 64) % 2 == 0;
        if !mrow {
            return false;
        }
        let q = t / 128;
        (RC[(q + 23) % 24] >> z) & 1 == 1
    }

    fn rc_pack(j: usize) -> u32 {
        (0..7)
            .map(|k| (((RC[j] >> ((1u32 << k) - 1)) & 1) as u32) << k)
            .sum()
    }
}

const NPERIODIC: usize = 40;
const PER_LO16: usize = 39;

impl<F: Field> BaseAir<F> for L2ShapePAir {
    fn width(&self) -> usize {
        match self.version {
            L2Version::V1 => L2P_WIDTH,
            L2Version::V2Auth => L2P_WIDTH_V2,
            L2Version::V3 => L2P_WIDTH_V3,
        }
    }

    fn num_public_values(&self) -> usize {
        match self.version {
            L2Version::V1 => PV_LEN,
            L2Version::V2Auth => PV_LEN_V2,
            L2Version::V3 => PV_LEN_V3,
        }
    }

    fn num_periodic_columns(&self) -> usize {
        NPERIODIC
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        let mut cols = vec![Vec::with_capacity(128); NPERIODIC];
        for t in 0..128usize {
            let mrow = t < 64;
            cols[0].push(F::from_bool(mrow));
            cols[1].push(F::from_bool(t == 63));
            for l in 0..25 {
                let wrap = !mrow && (t - 64) + RHO[l] as usize >= 64;
                cols[2 + l].push(F::from_bool(wrap));
            }
            cols[27].push(F::from_bool(t == 127));
            for k in 0..7 {
                cols[28 + k].push(F::from_bool(mrow && t == (1 << k) - 1));
            }
            let z = t % 64;
            for j in 0..4 {
                let v = if z / 16 == j {
                    F::from_u32(1 << (z % 16))
                } else {
                    F::ZERO
                };
                cols[35 + j].push(v);
            }
            cols[PER_LO16].push(F::from_bool(z < ASSET_BITS));
        }
        cols
    }
}

fn xor2<E: Clone + core::ops::Add<Output = E> + core::ops::Sub<Output = E> + core::ops::Mul<Output = E>>(
    a: E,
    b: E,
    two: E,
) -> E {
    a.clone() + b.clone() - two * a * b
}

impl<AB: AirBuilder> Air<AB> for L2ShapePAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let two = AB::Expr::TWO;

        let main = builder.main();
        let local: Vec<AB::Expr> = main.current_slice().iter().map(|v| (*v).into()).collect();
        let next: Vec<AB::Expr> = main.next_slice().iter().map(|v| (*v).into()).collect();

        let per: Vec<AB::Expr> = builder
            .periodic_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let mrow = per[0].clone();
        let u63 = per[1].clone();
        let e1 = |l: usize| per[2 + l].clone();
        let blast = per[27].clone();
        let sel = |k: usize| per[28 + k].clone();
        let lo16 = per[PER_LO16].clone();
        let trow = AB::Expr::ONE - mrow.clone();

        let rc = (0..7)
            .map(|k| sel(k) * local[B_OFF + k].clone())
            .fold(AB::Expr::ZERO, |acc, e| acc + e);

        let a = |l: usize| local[A_OFF + l].clone();
        let eff = |l: usize| local[EFF_OFF + l].clone();
        let c = |x: usize| local[C_OFF + x].clone();
        let us = |l: usize| local[US_OFF + l].clone();
        let ap = |l: usize| local[AP_OFF + l].clone();
        let uv = |l: usize| local[UV_OFF + l].clone();
        let uu = |i: usize| local[UU_OFF + i].clone();
        let x00 = local[X00_COL].clone();

        // --- Same-row constraints: the Keccak engine (verbatim) ---
        for l in 0..25 {
            builder.assert_bool(local[US_OFF + l].clone());
            builder.assert_bool(local[UV_OFF + l].clone());
        }
        for i in 0..10 {
            builder.assert_bool(local[UU_OFF + i].clone());
        }
        for x in 0..5 {
            builder.assert_bool(local[C_OFF + x].clone());
        }
        let weighted = |off: usize, n: usize, row: &[AB::Expr]| -> AB::Expr {
            (0..n)
                .map(|i| row[off + i].clone() * AB::Expr::from_u32(1 << i))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        builder.assert_eq(weighted(US_OFF, 25, &local), local[s_col(1)].clone());
        builder.assert_eq(weighted(UV_OFF, 25, &local), local[v_col(1)].clone());
        builder.assert_eq(weighted(UU_OFF, 10, &local), local[u_col(1)].clone());

        let b = |bx: usize, by: usize| us(INV_PI[bx + 5 * by]);
        let chi = |x: usize, y: usize| -> AB::Expr {
            let b0 = b(x, y);
            let b1 = b((x + 1) % 5, y);
            let b2 = b((x + 2) % 5, y);
            let and = (AB::Expr::ONE - b1) * b2;
            xor2(b0, and, two.clone())
        };
        for y in 0..5 {
            for x in 0..5 {
                if (x, y) != (0, 0) {
                    builder.assert_eq(a(x + 5 * y), chi(x, y));
                }
            }
        }
        builder.assert_eq(x00.clone(), chi(0, 0));
        builder.assert_eq(a(0), xor2(x00, rc, two.clone()));

        for x in 0..5 {
            let s = (0..5)
                .map(|y| eff(x + 5 * y))
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            let d = s - c(x);
            builder.assert_zero(
                d.clone() * (d.clone() - two.clone()) * (d - two.clone() * two.clone()),
            );
        }

        for y in 0..5 {
            for x in 0..5 {
                let p = uv(x + 5 * y);
                let q = uu((x + 4) % 5);
                let r = uu(5 + (x + 1) % 5);
                let xor3 = p.clone() + q.clone() + r.clone()
                    - two.clone() * (p.clone() * q.clone() + p.clone() * r.clone() + q.clone() * r.clone())
                    + two.clone() * two.clone() * p * q * r;
                builder.assert_eq(ap(x + 5 * y), xor3);
            }
        }

        // --- Program machinery (5-bit codes, 53-limb ring) ---
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[PB_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..4 {
            builder.when_first_row().assert_eq(
                local[PH_OFF + i].clone(),
                if i == 0 { AB::Expr::ONE } else { AB::Expr::ZERO },
            );
        }
        for i in 0..self.ring_limbs() {
            builder.when_first_row().assert_eq(
                local[Self::ring_col(i)].clone(),
                AB::Expr::from_u32(self.pr_limb(i)),
            );
        }
        for k in 0..4 * ROLE_BITS {
            builder.assert_bool(local[D_OFF + k].clone());
        }
        builder.assert_eq(weighted(D_OFF, 4 * ROLE_BITS, &local), local[PR_OFF].clone());
        for k in 0..ROLE_BITS {
            let sel_quarter = (0..4)
                .map(|phi| {
                    local[PH_OFF + (4 - phi) % 4].clone()
                        * local[D_OFF + ROLE_BITS * phi + k].clone()
                })
                .fold(AB::Expr::ZERO, |acc, e| acc + e);
            builder.assert_eq(local[RB_OFF + k].clone(), sel_quarter);
        }
        let r = |k: usize| local[RB_OFF + k].clone();
        let pair = |b0: AB::Expr, b1: AB::Expr, j: u32| -> AB::Expr {
            let t0 = if j & 1 == 1 { b0 } else { AB::Expr::ONE - b0 };
            let t1 = if j & 2 == 2 { b1 } else { AB::Expr::ONE - b1 };
            t0 * t1
        };
        for j in 0..4u32 {
            builder.assert_eq(local[LO_OFF + j as usize].clone(), pair(r(0), r(1), j));
        }
        for (i, code) in SEL_CODES.iter().enumerate() {
            let lo = local[LO_OFF + (code & 3) as usize].clone();
            let hi = pair(r(2), r(3), (code >> 2) & 3);
            let top = if (code >> 4) & 1 == 1 {
                r(4)
            } else {
                AB::Expr::ONE - r(4)
            };
            builder.assert_eq(local[SEL_OFF + i].clone(), lo * hi * top);
        }
        let sel_role = |i: usize| local[SEL_OFF + i].clone();
        let bnd = mrow.clone() * local[PB_OFF].clone();
        builder.assert_eq(
            local[INJ_OFF].clone(),
            bnd.clone() * (sel_role(0) + sel_role(1)),
        );
        builder.assert_eq(local[INJ_OFF + 1].clone(), bnd.clone() * sel_role(2));
        // ARKM and ARKM2 share the injection class (the message is the same);
        // only ARKM carries bank-1 legs.
        builder.assert_eq(
            local[INJ_OFF + 2].clone(),
            bnd.clone() * (sel_role(3) + sel_role(SEL_ARKM2)),
        );
        for i in 3..5 {
            builder.assert_eq(
                local[INJ_OFF + i].clone(),
                bnd.clone() * sel_role(i + 1),
            );
        }
        builder.assert_eq(local[INJ_OFF + 5].clone(), bnd.clone() * sel_role(SEL_ARHO));
        builder.assert_eq(local[INJ_OFF + 6].clone(), bnd.clone() * sel_role(SEL_AREG));
        builder.assert_eq(local[INJ_OFF + INJ_AISS].clone(), bnd.clone() * sel_role(SEL_AISS));
        builder.assert_eq(local[INJ_OFF + INJ_AFRZ].clone(), bnd.clone() * sel_role(SEL_AFRZ));
        builder.assert_eq(local[INJ_OFF + INJ_ACRED].clone(), bnd.clone() * sel_role(SEL_ACRED));
        builder.assert_eq(local[INJ_OFF + INJ_AFKEY].clone(), bnd.clone() * sel_role(SEL_AFKEY));
        // P3 (A4): the fee input's note block, its own injection class.
        builder.assert_eq(local[INJ_OFF + INJ_ACMF].clone(), bnd.clone() * sel_role(SEL_ACMF));
        builder.assert_eq(
            local[G4_COL].clone(),
            blast.clone() * local[PB_OFF + 1].clone() * local[PH_OFF + 1].clone(),
        );
        builder.assert_bool(local[PBIT_COL].clone());
        // The NF path-bit fix: NF absorbs through the Merkle mux, whose path bit would swap
        // (nk ‖ ρ) into (ρ ‖ nk) — a second nullifier for the same note. NF's
        // operand order is fixed: PBIT is 0 on every NF row (it is constant
        // within a perm, so this covers the boundary rows; degree 2).
        builder.assert_zero(local[SEL_OFF + 1].clone() * local[PBIT_COL].clone());
        for i in 0..NW {
            builder.assert_bool(local[W_OFF + i].clone());
        }
        let pbit = local[PBIT_COL].clone();
        let w = |i: usize| local[W_OFF + i].clone();
        let inj = |i: usize| local[INJ_OFF + i].clone();
        for l in 0..25 {
            let msg_mrk: AB::Expr = match l {
                0..=3 => pbit.clone() * w(l) + (AB::Expr::ONE - pbit.clone()) * a(l),
                4..=7 => {
                    pbit.clone() * a(l - 4) + (AB::Expr::ONE - pbit.clone()) * w(l - 4)
                }
                8 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_ank: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(0),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_arkm: AB::Expr = if self.is_v2() {
                // v2: nk ‖ D_R ‖ d ‖ auth_root, pad lane 11 — for ARKM and both
                // ARKM2s (one injection class).
                match l {
                    0..=3 => w(l),
                    4 => sel(1),
                    5 => w(5),
                    6 => w(6),
                    7..=10 => w(l),
                    11 => sel(0),
                    16 => u63.clone(),
                    _ => AB::Expr::ZERO,
                }
            } else {
                match l {
                    0..=3 => w(l),
                    4 => sel(1),
                    5 => w(5),
                    6 => w(6),
                    7 => sel(0),
                    16 => u63.clone(),
                    _ => AB::Expr::ZERO,
                }
            };
            let msg_acm: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => a(l - 2),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_acmout: AB::Expr = match l {
                0 => w(4),
                1 => w(13),
                2..=5 => w(l - 2),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_arho: AB::Expr = match l {
                0..=3 => w(l + 5),
                // v3: D_P = 8 for ρ′₁, 9 for ρ′₂ (after the first `BCM2`).
                4 if self.is_v3() => sel(2) + local[OM2_COL].clone() * sel(0),
                4 => sel(2),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let msg_areg: AB::Expr = match l {
                0 => w(13),
                1..=4 => w(l - 1),
                5 => w(4),
                6..=9 => w(l - 1),
                10..=13 => w(l - 1),
                14 => w(14),
                15 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // AISS: isk = W0..4, D_I = lane 4 bit 7, pad at lane 5.
            let msg_aiss: AB::Expr = match l {
                0..=3 => w(l),
                4 => sel(3),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // AFRZ: the low leaf `key_lo ‖ key_hi`, leaf marker lane 8 bit 3.
            let msg_afrz: AB::Expr = match l {
                0..=3 => w(l),
                4..=7 => w(l + 1),
                8 => sel(2),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // ACRED: rkm chained, D_CRED = lane 4 bit 15, pad at lane 5.
            let msg_acred: AB::Expr = match l {
                0..=3 => a(l),
                4 => sel(4),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            // AFKEY: rkm chained, D_FRZ = lane 4 bit 31, pad at lane 5.
            let msg_afkey: AB::Expr = match l {
                0..=3 => a(l),
                4 => sel(5),
                5 => sel(0),
                16 => u63.clone(),
                _ => AB::Expr::ZERO,
            };
            let mut expr = a(l)
                + inj(0) * (msg_mrk - a(l))
                + inj(1) * (msg_ank - a(l))
                + inj(2) * (msg_arkm - a(l))
                + inj(3) * (msg_acm.clone() - a(l))
                + inj(INJ_ACMF) * (msg_acm - a(l))
                + inj(4) * (msg_acmout - a(l))
                + inj(5) * (msg_arho - a(l))
                + inj(6) * (msg_areg - a(l))
                + inj(INJ_AISS) * (msg_aiss - a(l))
                + inj(INJ_AFRZ) * (msg_afrz - a(l))
                + inj(INJ_ACRED) * (msg_acred - a(l))
                + inj(INJ_AFKEY) * (msg_afkey - a(l));
            if self.is_v2() {
                // NFA: nk (W9..12) ‖ ρ (W0..3); AAUTH: leaf W0..3 / sibling
                // W4..7 by the path bit (shape S v2's messages verbatim).
                let msg_nfa: AB::Expr = match l {
                    0..=3 => w(l + 9),
                    4..=7 => w(l - 4),
                    8 => sel(0),
                    16 => u63.clone(),
                    _ => AB::Expr::ZERO,
                };
                let msg_aauth: AB::Expr = match l {
                    0..=3 => pbit.clone() * w(l + 4) + (AB::Expr::ONE - pbit.clone()) * w(l),
                    4..=7 => pbit.clone() * w(l - 4) + (AB::Expr::ONE - pbit.clone()) * w(l),
                    8 => sel(0),
                    16 => u63.clone(),
                    _ => AB::Expr::ZERO,
                };
                expr = expr
                    + local[INJV2_OFF].clone() * (msg_nfa - a(l))
                    + local[INJV2_OFF + 1].clone() * (msg_aauth - a(l));
            }
            builder.assert_eq(eff(l), expr);
        }

        // --- Equality banks 1 and 2 (the S gates verbatim) ---
        let gperm = blast.clone() * local[PB_OFF + 1].clone();
        builder.assert_eq(local[EG_OFF].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 1].clone(),
            bnd.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 2].clone(),
            gperm.clone() * local[SE_OFF + 1].clone(),
        );
        builder.assert_eq(local[EG_OFF + 3].clone(), bnd.clone() * local[SE_OFF].clone());
        builder.assert_eq(
            local[EG_OFF + 4].clone(),
            bnd.clone() * local[SE_OFF + 2].clone(),
        );
        builder.assert_eq(
            local[EG_OFF + 5].clone(),
            gperm.clone() * local[SE_OFF + 2].clone(),
        );
        for j in 0..16 {
            builder.assert_zero(local[EG_OFF + 2].clone() * local[EQ_OFF + j].clone());
            builder
                .assert_zero(local[EG_OFF + 5].clone() * local[EQ_OFF + 16 + j].clone());
        }
        for j in 0..32 {
            builder.when_first_row().assert_zero(local[EQ_OFF + j].clone());
        }

        // --- Epoch, ep-gated selectors, bind bank ---
        let ep = local[EP_COL].clone();
        builder.when_first_row().assert_eq(ep.clone(), AB::Expr::ONE);
        builder.assert_eq(
            local[GWRAP_COL].clone(),
            gperm.clone() * sel_role(12),
        );
        let se_src: [usize; 4] = [1, 3, 4, 5]; // nf, arkm, acm, acmout
        for (i, si) in se_src.iter().enumerate() {
            // A4: `ACMF` closes bank 2 like `ACM` — `SE[acm]` counts both.
            let s_i = if i == 2 { sel_role(*si) + sel_role(SEL_ACMF) } else { sel_role(*si) };
            builder.assert_eq(local[SE_OFF + i].clone(), s_i * ep.clone());
        }
        let bindsum = sel_role(6)
            + sel_role(7)
            + sel_role(8)
            + sel_role(9)
            + sel_role(10)
            + sel_role(SEL_BREG)
            + sel_role(SEL_BNF3);
        builder.assert_eq(local[SE_OFF + 4].clone(), bindsum * ep.clone());
        builder.assert_eq(local[SE_OFF + 5].clone(), sel_role(11) * ep.clone());
        builder.assert_eq(
            local[SE_OFF + SE_RHO].clone(),
            (sel_role(SEL_ARHO) + sel_role(5)) * ep.clone(),
        );
        builder.assert_eq(
            local[SE_OFF + SE_AREG].clone(),
            sel_role(SEL_AREG) * ep.clone(),
        );
        builder.assert_eq(
            local[BGCAP_COL].clone(),
            bnd.clone() * local[SE_OFF + 4].clone(),
        );
        builder.assert_eq(
            local[BGRST_COL].clone(),
            gperm.clone() * local[SE_OFF + 4].clone(),
        );
        for (i, si) in [6usize, 7, 8, 9, 10, SEL_BREG, SEL_BNF3].iter().enumerate() {
            builder.assert_eq(
                local[BGC_OFF + i].clone(),
                gperm.clone() * sel_role(*si),
            );
        }
        let pvs: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|v| (*v).into())
            .collect();
        let pv = |i: usize| -> AB::Expr { pvs[i].clone() };
        let pv_base: [usize; NBGC] = [PV_ANCHOR, PV_NF1, PV_NF2, PV_CM1, PV_CM2, PV_REGROOT, PV_NF3];
        for (x, base) in pv_base.iter().enumerate() {
            for j in 0..16 {
                // v3: the second `BCM2` (after `OM2` is set) binds output 3.
                let target = if x == 4 && self.is_v3() {
                    let om2 = local[OM2_COL].clone();
                    (AB::Expr::ONE - om2.clone()) * pv(base + j) + om2 * pv(PV_CM3 + j)
                } else {
                    pv(base + j)
                };
                let close = local[BGC_OFF + x].clone()
                    * (local[BQ_OFF + j].clone() - target * ep.clone());
                // #219's `L·dv` and (A4) `L3·d3` relax the anchor close; the two
                // latches are never both high, so the relaxation is linear.
                let close = if x == 0 {
                    (AB::Expr::ONE - local[LDV_COL].clone() - local[L3D3_COL].clone()) * close
                } else {
                    close
                };
                builder.assert_zero(close);
            }
        }
        for j in 0..16 {
            builder.when_first_row().assert_zero(local[BQ_OFF + j].clone());
        }

        // --- The third bank (#215 option 4, verbatim gates) ---
        {
            builder.assert_eq(
                local[EG3_OFF].clone(),
                bnd.clone() * local[SE_OFF + SE_RHO].clone(),
            );
            builder.assert_eq(
                local[EG3_OFF + 1].clone(),
                bnd.clone() * local[SE_OFF + 3].clone() * local[OM_COL].clone(),
            );
            builder.assert_eq(
                local[EG3_OFF + 2].clone(),
                gperm.clone() * local[SE_OFF + SE_RHO].clone(),
            );
            builder.assert_bool(local[OM_COL].clone());
            builder.when_first_row().assert_zero(local[OM_COL].clone());
            for j in 0..16 {
                builder.assert_zero(
                    local[EG3_OFF + 2].clone()
                        * (local[EQ3_OFF + j].clone()
                            - (AB::Expr::ONE - local[OM_COL].clone())
                                * pv(PV_NF1 + j)
                                * ep.clone()),
                );
                builder.when_first_row().assert_zero(local[EQ3_OFF + j].clone());
            }
        }

        // --- Balance gates ---
        builder.assert_eq(local[INJ3E_COL].clone(), inj(3) * ep.clone());
        builder.assert_eq(local[INJ4E_COL].clone(), inj(4) * ep.clone());
        builder.assert_eq(local[INJRE_COL].clone(), inj(6) * ep.clone());
        builder.assert_eq(
            local[BLCLOSE_COL].clone(),
            gperm.clone() * local[SE_OFF + 5].clone(),
        );
        for k in 0..9 {
            builder.assert_bool(local[BLC_OFF + k].clone());
            builder.assert_bool(local[BLC2_OFF + k].clone());
        }
        for j in 0..4 {
            builder.when_first_row().assert_zero(local[BL_OFF + j].clone());
            builder.when_first_row().assert_zero(local[BL2_OFF + j].clone());
        }

        // --- Shape S: the latch and the marker as the "which slot" signals ---
        let latch = local[LATCH_COL].clone();
        let om = local[OM_COL].clone();
        builder.assert_eq(
            local[AG_OFF + AG_IN1].clone(),
            local[INJ3E_COL].clone() * (AB::Expr::ONE - latch.clone()),
        );
        builder.assert_eq(
            local[AG_OFF + AG_IN2].clone(),
            local[INJ3E_COL].clone() * latch.clone(),
        );
        builder.assert_eq(
            local[AG_OFF + AG_O1].clone(),
            local[INJ4E_COL].clone() * (AB::Expr::ONE - om.clone()),
        );
        if self.is_v3() {
            // v3: `OM`'s span holds outputs 2 and 3; `OM2` splits it.
            let om2 = local[OM2_COL].clone();
            builder.assert_eq(
                local[AG_OFF + AG_O2].clone(),
                local[INJ4E_COL].clone() * om.clone() * (AB::Expr::ONE - om2.clone()),
            );
            builder.assert_eq(local[AG_O3_COL].clone(), local[INJ4E_COL].clone() * om.clone() * om2);
        } else {
            builder.assert_eq(
                local[AG_OFF + AG_O2].clone(),
                local[INJ4E_COL].clone() * om.clone(),
            );
        }
        builder.assert_eq(
            local[AG_OFF + AG_R1].clone(),
            local[INJRE_COL].clone() * (AB::Expr::ONE - latch.clone()),
        );
        builder.assert_eq(
            local[AG_OFF + AG_R2].clone(),
            local[INJRE_COL].clone() * latch.clone(),
        );
        for k in 0..4 {
            builder.assert_bool(local[SEL2_OFF + k].clone());
        }
        {
            let close = local[BLCLOSE_COL].clone();
            let q = local[SEL2_OFF + S2_Q].clone();
            builder.assert_eq(local[CQ_OFF].clone(), close.clone() * q.clone());
            builder.assert_eq(local[CQ_OFF + 1].clone(), close * (AB::Expr::ONE - q));
        }
        builder.assert_eq(
            local[SG_OFF].clone(),
            local[AG_OFF + AG_O1].clone() * local[SEL2_OFF + S2_O1A].clone(),
        );
        builder.assert_eq(
            local[SG_OFF + 1].clone(),
            local[AG_OFF + AG_O2].clone() * local[SEL2_OFF + S2_O2A].clone(),
        );
        for k in 0..6 {
            builder.when_first_row().assert_zero(local[AC_OFF + k].clone());
        }
        let hi = AB::Expr::ONE - lo16.clone();
        builder.assert_zero(local[INJ3E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJ4E_COL].clone() * hi.clone() * w(13));
        builder.assert_zero(local[INJRE_COL].clone() * hi * w(13));

        // --- Shape P: the policy constants and their bindings ---
        let pol = |k: usize| local[POL_OFF + k].clone();
        for k in 0..2 {
            builder.assert_bool(pol(POL_HY + k));
            builder.assert_bool(pol(POL_RG + k));
            builder.assert_bool(pol(POL_ROPEN + k));
            builder.assert_bool(pol(POL_NZ + k));
            // Hybrid and Regulated are exclusive.
            builder.assert_zero(pol(POL_HY + k) * pol(POL_RG + k));
        }
        // `mode` lane at AREG: bit 0 = hy, bit 1 = rg, everything else 0;
        // `flags` lane: bit 0 = redeem_open, everything else 0. `AG_R1`/`AG_R2`
        // are `INJRE·(1−L)` / `INJRE·L` — input 0's and input 1's AREG rows.
        for (k, g) in [AG_R1, AG_R2].iter().enumerate() {
            let gate = local[AG_OFF + g].clone();
            builder.assert_zero(
                gate.clone() * (w(4) - pol(POL_HY + k) * sel(0) - pol(POL_RG + k) * sel(1)),
            );
            builder.assert_zero(gate.clone() * (w(14) - pol(POL_ROPEN + k) * sel(0)));
            // Freeze non-membership, the root: on AREG's boundary rows the
            // chained digest is the depth-20 fold of the low leaf; when the
            // asset has a freeze tree (hy ∨ rg) it equals the leaf's
            // `freeze_root` lanes W5..8, bit by bit. Zero columns.
            let frz = pol(POL_HY + k) + pol(POL_RG + k);
            for l in 0..4 {
                builder.assert_zero(gate.clone() * frz.clone() * (a(l) - w(5 + l)));
            }
        }
        // `nz_k` ⇔ `Σm_k ≠ 0` (the chunks are 16-bit public values; their sum
        // is nonzero iff the amount is).
        let sum_m = |k: usize| -> AB::Expr {
            (0..4)
                .map(|j| pv(pv_vp_chunk(k, j)))
                .fold(AB::Expr::ZERO, |acc, e| acc + e)
        };
        for k in 0..2 {
            builder.assert_zero(pol(POL_NZ + k) * (pol(POL_VPINV + k) * sum_m(k) - AB::Expr::ONE));
            builder.assert_zero((AB::Expr::ONE - pol(POL_NZ + k)) * sum_m(k));
            // A Cloaked asset (neither flag) carries vPublic = 0 — except a
            // REDEEM of asset 0, the exit edge (lab #785 F5-4d, F-B (ii)):
            // `x_k = s_k·z_k`, an expression (`s_k` is a public value). A mint
            // on asset 0 (`s_k = 0`) is still refused. Degree 3.
            let x = pv(pv_vp_sign(k)) * local[Z_OFF + k].clone();
            builder.assert_zero(
                sum_m(k) * (AB::Expr::ONE - pol(POL_HY + k) - pol(POL_RG + k)) * (AB::Expr::ONE - x.clone()),
            );
            // REQ_k = nz_k · (1 − s_k · ropen_k) · (1 − x_k): the issuer key is
            // required to mint, and to redeem an asset that is not redeem_open —
            // but never to redeem asset 0 (it has no issuer). Degree 3.
            builder.assert_eq(
                pol(POL_REQ + k),
                (pol(POL_NZ + k) - pol(POL_NZ + k) * pv(pv_vp_sign(k)) * pol(POL_ROPEN + k)) * (AB::Expr::ONE - x),
            );
        }
        // The two "current input" muxes.
        builder.assert_eq(
            pol(POL_RQ),
            pol(POL_REQ) + latch.clone() * (pol(POL_REQ + 1) - pol(POL_REQ)),
        );
        builder.assert_eq(
            pol(POL_ALW),
            pol(POL_RG) + latch.clone() * (pol(POL_RG + 1) - pol(POL_RG)),
        );
        // Shape-P gate columns.
        builder.assert_eq(local[INJ_AFRZE_COL].clone(), inj(INJ_AFRZ) * ep.clone());
        builder.assert_eq(local[INJ_ACREDE_COL].clone(), inj(INJ_ACRED) * ep.clone());
        builder.assert_eq(local[INJ_AFKEYE_COL].clone(), inj(INJ_AFKEY) * ep.clone());
        builder.assert_eq(
            local[CLOSE_CRED_COL].clone(),
            gperm.clone() * sel_role(SEL_ACRED) * ep.clone(),
        );
        builder.assert_eq(local[EGB_COL].clone(), bnd.clone() * sel_role(SEL_BALLOW) * ep.clone());
        builder.assert_eq(
            local[EGBC_COL].clone(),
            gperm.clone() * sel_role(SEL_BALLOW) * ep.clone(),
        );
        builder.assert_eq(
            local[AREGE_COL].clone(),
            gperm.clone() * local[SE_OFF + SE_AREG].clone(),
        );
        builder.assert_eq(local[CRQ_COL].clone(), local[AREGE_COL].clone() * pol(POL_RQ));
        // Bank closes: the third bank's rkm window at ACRED's end; the bind
        // bank's rkm′ window at ACM's end (EG[5] = gperm·SE[acm]); the bind
        // bank's AISS window at AREG's end, gated by REQ; bank 1's allowlist
        // window at BALLOW's end (its legs are gated by ALW, so an off
        // allowlist accumulates nothing).
        for j in 0..16 {
            builder.assert_zero(local[CLOSE_CRED_COL].clone() * local[EQ3_OFF + j].clone());
            builder.assert_zero(local[EG_OFF + 5].clone() * local[BQ_OFF + j].clone());
            builder.assert_zero(local[CRQ_COL].clone() * local[BQ_OFF + j].clone());
            builder.assert_zero(local[EGBC_COL].clone() * local[EQ_OFF + j].clone());
        }

        // --- The two 256-bit comparisons, bit-serial (LSB → MSB over z) ---
        // Block 0: key_lo (W0..3) < K (a); block 1: K (a) < key_hi (W5..8),
        // K = H(rkm ‖ D_FRZ) the chained digest on AFRZ's boundary.
        // Per lane: LT_z = (1−x)·y + (1 − x − y + 2xy)·LT_{z−1}, EQ_z = EQ_{z−1}·(1 − x − y + 2xy),
        // seeded at z = 0 (same-row, `sel(0)`), advanced on M rows z < 63
        // (transition), free on T rows and at the M → T edge. The lane
        // combines C1..C3 are same-row everywhere; C3 at AFRZ's z = 63 is the
        // verdict.
        let cmp = |blk: usize, k: usize| local[CMP_OFF + CMP_BLOCK * blk + k].clone();
        let cmp_next = |blk: usize, k: usize| next[CMP_OFF + CMP_BLOCK * blk + k].clone();
        let xy = |blk: usize, l: usize, row: &[AB::Expr]| -> (AB::Expr, AB::Expr) {
            if blk == 0 {
                (row[W_OFF + l].clone(), row[A_OFF + l].clone())
            } else {
                (row[A_OFF + l].clone(), row[W_OFF + 5 + l].clone())
            }
        };
        for blk in 0..2 {
            for l in 0..4 {
                let (x, y) = xy(blk, l, &local);
                let same = AB::Expr::ONE - x.clone() - y.clone() + two.clone() * x.clone() * y.clone();
                builder.assert_zero(sel(0) * (cmp(blk, CMP_LT + l) - (AB::Expr::ONE - x.clone()) * y.clone()));
                builder.assert_zero(sel(0) * (cmp(blk, CMP_EQ + l) - same));
            }
            let c1 = cmp(blk, CMP_LT + 1) + cmp(blk, CMP_EQ + 1) * cmp(blk, CMP_LT);
            builder.assert_eq(cmp(blk, CMP_C), c1);
            let c2 = cmp(blk, CMP_LT + 2) + cmp(blk, CMP_EQ + 2) * cmp(blk, CMP_C);
            builder.assert_eq(cmp(blk, CMP_C + 1), c2);
            let c3 = cmp(blk, CMP_LT + 3) + cmp(blk, CMP_EQ + 3) * cmp(blk, CMP_C + 1);
            builder.assert_eq(cmp(blk, CMP_C + 2), c3);
            // The verdict on AFRZ's last boundary row.
            builder.assert_zero(
                local[INJ_AFRZE_COL].clone() * u63.clone() * (cmp(blk, CMP_C + 2) - AB::Expr::ONE),
            );
        }

        // Balance closes with vPublic. Under `¬q` (CQ[1]): row 1 pays `f1·fee`
        // and carries vPublic₁, row 2 pays `(1 − f1)·fee` and carries
        // vPublic₂, each on its own chain. Under `q` (CQ[0]): the rows are
        // summed, pay the whole fee once and carry vPublic₁ (vPublic₂ = 0).
        // Carry offset −3: c ∈ [−3, 4] (the signed term widens the L1 range).
        // v3: offset −4, c ∈ [−4, 3] — a fifth debit per row (three outputs,
        // the fee, a redeeming vPublic) reaches c = −4; three credits (two
        // inputs, a minting vPublic) keep c ≤ 2.
        let v3_bias = self.is_v3();
        let carry = |off: usize, j: usize| -> AB::Expr {
            let c = local[off + 3 * j].clone()
                + local[off + 3 * j + 1].clone() * two.clone()
                + local[off + 3 * j + 2].clone() * two.clone() * two.clone()
                - two.clone()
                - AB::Expr::ONE;
            if v3_bias {
                c - AB::Expr::ONE
            } else {
                c
            }
        };
        let close = local[BLCLOSE_COL].clone();
        let close_q = local[CQ_OFF].clone();
        let close_nq = local[CQ_OFF + 1].clone();
        let w16 = AB::Expr::from_u32(1 << 16);
        let f1 = local[SEL2_OFF + S2_F1].clone();
        // A4: the rows owe the fee only when slot 3 is a dummy.
        let d3 = local[D3_COL].clone();
        let acc = |bl: usize, j: usize| local[bl + j].clone();
        let summed = |j: usize| local[BL_OFF + j].clone() + local[BL2_OFF + j].clone();
        // (gate, accumulator at chunk j, carry block, fee selector, vPublic row)
        type Chain<'a, E> = (E, Box<dyn Fn(usize) -> E + 'a>, usize, E, usize);
        let chains: [Chain<'_, AB::Expr>; 3] = [
            (close_nq.clone(), Box::new(move |j| acc(BL_OFF, j)), BLC_OFF, d3.clone() * f1.clone(), 0),
            (
                close_nq.clone(),
                Box::new(move |j| acc(BL2_OFF, j)),
                BLC2_OFF,
                d3.clone() * (AB::Expr::ONE - f1.clone()),
                1,
            ),
            (close_q.clone(), Box::new(summed), BLC_OFF, d3.clone(), 0),
        ];
        for (gate, bl, blc, fsel, k) in chains.iter() {
            // in − out − fee + (1 − 2s)·m = 0  ⇔  bl = fee − (1 − 2s)·m
            let sgn = AB::Expr::ONE - two.clone() * pv(pv_vp_sign(*k));
            let feev = |j: usize| {
                fsel.clone() * pv(PV_FEE + j) * ep.clone() - sgn.clone() * pv(pv_vp_chunk(*k, j)) * ep.clone()
            };
            builder.assert_zero(gate.clone() * (bl(0) - feev(0) - w16.clone() * carry(*blc, 0)));
            for j in 1..3 {
                builder.assert_zero(
                    gate.clone()
                        * (bl(j) + carry(*blc, j - 1) - feev(j) - w16.clone() * carry(*blc, j)),
                );
            }
            builder.assert_zero(gate.clone() * (bl(3) + carry(*blc, 2) - feev(3)));
        }
        let ac = |k: usize| local[AC_OFF + k].clone();
        builder.assert_zero(close_q.clone() * (ac(AG_IN1) - ac(AG_IN2)));
        builder.assert_zero(
            close_nq * (local[QINV_COL].clone() * (ac(AG_IN1) - ac(AG_IN2)) - AB::Expr::ONE),
        );
        let o1a = local[SEL2_OFF + S2_O1A].clone();
        let o2a = local[SEL2_OFF + S2_O2A].clone();
        builder.assert_zero(close.clone() * o1a.clone() * (ac(AG_O1) - ac(AG_IN1)));
        builder.assert_zero(
            close.clone() * (AB::Expr::ONE - o1a) * (ac(AG_O1) - ac(AG_IN2)),
        );
        builder.assert_zero(close.clone() * o2a.clone() * (ac(AG_O2) - ac(AG_IN1)));
        builder.assert_zero(
            close.clone() * (AB::Expr::ONE - o2a) * (ac(AG_O2) - ac(AG_IN2)),
        );
        if self.is_v3() {
            // Row 1 (`o3a`), the fee bank (`o3f`, asset 0) or row 2.
            let o3a = local[SEL_O3A_COL].clone();
            let o3f = local[O3F_COL].clone();
            let ac3 = local[AC_O3_COL].clone();
            builder.assert_zero(close.clone() * o3a.clone() * (ac3.clone() - ac(AG_IN1)));
            builder.assert_zero(
                close.clone() * (AB::Expr::ONE - o3a - o3f.clone()) * (ac3.clone() - ac(AG_IN2)),
            );
            builder.assert_zero(close.clone() * o3f * ac3);
        }
        builder.assert_zero(close.clone() * d3.clone() * f1.clone() * ac(AG_IN1));
        builder.assert_zero(close.clone() * d3.clone() * (AB::Expr::ONE - f1) * ac(AG_IN2));
        // A4 — the fee input: asset 0 bit by bit; worth exactly the fee when
        // real, 0 when a dummy (the fee bank closes at `(1 − d3)·fee`).
        builder.assert_zero(inj(INJ_ACMF) * w(13));
        if self.is_v3() {
            // Lab #937 A′: shape S's fee-bank chain, verbatim — the bank is
            // `v(fee note) − o3f·v(O3)`, closed against `(1 − d3)·fee` with
            // carries in {−2, −1, 0} (the argument is at shape S's close).
            let fcarry = |j: usize| -> AB::Expr {
                local[FBC_OFF + 2 * j].clone() + local[FBC_OFF + 2 * j + 1].clone() * two.clone()
                    - two.clone()
            };
            let owed = |j: usize| (AB::Expr::ONE - d3.clone()) * pv(PV_FEE + j) * ep.clone();
            builder.assert_zero(
                close.clone() * (local[FB_OFF].clone() - owed(0) - w16.clone() * fcarry(0)),
            );
            for j in 1..3 {
                builder.assert_zero(
                    close.clone()
                        * (local[FB_OFF + j].clone() + fcarry(j - 1) - owed(j) - w16.clone() * fcarry(j)),
                );
            }
            builder.assert_zero(close.clone() * (local[FB_OFF + 3].clone() + fcarry(2) - owed(3)));
            for j in 0..4 {
                builder.when_first_row().assert_zero(local[FB_OFF + j].clone());
            }
        } else {
            for j in 0..4 {
                builder.assert_zero(
                    close.clone()
                        * (local[FB_OFF + j].clone()
                            - (AB::Expr::ONE - d3.clone()) * pv(PV_FEE + j) * ep.clone()),
                );
                builder.when_first_row().assert_zero(local[FB_OFF + j].clone());
            }
        }
        builder.assert_bool(d3.clone());
        builder.assert_bool(local[L3_COL].clone());
        builder.when_first_row().assert_zero(local[L3_COL].clone());
        builder.assert_eq(local[L3D3_COL].clone(), local[L3_COL].clone() * d3);
        builder.assert_zero(close.clone() * (ac(AG_R1) - ac(AG_IN1)));
        builder.assert_zero(close.clone() * (ac(AG_R2) - ac(AG_IN2)));
        // vPublic's public surface: the sign is a bool; the revealed asset is
        // the row's when the amount is nonzero; one distinct asset ⇒ vPublic₂ = 0.
        for k in 0..2 {
            let s = pv(pv_vp_sign(k));
            builder.assert_zero(close.clone() * s.clone() * (AB::Expr::ONE - s));
            let row_asset = if k == 0 { ac(AG_IN1) } else { ac(AG_IN2) };
            builder.assert_zero(close.clone() * sum_m(k) * (pv(pv_vp_asset(k)) - row_asset));
        }
        builder.assert_zero(close_q.clone() * sum_m(1));
        builder.assert_zero(close_q * pv(pv_vp_sign(1)));

        // --- Lab #785 F5-4d: the asset-0 exit edge and its recipient ---
        {
            let z = |k: usize| local[Z_OFF + k].clone();
            let zinv = |k: usize| local[ZINV_OFF + k].clone();
            let xe = local[XE_COL].clone();
            for k in 0..2 {
                // `z_k = [the registry leaf's asset = 0]`, bound on the close
                // row where `AG_Rk` holds the leaf's asset lane (ruling
                // Q-4d-3). Degree 3.
                builder.assert_bool(z(k));
                let leaf_asset = ac(if k == 0 { AG_R1 } else { AG_R2 });
                builder.assert_zero(close.clone() * (leaf_asset.clone() * zinv(k) - (AB::Expr::ONE - z(k))));
                builder.assert_zero(close.clone() * leaf_asset * z(k));
            }
            // `e_k = s_k · z_k · nz_k`: degree 2 in columns, because `s_k` is a
            // public value (a constant to the AIR). `XE = e_0 ∨ e_1` is the
            // exit edge's one degree-4 constraint (`e_0 · e_1`); the shape
            // already had others, so the maximum stays 4.
            let e = |k: usize| pv(pv_vp_sign(k)) * z(k) * pol(POL_NZ + k);
            builder.assert_eq(xe.clone(), e(0) + e(1) - e(0) * e(1));
            // The recipient: nonzero on an exit (Σ of 16 16-bit limbs is below
            // 2^20 < p, so it is 0 only when every limb is — the verifier's
            // 16-bit PV range check is what makes that true), zero otherwise.
            let sum_x = (0..16).map(|j| pv(PV_XRKM + j)).fold(AB::Expr::ZERO, |a, e| a + e);
            builder.assert_zero(xe.clone() * (AB::Expr::ONE - local[XINV_COL].clone() * sum_x));
            for j in 0..16 {
                builder.assert_zero((AB::Expr::ONE - xe.clone()) * pv(PV_XRKM + j));
            }
        }

        // --- The #219 latch (verbatim) + the dummy slot's asset ---
        {
            let dv = local[DV_COL].clone();
            builder.assert_bool(latch.clone());
            builder.assert_bool(dv.clone());
            builder.when_first_row().assert_zero(latch.clone());
            builder.assert_eq(local[LDV_COL].clone(), latch.clone() * dv);
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 4].clone(),
            );
            builder.assert_zero(
                local[INJ3E_COL].clone()
                    * local[LDV_COL].clone()
                    * local[W_OFF + 13].clone(),
            );
        }

        // RC ring.
        for k in 0..7 {
            builder.assert_bool(local[B_OFF + k].clone());
        }
        builder.assert_eq(weighted(B_OFF, 7, &local), local[R_OFF].clone());
        for i in 0..24 {
            builder.when_first_row().assert_eq(
                local[R_OFF + i].clone(),
                AB::Expr::from_u32(Self::rc_pack((23 + i) % 24)),
            );
        }

        // --- v2 (Candidate A): selectors, injections, the leaf and root banks ---
        if self.is_v2() {
            for (i, code) in SEL_CODES_V2.iter().enumerate() {
                let lo = local[LO_OFF + (code & 3) as usize].clone();
                let hi = pair(r(2), r(3), (code >> 2) & 3);
                let top = if (code >> 4) & 1 == 1 {
                    r(4)
                } else {
                    AB::Expr::ONE - r(4)
                };
                builder.assert_eq(local[SELV2_OFF + i].clone(), lo * hi * top);
                builder.assert_eq(
                    local[SEV2_OFF + i].clone(),
                    local[SELV2_OFF + i].clone() * ep.clone(),
                );
            }
            builder.assert_eq(
                local[INJV2_OFF].clone(),
                bnd.clone() * local[SELV2_OFF].clone(),
            );
            builder.assert_eq(
                local[INJV2_OFF + 1].clone(),
                bnd.clone() * local[SELV2_OFF + 1].clone(),
            );
            builder.assert_eq(local[EGN_COL].clone(), bnd.clone() * local[SEV2_OFF].clone());
            builder.assert_eq(
                local[EGL_POS_COL].clone(),
                bnd.clone() * local[SEV2_OFF + 1].clone(),
            );
            builder.assert_eq(
                local[EGL_CLOSE_COL].clone(),
                gperm.clone() * local[SEV2_OFF + 1].clone(),
            );
            builder.assert_eq(
                local[EGA_POS_COL].clone(),
                bnd.clone() * local[SEV2_OFF + 2].clone(),
            );
            let l1 = local[LATCH_COL].clone();
            let l3 = local[L3_COL].clone();
            for j in 0..16 {
                let target = (AB::Expr::ONE - l1.clone() - l3.clone()) * pv(PV_LEAF1 + j)
                    + l1.clone() * pv(PV_LEAF2 + j)
                    + l3.clone() * pv(PV_LEAF3 + j);
                builder.assert_zero(
                    local[EGL_CLOSE_COL].clone()
                        * (local[EQL_OFF + j].clone() - target * ep.clone()),
                );
                builder.when_first_row().assert_zero(local[EQL_OFF + j].clone());
                // The auth root equals the first ARKM's `auth_root` lanes:
                // bank EQA is zero at ARKM's close (`EG[2]`, ARKM only — the
                // ARKM2s carry no bank-1 legs and no EQA leg).
                builder.assert_zero(local[EG_OFF + 2].clone() * local[EQA_OFF + j].clone());
                builder.when_first_row().assert_zero(local[EQA_OFF + j].clone());
            }
        }

        // --- v3: the third output's selector, gate and marker ---
        if self.is_v3() {
            builder.assert_bool(local[SEL_O3A_COL].clone());
            builder.assert_eq(
                local[SG3_COL].clone(),
                local[AG_O3_COL].clone() * local[SEL_O3A_COL].clone(),
            );
            builder.assert_bool(local[OM2_COL].clone());
            builder.when_first_row().assert_zero(local[OM2_COL].clone());
            builder.when_first_row().assert_zero(local[AC_O3_COL].clone());
            // Lab #937 A′: `o3f` — bool, `⇒ d3 = 0`, `⇒ ¬o3a`, `SF3 = AG[o3]·o3f`.
            let o3f = local[O3F_COL].clone();
            builder.assert_bool(o3f.clone());
            builder.assert_zero(o3f.clone() * local[D3_COL].clone());
            builder.assert_zero(o3f.clone() * local[SEL_O3A_COL].clone());
            builder.assert_eq(local[SF3_COL].clone(), local[AG_O3_COL].clone() * o3f);
            for k in 0..6 {
                builder.assert_bool(local[FBC_OFF + k].clone());
            }
        }

        // --- Transition constraints ---
        let mut t = builder.when_transition();

        for i in 0..24 {
            t.assert_eq(
                next[R_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[R_OFF + i].clone()
                    + blast.clone() * local[R_OFF + (i + 1) % 24].clone(),
            );
        }
        for i in 0..24 {
            t.assert_eq(
                next[PB_OFF + i].clone(),
                (AB::Expr::ONE - blast.clone()) * local[PB_OFF + i].clone()
                    + blast.clone() * local[PB_OFF + (i + 1) % 24].clone(),
            );
        }
        let g = blast.clone() * local[PB_OFF + 1].clone();
        for i in 0..4 {
            t.assert_eq(
                next[PH_OFF + i].clone(),
                (AB::Expr::ONE - g.clone()) * local[PH_OFF + i].clone()
                    + g.clone() * local[PH_OFF + (i + 1) % 4].clone(),
            );
        }
        let g4 = local[G4_COL].clone();
        let n_ring = self.ring_limbs();
        for i in 0..n_ring {
            t.assert_eq(
                next[Self::ring_col(i)].clone(),
                (AB::Expr::ONE - g4.clone()) * local[Self::ring_col(i)].clone()
                    + g4.clone() * local[Self::ring_col((i + 1) % n_ring)].clone(),
            );
        }
        t.assert_zero(
            (AB::Expr::ONE - g.clone())
                * (next[PBIT_COL].clone() - local[PBIT_COL].clone()),
        );

        for d in 1..=S_SLOTS {
            let mut expr = if d < S_SLOTS {
                local[s_col(d + 1)].clone()
            } else {
                AB::Expr::ZERO
            };
            for l in 0..25 {
                let wgt = AB::Expr::from_u32(1 << l);
                if RHO[l] as usize == d {
                    expr = expr + e1(l) * wgt.clone() * ap(l);
                }
                if 64 + RHO[l] as usize == d {
                    expr = expr + (trow.clone() - e1(l)) * wgt * ap(l);
                }
            }
            t.assert_eq(next[s_col(d)].clone(), expr);
        }
        for d in 1..V_SLOTS {
            t.assert_eq(next[v_col(d)].clone(), local[v_col(d + 1)].clone());
        }
        t.assert_eq(
            next[v_col(V_SLOTS)].clone(),
            mrow.clone() * weighted(EFF_OFF, 25, &local),
        );
        let lo_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << x))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        let hi_c = (0..5)
            .map(|x| c(x) * AB::Expr::from_u32(1 << (5 + x)))
            .fold(AB::Expr::ZERO, |acc, e| acc + e);
        t.assert_eq(
            next[u_col(1)].clone(),
            local[u_col(2)].clone() + u63.clone() * hi_c.clone(),
        );
        for d in 2..64 {
            t.assert_eq(next[u_col(d)].clone(), local[u_col(d + 1)].clone());
        }
        t.assert_eq(
            next[u_col(64)].clone(),
            local[u_col(65)].clone() + mrow.clone() * lo_c,
        );
        t.assert_eq(next[u_col(65)].clone(), (mrow.clone() - u63.clone()) * hi_c);

        t.assert_eq(
            next[EP_COL].clone(),
            local[EP_COL].clone() * (AB::Expr::ONE - local[GWRAP_COL].clone()),
        );
        // The bind bank: S's capture/reset, plus the AISS window (+a at ARKM's
        // boundary, −W0..3 at AREG's; reset at AREG's end) and the rkm′ window
        // (+a at ACRED's boundary, −a at ACM's; asserted 0 at ACM's end).
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                t.assert_eq(
                    next[BQ_OFF + idx].clone(),
                    (AB::Expr::ONE - local[BGRST_COL].clone() - local[AREGE_COL].clone())
                        * local[BQ_OFF + idx].clone()
                        + local[BGCAP_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone()
                        // The AISS window's `+a` at ARKM — not in the fee chain
                        // (A4): its ARKM has no AISS before it and no AREG after
                        // to close the window, so `(1 − L3)` keeps the bind bank
                        // clean for `BANCHOR`'s close and bank 2's at `ACMF`.
                        + local[EG_OFF + 1].clone()
                            * (AB::Expr::ONE - local[L3_COL].clone())
                            * per[35 + j].clone()
                            * local[A_OFF + l].clone()
                        - local[INJRE_COL].clone() * per[35 + j].clone() * local[W_OFF + l].clone()
                        + local[INJ_ACREDE_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone()
                        - local[INJ3E_COL].clone() * per[35 + j].clone() * local[A_OFF + l].clone(),
                );
            }
        }
        for j in 0..4 {
            let pw = per[35 + j].clone();
            let v = local[W_OFF + 4].clone();
            let mut row1 = local[BL_OFF + j].clone()
                + local[AG_OFF + AG_IN1].clone() * pw.clone() * v.clone()
                - local[SG_OFF].clone() * pw.clone() * v.clone()
                - local[SG_OFF + 1].clone() * pw.clone() * v.clone();
            let mut row2 = local[BL2_OFF + j].clone()
                + local[AG_OFF + AG_IN2].clone() * pw.clone() * v.clone()
                - (local[AG_OFF + AG_O1].clone() - local[SG_OFF].clone())
                    * pw.clone()
                    * v.clone()
                - (local[AG_OFF + AG_O2].clone() - local[SG_OFF + 1].clone())
                    * pw.clone()
                    * v.clone();
            if self.is_v3() {
                // Output 3: row 1 under `o3a`, neither row under `o3f`, else row 2.
                row1 -= local[SG3_COL].clone() * pw.clone() * v.clone();
                row2 -= (local[AG_O3_COL].clone() - local[SG3_COL].clone() - local[SF3_COL].clone()) * pw * v;
            }
            t.assert_eq(next[BL_OFF + j].clone(), row1);
            t.assert_eq(next[BL2_OFF + j].clone(), row2);
        }
        for k in 0..6 {
            t.assert_eq(
                next[AC_OFF + k].clone(),
                local[AC_OFF + k].clone()
                    + local[AG_OFF + k].clone() * per[35].clone() * local[W_OFF + 13].clone(),
            );
        }
        for k in 0..4 {
            t.assert_eq(next[SEL2_OFF + k].clone(), local[SEL2_OFF + k].clone());
        }
        t.assert_eq(next[QINV_COL].clone(), local[QINV_COL].clone());
        if self.is_v3() {
            // Output 3's asset held; `o3a` constant; `OM2` set at the first
            // `BCM2` close.
            t.assert_eq(
                next[AC_O3_COL].clone(),
                local[AC_O3_COL].clone()
                    + local[AG_O3_COL].clone() * per[35].clone() * local[W_OFF + 13].clone(),
            );
            t.assert_eq(next[SEL_O3A_COL].clone(), local[SEL_O3A_COL].clone());
            t.assert_eq(next[O3F_COL].clone(), local[O3F_COL].clone());
            let om2 = local[OM2_COL].clone();
            t.assert_eq(
                next[OM2_COL].clone(),
                om2.clone() + (AB::Expr::ONE - om2) * local[BGC_OFF + 4].clone(),
            );
        }
        // A4: the fee bank, the fee chain's latch, `d3` constant.
        for j in 0..4 {
            let mut fb = local[FB_OFF + j].clone()
                + local[INJ_OFF + INJ_ACMF].clone() * per[35 + j].clone() * local[W_OFF + 4].clone();
            if self.is_v3() {
                // Lab #937 A′: output 3 under `o3f` is debited here.
                fb -= local[SF3_COL].clone() * per[35 + j].clone() * local[W_OFF + 4].clone();
            }
            t.assert_eq(next[FB_OFF + j].clone(), fb);
        }
        t.assert_eq(
            next[L3_COL].clone(),
            local[L3_COL].clone() * (AB::Expr::ONE - local[BGC_OFF].clone()) + local[BGC_OFF + 6].clone(),
        );
        t.assert_eq(next[D3_COL].clone(), local[D3_COL].clone());
        // The policy constants are per-transaction declarations.
        for k in [POL_HY, POL_HY + 1, POL_RG, POL_RG + 1, POL_ROPEN, POL_ROPEN + 1, POL_NZ, POL_NZ + 1, POL_VPINV, POL_VPINV + 1] {
            t.assert_eq(next[POL_OFF + k].clone(), local[POL_OFF + k].clone());
        }
        // Lab #785 F5-4d: so are the exit edge's.
        for c in [Z_OFF, Z_OFF + 1, ZINV_OFF, ZINV_OFF + 1, XE_COL, XINV_COL] {
            t.assert_eq(next[c].clone(), local[c].clone());
        }
        {
            t.assert_eq(
                next[LATCH_COL].clone(),
                local[LATCH_COL].clone() * (AB::Expr::ONE - local[BGC_OFF].clone())
                    + local[BGC_OFF + 2].clone(),
            );
            t.assert_eq(next[DV_COL].clone(), local[DV_COL].clone());
        }
        // The output-1 marker and the third bank: S's legs, plus the rkm
        // window (+a at AFKEY's boundary, −a at ACRED's; reset at ACRED's end).
        {
            let arho_close =
                local[EG3_OFF + 2].clone() * local[SEL_OFF + SEL_ARHO].clone();
            t.assert_eq(
                next[OM_COL].clone(),
                local[OM_COL].clone() * (AB::Expr::ONE - local[BGC_OFF + 4].clone())
                    + arho_close,
            );
            for l in 0..4 {
                for j in 0..4 {
                    let idx = 4 * l + j;
                    t.assert_eq(
                        next[EQ3_OFF + idx].clone(),
                        (AB::Expr::ONE - local[EG3_OFF + 2].clone() - local[CLOSE_CRED_COL].clone())
                            * local[EQ3_OFF + idx].clone()
                            + local[EG3_OFF].clone()
                                * per[35 + j].clone()
                                * local[W_OFF + 5 + l].clone()
                            - local[EG3_OFF + 1].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone()
                            + local[INJ_AFKEYE_COL].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone()
                            - local[INJ_ACREDE_COL].clone()
                                * per[35 + j].clone()
                                * local[A_OFF + l].clone(),
                    );
                }
            }
        }
        // Banks 1 and 2: S's legs, plus bank 1's allowlist window (−W9..12 at
        // AREG's boundary, +a at BALLOW's, both gated by ALW).
        let pwk = |j: usize| per[35 + j].clone();
        let alw = local[POL_OFF + POL_ALW].clone();
        for l in 0..4 {
            for j in 0..4 {
                let idx = 4 * l + j;
                let mut bank1 = local[EQ_OFF + idx].clone()
                    + local[EG_OFF].clone() * pwk(j) * local[A_OFF + l].clone()
                    - local[EG_OFF + 1].clone() * pwk(j) * local[W_OFF + l].clone()
                    + local[EGB_COL].clone() * alw.clone() * pwk(j) * local[A_OFF + l].clone()
                    - local[INJRE_COL].clone() * alw.clone() * pwk(j) * local[W_OFF + 9 + l].clone();
                let mut bank2 = local[EQ_OFF + 16 + idx].clone()
                    + local[EG_OFF + 3].clone() * pwk(j) * local[W_OFF + l].clone()
                    - local[EG_OFF + 4].clone() * pwk(j) * local[W_OFF + 5 + l].clone();
                if self.is_v2() {
                    // NFA: +nk (W9..12) into bank 1, +ρ (W0..3) into bank 2.
                    bank1 += local[EGN_COL].clone() * pwk(j) * local[W_OFF + 9 + l].clone();
                    bank2 += local[EGN_COL].clone() * pwk(j) * local[W_OFF + l].clone();
                }
                t.assert_eq(next[EQ_OFF + idx].clone(), bank1);
                t.assert_eq(next[EQ_OFF + 16 + idx].clone(), bank2);
                if self.is_v2() {
                    t.assert_eq(
                        next[EQL_OFF + idx].clone(),
                        (AB::Expr::ONE - local[EGL_CLOSE_COL].clone()) * local[EQL_OFF + idx].clone()
                            + local[EGL_POS_COL].clone() * pwk(j) * local[W_OFF + l].clone(),
                    );
                    t.assert_eq(
                        next[EQA_OFF + idx].clone(),
                        local[EQA_OFF + idx].clone()
                            + local[EGA_POS_COL].clone() * pwk(j) * local[A_OFF + l].clone()
                            - local[EG_OFF + 1].clone() * pwk(j) * local[W_OFF + 7 + l].clone(),
                    );
                }
            }
        }
        // The comparison flags advance from every M row (gate `mrow` alone —
        // a second periodic factor would make these degree 5): from z = 63
        // the recurrence lands on the T row's first slot, which is free and
        // simply holds it; T rows are unconstrained; the next M row's z = 0
        // is re-seeded by the same-row `sel(0)` constraints.
        let adv = mrow.clone();
        for blk in 0..2 {
            for l in 0..4 {
                let (x, y) = xy(blk, l, &next);
                let same = AB::Expr::ONE - x.clone() - y.clone() + two.clone() * x.clone() * y.clone();
                t.assert_zero(
                    adv.clone()
                        * (cmp_next(blk, CMP_LT + l)
                            - (AB::Expr::ONE - x.clone()) * y.clone()
                            - same.clone() * cmp(blk, CMP_LT + l)),
                );
                t.assert_zero(
                    adv.clone() * (cmp_next(blk, CMP_EQ + l) - same * cmp(blk, CMP_EQ + l)),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Host mirrors of the shape-P hashes and the policy trees
// ---------------------------------------------------------------------------

/// `issuer_key = H(isk ‖ D_I)` — the `ROLE_AISS` block (D_I = lane 4 bit 7).
pub fn issuer_key_of(isk: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(isk);
    st[4] = 1 << 7;
    st[5] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// `cred = H(rkm ‖ D_CRED)` — the `ROLE_ACRED` block (D_CRED = lane 4 bit 15;
/// the derivation domain is W3's placeholder, an L2 parameter).
pub fn cred_of(rkm: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(rkm);
    st[4] = 1 << 15;
    st[5] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// The freeze key `K = H(rkm ‖ D_FRZ)` — the `ROLE_AFKEY` block (D_FRZ = lane 4
/// bit 31, pad at lane 5). The freeze tree's keys are these, never raw `rkm`s
/// (lab #704 Q1).
pub fn freeze_key_of(rkm: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(rkm);
    st[4] = 1 << 31;
    st[5] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// The indexed-Merkle low leaf `H(key_lo ‖ key_hi)` — the `ROLE_AFRZ` block
/// (leaf marker at lane 8 bit 3, distinct from the interior node's pad).
pub fn freeze_leaf_hash(key_lo: &[u64; 4], key_hi: &[u64; 4]) -> [u64; 4] {
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(key_lo);
    st[4..8].copy_from_slice(key_hi);
    st[8] = 1 << 3;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// `rkm = H(nk ‖ D ‖ d)` for one input — the `ROLE_ARKM` block, host side
/// (`l2::derive_input_l2` returns `nk`, `nf`, `cm`; the policy gadgets need
/// the intermediate).
pub fn derive_rkm_l2(inp: &L2TxInput) -> [u64; 4] {
    let (nk, _, _) = derive_input_l2(inp);
    let mut st = [0u64; 25];
    st[..4].copy_from_slice(&nk);
    st[4] = 1 << 1;
    st[5] = inp.d[0];
    st[6] = inp.d[1];
    st[7] = 1;
    st[16] = 1 << 63;
    crate::reference::keccak_f(&st)[..4].try_into().unwrap()
}

/// 256-bit keys are four little-endian lanes (lane 3 most significant) —
/// the order the bit-serial comparison combines them in.
pub fn key_lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for l in (0..4).rev() {
        if a[l] != b[l] {
            return a[l] < b[l];
        }
    }
    false
}

/// The indexed tree's "no successor" sentinel: `key_hi = 2^256 − 1`. Strict
/// `K < key_hi` then only excludes `K = MAX` (a hash output; negligible).
pub const KEY_MAX: [u64; 4] = [u64::MAX; 4];

/// A depth-20 authentication path (freeze tree and allowlist share the shape).
#[derive(Clone, Copy)]
pub struct PolicyWitness {
    pub siblings: [[u64; 4]; POLICY_DEPTH],
    pub path_bits: [bool; POLICY_DEPTH],
}

impl PolicyWitness {
    pub fn fold_root(&self, leaf: &[u64; 4]) -> [u64; 4] {
        let mut d = *leaf;
        for (sib, bit) in self.siblings.iter().zip(self.path_bits.iter()) {
            let st = if *bit {
                crate::reference::merkle_node_state(sib, &d)
            } else {
                crate::reference::merkle_node_state(&d, sib)
            };
            d = st[..4].try_into().unwrap();
        }
        d
    }
}

/// The real levels at the bottom of a fabricated policy tree: 2^3 = 8 leaf
/// slots hashed for real, 17 upper levels of shared pseudo-random siblings
/// (the house pattern of `narrow::fabricated_shared_tree` /
/// `l2::fabricated_registry_tree`, with a wider genuine subtree so a sorted
/// list of up to 7 frozen keys fits). Bench/self-test only.
pub const POLICY_SUB_LEVELS: usize = 3;

/// Fabricate a depth-20 policy tree over `leaves` (≤ 8; empty slots hold the
/// zero digest, which no leaf hash equals) and return every leaf's witness
/// and the root.
pub fn fabricated_policy_tree_for_tests(leaves: &[[u64; 4]], seed: u64) -> (Vec<PolicyWitness>, [u64; 4]) {
    let slots = 1usize << POLICY_SUB_LEVELS;
    assert!(leaves.len() <= slots, "fabricated policy tree holds at most {slots} leaves");
    let mut x = seed | 1;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let upper: Vec<[u64; 4]> = (POLICY_SUB_LEVELS..POLICY_DEPTH)
        .map(|_| [rnd(), rnd(), rnd(), rnd()])
        .collect();
    // Levels of the genuine subtree: level 0 = the 8 leaf digests.
    let mut levels: Vec<Vec<[u64; 4]>> = Vec::new();
    let mut cur: Vec<[u64; 4]> = (0..slots)
        .map(|i| leaves.get(i).copied().unwrap_or([0; 4]))
        .collect();
    levels.push(cur.clone());
    while cur.len() > 1 {
        cur = cur
            .chunks(2)
            .map(|p| crate::reference::merkle_node_state(&p[0], &p[1])[..4].try_into().unwrap())
            .collect();
        levels.push(cur.clone());
    }
    let mut root = levels[POLICY_SUB_LEVELS][0];
    for sib in &upper {
        root = crate::reference::merkle_node_state(&root, sib)[..4].try_into().unwrap();
    }
    let witnesses = (0..leaves.len())
        .map(|i| {
            let mut siblings = [[0u64; 4]; POLICY_DEPTH];
            let mut path_bits = [false; POLICY_DEPTH];
            let mut pos = i;
            for (lvl, sibs) in siblings.iter_mut().enumerate().take(POLICY_SUB_LEVELS) {
                *sibs = levels[lvl][pos ^ 1];
                path_bits[lvl] = pos & 1 == 1;
                pos >>= 1;
            }
            for (lvl, sib) in upper.iter().enumerate() {
                siblings[POLICY_SUB_LEVELS + lvl] = *sib;
            }
            PolicyWitness { siblings, path_bits }
        })
        .collect();
    (witnesses, root)
}

/// The circuit hash's zero chain for the policy trees (lab #722):
/// `zeros[0]` is the empty-leaf digest `[0; 4]` (no leaf hash equals it) and
/// `zeros[i] = H(zeros[i-1] ‖ zeros[i-1])` under the MERKLE node hash the
/// AIR folds with. `zeros[POLICY_DEPTH]` is the root of an all-empty tree.
pub fn policy_zeros() -> [[u64; 4]; POLICY_DEPTH + 1] {
    let mut z = [[0u64; 4]; POLICY_DEPTH + 1];
    for i in 1..=POLICY_DEPTH {
        z[i] = crate::reference::merkle_node_state(&z[i - 1], &z[i - 1])[..4].try_into().unwrap();
    }
    z
}

/// **The canonical depth-20 policy tree** (lab #722) over `leaves` placed at
/// positions `0..n`, every other slot empty: each level is computed only as
/// far as it holds a real node, and an absent node is `zeros[level]`. No seed
/// — the root is a function of the leaf list alone, so anyone holding the
/// list rebuilds it. Returns every leaf's witness and the root.
pub fn canonical_policy_tree(leaves: &[[u64; 4]]) -> (Vec<PolicyWitness>, [u64; 4]) {
    assert!(leaves.len() <= 1 << POLICY_DEPTH, "a depth-{POLICY_DEPTH} tree holds at most 2^{POLICY_DEPTH} leaves");
    let zeros = policy_zeros();
    let mut levels: Vec<Vec<[u64; 4]>> = vec![leaves.to_vec()];
    for lvl in 0..POLICY_DEPTH {
        let cur = &levels[lvl];
        let next: Vec<[u64; 4]> = cur
            .chunks(2)
            .map(|p| {
                let r = if p.len() == 2 { p[1] } else { zeros[lvl] };
                crate::reference::merkle_node_state(&p[0], &r)[..4].try_into().unwrap()
            })
            .collect();
        levels.push(next);
    }
    let root = levels[POLICY_DEPTH].first().copied().unwrap_or(zeros[POLICY_DEPTH]);
    let witnesses = (0..leaves.len())
        .map(|i| {
            let mut siblings = [[0u64; 4]; POLICY_DEPTH];
            let mut path_bits = [false; POLICY_DEPTH];
            let mut pos = i;
            for lvl in 0..POLICY_DEPTH {
                siblings[lvl] = levels[lvl].get(pos ^ 1).copied().unwrap_or(zeros[lvl]);
                path_bits[lvl] = pos & 1 == 1;
                pos >>= 1;
            }
            PolicyWitness { siblings, path_bits }
        })
        .collect();
    (witnesses, root)
}

fn key_order(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    if key_lt(a, b) {
        core::cmp::Ordering::Less
    } else if a == b {
        core::cmp::Ordering::Equal
    } else {
        core::cmp::Ordering::Greater
    }
}

/// **An issuer's freeze tree, canonical** (lab #722): the indexed tree over
/// the sorted frozen keys `K = H(rkm ‖ D_FRZ)` — leaves `(0, k₁), (k₁, k₂), …,
/// (kₙ, MAX)` — on [`canonical_policy_tree`]. What the issuer publishes is the
/// sorted key list; any wallet rebuilds this tree, its root, and its own
/// non-membership opening from that list alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFreezeTree {
    /// The sorted, deduplicated frozen keys (the published list).
    pub keys: Vec<[u64; 4]>,
    pub leaves: Vec<([u64; 4], [u64; 4])>,
    pub root: [u64; 4],
}

impl CanonicalFreezeTree {
    /// The tree over the addresses owning `frozen_rkms` (each hashed to its key).
    pub fn from_rkms(frozen_rkms: &[[u64; 4]]) -> Self {
        Self::from_keys(&frozen_rkms.iter().map(freeze_key_of).collect::<Vec<_>>())
    }

    /// The tree over already-hashed keys, in any order (sorted and deduplicated here).
    pub fn from_keys(frozen_keys: &[[u64; 4]]) -> Self {
        let mut keys = frozen_keys.to_vec();
        keys.sort_by(key_order);
        keys.dedup();
        assert!(!keys.contains(&[0; 4]) && !keys.contains(&KEY_MAX), "0 and MAX are the sentinels");
        let mut bounds = vec![[0u64; 4]];
        bounds.extend(keys.iter().copied());
        bounds.push(KEY_MAX);
        let leaves: Vec<([u64; 4], [u64; 4])> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
        let digests: Vec<[u64; 4]> = leaves.iter().map(|(lo, hi)| freeze_leaf_hash(lo, hi)).collect();
        let (_, root) = canonical_policy_tree(&digests);
        Self { keys, leaves, root }
    }

    /// The empty freeze tree (one `(0, MAX)` leaf).
    pub fn empty() -> Self {
        Self::from_keys(&[])
    }

    /// Whether `rkm`'s key is frozen.
    pub fn is_frozen(&self, rkm: &[u64; 4]) -> bool {
        self.keys.binary_search_by(|k| key_order(k, &freeze_key_of(rkm))).is_ok()
    }

    /// The low-leaf non-membership opening for `rkm`, or `None` when frozen.
    pub fn opening_for(&self, rkm: &[u64; 4]) -> Option<FreezeOpening> {
        let k = freeze_key_of(rkm);
        let i = self.leaves.iter().position(|(lo, hi)| key_lt(lo, &k) && key_lt(&k, hi))?;
        Some(self.opening_at(i))
    }

    /// Leaf `i`'s opening regardless of any key — for the negatives.
    pub fn opening_at(&self, i: usize) -> FreezeOpening {
        let digests: Vec<[u64; 4]> = self.leaves.iter().map(|(lo, hi)| freeze_leaf_hash(lo, hi)).collect();
        let (witnesses, _) = canonical_policy_tree(&digests);
        let (lo, hi) = self.leaves[i];
        FreezeOpening { key_lo: lo, key_hi: hi, witness: witnesses[i] }
    }
}

/// **An issuer's allowlist, canonical** (lab #722): the sorted credential
/// commitments `cred = H(rkm ‖ D_CRED)` as leaves of [`canonical_policy_tree`].
#[derive(Clone)]
pub struct CanonicalAllowTree {
    pub creds: Vec<[u64; 4]>,
    pub witnesses: Vec<PolicyWitness>,
    pub root: [u64; 4],
}

impl CanonicalAllowTree {
    pub fn from_creds(creds: &[[u64; 4]]) -> Self {
        let mut creds = creds.to_vec();
        creds.sort_by(key_order);
        creds.dedup();
        let (witnesses, root) = canonical_policy_tree(&creds);
        Self { creds, witnesses, root }
    }

    /// The allowlist over the holders owning `rkms`.
    pub fn from_rkms(rkms: &[[u64; 4]]) -> Self {
        Self::from_creds(&rkms.iter().map(cred_of).collect::<Vec<_>>())
    }

    pub fn witness_for(&self, cred: &[u64; 4]) -> Option<PolicyWitness> {
        self.creds.iter().position(|c| c == cred).map(|i| self.witnesses[i])
    }
}

/// One non-membership opening: the low leaf and its path.
#[derive(Clone, Copy)]
pub struct FreezeOpening {
    pub key_lo: [u64; 4],
    pub key_hi: [u64; 4],
    pub witness: PolicyWitness,
}

/// An issuer's freeze tree (l2-own-circuit-decision §3.2), indexed/sorted:
/// leaves `(k_i, k_{i+1})` over the sorted frozen **keys** `k = H(rkm ‖ D_FRZ)`
/// ([`freeze_key_of`]) with a `(0, k_1)` head and a `(k_n, MAX)` tail; the
/// empty tree is the single leaf `(0, MAX)`.
#[derive(Clone)]
pub struct FreezeTree {
    pub leaves: Vec<([u64; 4], [u64; 4])>,
    pub witnesses: Vec<PolicyWitness>,
    pub root: [u64; 4],
}

impl FreezeTree {
    /// **Test fixture** (lab #722): freeze the addresses owning
    /// `frozen_rkms` over the seeded fabricated tree. A real issuer or wallet
    /// uses [`CanonicalFreezeTree`].
    pub fn fixture_for_tests(frozen_rkms: &[[u64; 4]], seed: u64) -> Self {
        let keys: Vec<[u64; 4]> = frozen_rkms.iter().map(freeze_key_of).collect();
        Self::fixture_from_keys_for_tests(&keys, seed)
    }

    /// **Test fixture** over already-hashed keys (seeded, ≤ 7 keys) — not
    /// rebuildable from the key list alone; see [`CanonicalFreezeTree`].
    pub fn fixture_from_keys_for_tests(frozen_keys: &[[u64; 4]], seed: u64) -> Self {
        let mut keys: Vec<[u64; 4]> = frozen_keys.to_vec();
        keys.sort_by(|a, b| {
            if key_lt(a, b) {
                core::cmp::Ordering::Less
            } else if a == b {
                core::cmp::Ordering::Equal
            } else {
                core::cmp::Ordering::Greater
            }
        });
        keys.dedup();
        assert!(!keys.contains(&[0; 4]) && !keys.contains(&KEY_MAX), "0 and MAX are the sentinels");
        let mut bounds = vec![[0u64; 4]];
        bounds.extend(keys.iter().copied());
        bounds.push(KEY_MAX);
        let leaves: Vec<([u64; 4], [u64; 4])> = bounds.windows(2).map(|w| (w[0], w[1])).collect();
        let digests: Vec<[u64; 4]> = leaves.iter().map(|(lo, hi)| freeze_leaf_hash(lo, hi)).collect();
        let (witnesses, root) = fabricated_policy_tree_for_tests(&digests, seed);
        Self { leaves, witnesses, root }
    }

    /// **Test fixture**: the empty seeded tree (a Cloaked fixture's path).
    pub fn fixture_empty_for_tests() -> Self {
        Self::fixture_for_tests(&[], 0x0f7e_e2e0_0000_0001)
    }

    /// The low leaf for `rkm`'s key, or `None` when `rkm` is frozen.
    pub fn opening_for(&self, rkm: &[u64; 4]) -> Option<FreezeOpening> {
        let k = freeze_key_of(rkm);
        for (i, (lo, hi)) in self.leaves.iter().enumerate() {
            if key_lt(lo, &k) && key_lt(&k, hi) {
                return Some(FreezeOpening { key_lo: *lo, key_hi: *hi, witness: self.witnesses[i] });
            }
        }
        None
    }

    /// Leaf `i`'s opening regardless of `rkm` — for the negatives.
    pub fn opening_at(&self, i: usize) -> FreezeOpening {
        let (lo, hi) = self.leaves[i];
        FreezeOpening { key_lo: lo, key_hi: hi, witness: self.witnesses[i] }
    }
}

/// An issuer's allowlist (§3.4): a plain tree of credential commitments.
#[derive(Clone)]
pub struct AllowTree {
    pub creds: Vec<[u64; 4]>,
    pub witnesses: Vec<PolicyWitness>,
    pub root: [u64; 4],
}

impl AllowTree {
    /// **Test fixture** (lab #722): the seeded fabricated allowlist. A real
    /// issuer uses [`CanonicalAllowTree`].
    pub fn fixture_for_tests(creds: &[[u64; 4]], seed: u64) -> Self {
        let (witnesses, root) = fabricated_policy_tree_for_tests(creds, seed);
        Self { creds: creds.to_vec(), witnesses, root }
    }

    pub fn witness_for(&self, cred: &[u64; 4]) -> Option<PolicyWitness> {
        self.creds.iter().position(|c| c == cred).map(|i| self.witnesses[i])
    }
}

/// The dummy allowlist path a non-Regulated input spends its trace on.
pub fn dummy_allow_witness() -> PolicyWitness {
    CanonicalAllowTree::from_creds(&[[0xd0, 0xd1, 0xd2, 0xd3]]).witnesses[0]
}

/// One asset as the registry and the prover see it: the leaf plus the trees
/// behind its roots. Bench/self-test fixture.
#[derive(Clone)]
pub struct PolicyAsset {
    pub asset: u64,
    pub mode: u64,
    pub redeem_open: bool,
    /// `None` = no issuer (Cloaked).
    pub isk: Option<[u64; 4]>,
    pub freeze: FreezeTree,
    pub allow: AllowTree,
}

impl PolicyAsset {
    /// A Cloaked asset — what shape S opens; carries the empty trees.
    pub fn cloaked(asset: u64) -> Self {
        Self {
            asset,
            mode: MODE_CLOAKED,
            redeem_open: false,
            isk: None,
            freeze: FreezeTree::fixture_empty_for_tests(),
            allow: AllowTree::fixture_for_tests(&[], 0xa110_0000_0000_0000 ^ asset),
        }
    }

    /// A Hybrid stablecoin: issuer, freeze tree over `frozen`.
    pub fn hybrid(asset: u64, isk: [u64; 4], redeem_open: bool, frozen: &[[u64; 4]]) -> Self {
        Self {
            asset,
            mode: MODE_HYBRID,
            redeem_open,
            isk: Some(isk),
            freeze: FreezeTree::fixture_for_tests(frozen, 0xf7ee_0000_0000_0000 ^ asset),
            allow: AllowTree::fixture_for_tests(&[], 0xa110_0000_0000_0000 ^ asset),
        }
    }

    /// A Regulated asset: Hybrid plus an allowlist over `allowed` (rkm values —
    /// the tree holds their credential commitments).
    pub fn regulated(
        asset: u64,
        isk: [u64; 4],
        redeem_open: bool,
        frozen: &[[u64; 4]],
        allowed_rkm: &[[u64; 4]],
    ) -> Self {
        let creds: Vec<[u64; 4]> = allowed_rkm.iter().map(cred_of).collect();
        Self {
            asset,
            mode: MODE_REGULATED,
            redeem_open,
            isk: Some(isk),
            freeze: FreezeTree::fixture_for_tests(frozen, 0xf7ee_0000_0000_0000 ^ asset),
            allow: AllowTree::fixture_for_tests(&creds, 0xa110_0000_0000_0000 ^ asset),
        }
    }

    pub fn leaf(&self) -> RegistryLeaf {
        RegistryLeaf {
            asset: self.asset,
            issuer_key: self.isk.map(|k| issuer_key_of(&k)).unwrap_or([0; 4]),
            mode: self.mode,
            freeze_root: if self.mode == MODE_CLOAKED { [0; 4] } else { self.freeze.root },
            allow_root: if self.mode == MODE_REGULATED { self.allow.root } else { [0; 4] },
            flags: if self.redeem_open { FLAG_REDEEM_OPEN } else { 0 },
        }
    }

    /// The honest policy inputs for a note with `rkm` in this asset. A frozen
    /// `rkm` has no opening — the caller's negative supplies one by hand.
    pub fn policy_input_for(&self, rkm: &[u64; 4], reg_witness: RegistryWitness) -> Option<L2PolicyInput> {
        let freeze = if self.mode == MODE_CLOAKED {
            FreezeTree::fixture_empty_for_tests().opening_for(rkm)?
        } else {
            self.freeze.opening_for(rkm)?
        };
        let allow = if self.mode == MODE_REGULATED {
            self.allow.witness_for(&cred_of(rkm))?
        } else {
            dummy_allow_witness()
        };
        Some(L2PolicyInput {
            leaf: self.leaf(),
            reg_witness,
            freeze,
            allow,
            isk: self.isk.unwrap_or([0; 4]),
        })
    }
}

/// Everything shape P needs per input beyond the note itself.
#[derive(Clone, Copy)]
pub struct L2PolicyInput {
    pub leaf: RegistryLeaf,
    pub reg_witness: RegistryWitness,
    pub freeze: FreezeOpening,
    pub allow: PolicyWitness,
    /// The issuer secret when this row mints / redeems-closed; zeros otherwise.
    pub isk: [u64; 4],
}

/// Everything a prover/verifier pair needs for one shape-P instance.
#[cfg_attr(test, derive(Clone))] // the test fan-out needs owned copies; non-test build unchanged
pub struct L2PBucketInstance {
    pub air: L2ShapePAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub registry_root: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm_out: [[u64; 4]; 2],
    /// A4: slot 3's nullifier.
    pub nf3: [u64; 4],
}

/// Perm slots used by the shape-P3 program, INCLUDING the leading dummy
/// warm-up slot: 1 + 2 × 103 + 38 + 7 = **252**, at 3072 rows each = 774,144
/// rows → 2^20 (1,048,576), 89 spare perm slots. (P was 214; A4 added the
/// 38-perm fee chain. 212 before lab #704 Q1 added `AFKEY` per input.)
pub const SHAPE_P_PERMS: usize = 1
    + 2 * (3 + 1 + 1 + 1 + 1 + FREEZE_DEPTH + 1 + REGISTRY_DEPTH + 1 + 1 + 1 + ALLOW_DEPTH + 1 + 1 + 1 + MERKLE_DEPTH + 1)
    + (5 + MERKLE_DEPTH + 1)
    + 2 * 2
    + 1
    + 2;
const _: () = assert!(SHAPE_P_PERMS <= PROGRAM_SLOTS);
/// log2 of the shape-P trace height.
pub const SHAPE_P_LOG_HEIGHT: usize = 20;

/// Build shape P from caller-supplied commitment-tree witnesses + anchor, the
/// per-input policy openings, the registry root and the two `vPublic` terms.
/// Selectors are computed honestly from the assets; balance is NOT asserted.
/// No exit: the recipient PV is zero ([`build_bucket_l2p_exit_with_witnesses`]
/// takes one).
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2p_with_witnesses(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &FeeSlot,
) -> L2PBucketInstance {
    build_bucket_l2p_exit_with_witnesses(
        log_height, inputs, outputs, fee, witnesses, anchor, policy, registry_root, vp, fee_slot, [0; 4],
    )
}

/// [`build_bucket_l2p_with_witnesses`] with the exit recipient `xrkm` (lab
/// #785 F5-4d): the L1 `rkm` an asset-0 redeem pays. It must be nonzero
/// exactly when the transaction exits, or the trace is unsatisfiable.
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2p_exit_with_witnesses(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &FeeSlot,
    xrkm: [u64; 4],
) -> L2PBucketInstance {
    let (nk1, nf1, _cm1) = derive_input_l2(&inputs[0]);
    let (nk2, nf2, _cm2) = derive_input_l2(&inputs[1]);
    let fee_in = fee_slot.input();
    let (nk3, nf3, _cm3) = derive_input_l2(fee_in);

    let out_rho = [derive_output_rho(&nf1, 0), derive_output_rho(&nf1, 1)];
    let cmo1 = l2_cm(outputs[0].value, outputs[0].asset, &outputs[0].rkm, &out_rho[0], &outputs[0].rseed);
    let cmo2 = l2_cm(outputs[1].value, outputs[1].asset, &outputs[1].rkm, &out_rho[1], &outputs[1].rseed);

    let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
    let mut sw = vec![L2PSlotWitness::default(); PROGRAM_SLOTS];
    let mut slot = 1usize;
    let mut input_chain = |inp: &L2TxInput,
                           nk: &[u64; 4],
                           witness: &MerkleWitness,
                           pol: &L2PolicyInput,
                           bnf_role: u32| {
        let arkm = |program: &mut [u32; PROGRAM_SLOTS], sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, role: u32| {
            program[*slot] = role;
            sw[*slot].w[..4].copy_from_slice(nk);
            sw[*slot].w[5] = inp.d[0];
            sw[*slot].w[6] = inp.d[1];
            *slot += 1;
        };
        let path = |program: &mut [u32; PROGRAM_SLOTS], sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, sibs: &[[u64; 4]], bits: &[bool]| {
            for (sib, bit) in sibs.iter().zip(bits.iter()) {
                program[*slot] = ROLE_MERKLE;
                sw[*slot].w[..4].copy_from_slice(sib);
                sw[*slot].pbit = *bit;
                *slot += 1;
            }
        };
        program[slot] = ROLE_ANK;
        sw[slot].w[..4].copy_from_slice(&inp.sk);
        slot += 1;
        program[slot] = ROLE_NF;
        sw[slot].w[..4].copy_from_slice(&inp.rho);
        slot += 1;
        program[slot] = bnf_role;
        slot += 1;
        program[slot] = ROLE_AISS;
        sw[slot].w[..4].copy_from_slice(&pol.isk);
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM);
        program[slot] = ROLE_AFKEY;
        slot += 1;
        program[slot] = ROLE_AFRZ;
        sw[slot].w[..4].copy_from_slice(&pol.freeze.key_lo);
        sw[slot].w[5..9].copy_from_slice(&pol.freeze.key_hi);
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.freeze.witness.siblings, &pol.freeze.witness.path_bits);
        program[slot] = ROLE_AREG;
        sw[slot].w[..4].copy_from_slice(&pol.leaf.issuer_key);
        sw[slot].w[4] = pol.leaf.mode;
        sw[slot].w[5..9].copy_from_slice(&pol.leaf.freeze_root);
        sw[slot].w[9..13].copy_from_slice(&pol.leaf.allow_root);
        sw[slot].w[13] = pol.leaf.asset;
        sw[slot].w[14] = pol.leaf.flags;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.reg_witness.siblings, &pol.reg_witness.path_bits);
        program[slot] = ROLE_BREG;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM2);
        program[slot] = ROLE_ACRED;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.allow.siblings, &pol.allow.path_bits);
        program[slot] = ROLE_BALLOW;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, ROLE_ARKM2);
        program[slot] = ROLE_ACM;
        sw[slot].w[4] = inp.value;
        sw[slot].w[5..9].copy_from_slice(&inp.rho);
        sw[slot].w[9..13].copy_from_slice(&inp.rseed);
        sw[slot].w[13] = inp.asset;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &witness.siblings, &witness.path_bits);
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    };
    input_chain(&inputs[0], &nk1, &witnesses[0], &policy[0], ROLE_BNF1);
    input_chain(&inputs[1], &nk2, &witnesses[1], &policy[1], ROLE_BNF2);
    // A4: the fee chain — R's fee input (no policy: asset 0 is forced).
    {
        program[slot] = ROLE_ANK;
        sw[slot].w[..4].copy_from_slice(&fee_in.sk);
        slot += 1;
        program[slot] = ROLE_NF;
        sw[slot].w[..4].copy_from_slice(&fee_in.rho);
        slot += 1;
        program[slot] = ROLE_BNF3;
        slot += 1;
        program[slot] = ROLE_ARKM;
        sw[slot].w[..4].copy_from_slice(&nk3);
        sw[slot].w[5] = fee_in.d[0];
        sw[slot].w[6] = fee_in.d[1];
        slot += 1;
        program[slot] = ROLE_ACMF;
        sw[slot].w[4] = fee_in.value;
        sw[slot].w[5..9].copy_from_slice(&fee_in.rho);
        sw[slot].w[9..13].copy_from_slice(&fee_in.rseed);
        sw[slot].w[13] = fee_in.asset;
        slot += 1;
        let fw = fee_slot.witness();
        for (sib, bit) in fw.siblings.iter().zip(fw.path_bits.iter()) {
            program[slot] = ROLE_MERKLE;
            sw[slot].w[..4].copy_from_slice(sib);
            sw[slot].pbit = *bit;
            slot += 1;
        }
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    }
    for (j, (o, bcm)) in outputs.iter().zip([ROLE_BCM1, ROLE_BCM2]).enumerate() {
        if j == 1 {
            program[slot] = ROLE_ARHO;
            sw[slot].w[5..9].copy_from_slice(&nf1);
            slot += 1;
        }
        program[slot] = ROLE_ACMOUT;
        sw[slot].w[4] = o.value;
        sw[slot].w[..4].copy_from_slice(&o.rkm);
        sw[slot].w[5..9].copy_from_slice(&out_rho[j]);
        sw[slot].w[9..13].copy_from_slice(&o.rseed);
        sw[slot].w[13] = o.asset;
        slot += 1;
        program[slot] = bcm;
        slot += 1;
    }
    program[slot] = ROLE_BAL;
    slot += 1;
    program[slot] = ROLE_END;
    slot += 1;
    assert_eq!(slot, SHAPE_P_PERMS, "program layout drifted");

    let a1 = inputs[0].asset;
    let sel_o1a = outputs[0].asset == a1;
    let sel_o2a = outputs[1].asset == a1;
    let sel_f1 = a1 == 0;
    let sel_q = a1 == inputs[1].asset;
    let hy = [policy[0].leaf.mode == MODE_HYBRID, policy[1].leaf.mode == MODE_HYBRID];
    let rg = [policy[0].leaf.mode == MODE_REGULATED, policy[1].leaf.mode == MODE_REGULATED];
    let ropen = [
        policy[0].leaf.flags & FLAG_REDEEM_OPEN != 0,
        policy[1].leaf.flags & FLAG_REDEEM_OPEN != 0,
    ];
    let vpa = [
        if vp[0].amount != 0 { inputs[0].asset } else { 0 },
        if vp[1].amount != 0 { inputs[1].asset } else { 0 },
    ];
    let pvs = pv_vec_l2p(&anchor, &nf1, &nf2, &cmo1, &cmo2, fee, &registry_root, &vp, &vpa, &nf3, &xrkm);
    L2PBucketInstance {
        air: L2ShapePAir {
            log_height,
            version: L2Version::V1,
            program: program.to_vec(),
            slot_witness: sw,
            fee,
            dv: false,
            sel_o1a,
            sel_o2a,
            sel_f1,
            sel_q,
            hy,
            rg,
            ropen,
            vp,
            d3: fee_slot.is_dummy(),
            asset: [inputs[0].asset, inputs[1].asset],
            xrkm,
            sel_o3a: false,
            sel_o3f: false,
        },
        pvs,
        anchor,
        registry_root,
        nf: [nf1, nf2],
        cm_out: [cmo1, cmo2],
        nf3,
    }
}

/// Build shape P against **fabricated** trees: the commitment tree holds both
/// inputs at leaves 0/1, the registry holds the two assets' leaves, and each
/// input's policy openings come from its asset's trees. Panics if an input's
/// `rkm` is frozen or (Regulated) not allowlisted — the negatives build those
/// by hand through `build_bucket_l2p_with_witnesses`.
pub fn build_bucket_l2p(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    assets: &[PolicyAsset; 2],
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    build_bucket_l2p_exit(log_height, inputs, outputs, fee, assets, vp, [0; 4])
}

/// [`build_bucket_l2p`] with the exit recipient `xrkm` (lab #785 F5-4d).
pub fn build_bucket_l2p_exit(
    log_height: usize,
    inputs: &[L2TxInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    assets: &[PolicyAsset; 2],
    vp: [VPublic; 2],
    xrkm: [u64; 4],
) -> L2PBucketInstance {
    let (_, _, cm1) = derive_input_l2(&inputs[0]);
    let (_, _, cm2) = derive_input_l2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0]
            .policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0])
            .expect("input 0: rkm frozen or not allowlisted"),
        assets[1]
            .policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1])
            .expect("input 1: rkm frozen or not allowlisted"),
    ];
    build_bucket_l2p_exit_with_witnesses(
        log_height, inputs, outputs, fee, &witnesses, anchor, &policy, registry_root, vp,
        &FeeSlot::Dummy { input: dummy_fee_input(&inputs[0].rho) },
        xrkm,
    )
}

/// Shape P with **input slot 1 a dummy** (#219 on L2): `dv = true`, the dummy
/// carries value 0 and asset 0 (Cloaked, the empty trees).
pub fn build_bucket_l2p_dummy1_fabricated(
    log_height: usize,
    real: &L2TxInput,
    real_asset: &PolicyAsset,
    dummy: &L2TxInput,
    outputs: &[L2TxOutput; 2],
    fee: u64,
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    assert_eq!(dummy.value, 0, "a dummy input slot contributes 0 to the balance");
    assert_eq!(dummy.asset, 0, "a dummy input slot carries asset 0 (#700)");
    let (_, _, cm_real) = derive_input_l2(real);
    let (w_real, anchor) = fabricated_single_tree(&cm_real);
    let assets = [real_asset.clone(), PolicyAsset::cloaked(0)];
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&derive_rkm_l2(real), rw[0]).expect("real input"),
        assets[1].policy_input_for(&derive_rkm_l2(dummy), rw[1]).expect("dummy input"),
    ];
    let mut inst = build_bucket_l2p_with_witnesses(
        log_height,
        &[real.clone(), dummy.clone()],
        outputs,
        fee,
        &[w_real, off_tree_witness()],
        anchor,
        &policy,
        registry_root,
        vp,
        &FeeSlot::Dummy { input: dummy_fee_input(&real.rho) },
    );
    inst.air.dv = true;
    inst
}

// ---------------------------------------------------------------------------
// Trace generation — l2.rs's fill, mirrored constraint for constraint, plus
// the shape-P columns.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// v2 instances (Candidate A) — lab #896 seam C
// ---------------------------------------------------------------------------

/// v2 perm slots: v1's 252, minus `ANK` per chain, plus `AAUTH`, `D_AUTH − 1`
/// `MERKLE` and `BAUTH` per chain = 252 + 3·D_AUTH = **288** at D12 → 2^20
/// (341 perm capacity), the 288-slot ring exactly full.
pub const SHAPE_P_PERMS_V2: usize = SHAPE_P_PERMS + 3 * D_AUTH;
const _: () = assert!(SHAPE_P_PERMS_V2 <= PROGRAM_SLOTS_V2);
const _: () = assert!(SHAPE_P_PERMS_V2 * crate::l2::ROWS_PER_PERM <= 1 << SHAPE_P_LOG_HEIGHT);

/// Build a v2 shape-P instance. As [`build_bucket_l2p_exit_with_witnesses`],
/// with v2 inputs (`nk` + auth path) and a device-made fee slot; `dv`
/// declares input slot 2 a dummy (it still proves its leaf under its own
/// throwaway `auth_root`). The policy openings must be keyed by the v2 `rkm`
/// (`derive_input_l2_v2(..).1`).
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2p_v2(
    log_height: usize,
    inputs: &[L2AuthInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &FeeSlotV2,
    xrkm: [u64; 4],
    dv: bool,
) -> L2PBucketInstance {
    let b = build_bucket_l2p_auth(
        L2Version::V2Auth,
        log_height,
        inputs,
        outputs,
        fee,
        witnesses,
        anchor,
        policy,
        registry_root,
        vp,
        fee_slot,
        xrkm,
        dv,
    );
    L2PBucketInstance {
        air: b.air,
        pvs: b.pvs,
        anchor,
        registry_root,
        nf: [b.nf[0], b.nf[1]],
        cm_out: [b.cm_out[0], b.cm_out[1]],
        nf3: b.nf[2],
    }
}

/// What [`build_bucket_l2p_auth`] returns; the v2/v3 builders wrap it.
struct AuthBuildP {
    air: L2ShapePAir,
    pvs: Vec<u32>,
    nf: [[u64; 4]; 3],
    cm_out: Vec<[u64; 4]>,
}

/// The v2/v3 P builder: identical input chains; one output span per output.
#[allow(clippy::too_many_arguments)]
fn build_bucket_l2p_auth(
    version: L2Version,
    log_height: usize,
    inputs: &[L2AuthInput; 2],
    outputs: &[L2TxOutput],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &FeeSlotV2,
    xrkm: [u64; 4],
    dv: bool,
) -> AuthBuildP {
    let (n_out, period, perms) = match version {
        L2Version::V2Auth => (2, PROGRAM_SLOTS_V2, SHAPE_P_PERMS_V2),
        L2Version::V3 => (3, PROGRAM_SLOTS_V3, SHAPE_P_PERMS_V3),
        L2Version::V1 => panic!("v1 has its own builder"),
    };
    assert_eq!(outputs.len(), n_out, "{version:?} carries exactly {n_out} outputs");
    if dv {
        assert_eq!(inputs[1].value, 0, "a dummy input slot contributes 0 to the balance");
        assert_eq!(inputs[1].asset, 0, "a dummy input slot carries asset 0 (#700)");
    }
    let fee_in = fee_slot.input();
    let (nf1, _, _) = derive_input_l2_v2(&inputs[0]);
    let (nf2, _, _) = derive_input_l2_v2(&inputs[1]);
    let (nf3, _, _) = derive_input_l2_v2(fee_in);
    let out_rho: Vec<[u64; 4]> = (0..n_out).map(|j| derive_output_rho_l2(&nf1, j)).collect();
    let cm_out: Vec<[u64; 4]> = outputs
        .iter()
        .zip(&out_rho)
        .map(|(o, rho)| l2_cm(o.value, o.asset, &o.rkm, rho, &o.rseed))
        .collect();

    let mut program = vec![ROLE_DUMMY; period];
    let mut sw = vec![L2PSlotWitness::default(); period];
    let mut slot = 1usize;
    let path = |program: &mut Vec<u32>, sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, sibs: &[[u64; 4]], bits: &[bool]| {
        for (sib, bit) in sibs.iter().zip(bits.iter()) {
            program[*slot] = ROLE_MERKLE;
            sw[*slot].w[..4].copy_from_slice(sib);
            sw[*slot].pbit = *bit;
            *slot += 1;
        }
    };
    // NFA → bnf → AAUTH → (D−1)×MERKLE → BAUTH.
    let nfa_auth = |program: &mut Vec<u32>, sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, inp: &L2AuthInput, bnf: u32| {
        program[*slot] = ROLE_NFA;
        sw[*slot].w[..4].copy_from_slice(&inp.rho);
        sw[*slot].w[9..13].copy_from_slice(&inp.nk);
        *slot += 1;
        program[*slot] = bnf;
        *slot += 1;
        let a = &inp.auth;
        program[*slot] = ROLE_AAUTH;
        sw[*slot].w[..4].copy_from_slice(&a.leaf);
        sw[*slot].w[4..8].copy_from_slice(&a.siblings[0]);
        sw[*slot].pbit = a.leaf_index & 1 == 1;
        *slot += 1;
        for k in 1..D_AUTH {
            program[*slot] = ROLE_MERKLE;
            sw[*slot].w[..4].copy_from_slice(&a.siblings[k]);
            sw[*slot].pbit = (a.leaf_index >> k) & 1 == 1;
            *slot += 1;
        }
        program[*slot] = ROLE_BAUTH;
        *slot += 1;
    };
    // ARKM / ARKM2 with the v2 message: nk, d, auth_root.
    let arkm = |program: &mut Vec<u32>, sw: &mut Vec<L2PSlotWitness>, slot: &mut usize, inp: &L2AuthInput, role: u32| {
        program[*slot] = role;
        sw[*slot].w[..4].copy_from_slice(&inp.nk);
        sw[*slot].w[5] = inp.d[0];
        sw[*slot].w[6] = inp.d[1];
        sw[*slot].w[7..11].copy_from_slice(&inp.auth.root());
        *slot += 1;
    };
    for (k, bnf) in [ROLE_BNF1, ROLE_BNF2].into_iter().enumerate() {
        let (inp, pol, witness) = (&inputs[k], &policy[k], &witnesses[k]);
        nfa_auth(&mut program, &mut sw, &mut slot, inp, bnf);
        program[slot] = ROLE_AISS;
        sw[slot].w[..4].copy_from_slice(&pol.isk);
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, inp, ROLE_ARKM);
        program[slot] = ROLE_AFKEY;
        slot += 1;
        program[slot] = ROLE_AFRZ;
        sw[slot].w[..4].copy_from_slice(&pol.freeze.key_lo);
        sw[slot].w[5..9].copy_from_slice(&pol.freeze.key_hi);
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.freeze.witness.siblings, &pol.freeze.witness.path_bits);
        program[slot] = ROLE_AREG;
        sw[slot].w[..4].copy_from_slice(&pol.leaf.issuer_key);
        sw[slot].w[4] = pol.leaf.mode;
        sw[slot].w[5..9].copy_from_slice(&pol.leaf.freeze_root);
        sw[slot].w[9..13].copy_from_slice(&pol.leaf.allow_root);
        sw[slot].w[13] = pol.leaf.asset;
        sw[slot].w[14] = pol.leaf.flags;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.reg_witness.siblings, &pol.reg_witness.path_bits);
        program[slot] = ROLE_BREG;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, inp, ROLE_ARKM2);
        program[slot] = ROLE_ACRED;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &pol.allow.siblings, &pol.allow.path_bits);
        program[slot] = ROLE_BALLOW;
        slot += 1;
        arkm(&mut program, &mut sw, &mut slot, inp, ROLE_ARKM2);
        program[slot] = ROLE_ACM;
        sw[slot].w[4] = inp.value;
        sw[slot].w[5..9].copy_from_slice(&inp.rho);
        sw[slot].w[9..13].copy_from_slice(&inp.rseed);
        sw[slot].w[13] = inp.asset;
        slot += 1;
        path(&mut program, &mut sw, &mut slot, &witness.siblings, &witness.path_bits);
        program[slot] = ROLE_BANCHOR;
        slot += 1;
    }
    // The fee chain: no policy (asset 0 is forced).
    nfa_auth(&mut program, &mut sw, &mut slot, fee_in, ROLE_BNF3);
    arkm(&mut program, &mut sw, &mut slot, fee_in, ROLE_ARKM);
    program[slot] = ROLE_ACMF;
    sw[slot].w[4] = fee_in.value;
    sw[slot].w[5..9].copy_from_slice(&fee_in.rho);
    sw[slot].w[9..13].copy_from_slice(&fee_in.rseed);
    sw[slot].w[13] = fee_in.asset;
    slot += 1;
    let fw = fee_slot.witness();
    path(&mut program, &mut sw, &mut slot, &fw.siblings, &fw.path_bits);
    program[slot] = ROLE_BANCHOR;
    slot += 1;
    for (j, o) in outputs.iter().enumerate() {
        let bcm = if j == 0 { ROLE_BCM1 } else { ROLE_BCM2 };
        if j >= 1 {
            program[slot] = ROLE_ARHO;
            sw[slot].w[5..9].copy_from_slice(&nf1);
            slot += 1;
        }
        program[slot] = ROLE_ACMOUT;
        sw[slot].w[4] = o.value;
        sw[slot].w[..4].copy_from_slice(&o.rkm);
        sw[slot].w[5..9].copy_from_slice(&out_rho[j]);
        sw[slot].w[9..13].copy_from_slice(&o.rseed);
        sw[slot].w[13] = o.asset;
        slot += 1;
        program[slot] = bcm;
        slot += 1;
    }
    program[slot] = ROLE_BAL;
    slot += 1;
    program[slot] = ROLE_END;
    slot += 1;
    assert_eq!(slot, perms, "{version:?} program layout drifted");

    let a1 = inputs[0].asset;
    let hy = [policy[0].leaf.mode == MODE_HYBRID, policy[1].leaf.mode == MODE_HYBRID];
    let rg = [policy[0].leaf.mode == MODE_REGULATED, policy[1].leaf.mode == MODE_REGULATED];
    let ropen = [
        policy[0].leaf.flags & FLAG_REDEEM_OPEN != 0,
        policy[1].leaf.flags & FLAG_REDEEM_OPEN != 0,
    ];
    let vpa = [
        if vp[0].amount != 0 { inputs[0].asset } else { 0 },
        if vp[1].amount != 0 { inputs[1].asset } else { 0 },
    ];
    let leaves = [inputs[0].auth.leaf, inputs[1].auth.leaf, fee_in.auth.leaf];
    // Lab #937 A′: shape S's rule — output 3 rides the fee bank when slot 3
    // is a real fee note, output 3 is asset 0, and that note carries more
    // than the fee or no row is asset 0.
    let o3f = n_out == 3
        && !fee_slot.is_dummy()
        && outputs[2].asset == 0
        && (fee_in.value != fee || (a1 != 0 && inputs[1].asset != 0));
    let pvs = if n_out == 3 {
        let cm3: [[u64; 4]; 3] = [cm_out[0], cm_out[1], cm_out[2]];
        pv_vec_l2p_v3(&anchor, &nf1, &nf2, &cm3, fee, &registry_root, &vp, &vpa, &nf3, &xrkm, &leaves)
    } else {
        pv_vec_l2p_v2(&anchor, &nf1, &nf2, &cm_out[0], &cm_out[1], fee, &registry_root, &vp, &vpa, &nf3, &xrkm, &leaves)
    };
    AuthBuildP {
        air: L2ShapePAir {
            log_height,
            version,
            program,
            slot_witness: sw,
            fee,
            dv,
            sel_o1a: outputs[0].asset == a1,
            sel_o2a: outputs[1].asset == a1,
            sel_f1: a1 == 0,
            sel_q: a1 == inputs[1].asset,
            hy,
            rg,
            ropen,
            vp,
            d3: fee_slot.is_dummy(),
            asset: [inputs[0].asset, inputs[1].asset],
            xrkm,
            sel_o3a: n_out == 3 && !o3f && outputs[2].asset == a1,
            sel_o3f: o3f,
        },
        pvs,
        nf: [nf1, nf2, nf3],
        cm_out,
    }
}

/// [`build_bucket_l2p_v2`] against fabricated commitment and registry trees,
/// policy openings keyed by each input's v2 `rkm`, a device-made dummy fee
/// slot. Panics if an input is frozen or (Regulated) not allowlisted.
pub fn build_bucket_l2p_v2_fabricated(
    inputs: &[L2AuthInput; 2],
    outputs: &[L2TxOutput; 2],
    fee: u64,
    assets: &[PolicyAsset; 2],
    vp: [VPublic; 2],
) -> L2PBucketInstance {
    let (_, rkm1, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, rkm2, cm2) = derive_input_l2_v2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&rkm1, rw[0]).expect("input 0: rkm frozen or not allowlisted"),
        assets[1].policy_input_for(&rkm2, rw[1]).expect("input 1: rkm frozen or not allowlisted"),
    ];
    build_bucket_l2p_v2(
        SHAPE_P_LOG_HEIGHT,
        inputs,
        outputs,
        fee,
        &witnesses,
        anchor,
        &policy,
        registry_root,
        vp,
        &FeeSlotV2::Dummy { input: fabricated_auth_input(0xfee0_d00d, 0, 0, 1833) },
        [0; 4],
        false,
    )
}

/// The canonical honest v2 P instance: asset 0 (Cloaked) 100 + asset 7
/// (Hybrid, issuer key set, nothing frozen) 50 in, 90 + 50 out, fee 10, no
/// `vPublic` — a holder spend, the only P a shared prover may take (2b §2).
pub fn fabricated_bucket_l2p_v2() -> L2PBucketInstance {
    let inputs = [fabricated_auth_input(0x1111, 100, 0, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    let mk_out = |seed: u64, value: u64, asset: u64| L2TxOutput {
        value,
        asset,
        rkm: [seed, seed + 1, seed + 2, seed + 3],
        rho: [seed + 4; 4],
        rseed: [seed + 5; 4],
    };
    build_bucket_l2p_v2_fabricated(
        &inputs,
        &[mk_out(0x3333, 90, 0), mk_out(0x4444, 50, 7)],
        10,
        &[PolicyAsset::cloaked(0), PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[])],
        [VPublic::NONE; 2],
    )
}

/// Three real slots (lab #896 M): a Cloaked asset-0 input (100) and a Hybrid
/// asset-7 input (50, freeze tree live), the fee slot a real asset-0 note
/// worth exactly the fee (`d3 = 0`), all three in one fabricated commitment
/// tree; outputs 100 (asset 0) + 50 (asset 7), fee 10, no `vPublic` — a
/// holder spend. The box measurement's P instance.
pub fn fabricated_bucket_l2p_v2_exact_fee() -> L2PBucketInstance {
    let inputs = [fabricated_auth_input(0x1111, 100, 0, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    let fee_in = fabricated_auth_input(0x9999, 10, 0, 3350);
    let (_, rkm1, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, rkm2, cm2) = derive_input_l2_v2(&inputs[1]);
    let (_, _, cm3) = derive_input_l2_v2(&fee_in);
    let (w, anchor) = crate::l2::fabricated_tree3([&cm1, &cm2, &cm3]);
    let assets = [PolicyAsset::cloaked(0), PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[])];
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&rkm1, rw[0]).expect("input 0 policy"),
        assets[1].policy_input_for(&rkm2, rw[1]).expect("input 1 policy"),
    ];
    let mk_out = |seed: u64, value: u64, asset: u64| L2TxOutput {
        value,
        asset,
        rkm: [seed, seed + 1, seed + 2, seed + 3],
        rho: [seed + 4; 4],
        rseed: [seed + 5; 4],
    };
    build_bucket_l2p_v2(
        SHAPE_P_LOG_HEIGHT,
        &inputs,
        &[mk_out(0x3333, 100, 0), mk_out(0x4444, 50, 7)],
        10,
        &[w[0], w[1]],
        anchor,
        &policy,
        registry_root,
        [VPublic::NONE; 2],
        &FeeSlotV2::Exact { input: fee_in, witness: w[2] },
        [0; 4],
        false,
    )
}

/// The witness-free v2 shape-P AIR a verifier uses.
pub fn verifier_air_p_v2() -> L2ShapePAir {
    L2ShapePAir {
        program: fabricated_bucket_l2p_v2().air.program,
        ..L2ShapePAir::chain_only_v2(SHAPE_P_LOG_HEIGHT)
    }
}

/// v3 perm slots: v2's 288 + `ARHO`, `ACMOUT`, `BCM2` = **291** at D12, at
/// 3072 rows each = 893,952 rows → still 2^20 (341 perm capacity).
pub const SHAPE_P_PERMS_V3: usize = SHAPE_P_PERMS_V2 + 3;
const _: () = assert!(SHAPE_P_PERMS_V3 <= PROGRAM_SLOTS_V3);
const _: () = assert!(SHAPE_P_PERMS_V3 * crate::l2::ROWS_PER_PERM <= 1 << SHAPE_P_LOG_HEIGHT);

/// A v3 shape-P instance: v2's, with three output commitments.
#[cfg_attr(test, derive(Clone))]
pub struct L2PBucketInstanceV3 {
    pub air: L2ShapePAir,
    pub pvs: Vec<u32>,
    pub anchor: [u64; 4],
    pub registry_root: [u64; 4],
    pub nf: [[u64; 4]; 2],
    pub cm_out: [[u64; 4]; 3],
    pub nf3: [u64; 4],
}

/// Build a v3 shape-P instance: [`build_bucket_l2p_v2`]'s inputs, exactly
/// three outputs (the third a zero-value self note when there is nothing
/// else to pay — lab #937).
#[allow(clippy::too_many_arguments)]
pub fn build_bucket_l2p_v3(
    log_height: usize,
    inputs: &[L2AuthInput; 2],
    outputs: &[L2TxOutput; 3],
    fee: u64,
    witnesses: &[MerkleWitness; 2],
    anchor: [u64; 4],
    policy: &[L2PolicyInput; 2],
    registry_root: [u64; 4],
    vp: [VPublic; 2],
    fee_slot: &FeeSlotV2,
    xrkm: [u64; 4],
    dv: bool,
) -> L2PBucketInstanceV3 {
    let b = build_bucket_l2p_auth(
        L2Version::V3,
        log_height,
        inputs,
        outputs,
        fee,
        witnesses,
        anchor,
        policy,
        registry_root,
        vp,
        fee_slot,
        xrkm,
        dv,
    );
    L2PBucketInstanceV3 {
        air: b.air,
        pvs: b.pvs,
        anchor,
        registry_root,
        nf: [b.nf[0], b.nf[1]],
        cm_out: [b.cm_out[0], b.cm_out[1], b.cm_out[2]],
        nf3: b.nf[2],
    }
}

/// [`build_bucket_l2p_v3`] against fabricated commitment and registry trees,
/// policy openings keyed by each input's v2 `rkm`, a device-made dummy fee
/// slot — [`build_bucket_l2p_v2_fabricated`] with three outputs.
pub fn build_bucket_l2p_v3_fabricated(
    inputs: &[L2AuthInput; 2],
    outputs: &[L2TxOutput; 3],
    fee: u64,
    assets: &[PolicyAsset; 2],
    vp: [VPublic; 2],
) -> L2PBucketInstanceV3 {
    let (_, rkm1, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, rkm2, cm2) = derive_input_l2_v2(&inputs[1]);
    let (witnesses, anchor) = fabricated_shared_tree(&cm1, &cm2);
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&rkm1, rw[0]).expect("input 0: rkm frozen or not allowlisted"),
        assets[1].policy_input_for(&rkm2, rw[1]).expect("input 1: rkm frozen or not allowlisted"),
    ];
    build_bucket_l2p_v3(
        SHAPE_P_LOG_HEIGHT,
        inputs,
        outputs,
        fee,
        &witnesses,
        anchor,
        &policy,
        registry_root,
        vp,
        &FeeSlotV2::Dummy { input: fabricated_auth_input(0xfee0_d00d, 0, 0, 1833) },
        [0; 4],
        false,
    )
}

/// The fabricated outputs' shape (as the v2 fixtures build theirs).
pub(crate) fn mk_out_p(seed: u64, value: u64, asset: u64) -> L2TxOutput {
    L2TxOutput {
        value,
        asset,
        rkm: [seed, seed + 1, seed + 2, seed + 3],
        rho: [seed + 4; 4],
        rseed: [seed + 5; 4],
    }
}

/// The canonical honest v3 P instance: [`fabricated_bucket_l2p_v2`] with its
/// asset-0 output split in two — 85 + 50 (asset 7) + 5 (asset 0, the third).
pub fn fabricated_bucket_l2p_v3() -> L2PBucketInstanceV3 {
    let inputs = [fabricated_auth_input(0x1111, 100, 0, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    build_bucket_l2p_v3_fabricated(
        &inputs,
        &[mk_out_p(0x3333, 85, 0), mk_out_p(0x4444, 50, 7), mk_out_p(0x5555, 5, 0)],
        10,
        &[PolicyAsset::cloaked(0), PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[])],
        [VPublic::NONE; 2],
    )
}

/// Three real input slots, three outputs (the third a zero-value self note):
/// v3's counterpart of [`fabricated_bucket_l2p_v2_exact_fee`] — the rig
/// measurement's P instance.
pub fn fabricated_bucket_l2p_v3_exact_fee() -> L2PBucketInstanceV3 {
    let inputs = [fabricated_auth_input(0x1111, 100, 0, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    let fee_in = fabricated_auth_input(0x9999, 10, 0, 3350);
    let (_, rkm1, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, rkm2, cm2) = derive_input_l2_v2(&inputs[1]);
    let (_, _, cm3) = derive_input_l2_v2(&fee_in);
    let (w, anchor) = crate::l2::fabricated_tree3([&cm1, &cm2, &cm3]);
    let assets = [PolicyAsset::cloaked(0), PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[])];
    let leaves = [assets[0].leaf(), assets[1].leaf()];
    let (rw, registry_root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
    let policy = [
        assets[0].policy_input_for(&rkm1, rw[0]).expect("input 0 policy"),
        assets[1].policy_input_for(&rkm2, rw[1]).expect("input 1 policy"),
    ];
    build_bucket_l2p_v3(
        SHAPE_P_LOG_HEIGHT,
        &inputs,
        &[mk_out_p(0x3333, 100, 0), mk_out_p(0x4444, 50, 7), mk_out_p(0x5555, 0, 0)],
        10,
        &[w[0], w[1]],
        anchor,
        &policy,
        registry_root,
        [VPublic::NONE; 2],
        &FeeSlotV2::Exact { input: fee_in, witness: w[2] },
        [0; 4],
        false,
    )
}

/// Lab #937 A′: shape S's fee-bank spend in P — two asset-7 (Hybrid) notes,
/// 60 and 50, into 100 and 10; a fee note of `fee_note` pays `fee` and
/// output 3 through the fee bank (`o3f`).
pub fn fabricated_bucket_l2p_v3_fee_bank(fee_note: u64, outputs: [L2TxOutput; 3], fee: u64) -> L2PBucketInstanceV3 {
    let inputs = [fabricated_auth_input(0x1111, 60, 7, 2885), fabricated_auth_input(0x2222, 50, 7, 2468)];
    let fee_in = fabricated_auth_input(0x9999, fee_note, 0, 3350);
    let (_, rkm1, cm1) = derive_input_l2_v2(&inputs[0]);
    let (_, rkm2, cm2) = derive_input_l2_v2(&inputs[1]);
    let (_, _, cm3) = derive_input_l2_v2(&fee_in);
    let (w, anchor) = crate::l2::fabricated_tree3([&cm1, &cm2, &cm3]);
    let asset = PolicyAsset::hybrid(7, [0x7a, 0x7b, 0x7c, 0x7d], false, &[]);
    let (rw, registry_root) = fabricated_registry_tree(&asset.leaf().hash(), &asset.leaf().hash());
    let policy = [
        asset.policy_input_for(&rkm1, rw[0]).expect("input 0 policy"),
        asset.policy_input_for(&rkm2, rw[1]).expect("input 1 policy"),
    ];
    build_bucket_l2p_v3(
        SHAPE_P_LOG_HEIGHT,
        &inputs,
        &outputs,
        fee,
        &[w[0], w[1]],
        anchor,
        &policy,
        registry_root,
        [VPublic::NONE; 2],
        &FeeSlotV2::Exact { input: fee_in, witness: w[2] },
        [0; 4],
        false,
    )
}

/// Lab #937 A′: the canonical P fee-bank spend (fee 10, prover fee 3).
pub fn fabricated_bucket_l2p_v3_prover_fee() -> L2PBucketInstanceV3 {
    fabricated_bucket_l2p_v3_fee_bank(
        13,
        [mk_out_p(0x3333, 100, 7), mk_out_p(0x4444, 10, 7), mk_out_p(0x5555, 3, 0)],
        10,
    )
}

/// The witness-free v3 shape-P AIR a verifier uses.
pub fn verifier_air_p_v3() -> L2ShapePAir {
    L2ShapePAir {
        program: fabricated_bucket_l2p_v3().air.program,
        ..L2ShapePAir::chain_only_v3(SHAPE_P_LOG_HEIGHT)
    }
}

impl L2ShapePAir {
    pub fn generate_trace<F: Field>(&self, extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        let height = 1usize << self.log_height;
        let width = <Self as BaseAir<F>>::width(self);
        let v2 = self.is_v2();
        let v3 = self.is_v3();
        let size = height * width;
        let mut values = Vec::with_capacity(size << extra_capacity_bits);

        let mut s = [0u32; S_SLOTS + 1];
        let mut v = [0u32; V_SLOTS + 1];
        let mut u = [0u32; U_SLOTS + 1];
        let mut r: [u32; 24] = core::array::from_fn(|i| Self::rc_pack((23 + i) % 24));
        let mut pb: [u32; 24] = core::array::from_fn(|i| (i == 0) as u32);
        let mut ph: [u32; 4] = core::array::from_fn(|i| (i == 0) as u32);
        let mut pr: Vec<u32> = (0..self.ring_limbs()).map(|i| self.pr_limb(i)).collect();
        let mut perm_idx = 0usize;
        let role_of = |p: usize| self.program[p % self.program.len()];
        let wit = |p: usize| -> L2PSlotWitness {
            if self.slot_witness.is_empty() {
                L2PSlotWitness::default()
            } else {
                self.slot_witness[p % self.slot_witness.len()]
            }
        };
        let mut cur = wit(0);
        let mut eq = [0i64; 32];
        let mut ep: u32 = 1;
        let mut bq = [0i64; 16];
        let mut bl = [0i64; 4];
        let mut bl2 = [0i64; 4];
        let mut latch: u32 = 0;
        let dvv: u32 = self.dv as u32;
        // A4: the fee chain's latch, `d3`, the fee bank.
        let mut l3: u32 = 0;
        let d3v: u32 = self.d3 as u32;
        let mut fb = [0i64; 4];
        let mut eq3 = [0i64; 16];
        let mut eql = [0i64; 16];
        let mut eqa = [0i64; 16];
        let mut om: u32 = 0;
        let mut ac = [0i64; 6];
        // v3: the second marker, output 3's held asset, its selector.
        let mut om2: u32 = 0;
        let mut ac3: i64 = 0;
        let sel3: u32 = self.sel_o3a as u32;
        let o3fv: u32 = self.sel_o3f as u32;
        let sel2: [u32; 4] = [
            self.sel_o1a as u32,
            self.sel_o2a as u32,
            self.sel_f1 as u32,
            self.sel_q as u32,
        ];
        let qinv: F = {
            let mut assets = self
                .program
                .iter()
                .enumerate()
                .filter(|(_, r)| **r == ROLE_ACM)
                .map(|(i, _)| (wit(i).w[13] & 0xffff) as u32);
            let a1 = assets.next().unwrap_or(0);
            let a2 = assets.next().unwrap_or(0);
            let d = F::from_u32(a1) - F::from_u32(a2);
            if self.sel_q || d == F::ZERO {
                F::ZERO
            } else {
                d.inverse()
            }
        };
        // Policy constants.
        let hy: [u32; 2] = [self.hy[0] as u32, self.hy[1] as u32];
        let rg: [u32; 2] = [self.rg[0] as u32, self.rg[1] as u32];
        let ropen: [u32; 2] = [self.ropen[0] as u32, self.ropen[1] as u32];
        let sum_m = |k: usize| -> u32 {
            (0..4).map(|j| ((self.vp[k].amount >> (16 * j)) & 0xffff) as u32).sum()
        };
        let nz: [u32; 2] = [(sum_m(0) != 0) as u32, (sum_m(1) != 0) as u32];
        let vpinv: [F; 2] = core::array::from_fn(|k| {
            let sm = F::from_u32(sum_m(k));
            if sm == F::ZERO {
                F::ZERO
            } else {
                sm.inverse()
            }
        });
        let sgn: [u32; 2] = [self.vp[0].redeem as u32, self.vp[1].redeem as u32];
        // Lab #785 F5-4d: the exit edge.
        let zf: [u32; 2] = [(self.asset[0] == 0) as u32, (self.asset[1] == 0) as u32];
        let zinv: [F; 2] = core::array::from_fn(|k| {
            let a = F::from_u64(self.asset[k]);
            if a == F::ZERO { F::ZERO } else { a.inverse() }
        });
        let ek: [u32; 2] = core::array::from_fn(|k| sgn[k] * zf[k] * nz[k]);
        let xe: u32 = ek[0] + ek[1] - ek[0] * ek[1];
        let xinv: F = {
            let sx: u64 = self.xrkm.iter().flat_map(|l| (0..4).map(move |j| (l >> (16 * j)) & 0xffff)).sum();
            let sx = F::from_u64(sx);
            if sx == F::ZERO { F::ZERO } else { sx.inverse() }
        };
        let req: [u32; 2] = core::array::from_fn(|k| nz[k] * (1 - sgn[k] * ropen[k]) * (1 - sgn[k] * zf[k]));
        // Running comparison flags [block][lane].
        let mut cmp_lt = [[0u32; 4]; 2];
        let mut cmp_eq = [[0u32; 4]; 2];

        let bit = |w: u32, i: usize| (w >> i) & 1;

        for t in 0..height {
            let mrow = (t / 64) % 2 == 0;
            let z = t % 64;

            let us: [u32; 25] = core::array::from_fn(|l| bit(s[1], l));
            let uv: [u32; 25] = core::array::from_fn(|l| bit(v[1], l));
            let uu: [u32; 10] = core::array::from_fn(|i| bit(u[1], i));

            let b = |bx: usize, by: usize| us[INV_PI[bx + 5 * by]];
            let chi = |x: usize, y: usize| {
                b(x, y) ^ ((1 - b((x + 1) % 5, y)) & b((x + 2) % 5, y))
            };
            let x00 = chi(0, 0);
            let rc = Self::rc_bit(t) as u32;
            let a: [u32; 25] = core::array::from_fn(|l| {
                if l == 0 {
                    x00 ^ rc
                } else {
                    chi(l % 5, l / 5)
                }
            });
            let role_now = role_of(perm_idx);
            let bnd_now = ((mrow as u32) * pb[0]) == 1;
            let wbit: [u32; NW] = core::array::from_fn(|i| ((cur.w[i] >> z) & 1) as u32);
            let pbv = cur.pbit as u32;
            let z0 = (z == 0) as u32;
            let z1 = (z == 1) as u32;
            let z63 = (z == 63) as u32;
            let eff: [u32; 25] = core::array::from_fn(|l| {
                if !bnd_now {
                    return a[l];
                }
                match role_now {
                    ROLE_MERKLE | ROLE_NF => match l {
                        0..=3 => pbv * wbit[l] + (1 - pbv) * a[l],
                        4..=7 => pbv * a[l - 4] + (1 - pbv) * wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ANK => match l {
                        0..=3 => wbit[l],
                        4 => z0,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARKM | ROLE_ARKM2 if v2 => match l {
                        0..=3 => wbit[l],
                        4 => z1,
                        5 => wbit[5],
                        6 => wbit[6],
                        7..=10 => wbit[l],
                        11 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARKM | ROLE_ARKM2 => match l {
                        0..=3 => wbit[l],
                        4 => z1,
                        5 => wbit[5],
                        6 => wbit[6],
                        7 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_NFA if v2 => match l {
                        0..=3 => wbit[l + 9],
                        4..=7 => wbit[l - 4],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AAUTH if v2 => match l {
                        0..=3 => pbv * wbit[l + 4] + (1 - pbv) * wbit[l],
                        4..=7 => pbv * wbit[l - 4] + (1 - pbv) * wbit[l],
                        8 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ARHO => match l {
                        0..=3 => wbit[l + 5],
                        4 if v3 => (z == 3) as u32 + om2 * z0,
                        4 => (z == 3) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACM | ROLE_ACMOUT | ROLE_ACMF => match l {
                        0 => wbit[4],
                        1 => wbit[13],
                        2..=5 => {
                            if role_now == ROLE_ACM || role_now == ROLE_ACMF {
                                a[l - 2]
                            } else {
                                wbit[l - 2]
                            }
                        }
                        6..=9 => wbit[l - 1],
                        10..=13 => wbit[l - 1],
                        14 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AREG => match l {
                        0 => wbit[13],
                        1..=4 => wbit[l - 1],
                        5 => wbit[4],
                        6..=9 => wbit[l - 1],
                        10..=13 => wbit[l - 1],
                        14 => wbit[14],
                        15 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AISS => match l {
                        0..=3 => wbit[l],
                        4 => (z == 7) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AFRZ => match l {
                        0..=3 => wbit[l],
                        4..=7 => wbit[l + 1],
                        8 => (z == 3) as u32,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_ACRED => match l {
                        0..=3 => a[l],
                        4 => (z == 15) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    ROLE_AFKEY => match l {
                        0..=3 => a[l],
                        4 => (z == 31) as u32,
                        5 => z0,
                        16 => z63,
                        _ => 0,
                    },
                    _ => a[l],
                }
            });
            let g_e1pos = (bnd_now && role_now == ROLE_NF) as i64;
            let g_e1neg = (bnd_now && role_now == ROLE_ARKM) as i64;
            let g_e2pos = g_e1pos;
            let g_e2neg = (bnd_now && (role_now == ROLE_ACM || role_now == ROLE_ACMF)) as i64;
            let c: [u32; 5] = core::array::from_fn(|x| {
                eff[x] ^ eff[x + 5] ^ eff[x + 10] ^ eff[x + 15] ^ eff[x + 20]
            });
            let ap: [u32; 25] = core::array::from_fn(|l| {
                let x = l % 5;
                uv[l] ^ uu[(x + 4) % 5] ^ uu[5 + (x + 1) % 5]
            });

            // Comparison flags for this row: M rows run the recurrence (seeded
            // at z = 0); the first T row carries it one step further (the
            // `mrow`-gated transition from z = 63 lands there); other T rows 0.
            if mrow || z == 0 {
                for blk in 0..2 {
                    for l in 0..4 {
                        let (x, y) = if blk == 0 { (wbit[l], a[l]) } else { (a[l], wbit[5 + l]) };
                        let same = 1 - x - y + 2 * x * y; // 1 iff x == y
                        let lt_bit = (1 - x) * y;
                        if z == 0 && mrow {
                            cmp_lt[blk][l] = lt_bit;
                            cmp_eq[blk][l] = same;
                        } else {
                            cmp_lt[blk][l] = lt_bit + same * cmp_lt[blk][l];
                            cmp_eq[blk][l] *= same;
                        }
                    }
                }
            } else {
                cmp_lt = [[0; 4]; 2];
                cmp_eq = [[0; 4]; 2];
            }

            let base = values.len();
            values.resize(base + width, F::ZERO);
            let row = &mut values[base..];
            for l in 0..25 {
                row[A_OFF + l] = F::from_u32(a[l]);
                row[US_OFF + l] = F::from_u32(us[l]);
                row[AP_OFF + l] = F::from_u32(ap[l]);
                row[UV_OFF + l] = F::from_u32(uv[l]);
            }
            for x in 0..5 {
                row[C_OFF + x] = F::from_u32(c[x]);
            }
            for i in 0..10 {
                row[UU_OFF + i] = F::from_u32(uu[i]);
            }
            row[X00_COL] = F::from_u32(x00);
            for (i, ri) in r.iter().enumerate() {
                row[R_OFF + i] = F::from_u32(*ri);
            }
            for k in 0..7 {
                row[B_OFF + k] = F::from_u32((r[0] >> k) & 1);
            }
            for (i, vv) in pb.iter().enumerate() {
                row[PB_OFF + i] = F::from_u32(*vv);
            }
            for (i, vv) in ph.iter().enumerate() {
                row[PH_OFF + i] = F::from_u32(*vv);
            }
            for (i, vv) in pr.iter().enumerate() {
                row[Self::ring_col(i)] = F::from_u32(*vv);
            }
            for k in 0..4 * ROLE_BITS {
                row[D_OFF + k] = F::from_u32((pr[0] >> k) & 1);
            }
            for k in 0..ROLE_BITS {
                row[RB_OFF + k] = F::from_u32((role_now >> k) & 1);
            }
            for j in 0..4u32 {
                row[LO_OFF + j as usize] = F::from_u32(((role_now & 3) == j) as u32);
            }
            let selv: [u32; NSEL] =
                core::array::from_fn(|i| (role_now == SEL_CODES[i]) as u32);
            for (i, vv) in selv.iter().enumerate() {
                row[SEL_OFF + i] = F::from_u32(*vv);
            }
            let bndv = (mrow as u32) * pb[0];
            row[INJ_OFF] = F::from_u32(bndv * (selv[0] + selv[1]));
            row[INJ_OFF + 1] = F::from_u32(bndv * selv[2]);
            row[INJ_OFF + 2] = F::from_u32(bndv * (selv[3] + selv[SEL_ARKM2]));
            row[INJ_OFF + 3] = F::from_u32(bndv * selv[4]);
            row[INJ_OFF + 4] = F::from_u32(bndv * selv[5]);
            row[INJ_OFF + 5] = F::from_u32(bndv * selv[SEL_ARHO]);
            row[INJ_OFF + 6] = F::from_u32(bndv * selv[SEL_AREG]);
            row[INJ_OFF + INJ_AISS] = F::from_u32(bndv * selv[SEL_AISS]);
            row[INJ_OFF + INJ_AFRZ] = F::from_u32(bndv * selv[SEL_AFRZ]);
            row[INJ_OFF + INJ_ACRED] = F::from_u32(bndv * selv[SEL_ACRED]);
            row[INJ_OFF + INJ_AFKEY] = F::from_u32(bndv * selv[SEL_AFKEY]);
            let injf = bndv * selv[SEL_ACMF];
            row[INJ_OFF + INJ_ACMF] = F::from_u32(injf);
            let g4 = ((t % 128 == 127) as u32) * pb[1] * ph[1];
            row[G4_COL] = F::from_u32(g4);
            let gpermv = ((t % 128 == 127) as u32) * pb[1];
            let bindsum = selv[6] + selv[7] + selv[8] + selv[9] + selv[10] + selv[SEL_BREG] + selv[SEL_BNF3];
            let mut se = [0u32; NSE];
            se[..6].copy_from_slice(&[
                selv[1] * ep,
                selv[3] * ep,
                (selv[4] + selv[SEL_ACMF]) * ep,
                selv[5] * ep,
                bindsum * ep,
                selv[11] * ep,
            ]);
            se[SE_RHO] = (selv[SEL_ARHO] + selv[5]) * ep;
            se[SE_AREG] = selv[SEL_AREG] * ep;
            for (i, vv) in se.iter().enumerate() {
                row[SE_OFF + i] = F::from_u32(*vv);
            }
            row[EP_COL] = F::from_u32(ep);
            let gwrap = gpermv * selv[12];
            row[GWRAP_COL] = F::from_u32(gwrap);
            let eg1 = bndv * se[1];
            row[EG_OFF] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 1] = F::from_u32(eg1);
            row[EG_OFF + 2] = F::from_u32(gpermv * se[1]);
            row[EG_OFF + 3] = F::from_u32(bndv * se[0]);
            row[EG_OFF + 4] = F::from_u32(bndv * se[2]);
            row[EG_OFF + 5] = F::from_u32(gpermv * se[2]);
            let bgcap = bndv * se[4];
            let bgrst = gpermv * se[4];
            row[BGCAP_COL] = F::from_u32(bgcap);
            row[BGRST_COL] = F::from_u32(bgrst);
            for (i, si) in [6usize, 7, 8, 9, 10, SEL_BREG, SEL_BNF3].iter().enumerate() {
                row[BGC_OFF + i] = F::from_u32(gpermv * selv[*si]);
            }
            let (bgc_banchor, bgc_bnf2) = (gpermv * selv[6], gpermv * selv[8]);
            let bgc_bnf3 = gpermv * selv[SEL_BNF3];
            row[LATCH_COL] = F::from_u32(latch);
            row[DV_COL] = F::from_u32(dvv);
            row[LDV_COL] = F::from_u32(latch * dvv);
            // Signed: under `o3f` (lab #937 A′) the bank holds `v(fee) − v(O3)`.
            row[FB_OFF..FB_OFF + 4].iter_mut().zip(fb.iter()).for_each(|(c, v)| {
                *c = if *v >= 0 { F::from_u32(*v as u32) } else { -F::from_u32((-*v) as u32) }
            });
            row[L3_COL] = F::from_u32(l3);
            row[D3_COL] = F::from_u32(d3v);
            row[L3D3_COL] = F::from_u32(l3 * d3v);
            let (g3pos, g3neg, g3close) = (
                bndv * se[SE_RHO],
                bndv * se[3] * om,
                gpermv * se[SE_RHO],
            );
            row[OM_COL] = F::from_u32(om);
            row[EG3_OFF] = F::from_u32(g3pos);
            row[EG3_OFF + 1] = F::from_u32(g3neg);
            row[EG3_OFF + 2] = F::from_u32(g3close);
            // `ACM`'s alone: the fee input's `ACMF` never enters the rows.
            let inj3e = bndv * selv[4] * ep;
            let inj4e = bndv * se[3];
            let injre = bndv * se[SE_AREG];
            row[INJ3E_COL] = F::from_u32(inj3e);
            row[INJ4E_COL] = F::from_u32(inj4e);
            row[INJRE_COL] = F::from_u32(injre);
            row[BLCLOSE_COL] = F::from_u32(gpermv * se[5]);
            let ag: [u32; 6] = [
                inj3e * (1 - latch),
                inj3e * latch,
                inj4e * (1 - om),
                if v3 { inj4e * om * (1 - om2) } else { inj4e * om },
                injre * (1 - latch),
                injre * latch,
            ];
            let ag_o3 = if v3 { inj4e * om * om2 } else { 0 };
            let sg3 = ag_o3 * sel3;
            let sf3 = ag_o3 * o3fv;
            if v3 {
                row[OM2_COL] = F::from_u32(om2);
                row[AG_O3_COL] = F::from_u32(ag_o3);
                row[SEL_O3A_COL] = F::from_u32(sel3);
                row[SG3_COL] = F::from_u32(sg3);
                row[O3F_COL] = F::from_u32(o3fv);
                row[SF3_COL] = F::from_u32(sf3);
            }
            for (k, vv) in ag.iter().enumerate() {
                row[AG_OFF + k] = F::from_u32(*vv);
            }
            let sg: [u32; 2] = [ag[AG_O1] * sel2[S2_O1A], ag[AG_O2] * sel2[S2_O2A]];
            row[SG_OFF] = F::from_u32(sg[0]);
            row[SG_OFF + 1] = F::from_u32(sg[1]);
            for (k, vv) in sel2.iter().enumerate() {
                row[SEL2_OFF + k] = F::from_u32(*vv);
            }
            row[QINV_COL] = qinv;
            let closev = gpermv * se[5];
            row[CQ_OFF] = F::from_u32(closev * sel2[S2_Q]);
            row[CQ_OFF + 1] = F::from_u32(closev * (1 - sel2[S2_Q]));
            // Shape-P gates and constants.
            let inj_afrze = bndv * selv[SEL_AFRZ] * ep;
            let inj_acrede = bndv * selv[SEL_ACRED] * ep;
            let inj_afkeye = bndv * selv[SEL_AFKEY] * ep;
            let close_cred = gpermv * selv[SEL_ACRED] * ep;
            let egb = bndv * selv[SEL_BALLOW] * ep;
            let egbc = gpermv * selv[SEL_BALLOW] * ep;
            let arege = gpermv * se[SE_AREG];
            let rq = req[0] + latch * (req[1] + 4 - req[0]) - latch * 4; // req[0] + latch·(req[1] − req[0]) without underflow
            let alw = rg[0] + latch * (rg[1] + 4 - rg[0]) - latch * 4;
            let crq = arege * rq;
            row[INJ_AFRZE_COL] = F::from_u32(inj_afrze);
            row[INJ_ACREDE_COL] = F::from_u32(inj_acrede);
            row[CLOSE_CRED_COL] = F::from_u32(close_cred);
            row[EGB_COL] = F::from_u32(egb);
            row[EGBC_COL] = F::from_u32(egbc);
            row[AREGE_COL] = F::from_u32(arege);
            row[CRQ_COL] = F::from_u32(crq);
            row[INJ_AFKEYE_COL] = F::from_u32(inj_afkeye);
            for blk in 0..2 {
                for l in 0..4 {
                    row[CMP_OFF + CMP_BLOCK * blk + CMP_LT + l] = F::from_u32(cmp_lt[blk][l]);
                    row[CMP_OFF + CMP_BLOCK * blk + CMP_EQ + l] = F::from_u32(cmp_eq[blk][l]);
                }
                let c1 = cmp_lt[blk][1] + cmp_eq[blk][1] * cmp_lt[blk][0];
                let c2 = cmp_lt[blk][2] + cmp_eq[blk][2] * c1;
                let c3 = cmp_lt[blk][3] + cmp_eq[blk][3] * c2;
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C] = F::from_u32(c1);
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C + 1] = F::from_u32(c2);
                row[CMP_OFF + CMP_BLOCK * blk + CMP_C + 2] = F::from_u32(c3);
            }
            for k in 0..2 {
                row[POL_OFF + POL_HY + k] = F::from_u32(hy[k]);
                row[POL_OFF + POL_RG + k] = F::from_u32(rg[k]);
                row[POL_OFF + POL_ROPEN + k] = F::from_u32(ropen[k]);
                row[POL_OFF + POL_NZ + k] = F::from_u32(nz[k]);
                row[POL_OFF + POL_VPINV + k] = vpinv[k];
                row[POL_OFF + POL_REQ + k] = F::from_u32(req[k]);
            }
            row[POL_OFF + POL_RQ] = F::from_u32(rq);
            row[POL_OFF + POL_ALW] = F::from_u32(alw);
            for k in 0..2 {
                row[Z_OFF + k] = F::from_u32(zf[k]);
                row[ZINV_OFF + k] = zinv[k];
            }
            row[XE_COL] = F::from_u32(xe);
            row[XINV_COL] = xinv;
            let sgnf = |vv: i64| -> F {
                if vv >= 0 {
                    F::from_u32(vv as u32)
                } else {
                    -F::from_u32((-vv) as u32)
                }
            };
            for (i, acc) in bq.iter().enumerate() {
                row[BQ_OFF + i] = sgnf(*acc);
            }
            for (j, acc) in bl.iter().enumerate() {
                row[BL_OFF + j] = sgnf(*acc);
            }
            for (j, acc) in bl2.iter().enumerate() {
                row[BL2_OFF + j] = sgnf(*acc);
            }
            for (k, acc) in ac.iter().enumerate() {
                row[AC_OFF + k] = sgnf(*acc);
            }
            if v3 {
                row[AC_O3_COL] = sgnf(ac3);
            }
            // Carry encodings (offset −3). Each chain owes `fee_row − (1 − 2s)·m`
            // per chunk: under ¬q row 1 carries vPublic₁ and f1·fee, row 2
            // vPublic₂ and (1 − f1)·fee; under q the summed chain carries
            // vPublic₁ and the whole fee on row 1's block.
            {
                let chunk = |x: u64, j: usize| ((x >> (16 * j)) & 0xffff) as i64;
                let signed_m = |k: usize, j: usize| -> i64 {
                    let m = chunk(self.vp[k].amount, j);
                    if self.vp[k].redeem {
                        -m
                    } else {
                        m
                    }
                };
                // A4: the rows owe the fee only under `d3`.
                let row_fee = if self.d3 { self.fee } else { 0 };
                let (fee1, chain1): (u64, [i64; 4]) = if self.sel_q {
                    (row_fee, core::array::from_fn(|j| bl[j] + bl2[j]))
                } else if self.sel_f1 {
                    (row_fee, bl)
                } else {
                    (0, bl)
                };
                let fee2 = if self.sel_f1 { 0 } else { row_fee };
                for (accs, off, rf, k) in [(chain1, BLC_OFF, fee1, 0usize), (bl2, BLC2_OFF, fee2, 1)] {
                    let mut cc = [0i64; 3];
                    let mut prev = 0i64;
                    for j in 0..3 {
                        let tj = accs[j] + prev - chunk(rf, j) + signed_m(k, j);
                        cc[j] = tj >> 16;
                        prev = cc[j];
                    }
                    // v3: bias 4 (a fifth debit per row), and an out-of-range
                    // carry fails loudly: an honest v3 witness keeps every
                    // carry in [−4, 2].
                    let bias = if v3 { 4 } else { 3 };
                    for (j, cj) in cc.iter().enumerate() {
                        if v3 {
                            assert!(
                                (0..=7).contains(&(cj + bias)),
                                "v3 balance carry out of range at row {t}, chunk {j}: c = {cj} (encodable: −4..=3)"
                            );
                        }
                        let enc = (cj + bias).clamp(0, 7) as u32;
                        for bb in 0..3 {
                            row[off + 3 * j + bb] = F::from_u32((enc >> bb) & 1);
                        }
                    }
                }
                // Lab #937 A′: the fee bank's chain against `(1 − d3)·fee`.
                if v3 {
                    let owed = if self.d3 { 0 } else { self.fee };
                    let mut prev = 0i64;
                    for j in 0..3 {
                        let cj = (fb[j] + prev - chunk(owed, j)) >> 16;
                        prev = cj;
                        assert!(
                            (0..=3).contains(&(cj + 2)),
                            "v3 fee-bank carry out of range at row {t}, chunk {j}: c = {cj} (encodable: −2..=1; honest: −1..=0)"
                        );
                        let enc = (cj + 2) as u32;
                        row[FBC_OFF + 2 * j] = F::from_u32(enc & 1);
                        row[FBC_OFF + 2 * j + 1] = F::from_u32((enc >> 1) & 1);
                    }
                }
            }
            row[PBIT_COL] = F::from_u32(pbv);
            for i in 0..NW {
                row[W_OFF + i] = F::from_u32(wbit[i]);
            }
            for (i, acc) in eq.iter().enumerate() {
                row[EQ_OFF + i] = sgnf(*acc);
            }
            for (i, acc) in eq3.iter().enumerate() {
                row[EQ3_OFF + i] = sgnf(*acc);
            }
            for l in 0..25 {
                row[EFF_OFF + l] = F::from_u32(eff[l]);
            }
            // v2 columns.
            let (egn, egl_pos, egl_close, ega_pos) = if v2 {
                let selv2: [u32; 3] = core::array::from_fn(|i| (role_now == SEL_CODES_V2[i]) as u32);
                for (i, vv) in selv2.iter().enumerate() {
                    row[SELV2_OFF + i] = F::from_u32(*vv);
                    row[SEV2_OFF + i] = F::from_u32(*vv * ep);
                }
                row[INJV2_OFF] = F::from_u32(bndv * selv2[0]);
                row[INJV2_OFF + 1] = F::from_u32(bndv * selv2[1]);
                let gates = (
                    bndv * selv2[0] * ep,
                    bndv * selv2[1] * ep,
                    gpermv * selv2[1] * ep,
                    bndv * selv2[2] * ep,
                );
                row[EGN_COL] = F::from_u32(gates.0);
                row[EGL_POS_COL] = F::from_u32(gates.1);
                row[EGL_CLOSE_COL] = F::from_u32(gates.2);
                row[EGA_POS_COL] = F::from_u32(gates.3);
                for i in 0..16 {
                    row[EQL_OFF + i] = sgnf(eql[i]);
                    row[EQA_OFF + i] = sgnf(eqa[i]);
                }
                gates
            } else {
                (0, 0, 0, 0)
            };
            // Advance the accumulators.
            {
                let jc = z / 16;
                let wgt = 1i64 << (z % 16);
                let epi = ep as i64;
                let alwi = alw as i64;
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq[idx] += epi
                        * (g_e1pos * wgt * a[l] as i64 - g_e1neg * wgt * wbit[l] as i64)
                        + (egb as i64) * alwi * wgt * a[l] as i64
                        - (injre as i64) * alwi * wgt * wbit[9 + l] as i64;
                    eq[16 + idx] += epi
                        * (g_e2pos * wgt * wbit[l] as i64
                            - g_e2neg * wgt * wbit[5 + l] as i64);
                    if v2 {
                        eq[idx] += egn as i64 * wgt * wbit[9 + l] as i64;
                        eq[16 + idx] += egn as i64 * wgt * wbit[l] as i64;
                        eqa[idx] += ega_pos as i64 * wgt * a[l] as i64
                            - eg1 as i64 * wgt * wbit[7 + l] as i64;
                    }
                    bq[idx] += (bgcap as i64) * wgt * a[l] as i64
                        + (eg1 as i64) * (1 - l3 as i64) * wgt * a[l] as i64
                        - (injre as i64) * wgt * wbit[l] as i64
                        + (inj_acrede as i64) * wgt * a[l] as i64
                        - (inj3e as i64) * wgt * a[l] as i64;
                }
                let vb = wbit[4] as i64;
                bl[jc] += (ag[AG_IN1] as i64) * wgt * vb
                    - (sg[0] as i64) * wgt * vb
                    - (sg[1] as i64) * wgt * vb
                    - (sg3 as i64) * wgt * vb;
                bl2[jc] += (ag[AG_IN2] as i64) * wgt * vb
                    - ((ag[AG_O1] - sg[0]) as i64) * wgt * vb
                    - ((ag[AG_O2] - sg[1]) as i64) * wgt * vb
                    - ((ag_o3 - sg3 - sf3) as i64) * wgt * vb;
                if jc == 0 {
                    for k in 0..6 {
                        ac[k] += (ag[k] as i64) * wgt * wbit[13] as i64;
                    }
                    ac3 += (ag_o3 as i64) * wgt * wbit[13] as i64;
                }
                fb[jc] += (injf as i64) * wgt * vb - (sf3 as i64) * wgt * vb;
                if bgrst == 1 || arege == 1 {
                    bq = [0i64; 16];
                }
                if g3close == 1 || close_cred == 1 {
                    eq3 = [0i64; 16];
                }
                if v2 {
                    if egl_close == 1 {
                        eql = [0i64; 16];
                    }
                    for l in 0..4 {
                        eql[4 * l + jc] += egl_pos as i64 * wgt * wbit[l] as i64;
                    }
                }
                for l in 0..4 {
                    let idx = 4 * l + jc;
                    eq3[idx] += g3pos as i64 * wgt * wbit[5 + l] as i64
                        - g3neg as i64 * wgt * a[l] as i64
                        + inj_afkeye as i64 * wgt * a[l] as i64
                        - inj_acrede as i64 * wgt * a[l] as i64;
                }
                om = om * (1 - gpermv * selv[10]) + g3close * selv[SEL_ARHO];
                if v3 {
                    om2 += (1 - om2) * gpermv * selv[10];
                }
                ep *= 1 - gwrap;
                latch = latch * (1 - bgc_banchor) + bgc_bnf2;
                l3 = l3 * (1 - bgc_banchor) + bgc_bnf3;
            }
            for d in 1..=S_SLOTS {
                row[s_col(d)] = F::from_u32(s[d]);
            }
            for d in 1..=V_SLOTS {
                row[v_col(d)] = F::from_u32(v[d]);
            }
            for d in 1..=U_SLOTS {
                row[u_col(d)] = F::from_u32(u[d]);
            }

            for d in 1..S_SLOTS {
                s[d] = s[d + 1];
            }
            s[S_SLOTS] = 0;
            if !mrow {
                let j = z;
                for l in 0..25 {
                    let rot = RHO[l] as usize;
                    let d = if j + rot >= 64 { rot } else { 64 + rot };
                    s[d] |= ap[l] << l;
                }
            }
            for d in 1..V_SLOTS {
                v[d] = v[d + 1];
            }
            v[V_SLOTS] = 0;
            for d in 1..U_SLOTS {
                u[d] = u[d + 1];
            }
            u[U_SLOTS] = 0;
            if t % 128 == 127 {
                r.rotate_left(1);
                if pb[1] == 1 {
                    if ph[1] == 1 {
                        pr.rotate_left(1);
                    }
                    ph.rotate_left(1);
                    perm_idx += 1;
                    cur = wit(perm_idx);
                }
                pb.rotate_left(1);
            }
            if mrow {
                let a_limb: u32 = (0..25).map(|l| eff[l] << l).sum();
                let lo: u32 = (0..5).map(|x| c[x] << x).sum();
                let hi: u32 = (0..5).map(|x| c[x] << (5 + x)).sum();
                v[V_SLOTS] = a_limb;
                u[64] |= lo;
                if z == 63 {
                    u[1] |= hi;
                } else {
                    u[65] |= hi;
                }
            }
        }

        RowMajorMatrix::new(values, width)
    }

    /// The state materialized at block `q` (the round-q input).
    pub fn extract_state<F: Field>(trace: &RowMajorMatrix<F>, q: usize) -> [u64; 25] {
        let mut state = [0u64; 25];
        for z in 0..64 {
            let row = 128 * q + z;
            for (l, lane) in state.iter_mut().enumerate() {
                if trace.values[row * L2P_WIDTH + A_OFF + l] == F::ONE {
                    *lane |= 1u64 << z;
                }
            }
        }
        state
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use p3_air::check_constraints;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;

    use super::*;
    use crate::l2::ROLE_ACMOUT;
    use crate::l2test::{self, Violation, ASSIGNMENT_FANOUT};
    use crate::reference;

    type F = KoalaBear;

    const ROWS_PER_PERM_LOCAL: usize = 24 * 128;
    /// Rows the shape-P program occupies — the scanner's tail-first hint
    /// (the balance close is perm 212 of 214; see `l2test`).
    const PROGRAM_END: usize = SHAPE_P_PERMS * ROWS_PER_PERM_LOCAL;

    fn zero_pvs() -> Vec<F> {
        vec![F::ZERO; PV_LEN]
    }
    fn pvs_of(inst: &L2PBucketInstance) -> Vec<F> {
        inst.pvs.iter().map(|v| F::from_u32(*v)).collect()
    }
    fn digest(state: &[u64; 25]) -> [u64; 4] {
        state[..4].try_into().unwrap()
    }
    fn slot_of(program: &[u32], role: u32, nth: usize) -> usize {
        program.iter().enumerate().filter(|(_, r)| **r == role).map(|(i, _)| i).nth(nth).unwrap()
    }

    // -----------------------------------------------------------------------
    // The cost model (lab #700 baton 3), `l2::tests`'s exactly: SAT claims
    // scan every row in parallel; UNSAT claims stop at the first violation,
    // tail first; the honest instances are generated and scanned once.
    // -----------------------------------------------------------------------

    /// A SAT claim: generate, then every row. Positives only.
    fn assert_sat(inst: &L2PBucketInstance, what: &str) {
        let pvs = pvs_of(inst);
        let trace = inst.air.generate_trace::<F>(0);
        l2test::assert_satisfied(&inst.air, &trace, &pvs, what);
    }
    /// An UNSAT claim: generate, then the first violation found.
    fn refused(inst: &L2PBucketInstance) -> Option<Violation> {
        let pvs = pvs_of(inst);
        let trace = inst.air.generate_trace::<F>(0);
        l2test::first_violation(&inst.air, &trace, &pvs, PROGRAM_END)
    }
    fn assert_unsat(inst: &L2PBucketInstance, what: &str) {
        assert!(refused(inst).is_some(), "{what} VERIFIED");
    }
    /// The eight `(o1a, o2a, f1)` assignments at `q` (`l2.rs`'s helper, same
    /// grounds), each regenerating its trace, `ASSIGNMENT_FANOUT` at a time.
    /// Returns the assignments that VERIFIED — which must be none.
    fn assignments_that_verify_at(inst: &L2PBucketInstance, q: bool) -> Vec<u32> {
        let variants: Vec<(u32, L2PBucketInstance)> = (0..8u32)
            .map(|bits| {
                let mut v = inst.clone();
                v.air.sel_o1a = bits & 1 == 1;
                v.air.sel_o2a = bits & 2 == 2;
                v.air.sel_f1 = bits & 4 == 4;
                v.air.sel_q = q;
                (bits, v)
            })
            .collect();
        l2test::fan_out(variants, ASSIGNMENT_FANOUT, |(bits, v)| (bits, refused(&v)))
            .into_iter()
            .filter(|(_, r)| r.is_none())
            .map(|(bits, _)| bits)
            .collect()
    }
    fn assert_refused_under_every_assignment(inst: &L2PBucketInstance, what: &str) {
        let ok = assignments_that_verify_at(inst, inst.air.sel_q);
        assert!(ok.is_empty(), "{what} VERIFIED under selector assignment(s) {ok:?}");
    }

    /// An honest instance with its trace and verdict, generated and scanned
    /// once for the module (rule (a)).
    struct Fixture {
        inst: L2PBucketInstance,
        trace: RowMajorMatrix<F>,
        pvs: Vec<F>,
        verdict: Result<(), Violation>,
    }
    impl Fixture {
        fn new(inst: L2PBucketInstance) -> Self {
            let pvs = pvs_of(&inst);
            let trace = inst.air.generate_trace::<F>(0);
            let verdict = l2test::satisfied(&inst.air, &trace, &pvs);
            Fixture { inst, trace, pvs, verdict }
        }
        fn assert_sat(&self, what: &str) {
            if let Err(v) = &self.verdict {
                panic!("{what}: constraints not satisfied on {v}");
            }
        }
    }
    /// An instance and its verdict, the trace dropped after the one scan.
    struct Verdict {
        inst: L2PBucketInstance,
        verdict: Result<(), Violation>,
    }
    impl Verdict {
        fn new(inst: L2PBucketInstance) -> Self {
            let f = Fixture::new(inst);
            Verdict { inst: f.inst, verdict: f.verdict }
        }
        fn assert_sat(&self, what: &str) {
            if let Err(v) = &self.verdict {
                panic!("{what}: constraints not satisfied on {v}");
            }
        }
    }

    static HONEST: OnceLock<Fixture> = OnceLock::new();
    /// The canonical honest shape-P instance (`honest()`), trace resident for the module.
    fn honest_fixture() -> &'static Fixture {
        HONEST.get_or_init(|| Fixture::new(honest()))
    }
    static SAME_ASSET: OnceLock<Verdict> = OnceLock::new();
    /// Both inputs asset 0: 60 + 40 = 70 + 25 + 5 — the `q = 1` corner.
    fn same_asset() -> &'static Verdict {
        SAME_ASSET.get_or_init(|| Verdict::new(bucket(0x5c05_0008, 60, 0, 40, 0, 70, 0, 25, 0, 5, [VPublic::NONE; 2])))
    }
    static FEE_ON_INPUT_2: OnceLock<Verdict> = OnceLock::new();
    /// Fee asset on input 2: asset 7 (100) + asset 0 (50) → 100 (7) + 40 (0) + fee 10.
    fn fee_on_input_2() -> &'static Verdict {
        FEE_ON_INPUT_2.get_or_init(|| Verdict::new(bucket(0x5c05_0009, 100, 7, 50, 0, 100, 7, 40, 0, 10, [VPublic::NONE; 2])))
    }
    static REGULATED: OnceLock<Verdict> = OnceLock::new();
    /// A Regulated input on row 2: asset 0 (100) + asset 9 (50) → 90 + 50, fee 10.
    fn regulated() -> &'static Verdict {
        REGULATED.get_or_init(|| Verdict::new(bucket(0x9e90_0001, 100, 0, 50, 9, 90, 0, 50, 9, 10, [VPublic::NONE; 2])))
    }
    static MINT100: OnceLock<Verdict> = OnceLock::new();
    /// Mint 100 of asset 7 with the issuer key: 50 in + 100 minted = 150 out; asset 0 pays the fee.
    fn mint100() -> &'static Verdict {
        MINT100.get_or_init(|| {
            Verdict::new(bucket(0x0a11_0001, 100, 0, 50, 7, 90, 0, 150, 7, 10, [VPublic::NONE, VPublic::mint(100)]))
        })
    }

    struct Rnd(u64);
    impl Rnd {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn d4(&mut self) -> [u64; 4] {
            [self.next(), self.next(), self.next(), self.next()]
        }
        fn input(&mut self, value: u64, asset: u64) -> L2TxInput {
            L2TxInput { sk: self.d4(), value, asset, rho: self.d4(), rseed: self.d4(), d: [self.next(), self.next()] }
        }
        fn output(&mut self, value: u64, asset: u64) -> L2TxOutput {
            L2TxOutput { value, asset, rkm: self.d4(), rho: self.d4(), rseed: self.d4() }
        }
    }

    const ISK7: [u64; 4] = [0x15c7_0001, 0x15c7_0002, 0x15c7_0003, 0x15c7_0004];
    const ISK9: [u64; 4] = [0x15c9_0001, 0x15c9_0002, 0x15c9_0003, 0x15c9_0004];

    fn frozen_keys() -> Vec<[u64; 4]> {
        let mut r = Rnd(0xf7ee_0000_dead_beef);
        (0..3).map(|_| r.d4()).collect()
    }

    /// Asset 7: a Hybrid stablecoin with three frozen keys, `redeem_open` per arg.
    fn hybrid7(redeem_open: bool) -> PolicyAsset {
        PolicyAsset::hybrid(7, ISK7, redeem_open, &frozen_keys())
    }

    /// The canonical honest shape-P instance: asset 0 (Cloaked, 100) + asset 7
    /// (Hybrid, 50) in, 90 (asset 0) + 50 (asset 7) out, fee 10, no vPublic.
    fn honest() -> L2PBucketInstance {
        let mut r = Rnd(0x1234_5678_9abc_def0);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(50, 7)];
        build_bucket_l2p(
            SHAPE_P_LOG_HEIGHT,
            &inputs,
            &outputs,
            10,
            &[PolicyAsset::cloaked(0), hybrid7(false)],
            [VPublic::NONE; 2],
        )
    }

    /// A pseudo-random bucket with the given values/assets (assets 0, 7, 9
    /// resolve to Cloaked / Hybrid / Regulated fixtures; anything else is
    /// Cloaked). Regulated inputs are allowlisted by construction.
    #[allow(clippy::too_many_arguments)]
    fn bucket(
        seed: u64,
        v1: u64,
        a1: u64,
        v2: u64,
        a2: u64,
        o1: u64,
        oa1: u64,
        o2: u64,
        oa2: u64,
        fee: u64,
        vp: [VPublic; 2],
    ) -> L2PBucketInstance {
        let mut r = Rnd(seed);
        let inputs = [r.input(v1, a1), r.input(v2, a2)];
        let outputs = [r.output(o1, oa1), r.output(o2, oa2)];
        let asset_of = |a: u64, rkms: &[[u64; 4]]| match a {
            7 => hybrid7(false),
            9 => PolicyAsset::regulated(9, ISK9, false, &frozen_keys(), rkms),
            x => PolicyAsset::cloaked(x),
        };
        let rkms: Vec<[u64; 4]> = inputs.iter().map(derive_rkm_l2).collect();
        let assets = [asset_of(a1, &rkms), asset_of(a2, &rkms)];
        build_bucket_l2p(SHAPE_P_LOG_HEIGHT, &inputs, &outputs, fee, &assets, vp)
    }

    #[test]
    fn l2p_chain_only_satisfies_constraints() {
        let air = L2ShapePAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        check_constraints(&air, &trace, &zero_pvs());
    }

    #[test]
    fn l2p_chain_matches_reference_rounds() {
        let air = L2ShapePAir::chain_only(13);
        let trace = air.generate_trace::<F>(0);
        let blocks = (1usize << air.log_height) / 128;
        for q in 0..blocks - 1 {
            let cur = L2ShapePAir::extract_state(&trace, q);
            let nxt = L2ShapePAir::extract_state(&trace, q + 1);
            assert_eq!(nxt, reference::round(&cur, reference::RC[q % 24]), "block {q}");
        }
    }

    /// The three shape-P blocks read off the trace against their host mirrors:
    /// `AISS` = `issuer_key_of`, `AFRZ` = `freeze_leaf_hash`, `ACRED` =
    /// `cred_of(rkm)` with `rkm` chained from `ARKM2`.
    #[test]
    fn l2p_policy_blocks_match_reference() {
        let mut r = Rnd(0xb10c_0000_0000_0001);
        let inp = r.input(5, 7);
        let (nk, _, _) = derive_input_l2(&inp);
        let rkm = derive_rkm_l2(&inp);
        let (lo, hi) = (r.d4(), r.d4());
        let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
        let mut sw = vec![L2PSlotWitness::default(); PROGRAM_SLOTS];
        program[1] = ROLE_AISS;
        sw[1].w[..4].copy_from_slice(&ISK7);
        program[2] = ROLE_ARKM2;
        sw[2].w[..4].copy_from_slice(&nk);
        sw[2].w[5] = inp.d[0];
        sw[2].w[6] = inp.d[1];
        program[3] = ROLE_ACRED;
        program[4] = ROLE_AFRZ;
        sw[4].w[..4].copy_from_slice(&lo);
        sw[4].w[5..9].copy_from_slice(&hi);
        program[5] = ROLE_ARKM2;
        sw[5].w[..4].copy_from_slice(&nk);
        sw[5].w[5] = inp.d[0];
        sw[5].w[6] = inp.d[1];
        program[6] = ROLE_AFKEY;
        let air = L2ShapePAir { log_height: 15, program: program.to_vec(), slot_witness: sw, ..L2ShapePAir::chain_only(15) };
        let trace = air.generate_trace::<F>(0);
        assert_eq!(digest(&L2ShapePAir::extract_state(&trace, 24 * 2)), issuer_key_of(&ISK7), "AISS");
        assert_eq!(digest(&L2ShapePAir::extract_state(&trace, 24 * 3)), rkm, "ARKM2 = rkm");
        assert_eq!(digest(&L2ShapePAir::extract_state(&trace, 24 * 4)), cred_of(&rkm), "ACRED");
        assert_eq!(digest(&L2ShapePAir::extract_state(&trace, 24 * 5)), freeze_leaf_hash(&lo, &hi), "AFRZ");
        assert_eq!(digest(&L2ShapePAir::extract_state(&trace, 24 * 7)), freeze_key_of(&rkm), "AFKEY = H(rkm ‖ D_FRZ)");
        assert_ne!(freeze_key_of(&rkm), cred_of(&rkm), "D_FRZ ≠ D_CRED");
    }

    /// The bit-serial comparison: on `AFRZ`'s last boundary row the two
    /// verdict columns read `[key_lo < rkm]` and `[rkm < key_hi]` exactly, for
    /// keys on both sides of `rkm` (each lane order exercised).
    #[test]
    fn l2p_comparison_verdicts_read_off_the_trace() {
        let mut r = Rnd(0xc0de_c0de_0000_0002);
        let inp = r.input(5, 7);
        let (nk, _, _) = derive_input_l2(&inp);
        let rkm = derive_rkm_l2(&inp);
        let cases: Vec<([u64; 4], [u64; 4])> = vec![
            ([0; 4], KEY_MAX),
            (rkm, KEY_MAX),                                       // key_lo = rkm: not <
            ([0; 4], rkm),                                        // key_hi = rkm: not <
            ([rkm[0], rkm[1], rkm[2], rkm[3].wrapping_sub(1)], KEY_MAX), // just below in the top lane
            ([rkm[0].wrapping_add(1), rkm[1], rkm[2], rkm[3]], KEY_MAX), // above in the low lane
            (r.d4(), r.d4()),
        ];
        for (lo, hi) in cases {
            let mut program = [ROLE_DUMMY; PROGRAM_SLOTS];
            let mut sw = vec![L2PSlotWitness::default(); PROGRAM_SLOTS];
            program[1] = ROLE_ARKM2;
            sw[1].w[..4].copy_from_slice(&nk);
            sw[1].w[5] = inp.d[0];
            sw[1].w[6] = inp.d[1];
            program[2] = ROLE_AFRZ;
            sw[2].w[..4].copy_from_slice(&lo);
            sw[2].w[5..9].copy_from_slice(&hi);
            let air = L2ShapePAir { log_height: 13, program: program.to_vec(), slot_witness: sw, ..L2ShapePAir::chain_only(13) };
            let trace = air.generate_trace::<F>(0);
            let row = 2 * ROWS_PER_PERM_LOCAL + 63; // AFRZ's boundary, z = 63
            let at = |blk: usize| trace.values[row * L2P_WIDTH + CMP_OFF + CMP_BLOCK * blk + CMP_C + 2];
            assert_eq!(at(0), F::from_bool(key_lt(&lo, &rkm)), "key_lo < rkm for {lo:x?}");
            assert_eq!(at(1), F::from_bool(key_lt(&rkm, &hi)), "rkm < key_hi for {hi:x?}");
        }
    }

    /// The complete shape P — a Cloaked and a Hybrid input, every gadget in
    /// the trace, no vPublic — satisfies the AIR with the real public values
    /// at 2^20 (the module fixture's full scan).
    /// The named column offsets, pinned (lab #758): the `// NNN` comments on
    /// the constant chain had drifted after A4 and misled two readers of the
    /// audit. This fails if the chain moves without its comments.
    #[test]
    fn l2p_named_offsets_are_the_constant_chain() {
        assert_eq!(
            (W_OFF, EQ_OFF, EG_OFF, EQ3_OFF, SEL2_OFF, CMP_OFF, POL_OFF, Z_OFF, L2P_WIDTH),
            (560, 575, 607, 693, 725, 755, 777, 798, 804)
        );
    }

    #[test]
    fn l2p_shape_p_satisfies_constraints() {
        let fx = honest_fixture();
        assert_eq!(fx.inst.air.program.iter().filter(|r| **r != ROLE_DUMMY).count(), SHAPE_P_PERMS - 1);
        assert!(fx.inst.air.hy == [false, true] && fx.inst.air.rg == [false, false]);
        fx.assert_sat("shape P, the honest instance at 2^20");
    }

    /// A Regulated input (freeze + allowlist both live) verifies; the same
    /// asset on both rows (q, both Regulated) verifies with the summed close.
    #[test]
    fn l2p_regulated_inputs_satisfy() {
        let a = regulated();
        assert!(a.inst.air.rg == [false, true]);
        a.assert_sat("a Regulated input on row 2");
        // (Two Regulated inputs of one asset is NOT a legal bucket: it has
        // no asset-0 note — the shape-S no-fee-asset-note negative's ground.
        // `q` is reachable only with both inputs in asset 0, where no policy
        // applies.) Regulated on row 1, the fee asset on row 2.
        let b = bucket(0x9e90_0002, 50, 9, 100, 0, 50, 9, 90, 0, 10, [VPublic::NONE; 2]);
        assert!(!b.air.sel_f1 && b.air.rg == [true, false]);
        assert_sat(&b, "a Regulated input on row 1");
    }

    /// The `vPublic` edge (§3.1), positives: mint with the issuer key; redeem
    /// on a `redeem_open` asset without it; redeem on a closed asset with it;
    /// a mint on row 2; both rows carrying a term (two policy assets).
    #[test]
    fn l2p_vpublic_edges_satisfy() {
        // Mint 100 of asset 7: 50 in + 100 minted = 150 out; asset 0 pays the fee.
        let mint = mint100();
        assert_eq!(mint.inst.pvs[pv_vp_asset(1)], 7, "the minted asset is public");
        assert_eq!(mint.inst.pvs[pv_vp_asset(0)], 0, "no term on row 1 → nothing revealed");
        mint.assert_sat("mint with isk");
        // Redeem 20 of asset 7 (closed): 50 in = 30 out + 20 redeemed, isk supplied.
        let redeem_closed = bucket(0x0a11_0002, 100, 0, 50, 7, 90, 0, 30, 7, 10, [VPublic::NONE, VPublic::redeem(20)]);
        assert_sat(&redeem_closed, "closed redeem with isk");
        // Redeem on a redeem_open asset WITHOUT the issuer key.
        let mut r = Rnd(0x0a11_0003);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(30, 7)];
        let mut open7 = hybrid7(true);
        open7.isk = Some([0xbad; 4]); // a holder's guess — the leaf still carries the real issuer key
        let real_leaf = hybrid7(true).leaf();
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [PolicyAsset::cloaked(0).leaf(), real_leaf];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let mut pol1 = open7.policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1]).unwrap();
        pol1.leaf = real_leaf;
        let pol0 = PolicyAsset::cloaked(0).policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let open = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root,
            [VPublic::NONE, VPublic::redeem(20)], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert!(open.air.ropen == [false, true]);
        assert_sat(&open, "open redeem without isk");
        // Mint on row 1 (asset 7 is input 1), fee from row 2.
        let mint1 = bucket(0x0a11_0004, 50, 7, 100, 0, 150, 7, 90, 0, 10, [VPublic::mint(100), VPublic::NONE]);
        assert!(!mint1.air.sel_f1);
        assert_sat(&mint1, "mint on row 1");
        // Two policy assets, a term each: mint 10 of 7, redeem 5 of 9 — no asset-0
        // note is refused (fee assignment), so fee 0 still fails; give asset 0…
        // not possible with two inputs in 7 and 9. Instead: row 1 asset 7 with
        // a dummy? No — keep to what the 2×2 admits: redeem on both rows needs
        // an asset-0 note, which one of the rows must be. So: asset 0 + asset 9,
        // redeem 5 of 9 (Regulated, closed, isk supplied).
        let two = bucket(0x0a11_0005, 100, 0, 50, 9, 90, 0, 45, 9, 10, [VPublic::NONE, VPublic::redeem(5)]);
        assert_sat(&two, "redeem on a Regulated row");
    }

    // -----------------------------------------------------------------------
    // Column accounting and degree, in the q69 style.
    // -----------------------------------------------------------------------

    /// The trace width `prove` is handed: **778**, accounted column by column
    /// over shape S's 702 (774 before lab #704 Q1's `AFKEY`: +1 ring limb,
    /// +1 selector, +1 injection, +1 gate). Asserted against the matrix.
    #[test]
    fn l2p_trace_width_is_read_off_the_matrix() {
        let air = L2ShapePAir::chain_only(10);
        let trace = air.generate_trace::<F>(0);
        assert_eq!(trace.width(), L2P_WIDTH, "width must be the matrix's own");

        const SHAPE_S: usize = 702;
        let ring = 31; // PR ring 32 → 63 limbs (252 program slots, all used — P3, A4)
        let roles = 6 // sel(AISS), sel(AFRZ), sel(ACRED), sel(BALLOW), sel(ARKM2), sel(AFKEY) — NSEL 16 → 22
            + 4; // inj(AISS), inj(AFRZ), inj(ACRED), inj(AFKEY)                                — NINJ 7 → 11
        let gates = 8; // INJ_AFRZE, INJ_ACREDE, CLOSE_CRED, EGB, EGBC, AREGE, CRQ, INJ_AFKEYE
        let comparisons = 2 * (4 + 4 + 3); // per 256-bit comparison: LT ×4, EQ ×4, C1..C3
        let policy = 2 * 6 // hy, rg, ropen, nz, vpinv, REQ — per input
            + 2; // RQ, ALW — the current-input muxes
        let fee_input = 2 // sel(BNF3), sel(ACMF)                — NSEL 22 → 24 (A4)
            + 1 // inj(ACMF)                                    — NINJ 11 → 12
            + 1 // BGC[bnf3]                                    — NBGC 6 → 7
            + 4 // FB: the fee bank
            + 3; // L3, d3, L3·d3
        assert_eq!(comparisons, 22);
        assert_eq!(policy, 14);
        assert_eq!(fee_input, 11);
        let exit_edge = 2 * 2 // z, zinv — per input (lab #785 F5-4d)
            + 2; // XE, XINV
        assert_eq!(
            trace.width(),
            SHAPE_S + ring + roles + gates + comparisons + policy + fee_input + exit_edge,
            "width must be 702 plus exactly the columns named above"
        );
        assert_eq!(trace.width(), 804, "the shape-P3 width (P's 778 + A4's 20 + F5-4d's 6)");
        // The accounting is over pre-A4 S (702); S3 is that + its own ring
        // growth (32 → 40 limbs) + the same 11 fee-input columns.
        assert_eq!(crate::l2::L2_WIDTH, SHAPE_S + 8 + 11, "S3 = pre-A4 S + ring + fee input");
    }

    /// The quotient degree does not move: max constraint degree **4** (the 22
    /// materialized role selectors, EG3[1], the 16 comparison transitions),
    /// 4 quotient chunks — the L1's ceiling exactly.
    #[test]
    fn l2p_quotient_degree_matches_the_l1() {
        use p3_air::symbolic::{get_max_constraint_degree, get_symbolic_constraints, AirLayout};
        let air = L2ShapePAir::chain_only(SHAPE_P_LOG_HEIGHT);
        let layout = AirLayout::from_air::<F>(&air);
        let deg = get_max_constraint_degree::<F, _>(&air, layout);
        assert_eq!(deg, 4, "max constraint degree");
        assert_eq!((deg - 1).next_power_of_two(), 4, "quotient chunks");
        let cs = get_symbolic_constraints::<F, _>(&air, AirLayout::from_air::<F>(&air));
        let mut hist = std::collections::BTreeMap::new();
        for c in &cs {
            *hist.entry(c.degree_multiple()).or_insert(0usize) += 1;
        }
        assert_eq!(hist.keys().max(), Some(&4), "nothing above degree 4");
        // The deg-4 population, pinned: 22 role selectors + EG3[1] (S's 17
        // pattern) + 16 comparison-flag transitions (`mrow · same · flag`,
        // the periodic gate counting one) + 16 bank-1 transitions (the
        // ALW-gated allowlist legs, `EGB · ALW · pw · a`) + the three gate
        // definitions CLOSE_CRED / EGB / EGBC (`gperm|bnd · sel · ep`).
        // Materializing those to ≤ 3 would cost 4–5 columns for no quotient
        // benefit (4 chunks either way) — recorded, not taken.
        // A4 adds: 2 role selectors; the two row-fee chains' 4 chunk closes
        // each (`close·d3·f1·fee·ep`); the two row-fee asset bindings; and the
        // 16 bind-bank transitions whose AISS leg carries `(1 − L3)`.
        // F5-4d (lab #785) adds one: `XE`'s definition (`e_0 · e_1`).
        assert_eq!(
            hist.get(&4).copied().unwrap_or(0),
            24 + 1 + 16 + 16 + 3 + 8 + 2 + 16 + 1,
            "deg-4 constraints"
        );
    }

    /// Program geometry: 214 perms (+2 spare ring slots), fits 2^20, the
    /// per-input order.
    #[test]
    fn l2p_program_geometry() {
        let inst = &honest_fixture().inst;
        assert_eq!(SHAPE_P_PERMS, 252);
        assert_eq!(PROGRAM_SLOTS, 252);
        assert!(p_spare_slots_are_dummy(&honest_fixture().inst.air.program));
        assert!(SHAPE_P_PERMS * ROWS_PER_PERM_LOCAL <= 1 << SHAPE_P_LOG_HEIGHT);
        assert!(SHAPE_P_PERMS * ROWS_PER_PERM_LOCAL > 1 << (SHAPE_P_LOG_HEIGHT - 1), "P does not fit 2^19");
        let p = &inst.air.program;
        assert_eq!(p[0], ROLE_DUMMY);
        let mut want = vec![ROLE_ANK, ROLE_NF, ROLE_BNF1, ROLE_AISS, ROLE_ARKM, ROLE_AFKEY, ROLE_AFRZ];
        want.extend(std::iter::repeat(ROLE_MERKLE).take(FREEZE_DEPTH));
        want.push(ROLE_AREG);
        want.extend(std::iter::repeat(ROLE_MERKLE).take(REGISTRY_DEPTH));
        want.extend([ROLE_BREG, ROLE_ARKM2, ROLE_ACRED]);
        want.extend(std::iter::repeat(ROLE_MERKLE).take(ALLOW_DEPTH));
        want.extend([ROLE_BALLOW, ROLE_ARKM2, ROLE_ACM]);
        want.extend(std::iter::repeat(ROLE_MERKLE).take(MERKLE_DEPTH));
        want.push(ROLE_BANCHOR);
        assert_eq!(want.len(), 103);
        assert_eq!(&p[1..1 + want.len()], &want[..], "input chain 1");
        want[2] = ROLE_BNF2;
        assert_eq!(&p[1 + want.len()..1 + 2 * want.len()], &want[..], "input chain 2");
        // A4: the fee chain, then the outputs.
        let mut fee = vec![ROLE_ANK, ROLE_NF, ROLE_BNF3, ROLE_ARKM, ROLE_ACMF];
        fee.extend(std::iter::repeat(ROLE_MERKLE).take(MERKLE_DEPTH));
        fee.push(ROLE_BANCHOR);
        let at = 1 + 2 * want.len();
        assert_eq!(&p[at..at + fee.len()], &fee[..], "the fee chain");
        let tail = [ROLE_ACMOUT, ROLE_BCM1, ROLE_ARHO, ROLE_ACMOUT, ROLE_BCM2, ROLE_BAL, ROLE_END];
        assert_eq!(&p[at + fee.len()..SHAPE_P_PERMS], &tail[..]);
    }

    fn p_spare_slots_are_dummy(p: &[u32]) -> bool {
        p[SHAPE_P_PERMS..].iter().all(|r| *r == ROLE_DUMMY)
    }

    // -----------------------------------------------------------------------
    // The stage-2 negatives (lab #700 stage-1 ruling, item 2), each a real
    // UNSAT under the honest selector assignment (the policy gadgets do not
    // read the balance selectors; where a negative touches assets the eight
    // assignments are iterated as in `l2.rs`).
    // -----------------------------------------------------------------------

    /// The honest fixture rebuilt with input 1's policy opening replaced.
    fn honest_with_policy1(edit: impl FnOnce(&mut L2PolicyInput, &[u64; 4], &PolicyAsset)) -> L2PBucketInstance {
        let mut r = Rnd(0x1234_5678_9abc_def0);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(50, 7)];
        let assets = [PolicyAsset::cloaked(0), hybrid7(false)];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let rkm1 = derive_rkm_l2(&inputs[1]);
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let mut pol1 = assets[1].policy_input_for(&rkm1, rw[1]).unwrap();
        edit(&mut pol1, &rkm1, &assets[1]);
        build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        )
    }

    /// A4 (#283): the bind bank's AISS `+a` leg is gated by `(1 − L3)`. The
    /// forgery: a prover carries that leg into the fee chain anyway — every
    /// BQ accumulator follows the UNGATED transition from the fee chain's
    /// `ARKM` boundary on (the leg added there, then carried and reset exactly
    /// as the bank's own rule carries it). Refused, and refused at that
    /// boundary row, where the honest trace holds.
    #[test]
    fn l2p_neg_aiss_leg_under_l3() {
        let fx = honest_fixture();
        fx.assert_sat("the honest instance");
        let program = &fx.inst.air.program;
        let arkm = slot_of(program, ROLE_BNF3, 0) + 1;
        assert_eq!(program[arkm], ROLE_ARKM, "the fee chain is ANK → NF → BNF3 → ARKM");
        let w = L2P_WIDTH;
        let at = |t: &RowMajorMatrix<F>, row: usize, col: usize| t.values[row * w + col];
        let perm_rows = arkm * ROWS_PER_PERM_LOCAL..(arkm + 1) * ROWS_PER_PERM_LOCAL;
        assert!(
            perm_rows
                .clone()
                .any(|r| at(&fx.trace, r, EG_OFF + 1) != F::ZERO && at(&fx.trace, r, L3_COL) == F::ONE),
            "the fee chain's ARKM fires bank 1's gate under L3 (else this probe measures nothing)"
        );

        let periodic = <L2ShapePAir as BaseAir<F>>::periodic_columns(&fx.inst.air);
        let per = |k: usize, row: usize| periodic[k][row % periodic[k].len()];
        let mut forged = fx.trace.clone();
        let mut delta = [F::ZERO; 16];
        // The first row whose transition the forgery breaks: where the
        // ungated leg first adds something nonzero.
        let mut gate_row = None;
        for r in perm_rows.start..forged.height() - 1 {
            let keep = F::ONE - at(&forged, r, BGRST_COL) - at(&forged, r, AREGE_COL);
            let eg1 = at(&forged, r, EG_OFF + 1) * at(&forged, r, L3_COL);
            for l in 0..4 {
                for j in 0..4 {
                    let i = 4 * l + j;
                    let leg = eg1 * per(35 + j, r) * at(&forged, r, A_OFF + l);
                    if leg != F::ZERO && gate_row.is_none() {
                        gate_row = Some(r);
                    }
                    delta[i] = keep * delta[i] + leg;
                    forged.values[(r + 1) * w + BQ_OFF + i] += delta[i];
                }
            }
        }
        let r0 = gate_row.expect("the forged leg is nonzero somewhere (else this probe measures nothing)");
        assert!(perm_rows.contains(&r0), "the leg first fires inside the fee chain's ARKM (row {r0})");

        assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &fx.pvs, r0).is_empty(), "honest at the boundary");
        let at_gate = l2test::violations_at(&fx.inst.air, &forged, &fx.pvs, r0);
        assert!(!at_gate.is_empty(), "a forged AISS leg under L3 VERIFIED at the fee chain's ARKM (row {r0})");
        assert!(
            l2test::first_violation(&fx.inst.air, &forged, &fx.pvs, PROGRAM_END).is_some(),
            "a forged AISS leg under L3 VERIFIED"
        );
    }

    /// 🔴 **Spend a frozen `rkm`**: the issuer freezes input 1's `rkm`; the
    /// tree now holds `(prev, rkm)` and `(rkm, next)`. Every low leaf the
    /// prover can open is refused — the two adjacent ones by the strict
    /// comparisons alone (their paths are genuine), every other by range.
    #[test]
    fn l2p_neg_spend_frozen_rkm() {
        let mut r = Rnd(0x1234_5678_9abc_def0);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(50, 7)];
        let rkm1 = derive_rkm_l2(&inputs[1]);
        let mut frozen = frozen_keys();
        frozen.push(rkm1);
        let frozen7 = PolicyAsset::hybrid(7, ISK7, false, &frozen);
        assert!(frozen7.freeze.opening_for(&rkm1).is_none(), "precondition: rkm is a key");
        let assets = [PolicyAsset::cloaked(0), frozen7.clone()];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let n = frozen7.freeze.leaves.len();
        assert_eq!(n, 5);
        for i in 0..n {
            let opening = frozen7.freeze.opening_at(i);
            let k1 = freeze_key_of(&rkm1);
            let kind = if opening.key_hi == k1 {
                "predecessor (key_hi = K)"
            } else if opening.key_lo == k1 {
                "successor (key_lo = K)"
            } else {
                "unrelated leaf"
            };
            let pol1 = L2PolicyInput {
                leaf: frozen7.leaf(),
                reg_witness: rw[1],
                freeze: opening,
                allow: dummy_allow_witness(),
                isk: [0; 4],
            };
            let bad = build_bucket_l2p_with_witnesses(
                SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
            );
            assert_eq!(opening.witness.fold_root(&freeze_leaf_hash(&opening.key_lo, &opening.key_hi)), frozen7.freeze.root, "every path is genuine");
            assert_unsat(&bad, &format!("a frozen rkm through leaf {i} ({kind})"));
        }
    }

    /// 🔴 **Wrong low leaf**: a genuine leaf of the genuine tree whose range
    /// does not contain `rkm` (the comparison refuses; the fold is fine).
    #[test]
    fn l2p_neg_wrong_low_leaf() {
        honest_fixture().assert_sat("precondition");
        let asset = hybrid7(false);
        let rkm1 = derive_rkm_l2(&{
            let mut r = Rnd(0x1234_5678_9abc_def0);
            let _ = r.input(100, 0);
            r.input(50, 7)
        });
        let right = asset.freeze.opening_for(&rkm1).unwrap();
        let wrong_ix = (0..asset.freeze.leaves.len())
            .find(|i| asset.freeze.leaves[*i].0 != right.key_lo)
            .unwrap();
        let bad = honest_with_policy1(|pol, _, a| pol.freeze = a.freeze.opening_at(wrong_ix));
        assert_unsat(&bad, "a genuine leaf outside rkm's range");
    }

    /// 🔴 **Low-leaf range lie**: the range says `key_lo < rkm < key_hi` but
    /// the leaf is not in the tree (forged bounds on a genuine path, and a
    /// genuine leaf with one bound moved onto rkm).
    #[test]
    fn l2p_neg_low_leaf_range_lie() {
        let forged = honest_with_policy1(|pol, rkm, _| {
            let k = freeze_key_of(rkm);
            pol.freeze.key_lo = [k[0].wrapping_sub(1), k[1], k[2], k[3]];
            pol.freeze.key_hi = [k[0].wrapping_add(1), k[1], k[2], k[3]];
        });
        assert_unsat(&forged, "a forged low leaf (range holds on K, not in the tree)");
        let lo_lie = honest_with_policy1(|pol, rkm, _| pol.freeze.key_lo = freeze_key_of(rkm));
        assert_unsat(&lo_lie, "key_lo = K");
        let hi_lie = honest_with_policy1(|pol, rkm, _| pol.freeze.key_hi = freeze_key_of(rkm));
        assert_unsat(&hi_lie, "key_hi = K");
    }

    /// 🔴 **A raw-`rkm`-keyed witness** (lab #704 Q1 — the mutation check for
    /// the hashed key): the issuer freezes input 1, so the genuine tree over
    /// `K = H(rkm ‖ D_FRZ)` holds `(0, K)` and `(K, MAX)`. The prover opens the
    /// genuine leaf whose range brackets the RAW `rkm` — exactly what a
    /// raw-keyed circuit (W3 as built) accepted. It must be UNSAT: the key
    /// compared on `AFRZ`'s boundary is `K`, which no leaf brackets.
    #[test]
    fn l2p_neg_raw_rkm_keyed_witness() {
        let mut r = Rnd(0x1234_5678_9abc_def0);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(50, 7)];
        let rkm1 = derive_rkm_l2(&inputs[1]);
        let k1 = freeze_key_of(&rkm1);
        let frozen7 = PolicyAsset::hybrid(7, ISK7, false, &[rkm1]);
        assert!(frozen7.freeze.opening_for(&rkm1).is_none(), "precondition: input 1 is frozen");
        let i = (0..frozen7.freeze.leaves.len())
            .find(|&i| {
                let (lo, hi) = frozen7.freeze.leaves[i];
                key_lt(&lo, &rkm1) && key_lt(&rkm1, &hi)
            })
            .expect("some genuine leaf brackets the raw rkm");
        let opening = frozen7.freeze.opening_at(i);
        assert!(
            !(key_lt(&opening.key_lo, &k1) && key_lt(&k1, &opening.key_hi)),
            "precondition: that leaf does not bracket K"
        );
        // Everything else genuine: the registry holds the frozen asset's leaf,
        // the freeze path folds to its freeze_root.
        let assets = [PolicyAsset::cloaked(0), frozen7.clone()];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        assert_eq!(
            opening.witness.fold_root(&freeze_leaf_hash(&opening.key_lo, &opening.key_hi)),
            frozen7.freeze.root,
            "the path is genuine"
        );
        let pol1 = L2PolicyInput {
            leaf: frozen7.leaf(),
            reg_witness: rw[1],
            freeze: opening,
            allow: dummy_allow_witness(),
            isk: [0; 4],
        };
        let bad = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert_unsat(&bad, "a raw-rkm-keyed freeze witness");
    }


    /// 🔴 **Wrong sibling** in the freeze path (one sibling at level 5
    /// replaced), and the same for the allowlist path of a Regulated input.
    #[test]
    fn l2p_neg_wrong_sibling() {
        let bad = honest_with_policy1(|pol, _, _| pol.freeze.witness.siblings[5][0] ^= 1);
        assert_unsat(&bad, "a wrong freeze sibling");
        let fx = regulated();
        fx.assert_sat("precondition: the Regulated spend verifies");
        let mut reg = fx.inst.clone();
        let s = slot_of(&reg.air.program, ROLE_ACRED, 1) + 6; // 5th MERKLE step of input 1's allow path
        reg.air.slot_witness[s].w[0] ^= 1;
        assert_unsat(&reg, "a wrong allowlist sibling");
    }

    /// 🔴 **Mint without `isk`**: the mint from `l2p_vpublic_edges_satisfy`
    /// with a wrong issuer secret (the leaf's issuer_key is the real one).
    #[test]
    fn l2p_neg_mint_without_isk() {
        let mut r = Rnd(0x0a11_0001);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(150, 7)];
        let assets = [PolicyAsset::cloaked(0), hybrid7(false)];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let mut pol1 = assets[1].policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1]).unwrap();
        pol1.isk = [0xbad; 4];
        let bad = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root,
            [VPublic::NONE, VPublic::mint(100)], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert_unsat(&bad, "a mint without the issuer key");
        // …and with the wrong isk but NO mint the instance verifies (the AISS
        // window is unchecked when not required) — the refusal above is REQ's.
        let outputs_ok = [outputs[0], L2TxOutput { value: 50, ..outputs[1] }];
        let ok = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs_ok, 10, &w, anchor, &[pol0, pol1], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert_sat(&ok, "a wrong isk with nothing to prove must not matter");
    }

    /// 🔴 **Redeem a non-`redeem_open` asset without `isk`** (refused), and
    /// the `redeem_open` twin verifies (built in `l2p_vpublic_edges_satisfy`).
    #[test]
    fn l2p_neg_redeem_closed_without_isk() {
        let mut r = Rnd(0x0a11_0002);
        let inputs = [r.input(100, 0), r.input(50, 7)];
        let outputs = [r.output(90, 0), r.output(30, 7)];
        let assets = [PolicyAsset::cloaked(0), hybrid7(false)];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let mut pol1 = assets[1].policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1]).unwrap();
        pol1.isk = [0xbad; 4];
        let bad = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root,
            [VPublic::NONE, VPublic::redeem(20)], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert!(!bad.air.ropen[1]);
        assert_unsat(&bad, "a closed redeem without the issuer key");
        // Lying `ropen = 1` is refused by the flags binding.
        let mut lie = bad.clone();
        lie.air.ropen[1] = true;
        assert_unsat(&lie, "a lied redeem_open");
    }

    /// 🔴 **`vPublic ≠ 0` on a Cloaked asset**: minting 10 of asset 0 (no
    /// issuer, no mode bits) is refused — whatever the `hy`/`rg` witness says,
    /// because those are bound to the leaf.
    #[test]
    fn l2p_neg_vpublic_on_cloaked() {
        let mut bad = bucket(0xc10a_0001, 100, 0, 50, 7, 100, 0, 50, 7, 10, [VPublic::mint(10), VPublic::NONE]);
        assert_unsat(&bad, "a mint on a Cloaked asset");
        bad.air.hy[0] = true; // claim Hybrid for asset 0: the mode lane refuses
        assert_unsat(&bad, "a mint on a Cloaked asset with a lied mode");
        // A redeem on a Cloaked asset other than 0 likewise (lab #785 F5-4d:
        // asset 0's redeem is the exit edge, `l2p_asset0_redeem_is_the_exit`).
        let bad2 = bucket(0xc10a_0002, 100, 0, 50, 5, 90, 0, 40, 5, 10, [VPublic::NONE, VPublic::redeem(10)]);
        assert_unsat(&bad2, "a redeem on a Cloaked asset");
    }

    /// Like [`bucket`], with the exit recipient.
    #[allow(clippy::too_many_arguments)]
    fn bucket_exit(seed: u64, v: [(u64, u64); 2], o: [(u64, u64); 2], fee: u64, vp: [VPublic; 2], xrkm: [u64; 4]) -> L2PBucketInstance {
        let mut r = Rnd(seed);
        let inputs = [r.input(v[0].0, v[0].1), r.input(v[1].0, v[1].1)];
        let outputs = [r.output(o[0].0, o[0].1), r.output(o[1].0, o[1].1)];
        let asset_of = |a: u64| if a == 7 { hybrid7(false) } else { PolicyAsset::cloaked(a) };
        build_bucket_l2p_exit(SHAPE_P_LOG_HEIGHT, &inputs, &outputs, fee, &[asset_of(v[0].1), asset_of(v[1].1)], vp, xrkm)
    }
    /// A recipient that is NOT the spender's key (any L1 `rkm` is a valid
    /// payee — exiting to someone else is legitimate).
    const EXIT_TO: [u64; 4] = [0x0e71_0001, 0x0e71_0002, 0x0e71_0003, 0x0e71_0004];

    /// Lab #785 F5-4d (F-B (ii)): a redeem of asset 0 — Cloaked, no issuer —
    /// is the exit: it needs no issuer key, runs no freeze or allowlist leg,
    /// and pays the named recipient. Asset 0 (100) + asset 7 (50) → 80 (0) +
    /// 50 (7) + fee 10, redeeming 10 of asset 0.
    #[test]
    fn l2p_asset0_redeem_is_the_exit() {
        let vp = [VPublic::redeem(10), VPublic::NONE];
        let exit = bucket_exit(0xe417_0001, [(100, 0), (50, 7)], [(80, 0), (50, 7)], 10, vp, EXIT_TO);
        assert_ne!(EXIT_TO, derive_rkm_l2(&Rnd(0xe417_0001).input(100, 0)), "the recipient is not the spender");
        assert_eq!(&exit.pvs[PV_XRKM..PV_XRKM + 16], &pv_chunks(&EXIT_TO)[..]);
        assert_sat(&exit, "an asset-0 redeem to a named recipient");
        // The exit row on the second input (asset 7 first): also an exit.
        let row2 = bucket_exit(0xe417_0002, [(50, 7), (100, 0)], [(50, 7), (80, 0)], 10, [VPublic::NONE, VPublic::redeem(10)], EXIT_TO);
        assert_sat(&row2, "an exit on row 2");
    }

    /// Lab #785 F5-4d forgeries (pre-review U5). (1) A redeem of Cloaked
    /// asset 5 whose `z` claims asset 0 — everything else an exit would
    /// carry is consistent (recipient named, balance holds) — is refused by
    /// the close binding `leaf_asset · z = 0`. (2) A MINT of asset 0 carrying
    /// a recipient: `s = 0` keeps the Cloaked gate shut and `XE = 0`, so both
    /// the gate and `(1 − XE)·xrkm` refuse it.
    #[test]
    fn l2p_neg_exit_forgeries() {
        // 100 (0) + 50 (5) → 90 (0) + 40 (5) + fee 10, redeeming 10 of asset 5.
        let vp = [VPublic::NONE, VPublic::redeem(10)];
        let honest_shape = bucket_exit(0xe417_0007, [(100, 0), (50, 5)], [(90, 0), (40, 5)], 10, vp, [0; 4]);
        assert_unsat(&honest_shape, "a redeem of Cloaked asset 5");
        let mut z_lie = bucket_exit(0xe417_0007, [(100, 0), (50, 5)], [(90, 0), (40, 5)], 10, vp, EXIT_TO);
        z_lie.air.asset[1] = 0; // the trace fill now writes z = 1 on row 2
        assert_unsat(&z_lie, "z = 1 on a non-zero asset (a forged exit)");
        // 100 (0) + 50 (7) → 100 (0) + 50 (7) + fee 10, minting 10 of asset 0.
        let mint = bucket_exit(0xe417_0008, [(100, 0), (50, 7)], [(100, 0), (50, 7)], 10, [VPublic::mint(10), VPublic::NONE], EXIT_TO);
        assert_unsat(&mint, "a mint of asset 0 carrying a recipient");
    }

    /// Lab #785 F5-4d: the recipient is canonical — nonzero exactly when the
    /// transaction exits. An exit to the zero recipient, a non-exit carrying
    /// one, and a zero-amount asset-0 "redeem" (no exit) carrying one are
    /// each refused; the zero-amount row with no recipient is fine.
    #[test]
    fn l2p_neg_exit_recipient_is_canonical() {
        let vp = [VPublic::redeem(10), VPublic::NONE];
        let zero_to = bucket_exit(0xe417_0003, [(100, 0), (50, 7)], [(80, 0), (50, 7)], 10, vp, [0; 4]);
        assert_unsat(&zero_to, "an exit to the zero recipient");
        let stray = bucket_exit(0xe417_0004, [(100, 0), (50, 7)], [(90, 0), (50, 7)], 10, [VPublic::NONE; 2], EXIT_TO);
        assert_unsat(&stray, "a recipient on a transaction that does not exit");
        let zero_amount = [VPublic::redeem(0), VPublic::NONE];
        let z = bucket_exit(0xe417_0005, [(100, 0), (50, 7)], [(90, 0), (50, 7)], 10, zero_amount, EXIT_TO);
        assert_unsat(&z, "a zero-amount asset-0 redeem is no exit, so no recipient");
        let z_ok = bucket_exit(0xe417_0006, [(100, 0), (50, 7)], [(90, 0), (50, 7)], 10, zero_amount, [0; 4]);
        assert_sat(&z_ok, "a zero-amount asset-0 redeem with no recipient");
    }

    /// 🔴 **Allowlist path under the wrong root**: a Regulated input whose
    /// `rkm` is NOT allowlisted opens (a) a genuine path of another holder's
    /// credential — the leaf is not `cred(rkm)`; (b) a path under a different
    /// allow tree — the root is not the leaf's.
    #[test]
    fn l2p_neg_allowlist_wrong_root() {
        let mut r = Rnd(0xa110_0bad_0000_0001);
        let inputs = [r.input(100, 0), r.input(50, 9)];
        let outputs = [r.output(90, 0), r.output(50, 9)];
        let rkm1 = derive_rkm_l2(&inputs[1]);
        let other_rkm = r.d4();
        // (a) the registry's asset 9 allowlists `other_rkm`, not ours.
        let asset9 = PolicyAsset::regulated(9, ISK9, false, &frozen_keys(), &[other_rkm]);
        assert!(asset9.policy_input_for(&rkm1, RegistryWitness { siblings: [[0; 4]; REGISTRY_DEPTH], path_bits: [false; REGISTRY_DEPTH] }).is_none());
        let assets = [PolicyAsset::cloaked(0), asset9.clone()];
        let (_, _, cm1) = derive_input_l2(&inputs[0]);
        let (_, _, cm2) = derive_input_l2(&inputs[1]);
        let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let pol0 = assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap();
        let pol1 = L2PolicyInput {
            leaf: asset9.leaf(),
            reg_witness: rw[1],
            freeze: asset9.freeze.opening_for(&rkm1).unwrap(),
            allow: asset9.allow.witness_for(&cred_of(&other_rkm)).unwrap(),
            isk: [0; 4],
        };
        let bad = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert_unsat(&bad, "another holder's credential path");
        // (b) our own credential, genuinely in a DIFFERENT tree.
        let elsewhere = AllowTree::fixture_for_tests(&[cred_of(&rkm1)], 0xe15e_0000_0000_0001);
        let pol1b = L2PolicyInput { allow: elsewhere.witnesses[0], ..pol1 };
        let bad_b = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &[pol0, pol1b], root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        assert_unsat(&bad_b, "a credential path under another root");
        // (c) and lying `rg = 0` to switch the allowlist off is refused by the
        // mode binding.
        let mut lie = bad_b.clone();
        lie.air.rg[1] = false;
        assert_unsat(&lie, "a lied mode (allowlist off)");
        lie.air.rg[1] = true;
        lie.air.hy[1] = true;
        assert_unsat(&lie, "hy ∧ rg");
    }

    /// 🔴 **The re-derivation lie** — the soundness anchor of the three-`ARKM`
    /// layout: `ARKM′` (before `ACRED`) or `ARKM″` (before `ACM`) fed another
    /// `nk` so a different `rkm` reaches the allowlist or the note. Each is
    /// refused by its bank window (third bank / bind bank).
    #[test]
    fn l2p_neg_rkm_rederivation_lie() {
        let fx = honest_fixture();
        for (nth, name) in [(2usize, "ARKM′ (allowlist)"), (3, "ARKM″ (note)")] {
            let mut bad = fx.inst.clone();
            let s = slot_of(&bad.air.program, ROLE_ARKM2, nth);
            bad.air.slot_witness[s].w[0] ^= 0x5eed;
            assert_unsat(&bad, &format!("{name} with a different nk"));
        }
        // And the first ARKM (the bank-1-bound one) lied likewise.
        let mut bad = fx.inst.clone();
        let s = slot_of(&bad.air.program, ROLE_ARKM, 1);
        bad.air.slot_witness[s].w[0] ^= 0x5eed;
        assert_unsat(&bad, "ARKM with a different nk");
    }

    /// 🔴 Lab #758 — the bank-bound copies the determination census could
    /// not reach forward on P, tampered directly, each asserted refused **at
    /// its binding** (a row where that window closes, or the anchor's bind),
    /// not merely somewhere: `ρ` at `ACM` / `ACMF` — bank 2 against `NF`'s
    /// capture (the anchor moves too: the naive tamper, so the claim is only
    /// that bank 2's close is among the refusals); `nk` at the fee chain's
    /// `ARKM` — bank 1; `nf1` at `ARHO` — the third bank (output 1's `cm`
    /// rides `ACMOUT`'s own copy, so the published `cm2` still matches); and
    /// the note path's first step under input 0 (sibling, path bit) — the
    /// anchor's bind at `BANCHOR`.
    #[test]
    fn l2p_neg_bank_bound_copies() {
        let fx = honest_fixture();
        let w = fx.trace.width();
        let rpp = crate::l2::ROWS_PER_PERM;
        // Rows where `col` is nonzero on the honest trace (a window's close).
        let gate_rows = |col: usize| -> Vec<usize> { (0..fx.trace.height()).filter(|r| fx.trace.values[r * w + col] != F::ZERO).collect() };
        // Refused on one of `rows`: every constraint on each row, honest
        // rows first clean (else the probe measures nothing).
        let refused_on = |bad: &L2PBucketInstance, rows: &[usize], what: &str| {
            assert!(!rows.is_empty(), "{what}: no binding rows (probe measures nothing)");
            for r in rows {
                assert!(l2test::violations_at(&fx.inst.air, &fx.trace, &fx.pvs, *r).is_empty(), "{what}: honest trace violated at row {r}");
            }
            let pvs = pvs_of(bad);
            let t = bad.air.generate_trace::<F>(0);
            assert!(rows.iter().any(|r| !l2test::violations_at(&bad.air, &t, &pvs, *r).is_empty()), "{what} VERIFIED at its binding");
        };
        let bank1 = gate_rows(EG_OFF + 2);
        let bank2 = gate_rows(EG_OFF + 5);
        let bank3 = gate_rows(EG3_OFF + 2);
        for (role, name) in [(ROLE_ACM, "ρ@ACM"), (ROLE_ACMF, "ρ@ACMF")] {
            let mut bad = fx.inst.clone();
            let s = slot_of(&bad.air.program, role, 0);
            bad.air.slot_witness[s].w[5] ^= 0x5eed;
            refused_on(&bad, &bank2, &format!("{name} not NF's ρ (bank 2)"));
        }
        // The fee chain's ARKM: the third ARKM slot.
        let mut bad = fx.inst.clone();
        let s = slot_of(&bad.air.program, ROLE_ARKM, 2);
        bad.air.slot_witness[s].w[0] ^= 0x5eed;
        refused_on(&bad, &bank1, "nk@ARKM (fee chain) not NF's (bank 1)");
        let mut bad = fx.inst.clone();
        let s = slot_of(&bad.air.program, ROLE_ARHO, 0);
        bad.air.slot_witness[s].w[5] ^= 0x5eed;
        refused_on(&bad, &bank3, "nf1@ARHO not nf₀, cm2 unchanged (third bank)");
        // Input 0's note path starts after 20 + 16 + 20 policy steps; its
        // anchor binds at input 0's BANCHOR.
        let step = FREEZE_DEPTH + REGISTRY_DEPTH + ALLOW_DEPTH;
        let banchor = slot_of(&fx.inst.air.program, ROLE_BANCHOR, 0);
        let anchor_rows: Vec<usize> = (banchor * rpp..(banchor + 1) * rpp).collect();
        let s = slot_of(&fx.inst.air.program, ROLE_MERKLE, step);
        let mut bad = fx.inst.clone();
        bad.air.slot_witness[s].w[0] ^= 0x5eed;
        refused_on(&bad, &anchor_rows, "a wrong note-path sibling (anchor bind)");
        let mut bad = fx.inst.clone();
        bad.air.slot_witness[s].pbit = !bad.air.slot_witness[s].pbit;
        refused_on(&bad, &anchor_rows, "a flipped note-path bit (anchor bind)");
    }

    /// 🔴 **The public `vPublic` surface**: `vpa` not the row's asset; a term
    /// on row 2 under `q`; a non-bool sign; a lied `nz`.
    #[test]
    fn l2p_neg_vpublic_surface() {
        let mint = mint100();
        mint.assert_sat("precondition");
        let mut vpa = mint.inst.clone();
        vpa.pvs[pv_vp_asset(1)] = 3;
        assert_unsat(&vpa, "a mint revealing the wrong asset");
        // Here `q` is on two asset-0 inputs, where the Cloaked rule already
        // refuses any term; the `close_q · vPublic₂ = 0` leg is exercised on
        // top of it. (Since A4's fee slot, `q` is also reachable on a policy
        // asset — the merge — where vPublic₁ is legal on the summed chain:
        // lab #758's merge-mint/merge-redeem fixtures.)
        let q2 = same_asset();
        q2.assert_sat("precondition: same-asset spend");
        let q2b = bucket(0x0a11_0777, 60, 0, 40, 0, 70, 0, 35, 0, 5, [VPublic::NONE, VPublic::mint(10)]);
        assert!(q2b.air.sel_q);
        assert_unsat(&q2b, "vPublic₂ under q");
        let mut sign = q2.inst.clone();
        sign.pvs[pv_vp_sign(0)] = 2;
        assert_unsat(&sign, "a non-bool sign");
        let mut nz_lie = mint.inst.clone();
        nz_lie.air.vp[1] = VPublic::NONE; // the trace claims nz = 0 while the PVs carry 100
        assert_unsat(&nz_lie, "a lied nz");
    }

    // -----------------------------------------------------------------------
    // The shape-S negatives, re-run against shape P's AIR (they must still hold).
    // -----------------------------------------------------------------------

    fn cm_of_slot(w: &L2PSlotWitness) -> [u64; 4] {
        let rkm: [u64; 4] = w.w[..4].try_into().unwrap();
        let rho: [u64; 4] = w.w[5..9].try_into().unwrap();
        let rseed: [u64; 4] = w.w[9..13].try_into().unwrap();
        l2_cm(w.w[4], w.w[13], &rkm, &rho, &rseed)
    }
    fn republish(inst: &mut L2PBucketInstance, j: usize) {
        let s = slot_of(&inst.air.program, ROLE_ACMOUT, j);
        let cm = cm_of_slot(&inst.air.slot_witness[s]);
        let base = if j == 0 { PV_CM1 } else { PV_CM2 };
        for (k, c) in pv_chunks(&cm).iter().enumerate() {
            inst.pvs[base + k] = *c;
        }
    }

    /// The ten shape-S negatives on P's AIR, one test on the shared fixtures
    /// with a named assertion per tamper (lab #700 ruling 2026-09-23, (c)).
    /// The tamper list is stage 2's, unchanged; the former tests map to the
    /// assertion labels: `l2p_s_neg_output_asset_from_nowhere` → S1,
    /// `…cross_asset_balance` → S2, `…fee_in_wrong_asset` → S3,
    /// `…no_fee_asset_note` → S4, `…registry_leaf_under_wrong_root` → S5a/S5b,
    /// `…mode_bits_outside_the_three` → S6, `…q_lie_is_unsat_both_ways` → S7,
    /// `l2p_s_public_value_negatives` → S8,
    /// `l2p_s_asset_id_is_a_16_bit_registry_index` → S9,
    /// `l2p_s_output_rho_is_still_bound` → S10.
    #[test]
    fn l2p_s_negatives_hold_on_shape_p() {
        let fx = honest_fixture();
        fx.assert_sat("the honest P instance verifies — else every S-negative below is vacuous");

        // S1 — asset from nowhere: output 1 in asset 9, commitment republished.
        let mut s1 = fx.inst.clone();
        let s = slot_of(&s1.air.program, ROLE_ACMOUT, 1);
        s1.air.slot_witness[s].w[13] = 9;
        republish(&mut s1, 1);
        assert_refused_under_every_assignment(&s1, "S1: an output in an asset neither input carries");

        // S2 — cross-asset balance: totals balance, per asset they do not.
        let s2 = bucket(0x5c05_0001, 100, 0, 50, 7, 80, 0, 60, 7, 10, [VPublic::NONE; 2]);
        assert_refused_under_every_assignment(&s2, "S2: cross-asset value movement");

        // S3 — fee charged in the wrong asset.
        let s3 = bucket(0x5c05_0002, 100, 0, 50, 7, 100, 0, 40, 7, 10, [VPublic::NONE; 2]);
        assert_refused_under_every_assignment(&s3, "S3: a fee paid in asset 7");

        // S4 — no asset-0 note.
        let s4 = bucket(0x5c05_0003, 100, 3, 50, 7, 100, 3, 50, 7, 0, [VPublic::NONE; 2]);
        assert_refused_under_every_assignment(&s4, "S4: a transaction with no asset-0 note");

        // S5a — a forged registry root (public value only).
        let mut s5a = fx.inst.clone();
        s5a.pvs[PV_REGROOT + 3] += 1;
        assert_refused_under_every_assignment(&s5a, "S5a: a forged registry root");
        // S5b — another asset's leaf (asset 5, Cloaked) genuinely opened while
        // spending asset 7 — refused by the R = A binding.
        {
            let mut r = Rnd(0x1234_5678_9abc_def0);
            let inputs = [r.input(100, 0), r.input(50, 7)];
            let outputs = [r.output(90, 0), r.output(50, 7)];
            let assets = [PolicyAsset::cloaked(0), PolicyAsset::cloaked(5)];
            let (_, _, cm1) = derive_input_l2(&inputs[0]);
            let (_, _, cm2) = derive_input_l2(&inputs[1]);
            let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
            let leaves = [assets[0].leaf(), assets[1].leaf()];
            let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
            let pol = [
                assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap(),
                assets[1].policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1]).unwrap(),
            ];
            let s5b = build_bucket_l2p_with_witnesses(
                SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &pol, root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
            );
            assert_refused_under_every_assignment(&s5b, "S5b: opening another asset's registry leaf");
        }

        // S6 — shape S's negative 6 inverts on P: a Hybrid leaf is what P is
        // for, and P accepts Cloaked leaves too (a shape-S-class asset in a P
        // transaction) — that is the honest fixture's own claim, asserted
        // above. What P refuses is a leaf whose mode bits are not one of the
        // three, under every (hy, rg) the prover could claim.
        {
            let mut r = Rnd(0x5c05_0007);
            let inputs = [r.input(100, 0), r.input(50, 7)];
            let outputs = [r.output(90, 0), r.output(50, 7)];
            let mut weird = hybrid7(false);
            weird.mode = 4; // bit 2: neither Hybrid nor Regulated nor Cloaked
            let assets = [PolicyAsset::cloaked(0), weird];
            let (_, _, cm1) = derive_input_l2(&inputs[0]);
            let (_, _, cm2) = derive_input_l2(&inputs[1]);
            let (w, anchor) = fabricated_shared_tree(&cm1, &cm2);
            let leaves = [assets[0].leaf(), assets[1].leaf()];
            let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
            let pol = [
                assets[0].policy_input_for(&derive_rkm_l2(&inputs[0]), rw[0]).unwrap(),
                assets[1].policy_input_for(&derive_rkm_l2(&inputs[1]), rw[1]).unwrap(),
            ];
            let mut s6 = build_bucket_l2p_with_witnesses(
                SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &pol, root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
            );
            for (hy, rg) in [(false, false), (true, false), (false, true)] {
                s6.air.hy[1] = hy;
                s6.air.rg[1] = rg;
                assert_unsat(&s6, &format!("S6: mode = 4 as hy={hy} rg={rg}"));
            }
        }

        // S7 — the q lie, both ways, on the two shared fixtures: equal assets
        // with q cleared, distinct assets with q set, each under all eight
        // (o1a, o2a, f1).
        let a = same_asset();
        a.assert_sat("S7 precondition: honest with q = 1");
        let ok = assignments_that_verify_at(&a.inst, false);
        assert!(ok.is_empty(), "S7: q = 0 on equal assets VERIFIED (assignment(s) {ok:?})");
        let b = fee_on_input_2();
        b.assert_sat("S7 precondition: honest with q = 0");
        let ok = assignments_that_verify_at(&b.inst, true);
        assert!(ok.is_empty(), "S7: q = 1 on distinct assets VERIFIED (assignment(s) {ok:?})");

        // S8 — wrong public values on the fixture's trace: nf1, fee, anchor, cm2, nf2.
        for (idx, name) in [(PV_NF1 + 3, "nf1"), (PV_FEE, "fee"), (PV_ANCHOR, "anchor"), (PV_CM2 + 1, "cm2"), (PV_NF2 + 7, "nf2")] {
            let mut pvs = fx.pvs.clone();
            pvs[idx] += F::ONE;
            assert!(
                l2test::first_violation(&fx.inst.air, &fx.trace, &pvs, PROGRAM_END).is_some(),
                "S8: wrong {name} not caught"
            );
        }

        // S9 — an asset id of 2^16 on output 0 (commitment republished).
        let big = 1u64 << ASSET_BITS;
        let mut s9 = fx.inst.clone();
        let s = slot_of(&s9.air.program, ROLE_ACMOUT, 0);
        s9.air.slot_witness[s].w[13] = big;
        republish(&mut s9, 0);
        assert_refused_under_every_assignment(&s9, "S9: a 2^16 output asset");

        // S10 — a free output seed with the matching commitment republished.
        let mut s10 = fx.inst.clone();
        let s = slot_of(&s10.air.program, ROLE_ACMOUT, 0);
        s10.air.slot_witness[s].w[5..9].copy_from_slice(&[0xdead_beef, 1, 2, 3]);
        republish(&mut s10, 0);
        assert_unsat(&s10, "S10: a free output seed on P");
    }

    // -----------------------------------------------------------------------
    // The #219 dummy slot on P.
    // -----------------------------------------------------------------------

    fn dummy_parts() -> (L2TxInput, L2TxInput, [L2TxOutput; 2]) {
        let real = L2TxInput {
            sk: [0x11, 0x22, 0x33, 0x44],
            value: 1_000,
            asset: 7,
            rho: [0x55, 0x66, 0x77, 0x88],
            rseed: [0x99, 0xaa, 0xbb, 0xcc],
            d: [0xd1, 0xd2],
        };
        let dummy = L2TxInput {
            sk: [0xf00d, 0xf00e, 0xf00f, 0xf010],
            value: 0,
            asset: 0,
            rho: [0xbeef01, 0xbeef02, 0xbeef03, 0xbeef04],
            rseed: [0xcafe01, 0xcafe02, 0xcafe03, 0xcafe04],
            d: [0, 0],
        };
        let outputs = [
            L2TxOutput { value: 600, asset: 7, rkm: [2; 4], rho: [3; 4], rseed: [4; 4] },
            L2TxOutput { value: 400, asset: 7, rkm: [5; 4], rho: [6; 4], rseed: [7; 4] },
        ];
        (real, dummy, outputs)
    }

    /// A one-real-input stablecoin spend with a dummy slot verifies (fee 0,
    /// the dummy IS the asset-0 note); a forged seed under the dummy shape is
    /// refused; a nonzero dummy value is a mint; `dv` cannot make slot 0 the dummy.
    #[test]
    fn l2p_dummy_shape_holds() {
        let (real, dummy, outputs) = dummy_parts();
        let inst = build_bucket_l2p_dummy1_fabricated(SHAPE_P_LOG_HEIGHT, &real, &hybrid7(false), &dummy, &outputs, 0, [VPublic::NONE; 2]);
        assert!(inst.air.dv);
        assert_sat(&inst, "the one-real-input stablecoin dummy shape");
        // Redeem 100 from the real input with the dummy in slot 1 (issuer-closed, isk supplied).
        let mut outs = outputs;
        outs[1].value = 300;
        let redeem = build_bucket_l2p_dummy1_fabricated(SHAPE_P_LOG_HEIGHT, &real, &hybrid7(false), &dummy, &outs, 0, [VPublic::redeem(100), VPublic::NONE]);
        assert_sat(&redeem, "a redeem with a dummy slot");
        // Forged seed under the dummy shape (option 4 on the latch).
        let mut forged = inst.clone();
        let out1 = slot_of(&forged.air.program, ROLE_ACMOUT, 1);
        forged.air.slot_witness[out1].w[5..9].copy_from_slice(&[0xbad_5eed, 1, 2, 3]);
        republish(&mut forged, 1);
        assert_refused_under_every_assignment(&forged, "a forged seed under the dummy shape");
        // A nonzero dummy value (the builder refuses it, so it is built by
        // hand through the witness API with `dv` set): the AIR refuses too.
        let mut minted = dummy.clone();
        minted.value = 500;
        let mut outs2 = outputs;
        outs2[1].value = 900;
        let (_, _, cm_real) = derive_input_l2(&real);
        let (w_real, anchor) = fabricated_single_tree(&cm_real);
        let assets = [hybrid7(false), PolicyAsset::cloaked(0)];
        let leaves = [assets[0].leaf(), assets[1].leaf()];
        let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
        let policy = [
            assets[0].policy_input_for(&derive_rkm_l2(&real), rw[0]).unwrap(),
            assets[1].policy_input_for(&derive_rkm_l2(&minted), rw[1]).unwrap(),
        ];
        let mut bad = build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &[real.clone(), minted.clone()], &outs2, 0, &[w_real, off_tree_witness()], anchor, &policy, root, [VPublic::NONE; 2], &FeeSlot::Dummy { input: dummy_fee_input(&[0x7e57; 4]) },
        );
        bad.air.dv = true;
        assert_refused_under_every_assignment(&bad, "a nonzero dummy value (a mint)");
        // A mint on the dummy's row (asset 0, Cloaked) is refused.
        let bad2 = build_bucket_l2p_dummy1_fabricated(SHAPE_P_LOG_HEIGHT, &real, &hybrid7(false), &dummy, &outs2, 0, [VPublic::NONE, VPublic::mint(500)]);
        assert_unsat(&bad2, "a mint through the dummy row");
    }

    /// NF path-bit regression (shape P): the second input's NF perm with its path bit
    /// set, the public nf2 rebound to match — refused by NF's operand order.
    #[test]
    fn l2p_swapped_nf_is_unsat() {
        let fx = honest_fixture();
        fx.assert_sat("precondition: the honest instance verifies");
        let mut inst = fx.inst.clone();
        let slot = slot_of(&inst.air.program, ROLE_NF, 1);
        let nk = digest(&L2ShapePAir::extract_state(&fx.trace, 24 * slot));
        let rho: [u64; 4] = inst.air.slot_witness[slot].w[..4].try_into().unwrap();
        let nf2 = digest(&crate::reference::merkle_node_state(&rho, &nk));
        assert_ne!(nf2, inst.nf[1], "the swap is a different nullifier");
        inst.air.slot_witness[slot].pbit = true;
        for (k, c) in pv_chunks(&nf2).iter().enumerate() {
            inst.pvs[PV_NF2 + k] = *c;
        }
        assert_unsat(&inst, "a swapped-NF second nullifier");
    }
    // -----------------------------------------------------------------------
    // A4 (design #283): the 3×2 merge on P — shape S's positive and six
    // ruled negatives over two Hybrid asset-7 notes (each with its freeze
    // and allowlist openings), complete forgeries through the builder,
    // refused by the early-exit scanner.
    // -----------------------------------------------------------------------

    enum Slot3 {
        Exact { value: u64, asset: u64 },
        Dummy { value: u64 },
    }

    /// Two Hybrid asset-7 notes (30 + 20) in, `outs` (asset 7) out, `fee`
    /// public, slot 3 as given; the builder's honest selectors.
    fn merge(outs: [u64; 2], fee: u64, slot: Slot3) -> L2PBucketInstance {
        let mut r = Rnd(0xa4a4_3e3e_f33d_0003);
        let inputs = [r.input(30, 7), r.input(20, 7)];
        let fee_in = match slot {
            Slot3::Exact { value, asset } => r.input(value, asset),
            Slot3::Dummy { value } => r.input(value, 0),
        };
        let outputs = [r.output(outs[0], 7), r.output(outs[1], 7)];
        let cm = |i: &L2TxInput| derive_input_l2(i).2;
        let (ws, anchor, fee_slot) = match slot {
            Slot3::Exact { .. } => {
                let (w, anchor) = crate::l2::fabricated_tree3([&cm(&inputs[0]), &cm(&inputs[1]), &cm(&fee_in)]);
                ([w[0], w[1]], anchor, FeeSlot::Exact { input: fee_in, witness: w[2] })
            }
            Slot3::Dummy { .. } => {
                let (w, anchor) = fabricated_shared_tree(&cm(&inputs[0]), &cm(&inputs[1]));
                (w, anchor, FeeSlot::Dummy { input: fee_in })
            }
        };
        let asset = hybrid7(false);
        let leaf = asset.leaf().hash();
        let (rw, root) = fabricated_registry_tree(&leaf, &leaf);
        let policy = [0, 1].map(|i| asset.policy_input_for(&derive_rkm_l2(&inputs[i]), rw[i]).expect("not frozen"));
        build_bucket_l2p_with_witnesses(
            SHAPE_P_LOG_HEIGHT, &inputs, &outputs, fee, &ws, anchor, &policy, root, [VPublic::NONE; 2], &fee_slot,
        )
    }

    fn honest_merge() -> L2PBucketInstance {
        merge([50, 0], 10, Slot3::Exact { value: 10, asset: 0 })
    }

    #[test]
    fn l2p_a4_merge_with_an_exact_fee_note_satisfies() {
        let inst = honest_merge();
        assert!(!inst.air.d3 && inst.air.sel_q && !inst.air.sel_f1, "the builder's merge: d3 = 0, q, no row fee");
        assert_sat(&inst, "A4 P merge (d3 = 0)");
    }

    #[test]
    fn l2p_neg_a4_fee_value_not_the_tariff() {
        assert_unsat(&merge([50, 0], 10, Slot3::Exact { value: 11, asset: 0 }), "a d3 = 0 fee note worth 11 for a fee of 10");
        assert_unsat(&merge([50, 0], 10, Slot3::Exact { value: 9, asset: 0 }), "a d3 = 0 fee note worth 9 for a fee of 10");
    }

    #[test]
    fn l2p_neg_a4_fee_input_asset_not_zero() {
        assert_unsat(&merge([50, 0], 10, Slot3::Exact { value: 10, asset: 7 }), "a fee note of asset 7");
    }

    #[test]
    fn l2p_neg_a4_nf3_bind_lie() {
        let mut inst = honest_merge();
        inst.pvs[PV_NF3] ^= 1;
        assert_unsat(&inst, "a published fee-input nullifier the fee chain did not derive");
    }

    #[test]
    fn l2p_neg_a4_dummy_fee_input_with_a_value() {
        // `honest()`'s spend (asset 0 pays the row fee, d3 = 1) with its dummy
        // slot 3 carrying 5 — and the value-0 control through the same scanner.
        let build = |value: u64| {
            let mut r = Rnd(0x1234_5678_9abc_def0);
            let inputs = [r.input(100, 0), r.input(50, 7)];
            let outputs = [r.output(90, 0), r.output(50, 7)];
            let assets = [PolicyAsset::cloaked(0), hybrid7(false)];
            let (w, anchor) = fabricated_shared_tree(&derive_input_l2(&inputs[0]).2, &derive_input_l2(&inputs[1]).2);
            let leaves = [assets[0].leaf(), assets[1].leaf()];
            let (rw, root) = fabricated_registry_tree(&leaves[0].hash(), &leaves[1].hash());
            let policy = [0, 1].map(|i| assets[i].policy_input_for(&derive_rkm_l2(&inputs[i]), rw[i]).unwrap());
            let mut dummy = dummy_fee_input(&[9, 8, 7, 6]);
            dummy.value = value;
            build_bucket_l2p_with_witnesses(
                SHAPE_P_LOG_HEIGHT, &inputs, &outputs, 10, &w, anchor, &policy, root, [VPublic::NONE; 2],
                &FeeSlot::Dummy { input: dummy },
            )
        };
        assert!(refused(&build(0)).is_none(), "control: the value-0 dummy spend");
        assert_unsat(&build(5), "a d3 = 1 dummy fee input worth 5");
    }

    /// P's balance block is its own copy of S's (the chains carry vPublic),
    /// not a shared fn — so P runs the full eight-assignment fan-out too
    /// (coordinator ruling on A4 step 4).
    #[test]
    fn l2p_neg_a4_d3_1_row_fee_on_a_non_zero_asset_row() {
        assert_refused_under_every_assignment(&merge([40, 0], 10, Slot3::Dummy { value: 0 }), "a d3 = 1 fee on an asset-7 row");
    }

    #[test]
    fn l2p_neg_a4_merge_over_issue() {
        assert_refused_under_every_assignment(
            &merge([50, 1], 10, Slot3::Exact { value: 10, asset: 0 }),
            "a merge minting 1 (30 + 20 → 50 + 1)",
        );
    }

}

/// **The canonical policy tree** (lab #722): goldens pinned from the named
/// run of `examples/canonical_policy_tree_goldens` (twice, byte-identical),
/// whose independent encoder folds the full padded 2^20 leaf array.
#[cfg(test)]
mod canonical_tree_tests {
    use super::*;

    const EMPTY_ROOT: [u64; 4] = [0xf8d82fd66d2735bb, 0xd8bf72a840613477, 0xf06f185fb6a4c488, 0x80c09ad3c7cac22d];
    const THREE_KEY_ROOT: [u64; 4] = [0xab4045d7128feeb8, 0xfcc918c5a405d481, 0x642dac75d472a9c2, 0xf257044207d689a6];

    fn three_keys() -> Vec<[u64; 4]> {
        (1..=3u64).map(|i| freeze_key_of(&[i, i, i, i])).collect()
    }

    #[test]
    fn the_canonical_freeze_tree_roots_are_the_pinned_goldens() {
        assert_eq!(CanonicalFreezeTree::empty().root, EMPTY_ROOT);
        assert_eq!(CanonicalFreezeTree::from_keys(&three_keys()).root, THREE_KEY_ROOT);
        // Order- and duplicate-free: the published list is a set.
        let mut shuffled = three_keys();
        shuffled.reverse();
        shuffled.push(shuffled[0]);
        assert_eq!(CanonicalFreezeTree::from_keys(&shuffled).root, THREE_KEY_ROOT);
        assert_eq!(CanonicalFreezeTree::from_rkms(&[[1; 4], [2; 4], [3; 4]]).root, THREE_KEY_ROOT);
    }

    #[test]
    fn every_opening_folds_to_the_root_and_a_frozen_key_has_none() {
        let t = CanonicalFreezeTree::from_rkms(&[[1; 4], [2; 4], [3; 4]]);
        assert!(t.is_frozen(&[2; 4]) && !t.is_frozen(&[9; 4]));
        assert!(t.opening_for(&[2; 4]).is_none(), "a frozen rkm has no non-membership opening");
        for rkm in [[9u64; 4], [0x77; 4], [u64::MAX - 1; 4]] {
            let o = t.opening_for(&rkm).expect("an unfrozen rkm opens");
            let k = freeze_key_of(&rkm);
            assert!(key_lt(&o.key_lo, &k) && key_lt(&k, &o.key_hi));
            assert_eq!(o.witness.fold_root(&freeze_leaf_hash(&o.key_lo, &o.key_hi)), t.root);
        }
        let allow = CanonicalAllowTree::from_rkms(&[[4; 4], [5; 4]]);
        let w = allow.witness_for(&cred_of(&[5; 4])).expect("an allowlisted holder has a witness");
        assert_eq!(w.fold_root(&cred_of(&[5; 4])), allow.root);
        assert!(allow.witness_for(&cred_of(&[6; 4])).is_none());
        assert_eq!(policy_zeros()[POLICY_DEPTH], CanonicalAllowTree::from_creds(&[]).root, "an empty allowlist is the zero chain's top");
    }
}

// ---------------------------------------------------------------------------
// The witness manifest (lab #758), read against
// `build_bucket_l2p_with_witnesses`'s program/lane writes.
// ---------------------------------------------------------------------------

/// Shape P3's witness manifest: S3's, plus the policy blocks (`isk`, the
/// freeze non-membership keys, the allowlist path). `hy`/`rg`/`ropen` are
/// bound to the leaf in-circuit and are not inputs.
#[cfg(any(test, feature = "audit"))]
pub fn witness_manifest() -> Vec<crate::detaudit::ManifestEntry> {
    use crate::detaudit::{ManifestEntry as M, ANY_ROLE};
    let w = |r: core::ops::Range<usize>| r.map(|i| W_OFF + i).collect::<Vec<_>>();
    let mut m = vec![
        M::input(ROLE_ANK, w(0..4), "input.sk"),
        M::input(ROLE_NF, w(0..4), "input.rho"),
        M::input(ROLE_AISS, w(0..4), "policy.isk"),
        M::copy(ROLE_ARKM, w(0..4), "input.nk"),
        M::input(ROLE_ARKM, w(5..7), "input.d"),
        M::copy(ROLE_ARKM2, w(0..4), "input.nk"),
        M::input(ROLE_ARKM2, w(5..7), "input.d"),
        M::input(ROLE_AFRZ, w(0..4), "freeze.key_lo"),
        M::input(ROLE_AFRZ, w(5..9), "freeze.key_hi"),
        M::input(ROLE_AREG, w(0..15), "registry.leaf"),
        M::input(ROLE_MERKLE, w(0..4), "path.sibling"),
        M::input(ROLE_MERKLE, vec![PBIT_COL], "path.bit"),
        M::copy(ROLE_ARHO, w(5..9), "nf1"),
        M::input(ROLE_ACMOUT, w(0..4), "output.rkm"),
        M::input(ROLE_ACMOUT, w(4..5), "output.value"),
        M::copy(ROLE_ACMOUT, w(5..9), "output.rho"),
        M::input(ROLE_ACMOUT, w(9..13), "output.rseed"),
        M::input(ROLE_ACMOUT, w(13..14), "output.asset"),
        M::input(ANY_ROLE, vec![DV_COL], "dv"),
        M::input(ANY_ROLE, vec![D3_COL], "d3"),
    ];
    for role in [ROLE_ACM, ROLE_ACMF] {
        m.push(M::input(role, w(4..5), "input.value"));
        m.push(M::copy(role, w(5..9), "input.rho"));
        m.push(M::input(role, w(9..13), "input.rseed"));
        m.push(M::input(role, w(13..14), "input.asset"));
    }
    m
}

/// Lab #896 seam T: shape P **v2**'s witness manifest — v1's without `ANK`
/// and `NF`, plus shape S v2's entries (`NFA`'s `nk`/ρ inputs, `AAUTH`'s
/// leaf copy and sibling/bit inputs, the first `ARKM`'s `auth_root` copy via
/// `EQA`). The two `ARKM2`s' `auth_root` is a **copy**, as their `nk` is: both
/// are bound to the first `ARKM` only through the output equality, so the
/// census treats them alike — determined only under the collision-resistance
/// premise ([`audit_cr_premise_v2`]), exactly as lab #758 ran v1.
#[cfg(any(test, feature = "audit"))]
pub fn witness_manifest_v2() -> Vec<crate::detaudit::ManifestEntry> {
    use crate::detaudit::ManifestEntry as M;
    let w = |r: core::ops::Range<usize>| r.map(|i| W_OFF + i).collect::<Vec<_>>();
    let mut m: Vec<_> = witness_manifest().into_iter().filter(|e| e.role != ROLE_ANK && e.role != ROLE_NF).collect();
    m.extend([
        M::input(ROLE_NFA, w(9..13), "input.nk"),
        M::input(ROLE_NFA, w(0..4), "input.rho"),
        M::copy(ROLE_AAUTH, w(0..4), "auth.leaf"),
        M::input(ROLE_AAUTH, w(4..8), "auth.sibling"),
        M::input(ROLE_AAUTH, vec![PBIT_COL], "auth.bit"),
        M::copy(ROLE_ARKM, w(7..11), "input.auth_root"),
        M::copy(ROLE_ARKM2, w(7..11), "input.auth_root"),
    ]);
    m
}

/// Shape P3's program as the census reads it.
#[cfg(any(test, feature = "audit"))]
pub fn audit_program(air: &L2ShapePAir) -> crate::detaudit::Program {
    crate::detaudit::Program { rows_per_perm: crate::l2::ROWS_PER_PERM, roles: air.program.to_vec() }
}

/// The census's public-value range premise (lab #758), per [`pv_vec_l2p`]:
/// digests and the fee and each `vPublic` amount as 16-bit chunks, each
/// row's `redeem` a bool (`as u32` of a bool), each row's `vpa` a `u32` cast
/// of the asset. The node builds them with it (`qumbra-node` `verifier.rs`,
/// `qlab_l2::pv_vec_p`); `qlab_l2::verify_p` refuses a vector outside them.
pub fn audit_pv_bits() -> Vec<u32> {
    let mut b = vec![16; PV_LEN];
    for base in [PV_VP1, PV_VP2] {
        b[base] = 1; // redeem
        b[base + 5] = 32; // vpa
    }
    b
}

/// Column regions by name (lab #758): every `*_OFF`/`*_COL` constant of this
/// module, so census output names columns from the source of truth rather
/// than from comments. A column belongs to the region with the greatest
/// start ≤ it.
#[cfg(any(test, feature = "audit"))]
pub fn audit_col_regions() -> Vec<(&'static str, usize)> {
    let mut v = vec![
        ("A_OFF", A_OFF),
        ("C_OFF", C_OFF),
        ("US_OFF", US_OFF),
        ("AP_OFF", AP_OFF),
        ("X00_COL", X00_COL),
        ("S_OFF", S_OFF),
        ("V_OFF", V_OFF),
        ("UV_OFF", UV_OFF),
        ("U_OFF", U_OFF),
        ("UU_OFF", UU_OFF),
        ("R_OFF", R_OFF),
        ("B_OFF", B_OFF),
        ("PB_OFF", PB_OFF),
        ("PH_OFF", PH_OFF),
        ("PR_OFF", PR_OFF),
        ("D_OFF", D_OFF),
        ("RB_OFF", RB_OFF),
        ("LO_OFF", LO_OFF),
        ("SEL_OFF", SEL_OFF),
        ("INJ_OFF", INJ_OFF),
        ("G4_COL", G4_COL),
        ("PBIT_COL", PBIT_COL),
        ("W_OFF", W_OFF),
        ("EQ_OFF", EQ_OFF),
        ("EG_OFF", EG_OFF),
        ("EP_COL", EP_COL),
        ("GWRAP_COL", GWRAP_COL),
        ("SE_OFF", SE_OFF),
        ("BQ_OFF", BQ_OFF),
        ("BGCAP_COL", BGCAP_COL),
        ("BGRST_COL", BGRST_COL),
        ("BGC_OFF", BGC_OFF),
        ("BL_OFF", BL_OFF),
        ("BLC_OFF", BLC_OFF),
        ("BLCLOSE_COL", BLCLOSE_COL),
        ("INJ3E_COL", INJ3E_COL),
        ("INJ4E_COL", INJ4E_COL),
        ("EFF_OFF", EFF_OFF),
        ("LATCH_COL", LATCH_COL),
        ("DV_COL", DV_COL),
        ("LDV_COL", LDV_COL),
        ("OM_COL", OM_COL),
        ("EQ3_OFF", EQ3_OFF),
        ("EG3_OFF", EG3_OFF),
        ("INJRE_COL", INJRE_COL),
        ("AG_OFF", AG_OFF),
        ("AC_OFF", AC_OFF),
        ("SEL2_OFF", SEL2_OFF),
        ("QINV_COL", QINV_COL),
        ("CQ_OFF", CQ_OFF),
        ("SG_OFF", SG_OFF),
        ("BL2_OFF", BL2_OFF),
        ("BLC2_OFF", BLC2_OFF),
        ("INJ_AFRZE_COL", INJ_AFRZE_COL),
        ("INJ_ACREDE_COL", INJ_ACREDE_COL),
        ("CLOSE_CRED_COL", CLOSE_CRED_COL),
        ("EGB_COL", EGB_COL),
        ("EGBC_COL", EGBC_COL),
        ("AREGE_COL", AREGE_COL),
        ("CRQ_COL", CRQ_COL),
        ("INJ_AFKEYE_COL", INJ_AFKEYE_COL),
        ("CMP_OFF", CMP_OFF),
        ("POL_OFF", POL_OFF),
        ("FB_OFF", FB_OFF),
        ("L3_COL", L3_COL),
        ("D3_COL", D3_COL),
        ("L3D3_COL", L3D3_COL),
        ("Z_OFF", Z_OFF),
        ("ZINV_OFF", ZINV_OFF),
        ("XE_COL", XE_COL),
        ("XINV_COL", XINV_COL),
    ];
    v.sort_by_key(|(_, c)| *c);
    v
}

/// Lab #896 seam T: v1's regions plus every column v2 appends, up to
/// [`L2P_WIDTH_V2`].
#[cfg(any(test, feature = "audit"))]
pub fn audit_col_regions_v2() -> Vec<(&'static str, usize)> {
    let mut v = audit_col_regions();
    v.extend([
        ("XR_OFF", XR_OFF),
        ("SELV2_OFF", SELV2_OFF),
        ("SEV2_OFF", SEV2_OFF),
        ("INJV2_OFF", INJV2_OFF),
        ("EGN_COL", EGN_COL),
        ("EGL_POS_COL", EGL_POS_COL),
        ("EGL_CLOSE_COL", EGL_CLOSE_COL),
        ("EQL_OFF", EQL_OFF),
        ("EGA_POS_COL", EGA_POS_COL),
        ("EQA_OFF", EQA_OFF),
    ]);
    v.sort_by_key(|(_, c)| *c);
    v
}

/// The census's verifier-supplied public values (lab #758): **only** a
/// `vPublic` row's `redeem` and `vpa` when that row's amount is zero. There
/// the AIR reads them only through `Σm·(vpa − asset)`, `s·m` and
/// `nz·s·ropen` — all zero — so they are free in the AIR, and it is the
/// surface codec that pins them: `qlab-devnet` `annulet.rs` refuses a
/// zero-amount term with `redeem` set or `asset ≠ 0`
/// (`L2SurfaceError::NonCanonicalZeroTerm`) before any proof is checked.
/// The amount's chunks are never declared: they must come out of the witness
/// through the balance (a nonzero row's `redeem`/`vpa` too).
/// A **diagnostic** premise, never a verdict's (lab #758 R12): the
/// bit-serial compare's cells (both blocks) declared as sources on every
/// row. They reach the statement only through the verdict at `AFRZ`'s
/// z = 63; declaring them separates "the compare's free T-row cells block
/// the census's elimination" from "a bank tie is missing".
#[cfg(any(test, feature = "audit"))]
pub fn audit_cmp_cells() -> crate::detaudit::ManifestEntry {
    crate::detaudit::ManifestEntry::input(crate::detaudit::ANY_ROLE, (CMP_OFF..CMP_OFF + 2 * CMP_BLOCK).collect(), "cmp (diagnostic premise)")
}

/// The census's **collision-resistance premise** (lab #758 R14), declared
/// sources: the one copy whose only tie runs through a digest's *output*.
/// `ARKM′`/`ARKM″` (`ROLE_ARKM2`) take `nk` as a free input, with no bank-1
/// legs; what binds it is the output: `rkm@AFKEY − rkm′@ACRED` on the third
/// bank, closed at `ACRED`'s end, and `rkm′@ACRED − rkm″@ACM` on the bind
/// bank, closed at `ACM`'s end (module doc, "Why three ARKMs"). A different
/// `nk` reaching the same `rkm` is a Keccak preimage/collision — out of the
/// census's algebraic scope, so the census cannot determine these cells
/// forward and everything downstream of the first `ARKM′` reads free. Every
/// other copy is tied by a bank to a value computed forward (nk@ARKM by bank
/// 1 from NF's capture; ρ@ACM/ACMF by bank 2 from NF's; nf1@ARHO and the
/// outputs' ρ by the third bank): those are NOT under this premise.
#[cfg(any(test, feature = "audit"))]
pub fn audit_cr_premise() -> Vec<crate::detaudit::ManifestEntry> {
    let w = |r: core::ops::Range<usize>| r.map(|i| W_OFF + i).collect::<Vec<_>>();
    vec![crate::detaudit::ManifestEntry::input(ROLE_ARKM2, w(0..4), "input.nk @ ARKM′/″ (CR premise)")]
}

/// Lab #896 seam T: v1's collision-resistance premise plus the v2 lanes it
/// covers — `auth_root` at `ARKM′/″`, bound only through the same output.
#[cfg(any(test, feature = "audit"))]
pub fn audit_cr_premise_v2() -> Vec<crate::detaudit::ManifestEntry> {
    let w = |r: core::ops::Range<usize>| r.map(|i| W_OFF + i).collect::<Vec<_>>();
    let mut v = audit_cr_premise();
    v.push(crate::detaudit::ManifestEntry::input(ROLE_ARKM2, w(7..11), "input.auth_root @ ARKM′/″ (CR premise)"));
    v
}

/// A **diagnostic** premise (lab #758 R15): the output-row selectors
/// `o1a`/`o2a` declared sources. Under `q` (one distinct asset) they are the
/// designed accounting freedom — the balance closes on `BL + BL2`, so which
/// row an output is counted on moves no public value (confirmed SAT with no
/// PV moved). Declared, the per-row accumulators `BL`/`BL2` become
/// determinable and the enumeration can reach row 1's amount; the amount
/// reads only their sum, which no assignment of `o1a`/`o2a` changes.
#[cfg(any(test, feature = "audit"))]
pub fn audit_sel2_accounting() -> crate::detaudit::ManifestEntry {
    crate::detaudit::ManifestEntry::input(crate::detaudit::ANY_ROLE, vec![SEL2_OFF + S2_O1A, SEL2_OFF + S2_O2A], "o1a, o2a (diagnostic premise)")
}

/// Where each witness copy is actually read (lab #758 R11): its field,
/// the injection column that is 1 on the rows whose message absorbs it, and
/// its lanes. [`witness_manifest`] declares a copy on every row of its role;
/// off the injection rows the lanes are read only by the bit-serial compare
/// (xy block 0 reads `W0..3`, block 1 `W5..8`, on every M row), so a census
/// component there names the copy without touching the value the hash reads.
#[cfg(any(test, feature = "audit"))]
pub fn audit_copy_reads() -> Vec<(&'static str, usize, Vec<usize>)> {
    let w = |r: core::ops::Range<usize>| r.map(|i| W_OFF + i).collect::<Vec<_>>();
    vec![
        ("input.nk (ARKM + ARKM2 absorb)", INJ_OFF + 2, w(0..4)),
        ("input.rho (ACM absorb)", INJ_OFF + 3, w(5..9)),
        ("input.rho (ACMF absorb)", INJ_OFF + INJ_ACMF, w(5..9)),
        ("output.rho (ACMOUT absorb)", INJ_OFF + 4, w(5..9)),
        ("nf1 (ARHO absorb)", INJ_OFF + 5, w(5..9)),
    ]
}

#[cfg(any(test, feature = "audit"))]
pub fn audit_pv_inputs(pvs: &[u32]) -> Vec<usize> {
    let mut v = Vec::new();
    for base in [PV_VP1, PV_VP2] {
        if pvs[base + 1..base + 5].iter().all(|m| *m == 0) {
            v.extend([base, base + 5]);
        }
    }
    v
}

/// Lab #937: shape P **v3**'s witness manifest is v2's — the third output
/// span reuses `ARHO` / `ACMOUT` / `BCM2`, whose entries are per role — plus
/// `o3f` (A′), a per-transaction declaration like `d3`.
#[cfg(any(test, feature = "audit"))]
pub fn witness_manifest_v3() -> Vec<crate::detaudit::ManifestEntry> {
    let mut m = witness_manifest_v2();
    m.push(crate::detaudit::ManifestEntry::input(crate::detaudit::ANY_ROLE, vec![O3F_COL], "o3f"));
    m
}

/// Lab #937: v2's regions plus every column v3 appends, up to
/// [`L2P_WIDTH_V3`].
#[cfg(any(test, feature = "audit"))]
pub fn audit_col_regions_v3() -> Vec<(&'static str, usize)> {
    let mut v = audit_col_regions_v2();
    v.extend([
        ("XR3_COL", XR3_COL),
        ("OM2_COL", OM2_COL),
        ("AG_O3_COL", AG_O3_COL),
        ("AC_O3_COL", AC_O3_COL),
        ("SEL_O3A_COL", SEL_O3A_COL),
        ("SG3_COL", SG3_COL),
        ("O3F_COL", O3F_COL),
        ("SF3_COL", SF3_COL),
        ("FBC_OFF", FBC_OFF),
    ]);
    v.sort_by_key(|(_, c)| *c);
    v
}

/// [`audit_sel2_accounting`] for v3: `o3a` is the same designed accounting
/// freedom under `q` as `o1a`/`o2a`.
#[cfg(any(test, feature = "audit"))]
pub fn audit_sel2_accounting_v3() -> crate::detaudit::ManifestEntry {
    crate::detaudit::ManifestEntry::input(
        crate::detaudit::ANY_ROLE,
        vec![SEL2_OFF + S2_O1A, SEL2_OFF + S2_O2A, SEL_O3A_COL],
        "o1a, o2a, o3a (diagnostic premise)",
    )
}

#[cfg(test)]
#[path = "l2p_v2_tests.rs"]
mod v2_tests;

#[cfg(test)]
#[path = "l2p_v3_tests.rs"]
mod v3_tests;
