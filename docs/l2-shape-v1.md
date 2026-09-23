# L2 shape v1 — shapes frozen, lane provisional

> [中文版](l2-shape-v1-zh.md) · tracker: lab issue #704 (l2-roadmap A1) · circuits: lab PR #701 / issue #700 (W3) · crate: `crates/qlab-l2`

**Status (2026-09-23):** the two L2 transaction shapes, **S** and **P**, are frozen as v1. Their program, geometry, public-value layout, note block, in-circuit domains and constraint set are pinned by name in `qlab-l2` and `qlab-note`. The **lane is not frozen**: `L2_CFG_PROVISIONAL` stays provisional while a coordinator-side review of the lane's PCS configuration is open. That review can change the proof wire without touching the AIRs, so **no proof-byte count is pinned**.

## 1. What is frozen

| object | v1 value | pinned by |
|---|---|---|
| shape S geometry | 702 columns · 120 perms · 2^19 rows · max constraint degree 4 (4 quotient chunks) · 100 public values | `l2_shape_geometry_is_locked`; `qlab-air` `l2_trace_width_is_read_off_the_matrix`, `l2_quotient_degree_matches_the_l1` |
| shape P geometry | **778** columns · **214** perms (216-slot ring) · 2^20 rows · degree 4 · 112 public values | `l2_shape_geometry_is_locked`; `qlab-air` `l2p_trace_width_is_read_off_the_matrix`, `l2p_quotient_degree_matches_the_l1`, `l2p_program_geometry` |
| PV layout | `anchor` 0 · `nf₁` 16 · `nf₂` 32 · `cm₁` 48 · `cm₂` 64 · `fee` 80 (four 16-bit chunks) · `registry_root` 84 · P only: `vPublic₁` 100, `vPublic₂` 106 (each `redeem`, four 16-bit chunks of `amount`, `vpa`) | `l2_shape_geometry_is_locked`, `l2_golden_pv_vectors` |
| the program | every slot's 5-bit role code; every builder emits the same program, so a verifier's AIR is a function of the shape alone | `l2_verifier_air_is_instance_independent`; the shape digest |
| the note block | `cm = H(value ‖ asset ‖ rkm ‖ ρ ‖ rseed)`; 112-B plaintext `value(8 LE) ‖ asset(8 LE) ‖ rkm ‖ ρ ‖ rseed` | `qlab-note` `l2_golden_note_block` (literals computed outside Rust), `l2_commitment_matches_qlab_air_build_bucket_l2` |
| discovery payload | `L2_PAYLOAD_LEN = 128` (112-B note + 16-B tag) | `qlab-note` `l2_payload_len_is_128` |
| in-circuit domains (P) | `D_I` = lane 4 bit 7 (`issuer_key = H(isk ‖ D_I)`) · `D_CRED` = lane 4 bit 15 (`cred = H(rkm ‖ D_CRED)`) · **`D_FRZ` = lane 4 bit 31** (`K = H(rkm ‖ D_FRZ)`, the freeze key) | known answers inside the shape digest; `l2p_policy_blocks_match_reference` |
| asset id space | 16-bit registry index (bits 16..63 forced zero); registry depth 16 | `l2_asset_id_is_a_16_bit_registry_index`; `l2_shape_geometry_is_locked` |
| tree depths | commitment 32 · registry 16 · freeze 20 (indexed, sorted, keyed by `K`) · allowlist 20 | the shape digest |
| **shape digests** | S `7a6391bc98eed26b4bff7aaaa987f7d6ef657e27ad50746c9c519bcabdae6670` · P `ad53d40e7d5ffd8235b701fab16856f428790b7ba33efc8915abe625f1bacaff` | `l2_shape_digests_are_pinned` |

**The shape digest** (`qlab_l2::digest`) is `Keccak-256(b"qumbra:l2:shape:v1" ‖ tag ‖ constants ‖ constraints)`:
- *constants*: geometry, the PV layout, the canonical program, depths, modes and flags, plus known-answer outputs of every host hash the circuit mirrors. The domains are lane/bit positions inside hash blocks, not named constants, so they are pinned through those outputs rather than re-typed.
- *constraints*: a structural content hash of Plonky3's symbolic constraint set — S has 1,057 constraints, P has 1,270. A constraint edit that moves no constant still moves the digest.
- The digest is computed twice in the test, which checks it is deterministic.
- **A Plonky3 bump that moves it is a freeze event.** Re-pin only with the coordinator.

### 1.1 The one change to W3's shape P: the freeze key is hashed

W3 built shape P with the freeze tree keyed by the **raw `rkm`**. The #704 ruling (Q1) replaced that key with **`K = H(rkm ‖ D_FRZ)`**:
- A new perm `AFKEY` (role code 22) sits between `ARKM` and `AFRZ` on each input. It absorbs the chained `rkm` with `D_FRZ`.
- The two bit-serial comparisons on `AFRZ`'s boundary now compare `K` against the low leaf.
- The third bank's `+rkm` leg moves to `AFKEY`'s boundary, so `rkm` is still tied across all three of its derivations.

Cost: +2 perms (212 → 214, still 2^20) and +4 columns (774 → 778): one ring limb, one selector, one injection, one gate. The degree is unchanged.

Why it was worth changing: with raw keys, the published freeze list hands every reader the owner half of each frozen address. With hashed keys, a reader learns nothing about an address it does not already hold. A party that does hold the address can still test it, which is the same disclosure a public sanctions list makes.

The mutation check is `l2p_neg_raw_rkm_keyed_witness`: a genuine leaf that brackets the *raw* `rkm` of a frozen holder, which W3's circuit accepted, is now UNSAT.

## 2. What is not frozen

| object | status |
|---|---|
| the lane `L2_CFG_PROVISIONAL` = b4/q43/g22/fp16/a16 | **provisional**; built at exactly one site, `qlab_l2::make_config_l2()`, so the lane review's outcome is a one-site change. It is guarded against *accidental* edits by `l2_cfg_provisional_is_value_locked`. Why b4: both shapes are degree 4 (4 quotient chunks), and b2 does not verify a 4-chunk AIR in Plonky3 0.6.1 (`l2shape_b2_is_not_a_lane_for_a_degree_4_air`). q43/g22 = 101.6 bits under the 2197-corrected accounting. |
| the proof wire | **not pinned.** No `WIRE_BYTES_S/P` constant and no byte test; the numbers below are measurements. |
| proof bytes of a fixed instance | never pinned, by design. Plonky3's grind witness is found by a parallel `find_any` and every query index is drawn after it, so the same instance can yield different proofs across thread schedules. The PV vector and the note block are pinned instead. |

## 3. Measured under the provisional lane (W3 record, not pins)

Apple M5 Max / 36 GiB, release binary directly under `/usr/bin/time -l` inside `scripts/rig run`, zero swap; sources `docs/w3-run1.md` … `w3-run4.md`.

| shape | lane | width | log_height | prove | peak footprint | proof, bincode-fixed |
|---|---|---|---|---|---|---|
| S (rev `8a20234`) | b4/q43/g22 | 702 | 19 | 1.52 s | 6.80 GB | 285,605 B |
| P (rev `20723c9`, **774 cols — before `AFKEY`**) | b4/q43/g22 | 774 | 20 | 3.56–3.76 s | 15.06–15.11 GB | 312,677 B |
| P v1 (778 cols) | b4/q43/g22 | 778 | 20 | **re-measure owed (coordinator's rig)** | — | — |

**Shape S proves on 16 GB-class machines, shape P on 32 GB-class machines at b4.** P's 15.1 GB does not fit a 16 GB laptop with an OS on it.

## 4. Tests added by A1

`qlab-l2`: `l2_cfg_provisional_is_value_locked`, `l2_crate_deps_are_exactly_air_and_consensus`, `l2_shape_geometry_is_locked`, `l2_verifier_air_is_instance_independent`, `l2_prove_verify_roundtrip_s`, `l2_prove_verify_roundtrip_p`, `l2_shape_digests_are_pinned`, `l2_golden_pv_vectors`. `qlab-note`: `l2_payload_len_is_128`, `l2_golden_note_block`. `qlab-air`: `l2p_neg_raw_rkm_keyed_witness`. Existing tests were updated for P v1; none were removed.
