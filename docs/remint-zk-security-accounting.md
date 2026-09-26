# The re-mint's hiding lane — security accounting

> [中文版](remint-zk-security-accounting-zh.md) · the security re-mint · method: `qumbra-design/fri-soundness-accounting-2026-07.md` §6 (the 2197-corrected conjectured ceiling) and `docs/issue22-soundcalc.md` (the proven-regime term inventory)

**Summary: the ≥ 100-bit conjectured floor holds under ZK with Plonky3's example values (query term unchanged: L1 100.6, L2 101.6), but the margin of the tightest non-query term **narrows by one bit**, from 3–12 to ~2–11 bits above the floor (soundcalc: −1 bit on every non-query term, §2). Salt 123.8 bits meets the floor. 2024/1037 sets no minimum on `num_random_codewords` (its conditions are on the randomizer degrees and the FRI mask, all met with large margins); 4 is kept (§3).**

**Status (2026-09-24): derived by reading, then checked by one tool run.** The non-query term inventory under ZK comes from a coordinator-named soundcalc run (§2); nothing else comes from a run.

## 1. What the hiding lane changes

Plonky3 0.6.1 `HidingFriPcs` implements eprint 2024/1037. The prover path was read in `p3-fri` `hiding_pcs.rs` and `p3-uni-stark` `prover.rs`. It changes five things:

1. **Every committed matrix is randomized.** The height doubles: original rows are interleaved with uniformly random rows. `NUM_RANDOM_CODEWORDS` = 4 uniformly random columns are appended. The proof's `degree_bits` becomes `log_height + 1` (`IS_ZK = 1`).
2. **The quotient is masked.** The constraint degree seen by the quotient becomes `d + 1`, and the chunk count doubles: with degree 4, the chunks go from 4 to 8. Each chunk `i < last` gets `v_H·t_i` with random `t_i`, and the last chunk takes the balancing term (2024/1037 §4.2). `num_chunks > 1` is asserted by Plonky3.
3. **The FRI batch is masked.** A separate randomization commitment has width `NUM_RANDOM_CODEWORDS + D`, where `D = 4` is the extension degree. It is added to the batch, so the batched DEEP quotient that FRI tests is itself uniformly masked over the extension field.
4. **Merkle leaves are salted** with `SALT_ELEMS` = 4 random base-field elements (`MerkleTreeHidingMmcs`), for both the trace MMCS and the FRI MMCS.
5. **All of this randomness** comes from `ProverRng`: ChaCha20 with a 256-bit seed drawn from the OS. Each consumer (trace MMCS, FRI MMCS, PCS) gets its own seed, and a clone reseeds.

## 2. Soundness: the ≥ 100-bit conjectured floor

**The query term does not move.** The 2197-corrected ceiling is `t · β(ρ) + g`:
- `β(ρ)` is the per-query bits at the base-field list-decoding radius. It depends on the rate `ρ = 1/blowup`, and on the codeword length `n` only through whether the list size exceeds `|F|`. For every `n ≥ 2^16` it does, by hundreds of orders of magnitude, so the ceiling is independent of `n` to well under 0.1 bit (§6's own cross-check shows the same saturation).
- The hiding lane doubles `n` (the trace is committed at 2N) and leaves `ρ`, `t` and `g` alone.

| lane | ρ | t | g | 2197-corrected, non-ZK (measured record) | under ZK |
|---|---|---|---|---|---|
| L1 consensus b16/q21/g22 | 1/16 | 21 | 22 | 100.6 | **100.6** |
| L2 b4/q43/g22 (S/P/R) | 1/4 | 43 | 22 | 101.6 | **101.6** |

**Non-query terms move by about 1–2 bits.** The proven-regime inventory (soundcalc, issue #22) puts DEEP and ALI 3–12 bits above the conjectured query floor. Under ZK:
- the DEEP term's `n·d/|F|` grows by 2× in `n` and by `(d+1)/d` in degree: about −1.3 to −1.6 bits;
- ALI grows with the constraint count, +1 for the NF fix: negligible;
- batching grows with the batch width: +4 columns per matrix, plus 8 quotient chunks instead of 4, plus the randomizer. That is `log2` of a few-percent width change: well under 1 bit.

**Measured by soundcalc** (the proven-regime inventory tool of issue #22, rev `809896fb`; input `docs/remint-zk-soundcalc-input.toml`; each lane run as a non-ZK twin with today's real values and a ZK twin with trace ×2, degree + 1, width + 4). soundcalc has no ZK model, so ZK enters only through those parameters:

| lane | regime | query | batching | commit (min round) | ALI | DEEP | total |
|---|---|---|---|---|---|---|---|
| L1 b16/q21/g22, non-ZK | UDR | 41 | 93 | 103 | 114 | 103 | 41 |
| L1 b16/q21/g22, **ZK** | UDR | 41 | **92** | **102** | 114 | **102** | 41 |
| L1 b16/q21/g22, non-ZK | JBR | 63 | 60 | 69 | 104 | 94 | 60 |
| L1 b16/q21/g22, **ZK** | JBR | 63 | **59** | **68** | 104 | **93** | **59** |
| L2 P b4/q43/g22, non-ZK | UDR | 51 | 93 | 103 | 113 | 101 | 51 |
| L2 P b4/q43/g22, **ZK** | UDR | 51 | **92** | **102** | 113 | **100** | 51 |
| L2 P b4/q43/g22, non-ZK | JBR | 63 | 68 | 77 | 107 | 95 | 63 |
| L2 P b4/q43/g22, **ZK** | JBR | 63 | **67** | **76** | 107 | **94** | 63 |

**ZK costs exactly one bit on every non-query term** (batching, every commit round, DEEP), in both regimes and both lanes, and nothing on the query term or ALI. That is slightly less than the hand estimate above: soundcalc rounds to whole bits and puts DEEP at −1, not −1.3 to −1.6. The one proven-regime total that moves is **L1 JBR, 60 → 59**, where batching is the binding term (it was already the binding term, one bit under the query phase, in issue #22). In the conjectured regime, the tightest non-query term therefore sits about **2–11 bits** above the query floor instead of 3–12. **It does not cross, but the margin narrows by one bit.**

Run: `scripts/rig run -- /usr/bin/time -l python3 run_soundcalc.py` (a driver that loads this TOML through soundcalc's own `zkVM.load_from_toml` and prints its summaries), **0.04 s wall, 13.0 MB peak**, exit 0. soundcalc imports the third-party `toml` package; the run used a three-line stand-in over the standard library's `tomllib` instead of installing it. A first attempt the same minute failed at that import before computing anything.

**Verdict: the ≥ 100-bit conjectured floor holds under ZK with Plonky3's example values; no query bump is needed.** The `make_config_with` assertion and `l2shape_lanes_are_at_the_floor` remain the code-level gates, and they are unchanged.

## 3. Zero knowledge: are Plonky3's example values enough?

**Salt, `SALT_ELEMS = 4`.**
- KoalaBear has `log2 p = 30.95`, so a leaf's salt carries **123.8 bits** of entropy. This is **≥ 100: it meets the floor.**
- It hides a leaf's contents from an adversary who can enumerate candidate contents. Low-entropy leaves are exactly the ones that matter here: note fields and bits of a key.
- The Keccak-256-class digest (collision ~128) is not the binding term.

**Trace randomization.** 2024/1037's hiding argument needs the number of evaluations the verifier learns of each masked polynomial to stay below its random degrees of freedom:
- The degrees of freedom are `h` random rows: L1 2^18; L2 2^18–2^20.
- The verifier learns 2 out-of-domain openings (`ζ`, `ζ·g`) plus one input opening per query per matrix: **23** for L1 (t = 21), **45** for L2 (t = 43). The FRI layers reveal arity-16 cosets of the *batched, separately masked* function, not the trace.
- The margin is more than 2^12×. **Meets it with room.**

**`NUM_RANDOM_CODEWORDS = 4` — re-derived from the paper (Haböck–Al Kindi, eprint 2024/1037, revision of 2025-02-20).**

The paper's zero-knowledge conditions (Theorems 4, 6, 8) are on three objects. **None of them is a count of random codewords.** Plonky3's quotient masking is the paper's §4.2 **Lagrange decomposition**: `q̂_i = q_i + v_{H_i}·t_i` for `i < d`, with the last chunk carrying the balancing term (eqs. 13–14; `get_quotient_ldes`). So the §4.2 bounds apply:

1. **The witness randomizer degree `h`** must satisfy `2·(e·n_F + n_D) ≤ h ≤ |H|` (eq. 17).
   - Here `e = 4` is the extension degree, `n_F = 1` is the out-of-domain point (its `g`-translate is the factor 2), and `n_D` is the FRI query count.
   - Plonky3 commits each trace at height `2|H|` with the second coset filled uniformly at random. That is `ŵ = w + v_H·r` with `r` uniform of degree `< |H|`, i.e. **`h = |H|`, the maximum**.
   - Needed: L1 `2·(4 + 21) = 50`; L2 `2·(4 + 43) = 94`. Have: `2^18`–`2^20`.
2. **The quotient randomizer degree `h_p`** must satisfy `n_F + n_D ≤ h_p` (eq. 16).
   - The `t_i` are drawn over the chunk domain, so `h_p` is of order `|H|`.
   - Needed: 22 (L1) and 44 (L2).
3. **The FRI batch mask** `R(X) ∈ F[X]^{<|H|+h−1}` (Protocol 2; Lemma 2 makes it a perfect isolator of the FRI transcript).
   - It is **one extension-field polynomial = `D` base-field columns**, which is the `+ D` part of Plonky3's randomization commitment (`num_random_codewords + D` wide, degree `< 2|H|`).

**So the paper imposes no minimum on `num_random_codewords`.** On its model, the four extra random columns Plonky3 appends to every committed matrix, and to the randomizer, are masking beyond what the proof needs. `4` meets every requirement the paper states, and so would a smaller value.

**Recommendation:** keep 4, the upstream value. It costs a few columns of bytes. Taking it below upstream would be an optimization on a proof we did not write, for a gain we have not measured.

> **Amended 2026-09-26: rc 4 → 0 on the T-net** (Larry's ruling on lab #742; built in re-genesis batch 2, lab #747; mainnet waits on the M13 audit).
>
> **Why the recommendation above changed.** It said two things: "a few columns of bytes" and "a gain we have not measured". **Both turned out to be false once measured.**
> - `num_random_codewords` widens **every quotient chunk** (D + rc, so 4 → 8 columns, which doubles the quotient LDE) and the randomizer commitment (rc + D), not only the trace.
> - The A5 phase table (lab PR #745's `zkpeak --phases`) shows all of it is resident through `open`, where the prover peaks: rc = 4 costs **≈ 1.25 GiB** of the P3 and L1 peaks.
> - It also costs **4,064 B** of the L1 wire (182,745 → 178,681 B) and 7,584 B per L2 proof.
>
> **Why the argument above still holds at rc = 0.** The three conditions it names are each independent of rc in the code:
> - `h = |H|` comes from the `w` interleaved random columns that `with_random_cols(w + 2·rc)` adds on top of rc;
> - the `t_i` cover all D quotient columns whatever the chunk width;
> - `R` is the randomizer's `+ D` columns, which remain at rc = 0.
>
> Soundcalc shows no term moving at whole bits (lab #742). Upstream Plonky3's own security accounting models rc as batched width only, and its unit tests use `hiding(0)`.
>
> **What changes in the claim: nothing, and the caveat stays.** The mapping of code to paper is still this document's reading, not a Plonky3 statement, and nobody outside has reviewed it. It is put to the M13 audit by name.
>
> The full analysis is qumbra-design `hiding-random-codewords-2026-09.md` (design PR #300). The pin is `rc_is_zero_and_no_random_openings_travel` in qlab-consensus, plus one hiding smoke test per L2 shape.

**What this rests on:** the mapping of Plonky3's code to the paper's objects:
- row interleaving ⇒ `h = |H|`;
- the `+ D` columns ⇒ `R`;
- the `t_i` domain ⇒ `h_p`.
That mapping is my reading of `hiding_pcs.rs` (commit, `get_quotient_ldes`, `get_opt_randomization_poly_commitment`), not a Plonky3 statement. The paper's result is honest-verifier ZK, which Fiat–Shamir lifts (as the paper notes).

**Randomness quality.** ChaCha20 with 256-bit OS seeds; independent streams per consumer; clones reseed. Plonky3's own ZK test reuses one `SmallRng` stream for both the MMCS and the PCS; ours does not.

**What ZK does not cover.** Hiding covers the witness *inside* the proof. It does not hide the public values: nullifiers, commitments, the anchor, the fee, the L2 surfaces. Nor does it hide anything a wallet reveals off-proof. Nor does it change proof size by instance: the dummy/real indistinguishability test runs under ZK.

## 4. Owed before the genesis is cut

1. ~~A soundcalc re-run with the ZK parameters~~ — **done** (§2): −1 bit on every non-query term.
2. ~~Confirm the role and minimum of `num_random_codewords`~~ — **settled on the paper** (§3): 2024/1037 has no such parameter; its three conditions (`h`, `h_p`, `R`) are met with margins of about 10^3–10^4×; 4 is kept as upstream surplus.
3. **The measured costs** (coordinator's rig, `qlab-bench zkpeak --case l1|p19|p`): prove time, peak footprint, and wire bytes. `WIRE_BYTES` is pinned from the l1 case.
