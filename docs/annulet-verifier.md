# Annulet transaction verifier — B4 build note (lab #712)

B4 makes the node verify every Annulet transaction's proof against its **declared** public surface, as `ConsensusVerifier` does for the L1. It also adds the block-level rules that need no prover: the parent-registry-root binding, and outstanding public supply that never goes negative. Base: B1 (`annulet-chain-form.md`), B2 (`annulet-sequencer.md`), B3 (`annulet-registry.md`).

## The verifier

`qumbra_node::verifier::L2Verifier` runs over `qlab_l2`'s canonical witness-free AIRs, and `make_config_l2()` is the only config site. The steps, each refusal by name (`L2VerifyError`):

1. **The surface** must be present and canonical: `NoSurface` means an L1 transaction; otherwise `SurfaceMalformed`.
2. **The bucket** must be 2×2 (`NotTwoByTwo`).
3. **A strict decode**: bincode fixint (what `bincode::serialize` writes), reject-trailing, and a limit equal to the input length, so a hostile length prefix cannot allocate (`ProofDecode`).
4. **The structure the config implies** (`ProofShape{what, got, want}`): `degree_bits == LOG_HEIGHT_{S,P}`, `num_queries` query proofs, a `2^log_final_poly_len` final polynomial.
   - Every number is read from `qlab_l2`. **There is no wire-byte literal:** the lane was provisional (lab #704) and is frozen at b4/q45 since lab #785 F5-2; the numbers are still read from the config, so the lane keeps one source.
   - This step is also what separates an L1 proof from an L2 one: both decode as `Proof<Config>`, and only their structure differs.
5. **`verify_s` / `verify_p`** run against PVs rebuilt from the declared surface (`ProofInvalid`). For shape P, each `VPublicTerm {redeem, amount, asset}` becomes `VPublic{redeem, amount}` plus the revealed asset.

**The default:** `select_verifier(rehearsal, form, l2_auth)`.
- On an Annulet genesis the real `L2Verifier` is the default. B2's rehearsal-only interim is retired: M10-T0-4's rule, real verifier before any public net.
- On a Candidate A Annulet genesis (`L2AuthForm::CandidateA`, format 33) it is `L2VerifierV2` (lab #896 E3): the v2 shapes, with each auth-section slot's leaf appended to the PVs. Each verifier refuses the other version's transactions by name (`AuthOnV1Net`, `AuthMissing`); a section that does not decode for the shape is `AuthMalformed`, before the proof is read.
- On a format-34 genesis (`L2AuthForm::CandidateAV3`, lab #937) it is `L2VerifierV3`: S and P at the **v3** shapes (three output commitments, `cm3` appended after v2's PVs; `qlab_l2::v3::verify_{s,p}_u32`), R at v2. The S/P arity is the axis's — 3 nullifiers and 2 commitments on formats 32/33, 3 and 3 on format 34 — in the verifier (`WrongArity`), the body rule and the mempool (`check_l2_arity`, `BodyError::L2WrongArity`). The other format's well-formed S/P spend is refused **by name**, from its declared arity and before the proof is read (S v2 and S v3 are both 2^20, so the proof's height cannot tell them apart): `V2SpendOnV3Net` / `V3SpendOnV2Net` in the verifier, `L2V2SpendOnV3Net` / `L2V3SpendOnV2Net` in the body rule and the pool.
- `--rehearsal-verifier` stays a loud ⚠️ opt-in on every form.
- `ConsensusVerifier` refuses any transaction carrying an L2 surface.

## Block and mempool rules (no prover)

- **Registry root:** a surface's `registry_root` must be the **parent** header's (the §5 ruling). `validate_body_annulet` checks it against the header's own root, which B2's header rule has just proved equal to the parent's (`BodyError::L2RegistryRootStale`). The mempool checks it against the tip's root.
- **Supply delta:** `qlab_devnet::annulet::annulet_supply_delta(body)` is the signed per-asset sum of every surface's `vPublic` (mint +, redeem −, i128, zero nets dropped). It is a pure function of committed data, because the body commitment binds every surface. So it is derived, never stored twice: there is no header field and no body section.
- **Outstanding supply is chain state.** The node keeps the running per-asset Σ of those deltas and records each block's delta for D1. It is **recomputed, never persisted**: folded in `apply_state` (which every replay and rewind runs), and rebuilt at `open_annulet` from the held main chain, which covers the snapshot prefix that skips `apply_state`.
- **Never negative:** a block whose redeems would take an asset below zero is refused before any mutation (`NodeError::SupplyUnderflow`). Issuance is public arithmetic, and it cannot be negative.
- **Mempool redeems:** the pool refuses a redeem exceeding the outstanding supply net of the redeems already pooled (`MempoolError::RedeemExceedsOutstanding`). Pooled mints are not counted: assembly may leave a mint out, and the sequencer's own block would then be refused.

## Tests and cost

- **Real S and P proves**, one each over `qlab_l2`'s fixtures, shared through `OnceLock` (≈ 10 s each on the Graviton lane; P peaks ≈ 15 GB as W3 measured).
- **The L1 tests share one M3 prove** in place of the three they each ran before, which funds most of the above.
- **Covered:**
  - accept S and P;
  - tampered fee, nullifier, registry root and vPublic are refused;
  - an S proof declared as P is refused by structure;
  - strict decode: garbage, a trailing byte, a truncation;
  - the L1/L2 separation both ways;
  - the vPublic → PV mapping, without a prove;
  - the supply rule, restart recompute, and the mempool rules.

## Named gaps

- **A proved mint/redeem.** The P fixture has no `vPublic`, so the non-zero mapping is unit-tested against `pv_vec_p`, not proved. An issuer-authorised P witness is C-track (C3) material.
- **The supply surface D1 serves:** D1. The node keeps the record.
- **Registry-root reconcile for pooled transactions:** the registry is immutable until A2, so a pooled surface cannot go stale before then. A2 must add the reconcile when it adds updates.
