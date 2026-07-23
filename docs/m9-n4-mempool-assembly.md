# M9-N4 — mempool + block assembly (issue #51)

Wave-2 baton. New surface: `qlab-node` gains two consensus-facing duties the N1
skeleton left open — **mempool admission** and **block assembly** — plus the
**normative integer emission**. Boundary-clean: touches only `qlab-node/src`
(new `emission.rs` + `mempool.rs`, `lib.rs` re-exports, `Cargo.toml` +qlab-econ)
and a one-line `params_devnet` fee convergence. Zero contact with
qlab-bench / m4gate / qlab-p2p (parallel-safe vs N5/N6).

## What landed

| Piece | File | Binding rule |
|---|---|---|
| Coinbase emission | `emission.rs` | `coinbase(h) = S_atomic(h+1) − S_atomic(h)` over the frozen B2 curve (r0=50 QMB, d=8.237e-7, tail=1.22441; §6/§2), telescoping-exact; 65/15/20 split (§3); maturity 144 (§2) |
| Mempool admission | `mempool.rs` | fee == posted price (§4/§5); finalized in-window anchor (§4/§7); coinbase maturity (§2); cross-block + in-pool double-spend; injected proof verify |
| Block assembly | `mempool.rs` | two-median weight governor, frozen §6 constants; over-weight (> 2M) template refused; coinbase + split + fees |

Emission reuses `qlab-econ`'s closed-form `S(h)` (the same curve that produced
candidate B2, PR #36) — pinning the frozen constants directly rather than
re-deriving `d`/`tail` from targets, so the node and the design's supply-audit
anchor evaluate the *same* `S(h)`.

## Acceptance negatives (all present + green)

- **wrong-fee tx rejected** — `rejects_wrong_fee` (one bessel off) and
  `rejects_wrong_fee_even_for_a_different_bucket` (4×4 paying the 2×2 price).
- **over-weight template refused** — `over_weight_template_is_refused`
  (Σweight > 2·M ⇒ `AssemblyError::TemplateOverWeight`; a within-cap subset is
  accepted and, above the median, pays the quadratic penalty).
- **immature-coinbase spend rejected** — `rejects_immature_coinbase_spend_then_admits_after_maturity`
  (rejected at prospective height < created+144, admitted at == matures_at).

Plus: anchor-invalid, cross-block double-spend, in-pool double-spend, duplicate,
bad-proof; emission telescoping/non-negativity/split; frozen §6 weight params;
and an end-to-end `MemNode` integration (`tests/mempool_assembly.rs`) proving a
mempool-admitted tx set assembles into a body the node's `apply_block` accepts
(admission == block-validity, both directions).

## Decisions & reportable items (for the coordinator)

1. **Fee absolutes converged to FROZEN §5 (params_devnet).**
   `FEE_MARGINAL_UNITS` 5_000 → **500_000**, so `posted_fee()` returns the frozen
   §5 table exactly: 0.01 / 0.02 / 0.04 QMB (10⁶ / 2×10⁶ / 4×10⁶ bessel). The
   1/2/4 ratio is unchanged from the M6 placeholder; only the absolute scale was
   pinned. Endorsed by CLAUDE.md ("params_devnet placeholders should converge to
   [the frozen table]" — same act as the anchor-window fix on PR #45). **Safe
   across the workspace**: every consumer calls `posted_fee(bucket)` relatively,
   and the circuit-bound fee is decoupled from the public/posted fee (the demo
   records its circuit fee 1_000, not the posted fee), so all real-proof paths
   (demo, m6devnet, cbserver) stay green — verified.
   - *Known pre-existing boundary (not N4's to fix):* `TxPublic.fee` (public/
     posted) and the circuit-bound fee inside the proof are not cross-checked by
     `validate_body`. This decoupling predates N4 (it existed at 10_000 vs 1_000);
     converging the absolute did not create or widen it. Flagged for whoever owns
     the fee-in-proof binding.

2. **Weight long-window: node uses the frozen 100,000; devnet keeps 5,000.**
   The frozen §6 window is 100,000 blocks, but `params_devnet::WEIGHT_LONG_WINDOW`
   is deliberately 5,000 so the PR #46 load-harness sweep runs in bounded time.
   Rather than disturb the load harness, `qlab-node` defines
   `consensus_weight_params()` = the devnet defaults (min_weight 10 MB, 2×, 1.4×,
   st 50 — all already equal to frozen §6) **with `long_window` overridden to the
   frozen 100,000**. A test locks the whole frozen §6 set.

3. **Coinbase-maturity model (prototype policy boundary, documented).**
   Tokenomics §6: a coinbase note "carries public value at creation and enters
   the pool as an ordinary note after a maturity delay" (one-hop transparency).
   N4 enforces this at the node-policy layer it can actually see: assembly mints a
   deterministic coinbase-note commitment (`coinbase_note_commitment`, a
   `[devnet-placeholder]` domain-separated shape — the real note is `H(note)` over
   a tx-position-derived ρ), the node records it with its creation height, and a
   candidate tx **declares** the coinbase notes it consumes; admission requires
   each ≥ 144 blocks deep at the prospective height. Full in-tree / in-circuit
   maturity enforcement (a spend proving its input note is matured) is later
   node-state / circuit work — N4 binds the **policy and the constant (144)**, not
   the circuit.

## No protocol-spec deviations

Every constant traces to the frozen table (§2 emission, §3 split, §5 fees, §6
weight, §2 maturity) or protocol-spec §4/§6/§7. The `[devnet-placeholder]` items
(coinbase-note commitment shape, and the fee-in-proof binding boundary) bind the
*shape*, not a frozen value, and are flagged above.
