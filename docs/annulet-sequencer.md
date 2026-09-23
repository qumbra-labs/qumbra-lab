# Annulet sequencer — B2 build note (lab #708, PR #709)

B2 replaces proof-of-work with a signature rule on the Annulet form and produces blocks: one genesis-pinned sequencer seals every block, and followers run the same binary with production off. B1's chain form (`annulet-chain-form.md`) is the base.

## The trust model, stated

- **Finality is operator governance, not BFT.** A block is final on acceptance (Q4): `finalized_height = tip`, and genesis is final. With one signer and equivocation refused at ingest there is no competing branch, so there is nothing for a later finality to decide.
- **Withholding is a liveness failure only.** A sequencer that stops sealing, or seals and does not relay, stalls the chain; it cannot rewrite it. Nothing in B2 upgrades withholding to a safety property.
- **Equivocation** — a second validly sealed header at an occupied height — is refused at ingest, logged loudly (`EQUIVOCATION`), and kept as evidence (`NodeAdapter::equivocations`). Slashing waits for the sequencer committee (Phase 1).
- **The anchor age window** on Annulet is the L1 constant, 1,152 blocks — about 3.2 h at 10 s slots. Whether that is the right window for the L2 is **B6's call**; B2 only notes that with finality at the tip the window is measured from the tip.

## What landed

| piece | where |
|---|---|
| the seal: `SealedHeader` (153-B preimage ‖ 3,309-B ML-DSA-65 seal = 3,462 B), `SequencerKey`, `validate_sealed_header_annulet` | `qlab-devnet` `annulet.rs`, `validation.rs` |
| fork-choice weight 1 per Annulet block (cumulative work = height) | `qlab-devnet` `chain.rs` |
| slot parameters in genesis: `slot_secs = 10`, `max_empty_slots = 6` (Q5) | `qumbra-node` `annulet_genesis.rs` |
| the node's sealed apply, final on acceptance, L2 fee-tier mempool admission | `qlab-node` `node.rs`, `mempool.rs` |
| the log record: persist `WireRecord` variant 3 (additive; `FORMAT_VERSION` stays 3), `MemNode::open_annulet`, finality derived again at replay | `qlab-node` `persist.rs`, `node.rs` |
| sealed ingest, equivocation refusal, the producer step, the pending-seal map | `qlab-p2p` `adapter_annulet.rs` |
| the wire: `WireHeader`, `Header`/`Headers` at the 3,462-B unit, the Annulet `BlockAnnounce` frame, the net's tx wire on `Tx`/`BlockTxn` | `qlab-p2p` `codec.rs`, `compact.rs`, `node.rs` |
| `run`: `load_any`, producer iff `sequencer.key` in the data dir, the slot loop, the run-side Annulet arms | `qumbra-node` `main.rs`, `run.rs`, `run_annulet.rs` |

## Running a node on an Annulet genesis

- `run` loads the genesis through `load_any`. An Annulet genesis runs **only with `--rehearsal-verifier`** until B4 lands the L2 transaction verifier (the L1 verifier would refuse every L2 transaction); without the flag it is refused by name.
- **Role:** a `sequencer.key` file in the data dir (TOML, `seed_hex = "…"`, the committee-key convention) makes the node the producer. Its key must be the genesis `sequencer_key`, or `run` refuses to start. Without the file the node follows.
- **Refused by name on an Annulet genesis:** `committee_key_paths` (no committee), `mining = true` (production is the key file's), a wrong pinned genesis hash.
- **The slot rule:** at each `slot_secs` the producer seals when its pool is non-empty, and otherwise seals an empty block once `max_empty_slots` slots have passed empty. It does not seal while its state lags its header tip.

## The finality consumers and their Annulet arms

Every consumer of finality has a named decision on Annulet (the trace posted on lab #708):

- **`ChainView::finalized_height`** and **`CommitteeControl::finality_status`** read the fork-choice pointer on Annulet. Both used to read the committee tracker, which is never fed there — every telemetry surface would have shown a degraded, never-finalizing chain.
- Checkpoint votes are `Stale` before the tally; checkpoint fast-sync is `Ignored`.
- `run`: no checkpoint rounds, no `try_checkpoint`, no boundary checkpoint, no halt height.
- **Committee gauges:** `/metrics` emits the three `qumbra_committee_*` series with no sample. The served `/v1/telemetry` wire has a fixed layout, so it carries zeros ("no committee") rather than the "need 1 of 0" an empty roster's quorum rule would read.
- **The form names itself on the text surfaces** (ruled on lab #708), so those zeros and final-at-tip read as the form's: the `TELEMETRY` line ends `form=annulet finality=operator` (an L1 line is byte-identical), and `/metrics` carries `qumbra_chain_form{form="annulet",finality="operator"} 1`.

🔴 **Review checklist: any new consumer of finality must appear in the finality lock** — `run_annulet::tests::every_finality_surface_reads_final_at_the_tip_on_an_annulet_chain`, which drives 1,200 sealed blocks through a real `RunningNode` and asserts every finality-facing surface at once, with the same assertions shown failing on an L1 chain whose finality lags. A lexical lock cannot see a *missing* form decision; this test can.

## The wire seam B5 owns

The Annulet `BlockAnnounce` frame is served by B2 (the B1 owner moved by ruling): sealed header ‖ nonce ‖ no coinbase section ‖ short ids ‖ prefilled on the Annulet tx wire. **B5 owns the discovery payload width inside the transaction codec** (120 → 128 B) and changes only `encode_tx_annulet` / `decode_tx_annulet`; the frame inherits it with no edit.

## Goldens and how they were computed

| golden | value | computed by |
|---|---|---|
| fixture Annulet genesis hash (3,047 B; slot params added) | `a73f547d…ead2` (B1: `c0257d67…b19a`) | named run ×2, byte-identical |
| the fixture key's seal over B1's fixture header verifies | `true` (**load-bearing**) | named run; `the_seal_goldens` |
| signature / sealed-wire digests | `e02a1bd0…fc43` / `9ed2e2dc…8ee4` | named run + Python re-hash; **valid only while the crate's default signer is deterministic** |
| persist variant-3 record (3,745 B) | keccak `7c378193…6c68` | independent Python bincode encoder (synthetic seal) |
| v4 / v5 announce frames (301 B each) | hex literals | independent Python encoder — no L1 announce golden existed before B2 |
| Annulet announce frame (3,659 B) | hex literal | independent Python encoder (synthetic seal) |

The Python cross-checks cover Keccak and framing; no independent ML-DSA implementation verified the seal (an audit item, recorded on lab #708).

## Named gaps (not B2's, owned by name)

- **The L2 transaction verifier:** B4. Until then an Annulet node runs only with the rehearsal verifier.
- **`qumbra-node check`** (preflight) still loads an L1 genesis only; an Annulet preflight is B6's.
- **The form on the binary `/v1/telemetry` wire: B6.** The payload does not carry the form yet (ruled on lab #708: the bump is a fleet-visible L1 wire change and does not belong in B2). The recipe is the #212 append discipline: append a `form(u8)` tail **last** in `Telemetry::to_bytes`, so every earlier version's payload is an exact byte prefix; bump the shared `qlab_node::rpc::RPC_VERSION` (0x07 → 0x08); add a `FORM_SINCE_VERSION` gate in `decode_body`; add 0x07 to `READABLE_TELEMETRY_VERSIONS` so an opview reads un-rolled hosts; extend the per-version wire-order test; have `qumbra-opview` render the form. Until B6 no Annulet net serves `/v1/telemetry`.
- **Out-of-order Annulet bodies are not buffered:** a body that arrives before its parent is applied answers `Orphan` and is re-asked, where the L1 path buffers it. Enough for B2's sync; B6 may want the buffer.
- **Discovery of an Annulet transaction:** B5. **The registry-root binding of each surface:** B4. **Registry updates:** A2/B3.
