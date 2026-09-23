# Annulet chain form — B1 build note (lab #706, PR #707)

Build note, not paired (lab convention). This records what B1 put where, with the two items the coordinator asked to have on the record:
- (i) the per-site Annulet arm table;
- (ii) the persisted-bytes verdict.

Stage-0 plan and ruling: lab issue #706.

## What landed

| piece | where |
|---|---|
| `GenesisForm::Annulet` ↔ `format_version` 32; no name service | `qlab-devnet/src/forms.rs` |
| `HeaderExt` (`L1` / `Annulet{l1_anchor_height, l1_anchor_root, registry_root}`), `BlockHeader.ext` | `qlab-devnet/src/annulet.rs`, `header.rs` |
| 153-B Annulet header preimage (version `0x20`, u48 height, timestamp, anchor, registry root, body commitment, `00 00`); signing message `qumbra:annulet:header:v1 ‖ preimage` | `header.rs` |
| `L2ShapeTag` (0x01 S / 0x02 P), `L2Surface` codec (33 / 55 B), `L2FeeTable` | `annulet.rs` |
| `TxEntry.l2` (rider discipline, absent = `[0x00]`) | `body.rs` |
| Annulet body commitment (`qumbra:body:annulet:v1`), genesis body commitment + `GenesisNote`, `validate_body_annulet` | `annulet.rs` |
| L1 refusals: `BodyError::L2SurfaceOnL1`, `encode_tx` asserts no surface, the L1 store mirrors assert `ext == NONE` / `l2` absent | `body.rs`, `qlab-p2p/src/codec.rs`, `qlab-node/src/store.rs` |
| Annulet header + tx wire codecs | `qlab-p2p/src/codec.rs` |
| `AnnuletGenesisFile`, `load_any`, `registry_root_of`, fixture | `qumbra-node/src/annulet_genesis.rs` |
| L1 loader refuses a leading 32 by name (`AnnuletGenesisNotServed`, naming B2). This is also `run`'s refusal. | `qumbra-node/src/genesis.rs` |
| Exhaustiveness lock (no catch-all over `GenesisForm`, no `==`/`!=` against a variant) | `qumbra-node/tests/genesis_form_exhaustive.rs` |
| `L2ShapeTag` ↔ `qlab_l2::Shape` cross-lock | `qumbra-node/tests/annulet_shape_crosslock.rs` |

## (i) The Annulet arm at every form site

"Refused" means a typed error or panic that names the owning milestone. It is never `unreachable!()`, never `_ =>`, never a comparison.

| site | Annulet arm | kind |
|---|---|---|
| `forms.rs` `from_/genesis_format_version` | 32 ↔ Annulet | rule |
| `forms.rs` `name_boundary`, `rider_admit_boundary` | `None`, `None` (riders never active) | rule |
| `header.rs` `preimage_for` | the 153-B form; refuses `L1` ext, non-zero difficulty/nonce, height > u48 | rule |
| `header.rs` `genesis_for`, `child_of_for` | panic, naming `genesis_annulet` / `child_of_annulet` | refusal (local input) |
| `pow.rs` `hash_to_work_value_for` / `satisfies_target_for` | `u64::MAX` / **never satisfies** (difficulty 0 included) | rule |
| `qlab-node` `emission::coinbase_for` | 0 | rule |
| `qlab-node` `coinbase::coinbase_note_parts_for` | `None` | rule |
| `qlab-node` `supply` pins / straddle / expected row | `&[]` / no straddle / 0 | rule |
| `qlab-node` `node.rs` stored binding, `validate` ×2 | `NodeError::FormNotServed { owner: "B2/B3" }` | refusal |
| `qlab-node` `node.rs` `from_genesis` | panic naming B2/B3 (locally-built input) | refusal |
| `qlab-p2p` codec `header_wire_len`, `decode_header` | 153, the Annulet decoder | rule |
| `qlab-p2p` compact `encode_announce` / `decode_announce` | panic / `DecodeError::FormNotServed { owner: "B5" }`, before reading a byte | refusal |
| `qlab-p2p` adapter payee cap, payee schedule | `Err` naming B2 | refusal |
| `qlab-p2p` adapter `assemble_on_parent` | `None` (no candidate; mining never starts on an Annulet net) | refusal |
| `qlab-p2p` adapter body validation | `IngestOutcome::Ignored(ANNULET_NOT_SERVED_REASON)`, not the sender's fault | refusal |
| `qlab-p2p` node `Version` net id / `net_refusal` | carries and requires the net id, like T2 | rule |
| `qumbra-node` `mine_rpc` cap / `form_token` | `Err` / `"annulet"` | refusal / label |
| `qumbra-pool` `submit_block`, `payee_cap`, `assemble_coinbase`, `blob_with_extranonce`, `serves_stock_xmrig` | `Err` / 0 / `NoCoinbaseOnForm` / `NotMinable` / `false` | refusal |
| `qumbra-wallet` `net_name` | `"annulet"` | label |

The three silent comparisons found at stage 0 are now exhaustive matches: `supply.rs` (straddle), `qlab-p2p/src/node.rs` (`net_refusal`), `qumbra-pool/src/template.rs` (`serves_stock_xmrig`). The lock test scanned 36 form-match blocks at commit time; its sentinel is ≥ 30.

## (ii) Persisted-bytes verdict

**No L1 on-disk byte moved, and `FORMAT_VERSION` stays 3.**
- `BlockHeader` and `TxEntry` derive no serde.
- What reaches disk are the hand-written mirrors `StoredHeader` and `StoredTx`, which B1 did not edit.
- The log writes rider-free blocks through the frozen `LegacyStoredBlock`.

The gate is a test: `persist::tests::a_v4_block_reaches_disk_byte_identically_to_the_frozen_layout`.
- It builds a v4 block from a live `BlockHeader` + `BlockBody`, so the path crosses the mirrors B1 touched.
- It writes the block through the real `append_record` and compares the raw `blocks.log` bytes (362 B) to a hex literal computed by a Python bincode encoder.
- The mirrors now **assert** `ext == NONE` and `l2` absent, rather than silently dropping them.

## Goldens and how they were computed

| golden | value | computed by |
|---|---|---|
| Annulet header id (fixture) | `1bc6fce1…8b97` | named run + independent Python Keccak-256 |
| Annulet signing-message digest | `2d00955c…c9e3` | named run + Python |
| Annulet empty-body commitment | `75dc7b56…52be` | named run + Python |
| Annulet empty genesis-body commitment | `3ad958aa…d253` | named run + Python |
| fixture Annulet genesis hash (3,031 B file) | `c0257d67…b19a` | named run ×2, byte-identical |
| on-disk v4 block record | 362 B literal | Python bincode encoder |

The local runs (both named by the #706 ruling; no proving):
```
/usr/bin/time -l cargo run --release -p qlab-devnet --example annulet_goldens          # 0.40 s real, 1.47 MB peak footprint
/usr/bin/time -l cargo run --release -p qumbra-node --example annulet_fixture_genesis  # ×2: 0.39 s / 0.11 s real, 2.64 MB peak footprint
```
The figures are for the `cargo → example` process tree with the examples already built.

`cargo check --target wasm32-unknown-unknown -p qumbra-ffi` (with `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`) passes. `cargo tree` shows no `qlab-l2`, `qlab-consensus`, `p3-uni-stark` or `rayon` in that graph.

## Named gaps (not B1's, owned by name)

- **The parent-registry-root binding** of each transaction's surface (Q6): B4. The codec carries the value; `validate_body_annulet` does not read the chain.
- **The discovery group of an Annulet transaction** (`ANNULET_DISCOVERY_RULE_OWNER = "B5"`). It is committed in the Annulet body preimage but not judged: the L1 codec frames 120-B payloads, the L2's are 128-B.
- **The sequencer signature**: its carriage (block, wire, log) and verification are B2's. The header's signing message and id are fixed here.
- **Applying the genesis notes and registry leaves** to chain state: B3 (P13).
- **The Annulet stored form** (log / snapshot): B2/B3. The L1 mirrors refuse Annulet values.
- **`registry_root_of` is B3's contract fixed early**: depth 16, empty slot = zero digest, `qlab-air` Merkle node. B3's `RegistryTree` must reproduce it.
- **A cross-wire misparse risk that is fenced but not closed.** An Annulet tx wire fed to the **L1** `decode_tx` would read its surface section as a name-rider section. It is then refused at validation (rider decode or boundary), but by the wrong name. The two nets are separated earlier, because an Annulet node sends a net id that a v4 node's reject-trailing `Version` decoder refuses.
