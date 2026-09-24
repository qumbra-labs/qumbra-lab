# Annulet registry state — B3 build note (lab #710)

B3 makes the asset registry chain state: a depth-16 Merkle tree of `AREG` leaves whose root is in every Annulet header (B1), bound to what the node holds, persisted beside the commitment tree, and served to wallets. It also applies the Annulet genesis notes to the commitment tree (B1's P13, ruled into B3). The base is B1's chain form (`annulet-chain-form.md`) and B2's sequencer (`annulet-sequencer.md`).

**Immutable after genesis until A2.** Runtime registry updates arrive with shape R. Until then the only update seam, `RegistryTree::apply_update`, answers `RegistryError::UpdatesArriveWithA2`, and nothing calls it.

*Update 2026-09-24 (A2, lab #724):* shape R, the registry-write circuit, has landed (`qlab-air::l2r`, `docs/l2-shape-v1.md` §5). The node does not apply R transactions until **B3b**, so the seam above still refuses. A2 also enforces the registry invariant when genesis loads (`RegistryTree::check_invariant`, `RegistryError::SlotAssetMismatch`). R enforces the same invariant on every write.

## What landed

| piece | where |
|---|---|
| `RegistryTree`: sparse, depth 16, keyed by asset id; a **sibling** of `CommitmentTree`, reusing its node hash and zero ladder; the witness is the circuit's own `RegistryWitness` | `qlab-cbserver` `registry.rs` |
| the served wire: root and opening bodies, version byte first, each carrying the root it was computed against; no path bits (derived from the asset id) | `qlab-cbserver` `registry.rs` |
| B1's `registry_root_of` delegates to the tree; the unchanged fixture genesis hash pin is the byte-identity proof | `qumbra-node` `annulet_genesis.rs` |
| `RegistryStore` + `MemRegistryStore` + the `registry.bin` sidecar (`names.bin` pattern) | `qlab-node` `registry_store.rs` |
| the binding `header.registry_root == store root`, at genesis load and on every applied block (sealed apply and replay); `NodeError::RegistryRootMismatch` / `RegistryGenesis` | `qlab-node` `node.rs` |
| the genesis notes appended at height 0 through the same append a block's outputs take | `qlab-node` `node.rs` |
| `GET /v1/registry/root`, `GET /v1/registry/{asset}` (Annulet only; an L1 node refuses by name) | `qumbra-node` `discovery_server.rs`, `run.rs` |

## Why a sibling tree, not `MerkleTree<const D>`

The commitment tree is an append-only frontier over sequential positions. The registry is sparse, keyed by asset id, and (from A2) replaced in place. The commitment tree's witness type is fixed at depth 32 inside `qlab-air`, a circuit crate. The two share only the node hash and the empty leaf, and the registry reuses both (`tree::zeros()[..=16]`, `hash_node`), so `CommitmentTree` and its depth-32 goldens are untouched by construction.

## The served wire

```text
GET /v1/registry/root     →  ver(u8 = 1) ‖ height(u64 LE) ‖ root(32)
GET /v1/registry/{asset}  →  ver ‖ height ‖ root(32) ‖ leaf(15 × u64 LE) ‖ 16 × sibling(32)
GET /v1/registry/slot/{asset}  →  ver ‖ height ‖ root(32) ‖ slot(u16 LE) ‖ occupied(u8 0/1) ‖ leaf(15 × u64 LE, zero when empty) ‖ 16 × sibling(32)   (676 B, B3b)
```

- Digests are lane-major little-endian (the node's `h32`). The leaf lanes are `RegistryLeaf::state()[0..15]`.
- **Every answer names the root it was computed against.** A wallet binds its transaction to a header's registry root (B4's rule), so it must know which root an opening matches.
- **Path bits do not travel.** An opening is for position `asset`, so the decoder derives them from the asset id rather than trusting a second copy.
- The asset id is canonical decimal below 65,536 (400 otherwise). An unregistered asset gets a named 404 on `/v1/registry/{asset}`. On an L1 node every registry route refuses by name with 400.
- **The slot route answers every slot** (B3b, lab #728 Q5): a registration proves against an *empty* slot, which `/v1/registry/{asset}` 404s. An empty slot's leaf digest is zero; the decoder refuses an occupancy byte other than 0/1, an empty slot carrying a non-zero lane, and an occupied slot whose leaf is of another asset, each by name. A pure route addition: no `RPC_VERSION` bump.
- **The served tree moves with registry writes** (B3b): the run loop re-projects it at every new tip, so the `height` is the applied tip the root holds at.
- The codec lives in `qlab-cbserver::registry`, so the wallet side (C1) decodes with the same code.

## Persistence

`registry.bin` is a versioned bincode sidecar written with tmp + rename, at open and with every snapshot, carrying the height it was captured at. It is not part of the block log: `persist::FORMAT_VERSION` stays 3, and B1's 362-B persisted-bytes gate is untouched. **The registry is chain state, the sidecar a cache** (B3b, lab #728 Q3): every resume path derives the registry from the log — full replay through `apply_state`, a snapshot resume by re-folding the held main chain's writes over the genesis registry before its tail replays — and the sidecar is compared against that derivation. One that disagrees or cannot be read is rewritten from the chain and the node says so (a `REGISTRY` line). It is never trusted.

## The genesis notes (B1 P13)

- The notes are appended at height 0, in genesis order, through `append_commitment` / `record_root_at`, the append every block's outputs take. There is no special-case insert.
- The genesis anchor is the tree over the notes, and block 1 anchors on it.
- The notes spend nothing, so there are no nullifiers. Their payloads are served on `GET /v1/genesis/notes` (B5, `annulet-discovery.md`); `/v1/compact` at height 0 is groupless.
- The genesis file and its hash do not move: the header binds the notes' body commitment, not the tree root.
- Found on the way: `restore_from_snapshot` appended the snapshot's commitments onto a tree that already held the genesis notes. It now appends only what follows the held prefix.

## Registry writes (B3b, lab #728)

- **One write per block, carried whole.** Shape R's 185-B surface is `0x03 ‖ old_root ‖ new_root ‖ the new leaf's 15 lanes`. The body rule allows at most one R per block; the header's `registry_root` is the root *after* the block (the write's `new_root`, or the parent's when nothing is written); every surface in the block binds the root *before* it.
- **The node writes the leaf it was shown.** `apply_state` computes the registry after the block before any mutation: the write must be proven against this node's root (`RegistryWriteNotOnParent`), writing its leaf must reach the declared root (`RegistryWriteRootMismatch`), the slot must be writable (`RegistryWrite` — asset 0 is pinned), and the header must carry the result (`RegistryRootMismatch`). Each is refused by name with state untouched. A cheap parent check runs before proofs are verified.
- **The pool admits only a write that will apply**, and one at a time: a write whose leaf does not reach its root is `RegistryWriteInvalid`, a second write is `RegistryWriteAlreadyPooled`. When a write lands, every pooled surface still bound to the old root is evicted. (Pooling a write that cannot apply would fail the producer's own block every slot, with nothing to evict it.)
- **The producer** sets the header root from the template's write.
- **Genesis supply** (Q7): the genesis notes' issuance is outstanding from height 0, so a redeem of genesis supply is not an underflow. A genesis note that does not open its commitment is refused (`GenesisIssuance`).
- **Q6, the genesis-file invariant, is a demonstration:** a genesis registry record has no slot field. It is placed at its own asset lane, so "asset 9's leaf at slot 10" cannot be written. The nearest expressible attempt, a repeated asset, is refused by `verify` (`a_genesis_registry_record_can_only_sit_at_its_own_slot`).

## Goldens and how they were computed

| golden | value | computed by |
|---|---|---|
| fixture Annulet genesis hash (unchanged in B3) | `a73f547d…ead2` | B2's pin; unchanged across the delegation, so it proves byte-identity. *(B3b re-pinned it to `85dd805d…6cce`, 3,055 B, when `fee_tier_r` joined `AnnuletParams`; devnet `831de12f…e9ef` → `00c70e55…7e03`, 5,238 B. Named run ×2 each, byte-identical.)* |
| registry root body (41 B) | hex literal | independent Python encoder over synthetic digests |
| registry opening body (673 B) | hex literal | independent Python encoder over synthetic digests |
| commitment-tree root over leaves `[1;32], [2;32], [3;32]` | `b358f03f…2bae` | independent Python Keccak-f[1600]: self-checked against Keccak-256(""), and its empty tree reproduces `qlab-cbserver`'s existing `27ae5ba0…d757`. *(B3b: pinned on the tree directly. The node test's genesis notes are real plaintexts now — the node seeds supply from them — so the genesis anchor is asserted equal to the tree over their commitments in order.)* |

No cargo run was needed; there were no local runs in B3.

## The done-when test

`qumbra-node/tests/annulet_registry_prove.rs` runs two in-process Annulet nodes on two test genesis files, serving `/v1/registry/*` over HTTP.
- Genesis A registers asset 0, a Cloaked 5 and a Hybrid 7. The fixture genesis cannot serve this test: its asset 7 is Hybrid, and shape S opens Cloaked leaves only.
- A shape-S spend of assets 0 and 5 takes genesis A's **served** leaves, openings and root, proves with `qlab_l2::prove_s`, and verifies with `verify_s`.
- The same proof, with genesis B's served root in the registry-root public values, is refused.
- **One real prove (~10 s on the lane).**

## Named gaps (owned by name)

- **Runtime registry updates:** landed in B3b (shape R; lab #728). **The registry-root freshness rule for a transaction** (the parent header's root): B4.
- **Genesis-note serving:** landed in B5 (`/v1/genesis/notes`).
- No live net has served the registry routes yet; B6 is the first.
