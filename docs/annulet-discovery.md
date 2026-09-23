# Annulet discovery — B5 build note (lab #714)

B5 gives Annulet transactions their discovery group at the L2 width: 128-B committed payloads (A1's `L2_PAYLOAD_LEN` = the 112-B `L2Note` plaintext + a 16-B tag). It validates them, serves them by projection, and opens them on the wallet side. The genesis notes get their own served projection. Base: B1–B4 (`annulet-chain-form.md`, `annulet-sequencer.md`, `annulet-registry.md`, `annulet-verifier.md`).

## Where the width lives (two corrected premises)

- **Not in the transaction codec.** The tx wire carries the discovery group as opaque `varint len ‖ bytes`. B2's note said B5 would change `encode_tx_annulet`; it did not need to, and that comment is corrected.
- **Not on `/v1/compact`.** That route serves the committed region's `group_contents` **prefix** (the #188 (a) relocation), whose framing has no width. The payloads ride `/v1/block/{h}/tx/{i}/full`, which frames each one with its own length. **No served wire changed.**
- **The width is the committed-region codec's.** `qlab_note::compact::{encode,decode}_committed_discovery_with_width` and `committed_payloads_per_recipient_with_width`; the width-free functions are their 120-B instances, so every L1 byte is unchanged.
- **One selection point:** `GenesisForm::discovery_payload_len()` (V4|V5 → 120, Annulet → 128).

## The rules

- **Body and mempool:** `check_tx_discovery_annulet` applies the L1's §4 rules at 128 B: decode exactly, re-encode to itself, and describe exactly the declared commitments (the shared `check_discovery_binds`). `validate_body_annulet` runs it, and the mempool calls `check_tx_discovery_for(form, …)`, so pool and block cannot disagree.
- **Rule (i): genesis payloads are `GenesisPlaintext`**, the note plaintext followed by a zero tag, **by construction**. The type is named so a genesis payload cannot be mistaken for an encrypted entry. This is safe only because the Phase-0 fee-unit stock goes to a public faucet `rkm`, and spending still needs the faucet's `nk`. `AnnuletGenesisFile::verify` refuses a genesis note whose payload is not a `GenesisPlaintext` opening to its commitment.
- **Rule (ii): every output from height 1 on carries a full encrypted entry.** A zero-tag payload in a non-genesis body is refused by name (`BodyError::GenesisPlaintextInBody`). An honest AEAD tag is all zeros with probability 2⁻¹²⁸.

## Serving

- **`/v1/compact` and `/full`.** `BlockDiscovery` takes its payload width from the block itself: `StoredBlock::annulet` is present exactly on Annulet blocks. Annulet bodies are therefore served **by projection**, with no re-encoding.
- **`GET /v1/genesis/notes`** (Annulet only; an L1 node refuses it by name with 400). It is a projection of the genesis file:
  ```text
  ver(u8 = 1) ‖ genesis_hash(32) ‖ n(u32 LE) ‖ [cm(32) ‖ payload(128)]×n
  ```
  - The body names the genesis file it projects.
  - The decoder (`qlab_cbserver::registry::decode_genesis_notes`) refuses a payload that is not a genesis plaintext.
  - `/v1/compact` at height 0 stays **groupless**. A genesis note has no recipient bundle (no ML-KEM ciphertext, no detection tag), so it cannot be detected through the compact wire and must not pretend to be. Its owner, the faucet, reads it from this route.

## The wallet side

- `qlab_note::scan` is **generic over the note plaintext** (`NotePlaintext`, implemented by `Note` and `L2Note`): one encryptor and one scanner for both forms. `encrypt_to_recipient` / `scan` keep their L1 signatures.
- `qlab_cbserver::client::open_served_l2(dk, bundle, payloads)` opens a served Annulet output, with the detection, the AEAD and the commitment recompute all the L1's. The asset-aware wallet store and the multi-block scan are C1's; this is the decode C1 builds on.

## Goldens

| golden | value | computed by |
|---|---|---|
| Annulet committed region (1 recipient, 2 entries, 2 × 128-B payloads) | 1,428 B, keccak `8f28ace3…5987` | independent Python encoder |
| the served prefix at either width | the same 1,172 B | asserted in the same test |
| L1 `golden_bytes_lock_the_framing`, `golden_body_commitment_bytes` | unmoved | the L1 tests themselves |
| fixture genesis hash | unmoved (`GenesisPlaintext::of` builds the same bytes) | B2/B3's pin |

## The done-when test

`qumbra-node/tests/annulet_discovery.rs`:
- A producer on the fixture genesis admits a transaction whose two outputs are really encrypted to a wallet key at 128 B, and seals it.
- Over HTTP, `/v1/compact` (height 0 groupless) and `/full` are fetched, and `open_served_l2` opens both notes, whose commitments are the served ones. A stranger's key opens none.
- `/v1/genesis/notes` serves the fixture's notes as `GenesisPlaintext`s under the genesis hash.
- No proves.

## Named gaps

- **C1:** the asset-aware wallet store and scan over many blocks.
- **B6:** the faucet reading `/v1/genesis/notes`, and whether a real devnet genesis keeps its stock as plaintext (rule (i) says it may, by name).
