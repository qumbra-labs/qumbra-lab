# qlab-cbserver — compact-block reference server + light-client scan flow (plan)

Implements **wallet-interop-spec.md §2** (ecosystem phase-1's "light-client server
reference") against the ratified **note-discovery.md §2** wire. New isolated crate
`qlab-cbserver`; strictly additive to the workspace (the only shared-file edit is
adding the crate to `[workspace].members`).

This crate is the **reference implementation** of §2's compact-block protocol: its
bytes *are* the spec's meaning from here on (per the task brief). The compact-group
framing is golden-locked; where §2 leaves a wrapper/format detail to the reference,
this doc records the choice.

## Decisions on record

### Server crate choice (bench discipline: record choice + version)
- **`tiny_http` = 0.12.0** — the minimal maintained blocking HTTP/1.1 server crate
  (no async runtime, no tokio). Chosen over axum/hyper (async, heavyweight) because a
  localhost reference server needs three blocking `GET` handlers and nothing more.
  Transitive deps (`ascii`, `httparse`, `chunked_transfer`) already present in the
  cargo cache. Pinned exactly (`=0.12.0`) per bench discipline #1.
- HTTP client for the light-client flow: **no crate** — a ~40-line std `TcpStream`
  HTTP/1.1 GET is enough and keeps the client dependency-free (we control both ends,
  localhost, fixed response shapes). Recorded here rather than pulling `ureq`/`reqwest`.

### §2 compact-group framing (FROZEN — golden-locked in `codec.rs`)
Exactly as the spec's §2 table. All integers little-endian; a format version byte
leads every response.

Per-tx compact group:
```
tx_index      : varint (unsigned LEB128, little-endian base-128)
n_recipients  : u8
  per recipient:
    ml_kem_ct : 1088 bytes            (shared per (tx, recipient) — the amortization)
    n_outputs : u8
      per output:
        cm       : 32 bytes
        tag      : 8 bytes
        clue_len : u8  (= 0 at v1)
        clue     : clue_len bytes  (= 0 bytes at v1)
```
- **varint = unsigned LEB128.** §2 says "tx_index (varint)" + "all integers
  little-endian"; LEB128 is *the* little-endian byte-order varint. Locked as the
  reference meaning of "varint".
- **clue framing.** §2 writes `clue_len (u8=0) ‖ clue (0 B)` (a length-prefixed clue).
  qlab-note's `CompactEntry` serializes its `ClueSlot::Empty` as a single `0x00` byte.
  For the empty (v1) clue these are **byte-identical** (`0x00` + 0 bytes = one `0x00`),
  so a per-output = `cm ‖ tag ‖ 0x00` = qlab-note's `CompactEntry::to_bytes()`. A test
  asserts this equivalence. The length-prefix reading is the forward-compatible one (a
  clue-unaware client skips `clue_len` bytes) and is what this reference adopts.

Response wrapper (this reference's framing around the frozen groups — `/v1/compact`):
```
version   : u8 (= 0x01)
n_blocks  : varint
  per block:
    height   : varint
    n_groups : varint
      per group : <compact group above>
```
`version`/`n_blocks`/`height`/`n_groups` are wrapper fields §2 does not itemize (§2
only fixes the per-tx group). Recorded as reference choices; version byte 0x01.

### `/v1/block/<height>/tx/<index>/full`
Returns the full-fetch payload for one tx: `version(0x01) ‖ n_recipients(u8) ‖
[per recipient: n_payloads(u8) ‖ [payload_len(varint) ‖ payload_bytes]]`. Payloads are
the qlab-note AEAD ciphertexts (encrypted note plaintext+memo), index-aligned with the
compact entries. The compact stream carries cm/tag/ct; the full fetch carries the AEAD
payloads a wallet pulls **only for matched notes**.

### `/v1/tree/frontier?at=<height>`  (spec O5 — flagged)
§2 says the format is "the qlab-air frontier serialization, versioned". **qlab-air has
no frontier serialization yet** (spec O5: "frontier-serialization freeze follows
qlab-air's format when the wallet-era light-client work lands" — that is *this* work).
So this crate proposes the reference frontier format, built on qlab-air's exact
consensus node hash (`qlab_air::reference::merkle_node_state`, `MERKLE_DEPTH = 32`):
```
version    : u8 (= 0x01)
depth      : u8 (= 32)
n_leaves   : varint
  per level 0..depth: present(u8 0|1) ‖ node(32 B if present)
```
This is a **reference proposal**, not a frozen golden format (unlike the compact-group
framing) — O5 remains a design-side freeze item. Round-trip + root-reconstruction are
tested against the devnet tree.

## Data source
Compose `qlab-devnet` (real block/header/chain types) + `qlab-note` (real ML-KEM-768
encap + ChaCha20-Poly1305 AEAD + the ratified cm) into a pre-generated, reused chain:
per block, several txs, each tx one or more recipient bundles (some 1-of-1, some
2-of-1 to exercise amortization), a known "our wallet" keypair planted in a subset so
the scan flow has real matches. Note commitments feed the depth-32 tree for the
frontier endpoint. Proofs are opaque placeholders — the compact-block layer serves
*note-discovery* artifacts, orthogonal to proof verification (documented; not a gap).

## Trust posture (Tor OUT of scope — documented)
Per §2's normative note: the server serves consensus data verbatim, cannot forge
(cm/tag client-recomputed) nor decrypt. It DOES observe requester IP / height ranges /
full-fetch pattern (the fetch-after-match side channel, FO-skip §4b). This reference
serves **localhost only, no external network** — Tor integration is explicitly out of
scope. The client implements the normative **decoy over-fetch** mitigation (≥1
randomized decoy full-fetch per matched fetch) behind a flag.

## Deliverables → files
1. `codec.rs` — §2 framing encode/decode + golden bytes.
2. `tree.rs` — depth-32 commitment tree + frontier + serialization.
3. `data.rs` — devnet+note data source (pre-generate once).
4. `server.rs` — tiny_http, three endpoints, in-memory store.
5. `client.rs` — light-client scan flow + decoy hook.
6. `src/bin/cbreport.rs` — measured report driver → `docs/cbserver-run{1,2}.md`.

## Hard lines honored
No design-repo writes; localhost only; no persistence (in-memory); no edits to
qlab-air/qlab-wallet (issue #32 owns them) — this crate only *depends* on qlab-note
(+ qlab-air via it) and qlab-devnet. Full unfiltered `cargo test --release` stays green.
