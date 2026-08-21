/* qumbra_ffi.h — the wallet kernel's C ABI (issue #246 rung A).
 *
 * Hand-maintained beside src/lib.rs; the Rust test
 * `the_header_names_every_exported_function_and_nothing_else` pins the two to
 * the same function list, in both directions.
 *
 * Rules (all load-bearing, argued in the crate docs):
 *   - qmb_wallet_t is opaque; free with qmb_wallet_free.
 *   - Every char* returned here is freed with qmb_string_free, nothing else.
 *   - Constructors return NULL on refusal, with a reason in *err_out
 *     (also a qmb_string_free string). err_out may be NULL.
 *   - The platform sources all entropy (SecRandomCopyBytes on iOS).
 *   - qmb_wallet_reveal_mnemonic is the ONLY function returning key material.
 */

#ifndef QUMBRA_FFI_H
#define QUMBRA_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct qmb_wallet_t qmb_wallet_t;

/* --- lifecycle ---------------------------------------------------------- */

/* 32 platform-sourced entropy bytes in; never NULL for non-NULL input. */
qmb_wallet_t *qmb_wallet_from_entropy(const uint8_t *entropy32);

/* Restore from a Qumbra mnemonic (UTF-8, NUL-terminated). NULL + *err_out on
 * refusal — Qumbra's wordlist is deliberately NOT BIP-39. */
qmb_wallet_t *qmb_wallet_restore(const char *phrase, char **err_out);

/* Re-open from persisted parts (the Keychain handshake). Unknown versions are
 * refused with a reason, never guessed at. */
qmb_wallet_t *qmb_wallet_from_parts(uint8_t version, const uint8_t *entropy32,
                                    char **err_out);

void qmb_wallet_free(qmb_wallet_t *w);
void qmb_string_free(char *s);

/* Caller-side input buffers (the WASM host's only way to hand us a string).
 * Pair qmb_alloc with qmb_dealloc; unrelated to qmb_string_free. */
uint8_t *qmb_alloc(size_t len);
void qmb_dealloc(uint8_t *p, size_t len);

/* --- key material (explicit) -------------------------------------------- */

/* The ONLY key-material return in this ABI — the explicit reveal. */
char *qmb_wallet_reveal_mnemonic(const qmb_wallet_t *w);

/* The persistence handshake: what the platform seals (rung C: Keychain under
 * a Secure-Enclave-wrapped key). */
uint8_t qmb_wallet_seed_version(const qmb_wallet_t *w);
void qmb_wallet_seed_entropy(const qmb_wallet_t *w, uint8_t *out32);

/* --- addresses ----------------------------------------------------------- */

/* Full bech32m address at a diversifier index (qaddr1…, ~2.2 KB). */
char *qmb_wallet_address(const qmb_wallet_t *w, uint64_t index);

/* Short address (qs1…) — the human-facing default. */
char *qmb_wallet_address_short(const qmb_wallet_t *w, uint64_t index);

/* The full address as a QR code in SVG (#342's renderer, EC-L). Show the
 * qs1… fingerprint BESIDE it: a QR that merely scans is not a verified
 * address. NULL + *err_out if the payload cannot fit. */
char *qmb_address_qr_svg(const qmb_wallet_t *w, uint64_t index, char **err_out);

/* --- scan ---------------------------------------------------------------- */

/* Light-client scan for the given indices against a cbserver base URL over
 * [from, to]; returns the RENDERED report (verdicts computed Rust-side: the
 * UNAVAILABLE discipline, no partial totals). Blocking — call off the main
 * thread. rng_seed32: 32 platform-sourced bytes for the decoy rng. */
char *qmb_wallet_scan_report(const qmb_wallet_t *w, const char *base_url,
                             uint64_t from, uint64_t to,
                             const uint64_t *indices, size_t n_indices,
                             const uint8_t *rng_seed32);

/* Fetch one scan path — the transport belongs to the SHELL.
 *
 * The public edge is https-only and the Rust socket path above is
 * plaintext-only on purpose (lab #297: TLS in qlab-cbserver would link rustls
 * into the consensus node). So instead of giving this library its own TLS, the
 * shell lends its own: URLSession on iOS brings https and App Transport
 * Security from the platform — the same trade as entropy, which the platform
 * also supplies rather than this library inventing it.
 *
 * Return 0 on success with the body in *out_body / *out_len. OWNERSHIP MOVES
 * to this library, which releases both buffers with free() — so they must come
 * from malloc(). This is the one place a pointer crossing INTO this library is
 * owned by it; everything returned OUT is still freed with qmb_string_free.
 *
 * Return nonzero on failure, optionally with a NUL-terminated reason in
 * *out_err under the same malloc/free contract. A failed path becomes one
 * error inside the scan, which the report renders as UNAVAILABLE — never as a
 * zero balance. */
typedef int32_t (*qmb_fetch_fn)(void *ctx, const char *path_and_query,
                               uint8_t **out_body, size_t *out_len,
                               char **out_err);

/* The same scan over a caller-supplied transport. source_label is what the
 * report NAMES as its source: this library no longer knows the transport, so
 * it cannot infer where the numbers came from, and a report must say. Both
 * this and qmb_wallet_scan_report route into one scan flow, so what counts as
 * detected/opened/unopened cannot drift between them. Blocking — call off the
 * main thread. */
/* The wallet's own LEDGER — received notes and the spends the chain published —
 * rendered, over the same caller-supplied transport.
 *
 * Send events refuse their figures here by design: attributing a fee needs the
 * posted table, which lives in a crate that cannot cross-compile to iOS, so such
 * an event reports UNAVAILABLE with the reason. That is the honest state and not
 * a placeholder — an unprovable total is worse than an absent one (lab #407).
 * There is no local send record on this platform either, so an unmatched record
 * cannot arise.
 *
 * Blocking — call off the main thread. */
char *qmb_wallet_ledger_report_over_fetch(const qmb_wallet_t *w,
                                          const char *source_label,
                                          uint64_t from, uint64_t to,
                                          const uint64_t *indices, size_t n_indices,
                                          const uint8_t *rng_seed32,
                                          qmb_fetch_fn fetch, void *fetch_ctx);

char *qmb_wallet_scan_report_over_fetch(const qmb_wallet_t *w,
                                        const char *source_label,
                                        uint64_t from, uint64_t to,
                                        const uint64_t *indices, size_t n_indices,
                                        const uint8_t *rng_seed32,
                                        qmb_fetch_fn fetch, void *fetch_ctx);

/* --- the pumpable scan (lab #395) ---------------------------------------- */

/* The browser/WASM shell's scan. qmb_fetch_fn above is synchronous and a
 * browser has no synchronous fetch to put behind it, so here the SHELL pumps:
 * alternate qmb_scan_step with qmb_scan_supply / qmb_scan_supply_err from any
 * async transport. Same one orchestration as both sync paths — what counts as
 * detected/opened/unopened cannot drift.
 *
 * qmb_scan_step returns
 *    1  NEED: *out is the path to fetch (a qmb_string_free string);
 *    0  DONE: *out is the rendered report — crosses ONCE, then the handle
 *       answers -1;
 *   -1  NULL/finished handle or NULL out.
 *
 * Supplied bytes are COPIED — the caller keeps its buffer (a WASM host writes
 * into qmb_alloc memory and qmb_dealloc's it afterwards; nothing here is the
 * malloc/free contract of qmb_fetch_fn). A reason given to qmb_scan_supply_err
 * survives into the report: UNAVAILABLE, never a zero. */
typedef struct qmb_scan_t qmb_scan_t;

qmb_scan_t *qmb_scan_new(const qmb_wallet_t *w, const char *source_label,
                         uint64_t from, uint64_t to,
                         const uint64_t *indices, size_t n_indices,
                         const uint8_t *rng_seed32);
int32_t qmb_scan_step(qmb_scan_t *s, char **out);
void qmb_scan_supply(qmb_scan_t *s, const uint8_t *body, size_t len);
void qmb_scan_supply_err(qmb_scan_t *s, const char *reason);
void qmb_scan_free(qmb_scan_t *s);

/* --- the pumpable select + the witness bundle (lab #400) ------------------ */

/* Phase 1 of a spend, pumped the same way the scan is — born from a FINISHED
 * scan's outcomes (consumed; scan again for another select), finishing as the
 * serialized witness bundle the native prover host takes.
 *
 * qmb_select_step_events returns
 *    1  NEED from the SCAN endpoint: *out is the path (qmb_string_free);
 *    2  NEED from the NODE endpoint: same contract, other host — one host
 *       normally serves both, the code still names which wire it is;
 *    0  DONE: take the bytes with qmb_select_take_bundle;
 *   -2  FAILED by name: *out is the reason (qmb_string_free);
 *   -1  NULL/invalid call.
 *
 * EVERY call also hands back the selection's narration (lab #432): the events
 * the driver emitted since the last call land in *events_out / *events_len,
 * released with qmb_dealloc(p, len). No events -> *events_out = NULL and
 * *events_len = 0. NULL events_out/events_len is refused with -1 — narration
 * rides the step return precisely so a send surface cannot skip it.
 *
 * 🔴 THE NARRATION CONTRACT (lab #424 guardrail 1 — visible degradation):
 * a consumer MUST surface QMB_EVENT_WARNING and
 * QMB_EVENT_COINBASE_UNAVAILABLE to its user. QMB_EVENT_COINBASE_UNAVAILABLE
 * means this selection could NOT see the wallet's mined coins and proceeded
 * on transaction notes only (the 2026-08-16 ruling): a user must never think
 * they spent from a complete view when they did not. A shell that drops these
 * events is violating this header's stated contract.
 *
 * Event encoding — tagged, length-prefixed, unknown-kind-skippable:
 *
 *    blob   := u32le record_count || record_count * record
 *    record := u16le kind || u32le body_len || body_len bytes
 *
 * Integers little-endian; text UTF-8, NOT NUL-terminated (lengths are
 * explicit). A record of a kind you do not know is SKIPPED by body_len and
 * the rest of the blob still parses — a future event kind must not break a
 * shipped shell. Kinds and bodies:
 *
 *    QMB_EVENT_OTHER                 0  UTF-8 display text (narration with no
 *                                       dedicated shape yet; display it)
 *    QMB_EVENT_SELECTED              1  u64le spendable || u64le skipped_spent
 *                                       || u64le mined
 *    QMB_EVENT_TREE                  2  u64le held || u64le fetched ||
 *                                       u64le anchor_count || u64le node_tip ||
 *                                       u8 has_finalized || u64le finalized ||
 *                                       u64le anchor_behind || anchor_root
 *                                       (UTF-8 hex, the rest of the body)
 *    QMB_EVENT_WARNING               3  UTF-8 text — must be SEEN, must not
 *                                       stop the spend
 *    QMB_EVENT_COINBASE_UNAVAILABLE  4  UTF-8 text — the reason, verbatim
 *
 * No event payload ever carries key material, at any kind, ever.
 *
 * qmb_select_step is the pre-#432 pump, kept because this ABI is additive.
 * It returns the same codes and drains NOTHING: events stay queued in the
 * handle (deferred, never lost) until a qmb_select_step_events call returns
 * them. Building a send surface on it violates the narration contract above.
 *
 * The bundle bytes carry SPENDING-KEY MATERIAL: hand them to the native
 * prover host and nowhere else, discard once the transaction is accepted or
 * known-duplicate. The buffer from qmb_select_take_bundle is released with
 * qmb_dealloc(p, len); it crosses ONCE.
 *
 * qmb_bundle_review renders the approval text from DECODED bundle bytes —
 * the popup's approval screen reads the artifact that will be proved, never
 * form state. Undecodable or semantically-refused bundles answer NULL with
 * the reason in *err_out. */
typedef struct qmb_select_t qmb_select_t;

#define QMB_EVENT_OTHER 0
#define QMB_EVENT_SELECTED 1
#define QMB_EVENT_TREE 2
#define QMB_EVENT_WARNING 3
#define QMB_EVENT_COINBASE_UNAVAILABLE 4

qmb_select_t *qmb_select_new(const qmb_wallet_t *w, qmb_scan_t *scan,
                             const char *recipient, uint64_t amount,
                             const uint8_t *held_leaves, size_t held_len,
                             const uint8_t *rng_seed32, char **err_out);
int32_t qmb_select_step(qmb_select_t *s, char **out);
int32_t qmb_select_step_events(qmb_select_t *s, char **out,
                               uint8_t **events_out, size_t *events_len);
void qmb_select_supply(qmb_select_t *s, const uint8_t *body, size_t len);
void qmb_select_supply_err(qmb_select_t *s, const char *reason);
uint8_t *qmb_select_take_bundle(qmb_select_t *s, size_t *out_len);
void qmb_select_free(qmb_select_t *s);

char *qmb_bundle_review(const uint8_t *bytes, size_t len, char **err_out);

/* --- payment URIs + the history join (roadmap #3/#4) ---------------------- */

/* Parse a qumbra: payment URI (#342's one codec). Returns the FULL qaddr1…;
 * an amount, when present, lands in *out_amount_bessel with *out_has_amount=1
 * (integer-exact bessel). Label/memo are display-only and do not cross in v1.
 * NULL + *err_out on refusal, by name. */
char *qmb_uri_parse(const char *uri, uint64_t *out_amount_bessel,
                    uint8_t *out_has_amount, char **err_out);

/* The bundle's REAL-input nullifiers, hex, newline-joined — the history join
 * key: these bytes go on-chain when the spend lands, so a record keyed on
 * them can later be marked CONFIRMED by the chain's own nullifier stream. */
char *qmb_bundle_nullifiers(const uint8_t *bytes, size_t len, char **err_out);

/* The bulk nullifier stream, caller-pumped (same vocabulary as scan/select;
 * the accumulation checks are the ONE copy shared with the CLI and the select
 * driver). qmb_spent_step: 1 NEED (*out = page path) · 0 DONE (query with
 * qmb_spent_contains) · -2 FAILED by name (*out) · -1 invalid call.
 * qmb_spent_contains after DONE: 1 on-chain, 0 not, -1 unanswerable
 * (before DONE / malformed hex) — refused, never guessed. */
/* Decode a /v1/anchors response into the connection facts a wallet shows and
 * scans by: tip height, plus the finalized height when the chain has one
 * (*out_has_finalized = 0 means nothing-finalized — said, never guessed as
 * height 0). Scanning to FINALIZED keeps a balance spendable-consistent.
 * 0 on success; -1 + *err_out on refusal, by name. */
int32_t qmb_anchors_facts(const uint8_t *bytes, size_t len, uint64_t *out_tip,
                          uint8_t *out_has_finalized, uint64_t *out_finalized,
                          char **err_out);

typedef struct qmb_spent_t qmb_spent_t;

qmb_spent_t *qmb_spent_new(uint64_t from, uint64_t to);
int32_t qmb_spent_step(qmb_spent_t *s, char **out);
void qmb_spent_supply(qmb_spent_t *s, const uint8_t *body, size_t len);
void qmb_spent_supply_err(qmb_spent_t *s, const char *reason);
int32_t qmb_spent_contains(const qmb_spent_t *s, const char *nf_hex);
void qmb_spent_free(qmb_spent_t *s);

/* ── the paired-prover session ─────────────────────────────────────────────
 *
 * A phone cannot prove a Qumbra spend: the consensus config needs a 15.1 GB
 * working set (self-proving-vs-proof-size.md, branch (b)). So a phone SELECTS
 * and SIGNS locally and hands the witness bundle to the user's own Mac —
 * qumbra-wallet-macos's `qumbra-paired-prover`, specified in that repo's
 * docs/mobile-paired-prover.md. This is the client half of that channel.
 *
 * The kernel owns the protocol; the shell owns the socket and nothing else.
 * That split is not a preference:
 *
 *   - frame reassembly, the frame counters and the AAD are the security core,
 *     and a copy per shell is a second place to get them wrong;
 *   - the spec's client obligation is to "verify byte length and SHA3-256
 *     before exact-byte submission", and Apple's CryptoKit has no SHA-3, so an
 *     iOS shell CANNOT discharge it. A shell that cannot verify the artifact is
 *     not the thing that should decide whether the artifact is the transaction;
 *   - the pairing secret never crosses this boundary. It is read from the URI
 *     inside qmb_pair_new and dropped with the session.
 *
 * The wire, transcribed from the server implementation rather than its prose:
 *
 *    URI        qumbra-prover://HOST:PORT?v=1&secret=<64 hex>
 *    handshake  "QMBPAIR\0" || version:u8 || server_nonce:16   (25 B, plaintext)
 *    key        SHA3-256("qumbra-wallet/paired-prover/key/v1\0"
 *                        || secret || server_nonce)
 *    frame      counter:u64le || ciphertext_len:u32le || ChaCha20-Poly1305
 *    nonce      direction:4 || counter:u64le
 *    aad        magic:8 || version:u8 || server_nonce:16 || direction:4
 *                        || counter:u64le
 *    direction  client->Mac "MOBI"    Mac->client "DESK"
 *
 * Drive it as a pump, exactly like qmb_scan_new / qmb_scan_step /
 * qmb_scan_supply. Named rather than wildcarded ON PURPOSE: the header-vs-source
 * test scans every line of this file, comments included, for a function-shaped
 * token, so a trailing-asterisk wildcard reads to it as an undeclared function.
 * It caught exactly that on this PR's first verify run — and then caught the
 * explanation of the fix, which had spelled the bare prefix out loud. Write the
 * names.
 *
 *    s = qmb_pair_new(uri, id, op, bundle, len, scan_url, node_url, &err);
 *    connect to qmb_pair_endpoint(s);
 *    loop {
 *      switch (qmb_pair_step(s, &out, &out_len, &err)) {
 *        case 1: write(out, out_len); qmb_dealloc(out, out_len); break;
 *        case 2: n = read(buf); qmb_pair_supply(s, buf, n);      break;
 *        case 0: tx = qmb_pair_take_artifact(s, &tx_len);        break;
 *        default: show err;                                      break;
 *      }
 *      show qmb_pair_take_notes(s);   // REQUIRED — see below
 *    }
 *
 * 🔴 A shell MUST surface qmb_pair_take_notes. Proving runs seconds to minutes
 * and a silent minute reads as a hang; the same obligation the select pump's
 * event contract carries, for the same reason.
 *
 * ⚠️ TIMEOUTS: the Mac's 30-second socket timeout covers HANDSHAKE I/O, not
 * proving. A shell that applies a 30 s read timeout while waiting for
 * artifact_chunk frames will abandon a healthy prover mid-proof.
 *
 * The witness bundle passed in carries SPENDING-KEY MATERIAL, and so does the
 * pairing secret in the URI: both are spend authority for exactly the
 * transaction they prove. operation is 0 = inspect (decode and describe; no
 * proving, no endpoints needed) or 1 = prove (scan_url and node_url REQUIRED —
 * the host re-validates against live anchors before allocating STARK work).
 *
 * The artifact from qmb_pair_take_artifact has ALREADY been checked against the
 * length and the SHA3-256 the prover announced. */
typedef struct qmb_pair_t qmb_pair_t;

qmb_pair_t *qmb_pair_new(const char *uri, const char *request_id, uint8_t operation,
                         const uint8_t *bundle, size_t bundle_len,
                         const char *scan_url, const char *node_url, char **err_out);
char *qmb_pair_endpoint(const qmb_pair_t *p);
void qmb_pair_supply(qmb_pair_t *p, const uint8_t *bytes, size_t len);
int32_t qmb_pair_step(qmb_pair_t *p, uint8_t **out, size_t *out_len, char **err_out);
char *qmb_pair_take_notes(qmb_pair_t *p);
uint8_t *qmb_pair_take_artifact(qmb_pair_t *p, size_t *out_len);
void qmb_pair_free(qmb_pair_t *p);

#ifdef __cplusplus
}
#endif

#endif /* QUMBRA_FFI_H */
