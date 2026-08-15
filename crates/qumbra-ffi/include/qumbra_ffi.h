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
 * qmb_select_step returns
 *    1  NEED from the SCAN endpoint: *out is the path (qmb_string_free);
 *    2  NEED from the NODE endpoint: same contract, other host — one host
 *       normally serves both, the code still names which wire it is;
 *    0  DONE: take the bytes with qmb_select_take_bundle;
 *   -2  FAILED by name: *out is the reason (qmb_string_free);
 *   -1  NULL/invalid call.
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

qmb_select_t *qmb_select_new(const qmb_wallet_t *w, qmb_scan_t *scan,
                             const char *recipient, uint64_t amount,
                             const uint8_t *held_leaves, size_t held_len,
                             const uint8_t *rng_seed32, char **err_out);
int32_t qmb_select_step(qmb_select_t *s, char **out);
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
typedef struct qmb_spent_t qmb_spent_t;

qmb_spent_t *qmb_spent_new(uint64_t from, uint64_t to);
int32_t qmb_spent_step(qmb_spent_t *s, char **out);
void qmb_spent_supply(qmb_spent_t *s, const uint8_t *body, size_t len);
void qmb_spent_supply_err(qmb_spent_t *s, const char *reason);
int32_t qmb_spent_contains(const qmb_spent_t *s, const char *nf_hex);
void qmb_spent_free(qmb_spent_t *s);

#ifdef __cplusplus
}
#endif

#endif /* QUMBRA_FFI_H */
