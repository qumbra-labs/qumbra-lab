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

/* --- scan ---------------------------------------------------------------- */

/* Light-client scan for the given indices against a cbserver base URL over
 * [from, to]; returns the RENDERED report (verdicts computed Rust-side: the
 * UNAVAILABLE discipline, no partial totals). Blocking — call off the main
 * thread. rng_seed32: 32 platform-sourced bytes for the decoy rng. */
char *qmb_wallet_scan_report(const qmb_wallet_t *w, const char *base_url,
                             uint64_t from, uint64_t to,
                             const uint64_t *indices, size_t n_indices,
                             const uint8_t *rng_seed32);

#ifdef __cplusplus
}
#endif

#endif /* QUMBRA_FFI_H */
