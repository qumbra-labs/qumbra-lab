/* qvask.h — the exchange/VASP kit verifier's C ABI (lab #483 stage 1).
 *
 * Verify a wallet-interop §3 deposit-disclosure envelope. Hand-maintained
 * beside src/lib.rs; two Rust tests pin the two files to each other in both
 * directions (#246 discipline): the exported-function list, and the QVASK_*
 * refusal-code values by name AND number.
 *
 * Rules (all load-bearing, argued in the crate docs):
 *   - Verification is a pure function: no handles, no state, no callbacks.
 *     Thread-safe by statelessness; nothing is retained past a call.
 *   - All input buffers are caller-owned. The ONLY library allocation that
 *     crosses out is *reason_out — free it with qvask_string_free, nothing
 *     else. qvask_string_free(NULL) is a no-op.
 *   - NULL arguments (out-params included) are refused with
 *     QVASK_INVALID_CALL: a consumer cannot opt out of the refusal reason.
 *   - The FRI config and the statement height are PINNED INSIDE the library
 *     (Rust DISCLOSURE_V1_CFG, b16/q20/g22, 102-bit conjectured): a caller
 *     cannot weaken the verifier by parameter. A config change is a new ABI
 *     version, reported by qvask_abi_version().
 *   - Rule 1 of §3 (tx exists on-chain and is finalized) stays the CALLER's
 *     chain lookup: chain_cm below is the commitment the caller read at
 *     (tx_ref, output_index) on its own finalized view.
 */

#ifndef QVASK_H
#define QVASK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI + pinned-parameter version this header describes; qvask_abi_version()
 * returns the same number from the linked library — check it at startup. */
#define QVASK_ABI_VERSION 1

/* --- refusal taxonomy (stable; pinned to lib.rs by value) ---------------- */

/* Verified: *claim_out is the proven claim. */
#define QVASK_OK 0
/* NULL args / contract violation — never a verdict about the envelope. */
#define QVASK_INVALID_CALL -1
/* Framing refused: truncated field, trailing bytes, varint. */
#define QVASK_MALFORMED -2
/* §3 rule 3: unknown envelope version — rejected, never ignored. */
#define QVASK_UNKNOWN_VERSION -3
/* §3 rule 3: unknown claim type — rejected, never ignored. */
#define QVASK_UNKNOWN_CLAIM_TYPE -4
/* proof_bytes did not deserialize into a proof structure. */
#define QVASK_PROOF_DECODE -5
/* §3 rule 2 failed: proof does not verify against claim body + chain cm. */
#define QVASK_PROOF_INVALID -6

/* --- the claim ------------------------------------------------------------ */

/* The claim-0x01 fields an exchange matches against its deposit record.
 * Layout is ABI: offsets 0 / 32 / 40 / 72, size 80 (asserted Rust-side). */
typedef struct {
  uint8_t  tx_ref[32];          /* txid the claim binds to                  */
  uint64_t value;               /* disclosed amount, bessel                 */
  uint8_t  addr_commitment[32]; /* Keccak256(recipient's full raw address)  */
  uint8_t  output_index;        /* which output of tx_ref                   */
} qvask_claim_t;

/* --- entry points ---------------------------------------------------------- */

/* ABI + pinned-parameter version this library implements. */
int32_t qvask_abi_version(void);        /* = 1 */

/* Envelope format version accepted (mirrors the Rust ENVELOPE_VER). */
uint8_t qvask_envelope_ver(void);       /* = 0x01 */

/* Parse WITHOUT verifying: extract the claim fields to match against the
 * deposit record before paying for verification (~26 ms). Full framing
 * checks run; the proof bytes are not touched. *claim_out is written only
 * on QVASK_OK.
 * Refusals: QVASK_MALFORMED / QVASK_UNKNOWN_VERSION / QVASK_UNKNOWN_CLAIM_TYPE. */
int32_t qvask_envelope_peek(const uint8_t *envelope, size_t envelope_len,
                            qvask_claim_t *claim_out);

/* Verify (§3 rules 2–3) under the library-pinned config. chain_cm is the
 * 32-byte commitment the CALLER read at (tx_ref, output_index) on its
 * finalized view — rule 1 stays the caller's. *claim_out is filled on ANY
 * parse success (QVASK_OK, QVASK_PROOF_DECODE, QVASK_PROOF_INVALID) so a
 * refused claim can still be logged against the deposit record. On refusal
 * *reason_out is set to a NUL-terminated reason (free with
 * qvask_string_free); on QVASK_OK it is NULL. */
int32_t qvask_verify(const uint8_t *envelope, size_t envelope_len,
                     const uint8_t chain_cm[32],
                     qvask_claim_t *claim_out,
                     char **reason_out);

/* Free a string returned through reason_out. NULL is a no-op. */
void qvask_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* QVASK_H */
