/* qlab_remote_auth_mobile_bench.h — research-only Candidate A phone benchmark.
 *
 * This ABI is not a wallet, protocol, transaction, prover, or key-storage
 * interface. It uses fixed synthetic material and exists only to measure the
 * D12..D16 ML-DSA rotation-tree work that cannot be delegated without giving
 * a backend spend authority.
 *
 * qra_mobile_bench_run() is synchronous. Call it off the UI thread. The
 * callback executes on that same calling thread and may request cancellation
 * by returning non-zero. No pointer is retained after a call, no allocation
 * crosses the ABI, and result_out is written only on QRA_MOBILE_BENCH_OK.
 */

#ifndef QLAB_REMOTE_AUTH_MOBILE_BENCH_H
#define QLAB_REMOTE_AUTH_MOBILE_BENCH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QRA_MOBILE_BENCH_ABI_VERSION 1

#define QRA_MOBILE_BENCH_OK 0
#define QRA_MOBILE_BENCH_INVALID_CALL -1
#define QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH -2
#define QRA_MOBILE_BENCH_CANCELLED -3
#define QRA_MOBILE_BENCH_INTERNAL -4

typedef int32_t (*qra_mobile_bench_progress_fn)(void *context,
                                                uint32_t completed_leaves,
                                                uint32_t total_leaves);

/* Layout is ABI: offsets 0/4/8/12, timing fields 16..56, size fields 64..76,
 * selected_indices at 80, root at 88, digest at 120, total size 152 bytes.
 * All timings are monotonic wall-clock nanoseconds. */
typedef struct {
  uint32_t struct_size;
  uint32_t abi_version;
  uint32_t depth;
  uint32_t leaf_count;
  uint64_t address_leaf_generation_ns;
  uint64_t address_tree_hashing_ns;
  uint64_t rotation_schedule_ns;
  uint64_t spend_signing_ns;
  uint64_t spend_verification_ns;
  uint64_t total_ns;
  uint32_t auth_section_bytes;
  uint32_t verifying_key_bytes_per_slot;
  uint32_t signature_bytes_per_slot;
  uint32_t rotation_schedule_bytes;
  uint32_t selected_indices[2];
  uint8_t root[32];
  uint8_t intent_digest[32];
} qra_mobile_bench_result_t;

uint32_t qra_mobile_bench_abi_version(void); /* = 1 */

/* The exact qlab commit supplied by the build script, or "unknown" for an
 * unlabelled local build. Static storage owned by the library; never free. */
const char *qra_mobile_bench_build_revision(void);

/* Exact mobile-shell commit supplied by its build script, with "+dirty" when
 * local changes were present; "unknown" for an unlabelled local build. */
const char *qra_mobile_bench_shell_revision(void);

/* Static message for a QRA_MOBILE_BENCH_* status; never free. */
const char *qra_mobile_bench_status_message(int32_t status);

int32_t qra_mobile_bench_run(uint32_t depth,
                             qra_mobile_bench_progress_fn progress,
                             void *progress_context,
                             qra_mobile_bench_result_t *result_out);

#ifdef __cplusplus
}
#endif

#endif /* QLAB_REMOTE_AUTH_MOBILE_BENCH_H */
