/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the rolling-anchor service's private cross-TU contract — the
 * state-free computations its lifecycle half calls.
 *
 * rolling_anchor_service.c owns the module state (the g_ra ring, its mutex,
 * the supervisor contract, persistence, and the public entry points);
 * rolling_anchor_compute.c owns the helpers that touch none of it. The
 * split happened when the combined file passed the 800-line shape ceiling.
 * Nothing outside those two translation units may include this header —
 * the public contract is services/rolling_anchor_service.h.
 */

#ifndef ZCL_SERVICES_ROLLING_ANCHOR_INTERNAL_H
#define ZCL_SERVICES_ROLLING_ANCHOR_INTERNAL_H

#include "platform/positioned_file.h"
#include "validation/main_state.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* End height of the compile-time SHA3 window prefix, or -1 when this build
 * carries no compile-time windows. */
int ra_compile_time_end(void);

/* File-level SHA3 over an on-disk body (everything before the trailing
 * 32-byte digest). */
void ra_file_digest(const uint8_t *body, size_t body_len, uint8_t out[32]);

/* True when two positioned-file snapshots describe the same unchanged file
 * identity, size, and timestamps. */

/* SHA3 over the serialized blocks of one window [start_h .. +999], read
 * from disk through active_chain. True when every block was read; on false
 * *out_failure_height carries the height that stopped it (-1 on bad args). */
bool ra_compute_window_hash(struct main_state *ms, const char *datadir,
                            int start_h, uint8_t out_hash[32],
                            int *out_failure_height);

/* Quorum verdict for committing a window ending at `height`. Fails OPEN:
 * true whenever the oracle cannot be probed or only one source answered. */
bool ra_quorum_allows_commit(int height);

#endif /* ZCL_SERVICES_ROLLING_ANCHOR_INTERNAL_H */
