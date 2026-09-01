/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Header Probe — pull headers in bulk from a co-located
 * zclassicd (the legacy C++ ZClassic node, RPC 8232) via JSON-RPC
 * when our local header tip lags behind. Validates each fetched
 * header locally via accept_block_header() (Equihash + nBits
 * lineage + checkpoints) and inserts into our block_index.
 *
 * Why this exists:
 *   When P2P header sync stalls or is the bottleneck, the co-located
 *   zclassicd has all the headers and can serve them in single-digit
 *   milliseconds per call. This service closes the gap in seconds
 *   instead of hours.
 *
 * Architecture:
 *   - Pull loop calls getblockhash(h) → getblockheader(hash, false)
 *     for height range [start, start+max] on the local zclassicd.
 *   - Each returned hex-serialized header is parsed via
 *     block_header_deserialize and handed to accept_block_header().
 *   - A supervised header_probe_poll Job calls header_probe_tick_once()
 *     whenever our header tip trails the remote tip by more than
 *     `lag_threshold`.
 *   - No new pthreads. The supervised header_probe_poll Job owns cadence.
 *
 * See CLAUDE.md "Adding state introspection" — this module follows
 * the *_dump_state_json convention and is wired into the generic
 * native dump-state dispatcher.
 */

#ifndef ZCL_SERVICES_HEADER_PROBE_H
#define ZCL_SERVICES_HEADER_PROBE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct main_state;
struct chain_params;
struct json_value;

struct header_probe_config {
    const char *rpc_host;       /* default "127.0.0.1" */
    int         rpc_port;       /* default 8232 */
    const char *rpc_user;       /* read zclassic.conf if NULL */
    const char *rpc_password;
    int         batch_size;     /* default 2000; max 5000 */
    int         lag_threshold;  /* only probe when our_tip < their_tip - this; default 100 */
};

/* Apply config + load credentials. Safe to call before start to
 * override defaults. Idempotent. Returns a non-ok zcl_result only on a
 * missing zclassic.conf when no user/password were supplied. */
struct zcl_result header_probe_init(const struct header_probe_config *cfg,
                                    struct main_state *ms,
                                    const struct chain_params *params);

/* One-shot poll tick. Cheap getblockcount discovers the remote tip,
 * compares it against the local header tip, and pulls a batch if the
 * lag threshold is exceeded. Safe to call when not initialized (no-op).
 *
 * Used by the `header_probe_poll` Job (engine/jobs/) as the body of
 * its supervisor tick callback. Pure scheduling separation — same
 * RPC, same validation, same accept_block_header path. */
void header_probe_tick_once(void);

/* Synchronous one-shot for native diagnostics and tests:
 *   start_height: where to begin (inclusive). Use our_tip+1 normally.
 *   max_headers:  cap on number of headers to pull in this call
 *                 (clamped to [1, 5000]).
 *   out_added:    receives the number successfully accepted (NULL OK).
 * Returns ZCL_OK if at least one header was added, we're already at
 * tip, or the legacy node is unreachable (RPC errors are surfaced via
 * state counters, not the return). Returns a non-ok zcl_result only if
 * init() hasn't been called or arguments are bogus. */
struct zcl_result header_probe_pull_range(int start_height, int max_headers,
                                          int *out_added);

/* ── Detective lane A2: repair-source accounting ──────────────────
 *
 * A corrupted / solutionless stored header is repaired from one of two
 * sources, in explicit priority order:
 *   ORACLE — the co-located zclassicd legacy RPC (cheap, local; tried first).
 *   P2P    — the connected peer set, via the EXISTING getdata block-refetch
 *            machinery (used when the oracle is unreachable / absent — the
 *            zclassicd oracle is being retired, so header repair must not
 *            depend on it).
 * The stale_validate_headers_repair Condition orchestrates the ordering and
 * records which source acted via the note_* functions below, so the
 * `z23 dumpstate header_probe` reports the last repair source and
 * per-source counters (which source served the last repair, how many repairs
 * each source served, how many P2P re-fetches were requested, and how many of
 * those fired with zero connected peers = a missing-input event). */
enum header_probe_repair_source {
    HEADER_PROBE_SRC_NONE = 0,
    HEADER_PROBE_SRC_ORACLE,
    HEADER_PROBE_SRC_P2P,
};

const char *header_probe_repair_source_name(enum header_probe_repair_source s);

/* Record that the header-solution repair for `height` was served (the correct
 * canonical solution is now durably present) by `src`. Bumps the per-source
 * served counter and latches last_repair_source / last_repair_height. NONE is
 * ignored. */
void header_probe_note_repair_served(enum header_probe_repair_source src,
                                     int height);

/* Record that a P2P getdata re-fetch of the canonical block for `height` was
 * requested because the oracle could not serve it. `peers_available` is the
 * connected-peer count at request time; <= 0 means no source can serve the
 * repair right now (missing input) and is counted separately. */
void header_probe_note_p2p_request(int height, int peers_available);

/* Reentrant-safe dispatcher entry for `z23 dumpstate header_probe`. */
bool header_probe_dump_state_json(struct json_value *out, const char *key);

/* Test hooks — reset state between unit tests. */
void header_probe_reset_for_test(void);

#ifdef ZCL_TESTING
/* Snapshot of the repair-source counters for hermetic tests. */
struct header_probe_repair_stats {
    int64_t oracle_repairs;
    int64_t p2p_requests;
    int64_t p2p_repairs;
    int64_t p2p_no_peer_events;
    int     last_repair_source;   /* enum header_probe_repair_source */
    int     last_repair_height;
};
void header_probe_test_get_repair_stats(struct header_probe_repair_stats *out);
#endif

#endif /* ZCL_SERVICES_HEADER_PROBE_H */
