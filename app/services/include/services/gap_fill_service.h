/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gap_fill_service — sequential block-gap filler for IBD and catch-up.
 *
 * Problem: when a peer announces a tip far ahead of ours (gap > 512),
 * reducer activation defers and queues only the one far block via
 * `dl_queue_priority`. The 2,500 intermediate blocks `[tip+1, far-1]`
 * are not requested by that path — they depend on the header-reception path
 * in `msg_headers.c` queueing them, which only fires when new
 * headers arrive. If headers have already arrived and the chain still
 * has missing block data, the gap never closes.
 *
 * Solution: a background pthread that, while `tip_h < best_header_h`:
 *   1. Walks pprev from `pindex_best_header` down to `tip+1`
 *      (capped at GAPFILL_WINDOW) collecting candidate block_index ptrs
 *   2. For each that lacks `BLOCK_HAVE_DATA` and is not already
 *      in-flight, batches the hash/height pair
 *   3. Calls `dl_queue_blocks` once per pass
 *   4. Sleeps GAPFILL_TICK_SECS or until woken by `gap_fill_kick`
 *
 * Crash-safe: takes `ms->cs_main` briefly per pass; never holds the
 * lock across a download-manager mutation. Walks use the same
 * monotonicity + step-cap pattern as `pprev_walk_safe` (canonical
 * helper landing in Part 2). */

#ifndef ZCL_GAP_FILL_SERVICE_H
#define ZCL_GAP_FILL_SERVICE_H

#include "util/result.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct main_state;
struct download_manager;
struct block_index;

typedef void (*gap_fill_dispatch_wake_fn)(void *ctx);

#define GAPFILL_TICK_SECS    5       /* periodic refill cadence */
#define GAPFILL_WINDOW       65536   /* max blocks per pass — needs to be
                                      * large enough to cover any plausible
                                      * mining-rate gap. 65k = ~6 weeks of
                                      * ZCL blocks (~75s/block); single
                                      * pass can reach tip+1 even after a
                                      * long disconnection. */
#define GAPFILL_WALK_CAP     131072  /* hard pprev step cap, 2x window for
                                      * defense against pprev cycles */
#define GAPFILL_PRIORITY_BOTTOM_N 16 /* front-insert the lowest N missing
                                      * blocks of the window (the
                                      * connectable bottom: tip+1..) so the
                                      * tip-advancing body can never be
                                      * tail-starved behind far-ahead live
                                      * blocks. See gap_fill_pass(). */

struct gap_fill_stats {
    uint64_t passes;
    uint64_t blocks_enqueued;
    uint64_t passes_idle;
    uint64_t passes_corrupt_walk;
    uint64_t timeout_sweeps;
    uint64_t timeouts_requeued;
    uint64_t dispatch_wakes;
    int      last_tip_h;
    int      last_best_h;
    int      last_window_lo;
    int      last_window_hi;
};

struct gap_fill_window {
    int  effective_tip_h;
    int  best_h;
    int  lo;
    int  hi;
    int  count;
    bool has_work;
};

/* Pure window calculation used by the worker and pinned by tests.
 * `floor_cursor` is the fastest safe upper bound on new download work — the
 * caller passes the validate_headers cursor (header-only, decoupled from
 * body-on-disk presence) rather than the body_fetch cursor, so a stall in
 * the body-fetch reducer stage does not also stall on-disk body prefetch.
 * When floor_cursor is behind active tip, gap-fill still refills from
 * floor_cursor, not active_tip+1, as a defensive floor against running the
 * window past validated headers. GAPFILL_WINDOW bounds the result. */
bool gap_fill_compute_window(int active_tip_h, int best_header_h,
                             uint64_t floor_cursor,
                             struct gap_fill_window *out);

/* Return the indexed ancestor that starts the connectable bottom window.
 * Returns NULL when ancestry cannot resolve the exact requested height; the
 * worker refuses that pass rather than scheduling a far-ahead top window. */
struct block_index *gap_fill_window_walk_start(
    struct block_index *best, const struct gap_fill_window *window);

/* Candidate predicate before the download-manager in-flight check. */
bool gap_fill_block_needs_queue(const struct block_index *bi);

/* Copy cheap runtime counters for RPC/API/agent diagnostics. */
void gap_fill_get_stats(struct gap_fill_stats *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool gap_fill_dump_state_json(struct json_value *out, const char *key);

/* Run the independent download timeout sweep owned by the supervised gap-fill
 * cadence. This is the redundant path for peers that keep in-flight slots
 * occupied while the peer send loop is not making timeout progress. */
size_t gap_fill_sweep_download_timeouts(struct download_manager *dm,
                                        int64_t now_seconds);

/* Wake the network dispatcher when block work is already queued but no
 * request is in flight. This covers duplicate/no-op refill passes where the
 * original queue wake may have raced the message-handler wait. */
bool gap_fill_wake_dispatch_if_idle(struct download_manager *dm,
                                    const char *reason);

/* Start the service. Spawns one pthread. ms and dm must outlive the
 * service. Returns ZCL_OK on success (including the already-running
 * no-op); a non-ok result on bad args or spawn failure. Idempotent —
 * safe to call twice. */
struct zcl_result gap_fill_start(struct main_state *ms, struct download_manager *dm);

/* Request shutdown and join the thread. Safe if never started. */
void gap_fill_stop(void);

/* Wake the service immediately (instead of waiting for the next tick).
 * Called from reducer activation when a far-ahead block is deferred and from
 * header-reception when new headers expand pindex_best_header. No-op if
 * service not running. */
void gap_fill_kick(void);

/* Optional wake hook for the network dispatcher. Gap-fill owns queue refill
 * and timeout sweeps; connman owns peer enumeration and getdata writes. This
 * bridges those two without exposing peer internals to the service. */
void gap_fill_set_dispatch_wake(gap_fill_dispatch_wake_fn fn, void *ctx);

#endif /* ZCL_GAP_FILL_SERVICE_H */
