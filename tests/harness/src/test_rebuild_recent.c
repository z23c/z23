/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the rebuild_recent recovery primitive.
 *
 * rebuild_recent fetches the recent block range from the legacy advisory
 * source and submits each block through local consensus validation
 * (process_new_block), reorging off any stale local fork.
 *
 * WHAT THESE TESTS COVER (pure, no live node required):
 *   - The range resolution math: default look-back below the tip,
 *     explicit from_height, upper-bound clamping to the remote tip,
 *     the recent-window cap, and the idempotent at-tip no-op signal.
 *
 * WHAT THESE TESTS MOCK / DO NOT COVER:
 *   - The actual fetch from zclassicd (legacy_chain_rpc_get_block_hex /
 *     _get_block_count) requires a live zclassicd RPC endpoint, so it is
 *     not exercised here.
 *   - The validated accept path (process_new_block → accept_block →
 *     connect_block) requires a fully initialised main_state + coins
 *     view + chain params + datadir. That path is the SAME one the reorg
 *     corpus (test_reorg_safety.c, run via --only=reorg) and submitblock
 *     exercise; rebuild_recent adds no new acceptance logic — it only
 *     deserializes a fetched block and calls process_new_block with
 *     force_processing=true, exactly like rpc_submitblock. The consensus
 *     safety of the connect step is therefore covered transitively.
 *
 * The range/bound/idempotence logic is the only net-new decision surface
 * and is fully covered below against the published bounds:
 *   REBUILD_RECENT_MAX_RANGE        = 10000
 *   REBUILD_RECENT_DEFAULT_MARGIN   = 10
 */

#include "test/test_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Published bounds (mirror the #defines in repair_controller_rebuild.c).
 * Kept in sync deliberately; if those change, this test must be updated.
 * 10000 since 4d4e8c436 — must cover one full cold-import seed window
 * (~5.5-7k blocks). */
#define RR_MAX_RANGE      10000
#define RR_DEFAULT_MARGIN 10

/* Non-static helper under test (declared in the controller .c). */
bool rebuild_recent_resolve_range(int tip_height, int remote_height,
                                  int64_t from_arg, bool from_present,
                                  int *lo_out, int *hi_out,
                                  char *err, size_t err_sz);

#define RR_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* 1. Default look-back: from omitted → lo = tip - margin, hi = remote. */
static int t_default_lookback(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    bool ok = rebuild_recent_resolve_range(/*tip*/100, /*remote*/105,
                                           0, false, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: default look-back resolves ok",
           ok && lo == 100 - RR_DEFAULT_MARGIN && hi == 105);
    return failures;
}

/* 2. Default look-back floors lo at 0 when the tip is shallow. */
static int t_default_floor_zero(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    bool ok = rebuild_recent_resolve_range(/*tip*/3, /*remote*/8,
                                           0, false, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: default look-back floors lo at 0",
           ok && lo == 0 && hi == 8);
    return failures;
}

/* 3. Explicit from_height is honoured. */
static int t_explicit_from(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    bool ok = rebuild_recent_resolve_range(/*tip*/200, /*remote*/210,
                                           150, true, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: explicit from_height honoured",
           ok && lo == 150 && hi == 210);
    return failures;
}

/* 4. Idempotent at-tip no-op: local already at/above remote → hi < lo. */
static int t_idempotent_at_tip(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    /* tip 105, remote 105 → default lo = 95, hi = 105 (still work to
     * re-verify). The true no-op is when from_height > remote. */
    bool ok = rebuild_recent_resolve_range(/*tip*/105, /*remote*/105,
                                           106, true, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: from above remote tip is a no-op (hi < lo)",
           ok && hi < lo);
    return failures;
}

/* 5. Upper bound is clamped to one recent window past lo. */
static int t_window_clamp(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    /* from = remote - (MAX_RANGE - 1): exactly the largest allowed span,
     * so it is accepted and hi clamps to remote. */
    int remote = 1000000;
    int from = remote - (RR_MAX_RANGE - 1);
    bool ok = rebuild_recent_resolve_range(/*tip*/remote - 1, remote,
                                           from, true, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: max-span request accepted, hi clamps to remote",
           ok && lo == from && hi == remote &&
           (hi - lo + 1) == RR_MAX_RANGE);
    return failures;
}

/* 6. A span one block past the cap is refused (cold-import's job). */
static int t_refuse_deep_replay(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    int remote = 1000000;
    int from = remote - RR_MAX_RANGE; /* span = MAX_RANGE + 1 */
    bool ok = rebuild_recent_resolve_range(/*tip*/remote - 1, remote,
                                           from, true, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: deep replay beyond cap is refused with reason",
           !ok && err[0] != '\0');
    return failures;
}

/* 7. Bad inputs are rejected. */
static int t_bad_inputs(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};

    bool null_out = rebuild_recent_resolve_range(10, 10, 0, false,
                                                 NULL, &hi,
                                                 err, sizeof(err));
    bool neg_tip  = rebuild_recent_resolve_range(-1, 10, 0, false,
                                                 &lo, &hi,
                                                 err, sizeof(err));
    bool neg_from = rebuild_recent_resolve_range(10, 10, -5, true,
                                                 &lo, &hi,
                                                 err, sizeof(err));
    RR_RUN("rr: null out / negative tip / negative from all rejected",
           !null_out && !neg_tip && !neg_from);
    return failures;
}

/* 8. When the local tip is far below a near remote but within the
 *    window, the full [lo..remote] range is returned. */
static int t_within_window(void)
{
    int failures = 0;
    int lo = -1, hi = -1;
    char err[128] = {0};
    /* tip 3125314, remote 3125315 (the live stale-1-block-fork case):
     * default lo = tip - 10, hi = remote. Small, in-window. */
    bool ok = rebuild_recent_resolve_range(3125314, 3125315,
                                           0, false, &lo, &hi,
                                           err, sizeof(err));
    RR_RUN("rr: live 1-block-fork case resolves to a tiny in-window range",
           ok && lo == 3125314 - RR_DEFAULT_MARGIN && hi == 3125315 &&
           (hi - lo + 1) <= RR_MAX_RANGE);
    return failures;
}

int test_rebuild_recent(void)
{
    int failures = 0;
    printf("\n=== rebuild_recent (recovery range/bound logic) ===\n");
    failures += t_default_lookback();
    failures += t_default_floor_zero();
    failures += t_explicit_from();
    failures += t_idempotent_at_tip();
    failures += t_window_clamp();
    failures += t_refuse_deep_replay();
    failures += t_bad_inputs();
    failures += t_within_window();
    return failures;
}
