/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * segment_corruption — the {detect, remedy, witness} healer for the sealed ROM
 * segment store. See conditions/segment_corruption.h for the symptom model.
 *
 * The pure helpers (scan_one / repair) operate on a segments directory with no
 * node state, so the detect→repair→witness flow is exercisable on a fixture.
 * The condition wrapper adds GetDataDir and the optional network-refetch seam.
 */

#include "conditions/segment_corruption.h"

#include "framework/condition.h"
#include "services/sync_monitor.h"
#include "storage/chain_segment.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/util.h"
#include "validation/main_state.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static _Atomic uint32_t g_sweep_cursor = 0;
static _Atomic int64_t  g_corrupt_first = -1;
static _Atomic int64_t  g_corrupt_count = 0;
static _Atomic int      g_remedy_calls = 0;
static _Atomic int      g_refetch_calls = 0;

/* ── Pure helpers ───────────────────────────────────────────────────────── */

enum cseg_status segment_corruption_scan_one(const char *dir, uint32_t *cursor,
                                             uint32_t *first, uint32_t *count,
                                             char *err, size_t errlen)
{
    if (first) *first = 0;
    if (count) *count = 0;

    struct chain_segment_store *store = NULL;
    enum cseg_status st = chain_segment_store_open(dir, &store, err, errlen);
    if (st != CSEG_OK)
        return st;

    uint32_t n = chain_segment_store_segment_count(store);
    if (n == 0) {
        chain_segment_store_close(store);
        return CSEG_ERR_NOT_FOUND;
    }
    uint32_t idx = cursor ? ((*cursor)++ % n) : 0;
    uint32_t f = 0, c = 0;
    chain_segment_store_segment_range(store, idx, &f, &c);
    if (first) *first = f;
    if (count) *count = c;

    st = chain_segment_store_verify_index(store, idx, err, errlen);
    chain_segment_store_close(store);
    return st;
}

enum cseg_status segment_corruption_repair(const char *dir, uint32_t first,
                                           uint32_t count,
                                           char *err, size_t errlen)
{
    char path[3200];
    snprintf(path, sizeof(path), "%s/seg-%u-%u.dat", dir, first, count);

    /* Sealed segments are 0444; unlink depends on directory perms, not the
     * file's, but relax the mode first so the removal is unambiguous. */
    (void)chmod(path, 0644);
    if (unlink(path) != 0 && errno != ENOENT) {
        if (err && errlen) snprintf(err, errlen, "unlink(%s): %s", path,
                                    strerror(errno));
        return CSEG_ERR_IO;
    }

    /* Rebuild the manifest from the survivors. Best-effort: even if another
     * segment is also corrupt (rebuild names it), THIS one is already gone and
     * reads fall back to blk*.dat. */
    char rerr[256] = {0};
    enum cseg_status rst = chain_segment_manifest_rebuild(dir, rerr, sizeof(rerr));
    if (rst != CSEG_OK)
        LOG_WARN("condition",
                 "[condition:segment_corruption] manifest rebuild after "
                 "unlink %s: %s (%s)", path, cseg_status_str(rst), rerr);

    struct stat sb;
    if (stat(path, &sb) == 0) {
        if (err && errlen) snprintf(err, errlen, "%s still present", path);
        return CSEG_ERR_IO;
    }
    return CSEG_OK;
}

/* ── Condition wrapper ──────────────────────────────────────────────────── */

static void segments_dir(char *buf, size_t buflen)
{
    char datadir[2048];
    GetDataDir(true, datadir, sizeof(datadir));
    snprintf(buf, buflen, "%s/segments", datadir);
}

static bool detect_segment_corruption(void)
{
    char dir[2560];
    segments_dir(dir, sizeof(dir));

    uint32_t cursor = atomic_load(&g_sweep_cursor);
    uint32_t first = 0, count = 0;
    char err[256] = {0};
    enum cseg_status st =
        segment_corruption_scan_one(dir, &cursor, &first, &count,
                                    err, sizeof(err));
    atomic_store(&g_sweep_cursor, cursor);

    if (st == CSEG_OK || st == CSEG_ERR_NOT_FOUND)
        return false; /* clean segment or empty store */

    /* A corrupt sealed segment — the typed blocker. The condition being active
     * IS the named blocker (visible in `dumpstate watchdog`/condition engine). */
    atomic_store(&g_corrupt_first, (int64_t)first);
    atomic_store(&g_corrupt_count, (int64_t)count);
    LOG_WARN("condition",
             "[condition:segment_corruption] seg-%u-%u corrupt: %s (%s)",
             first, count, cseg_status_str(st), err);
    return true;
}

static enum condition_remedy_result remedy_segment_corruption(void)
{
    int64_t first = atomic_load(&g_corrupt_first);
    int64_t count = atomic_load(&g_corrupt_count);
    if (first < 0 || count <= 0)
        return COND_REMEDY_SKIP;

    atomic_fetch_add(&g_remedy_calls, 1);

    char dir[2560];
    segments_dir(dir, sizeof(dir));
    char err[256] = {0};
    enum cseg_status st = segment_corruption_repair(
        dir, (uint32_t)first, (uint32_t)count, err, sizeof(err));
    if (st != CSEG_OK) {
        LOG_WARN("condition",
                 "[condition:segment_corruption] repair seg-%lld-%lld failed: "
                 "%s (%s)", (long long)first, (long long)count,
                 cseg_status_str(st), err);
        return COND_REMEDY_FAILED;
    }
    LOG_WARN("condition",
             "[condition:segment_corruption] unlinked corrupt seg-%lld-%lld; "
             "reads fall back to blk*.dat, sealer will re-seal",
             (long long)first, (long long)count);

    /* Healer seam: if the authoritative on-disk body is also unreadable, the
     * sealer cannot re-seal — re-fetch the range's frontier body from peers via
     * the height-agnostic refetch primitive. Skipped when there is no node
     * (unit test / early boot): the unlink already restored read-correctness. */
    struct main_state *ms = sync_monitor_main_state();
    if (ms) {
        struct zcl_result r = sync_monitor_queue_active_frontier_body(
            (int)first, "condition:segment_corruption");
        if (r.ok)
            atomic_fetch_add(&g_refetch_calls, 1);
        else
            LOG_WARN("condition",
                     "[condition:segment_corruption] refetch queue h=%lld "
                     "code=%d msg=%s", (long long)first, r.code, r.message);
    }
    return COND_REMEDY_OK;
}

static bool witness_segment_corruption(int64_t target_at_detect)
{
    (void)target_at_detect;
    // honest-witness-ok: re-opens the store and re-hashes the actual on-disk
    // segment via chain_segment_store_verify_index — a bounded external-state
    // read of the real filesystem, not an FSM/poison-absence flag. The symptom
    // has moved only when no segment covering the range verifies-corrupt.
    int64_t first = atomic_load(&g_corrupt_first);
    if (first < 0)
        return true;

    char dir[2560];
    segments_dir(dir, sizeof(dir));
    char err[256] = {0};
    struct chain_segment_store *store = NULL;
    if (chain_segment_store_open(dir, &store, err, sizeof(err)) != CSEG_OK)
        return false;

    bool cleared = true;
    if (chain_segment_store_covers(store, (uint32_t)first)) {
        /* A segment still covers the range — verify it is now clean. */
        uint32_t n = chain_segment_store_segment_count(store);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t f = 0, c = 0;
            chain_segment_store_segment_range(store, i, &f, &c);
            if ((uint32_t)first >= f && (uint32_t)first < f + c) {
                cleared = chain_segment_store_verify_index(
                              store, i, err, sizeof(err)) == CSEG_OK;
                break;
            }
        }
    }
    chain_segment_store_close(store);
    return cleared;
}

static struct condition c_segment_corruption = {
    .name = "segment_corruption",
    .severity = COND_WARN,
    .poll_secs = 30,
    .backoff_secs = 60,
    .max_attempts = 3,
    .detect = detect_segment_corruption,
    .remedy = remedy_segment_corruption,
    .witness = witness_segment_corruption,
    .witness_window_secs = 60,
};

void register_segment_corruption(void)
{
    (void)condition_register(&c_segment_corruption);
}
