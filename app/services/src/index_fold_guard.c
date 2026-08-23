// one-result-type-ok:gate-predicate — this file owns no orchestration result.
// Its only bool export (index_fold_disk_ok) is a simple go/no-go gate; the
// other exports are void blocker-raisers/clearers and a test setter. There is
// no fallible service lifecycle whose failure reason must travel via
// struct zcl_result — every failure surfaces as a NAMED util/blocker.h record.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * index_fold_guard — see services/index_fold_guard.h. Two safety rails shared
 * by the address_index and txindex index folds; each names a typed blocker
 * rather than failing silently or spinning. NOT a repair rung: it never
 * re-derives or heals state — it REFUSES to start the fold (disk headroom) or
 * NAMES a structural coverage floor (snapshot seed), so the writer never
 * produces bad state in the first place. */

#include "services/index_fold_guard.h"

#include "jobs/reducer_frontier.h"          /* REDUCER_TRUSTED_BASE_HEIGHT_KEY */
#include "services/disk_monitor.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* Test-overridable free-space floor. <0 means "use the compiled default". */
static _Atomic int64_t g_min_free_override = -1;

void index_fold_set_min_free_for_test(int64_t bytes)
{
    atomic_store(&g_min_free_override, bytes);
}

static int64_t min_free_bytes(void)
{
    int64_t o = atomic_load(&g_min_free_override);
    return o >= 0 ? o : INDEX_FOLD_MIN_FREE_BYTES;
}

/* Build "<index_id>.<suffix>" into out (bounded). */
static void mk_blocker_id(char *out, size_t cap, const char *index_id,
                          const char *suffix)
{
    snprintf(out, cap, "%s.%s", index_id, suffix);
}

/* ── Keep-alive, not a horn ───────────────────────────────────────────
 * The seed floor is structural: every backfill tick re-observes it, so the
 * blocker's fire_count climbs without bound (11,666 on the canonical node,
 * 2026-07-27) while nothing about the situation changes. Historically this
 * site logged NOTHING to avoid a per-tick storm, which left an operator
 * tailing node.log with no trace of a condition that had been standing for
 * days.
 *
 * Neither extreme is right. log_throttle gives the established middle: emit
 * on first observation and on any CHANGE of (index, absent height, seed
 * floor), then one keep-alive per hour carrying the suppressed-repeat count.
 * The line therefore never reads as new, and the alarm is never silent.
 *
 * One throttle per index: the guard is shared by address_index, txindex and
 * op_return_index, and a single throttle would see the key flip every pass
 * and emit for all three every tick — worse than no throttle at all. The
 * slot is chosen by a hash of the index id and the KEY also carries that
 * hash, so a slot collision costs one extra emit, never a wrong claim. */
#define INDEX_FOLD_SEED_KEEPALIVE_SECS 3600
#define INDEX_FOLD_THROTTLE_SLOTS      4

static struct log_throttle g_seed_throttle[INDEX_FOLD_THROTTLE_SLOTS] = {
    LOG_THROTTLE_INIT, LOG_THROTTLE_INIT, LOG_THROTTLE_INIT, LOG_THROTTLE_INIT
};

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; s && *s; s++) {
        h ^= (uint64_t)(unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

bool index_fold_disk_ok(const char *index_id, const char *subsys,
                            const char *datadir)
{
    if (!index_id || !subsys || !datadir || !datadir[0])
        return true;                         /* nothing to measure — fail open */

    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.disk_low */
    mk_blocker_id(id, sizeof(id), index_id, "disk_low");

    /* The running disk_monitor already owns the hard CRITICAL refuse; a backfill
     * must not add bytes while it is tripped. */
    bool critical = disk_monitor_is_critical();

    /* Conservative backfill-specific floor: a fresh statvfs of the datadir FS.
     * A statvfs error returns <0 and we fail OPEN (the monitor is the authority
     * on a genuinely full disk; we don't want a transient stat error to wedge
     * the catalog). */
    int64_t free_bytes = disk_monitor_free_bytes(datadir);
    int64_t floor = min_free_bytes();
    bool low = free_bytes >= 0 && free_bytes < floor;

    if (critical || low) {
        struct blocker_record r;
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "disk headroom too low to start/continue the %s backfill: "
                 "free=%lld bytes, floor=%lld bytes, disk_monitor_critical=%d "
                 "on %s — holding the index fold so consensus writes keep their "
                 "last bytes. Auto-clears when free space returns above the "
                 "floor; free space (or -%s=0 to disable this index).",
                 index_id, (long long)free_bytes, (long long)floor,
                 (int)critical, datadir, index_id);
        if (blocker_init(&r, id, subsys, BLOCKER_RESOURCE, reason))
            (void)blocker_set(&r);
        return false;
    }

    blocker_clear(id);                       /* healthy — no-op if never set */
    return true;
}

/* Ticks that yielded rather than block behind the reducer drive.
 * Non-zero is the yield WORKING, not a fault. */
static _Atomic uint64_t g_seed_floor_yields = 0;

uint64_t index_fold_seed_floor_yields(void)
{
    return atomic_load(&g_seed_floor_yields);
}

/* Read REDUCER_TRUSTED_BASE_HEIGHT_KEY (8-byte LE) from progress_meta.
 * Returns true on a clean read; *found=false when the key is absent (a
 * from-genesis datadir with no snapshot seed).
 *
 * LOCK-ORDER LAW — this MUST NOT take a blocking progress-store lock.
 * Callers run on the supervisor tick-runner thread, which dispatches every
 * child synchronously and stamps its heartbeat only BETWEEN rounds.
 * progress_meta_get_blob_exact() acquires progress_store_tx_lock(), a plain
 * blocking pthread mutex the reducer drive holds across a fold commit —
 * routinely 120-330 s at tip. Blocking here freezes the runner heartbeat for
 * that whole window, boot_sd_watchdog withholds the systemd keepalive, and
 * systemd SIGABRTs the node at the 120 s WatchdogSec limit. That is the
 * 2026-07-27 crash loop: seven kills in forty minutes on a node that was
 * folding blocks correctly the entire time — the folder was fine, the
 * OBSERVER jammed behind it and its silence got the worker killed.
 *
 * So: TRY, and yield the tick if the reducer owns the lock. The mutex is
 * recursive, so holding it here composes with the inner acquire. Yielding is
 * free — the caller leaves the blocker exactly as it found it and the next
 * tick is 2 s away. Same discipline as reducer_drive_watchdog.c:442
 * ("NEVER a blocking coins/progress lock"). Regression-tested in
 * test_address_index.c: the pre-fix code DEADLOCKS that case. */
static bool read_seed_floor(sqlite3 *db, int64_t *floor_out, bool *found)
{
    *floor_out = -1;
    *found = false;
    if (!db)
        return false;
    if (!progress_store_tx_trylock()) {
        atomic_fetch_add(&g_seed_floor_yields, 1);
        return false;                        /* reducer owns it — leave as-is */
    }
    uint8_t blob[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!progress_meta_get_blob_exact(db, REDUCER_TRUSTED_BASE_HEIGHT_KEY,
                                      blob, sizeof(blob), &n, &present)) {
        progress_store_tx_unlock();
        LOG_WARN("index_backfill",
                 "trusted_base_height read failed — leaving seed blocker as-is");
        return false;
    }
    progress_store_tx_unlock();              /* nothing below touches `db` */
    if (!present)
        return true;                         /* clean read, no seed floor */
    if (n != sizeof(blob)) {
        LOG_WARN("index_backfill",
                 "trusted_base blob malformed (len=%zu) — treating as no floor",
                 n);
        return true;
    }
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | blob[i];              /* little-endian */
    *floor_out = (int64_t)v;
    *found = true;
    return true;
}

void index_fold_note_absent_body(const char *index_id, const char *subsys,
                                     sqlite3 *db, int64_t absent_height)
{
    if (!index_id || !subsys)
        return;

    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.below_snapshot_seed */
    mk_blocker_id(id, sizeof(id), index_id, "below_snapshot_seed");

    /* A4: the snapshot-seed floor (REDUCER_TRUSTED_BASE_HEIGHT_KEY) is a KERNEL
     * fact written by the reducer to consensus.db. Read it from the kernel
     * authority, NOT the projection fold handle `db` the caller passes
     * (progress.kv holds only address_index/txindex and has no progress_meta). */
    (void)db;
    int64_t seed_floor = -1;
    bool have_seed = false;
    if (!read_seed_floor(progress_store_db(), &seed_floor, &have_seed))
        return;                              /* DB read error — leave as-is */

    if (!have_seed || absent_height > seed_floor) {
        /* No snapshot seed, or the hole is ABOVE the seed floor: this is a
         * transient/genuine gap the service's own coverage_blocked flag already
         * surfaces. Not a structural below-seed floor. */
        blocker_clear(id);
        log_throttle_reset(
            &g_seed_throttle[fnv1a(index_id) % INDEX_FOLD_THROTTLE_SLOTS]);
        return;
    }

    /* absent_height <= seed_floor: bodies below the snapshot seed are
     * structurally absent; the forward-only fold can never cross the floor.
     * Name it so the operator sees a DEPENDENCY on the historical body backfill
     * rather than a silent spin. */
    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%s backfill cannot fold at height %lld: the block body is absent "
             "at/below the snapshot-seed floor (reducer_trusted_base_height=%lld). "
             "Bodies below the seed were never downloaded on this snapshot-seeded "
             "datadir, so this rebuildable index has no source. Not an error and "
             "not a consensus stall. A PERSON decides: backfill the pre-seed "
             "bodies (costs time+bandwidth) or accept partial coverage (-%s=0). "
             "See operator_decision in `dumpstate blocker`.",
             index_id, (long long)absent_height, (long long)seed_floor,
             index_id);
    /* No escape action and no retry budget, deliberately and explicitly: there
     * is nothing safe for the node to attempt. The hand-off is the remedy —
     * `*.below_snapshot_seed` is bound OWNER in blocker_remedy_bindings.def and
     * carries its decision text in blocker_operator_decisions.def, both of
     * which `dumpstate blocker` now renders per blocker. */
    if (blocker_init(&r, id, subsys, BLOCKER_DEPENDENCY, reason)) {
        r.escape_deadline_secs = 0;
        r.retry_budget = 0;
        (void)blocker_set(&r);
    }

    uint64_t idh = fnv1a(index_id);
    struct log_throttle *t = &g_seed_throttle[idh % INDEX_FOLD_THROTTLE_SLOTS];
    uint64_t key = idh ^ ((uint64_t)absent_height * 1099511628211ULL) ^
                   ((uint64_t)seed_floor << 1);
    uint64_t reps = 0;
    if (log_throttle_should_emit(t, key, platform_time_wall_unix(),
                                 INDEX_FOLD_SEED_KEEPALIVE_SECS, &reps)) {
        LOG_INFO("index_backfill",
                 "[%s] standing coverage floor: body absent at h=%lld, "
                 "seed_floor=%lld — awaiting an operator decision (backfill "
                 "pre-seed bodies, or accept partial coverage). %llu identical "
                 "observation(s) suppressed since the last line.",
                 index_id, (long long)absent_height, (long long)seed_floor,
                 (unsigned long long)reps);
    }
}

bool index_fold_snapshot_seed_floor(int64_t *floor_out)
{
    int64_t floor = -1;
    bool found = false;
    bool ok = read_seed_floor(progress_store_db(), &floor, &found);
    if (floor_out) *floor_out = (ok && found) ? floor : -1;
    return ok && found;
}

void index_fold_declare_partial_coverage(const char *index_id,
                                         const char *subsys,
                                         int64_t base_height,
                                         int64_t seed_floor)
{
    if (!index_id || !subsys)
        return;

    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.partial_coverage */
    mk_blocker_id(id, sizeof(id), index_id, "partial_coverage");

    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%s covers heights %lld and up ONLY. This datadir was seeded from "
             "a UTXO snapshot at reducer_trusted_base_height=%lld, so bodies "
             "below that floor were never downloaded and this projection has no "
             "source for them. The index has adopted the floor as its declared "
             "base (base_height/base_digest travel with the digest) and folds "
             "forward normally — it is NOT stalled. A PERSON decides whether to "
             "backfill the pre-seed bodies. See operator_decision.",
             index_id, (long long)base_height, (long long)seed_floor);
    /* No escape action and no retry budget, deliberately: the node cannot
     * conjure bodies it never downloaded, and fabricating rows for them would
     * be inventing data. The hand-off IS the remedy (OWNER-bound). */
    if (blocker_init(&r, id, subsys, BLOCKER_DEPENDENCY, reason)) {
        r.escape_deadline_secs = 0;
        r.retry_budget = 0;
        (void)blocker_set(&r);
    }

    /* The declaration supersedes the spin: one fact, one name. */
    index_fold_clear_seed_blocker(index_id);

    LOG_INFO("index_backfill",
             "[%s] declared partial coverage: base_height=%lld "
             "(snapshot seed floor %lld) — folding forward from the base; "
             "pre-seed history is out of range by declaration.",
             index_id, (long long)base_height, (long long)seed_floor);
}

void index_fold_clear_partial_coverage(const char *index_id)
{
    if (!index_id)
        return;
    char id[BLOCKER_ID_MAX];
    mk_blocker_id(id, sizeof(id), index_id, "partial_coverage");
    blocker_clear(id);
}

void index_fold_note_unreadable_body(const char *index_id, const char *subsys,
                                     int64_t height, uint64_t attempts)
{
    if (!index_id || !subsys)
        return;

    char id[BLOCKER_ID_MAX];
    /* blocker-id: *.body_unreadable */
    mk_blocker_id(id, sizeof(id), index_id, "body_unreadable");

    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "%s backfill cannot fold at height %lld: the block index flags "
             "BLOCK_HAVE_DATA and names an (nFile,nDataPos), but the bytes "
             "there do not read back as that block — a torn import, or a "
             "blk*.dat shared with a foreign writer that overwrote the "
             "indexed record. %llu consecutive re-reads have failed "
             "identically; nothing in this process repairs a height this far "
             "below the fold frontier, so the retry is now backed off rather "
             "than run every tick. A PERSON decides: re-point the index at a "
             "surviving copy (block_index_repair_pos_from_disk), clear "
             "HAVE_DATA so the body is re-fetched, or accept partial "
             "coverage. See operator_decision in `dumpstate blocker`.",
             index_id, (long long)height, (unsigned long long)attempts);
    /* No escape action and no retry budget, deliberately: the node cannot
     * re-derive bytes that are not on disk, and the ONE thing it could try
     * (a hash-targeted rescan) belongs to the have_data_unreadable Condition,
     * not to a projection backfill. The hand-off IS the remedy (OWNER-bound). */
    if (blocker_init(&r, id, subsys, BLOCKER_DEPENDENCY, reason)) {
        r.escape_deadline_secs = 0;
        r.retry_budget = 0;
        (void)blocker_set(&r);
    }
}

void index_fold_clear_unreadable_body(const char *index_id)
{
    if (!index_id)
        return;
    char id[BLOCKER_ID_MAX];
    mk_blocker_id(id, sizeof(id), index_id, "body_unreadable");
    blocker_clear(id);
}

void index_fold_clear_seed_blocker(const char *index_id)
{
    if (!index_id)
        return;
    char id[BLOCKER_ID_MAX];
    mk_blocker_id(id, sizeof(id), index_id, "below_snapshot_seed");
    blocker_clear(id);
    /* The condition ENDED — re-arm so a later recurrence emits at once with a
     * zeroed suppressed count instead of waiting out the keep-alive window. */
    log_throttle_reset(
        &g_seed_throttle[fnv1a(index_id) % INDEX_FOLD_THROTTLE_SLOTS]);
}
