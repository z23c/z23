/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * refold_progress — see refold_progress.h. The durable key lives in
 * progress.kv (progress_meta); a cached atomic answers the hot-path reader. */

#include "jobs/refold_progress.h"

#include "jobs/reducer_frontier.h"   /* REDUCER_FRONTIER_TRUSTED_ANCHOR */
#include "storage/progress_store.h"
#include "json/json.h"
#include "util/util.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Cached answer for the hot path. Refreshed at boot + on every mark/clear.
 * Conservative default: false (== normal boot, floor stays at the anchor). */
static _Atomic bool g_refold_in_progress = false;

/* The from-ANCHOR sub-mode cache. A from-anchor refold sets BOTH this and
 * g_refold_in_progress; this one keeps the L0 floor at the compiled anchor (the
 * fold starts AT the anchor) instead of letting refold_in_progress() drop it to
 * 0 as the from-genesis refold does. Conservative default false (normal boot). */
static _Atomic bool g_refold_from_anchor = false;

/* Cached from-anchor resume target (the durable REFOLD_FROM_ANCHOR_TARGET_KEY),
 * so the rom_compile dumper reads it lock-free instead of taking the blocking
 * progress lock on the RPC path. Seeded at boot by refold_progress_refresh and
 * republished at every mark/bump/clear. -1 = absent/unset. */
static _Atomic int32_t g_from_anchor_target = -1;

bool refold_in_progress(void)
{
    return atomic_load(&g_refold_in_progress);
}

bool refold_from_anchor_active(void)
{
    return atomic_load(&g_refold_from_anchor);
}

bool refold_from_anchor_target_cached(int32_t *out)
{
    int32_t t = atomic_load(&g_from_anchor_target);
    if (t <= 0)
        return false;
    if (out) *out = t;
    return true;
}

bool refold_progress_refresh(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("refold", "refresh: NULL db");

    uint8_t blob[1] = {0};
    size_t n = 0;
    bool found = false;
    uint8_t ablob[1] = {0};
    size_t an = 0;
    bool afound = false;
    uint8_t tbuf[4] = {0};
    size_t tn = 0;
    bool tfound = false;
    progress_store_tx_lock();
    bool ok = progress_meta_get(db, REFOLD_IN_PROGRESS_KEY,
                                blob, sizeof(blob), &n, &found);
    bool aok = progress_meta_get(db, REFOLD_FROM_ANCHOR_KEY,
                                 ablob, sizeof(ablob), &an, &afound);
    bool tok = progress_meta_get(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                 tbuf, sizeof(tbuf), &tn, &tfound);
    progress_store_tx_unlock();
    if (!ok || !aok) {
        /* On a read error keep both caches conservatively false: a stuck-true
         * cache would silently suspend the self-repair on a normal boot. */
        atomic_store(&g_refold_in_progress, false);
        atomic_store(&g_refold_from_anchor, false);
        LOG_FAIL("refold", "refresh: progress_meta_get failed");
    }

    bool on = found && n == 1 && blob[0] == 0x01;
    atomic_store(&g_refold_in_progress, on);
    bool aon = afound && an == 1 && ablob[0] == 0x01;
    atomic_store(&g_refold_from_anchor, aon);
    /* Seed the cached target (same LE int32 decode as the write path). */
    if (tok && tfound && tn == sizeof(tbuf))
        atomic_store(&g_from_anchor_target,
                     (int32_t)((uint32_t)tbuf[0] | ((uint32_t)tbuf[1] << 8) |
                               ((uint32_t)tbuf[2] << 16) |
                               ((uint32_t)tbuf[3] << 24)));
    else
        atomic_store(&g_from_anchor_target, -1);
    return true;
}

bool refold_progress_mark_started(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("refold", "mark_started: NULL db");

    const uint8_t one = 0x01;
    progress_store_tx_lock();
    bool ok = progress_meta_set(db, REFOLD_IN_PROGRESS_KEY, &one, sizeof(one));
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("refold", "mark_started: progress_meta_set failed");

    atomic_store(&g_refold_in_progress, true);
    LOG_INFO("refold",
             "from-genesis refold marked in progress — H* floor lowered to 0 "
             "and below-anchor self-repair suspended until the fold's "
             "utxo_apply cursor passes the trusted anchor (%d)",
             (int)REDUCER_FRONTIER_TRUSTED_ANCHOR);
    return true;
}

void refold_progress_boot_init(sqlite3 *db, bool mark_started)
{
    if (!db) {
        LOG_WARN("refold", "boot_init: NULL db — cache stays false");
        return;
    }
    (void)refold_progress_refresh(db);
    if (mark_started)
        (void)refold_progress_mark_started(db);
}

bool refold_progress_clear_if_crossed(sqlite3 *db, int32_t utxo_apply_cursor)
{
    if (!db)
        LOG_FAIL("refold", "clear_if_crossed: NULL db");

    /* Cheap pre-check off the cache: nothing to clear when not refolding. */
    if (!atomic_load(&g_refold_in_progress))
        return true;
    if (utxo_apply_cursor < REDUCER_FRONTIER_TRUSTED_ANCHOR)
        return true;  /* still below the floor — keep refolding */

    progress_store_tx_lock();
    /* Confirm against the durable key (the cache could be a stale true from a
     * crash window). Absent key => already cleared, nothing to do. */
    uint8_t blob[1] = {0};
    size_t n = 0;
    bool found = false;
    bool ok = progress_meta_get(db, REFOLD_IN_PROGRESS_KEY,
                                blob, sizeof(blob), &n, &found);
    if (ok && found)
        ok = progress_meta_delete(db, REFOLD_IN_PROGRESS_KEY);
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("refold", "clear_if_crossed: progress_meta read/delete failed");

    atomic_store(&g_refold_in_progress, false);
    LOG_INFO("refold",
             "from-genesis refold crossed the trusted anchor (%d) at "
             "utxo_apply cursor=%d — cleared refold_in_progress; H* floor "
             "and self-repair restored to normal",
             (int)REDUCER_FRONTIER_TRUSTED_ANCHOR, (int)utxo_apply_cursor);
    return true;
}

/* ── from-ANCHOR refold ─────────────────────────────────────────────────── */

bool refold_progress_mark_started_from_anchor(sqlite3 *db, int32_t resume_target)
{
    if (!db)
        LOG_FAIL("refold", "mark_started_from_anchor: NULL db");

    /* Store the resume target little-endian (a stable, byte-order-independent
     * int32 blob, matching the coins_applied_height encoding convention). */
    uint8_t tbuf[4] = {
        (uint8_t)(resume_target & 0xff),
        (uint8_t)((resume_target >> 8) & 0xff),
        (uint8_t)((resume_target >> 16) & 0xff),
        (uint8_t)((resume_target >> 24) & 0xff),
    };
    const uint8_t one = 0x01;
    progress_store_tx_lock();
    /* Set BOTH the shared in-progress key (so refold_in_progress() + the
     * mirror-sync guard hold) AND the from-anchor sub-mode key + target. */
    bool ok = progress_meta_set(db, REFOLD_IN_PROGRESS_KEY, &one, sizeof(one));
    if (ok)
        ok = progress_meta_set(db, REFOLD_FROM_ANCHOR_KEY, &one, sizeof(one));
    if (ok)
        ok = progress_meta_set(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                               tbuf, sizeof(tbuf));
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("refold", "mark_started_from_anchor: progress_meta_set failed");

    atomic_store(&g_refold_in_progress, true);
    atomic_store(&g_refold_from_anchor, true);
    atomic_store(&g_from_anchor_target, resume_target);
    LOG_INFO("refold",
             "from-ANCHOR refold marked in progress — H* floor HELD at the "
             "compiled anchor (%d) and below-anchor self-repair suspended until "
             "the fold's utxo_apply cursor reaches the resume target (%d)",
             (int)REDUCER_FRONTIER_TRUSTED_ANCHOR, (int)resume_target);
    return true;
}

bool refold_progress_clear_if_reached(sqlite3 *db, int32_t utxo_apply_cursor,
                                      int32_t target)
{
    if (!db)
        LOG_FAIL("refold", "clear_if_reached: NULL db");

    /* Cheap pre-check off the cache: nothing to clear when not from-anchor. */
    if (!atomic_load(&g_refold_from_anchor))
        return true;

    progress_store_tx_lock();
    /* When the caller passes target < 0, read the durable resume target written
     * by mark_started_from_anchor (the single place the LE int32 is decoded). */
    if (target < 0) {
        uint8_t tbuf[4] = {0};
        size_t tn = 0;
        bool tfound = false;
        if (progress_meta_get(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                              tbuf, sizeof(tbuf), &tn, &tfound) &&
            tfound && tn == 4)
            target = (int32_t)((uint32_t)tbuf[0] | ((uint32_t)tbuf[1] << 8) |
                               ((uint32_t)tbuf[2] << 16) |
                               ((uint32_t)tbuf[3] << 24));
    }
    if (target > 0 && utxo_apply_cursor < target) {
        progress_store_tx_unlock();
        return true;  /* still below the target — keep refolding */
    }

    /* Confirm against the durable key (the cache could be a stale true from a
     * crash window). Absent key => already cleared, nothing to do. */
    uint8_t blob[1] = {0};
    size_t n = 0;
    bool found = false;
    bool ok = progress_meta_get(db, REFOLD_FROM_ANCHOR_KEY,
                                blob, sizeof(blob), &n, &found);
    if (ok && found) {
        ok = progress_meta_delete(db, REFOLD_FROM_ANCHOR_KEY);
        if (ok)
            ok = progress_meta_delete(db, REFOLD_FROM_ANCHOR_TARGET_KEY);
        if (ok)
            ok = progress_meta_delete(db, REFOLD_IN_PROGRESS_KEY);
    }
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("refold", "clear_if_reached: progress_meta read/delete failed");

    atomic_store(&g_refold_from_anchor, false);
    atomic_store(&g_refold_in_progress, false);
    atomic_store(&g_from_anchor_target, -1);
    LOG_INFO("refold",
             "from-anchor refold reached the resume target (%d) at utxo_apply "
             "cursor=%d — cleared refold_from_anchor + refold_in_progress; H* "
             "floor and self-repair restored to normal",
             (int)target, (int)utxo_apply_cursor);
    return true;
}

bool refold_progress_bump_target(sqlite3 *db, int32_t live_tip)
{
    if (!db)
        LOG_FAIL("refold", "bump_target: NULL db");

    /* Cheap pre-check off the cache: only a from-anchor refold has a target. */
    if (!atomic_load(&g_refold_from_anchor))
        return true;
    if (live_tip < 0)
        return true;  /* nothing meaningful to raise to */

    progress_store_tx_lock();
    /* Read the durable target; absent => from-anchor refold not actually armed
     * on disk (cache stale from a crash window) — leave it alone. */
    uint8_t tbuf[4] = {0};
    size_t tn = 0;
    bool tfound = false;
    bool ok = progress_meta_get(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                tbuf, sizeof(tbuf), &tn, &tfound);
    if (ok && tfound && tn == 4) {
        int32_t stored = (int32_t)((uint32_t)tbuf[0] | ((uint32_t)tbuf[1] << 8) |
                                   ((uint32_t)tbuf[2] << 16) |
                                   ((uint32_t)tbuf[3] << 24));
        /* NEVER lower the target — only raise it to a higher live tip. */
        if (live_tip > stored) {
            uint8_t nbuf[4] = {
                (uint8_t)(live_tip & 0xff),
                (uint8_t)((live_tip >> 8) & 0xff),
                (uint8_t)((live_tip >> 16) & 0xff),
                (uint8_t)((live_tip >> 24) & 0xff),
            };
            ok = progress_meta_set(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                   nbuf, sizeof(nbuf));
            if (ok)
                atomic_store(&g_from_anchor_target, live_tip);
        }
    }
    progress_store_tx_unlock();
    if (!ok)
        LOG_FAIL("refold", "bump_target: progress_meta read/write failed");
    return true;
}

static void refold_snapshot_candidate_dump_json(struct json_value *out)
{
    char path[1100] = {0};
    const char *source = "datadir";
    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    bool path_ok = false;

    if (env_out && env_out[0]) {
        int n = snprintf(path, sizeof(path), "%s", env_out);
        path_ok = n > 0 && (size_t)n < sizeof(path);
        source = "ZCL_MINT_ANCHOR_OUT";
    } else {
        char datadir[1024] = {0};
        GetDataDir(true, datadir, sizeof(datadir));
        int n = snprintf(path, sizeof(path), "%s/utxo-anchor.snapshot",
                         datadir);
        path_ok = n > 0 && (size_t)n < sizeof(path);
    }

    struct stat st;
    bool present = path_ok && stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
                   st.st_size > 0;

    json_push_kv_str(out, "anchor_snapshot_candidate_source", source);
    json_push_kv_str(out, "anchor_snapshot_candidate_path",
                     path_ok ? path : "");
    json_push_kv_bool(out, "anchor_snapshot_candidate_stat_present", present);
    json_push_kv_int(out, "anchor_snapshot_candidate_stat_size",
                     present ? (int64_t)st.st_size : 0);
    json_push_kv_bool(out, "anchor_snapshot_verified", false);
    json_push_kv_str(out, "anchor_snapshot_verification",
                     "not checked by dumpstate; boot verifies full SHA3/count "
                     "before use");
}

/* ── Native dump-state introspection ───────────────────────────────────────
 *
 * See CLAUDE.md "Adding state introspection". Read-only: this dumper observes
 * the cached atomics and the durable progress.kv keys; it never marks, clears,
 * or otherwise mutates refold state. `key` is unused. Reentrant-safe — the
 * cached reads take no lock, and the durable peek takes progress_store_tx_lock
 * NON-BLOCKING (trylock): the reducer holds that lock around each fold batch,
 * so a diagnostics thread must never block on it (it would queue an RPC worker
 * behind the fold). When the fold owns the lock the durable peek is skipped and
 * labeled progress_store_busy; the lock-free cached answers are always present.
 * Mirrors the A2 stage-dump trylock fix. */
bool refold_progress_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("refold", "dump_state_json: NULL out");
    json_set_object(out);

    /* Cheap, lock-free cached answers — the same values the hot path reads. */
    bool in_progress = atomic_load(&g_refold_in_progress);
    bool from_anchor = atomic_load(&g_refold_from_anchor);
    json_push_kv_bool(out, "in_progress", in_progress);
    json_push_kv_bool(out, "from_anchor", from_anchor);

    /* The compiled SHA3 UTXO checkpoint the from-genesis fold must re-cross
     * before the H* floor and below-anchor self-repair return to normal. */
    json_push_kv_int(out, "trusted_anchor",
                     (int64_t)REDUCER_FRONTIER_TRUSTED_ANCHOR);
    refold_snapshot_candidate_dump_json(out);

    /* Durable view: peek the persisted keys so a restart mid-fold is visible
     * even before the cache is refreshed. Best-effort — when the progress
     * store is not open we report the cached answers only. */
    sqlite3 *db = progress_store_db();
    json_push_kv_bool(out, "durable_store_open", db != NULL);
    /* Non-blocking durable peek: the reducer holds progress_store_tx_lock
     * around each fold batch (heavily so during the from-genesis/from-anchor
     * refold this dumper reports on), so a BLOCKING acquire here would queue an
     * RPC worker behind the fold and take the observability front door dark
     * exactly when it is most needed. Trylock and, when the fold owns the lock,
     * report busy and emit only the lock-free cached answers above. */
    bool durable_ok = db && progress_store_tx_trylock();
    json_push_kv_str(out, "durable_store_status",
                     !db ? "progress_store_unavailable"
                         : durable_ok ? "available" : "progress_store_busy");
    if (db && !durable_ok)
        json_push_kv_bool(out, "durable_snapshot_retryable", true);
    if (durable_ok) {
        uint8_t ip[1] = {0};
        size_t ip_n = 0;
        bool ip_found = false;
        uint8_t fa[1] = {0};
        size_t fa_n = 0;
        bool fa_found = false;
        uint8_t tbuf[4] = {0};
        size_t t_n = 0;
        bool t_found = false;
        bool ip_ok = progress_meta_get(db, REFOLD_IN_PROGRESS_KEY,
                                       ip, sizeof(ip), &ip_n, &ip_found);
        bool fa_ok = progress_meta_get(db, REFOLD_FROM_ANCHOR_KEY,
                                       fa, sizeof(fa), &fa_n, &fa_found);
        bool t_ok = progress_meta_get(db, REFOLD_FROM_ANCHOR_TARGET_KEY,
                                      tbuf, sizeof(tbuf), &t_n, &t_found);
        progress_store_tx_unlock();

        bool durable_in_progress = ip_ok && ip_found && ip_n == 1 &&
                                   ip[0] == 0x01;
        bool durable_from_anchor = fa_ok && fa_found && fa_n == 1 &&
                                   fa[0] == 0x01;
        json_push_kv_bool(out, "durable_in_progress", durable_in_progress);
        json_push_kv_bool(out, "durable_from_anchor", durable_from_anchor);

        /* The from-anchor resume target tip, decoded little-endian (the same
         * encoding mark_started_from_anchor writes). Absent on a normal boot
         * or a from-genesis refold. */
        if (t_ok && t_found && t_n == 4) {
            int32_t target = (int32_t)((uint32_t)tbuf[0] |
                                       ((uint32_t)tbuf[1] << 8) |
                                       ((uint32_t)tbuf[2] << 16) |
                                       ((uint32_t)tbuf[3] << 24));
            json_push_kv_int(out, "from_anchor_target_tip", (int64_t)target);
        } else {
            json_push_kv_bool(out, "from_anchor_target_tip_present", false);
        }
    }
    return true;
}

#ifdef ZCL_TESTING
void refold_progress_test_set_cached(bool in_progress)
{
    atomic_store(&g_refold_in_progress, in_progress);
}
#endif
