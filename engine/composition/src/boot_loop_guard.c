/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_loop_guard — implementation. See config/boot_loop_guard.h.
 */

#include "config/boot_loop_guard.h"

#include "models/database.h"
#include "platform/time_compat.h"
#include "services/binary_ab_fallback.h"
#include "services/chain_tip_watchdog.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/shutdown_stagewatch.h"
#include "util/supervisor_backstop.h"
#include "json/json.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t g_bootloop_lock = PTHREAD_MUTEX_INITIALIZER;
static bool    g_have_state = false;
static int64_t g_last_count = 0;
static bool    g_last_fired = false;
static char    g_last_exit_reason[SHUTDOWN_EXIT_REASON_MAX];
static bool    g_last_exit_forced = false;

/* Derive "<datadir>" from node.db's own path ("<datadir>/node.db", the
 * convention every node_db_open() call site in the codebase uses). Writes
 * an empty string (never a partial/garbage path) when `ndb->path` has no
 * '/' (e.g. a ":memory:" test fixture) — callers treat an empty datadir as
 * "no exit-reason breadcrumb available", never a crash. */
static void bootloop_datadir_from_ndb(const struct node_db *ndb,
                                      char *out, size_t n)
{
    if (n > 0) out[0] = '\0';
    if (!ndb || ndb->path[0] == '\0' || n == 0)
        return;
    const char *slash = strrchr(ndb->path, '/');
    if (!slash)
        return;
    size_t len = (size_t)(slash - ndb->path);
    if (len >= n) len = n - 1;
    memcpy(out, ndb->path, len);
    out[len] = '\0';
}

void boot_loop_guard_check(struct node_db *ndb)
{
    if (!ndb || !ndb->open) {
        LOG_WARN("boot_loop_guard", "check: node.db unavailable — skipped");
        return;
    }

    int64_t now = platform_time_wall_unix();
    int64_t window_start = now - (int64_t)BOOT_LOOP_GUARD_WINDOW_MINUTES * 60;

    int64_t count = 0;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(DISTINCT boot_epoch) FROM boot_stage_timings "
            "WHERE boot_epoch >= ?", -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(s, 1, window_start);
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            count = sqlite3_column_int64(s, 0);
    } else {
        LOG_WARN("boot_loop_guard", "check: query prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
    }
    if (s) sqlite3_finalize(s);

    char datadir[1024];
    bootloop_datadir_from_ndb(ndb, datadir, sizeof(datadir));

    char exit_reason[SHUTDOWN_EXIT_REASON_MAX] = {0};
    bool exit_forced = false;
    bool have_reason = datadir[0] &&
        shutdown_stagewatch_read_exit_reason(datadir, exit_reason,
                                             sizeof(exit_reason), &exit_forced);

    /* A self-respawn re-execs the SAME binary in-process (main.c), bypassing
     * the external native launcher entirely, so its own streak
     * increment never sees it — count it here instead. */
    if (have_reason && strncmp(exit_reason, "self_respawn", 12) == 0)
        binary_ab_note_self_respawn_exit_env();

    bool fired = count >= BOOT_LOOP_GUARD_THRESHOLD;

    pthread_mutex_lock(&g_bootloop_lock);
    g_have_state = true;
    g_last_count = count;
    g_last_fired = fired;
    snprintf(g_last_exit_reason, sizeof(g_last_exit_reason), "%s",
             have_reason ? exit_reason : "unknown");
    g_last_exit_forced = exit_forced;
    pthread_mutex_unlock(&g_bootloop_lock);

    if (!fired)
        return;

    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "count=%lld window_min=%d threshold=%d last_exit_reason=%s%s",
             (long long)count, BOOT_LOOP_GUARD_WINDOW_MINUTES,
             BOOT_LOOP_GUARD_THRESHOLD,
             have_reason ? exit_reason : "unknown",
             exit_forced ? " (shutdown-watchdog-forced)" : "");
    if (!blocker_init(&r, BOOT_LOOP_GUARD_BLOCKER_ID, BOOT_LOOP_GUARD_BLOCKER_OWNER,
                      BLOCKER_TRANSIENT, reason))
        return;   /* blocker_init already logged via LOG_FAIL */
    blocker_set(&r);
    LOG_WARN("boot_loop_guard",
             "boot.restart_loop: %lld boots in the last %d minutes "
             "(threshold=%d) — last exit reason=%s%s — boot proceeding, "
             "named blocker raised",
             (long long)count, BOOT_LOOP_GUARD_WINDOW_MINUTES,
             BOOT_LOOP_GUARD_THRESHOLD, have_reason ? exit_reason : "unknown",
             exit_forced ? " (forced)" : "");
}

void boot_loop_guard_note_shutdown_intent(void)
{
    bool respawn_tip_wd   = chain_tip_watchdog_respawn_requested();
    bool respawn_backstop = supervisor_backstop_respawn_requested();
    const char *exit_reason = SHUTDOWN_EXIT_REASON_OPERATOR;
    if (respawn_tip_wd && respawn_backstop)
        exit_reason = SHUTDOWN_EXIT_REASON_SELF_RESPAWN_BOTH;
    else if (respawn_tip_wd)
        exit_reason = SHUTDOWN_EXIT_REASON_SELF_RESPAWN_TIP_WATCHDOG;
    else if (respawn_backstop)
        exit_reason = SHUTDOWN_EXIT_REASON_SELF_RESPAWN_SUPERVISOR_BACKSTOP;
    shutdown_stagewatch_write_exit_reason(exit_reason);
}

bool boot_loop_guard_dump_state_json(struct json_value *out)
{
    if (!out) return false;

    pthread_mutex_lock(&g_bootloop_lock);
    bool    have   = g_have_state;
    int64_t count  = g_last_count;
    bool    fired  = g_last_fired;
    bool    forced = g_last_exit_forced;
    char    reason[SHUTDOWN_EXIT_REASON_MAX];
    snprintf(reason, sizeof(reason), "%s", have ? g_last_exit_reason : "");
    pthread_mutex_unlock(&g_bootloop_lock);

    struct json_value rl = {0};
    json_set_object(&rl);
    json_push_kv_int (&rl, "count", count);
    json_push_kv_int (&rl, "window_minutes", BOOT_LOOP_GUARD_WINDOW_MINUTES);
    json_push_kv_int (&rl, "threshold", BOOT_LOOP_GUARD_THRESHOLD);
    json_push_kv_bool(&rl, "armed", have);
    json_push_kv_bool(&rl, "fired", fired);
    json_push_kv_str (&rl, "last_exit_reason", reason);
    json_push_kv_bool(&rl, "last_exit_forced", forced);
    json_push_kv(out, "restart_loop", &rl);
    json_free(&rl);
    return true;
}

#ifdef ZCL_TESTING
void boot_loop_guard_reset_for_testing(void)
{
    pthread_mutex_lock(&g_bootloop_lock);
    g_have_state = false;
    g_last_count = 0;
    g_last_fired = false;
    g_last_exit_reason[0] = '\0';
    g_last_exit_forced = false;
    pthread_mutex_unlock(&g_bootloop_lock);
}
#endif
