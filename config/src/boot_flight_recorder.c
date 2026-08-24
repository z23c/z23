/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_flight_recorder — implementation. See config/boot_flight_recorder.h.
 */

#include "config/boot_flight_recorder.h"

#include "config/boot_loop_guard.h"
#include "config/runtime.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "json/json.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define BFR_STAGE_NAME_MAX 40

struct bfr_mark {
    char stage[BFR_STAGE_NAME_MAX];
    int64_t ms;
};

static pthread_mutex_t g_bfr_lock = PTHREAD_MUTEX_INITIALIZER;
static struct bfr_mark g_bfr_marks[BOOT_FLIGHT_RECORDER_MAX_STAGES];
static size_t g_bfr_count = 0;
static bool g_bfr_overflow_warned = false;

int64_t boot_mark_step(int64_t t0, const char *done, const char *next)
{
    struct timespec ts;
    platform_time_monotonic_timespec(&ts);
    int64_t now = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    printf("[boot]   %-28s %lldms\n", done, (long long)(now - t0));
    if (next) boot_step_enter(next); else boot_step_done();
    return now;
}

void boot_flight_recorder_mark(const char *stage, int64_t ms)
{
    if (!stage || !*stage) return;
    pthread_mutex_lock(&g_bfr_lock);
    /* A stage name already buffered this boot (e.g. a retried step) just
     * overwrites its entry — the most recent timing for a repeated stage
     * is the interesting one, and this keeps the buffer from filling on a
     * step that legitimately runs more than once. */
    for (size_t i = 0; i < g_bfr_count; i++) {
        if (strncmp(g_bfr_marks[i].stage, stage, BFR_STAGE_NAME_MAX) == 0) {
            g_bfr_marks[i].ms = ms;
            pthread_mutex_unlock(&g_bfr_lock);
            return;
        }
    }
    if (g_bfr_count >= BOOT_FLIGHT_RECORDER_MAX_STAGES) {
        if (!g_bfr_overflow_warned) {
            g_bfr_overflow_warned = true;
            LOG_WARN("boot_flight", "mark buffer full (cap=%d) — dropping '%s'",
                     BOOT_FLIGHT_RECORDER_MAX_STAGES, stage);
        }
        pthread_mutex_unlock(&g_bfr_lock);
        return;
    }
    struct bfr_mark *m = &g_bfr_marks[g_bfr_count++];
    size_t n = strlen(stage);
    if (n >= BFR_STAGE_NAME_MAX) n = BFR_STAGE_NAME_MAX - 1;
    memcpy(m->stage, stage, n);
    m->stage[n] = '\0';
    m->ms = ms;
    pthread_mutex_unlock(&g_bfr_lock);
}

#ifdef ZCL_TESTING
void boot_flight_recorder_reset_buffer_for_testing(void)
{
    pthread_mutex_lock(&g_bfr_lock);
    g_bfr_count = 0;
    g_bfr_overflow_warned = false;
    pthread_mutex_unlock(&g_bfr_lock);
}
#endif

static bool bfr_ensure_schema(struct node_db *ndb)
{
    return node_db_exec(ndb,
        "CREATE TABLE IF NOT EXISTS boot_stage_timings ("
        " boot_epoch INTEGER NOT NULL,"
        " stage      TEXT    NOT NULL,"
        " ms         INTEGER NOT NULL,"
        " ts         INTEGER NOT NULL,"
        " PRIMARY KEY (boot_epoch, stage))");
}

/* Approximate median ms for `stage` across every durably retained boot
 * (there is no MEDIAN() aggregate in SQLite): the middle row of the ms-
 * ordered set, upper-middle on an even count. Returns false (out=0) if
 * fewer than 3 samples exist — too little history to trust a median. */
static bool bfr_median_for_stage(sqlite3 *db, const char *stage, int64_t *out)
{
    *out = 0;
    sqlite3_stmt *cnt = NULL;
    int64_t n = 0;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM boot_stage_timings WHERE stage=?",
            -1, &cnt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(cnt, 1, stage, -1, SQLITE_STATIC);
    if (AR_STEP_ROW_READONLY(cnt) == SQLITE_ROW) n = sqlite3_column_int64(cnt, 0);
    sqlite3_finalize(cnt);
    if (n < 3) return false;

    sqlite3_stmt *med = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ms FROM boot_stage_timings WHERE stage=? "
            "ORDER BY ms LIMIT 1 OFFSET ?", -1, &med, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(med, 1, stage, -1, SQLITE_STATIC);
    sqlite3_bind_int64(med, 2, n / 2);
    bool ok = false;
    if (AR_STEP_ROW_READONLY(med) == SQLITE_ROW) {
        *out = sqlite3_column_int64(med, 0);
        ok = true;
    }
    sqlite3_finalize(med);
    return ok;
}

/* max(5000ms, 4 * median) breach → raise the named, non-fatal blocker. */
static void bfr_check_regression(const char *stage, int64_t ms, int64_t median)
{
    int64_t threshold = median * 4;
    if (threshold < 5000) threshold = 5000;
    if (ms <= threshold) return;

    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "stage=%s ms=%lld median=%lld threshold=%lld",
             stage, (long long)ms, (long long)median, (long long)threshold);
    if (!blocker_init(&r, "boot.stage_regression", "boot",
                      BLOCKER_TRANSIENT, reason))
        return;
    blocker_set(&r);
    LOG_WARN("boot_flight",
             "stage regression: %s took %lldms (median %lldms, "
             "threshold %lldms) — boot proceeding, named blocker raised",
             stage, (long long)ms, (long long)median, (long long)threshold);
}

static void bfr_persist_and_prune(struct node_db *ndb, int64_t boot_epoch,
                                  const struct bfr_mark *marks, size_t count)
{
    int64_t ts = platform_time_wall_unix();
    sqlite3_stmt *ins = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT OR REPLACE INTO boot_stage_timings"
            "(boot_epoch,stage,ms,ts) VALUES (?,?,?,?)",
            -1, &ins, NULL) != SQLITE_OK) {
        LOG_WARN("boot_flight", "insert prepare failed: %s",
                 sqlite3_errmsg(ndb->db));
        return;
    }
    for (size_t i = 0; i < count; i++) {
        sqlite3_reset(ins);
        sqlite3_bind_int64(ins, 1, boot_epoch);
        sqlite3_bind_text(ins, 2, marks[i].stage, -1, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 3, marks[i].ms);
        sqlite3_bind_int64(ins, 4, ts);
        if (AR_STEP_WRITE(ins) != SQLITE_DONE)
            LOG_WARN("boot_flight", "insert failed stage=%s: %s",
                     marks[i].stage, sqlite3_errmsg(ndb->db));
    }
    sqlite3_finalize(ins);

    char prune_sql[256];
    snprintf(prune_sql, sizeof(prune_sql),
             "DELETE FROM boot_stage_timings WHERE boot_epoch NOT IN "
             "(SELECT DISTINCT boot_epoch FROM boot_stage_timings "
             "ORDER BY boot_epoch DESC LIMIT %d)",
             BOOT_FLIGHT_RECORDER_MAX_BOOTS);
    if (ar_exec_write_sql(ndb->db, prune_sql) != SQLITE_OK)
        LOG_WARN("boot_flight", "prune failed: %s", sqlite3_errmsg(ndb->db));
}

void boot_flight_recorder_finish(struct node_db *ndb)
{
    if (!ndb || !ndb->open) {
        LOG_WARN("boot_flight", "finish: node.db unavailable — marks not persisted");
        return;
    }

    struct bfr_mark marks[BOOT_FLIGHT_RECORDER_MAX_STAGES];
    size_t count;
    pthread_mutex_lock(&g_bfr_lock);
    count = g_bfr_count;
    memcpy(marks, g_bfr_marks, count * sizeof(marks[0]));
    g_bfr_count = 0;
    g_bfr_overflow_warned = false;
    pthread_mutex_unlock(&g_bfr_lock);

    if (count == 0) return;
    if (!bfr_ensure_schema(ndb)) {
        LOG_WARN("boot_flight", "finish: schema create failed — marks not persisted");
        return;
    }

    /* Regression check FIRST — against history that does not yet include
     * this boot's own rows. */
    for (size_t i = 0; i < count; i++) {
        int64_t median = 0;
        if (bfr_median_for_stage(ndb->db, marks[i].stage, &median))
            bfr_check_regression(marks[i].stage, marks[i].ms, median);
    }

    int64_t boot_epoch = platform_time_wall_unix();
    bfr_persist_and_prune(ndb, boot_epoch, marks, count);

    /* E2 boot-loop-failsafe: this boot's own row is now persisted (just
     * above), so the boot-loop detector's window count includes it. See
     * config/boot_loop_guard.h for the incident this closes. */
    boot_loop_guard_check(ndb);
}

bool boot_flight_recorder_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;

    struct node_db *ndb = app_runtime_node_db();
    struct json_value stages = {0};
    json_set_array(&stages);
    int64_t last_epoch = -1;

    if (ndb && ndb->open) {
        sqlite3_stmt *ep = NULL;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT MAX(boot_epoch) FROM boot_stage_timings",
                -1, &ep, NULL) == SQLITE_OK &&
            AR_STEP_ROW_READONLY(ep) == SQLITE_ROW &&
            sqlite3_column_type(ep, 0) != SQLITE_NULL) {
            last_epoch = sqlite3_column_int64(ep, 0);
        }
        if (ep) sqlite3_finalize(ep);

        if (last_epoch >= 0) {
            sqlite3_stmt *s = NULL;
            if (sqlite3_prepare_v2(ndb->db,
                    "SELECT stage, ms FROM boot_stage_timings "
                    "WHERE boot_epoch=? ORDER BY stage",
                    -1, &s, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(s, 1, last_epoch);
                while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                    const unsigned char *stage = sqlite3_column_text(s, 0);
                    int64_t ms = sqlite3_column_int64(s, 1);
                    int64_t median = 0;
                    bool have_median = stage &&
                        bfr_median_for_stage(ndb->db, (const char *)stage, &median);

                    struct json_value row = {0};
                    json_set_object(&row);
                    json_push_kv_str(&row, "stage", stage ? (const char *)stage : "");
                    json_push_kv_int(&row, "last_ms", ms);
                    if (have_median)
                        json_push_kv_int(&row, "median_ms", median);
                    json_push_back(&stages, &row);
                    json_free(&row);
                }
                sqlite3_finalize(s);
            }
        }
    }

    json_push_kv_int(out, "last_boot_epoch", last_epoch);
    json_push_kv(out, "stages", &stages);
    json_free(&stages);
    /* E2 boot-loop-failsafe: fold the boot-loop detector's state in as a
     * "restart_loop" sub-object — see CLAUDE.md "Adding state
     * introspection" (extending an existing dumper, not registering a new
     * one) and config/boot_loop_guard.h for what the fields mean. */
    boot_loop_guard_dump_state_json(out);
    return true;
}
