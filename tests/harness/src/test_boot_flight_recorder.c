/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for boot_flight_recorder — the boot-phase timing memory:
 *   - marks buffered during a boot persist into node.db on finish();
 *   - the diagnostics dumper ('boot_timings') reports the most recent
 *     boot's per-stage ms next to the recorded median;
 *   - a stage that blows past max(5s, 4x its recorded median) raises the
 *     named blocker boot.stage_regression — but ONLY once enough history
 *     exists (>=3 samples) to trust a median, and never on the boot that
 *     first establishes it;
 *   - the durable table is pruned to the last BOOT_FLIGHT_RECORDER_MAX_BOOTS
 *     distinct boot_epochs;
 *   - engine/composition/src/boot_timing_marks.c: boot_clock_ms() is monotonic
 *     on its own source (never the wall clock); boot_submark/boot_topmark
 *     record the elapsed-since-`since` ms via boot_flight_recorder_mark(), and
 *     boot_submark returns a fresh clock reading to chain the next phase.
 */

#include "test/test_core.h"

#include "config/boot_flight_recorder.h"
#include "config/boot_loop_guard.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/binary_ab_fallback.h"
#include "util/blocker.h"
#include "util/shutdown_stagewatch.h"
#include "../../../engine/composition/src/boot_timing_marks_internal.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BFR_CHECK(name, expr) do {                                        \
    if (expr) { printf("  boot_flight_recorder: %s... OK\n", (name)); }    \
    else { printf("  boot_flight_recorder: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Fabricate one prior-boot history row directly (bypassing finish()'s
 * wall-clock boot_epoch, so a test can build precise multi-boot history
 * without depending on real time granularity between calls). */
static bool bfr_insert_history_row(sqlite3 *db, int64_t boot_epoch,
                                   const char *stage, int64_t ms)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO boot_stage_timings"
            "(boot_epoch,stage,ms,ts) VALUES (?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(s, 1, boot_epoch);
    sqlite3_bind_text(s, 2, stage, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 3, ms);
    sqlite3_bind_int64(s, 4, boot_epoch);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

/* Read a small text file whole; returns -1 (buf untouched) on any failure,
 * else the byte count read (buf is NUL-terminated within `n`). */
static int bfr_read_file(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t r = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[r] = '\0';
    return (int)r;
}

static int64_t bfr_distinct_epoch_count(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(DISTINCT boot_epoch) FROM boot_stage_timings",
            -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* Sweep every boot_stage_timings row so a section's epoch/row counts start
 * clean; logs `label` and counts a failure if the DELETE fails. */
static int bfr_clear_stage_timing_history(struct node_db *ndb,
                                          const char *label)
{
    int failures = 0;
    char *errmsg = NULL;
    int rc = sqlite3_exec(ndb->db, "DELETE FROM boot_stage_timings",
                          NULL, NULL, &errmsg);
    BFR_CHECK(label, rc == SQLITE_OK);
    if (errmsg) sqlite3_free(errmsg);
    return failures;
}

static int bfr_test_first_boot_dump(struct node_db *ndb)
{
    int failures = 0;
    /* ── mark() + finish() persists; the dumper reflects the latest boot. */
    boot_flight_recorder_mark("phase_a", 111);
    boot_flight_recorder_mark("phase_b", 222);
    boot_flight_recorder_finish(ndb);
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = boot_flight_recorder_dump_state_json(&v, NULL);
        const struct json_value *epoch = json_get(&v, "last_boot_epoch");
        const struct json_value *stages = json_get(&v, "stages");
        bool shape_ok = ok && epoch && json_get_int(epoch) > 0 &&
                        stages && json_size(stages) == 2;
        BFR_CHECK("dump_state_json reports last_boot_epoch + 2 stages", shape_ok);
        json_free(&v);
    }
    BFR_CHECK("first-ever boot for a stage never raises a regression "
              "(no history to compare against)",
              !blocker_exists("boot.stage_regression"));
    return failures;
}

static int bfr_test_regression_needs_three_samples(struct node_db *ndb)
{
    int failures = 0;
    /* ── Regression check: needs >=3 PRIOR samples before it trusts a
     * median — a stage with only 1-2 history rows never fires even on a
     * wildly high ms, so a fresh datadir's first few boots can't false-fire. */
    BFR_CHECK("seed history epoch 1001", bfr_insert_history_row(ndb->db, 1001, "phase_c", 100));
    BFR_CHECK("seed history epoch 1002", bfr_insert_history_row(ndb->db, 1002, "phase_c", 100));
    boot_flight_recorder_mark("phase_c", 50000);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("no regression with only 2 prior samples (insufficient history)",
              !blocker_exists("boot.stage_regression"));
    return failures;
}

static int bfr_test_regression_fires_on_breach(struct node_db *ndb)
{
    int failures = 0;
    /* ── Third prior sample establishes a trustworthy median (100ms) ->
     * threshold = max(5000, 4*100) = 5000ms. A stage at 6000ms breaches it. */
    BFR_CHECK("seed history epoch 1003", bfr_insert_history_row(ndb->db, 1003, "phase_c", 100));
    boot_flight_recorder_mark("phase_c", 6000);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("stage_regression blocker raised on a real breach",
              blocker_exists("boot.stage_regression"));
    {
        struct blocker_snapshot snaps[8];
        int n = blocker_snapshot_all(snaps, 8);
        bool found = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, "boot.stage_regression") == 0) {
                found = strstr(snaps[i].reason, "phase_c") != NULL &&
                        strstr(snaps[i].reason, "6000") != NULL;
            }
        }
        BFR_CHECK("blocker reason names the stage + ms", found);
    }
    BFR_CHECK("boot still proceeds past a regression (fail-LOUD not fail-stop "
              "-- finish() returned, this line runs)", true);
    blocker_clear("boot.stage_regression");
    return failures;
}

static int bfr_test_regression_threshold_boundary(struct node_db *ndb)
{
    int failures = 0;
    /* median now includes the 6000ms outlier row, so seed a FRESH stage name
     * with a clean, larger history. */
    BFR_CHECK("seed phase_d epoch 2001", bfr_insert_history_row(ndb->db, 2001, "phase_d", 2000));
    BFR_CHECK("seed phase_d epoch 2002", bfr_insert_history_row(ndb->db, 2002, "phase_d", 2000));
    BFR_CHECK("seed phase_d epoch 2003", bfr_insert_history_row(ndb->db, 2003, "phase_d", 2000));
    /* threshold = max(5000, 4*2000=8000) = 8000; 7000 < 8000 -> no fire. */
    boot_flight_recorder_mark("phase_d", 7000);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("no regression strictly under threshold",
              !blocker_exists("boot.stage_regression"));
    /* 9000 > 8000 -> fires. */
    boot_flight_recorder_mark("phase_d", 9000);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("regression fires once over threshold", blocker_exists("boot.stage_regression"));
    blocker_clear("boot.stage_regression");
    return failures;
}

static int bfr_test_epoch_retention_pruning(struct node_db *ndb)
{
    int failures = 0;
    /* ── Retention: prune to the last BOOT_FLIGHT_RECORDER_MAX_BOOTS distinct
     * boot_epochs. Seed past the cap with distinct FUTURE epochs so "the 30
     * largest boot_epochs survive" is unambiguous. */
    const int64_t PRUNE_EPOCH_BASE = 9000000000LL; /* year ~2255 */
    int prune_rows = BOOT_FLIGHT_RECORDER_MAX_BOOTS + 10;
    for (int i = 0; i < prune_rows; i++) {
        BFR_CHECK("seed prune-fixture row",
                  bfr_insert_history_row(ndb->db, PRUNE_EPOCH_BASE + i,
                                         "prune_stage", 42));
    }
    boot_flight_recorder_mark("prune_stage", 43);
    boot_flight_recorder_finish(ndb);
    int64_t epochs_after = bfr_distinct_epoch_count(ndb->db);
    BFR_CHECK("retention caps distinct boot_epochs at BOOT_FLIGHT_RECORDER_MAX_BOOTS",
              epochs_after == BOOT_FLIGHT_RECORDER_MAX_BOOTS);

    /* The MOST RECENT (largest boot_epoch) boots survive pruning; the real
     * finish() epoch is pruned away. */
    {
        sqlite3_stmt *s = NULL;
        int64_t max_epoch = -1;
        if (sqlite3_prepare_v2(ndb->db,
                "SELECT MAX(boot_epoch) FROM boot_stage_timings",
                -1, &s, NULL) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW)
            max_epoch = sqlite3_column_int64(s, 0);
        sqlite3_finalize(s);
        BFR_CHECK("newest boot_epoch survives pruning",
                  max_epoch == PRUNE_EPOCH_BASE + prune_rows - 1);
    }
    return failures;
}

static int bfr_test_loop_guard_spaced_boots(struct node_db *ndb)
{
    int failures = 0;
    /* ── boot_loop_guard (fired via finish()) + the exit-reason breadcrumb it
     * reads. Clear prior history first: the far-future fixture epochs would
     * otherwise fall inside any "last N minutes" window and corrupt the
     * counts. */
    failures += bfr_clear_stage_timing_history(
        ndb, "clear history ahead of boot-loop-guard tests");
    blocker_clear(BOOT_LOOP_GUARD_BLOCKER_ID);
    boot_loop_guard_reset_for_testing();
    int64_t bl_now = platform_time_wall_unix();

    /* ── Spaced boots: two prior boots well outside the 15-minute window,
     * plus THIS finish() call's own real-time row -> only the real-time row
     * falls inside the window -> count=1, below threshold -> no fire. */
    BFR_CHECK("seed spaced boot (60 min ago)",
              bfr_insert_history_row(ndb->db, bl_now - 3600, "phase_x", 10));
    BFR_CHECK("seed spaced boot (45 min ago)",
              bfr_insert_history_row(ndb->db, bl_now - 2700, "phase_x", 10));
    boot_flight_recorder_mark("phase_x", 10);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("spaced boots: no restart-loop blocker",
              !blocker_exists(BOOT_LOOP_GUARD_BLOCKER_ID));
    {
        struct json_value v = {0};
        json_set_object(&v);
        boot_flight_recorder_dump_state_json(&v, NULL);
        const struct json_value *rl = json_get(&v, "restart_loop");
        bool ok = rl && json_get_int(json_get(rl, "count")) == 1 &&
                  json_get_bool(json_get(rl, "armed")) &&
                  !json_get_bool(json_get(rl, "fired"));
        BFR_CHECK("dumper: spaced boots report count=1 armed fired=false", ok);
        json_free(&v);
    }
    return failures;
}

static int bfr_test_loop_guard_quick_boots(struct node_db *ndb)
{
    int failures = 0;
    /* The spaced and quick scenarios must not share finish()'s wall-clock
     * boot_epoch (same-second finishes deduplicate); reset the fixture so the
     * threshold proof is independent of scheduler timing. */
    failures += bfr_clear_stage_timing_history(
        ndb, "reset history between spaced and quick boot scenarios");
    blocker_clear(BOOT_LOOP_GUARD_BLOCKER_ID);
    boot_loop_guard_reset_for_testing();
    int64_t bl_now = platform_time_wall_unix();

    /* ── Quick boots: two boots seeded well inside the window, plus
     * this finish() call's own real-time row -> 3 distinct boot_epochs in
     * the last 15 minutes -> threshold (3) reached -> blocker fires. */
    BFR_CHECK("seed quick boot (10 min ago)",
              bfr_insert_history_row(ndb->db, bl_now - 600, "phase_x", 10));
    BFR_CHECK("seed quick boot (2 min ago)",
              bfr_insert_history_row(ndb->db, bl_now - 120, "phase_x", 10));
    boot_flight_recorder_mark("phase_x", 10);
    boot_flight_recorder_finish(ndb);
    BFR_CHECK("restart-loop blocker raised at the boot-count threshold",
              blocker_exists(BOOT_LOOP_GUARD_BLOCKER_ID));
    {
        struct blocker_snapshot snaps[8];
        int n = blocker_snapshot_all(snaps, 8);
        bool found = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(snaps[i].id, BOOT_LOOP_GUARD_BLOCKER_ID) == 0) {
                found = strstr(snaps[i].reason, "count=3") != NULL &&
                        strstr(snaps[i].reason, "window_min=15") != NULL;
            }
        }
        BFR_CHECK("blocker reason names the count + window", found);
    }
    BFR_CHECK("boot still proceeds past a restart-loop verdict (fail-LOUD "
              "not fail-stop -- finish() returned, this line runs)", true);
    blocker_clear(BOOT_LOOP_GUARD_BLOCKER_ID);
    return failures;
}

static int bfr_test_exit_reason_streak_wiring(struct node_db *ndb,
                                              const char *dir)
{
    int failures = 0;
    /* ── Exit-reason breadcrumb roundtrip + binary A/B streak wiring:
     * shutdown_stagewatch_write_exit_reason() writes <dir>/boot-exit-reason.v1;
     * boot_loop_guard_check() reads it at the NEXT boot and, for a
     * self-respawn reason, increments the binary A/B launcher's boot-failure
     * streak file (services/binary_ab_fallback.h), since a self-respawn's
     * in-process execv bypasses the external launcher. */
    /* Clear history again so this section tests only the breadcrumb/streak
     * wiring, not the count threshold. */
    failures += bfr_clear_stage_timing_history(
        ndb, "clear history ahead of breadcrumb tests");

    char streak_path[600];
    snprintf(streak_path, sizeof(streak_path), "%s/%s", dir,
             BINARY_AB_STREAK_BASENAME);
    setenv(BINARY_AB_ENV_SLOTS_DIR, dir, 1);

    shutdown_stagewatch_begin(dir);
    shutdown_stagewatch_write_exit_reason(
        SHUTDOWN_EXIT_REASON_SELF_RESPAWN_SUPERVISOR_BACKSTOP);
    shutdown_stagewatch_reset_for_test();

    blocker_clear(BOOT_LOOP_GUARD_BLOCKER_ID);
    boot_loop_guard_reset_for_testing();
    boot_loop_guard_check(ndb);

    char buf[64];
    int r = bfr_read_file(streak_path, buf, sizeof(buf));
    BFR_CHECK("self-respawn breadcrumb increments the boot-fail streak "
              "from missing-file (0) to 1",
              r > 0 && strcmp(buf, "1\n") == 0);

    struct json_value v = {0};
    json_set_object(&v);
    boot_flight_recorder_dump_state_json(&v, NULL);
    const struct json_value *rl = json_get(&v, "restart_loop");
    const char *reason = rl ? json_get_str(json_get(rl, "last_exit_reason")) : NULL;
    BFR_CHECK("dumper reports the self-respawn exit reason verbatim",
              reason && strcmp(reason,
                  SHUTDOWN_EXIT_REASON_SELF_RESPAWN_SUPERVISOR_BACKSTOP) == 0);
    json_free(&v);

    /* A SECOND self-respawn exit increments the SAME streak file again
     * (1 -> 2) -- the streak survives across boots exactly like the
     * launcher's own shell-side increment does. */
    shutdown_stagewatch_begin(dir);
    shutdown_stagewatch_write_exit_reason(
        SHUTDOWN_EXIT_REASON_SELF_RESPAWN_TIP_WATCHDOG);
    shutdown_stagewatch_reset_for_test();
    boot_loop_guard_check(ndb);
    r = bfr_read_file(streak_path, buf, sizeof(buf));
    BFR_CHECK("a second self-respawn exit increments the streak to 2",
              r > 0 && strcmp(buf, "2\n") == 0);

    /* An OPERATOR exit does NOT touch the streak. */
    shutdown_stagewatch_begin(dir);
    shutdown_stagewatch_write_exit_reason(SHUTDOWN_EXIT_REASON_OPERATOR);
    shutdown_stagewatch_reset_for_test();
    boot_loop_guard_check(ndb);
    r = bfr_read_file(streak_path, buf, sizeof(buf));
    BFR_CHECK("an operator exit leaves the streak untouched at 2",
              r > 0 && strcmp(buf, "2\n") == 0);
    return failures;
}

static int bfr_test_forced_exit_marker_readback(const char *dir)
{
    int failures = 0;
    /* Read-side "forced" parsing: a shutdown-watchdog-forced exit appends
     * "forced=1" (async-signal-safe) to the same breadcrumb file; simulate
     * the append and confirm the reader surfaces it. */
    char exit_reason_path[600];
    snprintf(exit_reason_path, sizeof(exit_reason_path), "%s/%s", dir,
             "boot-exit-reason.v1");
    FILE *f = fopen(exit_reason_path, "a");
    BFR_CHECK("append forced=1 marker to the breadcrumb file", f != NULL);
    if (f) { fputs("forced=1\n", f); fclose(f); }

    char reason_buf[SHUTDOWN_EXIT_REASON_MAX];
    bool forced = false;
    bool have = shutdown_stagewatch_read_exit_reason(
        dir, reason_buf, sizeof(reason_buf), &forced);
    BFR_CHECK("read_exit_reason surfaces the forced marker",
              have && forced &&
              strcmp(reason_buf, SHUTDOWN_EXIT_REASON_OPERATOR) == 0);

    unsetenv(BINARY_AB_ENV_SLOTS_DIR);
    blocker_clear(BOOT_LOOP_GUARD_BLOCKER_ID);
    boot_loop_guard_reset_for_testing();
    return failures;
}

static int bfr_test_read_exit_reason_missing_breadcrumb(const char *dir)
{
    int failures = 0;
    /* ── read_exit_reason on a datadir that never had a breadcrumb written
     * is a clean "no breadcrumb" answer, never a crash. */
    {
        char fresh_dir[300];
        snprintf(fresh_dir, sizeof(fresh_dir), "%s/never-written", dir);
        char reason_buf[SHUTDOWN_EXIT_REASON_MAX] = "unchanged";
        bool forced = true;
        bool have = shutdown_stagewatch_read_exit_reason(
            fresh_dir, reason_buf, sizeof(reason_buf), &forced);
        BFR_CHECK("no breadcrumb -> read_exit_reason returns false, clears output",
                  !have && reason_buf[0] == '\0' && !forced);
    }
    return failures;
}

static int bfr_test_boot_clock_monotonic(struct node_db *ndb)
{
    int failures = 0;
    /* ── boot_timing_marks: boot_clock_ms / boot_submark / boot_topmark.
     * Clear history so this section's counts are independent. */
    failures += bfr_clear_stage_timing_history(
        ndb, "clear history ahead of boot_timing_marks tests");
    boot_flight_recorder_reset_buffer_for_testing();
    blocker_clear("boot.stage_regression");

    /* boot_clock_ms(): ordered on its OWN monotonic source, never the
     * wall clock; a real sleep forces observable forward progress. */
    int64_t c0 = boot_clock_ms();
    BFR_CHECK("boot_clock_ms: a reading is a sane positive ms value",
              c0 > 0);
    platform_sleep_ms(5);
    int64_t c1 = boot_clock_ms();
    BFR_CHECK("boot_clock_ms: never goes backwards", c1 >= c0);
    BFR_CHECK("boot_clock_ms: real work between two readings is "
              "observable as forward progress", c1 > c0);
    return failures;
}

/* Scan a dump's "stages" array for `stage_name`; report whether it was found
 * and store its "last_ms" (the last matching row wins, as in a full scan). */
static bool bfr_find_stage_last_ms(const struct json_value *stages,
                                   const char *stage_name, int64_t *ms_out)
{
    bool found = false;
    size_t n = stages ? json_size(stages) : 0;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(stages, i);
        const char *stage = row ? json_get_str(json_get(row, "stage")) : NULL;
        if (stage && strcmp(stage, stage_name) == 0) {
            *ms_out = json_get_int(json_get(row, "last_ms"));
            found = true;
        }
    }
    return found;
}

/* Single pass over a dump's "stages" array recording the last_ms and presence
 * of both chained submark rows (one scan, as the original loop did). */
static void bfr_find_submark_pair(const struct json_value *stages,
                                  int64_t *ms_one, bool *found_one,
                                  int64_t *ms_two, bool *found_two)
{
    size_t n = stages ? json_size(stages) : 0;
    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(stages, i);
        const char *stage = row ? json_get_str(json_get(row, "stage")) : NULL;
        if (stage && strcmp(stage, "tm_test_submark_one") == 0) {
            *ms_one = json_get_int(json_get(row, "last_ms"));
            *found_one = true;
        } else if (stage && strcmp(stage, "tm_test_submark_two") == 0) {
            *ms_two = json_get_int(json_get(row, "last_ms"));
            *found_two = true;
        }
    }
}

/* Verify the recorded ms values of the two chained submarks against the
 * clock windows the test observed around the calls. */
static int bfr_check_submark_recorded_bounds(int64_t t0, int64_t t1, int64_t t2,
                                             int64_t ms_one, int64_t ms_two,
                                             bool found_one, bool found_two)
{
    int failures = 0;
    BFR_CHECK("recorder actually received both boot_submark marks "
              "(not just a compile-time no-op)", found_one && found_two);
    /* The recorded ms is bounded by the window already observed
     * (internal read lies between `since` and the returned reading):
     * an exact derived bound, not a hardcoded threshold. */
    BFR_CHECK("submark one: recorded ms is bounded by [0, t1-t0]",
              ms_one >= 0 && ms_one <= (t1 - t0));
    BFR_CHECK("submark two: recorded ms is bounded by [0, t2-t1]",
              ms_two >= 0 && ms_two <= (t2 - t1));
    /* The sleep guarantees the second recorded ms is strictly
     * positive. */
    BFR_CHECK("submark two: real work before the call shows up as "
              "strictly positive recorded ms", ms_two > 0);
    return failures;
}

static int bfr_test_boot_submark_recording(struct node_db *ndb)
{
    int failures = 0;
    /* boot_submark(name, since): records (internal clock read - since),
     * then returns a FRESH boot_clock_ms() reading to chain as the next
     * `since`. Chain two calls with a real sleep between them. */
    int64_t t0 = boot_clock_ms();
    int64_t t1 = boot_submark("tm_test_submark_one", t0);
    BFR_CHECK("boot_submark: returned since >= the since it was given",
              t1 >= t0);
    platform_sleep_ms(5);
    int64_t t2 = boot_submark("tm_test_submark_two", t1);
    BFR_CHECK("boot_submark: returned since strictly advances when real "
              "work happens before the next call", t2 > t1);

    boot_flight_recorder_finish(ndb);
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = boot_flight_recorder_dump_state_json(&v, NULL);
        const struct json_value *stages = json_get(&v, "stages");
        BFR_CHECK("dump_state_json ok + exactly 2 submark stages recorded",
                  ok && stages && json_size(stages) == 2);

        int64_t ms_one = -1, ms_two = -1;
        bool found_one = false, found_two = false;
        bfr_find_submark_pair(stages, &ms_one, &found_one, &ms_two, &found_two);
        failures += bfr_check_submark_recorded_bounds(t0, t1, t2, ms_one,
                                                      ms_two, found_one,
                                                      found_two);
        json_free(&v);
    }
    return failures;
}

static int bfr_test_boot_topmark_recording(struct node_db *ndb)
{
    int failures = 0;
    /* boot_topmark(name, since): same recording contract, void return;
     * isolated in its own boot_epoch. */
    boot_flight_recorder_reset_buffer_for_testing();
    failures += bfr_clear_stage_timing_history(
        ndb, "clear history ahead of boot_topmark test");
    int64_t t3 = boot_clock_ms();
    platform_sleep_ms(5);
    boot_topmark("tm_test_topmark", t3);
    int64_t t4 = boot_clock_ms();
    boot_flight_recorder_finish(ndb);
    {
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = boot_flight_recorder_dump_state_json(&v, NULL);
        const struct json_value *stages = json_get(&v, "stages");
        int64_t ms = -1;
        bool found = bfr_find_stage_last_ms(stages, "tm_test_topmark", &ms);
        BFR_CHECK("dump_state_json ok + exactly 1 topmark stage recorded",
                  ok && stages && json_size(stages) == 1 && found);
        BFR_CHECK("boot_topmark: recorded ms is bounded by [0, t4-t3]",
                  ms >= 0 && ms <= (t4 - t3));
        BFR_CHECK("boot_topmark: real work before the call shows up as "
                  "strictly positive recorded ms", ms > 0);
        json_free(&v);
    }

    boot_flight_recorder_reset_buffer_for_testing();
    blocker_clear("boot.stage_regression");
    failures += bfr_clear_stage_timing_history(
        ndb, "clear history after boot_timing_marks tests");
    return failures;
}

int test_boot_flight_recorder(void);
int test_boot_flight_recorder(void)
{
    printf("\n=== boot_flight_recorder tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "boot_flight_recorder", "main");
    char ndb_path[600];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

    struct node_db ndb;
    bool db_ok = node_db_open(&ndb, ndb_path);
    BFR_CHECK("node.db opens", db_ok);
    if (!db_ok) { test_cleanup_tmpdir(dir); return failures; }

    struct db_service dbsvc;
    struct app_runtime_context runtime;
    memset(&runtime, 0, sizeof(runtime));
    db_service_init(&dbsvc);
    BFR_CHECK("db service attaches", db_service_attach(&dbsvc, &ndb));
    BFR_CHECK("db service starts", db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);

    boot_flight_recorder_reset_buffer_for_testing();
    blocker_clear("boot.stage_regression");

    /* ── finish() with no marks is a logged no-op — no schema, no rows. */
    boot_flight_recorder_finish(&ndb);
    BFR_CHECK("finish() with zero marks creates no rows",
              bfr_distinct_epoch_count(ndb.db) <= 0);

    /* ── finish(NULL/closed) is a logged no-op, never a crash. */
    boot_flight_recorder_mark("throwaway", 1);
    boot_flight_recorder_finish(NULL);
    boot_flight_recorder_reset_buffer_for_testing();

    failures += bfr_test_first_boot_dump(&ndb);
    failures += bfr_test_regression_needs_three_samples(&ndb);
    failures += bfr_test_regression_fires_on_breach(&ndb);
    failures += bfr_test_regression_threshold_boundary(&ndb);
    failures += bfr_test_epoch_retention_pruning(&ndb);
    failures += bfr_test_loop_guard_spaced_boots(&ndb);
    failures += bfr_test_loop_guard_quick_boots(&ndb);
    failures += bfr_test_exit_reason_streak_wiring(&ndb, dir);
    failures += bfr_test_forced_exit_marker_readback(dir);
    failures += bfr_test_read_exit_reason_missing_breadcrumb(dir);
    failures += bfr_test_boot_clock_monotonic(&ndb);
    failures += bfr_test_boot_submark_recording(&ndb);
    failures += bfr_test_boot_topmark_recording(&ndb);

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}
