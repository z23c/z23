/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_operator_ux — the operator-UX native commands (wf/operator-ux):
 *   explain (pure topic composers), profile (in-process thread sampler),
 *   ops.producer.status (node-free producer datadir reader), and the CLI UX
 *   contract (docs/NATIVE_COMMAND_INTERFACE.md): the ONE-LINE status brief,
 *   the next-command hint, the field selector, and the unknown-command
 *   diagnostic. Each is exercised without a running node using fabricated
 *   fixtures / a synthetic datadir.
 */

#include "test/test_core.h"

#include "controllers/explain_native_handlers.h"
#include "config/consensus_state_producer_receipt.h"
#include "config/command_catalog.h"
#include "command/native_command.h"
#include "kernel/command_registry.h"
#include "util/thread_profile.h"
#include "util/stage.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "platform/time_compat.h"
#include "json/json.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* ── explain ───────────────────────────────────────────────────────── */

static int test_explain_sync_names_dominant_blocker(void)
{
    int failures = 0;
    TEST("explain sync names the dominant blocker on a known fixture") {
        /* Frontier: H*=100. */
        struct json_value frontier;
        json_init(&frontier);
        json_set_object(&frontier);
        json_push_kv_int(&frontier, "hstar", 100);
        json_push_kv_int(&frontier, "served_floor", 100);
        json_push_kv_str(&frontier, "hstar_next_primary_stage", "utxo_apply");
        json_push_kv_str(&frontier, "hstar_next_primary_kind", "DEPENDENCY");
        json_push_kv_str(&frontier, "hstar_next_primary_detail",
                         "anchor backfill gap");

        /* Chain: validated header tip 200 -> gap 100. */
        struct json_value chain;
        json_init(&chain);
        json_set_object(&chain);
        json_push_kv_int(&chain, "best_header_height", 200);

        /* One active blocker with a distinctive id. */
        struct json_value blockers, b;
        json_init(&blockers);
        json_set_array(&blockers);
        json_init(&b);
        json_set_object(&b);
        json_push_kv_str(&b, "id", "anchor_backfill_gap");
        json_push_kv_str(&b, "class", "PERMANENT");
        json_push_kv_str(&b, "reason", "missing historical shielded anchors");
        json_push_kv_int(&b, "fire_count", 3);
        json_push_back(&blockers, &b);
        json_free(&b);

        struct explain_inputs in = {
            .frontier = &frontier, .blockers = &blockers, .chain = &chain,
            .block_height = 100, .block_height_known = true,
        };
        struct json_value out;
        json_init(&out);
        explain_compose_sync(&in, &out);

        const char *text = json_get_str(json_get(&out, "text"));
        ASSERT(text != NULL);
        ASSERT(strstr(text, "anchor_backfill_gap") != NULL);
        ASSERT(strstr(text, "BEHIND") != NULL);
        ASSERT(json_get_int(json_get(&out, "gap")) == 100);
        ASSERT(strcmp(json_get_str(json_get(&out, "dominant_blocker")),
                      "anchor_backfill_gap") == 0);

        json_free(&out);
        json_free(&blockers);
        json_free(&chain);
        json_free(&frontier);
        PASS();
    } _test_next:;
    return failures;
}

/* `explain sync` must show the stage cursors AND say which of them are above
 * the verified height. It showed neither: the block tested the frontier's
 * stage_cursors for JSON_OBJ while reducer_frontier emits an ARRAY, so the
 * whole section was silently dropped from the plain-language surface. Third
 * case: a node that sends no depth field must read "UNAVAILABLE", never as an
 * all-clear. */
static int test_explain_sync_marks_run_ahead_cursors(void)
{
    int failures = 0;
    TEST("explain sync marks stage cursors above the verified height") {
        struct json_value frontier;
        json_init(&frontier);
        json_set_object(&frontier);
        json_push_kv_int(&frontier, "hstar", 100);
        json_push_kv_int(&frontier, "served_floor", 100);

        struct json_value cursors, c;
        json_init(&cursors);
        json_set_array(&cursors);
        json_init(&c);
        json_set_object(&c);
        json_push_kv_str(&c, "stage", "utxo_apply");
        json_push_kv_int(&c, "cursor", 101);
        json_push_kv_int(&c, "heights_above_hstar", 0);
        json_push_back(&cursors, &c);
        json_free(&c);
        json_init(&c);
        json_set_object(&c);
        json_push_kv_str(&c, "stage", "body_fetch");
        json_push_kv_int(&c, "cursor", 108);
        json_push_kv_int(&c, "heights_above_hstar", 7);
        json_push_back(&cursors, &c);
        json_free(&c);
        json_push_kv(&frontier, "stage_cursors", &cursors);
        json_free(&cursors);

        struct explain_inputs in = {
            .frontier = &frontier,
            .block_height = 100, .block_height_known = true,
        };
        struct json_value out;
        json_init(&out);
        explain_compose_sync(&in, &out);
        const char *text = json_get_str(json_get(&out, "text"));
        ASSERT(text != NULL);
        /* The section is rendered at all. */
        ASSERT(strstr(text, "stage cursors") != NULL);
        ASSERT(strstr(text, "body_fetch=108*") != NULL);
        /* The level cursor is NOT starred. */
        ASSERT(strstr(text, "utxo_apply=101 ") != NULL ||
               strstr(text, "utxo_apply=101\n") != NULL);
        /* And the meaning is spelled out, not left to the reader. */
        ASSERT(strstr(text, "ABOVE H*") != NULL);
        ASSERT(strstr(text, "unproven") != NULL);
        ASSERT(strstr(text, "1 cursor(s), up to 7 height(s)") != NULL);
        json_free(&out);

        /* Nothing above H*: an explicit all-clear, no star. */
        struct json_value clear_cursors, cc;
        json_init(&clear_cursors);
        json_set_array(&clear_cursors);
        json_init(&cc);
        json_set_object(&cc);
        json_push_kv_str(&cc, "stage", "utxo_apply");
        json_push_kv_int(&cc, "cursor", 101);
        json_push_kv_int(&cc, "heights_above_hstar", 0);
        json_push_back(&clear_cursors, &cc);
        json_free(&cc);
        struct json_value clear_frontier;
        json_init(&clear_frontier);
        json_set_object(&clear_frontier);
        json_push_kv_int(&clear_frontier, "hstar", 100);
        json_push_kv(&clear_frontier, "stage_cursors", &clear_cursors);
        json_free(&clear_cursors);
        struct explain_inputs clear_in = {
            .frontier = &clear_frontier,
            .block_height = 100, .block_height_known = true,
        };
        struct json_value clear_out;
        json_init(&clear_out);
        explain_compose_sync(&clear_in, &clear_out);
        const char *clear_text = json_get_str(json_get(&clear_out, "text"));
        ASSERT(clear_text != NULL);
        ASSERT(strstr(clear_text, "no cursor is above H*") != NULL);
        ASSERT(strstr(clear_text, "ABOVE H*") == NULL);
        ASSERT(strstr(clear_text, "utxo_apply=101*") == NULL);
        json_free(&clear_out);
        json_free(&clear_frontier);

        /* A node that sends no depth field: never an all-clear. */
        struct json_value old_cursors, oc;
        json_init(&old_cursors);
        json_set_array(&old_cursors);
        json_init(&oc);
        json_set_object(&oc);
        json_push_kv_str(&oc, "stage", "body_fetch");
        json_push_kv_int(&oc, "cursor", 108);
        json_push_back(&old_cursors, &oc);
        json_free(&oc);
        struct json_value old_frontier;
        json_init(&old_frontier);
        json_set_object(&old_frontier);
        json_push_kv_int(&old_frontier, "hstar", 100);
        json_push_kv(&old_frontier, "stage_cursors", &old_cursors);
        json_free(&old_cursors);
        struct explain_inputs old_in = {
            .frontier = &old_frontier,
            .block_height = 100, .block_height_known = true,
        };
        struct json_value old_out;
        json_init(&old_out);
        explain_compose_sync(&old_in, &old_out);
        const char *old_text = json_get_str(json_get(&old_out, "text"));
        ASSERT(old_text != NULL);
        ASSERT(strstr(old_text, "UNAVAILABLE") != NULL);
        ASSERT(strstr(old_text, "no cursor is above H*") == NULL);
        json_free(&old_out);
        json_free(&old_frontier);

        json_free(&frontier);
        PASS();
    } _test_next:;
    return failures;
}

static int test_explain_topics_and_health(void)
{
    int failures = 0;
    TEST("explain topic table is non-empty and blockers/health compose") {
        ASSERT(explain_topic_count() == 3);
        char csv[128];
        size_t n = explain_topics_csv(csv, sizeof(csv));
        ASSERT(n > 0);
        ASSERT(strstr(csv, "sync") != NULL);
        ASSERT(strstr(csv, "blockers") != NULL);
        ASSERT(strstr(csv, "health") != NULL);

        /* health compose with a fabricated healthcheck: unhealthy. */
        struct json_value health, checks, chk;
        json_init(&health);
        json_set_object(&health);
        json_push_kv_bool(&health, "healthy", false);
        json_push_kv_bool(&health, "serving", true);
        json_push_kv_int(&health, "memory_rss_mb", 4096);
        json_init(&checks);
        json_set_object(&checks);
        json_init(&chk);
        json_set_object(&chk);
        json_push_kv_bool(&chk, "ok", false);
        json_push_kv(&checks, "sync_lag", &chk);
        json_free(&chk);
        json_push_kv(&health, "checks", &checks);
        json_free(&checks);

        struct explain_inputs in = { .health = &health };
        struct json_value out;
        json_init(&out);
        explain_compose_health(&in, &out);
        const char *text = json_get_str(json_get(&out, "text"));
        ASSERT(text != NULL && strstr(text, "healthy: no") != NULL);
        ASSERT(strstr(text, "sync_lag") != NULL);
        ASSERT(json_get_int(json_get(&out, "unhealthy_checks")) == 1);
        json_free(&out);

        /* blockers compose with no active blockers. */
        struct json_value empty;
        json_init(&empty);
        json_set_array(&empty);
        struct explain_inputs in2 = { .blockers = &empty };
        struct json_value out2;
        json_init(&out2);
        explain_compose_blockers(&in2, &out2);
        const char *t2 = json_get_str(json_get(&out2, "text"));
        ASSERT(t2 != NULL && strstr(t2, "dominant: none") != NULL);
        json_free(&out2);
        json_free(&empty);
        json_free(&health);
        PASS();
    } _test_next:;
    return failures;
}

/* ── profile ───────────────────────────────────────────────────────── */

static void *tp_racer(void *arg)
{
    (void)arg;
    platform_sleep_ms(20); /* exit mid-window so the tid races the sample */
    return NULL;
}

static int test_profile_samples_threads(void)
{
    int failures = 0;
    TEST("profile returns >=1 thread and a verdict, never crashes on a race") {
        pthread_t racer;
        int rc = pthread_create(&racer, NULL, tp_racer, NULL);
        ASSERT(rc == 0);

        struct thread_profile_opts opts = { .sample_ms = 120, .top_n = 8 };
        struct json_value out;
        json_init(&out);
        bool ok = thread_profile_sample(&opts, &out);
        pthread_join(racer, NULL);

        ASSERT(ok);
        ASSERT(json_get_int(json_get(&out, "sampled_threads")) >= 1);
        const char *verdict = json_get_str(json_get(&out, "verdict"));
        ASSERT(verdict != NULL && verdict[0] != '\0');
        const struct json_value *threads = json_get(&out, "threads");
        ASSERT(threads != NULL && threads->type == JSON_ARR);
        ASSERT(threads->num_children >= 1);
        json_free(&out);
        PASS();
    } _test_next:;
    return failures;
}

/* ── producer.status ───────────────────────────────────────────────── */

static bool producer_status_exec(sqlite3 *db, const char *sql);

#ifdef ZCL_TESTING
void consensus_state_producer_status_test_set_after_first_cursor_hook(
    void (*hook)(void *), void *ctx);
int64_t zcl_native_producer_applied_height_for_test(
    const struct producer_status_read *st);
bool consensus_state_producer_status_rate_window_current_for_test(
    const struct producer_status_read *status,
    int64_t older_time_unix, int64_t newer_height,
    int64_t newer_time_unix);
#endif

static int test_producer_status_synthetic(void)
{
    int failures = 0;
    TEST("producer status reads a synthetic progress.kv datadir") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "seed");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(stage_set_named_cursor(db, "tip_finalize", 12300));
        /* Capture one clock value. Two separate SQLite statements using
         * strftime('now') can straddle a second boundary under full-suite
         * load, turning the exact 60-second fixture into 59 or 61 seconds. */
        int64_t now = (int64_t)platform_time_wall_time_t();
        char seed_sql[1024];
        int seed_n = snprintf(seed_sql, sizeof(seed_sql),
            "CREATE TABLE utxo_apply_log("
            "height INTEGER PRIMARY KEY,status TEXT NOT NULL,"
            "ok INTEGER NOT NULL,spent_count INTEGER NOT NULL,"
            "added_count INTEGER NOT NULL,total_value_delta INTEGER NOT NULL,"
            "first_failure_kind TEXT,first_failure_detail BLOB,"
            "applied_at INTEGER NOT NULL);"
            "INSERT INTO utxo_apply_log VALUES("
            "12000,'ok',1,0,0,0,NULL,NULL,%lld);"
            "INSERT INTO utxo_apply_log VALUES("
            "12344,'ok',1,0,0,0,NULL,NULL,%lld);",
            (long long)(now - 60), (long long)now);
        ASSERT(seed_n > 0 && (size_t)seed_n < sizeof(seed_sql));
        ASSERT(producer_status_exec(db, seed_sql));
        progress_store_close();

        struct producer_status_read st;
        char err[256];
        ASSERT(consensus_state_producer_status_read(dir, &st, err,
                                                     sizeof(err)));
        ASSERT(st.progress_kv_present);
        ASSERT(st.utxo_apply_cursor == 12345);
        ASSERT(st.tip_finalize_cursor == 12300);
        /* No producer session/receipt seeded -> absent. */
        ASSERT(!st.session_open);
        ASSERT(!st.receipt_finalized);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "datadir", dir));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.ops_producer_status.v1");
        zcl_native_handle_ops_producer_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&reply.data, "height")) == 12344);
        ASSERT(json_get_int(json_get(&reply.data, "utxo_apply_cursor")) ==
               12345);
        ASSERT(json_get_bool(json_get(
            &reply.data, "durable_rate_available")));
        ASSERT(json_get_bool(json_get(&reply.data, "durable_rate_recent")));
        ASSERT(json_get_int(json_get(&reply.data, "target_height")) ==
               3056758);
        ASSERT(json_get_int(json_get(&reply.data, "remaining_blocks")) ==
               3044414);
        ASSERT(json_get_int(json_get(
            &reply.data, "rate_blocks_per_second_milli")) == 5733);
        ASSERT(json_get_int(json_get(&reply.data, "eta_seconds")) ==
               (INT64_C(3044414000) + 5732) / 5733);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "rate_source")),
                      "consensus.db:utxo_apply_log.applied_at") == 0);
        const char *text = json_get_str(json_get(&reply.data, "text"));
        ASSERT(text != NULL && strchr(text, '\n') == NULL);
        ASSERT(strstr(text, "height=12344") != NULL);
        ASSERT(strstr(text, "target=3056758") != NULL);
        ASSERT(strstr(text, "rate=5.7blk/s") != NULL);
        zcl_command_reply_free(&reply);

        ASSERT(progress_store_open(dir));
        db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(producer_status_exec(
            db, "DELETE FROM stage_cursor WHERE name='utxo_apply'"));
        progress_store_close();
        zcl_command_reply_init(&reply, "zcl.ops_producer_status.v1");
        zcl_native_handle_ops_producer_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_int(json_get(&reply.data, "height")) == 12300);
        ASSERT(json_get_int(json_get(&reply.data, "utxo_apply_cursor")) == -1);
        zcl_command_reply_free(&reply);
        json_free(&input);

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_absent(void)
{
    int failures = 0;
    TEST("producer status on a datadir with no progress.kv is not an error") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "empty");
        mkdir(dir, 0700);

        struct producer_status_read st;
        char err[256];
        ASSERT(consensus_state_producer_status_read(dir, &st, err,
                                                     sizeof(err)));
        ASSERT(!st.progress_kv_present);
        ASSERT(st.utxo_apply_cursor == -1);

        char progress_dir[320];
        snprintf(progress_dir, sizeof(progress_dir), "%s/progress.kv", dir);
        ASSERT(mkdir(progress_dir, 0700) == 0);
        ASSERT(!consensus_state_producer_status_read(dir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "not regular") != NULL);

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static bool producer_status_exec(sqlite3 *db, const char *sql)
{
    char *error = NULL;
    bool ok = sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK;
    sqlite3_free(error);
    return ok;
}

struct producer_snapshot_writer {
    char progress_path[320];
    bool committed;
};

static void producer_snapshot_write_between_reads(void *opaque)
{
    struct producer_snapshot_writer *writer = opaque;
    sqlite3 *db = NULL;
    if (!writer || sqlite3_open_v2(writer->progress_path, &db,
                                   SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return;
    }
    sqlite3_busy_timeout(db, 2000);
    writer->committed = producer_status_exec(
        db,
        "BEGIN IMMEDIATE;"
        "UPDATE stage_cursor SET cursor=190 WHERE name='tip_finalize';"
        "INSERT INTO utxo_apply_log VALUES(200,1,1120);"
        "COMMIT;");
    sqlite3_close(db);
}

static int test_producer_status_uses_one_read_snapshot(void)
{
    int failures = 0;
    TEST("producer status pins one WAL snapshot across all projections") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "snapshot");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 101));
        ASSERT(stage_set_named_cursor(db, "tip_finalize", 90));
        ASSERT(producer_status_exec(
            db,
            "CREATE TABLE utxo_apply_log("
            "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,"
            "applied_at INTEGER NOT NULL);"
            "INSERT INTO utxo_apply_log VALUES(40,1,1000);"
            "INSERT INTO utxo_apply_log VALUES(100,1,1060);"));
        progress_store_close();

        struct producer_snapshot_writer writer = {0};
        /* A4: the kernel store the reader pins is consensus.db post-flip; the
         * mid-read writer must target the same file it reads. */
        ASSERT(snprintf(writer.progress_path, sizeof(writer.progress_path),
                        "%s/consensus.db", dir) > 0);
        consensus_state_producer_status_test_set_after_first_cursor_hook(
            producer_snapshot_write_between_reads, &writer);
        struct producer_status_read st;
        char err[256] = {0};
        bool read_ok = consensus_state_producer_status_read(
            dir, &st, err, sizeof(err));
        consensus_state_producer_status_test_set_after_first_cursor_hook(
            NULL, NULL);
        ASSERT(read_ok);
        ASSERT(writer.committed);
        ASSERT(st.utxo_apply_cursor == 101);
        ASSERT(st.tip_finalize_cursor == 90);
        ASSERT(st.rate_newer_height == 100);

        struct producer_status_read after;
        ASSERT(consensus_state_producer_status_read(dir, &after, err,
                                                     sizeof(err)));
        ASSERT(after.tip_finalize_cursor == 190);
        /* The newly committed row is above the unchanged utxo_apply cursor;
         * it belongs to no current durable frontier and cannot drive ETA. */
        ASSERT(!after.durable_rate_available);
        ASSERT(after.rate_newer_height == -1);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    consensus_state_producer_status_test_set_after_first_cursor_hook(NULL,
                                                                     NULL);
    return failures;
}

static int test_producer_status_final_receipt_cursor_wins(void)
{
    int failures = 0;
    TEST("producer status gives a finalized receipt cursor precedence") {
        struct producer_status_read st = {
            .receipt_finalized = true,
            .fold_cursor = 101,
            .utxo_apply_cursor = 41,
            .tip_finalize_cursor = 39,
        };
        ASSERT(zcl_native_producer_applied_height_for_test(&st) == 100);
        st.receipt_finalized = false;
        ASSERT(zcl_native_producer_applied_height_for_test(&st) == 40);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_rate_window_rejects_prior_session(void)
{
    int failures = 0;
    TEST("producer ETA rejects rate rows predating the open session") {
        struct producer_status_read st = {
            .session_open = true,
            .utxo_apply_cursor = 101,
            .start_time_us = INT64_C(1060500000),
        };
        ASSERT(!consensus_state_producer_status_rate_window_current_for_test(
            &st, 1000, 100, 1120));
        /* Whole-second precision: a row in the floored start second belongs
         * to this session even when start_time_us had a fractional second. */
        ASSERT(consensus_state_producer_status_rate_window_current_for_test(
            &st, 1060, 100, 1120));
        /* The newest row must also coincide with the durable apply frontier. */
        ASSERT(!consensus_state_producer_status_rate_window_current_for_test(
            &st, 1060, 99, 1120));
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_residual_row_integration(void)
{
    int failures = 0;
    TEST("producer ETA ignores a current-height window that starts before session") {
        static const char source_id[] =
            "1111111111111111111111111111111111111111111111111111111111111111";
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "oldwindow");
        mkdir(dir, 0700);
        consensus_state_producer_receipt_test_set_identity(source_id, true);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        char receipt_err[256] = {0};
        ASSERT(consensus_state_producer_receipt_begin(
            db, CONSENSUS_STATE_VALIDATION_FULL,
            receipt_err, sizeof(receipt_err)));
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(producer_status_exec(
            db,
            "CREATE TABLE utxo_apply_log("
            "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,"
            "applied_at INTEGER NOT NULL);"
            "INSERT INTO utxo_apply_log VALUES(12000,1,"
            "CAST(strftime('%s','now') AS INTEGER)-120);"
            "INSERT INTO utxo_apply_log VALUES(12344,1,"
            "CAST(strftime('%s','now') AS INTEGER));"));
        progress_store_close();

        struct producer_status_read status;
        char err[256] = {0};
        ASSERT(consensus_state_producer_status_read(dir, &status, err,
                                                     sizeof(err)));
        ASSERT(status.session_open);
        ASSERT(!status.durable_rate_available);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    consensus_state_producer_receipt_test_set_identity(NULL, true);
    progress_store_close();
    return failures;
}

static int test_producer_status_rejects_future_rate_for_eta(void)
{
    int failures = 0;
    TEST("producer ETA rejects a materially future durable rate sample") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "future");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(producer_status_exec(
            db,
            "CREATE TABLE utxo_apply_log("
            "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,"
            "applied_at INTEGER NOT NULL);"
            "INSERT INTO utxo_apply_log VALUES(12000,1,"
            "CAST(strftime('%s','now') AS INTEGER));"
            "INSERT INTO utxo_apply_log VALUES(12344,1,"
            "CAST(strftime('%s','now') AS INTEGER)+60);"));
        progress_store_close();

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "datadir", dir));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.ops_producer_status.v1");
        zcl_native_handle_ops_producer_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(
            &reply.data, "durable_rate_available")));
        ASSERT(!json_get_bool(json_get(
            &reply.data, "rate_sample_clock_valid")));
        ASSERT(!json_get_bool(json_get(&reply.data, "durable_rate_recent")));
        ASSERT(!json_get_bool(json_get(&reply.data, "eta_available")));
        ASSERT(json_get_int(json_get(
            &reply.data, "rate_sample_age_seconds")) == -1);
        ASSERT(json_get_int(json_get(
            &reply.data, "rate_future_skew_tolerance_seconds")) == 5);
        ASSERT(json_get_int(json_get(
            &reply.data, "rate_future_skew_seconds")) > 5);
        const char *text = json_get_str(json_get(&reply.data, "text"));
        ASSERT(text != NULL && strstr(text, "rate=unknown") != NULL);
        ASSERT(strstr(text, "eta=unknown") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_rejects_malformed_store(void)
{
    int failures = 0;
    TEST("producer status does not project malformed rows as absent") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "badrow");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(producer_status_exec(
            db, "UPDATE stage_cursor SET cursor='not-an-integer' "
                "WHERE name='utxo_apply'"));
        progress_store_close();

        struct producer_status_read st;
        char err[256] = {0};
        ASSERT(!consensus_state_producer_status_read(dir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "integer projection is malformed") != NULL);

        ASSERT(progress_store_open(dir));
        db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(producer_status_exec(
            db, "UPDATE stage_cursor SET cursor=12345 "
                "WHERE name='utxo_apply'"));
        ASSERT(producer_status_exec(
            db, "CREATE TABLE consensus_state_producer_session("
                "singleton INTEGER PRIMARY KEY,schema TEXT,"
                "source_tree_root BLOB,source_epoch_digest BLOB,"
                "producer_commit TEXT,toolchain_digest BLOB,"
                "build_inputs_digest BLOB,source_clean INTEGER,"
                "start_time_us INTEGER,"
                "validation_profile INTEGER)"));
        ASSERT(producer_status_exec(
            db, "INSERT INTO consensus_state_producer_session VALUES("
                "1,'zcl.consensus_state_producer_session.v2',"
                "zeroblob(31),zeroblob(32),'',zeroblob(32),"
                "zeroblob(32),1,123,1)"));
        progress_store_close();

        memset(err, 0, sizeof(err));
        ASSERT(!consensus_state_producer_status_read(dir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "source identity is malformed") != NULL);

        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_rejects_malformed_rate_sample(void)
{
    int failures = 0;
    TEST("producer status rejects a non-integer durable rate sample") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "badrate");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(producer_status_exec(
            db,
            "CREATE TABLE utxo_apply_log("
            "height INTEGER PRIMARY KEY,ok INTEGER NOT NULL,"
            "applied_at INTEGER NOT NULL);"
            "INSERT INTO utxo_apply_log VALUES(12000,1,1000);"
            "INSERT INTO utxo_apply_log VALUES(12344,1,'not-a-time');"));
        progress_store_close();

        struct producer_status_read st;
        char err[256] = {0};
        ASSERT(!consensus_state_producer_status_read(dir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "durable rate samples") != NULL);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_rejects_impossible_cursor(void)
{
    int failures = 0;
    TEST("producer status rejects an out-of-range durable stage cursor") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "badcursor");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 12345));
        ASSERT(producer_status_exec(
            db, "UPDATE stage_cursor SET cursor=9223372036854775807 "
                "WHERE name='utxo_apply'"));
        progress_store_close();

        struct producer_status_read st;
        char err[256] = {0};
        ASSERT(!consensus_state_producer_status_read(dir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "utxo_apply cursor is malformed") != NULL);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_completed_target_needs_no_rate(void)
{
    int failures = 0;
    TEST("producer status reports zero ETA at the anchor without rate evidence") {
        char dir[256];
        test_fmt_tmpdir(dir, sizeof(dir), "operator_ux_producer", "complete");
        mkdir(dir, 0700);

        ASSERT(progress_store_open(dir));
        sqlite3 *db = progress_store_db();
        ASSERT(db != NULL);
        /* utxo_apply is the NEXT height, so this is applied through the
         * compiled sovereign anchor 3,056,758. */
        ASSERT(stage_set_named_cursor(db, "utxo_apply", 3056759));
        progress_store_close();

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "datadir", dir));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.ops_producer_status.v1");
        zcl_native_handle_ops_producer_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data,
                                       "durable_rate_available")));
        ASSERT(json_get_bool(json_get(&reply.data, "eta_available")));
        ASSERT(json_get_int(json_get(&reply.data, "eta_seconds")) == 0);
        ASSERT(json_get_int(json_get(&reply.data, "remaining_blocks")) == 0);
        const char *text = json_get_str(json_get(&reply.data, "text"));
        ASSERT(text && strstr(text, "rate=unknown eta=0s") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        test_cleanup_tmpdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_producer_status_rejects_long_datadir(void)
{
    int failures = 0;
    TEST("producer status rejects overlong datadirs before path/render use") {
        char datadir[CONSENSUS_STATE_PRODUCER_DATADIR_MAX + 1];
        memset(datadir, 'x', sizeof(datadir) - 1);
        datadir[sizeof(datadir) - 1] = '\0';

        struct producer_status_read st;
        char err[256];
        ASSERT(!consensus_state_producer_status_read(datadir, &st, err,
                                                      sizeof(err)));
        ASSERT(strstr(err, "exceeds 1023 bytes") != NULL);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "datadir", datadir));
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.ops_producer_status.v1");
        zcl_native_handle_ops_producer_status(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_INVALID);
        ASSERT(strcmp(reply.error.code, "DATADIR_TOO_LONG") == 0);
        ASSERT(json_get(&reply.data, "text") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── CLI UX contract: ONE-LINE status brief ──────────────────────────── */

static void fixture_brief_body(struct json_value *d, int64_t hstar,
                               int64_t header, int64_t gap,
                               const char *sync_state, const char *blocker,
                               int64_t blocker_age_s,
                               int64_t active_conditions, int64_t peer_count,
                               int64_t rss_mb, bool healthy)
{
    json_init(d);
    json_set_object(d);
    json_push_kv_int(d, "hstar", hstar);
    json_push_kv_int(d, "served_height", hstar);
    json_push_kv_int(d, "header_height", header);
    json_push_kv_int(d, "gap", gap);
    json_push_kv_int(d, "peer_best", header);
    json_push_kv_str(d, "sync_state", sync_state);
    json_push_kv_bool(d, "serving", true);
    json_push_kv_bool(d, "healthy", healthy);
    json_push_kv_int(d, "peer_count", peer_count);
    json_push_kv_str(d, "primary_blocker", blocker);
    json_push_kv_int(d, "blocker_age_s", blocker_age_s);
    json_push_kv_int(d, "active_conditions", active_conditions);
    json_push_kv_int(d, "rss_mb", rss_mb);
    json_push_kv_int(d, "tip_advance_age_seconds", 5);
}

static int test_brief_status_one_line_contract(void)
{
    int failures = 0;
    TEST("brief status is ONE line, <=200 bytes, stable key=value, no braces") {
        struct json_value d;
        fixture_brief_body(&d, 100, 142, 42, "syncing",
                           "anchor_backfill_gap", 3600, 2, 8, 512, false);

        char buf[1024];
        zcl_native_status_brief_render(&d, buf, sizeof(buf));

        ASSERT(strchr(buf, '\n') == NULL); /* exactly one line */
        ASSERT(strlen(buf) <= 200);
        ASSERT(strchr(buf, '{') == NULL && strchr(buf, '}') == NULL);
        ASSERT(strstr(buf, "hstar=100") != NULL);
        ASSERT(strstr(buf, "gap=42") != NULL);
        ASSERT(strstr(buf, "peer_best=142") != NULL);
        ASSERT(strstr(buf, "sync=syncing") != NULL);
        ASSERT(strstr(buf, "blocker=anchor_backfill_gap") != NULL);
        ASSERT(strstr(buf, "blocker_age=3600s") != NULL);
        ASSERT(strstr(buf, "conditions=2") != NULL);
        ASSERT(strstr(buf, "peers=8") != NULL);
        ASSERT(strstr(buf, "rss_mb=512") != NULL);

        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

static int test_brief_status_registry_fields_agree(void)
{
    int failures = 0;
    TEST("brief renders blockers=/blocker_head= from the registry so it agrees "
         "with dumpstate blocker, and only when present") {
        /* Disjoint-truth case: headline blocker is a posture gate while the
         * typed-blocker registry head is a different id. Both must appear so
         * the two surfaces never name disjoint truths. */
        struct json_value d;
        fixture_brief_body(&d, 3187524, 3187525, 1, "at_tip",
                           "review_required_bootstrap_trust", 0, 1, 4, 2937,
                           false);
        json_push_kv_int(&d, "active_blockers", 6);
        json_push_kv_str(&d, "blocker_head",
                         "catalog.address_index.lag_exceeded");

        char buf[1024];
        zcl_native_status_brief_render(&d, buf, sizeof(buf));
        ASSERT(strchr(buf, '\n') == NULL);
        ASSERT(strlen(buf) <= 200);
        ASSERT(strstr(buf, "blocker=review_required_bootstrap_trust") != NULL);
        ASSERT(strstr(buf, "blockers=6") != NULL);
        ASSERT(strstr(buf, "blocker_head=catalog.address_index.lag_exceeded")
               != NULL);
        json_free(&d);

        /* Absent case: a node that does not export the registry summary must
         * not fabricate blockers=0 / an empty head. */
        struct json_value d2;
        fixture_brief_body(&d2, 100, 142, 42, "syncing", "none", 0, 0, 8, 512,
                           true);
        zcl_native_status_brief_render(&d2, buf, sizeof(buf));
        ASSERT(strstr(buf, "blockers=") == NULL);
        ASSERT(strstr(buf, "blocker_head=") == NULL);
        json_free(&d2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_brief_status_unknown_fields_render_unknown(void)
{
    int failures = 0;
    TEST("brief status renders 'unknown', never a fabricated zero, for a "
         "missing field") {
        struct json_value d;
        json_init(&d);
        json_set_object(&d);
        /* Deliberately sparse: only sync_state known. */
        json_push_kv_str(&d, "sync_state", "unknown");

        char buf[1024];
        zcl_native_status_brief_render(&d, buf, sizeof(buf));
        ASSERT(strstr(buf, "hstar=unknown") != NULL);
        ASSERT(strstr(buf, "gap=unknown") != NULL);
        ASSERT(strstr(buf, "blocker=unknown") != NULL);
        ASSERT(strstr(buf, "0") == NULL); /* never a fabricated zero */

        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

static int test_money_journey_status_one_line_contract(void)
{
    int failures = 0;
    TEST("money journey status renders the user questions in one safe line") {
        struct json_value d;
        json_init(&d);
        json_set_object(&d);
        json_push_kv_bool(&d, "node_healthy", true);
        json_push_kv_bool(&d, "synced", true);
        json_push_kv_bool(&d, "wallet_ready", true);
        json_push_kv_bool(&d, "can_receive", true);
        json_push_kv_bool(&d, "can_send", false);
        json_push_kv_int(&d, "spendable_zat", 10000000);
        json_push_kv_int(&d, "pending_zat", 1000);
        json_push_kv_int(&d, "reserved_zat", 2000);
        json_push_kv_str(&d, "primary_blocker",
                         "review_required_bootstrap_trust");
        json_push_kv_str(&d, "error_code", "WALLET_LOCKED");
        json_push_kv_str(&d, "next_action", "z23 core sync diagnose");

        char buf[1024];
        zcl_native_status_journey_render(&d, buf, sizeof(buf));
        ASSERT(strchr(buf, '\n') == NULL);
        ASSERT(strlen(buf) <= 320);
        ASSERT(strstr(buf, "node=healthy") != NULL);
        ASSERT(strstr(buf, "synced=yes") != NULL);
        ASSERT(strstr(buf, "wallet=ready") != NULL);
        ASSERT(strstr(buf, "receive=yes") != NULL);
        ASSERT(strstr(buf, "send=no") != NULL);
        ASSERT(strstr(buf, "spendable_zat=10000000") != NULL);
        ASSERT(strstr(buf, "pending_zat=1000") != NULL);
        ASSERT(strstr(buf, "reserved_zat=2000") != NULL);
        ASSERT(strstr(buf, "blocker=review_required_bootstrap_trust") != NULL);
        ASSERT(strstr(buf, "next_action=z23 core sync diagnose") != NULL);
        ASSERT(strstr(buf, "address") == NULL);
        ASSERT(strstr(buf, "path") == NULL);
        json_free(&d);
        PASS();
    }
    TEST("money journey next action cannot inject another output line") {
        struct json_value d;
        json_init(&d);
        json_set_object(&d);
        json_push_kv_str(&d, "next_action", "first\nsecond\tstep");
        char buf[1024];
        zcl_native_status_journey_render(&d, buf, sizeof(buf));
        ASSERT(strchr(buf, '\n') == NULL);
        ASSERT(strstr(buf, "next_action=first second step") != NULL);
        json_free(&d);
        PASS();
    }
    TEST("money journey preserves a complete action under oversized input") {
        struct json_value d;
        json_init(&d);
        json_set_object(&d);
        char oversized[256];
        memset(oversized, 'x', sizeof(oversized) - 1);
        oversized[sizeof(oversized) - 1] = '\0';
        json_push_kv_str(&d, "primary_blocker", oversized);
        json_push_kv_str(&d, "next_action", "z23 core sync diagnose");
        char buf[1024];
        zcl_native_status_journey_render(&d, buf, sizeof(buf));
        ASSERT(strlen(buf) <= 320);
        ASSERT(strstr(buf, "blocker=status_detail_too_long") != NULL);
        ASSERT(strstr(buf, "next_action=z23 core sync diagnose") != NULL);
        json_free(&d);
        PASS();
    }
    TEST("money journey never renders a partial oversized action") {
        struct json_value d;
        json_init(&d);
        json_set_object(&d);
        char oversized[256];
        memset(oversized, 'x', sizeof(oversized) - 1);
        oversized[sizeof(oversized) - 1] = '\0';
        json_push_kv_str(&d, "next_action", oversized);
        char buf[1024];
        zcl_native_status_journey_render(&d, buf, sizeof(buf));
        ASSERT(strlen(buf) <= 320);
        ASSERT(strstr(buf, "next_action=z23 status --format=json") != NULL);
        ASSERT(strstr(buf, "xxxxxxxx") == NULL);
        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

/* ── CLI UX contract: next-command hint ──────────────────────────────── */

static int test_next_command_prioritizes_blocker_over_gap(void)
{
    int failures = 0;
    TEST("next-command names the blocker before the gap or native health") {
        struct json_value d;
        fixture_brief_body(&d, 100, 200, 100, "syncing", "anchor_gap", 10, 0,
                           4, 256, false);
        ASSERT(strcmp(zcl_native_status_brief_next_command(&d),
                      "z23 explain blockers") == 0);
        json_free(&d);

        fixture_brief_body(&d, 100, 200, 100, "syncing", "none", 0, 0, 4,
                           256, false);
        ASSERT(strcmp(zcl_native_status_brief_next_command(&d),
                      "z23 explain sync") == 0);
        json_free(&d);

        fixture_brief_body(&d, 200, 200, 0, "synced", "none", 0, 0, 4, 256,
                           true);
        ASSERT(strcmp(zcl_native_status_brief_next_command(&d),
                      "z23 ops health") == 0);
        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

/* ── CLI UX contract: field selector ──────────────────────────────────── */

static int test_field_selection_selects_requested_fields(void)
{
    int failures = 0;
    TEST("field selection returns exactly the requested fields as key=value") {
        struct json_value d;
        fixture_brief_body(&d, 100, 142, 42, "syncing", "none", 0, 1, 8, 512,
                           true);

        char out[512], err[256];
        ASSERT(zcl_native_render_field_selection(&d, "gap,primary_blocker",
                                                 out, sizeof(out), err,
                                                 sizeof(err)));
        ASSERT(strcmp(out, "gap=42\nprimary_blocker=none\n") == 0);

        /* Whitespace-tolerant, order-preserving. */
        char out2[512];
        ASSERT(zcl_native_render_field_selection(&d, " hstar , sync_state ",
                                                 out2, sizeof(out2), err,
                                                 sizeof(err)));
        ASSERT(strcmp(out2, "hstar=100\nsync_state=syncing\n") == 0);

        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

static int test_field_selection_unknown_field_is_typed_error(void)
{
    int failures = 0;
    TEST("field selection rejects an unknown field name, never a partial "
         "line") {
        struct json_value d;
        fixture_brief_body(&d, 100, 142, 42, "syncing", "none", 0, 1, 8, 512,
                           true);

        char out[512], err[256];
        out[0] = '\1'; /* poison: must stay untouched on failure */
        bool ok = zcl_native_render_field_selection(
            &d, "gap,not_a_real_field", out, sizeof(out), err, sizeof(err));
        ASSERT(!ok);
        ASSERT(out[0] == '\1');
        ASSERT(strstr(err, "not_a_real_field") != NULL);

        /* Duplicate field names are also rejected. */
        ASSERT(!zcl_native_render_field_selection(&d, "gap,gap", out,
                                                  sizeof(out), err,
                                                  sizeof(err)));
        ASSERT(strstr(err, "duplicate") != NULL);

        /* A container value too large for one key=value line fails typed —
         * never emitted truncated mid-string. */
        struct json_value big, item;
        json_init(&big);
        json_set_array(&big);
        for (int i = 0; i < 400; i++) {
            json_init(&item);
            json_set_str(&item, "twenty-byte-filler..");
            json_push_back(&big, &item);
            json_free(&item);
        }
        json_push_kv(&d, "big_container", &big);
        json_free(&big);
        char bigout[16384];
        ASSERT(!zcl_native_render_field_selection(&d, "big_container", bigout,
                                                  sizeof(bigout), err,
                                                  sizeof(err)));
        ASSERT(strstr(err, "big_container") != NULL);
        ASSERT(strstr(err, "format=json") != NULL);

        json_free(&d);
        PASS();
    } _test_next:;
    return failures;
}

/* ── CLI UX contract: unknown-command diagnostic ─────────────────────── */

static int test_unknown_command_diagnostic_has_typed_shape(void)
{
    int failures = 0;
    TEST("unknown-command diagnostic is error=...detail=...try=... plus a "
         "did-you-mean line when the reused search index has a hit") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);

        /* "stat" substring-matches the real "core.status" path/tags in the
         * existing (non-fuzzy) command-search index, so a did-you-mean line
         * is expected — proves the wiring, not a claim about typo-distance
         * quality (we reuse the index as-is, no new fuzzy matcher). */
        char buf[1024];
        size_t n = zcl_native_render_unknown_command(reg, "stat", buf,
                                                      sizeof(buf));
        ASSERT(n > 0);
        ASSERT(strstr(buf, "error=UNKNOWN_COMMAND") != NULL);
        ASSERT(strstr(buf, "detail=") != NULL);
        ASSERT(strstr(buf, "try=z23 discover search stat") != NULL);
        ASSERT(strstr(buf, "did you mean:") != NULL);

        /* A query the index has no hit for still gets the typed error line,
         * just no did-you-mean line (never fabricated). */
        n = zcl_native_render_unknown_command(
            reg, "zzznotarealcommandzzz", buf, sizeof(buf));
        ASSERT(n > 0);
        ASSERT(strstr(buf, "error=UNKNOWN_COMMAND") != NULL);
        ASSERT(strstr(buf, "did you mean:") == NULL);

        /* A NULL/empty method never crashes and writes nothing. */
        ASSERT(zcl_native_render_unknown_command(reg, NULL, buf,
                                                 sizeof(buf)) == 0);
        ASSERT(zcl_native_render_unknown_command(reg, "", buf,
                                                 sizeof(buf)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_operator_ux(void)
{
    int failures = 0;
    failures += test_explain_sync_names_dominant_blocker();
    failures += test_explain_sync_marks_run_ahead_cursors();
    failures += test_explain_topics_and_health();
    failures += test_profile_samples_threads();
    failures += test_producer_status_synthetic();
    failures += test_producer_status_absent();
    failures += test_producer_status_uses_one_read_snapshot();
    failures += test_producer_status_final_receipt_cursor_wins();
    failures += test_producer_status_rate_window_rejects_prior_session();
    failures += test_producer_status_residual_row_integration();
    failures += test_producer_status_rejects_future_rate_for_eta();
    failures += test_producer_status_rejects_malformed_store();
    failures += test_producer_status_rejects_malformed_rate_sample();
    failures += test_producer_status_rejects_impossible_cursor();
    failures += test_producer_status_completed_target_needs_no_rate();
    failures += test_producer_status_rejects_long_datadir();
    failures += test_brief_status_one_line_contract();
    failures += test_brief_status_registry_fields_agree();
    failures += test_brief_status_unknown_fields_render_unknown();
    failures += test_money_journey_status_one_line_contract();
    failures += test_next_command_prioritizes_blocker_over_gap();
    failures += test_field_selection_selects_requested_fields();
    failures += test_field_selection_unknown_field_is_typed_error();
    failures += test_unknown_command_diagnostic_has_typed_shape();
    printf("=== operator_ux: %d failures ===\n", failures);
    return failures;
}
