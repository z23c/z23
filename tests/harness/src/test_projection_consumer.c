/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused coverage for storage/projection_consumer.c — the generic
 * event-log projection consumer skeleton that znam_projection.c and
 * peers_projection.c are built on. A tiny fixture domain (one row per
 * applied event, no parsing) exercises open/catch_up/rebuild/close
 * directly, independent of any real projection's schema.
 */

#include "test/test_core.h"

#include "storage/event_log.h"
#include "storage/projection_consumer.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define PC_CHECK(label, cond) do { \
    bool _ok = (cond); \
    printf("projection_consumer: %s... %s\n", (label), _ok ? "OK" : "FAIL"); \
    if (!_ok) failures++; \
} while (0)

struct fixture_ctx {
    int apply_calls;
};

static bool fixture_ensure_schema(sqlite3 *db, void *ctx)
{
    (void)ctx;
    char *err = NULL;
    int rc = sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS fixture_rows ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " val INTEGER)",
        NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool fixture_apply_event(sqlite3 *db, enum event_log_type type,
                                const void *payload, size_t len, void *ctx,
                                bool *out_handled)
{
    (void)type;
    struct fixture_ctx *fx = ctx;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO fixture_rows(val) VALUES(?)",
                           -1, &s, NULL) != SQLITE_OK) {
        *out_handled = false;
        return false;
    }
    sqlite3_bind_int(s, 1, (int)len);
    (void)payload;
    bool ok = sqlite3_step(s) == SQLITE_DONE;  // raw-sql-ok:test-fixture
    sqlite3_finalize(s);
    if (!ok) {
        *out_handled = false;
        return false;
    }
    fx->apply_calls++;
    *out_handled = true;
    return true;
}

static uint64_t fixture_row_count(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    uint64_t n = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM fixture_rows",
                           -1, &s, NULL) != SQLITE_OK)
        return 0;
    if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-fixture
        n = (uint64_t)sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

static bool append_fixture_event(event_log_t *log, uint8_t tail)
{
    uint8_t payload[4] = {tail, 0, 0, 0};
    return event_log_append(log, EV_PEER_DROPPED, payload, sizeof(payload)) !=
           UINT64_MAX;
}

static int t_open_close_empty(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "projection_consumer", "open");
    test_projection_paths(dir, "fixture", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    struct fixture_ctx fx = {0};
    struct projection_consumer_spec spec = {
        .schema_version = 1,
        .ensure_schema = fixture_ensure_schema,
        .apply_event = fixture_apply_event,
        .ctx = &fx,
        .commit_batch = 0,
    };
    projection_consumer_t *pc = projection_consumer_open(proj_path, log, &spec);
    PC_CHECK("open handles", log && pc);
    PC_CHECK("empty row count", fixture_row_count(projection_consumer_db(pc)) == 0);
    PC_CHECK("bad args reject", projection_consumer_open(NULL, log, &spec) == NULL);
    projection_consumer_close(pc);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_rebuild_replays_from_zero(void)
{
    int failures = 0;
    char dir[256], elog_path[300], proj_path[300];
    test_make_tmpdir(dir, sizeof(dir), "projection_consumer", "rebuild");
    test_projection_paths(dir, "fixture", elog_path, sizeof(elog_path),
                          proj_path, sizeof(proj_path));
    event_log_t *log = event_log_open(elog_path);
    struct fixture_ctx fx = {0};
    struct projection_consumer_spec spec = {
        .schema_version = 1,
        .ensure_schema = fixture_ensure_schema,
        .apply_event = fixture_apply_event,
        .ctx = &fx,
        .commit_batch = 0,
    };
    projection_consumer_t *pc = projection_consumer_open(proj_path, log, &spec);
    PC_CHECK("open handles", log && pc);

    PC_CHECK("append 3 events",
             append_fixture_event(log, 1) && append_fixture_event(log, 2) &&
             append_fixture_event(log, 3));
    uint64_t off3 = projection_consumer_catch_up(pc);
    PC_CHECK("catch_up 3 events", off3 != UINT64_MAX);
    PC_CHECK("row count 3", fixture_row_count(projection_consumer_db(pc)) == 3);
    PC_CHECK("apply_calls 3", fx.apply_calls == 3);

    /* Rebuild without appending anything new: the CALLER drops the
     * domain's own rows first (rebuild only owns the cursor/meta, not
     * domain tables — see projection_consumer.h), then rebuild() must
     * replay the SAME 3 already-consumed events from offset 0 and land
     * on the identical cursor. A plain catch_up() here would be a
     * no-op (cursor is already caught up); rebuild proves it is not. */
    sqlite3 *db = projection_consumer_db(pc);
    char *err = NULL;
    PC_CHECK("clear domain rows before rebuild",
             sqlite3_exec(db, "DELETE FROM fixture_rows", NULL, NULL, &err) ==
             SQLITE_OK);
    if (err) sqlite3_free(err);
    fx.apply_calls = 0;

    uint64_t rebuilt_off = projection_consumer_rebuild(pc);
    PC_CHECK("rebuild succeeds", rebuilt_off != UINT64_MAX);
    PC_CHECK("rebuild lands on same cursor", rebuilt_off == off3);
    PC_CHECK("rebuild replayed all 3 rows", fixture_row_count(db) == 3);
    PC_CHECK("rebuild replayed via apply_event 3x", fx.apply_calls == 3);

    /* Append 2 more events post-rebuild and prove ordinary catch_up
     * still advances forward from the rebuilt cursor (rebuild did not
     * leave the consumer in some special mode). */
    PC_CHECK("append 2 more events",
             append_fixture_event(log, 4) && append_fixture_event(log, 5));
    uint64_t off5 = projection_consumer_catch_up(pc);
    PC_CHECK("catch_up after rebuild advances", off5 != UINT64_MAX &&
                                                off5 > rebuilt_off);
    PC_CHECK("row count 5 after further catch_up", fixture_row_count(db) == 5);

    projection_consumer_close(pc);
    event_log_close(log);

    /* Reopen and confirm the rebuilt+advanced cursor persisted correctly
     * (not silently reset to 0) — an idempotent catch_up on reopen must
     * NOT re-append any rows. */
    log = event_log_open(elog_path);
    struct fixture_ctx fx2 = {0};
    spec.ctx = &fx2;
    pc = projection_consumer_open(proj_path, log, &spec);
    PC_CHECK("reopen handles", log && pc);
    PC_CHECK("reopen preserved row count", fixture_row_count(projection_consumer_db(pc)) == 5);
    PC_CHECK("idempotent catch_up after reopen",
             projection_consumer_catch_up(pc) != UINT64_MAX);
    PC_CHECK("idempotent catch_up did not duplicate rows",
             fixture_row_count(projection_consumer_db(pc)) == 5);

    projection_consumer_close(pc);
    event_log_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

static int t_rebuild_null_safe(void)
{
    int failures = 0;
    PC_CHECK("rebuild NULL pc", projection_consumer_rebuild(NULL) == UINT64_MAX);
    PC_CHECK("catch_up NULL pc", projection_consumer_catch_up(NULL) == UINT64_MAX);
    PC_CHECK("db NULL pc", projection_consumer_db(NULL) == NULL);
    return failures;
}

int test_projection_consumer(void)
{
    int failures = 0;
    printf("\n=== projection_consumer tests ===\n");
    failures += t_open_close_empty();
    failures += t_rebuild_replays_from_zero();
    failures += t_rebuild_null_safe();
    printf("projection_consumer: %d failures\n", failures);
    return failures;
}
