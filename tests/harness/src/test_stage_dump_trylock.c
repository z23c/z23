/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_stage_dump_trylock — the observability-under-load guard for the three
 * tail-stage dump-state views (utxo_apply / script_validate / proof_validate).
 *
 * A2: during catch-up the reducer holds progress_store_tx_lock around each
 * bulk fold. Before this fix the three dumpers took that lock BLOCKING, so an
 * RPC worker calling `dumpstate <stage>` queued behind the fold and, at a few
 * concurrent calls, the node's whole observability front door (dumpstate /
 * status) disappeared exactly while the node was busiest. The fix mirrors
 * reducer_frontier_dump: acquire the lock non-blocking (trylock) and, when the
 * fold owns it, emit {"snapshot_status":"progress_store_busy","retryable":true}
 * and return cleanly instead of blocking. This test proves each dumper takes
 * that busy path — WITHOUT blocking — while another thread holds the lock.
 *
 * A2 amplifier: the utxo_apply dumper's "lowest ok=0 row" query full-scanned
 * ~3.18M rows on a healthy node (no index on ok). utxo_apply_log_ensure_schema
 * now creates a partial index (idx_utxo_apply_log_ok0 ON utxo_apply_log(height)
 * WHERE ok=0); this test asserts EXPLAIN QUERY PLAN uses that index rather than
 * a full table scan.
 *
 * Diagnostics sweep (same theme, other reducer-starvable dumpers): the durable
 * peek in refold_progress_dump_state_json and the failure-summary read behind
 * validate_headers_stage_dump_state_json also took progress_store_tx_lock
 * BLOCKING. Both now trylock and emit a busy status
 * (durable_store_status / failure_summary_status == "progress_store_busy") when
 * the fold owns the lock; validate_headers_log grows a partial ok=0 index that
 * bounds the successful-trylock hold. The cases below prove the busy path
 * (non-blocking + labeled) and the index.
 *
 * Trust-tier sweep: sovereignty_dump_state_json (the dumper behind
 * `z23 status`'s trust-tier surface, event_agent_summary.c ->
 * agent_summary_posture_cache.c) had the SAME blocking-lock hazard — commit
 * cc4de081a's own message names `z23 status` as a victim of this bug
 * class. It now trylocks and, when the fold/importer owns the lock, answers
 * from a process-wide last-known-good trust-tier cache (durable_store_status
 * == "busy_stale_cache" once something has been observed, or
 * "unknown_progress_store_busy" the very first time) instead of blocking.
 * sovereignty_guard_allow() itself stays blocking (enforcement gate) — the
 * dumper's busy branch returns before ever reaching it, so it never inherits
 * that block. The case below proves: (1) busy-before-any-observation reports
 * "unknown_progress_store_busy" with trust_mode "unknown"; (2) a subsequent
 * free call populates the cache with the real trust tier; (3) a second busy
 * call then reports "busy_stale_cache" carrying THAT observed value.
 */

#include "test/test_core.h"

#include "controllers/sovereignty_controller.h"
#include "jobs/proof_validate_stage.h"
#include "jobs/refold_progress.h"
#include "jobs/script_validate_stage.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/validate_headers_stage.h"
#include "json/json.h"
#include "storage/progress_store.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Production schema-ensure for utxo_apply_log / validate_headers_log — declared
 * extern (private headers live under engine/jobs/src/), the same pattern
 * test_utxo_root_ladder_tripwire.c uses. */
extern bool utxo_apply_log_ensure_schema(struct sqlite3 *db);
extern bool validate_headers_log_ensure_schema(struct sqlite3 *db);

#define SD_CHECK(name, expr) do {                                 \
    printf("stage_dump_trylock: %s... ", (name));                 \
    if (expr) { printf("OK\n"); }                                 \
    else { printf("FAIL\n"); failures++; }                        \
} while (0)

/* ---- lock-holder thread: grabs progress_store_tx_lock and parks ---- */
struct locker {
    _Atomic int locked;   /* set once the lock is held */
    _Atomic int release;  /* main thread sets this to let the holder go */
};

static void *locker_thread(void *arg)
{
    struct locker *lk = (struct locker *)arg;
    progress_store_tx_lock();
    atomic_store(&lk->locked, 1);
    /* Hold until told to release (bounded spin so a stuck test can never wedge
     * the suite forever). */
    for (int i = 0; i < 500000 && !atomic_load(&lk->release); i++) {
        struct timespec ts = { 0, 200000 }; /* 0.2ms */
        nanosleep(&ts, NULL);
    }
    progress_store_tx_unlock();
    return NULL;
}

/* True iff `out` carries the busy/retryable marker AND no SQLite detail. */
static bool is_busy_marker(const struct json_value *out)
{
    const struct json_value *st = json_get(out, "snapshot_status");
    const struct json_value *rt = json_get(out, "retryable");
    if (!st || !rt)
        return false;
    const char *s = json_get_str(st);
    return s && strcmp(s, "progress_store_busy") == 0 && json_get_bool(rt);
}

/* True iff `out[key]` is exactly the string `expected`. */
static bool json_status_is(const struct json_value *out, const char *key,
                           const char *expected)
{
    const struct json_value *v = json_get(out, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s && strcmp(s, expected) == 0;
}

/* (A2) Each of the 3 dumpers returns the busy marker — fast, non-blocking —
 * while a helper thread holds progress_store_tx_lock. */
static int case_dumpers_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "busy");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("busy: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    /* Create the utxo_apply schema so the non-busy path would have real rows to
     * read; the other two dumpers hit the busy path before any table read. */
    SD_CHECK("busy: utxo_apply schema", db && utxo_apply_log_ensure_schema(db));

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("busy: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    /* Wait until the holder actually owns the lock. */
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL);
    }
    SD_CHECK("busy: locker holds the progress lock", atomic_load(&lk.locked));

    /* Each dumper must return true AND the busy marker, promptly. A blocking
     * lock would deadlock here (the holder only releases after we signal). */
    struct json_value out;

    json_init(&out);
    bool d1 = utxo_apply_dump_state_json(&out, NULL);
    SD_CHECK("busy: utxo_apply dump returns true", d1);
    SD_CHECK("busy: utxo_apply emits progress_store_busy", is_busy_marker(&out));

    json_init(&out);
    bool d2 = script_validate_dump_state_json(&out, NULL);
    SD_CHECK("busy: script_validate dump returns true", d2);
    SD_CHECK("busy: script_validate emits progress_store_busy",
             is_busy_marker(&out));

    json_init(&out);
    bool d3 = proof_validate_dump_state_json(&out, NULL);
    SD_CHECK("busy: proof_validate dump returns true", d3);
    SD_CHECK("busy: proof_validate emits progress_store_busy",
             is_busy_marker(&out));

    /* Release the holder and confirm the SAME dumper now takes the normal path
     * (no busy marker) — proves the trylock succeeds when the lock is free. */
    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    json_init(&out);
    bool d4 = utxo_apply_dump_state_json(&out, NULL);
    SD_CHECK("free: utxo_apply dump returns true", d4);
    SD_CHECK("free: utxo_apply no longer busy", !is_busy_marker(&out));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (A2 amplifier) The lowest-ok=0 query uses the partial index, not a full
 * table scan. */
static int case_utxo_apply_ok0_index_used(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "eqp");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("eqp: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    SD_CHECK("eqp: utxo_apply schema (creates index)",
             db && utxo_apply_log_ensure_schema(db));

    /* A body of healthy ok=1 rows and no ok=0 row — the exact production shape
     * where a full scan would be worst (walks every row to find nothing). */
    progress_store_tx_lock();
    bool ins_ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                      == SQLITE_OK;
    for (int h = 1; ins_ok && h <= 4000; h++) {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO utxo_apply_log (height,status,ok,spent_count,"
                 "added_count,total_value_delta,applied_at) "
                 "VALUES (%d,'VERIFIED',1,0,0,0,0)", h);
        ins_ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    }
    sqlite3_exec(db, ins_ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    SD_CHECK("eqp: rows inserted", ins_ok);

    /* EXPLAIN QUERY PLAN of the exact dumper query. Column 3 ("detail") must
     * name the partial index; it must NOT be a bare "SCAN utxo_apply_log". */
    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool prep = sqlite3_prepare_v2(db,
        "EXPLAIN QUERY PLAN "
        "SELECT height, COALESCE(status,''), "
        "       COALESCE(first_failure_kind,''), first_failure_detail "
        "  FROM utxo_apply_log WHERE ok=0 "
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK;
    SD_CHECK("eqp: prepare EXPLAIN QUERY PLAN", prep);

    bool uses_index = false;
    bool bare_scan = false;
    while (prep && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *detail = sqlite3_column_text(st, 3);
        const char *d = detail ? (const char *)detail : "";
        if (strstr(d, "idx_utxo_apply_log_ok0"))
            uses_index = true;
        /* A full-table scan reads "SCAN utxo_apply_log" with no "USING INDEX". */
        if (strstr(d, "SCAN utxo_apply_log") && !strstr(d, "USING INDEX"))
            bare_scan = true;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();

    SD_CHECK("eqp: query plan uses idx_utxo_apply_log_ok0", uses_index);
    SD_CHECK("eqp: query plan is NOT a bare full-table scan", !bare_scan);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (diagnostics sweep) refold_progress + validate_headers dumps take the busy
 * path — fast, non-blocking, labeled — while a helper thread holds the lock,
 * then the normal path once it is free. */
static int case_diag_dumps_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "diag");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("diag: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    /* validate_headers needs its table so the FREE path has a real read; the
     * busy path returns before any table read. */
    SD_CHECK("diag: validate_headers schema",
             db && validate_headers_log_ensure_schema(db));

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("diag: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL);
    }
    SD_CHECK("diag: locker holds the progress lock", atomic_load(&lk.locked));

    /* A blocking lock would deadlock here (the holder only releases on signal). */
    struct json_value out;

    json_init(&out);
    bool r1 = refold_progress_dump_state_json(&out, NULL);
    SD_CHECK("diag: refold_progress dump returns true", r1);
    SD_CHECK("diag: refold_progress durable_store_status busy",
             json_status_is(&out, "durable_store_status", "progress_store_busy"));

    json_init(&out);
    bool v1 = validate_headers_stage_dump_state_json(&out, NULL);
    SD_CHECK("diag: validate_headers dump returns true", v1);
    SD_CHECK("diag: validate_headers failure_summary_status busy",
             json_status_is(&out, "failure_summary_status",
                            "progress_store_busy"));

    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    json_init(&out);
    bool r2 = refold_progress_dump_state_json(&out, NULL);
    SD_CHECK("free: refold_progress durable_store_status available",
             r2 && json_status_is(&out, "durable_store_status", "available"));

    json_init(&out);
    bool v2 = validate_headers_stage_dump_state_json(&out, NULL);
    SD_CHECK("free: validate_headers failure_summary_status available",
             v2 && json_status_is(&out, "failure_summary_status", "available"));

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (diagnostics sweep amplifier) The validate_headers failure-summary ok=0 query
 * uses the partial index, not a full table scan. */
static int case_validate_headers_ok0_index_used(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "vheqp");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("vheqp: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    sqlite3 *db = progress_store_db();
    SD_CHECK("vheqp: validate_headers schema (creates index)",
             db && validate_headers_log_ensure_schema(db));

    progress_store_tx_lock();
    sqlite3_stmt *st = NULL;
    bool prep = sqlite3_prepare_v2(db,
        "EXPLAIN QUERY PLAN "
        "SELECT height, COALESCE(fail_reason, '') "
        "  FROM validate_headers_log WHERE ok=0 "
        " ORDER BY height ASC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK;
    SD_CHECK("vheqp: prepare EXPLAIN QUERY PLAN", prep);

    bool uses_index = false;
    bool bare_scan = false;
    while (prep && sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *detail = sqlite3_column_text(st, 3);
        const char *d = detail ? (const char *)detail : "";
        if (strstr(d, "idx_validate_headers_log_ok0"))
            uses_index = true;
        if (strstr(d, "SCAN validate_headers_log") && !strstr(d, "USING INDEX"))
            bare_scan = true;
    }
    sqlite3_finalize(st);
    progress_store_tx_unlock();

    SD_CHECK("vheqp: query plan uses idx_validate_headers_log_ok0", uses_index);
    SD_CHECK("vheqp: query plan is NOT a bare full-table scan", !bare_scan);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* (trust-tier sweep) sovereignty_dump_state_json takes the busy path — fast,
 * non-blocking, labeled from the last-known-good cache — while a helper
 * thread holds progress_store_tx_lock; the very first busy observation (no
 * cache yet) is labeled distinctly from a later one (cache populated by an
 * intervening free call). */
static int case_sovereignty_dump_busy_path(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "stage_dump_trylock", "sov");

    progress_store_close();
    bool opened = progress_store_open(dir);
    SD_CHECK("sov: progress_store opens", opened);
    if (!opened) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    struct locker lk = { 0, 0 };
    pthread_t th;
    int rc = pthread_create(&th, NULL, locker_thread, &lk);
    SD_CHECK("sov: locker thread starts", rc == 0);
    if (rc != 0) {
        progress_store_close();
        test_cleanup_tmpdir(dir);
        return failures;
    }
    for (int i = 0; i < 500000 && !atomic_load(&lk.locked); i++) {
        struct timespec ts = { 0, 200000 };
        nanosleep(&ts, NULL);
    }
    SD_CHECK("sov: locker holds the progress lock", atomic_load(&lk.locked));

    /* A blocking lock would deadlock here (the holder only releases on
     * signal) — proves the dumper never queues behind the fold. First
     * observation ever: no cache published yet. */
    struct json_value out;
    json_init(&out);
    bool d1 = sovereignty_dump_state_json(&out, NULL);
    SD_CHECK("sov busy(1st): dump returns true", d1);
    SD_CHECK("sov busy(1st): durable_store_status unknown_progress_store_busy",
             json_status_is(&out, "durable_store_status",
                            "unknown_progress_store_busy"));
    SD_CHECK("sov busy(1st): trust_mode unknown",
             json_status_is(&out, "trust_mode", "unknown"));

    atomic_store(&lk.release, 1);
    pthread_join(th, NULL);

    /* Free path: real trust tier computed and published to the cache. A
     * fresh datadir has no coins_kv migration stamp, so trust_mode == bare
     * (G-SOV part 3's !proven_authority disjunct). */
    json_init(&out);
    bool d2 = sovereignty_dump_state_json(&out, NULL);
    SD_CHECK("sov free: dump returns true", d2);
    SD_CHECK("sov free: durable_store_status available",
             json_status_is(&out, "durable_store_status", "available"));
    SD_CHECK("sov free: trust_mode == bare",
             json_status_is(&out, "trust_mode", "bare"));

    /* Second busy window: the cache now holds the value the free call just
     * observed, so the busy answer must carry THAT value, labeled stale. */
    struct locker lk2 = { 0, 0 };
    rc = pthread_create(&th, NULL, locker_thread, &lk2);
    SD_CHECK("sov: 2nd locker thread starts", rc == 0);
    if (rc == 0) {
        for (int i = 0; i < 500000 && !atomic_load(&lk2.locked); i++) {
            struct timespec ts = { 0, 200000 };
            nanosleep(&ts, NULL);
        }
        SD_CHECK("sov: 2nd locker holds the progress lock",
                 atomic_load(&lk2.locked));

        json_init(&out);
        bool d3 = sovereignty_dump_state_json(&out, NULL);
        SD_CHECK("sov busy(2nd): dump returns true", d3);
        SD_CHECK("sov busy(2nd): durable_store_status busy_stale_cache",
                 json_status_is(&out, "durable_store_status",
                                "busy_stale_cache"));
        SD_CHECK("sov busy(2nd): trust_mode == bare (from cache)",
                 json_status_is(&out, "trust_mode", "bare"));

        atomic_store(&lk2.release, 1);
        pthread_join(th, NULL);
    }

    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_stage_dump_trylock(void)
{
    int failures = 0;
    failures += case_dumpers_busy_path();
    failures += case_utxo_apply_ok0_index_used();
    failures += case_diag_dumps_busy_path();
    failures += case_validate_headers_ok0_index_used();
    failures += case_sovereignty_dump_busy_path();
    if (failures == 0)
        printf("test_stage_dump_trylock: ALL PASSED\n");
    else
        printf("test_stage_dump_trylock: %d FAILURE(S)\n", failures);
    return failures;
}
