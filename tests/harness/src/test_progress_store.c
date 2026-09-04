/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the progress_store singleton (engine/modules/storage/src/progress_store.c).
 *
 * Coverage:
 *   - open creates <datadir>/consensus.db with WAL + stage_cursor table
 *   - second open on the same datadir is idempotent (no error, same handle)
 *   - second open on a *different* datadir is rejected (one process, one store)
 *   - close releases the singleton; reopen on a fresh path succeeds
 *   - data persisted via the F-2 stage primitive survives close + reopen
 *   - dump_state_json reports open status, path, and stage_cursor row count */

#include "test/test_core.h"

#include "json/json.h"
#include "storage/consensus_db.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "util/blocker.h"
#include "util/stage.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PS_CHECK(name, expr) do { \
    printf("progress_store: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)


/* Tiny stage step that advances the cursor by one each time. */
static job_result_t step_advance_by_one(struct stage_step_ctx *c)
{
    c->cursor_out = c->cursor_in + 1;
    return JOB_ADVANCED;
}

/* ── Wave A2 lock-order concurrency fixture ─────────────────────────────
 * Two threads, one per store handle, each holding its OWN tx lock + BEGIN
 * IMMEDIATE for a beat. They must not deadlock (different mutex domains,
 * WAL single-writer resolved by busy_timeout) and both must commit. */
struct lo_thread_arg {
    _Atomic bool committed;
    int hold_ms;
};

static void lo_sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void *lo_kernel_writer(void *p)
{
    struct lo_thread_arg *a = p;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    bool ok = db != NULL &&
              sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) {
        const int32_t v = 0x1111;
        ok = progress_meta_set_in_tx(db, "lock_order.kernel", &v, sizeof(v));
        lo_sleep_ms(a->hold_ms);               /* hold the writer for a beat */
        ok = sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) ==
                 SQLITE_OK && ok;
    }
    progress_store_tx_unlock();
    atomic_store(&a->committed, ok);
    return NULL;
}

static void *lo_projection_writer(void *p)
{
    struct lo_thread_arg *a = p;
    projection_store_tx_lock();
    sqlite3 *db = projection_store_db();
    bool ok = db != NULL &&
              sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) {
        ok = sqlite3_exec(db,
                          "INSERT OR REPLACE INTO lo_projection_scratch"
                          "(k,v) VALUES(1, 0x2222)", NULL, NULL, NULL) ==
             SQLITE_OK;
        lo_sleep_ms(a->hold_ms);
        ok = sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) ==
                 SQLITE_OK && ok;
    }
    projection_store_tx_unlock();
    atomic_store(&a->committed, ok);
    return NULL;
}

/* Count quarantine sidecar files (consensus.db*.corrupt.*) in dir. Used to
 * assert the quick_check quarantine fired exactly when expected. */
static int ps_count_corrupt(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "consensus.db", 12) == 0 &&
            strstr(e->d_name, ".corrupt.") != NULL)
            n++;
    }
    closedir(d);
    return n;
}

/* Same as ps_count_corrupt but for projection_store's progress.kv*.corrupt.*
 * sidecars. */
static int ps_count_corrupt_projection(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "progress.kv", 11) == 0 &&
            strstr(e->d_name, ".corrupt.") != NULL)
            n++;
    }
    closedir(d);
    return n;
}

int test_progress_store(void)
{
    printf("\n=== progress_store tests ===\n");
    int failures = 0;

    blocker_module_init();

    /* ── open creates file + table, idempotent on same path ────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "open");

        PS_CHECK("first open succeeds", progress_store_open(dir));
        PS_CHECK("handle is non-NULL", progress_store_db() != NULL);

        char fpath[512];
        /* After the A3 flip the kernel store file is consensus.db (a legacy
         * progress.kv would be migrated in place first). */
        snprintf(fpath, sizeof(fpath), "%s/consensus.db", dir);
        struct stat st;
        PS_CHECK("consensus.db file exists",
                 stat(fpath, &st) == 0 && S_ISREG(st.st_mode));

        sqlite3 *db1 = progress_store_db();
        PS_CHECK("second open same dir is idempotent",
                 progress_store_open(dir));
        PS_CHECK("handle unchanged after idempotent open",
                 progress_store_db() == db1);

        progress_store_tx_lock();
        bool recursive_trylock = progress_store_tx_trylock();
        PS_CHECK("trylock succeeds recursively for current owner",
                 recursive_trylock);
        if (recursive_trylock)
            progress_store_tx_unlock();
        progress_store_tx_unlock();

        /* Verify the stage_cursor schema is queryable. */
        sqlite3_stmt *st_check = NULL;
        int rc = sqlite3_prepare_v2(progress_store_db(),
            "SELECT COUNT(*) FROM stage_cursor",
            -1, &st_check, NULL);
        PS_CHECK("stage_cursor table query prepares",
                 rc == SQLITE_OK);
        sqlite3_finalize(st_check);

        /* Observational status readers use their own WAL connection rather
         * than queueing behind the reducer's shared-handle transaction lock. */
        sqlite3 *reader = progress_store_open_reader();
        PS_CHECK("independent read-only connection opens",
                 reader != NULL && reader != progress_store_db());
        st_check = NULL;
        rc = reader ? sqlite3_prepare_v2(
            reader, "SELECT COUNT(*) FROM stage_cursor", -1, &st_check, NULL)
                    : SQLITE_CANTOPEN;
        PS_CHECK("independent reader sees stage_cursor", rc == SQLITE_OK);
        if (st_check)
            sqlite3_finalize(st_check);
        if (reader)
            sqlite3_close(reader);

        /* Different dir is rejected (one process, one store). */
        char dir2[256];
        test_make_tmpdir(dir2, sizeof(dir2), "progress_store", "open_other");
        PS_CHECK("second open with different dir is rejected",
                 !progress_store_open(dir2));

        progress_store_close();
        PS_CHECK("handle NULL after close",
                 progress_store_db() == NULL);

        test_cleanup_tmpdir(dir);
        test_cleanup_tmpdir(dir2);
    }

    /* ── cursor persistence: stage cursor survives close + reopen ──── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "persist");

        PS_CHECK("open #1 OK", progress_store_open(dir));
        stage_t *s1 = stage_create("test-advance",
                                    step_advance_by_one, NULL);
        PS_CHECK("stage create OK", s1 != NULL);

        sqlite3 *db = progress_store_db();
        for (int i = 0; i < 5; i++) {
            PS_CHECK("advance step OK",
                     stage_run_once(s1, db) == JOB_ADVANCED);
        }
        PS_CHECK("cursor == 5 after 5 advances",
                 stage_cursor(s1) == 5);

        stage_destroy(s1);
        progress_store_close();

        /* Reopen and verify the cursor is still 5. */
        PS_CHECK("open #2 OK (reopen)", progress_store_open(dir));
        stage_t *s2 = stage_create("test-advance",
                                    step_advance_by_one, NULL);
        /* stage_run_once will restore cursor from DB on first invocation. */
        PS_CHECK("first step after reopen advances from 5 to 6",
                 stage_run_once(s2, progress_store_db()) == JOB_ADVANCED);
        PS_CHECK("cursor == 6 after reopen + 1 step",
                 stage_cursor(s2) == 6);

        stage_destroy(s2);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── dump_state_json shape ─────────────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "dump");

        char buf[1024];

        /* Closed state. */
        struct json_value v_closed;
        json_init(&v_closed);
        PS_CHECK("dump_state_json works when closed",
                 progress_store_dump_state_json(&v_closed, NULL));
        size_t n = json_write(&v_closed, buf, sizeof(buf));
        PS_CHECK("closed dump serializes", n > 0 && n < sizeof(buf));
        PS_CHECK("closed dump has open=false",
                 strstr(buf, "\"open\":false") != NULL);
        json_free(&v_closed);

        /* Open state. */
        PS_CHECK("open for dump", progress_store_open(dir));
        struct json_value v_open;
        json_init(&v_open);
        PS_CHECK("dump_state_json works when open",
                 progress_store_dump_state_json(&v_open, NULL));
        n = json_write(&v_open, buf, sizeof(buf));
        PS_CHECK("open dump serializes", n > 0 && n < sizeof(buf));
        PS_CHECK("open dump has open=true",
                 strstr(buf, "\"open\":true") != NULL);
        PS_CHECK("open dump reports stage_cursor_rows",
                 strstr(buf, "\"stage_cursor_rows\"") != NULL);
        PS_CHECK("open dump reports path",
                 strstr(buf, "consensus.db") != NULL);
        json_free(&v_open);

        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── input validation ──────────────────────────────────────────── */
    {
        PS_CHECK("open(NULL) rejected", !progress_store_open(NULL));
        PS_CHECK("open(\"\") rejected", !progress_store_open(""));
        PS_CHECK("reader unavailable while closed",
                 progress_store_open_reader() == NULL);
        PS_CHECK("dump(NULL) rejected",
                 !progress_store_dump_state_json(NULL, NULL));
    }

    /* ── progress_meta k/v API (S-4b) ───────────────────────────────── */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "meta");
        PS_CHECK("open for meta", progress_store_open(dir));
        sqlite3 *db = progress_store_db();

        /* Missing key returns found=false, len=0, function returns true. */
        bool found = true;
        size_t got = 99;
        uint8_t out[64] = {0};
        PS_CHECK("get missing returns true",
                 progress_meta_get(db, "no-such", out, sizeof(out),
                                   &got, &found));
        PS_CHECK("get missing reports not-found", !found && got == 0);

        /* Round-trip a blob value. */
        const char *payload = "the-quick-brown-fox";
        size_t payload_len = strlen(payload);
        PS_CHECK("set blob OK",
                 progress_meta_set(db, "k.blob", payload, payload_len));

        memset(out, 0, sizeof(out));
        got = 0; found = false;
        PS_CHECK("get blob OK",
                 progress_meta_get(db, "k.blob", out, sizeof(out),
                                   &got, &found));
        PS_CHECK("get blob reports found", found);
        PS_CHECK("get blob length matches", got == payload_len);
        PS_CHECK("get blob bytes match",
                 memcmp(out, payload, payload_len) == 0);

        memset(out, 0, sizeof(out));
        got = 0; found = false;
        PS_CHECK("exact-BLOB get accepts BLOB storage",
                 progress_meta_get_blob_exact(
                     db, "k.blob", out, sizeof(out), &got, &found) &&
                 found && got == payload_len &&
                 memcmp(out, payload, payload_len) == 0);
        PS_CHECK("exact-BLOB get reports missing without error",
                 progress_meta_get_blob_exact(
                     db, "k.exact-missing", out, sizeof(out), &got,
                     &found) && !found && got == 0);

        PS_CHECK("exact-BLOB TEXT fixture writes",
                 sqlite3_exec(db,
                     "INSERT OR REPLACE INTO progress_meta(key,value) "
                     "VALUES('k.exact-text',CAST('123x' AS TEXT))",
                     NULL, NULL, NULL) == SQLITE_OK);
        got = 99; found = false;
        PS_CHECK("exact-BLOB get rejects numeric-prefix TEXT authority",
                 !progress_meta_get_blob_exact(
                     db, "k.exact-text", out, sizeof(out), &got, &found) &&
                 found && got == 0);
        PS_CHECK("exact-BLOB REAL fixture writes",
                 sqlite3_exec(db,
                     "INSERT OR REPLACE INTO progress_meta(key,value) "
                     "VALUES('k.exact-real',1.25)",
                     NULL, NULL, NULL) == SQLITE_OK);
        got = 99; found = false;
        PS_CHECK("exact-BLOB get rejects REAL authority",
                 !progress_meta_get_blob_exact(
                     db, "k.exact-real", out, sizeof(out), &got, &found) &&
                 found && got == 0);
        PS_CHECK("exact-BLOB oversized fixture writes",
                 progress_meta_set(db, "k.exact-long", out, sizeof(out)));
        got = 99; found = false;
        PS_CHECK("exact-BLOB get never truncates authority",
                 !progress_meta_get_blob_exact(
                     db, "k.exact-long", out, 4, &got, &found) && found &&
                 got == 0);

        /* Out-of-band: get with NULL buffer reports length only. */
        got = 0;
        PS_CHECK("get blob with NULL buf reports length",
                 progress_meta_get(db, "k.blob", NULL, 0, &got, &found) &&
                 got == payload_len && found);

        /* INSERT OR REPLACE semantics — second set overwrites. */
        const char *payload2 = "OVERWRITTEN";
        PS_CHECK("set overwrite OK",
                 progress_meta_set(db, "k.blob",
                                   payload2, strlen(payload2)));
        got = 0;
        PS_CHECK("overwritten get OK",
                 progress_meta_get(db, "k.blob", out, sizeof(out),
                                   &got, &found));
        PS_CHECK("overwritten length matches",
                 got == strlen(payload2));
        PS_CHECK("overwritten bytes match",
                 memcmp(out, payload2, strlen(payload2)) == 0);

        /* int32 round-trip — typical sentinel/height storage. */
        int32_t height_in = 3120921;
        int32_t height_out = 0;
        PS_CHECK("set int32",
                 progress_meta_set(db, "k.height",
                                   &height_in, sizeof(height_in)));
        PS_CHECK("get int32",
                 progress_meta_get(db, "k.height", &height_out,
                                   sizeof(height_out), &got, &found));
        PS_CHECK("int32 round-trips",
                 found && got == sizeof(int32_t) &&
                 height_out == height_in);

        /* delete removes the row. */
        PS_CHECK("delete OK", progress_meta_delete(db, "k.blob"));
        found = true; got = 99;
        PS_CHECK("delete is observable",
                 progress_meta_get(db, "k.blob", out, sizeof(out),
                                   &got, &found) && !found && got == 0);
        /* deleting a missing key is allowed (no-op). */
        PS_CHECK("delete missing is no-op success",
                 progress_meta_delete(db, "never-existed"));

        /* in_tx variants compose with an outer BEGIN IMMEDIATE. */
        PS_CHECK("BEGIN for compose",
                 sqlite3_exec(db, "BEGIN IMMEDIATE",
                              NULL, NULL, NULL) == SQLITE_OK);
        const uint8_t one = 1;
        PS_CHECK("set_in_tx",
                 progress_meta_set_in_tx(db, "sentinel", &one, 1));
        PS_CHECK("delete_in_tx (sentinel) ok",
                 progress_meta_delete_in_tx(db, "sentinel"));
        PS_CHECK("COMMIT compose OK",
                 sqlite3_exec(db, "COMMIT",
                              NULL, NULL, NULL) == SQLITE_OK);
        PS_CHECK("sentinel not present after delete in compose",
                 progress_meta_get(db, "sentinel", out, sizeof(out),
                                   &got, &found) && !found);

        /* Batch-aware nesting (J3): the batch-unaware verbs
         * progress_meta_set / progress_meta_delete used to issue an
         * unconditional own BEGIN IMMEDIATE, which SQLite rejects when a
         * transaction is already open ("cannot start a transaction within a
         * transaction"). They now detect an open txn
         * (sqlite3_get_autocommit()==0) and nest as a SAVEPOINT, so a bare call
         * inside an outer BEGIN succeeds and commits atomically with that outer
         * transaction. */
        PS_CHECK("BEGIN for nested set",
                 sqlite3_exec(db, "BEGIN IMMEDIATE",
                              NULL, NULL, NULL) == SQLITE_OK);
        const uint8_t nested_val = 0x5a;
        PS_CHECK("progress_meta_set inside open BEGIN now succeeds",
                 progress_meta_set(db, "j3.nested", &nested_val, 1));
        memset(out, 0, sizeof(out));
        got = 0; found = false;
        PS_CHECK("nested set visible within outer txn",
                 progress_meta_get(db, "j3.nested", out, sizeof(out),
                                   &got, &found) &&
                 found && got == 1 && out[0] == 0x5a);
        PS_CHECK("progress_meta_delete inside open BEGIN also succeeds",
                 progress_meta_delete(db, "j3.nested"));
        PS_CHECK("nested delete visible within outer txn",
                 progress_meta_get(db, "j3.nested", out, sizeof(out),
                                   &got, &found) && !found);
        PS_CHECK("re-set nested for commit proof",
                 progress_meta_set(db, "j3.nested", &nested_val, 1));
        PS_CHECK("COMMIT outer txn OK (nested savepoints released into it)",
                 sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK);
        memset(out, 0, sizeof(out));
        got = 0; found = false;
        PS_CHECK("nested set committed durably with the outer txn",
                 progress_meta_get(db, "j3.nested", out, sizeof(out),
                                   &got, &found) &&
                 found && got == 1 && out[0] == 0x5a);
        /* clean the key so later persistence assertions are unaffected. */
        PS_CHECK("cleanup nested key",
                 progress_meta_delete(db, "j3.nested"));

        /* Bad input → false. */
        PS_CHECK("set NULL db rejected",
                 !progress_meta_set(NULL, "k", "v", 1));
        PS_CHECK("set NULL key rejected",
                 !progress_meta_set(db, NULL, "v", 1));
        PS_CHECK("set empty key rejected",
                 !progress_meta_set(db, "", "v", 1));
        PS_CHECK("get NULL db rejected",
                 !progress_meta_get(NULL, "k", out, sizeof(out),
                                    &got, &found));

        /* Persistence across close + reopen. */
        const char *persist_payload = "PERSISTED-1";
        PS_CHECK("set for persistence",
                 progress_meta_set(db, "k.persist",
                                   persist_payload,
                                   strlen(persist_payload)));
        progress_store_close();
        PS_CHECK("reopen for persistence", progress_store_open(dir));
        memset(out, 0, sizeof(out));
        got = 0; found = false;
        PS_CHECK("persisted blob survives close+reopen",
                 progress_meta_get(progress_store_db(), "k.persist",
                                   out, sizeof(out), &got, &found) &&
                 found && got == strlen(persist_payload) &&
                 memcmp(out, persist_payload, got) == 0);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── integrity quick_check + quarantine self-heal (competition
     *    robustness) ─────────────────────────────────────────────────────
     *
     * A corrupt progress.kv must NOT pin the node silently. On open the store
     * runs PRAGMA quick_check; a non-"ok" verdict quarantines the file aside
     * (rename → progress.kv.corrupt.<ts>...) and reopens a FRESH, empty store
     * so boot can re-seed coins_kv from the snapshot/anchor and re-fold. This
     * mirrors node.db's db_quick_check_ok path. We prove three things:
     *   (a) a HEALTHY store reopens with NO quarantine (no false positive),
     *   (b) a deliberately page-garbled store is detected → quarantine file
     *       appears → reopen succeeds with a fresh, queryable, EMPTY store,
     *   (c) it is auto-terminating (one quarantine, not a loop). */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "quarantine");
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/consensus.db", dir);

        /* Seed a healthy store with a recognizable marker, then close so the
         * WAL is checkpointed back into the main file (close TRUNCATEs WAL). */
        PS_CHECK("quarantine: seed open", progress_store_open(dir));
        const char *marker = "MARKER-PRE-CORRUPT";
        PS_CHECK("quarantine: seed marker",
                 progress_meta_set(progress_store_db(), "k.marker",
                                   marker, strlen(marker)));
        progress_store_close();

        /* (a) Reopen the HEALTHY file — must NOT quarantine, marker survives. */
        PS_CHECK("quarantine: healthy reopen OK", progress_store_open(dir));
        {
            uint8_t out[64] = {0};
            size_t got = 0; bool found = false;
            PS_CHECK("quarantine: healthy marker survives",
                     progress_meta_get(progress_store_db(), "k.marker",
                                       out, sizeof(out), &got, &found) &&
                     found && got == strlen(marker) &&
                     memcmp(out, marker, got) == 0);
        }
        PS_CHECK("quarantine: no false-positive .corrupt file",
                 ps_count_corrupt(dir) == 0);
        progress_store_close();

        /* Deliberately corrupt a middle page of the main DB file. SQLite's
         * default page size is 4096; page 1 is the header (offset 0). We
         * scribble garbage well inside the file (offset 4096 onward) so the
         * header still parses far enough for quick_check to walk the b-tree
         * and report malformation rather than a bare "file is not a
         * database". */
        {
            struct stat st;
            PS_CHECK("quarantine: file exists pre-corrupt",
                     stat(fpath, &st) == 0 && st.st_size > 4096);
            FILE *f = fopen(fpath, "r+b");
            PS_CHECK("quarantine: open file for corruption", f != NULL);
            if (f) {
                /* Overwrite from offset 4096 with 0xEE garbage across the
                 * second page region so a b-tree page is clobbered. */
                long start = 4096;
                long span = st.st_size - start;
                if (span > 4096) span = 4096;  /* one page is plenty */
                if (span < 0) span = 0;
                int seek_ok = (fseek(f, start, SEEK_SET) == 0);
                PS_CHECK("quarantine: seek into file body", seek_ok);
                uint8_t garbage[4096];
                memset(garbage, 0xEE, sizeof(garbage));
                size_t to_write = (size_t)span;
                size_t wrote = fwrite(garbage, 1,
                                      to_write < sizeof(garbage)
                                          ? to_write : sizeof(garbage), f);
                PS_CHECK("quarantine: wrote garbage page", wrote > 0);
                fclose(f);
            }
        }

        /* (b) Reopen the CORRUPT file — quick_check must fire the quarantine
         *     and reopen a fresh store. open() returns true (self-healed). */
        PS_CHECK("quarantine: corrupt reopen self-heals (returns true)",
                 progress_store_open(dir));
        PS_CHECK("quarantine: handle non-NULL after self-heal",
                 progress_store_db() != NULL);
        PS_CHECK("quarantine: .corrupt sidecar was created",
                 ps_count_corrupt(dir) >= 1);
        /* Fresh store is queryable (schema re-created) ... */
        {
            sqlite3_stmt *q = NULL;
            int rc = sqlite3_prepare_v2(progress_store_db(),
                "SELECT COUNT(*) FROM stage_cursor", -1, &q, NULL);
            PS_CHECK("quarantine: fresh store stage_cursor queryable",
                     rc == SQLITE_OK);
            sqlite3_finalize(q);
        }
        /* ... and EMPTY: the pre-corrupt marker is GONE (state was derived,
         * the snapshot/anchor is the real source of truth). */
        {
            uint8_t out[64] = {0};
            size_t got = 99; bool found = true;
            PS_CHECK("quarantine: fresh store dropped stale marker",
                     progress_meta_get(progress_store_db(), "k.marker",
                                       out, sizeof(out), &got, &found) &&
                     !found && got == 0);
        }
        progress_store_close();

        /* (c) A second reopen of the now-healthy fresh store does NOT create a
         *     further .corrupt file (auto-terminating; one quarantine). */
        {
            int before = ps_count_corrupt(dir);
            PS_CHECK("quarantine: post-heal reopen OK",
                     progress_store_open(dir));
            PS_CHECK("quarantine: no second quarantine (idempotent)",
                     ps_count_corrupt(dir) == before);
            progress_store_close();
        }

        test_cleanup_tmpdir(dir);
    }

    /* ── FUTURE schema marker (binary downgrade) refuses the open ──────────
     *
     * A consensus.db written by a NEWER binary (schema marker version >
     * CONSENSUS_DB_SCHEMA_VERSION) must refuse the open outright rather than
     * being silently treated as healthy — see
     * consensus_db_schema_is_downgrade() / progress_store_open(). Prove: (1)
     * a healthy current-version marker opens fine, (2) bumping the marker to
     * a future version makes the NEXT open fail (no handle), (3) the file on
     * disk is untouched (still readable, marker unchanged) — this is a
     * refusal, not a quarantine or a rewrite. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "downgrade");

        PS_CHECK("downgrade: seed open", progress_store_open(dir));
        PS_CHECK("downgrade: current-version marker writes",
                 consensus_db_write_schema_marker(progress_store_db(),
                                                  NULL, 0));
        progress_store_close();

        /* Bump the marker to a future version via a separate raw connection
         * (simulating what a newer binary would have left behind). */
        char cpath[512];
        snprintf(cpath, sizeof(cpath), "%s/consensus.db", dir);
        {
            sqlite3 *raw = NULL;
            PS_CHECK("downgrade: raw open for marker bump",
                     sqlite3_open_v2(cpath, &raw, SQLITE_OPEN_READWRITE,
                                     NULL) == SQLITE_OK);
            uint32_t future_v = (uint32_t)CONSENSUS_DB_SCHEMA_VERSION + 1;
            uint8_t le[4] = {
                (uint8_t)(future_v & 0xff), (uint8_t)((future_v >> 8) & 0xff),
                (uint8_t)((future_v >> 16) & 0xff),
                (uint8_t)((future_v >> 24) & 0xff)};
            PS_CHECK("downgrade: future marker writes",
                     raw && progress_meta_set(raw, CONSENSUS_DB_SCHEMA_VERSION_KEY,
                                              le, sizeof(le)));
            if (raw) sqlite3_close(raw);
        }

        /* (2) The next open must REFUSE — no handle, not self-healed. */
        PS_CHECK("downgrade: open refuses (returns false)",
                 !progress_store_open(dir));
        PS_CHECK("downgrade: handle stays NULL after refused open",
                 progress_store_db() == NULL);

        /* (3) Untouched, not quarantined: no .corrupt sidecar, and the
         * future marker is still exactly what we wrote (a refusal, not a
         * silent re-flip/overwrite). */
        PS_CHECK("downgrade: no .corrupt sidecar (refusal, not quarantine)",
                 ps_count_corrupt(dir) == 0);
        {
            sqlite3 *raw = NULL;
            bool opened = sqlite3_open_v2(cpath, &raw, SQLITE_OPEN_READONLY,
                                          NULL) == SQLITE_OK;
            PS_CHECK("downgrade: file still opens read-only", opened);
            uint8_t got[8]; size_t glen = 0; bool found = false;
            uint32_t future_v = (uint32_t)CONSENSUS_DB_SCHEMA_VERSION + 1;
            uint8_t want[4] = {
                (uint8_t)(future_v & 0xff), (uint8_t)((future_v >> 8) & 0xff),
                (uint8_t)((future_v >> 16) & 0xff),
                (uint8_t)((future_v >> 24) & 0xff)};
            PS_CHECK("downgrade: marker on disk still reads as the FUTURE "
                     "version (untouched)",
                     raw && progress_meta_get(raw, CONSENSUS_DB_SCHEMA_VERSION_KEY,
                                              got, sizeof(got), &glen, &found) &&
                     found && glen == sizeof(want) &&
                     memcmp(got, want, sizeof(want)) == 0);
            if (raw) sqlite3_close(raw);
        }

        test_cleanup_tmpdir(dir);
    }

    /* ── projection_store integrity quick_check + quarantine self-heal
     *    (Class C projection corruption robustness) ─────────────────────
     *
     * projection_store's progress.kv projection tables (address_index /
     * txindex / created_outputs) are fully rebuildable, but a corrupt file
     * left in place would otherwise surface as a mid-fold SQLITE_CORRUPT deep
     * inside a projection job with no named blocker. This mirrors the
     * consensus.db quarantine gate proven above — both stores run the SAME
     * shared gate (sqlite_integrity_gate.c). We prove the same three things:
     *   (a) a HEALTHY store reopens with NO quarantine (no false positive),
     *   (b) a deliberately page-garbled store is detected → quarantine file
     *       appears → reopen succeeds with a fresh, queryable, EMPTY store,
     *   (c) it is auto-terminating (one quarantine, not a loop). */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "proj_quarantine");
        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/progress.kv", dir);
        char receipt_path[544];
        snprintf(receipt_path, sizeof(receipt_path), "%s.clean", fpath);

        /* Seed a healthy store with a recognizable marker row, then close so
         * the WAL is checkpointed back into the main file. */
        PS_CHECK("proj quarantine: seed open", projection_store_open(dir));
        {
            sqlite3 *pdb = projection_store_db();
            PS_CHECK("proj quarantine: seed schema",
                     pdb && sqlite3_exec(pdb,
                         "CREATE TABLE IF NOT EXISTS proj_marker"
                         "(k INTEGER PRIMARY KEY, v TEXT NOT NULL)",
                         NULL, NULL, NULL) == SQLITE_OK);
            PS_CHECK("proj quarantine: seed marker row",
                     pdb && sqlite3_exec(pdb,
                         "INSERT INTO proj_marker(k,v) "
                         "VALUES (1,'MARKER-PRE-CORRUPT')",
                         NULL, NULL, NULL) == SQLITE_OK);
        }
        projection_store_close();
        PS_CHECK("proj quarantine: clean close writes fast-open receipt",
                 access(receipt_path, F_OK) == 0);

        /* (a) Reopen the HEALTHY file — must NOT quarantine, marker survives. */
        PS_CHECK("proj quarantine: healthy reopen OK",
                 projection_store_open(dir));
        PS_CHECK("proj quarantine: healthy reopen consumes receipt",
                 access(receipt_path, F_OK) != 0);
        {
            sqlite3_stmt *q = NULL;
            bool row_ok = false;
            if (sqlite3_prepare_v2(projection_store_db(),
                    "SELECT v FROM proj_marker WHERE k=1", -1, &q, NULL) ==
                SQLITE_OK) {
                row_ok = sqlite3_step(q) == SQLITE_ROW &&
                         strcmp((const char *)sqlite3_column_text(q, 0),
                                "MARKER-PRE-CORRUPT") == 0;
            }
            sqlite3_finalize(q);
            PS_CHECK("proj quarantine: healthy marker survives", row_ok);
        }
        PS_CHECK("proj quarantine: no false-positive .corrupt file",
                 ps_count_corrupt_projection(dir) == 0);
        projection_store_close();
        PS_CHECK("proj quarantine: second clean close rewrites receipt",
                 access(receipt_path, F_OK) == 0);

        /* Deliberately corrupt a middle page of the main DB file (same
         * technique as the consensus.db quarantine test above). */
        {
            struct stat st;
            PS_CHECK("proj quarantine: file exists pre-corrupt",
                     stat(fpath, &st) == 0 && st.st_size > 4096);
            FILE *f = fopen(fpath, "r+b");
            PS_CHECK("proj quarantine: open file for corruption", f != NULL);
            if (f) {
                long start = 4096;
                long span = st.st_size - start;
                if (span > 4096) span = 4096;
                if (span < 0) span = 0;
                int seek_ok = (fseek(f, start, SEEK_SET) == 0);
                PS_CHECK("proj quarantine: seek into file body", seek_ok);
                uint8_t garbage[4096];
                memset(garbage, 0xEE, sizeof(garbage));
                size_t to_write = (size_t)span;
                size_t wrote = fwrite(garbage, 1,
                                      to_write < sizeof(garbage)
                                          ? to_write : sizeof(garbage), f);
                PS_CHECK("proj quarantine: wrote garbage page", wrote > 0);
                fclose(f);
            }
        }

        /* (b) Reopen the CORRUPT file — quick_check must fire the quarantine
         *     and reopen a fresh store. open() returns true (self-healed). */
        PS_CHECK("proj quarantine: corrupt reopen self-heals (returns true)",
                 projection_store_open(dir));
        PS_CHECK("proj quarantine: corrupt reopen consumes/refuses receipt",
                 access(receipt_path, F_OK) != 0);
        PS_CHECK("proj quarantine: handle non-NULL after self-heal",
                 projection_store_db() != NULL);
        PS_CHECK("proj quarantine: .corrupt sidecar was created",
                 ps_count_corrupt_projection(dir) >= 1);
        /* Fresh store is queryable — schema-ensure (CREATE TABLE IF NOT
         * EXISTS, exactly what every projection job runs at boot) succeeds
         * on it just like a brand-new node. */
        {
            sqlite3 *pdb = projection_store_db();
            PS_CHECK("proj quarantine: fresh store schema-ensure works",
                     pdb && sqlite3_exec(pdb,
                         "CREATE TABLE IF NOT EXISTS proj_marker"
                         "(k INTEGER PRIMARY KEY, v TEXT NOT NULL)",
                         NULL, NULL, NULL) == SQLITE_OK);
        }
        /* ... and EMPTY: the pre-corrupt marker row is GONE (state was
         * derived, the kernel/anchor is the real source of truth). */
        {
            sqlite3_stmt *q = NULL;
            bool found = false;
            if (sqlite3_prepare_v2(projection_store_db(),
                    "SELECT v FROM proj_marker WHERE k=1", -1, &q, NULL) ==
                SQLITE_OK) {
                found = sqlite3_step(q) == SQLITE_ROW;
            }
            sqlite3_finalize(q);
            PS_CHECK("proj quarantine: fresh store dropped stale marker row",
                     !found);
        }
        projection_store_close();

        /* (c) A second reopen of the now-healthy fresh store does NOT create
         *     a further .corrupt file (auto-terminating; one quarantine). */
        {
            int before = ps_count_corrupt_projection(dir);
            PS_CHECK("proj quarantine: post-heal reopen OK",
                     projection_store_open(dir));
            PS_CHECK("proj quarantine: no second quarantine (idempotent)",
                     ps_count_corrupt_projection(dir) == before);
            projection_store_close();
        }

        test_cleanup_tmpdir(dir);
    }

    /* ── Wave A2 (D4): projection_store split — independent connection +
     *    lock-order concurrency ────────────────────────────────────────────
     * The projection handle is a SECOND sqlite3 connection to the SAME
     * progress.kv file. Two threads writing concurrently — kernel handle under
     * progress_store_tx_lock, projection handle under projection_store_tx_lock —
     * must not deadlock (disjoint mutex domains; WAL single-writer resolved by
     * busy_timeout) and both must commit their own row. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "projsplit");

        PS_CHECK("split: progress_store opens", progress_store_open(dir));
        PS_CHECK("split: projection_store opens", projection_store_open(dir));

        /* Independent connections: same file, distinct sqlite3 handles. */
        sqlite3 *kdb = progress_store_db();
        sqlite3 *pdb = projection_store_db();
        PS_CHECK("split: both handles non-NULL", kdb != NULL && pdb != NULL);
        PS_CHECK("split: projection handle is a DISTINCT connection",
                 kdb != NULL && pdb != NULL && kdb != pdb);

        /* projection_store dumper proves the split observably. */
        {
            struct json_value v; json_init(&v);
            char buf[1024];
            PS_CHECK("split: projection dump works",
                     projection_store_dump_state_json(&v, NULL));
            size_t n = json_write(&v, buf, sizeof(buf));
            PS_CHECK("split: projection dump serializes",
                     n > 0 && n < sizeof(buf));
            PS_CHECK("split: projection dump reports open=true",
                     strstr(buf, "\"open\":true") != NULL);
            PS_CHECK("split: projection dump reports independent_of_kernel=true",
                     strstr(buf, "\"independent_of_kernel\":true") != NULL);
            json_free(&v);
        }

        /* A scratch projection table only the projection handle writes. */
        PS_CHECK("split: projection scratch schema",
                 sqlite3_exec(pdb,
                     "CREATE TABLE IF NOT EXISTS lo_projection_scratch"
                     "(k INTEGER PRIMARY KEY, v INTEGER NOT NULL)",
                     NULL, NULL, NULL) == SQLITE_OK);

        struct lo_thread_arg ka = { false, 40 };
        struct lo_thread_arg pa = { false, 40 };
        pthread_t kt, pt;
        int krc = pthread_create(&kt, NULL, lo_kernel_writer, &ka);
        int prc = pthread_create(&pt, NULL, lo_projection_writer, &pa);
        PS_CHECK("split: both writer threads launch", krc == 0 && prc == 0);
        if (krc == 0) pthread_join(kt, NULL);   /* completes ⇒ no deadlock */
        if (prc == 0) pthread_join(pt, NULL);

        PS_CHECK("split: kernel tx committed (no deadlock)",
                 atomic_load(&ka.committed));
        PS_CHECK("split: projection tx committed (no deadlock)",
                 atomic_load(&pa.committed));

        /* Both rows landed on the shared file, each written through its own
         * connection: the kernel key via progress_meta, the projection row via
         * the scratch table. */
        {
            uint8_t out[8] = {0}; size_t got = 0; bool found = false;
            PS_CHECK("split: kernel row present via progress_meta",
                     progress_meta_get(kdb, "lock_order.kernel", out,
                                       sizeof(out), &got, &found) && found &&
                     got == sizeof(int32_t));
            sqlite3_stmt *q = NULL;
            int rc = sqlite3_prepare_v2(pdb,
                "SELECT v FROM lo_projection_scratch WHERE k=1",
                -1, &q, NULL);
            bool proj_row = rc == SQLITE_OK &&
                            sqlite3_step(q) == SQLITE_ROW &&
                            sqlite3_column_int(q, 0) == 0x2222;
            sqlite3_finalize(q);
            PS_CHECK("split: projection row present via projection handle",
                     proj_row);
        }

        projection_store_close();
        PS_CHECK("split: projection handle NULL after close",
                 projection_store_db() == NULL);
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    /* ── progress.kv stays inside its size bound under churn ─────────
     *
     * A field box carried a 2,874 MB progress.kv while a sibling at the same
     * chain height carried 1 MB. Nothing here compacted, so the file tracked
     * the high-water mark of everything the node had ever indexed and never
     * gave a page back. This case reproduces the mechanism at small scale:
     * fill a projection table, delete almost all of it, and prove the FILE
     * shrinks rather than just the row count. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "progress_store", "compact");
        PS_CHECK("compact: kernel open", progress_store_open(dir));
        PS_CHECK("compact: projection open", projection_store_open(dir));

        sqlite3 *pdb = projection_store_db();
        PS_CHECK("compact: projection handle live", pdb != NULL);

        struct projection_store_usage empty;
        PS_CHECK("compact: a fresh store measures itself",
                 projection_store_usage(&empty) && empty.file_bytes > 0 &&
                 empty.live_bytes >= 0);

        if (pdb) {
            projection_store_tx_lock();
            (void)sqlite3_exec(pdb,
                "CREATE TABLE IF NOT EXISTS compact_churn("
                "k INTEGER PRIMARY KEY, v BLOB)",
                NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
            (void)sqlite3_exec(pdb, "BEGIN", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
            sqlite3_stmt *ins = NULL;
            if (sqlite3_prepare_v2(pdb,
                    "INSERT INTO compact_churn(k, v) VALUES(?, ?)", -1, &ins,
                    NULL) == SQLITE_OK) {
                static uint8_t payload[2048];
                memset(payload, 0x5a, sizeof(payload));
                for (int i = 0; i < 4000; i++) {
                    sqlite3_reset(ins);
                    sqlite3_bind_int(ins, 1, i);
                    sqlite3_bind_blob(ins, 2, payload, sizeof(payload),
                                      SQLITE_STATIC);
                    (void)sqlite3_step(ins);  // raw-sql-ok:test-fixture-seeding
                }
                sqlite3_finalize(ins);
            }
            (void)sqlite3_exec(pdb, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
            projection_store_tx_unlock();
        }

        struct projection_store_usage grown;
        PS_CHECK("compact: the store grew", projection_store_usage(&grown) &&
                 grown.file_bytes > 4 * 1024 * 1024);

        /* Delete nearly everything. In plain SQLite those pages go to the
         * FREELIST inside the file — the file does not shrink by itself,
         * which is precisely the defect. */
        if (pdb) {
            projection_store_tx_lock();
            (void)sqlite3_exec(pdb, "DELETE FROM compact_churn WHERE k >= 40",
                               NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
            projection_store_tx_unlock();
        }

        struct projection_store_usage wasted;
        bool measured_waste = projection_store_usage(&wasted);
        PS_CHECK("compact: deleting rows does NOT shrink the file",
                 measured_waste && wasted.file_bytes >= grown.file_bytes * 9 / 10);
        PS_CHECK("compact: the freed space is visible as free bytes",
                 measured_waste && wasted.free_bytes > wasted.live_bytes);

        /* A bound the store is inside must not trigger a rewrite. */
        PS_CHECK("compact: an in-bound store is left alone",
                 !projection_store_compact_if_needed(1024LL * 1024 * 1024, 250,
                                                     NULL, NULL));

        /* The real bound: 1 MB floor, 250% ratio. The store is now several
         * megabytes of file over a few tens of kilobytes of live data. */
        struct projection_store_usage before, after;
        bool compacted = projection_store_compact_if_needed(
            1024 * 1024, 250, &before, &after);
        PS_CHECK("compact: an over-bound store is compacted", compacted);
        PS_CHECK("compact: the FILE shrank, not just the row count",
                 compacted && after.file_bytes < before.file_bytes);
        PS_CHECK("compact: the file is now within the bound",
                 compacted &&
                 !projection_store_over_bound(&after, 1024 * 1024, 250));
        PS_CHECK("compact: almost no free space is left",
                 compacted && after.free_bytes <= after.file_bytes / 10);

        /* The surviving rows must still be there — a bound that loses data
         * is not a bound. */
        if (pdb) {
            projection_store_tx_lock();
            sqlite3_stmt *q = NULL;
            int64_t rows = -1;
            if (sqlite3_prepare_v2(pdb, "SELECT COUNT(*) FROM compact_churn",
                                   -1, &q, NULL) == SQLITE_OK &&
                sqlite3_step(q) == SQLITE_ROW)  // raw-sql-ok:test-fixture-seeding
                rows = sqlite3_column_int64(q, 0);
            sqlite3_finalize(q);
            projection_store_tx_unlock();
            PS_CHECK("compact: the surviving rows survived", rows == 40);
        }

        /* Running it again is a no-op: the store is already dense, so the
         * bound must not put the node into a rewrite loop. */
        PS_CHECK("compact: a compacted store is not compacted again",
                 !projection_store_compact_if_needed(1024 * 1024, 250, NULL,
                                                     NULL));

        projection_store_close();
        progress_store_close();
        test_cleanup_tmpdir(dir);
    }

    printf("progress_store: %d failures\n", failures);

    return failures;
}
