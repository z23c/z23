/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for the first production projection adopter. */

#include "test/test_core.h"

#include "controllers/chain_projection.h"
#include "controllers/rpc_client.h"
#include "util/projection.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct projection_load_state {
    const char *db_path;
    atomic_bool writer_done;
    atomic_int reader_count;
    atomic_int reader_failures;
};

static bool exec_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "projection_adoption sql failed rc=%d: %s\n",
                rc, err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static void *projection_writer_thread(void *arg)
{
    struct projection_load_state *st = arg;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(st->db_path, &db,
                        SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        atomic_fetch_add(&st->reader_failures, 1);
        atomic_store(&st->writer_done, true);
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);

    for (int i = 0; i < 1000; i++) {
        if (!exec_sql(db, "UPDATE blocks SET height = height + 1")) {
            atomic_fetch_add(&st->reader_failures, 1);
            break;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };
        nanosleep(&ts, NULL);
    }

    sqlite3_close(db);
    atomic_store(&st->writer_done, true);
    return NULL;
}

static void *projection_reader_thread(void *arg)
{
    struct projection_load_state *st = arg;
    while (!atomic_load(&st->writer_done)) {
        projection_t *p = projection_open(st->db_path);
        if (!p) {
            atomic_fetch_add(&st->reader_failures, 1);
            continue;
        }

        int64_t h = -1;
        if (projection_query_int64(p, "SELECT height FROM blocks", &h) != 0 ||
            h < 100 || h > 1100) {
            atomic_fetch_add(&st->reader_failures, 1);
        } else {
            atomic_fetch_add(&st->reader_count, 1);
        }
        projection_close(p);
    }
    return NULL;
}

static bool create_projection_test_db(const char *path)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_busy_timeout(db, 5000);

    bool ok = exec_sql(db, "PRAGMA journal_mode=WAL") &&
              exec_sql(db, "CREATE TABLE blocks(height INTEGER NOT NULL)") &&
              exec_sql(db, "INSERT INTO blocks(height) VALUES (100)");
    sqlite3_close(db);
    return ok;
}

static int64_t query_height(sqlite3 *db)
{
    sqlite3_stmt *s = NULL;
    int64_t h = -1;
    if (sqlite3_prepare_v2(db, "SELECT height FROM blocks", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) {
        h = sqlite3_column_int64(s, 0);
    }
    sqlite3_finalize(s);
    return h;
}

static void cleanup_db(const char *path)
{
    char wal[320], shm[320];
    snprintf(wal, sizeof(wal), "%s-wal", path);
    snprintf(shm, sizeof(shm), "%s-shm", path);
    unlink(path);
    unlink(wal);
    unlink(shm);
}

int test_projection_adoption(void)
{
    int failures = 0;
    printf("\n=== projection_adoption tests ===\n");

    TEST("projection_query_text_and_double") {
        char tmpl[] = "/tmp/zcl-projection-typed-XXXXXX";
        char *dir = mkdtemp(tmpl);
        if (!dir) { failures++; printf("FAIL (mkdtemp)\n"); goto typed_done; }

        char path[320];
        snprintf(path, sizeof(path), "%s/node.db", dir);
        sqlite3 *db = NULL;
        if (sqlite3_open_v2(path, &db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            NULL) != SQLITE_OK) {
            failures++; printf("FAIL (open)\n"); goto typed_cleanup;
        }
        bool ok = exec_sql(db, "CREATE TABLE facts(name TEXT, ratio REAL)") &&
                  exec_sql(db, "INSERT INTO facts VALUES ('tip', 1.25)");
        sqlite3_close(db);
        if (!ok) { failures++; printf("FAIL (seed)\n"); goto typed_cleanup; }

        projection_t *p = projection_open(path);
        if (!p) { failures++; printf("FAIL (projection_open)\n"); goto typed_cleanup; }
        char name[16];
        double ratio = 0.0;
        ok = projection_query_text(p, "SELECT name FROM facts", name, sizeof(name)) == 0 &&
             strcmp(name, "tip") == 0 &&
             projection_query_double(p, "SELECT ratio FROM facts", &ratio) == 0 &&
             ratio > 1.24 && ratio < 1.26;
        projection_close(p);
        if (!ok) failures++;
        printf("%s\n", ok ? "OK" : "FAIL");

typed_cleanup:
        cleanup_db(path);
        rmdir(dir);
typed_done:
        ;
    }

    TEST("chain_projection_best_heights") {
        char tmpl[] = "/tmp/zcl-chain-projection-XXXXXX";
        char *dir = mkdtemp(tmpl);
        if (!dir) { failures++; printf("FAIL (mkdtemp)\n"); goto chain_done; }

        char path[320];
        snprintf(path, sizeof(path), "%s/node.db", dir);
        sqlite3 *db = NULL;
        if (sqlite3_open_v2(path, &db,
                            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            NULL) != SQLITE_OK) {
            failures++; printf("FAIL (open)\n"); goto chain_cleanup;
        }
        bool ok = exec_sql(db, "CREATE TABLE blocks(height INTEGER NOT NULL, status INTEGER NOT NULL)") &&
                  exec_sql(db, "INSERT INTO blocks(height,status) VALUES (122,3),(123,3),(124,1)");
        sqlite3_close(db);
        if (!ok) { failures++; printf("FAIL (seed)\n"); goto chain_cleanup; }

        node_rpc_client_init(dir, 0);
        int64_t best = chain_projection_best_block_height();
        int64_t hdr = chain_projection_best_header_height();
        ok = (best == 123 && hdr == 124);
        if (!ok) failures++;
        printf("%s\n", ok ? "OK" : "FAIL");

chain_cleanup:
        cleanup_db(path);
        rmdir(dir);
chain_done:
        ;
    }

    TEST("projection_mvcc_under_load") {
        char tmpl[] = "/tmp/zcl-projection-load-XXXXXX";
        char *dir = mkdtemp(tmpl);
        if (!dir) { failures++; printf("FAIL (mkdtemp)\n"); goto load_done; }

        char path[320];
        snprintf(path, sizeof(path), "%s/node.db", dir);
        if (!create_projection_test_db(path)) {
            failures++; printf("FAIL (seed)\n"); goto load_cleanup;
        }

        struct projection_load_state st = { .db_path = path };
        atomic_init(&st.writer_done, false);
        atomic_init(&st.reader_count, 0);
        atomic_init(&st.reader_failures, 0);

        pthread_t writer;
        pthread_t readers[4];
        bool ok = pthread_create(&writer, NULL, projection_writer_thread, &st) == 0;
        for (int i = 0; i < 4; i++)
            ok = ok && pthread_create(&readers[i], NULL,
                                      projection_reader_thread, &st) == 0;
        if (!ok) {
            atomic_store(&st.writer_done, true);
            failures++; printf("FAIL (pthread_create)\n"); goto load_cleanup;
        }

        pthread_join(writer, NULL);
        for (int i = 0; i < 4; i++)
            pthread_join(readers[i], NULL);

        sqlite3 *db = NULL;
        int64_t final_h = -1;
        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
            sqlite3_busy_timeout(db, 5000);
            final_h = query_height(db);
            sqlite3_close(db);
        }

        ok = atomic_load(&st.reader_failures) == 0 &&
             atomic_load(&st.reader_count) >= 100 &&
             final_h == 1100;
        if (!ok) failures++;
        printf("%s\n", ok ? "OK" : "FAIL");

load_cleanup:
        cleanup_db(path);
        rmdir(dir);
load_done:
        ;
    }

    printf("projection_adoption: %d failures\n", failures);
    return failures;
}
