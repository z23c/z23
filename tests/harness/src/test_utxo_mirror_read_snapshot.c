/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: offline node.db mirror reader fixtures; no canonical inputs. */
#define _DEFAULT_SOURCE
#include "test/test_core.h"
#include "storage/utxo_mirror_read_snapshot.h"
#include "crypto/sha3.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct umrt_fixture {
    char root[512], dir[1024], moved[1024], path[2048], old[2048];
    uint8_t digest[32];
    struct utxo_mirror_read_snapshot *reader;
};
static const char umrt_schema[] =
    "CREATE TABLE node_state(key TEXT PRIMARY KEY,value BLOB);"
    "CREATE TABLE utxos(txid BLOB NOT NULL,vout INTEGER NOT NULL,"
    "value INTEGER NOT NULL CHECK(value>=0 AND value<=2100000000000000),"
    "script BLOB NOT NULL,script_type INTEGER NOT NULL DEFAULT 0,"
    "address_hash BLOB,height INTEGER NOT NULL CHECK(height>=0),"
    "is_coinbase INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(txid,vout));";
static const char umrt_rows[] =
    "INSERT INTO utxos(txid,vout,value,script,height,is_coinbase) VALUES"
    "(zeroblob(32),1,2,X'',0,0),"
    "(X'0000000000000000000000000000000000000000000000000000000000000001',"
    "0,3,X'51AC',1,1);";
static bool umrt_digest(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    unsigned char bytes[4096];
    size_t n;
    while ((n = fread(bytes, 1, sizeof(bytes), f)) != 0)
        sha3_256_write(&hash, bytes, n);
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    if (ok) sha3_256_finalize(&hash, out);
    return ok;
}
static bool umrt_cleanup(struct umrt_fixture *f)
{
    bool ok = !f->reader || utxo_mirror_read_snapshot_abort(&f->reader);
    /* No test creates foreign statements; retained cleanup ownership is a
     * failure, never permission to unlink an object still used by SQLite. */
    if (f->reader) return false;
    if (f->path[0]) { TEST_DISCARD(unlink(f->path)); }
    if (f->old[0]) { TEST_DISCARD(unlink(f->old)); }
    if (f->dir[0]) { TEST_DISCARD(rmdir(f->dir)); }
    if (f->moved[0]) { TEST_DISCARD(rmdir(f->moved)); }
    if (f->root[0]) { TEST_DISCARD(rmdir(f->root)); }
    return ok;
}
static bool umrt_write_cursor(sqlite3 *db, uint64_t cursor,
    enum utxo_mirror_byte_order order, bool ok, int *finalized)
{
    uint8_t blob[8];
    for (unsigned i = 0; i < 8; i++) {
        unsigned at = order == UTXO_MIRROR_LITTLE_ENDIAN ? i : 7u - i;
        blob[at] = (uint8_t)(cursor >> (8u * i));
    }
    sqlite3_stmt *st = NULL;
    if (ok) ok = sqlite3_prepare_v2(db,
        "INSERT INTO node_state VALUES('utxos_mirror_height',?)", -1, &st, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_blob(st, 1, blob, 8, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_DONE;
    *finalized = sqlite3_finalize(st);
    return ok;
}

static bool umrt_make(struct umrt_fixture *f, uint64_t cursor,
                      enum utxo_mirror_byte_order order,
                      const char *rows, const char *change)
{
    if (!test_mkdtemp(f->root, sizeof(f->root), "utxo_mirror_reader")) return false;
    snprintf(f->dir, sizeof(f->dir), "%s/input", f->root);
    snprintf(f->moved, sizeof(f->moved), "%s/retained", f->root);
    snprintf(f->path, sizeof(f->path), "%s/input/node.db", f->root);
    snprintf(f->old, sizeof(f->old), "%s/retained/node.db", f->root);
    if (mkdir(f->dir, 0700) != 0) return false;
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(f->path, &db) == SQLITE_OK;
    if (ok) ok = sqlite3_exec(db, umrt_schema, NULL, NULL, NULL) == SQLITE_OK;
    int finalized = SQLITE_OK;
    ok = umrt_write_cursor(db, cursor, order, ok, &finalized);
    if (ok && rows) ok = sqlite3_exec(db, rows, NULL, NULL, NULL) == SQLITE_OK;
    if (ok && change) ok = sqlite3_exec(db, change, NULL, NULL, NULL) == SQLITE_OK;
    int closed = sqlite3_close(db);
    return ok && finalized == SQLITE_OK && closed == SQLITE_OK &&
        chmod(f->path, 0444) == 0 && umrt_digest(f->path, f->digest);
}
static bool umrt_open(struct umrt_fixture *f, enum utxo_mirror_byte_order order,
                      int32_t expected)
{
    int32_t height = -99;
    return utxo_mirror_read_snapshot_open(f->path, order, f->digest,
        &f->reader, &height) && height == expected;
}
static bool umrt_zero(const struct utxo_mirror_read_result *r)
{
    struct utxo_mirror_read_result zero = {0};
    return r->next_height == zero.next_height && r->count == 0 &&
        memcmp(r->root, zero.root, 32) == 0 && memcmp(r->file_sha3, zero.file_sha3, 32) == 0 &&
        r->input.schema_profile == 0 && !r->input.sidecars_all_absent &&
        memcmp(r->input.file_sha3, zero.input.file_sha3, 32) == 0 &&
        platform_positioned_file_snapshot_equal(&r->input.file, &zero.input.file);
}
static bool umrt_admitted_input(const struct umrt_fixture *f,
                                 struct utxo_mirror_read_attestation *admitted)
{
    struct platform_positioned_file independent;
    struct platform_positioned_file_snapshot stamp;
    platform_positioned_file_init(&independent);
    bool ok = utxo_mirror_read_snapshot_attestation(f->reader, admitted) &&
        admitted->schema_profile == UTXO_MIRROR_SCHEMA_V1 && admitted->sidecars_all_absent &&
        memcmp(admitted->file_sha3, f->digest, 32) == 0 &&
        platform_positioned_file_open(&independent, f->path) &&
        platform_positioned_file_snapshot(&independent, &stamp) &&
        platform_positioned_file_snapshot_equal(&admitted->file, &stamp);
    platform_positioned_file_close(&independent);
    return ok;
}

static bool umrt_first_record(struct utxo_mirror_read_snapshot *reader)
{
    struct coins_kv_read_snapshot_row row;
    return utxo_mirror_read_snapshot_next(reader, &row) == COINS_KV_READ_SNAPSHOT_ROW &&
        row.vout == 1 && row.value == 2 && row.script_len == 0 && row.height == 0 && !row.is_coinbase;
}
static bool umrt_second_record(struct utxo_mirror_read_snapshot *reader)
{
    struct coins_kv_read_snapshot_row row;
    return utxo_mirror_read_snapshot_next(reader, &row) == COINS_KV_READ_SNAPSHOT_ROW &&
        row.txid[31] == 1 && row.vout == 0 && row.value == 3 && row.script_len == 2 &&
        row.script[0] == 0x51 && row.script[1] == 0xac && row.height == 1 && row.is_coinbase;
}
static bool umrt_finished_result(const struct umrt_fixture *f,
    const struct utxo_mirror_read_attestation *admitted,
    const struct utxo_mirror_read_result *result, uint64_t cursor, bool rows)
{
    /* Independent wire vector: two records, fields at explicit byte offsets.
     * No production commitment/serializer routine builds the expected root. */
    static const uint8_t vector[108] = {
        [32]=1, [36]=2, [84]=1, [89]=3, [97]=2,
        [101]=0x51, [102]=0xac, [103]=1, [107]=1
    };
    struct sha3_256_ctx hash;
    uint8_t expected[32];
    sha3_256_init(&hash);
    if (rows) sha3_256_write(&hash, vector, sizeof(vector));
    sha3_256_finalize(&hash, expected);
    return result->next_height == (int32_t)cursor && result->count == (rows ? 2u : 0u) &&
        memcmp(result->root, expected, 32) == 0 && memcmp(result->file_sha3, f->digest, 32) == 0 &&
        result->input.schema_profile == UTXO_MIRROR_SCHEMA_V1 && result->input.sidecars_all_absent &&
        memcmp(result->input.file_sha3, f->digest, 32) == 0 &&
        platform_positioned_file_snapshot_equal(&result->input.file, &admitted->file);
}

static bool umrt_positive(uint64_t cursor, enum utxo_mirror_byte_order order, bool rows)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, cursor, order, rows ? umrt_rows : NULL, NULL) &&
        umrt_open(&f, order, (int32_t)cursor);
    struct utxo_mirror_read_attestation admitted = {0};
    if (ok) ok = umrt_admitted_input(&f, &admitted);
    struct coins_kv_read_snapshot_row row;
    if (ok && rows) ok = umrt_first_record(f.reader) && umrt_second_record(f.reader);
    if (ok) ok = utxo_mirror_read_snapshot_next(f.reader, &row) == COINS_KV_READ_SNAPSHOT_DONE;
    struct utxo_mirror_read_result result;
    if (ok) ok = utxo_mirror_read_snapshot_finish(&f.reader, &result) && f.reader == NULL;
    if (ok) ok = umrt_finished_result(&f, &admitted, &result, cursor, rows);
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
static bool umrt_bad(const char *rows, const char *change, uint64_t cursor, bool admission)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, cursor, UTXO_MIRROR_LITTLE_ENDIAN, rows, change);
    int32_t height = -99;
    bool opened = ok && utxo_mirror_read_snapshot_open(f.path,
        UTXO_MIRROR_LITTLE_ENDIAN, f.digest, &f.reader, &height);
    if (ok && admission) ok = !opened && height == -1;
    if (ok && !admission) {
        struct coins_kv_read_snapshot_row row;
        ok = opened && utxo_mirror_read_snapshot_next(f.reader, &row) == COINS_KV_READ_SNAPSHOT_ERROR;
        struct utxo_mirror_read_result result;
        memset(&result, 0xa5, sizeof(result));
        if (ok) ok = !utxo_mirror_read_snapshot_finish(&f.reader, &result) && umrt_zero(&result);
    }
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
static bool umrt_lifecycle(bool after_done)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, 0, UTXO_MIRROR_LITTLE_ENDIAN, NULL, NULL) &&
        umrt_open(&f, UTXO_MIRROR_LITTLE_ENDIAN, 0);
    struct coins_kv_read_snapshot_row row;
    if (ok && after_done) ok =
        utxo_mirror_read_snapshot_next(f.reader, &row) == COINS_KV_READ_SNAPSHOT_DONE &&
        utxo_mirror_read_snapshot_next(f.reader, &row) == COINS_KV_READ_SNAPSHOT_ERROR;
    struct utxo_mirror_read_result result;
    memset(&result, 0xa5, sizeof(result));
    if (ok) ok = !utxo_mirror_read_snapshot_finish(&f.reader, &result) && umrt_zero(&result);
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
static bool umrt_admission(unsigned mode)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, 2, UTXO_MIRROR_LITTLE_ENDIAN, NULL, NULL);
    char sidecar[sizeof(f.path) + 16] = {0};
    if (ok && mode < 3) {
        const char *suffix[] = {"-wal", "-shm", "-journal"};
        snprintf(sidecar, sizeof(sidecar), "%s%s", f.path, suffix[mode]);
        if (mode == 1) ok = symlink("absent-target", sidecar) == 0;
        else {
            int fd = open(sidecar, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            ok = fd >= 0;
            if (fd >= 0 && close(fd) != 0) ok = false;
        }
    } else if (ok && mode == 3) f.digest[0] ^= 1;
    int32_t height = 7;
    enum utxo_mirror_byte_order order = mode == 4 ? UTXO_MIRROR_BIG_ENDIAN :
        mode == 5 ? (enum utxo_mirror_byte_order)99 : UTXO_MIRROR_LITTLE_ENDIAN;
    if (ok) ok = !utxo_mirror_read_snapshot_open(f.path, order,
        f.digest, &f.reader, &height) && height == -1;
    if (sidecar[0] && unlink(sidecar) != 0) ok = false;
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
/* Mutate only fixture objects: no live datastore is opened or captured. */
static bool umrt_mutate(struct umrt_fixture *f, unsigned mode)
{
    bool ok = true;
    if (mode == 0) { /* parent path replacement */
        ok = rename(f->dir, f->moved) == 0 && mkdir(f->dir, 0700) == 0;
    } else if (mode == 1) { /* replacement FIFO */
        ok = rename(f->dir, f->moved) == 0 && mkdir(f->dir, 0700) == 0 && mkfifo(f->path, 0400) == 0;
    } else { /* mutate retained object; metadata/digest must refuse */
        ok = chmod(f->path, 0644) == 0;
        int fd = ok ? open(f->path, O_WRONLY | O_CLOEXEC) : -1;
        unsigned char byte = 0xff;
        bool wrote = fd >= 0 && pwrite(fd, &byte, 1, 100) == 1;
        bool closed = fd >= 0 && close(fd) == 0;
        ok = ok && wrote && closed;
    }
    return ok;
}
static bool umrt_rejected_attestation(struct utxo_mirror_read_snapshot *reader)
{
    struct utxo_mirror_read_attestation rejected;
    memset(&rejected, 0xa5, sizeof(rejected));
    struct platform_positioned_file_snapshot zero = {0};
    uint8_t digest_zero[32] = {0};
    return !utxo_mirror_read_snapshot_attestation(reader, &rejected) &&
        rejected.schema_profile == 0 && !rejected.sidecars_all_absent &&
        memcmp(rejected.file_sha3, digest_zero, 32) == 0 &&
        platform_positioned_file_snapshot_equal(&rejected.file, &zero);
}
static bool umrt_changed(unsigned mode, bool check_attestation)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, 2, UTXO_MIRROR_LITTLE_ENDIAN, umrt_rows, NULL) &&
        umrt_open(&f, UTXO_MIRROR_LITTLE_ENDIAN, 2);
    if (ok) ok = umrt_mutate(&f, mode);
    struct utxo_mirror_read_result result;
    memset(&result, 0xa5, sizeof(result));
    if (ok && check_attestation) {
        ok = umrt_rejected_attestation(f.reader);
    }
    if (ok) {
        struct coins_kv_read_snapshot_row row;
        enum coins_kv_read_snapshot_step step;
        do { step = utxo_mirror_read_snapshot_next(f.reader, &row); }
        while (step == COINS_KV_READ_SNAPSHOT_ROW);
        ok = !utxo_mirror_read_snapshot_finish(&f.reader, &result) && umrt_zero(&result);
    }
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
static bool umrt_initial_fifo(void)
{
    struct umrt_fixture f = {0};
    bool ok = umrt_make(&f, 0, UTXO_MIRROR_LITTLE_ENDIAN, NULL, NULL) &&
        unlink(f.path) == 0 && mkfifo(f.path, 0400) == 0;
    int32_t height = 7;
    if (ok) ok = !utxo_mirror_read_snapshot_open(f.path,
        UTXO_MIRROR_LITTLE_ENDIAN, f.digest, &f.reader, &height) && height == -1;
    bool closed = umrt_cleanup(&f);
    return ok && closed;
}
/* Existing harness pattern: child alarm makes a blocked open a test failure,
 * never a hung test runner. Parent must observe normal successful exit. */
/* Pure hang guard: the child builds a SQLite fixture before the open under
 * test, so 5 s was tight on a loaded host; nothing asserts on elapsed time. */
#define UMRT_HANG_GUARD_SECONDS 120u
static bool umrt_bounded(bool replacement)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        alarm(UMRT_HANG_GUARD_SECONDS);
        bool ok = replacement ? umrt_changed(1, false) : umrt_initial_fifo();
        _exit(ok ? 0 : 1);
    }
    int status;
    pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    return got == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int umrt_case_positive(void)
{
    int failures = 0;
    TEST_CASE("mirror copy: empty cursor0 and positive frontier, LE/BE rows") {
        ASSERT(umrt_positive(0, UTXO_MIRROR_LITTLE_ENDIAN, false));
        ASSERT(umrt_positive(2, UTXO_MIRROR_BIG_ENDIAN, false));
        ASSERT(umrt_positive(2, UTXO_MIRROR_LITTLE_ENDIAN, true));
        ASSERT(umrt_positive(2, UTXO_MIRROR_BIG_ENDIAN, true));
    } TEST_END;
    return failures;
}

static int umrt_case_cursor_schema(void)
{
    int failures = 0;
    TEST_CASE("mirror copy: malformed cursor and schema refuse admission") {
        ASSERT(umrt_bad(NULL, "UPDATE node_state SET value=X'00'", 2, true));
        ASSERT(umrt_bad(NULL, "UPDATE node_state SET value=2", 2, true));
        ASSERT(umrt_bad(NULL, "DELETE FROM node_state", 2, true));
        ASSERT(umrt_bad(NULL, NULL, UINT64_MAX, true));
        ASSERT(umrt_bad(NULL, "ALTER TABLE utxos ADD COLUMN extra INTEGER", 2, true));
        ASSERT(umrt_bad(NULL, "ALTER TABLE node_state RENAME TO old_state;"
            "CREATE VIEW node_state AS SELECT * FROM old_state", 2, true));
        ASSERT(umrt_bad(NULL, "DROP TABLE node_state; CREATE TABLE node_state(key TEXT,value BLOB);"
            "INSERT INTO node_state VALUES('utxos_mirror_height',X'0200000000000000')", 2, true));
    } TEST_END;
    return failures;
}

static int umrt_case_rows(void)
{
    int failures = 0;
    TEST_CASE("mirror copy: malformed row storage classes and ranges fail closed") {
        const char *base = "INSERT INTO utxos(txid,vout,value,script,height,is_coinbase) VALUES";
        const char *bad[] = {
            "(zeroblob(31),0,1,X'',0,0)", "(zeroblob(32),-1,1,X'',0,0)",
            "(zeroblob(32),4294967296,1,X'',0,0)", "(zeroblob(32),'bad',1,X'',0,0)",
            "(zeroblob(32),0,-1,X'',0,0)", "(zeroblob(32),0,1,'text',0,0)",
            "(zeroblob(32),0,1,X'',2,0)", "(zeroblob(32),0,1,X'',0,2)"
        };
        for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
            char sql[512];
            snprintf(sql, sizeof(sql), "PRAGMA ignore_check_constraints=ON;%s%s;", base, bad[i]);
            ASSERT(umrt_bad(sql, NULL, 2, false));
        }
        ASSERT(umrt_bad(umrt_rows, NULL, 0, false));
    } TEST_END;
    return failures;
}

static int umrt_case_admission_lifecycle(void)
{
    int failures = 0;
    TEST_CASE("mirror copy: sidecars, digest/order and lifecycle refuse") {
        for (unsigned i = 0; i < 6; i++) ASSERT(umrt_admission(i));
        ASSERT(umrt_lifecycle(false));
        ASSERT(umrt_lifecycle(true));
    } TEST_END;
    return failures;
}

static int umrt_case_mutation(void)
{
    int failures = 0;
    TEST_CASE("mirror copy: changed parent, content and FIFO inputs refuse") {

        ASSERT(umrt_changed(0, false));
        ASSERT(umrt_changed(2, false));
        ASSERT(umrt_changed(0, true));
        ASSERT(umrt_changed(2, true));
        ASSERT(umrt_bounded(false));
        ASSERT(umrt_bounded(true));
    } TEST_END;
    return failures;
}

#endif

int test_utxo_mirror_read_snapshot(void)
{
#ifndef _WIN32
    int failures = 0;
    failures += umrt_case_positive();
    failures += umrt_case_cursor_schema();
    failures += umrt_case_rows();
    failures += umrt_case_admission_lifecycle();
    failures += umrt_case_mutation();
    return failures;
#else
    printf("utxo_mirror_read_snapshot: SKIP (Windows): POSIX fixtures unavailable\n");
    return 0;
#endif
}
