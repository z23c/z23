/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: an import that could not take every coins record whole is refused,
 * while a chainstate that exactly fills the importer's limits still imports.
 */

#include "test/test_core.h"

#include "coins/compressor.h"
#include "core/serialize.h"
#include "models/database.h"
#include "services/node_db_import_service.h"
#include "storage/coins_db.h"
#include "storage/dbwrapper.h"
#include "storage/utxo_mirror_schema.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* node_db_import_internal.h:41: rows one chunk of 2048 records can hold. */
#define REJECT_CHUNK_ROWS 32768
/* The largest record the helper below can write: 2 + 8 * 511 outputs. */
#define REJECT_BIG_RECORD 4090
/* The result code of a set refused for missing outputs. */
#define REJECT_CODE_DROPPED (-11)

struct reject_fixture {
    char dir[128];
    char chainstate[160];
    char db_path[160];
};

/* outputs must be 2 + 8k: the first two live, then whole mask bytes. */
static bool reject_write_record(struct db_wrapper *db, uint8_t key_byte,
                                int outputs)
{
    struct byte_stream s;
    char key[33];
    uint8_t hash[20];
    int mask_bytes = (outputs - 2) / 8;
    bool ok;

    stream_init(&s, (size_t)outputs * 24u + 64u);
    memset(hash, 0x51, sizeof(hash));
    ok = stream_write_varint(&s, 1);
    ok &= stream_write_varint(&s, ((uint64_t)mask_bytes * 8u) | 0x07u);
    for (int i = 0; i < mask_bytes; i++)
        ok &= stream_write_u8(&s, 0xff);
    for (int i = 0; i < outputs; i++) {
        ok &= stream_write_varint(&s, compress_amount(1));
        ok &= stream_write_varint(&s, 0);
        ok &= stream_write_bytes(&s, hash, sizeof(hash));
    }
    ok &= stream_write_varint(&s, 7);
    key[0] = 'c';
    memset(key + 1, key_byte, 32);
    ok = ok && !s.error &&
         db_write(db, key, sizeof(key), (const char *)s.data, s.size, true);
    stream_free(&s);
    return ok;
}

static bool reject_fixture_make(struct reject_fixture *f, const int *outputs,
                                size_t count)
{
    struct db_wrapper db;
    bool ok = true;

    snprintf(f->dir, sizeof(f->dir), "./test-tmp/import_reject_%d_XXXXXX",
             (int)getpid());
    (void)mkdir("./test-tmp", 0755);
    if (!mkdtemp(f->dir))
        return false;
    snprintf(f->chainstate, sizeof(f->chainstate), "%s/chainstate", f->dir);
    snprintf(f->db_path, sizeof(f->db_path), "%s/node.db", f->dir);
    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, f->chainstate, 1u << 20, false, true))
        return false;
    for (size_t i = 0; ok && i < count; i++)
        ok = reject_write_record(&db, (uint8_t)(i + 1), outputs[i]);
    db_wrapper_close(&db);
    return ok;
}

struct reject_run {
    struct zcl_result result;
    int64_t rows;
};

static bool reject_run_import(const struct reject_fixture *f,
                              struct reject_run *out)
{
    struct coins_view_db cvdb;
    struct node_db ndb;
    int rows = -1;

    memset(&cvdb, 0, sizeof(cvdb));
    if (!coins_view_db_open(&cvdb, f->chainstate, 1u << 20, false, false))
        return false;
    if (!node_db_open(&ndb, f->db_path)) {
        coins_view_db_close(&cvdb);
        return false;
    }
    out->result = node_db_import_service_run(&ndb, &cvdb, &rows);
    out->rows = node_db_utxo_count(&ndb);
    node_db_close(&ndb);
    coins_view_db_close(&cvdb);
    return true;
}

/* Twelve records whose outputs add up to exactly what one chunk holds. */
static const int k_exact_fit[] = {
    REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
    REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
    2, 2, 2, 42,
};

static int reject_case_exact_fit_imports(void)
{
    int failures = 0;

    TEST("utxo import reject: records that exactly fill a chunk import whole") {
        struct reject_fixture f;
        struct reject_run run;

        ASSERT(reject_fixture_make(&f, k_exact_fit,
                                   sizeof(k_exact_fit) / sizeof(k_exact_fit[0])));
        ASSERT(reject_run_import(&f, &run));
        ASSERT_RESULT_OK(run.result);
        ASSERT(run.rows == REJECT_CHUNK_ROWS);
        PASS();
    } _test_next:;
    return failures;
}

static int reject_case_cut_record_refused(void)
{
    int failures = 0;

    TEST("utxo import reject: a record the chunk could not hold whole refuses") {
        /* The last record needs 50 rows and 48 are left. */
        const int outputs[] = {
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, 50,
        };
        struct reject_fixture f;
        struct reject_run run;

        ASSERT(reject_fixture_make(&f, outputs,
                                   sizeof(outputs) / sizeof(outputs[0])));
        ASSERT(reject_run_import(&f, &run));
        ASSERT(!run.result.ok);
        ASSERT(run.result.code == REJECT_CODE_DROPPED);
        PASS();
    } _test_next:;
    return failures;
}

static int reject_case_skipped_record_refused(void)
{
    int failures = 0;

    TEST("utxo import reject: a record skipped by a full chunk refuses") {
        const int outputs[] = {
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, 2, 2, 2, 42, 2,
        };
        struct reject_fixture f;
        struct reject_run run;

        ASSERT(reject_fixture_make(&f, outputs,
                                   sizeof(outputs) / sizeof(outputs[0])));
        ASSERT(reject_run_import(&f, &run));
        ASSERT(!run.result.ok);
        ASSERT(run.result.code == REJECT_CODE_DROPPED);
        PASS();
    } _test_next:;
    return failures;
}

static int reject_case_dropped_for_memory_refused(void)
{
    int failures = 0;

    TEST("utxo import reject: a record dropped for want of memory refuses") {
        const int outputs[] = { 2, 2, 2 };
        struct reject_fixture f;
        struct reject_run run;

        ASSERT(reject_fixture_make(&f, outputs,
                                   sizeof(outputs) / sizeof(outputs[0])));
        zcl_alloc_fault_fail_nth("import entry value", 2);
        bool ran = reject_run_import(&f, &run);
        zcl_alloc_fault_clear();
        ASSERT(ran);
        ASSERT(!run.result.ok);
        ASSERT(run.result.code == REJECT_CODE_DROPPED);
        PASS();
    } _test_next:;
    return failures;
}

/* What a node trusts about a set. Each must be gone once the set is. */
static bool reject_seed_state(const char *db_path)
{
    static const char *const keys[] = {
        UTXO_MIRROR_SYNC_CURSOR_KEY, "coins_best_block", "utxo_commitment",
        "leveldb_utxo_migrated", "cold_import_seed_anchor_height",
    };
    struct node_db ndb;
    bool ok = node_db_open(&ndb, db_path);

    for (size_t i = 0; ok && i < sizeof(keys) / sizeof(keys[0]); i++)
        ok = node_db_state_set_int(&ndb, keys[i], 5);
    if (ok)
        node_db_close(&ndb);
    return ok;
}

static bool reject_state_is_gone(const char *db_path)
{
    static const char *const keys[] = {
        UTXO_MIRROR_SYNC_CURSOR_KEY, "coins_best_block", "utxo_commitment",
        "leveldb_utxo_migrated", "cold_import_seed_anchor_height",
    };
    struct node_db ndb;
    bool gone = node_db_open(&ndb, db_path);

    for (size_t i = 0; gone && i < sizeof(keys) / sizeof(keys[0]); i++) {
        int64_t value = 0;
        gone = !node_db_state_get_int(&ndb, keys[i], &value);
    }
    if (node_db_utxo_count(&ndb) != 0)
        gone = false;
    node_db_close(&ndb);
    return gone;
}

static int reject_case_refusal_clears_the_set(void)
{
    int failures = 0;

    TEST("utxo import reject: a refused import leaves no rows and no claim about "
         "them, and says the import must be rerun") {
        const int good[] = { 2, 2, 2 };
        const int bad[] = {
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, 50,
        };
        struct reject_fixture old_set;
        struct reject_fixture refused;
        struct reject_run run;

        ASSERT(reject_fixture_make(&old_set, good,
                                   sizeof(good) / sizeof(good[0])));
        ASSERT(reject_run_import(&old_set, &run));
        ASSERT_RESULT_OK(run.result);
        ASSERT(run.rows == 6);
        ASSERT(reject_seed_state(old_set.db_path));

        ASSERT(reject_fixture_make(&refused, bad,
                                   sizeof(bad) / sizeof(bad[0])));
        memcpy(refused.db_path, old_set.db_path, sizeof(refused.db_path));
        ASSERT(reject_run_import(&refused, &run));
        ASSERT(!run.result.ok);
        ASSERT(run.result.code == REJECT_CODE_DROPPED);
        ASSERT(strstr(run.result.message, "run the import again") != NULL);
        ASSERT(run.rows == 0);
        ASSERT(reject_state_is_gone(refused.db_path));
        PASS();
    } _test_next:;
    return failures;
}

int test_utxo_import_reject(void)
{
    int failures = 0;

    failures += reject_case_refusal_clears_the_set();
    failures += reject_case_exact_fit_imports();
    failures += reject_case_cut_record_refused();
    failures += reject_case_skipped_record_refused();
    failures += reject_case_dropped_for_memory_refused();
    return failures;
}
