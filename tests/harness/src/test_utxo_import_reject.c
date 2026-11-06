/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: an import that could not take every coins record whole is refused,
 * while a chainstate that exactly fills the importer's limits still imports.
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "coins/compressor.h"
#include "coins/utxo_commitment.h"
#include "controllers/snapshot_controller.h"
#include "core/serialize.h"
#include "models/database.h"
#include "services/node_db_import_service.h"
#include "services/utxo_import_pipeline.h"
#include "services/utxo_recovery_service.h"
#include "storage/coins_db.h"
#include "storage/coins_view_sqlite.h"
#include "storage/dbwrapper.h"
#include "storage/utxo_mirror_schema.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include "validation/process_block.h"

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
/* At 10 outputs each, more rows than boot's 100000 row mark. */
#define REJECT_BOOT_RECORDS 12288

struct reject_fixture {
    char dir[128];
    char chainstate[160];
    char db_path[160];
};

/* outputs must be 2 + 8k: the first two live, then whole mask bytes. */
static bool reject_write_record(struct db_wrapper *db, uint32_t key_index,
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
    /* Big-endian, so the reader sees the records in the order they were made. */
    memset(key, 0x33, sizeof(key));
    key[0] = 'c';
    key[1] = (char)(key_index >> 24);
    key[2] = (char)(key_index >> 16);
    key[3] = (char)(key_index >> 8);
    key[4] = (char)key_index;
    ok = ok && !s.error &&
         db_write(db, key, sizeof(key), (const char *)s.data, s.size, false);
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
        ok = reject_write_record(&db, (uint32_t)i, outputs[i]);
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

/* Boot only marks a set as imported above 100000 rows, so both fixtures clear
 * that count. The refused one would keep it if its rows were left in place. */
static int k_boot_outputs[REJECT_BOOT_RECORDS];

static void reject_fill_boot_outputs(bool with_cut_record)
{
    for (int i = 0; i < REJECT_BOOT_RECORDS; i++)
        k_boot_outputs[i] = 10;
    for (int i = 0; with_cut_record && i < 9; i++)
        k_boot_outputs[i] = REJECT_BIG_RECORD;
}

struct reject_boot_run {
    struct utxo_import_result res;
    int64_t rows;
    bool marked_migrated;
};

static bool reject_run_boot_import(const struct reject_fixture *f,
                                   struct reject_boot_run *out)
{
    char lock[200];
    struct node_db ndb;
    struct main_state ms;
    struct coins_view_sqlite cvs;
    struct coins_view_cache cache;
    uint8_t mark[8];
    size_t mark_len = 0;

    /* Otherwise boot takes the copy path meant for a running zclassicd. */
    snprintf(lock, sizeof(lock), "%s/LOCK", f->chainstate);
    (void)unlink(lock);
    if (!node_db_open(&ndb, f->db_path))
        return false;
    main_state_init(&ms);
    memset(&cvs, 0, sizeof(cvs));
    if (!coins_view_sqlite_open(&cvs, ndb.db)) {
        main_state_free(&ms);
        node_db_close(&ndb);
        return false;
    }
    coins_view_cache_init(&cache, &cvs.view);

    struct utxo_recovery_ctx uctx = {
        .state = &ms,
        .coins_sqlite = &cvs,
        .coins_tip = &cache,
        .ndb = &ndb,
        .datadir = f->dir,
    };
    out->res = utxo_recovery_import_ldb(&uctx);
    out->rows = node_db_utxo_count(&ndb);
    out->marked_migrated = node_db_state_get(&ndb, "leveldb_utxo_migrated", mark,
                                             sizeof(mark), &mark_len);

    set_coins_sqlite_for_commitment(NULL);
    coins_view_cache_free(&cache);
    coins_view_sqlite_close(&cvs);
    main_state_free(&ms);
    node_db_close(&ndb);
    return true;
}

static int reject_case_boot_honours_refusal(void)
{
    int failures = 0;

    TEST("utxo import reject: boot reports a refused import and marks nothing") {
        struct reject_fixture f;
        struct reject_boot_run run;

        reject_fill_boot_outputs(true);
        ASSERT(reject_fixture_make(&f, k_boot_outputs, REJECT_BOOT_RECORDS));
        ASSERT(reject_run_boot_import(&f, &run));
        ASSERT(!run.res.status.ok);
        ASSERT(strstr(run.res.status.message, "run the import again") != NULL);
        ASSERT(!run.res.imported);
        ASSERT(!run.marked_migrated);
        ASSERT(run.rows == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int reject_case_boot_keeps_a_whole_set(void)
{
    int failures = 0;

    TEST("utxo import reject: boot keeps and marks a whole set of the same size") {
        struct reject_fixture f;
        struct reject_boot_run run;

        reject_fill_boot_outputs(false);
        ASSERT(reject_fixture_make(&f, k_boot_outputs, REJECT_BOOT_RECORDS));
        ASSERT(reject_run_boot_import(&f, &run));
        ASSERT_RESULT_OK(run.res.status);
        ASSERT(run.res.imported);
        ASSERT(run.marked_migrated);
        ASSERT(run.rows == (int64_t)REJECT_BOOT_RECORDS * 10);
        PASS();
    } _test_next:;
    return failures;
}

static int reject_case_snapshot_honours_refusal(void)
{
    int failures = 0;

    TEST("utxo import reject: the snapshot worker fails on a refused import and "
         "succeeds on a whole one") {
        const int good[] = { 2, 2, 2 };
        const int bad[] = {
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, REJECT_BIG_RECORD,
            REJECT_BIG_RECORD, REJECT_BIG_RECORD, 50,
        };
        struct reject_fixture good_set;
        struct reject_fixture bad_set;
        int count = -1;

        ASSERT(reject_fixture_make(&good_set, good,
                                   sizeof(good) / sizeof(good[0])));
        ASSERT(snapshot_import_utxos_for_test(good_set.dir, good_set.db_path,
                                              &count));
        ASSERT(count == 6);

        ASSERT(reject_fixture_make(&bad_set, bad, sizeof(bad) / sizeof(bad[0])));
        ASSERT(!snapshot_import_utxos_for_test(bad_set.dir, bad_set.db_path,
                                               &count));
        PASS();
    } _test_next:;
    return failures;
}

/* The checkpoint a fixture's imported set is compared with: at block 0x77..,
 * holding that set's own root and count, then changed by each case. */
static bool reject_checkpoint_for_set(const char *db_path,
                                      struct sha3_utxo_checkpoint *cp)
{
    struct node_db ndb;

    memset(cp, 0, sizeof(*cp));
    cp->height = 1000;
    memset(cp->block_hash, 0x77, sizeof(cp->block_hash));
    if (!node_db_open(&ndb, db_path))
        return false;
    utxo_commitment_sha3_compute(ndb.db, cp->sha3_hash, &cp->utxo_count);
    node_db_close(&ndb);
    return cp->utxo_count == 6;
}

static struct zcl_result reject_verify_at(const char *db_path,
                                          const struct sha3_utxo_checkpoint *cp,
                                          const struct uint256 *best)
{
    struct node_db ndb;
    struct zcl_result r;

    if (!node_db_open(&ndb, db_path))
        return ZCL_ERR(-100, "test could not open %s", db_path);
    checkpoints_set_sha3_override_for_test(cp);
    r = utxo_import_verify_checkpoint(&ndb, best);
    checkpoints_reset_sha3_override_for_test();
    node_db_close(&ndb);
    return r;
}

static int reject_case_checkpoint_compared_only_at_its_block(void)
{
    int failures = 0;

    TEST("utxo import reject: only a set at the checkpoint block is compared with "
         "it, and a real mismatch there still fails") {
        const int outputs[] = { 2, 2, 2 };
        struct reject_fixture f;
        struct reject_run run;
        struct sha3_utxo_checkpoint cp;
        struct uint256 at_checkpoint;
        struct uint256 elsewhere;

        ASSERT(reject_fixture_make(&f, outputs,
                                   sizeof(outputs) / sizeof(outputs[0])));
        ASSERT(reject_run_import(&f, &run));
        ASSERT_RESULT_OK(run.result);
        ASSERT(reject_checkpoint_for_set(f.db_path, &cp));
        memcpy(at_checkpoint.data, cp.block_hash, sizeof(at_checkpoint.data));
        memset(elsewhere.data, 0x78, sizeof(elsewhere.data));

        /* The right set at the checkpoint block passes. */
        ASSERT_RESULT_OK(reject_verify_at(f.db_path, &cp, &at_checkpoint));

        /* The wrong root fails at the checkpoint block and is not compared at
         * any other. */
        cp.sha3_hash[0] ^= 0x01;
        struct zcl_result wrong_root = reject_verify_at(f.db_path, &cp,
                                                        &at_checkpoint);
        ASSERT(!wrong_root.ok);
        ASSERT(strstr(wrong_root.message, "SHA3 UTXO MISMATCH") != NULL);
        ASSERT_RESULT_OK(reject_verify_at(f.db_path, &cp, &elsewhere));
        cp.sha3_hash[0] ^= 0x01;

        /* So does the wrong count with the right root. */
        cp.utxo_count += 1;
        ASSERT(!reject_verify_at(f.db_path, &cp, &at_checkpoint).ok);
        ASSERT_RESULT_OK(reject_verify_at(f.db_path, &cp, &elsewhere));
        cp.utxo_count -= 1;

        /* No best block: nobody can say it is not the checkpoint block. */
        ASSERT(!reject_verify_at(f.db_path, &cp, NULL).ok);
        PASS();
    } _test_next:;
    return failures;
}

int test_utxo_import_reject(void)
{
    int failures = 0;

    failures += reject_case_checkpoint_compared_only_at_its_block();
    failures += reject_case_boot_honours_refusal();
    failures += reject_case_boot_keeps_a_whole_set();
    failures += reject_case_snapshot_honours_refusal();
    failures += reject_case_refusal_clears_the_set();
    failures += reject_case_exact_fit_imports();
    failures += reject_case_cut_record_refused();
    failures += reject_case_skipped_record_refused();
    failures += reject_case_dropped_for_memory_refused();
    return failures;
}
