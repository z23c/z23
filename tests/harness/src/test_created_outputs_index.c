/* Unit tests for the forward creation index (P0 §2.1) — the prevout source
 * that lets script_validate resolve transparent spends without -txindex. */

#include "test/test_core.h"

#include "core/uint256.h"
#include "jobs/created_outputs_index.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "util/reducer_stage_profile.h"
#include "util/stage.h"
#include "json/json.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CO_CHECK(name, expr) do {                                  \
    if (expr) { printf("  created_outputs: %s... OK\n", (name)); }  \
    else { printf("  created_outputs: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Build a tx with `nout` outputs; output i carries a distinct value and a
 * scriptPubKey of length (3+i) filled with byte (0xA0+i). txid is set
 * deterministically from `tag` (we control it; the index keys on tx->hash). */
static void co_make_tx(struct transaction *tx, uint8_t tag, size_t nout)
{
    transaction_init(tx);
    tx->hash.data[0] = tag;
    tx->hash.data[1] = 0xC0;
    tx->hash.data[2] = (uint8_t)nout;
    tx->num_vout = nout;
    tx->vout = zcl_calloc(nout, sizeof(struct tx_out), "co_tx_vout");
    for (size_t i = 0; i < nout; i++) {
        tx->vout[i].value = (int64_t)(1000 + (int)tag * 10 + (int)i);
        unsigned char sb[16];
        size_t sl = 3 + i;
        if (sl > sizeof(sb)) sl = sizeof(sb);
        for (size_t k = 0; k < sl; k++)
            sb[k] = (unsigned char)(0xA0 + i);
        script_set(&tx->vout[i].script_pub_key, sb, sl);
    }
}

static bool co_get(sqlite3 *db, const struct uint256 *txid, uint32_t vout,
                   int64_t *value, unsigned char *sc, size_t cap, size_t *slen)
{
    return created_outputs_index_get(db, txid->data, vout, value, sc, cap, slen);
}

int test_created_outputs_index(void);
int test_created_outputs_index(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "created_outputs", "main");

    CO_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    CO_CHECK("db handle", db != NULL);

    /* get before schema exists -> graceful false (no crash, no throw). */
    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        struct uint256 z; uint256_set_null(&z);
        CO_CHECK("get before schema -> false",
                 !co_get(db, &z, 0, &v, sc, sizeof(sc), &sl));
    }

    CO_CHECK("ensure_schema", created_outputs_index_ensure_schema(db));
    CO_CHECK("ensure_schema idempotent",
             created_outputs_index_ensure_schema(db));

    /* Block at height 100: tx0 (2 vouts), tx1 (1 vout). */
    struct block blk; block_init(&blk);
    blk.num_vtx = 2;
    blk.vtx = zcl_calloc(2, sizeof(struct transaction), "co_blk_vtx");
    co_make_tx(&blk.vtx[0], 0x11, 2);
    co_make_tx(&blk.vtx[1], 0x22, 1);

    CO_CHECK("put_block height=100",
             created_outputs_index_put_block(db, &blk, 100));

    reducer_stage_profile_reset();
    CO_CHECK("batch prepare proof begins", stage_batch_begin(db));
    CO_CHECK("batch prepare proof put first",
             created_outputs_index_put_block(db, &blk, 300));
    CO_CHECK("batch prepare proof put second",
             created_outputs_index_put_block(db, &blk, 301));
    struct json_value profile;
    json_init(&profile);
    CO_CHECK("batch prepare profile dumps",
             reducer_stage_profile_dump_state_json(&profile, NULL));
    const struct json_value *profile_body = json_get(&profile, "body_persist");
    const struct json_value *profile_cumulative = profile_body
        ? json_get(profile_body, "cumulative") : NULL;
    const struct json_value *profile_prepares = profile_cumulative
        ? json_get(profile_cumulative, "created_index_statement_prepares")
        : NULL;
    CO_CHECK("batch reuses exactly one insert prepare",
             profile_prepares && json_get_int(profile_prepares) == 1);
    json_free(&profile);
    CO_CHECK("batch prepare proof commits", stage_batch_end(db, true));
    created_outputs_index_batch_reset();

    /* A future body with the same txid must coexist with, not overwrite, the
     * earlier creator. This is the real out-of-order pipeline regression: body
     * download may be thousands of heights ahead of script validation. */
    struct block duplicate; block_init(&duplicate);
    duplicate.num_vtx = 1;
    duplicate.vtx = zcl_calloc(1, sizeof(struct transaction), "co_dup_vtx");
    co_make_tx(&duplicate.vtx[0], 0x11, 2); /* same txid as blk.vtx[0] */
    duplicate.vtx[0].vout[0].value += 777;
    unsigned char future_script[] = {0x51, 0x51, 0x51, 0x51};
    script_set(&duplicate.vtx[0].vout[0].script_pub_key, future_script,
               sizeof(future_script));
    CO_CHECK("put future duplicate txid height=200",
             created_outputs_index_put_block(db, &duplicate, 200));

    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        int created_h = -1;
        uint64_t prepares_before =
            created_outputs_index_prepare_count_thread();
        CO_CHECK("bounded get includes creator height",
                 created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 90, 100, &v, sc,
                     sizeof(sc), &sl, &created_h) &&
                 created_h == 100 && v == blk.vtx[0].vout[0].value);
        CO_CHECK("bounded get records one actual prepare",
                 created_outputs_index_prepare_count_thread() ==
                     prepares_before + 1);
        CO_CHECK("bounded get ignores future duplicate txid",
                 created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 90, 150, &v, sc,
                     sizeof(sc), &sl, &created_h) &&
                 created_h == 100 && v == blk.vtx[0].vout[0].value &&
                 sl == blk.vtx[0].vout[0].script_pub_key.size &&
                 memcmp(sc, blk.vtx[0].vout[0].script_pub_key.data, sl) == 0);
        CO_CHECK("bounded get selects visible duplicate txid",
                 created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 90, 250, &v, sc,
                     sizeof(sc), &sl, &created_h) &&
                 created_h == 200 && v == duplicate.vtx[0].vout[0].value &&
                 sl == sizeof(future_script) &&
                 memcmp(sc, future_script, sl) == 0);
        CO_CHECK("bounded get rejects below window",
                 !created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 101, 110, &v, sc,
                     sizeof(sc), &sl, &created_h));
        CO_CHECK("bounded get rejects future window",
                 !created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 1, 99, &v, sc,
                     sizeof(sc), &sl, &created_h));
    }

    /* Round-trip every output: value + scriptPubKey exact. */
    for (size_t ti = 0; ti < blk.num_vtx; ti++) {
        struct transaction *tx = &blk.vtx[ti];
        for (uint32_t vo = 0; vo < (uint32_t)tx->num_vout; vo++) {
            int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
            bool got = created_outputs_index_get_bounded(
                db, tx->hash.data, vo, 100, 100, &v, sc, sizeof(sc), &sl,
                NULL);
            bool match = got && v == tx->vout[vo].value
                && sl == tx->vout[vo].script_pub_key.size
                && memcmp(sc, tx->vout[vo].script_pub_key.data, sl) == 0;
            char nm[64];
            snprintf(nm, sizeof(nm), "round-trip tx%zu vout%u", ti, vo);
            CO_CHECK(nm, match);
        }
    }

    /* Absent txid and absent vout both miss. */
    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        struct uint256 absent; uint256_set_null(&absent); absent.data[0] = 0xFE;
        CO_CHECK("absent txid -> false",
                 !co_get(db, &absent, 0, &v, sc, sizeof(sc), &sl));
        CO_CHECK("absent vout -> false",
                 !co_get(db, &blk.vtx[0].hash, 99, &v, sc, sizeof(sc), &sl));
    }

    /* Idempotent re-put (rewind/re-persist simulation). */
    CO_CHECK("re-put idempotent",
             created_outputs_index_put_block(db, &blk, 100));
    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        CO_CHECK("resolves after re-put",
                 created_outputs_index_get_bounded(
                     db, blk.vtx[0].hash.data, 0, 100, 100, &v, sc,
                     sizeof(sc), &sl, NULL)
                 && v == blk.vtx[0].vout[0].value);
    }

    /* Prune below finality/retention: the limited production helper removes
     * only the oldest eligible height per bounded pass; the full helper still
     * removes every eligible old row. */
    struct block low; block_init(&low);
    low.num_vtx = 1;
    low.vtx = zcl_calloc(1, sizeof(struct transaction), "co_low_vtx");
    co_make_tx(&low.vtx[0], 0x33, 1);
    CO_CHECK("put low height=50",
             created_outputs_index_put_block(db, &low, 50));
    struct block low2; block_init(&low2);
    low2.num_vtx = 1;
    low2.vtx = zcl_calloc(1, sizeof(struct transaction), "co_low2_vtx");
    co_make_tx(&low2.vtx[0], 0x44, 1);
    CO_CHECK("put low2 height=60",
             created_outputs_index_put_block(db, &low2, 60));
    int deleted_rows = -1;
    CO_CHECK("limited prune removes one old height",
             created_outputs_index_prune_below_limited(db, 100, 1,
                                                       &deleted_rows) &&
             deleted_rows == 1);
    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        CO_CHECK("limited prune removed oldest height",
                 !co_get(db, &low.vtx[0].hash, 0, &v, sc, sizeof(sc), &sl));
        CO_CHECK("limited prune kept next old height",
                 co_get(db, &low2.vtx[0].hash, 0, &v, sc, sizeof(sc), &sl));
        CO_CHECK("limited prune kept retained height",
                 co_get(db, &blk.vtx[0].hash, 0, &v, sc, sizeof(sc), &sl));
    }
    CO_CHECK("prune_below(100)", created_outputs_index_prune_below(db, 100));
    {
        int64_t v = 0; unsigned char sc[MAX_SCRIPT_SIZE]; size_t sl = 0;
        CO_CHECK("prune removed remaining height<100",
                 !co_get(db, &low2.vtx[0].hash, 0, &v, sc, sizeof(sc), &sl));
        CO_CHECK("prune kept height>=100",
                 co_get(db, &blk.vtx[0].hash, 0, &v, sc, sizeof(sc), &sl));
    }

    for (size_t ti = 0; ti < blk.num_vtx; ti++)
        transaction_free(&blk.vtx[ti]);
    free(blk.vtx);
    transaction_free(&duplicate.vtx[0]);
    free(duplicate.vtx);
    transaction_free(&low.vtx[0]);
    free(low.vtx);
    transaction_free(&low2.vtx[0]);
    free(low2.vtx);

    /* Upgrade proof: an existing two-column-key projection is migrated
     * atomically and keeps its surviving row. The next height-version with the
     * same outpoint then coexists with it. */
    sqlite3 *legacy_db = NULL;
    CO_CHECK("legacy migration db opens",
             sqlite3_open(":memory:", &legacy_db) == SQLITE_OK);
    if (legacy_db) {
        const char *legacy_sql =
            "CREATE TABLE created_outputs("
            "txid BLOB NOT NULL,vout INTEGER NOT NULL,value INTEGER NOT NULL,"
            "script BLOB NOT NULL,height INTEGER NOT NULL,"
            "PRIMARY KEY(txid,vout)) WITHOUT ROWID;"
            "INSERT INTO created_outputs VALUES("
            "x'0100000000000000000000000000000000000000000000000000000000000000',"
            "0,123,x'51',10);";
        CO_CHECK("legacy schema seeded",
                 sqlite3_exec(legacy_db, legacy_sql, NULL, NULL, NULL) ==
                     SQLITE_OK);
        CO_CHECK("legacy schema migrates",
                 created_outputs_index_ensure_schema(legacy_db));
        uint8_t legacy_txid[32] = {1};
        int64_t legacy_value = 0;
        unsigned char legacy_script[MAX_SCRIPT_SIZE];
        size_t legacy_len = 0;
        int legacy_height = -1;
        CO_CHECK("legacy row survives migration",
                 created_outputs_index_get_bounded(
                     legacy_db, legacy_txid, 0, 0, 10, &legacy_value,
                     legacy_script, sizeof(legacy_script), &legacy_len,
                     &legacy_height) &&
                 legacy_value == 123 && legacy_height == 10 &&
                 legacy_len == 1 && legacy_script[0] == 0x51);

        struct block legacy_dup; block_init(&legacy_dup);
        legacy_dup.num_vtx = 1;
        legacy_dup.vtx = zcl_calloc(1, sizeof(struct transaction),
                                    "co_legacy_dup_vtx");
        transaction_init(&legacy_dup.vtx[0]);
        memcpy(legacy_dup.vtx[0].hash.data, legacy_txid, sizeof(legacy_txid));
        legacy_dup.vtx[0].num_vout = 1;
        legacy_dup.vtx[0].vout = zcl_calloc(1, sizeof(struct tx_out),
                                           "co_legacy_dup_vout");
        legacy_dup.vtx[0].vout[0].value = 456;
        unsigned char op_true[] = {0x51, 0x51};
        script_set(&legacy_dup.vtx[0].vout[0].script_pub_key, op_true,
                   sizeof(op_true));
        CO_CHECK("post-migration duplicate version inserts",
                 created_outputs_index_put_block(legacy_db, &legacy_dup, 20));
        CO_CHECK("post-migration old version remains bounded",
                 created_outputs_index_get_bounded(
                     legacy_db, legacy_txid, 0, 0, 15, &legacy_value,
                     legacy_script, sizeof(legacy_script), &legacy_len,
                     &legacy_height) &&
                 legacy_value == 123 && legacy_height == 10);
        transaction_free(&legacy_dup.vtx[0]);
        free(legacy_dup.vtx);
        sqlite3_close(legacy_db);
    }
    progress_store_close();
    test_cleanup_tmpdir(dir);
    return failures;
}
