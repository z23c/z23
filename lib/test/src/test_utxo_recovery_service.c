/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for utxo_recovery_service — boot-time UTXO wipe, import,
 * restore, and integrity operations.
 */

#include "test/test_core.h"
#include "services/utxo_recovery_service.h"
#include "services/recovery_policy.h"
#include "services/chain_state_service.h"
#include "services/chain_activation_service.h"
#include "storage/utxo_reimport_flag.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "validation/main_state.h"
#include "chain/chainparams.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "storage/coins_view_sqlite.h"
#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define URS_HEX32(byte) \
    #byte #byte #byte #byte #byte #byte #byte #byte \
    #byte #byte #byte #byte #byte #byte #byte #byte \
    #byte #byte #byte #byte #byte #byte #byte #byte \
    #byte #byte #byte #byte #byte #byte #byte #byte

#define URS_CHECK(name, expr) do {              \
    printf("%s... ", (name));                   \
    if ((expr)) printf("OK\n");                 \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* Build a minimal chain in main_state */
static void urs_hash_for_height(int h, struct uint256 *out)
{
    memset(out, 0, sizeof(*out));
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[3] = 0xCC;  /* distinct from CSV tests */
}

static void urs_build_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[256];
    int limit = n < 256 ? n : 256;

    for (int h = 0; h < limit; h++) {
        urs_hash_for_height(h, &hashes[h]);

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(h + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(h + 1));

        if (h > 0) {
            struct block_index *prev = block_map_find(
                &ms->map_block_index, &hashes[h - 1]);
            if (prev) pi->pprev = prev;
        }
    }
    if (limit > 0) {
        struct block_index *tip = block_map_find(
            &ms->map_block_index, &hashes[limit - 1]);
        if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
    }
}

static int64_t urs_count_sql(struct node_db *ndb, const char *sql)
{
    int64_t count = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (AR_STEP_ROW_READONLY(st) == SQLITE_ROW)
            count = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    return count;
}

static bool urs_exec_progress(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("progress SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static bool urs_seed_finalized_floor(int height, const struct uint256 *hash,
                                     const char *status)
{
    sqlite3 *db = progress_store_db();
    if (!db || !hash)
        return false;
    if (!urs_exec_progress(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "tip_hash BLOB)"))
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) "
            "VALUES(?,?,1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status ? status : "finalized", -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

/* ── Invariant A fixtures (12d-12g) ──────────────────────────────────
 * A hash-linked synthetic segment at the compiled trusted-anchor scale —
 * the clamp only descends to the frontier, so chains need not root at
 * genesis. progress.kv is seeded with the REAL production schema
 * (mirrors test_reducer_frontier.c). */

/* Build hash-linked blocks [start .. start+n-1]; tip = the last block. */
static void urs_build_segment(struct main_state *ms, int start, int n)
{
    struct uint256 prev_hash;
    memset(&prev_hash, 0, sizeof(prev_hash));
    for (int i = 0; i < n; i++) {
        int h = start + i;
        struct uint256 hash;
        urs_hash_for_height(h, &hash);
        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hash);
        if (!pi) continue;
        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)i * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nChainTx = (uint32_t)(i + 1);
        arith_uint256_set_u64(&pi->nChainWork, (uint64_t)(i + 1));
        if (i > 0) {
            struct block_index *prev = block_map_find(&ms->map_block_index,
                                                      &prev_hash);
            if (prev) pi->pprev = prev;
        }
        prev_hash = hash;
    }
    struct uint256 tip_hash;
    urs_hash_for_height(start + n - 1, &tip_hash);
    struct block_index *tip = block_map_find(&ms->map_block_index, &tip_hash);
    if (tip) active_chain_move_window_tip(&ms->chain_active, tip);
}

/* Create the progress.kv tables the frontier reader walks, matching the
 * production schema (test_reducer_frontier.c's build_schema subset). */
static bool urs_seed_frontier_schema(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return false;
    return urs_exec_progress(db,
        "CREATE TABLE IF NOT EXISTS stage_cursor ("
        "name TEXT PRIMARY KEY, cursor INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "fail_reason TEXT, validated_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
        "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
        "tip_hash BLOB)");
}

/* Stamp the canonical coins store as proven through applied_height-1.  The
 * reducer uses next-height semantics, so a frontier at H is covered only when
 * applied_height > H. */
static bool urs_stamp_coin_authority(int applied_height)
{
    sqlite3 *db = progress_store_db();
    static const uint8_t dummy_txid[32] = {0x73};
    if (!db || !coins_kv_ensure_schema(db) ||
        !coins_kv_add(db, dummy_txid, 0, 0, 0, false, NULL, 0) ||
        !coins_kv_set_applied_height_in_tx(db, applied_height))
        return false;
    uint8_t one = 1;
    return progress_meta_set(db, "coins_kv_migration_complete", &one,
                             sizeof(one));
}

/* validate_headers_log ok=1 rows [from..to] (hash = the index hash at that
 * height) + the stage cursor at to+1. Coin authority extends one additional
 * height: this models a rolling log whose newest applied row has already been
 * pruned, so recovery exercises the scan-fallback gate instead of short-
 * circuiting through the separately-derived coins-best fast path. */
static bool urs_seed_validated_headers(int from, int to)
{
    sqlite3 *db = progress_store_db();
    if (!db) {
        printf("urs_seed_validated_headers: progress store not open\n");
        return false;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log(height,hash,ok) "
            "VALUES(?,?,1)", -1, &st, NULL) != SQLITE_OK) {
        printf("urs_seed_validated_headers: prepare failed: %s\n",
               sqlite3_errmsg(db));
        return false;
    }
    bool ok = true;
    for (int h = from; h <= to && ok; h++) {
        struct uint256 hash;
        urs_hash_for_height(h, &hash);
        sqlite3_reset(st);
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, hash.data, 32, SQLITE_TRANSIENT);
        ok = sqlite3_step(st) == SQLITE_DONE;
        if (!ok)
            printf("urs_seed_validated_headers: insert h=%d failed: %s\n",
                   h, sqlite3_errmsg(db));
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES('validate_headers',?,0)", -1, &st, NULL) != SQLITE_OK) {
        printf("urs_seed_validated_headers: cursor prepare failed: %s\n",
               sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_int(st, 1, to + 1);
    ok = sqlite3_step(st) == SQLITE_DONE;
    if (!ok)
        printf("urs_seed_validated_headers: cursor write failed: %s\n",
               sqlite3_errmsg(db));
    sqlite3_finalize(st);
    return ok && urs_stamp_coin_authority(to + 2);
}

/* Read (ok,status) of the tip_finalize_log row at `height`. *ok_out = -1
 * when the row is absent. */
static bool urs_tipfin_row(int height, int *ok_out, char *status_out,
                           size_t status_len)
{
    sqlite3 *db = progress_store_db();
    if (!db || !ok_out)
        return false;
    *ok_out = -1;
    if (status_out && status_len)
        status_out[0] = '\0';
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok, status FROM tip_finalize_log WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    if (found) {
        *ok_out = sqlite3_column_int(st, 0);
        const unsigned char *s = sqlite3_column_text(st, 1);
        if (s && status_out && status_len)
            snprintf(status_out, status_len, "%s", (const char *)s);
    }
    sqlite3_finalize(st);
    return found;
}

/* MAX(height) over ok=1 tip_finalize rows, -1 when none, -2 on error. */
static int urs_tipfin_max_ok(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return -2;
    sqlite3_stmt *st = NULL;
    int v = -2;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height),-1) FROM tip_finalize_log "
            "WHERE ok=1", -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
    }
    return v;
}

struct urs_frontier_fixture {
    char db_path[256];
    char progress_dir[256];
    bool pdb_open;
    struct node_db ndb;
    struct main_state ms;
    struct coins_view nv;
    struct coins_view_cache cache;
    struct chain_state_repository *csr;
    struct utxo_recovery_ctx uctx;
};

/* Segment [seg_start .. seg_start+seg_len-1] + empty coins cache + live CSR.
 * Returns false (and self-cleans) if the OS-level pieces fail to open. */
static bool urs_frontier_fixture_setup(struct urs_frontier_fixture *fx,
                                       const char *tag,
                                       int seg_start, int seg_len)
{
    memset(fx, 0, sizeof(*fx));
    snprintf(fx->db_path, sizeof(fx->db_path),
             "./test-tmp/%d_%s.db", getpid(), tag);
    test_make_tmpdir(fx->progress_dir, sizeof(fx->progress_dir),
                     tag, "progress");
    fx->pdb_open = progress_store_open(fx->progress_dir);
    if (!fx->pdb_open) {
        test_cleanup_tmpdir(fx->progress_dir);
        return false;
    }
    if (!node_db_open(&fx->ndb, fx->db_path)) {
        progress_store_close();
        test_cleanup_tmpdir(fx->progress_dir);
        return false;
    }
    chain_params_select(CHAIN_MAIN);
    block_map_init(&fx->ms.map_block_index);
    active_chain_init(&fx->ms.chain_active);
    urs_build_segment(&fx->ms, seg_start, seg_len);
    coins_view_cache_init(&fx->cache, &fx->nv);
    fx->csr = csr_instance();
    csr_init(fx->csr, &fx->ms.map_block_index, &fx->ms.chain_active,
             &fx->ms.pindex_best_header, &fx->cache, &fx->ndb, NULL);
    fx->uctx = (struct utxo_recovery_ctx){
        .state = &fx->ms,
        .coins_sqlite = NULL,
        .coins_tip = &fx->cache,
        .ndb = &fx->ndb,
        .datadir = "/nonexistent",
        .params = chain_params_get(),
        .activation_ctl = NULL,
        .db_service = NULL,
    };
    return true;
}

static void urs_frontier_fixture_teardown(struct urs_frontier_fixture *fx)
{
    if (fx->csr)
        csr_free(fx->csr);
    coins_view_cache_free(&fx->cache);
    active_chain_free(&fx->ms.chain_active);
    block_map_free(&fx->ms.map_block_index);
    if (fx->ndb.open)
        node_db_close(&fx->ndb);
    if (fx->pdb_open)
        progress_store_close();
    test_cleanup_tmpdir(fx->progress_dir);
    unlink(fx->db_path);
}

int test_utxo_recovery_service(void)
{
    printf("\n=== utxo recovery service tests ===\n");
    int failures = 0;

    /* ── 1. Policy-gated wipe: allowed (small UTXO set) ── */

    {
        /* Create temp SQLite DB with a few UTXOs */
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_wipe.db", getpid());
        mkdir("./test-tmp", 0755);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            /* Insert 5 fake UTXOs */
            for (int i = 0; i < 5; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, i + 1);
                node_db_exec(&ndb, sql);
            }

            int64_t before = node_db_utxo_count(&ndb);

            /* A prior import's durable seed anchor — the wipe destroys the
             * coins, so it MUST also clear the anchor that attests to them. */
            uint8_t seed_hash[32];
            memset(seed_hash, 0xCD, sizeof(seed_hash));
            node_db_state_set_int(&ndb, "cold_import_seed_anchor_height",
                                  3100000);
            node_db_state_set(&ndb, "cold_import_seed_anchor_hash",
                              seed_hash, sizeof(seed_hash));
            node_db_state_set_int(&ndb, "cold_import_seed_anchor_utxo_count",
                                  before);

            /* Set env to allow wipe of 10 rows */
            setenv("ZCL_MAX_UTXO_WIPE_ROWS", "10", 1);
            bool ok = utxo_recovery_wipe(&ndb, "test.small_wipe").ok;
            int64_t after = node_db_utxo_count(&ndb);
            unsetenv("ZCL_MAX_UTXO_WIPE_ROWS");

            int64_t seed_h = -1;
            bool have_h = node_db_state_get_int(
                &ndb, "cold_import_seed_anchor_height", &seed_h);
            int64_t seed_c = -1;
            bool have_c = node_db_state_get_int(
                &ndb, "cold_import_seed_anchor_utxo_count", &seed_c);

            URS_CHECK("urs: policy allows small wipe",
                      ok && before == 5 && after == 0);
            URS_CHECK("urs: utxo wipe clears cold-import seed anchor "
                      "(key cannot outlive the coins it attests to)",
                      !have_h && !have_c);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: policy allows small wipe (db open failed)", false);
        }
        unlink(db_path);
    }

    /* ── 2. Policy-gated wipe: refused (too many rows) ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_refuse.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            /* Insert 50 fake UTXOs */
            node_db_begin(&ndb);
            for (int i = 0; i < 50; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, i + 1);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            /* Set env to allow only 10 rows — should refuse 50 */
            setenv("ZCL_MAX_UTXO_WIPE_ROWS", "10", 1);
            bool ok = utxo_recovery_wipe(&ndb, "test.large_wipe").ok;
            int64_t after = node_db_utxo_count(&ndb);
            unsetenv("ZCL_MAX_UTXO_WIPE_ROWS");

            URS_CHECK("urs: policy refuses large wipe",
                      !ok && after == 50);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: policy refuses large wipe (db open failed)", false);
        }
        unlink(db_path);
    }

    /* ── 3. Reimport flag detection ── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_urs_reimport", getpid());
        mkdir(tmpdir, 0755);

        /* Write needs_reimport flag */
        char flag_path[512];
        snprintf(flag_path, sizeof(flag_path), "%s/needs_reimport", tmpdir);
        FILE *f = fopen(flag_path, "w");
        if (f) { fputs("1", f); fclose(f); }

        bool found = utxo_reimport_flag_check_and_clear(tmpdir);
        /* File should be removed after check */
        struct stat st;
        bool file_gone = (stat(flag_path, &st) != 0);

        URS_CHECK("urs: reimport flag detected and removed",
                  found && file_gone);

        rmdir(tmpdir);
    }

    /* ── 4. Reimport flag absent → returns false ── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_urs_no_reimport", getpid());
        mkdir(tmpdir, 0755);

        bool found = utxo_reimport_flag_check_and_clear(tmpdir);
        URS_CHECK("urs: no reimport flag → false", !found);

        rmdir(tmpdir);
    }

    /* ── 5. Prepare reimport: wipe + clear migration flag ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_prep.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            /* Set migration flag */
            uint8_t one = 1;
            node_db_state_set(&ndb, "leveldb_utxo_migrated", &one, 1);

            /* Set the durable cold-import seed anchor (height/hash/count) as a
             * prior accepted import would. prepare_reimport MUST clear all
             * three so a later partial reimport cannot read a stale key and
             * trust-stamp a finalized frontier above the real coin frontier. */
            uint8_t seed_hash[32];
            memset(seed_hash, 0xAB, sizeof(seed_hash));
            node_db_state_set_int(&ndb, "cold_import_seed_anchor_height",
                                  3100000);
            node_db_state_set(&ndb, "cold_import_seed_anchor_hash",
                              seed_hash, sizeof(seed_hash));
            node_db_state_set_int(&ndb, "cold_import_seed_anchor_utxo_count",
                                  1300000);

            /* Insert 3 UTXOs */
            for (int i = 0; i < 3; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, 1, "
                    "100000, X'00')", i, i);
                node_db_exec(&ndb, sql);
            }

            bool ok = utxo_recovery_prepare_reimport(&ndb).ok;

            /* prepare_reimport no longer wipes UTXOs (the wipe happens
             * at the start of import_ldb instead).  It only clears the
             * migration flag so import_ldb will re-run. */
            int64_t utxos = node_db_utxo_count(&ndb);
            uint8_t buf[8];
            size_t len = 0;
            bool flag = node_db_state_get(&ndb, "leveldb_utxo_migrated",
                                           buf, sizeof(buf), &len);

            /* The three durable seed keys must ALL be gone. */
            int64_t seed_h = -1;
            bool have_h = node_db_state_get_int(
                &ndb, "cold_import_seed_anchor_height", &seed_h);
            uint8_t hbuf[32];
            size_t hlen = 0;
            bool have_hash = node_db_state_get(
                &ndb, "cold_import_seed_anchor_hash",
                hbuf, sizeof(hbuf), &hlen);
            int64_t seed_c = -1;
            bool have_c = node_db_state_get_int(
                &ndb, "cold_import_seed_anchor_utxo_count", &seed_c);

            URS_CHECK("urs: prepare reimport: clear flag, keep UTXOs",
                      ok && utxos == 3 && !flag);
            URS_CHECK("urs: prepare reimport clears cold-import seed anchor "
                      "(no stale key strands across a reimport)",
                      !have_h && !have_hash && !have_c);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: prepare reimport (db open failed)", false);
        }
        unlink(db_path);
    }

    /* ── 6. Clean above tip: removes only stragglers ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_above.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 50);  /* tip at h=49 */

        if (node_db_open(&ndb, db_path)) {
            /* Insert UTXOs: 10 below tip, 5 at tip+1 */
            node_db_begin(&ndb);
            for (int i = 0; i < 15; i++) {
                int h = (i < 10) ? (i + 1) : 50;
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, h);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            int64_t before = node_db_utxo_count(&ndb);
            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t after = node_db_utxo_count(&ndb);

            URS_CHECK("urs: clean above tip removes 5 tip+1 stragglers",
                      before == 15 && cleaned == 5 && after == 10);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: clean above tip (db open failed)", false);
        }
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 7. Clean above tip: refuses when >1000 ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_refuse_above.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 10);  /* tip at h=9 */

        if (node_db_open(&ndb, db_path)) {
            /* Insert 1500 UTXOs all above tip (h=10..1509) */
            node_db_begin(&ndb);
            for (int i = 0; i < 1500; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, 10 + i);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            blocker_reset_for_testing();

            int64_t before = node_db_utxo_count(&ndb);
            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t after = node_db_utxo_count(&ndb);

            URS_CHECK("urs: clean above tip refuses >1000",
                      before == 1500 && cleaned == 0 && after == 1500);

            /* Advance-or-named-blocker law: the multi-block overshoot
             * refusal must raise a typed, dumpstate-visible blocker with
             * the guard's own numbers, not just a log line. */
            struct blocker_snapshot snaps[8];
            int n = blocker_snapshot_all(snaps, 8);
            bool found = false;
            bool fields_ok = false;
            for (int k = 0; k < n; k++) {
                if (strcmp(snaps[k].id,
                          UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID) == 0) {
                    found = true;
                    fields_ok =
                        strstr(snaps[k].reason, "tip_height=9") &&
                        strstr(snaps[k].reason, "max_height=1509") &&
                        strstr(snaps[k].reason, "row_count=1500") &&
                        strstr(snaps[k].reason, "guard=32") &&
                        snaps[k].class == BLOCKER_PERMANENT;
                    break;
                }
            }
            URS_CHECK("urs: rewind overshoot refusal raises typed blocker",
                      found);
            URS_CHECK("urs: rewind overshoot blocker carries "
                      "tip/max/row/guard fields", fields_ok);

            /* Later pass finds the condition gone (the offending rows are
             * removed out-of-band, e.g. by an operator) -> the next call
             * must clear the blocker, matching the registry's lifecycle
             * contract. */
            node_db_exec(&ndb, "DELETE FROM utxos WHERE height > 9");
            int cleaned2 = utxo_recovery_clean_above_tip(&ndb, &ms);
            URS_CHECK("urs: rewind overshoot blocker clears once resolved",
                      cleaned2 == 0 &&
                      !blocker_exists(
                          UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID));

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: clean above tip refuses (db open failed)", false);
        }
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 8. Clean above tip: stale coinbase at tip+1 is rewound ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_stale_coinbase.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 50);  /* tip at h=49 */

        if (node_db_open(&ndb, db_path)) {
            node_db_begin(&ndb);
            node_db_exec(&ndb,
                "INSERT INTO utxos(txid, vout, height, value, script, "
                "is_coinbase) VALUES(X'" URS_HEX32(AB) "', 0, 50, "
                "100000, X'51', 1)");
            node_db_exec(&ndb,
                "INSERT OR REPLACE INTO node_state(key,value) "
                "VALUES('utxo_commitment', X'" URS_HEX32(CD) "')");
            node_db_commit(&ndb);

            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t stale = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM utxos WHERE txid=X'" URS_HEX32(AB) "'");
            int64_t commitment = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM node_state WHERE key='utxo_commitment'");

            URS_CHECK("urs: stale coinbase at tip+1 is rewound on boot",
                      cleaned == 1 && stale == 0 && commitment == 0);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: stale coinbase at tip+1 (db open failed)",
                      false);
        }
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 9. Clean above tip: refuses >32 single-block rows ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_refuse_33.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 50);  /* tip at h=49 */

        if (node_db_open(&ndb, db_path)) {
            node_db_begin(&ndb);
            for (int i = 0; i < 33; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, script, "
                    "is_coinbase) VALUES(randomblob(32), %d, 50, "
                    "100000, X'51', 1)", i);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t above = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM utxos WHERE height > 49");

            URS_CHECK("urs: clean above tip refuses >32 rows",
                      cleaned == 0 && above == 33);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: clean above tip refuses >32 (db open failed)",
                      false);
        }
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 9b. Clean above tip: MIRROR-ONLY overshoot >guard self-heals ──
     *
     * Kernel coins_kv is proven-authority AND its own derived coins-best
     * height (applied_height - 1) equals the chain tip exactly — the kernel
     * itself holds nothing above the cursor. The 1500-row overshoot living
     * only in the node.db `utxos` mirror is provably harmless (the mirror
     * carries no consensus weight), so the unguarded purge fires instead of
     * the 32-row guard, and NO blocker is raised. */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_mirror_only.db", getpid());
        char progress_dir[256];
        test_make_tmpdir(progress_dir, sizeof(progress_dir),
                         "urs_mirror_only", "progress");

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 50);  /* tip at h=49 */

        bool pdb_open = progress_store_open(progress_dir);
        if (node_db_open(&ndb, db_path) && pdb_open) {
            sqlite3 *pdb = progress_store_db();

            /* Kernel coins_kv proven-authority at applied_height=50, so the
             * derived coins-best (applied-1) == 49 == tip_h. */
            URS_CHECK("urs mirror-only: coins_kv schema",
                      coins_kv_ensure_schema(pdb));
            uint8_t kv_txid[32];
            memset(kv_txid, 0, sizeof(kv_txid));
            kv_txid[31] = 0x7E;
            URS_CHECK("urs mirror-only: coins_kv seed row",
                      coins_kv_add(pdb, kv_txid, 0, 1000LL, 40, false,
                                  NULL, 0));
            bool applied_ok =
                sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                    SQLITE_OK &&
                coins_kv_set_applied_height_in_tx(pdb, 50);
            sqlite3_exec(pdb, applied_ok ? "COMMIT" : "ROLLBACK",
                        NULL, NULL, NULL);
            URS_CHECK("urs mirror-only: applied_height=50 set", applied_ok);
            uint8_t mig_flag = 1;
            URS_CHECK("urs mirror-only: migration_complete stamped",
                      progress_meta_set(pdb, "coins_kv_migration_complete",
                                        &mig_flag, 1));

            /* node.db `utxos` mirror: 1500 rows above tip (h=50..1549) —
             * far past the 32-row guard, identical shape to test 7. */
            node_db_begin(&ndb);
            for (int i = 0; i < 1500; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, 50 + i);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            blocker_reset_for_testing();

            int64_t before = node_db_utxo_count(&ndb);
            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t after = node_db_utxo_count(&ndb);

            URS_CHECK("urs: mirror-only overshoot >guard self-heals",
                      before == 1500 && cleaned == 1500 && after == 0);
            URS_CHECK("urs: mirror-only self-heal raises no blocker",
                      !blocker_exists(
                          UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID));

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: mirror-only overshoot fixture", false);
            if (ndb.open)
                node_db_close(&ndb);
        }
        if (pdb_open)
            progress_store_close();
        test_cleanup_tmpdir(progress_dir);
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 9c. Clean above tip: KERNEL-store overshoot still refuses ──
     *
     * Kernel coins_kv is proven-authority (same as 9b) but its OWN derived
     * coins-best height (applied_height - 1 = 54) does NOT match the chain
     * tip (49) — the kernel itself disagrees with the tip, which is genuine
     * block_index/coins drift, not a harmless mirror artifact. The
     * mirror-only self-heal must NOT fire; the 32-row guard's refusal (and
     * its typed blocker) must stand exactly as it does with no progress
     * store open at all. */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_kernel_overshoot.db", getpid());
        char progress_dir[256];
        test_make_tmpdir(progress_dir, sizeof(progress_dir),
                         "urs_kernel_overshoot", "progress");

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        urs_build_chain(&ms, 50);  /* tip at h=49 */

        bool pdb_open = progress_store_open(progress_dir);
        if (node_db_open(&ndb, db_path) && pdb_open) {
            sqlite3 *pdb = progress_store_db();

            /* Kernel coins_kv proven-authority, but applied_height=55 =>
             * derived coins-best=54 != tip_h=49 — the kernel itself is
             * AHEAD of the chain tip (kernel-store rows above the cursor). */
            URS_CHECK("urs kernel-overshoot: coins_kv schema",
                      coins_kv_ensure_schema(pdb));
            uint8_t kv_txid[32];
            memset(kv_txid, 0, sizeof(kv_txid));
            kv_txid[31] = 0x7F;
            URS_CHECK("urs kernel-overshoot: coins_kv seed row",
                      coins_kv_add(pdb, kv_txid, 0, 1000LL, 40, false,
                                  NULL, 0));
            bool applied_ok =
                sqlite3_exec(pdb, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                    SQLITE_OK &&
                coins_kv_set_applied_height_in_tx(pdb, 55);
            sqlite3_exec(pdb, applied_ok ? "COMMIT" : "ROLLBACK",
                        NULL, NULL, NULL);
            URS_CHECK("urs kernel-overshoot: applied_height=55 set",
                      applied_ok);
            uint8_t mig_flag = 1;
            URS_CHECK("urs kernel-overshoot: migration_complete stamped",
                      progress_meta_set(pdb, "coins_kv_migration_complete",
                                        &mig_flag, 1));

            /* Same 1500-row node.db mirror overshoot as 9b. */
            node_db_begin(&ndb);
            for (int i = 0; i < 1500; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, "
                    "script) VALUES(X'%032d', %d, %d, "
                    "100000, X'00')", i, i, 50 + i);
                node_db_exec(&ndb, sql);
            }
            node_db_commit(&ndb);

            blocker_reset_for_testing();

            int64_t before = node_db_utxo_count(&ndb);
            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            int64_t after = node_db_utxo_count(&ndb);

            URS_CHECK("urs: kernel-store overshoot still refuses",
                      before == 1500 && cleaned == 0 && after == 1500);

            struct blocker_snapshot snaps[8];
            int n = blocker_snapshot_all(snaps, 8);
            bool found = false;
            for (int k = 0; k < n; k++) {
                if (strcmp(snaps[k].id,
                          UTXO_RECOVERY_REWIND_OVERSHOOT_BLOCKER_ID) == 0) {
                    found = true;
                    break;
                }
            }
            URS_CHECK("urs: kernel-store overshoot raises typed blocker",
                      found);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: kernel-store overshoot fixture", false);
            if (ndb.open)
                node_db_close(&ndb);
        }
        if (pdb_open)
            progress_store_close();
        test_cleanup_tmpdir(progress_dir);
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 10. Reimport flag with "0" value → no reimport ── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_urs_reimport0", getpid());
        mkdir(tmpdir, 0755);

        char flag_path[512];
        snprintf(flag_path, sizeof(flag_path), "%s/needs_reimport", tmpdir);
        FILE *f = fopen(flag_path, "w");
        if (f) { fputs("0", f); fclose(f); }

        bool found = utxo_reimport_flag_check_and_clear(tmpdir);
        URS_CHECK("urs: reimport flag '0' → no reimport", !found);

        /* File should still be removed */
        unlink(flag_path);
        rmdir(tmpdir);
    }

    /* ── 11. LDB import: already migrated → no-op ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_ldb_noop.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            /* Mark as already migrated */
            uint8_t one = 1;
            node_db_state_set(&ndb, "leveldb_utxo_migrated", &one, 1);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            block_map_init(&ms.map_block_index);
            active_chain_init(&ms.chain_active);

            struct coins_view_cache cache;
            struct coins_view nv;
            memset(&nv, 0, sizeof(nv));
            coins_view_cache_init(&cache, &nv);

            struct utxo_recovery_ctx uctx = {
                .state = &ms,
                .coins_sqlite = NULL,
                .coins_tip = &cache,
                .ndb = &ndb,
                .datadir = "/nonexistent",
                .params = NULL,
                .activation_ctl = NULL,
                .db_service = NULL,
            };

            struct utxo_import_result ir = utxo_recovery_import_ldb(&uctx);

            URS_CHECK("urs: LDB import skips when already migrated",
                      ir.status.ok && !ir.imported && !ir.skip_activate);

            coins_view_cache_free(&cache);
            block_map_free(&ms.map_block_index);
            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: LDB import skip (db open failed)", false);
        }
        unlink(db_path);
    }

    /* ── 12. Restore with no UTXOs publishes genesis through CSR ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_restore_genesis.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            chain_params_select(CHAIN_MAIN);
            const struct chain_params *params = chain_params_get();

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            block_map_init(&ms.map_block_index);
            active_chain_init(&ms.chain_active);

            struct block_index *genesis = chainstate_insert_block_index(
                (struct chainstate *)&ms,
                &params->consensus.hashGenesisBlock);
            if (genesis) {
                genesis->nHeight = 0;
                genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
                genesis->nTx = 1;
                genesis->nChainTx = 1;
            }

            struct coins_view_cache cache;
            struct coins_view nv;
            memset(&nv, 0, sizeof(nv));
            coins_view_cache_init(&cache, &nv);

            struct uint256 unknown_best;
            memset(&unknown_best, 0x42, sizeof(unknown_best));
            coins_view_cache_set_best_block(&cache, &unknown_best);

            struct chain_state_repository *csr = csr_instance();
            csr_init(csr, &ms.map_block_index, &ms.chain_active,
                     &ms.pindex_best_header, &cache, &ndb, NULL);

            struct utxo_recovery_ctx uctx = {
                .state = &ms,
                .coins_sqlite = NULL,
                .coins_tip = &cache,
                .ndb = &ndb,
                .datadir = "/nonexistent",
                .params = params,
                .activation_ctl = NULL,
                .db_service = NULL,
            };

            struct chain_restore_result rr =
                utxo_recovery_restore_chain_tip(&uctx, NULL);

            struct uint256 got_best;
            memset(&got_best, 0, sizeof(got_best));
            coins_view_cache_get_best_block(&cache, &got_best);

            uint8_t persisted[32];
            size_t persisted_len = 0;
            bool got_persisted = node_db_state_get(
                &ndb, "coins_best_block", persisted, sizeof(persisted),
                &persisted_len);

            URS_CHECK("urs: no-UTXO restore commits genesis through CSR",
                      rr.status.ok && rr.restored &&
                      active_chain_tip(&ms.chain_active) == genesis &&
                      uint256_eq(&got_best,
                                  &params->consensus.hashGenesisBlock) &&
                      got_persisted && persisted_len == 32 &&
                      memcmp(persisted,
                             params->consensus.hashGenesisBlock.data,
                             32) == 0);

            csr_free(csr);
            coins_view_cache_free(&cache);
            active_chain_free(&ms.chain_active);
            block_map_free(&ms.map_block_index);
            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: no-UTXO restore commits genesis through CSR "
                      "(db open failed)", false);
        }
        unlink(db_path);
    }

    /* ── 12b. scan_fallback cannot roll below finalized reducer floor ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_scan_floor.db", getpid());
        char progress_dir[256];
        test_make_tmpdir(progress_dir, sizeof(progress_dir),
                         "urs_scan_floor", "progress");

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool pdb_open = progress_store_open(progress_dir);
        if (node_db_open(&ndb, db_path) && pdb_open) {
            chain_params_select(CHAIN_MAIN);
            const struct chain_params *params = chain_params_get();

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            block_map_init(&ms.map_block_index);
            active_chain_init(&ms.chain_active);
            urs_build_chain(&ms, 121);  /* active tip h=120 */

            struct uint256 scan_hash;
            urs_hash_for_height(80, &scan_hash);
            struct block_index *scan_fallback =
                block_map_find(&ms.map_block_index, &scan_hash);

            struct coins_view_cache cache;
            struct coins_view nv;
            memset(&nv, 0, sizeof(nv));
            coins_view_cache_init(&cache, &nv);

            struct chain_state_repository *csr = csr_instance();
            csr_init(csr, &ms.map_block_index, &ms.chain_active,
                     &ms.pindex_best_header, &cache, &ndb, NULL);

            struct utxo_recovery_ctx uctx = {
                .state = &ms,
                .coins_sqlite = NULL,
                .coins_tip = &cache,
                .ndb = &ndb,
                .datadir = "/nonexistent",
                .params = params,
                .activation_ctl = NULL,
                .db_service = NULL,
            };

            struct uint256 floor_hash;
            urs_hash_for_height(120, &floor_hash);
            bool seeded = urs_seed_frontier_schema() &&
                          urs_seed_validated_headers(0, 120) &&
                          urs_seed_finalized_floor(120, &floor_hash,
                                                   "anchor");
            struct chain_restore_result rr =
                utxo_recovery_restore_chain_tip(&uctx, scan_fallback);

            struct uint256 got_best;
            coins_view_cache_get_best_block(&cache, &got_best);

            URS_CHECK("urs: scan_fallback refuses finalized-floor rollback",
                      seeded && rr.status.ok && rr.restored &&
                      rr.restored_height == 120 &&
                      uint256_eq(&rr.restored_hash, &floor_hash) &&
                      rr.skip_activate &&
                      active_chain_height(&ms.chain_active) == 120 &&
                      uint256_is_null(&got_best));

            csr_free(csr);
            coins_view_cache_free(&cache);
            active_chain_free(&ms.chain_active);
            block_map_free(&ms.map_block_index);
            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: scan_fallback finalized-floor fixture", false);
            if (ndb.open)
                node_db_close(&ndb);
        }
        if (pdb_open)
            progress_store_close();
        test_cleanup_tmpdir(progress_dir);
        unlink(db_path);
    }

    /* ── 12d. Invariant A: restore candidate above the validated header
     *         frontier is clamped to the hash-linked ancestor (via=pprev) ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_clamp_pprev", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        /* Reproduce header-first boot: the validated header chain is already
         * ahead of the coins/body recovery candidate.  Repair may lower the
         * active body tip to the derivable frontier, but must preserve this
         * independent header frontier. */
        if (scan_fallback)
            fx.ms.pindex_best_header = scan_fallback;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        struct uint256 want_hash;
        urs_hash_for_height(A + 10, &want_hash);
        struct uint256 got_best;
        memset(&got_best, 0, sizeof(got_best));
        if (up)
            coins_view_cache_get_best_block(&fx.cache, &got_best);

        URS_CHECK("urs: invariant A clamps restore candidate to the "
                  "hash-linked frontier ancestor (via=pprev)",
                  up && seeded && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 10 &&
                  uint256_eq(&rr.restored_hash, &want_hash) &&
                  uint256_eq(&got_best, &want_hash) &&
                  active_chain_height(&fx.ms.chain_active) == A + 10 &&
                  fx.ms.pindex_best_header &&
                  fx.ms.pindex_best_header->nHeight == A + 20);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12d2. Same clamp with the pprev chain TORN above the frontier
     *          (the live-wedge shape): the clamp resolves the frontier tip
     *          from validate_headers_log's OWN hash (via=log_hash) ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_clamp_loghash", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);

        /* Sever pprev ABOVE the frontier — candidate 3,143,175 / extent
         * break 3,142,801 / frontier 3,141,533 in the live fixture. */
        struct uint256 cut_hash;
        urs_hash_for_height(A + 13, &cut_hash);
        struct block_index *cut = up
            ? block_map_find(&fx.ms.map_block_index, &cut_hash) : NULL;
        if (cut)
            cut->pprev = NULL;

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && cut && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        struct uint256 want_hash;
        urs_hash_for_height(A + 10, &want_hash);

        URS_CHECK("urs: invariant A clamp survives a torn pprev extent "
                  "via the log's own hash (via=log_hash)",
                  up && seeded && cut && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 10 &&
                  uint256_eq(&rr.restored_hash, &want_hash) &&
                  active_chain_height(&fx.ms.chain_active) == A + 10);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12d3. Same clamp with a cyclic/non-descending pprev extent above
     *          the frontier: boot must not spin; it should fall through to
     *          validate_headers_log's OWN hash (via=log_hash) ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_clamp_cycle", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);

        struct uint256 cut_hash;
        struct uint256 loop_hash;
        urs_hash_for_height(A + 15, &cut_hash);
        urs_hash_for_height(A + 18, &loop_hash);
        struct block_index *cut = up
            ? block_map_find(&fx.ms.map_block_index, &cut_hash) : NULL;
        struct block_index *loop = up
            ? block_map_find(&fx.ms.map_block_index, &loop_hash) : NULL;
        if (cut && loop)
            cut->pprev = loop;

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && cut && loop && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        struct uint256 want_hash;
        urs_hash_for_height(A + 10, &want_hash);

        URS_CHECK("urs: invariant A clamp bounds cyclic pprev descent "
                  "and falls back to the log's own hash",
                  up && seeded && cut && loop && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 10 &&
                  uint256_eq(&rr.restored_hash, &want_hash) &&
                  active_chain_height(&fx.ms.chain_active) == A + 10);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12d4. Wired-but-EMPTY canonical coins store (the pre-fold instant-on
     *         shape: boot-1 prefetched bodies ahead of the validated headers,
     *         zero coins behind them): the scan_fallback commit must roll back
     *         to genesis — a clamped tip with no state is a phantasm that
     *         breaks the bundle-install fresh-genesis gate and fires a doomed
     *         Sapling rebuild. NULL/unwired coins view keeps the legacy anchor
     *         commit (12d1-12d3 above). ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_empty_coins_rb", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);

        /* The fixture segment starts at A — seat genesis so the rollback
         * target resolves, exactly as the production block-index ladder
         * guarantees. */
        bool genesis_ok = false;
        if (up) {
            const struct chain_params *cp = chain_params_get();
            struct block_index *g = chainstate_insert_block_index(
                (struct chainstate *)&fx.ms,
                &cp->consensus.hashGenesisBlock);
            if (g) {
                g->nHeight = 0;
                genesis_ok = true;
            }
        }

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        /* Wire the canonical coins view — genuinely EMPTY utxos. */
        struct coins_view_sqlite cvs;
        bool cvs_open = up && coins_view_sqlite_open(&cvs, fx.ndb.db);
        if (cvs_open)
            fx.uctx.coins_sqlite = &cvs;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && genesis_ok && scan_fallback && cvs_open)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        URS_CHECK("urs: wired empty coins store rolls the scan_fallback "
                  "commit back to genesis (no state behind the tip)",
                  up && seeded && genesis_ok && scan_fallback && cvs_open &&
                  rr.status.ok && !rr.restored &&
                  active_chain_height(&fx.ms.chain_active) == 0);

        if (cvs_open)
            coins_view_sqlite_close(&cvs);
        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12e. Fresh datadir / no frontier evidence: FAIL OPEN (no clamp,
     *         today's behavior preserved bit-for-bit) ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_failopen", A, 21);
        /* Deliberately NO progress tables — no log evidence at all. */

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        URS_CHECK("urs: no frontier evidence fails open (candidate "
                  "committed unclamped)",
                  up && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 20 &&
                  uint256_eq(&rr.restored_hash, &cand_hash) &&
                  active_chain_height(&fx.ms.chain_active) == A + 20);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12f. A finalized floor ABOVE the frontier is provably unbackable:
     *         the clamp commits the frontier and REWINDS the floor rows
     *         (ok=0, status='floor_rewind' — history preserved) ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_floor_rewind", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);
        struct uint256 floor_hash;
        urs_hash_for_height(A + 15, &floor_hash);
        /* The bogus over-frontier anchor stamp from the live wedge. */
        seeded = seeded
              && urs_seed_finalized_floor(A + 15, &floor_hash, "anchor");

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        int row_ok = -1;
        char row_status[32] = "";
        bool row_found = up && urs_tipfin_row(A + 15, &row_ok, row_status,
                                              sizeof(row_status));

        URS_CHECK("urs: unbackable finalized floor is rewound with "
                  "evidence (ok=0 status=floor_rewind)",
                  up && seeded && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 10 &&
                  row_found && row_ok == 0 &&
                  strcmp(row_status, "floor_rewind") == 0 &&
                  urs_tipfin_max_ok() == -1);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12g. scan_fallback floor-guard learns the rewind: an unbackable
     *         floor no longer fabricates restored_height=floor — the guard
     *         rewinds it and the consistent scan_fallback commits ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_guard_rewind", A, 21);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 10);
        struct uint256 floor_hash;
        urs_hash_for_height(A + 15, &floor_hash);
        seeded = seeded
              && urs_seed_finalized_floor(A + 15, &floor_hash, "anchor");

        /* The consistent fallback sits BELOW the bogus floor — yesterday's
         * guard refused it and fabricated restored_height=A+15. */
        struct uint256 cand_hash;
        urs_hash_for_height(A + 5, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        int row_ok = -1;
        char row_status[32] = "";
        bool row_found = up && urs_tipfin_row(A + 15, &row_ok, row_status,
                                              sizeof(row_status));

        URS_CHECK("urs: scan_fallback guard rewinds the unbackable floor "
                  "and commits the consistent fallback",
                  up && seeded && scan_fallback &&
                  rr.status.ok && rr.restored && !rr.skip_activate &&
                  rr.restored_height == A + 5 &&
                  uint256_eq(&rr.restored_hash, &cand_hash) &&
                  row_found && row_ok == 0 &&
                  strcmp(row_status, "floor_rewind") == 0 &&
                  active_chain_height(&fx.ms.chain_active) == A + 5);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12h. The detached-index-island shape: a detached index island
     *         vouched for by fabricated log evidence. The log frontier
     *         sits ABOVE the floor (fabricated anchor rows + cursors), so
     *         the log-only test passes — but the floor rows fail the INDEX
     *         half: the top row's hash resolves at the WRONG height (the
     *         3,143,171→3,143,175 shape) and the rows beneath resolve onto
     *         a detached island rooted above the trust anchor. The guard
     *         must flip ALL of them and commit the trust-rooted
     *         scan_fallback ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_island_floor", A, 21);
        /* Detached island [A+30 .. A+40]: root pprev=NULL ABOVE the
         * anchor — the live fixture's 375-block island rooted at
         * 3,142,801. (Also moves the active tip onto the island, like
         * the wedged datadir.) */
        if (up)
            urs_build_segment(&fx.ms, A + 30, 11);
        /* Fabricated log evidence up to the island top: frontier=A+40. */
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 40);

        /* Floor debris, loudest shape on top: A+38 records the hash of
         * the A+39 island block (height disagreement), A+35/A+33 record
         * correct island hashes (resolvable but not trust-rooted). */
        struct uint256 h39, h35, h33;
        urs_hash_for_height(A + 39, &h39);
        urs_hash_for_height(A + 35, &h35);
        urs_hash_for_height(A + 33, &h33);
        seeded = seeded
              && urs_seed_finalized_floor(A + 33, &h33, "anchor")
              && urs_seed_finalized_floor(A + 35, &h35, "anchor")
              && urs_seed_finalized_floor(A + 38, &h39, "anchor");

        struct uint256 cand_hash;
        urs_hash_for_height(A + 5, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        int ok38 = -1, ok35 = -1, ok33 = -1;
        char st38[32] = "", st35[32] = "", st33[32] = "";
        bool rows_found = up
            && urs_tipfin_row(A + 38, &ok38, st38, sizeof(st38))
            && urs_tipfin_row(A + 35, &ok35, st35, sizeof(st35))
            && urs_tipfin_row(A + 33, &ok33, st33, sizeof(st33));

        URS_CHECK("urs: island-backed floor rows (wrong-height + unrooted) "
                  "are all rewound and the trust-rooted fallback commits",
                  up && seeded && scan_fallback &&
                  rr.status.ok && rr.restored && !rr.skip_activate &&
                  rr.restored_height == A + 5 &&
                  uint256_eq(&rr.restored_hash, &cand_hash) &&
                  rows_found &&
                  ok38 == 0 && strcmp(st38, "floor_rewind") == 0 &&
                  ok35 == 0 && strcmp(st35, "floor_rewind") == 0 &&
                  ok33 == 0 && strcmp(st33, "floor_rewind") == 0 &&
                  urs_tipfin_max_ok() == -1 &&
                  active_chain_height(&fx.ms.chain_active) == A + 5);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12i. A detached-island candidate WITHIN the (fabricated) log
     *         frontier is refused by the INDEX half of the gate: the
     *         height test alone would have installed it ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_island_cand", A, 21);
        if (up)
            urs_build_segment(&fx.ms, A + 30, 11);
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 1, A + 40);

        struct uint256 cand_hash;
        urs_hash_for_height(A + 40, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        URS_CHECK("urs: detached-island candidate within the log frontier "
                  "is refused (not trust-rooted)",
                  up && seeded && scan_fallback &&
                  !rr.status.ok && rr.status.code == -21 && !rr.restored);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12j. Rolling-window abstention: the candidate sits BELOW the
     *         oldest validate_headers_log row (the log is a pruned
     *         window), so the log cannot refute it — the index half
     *         (trust-rooted ancestry) decides alone and the candidate
     *         commits UNCLAMPED. Without this the second copy-prove
     *         clamped the trust-rooted candidate 3,137,373 down to the
     *         compiled anchor 3,056,758 ── */

    {
        const int A = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_log_window", A, 21);
        /* Log rows only at [A+30 .. A+40] — detached from the anchor, so
         * the contiguous prefix (and thus the frontier) collapses to A,
         * while the window floor is A+30. */
        bool seeded = up && urs_seed_frontier_schema()
                   && urs_seed_validated_headers(A + 30, A + 40);

        struct uint256 cand_hash;
        urs_hash_for_height(A + 20, &cand_hash);
        struct block_index *scan_fallback = up
            ? block_map_find(&fx.ms.map_block_index, &cand_hash) : NULL;

        struct chain_restore_result rr;
        memset(&rr, 0, sizeof(rr));
        if (up && seeded && scan_fallback)
            rr = utxo_recovery_restore_chain_tip(&fx.uctx, scan_fallback);

        URS_CHECK("urs: candidate below the log coverage window commits "
                  "unclamped on trust-rooted index ancestry",
                  up && seeded && scan_fallback &&
                  rr.status.ok && rr.restored &&
                  rr.restored_height == A + 20 &&
                  uint256_eq(&rr.restored_hash, &cand_hash) &&
                  active_chain_height(&fx.ms.chain_active) == A + 20);

        if (up)
            urs_frontier_fixture_teardown(&fx);
    }

    /* ── 12c. Recovery entry points return rich status on invalid context ── */

    {
        struct utxo_import_result ir = utxo_recovery_import_ldb(NULL);
        URS_CHECK("urs: import null ctx returns zcl_result error",
                  !ir.status.ok && ir.status.code == -1);

        struct chain_restore_result rr =
            utxo_recovery_restore_chain_tip(NULL, NULL);
        URS_CHECK("urs: restore null ctx returns zcl_result error",
                  !rr.status.ok && rr.status.code == -20 &&
                  rr.restored_height == -1);

        struct boot_validation_result vr;
        memset(&vr, 0, sizeof(vr));
        vr.action = BOOT_OK;
        struct recovery_exec_result er = utxo_recovery_execute(NULL, &vr);
        URS_CHECK("urs: execute null ctx returns zcl_result error",
                  !er.status.ok && er.status.code == -30 &&
                  !er.recovered && !er.skip_activate &&
                  /* A failed execute never authorises the caller to drop the
                   * node.db secondary indexes (see bulk_reload_pending). */
                  !er.bulk_reload_pending);
    }

    /* ── 13. Clean above tip: no-op when tip=0 ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        /* no chain built — tip is NULL */

        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_notip.db", getpid());
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            int cleaned = utxo_recovery_clean_above_tip(&ndb, &ms);
            URS_CHECK("urs: clean above tip no-op when tip=0",
                      cleaned == 0);
            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: clean above tip no-op (db open failed)", false);
        }
        unlink(db_path);
        block_map_free(&ms.map_block_index);
    }

    /* ── 14. Stale coins cursor can advance to sync projection tip ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_stale_cursor.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            node_db_begin(&ndb);
            node_db_exec(&ndb,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "file_num,data_pos,num_tx) VALUES("
                "X'" URS_HEX32(11) "',100,X'" URS_HEX32(00) "',4,"
                "X'" URS_HEX32(22) "',1000,0,X'',X'',X'',13,0,1,1)");
            node_db_exec(&ndb,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "file_num,data_pos,num_tx) VALUES("
                "X'" URS_HEX32(33) "',105,X'" URS_HEX32(11) "',4,"
                "X'" URS_HEX32(44) "',2000,0,X'',X'',X'',13,0,2,1)");
            node_db_exec(&ndb,
                "INSERT INTO utxos(txid,vout,height,value,script,"
                "is_coinbase) VALUES(X'" URS_HEX32(AA) "',0,105,"
                "100000,X'51',1)");
            node_db_exec(&ndb,
                "INSERT INTO utxos(txid,vout,height,value,script,"
                "is_coinbase) VALUES(X'" URS_HEX32(BB) "',0,106,"
                "100000,X'51',1)");
            node_db_exec(&ndb,
                "INSERT INTO transactions(txid,block_hash,block_height,"
                "tx_index,file_num,file_pos,is_coinbase) VALUES("
                "X'" URS_HEX32(BB) "',X'" URS_HEX32(55) "',106,0,0,0,1)");
            node_db_exec(&ndb,
                "INSERT OR REPLACE INTO node_state(key,value) "
                "VALUES('utxo_commitment', X'" URS_HEX32(CC) "')");
            node_db_commit(&ndb);

            uint8_t coins_hash[32];
            memset(coins_hash, 0x11, sizeof(coins_hash));
            uint8_t sync_hash[32];
            memset(sync_hash, 0x33, sizeof(sync_hash));
            node_db_state_set(&ndb, "coins_best_block",
                              coins_hash, sizeof(coins_hash));
            node_db_state_set(&ndb, "sync_projection_tip_hash",
                              sync_hash, sizeof(sync_hash));
            node_db_state_set_int(&ndb, "sync_projection_tip_height", 105);

            bool repaired =
                utxo_recovery_repair_stale_cursor_from_sync_projection(&ndb);

            uint8_t got[32];
            size_t got_len = 0;
            bool got_best = node_db_state_get(&ndb, "coins_best_block",
                                              got, sizeof(got), &got_len);
            int64_t above = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM utxos WHERE height > 105");
            int64_t stale_tx = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM transactions WHERE block_height > 105");
            int64_t commitment = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM node_state WHERE key='utxo_commitment'");

            struct coins_view_sqlite cvs;
            bool opens = coins_view_sqlite_open(&cvs, ndb.db);
            if (opens)
                coins_view_sqlite_close(&cvs);

            URS_CHECK("urs: stale coins cursor repairs from sync projection",
                      repaired && got_best && got_len == 32 &&
                      memcmp(got, sync_hash, sizeof(sync_hash)) == 0 &&
                      above == 0 && stale_tx == 0 && commitment == 0 &&
                      opens);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: stale coins cursor repair (db open failed)",
                      false);
        }
        unlink(db_path);
    }

    /* ── 15. Stale cursor repair tolerates live UTXO height lag ── */

    {
        char db_path[256];
        snprintf(db_path, sizeof(db_path),
                 "./test-tmp/%d_urs_stale_cursor_lag.db", getpid());

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        if (node_db_open(&ndb, db_path)) {
            node_db_begin(&ndb);
            node_db_exec(&ndb,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "file_num,data_pos,num_tx) VALUES("
                "X'" URS_HEX32(21) "',100,X'" URS_HEX32(00) "',4,"
                "X'" URS_HEX32(22) "',1000,0,X'',X'',X'',13,0,1,1)");
            node_db_exec(&ndb,
                "INSERT INTO blocks(hash,height,prev_hash,version,"
                "merkle_root,time,bits,nonce,solution,chain_work,status,"
                "file_num,data_pos,num_tx) VALUES("
                "X'" URS_HEX32(43) "',105,X'" URS_HEX32(21) "',4,"
                "X'" URS_HEX32(44) "',2000,0,X'',X'',X'',13,0,2,1)");
            node_db_exec(&ndb,
                "INSERT INTO utxos(txid,vout,height,value,script,"
                "is_coinbase) VALUES(X'" URS_HEX32(DD) "',0,102,"
                "100000,X'51',1)");
            node_db_exec(&ndb,
                "INSERT OR REPLACE INTO node_state(key,value) "
                "VALUES('utxo_commitment', X'" URS_HEX32(EE) "')");
            node_db_commit(&ndb);

            uint8_t coins_hash[32];
            memset(coins_hash, 0x21, sizeof(coins_hash));
            uint8_t sync_hash[32];
            memset(sync_hash, 0x43, sizeof(sync_hash));
            node_db_state_set(&ndb, "coins_best_block",
                              coins_hash, sizeof(coins_hash));
            node_db_state_set(&ndb, "sync_projection_tip_hash",
                              sync_hash, sizeof(sync_hash));
            node_db_state_set_int(&ndb, "sync_projection_tip_height", 105);

            bool repaired =
                utxo_recovery_repair_stale_cursor_from_sync_projection(&ndb);
            uint8_t got[32];
            size_t got_len = 0;
            bool got_best = node_db_state_get(&ndb, "coins_best_block",
                                              got, sizeof(got), &got_len);
            int64_t commitment = urs_count_sql(&ndb,
                "SELECT COUNT(*) FROM node_state WHERE key='utxo_commitment'");

            struct coins_view_sqlite cvs;
            bool opens = coins_view_sqlite_open(&cvs, ndb.db);
            if (opens)
                coins_view_sqlite_close(&cvs);

            URS_CHECK("urs: stale cursor repair allows UTXO height lag",
                      repaired && got_best && got_len == 32 &&
                      memcmp(got, sync_hash, sizeof(sync_hash)) == 0 &&
                      commitment == 0 && opens);

            node_db_close(&ndb);
        } else {
            URS_CHECK("urs: stale cursor lag repair (db open failed)",
                      false);
        }
        unlink(db_path);
    }

    /* ── Turbo mode follows the BULK RELOAD, not the word "recovered" ──
     *
     * Entering turbo mode DROPS every secondary index on node.db and the
     * matching normal_mode call rebuilds all of them. That trade only pays
     * when a wipe to genesis is followed by a bulk re-populate.
     *
     * utxo_recovery_execute() sets `recovered` on TWO different outcomes:
     * the wipe, and the abort-wipe path where the coin stores turned out
     * to be populated and only a stale cursor was corrected. Gating turbo
     * on `recovered` therefore dropped the indexes on a healthy warm
     * restart and paid a full rebuild seconds later, for nothing. The two
     * outcomes need separate flags, and this pins the one that matters:
     * refusing to wipe must NOT request a bulk reload. */
    {
        struct urs_frontier_fixture fx;
        bool up = urs_frontier_fixture_setup(&fx, "urs_no_turbo", 1, 21);
        if (!up) {
            URS_CHECK("urs: abort-wipe requests no bulk reload (setup failed)",
                      false);
        } else {
            /* Populate the mirror past recover_stale_metadata's 1000-row
             * floor so the wipe is REFUSED — the exact state a warm
             * restart with a stale coins cursor is in. */
            node_db_exec(&fx.ndb, "BEGIN");
            for (int i = 0; i < 1200; i++) {
                char sql[256];
                snprintf(sql, sizeof(sql),
                    "INSERT INTO utxos(txid, vout, height, value, script) "
                    "VALUES(randomblob(32), %d, %d, 100000, X'00')",
                    i, (i % 20) + 1);
                node_db_exec(&fx.ndb, sql);
            }
            node_db_exec(&fx.ndb, "COMMIT");

            struct chain_activation_controller ctl;
            activation_controller_init(&ctl, &fx.ms, NULL,
                                       chain_params_get(), NULL);
            fx.uctx.activation_ctl = &ctl;

            struct boot_validation_result vr;
            memset(&vr, 0, sizeof(vr));
            vr.action = BOOT_RECOVER_WIPE_WAIT;
            vr.chain_height = 20;

            int64_t before = node_db_utxo_count(&fx.ndb);
            struct recovery_exec_result er =
                utxo_recovery_execute(&fx.uctx, &vr);
            int64_t after = node_db_utxo_count(&fx.ndb);

            /* The coins survived, a recovery action was taken, and NO
             * bulk reload was requested — so boot.c leaves the indexes
             * alone. The count assertion is what makes the flag
             * assertion meaningful: it proves this really is the
             * abort-wipe path and not a wipe that happened to be quiet. */
            URS_CHECK("urs: refusing to wipe requests no bulk reload",
                      before == 1200 && after == 1200 &&
                      er.recovered && !er.bulk_reload_pending);

            urs_frontier_fixture_teardown(&fx);
        }
    }

    printf("--- utxo_recovery_service: %d failure(s) ---\n", failures);
    return failures;
}
