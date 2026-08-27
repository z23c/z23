/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for utxo_mirror_sync — the node.db `utxos` mirror feeder that
 * keeps the explorer read model synced to the authoritative coins_kv set.
 *
 * The load-bearing assertions:
 *   - a frozen mirror (cold-import seed) below the coins_kv applied frontier
 *     is DETECTED as drift and rebuilt to match coins_kv exactly;
 *   - the rebuilt rows carry the DERIVED explorer columns (script_type +
 *     address_hash) computed from each scriptPubKey, so address balances are
 *     correct after the rebuild;
 *   - the durable cursor (node.db state key) advances to the frontier and is
 *     read back on the next pass so a no-drift mirror does NO work;
 *   - a spent coin (absent from coins_kv) is removed from the mirror;
 *   - the feeder NEVER touches coins_kv (consensus authority untouched).
 */

#include "test/test_core.h"
#include "json/json.h"

#include "chain/chain.h"
#include "coins/utxo_commitment.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "models/database.h"
#include "models/utxo.h"
#include "script/standard.h"
#include "services/chain_state_service.h"
#include "services/utxo_mirror_delta.h"
#include "services/utxo_mirror_sync_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define UMS_CHECK(name, expr) do {                                          \
    if (expr) { printf("  utxo_mirror_sync: %s... OK\n", (name)); }          \
    else { printf("  utxo_mirror_sync: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* A 25-byte P2PKH script with a recognisable 20-byte hash derived from tag. */
static void ums_p2pkh(uint8_t script[25], uint8_t hash20[20], uint8_t tag)
{
    memset(hash20, 0, 20);
    hash20[0] = tag; hash20[19] = 0xA5;
    script[0] = 0x76; /* OP_DUP */
    script[1] = 0xa9; /* OP_HASH160 */
    script[2] = 0x14; /* push 20 */
    memcpy(script + 3, hash20, 20);
    script[23] = 0x88; /* OP_EQUALVERIFY */
    script[24] = 0xac; /* OP_CHECKSIG */
}

static void ums_txid(uint8_t out[32], uint8_t tag)
{
    memset(out, 0, 32);
    out[0] = tag; out[31] = 0x9c;
}

/* Set the coins_kv applied frontier inside its own txn (a writer's job; the
 * feeder only reads it). */
static bool ums_set_frontier(sqlite3 *db, int32_t h)
{
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, h)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    if (!ok) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    return ok;
}

/* Seed one frozen row directly into the node.db mirror (the cold-import seed
 * the feeder must bring forward). */
static bool ums_seed_mirror_row(struct node_db *ndb, uint8_t tag, int32_t h)
{
    uint8_t txid[32]; ums_txid(txid, tag);
    uint8_t script[25], hash20[20]; ums_p2pkh(script, hash20, tag);
    struct db_utxo u; memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid, 32);
    u.vout = 0; u.value = 1000; u.height = h; u.is_coinbase = true;
    u.script = script; u.script_len = sizeof(script);
    u.script_type = utxo_classify_script(u.script, u.script_len,
                                         u.address_hash, &u.has_address);
    return db_utxo_save(ndb, &u);
}

/* Add one coin to the authoritative coins_kv set. */
static bool ums_add_coin(sqlite3 *pdb, uint8_t tag, int64_t value, int32_t h)
{
    uint8_t txid[32]; ums_txid(txid, tag);
    uint8_t script[25], hash20[20]; ums_p2pkh(script, hash20, tag);
    return coins_kv_add(pdb, txid, 0, value, h, true, script, sizeof(script));
}

/* ── Delta-path fixtures ────────────────────────────────────────────
 * The incremental (delta) mirror path reads utxo_apply_delta.spent_blob to
 * learn which coins left the set at each height. These helpers write that
 * table directly (in progress.kv) in the exact serialize_spent() wire layout
 * so the delta apply exercises the real read/parse path. */

static void ums_le32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void ums_le64(uint8_t *p, int64_t v)
{
    uint64_t u=(uint64_t)v;
    for (int i=0;i<8;i++) p[i]=(uint8_t)(u>>(8*i));
}

/* Ensure the delta table exists, then INSERT one height row whose spent_blob
 * holds a SINGLE spent coin (tag) with its full pre-image. added_blob empty. */
static bool ums_write_delta_row(sqlite3 *pdb, int32_t height, uint8_t spent_tag,
                                int64_t spent_value, int32_t spent_height)
{
    if (sqlite3_exec(pdb,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;

    uint8_t txid[32]; ums_txid(txid, spent_tag);
    uint8_t script[25], hash20[20]; ums_p2pkh(script, hash20, spent_tag);

    uint8_t blob[32+4+8+4+1+4+25];
    uint8_t *p = blob;
    memcpy(p, txid, 32); p += 32;
    ums_le32(p, 0);              p += 4;   /* vout */
    ums_le64(p, spent_value);    p += 8;   /* value */
    ums_le32(p, (uint32_t)spent_height); p += 4; /* creation height */
    *p++ = 1;                              /* is_coinbase */
    ums_le32(p, sizeof(script)); p += 4;   /* script_len */
    memcpy(p, script, sizeof(script)); p += sizeof(script);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(pdb,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            " (height,branch_hash,spent_blob,added_blob) VALUES (?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    uint8_t zero32[32] = {0};
    sqlite3_bind_int64(s, 1, height);
    sqlite3_bind_blob(s, 2, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, blob, (int)(p - blob), SQLITE_STATIC);
    sqlite3_bind_blob(s, 4, "", 0, SQLITE_STATIC);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool ums_write_empty_delta_row(sqlite3 *pdb, int32_t height)
{
    if (sqlite3_exec(pdb,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(pdb,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            " (height,branch_hash,spent_blob,added_blob) VALUES (?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK)
        return false;
    uint8_t zero32[32] = {0};
    sqlite3_bind_int64(s, 1, height);
    sqlite3_bind_blob(s, 2, zero32, 32, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, "", 0, SQLITE_STATIC);
    sqlite3_bind_blob(s, 4, "", 0, SQLITE_STATIC);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool ums_add_height_coin(sqlite3 *pdb, int32_t height)
{
    uint8_t txid[32] = {0};
    ums_le32(txid, (uint32_t)height);
    txid[31] = 0x5a;
    uint8_t script[25], hash20[20];
    ums_p2pkh(script, hash20, (uint8_t)height);
    return coins_kv_add(pdb, txid, 0, 1000 + height, height, false,
                        script, sizeof(script));
}

/* Read the `addresses` aggregate cache balance for a hash; -1 if no row. */
static int64_t ums_addr_cache_balance(struct node_db *ndb, const uint8_t h[20])
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT balance FROM addresses WHERE address_hash=?",
            -1, &s, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(s, 1, h, 20, SQLITE_STATIC);
    int64_t bal = (sqlite3_step(s) == SQLITE_ROW) ? sqlite3_column_int64(s, 0) : -1;
    sqlite3_finalize(s);
    return bal;
}

int test_utxo_mirror_sync(void);
int test_utxo_mirror_sync(void)
{
    printf("\n=== utxo_mirror_sync tests ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "utxo_mirror_sync", "main");

    char ndb_path[600];
    snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", dir);

    struct node_db ndb;
    bool db_ok = node_db_open(&ndb, ndb_path);
    UMS_CHECK("node.db opens", db_ok);
    if (!db_ok) { test_cleanup_tmpdir(dir); return failures; }

    UMS_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *pdb = progress_store_db();
    UMS_CHECK("coins_kv schema", coins_kv_ensure_schema(pdb));

    /* Empty scriptPubKeys are consensus-valid. A NULL C pointer with length
     * zero must persist as a zero-length BLOB, never SQL NULL (which violates
     * the mirror schema and used to wedge every wholesale rebuild after a
     * `generate` coin entered coins_kv). Exercise both model write paths. */
    {
        struct db_utxo empty;
        memset(&empty, 0, sizeof(empty));
        ums_txid(empty.txid, 0xEE);
        empty.value = 1;
        empty.height = 1;
        empty.is_coinbase = true;
        empty.script_type = SCRIPT_OTHER;
        UMS_CHECK("empty script lifecycle save persists",
                  db_utxo_save(&ndb, &empty));
        sqlite3_stmt *q = NULL;
        bool blob_ok = sqlite3_prepare_v2(ndb.db,
            "SELECT typeof(script),length(script) FROM utxos "
            "WHERE txid=? AND vout=0", -1, &q, NULL) == SQLITE_OK;
        if (blob_ok) {
            sqlite3_bind_blob(q, 1, empty.txid, 32, SQLITE_STATIC);
            blob_ok = sqlite3_step(q) == SQLITE_ROW &&
                strcmp((const char *)sqlite3_column_text(q, 0), "blob") == 0 &&
                sqlite3_column_int(q, 1) == 0;
        }
        sqlite3_finalize(q);
        UMS_CHECK("empty script lifecycle value is zero-length BLOB", blob_ok);
        UMS_CHECK("remove empty lifecycle fixture",
                  db_utxo_delete(&ndb, empty.txid, 0));

        empty.vout = 1;
        UMS_CHECK("empty script bulk insert persists",
                  db_utxo_insert_raw(&ndb, &empty));
        q = NULL;
        blob_ok = sqlite3_prepare_v2(ndb.db,
            "SELECT typeof(script),length(script) FROM utxos "
            "WHERE txid=? AND vout=1", -1, &q, NULL) == SQLITE_OK;
        if (blob_ok) {
            sqlite3_bind_blob(q, 1, empty.txid, 32, SQLITE_STATIC);
            blob_ok = sqlite3_step(q) == SQLITE_ROW &&
                strcmp((const char *)sqlite3_column_text(q, 0), "blob") == 0 &&
                sqlite3_column_int(q, 1) == 0;
        }
        sqlite3_finalize(q);
        UMS_CHECK("empty script bulk value is zero-length BLOB", blob_ok);
        UMS_CHECK("remove empty bulk fixture",
                  db_utxo_delete(&ndb, empty.txid, 1));
    }

    /* ── Fixture: a FROZEN mirror (2 rows at h=100) while coins_kv holds the
     * live set (4 coins through h=104) — the exact cold-import-freeze shape. */
    UMS_CHECK("seed frozen mirror tag=0x11", ums_seed_mirror_row(&ndb, 0x11, 100));
    UMS_CHECK("seed frozen mirror tag=0x22", ums_seed_mirror_row(&ndb, 0x22, 100));
    UMS_CHECK("mirror count == 2 (frozen)", db_utxo_count(&ndb) == 2);

    /* coins_kv: the same two coins PLUS two created after the freeze. */
    UMS_CHECK("coin 0x11", ums_add_coin(pdb, 0x11, 1000, 100));
    UMS_CHECK("coin 0x22", ums_add_coin(pdb, 0x22, 1000, 100));
    UMS_CHECK("coin 0x33 (post-freeze)", ums_add_coin(pdb, 0x33, 2222, 103));
    UMS_CHECK("coin 0x44 (post-freeze)", ums_add_coin(pdb, 0x44, 3333, 104));
    UMS_CHECK("coins_kv count == 4", coins_kv_count(pdb) == 4);
    UMS_CHECK("set frontier 105", ums_set_frontier(pdb, 105));

    /* ── The feeder. */
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    struct utxo_mirror_sync_service svc;
    memset(&runtime, 0, sizeof(runtime));
    db_service_init(&dbsvc);
    UMS_CHECK("db service attaches", db_service_attach(&dbsvc, &ndb));
    UMS_CHECK("db service starts", db_service_start(&dbsvc));
    runtime.db_service = &dbsvc;
    app_runtime_set_current(&runtime);
    utxo_mirror_sync_init(&svc, &ndb);

    /* NULL/closed-db guard. */
    UMS_CHECK("run_once(NULL) -> -1", utxo_mirror_sync_run_once(NULL) == -1);

    UMS_CHECK("open sync batch before mirror pass", db_service_begin_write(&dbsvc));
    ndb.sync_in_batch = true;

    /* Pass 1: drift detected, mirror rebuilt to match coins_kv (4 rows). */
    int64_t written = utxo_mirror_sync_run_once(&svc);
    UMS_CHECK("pass1 wrote 4 rows", written == 4);
    UMS_CHECK("mirror pass flushed open sync batch",
              !ndb.sync_in_batch && !ndb.tx_open);
    UMS_CHECK("mirror count == 4 after rebuild", db_utxo_count(&ndb) == 4);
    UMS_CHECK("mirror max height == 104", db_utxo_max_height(&ndb) == 104);

    /* The post-freeze coin's address balance is now present (the whole point —
     * a frozen mirror would report 0 for tag=0x44). */
    {
        uint8_t script[25], hash20[20]; ums_p2pkh(script, hash20, 0x44);
        int64_t bal = db_utxo_balance_for_address(&ndb, hash20);
        UMS_CHECK("post-freeze address balance == 3333", bal == 3333);
        UMS_CHECK("post-freeze script_type == P2PKH",
                  utxo_classify_script(script, sizeof(script), hash20, &(bool){0})
                  == SCRIPT_P2PKH);
    }

    /* Durable cursor advanced to the frontier. */
    {
        int64_t cur = -1;
        bool got = node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
        UMS_CHECK("cursor persisted", got);
        UMS_CHECK("cursor == frontier (105)", cur == 105);
    }

    /* Pass 2: no drift (cursor == frontier, counts equal) → no work. */
    int64_t written2 = utxo_mirror_sync_run_once(&svc);
    UMS_CHECK("pass2 no-op (0 rows)", written2 == 0);
    UMS_CHECK("mirror count still 4", db_utxo_count(&ndb) == 4);

    /* dump_state_json (`z23 dumpstate utxo_mirror_sync`) reads the
     * boot-owned global instance pointer — temporarily point it at this
     * test's local `svc` (already carries pass1's counters) to prove the
     * dumper surfaces them, then restore NULL so later groups see "not
     * started" as before. */
    {
        g_utxo_mirror_sync = &svc;
        struct json_value v = {0};
        json_set_object(&v);
        bool ok = utxo_mirror_sync_dump_state_json(&v, NULL);
        const struct json_value *present = json_get(&v, "instance_present");
        const struct json_value *rebuilds = json_get(&v, "rebuilds_run");
        const struct json_value *rows = json_get(&v, "rows_written");
        bool shape_ok = ok && present && json_get_bool(present) == true &&
                        rebuilds && json_get_int(rebuilds) >= 1 &&
                        rows && json_get_int(rows) >= 4;
        json_free(&v);
        g_utxo_mirror_sync = NULL;
        UMS_CHECK("dump_state_json reports instance + rebuilds_run + rows_written",
                  shape_ok);
    }

    /* ── Spend one coin in coins_kv + advance the frontier. The next pass must
     * REMOVE it from the mirror (count back to 3) — proves spends propagate. */
    {
        uint8_t txid[32]; ums_txid(txid, 0x33);
        UMS_CHECK("spend coin 0x33", coins_kv_spend(pdb, txid, 0));
        UMS_CHECK("coins_kv count == 3", coins_kv_count(pdb) == 3);
        UMS_CHECK("write utxo_apply_delta[105] (spends 0x33)",
                  ums_write_delta_row(pdb, 105, 0x33, 2222, 103));
        UMS_CHECK("advance frontier 106", ums_set_frontier(pdb, 106));
    }
    int64_t written3 = utxo_mirror_sync_run_once(&svc);
    UMS_CHECK("pass3 changed only the spent row", written3 == 1);
    UMS_CHECK("mirror count == 3 after spend", db_utxo_count(&ndb) == 3);
    UMS_CHECK("spent coin gone from mirror",
              !db_utxo_exists(&ndb,
                  (const uint8_t[32]){[0]=0x33,[31]=0x9c}, 0));

    /* The feeder never wrote coins_kv: the authority count is unchanged by the
     * mirror passes (consensus path untouched). */
    UMS_CHECK("coins_kv count untouched by feeder (== 3)",
              coins_kv_count(pdb) == 3);

    /* ── DELTA PATH ────────────────────────────────────────────────────
     * State now: mirror {0x11@100, 0x22@100, 0x44@104}, cursor==106,
     * coins_kv {0x11,0x22,0x44}, frontier==106. A new block at h=106 CREATES
     * 0x55 and SPENDS 0x44. With a utxo_apply_delta row present for h=107 the
     * mirror pass must take the INCREMENTAL path: upsert only 0x55, delete only
     * 0x44, and re-derive only the touched addresses — NOT wipe+rebuild all
     * rows. The discriminator: the delta returns rows_CHANGED (2 = 1 add + 1
     * delete), whereas a wholesale rebuild would return the full row count (3). */
    {
        uint8_t txid44[32]; ums_txid(txid44, 0x44);
        UMS_CHECK("delta: add coin 0x55@106", ums_add_coin(pdb, 0x55, 5555, 106));
        UMS_CHECK("delta: spend coin 0x44", coins_kv_spend(pdb, txid44, 0));
        UMS_CHECK("delta: coins_kv count == 3", coins_kv_count(pdb) == 3);
        UMS_CHECK("delta: write utxo_apply_delta[106] (spends 0x44)",
                  ums_write_delta_row(pdb, 106, 0x44, 3333, 104));
        UMS_CHECK("delta: advance frontier 107", ums_set_frontier(pdb, 107));

        int64_t w = utxo_mirror_sync_run_once(&svc);
        UMS_CHECK("delta: rows_changed == 2 (incremental, not a full rebuild)",
                  w == 2);
        UMS_CHECK("delta: mirror count == 3", db_utxo_count(&ndb) == 3);
        UMS_CHECK("delta: mirror max height == 106", db_utxo_max_height(&ndb) == 106);
        UMS_CHECK("delta: spent 0x44 gone from mirror",
                  !db_utxo_exists(&ndb, txid44, 0));
        UMS_CHECK("delta: new 0x55 present in mirror",
                  db_utxo_exists(&ndb,
                      (const uint8_t[32]){[0]=0x55,[31]=0x9c}, 0));

        uint8_t s55[25], h55[20]; ums_p2pkh(s55, h55, 0x55);
        uint8_t s44[25], h44[20]; ums_p2pkh(s44, h44, 0x44);
        UMS_CHECK("delta: 0x55 utxo balance == 5555",
                  db_utxo_balance_for_address(&ndb, h55) == 5555);
        /* addresses AGGREGATE cache was maintained incrementally, not left
         * stale: 0x55 appears with its balance, 0x44 row is gone. */
        UMS_CHECK("delta: addresses cache 0x55 == 5555",
                  ums_addr_cache_balance(&ndb, h55) == 5555);
        UMS_CHECK("delta: addresses cache 0x44 removed",
                  ums_addr_cache_balance(&ndb, h44) == -1);
        /* An untouched address (0x11) is unchanged. */
        uint8_t s11[25], h11[20]; ums_p2pkh(s11, h11, 0x11);
        UMS_CHECK("delta: untouched 0x11 cache == 1000",
                  ums_addr_cache_balance(&ndb, h11) == 1000);

        int64_t cur = -1;
        node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
        UMS_CHECK("delta: cursor advanced to 107", cur == 107);

        /* Next pass: no drift → no work (proves the delta cursor is durable). */
        UMS_CHECK("delta: pass after is a no-op",
                  utxo_mirror_sync_run_once(&svc) == 0);
        UMS_CHECK("delta: coins_kv still untouched (== 3)",
                  coins_kv_count(pdb) == 3);
    }

    /* ── DELTA QUARANTINE ──────────────────────────────────────────────
     * A missing causal row cannot silently drop a spend and cannot trigger a
     * repeated million-row rebuild. The derived mirror freezes until the
     * missing record is supplied, then resumes incrementally. */
    {
        uint8_t txid55[32]; ums_txid(txid55, 0x55);
        UMS_CHECK("quarantine: spend 0x55", coins_kv_spend(pdb, txid55, 0));
        UMS_CHECK("quarantine: coins_kv count == 2", coins_kv_count(pdb) == 2);
        /* Deliberately DO NOT write utxo_apply_delta[107]. */
        UMS_CHECK("quarantine: advance frontier 108", ums_set_frontier(pdb, 108));
        int64_t rebuilds_before = atomic_load(&svc.rebuilds_run);
        int64_t w = utxo_mirror_sync_run_once(&svc);
        UMS_CHECK("quarantine: first missing delta fails closed", w == -1);
        UMS_CHECK("quarantine: state is QUARANTINED",
                  atomic_load(&svc.mirror_health) == UTXO_MIRROR_QUARANTINED);
        UMS_CHECK("quarantine: mirror remains at prior complete frontier",
                  db_utxo_count(&ndb) == 3 && db_utxo_exists(&ndb, txid55, 0));
        UMS_CHECK("quarantine: repeated tick is bounded no-op",
                  utxo_mirror_sync_run_once(&svc) == 0);
        UMS_CHECK("quarantine: zero wholesale rebuilds triggered",
                  atomic_load(&svc.rebuilds_run) == rebuilds_before);

        UMS_CHECK("quarantine: supply missing delta[107]",
                  ums_write_delta_row(pdb, 107, 0x55, 5555, 106));
        atomic_store(&svc.mirror_health, UTXO_MIRROR_HEALTHY);
        UMS_CHECK("quarantine: recovered pass changes one row",
                  utxo_mirror_sync_run_once(&svc) == 1);
        UMS_CHECK("quarantine: spent 0x55 gone after causal recovery",
                  !db_utxo_exists(&ndb, txid55, 0));
        UMS_CHECK("quarantine: recovery stayed incremental",
                  atomic_load(&svc.rebuilds_run) == rebuilds_before);
    }

    /* ── XOR CHECKPOINT — height-tracked live maintenance ────────────────
     * The lane's actual root-cause fix: utxo_mirror_delta_apply and the
     * wholesale rebuild above now stamp UTXO_COMMITMENT_HEIGHT_KEY at the
     * SAME commit boundary that mutates the mirror, so the checkpoint
     * tracks the live mirror instead of going stale between boots. Prove
     * it against ground truth (utxo_commitment_compute_db over the actual
     * `utxos` table) at every step, including the two failure classes a
     * naive incremental XOR would get wrong: a coin created-and-spent
     * inside the SAME still-open delta window, and a retried pass (mirror
     * cursor persist failed after a prior commitment update landed). */
    {
        /* The recovered delta maintained the checkpoint at the same commit
         * boundary as rows, caches, and cursor. */
        struct utxo_commitment ground_truth;
        utxo_commitment_compute_db(ndb.db, &ground_truth);
        struct utxo_commitment computed;
        bool refreshed = true;
        UMS_CHECK("xor: boot_check fast path after wholesale rebuild",
                  utxo_commitment_boot_check_and_refresh(ndb.db, 108,
                      &computed, &refreshed) && !refreshed &&
                  utxo_commitment_equal(&computed, &ground_truth));

        /* ── Created-and-spent within the SAME delta window: 0x66 created
         * AND spent at h=108. It must never touch the mirror table (already
         * proven elsewhere) and must NOT be folded into the checkpoint
         * either — folding an add that was never counted (or a remove for
         * it) would corrupt the XOR accumulator. */
        UMS_CHECK("xor: add+spend-in-window coin 0x66@108",
                  ums_add_coin(pdb, 0x66, 9999, 108));
        {
            uint8_t txid66[32]; ums_txid(txid66, 0x66);
            UMS_CHECK("xor: spend 0x66 same block", coins_kv_spend(pdb, txid66, 0));
        }
        UMS_CHECK("xor: write utxo_apply_delta[108] (spends 0x66@108)",
                  ums_write_delta_row(pdb, 108, 0x66, 9999, 108));
        UMS_CHECK("xor: advance frontier 109", ums_set_frontier(pdb, 109));
        int64_t w109 = utxo_mirror_sync_run_once(&svc);
        /* rows_changed counts the spent_blob entry PROCESSED (a harmless
         * no-op DELETE — 0x66 was never live in the mirror), not net table
         * mutations: 0 adds (0x66 wasn't live at the ADD-select's read time)
         * + 1 delete-attempt = 1. */
        UMS_CHECK("xor: h109 pass processes only the no-op delete (1 row)",
                  w109 == 1);
        UMS_CHECK("xor: mirror count unchanged by in-window create+spend",
                  db_utxo_count(&ndb) == 2);

        utxo_commitment_compute_db(ndb.db, &ground_truth);
        UMS_CHECK("xor: checkpoint still matches ground truth after in-window "
                  "create+spend",
                  utxo_commitment_boot_check_and_refresh(ndb.db, 109,
                      &computed, &refreshed) && !refreshed &&
                  utxo_commitment_equal(&computed, &ground_truth));

        /* ── Retry safety: call utxo_mirror_delta_apply directly TWICE
         * over the SAME range. Rows, caches, commitment, and cursor now share
         * one transaction, but replay remains a valuable crash/recovery seam.
         * A naive (cursor-gated, not checkpoint-height-gated)
         * incremental fold would double-XOR the h=110 spend of 0x11 and
         * corrupt the accumulator; the height-gated fold must not. */
        UMS_CHECK("xor: add coin 0x77@109", ums_add_coin(pdb, 0x77, 4242, 109));
        {
            uint8_t txid11[32]; ums_txid(txid11, 0x11);
        UMS_CHECK("xor: spend long-lived 0x11 at h=109",
                      coins_kv_spend(pdb, txid11, 0));
        }
        UMS_CHECK("xor: write utxo_apply_delta[109] (spends 0x11, created h=100)",
                  ums_write_delta_row(pdb, 109, 0x11, 1000, 100));
        UMS_CHECK("xor: advance frontier 110", ums_set_frontier(pdb, 110));

        int32_t applied1 = -1; int64_t rows1 = 0;
        int rc1 = utxo_mirror_delta_apply(
            &ndb, 109, 110, 0, UTXO_MIRROR_SYNC_CURSOR_KEY,
            &applied1, &rows1);
        UMS_CHECK("xor: retry pass 1 OK", rc1 == UTXO_MIRROR_DELTA_OK &&
                  applied1 == 110);
        /* Re-run the same range directly. Rows, caches, commitment, and cursor
         * already committed together, so this is purely idempotent replay. */
        int32_t applied2 = -1; int64_t rows2 = 0;
        int rc2 = utxo_mirror_delta_apply(
            &ndb, 109, 110, 0, UTXO_MIRROR_SYNC_CURSOR_KEY,
            &applied2, &rows2);
        UMS_CHECK("xor: retry pass 2 (same range) OK", rc2 == UTXO_MIRROR_DELTA_OK &&
                  applied2 == 110);

        utxo_commitment_compute_db(ndb.db, &ground_truth);
        UMS_CHECK("xor: checkpoint correct after a retried (double-applied) pass",
                  utxo_commitment_boot_check_and_refresh(ndb.db, 110,
                      &computed, &refreshed) && !refreshed &&
                  utxo_commitment_equal(&computed, &ground_truth));
        UMS_CHECK("xor: mirror count == 2 (0x22, 0x77) after retried pass",
                  db_utxo_count(&ndb) == 2);
        UMS_CHECK("xor: retried-pass long-lived spend (0x11) gone from mirror",
                  !db_utxo_exists(&ndb,
                      (const uint8_t[32]){[0]=0x11,[31]=0x9c}, 0));

        int64_t v110 = -1;
        UMS_CHECK("xor: delta transaction persisted cursor atomically",
                  node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY,
                                        &v110) && v110 == 110);
    }

    /* ── HEADER-TIP GUARD — cursor is next-height-to-apply ─────────────
     * The symmetric header guard in utxo_mirror_sync_run_once must compare
     * header_tip against frontier - 1 (the last APPLIED height), not the raw
     * utxo_apply cursor (the NEXT height to apply). With the raw cursor a
     * quiet at-tip node (frontier == tip + 1, header_tip == tip) deferred
     * every tick forever, the mirror never completed, and the wallet/vault
     * read models starved. Wire a fake header tip into the csr singleton
     * (this binary never boots the real one) and prove all three arms. */
    {
        struct chain_state_repository *csr = csr_instance();
        bool was_init = csr->initialized;
        struct block_index **was_slot = csr->pindex_best_hdr;

        struct block_index bi;
        memset(&bi, 0, sizeof(bi));
        struct block_index *slot = &bi;
        csr->pindex_best_hdr = &slot;
        csr->initialized = true;

        /* (a) Steady state: headers AT the last applied height (frontier - 1).
         *     The pass must NOT defer — this is the arm that used to starve. */
        bi.nHeight = 110;
        UMS_CHECK("guard: write empty causal delta[110]",
                  ums_write_empty_delta_row(pdb, 110));
        UMS_CHECK("guard: advance frontier 111 (applied through 110)",
                  ums_set_frontier(pdb, 111));
        int64_t wg = utxo_mirror_sync_run_once(&svc);
        UMS_CHECK("guard: frontier-1 == header_tip does NOT defer "
                  "(incremental empty block, 0 rows)", wg == 0);
        UMS_CHECK("guard: mirror count still 2", db_utxo_count(&ndb) == 2);
        {
            int64_t cur = -1;
            node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
            UMS_CHECK("guard: cursor advanced to 111", cur == 111);
        }

        /* (b) Headers genuinely BEHIND the last applied height (the snapshot-
         *     seed shape the guard exists for): the pass MUST defer. */
        UMS_CHECK("guard: add coin 0x99@111", ums_add_coin(pdb, 0x99, 7777, 111));
        UMS_CHECK("guard: write empty causal delta[111]",
                  ums_write_empty_delta_row(pdb, 111));
        UMS_CHECK("guard: advance frontier 112", ums_set_frontier(pdb, 112));
        bi.nHeight = 100;
        UMS_CHECK("guard: frontier-1 > header_tip defers (0 rows)",
                  utxo_mirror_sync_run_once(&svc) == 0);
        UMS_CHECK("guard: deferred pass left mirror untouched (count 2)",
                  db_utxo_count(&ndb) == 2);
        {
            int64_t cur = -1;
            node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
            UMS_CHECK("guard: deferred pass left cursor at 111", cur == 111);
        }

        /* (c) Headers catch up to the last applied height: the SAME pass now
         *     runs and picks up the coin added while deferred. */
        bi.nHeight = 111;
        UMS_CHECK("guard: caught-up pass adds only the new coin",
                  utxo_mirror_sync_run_once(&svc) == 1);
        UMS_CHECK("guard: mirror count == 3 after catch-up",
                  db_utxo_count(&ndb) == 3);
        UMS_CHECK("guard: 0x99 present after catch-up",
                  db_utxo_exists(&ndb,
                      (const uint8_t[32]){[0]=0x99,[31]=0x9c}, 0));
        {
            int64_t cur = -1;
            node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
            UMS_CHECK("guard: cursor advanced to 112", cur == 112);
        }

        /* One hundred sequential post-convergence blocks: every pass is
         * proportional to its single created coin and no wholesale scan is
         * permitted. */
        int64_t rebuilds_before = atomic_load(&svc.rebuilds_run);
        int64_t delta_rows_before = atomic_load(&svc.delta_rows_changed);
        bool hundred_ok = true;
        bi.nHeight = 211;
        for (int32_t h = 112; h < 212 && hundred_ok; h++) {
            hundred_ok = ums_add_height_coin(pdb, h) &&
                         ums_write_empty_delta_row(pdb, h) &&
                         ums_set_frontier(pdb, h + 1) &&
                         utxo_mirror_sync_run_once(&svc) == 1;
        }
        UMS_CHECK("100 sequential blocks apply with changed-coin work only",
                  hundred_ok);
        UMS_CHECK("100 sequential blocks trigger zero wholesale rebuilds",
                  atomic_load(&svc.rebuilds_run) == rebuilds_before);
        UMS_CHECK("100 sequential blocks report exactly 100 delta rows",
                  atomic_load(&svc.delta_rows_changed) ==
                      delta_rows_before + 100);

        /* A canonical rewind lowers coins_applied_height before the mirror
         * has an inverse projection record. Both markers are next-height
         * cursors, so cursor == frontier+1 is a real authority rewind, not an
         * off-by-one convention to normalize. Fail closed without touching
         * the projection; even a later frontier rebound must not auto-clear
         * the quarantine because the same height can name a different branch. */
        uint8_t rewind_txid[32] = {0};
        ums_le32(rewind_txid, 211);
        rewind_txid[31] = 0x5a;
        UMS_CHECK("rewind: remove losing-branch h=211 authority coin",
                  coins_kv_spend(pdb, rewind_txid, 0));
        UMS_CHECK("rewind: lower authority frontier from 212 to 211",
                  ums_set_frontier(pdb, 211));
        int64_t rewind_rebuilds = atomic_load(&svc.rebuilds_run);
        int64_t rewind_rows = db_utxo_count(&ndb);
        UMS_CHECK("rewind: ahead mirror cursor quarantines",
                  utxo_mirror_sync_run_once(&svc) == -1 &&
                  atomic_load(&svc.mirror_health) ==
                      UTXO_MIRROR_QUARANTINED);
        UMS_CHECK("rewind: losing-branch mirror rows remain frozen",
                  db_utxo_count(&ndb) == rewind_rows &&
                  db_utxo_exists(&ndb, rewind_txid, 0));
        {
            int64_t cur = -1;
            node_db_state_get_int(&ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cur);
            UMS_CHECK("rewind: cursor is never silently decremented", cur == 212);
        }
        UMS_CHECK("rewind: no automatic wholesale rebuild",
                  atomic_load(&svc.rebuilds_run) == rewind_rebuilds);
        UMS_CHECK("rewind: repeated tick is a bounded no-op",
                  utxo_mirror_sync_run_once(&svc) == 0);
        UMS_CHECK("rewind: authority frontier can rebound",
                  ums_set_frontier(pdb, 212));
        UMS_CHECK("rewind: equal-height rebound stays quarantined",
                  utxo_mirror_sync_run_once(&svc) == 0 &&
                  atomic_load(&svc.mirror_health) ==
                      UTXO_MIRROR_QUARANTINED &&
                  db_utxo_exists(&ndb, rewind_txid, 0));

        csr->initialized = was_init;
        csr->pindex_best_hdr = was_slot;
    }

    app_runtime_set_current(NULL);
    db_service_stop(&dbsvc);
    progress_store_close();
    node_db_close(&ndb);
    test_cleanup_tmpdir(dir);
    return failures;
}
