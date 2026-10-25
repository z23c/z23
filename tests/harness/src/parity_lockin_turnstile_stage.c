/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Stage-level ZIP-209 turnstile cases: the REAL utxo_apply stage step is
 * driven over a synthetic chain whose block 2 (enforce) or block 1 (shadow)
 * carries a Sapling value_balance that drives the pool negative.
 *
 *  - ENFORCE: block 1 reveals nullifier N and block 2 reveals a fresh X and
 *    then N again while violating the turnstile. The refusal must be the
 *    turnstile (not the double-spend N would raise if the nullifier gate ran
 *    first), leave no nullifier rows at the refused height, no totals row,
 *    and hold the cursor at the refused height.
 *  - SHADOW (default): the same violation still applies; the totals row is
 *    written with the chain's real totals together with the inverse-delta. */

#include "test/parity_lockin_turnstile_stage.h"

#include "test/block_fixtures.h"
#include "test/block_index_ext_fixture.h"
#include "test/test_core.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/utxo_apply_turnstile.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "storage/shielded_pool_kv.h"
#include "test/test_block_map.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/util.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define PT_CHECK(name, expr) do {                                  \
    printf("parity_lockin_turnstile: stage %s... ", (name));       \
    if ((expr)) printf("OK\n");                                    \
    else { printf("FAIL\n"); failures++; }                         \
} while (0)

#define PT_BLOCKS 3

struct pt_chain {
    struct block_index blocks[PT_BLOCKS];
    struct uint256 hashes[PT_BLOCKS];
    struct block bodies[PT_BLOCKS];
};

static void pt_txid(struct uint256 *out, int h, int salt)
{
    uint256_set_null(out);
    out->data[0] = (uint8_t)(0x80 + h);
    out->data[1] = (uint8_t)salt;
}

/* Coinbase-only body for height h (value 50 + h, the same synthetic shape the
 * other stage tests use). */
static bool pt_body(struct block *b, int h)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = (uint32_t)(1700002000u + (uint32_t)h);
    b->header.nBits = 0x1f07ffff;
    b->num_vtx = 1;
    b->vtx = zcl_calloc(1, sizeof(struct transaction), "pt_tx");
    if (!b->vtx)
        return false;
    transaction_init(&b->vtx[0]);
    if (!transaction_alloc(&b->vtx[0], 1, 1))
        return false;
    outpoint_set_null(&b->vtx[0].vin[0].prevout);
    b->vtx[0].vout[0].value = 50 + h;
    b->vtx[0].vout[0].script_pub_key.size = 0;
    pt_txid(&b->vtx[0].hash, h, 1);
    b->header.hashMerkleRoot = b->vtx[0].hash;
    return true;
}

static bool pt_build(struct pt_chain *c)
{
    memset(c, 0, sizeof(*c));
    for (int i = 0; i < PT_BLOCKS; i++) {
        if (!pt_body(&c->bodies[i], i))
            return false;
        if (i > 0)
            c->bodies[i].header.hashPrevBlock = c->hashes[i - 1];
        block_header_get_hash(&c->bodies[i].header, &c->hashes[i]);
        block_index_init(&c->blocks[i]);
        c->blocks[i].phashBlock = &c->hashes[i];
        tbi_ext(&c->blocks[i])->hashMerkleRoot =
            c->bodies[i].header.hashMerkleRoot;
        c->blocks[i].nHeight = i;
        c->blocks[i].nVersion = c->bodies[i].header.nVersion;
        c->blocks[i].nTime = c->bodies[i].header.nTime;
        c->blocks[i].nBits = c->bodies[i].header.nBits;
        c->blocks[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0)
            c->blocks[i].pprev = &c->blocks[i - 1];
    }
    return true;
}

/* Append a bare shielded-data tx to block h revealing the Sapling nullifiers
 * (tags[i], 0x5A) and carrying value_balance. The vtx array is shallow-moved
 * (inner pointers transfer; the old array is released with plain free). */
static bool pt_add_shielded(struct pt_chain *c, int h, const uint8_t *tags,
                            size_t n, int64_t value_balance)
{
    struct block *b = &c->bodies[h];
    struct transaction *nv = zcl_calloc(b->num_vtx + 1, sizeof(*nv), "pt_tx2");
    if (!nv)
        return false;
    memcpy(nv, b->vtx, b->num_vtx * sizeof(*nv));
    free(b->vtx);
    b->vtx = nv;
    struct transaction *tx = &b->vtx[b->num_vtx++];
    transaction_init(tx);
    pt_txid(&tx->hash, h, 3);
    tx->value_balance = value_balance;
    tx->v_shielded_spend =
        zcl_calloc(n, sizeof(struct spend_description), "pt_sap");
    if (!tx->v_shielded_spend)
        return false;
    tx->num_shielded_spend = n;
    struct incremental_merkle_tree empty;
    struct uint256 empty_root;
    sapling_tree_init(&empty);
    incremental_tree_root(&empty, &empty_root);
    for (size_t i = 0; i < n; i++) {
        tx->v_shielded_spend[i].anchor = empty_root;
        tx->v_shielded_spend[i].nullifier.data[0] = tags[i];
        tx->v_shielded_spend[i].nullifier.data[1] = 0x5A;
    }
    return true;
}

static void pt_free(struct pt_chain *c)
{
    for (int i = 0; i < PT_BLOCKS; i++)
        block_free(&c->bodies[i]);
}

static bool pt_reader(struct block *out, const struct block_index *bi,
                      const char *datadir, void *user)
{
    (void)datadir;
    struct pt_chain *c = user;
    if (!out || !bi || !c || bi->nHeight < 0 || bi->nHeight >= PT_BLOCKS)
        return false;
    return test_block_copy(out, &c->bodies[bi->nHeight], "pt_tx_copy");
}

static bool pt_lookup(const struct uint256 *txid, uint32_t vout,
                      struct utxo_apply_lookup *out, void *user)
{
    (void)txid; (void)vout; (void)user;
    memset(out, 0, sizeof(*out));
    return true;
}

static bool pt_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err)
        sqlite3_free(err);
    return rc == SQLITE_OK;
}

/* Upstream verdicts the stage requires: proof_validate_log (+ cursor) before
 * stage init, script_validate_log after (init creates the table). */
static bool pt_seed_proof(sqlite3 *db, const struct pt_chain *c)
{
    if (!pt_exec(db,
        "CREATE TABLE IF NOT EXISTS proof_validate_log ("
        "  height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
        "  ok INTEGER NOT NULL, sapling_spends_total INTEGER NOT NULL,"
        "  sapling_outputs_total INTEGER NOT NULL,"
        "  sprout_joinsplits_total INTEGER NOT NULL, block_hash BLOB,"
        "  first_failure_txid BLOB, first_failure_proof_type TEXT,"
        "  validated_at INTEGER NOT NULL)"))
        return false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO proof_validate_log "
        "(height, status, ok, sapling_spends_total, sapling_outputs_total, "
        " sprout_joinsplits_total, block_hash, validated_at) "
        "VALUES (?, 'verified', 1, 0, 0, 0, ?, 1)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < PT_BLOCKS; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, c->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:test-fixture-seeding
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name, cursor, updated_at) "
             "VALUES('proof_validate', %d, 1)", PT_BLOCKS);
    return pt_exec(db, sql);
}

static bool pt_seed_script(sqlite3 *db, const struct pt_chain *c)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO script_validate_log "
        "(height, status, ok, tx_count, input_count, validated_at, "
        " block_hash) VALUES (?, 'verified', 1, 1, 1, 1, ?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    for (int h = 0; h < PT_BLOCKS; h++) {
        sqlite3_bind_int(st, 1, h);
        sqlite3_bind_blob(st, 2, c->hashes[h].data, 32, SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) {  // raw-sql-ok:test-fixture-seeding
            sqlite3_finalize(st);
            return false;
        }
        sqlite3_reset(st);
    }
    sqlite3_finalize(st);
    return true;
}

static int pt_setup(const char *tag, char *dir, size_t dir_size,
                    struct main_state *ms, struct pt_chain *c)
{
    /* *ms is zeroed and its chain and block map are initialised before the
     * first failure return, so every return path leaves *ms initialised. */
    memset(ms, 0, sizeof(*ms));
    active_chain_init(&ms->chain_active);
    block_map_init(&ms->map_block_index);
    test_fmt_tmpdir(dir, dir_size, "utxo_apply", tag);
    if (mkdir("./test-tmp", 0700) != 0 && errno != EEXIST)
        return 1;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return 1;
    SetDataDir(dir);
    if (!progress_store_open(dir) || !projection_store_open(dir))
        return 2;
    if (!pt_build(c))
        return 3;
    active_chain_move_window_tip(&ms->chain_active, &c->blocks[PT_BLOCKS - 1]);
    if (!pt_seed_proof(progress_store_db(), c))
        return 4;
    if (!utxo_apply_stage_init(ms))
        return 5;
    if (!pt_seed_script(progress_store_db(), c))
        return 6;
    utxo_apply_stage_set_reader(pt_reader, c);
    utxo_apply_stage_set_lookup(pt_lookup, c);
    return 0;
}

static void pt_teardown(const char *dir, struct main_state *ms,
                        struct pt_chain *c)
{
    utxo_apply_stage_shutdown();
    active_chain_free(&ms->chain_active);
    block_map_free(&ms->map_block_index);
    pt_free(c);
    projection_store_close();
    progress_store_close();
    SetDataDir("");
    ClearDataDirCache();
    test_cleanup_tmpdir(dir);
}

static int64_t pt_count(sqlite3 *db, const char *table, int height)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s WHERE height = ?",
             table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, height);
    int64_t n = -1;
    if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-fixture-seeding
        n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return n;
}

static bool pt_pool_is(sqlite3 *db, int h, int64_t sprout, int64_t sapling)
{
    int64_t a = 0, b = 0;
    bool found = false;
    return shielded_pool_kv_get(db, h, &a, &b, &found) && found &&
           a == sprout && b == sapling;
}

static bool pt_pool_absent(sqlite3 *db, int h)
{
    int64_t a = 0, b = 0;
    bool found = true;
    return shielded_pool_kv_get(db, h, &a, &b, &found) && !found;
}

static bool pt_blocker_has(const char *needle)
{
    struct blocker_snapshot snaps[16];
    int n = blocker_snapshot_all(snaps, 16);
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, "utxo_apply.apply_failed") == 0 &&
            strstr(snaps[i].reason, needle) != NULL)
            return true;
    return false;
}

/* ENFORCE: h1 reveals N (no value); h2 reveals fresh X then N again with
 * value_balance -5 (sapling total 0 -> -5). */
static int pt_enforce_case(void)
{
    int failures = 0;
    char dir[256];
    struct main_state ms;
    struct pt_chain c;
    const uint8_t h1_tags[1] = { 0xA1 };
    const uint8_t h2_tags[2] = { 0xAE, 0xA1 };
    blocker_clear("utxo_apply.apply_failed");
    PT_CHECK("enforce: setup",
             pt_setup("ts_stage_enf", dir, sizeof(dir), &ms, &c) == 0);
    PT_CHECK("enforce: h1 shielded tx attaches",
             pt_add_shielded(&c, 1, h1_tags, 1, 0));
    PT_CHECK("enforce: h2 shielded tx attaches",
             pt_add_shielded(&c, 2, h2_tags, 2, -5));
    atomic_store(&g_enforce_turnstile, true);
    (void)utxo_apply_stage_drain(100);
    atomic_store(&g_enforce_turnstile, false);
    sqlite3 *db = progress_store_db();
    PT_CHECK("enforce: cursor held at the refused height",
             utxo_apply_stage_cursor() == 2);
    PT_CHECK("enforce: refused as turnstile_sapling, not a double-spend",
             pt_blocker_has("status=turnstile_sapling") &&
             pt_blocker_has("kind=bad-txns-sapling-turnstile-violation"));
    PT_CHECK("enforce: applied h1 left its nullifier and totals row",
             pt_count(db, "nullifiers", 1) == 1 && pt_pool_is(db, 1, 0, 0));
    PT_CHECK("enforce: refused h2 left NO nullifier rows",
             pt_count(db, "nullifiers", 2) == 0);
    PT_CHECK("enforce: refused h2 wrote NO totals row",
             pt_pool_absent(db, 2));
    PT_CHECK("enforce: refused h2 wrote no inverse-delta row",
             pt_count(db, "utxo_apply_delta", 2) == 0);
    blocker_clear("utxo_apply.apply_failed");
    pt_teardown(dir, &ms, &c);
    return failures;
}

/* SHADOW (default mode): the violating block applies and records the chain's
 * real totals with its inverse-delta in the same stage txn. */
static int pt_shadow_case(void)
{
    int failures = 0;
    char dir[256];
    struct main_state ms;
    struct pt_chain c;
    const uint8_t h1_tags[1] = { 0xB1 };
    blocker_clear("utxo_apply.apply_failed");
    PT_CHECK("shadow: setup",
             pt_setup("ts_stage_shd", dir, sizeof(dir), &ms, &c) == 0);
    PT_CHECK("shadow: h1 shielded tx attaches",
             pt_add_shielded(&c, 1, h1_tags, 1, -5));
    atomic_store(&g_enforce_turnstile, false);
    (void)utxo_apply_stage_drain(100);
    sqlite3 *db = progress_store_db();
    PT_CHECK("shadow: every block applied",
             utxo_apply_stage_cursor() == PT_BLOCKS);
    PT_CHECK("shadow: no apply_failed blocker",
             !blocker_exists("utxo_apply.apply_failed"));
    PT_CHECK("shadow: would-reject counted",
             atomic_load(&g_ua_turnstile_would_reject_total) >= 1);
    PT_CHECK("shadow: h1 nullifier inserted",
             pt_count(db, "nullifiers", 1) == 1);
    PT_CHECK("shadow: h1 inverse-delta and totals row written together",
             pt_count(db, "utxo_apply_delta", 1) == 1 &&
             pt_pool_is(db, 1, 0, -5));
    PT_CHECK("shadow: h0 genesis row is the known {0,0} start",
             pt_pool_is(db, 0, 0, 0));
    pt_teardown(dir, &ms, &c);
    return failures;
}

int parity_lockin_turnstile_stage_cases(void)
{
    return pt_enforce_case() + pt_shadow_case();
}
