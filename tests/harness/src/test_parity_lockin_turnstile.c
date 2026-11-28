/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Parity pins for the pure ZIP-209 turnstile core (step 1 of
 * reducer-shielded-consensus-plan.md (c); not wired into block application).
 * Each case states what core/modules/validation/src/connect_block.c does for
 * the same inputs: Sprout is checked first, a pool is enforced only when its
 * previous total is known, an unknown parent leaves the pool unknown. */

#include "test/test_core.h"
#include "test/parity_lockin_turnstile_stage.h"
#include "test/shielded_pool_reset_pairing.h"

#include "chain/chainparams.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_turnstile.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/nullifier_kv.h"
#include "storage/shielded_pool_kv.h"
#include "util/safe_alloc.h"
#include "validation/connect_block.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TS_CHECK(name, expr) do {                       \
    printf("parity_lockin_turnstile: %s... ", (name));  \
    if ((expr)) printf("OK\n");                        \
    else { printf("FAIL\n"); failures++; }             \
} while (0)

#define SPROUT_ERR "bad-txns-sprout-turnstile-violation"
#define SAPLING_ERR "bad-txns-sapling-turnstile-violation"

static struct utxo_apply_turnstile_pool known(int64_t v)
{
    struct utxo_apply_turnstile_pool p = { v, true };
    return p;
}

static struct utxo_apply_turnstile_pool unknown(void)
{
    struct utxo_apply_turnstile_pool p = { 0, false };
    return p;
}

static const char *run(struct utxo_apply_turnstile_pool ps,
                       struct utxo_apply_turnstile_pool pp,
                       int64_t bs, int64_t bp,
                       struct utxo_apply_turnstile_pool *os,
                       struct utxo_apply_turnstile_pool *op)
{
    return utxo_apply_turnstile_check(ps, pp, bs, bp, os, op);
}

static int test_block_values(void)
{
    int failures = 0;
    struct block blk;
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = 2;
    blk.vtx = zcl_calloc(2, sizeof(struct transaction), "ts_vtx");
    blk.vtx[0].num_joinsplit = 2;
    blk.vtx[0].v_joinsplit = zcl_calloc(2, sizeof(struct js_description),
                                        "ts_js");
    blk.vtx[0].v_joinsplit[0].vpub_old = 100;
    blk.vtx[0].v_joinsplit[0].vpub_new = 30;
    blk.vtx[0].v_joinsplit[1].vpub_old = 5;
    blk.vtx[0].v_joinsplit[1].vpub_new = 50;
    blk.vtx[0].value_balance = -7;
    blk.vtx[1].value_balance = 20;
    blk.vtx[0].ironwood_value_balance = -5;
    blk.vtx[1].ironwood_value_balance = -2;

    int64_t s = -1, p = -1, i = -1;
    TS_CHECK("block sums compute without overflow",
             connect_block_shielded_values(&blk, &s, &p, &i));
    TS_CHECK("block sums: sprout += old - new, sapling -= value_balance",
             s == 25 && p == -13 && i == 7);

    free(blk.vtx[0].v_joinsplit);
    free(blk.vtx);

    /* zclassicd at height 476977, the first Sapling shielding after
     * activation: one tx with valueBalance -1.00000000 ZCL moves the Sapling
     * chainValue from 0 to +1.00000000, and the Sprout delta is -11.875 ZCL
     * (12496.61384694 -> 12484.73884694). */
    memset(&blk, 0, sizeof(blk));
    blk.num_vtx = 1;
    blk.vtx = zcl_calloc(1, sizeof(struct transaction), "ts_vtx_476977");
    blk.vtx[0].value_balance = -100000000;
    connect_block_shielded_values(&blk, &s, &p, NULL);
    TS_CHECK("oracle 476977: valueBalance -1 ZCL grows the Sapling pool by 1 ZCL",
             s == 0 && p == 100000000);
    free(blk.vtx);
    {
        struct utxo_apply_turnstile_pool os, op;
        TS_CHECK("oracle 476977: totals advance to zclassicd's chainValue",
                 run(known(1249661384694), known(0), -1187500000, 100000000,
                     &os, &op) == NULL &&
                 os.known && os.total == 1248473884694 &&
                 op.known && op.total == 100000000);
    }
    memset(&blk, 0, sizeof(blk));
    connect_block_shielded_values(&blk, &s, &p, NULL);
    TS_CHECK("empty block sums to zero", s == 0 && p == 0);
    return failures;
}

static const char *run_ironwood(struct utxo_apply_turnstile_pool prev,
                                int64_t block,
                                struct utxo_apply_turnstile_pool *out)
{
    return utxo_apply_turnstile_ironwood_check(prev, block, out);
}

static int test_check(void)
{
    int failures = 0;
    struct utxo_apply_turnstile_pool os, op;

    {
        const char *r = run(known(0), known(10), 0, -11, &os, &op);
        TS_CHECK("sapling value_balance driving the pool negative is refused",
                 r && !strcmp(r, SAPLING_ERR));
    }
    TS_CHECK("sprout vpub_new above vpub_old plus the pool is refused",
             !strcmp(run(known(40), known(0), -41, 0, &os, &op),
                     SPROUT_ERR));
    TS_CHECK("both pools violating returns the sprout string",
             !strcmp(run(known(1), known(1), -2, -2, &os, &op), SPROUT_ERR));
    TS_CHECK("exact-zero totals are accepted",
             run(known(5), known(7), -5, -7, &os, &op) == NULL &&
             os.known && os.total == 0 && op.known && op.total == 0);
    TS_CHECK("unknown parent pools are never enforced and stay unknown",
             run(unknown(), unknown(), -1000, -1000, &os, &op) == NULL &&
             !os.known && !op.known);
    TS_CHECK("unknown sprout does not mask a known sapling violation",
             !strcmp(run(unknown(), known(1), -1000, -2, &os, &op),
                     SAPLING_ERR) && !os.known);
    TS_CHECK("no shielded activity carries totals forward unchanged",
             run(known(123), known(456), 0, 0, &os, &op) == NULL &&
             os.known && os.total == 123 && op.known && op.total == 456);
    TS_CHECK("positive block values accumulate",
             run(known(1), known(2), 10, 20, &os, &op) == NULL &&
             os.total == 11 && op.total == 22);
    return failures;
}

static int test_ironwood_check(void)
{
    int failures = 0;
    struct utxo_apply_turnstile_pool os;
    TS_CHECK("ironwood positive and negative movements are independent",
             run_ironwood(known(100), -20, &os) == NULL && os.total == 80 &&
             run_ironwood(known(80), 25, &os) == NULL && os.total == 105);
    TS_CHECK("ironwood negative total is refused",
             run_ironwood(known(0), -1, &os) != NULL);
    TS_CHECK("ironwood cumulative overflow is refused without a total",
             run_ironwood(known(INT64_MAX), 1, &os) != NULL && !os.known);
    TS_CHECK("ironwood cumulative underflow is refused without a total",
             run_ironwood(known(INT64_MIN), -1, &os) != NULL && !os.known);
    TS_CHECK("ironwood pure unknown parent remains unknown",
             run_ironwood(unknown(), 100, &os) == NULL && !os.known);
    TS_CHECK("ironwood block delta underflow is refused",
             !connect_block_shielded_values(&(struct block){
                 .num_vtx = 1,
                 .vtx = &(struct transaction){ .ironwood_value_balance = INT64_MIN }
             }, NULL, NULL, &os.total));
    TS_CHECK("ironwood NULL output skips overflow and preserves legacy callers",
             connect_block_shielded_values(&(struct block){
                 .num_vtx = 1,
                 .vtx = &(struct transaction){ .ironwood_value_balance = INT64_MIN }
             }, NULL, NULL, NULL));
    return failures;
}


static bool kv_pair(sqlite3 *db, int64_t h, int64_t sp, int64_t sa)
{
    int64_t a = 0, b = 0;
    bool found = false;
    return shielded_pool_kv_get(db, h, &a, &b, &found) && found &&
           a == sp && b == sa;
}

static bool kv_absent(sqlite3 *db, int64_t h)
{
    int64_t a = 0, b = 0;
    bool found = true;
    return shielded_pool_kv_get(db, h, &a, &b, &found) && !found;
}

static bool kv_ironwood_pair(sqlite3 *db, int64_t h, int64_t total,
                             bool known, bool found)
{
    int64_t actual = 0;
    bool actual_known = false, actual_found = false;
    return shielded_pool_kv_get_ironwood(db, h, &actual, &actual_known,
                                         &actual_found) &&
        actual_found == found && actual_known == known &&
        (!known || actual == total);
}

static int test_pool_kv_rows(sqlite3 *db);

static int test_pool_kv(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("open in-memory store",
             sqlite3_open(":memory:", &db) == SQLITE_OK);
    TS_CHECK("ensure_schema is idempotent",
             shielded_pool_kv_ensure_schema(db) &&
             shielded_pool_kv_ensure_schema(db));
    int64_t mh = 7;
    bool mf = true;
    TS_CHECK("max_height on empty table is not found",
             shielded_pool_kv_max_height(db, &mh, &mf) && !mf && mh == -1);
    TS_CHECK("put/get round trip incl. negative totals",
             shielded_pool_kv_put(db, 0, 5, -9) && kv_pair(db, 0, 5, -9));
    TS_CHECK("missing row is not found", kv_absent(db, 1));
    TS_CHECK("same-value re-put is ok", shielded_pool_kv_put(db, 0, 5, -9));
    TS_CHECK("different sprout re-put is refused and keeps the row",
             !shielded_pool_kv_put(db, 0, 6, -9) && kv_pair(db, 0, 5, -9));
    TS_CHECK("different sapling re-put is refused and keeps the row",
             !shielded_pool_kv_put(db, 0, 5, 1) && kv_pair(db, 0, 5, -9));
    failures += test_pool_kv_rows(db);
    sqlite3_close(db);
    return failures;
}

static int test_pool_kv_rows(sqlite3 *db)
{
    int failures = 0;
    int64_t mh = 7;
    bool mf = true;
    TS_CHECK("more rows", shielded_pool_kv_put(db, 1, 1, 1) &&
             shielded_pool_kv_put(db, 2, 2, 2) &&
             shielded_pool_kv_put(db, 3, 3, 3));
    TS_CHECK("max_height reports the top row",
             shielded_pool_kv_max_height(db, &mh, &mf) && mf && mh == 3);
    TS_CHECK("delete_range removes exactly [2,3]",
             shielded_pool_kv_delete_range(db, 2, 3) && kv_absent(db, 2) &&
             kv_absent(db, 3) && kv_pair(db, 1, 1, 1) && kv_pair(db, 0, 5, -9));
    TS_CHECK("max_height follows the delete",
             shielded_pool_kv_max_height(db, &mh, &mf) && mf && mh == 1);
    TS_CHECK("delete_range rejects an inverted range",
             !shielded_pool_kv_delete_range(db, 5, 4));
    return failures;
}


static int test_pool_ironwood_migration(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood migration: open legacy schema",
             sqlite3_open(":memory:", &db) == SQLITE_OK &&
             sqlite3_exec(db,
                 "CREATE TABLE shielded_pool_totals("
                 "height INTEGER PRIMARY KEY,sprout INTEGER NOT NULL,"
                 "sapling INTEGER NOT NULL)", NULL, NULL, NULL) == SQLITE_OK &&
             sqlite3_exec(db,
                 "INSERT INTO shielded_pool_totals VALUES(0,1,2)",
                 NULL, NULL, NULL) == SQLITE_OK);
    TS_CHECK("ironwood migration: additive schema is idempotent",
             shielded_pool_kv_ensure_schema(db) &&
             shielded_pool_kv_ensure_schema(db));
    TS_CHECK("ironwood migration: legacy row is present but total unknown",
             kv_ironwood_pair(db, 0, 0, false, true));
    TS_CHECK("ironwood migration: first known put succeeds",
             shielded_pool_kv_put_ironwood(db, 0, -42) &&
             kv_ironwood_pair(db, 0, -42, true, true));
    TS_CHECK("ironwood migration: same-value re-put accepted",
             shielded_pool_kv_put_ironwood(db, 0, -42));
    TS_CHECK("ironwood migration: conflicting known value refused",
             !shielded_pool_kv_put_ironwood(db, 0, 7) &&
             kv_ironwood_pair(db, 0, -42, true, true));
    TS_CHECK("ironwood migration: missing row refused",
             !shielded_pool_kv_put_ironwood(db, 99, 1) &&
             kv_ironwood_pair(db, 99, 0, false, false));
    sqlite3_close(db);
    return failures;
}

static int test_pool_ironwood_types_and_rows(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    TS_CHECK("ironwood storage: seed rows",
             shielded_pool_kv_put(db, 0, 0, 0) &&
             shielded_pool_kv_put(db, 1, 0, 0) &&
             shielded_pool_kv_put(db, 2, 0, 0));
    TS_CHECK("ironwood storage: TEXT is not a known total",
             sqlite3_exec(db, "UPDATE shielded_pool_totals SET ironwood='not-a-number' WHERE height=0",
                          NULL, NULL, NULL) == SQLITE_OK &&
             kv_ironwood_pair(db, 0, 0, false, false));
    TS_CHECK("ironwood storage: REAL is not a known total",
             sqlite3_exec(db, "UPDATE shielded_pool_totals SET ironwood=1.5 WHERE height=0",
                          NULL, NULL, NULL) == SQLITE_OK &&
             kv_ironwood_pair(db, 0, 0, false, false));
    TS_CHECK("ironwood storage: BLOB is not a known total",
             sqlite3_exec(db, "UPDATE shielded_pool_totals SET ironwood=zeroblob(4) WHERE height=0",
                          NULL, NULL, NULL) == SQLITE_OK &&
             kv_ironwood_pair(db, 0, 0, false, false));
    TS_CHECK("ironwood storage: concurrent delete makes affected rows zero",
             shielded_pool_kv_put(db, 4, 0, 0) &&
             sqlite3_exec(db,
                 "CREATE TRIGGER ironwood_delete_before_update "
                 "BEFORE UPDATE ON shielded_pool_totals "
                 "WHEN OLD.height=4 BEGIN "
                 "DELETE FROM shielded_pool_totals WHERE height=4; END;",
                 NULL, NULL, NULL) == SQLITE_OK &&
             !shielded_pool_kv_put_ironwood(db, 4, 9) &&
             kv_absent(db, 4));
    sqlite3_close(db);
    return failures;
}

/* ── Stage-facing step (shadow by default, refusal under enforcement) ──── */

#define KIND_SPROUT "bad-txns-sprout-turnstile-violation"
#define KIND_SAPLING "bad-txns-sapling-turnstile-violation"

static void ts_block(struct block *blk, int64_t value_balance,
                     int64_t vpub_old, int64_t vpub_new)
{
    memset(blk, 0, sizeof(*blk));
    blk->num_vtx = 1;
    blk->vtx = zcl_calloc(1, sizeof(struct transaction), "ts_stage_tx");
    blk->vtx[0].value_balance = value_balance;
    if (vpub_old || vpub_new) {
        blk->vtx[0].num_joinsplit = 1;
        blk->vtx[0].v_joinsplit = zcl_calloc(1, sizeof(struct js_description),
                                             "ts_stage_js");
        blk->vtx[0].v_joinsplit[0].vpub_old = vpub_old;
        blk->vtx[0].v_joinsplit[0].vpub_new = vpub_new;
    }
}

static void ts_block_free(struct block *blk)
{
    free(blk->vtx[0].v_joinsplit);
    free(blk->vtx);
}


/* One stage_check call on a fresh summary. */
static bool ts_step_ironwood(sqlite3 *db, int64_t h, int64_t vb, int64_t vo,
                             int64_t vn, int64_t ivb, struct delta_summary *s,
                             struct utxo_apply_turnstile_pending *p)
{
    struct block blk;
    ts_block(&blk, vb, vo, vn);
    blk.vtx[0].ironwood_value_balance = ivb;
    memset(s, 0, sizeof(*s));
    s->ok = true;
    s->status = "ok";
    bool r = utxo_apply_turnstile_stage_check(db, &blk, h, NULL, s, p);
    ts_block_free(&blk);
    return r;
}

static bool ts_step(sqlite3 *db, int64_t h, int64_t vb, int64_t vo,
                    int64_t vn, struct delta_summary *s,
                    struct utxo_apply_turnstile_pending *p)
{
    return ts_step_ironwood(db, h, vb, vo, vn, 0, s, p);
}

static bool ts_pending_is(const struct utxo_apply_turnstile_pending *p,
                          bool write, int64_t sprout, int64_t sapling)
{
    return p->write == write && (!write || (p->sprout == sprout &&
                                            p->sapling == sapling));
}

static bool ts_pending_ironwood_is(const struct utxo_apply_turnstile_pending *p,
                                   int64_t total)
{
    return p->ironwood_known && p->ironwood == total;
}

static bool ts_refused_as(const struct delta_summary *s, const char *status,
                          const char *kind)
{
    return !s->ok && !strcmp(s->status, status) &&
           !strcmp(s->failure_kind, kind);
}

static int test_stage_genesis_and_accept(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("genesis: parent is known {0,0}, row = its own block values",
             ts_step(db, 0, -5, 3, 1, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 2, 5) &&
             shielded_pool_kv_put(db, 0, p.sprout, p.sapling) &&
             kv_pair(db, 0, 2, 5));
    TS_CHECK("known parent, positive block: accepted, totals accumulate",
             ts_step(db, 1, -4, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 2, 9));
    sqlite3_close(db);
    return failures;
}

static int test_stage_sapling(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    uint64_t before = atomic_load(&g_ua_turnstile_would_reject_total);
    (void)shielded_pool_kv_put(db, 9, 0, 10);
    TS_CHECK("shadow: negative sapling pool still applies, records total",
             ts_step(db, 10, 20, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, -10));
    TS_CHECK("shadow: would_reject counted once",
             atomic_load(&g_ua_turnstile_would_reject_total) == before + 1);
    atomic_store(&g_enforce_turnstile, true);
    TS_CHECK("enforce: sapling violation refused, exact label, no row",
             ts_step(db, 10, 20, 0, 0, &s, &p) &&
             ts_refused_as(&s, "turnstile_sapling", KIND_SAPLING) &&
             !p.write && kv_absent(db, 10));
    TS_CHECK("enforce: exactly-zero sapling total is accepted",
             ts_step(db, 10, 10, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, 0));
    atomic_store(&g_enforce_turnstile, false);
    sqlite3_close(db);
    return failures;
}

static int test_stage_sprout(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    (void)shielded_pool_kv_put(db, 9, 5, 7);
    TS_CHECK("shadow: vpub_new > vpub_old + pool still applies",
             ts_step(db, 10, 0, 0, 8, &s, &p) && s.ok &&
             ts_pending_is(&p, true, -3, 7));
    atomic_store(&g_enforce_turnstile, true);
    TS_CHECK("enforce: sprout violation refused, exact label, no row",
             ts_step(db, 10, 0, 0, 8, &s, &p) &&
             ts_refused_as(&s, "turnstile_sprout", KIND_SPROUT) &&
             !p.write && kv_absent(db, 10));
    TS_CHECK("enforce: sprout is checked before sapling",
             ts_step(db, 10, 100, 0, 8, &s, &p) &&
             ts_refused_as(&s, "turnstile_sprout", KIND_SPROUT));
    TS_CHECK("enforce: exactly-zero sprout total is accepted",
             ts_step(db, 10, 0, 0, 5, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, 7));
    atomic_store(&g_enforce_turnstile, false);
    sqlite3_close(db);
    return failures;
}

static bool ts_unknown_in_mode(sqlite3 *db, bool enforce)
{
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    uint64_t u = atomic_load(&g_ua_turnstile_unknown_total);
    uint64_t w = atomic_load(&g_ua_turnstile_would_reject_total);
    atomic_store(&g_enforce_turnstile, enforce);
    bool ok = ts_step(db, 50, 1000, 0, 1000, &s, &p) && s.ok && !p.write &&
              atomic_load(&g_ua_turnstile_unknown_total) == u + 1 &&
              atomic_load(&g_ua_turnstile_would_reject_total) == w;
    atomic_store(&g_enforce_turnstile, false);
    return ok;
}

static int test_stage_unknown_parent(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    TS_CHECK("unknown parent: applied, no row, unknown+1 (shadow)",
             ts_unknown_in_mode(db, false));
    TS_CHECK("unknown parent: applied, no row, unknown+1 (enforce)",
             ts_unknown_in_mode(db, true));
    TS_CHECK("unknown parent wrote no row", kv_absent(db, 50));
    sqlite3_close(db);
    return failures;
}

static bool ts_reorg_schema(sqlite3 *db)
{
    return sqlite3_exec(db, "CREATE TABLE utxo_apply_log(height INTEGER)",
                        NULL, NULL, NULL) == SQLITE_OK &&
           utxo_apply_ensure_delta_schema(db) &&
           nullifier_kv_ensure_schema(db);
}

static bool ts_seed_old_branch(sqlite3 *db)
{
    if (!ts_reorg_schema(db))
        return false;
    for (int64_t h = 0; h <= 5; h++)
        if (!shielded_pool_kv_put(db, h, 0, h + 1))
            return false;
    return true;
}

static int test_pool_reset(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("reset: open in-memory store",
             sqlite3_open(":memory:", &db) == SQLITE_OK);
    TS_CHECK("reset: seed rows",
             shielded_pool_kv_ensure_schema(db) &&
             shielded_pool_kv_put(db, 0, 1, 2) &&
             shielded_pool_kv_put(db, 1, 3, 4));
    TS_CHECK("reset outside a transaction is refused and keeps the rows",
             !shielded_pool_kv_reset_in_tx(db) && kv_pair(db, 0, 1, 2) &&
             kv_pair(db, 1, 3, 4));
    TS_CHECK("reset inside a transaction drops every row",
             sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
             shielded_pool_kv_reset_in_tx(db) && kv_absent(db, 0) &&
             kv_absent(db, 1));
    TS_CHECK("reset rolls back with its transaction",
             sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK &&
             kv_pair(db, 0, 1, 2) && kv_pair(db, 1, 3, 4));
    TS_CHECK("a recomputed height after a committed reset puts cleanly",
             sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
             shielded_pool_kv_reset_in_tx(db) &&
             sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK &&
             shielded_pool_kv_put(db, 0, 9, 9) && kv_pair(db, 0, 9, 9));
    sqlite3_close(db);
    return failures;
}

static int test_stage_ironwood_movement(void)
{
    int failures = 0;
    TS_CHECK("ironwood stage: select research chain",
             chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("ironwood stage: genesis deposit starts from known zero",
             ts_step_ironwood(db, 0, 0, 0, 0, -100, &s, &p) && s.ok &&
             ts_pending_ironwood_is(&p, 100) &&
             shielded_pool_kv_put(db, 0, p.sprout, p.sapling) &&
             shielded_pool_kv_put_ironwood(db, 0, p.ironwood) &&
             kv_ironwood_pair(db, 0, 100, true, true));
    TS_CHECK("ironwood stage: withdrawal reduces the total",
             ts_step_ironwood(db, 1, 0, 0, 0, 25, &s, &p) && s.ok &&
             ts_pending_ironwood_is(&p, 75) &&
             shielded_pool_kv_put(db, 1, p.sprout, p.sapling) &&
             shielded_pool_kv_put_ironwood(db, 1, p.ironwood) &&
             kv_ironwood_pair(db, 1, 75, true, true));
    TS_CHECK("ironwood stage: second deposit accumulates independently",
             ts_step_ironwood(db, 2, 0, 0, 0, -50, &s, &p) && s.ok &&
             ts_pending_ironwood_is(&p, 125));
    sqlite3_close(db);
    chain_params_select(CHAIN_REGTEST);
    return failures;
}

static int test_stage_ironwood_overflow(void)
{
    int failures = 0;
    TS_CHECK("ironwood overflow: select research chain",
             chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    (void)shielded_pool_kv_put(db, 9, 0, 0);
    (void)shielded_pool_kv_put_ironwood(db, 9, INT64_MAX);
    atomic_store(&g_enforce_turnstile, false);
    TS_CHECK("ironwood overflow: cumulative overflow fails closed",
             ts_step_ironwood(db, 10, 0, 0, 0, -1, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 10));
    (void)shielded_pool_kv_put(db, 10, 0, 0);
    (void)shielded_pool_kv_put_ironwood(db, 10, INT64_MIN);
    TS_CHECK("ironwood overflow: cumulative underflow fails closed",
             ts_step_ironwood(db, 11, 0, 0, 0, 1, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 11));
    (void)shielded_pool_kv_put(db, 11, 0, 0);
    (void)shielded_pool_kv_put_ironwood(db, 11, 0);
    TS_CHECK("ironwood overflow: block delta underflow fails closed",
             ts_step_ironwood(db, 12, 0, 0, 0, INT64_MIN, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 12));
    sqlite3_close(db);
    chain_params_select(CHAIN_REGTEST);
    return failures;
}

static int test_stage_ironwood_unknown_parent(void)
{
    int failures = 0;
    TS_CHECK("ironwood unknown parent: select research chain",
             chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("ironwood unknown parent: missing parent is not known zero",
             ts_step_ironwood(db, 50, 0, 0, 0, 0, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 50));
    (void)shielded_pool_kv_put(db, 30, 1, 2);
    TS_CHECK("ironwood unknown parent: legacy NULL parent remains unknown",
             ts_step_ironwood(db, 31, 0, 0, 0, 0, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 31));
    sqlite3_close(db);
    chain_params_select(CHAIN_REGTEST);
    return failures;
}

static int test_stage_ironwood_negative(void)
{
    int failures = 0;
    TS_CHECK("ironwood negative: select research chain",
             chain_research_profile_select(CHAIN_RESEARCH_IRONWOOD));
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    (void)shielded_pool_kv_put(db, 20, 0, 0);
    (void)shielded_pool_kv_put_ironwood(db, 20, 0);
    atomic_store(&g_enforce_turnstile, true);
    TS_CHECK("ironwood negative: negative total refused under enforcement",
             ts_step_ironwood(db, 21, 0, 0, 0, 1, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 21));
    atomic_store(&g_enforce_turnstile, false);
    TS_CHECK("ironwood negative: shadow negative total records real chain",
             ts_step_ironwood(db, 21, 0, 0, 0, 1, &s, &p) && s.ok &&
             ts_pending_ironwood_is(&p, -1) &&
             shielded_pool_kv_put(db, 21, p.sprout, p.sapling) &&
             shielded_pool_kv_put_ironwood(db, 21, p.ironwood) &&
             kv_ironwood_pair(db, 21, -1, true, true));
    atomic_store(&g_enforce_turnstile, true);
    TS_CHECK("ironwood negative: known negative parent refused under enforcement",
             ts_step_ironwood(db, 22, 0, 0, 0, 0, &s, &p) &&
             ts_refused_as(&s, "turnstile_ironwood",
                           "bad-txns-ironwood-turnstile-violation") &&
             !p.write && kv_absent(db, 22));
    atomic_store(&g_enforce_turnstile, false);
    sqlite3_close(db);
    chain_params_select(CHAIN_REGTEST);
    return failures;
}

static int test_stage_unwind(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    TS_CHECK("ironwood storage: open store", sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("old branch rows 0..5", ts_seed_old_branch(db));
    TS_CHECK("unwind above fork 2 trims rows 3..5 and keeps the fork row",
             utxo_apply_delete_rows_above(db, 3, 5) && kv_absent(db, 3) &&
             kv_absent(db, 5) && kv_pair(db, 2, 0, 3));
    TS_CHECK("new branch recomputes from the fork row, put succeeds",
             ts_step(db, 3, -10, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, 13) &&
             shielded_pool_kv_put(db, 3, p.sprout, p.sapling) &&
             kv_pair(db, 3, 0, 13));
    sqlite3_close(db);
    return failures;
}

int test_parity_lockin_turnstile(void)
{
    return test_block_values() + test_check() + test_ironwood_check() +
           test_pool_kv() +
           test_pool_ironwood_migration() + test_pool_ironwood_types_and_rows() +
           test_stage_genesis_and_accept() + test_stage_sapling() +
           test_stage_sprout() + test_stage_unknown_parent() +
           test_stage_ironwood_movement() + test_stage_ironwood_overflow() +
           test_stage_ironwood_unknown_parent() + test_stage_ironwood_negative() +
           test_stage_unwind() + test_pool_reset() +
           shielded_pool_reset_pairing_cases() +
           parity_lockin_turnstile_stage_cases();
}
