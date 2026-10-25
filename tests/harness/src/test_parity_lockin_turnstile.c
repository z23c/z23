/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Parity pins for the pure ZIP-209 turnstile core (step 1 of
 * reducer-shielded-consensus-plan.md (c); not wired into block application).
 * Each case states what core/modules/validation/src/connect_block.c does for
 * the same inputs: Sprout is checked first, a pool is enforced only when its
 * previous total is known, an unknown parent leaves the pool unknown. */

#include "test/test_core.h"

#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_turnstile.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/nullifier_kv.h"
#include "storage/shielded_pool_kv.h"
#include "util/safe_alloc.h"

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

    int64_t s = -1, p = -1;
    utxo_apply_turnstile_block_values(&blk, &s, &p);
    TS_CHECK("block sums: sprout += old - new, sapling += value_balance",
             s == 25 && p == 13);

    free(blk.vtx[0].v_joinsplit);
    free(blk.vtx);
    memset(&blk, 0, sizeof(blk));
    utxo_apply_turnstile_block_values(&blk, &s, &p);
    TS_CHECK("empty block sums to zero", s == 0 && p == 0);
    return failures;
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

static sqlite3 *ts_db(int *failures)
{
    sqlite3 *db = NULL;
    TS_CHECK("open in-memory store",
             sqlite3_open(":memory:", &db) == SQLITE_OK &&
             shielded_pool_kv_ensure_schema(db));
    return db;
}

/* One stage_check call on a fresh summary. */
static bool ts_step(sqlite3 *db, int64_t h, int64_t vb, int64_t vo,
                    int64_t vn, struct delta_summary *s,
                    struct utxo_apply_turnstile_pending *p)
{
    struct block blk;
    ts_block(&blk, vb, vo, vn);
    memset(s, 0, sizeof(*s));
    s->ok = true;
    s->status = "ok";
    bool r = utxo_apply_turnstile_stage_check(db, &blk, h, NULL, s, p);
    ts_block_free(&blk);
    return r;
}

static bool ts_pending_is(const struct utxo_apply_turnstile_pending *p,
                          bool write, int64_t sprout, int64_t sapling)
{
    return p->write == write && (!write || (p->sprout == sprout &&
                                            p->sapling == sapling));
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
    sqlite3 *db = ts_db(&failures);
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("genesis: parent is known {0,0}, row = its own block values",
             ts_step(db, 0, 5, 3, 1, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 2, 5) &&
             shielded_pool_kv_put(db, 0, p.sprout, p.sapling) &&
             kv_pair(db, 0, 2, 5));
    TS_CHECK("known parent, positive block: accepted, totals accumulate",
             ts_step(db, 1, 4, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 2, 9));
    sqlite3_close(db);
    return failures;
}

static int test_stage_sapling(void)
{
    int failures = 0;
    sqlite3 *db = ts_db(&failures);
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    uint64_t before = atomic_load(&g_ua_turnstile_would_reject_total);
    (void)shielded_pool_kv_put(db, 9, 0, 10);
    TS_CHECK("shadow: negative sapling pool still applies, records total",
             ts_step(db, 10, -20, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, -10));
    TS_CHECK("shadow: would_reject counted once",
             atomic_load(&g_ua_turnstile_would_reject_total) == before + 1);
    atomic_store(&g_enforce_turnstile, true);
    TS_CHECK("enforce: sapling violation refused, exact label, no row",
             ts_step(db, 10, -20, 0, 0, &s, &p) &&
             ts_refused_as(&s, "turnstile_sapling", KIND_SAPLING) &&
             !p.write && kv_absent(db, 10));
    TS_CHECK("enforce: exactly-zero sapling total is accepted",
             ts_step(db, 10, -10, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, 0));
    atomic_store(&g_enforce_turnstile, false);
    sqlite3_close(db);
    return failures;
}

static int test_stage_sprout(void)
{
    int failures = 0;
    sqlite3 *db = ts_db(&failures);
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
             ts_step(db, 10, -100, 0, 8, &s, &p) &&
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
    bool ok = ts_step(db, 50, -1000, 0, 1000, &s, &p) && s.ok && !p.write &&
              atomic_load(&g_ua_turnstile_unknown_total) == u + 1 &&
              atomic_load(&g_ua_turnstile_would_reject_total) == w;
    atomic_store(&g_enforce_turnstile, false);
    return ok;
}

static int test_stage_unknown_parent(void)
{
    int failures = 0;
    sqlite3 *db = ts_db(&failures);
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

static int test_stage_unwind(void)
{
    int failures = 0;
    sqlite3 *db = ts_db(&failures);
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    TS_CHECK("old branch rows 0..5", ts_seed_old_branch(db));
    TS_CHECK("unwind above fork 2 trims rows 3..5 and keeps the fork row",
             utxo_apply_delete_rows_above(db, 3, 5) && kv_absent(db, 3) &&
             kv_absent(db, 5) && kv_pair(db, 2, 0, 3));
    TS_CHECK("new branch recomputes from the fork row, put succeeds",
             ts_step(db, 3, 10, 0, 0, &s, &p) && s.ok &&
             ts_pending_is(&p, true, 0, 13) &&
             shielded_pool_kv_put(db, 3, p.sprout, p.sapling) &&
             kv_pair(db, 3, 0, 13));
    sqlite3_close(db);
    return failures;
}

int test_parity_lockin_turnstile(void)
{
    return test_block_values() + test_check() + test_pool_kv() +
           test_stage_genesis_and_accept() + test_stage_sapling() +
           test_stage_sprout() + test_stage_unknown_parent() +
           test_stage_unwind();
}
