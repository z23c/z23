/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * ZIP-209 pool-totals seeder (lane 2b): fills shielded_pool_totals from the
 * block bodies up to cursor-1 on a node that synced before the table
 * existed. A synthetic active chain plus an injected body reader stand in
 * for the blk files; the store is an in-memory sqlite. */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_turnstile.h"
#include "jobs/utxo_apply_turnstile_seed.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/shielded_pool_kv.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SD_CHECK(name, expr) do {                          \
    printf("utxo_apply_turnstile_seed: %s... ", (name));   \
    if ((expr)) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }                 \
} while (0)

struct sd_fx {
    sqlite3 *db;
    struct main_state ms;
    struct block_index *bi;
    struct uint256 *hash;
    int64_t *sprout;    /* per-height block values (the body decides) */
    int64_t *sapling;
    int n;
    int fail_h;         /* reader refuses this height, -1 none */
};

static int64_t sd_sprout_of(int h) { return h % 3; }
static int64_t sd_sapling_of(int h) { return h + 1; }

static bool sd_reader(struct block *out, const struct block_index *bi,
                      const char *datadir, void *user)
{
    (void)datadir;
    struct sd_fx *fx = user;
    int h = bi->nHeight;
    memset(out, 0, sizeof(*out));
    if (h < 0 || h >= fx->n || h == fx->fail_h)
        return false;
    out->num_vtx = 1;
    out->vtx = zcl_calloc(1, sizeof(struct transaction), "sd_tx");
    out->vtx[0].value_balance = fx->sapling[h];
    if (fx->sprout[h] != 0) {
        out->vtx[0].num_joinsplit = 1;
        out->vtx[0].v_joinsplit =
            zcl_calloc(1, sizeof(struct js_description), "sd_js");
        out->vtx[0].v_joinsplit[0].vpub_old = fx->sprout[h];
    }
    return true;
}

static void sd_set_cursor(struct sd_fx *fx, int64_t cursor)
{
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
             "VALUES('utxo_apply',%lld,0)", (long long)cursor);
    sqlite3_exec(fx->db, sql, NULL, NULL, NULL);
}

static bool sd_open(struct sd_fx *fx, int n, int64_t cursor)
{
    memset(fx, 0, sizeof(*fx));
    fx->n = n;
    fx->fail_h = -1;
    fx->bi = zcl_calloc((size_t)n, sizeof(struct block_index), "sd_bi");
    fx->hash = zcl_calloc((size_t)n, sizeof(struct uint256), "sd_hash");
    fx->sprout = zcl_calloc((size_t)n, sizeof(int64_t), "sd_sp");
    fx->sapling = zcl_calloc((size_t)n, sizeof(int64_t), "sd_sa");
    active_chain_init(&fx->ms.chain_active);
    for (int i = 0; i < n; i++) {
        fx->hash[i].data[0] = (unsigned char)(i & 0xff);
        fx->hash[i].data[1] = (unsigned char)(i >> 8);
        fx->hash[i].data[31] = 0x5a;
        block_index_init(&fx->bi[i]);
        fx->bi[i].phashBlock = &fx->hash[i];
        fx->bi[i].nHeight = i;
        fx->bi[i].nFile = 0;
        fx->bi[i].nDataPos = 1;
        fx->bi[i].nStatus = BLOCK_HAVE_DATA;
        if (i > 0)
            fx->bi[i].pprev = &fx->bi[i - 1];
        fx->sprout[i] = sd_sprout_of(i);
        fx->sapling[i] = sd_sapling_of(i);
    }
    active_chain_move_window_tip(&fx->ms.chain_active, &fx->bi[n - 1]);
    if (sqlite3_open(":memory:", &fx->db) != SQLITE_OK ||
        !shielded_pool_kv_ensure_schema(fx->db) ||
        sqlite3_exec(fx->db,
            "CREATE TABLE stage_cursor(name TEXT PRIMARY KEY,"
            "cursor INTEGER NOT NULL,updated_at INTEGER NOT NULL)",
            NULL, NULL, NULL) != SQLITE_OK)
        return false;
    sd_set_cursor(fx, cursor);
    utxo_apply_turnstile_seed_reset_for_test();
    return true;
}

static void sd_close(struct sd_fx *fx)
{
    utxo_apply_turnstile_seed_reset_for_test();
    sqlite3_close(fx->db);
    active_chain_free(&fx->ms.chain_active);
    free(fx->bi);
    free(fx->hash);
    free(fx->sprout);
    free(fx->sapling);
}

static bool sd_run(struct sd_fx *fx)
{
    return utxo_apply_turnstile_seed_run(fx->db, &fx->ms, "", sd_reader, fx);
}

static int64_t sd_max(struct sd_fx *fx)
{
    int64_t h = -1;
    bool found = false;
    return shielded_pool_kv_max_height(fx->db, &h, &found) && found ? h : -1;
}

static bool sd_row_is(struct sd_fx *fx, int64_t h, int64_t sp, int64_t sa)
{
    int64_t a = 0, b = 0;
    bool found = false;
    return shielded_pool_kv_get(fx->db, h, &a, &b, &found) && found &&
           a == sp && b == sa;
}

static void sd_sums(int upto, int64_t *sp, int64_t *sa)
{
    *sp = *sa = 0;
    for (int h = 0; h <= upto; h++) {
        *sp += sd_sprout_of(h);
        *sa += sd_sapling_of(h);
    }
}

static int test_seed_empty_table(void)
{
    int failures = 0;
    struct sd_fx fx;
    int64_t sp, sa;
    SD_CHECK("fixture", sd_open(&fx, 10, 10));
    while (sd_run(&fx)) {}
    sd_sums(9, &sp, &sa);
    SD_CHECK("empty table seeds 0..cursor-1", sd_max(&fx) == 9);
    SD_CHECK("row cursor-1 equals the summed block values",
             sd_row_is(&fx, 9, sp, sa));
    sd_sums(0, &sp, &sa);
    SD_CHECK("genesis row is its own block values", sd_row_is(&fx, 0, sp, sa));
    SD_CHECK("seeded range is idle once complete", !sd_run(&fx));
    sd_close(&fx);
    return failures;
}

static int test_seed_bounded_slice(void)
{
    int failures = 0;
    struct sd_fx fx;
    SD_CHECK("fixture", sd_open(&fx, 2600, 2600));
    SD_CHECK("one call writes rows", sd_run(&fx));
    SD_CHECK("one call writes at most 1024 rows", sd_max(&fx) == 1023);
    SD_CHECK("second call continues the run", sd_run(&fx) &&
             sd_max(&fx) == 2047);
    sd_close(&fx);
    return failures;
}

static int test_seed_missing_body(void)
{
    int failures = 0;
    struct sd_fx fx;
    struct utxo_apply_turnstile_seed_stats st;
    SD_CHECK("fixture", sd_open(&fx, 10, 5));
    while (sd_run(&fx)) {}
    SD_CHECK("seeded 0..4", sd_max(&fx) == 4);
    sd_set_cursor(&fx, 10);
    fx.fail_h = 5;
    SD_CHECK("missing body at K+1 writes nothing", !sd_run(&fx) &&
             sd_max(&fx) == 4);
    utxo_apply_turnstile_seed_stats_get(&st);
    SD_CHECK("missing body raises the transient blocker",
             blocker_exists("utxo_apply.turnstile_seed_body") &&
             !strcmp(st.hold, "body"));
    fx.fail_h = -1;
    SD_CHECK("readable body resumes seeding", sd_run(&fx) && sd_max(&fx) == 9);
    utxo_apply_turnstile_seed_stats_get(&st);
    SD_CHECK("blocker clears once the body reads",
             !blocker_exists("utxo_apply.turnstile_seed_body") &&
             !strcmp(st.hold, "none"));
    sd_close(&fx);
    return failures;
}

static int test_seed_ignores_cached_values(void)
{
    int failures = 0;
    struct sd_fx fx;
    int64_t sp, sa;
    SD_CHECK("fixture", sd_open(&fx, 8, 8));
    for (int i = 0; i < 8; i++) {   /* wrong either way: junk and zero */
        fx.bi[i].nSproutValue = (i % 2) ? 777 : 0;
        fx.bi[i].nSaplingValue = (i % 2) ? 0 : -555;
    }
    while (sd_run(&fx)) {}
    sd_sums(7, &sp, &sa);
    SD_CHECK("the body decides, the cached columns are ignored",
             sd_max(&fx) == 7 && sd_row_is(&fx, 7, sp, sa));
    sd_close(&fx);
    return failures;
}

static void sd_rewind_hook(void *user)
{
    sd_set_cursor(user, 3);
}

static void sd_rehash_hook(void *user)
{
    struct sd_fx *fx = user;
    static struct uint256 other;
    other.data[0] = 0xee;
    fx->bi[4].phashBlock = &other;
}

static int test_seed_discards_stale_slice(void)
{
    int failures = 0;
    struct sd_fx fx;
    SD_CHECK("fixture", sd_open(&fx, 10, 10));
    utxo_apply_turnstile_seed_set_gap_hook_for_test(sd_rewind_hook, &fx);
    SD_CHECK("cursor rewound between phases keeps only heights < cursor",
             sd_run(&fx) && sd_max(&fx) == 2);
    sd_close(&fx);
    SD_CHECK("fixture 2", sd_open(&fx, 10, 10));
    utxo_apply_turnstile_seed_set_gap_hook_for_test(sd_rehash_hook, &fx);
    SD_CHECK("changed active-chain hash discards the slice",
             !sd_run(&fx) && sd_max(&fx) == -1);
    sd_close(&fx);
    return failures;
}

static int test_seed_handoff(void)
{
    int failures = 0;
    struct sd_fx fx;
    struct delta_summary s;
    struct utxo_apply_turnstile_pending p;
    struct block blk;
    int64_t sp, sa;
    SD_CHECK("fixture", sd_open(&fx, 10, 9));   /* genesis datadir shape */
    while (sd_run(&fx)) {}
    SD_CHECK("genesis row written from the genesis body",
             sd_row_is(&fx, 0, sd_sprout_of(0), sd_sapling_of(0)));
    memset(&s, 0, sizeof(s));
    s.ok = true;
    s.status = "ok";
    SD_CHECK("reader for cursor body", sd_reader(&blk, &fx.bi[9], "", &fx));
    SD_CHECK("stage apply of the cursor height finds its parent row",
             utxo_apply_turnstile_stage_check(fx.db, &blk, 9, NULL, &s, &p) &&
             p.write);
    sd_sums(9, &sp, &sa);
    SD_CHECK("stage continues the run with the right totals",
             p.sprout == sp && p.sapling == sa &&
             shielded_pool_kv_put(fx.db, 9, p.sprout, p.sapling) &&
             sd_max(&fx) == 9);
    block_free(&blk);
    sd_close(&fx);
    return failures;
}

static int test_seed_negative_total(void)
{
    int failures = 0;
    struct sd_fx fx;
    SD_CHECK("fixture", sd_open(&fx, 10, 10));
    fx.sapling[3] = -1000;
    SD_CHECK("slice writes rows below the finding", sd_run(&fx));
    SD_CHECK("no row at or above the negative total", sd_max(&fx) == 2);
    SD_CHECK("a transient blocker names the finding",
             blocker_exists("utxo_apply.turnstile_seed_negative"));
    SD_CHECK("seeding stops", !sd_run(&fx) && sd_max(&fx) == 2);
    sd_close(&fx);
    return failures;
}

int test_utxo_apply_turnstile_seed(void)
{
    return test_seed_empty_table() + test_seed_bounded_slice() +
           test_seed_missing_body() + test_seed_ignores_cached_values() +
           test_seed_discards_stale_slice() + test_seed_handoff() +
           test_seed_negative_total();
}
