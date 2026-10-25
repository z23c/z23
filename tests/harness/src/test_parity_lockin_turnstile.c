/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Parity pins for the pure ZIP-209 turnstile core (step 1 of
 * reducer-shielded-consensus-plan.md (c); not wired into block application).
 * Each case states what core/modules/validation/src/connect_block.c does for
 * the same inputs: Sprout is checked first, a pool is enforced only when its
 * previous total is known, an unknown parent leaves the pool unknown. */

#include "test/test_core.h"

#include "jobs/utxo_apply_turnstile.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"

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

int test_parity_lockin_turnstile(void)
{
    return test_block_values() + test_check();
}
