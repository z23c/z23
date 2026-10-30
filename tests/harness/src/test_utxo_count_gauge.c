/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the periodic UTXO-count gauge reuses a cached exact count instead
 * of scanning the utxos table on every poll, and stays correct across insert,
 * spend and re-insert (undo) once its age bound passes. */

#include "test/test_core.h"

#include "models/database.h"
#include "models/utxo.h"
#include "models/utxo_count_cache.h"

#include <stdio.h>
#include <string.h>

#define UCG_CHECK(name, expr) do {                       \
    printf("utxo_count_gauge: %s... ", (name));          \
    if (expr) printf("OK\n");                            \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static int64_t g_ucg_now = 1000;

static int64_t ucg_clock(void)
{
    return g_ucg_now;
}

static bool ucg_put(struct node_db *ndb, uint8_t id)
{
    static const uint8_t script[3] = {0x51, 0x51, 0x51};
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    u.txid[0] = id;
    u.vout = 0;
    u.value = 1000;
    u.script = (uint8_t *)script;
    u.script_len = sizeof(script);
    u.height = 1;
    return db_utxo_save(ndb, &u);
}

static bool ucg_polls_hit_cache(struct node_db *ndb, int64_t expect)
{
    bool ok = true;
    for (int i = 0; i < 100; i++)
        ok = ok && node_db_utxo_count_gauge(ndb) == expect;
    return ok;
}

static int ucg_case_cached_and_correct(void)
{
    int failures = 0;
    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:"))
        return 1;
    node_db_utxo_count_gauge_test_reset(ucg_clock);
    g_ucg_now = 1000;

    bool seeded = ucg_put(&ndb, 1) && ucg_put(&ndb, 2) && ucg_put(&ndb, 3);
    UCG_CHECK("100 polls return the exact count", seeded &&
              ucg_polls_hit_cache(&ndb, 3));
    UCG_CHECK("100 polls run one full count",
              node_db_utxo_count_gauge_test_full_counts() == 1);

    bool spent = db_utxo_delete(&ndb, (uint8_t[32]){2}, 0);
    g_ucg_now += UTXO_COUNT_GAUGE_MAX_AGE_SECS - 1;
    UCG_CHECK("inside the age bound the cached value is served",
              spent && node_db_utxo_count_gauge(&ndb) == 3 &&
              node_db_utxo_count_gauge_test_full_counts() == 1);
    g_ucg_now += 1;
    UCG_CHECK("after the bound a spend is reflected",
              node_db_utxo_count_gauge(&ndb) == 2 &&
              node_db_utxo_count_gauge_test_full_counts() == 2);

    bool undone = ucg_put(&ndb, 2) && ucg_put(&ndb, 4);
    g_ucg_now += UTXO_COUNT_GAUGE_MAX_AGE_SECS;
    UCG_CHECK("after the bound an undo and an insert are reflected",
              undone && node_db_utxo_count_gauge(&ndb) == 4 &&
              node_db_utxo_count_gauge(&ndb) == node_db_utxo_count(&ndb));
    node_db_utxo_count_gauge_test_reset(NULL);
    node_db_close(&ndb);
    return failures;
}

static int ucg_case_cache_primitive(void)
{
    int failures = 0;
    struct utxo_count_cache c = {0};
    int64_t v = -1;
    UCG_CHECK("empty cache misses", !utxo_count_cache_get(&c, 100, 60, &v));
    utxo_count_cache_put(&c, 100, 42);
    UCG_CHECK("fresh value hits", utxo_count_cache_get(&c, 159, 60, &v) &&
              v == 42);
    UCG_CHECK("expired value misses", !utxo_count_cache_get(&c, 160, 60, &v));
    UCG_CHECK("clock moving backwards misses",
              !utxo_count_cache_get(&c, 99, 60, &v));
    return failures;
}

int test_utxo_count_gauge(void)
{
    printf("\n=== utxo_count_gauge tests ===\n");
    int failures = 0;
    failures += ucg_case_cached_and_correct();
    failures += ucg_case_cache_primitive();
    return failures;
}
