/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the bg_hash_verify_store seam.
 *
 * Exercises the sqlite adapter through its port surface against an
 * ISOLATED in-memory node DB (the real state-kv schema, never the live
 * node DB):
 *
 *   1. A fresh store has no cursor -> load_progress returns false and
 *      leaves the out-parameter untouched (caller restarts from genesis).
 *   2. save_progress(h) then load_progress reads back exactly h.
 *   3. save_progress overwrites the prior cursor (highest-wins is the
 *      caller's job; the store just round-trips the last value written).
 *   4. Guard rails: bind rejects a NULL out_port; a port bound over a
 *      NULL / closed DB degrades to "no cursor" / "save no-ops" without
 *      crashing.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/bg_hash_verify_store_sqlite.h"
#include "ports/bg_hash_verify_store_port.h"
#include "models/database.h"

#include <string.h>
#include <stdio.h>

#define BGHV_CHECK(name, expr) do {                          \
    printf("bg_hash_verify_store_port: %s... ", (name));     \
    if ((expr)) { printf("OK\n"); }                          \
    else { printf("FAIL\n"); failures++; }                   \
} while (0)

int test_bg_hash_verify_store_port(void)
{
    int failures = 0;

    /* ---- Round-trip through the port over an in-memory node DB ---- */
    {
        struct node_db ndb;
        BGHV_CHECK("open in-memory node db",
                   node_db_open(&ndb, ":memory:") && ndb.open);

        struct bg_hash_verify_store_port store = {0};
        BGHV_CHECK("bind store port",
                   bg_hash_verify_store_sqlite_bind(&ndb, &store));

        /* 1. fresh store: no cursor. */
        int h = 12345;            /* sentinel; must stay untouched */
        BGHV_CHECK("fresh load returns false",
                   !store.load_progress(store.self, &h));
        BGHV_CHECK("fresh load leaves out untouched", h == 12345);

        /* 2. save then load. */
        BGHV_CHECK("save 1000 succeeds",
                   store.save_progress(store.self, 1000));
        int got = 0;
        BGHV_CHECK("load after save returns true",
                   store.load_progress(store.self, &got));
        BGHV_CHECK("loaded cursor == 1000", got == 1000);

        /* 3. overwrite. */
        BGHV_CHECK("save 2000 overwrites",
                   store.save_progress(store.self, 2000));
        got = 0;
        BGHV_CHECK("load reads overwritten 2000",
                   store.load_progress(store.self, &got) && got == 2000);

        node_db_close(&ndb);
    }

    /* ---- Guard rails ---- */
    {
        struct bg_hash_verify_store_port store = {0};
        BGHV_CHECK("bind rejects NULL out_port",
                   !bg_hash_verify_store_sqlite_bind((struct node_db *)0x1,
                                                     NULL));

        /* A port bound over a NULL db degrades gracefully. */
        BGHV_CHECK("bind accepts NULL db",
                   bg_hash_verify_store_sqlite_bind(NULL, &store));
        int h = 7;
        BGHV_CHECK("load over NULL db returns false",
                   !store.load_progress(store.self, &h));
        BGHV_CHECK("load over NULL db leaves out untouched", h == 7);
        BGHV_CHECK("save over NULL db returns false",
                   !store.save_progress(store.self, 99));
    }

    return failures;
}
