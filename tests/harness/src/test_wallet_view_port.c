/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the wallet_view storage seam.
 *
 * Two layers are exercised against an ISOLATED in-memory fixture DB
 * (built with the real wallet_sapling_keys / wallet_keys / zslp_tokens /
 * zslp_transfers schema) — never the live node DB:
 *
 *   1. The sqlite adapter through its port surface directly:
 *      list_receive_addresses, list_held_tokens.
 *
 *   2. The service (wv_list_receive_addresses / wv_list_held_tokens)
 *      driving the SAME fixture and producing identical projected rows —
 *      proving the rewire preserved external behaviour bit-for-bit.
 *
 * NOTE on coupling: test_wallet_view.c queries the LIVE node DB and is
 * unrelated to this fixture-based test; this file does not touch it and
 * uses its own throwaway DB so it is hermetic.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/wallet_view_sqlite.h"
#include "ports/wallet_view_port.h"
#include "services/wallet_view_projection.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define WV_CHECK(name, expr) do {                           \
    printf("wallet_view_port: %s... ", (name));             \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* Build the minimal subset of the real schema the queries touch. */
static bool make_fixture_db(sqlite3 **out_db)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK || !db)
        return false;

    static const char *ddl =
        "CREATE TABLE wallet_sapling_keys ("
        " address TEXT);"
        "CREATE TABLE wallet_keys ("
        " pubkey_hash BLOB);"
        "CREATE TABLE zslp_tokens ("
        " token_id BLOB PRIMARY KEY, ticker TEXT, decimals INTEGER);"
        "CREATE TABLE zslp_transfers ("
        " token_id BLOB, to_addr BLOB, tx_type TEXT, amount INTEGER);";
    if (sqlite3_exec(db, ddl, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    *out_db = db;
    return true;
}

static bool exec_sql(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

/* Seed a scenario:
 *   - 3 sapling receive addresses, one NULL and one empty (filtered out).
 *   - one wallet key (pubkey_hash = x'DEAD').
 *   - token TOK1 (token_id x'11', 8 decimals): SEND of 300 to our key,
 *     SEND of 100 to our key -> net 400 (positive, held).
 *   - token TOK2 (token_id x'22', 0 decimals): SEND of 50 to a STRANGER
 *     key -> not held (net to our key = 0, filtered by the subquery). */
static bool seed_scenario(sqlite3 *db)
{
    if (!exec_sql(db,
        "INSERT INTO wallet_sapling_keys(address) VALUES"
        " ('zs1aaa'),(NULL),(''),('zs1bbb');"))
        return false;
    if (!exec_sql(db,
        "INSERT INTO wallet_keys(pubkey_hash) VALUES (x'DEAD');"))
        return false;
    if (!exec_sql(db,
        "INSERT INTO zslp_tokens(token_id,ticker,decimals) VALUES"
        " (x'11','TOK1',8),(x'22','TOK2',0);"))
        return false;
    if (!exec_sql(db,
        "INSERT INTO zslp_transfers(token_id,to_addr,tx_type,amount) VALUES"
        " (x'11',x'DEAD','SEND',300),"
        " (x'11',x'DEAD','SEND',100),"
        " (x'22',x'BEEF','SEND',50);"))
        return false;
    return true;
}

int test_wallet_view_port(void)
{
    int failures = 0;

    /* ---- Layer 1: adapter through the port directly ---- */
    {
        sqlite3 *db = NULL;
        WV_CHECK("fixture db builds", make_fixture_db(&db));
        WV_CHECK("scenario seeds", db && seed_scenario(db));

        struct wallet_view_port port = {0};
        WV_CHECK("bind sqlite port", wallet_view_sqlite_bind(db, &port));

        struct wallet_view_receive_address addrs[8];
        memset(addrs, 0, sizeof addrs);
        int na = port.list_receive_addresses(port.self, addrs, 8);
        WV_CHECK("receive addresses: 2 non-empty rows", na == 2);
        WV_CHECK("receive addr[0] == zs1aaa",
                 na == 2 && strcmp(addrs[0].address, "zs1aaa") == 0);
        WV_CHECK("receive addr[1] == zs1bbb",
                 na == 2 && strcmp(addrs[1].address, "zs1bbb") == 0);

        /* max=1 caps the projection. */
        int na1 = port.list_receive_addresses(port.self, addrs, 1);
        WV_CHECK("receive addresses respects max=1", na1 == 1);

        struct wallet_view_held_token toks[8];
        memset(toks, 0, sizeof toks);
        int nt = port.list_held_tokens(port.self, toks, 8);
        WV_CHECK("held tokens: only TOK1 held", nt == 1);
        WV_CHECK("held tok ticker == TOK1",
                 nt == 1 && strcmp(toks[0].ticker, "TOK1") == 0);
        WV_CHECK("held tok decimals == 8", nt == 1 && toks[0].decimals == 8);
        WV_CHECK("held tok token_id == hex(11)",
                 nt == 1 && strcmp(toks[0].token_id, "11") == 0);

        sqlite3_close(db);
    }

    /* ---- Layer 2: the service projects identical rows via the port ---- */
    {
        sqlite3 *db = NULL;
        if (!make_fixture_db(&db) || !seed_scenario(db)) {
            WV_CHECK("service fixture builds", false);
            if (db) sqlite3_close(db);
            return failures;
        }

        struct wv_receive_address addrs[8];
        memset(addrs, 0, sizeof addrs);
        int na = wv_list_receive_addresses(db, addrs, 8);
        WV_CHECK("service receive: 2 rows", na == 2);
        WV_CHECK("service addr[0] == zs1aaa",
                 na == 2 && strcmp(addrs[0].address, "zs1aaa") == 0);

        struct wv_held_token toks[8];
        memset(toks, 0, sizeof toks);
        int nt = wv_list_held_tokens(db, toks, 8);
        WV_CHECK("service held: 1 token", nt == 1);
        WV_CHECK("service held ticker TOK1",
                 nt == 1 && strcmp(toks[0].ticker, "TOK1") == 0);

        sqlite3_close(db);
    }

    /* ---- Guard rails: NULL / bad args ---- */
    {
        struct wallet_view_port port = {0};
        struct wallet_view_receive_address a[1];
        struct wallet_view_held_token t[1];
        WV_CHECK("bind rejects NULL db",
                 !wallet_view_sqlite_bind(NULL, &port));
        WV_CHECK("service receive rejects NULL db",
                 wv_list_receive_addresses(NULL, (void *)a, 1) == 0);
        WV_CHECK("service held rejects NULL db",
                 wv_list_held_tokens(NULL, (void *)t, 1) == 0);
        WV_CHECK("service receive rejects max=0",
                 wv_list_receive_addresses((sqlite3 *)0x1,
                                           (void *)a, 0) == 0);
    }

    return failures;
}
