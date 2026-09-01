/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * END-TO-END WALLET SPECS — test with REAL SQLite data.
 *
 * These create a temporary database with realistic wallet state,
 * then render pages and verify the HTML matches the data.
 * This catches bugs like "says untraceable but 84% is public."
 *
 * The in-memory DB gives us a controlled test environment
 * without touching the real wallet. */

#include "test/test_core.h"
#include "test/wallet_view_fixture.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include "models/database.h"
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <unistd.h>

DEFINE_WALLET_VIEW_CLIENT(_resp, _e2e_len, e2e_request, e2e_GET, e2e_POST,
                          e2e_has, 131072)

/* Create a temp dir with a node.db that has controlled wallet state */
static char g_tmpdir[256];

static bool setup_test_db(int64_t transparent_sat, int64_t shielded_sat)
{
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/zcl_e2e_XXXXXX");
    if (!mkdtemp(g_tmpdir)) return false;

    char dbpath[512];
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", g_tmpdir);

    sqlite3 *db = NULL;
    if (sqlite3_open(dbpath, &db) != SQLITE_OK) return false;

    /* Create minimal schema */
    TEST_DB_EXEC(db,
        "CREATE TABLE IF NOT EXISTS blocks ("
        "  hash BLOB PRIMARY KEY, height INTEGER, time INTEGER,"
        "  prev_hash BLOB, version INTEGER, merkle_root BLOB,"
        "  bits INTEGER, nonce BLOB, solution BLOB, chain_work BLOB,"
        "  status INTEGER DEFAULT 0, file_pos INTEGER DEFAULT 0,"
        "  num_tx INTEGER DEFAULT 0, sapling_root BLOB,"
        "  sprout_root BLOB, sapling_value_balance INTEGER DEFAULT 0,"
        "  sprout_value_balance INTEGER DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS wallet_utxos ("
        "  txid BLOB, vout INTEGER, value INTEGER,"
        "  address_hash BLOB, script BLOB, height INTEGER,"
        "  spent_txid BLOB, spent_vin INTEGER, is_coinbase INTEGER,"
        "  PRIMARY KEY(txid, vout));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_notes ("
        "  txid BLOB, output_index INTEGER, value INTEGER,"
        "  rcm BLOB, memo BLOB, ivk BLOB, diversifier BLOB,"
        "  pk_d BLOB, cm BLOB, nullifier BLOB UNIQUE,"
        "  block_height INTEGER, spent_txid BLOB, address TEXT,"
        "  PRIMARY KEY(txid, output_index));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_keys ("
        "  ivk BLOB PRIMARY KEY, xsk BLOB, xfvk BLOB,"
        "  diversifier BLOB, pk_d BLOB, child_index INTEGER,"
        "  address TEXT);"
        "CREATE TABLE IF NOT EXISTS wallet_keys ("
        "  pubkey_hash BLOB PRIMARY KEY, pubkey BLOB, privkey BLOB,"
        "  compressed INTEGER, created_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS wallet_transactions ("
        "  txid BLOB PRIMARY KEY, raw_tx BLOB, block_hash BLOB,"
        "  block_height INTEGER, time_received INTEGER,"
        "  from_me INTEGER, fee INTEGER);"
        "CREATE TABLE IF NOT EXISTS peers ("
        "  id INTEGER PRIMARY KEY, ip TEXT, port INTEGER,"
        "  services INTEGER, last_seen INTEGER,"
        "  last_try INTEGER, attempts INTEGER, source TEXT);"
        "CREATE TABLE IF NOT EXISTS mempool ("
        "  txid BLOB PRIMARY KEY, raw_tx BLOB, fee INTEGER,"
        "  size INTEGER, time_added INTEGER, height_added INTEGER);"
        "CREATE TABLE IF NOT EXISTS sapling_spends ("
        "  nullifier BLOB PRIMARY KEY, txid BLOB);"
        "CREATE TABLE IF NOT EXISTS zslp_tokens ("
        "  token_id BLOB PRIMARY KEY, ticker TEXT, name TEXT,"
        "  decimals INTEGER, genesis_height INTEGER);"
        "CREATE TABLE IF NOT EXISTS zslp_transfers ("
        "  id INTEGER PRIMARY KEY, token_id BLOB, tx_type TEXT,"
        "  txid BLOB, from_addr BLOB, to_addr BLOB, amount INTEGER);"
        "CREATE TABLE IF NOT EXISTS contacts ("
        "  address TEXT PRIMARY KEY, name TEXT, last_used INTEGER);"
    );

    /* Insert transparent UTXOs if requested */
    if (transparent_sat > 0) {
        uint8_t fake_txid[32] = {0x01};
        uint8_t fake_addr[20] = {0xAA};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_utxos (txid,vout,value,address_hash,height)"
            " VALUES (?,0,?,?,100)", {
            sqlite3_bind_blob(s, 1, fake_txid, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, transparent_sat);
            sqlite3_bind_blob(s, 3, fake_addr, 20, SQLITE_STATIC);
        });
    }

    /* Insert shielded notes if requested */
    if (shielded_sat > 0) {
        uint8_t fake_txid[32] = {0x02};
        uint8_t fake_nf[32] = {0xBB};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_sapling_notes"
            " (txid,output_index,value,nullifier,block_height)"
            " VALUES (?,0,?,?,200)", {
            sqlite3_bind_blob(s, 1, fake_txid, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, shielded_sat);
            sqlite3_bind_blob(s, 3, fake_nf, 32, SQLITE_STATIC);
        });
    }

    /* Insert a tip block so height queries work */
    {
        uint8_t h[32] = {0xFF};
        uint8_t ph[32] = {0xFE};
        uint8_t mr[32] = {0xFD};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO blocks (hash,height,time,prev_hash,version,"
            "merkle_root,bits,status,num_tx)"
            " VALUES (?,500000,1700000000,?,4,?,0x1d00ffff,3,1)",
        {
            sqlite3_bind_blob(s, 1, h, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, ph, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 3, mr, 32, SQLITE_STATIC);
        });
    }

    sqlite3_close(db);
    return true;
}

static void cleanup_test_db(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
    (void)system(cmd);
    wallet_view_init(NULL);
}

int spec_e2e_wallet(void)
{
    int failures = 0;
    printf("\n=== E2E Wallet Tests (real SQLite data) ===\n");

    /* ── Test: mostly public funds shows accurate privacy % ── */
    {   printf("e2e: 84%% public shows honest privacy meter... ");
        bool ok = setup_test_db(
            84000000,   /* 0.84 ZCL transparent */
            16000000    /* 0.16 ZCL shielded */
        );
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet");

            /* Should show ~16% private, not claim "untraceable" */
            ok = e2e_has("private");
            ok = ok && !e2e_has("untraceable");
            ok = ok && !e2e_has("You are now untraceable");
            /* Should show nudge to shield remaining */
            ok = ok && (e2e_has("Shield All") || e2e_has("shield") ||
                        e2e_has("/wallet/shield"));
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: 100% private shows celebration ── */
    {   printf("e2e: 100%% private shows all-private state... ");
        bool ok = setup_test_db(0, 100000000); /* 1.0 ZCL all shielded */
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet");

            /* Should show 100% private */
            ok = e2e_has("100%") || e2e_has("All funds private");
            /* Should NOT show the nudge */
            ok = ok && !e2e_has("Shield All");
            ok = ok && !e2e_has("transparent addresses");
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: zero balance shows clean empty state ── */
    {   printf("e2e: zero balance renders cleanly... ");
        bool ok = setup_test_db(0, 0);
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet");

            ok = e2e_has("0.00") || e2e_has("0.0000");
            ok = ok && !e2e_has("untraceable");
            ok = ok && !e2e_has("sqlite");
            ok = ok && !e2e_has("ERROR");
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: dashboard renders all key elements with data ── */
    {   printf("e2e: dashboard with real data has all elements... ");
        bool ok = setup_test_db(50000000, 50000000); /* 0.5 + 0.5 */
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet");

            ok = e2e_has("ZCL");          /* balance shows */
            ok = ok && e2e_has("Send");    /* nav works */
            ok = ok && e2e_has("Receive");
            ok = ok && e2e_has("private"); /* privacy meter */
            ok = ok && e2e_has("/wallet/node"); /* node strip */
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: node page works with real block data ── */
    {   printf("e2e: node page shows block height from DB... ");
        bool ok = setup_test_db(0, 0);
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet/node");

            ok = e2e_has("Command Center");
            ok = ok && e2e_has("Block Height");
            ok = ok && e2e_has("500"); /* height 500000 */
            ok = ok && e2e_has("sovereign");
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: history page with no transactions is clean ── */
    {   printf("e2e: empty history shows friendly state... ");
        bool ok = setup_test_db(0, 0);
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet/history");

            ok = !e2e_has("sqlite");
            ok = ok && !e2e_has("SELECT");
            ok = ok && !e2e_has("ERROR");
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Test: coins page shows real UTXO data ── */
    {   printf("e2e: coins page shows transparent UTXOs... ");
        bool ok = setup_test_db(75000000, 25000000);
        if (ok) {
            wallet_view_init(g_tmpdir);
            e2e_GET("/wallet/coins");

            ok = e2e_has("Coin Audit") || e2e_has("ZCL");
            ok = ok && !e2e_has("sqlite");
        }
        cleanup_test_db();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("E2E wallet: %d failures\n", failures);
    return failures;
}
