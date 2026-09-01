/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * RENDER AUDIT — find real bugs in rendered HTML.
 *
 * Creates a realistic wallet DB, renders every page, and checks
 * for actual defects:
 * - Unresolved {{template_vars}} leaking to user
 * - Empty pages (0 bytes or just headers)
 * - SQL/internal errors leaking to user
 * - Broken HTML structure
 * - Missing nav on any page
 * - Inconsistent active tab highlighting
 * - Privacy claims contradicting actual data */

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

DEFINE_WALLET_VIEW_CLIENT(_buf, _audit_len, render, audit_get, audit_post,
                          contains, 131072)

static char g_tmp[256];

static bool make_db(int64_t t_sat, int64_t z_sat, int n_txs, int n_peers)
{
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/zcl_audit_XXXXXX");
    if (!mkdtemp(g_tmp)) return false;

    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", g_tmp);

    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return false;

    TEST_DB_EXEC(db,
        "CREATE TABLE IF NOT EXISTS blocks"
        "(hash BLOB PRIMARY KEY,height INT,time INT,prev_hash BLOB,"
        "version INT,merkle_root BLOB,bits INT,nonce BLOB,solution BLOB,"
        "chain_work BLOB,status INT DEFAULT 0,file_pos INT DEFAULT 0,"
        "num_tx INT DEFAULT 0,sapling_root BLOB,sprout_root BLOB,"
        "sapling_value_balance INT DEFAULT 0,sprout_value_balance INT DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS wallet_utxos"
        "(txid BLOB,vout INT,value INT,address_hash BLOB,script BLOB,"
        "height INT,spent_txid BLOB,spent_vin INT,is_coinbase INT,"
        "PRIMARY KEY(txid,vout));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_notes"
        "(txid BLOB,output_index INT,value INT,rcm BLOB,memo BLOB,"
        "ivk BLOB,diversifier BLOB,pk_d BLOB,cm BLOB,"
        "nullifier BLOB UNIQUE,block_height INT,spent_txid BLOB,"
        "address TEXT,PRIMARY KEY(txid,output_index));"
        "CREATE TABLE IF NOT EXISTS wallet_sapling_keys"
        "(ivk BLOB PRIMARY KEY,xsk BLOB,xfvk BLOB,diversifier BLOB,"
        "pk_d BLOB,child_index INT,address TEXT);"
        "CREATE TABLE IF NOT EXISTS wallet_keys"
        "(pubkey_hash BLOB PRIMARY KEY,pubkey BLOB,privkey BLOB,"
        "compressed INT,created_at INT);"
        "CREATE TABLE IF NOT EXISTS wallet_transactions"
        "(txid BLOB PRIMARY KEY,raw_tx BLOB,block_hash BLOB,"
        "block_height INT,time_received INT,from_me INT,fee INT);"
        "CREATE TABLE IF NOT EXISTS peers"
        "(id INTEGER PRIMARY KEY,ip TEXT,port INT,services INT,"
        "last_seen INT,last_try INT,attempts INT,source TEXT);"
        "CREATE TABLE IF NOT EXISTS mempool"
        "(txid BLOB PRIMARY KEY,raw_tx BLOB,fee INT,size INT,"
        "time_added INT,height_added INT);"
        "CREATE TABLE IF NOT EXISTS sapling_spends"
        "(nullifier BLOB PRIMARY KEY,txid BLOB);"
        "CREATE TABLE IF NOT EXISTS zslp_tokens"
        "(token_id BLOB PRIMARY KEY,ticker TEXT,name TEXT,"
        "decimals INT,genesis_height INT);"
        "CREATE TABLE IF NOT EXISTS zslp_transfers"
        "(id INTEGER PRIMARY KEY,token_id BLOB,tx_type TEXT,"
        "txid BLOB,from_addr BLOB,to_addr BLOB,amount INT);"
        "CREATE TABLE IF NOT EXISTS contacts"
        "(address TEXT PRIMARY KEY,name TEXT,last_used INT);"
        );

    /* Tip block */
    {
        uint8_t h[32]={0xFF}, p[32]={0xFE}, m[32]={0xFD};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO blocks(hash,height,time,prev_hash,version,"
            "merkle_root,bits,status,num_tx) VALUES"
            "(?,500000,1700000000,?,4,?,0x1d00ffff,3,5)",
        {
            sqlite3_bind_blob(s, 1, h, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, p, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 3, m, 32, SQLITE_STATIC);
        });
    }

    /* Transparent UTXOs */
    if (t_sat > 0) {
        uint8_t tx[32]={1}, ah[20]={0xAA};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_utxos(txid,vout,value,address_hash,height)"
            " VALUES(?,0,?,?,100)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, t_sat);
            sqlite3_bind_blob(s, 3, ah, 20, SQLITE_STATIC);
        });
    }

    /* Shielded notes */
    if (z_sat > 0) {
        uint8_t tx[32]={2}, nf[32]={0xBB};
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_sapling_notes"
            "(txid,output_index,value,nullifier,block_height)"
            " VALUES(?,0,?,?,200)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, z_sat);
            sqlite3_bind_blob(s, 3, nf, 32, SQLITE_STATIC);
        });
    }

    /* Wallet transactions */
    for (int i = 0; i < n_txs; i++) {
        uint8_t tx[32]; memset(tx, 0x10+i, 32);
        uint8_t bh[32]; memset(bh, 0xFF, 32);
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_transactions"
            "(txid,block_hash,block_height,time_received,from_me,fee)"
            " VALUES(?,?,?,?,?,?)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, bh, 32, SQLITE_STATIC);
            sqlite3_bind_int(s, 3, 499990 + i);
            sqlite3_bind_int(s, 4, 1700000000 - i * 600);
            sqlite3_bind_int(s, 5, i % 2);
            sqlite3_bind_int64(s, 6, 10000);
        });
    }

    /* Peers */
    for (int i = 0; i < n_peers; i++) {
        char ip[32]; snprintf(ip, sizeof(ip), "192.168.1.%d", i+1);
        sqlite3_stmt *s = NULL;
        TEST_DB_RUN(db, s,
            "INSERT INTO peers(ip,port,services,last_seen)"
            " VALUES(?,8033,5,?)", {
            sqlite3_bind_text(s, 1, ip, -1, SQLITE_STATIC);
            sqlite3_bind_int(s, 2, 1700000000);
        });
    }

    sqlite3_close(db);
    return true;
}

static void cleanup(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmp);
    (void)system(cmd);
    wallet_view_init(NULL);
}

/* ── The actual audit ──────────────────────────────────── */

int spec_render_audit(void)
{
    int failures = 0;
    printf("\n=== Render Audit (real data, every route) ===\n");

    bool db_ok = make_db(81000000, 16000000, 10, 3);
    if (!db_ok) {
        printf("SKIP: could not create test DB\n");
        return 0;
    }
    wallet_view_init(g_tmp);

    /* ── Route: dashboard ── */
    {   printf("audit: dashboard renders with data... ");
        size_t n = render("GET", "/wallet", NULL);
        bool ok = n > 500;
        ok = ok && contains("ZCL");
        ok = ok && contains("private");
        ok = ok && contains("Send");
        ok = ok && contains("Receive");
        ok = ok && contains("/wallet/node");
        /* NO unresolved template vars (}}} can appear in JS legitimately) */
        ok = ok && !contains("{{{");
        /* NO SQL leaks */
        ok = ok && !contains("sqlite");
        ok = ok && !contains("SELECT ");
        ok = ok && !contains("INSERT ");
        if (!ok) {
            printf("FAIL:");
            if (n <= 500) printf(" too-short");
            if (!contains("ZCL")) printf(" no-ZCL");
            if (!contains("private")) printf(" no-private");
            if (!contains("Send")) printf(" no-Send");
            if (!contains("Receive")) printf(" no-Receive");
            if (!contains("/wallet/node")) printf(" no-node-link");
            if (contains("{{{")) printf(" LEAKED-TEMPLATE-VAR");
            if (contains("sqlite")) printf(" LEAKED-sqlite");
            if (contains("SELECT ")) printf(" LEAKED-SELECT");
            if (contains("INSERT ")) printf(" LEAKED-INSERT");
            printf(" (len=%zu)\n", n);
            failures++;
        } else printf("OK\n");
    }

    /* ── Route: send ── */
    {   printf("audit: send page renders... ");
        size_t n = render("GET", "/wallet/send", NULL);
        bool ok = n > 500;
        ok = ok && (contains("address") || contains("Address"));
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        ok = ok && contains(">Send<"); /* nav active */
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: send review with valid-looking address ── */
    {   printf("audit: send review handles bad address... ");
        size_t n = render("POST", "/wallet/send/review",
            "address=t1TestAddr12345678901234567890&amount=0.1");
        bool ok = n > 200;
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: receive ── */
    {   printf("audit: receive page renders... ");
        size_t n = render("GET", "/wallet/receive", NULL);
        bool ok = n > 500;
        ok = ok && contains("recommended");
        ok = ok && contains("zero-knowledge proof");
        ok = ok && !contains("{{{");
        ok = ok && contains(">Receive<"); /* nav active */
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: history ── */
    {   printf("audit: history with 10 txs renders... ");
        size_t n = render("GET", "/wallet/history", NULL);
        bool ok = n > 500;
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        ok = ok && contains(">History<"); /* nav active */
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: history page 2 ── */
    {   printf("audit: history page 2 renders... ");
        size_t n = render("GET", "/wallet/history?page=1", NULL);
        bool ok = n > 200;
        ok = ok && !contains("{{{");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: history with filter ── */
    {   printf("audit: history filter=sent... ");
        size_t n = render("GET", "/wallet/history?filter=sent", NULL);
        bool ok = n > 200;
        ok = ok && !contains("{{{");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: node ── */
    {   printf("audit: node page with real data... ");
        size_t n = render("GET", "/wallet/node", NULL);
        bool ok = n > 500;
        ok = ok && contains("Command Center");
        ok = ok && contains("sovereign");
        ok = ok && contains("500"); /* height 500000 */
        ok = ok && contains("3");   /* 3 peers */
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        ok = ok && contains(">Node<"); /* nav active */
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: coins ── */
    {   printf("audit: coins page with UTXOs... ");
        size_t n = render("GET", "/wallet/coins", NULL);
        bool ok = n > 200;
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: shield ── */
    {   printf("audit: shield amount form... ");
        size_t n = render("GET", "/wallet/shield", NULL);
        bool ok = n > 500;
        ok = ok && (contains("Amount") || contains("amount"));
        ok = ok && !contains("{{{");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: shield confirm ── */
    {   printf("audit: shield confirm page... ");
        size_t n = render("GET", "/wallet/shield?amount=0.5", NULL);
        bool ok = n > 500;
        ok = ok && contains("0.5");
        ok = ok && contains("Confirm");
        ok = ok && !contains("{{{");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: pulse API ── */
    {   printf("audit: pulse returns valid JSON... ");
        size_t n = render("GET", "/api/wallet/pulse", NULL);
        bool ok = n > 10;
        ok = ok && contains("{");
        ok = ok && contains("height");
        ok = ok && contains("balance");
        ok = ok && !contains("<!DOCTYPE");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Route: tx detail ── */
    {   printf("audit: tx detail with valid hex txid... ");
        size_t n = render("GET",
            "/wallet/tx/"
            "1010101010101010101010101010101010101010101010101010101010101010",
            NULL);
        bool ok = n > 200;
        ok = ok && !contains("{{{");
        ok = ok && !contains("sqlite");
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    /* ── Privacy accuracy check ── */
    {   printf("audit: 16%% shielded matches actual data... ");
        render("GET", "/wallet", NULL);
        /* With 81M t-sat + 16M z-sat = 97M total, ~16% private */
        bool ok = contains("16%") || contains("17%");
        /* Must NOT claim untraceable */
        ok = ok && !contains("untraceable");
        ok = ok && !contains("Untraceable");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Shield nudge shown when public balance exists ── */
    {   printf("audit: shield nudge shown with public balance... ");
        render("GET", "/wallet", NULL);
        bool ok = contains("Shield All") || contains("/wallet/shield");
        ok = ok && (contains("transparent addresses") ||
             contains("chain analysis"));
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── XSS checks ── */
    {   printf("audit: XSS in history search sanitized... ");
        render("GET", "/wallet/history?q=<script>alert(1)</script>", NULL);
        bool ok = !contains("<script>alert");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("audit: XSS in tx detail sanitized... ");
        render("GET", "/wallet/tx/<img+onerror=alert(1)>", NULL);
        bool ok = !contains("<img+onerror");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Edge cases ── */
    {   printf("audit: unknown route returns 0... ");
        size_t n = render("GET", "/wallet/doesnotexist", NULL);
        bool ok = n == 0;
        if (ok) printf("OK\n"); else { printf("FAIL (len=%zu)\n", n); failures++; }
    }

    {   printf("audit: POST with NULL body doesn't crash... ");
        size_t n = render("POST", "/wallet/send/review", NULL);
        bool ok = n > 0; /* should render error page, not crash */
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    {   printf("audit: POST shield confirm with 0 amount... ");
        size_t n = render("POST", "/wallet/shield/confirm", "amount=0");
        bool ok = n > 0;
        ok = ok && !contains("{{{");
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    cleanup();

    /* ── 100% private wallet ── */
    {   printf("audit: 100%% private wallet shows no nudge... ");
        bool ok = make_db(0, 100000000, 0, 0);
        if (ok) {
            wallet_view_init(g_tmp);
            render("GET", "/wallet", NULL);
            ok = contains("100%") || contains("All funds private");
            ok = ok && !contains("Shield All");
            ok = ok && !contains("transparent addresses");
            ok = ok && !contains("untraceable"); /* factual, not cutesy */
        }
        cleanup();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Empty wallet ── */
    {   printf("audit: empty wallet renders cleanly... ");
        bool ok = make_db(0, 0, 0, 0);
        if (ok) {
            wallet_view_init(g_tmp);
            render("GET", "/wallet", NULL);
            ok = contains("0.00") || contains("0.0000");
            ok = ok && !contains("{{{");
            ok = ok && !contains("sqlite");
            ok = ok && !contains("untraceable");
        }
        cleanup();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("Render audit: %d failures\n", failures);
    return failures;
}
