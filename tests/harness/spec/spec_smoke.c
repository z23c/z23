/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SMOKE TEST — simulate every user click against real data.
 * If any page crashes, returns 0 bytes, leaks SQL, or shows
 * unresolved templates, this test catches it.
 *
 * This is the last line of defense before the user sees it. */

#include "test/test_core.h"
#include "test/wallet_view_fixture.h"
#include "controllers/wallet_view_controller.h"
#include "controllers/wallet_view_internal.h"
#include <string.h>
#include <stdio.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <unistd.h>

DEFINE_WALLET_VIEW_CLIENT(_r, _rlen, smoke_request, DO_GET, DO_POST, HAS,
                          131072)

/* Check a rendered page for common defects */
static int check_page(const char *name, size_t min_len) {
    int bad = 0;
    if (_rlen < min_len) {
        printf("  BUG: %s too short (%zu bytes, expected >%zu)\n",
               name, _rlen, min_len);
        bad++;
    }
    if (HAS("{{{")) {
        printf("  BUG: %s has unresolved template var\n", name);
        bad++;
    }
    if (HAS("sqlite3")) {
        printf("  BUG: %s leaks sqlite3 internals\n", name);
        bad++;
    }
    if (HAS("SELECT ") || HAS("INSERT ") || HAS("DELETE ")) {
        printf("  BUG: %s leaks SQL statement\n", name);
        bad++;
    }
    if (HAS("segfault") || HAS("SIGSEGV") || HAS("core dump")) {
        printf("  BUG: %s has crash text\n", name);
        bad++;
    }
    if (HAS("Error:") && !HAS("addr-err")) {
        /* addr-err is a CSS class for validation, that's OK */
        printf("  WARN: %s contains 'Error:' text\n", name);
    }
    return bad;
}

static char g_dir[256];

static bool setup_wallet(int64_t t_sat, int64_t z_sat,
                          int n_tx, int n_peers) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/zcl_smoke_XXXXXX");
    if (!mkdtemp(g_dir)) return false;

    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", g_dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return false;

    /* Full schema */
    const char *schema =
        "CREATE TABLE blocks(hash BLOB PRIMARY KEY,height INT,time INT,"
        "prev_hash BLOB,version INT,merkle_root BLOB,bits INT,"
        "nonce BLOB,solution BLOB,chain_work BLOB,status INT DEFAULT 0,"
        "file_pos INT DEFAULT 0,num_tx INT DEFAULT 0,sapling_root BLOB,"
        "sprout_root BLOB,sapling_value_balance INT DEFAULT 0,"
        "sprout_value_balance INT DEFAULT 0);"
        "CREATE TABLE wallet_utxos(txid BLOB,vout INT,value INT,"
        "address_hash BLOB,script BLOB,height INT,spent_txid BLOB,"
        "spent_vin INT,is_coinbase INT,PRIMARY KEY(txid,vout));"
        "CREATE TABLE wallet_sapling_notes(txid BLOB,output_index INT,"
        "value INT,rcm BLOB,memo BLOB,ivk BLOB,diversifier BLOB,"
        "pk_d BLOB,cm BLOB,nullifier BLOB UNIQUE,block_height INT,"
        "spent_txid BLOB,address TEXT,PRIMARY KEY(txid,output_index));"
        "CREATE TABLE wallet_sapling_keys(ivk BLOB PRIMARY KEY,"
        "xsk BLOB,xfvk BLOB,diversifier BLOB,pk_d BLOB,"
        "child_index INT,address TEXT);"
        "CREATE TABLE wallet_keys(pubkey_hash BLOB PRIMARY KEY,"
        "pubkey BLOB,privkey BLOB,compressed INT,created_at INT);"
        "CREATE TABLE wallet_transactions(txid BLOB PRIMARY KEY,"
        "raw_tx BLOB,block_hash BLOB,block_height INT,"
        "time_received INT,from_me INT,fee INT);"
        "CREATE TABLE peers(id INTEGER PRIMARY KEY,ip TEXT,port INT,"
        "services INT,last_seen INT,last_try INT,attempts INT,source TEXT);"
        "CREATE TABLE mempool(txid BLOB PRIMARY KEY,raw_tx BLOB,"
        "fee INT,size INT,time_added INT,height_added INT);"
        "CREATE TABLE sapling_spends(nullifier BLOB PRIMARY KEY,txid BLOB);"
        "CREATE TABLE zslp_tokens(token_id BLOB PRIMARY KEY,ticker TEXT,"
        "name TEXT,decimals INT,genesis_height INT);"
        "CREATE TABLE zslp_transfers(id INTEGER PRIMARY KEY,"
        "token_id BLOB,tx_type TEXT,txid BLOB,from_addr BLOB,"
        "to_addr BLOB,amount INT);"
        "CREATE TABLE contacts(address TEXT PRIMARY KEY,name TEXT,"
        "last_used INT);";
    TEST_DB_EXEC(db, schema);

    /* Tip block */
    uint8_t h[32]={0xFF}, p[32]={0xFE}, m[32]={0xFD};
    sqlite3_stmt *s = NULL;
    TEST_DB_RUN(db, s,
        "INSERT INTO blocks(hash,height,time,prev_hash,version,"
        "merkle_root,bits,status,num_tx)"
        " VALUES(?,3041000,1711400000,?,4,?,0x1d00ffff,3,5)",
    {
        sqlite3_bind_blob(s, 1, h, 32, SQLITE_STATIC);
        sqlite3_bind_blob(s, 2, p, 32, SQLITE_STATIC);
        sqlite3_bind_blob(s, 3, m, 32, SQLITE_STATIC);
    });

    /* t-address UTXOs across multiple addresses */
    if (t_sat > 0) {
        int64_t per_addr = t_sat / 3;
        for (int i = 0; i < 3; i++) {
            int64_t val = (i < 2) ? per_addr : (t_sat - 2*per_addr);
            uint8_t tx[32]; memset(tx, 0x10+i, 32);
            uint8_t ah[20]; memset(ah, 0xA0+i, 20);
            TEST_DB_RUN(db, s,
                "INSERT INTO wallet_utxos(txid,vout,value,address_hash,"
                "height,is_coinbase) VALUES(?,0,?,?,100,0)",
            {
                sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
                sqlite3_bind_int64(s, 2, val);
                sqlite3_bind_blob(s, 3, ah, 20, SQLITE_STATIC);
            });
        }
    }

    /* Shielded notes */
    if (z_sat > 0) {
        uint8_t tx[32]={0x20}, nf[32]={0xBB};
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_sapling_notes(txid,output_index,value,"
            "nullifier,block_height) VALUES(?,0,?,?,200)",
        {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_int64(s, 2, z_sat);
            sqlite3_bind_blob(s, 3, nf, 32, SQLITE_STATIC);
        });
    }

    /* z-address for receive page */
    {
        uint8_t ivk[32]={0xCC};
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_sapling_keys(ivk,address,child_index)"
            " VALUES(?,'zs1testaddr00000000000000000000000000000000"
            "000000000000000000000000000000000000000test',0)",
        {
            sqlite3_bind_blob(s, 1, ivk, 32, SQLITE_STATIC);
        });
    }

    /* Wallet transactions */
    for (int i = 0; i < n_tx; i++) {
        uint8_t tx[32]; memset(tx, 0x30+i, 32);
        uint8_t bh[32]; memset(bh, 0xFF, 32);
        TEST_DB_RUN(db, s,
            "INSERT INTO wallet_transactions(txid,block_hash,"
            "block_height,time_received,from_me,fee)"
            " VALUES(?,?,?,?,?,10000)", {
            sqlite3_bind_blob(s, 1, tx, 32, SQLITE_STATIC);
            sqlite3_bind_blob(s, 2, bh, 32, SQLITE_STATIC);
            sqlite3_bind_int(s, 3, 3040990 + i);
            sqlite3_bind_int(s, 4, 1711400000 - i * 600);
            sqlite3_bind_int(s, 5, i % 2);
        });
    }

    /* Peers */
    for (int i = 0; i < n_peers; i++) {
        char ip[32]; snprintf(ip, sizeof(ip), "10.0.%d.%d", i/256, i%256);
        TEST_DB_RUN(db, s,
            "INSERT INTO peers(ip,port,services,last_seen)"
            " VALUES(?,8033,5,1711400000)", {
            sqlite3_bind_text(s, 1, ip, -1, SQLITE_STATIC);
        });
    }

    sqlite3_close(db);
    return true;
}

static void teardown(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    (void)system(cmd);
    wallet_view_init(NULL);
}

/* ────────────────────────────────────────────────────────── */

int spec_smoke(void)
{
    int failures = 0;
    printf("\n=== SMOKE TEST: every user flow with real data ===\n");

    /* Realistic wallet: 0.81 transparent, 0.16 shielded,
       15 transactions, 8 peers */
    if (!setup_wallet(81000000, 16000000, 15, 8)) {
        printf("SKIP: could not create test wallet\n");
        return 0;
    }
    wallet_view_init(g_dir);

    /* ── 1. User opens the app ── */
    printf("1. Dashboard loads... ");
    DO_GET("/wallet");
    failures += check_page("dashboard", 1000);
    {
        bool ok = HAS("ZCL") && HAS("Send") && HAS("Receive")
               && HAS("private") && HAS("/wallet/node");
        if (!ok) { printf("  BUG: dashboard missing core elements\n"); failures++; }
        /* Privacy must be accurate: ~16% */
        if (HAS("untraceable")) { printf("  BUG: claims untraceable at 16%%\n"); failures++; }
        if (!HAS("Shield All") && !HAS("/wallet/shield")) {
            printf("  BUG: no shield action with 84%% transparent\n"); failures++;
        }
    }
    if (failures == 0) printf("OK\n");

    /* ── 2. User clicks Send ── */
    printf("2. Send page... ");
    {   int f0 = failures;
        DO_GET("/wallet/send");
        failures += check_page("send", 1000);
        if (!HAS("address") && !HAS("Address")) {
            printf("  BUG: send has no address field\n"); failures++;
        }
        if (!HAS("active'>Send")) {
            printf("  BUG: Send tab not active\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 3. User submits bad address ── */
    printf("3. Send review (bad address)... ");
    {   int f0 = failures;
        DO_POST("/wallet/send/review", "address=xyz&amount=1.0");
        failures += check_page("send-review-bad", 200);
        if (!HAS("Invalid") && !HAS("invalid") && !HAS("too short")) {
            printf("  BUG: no validation error for bad address\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 4. User submits zero amount ── */
    printf("4. Send review (zero amount)... ");
    {   int f0 = failures;
        DO_POST("/wallet/send/review",
            "address=t1ExampleAddr123456789012345&amount=0");
        failures += check_page("send-review-zero", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 5. User submits empty form ── */
    printf("5. Send review (empty body)... ");
    {   int f0 = failures;
        DO_POST("/wallet/send/review", "");
        failures += check_page("send-review-empty", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 6. Send confirm with no body ── */
    printf("6. Send confirm (empty)... ");
    {   int f0 = failures;
        DO_POST("/wallet/send/confirm", "");
        failures += check_page("send-confirm-empty", 100);
        if (failures == f0) printf("OK\n");
    }

    /* ── 7. User clicks Receive ── */
    printf("7. Receive page... ");
    {   int f0 = failures;
        DO_GET("/wallet/receive");
        failures += check_page("receive", 500);
        if (!HAS("recommended")) {
            printf("  BUG: private not marked recommended\n"); failures++;
        }
        if (!HAS("active'>Receive") && !HAS("active-z")) {
            printf("  BUG: Receive tab or z-pane not active\n"); failures++;
        }
        if (!HAS("<svg")) {
            printf("  BUG: no QR code SVG\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 8. User clicks History ── */
    printf("8. History page... ");
    {   int f0 = failures;
        DO_GET("/wallet/history");
        failures += check_page("history", 500);
        if (!HAS("active'>History")) {
            printf("  BUG: History tab not active\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 9. History page 2 ── */
    printf("9. History page 2... ");
    {   int f0 = failures;
        DO_GET("/wallet/history?page=1");
        failures += check_page("history-p2", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 10. History with filter ── */
    printf("10. History filter=sent... ");
    {   int f0 = failures;
        DO_GET("/wallet/history?filter=sent");
        failures += check_page("history-sent", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 11. History with search ── */
    printf("11. History search... ");
    {   int f0 = failures;
        DO_GET("/wallet/history?q=abcdef");
        failures += check_page("history-search", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 12. User clicks Node ── */
    printf("12. Node page... ");
    {   int f0 = failures;
        DO_GET("/wallet/node");
        failures += check_page("node", 1000);
        if (!HAS("Command Center")) {
            printf("  BUG: missing Command Center heading\n"); failures++;
        }
        if (!HAS("sovereign")) {
            printf("  BUG: missing sovereignty statement\n"); failures++;
        }
        if (!HAS("3,041,000") && !HAS("3041000")) {
            printf("  BUG: block height not shown\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 13. Coins page ── */
    printf("13. Coins page... ");
    {   int f0 = failures;
        DO_GET("/wallet/coins");
        failures += check_page("coins", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 14. Shield form ── */
    printf("14. Shield form... ");
    {   int f0 = failures;
        DO_GET("/wallet/shield");
        failures += check_page("shield-form", 500);
        if (!HAS("Amount") && !HAS("amount")) {
            printf("  BUG: shield form has no amount field\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 15. Shield confirm ── */
    printf("15. Shield confirm (0.5 ZCL)... ");
    {   int f0 = failures;
        DO_GET("/wallet/shield?amount=0.5");
        failures += check_page("shield-confirm", 500);
        if (!HAS("0.5")) {
            printf("  BUG: amount not shown on confirm\n"); failures++;
        }
        if (!HAS("Confirm")) {
            printf("  BUG: no Confirm button\n"); failures++;
        }
        if (!HAS("Cancel")) {
            printf("  BUG: no Cancel button\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 16. Shield confirm POST (will fail RPC but shouldn't crash) ── */
    printf("16. Shield confirm POST (no zclassicd)... ");
    {   int f0 = failures;
        DO_POST("/wallet/shield/confirm", "amount=0.5");
        failures += check_page("shield-confirm-post", 200);
        /* Should show error, not crash */
        if (_rlen < 200) {
            printf("  BUG: shield POST returned too little\n"); failures++;
        }
        if (failures == f0) printf("OK\n");
    }

    /* ── 17. Tx detail (valid hex) ── */
    printf("17. Tx detail (valid txid)... ");
    {   int f0 = failures;
        DO_GET("/wallet/tx/"
            "3030303030303030303030303030303030303030"
            "303030303030303030303030303030303030303030303030");
        failures += check_page("tx-detail", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 18. Tx detail (bad txid) ── */
    printf("18. Tx detail (bad txid)... ");
    {   int f0 = failures;
        DO_GET("/wallet/tx/not-a-txid");
        failures += check_page("tx-detail-bad", 200);
        if (failures == f0) printf("OK\n");
    }

    /* ── 19. Pulse API ── */
    printf("19. Pulse API... ");
    {   int f0 = failures;
        DO_GET("/api/wallet/pulse");
        if (_rlen < 10) { printf("  BUG: pulse returned nothing\n"); failures++; }
        if (!HAS("height")) { printf("  BUG: pulse missing height\n"); failures++; }
        if (!HAS("balance")) { printf("  BUG: pulse missing balance\n"); failures++; }
        if (!HAS("peers")) { printf("  BUG: pulse missing peers\n"); failures++; }
        if (HAS("<!DOCTYPE")) { printf("  BUG: pulse returned HTML\n"); failures++; }
        if (failures == f0) printf("OK\n");
    }

    /* ── 20. Unknown route ── */
    printf("20. Unknown route... ");
    {   int f0 = failures;
        size_t n = DO_GET("/wallet/nonexistent");
        if (n != 0) { printf("  BUG: unknown route returned %zu bytes\n", n); failures++; }
        if (failures == f0) printf("OK\n");
    }

    /* ── 21. XSS in search ── */
    printf("21. XSS in search param... ");
    {   int f0 = failures;
        DO_GET("/wallet/history?q=<script>alert(1)</script>");
        if (HAS("<script>alert")) { printf("  BUG: XSS not escaped\n"); failures++; }
        if (failures == f0) printf("OK\n");
    }

    /* ── 22. XSS in txid ── */
    printf("22. XSS in txid... ");
    {   int f0 = failures;
        DO_GET("/wallet/tx/<script>alert(1)</script>");
        if (HAS("<script>alert")) { printf("  BUG: XSS not escaped\n"); failures++; }
        if (failures == f0) printf("OK\n");
    }

    teardown();

    /* ── 23. Empty wallet ── */
    printf("23. Empty wallet dashboard... ");
    {   int f0 = failures;
        setup_wallet(0, 0, 0, 0);
        wallet_view_init(g_dir);
        DO_GET("/wallet");
        failures += check_page("empty-dashboard", 500);
        if (HAS("untraceable")) {
            printf("  BUG: empty wallet claims untraceable\n"); failures++;
        }
        teardown();
        if (failures == f0) printf("OK\n");
    }

    /* ── 24. 100% shielded wallet ── */
    printf("24. 100%% shielded wallet... ");
    {   int f0 = failures;
        setup_wallet(0, 97000000, 5, 3);
        wallet_view_init(g_dir);
        DO_GET("/wallet");
        failures += check_page("shielded-dashboard", 500);
        if (HAS("Shield All")) {
            printf("  BUG: shows Shield All when 100%% shielded\n"); failures++;
        }
        if (HAS("transparent addresses")) {
            printf("  BUG: mentions transparent when none exist\n"); failures++;
        }
        teardown();
        if (failures == f0) printf("OK\n");
    }

    printf("\n=== SMOKE: %d failures ===\n", failures);
    return failures;
}
