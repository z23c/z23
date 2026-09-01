/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused ZSLP model tests. */

#include "test/test_core.h"
#include "models/zslp.h"
#include "services/zslp_service.h"
#include <unistd.h>

int test_model_zslp(void)
{
    int failures = 0;

    printf("ZSLP balance validates token_id and address... ");
    {
        struct db_zslp_balance bal;
        struct ar_errors e;
        memset(&bal, 0, sizeof(bal));
        bal.balance = 5;
        ar_errors_clear(&e);
        db_zslp_balance_validate(&bal, &e);
        if (ar_errors_any(&e)) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ZSLP balance save normalizes token key before save... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_zslp", "balances");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_zslp_balance bal;
            struct db_zslp_balance got;
            memset(&bal, 0, sizeof(bal));
            memset(&got, 0, sizeof(got));
            snprintf(bal.token_id, sizeof(bal.token_id), "%s", "testcoin");
            snprintf(bal.address, sizeof(bal.address), "%s", "t1Buyer123");
            bal.balance = 42;
            ok = db_zslp_balance_save(&ndb, &bal);
            if (ok && strcmp(bal.token_id, "TESTCOIN") != 0) {
                ok = false;
            }
            if (ok && !db_zslp_balance_find(&ndb, "testcoin", "t1Buyer123", &got)) {
                ok = false;
            }
            if (ok && strcmp(got.token_id, "TESTCOIN") != 0) {
                ok = false;
            }
            if (ok && got.balance != 42) {
                ok = false;
            }
            if (ok && !db_zslp_balance_credit(&ndb, "testcoin", "t1Buyer123", 8)) {
                ok = false;
            }
            if (ok && !db_zslp_balance_find(&ndb, "TESTCOIN", "t1Buyer123", &got)) {
                ok = false;
            }
            if (ok && got.balance != 50) {
                ok = false;
            }
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ZSLP token model saves, finds, and lists normalized keys... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_zslp", "tokens");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_zslp_token_info token;
            struct db_zslp_token_info listed[4];
            struct ar_errors e;
            memset(&token, 0, sizeof(token));
            memset(listed, 0, sizeof(listed));
            ar_errors_clear(&e);
            ok = !db_zslp_token_validate_key("", &e) && ar_errors_any(&e);
            if (ok && !db_zslp_token_save_key(&ndb, "testcoin",
                                              "TESTCOIN", "Test Coin",
                                              2, "", 0, 1000)) {
                ok = false;
            }
            if (ok && !db_zslp_token_save_key(&ndb, "coinb",
                                              "COINB", "Coin B",
                                              0, "", 12, 500)) {
                ok = false;
            }
            if (ok && !db_zslp_token_find(&ndb, "TESTCOIN", &token)) {
                ok = false;
            }
            if (ok && strcmp(token.token_id, "TESTCOIN") != 0) {
                ok = false;
            }
            if (ok && strcmp(token.ticker, "TESTCOIN") != 0) {
                ok = false;
            }
            if (ok && token.total_minted != 1000) {
                ok = false;
            }
            if (ok && db_zslp_token_list(&ndb, listed, 4) != 2) {
                ok = false;
            }
            if (ok && strcmp(listed[0].ticker, "COINB") != 0) {
                ok = false;
            }
            if (ok && strcmp(listed[1].ticker, "TESTCOIN") != 0) {
                ok = false;
            }
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("ZSLP transfer model lists token-scoped transfers... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_zslp", "transfers");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            uint8_t txid[32];
            uint8_t token_id[32];
            uint8_t addr_hash[20];
            struct db_zslp_transfer_info listed[4];

            memset(txid, 0x11, sizeof(txid));
            memset(token_id, 0x22, sizeof(token_id));
            memset(addr_hash, 0x33, sizeof(addr_hash));
            memset(listed, 0, sizeof(listed));
            ok = db_zslp_transfer_save(&ndb, txid, 123, token_id, 2, 77, 1, addr_hash);
            if (ok && db_zslp_transfer_list_by_token(&ndb,
                    "2222222222222222222222222222222222222222222222222222222222222222",
                    listed, 4) != 1) {
                ok = false;
            }
            if (ok && strcmp(listed[0].token_id,
                    "2222222222222222222222222222222222222222222222222222222222222222") != 0) {
                ok = false;
            }
            if (ok && listed[0].block_height != 123) {
                ok = false;
            }
            if (ok && listed[0].tx_type != 2) {
                ok = false;
            }
            if (ok && listed[0].amount != 77) {
                ok = false;
            }
            if (ok && listed[0].vout != 1) {
                ok = false;
            }
            if (ok && strlen(listed[0].to_addr_hex) != 40) {
                ok = false;
            }
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── token_key validator disambiguation ─────────────────── */

    printf("validate_token_key: accepts 3-char ticker 'ZCL' (has non-hex)... ");
    {
        if (zslp_service_validate_token_key("ZCL").ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: accepts 'BTC' (T is non-hex)... ");
    {
        if (zslp_service_validate_token_key("BTC").ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: accepts 11-char 'ZCL23ACCESS' "
           "(has Z/L/S non-hex — real codebase token)... ");
    {
        /* This one is load-bearing — store_controller.c:178 seeds
         * 'ZCL23ACCESS' as a token_id for token-gated access. */
        if (zslp_service_validate_token_key("ZCL23ACCESS").ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: accepts 10-char 'ZCL23STORE'... ");
    {
        if (zslp_service_validate_token_key("ZCL23STORE").ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects 10-char all-hex "
           "(ambiguous with truncated txid)... ");
    {
        /* Pre-fix "abcdef1234" was accepted as alphanumeric; canonicalized
         * to "ABCDEF1234", indistinguishable from a truncated hex txid
         * prefix of the same shape — the exact collision. */
        if (!zslp_service_validate_token_key("abcdef1234").ok)
            printf("OK\n");
        else { printf("FAIL (collision gate missing)\n"); failures++; }
    }

    printf("validate_token_key: rejects 32-char all-hex "
           "(mid-range txid prefix)... ");
    {
        if (!zslp_service_validate_token_key(
                "abcdef0123456789abcdef0123456789").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects 63-char all-hex "
           "(just below full txid)... ");
    {
        if (!zslp_service_validate_token_key(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: accepts 64-char hex txid "
           "(canonical full-txid form)... ");
    {
        if (zslp_service_validate_token_key(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: accepts 64-char non-hex alphanumeric... ");
    {
        /* 64 chars with 'g' — alphanumeric, non-hex. Not a txid
         * (txids are hex), not ambiguous with anything — accept. */
        if (zslp_service_validate_token_key(
                "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects empty string... ");
    {
        if (!zslp_service_validate_token_key("").ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects >64 chars... ");
    {
        /* 65 chars */
        if (!zslp_service_validate_token_key(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects NULL... ");
    {
        if (!zslp_service_validate_token_key(NULL).ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("validate_token_key: rejects punctuation (non-alnum)... ");
    {
        if (!zslp_service_validate_token_key("ZCL-23").ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
