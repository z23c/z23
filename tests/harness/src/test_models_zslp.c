/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused ZSLP model tests. */

#include "test/test_core.h"
#include "models/zslp.h"
#include "models/zslp_validity.h"
#include "services/zslp_service.h"
#include "core/uint256.h"
#include <unistd.h>


/* ── One identity, one byte order ──────────────────────────────────
 *
 * A chain token id IS its GENESIS txid, and every wallet-facing surface
 * speaks that txid's DISPLAY order: the intent service answers
 * app.tokens.create with uint256_get_hex (contexts/market/services/src/
 * zslp_transaction_intent_service.c), app.tokens.mint/send/burn parse the
 * answer back with uint256_set_hex (contexts/market/controllers/src/
 * zslp_intent_controller.c), and the store access gate keys the ledger the
 * same way (engine/controllers/src/store_access_gate.c). The projection
 * reads below must render the SAME string. When they render the stored
 * blob forward instead, an operator who pastes a listed id into mint names
 * a DIFFERENT token, and zslp_controller_render_validity — which recovers
 * the 32 bytes from this very field with uint256_set_hex — looks up the
 * mirrored key and reports validated_height=-1 with every strict column
 * dead for a token that really minted. */

static void tzslp_hex_forward(const uint8_t *bytes, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        snprintf(out + i * 2, 3, "%02x", bytes[i]);
    out[n * 2] = '\0';
}

/* Seed the two strict-overlay rows a confirmed GENESIS of 1000 units with a
 * live mint baton leaves behind, keyed the way the overlay keys them: the
 * 32 internal bytes. */
static bool tzslp_seed_strict_rows(struct node_db *ndb,
                                   const uint8_t token[32],
                                   const uint8_t txid[32], int height)
{
    char token_hex[65];
    char txid_hex[65];
    char sql[512];

    tzslp_hex_forward(token, 32, token_hex);
    tzslp_hex_forward(txid, 32, txid_hex);
    snprintf(sql, sizeof(sql),
             "INSERT INTO zslp_validity(txid,token_id,tx_type,status,reason,"
             "block_height,input_units,output_units,burned_units,"
             "minted_units,baton_vout) "
             "VALUES(x'%s',x'%s',1,1,'',%d,0,1000,0,1000,2)",
             txid_hex, token_hex, height);
    if (!node_db_exec(ndb, sql))
        return false;
    snprintf(sql, sizeof(sql),
             "INSERT INTO zslp_ledger(token_id,txid,vout,amount,address,"
             "created_height,role) VALUES(x'%s',x'%s',2,0,NULL,%d,2)",
             token_hex, txid_hex, height);
    return node_db_exec(ndb, sql);
}

/* Every projection read renders the one display-order id, and accepts it
 * back as a lookup key. Returns NULL on success, else what diverged. */
static const char *tzslp_check_display_identity(struct node_db *ndb,
                                                const uint8_t token[32],
                                                const uint8_t txid[32],
                                                const char *want,
                                                const char *want_txid)
{
    struct db_zslp_token_info found;
    struct db_zslp_token_info listed[4];
    struct db_zslp_transfer_info xfers[4];

    memset(&found, 0, sizeof(found));
    memset(listed, 0, sizeof(listed));
    memset(xfers, 0, sizeof(xfers));

    if (!db_zslp_token_find(ndb, want, &found))
        return "db_zslp_token_find rejects the id app.tokens.create answered";
    if (strcmp(found.token_id, want) != 0)
        return "db_zslp_token_find renders a different id than create answered";
    if (db_zslp_token_list(ndb, listed, 4) != 1)
        return "db_zslp_token_list did not return the one saved token";
    if (strcmp(listed[0].token_id, want) != 0)
        return "db_zslp_token_list renders a different id than create answered";
    memset(&found, 0, sizeof(found));
    if (db_zslp_asset_lookup(ndb, token, &found) != 1)
        return "db_zslp_asset_lookup did not find the chain asset";
    if (strcmp(found.token_id, want) != 0)
        return "db_zslp_asset_lookup renders a different id than create answered";
    if (db_zslp_transfer_list_by_token(ndb, want, xfers, 4) != 1)
        return "db_zslp_transfer_list_by_token rejects the created id";
    if (strcmp(xfers[0].token_id, want) != 0)
        return "a transfer row renders a different id than create answered";
    if (strcmp(xfers[0].txid, want_txid) != 0)
        return "a transfer row renders its txid in the wrong byte order";
    (void)txid;
    return NULL;
}

/* Exactly what zslp_controller_render_validity does with the rendered
 * field: recover the 32 bytes and read the strict overlay. */
static const char *tzslp_check_strict_columns(struct node_db *ndb,
                                              const char *rendered,
                                              int height)
{
    struct uint256 recovered;
    struct zslp_token_validity_summary strict;

    uint256_set_hex(&recovered, rendered);
    memset(&strict, 0, sizeof(strict));
    if (!zslp_validity_token_summary(ndb, recovered.data, &strict))
        return "zslp_validity_token_summary failed for the rendered id";
    if (strict.validated_height != height)
        return "validity render reports validated_height=-1 for a minted token";
    if (strict.total_minted != 1000 || strict.circulating_supply != 1000)
        return "validity render reports zero strict minted/circulating units";
    if (!strict.baton_active)
        return "validity render reports no mint baton for a live baton";
    return NULL;
}

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

    printf("ZSLP projection renders the id app.tokens.create answered... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        const char *why = NULL;
        bool ok;
        test_make_tmpdir(dbdir, sizeof(dbdir), "models_zslp", "display_order");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);
        if (!ok)
            why = "node_db_open failed";

        if (ok) {
            /* Deliberately NOT a palindrome: a byte-reversed rendering of
             * this id is a visibly different string. */
            struct uint256 token_u;
            struct uint256 txid_u;
            uint8_t addr_hash[20];
            char want[65];
            char want_txid[65];

            for (int i = 0; i < 32; i++) {
                token_u.data[i] = (uint8_t)(0x10 + i);
                txid_u.data[i] = (uint8_t)(0xf0 - i);
            }
            memset(addr_hash, 0x44, sizeof(addr_hash));
            /* The exact string zti_view answers for a GENESIS intent. */
            uint256_get_hex(&token_u, want);
            uint256_get_hex(&txid_u, want_txid);

            if (!db_zslp_token_save(&ndb, token_u.data, "OPPROOF",
                                    "Operator Proof Token", 0, "", 100, 1000))
                why = "db_zslp_token_save failed";
            else if (!db_zslp_transfer_save(&ndb, txid_u.data, 100,
                                            token_u.data, 1, 1000, 1,
                                            addr_hash))
                why = "db_zslp_transfer_save failed";
            else if (!tzslp_seed_strict_rows(&ndb, token_u.data, txid_u.data,
                                             100))
                why = "seeding the strict overlay rows failed";
            else if ((why = tzslp_check_display_identity(
                          &ndb, token_u.data, txid_u.data, want,
                          want_txid)) != NULL)
                ok = false;
            else if ((why = tzslp_check_strict_columns(&ndb, want, 100)) !=
                     NULL)
                ok = false;
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (!why) printf("OK\n");
        else { printf("FAIL (%s)\n", why); failures++; }
    }

    return failures;
}
