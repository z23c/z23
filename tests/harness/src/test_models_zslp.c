/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused ZSLP model tests. */

#include "test/test_core.h"
#include "models/zslp.h"
#include "models/zslp_validity.h"
#include "services/zslp_service.h"
#include "core/uint256.h"
#include <unistd.h>

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}


/* One identity, one byte order: a chain token id is its GENESIS txid, and
 * every wallet-facing surface uses the txid DISPLAY order. The projection
 * reads below must render that same string, or an id pasted into mint names
 * a different token and zslp_controller_render_validity reports
 * validated_height=-1. */

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


/* The whole contract in one case: save a chain GENESIS and its transfer
 * row, seed the strict overlay, then require every read to name the token
 * with the exact string app.tokens.create answered. */
static int tzslp_test_display_order(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    const char *why = NULL;

    test_make_tmpdir(dbdir, sizeof(dbdir), "models_zslp", "display_order");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    printf("ZSLP projection renders the id app.tokens.create answered... ");
    if (!node_db_open(&ndb, dbpath)) {
        why = "node_db_open failed";
    } else {
        /* Deliberately NOT a palindrome: a byte-reversed rendering of these
         * ids is a visibly different string. */
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
        /* The exact strings zti_view answers for a GENESIS intent. */
        uint256_get_hex(&token_u, want);
        uint256_get_hex(&txid_u, want_txid);

        if (!db_zslp_token_save(&ndb, token_u.data, "OPPROOF",
                                "Operator Proof Token", 0, "", 100, 1000))
            why = "db_zslp_token_save failed";
        else if (!db_zslp_transfer_save(&ndb, txid_u.data, 100, token_u.data,
                                        1, 1000, 1, addr_hash))
            why = "db_zslp_transfer_save failed";
        else if (!tzslp_seed_strict_rows(&ndb, token_u.data, txid_u.data, 100))
            why = "seeding the strict overlay rows failed";
        else if (!(why = tzslp_check_display_identity(&ndb, token_u.data,
                                                      want, want_txid)))
            why = tzslp_check_strict_columns(&ndb, want, 100);
        node_db_close(&ndb);
    }
    if (!fixture_rm_ok(dbdir) && !why)
        why = "fixture cleanup failed";
    if (!why) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (%s)\n", why);
    return 1;
}

/* The three db-backed cases share one open and one close. The directory is
 * always removed; the db is closed only after a successful open. */
static bool tzslp_open_model_db(struct node_db *ndb,
                                char *dbdir, size_t dbdir_n,
                                char *dbpath, size_t dbpath_n,
                                const char *tag)
{
    test_make_tmpdir(dbdir, dbdir_n, "models_zslp", tag);
    snprintf(dbpath, dbpath_n, "%s/node.db", dbdir);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, dbpath);
}

static bool tzslp_close_model_db(struct node_db *ndb, bool opened, bool ok,
                                 const char *dbdir)
{
    if (opened)
        node_db_close(ndb);
    ok &= fixture_rm_ok(dbdir);
    return ok;
}

/* Save a balance, require the normalized key, credit it, and read it back. */
static bool tzslp_balance_saved_and_credited(struct node_db *ndb)
{
    struct db_zslp_balance bal;
    struct db_zslp_balance got;
    bool ok;

    memset(&bal, 0, sizeof(bal));
    memset(&got, 0, sizeof(got));
    snprintf(bal.token_id, sizeof(bal.token_id), "%s", "testcoin");
    snprintf(bal.address, sizeof(bal.address), "%s", "t1Buyer123");
    bal.balance = 42;
    ok = db_zslp_balance_save(ndb, &bal);
    ok = ok && (strcmp(bal.token_id, "TESTCOIN") == 0);
    if (!ok)
        return ok;
    ok = db_zslp_balance_find(ndb, "testcoin", "t1Buyer123", &got);
    ok = ok && (strcmp(got.token_id, "TESTCOIN") == 0)
            && (got.balance == 42);
    if (!ok)
        return ok;
    ok = db_zslp_balance_credit(ndb, "testcoin", "t1Buyer123", 8);
    if (!ok)
        return ok;
    ok = db_zslp_balance_find(ndb, "TESTCOIN", "t1Buyer123", &got);
    ok = ok && (got.balance == 50);
    return ok;
}

/* Reject a blank key, save two tokens, then find and list them in order. */
static bool tzslp_token_saved_found_listed(struct node_db *ndb)
{
    struct db_zslp_token_info token;
    struct db_zslp_token_info listed[4];
    struct ar_errors e;
    bool ok;

    memset(&token, 0, sizeof(token));
    memset(listed, 0, sizeof(listed));
    ar_errors_clear(&e);
    ok = !db_zslp_token_validate_key("", &e) && ar_errors_any(&e);
    if (!ok)
        return ok;
    ok = db_zslp_token_save_key(ndb, "testcoin",
                                "TESTCOIN", "Test Coin",
                                2, "", 0, 1000);
    ok = ok && db_zslp_token_save_key(ndb, "coinb",
                                      "COINB", "Coin B",
                                      0, "", 12, 500);
    if (!ok)
        return ok;
    ok = db_zslp_token_find(ndb, "TESTCOIN", &token);
    ok = ok && (strcmp(token.token_id, "TESTCOIN") == 0)
            && (strcmp(token.ticker, "TESTCOIN") == 0)
            && (token.total_minted == 1000);
    if (!ok)
        return ok;
    return (db_zslp_token_list(ndb, listed, 4) == 2)
        && (strcmp(listed[0].ticker, "COINB") == 0)
        && (strcmp(listed[1].ticker, "TESTCOIN") == 0);
}

/* One transfer row, listed back by the display-order token id. */
static bool tzslp_transfer_listed(struct node_db *ndb)
{
    uint8_t txid[32];
    uint8_t token_id[32];
    uint8_t addr_hash[20];
    struct db_zslp_transfer_info listed[4];
    bool ok;

    memset(txid, 0x11, sizeof(txid));
    memset(token_id, 0x22, sizeof(token_id));
    memset(addr_hash, 0x33, sizeof(addr_hash));
    memset(listed, 0, sizeof(listed));
    ok = db_zslp_transfer_save(ndb, txid, 123, token_id, 2, 77, 1,
                               addr_hash);
    if (!ok)
        return ok;
    return (db_zslp_transfer_list_by_token(
                ndb,
                "2222222222222222222222222222222222222222222222222222222222222222",
                listed, 4) == 1)
        && (strcmp(listed[0].token_id,
                   "2222222222222222222222222222222222222222222222222222222222222222") == 0)
        && (listed[0].block_height == 123)
        && (listed[0].tx_type == 2)
        && (listed[0].amount == 77)
        && (listed[0].vout == 1)
        && (strlen(listed[0].to_addr_hex) == 40);
}

static bool tzslp_model_db_case_ok(const char *tag,
                                   bool (*exercise)(struct node_db *ndb))
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool opened;
    bool ok;

    opened = tzslp_open_model_db(&ndb, dbdir, sizeof(dbdir),
                                 dbpath, sizeof(dbpath), tag);
    ok = opened;
    if (ok)
        ok = exercise(&ndb);
    return tzslp_close_model_db(&ndb, opened, ok, dbdir);
}

/* banner, key, want_ok, collision_fail. want_ok 1 accepts .ok; 0 accepts
 * !.ok. collision_fail selects the one distinct failure line. */
struct tzslp_key_row {
    const char *banner;
    const char *key;
    int want_ok;
    int collision_fail;
};

static const struct tzslp_key_row tzslp_key_rows[] = {
    {
        .banner = "validate_token_key: accepts 3-char ticker 'ZCL' (has non-hex)... ",
        .key = "ZCL",
        .want_ok = 1,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: accepts 'BTC' (T is non-hex)... ",
        .key = "BTC",
        .want_ok = 1,
        .collision_fail = 0
    },
    /* store_controller seeds "ZCL23ACCESS" as a token_id for token-gated access. */
    {
        .banner = "validate_token_key: accepts 11-char 'ZCL23ACCESS' "
                  "(has Z/L/S non-hex — real codebase token)... ",
        .key = "ZCL23ACCESS",
        .want_ok = 1,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: accepts 10-char 'ZCL23STORE'... ",
        .key = "ZCL23STORE",
        .want_ok = 1,
        .collision_fail = 0
    },
    /* Hex-shaped ids that are not full txids are rejected: they would collide with a truncated txid prefix. */
    {
        .banner = "validate_token_key: rejects 10-char all-hex "
                  "(ambiguous with truncated txid)... ",
        .key = "abcdef1234",
        .want_ok = 0,
        .collision_fail = 1
    },
    {
        .banner = "validate_token_key: rejects 32-char all-hex "
                  "(mid-range txid prefix)... ",
        .key = "abcdef0123456789abcdef0123456789",
        .want_ok = 0,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: rejects 63-char all-hex "
                  "(just below full txid)... ",
        .key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678",
        .want_ok = 0,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: accepts 64-char hex txid "
                  "(canonical full-txid form)... ",
        .key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .want_ok = 1,
        .collision_fail = 0
    },
    /* 64 chars with 'g' — alphanumeric, non-hex. Not a txid
     * (txids are hex), not ambiguous with anything — accept. */
    {
        .banner = "validate_token_key: accepts 64-char non-hex alphanumeric... ",
        .key = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        .want_ok = 1,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: rejects empty string... ",
        .key = "",
        .want_ok = 0,
        .collision_fail = 0
    },
    /* 65 chars */
    {
        .banner = "validate_token_key: rejects >64 chars... ",
        .key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890",
        .want_ok = 0,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: rejects NULL... ",
        .key = NULL,
        .want_ok = 0,
        .collision_fail = 0
    },
    {
        .banner = "validate_token_key: rejects punctuation (non-alnum)... ",
        .key = "ZCL-23",
        .want_ok = 0,
        .collision_fail = 0
    }
};

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
    if (tzslp_model_db_case_ok("balances",
                               tzslp_balance_saved_and_credited))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ZSLP token model saves, finds, and lists normalized keys... ");
    if (tzslp_model_db_case_ok("tokens", tzslp_token_saved_found_listed))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("ZSLP transfer model lists token-scoped transfers... ");
    if (tzslp_model_db_case_ok("transfers", tzslp_transfer_listed))
        printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    /* ── token_key validator disambiguation ─────────────────── */
    for (size_t i = 0;
         i < sizeof(tzslp_key_rows) / sizeof(tzslp_key_rows[0]); i++) {
        const struct tzslp_key_row *row = &tzslp_key_rows[i];
        int raw;
        int passed;

        printf("%s", row->banner);
        raw = zslp_service_validate_token_key(row->key).ok;
        passed = row->want_ok ? raw : !raw;
        if (passed)
            printf("OK\n");
        else if (row->collision_fail) {
            printf("FAIL (collision gate missing)\n");
            failures++;
        } else {
            printf("FAIL\n");
            failures++;
        }
    }

    failures += tzslp_test_display_order();

    return failures;
}
