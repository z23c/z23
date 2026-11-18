/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZSLP ledger holder balances are exact, and saturate instead of failing.
 *
 * Each row of zslp_ledger is a valid SLP quantity (0..2^63-1), but one holder
 * can own several: three MINTs of 2^63-1 to one address are three valid
 * unspent rows. The balance reads used SQLite SUM(), which raises "integer
 * overflow" for integers and was answered as 0 by the query helpers, so the
 * largest holder read as holding nothing and one such address emptied
 * zslp_ledger_wallet_tokens() for every token the wallet owns.
 *
 * This test asserts: sums that fit are exact (including across the 2^32
 * carry), sums that do not fit read INT64_MAX, one overflowing token does not
 * hide the wallet's other tokens, and the as-of-height and wallet-wide reads
 * agree with the per-address read. node.db in memory only. */

#include "test/test_core.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SAT_CHECK(label, cond) do { \
    printf("zslp_ledger_saturation: %s... ", (label)); \
    if (cond) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static void sat_row(struct node_db *ndb, uint8_t token, uint8_t txbyte,
                    int64_t amount, const uint8_t addr[20], int height)
{
    uint8_t tok[32], txid[32];
    memset(tok, token, 32);
    memset(txid, txbyte, 32);
    if (!zslp_ledger_record_valid_output(ndb, tok, txid, 1, amount, addr,
                                         height, ZSLP_LEDGER_TOKEN))
        printf("zslp_ledger_saturation: fixture row insert failed\n");
}

static void sat_wallet_key(struct node_db *ndb, const uint8_t hash160[20])
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO wallet_keys"
        "(pubkey_hash,pubkey,privkey,compressed,created_at)"
        " VALUES(?,zeroblob(33),zeroblob(32),1,0)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, hash160, 20, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

int test_zslp_ledger_saturation(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zslp_ledger_saturation: open node.db... FAIL\n");
        return 1;
    }

    uint8_t big[20], small[20], mid[20];
    memset(big, 0xB1, 20);
    memset(small, 0xB2, 20);
    memset(mid, 0xB3, 20);
    uint8_t tokBig[32], tokSmall[32], tokMid[32];
    memset(tokBig, 0x71, 32);
    memset(tokSmall, 0x72, 32);
    memset(tokMid, 0x73, 32);

    /* token 0x71: three mints of 2^63-1 to one address (the reported case). */
    sat_row(&ndb, 0x71, 0x01, INT64_MAX, big, 10);
    sat_row(&ndb, 0x71, 0x02, INT64_MAX, big, 11);
    sat_row(&ndb, 0x71, 0x03, INT64_MAX, big, 12);
    /* token 0x72: an ordinary holding for the same wallet. */
    sat_row(&ndb, 0x72, 0x04, 600, big, 10);
    sat_row(&ndb, 0x72, 0x05, 400, big, 11);
    /* token 0x73: sums that fit but cross the 2^32 carry and 2^62. */
    sat_row(&ndb, 0x73, 0x06, 0xFFFFFFFFLL, mid, 10);
    sat_row(&ndb, 0x73, 0x07, 0xFFFFFFFFLL, mid, 11);
    sat_row(&ndb, 0x73, 0x08, 0xFFFFFFFFLL, mid, 12);
    sat_row(&ndb, 0x73, 0x09, (int64_t)1 << 40, small, 10);
    sat_row(&ndb, 0x73, 0x0A, ((int64_t)1 << 40) + 7, small, 11);
    sat_wallet_key(&ndb, big);

    SAT_CHECK("three 2^63-1 rows read INT64_MAX, not 0",
              zslp_ledger_balance(&ndb, tokBig, big) == INT64_MAX);
    SAT_CHECK("an ordinary sum is exact",
              zslp_ledger_balance(&ndb, tokSmall, big) == 1000);
    SAT_CHECK("a sum crossing the 2^32 carry is exact",
              zslp_ledger_balance(&ndb, tokMid, mid) == 3 * 0xFFFFFFFFLL);
    SAT_CHECK("a sum of two 2^40-scale rows is exact",
              zslp_ledger_balance(&ndb, tokMid, small) ==
                  2 * ((int64_t)1 << 40) + 7);
    SAT_CHECK("an address with no rows reads 0",
              zslp_ledger_balance(&ndb, tokBig, small) == 0);

    SAT_CHECK("as-of height below every row reads 0",
              zslp_ledger_balance_at_height(&ndb, tokBig, big, 9) == 0);
    SAT_CHECK("as-of height with one row reads that row exactly",
              zslp_ledger_balance_at_height(&ndb, tokBig, big, 10) ==
                  INT64_MAX);
    SAT_CHECK("as-of height with two rows saturates",
              zslp_ledger_balance_at_height(&ndb, tokBig, big, 11) ==
                  INT64_MAX);
    SAT_CHECK("as-of height sum crossing the carry is exact",
              zslp_ledger_balance_at_height(&ndb, tokMid, mid, 11) ==
                  2 * 0xFFFFFFFFLL);

    SAT_CHECK("wallet-wide balance saturates",
              zslp_ledger_wallet_balance(&ndb, tokBig) == INT64_MAX);
    SAT_CHECK("wallet-wide balance as of a height is exact below saturation",
              zslp_ledger_wallet_balance_at_height(&ndb, tokSmall, 10) == 600);
    SAT_CHECK("wallet-wide balance as of a height saturates",
              zslp_ledger_wallet_balance_at_height(&ndb, tokBig, 12) ==
                  INT64_MAX);

    /* The sweep: the overflowing token must not hide the ordinary one. */
    struct zslp_wallet_token held[8];
    int n = zslp_ledger_wallet_tokens(&ndb, held, 8);
    SAT_CHECK("wallet sweep lists both tokens despite the overflowing one",
              n == 2);
    bool sat_ok = false, ord_ok = false;
    for (int i = 0; i < n; i++) {
        if (memcmp(held[i].token_id, tokBig, 32) == 0)
            sat_ok = held[i].balance == INT64_MAX && held[i].utxo_count == 3;
        if (memcmp(held[i].token_id, tokSmall, 32) == 0)
            ord_ok = held[i].balance == 1000 && held[i].utxo_count == 2;
    }
    SAT_CHECK("sweep: overflowing token saturates with its row count", sat_ok);
    SAT_CHECK("sweep: ordinary token stays exact", ord_ok);

    node_db_close(&ndb);
    return failures;
}
