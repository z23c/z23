/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_coins_view_kv — the coins_kv-backed coins_view reconstructs
 * `struct coins` correctly from coins_kv rows.
 *
 * This is the test of record for the PRODUCTION read view (the live
 * coins_tip cache backing; the event-log-fed UTXO projection was deleted in
 * Program H1). It seeds coins_kv (coins_kv_add / coins_kv_spend on an in-mem
 * progress.kv) and reconstructs through the coins_kv-backed view:
 *   1. reconstruct — a multi-output txid (one output spent) yields a
 *      struct coins with the right num_vout, the spent vout nulled, the
 *      live vouts' value/script intact, version==1, height/is_coinbase
 *      preserved.
 *   2. have/absent — have_coins is true for a live txid, false once all its
 *      outputs are spent and false for an unknown txid.
 *   3. best_block — returns false + null (coins_kv tracks no best-block;
 *      the tip_finalize cursor is the definitional tip). */

#include "test/test_core.h"

#include "coins/coins.h"
#include "coins/coins_view.h"
#include "core/uint256.h"
#include "storage/coins_kv.h"
#include "storage/coins_view_kv.h"
#include "storage/progress_store.h"

#include <stdio.h>
#include <string.h>

#define CKV_CHECK(name, expr) do { \
    if (!(expr)) { printf("  FAIL: %s\n", name); failures++; } \
} while (0)

static void make_txid(uint8_t txid[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)(seed + i);
}

static bool kv_add(sqlite3 *db, uint8_t seed, uint32_t vout, int64_t value,
                   int32_t height, bool coinbase, uint32_t script_len)
{
    uint8_t txid[32]; make_txid(txid, seed);
    uint8_t script[64];
    for (uint32_t k = 0; k < script_len && k < sizeof(script); k++)
        script[k] = (uint8_t)((seed * 11 + k) & 0xFF);
    return coins_kv_add(db, txid, vout, value, height, coinbase,
                        script_len ? script : NULL, script_len);
}

static bool kv_spend(sqlite3 *db, uint8_t seed, uint32_t vout)
{
    uint8_t txid[32]; make_txid(txid, seed);
    return coins_kv_spend(db, txid, vout);
}

int test_coins_view_kv(void);
int test_coins_view_kv(void)
{
    int failures = 0;
    printf("test_coins_view_kv: coins_kv-backed coins_view\n");

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "coins_view_kv", "main");

    CKV_CHECK("progress_store opens", progress_store_open(dir));
    sqlite3 *db = progress_store_db();
    CKV_CHECK("db handle", db != NULL);
    CKV_CHECK("ensure_schema", coins_kv_ensure_schema(db));

    /* txid T (seed 0x70): coinbase tx, 3 outputs; vout 1 later spent. */
    CKV_CHECK("add T:0", kv_add(db, 0x70, 0, 5000000000LL, 250, true, 25));
    CKV_CHECK("add T:1", kv_add(db, 0x70, 1, 1500, 250, true, 10));
    CKV_CHECK("add T:2", kv_add(db, 0x70, 2, 2500, 250, true, 33));
    /* An unrelated txid U (seed 0x90): single output, will be fully spent. */
    CKV_CHECK("add U:0", kv_add(db, 0x90, 0, 777, 251, false, 5));
    CKV_CHECK("spend T:1", kv_spend(db, 0x70, 1));
    CKV_CHECK("spend U:0", kv_spend(db, 0x90, 0));

    struct coins_view_kv ckv;
    CKV_CHECK("init adapter", coins_view_kv_init(&ckv));

    /* 1. reconstruct T */
    uint8_t tT[32]; make_txid(tT, 0x70);
    struct uint256 T; memcpy(T.data, tT, 32);
    struct coins c;
    bool got = coins_view_get_coins(&ckv.view, &T, &c);
    CKV_CHECK("T get_coins true", got);
    if (got) {
        CKV_CHECK("T num_vout==3", c.num_vout == 3);
        CKV_CHECK("T version==1", c.version == 1);
        CKV_CHECK("T height==250", c.height == 250);
        CKV_CHECK("T is_coinbase", c.is_coinbase == true);
        if (c.num_vout == 3) {
            CKV_CHECK("T vout0 value", c.vout[0].value == 5000000000LL);
            CKV_CHECK("T vout0 script_len", c.vout[0].script_pub_key.size == 25);
            CKV_CHECK("T vout1 spent (null)", tx_out_is_null(&c.vout[1]));
            CKV_CHECK("T vout2 value", c.vout[2].value == 2500);
            CKV_CHECK("T vout2 script_len", c.vout[2].script_pub_key.size == 33);
            bool s0ok = true;
            for (uint32_t k = 0; k < 25; k++)
                if (c.vout[0].script_pub_key.data[k] !=
                    (uint8_t)((0x70 * 11 + k) & 0xFF)) { s0ok = false; break; }
            CKV_CHECK("T vout0 script bytes", s0ok);
        }
        coins_free(&c);
    }

    /* 2. have / absent */
    CKV_CHECK("have T (live)", coins_view_have_coins(&ckv.view, &T));

    uint8_t tU[32]; make_txid(tU, 0x90);
    struct uint256 U; memcpy(U.data, tU, 32);
    CKV_CHECK("U absent (all spent)", !coins_view_have_coins(&ckv.view, &U));
    struct coins cu;
    CKV_CHECK("U get_coins false", !coins_view_get_coins(&ckv.view, &U, &cu));
    CKV_CHECK("U coins_init'd (num_vout==0)", cu.num_vout == 0);

    uint8_t tX[32]; make_txid(tX, 0x12);
    struct uint256 X; memcpy(X.data, tX, 32);
    CKV_CHECK("unknown txid absent", !coins_view_have_coins(&ckv.view, &X));

    /* 3. best_block — coins_kv names no tip, returns false + null. */
    struct uint256 bb; memset(bb.data, 0xAB, 32);
    CKV_CHECK("get_best_block false", !coins_view_get_best_block(&ckv.view, &bb));
    bool bb_null = true;
    for (int i = 0; i < 32; i++) if (bb.data[i] != 0) { bb_null = false; break; }
    CKV_CHECK("get_best_block nulled hash", bb_null);

    progress_store_close();
    test_cleanup_tmpdir(dir);
    if (failures == 0)
        printf("  all coins_view_kv checks passed\n");
    return failures;
}
