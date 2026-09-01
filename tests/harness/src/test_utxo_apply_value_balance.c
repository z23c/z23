/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_utxo_apply_value_balance - focused regression for the per-transaction
 * no-inflation check in utxo_apply_compute_block_delta.
 *
 * WHY THIS TEST EXISTS
 * --------------------
 * compute_block_delta's per-tx money rule is the ONLY no-inflation guard on
 * the reducer path a connected block takes (connect_block.c's
 * value_in<value_out check has no production caller). The prior check was
 * transparent-only (tx_output_value > tx_input_value) and therefore
 * false-rejected a legitimate shielded->transparent UNSHIELD: a tx whose
 * transparent outputs exceed its transparent inputs because the shielded pool
 * (value_balance > 0, or a JoinSplit vpub_new) funds the difference. That
 * false rejection froze the live node at height 3,138,977.
 *
 * The fix is the full Zcash money rule:
 *   value_in  = transparent_in + max(0, value_balance) + Σ vpub_new
 *   value_out = transparent_out + max(0,-value_balance) + Σ vpub_old
 *   reject (status "value_overflow") iff !coinbase && value_in < value_out.
 *
 * This test calls compute_block_delta DIRECTLY with hand-built blocks and a
 * trivial in-test lookup, and asserts:
 *   (a) UNSHIELD via value_balance PASSES  (transparent_out > transparent_in,
 *       value_balance = +D funds the gap)            -> out.ok == true
 *   (b) the SAME shape with value_balance = 0 (no shielded funding) is real
 *       inflation and FAILS                          -> out.ok == false,
 *                                                       status "value_overflow"
 *   (c) UNSHIELD via a JoinSplit vpub_new = D PASSES -> out.ok == true
 *
 * Only the per-tx money check is under test; the block is a bare {coinbase,
 * spend} pair (compute_block_delta reads only vtx values + the lookup; it does
 * not touch the header), and the spent input coin is supplied by the lookup.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "jobs/stage_helpers.h"
#include "jobs/utxo_apply_delta.h"
#include "jobs/utxo_apply_stage.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include "util/stage.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UAVB_CHECK(name, expr) do {                  \
    printf("utxo_apply_value_balance: %s... ", (name));\
    if ((expr)) printf("OK\n");                       \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

/* The single external input coin every spend tx consumes. The lookup below
 * returns it for the matching outpoint and "not found" for anything else. */
struct uavb_coin {
    struct uint256 txid;
    uint32_t vout;
    int64_t value;
    bool is_coinbase;            /* drives the coinbase-protection rule (case f/g) */
};

static bool uavb_lookup(const struct uint256 *txid, uint32_t vout,
                        struct utxo_apply_lookup *out, void *user)
{
    const struct uavb_coin *c = user;
    memset(out, 0, sizeof(*out));
    if (c && c->vout == vout && uint256_eq(&c->txid, txid)) {
        out->found = true;
        out->value = c->value;
        out->height = 0;
        out->is_coinbase = c->is_coinbase;
        out->script_len = 0;     /* no restore script needed for this test */
    }
    return true; /* lookup itself never errors */
}

/* Coinbase vtx[0]: compute_block_delta skips the money check for it, so its
 * value is irrelevant to the rule under test. Distinct hash per `tag`. */
static void uavb_make_coinbase(struct transaction *tx, uint8_t tag)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vout[0].value = 1000000000LL;
    uint8_t pk[3] = { 0x76, 0xa9, tag };
    script_set(&tx->vout[0].script_pub_key, pk, 3);
    uint256_set_null(&tx->hash);
    tx->hash.data[0] = 0xC0;
    tx->hash.data[1] = tag;
}

/* A non-coinbase tx spending `coin` (transparent_in = coin->value) and
 * creating ONE transparent output of `tout` (transparent_out = tout). With
 * tout > coin->value the tx is transparent-inflationary; the shielded funding
 * (value_balance / joinsplit) decides whether the money rule accepts it. */
static void uavb_make_spend(struct transaction *tx, uint8_t tag,
                            const struct uavb_coin *coin, int64_t tout)
{
    transaction_init(tx);
    (void)transaction_alloc(tx, 1, 1);
    tx->vin[0].prevout.hash = coin->txid;
    tx->vin[0].prevout.n = coin->vout;
    tx->vout[0].value = tout;
    uint8_t pk[4] = { 0x76, 0xa9, 0xBB, tag };
    script_set(&tx->vout[0].script_pub_key, pk, 4);
    uint256_set_null(&tx->hash);
    tx->hash.data[0] = 0x5E;
    tx->hash.data[1] = tag;
}

/* Build a {coinbase, spend} block. The caller fills the shielded fields of
 * vtx[1] (value_balance and/or joinsplit) after this returns. */
static bool uavb_build_block(struct block *b, uint8_t tag,
                             const struct uavb_coin *coin, int64_t tout)
{
    block_init(b);
    b->num_vtx = 2;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction), "uavb_vtx");
    if (!b->vtx) return false;
    uavb_make_coinbase(&b->vtx[0], tag);
    uavb_make_spend(&b->vtx[1], tag, coin, tout);
    return true;
}

/* Build {coinbase, tx1, tx2}, where tx2 spends tx1's transparent output in
 * the same block. This exercises compute_block_delta's intra-block prevout
 * resolver directly. */
static bool uavb_build_intra_spend_block(struct block *b, uint8_t tag,
                                         const struct uavb_coin *coin)
{
    block_init(b);
    b->num_vtx = 3;
    b->vtx = zcl_calloc(b->num_vtx, sizeof(struct transaction),
                        "uavb_vtx_intra");
    if (!b->vtx) return false;
    int64_t mid = coin->value - 1000;
    int64_t final = coin->value - 2000;
    uavb_make_coinbase(&b->vtx[0], tag);
    uavb_make_spend(&b->vtx[1], (uint8_t)(tag + 1), coin, mid);
    uavb_make_spend(&b->vtx[2], (uint8_t)(tag + 2), coin, final);
    b->vtx[2].vin[0].prevout.hash = b->vtx[1].hash;
    b->vtx[2].vin[0].prevout.n = 0;
    return true;
}

/* Attach one JoinSplit with vpub_new = D to vtx[1] (Sprout->transparent
 * unshield). transaction_free() frees v_joinsplit via plain free(), so a
 * zcl_calloc'd array is released correctly at block_free. */
static bool uavb_add_joinsplit(struct transaction *tx, int64_t vpub_new)
{
    tx->v_joinsplit =
        zcl_calloc(1, sizeof(struct js_description), "uavb_js");
    if (!tx->v_joinsplit) return false;
    tx->num_joinsplit = 1;
    tx->v_joinsplit[0].vpub_old = 0;
    tx->v_joinsplit[0].vpub_new = vpub_new;
    return true;
}

static bool uavb_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK)
        printf("uavb SQL failed: %s\n", err ? err : "(no message)");
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static bool uavb_set_cursor_and_frontier(sqlite3 *db, int cursor)
{
    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
        "VALUES('utxo_apply',?,1)",
        -1, &st, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_int(st, 1, cursor);
        ok = sqlite3_step(st) == SQLITE_DONE;
    }
    sqlite3_finalize(st);
    if (ok)
        ok = coins_kv_set_applied_height_in_tx(db, cursor);
    if (!ok) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }
    return true;
}

static bool uavb_put_utxo_log(sqlite3 *db, int height, const char *status,
                              int ok)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
        "VALUES(?,?,?)",
        -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok);
    bool done = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return done;
}

static bool uavb_row_exists(sqlite3 *db, const char *table, int height)
{
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT 1 FROM %s WHERE height=?", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool found = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return found;
}

static bool uavb_seed_future_delta(sqlite3 *db, int height,
                                   const struct uint256 *txid,
                                   const struct uint256 *branch_hash)
{
    if (!coins_kv_add(db, txid->data, 0, 777, height, false, NULL, 0))
        return false;
    struct delta_entry added;
    memset(&added, 0, sizeof(added));
    added.txid = *txid;
    added.vout = 0;
    added.value = 777;

    struct delta_summary s;
    memset(&s, 0, sizeof(s));
    s.ok = true;
    s.status = "verified";
    s.added = &added;
    s.added_count = 1;
    return utxo_apply_delta_persist(db, height, branch_hash, &s);
}

static int uavb_repair_fixture_open(char dir[256], const char *tag,
                                    const struct uavb_coin *coin)
{
    test_make_tmpdir(dir, 256, "utxo_apply_value_overflow_repair", tag);
    if (!progress_store_open(dir))
        return 1;
    sqlite3 *db = progress_store_db();
    if (!stage_table_ensure(db) ||
        !coins_kv_ensure_schema(db) ||
        !utxo_apply_ensure_delta_schema(db) ||
        !uavb_exec(db, "CREATE TABLE IF NOT EXISTS utxo_apply_log("
                       "height INTEGER PRIMARY KEY,"
                       "status TEXT,"
                       "ok INTEGER NOT NULL)"))
        return 2;
    if (!coins_kv_add(db, coin->txid.data, coin->vout, coin->value, 0,
                      false, NULL, 0))
        return 3;
    return 0;
}

static void uavb_repair_fixture_close(char dir[256])
{
    progress_store_close();
    test_cleanup_tmpdir(dir);
}

/* No-op step for a throwaway stage_t handle: utxo_apply_reorg_unwind_if_needed
 * uses its stage argument only as a non-NULL guard (the cursor comes from the
 * DB), so the handle is never stepped. */
static job_result_t uavb_noop_step(struct stage_step_ctx *c)
{
    (void)c;
    return JOB_IDLE;
}

int test_utxo_apply_value_balance(void);
int test_utxo_apply_value_balance(void)
{
    printf("\n=== utxo_apply value-balance money-rule test ===\n");
    int failures = 0;

    /* The input coin every spend consumes: 500,000,000 zat at vout 0. */
    struct uavb_coin coin;
    memset(&coin, 0, sizeof(coin));
    coin.txid.data[0] = 0xE7;
    coin.txid.data[1] = 0x0A;
    coin.vout = 0;
    coin.value = 500000000LL;

    const int64_t D = 1000LL;                 /* unshield amount */
    const int64_t tout = coin.value + D;      /* transparent_out > in by D */

    /* (a) UNSHIELD via value_balance PASSES.
     * transparent_in = coin.value, transparent_out = coin.value + D,
     * value_balance = +D funds the gap => value_in == value_out => accept. */
    {
        struct block b;
        bool built = uavb_build_block(&b, 0xA1, &coin, tout);
        UAVB_CHECK("(a) unshield block builds", built);
        if (built) {
            b.vtx[1].value_balance = +D;      /* shielded pool funds the +D */

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            UAVB_CHECK("(a) unshield with value_balance=+D PASSES (out.ok)",
                       out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (b) INFLATION FAILS.
     * Same shape, value_balance = 0: transparent_out exceeds transparent_in
     * by D with NO shielded funding => value_in < value_out => reject with
     * status "value_overflow". */
    {
        struct block b;
        bool built = uavb_build_block(&b, 0xB2, &coin, tout);
        UAVB_CHECK("(b) inflation block builds", built);
        if (built) {
            b.vtx[1].value_balance = 0;       /* no shielded funding */

            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            UAVB_CHECK("(b) inflation with value_balance=0 FAILS (!out.ok)",
                       out.ok == false);
            UAVB_CHECK("(b) inflation status is value_overflow",
                       out.status != NULL &&
                       strcmp(out.status, "value_overflow") == 0);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (c) UNSHIELD via JoinSplit vpub_new PASSES.
     * Same transparent shape (transparent_out exceeds in by D), funded by a
     * single JoinSplit with vpub_new = D (value FROM the Sprout pool) and
     * value_balance = 0 => value_in == value_out => accept. */
    {
        struct block b;
        bool built = uavb_build_block(&b, 0xC3, &coin, tout);
        UAVB_CHECK("(c) joinsplit block builds", built);
        if (built) {
            b.vtx[1].value_balance = 0;
            bool js = uavb_add_joinsplit(&b.vtx[1], D);
            UAVB_CHECK("(c) joinsplit attaches", js);
            if (js) {
                struct delta_summary out;
                utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
                UAVB_CHECK("(c) unshield with joinsplit vpub_new=D PASSES "
                           "(out.ok)", out.ok == true);
                free_delta(&out);
            }
        }
        block_free(&b);
    }

    /* (c2) INTRA-BLOCK create-then-spend PASSES. tx2 spends tx1's output
     * before that output exists in the durable UTXO set, so the fold must
     * resolve it from the current block's added-output index. */
    {
        struct block b;
        bool built = uavb_build_intra_spend_block(&b, 0xC6, &coin);
        UAVB_CHECK("(c2) intra-block spend block builds", built);
        if (built) {
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            int64_t mid = coin.value - 1000;
            UAVB_CHECK("(c2) intra-block spend PASSES (out.ok)",
                       out.ok == true);
            UAVB_CHECK("(c2) records all created outputs",
                       out.added_count == 3);
            UAVB_CHECK("(c2) records external + intra spends",
                       out.spent_count == 2);
            UAVB_CHECK("(c2) second spend uses tx1 output preimage",
                       out.spent_count == 2 &&
                       uint256_eq(&out.spent[1].txid, &b.vtx[1].hash) &&
                       out.spent[1].vout == 0 &&
                       out.spent[1].value == mid &&
                       out.spent[1].height == 1 &&
                       out.spent[1].script_len ==
                           b.vtx[1].vout[0].script_pub_key.size &&
                       memcmp(out.spent[1].script,
                              b.vtx[1].vout[0].script_pub_key.data,
                              out.spent[1].script_len) == 0);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (d) STALE value_overflow REPAIR.
     * Seed a false value_overflow row at H=1 below cursor=3 and a future h=2
     * inverse delta. The current binary dry-runs H successfully, so the one-shot
     * rewinds cursor/frontier to H, deletes rows [H..cursor), and inverts h=2. */
    {
        char dir[256];
        UAVB_CHECK("(d) repair fixture opens",
                   uavb_repair_fixture_open(dir, "ok", &coin) == 0);
        sqlite3 *db = progress_store_db();
        struct block b;
        bool built = uavb_build_block(&b, 0xD4, &coin, coin.value);
        UAVB_CHECK("(d) repair block builds", built);
        if (built) {
            struct uint256 block_hash;
            struct uint256 future_txid;
            struct uint256 future_hash;
            block_get_hash(&b, &block_hash);
            uint256_set_null(&future_txid);
            future_txid.data[0] = 0xF2;
            uint256_set_null(&future_hash);
            future_hash.data[0] = 0xA2;

            bool seeded =
                uavb_put_utxo_log(db, 1, "value_overflow", 0) &&
                uavb_put_utxo_log(db, 2, "verified", 1) &&
                uavb_seed_future_delta(db, 2, &future_txid, &future_hash) &&
                uavb_set_cursor_and_frontier(db, 3);
            UAVB_CHECK("(d) repair stale rows seeded", seeded);

            setenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK", "1", 1);
            struct utxo_apply_value_overflow_repair_result rr;
            bool ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &block_hash, &b, &rr);
            int32_t frontier = -1;
            bool frontier_found = false;
            (void)coins_kv_get_applied_height(db, &frontier, &frontier_found);
            UAVB_CHECK("(d) repair call succeeds", ok);
            UAVB_CHECK("(d) repair reports repaired",
                       rr.attempted && rr.dry_run_ok && rr.repaired &&
                       rr.cursor_before == 3 && rr.cursor_after == 1);
            UAVB_CHECK("(d) cursor/frontier rewound to H",
                       frontier_found && frontier == 1 &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 1);
            UAVB_CHECK("(d) stale log rows deleted",
                       !uavb_row_exists(db, "utxo_apply_log", 1) &&
                       !uavb_row_exists(db, "utxo_apply_log", 2));
            UAVB_CHECK("(d) future delta deleted and inverse applied",
                       !uavb_row_exists(db, "utxo_apply_delta", 2) &&
                       !coins_kv_exists(db, future_txid.data, 0));

            /* Re-seed the stale row/cursor under the same block hash: the
             * marker should stop a second mutation. */
            bool reseeded = uavb_put_utxo_log(db, 1, "value_overflow", 0) &&
                            uavb_set_cursor_and_frontier(db, 3);
            UAVB_CHECK("(d) marker guard reseed succeeds", reseeded);
            memset(&rr, 0, sizeof(rr));
            ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &block_hash, &b, &rr);
            UAVB_CHECK("(d) marker guard stops second attempt",
                       ok && rr.marker_seen && !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3);
            unsetenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK");
        }
        block_free(&b);
        uavb_repair_fixture_close(dir);
    }

    /* (e) REPAIR GUARDS.
     * Wrong author refuses before mutation; a genuinely invalid current-binary
     * dry-run logs the verdict and leaves the row/cursor untouched. */
    {
        char dir[256];
        UAVB_CHECK("(e) guard fixture opens",
                   uavb_repair_fixture_open(dir, "guards", &coin) == 0);
        sqlite3 *db = progress_store_db();
        struct block b;
        bool built = uavb_build_block(&b, 0xE5, &coin, coin.value);
        UAVB_CHECK("(e) guard block builds", built);
        if (built) {
            struct uint256 block_hash;
            block_get_hash(&b, &block_hash);
            /* h=2 gets a consistent verified-row + delta pair so the
             * genuinely-invalid sub-case below reaches the dry-run instead
             * of the torn-walk refusal. */
            struct uint256 e_txid, e_hash;
            uint256_set_null(&e_txid);
            e_txid.data[0] = 0xF4;
            uint256_set_null(&e_hash);
            e_hash.data[0] = 0xA4;
            bool seeded = uavb_put_utxo_log(db, 1, "value_overflow", 0) &&
                          uavb_put_utxo_log(db, 2, "verified", 1) &&
                          uavb_seed_future_delta(db, 2, &e_txid, &e_hash) &&
                          uavb_set_cursor_and_frontier(db, 3);
            UAVB_CHECK("(e) author guard rows seeded", seeded);

            unsetenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK");
            struct utxo_apply_value_overflow_repair_result rr;
            memset(&rr, 0, sizeof(rr));
            bool ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &block_hash, &b, &rr);
            UAVB_CHECK("(e) owner gate refuses without mutation",
                       ok && rr.owner_refused && !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3 &&
                       uavb_row_exists(db, "utxo_apply_log", 1));
        }
        block_free(&b);

        struct block bad;
        built = uavb_build_block(&bad, 0xE6, &coin, coin.value + 1);
        UAVB_CHECK("(e) invalid dry-run block builds", built);
        if (built) {
            struct uint256 bad_hash;
            block_get_hash(&bad, &bad_hash);
            setenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK", "1", 1);
            struct utxo_apply_value_overflow_repair_result rr;
            bool ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &bad_hash, &bad, &rr);
            UAVB_CHECK("(e) genuinely invalid block refused without rewind",
                       ok && rr.genuinely_invalid && !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3 &&
                       uavb_row_exists(db, "utxo_apply_log", 1));
            unsetenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK");
        }
        block_free(&bad);
        uavb_repair_fixture_close(dir);
    }

    /* (m) TOCTOU CURSOR GUARD.
     * The caller snapshots the cursor under the progress lock, releases it
     * for the disk block read, then calls the repair. If utxo_apply advanced
     * in that gap, an inverse walk keyed to the stale cursor would rewind
     * past coins it never unwound. Persisted cursor = 4 while the call still
     * says 3: refuse without mutation and without burning the one-shot
     * marker; the same call with the fresh cursor then repairs. */
    {
        char dir[256];
        UAVB_CHECK("(m) stale-cursor fixture opens",
                   uavb_repair_fixture_open(dir, "stale", &coin) == 0);
        sqlite3 *db = progress_store_db();
        struct block b;
        bool built = uavb_build_block(&b, 0x91, &coin, coin.value);
        UAVB_CHECK("(m) stale-cursor block builds", built);
        if (built) {
            struct uint256 block_hash;
            block_get_hash(&b, &block_hash);
            struct uint256 t2, h2, t3, h3;
            uint256_set_null(&t2); t2.data[0] = 0xF2;
            uint256_set_null(&h2); h2.data[0] = 0xA2;
            uint256_set_null(&t3); t3.data[0] = 0xF3;
            uint256_set_null(&h3); h3.data[0] = 0xA3;
            bool seeded =
                uavb_put_utxo_log(db, 1, "value_overflow", 0) &&
                uavb_put_utxo_log(db, 2, "verified", 1) &&
                uavb_seed_future_delta(db, 2, &t2, &h2) &&
                uavb_put_utxo_log(db, 3, "verified", 1) &&
                uavb_seed_future_delta(db, 3, &t3, &h3) &&
                uavb_set_cursor_and_frontier(db, 4);
            UAVB_CHECK("(m) stale-cursor rows seeded", seeded);

            setenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK", "1", 1);
            struct utxo_apply_value_overflow_repair_result rr;
            bool ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3 /* stale: persisted cursor is 4 */, &block_hash,
                &b, &rr);
            UAVB_CHECK("(m) stale cursor refused without mutation",
                       ok && rr.attempted && rr.cursor_stale_refused &&
                       !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 4 &&
                       uavb_row_exists(db, "utxo_apply_log", 1));

            memset(&rr, 0, sizeof(rr));
            ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 4, &block_hash, &b, &rr);
            UAVB_CHECK("(m) fresh cursor then repairs",
                       ok && rr.repaired && !rr.cursor_stale_refused &&
                       rr.cursor_after == 1 &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 1 &&
                       !coins_kv_exists(db, t3.data, 0));
            unsetenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK");
        }
        block_free(&b);
        uavb_repair_fixture_close(dir);
    }

    /* (n) TORN INVERSE-WALK RANGE.
     * h=2 logged ok=1 but its delta row is MISSING (torn datadir): the
     * inverse walk would silently skip it and rewind past coins it never
     * unwound. The repair must refuse loudly instead of partially rewinding;
     * same refusal when a height in the range has no log row at all. */
    {
        char dir[256];
        UAVB_CHECK("(n) torn fixture opens",
                   uavb_repair_fixture_open(dir, "torn", &coin) == 0);
        sqlite3 *db = progress_store_db();
        struct block b;
        bool built = uavb_build_block(&b, 0x92, &coin, coin.value);
        UAVB_CHECK("(n) torn block builds", built);
        if (built) {
            struct uint256 block_hash;
            block_get_hash(&b, &block_hash);
            bool seeded =
                uavb_put_utxo_log(db, 1, "value_overflow", 0) &&
                uavb_put_utxo_log(db, 2, "verified", 1) && /* no delta row */
                uavb_set_cursor_and_frontier(db, 3);
            UAVB_CHECK("(n) torn rows seeded", seeded);

            setenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK", "1", 1);
            struct utxo_apply_value_overflow_repair_result rr;
            bool ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &block_hash, &b, &rr);
            UAVB_CHECK("(n) ok-without-delta refused without mutation",
                       ok && rr.walk_torn_refused && !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3 &&
                       uavb_row_exists(db, "utxo_apply_log", 2));

            UAVB_CHECK("(n) drop h=2 log row",
                       uavb_exec(db,
                           "DELETE FROM utxo_apply_log WHERE height=2"));
            memset(&rr, 0, sizeof(rr));
            ok = utxo_apply_repair_value_overflow_hole(
                db, 1, 3, &block_hash, &b, &rr);
            UAVB_CHECK("(n) missing-log-row refused without mutation",
                       ok && rr.walk_torn_refused && !rr.repaired &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3);
            unsetenv("ZCL_REDUCER_VALUE_OVERFLOW_REPAIR_ACK");
        }
        block_free(&b);
        uavb_repair_fixture_close(dir);
    }

    /* (o) REORG FORK-WALK FINALITY CLAMP.
     * cursor = 13 (tip C-1 = 12; ZCL_FINALITY_DEPTH = 10 → floor = 2). With
     * every delta branch_hash divergent from the active chain there is no
     * fork at or above the floor: the unwind must refuse immediately
     * (identical outcome to the old to-genesis scan + reorg_is_allowed
     * refusal) without mutating. Re-stamping h=2 — exactly the floor — as
     * the fork point must then unwind (2, 12], the deepest ALLOWED reorg. */
    {
        char dir[256];
        UAVB_CHECK("(o) reorg fixture opens",
                   uavb_repair_fixture_open(dir, "reorgclamp", &coin) == 0);
        sqlite3 *db = progress_store_db();

        enum { UAVB_ON = 13 };
        struct block_index nodes[UAVB_ON];
        struct uint256 divergent[UAVB_ON];
        struct uint256 coins_txid[UAVB_ON];
        memset(nodes, 0, sizeof(nodes));
        for (int i = 0; i < UAVB_ON; i++) {
            uint256_set_null(&nodes[i].hashBlock);
            nodes[i].hashBlock.data[0] = 0x40;
            nodes[i].hashBlock.data[1] = (uint8_t)i;
            nodes[i].phashBlock = &nodes[i].hashBlock;
            nodes[i].nHeight = i;
            nodes[i].pprev = i ? &nodes[i - 1] : NULL;
            uint256_set_null(&divergent[i]);
            divergent[i].data[0] = 0xDD;
            divergent[i].data[1] = (uint8_t)i;
            uint256_set_null(&coins_txid[i]);
            coins_txid[i].data[0] = 0xF5;
            coins_txid[i].data[1] = (uint8_t)i;
        }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        active_chain_init(&ms.chain_active);
        bool chain_up = active_chain_move_window_tip(&ms.chain_active,
                                                     &nodes[UAVB_ON - 1]);
        UAVB_CHECK("(o) active chain builds", chain_up);

        bool seeded = true;
        for (int h = 0; h < UAVB_ON && seeded; h++)
            seeded = uavb_seed_future_delta(db, h, &coins_txid[h],
                                            &divergent[h]);
        seeded = seeded && uavb_set_cursor_and_frontier(db, UAVB_ON);
        UAVB_CHECK("(o) divergent deltas seeded", seeded);

        stage_t *st = stage_create("uavb_noop", uavb_noop_step, NULL);
        UAVB_CHECK("(o) throwaway stage", st != NULL);
        if (st && chain_up && seeded) {
            _Atomic uint64_t unwound = 0;
            _Atomic int64_t blocked = 0;
            bool ok = utxo_apply_reorg_unwind_if_needed(db, st, &ms,
                                                        &unwound, &blocked);
            UAVB_CHECK("(o) no fork at/above floor refuses without mutation",
                       !ok && unwound == 0 &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb")
                           == UAVB_ON &&
                       uavb_row_exists(db, "utxo_apply_delta", 3));

            struct uint256 t2b;
            uint256_set_null(&t2b);
            t2b.data[0] = 0xF6;
            UAVB_CHECK("(o) fork stamped at floor",
                       uavb_seed_future_delta(db, 2, &t2b,
                                              &nodes[2].hashBlock));
            ok = utxo_apply_reorg_unwind_if_needed(db, st, &ms,
                                                   &unwound, &blocked);
            UAVB_CHECK("(o) fork at floor unwinds to fork+1",
                       ok && unwound == 1 &&
                       stage_cursor_persisted(db, "utxo_apply", "uavb") == 3 &&
                       !uavb_row_exists(db, "utxo_apply_delta", 3) &&
                       uavb_row_exists(db, "utxo_apply_delta", 2) &&
                       !coins_kv_exists(db, coins_txid[UAVB_ON - 1].data, 0));
        }
        if (st)
            stage_destroy(st);
        active_chain_free(&ms.chain_active);
        uavb_repair_fixture_close(dir);
    }

    /* (f) COINBASE-SPEND PROTECTION.
     * A tx that spends a coinbase output and has any transparent output is
     * rejected (zclassicd bad-txns-coinbase-spend-has-transparent-outputs,
     * src/main.cpp:2062-2070). Tests run under CHAIN_MAIN (tests/harness/src/test.c)
     * so consensus.fCoinbaseMustBeProtected is true. tout == coin.value keeps
     * the money rule satisfied, isolating the coinbase rule as the only
     * possible rejection. */
    {
        struct uavb_coin cb = coin;
        cb.is_coinbase = true;
        struct block b;
        bool built = uavb_build_block(&b, 0xF6, &cb, cb.value);
        UAVB_CHECK("(f) coinbase-spend block builds", built);
        if (built) {
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &cb, &out);
            UAVB_CHECK("(f) coinbase spend to transparent FAILS (!out.ok)",
                       out.ok == false);
            UAVB_CHECK("(f) status is coinbase_protect",
                       out.status != NULL &&
                       strcmp(out.status, "coinbase_protect") == 0);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (g) COINBASE SPENT TO SHIELDED IS ALLOWED.
     * Same coinbase input, but the spend has NO transparent outputs
     * (num_vout == 0 — value moves to the shielded pool). The protection rule
     * must NOT fire; the money rule passes (value_in >= 0). */
    {
        struct uavb_coin cb = coin;
        cb.is_coinbase = true;
        struct block b;
        bool built = uavb_build_block(&b, 0x67, &cb, cb.value);
        UAVB_CHECK("(g) shielded-coinbase block builds", built);
        if (built) {
            b.vtx[1].num_vout = 0;   /* no transparent outputs; vout array still freed */
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &cb, &out);
            UAVB_CHECK("(g) coinbase spend with no transparent output is allowed "
                       "(out.ok)", out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (h) NON-COINBASE SPEND TO TRANSPARENT IS ALLOWED.
     * Proves the rule is coinbase-specific: the same transparent-output shape
     * with a non-coinbase input is accepted. */
    {
        struct uavb_coin nc = coin;
        nc.is_coinbase = false;
        struct block b;
        bool built = uavb_build_block(&b, 0x68, &nc, nc.value);
        UAVB_CHECK("(h) non-coinbase block builds", built);
        if (built) {
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &nc, &out);
            UAVB_CHECK("(h) non-coinbase spend to transparent is allowed (out.ok)",
                       out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* ── COINBASE SUBSIDY CEILING (C-2) ──────────────────────────────────
     * compute_block_delta now enforces zclassicd's ConnectBlock reward cap
     * (main.cpp:2695-2700): vtx[0] value_out <= fees + subsidy(height), with
     * the genesis block exempt (main.cpp:2515-2527). Tests run under
     * CHAIN_MAIN where nSubsidySlowStartInterval=2, so subsidy(1) =
     * (12.5e8/2)*(1+1) = 1,250,000,000 zat. The spend tx supplies the fee:
     * fee = coin.value - tout (no shielded funding). */
    const int64_t subsidy1 = 1250000000LL;

    /* (i) coinbase == subsidy + fees PASSES (the exact ceiling). */
    {
        const int64_t fee = 100000000LL;
        struct block b;
        bool built = uavb_build_block(&b, 0x71, &coin, coin.value - fee);
        UAVB_CHECK("(i) ceiling block builds", built);
        if (built) {
            b.vtx[0].vout[0].value = subsidy1 + fee;
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            UAVB_CHECK("(i) coinbase == subsidy+fees PASSES (out.ok)",
                       out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (j) coinbase == subsidy + fees + 1 zat FAILS as bad_cb_amount
     * (inflation by a single zatoshi). */
    {
        const int64_t fee = 100000000LL;
        struct block b;
        bool built = uavb_build_block(&b, 0x72, &coin, coin.value - fee);
        UAVB_CHECK("(j) inflation block builds", built);
        if (built) {
            b.vtx[0].vout[0].value = subsidy1 + fee + 1;
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            UAVB_CHECK("(j) coinbase +1 zat FAILS (!out.ok)",
                       out.ok == false);
            UAVB_CHECK("(j) status is bad_cb_amount",
                       out.status != NULL &&
                       strcmp(out.status, "bad_cb_amount") == 0);
            UAVB_CHECK("(j) kind is bad-cb-amount",
                       out.failure_kind != NULL &&
                       strcmp(out.failure_kind, "bad-cb-amount") == 0);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (k) fee-funded overpay ABOVE the bare subsidy (but within
     * subsidy + fees) PASSES — fees legitimately raise the ceiling. */
    {
        const int64_t fee = 100000000LL;
        struct block b;
        bool built = uavb_build_block(&b, 0x73, &coin, coin.value - fee);
        UAVB_CHECK("(k) fee-funded block builds", built);
        if (built) {
            b.vtx[0].vout[0].value = subsidy1 + fee / 2;
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 1, uavb_lookup, &coin, &out);
            UAVB_CHECK("(k) fee-funded overpay above bare subsidy PASSES "
                       "(out.ok)", out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    /* (l) GENESIS EXEMPTION: the same gross overpay at block_height=0 is
     * accepted — zclassicd's ConnectBlock early-exits the genesis block
     * before any reward check (main.cpp:2515-2527). subsidy(0)=0 under the
     * slow start, so the 1e9 default coinbase would fail at any height>0. */
    {
        struct block b;
        bool built = uavb_build_block(&b, 0x74, &coin, coin.value);
        UAVB_CHECK("(l) genesis block builds", built);
        if (built) {
            struct delta_summary out;
            utxo_apply_compute_block_delta(&b, 0, uavb_lookup, &coin, &out);
            UAVB_CHECK("(l) overpay at height 0 is exempt (out.ok)",
                       out.ok == true);
            free_delta(&out);
        }
        block_free(&b);
    }

    printf("=== utxo_apply value-balance money-rule: %d failures ===\n",
           failures);
    return failures;
}
