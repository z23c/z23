/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Bounds on the ZSLP ancestry walk behind zslp_validity_apply_height.
 *
 * Every verdict the walk finishes must stay what it always was, and no long
 * chain of unsettled ancestors may stop the backfill or cost more than a
 * bounded amount of work per transaction. A transaction whose walk still does
 * not fit once its height has settled stays UNKNOWN, and the ledger does not
 * depend on whether a height was interrupted and applied again.
 *
 * Entry point: zslp_validity_walk_tests(), called from test_zslp_ledger().
 * Hermetic: each case builds its own in-memory node.db from seeded
 * projection rows. Thread cases run in a forked child so a lost child fails the
 * case instead of the runner. */

#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "models/database.h"
#include "models/zslp_ledger.h"
#include "models/zslp_validity.h"
#include "services/zslp_ledger_backfill_service.h"
#include "zslp/slp.h"

#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

int zslp_validity_walk_tests(void);

/* Thread sizes for the cases: a common process default, not a promise about any
 * node's limits; a small one; and a large one that lets the pinned fixture
 * finish as it always could. */
#define WK_THREAD_DEFAULT ((size_t)8 * 1024 * 1024)
#define WK_THREAD_SMALL ((size_t)1024 * 1024)
#define WK_THREAD_LARGE ((size_t)512 * 1024 * 1024)

#define WK_LEVEL_TOP 0x00FFFFFFu
#define WK_DEEP_LEVELS 300
#define WK_DEEP_RESOLVED_LEVELS 256
#define WK_WIDE_PARENTS 1100
#define WK_UNREPRESENTABLE ((uint64_t)INT64_MAX + 1)

/* Transaction families. The first txid byte orders the height scan, so a
 * descendant family sorts before its ancestors and the walk has to run. */
enum {
    WK_GENESIS_A = 0x10, WK_SEND_A = 0x11, WK_OVERSPEND = 0x12, WK_BURN = 0x13,
    WK_MISSING_PARENT = 0x14, WK_MISSING_CHILD = 0x15, WK_NO_PARENT = 0x16,
    WK_ORPHAN = 0x17, WK_MIXED = 0x18, WK_GENESIS_B = 0x19,
    WK_FOREIGN_UNKNOWN = 0x20, WK_UNKNOWN_SEND = 0x21, WK_GENESIS_HUGE = 0x22,
    WK_DEEP_CHAIN = 0x30, WK_GENESIS_DEEP = 0x31, WK_MINT = 0x32,
    WK_FORGED_MINT = 0x33, WK_GENESIS_BATON = 0x34, WK_OVERFULL = 0x35,
    WK_PLAIN_PARENT = 0x36, WK_DIAMOND = 0x37, WK_DIAMOND_PARENT = 0x38,
    WK_GENESIS_DIAMOND = 0x39, WK_MALFORMED = 0x3A, WK_LONE = 0x3B,
    WK_HELD = 0x3C, WK_HELD_TWICE = 0x3D,
    WK_WIDE = 0x40, WK_WIDE_GENESIS = 0x41, WK_WIDE_PARENT = 0x42,
    WK_WIDE_CHILD = 0x43, WK_MANY_EDGES = 0x44, WK_EDGE_PARENT = 0x45,
    WK_LONE_GENESIS = 0x46, WK_LONE_PARENT = 0x47, WK_LONE_SPENDER = 0x48,
    WK_HELD_GENESIS = 0x49, WK_HELD_PARENT = 0x4A, WK_HELD_CHAIN = 0x4B,
    WK_HELD_ROOT = 0x4C,
    WK_CYCLE_A = 0x50, WK_CYCLE_B = 0x51, WK_SELF_LOOP = 0x52
};

struct wk_expected {
    uint8_t family;
    uint32_t index;
    enum zslp_validity_status status;
    const char *reason;
};

static void wk_txid(uint8_t out[32], uint8_t family, uint32_t index)
{
    memset(out, family, 32);
    out[1] = (uint8_t)(index >> 24);
    out[2] = (uint8_t)(index >> 16);
    out[3] = (uint8_t)(index >> 8);
    out[4] = (uint8_t)index;
}

static int wk_check(const char *what, bool ok)
{
    printf("zslp walk: %s... %s\n", what, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

/* ── Seeded projection rows ───────────────────────────────────────── */

static void wk_ins_transfer(struct node_db *ndb, const uint8_t txid[32],
                            int height, const uint8_t token[32], int tx_type,
                            int64_t amount, int vout)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO zslp_transfers"
        "(txid,block_height,token_id,tx_type,amount,vout,to_addr)"
        " VALUES(?,?,?,?,?,?,NULL)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, token, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, tx_type);
    sqlite3_bind_int64(s, 5, amount);
    sqlite3_bind_int(s, 6, vout);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void wk_ins_output(struct node_db *ndb, const uint8_t txid[32], int vout,
                          int height)
{
    uint8_t addr[20];
    memset(addr, 0xA0 + (vout & 0x0F), sizeof(addr));
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO tx_outputs"
        "(txid,vout,value,script_type,address_hash,block_height)"
        " VALUES(?,?,546,1,?,?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, vout);
    sqlite3_bind_blob(s, 3, addr, 20, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, height);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void wk_spend(struct node_db *ndb, const uint8_t txid[32], int vin,
                     const uint8_t prev[32], int prev_vout, int height)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO tx_inputs"
        "(txid,vin_index,prev_txid,prev_vout,block_height)"
        " VALUES(?,?,?,?,?)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, vin);
    sqlite3_bind_blob(s, 3, prev, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, prev_vout);
    sqlite3_bind_int(s, 5, height);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void wk_ins_script(struct node_db *ndb, const uint8_t txid[32],
                          int height, const uint8_t *script, size_t len)
{
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb->db,
        "INSERT OR REPLACE INTO op_returns"
        "(txid,block_height,script,is_slp) VALUES(?,?,?,1)", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, height);
    sqlite3_bind_blob(s, 3, script, (int)len, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-insert
    sqlite3_finalize(s);
}

static void wk_seed_genesis(struct node_db *ndb, const uint8_t txid[32],
                            int height, uint64_t quantity, uint8_t baton)
{
    uint8_t script[256];
    size_t len = slp_build_genesis(script, sizeof(script), "WLK", "Walk", "",
                                   NULL, 0, baton, quantity);
    wk_ins_script(ndb, txid, height, script, len);
    wk_ins_output(ndb, txid, 1, height);
    if (baton)
        wk_ins_output(ndb, txid, baton, height);
    wk_ins_transfer(ndb, txid, height, txid, SLP_TX_GENESIS,
                    quantity > (uint64_t)INT64_MAX ? INT64_MAX
                                                   : (int64_t)quantity, 1);
}

static void wk_wire_token(const uint8_t token[32], struct uint256 *wire)
{
    for (int i = 0; i < 32; i++)
        wire->data[i] = token[31 - i];
}

static void wk_seed_send(struct node_db *ndb, const uint8_t txid[32],
                         int height, const uint8_t token[32],
                         const uint64_t *quantities, int count)
{
    struct uint256 wire;
    wk_wire_token(token, &wire);
    uint8_t script[256];
    size_t len = slp_build_send(script, sizeof(script), &wire, quantities,
                                count);
    wk_ins_script(ndb, txid, height, script, len);
    for (int i = 0; i < count; i++) {
        wk_ins_output(ndb, txid, i + 1, height);
        wk_ins_transfer(ndb, txid, height, token, SLP_TX_SEND,
                        (int64_t)quantities[i], i + 1);
    }
}

static void wk_seed_mint(struct node_db *ndb, const uint8_t txid[32],
                         int height, const uint8_t token[32], uint64_t quantity)
{
    struct uint256 wire;
    wk_wire_token(token, &wire);
    uint8_t script[256];
    size_t len = slp_build_mint(script, sizeof(script), &wire, 2, quantity);
    wk_ins_script(ndb, txid, height, script, len);
    wk_ins_output(ndb, txid, 1, height);
    wk_ins_output(ndb, txid, 2, height);
    wk_ins_transfer(ndb, txid, height, token, SLP_TX_MINT, (int64_t)quantity, 1);
}

/* A SEND of one output spending the two listed outpoints of `prev`. */
static void wk_seed_double_spender(struct node_db *ndb, const uint8_t txid[32],
                                   int height, const uint8_t token[32],
                                   const uint8_t prev[32])
{
    uint64_t one[1] = {1};
    wk_seed_send(ndb, txid, height, token, one, 1);
    wk_spend(ndb, txid, 0, prev, 1, height);
    wk_spend(ndb, txid, 1, prev, 2, height);
}

/* ── Running one fold on a thread of a chosen size ────────────────── */

struct wk_fold_job {
    struct node_db *ndb;
    int from;
    int to;
    int replays;
    uint8_t digest[32];
    bool ok;
};

static void *wk_fold_main(void *arg)
{
    struct wk_fold_job *job = arg;
    uint8_t next[32];
    job->ok = true;
    for (int h = job->from; h <= job->to && job->ok; h++) {
        for (int r = 0; r <= job->replays && job->ok; r++)
            job->ok = zslp_ledger_apply_height(job->ndb, h, job->digest, next);
        if (job->ok)
            memcpy(job->digest, next, sizeof(next));
    }
    return NULL;
}

static bool wk_run_on_thread(size_t thread_bytes, void *(*body)(void *), void *arg)
{
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
        return false;
    pthread_t thread;
    bool started = pthread_attr_setstacksize(&attr, thread_bytes) == 0 &&
                   pthread_create(&thread, &attr, body, arg) == 0;
    pthread_attr_destroy(&attr);
    return started && pthread_join(thread, NULL) == 0;
}

static bool wk_fold(struct node_db *ndb, size_t thread_bytes, int from, int to,
                    int replays, uint8_t digest[32])
{
    struct wk_fold_job job;
    memset(&job, 0, sizeof(job));
    job.ndb = ndb;
    job.from = from;
    job.to = to;
    job.replays = replays;
    if (digest)
        memcpy(job.digest, digest, 32);
    bool ran = wk_run_on_thread(thread_bytes, wk_fold_main, &job);
    if (digest)
        memcpy(digest, job.digest, 32);
    return ran && job.ok;
}

/* ── Counting the statements one fold runs ────────────────────────── */

struct wk_counts {
    long statements;
    long saves;
};

static int wk_trace(unsigned type, void *ctx, void *stmt, void *text)
{
    (void)stmt;
    static const char save[] = "INSERT OR REPLACE INTO zslp_validity";
    struct wk_counts *counts = ctx;
    if (type == SQLITE_TRACE_STMT) {
        counts->statements++;
        if (strncmp(text, save, sizeof(save) - 1) == 0)
            counts->saves++;
    }
    return 0;
}

static bool wk_fold_counted(struct node_db *ndb, int height,
                            struct wk_counts *counts)
{
    uint8_t digest[32] = {0};
    memset(counts, 0, sizeof(*counts));
    sqlite3_trace_v2(ndb->db, SQLITE_TRACE_STMT, wk_trace, counts);
    bool ok = wk_fold(ndb, WK_THREAD_LARGE, height, height, 0, digest);
    sqlite3_trace_v2(ndb->db, 0, NULL, NULL);
    return ok;
}

/* ── Reading the ledger back ──────────────────────────────────────── */

static bool wk_is(struct node_db *ndb, uint8_t family, uint32_t index,
                  enum zslp_validity_status status, const char *reason)
{
    uint8_t txid[32];
    char got[96];
    wk_txid(txid, family, index);
    enum zslp_validity_status actual =
        zslp_validity_get(ndb, txid, got, sizeof(got));
    bool ok = actual == status && strcmp(got, reason) == 0;
    if (!ok)
        printf("zslp walk: family %02x index %u is %d '%s', wanted %d '%s'\n",
               family, index, (int)actual, got, (int)status, reason);
    return ok;
}

static void wk_hash_rows(struct sha3_256_ctx *ctx, struct node_db *ndb,
                         const char *sql)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) != SQLITE_OK)
        return;
    while (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:test-readonly-scan
        for (int col = 0; col < sqlite3_column_count(s); col++) {
            const unsigned char *text = sqlite3_column_text(s, col);
            if (text)
                sha3_256_write(ctx, text, strlen((const char *)text));
            sha3_256_write(ctx, (const uint8_t *)"|", 1);
        }
    }
    sqlite3_finalize(s);
}

static void wk_hex(const uint8_t bytes[32], char hex[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(hex + i * 2, 3, "%02x", bytes[i]);
}

/* Every column of every validity and ledger row, so a changed verdict, reason,
 * unit count, spend mark or missing row all move this value. */
static void wk_fingerprint(struct node_db *ndb, char hex[65])
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    sha3_256_init(&ctx);
    wk_hash_rows(&ctx, ndb,
        "SELECT hex(txid),hex(token_id),tx_type,status,reason,block_height,"
        "input_units,output_units,burned_units,minted_units,baton_vout "
        "FROM zslp_validity ORDER BY txid");
    wk_hash_rows(&ctx, ndb,
        "SELECT hex(token_id),hex(txid),vout,amount,hex(address),"
        "created_height,role,hex(spent_by_txid),spent_height "
        "FROM zslp_ledger ORDER BY txid,vout");
    sha3_256_finalize(&ctx, digest);
    wk_hex(digest, hex);
}

static int64_t wk_count(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int64_t n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
        n = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return n;
}

/* ── Pinned fixture: every chain here finished before the bound existed ── */

static void wk_seed_pinned_token_a(struct node_db *ndb)
{
    uint8_t ga[32], a1[32], tx[32], other[32];
    wk_txid(ga, WK_GENESIS_A, 0);
    wk_txid(a1, WK_SEND_A, 0);
    wk_seed_genesis(ndb, ga, 1, 1000, 0);
    uint64_t split[4] = {400, 200, 200, 200};
    wk_seed_send(ndb, a1, 2, ga, split, 4);
    wk_spend(ndb, a1, 0, ga, 1, 2);

    uint64_t over[1] = {401};
    wk_txid(tx, WK_OVERSPEND, 0);
    wk_seed_send(ndb, tx, 3, ga, over, 1);
    wk_spend(ndb, tx, 0, a1, 1, 3);

    uint64_t burn[1] = {50};
    wk_txid(tx, WK_BURN, 0);
    wk_seed_send(ndb, tx, 3, ga, burn, 1);
    wk_spend(ndb, tx, 0, a1, 2, 3);

    uint64_t five[1] = {5};
    wk_txid(other, WK_MISSING_PARENT, 0);
    wk_ins_transfer(ndb, other, 0, ga, SLP_TX_SEND, 5, 1);
    wk_txid(tx, WK_MISSING_CHILD, 0);
    wk_seed_send(ndb, tx, 4, ga, five, 1);
    wk_spend(ndb, tx, 0, other, 1, 4);

    wk_txid(other, WK_NO_PARENT, 0);
    wk_txid(tx, WK_ORPHAN, 0);
    wk_seed_send(ndb, tx, 4, ga, five, 1);
    wk_spend(ndb, tx, 0, other, 1, 4);

    uint64_t mixed[1] = {200};
    wk_txid(other, WK_GENESIS_B, 0);
    wk_seed_genesis(ndb, other, 5, 50, 0);
    wk_txid(tx, WK_MIXED, 0);
    wk_seed_send(ndb, tx, 5, ga, mixed, 1);
    wk_spend(ndb, tx, 0, a1, 3, 5);
    wk_spend(ndb, tx, 1, other, 1, 5);
}

/* A lineage that stays UNKNOWN, and a spend of its token alongside another
 * token's input, which has always been judged on the other token alone. */
static void wk_seed_pinned_unknown(struct node_db *ndb)
{
    uint8_t huge[32], prev[32], tx[32], ga[32], a1[32];
    wk_txid(huge, WK_GENESIS_HUGE, 0);
    wk_seed_genesis(ndb, huge, 6, WK_UNREPRESENTABLE, 0);
    memcpy(prev, huge, 32);
    for (uint32_t level = 1; level <= 3; level++) {
        wk_txid(tx, WK_UNKNOWN_SEND, WK_LEVEL_TOP - level);
        wk_seed_double_spender(ndb, tx, 6, huge, prev);
        memcpy(prev, tx, 32);
    }
    wk_txid(ga, WK_GENESIS_A, 0);
    wk_txid(a1, WK_SEND_A, 0);
    uint64_t rest[1] = {200};
    wk_txid(tx, WK_FOREIGN_UNKNOWN, 0);
    wk_seed_send(ndb, tx, 6, ga, rest, 1);
    wk_spend(ndb, tx, 0, a1, 4, 6);
    wk_spend(ndb, tx, 1, prev, 1, 6);
}

static void wk_seed_chain(struct node_db *ndb, int height, uint8_t genesis_family,
                          uint8_t chain_family, uint32_t levels)
{
    uint8_t genesis[32], prev[32], tx[32];
    uint64_t all[1] = {1000};
    wk_txid(genesis, genesis_family, 0);
    wk_seed_genesis(ndb, genesis, height, 1000, 0);
    memcpy(prev, genesis, 32);
    for (uint32_t level = 1; level <= levels; level++) {
        wk_txid(tx, chain_family, WK_LEVEL_TOP - level);
        wk_seed_send(ndb, tx, height, genesis, all, 1);
        wk_spend(ndb, tx, 0, prev, 1, height);
        memcpy(prev, tx, 32);
    }
}

static void wk_seed_pinned_mint_and_limits(struct node_db *ndb)
{
    uint8_t baton_genesis[32], tx[32], plain[32], parent[32], gd[32];
    wk_txid(baton_genesis, WK_GENESIS_BATON, 0);
    wk_seed_genesis(ndb, baton_genesis, 7, 10, 2);
    wk_txid(tx, WK_MINT, 0);
    wk_seed_mint(ndb, tx, 7, baton_genesis, 5);
    wk_spend(ndb, tx, 0, baton_genesis, 2, 7);
    wk_txid(tx, WK_FORGED_MINT, 0);
    wk_seed_mint(ndb, tx, 7, baton_genesis, 5);

    uint64_t one[1] = {1};
    wk_txid(tx, WK_OVERFULL, 0);
    wk_seed_send(ndb, tx, 7, baton_genesis, one, 1);
    for (uint32_t i = 0; i <= 4096; i++) {
        wk_txid(plain, WK_PLAIN_PARENT, i);
        wk_spend(ndb, tx, (int)i, plain, 0, 7);
    }

    uint64_t half[2] = {600, 400};
    uint64_t whole[1] = {1000};
    wk_txid(gd, WK_GENESIS_DIAMOND, 0);
    wk_seed_genesis(ndb, gd, 7, 1000, 0);
    wk_txid(parent, WK_DIAMOND_PARENT, 0);
    wk_seed_send(ndb, parent, 7, gd, half, 2);
    wk_spend(ndb, parent, 0, gd, 1, 7);
    wk_txid(tx, WK_DIAMOND, 0);
    wk_seed_send(ndb, tx, 7, gd, whole, 1);
    wk_spend(ndb, tx, 0, parent, 1, 7);
    wk_spend(ndb, tx, 1, parent, 2, 7);

    static const uint8_t garbage[2] = {0x6a, 0x00};
    wk_txid(tx, WK_MALFORMED, 0);
    wk_ins_script(ndb, tx, 7, garbage, sizeof(garbage));
}

static void wk_seed_pinned(struct node_db *ndb)
{
    wk_seed_pinned_token_a(ndb);
    wk_seed_pinned_unknown(ndb);
    wk_seed_chain(ndb, 7, WK_GENESIS_DEEP, WK_DEEP_CHAIN, 200);
    wk_seed_pinned_mint_and_limits(ndb);
}

static const struct wk_expected g_pinned[] = {
    {WK_GENESIS_A, 0, ZSLP_VALIDITY_VALID, "valid_genesis"},
    {WK_SEND_A, 0, ZSLP_VALIDITY_VALID, "valid_send"},
    {WK_OVERSPEND, 0, ZSLP_VALIDITY_INVALID, "send_output_exceeds_input"},
    {WK_BURN, 0, ZSLP_VALIDITY_VALID, "valid_send"},
    {WK_MISSING_CHILD, 0, ZSLP_VALIDITY_UNKNOWN, "send_parent_unknown"},
    {WK_ORPHAN, 0, ZSLP_VALIDITY_INVALID, "send_ancestry_invalid"},
    {WK_MIXED, 0, ZSLP_VALIDITY_INVALID, "mixed_token_inputs"},
    {WK_GENESIS_HUGE, 0, ZSLP_VALIDITY_UNKNOWN, "quantity_unrepresentable"},
    {WK_UNKNOWN_SEND, WK_LEVEL_TOP - 3, ZSLP_VALIDITY_UNKNOWN,
     "send_parent_unknown"},
    {WK_FOREIGN_UNKNOWN, 0, ZSLP_VALIDITY_VALID, "valid_send"},
    {WK_DEEP_CHAIN, WK_LEVEL_TOP - 200, ZSLP_VALIDITY_VALID, "valid_send"},
    {WK_MINT, 0, ZSLP_VALIDITY_VALID, "valid_mint"},
    {WK_FORGED_MINT, 0, ZSLP_VALIDITY_INVALID, "mint_baton_lineage_invalid"},
    {WK_OVERFULL, 0, ZSLP_VALIDITY_UNKNOWN, "input_limit_exceeded"},
    {WK_DIAMOND, 0, ZSLP_VALIDITY_VALID, "valid_send"},
    {WK_MALFORMED, 0, ZSLP_VALIDITY_INVALID, "malformed_slp"},
};

/* Taken from the walk as it stood before it was bounded, given all the room
 * it needed to finish. A change here changes a deterministic ledger. */
#define WK_PINNED_FINGERPRINT \
    "e93209ce30d060595db9e0d3dfb8abd6e52cd9106b7b57ece85826b474ad19b5"
#define WK_PINNED_DIGEST \
    "07ff583649c91ec72000d1fe4126b4aa307d1ac3ef3b3f5133e0fee1818958ad"

static int wk_case_pinned(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("pinned fixture opens a database", false);
    wk_seed_pinned(&ndb);

    uint8_t digest[32] = {0};
    int failures = wk_check("pinned fixture folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 7, 0, digest));
    bool verdicts = true;
    for (size_t i = 0; i < sizeof(g_pinned) / sizeof(g_pinned[0]); i++)
        verdicts = wk_is(&ndb, g_pinned[i].family, g_pinned[i].index,
                         g_pinned[i].status, g_pinned[i].reason) && verdicts;
    failures += wk_check("pinned verdicts and reasons are unchanged", verdicts);

    char print[65], running[65];
    wk_fingerprint(&ndb, print);
    wk_hex(digest, running);
    printf("zslp walk: pinned fingerprint %s digest %s\n", print, running);
    failures += wk_check("pinned rows are byte-identical",
                         strcmp(print, WK_PINNED_FINGERPRINT) == 0);
    failures += wk_check("pinned running digest is byte-identical",
                         strcmp(running, WK_PINNED_DIGEST) == 0);
    node_db_close(&ndb);
    return failures;
}

/* ── Thread sizes: the backfill finishes every chain on each ───── */

/* Runs the backfill the way its tick does, to the tip. */
static void *wk_backfill_main(void *arg)
{
    bool *ok = arg;
    int guard = 0;
    while (zslp_ledger_backfill_run_once() > 0 && guard < 1000)
        guard++;
    *ok = guard < 1000;
    return NULL;
}

static bool wk_backfill_to_tip(struct node_db *ndb, size_t thread_bytes, int tip)
{
    bool ran = false;
    int32_t cursor = -1;
    g_zslp_ledger_backfill_test_ndb = ndb;
    reducer_frontier_provable_tip_set(tip);
    (void)node_db_state_set_int(ndb, "sync_projection_tip_height", tip);
    bool done = wk_run_on_thread(thread_bytes, wk_backfill_main, &ran) && ran;
    done = done && zslp_ledger_get_cursor(ndb, &cursor, NULL) && cursor == tip;
    g_zslp_ledger_backfill_test_ndb = NULL;
    reducer_frontier_provable_tip_reset();
    return done;
}

#if !defined(_WIN32)
/* A long chain of unsettled ancestors, one height each. */
static void wk_seed_unknown_chain(struct node_db *ndb, int levels)
{
    uint8_t huge[32], prev[32], tx[32];
    wk_txid(huge, WK_GENESIS_HUGE, 0);
    wk_seed_genesis(ndb, huge, 1, WK_UNREPRESENTABLE, 0);
    memcpy(prev, huge, 32);
    uint64_t one[1] = {1};
    for (int level = 1; level <= levels; level++) {
        wk_txid(tx, WK_UNKNOWN_SEND, (uint32_t)level);
        wk_seed_send(ndb, tx, level + 1, huge, one, 1);
        wk_spend(ndb, tx, 0, prev, 1, level + 1);
        memcpy(prev, tx, 32);
    }
}

static bool wk_child_unknown_chain(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return false;
    wk_seed_unknown_chain(&ndb, 40);
    return wk_backfill_to_tip(&ndb, WK_THREAD_DEFAULT, 41) &&
           wk_is(&ndb, WK_UNKNOWN_SEND, 40, ZSLP_VALIDITY_UNKNOWN,
                 "send_parent_unknown");
}

/* A chain past the depth cap on a small thread. */
static bool wk_child_deep_on_small_thread(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return false;
    wk_seed_chain(&ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, WK_DEEP_LEVELS);
    return wk_backfill_to_tip(&ndb, WK_THREAD_SMALL, 1) &&
           wk_is(&ndb, WK_DEEP_CHAIN, WK_LEVEL_TOP - WK_DEEP_LEVELS,
                 ZSLP_VALIDITY_VALID, "valid_send");
}

static bool wk_in_child(bool (*body)(void))
{
    fflush(stdout);
    fflush(stderr);
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0)
        _exit(body() ? 0 : 1);
    int status = 0;
    if (waitpid(child, &status, 0) != child)
        return false;
    if (WIFSIGNALED(status))
        printf("zslp walk: child ended on signal %d\n", WTERMSIG(status));
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int wk_case_thread_sizes(void)
{
    int failures = wk_check(
        "a long unsettled chain backfills on a default-sized thread",
        wk_in_child(wk_child_unknown_chain));
    failures += wk_check(
        "a chain past the depth cap backfills on a small thread",
        wk_in_child(wk_child_deep_on_small_thread));
    return failures;
}
#else
static int wk_case_thread_sizes(void) { return 0; }
#endif

/* ── Work: what one transaction may cost is bounded ────────── */

static int wk_case_double_inputs(void)
{
    enum { LEVELS = 14 };
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("double-input fixture opens a database", false);
    uint8_t huge[32], prev[32], tx[32];
    wk_txid(huge, WK_GENESIS_HUGE, 0);
    wk_seed_genesis(&ndb, huge, 1, WK_UNREPRESENTABLE, 0);
    memcpy(prev, huge, 32);
    for (int level = 1; level <= LEVELS; level++) {
        wk_txid(tx, WK_UNKNOWN_SEND, (uint32_t)level);
        wk_seed_double_spender(&ndb, tx, level + 1, huge, prev);
        memcpy(prev, tx, 32);
    }
    struct wk_counts counts;
    bool folded = wk_fold(&ndb, WK_THREAD_LARGE, 0, LEVELS, 0, NULL) &&
                  wk_fold_counted(&ndb, LEVELS + 1, &counts);
    printf("zslp walk: top height ran %ld statements, %ld verdict writes\n",
           counts.statements, counts.saves);
    int failures = wk_check("double-input chain folds", folded);
    failures += wk_check("each ancestor is judged once per transaction",
                         counts.saves == LEVELS + 1);
    failures += wk_check("statements stay within the walk bound",
                         counts.statements < 60 * (LEVELS + 1));
    failures += wk_check("double-input chain stays UNKNOWN",
                         wk_is(&ndb, WK_UNKNOWN_SEND, LEVELS,
                               ZSLP_VALIDITY_UNKNOWN, "send_parent_unknown"));
    node_db_close(&ndb);
    return failures;
}

/* T spends more unsettled parents than one walk may judge at its turn. Its
 * parents settle on their own turn in the height, so T then fits and gets the
 * verdict it always had. */
static void wk_seed_wide(struct node_db *ndb, int height)
{
    uint8_t wide[32], parent[32], genesis[32], child[32];
    uint64_t one[1] = {1};
    wk_txid(wide, WK_WIDE, 0);
    wk_txid(genesis, WK_WIDE_GENESIS, 0);
    wk_seed_send(ndb, wide, height, wide, one, 1);
    wk_seed_genesis(ndb, genesis, height, 10, 0);
    for (uint32_t i = 0; i < WK_WIDE_PARENTS; i++) {
        wk_txid(parent, WK_WIDE_PARENT, i);
        wk_seed_genesis(ndb, parent, height, 1, 0);
        wk_spend(ndb, wide, (int)i, parent, 1, height);
        wk_spend(ndb, genesis, (int)i, parent, 1, height);
    }
    wk_txid(child, WK_WIDE_CHILD, 0);
    wk_seed_send(ndb, child, height + 1, wide, one, 1);
    wk_spend(ndb, child, 0, wide, 1, height + 1);
}

static int wk_case_wide(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("wide fixture opens a database", false);
    wk_seed_wide(&ndb, 1);
    uint8_t digest[32] = {0};
    int failures = wk_check("wide height folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 1, 0, digest));
    failures += wk_check("a refused walk gets its old verdict in its own height",
                         wk_is(&ndb, WK_WIDE, 0, ZSLP_VALIDITY_INVALID,
                               "send_ancestry_invalid"));
    failures += wk_check("a GENESIS needs no ancestry to be judged",
                         wk_is(&ndb, WK_WIDE_GENESIS, 0, ZSLP_VALIDITY_VALID,
                               "valid_genesis"));
    failures += wk_check("parents of a refused walk settle on their own turn",
                         wk_is(&ndb, WK_WIDE_PARENT, WK_WIDE_PARENTS - 1,
                               ZSLP_VALIDITY_VALID, "valid_genesis"));
    failures += wk_check("a child of the refused transaction keeps that verdict",
                         wk_fold(&ndb, WK_THREAD_LARGE, 2, 2, 0, digest) &&
                         wk_is(&ndb, WK_WIDE_CHILD, 0, ZSLP_VALIDITY_INVALID,
                               "send_ancestry_invalid"));
    node_db_close(&ndb);
    return failures;
}

/* A SEND that would be VALID, past the bound at its turn and spent by nothing
 * that walks it. A transaction without a token spends one of its outputs in the
 * same height. */
static void wk_seed_lone(struct node_db *ndb, int height)
{
    uint8_t lone[32], genesis[32], parent[32], spender[32];
    uint64_t split[2] = {10, 5};
    wk_txid(lone, WK_LONE, 0);
    wk_txid(genesis, WK_LONE_GENESIS, 0);
    wk_seed_genesis(ndb, genesis, height, 20, 0);
    wk_seed_send(ndb, lone, height, genesis, split, 2);
    wk_spend(ndb, lone, 0, genesis, 1, height);
    for (uint32_t i = 0; i < WK_WIDE_PARENTS; i++) {
        wk_txid(parent, WK_LONE_PARENT, i);
        wk_seed_genesis(ndb, parent, height, 1, 0);
        wk_spend(ndb, lone, (int)i + 1, parent, 5, height);
    }
    wk_txid(spender, WK_LONE_SPENDER, 0);
    wk_spend(ndb, spender, 0, lone, 2, height);
}

static bool wk_outpoint_unspent(struct node_db *ndb, uint8_t family, int vout,
                                bool want_unspent)
{
    uint8_t txid[32];
    wk_txid(txid, family, 0);
    sqlite3_stmt *s = NULL;
    bool found = false, unspent = false;
    if (sqlite3_prepare_v2(ndb->db,
            "SELECT spent_by_txid IS NULL FROM zslp_ledger "
            "WHERE txid=? AND vout=?", -1, &s, NULL) == SQLITE_OK) {
        sqlite3_bind_blob(s, 1, txid, 32, SQLITE_STATIC);
        sqlite3_bind_int(s, 2, vout);
        if (sqlite3_step(s) == SQLITE_ROW) {  // raw-sql-ok:test-readonly-probe
            found = true;
            unspent = sqlite3_column_int(s, 0) != 0;
        }
    }
    sqlite3_finalize(s);
    return found && unspent == want_unspent;
}

static int wk_case_lone(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("lone fixture opens a database", false);
    wk_seed_lone(&ndb, 1);
    uint8_t digest[32] = {0};
    int failures = wk_check("lone height folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 1, 0, digest));
    failures += wk_check("a refused SEND with no descendant is VALID at its height",
                         wk_is(&ndb, WK_LONE, 0, ZSLP_VALIDITY_VALID,
                               "valid_send"));
    failures += wk_check("its token input is spent",
                         wk_outpoint_unspent(&ndb, WK_LONE_GENESIS, 1, false));
    failures += wk_check("its output spent in the same height is spent",
                         wk_outpoint_unspent(&ndb, WK_LONE, 2, false));
    failures += wk_check("its other output is unspent",
                         wk_outpoint_unspent(&ndb, WK_LONE, 1, true));
    failures += wk_check("every other unspent output is a parent's own",
                         zslp_ledger_unspent_count(&ndb) ==
                             WK_WIDE_PARENTS + 1);
    node_db_close(&ndb);
    return failures;
}

/* T holds a real token input, but more parents than one walk may judge stay
 * UNKNOWN, so nothing in the height can bring its walk within the bound. */
static void wk_seed_held(struct node_db *ndb, int height)
{
    uint8_t held[32], genesis[32], parent[32];
    uint64_t all[1] = {5};
    wk_txid(held, WK_HELD, 0);
    wk_txid(genesis, WK_HELD_GENESIS, 0);
    wk_seed_genesis(ndb, genesis, height, 5, 0);
    wk_seed_send(ndb, held, height, genesis, all, 1);
    wk_spend(ndb, held, 0, genesis, 1, height);
    for (uint32_t i = 0; i < WK_WIDE_PARENTS; i++) {
        wk_txid(parent, WK_HELD_PARENT, i);
        wk_seed_genesis(ndb, parent, height, WK_UNREPRESENTABLE, 0);
        wk_spend(ndb, held, (int)i + 1, parent, 1, height);
    }
}

/* T is past the work bound at its turn and past the depth cap once its other
 * parents have settled. The reason it keeps is the one from its turn. */
static void wk_seed_held_twice(struct node_db *ndb, int chain_height, int height)
{
    uint8_t held[32], root[32], parent[32], prev[32], tx[32];
    uint64_t one[1] = {1};
    wk_txid(root, WK_HELD_ROOT, 0);
    wk_seed_genesis(ndb, root, chain_height, WK_UNREPRESENTABLE, 0);
    memcpy(prev, root, 32);
    for (uint32_t level = 1; level <= WK_DEEP_RESOLVED_LEVELS + 4; level++) {
        wk_txid(tx, WK_HELD_CHAIN, WK_LEVEL_TOP - level);
        wk_seed_send(ndb, tx, chain_height, root, one, 1);
        wk_spend(ndb, tx, 0, prev, 1, chain_height);
        memcpy(prev, tx, 32);
    }
    wk_txid(held, WK_HELD_TWICE, 0);
    wk_seed_send(ndb, held, height, held, one, 1);
    for (uint32_t i = 0; i < WK_WIDE_PARENTS; i++) {
        wk_txid(parent, WK_LONE_PARENT, i);
        wk_seed_genesis(ndb, parent, height, 1, 0);
        wk_spend(ndb, held, (int)i, parent, 5, height);
    }
    wk_spend(ndb, held, WK_WIDE_PARENTS, prev, 1, height);
}

static int wk_case_held(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("held fixture opens a database", false);
    wk_seed_held(&ndb, 1);
    uint8_t digest[32] = {0};
    int failures = wk_check("held height folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 1, 0, digest));
    failures += wk_check("a walk still past the work bound stays UNKNOWN",
                         wk_is(&ndb, WK_HELD, 0, ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_work_exceeded"));
    node_db_close(&ndb);
    return failures;
}

/* Few parents, each with many plain inputs: the bound counts inputs too. */
static void wk_seed_many_edges(struct node_db *ndb, bool parents_stay_unknown)
{
    uint8_t top[32], parent[32], plain[32];
    uint64_t one[1] = {1};
    wk_txid(top, WK_MANY_EDGES, 0);
    wk_seed_send(ndb, top, 1, top, one, 1);
    for (uint32_t p = 0; p < 20; p++) {
        wk_txid(parent, WK_EDGE_PARENT, p);
        if (parents_stay_unknown)
            wk_seed_genesis(ndb, parent, 1, WK_UNREPRESENTABLE, 0);
        else
            wk_seed_send(ndb, parent, 1, top, one, 1);
        wk_spend(ndb, top, (int)p, parent, 1, 1);
        for (uint32_t i = 0; i < 1000; i++) {
            wk_txid(plain, WK_PLAIN_PARENT, p * 1000 + i);
            wk_spend(ndb, parent, (int)i, plain, 0, 1);
        }
    }
}

static int wk_case_many_edges_with(bool parents_stay_unknown,
                                   enum zslp_validity_status status,
                                   const char *reason)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("input-bound fixture opens a database", false);
    wk_seed_many_edges(&ndb, parents_stay_unknown);
    struct wk_counts counts;
    bool folded = wk_fold_counted(&ndb, 1, &counts);
    printf("zslp walk: input-heavy height ran %ld statements\n",
           counts.statements);
    int failures = wk_check("input-heavy height folds", folded);
    failures += wk_check(parents_stay_unknown
                             ? "a walk still past the input bound stays UNKNOWN"
                             : "a walk past the input bound gets its old verdict",
                         wk_is(&ndb, WK_MANY_EDGES, 0, status, reason));
    node_db_close(&ndb);
    return failures;
}

static int wk_case_many_edges(void)
{
    return wk_case_many_edges_with(false, ZSLP_VALIDITY_INVALID,
                                   "send_ancestry_invalid") +
           wk_case_many_edges_with(true, ZSLP_VALIDITY_UNKNOWN,
                                   "ancestry_work_exceeded");
}

/* ── Depth: a chain past the cap settles in its own height ─────────── */

static void wk_seed_deep_child(struct node_db *ndb, int height)
{
    uint8_t genesis[32], last[32], child[32];
    uint64_t all[1] = {1000};
    wk_txid(genesis, WK_GENESIS_DEEP, 0);
    wk_txid(last, WK_DEEP_CHAIN, WK_LEVEL_TOP - WK_DEEP_LEVELS);
    wk_txid(child, WK_WIDE_CHILD, 1);
    wk_seed_send(ndb, child, height, genesis, all, 1);
    wk_spend(ndb, child, 0, last, 1, height);
}

static int wk_case_deep_settles(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("deep fixture opens a database", false);
    wk_seed_chain(&ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, WK_DEEP_LEVELS);
    wk_seed_deep_child(&ndb, 2);
    uint8_t digest[32] = {0};
    int failures = wk_check("deep chain height folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 1, 0, digest));
    failures += wk_check("a chain past the depth cap is VALID at its own height",
                         wk_is(&ndb, WK_DEEP_CHAIN,
                               WK_LEVEL_TOP - WK_DEEP_LEVELS,
                               ZSLP_VALIDITY_VALID, "valid_send"));
    failures += wk_check("the first level past the cap is VALID",
                         wk_is(&ndb, WK_DEEP_CHAIN,
                               WK_LEVEL_TOP - (WK_DEEP_RESOLVED_LEVELS + 1),
                               ZSLP_VALIDITY_VALID, "valid_send"));
    failures += wk_check("the deepest chain within the cap is VALID",
                         wk_is(&ndb, WK_DEEP_CHAIN,
                               WK_LEVEL_TOP - WK_DEEP_RESOLVED_LEVELS,
                               ZSLP_VALIDITY_VALID, "valid_send"));
    failures += wk_check("only the newest output of the height stays unspent",
                         zslp_ledger_unspent_count(&ndb) == 1);
    failures += wk_check("a later child is VALID",
                         wk_fold(&ndb, WK_THREAD_LARGE, 2, 2, 0, digest) &&
                         wk_is(&ndb, WK_WIDE_CHILD, 1, ZSLP_VALIDITY_VALID,
                               "valid_send"));
    failures += wk_check("exactly the newest output stays unspent",
                         zslp_ledger_unspent_count(&ndb) == 1);
    node_db_close(&ndb);
    return failures;
}

/* A chain past the depth cap whose lineage stays UNKNOWN, all in one height, and
 * a child one height later: no walk from past the cap can ever fit. */
static void wk_seed_deep_unknown(struct node_db *ndb)
{
    uint8_t huge[32], prev[32], tx[32];
    uint64_t one[1] = {1};
    wk_txid(huge, WK_GENESIS_HUGE, 0);
    wk_seed_genesis(ndb, huge, 1, WK_UNREPRESENTABLE, 0);
    memcpy(prev, huge, 32);
    for (uint32_t level = 1; level <= WK_DEEP_LEVELS + 1; level++) {
        wk_txid(tx, WK_UNKNOWN_SEND, WK_LEVEL_TOP - level);
        int height = level <= WK_DEEP_LEVELS ? 1 : 2;
        wk_seed_send(ndb, tx, height, huge, one, 1);
        wk_spend(ndb, tx, 0, prev, 1, height);
        memcpy(prev, tx, 32);
    }
}

static int wk_case_deep_unknown(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("deep UNKNOWN fixture opens a database", false);
    wk_seed_deep_unknown(&ndb);
    int failures = wk_check("deep UNKNOWN heights fold",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 2, 0, NULL));
    failures += wk_check("past the depth cap the row says so",
                         wk_is(&ndb, WK_UNKNOWN_SEND,
                               WK_LEVEL_TOP - (WK_DEEP_RESOLVED_LEVELS + 1),
                               ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_depth_exceeded"));
    failures += wk_check("within the depth cap the row names its parent",
                         wk_is(&ndb, WK_UNKNOWN_SEND,
                               WK_LEVEL_TOP - WK_DEEP_RESOLVED_LEVELS,
                               ZSLP_VALIDITY_UNKNOWN, "send_parent_unknown"));
    failures += wk_check("a child past the depth cap stays UNKNOWN",
                         wk_is(&ndb, WK_UNKNOWN_SEND,
                               WK_LEVEL_TOP - (WK_DEEP_LEVELS + 1),
                               ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_depth_exceeded"));
    node_db_close(&ndb);
    return failures;
}

/* A row left refused at an earlier height settles from any later walk that
 * fits. Its own height's sweep has passed, so the fixture sets the row back. */
static int wk_case_earlier_refusal_settles(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("earlier-refusal fixture opens a database", false);
    wk_seed_chain(&ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, 3);
    uint8_t digest[32] = {0}, genesis[32], last[32], child[32];
    uint64_t all[1] = {1000};
    int failures = wk_check("earlier-refusal height folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 0, 1, 0, digest));
    wk_txid(last, WK_DEEP_CHAIN, WK_LEVEL_TOP - 3);
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(ndb.db,
        "UPDATE zslp_validity SET status=0,reason='ancestry_depth_exceeded' "
        "WHERE txid=?", -1, &s, NULL);
    sqlite3_bind_blob(s, 1, last, 32, SQLITE_STATIC);
    sqlite3_step(s);  // raw-sql-ok:test-fixture-update
    sqlite3_finalize(s);
    wk_txid(child, WK_WIDE_CHILD, 2);
    wk_txid(genesis, WK_GENESIS_DEEP, 0);
    wk_seed_send(&ndb, child, 2, genesis, all, 1);
    wk_spend(&ndb, child, 0, last, 1, 2);
    failures += wk_check("a later walk settles the earlier refusal",
                         wk_fold(&ndb, WK_THREAD_LARGE, 2, 2, 0, NULL) &&
                         wk_is(&ndb, WK_DEEP_CHAIN, WK_LEVEL_TOP - 3,
                               ZSLP_VALIDITY_VALID, "valid_send") &&
                         wk_is(&ndb, WK_WIDE_CHILD, 2, ZSLP_VALIDITY_VALID,
                               "valid_send"));
    node_db_close(&ndb);
    return failures;
}

/* ── Interruption: applying a height again changes nothing ─────────── */

struct wk_fixture {
    void (*seed)(struct node_db *ndb);
    int from;
    int tip;
};

struct wk_ledger_state {
    bool ok;
    char print[65];
    char running[65];
};

/* Stops the fold at one walk's failed allocation, part way through a height,
 * and retries that height the way the next tick does. */
static bool wk_fold_stopped_at_walk(struct node_db *ndb,
                                    const struct wk_fixture *fixture,
                                    unsigned nth_walk, uint8_t digest[32])
{
    uint8_t next[32];
    bool ok = true;
    zcl_alloc_fault_fail_nth("zslp_validity_walk", nth_walk);
    for (int h = fixture->from; h <= fixture->tip && ok; h++) {
        ok = zslp_ledger_apply_height(ndb, h, digest, next) ||
             zslp_ledger_apply_height(ndb, h, digest, next);
        if (ok)
            memcpy(digest, next, sizeof(next));
    }
    bool stopped = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    return ok && stopped;
}

static bool wk_fold_by_ticks(struct node_db *ndb, int last_tip,
                             uint8_t digest[32])
{
    bool ok = true;
    for (int tip = 0; tip <= last_tip && ok; tip++)
        ok = wk_backfill_to_tip(ndb, WK_THREAD_LARGE, tip);
    return ok && zslp_ledger_get_cursor(ndb, NULL, digest);
}

/* mode: -1 one fold, -2 every height applied twice, -3 one height per tick,
 * otherwise the walk number to stop at. */
static struct wk_ledger_state wk_fold_interruptible(
    const struct wk_fixture *fixture, int mode)
{
    struct wk_ledger_state state;
    struct node_db ndb;
    uint8_t digest[32] = {0};
    memset(&state, 0, sizeof(state));
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return state;
    fixture->seed(&ndb);
    if (mode == -3)
        state.ok = wk_fold_by_ticks(&ndb, fixture->tip, digest);
    else if (mode < 0)
        state.ok = wk_fold(&ndb, WK_THREAD_LARGE, fixture->from, fixture->tip,
                           mode == -2 ? 1 : 0, digest);
    else
        state.ok = wk_fold_stopped_at_walk(&ndb, fixture, (unsigned)mode,
                                           digest);
    wk_fingerprint(&ndb, state.print);
    wk_hex(digest, state.running);
    node_db_close(&ndb);
    return state;
}

static int wk_check_same_ledger(const struct wk_fixture *fixture,
                                const char *what, int mode,
                                const struct wk_ledger_state *whole)
{
    struct wk_ledger_state state = wk_fold_interruptible(fixture, mode);
    return wk_check(what, whole->ok && state.ok &&
                          strcmp(whole->print, state.print) == 0 &&
                          strcmp(whole->running, state.running) == 0);
}

static int wk_check_stops(const struct wk_fixture *fixture, const int *stops,
                          size_t count, const struct wk_ledger_state *whole)
{
    bool same = true;
    for (size_t i = 0; i < count; i++)
        same = wk_check_same_ledger(fixture, "stopping a height part way and "
                                    "retrying keeps the rows and digest",
                                    stops[i], whole) == 0 && same;
    return same ? 0 : 1;
}

static void wk_seed_interrupted(struct node_db *ndb)
{
    wk_seed_chain(ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, WK_DEEP_LEVELS);
    wk_seed_deep_child(ndb, 2);
    wk_seed_wide(ndb, 3);
}

static int wk_case_interrupted(void)
{
    static const struct wk_fixture fixture = {wk_seed_interrupted, 0, 4};
    struct wk_ledger_state whole = wk_fold_interruptible(&fixture, -1);
    int failures = wk_check("interruption fixture folds", whole.ok);
    failures += wk_check_same_ledger(&fixture,
        "applying each height twice keeps the rows and digest", -2, &whole);
    failures += wk_check_same_ledger(&fixture,
        "folding one height per tick keeps the rows and digest", -3, &whole);
    /* Walks 1-44 are refused, 45 settles the chain within the cap, 46 is the
     * sweep settling the rest, 600 is inside the wide height's scan and 1150 is
     * its sweep. */
    static const int stops[] = {1, 20, 44, 45, 46, 600, 1150};
    failures += wk_check_stops(&fixture, stops,
                               sizeof(stops) / sizeof(stops[0]), &whole);
    return failures;
}

/* The chain sits below where this fold starts, as rows from before it. */
static void wk_seed_held_twice_above_chain(struct node_db *ndb)
{
    wk_seed_held_twice(ndb, 1, 2);
}

/* Walk 1 refuses T for work, 2-1101 settle its parents, and 1102 is the sweep
 * finding T past the depth cap; a retried scan that walked T again would store
 * that different reason. */
static int wk_case_refusal_reason_stands(void)
{
    static const struct wk_fixture fixture =
        {wk_seed_held_twice_above_chain, 2, 2};
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("reason fixture opens a database", false);
    wk_seed_held_twice_above_chain(&ndb);
    int failures = wk_check("reason fixture folds",
                            wk_fold(&ndb, WK_THREAD_LARGE, 2, 2, 0, NULL));
    failures += wk_check("a row that stays refused keeps its reason",
                         wk_is(&ndb, WK_HELD_TWICE, 0, ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_work_exceeded"));
    node_db_close(&ndb);
    struct wk_ledger_state whole = wk_fold_interruptible(&fixture, -1);
    failures += wk_check_same_ledger(&fixture,
        "applying that height twice keeps the rows and digest", -2, &whole);
    static const int stops[] = {1102};
    failures += wk_check_stops(&fixture, stops,
                               sizeof(stops) / sizeof(stops[0]), &whole);
    return failures;
}

/* ── Sweep: a height keeps passing while a pass settles something ──── */

#define WK_PASSES_LEVELS 520

static void wk_seed_passes(struct node_db *ndb)
{
    wk_seed_chain(ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, WK_PASSES_LEVELS);
}

static int wk_case_sweep_passes(void)
{
    static const struct wk_fixture fixture = {wk_seed_passes, 0, 1};
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("multi-pass fixture opens a database", false);
    wk_seed_passes(&ndb);
    struct wk_counts counts;
    bool folded = wk_fold_counted(&ndb, 1, &counts);
    printf("zslp walk: multi-pass height ran %ld statements\n",
           counts.statements);
    int failures = wk_check("multi-pass height folds", folded);
    failures += wk_check("every level settles in its own height",
                         wk_count(&ndb, "SELECT COUNT(*) FROM zslp_validity "
                                        "WHERE status=0") == 0);
    failures += wk_check("the newest level is VALID",
                         wk_is(&ndb, WK_DEEP_CHAIN,
                               WK_LEVEL_TOP - WK_PASSES_LEVELS,
                               ZSLP_VALIDITY_VALID, "valid_send"));
    failures += wk_check("only its output stays unspent",
                         zslp_ledger_unspent_count(&ndb) == 1);
    node_db_close(&ndb);

    struct wk_ledger_state whole = wk_fold_interruptible(&fixture, -1);
    /* Walks 1-264 are refused, 265 settles the first levels, 266-272 are the
     * first pass refused again, 273 settles the next levels, and 274 is the
     * second pass settling the rest. */
    static const int stops[] = {274};
    failures += wk_check_stops(&fixture, stops,
                               sizeof(stops) / sizeof(stops[0]), &whole);
    return failures;
}

/* ── Refusals that must not hang or lose the height ───────────────── */

static int wk_case_cycle(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("cycle fixture opens a database", false);
    uint8_t a[32], b[32], self[32];
    uint64_t one[1] = {1};
    wk_txid(a, WK_CYCLE_A, 0);
    wk_txid(b, WK_CYCLE_B, 0);
    wk_txid(self, WK_SELF_LOOP, 0);
    wk_seed_send(&ndb, a, 1, a, one, 1);
    wk_seed_send(&ndb, b, 1, a, one, 1);
    wk_seed_send(&ndb, self, 1, self, one, 1);
    wk_spend(&ndb, a, 0, b, 1, 1);
    wk_spend(&ndb, b, 0, a, 1, 1);
    wk_spend(&ndb, self, 0, self, 1, 1);
    int failures = wk_check("damaged inputs that form a loop still fold",
                            wk_fold(&ndb, WK_THREAD_LARGE, 1, 1, 0, NULL));
    failures += wk_check("a loop of two is UNKNOWN",
                         wk_is(&ndb, WK_CYCLE_A, 0, ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_depth_exceeded"));
    failures += wk_check("a transaction spending itself is UNKNOWN",
                         wk_is(&ndb, WK_SELF_LOOP, 0, ZSLP_VALIDITY_UNKNOWN,
                               "ancestry_depth_exceeded"));
    node_db_close(&ndb);
    return failures;
}

static int wk_case_allocation_failure(void)
{
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:"))
        return wk_check("allocation fixture opens a database", false);
    wk_seed_chain(&ndb, 1, WK_GENESIS_DEEP, WK_DEEP_CHAIN, 3);
    uint8_t digest[32] = {0}, next[32];
    zcl_alloc_fault_fail_next("zslp_validity_walk");
    bool refused = !zslp_ledger_apply_height(&ndb, 1, digest, next);
    zcl_alloc_fault_clear();
    int failures = wk_check("a failed allocation refuses the height", refused);
    failures += wk_check("a refused height stores no verdict",
                         wk_count(&ndb,
                                  "SELECT COUNT(*) FROM zslp_validity") == 0);
    failures += wk_check("the same height applies on the retry",
                         zslp_ledger_apply_height(&ndb, 1, digest, next) &&
                         wk_is(&ndb, WK_DEEP_CHAIN, WK_LEVEL_TOP - 3,
                               ZSLP_VALIDITY_VALID, "valid_send"));
    node_db_close(&ndb);
    return failures;
}

int zslp_validity_walk_tests(void)
{
    int failures = 0;
    failures += wk_case_pinned();
    failures += wk_case_thread_sizes();
    failures += wk_case_double_inputs();
    failures += wk_case_wide();
    failures += wk_case_lone();
    failures += wk_case_held();
    failures += wk_case_many_edges();
    failures += wk_case_deep_settles();
    failures += wk_case_deep_unknown();
    failures += wk_case_earlier_refusal_settles();
    failures += wk_case_interrupted();
    failures += wk_case_refusal_reason_stands();
    failures += wk_case_sweep_passes();
    failures += wk_case_cycle();
    failures += wk_case_allocation_failure();
    return failures;
}
