/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for stage_repair_coin_backfill — the guarded multi-coin backfill for
 * prevout_unresolved frontier holes. Cases 1-13 (numbered in the per-case
 * comments below) cover the happy path plus every adversarial guard: a
 * spent-mid-range prevout, an off-chain creator, a delta-window creator, a
 * scan gap, a present-but-unusable coin, coinbase immaturity, a multi-coin
 * block, resume/frontier-race integrity, the owner gate + value bounds +
 * round cap, and chain-rebind-on-reorg/terminal-linkage.
 *
 * Fixture model (mirrors test_stage_reducer_unwedge.c): a synthetic
 * progress.kv (hole row, cursors, coins_applied frontier, utxo_apply_log +
 * inverse-delta rows defining the delta horizon) plus an in-memory 20-block
 * chain with REAL double-SHA256 header/tx hashing so the scan's prev-link and
 * terminal-linkage checks operate on genuine hash chains. The chain is served
 * through the coin_backfill_io seam; a fixture node_db (":memory:") provides
 * the txid -> creating-height txindex.
 *
 * Geometry (heights 0..19):
 *   creator T_A @5 (12 outputs), T_B @7, midspend @8 (optional),
 *   delta-window creator T_C @11, delta horizon = 10 (utxo_apply_log+delta
 *   rows 10..13), coins_applied frontier = 14, scan top = 13, hole H = 16
 *   (spender tx, variant-controlled inputs), second spender of (T_A,0) @18
 *   for the MARKER_SEEN-at-H' case. */

#include "test/test_core.h"
#include "test/block_fixtures.h"
#include "bloom/merkle.h"
#include "coins/coins.h"
#include "validation/main_state.h"
#include "models/tx_index.h"

#include "jobs/stage_repair_coin_backfill.h"
#include "jobs/created_outputs_index.h"
#include "services/block_index_loader.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "event/event.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Mirrors app/jobs/src/stage_repair_coin_backfill_internal.h (a src-private
 * header; same idiom as test_utxo_apply_stage.c's delta-internal mirror). */
enum coin_backfill_scan_verdict {
    COIN_SCAN_IN_PROGRESS,
    COIN_SCAN_CLEAN,
    COIN_SCAN_SPENT_FOUND,
    COIN_SCAN_GAP,
    COIN_SCAN_CHAIN_REBOUND,
    COIN_SCAN_WINDOW_OVER_BUDGET,
};
enum coin_backfill_scan_verdict coin_backfill_scan_step(
    struct sqlite3 *db, struct main_state *ms, const struct coin_backfill_io *io,
    int hole_height, const struct uint256 *hole_hash,
    const struct coin_backfill_outpoint *set, size_t n,
    int floor_height, int top_height, int frontier_at_start,
    int max_blocks, int64_t max_wall_ms,
    int *out_next_height, int *out_spent_height, uint8_t out_spender_txid[32]);

/* Mirrors app/jobs/src/stage_repair_coin_backfill_util.h (src-private): the
 * dedicated test hook clearing the per-(H,holehash,status) page latches so
 * each fixture's refusal-paging assertions run isolated. Paired with
 * blocker_reset_for_testing per the hook's contract. */
void coin_backfill_reset_latches_for_testing(void);
bool coin_backfill_refusal_marker_decode(const uint8_t *blob, size_t len,
                                         bool *out_active,
                                         bool *out_legacy_spent,
                                         bool *out_legacy_txindex_miss);

/* STEP-2A pending-prevout HOLD signal writer (src-private util) — lets this
 * test prove coin_backfill fires from the NON-TERMINAL pending signal alone,
 * with NO terminal ok=0 row and the script_validate cursor frozen at the hole. */
bool coin_backfill_pending_prevout_set(struct sqlite3 *db, int height,
                                       const struct uint256 *block_hash,
                                       const struct uint256 *fail_txid,
                                       int fail_vin);

#define CBT(desc, expr) do { \
    printf("coin_backfill: %s... ", (desc)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define CB_ACK_ENV "ZCL_REDUCER_COIN_BACKFILL_ACK"

#define CB_N            20
#define CB_CREATOR       5   /* T_A: 12 outputs, vout 0 is the lost coin */
#define CB_CREATOR_B     7   /* T_B: second creator for the multi-coin case */
#define CB_MID           8   /* optional mid-range spender of (T_A,0) */
#define CB_DELTA_CREATOR 11  /* T_C: created INSIDE the delta window */
#define CB_HORIZON      10   /* lowest contiguous utxo_apply_log+delta height */
#define CB_FRONTIER     14   /* coins_applied_height == utxo_apply cursor */
#define CB_TOP          13   /* frontier - 1 */
#define CB_HOLE         16   /* prevout_unresolved hole height H */
#define CB_HOLE2        18   /* second spender of (T_A,0) — MARKER_SEEN at H' */

#define CB_TA0_VALUE 1127138452LL
#define CB_TRY_CAP   50

enum cb_variant {
    CBV_TA0 = 0,     /* hole block spends (T_A,0)                   */
    CBV_TA0_TB0,     /* spends (T_A,0) + (T_B,0) — multi-coin        */
    CBV_TA0_TC0,     /* spends (T_A,0) + (T_C,0) — delta-window mix  */
    CBV_CB5,         /* spends (coinbase@5, 0) — immature            */
    CBV_TA0_TO_9,    /* spends (T_A,0..9) — round-cap fixture        */
    CBV_BOGUS,       /* spends an outpoint whose txindex row lies    */
    CBV_TA0_CREATOR_SPEND, /* like CBV_TA0 but the CREATOR block's vtx[2]
                            * already spends (T_A,0) — first-iteration
                            * h == floor == creator boundary (TG-F2) */
    CBV_TA0_EMPTY_SCRIPT,  /* like CBV_TA0 but T_A vout0 has a zero-length
                            * scriptPubKey (TG-F4) */
};

/* ── EV_OPERATOR_NEEDED observer ───────────────────────────────────── */

static _Atomic int g_cb_op_needed;

static void cb_op_needed_observer(enum event_type type, uint32_t peer_id,
                                  const void *payload, uint32_t payload_len,
                                  void *ctx)
{
    (void)type; (void)peer_id; (void)ctx;
    char buf[256] = {0};
    if (payload && payload_len > 0) {
        uint32_t n = payload_len < sizeof(buf) - 1
                         ? payload_len : (uint32_t)(sizeof(buf) - 1);
        memcpy(buf, payload, n);
    }
    if (strstr(buf, "coin_backfill"))
        atomic_fetch_add(&g_cb_op_needed, 1);
}

/* ── In-memory chain with real hashing ─────────────────────────────── */

struct cb_chain {
    int n;
    uint32_t salt;
    enum cb_variant variant;
    int64_t ta0_value;
    bool midspend;
    int bump_from;       /* heights >= this get the extra time bump */
    uint32_t bump;
    struct block bodies[CB_N];
    struct uint256 hashes[CB_N];
    bool missing[CB_N];
    int reads;
};

static void cb_p2pkh(uint8_t script[25], uint8_t tag)
{
    script[0] = 0x76; script[1] = 0xa9; script[2] = 0x14;
    memset(script + 3, tag, 20);
    script[23] = 0x88; script[24] = 0xac;
}

static bool cb_make_coinbase(struct transaction *tx, int h)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1)) return false;
    outpoint_set_null(&tx->vin[0].prevout);
    tx->vin[0].sequence = UINT32_MAX;
    tx->vout[0].value = 1000 + h;
    uint8_t s[25];
    cb_p2pkh(s, (uint8_t)(0xC0 + h));
    script_set(&tx->vout[0].script_pub_key, s, 25);
    transaction_compute_hash(tx);
    return true;
}

static bool cb_make_spend_tx(struct transaction *tx,
                             const struct outpoint *ins, size_t nin,
                             const int64_t *vals, size_t nout, uint8_t tag)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, nin, nout)) return false;
    for (size_t i = 0; i < nin; i++) {
        tx->vin[i].prevout = ins[i];
        tx->vin[i].sequence = UINT32_MAX;
    }
    for (size_t j = 0; j < nout; j++) {
        tx->vout[j].value = vals[j];
        uint8_t s[25];
        cb_p2pkh(s, (uint8_t)(tag + j));
        script_set(&tx->vout[j].script_pub_key, s, 25);
    }
    transaction_compute_hash(tx);
    return true;
}

static void cb_fake_outpoint(struct outpoint *op, uint8_t tag)
{
    memset(op->hash.data, tag, 32);
    op->n = 0;
}

static void cb_bogus_txid(struct uint256 *out)
{
    memset(out->data, 0xB6, 32);
}

/* The non-coinbase tx of a fixture block, or NULL. */
static const struct transaction *cb_tx_at(const struct cb_chain *ch, int h)
{
    if (h < 0 || h >= ch->n || ch->bodies[h].num_vtx < 2)
        return NULL;
    return &ch->bodies[h].vtx[1];
}

/* (Re)build the body at height h from the chain config. bodies[h] must be
 * block_init'd or previously built (it is freed first). The prev-link uses
 * the CURRENT hashes[h-1], so callers rebuilding a suffix update hashes
 * progressively. */
static bool cb_build_body(struct cb_chain *ch, int h)
{
    struct block *b = &ch->bodies[h];
    block_free(b);
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1700000000u + ch->salt * 100000u + (uint32_t)h * 7u +
                      (h >= ch->bump_from ? ch->bump : 0u);
    b->header.nBits = 0x1f07ffff;
    if (h > 0)
        b->header.hashPrevBlock = ch->hashes[h - 1];

    struct transaction extra, extra2;
    bool have_extra = false, have_extra2 = false;
    transaction_init(&extra);
    transaction_init(&extra2);

    if (h == CB_CREATOR) {
        struct outpoint in;
        cb_fake_outpoint(&in, 0xAA);
        int64_t vals[12];
        vals[0] = ch->ta0_value;
        for (int i = 1; i < 12; i++)
            vals[i] = 2000 + i;
        have_extra = cb_make_spend_tx(&extra, &in, 1, vals, 12, 0xA0);
        if (!have_extra) return false;
        if (ch->variant == CBV_TA0_EMPTY_SCRIPT) {
            /* Zero-length scriptPubKey on the lost coin; the txid must be
             * recomputed over the emptied script (TG-F4). */
            extra.vout[0].script_pub_key.size = 0;
            transaction_compute_hash(&extra);
        }
        if (ch->variant == CBV_TA0_CREATOR_SPEND) {
            /* vtx[2] spends (T_A,0) INSIDE the creator block: the scan's
             * very first iteration (h == floor == creator) must see it. */
            struct outpoint in2 = { .hash = extra.hash, .n = 0 };
            int64_t v2[1] = { 700 };
            have_extra2 = cb_make_spend_tx(&extra2, &in2, 1, v2, 1, 0xDA);
            if (!have_extra2) {
                transaction_free(&extra);
                return false;
            }
        }
    } else if (h == CB_CREATOR_B) {
        struct outpoint in;
        cb_fake_outpoint(&in, 0xBB);
        int64_t vals[2] = { 3000, 3001 };
        have_extra = cb_make_spend_tx(&extra, &in, 1, vals, 2, 0xB0);
        if (!have_extra) return false;
    } else if (h == CB_MID && ch->midspend) {
        const struct transaction *ta = cb_tx_at(ch, CB_CREATOR);
        if (!ta) return false;
        struct outpoint in = { .hash = ta->hash, .n = 0 };
        int64_t vals[1] = { 400 };
        have_extra = cb_make_spend_tx(&extra, &in, 1, vals, 1, 0xD0);
        if (!have_extra) return false;
    } else if (h == CB_DELTA_CREATOR) {
        struct outpoint in;
        cb_fake_outpoint(&in, 0xCC);
        int64_t vals[1] = { 4000 };
        have_extra = cb_make_spend_tx(&extra, &in, 1, vals, 1, 0xE0);
        if (!have_extra) return false;
    } else if (h == CB_HOLE) {
        const struct transaction *ta = cb_tx_at(ch, CB_CREATOR);
        const struct transaction *tb = cb_tx_at(ch, CB_CREATOR_B);
        const struct transaction *tc = cb_tx_at(ch, CB_DELTA_CREATOR);
        const struct transaction *cb5 =
            (CB_CREATOR < ch->n && ch->bodies[CB_CREATOR].num_vtx >= 1)
                ? &ch->bodies[CB_CREATOR].vtx[0] : NULL;
        if (!ta || !tb || !tc || !cb5) return false;
        struct outpoint ins[10];
        size_t nin = 0;
        switch (ch->variant) {
        case CBV_TA0:
        case CBV_TA0_CREATOR_SPEND:
        case CBV_TA0_EMPTY_SCRIPT:
            ins[0].hash = ta->hash; ins[0].n = 0; nin = 1;
            break;
        case CBV_TA0_TB0:
            ins[0].hash = ta->hash; ins[0].n = 0;
            ins[1].hash = tb->hash; ins[1].n = 0; nin = 2;
            break;
        case CBV_TA0_TC0:
            ins[0].hash = ta->hash; ins[0].n = 0;
            ins[1].hash = tc->hash; ins[1].n = 0; nin = 2;
            break;
        case CBV_CB5:
            ins[0].hash = cb5->hash; ins[0].n = 0; nin = 1;
            break;
        case CBV_TA0_TO_9:
            for (uint32_t i = 0; i < 10; i++) {
                ins[i].hash = ta->hash;
                ins[i].n = i;
            }
            nin = 10;
            break;
        case CBV_BOGUS:
            cb_bogus_txid(&ins[0].hash); ins[0].n = 0; nin = 1;
            break;
        }
        int64_t vals[1] = { 500 };
        have_extra = cb_make_spend_tx(&extra, ins, nin, vals, 1, 0xF0);
        if (!have_extra) return false;
    } else if (h == CB_HOLE2) {
        const struct transaction *ta = cb_tx_at(ch, CB_CREATOR);
        if (!ta) return false;
        struct outpoint in = { .hash = ta->hash, .n = 0 };
        int64_t vals[1] = { 600 };
        have_extra = cb_make_spend_tx(&extra, &in, 1, vals, 1, 0xF8);
        if (!have_extra) return false;
    }

    size_t ntx = 1 + (have_extra ? 1u : 0u) + (have_extra2 ? 1u : 0u);
    b->vtx = zcl_calloc(ntx, sizeof(struct transaction), "cb_test_vtx");
    if (!b->vtx) {
        if (have_extra) transaction_free(&extra);
        if (have_extra2) transaction_free(&extra2);
        return false;
    }
    b->num_vtx = ntx;
    if (!cb_make_coinbase(&b->vtx[0], h)) {
        if (have_extra) transaction_free(&extra);
        if (have_extra2) transaction_free(&extra2);
        return false;
    }
    if (have_extra)
        b->vtx[1] = extra;   /* ownership moves into the block */
    if (have_extra2)
        b->vtx[2] = extra2;  /* only ever set together with have_extra */

    struct uint256 txids[3];
    for (size_t i = 0; i < ntx; i++)
        txids[i] = b->vtx[i].hash;
    b->header.hashMerkleRoot = compute_merkle_root(txids, ntx);
    block_get_hash(b, &ch->hashes[h]);
    return true;
}

static bool cb_chain_build_range(struct cb_chain *ch, int from)
{
    for (int h = from; h < ch->n; h++) {
        if (!cb_build_body(ch, h))
            return false;
    }
    return true;
}

static bool cb_chain_init(struct cb_chain *ch, uint32_t salt,
                          enum cb_variant variant, int64_t ta0_value,
                          bool midspend)
{
    memset(ch, 0, sizeof(*ch));
    ch->n = CB_N;
    ch->salt = salt;
    ch->variant = variant;
    ch->ta0_value = ta0_value;
    ch->midspend = midspend;
    ch->bump_from = CB_N;     /* no bump initially */
    for (int h = 0; h < CB_N; h++)
        block_init(&ch->bodies[h]);
    return cb_chain_build_range(ch, 0);
}

/* Reorg: replace every block at height >= fork with a different (time-bumped)
 * branch, prev-linked through the new hashes. Tx content (and so txids) is
 * unchanged — only headers/hashes differ. */
static bool cb_chain_reorg_from(struct cb_chain *ch, int fork)
{
    ch->bump_from = fork;
    ch->bump += 1000000u;
    return cb_chain_build_range(ch, fork);
}

/* Adversarial single-block swap: rebuild ONLY height h (new hash), leaving
 * the children's prev-links pointing at the OLD hash — the torn/oscillation
 * io state the insert-time top_hash re-check must catch. */
static bool cb_chain_swap_one(struct cb_chain *ch, int h)
{
    int saved_from = ch->bump_from;
    ch->bump += 1000000u;
    ch->bump_from = h;
    bool ok = cb_build_body(ch, h);
    ch->bump_from = saved_from;
    return ok;
}

static void cb_chain_free(struct cb_chain *ch)
{
    for (int h = 0; h < ch->n; h++)
        block_free(&ch->bodies[h]);
    memset(ch, 0, sizeof(*ch));
}

static bool cb_read_block(void *user, int height, struct block *blk,
                          struct uint256 *hash)
{
    struct cb_chain *ch = user;
    if (!ch || !blk || !hash)
        return false;
    ch->reads++;
    if (height < 0 || height >= ch->n || ch->missing[height])
        return false;
    if (!test_block_copy(blk, &ch->bodies[height], "cb_test_blk"))
        return false;
    *hash = ch->hashes[height];
    return true;
}

/* ── progress.kv seeding (mirrors the production schemas) ──────────── */

static bool cb_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);  // raw-sql-ok:test-seed
    if (rc != SQLITE_OK) {
        printf("coin_backfill: SQL failed: %s\n", err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }
    return true;
}

static int cb_query_int(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int cb_cursor(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    int v = -999;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name=?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            v = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

static bool cb_seed_cursor(sqlite3 *db, const char *name, int cursor)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
            "VALUES(?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, cursor);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static int cb_meta_count_like(sqlite3 *db, const char *pattern)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM progress_meta WHERE key LIKE ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, pattern, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            v = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

/* Count repair_marker rows of a given kind (the coin_backfill.refused /
 * coin_backfill.scan namespaces now live there, not in progress_meta). */
static int cb_marker_count(sqlite3 *db, const char *kind)
{
    sqlite3_stmt *st = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM repair_marker WHERE kind = ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, kind, -1, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW)  // raw-sql-ok:test-readback
            v = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

static bool cb_put_script_row(sqlite3 *db, int height, const char *status,
                              int ok_flag, const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO script_validate_log"
            "(height,status,ok,tx_count,input_count,first_failure_txid,"
            " first_failure_vin,validated_at,block_hash) "
            "VALUES(?,?,?,2,1,NULL,0,1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_text(st, 2, status, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, ok_flag);
    sqlite3_bind_blob(st, 4, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool cb_put_utxo_row_and_delta(sqlite3 *db, int height,
                                      const struct uint256 *branch_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_log"
            "(height,status,ok,spent_count,added_count,total_value_delta,"
            " applied_at) VALUES(?,'applied',1,0,1,0,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok)
        return false;

    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO utxo_apply_delta"
            "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, branch_hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_zeroblob(st, 3, 0);
    sqlite3_bind_zeroblob(st, 4, 0);
    ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool cb_put_tip_row(sqlite3 *db, int height,
                           const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) VALUES(?,'finalized',1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, height);
    sqlite3_bind_blob(st, 2, hash->data, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

static bool cb_set_coins_applied(sqlite3 *db, int64_t height)
{
    uint8_t blob[8];
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)((uint64_t)height >> (8 * i));
    return progress_meta_set(db, COINS_APPLIED_HEIGHT_KEY, blob, sizeof(blob));
}

static bool cb_update_hole_hash(sqlite3 *db, int height,
                                const struct uint256 *hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "UPDATE script_validate_log SET block_hash=? WHERE height=?",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, hash->data, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, height);
    bool ok = sqlite3_step(st) == SQLITE_DONE;  // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    return ok;
}

/* Flip one byte inside the persisted scan record's set_digest field
 * (payload layout per the internal-header contract:
 * [next i32][frontier i32][last_scanned_hash 32][set_digest 32]...). */
static bool cb_tamper_scan_digest(sqlite3 *db)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height, hash, payload FROM repair_marker "
            "WHERE kind = 'coin_backfill.scan' LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = false;
    int64_t height = 0;
    uint8_t hash[32] = {0};
    uint8_t buf[256];
    size_t len = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {  // raw-sql-ok:test-readback
        height = sqlite3_column_int64(st, 0);
        const void *h = sqlite3_column_blob(st, 1);
        int hl = sqlite3_column_bytes(st, 1);
        const void *v = sqlite3_column_blob(st, 2);
        int vl = sqlite3_column_bytes(st, 2);
        if (h && hl == 32 && v && vl > 45 && vl <= (int)sizeof(buf)) {
            memcpy(hash, h, 32);
            memcpy(buf, v, (size_t)vl);
            len = (size_t)vl;
            ok = true;
        }
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;
    buf[45] ^= 0x5a;   /* inside set_digest [40..71] */
    return repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                              height, hash, buf, len);
}

/* ── Fixture ───────────────────────────────────────────────────────── */

struct cbf {
    char dir[256];
    struct main_state ms;
    bool ms_init;
    struct node_db ndb;
    bool ndb_open;
    bool store_open;
    struct cb_chain chain;
    struct coin_backfill_io io;
    sqlite3 *db;
    int tip_rows_before;
};

static bool cb_save_tx_row(struct node_db *ndb, const struct uint256 *txid,
                           const struct uint256 *block_hash, int height,
                           int tx_index, bool is_coinbase)
{
    struct db_tx_index row;
    memset(&row, 0, sizeof(row));
    memcpy(row.txid, txid->data, 32);
    memcpy(row.block_hash, block_hash->data, 32);
    row.block_height = height;
    row.tx_index = tx_index;
    row.file_num = 0;
    row.file_pos = 0;
    row.is_coinbase = is_coinbase;
    return db_tx_save(ndb, &row);
}

static bool cb_seed_store(struct cbf *fx)
{
    sqlite3 *db = fx->db;
    if (!progress_meta_table_ensure(db) ||
        !coins_kv_ensure_schema(db) ||
        !created_outputs_index_ensure_schema(db))
        return false;

    /* Mirrors of the production schemas (script_validate_log_store.c,
     * utxo_apply_log_store.c, utxo_apply_delta.c). */
    if (!cb_exec(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, tx_count INTEGER NOT NULL,"
            " input_count INTEGER NOT NULL, first_failure_txid BLOB,"
            " first_failure_vin INTEGER, first_failure_serror INTEGER,"
            " validated_at INTEGER NOT NULL, block_hash BLOB)") ||
        !cb_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            " height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
            " ok INTEGER NOT NULL, spent_count INTEGER NOT NULL,"
            " added_count INTEGER NOT NULL,"
            " total_value_delta INTEGER NOT NULL,"
            " first_failure_kind TEXT, first_failure_detail BLOB,"
            " applied_at INTEGER NOT NULL)") ||
        !cb_exec(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            " height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            " spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL)") ||
        !cb_exec(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            " height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            " tip_hash BLOB)"))
        return false;

    if (!cb_seed_cursor(db, "validate_headers", CB_HOLE + 2) ||
        !cb_seed_cursor(db, "body_fetch", CB_HOLE + 2) ||
        !cb_seed_cursor(db, "body_persist", CB_HOLE + 1) ||
        !cb_seed_cursor(db, "script_validate", CB_HOLE + 1) ||
        !cb_seed_cursor(db, "proof_validate", CB_HOLE + 1) ||
        !cb_seed_cursor(db, "utxo_apply", CB_FRONTIER) ||
        !cb_seed_cursor(db, "tip_finalize", CB_FRONTIER))
        return false;

    /* Delta window: contiguous utxo_apply_log + inverse-delta rows in
     * [CB_HORIZON .. CB_FRONTIER-1]; nothing below — the lost-coin era. */
    for (int h = CB_HORIZON; h < CB_FRONTIER; h++) {
        if (!cb_put_utxo_row_and_delta(db, h, &fx->chain.hashes[h]))
            return false;
        if (!cb_put_tip_row(db, h, &fx->chain.hashes[h]))
            return false;
    }
    if (!cb_set_coins_applied(db, CB_FRONTIER))
        return false;

    /* The hole row: prevout_unresolved at H, hash-bound to the fixture
     * chain's block H. */
    if (!cb_put_script_row(db, CB_HOLE, "prevout_unresolved", 0,
                           &fx->chain.hashes[CB_HOLE]))
        return false;

    fx->tip_rows_before =
        cb_query_int(db, "SELECT COUNT(*) FROM tip_finalize_log");
    return fx->tip_rows_before >= 0;
}

static bool cb_setup(struct cbf *fx, const char *tag, uint32_t salt,
                     enum cb_variant variant, int64_t ta0_value,
                     bool midspend, bool seed_baseline_coin)
{
    memset(fx, 0, sizeof(*fx));
    if (!cb_chain_init(&fx->chain, salt, variant, ta0_value, midspend))
        return false;

    test_make_tmpdir(fx->dir, sizeof(fx->dir), "coin_backfill", tag);
    if (!progress_store_open(fx->dir))
        return false;
    fx->store_open = true;
    fx->db = progress_store_db();
    if (!fx->db || !cb_seed_store(fx))
        return false;

    if (!node_db_open(&fx->ndb, ":memory:"))
        return false;
    fx->ndb_open = true;

    /* txindex rows. tx_index is deliberately WRONG for T_A (it is vtx[1]) —
     * the design forbids trusting row.tx_index; the creator must be located
     * by recomputed txid. The BOGUS row maps a txid to a block that does NOT
     * contain it (off-chain-creator case). */
    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    const struct transaction *tb = cb_tx_at(&fx->chain, CB_CREATOR_B);
    const struct transaction *tc = cb_tx_at(&fx->chain, CB_DELTA_CREATOR);
    const struct transaction *cb5 = &fx->chain.bodies[CB_CREATOR].vtx[0];
    struct uint256 bogus;
    cb_bogus_txid(&bogus);
    if (!ta || !tb || !tc ||
        !cb_save_tx_row(&fx->ndb, &ta->hash,
                        &fx->chain.hashes[CB_CREATOR], CB_CREATOR, 0, false) ||
        !cb_save_tx_row(&fx->ndb, &tb->hash,
                        &fx->chain.hashes[CB_CREATOR_B], CB_CREATOR_B, 1,
                        false) ||
        !cb_save_tx_row(&fx->ndb, &tc->hash,
                        &fx->chain.hashes[CB_DELTA_CREATOR], CB_DELTA_CREATOR,
                        1, false) ||
        !cb_save_tx_row(&fx->ndb, &cb5->hash,
                        &fx->chain.hashes[CB_CREATOR], CB_CREATOR, 0, true) ||
        !cb_save_tx_row(&fx->ndb, &bogus,
                        &fx->chain.hashes[CB_CREATOR_B], CB_CREATOR_B, 1,
                        false))
        return false;

    /* Baseline unrelated live coin (T_A,1): makes zero-coin-write asserts
     * meaningful and exercises the per-vout miss path of coins_kv_get_coins. */
    if (seed_baseline_coin) {
        if (!coins_kv_add(fx->db, ta->hash.data, 1,
                          ta->vout[1].value, CB_CREATOR, false,
                          ta->vout[1].script_pub_key.data,
                          ta->vout[1].script_pub_key.size))
            return false;
    }

    main_state_init(&fx->ms);
    fx->ms_init = true;
    fx->io.read_block = cb_read_block;
    fx->io.user = &fx->chain;
    fx->io.ndb = &fx->ndb;

    blocker_reset_for_testing();
    coin_backfill_reset_latches_for_testing();
    atomic_store(&g_cb_op_needed, 0);
    if (setenv(CB_ACK_ENV, "1", 1) != 0)
        return false;
    return true;
}

static void cb_teardown(struct cbf *fx)
{
    if (fx->ndb_open)
        node_db_close(&fx->ndb);
    if (fx->ms_init)
        main_state_free(&fx->ms);
    if (fx->store_open)
        progress_store_close();
    cb_chain_free(&fx->chain);
    if (fx->dir[0])
        test_cleanup_tmpdir(fx->dir);
}

/* Run apply ticks until the status settles (not SCANNING). Returns the final
 * status, -1 on an infrastructure failure, -2 if still scanning at the cap. */
static int cb_try_until(struct cbf *fx, struct coin_backfill_result *out)
{
    for (int i = 0; i < CB_TRY_CAP; i++) {
        memset(out, 0, sizeof(*out));
        if (!stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                            out))
            return -1;
        if (out->status != COIN_BACKFILL_SCANNING)
            return (int)out->status;
    }
    return -2;
}

static bool cb_is_refusal(int status)
{
    return status == COIN_BACKFILL_OWNER_REFUSED ||
           status == COIN_BACKFILL_REFUSED_SPENT ||
           status == COIN_BACKFILL_REFUSED_UNPROVABLE ||
           status == COIN_BACKFILL_MARKER_SEEN;
}

/* Seed / read the coin_backfill.refused repair_marker for the CB_HOLE hole. */
static bool cb_refused_seed(struct cbf *fx, const void *val, size_t len)
{
    return repair_marker_note(fx->db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                              CB_HOLE, fx->chain.hashes[CB_HOLE].data, val, len);
}

static bool cb_refused_have(struct cbf *fx, void *buf, size_t cap,
                            size_t *len, bool *present)
{
    return repair_marker_have(fx->db, REPAIR_MARKER_KIND_COIN_BACKFILL_REFUSED,
                              CB_HOLE, fx->chain.hashes[CB_HOLE].data, present,
                              buf, cap, len);
}

/* Plant a raw coin_backfill.scan record payload for the CB_HOLE hole. */
static bool cb_scan_seed(struct cbf *fx, const void *val, size_t len)
{
    return repair_marker_note(fx->db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                              CB_HOLE, fx->chain.hashes[CB_HOLE].data, val, len);
}

static enum coin_backfill_scan_verdict cb_scan(
    struct cbf *fx, const struct uint256 *hole_hash,
    const struct coin_backfill_outpoint *set, size_t n,
    int floor_h, int top_h, int frontier, int max_blocks,
    int *next_out, int *spent_out, uint8_t spender[32])
{
    return coin_backfill_scan_step(fx->db, &fx->ms, &fx->io, CB_HOLE,
                                   hole_hash, set, n, floor_h, top_h,
                                   frontier, max_blocks, 60000,
                                   next_out, spent_out, spender);
}

static void cb_fill_outpoint(struct coin_backfill_outpoint *o,
                             const struct cbf *fx, int creator_h, int tx_idx,
                             uint32_t vout, bool is_coinbase)
{
    memset(o, 0, sizeof(*o));
    const struct transaction *tx = &fx->chain.bodies[creator_h].vtx[tx_idx];
    memcpy(o->txid, tx->hash.data, 32);
    o->vout = vout;
    o->creator_height = creator_h;
    o->value = tx->vout[vout].value;
    o->script_len = tx->vout[vout].script_pub_key.size;
    memcpy(o->script, tx->vout[vout].script_pub_key.data, o->script_len);
    o->is_coinbase = is_coinbase;
}

struct cb_blocker_view {
    bool found;
    int class;
    char joined[BLOCKER_ID_MAX + BLOCKER_REASON_MAX + BLOCKER_ACTION_MAX + 8];
};

static void cb_find_blocker(struct cb_blocker_view *v)
{
    memset(v, 0, sizeof(*v));
    struct blocker_snapshot snaps[BLOCKER_CAP];
    int n = blocker_snapshot_all(snaps, BLOCKER_CAP);
    for (int i = 0; i < n; i++) {
        if (strstr(snaps[i].id, "coin_backfill")) {
            v->found = true;
            v->class = snaps[i].class;
            snprintf(v->joined, sizeof(v->joined), "%s %s %s",
                     snaps[i].id, snaps[i].reason, snaps[i].escape_action);
            return;
        }
    }
}

static bool cb_coin_present(sqlite3 *db, const struct cbf *fx, int creator_h,
                            int tx_idx, uint32_t vout)
{
    const struct transaction *tx = &fx->chain.bodies[creator_h].vtx[tx_idx];
    return coins_kv_exists(db, tx->hash.data, vout);
}

/* ── Cases ─────────────────────────────────────────────────────────── */

/* Case 1: happy path — detect, multi-chunk prev-linked scan via the internal
 * scan-step (small chunks force >= 2 resumes through the persisted record),
 * terminal linkage to the hole hash, then the insert transaction. */
static int cb_case_happy(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("happy: setup", cb_setup(fx, "happy", 1, CBV_TA0, CB_TA0_VALUE,
                                 false, true));

    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    int64_t coins_before = coins_kv_count(fx->db);

    /* STEP 3: the stale-script replay no longer uses a write-once marker
     * (termination is the body-vs-row delta), so coin_backfill no longer seeds
     * or clears one. */

    /* Detect (apply=false): applicable, no scan, no writes. */
    struct coin_backfill_result det;
    memset(&det, 0, sizeof(det));
    CBT("happy: detect call succeeds",
        stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, false, &det));
    CBT("happy: detect reports SCANNING for the hole",
        det.status == COIN_BACKFILL_SCANNING &&
        det.hole_height == CB_HOLE &&
        det.unresolved_count == 1 &&
        det.inserted_count == 0);
    CBT("happy: detect writes nothing",
        coins_kv_count(fx->db) == coins_before &&
        cb_marker_count(fx->db, "coin_backfill.scan") == 0);

    /* Multi-chunk chain-bound scan through the internal seam: max_blocks=3
     * over [5..13] forces several persisted-record resumes. */
    struct coin_backfill_outpoint *set =
        zcl_malloc(sizeof(*set), "cb_test_set");
    CBT("happy: set alloc", set != NULL);
    if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

    int next = -1, spent = -1, ip_count = 0, last_next = -1;
    uint8_t spender[32];
    enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
    bool monotonic = true;
    for (int i = 0; i < 20 && v == COIN_SCAN_IN_PROGRESS; i++) {
        v = cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                    CB_TOP, CB_FRONTIER, 3, &next, &spent, spender);
        if (v == COIN_SCAN_IN_PROGRESS) {
            ip_count++;
            if (next <= last_next)
                monotonic = false;
            last_next = next;
        }
    }
    CBT("happy: multi-chunk scan reaches CLEAN (terminal linkage to H)",
        v == COIN_SCAN_CLEAN);
    CBT("happy: scan progressed over >= 2 chunks, cursor monotonic",
        ip_count >= 2 && monotonic);
    CBT("happy: scan record persisted while in flight",
        cb_marker_count(fx->db, "coin_backfill.scan") == 1);

    /* Apply: the CLEAN proof is consumed by the insert transaction. */
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("happy: apply repairs", st == COIN_BACKFILL_REPAIRED);
    CBT("happy: result fields",
        res.hole_height == CB_HOLE &&
        res.unresolved_count == 1 &&
        res.inserted_count == 1 &&
        res.creator_floor == CB_CREATOR &&
        res.delta_horizon == CB_HORIZON &&
        res.scan_top_height == CB_TOP);

    /* The coin: exact value, height, script, non-coinbase. */
    int64_t value = 0;
    uint8_t script[64];
    size_t slen = 0;
    bool got = coins_kv_get(fx->db, ta->hash.data, 0, &value, script,
                            sizeof(script), &slen);
    CBT("happy: coin inserted with exact value/script",
        got && value == CB_TA0_VALUE && slen == 25 &&
        memcmp(script, ta->vout[0].script_pub_key.data, 25) == 0);
    struct coins c;
    coins_init(&c);
    got = coins_kv_get_coins(fx->db, ta->hash.data, &c);
    CBT("happy: coin carries creator height, not coinbase",
        got && c.height == CB_CREATOR && !c.is_coinbase);
    coins_free(&c);
    CBT("happy: exactly one new coin", coins_kv_count(fx->db) ==
        coins_before + 1);

    /* Markers + record bookkeeping. */
    char op_hex[65];
    char op_key[192];
    uint256_get_hex(&ta->hash, op_hex);
    snprintf(op_key, sizeof(op_key),
             "utxo_apply.coin_backfill.outpoint.%s:%u", op_hex, 0u);
    uint8_t blob[128];
    size_t blen = 0;
    bool found = false;
    CBT("happy: outpoint-keyed one-shot marker written",
        cb_meta_count_like(fx->db,
                           "utxo_apply.coin_backfill.outpoint.%") == 1 &&
        progress_meta_get(fx->db, op_key, blob, sizeof(blob), &blen, &found) &&
        found);
    CBT("happy: scan record consumed",
        cb_marker_count(fx->db, "coin_backfill.scan") == 0);

    /* Cursors and logs untouched; tip_finalize_log rows never deleted. */
    CBT("happy: cursors untouched",
        cb_cursor(fx->db, "script_validate") == CB_HOLE + 1 &&
        cb_cursor(fx->db, "proof_validate") == CB_HOLE + 1 &&
        cb_cursor(fx->db, "utxo_apply") == CB_FRONTIER &&
        cb_cursor(fx->db, "tip_finalize") == CB_FRONTIER);
    CBT("happy: hole row left in place (replay owns clearing it)",
        cb_query_int(fx->db,
            "SELECT ok FROM script_validate_log WHERE height=16") == 0);
    CBT("happy: no tip_finalize_log rows deleted",
        cb_query_int(fx->db, "SELECT COUNT(*) FROM tip_finalize_log") ==
            fx->tip_rows_before);

    /* Re-run: the coin now resolves -> NOT_APPLICABLE fall-through. */
    st = cb_try_until(fx, &res);
    CBT("happy: re-run is NOT_APPLICABLE",
        st == COIN_BACKFILL_NOT_APPLICABLE);

    free(set);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 2: ADVERSARIAL — coin actually spent mid-range. */
/* Case: the STEP-2A pending-prevout HOLD signal (NOT a terminal ok=0 row) is
 * what arms coin_backfill. script_validate HOLDS its cursor AT the torn hole and
 * publishes the non-terminal pending signal instead of writing ok=0 — so the
 * legacy ok=0 trigger is GONE. coin_backfill must still discover and repair the
 * hole (preserving the torn-coins class's auto-terminating remedy owner), after
 * which the frozen H* can climb. Same fixture as happy, but the ok=0 row is
 * removed, the script_validate cursor is frozen AT the hole (== hole_h), and the
 * pending signal is the only trigger present. */
static int cb_case_pending_signal_arms(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("pending_signal: setup",
        cb_setup(fx, "pending_signal", 9, CBV_TA0, CB_TA0_VALUE, false, true));

    /* Swap the legacy terminal trigger for the STEP-2A HOLD state: drop the
     * ok=0 row, freeze the script_validate cursor AT the hole, publish ONLY the
     * non-terminal pending-prevout signal. */
    CBT("pending_signal: drop the legacy ok=0 row",
        cb_exec(fx->db,
                "DELETE FROM script_validate_log WHERE height=16")); /* CB_HOLE */
    CBT("pending_signal: legacy ok=0 row is gone",
        cb_query_int(fx->db,
            "SELECT COUNT(*) FROM script_validate_log WHERE height=16") == 0);
    CBT("pending_signal: freeze script_validate cursor at the hole",
        cb_seed_cursor(fx->db, "script_validate", CB_HOLE));
    const struct transaction *spender = &fx->chain.bodies[CB_HOLE].vtx[1];
    CBT("pending_signal: publish the non-terminal pending HOLD signal",
        coin_backfill_pending_prevout_set(fx->db, CB_HOLE,
                                          &fx->chain.hashes[CB_HOLE],
                                          &spender->hash, 0));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("pending_signal: repairs from the pending signal alone",
        st == COIN_BACKFILL_REPAIRED && res.hole_height == CB_HOLE &&
        res.inserted_count == 1);
    CBT("pending_signal: the torn coin is re-inserted (H* can climb)",
        coins_kv_count(fx->db) == coins_before + 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

static int cb_case_spent(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("spent: setup", cb_setup(fx, "spent", 2, CBV_TA0, CB_TA0_VALUE,
                                 true /* midspend at 8 */, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("spent: refused as REFUSED_SPENT", st == COIN_BACKFILL_REFUSED_SPENT);
    CBT("spent: zero coin writes",
        coins_kv_count(fx->db) == coins_before &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));
    CBT("spent: refusal marker written",
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);
    {
        uint8_t blob[16] = {0};
        size_t blen = 0;
        bool present = false;
        CBT("spent: marker value is terminal-linkage v2",
            cb_refused_have(fx, blob, sizeof(blob), &blen, &present) &&
            present && blen == 8 && memcmp(blob, "spent:v2", 8) == 0);
    }

    struct cb_blocker_view bv;
    cb_find_blocker(&bv);
    CBT("spent: PERMANENT blocker + EV_OPERATOR_NEEDED paged once",
        bv.found && bv.class == (int)BLOCKER_PERMANENT &&
        atomic_load(&g_cb_op_needed) == 1);

    /* Second call: refuses again WITHOUT rescanning and without re-paging. */
    int reads_before = fx->chain.reads;
    memset(&res, 0, sizeof(res));
    bool ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                             &res);
    CBT("spent: second call refuses without rescanning (no loop)",
        ok && cb_is_refusal((int)res.status) && res.inserted_count == 0 &&
        fx->chain.reads - reads_before <= 6);
    CBT("spent: page once-latched (no duplicate event)",
        atomic_load(&g_cb_op_needed) == 1);
    CBT("spent: still zero coin writes",
        coins_kv_count(fx->db) == coins_before);
    CBT("spent: no tip_finalize_log rows deleted",
        cb_query_int(fx->db, "SELECT COUNT(*) FROM tip_finalize_log") ==
            fx->tip_rows_before);

    cb_teardown(fx);
    free(fx);
    return failures;
}

static int cb_case_refusal_marker_decoder_contract(void)
{
    int failures = 0;
    bool active = true;
    bool legacy_spent = true;
    bool legacy_txindex = true;

    CBT("marker_decode: spent:v2 is active",
        coin_backfill_refusal_marker_decode((const uint8_t *)"spent:v2", 8,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        active && !legacy_spent && !legacy_txindex);
    CBT("marker_decode: txindex_miss:v2 is active",
        coin_backfill_refusal_marker_decode(
            (const uint8_t *)"txindex_miss:v2", 15, &active, &legacy_spent,
            &legacy_txindex) &&
        active && !legacy_spent && !legacy_txindex);
    CBT("marker_decode: unprovable is active",
        coin_backfill_refusal_marker_decode((const uint8_t *)"unprovable", 10,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        active && !legacy_spent && !legacy_txindex);
    CBT("marker_decode: round_cap is active",
        coin_backfill_refusal_marker_decode((const uint8_t *)"round_cap", 9,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        active && !legacy_spent && !legacy_txindex);
    CBT("marker_decode: relost is active",
        coin_backfill_refusal_marker_decode((const uint8_t *)"relost", 6,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        active && !legacy_spent && !legacy_txindex);

    CBT("marker_decode: legacy spent is reproof-only",
        coin_backfill_refusal_marker_decode((const uint8_t *)"spent", 5,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        !active && legacy_spent && !legacy_txindex);
    CBT("marker_decode: legacy txindex_miss is reproof-only",
        coin_backfill_refusal_marker_decode((const uint8_t *)"txindex_miss",
                                            12, &active, &legacy_spent,
                                            &legacy_txindex) &&
        !active && !legacy_spent && legacy_txindex);
    CBT("marker_decode: unknown marker is ignored",
        coin_backfill_refusal_marker_decode((const uint8_t *)"spent:v9", 8,
                                            &active, &legacy_spent,
                                            &legacy_txindex) &&
        !active && !legacy_spent && !legacy_txindex);
    CBT("marker_decode: empty marker is ignored",
        coin_backfill_refusal_marker_decode(NULL, 0, &active, &legacy_spent,
                                            &legacy_txindex) &&
        !active && !legacy_spent && !legacy_txindex);

    return failures;
}

/* Upgrade guard: historical unversioned "spent" markers were written before
 * the scan proved terminal hash(H)==hole_hash. They must not permanently block
 * a repaired binary; delete and re-prove them with the v2 scan. */
static int cb_case_legacy_spent_marker_reproved(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("legacy_spent_marker: setup",
        cb_setup(fx, "legacy_spent_marker", 22, CBV_TA0, CB_TA0_VALUE,
                 false, true));

    CBT("legacy_spent_marker: seed old unsafe marker",
        cb_refused_seed(fx, "spent", 5));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("legacy_spent_marker: old marker does not block v2 re-proof",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 1);
    CBT("legacy_spent_marker: coin inserted and marker deleted",
        coins_kv_count(fx->db) == coins_before + 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0) &&
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Upgrade guard: historical txindex_miss markers trusted node.db projection
 * state as terminal. If active-chain block data can now locate the creator,
 * the marker must be ignored, deleted, and re-proven. */
static int cb_case_legacy_txindex_miss_marker_reproved(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("legacy_txidx_marker: setup",
        cb_setup(fx, "legacy_txidx_marker", 23, CBV_TA0, CB_TA0_VALUE,
                 false, true));

    CBT("legacy_txidx_marker: seed old unsafe marker",
        cb_refused_seed(fx, "txindex_miss", 12));

    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    CBT("legacy_txidx_marker: delete stale projection tx row",
        ta && db_tx_delete(&fx->ndb, ta->hash.data));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("legacy_txidx_marker: old marker does not block active-chain proof",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 1);
    CBT("legacy_txidx_marker: coin inserted and marker deleted",
        coins_kv_count(fx->db) == coins_before + 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0) &&
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 3: ADVERSARIAL — the txindex row points at a block that does not
 * contain the txid (recomputed tx hashes never match). */
static int cb_case_offchain_creator(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("offchain: setup", cb_setup(fx, "offchain", 3, CBV_BOGUS,
                                    CB_TA0_VALUE, false, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("offchain: refused, never minted",
        cb_is_refusal(st) && res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 4: one member created INSIDE the delta window is still repairable after
 * creator proof + terminal-bound no-spend proof. The delta horizon is
 * observability, not a consensus refusal boundary. */
static int cb_case_delta_window(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("delta_window: setup", cb_setup(fx, "delta_window", 4, CBV_TA0_TC0,
                                        CB_TA0_VALUE, false, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("delta_window: repairs whole set after proof",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 2 &&
        res.delta_horizon == CB_HORIZON);
    CBT("delta_window: both coins written (no partial insert)",
        coins_kv_count(fx->db) == coins_before + 2 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0) &&
        cb_coin_present(fx->db, fx, CB_DELTA_CREATOR, 1, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 5: scan gap — missing body mid-range pages a DEPENDENCY blocker with
 * the real escape (rebuild_recent / cold-import), and the scan is resumable
 * once the body appears (this also exercises the pure-try() happy drive). */
static int cb_case_scan_gap(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("gap: setup", cb_setup(fx, "gap", 5, CBV_TA0, CB_TA0_VALUE,
                               false, true));

    fx->chain.missing[CB_HORIZON] = true;   /* mid-range body hole */
    int64_t coins_before = coins_kv_count(fx->db);

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("gap: REFUSED_UNPROVABLE on the missing body",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE && res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before);

    struct cb_blocker_view bv;
    cb_find_blocker(&bv);
    CBT("gap: DEPENDENCY blocker with rebuild_recent escape text",
        bv.found && bv.class == (int)BLOCKER_DEPENDENCY &&
        strstr(bv.joined, "rebuild_recent") != NULL);
    CBT("gap: paged once", atomic_load(&g_cb_op_needed) == 1);

    /* The body appears: the repair resumes and completes via try() alone. */
    fx->chain.missing[CB_HORIZON] = false;
    st = cb_try_until(fx, &res);
    CBT("gap: resumable after the body appears",
        st == COIN_BACKFILL_REPAIRED &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 5b: node.db txindex is a hint. If a real creator row is missing from
 * node.db but the hash-bound active-chain body still contains the tx, repair
 * proceeds. A true txindex_miss still persists the durable refusal marker only
 * when txindex is COMPLETE (node.db tx_index_complete >= 3). */
static int cb_case_txindex_miss_persistence(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("txidx_hint: setup", cb_setup(fx, "txidx_hint", 31, CBV_TA0,
                                      CB_TA0_VALUE, false, true));

    /* Drop the creator (T_A) txindex row. Active-chain fallback should still
     * locate T_A in block CB_CREATOR and repair; stale node.db projection is
     * not terminal chain evidence. */
    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    int64_t coins_before = coins_kv_count(fx->db);
    CBT("txidx_hint: delete creator txindex row + mark complete",
        ta && db_tx_delete(&fx->ndb, ta->hash.data) &&
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("txidx_hint: active-chain fallback repairs",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 1 &&
        coins_kv_count(fx->db) == coins_before + 1);
    CBT("txidx_hint: no durable refusal marker",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    cb_teardown(fx);
    free(fx);

    fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return failures + 1;
    CBT("txidx_miss: setup", cb_setup(fx, "txidx_miss", 31, CBV_BOGUS,
                                      CB_TA0_VALUE, false, true));

    struct uint256 bogus;
    cb_bogus_txid(&bogus);
    CBT("txidx_miss: delete bogus txindex row",
        db_tx_delete(&fx->ndb, bogus.data));
    coins_before = coins_kv_count(fx->db);

    /* (a) RETRYABLE: txindex completeness NOT marked (default node.db has no
     * tx_index_complete row). The miss is transient (index still building) →
     * REFUSED_UNPROVABLE but NO durable marker persisted. */
    st = cb_try_until(fx, &res);
    CBT("txidx_miss: refused on txindex_miss",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        strstr(res.refuse_reason, "txindex_miss") != NULL &&
        res.inserted_count == 0 && coins_kv_count(fx->db) == coins_before);
    CBT("txidx_miss: incomplete txindex => NO durable marker (retryable)",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    /* (b) TERMINAL: mark txindex complete (>= 3). The same miss is now a
     * proven-absent creator → REFUSED_UNPROVABLE AND a durable marker. */
    CBT("txidx_miss: mark txindex complete",
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));
    st = cb_try_until(fx, &res);
    CBT("txidx_miss: still refused on txindex_miss",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        strstr(res.refuse_reason, "txindex_miss") != NULL);
    CBT("txidx_miss: complete txindex => durable marker persisted (terminal)",
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);

    /* The persisted marker keys on the HOLE (height, hash), exactly the row the
     * boot gate reads via coin_backfill_refusal_marker_read. Verify presence. */
    bool present = false;
    uint8_t blob[32];
    size_t blen = 0;
    CBT("txidx_miss: marker keyed on (hole_h, hole_hash)",
        cb_refused_have(fx, blob, sizeof(blob), &blen, &present) && present);
    CBT("txidx_miss: marker value is active-chain-vetted v2",
        present && blen == 15 && memcmp(blob, "txindex_miss:v2", 15) == 0);
    CBT("txidx_miss: still zero coin writes",
        coins_kv_count(fx->db) == coins_before);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 5c: stale/corrupt txindex rows are hints, not proof. If the row points
 * at the wrong active block, fall back to active-chain scanning and repair when
 * the real creator is present. */
static int cb_case_txindex_stale_row_fallback(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("txidx_stale_row: setup", cb_setup(fx, "txidx_stale_row", 34,
                                           CBV_TA0, CB_TA0_VALUE, false,
                                           true));

    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    int64_t coins_before = coins_kv_count(fx->db);
    CBT("txidx_stale_row: point creator row at wrong block",
        ta && cb_save_tx_row(&fx->ndb, &ta->hash,
                             &fx->chain.hashes[CB_CREATOR_B], CB_CREATOR_B,
                             0, false) &&
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("txidx_stale_row: active-chain fallback repairs",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 1 &&
        coins_kv_count(fx->db) == coins_before + 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));
    CBT("txidx_stale_row: no durable refusal marker",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 5d: an indexed creator whose body is currently unreadable is retryable.
 * Missing block data must not become a durable boot-gate refusal marker. */
static int cb_case_creator_body_unreadable_retryable(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("creator_gap: setup", cb_setup(fx, "creator_gap", 35, CBV_TA0,
                                       CB_TA0_VALUE, false, true));

    CBT("creator_gap: mark txindex complete",
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));
    fx->chain.missing[CB_CREATOR] = true;
    int64_t coins_before = coins_kv_count(fx->db);

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("creator_gap: unreadable creator refused retryably",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        strstr(res.refuse_reason, "creator_scan_gap") != NULL &&
        res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before);
    CBT("creator_gap: no durable marker while body is missing",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    fx->chain.missing[CB_CREATOR] = false;
    st = cb_try_until(fx, &res);
    CBT("creator_gap: repairs after creator body appears",
        st == COIN_BACKFILL_REPAIRED && res.inserted_count == 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 5c: node_db_unavailable is RETRYABLE — a fixture/txindex-less run with
 * no node.db handle cannot resolve the creator THIS process, but a later boot
 * with the handle wired may. It must refuse WITHOUT persisting a terminal
 * marker (no false escalation of a transient infra gap). */
static int cb_case_node_db_unavailable_no_persist(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("ndb_gone: setup", cb_setup(fx, "ndb_gone", 32, CBV_TA0,
                                    CB_TA0_VALUE, false, true));

    /* Strip the node.db handle from the io seam (the txindex-less run). */
    fx->io.ndb = NULL;
    int64_t coins_before = coins_kv_count(fx->db);

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("ndb_gone: refused node_db_unavailable",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        strstr(res.refuse_reason, "node_db_unavailable") != NULL &&
        res.inserted_count == 0 && coins_kv_count(fx->db) == coins_before);
    CBT("ndb_gone: NO durable marker (retryable infra gap)",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* A unique synthetic block hash for the gate-e2e active-tip slot (distinct
 * from the fixture chain's real hashes so the index insert never collides). */
static void cb_synth_tip_hash(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[31] = 0x9e;
}

/* Case 5d: END-TO-END — the boot-time torn-import gate
 * (block_index_loader_torn_import_gate_fires) FIRES on the durable marker that
 * the REAL coin_backfill writer just persisted. This is the hermetic proof that
 * the writer's key (coin_backfill.refused.<h>.<hash>, written from the txindex_miss
 * terminal path) is byte-identical to the key the gate's reader builds for the
 * SAME lowest prevout_unresolved hole — NOT a hand-seeded marker. We drive the
 * REAL persistence path (txindex_miss + tx_index_complete>=3), install an active
 * tip at the hole height, then call the gate with a low checkpoint (the gate
 * takes the checkpoint as a parameter; production passes the SHA3 anchor, but
 * the gate logic — window + status + durable-marker — is checkpoint-agnostic). */
static int cb_case_gate_fires_on_real_marker(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("gate_e2e: setup", cb_setup(fx, "gate_e2e", 33, CBV_BOGUS,
                                    CB_TA0_VALUE, false, true));

    /* CONTROL: the gate must NOT fire before any marker exists — even though
     * the hole row + window are already present (no false-fire). */
    struct uint256 tip_hash;
    cb_synth_tip_hash(CB_HOLE, &tip_hash);
    struct block_index *tip =
        chainstate_insert_block_index((struct chainstate *)&fx->ms, &tip_hash);
    bool tip_ok = false;
    if (tip) {
        tip->nHeight = CB_HOLE;
        tip->nStatus = BLOCK_VALID_TREE;
        tip->nFile = -1;
        tip_ok = active_chain_install_tip_slot(&fx->ms.chain_active, tip) &&
                 active_chain_height(&fx->ms.chain_active) == CB_HOLE;
    }
    CBT("gate_e2e: active tip installed at the hole height", tip_ok);
    CBT("gate_e2e: gate does NOT fire before any durable marker",
        !block_index_loader_torn_import_gate_fires(&fx->ms, fx->db, CB_HOLE,
                                                   CB_HOLE - 1));

    /* Drive the REAL writer to a TERMINAL txindex_miss: the bogus prevout has
     * no creator in active-chain block data and no txindex row. */
    struct uint256 bogus;
    cb_bogus_txid(&bogus);
    CBT("gate_e2e: delete bogus txindex row + mark txindex complete",
        db_tx_delete(&fx->ndb, bogus.data) &&
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("gate_e2e: real path refuses txindex_miss + persists marker",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        strstr(res.refuse_reason, "txindex_miss") != NULL &&
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);

    /* Now the gate FIRES on that real-path marker (window: hole 16 in
     * (15, 16]; status prevout_unresolved; durable marker present). */
    blocker_reset_for_testing();
    CBT("gate_e2e: gate FIRES on the real-path durable marker",
        block_index_loader_torn_import_gate_fires(&fx->ms, fx->db, CB_HOLE,
                                                  CB_HOLE - 1));
    CBT("gate_e2e: PERMANENT seed.torn_import blocker raised",
        blocker_exists("seed.torn_import") &&
        blocker_class_for("seed.torn_import") == BLOCKER_PERMANENT);

    blocker_reset_for_testing();
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 6: coin present but unusable (height >= frontier) — a metadata tear,
 * not a missing coin; never mint over it. */
static int cb_case_present_unusable(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("unusable: setup", cb_setup(fx, "unusable", 6, CBV_TA0, CB_TA0_VALUE,
                                    false, false /* no baseline coin */));

    /* (T_A,0) IS present — but recorded at the frontier height. */
    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    CBT("unusable: seed present-but-unusable coin",
        coins_kv_add(fx->db, ta->hash.data, 0, CB_TA0_VALUE, CB_FRONTIER,
                     false, ta->vout[0].script_pub_key.data,
                     ta->vout[0].script_pub_key.size));
    int64_t coins_before = coins_kv_count(fx->db);

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("unusable: refused without writes",
        cb_is_refusal(st) && res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before);
    CBT("unusable: reason names the present-but-unusable coin",
        strstr(res.refuse_reason, "unusable") != NULL ||
        strstr(res.refuse_reason, "present") != NULL);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 7: coinbase immaturity — H - creator < COINBASE_MATURITY means the
 * spend is genuinely invalid; leave the hole, refuse. */
static int cb_case_coinbase_immature(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("immature: setup", cb_setup(fx, "immature", 7, CBV_CB5, CB_TA0_VALUE,
                                    false, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("immature: refused (H - creator < 100), no write",
        cb_is_refusal(st) && res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 0, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 8: multi-coin block — both missing coins enumerated, ONE scan pass,
 * both inserted atomically, replay marker cleared once. */
static int cb_case_multi_coin(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("multi: setup", cb_setup(fx, "multi", 8, CBV_TA0_TB0, CB_TA0_VALUE,
                                 false, true));

    /* STEP 3: the stale-script replay no longer uses a write-once marker
     * (termination is the body-vs-row delta), so coin_backfill no longer clears
     * one — the seed/clear assertions were removed. */
    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("multi: both coins enumerated and inserted in one round",
        st == COIN_BACKFILL_REPAIRED &&
        res.unresolved_count == 2 &&
        res.inserted_count == 2 &&
        res.creator_floor == CB_CREATOR);
    CBT("multi: both coins live",
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0) &&
        cb_coin_present(fx->db, fx, CB_CREATOR_B, 1, 0) &&
        coins_kv_count(fx->db) == coins_before + 2);
    CBT("multi: one outpoint marker per coin",
        cb_meta_count_like(fx->db,
                           "utxo_apply.coin_backfill.outpoint.%") == 2);
    CBT("multi: the single scan record was consumed by the insert",
        cb_marker_count(fx->db, "coin_backfill.scan") == 0);

    st = cb_try_until(fx, &res);
    CBT("multi: re-run is NOT_APPLICABLE",
        st == COIN_BACKFILL_NOT_APPLICABLE);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 9a: resume integrity — the cursor persists across calls; a tampered
 * set digest or a changed frontier restarts the scan from the floor. */
static int cb_case_resume_integrity(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("resume: setup", cb_setup(fx, "resume", 9, CBV_TA0, CB_TA0_VALUE,
                                  false, true));

    struct coin_backfill_outpoint *set =
        zcl_malloc(sizeof(*set), "cb_test_set");
    CBT("resume: set alloc", set != NULL);
    if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

    int next1 = -1, next2 = -1, next3 = -1, spent = -1;
    uint8_t spender[32];
    enum coin_backfill_scan_verdict v1 =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 3, &next1, &spent, spender);
    enum coin_backfill_scan_verdict v2 =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 3, &next2, &spent, spender);
    CBT("resume: cursor persists and advances across calls",
        v1 == COIN_SCAN_IN_PROGRESS && v2 == COIN_SCAN_IN_PROGRESS &&
        next2 > next1 &&
        cb_marker_count(fx->db, "coin_backfill.scan") == 1);

    /* Tampered set digest -> restart from floor. */
    CBT("resume: tamper persisted set digest", cb_tamper_scan_digest(fx->db));
    enum coin_backfill_scan_verdict v3 =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 3, &next3, &spent, spender);
    CBT("resume: tampered digest restarts from floor",
        v3 != COIN_SCAN_CLEAN && v3 != COIN_SCAN_SPENT_FOUND &&
        next3 < next2);

    /* TG-F3: malformed persisted records are treated as ABSENT — restart
     * from floor, never decoded, never CLEAN on that call. With
     * max_blocks=3 a from-floor restart checkpoints at exactly floor+3,
     * the observable proof the resume cursor was discarded. */
    uint8_t junk[105];   /* 105 == the record's CLEAN length */
    memset(junk, 0xC3, sizeof(junk));
    int next4 = -1;
    CBT("resume: plant 50-byte garbage record",
        cb_scan_seed(fx, junk, 50));
    enum coin_backfill_scan_verdict v4 =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 3, &next4, &spent, spender);
    CBT("resume: garbage record treated as absent, restart from floor",
        v4 == COIN_SCAN_IN_PROGRESS && next4 == CB_CREATOR + 3);

    /* CLEAN-length blob whose clean flag byte is 0: neither base form nor
     * clean form — malformed-as-absent, must never read as CLEAN. */
    junk[104] = 0;
    int next5 = -1;
    CBT("resume: plant 105-byte record with clean flag 0",
        cb_scan_seed(fx, junk, sizeof(junk)));
    enum coin_backfill_scan_verdict v5 =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 3, &next5, &spent, spender);
    CBT("resume: zeroed clean flag never yields CLEAN, restart from floor",
        v5 == COIN_SCAN_IN_PROGRESS && next5 == CB_CREATOR + 3);

    /* Drive to CLEAN, then a changed frontier must invalidate the record. */
    enum coin_backfill_scan_verdict v = v5;
    int next = next5;
    for (int i = 0; i < 20 && v == COIN_SCAN_IN_PROGRESS; i++)
        v = cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                    CB_TOP, CB_FRONTIER, 64, &next, &spent, spender);
    CBT("resume: scan completes after restart", v == COIN_SCAN_CLEAN);
    /* max_blocks=4: the moved frontier widens the terminal window to 4
     * blocks, and 3 would trip the over-budget guard before the record's
     * frontier mismatch (the path this case pins) is even consulted. */
    enum coin_backfill_scan_verdict vf =
        cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                CB_TOP - 1, CB_FRONTIER - 1, 4, &next, &spent, spender);
    CBT("resume: changed frontier does not reuse the CLEAN record",
        vf != COIN_SCAN_CLEAN && vf != COIN_SCAN_SPENT_FOUND);

    free(set);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 9b: frontier moved between scan completion and insert — the stale
 * CLEAN record (bound to the old frontier) must never be consumed. The new
 * scan top is made unreadable, so a fresh proof at the moved frontier is
 * underivable: ANY insert could only have come from the stale record, via
 * whichever guard (record frontier mismatch or the insert-tx frontier
 * re-check) the implementation hits first. */
static int cb_case_frontier_moved_before_insert(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("frontier_move: setup",
        cb_setup(fx, "frontier_move", 10, CBV_TA0, CB_TA0_VALUE, false, true));

    struct coin_backfill_outpoint *set =
        zcl_malloc(sizeof(*set), "cb_test_set");
    CBT("frontier_move: set alloc", set != NULL);
    if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

    int next = -1, spent = -1;
    uint8_t spender[32];
    enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
    for (int i = 0; i < 20 && v == COIN_SCAN_IN_PROGRESS; i++)
        v = cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                    CB_TOP, CB_FRONTIER, 64, &next, &spent, spender);
    CBT("frontier_move: scan CLEAN at the original frontier",
        v == COIN_SCAN_CLEAN &&
        cb_marker_count(fx->db, "coin_backfill.scan") == 1);

    /* The frontier moves (kill-9 / concurrent apply) before the insert, and
     * the new top is unreadable — no fresh proof can be derived. */
    fx->chain.missing[CB_FRONTIER - 2] = true;   /* new top = frontier'-1 */
    CBT("frontier_move: move coins_applied + utxo cursor",
        cb_set_coins_applied(fx->db, CB_FRONTIER - 1) &&
        cb_seed_cursor(fx->db, "utxo_apply", CB_FRONTIER - 1));

    bool never_inserted = true;
    for (int i = 0; i < 5 && never_inserted; i++) {
        struct coin_backfill_result res;
        memset(&res, 0, sizeof(res));
        if (!stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                            &res))
            break;
        never_inserted = res.status != COIN_BACKFILL_REPAIRED &&
                         res.inserted_count == 0 &&
                         !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0);
    }
    CBT("frontier_move: stale CLEAN proof never consumed — no insert",
        never_inserted);

    free(set);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 10a: owner gate — env ack missing pages DIRECTLY on the FIRST
 * refusing call; cursor movement between ticks neither suppresses nor
 * resets the latch. */
static int cb_case_owner_gate(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("owner: setup", cb_setup(fx, "owner", 11, CBV_TA0, CB_TA0_VALUE,
                                 false, true));
    unsetenv(CB_ACK_ENV);

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    memset(&res, 0, sizeof(res));
    bool ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                             &res);
    CBT("owner: OWNER_REFUSED with zero writes",
        ok && res.status == COIN_BACKFILL_OWNER_REFUSED &&
        res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before &&
        cb_marker_count(fx->db, "coin_backfill.scan") == 0);

    struct cb_blocker_view bv;
    cb_find_blocker(&bv);
    CBT("owner: DEPENDENCY blocker naming the ack env",
        bv.found && bv.class == (int)BLOCKER_DEPENDENCY &&
        strstr(bv.joined, CB_ACK_ENV) != NULL);
    CBT("owner: EV_OPERATOR_NEEDED on the FIRST refusing call",
        atomic_load(&g_cb_op_needed) == 1);

    /* Witnessed cursor movement elsewhere must not wash the page. */
    CBT("owner: move an unrelated cursor between ticks",
        cb_seed_cursor(fx->db, "body_fetch", CB_HOLE + 3));
    memset(&res, 0, sizeof(res));
    ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true, &res);
    CBT("owner: still refused after cursor movement",
        ok && res.status == COIN_BACKFILL_OWNER_REFUSED &&
        coins_kv_count(fx->db) == coins_before);
    CBT("owner: page latched — not re-emitted, not reset",
        atomic_load(&g_cb_op_needed) == 1);

    setenv(CB_ACK_ENV, "1", 1);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 10b: value bounds — a creating output above MAX_MONEY refuses. */
static int cb_case_value_bounds(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("bounds: setup", cb_setup(fx, "bounds", 12, CBV_TA0, MAX_MONEY + 1,
                                  false, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("bounds: value > MAX_MONEY refused, no write",
        cb_is_refusal(st) && res.inserted_count == 0 &&
        coins_kv_count(fx->db) == coins_before &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 10c: round cap — 8 rounds (each inserting a brand-new outpoint of the
 * same hole) succeed; the 9th refuses. */
static int cb_case_round_cap(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("rounds: setup", cb_setup(fx, "rounds", 13, CBV_TA0_TO_9,
                                  CB_TA0_VALUE, false,
                                  false /* coins seeded below */));

    /* (T_A,1..9) live; (T_A,0) lost — round 1's coin. */
    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    bool seeded = true;
    for (uint32_t i = 1; i <= 9 && seeded; i++)
        seeded = coins_kv_add(fx->db, ta->hash.data, i, ta->vout[i].value,
                              CB_CREATOR, false,
                              ta->vout[i].script_pub_key.data,
                              ta->vout[i].script_pub_key.size);
    CBT("rounds: seed coins 1..9", seeded);

    struct coin_backfill_result res;
    bool rounds_ok = true;
    for (int round = 1; round <= 8 && rounds_ok; round++) {
        if (round > 1) {
            /* Lose a DIFFERENT outpoint of the same failing block. */
            rounds_ok = coins_kv_spend(fx->db, ta->hash.data,
                                       (uint32_t)(round - 1));
            if (!rounds_ok) break;
        }
        int st = cb_try_until(fx, &res);
        rounds_ok = (st == COIN_BACKFILL_REPAIRED) &&
                    cb_coin_present(fx->db, fx, CB_CREATOR, 1,
                                    (uint32_t)(round - 1));
    }
    CBT("rounds: 8 rounds repair (one new outpoint each)", rounds_ok);
    CBT("rounds: 8 outpoint markers",
        cb_meta_count_like(fx->db,
                           "utxo_apply.coin_backfill.outpoint.%") == 8);

    CBT("rounds: lose a 9th outpoint",
        coins_kv_spend(fx->db, ta->hash.data, 8));
    int st = cb_try_until(fx, &res);
    CBT("rounds: 9th round refuses (round cap)",
        cb_is_refusal(st) && res.inserted_count == 0 &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 8));

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 10d: MARKER_SEEN at a DIFFERENT hole height H' — the one-shot marker
 * is keyed by outpoint only, so a re-lost coin is caught at ANY future hole. */
static int cb_case_marker_seen_other_height(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("marker: setup", cb_setup(fx, "marker", 14, CBV_TA0, CB_TA0_VALUE,
                                  false, true));

    /* Round 1 at H: normal repair writes the outpoint marker. */
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("marker: first repair at H succeeds",
        st == COIN_BACKFILL_REPAIRED &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    /* H resolves; the SAME outpoint is lost AGAIN and a new hole appears at
     * H' = 18 (block 18 also spends (T_A,0) in the fixture chain). */
    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    CBT("marker: resolve H, open hole at H', re-lose the coin",
        cb_exec(fx->db,
                "UPDATE script_validate_log "
                "SET ok=1, status='verified' WHERE height=16") &&
        cb_put_script_row(fx->db, CB_HOLE2, "prevout_unresolved", 0,
                          &fx->chain.hashes[CB_HOLE2]) &&
        cb_seed_cursor(fx->db, "script_validate", CB_HOLE2 + 1) &&
        cb_seed_cursor(fx->db, "proof_validate", CB_HOLE2 + 1) &&
        cb_seed_cursor(fx->db, "body_persist", CB_HOLE2 + 1) &&
        coins_kv_spend(fx->db, ta->hash.data, 0));

    blocker_reset_for_testing();
    coin_backfill_reset_latches_for_testing();
    atomic_store(&g_cb_op_needed, 0);

    memset(&res, 0, sizeof(res));
    bool ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                             &res);
    CBT("marker: MARKER_SEEN at H' (outpoint-keyed, not (H,outpoint))",
        ok && res.status == COIN_BACKFILL_MARKER_SEEN &&
        res.hole_height == CB_HOLE2 &&
        res.inserted_count == 0 &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    struct cb_blocker_view bv;
    cb_find_blocker(&bv);
    CBT("marker: PERMANENT blocker + page",
        bv.found && bv.class == (int)BLOCKER_PERMANENT &&
        atomic_load(&g_cb_op_needed) == 1);

    /* A re-lost coin is a proven repeated tear: it must leave the DURABLE
     * refused marker the boot torn-gate reads, not just the in-memory blocker
     * (which is gone after a reboot). */
    CBT("marker: durable refused marker persisted for the boot torn-gate",
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 11: dispatcher ordering — a LOWER internal_error hole belongs to the
 * existing stale-script replay; the backfill must report NOT_APPLICABLE. */
static int cb_case_dispatch_order(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("order: setup", cb_setup(fx, "order", 15, CBV_TA0, CB_TA0_VALUE,
                                 false, true));

    /* BOO-2: a LOWER transient internal_error must NOT mask the higher genuine
     * prevout_unresolved coin tear. internal_error is owned by the separate
     * stale-script replay path; coin_backfill scans for prevout_unresolved
     * specifically and repairs the real tear at CB_HOLE regardless. */
    CBT("order: seed lower internal_error hole",
        cb_put_script_row(fx->db, CB_HOLE - 1, "internal_error", 0,
                          &fx->chain.hashes[CB_HOLE - 1]));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("order: lower internal_error does NOT mask the prevout_unresolved tear",
        st == COIN_BACKFILL_REPAIRED &&
        res.hole_height == CB_HOLE &&
        res.inserted_count == 1 &&
        cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0) &&
        coins_kv_count(fx->db) == coins_before + 1);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 12: ADVERSARIAL — chain rebind on resume (kill-9 + reorg, B1).
 * (a) reorg of the already-scanned prefix breaks the resume prev-link ->
 *     CHAIN_REBOUND, restart from floor, never an insert over a mixed proof;
 * (b) reorg of H after CLEAN -> the hole-hash re-check refuses the insert;
 * (c) reorg of frontier-1 after CLEAN -> the persisted top_hash re-check
 *     ROLLs BACK the insert. */
static int cb_case_chain_rebind(void)
{
    int failures = 0;

    /* (a) */
    {
        struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
        if (!fx) return 1;
        CBT("rebind_a: setup", cb_setup(fx, "rebind_a", 16, CBV_TA0,
                                        CB_TA0_VALUE, false, true));

        struct coin_backfill_outpoint *set =
            zcl_malloc(sizeof(*set), "cb_test_set");
        CBT("rebind_a: set alloc", set != NULL);
        if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
        cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

        struct uint256 old_hole_hash = fx->chain.hashes[CB_HOLE];
        int next = -1, spent = -1;
        uint8_t spender[32];
        enum coin_backfill_scan_verdict v =
            cb_scan(fx, &old_hole_hash, set, 1, CB_CREATOR, CB_TOP,
                    CB_FRONTIER, 3, &next, &spent, spender);
        /* The persisted lineage must already cover the fork height (7), so
         * the post-reorg resume's FIRST block fails the prev-link. */
        CBT("rebind_a: partial scan persisted past the fork height",
            v == COIN_SCAN_IN_PROGRESS && next > CB_CREATOR_B);

        /* Reorg the scanned prefix (fork below the resume point). */
        CBT("rebind_a: reorg from h=7",
            cb_chain_reorg_from(&fx->chain, CB_CREATOR_B));
        v = cb_scan(fx, &old_hole_hash, set, 1, CB_CREATOR, CB_TOP,
                    CB_FRONTIER, 3, &next, &spent, spender);
        CBT("rebind_a: resume prev-link mismatch -> CHAIN_REBOUND",
            v == COIN_SCAN_CHAIN_REBOUND);
        CBT("rebind_a: no insert against a mixed-branch proof",
            !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

        /* Recovery: the hole row re-binds to the new branch (same block
         * content re-failed there), the scan restarts and completes. */
        CBT("rebind_a: rebind hole row to the new branch",
            cb_update_hole_hash(fx->db, CB_HOLE,
                                &fx->chain.hashes[CB_HOLE]));
        struct coin_backfill_result res;
        int st = cb_try_until(fx, &res);
        CBT("rebind_a: bounded restart recovers and repairs",
            st == COIN_BACKFILL_REPAIRED &&
            cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

        free(set);
        cb_teardown(fx);
        free(fx);
    }

    /* (b) */
    {
        struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
        if (!fx) return 1;
        CBT("rebind_b: setup", cb_setup(fx, "rebind_b", 17, CBV_TA0,
                                        CB_TA0_VALUE, false, true));

        struct coin_backfill_outpoint *set =
            zcl_malloc(sizeof(*set), "cb_test_set");
        CBT("rebind_b: set alloc", set != NULL);
        if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
        cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

        struct uint256 old_hole_hash = fx->chain.hashes[CB_HOLE];
        int next = -1, spent = -1;
        uint8_t spender[32];
        enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
        for (int i = 0; i < 20 && v == COIN_SCAN_IN_PROGRESS; i++)
            v = cb_scan(fx, &old_hole_hash, set, 1, CB_CREATOR, CB_TOP,
                        CB_FRONTIER, 64, &next, &spent, spender);
        CBT("rebind_b: scan CLEAN before the reorg", v == COIN_SCAN_CLEAN);

        CBT("rebind_b: reorg H itself",
            cb_chain_reorg_from(&fx->chain, CB_HOLE));
        struct coin_backfill_result res;
        int st = cb_try_until(fx, &res);
        CBT("rebind_b: insert refused after H reorg (hole-hash re-check)",
            cb_is_refusal(st) && res.inserted_count == 0 &&
            !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

        free(set);
        cb_teardown(fx);
        free(fx);
    }

    /* (c) */
    {
        struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
        if (!fx) return 1;
        CBT("rebind_c: setup", cb_setup(fx, "rebind_c", 18, CBV_TA0,
                                        CB_TA0_VALUE, false, true));

        struct coin_backfill_outpoint *set =
            zcl_malloc(sizeof(*set), "cb_test_set");
        CBT("rebind_c: set alloc", set != NULL);
        if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
        cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

        struct uint256 hole_hash = fx->chain.hashes[CB_HOLE];
        int next = -1, spent = -1;
        uint8_t spender[32];
        enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
        for (int i = 0; i < 20 && v == COIN_SCAN_IN_PROGRESS; i++)
            v = cb_scan(fx, &hole_hash, set, 1, CB_CREATOR, CB_TOP,
                        CB_FRONTIER, 64, &next, &spent, spender);
        CBT("rebind_c: scan CLEAN before the swap", v == COIN_SCAN_CLEAN);

        /* Swap ONLY frontier-1: H still matches the hole row, but the
         * insert-time active hash at scan_top no longer equals the
         * persisted top_hash. */
        CBT("rebind_c: swap frontier-1 block",
            cb_chain_swap_one(&fx->chain, CB_TOP));
        struct coin_backfill_result res;
        memset(&res, 0, sizeof(res));
        bool ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io,
                                                 true, &res);
        CBT("rebind_c: top_hash mismatch -> ROLLBACK, no insert",
            ok && res.status != COIN_BACKFILL_REPAIRED &&
            res.inserted_count == 0 &&
            !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

        /* And it must never insert on subsequent ticks against the torn io. */
        bool never_inserted = true;
        for (int i = 0; i < 5 && never_inserted; i++) {
            memset(&res, 0, sizeof(res));
            if (!stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io,
                                                true, &res))
                break;
            never_inserted = res.status != COIN_BACKFILL_REPAIRED &&
                             !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0);
        }
        CBT("rebind_c: refuses-by-delay, never a torn insert", never_inserted);

        free(set);
        cb_teardown(fx);
        free(fx);
    }

    return failures;
}

/* Case 13: terminal linkage — a mid-scan reorg with fork point ahead of the
 * read position leaves the scanned prefix prev-linked, but the [frontier..H]
 * walk must end at the hole row's hash; it doesn't -> never CLEAN, no write. */
static int cb_case_terminal_linkage(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("terminal: setup", cb_setup(fx, "terminal", 19, CBV_TA0,
                                    CB_TA0_VALUE, false, true));

    struct coin_backfill_outpoint *set =
        zcl_malloc(sizeof(*set), "cb_test_set");
    CBT("terminal: set alloc", set != NULL);
    if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

    struct uint256 old_hole_hash = fx->chain.hashes[CB_HOLE];
    int next = -1, spent = -1;
    uint8_t spender[32];
    enum coin_backfill_scan_verdict v =
        cb_scan(fx, &old_hole_hash, set, 1, CB_CREATOR, CB_TOP, CB_FRONTIER,
                3, &next, &spent, spender);
    CBT("terminal: partial scan persisted", v == COIN_SCAN_IN_PROGRESS);

    /* Fork point AHEAD of the read position and ABOVE the scan top: the
     * scanned segment stays valid, but block H's hash changes. */
    CBT("terminal: reorg from frontier (fork ahead of read position)",
        cb_chain_reorg_from(&fx->chain, CB_FRONTIER));

    bool never_clean = true;
    v = COIN_SCAN_IN_PROGRESS;
    for (int i = 0; i < 30 && never_clean; i++) {
        v = cb_scan(fx, &old_hole_hash, set, 1, CB_CREATOR, CB_TOP,
                    CB_FRONTIER, 64, &next, &spent, spender);
        if (v == COIN_SCAN_CLEAN || v == COIN_SCAN_SPENT_FOUND)
            never_clean = false;
        if (v == COIN_SCAN_GAP)
            break;
    }
    CBT("terminal: hash(H) != hole hash -> never CLEAN, never SPENT",
        never_clean);
    CBT("terminal: no coin written",
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    /* The orchestration also refuses: the hole row binds the OLD branch. */
    struct coin_backfill_result res;
    memset(&res, 0, sizeof(res));
    bool ok = stage_repair_coin_backfill_try(fx->db, &fx->ms, &fx->io, true,
                                             &res);
    CBT("terminal: try() refuses against the rebound chain",
        ok && res.status != COIN_BACKFILL_REPAIRED &&
        res.inserted_count == 0 &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));

    free(set);
    cb_teardown(fx);
    free(fx);

    /* False-positive guard: a reorg can present a fork block at the first
     * divergent height with the same parent as the old branch. If that fork
     * block spends the candidate, the scan must still walk to H and notice that
     * hash(H) no longer equals the hole row's hash. Returning SPENT before that
     * terminal proof would persist a durable refusal for an off-branch spend. */
    fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return failures + 1;
    CBT("terminal_spent: setup", cb_setup(fx, "terminal_spent", 22, CBV_TA0,
                                          CB_TA0_VALUE, false, true));

    struct coin_backfill_outpoint *set2 =
        zcl_malloc(sizeof(*set2), "cb_test_set");
    CBT("terminal_spent: set alloc", set2 != NULL);
    if (!set2) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set2, fx, CB_CREATOR, 1, 0, false);

    struct uint256 old_hole_hash2 = fx->chain.hashes[CB_HOLE];
    fx->chain.midspend = true;
    CBT("terminal_spent: reorg from mid with a fork-branch spend",
        cb_chain_reorg_from(&fx->chain, CB_MID));
    next = -1;
    spent = -1;
    memset(spender, 0, sizeof(spender));
    enum coin_backfill_scan_verdict v2 =
        cb_scan(fx, &old_hole_hash2, set2, 1, CB_CREATOR, CB_TOP,
                CB_FRONTIER, 64, &next, &spent, spender);
    CBT("terminal_spent: off-branch spend -> CHAIN_REBOUND, never SPENT",
        v2 == COIN_SCAN_CHAIN_REBOUND && spent == -1);
    CBT("terminal_spent: no durable refusal marker from scan",
        cb_marker_count(fx->db, "coin_backfill.refused") == 0);

    free(set2);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 14 (TG-F1): terminal-window budget — the [frontier..H] walk must fit
 * in ONE chunk (a mid-window checkpoint clamps persist_next back to the
 * frontier), so a window (3 blocks here) larger than max_blocks must refuse
 * loudly instead of pinning next at the frontier forever (SCANNING every
 * tick, never paging). max_blocks=4 must still reach CLEAN, resuming
 * through a checkpoint landing exactly at top_height (frontier-1). */
static int cb_case_scan_window_budget(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("budget: setup", cb_setup(fx, "budget", 20, CBV_TA0, CB_TA0_VALUE,
                                  false, true));

    struct coin_backfill_outpoint *set =
        zcl_malloc(sizeof(*set), "cb_test_set");
    CBT("budget: set alloc", set != NULL);
    if (!set) { cb_teardown(fx); free(fx); return failures + 1; }
    cb_fill_outpoint(set, fx, CB_CREATOR, 1, 0, false);

    /* window = CB_HOLE - CB_FRONTIER + 1 = 3 blocks */
    static const int small[2] = { 1, 2 };
    for (int p = 0; p < 2; p++) {
        int next = -1, spent = -1, calls = 0;
        uint8_t spender[32];
        enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
        while (calls < CB_TRY_CAP && v == COIN_SCAN_IN_PROGRESS) {
            v = cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                        CB_TOP, CB_FRONTIER, small[p], &next, &spent,
                        spender);
            calls++;
        }
        char desc[80];
        snprintf(desc, sizeof(desc),
                 "budget: max_blocks=%d over-budget verdict, bounded calls",
                 small[p]);
        CBT(desc, v == COIN_SCAN_WINDOW_OVER_BUDGET && calls < CB_TRY_CAP);
    }
    CBT("budget: over-budget guard leaves no scan record",
        cb_marker_count(fx->db, "coin_backfill.scan") == 0);

    /* max_blocks=4: chunks [5..8], [9..12], then a checkpoint EXACTLY at
     * top_height=13; the final chunk walks 13 plus the whole 3-block
     * terminal window in one go. */
    int next = -1, spent = -1, calls = 0;
    bool saw_top_checkpoint = false;
    uint8_t spender[32];
    enum coin_backfill_scan_verdict v = COIN_SCAN_IN_PROGRESS;
    while (calls < CB_TRY_CAP && v == COIN_SCAN_IN_PROGRESS) {
        v = cb_scan(fx, &fx->chain.hashes[CB_HOLE], set, 1, CB_CREATOR,
                    CB_TOP, CB_FRONTIER, 4, &next, &spent, spender);
        calls++;
        if (v == COIN_SCAN_IN_PROGRESS && next == CB_TOP)
            saw_top_checkpoint = true;
    }
    CBT("budget: max_blocks=4 reaches CLEAN in bounded calls",
        v == COIN_SCAN_CLEAN && calls < CB_TRY_CAP);
    CBT("budget: resume geometry hit a checkpoint exactly at top_height",
        saw_top_checkpoint);

    free(set);
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 15 (TG-F2): spend INSIDE the creator block — the scan's first
 * iteration is h == floor == creator; a walk starting at floor+1 would mint
 * a provably-spent coin. The fixture's creator block carries vtx[2] spending
 * (T_A,0), so the refusal must bind the spend to CB_CREATOR itself. */
static int cb_case_spend_in_creator_block(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("creator_spend: setup",
        cb_setup(fx, "creator_spend", 21, CBV_TA0_CREATOR_SPEND,
                 CB_TA0_VALUE, false, true));

    int64_t coins_before = coins_kv_count(fx->db);
    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("creator_spend: refused as REFUSED_SPENT",
        st == COIN_BACKFILL_REFUSED_SPENT && res.inserted_count == 0);
    char want[32];
    snprintf(want, sizeof(want), "spent h=%d tx=", CB_CREATOR);
    CBT("creator_spend: spend pinned to the CREATOR height",
        strstr(res.refuse_reason, want) != NULL);
    CBT("creator_spend: zero coin writes",
        coins_kv_count(fx->db) == coins_before &&
        !cb_coin_present(fx->db, fx, CB_CREATOR, 1, 0));
    CBT("creator_spend: refusal marker written",
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* Case 16 (TG-F4): zero-length scriptPubKey — T_A vout0 carries an empty
 * script; the repair must round-trip slen==0 through resolve→insert→readback
 * (pins the slen==0 skip in resolve_creator). */
static int cb_case_empty_script(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("empty_script: setup",
        cb_setup(fx, "empty_script", 22, CBV_TA0_EMPTY_SCRIPT, CB_TA0_VALUE,
                 false, true));

    const struct transaction *ta = cb_tx_at(&fx->chain, CB_CREATOR);
    CBT("empty_script: fixture vout0 script really is empty",
        ta && ta->vout[0].script_pub_key.size == 0);

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("empty_script: repaired", st == COIN_BACKFILL_REPAIRED &&
        res.inserted_count == 1);

    int64_t value = 0;
    uint8_t script[64];
    size_t slen = 99;
    bool got = coins_kv_get(fx->db, ta->hash.data, 0, &value, script,
                            sizeof(script), &slen);
    CBT("empty_script: readback is live with slen == 0 and exact value",
        got && slen == 0 && value == CB_TA0_VALUE);

    cb_teardown(fx);
    free(fx);
    return failures;
}

/* BOO-2 (boot torn-gate): a LOWER transient internal_error must not mask a
 * higher durably-refused prevout_unresolved tear. Drive the REAL writer to a
 * terminal txindex_miss (persisting coin_backfill.refused at CB_HOLE), add a
 * lower ok=0 internal_error row, install the active tip at the hole, and assert
 * the gate STILL fires (the lowest prevout_unresolved row is the verdict, not
 * the lower internal_error). */
static int cb_case_gate_not_masked_by_lower_internal_error(void)
{
    int failures = 0;
    struct cbf *fx = zcl_malloc(sizeof(*fx), "cb_test_fx");
    if (!fx) return 1;
    CBT("gate_mask: setup", cb_setup(fx, "gate_mask", 42, CBV_BOGUS,
                                     CB_TA0_VALUE, false, true));

    struct uint256 tip_hash;
    cb_synth_tip_hash(CB_HOLE, &tip_hash);
    struct block_index *tip =
        chainstate_insert_block_index((struct chainstate *)&fx->ms, &tip_hash);
    bool tip_ok = false;
    if (tip) {
        tip->nHeight = CB_HOLE;
        tip->nStatus = BLOCK_VALID_TREE;
        tip->nFile = -1;
        tip_ok = active_chain_install_tip_slot(&fx->ms.chain_active, tip) &&
                 active_chain_height(&fx->ms.chain_active) == CB_HOLE;
    }
    CBT("gate_mask: active tip installed at the hole height", tip_ok);

    /* Lower transient internal_error hole below the genuine tear. */
    CBT("gate_mask: seed lower internal_error hole",
        cb_put_script_row(fx->db, CB_HOLE - 1, "internal_error", 0,
                          &fx->chain.hashes[CB_HOLE - 1]));

    /* Drive the REAL writer to a TERMINAL txindex_miss at CB_HOLE. */
    struct uint256 bogus;
    cb_bogus_txid(&bogus);
    CBT("gate_mask: delete bogus txindex row + mark txindex complete",
        db_tx_delete(&fx->ndb, bogus.data) &&
        node_db_state_set_int(&fx->ndb, "tx_index_complete", 3));

    struct coin_backfill_result res;
    int st = cb_try_until(fx, &res);
    CBT("gate_mask: real path refuses txindex_miss + persists marker",
        st == COIN_BACKFILL_REFUSED_UNPROVABLE &&
        cb_marker_count(fx->db, "coin_backfill.refused") == 1);

    /* The gate fires on the prevout_unresolved tear despite the lower
     * internal_error row. */
    blocker_reset_for_testing();
    CBT("gate_mask: gate FIRES (lower internal_error did not mask the tear)",
        block_index_loader_torn_import_gate_fires(&fx->ms, fx->db, CB_HOLE,
                                                  CB_HOLE - 1));
    CBT("gate_mask: PERMANENT seed.torn_import blocker raised",
        blocker_exists("seed.torn_import") &&
        blocker_class_for("seed.torn_import") == BLOCKER_PERMANENT);

    blocker_reset_for_testing();
    cb_teardown(fx);
    free(fx);
    return failures;
}

/* ── Entry point ───────────────────────────────────────────────────── */

int test_stage_repair_coin_backfill(void);
int test_stage_repair_coin_backfill(void)
{
    test_reset_shared_globals();   /* monolith isolation: see test_helpers.c */
    printf("\n=== stage_repair_coin_backfill tests ===\n");
    int failures = 0;

    /* Save the owner-ack env so this test is hermetic. */
    char saved_ack[64] = {0};
    const char *prev_ack = getenv(CB_ACK_ENV);
    bool had_ack = prev_ack != NULL;
    if (had_ack)
        snprintf(saved_ack, sizeof(saved_ack), "%s", prev_ack);

    event_log_init();
    event_clear_observers(EV_OPERATOR_NEEDED);
    event_observe(EV_OPERATOR_NEEDED, cb_op_needed_observer, NULL);
    blocker_module_init();
    blocker_reset_for_testing();

    failures += cb_case_happy();
    failures += cb_case_pending_signal_arms();
    failures += cb_case_spent();
    failures += cb_case_refusal_marker_decoder_contract();
    failures += cb_case_legacy_spent_marker_reproved();
    failures += cb_case_legacy_txindex_miss_marker_reproved();
    failures += cb_case_offchain_creator();
    failures += cb_case_delta_window();
    failures += cb_case_scan_gap();
    failures += cb_case_txindex_miss_persistence();
    failures += cb_case_txindex_stale_row_fallback();
    failures += cb_case_creator_body_unreadable_retryable();
    failures += cb_case_node_db_unavailable_no_persist();
    failures += cb_case_gate_fires_on_real_marker();
    failures += cb_case_present_unusable();
    failures += cb_case_coinbase_immature();
    failures += cb_case_multi_coin();
    failures += cb_case_resume_integrity();
    failures += cb_case_frontier_moved_before_insert();
    failures += cb_case_owner_gate();
    failures += cb_case_value_bounds();
    failures += cb_case_round_cap();
    failures += cb_case_marker_seen_other_height();
    failures += cb_case_dispatch_order();
    failures += cb_case_chain_rebind();
    failures += cb_case_terminal_linkage();
    failures += cb_case_scan_window_budget();
    failures += cb_case_spend_in_creator_block();
    failures += cb_case_empty_script();
    failures += cb_case_gate_not_masked_by_lower_internal_error();

    event_clear_observers(EV_OPERATOR_NEEDED);
    blocker_reset_for_testing();

    if (had_ack)
        setenv(CB_ACK_ENV, saved_ack, 1);
    else
        unsetenv(CB_ACK_ENV);

    printf("coin_backfill: %d failures\n", failures);
    return failures;
}
