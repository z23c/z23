/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: read a snapshot offer's height, hash, work and roots from the
 * mirror's cursor and block rows in one read transaction.
 */

#include "services/snapshot_offer_anchor.h"

#include "chain/mmr.h"
#include "coins/utxo_commitment.h"
#include "net/fast_sync.h"
#include "services/utxo_mirror_sync_service.h"
#include "storage/utxo_mirror_schema.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"

#include <limits.h>
#include <sqlite3.h>
#include <string.h>

#ifdef ZCL_TESTING
static void (*g_anchor_mid_read_hook)(void *ctx);
static void *g_anchor_mid_read_ctx;

void snapshot_offer_anchor_test_set_mid_read_hook(void (*hook)(void *ctx),
                                                  void *ctx)
{
    g_anchor_mid_read_hook = hook;
    g_anchor_mid_read_ctx = ctx;
}
#endif

static bool anchor_bytes32_nonzero(const uint8_t b[32])
{
    static const uint8_t zero[32];
    return memcmp(b, zero, 32) != 0;
}

/* The cursor as the mirror writes it: a native int64 in an eight-byte blob.
 * Missing is not zero, and -1 marks an invalidated mirror. */
static struct zcl_result anchor_read_height(sqlite3 *db, int32_t *height)
{
    sqlite3_stmt *st = NULL;
    int64_t cursor = 0;
    bool well_formed = false;

    if (sqlite3_prepare_v2(db, "SELECT value FROM node_state WHERE key=?",
                           -1, &st, NULL) != SQLITE_OK)
        return ZCL_ERR(-2, "snapshot anchor: cursor read: %s",
                       sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, UTXO_MIRROR_SYNC_CURSOR_KEY, -1, SQLITE_STATIC);
    struct zcl_result err = ZCL_OK;
    enum zcl_step step = ar_step_checked(st, "snapshot anchor: cursor read",
                                         &err);
    if (step == ZCL_STEP_ERROR) {
        sqlite3_finalize(st);
        return err;
    }
    if (step == ZCL_STEP_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(st, 0) == (int)sizeof(cursor)) {
        memcpy(&cursor, sqlite3_column_blob(st, 0), sizeof(cursor));
        well_formed = true;
    }
    sqlite3_finalize(st);
    if (!well_formed)
        return ZCL_ERR(-3, "snapshot anchor: no well-formed mirror cursor");
    /* Height 0 is genesis, which no offer may name. */
    if (cursor < 2 || cursor > (int64_t)INT32_MAX)
        return ZCL_ERR(-4, "snapshot anchor: mirror cursor %lld names no anchor",
                       (long long)cursor);
    *height = (int32_t)(cursor - 1);
    return ZCL_OK;
}

/* The validated row at height; the blocks table holds at most one per height. */
static struct zcl_result anchor_read_block(sqlite3 *db,
                                           struct snapshot_offer_anchor *out)
{
    sqlite3_stmt *st = NULL;
    bool found = false;

    if (sqlite3_prepare_v2(db,
            "SELECT hash, chain_work FROM blocks WHERE height=? AND status>=3 "
            "AND length(hash)=32 AND length(chain_work)=32",
            -1, &st, NULL) != SQLITE_OK)
        return ZCL_ERR(-5, "snapshot anchor: block read: %s",
                       sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, out->height);
    struct zcl_result err = ZCL_OK;
    enum zcl_step step = ar_step_checked(st, "snapshot anchor: block read",
                                         &err);
    if (step == ZCL_STEP_ERROR) {
        sqlite3_finalize(st);
        return err;
    }
    if (step == ZCL_STEP_ROW) {
        memcpy(out->block_hash, sqlite3_column_blob(st, 0), 32);
        memcpy(out->chain_work, sqlite3_column_blob(st, 1), 32);
        found = anchor_bytes32_nonzero(out->chain_work);
    }
    sqlite3_finalize(st);
    if (!found)
        return ZCL_ERR(-6, "snapshot anchor: no validated block at height %d",
                       out->height);
    return ZCL_OK;
}

/* The MMR over the validated hashes through the anchor. The live tree in
 * node_state stands at the tip, which is not the anchor once the two differ. */
static struct zcl_result anchor_read_mmr_root(sqlite3 *db,
                                              struct snapshot_offer_anchor *out)
{
    sqlite3_stmt *st = NULL;
    struct mmr m;
    int32_t next = 0;
    bool contiguous = true;

    if (sqlite3_prepare_v2(db,
            "SELECT height, hash FROM blocks WHERE height<=? AND status>=3 "
            "AND length(hash)=32 ORDER BY height",
            -1, &st, NULL) != SQLITE_OK)
        return ZCL_ERR(-11, "snapshot anchor: block hash read: %s",
                       sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, out->height);
    mmr_init(&m);
    struct zcl_result err = ZCL_OK;
    enum zcl_step step = ZCL_STEP_DONE;
    while (contiguous &&
           (step = ar_step_checked(st, "snapshot anchor: block hash read",
                                   &err)) == ZCL_STEP_ROW) {
        contiguous = sqlite3_column_int(st, 0) == next;
        next++;
        if (contiguous)
            mmr_append(&m, sqlite3_column_blob(st, 1));
    }
    sqlite3_finalize(st);
    if (step == ZCL_STEP_ERROR)
        return err;
    if (!contiguous || next != out->height + 1)
        return ZCL_ERR(-12, "snapshot anchor: validated blocks stop short of "
                       "height %d", out->height);
    mmr_root(&m, out->mmr_root);
    return ZCL_OK;
}

/* A row at or past the cursor means the mirror holds a block the cursor does
 * not claim, so the root would not be the root at the anchor. */
static struct zcl_result anchor_check_rows_below_cursor(sqlite3 *db,
                                                        int32_t height)
{
    sqlite3_stmt *st = NULL;
    struct zcl_result err = ZCL_OK;

    if (utxo_mirror_prepare_rows_above_scan(db, height, &st) != SQLITE_OK) {
        struct zcl_result r =
            ZCL_ERR(-7, "snapshot anchor: row scan: %s", sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return r;
    }
    /* A failed step proves nothing about the rows past the cursor: refuse. */
    enum zcl_step step = ar_step_checked(st, "snapshot anchor: row scan", &err);
    sqlite3_finalize(st);
    if (step == ZCL_STEP_ERROR)
        return err;
    if (step == ZCL_STEP_ROW)
        return ZCL_ERR(-8, "snapshot anchor: mirror holds rows past height %d",
                       height);
    return ZCL_OK;
}

static struct zcl_result anchor_read_in_txn(sqlite3 *db,
                                            struct snapshot_offer_anchor *out)
{
    struct zcl_result r = anchor_read_height(db, &out->height);

    if (!r.ok)
        return r;
#ifdef ZCL_TESTING
    if (g_anchor_mid_read_hook)
        g_anchor_mid_read_hook(g_anchor_mid_read_ctx);
#endif
    r = anchor_read_block(db, out);
    if (!r.ok)
        return r;
    r = anchor_read_mmr_root(db, out);
    if (!r.ok)
        return r;
    r = anchor_check_rows_below_cursor(db, out->height);
    if (!r.ok)
        return r;
    utxo_commitment_sha3_compute(db, out->utxo_root, &out->num_utxos);
    if (out->num_utxos == 0 || !anchor_bytes32_nonzero(out->utxo_root))
        return ZCL_ERR(-9, "snapshot anchor: empty mirror at height %d",
                       out->height);
    return ZCL_OK;
}

struct zcl_result snapshot_offer_anchor_read(const char *db_path,
                                             struct snapshot_offer_anchor *out)
{
    sqlite3 *db = NULL;
    struct zcl_result r;

    if (!db_path || !out)
        return ZCL_ERR(-1, "snapshot anchor: null path or out");
    memset(out, 0, sizeof(*out));
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                        NULL) != SQLITE_OK) {
        r = ZCL_ERR(-1, "snapshot anchor: open %s: %s", db_path,
                    db ? sqlite3_errmsg(db) : "out of memory");
        sqlite3_close(db);
        return r;
    }
    sqlite3_busy_timeout(db, 30000);

    /* Without this each statement sees its own moment: the writers run on. */
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        r = ZCL_ERR(-1, "snapshot anchor: begin: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return r;
    }
    r = anchor_read_in_txn(db, out);
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK && r.ok)
        r = ZCL_ERR(-10, "snapshot anchor: end read: %s", sqlite3_errmsg(db));
    sqlite3_close(db);
    if (!r.ok)
        memset(out, 0, sizeof(*out));
    return r;
}

struct zcl_result snapshot_offer_anchor_check_payload(
    const struct snapshot_offer_anchor *anchor,
    const uint8_t payload_sha3[32], uint64_t payload_count)
{
    if (!anchor || !payload_sha3)
        return ZCL_ERR(-1, "snapshot anchor: payload check needs both sides");
    if (payload_count != anchor->num_utxos ||
        memcmp(payload_sha3, anchor->utxo_root, 32) != 0)
        return ZCL_ERR(-11, "snapshot anchor: payload is not the set at %d",
                       anchor->height);
    return ZCL_OK;
}

void snapshot_offer_from_anchor(struct snapshot_offer *offer,
                                const struct snapshot_offer_anchor *anchor)
{
    offer->protocol_version = FAST_SYNC_PROTOCOL_VERSION;
    offer->snapshot_schema_version = FAST_SYNC_SNAPSHOT_SCHEMA_VERSION;
    offer->height = anchor->height;
    offer->peer_tip_height = anchor->height;
    memcpy(offer->block_hash, anchor->block_hash, 32);
    memcpy(offer->chain_work, anchor->chain_work, 32);
    memcpy(offer->utxo_root, anchor->utxo_root, 32);
    memcpy(offer->mmr_root, anchor->mmr_root, 32);
    offer->num_utxos = anchor->num_utxos;
    offer->total_bytes = anchor->num_utxos * 80;
}
