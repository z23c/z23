/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: make a keyed z_sendmany spend at most once.
 *
 * Order for a keyed send: record the key (STARTED), build, record the txid
 * (BUILT) before the wallet admits it, run the send, record COMMITTED. The
 * wallet's own persist-before-relay rule means a transaction that reached
 * the network is already in the wallet, so a BUILT row whose txid is in the
 * wallet is a known send. After a crash a repeat is answered from the row:
 *   COMMITTED                      -> the earlier txid
 *   BUILT and the wallet holds it  -> the earlier txid
 *   anything else, not running     -> outcome_unknown, nothing is sent
 * A key whose run failed before anything was built is released so the caller
 * can try again with the same key. Logs carry no address, amount, memo, key. */

#include "controllers/wallet_send_once.h"

#include "base/serialize_le.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/wallet_helpers.h"
#include "core/uint256.h"
#include "core/utiltime.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "models/database.h"
#include "models/wallet_send_once.h"
#include "primitives/transaction.h"
#include "util/log_macros.h"
#include "util/sync.h"
#include "wallet/wallet.h"

#include <ctype.h>
#include <string.h>

#define WSO_TAG "wallet_send_once"
#define WSO_ACTIVE_MAX 64
#define WSO_PRUNE_EVERY_SEC 3600

struct wso_scope {
    struct node_db *ndb;
    uint8_t key_hash[32];
    bool built;
    struct uint256 txid;
};

static zcl_once_t g_once = ZCL_ONCE_INIT;
static zcl_mutex_t g_lock;
static uint8_t g_active[WSO_ACTIVE_MAX][32];
static size_t g_active_n;
static int64_t g_last_prune;
static _Thread_local struct wso_scope *g_scope;


/* Writes run on the node.db single-writer lane when the db service owns this
 * database, after any open reducer batch is committed, so a record is on disk
 * before the call returns. Tests without a db service write directly. */
enum wso_op_kind { WSO_OP_INSERT, WSO_OP_ADVANCE, WSO_OP_RELEASE, WSO_OP_PRUNE };

struct wso_op {
    enum wso_op_kind kind;
    const struct wallet_send_once_row *row;
    const uint8_t *key_hash;
    const uint8_t *txid;
    enum wallet_send_once_state state;
    int64_t now;
    bool ok;
};

static bool wso_op_run(struct node_db *ndb, void *opaque)
{
    struct wso_op *op = opaque;
    op->ok = false;
    if (ndb->sync_in_batch && !node_db_sync_flush(ndb)) {
        LOG_ERROR(WSO_TAG, "pending node.db batch could not be committed");
        return true;
    }
    switch (op->kind) {
    case WSO_OP_INSERT:
        op->ok = db_wallet_send_once_insert(ndb, op->row);
        break;
    case WSO_OP_ADVANCE:
        op->ok = db_wallet_send_once_advance(ndb, op->key_hash, op->state,
                                             op->txid, op->now);
        break;
    case WSO_OP_RELEASE:
        op->ok = db_wallet_send_once_release(ndb, op->key_hash);
        break;
    case WSO_OP_PRUNE:
        op->ok = db_wallet_send_once_prune(ndb, op->now);
        break;
    }
    return true;
}

static bool wso_write(struct node_db *ndb, struct wso_op *op)
{
    struct db_service *svc = app_runtime_db_service();
    if (svc && db_service_is_started(svc) && db_service_node_db(svc) == ndb) {
        if (!db_service_run_write(svc, wso_op_run, op)) {
            LOG_WARN(WSO_TAG, "node.db write lane did not run the record write");
            return false;
        }
        return op->ok;
    }
    (void)wso_op_run(ndb, op);
    return op->ok;
}

static bool wso_insert(struct node_db *ndb,
                       const struct wallet_send_once_row *row)
{
    struct wso_op op = { .kind = WSO_OP_INSERT, .row = row };
    return wso_write(ndb, &op);
}

static bool wso_advance(struct node_db *ndb, const uint8_t kh[32],
                        enum wallet_send_once_state state, const uint8_t *txid,
                        int64_t now)
{
    struct wso_op op = { .kind = WSO_OP_ADVANCE, .key_hash = kh,
                         .state = state, .txid = txid, .now = now };
    return wso_write(ndb, &op);
}

static bool wso_release(struct node_db *ndb, const uint8_t kh[32])
{
    struct wso_op op = { .kind = WSO_OP_RELEASE, .key_hash = kh };
    return wso_write(ndb, &op);
}

static bool wso_prune(struct node_db *ndb, int64_t now)
{
    struct wso_op op = { .kind = WSO_OP_PRUNE, .now = now };
    return wso_write(ndb, &op);
}

static void wso_init(void) { zcl_mutex_init(&g_lock); }

bool wallet_send_once_key_valid(const char *key)
{
    size_t n = key ? strlen(key) : 0;
    if (n < 1 || n > 128)
        return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)key[i];
        if (!isalnum(c) && c != '.' && c != '_' && c != ':' && c != '-')
            return false; // raw-return-ok:key shape check
    }
    return true;
}

static void wso_absorb(struct sha3_256_ctx *c, const char *s)
{
    uint8_t len[4];
    size_t n = s ? strlen(s) : 0;
    zcl_write_u32_le(len, (uint32_t)n);
    sha3_256_write(c, len, sizeof(len));
    sha3_256_write(c, (const uint8_t *)(s ? s : ""), n);
}

static void wso_key_hash(const char *key, uint8_t out[32])
{
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    wso_absorb(&c, "z23/wallet-send-once/key/v1");
    wso_absorb(&c, key);
    sha3_256_finalize(&c, out);
}

/* Bound to the key, so the digest of a low-entropy request cannot be tested
 * against a copy of node.db without the key. */
static bool wso_digest(const char *key, const struct json_value *params,
                       uint8_t out[32])
{
    char from[1024], recips[16384], fee[64] = "";
    if (json_write(json_at(params, 0), from, sizeof(from)) == 0 ||
        json_write(json_at(params, 1), recips, sizeof(recips)) == 0)
        return false;
    const struct json_value *f = json_at(params, WALLET_SEND_ONCE_FEE_PARAM);
    if (f && !json_is_null(f) && json_write(f, fee, sizeof(fee)) == 0)
        return false;
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    wso_absorb(&c, "z23/wallet-send-once/request/v1");
    wso_absorb(&c, key);
    wso_absorb(&c, from);
    wso_absorb(&c, recips);
    wso_absorb(&c, fee);
    sha3_256_finalize(&c, out);
    return true;
}

static bool wso_is_active(const uint8_t kh[32])
{
    for (size_t i = 0; i < g_active_n; i++)
        if (memcmp(g_active[i], kh, 32) == 0)
            return true;
    return false;
}

static void wso_deactivate(const uint8_t kh[32])
{
    for (size_t i = 0; i < g_active_n; i++) {
        if (memcmp(g_active[i], kh, 32) == 0) {
            memcpy(g_active[i], g_active[--g_active_n], 32);
            return;
        }
    }
}

static bool wso_wallet_has(const struct wallet_rpc_context *ctx,
                           const struct uint256 *txid)
{
    if (!ctx || !ctx->wallet)
        return false;
    struct wallet_tx copy;
    memset(&copy, 0, sizeof(copy));
    if (!wallet_get_tx_copy(ctx->wallet, txid, &copy))
        return false; // raw-return-ok:absent from the wallet is an answer
    transaction_free(&copy.tx);
    return true;
}

static void wso_answer(struct json_value *result, const char *state,
                       const uint8_t *txid, bool replayed)
{
    json_set_object(result);
    (void)json_push_kv_str(result, "state", state);
    if (txid) {
        struct uint256 id;
        char hex[65];
        memcpy(id.data, txid, 32);
        uint256_get_hex(&id, hex);
        (void)json_push_kv_str(result, "txid", hex);
    }
    (void)json_push_kv_bool(result, "replayed", replayed);
}

static void wso_released(struct json_value *result, const char *message)
{
    json_set_object(result);
    (void)json_push_kv_str(result, "state", WALLET_SEND_ONCE_STATE_RELEASED);
    (void)json_push_kv_str(result, "message", message);
}

enum wso_begin { WSO_RUN, WSO_ANSWERED };

/* Answer a key that already has a row. */
static void wso_known(struct wallet_rpc_context *ctx,
                      const struct wallet_send_once_row *row,
                      const uint8_t digest[32], int64_t now,
                      struct json_value *result)
{
    if (memcmp(row->digest, digest, 32) != 0) {
        LOG_WARN(WSO_TAG, "key reused with different parameters");
        wso_answer(result, "key_conflict", NULL, true);
        return;
    }
    if (row->state == WALLET_SEND_ONCE_BUILT) {
        struct uint256 id;
        memcpy(id.data, row->txid, 32);
        if (wso_wallet_has(ctx, &id)) {
            (void)wso_advance(ctx->node_db, row->key_hash,
                WALLET_SEND_ONCE_COMMITTED, row->txid, now);
            wso_answer(result, "committed", row->txid, true);
            return;
        }
    }
    if (row->state == WALLET_SEND_ONCE_COMMITTED) {
        wso_answer(result, "committed", row->txid, true);
        return;
    }
    LOG_WARN(WSO_TAG, "repeat of a key with no known outcome");
    wso_answer(result, "outcome_unknown", row->has_txid ? row->txid : NULL,
               true);
}

static enum wso_begin wso_begin_send(struct wallet_rpc_context *ctx,
                                     const uint8_t kh[32],
                                     const uint8_t digest[32], int64_t now,
                                     struct json_value *result)
{
    if (wso_is_active(kh)) {
        wso_answer(result, "in_progress", NULL, true);
        return WSO_ANSWERED;
    }
    if (now - g_last_prune >= WSO_PRUNE_EVERY_SEC) {
        (void)wso_prune(ctx->node_db, now);
        g_last_prune = now;
    }
    struct wallet_send_once_row row;
    if (db_wallet_send_once_find(ctx->node_db, kh, &row)) {
        wso_known(ctx, &row, digest, now, result);
        return WSO_ANSWERED;
    }
    if (db_wallet_send_once_count(ctx->node_db) >= WALLET_SEND_ONCE_MAX_ROWS ||
        g_active_n >= WSO_ACTIVE_MAX) {
        wso_released(result, "Too many keyed sends on record");
        return WSO_ANSWERED;
    }
    memset(&row, 0, sizeof(row));
    memcpy(row.key_hash, kh, 32);
    memcpy(row.digest, digest, 32);
    row.state = WALLET_SEND_ONCE_STARTED;
    row.created_at = row.updated_at = now;
    if (!wso_insert(ctx->node_db, &row)) {
        wso_released(result, "Cannot record the send key");
        return WSO_ANSWERED;
    }
    memcpy(g_active[g_active_n++], kh, 32);
    return WSO_RUN;
}

/* Settle the row after the send ran. Success commits it; a failure keeps the
 * key only when the transaction may exist. */
static bool wso_finish(struct wallet_rpc_context *ctx, struct wso_scope *sc,
                       bool ok, const struct json_value *inner,
                       struct json_value *result)
{
    if (ok) {
        const char *hex = json_get_str(inner);
        if (!sc->built && hex && strlen(hex) == 64) {
            uint256_set_hex(&sc->txid, hex);
            sc->built = true;
        }
        if (!sc->built) {
            LOG_ERROR(WSO_TAG, "send succeeded without a recorded txid");
            wso_answer(result, "outcome_unknown", NULL, false);
            return true;
        }
        (void)wso_advance(ctx->node_db, sc->key_hash,
            WALLET_SEND_ONCE_COMMITTED, sc->txid.data, GetTime());
        wso_answer(result, "committed", sc->txid.data, false);
        return true;
    }
    const char *why = json_get_str(inner);
    if ((!sc->built || !wso_wallet_has(ctx, &sc->txid)) &&
        wso_release(ctx->node_db, sc->key_hash)) {
        wso_released(result, why ? why : "Shielded send failed");
        return true;
    }
    json_set_str(result, why ? why : "Shielded send failed");
    return false;
}

static bool wso_check_fee(const struct json_value *params,
                          struct wallet_rpc_context *ctx,
                          struct json_value *result)
{
    const struct json_value *f = json_at(params, WALLET_SEND_ONCE_FEE_PARAM);
    if (!f || json_is_null(f))
        return true;
    if (!ctx->wallet || parse_amount(f) != ctx->wallet->default_fee) {
        wso_released(result, "Fee changed since the plan; plan the send again");
        LOG_FAIL(WSO_TAG, "wallet fee differs from the planned fee");
    }
    return true;
}

bool wallet_send_once_dispatch(const struct json_value *params, bool help,
                               wallet_send_once_fn plain,
                               struct json_value *result)
{
    const struct json_value *kv = json_at(params, WALLET_SEND_ONCE_KEY_PARAM);
    if (help || !kv || json_is_null(kv))
        return plain(params, help, result);
    const char *key = json_get_str(kv);
    struct wallet_rpc_context *ctx = wallet_rpc_context_current();
    uint8_t kh[32], digest[32];
    if (!wallet_send_once_key_valid(key)) {
        json_set_str(result, "Invalid idempotency key");
        return false;
    }
    if (!ctx->node_db || !ctx->node_db->open || !ctx->wallet) {
        wso_released(result, "Send record unavailable");
        return true;
    }
    if (!wso_check_fee(params, ctx, result))
        return true; // released answer already set
    if (!wso_digest(key, params, digest)) {
        wso_released(result, "Send request too large");
        return true;
    }
    wso_key_hash(key, kh);

    (void)zcl_once_call(&g_once, wso_init);
    zcl_mutex_lock(&g_lock);
    enum wso_begin b = wso_begin_send(ctx, kh, digest, GetTime(), result);
    zcl_mutex_unlock(&g_lock);
    if (b != WSO_RUN)
        return b == WSO_ANSWERED;

    struct wso_scope sc = { .ndb = ctx->node_db };
    memcpy(sc.key_hash, kh, 32);
    struct json_value inner;
    json_init(&inner);
    g_scope = &sc;
    bool ok = plain(params, false, &inner);
    g_scope = NULL;

    zcl_mutex_lock(&g_lock);
    bool answered = wso_finish(ctx, &sc, ok, &inner, result);
    wso_deactivate(kh);
    zcl_mutex_unlock(&g_lock);
    json_free(&inner);
    return answered;
}

struct zcl_result wallet_send_once_before_commit(const struct uint256 *txid)
{
    struct wso_scope *sc = g_scope;
    if (!sc)
        return ZCL_OK;
    if (sc->built)
        return memcmp(sc->txid.data, txid->data, 32) == 0 ? ZCL_OK
            : ZCL_ERR(-1, "a keyed send may admit only one transaction");
    if (!wso_advance(sc->ndb, sc->key_hash,
            WALLET_SEND_ONCE_BUILT, txid->data, GetTime()))
        return ZCL_ERR(-1, "send record could not be advanced; send refused");
    sc->txid = *txid;
    sc->built = true;
    return ZCL_OK;
}
