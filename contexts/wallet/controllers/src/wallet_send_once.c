/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: make a keyed z_sendmany spend at most once.
 *
 * Order for a keyed send: record the key (STARTED), build, make the txid
 * durable (BUILT; synchronous=FULL, in its own transaction) before the wallet
 * admits the transaction, run the rest of the send, record COMMITTED. A repeat
 * reads the row first and is answered from it:
 *   COMMITTED and the wallet holds the txid   -> committed, the earlier txid
 *   COMMITTED and the wallet lost the txid    -> outcome_unknown with the txid
 *   BUILT, whether or not the wallet holds it -> outcome_unknown with the txid
 *   BUILT under the zero txid                 -> outcome_unknown, no txid
 *   STARTED, nobody running it                -> the row is freed, the send runs
 *   other digest, an earlier build's for this -> outcome_unknown, no txid
 *   other digest                              -> key_conflict
 * The wallet persists a transaction before it relays it, but holding a
 * transaction does not prove it was relayed, so BUILT never answers committed.
 *
 * A failed run frees its key only when the wallet never admitted the
 * transaction. After admission the pool may have held it and a peer may have
 * fetched it, so any later failure answers outcome_unknown with the txid and
 * the row stays. A built record that cannot be written before admission
 * refuses the send and releases the key, because nothing was sent. A record
 * that cannot be read or created, and a full table, refuse the send with a
 * plain error that does not claim the key is free. Logs carry no address,
 * amount, memo, key or txid. */

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
#include "util/safe_alloc.h"
#include "util/sync.h"
#include "wallet/wallet.h"

#include <ctype.h>
#include <string.h>

#define WSO_TAG "wallet_send_once"
#define WSO_ACTIVE_MAX 64
#define WSO_PRUNE_EVERY_SEC 3600
#define WSO_SYNC_FULL 2

struct wso_scope {
    struct node_db *ndb;
    uint8_t key_hash[32];
    bool built;      /* txid made durable */
    bool admitted;   /* the wallet admitted the transaction: never release */
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
    bool durable;   /* fsync the write-ahead log before the commit returns */
    bool ok;
};

static bool wso_apply(struct node_db *ndb, const struct wso_op *op)
{
    switch (op->kind) {
    case WSO_OP_INSERT:
        return db_wallet_send_once_insert(ndb, op->row);
    case WSO_OP_ADVANCE:
        return db_wallet_send_once_advance(ndb, op->key_hash, op->state,
                                           op->txid, op->now);
    case WSO_OP_RELEASE:
        return db_wallet_send_once_release(ndb, op->key_hash);
    case WSO_OP_PRUNE:
        return db_wallet_send_once_prune(ndb, op->now);
    }
    return false; // raw-return-ok:every kind is handled above
}

/* The synchronous level only changes outside a transaction, so it is raised
 * first and the write then runs in its own BEGIN IMMEDIATE ... COMMIT. A
 * writer that opened a transaction on this connection in between makes BEGIN
 * fail, and the write is refused rather than joining a transaction it does not
 * own. The level is read back inside the transaction before the write. */
static bool wso_apply_durable(struct node_db *ndb, const struct wso_op *op)
{
    /* Restore the level found (turbo import runs with OFF), not a constant. */
    int prev_sync = db_wallet_send_once_sync_level(ndb);
    if (prev_sync < 0) {
        LOG_ERROR(WSO_TAG, "cannot read node.db synchronous level");
        return false;
    }
    if (!node_db_exec(ndb, "PRAGMA synchronous=FULL")) {
        LOG_ERROR(WSO_TAG, "cannot raise node.db to synchronous=FULL");
        return false;
    }
    bool ok = false;
    if (!node_db_begin_immediate(ndb)) {
        LOG_ERROR(WSO_TAG, "cannot open a node.db transaction for the record");
    } else {
        ok = db_wallet_send_once_sync_level(ndb) >= WSO_SYNC_FULL &&
             wso_apply(ndb, op) && node_db_commit(ndb);
        if (!ok)
            (void)node_db_rollback(ndb);
    }
    char restore[40];
    (void)snprintf(restore, sizeof(restore), "PRAGMA synchronous=%d",
                   prev_sync);
    if (!node_db_exec(ndb, restore))
        LOG_ERROR(WSO_TAG, "cannot restore node.db synchronous level");
    return ok;
}

static bool wso_op_run(struct node_db *ndb, void *opaque)
{
    struct wso_op *op = opaque;
    op->ok = false;
    if (ndb->sync_in_batch && !node_db_sync_flush(ndb)) {
        LOG_ERROR(WSO_TAG, "pending node.db batch could not be committed");
        return true;
    }
    op->ok = op->durable ? wso_apply_durable(ndb, op) : wso_apply(ndb, op);
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
                        int64_t now, bool durable)
{
    struct wso_op op = { .kind = WSO_OP_ADVANCE, .key_hash = kh,
                         .state = state, .txid = txid, .now = now,
                         .durable = durable };
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

/* Absorb one request parameter as JSON text, every byte of it: a retry whose
 * tail differs must not share a digest with the send already on record. */
static bool wso_absorb_json(struct sha3_256_ctx *c, const struct json_value *v)
{
    size_t size = json_write(v, NULL, 0) + 1;
    char *text = zcl_malloc(size, "wso_digest_param");
    if (!text)
        LOG_FAIL(WSO_TAG, "no memory to read the send request");
    (void)json_write(v, text, size);
    wso_absorb(c, text);
    free(text);
    return true;
}

/* Bound to the key, so the digest of a low-entropy request cannot be tested
 * against a copy of node.db without the key. Absent and null fees absorb the
 * empty string. */
static bool wso_digest(const char *key, const struct json_value *params,
                       uint8_t out[32])
{
    const struct json_value *f = json_at(params, WALLET_SEND_ONCE_FEE_PARAM);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    wso_absorb(&c, "z23/wallet-send-once/request/v1");
    wso_absorb(&c, key);
    if (!wso_absorb_json(&c, json_at(params, 0)) ||
        !wso_absorb_json(&c, json_at(params, 1)))
        return false; // raw-return-ok:callee-logged
    if (f && !json_is_null(f)) {
        if (!wso_absorb_json(&c, f))
            return false; // raw-return-ok:callee-logged
    } else {
        wso_absorb(&c, "");
    }
    sha3_256_finalize(&c, out);
    return true;
}

/* The digest an earlier build stored for this request: each value written into
 * the fixed buffer that build used, so a longer one is cut where it was cut. */
static void wso_legacy_digest(const char *key, const struct json_value *params,
                              uint8_t out[32])
{
    const struct json_value *f = json_at(params, WALLET_SEND_ONCE_FEE_PARAM);
    char from[1024] = "", recips[16384] = "", fee[64] = "";
    (void)json_write(json_at(params, 0), from, sizeof(from));
    (void)json_write(json_at(params, 1), recips, sizeof(recips));
    if (f && !json_is_null(f))
        (void)json_write(f, fee, sizeof(fee));
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    wso_absorb(&c, "z23/wallet-send-once/request/v1");
    wso_absorb(&c, key);
    wso_absorb(&c, from);
    wso_absorb(&c, recips);
    wso_absorb(&c, fee);
    sha3_256_finalize(&c, out);
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

static void wso_released(struct json_value *result, const char *state,
                         const char *message)
{
    json_set_object(result);
    (void)json_push_kv_str(result, "state", state);
    (void)json_push_kv_str(result, "message", message);
}

static bool wso_fee_ok(const struct json_value *params,
                       const struct wallet_rpc_context *ctx)
{
    const struct json_value *f = json_at(params, WALLET_SEND_ONCE_FEE_PARAM);
    if (!f || json_is_null(f))
        return true;
    if (!ctx->wallet || parse_amount(f) != ctx->wallet->default_fee) {
        LOG_WARN(WSO_TAG, "wallet fee differs from the planned fee");
        return false; // raw-return-ok:logged; caller answers fee_changed
    }
    return true;
}

enum wso_begin { WSO_RUN, WSO_ANSWERED, WSO_ERROR, WSO_RERUN };

struct wso_request {
    const char *key;
    const struct json_value *params;
    uint8_t digest[32];
};

/* A row whose digest is not this request's. A row an earlier build wrote for
 * this request holds its legacy digest, and that send may have gone out: a
 * conflict would tell the client to pay again under a new key, and a txid would
 * claim this exact request was the one sent. So it answers outcome_unknown with
 * neither, whatever the row's state. */
static void wso_answer_mismatch(const struct wallet_send_once_row *row,
                                const struct wso_request *req,
                                struct json_value *result)
{
    uint8_t legacy[32];
    wso_legacy_digest(req->key, req->params, legacy);
    if (memcmp(row->digest, legacy, 32) == 0) {
        LOG_WARN(WSO_TAG, "repeat of a key recorded by an earlier build");
        wso_answer(result, "outcome_unknown", NULL, true);
        return;
    }
    LOG_WARN(WSO_TAG, "key reused with different parameters");
    wso_answer(result, "key_conflict", NULL, true);
}

/* Answer a key that already has a row. A committed row replays only while the
 * wallet still holds its transaction; a built row never replays, because the
 * wallet holding a transaction does not prove it was relayed. */
static enum wso_begin wso_known(struct wallet_rpc_context *ctx,
                                const struct wallet_send_once_row *row,
                                const struct wso_request *req,
                                struct json_value *result)
{
    if (memcmp(row->digest, req->digest, 32) != 0) {
        wso_answer_mismatch(row, req, result);
        return WSO_ANSWERED;
    }
    if (row->state == WALLET_SEND_ONCE_STARTED)
        return WSO_RERUN; /* no txid was ever made durable: never admitted */
    struct uint256 id;
    memcpy(id.data, row->txid, 32);
    if (row->state == WALLET_SEND_ONCE_COMMITTED && wso_wallet_has(ctx, &id)) {
        wso_answer(result, "committed", row->txid, true);
        return WSO_ANSWERED;
    }
    LOG_WARN(WSO_TAG, "repeat of a key with no confirmed send");
    wso_answer(result, "outcome_unknown", uint256_is_null(&id) ? NULL : row->txid,
               true);
    return WSO_ANSWERED;
}

static enum wso_begin wso_error(struct json_value *result, const char *msg)
{
    json_set_str(result, msg);
    return WSO_ERROR;
}

static enum wso_begin wso_insert_new(struct wallet_rpc_context *ctx,
                                     const uint8_t kh[32],
                                     const struct wso_request *req, int64_t now,
                                     struct json_value *result)
{
    struct wallet_send_once_row row;
    memset(&row, 0, sizeof(row));
    memcpy(row.key_hash, kh, 32);
    memcpy(row.digest, req->digest, 32);
    row.state = WALLET_SEND_ONCE_STARTED;
    row.created_at = row.updated_at = now;
    if (wso_insert(ctx->node_db, &row))
        return WSO_RUN;
    /* A failed insert may mean the row exists: read it. If it still cannot be
     * read, say so plainly; never claim the key is free. */
    if (db_wallet_send_once_find(ctx->node_db, kh, &row))
        return wso_known(ctx, &row, req, result);
    return wso_error(result, "Send record unreadable; nothing was changed "
                             "but the outcome of an earlier send is unknown");
}

/* The row is read first. Only a key with no row is checked against the fee. */
static enum wso_begin wso_begin_send(struct wallet_rpc_context *ctx,
                                     const uint8_t kh[32],
                                     const struct wso_request *req, int64_t now,
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
    enum wso_begin b;
    if (db_wallet_send_once_find(ctx->node_db, kh, &row)) {
        b = wso_known(ctx, &row, req, result);
        if (b != WSO_RERUN)
            return b;
        if (!wso_release(ctx->node_db, kh))
            return wso_error(result, "Send record cannot be released");
    }
    if (g_active_n >= WSO_ACTIVE_MAX ||
        db_wallet_send_once_count(ctx->node_db) >= WALLET_SEND_ONCE_MAX_ROWS)
        return wso_error(result, "Too many keyed sends on record; send refused");
    b = wso_insert_new(ctx, kh, req, now, result);
    if (b != WSO_RUN)
        return b == WSO_RERUN ? wso_error(result, "Send record is inconsistent")
                              : b;
    if (!wso_fee_ok(req->params, ctx)) {
        if (!wso_release(ctx->node_db, kh))
            return wso_error(result, "Send record cannot be released");
        wso_released(result, WALLET_SEND_ONCE_STATE_FEE_CHANGED,
                     "Fee changed since the plan; plan the send again");
        return WSO_ANSWERED;
    }
    memcpy(g_active[g_active_n++], kh, 32);
    return WSO_RUN;
}

/* A send reported success and no txid is known, so a started row would run it
 * again on a retry. Hold the key as built under the zero txid, which no
 * transaction has. The table allows only the three states, and a repeat never
 * frees a built row, so every repeat answers outcome_unknown. */
static void wso_hold_unknown(struct node_db *ndb, const uint8_t kh[32])
{
    static const uint8_t unknown_txid[32];
    if (!wso_advance(ndb, kh, WALLET_SEND_ONCE_BUILT, unknown_txid, GetTime(),
                     true))
        LOG_ERROR(WSO_TAG, "cannot hold the key of a send with no txid");
}

/* Settle the row after the send ran. Success commits it. A failure before
 * admission frees the key. A failure after admission keeps the row and answers
 * outcome_unknown: the transaction may be in the mempool or relayed whatever
 * happens next. */
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
            wso_hold_unknown(ctx->node_db, sc->key_hash);
            wso_answer(result, "outcome_unknown", NULL, false);
            return true;
        }
        (void)wso_advance(ctx->node_db, sc->key_hash,
                          WALLET_SEND_ONCE_COMMITTED, sc->txid.data, GetTime(),
                          false);
        wso_answer(result, "committed", sc->txid.data, false);
        return true;
    }
    if (sc->admitted) {
        LOG_WARN(WSO_TAG, "send failed after admission; outcome unknown");
        wso_answer(result, "outcome_unknown", sc->built ? sc->txid.data : NULL,
                   false);
        return true;
    }
    const char *why = json_get_str(inner);
    if (wso_release(ctx->node_db, sc->key_hash)) {
        wso_released(result, WALLET_SEND_ONCE_STATE_RELEASED,
                     why ? why : "Shielded send failed");
        return true;
    }
    json_set_str(result, why ? why : "Shielded send failed");
    return false;
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
    struct wso_request req = { .key = key, .params = params };
    uint8_t kh[32];
    if (!wallet_send_once_key_valid(key)) {
        json_set_str(result, "Invalid idempotency key");
        return false;
    }
    if (!ctx->node_db || !ctx->node_db->open || !ctx->wallet) {
        json_set_str(result, "Send record unavailable; send refused");
        return false;
    }
    if (!wso_digest(key, params, req.digest)) {
        json_set_str(result,
                     "Not enough memory to read the send request; send refused");
        return false;
    }
    wso_key_hash(key, kh);

    (void)zcl_once_call(&g_once, wso_init);
    zcl_mutex_lock(&g_lock);
    enum wso_begin b = wso_begin_send(ctx, kh, &req, GetTime(), result);
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
    /* Durable before admission: after power loss a relayed transaction must
     * still have its row. */
    if (!wso_advance(sc->ndb, sc->key_hash, WALLET_SEND_ONCE_BUILT, txid->data,
                     GetTime(), true))
        return ZCL_ERR(-1, "send record could not be made durable; send refused");
    sc->txid = *txid;
    sc->built = true;
    return ZCL_OK;
}

void wallet_send_once_after_commit(bool admitted)
{
    struct wso_scope *sc = g_scope;
    if (sc && admitted)
        sc->admitted = true;
}
