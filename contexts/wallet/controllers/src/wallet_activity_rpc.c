/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * walletsummary and wallethistory node RPCs behind core.wallet.summary and
 * core.wallet.history. Read-only: they read the wallet fact rows and the
 * loaded viewing keys (ivk), never a spending key, and write nothing. No
 * amount, address or memo reaches a log line. */

#include "controllers/wallet_shielded_internal.h"
#include "controllers/wallet_activity.h"
#include "controllers/sovereignty_controller.h"
#include "services/node_health_service.h"
#include "wallet/wallet_lock.h"
#include "core/uint256.h"

#include <inttypes.h>
#include <stdlib.h>

/* The one place the summary asks whether the wallet may send. */
bool wallet_send_gate(char *reason, size_t cap)
{
    return sovereignty_guard_allow("wallet_spend", reason, cap);
}

static void wa_kv_null(struct json_value *obj, const char *key)
{
    struct json_value v;
    json_init(&v);
    json_set_null(&v);
    json_push_kv(obj, key, &v);
    json_free(&v);
}

static void wa_kv_amount(struct json_value *obj, const char *zat_key,
                         const char *str_key, int64_t v)
{
    char buf[32];
    format_amount(v, buf, sizeof(buf));
    json_push_kv_int(obj, zat_key, v);
    json_push_kv_str(obj, str_key, buf);
}

static int wa_max_int(int a, int b)
{
    return a > b ? a : b;
}

static void wa_summary_chain(const struct wallet_chain_view *v,
                             struct json_value *out)
{
    int ahead = wa_max_int(v->header_height, v->peer_best_height);
    int behind = ahead > v->tip_height ? ahead - v->tip_height : 0;
    json_push_kv_int(out, "tip_height", v->tip_height);
    json_push_kv_int(out, "header_height", v->header_height);
    json_push_kv_int(out, "scanned_through_height", v->scanned_through);
    json_push_kv_int(out, "blocks_behind", behind);
    json_push_kv_bool(out, "current",
                      v->tip_height >= 0 && v->scanned_through >= v->tip_height &&
                      behind <= 1);
}

void wallet_summary_to_json(const struct wallet_summary *s,
                            const struct wallet_chain_view *v,
                            bool send_allowed, const char *send_reason,
                            struct json_value *out)
{
    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.wallet_summary.v1");
    wa_kv_amount(out, "spendable_zat", "spendable", s->spendable);
    wa_kv_amount(out, "pending_zat", "pending", s->pending);
    json_push_kv_int(out, "pending_notes", s->pending_count);
    json_push_kv_int(out, "pending_min_confirmations_needed",
                     s->pending_min_confs_needed);
    wa_kv_amount(out, "sending_zat", "sending", s->sending);
    wa_kv_amount(out, "public_zat", "public", s->public_confirmed);
    wa_kv_amount(out, "immature_zat", "immature", s->immature);
    wa_summary_chain(v, out);
    json_push_kv_bool(out, "locked", v->locked);
    json_push_kv_bool(out, "encrypted", v->encrypted);
    json_push_kv_int(out, "shielded_keys", (int64_t)v->shielded_keys);
    json_push_kv_bool(out, "send_allowed", send_allowed);
    json_push_kv_str(out, "send_blocked_reason",
                     send_allowed || !send_reason ? "" : send_reason);
}

void wallet_history_entry_to_json(const struct wallet_history_entry *e,
                                  struct json_value *out)
{
    static const char *const dir[] = { "received", "sent", "internal",
                                       "unknown" };
    char hex[65];
    wallet_txid_hex_le(e->txid, hex);
    json_set_object(out);
    json_push_kv_str(out, "txid", hex);
    json_push_kv_str(out, "status", e->height > 0 ? "confirmed" : "pending");
    if (e->height > 0)
        json_push_kv_int(out, "height", e->height);
    else
        wa_kv_null(out, "height");
    json_push_kv_int(out, "confirmations", e->confirmations);
    if (e->time > 0)
        json_push_kv_int(out, "time", e->time);
    else
        wa_kv_null(out, "time");
    json_push_kv_str(out, "direction", dir[e->direction]);
    json_push_kv_str(out, "kind", e->private_kind ? "private" : "public");
    if (e->amount_known)
        wa_kv_amount(out, "amount_zat", "amount", e->amount);
    else {
        wa_kv_null(out, "amount_zat");
        wa_kv_null(out, "amount");
    }
    if (e->fee_known)
        wa_kv_amount(out, "fee_zat", "fee", e->fee);
    else {
        wa_kv_null(out, "fee_zat");
        wa_kv_null(out, "fee");
    }
    json_push_kv_int(out, "net_zat", e->net);
    json_push_kv_bool(out, "memo_present", e->memo_present);
}

/* ── wallet state ────────────────────────────────────────────────── */

struct wa_keys {
    uint8_t (*ivk)[32];
    size_t n;
};

/* Copy the distinct loaded viewing keys. A repeated ivk is kept once. */
static bool wa_keys_collect(struct wallet_rpc_context *ctx, struct wa_keys *k)
{
    struct sapling_keystore *ks = &ctx->wallet->sapling_keys;
    k->n = 0;
    k->ivk = zcl_calloc(MAX_SAPLING_KEYS + 1, 32, "wallet ivk copy");
    if (!k->ivk)
        return false;
    zcl_mutex_lock(&ks->cs);
    for (size_t i = 0; i < ks->num_keys && i < MAX_SAPLING_KEYS; i++) {
        bool dup = false;
        for (size_t j = 0; j < k->n && !dup; j++)
            dup = memcmp(k->ivk[j], ks->keys[i].ivk, 32) == 0;
        if (ks->keys[i].used && !dup)
            memcpy(k->ivk[k->n++], ks->keys[i].ivk, 32);
    }
    zcl_mutex_unlock(&ks->cs);
    return true;
}

static void wa_chain_view(struct wallet_rpc_context *ctx,
                          const struct wa_keys *k,
                          struct wallet_chain_view *v)
{
    struct node_health_snapshot h = {0};
    node_health_collect(&h, ctx->node_db, ctx->main_state);
    memset(v, 0, sizeof(*v));
    v->tip_height = h.tip_height;
    if (v->tip_height < 0)
        v->tip_height = db_wallet_chain_tip_height(ctx->node_db);
    v->header_height = h.header_height;
    v->peer_best_height = h.peer_best_height;
    v->scanned_through = wallet_read_scanned_through_height(ctx->wallet);
    v->encrypted = wallet_lock_encrypted_at_rest();
    v->locked = !wallet_lock_is_unlocked();
    v->shielded_keys = k->n;
}

struct wa_facts {
    struct db_wallet_note_fact *notes;
    struct db_wallet_coin_fact *coins;
    struct db_wallet_tx_fact *txs;
    int nn, nc, nt;
};

static void wa_facts_free(struct wa_facts *f)
{
    free(f->notes);
    free(f->coins);
    free(f->txs);
}

static bool wa_facts_load(struct node_db *ndb, struct wa_facts *f)
{
    memset(f, 0, sizeof(*f));
    f->nn = db_wallet_note_facts_alloc(ndb, &f->notes);
    f->nc = db_wallet_coin_facts_alloc(ndb, &f->coins);
    f->nt = db_wallet_tx_facts_alloc(ndb, &f->txs);
    if (f->nn >= 0 && f->nc >= 0 && f->nt >= 0)
        return true;
    wa_facts_free(f);
    return false;
}

static bool wa_ready(struct wallet_rpc_context *ctx, struct json_value *result)
{
    if (!ctx->wallet || !wallet_ctx_db_ready(ctx)) {
        json_set_str(result, "Wallet not available");
        LOG_FAIL("wallet_activity", "wallet or node database not ready");
    }
    return true;
}

bool rpc_walletsummary(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletsummary\n"
        "\nReturns spendable, pending and public funds with sync state.\n");
    (void)params;
    if (!wa_ready(ctx, result))
        return false; // raw-return-ok:callee-logged

    struct wa_keys keys;
    struct wa_facts f;
    if (!wa_keys_collect(ctx, &keys)) {
        json_set_str(result, "Out of memory");
        return false;
    }
    if (!wa_facts_load(ctx->node_db, &f)) {
        free(keys.ivk);
        json_set_str(result, "Wallet database unreadable");
        LOG_FAIL("wallet_activity", "walletsummary: fact load failed");
    }
    struct wallet_chain_view view;
    struct wallet_summary sum;
    wa_chain_view(ctx, &keys, &view);
    wallet_summary_accumulate(f.notes, (size_t)f.nn, f.coins, (size_t)f.nc,
                              f.txs, (size_t)f.nt,
                              (const uint8_t (*)[32])keys.ivk, keys.n,
                              view.tip_height, &sum);
    char reason[96] = {0};
    bool allowed = wallet_send_gate(reason, sizeof(reason));
    wallet_summary_to_json(&sum, &view, allowed, reason, result);
    wa_facts_free(&f);
    free(keys.ivk);
    return true;
}

/* ── history ─────────────────────────────────────────────────────── */

static void wa_detail_memo(struct wallet_rpc_context *ctx,
                           const struct wa_keys *k, const uint8_t txid[32],
                           struct json_value *entry)
{
    struct db_wallet_note_memo memos[32];
    int n = db_wallet_note_memos_for_tx(ctx->node_db, txid, memos, 32);
    bool found = false;
    for (int i = 0; i < n && !found; i++) {
        bool mine = false;
        for (size_t j = 0; j < k->n && !mine; j++)
            mine = memcmp(k->ivk[j], memos[i].ivk, 32) == 0;
        if (!mine)
            continue;
        if (memos[i].address[0])
            json_push_kv_str(entry, "address", memos[i].address);
        size_t before = entry->num_children;
        wallet_memo_to_json(entry, memos[i].memo, memos[i].memo_len);
        found = entry->num_children > before;
    }
    wa_kv_null(entry, "counterparty");
    json_push_kv_bool(entry, "counterparty_known", false);
}

static bool wa_history_detail(struct wallet_rpc_context *ctx,
                              const struct wa_keys *k,
                              const struct wallet_history_entry *e, int n,
                              const char *txid_hex, struct json_value *result)
{
    struct uint256 id;
    uint256_set_hex(&id, txid_hex);
    for (int i = 0; i < n; i++) {
        if (memcmp(e[i].txid, id.data, 32) != 0)
            continue;
        struct json_value entry;
        json_init(&entry);
        wallet_history_entry_to_json(&e[i], &entry);
        wa_detail_memo(ctx, k, e[i].txid, &entry);
        json_set_object(result);
        json_push_kv_str(result, "schema", "zcl.wallet_history.v1");
        json_push_kv(result, "entry", &entry);
        json_free(&entry);
        return true;
    }
    json_set_str(result, "Transaction is not in wallet history");
    return false;
}

static void wa_history_page(const struct wallet_history_entry *e, int n,
                            size_t start, size_t limit,
                            struct json_value *result)
{
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    size_t end = start + limit < (size_t)n ? start + limit : (size_t)n;
    for (size_t i = start; i < end; i++) {
        struct json_value item;
        json_init(&item);
        wallet_history_entry_to_json(&e[i], &item);
        json_push_back(&list, &item);
        json_free(&item);
    }
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.wallet_history.v1");
    json_push_kv(result, "entries", &list);
    json_push_kv_int(result, "count", (int64_t)(end - start));
    json_free(&list);
    if (end < (size_t)n) {
        char cur[96];
        wallet_history_cursor_format(&e[end - 1], cur, sizeof(cur));
        json_push_kv_str(result, "next_cursor", cur);
    } else {
        wa_kv_null(result, "next_cursor");
    }
}

static bool wa_history_args(const struct json_value *params, size_t *limit,
                            struct wallet_history_cursor *cur,
                            const char **txid, struct json_value *result)
{
    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 0, 3);
    int64_t lim = rpc_permit_int(&p, 0, "limit", WALLET_HISTORY_DEFAULT_LIMIT);
    const char *cursor = rpc_permit_str(&p, 1, "cursor", "");
    *txid = rpc_permit_str(&p, 2, "txid", "");
    if (rpc_params_invalid(&p)) {
        rpc_params_error(&p, result);
        LOG_FAIL("wallet_activity", "wallethistory: invalid params");
    }
    if (lim < 1 || lim > WALLET_HISTORY_MAX_LIMIT ||
        (cursor[0] && !wallet_history_cursor_parse(cursor, cur)) ||
        ((*txid)[0] && strlen(*txid) != 64)) {
        json_set_str(result, "Invalid limit, cursor or txid");
        LOG_FAIL("wallet_activity", "wallethistory: argument out of range");
    }
    *limit = (size_t)lim;
    return true;
}

bool rpc_wallethistory(const struct json_value *params, bool help,
                       struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "wallethistory ( limit \"cursor\" \"txid\" )\n"
        "\nReturns wallet transactions newest first, paged by cursor.\n");
    if (!wa_ready(ctx, result))
        return false; // raw-return-ok:callee-logged
    size_t limit = 0;
    const char *txid = "";
    struct wallet_history_cursor cur = {0};
    if (!wa_history_args(params, &limit, &cur, &txid, result))
        return false; // raw-return-ok:callee-logged

    struct wa_keys keys;
    struct wa_facts f;
    if (!wa_keys_collect(ctx, &keys)) {
        json_set_str(result, "Out of memory");
        return false;
    }
    if (!wa_facts_load(ctx->node_db, &f)) {
        free(keys.ivk);
        json_set_str(result, "Wallet database unreadable");
        LOG_FAIL("wallet_activity", "wallethistory: fact load failed");
    }
    struct wallet_chain_view view;
    wa_chain_view(ctx, &keys, &view);
    struct wallet_history_entry *e = NULL;
    int n = wallet_history_build(f.notes, (size_t)f.nn, f.coins, (size_t)f.nc,
                                 f.txs, (size_t)f.nt,
                                 (const uint8_t (*)[32])keys.ivk, keys.n,
                                 view.tip_height, &e);
    bool ok = n >= 0;
    if (!ok)
        json_set_str(result, "Out of memory");
    else if (txid[0])
        ok = wa_history_detail(ctx, &keys, e, n, txid, result);
    else
        wa_history_page(e, n, wallet_history_page_start(e, (size_t)n, &cur),
                        limit, result);
    free(e);
    wa_facts_free(&f);
    free(keys.ivk);
    return ok;
}

/* Most recently added shielded address, or false when the wallet has none.
 * Reads the keystore only; it derives and stores nothing. */
bool wallet_latest_shielded_address(const struct sapling_keystore *ks,
                                    const char *hrp, char *out, size_t cap)
{
    bool found = false;
    zcl_mutex_lock((zcl_mutex_t *)&ks->cs);
    for (size_t i = ks->num_keys; i > 0 && !found; i--) {
        const struct sapling_key_entry *k = &ks->keys[i - 1];
        found = k->used &&
                sapling_encode_payment_address(k->diversifier, k->pk_d, hrp,
                                               out, cap);
    }
    zcl_mutex_unlock((zcl_mutex_t *)&ks->cs);
    return found;
}

bool rpc_walletlatestaddress(const struct json_value *params, bool help,
                             struct json_value *result)
{
    struct wallet_rpc_context *ctx = wallet_ctx();
    RPC_HELP(help, result, "walletlatestaddress\n"
        "\nReturns the newest shielded address, or null. Creates nothing.\n");
    (void)params;
    if (!ctx->wallet) {
        json_set_str(result, "Wallet not available");
        LOG_FAIL("wallet_activity", "walletlatestaddress: no wallet");
    }
    const struct chain_params *cp = chain_params_get();
    char addr[128];
    bool have = cp && wallet_latest_shielded_address(
        &ctx->wallet->sapling_keys,
        cp->bech32HRPs[BECH32_SAPLING_PAYMENT_ADDRESS], addr, sizeof(addr));
    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.wallet_latest_address.v1");
    if (have)
        json_push_kv_str(result, "address", addr);
    else
        wa_kv_null(result, "address");
    return true;
}

void register_wallet_activity_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "wallet", "walletlatestaddress", rpc_walletlatestaddress, false },
        { "wallet", "walletsummary", rpc_walletsummary, false },
        { "wallet", "wallethistory", rpc_wallethistory, false },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
