/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet send glue for the private relay and its status read. */

// supervisor-ok:bounded-tick-thread-stopped-by-registry-shutdown
#include "controllers/wallet_private_broadcast.h"

#include "controllers/strong_params.h"
#include "coins/coins_view.h"
#include "controllers/sync_controller.h"
#include "controllers/wallet_helpers.h"
#include "models/database.h"
#include "primitives/transaction.h"
#include "services/chain_nullifier_evidence_service.h"
#include "json/json.h"
#include "net/connman.h"
#include "platform/clock.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

#include <stdatomic.h>
#include <string.h>

struct wallet_rpc_context *wallet_send_view(struct wallet_rpc_context *ctx,
                                            struct wallet_rpc_context *view)
{
    struct wpr *relay = wpr_global();
    if (wpr_get_mode(relay) != WPR_MODE_PRIVATE)
        return ctx;
    *view = *ctx;
    view->mempool = wpr_pool(relay);
    view->connman = NULL;
    return view;
}

/* Callers resending a prepared (vault) transaction keep public relay. */
struct wallet_rpc_context *wallet_send_view_unless_prepared(
    struct wallet_rpc_context *ctx, struct wallet_rpc_context *view,
    const void *prepared)
{
    return prepared ? ctx : wallet_send_view(ctx, view);
}

#define WPB_ROLLED_BACK_TEXT "Private broadcast unavailable; send rolled back"
#define WPB_UNKNOWN_TEXT \
    "Private broadcast could not be queued and the send could not be fully " \
    "rolled back: its outcome is unknown. Do not pay again; check " \
    "walletbroadcaststatus and the wallet history."

static _Thread_local const char *g_relay_failure = WPB_ROLLED_BACK_TEXT;

const char *wallet_send_relay_failure_text(void)
{
    return g_relay_failure;
}

bool wallet_send_relay(struct wallet_rpc_context *ctx, struct wallet_tx *wtx)
{
    struct wpr *relay = wpr_global();
    g_relay_failure = WPB_ROLLED_BACK_TEXT;
    if (ctx->mempool != wpr_pool(relay)) {
        if (ctx->connman)
            connman_relay_transaction(ctx->connman, &wtx->tx.hash);
        return true;
    }
    struct zcl_result queued = wpr_enqueue(relay, &wtx->tx);
    if (queued.ok)
        return true;
    LOG_WARN("wallet", "private broadcast not queued (code=%d): %s",
             queued.code, queued.message);
    struct zcl_result rolled = wallet_rollback_persisted_commit(ctx, wtx);
    if (!rolled.ok) {
        /* The wallet may still hold the send and the pending record is kept,
         * so a later tick or restart can still deliver it. */
        g_relay_failure = WPB_UNKNOWN_TEXT;
        LOG_FAIL("wallet", "private broadcast rollback failed (code=%d): %s",
                rolled.code, rolled.message);
    }
    wpr_forget(relay, &wtx->tx.hash);
    return false;
}

enum wpb_expiry {
    WPB_EXPIRY_RETURNED,   /* coins back, terminal record kept */
    WPB_EXPIRY_HELD,       /* the chain may hold it: not rolled back */
    WPB_EXPIRY_DEFERRED,   /* confirmed, or the database write is retried */
};

/* No Sapling nullifier of the send is revealed on chain. */
static bool wpb_nullifiers_unseen(const struct transaction *tx)
{
    size_t n = tx->num_shielded_spend;
    if (n == 0)
        return true;
    if (!chain_nullifier_evidence_history_complete()) {
        LOG_WARN("wallet_pbcast", "nullifier history incomplete; spend cannot be proved unseen");
        return false;
    }
    struct chain_nullifier_query *q = zcl_calloc(n, sizeof(*q), "wpb_nf");
    if (!q) {
        LOG_WARN("wallet_pbcast", "nullifier query allocation failed");
        return false;
    }
    for (size_t i = 0; i < n; i++)
        q[i].bytes = tx->v_shielded_spend[i].nullifier.data;
    struct chain_nullifier_set_evidence ev;
    struct zcl_result r = chain_nullifier_evidence_lookup_set(
        q, n, CHAIN_NULLIFIER_POOL_SAPLING, &ev);
    free(q);
    return r.ok && !ev.any_found;
}

/* True only when the chain view PROVES every input still unspent. An input
 * that is spent or that the view cannot show means the send may be on chain,
 * so the answer is false. */
static bool wpb_chain_shows_unspent(struct wallet_rpc_context *base,
                                    const struct transaction *tx)
{
    if (!base->coins_tip || !base->main_state)
        return false;
    zcl_mutex_lock(&base->main_state->cs_main);
    bool inputs = coins_view_cache_have_inputs(base->coins_tip, tx);
    zcl_mutex_unlock(&base->main_state->cs_main);
    return inputs && wpb_nullifiers_unseen(tx);
}

static enum wpb_expiry wpb_roll_back(struct wpr *relay,
                                     const struct wallet_rpc_context *view,
                                     const struct wallet_tx *wtx)
{
    struct zcl_result rolled = wallet_rollback_persisted_commit(view, wtx);
    if (rolled.ok)
        return WPB_EXPIRY_RETURNED;
    LOG_WARN("wallet", "expired private send rollback failed (code=%d): %s",
             rolled.code, rolled.message);
    /* Code -3: memory is rolled back, the database row remains. */
    if (rolled.code == -3)
        wpr_set_disk_retry(relay, &wtx->tx.hash, true);
    return WPB_EXPIRY_DEFERRED;
}

static enum wpb_expiry wpb_expire_held_tx(struct wpr *relay,
                                          struct wallet_rpc_context *base,
                                          const struct wallet_rpc_context *view,
                                          const struct wallet_tx *wtx)
{
    if (wtx->confirms > 0) {
        wpr_note_seen(relay, &wtx->tx.hash);
        return WPB_EXPIRY_DEFERRED;
    }
    if (!wpb_chain_shows_unspent(base, &wtx->tx)) {
        wpr_mark_held(relay, &wtx->tx.hash, true);
        return WPB_EXPIRY_HELD;
    }
    return wpb_roll_back(relay, view, wtx);
}

/* The wallet memory no longer holds the send but its database row survived an
 * earlier failed delete: finish the delete. */
static bool wpb_finish_disk_delete(struct wallet_rpc_context *base,
                                   const struct uint256 *txid)
{
    if (!base->wallet_db)
        return true;
    return base->node_db && base->node_db->open &&
           node_db_sync_wallet_tx_delete(base->node_db, txid->data);
}

static enum wpb_expiry wpb_expire(const struct uint256 *txid)
{
    struct wpr *relay = wpr_global();
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    struct wallet_rpc_context view = *base;
    view.mempool = wpr_pool(relay);
    view.connman = NULL;

    enum wpb_expiry out;
    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (base->wallet && wallet_get_tx_copy(base->wallet, txid, &wtx)) {
        out = wpb_expire_held_tx(relay, base, &view, &wtx);
        transaction_free(&wtx.tx);
    } else if (wpr_disk_retry(relay, txid)) {
        out = wpb_finish_disk_delete(base, txid) ? WPB_EXPIRY_RETURNED
                                                 : WPB_EXPIRY_DEFERRED;
    } else {
        out = WPB_EXPIRY_RETURNED;  /* the wallet never held it */
    }
    if (out == WPB_EXPIRY_RETURNED)
        wpr_mark_expired(relay, txid);
    return out;
}

/* The wallet has read blocks through a height past the send's expiry and
 * margin and no block holds it. The coins return only when the chain view
 * proves every input unspent; otherwise the record stays. */
bool wallet_private_broadcast_expire(const struct uint256 *txid)
{
    return wpb_expire(txid) == WPB_EXPIRY_RETURNED;
}

struct zcl_result wallet_private_broadcast_before_commit(
    const struct wallet_rpc_context *ctx, const struct uint256 *txid)
{
    struct wpr *relay = wpr_global();
    if (!ctx || !txid || ctx->mempool != wpr_pool(relay))
        return ZCL_OK;
    if (!wpr_prepare(relay, txid).ok)
        return ZCL_ERR(-1, "private send record could not be made durable; "
                           "send refused");
    return ZCL_OK;
}

struct zcl_result wallet_private_broadcast_unsupported(const char *what)
{
    if (wpr_get_mode(wpr_global()) != WPR_MODE_PRIVATE)
        return ZCL_OK;
    return ZCL_ERR(WALLET_PBCAST_UNSUPPORTED_CODE,
                   "PRIVATE_BROADCAST_UNSUPPORTED: %s would be announced to "
                   "every peer, which private wallet broadcast forbids. "
                   "Restart without -walletbroadcast=private to use it.",
                   what);
}

bool wallet_private_broadcast_refuse_json(const char *what,
                                          struct json_value *result)
{
    struct zcl_result r = wallet_private_broadcast_unsupported(what);
    if (r.ok)
        return false;
    json_set_str(result, r.message);
    LOG_WARN("wallet", "%s refused: private wallet broadcast is active", what);
    return true;
}

static void wallet_private_broadcast_warn_held(size_t held)
{
    static int64_t last_ns;
    int64_t now = clock_now_monotonic_ns();
    if (held == 0 || (last_ns && now - last_ns <
                      (int64_t)WALLET_PBCAST_HELD_WARN_S * 1000000000))
        return;
    last_ns = now;
    if (wpr_get_mode(wpr_global()) == WPR_MODE_PRIVATE)
        LOG_WARN("wallet", "%zu private send(s) not yet sent: no connected "
                 "onion peer. The coins stay reserved until the send is "
                 "delivered, confirmed or expires; nothing is sent over "
                 "clearnet.", held);
    else
        LOG_WARN("wallet", "%zu private send(s) held and not being sent: "
                 "wallet broadcast mode is public. Restart with "
                 "-walletbroadcast=private to send them; otherwise they "
                 "expire and the coins are released.", held);
}

void wallet_private_broadcast_tick_at(int wallet_height)
{
    struct wpr *relay = wpr_global();
    struct wpr_tick_result res;
    wpr_tick(relay, wallet_height, &res);
    size_t returned = 0, held = 0;
    for (size_t i = 0; i < res.num_expired; i++) {
        enum wpb_expiry e = wpb_expire(&res.expired[i]);
        returned += e == WPB_EXPIRY_RETURNED;
        held += e == WPB_EXPIRY_HELD;
    }
    if (held)
        LOG_WARN("wallet", "%zu private send(s) are past their expiry but "
                 "the chain may already hold them: an input is spent or "
                 "unknown to this node. They were not rolled back. Do not "
                 "send the payment again; rescan and check the wallet "
                 "history.", held);
    if (returned)
        LOG_WARN("wallet", "%zu private send(s) expired unconfirmed and were "
                 "returned to the wallet: the coins are available again. To "
                 "pay again, send it again with a new key.", returned);
    wallet_private_broadcast_warn_held(res.held);
}

void wallet_private_broadcast_tick(void)
{
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    wallet_private_broadcast_tick_at(
        base->wallet ? wallet_read_scanned_through_height(base->wallet) : -1);
}

static _Atomic bool g_ticker_stop;
static _Atomic bool g_ticker_running;

static void *wallet_private_broadcast_thread(void *arg)
{
    (void)arg;
    while (!thread_registry_shutdown_requested() && !atomic_load(&g_ticker_stop)) {
        wallet_private_broadcast_tick();
        platform_sleep_ms(WALLET_PBCAST_TICK_MS);
    }
    atomic_store(&g_ticker_running, false);
    return NULL;
}

void wallet_private_broadcast_stop(void)
{
    atomic_store(&g_ticker_stop, true);
    for (int i = 0; i < 200 && atomic_load(&g_ticker_running); i++)
        platform_sleep_ms(25);
}

void wallet_private_broadcast_reserve_spends(const struct transaction *tx)
{
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    if (!tx || tx->num_shielded_spend == 0)
        return;
    if (base->node_db && !node_db_sync_wallet_sapling_spends(base->node_db, tx))
        LOG_WARN("wallet_pbcast", "re-reserving the notes of a recorded "
                 "send failed");
    if (base->wallet)
        wallet_mark_sapling_nullifiers_spent(base->wallet, tx);
}

bool wallet_private_broadcast_start(enum wpr_mode mode,
                                    const struct wpr_env *env)
{
    struct wpr *relay = wpr_global();
    struct wpr_env armed;
    if (env) {
        armed = *env;
        if (!armed.reserve)
            armed.reserve = wallet_private_broadcast_reserve_spends;
        env = &armed;
    }
    wpr_configure(relay, mode, env);
    wallet_require_admission_pool(mode == WPR_MODE_PRIVATE ? wpr_pool(relay)
                                                           : NULL);
    /* Always resume and tick: a send held in private mode must still expire
     * and release its coins after a restart in public mode. Nothing is pushed
     * unless the mode is private. */
    struct zcl_result resumed = wpr_resume(relay);
    if (!resumed.ok)
        LOG_WARN("wallet", "private broadcast resume incomplete: %s",
                 resumed.message);
    /* A previous ticker must be gone before the next one starts. */
    wallet_private_broadcast_stop();
    atomic_store(&g_ticker_stop, false);
    atomic_store(&g_ticker_running, true);
    // thread-supervision-ok:one-second tick owned by the thread registry, stops on shutdown
    if (thread_registry_spawn("zcl_wallet_pbcast",
                              wallet_private_broadcast_thread, NULL,
                              NULL) != 0) {
        atomic_store(&g_ticker_running, false);
        LOG_FAIL("wallet", "private broadcast thread did not start");
    }
    return true;
}

bool wallet_private_broadcast_is_held(const struct uint256 *txid)
{
    enum wpr_state st;
    struct wpr *relay = wpr_global();
    return wpr_get_mode(relay) == WPR_MODE_PRIVATE &&
           wpr_entry_state(relay, txid, &st, NULL) &&
           (st == WPR_WAITING_FOR_ROUTE || st == WPR_PREPARED);
}

/* What the owner can safely do for a send in this state. No amounts or
 * addresses. */
static const char *wallet_private_broadcast_next_step(
    enum wpr_mode mode, const struct wpr_status_entry *e)
{
    if (e->held)
        return "Past its expiry, but the chain may already hold it: an input "
               "is spent or unknown to this node. It was not rolled back. Do "
               "not send the payment again; rescan and check the wallet "
               "history.";
    if (e->disk_retry)
        return "Expiry in progress: the wallet database could not be "
               "updated yet and it is retried. Do not send the payment "
               "again.";
    switch (e->state) {
    case WPR_PREPARED:
        return "Being created. No action needed.";
    case WPR_WAITING_FOR_ROUTE:
        if (e->handed)
            return "Handed to an onion peer earlier; waiting for a connected "
                   "onion peer to try again. It may already be on the "
                   "network. Do not send the payment again; the coins stay "
                   "reserved.";
        return mode == WPR_MODE_PRIVATE
            ? "Waiting for a connected onion peer. Nothing was sent. The "
              "coins stay reserved; it is safe to wait."
            : "Held because the wallet broadcast mode is public. Restart "
              "with -walletbroadcast=private to send it; otherwise it expires "
              "and the coins are released.";
    case WPR_SCHEDULED:
        return e->handed
            ? "Will be handed to an onion peer again shortly. It may "
              "already be on the network. Do not send the payment again."
            : "Will be handed to one onion peer shortly. No action needed.";
    case WPR_SENT:
        return "Handed to one onion peer (queued on the connection; "
               "delivery is not confirmed); waiting to see it on the "
               "network. Do not send the payment again.";
    case WPR_SEEN:
        return e->mined
            ? "Seen on the network and in a block. No action needed."
            : "Seen on the network but not in a block yet. No action "
              "needed; do not send the payment again.";
    case WPR_EXPIRED:
        return "Expired unconfirmed. The coins are available again. To pay "
               "again, send it again with a new key; the old key keeps "
               "answering that the earlier outcome is unknown.";
    }
    return "";
}

bool rpc_walletbroadcaststatus(const struct json_value *params, bool help,
                               struct json_value *result)
{
    (void)params;
    RPC_HELP(help, result,
        "walletbroadcaststatus\n"
        "Returns the wallet send broadcast mode, the number of pending "
        "private sends, connected eligible onion peers, and per pending "
        "transaction its state, attempts and seconds since the last "
        "attempt. No amounts or addresses.");

    struct wpr_status *st = zcl_calloc(1, sizeof(*st), "wpr_status");
    if (!st) {
        json_set_str(result, "out of memory");
        LOG_FAIL("wallet", "walletbroadcaststatus: allocation failed");
    }
    wpr_status_snapshot(wpr_global(), st);

    json_set_object(result);
    json_push_kv_str(result, "schema", "zcl.wallet_broadcast_status.v1");
    json_push_kv_str(result, "mode", wpr_mode_name(st->mode));
    json_push_kv_int(result, "pending", (int64_t)st->pending);
    json_push_kv_int(result, "expired", (int64_t)st->expired);
    json_push_kv_int(result, "eligible_onion_peers",
                     (int64_t)st->eligible_peers);
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < st->num_entries; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        char hex[65];
        uint256_get_hex(&st->entries[i].txid, hex);
        json_push_kv_str(&item, "txid", hex);
        json_push_kv_str(&item, "state", wpr_state_name(st->entries[i].state));
        json_push_kv_str(&item, "next_step",
                         wallet_private_broadcast_next_step(
                             st->mode, &st->entries[i]));
        json_push_kv_int(&item, "attempts", st->entries[i].attempts);
        json_push_kv_int(&item, "seconds_since_last_attempt",
                         st->entries[i].seconds_since_attempt);
        json_push_back(&list, &item);
        json_free(&item);
    }
    json_push_kv(result, "transactions", &list);
    json_free(&list);
    free(st);
    return true;
}

void register_wallet_private_broadcast_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmd = { "wallet", "walletbroadcaststatus",
                               rpc_walletbroadcaststatus, false };
    rpc_table_must_append(t, &cmd);
}
