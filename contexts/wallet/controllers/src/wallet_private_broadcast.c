/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet send glue for the private relay and its status read. */

// supervisor-ok:bounded-tick-thread-stopped-by-registry-shutdown
#include "controllers/wallet_private_broadcast.h"

#include "controllers/strong_params.h"
#include "controllers/wallet_helpers.h"
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

bool wallet_send_relay(struct wallet_rpc_context *ctx, struct wallet_tx *wtx)
{
    struct wpr *relay = wpr_global();
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
    if (!rolled.ok)
        LOG_FAIL("wallet", "private broadcast rollback failed (code=%d): %s",
                rolled.code, rolled.message);
    return false;
}

/* The wallet has read blocks through a height past the send's expiry and
 * margin and no block holds it: return its coins, and keep a terminal record
 * for the status. A send the wallet now shows confirmed is not rolled back. */
bool wallet_private_broadcast_expire(const struct uint256 *txid)
{
    struct wpr *relay = wpr_global();
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    struct wallet_rpc_context view = *base;
    view.mempool = wpr_pool(relay);
    view.connman = NULL;

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (base->wallet && wallet_get_tx_copy(base->wallet, txid, &wtx)) {
        if (wtx.confirms > 0) {
            transaction_free(&wtx.tx);
            wpr_note_seen(relay, txid);
            return false;
        }
        struct zcl_result rolled = wallet_rollback_persisted_commit(&view, &wtx);
        transaction_free(&wtx.tx);
        if (!rolled.ok) {
            LOG_WARN("wallet", "expired private send rollback failed "
                     "(code=%d): %s", rolled.code, rolled.message);
            return false;
        }
    }
    wpr_mark_expired(relay, txid);
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
    size_t returned = 0;
    for (size_t i = 0; i < res.num_expired; i++)
        if (wallet_private_broadcast_expire(&res.expired[i]))
            returned++;
    if (returned)
        LOG_WARN("wallet", "%zu private send(s) expired unconfirmed and were "
                 "returned to the wallet: the coins are available again and "
                 "the payment may be sent again.", returned);
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

bool wallet_private_broadcast_start(enum wpr_mode mode,
                                    const struct wpr_env *env)
{
    struct wpr *relay = wpr_global();
    wpr_configure(relay, mode, env);
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

/* What the owner can safely do for a send in this state. No amounts or
 * addresses. */
static const char *wallet_private_broadcast_next_step(enum wpr_mode mode,
                                                      enum wpr_state state)
{
    switch (state) {
    case WPR_WAITING_FOR_ROUTE:
        return mode == WPR_MODE_PRIVATE
            ? "Waiting for a connected onion peer. Nothing was sent. The "
              "coins stay reserved; it is safe to wait."
            : "Held because the wallet broadcast mode is public. Restart "
              "with -walletbroadcast=private to send it; otherwise it expires "
              "and the coins are released.";
    case WPR_SCHEDULED:
        return "Will be sent to one onion peer shortly. No action needed.";
    case WPR_SENT:
        return "Sent to one onion peer; waiting to see it on the network. "
               "No action needed.";
    case WPR_SEEN:
        return "Seen on the network or confirmed. No action needed.";
    case WPR_EXPIRED:
        return "Expired unconfirmed. The coins are available again and the "
               "payment may be sent again.";
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
                             st->mode, st->entries[i].state));
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
