/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet send glue for the private relay and its status read. */

// supervisor-ok:bounded-tick-thread-stopped-by-registry-shutdown
#include "controllers/wallet_private_broadcast.h"

#include "controllers/strong_params.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "net/connman.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"

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

static void wallet_private_broadcast_expire(const struct uint256 *txid)
{
    struct wpr *relay = wpr_global();
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    struct wallet_rpc_context view = *base;
    view.mempool = wpr_pool(relay);
    view.connman = NULL;

    struct wallet_tx wtx;
    memset(&wtx, 0, sizeof(wtx));
    if (base->wallet && wallet_get_tx_copy(base->wallet, txid, &wtx)) {
        struct zcl_result rolled = wallet_rollback_persisted_commit(&view, &wtx);
        transaction_free(&wtx.tx);
        if (!rolled.ok) {
            LOG_WARN("wallet", "expired private send rollback failed "
                     "(code=%d): %s", rolled.code, rolled.message);
            return;
        }
    }
    wpr_forget(relay, txid);
}

void wallet_private_broadcast_tick_at(int tip_height)
{
    struct wpr *relay = wpr_global();
    struct wpr_tick_result res;
    wpr_tick(relay, tip_height, &res);
    for (size_t i = 0; i < res.num_expired; i++)
        wallet_private_broadcast_expire(&res.expired[i]);
}

void wallet_private_broadcast_tick(void)
{
    struct wallet_rpc_context *base = wallet_rpc_context_current();
    if (base->main_state)
        wallet_private_broadcast_tick_at(
            active_chain_height(&base->main_state->chain_active));
}

static void *wallet_private_broadcast_thread(void *arg)
{
    (void)arg;
    while (!thread_registry_shutdown_requested()) {
        wallet_private_broadcast_tick();
        platform_sleep_ms(1000);
    }
    return NULL;
}

bool wallet_private_broadcast_start(enum wpr_mode mode,
                                    const struct wpr_env *env)
{
    struct wpr *relay = wpr_global();
    wpr_configure(relay, mode, env);
    if (mode != WPR_MODE_PRIVATE)
        return true;
    struct zcl_result resumed = wpr_resume(relay);
    if (!resumed.ok)
        LOG_WARN("wallet", "private broadcast resume incomplete: %s",
                 resumed.message);
    // thread-supervision-ok:one-second tick owned by the thread registry, stops on shutdown
    if (thread_registry_spawn("zcl_wallet_pbcast",
                              wallet_private_broadcast_thread, NULL,
                              NULL) != 0) {
        LOG_FAIL("wallet", "private broadcast thread did not start");
        return false;
    }
    return true;
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
