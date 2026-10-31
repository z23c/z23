/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Boot selection of the wallet send broadcast mode: private broadcast by
 * default when Tor runs, public otherwise, overridable with
 * -walletbroadcast. */

#include "config/boot_internal.h"
#include "controllers/wallet_private_broadcast.h"
#include "services/wallet_private_relay.h"

#include <stdio.h>

void boot_start_wallet_broadcast(struct boot_svc_ctx *svc,
    const struct app_context *ctx, const struct chain_params *params)
{
    bool tor = app_tor_should_start(app_tor_real_build_linked(), ctx->no_tor);
    enum wpr_mode mode = ctx->wallet_broadcast == 1 ? WPR_MODE_PRIVATE
        : ctx->wallet_broadcast == 2 ? WPR_MODE_PUBLIC
        : tor ? WPR_MODE_PRIVATE : WPR_MODE_PUBLIC;
    struct wpr_env env = {
        .wallet = svc->wallet, .connman = svc->connman,
        .coins_tip = svc->coins_tip, .main_state = svc->state,
        .params = params, .datadir = ctx->datadir,
        .min_relay_fee = svc->mempool ? svc->mempool->min_relay_fee : 0,
    };
    if (!wallet_private_broadcast_start(mode, &env))
        fprintf(stderr, "[boot] wallet private broadcast did not start\n");
    printf("Wallet broadcast mode: %s\n", wpr_mode_name(mode));
}
