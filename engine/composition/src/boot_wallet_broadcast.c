/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Boot selection of the wallet send broadcast mode. Public relay is the
 * default; -walletbroadcast=private opts in and needs onion-only
 * networking. */

#include "config/boot_internal.h"
#include "controllers/wallet_private_broadcast.h"
#include "services/wallet_private_relay.h"

#include "util/util.h"

#include <stdio.h>

/* Private broadcast hides the sending IP only if no peer can reach this node
 * or learn its address except over Tor. Clearnet dials would let a clearnet
 * peer see the transaction a malicious onion peer echoes back, and
 * -externalip puts the node's address in the version message of the same
 * connection that carries the transaction. */
static bool boot_private_broadcast_allowed(const struct app_context *ctx)
{
    if (!ctx->onlynet_onion) {
        fprintf(stderr, "-walletbroadcast=private requires -onlynet=onion: "
                        "clearnet connections would let a peer see this "
                        "node announce the transaction. Add -onlynet=onion "
                        "or use -walletbroadcast=public.\n");
        return false;
    }
    if (ctx->external_ip || GetArg("-externalip", NULL)) {
        fprintf(stderr, "-walletbroadcast=private refuses -externalip: the "
                        "address is sent to every peer in the version "
                        "message, including the onion peer that receives the "
                        "transaction. Remove -externalip.\n");
        return false;
    }
    return true;
}

bool boot_start_wallet_broadcast(struct boot_svc_ctx *svc,
    const struct app_context *ctx, const struct chain_params *params)
{
    enum wpr_mode mode = ctx->wallet_broadcast == 1 ? WPR_MODE_PRIVATE
                                                    : WPR_MODE_PUBLIC;
    if (mode == WPR_MODE_PRIVATE && !boot_private_broadcast_allowed(ctx))
        return false;
    struct wpr_env env = {
        .wallet = svc->wallet, .connman = svc->connman,
        .coins_tip = svc->coins_tip, .main_state = svc->state,
        .params = params, .datadir = ctx->datadir,
        .min_relay_fee = svc->mempool ? svc->mempool->min_relay_fee : 0,
    };
    if (!wallet_private_broadcast_start(mode, &env))
        fprintf(stderr, "[boot] wallet private broadcast did not start\n");
    printf("Wallet broadcast mode: %s\n", wpr_mode_name(mode));
    return true;
}
