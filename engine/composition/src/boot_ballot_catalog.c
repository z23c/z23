/* purpose: Load an explicitly pinned test-network ballot catalog at boot. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "config/boot_ballot_catalog.h"
#include "config/boot.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "util/util.h"
#include <stdio.h>

/* GetArg uses argv-over-config precedence and distinguishes absent from empty. */
bool boot_ballot_catalog_load(struct app_context *ctx)
{
    if (!ctx) {
        fprintf(stderr, "FATAL: cannot configure ballot catalog without boot context\n");
        return false;
    }
    const char *digest = GetArg("-testballotcatalog", NULL);
    ctx->ballot_catalog_pin_present = false;
    if (!digest) return true;
    if (ctx->testnet == ctx->regtest ||
        (GetBoolArg("-testnet", false) && GetBoolArg("-regtest", false))) {
        fprintf(stderr, "FATAL: -testballotcatalog requires one unambiguous testnet or regtest\n");
        return false;
    }
    uint8_t parsed[32];
    if (!zcl_hex_decode_lower(digest, parsed, sizeof(parsed))) {
        fprintf(stderr, "FATAL: -testballotcatalog must be exactly 64 lowercase hexadecimal characters\n");
        return false;
    }
    const struct chain_params *cp = chain_params_get();
    if (!cp) {
        fprintf(stderr, "FATAL: cannot bind ballot catalog without selected network parameters\n");
        return false;
    }
    /* Use the selected datadir root, not the network-specific block folder. */
    struct zcl_result result = miner_signal_catalog_pin_load(
        ctx->datadir, digest, cp->consensus.hashGenesisBlock.data, &ctx->ballot_catalog_pin);
    if (!result.ok) {
        fprintf(stderr, "FATAL: -testballotcatalog: %s\n", result.message);
        return false;
    }
    ctx->ballot_catalog_pin_present = true;
    return true;
}

/* The one boot-time selection of a research profile. Windows supports none:
 * main.c refuses the selector there and this refuses it again at the boot
 * entry, so no Windows link owes the selector a definition. */
bool boot_research_profile_select(const struct app_context *ctx)
{
#if defined(_WIN32)
    (void)ctx;
    fprintf(stderr, "FATAL: the research profile is not supported on Windows\n");
    return false;
#else
    return chain_research_profile_select(ctx->testnet_profile->id);
#endif
}
