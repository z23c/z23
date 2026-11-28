/* purpose: Load an explicitly pinned test-network ballot catalog at boot. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "config/boot_ballot_catalog.h"
#include "config/boot.h"
#include "base/hex.h"
#include "chain/chainparams.h"
#include "consensus/params.h"
#include "services/research_rules.h"
#include "util/util.h"
#include <stdio.h>

/* This is a chain parameter of the private research history: every peer build
 * and the release manifest must agree on it. Only the selected runtime copy
 * is changed, after the verified catalog is bound and before consumers run. */
static void boot_research_shielded(void)
{
    struct chain_params *params = (struct chain_params *)chain_params_get();
    params->consensus.vUpgrades[UPGRADE_OVERWINTER].nActivationHeight =
        NETWORK_UPGRADE_ALWAYS_ACTIVE;
    params->consensus.vUpgrades[UPGRADE_SAPLING].nActivationHeight =
        NETWORK_UPGRADE_ALWAYS_ACTIVE;
    printf("research: Overwinter+Sapling active from genesis\n");
}

static bool boot_ballot_network_allowed(const struct app_context *ctx, bool research)
{
    return !((!research && ctx->testnet == ctx->regtest) ||
             (research && (ctx->testnet || ctx->regtest)) ||
             (GetBoolArg("-testnet", false) && GetBoolArg("-regtest", false)));
}

const char boot_ballot_catalog_consent_refusal[] =
    "FATAL: the research profile requires an explicitly pinned catalog "
    "(-testballotcatalog <digest>)";

bool boot_ballot_catalog_consent_present(void)
{
    return GetArg("-testballotcatalog", NULL) != NULL;
}

bool boot_ballot_catalog_consent(const struct app_context *ctx)
{
    if (!ctx) {
        fprintf(stderr, "FATAL: cannot configure ballot catalog without boot context\n");
        return false;
    }
    if (ctx->testnet_profile && !boot_ballot_catalog_consent_present()) {
        fprintf(stderr, "%s\n", boot_ballot_catalog_consent_refusal);
        return false;
    }
    return true;
}

/* GetArg uses argv-over-config precedence and distinguishes absent from empty. */
bool boot_ballot_catalog_load(struct app_context *ctx)
{
    if (!ctx) {
        fprintf(stderr, "FATAL: cannot configure ballot catalog without boot context\n");
        return false;
    }
    const char *digest = GetArg("-testballotcatalog", NULL);
    bool research = chain_research_profile_current() != NULL;
    ctx->ballot_catalog_pin_present = false;
    if (!digest) {
        if (!research) return true;
        fprintf(stderr, "%s\n", boot_ballot_catalog_consent_refusal);
        return false;
    }
    if (!boot_ballot_network_allowed(ctx, research)) {
        if (research)
            fprintf(stderr, "FATAL: research profile cannot be combined with testnet or regtest\n");
        else
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
    if (research && !research_rules_install(cp, &ctx->ballot_catalog_pin)) {
        fprintf(stderr, "FATAL: cannot bind research rules: wrong chain or catalog genesis, "
                        "or rules already bound\n");
        return false;
    }
    ctx->ballot_catalog_pin_present = true;
    if (research) boot_research_shielded();
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
