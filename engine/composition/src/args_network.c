/* purpose: Resolve node network selectors against the shared argument table. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "args_network_internal.h"
#include "config/args.h"
#include "config/boot.h"
#include "util/parse_num.h"
#include "util/util.h"
#include <stdio.h>
#include <string.h>

static bool network_bool(const char *text, bool *out)
{
    if (!text || !*text) { *out = true; return true; }
    /* The shared argument table truncates at MAX_ARG_LEN - 1. */
    if (strlen(text) >= MAX_ARG_LEN - 1) return false;
    int64_t n;
    if (!zcl_parse_i64(text, &n)) return false;
    *out = n != 0;
    return true;
}

/* ParseParameters normalizes negated argv keys before config is read. A
 * config-only negated key has no positive entry for downstream GetBoolArg. */
static bool network_config_one(const char *key, const char *negative, bool *out)
{
    const char *positive = GetArg(key, NULL), *negated = GetArg(negative, NULL);
    bool neg = false;
    if (negated && !network_bool(negated, &neg)) return false;
    if (positive) return network_bool(positive, out);
    return negated == NULL;
}

int args_network_begin(struct app_context *ctx)
{
    /* At capacity later argv or config keys may have been silently omitted. */
    if (g_nargs >= MAX_ARGS) {
        fprintf(stderr, "Argument table is full; network identity is ambiguous\n");
        return 1;
    }
    if (!network_config_one("-testnet", "-notestnet", &ctx->testnet) ||
        !network_config_one("-regtest", "-noregtest", &ctx->regtest)) {
        fprintf(stderr, "Invalid testnet or regtest selector in configuration\n");
        return 1;
    }
    return 0;
}

int args_network_arg(const char *arg, struct app_context *ctx, bool positional)
{
    const char *a = arg[0] == '-' && arg[1] == '-' ? arg + 1 : arg;
    const char *names[] = { "-testnet", "-regtest", "-notestnet", "-noregtest" };
    for (size_t i = 0; i < 4; i++) {
        size_t n = strlen(names[i]);
        if (strncmp(a, names[i], n) || (a[n] != '\0' && a[n] != '=')) continue;
        if (positional) {
            fprintf(stderr, "Network selector after a positional argument is not supported\n");
            return 1;
        }
        bool value;
        if (!network_bool(a[n] == '=' ? a + n + 1 : NULL, &value)) {
            fprintf(stderr, "Invalid network selector: %s\n", arg);
            return 1;
        }
        bool *target = i % 2 ? &ctx->regtest : &ctx->testnet;
        if (i < 2) *target = value;
        else if (!GetArg(names[i - 2], NULL)) *target = !value;
        return -1;
    }
    return -2;
}

int args_network_finish(const struct app_context *ctx)
{
    if (ctx->testnet && ctx->regtest) {
        fprintf(stderr, "Conflicting network selectors: testnet and regtest cannot both be enabled\n");
        return 1;
    }
    return 0;
}

/* Preserve the existing unknown-option warning wording and suggestions. */
void args_warn_unrecognized(const char *arg)
{
    char suggest[24] = {0};
    if (cli_flag_classify(arg, suggest, sizeof(suggest)) != CLI_FLAG_OK) {
        fprintf(stderr,
                "Warning: unrecognized flag '%s' (ignored) — "
                "z23 flags use a single dash with '=' "
                "joining the value; did you mean %s?\n", arg, suggest);
    } else {
        fprintf(stderr,
                "Warning: unrecognized flag '%s' (ignored) — check "
                "spelling or docs/RUNBOOK.md; this is not a supported "
                "z23 flag.\n", arg);
    }
}
