/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "params.h"
#include "json/json.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

/* Pinned in docs/node/GETTING_STARTED.md and in params.sha256 beside this file. */
const struct zapp_param_file zapp_param_files[ZAPP_PARAMS_COUNT] = {
    {"sapling-spend.params", 47958396, "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"},
    {"sapling-output.params", 3592860, "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"},
};

bool zapp_params_path(const char *files, char *out, size_t cap)
{
    int n = files && *files ? snprintf(out, cap, "%s/" ZAPP_PARAMS_DIR, files) : -1;
    return n > 0 && (size_t)n < cap;
}

bool zapp_params_present_set(const struct zapp_param_file *set, size_t count, const char *files)
{
    char dir[1100];
    if (!zapp_params_path(files, dir, sizeof(dir))) return false;
    for (size_t i = 0; i < count; i++) {
        char file[1400];
        struct stat st;
        int n = snprintf(file, sizeof(file), "%s/%s", dir, set[i].name);
        if (n <= 0 || (size_t)n >= sizeof(file) || lstat(file, &st) != 0 || !S_ISREG(st.st_mode) ||
            (uint64_t)st.st_size != set[i].size)
            return false;
    }
    return true;
}

bool zapp_params_present(const char *files)
{
    return zapp_params_present_set(zapp_param_files, ZAPP_PARAMS_COUNT, files);
}

bool zapp_params_arg(const char *files, char *out, size_t cap)
{
    char dir[1100];
    if (!zapp_params_path(files, dir, sizeof(dir))) return false;
    int n = snprintf(out, cap, "-paramsdir=%s", dir);
    return n > 0 && (size_t)n < cap;
}

enum zapp_proving zapp_proving_from_reply(const char *reply)
{
    struct json_value v = {0};
    enum zapp_proving out = ZAPP_PROVING_UNKNOWN;
    if (!reply || !json_read(&v, reply, strlen(reply))) return out;
    const struct json_value *error = json_get(&v, "error");
    const char *word = error && !json_is_null(error) ? ""
                       : json_get_str(json_get(json_get(json_get(&v, "result"), "sapling"), "proving_status"));
    if (!strcmp(word, "none")) out = ZAPP_PROVING_UNAVAILABLE;
    else if (!strcmp(word, "pair_present") || !strcmp(word, "pair_armed") || !strcmp(word, "full_set")) out = ZAPP_PROVING_ARMED;
    json_free(&v);
    return out;
}

enum zapp_proving zapp_proving_over_rpc(void *ctx)
{
    const struct zapp_rpc_probe *probe = ctx;
    char reply[8192], why[160];
    if (!probe || !probe->datadir || !probe->call) return ZAPP_PROVING_UNKNOWN;
    reply[0] = 0;
    return probe->call(probe->datadir, "getwalletinfo", "[]", 5000, reply, sizeof(reply), why, sizeof(why)) == ZAPP_RPC_OK
               ? zapp_proving_from_reply(reply) : ZAPP_PROVING_UNKNOWN;
}

bool zapp_prover_allowed(int thermal_status, bool params_verified, const struct zapp_proving_probe *node,
                         char *why, size_t cap)
{
    enum zapp_proving proving = params_verified && node && node->status ? node->status(node->ctx) : ZAPP_PROVING_UNKNOWN;
    const char *reason = !params_verified ? "The proving parameters are not ready yet."
                         : proving == ZAPP_PROVING_UNAVAILABLE ? "The node cannot prove a payment yet."
                         : proving != ZAPP_PROVING_ARMED ? "The node has not confirmed that it can prove a payment."
                         : thermal_status >= ZAPP_THERMAL_SEVERE
                             ? "The phone is too hot to prove a payment. Let it cool and try again."
                             : NULL;
    if (reason && why && cap) snprintf(why, cap, "%s", reason);
    return !reason;
}
