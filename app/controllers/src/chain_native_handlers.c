/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native argument parsing and RPC composition for chain read commands. See
 * controllers/native_handler_body.h for the failure contract. */

#include "controllers/chain_native_handlers.h"

#include "base/hex.h"
#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void native_body_set_rpc_error(struct zcl_native_body_err *err,
                                      const char *method, const char *context)
{
    int written = snprintf(err->message, sizeof(err->message),
                           "RPC %s failed: ", method);
    if (written < 0 || (size_t)written >= sizeof(err->message))
        return;

    size_t available = sizeof(err->message) - (size_t)written;
    snprintf(err->message + written, available, "%.*s",
             (int)available - 1, context);
}

/* Keep the transaction identity and lifecycle state ahead of potentially
 * large vin/vout/hex fields.  The native bridge deliberately pages bounded
 * objects in source order, so forwarding the legacy RPC order verbatim could
 * make a confirmed transaction look state-less whenever an earlier script or
 * shielded payload filled the first page. */
static char *rawtx_state_first(char *rpc_json,
                               struct zcl_native_body_err *err)
{
    static const char *const prefix[] = {
        "txid", "confirmations", "blockhash", "version", "locktime",
    };
    struct json_value source;
    json_init(&source);
    if (!rpc_json || !json_read(&source, rpc_json, strlen(rpc_json)) ||
        source.type != JSON_OBJ ||
        !json_get_str(json_get(&source, "txid"))) {
        json_free(&source);
        return rpc_json;
    }

    struct json_value ordered;
    json_init(&ordered);
    json_set_object(&ordered);
    bool ok = true;
    for (size_t p = 0; ok && p < sizeof(prefix) / sizeof(prefix[0]); p++) {
        const struct json_value *value = json_get(&source, prefix[p]);
        if (value)
            ok = json_push_kv(&ordered, prefix[p], value);
    }
    for (size_t i = 0; ok && i < source.num_children; i++) {
        bool already_added = false;
        for (size_t p = 0; p < sizeof(prefix) / sizeof(prefix[0]); p++) {
            if (strcmp(source.keys[i], prefix[p]) == 0) {
                already_added = true;
                break;
            }
        }
        if (!already_added)
            ok = json_push_kv(&ordered, source.keys[i], &source.children[i]);
    }

    size_t need = ok ? json_write(&ordered, NULL, 0) : 0;
    char *stable = need > 0
        ? zcl_malloc(need + 1, "native raw transaction state-first body")
        : NULL;
    if (stable && json_write(&ordered, stable, need + 1) == 0) {
        free(stable);
        stable = NULL;
    }
    json_free(&ordered);
    json_free(&source);
    if (!stable) {
        free(rpc_json);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "could not serialize transaction lifecycle state");
        LOG_NULL("native.chain",
                 "raw transaction state-first serialization failed");
        return NULL;
    }
    free(rpc_json);
    return stable;
}

char *zcl_native_getrawtransaction_body(const struct json_value *args,
                                         struct zcl_native_body_err *err)
{
    const char *txid = json_get_str(json_get(args, "txid"));
    const struct json_value *verbose_arg = json_get(args, "verbose");
    int verbosity = verbose_arg && verbose_arg->type == JSON_BOOL
        ? (json_get_bool(verbose_arg) ? 1 : 0)
        : 1;
    int64_t raw_offset = json_get_int_or(args, "raw_offset", 0);
    int64_t raw_bytes = json_get_int_or(args, "raw_bytes", 1024);
    if (verbosity == 0 &&
        (raw_offset < 0 || raw_bytes < 1 || raw_bytes > 1024)) {
        err->status = ZCL_NATIVE_BODY_INVALID;
        snprintf(err->message, sizeof(err->message),
                 "raw_offset must be nonnegative and raw_bytes must be 1..1024");
        LOG_NULL("native.chain",
                 "invalid raw transaction page offset=%lld bytes=%lld",
                 (long long)raw_offset, (long long)raw_bytes);
    }
    if (err->status != ZCL_NATIVE_BODY_OK)
        return NULL;
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, txid);
    rpc_arg_builder_push_int(&p, verbosity);
    char *params = rpc_arg_builder_to_json(&p);
    char *out = params ? node_rpc_call("getrawtransaction", params) : NULL;
    free(params);
    if (!out) {
        char ctx[192];
        snprintf(ctx, sizeof(ctx), "txid=%s", txid ? txid : "(null)");
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        native_body_set_rpc_error(err, "getrawtransaction", ctx);
        LOG_NULL("native.chain", "%s failed: %s", "getrawtransaction", ctx);
        return NULL;
    }

    /* getrawtransaction(..., 0) legitimately returns a bare JSON string.
     * Native handler bodies must be objects, so preserve the full raw bytes
     * in an explicit typed shape instead of letting the bridge mistake the
     * string for a legacy RPC error (and truncate it into an error message). */
    if (verbosity == 0) {
        struct json_value raw;
        json_init(&raw);
        if (json_read(&raw, out, strlen(out)) && raw.type == JSON_STR) {
            const char *full_hex = json_get_str(&raw);
            size_t hex_len = full_hex ? strlen(full_hex) : 0;
            bool is_hex = full_hex && hex_len > 0 && (hex_len & 1u) == 0;
            for (size_t i = 0; is_hex && i < hex_len; i++)
                is_hex = zcl_hex_nibble(full_hex[i], true) >= 0;
            if (!is_hex) {
                /* Preserve the native bridge's legacy RPC-error handling.
                 * A bare non-hex string is an error message, never raw bytes. */
                json_free(&raw);
                return out;
            }
            size_t total_bytes = hex_len / 2;
            size_t offset = (size_t)raw_offset;
            if (offset > total_bytes) {
                json_free(&raw);
                free(out);
                err->status = ZCL_NATIVE_BODY_INVALID;
                snprintf(err->message, sizeof(err->message),
                         "raw transaction page is outside the %zu-byte transaction",
                         total_bytes);
                LOG_NULL("native.chain",
                         "raw transaction page invalid offset=%zu total=%zu",
                         offset, total_bytes);
                return NULL;
            }
            size_t chunk_bytes = (size_t)raw_bytes;
            if (chunk_bytes > total_bytes - offset)
                chunk_bytes = total_bytes - offset;
            size_t chunk_hex_len = chunk_bytes * 2;
            char chunk_hex[2049];
            memcpy(chunk_hex, full_hex + offset * 2, chunk_hex_len);
            chunk_hex[chunk_hex_len] = '\0';
            struct json_value wrapped;
            json_init(&wrapped);
            json_set_object(&wrapped);
            (void)json_push_kv_str(&wrapped, "schema",
                                   "zcl.raw_transaction.v1");
            (void)json_push_kv_str(&wrapped, "txid", txid ? txid : "");
            (void)json_push_kv_str(&wrapped, "encoding", "hex");
            (void)json_push_kv_int(&wrapped, "offset_bytes", (int64_t)offset);
            (void)json_push_kv_int(&wrapped, "chunk_bytes",
                                   (int64_t)chunk_bytes);
            (void)json_push_kv_int(&wrapped, "total_bytes",
                                   (int64_t)total_bytes);
            bool complete = offset + chunk_bytes == total_bytes;
            (void)json_push_kv_bool(&wrapped, "complete", complete);
            if (!complete)
                (void)json_push_kv_int(&wrapped, "next_offset",
                                       (int64_t)(offset + chunk_bytes));
            (void)json_push_kv_str(&wrapped, "raw_hex", chunk_hex);
            size_t need = json_write(&wrapped, NULL, 0);
            char *typed = zcl_malloc(need + 1, "native raw transaction");
            if (typed)
                (void)json_write(&wrapped, typed, need + 1);
            json_free(&wrapped);
            json_free(&raw);
            free(out);
            if (!typed) {
                err->status = ZCL_NATIVE_BODY_INTERNAL;
                snprintf(err->message, sizeof(err->message),
                         "could not serialize raw transaction result");
                LOG_NULL("native.chain",
                         "raw transaction wrap alloc failed (%zu bytes)",
                         need + 1);
            }
            return typed;
        }
        json_free(&raw);
    }
    return verbosity == 0 ? out : rawtx_state_first(out, err);
}

char *zcl_native_getblock_body(const struct json_value *args,
                                struct zcl_native_body_err *err)
{
    const char *id_str = json_get_str(json_get(args, "block_id"));
    int verbosity = (int)json_get_int_or(args, "verbosity", 1);

    bool is_num = id_str && id_str[0];
    for (const char *c = id_str; is_num && *c; c++)
        if (*c < '0' || *c > '9') is_num = false;

    char clean[128] = {0};
    const char *hash_str = id_str;
    if (is_num) {
        struct rpc_arg_builder ph;
        rpc_arg_builder_init(&ph);
        rpc_arg_builder_push_int(&ph, id_str ? atoll(id_str) : 0);
        char *php = rpc_arg_builder_to_json(&ph);
        char *hash = php ? node_rpc_call("getblockhash", php) : NULL;
        free(php);
        if (!hash) {
            char ctx[192];
            snprintf(ctx, sizeof(ctx), "height=%s", id_str ? id_str : "(null)");
            err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
            native_body_set_rpc_error(err, "getblockhash", ctx);
            LOG_NULL("native.chain", "%s failed: %s", "getblockhash", ctx);
        }
        size_t ci = 0;
        for (size_t i = 0; hash[i] && ci < 127; i++)
            if (hash[i] != '"' && hash[i] != '\n') clean[ci++] = hash[i];
        clean[ci] = 0;
        free(hash);
        hash_str = clean;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, hash_str);
    rpc_arg_builder_push_int(&p, verbosity);
    char *params = rpc_arg_builder_to_json(&p);
    char *out = params ? node_rpc_call("getblock", params) : NULL;
    free(params);
    if (!out) {
        char ctx[192];
        snprintf(ctx, sizeof(ctx), "id=%s", id_str ? id_str : "(null)");
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        native_body_set_rpc_error(err, "getblock", ctx);
        LOG_NULL("native.chain", "%s failed: %s", "getblock", ctx);
    }
    return out;
}

char *zcl_native_utxo_audit_body(const struct json_value *args,
                                  struct zcl_native_body_err *err)
{
    const char *remote = json_get_str_or(args, "remote_sha3", NULL);
    const char *source = json_get_str_or(args, "source",      NULL);

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    if (remote && remote[0]) {
        rpc_arg_builder_push_str(&p, remote);
        rpc_arg_builder_push_int(&p, json_get_int_or(args, "remote_height", 0));
        rpc_arg_builder_push_str(&p, source && source[0] ? source : "trusted-peer");
    }
    char *params = rpc_arg_builder_to_json(&p);
    char *out = node_rpc_call("getutxoaudit", params);
    free(params);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "getutxoaudit");
        LOG_NULL("native.chain", "RPC %s returned null", "getutxoaudit");
    }
    return out;
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in lib/hotswap/include/hotswap/hotswap.h). Stages every native command
 * leaf this controller owns; the resident bridge re-points them at THIS
 * TU's freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * core.consensus.utxo.audit: rpc_getutxoaudit (blockchain_controller_chain.c)
 * accepts 0..3 params (rpc_params_expect(&p, 0, 3)) and, with remote_sha3
 * absent, falls back to utxo_audit_local() — a genuine local-only audit, not
 * an error — so the empty-args self-test dispatch succeeds.
 * See config/hotswap_eligible.def.
 *
 * THE TABLE BELOW HOLDS ONE LEAF, AND THAT IS THE WHOLE RULE.
 * core.chain.block.get and core.chain.transaction.get are NEVER hot-swappable
 * — an owner decision recorded, with its reason, in
 * config/hotswap_denied_leaves.def and enforced by
 * check-hotswap-denied-leaves. They RENDER BLOCK AND TRANSACTION BYTES: a
 * swapped renderer misreports chain data to every RPC reader without touching
 * one line of validation, so "READY + read-only" (which both leaves are) is
 * not the right test on that path.
 *
 * They used to be staged here, and that was not a theoretical hole:
 * hotswap_leaf_stage_thunk() in lib/hotswap/src/hotswap_loader.c applies NO
 * per-leaf allowlist to a Tier-1 generation — it accepts every row this table
 * exports — so a recompiled generation of this TU re-pointed both of them
 * even though neither leaf is named in any config/ manifest. The Tier-2
 * module path was never exposed: hotswap_module_admit() checks each leaf
 * against config/hotswap_swappable.def, which lists only the audit leaf.
 * Do not add a trampoline back without the owner reversing the decision. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "core.consensus.utxo.audit"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_utxo_audit, zcl_native_utxo_audit_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "core.consensus.utxo.audit",  tramp_utxo_audit },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=core.consensus.utxo.audit` build
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node/release TU. The
 * module re-points ONLY the `core.consensus.utxo.audit` leaf to this TU's
 * freshly-compiled body via the same zcl_native_bridge_run() seam the leaf
 * provider uses. See hotswap_module.h and hotswap_activate() (lib/hotswap).
 * NOTE: this leaf is a READ-ONLY audit projection — it is not consensus
 * validation; consensus/state roots remain unswappable (the allowlist +
 * check-hotswap-swappable-shape hard line). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_utxo_audit, zcl_native_utxo_audit_body)

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_utxo_audit(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

ZCL_HOTSWAP_MODULE("core.consensus.utxo.audit",
                   module_tramp_utxo_audit,
                   module_selftest_utxo_audit)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
