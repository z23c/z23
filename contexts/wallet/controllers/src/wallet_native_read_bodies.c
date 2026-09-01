/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native read bodies for the core.wallet.* query leaves: argument parsing and
 * RPC composition for listunspent, listtransactions, gettransaction,
 * listaddresses, and the two shielded reads.
 *
 * Split from wallet_native_handlers.c, which now holds only the mutating
 * registry handlers. The file had grown past the size ceiling carrying both
 * halves of a division its own header already described — reads that compose
 * an RPC call and return a body, and plan/commit leaves that create keys,
 * reveal keys, or move funds. Those are different risk classes and they now
 * live apart.
 *
 * See controllers/native_handler_body.h for the read-body failure contract. */

#include "controllers/wallet_native_handlers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Serialize one composed JSON document into a fresh heap buffer, or report a
 * body failure. Defined with the shielded read bodies below; the transparent
 * listunspent body uses it too. */
enum { WNH_SMALL_BODY = 4096, WNH_LIST_BODY = 262144 };
static char *wnh_body_render(const struct json_value *doc, const char *what,
                             size_t cap, struct zcl_native_body_err *err);

char *zcl_native_listunspent_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    int64_t minconf = json_get_int_or(args, "minconf", 1);
    int64_t maxconf = json_get_int_or(args, "maxconf", 9999999);
    char params[128];
    snprintf(params, sizeof(params), "[%lld,%lld]",
             (long long)minconf, (long long)maxconf);
    char *raw = node_rpc_call("listunspent", params);
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "listunspent");
        LOG_NULL("native.wallet", "RPC %s returned null", "listunspent");
    }

    /* The node RPC listunspent is Bitcoin-compatible and answers a BARE
     * ARRAY; the native command bridge projects an OBJECT and drops a
     * non-object body — the same defect class that made `app swap list`
     * answer BAD_TOOL_BODY for its whole existence (see rpc_swap_list).
     * Wrap the array in the envelope this command declared as its output
     * schema (engine/composition/commands/core.def: zcl.wallet_utxos.v1), naming the
     * confirmation window the answer was computed under — the projection
     * idiom the shielded read bodies below already use. */
    struct json_value utxos;
    if (!json_read(&utxos, raw, strlen(raw))) {
        json_free(&utxos);
        free(raw);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned an unparseable body", "listunspent");
        LOG_NULL("native.wallet", "RPC %s returned an unparseable body",
                 "listunspent");
    }
    free(raw);

    /* An RPC-level error body is forwarded verbatim: the bridge already
     * turns {"error":...} into a typed TOOL_ERROR, and re-wrapping it would
     * hide the node's own message. */
    if (utxos.type == JSON_OBJ && json_get(&utxos, "error")) {
        char *passthru = wnh_body_render(&utxos, "listunspent",
                                         WNH_LIST_BODY, err);
        json_free(&utxos);
        return passthru;
    }

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    if (utxos.type != JSON_ARR) {
        /* A wallet with no UTXOs still answers with an empty list, never a
         * missing key — an empty holding is an answer, not an absence. */
        json_free(&utxos);
        json_init(&utxos);
        json_set_array(&utxos);
    }
    (void)json_push_kv_str(&doc, "schema", "zcl.wallet_utxos.v1");
    (void)json_push_kv(&doc, "utxos", &utxos);
    (void)json_push_kv_int(&doc, "count", (int64_t)utxos.num_children);
    (void)json_push_kv_int(&doc, "minconf", minconf);
    (void)json_push_kv_int(&doc, "maxconf", maxconf);
    json_free(&utxos);

    char *out = wnh_body_render(&doc, "listunspent", WNH_LIST_BODY, err);
    json_free(&doc);
    return out;
}

char *zcl_native_listtransactions_body(const struct json_value *args,
                                        struct zcl_native_body_err *err)
{
    char params[128];
    snprintf(params, sizeof(params), "[\"\",%lld,%lld]",
             (long long)json_get_int_or(args, "count", 10),
             (long long)json_get_int_or(args, "skip",   0));
    char *out = node_rpc_call("listtransactions", params);
    if (!out) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "listtransactions");
        LOG_NULL("native.wallet", "RPC %s returned null", "listtransactions");
    }
    return out;
}

char *zcl_native_gettransaction_body(const struct json_value *args,
                                      struct zcl_native_body_err *err)
{
    const char *v = json_get_str(json_get(args, "txid"));
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, v);
    char *params = rpc_arg_builder_to_json(&p);
    char *out = params ? node_rpc_call("gettransaction", params) : NULL;
    free(params);
    if (!out) {
        char ctx[192];
        snprintf(ctx, sizeof(ctx), "txid=%s", v ? v : "(null)");
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC gettransaction failed: %.150s", ctx);
        LOG_NULL("native.wallet", "%s failed: %s", "gettransaction", ctx);
    }
    return out;
}

char *zcl_native_address_public_key_body(
    const struct json_value *args, struct zcl_native_body_err *err)
{
    const char *address = json_get_str(json_get(args, "address"));
    if (!address || !address[0]) {
        err->status = ZCL_NATIVE_BODY_INVALID;
        (void)snprintf(err->message, sizeof(err->message),
                       "address is required");
        LOG_NULL("native.wallet", "%s",
                 "address public-key lookup missing address");
    }
    if (err->status != ZCL_NATIVE_BODY_OK)
        return NULL;

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, address);
    char *params = rpc_arg_builder_to_json(&p);
    char *raw = params ? node_rpc_call("validateaddress", params) : NULL;
    free(params);
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        (void)snprintf(err->message, sizeof(err->message),
                       "RPC validateaddress returned null");
        LOG_NULL("native.wallet", "%s",
                 "RPC validateaddress returned null");
    }
    if (err->status != ZCL_NATIVE_BODY_OK)
        return NULL;

    struct json_value root;
    bool parsed = json_read(&root, raw, strlen(raw));
    free(raw);
    if (!parsed) {
        json_free(&root);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        (void)snprintf(err->message, sizeof(err->message),
                       "validateaddress returned an unparseable body");
        LOG_NULL("native.wallet", "%s",
                 "validateaddress returned an unparseable body");
    }
    if (err->status != ZCL_NATIVE_BODY_OK)
        return NULL;

    if (root.type == JSON_OBJ && json_get(&root, "error")) {
        char *out = wnh_body_render(&root, "validateaddress",
                                    WNH_SMALL_BODY, err);
        json_free(&root);
        return out;
    }

    bool valid = json_get_bool(json_get(&root, "isvalid"));
    bool owned = json_get_bool(json_get(&root, "ismine"));
    const char *pubkey = json_get_str(json_get(&root, "pubkey"));
    size_t pubkey_len = pubkey ? strlen(pubkey) : 0;
    bool pubkey_hex = pubkey_len == 66 || pubkey_len == 130;
    for (size_t i = 0; pubkey_hex && i < pubkey_len; i++)
        pubkey_hex = isxdigit((unsigned char)pubkey[i]) != 0;
    if (!valid || !owned || !pubkey_hex) {
        json_free(&root);
        err->status = ZCL_NATIVE_BODY_INVALID;
        const char *why = !valid ? "address is not valid"
            : !owned ? "address is not owned by this wallet"
                     : "wallet address has no canonical public key";
        (void)snprintf(err->message, sizeof(err->message), "%s", why);
        LOG_NULL("native.wallet", "address public-key lookup refused: %s",
                 why);
        return NULL;
    }

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_str(&doc, "schema", "zcl.wallet_public_key.v1");
    (void)json_push_kv_str(&doc, "pubkey", pubkey);
    (void)json_push_kv_bool(&doc, "compressed", pubkey_len == 66);
    (void)json_push_kv_bool(&doc, "owned", true);
    json_free(&root);

    char *out = wnh_body_render(&doc, "validateaddress",
                                WNH_SMALL_BODY, err);
    json_free(&doc);
    return out;
}

char *zcl_native_listaddresses_body(const struct json_value *args,
                                     struct zcl_native_body_err *err)
{
    (void)args;
    /* The node RPC `listwalletkeys` returns {transparent_keys:[{address,...}],
     * sapling_keys:[...]}.  Call it without private keys and project just
     * the addresses so the caller gets a clean list. */
    char *raw = node_rpc_call("listwalletkeys", "[false]");
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "listwalletkeys");
        LOG_NULL("native.wallet", "RPC %s returned null", "listwalletkeys");
    }

    struct json_value root;
    if (!json_read(&root, raw, strlen(raw)))
        return raw;
    free(raw);

    size_t cap = 65536;
    char *out = zcl_malloc(cap, "listaddresses_body");
    if (!out) {
        json_free(&root);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s", "listaddresses response");
        if (cap > 0)
            LOG_NULL("native.wallet", "malloc failed for %s (%zu bytes)",
                     "listaddresses response", cap);
        LOG_NULL("native.wallet", "malloc failed for %s",
                 "listaddresses response");
    }
    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, cap - pos, "{\"t_addresses\":[");

    const struct json_value *tk = json_get(&root, "transparent_keys");
    bool first = true;
    if (tk && tk->type == JSON_ARR) {
        for (size_t i = 0; i < tk->num_children; i++) {
            const struct json_value *k = &tk->children[i];
            const struct json_value *av = json_get(k, "address");
            const char *addr = av ? json_get_str(av) : NULL;
            if (!addr || !addr[0]) continue;
            if (pos + strlen(addr) + 8 >= cap) break;
            if (!first) out[pos++] = ',';
            first = false;
            out[pos++] = '"';
            for (const char *c = addr; *c && pos + 2 < cap; c++) out[pos++] = *c;
            out[pos++] = '"';
        }
    }
    pos += (size_t)snprintf(out + pos, cap - pos, "],\"z_addresses\":[");

    const struct json_value *sk = json_get(&root, "sapling_keys");
    first = true;
    if (sk && sk->type == JSON_ARR) {
        for (size_t i = 0; i < sk->num_children; i++) {
            const struct json_value *k = &sk->children[i];
            const struct json_value *av = json_get(k, "address");
            const char *addr = av ? json_get_str(av) : NULL;
            if (!addr || !addr[0]) continue;
            if (pos + strlen(addr) + 8 >= cap) break;
            if (!first) out[pos++] = ',';
            first = false;
            out[pos++] = '"';
            for (const char *c = addr; *c && pos + 2 < cap; c++) out[pos++] = *c;
            out[pos++] = '"';
        }
    }
    if (pos + 2 < cap) { out[pos++] = ']'; out[pos++] = '}'; out[pos] = 0; }

    json_free(&root);
    return out;
}

/* ── shielded read bodies ────────────────────────────────────────────────
 * z_getbalance answers with a bare decimal STRING and z_listunspent with a
 * bare ARRAY; the bridge projects an OBJECT. Each body therefore names what
 * it asked for alongside the answer, so the reply carries the address and
 * confirmation floor the number was computed under instead of an unlabelled
 * scalar the caller has to remember the question for. */

/* Serialize one composed JSON document into a fresh heap buffer, or report a
 * body failure. Shared by the list bodies; `cap` is sized to the answer (a
 * balance is three fields, a note list is unbounded by design and pages at
 * the bridge). The WNH_* sizes are declared with the forward declaration at
 * the top of the file. */
static char *wnh_body_render(const struct json_value *doc, const char *what,
                             size_t cap, struct zcl_native_body_err *err)
{
    char *out = zcl_malloc(cap, "shielded_body");
    if (!out) {
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "malloc failed for %s response", what);
        LOG_NULL("native.wallet", "malloc failed for %s response (%zu bytes)",
                 what, cap);
    }
    size_t n = json_write(doc, out, cap);
    if (n == 0 || n >= cap) {
        free(out);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "%s response did not fit the body buffer", what);
        LOG_NULL("native.wallet", "%s response did not fit %zu bytes",
                 what, cap);
    }
    return out;
}

/* True when `s` is a plain decimal amount ("0.00000000", "12", "-0.5").
 * z_getbalance answers a rejected address by setting its result string to
 * prose ("Invalid address") rather than an RPC error, so a body that copied
 * the string through would publish that prose as a balance under ok:true.
 * A balance field must always parse as a number or not exist. */
static bool wnh_is_decimal_amount(const char *s)
{
    if (!s || !s[0])
        return false;
    if (*s == '-' || *s == '+')
        s++;
    bool any_digit = false;
    bool seen_dot = false;
    for (; *s; s++) {
        if (*s >= '0' && *s <= '9') {
            any_digit = true;
        } else if (*s == '.' && !seen_dot) {
            seen_dot = true;
        } else {
            return false;
        }
    }
    return any_digit;
}

char *zcl_native_z_getbalance_body(const struct json_value *args,
                                   struct zcl_native_body_err *err)
{
    const char *addr = json_get_str(json_get(args, "address"));
    if (!addr || !addr[0]) {
        err->status = ZCL_NATIVE_BODY_INVALID;
        snprintf(err->message, sizeof(err->message),
                 "address is required for a shielded balance");
        LOG_NULL("native.wallet", "z_getbalance: address is required");
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, addr);
    char *params = rpc_arg_builder_to_json(&p);
    char *raw = params ? node_rpc_call("z_getbalance", params) : NULL;
    free(params);
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s failed: address=%s", "z_getbalance", addr);
        LOG_NULL("native.wallet", "%s failed: address=%s", "z_getbalance",
                 addr);
    }

    struct json_value result;
    if (!json_read(&result, raw, strlen(raw))) {
        json_free(&result);
        free(raw);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned an unparseable body", "z_getbalance");
        LOG_NULL("native.wallet", "RPC %s returned an unparseable body",
                 "z_getbalance");
    }
    free(raw);

    /* An RPC-level error body is forwarded verbatim: the bridge already
     * turns {"error":...} into a typed TOOL_ERROR, and re-wrapping it would
     * hide the node's own message. */
    if (result.type == JSON_OBJ && json_get(&result, "error")) {
        char *passthru = wnh_body_render(&result, "z_getbalance", WNH_SMALL_BODY, err);
        json_free(&result);
        return passthru;
    }

    const char *amount = result.type == JSON_STR ? json_get_str(&result)
                                                 : NULL;
    if (!wnh_is_decimal_amount(amount)) {
        char reason[128];
        (void)snprintf(reason, sizeof(reason), "%s",
                       amount && amount[0] ? amount : "no amount in reply");
        json_free(&result);
        err->status = ZCL_NATIVE_BODY_INVALID;
        snprintf(err->message, sizeof(err->message),
                 "z_getbalance did not return an amount for %s: %s",
                 addr, reason);
        LOG_NULL("native.wallet",
                 "z_getbalance returned a non-amount for address=%s: %s",
                 addr, reason);
    }

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv_str(&doc, "address", addr);
    (void)json_push_kv_str(&doc, "balance", amount);
    (void)json_push_kv_int(&doc, "minconf", 1);
    json_free(&result);

    char *out = wnh_body_render(&doc, "z_getbalance", WNH_SMALL_BODY, err);
    json_free(&doc);
    return out;
}

char *zcl_native_z_listunspent_body(const struct json_value *args,
                                    struct zcl_native_body_err *err)
{
    (void)args;
    /* minconf 0 — every note the wallet can see, confirmed or not. Each
     * entry carries its own `confirmations`, so filtering stays with the
     * caller instead of being silently applied here. */
    char *raw = node_rpc_call("z_listunspent", "[0]");
    if (!raw) {
        err->status = ZCL_NATIVE_BODY_UNAVAILABLE;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned null", "z_listunspent");
        LOG_NULL("native.wallet", "RPC %s returned null", "z_listunspent");
    }

    struct json_value notes;
    if (!json_read(&notes, raw, strlen(raw))) {
        json_free(&notes);
        free(raw);
        err->status = ZCL_NATIVE_BODY_INTERNAL;
        snprintf(err->message, sizeof(err->message),
                 "RPC %s returned an unparseable body", "z_listunspent");
        LOG_NULL("native.wallet", "RPC %s returned an unparseable body",
                 "z_listunspent");
    }
    free(raw);

    if (notes.type == JSON_OBJ && json_get(&notes, "error")) {
        char *passthru = wnh_body_render(&notes, "z_listunspent", WNH_LIST_BODY, err);
        json_free(&notes);
        return passthru;
    }

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    if (notes.type != JSON_ARR) {
        /* A wallet with no notes still answers with an empty list, never a
         * missing key — an empty holding is an answer, not an absence. */
        json_free(&notes);
        json_init(&notes);
        json_set_array(&notes);
    }
    (void)json_push_kv_int(&doc, "count", (int64_t)notes.num_children);
    (void)json_push_kv(&doc, "notes", &notes);
    json_free(&notes);

    char *out = wnh_body_render(&doc, "z_listunspent", WNH_LIST_BODY, err);
    json_free(&doc);
    return out;
}
