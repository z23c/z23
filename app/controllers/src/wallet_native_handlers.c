/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for the MUTATING core.wallet.* leaves — the ones that
 * create keys, reveal keys, move funds, rescan, or write a backup.
 *
 * The read bodies that compose a query RPC live in
 * wallet_native_read_bodies.c. They were split out when this file passed the
 * size ceiling: the two halves are different risk classes, and the leaves here
 * are the ones that carry ZCL_COMMAND_CONFIRM_PLAN_COMMIT.
 *
 * The trampolines at the end still bind the read bodies, which is why the
 * shared header is included from both files. */

#include "controllers/wallet_native_handlers.h"
#include "controllers/wallet_shielded_controller.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "core/amount.h"
#include "encoding/utilstrencodings.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "rpc/rpc_timeout.h"
#include "services/wallet_money_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/sapling_keys.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* ── core.wallet.* mutating native leaves ────────────────────────────────
 * Dedicated registry handlers (request -> reply) for the leaves that create
 * keys, reveal keys, move funds, rescan, or write a backup. Each reaches the
 * running node over the same loopback JSON-RPC path the read bodies use
 * (zcl_native_bridge_ensure_rpc + node_rpc_call) and renders one bounded
 * JSON document.
 *
 * transaction.send / shielded.send / address.export-key carry
 * ZCL_COMMAND_CONFIRM_PLAN_COMMIT, and honour it with the reserved `confirm`
 * boolean input key: a first call without `confirm:true` returns a
 * non-mutating plan plus the exact commit next-action, and only a second call
 * with `confirm:true` broadcasts or reveals. Bound in
 * config/commands/core.def.
 *
 * `idempotency_key` is a caller-supplied correlation tag: it is folded into
 * the plan token and echoed on the committed reply, so a plan and its commit
 * are provably the same intent. It is NOT node-side deduplication — the
 * wallet RPC layer has no replay ledger, so two identical confirmed commits
 * broadcast twice. */

#define WNH_TAG "native.wallet"

/* Detect a JSON-RPC failure body: {"error":{...}} / {"error":"..."} or a bare
 * {"code":int,"message":str} (the shape node_rpc_call returns on transport
 * failure). On error, sets *msg_out to the message text when there is one. */
static bool wnh_body_is_error(const struct json_value *body,
                              const char **msg_out)
{
    if (!body || body->type != JSON_OBJ)
        return false;
    const struct json_value *err = json_get(body, "error");
    if (err && !json_is_null(err)) {
        if (msg_out) {
            if (err->type == JSON_OBJ)
                *msg_out = json_get_str(json_get(err, "message"));
            else if (err->type == JSON_STR)
                *msg_out = json_get_str(err);
        }
        return true;
    }
    const struct json_value *code = json_get(body, "code");
    const struct json_value *m = json_get(body, "message");
    if (code && code->type == JSON_INT && m && m->type == JSON_STR) {
        if (msg_out)
            *msg_out = json_get_str(m);
        return true;
    }
    return false;
}

/* Call one wallet RPC method. On success returns true and fills *out (caller
 * json_free's it). On any failure sets a typed error body on `reply`, releases
 * its own scratch, and returns false — never leaves `reply` silent. */
static bool wnh_call_rpc_common(struct zcl_command_reply *reply,
                                const char *method, const char *params_json,
                                long total_ms, struct json_value *out)
{
    zcl_native_bridge_ensure_rpc();
    char *raw = total_ms > 0
        ? node_rpc_call_deadline(method, params_json, 2000, total_ms)
        : node_rpc_call(method, params_json);
    if (!raw) {
        LOG_ERROR(WNH_TAG, "RPC %s returned null", method);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_TRANSIENT, "NODE_UNAVAILABLE",
                               "dispatch", true, false,
                               "the node did not return a wallet result",
                               method);
        return false;
    }
    if (!json_read(out, raw, strlen(raw))) {
        json_free(out);
        free(raw);
        LOG_ERROR(WNH_TAG, "RPC %s returned an unparseable body", method);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY",
                               "serialize", false, false,
                               "wallet RPC returned an unparseable body",
                               method);
        return false;
    }
    free(raw);
    const char *emsg = NULL;
    if (wnh_body_is_error(out, &emsg)) {
        LOG_ERROR(WNH_TAG, "RPC %s reported an error: %s", method,
                  emsg && emsg[0] ? emsg : "(no message)");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "WALLET_RPC_ERROR",
                               "execute", false, false,
                               emsg && emsg[0] ? emsg
                                               : "wallet RPC reported an error",
                               method);
        json_free(out);
        return false;
    }
    return true;
}

bool wnh_call_rpc(struct zcl_command_reply *reply, const char *method,
                  const char *params_json, struct json_value *out)
{
    return wnh_call_rpc_common(reply, method, params_json, 0, out);
}

bool wnh_call_rpc_deadline(struct zcl_command_reply *reply, const char *method,
                           const char *params_json, long total_ms,
                           struct json_value *out)
{
    return wnh_call_rpc_common(reply, method, params_json, total_ms, out);
}

/* Deterministic, non-secret plan token binding a plan preview to its exact
 * parameters (FNV-1a over the parts, 16 hex). The operator can compare it
 * across the plan and the committed reply; no server state is stored. */
void wnh_plan_token(char out[17], const char *a, const char *b,
                    const char *c)
{
    uint64_t h = 1469598103934665603ULL;
    const char *parts[3] = { a, b, c };
    for (int i = 0; i < 3; i++) {
        for (const char *p = parts[i]; p && *p; p++) {
            h ^= (unsigned char)*p;
            h *= 1099511628211ULL;
        }
        h ^= 0x1f;
        h *= 1099511628211ULL;
    }
    (void)snprintf(out, 17, "%016llx", (unsigned long long)h);
}

/* Coerce an `amount` JSON value (int / real / decimal string) to a
 * non-negative double. Sets *ok=false on any other shape or a negative. */
static double wnh_amount_real(const struct json_value *amt, bool *ok)
{
    *ok = false;
    if (!amt)
        return 0.0;
    if (amt->type == JSON_REAL) {
        double v = json_get_real(amt);
        *ok = v >= 0.0;
        return v;
    }
    if (amt->type == JSON_INT) {
        double v = (double)json_get_int(amt);
        *ok = v >= 0.0;
        return v;
    }
    if (amt->type == JSON_STR) {
        const char *s = json_get_str(amt);
        if (!s || !s[0])
            return 0.0;
        char *end = NULL;
        double v = strtod(s, &end);
        if (end && !*end && v >= 0.0) {
            *ok = true;
            return v;
        }
    }
    return 0.0;
}

/* Exact zatoshis + RPC text; numbers must resolve to an integral zatoshi. */
static bool wnh_amount_exact(const struct json_value *amt, CAmount *zats_out, char amount_out[32])
{
    if (!amt || !zats_out || !amount_out)
        return false;
    CAmount zats = 0;
    if (amt->type == JSON_STR) {
        const char *s = json_get_str(amt);
        if (!s || !s[0] || !ParseFixedPoint(s, 8, &zats))
            return false;
    } else if (amt->type == JSON_INT) {
        int64_t coins = json_get_int(amt);
        if (coins <= 0 || coins > MAX_MONEY / COIN)
            return false;
        zats = coins * COIN;
    } else if (amt->type == JSON_REAL) {
        double coins = json_get_real(amt);
        if (!(coins > 0.0) || coins > (double)MAX_MONEY / (double)COIN)
            return false; /* also rejects NaN and positive infinity */
        double scaled = coins * (double)COIN;
        int64_t rounded = (int64_t)(scaled + 0.5);
        double delta = scaled - (double)rounded;
        if (delta < 0.0)
            delta = -delta;
        if (delta > 0.000001)
            return false;
        zats = rounded;
    } else return false;
    if (zats <= 0 || !MoneyRange(zats))
        return false;
    int64_t whole = zats / COIN;
    int64_t frac = zats % COIN;
    int n = snprintf(amount_out, 32, "%lld.%08lld",
                     (long long)whole, (long long)frac);
    if (n <= 0 || n >= 32)
        return false;
    *zats_out = zats;
    return true;
}

void wnh_fail(struct zcl_command_reply *reply,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    LOG_ERROR(WNH_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, "handle", false,
                           false, message, evidence ? evidence : "");
}

/* Serialize `ci` into `commit` as the exact commit-half input for a plan.
 * Truncating to {"confirm":true} silently discards the recipient and is not a
 * plan; callers must fail the plan when their declared response budget cannot
 * carry every binding. */
bool wnh_commit_input(const struct json_value *ci, char *commit,
                      size_t commit_size)
{
    size_t n = json_write(ci, commit, commit_size);
    if (n == 0 || n >= commit_size) {
        LOG_WARN(WNH_TAG, "commit input truncated (%zu bytes)", n);
        if (commit_size > 0)
            commit[0] = '\0';
        return false;
    }
    return true;
}

/* Emit the non-mutating plan half of a CONFIRM_PLAN_COMMIT leaf: stage=plan,
 * a plan_token, a confirm hint, and the exact input that commits it.
 *
 * The commit input travels as DATA, not as a next-action. A next-action naming
 * this same leaf cannot be serialized at all: push_next_array() rejects a next
 * whose path equals the current leaf's (lib/kernel/src/command_registry.c),
 * which is a deliberate guard against a command that only ever points at
 * itself. Emitting one anyway failed the whole reply, so every plan leg here —
 * send, shielded-send, export-key — answered RESPONSE_BUDGET_EXCEEDED instead
 * of a plan, and the plan/commit flow could not be driven from the typed
 * interface at all. The caller needs the committing input, not a link; it is
 * `commit_input` below, and re-running this leaf with it executes the plan. */
void wnh_emit_plan(struct zcl_command_reply *reply, const char *path,
                   const char *action, const char *token,
                   const char *commit_input)
{
    (void)path; /* the commit re-runs THIS leaf; see the note above */
    (void)json_push_kv_str(&reply->data, "stage", "plan");
    (void)json_push_kv_str(&reply->data, "action", action);
    (void)json_push_kv_bool(&reply->data, "committed", false);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    (void)json_push_kv_str(
        &reply->data, "confirm_hint",
        "re-run this same command with the commit_input below to execute");
    (void)json_push_kv_str(&reply->data, "commit_input", commit_input);
    reply->error.mutated = false;
}

/* Extract a bare JSON-string RPC result (getnewaddress / dumpprivkey /
 * sendtoaddress / z_sendmany all return one). NULL when the body was not a
 * non-empty string. */
static const char *wnh_string_result(const struct json_value *body)
{
    if (!body || body->type != JSON_STR)
        return NULL;
    const char *s = json_get_str(body);
    return (s && s[0]) ? s : NULL;
}

void zcl_native_handle_wallet_address_new(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value body;
    if (!wnh_call_rpc_deadline(reply, "getnewaddress", NULL,
                               RPC_WALLET_MUTATION_TIMEOUT_MS, &body))
        return;
    const char *addr = wnh_string_result(&body);
    if (!addr) {
        json_free(&body);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NO_ADDRESS",
                 "getnewaddress did not return an address", "getnewaddress");
        return;
    }
    (void)json_push_kv_str(&reply->data, "address", addr);
    (void)json_push_kv_bool(&reply->data, "created", true);
    reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_wallet_shielded_address(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value body;
    if (!wnh_call_rpc_deadline(reply, "z_getnewaddress", NULL,
                               RPC_WALLET_MUTATION_TIMEOUT_MS, &body))
        return;
    const char *addr = wnh_string_result(&body);
    uint8_t diversifier[11], pk_d[32];
    /* This adapter is a separate CLI process and its local chain_params may
     * still be the mainnet default while the authenticated target node is a
     * testnet/regtest process.  The node just generated this address for its
     * own active chain, so validate the complete Sapling encoding here; do
     * not misclassify it using the CLI process's unrelated active HRP. User
     * supplied send recipients continue to use wallet_addr_is_sapling(),
     * whose active-chain HRP check remains fail-closed. */
    if (!addr || !sapling_decode_payment_address(addr, diversifier, pk_d)) {
        const char *failure = addr && addr[0]
            ? addr
            : "z_getnewaddress did not return a shielded address";
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_ADDRESS_FAILED",
                 failure, "z_getnewaddress");
        json_free(&body);
        return;
    }
    (void)json_push_kv_str(&reply->data, "address", addr);
    (void)json_push_kv_bool(&reply->data, "created", true);
    reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_wallet_address_import(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *addr = json_get_str(json_get(request->input, "address"));
    if (!addr || !addr[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "core.wallet.address.import");
        return;
    }
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, addr);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode importaddress params", addr);
        return;
    }
    struct json_value body;
    bool ok = wnh_call_rpc(reply, "importaddress", params, &body);
    free(params);
    if (!ok)
        return;
    json_free(&body); /* importaddress acknowledges with null on success */
    (void)json_push_kv_str(&reply->data, "address", addr);
    (void)json_push_kv_bool(&reply->data, "imported", true);
    reply->error.mutated = true;
}

void zcl_native_handle_wallet_address_export_key(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *addr = json_get_str(json_get(request->input, "address"));
    if (!addr || !addr[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "core.wallet.address.export-key");
        return;
    }
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    char token[17];
    wnh_plan_token(token, "export-key", addr, "");

    if (!confirm) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "address", addr);
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[384];
        bool encoded = wnh_commit_input(&ci, commit, sizeof(commit));
        json_free(&ci);
        if (!encoded) {
            wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                     "exact export-key commit input exceeds its budget",
                     "address");
            return;
        }
        (void)json_push_kv_str(&reply->data, "address", addr);
        (void)json_push_kv_str(
            &reply->data, "warning",
            "commit reveals this address's private key in the response");
        wnh_emit_plan(reply, request->spec->path, "export-key", token, commit);
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, addr);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode dumpprivkey params", addr);
        return;
    }
    struct json_value body;
    bool ok = wnh_call_rpc(reply, "dumpprivkey", params, &body);
    free(params);
    if (!ok)
        return;
    const char *wif = wnh_string_result(&body);
    if (!wif) {
        json_free(&body);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NO_KEY",
                 "dumpprivkey did not return a private key", addr);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "address", addr);
    (void)json_push_kv_str(&reply->data, "privkey", wif);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    json_free(&body);
}

void zcl_native_handle_wallet_transaction_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *addr = json_get_str(json_get(request->input, "address"));
    if (!addr || !addr[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "core.wallet.transaction.send");
        return;
    }
    bool aok = false;
    double amount = wnh_amount_real(json_get(request->input, "amount"), &aok);
    if (!aok) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_AMOUNT",
                 "amount must be a non-negative number", addr);
        return;
    }
    const char *idem =
        json_get_str(json_get(request->input, "idempotency_key"));
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    char amtbuf[64];
    (void)snprintf(amtbuf, sizeof(amtbuf), "%.8f", amount);
    char token[17];
    wnh_plan_token(token, addr, amtbuf, idem ? idem : "");

    if (!confirm) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "address", addr);
        (void)json_push_kv_real(&ci, "amount", amount);
        if (idem && idem[0])
            (void)json_push_kv_str(&ci, "idempotency_key", idem);
        (void)json_push_kv_bool(&ci, "confirm", true);
        char commit[512];
        bool encoded = wnh_commit_input(&ci, commit, sizeof(commit));
        json_free(&ci);
        if (!encoded) {
            wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                     "exact send commit input exceeds its budget", "address");
            return;
        }
        (void)json_push_kv_str(&reply->data, "address", addr);
        (void)json_push_kv_real(&reply->data, "amount", amount);
        if (idem && idem[0])
            (void)json_push_kv_str(&reply->data, "idempotency_key", idem);
        wnh_emit_plan(reply, request->spec->path, "send", token, commit);
        return;
    }

    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, addr);
    rpc_arg_builder_push_real(&p, amount);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode sendtoaddress params", addr);
        return;
    }
    struct json_value body;
    bool ok = wnh_call_rpc(reply, "sendtoaddress", params, &body);
    free(params);
    if (!ok)
        return;
    const char *txid = wnh_string_result(&body);
    if (!txid) {
        json_free(&body);
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NO_TXID",
                 "sendtoaddress did not return a transaction id", addr);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "txid", txid);
    (void)json_push_kv_str(&reply->data, "address", addr);
    (void)json_push_kv_real(&reply->data, "amount", amount);
    if (idem && idem[0])
        (void)json_push_kv_str(&reply->data, "idempotency_key", idem);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
    json_free(&body);
}

void zcl_native_handle_wallet_shielded_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *wallet_scope =
        json_get_str(json_get(request->input, "wallet_scope"));
    if (!wallet_money_scope_valid(wallet_scope)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_WALLET_SCOPE",
                 "wallet_scope must explicitly be dev, prod, or test",
                 "core.wallet.shielded.send");
        return;
    }
    const char *from = json_get_str(json_get(request->input, "from"));
    const char *to = json_get_str(json_get(request->input, "to"));
    if (!from || !from[0] || !to || !to[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "both from and to are required", "core.wallet.shielded.send");
        return;
    }
    CAmount amount_zats = 0;
    char amount[32];
    if (!wnh_amount_exact(json_get(request->input, "amount"), &amount_zats,
                          amount)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_AMOUNT",
                 "amount must be positive, in range, and exact to 8 decimals",
                 "amount");
        return;
    }
    (void)amount_zats; /* exact range proof; the RPC consumes decimal text */
    const char *idem =
        json_get_str(json_get(request->input, "idempotency_key"));
    if (idem && strlen(idem) > 128) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_IDEMPOTENCY_KEY",
                 "idempotency_key must be at most 128 characters",
                 "idempotency_key");
        return;
    }
    /* Optional UTF-8 or raw Sapling memo. It also carries higher-level
     * bindings such as the store's ZCL23ORDER:<id> reconciliation key. */
    const char *memo = json_get_str(json_get(request->input, "memo"));
    const char *memo_hex = json_get_str(json_get(request->input, "memo_hex"));
    if (memo && !memo[0]) memo = NULL;
    if (memo_hex && !memo_hex[0]) memo_hex = NULL;
    if (memo_hex) {
        size_t hlen = strlen(memo_hex);
        bool hex_ok = (hlen % 2 == 0) && hlen <= 1024;
        for (size_t i = 0; hex_ok && i < hlen; i++)
            hex_ok = isxdigit((unsigned char)memo_hex[i]) != 0;
        if (!hex_ok) {
            wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_MEMO_HEX",
                     "memo_hex must be even-length hex, at most 1024 chars",
                     "memo_hex");
            return;
        }
    }
    if (memo && strlen(memo) > 512) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_MEMO",
                 "memo must be at most 512 bytes", "memo");
        return;
    }
    /* One document binds every field executed by either stage. */
    struct json_value ci;
    json_init(&ci);
    json_set_object(&ci);
    (void)json_push_kv_str(&ci, "wallet_scope", wallet_scope);
    (void)json_push_kv_str(&ci, "from", from);
    (void)json_push_kv_str(&ci, "to", to);
    (void)json_push_kv_str(&ci, "amount", amount);
    if (memo_hex)
        (void)json_push_kv_str(&ci, "memo_hex", memo_hex);
    else if (memo)
        (void)json_push_kv_str(&ci, "memo", memo);
    if (idem && idem[0])
        (void)json_push_kv_str(&ci, "idempotency_key", idem);
    (void)json_push_kv_bool(&ci, "confirm", true);
    char commit[2048];
    bool encoded = wnh_commit_input(&ci, commit, sizeof(commit));
    json_free(&ci);
    if (!encoded) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                 "exact shielded commit input exceeds its response budget",
                 "memo");
        return;
    }
    char token[17];
    wnh_plan_token(token, "shielded-send", commit, "");
    bool confirm = json_get_bool_or(request->input, "confirm", false);

    if (!confirm) {
        (void)json_push_kv_str(&reply->data, "wallet_scope", wallet_scope);
        (void)json_push_kv_str(&reply->data, "from", from);
        (void)json_push_kv_str(&reply->data, "to", to);
        (void)json_push_kv_str(&reply->data, "amount", amount);
        wnh_emit_plan(reply, request->spec->path, "shielded-send", token,
                      commit);
        return;
    }

    /* Build [from,[{address,amount,memo?}]] through the encoder so input text
     * cannot rewrite the RPC params array. */
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, from);
    struct json_value recip, recip_arr;
    json_init(&recip);
    json_set_object(&recip);
    (void)json_push_kv_str(&recip, "address", to);
    (void)json_push_kv_str(&recip, "amount", amount);
    if (memo_hex)
        (void)json_push_kv_str(&recip, "memo_hex", memo_hex);
    else if (memo)
        (void)json_push_kv_str(&recip, "memo", memo);
    json_init(&recip_arr);
    json_set_array(&recip_arr);
    (void)json_push_back(&recip_arr, &recip);
    rpc_arg_builder_push_value(&p, &recip_arr);
    json_free(&recip);
    json_free(&recip_arr);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode z_sendmany params", "z_sendmany");
        return;
    }
    struct json_value body;
    /* Sapling proof construction legitimately exceeds the generic wallet
     * RPC deadline on a busy full node. Keep this client deadline aligned
     * with the server's bounded proof-class deadline so a successful
     * broadcast never becomes an ambiguous timeout at the native surface. */
    bool ok = wnh_call_rpc_deadline(reply, "z_sendmany", params,
                                    RPC_PROOF_BUILD_TIMEOUT_MS, &body);
    free(params);
    if (!ok)
        return;
    /* z_sendmany is synchronous here and returns the broadcast txid. */
    const char *txid = wnh_string_result(&body);
    if (!txid || strlen(txid) != 64 || !IsHex(txid)) {
        const char *failure = txid && txid[0]
            ? txid
            : "z_sendmany did not return a transaction result";
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_SEND_FAILED",
                 failure, "z_sendmany");
        json_free(&body);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "txid", txid);
    (void)json_push_kv_str(&reply->data, "wallet_scope", wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", from);
    (void)json_push_kv_str(&reply->data, "to", to);
    (void)json_push_kv_str(&reply->data, "amount", amount);
    /* Echo the effective memo for higher-level binding. */
    (void)json_push_kv_bool(&reply->data, "memo_attached",
                            memo != NULL || memo_hex != NULL);
    if (memo_hex)
        (void)json_push_kv_str(&reply->data, "memo_hex", memo_hex);
    else if (memo)
        (void)json_push_kv_str(&reply->data, "memo", memo);
    if (idem && idem[0])
        (void)json_push_kv_str(&reply->data, "idempotency_key", idem);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = true;
    json_free(&body);
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in lib/hotswap/include/hotswap/hotswap.h). Stages every native command
 * leaf this controller owns; the resident bridge re-points them at THIS
 * TU's freshly-compiled bodies via zcl_native_bridge_run(). Probe is
 * core.wallet.address.list: zcl_native_listaddresses_body ignores `args`
 * ((void)args) and unconditionally calls listwalletkeys[false], returning
 * {"t_addresses":[...],"z_addresses":[...]} with no top-level "error" key
 * on success, so the empty-args self-test dispatch succeeds.
 * core.wallet.utxo.list / core.wallet.transaction.list also default their
 * params (minconf/maxconf, count/skip) and would work as a probe too;
 * core.wallet.transaction.get requires a caller-supplied txid and is NOT
 * a probe candidate. See config/hotswap_eligible.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "core.wallet.address.list"
#include "hotswap/hotswap.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(tramp_listaddresses, zcl_native_listaddresses_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_listunspent, zcl_native_listunspent_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_listtransactions, zcl_native_listtransactions_body)

ZCL_HOTSWAP_TRAMPOLINE(tramp_gettransaction, zcl_native_gettransaction_body)

static const struct zcl_hotswap_leaf_replacement k_leaves[] = {
    { "core.wallet.address.list",      tramp_listaddresses },
    { "core.wallet.utxo.list",         tramp_listunspent },
    { "core.wallet.transaction.list",  tramp_listtransactions },
    { "core.wallet.transaction.get",   tramp_gettransaction },
};

ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, sizeof(k_leaves) / sizeof(k_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

/* REAL (activatable) single-handler module ABI export. Compiled only under a
 * `make hotswap-module-so HANDLER=core.wallet.address.list` build
 * (-DZCL_HOTSWAP_MODULE_GEN); expands to nothing in the node/release TU. The
 * module re-points ONLY the `core.wallet.address.list` leaf to this TU's
 * freshly-compiled body via the same zcl_native_bridge_run() seam the leaf
 * provider uses. See hotswap_module.h and hotswap_activate() (lib/hotswap). */
#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_listaddresses, zcl_native_listaddresses_body)

/* The module's own health hook — runs before the loader publishes it. Kept
 * node-independent (no RPC): a structural OK. */
static bool module_selftest_listaddresses(char *err, size_t cap)
{
    (void)err;
    (void)cap;
    return true;
}

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_listunspent, zcl_native_listunspent_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_listtransactions, zcl_native_listtransactions_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_gettransaction, zcl_native_gettransaction_body)

/* Mirrors k_leaves above — all four READ projections this controller owns.
 * These render WALLET state (addresses, this wallet's own unspent outputs and
 * transaction history); they neither sign, spend, nor mutate the keystore, and
 * every one is ZCL_COMMAND_READY_READ. Wallet WRITE leaves stay resident. */
/* Shielded READ projections. Both bodies live in wallet_native_read_bodies.c,
 * already an island member, so they are genuinely recompiled by the swap.
 * These render balances and note metadata the wallet already holds; the
 * viewing keys, the note decryption, and every spend path stay resident. */
ZCL_HOTSWAP_TRAMPOLINE(module_tramp_z_getbalance, zcl_native_z_getbalance_body)

ZCL_HOTSWAP_TRAMPOLINE(module_tramp_z_listunspent, zcl_native_z_listunspent_body)

static const struct zcl_hotswap_leaf k_module_leaves[] = {
    { "core.wallet.address.list",      module_tramp_listaddresses },
    { "core.wallet.utxo.list",         module_tramp_listunspent },
    { "core.wallet.transaction.list",  module_tramp_listtransactions },
    { "core.wallet.transaction.get",   module_tramp_gettransaction },
    { "core.wallet.shielded.balance",  module_tramp_z_getbalance },
    { "core.wallet.shielded.notes",    module_tramp_z_listunspent },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_listaddresses)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
