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
#include "controllers/wallet_shield_address.h"
#include "controllers/wallet_shielded_controller.h"
#include "controllers/wallet_send_once.h"
#include "controllers/wallet_spend_gate.h"

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
#include <math.h>
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
 * engine/composition/commands/core.def.
 *
 * `idempotency_key` is required on the shielded send. It is folded into the
 * plan token with the fee, and the commit passes it to z_sendmany, where the
 * node records it durably before building (controllers/wallet_send_once.h):
 * a repeat of the key never builds or broadcasts again. The commit refuses
 * before any RPC when the wallet fee differs from the one the plan quoted. */

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
        /* A spend-rule refusal can carry a shortfall: the reply keeps it, the
         * log gets fixed text. */
        if (emsg && strncmp(emsg, WALLET_SPEND_REFUSAL_PREFIX,
                            strlen(WALLET_SPEND_REFUSAL_PREFIX)) == 0)
            LOG_ERROR(WNH_TAG, "RPC %s refused by the spend rule", method);
        else
            LOG_ERROR(WNH_TAG, "RPC %s reported an error: %s", method,
                      emsg && emsg[0] ? emsg : "(no message)");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "WALLET_RPC_ERROR",
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
 * finite non-negative double. Sets *ok=false on any other shape,
 * a negative, or a non-finite result. */
static double wnh_amount_real(const struct json_value *amt, bool *ok)
{
    *ok = false;
    if (!amt)
        return 0.0;
    if (amt->type == JSON_REAL) {
        double v = json_get_real(amt);
        *ok = isfinite(v) && v >= 0.0;
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
        if (end && !*end && isfinite(v) && v >= 0.0) {
            *ok = true;
            return v;
        }
    }
    return 0.0;
}

/* Exact zatoshis from a decimal-string amount (the RPC wire form). */
static bool wnh_amount_exact_str(const struct json_value *amt,
                                 CAmount *zats_out)
{
    const char *s = json_get_str(amt);
    return s && s[0] && ParseFixedPoint(s, 8, zats_out);
}

/* Exact zatoshis from a whole-coin integer amount. */
static bool wnh_amount_exact_int(const struct json_value *amt,
                                 CAmount *zats_out)
{
    int64_t coins = json_get_int(amt);
    if (coins <= 0 || coins > MAX_MONEY / COIN)
        return false;
    *zats_out = coins * COIN;
    return true;
}

/* Exact zatoshis from a real amount: the double must resolve to an integral
 * zatoshi. */
static bool wnh_amount_exact_real(const struct json_value *amt,
                                  CAmount *zats_out)
{
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
    *zats_out = rounded;
    return true;
}

/* Range-prove the parsed zatoshis and render the exact RPC decimal text. */
static bool wnh_amount_exact_finish(CAmount zats, CAmount *zats_out,
                                    char amount_out[32])
{
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

/* Exact zatoshis + RPC text; numbers must resolve to an integral zatoshi. */
static bool wnh_amount_exact(const struct json_value *amt, CAmount *zats_out, char amount_out[32])
{
    if (!amt || !zats_out || !amount_out)
        return false;
    CAmount zats = 0;
    bool parsed = false;
    if (amt->type == JSON_STR)
        parsed = wnh_amount_exact_str(amt, &zats);
    else if (amt->type == JSON_INT)
        parsed = wnh_amount_exact_int(amt, &zats);
    else if (amt->type == JSON_REAL)
        parsed = wnh_amount_exact_real(amt, &zats);
    if (!parsed)
        return false;
    return wnh_amount_exact_finish(zats, zats_out, amount_out);
}

void wnh_fail(struct zcl_command_reply *reply,
                     enum zcl_command_exit exit_code, const char *code,
                     const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    /* The evidence is the caller's address or amount: it stays in the reply. */
    LOG_ERROR(WNH_TAG, "%s: %s", code, message);
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
 * whose path equals the current leaf's (engine/modules/kernel/src/command_registry.c),
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

void zcl_native_handle_wallet_shielded_receive(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value body;
    if (!wnh_call_rpc_deadline(reply, "z_getreceiveaddress", NULL,
                               RPC_WALLET_MUTATION_TIMEOUT_MS, &body))
        return;
    const char *addr = wnh_string_result(&body);
    uint8_t diversifier[11], pk_d[32];
    /* Same validation as shielded.address: the node issued the address for
     * its own chain, so check the complete Sapling encoding here rather than
     * this CLI process's unrelated default HRP. */
    if (!addr || !sapling_decode_payment_address(addr, diversifier, pk_d)) {
        const char *failure = addr && addr[0]
            ? addr
            : "z_getreceiveaddress did not return a shielded address";
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_RECEIVE_FAILED",
                 failure, "z_getreceiveaddress");
        json_free(&body);
        return;
    }
    (void)json_push_kv_str(&reply->data, "address", addr);
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

/* Non-mutating plan half of transaction.send: echo the inputs and the exact
 * commit input that executes them. */
static void wnh_send_plan(struct zcl_command_reply *reply, const char *path,
                          const char *addr, double amount, const char *idem,
                          const char *token)
{
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
    wnh_emit_plan(reply, path, "send", token, commit);
}

/* Encode the sendtoaddress params and broadcast; on false the reply already
 * carries the typed error. */
static bool wnh_send_broadcast(struct zcl_command_reply *reply,
                               const char *addr, double amount,
                               struct json_value *body)
{
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, addr);
    rpc_arg_builder_push_real(&p, amount);
    char *params = rpc_arg_builder_to_json(&p);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode sendtoaddress params", addr);
        return false;
    }
    bool ok = wnh_call_rpc(reply, "sendtoaddress", params, body);
    free(params);
    return ok;
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
        wnh_send_plan(reply, request->spec->path, addr, amount, idem, token);
        return;
    }

    struct json_value body;
    if (!wnh_send_broadcast(reply, addr, amount, &body))
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

/* Exact decimal text for a zatoshi amount (8 places, the RPC wire form). */
static bool wnh_zat_text(CAmount zats, char out[32])
{
    if (zats < 0 || !MoneyRange(zats))
        return false;
    int n = snprintf(out, 32, "%lld.%08lld", (long long)(zats / COIN),
                     (long long)(zats % COIN));
    return n > 0 && n < 32;
}

/* The fee the z_sendmany commit pays is the node wallet default_fee, which
 * getwalletinfo reports as paytxfee. This read builds no transaction and
 * reserves no notes; an unreadable fee refuses before any broadcast. */
static bool wnh_shielded_fee_zat(struct zcl_command_reply *reply,
                                 CAmount *fee_out)
{
    struct json_value info;
    if (!wnh_call_rpc(reply, "getwalletinfo", NULL, &info)) {
        LOG_WARN(WNH_TAG, "shielded fee read: getwalletinfo failed");
        return false;
    }
    char fee_text[32];
    bool ok = wnh_amount_exact(json_get(&info, "paytxfee"), fee_out, fee_text);
    json_free(&info);
    if (!ok)
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "WALLET_FEE_UNKNOWN",
                 "getwalletinfo did not report a usable paytxfee",
                 "getwalletinfo");
    return ok;
}

static void wnh_emit_shielded_quote(struct zcl_command_reply *reply,
                                    CAmount amount_zats, CAmount fee_zats,
                                    CAmount total_zats)
{
    char total_text[32];
    (void)json_push_kv_int(&reply->data, "amount_zat", amount_zats);
    (void)json_push_kv_int(&reply->data, "fee_zat", fee_zats);
    (void)json_push_kv_int(&reply->data, "total_zat", total_zats);
    if (wnh_zat_text(total_zats, total_text))
        (void)json_push_kv_str(&reply->data, "total", total_text);
}

/* Echo the effective memo and idempotency key of a committed send. */
static void wnh_emit_shielded_echo(struct zcl_command_reply *reply,
                                   const char *memo, const char *memo_hex,
                                   const char *idem)
{
    (void)json_push_kv_bool(&reply->data, "memo_attached",
                            memo != NULL || memo_hex != NULL);
    if (memo_hex)
        (void)json_push_kv_str(&reply->data, "memo_hex", memo_hex);
    else if (memo)
        (void)json_push_kv_str(&reply->data, "memo", memo);
    if (idem && idem[0])
        (void)json_push_kv_str(&reply->data, "idempotency_key", idem);
}

/* Validated inputs of one core.wallet.shielded.send call: read and checked
 * once, then carried by both the plan and the commit stage. */
struct wnh_shielded_send_in {
    const char *wallet_scope;
    const char *from;
    const char *to;
    const char *idem;
    const char *memo;
    const char *memo_hex;
    const char *plan_token;
    CAmount amount_zats;
    CAmount fee_zats;      /* quoted at plan; carried by the commit input */
    bool has_fee;
    char amount[32];
};

/* Even-length hex of at most 1024 chars: the raw Sapling memo wire form. */
static bool wnh_memo_hex_shape_ok(const char *memo_hex)
{
    size_t hlen = strlen(memo_hex);
    bool hex_ok = (hlen % 2 == 0) && hlen <= 1024;
    for (size_t i = 0; hex_ok && i < hlen; i++)
        hex_ok = isxdigit((unsigned char)memo_hex[i]) != 0;
    return hex_ok;
}

/* Normalize and validate the memo pair; each output is NULL when absent. */
static bool wnh_shielded_memos_valid(struct zcl_command_reply *reply,
                                     const struct zcl_command_request *request,
                                     const char **memo_out,
                                     const char **memo_hex_out)
{
    /* Optional UTF-8 or raw Sapling memo. It also carries higher-level
     * bindings such as the store's ZCL23ORDER:<id> reconciliation key. */
    const char *memo = json_get_str(json_get(request->input, "memo"));
    const char *memo_hex = json_get_str(json_get(request->input, "memo_hex"));
    if (memo && !memo[0]) memo = NULL;
    if (memo_hex && !memo_hex[0]) memo_hex = NULL;
    if (memo_hex && !wnh_memo_hex_shape_ok(memo_hex)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_MEMO_HEX",
                 "memo_hex must be even-length hex, at most 1024 chars",
                 "memo_hex");
        return false;
    }
    if (memo && strlen(memo) > 512) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_MEMO",
                 "memo must be at most 512 bytes", "memo");
        return false;
    }
    *memo_out = memo;
    *memo_hex_out = memo_hex;
    return true;
}

/* The key is required: it is what makes a repeated request safe. */
static bool wnh_shielded_key_ok(struct zcl_command_reply *reply,
                                const char *idem)
{
    if (!idem || !idem[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_IDEMPOTENCY_KEY",
                 "idempotency_key is required: use one stable key per payment "
                 "request and repeat it unchanged when retrying that request",
                 "idempotency_key");
        return false;
    }
    if (!wallet_send_once_key_valid(idem)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_IDEMPOTENCY_KEY",
                 "idempotency_key must be 1 to 128 characters of letters, "
                 "digits, '.', '_', ':' or '-'",
                 "idempotency_key");
        return false;
    }
    return true;
}

/* The fee the plan quoted, when the caller supplies it (the commit does). */
static bool wnh_shielded_fee_input(struct zcl_command_reply *reply,
                                   const struct zcl_command_request *request,
                                   struct wnh_shielded_send_in *in)
{
    const struct json_value *fee = json_get(request->input, "fee_zat");
    in->has_fee = false;
    if (!fee)
        return true;
    if (fee->type != JSON_INT || json_get_int(fee) < 0 ||
        !MoneyRange(json_get_int(fee))) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_FEE",
                 "fee_zat must be the non-negative fee from the plan",
                 "fee_zat");
        return false;
    }
    in->fee_zats = json_get_int(fee);
    in->has_fee = true;
    return true;
}

/* Read and validate every shielded.send input field, in the order the
 * handler has always checked them. */
static bool wnh_shielded_send_inputs(struct zcl_command_reply *reply,
                                     const struct zcl_command_request *request,
                                     struct wnh_shielded_send_in *in)
{
    in->wallet_scope =
        json_get_str(json_get(request->input, "wallet_scope"));
    if (!wallet_money_scope_valid(in->wallet_scope)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_WALLET_SCOPE",
                 "wallet_scope must explicitly be dev, prod, or test",
                 "core.wallet.shielded.send");
        return false;
    }
    in->from = json_get_str(json_get(request->input, "from"));
    in->to = json_get_str(json_get(request->input, "to"));
    if (!in->from || !in->from[0] || !in->to || !in->to[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "both from and to are required", "core.wallet.shielded.send");
        return false;
    }
    in->amount_zats = 0;
    if (!wnh_amount_exact(json_get(request->input, "amount"),
                          &in->amount_zats, in->amount)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_AMOUNT",
                 "amount must be positive, in range, and exact to 8 decimals",
                 "amount");
        return false;
    }
    (void)in->amount_zats; /* exact range proof; the RPC consumes decimal text */
    in->idem = json_get_str(json_get(request->input, "idempotency_key"));
    if (!wnh_shielded_key_ok(reply, in->idem) ||
        !wnh_shielded_fee_input(reply, request, in))
        return false;
    in->plan_token = json_get_str(json_get(request->input, "plan_token"));
    return wnh_shielded_memos_valid(reply, request, &in->memo, &in->memo_hex);
}

/* One document binds every field executed by either stage. The plan token is
 * computed over the document without it; the commit input carries both. */
static bool wnh_shielded_commit_input(const struct wnh_shielded_send_in *in,
                                      char *commit, size_t commit_size,
                                      const char *token)
{
    struct json_value ci;
    json_init(&ci);
    json_set_object(&ci);
    (void)json_push_kv_str(&ci, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&ci, "from", in->from);
    (void)json_push_kv_str(&ci, "to", in->to);
    (void)json_push_kv_str(&ci, "amount", in->amount);
    (void)json_push_kv_int(&ci, "fee_zat", in->fee_zats);
    if (in->memo_hex)
        (void)json_push_kv_str(&ci, "memo_hex", in->memo_hex);
    else if (in->memo)
        (void)json_push_kv_str(&ci, "memo", in->memo);
    (void)json_push_kv_str(&ci, "idempotency_key", in->idem);
    (void)json_push_kv_bool(&ci, "confirm", true);
    if (token)
        (void)json_push_kv_str(&ci, "plan_token", token);
    bool encoded = wnh_commit_input(&ci, commit, commit_size);
    json_free(&ci);
    return encoded;
}

/* Non-mutating plan half: quote the fee the commit will pay, echo every
 * input, and emit the plan with its exact commit input. */
static void wnh_shielded_send_plan(struct zcl_command_reply *reply,
                                   const char *path,
                                   const struct wnh_shielded_send_in *in,
                                   const char *token, const char *commit)
{
    CAmount quote_fee = in->fee_zats;
    CAmount quote_total = in->amount_zats + quote_fee;
    if (!MoneyRange(quote_total)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_AMOUNT",
                 "amount plus the wallet fee exceeds the money range",
                 "amount");
        return;
    }
    (void)json_push_kv_str(&reply->data, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", in->from);
    (void)json_push_kv_str(&reply->data, "to", in->to);
    (void)json_push_kv_str(&reply->data, "amount", in->amount);
    wnh_emit_shielded_quote(reply, in->amount_zats, quote_fee, quote_total);
    wnh_emit_plan(reply, path, "shielded-send", token, commit);
}

/* Build [from,[{address,amount,memo?}]] through the encoder so input text
 * cannot rewrite the RPC params array. */
static char *wnh_shielded_send_params(const struct wnh_shielded_send_in *in)
{
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    rpc_arg_builder_push_str(&p, in->from);
    struct json_value recip, recip_arr;
    json_init(&recip);
    json_set_object(&recip);
    (void)json_push_kv_str(&recip, "address", in->to);
    (void)json_push_kv_str(&recip, "amount", in->amount);
    if (in->memo_hex)
        (void)json_push_kv_str(&recip, "memo_hex", in->memo_hex);
    else if (in->memo)
        (void)json_push_kv_str(&recip, "memo", in->memo);
    json_init(&recip_arr);
    json_set_array(&recip_arr);
    (void)json_push_back(&recip_arr, &recip);
    rpc_arg_builder_push_value(&p, &recip_arr);
    rpc_arg_builder_push_int(&p, 1);
    char fee_text[32];
    if (!wnh_zat_text(in->fee_zats, fee_text)) {
        json_free(&recip);
        json_free(&recip_arr);
        return NULL;
    }
    /* minconf, the quoted fee the node re-checks, and the idempotency key
     * the node records before it builds. */
    rpc_arg_builder_push_str(&p, fee_text);
    rpc_arg_builder_push_str(&p, in->idem);
    json_free(&recip);
    json_free(&recip_arr);
    return rpc_arg_builder_to_json(&p);
}

/* The txid goes in the reply only; the log line carries no wallet data. */
static void wnh_send_outcome_unknown(struct zcl_command_reply *reply,
                                     const struct json_value *body)
{
    const char *tx = json_get_str(json_get(body, "txid"));
    wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SEND_OUTCOME_UNKNOWN",
             "a send with this idempotency_key may have been made but is "
             "not confirmed; nothing was sent again. The transaction can "
             "still confirm until it expires, 20 blocks after it was "
             "made, and the wallet list may not show it. Do not pay again "
             "under a new key until the chain is more than 20 blocks past "
             "the send; then check the wallet transaction list",
             tx && tx[0] ? tx : "z_sendmany");
}

/* The node freed the key before it built anything: nothing was sent. A
 * spend-rule refusal can carry a shortfall, so its log line is fixed text. */
static void wnh_shielded_send_released(struct zcl_command_reply *reply,
                                       const struct json_value *body)
{
    char why[384];
    const char *node = json_get_str(json_get(body, "message"));
    (void)snprintf(why, sizeof(why),
                   "refused before any send was recorded; nothing was sent "
                   "and the idempotency_key is free to retry: %s",
                   node ? node : "no reason given");
    if (node && strncmp(node, WALLET_SPEND_REFUSAL_PREFIX,
                        strlen(WALLET_SPEND_REFUSAL_PREFIX)) == 0) {
        LOG_ERROR(WNH_TAG, "%s: refused by the spend rule",
                  WALLET_SEND_ONCE_CODE_RELEASED);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               WALLET_SEND_ONCE_CODE_RELEASED, "handle",
                               false, false, why, "z_sendmany");
    } else {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED,
                 WALLET_SEND_ONCE_CODE_RELEASED, why, "z_sendmany");
    }
}

/* Refuse a send whose node-side record says it must not run again. Returns
 * true when the body is a committed send to render. */
static bool wnh_shielded_send_state_ok(struct zcl_command_reply *reply,
                                       const struct json_value *body)
{
    const char *state = json_get_str(json_get(body, "state"));
    if (state && strcmp(state, "committed") == 0)
        return true;
    if (state && strcmp(state, WALLET_SEND_ONCE_STATE_RELEASED) == 0) {
        wnh_shielded_send_released(reply, body);
    } else if (state && strcmp(state, "in_progress") == 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_TRANSIENT, "SEND_IN_PROGRESS",
                 "a send with this idempotency_key is still running; repeat "
                 "the same request later to read its result", "z_sendmany");
    } else if (state && strcmp(state, WALLET_SEND_ONCE_STATE_FEE_CHANGED) == 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "FEE_CHANGED",
                 "the wallet fee changed since the plan; nothing was sent "
                 "and the idempotency_key is free to retry. Plan the send "
                 "again", "fee_zat");
    } else if (state && strcmp(state, "outcome_unknown") == 0) {
        wnh_send_outcome_unknown(reply, body);
    } else if (state && strcmp(state, "key_conflict") == 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "IDEMPOTENCY_KEY_REUSED",
                 "this idempotency_key was already used for a different "
                 "request; use a new key for a different payment",
                 "idempotency_key");
    } else {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_SEND_FAILED",
                 "z_sendmany did not return a transaction result",
                 "z_sendmany");
    }
    return false;
}

/* Render the committed reply from a keyed z_sendmany answer
 * {"state","txid","replayed"}. A replay reports the earlier transaction and
 * mutated=false: this call moved no funds. */
static bool wnh_shielded_send_committed(struct zcl_command_reply *reply,
                                        const struct json_value *body,
                                        const struct wnh_shielded_send_in *in,
                                        const char *token)
{
    const char *txid = json_get_str(json_get(body, "txid"));
    const char *bare = body && body->type == JSON_STR ? json_get_str(body) : NULL;
    /* A node that predates send-once ignores the key, sends, and returns the
     * bare txid: that is a sent transaction, never a failure. */
    if (bare && strlen(bare) == 64 && IsHex(bare)) {
        txid = bare;
    } else if (!wnh_shielded_send_state_ok(reply, body)) {
        return false; // raw-return-ok:state_ok logged the refusal
    }
    if (!txid || strlen(txid) != 64 || !IsHex(txid)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_SEND_FAILED",
                 "z_sendmany did not return a transaction result",
                 "z_sendmany");
        return false;
    }
    bool replayed = json_get_bool(json_get(body, "replayed"));
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "replayed", replayed);
    (void)json_push_kv_str(&reply->data, "txid", txid);
    (void)json_push_kv_str(&reply->data, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", in->from);
    (void)json_push_kv_str(&reply->data, "to", in->to);
    (void)json_push_kv_str(&reply->data, "amount", in->amount);
    (void)json_push_kv_int(&reply->data, "fee_zat", in->fee_zats);
    wnh_emit_shielded_echo(reply, in->memo, in->memo_hex, in->idem);
    (void)json_push_kv_str(&reply->data, "plan_token", token);
    reply->error.mutated = !replayed;
    return true;
}

/* The plan reads the wallet fee and carries it in the commit input. The
 * commit sends the planned fee to the node, which reads the send record first
 * and only then compares it with the wallet fee (answer fee_changed). */
static bool wnh_shielded_fee_bound(struct zcl_command_reply *reply,
                                   struct wnh_shielded_send_in *in,
                                   bool confirm)
{
    if (confirm) {
        if (in->has_fee)
            return true;
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PLAN_REQUIRED",
                 "commit with the commit_input from the plan; fee_zat is "
                 "missing", "fee_zat");
        return false;
    }
    CAmount current = 0;
    if (!wnh_shielded_fee_zat(reply, &current)) {
        LOG_WARN(WNH_TAG, "shielded send: wallet fee unavailable");
        return false;
    }
    in->fee_zats = current;
    in->has_fee = true;
    return true;
}

void zcl_native_handle_wallet_shielded_send(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct wnh_shielded_send_in in = { 0 };
    if (!wnh_shielded_send_inputs(reply, request, &in))
        return;
    bool confirm = json_get_bool_or(request->input, "confirm", false);
    if (!wnh_shielded_fee_bound(reply, &in, confirm))
        return;
    char commit[2048];
    if (!wnh_shielded_commit_input(&in, commit, sizeof(commit), NULL)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                 "exact shielded commit input exceeds its response budget",
                 "memo");
        return;
    }
    char token[17];
    wnh_plan_token(token, "shielded-send", commit, "");
    if (!confirm) {
    char signed_commit[2304];
        if (!wnh_shielded_commit_input(&in, signed_commit,
                                       sizeof(signed_commit), token)) {
            wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                     "exact shielded commit input exceeds its response budget",
                     "memo");
            return;
        }
        wnh_shielded_send_plan(reply, request->spec->path, &in, token,
                               signed_commit);
        return;
    }
    if (!in.plan_token || !in.plan_token[0]) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PLAN_REQUIRED",
                 "commit with the commit_input from the plan; plan_token is "
                 "missing", "plan_token");
        return;
    }
    if (strcmp(in.plan_token, token) != 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PLAN_TOKEN_MISMATCH",
                 "the request differs from the plan it names; nothing was "
                 "sent", "plan_token");
        return;
    }

    char *params = wnh_shielded_send_params(&in);
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
    (void)wnh_shielded_send_committed(reply, &body, &in, token);
    json_free(&body);
}

/* ── core.wallet.shielded.shield ─────────────────────────────────────────
 * Sweep one public address into the wallet's own newest shielded address
 * through z_shieldaddress. The caller names no destination and no amount:
 * the node resolves the address, takes every mature coin up to its cap and
 * pays total - fee, so a coinbase spend has no transparent output. The plan
 * token binds scope, source, destination, input count, total, fee and key. The
 * commit reads the sweep again and refuses PLAN_TOKEN_MISMATCH when any of them
 * moved; it then passes the count and total to the node, which checks them a
 * second time when it builds. */

/* The sweep as the node quotes it. */
struct wnh_shield_plan {
    char from[128];
    char to[192];
    int64_t inputs, coinbase, total, fee, amount, remaining, maturing;
};

static bool wnh_shield_read_plan(const struct json_value *body,
                                 struct wnh_shield_plan *pl)
{
    const char *from = json_get_str(json_get(body, "from"));
    const char *to = json_get_str(json_get(body, "to"));
    const struct { const char *key; int64_t *dst; } ints[] = {
        { "input_count", &pl->inputs },
        { "coinbase_input_count", &pl->coinbase },
        { "total_zat", &pl->total }, { "fee_zat", &pl->fee },
        { "amount_zat", &pl->amount },
        { "remaining_inputs", &pl->remaining },
        { "maturing_zat", &pl->maturing },
    };
    if (!from || !to || strlen(from) >= sizeof(pl->from) ||
        strlen(to) >= sizeof(pl->to))
        return false;
    (void)snprintf(pl->from, sizeof(pl->from), "%s", from);
    (void)snprintf(pl->to, sizeof(pl->to), "%s", to);
    for (size_t i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
        const struct json_value *v = json_get(body, ints[i].key);
        if (!v || v->type != JSON_INT)
            return false;
        *ints[i].dst = json_get_int(v);
    }
    return true;
}

static void wnh_shield_push_null(struct rpc_arg_builder *p)
{
    struct json_value nul;
    json_init(&nul);
    json_set_null(&nul);
    rpc_arg_builder_push_value(p, &nul);
    json_free(&nul);
}

/* The read-only sweep plan: z_shieldaddress with the source only. */
static bool wnh_shield_call_plan(struct zcl_command_reply *reply,
                                 const char *from, struct wnh_shield_plan *pl)
{
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    if (from && from[0])
        rpc_arg_builder_push_str(&p, from);
    else
        wnh_shield_push_null(&p);
    char *params = rpc_arg_builder_to_json(&p);
    struct json_value body;
    bool ok = params && wnh_call_rpc(reply, "z_shieldaddress", params, &body);
    free(params);
    if (!ok) {
        if (!params)
            wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                     "could not encode z_shieldaddress params",
                     "z_shieldaddress");
        return false;
    }
    const char *state = json_get_str(json_get(&body, "state"));
    const char *code = json_get_str(json_get(&body, "code"));
    const char *text = json_get_str(json_get(&body, "message"));
    if (state && strcmp(state, "refused") == 0)
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED,
                 code ? code : "SHIELD_REFUSED",
                 text ? text : "the sweep was refused", "z_shieldaddress");
    else if (!state || strcmp(state, "plan") != 0 ||
             !wnh_shield_read_plan(&body, pl))
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELD_PLAN_FAILED",
                 "z_shieldaddress did not return a plan", "z_shieldaddress");
    else {
        json_free(&body);
        return true;
    }
    json_free(&body);
    return false;
}

static void wnh_shield_token(char out[17],
                             const struct wnh_shielded_send_in *in,
                             const struct wnh_shield_plan *pl)
{
    char doc[768];
    (void)snprintf(doc, sizeof(doc), "%s|%s|%s|%lld|%lld|%lld|%s",
                   in->wallet_scope, pl->from, pl->to, (long long)pl->inputs,
                   (long long)pl->total, (long long)in->fee_zats, in->idem);
    wnh_plan_token(out, "shield-address", doc, "");
}

static bool wnh_shield_inputs(struct zcl_command_reply *reply,
                              const struct zcl_command_request *request,
                              struct wnh_shielded_send_in *in)
{
    in->wallet_scope = json_get_str(json_get(request->input, "wallet_scope"));
    if (!wallet_money_scope_valid(in->wallet_scope)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "INVALID_WALLET_SCOPE",
                 "wallet_scope must explicitly be dev, prod, or test",
                 "core.wallet.shielded.shield");
        return false;
    }
    in->from = json_get_str(json_get(request->input, "from"));
    if (in->from && !in->from[0])
        in->from = NULL;
    in->idem = json_get_str(json_get(request->input, "idempotency_key"));
    if (!wnh_shielded_key_ok(reply, in->idem) ||
        !wnh_shielded_fee_input(reply, request, in))
        return false;
    in->plan_token = json_get_str(json_get(request->input, "plan_token"));
    return true;
}

static void wnh_shield_plan_stage(struct zcl_command_reply *reply,
                                  const char *path,
                                  struct wnh_shielded_send_in *in)
{
    struct wnh_shield_plan pl;
    if (!wnh_shield_call_plan(reply, in->from, &pl))
        return;
    in->fee_zats = pl.fee;
    char token[17], commit[1024];
    wnh_shield_token(token, in, &pl);
    struct json_value ci;
    json_init(&ci);
    json_set_object(&ci);
    (void)json_push_kv_str(&ci, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&ci, "from", pl.from);
    (void)json_push_kv_int(&ci, "fee_zat", pl.fee);
    (void)json_push_kv_str(&ci, "idempotency_key", in->idem);
    (void)json_push_kv_bool(&ci, "confirm", true);
    (void)json_push_kv_str(&ci, "plan_token", token);
    bool encoded = wnh_commit_input(&ci, commit, sizeof(commit));
    json_free(&ci);
    if (!encoded) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "PLAN_TOO_LARGE",
                 "exact shield commit input exceeds its response budget",
                 "from");
        return;
    }
    (void)json_push_kv_str(&reply->data, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", pl.from);
    (void)json_push_kv_str(&reply->data, "to", pl.to);
    (void)json_push_kv_int(&reply->data, "input_count", pl.inputs);
    (void)json_push_kv_int(&reply->data, "coinbase_input_count", pl.coinbase);
    (void)json_push_kv_int(&reply->data, "total_zat", pl.total);
    (void)json_push_kv_int(&reply->data, "fee_zat", pl.fee);
    (void)json_push_kv_int(&reply->data, "amount_zat", pl.amount);
    (void)json_push_kv_int(&reply->data, "remaining_inputs", pl.remaining);
    (void)json_push_kv_int(&reply->data, "maturing_zat", pl.maturing);
    wnh_emit_plan(reply, path, "shield-address", token, commit);
}

/* [from, to, null, fee, key, input_count, total]: the node's own destination
 * and the coin set the plan named; the node checks both again. */
static char *wnh_shield_commit_params(const struct wnh_shielded_send_in *in,
                                      const struct wnh_shield_plan *pl)
{
    char fee_text[32];
    struct rpc_arg_builder p;
    rpc_arg_builder_init(&p);
    if (!wnh_zat_text(in->fee_zats, fee_text)) {
        rpc_arg_builder_free(&p);
        return NULL;
    }
    rpc_arg_builder_push_str(&p, pl->from);
    rpc_arg_builder_push_str(&p, pl->to);
    wnh_shield_push_null(&p);
    rpc_arg_builder_push_str(&p, fee_text);
    rpc_arg_builder_push_str(&p, in->idem);
    rpc_arg_builder_push_int(&p, pl->inputs);
    rpc_arg_builder_push_int(&p, pl->total);
    return rpc_arg_builder_to_json(&p);
}

/* A released answer whose text starts with one of the sweep codes is that
 * refusal; anything else follows the shared send-once states. */
static bool wnh_shield_state_ok(struct zcl_command_reply *reply,
                                const struct json_value *body)
{
    static const char *const codes[] = {
        WALLET_SHIELD_NOTHING, WALLET_SHIELD_NO_ADDRESS,
        WALLET_SHIELD_NO_PROVER, WALLET_SHIELD_CHANGED,
    };
    const char *state = json_get_str(json_get(body, "state"));
    const char *msg = json_get_str(json_get(body, "message"));
    bool released = state && strcmp(state, WALLET_SEND_ONCE_STATE_RELEASED) == 0;
    for (size_t i = 0; released && msg && i < sizeof(codes) / sizeof(codes[0]);
         i++) {
        size_t n = strlen(codes[i]);
        if (strncmp(msg, codes[i], n) != 0 || msg[n] != ':')
            continue;
        wnh_fail(reply,
                 i == 3 ? ZCL_COMMAND_EXIT_INVALID : ZCL_COMMAND_EXIT_FAILED,
                 codes[i], msg + n + 1 + (msg[n + 1] == ' '),
                 "z_shieldaddress");
        return false;
    }
    return wnh_shielded_send_state_ok(reply, body);
}

static void wnh_shield_committed(struct zcl_command_reply *reply,
                                 const struct json_value *body,
                                 const struct wnh_shielded_send_in *in,
                                 const struct wnh_shield_plan *pl)
{
    if (!wnh_shield_state_ok(reply, body))
        return;
    const char *txid = json_get_str(json_get(body, "txid"));
    if (!txid || strlen(txid) != 64 || !IsHex(txid)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SHIELDED_SEND_FAILED",
                 "z_shieldaddress did not return a transaction result",
                 "z_shieldaddress");
        return;
    }
    bool replayed = json_get_bool(json_get(body, "replayed"));
    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_bool(&reply->data, "replayed", replayed);
    (void)json_push_kv_str(&reply->data, "txid", txid);
    (void)json_push_kv_str(&reply->data, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", pl->from);
    (void)json_push_kv_str(&reply->data, "to", pl->to);
    (void)json_push_kv_int(&reply->data, "input_count", pl->inputs);
    (void)json_push_kv_int(&reply->data, "total_zat", pl->total);
    (void)json_push_kv_int(&reply->data, "fee_zat", in->fee_zats);
    (void)json_push_kv_int(&reply->data, "amount_zat", pl->total - in->fee_zats);
    (void)json_push_kv_str(&reply->data, "idempotency_key", in->idem);
    (void)json_push_kv_str(&reply->data, "plan_token", in->plan_token);
    reply->error.mutated = !replayed;
}

static void wnh_shield_commit_stage(struct zcl_command_reply *reply,
                                    const struct wnh_shielded_send_in *in)
{
    if (!in->plan_token || !in->plan_token[0] || !in->has_fee || !in->from) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PLAN_REQUIRED",
                 "commit with the commit_input from the plan", "plan_token");
        return;
    }
    struct wnh_shield_plan pl;
    char token[17];
    if (!wnh_shield_call_plan(reply, in->from, &pl))
        return;
    wnh_shield_token(token, in, &pl);
    if (strcmp(in->plan_token, token) != 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, WALLET_SHIELD_CHANGED,
                 "the public funds differ from the plan it names; nothing "
                 "was sent", "plan_token");
        return;
    }
    char *params = wnh_shield_commit_params(in, &pl);
    if (!params) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ARG_BUILD_FAILED",
                 "could not encode z_shieldaddress params", "z_shieldaddress");
        return;
    }
    struct json_value body;
    bool ok = wnh_call_rpc_deadline(reply, "z_shieldaddress", params,
                                    RPC_PROOF_BUILD_TIMEOUT_MS, &body);
    free(params);
    if (!ok)
        return;
    wnh_shield_committed(reply, &body, in, &pl);
    json_free(&body);
}

void zcl_native_handle_wallet_shielded_shield(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct wnh_shielded_send_in in = { 0 };
    if (!wnh_shield_inputs(reply, request, &in))
        return;
    if (json_get_bool_or(request->input, "confirm", false))
        wnh_shield_commit_stage(reply, &in);
    else
        wnh_shield_plan_stage(reply, request->spec->path, &in);
}

/* ── Tier-1 hot-swap: native.leaves generation entrypoint ──────
 * Dev-only (compiled only under -DZCL_HOTSWAP_GEN, a generation .so build;
 * expands to nothing in the node/release TU — see ZCL_HOTSWAP_EXPORT_LEAVES
 * in engine/modules/hotswap/include/hotswap/hotswap.h). Stages every native command
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

static const struct zcl_hotswap_leaf_replacement k_leaves[] = { /* hotswap-static-ok: leaf registration tables are immutable */    { "core.wallet.address.list",      tramp_listaddresses },
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
 * provider uses. See hotswap_module.h and hotswap_activate() (engine/modules/hotswap). */
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

static const struct zcl_hotswap_leaf k_module_leaves[] = { /* hotswap-static-ok: immutable leaf registration tables */    { "core.wallet.address.list",      module_tramp_listaddresses },
    { "core.wallet.utxo.list",         module_tramp_listunspent },
    { "core.wallet.transaction.list",  module_tramp_listtransactions },
    { "core.wallet.transaction.get",   module_tramp_gettransaction },
    { "core.wallet.shielded.balance",  module_tramp_z_getbalance },
    { "core.wallet.shielded.notes",    module_tramp_z_listunspent },
};

ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_listaddresses)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
