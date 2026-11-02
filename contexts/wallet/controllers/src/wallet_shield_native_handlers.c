/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core.wallet.shielded.shield: the plan and commit stages of the public
 * address sweep. Split from wallet_native_handlers.c, which holds the other
 * mutating wallet leaves; the shared helpers are published in
 * controllers/wallet_native_handlers.h. */

#include "controllers/wallet_native_handlers.h"
#include "controllers/wallet_shield_address.h"
#include "controllers/wallet_send_once.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "core/amount.h"
#include "encoding/utilstrencodings.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "rpc/rpc_timeout.h"
#include "services/wallet_money_service.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── core.wallet.shielded.shield ─────────────────────────────────────────
 * Sweep one public address into the wallet's own newest shielded address
 * through z_shieldaddress. The caller names no destination and no amount:
 * the node resolves the address, takes every mature coin up to its cap and
 * pays total - fee, so a coinbase spend has no transparent output. The plan
 * token binds scope, source, destination, input count, total, fee and key. The
 * commit input carries the destination, count and total the plan quoted; the
 * leaf checks them against the token and passes them to the node. The node
 * alone compares them with the coins it holds and refuses PLAN_TOKEN_MISMATCH
 * when they moved, after the send-once layer has answered a repeated key. A
 * retry of a finished sweep therefore replays its result, though its coins are
 * already spent. A destination that is not the node's own is refused there.
 *
 * A fresh commit echoes the sweep the node just verified against its coins. A
 * replay echoes nothing derived from the caller's input: the node never
 * compared the quoted count and total with anything, so only the txid, the
 * replayed flag and the idempotency key (the lookup key) are reported. */

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
    (void)json_push_kv_str(&ci, "to", pl.to);
    (void)json_push_kv_int(&ci, "input_count", pl.inputs);
    (void)json_push_kv_int(&ci, "total_zat", pl.total);
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
    if (replayed) {
        (void)json_push_kv_str(&reply->data, "idempotency_key", in->idem);
        reply->error.mutated = false;
        return;
    }
    (void)json_push_kv_str(&reply->data, "wallet_scope", in->wallet_scope);
    (void)json_push_kv_str(&reply->data, "from", pl->from);
    (void)json_push_kv_str(&reply->data, "to", pl->to);
    (void)json_push_kv_int(&reply->data, "input_count", pl->inputs);
    (void)json_push_kv_int(&reply->data, "total_zat", pl->total);
    (void)json_push_kv_int(&reply->data, "fee_zat", in->fee_zats);
    (void)json_push_kv_int(&reply->data, "amount_zat", pl->total - in->fee_zats);
    (void)json_push_kv_str(&reply->data, "idempotency_key", in->idem);
    (void)json_push_kv_str(&reply->data, "plan_token", in->plan_token);
    reply->error.mutated = true;
}

/* The sweep the plan quoted, read back from its commit input. */
static bool wnh_shield_quoted(const struct zcl_command_request *request,
                              const struct wnh_shielded_send_in *in,
                              struct wnh_shield_plan *pl)
{
    const char *to = json_get_str(json_get(request->input, "to"));
    const struct json_value *n = json_get(request->input, "input_count");
    const struct json_value *t = json_get(request->input, "total_zat");
    if (!to || !to[0] || strlen(to) >= sizeof(pl->to) || !n ||
        n->type != JSON_INT || !t || t->type != JSON_INT)
        return false;
    memset(pl, 0, sizeof(*pl));
    (void)snprintf(pl->from, sizeof(pl->from), "%s", in->from);
    (void)snprintf(pl->to, sizeof(pl->to), "%s", to);
    pl->inputs = json_get_int(n);
    pl->total = json_get_int(t);
    pl->fee = in->fee_zats;
    return true;
}

static void wnh_shield_commit_stage(struct zcl_command_reply *reply,
                                    const struct zcl_command_request *request,
                                    const struct wnh_shielded_send_in *in)
{
    struct wnh_shield_plan pl;
    if (!in->plan_token || !in->plan_token[0] || !in->has_fee || !in->from ||
        !wnh_shield_quoted(request, in, &pl)) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PLAN_REQUIRED",
                 "commit with the commit_input from the plan", "plan_token");
        return;
    }
    char token[17];
    wnh_shield_token(token, in, &pl);
    if (strcmp(in->plan_token, token) != 0) {
        wnh_fail(reply, ZCL_COMMAND_EXIT_INVALID, WALLET_SHIELD_CHANGED,
                 "the commit input does not match its plan token; nothing "
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
        wnh_shield_commit_stage(reply, request, &in);
    else
        wnh_shield_plan_stage(reply, request->spec->path, &in);
}
