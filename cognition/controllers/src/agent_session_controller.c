/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `agentsession` RPC: the node's own surface onto the agent_sessions
 * store. See controllers/agent_session_controller.h for WHY this is an RPC
 * (short version: the policy gates run in the CLI process, which has no
 * node.db, and a second writer on a live node's database is not an option).
 *
 * Shape: params are [ "<action>", { ...fields } ]. Every action answers an
 * OBJECT with an `ok` boolean and, on refusal, a `why` token drawn from the
 * service/model vocabulary — the caller maps that token straight onto a named
 * error, so a refusal never loses its reason crossing the socket. Failures
 * return false with the message in `result`, which is the RPC convention the
 * rest of the controllers use. */

#include "controllers/agent_session_controller.h"

#include "controllers/native_handler_body.h"
#include "json/json.h"
#include "models/agent_session.h"
#include "controllers/strong_params.h"
#include "encoding/utilstrencodings.h"
#include "rpc/server.h"
#include "services/agent_session_service.h"
#include "services/wallet_money_service.h"
#include "config/runtime.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <stdlib.h>
#include <string.h>

#define AGS_TAG "agentsession"

static bool ags_fail(struct json_value *result, const char *msg)
{
    json_set_str(result, msg);
    LOG_FAIL(AGS_TAG, "%s", msg);
}

/* An object answer with ok=false and a machine token — a REFUSAL, not a
 * transport failure, so the RPC itself succeeded. Keeping these apart is what
 * lets the caller tell "the policy said no" from "the node is unreachable",
 * which are opposite actions for an operator. */
static bool ags_refuse(struct json_value *result, const char *why)
{
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", false);
    (void)json_push_kv_str(result, "why", why);
    return true;
}

static int64_t ags_int(const struct json_value *o, const char *key,
                       int64_t dflt)
{
    const struct json_value *v = json_get(o, key);
    if (!v)
        return dflt;
    if (v->type == JSON_INT)
        return json_get_int(v);
    if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (s && s[0]) {
            char *end = NULL;
            long long n = strtoll(s, &end, 10);
            if (end && !*end)
                return (int64_t)n;
        }
    }
    return dflt;
}

static const char *ags_str(const struct json_value *o, const char *key)
{
    const char *s = json_get_str(json_get(o, key));
    return (s && s[0]) ? s : NULL;
}

/* ── mint ──────────────────────────────────────────────────────────────── */

static bool ags_mint(const struct json_value *in, struct json_value *result)
{
    struct agent_session_mint_request req;
    memset(&req, 0, sizeof(req));
    const char *account = ags_str(in, "account");
    if (!account)
        return ags_refuse(result, "BAD_ARGS");
    (void)snprintf(req.account, sizeof(req.account), "%s", account);
    req.max_per_tx_zat = ags_int(in, "max_per_tx_zat", -1);
    req.max_per_window_zat = ags_int(in, "max_per_window_zat", -1);
    req.reserve_floor_zat = ags_int(
        in, "reserve_floor_zat", AGENT_SESSION_DEV_RESERVE_DEFAULT_ZAT);
    req.window_seconds = ags_int(in, "window_seconds", 0);
    req.expires_in_seconds = ags_int(in, "expires_in_seconds", 0);
    const char *allow = ags_str(in, "recipient_allowlist");
    if (allow)
        (void)snprintf(req.recipient_allowlist,
                       sizeof(req.recipient_allowlist), "%s", allow);
    const char *wallet_scope = ags_str(in, "wallet_scope");
    if (!wallet_scope)
        return ags_refuse(result, "BAD_ARGS");
    (void)snprintf(req.wallet_scope, sizeof(req.wallet_scope), "%s",
                   wallet_scope);

    char sid[AGENT_SESSION_ID_MAX + 1] = { 0 };
    char why[64] = { 0 };
    if (!agent_session_service_mint(&req, sid, why, sizeof(why)))
        return ags_refuse(result, why[0] ? why : "PERSIST_FAILED");

    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "session_id", sid);
    return true;
}

/* ── list ──────────────────────────────────────────────────────────────── */

static bool ags_list(const struct json_value *in, struct json_value *result)
{
    struct db_agent_session *rows =
        zcl_malloc(sizeof(*rows) * AGENT_SESSION_LIST_MAX,
                   "agentsession rpc rows");
    if (!rows)
        return ags_fail(result, "agentsession: allocation failed");
    int n = agent_session_service_list(ags_str(in, "account"), rows,
                                       AGENT_SESSION_LIST_MAX);
    if (n < 0) {
        free(rows);
        return ags_refuse(result, "DB_UNAVAILABLE");
    }

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        /* Redact the token here for the same reason the native leaf does
         * (tools/command/native_vault_session_command.c): session_id is a
         * BEARER grant — presenting it is the whole act that makes a spend
         * run under that grant's caps, so listing sessions must never hand
         * back a usable one. This surface used to return it in full while
         * the native leaf redacted, which made the redaction cosmetic: two
         * doors onto the same rows, one locked. The cookie holder is still
         * outside the grant model by design (docs/CUSTODY_MODEL.md), so this
         * closes an inconsistency rather than a hole — but a rule that holds
         * on only one of two surfaces is not a rule. */
        char redacted[24];
        agent_session_redact_id(rows[i].session_id, redacted,
                                sizeof(redacted));
        struct json_value o;
        json_init(&o);
        json_set_object(&o);
        (void)json_push_kv_str(&o, "session_id", redacted);
        (void)json_push_kv_bool(&o, "session_id_redacted", true);
        (void)json_push_kv_str(&o, "account", rows[i].account);
        (void)json_push_kv_int(&o, "max_per_tx_zat", rows[i].max_per_tx_zat);
        (void)json_push_kv_int(&o, "max_per_window_zat",
                               rows[i].max_per_window_zat);
        (void)json_push_kv_int(&o, "reserve_floor_zat",
                               rows[i].reserve_floor_zat);
        (void)json_push_kv_int(&o, "window_seconds", rows[i].window_seconds);
        (void)json_push_kv_int(&o, "window_start_epoch",
                               rows[i].window_start_epoch);
        (void)json_push_kv_int(&o, "spent_in_window_zat",
                               rows[i].spent_in_window_zat);
        (void)json_push_kv_str(&o, "recipient_allowlist",
                               rows[i].recipient_allowlist);
        (void)json_push_kv_int(&o, "created_at", rows[i].created_at);
        (void)json_push_kv_int(&o, "expires_at", rows[i].expires_at);
        (void)json_push_kv_int(&o, "revoked", rows[i].revoked);
        (void)json_push_kv_str(&o, "wallet_scope", rows[i].wallet_scope);
        (void)json_push_kv_str(&o, "wallet_instance_id",
                               rows[i].wallet_instance_id);
        (void)json_push_kv_str(&o, "wallet_genesis",
                               rows[i].wallet_genesis);
        (void)json_push_kv_bool(&o, "wallet_bound",
                                rows[i].wallet_instance_id[0] != '\0');
        (void)json_push_kv_int(&o, "lifetime_spent_zat",
                               rows[i].lifetime_spent_zat);
        (void)json_push_back(&arr, &o);
        json_free(&o);
    }
    free(rows);

    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv(result, "sessions", &arr);
    (void)json_push_kv_int(result, "session_count", n);
    json_free(&arr);
    return true;
}

/* ── revoke / authorize / release ──────────────────────────────────────── */

static bool ags_revoke(const struct json_value *in, struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    if (!sid)
        return ags_refuse(result, "BAD_ARGS");
    char why[64] = { 0 };
    if (!agent_session_service_revoke(sid, why, sizeof(why)))
        return ags_refuse(result, why[0] ? why : "PERSIST_FAILED");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "revoked", true);
    return true;
}

static bool ags_authorize(const struct json_value *in,
                          struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    if (!sid)
        return ags_refuse(result, "BAD_ARGS");
    int64_t amount_zat = ags_int(in, "amount_zat", -1);
    bool commit = json_get_bool_or(in, "commit", false);
    bool canonical_plan = json_get_bool_or(in, "canonical_plan", false);
    int64_t remaining = 0;
    int64_t charged = 0;
    enum agent_session_authz v = agent_session_service_authorize(
        sid, amount_zat, ags_str(in, "recipient"),
        ags_str(in, "wallet_scope"), commit, canonical_plan,
        &remaining, &charged);
    if (v != AGENT_SESSION_AUTHZ_OK)
        return ags_refuse(result, agent_session_authz_token(v));
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "committed", commit);
    (void)json_push_kv_int(result, "window_remaining_zat", remaining);
    (void)json_push_kv_int(result, "charged_zat", charged);
    return true;
}

static bool ags_release(const struct json_value *in, struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    if (!sid)
        return ags_refuse(result, "BAD_ARGS");
    if (!agent_session_service_release(sid, ags_int(in, "amount_zat", 0)))
        return ags_refuse(result, "POLICY_STORE");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "released", true);
    return true;
}

static bool ags_plan_id(const struct json_value *in, uint8_t out[32])
{
    const char *hex = ags_str(in, "plan_id");
    return hex && strlen(hex) == 64 && IsHex(hex) &&
        ParseHex(hex, out, 32) == 32;
}

static bool ags_intent_bind(const struct json_value *in,
                            struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    const char *recipient = ags_str(in, "recipient");
    uint8_t plan_id[32];
    if (!sid || !recipient || !ags_plan_id(in, plan_id))
        return ags_refuse(result, "BAD_ARGS");
    char why[64] = { 0 };
    if (!agent_session_service_bind_intent(
            sid, plan_id, recipient, why, sizeof(why)))
        return ags_refuse(result, why[0] ? why : "POLICY_STORE");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "bound", true);
    return true;
}

static bool ags_intent_authorize(const struct json_value *in,
                                 struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    uint8_t plan_id[32];
    if (!sid || !ags_plan_id(in, plan_id))
        return ags_refuse(result, "BAD_ARGS");
    bool debit_managed = false;
    int64_t charged_zat = 0;
    char why[64] = { 0 };
    if (!agent_session_service_authorize_intent(
            sid, plan_id, &debit_managed, &charged_zat,
            why, sizeof(why)))
        return ags_refuse(result, why[0] ? why : "POLICY_STORE");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "debit_managed", debit_managed);
    (void)json_push_kv_int(result, "charged_zat", charged_zat);
    return true;
}

static bool ags_intent_release(const struct json_value *in,
                               struct json_value *result)
{
    const char *sid = ags_str(in, "session_id");
    uint8_t plan_id[32];
    if (!sid || !ags_plan_id(in, plan_id))
        return ags_refuse(result, "BAD_ARGS");
    if (!agent_session_service_release_intent(sid, plan_id))
        return ags_refuse(result, "POLICY_STORE");
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_bool(result, "released_if_safe", true);
    return true;
}

/* Internal authenticated reader used by metaverse.agent.money. It returns no
 * address, endpoint, datadir, token, or key material. */
static bool ags_custody(const struct json_value *in, struct json_value *result)
{
    const char *scope = ags_str(in, "wallet_scope");
    struct wallet_money_snapshot snapshot;
    struct zcl_result r = wallet_money_snapshot_build(
        app_runtime_node_db(), app_runtime_main_state(), scope, &snapshot);
    if (!r.ok)
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    struct json_value body;
    json_init(&body);
    if (!wallet_money_snapshot_to_json(&snapshot, &body).ok) {
        json_free(&body);
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    }
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv(result, "snapshot", &body);
    json_free(&body);
    return true;
}

/* Same aggregate-only custody answer, with the scope derived from the
 * wallet's persisted identity.  This is the status/front-door route: a
 * caller must never probe dev/prod/test in turn to find the wallet it hit. */
static bool ags_custody_current(struct json_value *result)
{
    struct wallet_money_snapshot snapshot;
    struct zcl_result r = wallet_money_snapshot_build_current(
        app_runtime_node_db(), app_runtime_main_state(), &snapshot);
    if (!r.ok)
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    struct json_value body;
    json_init(&body);
    if (!wallet_money_snapshot_to_json(&snapshot, &body).ok) {
        json_free(&body);
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    }
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv(result, "snapshot", &body);
    json_free(&body);
    return true;
}

/* Read-only execution-readiness planner. It sees exactly the confirmed,
 * reservation-filtered, non-ZSLP coin inventory used by wallet builders, but
 * returns only aggregate counts and amounts. No address or outpoint crosses
 * this internal RPC boundary. */
static bool ags_liquidity(const struct json_value *in,
                          struct json_value *result)
{
    const char *scope = ags_str(in, "wallet_scope");
    int64_t recipient_value_zat = ags_int(in, "recipient_value_zat", -1);
    int64_t maximum_fee_zat = ags_int(in, "maximum_fee_zat", -1);
    int64_t concurrency = ags_int(in, "concurrency", -1);
    if (!scope || recipient_value_zat <= 0 || maximum_fee_zat < 0 ||
        concurrency < 1 || concurrency > 50)
        return ags_refuse(result, "BAD_ARGS");

    struct wallet_money_snapshot money;
    struct zcl_result mr = wallet_money_snapshot_build(
        app_runtime_node_db(), app_runtime_main_state(), scope, &money);
    if (!mr.ok)
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    struct json_value money_json;
    json_init(&money_json);
    if (!wallet_money_snapshot_to_json(&money, &money_json).ok) {
        json_free(&money_json);
        return ags_refuse(result, "CUSTODY_UNAVAILABLE");
    }

    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "schema", "zcl.wallet_liquidity.v1");
    const char *identity = json_get_str(json_get(&money_json,
                                                 "wallet_instance_id"));
    const char *genesis = json_get_str(json_get(&money_json,
                                                "network_genesis"));
    const char *snapshot_root = json_get_str(json_get(&money_json,
                                                      "snapshot_root"));
    (void)json_push_kv_str(result, "wallet_scope", scope);
    (void)json_push_kv_str(result, "wallet_instance_id",
                           identity ? identity : "");
    (void)json_push_kv_str(result, "network_genesis",
                           genesis ? genesis : "");
    (void)json_push_kv_str(result, "money_status", money.status);
    (void)json_push_kv_str(result, "money_reason", money.reason);
    (void)json_push_kv_str(result, "money_snapshot_root",
                           snapshot_root ? snapshot_root : "");
    (void)json_push_kv_int(result, "observed_at", money.observed_at);
    if (!money.complete || strcmp(money.status, "CURRENT") != 0) {
        (void)json_push_kv_str(result, "status", money.status);
        (void)json_push_kv_bool(result, "ready_now", false);
        (void)json_push_kv_bool(result, "fanout_recommended", false);
        (void)json_push_kv_bool(result, "amounts_known", false);
        json_free(&money_json);
        return true;
    }

    struct wallet *wallet = app_runtime_wallet();
    if (!wallet) {
        json_free(&money_json);
        return ags_refuse(result, "WALLET_UNAVAILABLE");
    }
    enum { LIQUIDITY_COIN_CAP = 4096 };
    struct coin_entry *coins = zcl_calloc(
        LIQUIDITY_COIN_CAP, sizeof(*coins), "agent_liquidity_coins");
    if (!coins) {
        json_free(&money_json);
        return ags_refuse(result, "ALLOCATION_FAILED");
    }
    size_t coin_count = 0;
    wallet_available_coins(wallet, coins, &coin_count, LIQUIDITY_COIN_CAP,
                           true, false);
    int64_t fanout_fee_zat = wallet_default_fee(wallet);
    struct wallet_liquidity_plan plan;
    bool planned = fanout_fee_zat >= 0 && wallet_liquidity_plan_compute(
        coins, coin_count, money.agent_available_zat, recipient_value_zat,
        maximum_fee_zat, fanout_fee_zat, (int)concurrency, &plan);
    free(coins);
    if (!planned) {
        json_free(&money_json);
        return ags_refuse(result, "LIQUIDITY_PLAN_FAILED");
    }

    (void)json_push_kv_bool(result, "amounts_known", true);
    (void)json_push_kv_str(result, "status", plan.status);
    (void)json_push_kv_str(result, "reason", plan.reason);
    (void)json_push_kv_int(result, "requested_concurrency",
                           plan.requested_concurrency);
    (void)json_push_kv_int(result, "current_independent_slots",
                           plan.current_independent_slots);
    (void)json_push_kv_int(result, "current_inputs_used",
                           plan.current_inputs_used);
    (void)json_push_kv_int(result, "recipient_value_zat",
                           plan.recipient_value_zat);
    (void)json_push_kv_int(result, "maximum_fee_zat",
                           plan.maximum_fee_zat);
    (void)json_push_kv_int(result, "required_per_slot_zat",
                           plan.required_per_slot_zat);
    (void)json_push_kv_int(result, "future_total_required_zat",
                           plan.future_total_required_zat);
    (void)json_push_kv_int(result, "transparent_available_zat",
                           plan.transparent_available_zat);
    (void)json_push_kv_int(result, "agent_available_zat",
                           plan.agent_available_zat);
    (void)json_push_kv_bool(result, "ready_now", plan.ready_now);
    (void)json_push_kv_bool(result, "fanout_recommended",
                            plan.fanout_recommended);
    (void)json_push_kv_bool(result, "fanout_possible",
                            plan.fanout_possible);

    struct json_value fanout;
    json_init(&fanout);
    json_set_object(&fanout);
    (void)json_push_kv_bool(&fanout, "automatic", false);
    (void)json_push_kv_int(&fanout, "output_count",
                           plan.recommended_fanout_outputs);
    (void)json_push_kv_int(&fanout, "output_value_zat",
                           plan.fanout_output_value_zat);
    (void)json_push_kv_int(&fanout, "outputs_total_zat",
                           plan.fanout_outputs_total_zat);
    (void)json_push_kv_int(&fanout, "maximum_fee_zat",
                           plan.fanout_maximum_fee_zat);
    (void)json_push_kv_int(&fanout, "maximum_slots_under_policy",
                           plan.maximum_fanout_slots);
    (void)json_push_kv_str(&fanout, "prepare_command",
                           "vault.intent.fanout-plan");
    (void)json_push_kv_str(&fanout, "plan_command",
                           "vault.intent.fanout-plan");
    (void)json_push_kv_str(&fanout, "commit_command",
                           "vault.intent.commit");
    (void)json_push_kv_str(&fanout, "route", "transparent");
    (void)json_push_kv_bool(&fanout, "owner_commit_required", true);
    (void)json_push_kv(result, "fanout", &fanout);
    json_free(&fanout);
    (void)json_push_kv_bool(result, "advisory", true);
    (void)json_push_kv_str(result, "next_command",
        plan.ready_now ? "app.transaction-types.guide" :
        plan.fanout_recommended ? "vault.intent.fanout-plan" :
        strcmp(plan.status, "NEEDS_TRANSPARENT_LIQUIDITY") == 0
            ? "app.transaction-types.guide" : "metaverse.agent.money");
    json_free(&money_json);
    return true;
}

/* ── dispatch ──────────────────────────────────────────────────────────── */

static bool rpc_agentsession(const struct json_value *params, bool help,
                             struct json_value *result)
{
    RPC_HELP(help, result,
        "agentsession \"<action>\" { ...fields }\n"
        "\nThe node-side surface onto the agent_sessions store — scoped,\n"
        "revocable agent spend grants. Actions:\n"
        "  mint      {account, max_per_tx_zat, max_per_window_zat, reserve_floor_zat,\n"
        "             window_seconds, recipient_allowlist, expires_in_seconds,\n"
        "             wallet_scope}\n"
        "            -> {ok, session_id}  (the ONE time the token is returned)\n"
        "  list      {account?} -> {ok, sessions[], session_count}\n"
        "  revoke    {session_id} -> {ok, revoked}\n"
        "  authorize {session_id, amount_zat, recipient?, wallet_scope, commit}\n"
        "            -> {ok, committed, window_remaining_zat}; the check AND\n"
        "               the window debit in one indivisible step\n"
        "  release   {session_id, amount_zat} -> {ok, released}; credit back a\n"
        "               debit whose spend never happened\n"
        "  intent_bind {session_id, plan_id, recipient} -> {ok, bound}\n"
        "  intent_authorize {session_id, plan_id} -> {ok, debit_managed,\n"
        "               charged_zat}; exact once-only canonical commit debit\n"
        "  intent_release {session_id, plan_id} -> {ok}; releases only before\n"
        "               durable proving bytes or network acceptance exist\n"
        "  custody   {wallet_scope} -> {ok, snapshot}; identity-bound money\n"
        "               state with no endpoint/path/address/key fields\n"
        "  custody_current {} -> {ok, snapshot}; same aggregate, with scope\n"
        "               derived from the persisted wallet operator lane\n"
        "  liquidity {wallet_scope, recipient_value_zat, maximum_fee_zat,\n"
        "             concurrency} -> {ok, status, fanout}; aggregate-only\n"
        "               parallel-spend readiness with no automatic transfer\n"
        "\nA refusal answers {ok:false, why:\"<TOKEN>\"} — a successful RPC\n"
        "carrying a policy decision. Only a transport/usage error fails.");

    const char *action = json_get_str(json_at(params, 0));
    const struct json_value *in = json_at(params, 1);
    if (!action || !action[0])
        return ags_fail(result, "agentsession: action is required");
    if (in && in->type != JSON_OBJ)
        return ags_fail(result, "agentsession: second param must be an object");

    if (strcmp(action, "mint") == 0)
        return ags_mint(in, result);
    if (strcmp(action, "list") == 0)
        return ags_list(in, result);
    if (strcmp(action, "revoke") == 0)
        return ags_revoke(in, result);
    if (strcmp(action, "authorize") == 0)
        return ags_authorize(in, result);
    if (strcmp(action, "release") == 0)
        return ags_release(in, result);
    if (strcmp(action, "intent_bind") == 0)
        return ags_intent_bind(in, result);
    if (strcmp(action, "intent_authorize") == 0)
        return ags_intent_authorize(in, result);
    if (strcmp(action, "intent_release") == 0)
        return ags_intent_release(in, result);
    if (strcmp(action, "custody") == 0)
        return ags_custody(in, result);
    if (strcmp(action, "custody_current") == 0)
        return ags_custody_current(result);
    if (strcmp(action, "liquidity") == 0)
        return ags_liquidity(in, result);
    return ags_fail(result, "agentsession: unknown action");
}

void register_agent_session_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmd = { "wallet", "agentsession", rpc_agentsession,
                               false };
    rpc_table_must_append(t, &cmd);
}
