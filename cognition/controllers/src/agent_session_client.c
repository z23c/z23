/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See controllers/agent_session_client.h for the contract and for why the
 * store is reached over RPC rather than opened directly.
 *
 * One shape note: every helper below funnels through asc_call(), which owns
 * the whole failure vocabulary. A transport failure and a policy refusal are
 * DIFFERENT tokens (NODE_UNREACHABLE vs POLICY_*) because they call for
 * opposite operator actions, and neither is ever silently an allow. */

#include "controllers/agent_session_client.h"

#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASC_TAG "agent_session_client"

static void asc_why(char *why, size_t why_cap, const char *token)
{
    if (why && why_cap > 0)
        (void)snprintf(why, why_cap, "%s", token);
}

/* Call `agentsession <action> <params_obj_json>` and, on success, hand the
 * parsed answer object back in *out (caller json_free's it).
 *
 * Fail-closed contract: false means "no decision was obtained", never
 * "allowed". A node that is down, a body that will not parse, and an answer
 * whose `ok` is false are all false here — the last one carrying the node's
 * own `why` token so the caller can render the real reason. */
static bool asc_call(const char *action, const char *params_obj,
                     struct json_value *out, char *why, size_t why_cap)
{
    char params[1536];
    int n = snprintf(params, sizeof(params), "[\"%s\",%s]", action,
                     params_obj ? params_obj : "{}");
    if (n < 0 || (size_t)n >= sizeof(params)) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "%s: request params too large (%d bytes)", action, n);
    }

    char *raw = node_rpc_call("agentsession", params);
    if (!raw) {
        asc_why(why, why_cap, "NODE_UNREACHABLE");
        LOG_FAIL(ASC_TAG, "%s: node_rpc_call returned null", action);
    }
    struct json_value v;
    if (!json_read(&v, raw, strlen(raw))) {
        json_free(&v);
        free(raw);
        asc_why(why, why_cap, "NODE_UNREACHABLE");
        LOG_FAIL(ASC_TAG, "%s: unparseable answer from the node", action);
    }
    free(raw);

    if (v.type != JSON_OBJ) {
        json_free(&v);
        asc_why(why, why_cap, "NODE_UNREACHABLE");
        LOG_FAIL(ASC_TAG, "%s: answer is not an object", action);
    }
    /* An RPC-level error body means the method did not run — an older node
     * without `agentsession`, a wrong datadir, a 401, a transport timeout.
     * That is unreachable, not a refusal. node_rpc_call renders the node's own
     * error object bare ({"code":..,"message":..}) but its locally-generated
     * transport/cookie errors wrapped ({"error":{...}}), so both shapes are
     * recognized here rather than trusting one of them. */
    const struct json_value *errobj = json_get(&v, "error");
    if (!json_get(&v, "ok") &&
        (json_get(&v, "message") || (errobj && errobj->type == JSON_OBJ))) {
        const char *m = json_get_str(json_get(&v, "message"));
        if (!m && errobj)
            m = json_get_str(json_get(errobj, "message"));
        asc_why(why, why_cap, "NODE_UNREACHABLE");
        LOG_ERROR(ASC_TAG, "%s: node refused the call: %s", action,
                  m ? m : "(no message)");
        json_free(&v);
        return false;
    }
    if (!json_get_bool_or(&v, "ok", false)) {
        const char *token = json_get_str(json_get(&v, "why"));
        asc_why(why, why_cap, (token && token[0]) ? token : "POLICY_STORE");
        json_free(&v);
        /* Not LOG_FAIL: the caller logs the refusal with its own context
         * (which leaf, which redacted grant), and a double entry per refused
         * spend just makes the log harder to read. */
        return false;
    }
    *out = v;
    return true;
}

bool agent_session_client_mint(const char *account, int64_t max_per_tx_zat,
                               int64_t max_per_window_zat,
                               int64_t reserve_floor_zat,
                               int64_t window_seconds,
                               const char *recipient_allowlist,
                               int64_t expires_in_seconds,
                               const char *wallet_scope,
                               char out_session_id[AGENT_SESSION_ID_MAX + 1],
                               char *why, size_t why_cap)
{
    if (!account || !account[0] || !wallet_scope || !wallet_scope[0] ||
        !out_session_id) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "mint: bad args");
    }
    /* The allowlist is operator-supplied text landing in a JSON string, so it
     * is escaped through the writer rather than pasted in. */
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    (void)json_push_kv_str(&req, "account", account);
    (void)json_push_kv_int(&req, "max_per_tx_zat", max_per_tx_zat);
    (void)json_push_kv_int(&req, "max_per_window_zat", max_per_window_zat);
    (void)json_push_kv_int(&req, "reserve_floor_zat", reserve_floor_zat);
    (void)json_push_kv_int(&req, "window_seconds", window_seconds);
    (void)json_push_kv_int(&req, "expires_in_seconds", expires_in_seconds);
    (void)json_push_kv_str(&req, "recipient_allowlist",
                           recipient_allowlist ? recipient_allowlist : "");
    (void)json_push_kv_str(&req, "wallet_scope", wallet_scope);
    char body[1280];
    size_t bn = json_write(&req, body, sizeof(body));
    json_free(&req);
    if (bn == 0 || bn >= sizeof(body)) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "mint: request body too large (%zu bytes)", bn);
    }

    struct json_value ans;
    json_init(&ans);
    if (!asc_call("mint", body, &ans, why, why_cap))
        return false; /* raw-return-ok:asc_call already wrote why and logged */
    const char *sid = json_get_str(json_get(&ans, "session_id"));
    bool ok = sid && strlen(sid) == AGENT_SESSION_ID_MAX;
    if (ok)
        (void)snprintf(out_session_id, AGENT_SESSION_ID_MAX + 1, "%s", sid);
    json_free(&ans);
    if (!ok) {
        asc_why(why, why_cap, "PERSIST_FAILED");
        LOG_FAIL(ASC_TAG, "mint: the node returned no usable session id");
    }
    return true;
}

int agent_session_client_list(const char *account,
                              struct db_agent_session *out, size_t max,
                              char *why, size_t why_cap)
{
    if (!out || max == 0) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_ERR(ASC_TAG, "list: bad args");
    }
    char body[256];
    if (account && account[0]) {
        struct json_value req;
        json_init(&req);
        json_set_object(&req);
        (void)json_push_kv_str(&req, "account", account);
        size_t bn = json_write(&req, body, sizeof(body));
        json_free(&req);
        if (bn == 0 || bn >= sizeof(body)) {
            asc_why(why, why_cap, "BAD_ARGS");
            LOG_ERR(ASC_TAG, "list: account too long");
        }
    } else {
        (void)snprintf(body, sizeof(body), "{}");
    }

    struct json_value ans;
    json_init(&ans);
    if (!asc_call("list", body, &ans, why, why_cap))
        return -1; /* raw-return-ok:asc_call already wrote why and logged */

    const struct json_value *arr = json_get(&ans, "sessions");
    size_t used = 0;
    if (arr && arr->type == JSON_ARR) {
        for (size_t i = 0; i < arr->num_children && used < max; i++) {
            const struct json_value *o = json_at(arr, i);
            if (!o || o->type != JSON_OBJ)
                continue;
            struct db_agent_session *r = &out[used];
            memset(r, 0, sizeof(*r));
            const char *sid = json_get_str(json_get(o, "session_id"));
            const char *acct = json_get_str(json_get(o, "account"));
            const char *allow = json_get_str(json_get(o, "recipient_allowlist"));
            const char *scope = json_get_str(json_get(o, "wallet_scope"));
            const char *wid = json_get_str(json_get(o, "wallet_instance_id"));
            const char *genesis = json_get_str(json_get(o, "wallet_genesis"));
            (void)snprintf(r->session_id, sizeof(r->session_id), "%s",
                           sid ? sid : "");
            (void)snprintf(r->account, sizeof(r->account), "%s",
                           acct ? acct : "");
            (void)snprintf(r->recipient_allowlist,
                           sizeof(r->recipient_allowlist), "%s",
                           allow ? allow : "");
            (void)snprintf(r->wallet_scope, sizeof(r->wallet_scope), "%s",
                           scope ? scope : "");
            (void)snprintf(r->wallet_instance_id,
                           sizeof(r->wallet_instance_id), "%s", wid ? wid : "");
            (void)snprintf(r->wallet_genesis, sizeof(r->wallet_genesis), "%s",
                           genesis ? genesis : "");
            r->max_per_tx_zat = json_get_int(json_get(o, "max_per_tx_zat"));
            r->max_per_window_zat =
                json_get_int(json_get(o, "max_per_window_zat"));
            r->reserve_floor_zat =
                json_get_int(json_get(o, "reserve_floor_zat"));
            r->window_seconds = json_get_int(json_get(o, "window_seconds"));
            r->window_start_epoch =
                json_get_int(json_get(o, "window_start_epoch"));
            r->spent_in_window_zat =
                json_get_int(json_get(o, "spent_in_window_zat"));
            r->created_at = json_get_int(json_get(o, "created_at"));
            r->expires_at = json_get_int(json_get(o, "expires_at"));
            r->revoked = (int)json_get_int(json_get(o, "revoked"));
            r->lifetime_spent_zat =
                json_get_int(json_get(o, "lifetime_spent_zat"));
            used++;
        }
    }
    json_free(&ans);
    return (int)used;
}

bool agent_session_client_revoke(const char *session_id, char *why,
                                 size_t why_cap)
{
    if (!session_id || !session_id[0]) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "revoke: bad args");
    }
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    (void)json_push_kv_str(&req, "session_id", session_id);
    char body[256];
    size_t bn = json_write(&req, body, sizeof(body));
    json_free(&req);
    if (bn == 0 || bn >= sizeof(body)) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "revoke: session id too long");
    }
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("revoke", body, &ans, why, why_cap))
        return false; /* raw-return-ok:asc_call already wrote why and logged */
    json_free(&ans);
    return true;
}

bool agent_session_client_authorize(const char *session_id, int64_t amount_zat,
                                    const char *recipient,
                                    const char *wallet_scope, bool commit,
                                    bool canonical_plan,
                                    int64_t *window_remaining_zat,
                                    int64_t *charged_zat,
                                    char *why, size_t why_cap)
{
    if (window_remaining_zat)
        *window_remaining_zat = 0;
    if (charged_zat)
        *charged_zat = 0;
    if (!session_id || !session_id[0] || !wallet_scope ||
        !wallet_scope[0] || amount_zat < 0) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "authorize: bad args");
    }
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    (void)json_push_kv_str(&req, "session_id", session_id);
    (void)json_push_kv_int(&req, "amount_zat", amount_zat);
    (void)json_push_kv_bool(&req, "commit", commit);
    (void)json_push_kv_bool(&req, "canonical_plan", canonical_plan);
    (void)json_push_kv_str(&req, "wallet_scope", wallet_scope);
    if (recipient && recipient[0])
        (void)json_push_kv_str(&req, "recipient", recipient);
    char body[1280];
    size_t bn = json_write(&req, body, sizeof(body));
    json_free(&req);
    if (bn == 0 || bn >= sizeof(body)) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "authorize: request body too large (%zu bytes)", bn);
    }
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("authorize", body, &ans, why, why_cap))
        return false; /* raw-return-ok:asc_call already wrote why and logged */
    if (window_remaining_zat)
        *window_remaining_zat =
            json_get_int(json_get(&ans, "window_remaining_zat"));
    if (charged_zat)
        *charged_zat = json_get_int(json_get(&ans, "charged_zat"));
    json_free(&ans);
    return true;
}

bool agent_session_client_release(const char *session_id, int64_t amount_zat)
{
    if (!session_id || !session_id[0] || amount_zat <= 0)
        return false; /* raw-return-ok:nothing-to-credit-back-is-not-an-error */
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    (void)json_push_kv_str(&req, "session_id", session_id);
    (void)json_push_kv_int(&req, "amount_zat", amount_zat);
    char body[256];
    size_t bn = json_write(&req, body, sizeof(body));
    json_free(&req);
    if (bn == 0 || bn >= sizeof(body))
        LOG_FAIL(ASC_TAG, "release: request body too large (%zu bytes)", bn);
    char why[64] = { 0 };
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("release", body, &ans, why, sizeof(why)))
        LOG_FAIL(ASC_TAG, "release: %lld zat could not be credited back to "
                          "the session window (%s) — the window stays debited",
                 (long long)amount_zat, why);
    json_free(&ans);
    return true;
}

static bool asc_intent_body(const char *session_id, const char *plan_id,
                            const char *recipient, char *body, size_t body_cap)
{
    if (!session_id || !session_id[0] || !plan_id || strlen(plan_id) != 64 ||
        !body || body_cap == 0)
        return false;
    struct json_value req;
    json_init(&req);
    json_set_object(&req);
    (void)json_push_kv_str(&req, "session_id", session_id);
    (void)json_push_kv_str(&req, "plan_id", plan_id);
    if (recipient && recipient[0])
        (void)json_push_kv_str(&req, "recipient", recipient);
    size_t n = json_write(&req, body, body_cap);
    json_free(&req);
    return n > 0 && n < body_cap;
}

bool agent_session_client_bind_intent(
    const char *session_id, const char *plan_id, const char *recipient,
    char *why, size_t why_cap)
{
    char body[512];
    if (!recipient || !recipient[0] ||
        !asc_intent_body(session_id, plan_id, recipient,
                         body, sizeof(body))) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "intent bind: bad args");
    }
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("intent_bind", body, &ans, why, why_cap))
        return false; /* raw-return-ok:typed refusal already returned */
    json_free(&ans);
    return true;
}

bool agent_session_client_authorize_intent(
    const char *session_id, const char *plan_id,
    bool *debit_managed, int64_t *charged_zat,
    char *why, size_t why_cap)
{
    if (debit_managed) *debit_managed = false;
    if (charged_zat) *charged_zat = 0;
    char body[320];
    if (!asc_intent_body(session_id, plan_id, NULL, body, sizeof(body))) {
        asc_why(why, why_cap, "BAD_ARGS");
        LOG_FAIL(ASC_TAG, "intent authorize: bad args");
    }
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("intent_authorize", body, &ans, why, why_cap))
        return false; /* raw-return-ok:typed refusal already returned */
    if (debit_managed)
        *debit_managed = json_get_bool_or(&ans, "debit_managed", false);
    if (charged_zat)
        *charged_zat = json_get_int(json_get(&ans, "charged_zat"));
    json_free(&ans);
    return true;
}

bool agent_session_client_release_intent(
    const char *session_id, const char *plan_id)
{
    char body[320];
    if (!asc_intent_body(session_id, plan_id, NULL, body, sizeof(body)))
        return false; /* raw-return-ok:no valid managed debit was named */
    char why[64] = { 0 };
    struct json_value ans;
    json_init(&ans);
    if (!asc_call("intent_release", body, &ans, why, sizeof(why)))
        LOG_FAIL(ASC_TAG, "intent release could not safely settle (%s)",
                 why[0] ? why : "POLICY_STORE");
    json_free(&ans);
    return true;
}
