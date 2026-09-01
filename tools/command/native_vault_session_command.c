/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `vault.session` tree — the minting
 * and lifecycle surface for agent spend sessions
 * (docs/work/agent-spend-policy-design.md, "Minting + presentation"). These
 * leaves are grants, not custody: nothing here builds, signs or broadcasts a
 * transaction, and nothing here enforces a policy — mint/list/revoke only.
 * The workflow itself lives in cognition/services/src/agent_session_service.c;
 * every handler below is a thin parse → service → render over it, matching
 * the conventions of native_vault_command.c (named-error reply bodies, the
 * plan/commit confirm gate, no silent failures).
 *
 * Token hygiene is the one rule that matters here: the full session id is
 * rendered exactly once, in the create commit reply, and never again — list
 * rows and plan/commit echoes carry only the redacted form (first 8 chars +
 * "…") from agent_session_redact_id. */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
/* The grant store lives in the node's node.db and this handler runs in the
 * CLI process, which has none — so mint/list/revoke go over the node's
 * `agentsession` RPC (controllers/agent_session_client.h). The service header
 * is still included for agent_session_redact_id, the one presentation rule
 * both sides share. */
#include "controllers/agent_session_client.h"
#include "controllers/native_handler_body.h"
#include "json/json.h"
#include "models/agent_session.h"
#include "services/agent_session_service.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VS_TAG "native.vault.session"

/* ── small shared helpers (the native_vault_command.c shapes) ────────────── */

/* Fail the reply with a logged, evidence-carrying error body. Every failure
 * path in this file goes through here, so no leaf can return without saying
 * why. */
static void vs_fail(struct zcl_command_reply *reply,
                    enum zcl_command_status status,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *phase, bool retryable, const char *message,
                    const char *evidence)
{
    LOG_ERROR(VS_TAG, "%s: %s (%s)", code ? code : "ERROR",
              message ? message : "", evidence ? evidence : "");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, retryable,
                           false, message, evidence);
}

static const char *vs_str(const struct zcl_command_request *request,
                          const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

/* Coerce a ZCL-decimal JSON value (int / real / decimal string — the same
 * shapes wnh_amount_real accepts) to zatoshis, bounded to the model's cap.
 * The kernel's input validator types these keys as strings, so the string
 * form is what the CLI actually delivers; INT/REAL are accepted for direct
 * registry callers. */
static bool vs_amount_zat(const struct json_value *v, int64_t *out)
{
    double d = 0.0;
    bool ok = false;
    if (!v)
        return false;
    if (v->type == JSON_REAL) {
        d = json_get_real(v);
        ok = d >= 0.0;
    } else if (v->type == JSON_INT) {
        d = (double)json_get_int(v);
        ok = d >= 0.0;
    } else if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (s && s[0]) {
            char *end = NULL;
            d = strtod(s, &end);
            ok = end && !*end && d >= 0.0;
        }
    }
    if (!ok || d > (double)AGENT_SESSION_MAX_ZAT / 1.0e8)
        return false;
    *out = (int64_t)llround(d * 1.0e8);
    return true;
}

/* Coerce a seconds field (string digits from the CLI, or INT) to an int64 in
 * [min, INT64_MAX). */
static bool vs_seconds(const struct json_value *v, int64_t min, int64_t *out)
{
    int64_t n = 0;
    bool ok = false;
    if (!v)
        return false;
    if (v->type == JSON_INT) {
        n = json_get_int(v);
        ok = true;
    } else if (v->type == JSON_STR) {
        const char *s = json_get_str(v);
        if (s && s[0]) {
            char *end = NULL;
            long long parsed = strtoll(s, &end, 10);
            n = (int64_t)parsed;
            ok = end && !*end;
        }
    }
    if (!ok || n < min)
        return false;
    *out = n;
    return true;
}

/* Render the plan half of the plan/commit gate: the normalized grant (or the
 * redacted revoke target) plus the commit as DATA, never as a next-action —
 * the kernel rejects a next-action that points back at the leaf that emitted
 * it, and this plan's commit is this same leaf re-run with confirm:true. */
static void vs_push_plan(struct zcl_command_reply *reply,
                         struct json_value *commit_obj, const char *hint)
{
    (void)json_push_kv_bool(commit_obj, "confirm", true);
    char commit[640];
    size_t n = json_write(commit_obj, commit, sizeof(commit));
    if (n == 0 || n >= sizeof(commit)) {
        LOG_WARN(VS_TAG, "commit input truncated (%zu bytes)", n);
        (void)snprintf(commit, sizeof(commit), "{\"confirm\":true}");
    }
    (void)json_push_kv_str(&reply->data, "stage", "plan");
    (void)json_push_kv_bool(&reply->data, "committed", false);
    (void)json_push_kv_str(&reply->data, "commit_input", commit);
    (void)json_push_kv_str(&reply->data, "confirm_hint", hint);
    reply->error.mutated = false;
}

/* Map a service refusal token onto a reply failure. */
static void vs_fail_service(struct zcl_command_reply *reply, const char *why,
                            const char *message, const char *evidence)
{
    /* Both mean "the store was not reached", which is transient and points at
     * the node, not at the operator's input. NODE_UNREACHABLE is the CLI-side
     * shape of it (the RPC never completed); DB_UNAVAILABLE is the node's own. */
    if (why && (strcmp(why, "DB_UNAVAILABLE") == 0 ||
                strcmp(why, "NODE_UNREACHABLE") == 0)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
                why, "execute", true, message, evidence);
        (void)zcl_command_reply_add_next(reply, "status", "{}",
                                         "confirm the node is running");
        return;
    }
    if (why && (strcmp(why, "UNKNOWN_ACCOUNT") == 0 ||
                strcmp(why, "SESSION_INVALID") == 0)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                why, "execute", false, message, evidence);
        return;
    }
    vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            (why && why[0]) ? why : "INTERNAL", "execute", false, message,
            evidence);
}

/* ── vault.session.create ─────────────────────────────────────────────────── */

void zcl_native_handle_vault_session_create(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    struct agent_session_mint_request mreq;
    memset(&mreq, 0, sizeof(mreq));

    const char *wallet_scope = vs_str(request, "wallet_scope");
    if (!wallet_scope || (strcmp(wallet_scope, "dev") != 0 &&
                          strcmp(wallet_scope, "prod") != 0)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_WALLET_SCOPE", "normalize", false,
                "wallet_scope is required and must be exactly dev or prod; "
                "the wallet is never inferred from CLI defaults",
                "wallet_scope");
        return;
    }
    (void)snprintf(mreq.wallet_scope, sizeof(mreq.wallet_scope), "%s",
                   wallet_scope);

    const char *account = vs_str(request, "account");
    if (!account) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_ACCOUNT", "normalize", false,
                "account is required; name the principal this grant is for",
                request->spec->path);
        (void)zcl_command_reply_add_next(reply, "app.account.list", "{}",
                                         "list the principals on this node");
        return;
    }
    if (strlen(account) > AGENT_SESSION_ACCOUNT_MAX) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_ACCOUNT", "normalize", false,
                "account exceeds the principal address bound", account);
        return;
    }
    (void)snprintf(mreq.account, sizeof(mreq.account), "%s", account);

    if (!vs_amount_zat(json_get(request->input, "max_per_tx"),
                       &mreq.max_per_tx_zat)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_PER_TX", "normalize", false,
                "max_per_tx must be a ZCL decimal within the model cap",
                "e.g. \"max_per_tx\":\"1.5\"");
        return;
    }
    if (!vs_amount_zat(json_get(request->input, "max_per_window"),
                       &mreq.max_per_window_zat)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_PER_WINDOW", "normalize", false,
                "max_per_window must be a ZCL decimal within the model cap",
                "e.g. \"max_per_window\":\"10\"");
        return;
    }
    mreq.reserve_floor_zat = AGENT_SESSION_DEV_RESERVE_DEFAULT_ZAT;
    const struct json_value *reserve_floor =
        json_get(request->input, "reserve_floor");
    if (reserve_floor &&
        !vs_amount_zat(reserve_floor, &mreq.reserve_floor_zat)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_RESERVE_FLOOR", "normalize", false,
                "reserve_floor must be a ZCL decimal within the model cap",
                "e.g. \"reserve_floor\":\"0.08000000\"");
        return;
    }
    /* Upper bound as well as lower. An unbounded window_seconds does not just
     * make a silly grant: it overflows the window-roll arithmetic, every check
     * then reads as "the window already elapsed", and the per-window cap
     * silently stops existing — a typo that turns a bounded grant into an
     * unbounded one. Refused here, in the model's validate, and by the table
     * CHECK, so no path can persist one. */
    if (!vs_seconds(json_get(request->input, "window_seconds"), 1,
                    &mreq.window_seconds) ||
        mreq.window_seconds > AGENT_SESSION_WINDOW_SECONDS_MAX) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_WINDOW", "normalize", false,
                "window_seconds must be a whole number of seconds in "
                "[1, 31536000] (one year)",
                "e.g. \"window_seconds\":\"86400\"");
        return;
    }
    const char *allowlist = vs_str(request, "allowlist");
    if (allowlist) {
        if (strlen(allowlist) > AGENT_SESSION_ALLOWLIST_MAX) {
            vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                    "BAD_ALLOWLIST", "normalize", false,
                    "allowlist exceeds the CSV bound", allowlist);
            return;
        }
        (void)snprintf(mreq.recipient_allowlist,
                       sizeof(mreq.recipient_allowlist), "%s", allowlist);
    }
    const struct json_value *expires = json_get(request->input, "expires_in");
    if (expires && !vs_seconds(expires, 0, &mreq.expires_in_seconds)) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "BAD_EXPIRY", "normalize", false,
                "expires_in must be a non-negative whole number of seconds "
                "(0 or absent = never)", "e.g. \"expires_in\":\"604800\"");
        return;
    }

    if (!json_get_bool_or(request->input, "confirm", false)) {
        /* The commit re-runs this leaf with the SAME normalized values, so
         * the operator confirms exactly what was previewed. */
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        (void)json_push_kv_str(&ci, "account", account);
        (void)json_push_kv_str(&ci, "wallet_scope", wallet_scope);
        char amt[32];
        (void)snprintf(amt, sizeof(amt), "%.8f",
                       (double)mreq.max_per_tx_zat / 1.0e8);
        (void)json_push_kv_str(&ci, "max_per_tx", amt);
        (void)snprintf(amt, sizeof(amt), "%.8f",
                       (double)mreq.max_per_window_zat / 1.0e8);
        (void)json_push_kv_str(&ci, "max_per_window", amt);
        (void)snprintf(amt, sizeof(amt), "%.8f",
                       (double)mreq.reserve_floor_zat / 1.0e8);
        (void)json_push_kv_str(&ci, "reserve_floor", amt);
        (void)snprintf(amt, sizeof(amt), "%lld",
                       (long long)mreq.window_seconds);
        (void)json_push_kv_str(&ci, "window_seconds", amt);
        if (allowlist)
            (void)json_push_kv_str(&ci, "allowlist", allowlist);
        if (expires) {
            (void)snprintf(amt, sizeof(amt), "%lld",
                           (long long)mreq.expires_in_seconds);
            (void)json_push_kv_str(&ci, "expires_in", amt);
        }

        (void)json_push_kv_str(&reply->data, "account", account);
        (void)json_push_kv_str(&reply->data, "wallet_scope", wallet_scope);
        (void)json_push_kv_int(&reply->data, "max_per_tx_zat",
                               mreq.max_per_tx_zat);
        (void)json_push_kv_int(&reply->data, "max_per_window_zat",
                               mreq.max_per_window_zat);
        (void)json_push_kv_int(&reply->data, "reserve_floor_zat",
                               mreq.reserve_floor_zat);
        (void)json_push_kv_int(&reply->data, "window_seconds",
                               mreq.window_seconds);
        (void)json_push_kv_str(&reply->data, "recipient_allowlist",
                               mreq.recipient_allowlist);
        (void)json_push_kv_int(&reply->data, "expires_in_seconds",
                               mreq.expires_in_seconds);
        vs_push_plan(reply, &ci,
                     "re-run this command with \"confirm\":true to mint the "
                     "session; the full token is returned exactly once, in "
                     "the commit reply");
        json_free(&ci);
        return;
    }

    char sid[AGENT_SESSION_ID_MAX + 1];
    char why[64] = { 0 };
    if (!agent_session_client_mint(mreq.account, mreq.max_per_tx_zat,
                                   mreq.max_per_window_zat,
                                   mreq.reserve_floor_zat,
                                   mreq.window_seconds,
                                   mreq.recipient_allowlist,
                                   mreq.expires_in_seconds, wallet_scope,
                                   sid, why,
                                   sizeof(why))) {
        vs_fail_service(reply, why, "the session grant could not be minted",
                        account);
        return;
    }

    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "session_id", sid);
    (void)json_push_kv_str(&reply->data, "account", account);
    (void)json_push_kv_str(&reply->data, "wallet_scope", wallet_scope);
    (void)json_push_kv_int(&reply->data, "max_per_tx_zat", mreq.max_per_tx_zat);
    (void)json_push_kv_int(&reply->data, "max_per_window_zat",
                           mreq.max_per_window_zat);
    (void)json_push_kv_int(&reply->data, "reserve_floor_zat",
                           mreq.reserve_floor_zat);
    (void)json_push_kv_int(&reply->data, "window_seconds",
                           mreq.window_seconds);
    (void)json_push_kv_str(&reply->data, "recipient_allowlist",
                           mreq.recipient_allowlist);
    (void)json_push_kv_str(
        &reply->data, "token_note",
        "this is the only time the full session id is returned — store it "
        "now; vault.session.list only ever shows it redacted");
    (void)json_push_kv_str(
        &reply->data, "presentation",
        "present per-invocation as ZCL_AGENT_SESSION=<session_id> on the "
        "agent's CLI environment");
    reply->error.mutated = true;
}

/* ── vault.session.list ───────────────────────────────────────────────────── */

void zcl_native_handle_vault_session_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *account = vs_str(request, "account");

    struct db_agent_session *rows =
        zcl_malloc(sizeof(*rows) * AGENT_SESSION_LIST_MAX,
                   "vault_session_list rows");
    if (!rows) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "ALLOC_FAILED", "execute", true,
                "could not allocate the session page", "vault.session.list");
        return;
    }
    char list_why[64] = { 0 };
    int n = agent_session_client_list(account, rows, AGENT_SESSION_LIST_MAX,
                                      list_why, sizeof(list_why));
    if (n < 0) {
        free(rows);
        vs_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
                list_why[0] ? list_why : "DB_UNAVAILABLE", "execute", true,
                "the session store could not be read, so no session is "
                "reported — an empty answer would read as 'no grants exist'",
                "the node owns the grant store; is it running?");
        (void)zcl_command_reply_add_next(reply, "status", "{}",
                                         "confirm the node is running");
        return;
    }

    struct json_value sessions;
    json_init(&sessions);
    json_set_array(&sessions);
    for (int i = 0; i < n; i++) {
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
        (void)json_push_kv_bool(&o, "revoked", rows[i].revoked != 0);
        (void)json_push_kv_str(&o, "wallet_scope", rows[i].wallet_scope);
        (void)json_push_kv_str(&o, "wallet_instance_id",
                               rows[i].wallet_instance_id);
        (void)json_push_kv_str(&o, "wallet_genesis", rows[i].wallet_genesis);
        (void)json_push_kv_bool(&o, "wallet_bound",
                                rows[i].wallet_instance_id[0] != '\0');
        (void)json_push_kv_int(&o, "lifetime_spent_zat",
                               rows[i].lifetime_spent_zat);
        (void)json_push_back(&sessions, &o);
        json_free(&o);
    }
    free(rows);

    (void)json_push_kv_str(&reply->data, "scope",
                           (account && account[0]) ? "account" : "all");
    if (account && account[0])
        (void)json_push_kv_str(&reply->data, "account", account);
    (void)json_push_kv(&reply->data, "sessions", &sessions);
    (void)json_push_kv_int(&reply->data, "session_count", n);
    (void)json_push_kv_str(&reply->data, "redaction",
                           "session ids are never echoed in full after mint "
                           "(first 8 chars + \"…\")");
    json_free(&sessions);
}

/* ── vault.session.revoke ─────────────────────────────────────────────────── */

void zcl_native_handle_vault_session_revoke(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *sid = vs_str(request, "session_id");
    if (!sid) {
        vs_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_SESSION_ID", "normalize", false,
                "session_id is required; revoke names the full token",
                request->spec->path);
        (void)zcl_command_reply_add_next(reply, "vault.session.list", "{}",
                                         "list sessions (redacted) to find "
                                         "the grant");
        return;
    }

    char redacted[24];
    agent_session_redact_id(sid, redacted, sizeof(redacted));

    if (!json_get_bool_or(request->input, "confirm", false)) {
        struct json_value ci;
        json_init(&ci);
        json_set_object(&ci);
        /* The operator already presented the full token, so the commit echo
         * carries it (re-runnable); the plan's own rendering stays redacted. */
        (void)json_push_kv_str(&ci, "session_id", sid);
        (void)json_push_kv_str(&reply->data, "session_id", redacted);
        (void)json_push_kv_bool(&reply->data, "session_id_redacted", true);
        vs_push_plan(reply, &ci,
                     "re-run this command with \"confirm\":true to revoke "
                     "the grant; a revoked session fails closed at the spend "
                     "policy gate");
        json_free(&ci);
        return;
    }

    char why[64] = { 0 };
    if (!agent_session_client_revoke(sid, why, sizeof(why))) {
        vs_fail_service(reply, why, "the session grant could not be revoked",
                        redacted);
        return;
    }

    (void)json_push_kv_str(&reply->data, "stage", "committed");
    (void)json_push_kv_bool(&reply->data, "committed", true);
    (void)json_push_kv_str(&reply->data, "session_id", redacted);
    (void)json_push_kv_bool(&reply->data, "session_id_redacted", true);
    (void)json_push_kv_bool(&reply->data, "revoked", true);
    reply->error.mutated = true;
}
