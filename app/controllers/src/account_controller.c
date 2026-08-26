/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Account controller: the native command handlers for the multi-user-server
 * identity surface (auth.* login + account.* administration). Each handler
 * parses its input, delegates to the auth login service / principal model, and
 * renders one bounded JSON document into reply->data — never touching raw
 * SQLite (parse -> authorize -> call one service, per the controller shape).
 * Every failure path sets a structured error body (never a bare return). */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "models/principal.h"
#include "models/auth_challenge.h"
#include "services/auth_login_service.h"
#include "models/authz_policy.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "util/log_macros.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

/* Uniform failure body. */
static void acc_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                     const char *code, const char *message, const char *evidence)
{
    enum zcl_command_status status =
        exit_code == ZCL_COMMAND_EXIT_BLOCKED ? ZCL_COMMAND_STATUS_BLOCKED
                                              : ZCL_COMMAND_STATUS_FAILED;
    zcl_command_reply_fail(reply, status, exit_code, code, "handle",
                           false, false, message, evidence ? evidence : "");
    /* The registry serializer adds a schema-valid discover.describe action
     * for this exact command. Keeping that construction at the authority
     * boundary prevents handlers from emitting an unbound `{}` path. */
}

static struct node_db *acc_db(struct zcl_command_reply *reply)
{
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) {
        acc_fail(reply, ZCL_COMMAND_EXIT_BLOCKED, "NODE_DB_UNAVAILABLE",
                 "node database is not open", "principals");
        return NULL;
    }
    return ndb;
}

/* Render a bitmask as a "0x..." hex string (uint64 does not fit JSON int). */
static void acc_push_caps(struct json_value *obj, const char *key, uint64_t caps)
{
    char buf[32];
    (void)snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)caps);
    (void)json_push_kv_str(obj, key, buf);
}

/* Fill `into` with the public projection of a principal. */
static void acc_render_principal(struct json_value *into, const struct db_principal *p)
{
    (void)json_push_kv_str(into, "address", p->address);
    (void)json_push_kv_str(into, "pubkey_hex", p->pubkey_hex);
    (void)json_push_kv_int(into, "key_kind", (int)p->key_kind);
    (void)json_push_kv_str(into, "role", principal_role_name(p->role));
    (void)json_push_kv_str(into, "status", principal_status_name(p->status));
    acc_push_caps(into, "granted_capabilities", p->granted_capabilities);
    (void)json_push_kv_str(into, "authority_ceiling",
                           zcl_command_authority_name(
                               authz_ceiling_for_role(p->role)));
    (void)json_push_kv_int(into, "created_at", p->created_at);
    (void)json_push_kv_int(into, "last_login", p->last_login);
    if (p->znam_name[0])
        (void)json_push_kv_str(into, "znam_name", p->znam_name);
    (void)json_push_kv_int(into, "sybil_proof_height", p->sybil_proof_height);
}

/* ── auth.challenge ─────────────────────────────────────────────────── */
void zcl_native_handle_auth_challenge(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *address = json_get_str(json_get(in, "address"));
    if (!address || !address[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "address");
        return;
    }
    const char *server = json_get_str_or(in, "server", "zclassic23");
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;

    struct auth_challenge_issued issued;
    struct zcl_result r = auth_login_challenge(ndb, server, address, &issued);
    if (!r.ok) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "CHALLENGE_FAILED",
                 r.message, address);
        return;
    }
    (void)json_push_kv_str(&reply->data, "nonce", issued.nonce_hex);
    (void)json_push_kv_str(&reply->data, "message", issued.message);
    (void)json_push_kv_str(&reply->data, "server", server);
    (void)json_push_kv_str(&reply->data, "address", address);
    (void)json_push_kv_int(&reply->data, "issued_at", issued.issued_at);
    (void)json_push_kv_int(&reply->data, "expires_at", issued.expires_at);
    (void)json_push_kv_int(&reply->data, "ttl_seconds", AUTH_CHALLENGE_TTL_SECONDS);
}

/* ── auth.verify ────────────────────────────────────────────────────── */
void zcl_native_handle_auth_verify(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *address = json_get_str(json_get(in, "address"));
    const char *nonce = json_get_str(json_get(in, "nonce"));
    const char *sig_hex = json_get_str(json_get(in, "signature"));
    if (!address || !address[0] || !nonce || !nonce[0] || !sig_hex || !sig_hex[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ARGS",
                 "address, nonce, and signature are required", "auth.verify");
        return;
    }
    const char *server = json_get_str_or(in, "server", "zclassic23");
    const char *pubkey = json_get_str_or(in, "pubkey", NULL);

    uint8_t sig[128];
    size_t sig_len = ParseHex(sig_hex, sig, sizeof(sig));
    if (sig_len == 0) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_SIGNATURE_HEX",
                 "signature is not valid hex", "signature");
        return;
    }
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;

    struct auth_session sess;
    struct zcl_result r = auth_login_verify(ndb, server, address, nonce,
                                            sig, sig_len, pubkey, &sess);
    if (!r.ok) {
        /* Generic denial: no unknown-address vs bad-signature distinction. */
        acc_fail(reply, ZCL_COMMAND_EXIT_DENIED, "AUTH_DENIED",
                 r.message, "auth.verify");
        return;
    }
    (void)json_push_kv_str(&reply->data, "account", sess.account);
    (void)json_push_kv_str(&reply->data, "role", principal_role_name(sess.role));
    acc_push_caps(&reply->data, "granted_capabilities", sess.granted_capabilities);
    (void)json_push_kv_str(&reply->data, "authority_ceiling",
                           zcl_command_authority_name(sess.authority_ceiling));
    (void)json_push_kv_bool(&reply->data, "newly_registered", sess.newly_registered);
    /* Scoped spend authority exists for this account: the operator can mint
     * a bounded agent session (vault.session.create) on top of this login —
     * see docs/work/agent-spend-policy-design.md. */
    (void)json_push_kv_bool(&reply->data, "sessions_available", true);
}

/* ── account.list ───────────────────────────────────────────────────── */
void zcl_native_handle_account_list(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    (void)request;
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;
    struct db_principal rows[64];
    int n = db_principal_list(ndb, rows, 64);
    (void)json_push_kv_int(&reply->data, "count", db_principal_count(ndb));
    (void)json_push_kv_int(&reply->data, "returned", n);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        acc_render_principal(&item, &rows[i]);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "accounts", &arr);
    json_free(&arr);
}

/* ── account.show ───────────────────────────────────────────────────── */
void zcl_native_handle_account_show(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *address = json_get_str(json_get(request->input, "address"));
    if (!address || !address[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "address");
        return;
    }
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;
    struct db_principal p;
    if (!db_principal_find(ndb, address, &p)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NOT_FOUND",
                 "no principal with that address", address);
        return;
    }
    acc_render_principal(&reply->data, &p);
}

/* ── account.whoami ─────────────────────────────────────────────────── */
void zcl_native_handle_account_whoami(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    const char *address = json_get_str(json_get(request->input, "address"));
    if (!address || !address[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "address");
        return;
    }
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;
    struct db_principal p;
    bool found = db_principal_find(ndb, address, &p);
    (void)json_push_kv_str(&reply->data, "address", address);
    (void)json_push_kv_bool(&reply->data, "known", found);
    enum principal_role role = found ? p.role : PRINCIPAL_ROLE_GUEST;
    (void)json_push_kv_str(&reply->data, "role", principal_role_name(role));
    (void)json_push_kv_str(&reply->data, "status",
                           found ? principal_status_name(p.status) : "active");
    acc_push_caps(&reply->data, "granted_capabilities",
                  authz_caps_for_role(role));
    (void)json_push_kv_str(&reply->data, "authority_ceiling",
                           zcl_command_authority_name(
                               authz_ceiling_for_role(role)));
}

/* ── account.add ────────────────────────────────────────────────────── */
void zcl_native_handle_account_add(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const struct json_value *in = request->input;
    const char *address = json_get_str(json_get(in, "address"));
    const char *pubkey = json_get_str(json_get(in, "pubkey"));
    const char *role_s = json_get_str(json_get(in, "role"));
    if (!address || !address[0] || !pubkey || !pubkey[0] || !role_s || !role_s[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ARGS",
                 "address, pubkey, and role are required", "account.add");
        return;
    }
    enum principal_role role;
    if (!principal_role_from_name(role_s, &role)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_ROLE",
                 "role must be guest|member|operator|owner", role_s);
        return;
    }
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;

    struct db_principal p;
    if (!db_principal_find(ndb, address, &p)) {
        memset(&p, 0, sizeof(p));
        (void)snprintf(p.address, sizeof(p.address), "%s", address);
        p.status = PRINCIPAL_STATUS_ACTIVE;
        p.sybil_proof_height = -1;
    }
    (void)snprintf(p.pubkey_hex, sizeof(p.pubkey_hex), "%s", pubkey);
    p.role = role;
    p.key_kind = (enum principal_key_kind)json_get_int_or(in, "key_kind",
                                                          PRINCIPAL_KEY_SECP256K1);
    if (!db_principal_save(ndb, &p)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SAVE_FAILED",
                 "principal did not validate or persist", address);
        return;
    }
    (void)db_principal_find(ndb, address, &p);
    acc_render_principal(&reply->data, &p);
}

/* Shared body for the role/suspend/unsuspend mutations: load, mutate, save. */
static void acc_mutate_existing(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply,
                                bool set_role, enum principal_role role,
                                bool set_status, enum principal_status status)
{
    const char *address = json_get_str(json_get(request->input, "address"));
    if (!address || !address[0]) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "MISSING_ADDRESS",
                 "address is required", "address");
        return;
    }
    struct node_db *ndb = acc_db(reply);
    if (!ndb)
        return;
    struct db_principal p;
    if (!db_principal_find(ndb, address, &p)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_FAILED, "NOT_FOUND",
                 "no principal with that address", address);
        return;
    }
    if (set_role)
        p.role = role;
    if (set_status)
        p.status = status;
    if (!db_principal_save(ndb, &p)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_FAILED, "SAVE_FAILED",
                 "principal did not validate or persist", address);
        return;
    }
    (void)db_principal_find(ndb, address, &p);
    acc_render_principal(&reply->data, &p);
}

/* ── account.role ───────────────────────────────────────────────────── */
void zcl_native_handle_account_role(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const char *role_s = json_get_str(json_get(request->input, "role"));
    enum principal_role role;
    if (!role_s || !principal_role_from_name(role_s, &role)) {
        acc_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_ROLE",
                 "role must be guest|member|operator|owner",
                 role_s ? role_s : "");
        return;
    }
    acc_mutate_existing(request, reply, true, role, false,
                        PRINCIPAL_STATUS_ACTIVE);
}

/* ── account.suspend ────────────────────────────────────────────────── */
void zcl_native_handle_account_suspend(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    acc_mutate_existing(request, reply, false, PRINCIPAL_ROLE_GUEST, true,
                        PRINCIPAL_STATUS_SUSPENDED);
}

/* ── account.unsuspend ──────────────────────────────────────────────── */
void zcl_native_handle_account_unsuspend(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    acc_mutate_existing(request, reply, false, PRINCIPAL_ROLE_GUEST, true,
                        PRINCIPAL_STATUS_ACTIVE);
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only ACCOUNT projections: one account, the index, and the caller. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.account.list"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(account)
ZCL_HOTSWAP_LEAF("app.account.show", zcl_native_handle_account_show)
ZCL_HOTSWAP_LEAF("app.account.list", zcl_native_handle_account_list)
ZCL_HOTSWAP_LEAF("app.account.whoami", zcl_native_handle_account_whoami)
ZCL_HOTSWAP_LEAVES_END(account)
#endif
