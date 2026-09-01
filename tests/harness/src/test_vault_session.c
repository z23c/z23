/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Vault session tests (docs/work/agent-spend-policy-design.md, "Minting +
 * presentation"). Proves:
 *  1. service: minting for an existing principal returns a 32-char lowercase
 *     hex session id and agent_session_find round-trips every policy field
 *     (caps, window, allowlist, expiry = created_at + expires_in, not
 *     revoked, zeroed window accounting);
 *  2. service: minting for a missing principal fails with UNKNOWN_ACCOUNT;
 *  3. service: list returns the rows (per-account and across accounts) and
 *     revoke makes agent_session_is_usable false;
 *  4. presentation: ZCL_AGENT_SESSION is read by zcl_native_agent_session_env
 *     exactly as the argv context builder consumes it — unset/empty is the
 *     explicit local-operator exemption (NULL), a set value passes through;
 *  5. handler: vault.session.create without confirm returns a non-mutating
 *     plan and persists NOTHING (agent_session_count unchanged); with
 *     confirm:true it persists and returns the full token once;
 *  6. handler: vault.session.list never echoes a full session id — the
 *     serialized reply carries only the redacted form;
 *  7. handler: vault.session.revoke without confirm is a plan (session still
 *     usable); with confirm:true the session is revoked.
 *
 * The service resolves its DB through the runtime accessor
 * (app_runtime_node_db), so each fixture wires a tmp node_db through a
 * db_service into app_runtime_set_current — the same seam
 * test_agent_spend_policy.c uses. */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/agent_session_controller.h"
#include "controllers/native_handler_body.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "rpc/server.h"
#include "kernel/command_registry.h"
#include "models/agent_session.h"
#include "models/database.h"
#include "models/principal.h"
#include "platform/time_compat.h"
#include "services/agent_session_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const k_account = "t1VaultSessionTestAccount0000000000";

struct vsf_fixture {
    struct node_db ndb;
    struct db_service dbsvc;
    struct app_runtime_context runtime;
    char dir[256];
};

static struct rpc_table g_vsf_rpc_table;
static bool g_vsf_rpc_ready;

static char *vsf_rpc_hook(const char *method, const char *params_json)
{
    if (strcmp(method, "agentsession") != 0 || !g_vsf_rpc_ready)
        return strdup("null");
    struct json_value params;
    if (!json_read(&params, params_json, strlen(params_json))) {
        json_free(&params);
        return NULL;
    }
    struct json_value result;
    json_init(&result);
    bool ok = rpc_table_execute(&g_vsf_rpc_table, "agentsession", &params,
                                &result);
    json_free(&params);
    char *out = malloc(65536);
    if (!out) {
        json_free(&result);
        return NULL;
    }
    if (!ok || json_write(&result, out, 65536) == 0)
        (void)snprintf(out, 65536, "{\"code\":-32603,\"message\":\"rpc\"}");
    json_free(&result);
    return out;
}

/* node.db runs PRAGMA foreign_keys=ON, and agent_sessions.account REFERENCES
 * principals(address) — seed the principal row first. */
static void vsf_seed_principal(struct node_db *ndb, const char *address)
{
    struct db_principal p;
    memset(&p, 0, sizeof(p));
    snprintf(p.address, sizeof(p.address), "%s", address);
    snprintf(p.pubkey_hex, sizeof(p.pubkey_hex), "02%064x", 0xabcdU);
    p.key_kind = PRINCIPAL_KEY_SECP256K1;
    p.role = PRINCIPAL_ROLE_OPERATOR;
    p.status = PRINCIPAL_STATUS_ACTIVE;
    p.sybil_proof_height = -1;
    (void)db_principal_save(ndb, &p);
}

static int vsf_open(struct vsf_fixture *f, const char *tag)
{
    char dbpath[320];
    test_make_tmpdir(f->dir, sizeof(f->dir), "vault_session", tag);
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", f->dir);
    memset(&f->ndb, 0, sizeof(f->ndb));
    memset(&f->dbsvc, 0, sizeof(f->dbsvc));
    memset(&f->runtime, 0, sizeof(f->runtime));
    if (!node_db_open(&f->ndb, dbpath)) {
        printf("vault_session: node_db_open... FAIL\n");
        test_rm_rf(f->dir);
        return 0;
    }
    vsf_seed_principal(&f->ndb, k_account);
    struct wallet_identity_row identity;
    const uint8_t genesis[32] = { 0x42 };
    if (!wallet_identity_ensure(&f->ndb, genesis, "dev", &identity)) {
        node_db_close(&f->ndb);
        test_rm_rf(f->dir);
        return 0;
    }
    db_service_init(&f->dbsvc);
    if (!db_service_attach(&f->dbsvc, &f->ndb) ||
        !db_service_start(&f->dbsvc)) {
        printf("vault_session: db_service start... FAIL\n");
        node_db_close(&f->ndb);
        test_rm_rf(f->dir);
        return 0;
    }
    f->runtime.db_service = &f->dbsvc;
    /* app_runtime is the NODE side. The vault.session.* HANDLERS run in the
     * CLI process, which has no node.db, so they reach the store over the
     * node's `agentsession` RPC — the hook below stands a real rpc table in
     * for the socket (client -> controller -> service -> model). Substituting
     * the transport and not the store is the whole point: the handlers used to
     * be tested against a hand-wired app_runtime, which is a path the shipped
     * binary can never take. */
    app_runtime_set_current(&f->runtime);
    rpc_table_init(&g_vsf_rpc_table);
    register_agent_session_rpc_commands(&g_vsf_rpc_table);
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();
    g_vsf_rpc_ready = true;
    node_rpc_client_set_test_hook(vsf_rpc_hook);
    return 1;
}

static void vsf_close(struct vsf_fixture *f)
{
    node_rpc_client_set_test_hook(NULL);
    g_vsf_rpc_ready = false;
    app_runtime_set_current(NULL);
    db_service_stop(&f->dbsvc);
    node_db_close(&f->ndb);
    test_rm_rf(f->dir);
}

static struct agent_session_mint_request vsf_mint_req(const char *account)
{
    struct agent_session_mint_request r;
    memset(&r, 0, sizeof(r));
    snprintf(r.account, sizeof(r.account), "%s", account);
    r.max_per_tx_zat = 150000000;             /* 1.5 ZCL */
    r.max_per_window_zat = 1000000000;        /* 10 ZCL */
    r.reserve_floor_zat = 8000000;             /* 0.08 ZCL */
    r.window_seconds = 86400;
    snprintf(r.recipient_allowlist, sizeof(r.recipient_allowlist), "%s",
             "t1AllowedA0000000000000000");
    r.expires_in_seconds = 604800;
    snprintf(r.wallet_scope, sizeof(r.wallet_scope), "dev");
    return r;
}

static bool vsf_is_lower_hex32(const char *sid)
{
    if (!sid || strlen(sid) != AGENT_SESSION_ID_MAX)
        return false;
    for (size_t i = 0; i < AGENT_SESSION_ID_MAX; i++) {
        const char c = sid[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

static int test_service_mint_and_find(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("mint for an existing principal returns a 32-hex id; find round-trips") {
        ASSERT(vsf_open(&f, "mint"));
        struct agent_session_mint_request r = vsf_mint_req(k_account);
        char sid[AGENT_SESSION_ID_MAX + 1] = { 0 };
        char why[64] = { 0 };
        ASSERT(agent_session_service_mint(&r, sid, why, sizeof(why)));
        ASSERT(vsf_is_lower_hex32(sid));

        struct db_agent_session s;
        ASSERT(agent_session_find(&f.ndb, sid, &s));
        ASSERT_STR_EQ(s.account, k_account);
        ASSERT_EQ(s.max_per_tx_zat, 150000000);
        ASSERT_EQ(s.max_per_window_zat, 1000000000);
        ASSERT_EQ(s.reserve_floor_zat, 8000000);
        ASSERT_EQ(s.window_seconds, 86400);
        ASSERT_STR_EQ(s.recipient_allowlist, "t1AllowedA0000000000000000");
        ASSERT(s.created_at > 0);
        ASSERT_EQ(s.expires_at - s.created_at, 604800);
        ASSERT_EQ(s.revoked, 0);
        ASSERT_EQ(s.spent_in_window_zat, 0);
        ASSERT_EQ(s.window_start_epoch, s.created_at);
        ASSERT(agent_session_is_usable(&f.ndb, sid,
                                       (int64_t)platform_time_wall_time_t()));
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_mint_missing_principal(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("mint for a missing principal fails UNKNOWN_ACCOUNT") {
        ASSERT(vsf_open(&f, "missing"));
        struct agent_session_mint_request r =
            vsf_mint_req("t1NoSuchPrincipal0000000000000000");
        char sid[AGENT_SESSION_ID_MAX + 1] = { 0 };
        char why[64] = { 0 };
        ASSERT(!agent_session_service_mint(&r, sid, why, sizeof(why)));
        ASSERT_STR_EQ(why, "UNKNOWN_ACCOUNT");
        ASSERT_EQ(agent_session_count(&f.ndb), 0);
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_service_list_and_revoke(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("list returns the rows; revoke makes is_usable false") {
        ASSERT(vsf_open(&f, "list"));
        char sid_a[AGENT_SESSION_ID_MAX + 1] = { 0 };
        char sid_b[AGENT_SESSION_ID_MAX + 1] = { 0 };
        char why[64] = { 0 };
        struct agent_session_mint_request r = vsf_mint_req(k_account);
        ASSERT(agent_session_service_mint(&r, sid_a, why, sizeof(why)));
        ASSERT(agent_session_service_mint(&r, sid_b, why, sizeof(why)));
        ASSERT(strcmp(sid_a, sid_b) != 0);

        /* Per-account list: both rows, full ids inside the service. */
        struct db_agent_session rows[AGENT_SESSION_LIST_MAX];
        int n = agent_session_service_list(k_account, rows, sizeof(rows) /
                                           sizeof(rows[0]));
        ASSERT_EQ(n, 2);
        ASSERT(strcmp(rows[0].session_id, sid_a) == 0 ||
               strcmp(rows[1].session_id, sid_a) == 0);

        /* Across accounts (empty account): the same rows are reachable. */
        memset(rows, 0, sizeof(rows));
        n = agent_session_service_list(NULL, rows,
                                       sizeof(rows) / sizeof(rows[0]));
        ASSERT(n >= 2);

        /* Revoke one: the row stays (auditable) but is no longer usable. */
        ASSERT(agent_session_service_revoke(sid_a, why, sizeof(why)));
        ASSERT(!agent_session_is_usable(&f.ndb, sid_a,
                                        (int64_t)platform_time_wall_time_t()));
        ASSERT(agent_session_is_usable(&f.ndb, sid_b,
                                       (int64_t)platform_time_wall_time_t()));
        struct db_agent_session revoked;
        ASSERT(agent_session_find(&f.ndb, sid_a, &revoked));
        ASSERT_EQ(revoked.revoked, 1);

        /* Revoking a missing session fails SESSION_INVALID. */
        why[0] = '\0';
        ASSERT(!agent_session_service_revoke(
                   "dddddddddddddddddddddddddddddddd", why, sizeof(why)));
        ASSERT_STR_EQ(why, "SESSION_INVALID");
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_env_presentation(void)
{
    int failures = 0;
    TEST("ZCL_AGENT_SESSION: unset/empty exempts, set passes through") {
        /* The argv context builder in native_command.c wires exactly this
         * helper into context.agent_session. */
        ASSERT(unsetenv("ZCL_AGENT_SESSION") == 0);
        ASSERT(zcl_native_agent_session_env() == NULL);
        ASSERT(setenv("ZCL_AGENT_SESSION", "", 1) == 0);
        ASSERT(zcl_native_agent_session_env() == NULL);
        ASSERT(setenv("ZCL_AGENT_SESSION",
                      "0123456789abcdef0123456789abcdef", 1) == 0);
        const char *s = zcl_native_agent_session_env();
        ASSERT(s != NULL);
        ASSERT_STR_EQ(s, "0123456789abcdef0123456789abcdef");
        ASSERT(unsetenv("ZCL_AGENT_SESSION") == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── handler-level ──────────────────────────────────────────────────────────*/

static void vsf_run(const struct zcl_command_spec *spec,
                    struct json_value *input,
                    struct zcl_command_reply *reply,
                    void (*handler)(const struct zcl_command_request *,
                                    struct zcl_command_reply *))
{
    struct zcl_command_context ctx = {
        .registry = zcl_command_catalog(),
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct zcl_command_request request = {
        .spec = spec,
        .context = &ctx,
        .input = input,
        .view = "normal",
    };
    zcl_command_reply_init(reply, spec->output_schema);
    handler(&request, reply);
}

static void vsf_push_str(struct json_value *obj, const char *key,
                         const char *value)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, value);
    (void)json_push_kv(obj, key, &v);
    json_free(&v);
}

static struct json_value vsf_create_input(bool confirm)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    vsf_push_str(&input, "account", k_account);
    vsf_push_str(&input, "max_per_tx", "1.5");
    vsf_push_str(&input, "max_per_window", "10");
    vsf_push_str(&input, "reserve_floor", "0.08000000");
    vsf_push_str(&input, "window_seconds", "3600");
    vsf_push_str(&input, "wallet_scope", "dev");
    vsf_push_str(&input, "allowlist", "t1AllowedA0000000000000000");
    if (confirm) {
        struct json_value c;
        json_init(&c);
        json_set_bool(&c, true);
        (void)json_push_kv(&input, "confirm", &c);
        json_free(&c);
    }
    return input;
}

static int test_handler_create_plan_commit(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("create: plan persists nothing; confirm:true persists and returns the token once") {
        ASSERT(vsf_open(&f, "create"));
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(reg, "vault.session.create", NULL);
        ASSERT(spec != NULL);

        /* Plan: a non-mutating preview; the store is untouched. */
        struct json_value input = vsf_create_input(false);
        struct zcl_command_reply reply;
        vsf_run(spec, &input, &reply, zcl_native_handle_vault_session_create);
        const char *stage = json_get_str(json_get(&reply.data, "stage"));
        ASSERT(stage && strcmp(stage, "plan") == 0);
        ASSERT(!json_get_bool_or(&reply.data, "committed", true));
        ASSERT(json_get(&reply.data, "session_id") == NULL);
        ASSERT(json_get_str(json_get(&reply.data, "commit_input")) != NULL);
        ASSERT(!reply.error.mutated);
        ASSERT_EQ(agent_session_count(&f.ndb), 0);
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* Commit: persisted, and the full token is in the reply. */
        input = vsf_create_input(true);
        vsf_run(spec, &input, &reply, zcl_native_handle_vault_session_create);
        stage = json_get_str(json_get(&reply.data, "stage"));
        ASSERT(stage && strcmp(stage, "committed") == 0);
        const char *sid = json_get_str(json_get(&reply.data, "session_id"));
        ASSERT(vsf_is_lower_hex32(sid));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "max_per_tx_zat")),
                  150000000);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "reserve_floor_zat")),
                  8000000);
        struct db_agent_session persisted;
        ASSERT(agent_session_find(&f.ndb, sid, &persisted));
        ASSERT_EQ(persisted.reserve_floor_zat, 8000000);
        ASSERT_EQ(agent_session_count(&f.ndb), 1);
        ASSERT(reply.error.mutated);
        zcl_command_reply_free(&reply);
        json_free(&input);
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_handler_list_redacts(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("list never echoes the full session id (redacted form only)") {
        ASSERT(vsf_open(&f, "redact"));
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *create =
            zcl_command_registry_find(reg, "vault.session.create", NULL);
        const struct zcl_command_spec *list =
            zcl_command_registry_find(reg, "vault.session.list", NULL);
        ASSERT(create != NULL && list != NULL);

        struct json_value input = vsf_create_input(true);
        struct zcl_command_reply reply;
        vsf_run(create, &input, &reply, zcl_native_handle_vault_session_create);
        const char *sid = json_get_str(json_get(&reply.data, "session_id"));
        ASSERT(vsf_is_lower_hex32(sid));
        char sid_copy[AGENT_SESSION_ID_MAX + 1];
        snprintf(sid_copy, sizeof(sid_copy), "%s", sid);
        zcl_command_reply_free(&reply);
        json_free(&input);

        struct json_value bare;
        json_init(&bare);
        json_set_object(&bare);
        vsf_push_str(&bare, "account", k_account);
        vsf_run(list, &bare, &reply, zcl_native_handle_vault_session_list);

        char buf[ZCL_COMMAND_LIST_BUDGET + 1];
        size_t n = json_write(&reply.data, buf, sizeof(buf));
        ASSERT(n > 0 && n < sizeof(buf));
        /* The full token appears nowhere in the list rendering. */
        ASSERT(strstr(buf, sid_copy) == NULL);
        /* The redacted form (first 8 chars + "…") does. */
        char redacted[24];
        agent_session_redact_id(sid_copy, redacted, sizeof(redacted));
        ASSERT(strstr(buf, redacted) != NULL);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "session_count")), 1);
        zcl_command_reply_free(&reply);
        json_free(&bare);
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

static int test_handler_revoke(void)
{
    int failures = 0;
    struct vsf_fixture f;
    TEST("revoke: plan leaves the session usable; confirm revokes it") {
        ASSERT(vsf_open(&f, "revoke"));
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        const struct zcl_command_spec *create =
            zcl_command_registry_find(reg, "vault.session.create", NULL);
        const struct zcl_command_spec *revoke =
            zcl_command_registry_find(reg, "vault.session.revoke", NULL);
        ASSERT(create != NULL && revoke != NULL);

        struct json_value input = vsf_create_input(true);
        struct zcl_command_reply reply;
        vsf_run(create, &input, &reply, zcl_native_handle_vault_session_create);
        const char *sid = json_get_str(json_get(&reply.data, "session_id"));
        ASSERT(vsf_is_lower_hex32(sid));
        char sid_copy[AGENT_SESSION_ID_MAX + 1];
        snprintf(sid_copy, sizeof(sid_copy), "%s", sid);
        zcl_command_reply_free(&reply);
        json_free(&input);
        int64_t now = (int64_t)platform_time_wall_time_t();

        /* Plan: named but not revoked. */
        struct json_value rin;
        json_init(&rin);
        json_set_object(&rin);
        vsf_push_str(&rin, "session_id", sid_copy);
        vsf_run(revoke, &rin, &reply, zcl_native_handle_vault_session_revoke);
        const char *stage = json_get_str(json_get(&reply.data, "stage"));
        ASSERT(stage && strcmp(stage, "plan") == 0);
        ASSERT(!reply.error.mutated);
        ASSERT(agent_session_is_usable(&f.ndb, sid_copy, now));
        /* The plan's own rendering is redacted too. */
        const char *shown = json_get_str(json_get(&reply.data, "session_id"));
        ASSERT(shown != NULL);
        ASSERT(strcmp(shown, sid_copy) != 0);
        zcl_command_reply_free(&reply);

        /* Commit: revoked and unusable. */
        struct json_value c;
        json_init(&c);
        json_set_bool(&c, true);
        (void)json_push_kv(&rin, "confirm", &c);
        json_free(&c);
        vsf_run(revoke, &rin, &reply, zcl_native_handle_vault_session_revoke);
        stage = json_get_str(json_get(&reply.data, "stage"));
        ASSERT(stage && strcmp(stage, "committed") == 0);
        ASSERT(reply.error.mutated);
        ASSERT(!agent_session_is_usable(&f.ndb, sid_copy, now));
        zcl_command_reply_free(&reply);
        json_free(&rin);
        vsf_close(&f);
        PASS();
    } _test_next:;
    return failures;
}

int test_vault_session(void);
int test_vault_session(void)
{
    printf("\n=== vault session mint/presentation tests ===\n");
    int failures = 0;
    failures += test_service_mint_and_find();
    failures += test_service_mint_missing_principal();
    failures += test_service_list_and_revoke();
    failures += test_env_presentation();
    failures += test_handler_create_plan_commit();
    failures += test_handler_list_redacts();
    failures += test_handler_revoke();
    printf("vault_session: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
