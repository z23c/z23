/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry-level tests for the vault custody dispatch seam
 * (tools/command/native_vault_command.c): vault.send and
 * vault.send-shielded hold no spend logic — they re-run the kernel's
 * authorization and then call the owning leaf's handler pointer
 * (core.wallet.transaction.send / core.wallet.shielded.send).
 *
 * What is asserted here (the dispatch mechanics, not the target's own
 * plan/commit contract — that belongs to the wallet command's tests):
 *   1. plan path (no confirm): dispatch reaches the target and the vault
 *      annotates the reply with its advisory preflight for the class;
 *   2. commit path (confirm:true): the preflight is NOT attached;
 *   3. a session whose authority ceiling is below the target's OWNER is
 *      refused with AUTHORITY_DENIED before the target runs;
 *   4. a session missing the target's required capability is refused with
 *      CAPABILITY_DENIED before the target runs;
 *   5. input that fails the TARGET's schema is refused with
 *      ROUTE_INPUT_REJECTED before the target runs;
 *   6. the same routing holds for vault.send-shielded (spot checks).
 *
 * The target handlers run for real in cases 1/2/6 — with no wallet/node
 * services in this process they answer with their own error body, which
 * is fine: these tests assert the routing and gating, not the wallet's
 * answer. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "controllers/agent_session_controller.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/agent_session.h"
#include "models/database.h"
#include "models/principal.h"
#include "models/wallet_identity.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/legacy_balance_observer.h"
#include "services/vault_read.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <stdlib.h>
#include <string.h>

#define VD_CHECK(name, expr) do {                                           \
    if (expr) { printf("  vault_dispatch: %s... OK\n", (name)); }            \
    else { printf("  vault_dispatch: %s... FAIL\n", (name)); failures++; }   \
} while (0)

/* The policy gate reaches the grant store over the node's `agentsession` RPC
 * (the CLI process it runs in has no node.db of its own), so the policy cases
 * below stand a real rpc table in for the socket: client -> controller ->
 * service -> model, against this test's tmp node_db. Only the transport is
 * substituted; the store is genuine. */
static struct rpc_table g_vd_rpc_table;
static bool g_vd_rpc_ready;

static bool vd_legacy_balance_rpc(const char *body_json,
                                  uint32_t timeout_ms,
                                  char **out_resp,
                                  char *err, size_t err_sz)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\n\r\n"
        "{\"result\":{\"transparent\":\"0.00999662\","
        "\"private\":\"0.01970000\",\"total\":\"0.02969662\"},"
        "\"error\":null}";
    bool request_ok = body_json &&
        strstr(body_json, "\"method\":\"z_gettotalbalance\"") &&
        timeout_ms == LEGACY_BALANCE_OBSERVER_TIMEOUT_MS;
    if (!request_ok) {
        if (err && err_sz)
            (void)snprintf(err, err_sz, "unexpected legacy RPC request");
        return false;
    }
    *out_resp = strdup(response);
    if (!*out_resp && err && err_sz)
        (void)snprintf(err, err_sz, "fixture allocation failed");
    return *out_resp != NULL;
}

static char *vd_rpc_hook(const char *method, const char *params_json)
{
    if (strcmp(method, "dumpstate") == 0 && params_json &&
        strstr(params_json, "\"vault\"") != NULL) {
        struct json_value envelope, state;
        json_init(&envelope);
        json_set_object(&envelope);
        json_init(&state);
        if (!vault_read_dump_state_json(&state, NULL)) {
            json_free(&state);
            json_free(&envelope);
            return strdup("{\"code\":-32603,\"message\":\"vault\"}");
        }
        (void)json_push_kv_str(&envelope, "subsystem", "vault");
        (void)json_push_kv(&envelope, "state", &state);
        json_free(&state);
        char *out = malloc(16384);
        if (!out || json_write(&envelope, out, 16384) == 0) {
            free(out);
            out = NULL;
        }
        json_free(&envelope);
        return out;
    }
    if (strcmp(method, "agentsession") != 0 || !g_vd_rpc_ready)
        return strdup("null");
    struct json_value params;
    if (!json_read(&params, params_json, strlen(params_json))) {
        json_free(&params);
        return NULL;
    }
    struct json_value result;
    json_init(&result);
    bool ok = rpc_table_execute(&g_vd_rpc_table, "agentsession", &params,
                                &result);
    json_free(&params);
    char *out = malloc(8192);
    if (!out) {
        json_free(&result);
        return NULL;
    }
    if (!ok || json_write(&result, out, 8192) == 0)
        (void)snprintf(out, 8192, "{\"code\":-32603,\"message\":\"rpc\"}");
    json_free(&result);
    return out;
}

static struct zcl_command_context vd_ctx(
    const struct zcl_command_registry *reg,
    enum zcl_command_authority ceiling, uint64_t caps)
{
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = caps,
        .authority_ceiling = ceiling,
    };
    return ctx;
}

/* `settled` mirrors what the kernel gate sets on the request once it has
 * already ruled on (and accounted for) this invocation. Every registry path
 * reaches vault.send through execute_json, so settled=true is the real-world
 * shape; settled=false is the fallback the vault's own gate exists for. */
static void vd_run_send_ex(const struct zcl_command_spec *spec,
                           const struct zcl_command_context *ctx,
                           struct json_value *input,
                           struct zcl_command_reply *reply, bool settled)
{
    struct zcl_command_request request = {
        .spec = spec,
        .context = ctx,
        .input = input,
        .view = "normal",
        .agent_policy_settled = settled,
    };
    zcl_command_reply_init(reply, spec->output_schema);
    zcl_native_handle_vault_send(&request, reply);
}

static void vd_run_send(const struct zcl_command_spec *spec,
                        const struct zcl_command_context *ctx,
                        struct json_value *input,
                        struct zcl_command_reply *reply)
{
    vd_run_send_ex(spec, ctx, input, reply, false);
}

static void vd_run_send_shielded(const struct zcl_command_spec *spec,
                                 const struct zcl_command_context *ctx,
                                 struct json_value *input,
                                 struct zcl_command_reply *reply)
{
    struct zcl_command_request request = {
        .spec = spec,
        .context = ctx,
        .input = input,
        .view = "normal",
    };
    zcl_command_reply_init(reply, spec->output_schema);
    zcl_native_handle_vault_send_shielded(&request, reply);
}

static void vd_run_list(const struct zcl_command_spec *spec,
                        const struct zcl_command_context *ctx,
                        struct json_value *input,
                        struct zcl_command_reply *reply)
{
    struct zcl_command_request request = {
        .spec = spec,
        .context = ctx,
        .input = input,
        .view = "normal",
    };
    zcl_command_reply_init(reply, spec->output_schema);
    zcl_native_handle_vault_list(&request, reply);
}

static struct json_value vd_send_input(bool confirm)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    struct json_value addr, amt;
    json_init(&addr);
    json_init(&amt);
    json_set_str(&addr, "t1VdDispatchTestAddress0000000000000");
    json_set_real(&amt, 1.5);
    json_push_kv(&input, "address", &addr);
    json_push_kv(&input, "amount", &amt);
    json_push_kv_str(&input, "wallet_scope", "prod");
    if (confirm) {
        struct json_value c;
        json_init(&c);
        json_set_bool(&c, true);
        json_push_kv(&input, "confirm", &c);
    }
    return input;
}

static struct json_value vd_shielded_input(void)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    struct json_value from, to, amt;
    json_init(&from);
    json_init(&to);
    json_init(&amt);
    json_set_str(&from, "zs1vdtestfrom000000000000000000000000000000000");
    json_set_str(&to, "zs1vdtestto00000000000000000000000000000000000");
    json_set_real(&amt, 1.0);
    json_push_kv(&input, "from", &from);
    json_push_kv(&input, "to", &to);
    json_push_kv(&input, "amount", &amt);
    json_push_kv_str(&input, "wallet_scope", "dev");
    json_push_kv_str(&input, "memo_hex", "aabb");
    return input;
}

int test_vault_dispatch(void);
int test_vault_dispatch(void)
{
    printf("\n=== vault custody dispatch seam tests ===\n");
    int failures = 0;

    const struct zcl_command_registry *reg = zcl_command_catalog();
    VD_CHECK("catalog", reg != NULL);
    const struct zcl_command_spec *send =
        reg ? zcl_command_registry_find(reg, "vault.send", NULL) : NULL;
    const struct zcl_command_spec *send_shielded =
        reg ? zcl_command_registry_find(reg, "vault.send-shielded", NULL)
            : NULL;
    const struct zcl_command_spec *list =
        reg ? zcl_command_registry_find(reg, "vault.list", NULL) : NULL;
    VD_CHECK("vault.send leaf", send != NULL);
    VD_CHECK("vault.send-shielded leaf", send_shielded != NULL);
    VD_CHECK("vault.list leaf", list != NULL);
    if (!send || !send_shielded || !list)
        return failures + 1;

    struct zcl_command_context owner =
        vd_ctx(reg, ZCL_COMMAND_AUTH_OWNER, ~(uint64_t)0);

    /* 1. plan path: dispatch reaches the target (which answers with its own
     * error body in this service-less process) and the vault attaches the
     * advisory transparent-class preflight. */
    {
        struct json_value input = vd_send_input(false);
        struct zcl_command_reply reply;
        vd_run_send(send, &owner, &input, &reply);
        const struct json_value *pf = json_get(&reply.data, "preflight");
        VD_CHECK("plan (no confirm): preflight attached",
                 pf != NULL);
        const struct json_value *cls = pf ? json_get(pf, "class") : NULL;
        VD_CHECK("plan (no confirm): preflight class == transparent",
                 cls && json_get_str(cls) &&
                 strcmp(json_get_str(cls), "transparent") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 2. commit path: confirm:true forwards to the target's own commit —
     * the vault adds nothing (no preflight). */
    {
        struct json_value input = vd_send_input(true);
        struct zcl_command_reply reply;
        vd_run_send(send, &owner, &input, &reply);
        VD_CHECK("commit (confirm:true): no preflight attached",
                 json_get(&reply.data, "preflight") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 3. session authority below the target's OWNER: refused before the
     * target runs (no preflight, named error). */
    {
        struct zcl_command_context pub =
            vd_ctx(reg, ZCL_COMMAND_AUTH_PUBLIC, ~(uint64_t)0);
        struct json_value input = vd_send_input(false);
        struct zcl_command_reply reply;
        vd_run_send(send, &pub, &input, &reply);
        VD_CHECK("low-ceiling session: AUTHORITY_DENIED",
                 strcmp(reply.error.code, "AUTHORITY_DENIED") == 0);
        VD_CHECK("low-ceiling session: exit DENIED",
                 reply.exit_code == ZCL_COMMAND_EXIT_DENIED);
        VD_CHECK("low-ceiling session: target not run (no preflight)",
                 json_get(&reply.data, "preflight") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 4. session missing the target's required capability
     * (ZCL_COMMAND_CAP_WALLET_REQUEST): refused before the target runs. */
    {
        struct zcl_command_context nocap =
            vd_ctx(reg, ZCL_COMMAND_AUTH_OWNER, 0);
        struct json_value input = vd_send_input(false);
        struct zcl_command_reply reply;
        vd_run_send(send, &nocap, &input, &reply);
        VD_CHECK("no-capability session: CAPABILITY_DENIED",
                 strcmp(reply.error.code, "CAPABILITY_DENIED") == 0);
        VD_CHECK("no-capability session: target not run (no preflight)",
                 json_get(&reply.data, "preflight") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 5. a forwarded key with the wrong type: the vault forwards `confirm`
     * verbatim and the kernel validator demands a bool — refused before the
     * target runs. (Unknown keys never reach the validator: the vault
     * forwards only the target's declared keys, which is itself part of the
     * seam's contract.) */
    {
        struct json_value input = vd_send_input(false);
        struct json_value bad_confirm;
        json_init(&bad_confirm);
        json_set_str(&bad_confirm, "yes");
        json_push_kv(&input, "confirm", &bad_confirm);
        struct zcl_command_reply reply;
        vd_run_send(send, &owner, &input, &reply);
        VD_CHECK("wrong-typed confirm: ROUTE_INPUT_REJECTED",
                 strcmp(reply.error.code, "ROUTE_INPUT_REJECTED") == 0);
        VD_CHECK("wrong-typed confirm: target not run (no preflight)",
                 json_get(&reply.data, "preflight") == NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 7. agent spend policy (docs/work/agent-spend-policy-design.md): the
     * vault bypasses execute_json, so it re-runs the policy gate itself on
     * the forwarded input. The helper resolves its DB through the runtime
     * accessor, so wire a tmp node_db through db_service into
     * app_runtime_set_current (the test_node_health_service.c seam). */
    {
        char dir[256];
        char dbpath[320];
        struct node_db ndb;
        struct db_service dbsvc;
        struct app_runtime_context runtime;
        struct db_principal p;
        /* A wallet owns the fixed 65,536-entry transaction table and is tens
         * of MiB. Keeping it automatic made the optimized macOS harness
         * fault in ___chkstk_darwin before the first assertion ran. */
        struct wallet *wallet =
            zcl_calloc(1, sizeof(*wallet), "vault_dispatch.wallet");
        struct wallet_identity_row identity;
        test_make_tmpdir(dir, sizeof(dir), "vault_dispatch", "policy");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dir);
        memset(&ndb, 0, sizeof(ndb));
        memset(&dbsvc, 0, sizeof(dbsvc));
        memset(&runtime, 0, sizeof(runtime));
        memset(&p, 0, sizeof(p));
        memset(&identity, 0, sizeof(identity));
        bool db_ok = wallet != NULL;
        if (wallet) {
            wallet_init(wallet);
            wallet->default_fee = 0;
        }
        if (db_ok)
            db_ok = node_db_open(&ndb, dbpath);
        const uint8_t genesis[32] = { 0x42 };
        if (db_ok)
            db_ok = wallet_identity_ensure(&ndb, genesis, "canonical",
                                           &identity);
        if (db_ok) {
            snprintf(p.address, sizeof(p.address), "%s",
                     "t1VaultDispatchPolicyAccount00000");
            snprintf(p.pubkey_hex, sizeof(p.pubkey_hex), "02%064x", 0xabcdU);
            p.key_kind = PRINCIPAL_KEY_SECP256K1;
            p.role = PRINCIPAL_ROLE_OPERATOR;
            p.status = PRINCIPAL_STATUS_ACTIVE;
            p.sybil_proof_height = -1;
            db_ok = db_principal_save(&ndb, &p);
        }
        if (db_ok) {
            int64_t now = (int64_t)platform_time_wall_time_t();
            struct db_agent_session s;
            /* (a) tiny per-tx cap: 1000 zatoshis, way under the 1.5-ZCL
             * send below. */
            memset(&s, 0, sizeof(s));
            snprintf(s.session_id, sizeof(s.session_id), "%s",
                     "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
            snprintf(s.account, sizeof(s.account), "%s", p.address);
            s.max_per_tx_zat = 1000;
            s.max_per_window_zat = AGENT_SESSION_MAX_ZAT;
            s.window_seconds = 3600;
            s.window_start_epoch = now;
            s.created_at = now;
            snprintf(s.wallet_scope, sizeof(s.wallet_scope), "prod");
            snprintf(s.wallet_instance_id, sizeof(s.wallet_instance_id),
                     "%s", identity.wallet_instance_id);
            wallet_identity_genesis_hex(&identity, s.wallet_genesis);
            db_ok = agent_session_save(&ndb, &s);
            /* (b) generous caps: the 1.5-ZCL send clears every gate. */
            memset(&s, 0, sizeof(s));
            snprintf(s.session_id, sizeof(s.session_id), "%s",
                     "ffffffffffffffffffffffffffffffff");
            snprintf(s.account, sizeof(s.account), "%s", p.address);
            s.max_per_tx_zat = AGENT_SESSION_MAX_ZAT;
            s.max_per_window_zat = AGENT_SESSION_MAX_ZAT;
            s.window_seconds = 3600;
            s.window_start_epoch = now;
            s.created_at = now;
            snprintf(s.wallet_scope, sizeof(s.wallet_scope), "prod");
            snprintf(s.wallet_instance_id, sizeof(s.wallet_instance_id),
                     "%s", identity.wallet_instance_id);
            wallet_identity_genesis_hex(&identity, s.wallet_genesis);
            db_ok = db_ok && agent_session_save(&ndb, &s);
        }
        if (db_ok) {
            db_service_init(&dbsvc);
            db_ok = db_service_attach(&dbsvc, &ndb) &&
                    db_service_start(&dbsvc);
        }
        VD_CHECK("policy fixture: tmp node_db + runtime wired", db_ok);
        if (db_ok) {
            runtime.db_service = &dbsvc;
            runtime.wallet = wallet;
            app_runtime_set_current(&runtime);
            node_rpc_client_set_test_hook(vd_rpc_hook);

            /* The native vault vocabulary is intentionally shorter than the
             * read model's primitive names.  Prove that the adapter maps the
             * live model rather than reporting all six known rows absent. */
            {
                struct json_value input;
                json_init(&input);
                json_set_object(&input);
                struct zcl_command_reply reply;
                legacy_balance_observer_set_test_call(vd_legacy_balance_rpc);
                vd_run_list(list, &owner, &input, &reply);
                legacy_balance_observer_set_test_call(NULL);
                const struct json_value *classes =
                    json_get(&reply.data, "classes");
                const struct json_value *legacy =
                    json_get(&reply.data, "legacy_wallet");
                const struct json_value *first =
                    classes && classes->type == JSON_ARR &&
                            json_size(classes) > 0
                        ? json_at(classes, 0) : NULL;
                const char *first_class =
                    json_get_str(json_get(first, "class"));
                const char *first_source =
                    json_get_str(json_get(first, "source"));
                VD_CHECK("vault.list maps all live read-model classes",
                         classes && classes->type == JSON_ARR &&
                         json_size(classes) == 6 &&
                         json_get_int(json_get(&reply.data,
                                               "classes_available")) > 0 &&
                         json_get_int(json_get(&reply.data,
                                               "classes_available")) +
                         json_get_int(json_get(&reply.data,
                                               "classes_unavailable")) == 6);
                VD_CHECK("vault.list maps transparent_zcl to transparent",
                         first_class &&
                         strcmp(first_class, "transparent") == 0 &&
                         first_source && first_source[0] != '\0' &&
                         json_get(first, "spendable_zat") != NULL);
                VD_CHECK("vault.list no false unavailable blocker",
                         strcmp(reply.error.code,
                                "VAULT_READ_UNAVAILABLE") != 0);
                VD_CHECK("vault.list keeps legacy custody separate and exact",
                         legacy &&
                         json_get_bool(json_get(legacy, "complete")) &&
                         strcmp(json_get_str(json_get(legacy, "aggregation")),
                                "excluded") == 0 &&
                         json_get_int(json_get(legacy,
                                               "transparent_zat")) == 999662 &&
                         json_get_int(json_get(legacy,
                                               "shielded_zat")) == 1970000 &&
                         json_get_int(json_get(legacy,
                                               "total_zat")) == 2969662);
                zcl_command_reply_free(&reply);
                json_free(&input);
            }

            rpc_table_init(&g_vd_rpc_table);
            register_agent_session_rpc_commands(&g_vd_rpc_table);
            if (rpc_is_in_warmup(NULL, 0))
                set_rpc_warmup_finished();
            g_vd_rpc_ready = true;
            /* (a) over the session's per-tx cap: refused with
             * POLICY_TX_LIMIT before the target runs. */
            {
                struct zcl_command_context agent =
                    vd_ctx(reg, ZCL_COMMAND_AUTH_OWNER, ~(uint64_t)0);
                agent.agent_session = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
                struct json_value input = vd_send_input(false);
                struct zcl_command_reply reply;
                vd_run_send(send, &agent, &input, &reply);
                VD_CHECK("tiny-cap session: POLICY_TX_LIMIT",
                         strcmp(reply.error.code, "POLICY_TX_LIMIT") == 0);
                VD_CHECK("tiny-cap session: exit DENIED",
                         reply.exit_code == ZCL_COMMAND_EXIT_DENIED);
                VD_CHECK("tiny-cap session: target not run (no preflight)",
                         json_get(&reply.data, "preflight") == NULL);
                zcl_command_reply_free(&reply);
                json_free(&input);
            }

            /* (b) generous session: the gate passes and dispatch reaches
             * the target (preflight attached). */
            {
                struct zcl_command_context agent =
                    vd_ctx(reg, ZCL_COMMAND_AUTH_OWNER, ~(uint64_t)0);
                agent.agent_session = "ffffffffffffffffffffffffffffffff";
                struct json_value input = vd_send_input(false);
                struct zcl_command_reply reply;
                vd_run_send(send, &agent, &input, &reply);
                VD_CHECK("generous session: no policy refusal",
                         strstr(reply.error.code, "POLICY_") == NULL);
                VD_CHECK("generous session: target run (preflight attached)",
                         json_get(&reply.data, "preflight") != NULL);
                zcl_command_reply_free(&reply);
                json_free(&input);
            }

            /* (c) THE double-debit guard. When the kernel gate has already
             * ruled on this invocation it also already DEBITED it, and the
             * forwarded input carries the same amount and recipient — so the
             * vault must not evaluate again. If it did, the tiny-cap session
             * below would be refused here even though the kernel let it
             * through, and a session whose window cap equals its per-tx cap
             * could never complete one send. */
            {
                struct zcl_command_context agent =
                    vd_ctx(reg, ZCL_COMMAND_AUTH_OWNER, ~(uint64_t)0);
                agent.agent_session = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
                struct json_value input = vd_send_input(false);
                struct zcl_command_reply reply;
                vd_run_send_ex(send, &agent, &input, &reply, true);
                VD_CHECK("settled invocation: the vault does NOT re-gate "
                         "(no second debit)",
                         strstr(reply.error.code, "POLICY_") == NULL);
                VD_CHECK("settled invocation: target still run",
                         json_get(&reply.data, "preflight") != NULL);
                zcl_command_reply_free(&reply);
                json_free(&input);
            }

            node_rpc_client_set_test_hook(NULL);
            g_vd_rpc_ready = false;
            app_runtime_set_current(NULL);
            db_service_stop(&dbsvc);
        }
        if (ndb.open)
            node_db_close(&ndb);
        if (wallet) {
            wallet_free(wallet);
            free(wallet);
        }
        test_rm_rf(dir);
    }

    /* 6a. shielded plan path: preflight names the shielded class. */
    {
        struct json_value input = vd_shielded_input();
        struct zcl_command_reply reply;
        vd_run_send_shielded(send_shielded, &owner, &input, &reply);
        const struct json_value *pf = json_get(&reply.data, "preflight");
        const struct json_value *cls = pf ? json_get(pf, "class") : NULL;
        VD_CHECK("shielded plan: preflight class == shielded",
                 cls && json_get_str(cls) &&
                 strcmp(json_get_str(cls), "shielded") == 0);
        const char *commit_input =
            json_get_str(json_get(&reply.data, "commit_input"));
        struct json_value commit;
        json_init(&commit);
        bool commit_ok = commit_input &&
            json_read(&commit, commit_input, strlen(commit_input));
        const char *commit_scope = commit_ok
            ? json_get_str(json_get(&commit, "wallet_scope")) : NULL;
        const char *commit_memo = commit_ok
            ? json_get_str(json_get(&commit, "memo_hex")) : NULL;
        VD_CHECK("shielded plan: route preserves wallet_scope in commit",
                 commit_scope && strcmp(commit_scope, "dev") == 0);
        VD_CHECK("shielded plan: route preserves Sapling memo in commit",
                 commit_memo && strcmp(commit_memo, "aabb") == 0);
        json_free(&commit);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    /* 6b. shielded route is session-gated identically. */
    {
        struct zcl_command_context pub =
            vd_ctx(reg, ZCL_COMMAND_AUTH_PUBLIC, ~(uint64_t)0);
        struct json_value input = vd_shielded_input();
        struct zcl_command_reply reply;
        vd_run_send_shielded(send_shielded, &pub, &input, &reply);
        VD_CHECK("shielded low-ceiling session: AUTHORITY_DENIED",
                 strcmp(reply.error.code, "AUTHORITY_DENIED") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }

    printf("vault_dispatch: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
