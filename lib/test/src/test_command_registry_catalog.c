/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Golden contract tests for the native command registry catalog
 * (docs/NATIVE_COMMAND_INTERFACE.md §20). Proves the composition-root catalog
 * is well-formed, shallow, budgeted, fail-closed for planned leaves, and that
 * every READY leaf has a live binding — without contacting a node.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "config/command_handler_index.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "json/json.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/app_native_handlers.h"
#include "controllers/chain_native_handlers.h"
#include "controllers/rpc_client.h"

#include <stdio.h>
#include <string.h>

static const struct zcl_command_spec *find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static bool bridge_has_exact_binding(const char *path)
{
    return (zcl_native_bridge_body_for_path(path) != NULL) !=
           (zcl_native_bridge_rpc_for_path(path) != NULL);
}

static bool exec_leaf(const struct zcl_command_registry *reg,
                      const struct zcl_command_spec *spec,
                      char *out, size_t out_size,
                      enum zcl_command_exit *exit_code)
{
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal", 0,
                                                 0, NULL,
                                                 out, out_size, exit_code);
    json_free(&input);
    return n > 0;
}

static int test_catalog_wellformed(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("catalog validates and is non-trivial") {
        char why[128] = { 0 };
        ASSERT(reg != NULL);
        ASSERT(reg->count > 40);
        ASSERT(zcl_command_registry_validate(reg, why, sizeof(why)));
        PASS();
    } _test_next:;
    return failures;
}

/* Count registry entries (branches + leaves) rooted at or under `root`
 * (either path == root, or path starts with "root."). This is the
 * "how big is the native surface, per domain" contract.
 * Floors are set with headroom below the live count so routine additions
 * don't require bumping this file every commit (unlike the old
 * EXPECTED_TOTAL, which pinned an exact number). */
static size_t count_domain(const struct zcl_command_registry *reg,
                           const char *root)
{
    size_t n = 0;
    size_t len = strlen(root);
    for (size_t i = 0; i < reg->count; i++) {
        const char *p = reg->commands[i].path;
        if (strcmp(p, root) == 0) {
            n++;
            continue;
        }
        if (strncmp(p, root, len) == 0 && p[len] == '.')
            n++;
    }
    return n;
}

static int test_domain_leaf_counts(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("native registry per-domain counts meet the catalog floor") {
        ASSERT(reg->count >= 120);
        ASSERT(count_domain(reg, "core") >= 60);
        ASSERT(count_domain(reg, "dev") >= 35);
        ASSERT(count_domain(reg, "ops") >= 15);
        ASSERT(count_domain(reg, "app") >= 3);
        ASSERT(count_domain(reg, "code") >= 5);
        ASSERT(count_domain(reg, "discover") >= 4);
        ASSERT(count_domain(reg, "status") >= 1);
        ASSERT(count_domain(reg, "vault") >= 8);
        PASS();
    } _test_next:;
    return failures;
}

static int test_six_roots(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("root exposes exactly eleven choices") {
        size_t roots = 0;
        for (size_t i = 0; i < reg->count; i++) {
            const char *p = reg->commands[i].parent;
            if (!p || !p[0])
                roots++;
        }
        ASSERT_EQ(roots, (size_t)11);
        ASSERT(find_spec(reg, "status") != NULL);
        ASSERT(find_spec(reg, "core") != NULL);
        ASSERT(find_spec(reg, "app") != NULL);
        ASSERT(find_spec(reg, "dev") != NULL);
        ASSERT(find_spec(reg, "ops") != NULL);
        ASSERT(find_spec(reg, "discover") != NULL);
        ASSERT(find_spec(reg, "code") != NULL);
        ASSERT(find_spec(reg, "vault") != NULL);
        ASSERT(find_spec(reg, "zcode") != NULL);
        ASSERT(find_spec(reg, "metaverse") != NULL);
        ASSERT(find_spec(reg, "yardsale") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_yardsale_guide(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("yardsale.guide is a public local read that names the min-relay fee") {
        const struct zcl_command_spec *s = find_spec(reg, "yardsale.guide");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);
        ASSERT_EQ(s->authority, ZCL_COMMAND_AUTH_PUBLIC);
        ASSERT_EQ(s->scope, ZCL_COMMAND_SCOPE_LOCAL);
        ASSERT(s->handler == zcl_native_handle_yardsale_guide);
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.spec = s;
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.yardsale_guide.v1");
        zcl_native_handle_yardsale_guide(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "start_command")),
                      "z23 vault list") == 0);
        ASSERT(json_get_int(json_get(&reply.data, "fee_zat")) == 100);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "fee_zcl")),
                      "0.00000100") == 0);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "nft_create")),
                      "supply\":\"1\"") != NULL);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "confirm_rule")),
                      "confirm:true") != NULL);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "docs")),
                      "docs/SELL.md") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_code_guide_leaf(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("code.guide is a public local read that names lint-fast") {
        const struct zcl_command_spec *s = find_spec(reg, "code.guide");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);
        ASSERT_EQ(s->authority, ZCL_COMMAND_AUTH_PUBLIC);
        ASSERT_EQ(s->scope, ZCL_COMMAND_SCOPE_LOCAL);
        ASSERT(s->handler == zcl_native_handle_code_guide);
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request;
        memset(&request, 0, sizeof(request));
        request.spec = s;
        request.input = &input;
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.test.code_guide.v1");
        zcl_native_handle_code_guide(&request, &reply);
        ASSERT(reply.exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "start_command")),
                      "z23 code impact <file.c>") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "lint_command")),
                      "make lint-fast") == 0);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "push_command")),
                      "make pre-push-ci") == 0);
        ASSERT(strstr(json_get_str(json_get(&reply.data, "never")),
                      "test_zcl") != NULL);
        ASSERT(strcmp(json_get_str(json_get(&reply.data, "docs")),
                      "docs/DEVELOPING.md") == 0);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

static int test_root_menu_budget(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    TEST("root menu is within its byte budget") {
        size_t n = zcl_command_registry_menu_json(reg, "root", out,
                                                  sizeof(out));
        ASSERT(n > 0);
        ASSERT(n <= ZCL_COMMAND_ROOT_BUDGET);
        PASS();
    } _test_next:;
    return failures;
}

static int test_branch_menus_shallow(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    TEST("branch menus stay in budget and list only immediate children") {
        const char *branches[] = { "core", "core.chain", "core.wallet",
                                   "ops", "ops.debug", "discover" };
        for (size_t b = 0; b < sizeof(branches) / sizeof(branches[0]); b++) {
            size_t n = zcl_command_registry_menu_json(reg, branches[b], out,
                                                      sizeof(out));
            ASSERT(n > 0);
            ASSERT(n <= ZCL_COMMAND_BRANCH_BUDGET);
            struct json_value doc;
            ASSERT(json_read(&doc, out, n) && doc.type == JSON_OBJ);
            const struct json_value *children = json_get(&doc, "children");
            ASSERT(children && children->type == JSON_ARR);
            for (size_t i = 0; i < children->num_children; i++) {
                const char *cpath =
                    json_get_str(json_get(&children->children[i], "path"));
                const struct zcl_command_spec *cs = find_spec(reg, cpath);
                ASSERT(cs != NULL);
                ASSERT_STR_EQ(cs->parent, branches[b]);
            }
            json_free(&doc);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_search_bounded(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    TEST("search returns at most five ranked matches") {
        const char *queries[] = { "block", "wallet", "sync", "peer", "a" };
        for (size_t q = 0; q < sizeof(queries) / sizeof(queries[0]); q++) {
            size_t n = zcl_command_registry_search_json(reg, queries[q], out,
                                                        sizeof(out));
            ASSERT(n > 0);
            struct json_value doc;
            ASSERT(json_read(&doc, out, n) && doc.type == JSON_OBJ);
            const struct json_value *matches = json_get(&doc, "matches");
            ASSERT(matches && matches->type == JSON_ARR);
            ASSERT(matches->num_children <= ZCL_COMMAND_SEARCH_LIMIT);
            json_free(&doc);
        }
        PASS();
    } _test_next:;
    return failures;
}

static size_t search_total_matches(const struct zcl_command_registry *reg,
                                   const char *query, char *out, size_t out_sz)
{
    size_t n = zcl_command_registry_search_json(reg, query, out, out_sz);
    if (n == 0)
        return 0;
    struct json_value doc;
    if (!json_read(&doc, out, n) || doc.type != JSON_OBJ)
        return 0;
    const struct json_value *tm = json_get(&doc, "total_matches");
    size_t total = tm && tm->type == JSON_INT ? (size_t)json_get_int(tm) : 0;
    json_free(&doc);
    return total;
}

static int test_search_multiword(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    TEST("a space-separated query matches dotted command paths") {
        /* Regression: "dev loop" (space) previously matched nothing because
         * the literal string is never a substring of "dev.loop.status". Each
         * word must appear for a hit; a nonsense word blocks the match. */
        ASSERT(search_total_matches(reg, "dev loop", out, sizeof(out)) > 0);
        ASSERT(search_total_matches(reg, "loop dev", out, sizeof(out)) > 0);
        ASSERT(search_total_matches(reg, "dev zzznope", out, sizeof(out)) == 0);
        /* Single-word behavior is unchanged and still finds matches. */
        ASSERT(search_total_matches(reg, "loop", out, sizeof(out)) > 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ready_leaves_bound(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every READY leaf has a non-NULL handler and bridge binding") {
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (s->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            if (s->availability != ZCL_COMMAND_READY)
                continue;
            ASSERT(s->handler != NULL);
            if (s->handler == zcl_native_bridge_command)
                ASSERT(bridge_has_exact_binding(s->path));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_bridge_bindings_reverse(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every sampled bridge binding names a READY native leaf") {
        const char *sample[] = {
            "status", "core.status", "core.chain.tip", "ops.health",
            "ops.metrics", "core.storage.query", "core.chain.block.get",
        };
        for (size_t i = 0; i < sizeof(sample) / sizeof(sample[0]); i++) {
            ASSERT(bridge_has_exact_binding(sample[i]));
            const struct zcl_command_spec *s = find_spec(reg, sample[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT(s->handler == zcl_native_bridge_command);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_bridge_replacement_rejects_non_bridge_leaf(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("explicit bridge replacement rejects a non-bridge READY leaf") {
        const struct zcl_command_spec *target = find_spec(reg, "discover.help");
        zcl_native_body_fn replacement =
            zcl_native_bridge_body_for_path("core.status");
        ASSERT(target != NULL);
        ASSERT_EQ(target->availability, ZCL_COMMAND_READY);
        ASSERT(target->handler != zcl_native_bridge_command);
        ASSERT(replacement != NULL);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {
            .spec = target,
            .input = &input,
            .view = "normal",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, target->output_schema);
        zcl_native_bridge_run(&request, replacement, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INTERNAL);
        ASSERT_STR_EQ(reply.error.code, "NO_BRIDGE_BINDING");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* node_rpc_call strips the JSON-RPC envelope on a node error and returns the
 * bare error object. Locally-generated transport failures retain
 * the older {"error": {...}} wrapper. The native bridge must fail closed for
 * both shapes; otherwise -32601 (runtime/source skew) is projected as passing
 * command data. */
static const char *g_bridge_rpc_error_fixture;
static const char *g_bridge_rpc_method_fixture;

static char *bridge_rpc_error_mock(const char *method,
                                   const char *params_json)
{
    (void)params_json;
    if (!g_bridge_rpc_method_fixture ||
        strcmp(method, g_bridge_rpc_method_fixture) != 0 ||
        !g_bridge_rpc_error_fixture)
        return strdup("null");
    return strdup(g_bridge_rpc_error_fixture);
}

static int test_messaging_inbox_wraps_rpc_array(void)
{
    int failures = 0;
    TEST("native messaging inbox preserves the RPC array in an object") {
        g_bridge_rpc_method_fixture = "msg_inbox";
        g_bridge_rpc_error_fixture =
            "[{\"msg_id\":\"abc\",\"read\":false}]";
        node_rpc_client_set_test_hook(bridge_rpc_error_mock);

        struct zcl_native_body_err err = {0};
        char *body = zcl_native_msg_inbox_body(NULL, &err);
        struct json_value doc;
        json_init(&doc);
        bool parsed = body && json_read(&doc, body, strlen(body));
        const struct json_value *messages =
            parsed ? json_get(&doc, "messages") : NULL;
        const struct json_value *first =
            messages && messages->type == JSON_ARR ? json_at(messages, 0)
                                                   : NULL;
        bool ok = parsed && doc.type == JSON_OBJ && messages &&
                  messages->type == JSON_ARR && json_size(messages) == 1 &&
                  first && strcmp(json_get_str(json_get(first, "msg_id")),
                                  "abc") == 0;

        json_free(&doc);
        free(body);
        node_rpc_client_set_test_hook(NULL);
        g_bridge_rpc_method_fixture = NULL;
        g_bridge_rpc_error_fixture = NULL;
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static int g_peer_add_rpc_calls;
static char g_peer_add_params[256];
static const char *g_peer_add_reply;

static char *peer_add_rpc_mock(const char *method, const char *params_json)
{
    if (!method || strcmp(method, "addnode") != 0)
        return strdup("{\"code\":-32601,\"message\":\"unexpected method\"}");
    g_peer_add_rpc_calls++;
    (void)snprintf(g_peer_add_params, sizeof(g_peer_add_params), "%s",
                   params_json ? params_json : "");
    return strdup(g_peer_add_reply ? g_peer_add_reply : "null");
}

static int test_network_peer_add_binding(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("typed peer add requests numeric or Tor-rendezvous edges") {
        const struct zcl_command_spec *spec =
            find_spec(reg, "core.network.peers.add");
        ASSERT(spec != NULL);
        ASSERT_EQ(spec->availability, ZCL_COMMAND_READY);
        ASSERT(spec->handler == zcl_native_handle_network_peer_add);

        g_peer_add_rpc_calls = 0;
        g_peer_add_params[0] = '\0';
        g_peer_add_reply = "null";
        node_rpc_client_set_test_hook(peer_add_rpc_mock);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "address", "203.0.113.8:39023");
        struct zcl_command_request request = {
            .spec = spec, .input = &input, .view = "normal",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_network_peer_add(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(reply.error.mutated);
        ASSERT_EQ(g_peer_add_rpc_calls, 1);
        ASSERT_STR_EQ(g_peer_add_params,
                      "[\"203.0.113.8:39023\",\"add\"]");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "dial_requested");
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(
            &input, "address",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion");
        request.input = &input;
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_network_peer_add(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(reply.error.mutated);
        ASSERT_EQ(g_peer_add_rpc_calls, 2);
        ASSERT(strstr(g_peer_add_params, ".onion") != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "transport")),
                      "tor_rendezvous+p2p_tcp");
        zcl_command_reply_free(&reply);
        json_free(&input);

        /* Live node_rpc_call returns the JSON-RPC envelope, not a bare
         * null. The shipped handler must treat result:null as dial_requested
         * and still refuse a real error envelope. */
        g_peer_add_reply = "{\"result\":null,\"error\":null,\"id\":1}";
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(
            &input, "address",
            "5wvfod4ikluv4w3lqe3whn2k7xdsympxxu2qkqw452thtjxbar5hrcqd.onion:8055");
        request.input = &input;
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_network_peer_add(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")),
                      "dial_requested");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "transport")),
                      "tor_rendezvous+p2p_tcp");
        zcl_command_reply_free(&reply);
        json_free(&input);

        g_peer_add_reply =
            "{\"result\":null,\"error\":{\"code\":-8,\"message\":"
            "\"addnode: invalid .onion address\"},\"id\":1}";
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "address", "not-an-onion:8055");
        request.input = &input;
        zcl_command_reply_init(&reply, spec->output_schema);
        zcl_native_handle_network_peer_add(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_FAILED);
        ASSERT_STR_EQ(reply.error.code, "PEER_ADD_REFUSED");
        ASSERT(strstr(reply.error.message, "invalid .onion") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    g_peer_add_reply = NULL;
    return failures;
}

static int test_bridge_rpc_errors_fail_closed(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.chain.tip");
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("native bridge rejects bare and wrapped JSON-RPC errors") {
        static const struct {
            const char *body;
            const char *message;
        } cases[] = {
            {
                "{\"code\":-32601,\"message\":\"Method not found\","
                "\"method\":\"getchaintip\"}",
                "Method not found",
            },
            {
                "{\"error\":{\"code\":-32603,"
                "\"message\":\"cannot connect to node\"}}",
                "cannot connect to node",
            },
        };
        ASSERT(s != NULL);
        ASSERT(s->handler == zcl_native_bridge_command);
        ASSERT(zcl_native_bridge_body_for_path(s->path) == NULL);
        ASSERT_STR_EQ(zcl_native_bridge_rpc_for_path(s->path), "getchaintip");

        g_bridge_rpc_method_fixture = "getchaintip";
        node_rpc_client_set_test_hook(bridge_rpc_error_mock);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            g_bridge_rpc_error_fixture = cases[i].body;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_FAILED);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            ASSERT(strstr(out, "\"status\":\"failed\"") != NULL);
            ASSERT(strstr(out, "\"code\":\"TOOL_ERROR\"") != NULL);
            ASSERT(strstr(out, cases[i].message) != NULL);
        }
        PASS();
    } _test_next:;
    g_bridge_rpc_error_fixture = NULL;
    g_bridge_rpc_method_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static char *raw_transaction_string_mock(const char *method,
                                         const char *params_json)
{
    if (!method || strcmp(method, "getrawtransaction") != 0 || !params_json)
        return NULL;
    if (strstr(params_json, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
        return strdup("\"Transaction not found\"");
    if (strstr(params_json, ",0]"))
        return strdup("\"02a1ff\"");
    if (strstr(params_json, ",1]"))
        return strdup("{\"txid\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                      "\"vin\":[{\"scriptSig\":{\"hex\":\"0123\"}}],"
                      "\"blockhash\":\"cccccccccccccccccccccccccccccccc"
                      "cccccccccccccccccccccccccccccccc\","
                      "\"confirmations\":3}");
    return NULL;
}

static int test_raw_transaction_string_is_typed(void)
{
    int failures = 0;
    TEST("raw transaction mode wraps full hex instead of reporting an error") {
        struct json_value args;
        json_init(&args);
        json_set_object(&args);
        (void)json_push_kv_str(
            &args, "txid",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        (void)json_push_kv_bool(&args, "verbose", false);
        (void)json_push_kv_int(&args, "raw_bytes", 2);
        struct zcl_native_body_err err = {0};
        node_rpc_client_set_test_hook(raw_transaction_string_mock);
        char *body = zcl_native_getrawtransaction_body(&args, &err);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(body != NULL);
        struct json_value doc;
        json_init(&doc);
        ASSERT(json_read(&doc, body, strlen(body)));
        ASSERT_EQ(doc.type, JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "schema")),
                      "zcl.raw_transaction.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "encoding")), "hex");
        ASSERT_EQ(json_get_int(json_get(&doc, "offset_bytes")), 0);
        ASSERT_EQ(json_get_int(json_get(&doc, "chunk_bytes")), 2);
        ASSERT_EQ(json_get_int(json_get(&doc, "total_bytes")), 3);
        ASSERT(!json_get_bool(json_get(&doc, "complete")));
        ASSERT_EQ(json_get_int(json_get(&doc, "next_offset")), 2);
        ASSERT_STR_EQ(json_get_str(json_get(&doc, "raw_hex")), "02a1");
        json_free(&doc);
        free(body);
        json_free(&args);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_raw_transaction_verbose_bool(void)
{
    int failures = 0;
    TEST("verbose=true remains decoded mode rather than becoming raw mode") {
        struct json_value args;
        json_init(&args);
        json_set_object(&args);
        (void)json_push_kv_str(
            &args, "txid",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        (void)json_push_kv_bool(&args, "verbose", true);
        struct zcl_native_body_err err = {0};
        node_rpc_client_set_test_hook(raw_transaction_string_mock);
        char *body = zcl_native_getrawtransaction_body(&args, &err);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(body != NULL);
        ASSERT(strstr(body, "\"txid\"") != NULL);
        const char *confirmations = strstr(body, "\"confirmations\"");
        const char *inputs = strstr(body, "\"vin\"");
        ASSERT(confirmations != NULL);
        ASSERT(inputs != NULL);
        ASSERT(confirmations < inputs);
        ASSERT(strstr(body, "zcl.raw_transaction.v1") == NULL);
        free(body);
        json_free(&args);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_raw_transaction_error_string(void)
{
    int failures = 0;
    TEST("raw mode preserves a bare non-hex RPC error for bridge handling") {
        struct json_value args;
        json_init(&args);
        json_set_object(&args);
        (void)json_push_kv_str(
            &args, "txid",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        (void)json_push_kv_bool(&args, "verbose", false);
        struct zcl_native_body_err err = {0};
        node_rpc_client_set_test_hook(raw_transaction_string_mock);
        char *body = zcl_native_getrawtransaction_body(&args, &err);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(body != NULL);
        ASSERT_STR_EQ(body, "\"Transaction not found\"");
        free(body);
        json_free(&args);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* Direct-RPC leaves intentionally preserve zclassicd-compatible result bodies,
 * which do not carry zclassic23 schema labels. Prove each binding instead
 * checks its stable minimum field/type shape, and prove the three legitimate
 * top-level arrays accept empty/valid lists while rejecting mixed elements. */
static int test_bridge_rpc_success_shapes_fail_closed(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static const struct {
        const char *path;
        const char *valid;
        const char *invalid;
    } cases[] = {
        { "core.chain.tip",
          "{\"hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"height\":1}",
          "{\"hash\":1,\"height\":\"1\"}" },
        { "core.chain.mempool.status", "{\"size\":0,\"bytes\":0}",
          "{}" },
        { "core.chain.mempool.list",
          "[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"]",
          "[\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",7]" },
        { "core.sync.status", "{\"state\":\"syncing\",\"state_id\":1}",
          "{}" },
        { "core.sync.validation", "{\"state\":\"not_initialized\"}",
          "{\"state\":1}" },
        { "core.consensus.integrity",
          "{\"source\":\"persisted_consensus_tables\",\"master\":\"abc\"}",
          "{}" },
        { "core.consensus.utxo.commitment",
          "{\"sha3_hash\":\"abc\",\"height\":1,\"utxo_count\":2}",
          "{\"sha3_hash\":\"abc\",\"height\":1}" },
        { "core.consensus.mmb", "{\"mmr_root\":\"abc\",\"num_leaves\":1}",
          "{}" },
        { "core.network.status", "{\"connections\":0,\"networks\":[]}",
          "{\"connections\":\"0\",\"networks\":[]}" },
        { "core.network.peers.list", "[{\"id\":1,\"addr\":\"peer\"}]",
          "[{\"id\":1,\"addr\":\"peer\"},{}]" },
        { "core.network.peers.latency",
          "[{\"peer_id\":1,\"addr\":\"peer\"}]",
          "[{\"peer_id\":1,\"addr\":7}]" },
        { "core.network.onion.status",
          "{\"schema\":\"zcl.onion_status.v1\","
          "\"bootstrap_state\":\"ready\",\"tor_ready\":true,"
          "\"onion_service_ready\":true,\"onion_address\":\"node.onion\"}",
          "{}" },
        { "core.wallet.status", "{\"balance\":\"1.0\",\"txcount\":0}",
          "{}" },
        { "core.wallet.balance",
          "{\"transparent\":\"1.0\",\"total\":\"1.0\"}", "{}" },
        { "core.wallet.backup.status", "{\"running\":false,\"total_runs\":0}",
          "{}" },
        { "core.wallet.audit", "{\"chain_height\":1,\"summary\":{}}",
          "{\"chain_height\":1,\"summary\":[]}" },
        { "core.storage.stats", "{\"tip_height\":1,\"utxo_count\":2}",
          "{}" },
        { "core.mining.status", "{\"blocks\":1,\"chain\":\"main\"}",
          "{}" },
        { "core.mining.benchmark",
          "{\"primary_benchmark_source\":\"local\",\"primary_benchmarks\":[]}",
          "{}" },
        { "ops.health",
          "{\"status\":\"blocked\",\"healthy\":false,\"serving\":false}",
          "{\"status\":\"blocked\",\"healthy\":false}" },
        { "ops.lanes", "{\"status\":\"ok\",\"lanes\":[]}", "{}" },
        { "ops.recovery.status",
          "{\"ready_for_refold\":false,\"primary_blocker\":\"missing\"}",
          "{}" },
    };

    TEST("direct RPC bridge validates every legacy success shape") {
        node_rpc_client_set_test_hook(bridge_rpc_error_mock);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, cases[i].path);
            ASSERT(s != NULL);
            ASSERT(s->handler == zcl_native_bridge_command);
            ASSERT(zcl_native_bridge_body_for_path(s->path) == NULL);
            g_bridge_rpc_method_fixture =
                zcl_native_bridge_rpc_for_path(s->path);
            ASSERT(g_bridge_rpc_method_fixture != NULL);

            char out[ZCL_COMMAND_RESULT_BUDGET + 1];
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            g_bridge_rpc_error_fixture = cases[i].valid;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(out, "\"ok\":true") != NULL);

            g_bridge_rpc_error_fixture = cases[i].invalid;
            code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_FAILED);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            ASSERT(strstr(out, "\"code\":\"TOOL_ERROR\"") != NULL);
            ASSERT(strstr(out, "incompatible success body") != NULL);
        }

        /* Empty arrays are real no-data states, not schema failures. */
        const char *empty_paths[] = {
            "core.chain.mempool.list", "core.network.peers.list",
            "core.network.peers.latency",
        };
        for (size_t i = 0;
             i < sizeof(empty_paths) / sizeof(empty_paths[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, empty_paths[i]);
            ASSERT(s != NULL);
            g_bridge_rpc_method_fixture =
                zcl_native_bridge_rpc_for_path(s->path);
            g_bridge_rpc_error_fixture = "[]";
            char out[ZCL_COMMAND_RESULT_BUDGET + 1];
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(out, "\"items\":[]") != NULL);
            ASSERT(strstr(out, "\"total_items\":0") != NULL);
        }
        PASS();
    } _test_next:;
    g_bridge_rpc_error_fixture = NULL;
    g_bridge_rpc_method_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* Stubs the one bounded cached status document core.status.brief projects,
 * so the envelope test below runs without a live node (node_rpc_call's
 * ZCL_TESTING hook wins over both RPC backends). */
static const char *g_status_brief_agent_fixture;

static char *status_brief_mock_rpc(const char *method,
                                   const char *params_json)
{
    (void)params_json;
    if (strcmp(method, "agent") == 0 && g_status_brief_agent_fixture)
        return strdup(g_status_brief_agent_fixture);
    if (strcmp(method, "agent") == 0)
        return strdup(
            "{\"schema\":\"zcl.public_status.v2\","
            "\"partial_result\":false,"
            "\"served_height\":3117073,\"header_height\":3117074,"
            "\"served_height_known\":true,"
            "\"header_height_known\":true,"
            "\"gap\":1,\"peer_best_height\":3117074,"
            "\"peer_best_height_known\":true,"
            "\"target_height\":3117074,\"target_height_known\":true,"
            "\"chain_evidence_consistent\":true,"
            "\"sync_state\":\"at_tip\",\"serving\":true,"
            "\"healthy\":true,\"primary_blocker\":\"none\","
            "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                "\"budget_ms\":250,\"partial_result\":false,"
                "\"budget_exceeded\":false},"
            "\"peers\":{\"total\":1},"
            "\"conditions\":{"
                "\"schema\":\"zcl.condition_engine_summary.v2\","
                "\"active_count\":2},"
            "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                "\"rss_mb\":512},"
            "\"reducer\":{\"tip_advance_age_seconds\":3},"
            "\"security_posture\":{"
                "\"schema\":\"zcl.security_posture.v1\","
                "\"anchor_backfill_gap\":false,"
                "\"nullifier_backfill_gap\":false}}");
    return strdup("null");
}

static bool g_status_journey_plaintext;
static bool g_status_journey_typed_blocker;
static bool g_status_journey_witness_ready = true;

static char *status_journey_mock_rpc(const char *method,
                                     const char *params_json)
{
    (void)params_json;
    if (strcmp(method, "agent") == 0) {
        char body[2048];
        (void)snprintf(
            body, sizeof(body),
            "{\"schema\":\"zcl.public_status.v2\","
            "\"partial_result\":false,"
            "\"served_height\":3117074,\"header_height\":3117074,"
            "\"served_height_known\":true,\"header_height_known\":true,"
            "\"gap\":0,\"peer_best_height\":3117074,"
            "\"peer_best_height_known\":true,"
            "\"target_height\":3117074,\"target_height_known\":true,"
            "\"chain_evidence_consistent\":true,"
            "\"sync_state\":\"blocks_download\",\"serving\":true,"
            "\"healthy\":%s,"
            "\"primary_blocker\":\"%s\",\"tip_follow\":true,"
            "\"wallet_view_ready\":true,\"wallet_spend_allowed\":true,"
            "\"archive_complete\":\"incomplete\","
            "\"full_replay_verified\":false,"
            "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                "\"budget_ms\":250,\"partial_result\":false,"
                "\"budget_exceeded\":false},"
            "\"peers\":{\"total\":3},"
            "\"conditions\":{\"schema\":\"zcl.condition_engine_summary.v2\","
                "\"active_count\":0},"
            "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                "\"rss_mb\":64},"
            "\"reducer\":{\"tip_advance_age_seconds\":2},"
            "\"security_posture\":{\"schema\":\"zcl.security_posture.v1\","
                "\"anchor_backfill_gap\":false,"
                "\"nullifier_backfill_gap\":false}}",
            g_status_journey_typed_blocker ? "false" : "true",
            g_status_journey_typed_blocker
                ? "review_required_bootstrap_trust" : "none"
        );
        return strdup(body);
    }
    if (strcmp(method, "agentsession") == 0)
        return strdup(
            "{\"ok\":true,\"snapshot\":{\"status\":\"CURRENT\","
            "\"complete\":true,\"confirmed_zat\":10000000,"
            "\"transparent_spendable_zat\":0,"
            "\"shielded_spendable_zat\":10000000,\"pending_zat\":0,"
            "\"encumbered_zat\":0,\"intent_reserved_zat\":0,"
            "\"agent_available_zat\":10000000,"
            "\"wallet_instance_id\":\"must-not-cross-front-door\"}}"
        );
    if (strcmp(method, "getwalletinfo") == 0) {
        char body[512];
        (void)snprintf(body, sizeof(body),
            "{\"persistence\":{\"healthy\":true},"
            "\"lock\":{\"encrypted_at_rest\":%s,\"unlocked\":true},"
            "\"sapling\":{\"prover_ready\":true,"
            "\"checkpoint_healthy\":true,\"witness_ready\":%s,"
            "\"witness_state\":\"%s\"}}",
            g_status_journey_plaintext ? "false" : "true",
            g_status_journey_witness_ready ? "true" : "false",
            g_status_journey_witness_ready ? "ready"
                                           : "rescan_required_stale");
        return strdup(body);
    }
    if (strcmp(method, "walletbackupstatus") == 0)
        return strdup(
            "{\"healthy\":true,\"encrypted_backup_available\":true,"
            "\"last_path\":\"must-not-cross-front-door\"}"
        );
    if (strcmp(method, "getmempoolinfo") == 0)
        return strdup("{\"size\":1}");
    return strdup("null");
}

/* core.status.brief exists so an operator/AI never has to pipe the ~15KB
 * core.status body through grep/tr for the handful of fields that answer
 * "is the node serving and caught up" — see docs/NATIVE_COMMAND_INTERFACE.md
 * "CLI UX contract" and status_brief_native_handler.c. This proves the leaf
 * is READY-bridged, dispatches to a real zcl.result.v1 envelope, and that
 * `data` stays flat (no nested containers besides the universal `_page`
 * pagination sidecar every bridged leaf carries) with exactly the thirteen
 * documented sync/serving keys. */
static int test_status_brief_flat_lean_envelope(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief: flat lean zcl.result.v1 body, thirteen "
        "sync/serving fields") {
        const struct zcl_command_spec *root_status = find_spec(reg, "status");
        const struct zcl_command_spec *s =
            find_spec(reg, "core.status.brief");
        ASSERT(root_status != NULL);
        ASSERT_EQ(root_status->availability, ZCL_COMMAND_READY);
        ASSERT(root_status->handler == zcl_native_bridge_command);
        ASSERT_STR_EQ(root_status->output_schema,
                      "zcl.status_journey.v1");
        ASSERT((root_status->allowed_lanes & ZCL_COMMAND_LANE_LOCAL) != 0);
        ASSERT(bridge_has_exact_binding("status"));
        ASSERT(zcl_native_bridge_body_for_path("status") != NULL);
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT(s->handler == zcl_native_bridge_command);
        ASSERT(bridge_has_exact_binding("core.status.brief"));

        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&root, "schema")),
                      "zcl.result.v1");
        ASSERT(json_get_bool(json_get(&root, "ok")));
        ASSERT_STR_EQ(json_get_str(json_get(&root, "status")), "passed");

        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);

        static const char *const expected_keys[] = {
            "hstar", "header_height", "gap", "peer_best", "sync_state",
            "serving", "healthy", "peer_count", "primary_blocker",
            "blocker_age_s", "active_conditions", "rss_mb",
            "tip_advance_age_seconds",
        };
        size_t expected_count =
            sizeof(expected_keys) / sizeof(expected_keys[0]);
        /* The thirteen documented fields plus the universal `_page` sidecar
         * every bridged leaf's envelope carries — nothing else. */
        ASSERT(data->num_children == expected_count + 1);
        for (size_t i = 0; i < expected_count; i++) {
            const struct json_value *v = json_get(data, expected_keys[i]);
            ASSERT(v != NULL);
            ASSERT(v->type != JSON_OBJ && v->type != JSON_ARR);
        }
        const struct json_value *page = json_get(data, "_page");
        ASSERT(page != NULL && page->type == JSON_OBJ);
        ASSERT(!json_get_bool(json_get(page, "truncated")));

        ASSERT_EQ(json_get_int(json_get(data, "hstar")),
                  (int64_t)3117073);
        ASSERT_EQ(json_get_int(json_get(data, "header_height")),
                  (int64_t)3117074);
        ASSERT_EQ(json_get_int(json_get(data, "gap")), (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(data, "peer_best")),
                  (int64_t)3117074);
        ASSERT_STR_EQ(json_get_str(json_get(data, "sync_state")), "at_tip");
        ASSERT(json_get_bool(json_get(data, "serving")));
        ASSERT(json_get_bool(json_get(data, "healthy")));
        ASSERT_EQ(json_get_int(json_get(data, "peer_count")), (int64_t)1);
        ASSERT_STR_EQ(json_get_str(json_get(data, "primary_blocker")),
                      "none");
        /* No active blocker in the fixture -> age honestly null. */
        ASSERT(json_is_null(json_get(data, "blocker_age_s")));
        ASSERT_EQ(json_get_int(json_get(data, "active_conditions")),
                  (int64_t)2);
        ASSERT_EQ(json_get_int(json_get(data, "rss_mb")), (int64_t)512);
        ASSERT_EQ(json_get_int(json_get(data, "tip_advance_age_seconds")),
                  (int64_t)3);
        json_free(&root);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_status_journey_safe_money_frontdoor(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "status");
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("root status answers the money journey and emits no sensitive fields") {
        ASSERT(s != NULL);
        ASSERT_STR_EQ(s->output_schema, "zcl.status_journey.v1");
        node_rpc_client_set_test_hook(status_journey_mock_rpc);
        g_status_journey_plaintext = false;
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data && data->type == JSON_OBJ);
        ASSERT(json_get_bool(json_get(data, "node_healthy")));
        ASSERT(json_get_bool(json_get(data, "synced")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "sync_state")),
                      "blocks_download");
        ASSERT(json_get_bool(json_get(data, "wallet_ready")));
        ASSERT(json_get_bool(json_get(data, "can_receive")));
        ASSERT(json_get_bool(json_get(data, "can_send")));
        ASSERT(!json_get_bool(json_get(data, "can_send_transparent")));
        ASSERT(json_get_bool(json_get(data, "can_send_sapling")));
        ASSERT_EQ(json_get_int(json_get(data, "spendable_zat")),
                  (int64_t)10000000);
        ASSERT_EQ(json_get_int(json_get(data, "pending_zat")), (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(data, "reserved_zat")), (int64_t)0);
        ASSERT_EQ(json_get_int(json_get(data, "mempool_transactions")),
                  (int64_t)1);
        ASSERT(json_get_bool(json_get(data, "sapling_witness_ready")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "sapling_witness_state")),
                      "ready");
        ASSERT_STR_EQ(json_get_str(json_get(data, "error_code")), "NONE");
        ASSERT_STR_EQ(json_get_str(json_get(data, "operator_status")),
                      "healthy");
        ASSERT_STR_EQ(json_get_str(json_get(data, "summary")),
                      "node healthy at served frontier");
        ASSERT(!json_get_bool(json_get(data, "human_action_required")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "next_action")),
                      "z23 vault intent plan");
        ASSERT(strstr(out, "wallet_instance_id") == NULL);
        ASSERT(strstr(out, "last_path") == NULL);
        ASSERT(strstr(out, "must-not-cross-front-door") == NULL);
        json_free(&root);

        g_status_journey_plaintext = true;
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(!json_get_bool(json_get(data, "can_receive")));
        ASSERT(!json_get_bool(json_get(data, "can_send")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "error_code")),
                      "WALLET_PLAINTEXT");
        ASSERT_STR_EQ(json_get_str(json_get(data, "operator_status")),
                      "blocked");
        ASSERT_STR_EQ(json_get_str(json_get(data, "summary")),
                      "consensus-state trust posture requires review");
        ASSERT(json_get_bool(json_get(data, "human_action_required")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "next_action")),
                      "z23 core wallet security encrypt --input=-");
        json_free(&root);

        g_status_journey_plaintext = false;
        g_status_journey_witness_ready = false;
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(!json_get_bool(json_get(data, "can_send_sapling")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "error_code")),
                      "WITNESS_RESCAN_REQUIRED");
        ASSERT_STR_EQ(json_get_str(json_get(data, "current_state")),
                      "SHIELDED_WITNESS_NOT_READY");
        ASSERT_STR_EQ(json_get_str(json_get(data, "next_action")),
                      "z23 core wallet rescan-witnesses");
        json_free(&root);

        g_status_journey_witness_ready = true;
        g_status_journey_typed_blocker = true;
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(!json_get_bool(json_get(data, "node_healthy")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "primary_blocker")),
                      "review_required_bootstrap_trust");
        ASSERT_STR_EQ(json_get_str(json_get(data, "error_code")),
                      "NODE_TYPED_BLOCKER");
        ASSERT_STR_EQ(json_get_str(json_get(data, "next_action")),
                      "z23 core sync blockers");
        ASSERT(json_get_bool(json_get(data, "owner_review_required")));
        json_free(&root);
        PASS();
    } _test_next:;
    g_status_journey_plaintext = false;
    g_status_journey_typed_blocker = false;
    g_status_journey_witness_ready = true;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* core.wallet.utxo.list: the node RPC listunspent is Bitcoin-compatible and
 * answers a BARE ARRAY, which the native command bridge drops (the defect
 * class that made `app swap list` answer BAD_TOOL_BODY for its whole
 * existence — see rpc_swap_list). The body must wrap the array in the
 * leaf's declared output envelope (zcl.wallet_utxos.v1, config/commands/
 * core.def) so `z23 core wallet utxo list` returns a usable body.
 * Drives the leaf end-to-end through the registry with a mocked
 * node_rpc_call and asserts on the rendered reply bytes — the in-memory
 * reply struct alone would not catch a body the serializer drops. */
static char *listunspent_mock_rpc(const char *method,
                                  const char *params_json)
{
    (void)params_json;
    if (strcmp(method, "listunspent") == 0)
        return strdup(
            "[{\"txid\":\"aabbccddeeff00112233445566778899aabbccddeeff0011"
            "2233445566778899\",\"vout\":0,"
            "\"address\":\"t1Rv4ex2u7SG2G9hD9WjvjR1x4mZ3nQabcd\","
            "\"amount\":1.5,\"confirmations\":12,"
            "\"spendable\":true,\"solvable\":true},"
            "{\"txid\":\"00112233445566778899aabbccddeeff0011223344556677"
            "8899aabbccddeeff\",\"vout\":1,"
            "\"amount\":0.25,\"confirmations\":3,"
            "\"spendable\":true,\"solvable\":true}]");
    return strdup("null");
}

static int test_wallet_utxo_list_envelope(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.wallet.utxo.list wraps the bare RPC array in its declared "
        "zcl.wallet_utxos.v1 envelope") {
        const struct zcl_command_spec *s =
            find_spec(reg, "core.wallet.utxo.list");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT(s->handler == zcl_native_bridge_command);
        ASSERT_STR_EQ(s->output_schema, "zcl.wallet_utxos.v1");
        ASSERT(bridge_has_exact_binding("core.wallet.utxo.list"));

        node_rpc_client_set_test_hook(listunspent_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&root, "schema")),
                      "zcl.result.v1");
        ASSERT(json_get_bool(json_get(&root, "ok")));

        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(data, "schema")),
                      "zcl.wallet_utxos.v1");
        const struct json_value *utxos = json_get(data, "utxos");
        ASSERT(utxos != NULL && utxos->type == JSON_ARR);
        ASSERT_EQ((int64_t)utxos->num_children, (int64_t)2);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(utxos, 0), "txid")),
                      "aabbccddeeff00112233445566778899aabbccddeeff0011"
                      "2233445566778899");
        ASSERT_EQ(json_get_int(json_get(data, "count")), (int64_t)2);
        ASSERT_EQ(json_get_int(json_get(data, "minconf")), (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(data, "maxconf")), (int64_t)9999999);
        json_free(&root);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* POINT 3.4: a TRANSIENT/DEPENDENCY blocker never drives `primary_blocker`
 * (PERMANENT/RESOURCE-only headline, unchanged) so an overdue one could
 * otherwise sit invisible behind a "healthy" brief. Proves the registry's
 * overdue_transient_count/overdue_transient_dominant_id (event_agent_summary.c)
 * surface into the brief as overdue_transient_count/overdue_transient_note
 * (status_brief_native_handler.c), beside the existing active_blockers/
 * blocker_head fields, without ever becoming primary_blocker. */
static int test_status_brief_overdue_transient_surfaces(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief surfaces overdue_transient_count/note from the "
         "typed-blocker registry without promoting it to primary_blocker") {
        const struct zcl_command_spec *s =
            find_spec(reg, "core.status.brief");
        ASSERT(s != NULL);

        static const char fixture[] =
            "{\"schema\":\"zcl.public_status.v2\","
            "\"partial_result\":false,"
            "\"served_height\":100,\"header_height\":100,"
            "\"served_height_known\":true,"
            "\"header_height_known\":true,"
            "\"gap\":0,\"peer_best_height\":100,"
            "\"peer_best_height_known\":true,"
            "\"target_height\":100,\"target_height_known\":true,"
            "\"chain_evidence_consistent\":true,"
            "\"sync_state\":\"at_tip\",\"serving\":true,"
            "\"healthy\":true,\"primary_blocker\":\"none\","
            "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                "\"budget_ms\":250,\"partial_result\":false,"
                "\"budget_exceeded\":false},"
            "\"peers\":{\"total\":1},"
            "\"conditions\":{"
                "\"schema\":\"zcl.condition_engine_summary.v2\","
                "\"active_count\":0},"
            "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                "\"rss_mb\":512},"
            "\"reducer\":{\"tip_advance_age_seconds\":3},"
            "\"security_posture\":{"
                "\"schema\":\"zcl.security_posture.v1\","
                "\"anchor_backfill_gap\":false,"
                "\"nullifier_backfill_gap\":false},"
            "\"blocker_registry\":{"
                "\"schema\":\"zcl.blocker_registry_summary.v1\","
                "\"active_count\":3,"
                "\"dominant_id\":\"chain_gap\","
                "\"dominant_class\":\"TRANSIENT\","
                "\"overdue_transient_count\":2,"
                "\"overdue_transient_dominant_id\":"
                    "\"catalog.address_index.lag_exceeded\","
                "\"native_state_command\":\"z23 dumpstate blocker\"}}";
        g_status_brief_agent_fixture = fixture;

        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);

        /* The healthy-looking headline is untouched. */
        ASSERT_STR_EQ(json_get_str(json_get(data, "primary_blocker")),
                      "none");
        ASSERT(json_get_bool(json_get(data, "healthy")));

        /* The registry truth is fully visible from the compact brief alone. */
        ASSERT_EQ(json_get_int(json_get(data, "active_blockers")),
                  (int64_t)3);
        ASSERT_STR_EQ(json_get_str(json_get(data, "blocker_head")),
                      "chain_gap");
        ASSERT_EQ(json_get_int(json_get(data, "overdue_transient_count")),
                  (int64_t)2);
        const char *note = json_get_str(
            json_get(data, "overdue_transient_note"));
        ASSERT(note != NULL);
        ASSERT(strstr(note, "2") != NULL);
        ASSERT(strstr(note, "catalog.address_index.lag_exceeded") != NULL);

        json_free(&root);
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* Absent/zero case: a node predating the field, or with nothing overdue,
 * must never fabricate overdue_transient_count=0 or an empty note. */
static int test_status_brief_overdue_transient_absent_when_zero(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief omits overdue_transient_count/note when the "
         "registry reports zero, never fabricates a zero/empty field") {
        const struct zcl_command_spec *s =
            find_spec(reg, "core.status.brief");
        ASSERT(s != NULL);

        static const char fixture[] =
            "{\"schema\":\"zcl.public_status.v2\","
            "\"partial_result\":false,"
            "\"served_height\":100,\"header_height\":100,"
            "\"served_height_known\":true,"
            "\"header_height_known\":true,"
            "\"gap\":0,\"peer_best_height\":100,"
            "\"peer_best_height_known\":true,"
            "\"target_height\":100,\"target_height_known\":true,"
            "\"chain_evidence_consistent\":true,"
            "\"sync_state\":\"at_tip\",\"serving\":true,"
            "\"healthy\":true,\"primary_blocker\":\"none\","
            "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                "\"budget_ms\":250,\"partial_result\":false,"
                "\"budget_exceeded\":false},"
            "\"peers\":{\"total\":1},"
            "\"conditions\":{"
                "\"schema\":\"zcl.condition_engine_summary.v2\","
                "\"active_count\":0},"
            "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                "\"rss_mb\":512},"
            "\"reducer\":{\"tip_advance_age_seconds\":3},"
            "\"security_posture\":{"
                "\"schema\":\"zcl.security_posture.v1\","
                "\"anchor_backfill_gap\":false,"
                "\"nullifier_backfill_gap\":false},"
            "\"blocker_registry\":{"
                "\"schema\":\"zcl.blocker_registry_summary.v1\","
                "\"active_count\":1,"
                "\"dominant_id\":\"chain_gap\","
                "\"dominant_class\":\"TRANSIENT\","
                "\"overdue_transient_count\":0,"
                "\"overdue_transient_dominant_id\":\"none\","
                "\"native_state_command\":\"z23 dumpstate blocker\"}}";
        g_status_brief_agent_fixture = fixture;

        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);

        ASSERT_EQ(json_get_int(json_get(data, "active_blockers")),
                  (int64_t)1);
        /* known-but-zero -> field present with value 0 (never omitted,
         * since the registry DID report a known count); the NOTE, however,
         * only exists when the count is positive. */
        ASSERT_EQ(json_get_int(json_get(data, "overdue_transient_count")),
                  (int64_t)0);
        ASSERT(json_get(data, "overdue_transient_note") == NULL);

        json_free(&root);
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* wf/status-tier-frontdoor: the trust-tier surface (agent.trust_tier +
 * security_posture.{snapshot_anchor_height,background_validation_height})
 * flattens into core.status.brief as tier/install_height/verified_height/
 * capabilities_locked — all OPTIONAL, so their presence here must not shrink
 * the field count test_status_brief_flat_lean_envelope's default fixture
 * asserts (that fixture carries neither sub-field, so those four keys stay
 * absent there; this is the PRESENT case). */
static int test_status_brief_trust_tier_surfaces(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief surfaces tier/install_height/verified_height/"
         "capabilities_locked from agent.trust_tier + security_posture") {
        const struct zcl_command_spec *s =
            find_spec(reg, "core.status.brief");
        ASSERT(s != NULL);

        static const char fixture[] =
            "{\"schema\":\"zcl.public_status.v2\","
            "\"partial_result\":false,"
            "\"served_height\":100,\"header_height\":100,"
            "\"served_height_known\":true,"
            "\"header_height_known\":true,"
            "\"gap\":0,\"peer_best_height\":100,"
            "\"peer_best_height_known\":true,"
            "\"target_height\":100,\"target_height_known\":true,"
            "\"chain_evidence_consistent\":true,"
            "\"sync_state\":\"at_tip\",\"serving\":true,"
            "\"healthy\":true,\"primary_blocker\":\"none\","
            "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                "\"budget_ms\":250,\"partial_result\":false,"
                "\"budget_exceeded\":false},"
            "\"peers\":{\"total\":1},"
            "\"conditions\":{"
                "\"schema\":\"zcl.condition_engine_summary.v2\","
                "\"active_count\":0},"
            "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                "\"rss_mb\":512},"
            "\"reducer\":{\"tip_advance_age_seconds\":3},"
            "\"security_posture\":{"
                "\"schema\":\"zcl.security_posture.v1\","
                "\"anchor_backfill_gap\":false,"
                "\"nullifier_backfill_gap\":false,"
                "\"snapshot_anchor_height\":3000000,"
                "\"background_validation_height\":2500000},"
            "\"trust_tier\":{"
                "\"schema\":\"zcl.trust_tier.v1\","
                "\"trust_mode\":\"release_assisted\","
                "\"trust_state\":\"release_assisted_ready\","
                "\"durable_store_status\":\"available\","
                "\"mint_denied\":true,\"wallet_spend_denied\":true,"
                "\"export_bundle_denied\":true,"
                "\"capabilities_denied\":\"mint,wallet_spend,export_bundle\","
                "\"served_from_cache\":false,\"cache_age_ms\":0}}";
        g_status_brief_agent_fixture = fixture;

        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);

        ASSERT_STR_EQ(json_get_str(json_get(data, "tier")),
                      "release_assisted");
        ASSERT_EQ(json_get_int(json_get(data, "install_height")),
                  (int64_t)3000000);
        ASSERT_EQ(json_get_int(json_get(data, "verified_height")),
                  (int64_t)2500000);
        ASSERT_STR_EQ(json_get_str(json_get(data, "capabilities_locked")),
                      "mint,wallet_spend,export_bundle");

        json_free(&root);
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* Absent case: a node predating agent.trust_tier and the two security_
 * posture heights (an older-schema-family document, or a current v2 document
 * that simply hasn't populated them yet) must omit all four keys, never
 * fabricate a placeholder tier or a zero height. Reuses the DEFAULT
 * status_brief_mock_rpc fixture (no g_status_brief_agent_fixture override),
 * which carries neither sub-field. */
static int test_status_brief_trust_tier_absent_when_missing(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief omits tier/install_height/verified_height/"
         "capabilities_locked when the source document predates them") {
        const struct zcl_command_spec *s =
            find_spec(reg, "core.status.brief");
        ASSERT(s != NULL);

        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        bool dispatched = exec_leaf(reg, s, out, sizeof(out), &code);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(dispatched);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);

        ASSERT(json_get(data, "tier") == NULL);
        ASSERT(json_get(data, "install_height") == NULL);
        ASSERT(json_get(data, "verified_height") == NULL);
        ASSERT(json_get(data, "capabilities_locked") == NULL);

        json_free(&root);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_status_brief_composite_fails_closed(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief rejects RPC errors, unrecognized schemas, and wrong "
        "field types") {
        static const char *const cases[] = {
            "{\"code\":-32601,\"message\":\"Method not found\"}",
            "{\"error\":{\"code\":-32603,"
                "\"message\":\"cannot connect to node\"}}",
            /* Outside the known zcl.public_status.* family entirely (not a
             * version-skew case -- see
             * test_status_brief_schema_skew_degrades_gracefully for a
             * PRESENT-but-older/newer zcl.public_status.vN schema, which
             * now degrades instead of failing closed). */
            "{\"schema\":\"zcl.other_status.v1\"}",
            "{\"schema\":\"zcl.public_status.v2\","
                "\"served_height\":\"3117073\"}",
        };
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        /* RPC error objects (cases 0-1) surface the REAL transport/RPC
         * reason verbatim ("node status unavailable: ..."); a completely
         * unrecognized schema and a genuine field fault (cases 2-3) read as
         * a schema error. The version named is the one the DOCUMENT declared
         * when this build strictly reads it (case 3 is a v2 document, so the
         * error says v2); an out-of-family schema has no version to name, so
         * case 2 names the contract this build targets. Transport absence is
         * retryable; a malformed producer contract is not. */
        static const char *const expect_msg[] = {
            "node status unavailable: Method not found",
            "node status unavailable: cannot connect to node",
            "invalid zcl.public_status.v3",
            "invalid zcl.public_status.v2",
        };
        static const enum zcl_command_exit expect_exit[] = {
            ZCL_COMMAND_EXIT_TRANSIENT,
            ZCL_COMMAND_EXIT_TRANSIENT,
            ZCL_COMMAND_EXIT_INTERNAL,
            ZCL_COMMAND_EXIT_INTERNAL,
        };
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            g_status_brief_agent_fixture = cases[i];
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, expect_exit[i]);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            ASSERT(strstr(out, i < 2 ? "\"status\":\"blocked\""
                                    : "\"status\":\"failed\"") != NULL);
            ASSERT(strstr(out, i < 2 ? "\"retryable\":true"
                                    : "\"retryable\":false") != NULL);
            ASSERT(strstr(out, "\"code\":\"TOOL_ERROR\"") != NULL);
            ASSERT(strstr(out, expect_msg[i]) != NULL);
        }
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* wf/status-front-door: a PRESENT schema in the known zcl.public_status.*
 * family that is not the exact version the strict validator checks (an
 * older node's v1, a future v4) used to fall into the SAME hard
 * "invalid zcl.public_status.v2: missing/invalid field schema" error as
 * genuine corruption -- indistinguishable from a real bug. It now degrades
 * gracefully: whatever of the flat brief the differently-versioned document
 * still carries is surfaced, with `partial_result`/`schema_skew` naming the
 * mismatch, rather than failing the flagless `z23 status` front
 * door outright. A schema OUTSIDE the family, or one PRESENT-but-malformed
 * exact v2 field, must still fail closed (test_status_brief_composite_fails_
 * closed / test_status_brief_names_first_failing_field cover those). */
static int test_status_brief_schema_skew_degrades_gracefully(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief degrades a different zcl.public_status.vN "
        "schema instead of hard-failing") {
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);

        /* An older node (v1) still carries the fields this CLI knows about
         * under the SAME names -- those must come through untouched. */
        static const char older[] =
            "{\"schema\":\"zcl.public_status.v1\","
            "\"served_height\":100,\"served_height_known\":true,"
            "\"header_height\":101,\"header_height_known\":true,"
            "\"gap\":1,\"sync_state\":\"syncing\",\"serving\":true,"
            "\"healthy\":false,\"primary_blocker\":\"body_fetch.stalled\"}";
        g_status_brief_agent_fixture = older;
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"ok\":true") != NULL);
        ASSERT(strstr(out, "missing/invalid field") == NULL);

        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);
        ASSERT_EQ(json_get_int(json_get(data, "hstar")), (int64_t)100);
        ASSERT_EQ(json_get_int(json_get(data, "header_height")),
                  (int64_t)101);
        ASSERT_EQ(json_get_int(json_get(data, "gap")), (int64_t)1);
        ASSERT_STR_EQ(json_get_str(json_get(data, "sync_state")), "syncing");
        ASSERT(json_get_bool(json_get(data, "serving")));
        ASSERT(!json_get_bool(json_get(data, "healthy")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "primary_blocker")),
                      "body_fetch.stalled");
        ASSERT(json_get_bool(json_get(data, "partial_result")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "schema_skew")),
                      "zcl.public_status.v1");
        json_free(&root);

        /* A newer node (v4) whose document this CLI build recognizes
         * nothing else about still degrades to an all-unknown-but-ok brief
         * instead of failing. (v3 and v2 are BOTH validated strictly by this
         * build, so neither is a skew case — see
         * status_schema_is_strictly_read().) */
        static const char newer[] = "{\"schema\":\"zcl.public_status.v4\"}";
        g_status_brief_agent_fixture = newer;
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);
        ASSERT(json_is_null(json_get(data, "hstar")));
        ASSERT(json_is_null(json_get(data, "sync_state")));
        ASSERT(!json_get_bool(json_get(data, "serving")));
        ASSERT_STR_EQ(json_get_str(json_get(data, "schema_skew")),
                      "zcl.public_status.v4");
        json_free(&root);

        /* An ENTIRELY ABSENT schema key is unchanged: still the harder
         * "node binary predates the CLI contract" version-skew failure, not
         * the new graceful degrade (which requires a schema value to name). */
        static const char no_schema[] = "{\"served_height\":100}";
        g_status_brief_agent_fixture = no_schema;
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
        ASSERT(strstr(out, "predates the CLI contract") != NULL);
        ASSERT(strstr(out, "field schema") != NULL);

        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static void status_brief_fixture_write(
    char *out, size_t out_size,
    int64_t served, bool served_known,
    int64_t header, bool header_known,
    int64_t peer_best, bool peer_best_known,
    int64_t target, bool target_known,
    int64_t gap, bool chain_consistent,
    int64_t tip_age, bool partial, bool include_resources,
    bool serving, bool healthy, bool budget_exceeded,
    bool anchor_gap, bool nullifier_gap)
{
    (void)snprintf(
        out, out_size,
        "{\"schema\":\"zcl.public_status.v2\","
        "\"partial_result\":%s%s,"
        "\"served_height\":%lld,\"served_height_known\":%s,"
        "\"header_height\":%lld,\"header_height_known\":%s,"
        "\"gap\":%lld,\"peer_best_height\":%lld,"
        "\"peer_best_height_known\":%s,"
        "\"target_height\":%lld,\"target_height_known\":%s,"
        "\"chain_evidence_consistent\":%s,"
        "\"sync_state\":\"idle\",\"serving\":%s,\"healthy\":%s,"
        "\"primary_blocker\":\"none\","
        "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
        "\"budget_ms\":250,\"partial_result\":%s,"
        "\"budget_exceeded\":%s},"
        "\"peers\":{\"total\":0},"
        "\"conditions\":{"
        "\"schema\":\"zcl.condition_engine_summary.v2\","
        "\"active_count\":0},%s"
        "\"reducer\":{\"tip_advance_age_seconds\":%lld},"
        "\"security_posture\":{"
        "\"schema\":\"zcl.security_posture.v1\","
        "\"anchor_backfill_gap\":%s,"
        "\"nullifier_backfill_gap\":%s}}",
        partial ? "true" : "false",
        partial ? ",\"partial_reason\":\"optional_detail_budget_guard:resources\""
                : "",
        (long long)served, served_known ? "true" : "false",
        (long long)header, header_known ? "true" : "false",
        (long long)gap, (long long)peer_best,
        peer_best_known ? "true" : "false", (long long)target,
        target_known ? "true" : "false",
        chain_consistent ? "true" : "false",
        serving ? "true" : "false", healthy ? "true" : "false",
        partial ? "true" : "false",
        budget_exceeded ? "true" : "false",
        include_resources
            ? "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
              "\"rss_mb\":512},"
            : "",
        (long long)tip_age, anchor_gap ? "true" : "false",
        nullifier_gap ? "true" : "false");
}

static int test_status_brief_valid_unknown_and_partial_contracts(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char fixture[2048];
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief preserves valid boot/no-peer/partial unknowns") {
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);

        /* Fresh boot: no selected frontier, header, peer height, or tip-age
         * sample is a valid v1 response, not schema skew. */
        status_brief_fixture_write(
            fixture, sizeof(fixture), 0, false, -1, false, -1, false,
            0, false, 0, false, -1, false, true,
            false, false, false, false, false);
        g_status_brief_agent_fixture = fixture;
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        struct json_value root;
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        const struct json_value *data = json_get(&root, "data");
        ASSERT(data && data->type == JSON_OBJ);
        ASSERT(json_is_null(json_get(data, "hstar")));
        ASSERT(json_is_null(json_get(data, "header_height")));
        ASSERT(json_is_null(json_get(data, "gap")));
        ASSERT(json_is_null(json_get(data, "peer_best")));
        ASSERT(json_is_null(json_get(data, "tip_advance_age_seconds")));
        ASSERT_EQ(json_get_int(json_get(data, "peer_count")), (int64_t)0);
        json_free(&root);

        /* The producer intentionally omits resources when its optional-detail
         * guard fires before the 250ms first-call budget. */
        status_brief_fixture_write(
            fixture, sizeof(fixture), 100, true, 101, true, -1, false,
            101, true, 1, true, 3, true, false,
            true, true, false, false, false);
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(data && json_is_null(json_get(data, "rss_mb")));
        ASSERT_EQ(json_get_int(json_get(data, "hstar")), (int64_t)100);
        json_free(&root);

        /* Causal shielded gaps outrank the general latch without changing the
         * honest unknown peer projection. */
        status_brief_fixture_write(
            fixture, sizeof(fixture), 100, true, 101, true, -1, false,
            101, true, 1, true, 3, false, true,
            true, false, false, true, true);
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT_STR_EQ(json_get_str(json_get(data, "primary_blocker")),
                      "utxo_apply.anchor_backfill_gap");
        ASSERT(json_get_bool(json_get(data, "serving")));
        ASSERT(!json_get_bool(json_get(data, "healthy")));
        json_free(&root);

        /* The node's OWN first call overran its 250ms budget (the busiest,
         * most-needed-diagnostic moment: e.g. a post-restart fold under
         * heavy IO). It truthfully reports budget_exceeded=true and admits
         * partial_result=true rather than lying about completeness. This
         * degraded-but-honest envelope must still VALIDATE -- the operator
         * needs it most exactly when it looks like this. Regression for the
         * live bug: an earlier validator required budget_exceeded==false,
         * so the node's own truthful "I'm slow" signal was rejected as
         * "invalid zcl.public_status.v2: missing/invalid field
         * first_call.budget_exceeded". */
        status_brief_fixture_write(
            fixture, sizeof(fixture), 100, true, 101, true, -1, false,
            101, true, 1, true, 3, true, false,
            true, true, true, false, false);
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT(json_get_bool(json_get(data, "serving")));
        ASSERT_EQ(json_get_int(json_get(data, "hstar")), (int64_t)100);
        json_free(&root);

        /* Over budget yet COMPLETE (budget_exceeded=true, partial_result=
         * false, resources present) is equally honest and must validate:
         * budget overrun is a timing fact, orthogonal to completeness. */
        status_brief_fixture_write(
            fixture, sizeof(fixture), 100, true, 101, true, -1, false,
            101, true, 1, true, 3, false, true,
            true, true, true, false, false);
        code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
        data = json_get(&root, "data");
        ASSERT_EQ(json_get_int(json_get(data, "hstar")), (int64_t)100);
        json_free(&root);
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_status_brief_rejects_contract_contradictions(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char fixture[2048];
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief rejects known/sentinel, gap, and partial faults") {
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);
        /* budget_exceeded=true with partial_result=false is NOT a
         * contradiction and is no longer rejected: budget overrun is a pure
         * timing fact, orthogonal to data completeness — a busy node that
         * overran 250ms while still collecting every field reports exactly
         * that, truthfully. The valid case is covered in
         * test_status_brief_valid_unknown_and_partial_contracts. */
        static const int cases = 3;
        for (int i = 0; i < cases; i++) {
            if (i == 0) {
                /* known peer height may not carry the -1 sentinel. */
                status_brief_fixture_write(
                    fixture, sizeof(fixture), 100, true, 101, true, -1, true,
                    101, true, 1, true, 3, false, true,
                    true, true, false, false, false);
            } else if (i == 1) {
                /* A consistent chain's gap is exact header-H*. */
                status_brief_fixture_write(
                    fixture, sizeof(fixture), 100, true, 101, true, 101, true,
                    101, true, 9, true, 3, false, true,
                    true, true, false, false, false);
            } else {
                /* Full results cannot silently omit the resources member. */
                status_brief_fixture_write(
                    fixture, sizeof(fixture), 100, true, 101, true, 101, true,
                    101, true, 1, true, 3, false, false,
                    true, true, false, false, false);
            }
            g_status_brief_agent_fixture = fixture;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            ASSERT(strstr(out, "\"code\":\"TOOL_ERROR\"") != NULL);
        }
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* A fully valid zcl.public_status.v2 document. v2 is still validated
 * STRICTLY (the retained v2 reader — see status_schema_is_strictly_read), so
 * every fixture in this file that names v2 doubles as coverage that an older
 * node's document keeps working after the v3 bump. It mirrors
 * status_brief_mock_rpc's default fixture, so each case below can drop or
 * corrupt exactly one field and prove the resulting error names that field
 * instead of one opaque "invalid public status" message. */
static const char g_status_brief_valid_doc[] =
    "{\"schema\":\"zcl.public_status.v2\","
    "\"partial_result\":false,"
    "\"served_height\":3117073,\"header_height\":3117074,"
    "\"served_height_known\":true,"
    "\"header_height_known\":true,"
    "\"gap\":1,\"peer_best_height\":3117074,"
    "\"peer_best_height_known\":true,"
    "\"target_height\":3117074,\"target_height_known\":true,"
    "\"chain_evidence_consistent\":true,"
    "\"sync_state\":\"at_tip\",\"serving\":true,"
    "\"healthy\":true,\"primary_blocker\":\"none\","
    "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
        "\"budget_ms\":250,\"partial_result\":false,"
        "\"budget_exceeded\":false},"
    "\"peers\":{\"total\":1},"
    "\"conditions\":{"
        "\"schema\":\"zcl.condition_engine_summary.v2\","
        "\"active_count\":2},"
    "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
        "\"rss_mb\":512},"
    "\"reducer\":{\"tip_advance_age_seconds\":3},"
    "\"security_posture\":{"
        "\"schema\":\"zcl.security_posture.v1\","
        "\"anchor_backfill_gap\":false,"
        "\"nullifier_backfill_gap\":false}}";

/* E1: the composite validation used to collapse ~30 predicates into one
 * opaque "invalid public status" message. Each case here removes (or
 * corrupts) exactly one representative field from an otherwise-valid
 * document and proves the error names that exact field, and correctly
 * classifies an entirely-absent key (an older node binary's `agent` RPC
 * predating a newer field) as schema/version skew rather than a generic
 * malformed-document error. */
static int test_status_brief_names_first_failing_field(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("core.status.brief names the first failing public-status field") {
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);

        /* Case 1: an entirely-absent top-level bool field (as an older node
         * binary's agent RPC would omit) -> named + classified as version
         * skew, not a generic malformed-document error. */
        {
            const char *removed =
                "{\"schema\":\"zcl.public_status.v2\","
                "\"partial_result\":false,"
                "\"served_height\":3117073,\"header_height\":3117074,"
                "\"served_height_known\":true,"
                "\"header_height_known\":true,"
                "\"gap\":1,\"peer_best_height\":3117074,"
                "\"peer_best_height_known\":true,"
                "\"target_height\":3117074,\"target_height_known\":true,"
                "\"sync_state\":\"at_tip\",\"serving\":true,"
                "\"healthy\":true,\"primary_blocker\":\"none\","
                "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                    "\"budget_ms\":250,\"partial_result\":false,"
                    "\"budget_exceeded\":false},"
                "\"peers\":{\"total\":1},"
                "\"conditions\":{"
                    "\"schema\":\"zcl.condition_engine_summary.v2\","
                    "\"active_count\":2},"
                "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                    "\"rss_mb\":512},"
                "\"reducer\":{\"tip_advance_age_seconds\":3},"
                "\"security_posture\":{"
                    "\"schema\":\"zcl.security_posture.v1\","
                    "\"anchor_backfill_gap\":false,"
                    "\"nullifier_backfill_gap\":false}}";
            g_status_brief_agent_fixture = removed;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
            ASSERT(strstr(out, "chain_evidence_consistent") != NULL);
            ASSERT(strstr(out, "predates the CLI contract") != NULL);
        }

        /* Case 2: an entirely-absent nested object (a whole newer subsystem
         * projection an older node never emitted) -> named + version skew. */
        {
            const char *removed =
                "{\"schema\":\"zcl.public_status.v2\","
                "\"partial_result\":false,"
                "\"served_height\":3117073,\"header_height\":3117074,"
                "\"served_height_known\":true,"
                "\"header_height_known\":true,"
                "\"gap\":1,\"peer_best_height\":3117074,"
                "\"peer_best_height_known\":true,"
                "\"target_height\":3117074,\"target_height_known\":true,"
                "\"chain_evidence_consistent\":true,"
                "\"sync_state\":\"at_tip\",\"serving\":true,"
                "\"healthy\":true,\"primary_blocker\":\"none\","
                "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                    "\"budget_ms\":250,\"partial_result\":false,"
                    "\"budget_exceeded\":false},"
                "\"peers\":{\"total\":1},"
                "\"conditions\":{"
                    "\"schema\":\"zcl.condition_engine_summary.v2\","
                    "\"active_count\":2},"
                "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                    "\"rss_mb\":512},"
                "\"reducer\":{\"tip_advance_age_seconds\":3}}";
            g_status_brief_agent_fixture = removed;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
            ASSERT(strstr(out, "security_posture") != NULL);
            ASSERT(strstr(out, "predates the CLI contract") != NULL);
        }

        /* Case 3: a field that is PRESENT but the wrong JSON type -> named,
         * but classified as malformed, not version skew (the key exists;
         * its value just violates the contract). */
        {
            const char *malformed =
                "{\"schema\":\"zcl.public_status.v2\","
                "\"partial_result\":false,"
                "\"served_height\":3117073,\"header_height\":3117074,"
                "\"served_height_known\":true,"
                "\"header_height_known\":true,"
                "\"gap\":1,\"peer_best_height\":3117074,"
                "\"peer_best_height_known\":true,"
                "\"target_height\":3117074,\"target_height_known\":true,"
                "\"chain_evidence_consistent\":true,"
                "\"sync_state\":\"at_tip\",\"serving\":true,"
                "\"healthy\":\"yes\",\"primary_blocker\":\"none\","
                "\"first_call\":{\"schema\":\"zcl.first_call_contract.v1\","
                    "\"budget_ms\":250,\"partial_result\":false,"
                    "\"budget_exceeded\":false},"
                "\"peers\":{\"total\":1},"
                "\"conditions\":{"
                    "\"schema\":\"zcl.condition_engine_summary.v2\","
                    "\"active_count\":2},"
                "\"resources\":{\"schema\":\"zcl.node_resources.v1\","
                    "\"rss_mb\":512},"
                "\"reducer\":{\"tip_advance_age_seconds\":3},"
                "\"security_posture\":{"
                    "\"schema\":\"zcl.security_posture.v1\","
                    "\"anchor_backfill_gap\":false,"
                    "\"nullifier_backfill_gap\":false}}";
            g_status_brief_agent_fixture = malformed;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
            ASSERT(strstr(out, "\"healthy\"") != NULL ||
                   strstr(out, "field healthy") != NULL);
            ASSERT(strstr(out, "predates the CLI contract") == NULL);
            ASSERT(strstr(out, "missing/invalid field healthy") != NULL);
        }

        /* Baseline: the fully valid document names nothing and passes. */
        {
            g_status_brief_agent_fixture = g_status_brief_valid_doc;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        }
        PASS();
    } _test_next:;
    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* Lane S1 regression: the very first command a new user runs
 * (`z23 status`) must come back ok:true, schema-valid, and well
 * under its latency budget -- both on a healthy caught-up node and on a
 * fresh node that has not synced anything yet. The live bug this guards
 * against surfaced as "invalid zcl.public_status.v2: missing/invalid field
 * schema" together with an elapsed_ms far past budget_ms; assert all three
 * properties together, on both fixtures, rather than leaving them scattered
 * across the other status_brief_* tests above. */
int command_registry_status_latency_contract(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status.brief");
    char fixture[2048];
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];

    TEST("core.status.brief is schema-valid and fast on both a "
         "healthy node and a fresh not-yet-synced node") {
        ASSERT(s != NULL);
        node_rpc_client_set_test_hook(status_brief_mock_rpc);

        /* Case 1: healthy, at tip (status_brief_mock_rpc's default fixture). */
        {
            g_status_brief_agent_fixture = NULL;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(out, "\"ok\":true") != NULL);

            struct json_value root;
            ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
            ASSERT_STR_EQ(json_get_str(json_get(&root, "schema")),
                          "zcl.result.v1");
            ASSERT_STR_EQ(json_get_str(json_get(&root, "status")), "passed");
            int64_t budget_ms = json_get_int(json_get(&root, "budget_ms"));
            int64_t elapsed_ms = json_get_int(json_get(&root, "elapsed_ms"));
            ASSERT(budget_ms > 0);
            ASSERT(elapsed_ms >= 0 && elapsed_ms < budget_ms);
            ASSERT(!json_get_bool(json_get(&root, "budget_exceeded")));
            const struct json_value *data = json_get(&root, "data");
            ASSERT(data != NULL && data->type == JSON_OBJ);
            ASSERT(json_get_bool(json_get(data, "healthy")));
            json_free(&root);
        }

        /* Case 2: brand-new datadir -- nothing served, no header/peer-height
         * evidence, chain evidence not yet consistent -- every fact honestly
         * unknown rather than fabricated, but still a complete, valid
         * document that must degrade gracefully, never error. */
        {
            status_brief_fixture_write(
                fixture, sizeof(fixture), 0, false, -1, false, -1, false,
                0, false, 0, false, -1, false, true,
                false, false, false, false, false);
            g_status_brief_agent_fixture = fixture;
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
            ASSERT(strstr(out, "\"ok\":true") != NULL);

            struct json_value root;
            ASSERT(json_read(&root, out, strlen(out)) && root.type == JSON_OBJ);
            ASSERT_STR_EQ(json_get_str(json_get(&root, "schema")),
                          "zcl.result.v1");
            ASSERT_STR_EQ(json_get_str(json_get(&root, "status")), "passed");
            int64_t budget_ms = json_get_int(json_get(&root, "budget_ms"));
            int64_t elapsed_ms = json_get_int(json_get(&root, "elapsed_ms"));
            ASSERT(budget_ms > 0);
            ASSERT(elapsed_ms >= 0 && elapsed_ms < budget_ms);
            ASSERT(!json_get_bool(json_get(&root, "budget_exceeded")));
            const struct json_value *data = json_get(&root, "data");
            ASSERT(data != NULL && data->type == JSON_OBJ);
            ASSERT(json_is_null(json_get(data, "hstar")));
            ASSERT(!json_get_bool(json_get(data, "serving")));
            ASSERT(!json_get_bool(json_get(data, "healthy")));
            json_free(&root);
        }
        PASS();
    } _test_next:;

    g_status_brief_agent_fixture = NULL;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_planned_fail_closed(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("every planned leaf blocks with exit 3 and no handler") {
        int checked = 0;
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (s->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            if (s->availability != ZCL_COMMAND_PLANNED)
                continue;
            ASSERT(s->handler == NULL);
            ASSERT(s->availability_reason && s->availability_reason[0]);
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_BLOCKED);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            ASSERT(strstr(out, "COMMAND_PLANNED") != NULL);
            checked++;
        }
        ASSERT(checked > 5);
        PASS();
    } _test_next:;
    return failures;
}

static int test_envelope_vectors(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("a local discovery leaf returns a passing common envelope") {
        const struct zcl_command_spec *s = find_spec(reg, "discover.describe");
        ASSERT(s != NULL);
        struct zcl_command_context ctx = {
            .registry = reg, .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "path", "core.status");
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = zcl_command_registry_execute_json(
            reg, s, &ctx, &input, false, "discover.describe", "normal", 0, 0,
            NULL, out, sizeof(out), &code);
        json_free(&input);
        ASSERT(n > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"schema\":\"zcl.result.v1\"") != NULL);
        ASSERT(strstr(out, "\"ok\":true") != NULL);
        ASSERT(strstr(out, "core.status") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_typo_stays_branch(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("a typo under a canonical branch resolves to the branch, not a leaf") {
        /* `core chain bogus`: longest path is the core.chain BRANCH with the
         * unknown word left over. The adapter turns this into the structured
         * unknown-command error; the registry never invents a leaf for it, so
         * it can never fall through to an arbitrary RPC method. */
        const char *words[] = { "core", "chain", "bogus" };
        size_t consumed = 0;
        bool alias = false;
        char invoked[ZCL_COMMAND_MAX_PATH];
        const struct zcl_command_spec *s = zcl_command_registry_resolve_words(
            reg, words, 3, &consumed, &alias, invoked, sizeof(invoked));
        ASSERT(s != NULL);
        ASSERT_STR_EQ(s->path, "core.chain");
        ASSERT_EQ(s->mode, ZCL_COMMAND_MODE_BRANCH);
        ASSERT_EQ(consumed, (size_t)2);
        ASSERT(find_spec(reg, "core.chain.bogus") == NULL);
        ASSERT(zcl_command_registry_find(reg, "core.chain.bogus", NULL) ==
               NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dev_branch_leaves(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("dev branch carries the expected ready/planned leaf availability") {
        const struct zcl_command_spec *dev = find_spec(reg, "dev");
        ASSERT(dev != NULL);
        ASSERT_EQ(dev->mode, ZCL_COMMAND_MODE_BRANCH);

        const char *ready[] = {
            "dev.status", "dev.core.boundary", "dev.app.describe",
            "dev.app.plan", "dev.app.simulate", "dev.change.plan",
            "dev.app.list", "dev.test.plan",
        };
        for (size_t i = 0; i < sizeof(ready) / sizeof(ready[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, ready[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT(s->handler != NULL);
        }
        /* Unfinished dev operations are explicitly planned + handlerless, so
         * discovery can never advertise a dev command that cannot dispatch. */
        const char *planned[] = {
            "dev.core.proof", "dev.app.inspect", "dev.test.replay",
            "dev.generation.rollback",
        };
        for (size_t i = 0; i < sizeof(planned) / sizeof(planned[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, planned[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_PLANNED);
            ASSERT(s->handler == NULL);
        }
        /* Dev executors are real handlers only in ZCL_DEV_BUILD.  This test
         * binary is a release-shaped catalog, so those leaves must remain
         * explicit COMPAT entries rather than falsely READY. */
        const char *compat[] = {
            "dev.change.apply", "dev.begin", "dev.drive",
            "dev.publication.mirror.record",
            "dev.loop.ensure", "dev.loop.status",
            "dev.loop.wait", "dev.loop.events", "dev.loop.stop", "dev.test.run",
            "dev.test.sim", "dev.generation.current",
            "dev.generation.history", "dev.diagnose.latest",
            "dev.diagnose.show",
            "dev.vcs.revert", "dev.vcs.seal.grant",
        };
        for (size_t i = 0; i < sizeof(compat) / sizeof(compat[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, compat[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_COMPAT);
            ASSERT(s->handler == NULL);
            ASSERT(s->compat_target != NULL && s->compat_target[0]);
        }

        const struct zcl_command_spec *failure_latest =
            find_spec(reg, "dev.diagnose.latest");
        const struct zcl_command_spec *failure_show =
            find_spec(reg, "dev.diagnose.show");
        ASSERT(failure_latest != NULL && failure_show != NULL);
        ASSERT_STR_EQ(failure_latest->output_schema,
                      "zcl.dev_failure_latest_result.v1");
        ASSERT_EQ(failure_latest->budget_bytes, (size_t)2048);
        ASSERT_STR_EQ(failure_show->output_schema,
                      "zcl.dev_failure_show.v1");
        ASSERT_EQ(failure_show->budget_bytes, (size_t)6144);
        ASSERT_STR_EQ(failure_show->positional_keys, "failure_id");

        const struct zcl_command_spec *loop_wait =
            find_spec(reg, "dev.loop.wait");
        ASSERT(loop_wait != NULL);
        ASSERT_EQ(loop_wait->budget_bytes,
                  (size_t)ZCL_COMMAND_LIST_BUDGET);

        PASS();
    } _test_next:;
    return failures;
}

/* Build a body larger than the ordinary-result budget: several long scalar
 * fields plus one nested container, so projection must drop or page. */
static void make_large_body(struct json_value *body)
{
    char big[420];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    json_init(body);
    json_set_object(body);
    for (int i = 0; i < 8; i++) {
        char key[16];
        (void)snprintf(key, sizeof(key), "s%d", i);
        (void)json_push_kv_str(body, key, big);
    }
    struct json_value nested;
    json_init(&nested);
    json_set_object(&nested);
    (void)json_push_kv_str(&nested, "a", big);
    (void)json_push_kv_str(&nested, "b", big);
    (void)json_push_kv(body, "nested", &nested);
    json_free(&nested);
}

static int test_response_budget_views(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *s = find_spec(reg, "core.status");
    char scratch[ZCL_COMMAND_LIST_BUDGET + 1];

    TEST("bridge projection: summary/normal/full page a too-large body") {
        ASSERT(s != NULL);

        /* summary: drop containers, fit the ordinary-result budget. */
        struct json_value body;
        make_large_body(&body);
        struct zcl_command_request req = { .spec = s, .view = "summary" };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, s->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        size_t n = json_write(&reply.data, scratch, sizeof(scratch));
        ASSERT(n > 0 && n <= ZCL_COMMAND_RESULT_BUDGET);
        ASSERT(json_get(&reply.data, "nested") == NULL);
        const struct json_value *page = json_get(&reply.data, "_page");
        ASSERT(page != NULL && page->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(page, "view")), "summary");
        ASSERT(json_get(page, "truncated") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&body);

        /* normal: truncate, expose an advancing cursor, and point at the
         * command contract without emitting a self-loop. */
        make_large_body(&body);
        req = (struct zcl_command_request){ .spec = s, .view = "normal" };
        zcl_command_reply_init(&reply, s->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        n = json_write(&reply.data, scratch, sizeof(scratch));
        ASSERT(n > 0 && n <= ZCL_COMMAND_RESULT_BUDGET);
        page = json_get(&reply.data, "_page");
        ASSERT(page != NULL);
        const struct json_value *trunc = json_get(page, "truncated");
        ASSERT(trunc != NULL && trunc->type == JSON_BOOL && trunc->val.b);
        ASSERT(json_get(page, "next_cursor") != NULL);
        ASSERT(reply.next_count >= 1);
        ASSERT_STR_EQ(reply.next[0].command, "discover.describe");
        ASSERT(strstr(reply.next[0].input_json, "core.status") != NULL);
        zcl_command_reply_free(&reply);
        json_free(&body);

        /* full: honor --max-items and page via an advancing cursor. */
        make_large_body(&body);
        req = (struct zcl_command_request){
            .spec = s, .view = "full", .max_items = 3, .cursor = "0",
        };
        zcl_command_reply_init(&reply, s->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        page = json_get(&reply.data, "_page");
        ASSERT(page != NULL);
        ASSERT_EQ(json_get_int(json_get(page, "included")), (int64_t)3);
        const struct json_value *nc = json_get(page, "next_cursor");
        ASSERT(nc != NULL);
        ASSERT_EQ(json_get_int(nc), (int64_t)3);
        zcl_command_reply_free(&reply);
        json_free(&body);
        PASS();
    }
    TEST("peer list projection: slim rows fill the list budget; cursor continues") {
        const struct zcl_command_spec *peers =
            find_spec(reg, "core.network.peers.list");
        ASSERT(peers != NULL);
        struct json_value body;
        json_init(&body);
        json_set_array(&body);
        for (int i = 0; i < 29; i++) {
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_int(&row, "id", i);
            (void)json_push_kv_str(&row, "addr", "203.0.113.10:8033");
            (void)json_push_kv_str(&row, "subver", "/ZClassic23:0.1.0/");
            (void)json_push_kv_bool(&row, "zclassic23", true);
            (void)json_push_back(&body, &row);
            json_free(&row);
        }
        struct zcl_command_request req = { .spec = peers, .view = "normal" };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, peers->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        const struct json_value *page = json_get(&reply.data, "_page");
        ASSERT(page != NULL);
        ASSERT_EQ(json_get_int(json_get(page, "total_items")), (int64_t)29);
        ASSERT_EQ(json_get_int(json_get(page, "included")), (int64_t)29);
        ASSERT(!json_get_bool(json_get(page, "truncated")));
        zcl_command_reply_free(&reply);

        json_free(&body);
        json_init(&body);
        json_set_array(&body);
        {
            const struct {
                const char *addr;
                bool z23;
                bool bean;
            } mix[] = {
                { "203.0.113.1:8033", false, true },
                { "203.0.113.2:8033", false, true },
                { "203.0.113.10:8033", true, false },
            };
            for (size_t i = 0; i < 3; i++) {
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                (void)json_push_kv_int(&row, "id", (int64_t)i);
                (void)json_push_kv_str(&row, "addr", mix[i].addr);
                (void)json_push_kv_bool(&row, "zclassic23", mix[i].z23);
                (void)json_push_kv_bool(&row, "magicbean", mix[i].bean);
                (void)json_push_back(&body, &row);
                json_free(&row);
            }
        }
        req = (struct zcl_command_request){ .spec = peers, .view = "normal" };
        zcl_command_reply_init(&reply, peers->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        {
            const struct json_value *listed = json_get(&reply.data, "items");
            ASSERT(listed && listed->type == JSON_ARR &&
                   listed->num_children == 3);
            ASSERT(json_get_bool(json_get(&listed->children[0],
                                          "zclassic23")));
            ASSERT_STR_EQ(json_get_str(json_get(&listed->children[0], "addr")),
                          "203.0.113.10:8033");
            ASSERT(!json_get_bool(json_get(&listed->children[1],
                                           "zclassic23")));
        }
        zcl_command_reply_free(&reply);

        /* A fat nested blob must not stall the default view: cursor continues. */
        json_free(&body);
        json_init(&body);
        json_set_array(&body);
        char fat[1200];
        memset(fat, 'x', sizeof(fat) - 1);
        fat[sizeof(fat) - 1] = 0;
        for (int i = 0; i < 8; i++) {
            struct json_value row, life;
            json_init(&row);
            json_init(&life);
            json_set_object(&row);
            json_set_object(&life);
            (void)json_push_kv_int(&row, "id", i);
            (void)json_push_kv_str(&row, "addr", "203.0.113.10:8033");
            (void)json_push_kv_str(&life, "blob", fat);
            (void)json_push_kv(&row, "lifecycle", &life);
            (void)json_push_back(&body, &row);
            json_free(&life);
            json_free(&row);
        }
        req = (struct zcl_command_request){ .spec = peers, .view = "normal" };
        zcl_command_reply_init(&reply, peers->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        page = json_get(&reply.data, "_page");
        ASSERT(page != NULL);
        ASSERT(json_get_bool(json_get(page, "truncated")));
        const struct json_value *nc = json_get(page, "next_cursor");
        ASSERT(nc != NULL && json_get_int(nc) > 0);
        char cursor[32];
        (void)snprintf(cursor, sizeof(cursor), "%lld",
                       (long long)json_get_int(nc));
        size_t first_included = (size_t)json_get_int(json_get(page, "included"));
        ASSERT(first_included > 0 && first_included < 8);
        ASSERT(strstr(json_get_str(json_get(page, "continue")),
                      "z23 core network peers list --cursor=") != NULL);
        zcl_command_reply_free(&reply);

        req = (struct zcl_command_request){
            .spec = peers, .view = "normal", .cursor = cursor,
        };
        zcl_command_reply_init(&reply, peers->output_schema);
        zcl_native_bridge_project(&req, &body, &reply);
        page = json_get(&reply.data, "_page");
        ASSERT(page != NULL);
        ASSERT_EQ(json_get_int(json_get(page, "included")),
                  (int64_t)(8 - (long long)first_included));
        zcl_command_reply_free(&reply);
        json_free(&body);
        PASS();
    } _test_next:;

    return failures;
}

/* dev.vcs.revert IS a golden catalog row now (config/commands/dev.def via
 * ZCL_COMMAND_DEV_COMMAND, asserted COMPAT above in test_dev_branch_leaves).
 * What test_dev_branch_leaves does NOT reach is the handler body itself: a
 * release/testing build (this test binary is built WITHOUT ZCL_DEV_BUILD,
 * see Makefile TEST_FAST_CFLAGS) must link the `#ifndef ZCL_DEV_BUILD` stub
 * body of zcl_native_handle_dev_vcs_revert — never the real
 * vcs_revert()+shell-fallback path — and that stub must fail closed
 * (BLOCKED, not a silent no-op) instead of mutating anything. */
static int test_dev_vcs_revert_release_stub(void)
{
    int failures = 0;
    TEST("dev.vcs.revert fails closed (BLOCKED) outside a dev build") {
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "to",
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                               "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        (void)json_push_kv_bool(&input, "relink_generation", true);

        const struct zcl_command_spec *spec =
            find_spec(zcl_command_catalog(), "dev.vcs.revert");
        char why[128] = {0};
        ASSERT(spec != NULL);
        ASSERT(zcl_command_registry_input_validate(spec, &input, why,
                                                   sizeof(why)));

        struct zcl_command_request request = {
            .spec = NULL,
            .context = NULL,
            .input = &input,
            .view = "normal",
            .budget_bytes = 0,
            .invoked_by_alias = false,
            .invoked_name = "dev.vcs.revert",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.dev_vcs_revert.v1");
        zcl_native_handle_dev_vcs_revert(&request, &reply);

        ASSERT_EQ((int)reply.status, (int)ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_EQ((int)reply.exit_code, (int)ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT_STR_EQ(reply.error.code, "DEV_BUILD_REQUIRED");
        zcl_command_reply_free(&reply);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* dev.vcs.seal.grant IS a golden catalog row now (config/commands/dev.def
 * via ZCL_COMMAND_DEV_COMMAND, asserted COMPAT above in
 * test_dev_branch_leaves). Same shape as test_dev_vcs_revert_release_stub:
 * this release/testing build (no ZCL_DEV_BUILD) links the `#ifndef
 * ZCL_DEV_BUILD` stub body of zcl_native_handle_dev_vcs_seal_grant — never
 * the real vcs_seal_grant_unseal() path — so the mandatory-confirm gate
 * inside ZCL_DEV_BUILD is not reachable from this binary. What IS provable
 * here is that the stub fails closed (BLOCKED, never a silent mutation)
 * regardless of whether the caller supplied a well-formed, owner-confirmed
 * request or an unconfirmed one — granting a ZVCS unseal token is simply
 * unavailable outside a dev build. */
static int test_dev_vcs_seal_grant_release_stub(void)
{
    int failures = 0;
    TEST("dev.vcs.seal.grant fails closed (BLOCKED) outside a dev build, "
         "confirmed or not") {
        const bool confirms[] = { true, false };
        for (size_t i = 0; i < sizeof(confirms) / sizeof(confirms[0]); i++) {
            struct json_value input;
            json_init(&input);
            json_set_object(&input);
            (void)json_push_kv_str(&input, "reason", "post-baseline review");
            (void)json_push_kv_bool(&input, "confirm", confirms[i]);

            struct zcl_command_request request = {
                .spec = NULL,
                .context = NULL,
                .input = &input,
                .view = "normal",
                .budget_bytes = 0,
                .invoked_by_alias = false,
                .invoked_name = "dev.vcs.seal.grant",
            };
            struct zcl_command_reply reply;
            zcl_command_reply_init(&reply, "zcl.dev_vcs_seal_grant.v1");
            zcl_native_handle_dev_vcs_seal_grant(&request, &reply);

            ASSERT_EQ((int)reply.status, (int)ZCL_COMMAND_STATUS_BLOCKED);
            ASSERT_EQ((int)reply.exit_code, (int)ZCL_COMMAND_EXIT_BLOCKED);
            ASSERT_STR_EQ(reply.error.code, "DEV_BUILD_REQUIRED");
            zcl_command_reply_free(&reply);
            json_free(&input);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Every bridged READY leaf must resolve to exactly one dispatch: a
 * transport-neutral body function XOR a direct JSON-RPC method. */
static int test_bridge_bindings(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every bridged leaf has exactly one dispatch binding") {
        int checked = 0;
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (s->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            if (s->handler != zcl_native_bridge_command)
                continue;
            zcl_native_body_fn body = zcl_native_bridge_body_for_path(s->path);
            const char *rpc = zcl_native_bridge_rpc_for_path(s->path);
            /* exactly one of the two dispatch kinds */
            ASSERT((body != NULL) != (rpc != NULL));
            checked++;
        }
        /* the full bridged read surface, not a sample */
        ASSERT(checked >= 40);
        PASS();
    } _test_next:;
    return failures;
}

/* ops.selftest is a native, node-free sweep of the catalog's static
 * well-formedness the registry guarantees. Because test_catalog_wellformed
 * already proves the whole catalog validates, ops.selftest MUST report
 * fail == 0 with a passing envelope, so the dev-lane deploy verify can gate
 * on it without a running node. */
static int test_ops_selftest_registry(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    TEST("ops.selftest sweeps the registry and reports fail:0") {
        const struct zcl_command_spec *s = find_spec(reg, "ops.selftest");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT(s->handler != NULL);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "\"ok\":true") != NULL);
        ASSERT(strstr(out, "\"mode\":\"registry\"") != NULL);
        ASSERT(strstr(out, "\"fail\":0") != NULL);
        /* At least the READY read/discovery leaves pass. */
        ASSERT(strstr(out, "\"pass\":0") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ops.state contacts the dumpstate RPC and therefore needs a live node, but its input
 * guard is node-free: a missing `subsystem` must fail INVALID before any RPC,
 * naming MISSING_SUBSYSTEM and offering an executable next command. */
static int test_ops_state_requires_subsystem(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("ops.state fails INVALID without a subsystem, before any node call") {
        const struct zcl_command_spec *s = find_spec(reg, "ops.state");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT(s->handler != NULL);
        /* `explain` opts the reply into the telemetry-ontology verdicts
         * (util/telemetry_ontology.h) instead of bare numbers; it is optional
         * and off by default, so a routine dump is unchanged. */
        ASSERT_STR_EQ(s->input_keys, "subsystem,key,explain");
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT(strstr(out, "\"ok\":false") != NULL);
        ASSERT(strstr(out, "MISSING_SUBSYSTEM") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_is_root_ownership(void)
{
    int failures = 0;
    TEST("is_root owns terse status plus core/app/dev/ops/discover/code/vault") {
        ASSERT(zcl_native_command_is_root("core"));
        ASSERT(zcl_native_command_is_root("app"));
        ASSERT(zcl_native_command_is_root("ops"));
        ASSERT(zcl_native_command_is_root("discover"));
        ASSERT(zcl_native_command_is_root("code"));
        ASSERT(zcl_native_command_is_root("help"));
        ASSERT(zcl_native_command_is_root("search"));
        ASSERT(zcl_native_command_is_root("status"));
        ASSERT(zcl_native_command_is_root("dev"));
        ASSERT(zcl_native_command_is_root("vault"));
        ASSERT(!zcl_native_command_is_root("getblockcount"));
        /* Dotted first-token form: `<root>.<rest>` is owned too (the
         * canonical documented invocation), split into segments by
         * zcl_native_command_main before resolution. */
        ASSERT(zcl_native_command_is_root("zcode.science.study.list"));
        ASSERT(zcl_native_command_is_root("ops.state"));
        ASSERT(zcl_native_command_is_root("discover.search"));
        ASSERT(!zcl_native_command_is_root("getblockcount.foo"));
        ASSERT(!zcl_native_command_is_root("zcodeextra.leaf"));
        PASS();
    } _test_next:;
    return failures;
}

static void contract_noop_handler(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    (void)request;
    (void)reply;
}

/* OS-B1: validate must reject a READY leaf without a distinct, non-empty
 * `semantics` contract and a budget_bytes outside {0} ∪ [256, 65536]. Built as
 * a two-entry fixture registry (a branch parent + one leaf) mutated per case. */
static int test_semantics_contract_negative(void)
{
    int failures = 0;
    TEST("validate rejects missing/duplicate semantics and out-of-range budget") {
        struct zcl_command_spec branch = {
            .path = "x", .parent = "", .aliases = "", .summary = "branch x",
            .semantics = "", .tags = "", .input_schema = "",
            .output_schema = "", .input_keys = "", .positional_keys = "",
            .example = "", .availability_reason = "", .compat_target = "",
            .budget_bytes = 0, .layer = ZCL_COMMAND_LAYER_OPS,
            .effect = ZCL_COMMAND_EFFECT_READ, .risk = ZCL_COMMAND_RISK_READ,
            .scope = ZCL_COMMAND_SCOPE_LOCAL, .authority = ZCL_COMMAND_AUTH_PUBLIC,
            .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_BRANCH,
            .latency = ZCL_COMMAND_LATENCY_INSTANT, .cost = ZCL_COMMAND_COST_TINY,
            .confirmation = ZCL_COMMAND_CONFIRM_NONE,
            .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
            .transports = ZCL_COMMAND_TRANSPORT_NATIVE, .handler = NULL,
        };
        struct zcl_command_spec leaf_base = {
            .path = "x.y", .parent = "x", .aliases = "", .summary = "do a thing",
            .semantics = "the settled result of the thing, read locally",
            .tags = "t", .input_schema = "zcl.in.v1",
            .output_schema = "zcl.out.v1", .input_keys = "",
            .positional_keys = "", .example = "zclassic23 x y",
            .availability_reason = "", .compat_target = "", .budget_bytes = 0,
            .layer = ZCL_COMMAND_LAYER_OPS, .effect = ZCL_COMMAND_EFFECT_READ,
            .risk = ZCL_COMMAND_RISK_READ, .scope = ZCL_COMMAND_SCOPE_LOCAL,
            .authority = ZCL_COMMAND_AUTH_PUBLIC,
            .availability = ZCL_COMMAND_READY, .mode = ZCL_COMMAND_MODE_SYNC,
            .latency = ZCL_COMMAND_LATENCY_INSTANT, .cost = ZCL_COMMAND_COST_TINY,
            .confirmation = ZCL_COMMAND_CONFIRM_NONE,
            .allowed_lanes = ZCL_COMMAND_LANE_LOCAL,
            .transports = ZCL_COMMAND_TRANSPORT_NATIVE,
            .handler = contract_noop_handler,
        };
        char why[128] = { 0 };

        struct zcl_command_spec ok_specs[2] = { branch, leaf_base };
        struct zcl_command_registry ok_reg = { .commands = ok_specs, .count = 2 };
        ASSERT(zcl_command_registry_validate(&ok_reg, why, sizeof(why)));

        struct zcl_command_spec miss = leaf_base;
        miss.semantics = "";
        struct zcl_command_spec miss_specs[2] = { branch, miss };
        struct zcl_command_registry miss_reg = {
            .commands = miss_specs, .count = 2 };
        ASSERT(!zcl_command_registry_validate(&miss_reg, why, sizeof(why)));

        struct zcl_command_spec dup = leaf_base;
        dup.semantics = dup.summary;
        struct zcl_command_spec dup_specs[2] = { branch, dup };
        struct zcl_command_registry dup_reg = {
            .commands = dup_specs, .count = 2 };
        ASSERT(!zcl_command_registry_validate(&dup_reg, why, sizeof(why)));

        struct zcl_command_spec big = leaf_base;
        big.budget_bytes = 100000;
        struct zcl_command_spec big_specs[2] = { branch, big };
        struct zcl_command_registry big_reg = {
            .commands = big_specs, .count = 2 };
        ASSERT(!zcl_command_registry_validate(&big_reg, why, sizeof(why)));

        PASS();
    } _test_next:;
    return failures;
}

/* OS-B1: the real catalog now carries the contract on every leaf. */
static int test_leaf_semantics_and_budget(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every READY leaf has distinct non-empty semantics and a valid budget") {
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            ASSERT(s->budget_bytes == 0 ||
                   (s->budget_bytes >= 256 && s->budget_bytes <= 65536));
            if (s->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            if (s->availability != ZCL_COMMAND_READY)
                continue;
            ASSERT(s->semantics != NULL && s->semantics[0] != 0);
            ASSERT(strcmp(s->semantics, s->summary) != 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* OS-B1: describe surfaces the semantics contract and effective budget. */
static int test_describe_emits_semantics(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_SPEC_BUDGET + 1];
    TEST("describe emits the semantics contract and budget for a leaf") {
        size_t n = zcl_command_registry_describe_json(reg, "core.status", out,
                                                      sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"semantics\"") != NULL);
        ASSERT(strstr(out, "\"budget_bytes\"") != NULL);
        ASSERT(strstr(out, "\"display_only\":false") != NULL);
        n = zcl_command_registry_describe_json(
            reg, "app.presentation.show", out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "\"display_only\":true") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_presentation_leaves_are_display_only(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every native presentation leaf declares one display-only boundary") {
        const char *paths[] = {
            "app.qr.show",
            "app.presentation.show",
            "app.presentation.status",
            "app.presentation.corpus",
            "app.presentation.code-change",
            "app.presentation.reproduction",
            "app.presentation.publication-confirm",
            "app.presentation.release-confirm",
            "app.presentation.publication-status",
        };
        for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
            const struct zcl_command_spec *spec = find_spec(reg, paths[i]);
            ASSERT(spec != NULL);
            ASSERT_EQ(spec->availability, ZCL_COMMAND_READY);
            ASSERT((spec->traits & ZCL_COMMAND_TRAIT_DISPLAY_ONLY) != 0);
            ASSERT_EQ(spec->effect, ZCL_COMMAND_EFFECT_MUTATE);
            ASSERT_EQ(spec->risk, ZCL_COMMAND_RISK_APP_WRITE);
            ASSERT_EQ(spec->confirmation, ZCL_COMMAND_CONFIRM_NONE);
            ASSERT_EQ(spec->required_capabilities, ZCL_COMMAND_CAP_NONE);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* EVERY leaf, not one sample. An over-budget describe document renders as
 * nothing at all, and `discover describe` is the only surface that shows a
 * leaf's semantics text — so a leaf that overflows keeps dispatching while its
 * written contract silently becomes unreadable. That shipped: the money-safety
 * warning inside core.wallet.recovery.restore could not be read by anybody.
 * tools/lint/check_describe_budget.sh is the gate that names the offender and
 * carries the pre-existing baseline; this is the same property inside the test
 * suite, on the compiled catalog. */
static int test_every_describe_document_fits(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_SPEC_BUDGET + 1];
    TEST("every leaf's describe document fits its byte budget") {
        size_t leaves = 0, overflowed = 0;
        char first_bad[ZCL_COMMAND_MAX_PATH] = "";
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *spec = &reg->commands[i];
            if (spec->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            leaves++;
            if (zcl_command_registry_describe_json(reg, spec->path, out,
                                                   sizeof(out)) > 0)
                continue;
            /* zcode.endpoint.publish is baselined as pre-existing; see
             * tools/lint/describe_budget_baseline.txt. */
            if (strcmp(spec->path, "zcode.endpoint.publish") == 0)
                continue;
            overflowed++;
            if (first_bad[0] == '\0')
                snprintf(first_bad, sizeof(first_bad), "%s", spec->path);
        }
        if (overflowed)
            printf("    over budget: %zu leaf/leaves, first=%s\n", overflowed,
                   first_bad);
        ASSERT(leaves > 200);          /* anti-vacuous: the catalog was walked */
        ASSERT(overflowed == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int g_bad_next_case;

static void contract_bad_next_handler(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
    if (g_bad_next_case == 0)
        (void)zcl_command_reply_add_next(reply, request->spec->path, "{}",
                                         "illegal self-loop");
    else if (g_bad_next_case == 1)
        (void)zcl_command_reply_add_next(reply, "discover.describe", "{}",
                                         "missing required path");
    else
        (void)zcl_command_reply_add_next(reply, "unknown.command", "{}",
                                         "unknown command");
}

static int test_next_actions_fail_closed(void)
{
    int failures = 0;
    const struct zcl_command_registry *catalog = zcl_command_catalog();
    TEST("next actions reject self-loops, missing required input, and unknown leaves") {
        const struct zcl_command_spec *base = find_spec(catalog, "core.status");
        ASSERT(base != NULL);
        struct zcl_command_spec executable = *base;
        executable.handler = contract_bad_next_handler;
        struct zcl_command_registry local = {
            .commands = &executable,
            .count = 1,
        };
        struct zcl_command_context context = {
            .registry = catalog,
            .operator_lane = "dev",
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        for (g_bad_next_case = 0; g_bad_next_case < 3; g_bad_next_case++) {
            char out[ZCL_COMMAND_RESULT_BUDGET + 1];
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
            size_t n = zcl_command_registry_execute_json(
                &local, &executable, &context, &input, false,
                executable.path, "normal", 0, 0, NULL, out, sizeof(out),
                &code);
            ASSERT(n > 0);
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_INTERNAL);
            ASSERT(strstr(out, "\"ok\":false") != NULL);
            struct json_value reply;
            ASSERT(json_read(&reply, out, n));
            const struct json_value *error = json_get(&reply, "error");
            ASSERT(error && error->type == JSON_OBJ);
            ASSERT(json_get_str(json_get(error, "code")) != NULL);
            ASSERT_STR_EQ(json_get_str(json_get(error, "error_code")),
                          json_get_str(json_get(error, "code")));
            ASSERT(json_get_str(json_get(error, "current_state")) != NULL);
            ASSERT(json_get(error, "retryable") != NULL);
            ASSERT(json_get(error, "human_action_required") != NULL);
            ASSERT(json_get_str(json_get(error, "next_action")) != NULL);
            json_free(&reply);
        }
        json_free(&input);

        char menu[ZCL_COMMAND_ROOT_BUDGET + 1];
        size_t n = zcl_command_registry_menu_json(catalog, "", menu,
                                                   sizeof(menu));
        ASSERT(n > 0);
        struct json_value root;
        ASSERT(json_read(&root, menu, n));
        const struct json_value *next = json_get(&root, "next");
        ASSERT(next && next->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(next, "command")),
                      "discover.describe");
        const struct json_value *next_input = json_get(next, "input");
        const struct zcl_command_spec *describe =
            find_spec(catalog, "discover.describe");
        char why[160] = {0};
        ASSERT(describe && next_input &&
               zcl_command_registry_input_validate(describe, next_input, why,
                                                   sizeof(why)));
        json_free(&root);
        PASS();
    } _test_next:;
    return failures;
}

/* ── OS-B2: the per-command latency envelope ─────────────────────────── */

static int test_latency_budget_mapping(void)
{
    int failures = 0;
    TEST("latency enum maps to the documented ms budget, total over the enum") {
        ASSERT_EQ(zcl_command_latency_budget_ms(ZCL_COMMAND_LATENCY_INSTANT),
                  (int64_t)50);
        ASSERT_EQ(zcl_command_latency_budget_ms(ZCL_COMMAND_LATENCY_FAST),
                  (int64_t)250);
        ASSERT_EQ(zcl_command_latency_budget_ms(ZCL_COMMAND_LATENCY_FOREGROUND),
                  (int64_t)750);
        ASSERT_EQ(zcl_command_latency_budget_ms(ZCL_COMMAND_LATENCY_BACKGROUND),
                  (int64_t)900);
        ASSERT_EQ(zcl_command_latency_budget_ms(ZCL_COMMAND_LATENCY_PERSISTENT),
                  (int64_t)900);
        /* Out-of-range falls back to the PERSISTENT/900ms ceiling. */
        ASSERT_EQ(zcl_command_latency_budget_ms((enum zcl_command_latency)999),
                  (int64_t)900);
        PASS();
    } _test_next:;
    return failures;
}

static int test_envelope_carries_latency_contract(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("zcl.result.v1 carries budget_ms/elapsed_ms/budget_exceeded") {
        const struct zcl_command_spec *s = find_spec(reg, "discover.help");
        ASSERT(s != NULL);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        ASSERT(strstr(out, "\"budget_ms\"") != NULL);
        ASSERT(strstr(out, "\"elapsed_ms\"") != NULL);
        ASSERT(strstr(out, "\"budget_exceeded\":false") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool b2_latency_in_scope(const struct zcl_command_spec *s)
{
    if (s->availability != ZCL_COMMAND_READY ||
        s->effect != ZCL_COMMAND_EFFECT_READ ||
        s->mode != ZCL_COMMAND_MODE_SYNC)
        return false;
    return strncmp(s->path, "discover.", 9) == 0 ||
           strncmp(s->path, "code.", 5) == 0;
}

int command_registry_ready_read_latency_contract(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("every READY discover.*/code.* leaf's WARM dispatch meets its latency bucket") {
        /* budget_ms is a WARM-latency contract (docs/NATIVE_COMMAND_INTERFACE.md
         * §8 "warm latency class"). code.* leaves lazily build the in-binary
         * code index on their first call (a ~1s one-time O(codebase) scan);
         * that cold build is not the steady-state read this bucket budgets. So
         * warm each in-scope leaf once (result ignored), then assert the SECOND
         * dispatch's envelope meets the bucket. */
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (!b2_latency_in_scope(s))
                continue;
            char warm[ZCL_COMMAND_RESULT_BUDGET + 1];
            enum zcl_command_exit wcode = ZCL_COMMAND_EXIT_INTERNAL;
            (void)exec_leaf(reg, s, warm, sizeof(warm), &wcode);
        }
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (!b2_latency_in_scope(s))
                continue;
            char out[ZCL_COMMAND_RESULT_BUDGET + 1];
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            /* Dispatch with an empty object; leaves needing a required
             * positional fail input validation FAST (before any I/O) — still a
             * valid latency measurement, ok=false is expected and not asserted
             * here. A single wall-clock sample can include an involuntary
             * scheduler pause, so take up to three samples while keeping the
             * exact same latency threshold. A persistently slow leaf still
             * fails all three. */
            bool met_budget = false;
            for (int attempt = 0; attempt < 3 && !met_budget; attempt++) {
                ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
                met_budget = strstr(out,
                                    "\"budget_exceeded\":false") != NULL;
            }
            if (!met_budget)
                fprintf(stderr, "latency budget repeatedly exceeded: %s: %s\n",
                        s->path, out);
            ASSERT(met_budget);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_describe_emits_observed_p99(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("describe surfaces observed_p99_us/observed_samples after repeated dispatch") {
        const struct zcl_command_spec *s = find_spec(reg, "discover.help");
        ASSERT(s != NULL);
        char out[ZCL_COMMAND_RESULT_BUDGET + 1];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        for (int i = 0; i < 10; i++)
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
        char describe_out[ZCL_COMMAND_SPEC_BUDGET + 1];
        size_t n = zcl_command_registry_describe_json(reg, "discover.help",
                                                       describe_out,
                                                       sizeof(describe_out));
        ASSERT(n > 0);
        ASSERT(strstr(describe_out, "\"observed_p99_us\"") != NULL);
        /* Earlier tests in this binary already dispatched discover.help, so the
         * ring holds >= 10 samples (tests share the static g_latency_rings). */
        struct json_value root;
        ASSERT(json_read(&root, describe_out, n));
        const struct json_value *policy = json_get(&root, "policy");
        ASSERT(policy != NULL);
        int64_t samples = json_get_int(json_get(policy, "observed_samples"));
        ASSERT(samples >= (int64_t)10);
        json_free(&root);
        PASS();
    } _test_next:;
    return failures;
}

/* core.wallet.shielded is a complete surface: the node could already SPEND
 * shielded funds through a typed command while it could not READ them, so
 * balance/notes/address are bound rather than PLANNED. balance and notes are
 * READY reads dispatched through a body function (z_getbalance answers with a
 * bare string and z_listunspent with a bare array, so neither is a 1:1
 * RPC-shape proxy); address is a READY owner mutation with its own handler,
 * like core.wallet.address.new. */
static int test_wallet_shielded_reads_bound(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("core.wallet.shielded reads are READY and bound, not PLANNED") {
        const char *reads[] = {
            "core.wallet.shielded.balance",
            "core.wallet.shielded.notes",
        };
        for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, reads[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);
            ASSERT_STR_EQ(s->parent, "core.wallet.shielded");
            ASSERT(s->handler == zcl_native_bridge_command);
            ASSERT(zcl_native_bridge_body_for_path(reads[i]) != NULL);
            ASSERT(zcl_native_bridge_rpc_for_path(reads[i]) == NULL);
            /* A bound leaf carries no residual "not wired yet" excuse. */
            ASSERT(s->availability_reason != NULL);
            ASSERT(s->availability_reason[0] == 0);
            ASSERT(s->semantics != NULL && s->semantics[0]);
        }

        const struct zcl_command_spec *addr =
            find_spec(reg, "core.wallet.shielded.address");
        ASSERT(addr != NULL);
        ASSERT_EQ(addr->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(addr->effect, ZCL_COMMAND_EFFECT_MUTATE);
        ASSERT_EQ(addr->authority, ZCL_COMMAND_AUTH_OWNER);
        ASSERT(addr->handler != NULL);
        ASSERT(addr->handler != zcl_native_bridge_command);
        ASSERT(addr->availability_reason[0] == 0);

        /* The spend half was already READY; reading no longer lags it. */
        const struct zcl_command_spec *send =
            find_spec(reg, "core.wallet.shielded.send");
        ASSERT(send != NULL);
        ASSERT_EQ(send->availability, ZCL_COMMAND_READY);
        PASS();
    } _test_next:;
    return failures;
}

/* The ZCL application-feature leaves (config/commands/app_features.def).
 *
 * Read surface (names resolve/list, tokens list, messaging inbox, market
 * list/status/content, swap chains/list): READY and bridge-dispatched.
 *
 * Write surface, split on whether the backing RPC finishes its stated job:
 *   READY  — the six ZNAM writes, messaging send/read, swap
 *            initiate/participate, and private content registration. Each
 *            binds a dedicated handler in
 *            app/controllers/src/app_write_native_handlers.c over a backing
 *            RPC that really signs/broadcasts (ZNAM), writes to the peer
 *            socket (ZMSG p2p), or mints and persists the contract (ZSWP).
 *   PLANNED — messaging send-named (nothing drains the ZMSG store onto a
 *            peer), market offer (no origin MSG_FILE_LIST announce exists),
 *            market buy (no challenge, no payment tx). These fail closed. */
static int test_app_features_leaves(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("app feature leaves: reads bridged, finished writes READY, rest closed") {
        const char *branches[] = {
            "app.names", "app.tokens", "app.messaging", "app.market", "app.swap",
        };
        for (size_t i = 0; i < sizeof(branches) / sizeof(branches[0]); i++) {
            const struct zcl_command_spec *b = find_spec(reg, branches[i]);
            ASSERT(b != NULL);
            ASSERT_EQ(b->mode, ZCL_COMMAND_MODE_BRANCH);
            ASSERT_STR_EQ(b->parent, "app");
        }
        const struct zcl_command_spec *content_branch =
            find_spec(reg, "app.market.content");
        ASSERT(content_branch != NULL);
        ASSERT_EQ(content_branch->mode, ZCL_COMMAND_MODE_BRANCH);
        ASSERT_STR_EQ(content_branch->parent, "app.market");
        const struct zcl_command_spec *purchase_branch =
            find_spec(reg, "app.market.purchase");
        ASSERT(purchase_branch != NULL);
        ASSERT_EQ(purchase_branch->mode, ZCL_COMMAND_MODE_BRANCH);
        ASSERT_STR_EQ(purchase_branch->parent, "app.market");

        /* Read surface: READY with exactly one body-function binding. */
        const char *reads[] = {
            "app.names.resolve", "app.names.list", "app.tokens.list",
            "app.messaging.inbox", "app.market.list", "app.market.status",
            "app.market.content.list",
            "app.swap.chains", "app.swap.list",
        };
        for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, reads[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT(s->handler == zcl_native_bridge_command);
            ASSERT(zcl_native_bridge_body_for_path(s->path) != NULL);
            ASSERT(zcl_native_bridge_rpc_for_path(s->path) == NULL);
        }

        /* Executable write surface: READY with a dedicated (non-bridge)
         * handler, and every value-moving one still gated by plan/commit so a
         * bare invocation previews instead of broadcasting. */
        const char *ready_writes[] = {
            "app.names.register", "app.names.update", "app.names.transfer",
            "app.names.renew", "app.names.set-record", "app.names.set-text",
            "app.messaging.send", "app.messaging.read",
            "app.market.content.register", "app.market.offer",
            "app.market.purchase.plan",
            "app.market.purchase.commit", "app.market.purchase.retrieve",
            "app.swap.initiate", "app.swap.participate",
        };
        for (size_t i = 0;
             i < sizeof(ready_writes) / sizeof(ready_writes[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, ready_writes[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT(s->handler != NULL);
            ASSERT(s->handler != zcl_native_bridge_command);
            ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_MUTATE);
            ASSERT_EQ(s->authority, ZCL_COMMAND_AUTH_OWNER);
            /* A READY leaf carries no availability_reason — the reason field
             * exists to explain a refusal, and there is none to explain. */
            ASSERT(s->availability_reason && !s->availability_reason[0]);
            /* Every plan/commit leaf must accept the reserved `confirm` key,
             * or its commit half would be unreachable through the validator. */
            if (s->confirmation == ZCL_COMMAND_CONFIRM_PLAN_COMMIT)
                ASSERT(strstr(s->input_keys, "confirm") != NULL);
        }
        /* These local writes have no funds/network effect and do not demand a
         * confirm round trip. */
        ASSERT_EQ(find_spec(reg, "app.messaging.read")->confirmation,
                  ZCL_COMMAND_CONFIRM_NONE);
        ASSERT_EQ(find_spec(reg, "app.market.content.register")->confirmation,
                  ZCL_COMMAND_CONFIRM_NONE);
        ASSERT_EQ(find_spec(reg, "app.market.purchase.plan")->confirmation,
                  ZCL_COMMAND_CONFIRM_NONE);
        ASSERT_EQ(find_spec(reg, "app.market.purchase.commit")->confirmation,
                  ZCL_COMMAND_CONFIRM_IDEMPOTENCY);
        ASSERT_EQ(find_spec(reg, "app.market.purchase.retrieve")->confirmation,
                  ZCL_COMMAND_CONFIRM_NONE);
        const struct zcl_command_spec *purchase_status =
            find_spec(reg, "app.market.purchase.status");
        const struct zcl_command_spec *purchase_guide =
            find_spec(reg, "app.market.purchase.guide");
        ASSERT(purchase_guide != NULL);
        ASSERT_EQ(purchase_guide->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(purchase_guide->effect, ZCL_COMMAND_EFFECT_READ);
        ASSERT_EQ(purchase_guide->authority, ZCL_COMMAND_AUTH_PUBLIC);
        ASSERT(purchase_guide->handler ==
               zcl_native_handle_market_purchase_guide);
        ASSERT(purchase_status != NULL);
        ASSERT_EQ(purchase_status->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(purchase_status->effect, ZCL_COMMAND_EFFECT_READ);
        ASSERT_EQ(purchase_status->authority, ZCL_COMMAND_AUTH_OWNER);
        ASSERT(purchase_status->handler ==
               zcl_native_handle_market_purchase_status);
        const struct zcl_command_spec *market_offer =
            find_spec(reg, "app.market.offer");
        ASSERT(market_offer != NULL);
        ASSERT_EQ(market_offer->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(market_offer->confirmation, ZCL_COMMAND_CONFIRM_PLAN_COMMIT);
        ASSERT(market_offer->handler == zcl_native_handle_market_offer);

        /* Still-closed surface: PLANNED, no handler, honest reason, blocks
         * with exit 3 rather than reporting work the node never performs. */
        const char *writes[] = {
            "app.messaging.send-named", "app.market.buy",
        };
        char out[ZCL_COMMAND_RESULT_BUDGET + 1];
        for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, writes[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_PLANNED);
            ASSERT(s->handler == NULL);
            ASSERT(s->availability_reason && s->availability_reason[0]);
            ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_MUTATE);
            /* The reason must name what is missing, not restate the status:
             * a bare "not implemented"/"follow-up wave" placeholder is the
             * exact dishonesty this leaf population was cleaned of. */
            ASSERT(strstr(s->availability_reason, "needs ") != NULL);
            ASSERT(strlen(s->availability_reason) > 120);
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
            ASSERT(exec_leaf(reg, s, out, sizeof(out), &code));
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_BLOCKED);
            ASSERT(strstr(out, "COMMAND_PLANNED") != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* Each operator rollup dashboard is a READY read leaf under ops.debug.dash,
 * dispatched through a body function rather than an RPC-shape binding. */
static int test_ops_dash_dashboards_ported(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("ops.debug.dash operator dashboards are bridged READY leaves") {
        const char *leaves[] = {
            "ops.debug.dash.kpi",
            "ops.debug.dash.snapshot",
            "ops.debug.dash.summary",
            "ops.debug.dash.milestone",
            "ops.debug.dash.mirror",
            "ops.debug.dash.selfheal",
        };
        const struct zcl_command_spec *branch =
            find_spec(reg, "ops.debug.dash");
        ASSERT(branch != NULL);
        ASSERT_EQ(branch->mode, ZCL_COMMAND_MODE_BRANCH);
        ASSERT_STR_EQ(branch->parent, "ops.debug");
        for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
            const struct zcl_command_spec *s = find_spec(reg, leaves[i]);
            ASSERT(s != NULL);
            ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
            ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);
            ASSERT_STR_EQ(s->parent, "ops.debug.dash");
            ASSERT(s->handler == zcl_native_bridge_command);
            /* body-backed composition, never an RPC-shape binding */
            ASSERT(zcl_native_bridge_body_for_path(leaves[i]) != NULL);
            ASSERT(zcl_native_bridge_rpc_for_path(leaves[i]) == NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* config/src/command_catalog.c also builds a SECOND, parallel stringizing
 * expansion of the same .def catalogs — zcl_command_handler_index()
 * (config/command_handler_index.h). Its size must match the number of
 * catalog leaves that actually bind a handler (every such leaf produces
 * exactly one index entry, by construction), and a known handler name must
 * resolve to its command path. */
static int test_handler_index_matches_catalog(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_handler_index *idx = zcl_command_handler_index();
    TEST("handler index size matches bound-handler leaf count") {
        ASSERT(idx != NULL);
        ASSERT(idx->entries != NULL || idx->count == 0);
        size_t bound = 0;
        for (size_t i = 0; i < reg->count; i++)
            if (reg->commands[i].handler != NULL)
                bound++;
        ASSERT(idx->count == bound);
        PASS();
    } _test_next:;
    return failures;
}

static int test_handler_index_known_symbol_maps_to_path(void)
{
    int failures = 0;
    const struct zcl_command_handler_index *idx = zcl_command_handler_index();
    TEST("a known handler name maps to its command path") {
        bool found = false;
        for (size_t i = 0; i < idx->count; i++) {
            if (strcmp(idx->entries[i].handler_name,
                      "zcl_native_handle_code_sym") != 0)
                continue;
            ASSERT_STR_EQ(idx->entries[i].path, "code.sym");
            found = true;
        }
        ASSERT(found);
        PASS();
    } _test_next:;
    return failures;
}

/* ── ops.statecatalog: the typed leaf and the registry cannot drift ───
 *
 * The leaf exists so an agent can learn the dumpstate subsystem names
 * without reading diagnostics_dumpers.def out of a source tree. That is
 * only true while it reports EVERY name the registry holds, so this
 * drives the leaf through the real registry path — argv-shaped JSON in,
 * bounded envelope out, input_validate included — and checks each name in
 * diagnostics_dumper_at() against the emitted `names` array. Add a row to
 * the .def without the leaf seeing it and this fails.
 *
 * The registry path matters: calling the handler directly would skip
 * zcl_command_registry_input_validate, which is exactly how a leaf ends
 * up declaring input keys its handler does not accept (or the reverse)
 * and nobody notices. */
static int test_ops_statecatalog_matches_registry(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    /* Deliberately larger than the leaf's declared budget so the assert
     * below proves the response fits the BUDGET, not merely the buffer.
     * The argv path serves this leaf out of ZCL_COMMAND_LIST_BUDGET + 1,
     * so anything over that would fail RESPONSE_BUDGET_EXCEEDED there. */
    static char out[131072];
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };

    TEST("ops.statecatalog names every diagnostics-registry subsystem") {
        const struct zcl_command_spec *s = find_spec(reg, "ops.statecatalog");
        ASSERT(s != NULL);
        ASSERT_EQ(s->availability, ZCL_COMMAND_READY);
        ASSERT_EQ(s->effect, ZCL_COMMAND_EFFECT_READ);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = zcl_command_registry_execute_json(
            reg, s, &ctx, &input, false, "ops.statecatalog", "normal", 0, 0,
            NULL, out, sizeof(out), &code);
        json_free(&input);
        ASSERT(n > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        /* Fits its own declared budget: a truncated catalog would read as
         * "that subsystem does not exist", which is worse than an error. */
        ASSERT(n <= ZCL_COMMAND_LIST_BUDGET);

        struct json_value env;
        ASSERT(json_read(&env, out, n));
        const struct json_value *data = json_get(&env, "data");
        ASSERT(data != NULL && data->type == JSON_OBJ);
        const struct json_value *names = json_get(data, "names");
        ASSERT(names != NULL && names->type == JSON_ARR);

        size_t registry_count = diagnostics_dumper_count();
        ASSERT(registry_count > 0);
        ASSERT(json_size(names) == registry_count);
        ASSERT(json_get_int(json_get(data, "count")) ==
               (int64_t)registry_count);
        /* Node-free by construction — the registry is compiled in, so
         * this leaf must never be the one that needs a running node. */
        ASSERT(json_get_bool(json_get(data, "node_free")));

        /* Every registry row appears by name. Not count==count. */
        for (size_t i = 0; i < registry_count; i++) {
            const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
            ASSERT(e != NULL && e->name != NULL);
            bool found = false;
            for (size_t j = 0; j < json_size(names) && !found; j++) {
                const char *got = json_get_str(json_at(names, j));
                found = got && strcmp(got, e->name) == 0;
            }
            ASSERT(found);
        }
        json_free(&env);
        PASS();
    } _test_next:;
    return failures;
}

/* The paged half: `subsystem=` returns one full descriptor, an unknown
 * name fails closed with a next action, and walking the pages visits
 * every entry exactly once (so paging can never hide a subsystem the
 * `names` list promised). */
static int test_ops_statecatalog_paging_and_lookup(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static char out[131072];
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    const struct zcl_command_spec *s = find_spec(reg, "ops.statecatalog");

    TEST("ops.statecatalog resolves one subsystem and refuses an unknown") {
        ASSERT(s != NULL);
        const struct diagnostics_dump_entry *first = diagnostics_dumper_at(0);
        ASSERT(first != NULL);

        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "subsystem", first->name);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t n = zcl_command_registry_execute_json(
            reg, s, &ctx, &input, false, "ops.statecatalog", "normal", 0, 0,
            NULL, out, sizeof(out), &code);
        json_free(&input);
        ASSERT(n > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        struct json_value env;
        ASSERT(json_read(&env, out, n));
        const struct json_value *one =
            json_get(json_get(&env, "data"), "subsystem");
        ASSERT(one != NULL && one->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(one, "name")), first->name);
        /* The full descriptor, not a trimmed row — owner_file is the
         * field that makes the catalog worth reading. */
        ASSERT_STR_EQ(json_get_str(json_get(one, "owner_file")),
                      first->owner_file);
        json_free(&env);

        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "subsystem", "no_such_subsystem_xyz");
        code = ZCL_COMMAND_EXIT_OK;
        n = zcl_command_registry_execute_json(
            reg, s, &ctx, &input, false, "ops.statecatalog", "normal", 0, 0,
            NULL, out, sizeof(out), &code);
        json_free(&input);
        ASSERT(n > 0);
        ASSERT(code != ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(out, "UNKNOWN_SUBSYSTEM") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ops_statecatalog_paging_covers_all(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static char out[131072];
    struct zcl_command_context ctx = {
        .registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    const struct zcl_command_spec *s = find_spec(reg, "ops.statecatalog");

    TEST("ops.statecatalog paging visits every entry exactly once") {
        ASSERT(s != NULL);
        size_t registry_count = diagnostics_dumper_count();
        /* The leaf clamps `limit` to its own max (8); asking for exactly
         * that keeps the absolute-index check below honest. Walking EVERY
         * page also proves no window of descriptors blows the leaf budget:
         * the largest catalog entries are ~1.3 KB and a page must still
         * serialize inside ZCL_COMMAND_LIST_BUDGET. */
        const int64_t page_size = 5;
        size_t seen = 0;
        for (int64_t page = 0; page * page_size < (int64_t)registry_count;
             page++) {
            struct json_value input;
            json_init(&input);
            json_set_object(&input);
            (void)json_push_kv_int(&input, "limit", page_size);
            (void)json_push_kv_int(&input, "page", page);
            enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
            size_t n = zcl_command_registry_execute_json(
                reg, s, &ctx, &input, false, "ops.statecatalog", "normal", 0,
                0, NULL, out, sizeof(out), &code);
            json_free(&input);
            ASSERT(n > 0);
            ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
            ASSERT(n <= ZCL_COMMAND_LIST_BUDGET);
            struct json_value env;
            ASSERT(json_read(&env, out, n));
            const struct json_value *rows =
                json_get(json_get(&env, "data"), "subsystems");
            ASSERT(rows != NULL && rows->type == JSON_ARR);
            /* Each row must be the registry entry at its absolute index —
             * proves the page window, not just the row count. */
            for (size_t k = 0; k < json_size(rows); k++) {
                size_t abs = (size_t)(page * page_size) + k;
                const struct diagnostics_dump_entry *e =
                    diagnostics_dumper_at(abs);
                ASSERT(e != NULL);
                ASSERT_STR_EQ(json_get_str(json_get(json_at(rows, k), "name")),
                              e->name);
            }
            seen += json_size(rows);
            json_free(&env);
        }
        ASSERT(seen == registry_count);
        PASS();
    } _test_next:;
    return failures;
}

int test_command_registry_catalog(void)
{
    int failures = 0;
    failures += test_catalog_wellformed();
    failures += test_ops_statecatalog_matches_registry();
    failures += test_ops_statecatalog_paging_and_lookup();
    failures += test_ops_statecatalog_paging_covers_all();
    failures += test_handler_index_matches_catalog();
    failures += test_handler_index_known_symbol_maps_to_path();
    failures += test_app_features_leaves();
    failures += test_presentation_leaves_are_display_only();
    failures += test_wallet_shielded_reads_bound();
    failures += test_ops_dash_dashboards_ported();
    failures += test_semantics_contract_negative();
    failures += test_leaf_semantics_and_budget();
    failures += test_describe_emits_semantics();
    failures += test_every_describe_document_fits();
    failures += test_latency_budget_mapping();
    failures += test_envelope_carries_latency_contract();
    failures += test_describe_emits_observed_p99();
    failures += test_next_actions_fail_closed();
    failures += test_domain_leaf_counts();
    failures += test_six_roots();
    failures += test_yardsale_guide();
    failures += test_code_guide_leaf();
    failures += test_root_menu_budget();
    failures += test_branch_menus_shallow();
    failures += test_search_bounded();
    failures += test_search_multiword();
    failures += test_ready_leaves_bound();
    failures += test_bridge_bindings_reverse();
    failures += test_bridge_replacement_rejects_non_bridge_leaf();
    failures += test_messaging_inbox_wraps_rpc_array();
    failures += test_network_peer_add_binding();
    failures += test_bridge_rpc_errors_fail_closed();
    failures += test_raw_transaction_string_is_typed();
    failures += test_raw_transaction_verbose_bool();
    failures += test_raw_transaction_error_string();
    failures += test_bridge_rpc_success_shapes_fail_closed();
    failures += test_status_brief_flat_lean_envelope();
    failures += test_status_journey_safe_money_frontdoor();
    failures += test_wallet_utxo_list_envelope();
    failures += test_status_brief_overdue_transient_surfaces();
    failures += test_status_brief_overdue_transient_absent_when_zero();
    failures += test_status_brief_trust_tier_surfaces();
    failures += test_status_brief_trust_tier_absent_when_missing();
    failures += test_status_brief_composite_fails_closed();
    failures += test_status_brief_schema_skew_degrades_gracefully();
    failures += test_status_brief_valid_unknown_and_partial_contracts();
    failures += test_status_brief_rejects_contract_contradictions();
    failures += test_status_brief_names_first_failing_field();
    failures += test_bridge_bindings();
    failures += test_planned_fail_closed();
    failures += test_envelope_vectors();
    failures += test_dev_branch_leaves();
    failures += test_response_budget_views();
    failures += test_typo_stays_branch();
    failures += test_ops_selftest_registry();
    failures += test_ops_dash_dashboards_ported();
    failures += test_ops_state_requires_subsystem();
    failures += test_dev_vcs_revert_release_stub();
    failures += test_dev_vcs_seal_grant_release_stub();
    failures += test_is_root_ownership();
    printf("=== command_registry_catalog: %d failures ===\n", failures);
    return failures;
}
