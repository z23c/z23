/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "dev_activation.h"
#include "dev_failure_store.h"
#include "devloop.h"
#include "hotswap/hotfork_capsule.h"
#include "framework/app_definition.h"
#include "framework/app_platform.h"
#include "hotswap/hotswap_module.h"
#include "json/json.h"
#include "keys/key.h"
#include "platform/time_compat.h"
#include "services/dev_reflex_policy_service.h"
#include "sim/social_app_sim.h"
#include "util/safe_alloc.h"
#include "wallet/wallet.h"

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int route_handler(const struct zcl_app_request_v1 *request,
                         struct zcl_app_mut_bytes *response,
                         struct zcl_app_error *error)
{
    (void)request;
    (void)response;
    (void)error;
    return 0;
}

static int app_self_test(const struct zcl_app_host_v1 *host,
                         struct zcl_app_error *error)
{
    (void)host;
    (void)error;
    return 0;
}

static int app_quiesce(const struct zcl_app_host_v1 *host,
                       uint32_t timeout_ms,
                       struct zcl_app_error *error)
{
    (void)host;
    (void)timeout_ms;
    (void)error;
    return 0;
}

static struct zcl_app_manifest_v1 valid_manifest(void)
{
    static const struct zcl_app_route_v1 routes[] = {
        {
            .struct_size = sizeof(struct zcl_app_route_v1),
            .method = "GET",
            .path = "/posts",
            .flags = ZCL_APP_ROUTE_READ_ONLY,
            .handler = route_handler,
        },
    };
    return (struct zcl_app_manifest_v1) {
        .struct_size = sizeof(struct zcl_app_manifest_v1),
        .manifest_version = ZCL_APP_MANIFEST_V1,
        .required_host_abi = ZCL_APP_HOST_ABI_V1,
        .state_schema_version = 0,
        .app_id = "social",
        .display_name = "ZClassic Social",
        .app_version = "0.1.0",
        .build_identity = "build",
        .content_sha256 =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .required_capabilities = ZCL_APP_CAP_WEB_ROUTES,
        .routes = routes,
        .route_count = 1,
        .self_test = app_self_test,
        .quiesce = app_quiesce,
    };
}

static int g_app_prepare_calls;
static int g_app_commit_calls;
static int g_app_abort_calls;
static bool g_app_commit_fail;

static int app_state_open(void *ctx, const char *app_id, uint32_t schema,
                          zcl_app_state_handle *out,
                          struct zcl_app_error *error)
{
    (void)ctx;
    (void)schema;
    (void)error;
    if (!app_id || strcmp(app_id, "social") != 0 || !out)
        return -1;
    *out = 77;
    return 0;
}

static int app_state_read(void *ctx, zcl_app_state_handle state,
                          struct zcl_app_bytes key,
                          struct zcl_app_mut_bytes *value,
                          struct zcl_app_error *error)
{
    (void)ctx; (void)state; (void)key; (void)value; (void)error;
    return 0;
}

static int app_state_write(void *ctx, zcl_app_state_handle state,
                           struct zcl_app_bytes key,
                           struct zcl_app_bytes value,
                           struct zcl_app_error *error)
{
    (void)ctx; (void)state; (void)key; (void)value; (void)error;
    return 0;
}

static int app_migration_prepare(const struct zcl_app_host_v1 *host,
                                 zcl_app_state_handle state,
                                 struct zcl_app_error *error)
{
    (void)host; (void)error;
    if (state != 77) return -1;
    g_app_prepare_calls++;
    return 0;
}

static int app_migration_commit(const struct zcl_app_host_v1 *host,
                                zcl_app_state_handle state,
                                struct zcl_app_error *error)
{
    (void)host; (void)state;
    g_app_commit_calls++;
    if (!g_app_commit_fail) return 0;
    (void)snprintf(error->message, sizeof(error->message), "%s",
                   "injected commit refusal");
    return -1;
}

static void app_migration_abort(const struct zcl_app_host_v1 *host,
                                zcl_app_state_handle state)
{
    (void)host; (void)state;
    g_app_abort_calls++;
}

static const uint8_t g_test_social_chain_id[ZCL_APP_EVENT_CHAIN_ID_SIZE] = {
    0x02, 0x06, 0x26, 0x01, 0x43, 0x83, 0x8b, 0x5f,
    0xf5, 0x2d, 0xc2, 0xeb, 0x7b, 0x4b, 0x80, 0x99,
    0xd4, 0xe4, 0xc9, 0x9d, 0xc3, 0xef, 0x19, 0x79,
    0x42, 0x89, 0xa2, 0xcd, 0x4c, 0x10, 0x07, 0x00,
};

static struct zcl_app_event_scope_v1 test_social_scope(void)
{
    struct zcl_app_event_scope_v1 scope;
    memset(&scope, 0, sizeof(scope));
    scope.struct_size = sizeof(scope);
    memcpy(scope.app_id, "social", sizeof("social"));
    memcpy(scope.topic, "social.events.v1", sizeof("social.events.v1"));
    memcpy(scope.chain_id, g_test_social_chain_id, sizeof(scope.chain_id));
    scope.max_event_bytes = 65536;
    return scope;
}

static struct zcl_app_event_intent_v1 test_social_intent(
    const uint8_t *payload, size_t payload_len)
{
    struct zcl_app_event_intent_v1 intent;
    memset(&intent, 0, sizeof(intent));
    intent.struct_size = sizeof(intent);
    intent.kind = 1;
    intent.sequence = 1;
    intent.created_at = UINT64_C(1700000000);
    intent.payload.data = payload;
    intent.payload.len = payload_len;
    return intent;
}

static int test_menu_and_search(void)
{
    int failures = 0;
    TEST("dev platform: shallow menu and semantic search are compact JSON") {
        char body[32768];
        /* Wave 2.2: menu/help/search are now registry-driven, so the schema is
         * the canonical zcl.command_menu.v1 and the shape comes from the single
         * command catalog rather than a hardcoded dev tree. */
        size_t n = zcl_devloop_menu_json("dev", body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        struct json_value root = {0};
        ASSERT(json_read(&root, body, n));
        ASSERT(strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.command_menu.v1") == 0);
        /* Shallow: dev's immediate children appear, deep social nodes do not. */
        ASSERT(strstr(body, "dev.app") != NULL);
        ASSERT(strstr(body, "dev.app.describe") == NULL);
        ASSERT(strstr(body, "dev.app.social.resources") == NULL);
        json_free(&root);

        /* "censorship" is a registry tag on the deterministic App simulator. */
        n = zcl_devloop_menu_search_json("censorship", body, sizeof(body));
        ASSERT(n > 0);
        ASSERT(strstr(body, "dev.app.simulate") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_change_classification(void)
{
    int failures = 0;
    TEST("dev platform: classification maps every provider probe and keeps Core reload-only") {
        struct zcl_devloop_plan plan;
        static const struct {
            const char *path;
            const char *probe;
        } hot[] = {
            { "app/controllers/src/status_native_handlers.c", "core.status" },
            { "app/controllers/src/meta_native_handlers.c", "ops.metrics" },
            { "app/controllers/src/chain_native_handlers.c", "core.consensus.utxo.audit" },
            { "app/controllers/src/net_native_handlers.c", "core.network.peers.incidents" },
            { "app/controllers/src/wallet_native_handlers.c", "core.wallet.address.list" },
        };
        for (size_t i = 0; i < sizeof(hot) / sizeof(hot[0]); i++) {
            const char *files[] = { hot[i].path };
            ASSERT(zcl_devloop_plan_files(files, 1, &plan));
            ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
            ASSERT(strcmp(plan.proof_group, "hotswap_simnet") == 0);
            ASSERT(strcmp(plan.probe_tool, hot[i].probe) == 0);
        }

        const char *island_member[] = {
            "app/services/src/metaverse_agent_service.c",
        };
        ASSERT(zcl_devloop_plan_files(island_member, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.proof_group, "hotswap_simnet") == 0);
        ASSERT(strcmp(plan.probe_tool, "metaverse.property.list") == 0);

        const char *service_source[] = {
            "app/services/src/zcode_c23_corpus_service.c",
        };
        ASSERT(zcl_devloop_plan_files(service_source, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.probe_tool, "zcode.commons.corpus.show") == 0);
        const char *story_service[] = {
            "app/services/src/vault_intent_decision_service.c",
        };
        ASSERT(zcl_devloop_plan_files(story_service, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.proof_group, "transaction_intent") == 0);
        ASSERT(strcmp(plan.probe_tool, "dev.test.story") == 0);
        const char *service_header[] = {
            "app/services/include/services/zcode_c23_corpus_service.h",
        };
        ASSERT(zcl_devloop_plan_files(service_header, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);

        const char *service_batch[] = {
            "app/services/src/zcode_c23_economics_service.c",
            "app/services/src/zcode_c23_economics_internal.h",
        };
        ASSERT(zcl_devloop_plan_files(service_batch, 2, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.probe_tool,
                      "zcode.commons.economics.status") == 0);
        ASSERT(strcmp(plan.reason, "single_service_island_batch") == 0);

        struct zcl_devloop_restart_source_set restart_set = {0};
        ASSERT(zcl_devloop_restart_source_set_add(
            &restart_set, service_batch, 2));
        ASSERT(restart_set.count == 1);
        ASSERT_STR_EQ(restart_set.sources[0],
                      "app/services/src/zcode_c23_economics_service.c");
        const char *later_static[] = {
            "lib/test/src/test_zcode_commons_v2.c",
            "app/services/src/zcode_c23_economics_internal.h",
        };
        ASSERT(zcl_devloop_restart_source_set_add(
            &restart_set, later_static, 2));
        ASSERT(restart_set.count == 2);
        ASSERT_STR_EQ(restart_set.sources[1],
                      "lib/test/src/test_zcode_commons_v2.c");

        const char *cross_service_batch[] = {
            "app/services/src/zcode_c23_economics_service.c",
            "app/services/src/zcode_c23_corpus_service.c",
        };
        ASSERT(zcl_devloop_plan_files(cross_service_batch, 2, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);

        const char *multi_hot[] = {
            hot[0].path, hot[1].path,
        };
        ASSERT(zcl_devloop_plan_files(multi_hot, 2, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);
        ASSERT(strcmp(plan.reason,
                      "multi_provider_generation_not_yet_admitted") == 0);

        const char *core[] = { "core/params/src/params.c" };
        ASSERT(zcl_devloop_plan_files(core, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);
        ASSERT(plan.consensus_risk);

        const char *docs[] = { "docs/BUILD.md" };
        ASSERT(zcl_devloop_plan_files(docs, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_CHECK);
        ASSERT(plan.docs_only);
        PASS();
    } _test_next:;
    return failures;
}

/* Read and verify the worktree-scoped SHA3-sealed cycle verdict. */
static size_t read_native_cycle(const char *repo_root, char *buf, size_t cap)
{
    size_t len = 0;
    return zcl_devloop_cycle_state_read(repo_root, buf, cap, &len, NULL,
                                        NULL, 0) ==
                   ZCL_DEVLOOP_STATE_FOUND
               ? len : 0;
}

/* Write <dir>/<rel> creating parent dirs (mirrors test_codeindex's mk_write). */
static bool dp_mk_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static bool dp_group_in(const char (*groups)[ZCL_DEVLOOP_GROUP_MAX],
                        size_t len, const char *g)
{
    for (size_t i = 0; i < len; i++)
        if (strcmp(groups[i], g) == 0)
            return true;
    return false;
}

/* F3: dev test/change plan gains symbol-closure-derived proof groups. A tiny
 * codeindex fixture with a cross-file call edge lib/net/src/download.c ->
 * lib/net/src/tor_integration.c: changing the Tor file (path group
 * "test_tor") must
 * additionally surface download.c's groups ("download"...) via the closure,
 * WITHOUT dropping the path floor. */
#define DP_CLOSURE_FIX "test-tmp/dp_closure"

static int test_change_plan_closure(void)
{
    int failures = 0;
    TEST("dev platform: change plan unions symbol-closure groups onto the path floor") {
        system("rm -rf " DP_CLOSURE_FIX);
        /* tor_integration.c defines the changed leaf; download.c's function
         * calls it, so download.c is in the reverse-caller closure. Both paths
         * match distinct agent_impact rules ("test_tor" vs
         * "download ..."). */
        ASSERT(dp_mk_write(DP_CLOSURE_FIX, "lib/net/src/tor_integration.c",
                           "/* tor fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int tor_leaf(int x) { return x + 1; }\n"));
        ASSERT(dp_mk_write(DP_CLOSURE_FIX, "lib/net/src/download.c",
                           "/* download fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int dl_top(int x) { return tor_leaf(x) * 2; }\n"));
        ASSERT(dp_mk_write(DP_CLOSURE_FIX, "lib/net/include/net/clp.h",
                           "#ifndef NET_CLP_H\n#define NET_CLP_H\n"
                           "int tor_leaf(int x);\nint dl_top(int x);\n#endif\n"));
        ASSERT(dp_mk_write(DP_CLOSURE_FIX, "build/obj/tor_integration.d",
                           "build/obj/tor_integration.o: "
                           "lib/net/src/tor_integration.c "
                           "lib/net/include/net/clp.h\n"));
        ASSERT(dp_mk_write(DP_CLOSURE_FIX, "build/obj/download.d",
                           "build/obj/download.o: lib/net/src/download.c "
                           "lib/net/include/net/clp.h\n"));

        const char *files[] = { "lib/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));

        /* Floor: the path glob alone maps the changed file to "test_tor". */
        ASSERT(dp_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));
        /* "download" is NOT reachable by path glob from the tor file. */
        ASSERT(!dp_group_in(plan.path_groups, plan.path_groups_len, "download"));

        ASSERT(zcl_devloop_plan_add_closure(DP_CLOSURE_FIX, files, 1, &plan));
        ASSERT(plan.closure_attempted);
        ASSERT(!plan.closure_truncated);
        /* Closure surfaces download.c's group set as an ADDITION. */
        ASSERT(dp_group_in(plan.closure_groups, plan.closure_groups_len,
                           "download"));
        /* Additive only: the path floor is never dropped, and a closure group
         * is never also duplicated into the path set. */
        ASSERT(dp_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));
        ASSERT(!dp_group_in(plan.closure_groups, plan.closure_groups_len,
                            "test_tor"));

        /* Fallback: an unavailable index (empty root, no sources) leaves the
         * path floor intact and adds nothing — never a partial/huge plan. */
        struct zcl_devloop_plan plan2;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan2));
        ASSERT(zcl_devloop_plan_add_closure("test-tmp/dp_closure_absent",
                                            files, 1, &plan2));
        ASSERT(plan2.closure_attempted);
        ASSERT(plan2.closure_groups_len == 0);
        ASSERT(dp_group_in(plan2.path_groups, plan2.path_groups_len,
                           "test_tor"));

        /* JSON surface carries both group sets + the truncation flag. */
        char body[16384];
        size_t n = zcl_devloop_plan_json_closure(DP_CLOSURE_FIX, files, 1, body,
                                                 sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        struct json_value root = {0};
        ASSERT(json_read(&root, body, n));
        ASSERT(json_get(&root, "path_groups") != NULL);
        ASSERT(json_get(&root, "closure_groups") != NULL);
        ASSERT(strstr(body, "\"closure_truncated\":false") != NULL);
        ASSERT(strstr(body, "download") != NULL);
        json_free(&root);

        system("rm -rf " DP_CLOSURE_FIX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_core_classification(void)
{
    int failures = 0;
    TEST("dev platform: sealed core is classified sealed + heaviest-proof") {
        struct zcl_devloop_plan plan;

        /* A file under core/ is sealed AND consensus_risk (heaviest proof),
         * routed reload — never hotswap. */
        const char *core[] = { "core/consensus/src/check_block.c" };
        ASSERT(zcl_devloop_plan_files(core, 1, &plan));
        ASSERT(plan.sealed_core);
        ASSERT(plan.consensus_risk);
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);

        /* core/math is sealed too — broader than the legacy consensus_risk
         * prefix list, which never named it. */
        const char *math[] = { "core/math/src/uint256.c" };
        ASSERT(zcl_devloop_plan_files(math, 1, &plan));
        ASSERT(plan.sealed_core);
        ASSERT(plan.consensus_risk);

        /* A non-core consensus-risk file (lib/validation/...) is NOT sealed:
         * it still selects the heavy proof, but watcher classification never
         * grants publication authority. */
        const char *val[] = { "lib/validation/src/sighash.c" };
        ASSERT(zcl_devloop_plan_files(val, 1, &plan));
        ASSERT(!plan.sealed_core);
        ASSERT(plan.consensus_risk);
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);
        PASS();
    } _test_next:;
    return failures;
}

static int test_watcher_publication_containment(void)
{
    int failures = 0;
    TEST("dev platform: watchers verify by default and auto is island-only") {
        ASSERT(zcl_devloop_default_watch_publish_mode() ==
               ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        ASSERT(zcl_devloop_publication_target_port_supported(18252));
        ASSERT(!zcl_devloop_publication_target_port_supported(29352));
        ASSERT(!zcl_devloop_publish_mode_applies(
            ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY));
        ASSERT(zcl_devloop_publish_mode_applies(ZCL_DEVLOOP_PUBLISH_APPLY));
        ASSERT(strcmp(zcl_devloop_publish_mode_name(
                          ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                      "verify") == 0);
        ASSERT(strcmp(zcl_devloop_publish_mode_name(ZCL_DEVLOOP_PUBLISH_APPLY),
                      "auto") == 0);
        ASSERT(zcl_devloop_publish_mode_name(
                   (enum zcl_devloop_publish_mode)99) == NULL);
        ASSERT(strcmp(zcl_devloop_watcher_freshness(false, false, false),
                      "watcher_not_running") == 0);
        ASSERT(strcmp(zcl_devloop_watcher_freshness(true, false, false),
                      "watcher_starting") == 0);
        ASSERT(strcmp(zcl_devloop_watcher_freshness(true, true, false),
                      "runtime_starting") == 0);
        ASSERT(strcmp(zcl_devloop_watcher_freshness(true, true, true), "current")
               == 0);
        ASSERT(strcmp(zcl_devloop_watcher_next_action(
                          false, false, false,
                          ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                      "z23-dev dev begin")
               == 0);
        ASSERT(strcmp(zcl_devloop_watcher_next_action(
                          true, false, false,
                          ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                      "z23-dev dev loop status") == 0);
        ASSERT(strcmp(zcl_devloop_watcher_next_action(
                          true, true, true,
                          ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY),
                      "edit one C23 file")
               == 0);
        ASSERT(strcmp(zcl_devloop_watcher_next_action(
                          true, true, false, ZCL_DEVLOOP_PUBLISH_APPLY),
                      "start or wait for the isolated dev node on RPC 18252, then rerun z23-dev dev loop status")
               == 0);
        ASSERT(strcmp(zcl_devloop_watcher_next_action(
                          true, true, true, ZCL_DEVLOOP_PUBLISH_APPLY),
                      "edit one C23 file")
               == 0);

        char why_not_live[512], next_command[256];
        zcl_devloop_hotswap_guidance(
            "rejected", "resident_probe",
            "cannot read RPC auth cookie at /tmp/dev/.cookie",
            why_not_live, sizeof(why_not_live),
            next_command, sizeof(next_command));
        ASSERT(strcmp(why_not_live,
                      "cannot read RPC auth cookie at /tmp/dev/.cookie") == 0);
        ASSERT(strcmp(next_command,
                      "z23-dev dev generation current") == 0);
        zcl_devloop_hotswap_guidance(
            "rejected", "compile", "candidate did not compile",
            why_not_live, sizeof(why_not_live),
            next_command, sizeof(next_command));
        ASSERT(strcmp(why_not_live, "candidate did not compile") == 0);
        ASSERT(strcmp(next_command,
                      "z23-dev dev diagnose latest") == 0);
        zcl_devloop_hotswap_guidance(
            "rejected", "resident_probe",
            "service ABI changed; select DEV_RESTART",
            why_not_live, sizeof(why_not_live),
            next_command, sizeof(next_command));
        ASSERT(strcmp(next_command, "make -j\"$(nproc)\" dev-bin") == 0);
        zcl_devloop_hotswap_guidance(
            "passed", "resident_commit", "",
            why_not_live, sizeof(why_not_live),
            next_command, sizeof(next_command));
        ASSERT(why_not_live[0] == '\0');
        ASSERT(strcmp(next_command,
            "keep editing; the resident authority owns the next module epoch")
            == 0);
        struct json_value resident_error;
        json_init(&resident_error);
        ASSERT(json_read(&resident_error,
            "{\"error\":{\"code\":-32603,\"message\":\"cannot read RPC auth cookie at /tmp/dev/.cookie\"}}",
            strlen("{\"error\":{\"code\":-32603,\"message\":\"cannot read RPC auth cookie at /tmp/dev/.cookie\"}}")));
        ASSERT(zcl_devloop_hotswap_response_error(
            &resident_error, why_not_live, sizeof(why_not_live)));
        ASSERT(strcmp(why_not_live,
                      "cannot read RPC auth cookie at /tmp/dev/.cookie") == 0);
        json_free(&resident_error);

        char lock_path[ZCL_DEVLOOP_PATH_MAX];
        ASSERT(zcl_devloop_watch_lock_path("/tmp/zcl-wt-main", lock_path,
                                           sizeof(lock_path)));
        ASSERT(strcmp(lock_path,
                      "/tmp/zcl-wt-main/.cache/zcl-dev-watch.lock") == 0);
        char other_lock[ZCL_DEVLOOP_PATH_MAX];
        ASSERT(zcl_devloop_watch_lock_path("/tmp/zcl-wt-2", other_lock,
                                           sizeof(other_lock)));
        ASSERT(strcmp(lock_path, other_lock) != 0);
        ASSERT(!zcl_devloop_watch_lock_path(NULL, lock_path,
                                            sizeof(lock_path)));

        /* APPLY is meaningful only to the separate resident island fast path.
         * The generic cycle remains contained for ordinary reload, consensus,
         * and sealed-core edits. */
        const char *hot[] = { "app/controllers/src/status_native_handlers.c" };
        const char *reload[] = { "app/services/src/node_health_service.c" };
        const char *consensus[] = { "lib/validation/src/sighash.c" };
        const char *sealed[] = { "core/consensus/src/check_block.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(hot, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(hotswap_source_is_swappable(hot[0]));
        ASSERT(!hotswap_source_is_swappable(reload[0]));
        ASSERT(!zcl_devloop_publish_mode_applies(
            zcl_devloop_default_watch_publish_mode()));
        ASSERT(zcl_devloop_plan_files(reload, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD && !plan.consensus_risk);
        ASSERT(!zcl_devloop_publish_mode_applies(
            zcl_devloop_default_watch_publish_mode()));
        ASSERT(zcl_devloop_plan_files(consensus, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD && plan.consensus_risk &&
               !plan.sealed_core);
        ASSERT(!zcl_devloop_publish_mode_applies(
            zcl_devloop_default_watch_publish_mode()));
        ASSERT(zcl_devloop_plan_files(sealed, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD && plan.consensus_risk &&
               plan.sealed_core);
        ASSERT(!zcl_devloop_publish_mode_applies(
            zcl_devloop_default_watch_publish_mode()));

        PASS();
    } _test_next:;
    return failures;
}

static int test_core_refusal_envelope(void)
{
    int failures = 0;
    TEST("dev platform: refusal envelope names paths + elevated procedure") {
        /* Mixed set: only the sealed member appears in "paths". */
        const char *mixed[] = {
            "core/consensus/src/check_block.c", "docs/notes.md"
        };
        char body[4096];
        size_t n = zcl_devloop_refusal_json(mixed, 2, body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));

        struct json_value root = {0};
        ASSERT(json_read(&root, body, n));
        ASSERT(strcmp(json_get_str(json_get(&root, "schema")),
                      "zcl.dev_cycle.v1") == 0);
        ASSERT(strcmp(json_get_str(json_get(&root, "status")),
                      "refused") == 0);
        ASSERT(strcmp(json_get_str(json_get(&root, "reason")),
                      "sealed_consensus_core") == 0);
        ASSERT(strcmp(json_get_str(json_get(&root, "why_not_live")),
                      "sealed consensus core requires the owner-gated "
                      "unseal and elevated proof procedure") == 0);
        ASSERT(strcmp(json_get_str(json_get(&root, "manifest")),
                      "core/MANIFEST.sha3") == 0);
        ASSERT(strcmp(json_get_str(json_get(&root, "law")),
                      "docs/CONSENSUS_PARITY_DOCTRINE.md") == 0);
        /* Sealed != frozen: the unseal command + elevated procedure must be
         * present so an agent is never dead-ended. */
        ASSERT(strstr(json_get_str(json_get(&root, "unseal")),
                      "make core-unseal") != NULL);
        ASSERT(strstr(json_get_str(json_get(&root, "elevated_procedure")),
                      "copy-prove") != NULL);
        json_free(&root);

        /* "paths" carries the sealed file, not the doc. */
        ASSERT(strstr(body, "core/consensus/src/check_block.c") != NULL);
        ASSERT(strstr(body, "docs/notes.md") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_core_refusal_cycle(void)
{
    int failures = 0;
    TEST("dev platform: every apply cycle is contained before Core authority") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "core_refusal", "notoken");
        char *saved_home = getenv("HOME");
        saved_home = saved_home ? strdup(saved_home) : NULL;
        setenv("HOME", dir, 1);

        const char *core[] = { "core/consensus/src/check_block.c" };
        /* Publication containment precedes the Core-unseal boundary. */
        ASSERT(!zcl_devloop_unseal_token_present(dir));
        int rc = zcl_devloop_run_cycle(dir, core, 1);
        ASSERT(rc == 3);  /* blocked-by-precondition, before any publish */

        /* The refusal was persisted as the zcl.dev_cycle.v1 verdict. */
        char verdict[4096];
        size_t vn = read_native_cycle(dir, verdict, sizeof(verdict));
        ASSERT(vn > 0);
        struct json_value v = {0};
        ASSERT(json_read(&v, verdict, vn));
        ASSERT(strcmp(json_get_str(json_get(&v, "status")), "blocked") == 0);
        ASSERT(strcmp(json_get_str(json_get(&v, "phase")),
                      "publication_contained") == 0);
        json_free(&v);

        if (saved_home) {
            setenv("HOME", saved_home, 1);
            free(saved_home);
        } else {
            unsetenv("HOME");
        }
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_core_refusal_token(void)
{
    int failures = 0;
    TEST("dev platform: an unseal token is not publication authority") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "core_refusal", "token");
        char *saved_home = getenv("HOME");
        saved_home = saved_home ? strdup(saved_home) : NULL;
        setenv("HOME", dir, 1);

        /* Mint the one-shot token the owner ritual writes. */
        char tok[1024];
        snprintf(tok, sizeof(tok), "%s/.core-unseal-token", dir);
        FILE *tf = fopen(tok, "w");
        ASSERT(tf != NULL);
        if (tf) { fputs("unsealed test\n", tf); fclose(tf); }
        ASSERT(zcl_devloop_unseal_token_present(dir));

        const char *core[] = { "core/consensus/src/check_block.c" };
        int rc = zcl_devloop_run_cycle(dir, core, 1);
        ASSERT(rc == 3);

        char verdict[4096];
        size_t vn = read_native_cycle(dir, verdict, sizeof(verdict));
        ASSERT(vn > 0);
        struct json_value v = {0};
        ASSERT(json_read(&v, verdict, vn));
        ASSERT(strcmp(json_get_str(json_get(&v, "status")), "blocked") == 0);
        ASSERT(strcmp(json_get_str(json_get(&v, "phase")),
                      "publication_contained") == 0);
        json_free(&v);

        if (saved_home) {
            setenv("HOME", saved_home, 1);
            free(saved_home);
        } else {
            unsetenv("HOME");
        }
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;

    return failures;
}

static int test_public_app_abi(void)
{
    int failures = 0;
    TEST("dev platform: Core validates public app ABI fail-closed") {
        char why[256];
        struct zcl_app_manifest_v1 manifest = valid_manifest();
        ASSERT(zcl_app_manifest_v1_validate(
            &manifest, ZCL_APP_CAP_WEB_ROUTES, "build", why, sizeof(why)));

        manifest.required_capabilities |= ZCL_APP_CAP_WALLET_REQUESTS;
        ASSERT(!zcl_app_manifest_v1_validate(
            &manifest, ZCL_APP_CAP_WEB_ROUTES, "build", why, sizeof(why)));
        ASSERT(strstr(why, "capability") != NULL);

        manifest = valid_manifest();
        manifest.state_schema_version = 1;
        manifest.required_capabilities |= ZCL_APP_CAP_RESIDENT_STATE;
        ASSERT(!zcl_app_manifest_v1_validate(
            &manifest,
            ZCL_APP_CAP_WEB_ROUTES | ZCL_APP_CAP_RESIDENT_STATE,
            "build", why, sizeof(why)));
        ASSERT(strstr(why, "migration") != NULL);

        static const struct zcl_app_topic_v1 duplicate_topics[] = {
            { sizeof(struct zcl_app_topic_v1), "social.events.v1", 1, 1024 },
            { sizeof(struct zcl_app_topic_v1), "social.events.v1", 1, 2048 },
        };
        manifest = valid_manifest();
        manifest.topics = duplicate_topics;
        manifest.topic_count = 2;
        ASSERT(!zcl_app_manifest_v1_validate(
            &manifest, ZCL_APP_CAP_WEB_ROUTES, "build", why, sizeof(why)));
        ASSERT(strstr(why, "duplicate app topic") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_app_runtime_transaction(void)
{
    int failures = 0;
    TEST("dev platform: host-owned app generation and migration commit atomically") {
        struct zcl_app_host_v1 host = {
            .struct_size = sizeof(host),
            .abi_version = ZCL_APP_HOST_ABI_V1,
            .capabilities = ZCL_APP_CAP_WEB_ROUTES |
                            ZCL_APP_CAP_RESIDENT_STATE,
            .state_open = app_state_open,
            .state_read = app_state_read,
            .state_write = app_state_write,
        };
        char why[192];
        struct zcl_app_runtime_v1 *runtime = zcl_app_runtime_v1_create(
            &host, host.capabilities, "build", why, sizeof(why));
        ASSERT(runtime != NULL);

        struct zcl_app_manifest_v1 stateless = valid_manifest();
        struct zcl_app_activation_receipt_v1 receipt;
        ASSERT(zcl_app_runtime_v1_activate(runtime, &stateless, &receipt));
        ASSERT(receipt.ok && !receipt.rolled_back);
        ASSERT_EQ(receipt.generation, (uint64_t)1);

        static const struct zcl_app_migration_v1 to_v1 = {
            .struct_size = sizeof(struct zcl_app_migration_v1),
            .from_schema = 0,
            .to_schema = 1,
            .prepare = app_migration_prepare,
            .commit = app_migration_commit,
            .abort = app_migration_abort,
        };
        struct zcl_app_manifest_v1 stateful_v1 = valid_manifest();
        stateful_v1.state_schema_version = 1;
        stateful_v1.required_capabilities |= ZCL_APP_CAP_RESIDENT_STATE;
        stateful_v1.migration = &to_v1;
        g_app_prepare_calls = g_app_commit_calls = g_app_abort_calls = 0;
        g_app_commit_fail = false;
        ASSERT(zcl_app_runtime_v1_activate(runtime, &stateful_v1, &receipt));
        ASSERT(receipt.migration_prepared && receipt.migration_committed);
        ASSERT_EQ(receipt.generation, (uint64_t)2);
        ASSERT_EQ(g_app_prepare_calls, 1);
        ASSERT_EQ(g_app_commit_calls, 1);
        ASSERT_EQ(g_app_abort_calls, 0);

        static const struct zcl_app_migration_v1 to_v2 = {
            .struct_size = sizeof(struct zcl_app_migration_v1),
            .from_schema = 1,
            .to_schema = 2,
            .prepare = app_migration_prepare,
            .commit = app_migration_commit,
            .abort = app_migration_abort,
        };
        struct zcl_app_manifest_v1 rejected_v2 = valid_manifest();
        rejected_v2.state_schema_version = 2;
        rejected_v2.required_capabilities |= ZCL_APP_CAP_RESIDENT_STATE;
        rejected_v2.migration = &to_v2;
        g_app_commit_fail = true;
        ASSERT(!zcl_app_runtime_v1_activate(runtime, &rejected_v2, &receipt));
        ASSERT(receipt.rolled_back && !receipt.ok);
        ASSERT_STR_EQ(receipt.phase, "migration_commit");
        ASSERT_EQ(g_app_abort_calls, 1);
        uint64_t generation = 0;
        uint32_t schema = 0;
        ASSERT(zcl_app_runtime_v1_active(runtime, &generation, &schema) ==
               &stateful_v1);
        ASSERT_EQ(generation, (uint64_t)2);
        ASSERT_EQ(schema, (uint32_t)1);

        ASSERT(!zcl_app_runtime_v1_activate(runtime, &stateless, &receipt));
        ASSERT_STR_EQ(receipt.phase, "migration");
        ASSERT(zcl_app_runtime_v1_active(runtime, &generation, &schema) ==
               &stateful_v1);
        zcl_app_runtime_v1_destroy(runtime);
        PASS();
    } _test_next:;
    return failures;
}

static int test_app_definition_compiler(void)
{
    int failures = 0;
    TEST("dev platform: strict compiler accepts Blog, Social, and Yardsale catalog") {
        struct zcl_app_definition_v1 blog, social, yardsale;
        struct zcl_result result =
            zcl_app_definition_load_v1(".", "blog", &blog);
        ASSERT(result.ok);
        ASSERT(blog.struct_size == sizeof(blog));
        ASSERT(blog.definition_version == ZCL_APP_DEFINITION_V1);
        ASSERT(strcmp(blog.app_id, "blog") == 0);
        ASSERT(strcmp(blog.display_name, "ZClassic Blog") == 0);
        ASSERT(strcmp(blog.app_version, "0.1.0") == 0);
        ASSERT(blog.resource_count == 2);
        ASSERT(blog.topic_count == 1);
        ASSERT(strcmp(blog.topics[0].name, "blog.posts.v1") == 0);
        ASSERT(blog.topics[0].wire_version == 1);
        ASSERT(blog.topics[0].max_event_bytes == 20000);
        ASSERT(blog.mount_count == 1);
        ASSERT(strcmp(blog.mounts[0].path, "/blog") == 0);
        ASSERT(blog.onion_declared && blog.onion_enabled);
        ASSERT(blog.znam_declared && strcmp(blog.znam, "blog") == 0);
        ASSERT(blog.state_schema_declared && blog.state_schema_version == 1);
        ASSERT(blog.simulation_count == 0);
        ASSERT((blog.required_capabilities & ZCL_APP_CAP_SIGNED_EVENTS) != 0);

        result = zcl_app_definition_load_v1(".", "social", &social);
        ASSERT(result.ok);
        ASSERT(strcmp(social.app_id, "social") == 0);
        ASSERT(social.resource_count == 4);
        ASSERT(social.topic_count == 1);
        ASSERT(strcmp(social.topics[0].name, "social.events.v1") == 0);
        ASSERT(social.mount_count == 1);
        ASSERT(strcmp(social.mounts[0].path, "/") == 0);
        ASSERT(social.simulation_count == 4);

        result = zcl_app_definition_load_v1(".", "yardsale", &yardsale);
        ASSERT(result.ok);
        ASSERT(strcmp(yardsale.app_id, "yardsale") == 0);
        ASSERT(strcmp(yardsale.display_name, "ZClassic Yardsale") == 0);
        ASSERT(yardsale.resource_count == 1);
        ASSERT(strcmp(yardsale.resources[0].name, "ads") == 0);
        ASSERT(yardsale.topic_count == 1);
        ASSERT(strcmp(yardsale.topics[0].name, "yardsale.ads.v1") == 0);
        ASSERT(yardsale.topics[0].wire_version == 1);
        ASSERT(yardsale.topics[0].max_event_bytes == 4096);
        ASSERT(yardsale.mount_count == 1);
        ASSERT(strcmp(yardsale.mounts[0].path, "/yardsale") == 0);
        ASSERT(yardsale.onion_declared && yardsale.onion_enabled);
        ASSERT(yardsale.znam_declared &&
               strcmp(yardsale.znam, "yardsale") == 0);
        ASSERT(yardsale.state_schema_declared &&
               yardsale.state_schema_version == 1);
        ASSERT(yardsale.simulation_count == 0);
        ASSERT((yardsale.required_capabilities &
                (ZCL_APP_CAP_CHAIN_READ | ZCL_APP_CAP_RESIDENT_STATE |
                 ZCL_APP_CAP_WEB_ROUTES | ZCL_APP_CAP_ONION_BINDING |
                 ZCL_APP_CAP_ZNAM_BINDING | ZCL_APP_CAP_P2P_TOPICS |
                 ZCL_APP_CAP_WALLET_REQUESTS)) ==
               (ZCL_APP_CAP_CHAIN_READ | ZCL_APP_CAP_RESIDENT_STATE |
                ZCL_APP_CAP_WEB_ROUTES | ZCL_APP_CAP_ONION_BINDING |
                ZCL_APP_CAP_ZNAM_BINDING | ZCL_APP_CAP_P2P_TOPICS |
                ZCL_APP_CAP_WALLET_REQUESTS));

        struct zcl_app_definition_catalog_v1 catalog;
        ASSERT(zcl_app_definition_builtin_count_v1() == 3);
        ASSERT(strcmp(zcl_app_definition_builtin_id_v1(0), "blog") == 0);
        ASSERT(strcmp(zcl_app_definition_builtin_id_v1(1), "social") == 0);
        ASSERT(strcmp(zcl_app_definition_builtin_id_v1(2), "yardsale") == 0);
        ASSERT(zcl_app_definition_builtin_id_v1(3) == NULL);
        ASSERT(zcl_app_definition_builtin_v1("blog"));
        ASSERT(zcl_app_definition_builtin_v1("yardsale"));
        ASSERT(!zcl_app_definition_builtin_v1("Blog"));
        ASSERT(!zcl_app_definition_builtin_v1("missing"));
        result = zcl_app_definition_builtin_catalog_compile_v1(".", &catalog);
        ASSERT(result.ok);
        ASSERT(catalog.struct_size == sizeof(catalog));
        ASSERT(catalog.catalog_version == ZCL_APP_DEFINITION_V1);
        ASSERT(catalog.app_count == 3);
        ASSERT(strcmp(catalog.apps[0].app_id, "blog") == 0);
        ASSERT(strcmp(catalog.apps[1].app_id, "social") == 0);
        ASSERT(strcmp(catalog.apps[2].app_id, "yardsale") == 0);

        static const char *const duplicate_ids[] = { "blog", "blog" };
        memset(&catalog, 0xa5, sizeof(catalog));
        result = zcl_app_definition_catalog_compile_v1(
            ".", duplicate_ids,
            sizeof(duplicate_ids) / sizeof(duplicate_ids[0]), &catalog);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "duplicate catalog app id") != NULL);
        ASSERT(catalog.struct_size == 0 && catalog.app_count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_strict_dev_app_producers(void)
{
    int failures = 0;
    TEST("dev platform: app describe and plan consume strict definitions only") {
        char body[8192];
        size_t n = zcl_devloop_app_describe_json(
            ".", "blog", body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        struct json_value doc = {0};
        ASSERT(json_read(&doc, body, n));
        ASSERT(strcmp(json_get_str(json_get(&doc, "status")), "ok") == 0);
        ASSERT(strcmp(json_get_str(json_get(&doc, "app_id")), "blog") == 0);
        ASSERT(strcmp(json_get_str(json_get(&doc, "display_name")),
                      "ZClassic Blog") == 0);
        ASSERT(strcmp(json_get_str(json_get(&doc, "compiler")),
                      "strict-bounded-v1") == 0);
        ASSERT(strcmp(json_get_str(json_get(&doc, "authority")),
                      "definition-only") == 0);
        const struct json_value *topics = json_get(&doc, "topics");
        ASSERT(topics && topics->type == JSON_ARR && topics->num_children == 1);
        ASSERT(strcmp(json_get_str(json_get(&topics->children[0], "name")),
                      "blog.posts.v1") == 0);
        ASSERT(strstr(body, "signed_events") != NULL);
        ASSERT(strstr(body, "runtime_authority") != NULL);
        json_free(&doc);

        n = zcl_devloop_app_plan_json(
            ".", "blog", "comments", body, sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        memset(&doc, 0, sizeof(doc));
        ASSERT(json_read(&doc, body, n));
        ASSERT(strcmp(json_get_str(json_get(&doc, "mode")),
                      "preview-only") == 0);
        const struct json_value *writes = json_get(&doc, "writes");
        ASSERT(writes && writes->type == JSON_BOOL && !writes->val.b);
        ASSERT(strstr(body, "app/models/src/comments.c") != NULL);
        ASSERT(strstr(body, "apps/blog/models/comments.c") == NULL);
        ASSERT(strstr(body, "writes and publishes nothing") != NULL);
        json_free(&doc);

        /* The old textual scraper/planner accepted both of these. The strict
         * compiler now requires a real, valid app.def before producing a
         * description or even a preview-only resource plan. */
        ASSERT(zcl_devloop_app_describe_json(
            ".", "Blog", body, sizeof(body)) == 0);
        ASSERT(zcl_devloop_app_plan_json(
            ".", "missing", "posts", body, sizeof(body)) == 0);
        ASSERT(zcl_devloop_app_plan_json(
            ".", "blog", "Bad-Resource", body, sizeof(body)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_app_definition_hostile_fixtures(void)
{
    int failures = 0;
    TEST("dev platform: strict app compiler rejects hostile definitions") {
        static const struct {
            const char *name;
            const char *source;
            const char *error;
        } fixtures[] = {
            {
                "unknown directive",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n"
                "ZCL_APP_FUTURE(\"x\")\n",
                "unknown directive",
            },
            {
                "duplicate singleton",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n",
                "duplicate ZCL_APP",
            },
            {
                "malformed mount",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(WEB_ROUTES)\n"
                "ZCL_APP_WEB_MOUNT(\"/bad/../route\")\n",
                "invalid web mount",
            },
            {
                "missing mount capability",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n"
                "ZCL_APP_WEB_MOUNT(\"/fixture\")\n",
                "web mounts require WEB_ROUTES",
            },
            {
                "capability without mount",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(WEB_ROUTES)\n",
                "lacks a web mount",
            },
            {
                "duplicate mount",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(WEB_ROUTES)\n"
                "ZCL_APP_WEB_MOUNT(\"/fixture\")\n"
                "ZCL_APP_WEB_MOUNT(\"/fixture\")\n",
                "duplicate web mount",
            },
            {
                "duplicate topic",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(SIGNED_EVENTS)\n"
                "ZCL_APP_CAPABILITY(P2P_TOPICS)\n"
                "ZCL_APP_TOPIC(\"fixture.events.v1\", 1, 1024)\n"
                "ZCL_APP_TOPIC(\"fixture.events.v1\", 1, 2048)\n",
                "duplicate topic",
            },
            {
                "too many resources",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_RESOURCE(\"r00\")\nZCL_APP_RESOURCE(\"r01\")\n"
                "ZCL_APP_RESOURCE(\"r02\")\nZCL_APP_RESOURCE(\"r03\")\n"
                "ZCL_APP_RESOURCE(\"r04\")\nZCL_APP_RESOURCE(\"r05\")\n"
                "ZCL_APP_RESOURCE(\"r06\")\nZCL_APP_RESOURCE(\"r07\")\n"
                "ZCL_APP_RESOURCE(\"r08\")\nZCL_APP_RESOURCE(\"r09\")\n"
                "ZCL_APP_RESOURCE(\"r10\")\nZCL_APP_RESOURCE(\"r11\")\n"
                "ZCL_APP_RESOURCE(\"r12\")\nZCL_APP_RESOURCE(\"r13\")\n"
                "ZCL_APP_RESOURCE(\"r14\")\nZCL_APP_RESOURCE(\"r15\")\n"
                "ZCL_APP_RESOURCE(\"r16\")\n",
                "too many resources",
            },
            {
                "trailing junk",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\");\n",
                "trailing junk",
            },
            {
                "unknown capability",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(RAW_SOCKET)\n",
                "unknown capability",
            },
            {
                "duplicate capability",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n",
                "duplicate capability",
            },
            {
                "conflicting onion capability",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(WEB_ROUTES)\n"
                "ZCL_APP_CAPABILITY(ONION_BINDING)\n"
                "ZCL_APP_WEB_MOUNT(\"/fixture\")\n"
                "ZCL_APP_ONION(false)\n",
                "conflicts with disabled binding",
            },
            {
                "oversized topic event",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(SIGNED_EVENTS)\n"
                "ZCL_APP_CAPABILITY(P2P_TOPICS)\n"
                "ZCL_APP_TOPIC(\"fixture.events.v1\", 1, 65537)\n",
                "invalid topic declaration",
            },
            {
                "leading zero",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(SIGNED_EVENTS)\n"
                "ZCL_APP_CAPABILITY(P2P_TOPICS)\n"
                "ZCL_APP_TOPIC(\"fixture.events.v1\", 01, 1024)\n",
                "leading zero",
            },
            {
                "malformed declared id",
                "ZCL_APP(\"Fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n",
                "invalid app id",
            },
            {
                "malformed version",
                "ZCL_APP(\"fixture\", \"Fixture\", \"01.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n",
                "invalid semantic version",
            },
            {
                "unterminated comment",
                "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
                "ZCL_APP_CAPABILITY(CHAIN_READ)\n/* never closed",
                "unterminated comment",
            },
        };

        for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
            struct zcl_app_definition_v1 definition;
            memset(&definition, 0xa5, sizeof(definition));
            struct zcl_result result = zcl_app_definition_parse_v1(
                "fixture", fixtures[i].source, strlen(fixtures[i].source),
                &definition);
            ASSERT(!result.ok);
            ASSERT(strstr(result.message, fixtures[i].error) != NULL);
            ASSERT(definition.struct_size == 0);
        }

        static const char valid[] =
            "ZCL_APP(\"fixture\", \"Fixture\", \"1.0.0\")\n"
            "ZCL_APP_CAPABILITY(CHAIN_READ)\n";
        struct zcl_app_definition_v1 definition;
        struct zcl_result result = zcl_app_definition_parse_v1(
            "../fixture", valid, sizeof(valid) - 1, &definition);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "path id") != NULL);
        ASSERT(definition.struct_size == 0);

        char unterminated_id[ZCL_APP_ID_MAX + 1];
        memset(unterminated_id, 'a', sizeof(unterminated_id));
        result = zcl_app_definition_parse_v1(
            unterminated_id, valid, sizeof(valid) - 1, &definition);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "path id") != NULL);
        ASSERT(definition.struct_size == 0);

        static const char embedded_nul[] = {
            'Z','C','L','_','A','P','P','(', '"','f','i','x','t','u','r','e','"',
            ',', '"','F','i','x','t','u','r','e','"', ',', '"','1','.','0','.',
            '0','"',')','\n','\0','X'
        };
        result = zcl_app_definition_parse_v1(
            "fixture", embedded_nul, sizeof(embedded_nul), &definition);
        ASSERT(!result.ok);
        ASSERT(strstr(result.message, "embedded NUL") != NULL);
        ASSERT(definition.struct_size == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_signed_app_events(void)
{
    int failures = 0;
    struct wallet *wallet = NULL;
    struct zcl_app_event_signing_binding_v1 *binding = NULL;
    bool wallet_ready = false;
    TEST("dev platform: Core wallet signs canonical scoped App events") {
        static const uint8_t payload[] = "hello zclassic23";
        static const uint8_t expected_event_id[32] = {
            0xd2, 0xbf, 0x68, 0xe3, 0x05, 0xf1, 0xe5, 0x8a,
            0x02, 0xb0, 0x09, 0x43, 0x23, 0xd8, 0xfd, 0x8a,
            0xca, 0x29, 0x76, 0xe8, 0xa6, 0xdd, 0xaf, 0xe8,
            0x7a, 0x34, 0x59, 0x9d, 0xe3, 0xe4, 0xe3, 0xf8,
        };
        static const uint8_t high_s_signature[] = {
            0x30, 0x45, 0x02, 0x20, 0x2c, 0x27, 0x65, 0xc3,
            0x93, 0x17, 0xd3, 0x3a, 0xb0, 0x6e, 0x69, 0x6c,
            0x0a, 0x93, 0x4a, 0xff, 0xb0, 0xe6, 0x6b, 0xa5,
            0x2e, 0x80, 0x0f, 0xd6, 0x85, 0x3f, 0x8f, 0x10,
            0x5d, 0xd0, 0xe1, 0xb4, 0x02, 0x21, 0x00, 0x84,
            0xea, 0x62, 0x50, 0x59, 0x89, 0x60, 0x7a, 0x6b,
            0xe6, 0x27, 0x7d, 0xe7, 0x7e, 0x71, 0xf6, 0x54,
            0xd7, 0x30, 0x67, 0xe4, 0xc6, 0xe8, 0x71, 0x8d,
            0x55, 0x50, 0x71, 0xf1, 0xa6, 0xe9, 0x00,
        };
        struct privkey key;
        privkey_init(&key);
        key.vch[31] = 1;
        key.fValid = true;
        key.fCompressed = true;
        struct pubkey pubkey;
        ASSERT(privkey_get_pubkey(&key, &pubkey));
        struct key_id key_id = pubkey_get_id(&pubkey);

        wallet = zcl_calloc(1, sizeof(*wallet), "test_app_event_wallet");
        ASSERT(wallet != NULL);
        wallet_init(wallet);
        wallet_ready = true;
        ASSERT(wallet_import_key(wallet, &key));
        size_t wallet_tx_count = wallet->num_wallet_tx;
        size_t wallet_spent_count = wallet->num_spent;

        struct zcl_app_event_scope_v1 scope = test_social_scope();
        struct zcl_app_event_binding_test_spec_v1 binding_spec;
        memset(&binding_spec, 0, sizeof(binding_spec));
        binding_spec.struct_size = sizeof(binding_spec);
        binding_spec.operation = ZCL_APP_WALLET_OP_SIGN_EVENT_V1;
        binding_spec.app_generation = 7;
        binding_spec.grant_revision = 3;
        memset(binding_spec.grant_id, 0x11, sizeof(binding_spec.grant_id));
        memset(binding_spec.manifest_digest, 0x22,
               sizeof(binding_spec.manifest_digest));
        binding_spec.scope = scope;
        memcpy(binding_spec.author_key_id, key_id.id.data,
               sizeof(binding_spec.author_key_id));
        binding_spec.grant_active = true;
        struct zcl_app_event_intent_v1 intent =
            test_social_intent(payload, sizeof(payload) - 1);
        struct zcl_app_signed_event_v1 event;
        char why[256];

        ASSERT(zcl_app_event_signing_binding_v1_test_create(
            &binding_spec, &binding, why, sizeof(why)));

        ASSERT(zcl_app_signed_event_v1_sign_wallet(
            &intent, binding, wallet, &event, why, sizeof(why)));
        ASSERT(zcl_app_signed_event_v1_verify(
            &event, &scope, why, sizeof(why)));
        ASSERT(event.signature_len > 0 &&
               event.signature_len <= ZCL_APP_EVENT_SIGNATURE_MAX);
        ASSERT(memcmp(event.event_id, expected_event_id,
                      sizeof(expected_event_id)) == 0);

        uint8_t canonical[256];
        size_t canonical_len = 0;
        ASSERT(zcl_app_signed_event_v1_canonical_unsigned(
            &event, canonical, sizeof(canonical), &canonical_len,
            why, sizeof(why)));
        ASSERT(canonical_len == 187);
        ASSERT(canonical[0] == 1 && canonical[1] == 0 &&
               canonical[2] == 0 && canonical[3] == 0);
        ASSERT(canonical[36] == 6 && canonical[37] == 0);
        size_t required = 0;
        ASSERT(!zcl_app_signed_event_v1_canonical_unsigned(
            &event, NULL, 0, &required, why, sizeof(why)));
        ASSERT(required == canonical_len);

        struct zcl_app_signed_event_v1 replay;
        ASSERT(zcl_app_signed_event_v1_sign_wallet(
            &intent, binding, wallet, &replay,
            why, sizeof(why)));
        ASSERT(replay.signature_len == event.signature_len);
        ASSERT(memcmp(replay.signature, event.signature,
                      event.signature_len) == 0);
        ASSERT(memcmp(replay.event_id, event.event_id,
                      sizeof(event.event_id)) == 0);

        static const uint8_t tampered_payload[] = "jello zclassic23";
        struct zcl_app_signed_event_v1 bad = event;
        bad.payload.data = tampered_payload;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.app_id[0] = 'S';
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.topic[0] = 'x';
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.chain_id[0] ^= 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.author_key_id[0] ^= 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.author_pubkey[8] ^= 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.kind++;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.created_at++;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.sequence = 2;
        bad.previous_event_id[0] = 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.signature[bad.signature_len - 1] ^= 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.signature_len = ZCL_APP_EVENT_SIGNATURE_MAX + 1u;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        memset(bad.signature, 0, sizeof(bad.signature));
        memcpy(bad.signature, high_s_signature, sizeof(high_s_signature));
        bad.signature_len = sizeof(high_s_signature);
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        ASSERT(event.signature_len < sizeof(event.signature));
        bad = event;
        bad.signature[event.signature_len] = 1;
        ASSERT(zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.event_id[0] ^= 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.previous_event_id[0] = 1;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.payload.len = ZCL_APP_EVENT_PAYLOAD_MAX + 1u;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));
        bad = event;
        bad.payload.data = NULL;
        ASSERT(!zcl_app_signed_event_v1_verify(
            &bad, &scope, why, sizeof(why)));

        struct zcl_app_signed_event_v1 zero_event = {0};
        struct zcl_app_signed_event_v1 denied = event;
        struct zcl_app_event_signing_binding_v1 *denied_binding = NULL;
        struct zcl_app_event_binding_test_spec_v1 denied_spec = binding_spec;
        denied_spec.grant_active = false;
        ASSERT(!zcl_app_event_signing_binding_v1_test_create(
            &denied_spec, &denied_binding, why, sizeof(why)));
        ASSERT(denied_binding == NULL);
        ASSERT(!zcl_app_signed_event_v1_sign_wallet(
            &intent, NULL, wallet, &denied, why, sizeof(why)));
        ASSERT(memcmp(&denied, &zero_event, sizeof(denied)) == 0);

        struct zcl_app_event_binding_test_spec_v1 wrong_spec = binding_spec;
        wrong_spec.author_key_id[0] ^= 1;
        struct zcl_app_event_signing_binding_v1 *wrong_binding = NULL;
        ASSERT(zcl_app_event_signing_binding_v1_test_create(
            &wrong_spec, &wrong_binding, why, sizeof(why)));
        denied = event;
        ASSERT(!zcl_app_signed_event_v1_sign_wallet(
            &intent, wrong_binding, wallet, &denied, why, sizeof(why)));
        ASSERT(memcmp(&denied, &zero_event, sizeof(denied)) == 0);
        zcl_app_event_signing_binding_v1_test_destroy(wrong_binding);

        struct zcl_app_event_scope_v1 small_scope = scope;
        small_scope.max_event_bytes = (uint32_t)(canonical_len + 2 +
            event.signature_len);
        struct zcl_app_event_binding_test_spec_v1 small_spec = binding_spec;
        small_spec.scope = small_scope;
        struct zcl_app_event_signing_binding_v1 *small_binding = NULL;
        ASSERT(zcl_app_event_signing_binding_v1_test_create(
            &small_spec, &small_binding, why, sizeof(why)));
        denied = event;
        ASSERT(zcl_app_signed_event_v1_sign_wallet(
            &intent, small_binding, wallet, &denied, why, sizeof(why)));
        ASSERT(zcl_app_signed_event_v1_verify(
            &denied, &small_scope, why, sizeof(why)));
        zcl_app_event_signing_binding_v1_test_destroy(small_binding);
        small_scope.max_event_bytes--;
        small_spec.scope = small_scope;
        small_binding = NULL;
        ASSERT(zcl_app_event_signing_binding_v1_test_create(
            &small_spec, &small_binding, why, sizeof(why)));
        denied = event;
        ASSERT(!zcl_app_signed_event_v1_sign_wallet(
            &intent, small_binding, wallet, &denied, why, sizeof(why)));
        ASSERT(memcmp(&denied, &zero_event, sizeof(denied)) == 0);
        zcl_app_event_signing_binding_v1_test_destroy(small_binding);

        struct zcl_app_event_scope_v1 malformed_scope = scope;
        memset(malformed_scope.app_id, 'x', sizeof(malformed_scope.app_id));
        struct zcl_app_event_binding_test_spec_v1 malformed_spec = binding_spec;
        malformed_spec.scope = malformed_scope;
        struct zcl_app_event_signing_binding_v1 *malformed_binding = NULL;
        ASSERT(!zcl_app_event_signing_binding_v1_test_create(
            &malformed_spec, &malformed_binding, why, sizeof(why)));
        ASSERT(malformed_binding == NULL);

        uint8_t failed_id[32];
        memset(failed_id, 0xff, sizeof(failed_id));
        bad = event;
        bad.version = 0;
        ASSERT(!zcl_app_signed_event_v1_id(
            &bad, failed_id, why, sizeof(why)));
        uint8_t zero_id[32] = {0};
        ASSERT(memcmp(failed_id, zero_id, sizeof(failed_id)) == 0);
        ASSERT(wallet->num_wallet_tx == wallet_tx_count);
        ASSERT(wallet->num_spent == wallet_spent_count);
        PASS();
    } _test_next:;
    if (wallet) {
        if (wallet_ready)
            wallet_free(wallet);
        free(wallet);
    }
    zcl_app_event_signing_binding_v1_test_destroy(binding);
    return failures;
}

static int test_social_sim(void)
{
    int failures = 0;
    TEST("dev platform: social censorship proof is deterministic") {
        const uint64_t seed = UINT64_C(0x534f4349414c0001);
        struct zcl_social_sim_report a, b;
        ASSERT(zcl_social_app_sim_run(seed, &a));
        ASSERT(zcl_social_app_sim_run(seed, &b));
        ASSERT(a.censorship_bypassed);
        ASSERT(a.partition_rejoin_converged);
        ASSERT(a.late_joiner_caught_up);
        ASSERT(a.invalid_signature_rejected);
        ASSERT(a.real_secp256k1_verified);
        ASSERT(a.tampered_payload_rejected);
        ASSERT(a.wrong_author_rejected);
        ASSERT(a.forged_event_id_distinct);
        ASSERT(a.transcript == b.transcript);
        ASSERT(a.deliveries == b.deliveries);
        PASS();
    } _test_next:;
    return failures;
}

/* Wave 3.2 native activation engine wiring (devloop_cycle.c /
 * native_dev_command.c). devloop_cycle.c's own transactional_reload branch
 * and native_dev_command.c's dev.vcs.revert relink seam are both
 * ZCL_DEV_BUILD-only (they exec `make`/`systemctl`), so this build
 * (-DZCL_TESTING, no ZCL_DEV_BUILD -- see test_core_refusal_token() above)
 * cannot reach them directly. What IS reachable and load-bearing here is the
 * pure glue both call sites share (declared in devloop.h, defined in
 * devloop_cycle.c, compiled under `ZCL_DEV_BUILD || ZCL_TESTING`): the
 * ZCL_DEV_NATIVE_ACTIVATION switch itself, the dev-lane request builder, and
 * the result mapper. The switch selects retained machinery only; public
 * publication entrypoints remain contained for every value. */
static int test_native_activation_switch(void)
{
    int failures = 0;
    TEST("dev platform: retained native engine selector defaults OFF") {
        char *saved = getenv("ZCL_DEV_NATIVE_ACTIVATION");
        saved = saved ? strdup(saved) : NULL;

        unsetenv("ZCL_DEV_NATIVE_ACTIVATION");
        ASSERT(!dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "", 1);
        ASSERT(!dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "0", 1);
        ASSERT(!dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "nah", 1);
        ASSERT(!dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "1", 1);
        ASSERT(dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "true", 1);
        ASSERT(dev_activation_native_enabled());

        setenv("ZCL_DEV_NATIVE_ACTIVATION", "yes", 1);
        ASSERT(dev_activation_native_enabled());

        if (saved) {
            setenv("ZCL_DEV_NATIVE_ACTIVATION", saved, 1);
            free(saved);
        } else {
            unsetenv("ZCL_DEV_NATIVE_ACTIVATION");
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_activation_request_builder(void)
{
    int failures = 0;
    TEST("dev platform: dev_activation_request_from_cycle builds dev-lane defaults") {
        char dir[512];
        test_make_tmpdir(dir, sizeof(dir), "native_activation", "request");
        char *saved_home = getenv("HOME");
        saved_home = saved_home ? strdup(saved_home) : NULL;
        char *saved_gen_root = getenv("ZCL_DEV_GENERATION_ROOT");
        saved_gen_root = saved_gen_root ? strdup(saved_gen_root) : NULL;
        unsetenv("ZCL_DEV_GENERATION_ROOT");
        setenv("HOME", dir, 1);

        struct dev_activation_cycle_request creq;
        ASSERT(dev_activation_request_from_cycle("/repo", "abc1234", &creq));
        ASSERT(strcmp(creq.req.repo_root, "/repo") == 0);
        ASSERT(strcmp(creq.req.artifact_path,
                      "/repo/build/bin/zclassic23-dev") == 0);
        ASSERT(strcmp(creq.req.build_commit, "abc1234") == 0);
        ASSERT(strcmp(creq.req.build_type, "fast") == 0);
        ASSERT(strcmp(creq.req.unit, "zcl23-dev.service") == 0);
        ASSERT(creq.req.rpcport == 18252);
        ASSERT(creq.req.mode == DEV_ACTIVATION_MODE_ACTIVATE);
        char want_datadir[1024], want_gen_root[1024];
        snprintf(want_datadir, sizeof(want_datadir), "%s/.zclassic-c23-dev", dir);
        snprintf(want_gen_root, sizeof(want_gen_root),
                "%s/.local/lib/zclassic23-dev", dir);
        ASSERT(strcmp(creq.req.datadir, want_datadir) == 0);
        ASSERT(strcmp(creq.req.gen_root, want_gen_root) == 0);

        /* ZCL_DEV_GENERATION_ROOT overrides the default, same as
         * deploy-dev-lane.sh and native_dev_command.c:dev_generation_root(). */
        setenv("ZCL_DEV_GENERATION_ROOT", "/custom/gen-root", 1);
        ASSERT(dev_activation_request_from_cycle("/repo", "abc1234", &creq));
        ASSERT(strcmp(creq.req.gen_root, "/custom/gen-root") == 0);
        unsetenv("ZCL_DEV_GENERATION_ROOT");

        /* build_commit may be empty (the vcs.vcs.revert seam's use) but not
         * NULL; repo_root/out must not be NULL either. */
        ASSERT(dev_activation_request_from_cycle("/repo", "", &creq));
        ASSERT(creq.req.build_commit[0] == '\0');
        ASSERT(!dev_activation_request_from_cycle(NULL, "abc1234", &creq));
        ASSERT(!dev_activation_request_from_cycle("/repo", NULL, &creq));
        ASSERT(!dev_activation_request_from_cycle("/repo", "abc1234", NULL));

        unsetenv("HOME");
        ASSERT(!dev_activation_request_from_cycle("/repo", "abc1234", &creq));

        if (saved_home) {
            setenv("HOME", saved_home, 1);
            free(saved_home);
        } else {
            unsetenv("HOME");
        }
        if (saved_gen_root) {
            setenv("ZCL_DEV_GENERATION_ROOT", saved_gen_root, 1);
            free(saved_gen_root);
        } else {
            unsetenv("ZCL_DEV_GENERATION_ROOT");
        }
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_activation_result_mapping(void)
{
    int failures = 0;
    TEST("dev platform: dev_activation_map_result maps status/capsule/generation") {
        struct dev_activation_result r = {0};
        r.status = DEV_ACTIVATION_OK;
        snprintf(r.candidate_sha256, sizeof(r.candidate_sha256),
                "%064x", 0);
        struct dev_activation_cycle_outcome out;
        dev_activation_map_result(&r, &out);
        ASSERT(out.ok);
        ASSERT(out.capsule[0] == '\0');
        ASSERT(strcmp(out.generation_hex, r.candidate_sha256) == 0);

        memset(&r, 0, sizeof(r));
        r.status = DEV_ACTIVATION_E_PREFLIGHT;
        snprintf(r.failure_capsule, sizeof(r.failure_capsule),
                "candidate preflight failed");
        dev_activation_map_result(&r, &out);
        ASSERT(!out.ok);
        ASSERT(strcmp(out.capsule, "candidate preflight failed") == 0);

        /* When failure_capsule is empty, verify_detail is the fallback. */
        memset(&r, 0, sizeof(r));
        r.status = DEV_ACTIVATION_E_ACTIVATE;
        snprintf(r.verify_detail, sizeof(r.verify_detail),
                "activation probe did not become ready");
        dev_activation_map_result(&r, &out);
        ASSERT(!out.ok);
        ASSERT(strcmp(out.capsule, "activation probe did not become ready") == 0);

        /* NULL result -> zeroed, never-ok outcome, never a crash. */
        dev_activation_map_result(NULL, &out);
        ASSERT(!out.ok);
        ASSERT(out.capsule[0] == '\0');
        ASSERT(out.generation_hex[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

static int test_watch_relevance(void)
{
    int failures = 0;
    TEST("dev platform: watcher ignores transient lint fixtures, keeps real edits") {
        /* The bug this guards: the persistent watcher fired a phantom reload
         * cycle every test-suite run because test_make_lint_gates.c writes
         * `_*fixture*` .c files under app/, lib/, domain/ then deletes them. */
        static const char *const fixtures[] = {
            "app/_lint_gate_fixture_tmp.c",
            "app/_node_db_exec_lint_fixture_probe_tmp.c",
            "app/_e10_offshape_fixture_probe_tmp.c",
            "app/controllers/src/_coins_lookup_guard_fixture_tmp.c",
            "app/jobs/src/_e5_stage_fixture_tmp_stage.c",
            "lib/storage/src/_e4_pure_fixture_projection.c",
            "domain/wallet/src/_domain_purity_fixture_tmp.c",
        };
        for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++)
            ASSERT(!zcl_devloop_path_is_relevant(fixtures[i]));

        /* Real edits — including the genuine fixture SOURCES under
         * lib/test/fixtures/ (no leading underscore) — must still fire. */
        static const char *const real[] = {
            "app/jobs/src/stage_repair_reducer_frontier_coin.c",
            "core/consensus/src/check_block.c",
            "tools/dev/devloop_watch.c",
            "lib/test/fixtures/raw_sqlite_step_fixture.c",
            "docs/HANDOFF.md",
            "Makefile",
            "app/controllers/include/controllers/agent_impact_rules.def",
        };
        for (size_t i = 0; i < sizeof(real) / sizeof(real[0]); i++)
            ASSERT(zcl_devloop_path_is_relevant(real[i]));

        /* Editor temp / build / vcs noise stays filtered. */
        ASSERT(!zcl_devloop_path_is_relevant("app/services/src/foo.c~"));
        ASSERT(!zcl_devloop_path_is_relevant("build/bin/zclassic23"));
        ASSERT(!zcl_devloop_path_is_relevant(".git/index"));
        ASSERT(!zcl_devloop_path_is_relevant(""));
        ASSERT(!zcl_devloop_path_is_relevant(NULL));
        /* Reading/compiling source may update atime and emit IN_ATTRIB. That
         * is not a save and must never recursively cancel the active epoch. */
        ASSERT(!zcl_devloop_watch_event_is_mutation(IN_ATTRIB));
        ASSERT(zcl_devloop_watch_event_is_mutation(IN_CLOSE_WRITE));
        ASSERT(zcl_devloop_watch_event_is_mutation(IN_MOVED_TO));
        ASSERT(zcl_devloop_watch_event_is_mutation(IN_DELETE));
        /* A cancelled focused test can leave its dot-prefixed scratch
         * directory briefly visible at the checkout root. Directory noise
         * the recursive watcher never enters must not synthesize a Makefile
         * change and supersede the exact source epoch being proved. */
        ASSERT(zcl_devloop_watch_dir_is_ignored(".zcl_test_api"));
        ASSERT(zcl_devloop_watch_dir_is_ignored("test-tmp"));
        ASSERT(zcl_devloop_watch_dir_is_ignored("build"));
        ASSERT(!zcl_devloop_watch_dir_is_ignored("app"));
        ASSERT(!zcl_devloop_watch_dir_is_ignored("lib"));
        PASS();
    } _test_next:;
    return failures;
}

static void fill_hex(char out[65], char digit)
{
    memset(out, digit, 64);
    out[64] = 0;
}

static bool failure_record_path(char out[PATH_MAX], const char *home,
                                const struct zcl_dev_failure_record *record,
                                const char *leaf)
{
    int n = snprintf(
        out, PATH_MAX,
        "%s/.local/state/zclassic23-dev/workspaces/%s/failures/%s/%s",
        home, record->workspace_id, record->failure_id, leaf);
    return n > 0 && n < PATH_MAX;
}

static bool run_failure_store_fixture(void)
{
    bool ok = false;
    char home[PATH_MAX], repo1[PATH_MAX], repo2[PATH_MAX], repo3[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    if (getenv("HOME") && !saved_home)
        return false;
    test_make_tmpdir(home, sizeof(home), "dev_platform", "failure_store");
    if (snprintf(repo1, sizeof(repo1), "%s/repo1", home) <= 0 ||
        snprintf(repo2, sizeof(repo2), "%s/repo2", home) <= 0 ||
        snprintf(repo3, sizeof(repo3), "%s/repo3", home) <= 0 ||
        mkdir(repo1, 0700) != 0 || mkdir(repo2, 0700) != 0 ||
        mkdir(repo3, 0700) != 0 || setenv("HOME", home, 1) != 0)
        goto cleanup;

#define FS_REQUIRE(expr)                                                     \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "failure-store fixture failed at %s:%d: %s\n", \
                    __FILE__, __LINE__, #expr);                              \
            goto cleanup;                                                    \
        }                                                                    \
    } while (0)

    char source[65], mutation1[65], mutation2[65], execution1[65],
         execution2[65], why[192] = {0};
    fill_hex(source, 'a');
    fill_hex(mutation1, 'b');
    fill_hex(mutation2, 'd');
    fill_hex(execution1, 'c');
    fill_hex(execution2, 'e');

    struct zcl_dev_failure_record record, readback;
    FS_REQUIRE(zcl_dev_failure_read_latest(repo1, &readback, why,
                                           sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_ABSENT);
    char state_dir[PATH_MAX];
    FS_REQUIRE(zcl_devloop_workspace_state_dir(repo1, state_dir,
                                               sizeof(state_dir)));
    FS_REQUIRE(access(state_dir, F_OK) != 0); /* reads create no state */

    char normalized[ZCL_DEV_FAILURE_ERROR_MAX], pinned[65];
    FS_REQUIRE(zcl_dev_failure_normalize_error(
        " \tfoo.c:1: error: bad   token \r\nignored",
        normalized));
    FS_REQUIRE(strcmp(normalized, "foo.c:1: error: bad token") == 0);
    FS_REQUIRE(zcl_dev_failure_compute_id(
        source, "verify.compile", "foo.c:1: error: bad", pinned));
    FS_REQUIRE(strcmp(
        pinned,
        "be4309e5f776d702bf96a5ed6d36b5be1dfd559176bb7b767860ffd00af14b37")
        == 0);

    const char *error = "foo.c:12:5: error: bad token";
    const char *capsule =
        "first_error=foo.c:12:5: error: bad token\n\"quoted\"\\tail";
    FS_REQUIRE(zcl_dev_failure_record_failure(
        repo1, source, mutation1, execution1, "verify.compile", error,
        capsule, "dev.ff", &record, why, sizeof(why)));
    FS_REQUIRE(record.repeat_count == 1);
    FS_REQUIRE(strcmp(record.first_source_mutation, mutation1) == 0);
    FS_REQUIRE(strcmp(record.first_execution_id, execution1) == 0);
    FS_REQUIRE(strcmp(record.retry_command, "dev.ff") == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo1, record.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_FOUND);
    FS_REQUIRE(strcmp(readback.record_digest, record.record_digest) == 0);
    FS_REQUIRE(zcl_dev_failure_match_latest(
        repo1, source, mutation1, execution1, "verify.compile", &readback,
        why, sizeof(why)));
    FS_REQUIRE(!zcl_dev_failure_match_latest(
        repo1, source, mutation2, execution1, "verify.compile", &readback,
        why, sizeof(why)) && why[0] == 0);
    FS_REQUIRE(!zcl_dev_failure_note_coalesced(
        repo1, record.failure_id, source, mutation2, execution1,
        "verify.compile", &readback, why, sizeof(why)));
    FS_REQUIRE(zcl_dev_failure_note_coalesced(
        repo1, record.failure_id, source, mutation1, execution1,
        "verify.compile", &readback, why, sizeof(why)));
    FS_REQUIRE(readback.repeat_count == 2);

    struct zcl_dev_failure_record observed;
    FS_REQUIRE(zcl_dev_failure_record_failure(
        repo1, source, mutation2, execution2, "verify.compile", error,
        capsule, "dev.ff", &observed, why, sizeof(why)));
    FS_REQUIRE(strcmp(observed.failure_id, record.failure_id) == 0);
    FS_REQUIRE(observed.repeat_count == 3);
    FS_REQUIRE(strcmp(observed.first_source_mutation, mutation1) == 0);
    FS_REQUIRE(strcmp(observed.first_execution_id, execution1) == 0);
    FS_REQUIRE(zcl_dev_failure_match_latest(
        repo1, source, mutation2, execution2, "verify.compile", &readback,
        why, sizeof(why)));

    pid_t children[8];
    for (size_t i = 0; i < 8; i++) {
        children[i] = fork();
        FS_REQUIRE(children[i] >= 0);
        if (children[i] == 0) {
            struct zcl_dev_failure_record child_record;
            char child_why[128] = {0};
            bool child_ok = zcl_dev_failure_note_coalesced(
                repo1, record.failure_id, source, mutation2, execution2,
                "verify.compile", &child_record, child_why,
                sizeof(child_why));
            _exit(child_ok ? 0 : 90);
        }
    }
    for (size_t i = 0; i < 8; i++) {
        int status = 0;
        FS_REQUIRE(waitpid(children[i], &status, 0) == children[i]);
        FS_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    FS_REQUIRE(zcl_dev_failure_read(repo1, record.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_FOUND);
    FS_REQUIRE(readback.repeat_count == 11);
    FS_REQUIRE(zcl_dev_failure_read_latest(repo2, &readback, why,
                                           sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_ABSENT);

    /* Cycle verdicts share the exact worktree scope and distinguish absent,
     * found, and invalid sealed state. */
    static const char cycle[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"passed\",\"action\":\"check\","
        "\"reason\":\"fixture\",\"phase\":\"verify\","
        "\"runtime_published\":false,\"elapsed_ms\":1,\"files\":[]}";
    static const char cycle_impact[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"impact_ready\",\"action\":\"reflex\","
        "\"reason\":\"fixture\",\"phase\":\"IMPACT_READY\","
        "\"runtime_published\":false,\"elapsed_ms\":2,\"files\":[]}";
    static const char cycle_compile[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"compile_green\",\"action\":\"reflex\","
        "\"reason\":\"fixture\",\"phase\":\"COMPILE_GREEN\","
        "\"runtime_published\":false,\"elapsed_ms\":3,\"files\":[]}";
    FS_REQUIRE(zcl_devloop_cycle_state_write(
        repo1, cycle, sizeof(cycle) - 1, why, sizeof(why)));
    char cycle_out[4096];
    size_t cycle_len = 0;
    int64_t cycle_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &cycle_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(cycle_len == sizeof(cycle) - 1 &&
               memcmp(cycle_out, cycle, cycle_len) == 0 && cycle_epoch > 0);
    int64_t first_cycle_epoch = cycle_epoch;
    cycle_len = 0;
    cycle_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read_after(
        repo1, 0, cycle_out, sizeof(cycle_out), &cycle_len, &cycle_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(cycle_epoch == first_cycle_epoch &&
               cycle_len == sizeof(cycle) - 1 &&
               memcmp(cycle_out, cycle, cycle_len) == 0);
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo2, cycle_out, sizeof(cycle_out), &cycle_len, &cycle_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_ABSENT);

    char path[PATH_MAX];
    FS_REQUIRE(snprintf(path, sizeof(path), "%s/native-cycle.json",
                        state_dir) > 0);
    char sealed_cycle_record[32768];
    FILE *cycle_file = fopen(path, "r");
    FS_REQUIRE(cycle_file != NULL);
    size_t sealed_cycle_len =
        fread(sealed_cycle_record, 1, sizeof(sealed_cycle_record), cycle_file);
    FS_REQUIRE(!ferror(cycle_file) && fclose(cycle_file) == 0 &&
               sealed_cycle_len > 0 &&
               sealed_cycle_len < sizeof(sealed_cycle_record));
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    FS_REQUIRE(fd >= 0 && pwrite(fd, "X", 1, 0) == 1 && close(fd) == 0);
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &cycle_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_INVALID);
    FS_REQUIRE(!zcl_devloop_cycle_state_write(
        repo1, cycle, sizeof(cycle) - 1, why, sizeof(why)));

    /* Publication fails closed on corrupt current state. Physical restoration
     * of the exact prior sealed generation recovers without lowering epoch. */
    cycle_file = fopen(path, "w");
    FS_REQUIRE(cycle_file != NULL &&
               fwrite(sealed_cycle_record, 1, sealed_cycle_len, cycle_file) ==
                   sealed_cycle_len &&
               fflush(cycle_file) == 0 && fsync(fileno(cycle_file)) == 0 &&
               fclose(cycle_file) == 0);
    int64_t restored_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &restored_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(restored_epoch == first_cycle_epoch);
    FS_REQUIRE(zcl_devloop_cycle_stream_reset(
        repo1, restored_epoch, why, sizeof(why)));
    int64_t second_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_stream_publish(
        repo1, cycle_impact, sizeof(cycle_impact) - 1, &second_epoch,
        why, sizeof(why)));
    FS_REQUIRE(second_epoch == restored_epoch + 1);
    int64_t still_durable_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &still_durable_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(still_durable_epoch == restored_epoch);
    /* The volatile bounded stream is observable before its durable journal
     * consumer runs; this is the latency firewall's load-bearing property. */
    FS_REQUIRE(zcl_devloop_cycle_state_read_after(
        repo1, first_cycle_epoch, cycle_out, sizeof(cycle_out), &cycle_len,
        &cycle_epoch, why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(cycle_epoch == second_epoch &&
               cycle_len == sizeof(cycle_impact) - 1 &&
               memcmp(cycle_out, cycle_impact, cycle_len) == 0);

    int64_t third_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_stream_publish(
        repo1, cycle_compile, sizeof(cycle_compile) - 1, &third_epoch,
        why, sizeof(why)));
    FS_REQUIRE(zcl_devloop_cycle_state_read_after(
        repo1, second_epoch, cycle_out, sizeof(cycle_out), &cycle_len,
        &third_epoch, why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(third_epoch == second_epoch + 1 &&
               cycle_len == sizeof(cycle_compile) - 1 &&
               memcmp(cycle_out, cycle_compile, cycle_len) == 0);
    /* One post-feedback flush seals every earlier volatile event in order;
     * callers never have to move epoch numbers or bodies by hand. */
    FS_REQUIRE(zcl_devloop_cycle_stream_flush_through(
        repo1, third_epoch, why, sizeof(why)));
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &still_durable_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(still_durable_epoch == third_epoch);

    /* Restarting the resident stream at its durable anchor must discard every
     * unjournaled slot from the prior generation, even when the ring file was
     * already at its final size. */
    pid_t stream_child = fork();
    FS_REQUIRE(stream_child >= 0);
    if (stream_child == 0) {
        char child_why[128] = {0};
        int64_t child_epoch = 0;
        platform_sleep_ms(20);
        bool child_ok = zcl_devloop_cycle_stream_publish(
            repo1, cycle_impact, sizeof(cycle_impact) - 1, &child_epoch,
            child_why, sizeof(child_why));
        _exit(child_ok ? 0 : 92);
    }
    int64_t abandoned_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_wait_after(
        repo1, third_epoch, 1000, cycle_out, sizeof(cycle_out), &cycle_len,
        &abandoned_epoch, why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    int stream_status = 0;
    FS_REQUIRE(waitpid(stream_child, &stream_status, 0) == stream_child);
    FS_REQUIRE(WIFEXITED(stream_status) && WEXITSTATUS(stream_status) == 0);
    FS_REQUIRE(abandoned_epoch == third_epoch + 1);
    FS_REQUIRE(zcl_devloop_cycle_stream_reset(
        repo1, third_epoch, why, sizeof(why)));
    FS_REQUIRE(zcl_devloop_cycle_state_read_after(
        repo1, third_epoch, cycle_out, sizeof(cycle_out), &cycle_len,
        &cycle_epoch, why, sizeof(why)) == ZCL_DEVLOOP_STATE_ABSENT);

    /* Inode timestamp changes are not wait authority. */
    struct timespec times[2] = {
        { .tv_sec = 1, .tv_nsec = 0 }, { .tv_sec = 1, .tv_nsec = 0 }
    };
    FS_REQUIRE(utimensat(AT_FDCWD, path, times, 0) == 0);
    int64_t timestamp_tamper_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len,
        &timestamp_tamper_epoch, why, sizeof(why)) ==
               ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(timestamp_tamper_epoch == third_epoch);

    /* Concurrent writers serialize through the workspace capability lock. */
    pid_t cycle_children[8];
    for (size_t i = 0; i < 8; i++) {
        cycle_children[i] = fork();
        FS_REQUIRE(cycle_children[i] >= 0);
        if (cycle_children[i] == 0) {
            char child_why[128] = {0};
            bool child_ok = zcl_devloop_cycle_state_write(
                repo1, cycle, sizeof(cycle) - 1, child_why,
                sizeof(child_why));
            _exit(child_ok ? 0 : 91);
        }
    }
    for (size_t i = 0; i < 8; i++) {
        int status = 0;
        FS_REQUIRE(waitpid(cycle_children[i], &status, 0) ==
                   cycle_children[i]);
        FS_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    int64_t concurrent_epoch = 0;
    FS_REQUIRE(zcl_devloop_cycle_state_read(
        repo1, cycle_out, sizeof(cycle_out), &cycle_len, &concurrent_epoch,
        why, sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND);
    FS_REQUIRE(concurrent_epoch == third_epoch + 8);

    /* The first-newer contract never jumps over a damaged sealed event. */
    char event_path[PATH_MAX];
    FS_REQUIRE(snprintf(event_path, sizeof(event_path),
                        "%s/cycle-events/%020lld.json", state_dir,
                        (long long)second_epoch) > 0);
    fd = open(event_path, O_WRONLY | O_CLOEXEC);
    FS_REQUIRE(fd >= 0 && pwrite(fd, "X", 1, 0) == 1 && close(fd) == 0);
    FS_REQUIRE(zcl_devloop_cycle_state_read_after(
        repo1, first_cycle_epoch, cycle_out, sizeof(cycle_out), &cycle_len,
        &cycle_epoch, why, sizeof(why)) == ZCL_DEVLOOP_STATE_INVALID);
    FS_REQUIRE(strcmp(why, "cycle_event_integrity_invalid") == 0);

    /* A syntactically valid-looking counter edit still breaks its SHA3 seal. */
    FS_REQUIRE(failure_record_path(path, home, &record,
                                   "observations.json"));
    char observation_body[1024];
    FILE *observation_file = fopen(path, "r");
    FS_REQUIRE(observation_file != NULL);
    size_t observation_len = fread(observation_body, 1,
                                   sizeof(observation_body) - 1,
                                   observation_file);
    FS_REQUIRE(!ferror(observation_file) && fclose(observation_file) == 0 &&
               observation_len > 0);
    observation_body[observation_len] = 0;
    char *count_value = strstr(observation_body, "\"count\":11");
    FS_REQUIRE(count_value != NULL);
    fd = open(path, O_WRONLY | O_CLOEXEC);
    off_t count_digit = (off_t)(count_value - observation_body) +
                        (off_t)strlen("\"count\":1");
    FS_REQUIRE(fd >= 0 && pwrite(fd, "2", 1, count_digit) == 1 &&
               close(fd) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo1, record.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_INVALID);

    /* A second workspace proves private-mode, hardlink, and symlink rejection
     * without relying on the now-intentionally-corrupt first record. */
    struct zcl_dev_failure_record record2;
    FS_REQUIRE(zcl_dev_failure_record_failure(
        repo2, source, mutation1, execution1, "verify.compile", error,
        capsule, "dev.ff", &record2, why, sizeof(why)));
    FS_REQUIRE(failure_record_path(path, home, &record2, "base.json"));
    FS_REQUIRE(chmod(path, 0644) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo2, record2.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_INVALID);
    FS_REQUIRE(chmod(path, 0600) == 0);
    char alias[PATH_MAX];
    FS_REQUIRE(snprintf(alias, sizeof(alias), "%s.hardlink", path) > 0);
    FS_REQUIRE(link(path, alias) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo2, record2.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_INVALID);
    FS_REQUIRE(unlink(alias) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo2, record2.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_FOUND);
    FS_REQUIRE(unlink(path) == 0 && symlink("/etc/passwd", path) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo2, record2.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_INVALID);

    /* Third workspace: an unsealed extra JSON field is rejected. */
    struct zcl_dev_failure_record record3;
    FS_REQUIRE(zcl_dev_failure_record_failure(
        repo3, source, mutation1, execution1, "verify.compile", error,
        capsule, "dev.ff", &record3, why, sizeof(why)));
    FS_REQUIRE(failure_record_path(path, home, &record3, "base.json"));
    char json_body[4096];
    FILE *f = fopen(path, "r");
    FS_REQUIRE(f != NULL);
    size_t json_len = fread(json_body, 1, sizeof(json_body) - 1, f);
    FS_REQUIRE(!ferror(f) && fclose(f) == 0 && json_len > 2);
    while (json_len > 0 &&
           (json_body[json_len - 1] == '\n' ||
            json_body[json_len - 1] == '\r'))
        json_len--;
    FS_REQUIRE(json_len > 0 && json_body[json_len - 1] == '}');
    json_len--;
    static const char extra[] = ",\"unsealed_extra\":true}\n";
    FS_REQUIRE(json_len + sizeof(extra) < sizeof(json_body));
    memcpy(json_body + json_len, extra, sizeof(extra) - 1);
    json_len += sizeof(extra) - 1;
    fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
    FS_REQUIRE(fd >= 0 &&
               write(fd, json_body, json_len) == (ssize_t)json_len &&
               fsync(fd) == 0 && close(fd) == 0);
    FS_REQUIRE(zcl_dev_failure_read(repo3, record3.failure_id, &readback,
                                    why, sizeof(why)) ==
               ZCL_DEV_FAILURE_LOOKUP_INVALID);

    ok = true;

cleanup:
    if (saved_home) {
        (void)setenv("HOME", saved_home, 1);
        free(saved_home);
    } else
        (void)unsetenv("HOME");
    test_rm_rf_recursive(home);
#undef FS_REQUIRE
    return ok;
}

static int test_failure_store(void)
{
    int failures = 0;
    TEST("dev platform: failure receipts are scoped, sealed, concurrent, and fail closed") {
        ASSERT(run_failure_store_fixture());
        PASS();
    } _test_next:;
    return failures;
}

/* A4: distill_first_error picks the first actionable line (compiler
 * ": error:" or test FAIL/Assertion/EXPECT) and falls back cleanly when no
 * pattern matches. Exercised via the thin zcl_devloop_distill_first_error
 * wrapper (the underlying function is static in devloop_cycle.c). */
static int test_distill_first_error(void)
{
    int failures = 0;
    TEST("dev platform: distill_first_error extracts the first actionable line") {
        char dst[256];

        /* A compiler ": error:" line is extracted, newline-stripped, even when
         * it is not the last line of output. */
        const char *compiler =
            "cc -c foo.c\n"
            "foo.c: In function 'bar':\n"
            "foo.c:12:5: error: 'x' undeclared (first use in this function)\n"
            "make: *** [foo.o] Error 1\n";
        ASSERT(zcl_devloop_distill_first_error(compiler, strlen(compiler),
                                               dst, sizeof(dst)));
        ASSERT(strcmp(dst,
            "foo.c:12:5: error: 'x' undeclared (first use in this function)")
            == 0);

        /* A test FAIL line is extracted. */
        const char *testfail =
            "running group vcs_devloop\n"
            "[dev-watch-selftest] FAIL: stage command order is wrong\n"
            "1 failure\n";
        ASSERT(zcl_devloop_distill_first_error(testfail, strlen(testfail),
                                               dst, sizeof(dst)));
        ASSERT(strcmp(dst,
            "[dev-watch-selftest] FAIL: stage command order is wrong") == 0);

        /* An Assertion line is extracted (the first actionable line wins over
         * a later error-looking line). */
        const char *assertion =
            "ok: sanity\n"
            "Assertion `n > 0 && n < sizeof(body)' failed.\n";
        ASSERT(zcl_devloop_distill_first_error(assertion, strlen(assertion),
                                               dst, sizeof(dst)));
        ASSERT(strcmp(dst, "Assertion `n > 0 && n < sizeof(body)' failed.")
            == 0);

        /* No matching pattern => false, dst emptied (caller falls back to the
         * tail). */
        const char *clean = "cc -c foo.c\nlink ok\nall good here\n";
        ASSERT(!zcl_devloop_distill_first_error(clean, strlen(clean),
                                                dst, sizeof(dst)));
        ASSERT(dst[0] == 0);

        /* Bounded copy: a long matching line is truncated to dstcap-1, never
         * overruns, always NUL-terminated. */
        char tiny[8];
        const char *longline = "src.c:1:1: error: this line is far too long\n";
        ASSERT(zcl_devloop_distill_first_error(longline, strlen(longline),
                                               tiny, sizeof(tiny)));
        ASSERT(strlen(tiny) == sizeof(tiny) - 1);

        /* Defensive: NULL / zero-cap inputs are rejected without a crash. */
        ASSERT(!zcl_devloop_distill_first_error(NULL, 0, dst, sizeof(dst)));
        ASSERT(!zcl_devloop_distill_first_error(compiler, strlen(compiler),
                                                dst, 0));

        struct zcl_devloop_process_result result;
        memset(&result, 0, sizeof(result));
        result.exit_code = 1;
        (void)snprintf(
            result.output, sizeof(result.output),
            "raw compiler output\n"
            "[agent-fast-ci] FIRST-ERROR[compile]: "
            "foo.c:12:5: error: bad token\n"
            "[agent-fast-ci] FAIL: rung compile failed (exit 2)\n");
        result.output_len = strlen(result.output);
        char classified[512];
        ASSERT(zcl_devloop_deterministic_compile_failure(
            &result, classified));
        ASSERT(strcmp(classified, "foo.c:12:5: error: bad token") == 0);

        (void)snprintf(
            result.output, sizeof(result.output),
            "source.c:9:1: error: literal says "
            "[agent-fast-ci] FIRST-ERROR[compile]: "
            "fake.c:1:1: error: fake\n");
        result.output_len = strlen(result.output);
        ASSERT(!zcl_devloop_deterministic_compile_failure(
            &result, classified)); /* marker is not at a line boundary */

        (void)snprintf(
            result.output, sizeof(result.output),
            "[agent-fast-ci] FIRST-ERROR[compile]: "
            "foo.c:12:5: error: Killed\n");
        result.output_len = strlen(result.output);
        ASSERT(!zcl_devloop_deterministic_compile_failure(
            &result, classified));
        result.timed_out = true;
        ASSERT(!zcl_devloop_deterministic_compile_failure(
            &result, classified));
        result.timed_out = false;
        result.term_signal = 9;
        ASSERT(!zcl_devloop_deterministic_compile_failure(
            &result, classified));
        PASS();
    } _test_next:;
    return failures;
}

static bool dp_hotswap_cache_fixture_init(const char *root,
                                          const char *compiler)
{
    static const char owner_v1[] =
        "int zcl_hotswap_fixture_owner(void) { return 1; }\n";
    if (!dp_mk_write(root, "Makefile", "# fixture\n") ||
        !dp_mk_write(root, "config/hotswap_swappable.def", "/* fixture */\n") ||
        !dp_mk_write(root, "config/hotswap_islands.def", "/* fixture */\n") ||
        !dp_mk_write(root, "config/hotswap_services.def", "/* fixture */\n") ||
        !dp_mk_write(root, "config/hotswap_shadow_owners.def",
                     "/* fixture */\n") ||
        !dp_mk_write(root, "config/hotfork_capsules.def",
                     "/* fixture */\n") ||
        !dp_mk_write(root, "app/controllers/src/status_native_handlers.c",
                     owner_v1) ||
        !dp_mk_write(root, "app/controllers/src/status_native_helpers.c",
                     "int zcl_hotswap_fixture_helper(void) { return 2; }\n") ||
        !dp_mk_write(root,
                     "app/services/src/zcode_c23_corpus_service.c",
                     "int zcl_hotswap_fixture_service(void) { return 3; }\n") ||
        !dp_mk_write(root,
                     "app/services/src/zcode_c23_economics_service.c",
                     "#include \"zcode_c23_economics_internal.h\"\n"
                     "int zcl_hotswap_fixture_economics(void) { return 4; }\n") ||
        !dp_mk_write(root,
                     "app/services/src/zcode_c23_economics_internal.h",
                     "#define ZCL_ECONOMICS_FIXTURE 4\n"))
        return false;
    char canonical_root[PATH_MAX];
    if (!realpath(root, canonical_root))
        return false;
    char flags[PATH_MAX * 2];
    int n = snprintf(
        flags, sizeof(flags),
        "CC=%s\n"
        "COMPILER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "DEV_CFLAGS=-DZCL_DEV_BUILD -ffile-prefix-map=%s=/zclassic23\n"
        "HOTSWAP_MODULE_LDFLAGS=-shared -Wl,-Bsymbolic\n",
        compiler, canonical_root);
    return n > 0 && n < (int)sizeof(flags) &&
           dp_mk_write(root, "build/hotswap/fast/flags.env", flags);
}

static bool run_hotswap_artifact_cache_fixture(void)
{
    static const char root_a[] = "test-tmp/dev_hotswap_cache_a";
    static const char root_b[] = "test-tmp/dev_hotswap_cache_b";
    static const char cache_rel[] = "test-tmp/dev_hotswap_shared_cache";
    static const char compiler_rel[] = "test-tmp/dev_hotswap_fake_cc.sh";
    static const char fake_compiler[] =
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        "out= dep= source= compile=0\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -o) out=$2; shift 2 ;;\n"
        "    -MF) dep=$2; shift 2 ;;\n"
        "    -c) compile=1; shift ;;\n"
        "    *.c) source=$1; shift ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "[ -n \"$out\" ]\n"
        "if [ \"$compile\" -eq 1 ]; then\n"
        "  printf 'fixture-object-v1\\n' >\"$out\"\n"
        "  if [ \"$source\" = app/services/src/zcode_c23_corpus_service.c ]; then\n"
        "    printf '%s: %s\\n' \"$out\" \"$source\" >\"$dep\"\n"
        "  elif [ \"$source\" = app/services/src/zcode_c23_economics_service.c ]; then\n"
        "    printf '%s: %s app/services/src/zcode_c23_economics_internal.h\\n' \"$out\" \"$source\" >\"$dep\"\n"
        "  else\n"
        "    printf '%s: app/controllers/src/status_native_helpers.c app/controllers/src/status_native_handlers.c\\n' \"$out\" >\"$dep\"\n"
        "  fi\n"
        "else\n"
        "  printf 'fixture-module-v1\\n' >\"$out\"\n"
        "fi\n";
    bool ok = false;
    const char *stage = "setup";
    char why[256] = {0};
    char cwd[PATH_MAX], cache[PATH_MAX], compiler[PATH_MAX];
    char saved_cache[PATH_MAX] = {0};
    char saved_process[32] = {0};
    char saved_force_copy[32] = {0};
    const char *prior_cache = getenv("ZCL_DEV_ARTIFACT_CACHE");
    const char *prior_process = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    const char *prior_force_copy =
        getenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    bool had_cache = prior_cache && prior_cache[0];
    bool had_process = prior_process && prior_process[0];
    bool had_force_copy = prior_force_copy && prior_force_copy[0];
    if (had_cache)
        (void)snprintf(saved_cache, sizeof(saved_cache), "%s", prior_cache);
    if (had_process)
        (void)snprintf(saved_process, sizeof(saved_process), "%s",
                       prior_process);
    if (had_force_copy)
        (void)snprintf(saved_force_copy, sizeof(saved_force_copy), "%s",
                       prior_force_copy);
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(cache, sizeof(cache), "%s/%s", cwd, cache_rel) >=
            (int)sizeof(cache) ||
        snprintf(compiler, sizeof(compiler), "%s/%s", cwd, compiler_rel) >=
            (int)sizeof(compiler))
        goto out;
    test_rm_rf_recursive(root_a);
    test_rm_rf_recursive(root_b);
    test_rm_rf_recursive(cache_rel);
    (void)unlink(compiler_rel);
    if (!dp_mk_write(".", compiler_rel, fake_compiler) ||
        chmod(compiler_rel, 0700) != 0 ||
        !dp_hotswap_cache_fixture_init(root_a, compiler) ||
        !dp_hotswap_cache_fixture_init(root_b, compiler) ||
        setenv("ZCL_DEV_ARTIFACT_CACHE", cache, 1) != 0 ||
        setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0 ||
        setenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", "1", 1) != 0)
        goto out;

    struct zcl_devloop_hotswap_build_receipt first = {0}, built = {0};
    struct zcl_devloop_hotswap_build_receipt hit = {0}, edited = {0};
    struct zcl_devloop_hotswap_build_receipt reverted = {0}, cross = {0};
    struct zcl_devloop_hotswap_build_receipt service_first = {0};
    struct zcl_devloop_hotswap_build_receipt service_built = {0};
    struct zcl_devloop_hotswap_build_receipt batch_first = {0};
    struct zcl_devloop_hotswap_build_receipt batch_built = {0};
    struct zcl_devloop_hotswap_build_receipt batch_edited = {0};
    struct zcl_devloop_hotswap_build_receipt batch_cross_first = {0};
    struct zcl_devloop_hotswap_build_receipt batch_cross = {0};
    struct zcl_devloop_process_result process = {0};
    const char *owner = "app/controllers/src/status_native_handlers.c";

    stage = "dependency-baseline";
    if (zcl_devloop_hotswap_build(root_a, owner, &first, &process,
                                  why, sizeof(why)) ||
        strcmp(why,
               "dependency baseline initialized; save once more to activate") != 0 ||
        first.compiler_processes != 1 || first.linker_processes != 0)
        goto out;
    stage = "cross-device-publish";
    if (!zcl_devloop_hotswap_build(root_a, owner, &built, &process,
                                   why, sizeof(why)) ||
        built.artifact_cache_hit || built.compiler_processes != 1 ||
        built.linker_processes != 1 || strlen(built.artifact_cache_key) != 64 ||
        strlen(built.candidate_object_sha256) != 64)
        goto out;
    stage = "cross-device-inode-proof";
    char cache_artifact[PATH_MAX];
    struct stat cache_st = {0}, published_st = {0};
    int cache_n = snprintf(cache_artifact, sizeof(cache_artifact),
                           "%s/hotswap-v1/%s.so", cache,
                           built.artifact_cache_key);
    int cache_stat_rc = cache_n < (int)sizeof(cache_artifact)
        ? stat(cache_artifact, &cache_st) : -1;
    int published_stat_rc = stat(built.artifact_path, &published_st);
    if (cache_n >= (int)sizeof(cache_artifact) || cache_stat_rc != 0 ||
        published_stat_rc != 0 ||
        (cache_st.st_dev == published_st.st_dev &&
         cache_st.st_ino == published_st.st_ino)) {
        fprintf(stderr,
                "cross-device proof cache=%s artifact=%s stat=%d/%d "
                "identity=%llu:%llu/%llu:%llu\n",
                cache_artifact, built.artifact_path, cache_stat_rc,
                published_stat_rc, (unsigned long long)cache_st.st_dev,
                (unsigned long long)cache_st.st_ino,
                (unsigned long long)published_st.st_dev,
                (unsigned long long)published_st.st_ino);
        goto out;
    }
    if (unsetenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY") != 0)
        goto out;
    stage = "same-worktree-cache-hit";
    if (!zcl_devloop_hotswap_build(root_a, owner, &hit, &process,
                                   why, sizeof(why)) ||
        !hit.artifact_cache_hit || hit.compiler_processes != 0 ||
        hit.linker_processes != 0 ||
        strcmp(hit.artifact_cache_key, built.artifact_cache_key) != 0 ||
        strcmp(hit.artifact_sha256, built.artifact_sha256) != 0 ||
        strcmp(hit.candidate_object_sha256,
               built.candidate_object_sha256) != 0)
        goto out;

    if (!dp_mk_write(root_a,
                     "app/controllers/src/status_native_handlers.c",
                     "int zcl_hotswap_fixture_owner(void) { return 9; }\n") ||
        !zcl_devloop_hotswap_build(root_a, owner, &edited, &process,
                                   why, sizeof(why)) ||
        edited.artifact_cache_hit || edited.compiler_processes != 1 ||
        edited.linker_processes != 1 ||
        strcmp(edited.artifact_cache_key, built.artifact_cache_key) == 0)
        goto out;
    stage = "exact-revert";
    if (!dp_mk_write(root_a,
                     "app/controllers/src/status_native_handlers.c",
                     "int zcl_hotswap_fixture_owner(void) { return 1; }\n") ||
        !zcl_devloop_hotswap_build(root_a, owner, &reverted, &process,
                                   why, sizeof(why)) ||
        !reverted.artifact_cache_hit || reverted.compiler_processes != 0 ||
        reverted.linker_processes != 0 ||
        strcmp(reverted.artifact_cache_key, built.artifact_cache_key) != 0)
        goto out;

    /* The second checkout must learn its depfile once, then reuse the exact
     * artifact produced in the first checkout without a compiler or linker. */
    if (zcl_devloop_hotswap_build(root_b, owner, &first, &process,
                                  why, sizeof(why)) ||
        !zcl_devloop_hotswap_build(root_b, owner, &cross, &process,
                                   why, sizeof(why)) ||
        !cross.artifact_cache_hit || cross.compiler_processes != 0 ||
        cross.linker_processes != 0 ||
        strcmp(cross.artifact_cache_key, built.artifact_cache_key) != 0 ||
        strcmp(cross.artifact_sha256, built.artifact_sha256) != 0 ||
        strcmp(cross.candidate_object_sha256,
               built.candidate_object_sha256) != 0)
        goto out;

    /* A pure service island compiles its owner directly; it has no command
     * unity-member list.  Requiring one here made every service save reject
     * before starting the compiler. */
    const char *service =
        "app/services/src/zcode_c23_corpus_service.c";
    stage = "service-island";
    if (zcl_devloop_hotswap_build(root_a, service, &service_first, &process,
                                  why, sizeof(why)) ||
        strcmp(why,
               "dependency baseline initialized; save once more to activate") != 0 ||
        service_first.compiler_processes != 1 ||
        service_first.linker_processes != 0 ||
        !zcl_devloop_hotswap_build(root_a, service, &service_built, &process,
                                   why, sizeof(why)) ||
        service_built.compiler_processes != 1 ||
        service_built.linker_processes != 1 ||
        strcmp(service_built.source_tu, service) != 0)
        goto out;

    /* A source + private-header epoch maps back to one owner, compiles that
     * exact dependency closure once, and yields one candidate artifact. */
    const char *economics_source =
        "app/services/src/zcode_c23_economics_service.c";
    const char *economics_header =
        "app/services/src/zcode_c23_economics_internal.h";
    stage = "multi-file-island";
    if (zcl_devloop_hotswap_build(root_a, economics_header, &batch_first,
                                  &process, why, sizeof(why)) ||
        batch_first.compiler_processes != 1 ||
        !zcl_devloop_hotswap_build(root_a, economics_header, &batch_built,
                                   &process, why, sizeof(why)) ||
        batch_built.compiler_processes != 1 ||
        batch_built.linker_processes != 1 ||
        strcmp(batch_built.source_tu, economics_source) != 0 ||
        !dp_mk_write(root_a, economics_source,
                     "#include \"zcode_c23_economics_internal.h\"\n"
                     "int zcl_hotswap_fixture_economics(void) { return 5; }\n") ||
        !dp_mk_write(root_a, economics_header,
                     "#define ZCL_ECONOMICS_FIXTURE 5\n") ||
        !zcl_devloop_hotswap_build(root_a, economics_header, &batch_edited,
                                   &process, why, sizeof(why)) ||
        batch_edited.compiler_processes != 1 ||
        batch_edited.linker_processes != 1 ||
        strcmp(batch_edited.artifact_cache_key,
               batch_built.artifact_cache_key) == 0)
        goto out;
    if (zcl_devloop_hotswap_build(root_b, economics_header,
                                  &batch_cross_first, &process, why,
                                  sizeof(why)) ||
        !zcl_devloop_hotswap_build(root_b, economics_header, &batch_cross,
                                   &process, why, sizeof(why)) ||
        !batch_cross.artifact_cache_hit ||
        batch_cross.compiler_processes != 0 ||
        batch_cross.linker_processes != 0 ||
        strcmp(batch_cross.artifact_cache_key,
               batch_built.artifact_cache_key) != 0 ||
        strcmp(batch_cross.artifact_sha256,
               batch_built.artifact_sha256) != 0)
        goto out;
    ok = true;

out:
    if (!ok)
        fprintf(stderr, "hotswap cache fixture failed at %s: %s\n", stage,
                why[0] ? why : "no build reason");
    if (had_cache)
        (void)setenv("ZCL_DEV_ARTIFACT_CACHE", saved_cache, 1);
    else
        (void)unsetenv("ZCL_DEV_ARTIFACT_CACHE");
    if (had_process)
        (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", saved_process, 1);
    else
        (void)unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    if (had_force_copy)
        (void)setenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", saved_force_copy, 1);
    else
        (void)unsetenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    test_rm_rf_recursive(root_a);
    test_rm_rf_recursive(root_b);
    test_rm_rf_recursive(cache_rel);
    (void)unlink(compiler_rel);
    return ok;
}

static int test_hotswap_artifact_cache(void)
{
    int failures = 0;
    TEST("dev platform: resident artifacts are exact-input cached across edits and worktrees") {
        ASSERT(run_hotswap_artifact_cache_fixture());
        PASS();
    } _test_next:;
    return failures;
}

static bool run_resident_restart_fixture(void)
{
    static const char root[] = "test-tmp/dev_resident_restart";
    static const char cache_rel[] = "test-tmp/dev_restart_shared_cache";
    static const char compiler_rel[] = "test-tmp/dev_restart_fake_cc.sh";
    static const char fake_compiler[] =
        "#!/usr/bin/env bash\n"
        "set -eu\n"
        "out= dep= compile=0 rsp= source= base= allow=0 overlay_first=0 identity=0\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    -o) out=$2; shift 2 ;;\n"
        "    -MF) dep=$2; shift 2 ;;\n"
        "    -c) compile=1; shift ;;\n"
        "    @*) rsp=${1#@}; overlay_first=1; shift ;;\n"
        "    *restart-base.o) [ \"$overlay_first\" -eq 1 ]; base=$1; shift ;;\n"
        "    -Wl,--allow-multiple-definition) allow=1; shift ;;\n"
        "    -DZCL_BUILD_SOURCE_ID=*) identity=$((identity+1)); shift ;;\n"
        "    -DZCL_BUILD_SOURCE_MUTATION=*) identity=$((identity+1)); shift ;;\n"
        "    -DZCL_BUILD_SOURCE_CAS_SHA3=*) identity=$((identity+1)); shift ;;\n"
        "    *.c) source=$1; shift ;;\n"
        "    *) shift ;;\n"
        "  esac\n"
        "done\n"
        "[ -n \"$out\" ]\n"
        "if [ \"$compile\" -eq 1 ]; then\n"
        "  [ -n \"$source\" ]\n"
        "  case \"$source\" in lib/util/src/clientversion.c) [ \"$identity\" -eq 3 ];; esac\n"
        "  cp \"$source\" \"$out\"\n"
        "  printf '%s: tools/dev/restart_fixture.c\\n' \"$out\" >\"$dep\"\n"
        "else\n"
        "  [ -n \"$rsp\" ]\n"
        "  [ -n \"$base\" ]\n"
        "  [ \"$allow\" -eq 1 ]\n"
        "  if grep -q 'restart-test-objects' \"$rsp\"; then\n"
        "    case \"$base\" in *test-obj/fixture/restart-base.o) :;; *) exit 9;; esac\n"
        "    grep -q 'build/dev-loop/restart-test-objects/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    grep -q 'build/dev-loop/restart-test-objects/lib/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/test-obj/fixture/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    ! grep -q 'build/test-obj/fixture/lib/util/src/clientversion.o' \"$rsp\"\n"
        "    printf '#!/usr/bin/env bash\\nset -eu\\ngroups= cache=0 snapshot=0 changed=\\nfor arg in \"$@\"; do case \"$arg\" in --exact=*) groups=${arg#--exact=};; --cache) cache=1;; --cache-snapshot) snapshot=1;; --changed-source=*) changed=${arg#--changed-source=};; esac; done\\n[ -n \"$groups\" ]\\n[ \"$cache\" -eq 1 ]\\n[ \"$snapshot\" -eq 1 ]\\n[ \"$changed\" = tools/dev/restart_fixture.c ]\\ncount=1\\nrest=$groups\\nwhile [ \"${rest#*,}\" != \"$rest\" ]; do count=$((count+1)); rest=${rest#*,}; done\\nran=$((count-1))\\nfailed=$ZCL_DEVLOOP_TEST_FAIL_GROUPS\\nprintf \"SUITE VERDICT mode=cached groups_total=921 groups_ran=%%s groups_cached=1 groups_gated=0 groups_failed=%%s self_skips=0\\\\n\" \"$ran\" \"$failed\"\\n[ \"$failed\" -eq 0 ]\\n' >\"$out\"\n"
        "  else\n"
        "    case \"$base\" in *dev-obj/fixture/restart-base.o) :;; *) exit 9;; esac\n"
        "    grep -q 'build/dev-loop/restart-objects/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    grep -q 'build/dev-loop/restart-objects/lib/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/lib/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/lib/base/src/other.o' \"$rsp\"\n"
        "    printf '#!/usr/bin/env bash\\nexit 0\\n' >\"$out\"\n"
        "  fi\n"
        "  chmod 0700 \"$out\"\n"
        "fi\n";
    bool ok = false;
    char cwd[PATH_MAX], cache[PATH_MAX], compiler[PATH_MAX], plan[PATH_MAX * 4];
    char saved_cache[PATH_MAX] = {0};
    char saved_process[32] = {0};
    char saved_force_copy[32] = {0};
    const char *prior_cache = getenv("ZCL_DEV_ARTIFACT_CACHE");
    const char *prior_process = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    const char *prior_force_copy =
        getenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    bool had_cache = prior_cache && prior_cache[0];
    bool had_process = prior_process && prior_process[0];
    bool had_force_copy = prior_force_copy && prior_force_copy[0];
    if (had_cache)
        (void)snprintf(saved_cache, sizeof(saved_cache), "%s", prior_cache);
    if (had_process)
        (void)snprintf(saved_process, sizeof(saved_process), "%s",
                       prior_process);
    if (had_force_copy)
        (void)snprintf(saved_force_copy, sizeof(saved_force_copy), "%s",
                       prior_force_copy);
    test_rm_rf_recursive(root);
    test_rm_rf_recursive(cache_rel);
    (void)unlink(compiler_rel);
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(cache, sizeof(cache), "%s/%s", cwd, cache_rel) >=
            (int)sizeof(cache) ||
        snprintf(compiler, sizeof(compiler), "%s/%s", cwd, compiler_rel) >=
            (int)sizeof(compiler) ||
        !dp_mk_write(".", compiler_rel, fake_compiler) ||
        chmod(compiler_rel, 0700) != 0 ||
        !dp_mk_write(root, "Makefile", "# fixture\n") ||
        !dp_mk_write(root, "tools/dev/restart_fixture.c",
                     "int restart_fixture(void) { return 7; }\n") ||
        !dp_mk_write(root, "tools/dev/restart_second.c",
                     "int restart_second(void) { return 8; }\n") ||
        !dp_mk_write(root, "lib/test/src/restart_test_only.c",
                     "int restart_test_only(void) { return 9; }\n") ||
        !dp_mk_write(root, "tools/command/native_code_command.c",
                     "int native_code_fixture(void) { return 23; }\n") ||
        !dp_mk_write(root, "lib/util/src/clientversion.c",
                     "const char *resident_identity_fixture(void) { return \"identity\"; }\n") ||
        !dp_mk_write(root,
                     "build/dev-obj/fixture/tools/dev/restart_fixture.o",
                     "old-object\n") ||
        !dp_mk_write(root,
                     "build/dev-obj/fixture/tools/dev/restart_second.o",
                     "old-second-object\n") ||
        !dp_mk_write(root,
                     "build/dev-obj/fixture/tools/command/native_code_command.o",
                     "old-code-object\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/lib/base/src/other.o",
                     "other-object\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/lib/util/src/clientversion.o",
                     "stale-dev-identity\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/link-inputs.rsp",
                     "build/dev-obj/fixture/tools/dev/restart_fixture.o build/dev-obj/fixture/tools/dev/restart_second.o build/dev-obj/fixture/tools/command/native_code_command.o build/dev-obj/fixture/lib/util/src/clientversion.o build/dev-obj/fixture/lib/base/src/other.o\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/restart-base.o",
                     "frozen-dev-base\n") ||
        !dp_mk_write(root,
                     "build/test-obj/fixture/tools/dev/restart_fixture.o",
                     "old-test-object\n") ||
        !dp_mk_write(root,
                     "build/test-obj/fixture/tools/command/native_code_command.o",
                     "old-test-code-object\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/lib/base/src/other.o",
                     "other-test-object\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/lib/util/src/clientversion.o",
                     "stale-test-identity\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/link-inputs.rsp",
                     "build/test-obj/fixture/tools/dev/restart_fixture.o build/test-obj/fixture/tools/command/native_code_command.o build/test-obj/fixture/lib/util/src/clientversion.o build/test-obj/fixture/lib/base/src/other.o\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/restart-base.o",
                     "frozen-test-base\n") ||
        setenv("ZCL_DEV_ARTIFACT_CACHE", cache, 1) != 0)
        goto out;
    int n = snprintf(
        plan, sizeof(plan),
        "CC=%s\n"
        "COMPILER_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "BASE_GENERATION=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n"
        "DEV_CFLAGS=-DZCL_DEV_BUILD\n"
        "DEV_LDFLAGS=-pthread\n"
        "DEV_LIBS=-lm\n"
        "DEV_OBJ_DIR=build/dev-obj/fixture\n"
        "DEV_LINK_RSP=build/dev-obj/fixture/link-inputs.rsp\n"
        "DEV_BASE_RELOC=build/dev-obj/fixture/restart-base.o\n"
        "TEST_CFLAGS=-DZCL_TESTING\n"
        "TEST_LDFLAGS=-pthread\n"
        "TEST_LIBS=-lm\n"
        "TEST_OBJ_DIR=build/test-obj/fixture\n"
        "TEST_LINK_RSP=build/test-obj/fixture/link-inputs.rsp\n"
        "TEST_BASE_RELOC=build/test-obj/fixture/restart-base.o\n",
        compiler);
    if (n <= 0 || n >= (int)sizeof(plan) ||
        !dp_mk_write(root, "build/dev-loop/restart.env", plan) ||
        setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0 ||
        setenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", "1", 1) != 0 ||
        setenv("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "0", 1) != 0)
        goto out;

    const char *changed[] = { "tools/dev/restart_fixture.c" };
    struct zcl_devloop_restart_build_receipt receipt = {0};
    struct zcl_devloop_process_result process = {0};
    char why[256] = {0};
    if (!zcl_devloop_restart_build(root, changed, 1, &receipt, &process,
                                   why, sizeof(why)) ||
        !receipt.candidate_probe_passed || receipt.changed_sources != 1 ||
        receipt.artifact_cache_hit || receipt.compiler_processes != 2 ||
        receipt.linker_processes != 1 ||
        receipt.complete_graph_linker_processes != 0 ||
        receipt.probe_processes != 1 || receipt.source_guard_captures != 2 ||
        receipt.compile_startup_us <= 0 || receipt.compile_body_us <= 0 ||
        receipt.link_startup_us <= 0 || receipt.link_body_us <= 0 ||
        receipt.probe_startup_us <= 0 || receipt.probe_body_us <= 0 ||
        strcmp(receipt.probe, "discover.help") != 0 ||
        !receipt.source_identity_overlay ||
        strlen(receipt.source_cas_sha3) != 64 ||
        strlen(receipt.artifact_sha256) != 64 ||
        strlen(receipt.artifact_cache_key) != 64)
        goto out;
    char cache_artifact[PATH_MAX];
    struct stat cache_st = {0}, published_st = {0};
    int cache_n = snprintf(cache_artifact, sizeof(cache_artifact),
                           "%s/restart-v1/%s.bin", cache,
                           receipt.artifact_cache_key);
    if (cache_n <= 0 || cache_n >= (int)sizeof(cache_artifact) ||
        stat(cache_artifact, &cache_st) != 0 ||
        stat(receipt.artifact_path, &published_st) != 0 ||
        (cache_st.st_dev == published_st.st_dev &&
         cache_st.st_ino == published_st.st_ino))
        goto out;

    /* A test edit following a resident service publication carries both TUs
     * into the proof epoch. The runtime candidate compiles and links only the
     * service TU; the exact test candidate later compiles and links both with
     * TEST_CFLAGS, including APIs that exist only under ZCL_TESTING. */
    const char *runtime_and_test_changed[] = {
        "tools/dev/restart_fixture.c",
        "lib/test/src/restart_test_only.c",
    };
    memset(&receipt, 0, sizeof(receipt));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_build(root, runtime_and_test_changed, 2,
                                   &receipt, &process, why, sizeof(why)) ||
        !receipt.candidate_probe_passed || receipt.changed_sources != 2 ||
        receipt.compiler_processes != 2 || !receipt.artifact_cache_hit ||
        receipt.linker_processes != 0 || receipt.probe_processes != 1)
        goto out;
    if (unsetenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY") != 0)
        goto out;
    char first_build_key[65], first_build_hash[65];
    (void)snprintf(first_build_key, sizeof(first_build_key), "%s",
                   receipt.artifact_cache_key);
    (void)snprintf(first_build_hash, sizeof(first_build_hash), "%s",
                   receipt.artifact_sha256);

    struct zcl_devloop_plan proof_plan = {0};
    if (!zcl_devloop_plan_files(changed, 1, &proof_plan))
        goto out;
    for (size_t d = 0; d < ZCL_DEVLOOP_DIM__COUNT; d++)
        proof_plan.dims[d].status = ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    struct zcl_devloop_restart_proof_receipt proof = {0};
    if (!zcl_devloop_restart_prove(root, changed, 1, &proof_plan, &proof,
                                   &process, why, sizeof(why)) ||
        !proof.proof_complete || !proof.immediate_proof_complete ||
        proof.integration_proof_deferred || proof.deferred_group_count != 0 ||
        proof.group_count != 18 ||
        proof.groups_ran != 17 || proof.groups_cached != 1 ||
        proof.self_skips != 0 ||
        !strstr(proof.groups, "test_dev_platform") ||
        !strstr(proof.groups, "test_make_lint_gates_heavy_02") ||
        proof.artifact_cache_hit || proof.compiler_processes != 2 ||
        proof.linker_processes != 1 ||
        proof.complete_graph_linker_processes != 0 ||
        proof.test_processes != 2 || proof.source_guard_captures != 2 ||
        strcmp(proof.priority_group, "test_make_lint_gates") != 0 ||
        strcmp(proof.priority_reason, "direct_owner_invariant") != 0 ||
        proof.priority_test_us <= 0 ||
        proof.selection_us <= 0 ||
        proof.compile_startup_us <= 0 || proof.compile_body_us <= 0 ||
        proof.link_startup_us <= 0 || proof.link_body_us <= 0 ||
        proof.test_startup_us <= 0 || proof.test_body_us <= 0 ||
        strlen(proof.artifact_sha256) != 64 ||
        strlen(proof.artifact_cache_key) != 64 ||
        !proof.source_identity_overlay ||
        strlen(proof.source_cas_sha3) != 64 ||
        strlen(proof.groups_sha256) != 64)
        goto out;

    /* Born red: a real exact-group failure must not be collapsed into the
     * runner-accounting fallback. The next action needs the failing count. */
    if (setenv("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "2", 1) != 0)
        goto out;
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (zcl_devloop_restart_prove(root, changed, 1, &proof_plan, &proof,
                                  &process, why, sizeof(why)) ||
        strcmp(why, "failure-first direct owner invariant failed") != 0 ||
        proof.groups_failed != 2 ||
        proof.immediate_proof_complete || proof.proof_complete)
        goto out;
    if (setenv("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "0", 1) != 0)
        goto out;

    /* The next edit for the same task executes the remembered RED before
     * default/catalog order. Passing it clears the warm scheduling hint; it
     * never substitutes for the complete affected batch that follows. */
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_prove(root, changed, 1, &proof_plan, &proof,
                                   &process, why, sizeof(why)) ||
        !proof.proof_complete || proof.test_processes != 2 ||
        strcmp(proof.priority_group, "test_make_lint_gates") != 0 ||
        strcmp(proof.priority_reason, "previous_failure") != 0)
        goto out;

    /* Born-red P0 regression: a tooling edit whose mapped closure includes
     * code_capsule must carry the epoch-generated clientversion overlay all
     * the way through a complete resident proof. The second source keeps the
     * fixture runner's fixed bounded changed-source probe deterministic. */
    const char *code_changed[] = {
        "tools/command/native_code_command.c",
        "tools/dev/restart_fixture.c",
    };
    struct zcl_devloop_plan code_plan = {0};
    if (!zcl_devloop_plan_files(code_changed, 2, &code_plan))
        goto out;
    for (size_t d = 0; d < ZCL_DEVLOOP_DIM__COUNT; d++)
        code_plan.dims[d].status = ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_prove(root, code_changed, 2, &code_plan, &proof,
                                   &process, why, sizeof(why)) ||
        !proof.proof_complete || !proof.immediate_proof_complete ||
        proof.integration_proof_deferred ||
        !strstr(proof.groups, "test_code_capsule") ||
        !proof.source_identity_overlay ||
        strlen(proof.source_cas_sha3) != 64 ||
        proof.compiler_processes != 3 || proof.linker_processes != 1 ||
        proof.test_processes != 2)
        goto out;

    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_prove_immediate(
            root, changed, 1, &proof_plan, &proof, &process,
            why, sizeof(why)) ||
        proof.proof_complete || !proof.immediate_proof_complete ||
        !proof.integration_proof_deferred || proof.group_count != 5 ||
        proof.deferred_group_count != 13 ||
        proof.groups_ran != 4 || proof.groups_cached != 1 ||
        proof.self_skips != 0 ||
        !proof.artifact_cache_hit || proof.compiler_processes != 2 ||
        proof.linker_processes != 0 ||
        strstr(proof.groups, "test_make_lint_gates") ||
        !strstr(proof.deferred_groups,
                "test_make_lint_gates_heavy_02") ||
        strlen(proof.deferred_groups_sha256) != 64)
        goto out;

    /* Exact, edit, and revert cycles compile the source for diagnostic
     * freshness, but only new complete-graph link inputs may invoke a linker. */
    memset(&receipt, 0, sizeof(receipt));
    if (!zcl_devloop_restart_build(root, changed, 1, &receipt, &process,
                                   why, sizeof(why)) ||
        !receipt.artifact_cache_hit || receipt.compiler_processes != 2 ||
        receipt.linker_processes != 0 ||
        strcmp(receipt.artifact_cache_key, first_build_key) != 0 ||
        strcmp(receipt.artifact_sha256, first_build_hash) != 0)
        goto out;
    if (!dp_mk_write(root, "tools/dev/restart_fixture.c",
                     "int restart_fixture(void) { return 9; }\n"))
        goto out;
    memset(&receipt, 0, sizeof(receipt));
    if (!zcl_devloop_restart_build(root, changed, 1, &receipt, &process,
                                   why, sizeof(why)) ||
        receipt.artifact_cache_hit || receipt.compiler_processes != 2 ||
        receipt.linker_processes != 1 ||
        receipt.complete_graph_linker_processes != 0 ||
        strcmp(receipt.artifact_cache_key, first_build_key) == 0)
        goto out;
    if (!dp_mk_write(root, "tools/dev/restart_fixture.c",
                     "int restart_fixture(void) { return 7; }\n"))
        goto out;
    memset(&receipt, 0, sizeof(receipt));
    if (!zcl_devloop_restart_build(root, changed, 1, &receipt, &process,
                                   why, sizeof(why)) ||
        !receipt.artifact_cache_hit || receipt.compiler_processes != 2 ||
        receipt.linker_processes != 0 ||
        strcmp(receipt.artifact_cache_key, first_build_key) != 0 ||
        strcmp(receipt.artifact_sha256, first_build_hash) != 0)
        goto out;

    struct zcl_devloop_plan overwide = proof_plan;
    (void)snprintf(overwide.closure_groups[0],
                   sizeof(overwide.closure_groups[0]), "%s", "wallet");
    (void)snprintf(overwide.closure_groups[1],
                   sizeof(overwide.closure_groups[1]), "%s", "net");
    overwide.closure_groups_len = 2;
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_prove_immediate(
            root, changed, 1, &overwide, &proof, &process,
            why, sizeof(why)) ||
        !proof.immediate_proof_complete || proof.proof_complete ||
        !proof.integration_proof_deferred || !proof.bounded_proof_deferred ||
        proof.group_count == 0 || proof.group_count > 32 ||
        proof.deferred_group_count == 0 ||
        !strstr(proof.groups, "test_dev_platform") ||
        strstr(proof.groups, "test_wallet") || strstr(proof.groups, "test_net") ||
        !strstr(proof.deferred_groups, "test_wallet") ||
        !strstr(proof.deferred_groups, "test_net") ||
        proof.compiler_processes != 2 || proof.linker_processes != 0 ||
        proof.test_processes != 1)
        goto out;

    struct zcl_devloop_plan substituted = proof_plan;
    (void)snprintf(substituted.path_groups[0],
                   sizeof(substituted.path_groups[0]), "%s", "json");
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (zcl_devloop_restart_prove(root, changed, 1, &substituted, &proof,
                                  &process, why, sizeof(why)) ||
        strcmp(why,
               "affected proof plan does not match the changed source set") != 0 ||
        proof.compiler_processes != 0 || proof.linker_processes != 0 ||
        proof.test_processes != 0)
        goto out;

    /* A later edit links both its new overlay and the prior source's still
     * exact overlay. The fake linker always requires the first overlay, so
     * this second call fails if the resident forgets earlier direct edits. */
    const char *second[] = { "tools/dev/restart_second.c" };
    memset(&receipt, 0, sizeof(receipt));
    if (!zcl_devloop_restart_build(root, second, 1, &receipt, &process,
                                   why, sizeof(why)) ||
        !receipt.candidate_probe_passed || receipt.compiler_processes != 2 ||
        receipt.linker_processes != 1 ||
        receipt.complete_graph_linker_processes != 0 ||
        receipt.probe_processes != 1)
        goto out;

    if (!dp_mk_write(root, "tools/dev/restart_second.c",
                     "const char *restart_second(void) { return \".init_array\"; }\n"))
        goto out;
    memset(&receipt, 0, sizeof(receipt));
    if (zcl_devloop_restart_build(root, second, 1, &receipt, &process,
                                  why, sizeof(why)) ||
        strcmp(why,
               "overlay link input is missing, unreadable, or owns process initialization") != 0 ||
        receipt.compiler_processes != 2 || receipt.linker_processes != 0 ||
        receipt.complete_graph_linker_processes != 0 ||
        receipt.probe_processes != 0)
        goto out;

    const char *forbidden[] = { "core/consensus/src/restart_fixture.c" };
    memset(&receipt, 0, sizeof(receipt));
    if (zcl_devloop_restart_build(root, forbidden, 1, &receipt, &process,
                                  why, sizeof(why)) ||
        strcmp(why, "consensus-risk input is excluded from fast restart") != 0 ||
        receipt.compiler_processes != 0 || receipt.linker_processes != 0 ||
        receipt.probe_processes != 0)
        goto out;
    ok = true;

out:
    (void)unsetenv("ZCL_DEVLOOP_TEST_FAIL_GROUPS");
    if (had_cache)
        (void)setenv("ZCL_DEV_ARTIFACT_CACHE", saved_cache, 1);
    else
        (void)unsetenv("ZCL_DEV_ARTIFACT_CACHE");
    if (had_process)
        (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", saved_process, 1);
    else
        (void)unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    if (had_force_copy)
        (void)setenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", saved_force_copy, 1);
    else
        (void)unsetenv("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
    test_rm_rf_recursive(root);
    test_rm_rf_recursive(cache_rel);
    (void)unlink(compiler_rel);
    return ok;
}

static int test_resident_restart_builder(void)
{
    int failures = 0;
    TEST("dev platform: resident restart builds and probes an isolated candidate without Make") {
        ASSERT(run_resident_restart_fixture());
        PASS();
    } _test_next:;
    return failures;
}

static int test_resident_process_cancellation(void)
{
    int failures = 0;
    TEST("dev platform: resident cancellation promptly stops an active child group") {
        const char *saved = getenv("ZCL_DEVLOOP_TEST_PROCESS");
        char *saved_copy = saved ? strdup(saved) : NULL;
        ASSERT(!saved || saved_copy);
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);

        const char *argv[] = { "sleep", "30", NULL };
        struct zcl_devloop_process_result result = {0};
        zcl_devloop_process_cancel_request();
        int64_t started = platform_time_monotonic_us();
        ASSERT(zcl_devloop_process_run(".", argv, 60000, &result));
        int64_t elapsed_us = platform_time_monotonic_us() - started;
        ASSERT(result.cancelled);
        ASSERT(!result.timed_out);
        ASSERT(result.term_signal == SIGTERM);
        ASSERT(elapsed_us >= 0 && elapsed_us < INT64_C(1000000));
        zcl_devloop_process_cancel_clear();

        if (saved_copy) {
            ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", saved_copy, 1) == 0);
            free(saved_copy);
        } else {
            ASSERT(unsetenv("ZCL_DEVLOOP_TEST_PROCESS") == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

struct process_poll_fixture {
    unsigned calls;
    unsigned cancel_after;
    const char *ready_path;
};

static bool cancel_after_poll(void *opaque)
{
    struct process_poll_fixture *fixture = opaque;
    fixture->calls++;
    /* A poll count is not process readiness: under full-suite load the parent
     * can poll repeatedly before the nested shell has executed its first
     * instruction. When a readiness marker is supplied, cancellation begins
     * only after the child has explicitly published it. */
    if (fixture->ready_path && access(fixture->ready_path, F_OK) != 0)
        return false;
    return fixture->calls >= fixture->cancel_after;
}

static int test_resident_process_supersession(void)
{
    int failures = 0;
    TEST("dev platform: resident process polling cancels superseded work") {
        const char *saved = getenv("ZCL_DEVLOOP_TEST_PROCESS");
        char *saved_copy = saved ? strdup(saved) : NULL;
        ASSERT(!saved || saved_copy);
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);

        struct process_poll_fixture fixture = { .cancel_after = 2 };
        zcl_devloop_process_cancel_poll_set(cancel_after_poll, &fixture);
        const char *argv[] = { "sleep", "30", NULL };
        struct zcl_devloop_process_result result = {0};
        ASSERT(zcl_devloop_process_run(".", argv, 60000, &result));
        zcl_devloop_process_cancel_poll_clear();
        /* Clear shared cancellation before assertions can leave this test. */
        zcl_devloop_process_cancel_clear();
        ASSERT(fixture.calls >= 2);
        ASSERT(result.cancelled);
        ASSERT(!result.timed_out);
        ASSERT(result.elapsed_ms < 1000);

        char pid_path[PATH_MAX], pid_tmp_path[PATH_MAX];
        char script[PATH_MAX * 3 + 160];
        ASSERT(snprintf(pid_path, sizeof(pid_path),
                        "test-tmp/devloop_nested_%ld.pid", (long)getpid()) > 0);
        ASSERT(snprintf(pid_tmp_path, sizeof(pid_tmp_path), "%s.tmp",
                        pid_path) > 0);
        ASSERT(snprintf(script, sizeof(script),
                        "timeout 30 sh -c 'echo $$ > %s && mv %s %s && "
                        "sleep 30'",
                        pid_tmp_path, pid_tmp_path, pid_path) > 0);
        (void)unlink(pid_path);
        (void)unlink(pid_tmp_path);
        fixture.calls = 0;
        fixture.cancel_after = 1;
        fixture.ready_path = pid_path;
        zcl_devloop_process_cancel_poll_set(cancel_after_poll, &fixture);
        const char *nested_argv[] = { "sh", "-c", script, NULL };
        memset(&result, 0, sizeof(result));
        ASSERT(zcl_devloop_process_run(".", nested_argv, 60000, &result));
        zcl_devloop_process_cancel_poll_clear();
        /* The result carries cancellation evidence; the shared flag need not
         * remain armed while descendant/process assertions run. */
        zcl_devloop_process_cancel_clear();
        ASSERT(result.cancelled);
        FILE *pid_file = fopen(pid_path, "r");
        ASSERT(pid_file != NULL);
        long nested_pid = 0;
        ASSERT(fscanf(pid_file, "%ld", &nested_pid) == 1);
        ASSERT(fclose(pid_file) == 0);
        ASSERT(nested_pid > 1);
        bool gone = false;
        const struct timespec retry_delay = { .tv_nsec = 10000000L };
        for (int i = 0; i < 100; i++) {
            errno = 0;
            if (kill((pid_t)nested_pid, 0) != 0 && errno == ESRCH) {
                gone = true;
                break;
            }
            (void)nanosleep(&retry_delay, NULL);
        }
        ASSERT(gone);
        ASSERT(unlink(pid_path) == 0);
        if (saved_copy) {
            ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", saved_copy, 1) == 0);
            free(saved_copy);
        } else {
            ASSERT(unsetenv("ZCL_DEVLOOP_TEST_PROCESS") == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_source_cas_shadow(void)
{
    int failures = 0;
    TEST("dev platform: native source CAS is incremental and remains shadow authority") {
        static const char fixture[] = "test-tmp/dev_source_cas_shadow";
        ASSERT(system("rm -rf test-tmp/dev_source_cas_shadow") == 0);
        ASSERT(dp_mk_write(fixture, "lib/net/src/source_cas_a.c",
                           "int source_cas_a(void) { return 1; }\n"));
        ASSERT(dp_mk_write(fixture, "lib/net/include/net/source_cas_a.h",
                           "int source_cas_a(void);\n"));

        struct dev_source_record first = {0}, warm = {0}, edited = {0};
        ASSERT(zcl_dev_source_cas_capture(fixture, &first));
        ASSERT(first.cas_present);
        ASSERT(strlen(first.cas_root_sha3) == 64);
        ASSERT(strlen(first.source_id) == 64);
        ASSERT(strlen(first.mutation_id) == 64);
        ASSERT(first.cas_files_total == 2);
        ASSERT(first.cas_files_read == 2);
        ASSERT(first.cas_bytes_total == 61);
        ASSERT(first.cas_bytes_read == 61);

        ASSERT(zcl_dev_source_cas_capture(fixture, &warm));
        ASSERT(warm.cas_present);
        ASSERT(strcmp(first.cas_root_sha3, warm.cas_root_sha3) == 0);
        ASSERT(strcmp(first.source_id, warm.source_id) == 0);
        ASSERT(strcmp(first.mutation_id, warm.mutation_id) == 0);
        ASSERT(warm.cas_files_total == 2);
        ASSERT(warm.cas_files_read == 0);
        ASSERT(warm.cas_nodes_hashed == 0);
        ASSERT(warm.cas_bytes_total == 61);
        ASSERT(warm.cas_bytes_read == 0);

        ASSERT(dp_mk_write(fixture, "lib/net/src/source_cas_a.c",
                           "int source_cas_a(void) { return 2; }\n"));
        ASSERT(zcl_dev_source_cas_capture(fixture, &edited));
        ASSERT(edited.cas_present);
        ASSERT(edited.cas_files_read == 1);
        ASSERT(edited.cas_bytes_total == 61);
        ASSERT(edited.cas_bytes_read == 37);
        ASSERT(strcmp(first.cas_root_sha3, edited.cas_root_sha3) != 0);
        ASSERT(strcmp(first.source_id, edited.source_id) != 0);
        ASSERT(strcmp(first.mutation_id, edited.mutation_id) != 0);

        struct dev_source_record authoritative = {0};
        memset(authoritative.source_id, 'a', 64);
        authoritative.source_id[64] = 0;
        memset(authoritative.mutation_id, 'b', 64);
        authoritative.mutation_id[64] = 0;
        ASSERT(zcl_dev_source_cas_capture(fixture, &authoritative));
        ASSERT(strcmp(authoritative.source_id,
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
        ASSERT(strcmp(authoritative.mutation_id,
                      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0);
        ASSERT(system("rm -rf test-tmp/dev_source_cas_shadow") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_cycle_proof_reuse_contract(void)
{
    int failures = 0;
    TEST("dev platform: only a passed source-wide verify is reusable proof") {
        ASSERT(zcl_devloop_cycle_proof_complete("passed", "verify"));
        ASSERT(!zcl_devloop_cycle_proof_complete("deferred", "verify"));
        ASSERT(!zcl_devloop_cycle_proof_complete("superseded", "verify"));
        ASSERT(!zcl_devloop_cycle_proof_complete("rejected", "verify"));
        ASSERT(!zcl_devloop_cycle_proof_complete("passed",
                                                 "precommit_probe"));
        ASSERT(!zcl_devloop_cycle_proof_complete("passed",
                                                 "resident_commit"));
        ASSERT(!zcl_devloop_cycle_proof_complete(NULL, "verify"));
        ASSERT(!zcl_devloop_cycle_proof_complete("passed", NULL));
        PASS();
    } _test_next:;
    return failures;
}

static int test_progressive_event_vocabulary(void)
{
    int failures = 0;
    TEST("dev platform: progressive events have one stable scheduling vocabulary") {
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "edit_seen", "legacy"), "EDIT_SEEN") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "impact_ready", "legacy"), "IMPACT_READY") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "reflex_ready", "candidate_probe"),
                      "COMPILE_GREEN") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "rejected", "compile_link_probe"),
                      "COMPILE_RED") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "story_green", "vault_intent_story"),
                      "STORY_GREEN") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "story_red", "vault_intent_story"),
                      "STORY_RED") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "feedback_ready", "immediate_affected_proofs"),
                      "FOCUSED_GREEN") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "rejected", "affected_proofs"),
                      "FOCUSED_RED") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "proof_pending", "integration"),
                      "PROOF_PENDING") == 0);
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "superseded", "source_epoch_cas"),
                      "SUPERSEDED") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_reflex_policy_boundary(void)
{
    int failures = 0;
    TEST("dev platform: reflex policy projects feedback and seals proof inputs") {
        const struct dev_reflex_policy_service_v1 *policy =
            dev_reflex_policy_service_builtin();
        ASSERT(policy != NULL);
        ASSERT(!policy->action_changing("impact_ready", NULL));
        ASSERT(policy->action_changing("compile_only", NULL));
        ASSERT(policy->action_changing("story_red", NULL));

        struct json_value cycle;
        struct json_value compact;
        json_init(&cycle);
        json_set_object(&cycle);
        ASSERT(json_push_kv_str(&cycle, "status", "story_green"));
        ASSERT(json_push_kv_str(&cycle, "phase", "STORY_GREEN"));
        ASSERT(json_push_kv_int(&cycle, "edit_epoch", 7));
        ASSERT(json_push_kv_str(&cycle, "action", "hot_shadow"));
        ASSERT(json_push_kv_int(&cycle, "elapsed_us", 90000));
        ASSERT(json_push_kv_str(&cycle, "story_fixture_id", "fixture.v1"));
        ASSERT(json_push_kv_str(&cycle, "story_adapter", "adapter.v1"));
        ASSERT(json_push_kv_int(&cycle, "story_timeout_ms", 1000));
        ASSERT(json_push_kv_str(&cycle, "forbidden_effect_mask",
                               "git|make|network"));
        ASSERT(policy->project_cycle(&cycle, 7, &compact));
        ASSERT_STR_EQ(json_get_str(json_get(&compact, "lane")), "REFLEX");
        ASSERT_STR_EQ(json_get_str(json_get(&compact, "event")),
                      "STORY_GREEN");
        ASSERT_EQ(json_get_int(json_get(&compact, "feedback_us")), 90000);
        ASSERT_STR_EQ(json_get_str(json_get(&compact, "story_fixture_id")),
                      "fixture.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&compact, "story_adapter")),
                      "adapter.v1");
        ASSERT_EQ(json_get_int(json_get(&compact, "story_timeout_ms")), 1000);
        ASSERT_STR_EQ(json_get_str(json_get(&compact,
                                            "forbidden_effect_mask")),
                      "git|make|network");
        json_free(&compact);
        json_free(&cycle);

        struct dev_reflex_proof_handoff_v2 handoff = {
            .candidate_epoch =
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            .source_epoch =
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            .affected_component = "app/services/src/example.c",
            .action = "affected_proof",
            .proof_inputs_sha3 =
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            .focused_evidence_sha3 =
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            .feedback_class = "HOT_SHADOW_CORE",
            .candidate_object_root =
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            .candidate_module_root =
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .story_root =
                "1111111111111111111111111111111111111111111111111111111111111111",
            .story_fixture_root =
                "2222222222222222222222222222222222222222222222222222222222222222",
            .observation_root =
                "3333333333333333333333333333333333333333333333333333333333333333",
            .affected_file_count = 1,
            .compile_green = true,
            .story_obtained = true,
        };
        char why[128] = {0};
        ASSERT(policy->handoff_validate(&handoff, why, sizeof(why)));
        handoff.compile_green = false;
        ASSERT(!policy->handoff_validate(&handoff, why, sizeof(why)));
        ASSERT(strstr(why, "compile-green") != NULL);
        handoff.compile_green = true;
        (void)snprintf(handoff.feedback_class,
                       sizeof(handoff.feedback_class), "%s", "COMPILE_ONLY");
        ASSERT(!policy->handoff_validate(&handoff, why, sizeof(why)));
        ASSERT(strstr(why, "behavior feedback class") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool hotfork_test_story(struct zcl_hotfork_observation_v1 *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->magic = ZCL_HOTFORK_OBSERVATION_MAGIC;
    return true;
}

static int test_hotfork_descriptor_boundary(void)
{
    int failures = 0;
    TEST("dev platform: HOT_FORK descriptor binds exact object and frozen owner story") {
        ASSERT(zcl_devloop_hotfork_registry_validate());
        const char object_root[] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        struct zcl_hotfork_capsule_v1 capsule = {
            .abi_version = ZCL_HOTFORK_CAPSULE_ABI_V1,
            .descriptor_size = sizeof(capsule),
            .owner_id = "vcs.source-package-checkout.v1",
            .source_tu = "lib/vcs/src/source_package_checkout.c",
            .candidate_object_root = object_root,
            .story_id = "source-package-checkout-result-and-shard-shape.v1",
            .story_root =
                "2b0966285304dc6742d5d3b4b5e416bd1a8766455b86d55632dbd5d36d5cd05d",
            .story_fixture_root =
                "4f7e0b7ddef2a52441bab973fc33e76dd754bfff9cf2aade463544a931cc4c3c",
            .run_story = hotfork_test_story,
        };
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        capsule.candidate_object_root =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        capsule.candidate_object_root = object_root;
        capsule.story_root =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "dev.native-command-input-policy.v1";
        capsule.source_tu = "tools/command/native_dev_command.c";
        capsule.story_id = "native-dev-input-and-interrupt-policy.v1";
        capsule.story_root =
                "9029d31e65330bcb075692f03854a1eeae81b9e79a9a83b82cbc0cfbb3d639b7";
        capsule.story_fixture_root =
            "84a5a5c9cda8f565a1cc4ac6b8d7c24ad1cbf33e67a540cf929a271028a821a3";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "dev.native-hotswap-receipt-policy.v1";
        capsule.source_tu = "tools/command/native_dev_hotswap.c";
        capsule.story_id = "native-dev-hotswap-receipt-policy.v1";
        capsule.story_root =
                "f96b868b4c9bdbcf0f27dee4425783310ab17a67d79c18f03b672a4b0aacbb46";
        capsule.story_fixture_root =
            "0cde6a93be5a14e0a8b8c6087b30f57178d80baf832cd38f71a41d95d6579d5b";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "vcs.devloop-proof-envelope.v1";
        capsule.source_tu = "lib/vcs/src/vcs_devloop.c";
        capsule.story_id = "vcs-devloop-publication-envelope.v1";
        capsule.story_root =
                "44919a4d66ff076e797584cce598772fbf711151b22c975b979e7c2e7ec0f0f9";
        capsule.story_fixture_root =
            "83ecbf1fe6983cd9d56c53e329743547d431339106902a12885de59a1ef128c8";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "app.native-read-rpc-composition.v1";
        capsule.source_tu = "app/controllers/src/app_native_handlers.c";
        capsule.story_id = "app-native-read-rpc-composition.v1";
        capsule.story_root =
                "4edc74613c7ac7916153b844c124221f91f10912b8f304a9b03dea4e5ac612c2";
        capsule.story_fixture_root =
            "b1bb052aee4622498ef45073f721013b6fa868d86c3864bc2cffd9d5b23cf647";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        const char *resident_owner[] = { capsule.source_tu };
        ASSERT(zcl_devloop_hotfork_batch_event(
            ".", resident_owner, 1, ZCL_DEVLOOP_PUBLISH_APPLY) == 0);

        capsule.owner_id = "zcode.moderation-input-policy.v1";
        capsule.source_tu =
            "tools/command/native_zcode_moderation_command.c";
        capsule.story_id = "zcode-moderation-input-policy.v1";
        capsule.story_root =
                "e635c666b7c34417ae7e3193758b5d41cf953f9fd689db85654005c4814da6f1";
        capsule.story_fixture_root =
            "d9185e80e37d0ca3ee3d728340d98b445c6971833a04569b9be0064699c37ef4";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "zcode.dev-input-policy.v1";
        capsule.source_tu = "tools/command/native_zcode_dev_command.c";
        capsule.story_id = "zcode-dev-input-policy.v1";
        capsule.story_root =
                "922b2a12b7a3350f5321030339bfeaa4c828da7c8cf094732625f6b6e024d5c8";
        capsule.story_fixture_root =
            "9628ecb3dda66dc1e4cbb61c95c2a8d4a69b5aee132949a446710c7b3a264526";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "zcode.epoch-propose-input-policy.v1";
        capsule.source_tu =
            "tools/command/native_zcode_epoch_propose_command.c";
        capsule.story_id = "zcode-epoch-propose-input-policy.v1";
        capsule.story_root =
                "c60772a3814ac424f88351b35800d4a8834346f594de320fe862f89094d4837b";
        capsule.story_fixture_root =
            "0fa5413c5a1995a9218b25e09fb199df5097e6d74579aec86755423913c85e5e";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "zcode.passport-input-policy.v1";
        capsule.source_tu =
            "tools/command/native_zcode_passport_command.c";
        capsule.story_id = "zcode-passport-input-policy.v1";
        capsule.story_root =
                "582c424d4bc7711bfb62eaf30f4e48c4b13a2519f9448f5c244ac4d4f9e4fc47";
        capsule.story_fixture_root =
            "4694dba2830b31f0fc2f1a36076ccfb1fb622db329c2ac736a659a6da7fb7aae";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "zcode.workspace-input-policy.v1";
        capsule.source_tu =
            "tools/command/native_zcode_workspace_command.c";
        capsule.story_id = "zcode-workspace-input-policy.v1";
        capsule.story_root =
                "d9d6725572788a6a89dad53461974cd298e220f5886bbfcc6abfa3b8707dd1de";
        capsule.story_fixture_root =
            "1f2478bb32a61ceee86df7160130be132caf9bd808d37f155553cf8bcc306899";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "vcs.source-package-transport-shape.v1";
        capsule.source_tu = "lib/vcs/src/source_package_transport.c";
        capsule.story_id = "source-package-transport-shape.v1";
        capsule.story_root =
                "b77e5e834b7480c64c5db2f81e7d392ee0514776ecaacc376f31f50a2d507d29";
        capsule.story_fixture_root =
            "7f0099af65b52a8bb07058b75a5f5df74480825a4ad0ee35149eeac5a996e060";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "zcode.source-bundle-input-policy.v1";
        capsule.source_tu =
            "tools/command/native_zcode_source_bundle_command.c";
        capsule.story_id = "zcode-source-bundle-input-policy.v1";
        capsule.story_root =
            "5bc89f38ee26e61acb4ba8ed09e35220c0d018c3113da27cf9ad966758e0146d";
        capsule.story_fixture_root =
            "4f2383f01fb601897bcfc2f375060129b319e293cb907cf577532efa6000854d";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_platform(void)
{
    int failures = 0;
    failures += test_failure_store();
    failures += test_distill_first_error();
    failures += test_hotswap_artifact_cache();
    failures += test_resident_restart_builder();
    failures += test_resident_process_cancellation();
    failures += test_resident_process_supersession();
    failures += test_native_source_cas_shadow();
    failures += test_cycle_proof_reuse_contract();
    failures += test_progressive_event_vocabulary();
    failures += test_reflex_policy_boundary();
    failures += test_hotfork_descriptor_boundary();
    failures += test_menu_and_search();
    failures += test_change_classification();
    failures += test_change_plan_closure();
    failures += test_watcher_publication_containment();
    failures += test_watch_relevance();
    failures += test_core_classification();
    failures += test_core_refusal_envelope();
    failures += test_core_refusal_cycle();
    failures += test_core_refusal_token();
    failures += test_public_app_abi();
    failures += test_app_runtime_transaction();
    failures += test_app_definition_compiler();
    failures += test_strict_dev_app_producers();
    failures += test_app_definition_hostile_fixtures();
    failures += test_signed_app_events();
    failures += test_social_sim();
    failures += test_native_activation_switch();
    failures += test_native_activation_request_builder();
    failures += test_native_activation_result_mapping();
    printf("=== dev_platform: %d failures ===\n", failures);
    return failures;
}
