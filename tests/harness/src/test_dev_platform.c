/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/test_timing_budget.h"
#include "test_group_catalog.h"

#include "command/native_dev_loop_command.h"
#include "dev_activation.h"
#include "dev_failure_store.h"
#include "devloop.h"
#include "devloop_watch_session.h"
#include "kernel/command_registry.h"
#include "hotswap/hotfork_capsule.h"
#include "framework/app_definition.h"
#include "framework/app_platform.h"
#include "hotswap/hotswap_module.h"
#include "json/json.h"
#include "keys/key.h"
#include "platform/directory_compat.h"
#include "platform/environment_compat.h"
#include "platform/time_compat.h"
#include "platform/file_watch_compat.h"
#include "platform/os_proc.h"
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
#if !defined(_WIN32)
#include <poll.h>
#include <sys/file.h>
#include <sys/wait.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int dp_environment_unset(const char *name)
{
#if defined(_WIN32)
    return platform_environment_set(name, "", 1);
#else
    return unsetenv(name);
#endif
}

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
            { "engine/controllers/src/status_native_handlers.c", "core.status" },
            { "engine/controllers/src/meta_native_handlers.c", "ops.metrics" },
            { "engine/controllers/src/chain_native_handlers.c", "core.consensus.utxo.audit" },
            { "engine/controllers/src/net_native_handlers.c", "core.network.peers.incidents" },
            { "contexts/wallet/controllers/src/wallet_native_handlers.c", "core.wallet.address.list" },
        };
        for (size_t i = 0; i < sizeof(hot) / sizeof(hot[0]); i++) {
            const char *files[] = { hot[i].path };
            ASSERT(zcl_devloop_plan_files(files, 1, &plan));
            ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
            ASSERT(strcmp(plan.proof_group, "hotswap_simnet") == 0);
            ASSERT(strcmp(plan.probe_tool, hot[i].probe) == 0);
        }

        const char *island_member[] = {
            "cognition/services/src/metaverse_agent_service.c",
        };
        ASSERT(zcl_devloop_plan_files(island_member, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.proof_group, "hotswap_simnet") == 0);
        ASSERT(strcmp(plan.probe_tool, "metaverse.property.list") == 0);

        const char *service_source[] = {
            "contexts/commons/services/src/zcode_c23_corpus_service.c",
        };
        ASSERT(zcl_devloop_plan_files(service_source, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.probe_tool, "zcode.commons.corpus.show") == 0);
        const char *story_service[] = {
            "contexts/wallet/services/src/vault_intent_decision_service.c",
        };
        ASSERT(zcl_devloop_plan_files(story_service, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_HOTSWAP);
        ASSERT(strcmp(plan.proof_group, "transaction_intent") == 0);
        ASSERT(strcmp(plan.probe_tool, "dev.test.story") == 0);
        const char *service_header[] = {
            "contexts/commons/services/include/services/zcode_c23_corpus_service.h",
        };
        ASSERT(zcl_devloop_plan_files(service_header, 1, &plan));
        ASSERT(plan.action == ZCL_DEVLOOP_RELOAD);

        const char *service_batch[] = {
            "contexts/commons/services/src/zcode_c23_economics_service.c",
            "contexts/commons/services/src/zcode_c23_economics_internal.h",
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
                      "contexts/commons/services/src/zcode_c23_economics_service.c");
        const char *later_static[] = {
            "tests/harness/src/test_zcode_commons.c",
            "contexts/commons/services/src/zcode_c23_economics_internal.h",
        };
        ASSERT(zcl_devloop_restart_source_set_add(
            &restart_set, later_static, 2));
        ASSERT(restart_set.count == 2);
        ASSERT_STR_EQ(restart_set.sources[1],
                      "tests/harness/src/test_zcode_commons.c");

        const char *cross_service_batch[] = {
            "contexts/commons/services/src/zcode_c23_economics_service.c",
            "contexts/commons/services/src/zcode_c23_corpus_service.c",
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

        /* A package lifecycle source maps to its owner groups where it now
         * lives; an unmapped change refuses the restart reflex outright. */
        const char *store[] = {
            "contexts/commons/services/src/package_lifecycle_store.c" };
        const char *refusal = NULL;
        ASSERT(zcl_devloop_plan_files(store, 1, &plan));
        ASSERT(plan.path_groups_len > 0);
        ASSERT(zcl_devloop_plan_proof_admissible(&plan, &refusal) ||
               strcmp(refusal, "unmapped-code-change") != 0);
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
/* Give a fixture file a settled mtime in the past. A cache that honours the
 * racy-clean rule re-reads any file whose mtime is not strictly older than the
 * pass that captured it, so a fixture written moments ago cannot demonstrate
 * reuse; a settled one can, and a distinct seq per write keeps every edit
 * visible in the stat key without depending on the clock ticking. */
static bool dp_settle(const char *dir, const char *rel, long seq)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    struct timespec times[2];
    times[0].tv_sec = times[1].tv_sec = (time_t)(1600000000L + seq);
    times[0].tv_nsec = times[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, full, times, 0) == 0;
}

static bool dp_mk_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; platform_directory_create(full, 0755); *p = '/'; }
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
 * codeindex fixture with a cross-file call edge core/modules/net/src/download.c ->
 * core/modules/net/src/tor_integration.c: changing the Tor file (path group
 * "test_tor") must
 * additionally surface download.c's groups ("download"...) via the closure,
 * WITHOUT dropping the path floor. */
static int test_change_plan_closure(void)
{
    int failures = 0;
    char fixture[PATH_MAX], absent[PATH_MAX];
    if (snprintf(fixture, sizeof(fixture), "test-tmp/dp_closure_%ld",
                 (long)getpid()) >= (int)sizeof(fixture) ||
        snprintf(absent, sizeof(absent), "test-tmp/dp_closure_absent_%ld",
                 (long)getpid()) >= (int)sizeof(absent))
        return 1;
    TEST("dev platform: change plan unions symbol-closure groups onto the path floor") {
        const char *leaf_files[] = {
            "tests/harness/src/test_dev_platform.c",
        };
        struct zcl_devloop_plan leaf_plan;
        ASSERT(zcl_devloop_plan_files(leaf_files, 1, &leaf_plan));
        ASSERT(leaf_plan.path_groups_len == 1);
        ASSERT(dp_group_in(leaf_plan.path_groups,
                           leaf_plan.path_groups_len,
                           "test_dev_platform"));

        ASSERT(test_rm_rf_recursive(fixture) == 0 || errno == ENOENT);
        /* tor_integration.c defines the changed leaf; download.c's function
         * calls it, so download.c is in the reverse-caller closure. Both paths
         * match distinct agent_impact rules ("test_tor" vs
         * "download ..."). */
        ASSERT(dp_mk_write(fixture, "core/modules/net/src/tor_integration.c",
                           "/* tor fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int tor_leaf(int x) { return x + 1; }\n"));
        ASSERT(dp_mk_write(fixture, "core/modules/net/src/download.c",
                           "/* download fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int dl_top(int x) { return tor_leaf(x) * 2; }\n"));
        ASSERT(dp_mk_write(fixture,
                           "tests/harness/src/test_dev_platform.c",
                           "/* semantic test leaf fixture */\n"
                           "#include \"net/clp.h\"\n"
                           "int test_dev_platform(void) { return tor_leaf(1); }\n"));
        ASSERT(dp_mk_write(fixture, "core/modules/net/include/net/clp.h",
                           "#ifndef NET_CLP_H\n#define NET_CLP_H\n"
                           "int tor_leaf(int x);\nint dl_top(int x);\n#endif\n"));
        ASSERT(dp_mk_write(fixture, "build/obj/tor_integration.d",
                           "build/obj/tor_integration.o: "
                           "core/modules/net/src/tor_integration.c "
                           "core/modules/net/include/net/clp.h\n"));
        ASSERT(dp_mk_write(fixture, "build/obj/download.d",
                           "build/obj/download.o: core/modules/net/src/download.c "
                           "core/modules/net/include/net/clp.h\n"));
        ASSERT(dp_mk_write(fixture,
                           "build/obj/test_dev_platform.d",
                           "build/obj/test_dev_platform.o: "
                           "tests/harness/src/test_dev_platform.c "
                           "core/modules/net/include/net/clp.h\n"));

        const char *files[] = { "core/modules/net/src/tor_integration.c" };
        struct zcl_devloop_plan plan;
        ASSERT(zcl_devloop_plan_files(files, 1, &plan));

        /* Floor: the path glob alone maps the changed file to "test_tor". */
        ASSERT(dp_group_in(plan.path_groups, plan.path_groups_len,
                           "test_tor"));
        /* "download" is NOT reachable by path glob from the tor file. */
        ASSERT(!dp_group_in(plan.path_groups, plan.path_groups_len, "download"));

        ASSERT(zcl_devloop_plan_add_closure(fixture, files, 1, &plan));
        ASSERT(plan.closure_attempted);
        ASSERT(!plan.closure_truncated);
        /* Closure surfaces download.c's group set as an ADDITION. */
        ASSERT(dp_group_in(plan.closure_groups, plan.closure_groups_len,
                           "download"));
        ASSERT(dp_group_in(plan.closure_groups, plan.closure_groups_len,
                           "test_dev_platform"));
        ASSERT(!dp_group_in(plan.closure_groups, plan.closure_groups_len,
                            "blog"));
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
        ASSERT(zcl_devloop_plan_add_closure(absent,
                                            files, 1, &plan2));
        ASSERT(plan2.closure_attempted);
        ASSERT(plan2.closure_groups_len == 0);
        ASSERT(dp_group_in(plan2.path_groups, plan2.path_groups_len,
                           "test_tor"));

        /* JSON surface carries both group sets + the truncation flag. */
        char body[16384];
        size_t n = zcl_devloop_plan_json_closure(fixture, files, 1, body,
                                                 sizeof(body));
        ASSERT(n > 0 && n < sizeof(body));
        struct json_value root = {0};
        ASSERT(json_read(&root, body, n));
        ASSERT(json_get(&root, "path_groups") != NULL);
        ASSERT(json_get(&root, "closure_groups") != NULL);
        ASSERT(strstr(body, "\"closure_truncated\":false") != NULL);
        ASSERT(strstr(body, "download") != NULL);
        json_free(&root);

        ASSERT(test_rm_rf_recursive(fixture) == 0 || errno == ENOENT);
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

        /* Validation lives beneath core/, so it is sealed and selects the
         * heaviest proof. Watcher classification never grants publication
         * authority. */
        const char *val[] = { "core/modules/validation/src/sighash.c" };
        ASSERT(zcl_devloop_plan_files(val, 1, &plan));
        ASSERT(plan.sealed_core);
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
        ASSERT(strcmp(next_command,
                      "make -j\"$(getconf _NPROCESSORS_ONLN)\" dev-bin") == 0);
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
        const char *hot[] = { "engine/controllers/src/status_native_handlers.c" };
        const char *reload[] = { "engine/services/src/node_health_service.c" };
        const char *consensus[] = { "core/modules/validation/src/sighash.c" };
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
               plan.sealed_core);
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
        platform_environment_set("HOME", dir, 1);

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
            platform_environment_set("HOME", saved_home, 1);
            free(saved_home);
        } else {
            dp_environment_unset("HOME");
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
        platform_environment_set("HOME", dir, 1);

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
            platform_environment_set("HOME", saved_home, 1);
            free(saved_home);
        } else {
            dp_environment_unset("HOME");
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
        ASSERT(strstr(body, "engine/models/src/comments.c") != NULL);
        ASSERT(strstr(body, "apps/blog/models/comments.c") == NULL);
        ASSERT(strstr(body, "writes and publishes nothing") != NULL);
        ASSERT(strstr(body, "dev app scaffold blog comments") != NULL);
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

        dp_environment_unset("ZCL_DEV_NATIVE_ACTIVATION");
        ASSERT(!dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "", 1);
        ASSERT(!dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "0", 1);
        ASSERT(!dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "nah", 1);
        ASSERT(!dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "1", 1);
        ASSERT(dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "true", 1);
        ASSERT(dev_activation_native_enabled());

        platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", "yes", 1);
        ASSERT(dev_activation_native_enabled());

        if (saved) {
            platform_environment_set("ZCL_DEV_NATIVE_ACTIVATION", saved, 1);
            free(saved);
        } else {
            dp_environment_unset("ZCL_DEV_NATIVE_ACTIVATION");
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
        dp_environment_unset("ZCL_DEV_GENERATION_ROOT");
        platform_environment_set("HOME", dir, 1);

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
        platform_environment_set("ZCL_DEV_GENERATION_ROOT", "/custom/gen-root", 1);
        ASSERT(dev_activation_request_from_cycle("/repo", "abc1234", &creq));
        ASSERT(strcmp(creq.req.gen_root, "/custom/gen-root") == 0);
        dp_environment_unset("ZCL_DEV_GENERATION_ROOT");

        /* build_commit may be empty (the vcs.vcs.revert seam's use) but not
         * NULL; repo_root/out must not be NULL either. */
        ASSERT(dev_activation_request_from_cycle("/repo", "", &creq));
        ASSERT(creq.req.build_commit[0] == '\0');
        ASSERT(!dev_activation_request_from_cycle(NULL, "abc1234", &creq));
        ASSERT(!dev_activation_request_from_cycle("/repo", NULL, &creq));
        ASSERT(!dev_activation_request_from_cycle("/repo", "abc1234", NULL));

        dp_environment_unset("HOME");
        ASSERT(!dev_activation_request_from_cycle("/repo", "abc1234", &creq));

        if (saved_home) {
            platform_environment_set("HOME", saved_home, 1);
            free(saved_home);
        } else {
            dp_environment_unset("HOME");
        }
        if (saved_gen_root) {
            platform_environment_set("ZCL_DEV_GENERATION_ROOT", saved_gen_root, 1);
            free(saved_gen_root);
        } else {
            dp_environment_unset("ZCL_DEV_GENERATION_ROOT");
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

static int test_watch_start_wait_reply(void)
{
    int failures = 0;
    TEST("dev platform: starting lock with a live watcher is blocked, dead pid fails") {
        /* Fresh-start wait: a live watcher that holds the lock in `starting`
         * is BLOCKED/WATCH_STARTING (retryable). A dead pid is still
         * WATCH_START_FAILED — the lock was never acquired. */
        struct zcl_dev_watch_start_wait_reply starting =
            zcl_native_dev_watch_start_wait_classify(
                4242, false, true, (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY,
                (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        ASSERT(starting.status == (int)ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT(starting.exit_code == (int)ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(starting.retryable);
        ASSERT(strcmp(starting.code, "WATCH_STARTING") == 0);
        ASSERT(strcmp(starting.message,
                      "watcher did not finish source reconciliation within "
                      "5 seconds") == 0);
        struct zcl_dev_watch_start_wait_reply dead =
            zcl_native_dev_watch_start_wait_classify(
                4242, false, false, (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY,
                (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        ASSERT(dead.status == (int)ZCL_COMMAND_STATUS_FAILED);
        ASSERT(dead.exit_code == (int)ZCL_COMMAND_EXIT_FAILED);
        ASSERT(dead.retryable);
        ASSERT(strcmp(dead.code, "WATCH_START_FAILED") == 0);
        ASSERT(strcmp(dead.message,
                      "watcher did not acquire its singleton lock") == 0);
        struct zcl_dev_watch_start_wait_reply pid1 =
            zcl_native_dev_watch_start_wait_classify(
                1, false, true, (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY,
                (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        ASSERT(strcmp(pid1.code, "WATCH_START_FAILED") == 0);
        struct zcl_dev_watch_start_wait_reply mismatch =
            zcl_native_dev_watch_start_wait_classify(
                4242, false, true, (int)ZCL_DEVLOOP_PUBLISH_APPLY,
                (int)ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
        ASSERT(strcmp(mismatch.code, "WATCH_START_FAILED") == 0);
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
            "engine/controllers/src/_coins_lookup_guard_fixture_tmp.c",
            "engine/jobs/src/_e5_stage_fixture_tmp_stage.c",
            "engine/modules/storage/src/_e4_pure_fixture_projection.c",
            "contexts/wallet/domain/src/_domain_purity_fixture_tmp.c",
        };
        for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++)
            ASSERT(!zcl_devloop_path_is_relevant(fixtures[i]));

        /* Real edits — including the genuine fixture SOURCES under
         * tests/harness/fixtures/ (no leading underscore) — must still fire. */
        static const char *const real[] = {
            "engine/reducer/jobs/src/stage_repair_reducer_frontier_coin.c",
            "core/consensus/src/check_block.c",
            "tools/dev/devloop_watch.c",
            "tests/harness/fixtures/raw_sqlite_step_fixture.c",
            "docs/HANDOFF.md",
            "Makefile",
            "cognition/controllers/include/controllers/agent_impact_rules.def",
        };
        for (size_t i = 0; i < sizeof(real) / sizeof(real[0]); i++)
            ASSERT(zcl_devloop_path_is_relevant(real[i]));

        /* Editor temp / build / vcs noise stays filtered. */
        ASSERT(!zcl_devloop_path_is_relevant("engine/services/src/foo.c~"));
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

/* The whole fixture below is POSIX process-and-locking semantics: fork(2)/
 * waitpid(2) concurrent writers, O_CLOEXEC, and AT_FDCWD/utimensat. It is
 * exercised only on POSIX; it is never expected to run on Windows, only to
 * stay syntactically valid there (mingw ships none of the above). */
#if !defined(_WIN32)
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
        mkdir(repo3, 0700) != 0 || platform_environment_set("HOME", home, 1) != 0)
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
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else
        (void)dp_environment_unset("HOME");
    test_rm_rf_recursive(home);
#undef FS_REQUIRE
    return ok;
}
#else
static bool run_failure_store_fixture(void)
{
    /* Not exercised on Windows: fork/waitpid concurrency and flock-style
     * locking below have no Windows equivalent in this fixture. */
    return true;
}
#endif /* !defined(_WIN32) */

static int test_failure_store(void)
{
    int failures = 0;
    TEST("dev platform: failure receipts are scoped, sealed, concurrent, and fail closed") {
        ASSERT(run_failure_store_fixture());
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
static bool seal_batch_copy_file(const char *from, const char *to)
{
    char body[32768];
    FILE *in = fopen(from, "r");
    if (!in)
        return false;
    size_t len = fread(body, 1, sizeof(body), in);
    bool ok = !ferror(in) && len > 0 && len < sizeof(body);
    if (fclose(in) != 0 || !ok)
        return false;
    int fd = open(to, O_WRONLY | O_TRUNC | O_CLOEXEC);
    ok = fd >= 0 && write(fd, body, len) == (ssize_t)len && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0)
        ok = false;
    return ok;
}

static int64_t seal_batch_pointer_epoch(const char *repo)
{
    char out[4096], why[192] = {0};
    size_t len = 0;
    int64_t epoch = -1;
    if (zcl_devloop_cycle_state_read(repo, out, sizeof(out), &len, &epoch,
                                     why, sizeof(why)) !=
        ZCL_DEVLOOP_STATE_FOUND)
        return -1;
    return epoch;
}

#define SB_CHECK(expr)                                                       \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "seal-batch fixture failed at %s:%d: %s\n",     \
                    __FILE__, __LINE__, #expr);                              \
            return false;                                                    \
        }                                                                    \
    } while (0)

static bool seal_batch_event_path(const char *state_dir, int64_t epoch,
                                  char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/cycle-events/%020lld.json",
                     state_dir, (long long)epoch);
    return n > 0 && n < PATH_MAX;
}

static const char g_seal_batch_event[] =
    "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
    "\"status\":\"impact_ready\",\"action\":\"reflex\","
    "\"reason\":\"fixture\",\"phase\":\"IMPACT_READY\","
    "\"runtime_published\":false,\"elapsed_ms\":2,\"files\":[]}";

/* One flush journals three ring events and moves the latest pointer once;
 * a second heal is a no-op. */
static bool seal_batch_flush(const char *repo, const char *state_dir,
                             int64_t epochs[4])
{
    static const char anchor[] =
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"passed\",\"action\":\"check\","
        "\"reason\":\"fixture\",\"phase\":\"verify\","
        "\"runtime_published\":false,\"elapsed_ms\":1,\"files\":[]}";
    char why[192] = {0}, event_path[PATH_MAX];
    /* No state yet: healing creates nothing and succeeds. */
    SB_CHECK(zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             access(state_dir, F_OK) != 0);
    SB_CHECK(zcl_devloop_cycle_state_write(repo, anchor, sizeof(anchor) - 1,
                                           why, sizeof(why)));
    int64_t base = seal_batch_pointer_epoch(repo);
    SB_CHECK(base > 0 &&
             zcl_devloop_cycle_stream_reset(repo, base, why, sizeof(why)));
    for (int64_t i = 0; i < 3; i++)
        SB_CHECK(zcl_devloop_cycle_stream_publish(
                     repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
                     &epochs[i], why, sizeof(why)) &&
                 epochs[i] == base + 1 + i);
    SB_CHECK(zcl_devloop_cycle_stream_flush_through(repo, epochs[2], why,
                                                    sizeof(why)));
    for (size_t i = 0; i < 3; i++)
        SB_CHECK(seal_batch_event_path(state_dir, epochs[i], event_path) &&
                 access(event_path, F_OK) == 0);
    SB_CHECK(seal_batch_pointer_epoch(repo) == epochs[2]);
    SB_CHECK(zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == epochs[2]);
    return true;
}

/* A flusher killed after journaling the batch's first event leaves the
 * pointer on that event. Healing adopts the verified tail, and inside a live
 * stream the next flush heals first so its epoch does not collide. */
static bool seal_batch_heal(const char *repo, const char *state_dir,
                            const char *pointer, int64_t epochs[4])
{
    char why[192] = {0}, event_path[PATH_MAX];
    SB_CHECK(seal_batch_event_path(state_dir, epochs[0], event_path) &&
             seal_batch_copy_file(event_path, pointer) &&
             seal_batch_pointer_epoch(repo) == epochs[0]);
    SB_CHECK(zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == epochs[2]);
    SB_CHECK(seal_batch_copy_file(event_path, pointer) &&
             seal_batch_pointer_epoch(repo) == epochs[0]);
    SB_CHECK(zcl_devloop_cycle_stream_publish(
                 repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
                 &epochs[3], why, sizeof(why)) &&
             epochs[3] == epochs[2] + 1);
    SB_CHECK(zcl_devloop_cycle_stream_flush_through(repo, epochs[3], why,
                                                    sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == epochs[3]);
    return true;
}

/* A damaged tail event is never adopted: healing and flushing refuse and
 * the pointer stays where it was. */
static bool seal_batch_damaged_tail(const char *repo, const char *state_dir,
                                    const char *pointer,
                                    const int64_t epochs[4])
{
    char why[192] = {0}, event_path[PATH_MAX];
    SB_CHECK(seal_batch_event_path(state_dir, epochs[2], event_path) &&
             seal_batch_copy_file(event_path, pointer) &&
             seal_batch_pointer_epoch(repo) == epochs[2]);
    SB_CHECK(seal_batch_event_path(state_dir, epochs[3], event_path));
    int fd = open(event_path, O_WRONLY | O_CLOEXEC);
    SB_CHECK(fd >= 0 && pwrite(fd, "X", 1, 0) == 1 && close(fd) == 0);
    SB_CHECK(!zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             strcmp(why, "cycle_state_heal_failed") == 0);
    SB_CHECK(!zcl_devloop_cycle_stream_flush_through(repo, epochs[3], why,
                                                     sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == epochs[2]);
    return true;
}

/* Publishes two ring events and forks a flusher that dies halfway through
 * writing the second one's journal record. */
static pid_t seal_batch_torn_flusher(const char *repo, int64_t base,
                                     int64_t next[2])
{
    char why[192] = {0};
    for (int i = 0; i < 2; i++)
        if (!zcl_devloop_cycle_stream_publish(
                repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
                &next[i], why, sizeof(why)) ||
            next[i] != base + 1 + i)
            return -1;
    pid_t flusher = fork();
    if (flusher == 0) {
        /* Record 1 journals next[0]; record 2 is next[1]'s, torn midway. */
        zcl_devloop_cycle_stream_test_kill_in_write(2);
        _exit(zcl_devloop_cycle_stream_flush_through(repo, next[1], why,
                                                     sizeof(why)) ? 0 : 1);
    }
    return flusher;
}

/* A flusher killed halfway through writing a journal record leaves no file
 * under that record's final name (records are staged, then renamed whole),
 * so the next heal and flush continue the journal instead of refusing a
 * torn tail. An ordinary heal does not scan the directory for the dead
 * writer's staging file; the next watcher restart sweeps it and seals the
 * ring event the flusher did not reach. */
static bool seal_batch_torn_write(const char *repo, const char *state_dir)
{
    char why[192] = {0}, event_path[PATH_MAX], staged[PATH_MAX];
    int64_t next[2] = {0}, durable = 0;
    int64_t base = seal_batch_pointer_epoch(repo);
    pid_t flusher = seal_batch_torn_flusher(repo, base, next);
    int status = 0;
    SB_CHECK(flusher > 0 && waitpid(flusher, &status, 0) == flusher &&
             WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    SB_CHECK(seal_batch_event_path(state_dir, next[0], event_path) &&
             access(event_path, F_OK) == 0);
    SB_CHECK(seal_batch_event_path(state_dir, next[1], event_path) &&
             access(event_path, F_OK) != 0 && errno == ENOENT);
    SB_CHECK(snprintf(staged, sizeof(staged),
                      "%s/cycle-events/.cycle.%ld.0.tmp", state_dir,
                      (long)flusher) > 0 &&
             access(staged, F_OK) == 0);
    SB_CHECK(seal_batch_pointer_epoch(repo) == base);
    SB_CHECK(zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == next[0]);
    SB_CHECK(access(staged, F_OK) == 0);
    SB_CHECK(zcl_devloop_cycle_stream_restart(repo, &durable, why,
                                              sizeof(why)) &&
             why[0] == 0 && durable == next[1] &&
             seal_batch_pointer_epoch(repo) == next[1] &&
             access(event_path, F_OK) == 0);
    SB_CHECK(access(staged, F_OK) != 0 && errno == ENOENT);
    return true;
}

/* On a filesystem without a no-replace rename (NFS, eCryptfs, some FUSE
 * mounts report EINVAL), journal records are published by link() then
 * unlink(): the batch still seals, each event keeps a single link, and no
 * staging file is left behind. */
static bool seal_batch_link_fallback(const char *repo, const char *state_dir)
{
    char why[192] = {0}, event_path[PATH_MAX], staged[PATH_MAX];
    int64_t epochs[2] = {0};
    struct stat st;
    zcl_devloop_cycle_stream_test_force_link(true);
    bool published = true;
    for (int i = 0; i < 2 && published; i++)
        published = zcl_devloop_cycle_stream_publish(
            repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
            &epochs[i], why, sizeof(why));
    bool sealed = published && zcl_devloop_cycle_stream_flush_through(
                                   repo, epochs[1], why, sizeof(why));
    zcl_devloop_cycle_stream_test_force_link(false);
    if (!sealed)
        fprintf(stderr, "link-fallback seal: %s\n", why);
    SB_CHECK(sealed && seal_batch_pointer_epoch(repo) == epochs[1]);
    for (int i = 0; i < 2; i++)
        SB_CHECK(seal_batch_event_path(state_dir, epochs[i], event_path) &&
                 stat(event_path, &st) == 0 && st.st_nlink == 1);
    SB_CHECK(snprintf(staged, sizeof(staged),
                      "%s/cycle-events/.cycle.%ld.0.tmp", state_dir,
                      (long)getpid()) > 0 &&
             access(staged, F_OK) != 0 && errno == ENOENT);
    return true;
}

/* A restart that finds an intact ring tail the journal cannot take (here a
 * read-only event directory, as ENOSPC or EIO would be) refuses and leaves
 * the ring untouched; once the journal can take it, the restart seals it. */
static bool seal_batch_restart_refusal(const char *repo, const char *state_dir)
{
    char why[192] = {0}, events_dir[PATH_MAX];
    int64_t tail = seal_batch_pointer_epoch(repo), epoch = 0;
    int64_t latest = 0, durable = 0;
    if (geteuid() == 0)
        return true; /* root writes through a read-only directory mode */
    for (int i = 0; i < 2; i++)
        SB_CHECK(zcl_devloop_cycle_stream_publish(
            repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
            &epoch, why, sizeof(why)));
    SB_CHECK(snprintf(events_dir, sizeof(events_dir), "%s/cycle-events",
                      state_dir) > 0 &&
             chmod(events_dir, 0500) == 0);
    bool refused = !zcl_devloop_cycle_stream_restart(repo, &durable, why,
                                                     sizeof(why));
    SB_CHECK(chmod(events_dir, 0700) == 0);
    if (!refused || !strstr(why, "cycle_stream_restart_tail_unsealed:"))
        fprintf(stderr, "restart over an unwritable journal: %s\n", why);
    SB_CHECK(refused && strstr(why, "cycle_stream_restart_tail_unsealed:"));
    SB_CHECK(zcl_devloop_cycle_stream_marks(repo, &latest, &durable) &&
             latest == tail + 2 && durable == tail &&
             seal_batch_pointer_epoch(repo) == tail);
    SB_CHECK(zcl_devloop_cycle_stream_restart(repo, &durable, why,
                                              sizeof(why)) &&
             why[0] == 0 && durable == tail + 2 &&
             seal_batch_pointer_epoch(repo) == tail + 2);
    return true;
}

/* A ring tail already overwritten (more events than slots since the journal
 * tail) cannot be sealed: the restart gives it up, continues after the
 * journal tail, and names the lost epoch range. */
static bool seal_batch_restart_loss(const char *repo)
{
    char why[192] = {0}, want[128];
    int64_t tail = seal_batch_pointer_epoch(repo), epoch = 0, durable = 0;
    int64_t latest = 0;
    for (int i = 0; i < 70; i++)
        SB_CHECK(zcl_devloop_cycle_stream_publish(
            repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
            &epoch, why, sizeof(why)));
    SB_CHECK(snprintf(want, sizeof(want),
                      "cycle_stream_restart_tail_lost:epochs=%lld..%lld:"
                      "cycle_stream_flush_range_evicted",
                      (long long)(tail + 1), (long long)(tail + 70)) > 0);
    bool restarted = zcl_devloop_cycle_stream_restart(repo, &durable, why,
                                                      sizeof(why));
    if (!restarted || strcmp(why, want) != 0)
        fprintf(stderr, "restart over an evicted tail: %s\n", why);
    SB_CHECK(restarted && strcmp(why, want) == 0 && durable == tail);
    SB_CHECK(zcl_devloop_cycle_stream_marks(repo, &latest, &durable) &&
             latest == tail && durable == tail &&
             seal_batch_pointer_epoch(repo) == tail);
    return true;
}

/* With no live ring, a direct journal write heals first: a writer killed
 * between link() and unlink() left the tail event with a second link and the
 * pointer behind it, and the write still takes the next epoch. */
static bool seal_batch_linked_direct(const char *repo, const char *state_dir,
                                     const char *pointer)
{
    char why[192] = {0}, event_path[PATH_MAX], staged[PATH_MAX];
    char previous[PATH_MAX], ring[PATH_MAX];
    int64_t tail = seal_batch_pointer_epoch(repo);
    struct stat st;
    SB_CHECK(tail > 1 && seal_batch_event_path(state_dir, tail, event_path) &&
             snprintf(staged, sizeof(staged),
                      "%s/cycle-events/.cycle.4243.0.tmp", state_dir) > 0 &&
             link(event_path, staged) == 0);
    SB_CHECK(seal_batch_event_path(state_dir, tail - 1, previous) &&
             seal_batch_copy_file(previous, pointer) &&
             snprintf(ring, sizeof(ring), "%s/native-events.ring",
                      state_dir) > 0 &&
             unlink(ring) == 0);
    bool written = zcl_devloop_cycle_state_write(
        repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1, why,
        sizeof(why));
    if (!written)
        fprintf(stderr, "direct write over a linked tail: %s\n", why);
    SB_CHECK(written && seal_batch_pointer_epoch(repo) == tail + 1 &&
             access(staged, F_OK) != 0 && stat(event_path, &st) == 0 &&
             st.st_nlink == 1);
    return true;
}

/* An older build published records with link() then unlink(); a kill between
 * the two left the sealed tail event with a second link under a staging
 * name, which the single-link check refuses. The next heal sweeps the
 * staging name under the cycle lock and the journal continues. */
static bool seal_batch_linked_tail(const char *repo, const char *state_dir,
                                   const char *pointer)
{
    char why[192] = {0}, event_path[PATH_MAX], staged[PATH_MAX];
    char previous[PATH_MAX];
    char out[4096];
    size_t len = 0;
    int64_t tail = seal_batch_pointer_epoch(repo), epoch = 0;
    struct stat st;
    SB_CHECK(tail > 0 && seal_batch_event_path(state_dir, tail, event_path) &&
             snprintf(staged, sizeof(staged),
                      "%s/cycle-events/.cycle.4242.0.tmp", state_dir) > 0 &&
             link(event_path, staged) == 0 && stat(event_path, &st) == 0 &&
             st.st_nlink == 2);
    /* The kill also came before the batch moved the pointer. */
    SB_CHECK(seal_batch_event_path(state_dir, tail - 1, previous) &&
             seal_batch_copy_file(previous, pointer) &&
             seal_batch_pointer_epoch(repo) == tail - 1);
    SB_CHECK(zcl_devloop_cycle_state_read_after(
                 repo, tail - 1, out, sizeof(out), &len, &epoch, why,
                 sizeof(why)) == ZCL_DEVLOOP_STATE_INVALID);
    SB_CHECK(zcl_devloop_cycle_state_heal(repo, why, sizeof(why)) &&
             access(staged, F_OK) != 0 && stat(event_path, &st) == 0 &&
             st.st_nlink == 1 && seal_batch_pointer_epoch(repo) == tail);
    SB_CHECK(zcl_devloop_cycle_stream_publish(
                 repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
                 &epoch, why, sizeof(why)) &&
             epoch == tail + 1 &&
             zcl_devloop_cycle_stream_flush_through(repo, epoch, why,
                                                    sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == epoch);
    return true;
}

/* The journal lifecycle in one workspace: batch, heal, a linked tail, then a
 * damaged tail. */
static bool seal_batch_chain(const char *repo, const char *state_dir,
                             const char *pointer, int64_t epochs[4])
{
    return seal_batch_heal(repo, state_dir, pointer, epochs) &&
           seal_batch_linked_tail(repo, state_dir, pointer) &&
           seal_batch_damaged_tail(repo, state_dir, pointer, epochs);
}

static bool seal_batch_link_step(const char *repo, const char *state_dir,
                                 const char *pointer, int64_t epochs[4])
{
    (void)pointer;
    (void)epochs;
    return seal_batch_link_fallback(repo, state_dir);
}

static bool seal_batch_torn_step(const char *repo, const char *state_dir,
                                 const char *pointer, int64_t epochs[4])
{
    (void)pointer;
    (void)epochs;
    return seal_batch_torn_write(repo, state_dir);
}

static bool seal_batch_refusal_step(const char *repo, const char *state_dir,
                                    const char *pointer, int64_t epochs[4])
{
    (void)pointer;
    (void)epochs;
    return seal_batch_restart_refusal(repo, state_dir);
}

static bool seal_batch_loss_step(const char *repo, const char *state_dir,
                                 const char *pointer, int64_t epochs[4])
{
    (void)state_dir;
    (void)pointer;
    (void)epochs;
    return seal_batch_restart_loss(repo);
}

static bool seal_batch_direct_step(const char *repo, const char *state_dir,
                                   const char *pointer, int64_t epochs[4])
{
    (void)epochs;
    return seal_batch_linked_direct(repo, state_dir, pointer);
}

typedef bool (*seal_batch_step_fn)(const char *repo, const char *state_dir,
                                   const char *pointer, int64_t epochs[4]);

/* Runs `step` in a fresh workspace (its own HOME) seeded by one flush batch,
 * so each property is checked, and fails, on its own. */
static bool seal_batch_in_workspace(const char *name, seal_batch_step_fn step)
{
    char home[PATH_MAX], repo[PATH_MAX], state_dir[PATH_MAX];
    char pointer[PATH_MAX];
    int64_t epochs[4] = {0};
    test_make_tmpdir(home, sizeof(home), "dev_platform", name);
    bool ok = snprintf(repo, sizeof(repo), "%s/repo", home) > 0 &&
              mkdir(repo, 0700) == 0 &&
              platform_environment_set("HOME", home, 1) == 0 &&
              zcl_devloop_workspace_state_dir(repo, state_dir,
                                              sizeof(state_dir)) &&
              snprintf(pointer, sizeof(pointer), "%s/native-cycle.json",
                       state_dir) > 0 &&
              seal_batch_flush(repo, state_dir, epochs) &&
              step(repo, state_dir, pointer, epochs);
    test_rm_rf_recursive(home);
    return ok;
}

static bool run_cycle_seal_batch_fixture(void)
{
    static const struct {
        const char *name;
        seal_batch_step_fn step;
    } steps[] = {
        {"cycle_seal_batch", seal_batch_chain},
        {"cycle_seal_link", seal_batch_link_step},
        {"cycle_seal_torn", seal_batch_torn_step},
        {"cycle_seal_refusal", seal_batch_refusal_step},
        {"cycle_seal_loss", seal_batch_loss_step},
        {"cycle_seal_direct", seal_batch_direct_step},
    };
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    if (getenv("HOME") && !saved_home)
        return false;
    bool ok = true;
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++)
        if (!seal_batch_in_workspace(steps[i].name, steps[i].step))
            ok = false;
    if (saved_home) {
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else
        (void)dp_environment_unset("HOME");
    return ok;
}
#undef SB_CHECK
#else
static bool run_cycle_seal_batch_fixture(void)
{
    return true; /* The journal fixture paths and modes are POSIX. */
}
#endif /* !defined(_WIN32) */

static int test_cycle_seal_batch(void)
{
    int failures = 0;
    TEST("dev platform: a journal flush batch moves the pointer once and heals a lagging pointer") {
        ASSERT(run_cycle_seal_batch_fixture());
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
#define DW_CHECK(expr)                                                       \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "drive-wait fixture failed at %s:%d: %s\n",     \
                    __FILE__, __LINE__, #expr);                              \
            return false;                                                    \
        }                                                                    \
    } while (0)

/* Holds the cycle lock exclusively, as a sealer does across journal fsyncs,
 * until released or five seconds pass. */
static pid_t drive_wait_lock_holder(const char *state_dir, int ready_fd,
                                    int release_fd)
{
    pid_t child = fork();
    if (child != 0)
        return child;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/cycle-state.lock", state_dir);
    int fd = n > 0 && n < PATH_MAX ? open(path, O_RDWR | O_CLOEXEC) : -1;
    if (fd < 0 || flock(fd, LOCK_EX) != 0 || write(ready_fd, "r", 1) != 1)
        _exit(1);
    struct pollfd release = {.fd = release_fd, .events = POLLIN};
    (void)poll(&release, 1, 5000);
    _exit(0);
}

/* Publishes one ring event after 200 ms, without sealing it. */
static pid_t drive_wait_late_publisher(const char *repo)
{
    pid_t child = fork();
    if (child != 0)
        return child;
    char why[192] = {0};
    int64_t epoch = 0;
    platform_sleep_ms(200);
    _exit(zcl_devloop_cycle_stream_publish(
              repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
              &epoch, why, sizeof(why)) ? 0 : 1);
}

static bool drive_wait_found(const char *repo, int64_t after,
                             int64_t expect_epoch)
{
    char out[4096], why[192] = {0};
    size_t len = 0;
    int64_t epoch = 0;
    int64_t started = platform_time_monotonic_us();
    enum zcl_devloop_state_lookup got = zcl_devloop_cycle_state_wait_after(
        repo, after, 10000, out, sizeof(out), &len, &epoch, why, sizeof(why));
    int64_t elapsed_ms = (platform_time_monotonic_us() - started) / 1000;
    if (got == ZCL_DEVLOOP_STATE_FOUND && epoch == expect_epoch &&
        elapsed_ms < 2000)
        return true;
    fprintf(stderr, "drive wait after=%lld: lookup=%d epoch=%lld "
                    "elapsed=%lld ms why=%s\n",
            (long long)after, (int)got, (long long)epoch,
            (long long)elapsed_ms, why);
    return false;
}

/* While a writer holds the cycle lock: an event already sealed out of the
 * ring and an event published later both reach the waiter at once, and an
 * absent event is an honest timeout rather than INVALID. */
static bool drive_wait_under_lock(const char *repo, int64_t sealed)
{
    char out[4096], why[192] = {0};
    size_t len = 0;
    int64_t epoch = 0;
    DW_CHECK(drive_wait_found(repo, sealed - 1, sealed));
    pid_t publisher = drive_wait_late_publisher(repo);
    DW_CHECK(publisher > 0);
    bool late = drive_wait_found(repo, sealed, sealed + 1);
    int status = 0;
    DW_CHECK(waitpid(publisher, &status, 0) == publisher &&
             WIFEXITED(status) && WEXITSTATUS(status) == 0);
    DW_CHECK(late);
    DW_CHECK(zcl_devloop_cycle_state_wait_after(
                 repo, sealed + 1, 300, out, sizeof(out), &len, &epoch, why,
                 sizeof(why)) == ZCL_DEVLOOP_STATE_ABSENT &&
             epoch == sealed + 1);
    return true;
}

/* A journal file the ring has not yet marked durable is a seal still in
 * progress: a waiter that cannot take the lock does not read it lock-free. */
static bool drive_wait_undurable(const char *repo, int64_t sealed)
{
    char out[4096], why[192] = {0};
    size_t len = 0;
    int64_t epoch = 0;
    DW_CHECK(zcl_devloop_cycle_state_wait_after(
                 repo, sealed, 300, out, sizeof(out), &len, &epoch, why,
                 sizeof(why)) == ZCL_DEVLOOP_STATE_ABSENT &&
             epoch == sealed);
    return true;
}

/* Runs `under` while another process holds the cycle lock exclusively. */
static bool drive_wait_with_lock(const char *repo, const char *state_dir,
                                 int64_t epoch,
                                 bool (*under)(const char *, int64_t))
{
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    DW_CHECK(pipe(ready) == 0 && pipe(release) == 0);
    pid_t holder = drive_wait_lock_holder(state_dir, ready[1], release[0]);
    char byte = 0;
    bool held = holder > 0 && read(ready[0], &byte, 1) == 1;
    bool ok = held && under(repo, epoch);
    int status = 0;
    bool released = write(release[1], "x", 1) == 1 && holder > 0 &&
                    waitpid(holder, &status, 0) == holder &&
                    WIFEXITED(status) && WEXITSTATUS(status) == 0;
    for (int i = 0; i < 2; i++) {
        (void)close(ready[i]);
        (void)close(release[i]);
    }
    return ok && released;
}

static bool drive_wait_fixture(const char *repo, const char *state_dir)
{
    char why[192] = {0};
    int64_t epoch = 0;
    DW_CHECK(zcl_devloop_cycle_state_write(
        repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1, why,
        sizeof(why)));
    int64_t base = seal_batch_pointer_epoch(repo);
    DW_CHECK(base > 0 &&
             zcl_devloop_cycle_stream_reset(repo, base, why, sizeof(why)));
    DW_CHECK(zcl_devloop_cycle_stream_publish(
                 repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1,
                 &epoch, why, sizeof(why)) &&
             zcl_devloop_cycle_stream_flush_through(repo, epoch, why,
                                                    sizeof(why)));
    DW_CHECK(drive_wait_with_lock(repo, state_dir, epoch,
                                  drive_wait_under_lock));
    /* The late publisher left epoch + 1 in the ring. Seal it, then restart
     * the ring one epoch behind the journal: that file is not yet durable
     * as far as the ring knows. */
    DW_CHECK(zcl_devloop_cycle_stream_flush_through(repo, epoch + 1, why,
                                                    sizeof(why)) &&
             zcl_devloop_cycle_stream_reset(repo, epoch, why, sizeof(why)));
    return drive_wait_with_lock(repo, state_dir, epoch, drive_wait_undurable);
}

static bool run_drive_wait_fixture(void)
{
    char home[PATH_MAX], repo[PATH_MAX], state_dir[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    if (getenv("HOME") && !saved_home)
        return false;
    test_make_tmpdir(home, sizeof(home), "dev_platform", "drive_wait_lock");
    bool ok = snprintf(repo, sizeof(repo), "%s/repo", home) > 0 &&
              mkdir(repo, 0700) == 0 &&
              platform_environment_set("HOME", home, 1) == 0 &&
              zcl_devloop_workspace_state_dir(repo, state_dir,
                                              sizeof(state_dir)) &&
              drive_wait_fixture(repo, state_dir);
    if (saved_home) {
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else
        (void)dp_environment_unset("HOME");
    test_rm_rf_recursive(home);
    return ok;
}
#undef DW_CHECK
#else
static bool run_drive_wait_fixture(void)
{
    return true; /* flock and inotify waits are POSIX. */
}
#endif /* !defined(_WIN32) */

static int test_drive_wait_ignores_seal_lock(void)
{
    int failures = 0;
    TEST("dev platform: drive's event wait is never delayed by a writer holding the cycle lock") {
        ASSERT(run_drive_wait_fixture());
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
#define MW_CHECK(expr)                                                       \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "mirror-write fixture failed at %s:%d: %s\n",   \
                    __FILE__, __LINE__, #expr);                              \
            return false;                                                    \
        }                                                                    \
    } while (0)

#define MW_EVENTS 26

/* Reasons 0-2: ring events published before the writes; 3-12 and 13-22:
 * two concurrent ring publishers; 23-25: direct journal writes. */
static bool mirror_write_reason(size_t k, char reason[32])
{
    int r = k < 3 ? snprintf(reason, 32, "ring-%zu", k)
          : k < 23 ? snprintf(reason, 32, "pub%zu-%zu", (k - 3) / 10,
                              (k - 3) % 10)
                   : snprintf(reason, 32, "mirror-%zu", k - 23);
    return r > 0 && r < 32;
}

static bool mirror_write_event(size_t k, char body[512], size_t *len)
{
    char reason[32];
    int n = mirror_write_reason(k, reason) ? snprintf(
        body, 512,
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"impact_ready\",\"action\":\"reflex\","
        "\"reason\":\"%s\",\"phase\":\"IMPACT_READY\","
        "\"runtime_published\":false,\"elapsed_ms\":2,\"files\":[]}",
        reason) : -1;
    *len = n > 0 ? (size_t)n : 0;
    return n > 0 && n < 512;
}

/* Publishes its ten ring events, pausing inside each epoch reservation. */
static pid_t mirror_write_publisher(const char *repo, size_t id)
{
    pid_t child = fork();
    if (child != 0)
        return child;
    zcl_devloop_cycle_stream_test_publish_pause_ms(2);
    for (size_t i = 0; i < 10; i++) {
        char body[512], why[192] = {0};
        size_t len = 0;
        int64_t epoch = 0;
        if (!mirror_write_event(3 + id * 10 + i, body, &len) ||
            !zcl_devloop_cycle_stream_publish(repo, body, len, &epoch, why,
                                              sizeof(why)))
            _exit(1);
    }
    _exit(0);
}

/* Journal epochs (base, tail] hold every event exactly once. */
static bool mirror_write_journal_agrees(const char *repo, int64_t base,
                                        int64_t tail)
{
    bool seen[MW_EVENTS] = {false};
    MW_CHECK(tail - base == MW_EVENTS);
    for (int64_t e = base + 1; e <= tail; e++) {
        char out[4096], why[192] = {0}, reason[32], key[48];
        size_t len = 0;
        int64_t epoch = 0;
        MW_CHECK(zcl_devloop_cycle_state_read_after(
                     repo, e - 1, out, sizeof(out), &len, &epoch, why,
                     sizeof(why)) == ZCL_DEVLOOP_STATE_FOUND &&
                 epoch == e);
        size_t matched = MW_EVENTS;
        for (size_t k = 0; k < MW_EVENTS; k++) {
            MW_CHECK(mirror_write_reason(k, reason));
            int n = snprintf(key, sizeof(key), "\"reason\":\"%s\"", reason);
            if (n > 0 && (size_t)n < sizeof(key) && strstr(out, key))
                matched = k;
        }
        MW_CHECK(matched < MW_EVENTS && !seen[matched]);
        seen[matched] = true;
    }
    return true;
}

/* An anchor event, then a ring restarted after it holding three unsealed
 * events. */
static bool mirror_write_seed(const char *repo, int64_t *base)
{
    char why[192] = {0}, body[512];
    size_t len = 0;
    int64_t epoch = 0;
    MW_CHECK(zcl_devloop_cycle_state_write(
        repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1, why,
        sizeof(why)));
    *base = seal_batch_pointer_epoch(repo);
    MW_CHECK(*base > 0 &&
             zcl_devloop_cycle_stream_reset(repo, *base, why, sizeof(why)));
    for (size_t k = 0; k < 3; k++)
        MW_CHECK(mirror_write_event(k, body, &len) &&
                 zcl_devloop_cycle_stream_publish(repo, body, len, &epoch,
                                                  why, sizeof(why)));
    return true;
}

/* The publication lock is uncontended in the common case. */
static bool mirror_write_publish_cost(const char *repo)
{
    char why[192] = {0};
    int64_t epoch = 0;
    int64_t started = platform_time_monotonic_us();
    for (int i = 0; i < 200; i++)
        MW_CHECK(zcl_devloop_cycle_stream_publish(
            repo, g_seal_batch_event, sizeof(g_seal_batch_event) - 1, &epoch,
            why, sizeof(why)));
    int64_t per_publish_us = (platform_time_monotonic_us() - started) / 200;
    fprintf(stderr, "ring publish under its lock: %lld us each\n",
            (long long)per_publish_us);
    MW_CHECK(per_publish_us < 5000);
    return true;
}

/* Direct journal writes while ring events are still unsealed and two other
 * processes publish: each write takes a ring epoch after the unsealed ones,
 * every event is journaled once, and ring and journal agree. */
static bool mirror_write_fixture(const char *repo)
{
    char why[192] = {0}, body[512];
    size_t len = 0;
    int64_t base = 0, latest = 0, durable = 0;
    MW_CHECK(mirror_write_seed(repo, &base));
    pid_t publishers[2] = {mirror_write_publisher(repo, 0),
                           mirror_write_publisher(repo, 1)};
    bool written = true;
    for (size_t k = 23; k < MW_EVENTS; k++)
        written = written && mirror_write_event(k, body, &len) &&
                  zcl_devloop_cycle_state_write(repo, body, len, why,
                                                sizeof(why));
    bool joined = true;
    for (int i = 0; i < 2; i++) {
        int status = 0;
        joined = joined && publishers[i] > 0 &&
                 waitpid(publishers[i], &status, 0) == publishers[i] &&
                 WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (!written)
        fprintf(stderr, "mirror write refused: %s\n", why);
    MW_CHECK(written && joined);
    MW_CHECK(zcl_devloop_cycle_stream_marks(repo, &latest, &durable) &&
             latest == base + MW_EVENTS);
    MW_CHECK(zcl_devloop_cycle_stream_flush_through(repo, latest, why,
                                                    sizeof(why)) &&
             seal_batch_pointer_epoch(repo) == latest);
    MW_CHECK(mirror_write_journal_agrees(repo, base, latest));
    return mirror_write_publish_cost(repo);
}

static bool run_mirror_write_fixture(void)
{
    char home[PATH_MAX], repo[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    if (getenv("HOME") && !saved_home)
        return false;
    test_make_tmpdir(home, sizeof(home), "dev_platform", "mirror_write");
    bool ok = snprintf(repo, sizeof(repo), "%s/repo", home) > 0 &&
              mkdir(repo, 0700) == 0 &&
              platform_environment_set("HOME", home, 1) == 0 &&
              mirror_write_fixture(repo);
    if (saved_home) {
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else
        (void)dp_environment_unset("HOME");
    test_rm_rf_recursive(home);
    return ok;
}
#undef MW_CHECK
#else
static bool run_mirror_write_fixture(void)
{
    return true; /* Concurrent publishers are forked processes. */
}
#endif /* !defined(_WIN32) */

static int test_mirror_write_joins_ring(void)
{
    int failures = 0;
    TEST("dev platform: a direct journal write takes the ring's next epoch and never collides with unsealed ring events") {
        ASSERT(run_mirror_write_fixture());
        PASS();
    } _test_next:;
    return failures;
}

#if !defined(_WIN32)
/* The selftest runs in a fresh child, so "no child outlived the watcher"
 * cannot be confused with a resident helper an earlier case left running. */
static bool run_watch_sealer_isolated(const char *repo)
{
    int report[2];
    if (pipe(report) != 0)
        return false;
    pid_t child = fork();
    if (child == 0) {
        (void)close(report[0]);
        const char *broken = zcl_devloop_watch_sealer_selftest(repo);
        size_t len = broken ? strlen(broken) : 0;
        bool sent = !broken || write(report[1], broken, len) == (ssize_t)len;
        _exit(!broken && sent ? 0 : 1);
    }
    (void)close(report[1]);
    char broken[1024] = {0};
    ssize_t n = child > 0 ? read(report[0], broken, sizeof(broken) - 1) : -1;
    (void)close(report[0]);
    int status = 0;
    bool exited = child > 0 && waitpid(child, &status, 0) == child &&
                  WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!exited)
        fprintf(stderr, "watch sealer selftest: %s (wait status %d)\n",
                n > 0 ? broken : "no report", status);
    return exited && n == 0;
}
#endif

static int test_watcher_journal_sealer(void)
{
    int failures = 0;
#if !defined(_WIN32)
    char home[PATH_MAX] = {0}, repo[PATH_MAX] = {0};
    const char *current_home = getenv("HOME");
    char *saved_home = current_home ? strdup(current_home) : NULL;
    TEST("dev platform: the watcher's journal sealer drains on stop, falls back inline, survives a crash and SIGTERM, and outlives a killed watcher safely") {
        ASSERT(!current_home || saved_home);
        test_make_tmpdir(home, sizeof(home), "dev_platform", "watch_sealer");
        int n = snprintf(repo, sizeof(repo), "%s/repo", home);
        ASSERT(n > 0 && (size_t)n < sizeof(repo));
        ASSERT(mkdir(repo, 0700) == 0);
        ASSERT(platform_environment_set("HOME", home, 1) == 0);
        ASSERT(run_watch_sealer_isolated(repo));
        PASS();
    } _test_next:;
    if (saved_home) {
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else {
        (void)dp_environment_unset("HOME");
    }
    if (home[0])
        test_rm_rf_recursive(home);
#endif
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
        !dp_mk_write(root, "engine/composition/hotswap_swappable.def", "/* fixture */\n") ||
        !dp_mk_write(root, "engine/composition/hotswap_islands.def", "/* fixture */\n") ||
        !dp_mk_write(root, "engine/composition/hotswap_services.def", "/* fixture */\n") ||
        !dp_mk_write(root, "engine/composition/hotswap_shadow_owners.def",
                     "/* fixture */\n") ||
        !dp_mk_write(root, "engine/composition/hotfork_capsules.def",
                     "/* fixture */\n") ||
        !dp_mk_write(root, "engine/controllers/src/status_native_handlers.c",
                     owner_v1) ||
        !dp_mk_write(root, "engine/controllers/src/status_native_helpers.c",
                     "int zcl_hotswap_fixture_helper(void) { return 2; }\n") ||
        !dp_mk_write(root, "engine/controllers/src/status_mutation_fixture.h",
                     "#define ZCL_HOTSWAP_MUTATION_FIXTURE 1\n") ||
        /* Every island member of the owner TU must exist in the sandbox: the
         * island wrapper #includes each one, and a member it cannot stat
         * fails the build with "island member list is invalid or unwritable".
         * engine/composition/hotswap_islands.def is the authority for this list — when a
         * member is added there, add it here too, or this fixture breaks in a
         * way whose message points at the wrapper rather than at the sandbox. */
        !dp_mk_write(root, "engine/controllers/src/status_brief_native_handler.c",
                     "int zcl_hotswap_fixture_brief(void) { return 5; }\n") ||
        !dp_mk_write(root,
                     "contexts/commons/services/src/zcode_c23_corpus_service.c",
                     "int zcl_hotswap_fixture_service(void) { return 3; }\n") ||
        !dp_mk_write(root,
                     "contexts/commons/services/src/zcode_c23_economics_service.c",
                     "#include \"zcode_c23_economics_internal.h\"\n"
                     "int zcl_hotswap_fixture_economics(void) { return 4; }\n") ||
        !dp_mk_write(root,
                     "contexts/commons/services/src/zcode_c23_economics_internal.h",
                     "#define ZCL_ECONOMICS_FIXTURE 4\n"))
        return false;
    char canonical_root[PATH_MAX];
    if (!platform_directory_canonical_real(root, canonical_root,
                                           sizeof(canonical_root)))
        return false;
    char flags[PATH_MAX * 2];
    int n = snprintf(
        flags, sizeof(flags),
        "CC=%s\n"
        "CXX=g++\n"
        "COMPILER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "DEV_CFLAGS=-DZCL_DEV_BUILD -ffile-prefix-map=%s=/zclassic23\n"
        "HOTSWAP_MODULE_LDFLAGS=-shared -nostartfiles -Wl,-Bsymbolic\n",
        compiler, canonical_root);
    return n > 0 && n < (int)sizeof(flags) &&
           dp_mk_write(root, "build/hotswap-fast/flags.env", flags);
}

/* A second checkout discovers its closure once, then reuses the exact
 * artifact immediately without requiring a second save -- and on the same
 * device as the cache, with no forced copy, it still gets a fresh
 * single-link file, never a hardlink into the shared cache: build/hotswap/
 * is a tree check-no-hardlink-seeding refuses to find a multiply-linked
 * file in. */
static bool dp_second_checkout_hit_is_single_link(
    const char *root_b, const char *owner,
    const struct zcl_devloop_hotswap_build_receipt *built,
    const struct stat *cache_st,
    struct zcl_devloop_hotswap_build_receipt *cross,
    struct zcl_devloop_process_result *process, char *why, size_t why_cap)
{
    if (!zcl_devloop_hotswap_build(root_b, owner, cross, process, why,
                                   why_cap) ||
        !cross->artifact_cache_hit || cross->compiler_processes != 1 ||
        cross->linker_processes != 0 ||
        strcmp(cross->artifact_cache_key, built->artifact_cache_key) != 0 ||
        strcmp(cross->artifact_sha256, built->artifact_sha256) != 0 ||
        strcmp(cross->candidate_object_sha256,
               built->candidate_object_sha256) != 0)
        return false;
    struct stat cross_st = {0};
    return stat(cross->artifact_path, &cross_st) == 0 &&
           cross_st.st_nlink == 1 &&
           (cross_st.st_dev != cache_st->st_dev ||
            cross_st.st_ino != cache_st->st_ino);
}

static bool dp_hotswap_fixture_paths(
    char root_a[PATH_MAX], char root_b[PATH_MAX],
    char cache_rel[PATH_MAX], char compiler_rel[PATH_MAX],
    char dep_path[PATH_MAX], char cache[PATH_MAX], char compiler[PATH_MAX])
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(root_a, PATH_MAX, "test-tmp/dev_hotswap_cache_a_%ld",
                 (long)getpid()) >= PATH_MAX ||
        snprintf(root_b, PATH_MAX, "test-tmp/dev_hotswap_cache_b_%ld",
                 (long)getpid()) >= PATH_MAX ||
        snprintf(cache_rel, PATH_MAX, "test-tmp/dev_hotswap_shared_cache_%ld",
                 (long)getpid()) >= PATH_MAX ||
        snprintf(compiler_rel, PATH_MAX, "test-tmp/dev_hotswap_fake_cc_%ld.sh",
                 (long)getpid()) >= PATH_MAX ||
        snprintf(dep_path, PATH_MAX,
                 "%s/build/hotswap-fast/engine_controllers_src_status_native_handlers.c.d",
                 root_b) >= PATH_MAX ||
        snprintf(cache, PATH_MAX, "%s/%s", cwd, cache_rel) >= PATH_MAX ||
        snprintf(compiler, PATH_MAX, "%s/%s", cwd, compiler_rel) >= PATH_MAX)
        return false;
    return true;
}

static bool run_hotswap_artifact_cache_fixture(void)
{
    char root_a[PATH_MAX], root_b[PATH_MAX], cache_rel[PATH_MAX];
    char compiler_rel[PATH_MAX], dep_path[PATH_MAX];
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
        "  extra=\n"
        "  if [ \"${ZCL_DEVLOOP_TEST_MUTATE_DEPS:-0}\" = 1 ]; then\n"
        "    count_file=build/hotswap-fast/mutation-compile-count\n"
        "    n=$(cat \"$count_file\" 2>/dev/null || echo 0); n=$((n + 1))\n"
        "    printf '%s\\n' \"$n\" >\"$count_file\"\n"
        "    if [ \"$n\" -ge 2 ]; then extra=' engine/controllers/src/status_mutation_fixture.h'; fi\n"
        "  fi\n"
        "  printf 'fixture-object-v1\\n' >\"$out\"\n"
        "  if [ \"$source\" = contexts/commons/services/src/zcode_c23_corpus_service.c ]; then\n"
        "    printf '%s: %s\\n' \"$out\" \"$source\" >\"$dep\"\n"
        "  elif [ \"$source\" = contexts/commons/services/src/zcode_c23_economics_service.c ]; then\n"
        "    printf '%s: %s contexts/commons/services/src/zcode_c23_economics_internal.h\\n' \"$out\" \"$source\" >\"$dep\"\n"
        "  else\n"
        "    printf '%s: engine/controllers/src/status_native_helpers.c engine/controllers/src/status_native_handlers.c%s\\n' \"$out\" \"$extra\" >\"$dep\"\n"
        "  fi\n"
        "else\n"
        "  printf 'fixture-module-v1\\n' >\"$out\"\n"
        "fi\n";
    bool ok = false;
    const char *stage = "setup";
    char why[256] = {0};
    char cache[PATH_MAX], compiler[PATH_MAX];
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
    if (!dp_hotswap_fixture_paths(root_a, root_b, cache_rel, compiler_rel,
                                  dep_path, cache, compiler))
        return false;
    if (had_cache)
        (void)snprintf(saved_cache, sizeof(saved_cache), "%s", prior_cache);
    if (had_process)
        (void)snprintf(saved_process, sizeof(saved_process), "%s",
                       prior_process);
    if (had_force_copy)
        (void)snprintf(saved_force_copy, sizeof(saved_force_copy), "%s",
                       prior_force_copy);
    test_rm_rf_recursive(root_a);
    test_rm_rf_recursive(root_b);
    test_rm_rf_recursive(cache_rel);
    (void)unlink(compiler_rel);
    if (!dp_mk_write(".", compiler_rel, fake_compiler) ||
        chmod(compiler_rel, 0700) != 0 ||
        !dp_hotswap_cache_fixture_init(root_a, compiler) ||
        !dp_hotswap_cache_fixture_init(root_b, compiler) ||
        platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", cache, 1) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", "1", 1) != 0)
        goto out;

    struct zcl_devloop_hotswap_build_receipt built = {0};
    struct zcl_devloop_hotswap_build_receipt hit = {0}, edited = {0};
    struct zcl_devloop_hotswap_build_receipt reverted = {0}, cross = {0};
    struct zcl_devloop_hotswap_build_receipt mutated = {0};
    struct zcl_devloop_hotswap_build_receipt service_built = {0};
    struct zcl_devloop_hotswap_build_receipt batch_built = {0};
    struct zcl_devloop_hotswap_build_receipt batch_edited = {0};
    struct zcl_devloop_hotswap_build_receipt batch_cross = {0};
    struct zcl_devloop_process_result process = {0};
    const char *owner = "engine/controllers/src/status_native_handlers.c";

    stage = "cold-first-publish";
    if (!zcl_devloop_hotswap_build(root_a, owner, &built, &process,
                                   why, sizeof(why)) ||
        built.artifact_cache_hit || built.compiler_processes != 2 ||
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
    if (dp_environment_unset("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY") != 0)
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
                     "engine/controllers/src/status_native_handlers.c",
                     "int zcl_hotswap_fixture_owner(void) { return 9; }\n") ||
        !zcl_devloop_hotswap_build(root_a, owner, &edited, &process,
                                   why, sizeof(why)) ||
        edited.artifact_cache_hit || edited.compiler_processes != 1 ||
        edited.linker_processes != 1 ||
        strcmp(edited.artifact_cache_key, built.artifact_cache_key) == 0)
        goto out;
    stage = "exact-revert";
    if (!dp_mk_write(root_a,
                     "engine/controllers/src/status_native_handlers.c",
                     "int zcl_hotswap_fixture_owner(void) { return 1; }\n") ||
        !zcl_devloop_hotswap_build(root_a, owner, &reverted, &process,
                                   why, sizeof(why)) ||
        !reverted.artifact_cache_hit || reverted.compiler_processes != 0 ||
        reverted.linker_processes != 0 ||
        strcmp(reverted.artifact_cache_key, built.artifact_cache_key) != 0)
        goto out;

    stage = "cross-checkout-hit";
    if (!dp_second_checkout_hit_is_single_link(root_b, owner, &built, &cache_st,
                                               &cross, &process, why,
                                               sizeof(why)))
        goto out;

    /* A dependency appearing between the discovery and verification compile
     * must refuse the cold activation and publish no module. */
    stage = "cold-dependency-mutation";
    if (!dp_mk_write(root_b, owner,
                     "int zcl_hotswap_fixture_owner(void) { return 13; }\n") ||
        unlink(dep_path) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_MUTATE_DEPS", "1", 1) != 0 ||
        zcl_devloop_hotswap_build(root_b, owner, &mutated, &process,
                                  why, sizeof(why)) ||
        dp_environment_unset("ZCL_DEVLOOP_TEST_MUTATE_DEPS") != 0 ||
        mutated.compiler_processes != 2 || mutated.linker_processes != 0 ||
        strstr(why, "dependency closure size changed") == NULL)
        goto out;

    /* A pure service island compiles its owner directly; it has no command
     * unity-member list.  Requiring one here made every service save reject
     * before starting the compiler. */
    const char *service =
        "contexts/commons/services/src/zcode_c23_corpus_service.c";
    stage = "service-island";
    if (!zcl_devloop_hotswap_build(root_a, service, &service_built, &process,
                                   why, sizeof(why)) ||
        service_built.compiler_processes != 2 ||
        service_built.linker_processes != 1 ||
        strcmp(service_built.source_tu, service) != 0)
        goto out;

    /* A source + private-header epoch maps back to one owner, compiles that
     * exact dependency closure once, and yields one candidate artifact. */
    const char *economics_source =
        "contexts/commons/services/src/zcode_c23_economics_service.c";
    const char *economics_header =
        "contexts/commons/services/src/zcode_c23_economics_internal.h";
    stage = "multi-file-island";
    if (!zcl_devloop_hotswap_build(root_a, economics_header, &batch_built,
                                   &process, why, sizeof(why)) ||
        batch_built.compiler_processes != 2 ||
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
    if (!zcl_devloop_hotswap_build(root_b, economics_header, &batch_cross,
                                   &process, why, sizeof(why)) ||
        !batch_cross.artifact_cache_hit ||
        batch_cross.compiler_processes != 1 ||
        batch_cross.linker_processes != 0 ||
        strcmp(batch_cross.artifact_cache_key,
               batch_built.artifact_cache_key) != 0 ||
        strcmp(batch_cross.artifact_sha256,
               batch_built.artifact_sha256) != 0)
        goto out;
    ok = true;

out:
    (void)dp_environment_unset("ZCL_DEVLOOP_TEST_MUTATE_DEPS");
    if (!ok)
        fprintf(stderr, "hotswap cache fixture failed at %s: %s\n", stage,
                why[0] ? why : "no build reason");
    if (had_cache)
        (void)platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", saved_cache, 1);
    else
        (void)dp_environment_unset("ZCL_DEV_ARTIFACT_CACHE");
    if (had_process)
        (void)platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved_process, 1);
    else
        (void)dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS");
    if (had_force_copy)
        (void)platform_environment_set("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", saved_force_copy, 1);
    else
        (void)dp_environment_unset("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
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

/* Mirror the catalog's exact selection, then split only the declared
 * integration-only groups. This fixture must assert the complete selected
 * set even when the owner group acquires new registered shards. */
static bool dp_expected_proof_groups(
    const struct zcl_devloop_plan *plan,
    char full[4096], char immediate[4096], char deferred[4096],
    uint32_t *total, uint32_t *now, uint32_t *later)
{
    const char *ids[ZCL_DEVLOOP_MAX_PLAN_GROUPS * 2];
    size_t id_count = 0;
    for (size_t i = 0; i < plan->path_groups_len; i++)
        ids[id_count++] = plan->path_groups[i];
    for (size_t i = 0; i < plan->closure_groups_len; i++)
        ids[id_count++] = plan->closure_groups[i];
    char selected[64][ZCL_TEST_GROUP_FULL_MAX];
    bool truncated = false;
    size_t count = zcl_test_group_expand_plan(
        ids, id_count, selected, 64, &truncated);
    if (count == SIZE_MAX || count == 0 || truncated)
        return false;
    full[0] = immediate[0] = deferred[0] = 0;
    *total = *now = *later = 0;
    for (size_t i = 0; i < count; i++) {
        bool integration = zcl_test_group_is_integration_only(selected[i]);
        char *tier = integration ? deferred : immediate;
        size_t full_used = strlen(full), tier_used = strlen(tier);
        int a = snprintf(full + full_used, 4096 - full_used, "%s%s",
                         full_used ? "," : "", selected[i]);
        int b = snprintf(tier + tier_used, 4096 - tier_used, "%s%s",
                         tier_used ? "," : "", selected[i]);
        if (a <= 0 || (size_t)a >= 4096 - full_used ||
            b <= 0 || (size_t)b >= 4096 - tier_used)
            return false;
        (*total)++;
        if (integration) (*later)++;
        else (*now)++;
    }
    return *now <= 32;
}

static bool dp_restart_first_receipt_ok(
    const struct zcl_devloop_restart_build_receipt *receipt)
{
    return receipt->candidate_probe_passed &&
           receipt->changed_sources == 1 &&
           !receipt->artifact_cache_hit &&
           receipt->compiler_processes == 2 &&
           receipt->linker_processes == 1 &&
           receipt->complete_graph_linker_processes == 0 &&
           receipt->probe_processes == 1 &&
           receipt->source_guard_captures == 2;
}

static bool dp_restart_first_identity_ok(
    const struct zcl_devloop_restart_build_receipt *receipt)
{
    return receipt->compile_startup_us > 0 &&
           receipt->compile_body_us > 0 &&
           receipt->link_startup_us > 0 &&
           receipt->link_body_us > 0 &&
           receipt->probe_startup_us > 0 &&
           receipt->probe_body_us > 0 &&
           strcmp(receipt->probe, "discover.help") == 0 &&
           receipt->source_identity_overlay &&
           strlen(receipt->source_cas_sha3) == 64 &&
           strlen(receipt->artifact_sha256) == 64 &&
           strlen(receipt->artifact_cache_key) == 64;
}

/* A candidate that runs the complete path floor of a closure too wide to
 * enumerate reports exactly that: group_count of groups_selected, bounded
 * deferral, no complete proof, and the executed bytes by hash and inode. */
static bool dp_partial_receipt_shaped(
    const struct zcl_devloop_restart_proof_receipt *proof)
{
    bool counted = proof->groups_selected == zcl_test_group_catalog_count() &&
        proof->group_count > 0 && proof->group_count <= 32 &&
        proof->deferred_group_count ==
            proof->groups_selected - proof->group_count &&
        proof->deferred_groups[0] == 0 &&
        proof->deferred_groups_sha256[0] == 0;
    bool floor_only = strstr(proof->groups, "test_dev_platform") &&
        !strstr(proof->groups, "test_wallet");
    bool bound = strlen(proof->artifact_sha256) == 64 &&
        proof->artifact_ino != 0;
    return counted && floor_only && bound;
}

static bool dp_restart_partial_floor_ok(const char *root,
                                        const char *const *changed,
                                        const struct zcl_devloop_plan *plan,
                                        char *why, size_t why_len)
{
    struct zcl_devloop_plan universal = *plan;
    universal.closure_universal = true;
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result process = {0};
    bool ok = zcl_devloop_restart_prove_immediate(
        root, changed, 1, &universal, &proof, &process, why, why_len);
    bool shaped = ok && proof.immediate_proof_complete &&
        !proof.proof_complete && proof.bounded_proof_deferred &&
        dp_partial_receipt_shaped(&proof);
    if (!shaped)
        fprintf(stderr, "partial floor: ok=%d bounded=%d run=%u selected=%u "
                "deferred=%u\n", ok, proof.bounded_proof_deferred,
                proof.group_count, proof.groups_selected,
                proof.deferred_group_count);
    return shaped;
}

struct dp_probe_watch {
    char marker[PATH_MAX];
    char source[PATH_MAX];
};

/* The watcher's poll: new filesystem activity arrives once the focused probe
 * is running. A supersede poll also writes the newer save first. */
static bool dp_probe_cancel_poll(void *opaque)
{
    const struct dp_probe_watch *watch = opaque;
    if (access(watch->marker, F_OK) != 0)
        return false;
    if (watch->source[0]) {
        FILE *f = fopen(watch->source, "w");
        if (f) {
            (void)fputs("int restart_fixture(void) { return 13; }\n", f);
            (void)fclose(f);
        }
    }
    return true;
}

static bool dp_pid_gone(long pid)
{
    for (int i = 0; i < 300; i++) {
        if (kill((pid_t)pid, 0) != 0 && errno == ESRCH)
            return true;
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
        (void)nanosleep(&pause, NULL);
    }
    return false;
}

/* Every process the probe started — the candidate, its hook, and the hook's
 * own background child — is gone once the cancelled probe returns. */
static bool dp_probe_left_no_children(const char *marker)
{
    FILE *f = fopen(marker, "r");
    long hook = 0, child = 0;
    bool read = f && fscanf(f, "%ld %ld", &hook, &child) == 2;
    if (f) (void)fclose(f);
    bool gone = read && hook > 1 && child > 1 && dp_pid_gone(hook) &&
        dp_pid_gone(child);
    if (!gone)
        fprintf(stderr, "probe children: read=%d hook=%ld child=%ld\n",
                read, hook, child);
    return gone;
}

static bool dp_probe_hook_write(const char *hook, const char *marker)
{
    char body[PATH_MAX * 2 + 256];
    int n = snprintf(body, sizeof(body),
                     "#!/usr/bin/env bash\n"
                     "sleep 30 &\n"
                     "printf '%%s %%s\\n' \"$$\" \"$!\" >'%s.tmp'\n"
                     "mv '%s.tmp' '%s'\n"
                     "wait\n", marker, marker, marker);
    return n > 0 && n < (int)sizeof(body) && dp_mk_write(".", hook, body) &&
        chmod(hook, 0700) == 0;
}

static bool dp_probe_setup(const char *root, bool supersede,
                           char hook[PATH_MAX], struct dp_probe_watch *watch)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(hook, PATH_MAX, "%s/test-tmp/dev_restart_probe_hook_%ld.sh",
                 cwd, (long)getpid()) >= PATH_MAX ||
        snprintf(watch->marker, sizeof(watch->marker),
                 "%s/test-tmp/dev_restart_probe_pids_%ld", cwd,
                 (long)getpid()) >= (int)sizeof(watch->marker))
        return false;
    if (supersede &&
        snprintf(watch->source, sizeof(watch->source),
                 "%s/%s/tools/dev/restart_fixture.c", cwd, root) >=
            (int)sizeof(watch->source))
        return false;
    (void)unlink(watch->marker);
    return dp_probe_hook_write(hook, watch->marker) &&
        platform_environment_set("ZCL_DEVLOOP_TEST_PROBE_HOOK", hook, 1) == 0;
}

/* Stop (or a newer save) mid-probe: the bounded probe is cancelled, never
 * reported, and reaps every descendant. */
static bool dp_restart_probe_cancel_ok(const char *root,
                                       const char *const *changed,
                                       const struct zcl_devloop_plan *plan,
                                       bool supersede, char *why,
                                       size_t why_len)
{
    char hook[PATH_MAX];
    struct dp_probe_watch watch = {0};
    if (!dp_probe_setup(root, supersede, hook, &watch))
        return false;
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result process = {0};
    zcl_devloop_process_cancel_poll_set(dp_probe_cancel_poll, &watch);
    int64_t started = platform_time_monotonic_us();
    bool ran = zcl_devloop_restart_prove_immediate(
        root, changed, 1, plan, &proof, &process, why, why_len);
    int64_t elapsed_ms = (platform_time_monotonic_us() - started) / 1000;
    zcl_devloop_process_cancel_poll_clear();
    zcl_devloop_process_cancel_clear();
    (void)dp_environment_unset("ZCL_DEVLOOP_TEST_PROBE_HOOK");
    bool ok = !ran && process.cancelled && !proof.immediate_proof_complete &&
        !proof.proof_complete && elapsed_ms < 20000 &&
        dp_probe_left_no_children(watch.marker);
    if (!ok)
        fprintf(stderr, "probe cancel: ran=%d cancelled=%d elapsed=%lldms\n",
                ran, process.cancelled, (long long)elapsed_ms);
    (void)unlink(watch.marker);
    (void)unlink(hook);
    if (ok && supersede)
        ok = dp_mk_write(root, "tools/dev/restart_fixture.c",
                         "int restart_fixture(void) { return 7; }\n");
    return ok;
}

/* A focused verdict names the bytes it ran and claims no receipt authority. */
static bool dp_focused_event_bound(const struct json_value *doc)
{
    const char *bytes = json_get_str(json_get(doc, "probe_candidate_sha256"));
    const struct json_value *authority = json_get(doc, "receipt_authority");
    return bytes && strlen(bytes) == 64 && authority &&
        !json_get_bool(authority);
}

static bool dp_restart_event_phase(const char *root, int event, int want,
                                   const char *want_phase)
{
    static char verdict[16384];
    size_t n = read_native_cycle(root, verdict, sizeof(verdict));
    struct json_value doc = {0};
    bool parsed = n > 0 && json_read(&doc, verdict, n);
    const char *phase = parsed ? json_get_str(json_get(&doc, "phase")) : NULL;
    bool focused = strncmp(want_phase, "FOCUSED_", 8) == 0;
    bool ok = event == want && phase && strcmp(phase, want_phase) == 0 &&
        !json_get_bool(json_get(&doc, "proof_complete")) &&
        !json_get_bool(json_get(&doc, "runtime_published")) &&
        (!focused || dp_focused_event_bound(&doc));
    if (!ok)
        fprintf(stderr, "restart event: event=%d phase=%s (want %d %s)\n",
                event, phase ? phase : "(none)", want, want_phase);
    json_free(&doc);
    return ok;
}

/* Through the watcher's restart entry: a clean save earns its focused
 * verdict and still hands the conservative proof to the watcher; a save that
 * lands while the probe runs leaves no verdict for the obsolete epoch. */
static bool dp_restart_event_verdicts_ok(const char *root,
                                         const char *const *changed)
{
    int event = zcl_devloop_restart_event(root, changed, 1,
                                          ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
    if (!dp_restart_event_phase(root, event,
                                ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING,
                                "FOCUSED_GREEN"))
        return false;
    char cwd[PATH_MAX], hook[PATH_MAX], body[PATH_MAX * 2 + 128];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(hook, sizeof(hook), "%s/test-tmp/dev_restart_edit_hook_%ld.sh",
                 cwd, (long)getpid()) >= (int)sizeof(hook))
        return false;
    int n = snprintf(body, sizeof(body),
                     "#!/usr/bin/env bash\n"
                     "printf 'int restart_fixture(void) { return 13; }\\n' "
                     ">'%s/%s/tools/dev/restart_fixture.c'\n", cwd, root);
    if (n <= 0 || n >= (int)sizeof(body) || !dp_mk_write(".", hook, body) ||
        chmod(hook, 0700) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_PROBE_HOOK", hook, 1) != 0)
        return false;
    event = zcl_devloop_restart_event(root, changed, 1,
                                      ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
    (void)dp_environment_unset("ZCL_DEVLOOP_TEST_PROBE_HOOK");
    (void)unlink(hook);
    zcl_devloop_process_cancel_clear();
    return dp_restart_event_phase(root, event,
                                  ZCL_DEVLOOP_RESTART_EVENT_CANCELLED,
                                  "COMPILE_GREEN") &&
        dp_mk_write(root, "tools/dev/restart_fixture.c",
                    "int restart_fixture(void) { return 7; }\n");
}

static bool dp_restart_focused_scope_ok(const char *root,
                                        const char *const *changed,
                                        const struct zcl_devloop_plan *plan,
                                        char *why, size_t why_len)
{
    return dp_restart_partial_floor_ok(root, changed, plan, why, why_len) &&
        dp_restart_probe_cancel_ok(root, changed, plan, false, why,
                                   why_len) &&
        dp_restart_probe_cancel_ok(root, changed, plan, true, why, why_len) &&
        dp_restart_event_verdicts_ok(root, changed);
}

static bool run_resident_restart_fixture(void)
{
    char root[PATH_MAX], cache_rel[PATH_MAX], compiler_rel[PATH_MAX];
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
        "  case \"$source\" in platform/modules/util/src/clientversion.c) [ \"$identity\" -eq 3 ];; esac\n"
        "  cp \"$source\" \"$out\"\n"
        "  printf '%s: tools/dev/restart_fixture.c\\n' \"$out\" >\"$dep\"\n"
        "else\n"
        "  [ -n \"$rsp\" ]\n"
        "  [ -n \"$base\" ]\n"
        "  [ \"$allow\" -eq 1 ]\n"
        "  if grep -q 'restart-test-objects' \"$rsp\"; then\n"
        "    case \"$base\" in *test-obj/fixture/restart-base.o) :;; *) exit 9;; esac\n"
        "    grep -q 'build/dev-loop/restart-test-objects/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    grep -q 'build/dev-loop/restart-test-objects/platform/modules/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/test-obj/fixture/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    ! grep -q 'build/test-obj/fixture/platform/modules/util/src/clientversion.o' \"$rsp\"\n"
        "    printf '#!/usr/bin/env bash\\nset -eu\\ngroups= cache=0 snapshot=0 changed=\\nfor arg in \"$@\"; do case \"$arg\" in --exact=*) groups=${arg#--exact=};; --cache) cache=1;; --cache-snapshot) snapshot=1;; --changed-source=*) changed=${arg#--changed-source=};; esac; done\\n[ -n \"$groups\" ]\\n[ \"$cache\" -eq 1 ]\\n[ \"$snapshot\" -eq 1 ]\\n[ \"$changed\" = tools/dev/restart_fixture.c ]\\n[ -z \"${ZCL_DEVLOOP_TEST_PROBE_HOOK:-}\" ] || \"$ZCL_DEVLOOP_TEST_PROBE_HOOK\"\\ncount=1\\nrest=$groups\\nwhile [ \"${rest#*,}\" != \"$rest\" ]; do count=$((count+1)); rest=${rest#*,}; done\\nran=$((count-1))\\nfailed=$ZCL_DEVLOOP_TEST_FAIL_GROUPS\\nprintf \"SUITE VERDICT mode=cached groups_total=921 groups_ran=%%s groups_cached=1 groups_gated=0 groups_failed=%%s self_skips=0\\\\n\" \"$ran\" \"$failed\"\\n[ \"$failed\" -eq 0 ]\\n' >\"$out\"\n"
        "  else\n"
        "    case \"$base\" in *dev-obj/fixture/restart-base.o) :;; *) exit 9;; esac\n"
        "    grep -q 'build/dev-loop/restart-objects/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    grep -q 'build/dev-loop/restart-objects/platform/modules/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/tools/dev/restart_fixture.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/platform/modules/util/src/clientversion.o' \"$rsp\"\n"
        "    ! grep -q 'build/dev-obj/fixture/platform/modules/base/src/other.o' \"$rsp\"\n"
        "    printf '#!/usr/bin/env bash\\nexit 0\\n' >\"$out\"\n"
        "  fi\n"
        "  chmod 0700 \"$out\"\n"
        "fi\n";
    bool ok = false;
    const char *stage = "fixture setup";
    char why[256] = {0};
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
    if (snprintf(root, sizeof(root), "test-tmp/dev_resident_restart_%ld",
                 (long)getpid()) >= (int)sizeof(root) ||
        snprintf(cache_rel, sizeof(cache_rel),
                 "test-tmp/dev_restart_shared_cache_%ld", (long)getpid()) >=
            (int)sizeof(cache_rel) ||
        snprintf(compiler_rel, sizeof(compiler_rel),
                 "test-tmp/dev_restart_fake_cc_%ld.sh", (long)getpid()) >=
            (int)sizeof(compiler_rel))
        return false;
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
        !dp_mk_write(root, "tests/harness/src/restart_test_only.c",
                     "int restart_test_only(void) { return 9; }\n") ||
        !dp_mk_write(root, "tools/command/native_code_command.c",
                     "int native_code_fixture(void) { return 23; }\n") ||
        !dp_mk_write(root, "platform/modules/util/src/clientversion.c",
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
        !dp_mk_write(root, "build/dev-obj/fixture/platform/modules/base/src/other.o",
                     "other-object\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/platform/modules/util/src/clientversion.o",
                     "stale-dev-identity\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/link-inputs.rsp",
                     "build/dev-obj/fixture/tools/dev/restart_fixture.o build/dev-obj/fixture/tools/dev/restart_second.o build/dev-obj/fixture/tools/command/native_code_command.o build/dev-obj/fixture/platform/modules/util/src/clientversion.o build/dev-obj/fixture/platform/modules/base/src/other.o\n") ||
        !dp_mk_write(root, "build/dev-obj/fixture/restart-base.o",
                     "frozen-dev-base\n") ||
        !dp_mk_write(root,
                     "build/test-obj/fixture/tools/dev/restart_fixture.o",
                     "old-test-object\n") ||
        !dp_mk_write(root,
                     "build/test-obj/fixture/tools/command/native_code_command.o",
                     "old-test-code-object\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/platform/modules/base/src/other.o",
                     "other-test-object\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/platform/modules/util/src/clientversion.o",
                     "stale-test-identity\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/link-inputs.rsp",
                     "build/test-obj/fixture/tools/dev/restart_fixture.o build/test-obj/fixture/tools/command/native_code_command.o build/test-obj/fixture/platform/modules/util/src/clientversion.o build/test-obj/fixture/platform/modules/base/src/other.o\n") ||
        !dp_mk_write(root, "build/test-obj/fixture/restart-base.o",
                     "frozen-test-base\n") ||
        platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", cache, 1) != 0)
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
        platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", "1", 1) != 0 ||
        platform_environment_set("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "0", 1) != 0)
        goto out;

    stage = "first candidate build";
    const char *changed[] = { "tools/dev/restart_fixture.c" };
    struct zcl_devloop_restart_build_receipt receipt = {0};
    struct zcl_devloop_process_result process = {0};
    bool first_build_ok = zcl_devloop_restart_build(
        root, changed, 1, &receipt, &process, why, sizeof(why));
    if (!first_build_ok || !dp_restart_first_receipt_ok(&receipt) ||
        !dp_restart_first_identity_ok(&receipt)) {
        fprintf(stderr, "resident first build: ok=%d probe=%d changed=%u hit=%d "
                "compile=%u link=%u full_link=%u probe_process=%u guard=%u "
                "timing=%lld/%lld/%lld/%lld/%lld/%lld probe=%s overlay=%d "
                "hashlen=%zu/%zu/%zu\n",
                first_build_ok, receipt.candidate_probe_passed,
                receipt.changed_sources, receipt.artifact_cache_hit,
                receipt.compiler_processes, receipt.linker_processes,
                receipt.complete_graph_linker_processes, receipt.probe_processes,
                receipt.source_guard_captures,
                (long long)receipt.compile_startup_us,
                (long long)receipt.compile_body_us,
                (long long)receipt.link_startup_us,
                (long long)receipt.link_body_us,
                (long long)receipt.probe_startup_us,
                (long long)receipt.probe_body_us,
                receipt.probe, receipt.source_identity_overlay,
                strlen(receipt.source_cas_sha3),
                strlen(receipt.artifact_sha256),
                strlen(receipt.artifact_cache_key));
        goto out;
    }
    stage = "first cache copy";
    char cache_artifact[PATH_MAX];
    struct stat cache_st = {0}, published_st = {0};
    int cache_n = snprintf(cache_artifact, sizeof(cache_artifact),
                           "%s/restart-v1/%s.bin", cache,
                           receipt.artifact_cache_key);
    if (cache_n <= 0 || cache_n >= (int)sizeof(cache_artifact) ||
        stat(cache_artifact, &cache_st) != 0 ||
        stat(receipt.artifact_path, &published_st) != 0 ||
        (cache_st.st_dev == published_st.st_dev &&
         cache_st.st_ino == published_st.st_ino)) {
        fprintf(stderr, "resident cache copy: artifact=%s cache=%s errno=%d "
                "cache_ino=%llu published_ino=%llu\n",
                receipt.artifact_path, cache_artifact, errno,
                (unsigned long long)cache_st.st_ino,
                (unsigned long long)published_st.st_ino);
        goto out;
    }

    /* A test edit following a resident service publication carries both TUs
     * into the proof epoch. The runtime candidate compiles and links only the
     * service TU; the exact test candidate later compiles and links both with
     * TEST_CFLAGS, including APIs that exist only under ZCL_TESTING. */
    stage = "runtime and test changed";
    const char *runtime_and_test_changed[] = {
        "tools/dev/restart_fixture.c",
        "tests/harness/src/restart_test_only.c",
    };
    memset(&receipt, 0, sizeof(receipt));
    memset(&process, 0, sizeof(process));
    bool mixed_build_ok = zcl_devloop_restart_build(
        root, runtime_and_test_changed, 2, &receipt, &process, why, sizeof(why));
    if (!mixed_build_ok ||
        !receipt.candidate_probe_passed || receipt.changed_sources != 2 ||
        receipt.compiler_processes != 2 || !receipt.artifact_cache_hit ||
        receipt.linker_processes != 0 || receipt.probe_processes != 1) {
        fprintf(stderr, "resident mixed build: ok=%d probe=%d changed=%u "
                "compile=%u hit=%d link=%u probe_process=%u\n",
                mixed_build_ok, receipt.candidate_probe_passed,
                receipt.changed_sources, receipt.compiler_processes,
                receipt.artifact_cache_hit, receipt.linker_processes,
                receipt.probe_processes);
        goto out;
    }
    if (dp_environment_unset("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY") != 0)
        goto out;
    char first_build_key[65], first_build_hash[65];
    (void)snprintf(first_build_key, sizeof(first_build_key), "%s",
                   receipt.artifact_cache_key);
    (void)snprintf(first_build_hash, sizeof(first_build_hash), "%s",
                   receipt.artifact_sha256);

    stage = "complete resident proof";
    struct zcl_devloop_plan proof_plan = {0};
    if (!zcl_devloop_plan_files(changed, 1, &proof_plan))
        goto out;
    for (size_t d = 0; d < ZCL_DEVLOOP_DIM__COUNT; d++)
        proof_plan.dims[d].status = ZCL_DEVLOOP_DIM_NOT_APPLICABLE;
    char expected_all[4096], expected_now[4096], expected_later[4096];
    uint32_t expected_total = 0, expected_immediate = 0, expected_deferred = 0;
    if (!dp_expected_proof_groups(&proof_plan, expected_all, expected_now,
                                  expected_later, &expected_total,
                                  &expected_immediate, &expected_deferred))
        goto out;
    struct zcl_devloop_restart_proof_receipt proof = {0};
    if (!zcl_devloop_restart_prove(root, changed, 1, &proof_plan, &proof,
                                   &process, why, sizeof(why)) ||
        !proof.proof_complete || !proof.immediate_proof_complete ||
        proof.integration_proof_deferred || proof.deferred_group_count != 0 ||
        proof.group_count != expected_total ||
        strcmp(proof.groups, expected_all) != 0 ||
        proof.groups_ran + proof.groups_cached != expected_total ||
        proof.groups_cached != 1 ||
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
    stage = "born red proof";
    if (platform_environment_set("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "2", 1) != 0)
        goto out;
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (zcl_devloop_restart_prove(root, changed, 1, &proof_plan, &proof,
                                  &process, why, sizeof(why)) ||
        strcmp(why, "failure-first direct owner invariant failed") != 0 ||
        proof.groups_failed != 2 ||
        proof.immediate_proof_complete || proof.proof_complete)
        goto out;
    if (platform_environment_set("ZCL_DEVLOOP_TEST_FAIL_GROUPS", "0", 1) != 0)
        goto out;

    /* The next edit for the same task executes the remembered RED before
     * default/catalog order. Passing it clears the warm scheduling hint; it
     * never substitutes for the complete affected batch that follows. */
    stage = "remembered red proof";
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
    stage = "code capsule overlay proof";
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

    stage = "immediate proof";
    memset(&proof, 0, sizeof(proof));
    memset(&process, 0, sizeof(process));
    if (!zcl_devloop_restart_prove_immediate(
            root, changed, 1, &proof_plan, &proof, &process,
            why, sizeof(why)) ||
        proof.proof_complete || !proof.immediate_proof_complete ||
        !proof.integration_proof_deferred ||
        proof.group_count != expected_immediate ||
        proof.deferred_group_count != expected_deferred ||
        strcmp(proof.groups, expected_now) != 0 ||
        strcmp(proof.deferred_groups, expected_later) != 0 ||
        proof.groups_ran + proof.groups_cached != expected_immediate ||
        proof.groups_cached != 1 ||
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
    stage = "exact edit revert build";
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

    stage = "focused scope, stop and supersede";
    why[0] = 0;
    ok = dp_restart_focused_scope_ok(root, changed, &proof_plan, why,
                                     sizeof(why));

out:
    if (!ok)
        fprintf(stderr, "resident restart fixture failed at %s: %s\n",
                stage, why[0] ? why : "no build reason");
    (void)dp_environment_unset("ZCL_DEVLOOP_TEST_FAIL_GROUPS");
    if (had_cache)
        (void)platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", saved_cache, 1);
    else
        (void)dp_environment_unset("ZCL_DEV_ARTIFACT_CACHE");
    if (had_process)
        (void)platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved_process, 1);
    else
        (void)dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS");
    if (had_force_copy)
        (void)platform_environment_set("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY", saved_force_copy, 1);
    else
        (void)dp_environment_unset("ZCL_DEVLOOP_TEST_FORCE_CACHE_COPY");
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

#if defined(__APPLE__)
static bool run_darwin_attested_descriptor_fixture(void)
{
    const char *saved = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved_copy = saved ? strdup(saved) : NULL;
    if (saved && !saved_copy)
        return false;

    char unresolved[PATH_MAX], executable[PATH_MAX];
    uint32_t unresolved_len = sizeof(unresolved);
    bool ok = _NSGetExecutablePath(unresolved, &unresolved_len) == 0 &&
              realpath(unresolved, executable) != NULL;
    int fd = ok ? open(executable, O_RDONLY | O_CLOEXEC) : -1;
    if (fd < 0)
        ok = false;
    if (ok && platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1)
                  != 0)
        ok = false;

    struct zcl_devloop_process_result result = {0};
    const char *argv[] = { executable, "--source-record", NULL };
    if (ok) {
        ok = zcl_devloop_process_run_fd(".", fd, argv, 30000, &result) &&
             result.exit_code == 0 && result.term_signal == 0 &&
             !result.timed_out && !result.cancelled &&
             result.output_len >= 131 && result.startup_us > 0;
        char source_id[65] = {0}, mutation_id[65] = {0}, extra = 0;
        int complete = 0;
        if (ok)
            ok = sscanf(result.output, "%64[0-9a-f] %d %64[0-9a-f] %c",
                        source_id, &complete, mutation_id, &extra) == 3 &&
                 strlen(source_id) == 64 && strlen(mutation_id) == 64 &&
                 complete == 1;
    }

    if (fd >= 0)
        close(fd);
    if (saved_copy) {
        if (platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved_copy,
                                     1) != 0)
            ok = false;
        free(saved_copy);
    } else if (dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS") != 0) {
        ok = false;
    }
    return ok;
}

static int test_darwin_attested_descriptor_process(void)
{
    int failures = 0;
    TEST("dev platform: Darwin executes the open Mach-O only after kernel CodeDirectory attestation") {
        ASSERT(run_darwin_attested_descriptor_fixture());
        PASS();
    } _test_next:;
    return failures;
}
#endif

static int test_resident_process_cancellation(void)
{
    int failures = 0;
    TEST("dev platform: resident cancellation promptly stops an active child group") {
        const char *saved = getenv("ZCL_DEVLOOP_TEST_PROCESS");
        char *saved_copy = saved ? strdup(saved) : NULL;
        ASSERT(!saved || saved_copy);
        ASSERT(platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);

        const char *argv[] = { "sleep", "30", NULL };
        struct zcl_devloop_process_result result = {0};
        zcl_devloop_process_cancel_request();
        int64_t started = platform_time_monotonic_us();
        ASSERT(zcl_devloop_process_run(".", argv, 60000, &result));
        int64_t elapsed_us = platform_time_monotonic_us() - started;
        ASSERT(result.cancelled);
        ASSERT(!result.timed_out);
        ASSERT(result.term_signal == SIGTERM);
        /* Cancel must land promptly; the 1 s ceiling scales with measured
         * host load so a loaded lane does not flake the verdict. */
        struct test_budget cancel_budget =
            test_budget_scale(UINT64_C(1000000));
        printf("  dev platform: cancel-latency elapsed_us=%lld "
               "nominal_us=%llu effective_us=%llu load_factor=%.2f "
               "calib_us=%llu\n",
               (long long)elapsed_us,
               (unsigned long long)cancel_budget.nominal_us,
               (unsigned long long)cancel_budget.effective_us,
               cancel_budget.factor,
               (unsigned long long)cancel_budget.calib_med_us);
        ASSERT(elapsed_us >= 0 &&
               (uint64_t)elapsed_us < cancel_budget.effective_us);
        zcl_devloop_process_cancel_clear();

        if (saved_copy) {
            ASSERT(platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved_copy, 1) == 0);
            free(saved_copy);
        } else {
            ASSERT(dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS") == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_exact_commit_preempts_edit_proof(void)
{
    int failures = 0;
    TEST("dev platform: runnable exact commit retires edit proof without cancelling commit or dirty feedback") {
        ASSERT(zcl_devloop_watch_commit_preemption_selftest());
        PASS();
    } _test_next:;
    return failures;
}

/* The forked edit worker yields to a runnable exact commit proof; the
 * synchronous cycle that holds the reactor did not, so a queued landing
 * proof waited behind work the commit had already subsumed. */
static int test_foreground_cycle_yields_to_commit(void)
{
    int failures = 0;
    char base[PATH_MAX] = {0}, repo[PATH_MAX] = {0};
    const char *current = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = current ? strdup(current) : NULL;
    TEST("dev platform: a runnable exact commit cancels the obsolete foreground cycle, rate limited, dirty feedback kept") {
        ASSERT(!current || saved);
        test_make_tmpdir(base, sizeof(base), "dev_platform", "fg_yield");
        int n = snprintf(repo, sizeof(repo), "%s/repo", base);
        ASSERT(n > 0 && (size_t)n < sizeof(repo));
        ASSERT(mkdir(repo, 0700) == 0);
        /* The predicate under test runs real git in the fixture repository,
         * and bounded process execution is refused under ZCL_TESTING unless
         * the isolated fixture opts in. */
        ASSERT(platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1",
                                        1) == 0);
        ASSERT(zcl_devloop_watch_foreground_yield_selftest(repo));
        PASS();
    } _test_next:;
    if (saved) {
        (void)platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved, 1);
        free(saved);
    } else {
        (void)dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS");
    }
    if (base[0])
        test_rm_rf_recursive(base);
    return failures;
}

static int test_watcher_stream_backpressure(void)
{
    int failures = 0;
    char home[PATH_MAX] = {0}, repo[PATH_MAX] = {0};
    const char *current_home = getenv("HOME");
    char *saved_home = current_home ? strdup(current_home) : NULL;
    TEST("dev platform: full watcher event queue flushes exact epochs and remains live") {
        ASSERT(!current_home || saved_home);
        test_make_tmpdir(home, sizeof(home), "dev_platform", "watch_stream");
        int n = snprintf(repo, sizeof(repo), "%s/repo", home);
        ASSERT(n > 0 && (size_t)n < sizeof(repo));
        ASSERT(mkdir(repo, 0700) == 0);
        ASSERT(platform_environment_set("HOME", home, 1) == 0);
        ASSERT(zcl_devloop_watch_stream_backpressure_selftest(repo));
        PASS();
    } _test_next:;
    if (saved_home) {
        (void)platform_environment_set("HOME", saved_home, 1);
        free(saved_home);
    } else {
        (void)dp_environment_unset("HOME");
    }
    if (home[0])
        test_rm_rf_recursive(home);
    return failures;
}

static int test_watch_idle_exit(void)
{
    int failures = 0;
    TEST("dev platform: idle watcher exits; source/pending/landing reset or refuse idle-exit") {
        ASSERT(ZCL_DEVLOOP_WATCH_IDLE_BUDGET_MS == (60 * 60 * 1000));
        ASSERT(zcl_devloop_watch_idle_exit_selftest());

        char fixture[PATH_MAX];
        char land_wt[PATH_MAX];
        char other[PATH_MAX];
        int n = snprintf(fixture, sizeof(fixture),
                         "test-tmp/devloop_land_pred_%ld", (long)getpid());
        ASSERT(n > 0 && (size_t)n < sizeof(fixture));
        n = snprintf(land_wt, sizeof(land_wt), "%s/land/wt", fixture);
        ASSERT(n > 0 && (size_t)n < sizeof(land_wt));
        n = snprintf(other, sizeof(other), "%s/other", fixture);
        ASSERT(n > 0 && (size_t)n < sizeof(other));
        ASSERT(dp_mk_write(fixture, "land/queue.lock", "land\n"));
        ASSERT(dp_mk_write(land_wt, ".keep", "wt\n"));
        ASSERT(dp_mk_write(other, ".keep", "not land\n"));
        ASSERT(zcl_devloop_watch_root_is_landing(land_wt));
        ASSERT(!zcl_devloop_watch_root_is_landing(other));
        ASSERT(!zcl_devloop_watch_root_is_landing(NULL));
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
        ASSERT(platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);

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
            if (os_proc_pid_liveness((uint64_t)nested_pid) ==
                OS_PROC_LIVENESS_DEAD) {
                gone = true;
                break;
            }
            (void)nanosleep(&retry_delay, NULL); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
        }
        ASSERT(gone);
        ASSERT(unlink(pid_path) == 0);
        if (saved_copy) {
            ASSERT(platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", saved_copy, 1) == 0);
            free(saved_copy);
        } else {
            ASSERT(dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS") == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_source_cas_shadow(void)
{
    int failures = 0;
    TEST("dev platform: native source CAS is incremental and remains shadow authority") {
        char fixture[PATH_MAX];
        ASSERT(snprintf(fixture, sizeof(fixture),
                        "test-tmp/dev_source_cas_shadow_%ld",
                        (long)getpid()) < (int)sizeof(fixture));
        ASSERT(test_rm_rf_recursive(fixture) == 0 || errno == ENOENT);
        ASSERT(dp_mk_write(fixture, "core/modules/net/src/source_cas_a.c",
                           "int source_cas_a(void) { return 1; }\n"));
        ASSERT(dp_mk_write(fixture, "core/modules/net/include/net/source_cas_a.h",
                           "int source_cas_a(void);\n"));
        ASSERT(dp_settle(fixture, "core/modules/net/src/source_cas_a.c", 1));
        ASSERT(dp_settle(fixture, "core/modules/net/include/net/source_cas_a.h", 2));

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

        ASSERT(dp_mk_write(fixture, "core/modules/net/src/source_cas_a.c",
                           "int source_cas_a(void) { return 2; }\n"));
        ASSERT(dp_settle(fixture, "core/modules/net/src/source_cas_a.c", 3));
        ASSERT(zcl_dev_source_cas_capture(fixture, &edited));
        ASSERT(edited.cas_present);
        ASSERT(edited.cas_files_read == 1);
        ASSERT(edited.cas_bytes_total == 61);
        ASSERT(edited.cas_bytes_read == 37);
        ASSERT(strcmp(first.cas_root_sha3, edited.cas_root_sha3) != 0);
        ASSERT(strcmp(first.source_id, edited.source_id) != 0);
        ASSERT(strcmp(first.mutation_id, edited.mutation_id) != 0);

        /* A generation materialized onto tmpfs writes every file inside one
         * coarse timestamp tick, so an edit made in that same tick moves no
         * field of the stat key. Such a leaf is racily clean and must be
         * re-read: pinned here with an mtime that is not older than any
         * capture instant, so no field of the key moves between the two
         * captures below and only the rule can explain the read. */
        char racy_path[PATH_MAX];
        ASSERT(snprintf(racy_path, sizeof(racy_path), "%s/%s", fixture,
                        "core/modules/net/src/source_cas_a.c") > 0);
        struct timespec ahead[2];
        ahead[0].tv_sec = ahead[1].tv_sec = (time_t)4102444800L; /* 2100 */
        ahead[0].tv_nsec = ahead[1].tv_nsec = 0;
        ASSERT(utimensat(AT_FDCWD, racy_path, ahead, 0) == 0);
        struct dev_source_record armed = {0}, racy = {0};
        ASSERT(zcl_dev_source_cas_capture(fixture, &armed));
        ASSERT(armed.cas_files_read == 1);
        ASSERT(zcl_dev_source_cas_capture(fixture, &racy));
        ASSERT(racy.cas_files_read == 1);
        ASSERT(racy.cas_nodes_hashed == 0);
        ASSERT(strcmp(edited.cas_root_sha3, racy.cas_root_sha3) == 0);

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
        ASSERT(test_rm_rf_recursive(fixture) == 0 || errno == ENOENT);
        PASS();
    } _test_next:;
    return failures;
}

static int test_source_identity_failure_tokens(void)
{
    int failures = 0;
    TEST("dev platform: source-identity failures classify to a specific "
         "evidence token and only load-shaped ones retry") {
        struct zcl_devloop_process_result result;
        char why[160];

        memset(&result, 0, sizeof(result));
        result.timed_out = true;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_timeout") == 0);
        ASSERT(zcl_dev_source_identity_failure_retryable(why));

        memset(&result, 0, sizeof(result));
        result.term_signal = 9;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_signal_9") == 0);
        ASSERT(zcl_dev_source_identity_failure_retryable(why));

        memset(&result, 0, sizeof(result));
        result.exit_code = 7;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_exit_7") == 0);
        ASSERT(!zcl_dev_source_identity_failure_retryable(why));

        /* 126 is the runner's OWN pre-exec setup-failure convention
         * (zcl_devloop_process_run's forked child: setsid, ready-pipe
         * write, chdir, dup2 -- see ZCL_DEVLOOP_PROCESS_EXIT_SETUP_FAILED),
         * never the capture command's exit code. A transient failure there
         * under load is load-shaped, so it must classify distinctly from an
         * ordinary nonzero exit and must be retryable. */
        memset(&result, 0, sizeof(result));
        result.exit_code = ZCL_DEVLOOP_PROCESS_EXIT_SETUP_FAILED;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_runner_setup_failed") == 0);
        ASSERT(zcl_dev_source_identity_failure_retryable(why));

        /* 127 stays "exec failed" -- a real execvp failure naming a missing
         * or unrunnable tool, which is a deterministic defect a retry
         * cannot fix. */
        memset(&result, 0, sizeof(result));
        result.exit_code = 127;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_exit_127") == 0);
        ASSERT(!zcl_dev_source_identity_failure_retryable(why));

        memset(&result, 0, sizeof(result));
        result.output_truncated = true;
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_output_truncated") == 0);
        ASSERT(zcl_dev_source_identity_failure_retryable(why));

        /* A clean process (no timeout/signal/exit/truncation) never reaches
         * this classifier in practice -- parse_source_record only calls it
         * when process_ok() failed or output was truncated -- but the
         * fallback token must still be the pre-existing undifferentiated one
         * and must never be treated as retryable. */
        memset(&result, 0, sizeof(result));
        ASSERT(zcl_dev_source_identity_classify_failure(&result, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_command_failed") == 0);
        ASSERT(!zcl_dev_source_identity_failure_retryable(why));

        ASSERT(zcl_dev_source_identity_classify_failure(NULL, why,
                                                         sizeof(why)));
        ASSERT(strcmp(why, "source_identity_command_failed") == 0);
        ASSERT(!zcl_dev_source_identity_failure_retryable(why));

        /* A content-level defect is a deterministic tool/output bug, not a
         * load symptom, so it must not be retried either. */
        ASSERT(!zcl_dev_source_identity_failure_retryable(
            "source_identity_output_invalid"));
        ASSERT(!zcl_dev_source_identity_failure_retryable(NULL));
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
        /* A path-floor run of a wider selection is never FOCUSED_GREEN. */
        ASSERT(strcmp(zcl_devloop_progress_phase(
                          "focused_partial", "path_floor_affected_proofs"),
                      "FOCUSED_PARTIAL") == 0);
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
            .affected_component = "engine/services/src/example.c",
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
            .source_tu = "contexts/commons/modules/vcs/src/source_package_checkout.c",
            .candidate_object_root = object_root,
            .story_id = "source-package-checkout-result-and-shard-shape.v1",
            .story_root =
                "8a4c2158401fba3e82b7b7caf2da54f2725447087d11275774c1a5ef58a29616",
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
        capsule.source_tu = "tools/command/native_dev_input_policy.c";
        capsule.story_id = "native-dev-input-and-interrupt-policy.v1";
        capsule.story_root =
                "6d10e6a34b181a3bb44f5e02217e673bf6ad7704fb9c43fb43b5eba01d8e0e1d";
        capsule.story_fixture_root =
            "84a5a5c9cda8f565a1cc4ac6b8d7c24ad1cbf33e67a540cf929a271028a821a3";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        /* The command and watcher shells the pure policy cores moved out of
         * are static authority shells (hotswap_shadow_owners.def), not
         * capsule members: an edit there is an exact shell compile check,
         * never a story over bytes the capsule does not compile. */
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            "tools/command/native_dev_command.c", object_root, &capsule));
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            "tools/dev/devloop_watch.c", object_root, &capsule));

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
        capsule.source_tu = "contexts/commons/modules/vcs/src/vcs_devloop.c";
        capsule.story_id = "vcs-devloop-publication-envelope.v1";
        capsule.story_root =
                "e548f8dea0408988a446c63990b195d75be96d96afd97bb077018ec9e07391ea";
        capsule.story_fixture_root =
            "83ecbf1fe6983cd9d56c53e329743547d431339106902a12885de59a1ef128c8";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));

        capsule.owner_id = "app.native-read-rpc-composition.v1";
        capsule.source_tu = "engine/controllers/src/app_native_handlers.c";
        capsule.story_id = "app-native-read-rpc-composition.v1";
        capsule.story_root =
                "baaf8a04f005d85c3581dcd215fa7f57b42a87dede3546888485bc1a5e631f1e";
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
        capsule.source_tu = "contexts/commons/modules/vcs/src/source_package_transport.c";
        capsule.story_id = "source-package-transport-shape.v1";
        capsule.story_root =
                "be59478a97d7a36ca97a1c772b274b236970c6512b955ff9e49d35797f35d42a";
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

        /* A capsule may own a SET of translation units: an owner TU plus the
         * `sibling_tus` named beside it in engine/composition/hotfork_capsules.def,
         * all of which the builder #includes into the capsule. The kernel
         * command-input capsule is the case that needs it — the validation
         * chain's per-key type table, length/budget rules and dev.agent arms
         * each live in their own TU now. An edit to ANY TU in the set must
         * select this capsule: a sibling the capsule does not claim is never
         * compiled into it, so its rules resolve from the RESIDENT binary
         * through RTLD_LAZY and a mutation there cannot turn the story red.
         * Descriptor identity stays the OWNER TU however the set was
         * entered, so one capsule keeps one name in every receipt. The
         * owner is the validator's own small TU: the dispatcher shell
         * command_registry.c is outside the set, so the capsule never pays
         * for compiling it. */
        capsule.owner_id = "kernel.command-input-validation-core.v1";
        capsule.source_tu =
            "engine/modules/kernel/src/command_registry_input_validate.c";
        capsule.story_id = "command-registry-input-validation-core.v1";
        capsule.story_root =
            "c051a5f54e69eb61d541f624bba84ca1d0d9310c68a65e097423c3f89703dfb8";
        capsule.story_fixture_root =
            "dcc2e025037440812fed20b2b0834a0e48b48c30f1df38fa0ac4d941d92c4b2b";
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            capsule.source_tu, object_root, &capsule));
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            "engine/modules/kernel/src/command_registry_input_types.c",
            object_root, &capsule));
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            "engine/modules/kernel/src/command_registry_input_budget.c",
            object_root, &capsule));
        ASSERT(zcl_devloop_hotfork_descriptor_validate(
            "engine/modules/kernel/src/command_registry_devagent_input.c",
            object_root, &capsule));
        /* A kernel TU outside the set is claimed by no capsule at all —
         * including the dispatcher shell the validator moved out of. */
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            "engine/modules/kernel/src/command_registry_search.c",
            object_root, &capsule));
        ASSERT(!zcl_devloop_hotfork_descriptor_validate(
            "engine/modules/kernel/src/command_registry.c",
            object_root, &capsule));
        PASS();
    } _test_next:;
    return failures;
}

/* HOT_FORK story adapters are real C files (tools/dev/hotfork_stories/),
 * rendered into the capsule unity after the owner TU set. This drives one
 * real owner through the whole reflex path in an isolated fixture root:
 * the real owner bytes and the real story file, compiled with a real
 * compiler, forked and dlopen'ed. The unchanged owner must reach
 * STORY_GREEN, a compile-valid behavioral mutation STORY_RED, and the
 * artifact cache key must move with the owner or story bytes and with
 * nothing else. */
static const char k_dp_hf_root[] = "test-tmp/dev_hotfork_story";
static const char k_dp_hf_cache[] = "test-tmp/dev_hotfork_story_cache";
static const char k_dp_hf_owner[] =
    "contexts/commons/modules/vcs/src/package_policy.c";
static const char k_dp_hf_story[] =
    "tools/dev/hotfork_stories/package_policy_boundary_calculation_v1.inc";
static const char k_dp_hf_rule[] = "publishes_this_week >= ";

struct dp_hf_seen {
    int event;
    char phase[32];
    char key[65];
    char detail[96];
};

static bool dp_hf_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(buf, 1, cap - 1, f);
    bool whole = !ferror(f) && feof(f);
    fclose(f);
    buf[n] = 0;
    return whole && n > 0;
}

static bool dp_hf_fixture_init(const char *cwd, const char *owner,
                               const char *story)
{
    char flags[PATH_MAX * 4];
    int n = snprintf(
        flags, sizeof(flags),
        "CC=cc\nCXX=g++\n"
        "COMPILER_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "DEV_CFLAGS=-DZCL_DEV_BUILD -std=c23 -Wall -Wextra -Werror -pedantic"
        " -I%s/engine/modules/hotswap/include"
        " -I%s/contexts/commons/modules/vcs/include"
        " -I%s/platform/modules/base/include\n"
        "HOTSWAP_MODULE_LDFLAGS=-shared -nostartfiles -Wl,-Bsymbolic\n",
        cwd, cwd, cwd);
    static const char *const defs[] = {
        "engine/composition/hotswap_swappable.def",
        "engine/composition/hotswap_islands.def",
        "engine/composition/hotswap_services.def",
        "engine/composition/hotswap_shadow_owners.def",
        "engine/composition/hotfork_capsules.def",
    };
    bool ok = n > 0 && n < (int)sizeof(flags) &&
        dp_mk_write(k_dp_hf_root, "Makefile", "# fixture\n");
    for (size_t i = 0; ok && i < sizeof(defs) / sizeof(defs[0]); i++)
        ok = dp_mk_write(k_dp_hf_root, defs[i], "/* fixture */\n");
    /* The action plan is written last so it is never older than its inputs. */
    return ok && dp_mk_write(k_dp_hf_root, k_dp_hf_owner, owner) &&
           dp_mk_write(k_dp_hf_root, k_dp_hf_story, story) &&
           dp_mk_write(k_dp_hf_root, "build/hotswap-fast/flags.env", flags);
}

static void dp_hf_copy(char *out, size_t cap, const char *value)
{
    (void)snprintf(out, cap, "%s", value ? value : "");
}

/* One save of the owner through the HOT_FORK path; `seen` gets the event
 * code plus the published verdict's phase, cache key and story detail. */
static bool dp_hf_drive(struct dp_hf_seen *seen)
{
    static char verdict[16384];
    static unsigned save_seq;
    const char *paths[] = { k_dp_hf_owner };
    char epoch[65];
    memset(seen, 0, sizeof(*seen));
    /* The watcher binds every save to a 64-hex edit epoch before the batch
     * event; STORY_GREEN's proof handoff refuses an unbound save. */
    snprintf(epoch, sizeof(epoch), "%064x", ++save_seq);
    if (!zcl_devloop_event_edit_epoch_set(epoch))
        return false;
    seen->event = zcl_devloop_hotfork_batch_event(
        k_dp_hf_root, paths, 1, ZCL_DEVLOOP_PUBLISH_VERIFY_ONLY);
    (void)zcl_devloop_event_edit_epoch_set("");
    size_t n = read_native_cycle(k_dp_hf_root, verdict, sizeof(verdict));
    struct json_value doc = {0};
    if (n == 0 || !json_read(&doc, verdict, n)) {
        fprintf(stderr, "hotfork story drive: event=%d published no verdict "
                "(%zu bytes)\n", seen->event, n);
        return false;
    }
    dp_hf_copy(seen->phase, sizeof(seen->phase),
               json_get_str(json_get(&doc, "phase")));
    dp_hf_copy(seen->key, sizeof(seen->key),
               json_get_str(json_get(json_get(&doc, "build_receipt"),
                                     "artifact_cache_key")));
    dp_hf_copy(seen->detail, sizeof(seen->detail),
               json_get_str(json_get(&doc, "story_detail")));
    json_free(&doc);
    return strlen(seen->key) == 64;
}

static bool dp_hf_expect(const char *stage, const struct dp_hf_seen *seen,
                         const char *phase, const char *detail)
{
    int want_event = strcmp(phase, "STORY_GREEN") == 0
        ? ZCL_DEVLOOP_RESTART_EVENT_PROOF_PENDING
        : ZCL_DEVLOOP_RESTART_EVENT_FINAL;
    bool ok = seen->event == want_event && strcmp(seen->phase, phase) == 0 &&
        strstr(seen->detail, detail) != NULL;
    if (!ok)
        fprintf(stderr, "hotfork story stage %s: event=%d phase=%s detail=%s "
                "(want %s %s)\n", stage, seen->event, seen->phase,
                seen->detail, phase, detail);
    return ok;
}

/* Green, unchanged re-save, owner mutation, owner restore. */
static bool dp_hf_owner_cycle(const char *owner, char *mutated,
                              struct dp_hf_seen *green)
{
    struct dp_hf_seen seen;
    if (!dp_hf_drive(green) ||
        !dp_hf_expect("green", green, "STORY_GREEN", "checks=15/15") ||
        !dp_hf_drive(&seen) ||
        !dp_hf_expect("unchanged", &seen, "STORY_GREEN", "checks=15/15") ||
        strcmp(seen.key, green->key) != 0)
        return false;
    /* `>=` becomes `>`: still compiles, but a new user may now publish a
     * second time in one week, which the story refuses. */
    char *rule = strstr(mutated, k_dp_hf_rule);
    if (!rule)
        return false;
    memmove(rule + sizeof(k_dp_hf_rule) - 3, rule + sizeof(k_dp_hf_rule) - 2,
            strlen(rule + sizeof(k_dp_hf_rule) - 2) + 1);
    if (!dp_mk_write(k_dp_hf_root, k_dp_hf_owner, mutated) ||
        !dp_hf_drive(&seen) ||
        !dp_hf_expect("mutated", &seen, "STORY_RED", "checks=14/15") ||
        strcmp(seen.key, green->key) == 0 ||
        !dp_mk_write(k_dp_hf_root, k_dp_hf_owner, owner) ||
        !dp_hf_drive(&seen) ||
        !dp_hf_expect("restored", &seen, "STORY_GREEN", "checks=15/15"))
        return false;
    return strcmp(seen.key, green->key) == 0;
}

/* A comment-only story edit is new story bytes: new key, same verdict. */
static bool dp_hf_story_cycle(const char *story, char *edited,
                              const struct dp_hf_seen *green)
{
    struct dp_hf_seen seen;
    size_t n = strlen(story);
    if (snprintf(edited, n + 64, "%s/* story comment edit */\n", story) <= 0 ||
        !dp_mk_write(k_dp_hf_root, k_dp_hf_story, edited) ||
        !dp_hf_drive(&seen) ||
        !dp_hf_expect("story-edit", &seen, "STORY_GREEN", "checks=15/15") ||
        strcmp(seen.key, green->key) == 0 ||
        !dp_mk_write(k_dp_hf_root, k_dp_hf_story, story) ||
        !dp_hf_drive(&seen))
        return false;
    return strcmp(seen.key, green->key) == 0;
}

/* The fixture's cache and workspace state (under $HOME) stay in test-tmp;
 * the prior HOME is restored afterwards. The cycle stream is reset from
 * epoch 0 because no watcher owns this fixture root. */
static bool dp_hf_env(const char *cwd, bool set)
{
    static char saved_home[PATH_MAX];
    if (!set)
        return dp_environment_unset("ZCL_DEV_ARTIFACT_CACHE") == 0 &&
               dp_environment_unset("ZCL_DEVLOOP_TEST_PROCESS") == 0 &&
               (saved_home[0]
                    ? platform_environment_set("HOME", saved_home, 1) == 0
                    : dp_environment_unset("HOME") == 0);
    const char *home = getenv("HOME");
    char cache[PATH_MAX], state_home[PATH_MAX], why[160] = {0};
    dp_hf_copy(saved_home, sizeof(saved_home), home);
    bool ok = snprintf(cache, sizeof(cache), "%s/%s", cwd, k_dp_hf_cache) <
                  (int)sizeof(cache) &&
        snprintf(state_home, sizeof(state_home), "%s/%s/home", cwd,
                 k_dp_hf_cache) < (int)sizeof(state_home) &&
        platform_environment_set("ZCL_DEV_ARTIFACT_CACHE", cache, 1) == 0 &&
        platform_environment_set("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0 &&
        platform_environment_set("HOME", state_home, 1) == 0;
    return ok && zcl_devloop_cycle_stream_reset(k_dp_hf_root, 0, why,
                                                sizeof(why));
}

static int test_hotfork_story_file_green_and_red(void)
{
    int failures = 0;
    TEST("dev platform: HOT_FORK story file drives STORY_GREEN, a behavioral mutation STORY_RED, and the cache key") {
        static char owner[16384], mutated[16384], story[16384], edited[16448];
        char cwd[PATH_MAX];
        struct dp_hf_seen green;
        ASSERT(getcwd(cwd, sizeof(cwd)) != NULL);
        ASSERT(!getenv("ZCL_DEV_ARTIFACT_CACHE") &&
               !getenv("ZCL_DEVLOOP_TEST_PROCESS"));
        ASSERT(dp_hf_slurp(k_dp_hf_owner, owner, sizeof(owner)));
        ASSERT(dp_hf_slurp(k_dp_hf_story, story, sizeof(story)));
        memcpy(mutated, owner, sizeof(owner));
        test_rm_rf_recursive(k_dp_hf_root);
        test_rm_rf_recursive(k_dp_hf_cache);
        ASSERT(dp_hf_fixture_init(cwd, owner, story));
        ASSERT(dp_hf_env(cwd, true));
        bool owner_ok = dp_hf_owner_cycle(owner, mutated, &green);
        bool story_ok = owner_ok && dp_hf_story_cycle(story, edited, &green);
        ASSERT(dp_hf_env(cwd, false));
        test_rm_rf_recursive(k_dp_hf_root);
        test_rm_rf_recursive(k_dp_hf_cache);
        ASSERT(owner_ok);
        ASSERT(story_ok);
        PASS();
    } _test_next:;
    return failures;
}

static int test_template_generator_concurrency(void)
{
    int failures = 0;
    TEST("dev platform: concurrent template generators preserve source identity") {
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            execlp("make", "make", "-s", "templates-no-touch-selftest",
                   (char *)NULL);
            _exit(127);
        }
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The lint gates keep their scan scopes honest by planting short-lived source
 * files inside the production tree, and the suite runs those groups next to
 * every other group in the same checkout. A whole-tree source-identity capture
 * takes seconds, so before this contract existed a fixture that appeared or
 * vanished during one made `make` refuse to select a compile epoch — every
 * concurrent build in the worktree died having run nothing.
 *
 * The Makefile already declines to compile these paths (a "/_" component is
 * never a translation unit), so binding them into the build identity bought
 * nothing. Prove both halves at once: an ephemeral fixture stays visible to
 * Git, which is what the gates grep, while leaving the source identity of the
 * tree byte-identical. Exercise it in a disposable Git worktree so its
 * directory churn cannot overlap a frozen proof generation. */
#define DP_EPHEMERAL_FIXTURE_REL \
    "engine/services/src/_dev_platform_source_identity_fixture_tmp.c"

/* The native source-identity-batch token passes must emit byte-identical
 * preimages to the portable shell oracle. This is the exactness contract
 * behind the parse-time speedup: the identity, mutation, and inventory
 * digests cannot move when the helper takes over, and shadow mode must
 * agree on a tree that also carries a live untracked file and a symlink. */
/* The build-epoch integrity gate must pass from a COLD cache on any host:
 * this regression pins the driver-discovery repair after a host whose plain
 * `cc` lacked cc1plus (and whose `gcc` rejected -std=c23) failed every cold
 * probe run behind a warm-cache mask. The test forces a private empty cache
 * directory, so the wrapper's cached verdict path is unreachable and the
 * compiler probes run for real every time. */
static int test_cold_epoch_integrity_gate(void)
{
    int failures = 0;
    TEST("dev platform: build-epoch integrity passes from a cold cache") {
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            execlp("bash", "bash", "-c",
                   "set -eu\n"
                   "origin=\"$(pwd -P)\"\n"
                   "scratch=\"$(mktemp -d "
                   "${TMPDIR:-/tmp}/zcl-cold-epoch.XXXXXX)\"\n"
                   "cleanup() {\n"
                   "  cd \"$origin\"\n"
                   "  rm -rf \"$scratch\"\n"
                   "}\n"
                   "trap cleanup EXIT HUP INT TERM\n"
                   "ZCL_BUILD_EPOCH_CACHE_DIR=\"$scratch/cache\" \\\n"
                   "  tools/dev/build-epoch-integrity-cached.sh \\\n"
                   "  >\"$scratch/out.log\" 2>&1\n"
                   "grep -Fq 'build-epoch-selftest: PASS' \"$scratch/out.log\"\n"
                   "grep -Fq 'make-depfile-scope-selftest: PASS' "
                   "\"$scratch/out.log\"\n",
                   (char *)NULL);
            _exit(127);
        }
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_identity_tokens_match_oracle(void)
{
    int failures = 0;
    TEST("dev platform: native identity tokens match the portable oracle") {
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            execlp("bash", "bash", "-c",
                   "set -eu\n"
                   "origin=\"$(pwd -P)\"\n"
                   "scratch=\"$(mktemp -d "
                   "${TMPDIR:-/tmp}/zcl-identity-native.XXXXXX)\"\n"
                   "tree=\"$scratch/tree\"\n"
                   "cleanup() {\n"
                   "  cd \"$origin\"\n"
                   "  git worktree remove --force \"$tree\" "
                   ">/dev/null 2>&1 || :\n"
                   "  rm -rf \"$scratch\"\n"
                   "}\n"
                   "trap cleanup EXIT HUP INT TERM\n"
                   "git worktree add --detach \"$tree\" HEAD >/dev/null\n"
                   "cd \"$tree\"\n"
                   "printf 'int zcl_native_oracle_probe(void) { return 7; }\\n' "
                   "> engine/services/src/native_oracle_probe_tmp.c\n"
                   "ln -s Makefile native_oracle_link_tmp\n"
                   "native=\"$(tools/dev/source-identity.sh capture-record)\"\n"
                   "portable=\"$(ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 "
                   "tools/dev/source-identity.sh capture-record)\"\n"
                   "[ \"$native\" = \"$portable\" ] || {\n"
                   "  echo \"native and portable capture records differ:\" "
                   "\"$native\" vs \"$portable\" >&2\n"
                   "  exit 1\n"
                   "}\n"
                   "ZCL_SOURCE_IDENTITY_BATCH_SHADOW=1 "
                   "tools/dev/source-identity.sh capture-record >/dev/null\n",
                   (char *)NULL);
            _exit(127);
        }
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_ephemeral_fixture_leaves_source_identity(void)
{
    int failures = 0;
    TEST("dev platform: ephemeral lint fixtures do not move source identity") {
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            execlp("bash", "bash", "-c",
                   "set -eu\n"
                   "fixture=" DP_EPHEMERAL_FIXTURE_REL "\n"
                   "origin=\"$(pwd -P)\"\n"
                   "scratch=\"$(mktemp -d "
                   "${TMPDIR:-/tmp}/zcl-identity-fixture.XXXXXX)\"\n"
                   "tree=\"$scratch/tree\"\n"
                   "cleanup() {\n"
                   "  rm -f \"$tree/$fixture\"\n"
                   "  cd \"$origin\"\n"
                   "  git worktree remove --force \"$tree\" "
                   ">/dev/null 2>&1 || :\n"
                   "  rm -rf \"$scratch\"\n"
                   "}\n"
                   "trap cleanup EXIT HUP INT TERM\n"
                   "git worktree add --detach \"$tree\" HEAD >/dev/null\n"
                   "cd \"$tree\"\n"
                   "rm -f \"$fixture\"\n"
                   "before=\"$(tools/dev/source-identity.sh capture-record)\"\n"
                   "printf 'void zcl_ephemeral_fixture(void) { }\\n' "
                   "> \"$fixture\"\n"
                   "listing=\"$(git ls-files --others --exclude-standard -- "
                   "engine/services/src)\"\n"
                   "case \"$listing\" in\n"
                   "  *\"$fixture\"*) ;;\n"
                   "  *) echo 'fixture is hidden from Git; the lint gates that"
                   " grep --untracked would stop seeing their own fixtures'"
                   " >&2; exit 1 ;;\n"
                   "esac\n"
                   "during=\"$(tools/dev/source-identity.sh capture-record)\"\n"
                   "read -r before_id before_clean before_mutation "
                   "<<< \"$before\"\n"
                   "read -r during_id during_clean during_mutation "
                   "<<< \"$during\"\n"
                   "[ \"$before_id\" = \"$during_id\" ] && "
                   "[ \"$before_clean\" = \"$during_clean\" ] || {\n"
                   "  echo 'an ephemeral lint fixture changed the source"
                   " identity; every concurrent make in this checkout would"
                   " refuse to select a compile epoch' >&2\n"
                   "  exit 1\n"
                   "}\n"
                   "tools/dev/source-identity.sh verify-mutation "
                   "\"$before_mutation\" >/dev/null\n"
                   "rm -f \"$fixture\"\n"
                   "after=\"$(tools/dev/source-identity.sh capture-record)\"\n"
                   "read -r after_id after_clean after_mutation "
                   "<<< \"$after\"\n"
                   "[ \"$before_id\" = \"$after_id\" ] && "
                   "[ \"$before_clean\" = \"$after_clean\" ] || {\n"
                   "  echo 'removing an ephemeral lint fixture changed the"
                   " source identity' >&2\n"
                   "  exit 1\n"
                   "}\n"
                   "[ \"$before_mutation\" = \"$during_mutation\" ] && "
                   "[ \"$during_mutation\" = \"$after_mutation\" ] || {\n"
                   "  echo 'an ephemeral lint fixture entered the source"
                   " mutation epoch' >&2\n"
                   "  exit 1\n"
                   "}\n"
                   "tools/dev/source-identity.sh verify-mutation "
                   "\"$before_mutation\" >/dev/null\n",
                   (char *)NULL);
            _exit(127);
        }
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(WIFEXITED(status));
        ASSERT(WEXITSTATUS(status) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Resident watcher session: identity and a stop that leaves nothing ──
 *
 * A stand-in with the resident watcher's process shape: a setsid() session
 * leader holding the checkout's singleton lock, plus one proof worker child
 * that closes the lock and takes `linger_ms` to honour SIGTERM. On SIGTERM
 * (a stop) or SIGUSR1 (an idle exit or loop error) the leader does what
 * devloop_watch.c does on the way out: signal the worker, release the lock,
 * then join the worker. It is double-forked so init reaps it, as it reaps
 * the real daemonized watcher. Like the launcher's child it works from the
 * checkout root, and it runs this test binary's image, so only launch
 * identity — never the executable's name — can vouch for it. */
struct dp_fake_watch {
    pid_t watcher;
    pid_t worker;
};

[[noreturn]] static void dp_fake_worker(int linger_ms)
{
    sigset_t term;
    int sig = 0;
    sigemptyset(&term);
    sigaddset(&term, SIGTERM);
    (void)sigwait(&term, &sig);
    platform_sleep_ms(linger_ms);
    _exit(0);
}

[[noreturn]] static void dp_fake_watcher(const char *root, int linger_ms,
                                         int report_fd)
{
    char lock[PATH_MAX];
    sigset_t stop;
    int sig = 0;
    (void)setsid();
    if (chdir(root) != 0)
        _exit(2);
    sigemptyset(&stop);
    sigaddset(&stop, SIGTERM);
    sigaddset(&stop, SIGUSR1);
    (void)sigprocmask(SIG_BLOCK, &stop, NULL);
    int fd = zcl_devloop_watch_lock_path(root, lock, sizeof(lock))
        ? open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 || ftruncate(fd, 0) != 0 ||
        dprintf(fd, "%ld verify ready proofq1\n", (long)getpid()) <= 0)
        _exit(2);
    pid_t worker = fork();
    if (worker == 0) {
        (void)close(fd);
        (void)close(report_fd);
        dp_fake_worker(linger_ms);
    }
    pid_t pids[2] = {getpid(), worker};
    if (worker < 0 || write(report_fd, pids, sizeof(pids)) != sizeof(pids))
        _exit(3);
    (void)close(report_fd);
    (void)sigwait(&stop, &sig);
    (void)kill(worker, SIGTERM);
    (void)close(fd);
    (void)waitpid(worker, NULL, 0);
    _exit(0);
}

/* Start one stand-in and record it exactly as the launcher records the
 * watcher it forks. */
static bool dp_fake_watch_start(const char *root, int linger_ms,
                                struct dp_fake_watch *out)
{
    int report[2];
    memset(out, 0, sizeof(*out));
    if (pipe(report) != 0)
        return false;
    pid_t middle = fork();
    if (middle == 0) {
        (void)close(report[0]);
        if (fork() == 0)
            dp_fake_watcher(root, linger_ms, report[1]);
        _exit(0);
    }
    (void)close(report[1]);
    pid_t pids[2] = {0, 0};
    struct pollfd ready = {.fd = report[0], .events = POLLIN};
    bool ok = middle > 0 && waitpid(middle, NULL, 0) == middle &&
              poll(&ready, 1, 5000) == 1 &&
              read(report[0], pids, sizeof(pids)) == sizeof(pids) &&
              pids[0] > 1 && pids[1] > 1;
    (void)close(report[0]);
    if (!ok)
        return false;
    out->watcher = pids[0];
    out->worker = pids[1];
    return zcl_devloop_watch_session_record(root, (int64_t)out->watcher);
}

/* Failure-path hygiene: never let a stand-in outlive its case. */
static void dp_fake_watch_reap(const struct dp_fake_watch *fake)
{
    if (fake->watcher <= 1)
        return;
    (void)zcl_devloop_process_session_members(fake->watcher, SIGKILL);
    for (int i = 0; i < 200 &&
         zcl_devloop_process_session_members(fake->watcher, 0) > 0; i++)
        platform_sleep_ms(10);
}

/* A killed worker whose parent died with it waits as a zombie for its new
 * reaper; it is not running. */
static bool dp_pid_running(pid_t pid)
{
    if (kill(pid, 0) != 0)
        return false;
#if defined(__linux__)
    char path[64], stat[256] = {0};
    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t got = read(fd, stat, sizeof(stat) - 1);
    (void)close(fd);
    const char *close_paren = got > 0 ? strrchr(stat, ')') : NULL;
    return !close_paren || close_paren[1] != ' ' || close_paren[2] != 'Z';
#else
    return true;
#endif
}

/* A canonical checkout-shaped root: .cache for the lock and records, and a
 * Makefile so the launcher accepts it. */
static bool dp_watch_session_root(char root[PATH_MAX], const char *leaf)
{
    const char *base = getenv("TMPDIR");
    char made[PATH_MAX], cache[PATH_MAX], makefile[PATH_MAX];
    int n = snprintf(made, sizeof(made), "%s/%s.XXXXXX",
                     base && base[0] ? base : ".", leaf);
    if (n <= 0 || n >= (int)sizeof(made) || !mkdtemp(made) ||
        !realpath(made, root))
        return false;
    n = snprintf(cache, sizeof(cache), "%s/.cache", root);
    int m = snprintf(makefile, sizeof(makefile), "%s/Makefile", root);
    if (n <= 0 || n >= (int)sizeof(cache) || m <= 0 ||
        m >= (int)sizeof(makefile) || mkdir(cache, 0700) != 0)
        return false;
    int fd = open(makefile, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    return fd >= 0 && close(fd) == 0;
}

/* Block until the lock at `root` is free (the group watchdog bounds a
 * wedge); the holder has then let go or died. */
static bool dp_wait_lock_free(const char *root)
{
    char lock[PATH_MAX];
    if (!zcl_devloop_watch_lock_path(root, lock, sizeof(lock)))
        return false;
    int fd = open(lock, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool released = flock(fd, LOCK_EX) == 0;
    (void)close(fd);
    return released;
}

static bool dp_pipe_cloexec(int fds[2])
{
    return pipe(fds) == 0 && fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0 &&
           fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0;
}

/* A foreign process for identity checks: a setsid() leader running another
 * program from the checkout root (so only its image can tell it apart).
 * With `hold_fd` >= 0 (close-on-exec in the caller) it runs
 * `sh -c 'sleep 60 & read x'` on that stdin, keeping the session alive after
 * the leader exits on EOF; otherwise `sleep 60`. Returns once the program
 * has replaced the forked image. */
static pid_t dp_foreign_session(const char *root, int hold_fd)
{
    int exec_seen[2];
    if (!dp_pipe_cloexec(exec_seen))
        return -1;
    pid_t child = fork();
    if (child == 0) {
        (void)close(exec_seen[0]);
        (void)setsid();
        if (chdir(root) != 0)
            _exit(126);
        if (hold_fd >= 0) {
            if (dup2(hold_fd, STDIN_FILENO) < 0)
                _exit(126);
            execl("/bin/sh", "sh", "-c", "sleep 60 & read x", (char *)NULL);
        } else {
            execl("/bin/sleep", "sleep", "60", (char *)NULL);
        }
        _exit(127);
    }
    (void)close(exec_seen[1]);
    char byte;
    while (child > 0 && read(exec_seen[0], &byte, 1) < 0 && errno == EINTR)
        ;
    (void)close(exec_seen[0]);
    return child;
}

/* Rewrite the birth token (third field) of the record for `pid`: what a
 * record looks like once its pid has been recycled. */
static bool dp_record_corrupt_token(const char *root, pid_t pid)
{
    char path[PATH_MAX], body[256] = {0}, schema[64];
    long long recorded = 0;
    unsigned long long token = 0;
    int used = 0;
    int n = snprintf(path, sizeof(path), "%s/%s/%ld", root,
                     ZCL_DEVLOOP_WATCH_SESSION_DIR_REL, (long)pid);
    int fd = n > 0 && n < (int)sizeof(path)
        ? open(path, O_RDONLY | O_CLOEXEC) : -1;
    if (fd < 0)
        return false;
    ssize_t got = read(fd, body, sizeof(body) - 1);
    (void)close(fd);
    if (got <= 0 || sscanf(body, "%63s %lld %llu%n", schema, &recorded,
                           &token, &used) != 3)
        return false;
    char rewritten[256];
    n = snprintf(rewritten, sizeof(rewritten), "%s %lld %llu%s", schema,
                 recorded, token + 1, body + used);
    fd = n > 0 && n < (int)sizeof(rewritten)
        ? open(path, O_WRONLY | O_TRUNC | O_CLOEXEC) : -1;
    if (fd < 0)
        return false;
    bool ok = write(fd, rewritten, (size_t)n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}

static int64_t dp_lock_text_pid(const char *root)
{
    char lock[PATH_MAX], body[64] = {0};
    if (!zcl_devloop_watch_lock_path(root, lock, sizeof(lock)))
        return 0;
    int fd = open(lock, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    ssize_t got = read(fd, body, sizeof(body) - 1);
    (void)close(fd);
    return got > 0 ? strtoll(body, NULL, 10) : 0;
}

static int test_watch_session_stop_leaves_nothing(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: the session library never signals a running leader and prunes a session that left nothing") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-stop"));
        ASSERT(dp_fake_watch_start(root, 1500, &fake));
        ASSERT_EQ(dp_lock_text_pid(root), (int64_t)fake.watcher);
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_LIVE);
        uint64_t born = 0;
        ASSERT(os_proc_pid_start_token((uint64_t)fake.watcher, &born));
        struct zcl_devloop_watch_stop stop = {.expect_born = born,
                                              .budget_ms = 8000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_LEADER_RUNNING);
        ASSERT_EQ(stop.escalation, 0);
        ASSERT(dp_pid_running(fake.watcher));
        /* It leaves as its stop endpoint would make it: the worker is
         * joined, so nothing of the session is left to retire. */
        ASSERT(kill(fake.watcher, SIGTERM) == 0);
        for (int i = 0; i < 400 &&
             zcl_devloop_process_session_members(fake.watcher, 0) > 0; i++)
            platform_sleep_ms(10);
        ASSERT_EQ(zcl_devloop_process_session_members(fake.watcher, 0),
                  (size_t)0);
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_GONE);
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        PASS();
    } _test_next:;
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_watch_session_orphaned_worker_stopped(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: the session library retires a killed watcher's surviving proof worker by its recorded birth") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-orphan"));
        ASSERT(dp_fake_watch_start(root, 30000, &fake));
        uint64_t born = 0;
        ASSERT(os_proc_pid_start_token((uint64_t)fake.watcher, &born));
        /* OOM or a harness cleanup: the leader dies, its lock with it, and
         * the proof worker keeps running for another 30 s. */
        ASSERT(kill(fake.watcher, SIGKILL) == 0);
        ASSERT(dp_wait_lock_free(root));
        ASSERT(dp_pid_running(fake.worker));
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_ORPHANED);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0),
                  (int64_t)fake.watcher);
        struct zcl_devloop_watch_orphan rows[4];
        ASSERT_EQ(zcl_devloop_watch_session_orphans(root, rows, 4), (size_t)1);
        ASSERT_EQ(rows[0].pid, (int64_t)fake.watcher);
        ASSERT_EQ(rows[0].born, born);
        struct zcl_devloop_watch_stop stop = {.expect_born = born,
                                              .budget_ms = 1000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOPPED);
        ASSERT(stop.escalation >= 1);
        ASSERT_EQ(zcl_devloop_process_session_members(fake.watcher, 0),
                  (size_t)0);
        ASSERT(!dp_pid_running(fake.worker));
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)0);
        PASS();
    } _test_next:;
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_watch_session_retired_owner_stops(void)
{
    int failures = 0;
    struct dp_fake_watch old = {0}, owner = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: a watcher that gave up the lock is refused while it runs, retired by its birth once orphaned, and the current owner is never touched") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-retired"));
        ASSERT(dp_fake_watch_start(root, 30000, &old));
        uint64_t born = 0;
        ASSERT(os_proc_pid_start_token((uint64_t)old.watcher, &born));
        /* It leaves its loop (idle exit, stream error): lock released, the
         * proof worker still running for another 30 s. */
        ASSERT(kill(old.watcher, SIGUSR1) == 0);
        ASSERT(dp_wait_lock_free(root));
        /* A launcher must not start beside it: that was the duplicate. */
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0),
                  (int64_t)old.watcher);
        /* Another watcher (the hook's `dev proof ensure`) takes the lock. */
        ASSERT(dp_fake_watch_start(root, 100, &owner));
        ASSERT_EQ(dp_lock_text_pid(root), (int64_t)owner.watcher);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, owner.watcher),
                  (int64_t)old.watcher);
        /* Its leader still runs: the library refuses it untouched. */
        struct zcl_devloop_watch_stop stop = {.expect_born = born,
                                              .budget_ms = 1000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, old.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_LEADER_RUNNING);
        ASSERT(dp_pid_running(old.worker));
        /* Once its leader is gone, its birth retires what is left, not the
         * current owner, without waiting out the worker's 30 s. */
        ASSERT(kill(old.watcher, SIGKILL) == 0);
        for (int i = 0; i < 200 && dp_pid_running(old.watcher); i++)
            platform_sleep_ms(10);
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, old.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOPPED);
        ASSERT(stop.escalation >= 1);
        ASSERT_EQ(zcl_devloop_process_session_members(old.watcher, 0),
                  (size_t)0);
        ASSERT(!dp_pid_running(old.worker));
        ASSERT(kill(owner.watcher, 0) == 0);
        ASSERT(kill(owner.worker, 0) == 0);
        ASSERT_EQ(dp_lock_text_pid(root), (int64_t)owner.watcher);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, owner.watcher),
                  (int64_t)0);
        PASS();
    } _test_next:;
    dp_fake_watch_reap(&old);
    dp_fake_watch_reap(&owner);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_watch_session_refuses_unproven_pid(void)
{
    int failures = 0;
    struct dp_fake_watch owner = {0};
    char root[PATH_MAX] = {0};
    pid_t bystander = -1, foreign = -1;
    TEST("dev platform: stop never signals a process launch identity does not name") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-refuse"));
        ASSERT(dp_fake_watch_start(root, 100, &owner));
        bystander = fork();
        if (bystander == 0) {
            (void)setsid();
            for (;;)
                pause();
        }
        ASSERT(bystander > 1);
        struct zcl_devloop_watch_stop stop = {
            .expect_born = 1,
            .budget_ms = 1000};
        /* An unrecorded live process: no record names it. */
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, bystander, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING);
        /* A record whose birth token is not this process's birth: a
         * recycled pid. It proves nothing, and it is pruned. */
        (void)zcl_devloop_watch_session_record(root, bystander);
        ASSERT(dp_record_corrupt_token(root, bystander));
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, bystander),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, bystander, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING);
        /* A forged record for a foreign same-user session leader (a shell,
         * a node, a multiplexer) working in the checkout: its birth token is
         * public, its image is not a dev watcher's. */
        foreign = dp_foreign_session(root, -1);
        ASSERT(foreign > 1);
        (void)zcl_devloop_watch_session_record(root, foreign);
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, foreign),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, owner.watcher),
                  (int64_t)0);
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, foreign, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING);
        ASSERT(dp_pid_running(foreign));
        /* The lock owner itself runs: never signalled through here. */
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, owner.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_LEADER_RUNNING);
        ASSERT(kill(bystander, 0) == 0);
        ASSERT(kill(owner.watcher, 0) == 0);
        ASSERT(kill(owner.worker, 0) == 0);
        PASS();
    } _test_next:;
    if (bystander > 1) {
        (void)kill(bystander, SIGKILL);
        (void)waitpid(bystander, NULL, 0);
    }
    if (foreign > 1) {
        (void)kill(foreign, SIGKILL);
        (void)waitpid(foreign, NULL, 0);
    }
    dp_fake_watch_reap(&owner);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_watch_session_foreign_orphan_never_signalled(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    pid_t leader = -1;
    int hold[2] = {-1, -1};
    TEST("dev platform: a stale record over an unrelated orphaned session is pruned, never signalled") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-foreign"));
        ASSERT(dp_pipe_cloexec(hold));
        leader = dp_foreign_session(root, hold[0]);
        ASSERT(leader > 1);
        (void)close(hold[0]);
        hold[0] = -1;
        /* Recorded while alive (a recycled pid, or a forged record), then
         * the leader exits and leaves its background job in the session. */
        (void)zcl_devloop_watch_session_record(root, leader);
        (void)close(hold[1]);
        hold[1] = -1;
        ASSERT(waitpid(leader, NULL, 0) == leader);
        ASSERT(zcl_devloop_process_session_members(leader, 0) >= (size_t)1);
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, leader),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)0);
        struct zcl_devloop_watch_stop stop = {.budget_ms = 1000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, leader, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING);
        ASSERT(zcl_devloop_process_session_members(leader, 0) >= (size_t)1);
        PASS();
    } _test_next:;
    for (int i = 0; i < 2; i++)
        if (hold[i] >= 0)
            (void)close(hold[i]);
    if (leader > 1) {
        (void)zcl_devloop_process_session_members(leader, SIGKILL);
        (void)waitpid(leader, NULL, WNOHANG);
    }
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* The stand-in plus a helper member that, when told to, runs the stop from
 * inside the watcher's own session and reports the result. */
struct dp_inside_stop {
    int result;
    int escalation;
};

[[noreturn]] static void dp_fake_watcher_with_helper(const char *root,
                                                     int cmd_fd, int ready_fd,
                                                     int report_fd)
{
    char lock[PATH_MAX];
    sigset_t stop;
    int sig = 0;
    (void)setsid();
    if (chdir(root) != 0)
        _exit(2);
    sigemptyset(&stop);
    sigaddset(&stop, SIGTERM);
    (void)sigprocmask(SIG_BLOCK, &stop, NULL);
    int fd = zcl_devloop_watch_lock_path(root, lock, sizeof(lock))
        ? open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600) : -1;
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0 || ftruncate(fd, 0) != 0 ||
        dprintf(fd, "%ld verify ready proofq1\n", (long)getpid()) <= 0)
        _exit(2);
    pid_t leader = getpid();
    pid_t helper = fork();
    if (helper == 0) {
        char go = 0;
        uint64_t born = 0;
        (void)close(fd);
        (void)close(ready_fd);
        if (!os_proc_pid_start_token((uint64_t)leader, &born) ||
            read(cmd_fd, &go, 1) != 1)
            _exit(3);
        struct zcl_devloop_watch_stop io = {.expect_born = born,
                                            .budget_ms = 5000};
        struct dp_inside_stop out = {0};
        out.result = (int)zcl_devloop_watch_session_stop(root, leader, &io);
        out.escalation = io.escalation;
        _exit(write(report_fd, &out, sizeof(out)) == sizeof(out) ? 0 : 4);
    }
    pid_t pids[2] = {leader, helper};
    (void)close(cmd_fd);
    (void)close(report_fd);
    if (helper < 0 || write(ready_fd, pids, sizeof(pids)) != sizeof(pids))
        _exit(3);
    (void)close(ready_fd);
    (void)sigwait(&stop, &sig);
    (void)close(fd);
    _exit(0);
}

static int test_watch_session_stop_from_own_session(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    pid_t pids[2] = {0, 0};
    int cmd[2] = {-1, -1}, ready[2] = {-1, -1}, report[2] = {-1, -1};
    TEST("dev platform: a stop run inside a leaderless watcher session never signals its own session") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-inside"));
        ASSERT(pipe(cmd) == 0 && pipe(ready) == 0 && pipe(report) == 0);
        pid_t middle = fork();
        if (middle == 0) {
            (void)close(cmd[1]);
            (void)close(ready[0]);
            (void)close(report[0]);
            if (fork() == 0)
                dp_fake_watcher_with_helper(root, cmd[0], ready[1], report[1]);
            _exit(0);
        }
        ASSERT(middle > 0 && waitpid(middle, NULL, 0) == middle);
        (void)close(cmd[0]);
        (void)close(ready[1]);
        (void)close(report[1]);
        cmd[0] = ready[1] = report[1] = -1;
        struct pollfd wait_ready = {.fd = ready[0], .events = POLLIN};
        ASSERT(poll(&wait_ready, 1, 5000) == 1);
        ASSERT(read(ready[0], pids, sizeof(pids)) == sizeof(pids));
        ASSERT(pids[0] > 1 && pids[1] > 1);
        ASSERT(zcl_devloop_watch_session_record(root, pids[0]));
        /* The leader dies; the helper, still in its session, runs the stop. */
        ASSERT(kill(pids[0], SIGKILL) == 0);
        ASSERT(dp_wait_lock_free(root));
        char go = 1;
        ASSERT(write(cmd[1], &go, 1) == 1);
        struct dp_inside_stop out = {0};
        struct pollfd wait_report = {.fd = report[0], .events = POLLIN};
        ASSERT(poll(&wait_report, 1, 20000) == 1);
        /* The helper lived to report: its own session was refused. */
        ASSERT(read(report[0], &out, sizeof(out)) == sizeof(out));
        ASSERT_EQ(out.result, (int)ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH);
        ASSERT_EQ(out.escalation, 0);
        PASS();
    } _test_next:;
    int *fds[] = {cmd, ready, report};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
        for (int j = 0; j < 2; j++)
            if (fds[i][j] >= 0)
                (void)close(fds[i][j]);
    if (pids[0] > 1) {
        (void)zcl_devloop_process_session_members(pids[0], SIGKILL);
        for (int i = 0; i < 200 &&
             zcl_devloop_process_session_members(pids[0], 0) > 0; i++)
            platform_sleep_ms(10);
    }
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* The launcher's `owner_active`: a watcher holds this checkout's lock. */
static bool dp_lock_is_held(const char *root)
{
    char lock[PATH_MAX];
    if (!root ||
        !zcl_devloop_watch_lock_path(root, lock, sizeof(lock)))
        return false;
    int fd = open(lock, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return false;
    bool held = flock(fd, LOCK_EX | LOCK_NB) != 0;
    (void)close(fd);
    return held;
}

static int test_watch_session_admit_attach_refuse(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0}, brief = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: a launcher attaches to the live watcher and never starts beside a retiring one") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-admit"));
        ASSERT(dp_fake_watch_start(root, 30000, &fake));
        /* The owner holds the lock: attach at once. */
        ASSERT_EQ(zcl_devloop_watch_session_admit(root, dp_lock_is_held, 5000),
                  (int64_t)0);
        /* It leaves its loop; its proof worker runs on for 30 s. The
         * launcher waits out its budget and names it instead of forking. */
        ASSERT(kill(fake.watcher, SIGUSR1) == 0);
        ASSERT(dp_wait_lock_free(root));
        ASSERT_EQ(zcl_devloop_watch_session_admit(root, dp_lock_is_held, 200),
                  (int64_t)fake.watcher);
        ASSERT(!dp_lock_is_held(root));
        dp_fake_watch_reap(&fake);
        ASSERT_EQ(zcl_devloop_process_session_members(fake.watcher, 0),
                  (size_t)0);
        /* One that finishes inside the wait admits the launcher. */
        ASSERT(dp_fake_watch_start(root, 300, &brief));
        ASSERT(kill(brief.watcher, SIGUSR1) == 0);
        ASSERT(dp_wait_lock_free(root));
        ASSERT_EQ(zcl_devloop_watch_session_admit(root, dp_lock_is_held, 10000),
                  (int64_t)0);
        ASSERT_EQ(zcl_devloop_process_session_members(brief.watcher, 0),
                  (size_t)0);
        PASS();
    } _test_next:;
    dp_fake_watch_reap(&fake);
    dp_fake_watch_reap(&brief);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static bool dp_record_path(const char *root, pid_t pid, char path[PATH_MAX])
{
    int n = snprintf(path, PATH_MAX, "%s/%s/%ld", root,
                     ZCL_DEVLOOP_WATCH_SESSION_DIR_REL, (long)pid);
    return n > 0 && n < PATH_MAX;
}

static bool dp_path_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

/* The leader of dp_leaderless_session: forks `members` idle members that
 * work from `member_cwd`, reports its pid and the last member's, and exits
 * when `go_fd` reaches EOF. */
[[noreturn]] static void dp_leaderless_leader(const char *root, int members,
                                              const char *member_cwd,
                                              int report_fd, int go_fd)
{
    (void)setsid();
    if (chdir(root) != 0)
        _exit(2);
    pid_t last = -1;
    for (int i = 0; i < members; i++) {
        last = fork();
        if (last == 0) {
            if (chdir(member_cwd) != 0)
                _exit(2);
            for (;;)
                pause();
        }
        if (last < 0)
            _exit(3);
    }
    pid_t pids[2] = {getpid(), last};
    char byte;
    if (write(report_fd, pids, sizeof(pids)) != sizeof(pids))
        _exit(3);
    ssize_t got = read(go_fd, &byte, 1);
    _exit(got < 0 ? 4 : 0);
}

/* A recorded session whose leader has exited and left `members` processes
 * of this image, each working from `member_cwd`. Returns the leader's pid
 * (reaped) and one member's pid in `member`. */
static pid_t dp_leaderless_session(const char *root, int members,
                                   const char *member_cwd, pid_t *member)
{
    int report[2], go[2];
    *member = -1;
    if (!dp_pipe_cloexec(report))
        return -1;
    if (!dp_pipe_cloexec(go)) {
        (void)close(report[0]);
        (void)close(report[1]);
        return -1;
    }
    pid_t leader = fork();
    if (leader == 0) {
        (void)close(report[0]);
        (void)close(go[1]);
        dp_leaderless_leader(root, members, member_cwd, report[1], go[0]);
    }
    (void)close(report[1]);
    (void)close(go[0]);
    pid_t pids[2] = {0, 0};
    struct pollfd ready = {.fd = report[0], .events = POLLIN};
    bool ok = leader > 1 && poll(&ready, 1, 10000) == 1 &&
              read(report[0], pids, sizeof(pids)) == sizeof(pids) &&
              pids[1] > 1 && zcl_devloop_watch_session_record(root, leader);
    (void)close(report[0]);
    (void)close(go[1]); /* EOF: the leader exits */
    if (leader > 1)
        (void)waitpid(leader, NULL, 0);
    *member = pids[1];
    return ok ? leader : -leader;
}

/* A trusted record the running processes can neither prove nor disprove is
 * kept, never signalled, and holds the launcher back. */
static int dp_assert_unproven_kept(const char *root, pid_t leader,
                                   pid_t member)
{
    int failures = 0;
    char path[PATH_MAX];
    {
        ASSERT(dp_record_path(root, leader, path));
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, leader),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_UNPROVEN);
        ASSERT(dp_path_exists(path));
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)leader);
        ASSERT(dp_path_exists(path));
        ASSERT_EQ(zcl_devloop_watch_session_admit(root, dp_lock_is_held, 200),
                  (int64_t)leader);
        struct zcl_devloop_watch_stop stop = {.budget_ms = 1000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, leader, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_UNPROVEN);
        ASSERT(dp_path_exists(path));
        ASSERT(dp_pid_running(member));
    } _test_next:;
    return failures;
}

static void dp_session_kill(pid_t leader)
{
    if (leader <= 1)
        return;
    (void)zcl_devloop_process_session_members(leader, SIGKILL);
    for (int i = 0; i < 400 &&
         zcl_devloop_process_session_members(leader, 0) > 0; i++)
        platform_sleep_ms(10);
}

static int test_watch_session_unproven_record_kept(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    pid_t strayed = -1, crowd = -1, member = -1;
    TEST("dev platform: a session that cannot be proven right now is kept, not forgotten") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-unproven"));
        /* The only survivor runs the recorded dev image but not from the
         * root (the rooted member already exited): not proven, not
         * disproven. */
        strayed = dp_leaderless_session(root, 1, "/", &member);
        ASSERT(strayed > 1);
        ASSERT_EQ(dp_assert_unproven_kept(root, strayed, member), 0);
        dp_session_kill(strayed);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)0);
        strayed = -1;
        /* More members than one sweep can list: the unlisted ones are
         * unproven. */
        crowd = dp_leaderless_session(root, 65, root, &member);
        ASSERT(crowd > 1);
        ASSERT_EQ(dp_assert_unproven_kept(root, crowd, member), 0);
        dp_session_kill(crowd);
        ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)0);
        crowd = -1;
        PASS();
    } _test_next:;
    dp_session_kill(strayed < 0 ? -strayed : strayed);
    dp_session_kill(crowd < 0 ? -crowd : crowd);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

enum dp_tamper {
    DP_TAMPER_FILE_MODE,
    DP_TAMPER_DIR_MODE,
    DP_TAMPER_HARDLINK,
    DP_TAMPER_SYMLINK,
    DP_TAMPER_BOOT,
    DP_TAMPER_COUNT,
};

/* Rewrite the boot id (fourth field) of a record: one written in another
 * boot. */
static bool dp_record_other_boot(const char *path)
{
    char body[256] = {0}, schema[64], boot[64], rest[128];
    long long recorded = 0;
    unsigned long long token = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t got = fd >= 0 ? read(fd, body, sizeof(body) - 1) : -1;
    if (fd >= 0)
        (void)close(fd);
    if (got <= 0 || sscanf(body, "%63s %lld %llu %63s %127[^\n]", schema,
                           &recorded, &token, boot, rest) != 5)
        return false;
    boot[0] = boot[0] == '0' ? '1' : '0';
    char rewritten[256];
    int n = snprintf(rewritten, sizeof(rewritten), "%s %lld %llu %s %s\n",
                     schema, recorded, token, boot, rest);
    fd = n > 0 && n < (int)sizeof(rewritten)
        ? open(path, O_WRONLY | O_TRUNC | O_CLOEXEC) : -1;
    if (fd < 0)
        return false;
    bool ok = write(fd, rewritten, (size_t)n) == (ssize_t)n;
    return close(fd) == 0 && ok;
}

static bool dp_tamper_record(const char *root, const char *path,
                             enum dp_tamper how, char aside[PATH_MAX])
{
    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/%s", root,
                     ZCL_DEVLOOP_WATCH_SESSION_DIR_REL);
    int m = snprintf(aside, PATH_MAX, "%s/record.aside", root);
    if (n <= 0 || n >= (int)sizeof(dir) || m <= 0 || m >= PATH_MAX)
        return false;
    switch (how) {
    case DP_TAMPER_FILE_MODE:
        return chmod(path, 0620) == 0;
    case DP_TAMPER_DIR_MODE:
        return chmod(dir, 0770) == 0;
    case DP_TAMPER_HARDLINK:
        return link(path, aside) == 0;
    case DP_TAMPER_SYMLINK:
        return rename(path, aside) == 0 && symlink(aside, path) == 0;
    case DP_TAMPER_BOOT:
        return dp_record_other_boot(path);
    case DP_TAMPER_COUNT:
        break;
    }
    return false;
}

static int test_watch_session_untrusted_record_pruned(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0}, dir[PATH_MAX] = {0};
    TEST("dev platform: a writable, linked or other-boot record over a live watcher is pruned, never signalled") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc (exe, cwd, boot_id) */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-trust"));
        ASSERT(dp_fake_watch_start(root, 100, &fake));
        char path[PATH_MAX], aside[PATH_MAX];
        ASSERT(dp_record_path(root, fake.watcher, path));
        ASSERT(snprintf(dir, sizeof(dir), "%s/%s", root,
                        ZCL_DEVLOOP_WATCH_SESSION_DIR_REL) > 0);
        for (int how = 0; how < DP_TAMPER_COUNT; how++) {
            ASSERT(zcl_devloop_watch_session_record(root, fake.watcher));
            ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                      (int)ZCL_DEVLOOP_WATCH_SESSION_LIVE);
            ASSERT(dp_tamper_record(root, path, (enum dp_tamper)how, aside));
            ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                      (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
            ASSERT(!dp_path_exists(path));
            ASSERT_EQ(zcl_devloop_watch_session_retiring(root, 0), (int64_t)0);
            struct zcl_devloop_watch_stop stop = {.budget_ms = 1000};
            ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher,
                                                          &stop),
                      (int)ZCL_DEVLOOP_WATCH_STOP_NOT_RUNNING);
            ASSERT(dp_pid_running(fake.watcher));
            ASSERT(dp_pid_running(fake.worker));
            (void)unlink(aside);
            ASSERT(chmod(dir, 0700) == 0);
        }
        PASS();
    } _test_next:;
    if (dir[0])
        (void)chmod(dir, 0700);
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_watch_session_stop_binds_birth(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: the session library signals only a leaderless recorded session carrying the named birth") {
#if !defined(__linux__)
        PASS(); /* birth tokens and sessions need /proc */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-birth"));
        ASSERT(dp_fake_watch_start(root, 30000, &fake));
        uint64_t born = 0;
        ASSERT(os_proc_pid_start_token((uint64_t)fake.watcher, &born));
        /* A running leader is never signalled here, whatever it is named
         * by: only its bound session endpoint asks it to stop. */
        struct zcl_devloop_watch_stop stop = {.expect_born = born,
                                              .budget_ms = 1000};
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_LEADER_RUNNING);
        ASSERT(dp_pid_running(fake.watcher));
        ASSERT(dp_pid_running(fake.worker));
        /* Leaderless: another birth, or none named, is refused untouched. */
        ASSERT(kill(fake.watcher, SIGKILL) == 0);
        ASSERT(dp_wait_lock_free(root));
        stop.expect_born = born + 1;
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH);
        stop.expect_born = 0;
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOP_ID_MISMATCH);
        ASSERT(dp_pid_running(fake.worker));
        stop.expect_born = born;
        ASSERT_EQ((int)zcl_devloop_watch_session_stop(root, fake.watcher, &stop),
                  (int)ZCL_DEVLOOP_WATCH_STOPPED);
        ASSERT_EQ(zcl_devloop_process_session_members(fake.watcher, 0),
                  (size_t)0);
        PASS();
    } _test_next:;
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* A reused pid now owned by another user's session leader: kill(pid, 0)
 * reports EPERM and its image cannot be read. The birth token in
 * /proc/<pid>/stat is world-readable and differs from the record's, which
 * proves the reuse on its own; the record must be pruned, not kept
 * UNPROVEN (a launcher would refuse beside it forever). */
static int test_watch_session_reused_pid_other_user(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: a record whose pid now has another birth is pruned even when the process cannot be signalled") {
#if !defined(__linux__)
        PASS(); /* birth tokens need /proc */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-reused"));
        ASSERT(dp_fake_watch_start(root, 100, &fake));
        ASSERT(dp_record_corrupt_token(root, fake.watcher));
        struct zcl_devloop_watch_session_test_hooks hooks = {
            .signal0_denied_pid = fake.watcher};
        zcl_devloop_watch_session_test_hooks_set(&hooks);
        enum zcl_devloop_watch_session_state state =
            zcl_devloop_watch_session_probe(root, fake.watcher);
        int64_t retiring = zcl_devloop_watch_session_retiring(root, 0);
        zcl_devloop_watch_session_test_hooks_set(NULL);
        ASSERT_EQ((int)state, (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        ASSERT_EQ(retiring, (int64_t)0);
        char path[PATH_MAX];
        ASSERT(dp_record_path(root, fake.watcher, path));
        ASSERT(!dp_path_exists(path));
        ASSERT(dp_pid_running(fake.watcher));
        PASS();
    } _test_next:;
    zcl_devloop_watch_session_test_hooks_set(NULL);
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* The launcher rewrites a record (a new file renamed over the old) while a
 * prune of the old one is in flight. */
static void dp_rewrite_record_once(const char *root, int64_t pid, void *opaque)
{
    bool *done = opaque;
    if (*done)
        return;
    *done = true;
    (void)zcl_devloop_watch_session_record(root, pid);
}

static int test_watch_session_forget_spares_rewritten_record(void)
{
    int failures = 0;
    struct dp_fake_watch fake = {0};
    char root[PATH_MAX] = {0};
    TEST("dev platform: pruning a disproven record never removes a record written in its place") {
#if !defined(__linux__)
        PASS(); /* launch identity needs /proc */
        goto _test_next;
#endif
        ASSERT(dp_watch_session_root(root, "watch-forget"));
        ASSERT(dp_fake_watch_start(root, 100, &fake));
        ASSERT(dp_record_corrupt_token(root, fake.watcher));
        bool rewritten = false;
        struct zcl_devloop_watch_session_test_hooks hooks = {
            .before_forget = dp_rewrite_record_once, .opaque = &rewritten};
        zcl_devloop_watch_session_test_hooks_set(&hooks);
        enum zcl_devloop_watch_session_state state =
            zcl_devloop_watch_session_probe(root, fake.watcher);
        zcl_devloop_watch_session_test_hooks_set(NULL);
        ASSERT_EQ((int)state, (int)ZCL_DEVLOOP_WATCH_SESSION_ABSENT);
        ASSERT(rewritten);
        char path[PATH_MAX];
        ASSERT(dp_record_path(root, fake.watcher, path));
        ASSERT(dp_path_exists(path));
        ASSERT_EQ((int)zcl_devloop_watch_session_probe(root, fake.watcher),
                  (int)ZCL_DEVLOOP_WATCH_SESSION_LIVE);
        PASS();
    } _test_next:;
    zcl_devloop_watch_session_test_hooks_set(NULL);
    dp_fake_watch_reap(&fake);
    if (root[0])
        (void)test_rm_rf_recursive(root);
    return failures;
}

/* Case identity and ownership are kept in one table. The registered base
 * group proves the partition; each child group runs its assigned cases. */
struct dp_shard_case {
    const char *name;
    int (*run)(void);
    unsigned shard;
};
#define DP_CASE(fn, owner) {#fn, fn, owner}
static const struct dp_shard_case g_dp_cases[] = {
    DP_CASE(test_failure_store, 5),
    DP_CASE(test_cycle_seal_batch, 5),
    DP_CASE(test_drive_wait_ignores_seal_lock, 5),
    DP_CASE(test_mirror_write_joins_ring, 5),
    DP_CASE(test_distill_first_error, 7),
    DP_CASE(test_hotswap_artifact_cache, 5),
    DP_CASE(test_hotfork_story_file_green_and_red, 5),
    DP_CASE(test_resident_restart_builder, 4),
#if defined(__APPLE__)
    DP_CASE(test_darwin_attested_descriptor_process, 4),
#endif
    DP_CASE(test_resident_process_cancellation, 4),
    DP_CASE(test_exact_commit_preempts_edit_proof, 4),
    DP_CASE(test_foreground_cycle_yields_to_commit, 4),
    DP_CASE(test_watcher_stream_backpressure, 4),
    DP_CASE(test_watcher_journal_sealer, 4),
    DP_CASE(test_watch_idle_exit, 4),
    DP_CASE(test_resident_process_supersession, 4),
    DP_CASE(test_native_source_cas_shadow, 5),
    DP_CASE(test_source_identity_failure_tokens, 5),
    DP_CASE(test_cycle_proof_reuse_contract, 5),
    DP_CASE(test_progressive_event_vocabulary, 5),
    DP_CASE(test_reflex_policy_boundary, 5),
    DP_CASE(test_hotfork_descriptor_boundary, 5),
    DP_CASE(test_template_generator_concurrency, 3),
    DP_CASE(test_watch_session_stop_leaves_nothing, 3),
    DP_CASE(test_watch_session_orphaned_worker_stopped, 0),
    DP_CASE(test_watch_session_admit_attach_refuse, 5),
    DP_CASE(test_watch_session_foreign_orphan_never_signalled, 2),
    DP_CASE(test_watch_session_stop_from_own_session, 3),
    DP_CASE(test_watch_session_retired_owner_stops, 2),
    DP_CASE(test_watch_session_refuses_unproven_pid, 1),
    DP_CASE(test_watch_session_unproven_record_kept, 1),
    DP_CASE(test_watch_session_untrusted_record_pruned, 0),
    DP_CASE(test_watch_session_stop_binds_birth, 3),
    DP_CASE(test_watch_session_reused_pid_other_user, 6),
    DP_CASE(test_watch_session_forget_spares_rewritten_record, 7),
    DP_CASE(test_ephemeral_fixture_leaves_source_identity, 2),
    DP_CASE(test_native_identity_tokens_match_oracle, 1),
    DP_CASE(test_cold_epoch_integrity_gate, 0),
    DP_CASE(test_menu_and_search, 6),
    DP_CASE(test_change_classification, 6),
    DP_CASE(test_change_plan_closure, 6),
    DP_CASE(test_watcher_publication_containment, 6),
    DP_CASE(test_watch_start_wait_reply, 6),
    DP_CASE(test_watch_relevance, 6),
    DP_CASE(test_core_classification, 6),
    DP_CASE(test_core_refusal_envelope, 6),
    DP_CASE(test_core_refusal_cycle, 6),
    DP_CASE(test_core_refusal_token, 6),
    DP_CASE(test_public_app_abi, 7),
    DP_CASE(test_app_runtime_transaction, 7),
    DP_CASE(test_app_definition_compiler, 7),
    DP_CASE(test_strict_dev_app_producers, 7),
    DP_CASE(test_app_definition_hostile_fixtures, 7),
    DP_CASE(test_signed_app_events, 7),
    DP_CASE(test_social_sim, 7),
    DP_CASE(test_native_activation_switch, 7),
    DP_CASE(test_native_activation_request_builder, 7),
    DP_CASE(test_native_activation_result_mapping, 7),
};
#undef DP_CASE
#define DP_CASE_COUNT (sizeof(g_dp_cases) / sizeof(g_dp_cases[0]))
#define DP_SHARD_COUNT 8u

static const char *const g_dp_env_keys[] = {
    "HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "TMPDIR",
};
struct dp_saved_env {
    char *value[sizeof(g_dp_env_keys) / sizeof(g_dp_env_keys[0])];
    bool present[sizeof(g_dp_env_keys) / sizeof(g_dp_env_keys[0])];
};

static bool dp_restore_env(struct dp_saved_env *saved)
{
    bool ok = true;
    for (size_t i = 0; i < sizeof(g_dp_env_keys) / sizeof(g_dp_env_keys[0]); i++) {
        int rc = saved->present[i]
            ? setenv(g_dp_env_keys[i], saved->value[i], 1)
            : unsetenv(g_dp_env_keys[i]);
        if (rc != 0) ok = false;
        free(saved->value[i]);
        saved->value[i] = NULL;
    }
    return ok;
}

static bool dp_private_env(struct dp_saved_env *saved, const char *root)
{
    for (size_t i = 0; i < sizeof(g_dp_env_keys) / sizeof(g_dp_env_keys[0]); i++) {
        const char *value = getenv(g_dp_env_keys[i]);
        saved->present[i] = value != NULL;
        if (value) {
            saved->value[i] = strdup(value);
            if (!saved->value[i]) {
                for (size_t j = 0; j < i; j++) free(saved->value[j]);
                return false;
            }
        }
    }
    for (size_t i = 0; i < sizeof(g_dp_env_keys) / sizeof(g_dp_env_keys[0]); i++) {
        if (setenv(g_dp_env_keys[i], root, 1) != 0) {
            (void)dp_restore_env(saved);
            return false;
        }
    }
    return true;
}

static int dp_run_shard(unsigned shard)
{
    char cwd[PATH_MAX], root[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(root, sizeof(root), "%s.dp_shard_%ld_%u_XXXXXX",
                 cwd, (long)getpid(), shard + 1u) >= (int)sizeof(root) ||
        !mkdtemp(root)) {
        perror("dev_platform: private shard directory");
        return 1;
    }
    struct dp_saved_env saved = {0};
    if (!dp_private_env(&saved, root)) {
        fprintf(stderr, "dev_platform: private environment failed\n");
        (void)test_rm_rf_recursive(root);
        return 1;
    }
    int failures = 0;
    printf("=== dev_platform shard=%u pid=%ld root=%s ===\n",
           shard + 1u, (long)getpid(), root);
    for (size_t i = 0; i < DP_CASE_COUNT; i++) {
        if (g_dp_cases[i].shard != shard) continue;
        int64_t started = platform_time_monotonic_ms();
        int added = g_dp_cases[i].run();
        int64_t finished = platform_time_monotonic_ms();
        failures += added;
        printf("[dev-platform-case] shard=%u name=%s ms=%lld failures=%d\n",
               shard + 1u, g_dp_cases[i].name,
               (long long)(finished >= started ? finished - started : -1), added);
    }
    if (!dp_restore_env(&saved)) failures++;
    if (test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}

static int test_dev_platform_platform_arm(void)
{
    int failures = 0;
    unsigned counts[DP_SHARD_COUNT] = {0};
    bool unique = true;
    for (size_t i = 0; i < DP_CASE_COUNT; i++) {
        if (g_dp_cases[i].shard >= DP_SHARD_COUNT) {
            unique = false;
            continue;
        }
        counts[g_dp_cases[i].shard]++;
        for (size_t j = 0; j < i; j++)
            if (g_dp_cases[i].run == g_dp_cases[j].run ||
                strcmp(g_dp_cases[i].name, g_dp_cases[j].name) == 0)
                unique = false;
    }
    size_t owned = 0;
    bool nonempty = true;
    for (unsigned i = 0; i < DP_SHARD_COUNT; i++) {
        owned += counts[i];
        nonempty &= counts[i] > 0;
    }
    if (DP_CASE_COUNT != 57u + (unsigned)(
#if defined(__APPLE__)
            1
#else
            0
#endif
            ) || owned != DP_CASE_COUNT || !unique || !nonempty) {
        fprintf(stderr, "dev_platform: case partition invalid\n");
        failures++;
    }
    const char *plans[] = {"dev_platform"};
    char expanded[DP_SHARD_COUNT + 1u][ZCL_TEST_GROUP_FULL_MAX];
    bool truncated = false;
    size_t selected = zcl_test_group_expand_plan(plans, 1, expanded,
                                                  DP_SHARD_COUNT + 1u,
                                                  &truncated);
    if (selected != DP_SHARD_COUNT + 1u || truncated) {
        fprintf(stderr, "dev_platform: proof family omits a shard\n");
        failures++;
    }
    printf("dev_platform partition: cases=%zu shards=%u failures=%d\n",
           DP_CASE_COUNT, DP_SHARD_COUNT, failures);
    return failures;
}

#define DP_SHARD_FN(tag, index) \
    int test_dev_platform_shard_##tag(void) { return dp_run_shard(index); }
DP_SHARD_FN(01, 0)
DP_SHARD_FN(02, 1)
DP_SHARD_FN(03, 2)
DP_SHARD_FN(04, 3)
DP_SHARD_FN(05, 4)
DP_SHARD_FN(06, 5)
DP_SHARD_FN(07, 6)
DP_SHARD_FN(08, 7)
#undef DP_SHARD_FN
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked dev-platform child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_dev_platform_platform_arm(void)
{
    printf("dev_platform: SKIP (Windows): forked dev-platform child lane\n");
    return 0;
}
#endif

#if defined(_WIN32)
#define DP_SHARD_FN(tag) \
    int test_dev_platform_shard_##tag(void) { return test_dev_platform_platform_arm(); }
DP_SHARD_FN(01)
DP_SHARD_FN(02)
DP_SHARD_FN(03)
DP_SHARD_FN(04)
DP_SHARD_FN(05)
DP_SHARD_FN(06)
DP_SHARD_FN(07)
DP_SHARD_FN(08)
#undef DP_SHARD_FN
#endif

int test_dev_platform(void)
{
    return test_dev_platform_platform_arm();
}
