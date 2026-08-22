/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_fetch — the slice-12 typed-command contract gate for the
 * swarm operator surface (tools/command/native_zcode_swarm_command.c):
 *
 *   zcode package fetch    one-shot (no live engine): the resumable
 *                          download record is persisted under
 *                          <datadir>/zcode/downloads/<root-hex> and the
 *                          reply honestly reports live:false; a complete
 *                          package reports already_complete; BAD_ROOT
 *                          names the bad input; optional local library
 *                          `name` resolves from the rebuildable index
 *                          (UNKNOWN_NAME / NAME_ROOT_MISMATCH /
 *                          MISSING_ROOT_OR_NAME fail closed; never ZNAM)
 *   zcode package peers    one-shot: live:false, empty list, never a
 *                          replayed-from-disk fake; store-side possession
 *                          (complete, operator-pinned, public-serveable /
 *                          would_serve) is still reported, fail closed
 *   zcode package offered  one-shot: live:false, empty items, still
 *                          PASSED; live engine: one ANNOUNCE row with
 *                          engine advertisers and store-side have_local.
 *                          Replica counts are never invented.
 *   zcode package pin      UNKNOWN_PACKAGE names the untracked root; a
 *                          tracked package pins (operator path, never
 *                          tier-gated) and reports its pool
 *   zcode package unpin    releases the pin; idempotent
 *
 * Handlers are called directly with a typed JSON input (the zp_cmd
 * idiom from test_zcode_publish.c) over ./test-tmp datadirs. */

#include "test/test_core.h"

#include "base/hex.h"

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "controllers/rpc_client.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "vcs/blob_store.h"
#include "vcs/package_manifest.h"
#include "vcs/package_reward.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZF_MAX_FILE 256u

/* ── zp_cmd idiom ───────────────────────────────────────────────────── */

struct zf_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zf_cmd_init(struct zf_cmd *c, const char *datadir)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
}

static void zf_cmd_free(struct zf_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* ── fixture package (two single-chunk files) ───────────────────────── */

struct zf_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
    uint8_t contents[2][ZF_MAX_FILE];
    size_t lens[2];
};

static bool zf_make_package(struct zf_pkg *p, uint8_t seed)
{
    static const char *const k_paths[2] = { "LICENSE", "src/a.c" };
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < 2; i++) {
        size_t len = 48u + i * 37u + seed;
        for (size_t j = 0; j < len; j++)
            p->contents[i][j] = (uint8_t)(seed + i * 7u + j * 3u);
        p->lens[i] = len;
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(p->contents[i], len, hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, k_paths[i],
                                      VCS_PACKAGE_MODE_FILE, len, hash, 1))
            return false;
    }
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    zcl_hex_encode(p->root, 32, p->root_hex);
    return true;
}

static void zf_free_package(struct zf_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

static bool zf_discover_provider(struct json_value *selector,
                                 struct json_value *result)
{
    const char *kind = json_get_str(json_get(selector, "kind"));
    const char *ns = json_get_str(json_get(selector, "namespace"));
    const char *root = json_get_str(json_get(selector, "transport_root"));
    if (!kind || strcmp(kind, "provider") != 0 ||
        !ns || strcmp(ns, "zclassic23.source") != 0 ||
        !root || strlen(root) != 64)
        return false;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "count", 1);
    return true;
}

static bool zf_route_provider(struct json_value *selector,
                              struct json_value *result)
{
    const struct json_value *maximum = json_get(selector, "maximum_bytes");
    if (!maximum || maximum->type != JSON_INT ||
        json_get_int(maximum) != 268435456)
        return false;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "authenticated_providers", 1);
    (void)json_push_kv_str(result, "fetch_result", "ok");
    (void)json_push_kv_bool(result, "restricted", true);
    return true;
}

static bool zf_route_reproduction_complete(struct json_value *selector,
                                           struct json_value *result)
{
    if (!zf_route_provider(selector, result))
        return false;
    json_set_str((struct json_value *)json_get(result, "fetch_result"),
                 "already-complete");
    return true;
}

static bool zf_discover_provider_package(struct json_value *selector,
                                         struct json_value *result)
{
    const char *kind = json_get_str(json_get(selector, "kind"));
    const char *ns = json_get_str(json_get(selector, "namespace"));
    const char *root = json_get_str(json_get(selector, "transport_root"));
    if (!kind || strcmp(kind, "provider") != 0 ||
        !ns || strcmp(ns, "zclassic23.package") != 0 ||
        !root || strlen(root) != 64)
        return false;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "count", 2);
    return true;
}

/* The daemon routed the root and then refused under its own name: the
 * transport-level reply carries ok:false plus the refusal body. */
static bool zf_route_provider_refused(struct json_value *selector,
                                      struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    (void)json_push_kv_bool(result, "ok", false);
    (void)json_push_kv_str(result, "code", "FETCH_REFUSED");
    (void)json_push_kv_str(result, "error", "no-authenticated-provider");
    (void)json_push_kv_str(result, "fetch_result", "no-authenticated-provider");
    (void)json_push_kv_bool(result, "restricted", true);
    return false;
}

static char zf_reproduction_root[65];
static unsigned zf_reproduction_plan_calls;
static unsigned zf_reproduction_commit_calls;
static bool zf_reproduction_rpc_exact;

static char *zf_reproduction_rpc_hook(const char *method,
                                      const char *params_json)
{
    static const char token[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char source[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    if (strcmp(method, "zcode_dht_source_reproduction_ack") != 0)
        return zcl_strdup("{\"ok\":false,\"code\":\"UNEXPECTED_RPC\"}",
                          "test.zcode_fetch.reproduction_unexpected");
    bool plan = params_json && strstr(params_json, "\"mode\":\"plan\"");
    bool commit = params_json &&
        strstr(params_json, "\"mode\":\"commit\"");
    zf_reproduction_plan_calls += plan;
    zf_reproduction_commit_calls += commit;
    zf_reproduction_rpc_exact = params_json &&
        strstr(params_json, zf_reproduction_root) &&
        strstr(params_json, "\"namespace\":\"zclassic23.source\"") &&
        (!commit || strstr(params_json, token));
    char body[512];
    int n = snprintf(
        body, sizeof(body),
        "{\"ok\":true,\"mode\":\"%s\",\"committed\":%s,"
        "\"plan_token\":\"%s\",\"record\":{"
        "\"semantic_root\":\"%s\"}}",
        commit ? "commit" : "plan", commit ? "true" : "false",
        token, source);
    return n > 0 && (size_t)n < sizeof(body)
        ? zcl_strdup(body, "test.zcode_fetch.reproduction") : NULL;
}

static bool zf_store_package(struct vcs_package_store *store,
                             const struct zf_pkg *p)
{
    uint8_t root[32];
    if (vcs_package_store_put_manifest(store, p->wire, p->wire_len,
                                       root) != VCS_PACKAGE_STORE_OK)
        return false;
    for (size_t i = 0; i < 2; i++) {
        const char *path = p->manifest.files[i].path;
        if (vcs_package_store_put_chunk(store, root, path, 0,
                                        p->contents[i],
                                        p->lens[i]) != VCS_PACKAGE_STORE_OK)
            return false;
    }
    return true;
}

/* ── the cases (one TEST per function — the label is function-scoped) ── */

static int zf_t_fetch_one_shot(void)
{
    int failures = 0;
    TEST("zcode package fetch (one-shot): record persisted, live:false, "
         "state want-manifest; idempotent redelivery") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "fetch");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x44));

        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_int(&c.input, "day", 20500);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "live") &&
               !json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT(json_get(&c.reply.data, "already_complete") &&
               !json_get_bool(json_get(&c.reply.data, "already_complete")));
        {
            const struct json_value *dl = json_get(&c.reply.data, "download");
            ASSERT(dl != NULL);
            const char *state = json_get_str(json_get(dl, "state"));
            ASSERT(state && strcmp(state, "want-manifest") == 0);
            ASSERT_EQ(json_get_int(json_get(dl, "requested_bytes")), 0);
            ASSERT_EQ(json_get_int(json_get(dl, "transferred_bytes")), 0);
            ASSERT_EQ(json_get_int(json_get(dl, "reused_bytes")), 0);
            ASSERT_EQ(json_get_int(json_get(dl, "requested_objects")), 0);
            ASSERT_EQ(json_get_int(json_get(dl, "transferred_objects")), 0);
            ASSERT_EQ(json_get_int(json_get(dl, "reused_objects")), 0);
        }
        zf_cmd_free(&c);

        /* The resumable record is the one-shot command's only lasting
         * effect — persisted under <datadir>/zcode/downloads. */
        {
            char path[1200];
            snprintf(path, sizeof(path), "%s/zcode/downloads/%s", dd,
                     pkg.root_hex);
            struct stat st;
            ASSERT(stat(path, &st) == 0 && st.st_size > 0);
        }

        /* Idempotent: the same fetch again is still OK (active download
         * for the same root), and the record survives. */
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_int(&c.input, "day", 20500);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_fetch_bad_root(void)
{
    int failures = 0;
    TEST("zcode package fetch: BAD_ROOT names the bad input") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "badroot");
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", "not-hex");
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(c.reply.error.code, "BAD_ROOT") == 0);
        ASSERT(c.reply.error.message[0] != '\0');
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_fetch_missing_identity(void)
{
    int failures = 0;
    TEST("zcode package fetch: missing name and root fails closed") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "noid");
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(c.reply.error.code, "MISSING_ROOT_OR_NAME") == 0);
        ASSERT(c.reply.error.message[0] != '\0');
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_fetch_unknown_name(void)
{
    int failures = 0;
    TEST("zcode package fetch: unknown local name fails closed") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "unknown-name");
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "name", "nobody/missing-package");
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(c.reply.error.code, "UNKNOWN_NAME") == 0);
        ASSERT(c.reply.error.message[0] != '\0');
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_fetch_dht_routed_live(void)
{
    int failures = 0;
    TEST("zcode package fetch: namespace routes through the daemon-owned authenticated swarm") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "dht-route");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x4a));
        zcl_native_zcode_discovery_test_backend(
            zf_discover_provider, zf_route_provider);
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "namespace", "zclassic23.source");
        (void)json_push_kv_int(&c.input, "maximum_bytes", 268435456);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT(json_get_bool(json_get(&c.reply.data, "restricted")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data,
                                        "authenticated_providers")), 1);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data,
                                        "provider_records")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data,
                                            "package_root")),
                      pkg.root_hex);
        zf_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    return failures;
}

static int zf_t_fetch_dht_routed_refused(void)
{
    int failures = 0;
    TEST("zcode package fetch: a routed refusal keeps the daemon's exact code") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "dht-refused");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x6b));
        zcl_native_zcode_discovery_test_backend(
            zf_discover_provider_package, zf_route_provider_refused);
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "namespace", "zclassic23.package");
        (void)json_push_kv_int(&c.input, "maximum_bytes", 67108864);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_TRANSIENT);
        /* The code must survive the routed tree's release byte-for-byte;
         * before the copy-out fix this read freed memory. */
        ASSERT_STR_EQ(c.reply.error.code, "FETCH_REFUSED");
        ASSERT(strstr(c.reply.error.message, "no-authenticated-provider") !=
               NULL);
        ASSERT(strstr(c.reply.error.message, "2 provider record(s)") != NULL);
        ASSERT(c.reply.error.retryable);
        zf_cmd_free(&c);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    return failures;
}

static int zf_t_fetch_complete(void)
{
    int failures = 0;
    TEST("zcode package fetch on a complete package: already_complete") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "complete");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x55));
        {
            struct vcs_package_store *store = vcs_package_store_open(
                dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
            ASSERT(store != NULL);
            ASSERT(zf_store_package(store, &pkg));
            vcs_package_store_close(store);
        }
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        zcl_native_handle_zcode_package_fetch(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "already_complete") &&
               json_get_bool(json_get(&c.reply.data, "already_complete")));
        {
            const struct json_value *dl = json_get(&c.reply.data, "download");
            ASSERT(dl != NULL);
            const char *state = json_get_str(json_get(dl, "state"));
            ASSERT(state && strcmp(state, "complete") == 0);
        }
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_source_reproduction_loop(void)
{
    int failures = 0;
    TEST("zcode source reproduce: one root drives fetch, plan and commit") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "reproduce");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x5a));
        (void)snprintf(zf_reproduction_root,
                       sizeof(zf_reproduction_root), "%s", pkg.root_hex);

        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        (void)json_push_kv_str(&c.input, "root", "not-a-root");
        zcl_native_handle_zcode_package_source_reproduce(
            &c.request, &c.reply);
        ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(c.reply.error.code,
                      "BAD_SOURCE_REPRODUCTION_INPUT");
        zf_cmd_free(&c);

        zcl_native_zcode_discovery_test_backend(
            zf_discover_provider, zf_route_provider);
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        zcl_native_handle_zcode_package_source_reproduce(
            &c.request, &c.reply);
        if (c.reply.exit_code != ZCL_COMMAND_EXIT_OK)
            printf("source reproduce pending failed: %s: %s\n",
                   c.reply.error.code, c.reply.error.message);
        ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "status")),
                      "FETCH_PENDING");
        ASSERT(!json_get_bool(json_get(
            &c.reply.data, "reconstructed")));
        ASSERT(!json_get_bool(json_get(
            &c.reply.data, "evidence_signed")));
        ASSERT(strstr(json_get_str(json_get(
                          &c.reply.data, "next_command")),
                      pkg.root_hex) != NULL);
        zf_cmd_free(&c);

        zcl_native_zcode_discovery_test_backend(
            zf_discover_provider, zf_route_reproduction_complete);
        zf_reproduction_plan_calls = 0;
        zf_reproduction_commit_calls = 0;
        zf_reproduction_rpc_exact = false;
        node_rpc_client_set_test_hook(zf_reproduction_rpc_hook);
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        zcl_native_handle_zcode_package_source_reproduce(
            &c.request, &c.reply);
        if (c.reply.exit_code != ZCL_COMMAND_EXIT_OK)
            printf("source reproduce plan failed: %s: %s\n",
                   c.reply.error.code, c.reply.error.message);
        ASSERT_EQ(c.reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "status")),
                      "SOURCE_REPRODUCTION_PROVEN");
        ASSERT(json_get_bool(json_get(
            &c.reply.data, "reconstructed")));
        ASSERT(json_get_bool(json_get(
            &c.reply.data, "evidence_signed")));
        ASSERT(!json_get_bool(json_get(
            &c.reply.data, "physical_independence_attested")));
        ASSERT_STR_EQ(json_get_str(json_get(
                          &c.reply.data, "source_tree_root")),
                      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        ASSERT_EQ(zf_reproduction_plan_calls, 1u);
        ASSERT_EQ(zf_reproduction_commit_calls, 0u);
        ASSERT(zf_reproduction_rpc_exact);
        const struct json_value *planned_commit = json_get(
            &c.reply.data, "commit_input");
        ASSERT(planned_commit && planned_commit->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(planned_commit, "root")),
                      pkg.root_hex);
        ASSERT(json_get(planned_commit, "semantic_root") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(
                          planned_commit, "plan_token")),
                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        struct json_value commit_input;
        json_init(&commit_input);
        json_copy(&commit_input, planned_commit);
        zf_cmd_free(&c);

        struct zcl_command_request commit_request = {
            .input = &commit_input,
        };
        struct zcl_command_reply commit_reply;
        zcl_command_reply_init(&commit_reply,
                               "zcl.zcode_source_reproduce.v1");
        zf_reproduction_rpc_exact = false;
        zcl_native_handle_zcode_package_source_reproduce(
            &commit_request, &commit_reply);
        ASSERT_EQ(commit_reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(
                          &commit_reply.data, "status")),
                      "SOURCE_REPRODUCTION_PUBLISHED");
        ASSERT(json_get_bool(json_get(
            &commit_reply.data, "committed")));
        ASSERT_EQ(zf_reproduction_plan_calls, 1u);
        ASSERT_EQ(zf_reproduction_commit_calls, 1u);
        ASSERT(zf_reproduction_rpc_exact);
        zcl_command_reply_free(&commit_reply);
        json_free(&commit_input);
        node_rpc_client_set_test_hook(NULL);
        zcl_native_zcode_discovery_test_backend(NULL, NULL);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    return failures;
}

static const struct json_value *zf_possession(const struct zf_cmd *c)
{
    return json_get(&c->reply.data, "possession");
}

static int zf_t_peers_one_shot(void)
{
    int failures = 0;
    TEST("zcode package peers (one-shot): live:false, empty, honest note") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "peers");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x66));
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        zcl_native_handle_zcode_package_peers(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "live") &&
               !json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT(json_get_int(json_get(&c.reply.data, "peer_count")) == 0);
        ASSERT(json_get(&c.reply.data, "peers") != NULL);
        ASSERT(json_get_str(json_get(&c.reply.data, "note")) != NULL);
        {
            const struct json_value *pos = zf_possession(&c);
            ASSERT(pos != NULL);
            ASSERT(json_get(pos, "observed") &&
                   !json_get_bool(json_get(pos, "observed")));
            ASSERT(json_get(pos, "tracked") &&
                   !json_get_bool(json_get(pos, "tracked")));
            ASSERT(json_get(pos, "complete") &&
                   !json_get_bool(json_get(pos, "complete")));
            ASSERT(json_get(pos, "pinned") &&
                   !json_get_bool(json_get(pos, "pinned")));
            ASSERT(json_get(pos, "public_serveable") &&
                   !json_get_bool(json_get(pos, "public_serveable")));
            ASSERT(json_get(pos, "would_serve") &&
                   !json_get_bool(json_get(pos, "would_serve")));
            ASSERT_STR_EQ(json_get_str(json_get(pos, "public_shape")),
                          "refused");
            ASSERT_STR_EQ(json_get_str(json_get(pos, "serve_rule")),
                          "store-unobserved");
            ASSERT_EQ(json_get_int(json_get(pos, "present_bytes")), 0);
            ASSERT_EQ(json_get_int(json_get(pos, "total_bytes")), 0);
        }
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_peers_possession(void)
{
    int failures = 0;
    TEST("zcode package peers: store-side possession, pin, would_serve") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "peers-possess");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x67));
        uint8_t blob_root[32];
        char blob_hex[65];
        {
            struct vcs_package_store *store = vcs_package_store_open(
                dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
            ASSERT(store != NULL);
            ASSERT(zf_store_package(store, &pkg));
            uint8_t blob[16];
            for (size_t i = 0; i < sizeof(blob); i++)
                blob[i] = (uint8_t)(0xa0u + i);
            ASSERT(vcs_blob_put_to(store, blob, sizeof(blob), blob_root) ==
                   VCS_BLOB_OK);
            zcl_hex_encode(blob_root, 32, blob_hex);
            ASSERT(vcs_package_store_pin(store, pkg.root, true) ==
                   VCS_PACKAGE_STORE_OK);
            vcs_package_store_close(store);
        }

        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        zcl_native_handle_zcode_package_peers(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "live") &&
               !json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT(json_get_int(json_get(&c.reply.data, "peer_count")) == 0);
        {
            const struct json_value *pos = zf_possession(&c);
            ASSERT(pos != NULL);
            ASSERT(json_get_bool(json_get(pos, "observed")));
            ASSERT(json_get_bool(json_get(pos, "tracked")));
            ASSERT(json_get_bool(json_get(pos, "complete")));
            ASSERT(json_get_bool(json_get(pos, "pinned")));
            ASSERT(json_get(pos, "public_serveable") &&
                   !json_get_bool(json_get(pos, "public_serveable")));
            ASSERT(json_get(pos, "would_serve") &&
                   !json_get_bool(json_get(pos, "would_serve")));
            ASSERT_STR_EQ(json_get_str(json_get(pos, "public_shape")),
                          "refused");
            ASSERT(json_get_str(json_get(pos, "serve_rule")) != NULL);
            ASSERT(json_get_int(json_get(pos, "present_bytes")) > 0);
            ASSERT(json_get_int(json_get(pos, "total_bytes")) > 0);
            ASSERT(json_get(&c.reply.data, "replicas") == NULL);
            ASSERT(json_get(pos, "replicas") == NULL);
        }
        zf_cmd_free(&c);

        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", blob_hex);
        zcl_native_handle_zcode_package_peers(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "live") &&
               !json_get_bool(json_get(&c.reply.data, "live")));
        {
            const struct json_value *pos = zf_possession(&c);
            ASSERT(pos != NULL);
            ASSERT(json_get_bool(json_get(pos, "observed")));
            ASSERT(json_get_bool(json_get(pos, "tracked")));
            ASSERT(json_get_bool(json_get(pos, "complete")));
            ASSERT(json_get(pos, "pinned") &&
                   !json_get_bool(json_get(pos, "pinned")));
            ASSERT(json_get_bool(json_get(pos, "public_serveable")));
            ASSERT(json_get_bool(json_get(pos, "would_serve")));
            ASSERT_STR_EQ(json_get_str(json_get(pos, "public_shape")),
                          "blob");
            ASSERT_STR_EQ(json_get_str(json_get(pos, "serve_rule")),
                          "blob");
        }
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_pin_roundtrip(void)
{
    int failures = 0;
    TEST("zcode package pin: UNKNOWN_PACKAGE, then pin + unpin round-trip") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "pin");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x77));

        /* Unknown root: named rejection. */
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        zcl_native_handle_zcode_package_pin(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(c.reply.error.code, "UNKNOWN_PACKAGE") == 0);
        zf_cmd_free(&c);

        {
            struct vcs_package_store *store = vcs_package_store_open(
                dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
            ASSERT(store != NULL);
            ASSERT(zf_store_package(store, &pkg));
            vcs_package_store_close(store);
        }

        /* Pin plan is read-only; commit applies exactly that state token. */
        char token[65];
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        zcl_native_handle_zcode_package_pin(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!json_get_bool(json_get(&c.reply.data, "committed")));
        ASSERT(!json_get_bool(json_get(&c.reply.data, "pinned")));
        const char *planned = json_get_str(json_get(&c.reply.data,
                                                     "plan_token"));
        ASSERT(planned != NULL && strlen(planned) == 64);
        memcpy(token, planned, sizeof(token));
        zf_cmd_free(&c);

        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "mode", "commit");
        (void)json_push_kv_str(&c.input, "plan_token", token);
        zcl_native_handle_zcode_package_pin(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "committed")));
        ASSERT(json_get(&c.reply.data, "pinned") &&
               json_get_bool(json_get(&c.reply.data, "pinned")));
        {
            const struct json_value *pj = json_get(&c.reply.data, "package");
            ASSERT(pj != NULL);
            ASSERT(json_get_bool(json_get(pj, "pinned")));
            const char *pool = json_get_str(json_get(pj, "pool"));
            ASSERT(pool && strcmp(pool, "pins") == 0);
        }
        zf_cmd_free(&c);

        /* Unpin uses the same plan/commit lifecycle. */
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "mode", "plan");
        zcl_native_handle_zcode_package_unpin(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        planned = json_get_str(json_get(&c.reply.data, "plan_token"));
        ASSERT(planned != NULL && strlen(planned) == 64);
        memcpy(token, planned, sizeof(token));
        zf_cmd_free(&c);

        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", pkg.root_hex);
        (void)json_push_kv_str(&c.input, "mode", "commit");
        (void)json_push_kv_str(&c.input, "plan_token", token);
        zcl_native_handle_zcode_package_unpin(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "pinned") &&
               !json_get_bool(json_get(&c.reply.data, "pinned")));
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    return failures;
}

static bool zf_announce_package(struct vcs_swarm_engine *engine, uint64_t peer,
                                const struct zf_pkg *p)
{
    struct vcs_package_swarm_message msg;
    uint64_t total = 0;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    memcpy(msg.body.announce.package_root, p->root, 32);
    msg.body.announce.manifest_bytes = (uint32_t)p->wire_len;
    msg.body.announce.file_count = 2;
    for (size_t i = 0; i < 2; i++)
        total += p->lens[i];
    msg.body.announce.total_bytes = total;
    msg.body.announce.total_chunks = 2;
    uint8_t frame[128];
    size_t len = 0;
    if (!vcs_package_swarm_serialize(&msg, frame, sizeof(frame), &len))
        return false;
    struct vcs_swarm_frame_result r =
        vcs_swarm_engine_handle_frame(engine, peer, frame, len, 20500, 1);
    free(r.reply);
    return r.penalty == VCS_SWARM_PENALTY_NONE;
}

static int zf_t_offered_one_shot(void)
{
    int failures = 0;
    TEST("zcode package offered (one-shot): live:false, empty, PASSED") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "offered");
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get(&c.reply.data, "live") &&
               !json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "offered_count")), 0);
        {
            const struct json_value *items =
                json_get(&c.reply.data, "items");
            ASSERT(items != NULL && items->type == JSON_ARR);
            ASSERT_EQ(json_size(items), 0);
        }
        ASSERT(json_get(&c.reply.data, "truncated") &&
               !json_get_bool(json_get(&c.reply.data, "truncated")));
        {
            const char *next =
                json_get_str(json_get(&c.reply.data, "next_command"));
            ASSERT(next != NULL &&
                   strstr(next, "-packagehost=1 -buildworker=1") != NULL);
            ASSERT(strcmp(json_get_str(json_get(&c.reply.data, "join_flags")),
                          "-packagehost=1 -buildworker=1") == 0);
            ASSERT(!json_get_bool(json_get(&c.reply.data, "joined")));
            ASSERT(!json_get_bool(json_get(&c.reply.data, "package_hosting")));
            ASSERT(!json_get_bool(json_get(&c.reply.data, "build_worker")));
        }
        ASSERT(json_get(&c.reply.data, "replicas") == NULL);
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_offered_live(void)
{
    int failures = 0;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    struct vcs_swarm_engine *engine = NULL;
    TEST("zcode package offered (live): ANNOUNCE row, have_local, fetch next") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "offered-live");
        struct zf_pkg pkg;
        ASSERT(zf_make_package(&pkg, 0x68));
        {
            struct vcs_package_store *store = vcs_package_store_open(
                dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
            ASSERT(store != NULL);
            ASSERT(zf_store_package(store, &pkg));
            vcs_package_store_close(store);
        }

        engine = vcs_swarm_engine_create(NULL, NULL, NULL, NULL, NULL);
        ASSERT(engine != NULL);
        uint8_t key[33];
        memset(key, 0, sizeof(key));
        key[0] = 0x02;
        key[1] = 0x11;
        ASSERT(vcs_swarm_engine_peer_add(engine, 7, key));
        vcs_swarm_engine_set_global(engine);

        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "offered_count")), 0);
        {
            const char *next =
                json_get_str(json_get(&c.reply.data, "next_command"));
            ASSERT(next != NULL && strstr(next, "ANNOUNCE") != NULL);
            ASSERT(strstr(next, "peers") != NULL);
        }
        zf_cmd_free(&c);

        ASSERT(zf_announce_package(engine, 7, &pkg));

        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "offered_count")), 1);
        ASSERT(json_get(&c.reply.data, "truncated") &&
               !json_get_bool(json_get(&c.reply.data, "truncated")));
        {
            const struct json_value *items =
                json_get(&c.reply.data, "items");
            ASSERT(items != NULL && items->type == JSON_ARR);
            ASSERT_EQ(json_size(items), 1);
            const struct json_value *row = json_at(items, 0);
            ASSERT(row != NULL);
            {
                const char *root_hex = json_get_str(json_get(row, "root"));
                ASSERT(root_hex != NULL);
                ASSERT_STR_EQ(root_hex, pkg.root_hex);
            }
            ASSERT_EQ(json_get_int(json_get(row, "advertisers")), 1);
            ASSERT(json_get_bool(json_get(row, "have_local")));
            ASSERT(json_get(row, "replicas") == NULL);
        }
        {
            const char *next =
                json_get_str(json_get(&c.reply.data, "next_command"));
            ASSERT(next != NULL);
            ASSERT(strstr(next, "zcode package fetch") != NULL);
            ASSERT(strstr(next, pkg.root_hex) != NULL);
        }
        ASSERT(json_get(&c.reply.data, "replicas") == NULL);
        zf_cmd_free(&c);
        zf_free_package(&pkg);
        PASS();
    } _test_next:;
    vcs_swarm_engine_set_global(NULL);
    vcs_swarm_engine_free(engine);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

int test_zcode_fetch(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    failures += zf_t_fetch_one_shot();
    failures += zf_t_fetch_bad_root();
    failures += zf_t_fetch_missing_identity();
    failures += zf_t_fetch_unknown_name();
    failures += zf_t_fetch_dht_routed_live();
    failures += zf_t_fetch_dht_routed_refused();
    failures += zf_t_fetch_complete();
    failures += zf_t_source_reproduction_loop();
    failures += zf_t_peers_one_shot();
    failures += zf_t_peers_possession();
    failures += zf_t_pin_roundtrip();
    failures += zf_t_offered_one_shot();
    failures += zf_t_offered_live();
    return failures;
}
