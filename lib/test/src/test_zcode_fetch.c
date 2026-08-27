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
 *                          PASSED; next is `z23 join` until this process
 *                          is hosting, then the named restart. live
 *                          engine: one ANNOUNCE row with engine
 *                          advertisers and store-side have_local.
 *                          Replica counts are never invented.
 *   zcode package pin      UNKNOWN_PACKAGE names the untracked root; a
 *                          tracked package pins (operator path, never
 *                          tier-gated) and reports its pool
 *   zcode package unpin    releases the pin; idempotent
 *   zcode package fastobj export  a hand-built one-entry cache (key via
 *                          vcs_fastobj_key, sidecar components hashing to
 *                          that key, object hashing to the sidecar — a
 *                          real cache would need a confined worker run)
 *                          becomes one carrier in the store: deterministic
 *                          root, tracked + complete, and the honest
 *                          public-shape verdict (refused /
 *                          no-verified-release — the carrier is not a
 *                          licensed shape); a torn pair refuses the whole
 *                          export
 *   zcode package fastobj admit   the carrier reconstructs into a fresh
 *                          cache with byte-identical members; re-export
 *                          of that cache yields the SAME root (the
 *                          round-trip); the `root` input alias works;
 *                          UNKNOWN_PACKAGE / BAD_ROOT / MISSING_CACHE_DIR
 *                          name their refusals
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
#include "sha3/sha3.h"
#include "vcs/blob_store.h"
#include "vcs/fastobj.h"
#include "vcs/fastobj_carrier.h"
#include "vcs/package_manifest.h"
#include "vcs/package_reward.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"
#include "util/safe_alloc.h"
#include "util/util.h"

#include <errno.h>
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
        {
            const char *note =
                json_get_str(json_get(&c.reply.data, "note"));
            ASSERT(note != NULL);
            ASSERT(strstr(note, "z23 join") != NULL);
            ASSERT(strstr(note, dd) != NULL);
            ASSERT(strstr(note, "-packagehost") == NULL);
            ASSERT(strstr(note, "-buildworker") == NULL);
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
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "peer_count")), 0);
        ASSERT(!json_get_bool(json_get(&c.reply.data, "serving_ready")));
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
            ASSERT(next != NULL && strstr(next, "z23 join") != NULL);
            ASSERT(strstr(next, dd) != NULL);
            ASSERT(strstr(next, "-packagehost=1 -buildworker=1") == NULL);
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

static int zf_t_offered_one_shot_hosting(void)
{
    int failures = 0;
    TEST("zcode package offered (one-shot, hosting already in this process): "
         "next is restart, not another join") {
        char dd[1024];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "offered-hosting");
        const char *argv[] = { "z23", "-packagehost=1" };
        ParseParameters(2, argv);
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT(json_get_bool(json_get(&c.reply.data, "package_hosting")));
        {
            const char *next =
                json_get_str(json_get(&c.reply.data, "next_command"));
            ASSERT(next != NULL);
            ASSERT(strstr(next, "restart") != NULL);
            ASSERT(strstr(next, "z23 zcode package offered") != NULL);
            ASSERT(strstr(next, dd) != NULL);
            ASSERT(strstr(next, "z23 join") == NULL);
        }
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    {
        const char *reset[] = { "z23" };
        ParseParameters(1, reset);
    }
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
        vcs_swarm_engine_set_global(engine);

        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "peer_count")), 0);
        ASSERT(!json_get_bool(json_get(&c.reply.data, "serving_ready")));
        {
            const char *next =
                json_get_str(json_get(&c.reply.data, "next_command"));
            ASSERT(next != NULL && strstr(next, "NODE_ZCL23") != NULL);
        }
        zf_cmd_free(&c);

        uint8_t key[33];
        memset(key, 0, sizeof(key));
        key[0] = 0x02;
        key[1] = 0x11;
        ASSERT(vcs_swarm_engine_peer_add(engine, 7, key));

        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_offered(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&c.reply.data, "live")));
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "peer_count")), 1);
        ASSERT(json_get_bool(json_get(&c.reply.data, "serving_ready")));
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

/* ── fastobj carrier: the smallest honest cache fixture ─────────────── */

/* One hand-built cache entry, produced through the same authorities the
 * confined worker uses (vcs_fastobj_key derives the key,
 * vcs_fastobj_cache_paths places it): the sidecar's key_components hash
 * to the entry's own filename and the object hashes to the sidecar's
 * object_sha3. A REAL cache needs a worker run — too heavy for a
 * command-contract group; this fixture exercises every verify rule the
 * leaves rely on. */
struct zf_fastobj_fixture {
    uint8_t key[32];
    char key_hex[65];
    uint8_t object[128];
    size_t object_len;
    char sidecar[640];
    size_t sidecar_len;
};

static bool zf_fastobj_build(struct zf_fastobj_fixture *fx)
{
    memset(fx, 0, sizeof(*fx));
    uint8_t capsule[32], preproc[32];
    for (size_t i = 0; i < 32; i++) {
        capsule[i] = (uint8_t)(0x40u + i);
        preproc[i] = (uint8_t)(0x80u + i * 3u);
    }
    static const char *const argv[] = {"cc", "-c", "-O2", "src/tiny.c",
                                       NULL};
    static const char target[] = "x86_64-pc-linux-gnu";
    static const char profile[] = "standard";
    if (!vcs_fastobj_key(capsule, target, profile, argv, preproc, fx->key))
        return false;
    zcl_hex_encode(fx->key, 32, fx->key_hex);
    fx->object_len = sizeof(fx->object);
    for (size_t i = 0; i < fx->object_len; i++)
        fx->object[i] = (uint8_t)(i * 7u + 0x20u);
    uint8_t obj_sha[32];
    zcl_sha3_256(fx->object, fx->object_len, obj_sha);
    char capsule_hex[65], preproc_hex[65], obj_hex[65];
    zcl_hex_encode(capsule, 32, capsule_hex);
    zcl_hex_encode(preproc, 32, preproc_hex);
    zcl_hex_encode(obj_sha, 32, obj_hex);
    /* argv in the sidecar must be the same strings the key hashed. */
    int n = snprintf(
        fx->sidecar, sizeof(fx->sidecar),
        "{\"schema\":\"%s\",\"key_components\":{\"capsule_root\":\"%s\","
        "\"target\":\"%s\",\"profile\":\"%s\",\"argv\":[\"cc\",\"-c\","
        "\"-O2\",\"src/tiny.c\"],\"preprocessed_sha3\":\"%s\"},"
        "\"object_sha3\":\"%s\"}",
        VCS_FASTOBJ_SIDECAR_SCHEMA, capsule_hex, target, profile,
        preproc_hex, obj_hex);
    if (n <= 0 || (size_t)n >= sizeof(fx->sidecar))
        return false;
    fx->sidecar_len = (size_t)n;
    return true;
}

static bool zf_fastobj_mkdir(const char *path)
{
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
        return false;
    return true;
}

static bool zf_fastobj_write_pair(const char *cache_dir,
                                  const struct zf_fastobj_fixture *fx,
                                  bool sidecar)
{
    char obj_path[4096], side_path[4096], shard[4096], objects[4096];
    if (!vcs_fastobj_cache_paths(cache_dir, fx->key_hex, obj_path,
                                 sizeof(obj_path), side_path,
                                 sizeof(side_path)))
        return false;
    if (snprintf(shard, sizeof(shard), "%s", obj_path) >=
            (int)sizeof(shard) ||
        snprintf(objects, sizeof(objects), "%s/objects", cache_dir) >=
            (int)sizeof(objects))
        return false;
    char *slash = strrchr(shard, '/');
    if (!slash)
        return false;
    *slash = '\0';
    /* mkdir creates one level; the cache dir itself must come first. */
    if (!zf_fastobj_mkdir(cache_dir) || !zf_fastobj_mkdir(objects) ||
        !zf_fastobj_mkdir(shard))
        return false;
    FILE *f = fopen(obj_path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(fx->object, 1, fx->object_len, f) == fx->object_len;
    if (fclose(f) != 0)
        ok = false;
    if (!ok || !sidecar)
        return ok;
    f = fopen(side_path, "wb");
    if (!f)
        return false;
    ok = fwrite(fx->sidecar, 1, fx->sidecar_len, f) == fx->sidecar_len;
    if (fclose(f) != 0)
        ok = false;
    return ok;
}

static bool zf_fastobj_read_pair(const char *cache_dir,
                                 const struct zf_fastobj_fixture *fx,
                                 uint8_t *obj_out, size_t *obj_len,
                                 char *side_out, size_t *side_len)
{
    char obj_path[4096], side_path[4096];
    if (!vcs_fastobj_cache_paths(cache_dir, fx->key_hex, obj_path,
                                 sizeof(obj_path), side_path,
                                 sizeof(side_path)))
        return false;
    FILE *f = fopen(obj_path, "rb");
    if (!f)
        return false;
    size_t got = fread(obj_out, 1, fx->object_len, f);
    fclose(f);
    if (got != fx->object_len)
        return false;
    *obj_len = got;
    f = fopen(side_path, "rb");
    if (!f)
        return false;
    got = fread(side_out, 1, fx->sidecar_len, f);
    fclose(f);
    if (got != fx->sidecar_len)
        return false;
    *side_len = got;
    return true;
}

/* ── the fastobj cases ──────────────────────────────────────────────── */

static int zf_t_fastobj_export_admit(void)
{
    int failures = 0;
    TEST("zcode package fastobj export + admit: one entry round-trips") {
        char dd[1024], dd2[1024], cache[1200], cache2[1200];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "fobj-x");
        test_make_tmpdir(dd2, sizeof(dd2), "zcode_fetch", "fobj-x2");
        struct zf_fastobj_fixture fx;
        ASSERT(zf_fastobj_build(&fx));
        snprintf(cache, sizeof(cache), "%s/cache", dd);
        snprintf(cache2, sizeof(cache2), "%s/cache2", dd2);
        ASSERT(zf_fastobj_write_pair(cache, &fx, true));

        /* export: publish-here into the datadir store. */
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "cache_dir", cache);
        zcl_native_handle_zcode_package_fastobj_export(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        const char *root_hex =
            json_get_str(json_get(&c.reply.data, "package_root"));
        ASSERT(root_hex != NULL && strlen(root_hex) == 64u);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "entries")), 1);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "object_bytes")),
                  (int)fx.object_len);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "files")), 2);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "carrier_prefix")),
                      "zcl-fastobj-carrier.v1");
        /* The public-shape verdict is reported, not asserted away: the
         * carrier IS its own shape — a fixed directory of derived
         * objects, admitted only when the consumer-side verify re-derives
         * every hash from stored bytes — so an honest node serves it. */
        {
            const struct json_value *pos =
                json_get(&c.reply.data, "possession");
            ASSERT(pos != NULL);
            ASSERT(json_get_bool(json_get(pos, "tracked")));
            ASSERT(json_get_bool(json_get(pos, "complete")));
            ASSERT_STR_EQ(json_get_str(json_get(pos, "public_shape")),
                          "fastobj-carrier");
            ASSERT_STR_EQ(json_get_str(json_get(pos, "serve_rule")),
                          "fastobj-carrier");
            ASSERT(json_get_bool(json_get(pos, "public_serveable")));
            ASSERT(json_get_bool(json_get(pos, "would_serve")));
        }
        char root_copy[65];
        snprintf(root_copy, sizeof(root_copy), "%s", root_hex);
        zf_cmd_free(&c);

        /* Store-side truth, not the reply's word: the root is tracked and
         * complete in the datadir store the leaf claimed. */
        {
            uint8_t root[32];
            ASSERT(zcl_hex_decode(root_copy, root, 32));
            struct vcs_package_store *store = vcs_package_store_open(
                dd, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
            ASSERT(store != NULL);
            struct vcs_package_store_status st;
            memset(&st, 0, sizeof(st));
            ASSERT(vcs_package_store_package_status(store, root, &st));
            ASSERT(st.tracked && st.complete);
            vcs_package_store_close(store);
        }

        /* admit: consume-there into a fresh cache the leaf creates. */
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "package_root", root_copy);
        (void)json_push_kv_str(&c.input, "cache_dir", cache2);
        zcl_native_handle_zcode_package_fastobj_admit(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "entries")), 1);
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "object_bytes")),
                  (int)fx.object_len);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "package_root")),
                      root_copy);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "cache_dir")),
                      cache2);
        zf_cmd_free(&c);

        /* The reconstructed cache holds the exact bytes in the worker's
         * own layout. */
        {
            uint8_t obj[sizeof(fx.object)];
            char side[sizeof(fx.sidecar)];
            size_t obj_len = 0, side_len = 0;
            ASSERT(zf_fastobj_read_pair(cache2, &fx, obj, &obj_len, side,
                                        &side_len));
            ASSERT(obj_len == fx.object_len &&
                   memcmp(obj, fx.object, obj_len) == 0);
            ASSERT(side_len == fx.sidecar_len &&
                   memcmp(side, fx.sidecar, side_len) == 0);
        }

        /* The round-trip: exporting the SECOND cache elsewhere must
         * derive the SAME deterministic root. */
        zf_cmd_init(&c, dd2);
        (void)json_push_kv_str(&c.input, "cache_dir", cache2);
        zcl_native_handle_zcode_package_fastobj_export(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&c.reply.data, "package_root")),
                      root_copy);
        zf_cmd_free(&c);

        /* Idempotent: the same carrier over the identical cache passes,
         * through the `root` input alias the sibling leaves use. */
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "root", root_copy);
        (void)json_push_kv_str(&c.input, "cache_dir", cache2);
        zcl_native_handle_zcode_package_fastobj_admit(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zf_t_fastobj_refusals(void)
{
    int failures = 0;
    TEST("zcode package fastobj: named refusals at both leaves") {
        char dd[1024], torn[1200], good[1200];
        test_make_tmpdir(dd, sizeof(dd), "zcode_fetch", "fobj-ref");
        struct zf_fastobj_fixture fx;
        ASSERT(zf_fastobj_build(&fx));
        snprintf(torn, sizeof(torn), "%s/torn", dd);
        snprintf(good, sizeof(good), "%s/good", dd);

        /* A torn pair (object with no sidecar) refuses the WHOLE export
         * and names the rule. */
        ASSERT(zf_fastobj_write_pair(torn, &fx, false));
        struct zf_cmd c;
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "cache_dir", torn);
        zcl_native_handle_zcode_package_fastobj_export(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "CARRIER_EXPORT_REFUSED");
        ASSERT(strstr(c.reply.error.message, "torn") != NULL);
        zf_cmd_free(&c);

        /* Export without a cache_dir fails closed before any IO. */
        zf_cmd_init(&c, dd);
        zcl_native_handle_zcode_package_fastobj_export(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "MISSING_CACHE_DIR");
        zf_cmd_free(&c);

        /* Admit refusals: BAD_ROOT and MISSING_CACHE_DIR. */
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "package_root", "not-hex");
        (void)json_push_kv_str(&c.input, "cache_dir", good);
        zcl_native_handle_zcode_package_fastobj_admit(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "BAD_ROOT");
        zf_cmd_free(&c);
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "package_root", fx.key_hex);
        zcl_native_handle_zcode_package_fastobj_admit(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "MISSING_CACHE_DIR");
        zf_cmd_free(&c);

        /* UNKNOWN_PACKAGE: after a real export creates the store, a root
         * it never tracked fails by name. */
        ASSERT(zf_fastobj_write_pair(good, &fx, true));
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "cache_dir", good);
        zcl_native_handle_zcode_package_fastobj_export(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        zf_cmd_free(&c);
        zf_cmd_init(&c, dd);
        (void)json_push_kv_str(&c.input, "package_root",
                               "00000000000000000000000000000000000000000000"
                               "00000000000000000000");
        (void)json_push_kv_str(&c.input, "cache_dir", good);
        zcl_native_handle_zcode_package_fastobj_admit(&c.request, &c.reply);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_PACKAGE");
        zf_cmd_free(&c);
        PASS();
    } _test_next:;
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
    failures += zf_t_offered_one_shot_hosting();
    failures += zf_t_offered_live();
    failures += zf_t_fastobj_export_admit();
    failures += zf_t_fastobj_refusals();
    return failures;
}
