/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `z23 app publish` and `z23 app get`, the stranger's path: A
 * publishes a saved copy, B (another HOME and datadir, no file from A)
 * lists the catalog, fetches by identity, verifies and runs it. The
 * transport (bundle offer and fetch, board post and list) is a stub behind
 * zcl_app_offer_set_call, the way zcode_package_receive stands in for the
 * swarm; every board post the stub serves is really Ed25519-signed, and
 * every other leaf (share, verify, receive, build, open) is the real one.
 * Proven:
 *   - publish's plan writes nothing (no transport call, the HOME and
 *     datadir trees are unchanged) and its confirm offers the signed share
 *     bytes once and posts ONE zcl.app_offer.v1 entry to room apps that
 *     names exactly those bytes;
 *   - the entry round-trips through the catalog, and a malformed or
 *     tampered post is dropped;
 *   - get refuses a wrong sha256, root or publisher BEFORE any prompt and
 *     keeps nothing;
 *   - get hands the very bytes A offered to app.receive-copy, whose
 *     confirm shows A's full fingerprint and root, builds and opens;
 *   - MCP refuses app.publish and app.get (owner authority). */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#if !defined(_WIN32) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 700 /* nftw */
#endif
#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_app_offer.h"
#include "command/native_app_get_stage.h"
#include "command/native_app_fetch_progress.h"
#include "command/native_app_network.h"
#include "command/native_app_discover.h"
#include "command/app_selection.h"
#include "config/command_catalog.h"
#include "command/native_zcode_package_copy.h"
#include "command/native_app_library_command.h"

#if defined(_WIN32)
int test_app_get(void);
int test_app_get(void)
{
    printf("app get... SKIP (the copy open spawns through resident_launch, "
           "which refuses on Windows)\n");
    return 0;
}
#else

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha256.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_manifest.h"
#include "util/file_io.h"

#include <ftw.h>
#include <errno.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#define TAG_PATH 1400
#define TAG_CARRIER \
    "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00"
#define TAG_ONION \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
#define TAG_ENDPOINT TAG_ONION ":28133"
#define TAG_LOCAL_HOST "1111111111111111111111111111111111111111111111111111111111111111"
#define TAG_TEXT (ZCL_APP_OFFER_TEXT_MAX + 1u)

int zcl_test_app_run_copy_poll(long pid);
static int tag_process_observation(void)
{
    int failures = 0;
    TEST("app get: resident readiness rejects an unobservable process") {
        pid_t child = fork();
        if (child == 0) { for (;;) pause(); }
        int alive = child > 0 ? zcl_test_app_run_copy_poll((long)child) : -1;
        if (child > 0) { (void)kill(child, SIGKILL); (void)waitpid(child, NULL, 0); }
        int absent = zcl_test_app_run_copy_poll(2147483647L);
        ASSERT(child > 0 && alive == 0 && absent == 2);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the stub transport ─────────────────────────────────────────────── */

struct tag_stub {
    int offers, posts, lists, catalog_lists, shows, fetches, enables;
    uint8_t *bytes; /* what A's node was handed to offer */
    size_t len;
    char sha[65];
    char text[TAG_TEXT]; /* what A posted */
    char result_text[TAG_TEXT];
    char enable_text[TAG_TEXT];
    char room[40], kind[16], scope[16];
    int64_t ttl;
    struct json_value board; /* the posts B's node holds */
    bool tamper;             /* the fetch delivers other bytes */
    bool malformed_board;
    int show_mode;
    int page_mode;
    bool fetch_partial;
    bool onion_unavailable;
    bool onion_changed;
    bool malformed_post_id;
    bool fail_result_post;
    bool change_after_offer, bad_host_offer, fail_host_post, change_staged_after_receive;
    bool fail_host_output_alloc;
    int fetch_failures;
    char fetch_root[65], fetch_peer[96], fetch_out[TAG_PATH];
};

static struct tag_stub g_tag;
static bool tag_require_fetch_progress;
static atomic_bool tag_fetch_progress_seen;
static atomic_bool tag_fetch_progress_release;
static atomic_bool tag_fetch_progress_entered, tag_fetch_progress_timeout;
static int g_tag_rpc_mode;
static bool tag_capture_signed_post(struct zcl_command_reply *out);

extern bool zcl_app_get_host_reply_valid_for_testing(const struct json_value *, const char *);
extern void zcl_test_app_get_host_enabled(const char *, const char *, const char *, struct zcl_command_reply *);
extern bool zcl_test_app_publish_next(char *, size_t, const char *, const char *, const char *, const char *);

static bool tag_host_reply_case(const char *ok_field, const char *host,
                                const char *carrier, const char *generation)
{
    char wire[600];
    int n = snprintf(wire, sizeof(wire), "{%s\"host\":\"%s\",\"carrier\":\"%s\",\"enabled\":true,\"generation\":%s}",
                     ok_field, host, carrier, generation);
    struct json_value body; json_init(&body);
    bool valid = n > 0 && (size_t)n < sizeof(wire) && json_read(&body, wire, (size_t)n) &&
                 zcl_app_get_host_reply_valid_for_testing(&body, TAG_CARRIER);
    json_free(&body);
    return valid;
}
static bool tag_host_missing_hint(void)
{
    char datadir[4300], wire[8192]; memset(datadir, '\'', sizeof(datadir) - 1);
    datadir[0] = '/'; datadir[sizeof(datadir) - 1] = 0;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_get.v1");
    zcl_test_app_get_host_enabled(datadir, TAG_LOCAL_HOST, TAG_CARRIER, &reply);
    const struct zcl_command_spec *spec = asf_spec("app.get");
    size_t n = spec ? zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, &reply, wire, sizeof(wire)) : 0;
    struct json_value decoded; json_init(&decoded);
    bool parsed = n && n < sizeof(wire) && json_read(&decoded, wire, n);
    const struct json_value *facts = json_get(json_get(&decoded, "error"), "facts");
    const char *host = zcl_package_copy_str(facts, "hosting_host"), *carrier = zcl_package_copy_str(facts, "hosting_carrier");
    bool ok = parsed && reply.error.mutated && !strcmp(reply.error.code, "HOSTING_RESULT_UNAVAILABLE") &&
        json_get_bool(json_get(facts, "hosting_enabled")) && host && carrier &&
        !strcmp(host, TAG_LOCAL_HOST) && !strcmp(carrier, TAG_CARRIER) &&
        json_get_int(json_get(facts, "hosting_generation")) == 1;
    json_free(&decoded); zcl_command_reply_free(&reply); return ok;
}

static char *tag_onion_rpc_fault(int mode)
{
    switch (mode) {
    case 1: return strdup("not JSON");
    case 2: return strdup("{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"starting\",\"tor_ready\":false,\"onion_service_ready\":false,\"onion_address\":\"\",\"p2p_publish_ready\":false,\"port_mapping\":{\"routes\":[]}}");
    case 3: return strdup("{\"schema\":\"wrong\",\"bootstrap_state\":\"ready\",\"tor_ready\":true,\"onion_service_ready\":true,\"onion_address\":\"x\"}");
    case 4: { char *s = malloc(65538); if (s) { memset(s, 'x', 65537); s[65537] = '\0'; } return s; }
    case 5: return strdup("{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"ready\",\"tor_ready\":true,\"onion_service_ready\":true,\"onion_address\":\"" TAG_ONION "\",\"p2p_publish_ready\":true,\"port_mapping\":{\"routes\":[{\"name\":\"p2p_tcp\",\"virtual_port\":28133,\"installed\":true},{\"name\":\"p2p_tcp\",\"virtual_port\":28134,\"installed\":true}]}}");
    case 7: return strdup("{\"error\":{\"message\":\"offline\"}}");
    case 8: return strdup("{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"ready\",\"tor_ready\":true,\"onion_service_ready\":true,\"onion_address\":\"" TAG_ONION "\",\"p2p_publish_ready\":true,\"port_mapping\":{\"routes\":[{\"name\":\"p2p_tcp\",\"virtual_port\":65536,\"installed\":true}]}}");
    case 9: return strdup("{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"ready\",\"tor_ready\":false,\"onion_service_ready\":true,\"onion_address\":\"" TAG_ONION "\",\"p2p_publish_ready\":true,\"port_mapping\":{\"routes\":[{\"name\":\"p2p_tcp\",\"virtual_port\":28133,\"installed\":true}]}}");
    default: return NULL;
    }
}

/* A busy node's bounded dial ledger precedes the installed port mapping in
 * onionstatus. Exercise the real registry/CLI bridge, not the offer stub. */
static char *tag_busy_onion_rpc(const char *method, const char *params)
{
    (void)params;
    if (strcmp(method, "onionstatus")) return strdup("null");
    if (g_tag_rpc_mode) return tag_onion_rpc_fault(g_tag_rpc_mode);
    char wire[8192];
    int n = snprintf(wire, sizeof(wire), "{\"schema\":\"zcl.onion_status.v1\",\"bootstrap_state\":\"ready\",\"tor_ready\":true,\"onion_service_ready\":true,\"onion_address\":\"%s\",\"p2p_publish_ready\":true,\"recent_dials\":[", TAG_ONION);
    if (n <= 0 || (size_t)n >= sizeof(wire)) return NULL;
    size_t used = (size_t)n;
    for (int i = 0; i < 16; ++i) {
        n = snprintf(wire + used, sizeof(wire) - used,
            "%s{\"schema\":\"zcl.onion_dial_stages.v1\",\"target\":\"%s\",\"generation\":%d,\"active\":false,\"elapsed_ms\":1111,\"first_incomplete_stage\":\"complete\",\"dial_started\":1,\"stream_queued\":1,\"circuit_ready\":1,\"bridge_up\":1,\"open_refused\":0,\"circuit_timeout\":0,\"circuit_torn_down\":0,\"bridge_closed\":1,\"bytes_to_peer\":8192,\"bytes_from_peer\":1048576,\"peers_answered\":1}", i ? "," : "", TAG_ENDPOINT, i);
        if (n <= 0 || (size_t)n >= sizeof(wire) - used) return NULL;
        used += (size_t)n;
    }
    n = snprintf(wire + used, sizeof(wire) - used,
        "],\"port_mapping\":{\"routes\":[{\"name\":\"p2p_tcp\",\"virtual_port\":28133,\"installed\":true}]}}");
    return n > 0 && (size_t)n < sizeof(wire) - used ? strdup(wire) : NULL;
}

static int tag_busy_onion_bridge(void)
{
    int failures = 0;
    TEST("app host: busy onion status retains actual ready endpoint through the CLI bridge") {
        char host[63], endpoint[ZCL_APP_OFFER_ONION_MAX + 1u]; bool read = false;
        node_rpc_client_set_test_hook(tag_busy_onion_rpc);
        bool ready = zcl_app_offer_local_endpoint(host, endpoint, &read);
        bool right_endpoint = !strcmp(host, TAG_ONION) && !strcmp(endpoint, TAG_ENDPOINT);
        g_tag_rpc_mode = 1; bool bad_read = true;
        bool bad_ready = zcl_app_offer_local_endpoint(host, endpoint, &bad_read);
        g_tag_rpc_mode = 2; bool idle_read = false;
        bool idle_ready = zcl_app_offer_local_endpoint(host, endpoint, &idle_read);
        g_tag_rpc_mode = 3; bool schema_read = true;
        bool schema_ready = zcl_app_offer_local_endpoint(host, endpoint, &schema_read);
        g_tag_rpc_mode = 4; bool large_read = true;
        bool large_ready = zcl_app_offer_local_endpoint(host, endpoint, &large_read);
        g_tag_rpc_mode = 5; bool duplicate_read = false;
        bool duplicate_ready = zcl_app_offer_local_endpoint(host, endpoint, &duplicate_read);
        g_tag_rpc_mode = 6; bool null_read = true;
        bool null_ready = zcl_app_offer_local_endpoint(host, endpoint, &null_read);
        g_tag_rpc_mode = 7; bool error_read = true;
        bool error_ready = zcl_app_offer_local_endpoint(host, endpoint, &error_read);
        g_tag_rpc_mode = 8; bool port_read = false;
        bool port_ready = zcl_app_offer_local_endpoint(host, endpoint, &port_read);
        g_tag_rpc_mode = 9; bool contradiction_read = false;
        bool contradiction_ready = zcl_app_offer_local_endpoint(host, endpoint, &contradiction_read);
        g_tag_rpc_mode = 0;
        node_rpc_client_set_test_hook(NULL);
        ASSERT(read); ASSERT(ready); ASSERT(right_endpoint);
        ASSERT(!bad_read && !bad_ready); ASSERT(idle_read && !idle_ready);
        ASSERT(!schema_read && !schema_ready); ASSERT(!large_read && !large_ready);
        ASSERT(duplicate_read && !duplicate_ready);
        ASSERT(!null_read && !null_ready); ASSERT(!error_read && !error_ready);
        ASSERT(port_read && !port_ready);
        ASSERT(contradiction_read && !contradiction_ready);
        PASS();
    } _test_next:;
    return failures;
}

static void tag_sha(const uint8_t *b, size_t n, char hex[65])
{
    uint8_t d[32];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, b, n);
    sha256_finalize(&ctx, d);
    zcl_hex_encode(d, 32, hex);
}

static const char *tag_in(const struct json_value *in, const char *key)
{
    const char *s = json_get_str(json_get(in, key));
    return s ? s : "";
}

static bool tag_offer(const struct json_value *in, struct zcl_command_reply *out)
{
    free(g_tag.bytes);
    g_tag.bytes = NULL;
    if (!zcl_read_whole_file(tag_in(in, "file"), ZCL_APP_OFFER_SIZE_MAX,
                             &g_tag.bytes, &g_tag.len, "test.app_get"))
        return false;
    tag_sha(g_tag.bytes, g_tag.len, g_tag.sha);
    g_tag.offers++;
    if (g_tag.change_after_offer) g_tag.onion_changed = true;
    return json_push_kv_str(&out->data, "root", g_tag.bad_host_offer ? "bad" : TAG_CARRIER) &&
           json_push_kv_str(&out->data, "sha256", g_tag.sha) &&
           json_push_kv_int(&out->data, "size", (int64_t)g_tag.len) &&
           json_push_kv_bool(&out->data, "pinned", true);
}

static bool tag_change_staged(void)
{
    FILE *f = fopen(g_tag.fetch_out, "r+b");
    if (!f) return false;
    int c = fgetc(f); bool ok = c != EOF && fseek(f, 0, SEEK_SET) == 0 && fputc(c ^ 1, f) != EOF;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool tag_post_capture(const struct json_value *in,
                             struct zcl_command_reply *out)
{
    const struct json_value *ttl = json_get(in, "ttl");
    g_tag.posts++;
    bool result = strcmp(tag_in(in, "kind"), "result") == 0;
    if (result) (void)snprintf(g_tag.result_text, sizeof(g_tag.result_text), "%s", tag_in(in, "text"));
    else (void)snprintf(g_tag.text, sizeof(g_tag.text), "%s", tag_in(in, "text"));
    (void)snprintf(g_tag.room, sizeof(g_tag.room), "%s", tag_in(in, "room"));
    (void)snprintf(g_tag.kind, sizeof(g_tag.kind), "%s", tag_in(in, "kind"));
    (void)snprintf(g_tag.scope, sizeof(g_tag.scope), "%s",
                   tag_in(in, "scope"));
    g_tag.ttl = ttl && ttl->type == JSON_INT ? json_get_int(ttl) : 0;
    if (result && g_tag.change_staged_after_receive && !tag_change_staged()) return false;
    if (result && g_tag.fail_result_post) return false;
    if (!result && g_tag.fail_host_post) return false;
    if (g_tag.malformed_post_id) return json_push_kv_str(&out->data, "id", "bad");
    if (!result) return tag_capture_signed_post(out);
    return json_push_kv_str(&out->data, "id",
                            "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d"
                            "1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");
}

static void tag_wait_fetch_progress(void)
{
    if (tag_require_fetch_progress) {
        atomic_store(&tag_fetch_progress_entered, true);
        int64_t end = platform_time_monotonic_ms() + 30000;
        while (!atomic_load(&tag_fetch_progress_release) && platform_time_monotonic_ms() < end)
            platform_sleep_ms(1);
        if (!atomic_load(&tag_fetch_progress_release)) atomic_store(&tag_fetch_progress_timeout, true);
    }
}
static bool tag_fetch(const struct json_value *in, struct zcl_command_reply *out)
{
    tag_wait_fetch_progress();
    g_tag.fetches++;
    (void)snprintf(g_tag.fetch_root, sizeof(g_tag.fetch_root), "%s",
                   tag_in(in, "root"));
    (void)snprintf(g_tag.fetch_peer, sizeof(g_tag.fetch_peer), "%s",
                   tag_in(in, "peer"));
    (void)snprintf(g_tag.fetch_out, sizeof(g_tag.fetch_out), "%s",
                   tag_in(in, "out"));
    if (g_tag.fetch_failures > 0) { g_tag.fetch_failures--; return false; }
    if (!g_tag.bytes || g_tag.len < 64)
        return false;
    if (g_tag.fetch_partial) {
        FILE *partial = fopen(g_tag.fetch_out, "wbx");
        if (partial) { (void)fputs("partial", partial); (void)fclose(partial); }
        return false;
    }
    if (g_tag.tamper)
        g_tag.bytes[g_tag.len / 2] ^= 0x01;
    FILE *f = fopen(g_tag.fetch_out, "wbx");
    bool ok = f && fwrite(g_tag.bytes, 1, g_tag.len, f) == g_tag.len;
    ok = f ? fclose(f) == 0 && ok : false;
    if (g_tag.tamper)
        g_tag.bytes[g_tag.len / 2] ^= 0x01;
    return ok && json_push_kv_str(&out->data, "state", "complete");
}

static bool tag_onion_status(struct zcl_command_reply *out)
{
    struct json_value mapping, routes, route;
    json_init(&mapping); json_set_object(&mapping);
    json_init(&routes); json_set_array(&routes);
    json_init(&route); json_set_object(&route);
    bool ok = json_push_kv_str(&route, "name", "p2p_tcp") &&
              json_push_kv_bool(&route, "installed", !g_tag.onion_unavailable) &&
              json_push_kv_int(&route, "virtual_port", g_tag.onion_changed ? 28134 : 28133) &&
              json_push_back(&routes, &route) && json_push_kv(&mapping, "routes", &routes) &&
              json_push_kv_str(&out->data, "bootstrap_state", g_tag.onion_unavailable ? "publishing" : "ready") &&
              json_push_kv_bool(&out->data, "tor_ready", !g_tag.onion_unavailable) &&
              json_push_kv_bool(&out->data, "onion_service_ready", !g_tag.onion_unavailable) &&
              json_push_kv_bool(&out->data, "p2p_publish_ready", !g_tag.onion_unavailable) &&
              json_push_kv_str(&out->data, "onion_address", TAG_ONION) &&
              json_push_kv(&out->data, "port_mapping", &mapping);
    json_free(&route); json_free(&routes); json_free(&mapping);
    return ok;
}

static bool tag_host_enable(const struct json_value *in, struct zcl_command_reply *out)
{
    struct zcl_app_offer offer;
    const char *text = tag_in(in, "offer");
    g_tag.enables++;
    bool ok = !g_tag.fail_host_post && text &&
         zcl_app_offer_parse(text, strlen(text), &offer) &&
         json_get_bool(json_get(in, "confirm")) &&
         strlen(tag_in(in, "plan_id")) == 64 && strlen(tag_in(in, "token")) == 32 &&
         json_push_kv_bool(&out->data, "ok", true) &&
         json_push_kv_str(&out->data, "host", TAG_LOCAL_HOST) &&
         json_push_kv_str(&out->data, "carrier", offer.carrier) &&
         json_push_kv_int(&out->data, "generation", 1) &&
         json_push_kv_bool(&out->data, "enabled", true);
    if (ok) (void)snprintf(g_tag.enable_text, sizeof(g_tag.enable_text), "%s", text);
    if (ok && g_tag.fail_host_output_alloc) zcl_alloc_fault_fail_next("json_push_kv_key");
    return ok;
}

static bool tag_show(const struct json_value *in, struct zcl_command_reply *out)
{
    g_tag.shows++;
    if (g_tag.show_mode == 1) return false;
    for (size_t i = 0; i < json_size(&g_tag.board); ++i) {
        const struct json_value *post = json_at(&g_tag.board, i);
        const char *id = json_get_str(json_get(post, "id"));
        if (id && (g_tag.show_mode == 2 || !strcmp(id, tag_in(in, "id"))))
            return json_copy_checked(&out->data, post);
    }
    return false;
}

static size_t tag_page_start(int64_t before, const char *id)
{
    size_t start = 0, total = json_size(&g_tag.board);
    if (before) for (; start < total; ++start) {
        const struct json_value *p = json_at(&g_tag.board, start);
        int64_t t = json_get_int(json_get(p, "created_at"));
        const char *key = tag_in(p, "id");
        if (t < before || (t == before && strcmp(key, id) < 0)) break;
    }
    return start;
}
static bool tag_list_page(const struct json_value *in, struct zcl_command_reply *out)
{
        struct json_value posts; json_init(&posts); json_set_array(&posts);
        int64_t before = json_get_int(json_get(in, "before_created_at"));
        const char *id = tag_in(in, "before_id"); size_t total = json_size(&g_tag.board);
        size_t start = tag_page_start(before, id);
        size_t end = start + ZCL_APP_OFFER_ROWS_MAX;
        if (end > total) end = total;
        bool ok = true;
        for (size_t i = start; ok && i < end; ++i) ok = json_push_back(&posts, json_at(&g_tag.board, i));
        bool more = end < total;
        ok = ok && json_push_kv(&out->data, "posts", &posts) &&
            json_push_kv_int(&out->data, "returned", (int64_t)(end - start)) &&
            json_push_kv_bool(&out->data, "has_more", more);
        if (ok && more) {
            const struct json_value *last = json_at(&g_tag.board, end - 1);
            ok = json_push_kv_int(&out->data, "next_created_at", g_tag.page_mode == 3 && before ? before : json_get_int(json_get(last, "created_at"))) &&
                json_push_kv_str(&out->data, "next_id", g_tag.page_mode == 2 ? "malformed" :
                    g_tag.page_mode == 3 && before ? id : tag_in(last, "id"));
        }
        json_free(&posts); return ok;
}
static bool tag_list(const struct json_value *in, struct zcl_command_reply *out)
{
    g_tag.lists++;
    if (!strcmp(tag_in(in, "kind"), "offer")) g_tag.catalog_lists++;
    if (g_tag.malformed_board) return true;
    if (g_tag.page_mode == 4) {
        struct json_value posts; json_init(&posts); json_set_array(&posts);
        bool ok = json_push_back(&posts, json_at(&g_tag.board, 0)) &&
            json_push_kv(&out->data, "posts", &posts);
        json_free(&posts); return ok;
    }
    if (g_tag.page_mode) return tag_list_page(in, out);
    return json_push_kv(&out->data, "posts", &g_tag.board) &&
        json_push_kv_int(&out->data, "returned", (int64_t)json_size(&g_tag.board)) &&
        json_push_kv_bool(&out->data, "has_more", false);
}

static bool tag_call(const char *path, const struct json_value *in,
                     struct zcl_command_reply *out)
{
    bool ok;
    zcl_command_reply_init(out, "zcl.test.app_get.stub.v1");
    if (strcmp(path, ZCL_APP_OFFER_BUNDLE_OFFER) == 0)
        ok = tag_offer(in, out);
    else if (strcmp(path, ZCL_APP_OFFER_BOARD_POST) == 0)
        ok = tag_post_capture(in, out);
    else if (strcmp(path, ZCL_APP_OFFER_BUNDLE_FETCH) == 0)
        ok = tag_fetch(in, out);
    else if (strcmp(path, ZCL_APP_OFFER_BOARD_LIST) == 0)
        ok = tag_list(in, out);
    else if (strcmp(path, ZCL_APP_OFFER_BOARD_SHOW) == 0)
        ok = tag_show(in, out);
    else if (strcmp(path, "core.network.onion.status") == 0)
        ok = tag_onion_status(out);
    else if (strcmp(path, ZCL_APP_HOST_ENABLE) == 0)
        ok = tag_host_enable(in, out);
    else {
        zcl_command_reply_free(out);
        return zcl_app_inner_call(path, in, out, NULL);
    }
    if (!ok)
        zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "STUB_FAILED",
                               "execute", false, false, "stub transport",
                               path);
    return ok;
}

/* ── signed board posts, as B's node renders them ───────────────────── */

struct tag_post_spec {
    const char *text;
    const char *room;
    uint8_t kind;
    bool tamper; /* one byte of the text changes after signing */
};

static void tag_identity(uint8_t sk[32], uint8_t pk[32], uint8_t byte)
{
    uint8_t seed[32];
    memset(seed, byte, sizeof(seed));
    ed25519_keypair(pk, sk, seed);
}

#define TAG_NET_RELAY TAG_ONION
#define TAG_NET_HOST "bcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxy.onion"
struct tag_net {
    uint8_t *bytes, *manifest;
    size_t size, manifest_len;
    char frame[8192], badframe[8192], id[65];
    int fault, calls, cancel_checks, cancel_at;
};

static bool tag_net_bad_frame(struct tag_net *f, struct fleet_board_post *p,
                              const uint8_t sk[32], const uint8_t pk[32])
{
    uint8_t wire[4096]; size_t len = 0;
    snprintf(p->text, sizeof(p->text), "not an app");
    p->text_len = (uint32_t)strlen(p->text);
    bool ok = fleet_board_post_sign(p, sk, pk) == FLEET_BOARD_OK &&
        fleet_board_frame_encode_post(p, wire, sizeof(wire), &len) == FLEET_BOARD_OK &&
        len * 2u + 1u <= sizeof(f->badframe);
    if (ok) zcl_hex_encode(wire, len, f->badframe);
    return ok;
}

static bool tag_net_init(struct tag_net *f)
{
    memset(f, 0, sizeof(*f)); f->size = VCS_PACKAGE_CHUNK_BYTES + 13u;
    f->bytes = zcl_malloc(f->size, "test.network.bytes");
    if (!f->bytes) return false;
    for (size_t i = 0; i < f->size; i++) f->bytes[i] = (uint8_t)(i * 31u);
    uint8_t hashes[64], root[32] = {0}, sha[32]; struct sha256_ctx ctx;
    bool ok = vcs_package_chunk_hash(f->bytes, VCS_PACKAGE_CHUNK_BYTES, hashes) &&
        vcs_package_chunk_hash(f->bytes + VCS_PACKAGE_CHUNK_BYTES, 13, hashes + 32);
    struct vcs_package_manifest m; vcs_package_manifest_init(&m);
    ok = ok && vcs_package_manifest_add(&m, VCS_BUNDLE_PATH, VCS_PACKAGE_MODE_FILE,
                                        f->size, hashes, 2) &&
        vcs_package_manifest_root(&m, root) &&
        vcs_package_manifest_serialize(&m, &f->manifest, &f->manifest_len);
    vcs_package_manifest_free(&m);
    struct zcl_app_offer offer = {0};
    snprintf(offer.name, sizeof(offer.name), "test/app");
    memset(offer.root, '1', 64); offer.root[64] = 0;
    memset(offer.publisher, '2', 66); offer.publisher[66] = 0;
    zcl_hex_encode(root, 32, offer.carrier);
    sha256_init(&ctx); sha256_write(&ctx, f->bytes, f->size); sha256_finalize(&ctx, sha);
    zcl_hex_encode(sha, 32, offer.sha256); offer.size = (int64_t)f->size;
    snprintf(offer.onion, sizeof(offer.onion), "%s:28133", TAG_NET_HOST);
    struct fleet_board_post *p = zcl_calloc(1, sizeof(*p), "test.network.post");
    if (!p) return false;
    p->kind = FLEET_BOARD_KIND_OFFER; p->scope = FLEET_BOARD_SCOPE_PUBLIC;
    p->created_at = (uint64_t)platform_time_wall_unix(); p->ttl = 3600;
    snprintf(p->room, sizeof(p->room), "apps");
    ok = ok && zcl_app_offer_format(&offer, p->text, sizeof(p->text));
    p->text_len = (uint32_t)strlen(p->text);
    uint8_t sk[32], pk[32], wire[4096]; size_t wire_len = 0;
    tag_identity(sk, pk, 42);
    ok = ok && fleet_board_post_sign(p, sk, pk) == FLEET_BOARD_OK &&
        fleet_board_frame_encode_post(p, wire, sizeof(wire), &wire_len) == FLEET_BOARD_OK &&
        wire_len * 2u + 1u <= sizeof(f->frame);
    if (ok) {
        zcl_hex_encode(wire, wire_len, f->frame); fleet_board_id_to_hex(p->id, f->id);
        ok = tag_net_bad_frame(f, p, sk, pk);
    }
    free(p); return ok;
}

static bool tag_net_slice(struct tag_net *f, const char *path,
                          const uint8_t **data, size_t *size)
{
    unsigned chunk = 0; size_t offset = 0;
    const char *p = strstr(path, "/0/");
    if (!p || sscanf(p, "/0/%u/slice/%zu", &chunk, &offset) != 2) return false;
    size_t start = (size_t)chunk * VCS_PACKAGE_CHUNK_BYTES + offset;
    if (start >= f->size || offset >= VCS_PACKAGE_CHUNK_BYTES) return false;
    *size = f->size - start; if (*size > 48u * 1024u) *size = 48u * 1024u;
    if (*size > VCS_PACKAGE_CHUNK_BYTES - offset) *size = VCS_PACKAGE_CHUNK_BYTES - offset;
    *data = f->bytes + start; return true;
}
static bool tag_net_board_fault(struct tag_net *f, uint8_t *out, size_t cap, size_t *size)
{
    if (f->fault == 1) {
        if (*size == cap) return false;
        out[*size] = 0;
        char *frame = strstr((char *)out, "\"frames\":[\"");
        if (!frame) return false;
        frame += strlen("\"frames\":[\"");
        frame[20] = frame[20] == '0' ? '1' : '0';
    }
    if (f->fault == 5 && *size) (*size)--;
    if (f->fault == 6) *size = cap + 1u;
    return true;
}
static bool tag_net_fault(struct tag_net *f, const char *path, uint8_t *out,
                          size_t cap, size_t *size)
{
    if (!strncmp(path, "/board", 6))
        return tag_net_board_fault(f, out, cap, size);
    bool slice = strstr(path, "/slice/") != NULL;
    if (f->fault == 2 && slice && *size) out[0] ^= 1;
    if (f->fault == 3 && slice && *size) (*size)--;
    if (f->fault == 4 && !slice && *size) out[*size - 1] ^= 1;
    return true;
}
static bool tag_net_board_body(struct tag_net *f, char *json, size_t cap, size_t *size)
{
    char bad[8192]; const char *second = "";
    if (f->fault == 8 || f->fault == 9) {
        snprintf(bad, sizeof(bad), "%s", f->fault == 8 ? f->badframe : f->frame);
        if (f->fault == 9) bad[20] = bad[20] == '0' ? '1' : '0';
        second = bad;
    }
    int n = snprintf(json, cap, "{\"schema\":\"zcl.board_apps.v1\",\"version\":1,\"frames\":[\"%s\"%s%s%s],\"incomplete\":false}",
                     f->frame, second[0] ? ",\"" : "", second, second[0] ? "\"" : "");
    if (n < 0 || (size_t)n >= cap) return false;
    *size = (size_t)n; return true;
}
static bool tag_net_fetch(void *context, const char *onion, const char *path,
                          uint8_t *out, size_t cap, size_t *len, int *status,
                          unsigned timeout_ms)
{
    struct tag_net *f = context; f->calls++;
    if (!timeout_ms) return false;
    const uint8_t *data = NULL; size_t size = 0; char json[17000];
    if (!strncmp(path, "/board/apps/v1", 14)) {
        if (strcmp(onion, TAG_NET_RELAY)) return false;
        if (!tag_net_board_body(f, json, sizeof(json), &size)) return false;
        data = (const uint8_t *)json;
    } else {
        if (strcmp(onion, TAG_NET_HOST)) return false;
        if (strstr(path, "/slice/")) {
            if (!tag_net_slice(f, path, &data, &size)) return false;
        } else { data = f->manifest; size = f->manifest_len; }
    }
    if (size > cap) return false;
    memcpy(out, data, size);
    if (!tag_net_fault(f, path, out, cap, &size)) return false;
    *len = size; *status = 200; return true;
}

static bool tag_net_wrong_sha(struct tag_net *f)
{
    uint8_t wire[4096], sk[32], pk[32]; size_t n = 0;
    struct fleet_board_post *p = zcl_calloc(1, sizeof(*p), "test.network.sha");
    if (!p) return false;
    struct zcl_app_offer offer;
    bool ok = zcl_hex_decode_n(f->frame, wire, sizeof(wire), &n) &&
        fleet_board_frame_decode_post(wire, n, p) == FLEET_BOARD_OK &&
        zcl_app_offer_parse(p->text, p->text_len, &offer);
    if (ok) {
        offer.sha256[0] = offer.sha256[0] == '0' ? '1' : '0';
        ok = zcl_app_offer_format(&offer, p->text, sizeof(p->text));
        p->text_len = (uint32_t)strlen(p->text);
    }
    tag_identity(sk, pk, 42);
    ok = ok && fleet_board_post_sign(p, sk, pk) == FLEET_BOARD_OK &&
        fleet_board_frame_encode_post(p, wire, sizeof(wire), &n) == FLEET_BOARD_OK &&
        n * 2u + 1u <= sizeof(f->frame);
    if (ok) { zcl_hex_encode(wire, n, f->frame); fleet_board_id_to_hex(p->id, f->id); }
    free(p); return ok;
}
static bool tag_net_cancelled(void *context)
{
    struct tag_net *f = context;
    f->cancel_checks++;
    return f->fault == 7 || (f->cancel_at && f->cancel_checks >= f->cancel_at);
}
static bool tag_network_quota(struct tag_net *f, struct app_network_transport *t,
                              const struct zcl_app_offer_row *row, int64_t now)
{
    char dir[PATH_MAX] = ""; uint8_t seed_root[32], *out = NULL, seed[8];
    size_t len = 0, seed_len = 0; bool mutated = false;
    enum app_network_error error = APP_NETWORK_OK;
    bool made = test_mkdtemp(dir, sizeof(dir), "app_network_quota") != NULL;
    struct vcs_package_store *store = made ? vcs_package_store_open(dir, VCS_PACKAGE_CHUNK_BYTES) : NULL;
    const uint8_t keep[] = "keep";
    bool ok = store && vcs_bundle_put_to_no_evict(store, keep, sizeof(keep), seed_root) == VCS_BUNDLE_OK;
    f->fault = 0;
    ok = ok && !app_network_carrier(t, TAG_NET_RELAY, TAG_NET_HOST, row, now,
                                    store, &out, &len, &mutated, &error) &&
         mutated && !out && error == APP_NETWORK_STORE_REFUSED &&
         vcs_bundle_get_from(store, seed_root, seed, sizeof(seed), &seed_len) == VCS_BUNDLE_OK &&
         seed_len == sizeof(keep) && !memcmp(seed, keep, sizeof(keep));
    free(out); if (store) vcs_package_store_close(store);
    if (made) ok = test_rm_rf_recursive(dir) == 0 && ok;
    return ok;
}

static bool tag_network_cancellation(struct tag_net *f, struct app_network_transport *t,
                                     const struct zcl_app_offer_row *row,
                                     struct vcs_package_store *store, int64_t now)
{
    uint8_t *out = NULL; size_t len = 0; bool mutated = false;
    enum app_network_error error = APP_NETWORK_OK;
    int before_checks = f->cancel_checks;
    bool ok = app_network_carrier(t, TAG_NET_RELAY, TAG_NET_HOST, row, now,
                                   store, &out, &len, &mutated, &error) && mutated &&
         len == f->size && memcmp(out, f->bytes, len) == 0;
    free(out); out = NULL;
    int carrier_checks = f->cancel_checks - before_checks;
    f->cancel_at = f->cancel_checks + carrier_checks;
    mutated = false;
    ok = ok && carrier_checks > 0 &&
         !app_network_carrier(t, TAG_NET_RELAY, TAG_NET_HOST, row, now,
                              store, &out, &len, &mutated, &error) &&
         mutated && !out && len == 0 && error == APP_NETWORK_CANCELLED;
    f->cancel_at = 0; free(out); return ok;
}
static bool tag_network_bad_carriers(struct tag_net *f, struct app_network_transport *t,
                                     const struct zcl_app_offer_row *row,
                                     struct vcs_package_store *store, int64_t now)
{
    for (int fault = 2; fault <= 4; fault++) {
        uint8_t *out = NULL; size_t len = 0; bool mutated = false;
        enum app_network_error error = APP_NETWORK_OK; f->fault = fault;
        bool refused = !app_network_carrier(t, TAG_NET_RELAY, TAG_NET_HOST, row, now,
                                            store, &out, &len, &mutated, &error);
        free(out);
        if (!refused || mutated != (fault != 4)) return false;
        if (fault != 4 && error != APP_NETWORK_CONTENT_MISMATCH) return false;
    }
    f->fault = 0; return true;
}
static bool tag_network_bad_catalog(struct tag_net *f, struct app_network_transport *t, int64_t now)
{
    struct zcl_app_offer_row row, rows[4]; size_t count = 7; bool incomplete = true;
    enum app_network_error error;
    if (app_network_exact(t, TAG_NET_RELAY,
        "0000000000000000000000000000000000000000000000000000000000000000", now, &row, &error) ||
        app_network_exact(t, TAG_NET_RELAY, f->id, now + 7200, &row, &error)) return false;
    f->fault = 1;
    if (app_network_exact(t, TAG_NET_RELAY, f->id, now, &row, &error) || error != APP_NETWORK_INVALID_RESPONSE) return false;
    for (int fault = 5; fault <= 6; fault++) {
        f->fault = fault; count = 7; incomplete = true;
        if (app_network_catalog(t, TAG_NET_RELAY, now, rows, 4, &count, &incomplete, &error) || count || incomplete) return false;
    }
    for (int fault = 8; fault <= 9; fault++) {
        f->fault = fault; count = 0; incomplete = false;
        if (!app_network_catalog(t, TAG_NET_RELAY, now, rows, 4, &count, &incomplete, &error) ||
            count != 1 || !incomplete || strcmp(rows[0].post_id, f->id)) return false;
    }
    f->fault = 0; return true;
}
static bool tag_network_bad_sha(struct tag_net *f, struct app_network_transport *t,
                                struct vcs_package_store *store, int64_t now)
{
    struct zcl_app_offer_row row; uint8_t *out = NULL; size_t len = 0; bool mutated = false;
    enum app_network_error error;
    bool ok = tag_net_wrong_sha(f) && app_network_exact(t, TAG_NET_RELAY, f->id, now, &row, &error) &&
        !app_network_carrier(t, TAG_NET_RELAY, TAG_NET_HOST, &row, now, store, &out, &len, &mutated, &error) &&
        mutated && !out && error == APP_NETWORK_CONTENT_MISMATCH && tag_network_quota(f, t, &row, now);
    free(out); f->fault = 7; int before = f->calls;
    return ok && !app_network_exact(t, TAG_NET_RELAY, f->id, now, &row, &error) &&
           error == APP_NETWORK_CANCELLED && f->calls == before;
}
static bool tag_network_exercise(void)
{
    struct tag_net f; bool ok = tag_net_init(&f);
    char dir[PATH_MAX] = "";
    if (ok) ok = test_mkdtemp(dir, sizeof(dir), "app_network") != NULL;
    struct vcs_package_store *store = ok ? vcs_package_store_open(dir, vcs_package_store_quota_bytes()) : NULL;
    struct app_network_transport t = {.fetch = tag_net_fetch, .cancelled = tag_net_cancelled,
                                      .context = &f, .timeout_ms = 120000};
    struct zcl_app_offer_row row = {0}, rows[4] = {0}; size_t count = 0; bool incomplete = true;
    enum app_network_error error = APP_NETWORK_OK; int64_t now = platform_time_wall_unix();
    ok = ok && store && app_network_catalog(&t, TAG_NET_RELAY, now, rows, 4, &count, &incomplete, &error) &&
         count == 1 && !incomplete && app_network_exact(&t, TAG_NET_RELAY, f.id, now, &row, &error) &&
         tag_network_cancellation(&f, &t, &row, store, now) &&
         tag_network_bad_carriers(&f, &t, &row, store, now) &&
         tag_network_bad_catalog(&f, &t, now) && tag_network_bad_sha(&f, &t, store, now);
    if (store) vcs_package_store_close(store);
    if (dir[0]) ok = test_rm_rf_recursive(dir) == 0 && ok;
    free(f.bytes); free(f.manifest); return ok;
}
static int tag_network_test(void)
{
    int failures = 0;
    TEST("app network: independently verify frames and sliced carrier") {
        ASSERT(tag_network_exercise()); PASS();
    } _test_next:;
    return failures;
}

static bool tag_render(const struct fleet_board_post *p,
                       struct json_value *o)
{
    char id[65], host[65], ref[65], sig[2u * FLEET_BOARD_SIG_BYTES + 1u];
    fleet_board_id_to_hex(p->id, id);
    fleet_board_id_to_hex(p->host_pubkey, host);
    fleet_board_id_to_hex(p->ref, ref);
    zcl_hex_encode(p->signature, FLEET_BOARD_SIG_BYTES, sig);
    json_init(o);
    json_set_object(o);
    return json_push_kv_str(o, "id", id) &&
           json_push_kv_str(o, "kind", fleet_board_kind_name(p->kind)) &&
           json_push_kv_int(o, "created_at", (int64_t)p->created_at) &&
           json_push_kv_int(o, "ttl", (int64_t)p->ttl) &&
           json_push_kv_str(o, "ref", ref) &&
           json_push_kv_str(o, "host", host) &&
           json_push_kv_str(o, "signature", sig) &&
           json_push_kv_str(o, "agent", p->agent) &&
           json_push_kv_str(o, "scope", "public") &&
           json_push_kv_str(o, "room", p->room) &&
           json_push_kv_str(o, "text", p->text) &&
           json_push_kv_int(o, "text_len", (int64_t)p->text_len);
}

static bool tag_tamper(struct fleet_board_post *p)
{
    char *hex = strstr(p->text, "\"root\":\"");
    if (!hex) {
        hex = strstr(p->text, "\"image\":\"");
        if (hex) hex++;
    }
    if (!hex) return false;
    hex[8] = hex[8] == 'a' ? 'b' : 'a';
    return true;
}

/* One signed post appended to the stub board. */
static bool tag_board_add_as(const struct tag_post_spec *s, int64_t age,
                             uint8_t identity)
{
    uint8_t sk[32], pk[32];
    struct json_value o;
    struct fleet_board_post *p = calloc(1, sizeof(*p));
    tag_identity(sk, pk, identity);
    bool ok = p && strlen(s->text) < sizeof(p->text);
    if (ok) {
        p->kind = s->kind;
        p->scope = FLEET_BOARD_SCOPE_PUBLIC;
        p->created_at = (uint64_t)(platform_time_wall_unix() - age);
        p->ttl = 86400;
        (void)snprintf(p->room, sizeof(p->room), "%s", s->room);
        (void)snprintf(p->agent, sizeof(p->agent), "app.publish");
        (void)snprintf(p->text, sizeof(p->text), "%s", s->text);
        p->text_len = (uint32_t)strlen(p->text);
        ok = fleet_board_post_sign(p, sk, pk) == FLEET_BOARD_OK;
    }
    /* still a well-formed entry: one hex digit of the root changes, so
     * only the signature can tell */
    if (ok && s->tamper) ok = tag_tamper(p);
    ok = ok && tag_render(p, &o) && json_push_back(&g_tag.board, &o);
    if (ok)
        json_free(&o);
    free(p);
    return ok;
}

static bool tag_board_add(const struct tag_post_spec *s, int64_t age)
{
    return tag_board_add_as(s, age, 0x5a);
}

static void tag_board_reset(void)
{
    json_free(&g_tag.board);
    json_init(&g_tag.board);
    json_set_array(&g_tag.board);
}

static bool tag_capture_signed_post(struct zcl_command_reply *out)
{
    const struct tag_post_spec post = {g_tag.text, "apps", FLEET_BOARD_KIND_OFFER, false};
    tag_board_reset();
    if (!tag_board_add(&post, 1)) return false;
    const char *id = json_get_str(json_get(json_at(&g_tag.board, 0), "id"));
    return id && json_push_kv_str(&out->data, "id", id);
}

static int tag_rebuild_catalog(void)
{
    int failures = 0;
    struct zcl_app_rebuild r = {0};
    memset(r.publisher, 'a', 66); memset(r.release_root, 'b', 64);
    memset(r.package_root, 'c', 64); memset(r.version, 'd', 64);
    memset(r.image, 'e', 64); memset(r.closure, 'f', 64);
    memset(r.environment, '1', 64); memset(r.dependency, '2', 64);
    memset(r.record, '3', 64); (void)snprintf(r.target, sizeof(r.target), "linux-x86_64-v3");
    char text[TAG_TEXT], wrong[TAG_TEXT]; size_t count = 0;
    struct zcl_command_reply why;
    TEST("app rebuild: signed distinct matching hosts count once and expired/mismatched posts do not") {
        ASSERT(zcl_app_rebuild_format(&r, text, sizeof(text)));
        r.image[0] = 'f'; ASSERT(zcl_app_rebuild_format(&r, wrong, sizeof(wrong))); r.image[0] = 'e';
        const struct tag_post_spec match = {text, "apps", FLEET_BOARD_KIND_RESULT, false};
        const struct tag_post_spec other = {wrong, "apps", FLEET_BOARD_KIND_RESULT, false};
        tag_board_reset();
        ASSERT(tag_board_add_as(&match, 50, 0x5a));
        ASSERT(tag_board_add_as(&match, 40, 0x5a));
        ASSERT(tag_board_add_as(&match, 30, 0x6b));
        ASSERT(tag_board_add_as(&match, 90000, 0x6c));
        ASSERT(tag_board_add_as(&other, 10, 0x6d));
        ASSERT(zcl_app_rebuild_count(&r, &count, &why));
        zcl_command_reply_free(&why);
        ASSERT_EQ(count, 2u);
        PASS();
    }
    TEST("app rebuild: tampered signatures and mismatched release, target or environment do not count") {
        const struct tag_post_spec tampered = {text, "apps", FLEET_BOARD_KIND_RESULT, true};
        tag_board_reset(); ASSERT(tag_board_add_as(&tampered, 5, 0x5a));
        r.release_root[0] = 'c'; ASSERT(zcl_app_rebuild_format(&r, wrong, sizeof(wrong))); r.release_root[0] = 'b';
        const struct tag_post_spec changed = {wrong, "apps", FLEET_BOARD_KIND_RESULT, false};
        ASSERT(tag_board_add_as(&changed, 5, 0x6b));
        r.environment[0] = '2'; ASSERT(zcl_app_rebuild_format(&r, wrong, sizeof(wrong))); r.environment[0] = '1';
        ASSERT(tag_board_add_as(&changed, 5, 0x6c));
        (void)snprintf(r.target, sizeof(r.target), "linux-aarch64");
        ASSERT(zcl_app_rebuild_format(&r, wrong, sizeof(wrong)));
        (void)snprintf(r.target, sizeof(r.target), "linux-x86_64-v3");
        ASSERT(tag_board_add_as(&changed, 5, 0x6d));
        ASSERT(zcl_app_rebuild_count(&r, &count, &why)); zcl_command_reply_free(&why);
        ASSERT_EQ(count, 0u); PASS();
    }
    TEST("app rebuild: saturated result list is incomplete even with invalid rows") {
        tag_board_reset();
        for (size_t i = 0; i < ZCL_APP_OFFER_ROWS_MAX; ++i) {
            struct json_value invalid; json_init(&invalid); json_set_object(&invalid);
            bool added = json_push_back(&g_tag.board, &invalid); json_free(&invalid); ASSERT(added);
        }
        bool ok = zcl_app_rebuild_count(&r, &count, &why); zcl_command_reply_free(&why);
        ASSERT(!ok); ASSERT_EQ(count, 0u); PASS();
    } _test_next:;
    tag_board_reset(); return failures;
}

static int tag_catalog_independent(void)
{
    int failures = 0;
    struct zcl_app_offer offer = {0};
    char honest[TAG_TEXT], other[TAG_TEXT];
    struct zcl_app_offer_row rows[2];
    struct zcl_command_reply why;
    size_t count;
    (void)snprintf(offer.name, sizeof(offer.name), "alice/tinyapp");
    memset(offer.root, 'a', 64);
    memset(offer.publisher, 'b', 66);
    memset(offer.carrier, 'c', 64);
    memset(offer.sha256, 'd', 64);
    (void)snprintf(offer.onion, sizeof(offer.onion), "%s", TAG_ONION);
    offer.size = 1;
    TEST("app get: independently signed same-root offers remain visible") {
        ASSERT(zcl_app_offer_format(&offer, honest, sizeof(honest)));
        offer.carrier[0] = 'e';
        ASSERT(zcl_app_offer_format(&offer, other, sizeof(other)));
        const struct tag_post_spec first = {honest, "apps", FLEET_BOARD_KIND_OFFER, false};
        const struct tag_post_spec second = {other, "apps", FLEET_BOARD_KIND_OFFER, false};
        tag_board_reset();
        ASSERT(tag_board_add_as(&first, 60, 0x5a));
        ASSERT(tag_board_add_as(&second, 30, 0x6b));
        ASSERT(zcl_app_offer_catalog(rows, 2, &count, &why));
        zcl_command_reply_free(&why);
        ASSERT_EQ(count, 2u);
        PASS();
    }
    TEST("app get: insufficient catalog capacity refuses incomplete results") {
        ASSERT(!zcl_app_offer_catalog(rows, 1, &count, &why));
        zcl_command_reply_free(&why);
        ASSERT_EQ(count, 0u);
        PASS();
    }
    TEST("app get: a host's changed same-root offer remains visible") {
        const struct tag_post_spec first = {honest, "apps", FLEET_BOARD_KIND_OFFER, false};
        const struct tag_post_spec second = {other, "apps", FLEET_BOARD_KIND_OFFER, false};
        tag_board_reset();
        ASSERT(tag_board_add(&first, 60));
        ASSERT(tag_board_add(&second, 30));
        ASSERT(zcl_app_offer_catalog(rows, 2, &count, &why));
        zcl_command_reply_free(&why);
        ASSERT_EQ(count, 2u);
        PASS();
    }
    TEST("app get: saturated board refuses even when posts are invalid") {
        tag_board_reset();
        for (size_t i = 0; i < ZCL_APP_OFFER_ROWS_MAX; i++) {
            struct json_value invalid;
            json_init(&invalid);
            json_set_object(&invalid);
            bool added = json_push_back(&g_tag.board, &invalid);
            json_free(&invalid);
            ASSERT(added);
        }
        bool ok = zcl_app_offer_catalog(rows, 2, &count, &why);
        zcl_command_reply_free(&why);
        ASSERT(!ok);
        PASS();
    }
    TEST("app get: malformed board envelope refuses") {
        g_tag.malformed_board = true;
        bool ok = zcl_app_offer_catalog(rows, 2, &count, &why);
        g_tag.malformed_board = false;
        zcl_command_reply_free(&why);
        ASSERT(!ok);
        PASS();
    } _test_next:;
    tag_board_reset();
    return failures;
}

/* `text` with its one occurrence of `from` replaced by `to`. */
static bool tag_swap(const char *text, const char *from, const char *to,
                     char out[TAG_TEXT])
{
    const char *at = strstr(text, from);
    if (!at || strstr(at + 1, from))
        return false;
    int n = snprintf(out, TAG_TEXT, "%.*s%s%s", (int)(at - text), text, to,
                     at + strlen(from));
    return n > 0 && (size_t)n < TAG_TEXT;
}

/* ── the world ──────────────────────────────────────────────────────── */

struct tag_world {
    char root[512], repo[600];
    char saved_home[1024], saved_cwd[1024];
    struct asf_journey j;
    struct zcl_app_offer offer; /* what A posted */
    char name[160];             /* the published package name */
    char next[512];             /* the exact continuation displayed by publish */
};

static const char k_tag_makefile[] =
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/tiny.h src/main.c\n"
    "app:\n"
    "\tcc -std=c2x -O2 -Iinclude -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

static const char k_tag_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

static const char k_tag_main[] =
    "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
    "int main(void) { puts(TINY_NAME \" ready\"); fflush(stdout);\n"
    "    pause(); return 0; }\n";

/* A checkout app.seed accepts from its working directory, holding the one
 * stub app apps/tinyapp: directories first (in order), then files. */
static bool tag_checkout(struct tag_world *w, const char *license)
{
    static const char *const tree[][2] = {
        {"", NULL}, {"engine", NULL}, {"engine/composition", NULL},
        {"engine/composition/commands", NULL}, {"tools", NULL},
        {"tools/dev", NULL}, {"apps", NULL}, {"apps/tinyapp", NULL},
        {"apps/tinyapp/include", NULL}, {"apps/tinyapp/src", NULL},
        {"Makefile", "# fixture checkout\n"},
        {"engine/composition/commands/root.def", "\n"},
        {"tools/dev/test_group_" "catalog.def", "\n"},
        {"apps/tinyapp/zcode-package.json", k_tag_meta},
        {"apps/tinyapp/include/tiny.h", "#define TINY_NAME \"tinyapp\"\n"},
        {"apps/tinyapp/src/main.c", k_tag_main},
        {"apps/tinyapp/Makefile", k_tag_makefile},
        {"apps/tinyapp/LICENSE", ""}};
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(tree) / sizeof(tree[0]); i++) {
        char path[TAG_PATH];
        const char *text = tree[i][1];
        if (text && strcmp(tree[i][0], "apps/tinyapp/LICENSE") == 0)
            text = license;
        ok = snprintf(path, sizeof(path), "%s/%s", w->repo, tree[i][0]) <
             (int)sizeof(path);
        ok = ok && (text ? asf_put(w->repo, tree[i][0], text)
                         : mkdir(path, 0700) == 0);
    }
    return ok;
}

static bool tag_world_init(struct tag_world *w)
{
    static char license[4096];
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    size_t n = f ? fread(license, 1, sizeof(license) - 1u, f) : 0;
    if (f)
        (void)fclose(f);
    license[n] = '\0';
    if (n == 0 || !getcwd(w->saved_cwd, sizeof(w->saved_cwd)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_get"))
        return false;
    (void)snprintf(w->repo, sizeof(w->repo), "%s/repo", w->root);
    return tag_checkout(w, license) &&
           asf_journey_init(&w->j, "tinyapp", w->repo, w->root);
}

/* ── tree fingerprints: "writes nothing" means the same walk ────────── */

static uint64_t g_tag_walk;

static int tag_walk_one(const char *path, const struct stat *st, int flag,
                        struct FTW *ftw)
{
    (void)flag;
    (void)ftw;
    uint64_t h = 1469598103934665603ull;
    for (const char *p = path; *p; p++)
        h = (h ^ (uint8_t)*p) * 1099511628211ull;
    h ^= (uint64_t)st->st_size * 31u + (uint64_t)st->st_mtime * 17u +
         (uint64_t)st->st_mode;
    g_tag_walk += h * 0x9e3779b97f4a7c15ull;
    return 0;
}

static uint64_t tag_tree(const char *dir)
{
    g_tag_walk = 0;
    return nftw(dir, tag_walk_one, 16, FTW_PHYS) == 0 ? g_tag_walk : 0;
}

/* Paths matching `pattern` (a leftover temporary directory, say). */
static size_t tag_glob(const char *dir, const char *pattern)
{
    char pat[TAG_PATH];
    glob_t g;
    (void)snprintf(pat, sizeof(pat), "%s/%s", dir, pattern);
    size_t n = glob(pat, 0, NULL, &g) == 0 ? g.gl_pathc : 0;
    globfree(&g);
    return n;
}

/* ── A publishes ────────────────────────────────────────────────────── */

static int tag_a_plan(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: publish's plan writes nothing and calls no transport") {
        static struct asf_door run;
        ASSERT(asf_journey_copy(&w->j));
        uint64_t home = tag_tree(w->j.a_home);
        uint64_t data = tag_tree(w->j.a_datadir);
        ASSERT(home != 0 && data != 0);
        struct asf_leaf unavailable;
        asf_open(&unavailable);
        ASSERT(json_push_kv_str(&unavailable.in, "copy", w->j.copy));
        ASSERT(json_push_kv_str(&unavailable.in, "datadir", w->j.a_datadir));
        g_tag.onion_unavailable = true;
        bool answered = asf_exec("app.publish", &unavailable);
        g_tag.onion_unavailable = false;
        ASSERT(answered);
        ASSERT(asf_refusal(&unavailable, "ONION_UNAVAILABLE"));
        asf_close(&unavailable);
        ASSERT_EQ(g_tag.offers + g_tag.posts + g_tag.fetches, 0);
        ASSERT_EQ(tag_tree(w->j.a_home), home);
        ASSERT_EQ(tag_tree(w->j.a_datadir), data);
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "publish",
                     w->j.copy, ZCL_CLI_CONFIRM_PLAN_ONLY, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(strstr(run.text, "nothing changed") != NULL);
        ASSERT(strstr(run.text, "room: apps") != NULL);
        ASSERT(strstr(run.text, ZCL_APP_OFFER_SCHEMA) != NULL);
        ASSERT_EQ(g_tag.offers + g_tag.posts + g_tag.fetches, 0);
        ASSERT_EQ(tag_tree(w->j.a_home), home);
        ASSERT_EQ(tag_tree(w->j.a_datadir), data);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_a_publish(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: publish offers the signed share bytes once and posts ONE "
         "entry naming exactly them") {
        static struct asf_door run;
        char want[512];
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "publish",
                     w->j.copy, ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT_EQ(g_tag.offers, 1);
        ASSERT_EQ(g_tag.posts, 1);
        ASSERT(strcmp(g_tag.kind, "offer") == 0);
        ASSERT(strcmp(g_tag.room, "apps") == 0);
        ASSERT(strcmp(g_tag.scope, "public") == 0);
        ASSERT_EQ(g_tag.ttl, 86400);
        ASSERT(strlen(g_tag.text) <= ZCL_APP_OFFER_TEXT_MAX);
        ASSERT(zcl_app_offer_parse(g_tag.text, strlen(g_tag.text),
                                   &w->offer));
        ASSERT(strcmp(w->offer.sha256, g_tag.sha) == 0);
        ASSERT_EQ(w->offer.size, (int64_t)g_tag.len);
        ASSERT(strcmp(w->offer.carrier, TAG_CARRIER) == 0);
        ASSERT(strcmp(w->offer.onion, TAG_ENDPOINT) == 0);
        ASSERT(strncmp(w->offer.name, "k", 1) == 0 &&
               strstr(w->offer.name, "/tinyapp") != NULL);
        (void)snprintf(w->name, sizeof(w->name), "%s", w->offer.name);
        const char *id = json_get_str(json_get(json_at(&g_tag.board, 0), "id"));
        ASSERT(id != NULL);
        (void)snprintf(want, sizeof(want), "z23 app get %s --root=%s --publisher=%s --offer=%s",
                       w->name, w->offer.root, w->offer.publisher, id);
        const char *continuation = strstr(run.text, want);
        ASSERT(continuation != NULL && strcspn(continuation, "\n") == strlen(want));
        (void)snprintf(w->next, sizeof(w->next), "%.*s", (int)strlen(want), continuation);
        /* the private share file is gone: the node holds the bytes */
        ASSERT_EQ(tag_glob(w->j.a_datadir, ".app-publish*"), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_publish_collision(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: publish refuses an occupied private staging directory") {
        struct asf_leaf l;
        char token[33], plan[65], dir[TAG_PATH];
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "copy", w->j.copy));
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.a_datadir));
        ASSERT(asf_pass("app.publish", &l));
        ASSERT(strlen(asf_get(&l, "token")) == 32);
        ASSERT(strlen(asf_get(&l, "plan_id")) == 64);
        (void)snprintf(token, sizeof(token), "%s", asf_get(&l, "token"));
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        (void)snprintf(dir, sizeof(dir), "%s/.app-publish-%s", w->j.a_datadir, token);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(json_push_kv_str(&l.in, "token", token));
        ASSERT(json_push_kv_str(&l.in, "plan_id", plan));
        ASSERT(json_push_kv_bool(&l.in, "confirm", true));
        zcl_command_reply_free(&l.out);
        zcl_command_reply_init(&l.out, "zcl.test.app_get.v1");
        bool executed = asf_exec("app.publish", &l);
        int removed = rmdir(dir);
        ASSERT(executed);
        ASSERT(asf_refusal(&l, "TEMP_UNAVAILABLE"));
        ASSERT_EQ(removed, 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_publish_unknown(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: malformed post id reports a possibly published offer") {
        struct asf_leaf l;
        char token[33], plan[65];
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "copy", w->j.copy));
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.a_datadir));
        ASSERT(asf_pass("app.publish", &l));
        (void)snprintf(token, sizeof(token), "%s", asf_get(&l, "token"));
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        ASSERT(json_push_kv_str(&l.in, "token", token));
        ASSERT(json_push_kv_str(&l.in, "plan_id", plan));
        ASSERT(json_push_kv_bool(&l.in, "confirm", true));
        zcl_command_reply_free(&l.out);
        zcl_command_reply_init(&l.out, "zcl.test.app_get.v1");
        g_tag.malformed_post_id = true;
        bool answered = asf_exec("app.publish", &l);
        g_tag.malformed_post_id = false;
        ASSERT(answered);
        ASSERT(asf_refusal(&l, "PUBLISH_OUTCOME_UNKNOWN"));
        ASSERT(l.out.error.mutated);
        ASSERT_EQ(g_tag.offers, 1);
        ASSERT_EQ(g_tag.posts, 1);
        asf_close(&l);
        g_tag.offers = 0;
        g_tag.posts = 0;
        PASS();
    } _test_next:;
    g_tag.malformed_post_id = false;
    return failures;
}

static int tag_publish_source_change(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: a changed copy invalidates the publish plan") {
        struct asf_leaf l;
        char token[33], plan[65], changed[4096];
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "copy", w->j.copy));
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.a_datadir));
        ASSERT(asf_pass("app.publish", &l));
        (void)snprintf(token, sizeof(token), "%s", asf_get(&l, "token"));
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        ASSERT(json_push_kv_str(&l.in, "token", token));
        ASSERT(json_push_kv_str(&l.in, "plan_id", plan));
        ASSERT(json_push_kv_bool(&l.in, "confirm", true));
        int n = snprintf(changed, sizeof(changed), "%s\n/* changed after plan */\n", k_tag_main);
        ASSERT(n > 0 && (size_t)n < sizeof(changed));
        bool written = asf_put(w->j.a_copy, "src/main.c", changed);
        if (!written) (void)asf_put(w->j.a_copy, "src/main.c", k_tag_main);
        ASSERT(written);
        zcl_command_reply_free(&l.out);
        zcl_command_reply_init(&l.out, "zcl.test.app_get.v1");
        bool answered = asf_exec("app.publish", &l);
        bool restored = asf_put(w->j.a_copy, "src/main.c", k_tag_main);
        ASSERT(restored);
        ASSERT(answered);
        ASSERT(asf_refusal(&l, "PLAN_MISMATCH"));
        ASSERT_EQ(g_tag.offers + g_tag.posts, 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_publish_onion_change(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: a changed onion port invalidates the publish plan") {
        struct asf_leaf l;
        char token[33], plan[65];
        uint64_t home = tag_tree(w->j.a_home), data = tag_tree(w->j.a_datadir);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "copy", w->j.copy));
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.a_datadir));
        ASSERT(asf_pass("app.publish", &l));
        (void)snprintf(token, sizeof(token), "%s", asf_get(&l, "token"));
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        ASSERT(json_push_kv_str(&l.in, "token", token));
        ASSERT(json_push_kv_str(&l.in, "plan_id", plan));
        ASSERT(json_push_kv_bool(&l.in, "confirm", true));
        zcl_command_reply_free(&l.out);
        zcl_command_reply_init(&l.out, "zcl.test.app_get.v1");
        g_tag.onion_changed = true;
        bool answered = asf_exec("app.publish", &l);
        g_tag.onion_changed = false;
        ASSERT(answered);
        ASSERT(asf_refusal(&l, "PLAN_MISMATCH"));
        ASSERT_EQ(g_tag.offers + g_tag.posts, 0);
        ASSERT_EQ(tag_tree(w->j.a_home), home);
        ASSERT_EQ(tag_tree(w->j.a_datadir), data);
        asf_close(&l);
        PASS();
    } _test_next:;
    g_tag.onion_changed = false;
    return failures;
}

/* ── the catalog ────────────────────────────────────────────────────── */

static bool tag_board_valid(const struct tag_world *w, int64_t age)
{
    const struct tag_post_spec s = {g_tag.text, "apps",
                                    FLEET_BOARD_KIND_OFFER, false};
    return w->offer.root[0] && tag_board_add(&s, age);
}

static int tag_catalog(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: the entry round-trips through the catalog as one row") {
        struct asf_leaf l;
        char text[TAG_TEXT], brief[ZCL_APP_SHORT_FINGERPRINT_LEN], root16[17];
        ASSERT(zcl_app_offer_format(&w->offer, text, sizeof(text)));
        ASSERT(strcmp(text, g_tag.text) == 0);
        tag_board_reset();
        ASSERT(tag_board_valid(w, 300) && tag_board_valid(w, 60));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(asf_pass("app.get", &l));
        ASSERT_EQ(json_get_int(json_get(&l.out.data, "count")), 1);
        const char *line =
            json_get_str(json_at(json_get(&l.out.data, "lines"), 0));
        ASSERT(zcl_app_short_fingerprint(w->offer.publisher, brief));
        (void)snprintf(root16, sizeof(root16), "%.16s", w->offer.root);
        ASSERT(line && strstr(line, w->name) && strstr(line, brief) &&
               strstr(line, root16) && strstr(line, "1m ago"));
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

/* Each malformed text, as A's own entry with one field broken. */
static bool tag_malformed(const struct tag_world *w, size_t i,
                          char out[TAG_TEXT])
{
    const struct zcl_app_offer *o = &w->offer;
    char upper[65], size[48], big[48];
    for (size_t k = 0; k < 64; k++)
        upper[k] = (char)(o->root[k] >= 'a' ? o->root[k] - 32 : o->root[k]);
    upper[64] = '\0';
    (void)snprintf(size, sizeof(size), "\"size\":%lld", (long long)o->size);
    (void)snprintf(big, sizeof(big), "\"size\":%u",
                   ZCL_APP_OFFER_SIZE_MAX + 1u);
    const char *swap[][2] = {
        {o->root, upper}, {o->onion, "198.51.100.7:8033"}, {size, big},
        {"{\"schema\"", "{\"x\":1,\"schema\""},
        {ZCL_APP_OFFER_SCHEMA, "zcl.app_offer.v2"},
        {o->publisher, "02abc"}, {"\"name\":\"k", "\"name\":\"K"}};
    if (i < sizeof(swap) / sizeof(swap[0]))
        return tag_swap(g_tag.text, swap[i][0], swap[i][1], out);
    (void)snprintf(out, TAG_TEXT, "%s", "not an entry");
    return i == sizeof(swap) / sizeof(swap[0]);
}

static int tag_dropped(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: a malformed, mis-roomed, wrong-kind or tampered post is "
         "dropped") {
        char bad[TAG_TEXT];
        struct zcl_app_offer_row row;
        struct zcl_app_offer_row rows[16];
        struct zcl_command_reply why;
        size_t count = 99;
        tag_board_reset();
        for (size_t i = 0; tag_malformed(w, i, bad); i++) {
            const struct tag_post_spec s = {bad, "apps",
                                            FLEET_BOARD_KIND_OFFER, false};
            ASSERT(!zcl_app_offer_parse(bad, strlen(bad), &row.offer));
            ASSERT(tag_board_add(&s, 30));
        }
        const struct tag_post_spec other[] = {
            {g_tag.text, "general", FLEET_BOARD_KIND_OFFER, false},
            {g_tag.text, "apps", FLEET_BOARD_KIND_NOTE, false},
            {g_tag.text, "apps", FLEET_BOARD_KIND_OFFER, true}};
        for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); i++)
            ASSERT(tag_board_add(&other[i], 30));
        for (size_t i = 0; i < json_size(&g_tag.board); i++)
            ASSERT(!zcl_app_offer_from_post(json_at(&g_tag.board, i), &row));
        ASSERT(tag_board_valid(w, 30));
        ASSERT(zcl_app_offer_catalog(rows, 16, &count, &why));
        zcl_command_reply_free(&why);
        ASSERT_EQ(count, 1u);
        ASSERT(strcmp(rows[0].offer.root, w->offer.root) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── B gets ─────────────────────────────────────────────────────────── */

/* The board holds A's entry with one field replaced (signed as such). */
static bool tag_board_variant(const struct tag_world *w, const char *from,
                              const char *to, bool tamper)
{
    char text[TAG_TEXT];
    tag_board_reset();
    if (!from)
        return tag_board_valid(w, 30);
    const struct tag_post_spec s = {text, "apps", FLEET_BOARD_KIND_OFFER,
                                    tamper};
    return tag_swap(g_tag.text, from, to, text) && tag_board_add(&s, 30);
}

static bool tag_catalog_cli(const char *datadir, const char *name)
{
    const struct zcl_command_spec *spec = asf_spec("app.get");
    FILE *out = tmpfile();
    int saved = dup(STDOUT_FILENO), rc = -1;
    if (!spec || !out || saved < 0) {
        if (out) fclose(out);
        if (saved >= 0) close(saved);
        return false;
    }
    (void)fflush(stdout);
    bool redirected = dup2(fileno(out), STDOUT_FILENO) >= 0;
    bool handled = redirected && zcl_app_front_door_try(spec, NULL, 0, 0, datadir, &rc);
    (void)fflush(stdout);
    bool restored = dup2(saved, STDOUT_FILENO) >= 0;
    close(saved);
    rewind(out);
    char text[2048];
    size_t n = fread(text, 1, sizeof(text) - 1u, out);
    text[n] = '\0';
    fclose(out);
    return handled && restored && rc == 0 && strstr(text, name) != NULL;
}

static int tag_publish_long_name(struct tag_world *w)
{
    int failures = 0;
    TEST("app publish: continuation holds a maximum-length legal name") {
        struct zcl_app_offer offer = w->offer;
        memset(offer.name, 'a', sizeof(offer.name) - 1);
        offer.name[VCS_PACKAGE_RELEASE_NAME_HALF_MAX] = '/';
        offer.name[sizeof(offer.name) - 1] = '\0';
        const char *id = json_get_str(json_get(json_at(&g_tag.board, 0), "id"));
        char next[512], short_next[16];
        ASSERT(id && zcl_app_offer_valid(&offer));
        ASSERT(zcl_test_app_publish_next(next, sizeof(next), offer.name, offer.root, offer.publisher, id));
        ASSERT(strstr(next, offer.name) && strstr(next, id));
        ASSERT(!zcl_test_app_publish_next(short_next, sizeof(short_next), offer.name, offer.root, offer.publisher, id));
        PASS();
    } _test_next:;
    return failures;
}

static int tag_published_continuation(struct tag_world *w)
{
    int failures = 0;
    TEST("app publish: displayed continuation selects its exact offer among competing names") {
        char text[TAG_TEXT], other_root[65], command[512], *save = NULL;
        memset(other_root, 'a', 64); other_root[64] = '\0';
        ASSERT(tag_swap(g_tag.text, w->offer.root, other_root, text));
        const struct tag_post_spec other = {text, "apps", FLEET_BOARD_KIND_OFFER, false};
        ASSERT(tag_board_add_as(&other, 1, 0x6b));
        (void)snprintf(command, sizeof(command), "%s", w->next);
        const char *words[7]; size_t count = 0;
        for (char *p = strtok_r(command, " ", &save); p && count < 7; p = strtok_r(NULL, " ", &save))
            words[count++] = p;
        ASSERT(count == 7 && !strcmp(words[0], "z23") && !strcmp(words[1], "app") && !strcmp(words[2], "get"));
        FILE *out = tmpfile(); ASSERT(out != NULL);
        int saved = dup(STDOUT_FILENO), rc = -1, shows = g_tag.shows, lists = g_tag.catalog_lists;
        ASSERT(saved >= 0 && fflush(stdout) == 0 && dup2(fileno(out), STDOUT_FILENO) >= 0);
        bool handled = zcl_app_front_door_try(asf_spec("app.get"), words, count, 3, w->j.b_datadir, &rc);
        (void)fflush(stdout); bool restored = dup2(saved, STDOUT_FILENO) >= 0;
        close(saved); fclose(out);
        ASSERT(handled && restored && rc == 0);
        ASSERT(g_tag.shows == shows + 1 && g_tag.catalog_lists == lists);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_identity_selection(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: ambiguous name needs an exact root and publisher") {
        char text[TAG_TEXT], other_root[65];
        struct asf_leaf l;
        memset(other_root, 'a', 64); other_root[64] = '\0';
        ASSERT(tag_swap(g_tag.text, w->offer.root, other_root, text));
        tag_board_reset();
        const struct tag_post_spec other = {text, "apps", FLEET_BOARD_KIND_OFFER, false};
        ASSERT(tag_board_valid(w, 60));
        ASSERT(tag_board_add_as(&other, 30, 0x6b));
        ASSERT(tag_catalog_cli(w->j.b_datadir, w->name));
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "root", w->offer.root));
        ASSERT(asf_exec("app.get", &l));
        ASSERT(asf_refusal(&l, "BAD_INPUT"));
        asf_close(&l);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        ASSERT(asf_exec("app.get", &l));
        ASSERT(asf_refusal(&l, "AMBIGUOUS"));
        ASSERT(strstr(asf_get(&l, "choice_a"), "--publisher=") != NULL);
        ASSERT(strstr(asf_get(&l, "choice_b"), "--root=") != NULL);
        asf_close(&l);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        ASSERT(json_push_kv_str(&l.in, "root", w->offer.root));
        ASSERT(json_push_kv_str(&l.in, "publisher", w->offer.publisher));
        ASSERT(asf_pass("app.get", &l));
        ASSERT(strcmp(asf_get(&l, "package_root"), w->offer.root) == 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_endpoint_limit(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: endpoint budget gives an exact next offer selector") {
        struct asf_leaf l;
        char offer[65];
        const struct tag_post_spec post = {g_tag.text, "apps", FLEET_BOARD_KIND_OFFER, false};
        tag_board_reset();
        for (int i = 0; i < 5; i++)
            ASSERT(tag_board_add_as(&post, 30 + i, (uint8_t)(0x40 + i)));
        g_tag.fetch_failures = 4;
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        bool answered = asf_exec("app.get", &l);
        g_tag.fetch_failures = 0;
        ASSERT(answered);
        ASSERT(asf_refusal(&l, "ATTEMPT_LIMIT"));
        const char *selector = strstr(asf_get(&l, "next_offer"), "--offer=");
        ASSERT(selector && strlen(selector + 8) == 64);
        (void)snprintf(offer, sizeof(offer), "%s", selector + 8);
        asf_close(&l);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        ASSERT(json_push_kv_str(&l.in, "root", w->offer.root));
        ASSERT(json_push_kv_str(&l.in, "publisher", w->offer.publisher));
        ASSERT(json_push_kv_str(&l.in, "offer_id", offer));
        ASSERT(asf_pass("app.get", &l));
        ASSERT(strcmp(asf_get(&l, "offer_id"), offer) == 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    g_tag.fetch_failures = 0;
    return failures;
}

static bool tag_exact_input(struct asf_leaf *l, const struct tag_world *w,
                            const char *id, const char *root, const char *publisher)
{
    return json_push_kv_str(&l->in, "datadir", w->j.b_datadir) &&
        json_push_kv_str(&l->in, "name", w->name) &&
        json_push_kv_str(&l->in, "root", root) &&
        json_push_kv_str(&l->in, "publisher", publisher) &&
        json_push_kv_str(&l->in, "offer_id", id);
}

static bool tag_exact_rejected(struct tag_world *w, const char *id,
                               const char *root, const char *publisher)
{
    struct asf_leaf l; asf_open(&l);
    int fetches = g_tag.fetches;
    bool ok = tag_exact_input(&l, w, id, root, publisher) && asf_exec("app.get", &l) &&
        l.out.status != ZCL_COMMAND_STATUS_PASSED && !l.out.error.mutated &&
        g_tag.fetches == fetches;
    asf_close(&l); return ok;
}

static int tag_exact_refusals(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: exact lookup refuses wrong, expired, forged and unavailable posts before fetch") {
        char id[65];
        const char *wrong = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const char *wrong_pub = "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const struct tag_post_spec bad[] = {
            {g_tag.text, "other", FLEET_BOARD_KIND_OFFER, false},
            {g_tag.text, "apps", FLEET_BOARD_KIND_OFFER, true},
            {g_tag.text, "apps", FLEET_BOARD_KIND_OFFER, false},
        };
        tag_board_reset(); ASSERT(tag_board_valid(w, 30));
        (void)snprintf(id, sizeof(id), "%s", json_get_str(json_get(json_at(&g_tag.board, 0), "id")));
        ASSERT(tag_exact_rejected(w, id, wrong, w->offer.publisher));
        ASSERT(tag_exact_rejected(w, id, w->offer.root, wrong_pub));
        g_tag.show_mode = 2; ASSERT(tag_exact_rejected(w, wrong, w->offer.root, w->offer.publisher));
        g_tag.show_mode = 1; ASSERT(tag_exact_rejected(w, id, w->offer.root, w->offer.publisher));
        g_tag.show_mode = 0;
        for (size_t i = 0; i < 3; ++i) {
            tag_board_reset(); ASSERT(tag_board_add(&bad[i], i == 2 ? 90000 : 30));
            (void)snprintf(id, sizeof(id), "%s", json_get_str(json_get(json_at(&g_tag.board, 0), "id")));
            ASSERT(tag_exact_rejected(w, id, w->offer.root, w->offer.publisher));
        }
        PASS();
    } _test_next:;
    g_tag.show_mode = 0;
    return failures;
}

static bool tag_saturate_board(void)
{
    for (size_t i = 1; i < ZCL_APP_OFFER_ROWS_MAX; ++i) {
        struct json_value invalid; json_init(&invalid); json_set_object(&invalid);
        bool added = json_push_back(&g_tag.board, &invalid); json_free(&invalid);
        if (!added) return false;
    }
    return true;
}

static int tag_exact_offer(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: exact signed offer survives a saturated catalog") {
        struct asf_leaf l;
        char id[65], token[33], plan[65];
        tag_board_reset();
        ASSERT(tag_board_valid(w, 30));
        (void)snprintf(id, sizeof(id), "%s", json_get_str(json_get(json_at(&g_tag.board, 0), "id")));
        ASSERT(tag_saturate_board());
        int lists = g_tag.catalog_lists, shows = g_tag.shows, fetches = g_tag.fetches;
        asf_open(&l);
        ASSERT(tag_exact_input(&l, w, id, w->offer.root, w->offer.publisher));
        ASSERT(asf_pass("app.get", &l));
        ASSERT(!strcmp(asf_get(&l, "offer_id"), id));
        ASSERT(g_tag.catalog_lists == lists && g_tag.shows == shows + 1 && g_tag.fetches == fetches + 1);
        (void)snprintf(token, sizeof(token), "%s", asf_get(&l, "token"));
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        ASSERT(strlen(token) == 32 && strlen(plan) == 64);
        ASSERT(json_push_kv_str(&l.in, "token", token) &&
               json_push_kv_str(&l.in, "plan_id", plan) && json_push_kv_bool(&l.in, "confirm", true));
        zcl_command_reply_free(&l.out); zcl_command_reply_init(&l.out, "zcl.app_get.v1");
        bool received = asf_exec("app.get", &l) && l.out.status == ZCL_COMMAND_STATUS_PASSED;
        long pid = (long)json_get_int(json_get(&l.out.data, "pid"));
        bool stopped = pid > 0 && asf_alive_then_stop(pid);
        if (!received || !stopped || g_tag.catalog_lists != lists || g_tag.shows != shows + 2)
            printf("exact confirmed: received=%d stopped=%d pid=%ld lists=%d/%d shows=%d/%d code=%s message=%s\n",
                   received, stopped, pid, g_tag.catalog_lists, lists, g_tag.shows, shows + 2,
                   l.out.error.code, l.out.error.message);
        ASSERT(received && stopped && g_tag.catalog_lists == lists && g_tag.shows == shows + 2);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_exact_tests(struct tag_world *w)
{
    int failures = tag_exact_refusals(w);
    return failures ? failures : tag_exact_offer(w);
}

/* B's front door refuses with `code` without asking, keeping nothing. */
static bool tag_b_refused(const struct tag_world *w, const char *code)
{
    static struct asf_door run;
    asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name,
                 ZCL_CLI_CONFIRM_ASK, &run);
    bool ok = run.rc != 0 && !run.asked && strstr(run.text, code) != NULL &&
              tag_glob(w->j.b_datadir, "copies/*") == 0 &&
              tag_glob(w->j.b_datadir, ".app-get-*") == 0;
    if (!ok)
        printf("  [want %s before any prompt: rc=%d asked=%d]\n%s", code,
               run.rc, run.asked, run.text);
    return ok;
}

static int tag_refusals(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: a wrong sha256, root or publisher, or a tampered entry, "
         "is refused before any prompt") {
        const char *other_root =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const char *other_key =
            "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.tamper = true;
        ASSERT(tag_b_refused(w, "SHA256_MISMATCH"));
        g_tag.tamper = false;
        ASSERT(tag_board_variant(w, w->offer.root, other_root, false));
        ASSERT(tag_b_refused(w, "ROOT_MISMATCH"));
        ASSERT(tag_board_variant(w, w->offer.publisher, other_key, false));
        ASSERT(tag_b_refused(w, "PUBLISHER_MISMATCH"));
        ASSERT(tag_board_variant(w, "\"size\"", "\"size\"", true));
        ASSERT(tag_b_refused(w, "NOT_IN_CATALOG"));
        PASS();
    } _test_next:;
    return failures;
}

static int tag_b_plan(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: the plan fetches the entry's carrier from its onion, "
         "hands receive the exact bytes and keeps nothing") {
        struct asf_leaf l;
        int fetches = g_tag.fetches;
        int offers = g_tag.offers;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir) &&
               json_push_kv_str(&l.in, "name", w->name));
        ASSERT(asf_pass("app.get", &l));
        ASSERT_EQ(g_tag.fetches, fetches + 1);
        ASSERT_EQ(g_tag.offers, offers);
        ASSERT(strcmp(g_tag.fetch_root, TAG_CARRIER) == 0);
        ASSERT(strcmp(g_tag.fetch_peer, TAG_ENDPOINT) == 0);
        ASSERT(strncmp(g_tag.fetch_out, w->j.b_datadir,
                       strlen(w->j.b_datadir)) == 0);
        /* receive-copy's own verify of the handed file named A's root,
         * publisher and the copy it would make */
        ASSERT(strcmp(asf_get(&l, "package_root"), w->offer.root) == 0);
        ASSERT(strcmp(asf_get(&l, "publisher_fingerprint"),
                      w->offer.publisher) == 0);
        ASSERT(strcmp(asf_get(&l, "sha256"), g_tag.sha) == 0);
        ASSERT(strcmp(asf_get(&l, "copy"), "tinyapp-1") == 0);
        ASSERT(strlen(asf_get(&l, "plan_id")) == 64);
        ASSERT(!asf_flag(&l, "executed"));
        asf_close(&l);
        ASSERT_EQ(tag_glob(w->j.b_datadir, "copies/*"), 0u);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        PASS();
    } _test_next:;
    return failures;
}

struct tag_consumer {
    int calls, mode; char path[TAG_PATH], directory[TAG_PATH], saved[TAG_PATH], foreign[TAG_PATH];
    bool moved, linked; const struct tag_world *world;
};
static bool tag_replace_stage(struct tag_consumer *c, const char *path)
{
    if (strlen(path) >= sizeof(c->directory)) return false;
    memcpy(c->directory, path, strlen(path) + 1);
    char *slash = strrchr(c->directory, '/');
    if (!slash) return false;
    *slash = 0;
    int n = snprintf(c->saved, sizeof(c->saved), "%s.saved", c->directory);
    if (n <= 0 || (size_t)n >= sizeof(c->saved) || rename(c->directory, c->saved)) return false;
    c->moved = true;
    if (symlink(c->foreign, c->directory)) return false;
    c->linked = true; return true;
}
static bool tag_consume(void *context, const char *path,
    const struct app_receive_identity *identity, struct zcl_command_reply *reply, bool *host_original)
{
    (void)host_original;
    struct tag_consumer *c = context; char root[65], publisher[67], release[65];
    ++c->calls; (void)snprintf(c->path, sizeof(c->path), "%s", path);
    zcl_hex_encode(identity->package_root, 32, root);
    zcl_hex_encode(identity->publisher, 33, publisher);
    zcl_hex_encode(identity->release_id, 32, release);
    if (access(path, R_OK) || strcmp(root, c->world->offer.root) ||
        strcmp(publisher, c->world->offer.publisher)) return false;
    struct asf_leaf verify; asf_open(&verify);
    bool verified = json_push_kv_str(&verify.in, "file", path) &&
        asf_pass("zcode.package.bundle.verify", &verify) &&
        !strcmp(release, asf_get(&verify, "release_id"));
    asf_close(&verify);
    if (!verified) return false;
    if (c->mode == 3) return tag_replace_stage(c, path);
    if (c->mode) {
        zcl_package_copy_fail(reply, "TEST_CONSUMER", c->mode == 2, "fixture refusal", "fixture");
        return false;
    }
    return json_push_kv_str(&reply->data, "status", "canceled");
}
static bool tag_foreign_unchanged(const struct tag_consumer *c)
{
    char sentinel[TAG_PATH], text[15] = {0}; struct stat st;
    int n = snprintf(sentinel, sizeof(sentinel), "%s/offer.z23share", c->foreign);
    if (n <= 0 || (size_t)n >= sizeof(sentinel) || lstat(sentinel, &st) ||
        !S_ISREG(st.st_mode) || st.st_size != 14) return false;
    FILE *f = fopen(sentinel, "rb"); if (!f) return false;
    size_t read = fread(text, 1, 14, f); bool ok = read == 14 && !strcmp(text, "foreign stays\n");
    return fclose(f) == 0 && ok;
}
static bool tag_replacement_cleanup(struct tag_consumer *c)
{
    bool ok = true; char saved_file[TAG_PATH];
    if (c->linked && unlink(c->directory) != 0) ok = false;
    if (c->moved) {
        int n = snprintf(saved_file, sizeof(saved_file), "%s/offer.z23share", c->saved);
        if (n <= 0 || (size_t)n >= sizeof(saved_file) || unlink(saved_file) || rmdir(c->saved)) ok = false;
    }
    return ok;
}
static bool tag_replacement_refused(bool done, const struct tag_consumer *c,
    const struct zcl_command_reply *reply)
{
    struct stat st;
    return !done && c->calls == 1 && c->moved && c->linked &&
        reply->status != ZCL_COMMAND_STATUS_PASSED && reply->error.mutated &&
        !strcmp(reply->error.code, "TEMP_CLEANUP_FAILED") &&
        lstat(c->directory, &st) == 0 && S_ISLNK(st.st_mode) && tag_foreign_unchanged(c);
}
static bool tag_stage_replacement(struct tag_world *w, const struct zcl_app_offer_row *row)
{
    char tmp[TAG_PATH], canonical[PATH_MAX];
    struct tag_consumer c = {.world = w, .mode = 3};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_get.stage.v1");
    bool ok = test_mkdtemp(tmp, sizeof(tmp), "app_get_foreign") && realpath(tmp, canonical) &&
        strlen(canonical) < sizeof(c.foreign);
    if (ok) memcpy(c.foreign, canonical, strlen(canonical) + 1);
    ok = ok &&
        asf_put(c.foreign, "offer.z23share", "foreign stays\n");
    if (ok) {
        bool done = app_get_stage_consume(row, w->j.b_datadir, tag_consume, &c, &reply);
        ok = tag_replacement_refused(done, &c, &reply);
    }
    if (!tag_replacement_cleanup(&c)) ok = false;
    zcl_command_reply_free(&reply); return ok;
}
static bool tag_stage_attempt(struct tag_world *w, const struct zcl_app_offer_row *row,
    int mode, const char *failure)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_get.stage.v1");
    struct tag_consumer c = {.world = w, .mode = mode};
    bool ok = app_get_stage_consume(row, w->j.b_datadir, tag_consume, &c, &reply);
    const char *status = json_get_str(json_get(&reply.data, "status"));
    bool result = failure ? !ok && !strcmp(reply.error.code, failure) :
        ok && reply.status == ZCL_COMMAND_STATUS_PASSED && status && !strcmp(status, "canceled");
    result = result && reply.error.mutated == (mode == 2) &&
        c.calls == (failure && strcmp(failure, "TEST_CONSUMER") ? 0 : 1) &&
        (!c.path[0] || access(c.path, F_OK) != 0) && tag_glob(w->j.b_datadir, ".app-get-*") == 0;
    zcl_command_reply_free(&reply); return result;
}
static bool tag_stage_variant(struct tag_world *w, const char *from, const char *to,
    const char *failure)
{
    struct zcl_app_offer_row rows[4]; size_t count = 0; struct zcl_command_reply why;
    if (!tag_board_variant(w, from, to, false)) return false;
    bool ok = zcl_app_offer_catalog(rows, 4, &count, &why);
    zcl_command_reply_free(&why);
    return ok && count == 1 && tag_stage_attempt(w, &rows[0], 0, failure);
}
static int tag_stage_consumer(struct tag_world *w)
{
    int failures = 0; struct zcl_app_offer_row rows[4]; size_t count = 0;
    struct zcl_command_reply why;
    TEST("app get stages the exact fresh offer for one consumer and cleans up") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(zcl_app_offer_catalog(rows, 4, &count, &why)); zcl_command_reply_free(&why);
        ASSERT_EQ(count, 1u);
        int lists = g_tag.catalog_lists, shows = g_tag.shows;
        ASSERT(tag_stage_attempt(w, &rows[0], 0, NULL));
        ASSERT_EQ(g_tag.catalog_lists, lists); ASSERT_EQ(g_tag.shows, shows + 1);
        ASSERT(tag_stage_attempt(w, &rows[0], 1, "TEST_CONSUMER"));
        ASSERT(tag_stage_attempt(w, &rows[0], 2, "TEST_CONSUMER"));
        ASSERT(tag_stage_replacement(w, &rows[0]));
        struct zcl_app_offer_row stale = rows[0];
        stale.offer.root[0] = stale.offer.root[0] == '0' ? '1' : '0';
        ASSERT(tag_stage_attempt(w, &stale, 0, "OFFER_CHANGED"));
        g_tag.tamper = true;
        ASSERT(tag_stage_attempt(w, &rows[0], 0, "SHA256_MISMATCH"));
        g_tag.tamper = false;
        ASSERT(tag_stage_variant(w, w->offer.root,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ROOT_MISMATCH"));
        ASSERT(tag_stage_variant(w, w->offer.publisher,
            "02bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "PUBLISHER_MISMATCH"));
        PASS();
    } _test_next:;
    g_tag.tamper = false; return failures;
}
static int tag_stage_unsafe_parent(struct tag_world *w)
{
    int failures = 0; char root[TAG_PATH], canonical[PATH_MAX], parent[TAG_PATH], profile[TAG_PATH];
    struct zcl_app_offer_row rows[4]; size_t count = 0; struct zcl_command_reply why, reply;
    struct tag_consumer c = {.world = w};
    TEST("Discover staging refuses writable or symlink profile ancestors before fetching") {
        ASSERT(test_mkdtemp(root, sizeof(root), "app_get_unsafe") && realpath(root, canonical));
        ASSERT(snprintf(parent, sizeof(parent), "%s/parent", canonical) < (int)sizeof(parent));
        ASSERT(snprintf(profile, sizeof(profile), "%s/profile", parent) < (int)sizeof(profile));
        ASSERT(mkdir(parent, 0700) == 0 && chmod(parent, 0775) == 0);
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(zcl_app_offer_catalog(rows, 4, &count, &why)); zcl_command_reply_free(&why);
        ASSERT_EQ(count, 1u); int fetches = g_tag.fetches;
        zcl_command_reply_init(&reply, "zcl.app_get.stage.v1");
        ASSERT(!app_get_stage_consume(&rows[0], profile, tag_consume, &c, &reply));
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED &&
            !strcmp(reply.error.code, "UNSAFE_RECEIVE_PARENT") && !reply.error.mutated);
        zcl_command_reply_free(&reply); ASSERT(chmod(parent, 0700) == 0);
        ASSERT(symlink(canonical, profile) == 0);
        zcl_command_reply_init(&reply, "zcl.app_get.stage.v1");
        ASSERT(!app_get_stage_consume(&rows[0], profile, tag_consume, &c, &reply));
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED &&
            !reply.error.mutated && c.calls == 0 && g_tag.fetches == fetches);
        zcl_command_reply_free(&reply); PASS();
    } _test_next:;
    return failures;
}
struct tag_discover {
    int cards, receive, home, errors, detail, browser;
    bool keep, kept, cleanup_swap, oversized_share, fail_error_view, recovery_shown, host_original, host_prompted, host_identity, fail_host_result;
    bool report_rebuild, report_prompted, report_count_visible, close_keep, report_result, fetch_close, fetch_presenter_fail;
    bool report_result_unavailable, report_result_count, report_result_two, report_result_publish; int comparison_mode;
    bool cancel_after_error, share_canceled;
    struct zcl_command_reply *reply; char first_result[8192], image[65]; long pid; uint64_t start;
    struct tag_consumer swap;
};
extern void app_discover_test_evidence_hook(void (*)(const struct zcl_app_offer_row *, const struct json_value *, const struct json_value *));
static bool tag_rebuild_controls_seen, tag_rebuild_controls_ok;
static int tag_comparison_seed_mode;
static bool tag_comparison_seed_ok;
static void tag_rebuild_evidence_controls(const struct zcl_app_offer_row *, const struct json_value *, const struct json_value *);
static void tag_comparison_seed(const struct zcl_app_offer_row *, const struct json_value *, const struct json_value *);
static void tag_discover_diagnostic(const struct zcl_command_reply *reply, const char *continuation)
{
    if (continuation && !strcmp(continuation, "failed")) {
        const struct json_value *error = json_get(&reply->data, "continuation_error");
        const char *code = zcl_package_copy_str(error, "code");
        printf("  [discover continuation=%.32s error=%.64s]\n", continuation, code ? code : "unknown");
        const struct json_value *operations = json_get(&reply->data, "operations");
        for (size_t i = 0; operations && i < json_size(operations); ++i) {
            const struct json_value *op = json_at(operations, i);
            const char *status = zcl_package_copy_str(op, "status");
            const char *excerpt = zcl_package_copy_str(op, "error_excerpt");
            printf("  [discover operation=%zu status=%.32s excerpt=%.160s]\n", i,
                   status ? status : "unknown", excerpt ? excerpt : "");
        }
    }
}
static void tag_discover_capture(struct tag_discover *d)
{
    if (!d->reply || d->first_result[0] || !json_get(&d->reply->data, "continuation")) return;
    const char *continuation = zcl_package_copy_str(&d->reply->data, "continuation");
    d->kept = continuation && !strcmp(continuation, "kept");
    tag_discover_diagnostic(d->reply, continuation);
    (void)json_write(&d->reply->data, d->first_result, sizeof(d->first_result));
    const struct json_value *ops = json_get(&d->reply->data, "operations");
    for (size_t i = 0; ops && i < json_size(ops); ++i) {
        const struct json_value *op = json_at(ops, i), *pid = json_get(op, "pid");
        const char *start = zcl_package_copy_str(op, "start_token");
        const char *image = zcl_package_copy_str(op, "image_sha3");
        if (pid && pid->type == JSON_INT && json_get_int(pid) > 1 && start && image && strlen(image) == 64) {
            d->pid = (long)json_get_int(pid); d->start = strtoull(start, NULL, 10);
            memcpy(d->image, image, sizeof(d->image));
        }
    }
}
struct tag_xdg { char *config, *state; bool entered; };
static bool tag_xdg_enter(struct tag_xdg *x, const char *home)
{
    const char *config = getenv("XDG_CONFIG_HOME"), *state = getenv("XDG_STATE_HOME");
    x->config = config ? strdup(config) : NULL; x->state = state ? strdup(state) : NULL;
    if ((config && !x->config) || (state && !x->state)) { free(x->config); free(x->state); return false; }
    x->entered = true;
    return setenv("XDG_CONFIG_HOME", home, 1) == 0 && setenv("XDG_STATE_HOME", home, 1) == 0;
}
static void tag_xdg_leave(struct tag_xdg *x)
{
    if (!x->entered) return;
    if (x->config) (void)setenv("XDG_CONFIG_HOME", x->config, 1); else (void)unsetenv("XDG_CONFIG_HOME");
    if (x->state) (void)setenv("XDG_STATE_HOME", x->state, 1); else (void)unsetenv("XDG_STATE_HOME");
    free(x->config); free(x->state);
}
static bool tag_discover_library_card(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    if (model->action_count != 4 || !strstr(model->summary, "tinyapp")) return false;
    if (!strcmp(model->actions[0].id, "open")) ++d->detail;
    else if (!strcmp(model->actions[0].id, "choose")) ++d->browser;
    else return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    if (d->cancel_after_error && d->errors && !d->share_canceled)
        event->action_index = !strcmp(model->actions[0].id, "open") ? 2 : 0;
    else event->action_index = d->oversized_share && !strcmp(model->actions[0].id, "open") ? 2 : 3;
    return true;
}
static bool tag_discover_error_card(struct tag_discover *d, struct zcl_present_window_event_v1 *event)
{
    ++d->errors;
    if (d->fail_error_view) return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = 0; return true;
}
static bool tag_discover_share_menu(const struct tag_discover *d,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    if (!d->oversized_share && !d->cancel_after_error) return false;
    const char *id = d->share_canceled ? "share-back" : "share-file";
    unsigned i = 0;
    while (i < model->action_count && strcmp(model->actions[i].id, id)) ++i;
    if (i == model->action_count) return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    event->action_index = i; return true;
}
static bool tag_discover_home(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    const char *id = d->home ? "cancel" : "discover";
    if ((d->cancel_after_error && d->errors && !d->share_canceled) ||
        (d->cleanup_swap && d->home == 1)) id = "myapps";
    else if (d->keep && d->home == 1 && d->pid > 0 && d->kept) { g_tag.tamper = true; id = "discover"; }
    unsigned i = 0;
    while (i < model->action_count && strcmp(model->actions[i].id, id)) ++i;
    if (i == model->action_count) return false;
    event->action_index = i;
    ++d->home; return true;
}
static bool tag_discover_card(void *context, const struct zcl_present_model_v1 *model,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct tag_discover *d = context; (void)copy;
    tag_discover_capture(d);
    if (!zcl_present_model_validate_v1(model, why, cap)) return false;
    if (!strcmp(model->request_id, "library-home")) return tag_discover_home(d, model, event);
    if (!strcmp(model->request_id, "library-share-options"))
        return tag_discover_share_menu(d, model, event);
    if (d->keep && !strncmp(model->request_id, "library-", 8) && strcmp(model->request_id, "library-error"))
        return tag_discover_library_card(d, model, event);
    if (!strcmp(model->request_id, "discover-error")) return tag_discover_error_card(d, event);
    if (strcmp(model->request_id, "discover-0")) return false;
    ++d->cards; event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = 0; return true;
}
static bool tag_discover_visit_pages(const struct zcl_present_window_live_view_v1 *live, uint32_t count)
{
    bool redraw = false, close = false;
    if (count > 1) {
        struct zcl_present_window_event_v1 early = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 3};
        live->owner.update(live->owner.context, &early, true, &redraw, &close);
        if (close) return false;
    }
    for (uint32_t i = 1; i < count; ++i) {
        struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = '3'};
        uint32_t focus = 0, action = 0;
        if (!live->input(live->owner.context, &input, &focus, &action) || action != 2) return false;
        struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
        live->owner.update(live->owner.context, &e, true, &redraw, &close);
        if (close) return false;
    }
    return true;
}
static bool tag_discover_confirm(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    bool redraw = false, close = false;
    if (d->close_keep && !strcmp(model->title, "Preview opened")) {
        struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
        live->owner.update(live->owner.context, &event, true, &redraw, &close); return close;
    }
    uint32_t count = 0;
    if (!zcl_present_model_page_count_v1(model, &count, why, cap) || !tag_discover_visit_pages(live, count)) return false;
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = '4'};
    uint32_t focus = 0, action = 0;
    if (!live->input(live->owner.context, &input, &focus, &action) || action != 3) return false;
    struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    live->owner.update(live->owner.context, &e, true, &redraw, &close);
    if (close && d->cleanup_swap && !strcmp(model->title, "Preview opened") &&
        !tag_replace_stage(&d->swap, g_tag.fetch_out)) return false;
    return close;
}
static bool tag_discover_host_choice(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    d->host_prompted = true;
    struct zcl_app_offer original; char pub[17], root_prefix[17];
    if (!zcl_app_offer_parse(g_tag.text, strlen(g_tag.text), &original)) return false;
    (void)snprintf(pub, sizeof(pub), "%.16s", original.publisher);
    (void)snprintf(root_prefix, sizeof(root_prefix), "%.16s", original.root);
    bool name = false, publisher = false, root = false;
    for (unsigned i = 0; i < model->item_count; ++i) {
        name |= strstr(model->items[i].value, original.name) != NULL;
        publisher |= strstr(model->items[i].value, pub) != NULL;
        root |= strstr(model->items[i].value, root_prefix) != NULL;
    }
    d->host_identity = name && publisher && root;
    if (d->host_original) return tag_discover_confirm(d, model, live, why, cap);
    bool redraw = false, close = false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
    live->owner.update(live->owner.context, &event, true, &redraw, &close); return close;
}
static bool tag_discover_report_choice(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    d->report_prompted = true;
    bool keys = false, snapshot = false, unavailable = false;
    for (unsigned i = 0; i < model->item_count; ++i) {
        keys |= strstr(model->items[i].value, d->comparison_mode == 2 || d->comparison_mode == 4 ? "2 distinct" : "0 distinct") != NULL;
        snapshot |= strstr(model->items[i].value, "snapshot") != NULL;
        unavailable |= strstr(model->items[i].value, "unavailable") != NULL;
    }
    if (d->report_rebuild) {
        bool shown = tag_discover_confirm(d, model, live, why, cap);
        d->report_count_visible = shown && keys && snapshot;
        if (d->comparison_mode == 4) g_tag.malformed_board = true;
        return shown;
    }
    uint32_t pages = 0;
    if (!zcl_present_model_page_count_v1(model, &pages, why, cap) || !tag_discover_visit_pages(live, pages)) return false;
    d->report_count_visible = d->comparison_mode == 3 ? unavailable && !keys : keys && snapshot;
    bool redraw = false, close = false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
    live->owner.update(live->owner.context, &event, true, &redraw, &close); return close;
}
static bool tag_fetch_present(struct tag_discover *d, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live)
{
        if (!strstr(model->summary, "Downloading and checking")) return false;
        if (tag_require_fetch_progress) {
            int64_t end = platform_time_monotonic_ms() + 30000;
            while (!atomic_load(&tag_fetch_progress_entered) && platform_time_monotonic_ms() < end) platform_sleep_ms(1);
            if (!atomic_load(&tag_fetch_progress_entered)) { atomic_store(&tag_fetch_progress_release, true); return false; }
        }
        atomic_store(&tag_fetch_progress_seen, true);
        bool redraw = false, close = false;
        if (d->fetch_close) {
            live->owner.update(live->owner.context, NULL, true, &redraw, &close);
            if (close || !redraw || !strstr(model->summary, "Waiting for the current download")) {
                atomic_store(&tag_fetch_progress_release, true); return false;
            }
        }
        atomic_store(&tag_fetch_progress_release, true);
        if (d->fetch_presenter_fail) return false;
        while (!close) { live->owner.update(live->owner.context, NULL, false, &redraw, &close); if (!close) platform_sleep_ms(1); }
        return true;
}
static void tag_discover_report_result(struct tag_discover *d, const struct zcl_present_model_v1 *model)
{
    d->report_result = true;
    for (unsigned i = 0; i < model->item_count; ++i) {
        if (strstr(model->items[i].value, "unavailable")) d->report_result_unavailable = true;
        if (strstr(model->items[i].value, "0 distinct")) d->report_result_count = true;
        if (strstr(model->items[i].value, "2 distinct")) d->report_result_two = true;
    }
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, "publish")) d->report_result_publish = true;
}
static bool tag_discover_receive(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct tag_discover *d = context; (void)pages;
    if (!zcl_present_model_validate_v1(model, why, cap)) return false;
    if (!strcmp(model->request_id, "discover-fetch-progress")) return tag_fetch_present(d, model, live);
    if (d->fail_host_result && !strcmp(model->request_id, "discover-host-result")) return false;
    if (!strcmp(model->request_id, "discover-rebuild-result")) tag_discover_report_result(d, model);
    if (!strcmp(model->request_id, "discover-report-rebuild")) return tag_discover_report_choice(d, model, live, why, cap);
    if (!strcmp(model->request_id, "library-recovery")) d->recovery_shown = true;
    ++d->receive; bool redraw = false, close = false;
    if (!strcmp(model->request_id, "discover-host-original")) return tag_discover_host_choice(d, model, live, why, cap);
    if (d->keep && (!strcmp(model->request_id, "receive-copy") || model->action_count == 0)) {
        int64_t end = platform_time_monotonic_ms() + 60000;
        do {
            live->owner.update(live->owner.context, NULL, false, &redraw, &close);
            if (close) return true;
            platform_sleep_ms(1); /* real-clock: wait for this owner's actual worker */
        } while (platform_time_monotonic_ms() < end);
        return false;
    }
    if (d->keep) return tag_discover_confirm(d, model, live, why, cap);
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_DISMISSED};
    live->owner.update(live->owner.context, &event, true, &redraw, &close); return close;
}
static int tag_discover_fetch_close(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover d = {0};
    TEST("Closing a pending Discover fetch waits, cleans up and never starts Receive") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        atomic_store(&tag_fetch_progress_seen, false); atomic_store(&tag_fetch_progress_release, false); atomic_store(&tag_fetch_progress_entered, false); atomic_store(&tag_fetch_progress_timeout, false);
        tag_require_fetch_progress = true; d.fetch_close = true;
        int offers = g_tag.offers, posts = g_tag.posts;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        (void)app_discover_run(w->j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL);
        tag_require_fetch_progress = false;
        ASSERT(atomic_load(&tag_fetch_progress_seen)); ASSERT(!atomic_load(&tag_fetch_progress_timeout)); ASSERT_EQ(d.receive, 0);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT(!strcmp(zcl_package_copy_str(&reply.data, "status"), "canceled"));
        ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.posts, posts);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        zcl_command_reply_free(&reply); PASS();
    }
    TEST("A failed fetch progress presenter waits for worker cleanup and refuses Receive") {
        ASSERT(tag_board_variant(w, NULL, NULL, false)); memset(&d, 0, sizeof(d));
        atomic_store(&tag_fetch_progress_seen, false); atomic_store(&tag_fetch_progress_release, false); atomic_store(&tag_fetch_progress_entered, false); atomic_store(&tag_fetch_progress_timeout, false);
        tag_require_fetch_progress = true; d.fetch_presenter_fail = true;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        (void)app_discover_run(w->j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL);
        tag_require_fetch_progress = false;
        ASSERT(atomic_load(&tag_fetch_progress_seen)); ASSERT(!atomic_load(&tag_fetch_progress_timeout)); ASSERT_EQ(d.receive, 0);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        zcl_command_reply_free(&reply); PASS();
    }
    TEST("A failed selected carrier fetch reports failure without Receive or staging") {
        ASSERT(tag_board_variant(w, NULL, NULL, false)); memset(&d, 0, sizeof(d));
        atomic_store(&tag_fetch_progress_seen, false); atomic_store(&tag_fetch_progress_release, false); atomic_store(&tag_fetch_progress_entered, false); atomic_store(&tag_fetch_progress_timeout, false);
        tag_require_fetch_progress = true; g_tag.fetch_failures = 1;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        (void)app_discover_run(w->j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL);
        tag_require_fetch_progress = false; g_tag.fetch_failures = 0;
        ASSERT(atomic_load(&tag_fetch_progress_seen)); ASSERT(!atomic_load(&tag_fetch_progress_timeout)); ASSERT_EQ(d.receive, 0);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        zcl_command_reply_free(&reply); PASS();
    } _test_next:;
    tag_require_fetch_progress = false; atomic_store(&tag_fetch_progress_release, true);
    return failures;
}
struct tag_rpc_fetch { struct json_value input; struct zcl_command_reply reply; };
static atomic_bool tag_rpc_profile_ok;
static const char *tag_rpc_expected_profile;
static char *tag_fetch_rpc_profile(const char *method, const char *params)
{
    (void)params;
    if (strcmp(method, "fleet_bundle_fetch")) return NULL;
    atomic_store(&tag_fetch_progress_entered, true);
    int64_t end = platform_time_monotonic_ms() + 30000;
    while (!atomic_load(&tag_fetch_progress_release) && platform_time_monotonic_ms() < end) platform_sleep_ms(1);
    atomic_store(&tag_rpc_profile_ok, !strcmp(node_rpc_client_datadir(), tag_rpc_expected_profile) &&
        node_rpc_client_port() == 19381 && atomic_load(&tag_fetch_progress_release));
    return strdup("{\"ok\":false,\"code\":\"TEST_REFUSED\",\"message\":\"fixture refusal\"}");
}
static bool tag_actual_fetch(void *context)
{
    struct tag_rpc_fetch *f = context;
    return zcl_app_inner_call("fleet.bundle.fetch", &f->input, &f->reply, NULL);
}
static int tag_fetch_native_profile(struct tag_world *w)
{
    int failures = 0; struct tag_discover d = {0}; struct tag_rpc_fetch f;
    char out[TAG_PATH];
    char *old = strdup(zcl_native_command_datadir()); int port = zcl_native_command_rpc_port();
    json_init(&f.input); json_set_object(&f.input); zcl_command_reply_init(&f.reply, "zcl.test");
    TEST("Fetch progress worker preserves the actual native RPC profile") {
        int n = snprintf(out, sizeof(out), "%s/profile-fetch.z23share", w->root);
        ASSERT(n > 0 && (size_t)n < sizeof(out));
        ASSERT(old && json_push_kv_str(&f.input, "root", TAG_CARRIER) &&
            json_push_kv_str(&f.input, "sha256", TAG_CARRIER) &&
            json_push_kv_str(&f.input, "out", out) &&
            json_push_kv_int(&f.input, "size", 64) && json_push_kv_int(&f.input, "timeout_s", 1));
        atomic_store(&tag_fetch_progress_entered, false); atomic_store(&tag_fetch_progress_release, false);
        atomic_store(&tag_rpc_profile_ok, false); tag_require_fetch_progress = true;
        tag_rpc_expected_profile = strcmp(old, w->j.a_datadir) ? w->j.a_datadir : w->j.b_datadir;
        zcl_native_bridge_bind_rpc(tag_rpc_expected_profile, 19381); node_rpc_client_set_test_hook(tag_fetch_rpc_profile);
        enum app_fetch_progress_result result = app_fetch_progress_run(tag_actual_fetch, &f, tag_discover_receive, &d);
        node_rpc_client_set_test_hook(NULL); zcl_native_bridge_bind_rpc(old, port); tag_require_fetch_progress = false;
        if (result != APP_FETCH_FAILED || !atomic_load(&tag_rpc_profile_ok))
            fprintf(stderr, "native fetch fixture: result=%d code=%.80s message=%.160s\n",
                (int)result, f.reply.error.code, f.reply.error.message);
        ASSERT_EQ(result, APP_FETCH_FAILED); ASSERT(atomic_load(&tag_rpc_profile_ok)); PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL); if (old) zcl_native_bridge_bind_rpc(old, port);
    tag_require_fetch_progress = false; atomic_store(&tag_fetch_progress_release, true);
    free(old); json_free(&f.input); zcl_command_reply_free(&f.reply); return failures;
}
static int tag_discover_cancel(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover d = {0};
    TEST("Discover reviews the selected verified offer and native Receive can cancel without hosting") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        int offers = g_tag.offers, posts = g_tag.posts;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        ASSERT(!app_discover_run(w->j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL));
        ASSERT_EQ(d.cards, 1); ASSERT_EQ(d.receive, 1); ASSERT(!d.host_prompted);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT(!strcmp(zcl_package_copy_str(&reply.data, "status"), "canceled"));
        ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.posts, posts);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        ASSERT_EQ(tag_glob(w->j.b_datadir, "copies/*"), 0u);
        zcl_command_reply_free(&reply); PASS();
    }
    TEST("Discover displays progress while its selected carrier fetch is pending") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        memset(&d, 0, sizeof(d)); atomic_store(&tag_fetch_progress_seen, false); atomic_store(&tag_fetch_progress_release, false); atomic_store(&tag_fetch_progress_entered, false); atomic_store(&tag_fetch_progress_timeout, false);
        tag_require_fetch_progress = true;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        (void)app_discover_run(w->j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL);
        tag_require_fetch_progress = false;
        ASSERT(atomic_load(&tag_fetch_progress_seen)); ASSERT(!atomic_load(&tag_fetch_progress_timeout));
        ASSERT_EQ(d.receive, 1); ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        zcl_command_reply_free(&reply); PASS();
    } _test_next:;
    return failures;
}
static int tag_library_discover(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover d = {0};
    struct app_launch_env env; char why[256]; struct tag_xdg x = {0};
    TEST("My Apps home enters Discover and returns after native Receive cancel") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        ASSERT(tag_xdg_enter(&x, w->j.b_home));
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        int offers = g_tag.offers, posts = g_tag.posts;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_discover(&env, w->j.b_datadir, &reply,
            tag_discover_card, tag_discover_receive, &d);
        ASSERT_EQ(d.home, 2); ASSERT_EQ(d.cards, 1); ASSERT_EQ(d.receive, 1);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.posts, posts);
        ASSERT_EQ(tag_glob(w->j.b_datadir, "copies/*"), 0u);
        zcl_command_reply_free(&reply); PASS();
    }
    TEST("Discover refusal shows one error then Back returns to the home menu") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        memset(&d, 0, sizeof(d)); g_tag.tamper = true;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_discover(&env, w->j.b_datadir, &reply,
            tag_discover_card, tag_discover_receive, &d);
        g_tag.tamper = false;
        ASSERT_EQ(d.home, 2); ASSERT_EQ(d.cards, 1); ASSERT_EQ(d.errors, 1); ASSERT_EQ(d.receive, 0);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT(!strcmp(reply.error.code, "SHA256_MISMATCH"));
        zcl_command_reply_free(&reply); PASS();
    } _test_next:;
    g_tag.tamper = false;
    tag_xdg_leave(&x);
    return failures;
}
static bool tag_profile_canceled(const struct zcl_command_reply *reply, const struct tag_discover *d,
    const char *node, const char *stage_parent)
{
    return reply->status == ZCL_COMMAND_STATUS_PASSED && !reply->error.mutated && d->receive == 1 &&
        !strcmp(zcl_native_command_datadir(), node) &&
        !strncmp(g_tag.fetch_out, stage_parent, strlen(stage_parent));
}
static int tag_library_profile(struct tag_world *w)
{
    int failures = 0; struct tag_world fresh = *w; struct tag_xdg x = {0};
    struct tag_discover d = {0}; struct app_launch_env env; char why[256];
    bool had_home = getenv("HOME") != NULL;
    char *old_home = had_home ? strdup(getenv("HOME")) : NULL;
    char *old_node = strdup(zcl_native_command_datadir()); int old_port = zcl_native_command_rpc_port();
    struct json_value input; json_init(&input); json_set_object(&input);
    struct zcl_command_request request = {.input = &input};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps uses its explicit app profile while the node target stays separate") {
        ASSERT((!had_home || old_home) && old_node && test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_profile"));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root));
        ASSERT(rmdir(fresh.j.b_datadir) == 0 && chmod(fresh.j.b_home, 0755) == 0);
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        ASSERT(tag_xdg_enter(&x, fresh.j.b_home) && app_launch_env_from_process(&env, why, sizeof(why)));
        zcl_native_bridge_bind_rpc(w->j.a_datadir, 0);
        ASSERT(json_push_kv_str(&input, "datadir", fresh.j.b_datadir));
        g_tag.fetch_out[0] = 0; int offers = g_tag.offers, posts = g_tag.posts;
        zcl_test_app_library_request(&env, &request, &reply, tag_discover_card, tag_discover_receive, &d);
        struct stat st;
        ASSERT(tag_profile_canceled(&reply, &d, w->j.a_datadir, fresh.j.b_home));
        ASSERT(lstat(fresh.j.b_datadir, &st) != 0 && errno == ENOENT);
        ASSERT_EQ(tag_glob(fresh.j.b_home, ".app-get-*"), 0u);
        ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.posts, posts); PASS();
    }
    TEST("My Apps without an app profile retains the bound node datadir") {
        json_free(&input); json_init(&input); json_set_object(&input);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        memset(&d, 0, sizeof(d)); g_tag.fetch_out[0] = 0;
        int offers = g_tag.offers, posts = g_tag.posts;
        zcl_test_app_library_request(&env, &request, &reply, tag_discover_card, tag_discover_receive, &d);
        ASSERT(tag_profile_canceled(&reply, &d, w->j.a_datadir, w->j.a_datadir));
        ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.posts, posts); PASS();
    } _test_next:;
    if (old_node) { zcl_native_bridge_bind_rpc(old_node, old_port); free(old_node); }
    tag_xdg_leave(&x);
    if (old_home) { (void)setenv("HOME", old_home, 1); free(old_home); }
    else if (!had_home) (void)unsetenv("HOME");
    zcl_command_reply_free(&reply); json_free(&input); return failures;
}
static bool tag_kept_selection(const struct app_launch_env *env,
    struct app_selection *selection)
{
    struct app_selection_routes routes;
    return app_selection_routes_load(env->state_dir, &routes) == APP_SELECTION_OK && routes.count == 1 &&
        app_selection_load(env->state_dir, routes.names[0], selection) == APP_SELECTION_OK;
}
static bool tag_stop_receipt(const struct tag_discover *d, const char *datadir)
{
    if (!d->pid) return true;
    char image[TAG_PATH], resolved[PATH_MAX], actual[APP_LAUNCH_PATH_MAX]; uint64_t start = 0;
    int n = snprintf(image, sizeof(image), "%s/app_build/images/%s", datadir, d->image);
    return n > 0 && (size_t)n < sizeof(image) && realpath(image, resolved) &&
        app_proc_identity(d->pid, actual, &start) && start == d->start &&
        !strcmp(actual, resolved) && asf_alive_then_stop(d->pid);
}
static bool tag_first_use_cancel(struct tag_world *fresh)
{
    struct tag_discover cancel = {0}; struct zcl_command_reply reply; struct stat st;
    int offers = g_tag.offers, posts = g_tag.posts;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool ok = !app_discover_run(fresh->j.b_datadir, tag_discover_card, tag_discover_receive, &cancel, &reply, NULL) &&
        reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        lstat(fresh->j.b_datadir, &st) != 0 && errno == ENOENT &&
        tag_glob(fresh->j.b_home, ".app-get-*") == 0 && g_tag.offers == offers && g_tag.posts == posts;
    zcl_command_reply_free(&reply); return ok;
}
static bool tag_fixture_worker(const struct tag_world *w, char worker[PATH_MAX])
{
    char input[PATH_MAX];
    int n = snprintf(input, sizeof(input), "%s/build/bin/z23-dev", w->saved_cwd);
    return n > 0 && (size_t)n < sizeof(input) && realpath(input, worker);
}
static bool tag_host_failure_wire(struct zcl_command_reply *reply, const char *expected_carrier)
{
    char wire[32768]; const struct zcl_command_spec *spec = asf_spec("app.library");
    size_t n = spec ? zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, reply, wire, sizeof(wire)) : 0;
    struct json_value decoded; json_init(&decoded);
    bool parsed = n && n < sizeof(wire) && json_read(&decoded, wire, n);
    const struct json_value *facts = json_get(json_get(&decoded, "error"), "facts");
    const char *host = zcl_package_copy_str(facts, "hosting_host"), *carrier = zcl_package_copy_str(facts, "hosting_carrier");
    bool retained = parsed && json_get_bool(json_get(facts, "hosting_enabled")) && host && carrier &&
        !strcmp(host, TAG_LOCAL_HOST) && !strcmp(carrier, expected_carrier) &&
        json_get_int(json_get(facts, "hosting_generation")) == 1;
    json_free(&decoded); return retained;
}
static int tag_host_result_failure(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply;
    struct tag_discover d = {.keep = true, .host_original = true, .fail_host_result = true};
    struct tag_world fresh = *w; char worker[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL; bool fixture_ready = false;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Discover preserves enabled hosting identity when its result cannot be displayed") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_host_result"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root)); fixture_ready = true;
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        d.reply = &reply;
        ASSERT(!app_discover_run_test(fresh.j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL, worker));
        tag_discover_capture(&d);
        ASSERT(d.host_prompted && d.pid > 0 && reply.error.mutated && !strcmp(reply.error.code, "HOSTING_RESULT_UNAVAILABLE"));
        ASSERT(tag_host_failure_wire(&reply, fresh.offer.carrier)); PASS();
    } _test_next:;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    zcl_command_reply_free(&reply);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); } else (void)unsetenv("HOME");
    return failures;
}
static bool tag_comparison_case_result(const struct tag_discover *d, int mode, int posts)
{
    if (!tag_comparison_seed_ok || !d->report_prompted || !d->report_count_visible) return false;
    if (mode == 4) return d->report_result && d->report_result_unavailable &&
        !d->report_result_count && !d->report_result_two && g_tag.posts == posts + 1;
    return !d->report_result && g_tag.posts == posts;
}
static bool tag_unconfirmed_report(const struct tag_discover *d, const struct zcl_command_reply *reply, int posts)
{
    const char *status = zcl_package_copy_str(&reply->data, "rebuild_report");
    const char *retry = zcl_package_copy_str(&reply->data, "rebuild_retry");
    return d->report_prompted && d->report_result && g_tag.posts == posts + 1 &&
        status && strstr(status, "publication unconfirmed") && retry &&
        strstr(retry, "fleet board post --kind=result") && strstr(retry, g_tag.result_text);
}
static bool tag_rebuild_case_result(const struct tag_discover *d, const struct zcl_command_reply *reply,
    int mode, int posts)
{
    if (!d->pid || !reply->error.mutated || reply->status != ZCL_COMMAND_STATUS_PASSED) return false;
    const char *continuation = zcl_package_copy_str(&reply->data, "continuation");
    if (mode == 0) return !d->report_prompted && g_tag.posts == posts && continuation &&
        !strcmp(continuation, "previewed");
    if (mode >= 2) return tag_comparison_case_result(d, mode, posts);
    return tag_unconfirmed_report(d, reply, posts);
}
static int tag_rebuild_case(struct tag_world *w, int mode)
{
    int failures = 0; struct zcl_command_reply reply;
    struct tag_discover d = {.keep = true, .close_keep = mode == 0,
        .report_rebuild = mode == 1 || mode == 4, .comparison_mode = mode};
    struct tag_world fresh = *w; char worker[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL; bool fixture_ready = false;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Discover keeps Close and uncertain report outcomes distinct") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_report"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root)); fixture_ready = true;
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        int posts = g_tag.posts; g_tag.fail_result_post = mode == 1; d.reply = &reply;
        tag_comparison_seed_mode = mode; tag_comparison_seed_ok = false;
        if (mode >= 2) app_discover_test_evidence_hook(tag_comparison_seed);
        bool done = app_discover_run_test(fresh.j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL, worker);
        app_discover_test_evidence_hook(NULL);
        g_tag.fail_result_post = false; tag_discover_capture(&d);
        ASSERT(done && tag_rebuild_case_result(&d, &reply, mode, posts)); PASS();
    } _test_next:;
    app_discover_test_evidence_hook(NULL); g_tag.fail_result_post = false; g_tag.malformed_board = false;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    zcl_command_reply_free(&reply);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); } else (void)unsetenv("HOME");
    return failures;
}
static int tag_cached_comparison(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover d = {.keep = true};
    struct tag_world fresh = *w; char worker[PATH_MAX]; bool fixture_ready = false;
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Discover shows cached comparison without asking to publish") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_cached_comparison"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root)); fixture_ready = true;
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        int posts = g_tag.posts; d.reply = &reply;
        ASSERT(app_discover_run_test(fresh.j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL, worker));
        tag_discover_capture(&d); ASSERT(d.report_prompted && !d.report_result && tag_stop_receipt(&d, fresh.j.b_datadir));
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        memset(&d, 0, sizeof(d)); d.keep = true; d.reply = &reply;
        ASSERT(app_discover_run_test(fresh.j.b_datadir, tag_discover_card, tag_discover_receive, &d, &reply, NULL, worker));
        tag_discover_capture(&d);
        const char *status = zcl_package_copy_str(&reply.data, "rebuild_report");
        ASSERT(status && strstr(status, "cached image") && d.report_result && d.report_result_count &&
            !d.report_prompted && !d.report_result_publish && g_tag.posts == posts); PASS();
    } _test_next:;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    zcl_command_reply_free(&reply);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); } else (void)unsetenv("HOME");
    return failures;
}
static void tag_cancelled_share(void *context, const struct app_selection *selection,
                                const char *path, struct zcl_command_reply *reply)
{
    struct tag_discover *d = context; (void)selection; (void)path;
    d->share_canceled = true;
    if (!json_push_kv_str(&reply->data, "status", "canceled"))
        zcl_package_copy_fail(reply, "ALLOC", false, "Cannot record cancellation", "fixture");
}
static bool tag_rebuild_post_identity(const struct tag_world *w, const struct tag_discover *d)
{
    struct json_value report; json_init(&report);
    bool ok = json_read(&report, g_tag.result_text, strlen(g_tag.result_text));
    const char *schema = zcl_package_copy_str(&report, "schema"), *publisher = zcl_package_copy_str(&report, "publisher");
    const char *root = zcl_package_copy_str(&report, "release_root"), *image = zcl_package_copy_str(&report, "image");
    ok = ok && schema && publisher && root && image && !strcmp(schema, "zcl.app_rebuild.v1") &&
        !strcmp(publisher, w->offer.publisher) && !strcmp(root, w->offer.root) && !strcmp(image, d->image);
    json_free(&report); return ok && d->report_result;
}
static void tag_discover_failure_diagnostic(const struct tag_discover *d, const struct zcl_command_reply *reply,
    char *wire, size_t capacity)
{
    if (d->pid && d->detail == 3 && d->errors == 1) return;
    wire[0] = 0; (void)json_write(&reply->data, wire, capacity);
    printf("  [discover diagnostic: receive=%d home=%d detail=%d errors=%d code=%s message=%s first=%s final=%s]\n",
        d->receive, d->home, d->detail, d->errors, reply->error.code, reply->error.message, d->first_result, wire);
}
static int tag_library_kept_failure(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover d = {.keep = true, .cancel_after_error = true, .host_original = true, .report_rebuild = true};
    struct app_launch_env env; char why[256], wire[32768], worker[PATH_MAX];
    struct app_selection selection = {0}; struct tag_xdg x = {0};
    struct tag_world fresh = *w; char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    bool fixture_ready = false;
    TEST("Discover keeps the exact received app then preserves its compact reference on later failure") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_discover"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root));
        fixture_ready = true;
        ASSERT(rmdir(fresh.j.b_datadir) == 0 && chmod(fresh.j.b_home, 0755) == 0);
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false)); ASSERT(setenv("HOME", fresh.j.b_home, 1) == 0);
        ASSERT(tag_xdg_enter(&x, fresh.j.b_home));
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        ASSERT(tag_first_use_cancel(&fresh));
        int offers = g_tag.offers, enables = g_tag.enables, posts = g_tag.posts;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        d.reply = &reply;
        tag_rebuild_controls_seen = tag_rebuild_controls_ok = false;
        app_discover_test_evidence_hook(tag_rebuild_evidence_controls);
        zcl_test_app_library_discover_worker_share(&env, fresh.j.b_datadir, &reply,
            tag_discover_card, tag_discover_receive, &d, worker, tag_cancelled_share);
        app_discover_test_evidence_hook(NULL);
        g_tag.tamper = false;
        tag_discover_capture(&d);
        tag_discover_failure_diagnostic(&d, &reply, wire, sizeof(wire));
        ASSERT(d.pid > 0); ASSERT(tag_rebuild_controls_seen && tag_rebuild_controls_ok); ASSERT(d.report_prompted); ASSERT(d.report_count_visible); ASSERT_EQ(g_tag.posts, posts + 1);
        ASSERT(tag_rebuild_post_identity(w, &d));
        ASSERT(d.host_prompted && d.host_identity); ASSERT_EQ(g_tag.offers, offers + 1);
        ASSERT_EQ(g_tag.enables, enables + 1); ASSERT(strstr(g_tag.enable_text, w->offer.root));
        ASSERT(tag_kept_selection(&env, &selection));
        ASSERT_EQ(d.detail, 3); ASSERT(d.share_canceled); ASSERT_EQ(d.errors, 1);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.mutated);
        ASSERT(!strcmp(reply.error.code, "SHA256_MISMATCH"));
        const struct json_value *facts = json_get(&reply.data, "failure_facts");
        const struct json_value *kept = json_get(facts, "historical_keep");
        ASSERT(kept && !strcmp(zcl_package_copy_str(kept, "name"), selection.app));
        ASSERT(json_get_int(json_get(kept, "selection_revision")) == (int64_t)selection.revision);
        const struct zcl_command_spec *spec = asf_spec("app.library");
        ASSERT(spec);
        size_t n = zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, &reply, wire, sizeof(wire));
        ASSERT(n && n < sizeof(wire) && strstr(wire, "historical_keep") && strstr(wire, selection.app));
        zcl_command_reply_free(&reply); PASS();
    } _test_next:;
    app_discover_test_evidence_hook(NULL);
    g_tag.tamper = false;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    tag_xdg_leave(&x);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); }
    else (void)unsetenv("HOME");
    return failures;
}
static bool tag_kept_reference(const struct json_value *kept, const struct app_selection *selection)
{
    char version[65], image[65], record[65];
    zcl_hex_encode(selection->version, 32, version); zcl_hex_encode(selection->image, 32, image);
    zcl_hex_encode(selection->record, 32, record);
    const char *name = zcl_package_copy_str(kept, "name"), *v = zcl_package_copy_str(kept, "version");
    const char *i = zcl_package_copy_str(kept, "image_sha3"), *r = zcl_package_copy_str(kept, "record_id");
    const struct json_value *revision = json_get(kept, "selection_revision");
    return name && v && i && r && revision && revision->type == JSON_INT &&
        !strcmp(name, selection->app) && !strcmp(v, version) && !strcmp(i, image) &&
        !strcmp(r, record) && json_get_int(revision) == (int64_t)selection->revision;
}
static void tag_oversized_share(void *context, const struct app_selection *selection,
    const char *path, struct zcl_command_reply *reply)
{
    (void)context; (void)selection; (void)path;
    char large[2100], evidence[256], message[192];
    memset(large, '\\', sizeof(large) - 1); large[sizeof(large) - 1] = 0;
    memset(evidence, '\\', sizeof(evidence) - 1); evidence[sizeof(evidence) - 1] = 0;
    memset(message, '\\', sizeof(message) - 1); message[sizeof(message) - 1] = 0;
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "FIXTURE_OVERSIZED", "share", false, true, message, evidence);
    memset(reply->error.next_action, '\\', sizeof(reply->error.next_action) - 1);
    reply->error.next_action[sizeof(reply->error.next_action) - 1] = 0;
    memset(reply->error.current_state, '\\', sizeof(reply->error.current_state) - 1);
    reply->error.current_state[sizeof(reply->error.current_state) - 1] = 0;
    memset(reply->error.failure_id, '\\', sizeof(reply->error.failure_id) - 1);
    reply->error.failure_id[sizeof(reply->error.failure_id) - 1] = 0;
    (void)json_push_kv_str(&facts, "destination", large);
    (void)json_push_kv_str(&facts, "secondary", "still available");
    (void)json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
}
static bool tag_cleanup_recovery_wire(struct zcl_command_reply *reply,
    const struct app_selection *selection)
{
    char wire[32768]; const struct zcl_command_spec *spec = asf_spec("app.library");
    if (!spec || !zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, reply, wire, sizeof(wire))) return false;
    struct json_value decoded; json_init(&decoded);
    bool parsed = json_read(&decoded, wire, strlen(wire));
    const struct json_value *kept = json_get(json_get(json_get(&decoded, "error"), "facts"), "historical_keep");
    bool matched = parsed && tag_kept_reference(kept, selection); json_free(&decoded); return matched;
}
static bool tag_oversized_recovery_wire(struct zcl_command_reply *reply,
    const struct app_selection *selection)
{
    char wire[3073]; const struct zcl_command_spec *spec = asf_spec("app.library");
    char evidence[40]; memset(evidence, '\\', sizeof(evidence) - 1); evidence[39] = '\0';
    struct zcl_command_budget_fixture fixture = {.authority_evidence = evidence,
        .debited_zat = INT64_MAX, .remaining_zat = INT64_MAX, .elapsed_us = INT64_MAX,
        .budget_bytes = ZCL_COMMAND_ERROR_BUDGET, .presented = true, .alias = true};
    if (!spec || !zcl_command_registry_test_reply_wire_fixture(zcl_command_catalog(), spec,
        reply, &fixture, wire, sizeof(wire))) return false;
    struct json_value decoded; json_init(&decoded);
    bool parsed = json_read(&decoded, wire, strlen(wire));
    const struct json_value *facts = json_get(json_get(&decoded, "error"), "facts");
    const char *message = zcl_package_copy_str(json_get(&decoded, "error"), "message");
    const char *secondary = zcl_package_copy_str(facts, "secondary");
    bool matched = parsed && tag_kept_reference(json_get(facts, "historical_keep"), selection) &&
        json_get_bool(json_get(facts, "details_unavailable")) && !json_get(facts, "destination") &&
        secondary && !strcmp(secondary, "still available") && message && strlen(message) == 191;
    json_free(&decoded); return matched;
}
static int tag_library_oversized_failure(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct tag_discover d = {.keep = true, .oversized_share = true};
    struct tag_world fresh = *w; struct tag_xdg x = {0}; struct app_launch_env env;
    struct app_selection selection = {0}; char why[256], worker[PATH_MAX];
    char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL; bool fixture_ready = false;
    TEST("Keep survives a later oversized failure with exact bounded recovery") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_oversized"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root)); fixture_ready = true;
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        ASSERT(tag_xdg_enter(&x, fresh.j.b_home) && app_launch_env_from_process(&env, why, sizeof(why)));
        int offers = g_tag.offers, enables = g_tag.enables, posts = g_tag.posts;
        d.reply = &reply;
        zcl_test_app_library_discover_worker_share(&env, fresh.j.b_datadir, &reply,
            tag_discover_card, tag_discover_receive, &d, worker, tag_oversized_share);
        tag_discover_capture(&d);
        ASSERT(d.pid > 0 && d.kept && d.detail == 1 && tag_kept_selection(&env, &selection));
        ASSERT(d.host_prompted && d.host_identity && d.report_prompted); ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.enables, enables); ASSERT_EQ(g_tag.posts, posts);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.mutated &&
            !strcmp(reply.error.code, "FIXTURE_OVERSIZED"));
        ASSERT(tag_oversized_recovery_wire(&reply, &selection)); PASS();
    } _test_next:;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    zcl_command_reply_free(&reply); tag_xdg_leave(&x);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); }
    else (void)unsetenv("HOME");
    return failures;
}
static bool tag_cleanup_foreign(struct tag_discover *d, const char *root)
{
    char foreign[TAG_PATH], canonical[PATH_MAX];
    int n = snprintf(foreign, sizeof(foreign), "%s/foreign", root);
    if (n <= 0 || (size_t)n >= sizeof(foreign) || mkdir(foreign, 0700) ||
        !realpath(foreign, canonical) || strlen(canonical) >= sizeof(d->swap.foreign)) return false;
    memcpy(d->swap.foreign, canonical, strlen(canonical) + 1);
    return asf_put(d->swap.foreign, "offer.z23share", "foreign stays\n");
}
static bool tag_cleanup_navigation(const struct tag_discover *d, bool fail_error_view)
{
    return fail_error_view ? (d->recovery_shown && d->browser == 0 && d->home == 1) :
        (!d->recovery_shown && d->browser == 1 && d->home == 3);
}
static bool tag_cleanup_outcome(const struct tag_discover *d, bool fail_error_view,
    const struct app_launch_env *env, struct app_selection *selection,
    const struct zcl_command_reply *reply)
{
    return d->pid > 0 && d->kept && d->swap.moved && d->swap.linked && d->errors == 1 &&
        tag_cleanup_navigation(d, fail_error_view) &&
        tag_kept_selection(env, selection) && tag_foreign_unchanged(&d->swap) &&
        reply->status != ZCL_COMMAND_STATUS_PASSED && reply->error.mutated &&
        !strcmp(reply->error.code, "TEMP_CLEANUP_FAILED");
}
static int tag_library_cleanup_failure_case(struct tag_world *w, bool fail_error_view)
{
    int failures = 0; struct zcl_command_reply reply;
    struct tag_discover d = {.keep = true, .cleanup_swap = true, .fail_error_view = fail_error_view, .host_original = true};
    struct app_launch_env env; struct app_selection selection = {0}; struct tag_xdg x = {0};
    char why[256], worker[PATH_MAX];
    struct tag_world fresh = *w; char *saved_home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    bool fixture_ready = false; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Keep survives a replaced staging path with one cleanup error and exact recovery") {
        ASSERT(test_mkdtemp(fresh.root, sizeof(fresh.root), "app_get_cleanup"));
        ASSERT(tag_fixture_worker(w, worker));
        ASSERT(asf_journey_init(&fresh.j, "tinyapp", w->repo, fresh.root)); fixture_ready = true;
        ASSERT(tag_cleanup_foreign(&d, fresh.root));
        ASSERT(tag_board_variant(&fresh, NULL, NULL, false) && setenv("HOME", fresh.j.b_home, 1) == 0);
        ASSERT(tag_xdg_enter(&x, fresh.j.b_home) && app_launch_env_from_process(&env, why, sizeof(why)));
        int offers = g_tag.offers, enables = g_tag.enables;
        d.reply = &reply;
        zcl_test_app_library_discover_worker(&env, fresh.j.b_datadir, &reply,
            tag_discover_card, tag_discover_receive, &d, worker);
        tag_discover_capture(&d);
        ASSERT(tag_cleanup_outcome(&d, fail_error_view, &env, &selection, &reply));
        ASSERT(d.host_prompted); ASSERT_EQ(g_tag.offers, offers); ASSERT_EQ(g_tag.enables, enables);
        ASSERT(tag_cleanup_recovery_wire(&reply, &selection)); PASS();
    } _test_next:;
    if (fixture_ready && !tag_stop_receipt(&d, fresh.j.b_datadir)) ++failures;
    if (!tag_replacement_cleanup(&d.swap)) ++failures;
    zcl_command_reply_free(&reply); tag_xdg_leave(&x);
    if (saved_home) { (void)setenv("HOME", saved_home, 1); free(saved_home); }
    else (void)unsetenv("HOME");
    return failures;
}
static int tag_library_cleanup_failure(struct tag_world *w)
{
    int failures = tag_library_cleanup_failure_case(w, false);
    return failures ? failures : tag_library_cleanup_failure_case(w, true);
}
struct tag_discover_empty { unsigned calls; bool error, recover; };
static bool tag_discover_empty_card(void *context, const struct zcl_present_model_v1 *model,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct tag_discover_empty *d = context; (void)copy;
    if (!zcl_present_model_validate_v1(model, why, cap)) return false;
    if (d->error ? strcmp(model->request_id, "discover-error") : strcmp(model->request_id, "discover-0")) return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    event->action_index = d->calls++ ? 1 : 0;
    if (d->error && d->recover) { g_tag.malformed_board = false; d->error = false; }
    return true;
}
static int tag_discover_empty_cases(struct tag_world *w)
{
    int failures = 0; struct zcl_command_reply reply; struct tag_discover_empty d = {0};
    TEST("Discover distinguishes empty catalog from unreadable and supports retry then Back") {
        tag_board_reset(); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        ASSERT(!app_discover_run(w->j.b_datadir, tag_discover_empty_card, NULL, &d, &reply, NULL));
        ASSERT_EQ(d.calls, 2); ASSERT(!reply.error.mutated); zcl_command_reply_free(&reply);
        d.calls = 0; d.error = true; g_tag.malformed_board = true;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        ASSERT(!app_discover_run(w->j.b_datadir, tag_discover_empty_card, NULL, &d, &reply, NULL));
        ASSERT_EQ(d.calls, 2); ASSERT(!reply.error.mutated);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply.error.code, "CATALOG_INCOMPLETE"));
        const struct zcl_command_spec *spec = asf_spec("app.library"); char wire[32768];
        ASSERT(spec && zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, &reply, wire, sizeof(wire)));
        ASSERT(strstr(wire, "CATALOG_INCOMPLETE")); zcl_command_reply_free(&reply);
        d = (struct tag_discover_empty){.error = true, .recover = true}; g_tag.malformed_board = true;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        ASSERT(!app_discover_run(w->j.b_datadir, tag_discover_empty_card, NULL, &d, &reply, NULL));
        ASSERT_EQ(d.calls, 2); ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        zcl_command_reply_free(&reply);
        g_tag.malformed_board = false; PASS();
    } _test_next:;
    g_tag.malformed_board = false; return failures;
}

static int tag_failed_fetch_cleanup(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: failed fetch removes partial output and permits retry") {
        struct asf_leaf l;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.fetch_partial = true;
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        bool executed = asf_exec("app.get", &l);
        g_tag.fetch_partial = false;
        ASSERT(executed);
        ASSERT(asf_refusal(&l, "STUB_FAILED"));
        asf_close(&l);
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        asf_open(&l);
        ASSERT(json_push_kv_str(&l.in, "datadir", w->j.b_datadir));
        ASSERT(json_push_kv_str(&l.in, "name", w->name));
        ASSERT(asf_pass("app.get", &l));
        asf_close(&l);
        PASS();
    } _test_next:;
    g_tag.fetch_partial = false;
    return failures;
}

static int tag_b_get(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: get NAME asks once with A's full fingerprint and root, "
         "then receives, builds and opens") {
        static struct asf_door run;
        char copy[TAG_PATH];
        struct stat st;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get",
                     w->name, ZCL_CLI_CONFIRM_ASK, &run);
        bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
        ASSERT_EQ(run.rc, 0);
        ASSERT(run.asked);
        ASSERT(strstr(run.question, w->offer.publisher) != NULL);
        ASSERT(strstr(run.question, w->offer.root) != NULL);
        ASSERT(strstr(run.question, "public") != NULL);
        ASSERT(strstr(run.question, "pin") != NULL);
        ASSERT(strstr(run.text, "rebuild_report") != NULL);
        ASSERT(strstr(g_tag.result_text, "zcl.app_rebuild.v1") != NULL);
        ASSERT(strstr(run.text, "hosting_status: recurring hosting enabled") != NULL);
        ASSERT(strstr(run.text, "\n  hosting_generation: 1\n") != NULL);
        ASSERT(strstr(run.text, "app host status") != NULL && strstr(run.text, TAG_LOCAL_HOST));
        ASSERT(strstr(run.text, "app host stop") != NULL && strstr(run.text, w->j.b_datadir));
        struct zcl_app_offer hosted;
        ASSERT(zcl_app_offer_parse(g_tag.enable_text, strlen(g_tag.enable_text), &hosted));
        ASSERT(!strcmp(hosted.name, w->offer.name) && !strcmp(hosted.root, w->offer.root));
        ASSERT(!strcmp(hosted.publisher, w->offer.publisher) && !strcmp(hosted.carrier, w->offer.carrier));
        ASSERT(!strcmp(hosted.sha256, w->offer.sha256) && hosted.size == w->offer.size);
        ASSERT(stopped);
        (void)snprintf(copy, sizeof(copy), "%s/copies/tinyapp-1",
                       w->j.b_datadir);
        ASSERT(stat(copy, &st) == 0 && S_ISDIR(st.st_mode));
        ASSERT_EQ(tag_glob(w->j.b_datadir, ".app-get-*"), 0u);
        PASS();
    } _test_next:;
    return failures;
}

static bool tag_matching_fields(const struct json_value *a, const char *ak,
    const struct json_value *b, const char *bk)
{
    const char *x = zcl_package_copy_str(a, ak), *y = zcl_package_copy_str(b, bk);
    return x && y && !strcmp(x, y);
}
static const struct json_value *tag_passed_data(const struct json_value *wire, const char *command)
{
    const char *actual = zcl_package_copy_str(wire, "command");
    const char *status = zcl_package_copy_str(wire, "status");
    const struct json_value *ok = json_get(wire, "ok"), *data = json_get(wire, "data");
    return actual && !strcmp(actual, command) && status && !strcmp(status, "passed") &&
        ok && ok->type == JSON_BOOL && json_get_bool(ok) && data && data->type == JSON_OBJ ? data : NULL;
}
static bool tag_observation_tuple(const struct json_value *receive, const struct json_value *build,
    const struct json_value *opened, const struct json_value *result)
{
    return tag_matching_fields(receive, "version", build, "version") &&
        tag_matching_fields(receive, "version", opened, "head_version") &&
        tag_matching_fields(receive, "package_root", build, "package_root") &&
        tag_matching_fields(build, "package_root", opened, "package_root") &&
        tag_matching_fields(build, "image_sha3", opened, "image_sha3") &&
        tag_matching_fields(opened, "image_sha3", result, "image_sha3") &&
        tag_matching_fields(receive, "destination", opened, "copy_dir");
}
static bool tag_check_observations(const struct zcl_command_reply *reply, const char *datadir)
{
    const struct json_value *receive = tag_passed_data(json_get(&reply->data, "receive_observation"), "zcode.package.bundle.receive");
    const struct json_value *build = tag_passed_data(json_get(&reply->data, "build_observation"), "app.build");
    const struct json_value *opened = tag_passed_data(json_get(&reply->data, "open_observation"), "app.run.copy");
    const char *proof = zcl_package_copy_str(opened, "mapped_proof");
    const struct json_value *executed = json_get(opened, "executed"), *alive = json_get(opened, "settled_alive");
    return receive && build && opened && datadir &&
        tag_observation_tuple(receive, build, opened, &reply->data) &&
        proof && (!strcmp(proof, "fexecve_inode") || !strcmp(proof, "proc_exe_triple") || !strcmp(proof, "cdhash_suspended")) &&
        executed && executed->type == JSON_BOOL && json_get_bool(executed) &&
        alive && alive->type == JSON_BOOL && json_get_bool(alive);
}
static bool tag_library_wire(struct zcl_command_reply *reply, bool failure)
{
    char wire[16385];
    const struct zcl_command_spec *spec = asf_spec("app.library");
    size_t n = 0;
    if (spec && failure) n = zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, reply, wire, sizeof(wire));
    else if (spec) {
        struct zcl_command_budget_fixture fixture = {0}; size_t usable = 0;
        if (!zcl_command_registry_test_success_budget(spec, reply, &fixture, &usable, wire, sizeof(wire), &n)) n = 0;
    }
    struct json_value doc; json_init(&doc);
    bool ok = n && json_read(&doc, wire, n);
    if (failure) {
        const struct json_value *facts = json_get(json_get(&doc, "error"), "facts");
        ok = ok && json_get_str(json_get(facts, "destination")) && json_get_bool(json_get(facts, "executed"));
    } else ok = ok && json_get(json_get(&doc, "data"), "open_observation");
    json_free(&doc); return ok;
}
static int tag_recovery_serialization(void)
{
    int failures = 0;
    TEST("My Apps: nested recovery facts survive bounded failure serialization") {
        struct json_value inner, facts; json_init(&inner); json_set_object(&inner);
        json_init(&facts); json_set_object(&facts);
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
        ASSERT(json_push_kv_str(&facts, "destination", "/fixture/received") &&
            json_push_kv_bool(&facts, "executed", true) && json_push_kv(&inner, "failure_facts", &facts));
        ASSERT(zcl_app_copy_recovery(&reply.data, &inner));
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "INNER_FAILED", "receive", false, true, "Inspect the received copy.", "fixture");
        ASSERT(tag_library_wire(&reply, true));
        zcl_command_reply_free(&reply); json_free(&facts); json_free(&inner); PASS();
    } _test_next:;
    return failures;
}
static int tag_recovery_limits(void)
{
    int failures = 0;
    TEST("My Apps: oversized recovery refuses without inventing a partial path") {
        char path[2001], copy[257]; memset(path, 'a', sizeof(path) - 1); path[sizeof(path) - 1] = 0;
        memset(copy, 1, sizeof(copy) - 1); copy[sizeof(copy) - 1] = 0;
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
        struct json_value facts; json_init(&facts); json_set_object(&facts);
        ASSERT(json_push_kv_str(&facts, "destination", path) && json_push_kv_str(&facts, "copy", copy) &&
            json_push_kv_int(&facts, "pid", 123) &&
            json_push_kv_bool(&facts, "executed", true) && json_push_kv(&reply.data, "failure_facts", &facts));
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "INNER_FAILED", "receive", false, true, "Inspect the received copy.", "fixture");
        zcl_app_bound_committed_result(NULL, &reply, "app.library");
        char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
        size_t n = zcl_command_registry_test_reply_wire(zcl_command_catalog(), asf_spec("app.library"), &reply, wire, sizeof(wire));
        ASSERT(n && n <= ZCL_COMMAND_ERROR_BUDGET && strstr(wire, "INNER_FAILED") &&
            strstr(wire, "Recovery details are unavailable") && reply.error.mutated &&
            json_get_int(json_get(&reply.data, "pid")) == 123 && json_get_bool(json_get(&reply.data, "executed")) &&
            !json_get(&reply.data, "copy"));
        zcl_command_reply_free(&reply); json_free(&facts); PASS();
    }
    TEST("My Apps: oversized unrelated facts are removed before serialization") {
        char extra[2001]; memset(extra, 'x', sizeof(extra) - 1); extra[sizeof(extra) - 1] = 0;
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
        struct json_value facts; json_init(&facts); json_set_object(&facts);
        ASSERT(json_push_kv_str(&facts, "destination", "/fixture/received") &&
            json_push_kv_bool(&facts, "executed", true) && json_push_kv_str(&facts, "extra", extra) &&
            json_push_kv(&reply.data, "failure_facts", &facts));
        zcl_command_reply_fail(&reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "INNER_FAILED", "receive", false, true, "Inspect the received copy.", "fixture");
        zcl_app_bound_committed_result(NULL, &reply, "app.library");
        ASSERT(tag_library_wire(&reply, true));
        ASSERT(!json_get(json_get(&reply.data, "failure_facts"), "extra"));
        zcl_command_reply_free(&reply); json_free(&facts); PASS();
    } _test_next:;
    return failures;
}
static bool tag_get_plan_ids(const struct asf_leaf *leaf, char token[33], char plan[65], char offer[65])
{
    const char *t = asf_get(leaf, "token"), *p = asf_get(leaf, "plan_id"), *o = asf_get(leaf, "offer_id");
    if (strlen(t) != 32 || strlen(p) != 64 || strlen(o) != 64) return false;
    memcpy(token, t, 33); memcpy(plan, p, 65); memcpy(offer, o, 65); return true;
}
static struct json_value *tag_json_member(struct json_value *object, const char *name)
{
    if (!object || object->type != JSON_OBJ) return NULL;
    for (size_t i = 0; i < object->num_children; ++i)
        if (!strcmp(object->keys[i], name)) return &object->children[i];
    return NULL;
}
static void tag_rebuild_evidence_controls(const struct zcl_app_offer_row *row,
    const struct json_value *build, const struct json_value *opened)
{
    int posts = g_tag.posts; tag_rebuild_controls_seen = true;
    struct json_value box; json_init(&box); json_set_object(&box);
    bool ok = json_push_kv(&box, "build", build) && json_push_kv(&box, "open", opened);
    struct json_value *copy = tag_json_member(&box, "build"), *open = tag_json_member(&box, "open");
    struct json_value *copy_data = tag_json_member(copy, "data");
    struct json_value *made = tag_json_member(copy_data, "make_ran"), *open_copy = tag_json_member(open, "data");
    struct json_value *image = tag_json_member(open_copy, "image_sha3");
    struct zcl_app_rebuild observation;
    if (ok) ok = made && image && app_get_rebuild_prepare(row, copy, open, &observation) == APP_GET_REBUILD_FRESH;
    if (ok) { json_set_bool(made, false); ok = app_get_rebuild_prepare(row, copy, open, &observation) == APP_GET_REBUILD_CACHED; }
    if (ok) { json_set_str(image, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        ok = app_get_rebuild_prepare(row, copy, open, &observation) == APP_GET_REBUILD_INVALID; }
    tag_rebuild_controls_ok = ok && g_tag.posts == posts;
    json_free(&box);
}
static void tag_comparison_seed(const struct zcl_app_offer_row *row,
    const struct json_value *build, const struct json_value *opened)
{
    struct zcl_app_rebuild observation;
    tag_comparison_seed_ok = app_get_rebuild_prepare(row, build, opened, &observation) == APP_GET_REBUILD_FRESH;
    if (!tag_comparison_seed_ok) return;
    if (tag_comparison_seed_mode == 3) { g_tag.malformed_board = true; return; }
    char text[TAG_TEXT];
    tag_comparison_seed_ok = zcl_app_rebuild_format(&observation, text, sizeof(text));
    const struct tag_post_spec match = {text, "apps", FLEET_BOARD_KIND_RESULT, false};
    if (tag_comparison_seed_ok)
        tag_comparison_seed_ok = tag_board_add_as(&match, 10, 0x6b) && tag_board_add_as(&match, 9, 0x6c);
}
static int tag_get_observations(struct tag_world *w)
{
    int failures = 0; struct asf_leaf leaf; bool opened = false; struct tag_discover child = {0};
    char token[33], plan[65], offer[65];
    TEST("app get: real receive, build and open observations retain exact identities") {
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        asf_open(&leaf); opened = true;
        ASSERT(json_push_kv_str(&leaf.in, "datadir", w->j.b_datadir) &&
            json_push_kv_str(&leaf.in, "name", w->name));
        ASSERT(asf_pass("app.get", &leaf));
        ASSERT(tag_get_plan_ids(&leaf, token, plan, offer));
        zcl_command_reply_free(&leaf.out); zcl_command_reply_init(&leaf.out, "zcl.app_get.v1");
        ASSERT(json_push_kv_str(&leaf.in, "token", token) && json_push_kv_str(&leaf.in, "offer_id", offer) &&
            json_push_kv_str(&leaf.in, "plan_id", plan) && json_push_kv_bool(&leaf.in, "confirm", true));
        bool passed = asf_pass("app.get", &leaf);
        const struct json_value *p = json_get(&leaf.out.data, "pid");
        const struct json_value *observation = json_get(json_get(&leaf.out.data, "open_observation"), "data");
        const char *start = zcl_package_copy_str(observation, "start_token");
        const char *image = zcl_package_copy_str(observation, "image_sha3");
        if (p && p->type == JSON_INT && start && image && strlen(image) == 64) {
            child.pid = (long)json_get_int(p); child.start = strtoull(start, NULL, 10);
            memcpy(child.image, image, sizeof(child.image));
        }
        ASSERT(passed && child.pid > 1 && child.start);
        ASSERT(tag_check_observations(&leaf.out, w->j.b_datadir));
        ASSERT(tag_library_wire(&leaf.out, false));
        PASS();
    } _test_next:;
    if (child.pid > 1 && !tag_stop_receipt(&child, w->j.b_datadir)) ++failures;
    if (opened) asf_close(&leaf);
    return failures;
}
static int tag_b_journeys(struct tag_world *w)
{
    int failures = tag_b_get(w);
    return failures ? failures : tag_get_observations(w);
}

static bool tag_pages_board(struct tag_world *w, char target[65])
{
    tag_board_reset();
    if (!tag_board_valid(w, 0)) return false;
    int64_t now = json_get_int(json_get(json_at(&g_tag.board, 0), "created_at"));
    for (size_t i = 1; i <= 511; ++i) {
        struct json_value p; json_init(&p); json_set_object(&p);
        char id[65]; (void)snprintf(id, sizeof(id), "%064zx", 10000u - i);
        int64_t age = i == 256 ? 255 : (int64_t)i;
        bool ok = json_push_kv_int(&p, "created_at", now - age) &&
            json_push_kv_str(&p, "id", id) && json_push_back(&g_tag.board, &p);
        json_free(&p); if (!ok) return false;
    }
    if (!tag_board_valid(w, 512)) return false;
    (void)snprintf(target, 65, "%s", tag_in(json_at(&g_tag.board, 512), "id"));
    return strlen(target) == 64;
}
static int tag_public_pages(struct tag_world *w)
{
    int failures = 0;
    TEST("app catalog page: malformed, repeated and unsupported cursors refuse") {
        struct zcl_app_offer_row *rows = calloc(ZCL_APP_OFFER_ROWS_MAX, sizeof(*rows));
        struct zcl_app_offer_page page; struct zcl_command_reply why; char target[65];
        ASSERT(rows && tag_pages_board(w, target));
        g_tag.page_mode = 1;
        ASSERT(zcl_app_offer_catalog_page(rows, ZCL_APP_OFFER_ROWS_MAX, NULL, &page, &why));
        struct zcl_app_offer_position cursor = page.next; ASSERT(page.has_more);
        zcl_command_reply_free(&why);
        g_tag.page_mode = 3;
        ASSERT(!zcl_app_offer_catalog_page(rows, ZCL_APP_OFFER_ROWS_MAX, &cursor, &page, &why));
        ASSERT(!strcmp(why.error.code, "CATALOG_INCOMPLETE")); zcl_command_reply_free(&why);
        g_tag.page_mode = 2;
        ASSERT(!zcl_app_offer_catalog_page(rows, ZCL_APP_OFFER_ROWS_MAX, NULL, &page, &why));
        zcl_command_reply_free(&why);
        g_tag.page_mode = 4;
        ASSERT(!zcl_app_offer_catalog_page(rows, ZCL_APP_OFFER_ROWS_MAX, NULL, &page, &why));
        g_tag.page_mode = 0; zcl_command_reply_free(&why); free(rows);
        PASS();
    } _test_next:;
    g_tag.page_mode = 0; return failures;
}

static int tag_rebuild_outcomes(struct tag_world *w)
{
    int failures = 0;
    TEST("app rebuild: a cached get counts observations but does not claim a fresh build") {
        static struct asf_door run; int posts = g_tag.posts;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get",
                     w->name, ZCL_CLI_CONFIRM_ASK, &run);
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "cached image") != NULL);
        ASSERT(strstr(run.text, "matching signing keys") != NULL);
        ASSERT_EQ(g_tag.posts, posts); ASSERT(asf_alive_then_stop(asf_door_pid(run.text)));
        PASS();
    }
    TEST("app rebuild: board failure preserves the opened copy and provides an exact retry") {
        static struct asf_door run; char home[TAG_PATH], datadir[TAG_PATH];
        ASSERT(snprintf(home, sizeof(home), "%s/fail-home", w->root) > 0);
        ASSERT(snprintf(datadir, sizeof(datadir), "%s/datadir", home) > 0);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.fail_result_post = true;
        asf_door_run(home, home, datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.fail_result_post = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "publication unconfirmed") != NULL);
        ASSERT(strstr(run.text, "fleet board post --kind=result") != NULL);
        ASSERT(strstr(run.text, "matching signing keys") != NULL);
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    } _test_next:;
    g_tag.fail_result_post = false; return failures;
}

static int tag_rebuild_open_failure(struct tag_world *w)
{
    int failures = 0;
    TEST("app rebuild: open failure retains the successful build report") {
        static struct asf_door run; char home[TAG_PATH], datadir[TAG_PATH];
        ASSERT(asf_put(w->j.a_copy, "src/main.c", "int main(void) { return 0; }\n"));
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "save", w->j.copy, ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "publish", w->j.copy, ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(zcl_app_offer_parse(g_tag.text, strlen(g_tag.text), &w->offer));
        (void)snprintf(w->name, sizeof(w->name), "%s", w->offer.name);
        ASSERT(snprintf(home, sizeof(home), "%s/exit-home", w->root) > 0);
        ASSERT(snprintf(datadir, sizeof(datadir), "%s/datadir", home) > 0);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        asf_door_run(home, home, datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        ASSERT(run.rc != 0); ASSERT(strstr(run.text, "APP_EXITED:") != NULL);
        ASSERT(strstr(run.text, "rebuild_report: published") != NULL);
        ASSERT(strstr(run.text, "destination: ") != NULL);
        ASSERT(strstr(run.text, "earlier step already changed") != NULL);
        ASSERT(strstr(run.text, "hosting_status: recurring hosting enabled") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_rehost_build_failure(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: build failure keeps and hosts the verified received copy") {
        static struct asf_door run; char home[TAG_PATH], datadir[TAG_PATH];
        ASSERT(asf_put(w->j.a_copy, "src/main.c", "#error deliberate_build_failure\n"));
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "save", w->j.copy, ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        asf_door_run(w->j.a_home, w->j.a_home, w->j.a_datadir, "publish", w->j.copy, ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(zcl_app_offer_parse(g_tag.text, strlen(g_tag.text), &w->offer));
        (void)snprintf(w->name, sizeof(w->name), "%s", w->offer.name);
        ASSERT(snprintf(home, sizeof(home), "%s/build-fail-home", w->root) > 0);
        ASSERT(snprintf(datadir, sizeof(datadir), "%s/datadir", home) > 0);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        asf_door_run(home, home, datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        ASSERT(run.rc != 0); ASSERT(strstr(run.text, "BUILD_FAILED:") != NULL);
        ASSERT(strstr(run.text, "destination: ") != NULL);
        ASSERT(strstr(run.text, "hosting_status: recurring hosting enabled") != NULL);
        ASSERT(strstr(run.text, "earlier step already changed") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int tag_rehost_failures(struct tag_world *w)
{
    int failures = 0;
    TEST("app get: host enable reply requires explicit success and exact typed identity") {
        ASSERT(tag_host_reply_case("\"ok\":true,", TAG_LOCAL_HOST, TAG_CARRIER, "1"));
        ASSERT(!tag_host_reply_case("", TAG_LOCAL_HOST, TAG_CARRIER, "1"));
        ASSERT(!tag_host_reply_case("\"ok\":false,", TAG_LOCAL_HOST, TAG_CARRIER, "1"));
        ASSERT(!tag_host_reply_case("\"ok\":true,", "bad", TAG_CARRIER, "1"));
        ASSERT(!tag_host_reply_case("\"ok\":true,", TAG_LOCAL_HOST, "bad", "1"));
        ASSERT(!tag_host_reply_case("\"ok\":true,", TAG_LOCAL_HOST, TAG_CARRIER, "\"1\""));
        ASSERT(!tag_host_reply_case("\"ok\":true,", TAG_LOCAL_HOST, TAG_CARRIER, "0"));
        ASSERT(tag_host_missing_hint());
        PASS();
    }
    TEST("app get: recurring intent retains the original signed offer identity") {
        static struct asf_door run; struct zcl_app_offer hosted;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.onion_changed = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.onion_changed = false;
        ASSERT_EQ(run.rc, 0); ASSERT(zcl_app_offer_parse(g_tag.enable_text, strlen(g_tag.enable_text), &hosted));
        ASSERT(!strcmp(hosted.publisher, w->offer.publisher) && !strcmp(hosted.root, w->offer.root));
        ASSERT(!strcmp(hosted.carrier, w->offer.carrier) && !strcmp(hosted.sha256, w->offer.sha256));
        ASSERT(!strcmp(hosted.onion, w->offer.onion));
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    }
    TEST("app get: unavailable onion still records recurring hosting intent") {
        static struct asf_door run; int offers = g_tag.offers, posts = g_tag.posts;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.onion_unavailable = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.onion_unavailable = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "recurring hosting enabled") != NULL);
        ASSERT_EQ(g_tag.offers, offers + 1); ASSERT_EQ(g_tag.posts, posts);
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    }
    TEST("app get: endpoint change after pin retains recurring intent") {
        static struct asf_door run; int posts = g_tag.posts;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.change_after_offer = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.change_after_offer = false; g_tag.onion_changed = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "recurring hosting enabled") != NULL);
        ASSERT_EQ(g_tag.posts, posts); ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    }
    TEST("app get: mismatched offered carrier is never advertised") {
        static struct asf_door run; int posts = g_tag.posts;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.bad_host_offer = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.bad_host_offer = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "carrier pin was refused or unconfirmed") != NULL);
        ASSERT_EQ(g_tag.posts, posts); ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    }
    TEST("app get: unconfirmed host enable keeps the pin and gives retry") {
        static struct asf_door run;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.fail_host_post = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.fail_host_post = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "carrier pinned; recurring hosting unconfirmed") != NULL);
        ASSERT(strstr(run.text, "app get ") != NULL && strstr(run.text, w->j.b_datadir));
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    }
    TEST("app get: failed hosting report preserves the started copy and mutation") {
        static struct asf_door run;
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.fail_host_output_alloc = true;
        asf_door_run(w->j.b_home, w->j.b_home, w->j.b_datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.fail_host_output_alloc = false;
        zcl_alloc_fault_clear();
        bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
        ASSERT(run.rc != 0 && strstr(run.text, "HOSTING_RESULT_UNAVAILABLE") != NULL);
        ASSERT(strstr(run.text, "copy:") && strstr(run.text, "earlier step already changed"));
        ASSERT(stopped); PASS();
    }
    TEST("app get: changed staged bytes are never pinned") {
        static struct asf_door run; char home[TAG_PATH], datadir[TAG_PATH]; int offers = g_tag.offers;
        ASSERT(snprintf(home, sizeof(home), "%s/changed-home", w->root) > 0);
        ASSERT(snprintf(datadir, sizeof(datadir), "%s/datadir", home) > 0);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        ASSERT(tag_board_variant(w, NULL, NULL, false));
        g_tag.change_staged_after_receive = true;
        asf_door_run(home, home, datadir, "get", w->name, ZCL_CLI_CONFIRM_ASK, &run);
        g_tag.change_staged_after_receive = false;
        ASSERT_EQ(run.rc, 0); ASSERT(strstr(run.text, "no pin attempted: staged carrier changed") != NULL);
        ASSERT_EQ(g_tag.offers, offers); ASSERT(asf_alive_then_stop(asf_door_pid(run.text))); PASS();
    } _test_next:;
    g_tag.onion_unavailable = g_tag.onion_changed = g_tag.change_after_offer = false;
    g_tag.bad_host_offer = g_tag.fail_host_post = g_tag.change_staged_after_receive = false;
    return failures;
}

static int tag_mcp(void)
{
    int failures = 0;
    TEST("app get: MCP refuses app.publish and app.get (owner authority)") {
        ASSERT(asf_mcp_refuses_owner("app.publish", "copy", "tinyapp-1"));
        ASSERT(asf_mcp_refuses_owner("app.get", "name", "tinyapp"));
        PASS();
    } _test_next:;
    return failures;
}

/* This fixture's tiny app has no windows. A synthetic display supplies only
 * the desktop-session signal inherited by the real worker, not GUI proof. */
#if defined(__linux__)
struct tag_display { char *display, *wayland; bool captured; };
static bool tag_display_enter(struct tag_display *saved)
{
    const char *display = getenv("DISPLAY"), *wayland = getenv("WAYLAND_DISPLAY");
    saved->display = display ? strdup(display) : NULL;
    saved->wayland = wayland ? strdup(wayland) : NULL;
    if ((display && !saved->display) || (wayland && !saved->wayland)) return false;
    saved->captured = true;
    return setenv("DISPLAY", ":synthetic-app-get", 1) == 0 && unsetenv("WAYLAND_DISPLAY") == 0;
}
static bool tag_display_leave(struct tag_display *saved)
{
    if (!saved->captured) { free(saved->display); free(saved->wayland); return true; }
    bool ok = saved->display ? setenv("DISPLAY", saved->display, 1) == 0 : unsetenv("DISPLAY") == 0;
    if (saved->wayland ? setenv("WAYLAND_DISPLAY", saved->wayland, 1) != 0 : unsetenv("WAYLAND_DISPLAY") != 0)
        ok = false;
    free(saved->display); free(saved->wayland); return ok;
}
#endif
static int tag_keep_cases(struct tag_world *w)
{
#if defined(__linux__)
    struct tag_display saved = {0}; bool ready = tag_display_enter(&saved);
#else
    bool ready = true;
#endif
    int failures = ready ? tag_library_kept_failure(w) : 1;
    if (!failures) failures += tag_rebuild_case(w, false);
    if (!failures) failures += tag_rebuild_case(w, true);
    if (!failures) failures += tag_rebuild_case(w, 2);
    if (!failures) failures += tag_rebuild_case(w, 3);
    if (!failures) failures += tag_rebuild_case(w, 4);
    if (!failures) failures += tag_cached_comparison(w);
    if (!failures) failures += tag_host_result_failure(w);
    if (!failures) failures += tag_library_cleanup_failure(w);
    if (!failures) failures += tag_library_oversized_failure(w);
#if defined(__linux__)
    if (!tag_display_leave(&saved)) ++failures;
#endif
    return failures;
}

static int tag_world_cases(struct tag_world *w)
{
    int failures = 0;
    failures += tag_catalog(w);
    failures += tag_dropped(w);
    failures += tag_identity_selection(w);
    failures += tag_endpoint_limit(w);
    failures += tag_refusals(w);
    failures += tag_b_plan(w);
    failures += tag_stage_consumer(w);
    failures += tag_stage_unsafe_parent(w);
    failures += tag_discover_cancel(w);
    failures += tag_discover_fetch_close(w);
    failures += tag_fetch_native_profile(w);
    failures += tag_library_discover(w);
    failures += tag_library_profile(w);
    failures += tag_discover_empty_cases(w);
    if (failures == 0) failures += tag_keep_cases(w);
    failures += tag_failed_fetch_cleanup(w);
    failures += tag_b_journeys(w);
    if (failures == 0) failures += tag_exact_tests(w);
    if (failures == 0) failures += tag_rebuild_outcomes(w);
    if (failures == 0) failures += tag_rehost_failures(w);
    if (failures == 0) failures += tag_rebuild_open_failure(w);
    if (failures == 0) failures += tag_rehost_build_failure(w);
    if (failures == 0) failures += tag_public_pages(w);
    return failures;
}
int test_app_get(void);
int test_app_get(void)
{
    static struct tag_world w;
    int failures = 0;
    printf("app get (publish to room apps, get by identity)...\n");
    failures += tag_network_test();
    failures += tag_process_observation();
    failures += tag_recovery_serialization();
    failures += tag_recovery_limits();
    memset(&g_tag, 0, sizeof(g_tag));
    failures += tag_busy_onion_bridge();
    tag_board_reset();
    zcl_app_offer_set_call(tag_call);
    failures += tag_rebuild_catalog();
    failures += tag_catalog_independent();
    zcl_app_offer_set_call(NULL);
    failures += tag_mcp();
    if (!tag_world_init(&w)) {
        printf("  FAIL: app get world setup\n");
        return failures + 1;
    }
    zcl_app_offer_set_call(tag_call);
    failures += tag_a_plan(&w);
    if (failures == 0)
        failures += tag_publish_collision(&w);
    if (failures == 0)
        failures += tag_publish_onion_change(&w);
    if (failures == 0)
        failures += tag_publish_source_change(&w);
    if (failures == 0)
        failures += tag_publish_unknown(&w);
    if (failures == 0)
        failures += tag_a_publish(&w);
    if (failures == 0) failures += tag_publish_long_name(&w);
    if (failures == 0) failures += tag_published_continuation(&w);
    if (failures == 0) failures += tag_world_cases(&w);
    zcl_app_offer_set_call(NULL);
    json_free(&g_tag.board);
    free(g_tag.bytes);
    if (chdir(w.saved_cwd) != 0 ||
        (w.saved_home[0] && setenv("HOME", w.saved_home, 1) != 0))
        failures++;
    return failures;
}

#endif
