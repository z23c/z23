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
#include "command/native_app_library_command.h"
#include "command/native_app_receive_preview.h"
#include "command/app_selection.h"
#include "config/command_catalog.h"

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
#include "util/file_io.h"

#include <ftw.h>
#include <glob.h>
#include <stdio.h>
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
static int g_tag_rpc_mode;
static bool tag_capture_signed_post(struct zcl_command_reply *out);

extern bool zcl_app_get_host_reply_valid_for_testing(const struct json_value *, const char *);
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

static bool tag_fetch(const struct json_value *in, struct zcl_command_reply *out)
{
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

struct tag_library_view { bool keep, reopen, detail; };
static bool tag_library_present(void *context, const struct zcl_present_model_v1 *m,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct tag_library_view *v = context; (void)copy;
    if (!zcl_present_model_validate_v1(m, why, cap)) return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    if (!strcmp(m->request_id, "library-home")) event->action_index = v->reopen ? 0 : 1;
    else if (!strncmp(m->request_id, "library-public-", 15)) event->action_index = 0;
    else if (!strncmp(m->request_id, "library-", 8) && m->action_count == 4 &&
             !strcmp(m->actions[0].id, "choose")) event->action_index = 0;
    else if (v->reopen && m->action_count >= 3 && !strcmp(m->actions[1].id, "help") &&
             !strcmp(m->actions[2].id, "share")) { v->detail = true; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; }
    else return false;
    return true;
}
static bool tag_library_notice(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct tag_library_view *v = context; (void)pages;
    uint32_t count = 0;
    if (!zcl_present_model_page_count_v1(m, &count, why, cap)) return false;
    struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION};
    bool redraw = false, close = false;
    for (uint32_t i = 1; i < count; ++i) { e.action_index = 2; live->owner.update(live->owner.context, &e, false, &redraw, &close); }
    e.action_index = !strcmp(m->request_id, "received-app") && !v->keep ? 0 : 3;
    live->owner.update(live->owner.context, &e, false, &redraw, &close);
    return close;
}
static bool tag_library_get(void *context, const struct json_value *in, struct zcl_command_reply *out)
{
    (void)context; return zcl_app_inner_call("app.get", in, out, NULL);
}
static bool tag_bad_observation(struct app_receive_preview *preview, const struct json_value *wire,
    const char *field, struct zcl_command_reply *why)
{
    struct json_value bad; json_init(&bad);
    bool ok = json_copy_checked(&bad, wire);
    struct json_value *data = (struct json_value *)json_get(&bad, "data");
    struct json_value *value = (struct json_value *)json_get(data, field);
    if (ok && value && (!strcmp(field, "settled_alive") || !strcmp(field, "executed"))) json_set_bool(value, false);
    else if (ok && value && (!strcmp(field, "head_version") || !strcmp(field, "image_sha3")))
        json_set_str(value, "0000000000000000000000000000000000000000000000000000000000000000");
    else if (ok && value) json_set_str(value, "bad");
    ok = ok && value && !app_receive_preview_bind_run_copy(preview, &bad, why);
    json_free(&bad); return ok;
}
static bool tag_check_observations(const struct zcl_command_reply *reply, const char *datadir)
{
    const struct json_value *receive = json_get(&reply->data, "receive_observation");
    const struct json_value *build = json_get(&reply->data, "build_observation");
    const struct json_value *opened = json_get(&reply->data, "open_observation");
    struct zcl_command_reply why; zcl_command_reply_init(&why, "zcl.test.preview.v1");
    struct app_receive_preview *preview = NULL;
    bool ok = !app_receive_preview_create(NULL, datadir, &preview, &why) && !preview &&
        app_receive_preview_create(json_get(receive, "data"), datadir, &preview, &why) &&
        !app_receive_preview_bind_build(preview, NULL, &why) &&
        app_receive_preview_bind_build(preview, build, &why) &&
        !app_receive_preview_bind_run_copy(preview, NULL, &why);
    static const char *const fields[] = {"copy_dir", "head_version", "image_sha3", "start_token", "mapped_proof", "settled_alive", "executed"};
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); ++i)
        ok = tag_bad_observation(preview, opened, fields[i], &why);
    ok = ok && app_receive_preview_bind_run_copy(preview, opened, &why);
    app_receive_preview_close(preview); zcl_command_reply_free(&why); return ok;
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
static int tag_library_journey(struct tag_world *w)
{
    int failures = 0; char why[256] = {0}; struct app_launch_env env;
    const char *old = getenv("XDG_STATE_HOME"); char *saved = old ? strdup(old) : NULL;
    TEST("My Apps: real get, native Keep and reopen preserve the exact received version") {
        ASSERT(!old || saved); ASSERT(setenv("HOME", w->j.b_home, 1) == 0);
        ASSERT(setenv("XDG_STATE_HOME", w->j.b_home, 1) == 0);
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        for (int keep = 0; keep <= 1; ++keep) {
            ASSERT(tag_board_variant(w, NULL, NULL, false));
            struct tag_library_view view = {.keep = keep != 0};
            struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
            zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply, tag_library_present, &view,
                                          tag_library_notice, NULL, tag_library_get);
            const struct json_value *pid = json_get(&reply.data, "pid");
            bool stopped = pid && pid->type == JSON_INT && asf_alive_then_stop((long)json_get_int(pid));
            ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && stopped);
            ASSERT(tag_check_observations(&reply, w->j.b_datadir));
            ASSERT(tag_library_wire(&reply, false));
            struct app_selection_routes routes;
            ASSERT(app_selection_routes_load(env.state_dir, &routes) == APP_SELECTION_OK);
            ASSERT(routes.count == (size_t)keep);
            if (keep) {
                struct app_selection selection; char version[65];
                ASSERT(app_selection_load(env.state_dir, routes.names[0], &selection) == APP_SELECTION_OK);
                zcl_hex_encode(selection.version, 32, version);
                ASSERT(!strcmp(version, json_get_str(json_get(&reply.data, "version"))));
                ASSERT(!strcmp(selection.copy, json_get_str(json_get(&reply.data, "destination"))));
                view.reopen = true; zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
                zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply, tag_library_present, &view,
                                              tag_library_notice, NULL, tag_library_get);
                ASSERT(view.detail);
            }
            zcl_command_reply_free(&reply);
        }
        PASS();
    } _test_next:;
    if (saved) { (void)setenv("XDG_STATE_HOME", saved, 1); free(saved); }
    else (void)unsetenv("XDG_STATE_HOME");
    return failures;
}
static int tag_b_journeys(struct tag_world *w)
{
    int failures = tag_b_get(w);
    return failures ? failures : tag_library_journey(w);
}

struct tag_pages_view { unsigned stage; bool valid, selected, cancel_early, refresh, expect_error; char target[65]; };
static const char *tag_pages_action(const struct tag_pages_view *v)
{
    if (v->stage == 0) return "public";
    if (v->stage == 1) return "public-options";
    if (v->stage == 2 && v->refresh) return "public-refresh";
    if (v->stage == 2 || v->stage == 3) return "public-older";
    return "get";
}
static bool tag_pages_present(void *context, const struct zcl_present_model_v1 *m,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct tag_pages_view *v = context; (void)copy;
    if (!zcl_present_model_validate_v1(m, why, cap)) return false;
    if (v->expect_error && !strcmp(m->request_id, "library-error")) {
        event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
    }
    if (v->cancel_early && v->stage == 1) { event->struct_size = sizeof(*event);
        event->abi_version = ZCL_PRESENT_ABI_V1; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true; }
    if (v->refresh && v->stage == 3) { event->struct_size = sizeof(*event);
        event->abi_version = ZCL_PRESENT_ABI_V1; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true; }
    if (!v->refresh && v->stage == 3 && !strstr(m->summary, "No usable offers on this page")) return false;
    const char *want = tag_pages_action(v);
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    for (uint32_t i = 0; i < m->action_count; ++i) if (!strcmp(m->actions[i].id, want)) {
        event->action_index = i; ++v->stage; return true;
    }
    v->valid = false; return false;
}
static bool tag_pages_cancel(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)context; (void)m; (void)pages; (void)why; (void)cap;
    struct zcl_present_window_event_v1 e = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 0};
    bool redraw = false, close = false;
    live->owner.update(live->owner.context, &e, false, &redraw, &close);
    return close;
}
static bool tag_pages_get(void *context, const struct json_value *in, struct zcl_command_reply *out)
{
    struct tag_pages_view *v = context;
    v->selected = !strcmp(tag_in(in, "offer_id"), v->target) && !json_get(in, "confirm");
    return zcl_app_inner_call("app.get", in, out, NULL);
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
    }
    TEST("My Apps: older pages survive an empty valid page and cancel exact selection") {
        struct tag_pages_view view = {.valid = true};
        struct app_launch_env env; char why[256];
        ASSERT(tag_pages_board(w, view.target));
        ASSERT(setenv("HOME", w->j.b_home, 1) == 0 && setenv("XDG_STATE_HOME", w->j.b_home, 1) == 0);
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        size_t copies = tag_glob(w->j.b_datadir, "copies/*");
        int fetches = g_tag.fetches, posts = g_tag.posts, enables = g_tag.enables;
        g_tag.page_mode = 1;
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_library.v1");
        view.cancel_early = true;
        zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply,
            tag_pages_present, &view, tag_pages_cancel, NULL, tag_pages_get);
        ASSERT(g_tag.fetches == fetches && !view.selected);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_library.v1");
        view.stage = 0; view.cancel_early = false; view.refresh = true;
        zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply,
            tag_pages_present, &view, tag_pages_cancel, NULL, tag_pages_get);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && view.stage == 3 && g_tag.fetches == fetches);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_library.v1");
        view.stage = 0; view.refresh = false; view.expect_error = true; g_tag.page_mode = 3;
        zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply,
            tag_pages_present, &view, tag_pages_cancel, NULL, tag_pages_get);
        ASSERT(!strcmp(reply.error.code, "CATALOG_INCOMPLETE") && g_tag.fetches == fetches);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_library.v1");
        view.stage = 0; view.expect_error = false; g_tag.page_mode = 1;
        zcl_test_app_library_public_at(&env, w->j.b_datadir, &reply,
            tag_pages_present, &view, tag_pages_cancel, NULL, tag_pages_get);
        g_tag.page_mode = 0;
        ASSERT(view.valid && view.stage == 5 && view.selected);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && g_tag.fetches == fetches + 1);
        ASSERT(g_tag.posts == posts && g_tag.enables == enables && tag_glob(w->j.b_datadir, "copies/*") == copies);
        zcl_command_reply_free(&reply); PASS();
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

static int tag_followup_journeys(struct tag_world *w)
{
    int failures = tag_public_pages(w);
    if (failures == 0) failures += tag_exact_tests(w);
    if (failures == 0) failures += tag_rebuild_outcomes(w);
    if (failures == 0) failures += tag_rehost_failures(w);
    if (failures == 0) failures += tag_rebuild_open_failure(w);
    if (failures == 0) failures += tag_rehost_build_failure(w);
    return failures;
}

int test_app_get(void);
int test_app_get(void)
{
    static struct tag_world w;
    int failures = 0;
    printf("app get (publish to room apps, get by identity)...\n");
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
    if (failures == 0)
        failures += tag_publish_long_name(&w);
    if (failures == 0)
        failures += tag_published_continuation(&w);
    if (failures == 0) {
        failures += tag_catalog(&w);
        failures += tag_dropped(&w);
        failures += tag_identity_selection(&w);
        failures += tag_endpoint_limit(&w);
        failures += tag_refusals(&w);
        failures += tag_b_plan(&w);
        failures += tag_failed_fetch_cleanup(&w);
        failures += tag_b_journeys(&w);
        if (failures == 0) failures += tag_followup_journeys(&w);
    }
    zcl_app_offer_set_call(NULL);
    json_free(&g_tag.board);
    free(g_tag.bytes);
    if (chdir(w.saved_cwd) != 0 ||
        (w.saved_home[0] && setenv("HOME", w.saved_home, 1) != 0))
        failures++;
    return failures;
}

#endif
