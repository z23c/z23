/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: fleet hash-PSK pairing renewal: plan/confirm epoch N+1, smoke gate,
 * retire N, typed failure, no secret bytes in any output, plan binding. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "base/hex.h"
#include "platform/clock.h"
#include "platform/socket_compat.h"
#include "services/device_identity.h"
#include "models/device_pairing.h"
#include "util/authority_receipt.h"
#include "crypto/sha256.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
struct pr_fx {
    char root[1024], cs[1100], hs[1100], hc[1100], ev[1100], slot[1100], env[1200];
    char c_profile[1200], h_profile[1200], c_dir[1200], h_dir[1200];
    uint16_t target_port;
    int listener;
    pthread_t thread;
    atomic_bool stop;
    bool thread_on;
};

static void *pr_banner(void *opaque)
{
    struct pr_fx *fx = opaque;
    int conns[8];
    size_t used = 0;
    while (!atomic_load(&fx->stop)) {
        struct pollfd ready = {.fd = fx->listener, .events = POLLIN};
        if (poll(&ready, 1, 20) <= 0 || used >= 8) continue;
        struct sockaddr_in peer;
        size_t size = sizeof(peer);
        int fd = platform_socket_accept(fx->listener, (struct sockaddr *)&peer, &size);
        if (fd < 0) continue;
        (void)!send(fd, "SSH-2.0-z23-test\r\n", 18, MSG_NOSIGNAL);
        conns[used++] = fd;
    }
    for (size_t i = 0; i < used; ++i) close(conns[i]);
    return NULL;
}

static bool pr_write(const char *path, const char *text, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0) return false;
    bool ok = write(fd, text, strlen(text)) == (ssize_t)strlen(text);
    return close(fd) == 0 && ok && chmod(path, mode) == 0;
}
static bool pr_read(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t got = fread(out, 1, cap - 1, file);
    fclose(file);
    out[got] = 0;
    return true;
}
static bool pr_exists(const char *path) { return access(path, F_OK) == 0; }

static bool pr_route_files(struct pr_fx *fx, unsigned epoch, const uint8_t ckey[32], const uint8_t hkey[32],
    const uint8_t croot[32], const uint8_t hroot[32])
{
    char ck[65], hk[65], cr[65], hr[65], route[48], text[2048];
    zcl_hex_encode(ckey, 32, ck); zcl_hex_encode(hkey, 32, hk);
    zcl_hex_encode(croot, 32, cr); zcl_hex_encode(hroot, 32, hr);
    snprintf(route, sizeof(route), "r1-r2-e%u", epoch);
    snprintf(text, sizeof(text),
        "{\"directory\":\"%s\",\"peer_key\":\"%s\",\"expected_root\":\"%s\",\"target_port\":%u,\"route_id\":\"%s\","
        "\"route_address\":\"127.0.0.1\",\"route_port\":28022,\"connect_ms\":5000,\"handshake_ms\":10000,"
        "\"session_ms\":28800000,\"idle_ms\":1800000,\"confirm\":true}",
        fx->c_profile, hk, cr, (unsigned)fx->target_port, route);
    if (!authority_receipt_write_atomic(fx->c_dir, "client.json", (const uint8_t *)text, strlen(text), NULL, 0)) return false;
    snprintf(text, sizeof(text),
        "{\"directory\":\"%s\",\"peer_key\":\"%s\",\"expected_root\":\"%s\",\"target_port\":%u,\"route_id\":\"%s\","
        "\"listen_address\":\"127.0.0.1\",\"listen_port\":28022,\"allow_external\":false,\"lifetime_ms\":86400000,"
        "\"handshake_ms\":10000,\"session_ms\":28800000,\"idle_ms\":1800000,\"max_active\":4,\"max_sessions\":64,"
        "\"confirm\":true}",
        fx->h_profile, ck, hr, (unsigned)fx->target_port, route);
    return authority_receipt_write_atomic(fx->h_dir, "receiver.json", (const uint8_t *)text, strlen(text), NULL, 0);
}

static bool pr_grant(struct device_identity *own, struct device_identity *peer, uint16_t inbound, uint16_t outbound,
    uint64_t now, uint64_t expires, struct device_pairing_store *store, uint8_t root[32])
{
    struct db_device_pairing row = {.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD, .paired_at = now - 1, .expires_at = expires};
    if (!device_identity_pair_store(own, peer->public_key, store).ok) return false;
    memcpy(row.local_key, own->public_key, 32); memcpy(row.peer_key, peer->public_key, 32);
    memcpy(row.profile, store->profile, 32);
    row.host_scope.inbound_port = inbound; row.host_scope.outbound_port = outbound;
    row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
    struct device_pairing_psk_binding *binding = &row.host_scope.binding.psk;
    binding->credential_id[0] = 91; binding->key_epoch = 1;
    bool first = memcmp(row.local_key, row.peer_key, 32) < 0;
    memcpy(binding->endpoint_a, first ? row.local_key : row.peer_key, 32);
    memcpy(binding->endpoint_b, first ? row.peer_key : row.local_key, 32);
    uint8_t secret[32] = {17}, proposal[32];
    struct device_pairing_psk_publication report;
    struct db_device_pairing found;
    return device_pairing_host_proposal_root(&row, proposal) &&
        db_device_pairing_insert_host_psk(store, &row, secret, proposal, &report) &&
        db_device_pairing_inspect(store, row.peer_key, &found, root);
}

static bool pr_target(struct pr_fx *fx)
{
    fx->listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, true);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    if (fx->listener < 0 || bind(fx->listener, (struct sockaddr *)&address, size) != 0 ||
        listen(fx->listener, 8) != 0 || getsockname(fx->listener, (struct sockaddr *)&address, &size) != 0) return false;
    fx->target_port = ntohs(address.sin_port);
    atomic_store(&fx->stop, false);
    /* raw-pthread-ok: test banner target joined by pr_close */
    fx->thread_on = pthread_create(&fx->thread, NULL, pr_banner, fx) == 0;
    return fx->thread_on;
}

/* Epoch 1 as 20-pair.sh leaves it: client r1 holds r2-e1, the hub holds r1-e1. */
static bool pr_fixture(struct pr_fx *fx, int64_t expires_in_s)
{
    memset(fx, 0, sizeof(*fx));
    fx->listener = -1;
    if (!test_mkdtemp(fx->root, sizeof(fx->root), "pair-renew")) return false;
    snprintf(fx->cs, sizeof(fx->cs), "%s/cs", fx->root); snprintf(fx->hs, sizeof(fx->hs), "%s/hs", fx->root);
    snprintf(fx->hc, sizeof(fx->hc), "%s/hc", fx->root); snprintf(fx->ev, sizeof(fx->ev), "%s/ev", fx->root);
    snprintf(fx->slot, sizeof(fx->slot), "%s/slot-z23", fx->root);
    snprintf(fx->c_dir, sizeof(fx->c_dir), "%s/r2-e1", fx->cs); snprintf(fx->h_dir, sizeof(fx->h_dir), "%s/r1-e1", fx->hs);
    snprintf(fx->c_profile, sizeof(fx->c_profile), "%s/profile", fx->c_dir);
    snprintf(fx->h_profile, sizeof(fx->h_profile), "%s/profile", fx->h_dir);
    snprintf(fx->env, sizeof(fx->env), "%s/tunnel-receiver-r1.env", fx->hc);
    if (mkdir(fx->cs, 0700) || mkdir(fx->hs, 0700) || mkdir(fx->hc, 0700) || mkdir(fx->ev, 0700) ||
        mkdir(fx->c_dir, 0700) || mkdir(fx->h_dir, 0700) || !pr_target(fx)) return false;
    struct device_identity ci = {0}, hi = {0};
    struct device_identity_publication_report report;
    uint64_t now = (uint64_t)(clock_now_wall_ms() / 1000);
    struct device_pairing_store cstore, hstore;
    uint8_t croot[32], hroot[32];
    bool ok = fx->thread_on && device_identity_open(&ci, fx->c_profile, true, &report).ok &&
        device_identity_open(&hi, fx->h_profile, true, &report).ok &&
        pr_grant(&ci, &hi, 0, fx->target_port, now, now + (uint64_t)expires_in_s, &cstore, croot) &&
        pr_grant(&hi, &ci, fx->target_port, 0, now, now + (uint64_t)expires_in_s, &hstore, hroot) &&
        pr_route_files(fx, 1, ci.public_key, hi.public_key, croot, hroot);
    device_identity_close(&ci); device_identity_close(&hi);
    char text[1400];
    snprintf(text, sizeof(text), "# z23 tunnel receiver for client r1, epoch 1\nZ23_TUNNEL_RECEIVER_INPUT=%s/receiver.json\n", fx->h_dir);
    return ok && pr_write(fx->env, text, 0600);
}
static void pr_close(struct pr_fx *fx)
{
    atomic_store(&fx->stop, true);
    if (fx->thread_on) pthread_join(fx->thread, NULL);
    if (fx->listener >= 0) close(fx->listener);
    if (fx->root[0]) test_rm_rf(fx->root);
}

static bool pr_input(const struct pr_fx *fx, struct json_value *in, const char *plan_id, bool confirm, bool fault)
{
    json_set_object(in);
    bool ok = json_push_kv_str(in, "state_dir", fx->cs) && json_push_kv_str(in, "hub_state_dir", fx->hs) &&
        json_push_kv_str(in, "hub_config_dir", fx->hc) && json_push_kv_str(in, "peer", "r2");
    if (plan_id) ok = ok && json_push_kv_str(in, "plan_id", plan_id);
    if (confirm) ok = ok && json_push_kv_bool(in, "confirm", true);
    if (fault) ok = ok && json_push_kv_bool(in, "test_smoke_fault", true);
    return ok;
}
static bool pr_call(const char *path, const struct json_value *input, struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler) return false;
    reply->data_schema = spec->output_schema ? spec->output_schema : reply->data_schema;
    struct zcl_command_request request = {.spec = spec, .input = input};
    spec->handler(&request, reply);
    return true;
}
static bool pr_passed(const struct zcl_command_reply *r) { return r->status == ZCL_COMMAND_STATUS_PASSED; }
static bool pr_code(const struct zcl_command_reply *r, const char *code)
{
    return r->status == ZCL_COMMAND_STATUS_FAILED && !strcmp(r->error.code, code);
}
static bool pr_plan(const struct pr_fx *fx, const char *extra_key, int64_t extra, struct zcl_command_reply *reply)
{
    struct json_value in = {0};
    bool ok = pr_input(fx, &in, NULL, false, false) && (!extra_key || json_push_kv_int(&in, extra_key, extra)) &&
        pr_call("ops.mesh.device.pair.renew", &in, reply);
    json_free(&in);
    return ok;
}
static bool pr_confirm(const struct pr_fx *fx, const char *plan_id, bool fault, struct zcl_command_reply *reply)
{
    struct json_value in = {0};
    bool ok = pr_input(fx, &in, plan_id, true, fault) && pr_call("ops.mesh.device.pair.renew", &in, reply);
    json_free(&in);
    return ok;
}
static bool pr_bool(const struct zcl_command_reply *r, const char *key, bool want)
{
    const struct json_value *v = json_get(&r->data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v) == want;
}
static const char *pr_str(const struct zcl_command_reply *r, const char *key) { return json_get_str(json_get(&r->data, key)); }

/* The grant a profile holds for its peer: revoked_at, or UINT64_MAX when unreadable. */
static uint64_t pr_revoked(const char *profile, const char *peer_hex)
{
    struct device_identity id = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    struct db_device_pairing row;
    uint8_t peer[32], root[32];
    if (!zcl_hex_decode(peer_hex, peer, 32) || !device_identity_open(&id, profile, false, &report).ok) return UINT64_MAX;
    uint64_t value = UINT64_MAX;
    if (device_identity_pair_store(&id, peer, &store).ok && db_device_pairing_inspect(&store, peer, &row, root))
        value = row.revoked_at;
    device_identity_close(&id);
    return value;
}
static bool pr_json_file(const char *path, struct json_value *out)
{
    char text[4096];
    return pr_read(path, text, sizeof(text)) && json_read(out, text, strlen(text));
}
/* Both sides of an epoch: revoked_at of client grant and hub grant, UINT64_MAX when unreadable. */
static bool pr_epoch_revoked(const struct pr_fx *fx, unsigned epoch, uint64_t *client, uint64_t *hub)
{
    char path[1400];
    struct json_value cj = {0}, hj = {0};
    snprintf(path, sizeof(path), "%s/r2-e%u/client.json", fx->cs, epoch);
    bool have_client = pr_json_file(path, &cj);
    snprintf(path, sizeof(path), "%s/r1-e%u/receiver.json", fx->hs, epoch);
    bool have_hub = pr_json_file(path, &hj);
    *client = *hub = UINT64_MAX;
    if (have_client) {
        snprintf(path, sizeof(path), "%s/r2-e%u/profile", fx->cs, epoch);
        *client = pr_revoked(path, json_get_str(json_get(&cj, "peer_key")));
    }
    if (have_hub) {
        snprintf(path, sizeof(path), "%s/r1-e%u/profile", fx->hs, epoch);
        *hub = pr_revoked(path, json_get_str(json_get(&hj, "peer_key")));
    }
    json_free(&cj); json_free(&hj);
    return have_client && have_hub;
}

static int pr_plan_threshold(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: plan reports renew_due on both sides of the threshold and mutates nothing") {
        struct pr_fx due, later;
        ASSERT(pr_fixture(&due, 86400));
        ASSERT(pr_fixture(&later, 10 * 86400));
        struct zcl_command_reply r = {0};
        ASSERT(pr_plan(&due, NULL, 0, &r)); ASSERT(pr_passed(&r));
        ASSERT(pr_bool(&r, "renew_due", true)); ASSERT(pr_bool(&r, "committed", false));
        ASSERT_EQ(strlen(pr_str(&r, "plan_id")), 64u);
        ASSERT_EQ(json_get_int(json_get(&r.data, "current_epoch")), 1);
        ASSERT_EQ(json_get_int(json_get(&r.data, "next_epoch")), 2);
        ASSERT(!r.error.mutated);
        char path[1400];
        snprintf(path, sizeof(path), "%s/r2-e2", due.cs); ASSERT(!pr_exists(path));
        snprintf(path, sizeof(path), "%s/r1-e2", due.hs); ASSERT(!pr_exists(path));
        zcl_command_reply_free(&r);
        ASSERT(pr_plan(&later, NULL, 0, &r)); ASSERT(pr_passed(&r)); ASSERT(pr_bool(&r, "renew_due", false));
        zcl_command_reply_free(&r);
        ASSERT(pr_plan(&later, "renew_before_s", 11 * 86400, &r)); ASSERT(pr_passed(&r)); ASSERT(pr_bool(&r, "renew_due", true));
        zcl_command_reply_free(&r);
        /* A confirm on a pairing that is not due refuses with a typed code, even with its own plan_id. */
        ASSERT(pr_plan(&later, NULL, 0, &r));
        char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        ASSERT(pr_confirm(&later, id, false, &r)); ASSERT(pr_code(&r, "RENEW_NOT_DUE"));
        zcl_command_reply_free(&r);
        pr_close(&due); pr_close(&later);
    } TEST_END
    return failures;
}

static int pr_confirm_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: confirm creates epoch N+1, smoke passes and only then N is retired") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        struct zcl_command_reply r = {0};
        ASSERT(pr_plan(&fx, NULL, 0, &r)); ASSERT(pr_passed(&r));
        char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        ASSERT(pr_confirm(&fx, id, false, &r));
        ASSERT(pr_passed(&r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "epoch")), 2);
        ASSERT(pr_bool(&r, "smoke_passed", true)); ASSERT(pr_bool(&r, "previous_retired", true));
        ASSERT_EQ(strlen(pr_str(&r, "psk_fingerprint")), 16u);
        zcl_command_reply_free(&r);
        uint64_t c1, h1, c2, h2;
        ASSERT(pr_epoch_revoked(&fx, 1, &c1, &h1)); ASSERT(pr_epoch_revoked(&fx, 2, &c2, &h2));
        ASSERT(c1 != 0 && c1 != UINT64_MAX); ASSERT(h1 != 0 && h1 != UINT64_MAX);
        ASSERT_EQ(c2, 0u); ASSERT_EQ(h2, 0u);
        char path[1400];
        snprintf(path, sizeof(path), "%s/secret/psk", fx.c_dir); ASSERT(!pr_exists(path));
        snprintf(path, sizeof(path), "%s/r2-e2/secret/psk", fx.cs); ASSERT(!pr_exists(path));
        struct stat st;
        snprintf(path, sizeof(path), "%s/r2-e2/client.json", fx.cs); ASSERT(stat(path, &st) == 0); ASSERT_EQ(st.st_mode & 0777, 0600u);
        snprintf(path, sizeof(path), "%s/r1-e2/receiver.json", fx.hs); ASSERT(stat(path, &st) == 0); ASSERT_EQ(st.st_mode & 0777, 0600u);
        char env[1400]; ASSERT(pr_read(fx.env, env, sizeof(env)));
        snprintf(path, sizeof(path), "%s/r1-e2/receiver.json", fx.hs); ASSERT(strstr(env, path));
        /* The new pairing is now the current one and is no longer due. */
        ASSERT(pr_plan(&fx, NULL, 0, &r)); ASSERT(pr_passed(&r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "current_epoch")), 2); ASSERT(pr_bool(&r, "renew_due", false));
        zcl_command_reply_free(&r);
        pr_close(&fx);
    } TEST_END
    return failures;
}

static int pr_smoke_failure(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: an injected smoke failure leaves epoch N in force with a typed code") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        char before[1400], after[1400];
        ASSERT(pr_read(fx.env, before, sizeof(before)));
        struct zcl_command_reply r = {0};
        ASSERT(pr_plan(&fx, NULL, 0, &r)); char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        ASSERT(pr_confirm(&fx, id, true, &r));
        ASSERT(pr_code(&r, "RENEW_SMOKE_FAILED")); ASSERT(r.error.mutated);
        zcl_command_reply_free(&r);
        uint64_t c1, h1;
        ASSERT(pr_epoch_revoked(&fx, 1, &c1, &h1)); ASSERT_EQ(c1, 0u); ASSERT_EQ(h1, 0u);
        char path[1400];
        snprintf(path, sizeof(path), "%s/r2-e2/client.json", fx.cs); ASSERT(!pr_exists(path));
        snprintf(path, sizeof(path), "%s/r2-e2/burned", fx.cs); ASSERT(pr_exists(path));
        snprintf(path, sizeof(path), "%s/r2-e2/secret/psk", fx.cs); ASSERT(!pr_exists(path));
        ASSERT(pr_read(fx.env, after, sizeof(after))); ASSERT_STR_EQ(before, after);
        /* The burned epoch is never reused: the next plan counts past it and N is still current. */
        ASSERT(pr_plan(&fx, NULL, 0, &r)); ASSERT(pr_passed(&r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "current_epoch")), 1); ASSERT_EQ(json_get_int(json_get(&r.data, "next_epoch")), 3);
        zcl_command_reply_free(&r);
        pr_close(&fx);
    } TEST_END
    return failures;
}

static int g_saved_stderr = -1;
static bool pr_capture_begin(const char *path)
{
    fflush(stderr);
    g_saved_stderr = dup(2);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    bool ok = g_saved_stderr >= 0 && fd >= 0 && dup2(fd, 2) == 2;
    if (fd >= 0) close(fd);
    return ok;
}
static void pr_capture_end(void)
{
    fflush(stderr);
    if (g_saved_stderr >= 0) { (void)dup2(g_saved_stderr, 2); close(g_saved_stderr); g_saved_stderr = -1; }
}
static bool pr_find(const char *hay, size_t length, const void *needle, size_t n)
{
    for (size_t i = 0; i + n <= length; ++i) if (!memcmp(hay + i, needle, n)) return true;
    return false;
}
static bool pr_contains(const char *haystack, size_t length, const uint8_t secret[32])
{
    char hex[65];
    zcl_hex_encode(secret, 32, hex);
    return pr_find(haystack, length, hex, 64) || pr_find(haystack, length, secret, 32);
}
static bool pr_file_clean(const char *path, const uint8_t secret[32])
{
    char text[8192];
    FILE *file = fopen(path, "rb");
    if (!file) return true;
    size_t got = fread(text, 1, sizeof(text), file);
    fclose(file);
    return !pr_contains(text, got, secret);
}

static int pr_no_secret_bytes(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: no PSK bytes appear in the reply, the logs or the files it writes") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        struct zcl_command_reply r = {0};
        ASSERT(pr_plan(&fx, NULL, 0, &r)); char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        char log[1400]; snprintf(log, sizeof(log), "%s/stderr.log", fx.root);
        ASSERT(pr_capture_begin(log));
        bool called = pr_confirm(&fx, id, false, &r);
        pr_capture_end();
        ASSERT(called); ASSERT(pr_passed(&r));
        char wire[8192];
        size_t wrote = json_write(&r.data, wire, sizeof(wire));
        ASSERT(wrote > 0);
        char client_json[1400]; snprintf(client_json, sizeof(client_json), "%s/r2-e2/client.json", fx.cs);
        struct json_value cj = {0}; ASSERT(pr_json_file(client_json, &cj));
        char profile[1400]; snprintf(profile, sizeof(profile), "%s/r2-e2/profile", fx.cs);
        struct device_identity id_open = {0}; struct device_identity_publication_report report;
        struct device_pairing_store store; struct db_device_pairing row; uint8_t peer[32], root[32];
        ASSERT(zcl_hex_decode(json_get_str(json_get(&cj, "peer_key")), peer, 32));
        ASSERT(device_identity_open(&id_open, profile, false, &report).ok);
        ASSERT(device_identity_pair_store(&id_open, peer, &store).ok);
        ASSERT(db_device_pairing_inspect(&store, peer, &row, root));
        struct device_pairing_guard guard = {0}; struct device_pairing_psk_snapshot snap = {0};
        uint64_t now = (uint64_t)(clock_now_wall_ms() / 1000);
        ASSERT(device_pairing_psk_snapshot_acquire(&store, peer, root, now, DEVICE_PAIRING_HOST_OUTBOUND, fx.target_port, &guard, &snap));
        device_pairing_guard_release(&guard);
        uint8_t secret[32]; memcpy(secret, snap.secret, 32);
        device_pairing_psk_snapshot_destroy(&snap); device_identity_close(&id_open);
        char err[8192]; ASSERT(pr_read(log, err, sizeof(err)));
        ASSERT(!pr_contains(wire, wrote, secret));
        ASSERT(!pr_contains(err, strlen(err), secret));
        ASSERT(!pr_contains(r.error.message, strlen(r.error.message), secret));
        char path[1400];
        snprintf(path, sizeof(path), "%s/r2-e2/client.json", fx.cs); ASSERT(pr_file_clean(path, secret));
        snprintf(path, sizeof(path), "%s/r1-e2/receiver.json", fx.hs); ASSERT(pr_file_clean(path, secret));
        ASSERT(pr_file_clean(fx.env, secret));
        snprintf(path, sizeof(path), "%s/renew-r1-r2-e2.receipt", fx.cs); ASSERT(pr_exists(path)); ASSERT(pr_file_clean(path, secret));
        json_free(&cj); zcl_command_reply_free(&r);
        pr_close(&fx);
    } TEST_END
    return failures;
}

static int pr_plan_binding(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: a plan_id mismatch or stale evidence is refused and creates nothing") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        struct zcl_command_reply r = {0};
        ASSERT(pr_plan(&fx, NULL, 0, &r)); char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        char wrong[65]; snprintf(wrong, sizeof(wrong), "%s", id); wrong[0] = wrong[0] == '0' ? '1' : '0';
        ASSERT(pr_confirm(&fx, wrong, false, &r)); ASSERT(pr_code(&r, "RENEW_PLAN_MISMATCH")); ASSERT(!r.error.mutated);
        zcl_command_reply_free(&r);
        ASSERT(pr_confirm(&fx, NULL, false, &r)); ASSERT(pr_code(&r, "RENEW_PLAN_REQUIRED"));
        zcl_command_reply_free(&r);
        char path[1400];
        snprintf(path, sizeof(path), "%s/r2-e2", fx.cs); ASSERT(!pr_exists(path));
        snprintf(path, sizeof(path), "%s/r1-e2", fx.hs); ASSERT(!pr_exists(path));
        uint64_t c1, h1; ASSERT(pr_epoch_revoked(&fx, 1, &c1, &h1)); ASSERT_EQ(c1, 0u); ASSERT_EQ(h1, 0u);
        /* Evidence whose slot digest is not the running slot binary is stale: plan says so, confirm refuses. */
        ASSERT(pr_write(fx.slot, "slot-bytes", 0755));
        char env_text[400];
        snprintf(env_text, sizeof(env_text), "SLOT_NAME=tunnel-0123456789ab\nSLOT_SHA256=%064d\nSLOT_COMMIT=0\n", 7);
        snprintf(path, sizeof(path), "%s/slot.env", fx.ev); ASSERT(pr_write(path, env_text, 0600));
        struct json_value in = {0};
        ASSERT(pr_input(&fx, &in, NULL, false, false)); ASSERT(json_push_kv_str(&in, "evidence_dir", fx.ev));
        ASSERT(json_push_kv_str(&in, "slot_bin", fx.slot));
        ASSERT(pr_call("ops.mesh.device.pair.renew", &in, &r)); ASSERT(pr_passed(&r)); ASSERT(pr_bool(&r, "evidence_current", false));
        snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r); json_free(&in);
        ASSERT(pr_input(&fx, &in, id, true, false)); ASSERT(json_push_kv_str(&in, "evidence_dir", fx.ev));
        ASSERT(json_push_kv_str(&in, "slot_bin", fx.slot));
        ASSERT(pr_call("ops.mesh.device.pair.renew", &in, &r)); ASSERT(pr_code(&r, "RENEW_EVIDENCE_STALE")); ASSERT(!r.error.mutated);
        zcl_command_reply_free(&r); json_free(&in);
        snprintf(path, sizeof(path), "%s/r2-e2", fx.cs); ASSERT(!pr_exists(path));
        pr_close(&fx);
    } TEST_END
    return failures;
}

static int pr_status(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: status lists every pairing with expiry, state and PSK fingerprint only") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        struct json_value in = {0}; struct zcl_command_reply r = {0};
        ASSERT(pr_input(&fx, &in, NULL, false, false));
        ASSERT(pr_call("ops.mesh.device.pair.status", &in, &r)); ASSERT(pr_passed(&r));
        const struct json_value *list = json_get(&r.data, "pairings");
        ASSERT(list && list->type == JSON_ARR); ASSERT_EQ(list->num_children, 1u);
        const struct json_value *first = &list->children[0];
        ASSERT_EQ(json_get_int(json_get(first, "epoch")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(first, "state")), "active");
        ASSERT_EQ(strlen(json_get_str(json_get(first, "psk_fingerprint"))), 16u);
        ASSERT(json_get_int(json_get(first, "expires_at")) > 0);
        ASSERT(pr_bool(&r, "renew_due", true));
        zcl_command_reply_free(&r); json_free(&in);
        pr_close(&fx);
    } TEST_END
    return failures;
}
#endif

static int pr_bounds(void)
{
    int failures = 0;
    TEST_CASE("pair_renew: an over-long peer is refused, and an oversized unit environment aborts with epoch N in force") {
        struct pr_fx fx;
        ASSERT(pr_fixture(&fx, 86400));
        struct zcl_command_reply r = {0};
        struct json_value in = {0};
        char longpeer[201];
        memset(longpeer, 'a', sizeof(longpeer) - 1); longpeer[sizeof(longpeer) - 1] = 0;
        json_set_object(&in);
        ASSERT(json_push_kv_str(&in, "state_dir", fx.cs)); ASSERT(json_push_kv_str(&in, "hub_state_dir", fx.hs));
        ASSERT(json_push_kv_str(&in, "peer", longpeer));
        ASSERT(pr_call("ops.mesh.device.pair.renew", &in, &r));
        ASSERT(pr_code(&r, "RENEW_INPUT_REFUSED"));
        json_free(&in); zcl_command_reply_free(&r);
        /* A unit environment larger than the bounded copy cannot be restored faithfully: refuse before changing it. */
        char path[1400], big[5000];
        memset(big, '#', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
        snprintf(path, sizeof(path), "%s/tunnel-receiver-r1.env", fx.hc);
        ASSERT(pr_write(path, big, 0600));
        ASSERT(pr_plan(&fx, NULL, 0, &r)); ASSERT(pr_passed(&r));
        char id[65]; snprintf(id, sizeof(id), "%s", pr_str(&r, "plan_id")); zcl_command_reply_free(&r);
        ASSERT(pr_confirm(&fx, id, false, &r));
        ASSERT(pr_code(&r, "RENEW_ACTIVATE_FAILED"));
        char back[5200];
        ASSERT(pr_read(path, back, sizeof(back))); ASSERT_EQ(strlen(back), sizeof(big) - 1);
        zcl_command_reply_free(&r);
        pr_close(&fx);
    } TEST_END
    return failures;
}

int test_pair_renew(void)
{
    int failures = 0;
#if defined(__linux__)
    failures += pr_plan_threshold();
    failures += pr_confirm_roundtrip();
    failures += pr_smoke_failure();
    failures += pr_no_secret_bytes();
    failures += pr_plan_binding();
    failures += pr_status();
    failures += pr_bounds();
#endif
    return failures;
}
