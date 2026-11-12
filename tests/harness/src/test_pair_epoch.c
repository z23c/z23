/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: ops.mesh.device.pair.export / .import: deterministic sha256-stable
 * epoch archives, cross-host client.json directory rewrite, owner-only modes,
 * typed refusals (dest exists, sha mismatch, epoch exists), binary round trip. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "services/device_identity.h"
#include "models/device_pairing.h"
#include "platform/clock.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__linux__)
static bool pe_call(const char *path, const struct json_value *input, struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler) return false;
    reply->data_schema = spec->output_schema ? spec->output_schema : reply->data_schema;
    struct zcl_command_request request = {.spec = spec, .input = input};
    spec->handler(&request, reply);
    return true;
}
static bool pe_passed(const struct zcl_command_reply *r) { return r->status == ZCL_COMMAND_STATUS_PASSED; }
static bool pe_code(const struct zcl_command_reply *r, const char *code)
{
    return r->status == ZCL_COMMAND_STATUS_FAILED && !strcmp(r->error.code, code);
}
static const char *pe_str(const struct zcl_command_reply *r, const char *key) { return json_get_str(json_get(&r->data, key)); }
static int64_t pe_int(const struct zcl_command_reply *r, const char *key)
{
    const struct json_value *v = json_get(&r->data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}
static bool pe_mode_is(const char *path, mode_t want)
{
    struct stat info;
    return stat(path, &info) == 0 && (info.st_mode & 07777) == want;
}
static bool pe_read_text(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t got = fread(out, 1, cap - 1, file);
    fclose(file);
    out[got] = 0;
    return true;
}
static bool pe_bytes_are(const char *path, const uint8_t *want, size_t len)
{
    uint8_t got[64];
    if (len > sizeof(got)) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t got_len;
    do got_len = read(fd, got, sizeof(got)); while (got_len < 0 && errno == EINTR);
    close(fd);
    return (size_t)got_len == len && !memcmp(got, want, len);
}
static bool pe_file_sha256(const char *path, char hex[65])
{
    struct sha256_ctx ctx;
    uint8_t block[4096], digest[SHA256_OUTPUT_SIZE];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    sha256_init(&ctx);
    for (;;) {
        ssize_t got;
        do got = read(fd, block, sizeof(block)); while (got < 0 && errno == EINTR);
        if (got <= 0) break;
        sha256_write(&ctx, block, (size_t)got);
    }
    close(fd);
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, SHA256_OUTPUT_SIZE, hex);
    return true;
}

/* ── fixture: epoch 3 for peer r2 as 20-pair.sh leaves a client epoch ── */

struct pe_fx {
    char root[1024], state[1100], dest[1100], dir[1300], profile[1400], route[1500];
};

static const uint8_t pe_blob[] = {0x00, 0xff, 0x01, '\n', 0x7f, 0x80, 0xfe, 'z'};

static bool pe_write(const char *path, const void *bytes, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = len == 0 || write(fd, bytes, len) == (ssize_t)len;
    return close(fd) == 0 && ok && chmod(path, 0600) == 0;
}

static bool pe_grant(struct device_identity *own, struct device_identity *peer, uint64_t now, uint64_t expires,
                     struct device_pairing_store *store, uint8_t root[32])
{
    struct db_device_pairing row = {.capabilities = DEVICE_PAIRING_CAP_HOST_FORWARD, .paired_at = now - 1, .expires_at = expires};
    if (!device_identity_pair_store(own, peer->public_key, store).ok) return false;
    memcpy(row.local_key, own->public_key, 32);
    memcpy(row.peer_key, peer->public_key, 32);
    memcpy(row.profile, store->profile, 32);
    row.host_scope.inbound_port = 0;
    row.host_scope.outbound_port = 28022;
    row.host_scope.binding.backend_profile = DEVICE_PAIRING_HOST_SHAKE256_WRAP_PSK;
    struct device_pairing_psk_binding *binding = &row.host_scope.binding.psk;
    binding->credential_id[0] = 91;
    binding->key_epoch = 1;
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

static bool pe_fixture(struct pe_fx *fx)
{
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->root, sizeof(fx->root), "pair-epoch")) return false;
    snprintf(fx->state, sizeof(fx->state), "%s/state", fx->root);
    snprintf(fx->dest, sizeof(fx->dest), "%s/dest", fx->root);
    snprintf(fx->dir, sizeof(fx->dir), "%s/r2-e3", fx->state);
    snprintf(fx->profile, sizeof(fx->profile), "%s/profile", fx->dir);
    snprintf(fx->route, sizeof(fx->route), "%s/client.json", fx->dir);
    char hub_profile[1400], secret_dir[1400], secret[1500], note[1500];
    snprintf(hub_profile, sizeof(hub_profile), "%s/hub", fx->root);
    snprintf(secret_dir, sizeof(secret_dir), "%s/secret", fx->dir);
    snprintf(secret, sizeof(secret), "%s/psk", secret_dir);
    snprintf(note, sizeof(note), "%s/note", secret_dir);
    if (mkdir(fx->state, 0700) || mkdir(fx->dest, 0700) || mkdir(fx->dir, 0700) || mkdir(secret_dir, 0700)) return false;
    struct device_identity ci = {0}, hi = {0};
    struct device_identity_publication_report report;
    uint64_t now = (uint64_t)(clock_now_wall_ms() / 1000);
    struct device_pairing_store store;
    uint8_t croot[32];
    char hk[65], cr[65], text[1200];
    bool ok = device_identity_open(&ci, fx->profile, true, &report).ok &&
        device_identity_open(&hi, hub_profile, true, &report).ok &&
        pe_grant(&ci, &hi, now, now + 86400, &store, croot);
    zcl_hex_encode(hi.public_key, 32, hk);
    zcl_hex_encode(croot, 32, cr);
    device_identity_close(&ci);
    device_identity_close(&hi);
    if (!ok) return false;
    int n = snprintf(text, sizeof(text),
        "{\"directory\":\"%s\",\"peer_key\":\"%s\",\"expected_root\":\"%s\",\"target_port\":28022,\"route_id\":\"r1-r2-e3\","
        "\"route_address\":\"127.0.0.1\",\"route_port\":28022,\"connect_ms\":5000,\"handshake_ms\":10000,"
        "\"session_ms\":28800000,\"idle_ms\":1800000,\"confirm\":true}",
        fx->profile, hk, cr);
    if (n < 0 || (size_t)n >= sizeof(text)) return false;
    return pe_write(fx->route, text, (size_t)n) && pe_write(secret, pe_blob, sizeof(pe_blob)) && pe_write(note, "", 0);
}

static void pe_fixture_free(struct pe_fx *fx)
{
    if (fx->root[0]) test_rm_rf(fx->root);
}

static bool pe_export_call(const struct pe_fx *fx, const char *destination, struct zcl_command_reply *reply)
{
    struct json_value in = {0};
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "state_dir", fx->state) && json_push_kv_str(&in, "peer", "r2") &&
              json_push_kv_int(&in, "epoch", 3) && json_push_kv_str(&in, "destination", destination) &&
              pe_call("ops.mesh.device.pair.export", &in, reply);
    json_free(&in);
    return ok;
}

static bool pe_import_call(const char *archive, const char *sha, const char *state_root, struct zcl_command_reply *reply)
{
    struct json_value in = {0};
    json_set_object(&in);
    bool ok = json_push_kv_str(&in, "archive", archive) && json_push_kv_str(&in, "expected_sha256", sha) &&
              json_push_kv_str(&in, "state_root", state_root) && pe_call("ops.mesh.device.pair.import", &in, reply);
    json_free(&in);
    return ok;
}

static bool pe_export_sha_stable(const struct zcl_command_reply *a, const struct zcl_command_reply *b,
                                 const char *path_a, const char *path_b)
{
    char sha_a[65], sha_b[65];
    return pe_file_sha256(path_a, sha_a) && pe_file_sha256(path_b, sha_b) && !strcmp(pe_str(a, "sha256"), sha_a) &&
           !strcmp(sha_a, sha_b) && !strcmp(pe_str(b, "sha256"), sha_a);
}

static bool pe_export_result_ok(const struct pe_fx *fx, const struct zcl_command_reply *a, const struct zcl_command_reply *b,
                                const char *path_a, const char *path_b)
{
    return pe_export_sha_stable(a, b, path_a, path_b) && !strcmp(pe_str(a, "peer"), "r2") && pe_int(a, "epoch") == 3 &&
           !strcmp(pe_str(a, "route_id"), "r1-r2-e3") && !strcmp(pe_str(a, "directory"), fx->profile) &&
           !strcmp(pe_str(a, "archive"), path_a) && pe_int(a, "bytes") > 0 && pe_int(a, "bytes") == pe_int(b, "bytes");
}

static bool pe_export_archive_case(void)
{
    struct pe_fx fx;
    struct zcl_command_reply a = {0}, b = {0};
    char path_a[1200], path_b[1200];
    bool ok = pe_fixture(&fx);
    snprintf(path_a, sizeof(path_a), "%s/a.pea", fx.root);
    snprintf(path_b, sizeof(path_b), "%s/b.pea", fx.root);
    ok = ok && pe_export_call(&fx, path_a, &a) && pe_passed(&a) && pe_export_call(&fx, path_b, &b) && pe_passed(&b) &&
        pe_export_result_ok(&fx, &a, &b, path_a, path_b);
    /* The archive carries the PSK: it must exist at mode 0600 exactly. */
    ok = ok && pe_mode_is(path_a, 0600) && pe_mode_is(path_b, 0600);
    zcl_command_reply_free(&a);
    zcl_command_reply_free(&b);
    pe_fixture_free(&fx);
    return ok;
}

static bool pe_import_route_ok(const struct pe_fx *fx, const struct zcl_command_reply *im, const char *want_dir,
                               const char *want_route, char *text, size_t cap)
{
    return !strcmp(pe_str(im, "directory"), want_dir) && !strcmp(pe_str(im, "peer"), "r2") &&
           !strcmp(pe_str(im, "route_id"), "r1-r2-e3") && pe_int(im, "epoch") == 3 && pe_read_text(want_route, text, cap) &&
           strstr(text, fx->dest) != NULL && strstr(text, fx->state) == NULL;
}

static bool pe_import_files_ok(const char *want_dir, const char *want_route, const char *secret, const char *secret_dir)
{
    return pe_bytes_are(secret, pe_blob, sizeof(pe_blob)) && pe_mode_is(want_dir, 0700) && pe_mode_is(want_route, 0600) &&
           pe_mode_is(secret, 0600) && pe_mode_is(secret_dir, 0700);
}

static bool pe_import_rewrite_case(void)
{
    struct pe_fx fx;
    struct zcl_command_reply x = {0}, im = {0};
    char archive[1200], want_dir[1300], want_route[1400], secret[1500], secret_dir[1500], text[1600];
    bool ok = pe_fixture(&fx);
    snprintf(archive, sizeof(archive), "%s/x.pea", fx.root);
    snprintf(want_dir, sizeof(want_dir), "%s/r2-e3", fx.dest);
    snprintf(want_route, sizeof(want_route), "%s/client.json", want_dir);
    snprintf(secret, sizeof(secret), "%s/secret/psk", want_dir);
    snprintf(secret_dir, sizeof(secret_dir), "%s/secret", want_dir);
    ok = ok && pe_export_call(&fx, archive, &x) && pe_passed(&x) &&
        pe_import_call(archive, pe_str(&x, "sha256"), fx.dest, &im) && pe_passed(&im) &&
        pe_import_route_ok(&fx, &im, want_dir, want_route, text, sizeof(text)) &&
        pe_import_files_ok(want_dir, want_route, secret, secret_dir);
    zcl_command_reply_free(&x);
    zcl_command_reply_free(&im);
    pe_fixture_free(&fx);
    return ok;
}

static bool pe_refusals_case(void)
{
    struct pe_fx fx;
    struct zcl_command_reply x = {0}, bad_dest = {0}, bad_sha = {0}, first = {0}, second = {0};
    char archive[1200], other[1200], refused[1300];
    bool ok = pe_fixture(&fx);
    snprintf(archive, sizeof(archive), "%s/used.pea", fx.root);
    snprintf(other, sizeof(other), "%s/other", fx.root);
    ok = ok && pe_export_call(&fx, archive, &x) && pe_passed(&x);
    /* the archive path now exists: exporting onto it refuses typed */
    ok = ok && pe_export_call(&fx, archive, &bad_dest) && pe_code(&bad_dest, "EXPORT_DEST_EXISTS");
    /* a wrong digest refuses before anything is materialized */
    ok = ok && pe_import_call(archive, "0000000000000000000000000000000000000000000000000000000000000000", other, &bad_sha) &&
        pe_code(&bad_sha, "IMPORT_SHA_MISMATCH");
    snprintf(refused, sizeof(refused), "%s/r2-e3", other);
    ok = ok && access(refused, F_OK) != 0;
    /* a real import lands, and importing the same epoch again refuses */
    ok = ok && pe_import_call(archive, pe_str(&x, "sha256"), other, &first) && pe_passed(&first) &&
        pe_import_call(archive, pe_str(&x, "sha256"), other, &second) && pe_code(&second, "IMPORT_EPOCH_EXISTS");
    zcl_command_reply_free(&x);
    zcl_command_reply_free(&bad_dest);
    zcl_command_reply_free(&bad_sha);
    zcl_command_reply_free(&first);
    zcl_command_reply_free(&second);
    pe_fixture_free(&fx);
    return ok;
}

#endif /* __linux__ */

#if defined(__linux__)
static int pe_export_archive(void)
{
    int failures = 0;
    TEST_CASE("pair_epoch: two exports of one epoch are byte-identical and the sha256 names those bytes") {
        ASSERT(pe_export_archive_case());
    } TEST_END
    return failures;
}

static int pe_import_rewrite(void)
{
    int failures = 0;
    TEST_CASE("pair_epoch: import rewrites client.json's directory to the destination root with owner-only modes") {
        ASSERT(pe_import_rewrite_case());
    } TEST_END
    return failures;
}

static int pe_refusals(void)
{
    int failures = 0;
    TEST_CASE("pair_epoch: an existing destination, a sha mismatch and an existing epoch are refused typed") {
        ASSERT(pe_refusals_case());
    } TEST_END
    return failures;
}
#endif

int test_pair_epoch(void)
{
    int failures = 0;
#if defined(__linux__)
    failures += pe_export_archive();
    failures += pe_import_rewrite();
    failures += pe_refusals();
#endif
    return failures;
}
