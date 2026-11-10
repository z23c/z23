/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Fixed same-image child: verified app discovery with outbound-only Tor. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include "command/native_app_network_worker.h"
#if !defined(_WIN32)
#include "command/native_app_network.h"
#include "command/native_app_scratch.h"
#include "command/native_app_network_link.h"
#include "command/native_app_network_row.h"
#include "command/native_app_network_lifeline.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "vcs/bundle_carry.h"
#include "util/write_all.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* No process-global Tor state is shared: main dispatches this exact argument
 * shape before config/node startup and this process exits after one request.
 * argv: mode, URL, alternate carrier onion or '-', selected-row JSON or '-',
 * scratch path, scratch dev, scratch ino, bootstrap input port, timeout ms. */
static bool anw_enter_scratch(const char *path, const char *dev, const char *ino)
{
    uint64_t want_dev, want_ino;
    if (!path || path[0] != '/' || strnlen(path, 4096) >= 4096 ||
        !an_scratch_decimal(dev, UINT64_MAX, &want_dev) || !an_scratch_decimal(ino, UINT64_MAX, &want_ino)) return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 0777) == 0700 && (uint64_t)st.st_dev == want_dev &&
        (uint64_t)st.st_ino == want_ino && fchdir(fd) == 0;
    close(fd); return ok;
}
static bool anw_row_json(struct json_value *array, const struct zcl_app_offer_row *row)
{
    char offer[ZCL_APP_OFFER_TEXT_MAX + 1]; struct json_value v; json_init(&v); json_set_object(&v);
    bool ok = zcl_app_offer_format(&row->offer, offer, sizeof(offer)) &&
        json_push_kv_str(&v, "post_id", row->post_id) && json_push_kv_str(&v, "host", row->host) &&
        json_push_kv_int(&v, "created_at", row->created_at) && json_push_kv_str(&v, "offer", offer) &&
        json_push_back(array, &v);
    json_free(&v); return ok;
}
static bool anw_selected(const char *raw, struct zcl_app_offer_row *row)
{
    if (!raw || strnlen(raw, 4097) > 4096) return false;
    size_t len = strlen(raw); struct json_value v; json_init(&v);
    bool ok = json_read(&v, raw, len) && app_network_json_canonical(&v, raw, len) &&
        app_network_row_decode(&v, row);
    json_free(&v); return ok;
}
static bool anw_emit_rows(int fd, const struct zcl_app_offer_row *rows, size_t count, bool incomplete)
{
    struct json_value d, a; json_init(&d); json_init(&a); json_set_object(&d); json_set_array(&a);
    bool ok = json_push_kv_str(&d, "schema", "zcl.app_network_worker.v1") &&
              json_push_kv_bool(&d, "ok", true) && json_push_kv_bool(&d, "incomplete", incomplete);
    for (size_t i = 0; ok && i < count; i++) ok = anw_row_json(&a, &rows[i]);
    ok = ok && json_push_kv(&d, "rows", &a);
    size_t len = ok ? json_write(&d, NULL, 0) : 0;
    char *wire = len && len < 32768 ? zcl_malloc(len + 1, "network.worker.rows") : NULL;
    ok = wire && json_write(&d, wire, len + 1) == len && zcl_write_all(fd, wire, len);
    free(wire); json_free(&a); json_free(&d); return ok;
}
static bool anw_emit_carrier(int fd, const uint8_t *bytes, size_t len, const char *frame)
{
    if (!bytes || !len || len > VCS_BUNDLE_MAX_BYTES) return false;
    char head[128]; int n = snprintf(head, sizeof(head),
        "{\"schema\":\"zcl.app_network_worker.v1\",\"ok\":true,\"size\":%zu,\"carrier_hex\":\"", len);
    if (n <= 0 || (size_t)n >= sizeof(head) || !zcl_write_all(fd, head, (size_t)n)) return false;
    char hex[8193];
    while (len) {
        size_t take = len < 4096 ? len : 4096;
        zcl_hex_encode(bytes, take, hex);
        if (!zcl_write_all(fd, hex, take * 2u)) return false;
        bytes += take; len -= take;
    }
    if (!zcl_write_all(fd, "\"", 1)) return false;
    if (frame && *frame) return zcl_write_all(fd, ",\"frame\":\"", 10) &&
        zcl_write_all(fd, frame, strlen(frame)) && zcl_write_all(fd, "\"}", 2);
    return zcl_write_all(fd, "}", 1);
}
#if defined(ZCL_TESTING)
bool zcl_test_app_network_emit_direct(int fd, const uint8_t *bytes, size_t len, const char *frame)
{ return anw_emit_carrier(fd, bytes, len, frame); }
#endif
struct anw_request {
    struct app_network_link link; struct zcl_app_offer_row selected;
    uint64_t port, timeout, parent; bool catalog, exact, carrier, direct;
};
struct anw_result {
    struct zcl_app_offer_row rows[4]; size_t count; bool incomplete;
    uint8_t *bytes; size_t len; enum app_network_error error;
    char frame[APP_NETWORK_FRAME_HEX_CAP];
};
static bool anw_mode(struct anw_request *r, char **argv)
{
    bool empty = !strcmp(argv[4], "-") && !strcmp(argv[5], "-");
    r->catalog = !strcmp(argv[2], "catalog") && !r->link.exact && empty;
    r->exact = !strcmp(argv[2], "exact") && r->link.exact && empty;
    r->direct = !strcmp(argv[2], "direct") && r->link.exact && empty;
    r->carrier = !strcmp(argv[2], "carrier") && r->link.exact &&
        vcs_app_offer_peer_is_onion(argv[4]) && anw_selected(argv[5], &r->selected) &&
        !strcmp(r->selected.post_id, r->link.post_id);
    return r->catalog || r->exact || r->carrier || r->direct;
}
static bool anw_request_parse(struct anw_request *r, char **argv)
{
    memset(r, 0, sizeof(*r));
    return app_network_link_parse(argv[3], &r->link) &&
        an_scratch_decimal(argv[9], 53569u, &r->port) && r->port > 0 &&
        an_scratch_decimal(argv[10], 120000u, &r->timeout) && r->timeout > 0 &&
        !strcmp(argv[11], "v1") && an_scratch_decimal(argv[12], UINT64_MAX, &r->parent) &&
        r->parent > 1 && anw_mode(r, argv);
}
/* One maximum-size carrier must fit both staging and its eventual pool. */
static struct vcs_package_store *anw_store_open(const char *datadir)
{
    uint64_t quota = (uint64_t)VCS_BUNDLE_MAX_BYTES * 10u /
                     VCS_PACKAGE_STORE_STAGING_TENTHS;
    return vcs_package_store_open(datadir, quota);
}
#if defined(ZCL_TESTING)
struct vcs_package_store *zcl_test_app_network_worker_store_open(const char *datadir)
{ return anw_store_open(datadir); }
#endif

static bool anw_fetch(const struct anw_request *r, char **argv,
    struct app_network_transport *transport, struct anw_result *out)
{
    if (r->catalog) return app_network_catalog(transport, r->link.onion, platform_time_wall_unix(),
        out->rows, 4, &out->count, &out->incomplete, &out->error);
    if (r->exact) {
        bool ok = app_network_exact(transport, r->link.onion, r->link.post_id,
            platform_time_wall_unix(), &out->rows[0], &out->error);
        out->count = ok ? 1 : 0; return ok;
    }
    struct vcs_package_store *store = anw_store_open(".");
    bool mutated = false;
    bool ok = store && (r->direct ? app_network_direct(transport, r->link.onion, r->link.post_id,
        platform_time_wall_unix(), store, out->frame, &out->bytes, &out->len, &mutated, &out->error) :
        app_network_carrier(transport, r->link.onion, argv[4], &r->selected,
        platform_time_wall_unix(), store, &out->bytes, &out->len, &mutated, &out->error));
    if (store) vcs_package_store_close(store);
    return ok;
}
static bool anw_connect(const struct anw_request *r, char **argv, struct anw_result *out)
{
    int64_t start = platform_time_monotonic_ms(); bool started = false;
    if (start > 0 && !tor_integration_is_enabled() && anw_enter_scratch(argv[6], argv[7], argv[8])) {
        tor_integration_set_serve_onion(false);
        started = tor_integration_start_private(".", (uint16_t)r->port);
    }
    while (started && !tor_integration_is_dial_ready() &&
           platform_time_monotonic_ms() - start < (int64_t)r->timeout)
        platform_sleep_ms(100);
    int64_t elapsed = platform_time_monotonic_ms() - start;
    struct app_network_transport transport = {.fetch = app_network_tor_fetch,
        .timeout_ms = elapsed >= 0 && elapsed < (int64_t)r->timeout ? (unsigned)(r->timeout - (uint64_t)elapsed) : 0,
        .parallel_safe = true};
    bool ok = started && tor_integration_is_dial_ready() && transport.timeout_ms && anw_fetch(r, argv, &transport, out);
    if (started) tor_integration_stop();
    return ok;
}
static bool anw_emit_result(int protocol, const struct anw_result *result, bool ok)
{
    if (ok) return result->bytes ? anw_emit_carrier(protocol, result->bytes, result->len, result->frame) :
        anw_emit_rows(protocol, result->rows, result->count, result->incomplete);
    char message[160];
    int n = snprintf(message, sizeof(message), "{\"schema\":\"zcl.app_network_worker.v1\",\"ok\":false,\"error\":%d}", (int)result->error);
    return n > 0 && (size_t)n < sizeof(message) && zcl_write_all(protocol, message, (size_t)n);
}
/* Returns 0 only for a complete protocol reply; error code is fixed/local. */


#endif

int app_network_worker_main(int argc, char **argv)
{
#if !defined(_WIN32)
    if (argc != 13 || strcmp(argv[1], "--app-network-worker")) return 2;
    int protocol = dup(STDOUT_FILENO);
    if (protocol < 0 || fcntl(protocol, F_SETFD, FD_CLOEXEC) != 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
        if (protocol >= 0) close(protocol);
        return 2;
    }
    struct anw_request request; struct anw_result result = {.error = APP_NETWORK_UNAVAILABLE};
    struct app_network_lifeline guard;
    if (!anw_request_parse(&request, argv) ||
        !app_network_lifeline_start(&guard, request.parent, (unsigned)request.timeout + 15000u)) {
        close(protocol); return 2;
    }
    bool ok = anw_connect(&request, argv, &result);
    bool emitted = anw_emit_result(protocol, &result, ok);
    free(result.bytes); close(protocol);
    if (!app_network_lifeline_stop(&guard)) _exit(2);
    return emitted ? 0 : 2;
#else
    (void)argc; (void)argv; return 2;
#endif
}
