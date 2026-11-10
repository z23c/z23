/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Inert draft: per-process app-only carrier host, no node runtime. */
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include "command/native_app_host_worker.h"
#if !defined(_WIN32)
#include "chain/chainparams.h"
#include "command/native_app_scratch.h"
#include "command/native_app_network_lifeline.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/board_site_controller.h"
#include "controllers/zcode_site_controller.h"
#include "crypto/sha256.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "platform/rng.h"
#include "session/fleet_board_proto.h"
#include "util/write_all.h"
#include "vcs/app_offer.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_share.h"
#include "vcs/package_accept.h"
#include "vcs/package_store.h"
#include "vcs/zcode_dht_identity.h"
#include <stdatomic.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
struct ahw_context {
    struct fleet_board_post post;
    char carrier_root[65];
    int64_t started_ms, deadline_ms;
    pthread_mutex_t clock_mutex;
    int64_t clock_last;
    bool clock_bad;
    atomic_bool ready;
};
static bool ahw_scratch(const char *path, uint64_t dev, uint64_t ino)
{
    if (!path || path[0] != '/' || strnlen(path, 4096) >= 4096) return false;
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
        (st.st_mode & 0777) == 0700 && (uint64_t)st.st_dev == dev &&
        (uint64_t)st.st_ino == ino && fchdir(fd) == 0;
    close(fd); return ok;
}
#if defined(ZCL_TESTING)
bool zcl_test_app_host_enter_scratch(const char *path, uint64_t dev, uint64_t ino)
{ return ahw_scratch(path, dev, ino); }
#endif
static bool ahw_clock(struct ahw_context *c, int64_t *out)
{
    pthread_mutex_lock(&c->clock_mutex);
    int64_t now = platform_time_monotonic_ms();
    bool ok = !c->clock_bad && now > 0 && now >= c->started_ms && now >= c->clock_last;
    if (ok) { c->clock_last = now; *out = now; }
    else c->clock_bad = true;
    pthread_mutex_unlock(&c->clock_mutex); return ok;
}
static size_t ahw_handler(const char *method, const char *path, const uint8_t *body,
    size_t body_len, uint8_t *response, size_t cap, void *context)
{
    struct ahw_context *c = context;
    if (!atomic_load_explicit(&c->ready, memory_order_acquire) || !path) return 0;
    int64_t now;
    if (!ahw_clock(c, &now) || now >= c->deadline_ms) return 0;
    size_t written = 0;
    if (!strncmp(path, "/board/apps/v1", 14))
        written = board_site_handle_app_post(method, path, body, body_len, response, cap,
                                             &c->post, platform_time_wall_unix());
    else {
        static const char download[] = "/zcode/download/";
        size_t n = sizeof(download)-1;
        if (strncmp(path, download, n) || strncmp(path+n, c->carrier_root, 64) ||
            (path[n+64] && path[n+64] != '/')) return 0;
        written = zcode_site_handle_request(method, path, body, body_len, response, cap, ".");
    }
    return ahw_clock(c, &now) && now < c->deadline_ms ? written : 0;
}
static bool ahw_read_carrier(uint64_t expected_size, uint8_t **out)
{
    *out = NULL;
    if (!expected_size || expected_size > VCS_BUNDLE_MAX_BYTES) return false;
    int fd = open("carrier.z23share", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st; size_t n = (size_t)expected_size;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
              st.st_size >= 0 && (uint64_t)st.st_size == expected_size;
    uint8_t *bytes = ok ? malloc(n) : NULL; /* raw-alloc-ok: bounded carrier */
    ok = ok && bytes && an_scratch_read_exact(fd, bytes, n);
    close(fd); if (!ok) { free(bytes); return false; }
    *out = bytes; return true;
}
static bool ahw_store_carrier(struct ahw_context *c, const uint8_t *bytes, size_t size)
{
    if (!bytes || !size || size > VCS_BUNDLE_MAX_BYTES) return false;
    uint8_t carrier[32];
    /* The unpinned carrier must fit staging as well as the eventual rare pool.
     * Reserve quota, not data: only this one bounded carrier is stored here. */
    uint64_t quota = (uint64_t)VCS_BUNDLE_MAX_BYTES * 10u / VCS_PACKAGE_STORE_STAGING_TENTHS;
    struct vcs_package_store *store = vcs_package_store_open(".", quota);
    bool ok = store && vcs_bundle_put_to_no_evict(store, bytes, size, carrier) == VCS_BUNDLE_OK;
    if (ok) zcl_hex_encode(carrier, 32, c->carrier_root);
    if (store) vcs_package_store_close(store);
    return ok;
}
#if defined(ZCL_TESTING)
bool zcl_test_app_host_store_carrier(const uint8_t *bytes, size_t size, char root[65])
{
    struct ahw_context ctx = {0};
    bool ok = ahw_store_carrier(&ctx, bytes, size);
    if (ok) memcpy(root, ctx.carrier_root, 65);
    return ok;
}
#endif
static bool ahw_chain_matches(const struct vcs_package_share *share)
{
    char chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    return vcs_package_accept_chain_id(chain, sizeof(chain)) && !strcmp(share->release.chain_id, chain);
}
static bool ahw_carrier(struct ahw_context *c, const char *name, const char *release,
                        const char *package, const char *publisher, const char *hash, uint64_t size)
{
    uint8_t *bytes = NULL; struct vcs_package_share *share = zcl_calloc(1, sizeof(*share), "app.host.share");
    const char *reason = NULL;
    uint8_t expected[32], digest[32], release_id[32], package_id[32], pub[33];
    bool ok = share && zcl_hex_decode_lower(hash, expected, 32) && zcl_hex_decode_lower(release, release_id, 32) &&
        zcl_hex_decode_lower(package, package_id, 32) && zcl_hex_decode_lower(publisher, pub, 33) && ahw_read_carrier(size, &bytes);
    if (ok) {
        struct sha256_ctx sha; sha256_init(&sha); sha256_write(&sha, bytes, (size_t)size);
        sha256_finalize(&sha, digest);
        ok = !memcmp(expected, digest, 32) && vcs_package_share_load(share, bytes, (size_t)size, &reason) &&
            !strcmp(share->release.name, name) && !memcmp(share->release_id, release_id, 32) &&
            !memcmp(share->release.package_root, package_id, 32) &&
            !memcmp(share->release.publisher_pubkey, pub, 33) && ahw_chain_matches(share);
    }
    ok = ok && ahw_store_carrier(c, bytes, (size_t)size);
    if (share) { vcs_package_share_cleanup(share); free(share); }
    free(bytes); return ok;
}
#if defined(ZCL_TESTING)
bool zcl_test_app_host_verify_carrier(const char *name, const char *release, const char *package,
    const char *publisher, const char *hash, uint64_t size)
{
    struct ahw_context ctx = {0};
    return ahw_carrier(&ctx, name, release, package, publisher, hash, size);
}
#endif
static bool ahw_post(struct ahw_context *c, const char *name, const char *release,
                     const char *package, const char *publisher, const char *hash, uint64_t size, const char *onion)
{
    struct zcl_app_offer offer = {0};
    if (snprintf(offer.name, sizeof(offer.name), "%s", name) >= (int)sizeof(offer.name) ||
        snprintf(offer.onion, sizeof(offer.onion), "%s", onion) >= (int)sizeof(offer.onion)) return false;
    (void)release; memcpy(offer.root, package, 65); memcpy(offer.publisher, publisher, 67);
    memcpy(offer.carrier, c->carrier_root, 65); memcpy(offer.sha256, hash, 65); offer.size = (int64_t)size;
    struct fleet_board_post *post = &c->post;
    post->kind = FLEET_BOARD_KIND_OFFER; post->scope = FLEET_BOARD_SCOPE_PUBLIC;
    int64_t now = platform_time_wall_unix(); if (now <= 0) return false;
    post->created_at = (uint64_t)now; post->ttl = 86400u;
    (void)snprintf(post->room, sizeof(post->room), "apps");
    (void)snprintf(post->agent, sizeof(post->agent), "app-host");
    if (!zcl_app_offer_format(&offer, post->text, sizeof(post->text))) return false;
    post->text_len = (uint32_t)strlen(post->text);
    uint8_t seed[32], pub[32]; char error[256];
    bool ok = vcs_zcode_dht_online_key_load_or_create(".", seed, pub, error, sizeof(error)) &&
        fleet_board_post_sign(post, seed, pub) == FLEET_BOARD_OK;
    memset(seed, 0, sizeof(seed)); return ok;
}
static bool ahw_emit(int fd, const struct ahw_context *c, const char *onion)
{
    uint8_t wire[4096]; char hex[8193]; size_t n = 0;
    if (fleet_board_frame_encode_post(&c->post, wire, sizeof(wire), &n) != FLEET_BOARD_OK) return false;
    zcl_hex_encode(wire, n, hex);
    return zcl_write_all(fd, "zcl-app-host-v1 ", 16) && zcl_write_all(fd, onion, strlen(onion)) &&
        zcl_write_all(fd, " ", 1) && zcl_write_all(fd, hex, n * 2u) && zcl_write_all(fd, "\n", 1);
}
static bool ahw_bootstrap(struct ahw_context *ctx, int64_t deadline)
{
    int64_t start = 0;
    bool clock_ok = ahw_clock(ctx, &start);
    int64_t bootstrap_deadline = start > 0 && start <= INT64_MAX - 120000 ? start + 120000 : 0;
    if (bootstrap_deadline > deadline) bootstrap_deadline = deadline;
    bool ok = clock_ok && start > 0 && bootstrap_deadline > start;
    while (ok && tor_integration_is_enabled() && !tor_integration_is_ready()) {
        int64_t now = 0;
        if (!ahw_clock(ctx, &now) || now >= bootstrap_deadline) { ok = false; break; }
        platform_sleep_ms(100);
    }
    return ok;
}
static bool ahw_bootstrap_port(bool (*fill)(uint8_t *, size_t), uint16_t *out)
{
    uint8_t random[2];
    if (!fill || !out || !fill(random, sizeof(random))) return false;
    *out = (uint16_t)(1024u + (((unsigned)random[0] << 8 | random[1]) % (53569u - 1024u + 1u)));
    return true;
}
#if defined(ZCL_TESTING)
bool zcl_test_app_host_bootstrap_port(bool (*fill)(uint8_t *, size_t), uint16_t *out)
{ return ahw_bootstrap_port(fill, out); }
#endif
static bool ahw_start_tor(void)
{
    uint16_t port;
    return ahw_bootstrap_port(rng_host_fill, &port) && tor_integration_start_private(".", port);
}
static bool ahw_serve(struct ahw_context *ctx, int protocol, char **argv, uint64_t size, int64_t deadline)
{
    if (!ahw_carrier(ctx, argv[5], argv[6], argv[7], argv[8], argv[9], size)) return false;
    tor_integration_set_handler(ahw_handler, ctx);
    tor_integration_set_serve_onion(true);
    if (!ahw_start_tor()) return false;
    bool ok = ahw_bootstrap(ctx, deadline);
    const char *onion = ok && tor_integration_is_ready() ? tor_integration_get_onion_address() : NULL;
    ok = onion && strlen(onion) == 62 && ahw_post(ctx, argv[5], argv[6], argv[7], argv[8], argv[9], size, onion);
    int64_t ready_at = 0;
    ok = ok && ahw_clock(ctx, &ready_at) && ready_at < deadline;
    if (ok) {
        atomic_store_explicit(&ctx->ready, true, memory_order_release);
        ok = ahw_emit(protocol, ctx, onion);
    }
    bool expired = false;
    while (ok && tor_integration_is_enabled()) {
        int64_t now = 0;
        if (!ahw_clock(ctx, &now)) { ok = false; break; }
        if (now >= deadline) { expired = true; break; }
        platform_sleep_ms(100);
    }
    atomic_store_explicit(&ctx->ready, false, memory_order_release);
    tor_integration_stop(); return ok && expired;
}
struct ahw_args { uint64_t dev, ino, size, duration, deadline, parent; int64_t now; };
static bool ahw_deadline_valid(uint64_t deadline, uint64_t duration, int64_t now)
{
    return now > 0 && deadline > (uint64_t)now && deadline - (uint64_t)now <= duration &&
        deadline >= duration && deadline <= (uint64_t)INT64_MAX - 5000u &&
        (uint64_t)now >= deadline - duration;
}
static bool ahw_arguments(int argc, char **argv, struct ahw_args *out)
{
    uint64_t dev, ino, size, duration, deadline, parent;
    if (argc != 15 || strcmp(argv[1], "--app-host-worker") ||
        !an_scratch_decimal(argv[3], UINT64_MAX, &dev) || !an_scratch_decimal(argv[4], UINT64_MAX, &ino) ||
        !an_scratch_decimal(argv[10], VCS_BUNDLE_MAX_BYTES, &size) || !size ||
        !an_scratch_decimal(argv[11], 86400000u, &duration) || duration < 3000 ||
        !an_scratch_decimal(argv[12], INT64_MAX, &deadline) ||
        !an_scratch_decimal(argv[13], UINT64_MAX, &parent)) return false;
    int64_t now = platform_time_monotonic_ms();
    if (!ahw_deadline_valid(deadline, duration, now)) return false;
    *out = (struct ahw_args){dev, ino, size, duration, deadline, parent, now}; return true;
}

#endif

int app_host_worker_main(int argc, char **argv)
{
#if !defined(_WIN32)
    struct ahw_args args;
    if (!ahw_arguments(argc, argv, &args)) return 2;
    enum chain_network network;
    if (!an_scratch_chain_parse(argv[14], &network)) return 2;
    chain_params_select(network);
    uint64_t dev = args.dev, ino = args.ino, size = args.size, duration = args.duration;
    uint64_t deadline = args.deadline, parent = args.parent; int64_t now = args.now;
    int protocol = dup(STDOUT_FILENO);
    if (protocol < 0 || fcntl(protocol, F_SETFD, FD_CLOEXEC) != 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
        if (protocol >= 0) close(protocol);
        return 2;
    }
    struct app_network_lifeline guard;
    if (!app_host_lifeline_start(&guard, parent, (unsigned)(deadline - (uint64_t)now + 5000u))) { close(protocol); return 2; }
    struct ahw_context ctx = {0}; atomic_init(&ctx.ready, false);
    ctx.started_ms = (int64_t)(deadline - duration); ctx.deadline_ms = (int64_t)deadline; ctx.clock_last = now;
    bool initialized = pthread_mutex_init(&ctx.clock_mutex, NULL) == 0;
    bool ok = initialized && ahw_scratch(argv[2], dev, ino) && ahw_serve(&ctx, protocol, argv, size, (int64_t)deadline);
    if (initialized) (void)pthread_mutex_destroy(&ctx.clock_mutex);
    close(protocol);
    if (!app_network_lifeline_stop(&guard)) _exit(2);
    return ok ? APP_HOST_EXIT_EXPIRED : 2;
#else
    (void)argc; (void)argv; return 2;
#endif
}
