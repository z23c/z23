/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Verify one host's signed readiness before exposing its link. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_app_host_job.h"
#include "command/native_app_host_worker.h"
#include "base/hex.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"
#include "vcs/app_offer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>

#define AHJ_WIRE_MAX 8192u
struct ahj_stream {
    const struct app_host_job_args *args;
    app_host_ready_fn callback; app_host_unavailable_fn unavailable; void *context;
    struct app_host_job_result *result;
    char wire[AHJ_WIRE_MAX]; size_t used;
    bool invalid, callback_refused, ended_after_stop;
};
static bool ahj_field(const char *s, size_t n, size_t expected)
{
    return s && strnlen(s, n) == expected;
}
static bool ahj_identity_args(const struct app_host_job_args *a)
{
    return a->name && strnlen(a->name, 160) < 160 && a->name[0] &&
        ahj_field(a->release_root, 65, 64) && ahj_field(a->package_root, 65, 64) && ahj_field(a->publisher, 67, 66) &&
        ahj_field(a->carrier_sha256, 65, 64);
}
static bool ahj_args(const struct app_host_job_args *a)
{
    return a && a->self_path && a->self_path[0] == '/' && a->scratch_path && a->scratch_path[0] == '/' &&
        app_host_chain_token(a->network) && ahj_identity_args(a) && a->carrier_size > 0 && a->carrier_size <= ZCL_APP_OFFER_SIZE_MAX &&
        a->duration_ms >= 3000 && a->duration_ms <= 86400000u;
}
static bool ahj_offer_matches(const struct zcl_app_offer *offer, const char *onion,
                              const struct app_host_job_args *args)
{
    return !strcmp(offer->onion, onion) && !strcmp(offer->name, args->name) &&
        !strcmp(offer->root, args->package_root) && !strcmp(offer->publisher, args->publisher) &&
        !strcmp(offer->sha256, args->carrier_sha256) && offer->size == (int64_t)args->carrier_size;
}
static bool ahj_decode_post(const char *hex, size_t len, struct fleet_board_post *post)
{
    uint8_t frame[AHJ_WIRE_MAX / 2u];
    return zcl_hex_decode_lower(hex, frame, len / 2u) &&
        fleet_board_frame_decode_post(frame, len / 2u, post) == FLEET_BOARD_OK &&
        post->scope == FLEET_BOARD_SCOPE_PUBLIC && post->kind == FLEET_BOARD_KIND_OFFER &&
        !strcmp(post->room, "apps") && fleet_board_post_check_time(post, platform_time_wall_unix()) == FLEET_BOARD_OK;
}
static bool ahj_ready(struct ahj_stream *s)
{
    static const char prefix[] = "zcl-app-host-v1 ";
    size_t prefix_len = sizeof(prefix)-1;
    if (s->used <= prefix_len + 62 || memcmp(s->wire, prefix, prefix_len)) return false;
    char *onion = s->wire + prefix_len;
    if (onion[62] != ' ') return false;
    onion[62] = 0;
    if (!vcs_app_offer_peer_is_onion(onion)) return false;
    const char *hex = onion + 63; size_t hex_len = s->used - prefix_len - 63;
    if (!hex_len || (hex_len & 1u) || hex_len / 2u > AHJ_WIRE_MAX / 2u) return false;
    struct fleet_board_post post = {0};
    if (!ahj_decode_post(hex, hex_len, &post)) return false;
    struct zcl_app_offer offer;
    if (!zcl_app_offer_parse(post.text, post.text_len, &offer) ||
        !ahj_offer_matches(&offer, onion, s->args)) return false;
    struct app_host_ready ready = {0};
    memcpy(ready.onion, onion, 63); zcl_hex_encode(post.id, 32, ready.post_id);
    memcpy(ready.carrier_root, offer.carrier, 65); memcpy(ready.carrier_sha256, offer.sha256, 65);
    memcpy(ready.release_root, s->args->release_root, 65); memcpy(ready.package_root, offer.root, 65); memcpy(ready.publisher, offer.publisher, 67);
    ready.carrier_size = (uint64_t)offer.size;
    if (!s->callback(&ready, s->context)) { s->callback_refused = true; return false; }
    s->result->ready = true; return true;
}
static void ahj_end(void *ctx)
{
    struct ahj_stream *s = ctx;
    s->ended_after_stop = s->args->cancel && s->args->cancel(s->args->cancel_context);
    if (s->unavailable) s->unavailable(s->context);
}
static bool ahj_observe(const void *data, size_t len, void *ctx)
{
    struct ahj_stream *s = ctx;
    if (s->result->ready || len > sizeof(s->wire) - 1u - s->used) {
        s->invalid = true;
        if (s->unavailable) s->unavailable(s->context);
        return false;
    }
    const char *bytes = data;
    for (size_t i = 0; i < len; i++) {
        if (!bytes[i] || (bytes[i] == '\n' && i + 1u != len)) {
            s->invalid = true;
            if (s->unavailable) s->unavailable(s->context);
            return false;
        }
        if (bytes[i] == '\n') {
            s->wire[s->used] = 0;
            bool ok = ahj_ready(s);
            if (!ok && !s->callback_refused) s->invalid = true;
            return ok;
        }
        s->wire[s->used++] = bytes[i];
    }
    return true;
}
#if defined(ZCL_TESTING)
static bool ahj_test_ready(const struct app_host_ready *ready, void *ctx)
{ *(struct app_host_ready *)ctx = *ready; return true; }
bool zcl_test_app_host_ready(const struct app_host_job_args *a, const void *bytes,
    size_t len, size_t split, struct app_host_ready *ready)
{
    if (!a || !bytes || !ready || split > len) return false;
    struct app_host_job_result result = {0};
    struct ahj_stream stream = {.args = a, .callback = ahj_test_ready,
        .context = ready, .result = &result};
    const char *data = bytes;
    if (split && !ahj_observe(data, split, &stream)) return false;
    if (split < len && !ahj_observe(data + split, len - split, &stream)) return false;
    return result.ready;
}
#endif
static void ahj_result(struct app_host_job_result *result, const struct ahj_stream *stream,
    const struct zcl_spawn_binary_observation *out, const struct zcl_spawn_measure *m, bool refused)
{
    result->launched = m->launched; result->reaped = m->reaped;
    bool stopped = stream->ended_after_stop;
    result->cancelled = stopped; result->invalid_frame = stream->invalid || out->overflow;
    result->timed_out = out->timed_out;
    /* Readiness is historical; only the worker's reserved normal-expiry exit
     * distinguishes expiry from an unexpected exit. */
    if (!result->invalid_frame && m->reaped && stopped) result->outcome = APP_HOST_STOPPED;
    else if (!refused && !stopped && m->reaped && out->eof && !out->overflow &&
             !out->timed_out && out->exit_observed && out->exit_code == APP_HOST_EXIT_EXPIRED)
        result->outcome = APP_HOST_EXPIRED;
    else result->outcome = APP_HOST_FAILED;
}

#endif

bool app_host_job_run(const struct app_host_job_args *a, app_host_ready_fn ready,
                      app_host_unavailable_fn unavailable, void *ctx, struct app_host_job_result *result)
{
#if !defined(_WIN32)
    if (!result) return false;
    memset(result, 0, sizeof(*result));
    if (!ready || !unavailable || !ahj_args(a)) return false;
    int64_t start = platform_time_monotonic_ms();
    if (start <= 0 || start > INT64_MAX - (int64_t)a->duration_ms) return false;
    int64_t service_deadline = a->service_deadline_ms ? a->service_deadline_ms : start + a->duration_ms;
    if (service_deadline <= start || service_deadline - start > (int64_t)a->duration_ms ||
        start < service_deadline - (int64_t)a->duration_ms) return false;
    char dev[32], ino[32], size[32], duration[32], deadline[32], parent[32];
    (void)snprintf(dev, sizeof(dev), "%llu", (unsigned long long)a->scratch_dev);
    (void)snprintf(ino, sizeof(ino), "%llu", (unsigned long long)a->scratch_ino);
    (void)snprintf(size, sizeof(size), "%llu", (unsigned long long)a->carrier_size);
    (void)snprintf(duration, sizeof(duration), "%u", a->duration_ms);
    (void)snprintf(deadline, sizeof(deadline), "%llu", (unsigned long long)service_deadline);
    (void)snprintf(parent, sizeof(parent), "%llu", (unsigned long long)getpid());
    const char *argv[] = {a->self_path, "--app-host-worker", a->scratch_path, dev, ino,
        a->name, a->release_root, a->package_root, a->publisher, a->carrier_sha256, size, duration, deadline, parent,
        app_host_chain_token(a->network), NULL};
    char bytes[AHJ_WIRE_MAX]; bool canceled = false, refused = false;
    struct zcl_spawn_binary_observation out = {0}; struct zcl_spawn_measure m = {0};
    struct ahj_stream stream = {.args = a, .callback = ready, .unavailable = unavailable, .context = ctx, .result = result};
    struct zcl_result r = zcl_spawn_capture_binary_observe(argv, bytes, sizeof(bytes),
        (int)(a->duration_ms + 6000u), a->cancel, a->cancel_context, &canceled,
        ahj_observe, ahj_end, &stream, &refused, &out, &m);
    unavailable(ctx); /* observed termination or capture failure retracts the link */
    ahj_result(result, &stream, &out, &m, refused);
    (void)r; /* exact capture correctly reports the reserved nonzero exit */
    return result->ready && result->outcome == APP_HOST_EXPIRED;
#else
    (void)a; (void)ready; (void)unavailable; (void)ctx; if (result) memset(result, 0, sizeof(*result)); return false;
#endif
}
