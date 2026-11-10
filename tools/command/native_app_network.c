/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Verify public app catalog frames and carrier bytes without RPC. */
#include "command/native_app_network.h"
#include "command/native_app_network_row.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "session/fleet_board_proto.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_manifest.h"
#include "util/thread_registry.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AN_JSON_CAP 65536u
#define AN_MANIFEST_CAP 8192u
#define AN_SLICE (48u * 1024u)
#define AN_FRAME_CAP (FLEET_BOARD_BODY_MAX + FLEET_BOARD_SIG_BYTES + 5u)
#define AN_MAX_REQUESTS 128u

struct an_run { const struct app_network_transport *t; int64_t deadline; unsigned calls; enum app_network_error *error; };
static bool an_tor_ready(const char *onion, const char *path, unsigned timeout_ms)
{
    return onion && strlen(onion) == 62u && vcs_app_offer_peer_is_onion(onion) &&
           path && timeout_ms && tor_integration_is_enabled() && tor_integration_is_dial_ready();
}
bool app_network_tor_fetch(void *context, const char *onion, const char *path,
    uint8_t *out, size_t cap, size_t *len, int *status, unsigned timeout_ms)
{
    (void)context;
    if (!len || !status) return false;
    *len = 0; *status = 0;
    if (!out || !an_tor_ready(onion, path, timeout_ms)) return false;
    struct onion_fetch_result result;
    unsigned seconds = (timeout_ms + 999u) / 1000u;
    int rc = tor_integration_fetch_onion_blocking(onion, path, &result, (int)seconds);
    bool ok = rc == 0 && result.body_len <= cap;
    if (ok && result.body_len && !result.body) ok = false;
    if (ok) { if (result.body_len) memcpy(out, result.body, result.body_len); *len = result.body_len; *status = result.status; }
    free(result.body); return ok;
}
static bool an_onion(const char *s)
{
    return s && strlen(s) == 62u && vcs_app_offer_peer_is_onion(s);
}
static bool an_begin(struct an_run *r, const struct app_network_transport *t,
                     enum app_network_error *error)
{
    if (!t || !t->fetch || !t->timeout_ms || t->timeout_ms > 120000u) return false;
    int64_t now = platform_time_monotonic_ms();
    if (now < 0 || now > INT64_MAX - (int64_t)t->timeout_ms) return false;
    *r = (struct an_run){.t = t, .deadline = now + (int64_t)t->timeout_ms, .error = error};
    return true;
}
static bool an_live(struct an_run *r)
{
    if (r->t->cancelled && r->t->cancelled(r->t->context)) {
        *r->error = APP_NETWORK_CANCELLED; return false;
    }
    int64_t now = platform_time_monotonic_ms();
    if (now < 0 || now >= r->deadline) { *r->error = APP_NETWORK_TIMEOUT; return false; }
    return true;
}
static bool an_fetch(struct an_run *r, const char *onion, const char *path,
                     uint8_t *out, size_t cap, size_t *len)
{
    *len = 0;
    if (!an_live(r)) return false;
    int64_t now = platform_time_monotonic_ms();
    if (now < 0 || now >= r->deadline) { *r->error = APP_NETWORK_TIMEOUT; return false; }
    if (!an_onion(onion) || r->calls >= AN_MAX_REQUESTS) return false;
    r->calls++;
    int status = 0;
    unsigned remaining = (unsigned)(r->deadline - now);
    bool ok = r->t->fetch(r->t->context, onion, path, out, cap, len, &status, remaining);
    if (!an_live(r)) return false;
    if (!ok || status != 200) { *r->error = APP_NETWORK_UNAVAILABLE; return false; }
    if (*len > cap) { *r->error = APP_NETWORK_INVALID_RESPONSE; return false; }
    return true;
}
static bool an_post_valid(const struct fleet_board_post *p, int64_t now)
{
    static const uint8_t zero[32];
    return fleet_board_post_validate(p) == FLEET_BOARD_OK &&
        fleet_board_post_check_time(p, now) == FLEET_BOARD_OK &&
        p->scope == FLEET_BOARD_SCOPE_PUBLIC && p->kind == FLEET_BOARD_KIND_OFFER &&
        !strcmp(p->room, ZCL_APP_OFFER_ROOM) && !p->slug[0] &&
        !p->title[0] && !memcmp(p->supersedes, zero, sizeof(zero));
}
static bool an_post(const char *hex, int64_t now, struct zcl_app_offer_row *row)
{
    uint8_t wire[AN_FRAME_CAP]; size_t len = 0;
    struct fleet_board_post *post = zcl_calloc(1, sizeof(*post), "app.network.post");
    if (!post) return false;
    size_t chars = hex ? strlen(hex) : 0;
    bool ok = chars && !(chars & 1u) && chars / 2u <= sizeof(wire);
    len = chars / 2u;
    ok = ok && zcl_hex_decode_lower(hex, wire, len) &&
        fleet_board_frame_decode_post(wire, len, post) == FLEET_BOARD_OK &&
        an_post_valid(post, now) &&
        zcl_app_offer_parse(post->text, post->text_len, &row->offer);
    if (ok) {
        fleet_board_id_to_hex(post->id, row->post_id);
        fleet_board_id_to_hex(post->host_pubkey, row->host);
        row->created_at = (int64_t)post->created_at;
    } else memset(row, 0, sizeof(*row));
    free(post);
    return ok;
}
/* The envelope is deliberately strict: duplicate/extra keys cannot redefine
 * the frame list or completeness flag. */
static bool an_envelope_keys(const struct json_value *doc)
{
    if (doc->type != JSON_OBJ || doc->num_children != 4 || !doc->keys) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < doc->num_children; i++) {
        const char *k = doc->keys[i]; unsigned bit = 0;
        if (!strcmp(k, "schema")) bit = 1;
        else if (!strcmp(k, "version")) bit = 2;
        else if (!strcmp(k, "frames")) bit = 4;
        else if (!strcmp(k, "incomplete")) bit = 8;
        if (!bit || (seen & bit)) return false;
        seen |= bit;
    }
    return seen == 15;
}
static bool an_envelope(const uint8_t *body, size_t len, struct json_value *doc,
                        const struct json_value **frames, bool *incomplete)
{
    if (!json_read(doc, (const char *)body, len) || !an_envelope_keys(doc)) return false;
    const struct json_value *s = json_get(doc, "schema"), *v = json_get(doc, "version");
    const struct json_value *f = json_get(doc, "frames"), *i = json_get(doc, "incomplete");
    if (!s || s->type != JSON_STR || strcmp(json_get_str(s), "zcl.board_apps.v1") ||
        !v || v->type != JSON_INT || json_get_int(v) != 1 || !f || f->type != JSON_ARR ||
        json_size(f) > 4 || !i || i->type != JSON_BOOL) return false;
    *frames = f; *incomplete = json_get_bool(i); return true;
}
static bool an_rows(const struct json_value *frames, int64_t now,
                    struct zcl_app_offer_row *rows, size_t *count,
                    bool *incomplete)
{
    bool filtered = false;
    for (size_t n = 0; n < json_size(frames); n++) {
        const struct json_value *frame = json_at(frames, n);
        if (!frame || frame->type != JSON_STR) return false;
        if (an_post(json_get_str(frame), now, &rows[*count])) (*count)++;
        else filtered = true;
    }
    if (filtered) *incomplete = true;
    return !json_size(frames) || *count;
}
static bool an_catalog(struct an_run *r, const char *onion, const char *path,
                       int64_t now, struct zcl_app_offer_row *rows, size_t cap,
                       size_t *count, bool *incomplete)
{
    uint8_t *body = zcl_malloc(AN_JSON_CAP, "app.network.catalog");
    if (!body) { *r->error = APP_NETWORK_UNAVAILABLE; return false; }
    size_t len = 0; struct json_value doc; json_init(&doc);
    const struct json_value *frames = NULL;
    bool fetched = an_fetch(r, onion, path, body, AN_JSON_CAP, &len);
    bool ok = fetched && an_envelope(body, len, &doc, &frames, incomplete) && json_size(frames) <= cap;
    if (ok) ok = an_rows(frames, now, rows, count, incomplete);
    if (fetched && !ok) *r->error = APP_NETWORK_INVALID_RESPONSE;
    json_free(&doc); free(body); return ok;
}
bool app_network_catalog(const struct app_network_transport *t, const char *onion,
    int64_t now, struct zcl_app_offer_row *rows, size_t cap, size_t *count, bool *incomplete,
    enum app_network_error *error)
{
    if (!count || !incomplete || !error) return false;
    *count = 0; *incomplete = false; *error = APP_NETWORK_INVALID_RESPONSE;
    struct an_run r;
    bool ok = rows && cap && an_begin(&r, t, error) &&
              an_catalog(&r, onion, "/board/apps/v1", now, rows, cap, count, incomplete) &&
              an_live(&r);
    if (!ok) { *count = 0; *incomplete = false; }
    else { if (*count == 4u) *incomplete = true; *error = APP_NETWORK_OK; }
    return ok;
}
static bool an_exact(struct an_run *r, const char *onion, const char *id, int64_t now,
                     struct zcl_app_offer_row *row)
{
    if (!vcs_app_offer_hex_valid(id, 32)) return false;
    char path[96]; (void)snprintf(path, sizeof(path), "/board/apps/v1/%s", id);
    size_t count = 0; bool incomplete = false;
    return an_catalog(r, onion, path, now, row, 1, &count, &incomplete) &&
           count == 1 && !incomplete && !strcmp(row->post_id, id);
}
bool app_network_exact(const struct app_network_transport *t, const char *onion,
                       const char *id, int64_t now, struct zcl_app_offer_row *row,
                       enum app_network_error *error)
{
    if (!row || !error) return false;
    *error = APP_NETWORK_INVALID_RESPONSE;
    memset(row, 0, sizeof(*row)); struct an_run r;
    bool ok = an_begin(&r, t, error) && an_exact(&r, onion, id, now, row) && an_live(&r);
    if (ok) *error = APP_NETWORK_OK; else memset(row, 0, sizeof(*row));
    return ok;
}
static bool an_row_bounded(const struct zcl_app_offer_row *r)
{
    const struct zcl_app_offer *o = &r->offer;
    return memchr(r->post_id, 0, sizeof(r->post_id)) && memchr(r->host, 0, sizeof(r->host)) &&
        memchr(o->name, 0, sizeof(o->name)) && memchr(o->root, 0, sizeof(o->root)) &&
        memchr(o->publisher, 0, sizeof(o->publisher)) && memchr(o->carrier, 0, sizeof(o->carrier)) &&
        memchr(o->sha256, 0, sizeof(o->sha256)) && memchr(o->onion, 0, sizeof(o->onion));
}
static bool an_manifest(struct an_run *r, const char *onion, const struct zcl_app_offer *o,
                        uint8_t root[32], struct vcs_package_manifest *m,
                        struct vcs_package_store *store, bool *mutated)
{
    char path[128]; (void)snprintf(path, sizeof(path), "/zcode/download/%s", o->carrier);
    uint8_t wire[AN_MANIFEST_CAP], derived[32], admitted[32]; size_t len = 0;
    if (!zcl_hex_decode_lower(o->carrier, root, 32) ||
        !an_fetch(r, onion, path, wire, sizeof(wire), &len) ||
        !vcs_package_manifest_parse(wire, len, m)) return false;
    if (!vcs_bundle_manifest_is_bundle(m) || m->files[0].size != (uint64_t)o->size ||
        !vcs_package_manifest_root(m, derived) || memcmp(root, derived, 32)) {
        *r->error = APP_NETWORK_CONTENT_MISMATCH; return false;
    }
    *mutated = true;
    bool ok = vcs_package_store_put_manifest_no_evict(store, wire, len, admitted) == VCS_PACKAGE_STORE_OK &&
              !memcmp(root, admitted, 32);
    if (!ok) *r->error = APP_NETWORK_STORE_REFUSED;
    return ok;
}

/* Only the owner reserves requests and touches store/error state. Workers own
 * disjoint output ranges and publish completion as their final access. */
#define AN_SLICE_BATCH 4u
struct an_slice_job {
    const struct app_network_transport *transport;
    const char *onion;
    char path[160];
    uint8_t *out;
    size_t want, got;
    int64_t deadline;
    int status;
    bool ok;
    atomic_bool done;
    pthread_t thread;
};
struct an_slice_batch { struct an_slice_batch *next; struct an_slice_job jobs[AN_SLICE_BATCH]; };
static _Atomic(struct an_slice_batch *) an_unjoined;
#if defined(ZCL_TESTING)
static int an_test_spawn_after = -1, an_test_join_after = -1;
void zcl_test_app_network_thread_faults(int spawn_after, int join_after)
{ an_test_spawn_after = spawn_after; an_test_join_after = join_after; }
#endif
static int an_slice_spawn(struct an_slice_job *j);
static void *an_slice_worker(void *context)
{
    struct an_slice_job *j = context;
    int64_t now = platform_time_monotonic_ms();
    if (now >= 0 && now < j->deadline)
        j->ok = j->transport->fetch(j->transport->context, j->onion, j->path,
            j->out, j->want, &j->got, &j->status, (unsigned)(j->deadline - now));
    atomic_store_explicit(&j->done, true, memory_order_release);
    return NULL;
}
static int an_slice_spawn(struct an_slice_job *j)
{
#if defined(ZCL_TESTING)
    if (an_test_spawn_after == 0) return EAGAIN;
    if (an_test_spawn_after > 0) an_test_spawn_after--;
#endif
    return thread_registry_spawn("app-slice", an_slice_worker, j, &j->thread);
}
static void an_keep_unjoined(struct an_slice_batch *b)
{
    struct an_slice_batch *old = atomic_load_explicit(&an_unjoined, memory_order_relaxed);
    do { b->next = old; } while (!atomic_compare_exchange_weak_explicit(&an_unjoined, &old, b,
        memory_order_release, memory_order_relaxed));
}
static bool an_slice_join(struct an_slice_batch *b, unsigned started)
{
    bool joined = true;
    for (unsigned i = 0; i < started; i++) {
        struct an_slice_job *j = &b->jobs[i];
        while (!atomic_load_explicit(&j->done, memory_order_acquire))
            platform_sleep_ms(10); /* real-clock: owned callback completion barrier */
        int rc; do { rc = pthread_join(j->thread, NULL); } while (rc == EINTR);
#if defined(ZCL_TESTING)
        if (!rc && an_test_join_after == 0) { rc = EINVAL; an_test_join_after = -1; }
        else if (an_test_join_after > 0) an_test_join_after--;
#endif
        if (rc) joined = false;
    }
    return joined;
}
static bool an_slice_prepare(struct an_run *r, struct an_slice_job *j, const char *onion,
    const struct zcl_app_offer *o, uint32_t index, size_t off, size_t size, uint8_t *chunk)
{
    if (!an_live(r)) return false;
    int64_t now = platform_time_monotonic_ms();
    if (now < 0 || now >= r->deadline) { *r->error = APP_NETWORK_TIMEOUT; return false; }
    if (!an_onion(onion) || r->calls >= AN_MAX_REQUESTS) return false;
    j->transport = r->t; j->onion = onion; j->out = chunk + off;
    j->want = size - off < AN_SLICE ? size - off : AN_SLICE;
    j->deadline = r->deadline;
    (void)snprintf(j->path, sizeof(j->path), "/zcode/download/%s/0/%u/slice/%zu", o->carrier, index, off);
    atomic_init(&j->done, false); r->calls++; return true;
}
static bool an_slice_batch_fetch(struct an_run *r, const char *onion, const struct zcl_app_offer *o,
    uint32_t index, size_t *off, size_t size, uint8_t *chunk)
{
    struct an_slice_batch *b = zcl_calloc(1, sizeof(*b), "app.network.slices");
    if (!b) { *r->error = APP_NETWORK_UNAVAILABLE; return false; }
    unsigned started = 0; bool launch_ok = true, spawn_failed = false;
    while (started < AN_SLICE_BATCH && *off < size) {
        struct an_slice_job *j = &b->jobs[started];
        if (!an_slice_prepare(r, j, onion, o, index, *off, size, chunk)) { launch_ok = false; break; }
        if (an_slice_spawn(j) != 0) { launch_ok = false; spawn_failed = true; break; }
        *off += j->want; started++;
    }
    bool joined = an_slice_join(b, started);
    bool live = an_live(r);
    bool ok = live && launch_ok && joined;
    if (live && (!joined || spawn_failed)) *r->error = APP_NETWORK_UNAVAILABLE;
    for (unsigned i = 0; ok && i < started; i++) {
        struct an_slice_job *j = &b->jobs[i];
        if (!j->ok || j->status != 200) { *r->error = APP_NETWORK_UNAVAILABLE; ok = false; }
        else if (j->got > j->want) { *r->error = APP_NETWORK_INVALID_RESPONSE; ok = false; }
        else if (j->got != j->want) ok = false;
    }
    if (joined) free(b); else an_keep_unjoined(b);
    return ok;
}
static bool an_chunks(struct an_run *r, const char *onion, const struct zcl_app_offer *o,
                      const struct vcs_package_manifest *m, const uint8_t root[32],
                      struct vcs_package_store *store)
{
    uint8_t *chunk = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "app.network.chunk");
    if (!chunk) { *r->error = APP_NETWORK_UNAVAILABLE; return false; }
    const struct vcs_package_file *file = &m->files[0]; bool ok = true;
    for (uint32_t i = 0; ok && i < file->chunk_count; i++) {
        size_t left = (size_t)file->size - (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t size = left < VCS_PACKAGE_CHUNK_BYTES ? left : VCS_PACKAGE_CHUNK_BYTES;
        for (size_t off = 0; ok && off < size;) {
            if (r->t->parallel_safe) { ok = an_slice_batch_fetch(r, onion, o, i, &off, size, chunk); continue; }
            char path[160]; size_t got = 0;
            (void)snprintf(path, sizeof(path), "/zcode/download/%s/0/%u/slice/%zu", o->carrier, i, off);
            size_t want = size - off < AN_SLICE ? size - off : AN_SLICE;
            ok = an_fetch(r, onion, path, chunk + off, want, &got) && got == want;
            off += want;
        }
        if (ok && !vcs_package_verify_chunk(file, i, chunk, size)) {
            *r->error = APP_NETWORK_CONTENT_MISMATCH; ok = false;
        }
        if (ok && vcs_package_store_put_chunk_no_evict(store, root, VCS_BUNDLE_PATH, i, chunk, size) != VCS_PACKAGE_STORE_OK) {
            *r->error = APP_NETWORK_STORE_REFUSED; ok = false;
        }
    }
    free(chunk); return ok;
}
static bool an_output(struct an_run *r, struct vcs_package_store *store, const uint8_t root[32],
                      const struct zcl_app_offer *offer, uint8_t **bytes, size_t *len)
{
    uint8_t *out = zcl_malloc((size_t)offer->size, "app.network.carrier");
    if (!out) { *r->error = APP_NETWORK_UNAVAILABLE; return false; }
    size_t got = 0; uint8_t hash[32], expected[32]; struct sha256_ctx sha;
    bool ok = vcs_bundle_get_from(store, root, out, (size_t)offer->size, &got) == VCS_BUNDLE_OK &&
        got == (size_t)offer->size && zcl_hex_decode_lower(offer->sha256, expected, 32);
    if (ok) { sha256_init(&sha); sha256_write(&sha, out, got); sha256_finalize(&sha, hash); ok = !memcmp(hash, expected, 32); }
    if (!ok) { *r->error = APP_NETWORK_CONTENT_MISMATCH; free(out); return false; }
    *bytes = out; *len = got; return true;
}
static bool an_carrier_fetch(struct an_run *r, const char *onion,
    const struct zcl_app_offer_row *row, struct vcs_package_store *store,
    uint8_t **bytes, size_t *len, bool *mutated)
{
    struct vcs_package_manifest m; vcs_package_manifest_init(&m); uint8_t root[32];
    bool ok = an_manifest(r, onion, &row->offer, root, &m, store, mutated) &&
              an_chunks(r, onion, &row->offer, &m, root, store) && an_live(r) &&
              an_output(r, store, root, &row->offer, bytes, len);
    vcs_package_manifest_free(&m);
    if (ok && !an_live(r)) { free(*bytes); *bytes = NULL; *len = 0; ok = false; }
    if (ok) *r->error = APP_NETWORK_OK;
    else if (*r->error == APP_NETWORK_INVALID_RESPONSE && *mutated) *r->error = APP_NETWORK_CONTENT_MISMATCH;
    return ok;
}
bool app_network_carrier(const struct app_network_transport *t, const char *catalog_onion,
    const char *carrier_onion, const struct zcl_app_offer_row *selected, int64_t now,
    struct vcs_package_store *store, uint8_t **bytes, size_t *len, bool *mutated,
    enum app_network_error *error)
{
    if (!bytes || !len || !mutated || !error) return false;
    *bytes = NULL; *len = 0; *mutated = false; *error = APP_NETWORK_INVALID_RESPONSE;
    struct an_run r; struct zcl_app_offer_row actual = {0};
    if (!selected || !an_row_bounded(selected) || !store || !an_onion(carrier_onion) || !an_begin(&r, t, error) ||
        !an_exact(&r, catalog_onion, selected->post_id, now, &actual)) return false;
    if (!app_network_row_equal(selected, &actual)) { *error = APP_NETWORK_CHANGED_OFFER; return false; }
    return an_carrier_fetch(&r, carrier_onion, &actual, store, bytes, len, mutated);
}
