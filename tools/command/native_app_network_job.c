/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Fixed child, bounded capture, parent-side verification; no shell. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_app_network_job.h"
#include "command/native_app_scratch.h"
#include "command/native_app_network_link.h"
#include "command/native_app_network_row.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "vcs/bundle_carry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#if !defined(_WIN32)
/* One complete carrier hex plus small fixed envelope. Exact capture detects
 * overflow and EOF; the spare byte is only for a local JSON terminator. */
#define ANJ_WIRE_MAX (2u * VCS_BUNDLE_MAX_BYTES + APP_NETWORK_FRAME_HEX_CAP + 4096u)
static bool anj_selected_bounded(const struct zcl_app_offer_row *r)
{
    if (!r) return false;
    const struct zcl_app_offer *o = &r->offer;
    return memchr(r->post_id, 0, sizeof(r->post_id)) && memchr(r->host, 0, sizeof(r->host)) &&
        memchr(o->name, 0, sizeof(o->name)) && memchr(o->root, 0, sizeof(o->root)) &&
        memchr(o->publisher, 0, sizeof(o->publisher)) && memchr(o->carrier, 0, sizeof(o->carrier)) &&
        memchr(o->sha256, 0, sizeof(o->sha256)) && memchr(o->onion, 0, sizeof(o->onion));
}
static bool anj_row_arg(const struct zcl_app_offer_row *r, char *out, size_t cap)
{
    if (!anj_selected_bounded(r)) return false;
    char offer[ZCL_APP_OFFER_TEXT_MAX + 1];
    struct json_value v; json_init(&v); json_set_object(&v);
    bool ok = zcl_app_offer_format(&r->offer, offer, sizeof(offer)) &&
        json_push_kv_str(&v, "post_id", r->post_id) && json_push_kv_str(&v, "host", r->host) &&
        json_push_kv_int(&v, "created_at", r->created_at) && json_push_kv_str(&v, "offer", offer);
    size_t n = ok ? json_write(&v, out, cap) : cap;
    json_free(&v); return n < cap;
}
static bool anj_carrier(const struct json_value *d, const struct zcl_app_offer_row *selected,
                        struct app_network_job_result *r)
{
    const struct json_value *size = json_get(d, "size"), *hex = json_get(d, "carrier_hex");
    if (!selected || selected->offer.size <= 0 || !size || size->type != JSON_INT || json_get_int(size) != selected->offer.size ||
        !hex || hex->type != JSON_STR) return false;
    size_t len = (size_t)selected->offer.size; const char *text = json_get_str(hex);
    if (!len || len > VCS_BUNDLE_MAX_BYTES || strlen(text) != len * 2u) return false;
    uint8_t *bytes = zcl_malloc(len, "network.job.carrier"); if (!bytes) return false;
    uint8_t hash[32], expected[32]; struct sha256_ctx sha;
    bool ok = zcl_hex_decode_lower(text, bytes, len) && zcl_hex_decode_lower(selected->offer.sha256, expected, 32);
    if (ok) { sha256_init(&sha); sha256_write(&sha, bytes, len); sha256_finalize(&sha, hash); ok = !memcmp(hash, expected, 32); }
    if (!ok) { free(bytes); return false; }
    r->bytes = bytes; r->len = len; return true;
}
static bool anj_envelope(const struct json_value *v)
{
    const char *schema = app_network_json_string(v, "schema"); const struct json_value *ok = json_get(v, "ok");
    return v->type == JSON_OBJ && v->keys && schema && !strcmp(schema, "zcl.app_network_worker.v1") &&
        ok && ok->type == JSON_BOOL;
}
static bool anj_rows(const struct json_value *v, struct app_network_job_result *r)
{
    const struct json_value *rows = json_get(v, "rows"), *incomplete = json_get(v, "incomplete");
    if (v->num_children != 4 || !rows || rows->type != JSON_ARR || json_size(rows) > 4 ||
        !incomplete || incomplete->type != JSON_BOOL) return false;
    r->count = json_size(rows); r->incomplete = json_get_bool(incomplete);
    for (size_t i = 0; i < r->count; i++) if (!app_network_row_decode(json_at(rows, i), &r->rows[i])) return false;
    return true;
}
static bool anj_exact(const struct app_network_job_args *a, const struct app_network_job_result *r)
{
    if (strcmp(a->mode, "exact")) return true;
    struct app_network_link link;
    return app_network_link_parse(a->url, &link) && link.exact && r->count == 1 &&
        !r->incomplete && !strcmp(r->rows[0].post_id, link.post_id);
}
static bool anj_direct(const struct json_value *v, const struct app_network_job_args *a,
                       struct app_network_job_result *r)
{
    struct app_network_link link; struct zcl_app_offer_row row = {0};
    const char *frame = app_network_json_string(v, "frame");
    size_t n = frame ? strlen(frame) : 0;
    if (v->num_children != 5 || !n || n >= sizeof(r->frame) ||
        !app_network_link_parse(a->url, &link) || !link.exact ||
        !app_network_frame_row(frame, link.post_id, platform_time_wall_unix(), &row) ||
        !anj_carrier(v, &row, r)) return false;
    memcpy(r->frame, frame, n + 1u); r->rows[0] = row; r->count = 1;
    return true;
}
static void anj_error(const struct json_value *v, struct app_network_job_result *r)
{
    const struct json_value *e = json_get(v, "error");
    if (v->num_children == 3 && e && e->type == JSON_INT && json_get_int(e) >= APP_NETWORK_CANCELLED &&
        json_get_int(e) <= APP_NETWORK_STORE_REFUSED) r->error = (enum app_network_error)json_get_int(e);
}
static bool anj_parse(const char *wire, size_t len, const struct app_network_job_args *args,
    struct app_network_job_result *r)
{
    struct json_value v; json_init(&v);
    bool ok = json_read(&v, wire, len) && app_network_json_canonical(&v, wire, len) && anj_envelope(&v);
    if (ok && !json_get_bool(json_get(&v, "ok"))) { anj_error(&v, r); ok = false; }
    else if (ok && !strcmp(args->mode, "carrier")) ok = v.num_children == 4 && anj_carrier(&v, args->selected, r);
    else if (ok && !strcmp(args->mode, "direct")) ok = anj_direct(&v, args, r);
    else if (ok) ok = anj_rows(&v, r) && anj_exact(args, r);
    json_free(&v); if (ok) r->error = APP_NETWORK_OK; return ok;
}
#if defined(ZCL_TESTING)
bool zcl_test_app_network_job_parse(const char *wire, size_t len,
    const struct app_network_job_args *args, struct app_network_job_result *result)
{
    return wire && len && len < ANJ_WIRE_MAX && args && result && !memchr(wire, 0, len) &&
        anj_parse(wire, len, args, result);
}
#endif
static bool anj_mode_matches(const struct app_network_job_args *a, const struct app_network_link *link)
{
    if (!strcmp(a->mode, "catalog")) return !link->exact;
    if (!strcmp(a->mode, "exact") || !strcmp(a->mode, "direct")) return link->exact;
    if (strcmp(a->mode, "carrier") || !link->exact || !anj_selected_bounded(a->selected)) return false;
    return !strcmp(a->selected->post_id, link->post_id);
}
static bool anj_valid_args(const struct app_network_job_args *a)
{
    if (!a || !a->mode || !a->url || !a->scratch || !an_scratch_chain_token(a->network) ||
        !a->timeout_ms || a->timeout_ms > 120000u) return false;
    struct app_network_link link;
    return app_network_link_parse(a->url, &link) && anj_mode_matches(a, &link);
}
static bool anj_capture(const struct app_network_job_args *a, const char *const argv[],
    struct app_network_job_result *r)
{
    char *wire = zcl_malloc(ANJ_WIRE_MAX + 1u, "network.job.capture"); if (!wire) return false;
    struct zcl_spawn_measure measure = {0}; struct zcl_spawn_binary_observation observed = {0};
    bool cancelled = false;
    struct zcl_result capture = zcl_spawn_capture_binary_cancelable_measured(argv, wire,
        ANJ_WIRE_MAX, (int)a->timeout_ms + 15000, a->cancel, a->cancel_context,
        &cancelled, &observed, &measure);
    r->launched = measure.launched; r->reaped = measure.reaped; r->cancelled = cancelled;
    size_t n = observed.output_len;
    bool ok = capture.ok && n < ANJ_WIRE_MAX && !memchr(wire, 0, n);
    if (ok) { wire[n] = 0; ok = anj_parse(wire, n, a, r); }
    if (cancelled) r->error = APP_NETWORK_CANCELLED;
    free(wire); return ok;
}


#endif

bool app_network_job_run(const struct app_network_job_args *a, struct app_network_job_result *r)
{
#if !defined(_WIN32)
    if (!r) return false;
    memset(r, 0, sizeof(*r)); r->error = APP_NETWORK_UNAVAILABLE;
    if (!anj_valid_args(a)) return false;
    char self[4096], row[4097] = "-", dev[32], ino[32], port[16], timeout[16], parent[32];
    if (!os_proc_self_exe_open_path(self, sizeof(self))) return false;
    if (a->selected && !anj_row_arg(a->selected, row, sizeof(row))) return false;
    snprintf(dev, sizeof(dev), "%llu", (unsigned long long)a->scratch_dev);
    snprintf(ino, sizeof(ino), "%llu", (unsigned long long)a->scratch_ino);
    snprintf(port, sizeof(port), "%u", a->bootstrap_port);
    snprintf(timeout, sizeof(timeout), "%u", a->timeout_ms);
    snprintf(parent, sizeof(parent), "%llu", (unsigned long long)getpid());
    const char *argv[] = {self, "--app-network-worker", a->mode, a->url,
        a->carrier_onion ? a->carrier_onion : "-", row, a->scratch, dev, ino, port, timeout, "v1", parent,
        an_scratch_chain_token(a->network), NULL};
    return anj_capture(a, argv, r);
#else
    (void)a; if (r) { memset(r, 0, sizeof(*r)); r->error = APP_NETWORK_UNAVAILABLE; } return false;
#endif
}
