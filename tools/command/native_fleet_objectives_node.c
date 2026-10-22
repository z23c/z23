/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The PRODUCT producers behind `fleet.objectives` — what the
 *          running node itself measures about itself: resident memory and
 *          tip lag from the same status brief `z23 status` prints, and the
 *          seconds from process start to serving from the datadir's
 *          boot_status.json beacon. Read-only, no new RPC client, and a
 *          node that is down or silent is unmeasured with the reason, never
 *          a fabricated number.
 *
 * Tests never need a live node: options->brief names a file holding a
 * status-brief document that is read instead of asking the node, and
 * options->datadir names the datadir the beacon is read from. */

#include "native_fleet_objectives.h"

#include "base/safe_alloc.h"
#include "controllers/native_handler_body.h"
#include "controllers/status_native_handlers.h"
#include "json/json.h"
#include "util/boot_status.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBJ_NODE_DOC_MAX (256u * 1024u)

static void obj_node_reason(struct zcl_objective_value *v, const char *what,
                            const char *detail)
{
    v->measured = false;
    (void)snprintf(v->reason, sizeof(v->reason), "%s%s%s", what,
                   detail && detail[0] ? ": " : "", detail ? detail : "");
}

/* The whole fixture file, NUL-terminated, or NULL. Bounded. */
static char *obj_node_read_file(const char *path, size_t *len_out)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    size_t got;
    if (!fp)
        return NULL;
    buf = zcl_malloc(OBJ_NODE_DOC_MAX + 1u, "fleet_objectives_node_doc");
    if (!buf) {
        (void)fclose(fp);
        return NULL;
    }
    got = fread(buf, 1, OBJ_NODE_DOC_MAX + 1u, fp);
    if (ferror(fp) || got > OBJ_NODE_DOC_MAX) {
        free(buf);
        (void)fclose(fp);
        return NULL;
    }
    (void)fclose(fp);
    buf[got] = '\0';
    *len_out = got;
    return buf;
}

/* The status brief's raw text, a malloc'd string: from options->brief when
 * named, else from the node through the same body `z23 status` runs, within
 * options->node_budget_ms when one is set. NULL, with the reason in v, when
 * none can be had. */
static char *obj_node_fetch(const struct zcl_objectives_options *options,
                            struct zcl_objective_value *v)
{
    char *raw;
    size_t len = 0;
    if (options && options->brief) {
        raw = obj_node_read_file(options->brief, &len);
        if (!raw)
            obj_node_reason(v, "cannot read the status brief", options->brief);
    } else {
        struct zcl_native_body_err err;
        memset(&err, 0, sizeof(err));
        raw = (options && options->node_budget_ms > 0)
                  ? zcl_native_status_brief_body_within(
                        options->node_budget_ms, &err)
                  : zcl_native_status_brief_body(NULL, &err);
        if (!raw)
            obj_node_reason(v, "no node answered the status brief", "");
    }
    return raw;
}

void zcl_objectives_node_cache_free(struct zcl_objectives_node_cache *cache)
{
    if (!cache)
        return;
    free(cache->raw);
    cache->raw = NULL;
    cache->filled = false;
}

/* The status brief as a parsed object. With a node cache the node is asked
 * once per run and a failure is remembered too, so a down node costs one
 * wait and one log line, not one per row. False, with the reason in v, when
 * no object can be had. */
static bool obj_node_brief(const struct zcl_objectives_options *options,
                           struct json_value *doc,
                           struct zcl_objective_value *v)
{
    struct zcl_objectives_node_cache *cache =
        options ? options->node_cache : NULL;
    char *own = NULL;
    const char *raw;
    bool ok;
    if (cache) {
        if (!cache->filled) {
            cache->raw = obj_node_fetch(options, v);
            cache->filled = true;
            cache->fetches++;
        }
        raw = cache->raw;
    } else {
        own = obj_node_fetch(options, v);
        raw = own;
    }
    if (!raw) {
        if (!v->reason[0])
            obj_node_reason(v, "no node answered the status brief", "");
        return false;
    }
    json_init(doc);
    ok = json_read(doc, raw, strlen(raw)) && doc->type == JSON_OBJ;
    free(own);
    if (!ok) {
        json_free(doc);
        obj_node_reason(v, "the status brief is not a JSON object", "");
    }
    return ok;
}

/* A non-negative integer field; false when absent or not an integer. */
static bool obj_node_int(const struct json_value *doc, const char *key,
                         int64_t *out)
{
    const struct json_value *f = json_get(doc, key);
    if (!f || f->type != JSON_INT || json_get_int(f) < 0)
        return false;
    *out = json_get_int(f);
    return true;
}

struct zcl_objective_value zcl_objectives_node_rss_mb(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct json_value doc;
    int64_t rss;
    if (!obj_node_brief(options, &doc, &v))
        return v;
    if (!obj_node_int(&doc, "rss_mb", &rss)) {
        obj_node_reason(&v, "the node did not report rss_mb", "");
    } else {
        v.measured = true;
        v.value = rss;
    }
    json_free(&doc);
    return v;
}

/* Blocks the served tip trails the best height the node knows: the larger of
 * its header height and the best peer's tip, minus the served height. When
 * the node names no served height or no reference, its own `gap` stands. */
static bool obj_node_lag(const struct json_value *doc, int64_t *lag)
{
    int64_t served, header = -1, peer = -1, gap, best;
    bool have_served = obj_node_int(doc, "hstar", &served);
    bool have_header = obj_node_int(doc, "header_height", &header);
    bool have_peer = obj_node_int(doc, "peer_best", &peer);
    if (have_served && (have_header || have_peer)) {
        best = header > peer ? header : peer;
        *lag = best > served ? best - served : 0;
        return true;
    }
    if (obj_node_int(doc, "gap", &gap)) {
        *lag = gap;
        return true;
    }
    return false;
}

struct zcl_objective_value zcl_objectives_node_tip_lag_blocks(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct json_value doc;
    int64_t lag;
    if (!obj_node_brief(options, &doc, &v))
        return v;
    if (!obj_node_lag(&doc, &lag)) {
        obj_node_reason(&v, "the node named no served tip to compare", "");
    } else {
        v.measured = true;
        v.value = lag;
    }
    json_free(&doc);
    return v;
}

struct zcl_objective_value zcl_objectives_node_warm_restart_s(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    struct boot_status_snapshot snap;
    char why[192];
    const char *datadir = options && options->datadir
                              ? options->datadir
                              : zcl_native_command_datadir();
    if (!datadir || !datadir[0]) {
        obj_node_reason(&v, "no datadir to read the boot beacon from", "");
        return v;
    }
    if (!boot_status_read(datadir, &snap, why, sizeof(why))) {
        obj_node_reason(&v, "no readable boot beacon", "");
        return v;
    }
    if (!snap.serving) {
        obj_node_reason(&v, "the latest boot has not reached serving; stage",
                        snap.stage);
        return v;
    }
    v.measured = true;
    v.value = snap.elapsed_s;
    return v;
}
