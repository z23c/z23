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
#include "config/cli_lane_defaults.h"
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

/* The datadir the node rows read. An explicit one (options->datadir, or the
 * process's -datadir/ZCL_DATADIR) wins. With none, the product's own default
 * stands: this binary's lane default (the dev lane's own, when no node runs
 * there, is not the canonical node) is replaced by the release default
 * `z23 status` reads, through the same cli_lane_defaults.h resolver. A
 * datadir the process resolved some other way is kept. `buf` holds the path
 * when one is built; the result is NULL when nothing resolves. */
static const char *obj_node_target(const struct zcl_objectives_options *options,
                                   char *buf, size_t cap)
{
    const char *bound = zcl_native_command_datadir();
    const char *home = getenv("HOME");
    char lane[512];
    if (options && options->datadir && options->datadir[0])
        return options->datadir;
    if (zcl_native_command_datadir_is_explicit())
        return bound;
    if (!home || !home[0])
        return bound;
    if (bound && bound[0] &&
        !(zcl_cli_lane_default_datadir(lane, sizeof(lane), home) &&
          strcmp(bound, lane) == 0))
        return bound;
    return zcl_cli_release_default_datadir(buf, cap, home) ? buf : NULL;
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
        char target_buf[512], bound[512];
        const char *target = obj_node_target(options, target_buf,
                                             sizeof(target_buf));
        const char *now = zcl_native_command_datadir();
        int bound_port = zcl_native_command_rpc_port();
        bool rebind = target && target[0] && strcmp(target, now) != 0 &&
                      !(options && options->datadir);
        memset(&err, 0, sizeof(err));
        /* The call is synchronous: bind the target for it, then give the
         * process back the target it had, so no other row sees the change. */
        (void)snprintf(bound, sizeof(bound), "%s", now);
        if (rebind)
            zcl_native_bridge_bind_rpc(target, ZCL_CLI_RELEASE_RPC_PORT);
        raw = (options && options->node_budget_ms > 0)
                  ? zcl_native_status_brief_body_within(
                        options->node_budget_ms, &err)
                  : zcl_native_status_brief_body(NULL, &err);
        if (rebind)
            zcl_native_bridge_bind_rpc(bound, bound_port);
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
    char target_buf[512];
    const char *datadir = obj_node_target(options, target_buf,
                                          sizeof(target_buf));
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
