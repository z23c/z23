/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: lab.brief - "where is the lab right now?" in one bounded
 *          JSON object, composed from existing leaves only.
 *
 * WHAT IT IS. A read-only composition. It owns no state: every section names
 * the leaf (or the git object) it was read from, and a section whose source
 * fails is a typed {"unavailable":{"code","why"}} field, never a crash and
 * never a guess.
 *
 *   node       core.status.brief            tip, gap, sync, peers
 *   land       dev.land.status              queued, in flight, last landed,
 *                                           last failure
 *   plan       docs/work/FORWARD_PLAN.md    first three "Now" titles at HEAD
 *   agents     dev.agent.queue (status)     queued and running units
 *   deadlines  ops.mesh.device.pair.status  soonest pairing expiry
 *   next       derived from the sections above: one command
 *
 * BUDGET. The data object is at most ZCL_DAB_DATA_CAP bytes (the leaf's
 * response budget of 2048 bytes covers the whole envelope). Every string is
 * clipped to printable ASCII with no quote or backslash, to a per-field cap,
 * and a clipped string ends in "..." so the cut is visible. The per-field
 * caps are chosen so the worst case fits; the final size check is a
 * fail-closed guard (BRIEF_OVER_BUDGET), not a trimming step.
 */

#include "command/native_devagent_brief.h"

#include "base/safe_alloc.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZCL_DAB_LEAF "lab.brief"
#define ZCL_DAB_DATA_CAP 1536
#define ZCL_DAB_PLAN_ITEMS 3
#define ZCL_DAB_PLAN_PATH "docs/work/FORWARD_PLAN.md"
#define ZCL_DAB_PLAN_CAP (96 * 1024)
#define ZCL_DAB_SUB_CAP (72 * 1024)
#define ZCL_DAB_TIP 12
#define ZCL_DAB_TS 25
#define ZCL_DAB_STATE 12
#define ZCL_DAB_REASON 100
#define ZCL_DAB_TITLE 110
#define ZCL_DAB_WHY 80
#define ZCL_DAB_WORD 20

static const char *const k_dab_leaf[ZCL_BRIEF_SOURCE_COUNT] = {
    "core.status.brief", "dev.land.status", ZCL_DAB_PLAN_PATH "@HEAD",
    "dev.agent.queue", "ops.mesh.device.pair.status"};
static const char *const k_dab_key[ZCL_BRIEF_SOURCE_COUNT] = {
    "node", "land", "plan", "agents", "deadlines"};

struct dab_res {
    bool ok;
    struct json_value data;
    char code[40];
    char why[ZCL_DAB_WHY + 1];
};

struct dab_facts {
    bool node_bad;
    bool land_bad;
    bool failure_newer;
    bool renew_due;
    int64_t inflight;
};

static zcl_devagent_brief_fetch_fn g_dab_fetch;

void zcl_devagent_brief_set_fetch(zcl_devagent_brief_fetch_fn fn)
{
    g_dab_fetch = fn;
}

/* Printable ASCII only, no quote or backslash, at most max bytes with a
 * visible "..." marker when something was cut. */
static void dab_clip(char *dst, size_t max, const char *src)
{
    size_t n = src ? strlen(src) : 0;
    size_t keep = n > max ? max - 3 : n;
    for (size_t i = 0; i < keep; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c < 0x20 || c > 0x7e || c == '"' || c == '\\') ? ' ' : (char)c;
    }
    if (n > max) {
        memcpy(dst + keep, "...", 3);
        keep += 3;
    }
    dst[keep] = '\0';
}

static void dab_put_str(struct json_value *obj, const char *key, size_t max,
                        const char *src)
{
    char buf[ZCL_DAB_TITLE + 1];
    dab_clip(buf, max, src);
    (void)json_push_kv_str(obj, key, buf);
}

/* Copy one scalar (int or string) from `data[key]` to `obj[out]`. */
static bool dab_copy_scalar(struct json_value *obj, const char *out,
                            const struct json_value *data, const char *key)
{
    const struct json_value *v = json_get(data, key);
    if (v && v->type == JSON_INT) {
        (void)json_push_kv_int(obj, out, json_get_int(v));
        return true;
    }
    if (v && v->type == JSON_STR && json_get_str(v)) {
        dab_put_str(obj, out, ZCL_DAB_WORD, json_get_str(v));
        return true;
    }
    return false;
}

static const char *dab_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s ? s : "";
}

static void dab_unavailable(struct json_value *sec, const char *code,
                            const char *why)
{
    struct json_value u;
    json_init(&u);
    json_set_object(&u);
    dab_put_str(&u, "code", 39, code);
    dab_put_str(&u, "why", ZCL_DAB_WHY, why);
    (void)json_push_kv(sec, "unavailable", &u);
    json_free(&u);
}

/* ---- sections ----------------------------------------------------------- */

static bool dab_fill_node(struct json_value *sec, const struct json_value *d,
                          struct dab_facts *f)
{
    if (!dab_copy_scalar(sec, "tip", d, "hstar"))
        return false;
    (void)dab_copy_scalar(sec, "gap", d, "gap");
    (void)dab_copy_scalar(sec, "sync", d, "sync");
    (void)dab_copy_scalar(sec, "peers", d, "peers");
    const struct json_value *gap = json_get(d, "gap");
    const char *sync = dab_str(d, "sync");
    f->node_bad = (gap && gap->type == JSON_INT && json_get_int(gap) > 0) ||
                  (sync[0] && strcmp(sync, "at_tip") != 0);
    return true;
}

static bool dab_is_failure(const char *state)
{
    return strcmp(state, "failed") == 0 || strcmp(state, "conflict") == 0 ||
           strcmp(state, "fenced") == 0 || strcmp(state, "cancelled") == 0;
}

static void dab_land_event(struct json_value *sec, const char *key,
                           const struct json_value *row, bool with_reason)
{
    struct json_value e;
    const char *tip = dab_str(row, "tip_pushed");
    json_init(&e);
    json_set_object(&e);
    if (with_reason)
        dab_put_str(&e, "state", ZCL_DAB_STATE, dab_str(row, "state"));
    dab_put_str(&e, "tip", ZCL_DAB_TIP, tip[0] ? tip : dab_str(row, "tip"));
    dab_put_str(&e, "ts", ZCL_DAB_TS, dab_str(row, "ts"));
    if (with_reason)
        dab_put_str(&e, "reason", ZCL_DAB_REASON, dab_str(row, "detail"));
    (void)json_push_kv(sec, key, &e);
    json_free(&e);
}

/* Outcomes are oldest first: scan from the newest end. */
static void dab_land_outcomes(struct json_value *sec,
                              const struct json_value *outs,
                              struct dab_facts *f)
{
    const struct json_value *landed = NULL, *failed = NULL;
    size_t n = outs && outs->type == JSON_ARR ? outs->num_children : 0;
    for (size_t i = n; i-- > 0 && !(landed && failed);) {
        const struct json_value *row = json_at(outs, i);
        const char *st = dab_str(row, "state");
        if (!landed && strcmp(st, "landed") == 0)
            landed = row;
        else if (!failed && dab_is_failure(st))
            failed = row;
    }
    if (landed)
        dab_land_event(sec, "last_landed", landed, false);
    if (failed)
        dab_land_event(sec, "last_failure", failed, true);
    f->failure_newer = failed &&
        (!landed || strcmp(dab_str(failed, "ts"), dab_str(landed, "ts")) > 0);
}

static bool dab_fill_land(struct json_value *sec, const struct json_value *d,
                          struct dab_facts *f)
{
    const struct json_value *q = json_get(d, "queued");
    const struct json_value *in = json_get(d, "in_flight");
    if (!q || q->type != JSON_ARR)
        return false;
    f->inflight = in && in->type == JSON_OBJ ? 1 : 0;
    (void)json_push_kv_int(sec, "queued", (int64_t)q->num_children);
    (void)json_push_kv_int(sec, "inflight", f->inflight);
    dab_land_outcomes(sec, json_get(d, "outcomes"), f);
    return true;
}

/* "1. **Title.** rest" -> "Title" (the bold title only, never the body). */
static void dab_plan_title(char *dst, size_t max, const char *line)
{
    const char *open = strstr(line, "**");
    const char *close = open ? strstr(open + 2, "**") : NULL;
    char tmp[ZCL_DAB_TITLE * 2 + 8];
    size_t len;
    if (!close) {
        dab_clip(dst, max, line);
        return;
    }
    len = (size_t)(close - (open + 2));
    if (len >= sizeof(tmp))
        len = sizeof(tmp) - 1;
    memcpy(tmp, open + 2, len);
    tmp[len] = '\0';
    dab_clip(dst, max, tmp);
}

static bool dab_fill_plan(struct json_value *sec, const struct json_value *d)
{
    const struct json_value *items = json_get(d, "items");
    struct json_value arr;
    size_t n = items && items->type == JSON_ARR ? items->num_children : 0;
    if (n == 0)
        return false;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < n && i < ZCL_DAB_PLAN_ITEMS; i++) {
        struct json_value s;
        char title[ZCL_DAB_TITLE + 1];
        dab_clip(title, ZCL_DAB_TITLE, json_get_str(json_at(items, i)));
        json_init(&s);
        json_set_str(&s, title);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(sec, "now", &arr);
    json_free(&arr);
    return true;
}

static size_t dab_count(const struct json_value *d, const char *key)
{
    const struct json_value *v = json_get(d, key);
    return v && v->type == JSON_ARR ? v->num_children : 0;
}

static bool dab_fill_agents(struct json_value *sec, const struct json_value *d)
{
    if (!json_get(d, "queued") && !json_get(d, "running"))
        return false;
    (void)json_push_kv_int(sec, "queued", (int64_t)dab_count(d, "queued"));
    (void)json_push_kv_int(sec, "running", (int64_t)dab_count(d, "running"));
    return true;
}

static bool dab_fill_deadlines(struct json_value *sec,
                               const struct json_value *d, struct dab_facts *f)
{
    const struct json_value *soon = json_get(d, "soonest_expiry");
    const struct json_value *now = json_get(d, "now");
    const struct json_value *due = json_get(d, "renew_due");
    if (!soon || soon->type != JSON_INT || !now || now->type != JSON_INT)
        return false;
    (void)dab_copy_scalar(sec, "active", d, "active_count");
    if (json_get_int(soon) > 0)
        (void)json_push_kv_int(sec, "soonest_expiry_in_s",
                               json_get_int(soon) - json_get_int(now));
    f->renew_due = due && due->type == JSON_BOOL && json_get_bool(due);
    (void)json_push_kv_bool(sec, "renew_due", f->renew_due);
    return true;
}

static bool dab_fill(enum zcl_devagent_brief_source src,
                     struct json_value *sec, const struct json_value *d,
                     struct dab_facts *f)
{
    switch (src) {
    case ZCL_BRIEF_NODE:
        return dab_fill_node(sec, d, f);
    case ZCL_BRIEF_LAND:
        return dab_fill_land(sec, d, f);
    case ZCL_BRIEF_PLAN:
        return dab_fill_plan(sec, d);
    case ZCL_BRIEF_AGENTS:
        return dab_fill_agents(sec, d);
    case ZCL_BRIEF_DEADLINES:
        return dab_fill_deadlines(sec, d, f);
    default:
        return false;
    }
}

/* One section: provenance first, then either the fields or the typed
 * unavailable. A source that answered without the fields we need is
 * unavailable too (FIELDS_MISSING), never a half-filled section. */
static void dab_section(struct json_value *body, enum zcl_devagent_brief_source src,
                        const struct dab_res *r, struct dab_facts *f)
{
    struct json_value sec;
    json_init(&sec);
    json_set_object(&sec);
    (void)json_push_kv_str(&sec, src == ZCL_BRIEF_PLAN ? "source" : "leaf",
                           k_dab_leaf[src]);
    if (!r->ok) {
        dab_unavailable(&sec, r->code, r->why);
    } else if (!dab_fill(src, &sec, &r->data, f)) {
        dab_unavailable(&sec, "FIELDS_MISSING",
                        "the source answered without the fields the brief reads");
    }
    if (json_get(&sec, "unavailable")) {
        if (src == ZCL_BRIEF_NODE)
            f->node_bad = true;
        if (src == ZCL_BRIEF_LAND)
            f->land_bad = true;
    }
    (void)json_push_kv(body, k_dab_key[src], &sec);
    json_free(&sec);
}

/* The one command to run next, in the order of what is worst. */
static void dab_next(struct json_value *body, const struct dab_facts *f)
{
    const char *cmd = "z23 dev agent start";
    const char *why = "nothing urgent; orient and take the first free Now item";
    struct json_value n;
    if (f->node_bad) {
        cmd = "z23 core status brief";
        why = "node unreachable, behind or not at tip";
    } else if (f->land_bad || f->failure_newer || f->inflight > 0) {
        cmd = "z23 dev land status";
        why = f->inflight > 0 ? "a land is in flight"
                              : "the land queue failed or is unreadable";
    } else if (f->renew_due) {
        cmd = "z23 ops mesh device pair status";
        why = "a pairing grant is due for renewal";
    }
    json_init(&n);
    json_set_object(&n);
    (void)json_push_kv_str(&n, "command", cmd);
    (void)json_push_kv_str(&n, "why", why);
    (void)json_push_kv(body, "next", &n);
    json_free(&n);
}

/* ---- live sources -------------------------------------------------------- */

static void dab_fail(char *code, size_t ccap, char *why, size_t wcap,
                     const char *c, const char *w)
{
    (void)snprintf(code, ccap, "%s", c);
    (void)snprintf(why, wcap, "%s", w);
}

/* Run one registry leaf in-process and hand back its envelope's data. */
static bool dab_run_leaf(const struct zcl_command_request *rq, const char *path,
                         const char *input_json, struct json_value *data,
                         char *code, size_t ccap, char *why, size_t wcap)
{
    const struct zcl_command_context *ctx = rq ? rq->context : NULL;
    const struct zcl_command_spec *spec;
    struct json_value in, env;
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    bool was_alias = false, ok = false;
    char *out;
    size_t n;

    if (!ctx || !ctx->registry) {
        dab_fail(code, ccap, why, wcap, "NO_REGISTRY", "no command registry in this context");
        return false;
    }
    spec = zcl_command_registry_find(ctx->registry, path, &was_alias);
    out = zcl_malloc(ZCL_DAB_SUB_CAP, "agent brief sub-leaf reply");
    if (!spec || !out) {
        free(out);
        dab_fail(code, ccap, why, wcap, "LEAF_MISSING", "the leaf is not in this build");
        return false;
    }
    json_init(&in);
    json_init(&env);
    if (!json_read(&in, input_json, strlen(input_json)))
        json_set_object(&in);
    n = zcl_command_registry_execute_json(ctx->registry, spec, ctx, &in, false,
                                          path, "full", 0, 0, NULL, out,
                                          ZCL_DAB_SUB_CAP, &exit_code);
    if (n == 0 || !json_read(&env, out, n)) {
        dab_fail(code, ccap, why, wcap, "BAD_REPLY", "the leaf produced no readable reply");
    } else if (!json_get_bool(json_get(&env, "ok")) || !json_get(&env, "data")) {
        const char *ec = dab_str(json_get(&env, "error"), "code");
        dab_fail(code, ccap, why, wcap, ec[0] ? ec : "LEAF_FAILED",
                 dab_str(json_get(&env, "error"), "message"));
    } else {
        json_copy(data, json_get(&env, "data"));
        ok = true;
    }
    json_free(&in);
    json_free(&env);
    free(out);
    return ok;
}

/* The "Now" list: numbered lines under "## Now", up to the next "## ". */
static void dab_plan_collect(char *text, struct json_value *items)
{
    char *save = NULL;
    bool in_now = false;
    size_t found = 0;
    for (char *line = strtok_r(text, "\n", &save); line && found < ZCL_DAB_PLAN_ITEMS;
         line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "## ", 3) == 0) {
            in_now = strcmp(line, "## Now") == 0;
        } else if (in_now && line[0] >= '1' && line[0] <= '9' && line[1] == '.') {
            struct json_value s;
            char title[ZCL_DAB_TITLE + 1];
            dab_plan_title(title, ZCL_DAB_TITLE, line + 2);
            json_init(&s);
            json_set_str(&s, title);
            (void)json_push_back(items, &s);
            json_free(&s);
            found++;
        }
    }
}

static bool dab_live_plan(const struct zcl_command_request *rq,
                          struct json_value *data, char *code, size_t ccap,
                          char *why, size_t wcap)
{
    const char *root = rq && rq->context ? rq->context->source_root : NULL;
    const char *argv[8];
    size_t n = 0;
    struct json_value items;
    char *text = zcl_malloc(ZCL_DAB_PLAN_CAP, "agent brief plan text");
    int rc;

    if (!text) {
        dab_fail(code, ccap, why, wcap, "NO_MEMORY", "plan buffer");
        return false;
    }
    argv[n++] = "git";
    if (root && root[0]) {
        argv[n++] = "-C";
        argv[n++] = root;
    }
    argv[n++] = "show";
    argv[n++] = "HEAD:" ZCL_DAB_PLAN_PATH;
    argv[n] = NULL;
    rc = zcl_spawn_capture(argv, text, ZCL_DAB_PLAN_CAP, 10000);
    if (rc != 0) {
        free(text);
        dab_fail(code, ccap, why, wcap, "PLAN_UNREADABLE", "git show HEAD:" ZCL_DAB_PLAN_PATH " failed");
        return false;
    }
    json_init(&items);
    json_set_array(&items);
    dab_plan_collect(text, &items);
    json_set_object(data);
    (void)json_push_kv(data, "items", &items);
    json_free(&items);
    free(text);
    return true;
}

static bool dab_live(const struct zcl_command_request *rq,
                     enum zcl_devagent_brief_source src, struct json_value *data,
                     char *code, size_t ccap, char *why, size_t wcap)
{
    char input[320] = "{}";
    const char *sd = rq && rq->input ? dab_str(rq->input, "state_dir") : "";
    switch (src) {
    case ZCL_BRIEF_NODE:
        break;
    case ZCL_BRIEF_LAND:
        (void)snprintf(input, sizeof(input), "{\"json\":true}");
        break;
    case ZCL_BRIEF_AGENTS:
        (void)snprintf(input, sizeof(input), "{\"action\":\"status\"}");
        break;
    case ZCL_BRIEF_DEADLINES:
        if (sd[0] && strlen(sd) < 256 && !strpbrk(sd, "\"\\"))
            (void)snprintf(input, sizeof(input), "{\"state_dir\":\"%s\"}", sd);
        break;
    case ZCL_BRIEF_PLAN:
        return dab_live_plan(rq, data, code, ccap, why, wcap);
    default:
        return false;
    }
    return dab_run_leaf(rq, k_dab_leaf[src], input, data, code, ccap, why, wcap);
}

static void dab_fetch(const struct zcl_command_request *rq,
                      enum zcl_devagent_brief_source src, struct dab_res *r)
{
    zcl_devagent_brief_fetch_fn fn = g_dab_fetch ? g_dab_fetch : dab_live;
    json_init(&r->data);
    r->code[0] = r->why[0] = '\0';
    r->ok = fn(rq, src, &r->data, r->code, sizeof(r->code), r->why,
               sizeof(r->why));
    if (!r->ok && !r->code[0])
        (void)snprintf(r->code, sizeof(r->code), "UNAVAILABLE");
}

void zcl_native_handle_lab_brief(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    struct dab_res res[ZCL_BRIEF_SOURCE_COUNT];
    struct dab_facts facts = {0};
    char sized[ZCL_DAB_DATA_CAP + 64];
    size_t len;

    if (!reply)
        return;
    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "leaf", ZCL_DAB_LEAF);
    for (int i = 0; i < ZCL_BRIEF_SOURCE_COUNT; i++) {
        dab_fetch(request, (enum zcl_devagent_brief_source)i, &res[i]);
        dab_section(&reply->data, (enum zcl_devagent_brief_source)i, &res[i],
                    &facts);
        json_free(&res[i].data);
    }
    dab_next(&reply->data, &facts);
    len = json_write(&reply->data, sized, sizeof(sized));
    if (len > ZCL_DAB_DATA_CAP) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "BRIEF_OVER_BUDGET",
                               "compose", false, false,
                               "the composed brief exceeds its size cap",
                               "tools/command/native_devagent_brief.c");
        return;
    }
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
