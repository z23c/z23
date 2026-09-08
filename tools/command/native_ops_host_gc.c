/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: ops.host.gc — one call, one JSON report of what the host's
 *          dev-proof worktree pools hold and what is reclaimable, and
 *          (only with apply) the removal itself.
 *
 * WHY `ops`, NOT `dev`. engine/composition/commands/README.md splits the
 * trees by who the leaf serves: `dev` leaves are bound only in a dev build
 * and fail closed as COMPAT stubs in the release binary. Host garbage
 * collection is an OPERATOR duty on every node the fleet runs — the hourly
 * timer calls it on machines that carry the release binary and no checkout
 * — so binding it under `dev` would make it uncallable exactly where it
 * matters. It reads and reclaims machine-local state rather than chain
 * state, which is what LAYER_OPS/SCOPE_NODE already describe.
 *
 * DRY RUN IS THE DEFAULT and is TRAIT_IDEMPOTENT: without `apply` the leaf
 * classifies, measures, and removes nothing. `apply` is the only way a byte
 * moves, and even then the engine's only deletion path is git's own
 * worktree removal (see command/host_gc_sweep.h).
 */

#include "command/native_command.h"
#include "command/host_gc_sweep.h"

#include "json/json.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <string.h>

enum { OHG_MAX_FLOOR_HOURS = 24 * 365 };

static void ohg_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, phase, false,
                           false, message, evidence);
}

/* One `roots` element. An object names its own class label; a bare string
 * takes the pool directory's own basename, so the common case stays one
 * short array of paths. */
static bool ohg_take_root(const struct json_value *el,
                          struct host_gc_pool *pool)
{
    const char *path = json_get_str(el);
    const char *name = NULL;
    const char *slash;
    if (!path) {
        path = json_get_str(json_get(el, "path"));
        name = json_get_str(json_get(el, "class"));
    }
    if (!path || path[0] != '/')
        return false;
    if (!name || !name[0]) {
        slash = strrchr(path, '/');
        name = (slash && slash[1]) ? slash + 1 : path;
    }
    return snprintf(pool->name, sizeof(pool->name), "%s", name) > 0 &&
           (size_t)snprintf(pool->path, sizeof(pool->path), "%s", path) <
               sizeof(pool->path);
}

static bool ohg_take_roots(const struct json_value *roots,
                           struct host_gc_request *req)
{
    size_t n = json_size(roots);
    if (n == 0 || n > HOST_GC_MAX_POOLS)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!ohg_take_root(json_at(roots, i), &req->pools[i]))
            return false;
    req->npools = n;
    return true;
}

static void ohg_push_class(struct json_value *arr,
                           const struct host_gc_class *cls)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "class", cls->name);
    (void)json_push_kv_str(&row, "path", cls->path);
    (void)json_push_kv_str(&row, "repo", cls->repo);
    (void)json_push_kv_bool(&row, "present", cls->present);
    (void)json_push_kv_int(&row, "registered", cls->registered);
    (void)json_push_kv_int(&row, "reapable", cls->reapable);
    (void)json_push_kv_int(&row, "too_young", cls->too_young);
    (void)json_push_kv_int(&row, "in_use", cls->in_use);
    (void)json_push_kv_int(&row, "locked", cls->locked);
    (void)json_push_kv_int(&row, "need_review", cls->need_review);
    (void)json_push_kv_int(&row, "bytes_reclaimable",
                           (int64_t)cls->bytes_reclaimable);
    (void)json_push_kv_int(&row, "bytes_reclaimed",
                           (int64_t)cls->bytes_reclaimed);
    (void)json_push_back(arr, &row);
    json_free(&row);
}

static void ohg_push_refusal(struct json_value *arr,
                             const struct host_gc_refusal *ref)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "path", ref->path);
    (void)json_push_kv_str(&row, "reason", ref->reason);
    (void)json_push_back(arr, &row);
    json_free(&row);
}

static void ohg_push_totals(struct json_value *out,
                            const struct host_gc_report *report)
{
    struct json_value totals;
    int registered = 0, reapable = 0;
    uint64_t reclaimable = 0, reclaimed = 0;
    for (size_t i = 0; i < report->nclasses; i++) {
        registered += report->classes[i].registered;
        reapable += report->classes[i].reapable;
        reclaimable += report->classes[i].bytes_reclaimable;
        reclaimed += report->classes[i].bytes_reclaimed;
    }
    json_init(&totals);
    json_set_object(&totals);
    (void)json_push_kv_int(&totals, "registered", registered);
    (void)json_push_kv_int(&totals, "reapable", reapable);
    (void)json_push_kv_int(&totals, "bytes_reclaimable", (int64_t)reclaimable);
    (void)json_push_kv_int(&totals, "bytes_reclaimed", (int64_t)reclaimed);
    (void)json_push_kv(out, "totals", &totals);
    json_free(&totals);
}

static void ohg_project(struct zcl_command_reply *reply,
                        const struct host_gc_request *req,
                        const struct host_gc_report *report)
{
    struct json_value classes, refusals;
    json_init(&classes);
    json_set_array(&classes);
    for (size_t i = 0; i < report->nclasses; i++)
        ohg_push_class(&classes, &report->classes[i]);
    json_init(&refusals);
    json_set_array(&refusals);
    for (size_t i = 0; i < report->nrefusals; i++)
        ohg_push_refusal(&refusals, &report->refusals[i]);

    (void)json_push_kv_bool(&reply->data, "apply", req->apply);
    (void)json_push_kv_int(&reply->data, "floor_hours", req->floor_hours);
    (void)json_push_kv(&reply->data, "classes", &classes);
    ohg_push_totals(&reply->data, report);
    (void)json_push_kv(&reply->data, "refusals", &refusals);
    (void)json_push_kv_bool(&reply->data, "truncated", report->truncated);
    json_free(&classes);
    json_free(&refusals);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

void zcl_native_handle_ops_host_gc(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *roots = json_get(input, "roots");
    struct host_gc_request req;
    struct host_gc_report report;
    int64_t floor_hours;

    if (!reply)
        return;
    if (!host_gc_defaults(&req)) {
        ohg_fail(reply, "host_gc.home_unresolved", "anchor",
                 "HOME is unset or not an absolute path, so no pool root "
                 "can be anchored; refusing to sweep an unanchored tree",
                 "HOME");
        return;
    }
    req.apply = json_get_bool_or(input, "apply", false);
    floor_hours = json_get_int_or(input, "floor_hours",
                                  HOST_GC_DEFAULT_FLOOR_HOURS);
    if (floor_hours < 0 || floor_hours > OHG_MAX_FLOOR_HOURS) {
        ohg_fail(reply, "host_gc.floor_out_of_range", "validate",
                 "floor_hours must be between 0 and 8760", "floor_hours");
        return;
    }
    req.floor_hours = (int)floor_hours;
    if (roots && !ohg_take_roots(roots, &req)) {
        ohg_fail(reply, "host_gc.roots_invalid", "validate",
                 "roots must be 1..8 entries, each an absolute pool "
                 "directory (a string, or {\"class\",\"path\"})", "roots");
        return;
    }
    if (!host_gc_run(&req, &report)) {
        ohg_fail(reply, "host_gc.sweep_unavailable", "sweep",
                 "the sweep could not allocate its candidate table", "");
        return;
    }
    ohg_project(reply, &req, &report);
}
