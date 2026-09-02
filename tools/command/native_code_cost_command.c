/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Price the proof of a change: the focused test route for one path
 * plus what the last suite run measured those groups to cost. */

#include "command/native_command.h"

#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CODE_COST_GROUPS_CAP = 12,      /* mirrors code.tests test_groups cap */
    CODE_COST_TIMING_MAX = 4 * 1024 * 1024,
};

static const char *cost_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *root = getenv("ZCL_DEV_SOURCE_ROOT");
    return root && root[0] ? root : ".";
}

/* The last suite run's per-group timing artifact (schema zcl.test_timing.v1),
 * written by tests/harness/src/test_parallel.c. Absent, oversized, or
 * unparseable all mean one honest thing: this checkout has no usable
 * measurement. Never fabricate a number. */
static bool cost_timing_load(const char *root, struct json_value *out)
{
    char path[4096];
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/test-timing/last-run.json", root);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return false;
    char *buf = zcl_malloc(CODE_COST_TIMING_MAX, "code_cost_timing");
    if (!buf) {
        fclose(fp);
        return false;
    }
    size_t used = fread(buf, 1, CODE_COST_TIMING_MAX - 1, fp);
    bool oversized = !feof(fp);
    fclose(fp);
    if (oversized) {
        free(buf);
        return false;
    }
    buf[used] = '\0';
    bool ok = json_read(out, buf, used) && out->type == JSON_OBJ;
    free(buf);
    if (!ok)
        json_free(out);
    return ok;
}

/* Timing rows carry the registered full name ("test_codeindex",
 * "spec_p2p"); impact groups are bare ("codeindex"). Match either form. */
static bool cost_group_name_matches(const char *timing_name,
                                    const char *group)
{
    if (strcmp(timing_name, group) == 0)
        return true;
    if (strncmp(timing_name, "test_", 5) == 0 &&
        strcmp(timing_name + 5, group) == 0)
        return true;
    if (strncmp(timing_name, "spec_", 5) == 0 &&
        strcmp(timing_name + 5, group) == 0)
        return true;
    return false;
}

static const struct json_value *cost_timing_find(
    const struct json_value *timing, const char *group)
{
    const struct json_value *groups = json_get(timing, "groups");
    if (!groups || groups->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < groups->num_children; i++) {
        const struct json_value *row = json_at(groups, i);
        const char *name = json_get_str(json_get(row, "name"));
        if (name && cost_group_name_matches(name, group))
            return row;
    }
    return NULL;
}

void zcl_native_handle_code_cost(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *path = json_get_str(json_get(request->input, "path"));
    if (!path || !path[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PATH",
                               "normalize", false, false,
                               "code cost requires a repo-relative path", "");
        return;
    }

    struct agent_impact_acc acc = {0};
    bool crisk = false;
    const char *route = zcl_native_code_route_for_path(path, &acc, &crisk);
    if (!route)
        route = "make_lint_gates";

    struct json_value timing;
    bool have_timing = cost_timing_load(cost_source_root(request), &timing);

    size_t shown = acc.groups_len < (size_t)CODE_COST_GROUPS_CAP
                       ? acc.groups_len : (size_t)CODE_COST_GROUPS_CAP;

    struct json_value names;
    json_init(&names);
    json_set_array(&names);
    struct json_value groups;
    json_init(&groups);
    json_set_array(&groups);

    long long total_ms = 0;
    size_t measured = 0;
    for (size_t i = 0; i < shown; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, acc.groups[i]);
        (void)json_push_back(&names, &item);
        json_free(&item);

        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "name", acc.groups[i]);
        const struct json_value *t =
            have_timing ? cost_timing_find(&timing, acc.groups[i]) : NULL;
        if (t) {
            (void)json_push_kv_int(&row, "ms",
                                   json_get_int(json_get(t, "ms")));
            (void)json_push_kv_int(&row, "rc",
                                   json_get_int(json_get(t, "rc")));
            (void)json_push_kv_bool(&row, "cached",
                                    json_get_bool(json_get(t, "cached")));
            (void)json_push_kv_bool(&row, "measured", true);
            total_ms += json_get_int(json_get(t, "ms"));
            measured++;
        } else {
            (void)json_push_kv_bool(&row, "measured", false);
        }
        (void)json_push_back(&groups, &row);
        json_free(&row);
    }

    char summary[320];
    char route_part[128];
    if (shown > 1) {
        (void)snprintf(route_part, sizeof(route_part),
                       "routes to group %s (+%zu more)", route, shown - 1);
    } else {
        (void)snprintf(route_part, sizeof(route_part),
                       "routes to group %s", route);
    }
    if (measured > 0) {
        (void)snprintf(summary, sizeof(summary),
                       "%s; last measured %.1fs across %zu/%zu groups",
                       route_part, (double)total_ms / 1000.0, measured, shown);
    } else {
        (void)snprintf(summary, sizeof(summary),
                       "%s; not measured in this checkout yet "
                       "(run make t-fast ONLY=%s)", route_part, route);
    }

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "route", route);
    (void)json_push_kv_bool(&reply->data, "consensus_risk", crisk);
    (void)json_push_kv(&reply->data, "test_groups", &names);
    (void)json_push_kv(&reply->data, "groups", &groups);
    (void)json_push_kv_int(&reply->data, "total_ms", total_ms);
    (void)json_push_kv_int(&reply->data, "measured_groups", (int64_t)measured);
    (void)json_push_kv_int(&reply->data, "total_groups", (int64_t)shown);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&names);
    json_free(&groups);
    if (have_timing)
        json_free(&timing);
}
