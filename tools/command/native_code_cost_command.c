/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Price the proof of a change: the focused test route for one path
 * plus what the last suite run measured those groups to cost. */

#include "command/native_command.h"

#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include <limits.h>
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

/* Read a checkout file whole into a zcl_malloc'd, NUL-terminated buffer of at
 * most `max` bytes; *len receives its size. NULL when the file is absent,
 * oversized, or unreadable. The caller frees the buffer. The FS_READ reach
 * lives in this unit (module_capabilities.def) so code.body in
 * native_code_structure.c reads source without a capability row of its own. */
char *code_read_source_file(const char *path, size_t max, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    char *buf = NULL;
    if (fseek(fp, 0, SEEK_END) == 0) {
        long size = ftell(fp);
        if (size >= 0 && (unsigned long)size <= max &&
            fseek(fp, 0, SEEK_SET) == 0) {
            buf = zcl_malloc((size_t)size + 1, "code_source_file");
            if (buf && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
                free(buf);
                buf = NULL;
            }
            if (buf) {
                buf[size] = '\0';
                *len = (size_t)size;
            }
        }
    }
    fclose(fp);
    return buf;
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

/* A timing row only measures a group when its duration is a nonnegative
 * integer. Missing, mistyped and negative durations remain unmeasured. */
static bool cost_valid_ms(const struct json_value *row)
{
    const struct json_value *ms = row ? json_get(row, "ms") : NULL;
    return ms && ms->type == JSON_INT && json_get_int(ms) >= 0;
}

struct cost_totals { long long ms; size_t measured; bool overflow; };

static void cost_add_ms(struct cost_totals *totals, long long value)
{
    if ((value > 0 && totals->ms > LLONG_MAX - value) ||
        (value < 0 && totals->ms < LLONG_MIN - value))
        totals->overflow = true;
    else if (!totals->overflow)
        totals->ms += value;
}

static void cost_group_collect(const struct agent_impact_acc *acc, size_t shown,
                               const struct json_value *timing,
                               struct json_value *names, struct json_value *groups,
                               struct cost_totals *totals)
{
    for (size_t i = 0; i < acc->groups_len; i++) {
        const struct json_value *t = timing ? cost_timing_find(timing, acc->groups[i]) : NULL;
        if (!cost_valid_ms(t)) t = NULL;
        if (t) { cost_add_ms(totals, json_get_int(json_get(t, "ms"))); totals->measured++; }
        if (i >= shown) continue;
        struct json_value item, row;
        json_init(&item); json_set_str(&item, acc->groups[i]);
        (void)json_push_back(names, &item); json_free(&item);
        json_init(&row); json_set_object(&row);
        (void)json_push_kv_str(&row, "name", acc->groups[i]);
        if (t) {
            (void)json_push_kv_int(&row, "ms", json_get_int(json_get(t, "ms")));
            (void)json_push_kv_int(&row, "rc", json_get_int(json_get(t, "rc")));
            (void)json_push_kv_bool(&row, "cached", json_get_bool(json_get(t, "cached")));
            (void)json_push_kv_bool(&row, "measured", true);
        } else {
            (void)json_push_kv_bool(&row, "measured", false);
        }
        (void)json_push_back(groups, &row); json_free(&row);
    }
}

static void cost_group_count(struct json_value *data, const struct agent_impact_acc *acc,
                             size_t shown)
{
    (void)json_push_kv_int(data, "test_groups_retained_count", (int64_t)acc->groups_len);
    (void)json_push_kv_bool(data, "test_groups_lost", acc->groups_lost);
    (void)json_push_kv_bool(data, "test_groups_truncated", shown < acc->groups_len || acc->groups_lost);
    if (acc->groups_lost) {
        struct json_value unknown;
        json_init(&unknown); json_set_null(&unknown);
        (void)json_push_kv(data, "total_groups", &unknown); json_free(&unknown);
    } else {
        (void)json_push_kv_int(data, "total_groups", (int64_t)acc->groups_len);
    }
}

/* Totals cover retained groups, including entries beyond the displayed rows.
 * Missing groups or an overflowing sum are explicitly unknown. */
static void cost_summary(char summary[320], const char *route,
                         const struct agent_impact_acc *acc,
                         const struct cost_totals *totals)
{
    char route_part[128];
    if (acc->groups_len > 1) {
        (void)snprintf(route_part, sizeof(route_part),
                       "routes to group %s (+%zu more)", route, acc->groups_len - 1);
    } else {
        (void)snprintf(route_part, sizeof(route_part),
                       "routes to group %s", route);
    }
    if (totals->overflow) {
        (void)snprintf(summary, 320,
                       "%s; measured total unavailable (sum overflow)%s", route_part,
                       acc->groups_lost ? " (additional groups unknown)" : "");
    } else if (totals->measured > 0) {
        (void)snprintf(summary, 320,
                       "%s; last measured %.1fs across %zu/%zu retained groups%s",
                       route_part, (double)totals->ms / 1000.0, totals->measured,
                       acc->groups_len, acc->groups_lost ? " (additional groups unknown)" : "");
    } else {
        (void)snprintf(summary, 320,
                       "%s; not measured in this checkout yet%s "
                       "(run make t-fast ONLY=%s)", route_part,
                       acc->groups_lost ? " (additional groups unknown)" : "", route);
    }
}

static void cost_total_emit(struct json_value *data, const struct cost_totals *totals)
{
    if (totals->overflow) {
        struct json_value unknown;
        json_init(&unknown); json_set_null(&unknown);
        (void)json_push_kv(data, "total_ms", &unknown); json_free(&unknown);
    } else {
        (void)json_push_kv_int(data, "total_ms", totals->ms);
    }
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

    struct cost_totals totals = {0};
    cost_group_collect(&acc, shown, have_timing ? &timing : NULL,
                       &names, &groups, &totals);

    char summary[320];
    cost_summary(summary, route, &acc, &totals);

    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_str(&reply->data, "route", route);
    (void)json_push_kv_bool(&reply->data, "consensus_risk", crisk);
    (void)json_push_kv(&reply->data, "test_groups", &names);
    (void)json_push_kv(&reply->data, "groups", &groups);
    cost_total_emit(&reply->data, &totals);
    (void)json_push_kv_int(&reply->data, "measured_groups", (int64_t)totals.measured);
    cost_group_count(&reply->data, &acc, shown);
    (void)json_push_kv_bool(&reply->data, "timing_complete",
                            have_timing && !acc.groups_lost && !totals.overflow &&
                            totals.measured == acc.groups_len);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&names);
    json_free(&groups);
    if (have_timing)
        json_free(&timing);
}
