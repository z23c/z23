/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Parameter parsing and bounded server-side filters for the semantic event
 * timeline RPC. */

#include "controllers/event_timeline_filter_controller.h"

#include "event/event.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const struct json_value *timeline_param_object(
    const struct json_value *params)
{
    if (!params)
        return NULL;
    if (params->type == JSON_OBJ)
        return params;
    if (params->type == JSON_ARR && json_size(params) > 0) {
        const struct json_value *first = json_at(params, 0);
        if (first && first->type == JSON_OBJ)
            return first;
    }
    return NULL;
}

bool timeline_parse_embedded_object_arg(const struct json_value *params,
                                        struct json_value *out)
{
    const char *s = NULL;
    if (!params || !out)
        return false; // raw-return-ok:predicate-negative
    if (params->type == JSON_STR) {
        s = json_get_str(params);
    } else if (params->type == JSON_ARR && json_size(params) > 0) {
        const struct json_value *first = json_at(params, 0);
        if (first && first->type == JSON_STR)
            s = json_get_str(first);
    }
    if (!s || s[0] != '{')
        return false; // raw-return-ok:predicate-negative
    if (!json_read(out, s, strlen(s)) || out->type != JSON_OBJ) {
        json_free(out);
        return false; // raw-return-ok:predicate-negative
    }
    return true;
}

const char *timeline_param_category(const struct json_value *params)
{
    const struct json_value *obj = timeline_param_object(params);
    if (obj) {
        const char *s = json_get_str(json_get(obj, "category"));
        return (s && s[0]) ? s : "all";
    }
    if (!params)
        return "all";
    if (params->type == JSON_ARR && json_size(params) > 0) {
        const struct json_value *v = json_at(params, 0);
        if (v && v->type == JSON_STR) {
            const char *s = json_get_str(v);
            return (s && s[0]) ? s : "all";
        }
    }
    return "all";
}

static int timeline_param_count(const struct json_value *params)
{
    int count = 50;
    const struct json_value *obj = timeline_param_object(params);
    if (obj) {
        const struct json_value *v = json_get(obj, "count");
        if (v && v->type == JSON_INT)
            count = (int)json_get_int(v);
        else if (v && v->type == JSON_REAL)
            count = (int)v->val.d;
        goto done;
    }
    if (!params)
        goto done;
    if (params->type == JSON_ARR && json_size(params) > 0) {
        const struct json_value *v0 = json_at(params, 0);
        const struct json_value *v1 = json_size(params) > 1 ?
            json_at(params, 1) : NULL;
        const struct json_value *v = (v0 && v0->type == JSON_STR) ? v1 : v0;
        if (v && v->type == JSON_INT)
            count = (int)json_get_int(v);
        else if (v && v->type == JSON_REAL)
            count = (int)v->val.d;
    }
done:
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;
    return count;
}

static int64_t timeline_get_int_field(const struct json_value *params,
                                      const char *key, int64_t fallback)
{
    const struct json_value *v = params && params->type == JSON_OBJ
        ? json_get(params, key) : NULL;
    if (!v || (v->type != JSON_INT && v->type != JSON_REAL))
        return fallback;
    return json_get_int(v);
}

static void timeline_get_str_field(const struct json_value *params,
                                   const char *key, char *out,
                                   size_t out_len)
{
    const char *s = "";
    if (!out || out_len == 0)
        return;
    if (params && params->type == JSON_OBJ)
        s = json_get_str(json_get(params, key));
    snprintf(out, out_len, "%s", s && s[0] ? s : "");
}

struct timeline_filter timeline_filter_from_params(
    const struct json_value *params)
{
    struct timeline_filter f;
    memset(&f, 0, sizeof(f));
    f.count = timeline_param_count(params);
    f.scan_count = f.count;

    const struct json_value *obj = timeline_param_object(params);
    if (obj) {
        int64_t scan = timeline_get_int_field(obj, "scan_count", -1);
        if (scan < 0)
            scan = timeline_get_int_field(obj, "scan", -1);

        int64_t since_us = timeline_get_int_field(obj, "since_us", -1);
        int64_t since_secs =
            timeline_get_int_field(obj, "since_secs", -1);
        if (since_us >= 0) {
            f.has_since_us = true;
            f.since_us = since_us;
        } else if (since_secs > 0) {
            if (since_secs > 604800)
                since_secs = 604800;
            int64_t now = platform_time_realtime_us();
            f.has_since_us = true;
            f.since_us = now - since_secs * 1000000LL;
        }

        int64_t peer = timeline_get_int_field(obj, "peer", -1);
        if (peer >= 0) {
            f.has_peer = true;
            f.peer = peer;
        }

        int64_t height = timeline_get_int_field(obj, "height", -1);
        if (height >= 0) {
            f.has_height = true;
            f.height = height;
        }

        timeline_get_str_field(obj, "reducer_stage",
                               f.reducer_stage, sizeof(f.reducer_stage));
        if (!f.reducer_stage[0])
            timeline_get_str_field(obj, "stage",
                                   f.reducer_stage,
                                   sizeof(f.reducer_stage));
        timeline_get_str_field(obj, "condition",
                               f.condition, sizeof(f.condition));
        timeline_get_str_field(obj, "deploy",
                               f.deploy, sizeof(f.deploy));
        timeline_get_str_field(obj, "lane", f.lane, sizeof(f.lane));

        f.has_filters = f.has_since_us || f.has_peer || f.has_height ||
            f.reducer_stage[0] || f.condition[0] || f.deploy[0] ||
            f.lane[0];

        if (scan > 0)
            f.scan_count = (int)scan;
        else if (f.has_since_us)
            f.scan_count = EVENT_LOG_SIZE;
        else if (f.has_filters)
            f.scan_count = f.count * 8 > 1000 ? f.count * 8 : 1000;
    }

    if (f.scan_count < f.count)
        f.scan_count = f.count;
    if (f.scan_count < 1)
        f.scan_count = 1;
    if (f.scan_count > EVENT_LOG_SIZE)
        f.scan_count = EVENT_LOG_SIZE;
    return f;
}

static bool timeline_data_has(const char *type, const char *data,
                              const char *needle)
{
    if (!needle || !needle[0])
        return true;
    return (type && strstr(type, needle) != NULL) ||
           (data && strstr(data, needle) != NULL);
}

static bool timeline_data_has_height(const char *data, int64_t height)
{
    const char *keys[] = {
        "height=", "h=", "local=", "target=", "from=", "to=", "tip=",
        "max_peer=", "peer_tip=",
    };
    char pat[64];
    if (!data || !data[0])
        return false; // raw-return-ok:predicate-negative
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        snprintf(pat, sizeof(pat), "%s%lld", keys[i], (long long)height);
        const char *hit = data;
        while ((hit = strstr(hit, pat)) != NULL) {
            const char *end = hit + strlen(pat);
            if (*end == '\0' || (!isalnum((unsigned char)*end) &&
                                 *end != '_' && *end != '-'))
                return true;
            hit = end;
        }
    }
    return false; // raw-return-ok:predicate-negative
}

static bool timeline_event_matches_filter(const struct json_value *ev,
                                          const struct timeline_filter *f)
{
    const char *type = json_get_str(json_get(ev, "type"));
    const char *data = json_get_str(json_get(ev, "data"));
    if (!f || !f->has_filters)
        return true;
    if (f->has_since_us &&
        json_get_int(json_get(ev, "ts")) < f->since_us)
        return false; // raw-return-ok:predicate-negative
    if (f->has_peer &&
        json_get_int(json_get(ev, "peer")) != f->peer)
        return false; // raw-return-ok:predicate-negative
    if (f->has_height && !timeline_data_has_height(data, f->height))
        return false; // raw-return-ok:predicate-negative
    if (!timeline_data_has(type, data, f->reducer_stage))
        return false; // raw-return-ok:predicate-negative
    if (!timeline_data_has(type, data, f->condition))
        return false; // raw-return-ok:predicate-negative
    if (!timeline_data_has(type, data, f->deploy))
        return false; // raw-return-ok:predicate-negative
    if (!timeline_data_has(type, data, f->lane))
        return false; // raw-return-ok:predicate-negative
    return true;
}

void timeline_push_filters(struct json_value *out,
                           const struct timeline_filter *f)
{
    struct json_value filters;
    json_init(&filters);
    json_set_object(&filters);
    json_push_kv_bool(&filters, "active", f && f->has_filters);
    json_push_kv_int(&filters, "scan_count", f ? f->scan_count : 0);
    json_push_kv_int(&filters, "returned_limit", f ? f->count : 0);
    if (f && f->has_since_us)
        json_push_kv_int(&filters, "since_us", f->since_us);
    if (f && f->has_peer)
        json_push_kv_int(&filters, "peer", f->peer);
    if (f && f->has_height)
        json_push_kv_int(&filters, "height", f->height);
    if (f && f->reducer_stage[0])
        json_push_kv_str(&filters, "reducer_stage", f->reducer_stage);
    if (f && f->condition[0])
        json_push_kv_str(&filters, "condition", f->condition);
    if (f && f->deploy[0])
        json_push_kv_str(&filters, "deploy", f->deploy);
    if (f && f->lane[0])
        json_push_kv_str(&filters, "lane", f->lane);
    json_push_kv_str(&filters, "semantics",
        "filters apply server-side over a bounded scan of the retained structured event ring; height/stage/condition/deploy/lane match typed event payload text");
    json_push_kv(out, "filters", &filters);
    json_free(&filters);
}

bool timeline_filter_events(const struct json_value *scanned,
                            const struct timeline_filter *f,
                            struct json_value *filtered,
                            int64_t *matched_before_limit)
{
    struct json_value matches;
    size_t n = scanned && scanned->type == JSON_ARR ? json_size(scanned) : 0;
    json_init(&matches);
    json_set_array(&matches);
    for (size_t i = 0; i < n; i++) {
        const struct json_value *ev = json_at(scanned, i);
        if (timeline_event_matches_filter(ev, f))
            json_push_back(&matches, ev);
    }

    size_t matched = json_size(&matches);
    size_t keep = f && f->count > 0 ? (size_t)f->count : matched;
    size_t start = matched > keep ? matched - keep : 0;
    if (matched_before_limit)
        *matched_before_limit = (int64_t)matched;
    json_set_array(filtered);
    for (size_t i = start; i < matched; i++)
        json_push_back(filtered, json_at(&matches, i));
    json_free(&matches);
    return true;
}
