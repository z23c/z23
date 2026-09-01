/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONTROLLERS_EVENT_TIMELINE_FILTER_H
#define ZCL_CONTROLLERS_EVENT_TIMELINE_FILTER_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

struct timeline_filter {
    int count;
    int scan_count;
    bool has_filters;
    bool has_since_us;
    int64_t since_us;
    bool has_peer;
    int64_t peer;
    bool has_height;
    int64_t height;
    char reducer_stage[64];
    char condition[96];
    char deploy[96];
    char lane[64];
};

bool timeline_parse_embedded_object_arg(const struct json_value *params,
                                        struct json_value *out);
const char *timeline_param_category(const struct json_value *params);
struct timeline_filter timeline_filter_from_params(
    const struct json_value *params);
void timeline_push_filters(struct json_value *out,
                           const struct timeline_filter *f);
bool timeline_filter_events(const struct json_value *scanned,
                            const struct timeline_filter *f,
                            struct json_value *filtered,
                            int64_t *matched_before_limit);

#endif
