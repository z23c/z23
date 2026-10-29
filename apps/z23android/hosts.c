/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "hosts.h"
#include "json/json.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *text_of(const struct json_value *row, const char *key)
{
    const char *s = json_get_str(json_get(row, key));
    return s && s[0] ? s : "unknown";
}
static bool count_of(const struct json_value *row, const char *key, int64_t *value)
{
    const struct json_value *v = json_get(row, key);
    if (!v || v->type != JSON_INT) return false;
    *value = json_get_int(v); return true;
}
static bool host_ok(const struct json_value *row)
{
    int64_t height, reference;
    return count_of(row, "height", &height) && count_of(row, "reference_height", &reference) &&
        height == reference && !strcmp(text_of(row, "synced"), "yes");
}
[[gnu::format(printf, 4, 5)]]
static size_t append(char *out, size_t cap, size_t used, const char *format, ...)
{
    if (used >= cap) return cap;
    va_list args; va_start(args, format);
    int n = vsnprintf(out + used, cap - used, format, args);
    va_end(args);
    return n < 0 || (size_t)n >= cap - used ? cap : used + (size_t)n;
}
static size_t height_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    int64_t height = 0, reference = 0;
    bool has_height = count_of(row, "height", &height), has_ref = count_of(row, "reference_height", &reference);
    if (has_height && has_ref && height == reference)
        return append(out, cap, used, "  height %lld matches zclassicd\n", (long long)height);
    if (has_height && has_ref)
        return append(out, cap, used, "  height %lld · zclassicd %lld\n", (long long)height, (long long)reference);
    if (has_height) return append(out, cap, used, "  height %lld · zclassicd unknown\n", (long long)height);
    return append(out, cap, used, "  height unknown\n");
}
static size_t row_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    const struct json_value *reachable = json_get(row, "reachable");
    int64_t ms = 0, disk = 0;
    (void)count_of(row, "probe_ms", &ms);
    if (!reachable || reachable->type != JSON_BOOL || !json_get_bool(reachable))
        return append(out, cap, used, "\n%s · unreachable after %lld.%lld s\n", text_of(row, "host"),
            (long long)(ms / 1000), (long long)(ms % 1000 / 100));
    used = append(out, cap, used, "\n%s · %s\n", text_of(row, "host"), host_ok(row) ? "in step" : "needs attention");
    used = height_text(row, out, cap, used);
    used = append(out, cap, used, "  node %s", text_of(row, "node"));
    if (strcmp(text_of(row, "blocker"), "unknown")) used = append(out, cap, used, ": %s", text_of(row, "blocker"));
    if (count_of(row, "disk_free_gb", &disk)) used = append(out, cap, used, " · %lld GB free", (long long)disk);
    return append(out, cap, used, "\n");
}
bool zapp_hosts_format(const char *json, char *out, size_t cap)
{
    if (!json || !out || !cap) return false;
    out[0] = 0;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json)) && root.type == JSON_OBJ;
    const struct json_value *hosts = ok ? json_get(&root, "hosts") : NULL;
    ok = hosts && hosts->type == JSON_ARR && hosts->num_children;
    size_t healthy = 0, total = ok ? hosts->num_children : 0, used = 0;
    for (size_t i = 0; i < total; i++) healthy += host_ok(json_at(hosts, i));
    if (ok) used = append(out, cap, 0, "%zu of %zu hosts match zclassicd\n", healthy, total);
    for (size_t i = 0; ok && i < total; i++) used = row_text(json_at(hosts, i), out, cap, used);
    ok = ok && used < cap;
    if (!ok) out[0] = 0;
    json_free(&root);
    return ok;
}
