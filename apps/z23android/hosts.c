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
const char *zapp_grouped(int64_t value, char out[32])
{
    char digits[24];
    int n = snprintf(digits, sizeof(digits), "%lld", (long long)value);
    if (n <= 0 || value < 0) { snprintf(out, 32, "%s", n > 0 ? digits : "?"); return out; }
    size_t at = 0;
    for (int i = 0; i < n; i++) {
        if (i && (n - i) % 3 == 0) out[at++] = ',';
        out[at++] = digits[i];
    }
    out[at] = 0;
    return out;
}
const char *zapp_node_line(bool responding, bool process_running, bool stopping, int64_t height,
                           int64_t target, int64_t peers, char *out, size_t cap)
{
    char at[32], top[32], count[40] = "";
    if (peers >= 0) snprintf(count, sizeof(count), " · %lld %s", (long long)peers, peers == 1 ? "peer" : "peers");
    if (stopping) snprintf(out, cap, "Node stopping");
    else if (!responding) snprintf(out, cap, "Node %s", process_running ? "starting" : "stopped");
    else if (height < 0) snprintf(out, cap, "Node running%s", count);
    else if (target <= 0) snprintf(out, cap, "Node waiting for peers · %s", zapp_grouped(height, at));
    else if (height >= target) snprintf(out, cap, "Node in sync · %s%s", zapp_grouped(height, at), count);
    else snprintf(out, cap, "Node catching up · %s of %s", zapp_grouped(height, at), zapp_grouped(target, top));
    return out;
}
/* "in step", blocks behind or ahead of zclassicd, then the height; a negative height is unknown. */
static size_t state_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    int64_t height = -1, reference = -1;
    char at[32], by[32];
    if (!count_of(row, "height", &height) || height < 0) return append(out, cap, used, "height unknown");
    zapp_grouped(height, at);
    if (host_ok(row)) return append(out, cap, used, "in step · %s", at);
    if (!count_of(row, "reference_height", &reference) || reference < 0)
        return append(out, cap, used, "zclassicd unknown · %s", at);
    if (height == reference) return append(out, cap, used, "not synced · %s", at);
    int64_t gap = height < reference ? reference - height : height - reference;
    return append(out, cap, used, "%s %s %s · %s", zapp_grouped(gap, by), gap == 1 ? "block" : "blocks",
                  height < reference ? "behind" : "ahead", at);
}
/* A status code such as review_required_bootstrap_trust read as words. */
static const char *plain_words(const char *code, char out[160])
{
    size_t i = 0;
    for (; code[i] && i < 159; i++) {
        char ch = code[i] == '_' ? ' ' : code[i];
        out[i] = ch >= 'A' && ch <= 'Z' ? (char)(ch - 'A' + 'a') : ch;
    }
    out[i] = 0;
    return out;
}
static bool known(const char *value)
{
    return strcmp(value, "unknown") && strcmp(value, "none") && strcmp(value, "ok");
}
static size_t detail_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    const char *node = text_of(row, "node"), *blocker = text_of(row, "blocker");
    char words[160];
    int64_t disk = 0;
    bool blocked = known(blocker), odd = !blocked && known(node);
    if (blocked) used = append(out, cap, used, "\n  Blocked: %s", plain_words(blocker, words));
    else if (odd) used = append(out, cap, used, "\n  Node %s", plain_words(node, words));
    if (count_of(row, "disk_free_gb", &disk))
        used = append(out, cap, used, "%s%lld GB free", blocked || odd ? " · " : "\n  ", (long long)disk);
    return used;
}
static size_t row_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    const struct json_value *reachable = json_get(row, "reachable");
    int64_t ms = 0;
    (void)count_of(row, "probe_ms", &ms);
    if (!reachable || reachable->type != JSON_BOOL || !json_get_bool(reachable))
        return append(out, cap, used, "\n%s · unreachable after %lld.%lld s\n", text_of(row, "host"),
            (long long)(ms / 1000), (long long)(ms % 1000 / 100));
    used = append(out, cap, used, "\n%s · ", text_of(row, "host"));
    used = state_text(row, out, cap, used);
    used = detail_text(row, out, cap, used);
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
    if (ok) used = append(out, cap, 0, "%zu of %zu hosts in step\n", healthy, total);
    for (size_t i = 0; ok && i < total; i++) used = row_text(json_at(hosts, i), out, cap, used);
    ok = ok && used < cap;
    if (!ok) out[0] = 0;
    json_free(&root);
    return ok;
}
