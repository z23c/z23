/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "hosts.h"
#include "json/json.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

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
/* The two heights come from separate commands, so a block that lands between them shows a host at
 * the network height a block or two apart from its zclassicd. A busy node can answer its status
 * without the synced field; only a host that reports itself not synced is held apart. */
enum { IN_SYNC_SKEW = 2 };
static bool host_ok(const struct json_value *row)
{
    int64_t height, reference;
    return count_of(row, "height", &height) && count_of(row, "reference_height", &reference) &&
        height >= 0 && reference >= 0 &&
        (height > reference ? height - reference : reference - height) <= IN_SYNC_SKEW &&
        strcmp(text_of(row, "synced"), "no");
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
/* The one rule for "is this node's chain current". A node is current only when it is within the
 * skew of the highest height it has heard of (a peer's or the fleet's) and has evidence the chain is
 * live: enough peers, or a fleet height that agrees. Without that evidence, a quiet tip is unconfirmed,
 * never "in sync". Both the node line and the sync sentence read this, so they cannot disagree. */
enum chain_state { CHAIN_WAITING, CHAIN_BEHIND, CHAIN_UNCONFIRMED, CHAIN_CURRENT };
struct chain_verdict { enum chain_state state; int64_t reference; char reason[48]; };
static int64_t abs_gap(int64_t a, int64_t b) { return a > b ? a - b : b - a; }
static struct chain_verdict chain_verdict(int64_t height, int64_t target, int64_t peers,
                                          const struct zapp_chain_evidence *ev)
{
    const int64_t fleet = ev ? ev->fleet_height : -1, quiet = ev ? ev->quiet_secs : -1;
    struct chain_verdict v = {.reference = target > fleet ? target : fleet};
    if (v.reference <= 0) { v.state = CHAIN_WAITING; return v; }
    if (v.reference - height > ZAPP_CHAIN_SKEW) { v.state = CHAIN_BEHIND; return v; }
    const bool fleet_agrees = fleet >= 0 && abs_gap(fleet, height) <= ZAPP_CHAIN_SKEW;
    v.state = CHAIN_UNCONFIRMED;
    if (!fleet_agrees && peers < ZAPP_CHAIN_MIN_PEERS)
        snprintf(v.reason, sizeof(v.reason), peers == 1 ? "only 1 peer" : peers == 0 ? "no peers" : "no peer count");
    else if (!fleet_agrees && quiet > ZAPP_CHAIN_QUIET_SECS)
        snprintf(v.reason, sizeof(v.reason), "no new block for %lld min", (long long)(quiet / 60));
    else v.state = CHAIN_CURRENT;
    return v;
}
const char *zapp_node_line(bool responding, bool process_running, bool stopping, bool onion_ready,
                           int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap)
{
    char at[32], top[32], count[40] = "";
    const char *onion = responding ? (onion_ready ? " · onion ready" : " · onion starting") : "";
    if (peers >= 0) snprintf(count, sizeof(count), " · %lld %s", (long long)peers, peers == 1 ? "peer" : "peers");
    const struct chain_verdict v = chain_verdict(height, target, peers, evidence);
    if (stopping) snprintf(out, cap, "Node stopping");
    else if (!responding) snprintf(out, cap, "Node %s", process_running ? "starting" : "stopped");
    else if (height < 0) snprintf(out, cap, "Node running%s%s", count, onion);
    else if (v.state == CHAIN_WAITING) snprintf(out, cap, "Node waiting for peers · %s%s", zapp_grouped(height, at), onion);
    else if (v.state == CHAIN_BEHIND)
        snprintf(out, cap, "Behind · %s of %s%s", zapp_grouped(height, at), zapp_grouped(v.reference, top), onion);
    else if (v.state == CHAIN_UNCONFIRMED)
        snprintf(out, cap, "Height %s · %s, cannot confirm it is current%s", zapp_grouped(height, at), v.reason, onion);
    else snprintf(out, cap, "Node in sync · %s%s%s", zapp_grouped(height, at), count, onion);
    return out;
}
enum zapp_pace zapp_status_pace(const char *status)
{
    struct json_value root = {0};
    enum zapp_pace pace = ZAPP_PACE_NORMAL;
    if (!status || !json_read(&root, status, strlen(status))) return pace;
    const char *word = json_get_str(json_get(json_get(&root, "data"), "pace"));
    if (word && !strcmp(word, "gentle")) pace = ZAPP_PACE_GENTLE;
    else if (word && !strcmp(word, "pause")) pace = ZAPP_PACE_PAUSE;
    json_free(&root);
    return pace;
}
const char *zapp_paced_line(enum zapp_pace pace, bool process_running, const char *node_line,
                            char *out, size_t cap)
{
    const char *text = node_line;
    /* Only a node that is starting or catching up is slowed by the pace; a node that is stopping or in
     * sync keeps its true line. */
    const bool settled = node_line && (!strncmp(node_line, "Node stopping", 13) || !strncmp(node_line, "Node in sync", 12));
    if (settled) process_running = false;
    if (process_running && pace == ZAPP_PACE_GENTLE) text = "Syncing gently · phone is warm";
    else if (process_running && pace == ZAPP_PACE_PAUSE) text = "Sync paused · phone is cooling down";
    snprintf(out, cap, "%s", text ? text : "");
    return out;
}
const char *zapp_sync_line(bool responding, bool process_running, int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap)
{
    char gap[32];
    const struct chain_verdict v = chain_verdict(height, target, peers, evidence);
    if (!responding) snprintf(out, cap, "%s", process_running ?
        "Waiting for the node to answer." : "Start the node to begin synchronization.");
    else if (height < 0) snprintf(out, cap, "Waiting for the node to report its height.");
    else if (v.state == CHAIN_WAITING) snprintf(out, cap, "Waiting for a peer that reports the current chain.");
    else if (v.state == CHAIN_BEHIND) snprintf(out, cap, "%s %s to go.", zapp_grouped(v.reference - height, gap),
                                            v.reference - height == 1 ? "block" : "blocks");
    else if (v.state == CHAIN_UNCONFIRMED)
        snprintf(out, cap, "Your node has every block it can see, but with %s it cannot confirm it is current.", v.reason);
    else snprintf(out, cap, "Your node has every block its peers report.");
    return out;
}
/* Whether the snapshot was observed recently enough, by the clock of the host that probed it. */
static bool snapshot_current(const struct json_value *root, int64_t now_unix)
{
    int64_t observed = 0;
    return count_of(root, "observed_at", &observed) && observed > 0 &&
        observed >= now_unix - ZAPP_FLEET_MAX_AGE_SECS && observed <= now_unix + ZAPP_FLEET_FUTURE_SECS;
}
/* The highest of a reachable host's node and zclassicd heights, or -1. */
static int64_t reachable_height(const struct json_value *row)
{
    const struct json_value *reachable = json_get(row, "reachable");
    int64_t best = -1, value;
    if (!reachable || reachable->type != JSON_BOOL || !json_get_bool(reachable)) return -1;
    if (count_of(row, "height", &value) && value > best) best = value;
    if (count_of(row, "reference_height", &value) && value > best) best = value;
    return best;
}
/* The highest height any reachable host of a zapp_hosts_format snapshot reports, from its node or its
 * zclassicd; -1 when none does. The fleet's height is evidence the chain has reached that far, so a snapshot
 * counts only when its observed_at (unix seconds, set by the host that probed) is at most ZAPP_FLEET_MAX_AGE_SECS
 * old and at most ZAPP_FLEET_FUTURE_SECS ahead of now_unix; the laptop host serves its last snapshot after its
 * refreshes fail. */
int64_t zapp_fleet_height(const char *json, int64_t now_unix)
{
    struct json_value root = {0};
    int64_t best = -1;
    const bool read = json && json_read(&root, json, strlen(json));
    const struct json_value *hosts = read && snapshot_current(&root, now_unix) ? json_get(&root, "hosts") : NULL;
    for (size_t i = 0; hosts && hosts->type == JSON_ARR && i < hosts->num_children; i++) {
        int64_t height = reachable_height(json_at(hosts, i));
        if (height > best) best = height;
    }
    json_free(&root);
    return best;
}
/* "in sync", blocks behind or ahead of the host's zclassicd, then the height. A host that answered the
 * probe without a height has a node that did not answer; a negative height is unknown. Without the
 * zclassicd height a host cannot be compared, so it is not counted in sync even when it reports itself
 * synced, and its row says so. */
static size_t state_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    int64_t height = -1, reference = -1;
    char at[32], by[32];
    if (!count_of(row, "height", &height)) return append(out, cap, used, "node not answering");
    if (height < 0) return append(out, cap, used, "height unknown");
    zapp_grouped(height, at);
    if (host_ok(row)) return append(out, cap, used, "in sync · %s", at);
    if (!count_of(row, "reference_height", &reference) || reference < 0)
        return append(out, cap, used, "%szclassicd height unknown, not counted in sync · %s",
                      strcmp(text_of(row, "synced"), "yes") ? "" : "reports synced but ", at);
    if (height == reference) return append(out, cap, used, "not synced · %s", at);
    int64_t gap = height < reference ? reference - height : height - reference;
    return append(out, cap, used, "%s %s %s · %s", zapp_grouped(gap, by), gap == 1 ? "block" : "blocks",
                  height < reference ? "behind" : "ahead", at);
}
/* Free disk shows only below the 50 GB floor the node's own preflight keeps. Blocker codes stay off
 * the screen; the voice assistant reads a host's blockers on request. */
enum { LOW_DISK_GB = 50 };
static size_t disk_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    int64_t disk = 0;
    if (!count_of(row, "disk_free_gb", &disk) || disk < 0 || disk >= LOW_DISK_GB) return used;
    return append(out, cap, used, "\n  Low on disk · %lld GB free", (long long)disk);
}
static size_t row_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    const struct json_value *reachable = json_get(row, "reachable");
    int64_t ms = 0;
    (void)count_of(row, "probe_ms", &ms);
    if (!reachable || reachable->type != JSON_BOOL || !json_get_bool(reachable))
        return append(out, cap, used, "\n%s · host not answering after %lld.%lld s\n", text_of(row, "host"),
            (long long)(ms / 1000), (long long)(ms % 1000 / 100));
    used = append(out, cap, used, "\n%s · ", text_of(row, "host"));
    used = state_text(row, out, cap, used);
    used = disk_text(row, out, cap, used);
    return append(out, cap, used, "\n");
}
typedef size_t (*row_writer)(const struct json_value *row, char *out, size_t cap, size_t used);
static bool hosts_report(const char *json, char *out, size_t cap, row_writer write_row)
{
    if (!json || !out || !cap) return false;
    out[0] = 0;
    struct json_value root = {0};
    bool ok = json_read(&root, json, strlen(json)) && root.type == JSON_OBJ;
    const struct json_value *hosts = ok ? json_get(&root, "hosts") : NULL;
    ok = hosts && hosts->type == JSON_ARR && hosts->num_children;
    size_t healthy = 0, total = ok ? hosts->num_children : 0, used = 0;
    for (size_t i = 0; i < total; i++) healthy += host_ok(json_at(hosts, i));
    if (ok) used = append(out, cap, 0, "%zu of %zu hosts in sync\n", healthy, total);
    for (size_t i = 0; ok && i < total; i++) used = write_row(json_at(hosts, i), out, cap, used);
    ok = ok && used < cap;
    if (!ok) out[0] = 0;
    json_free(&root);
    return ok;
}
bool zapp_hosts_format(const char *json, char *out, size_t cap)
{
    return hosts_report(json, out, cap, row_text);
}
/* One verdict per host for the voice model, decided by the same host_ok rule as the headline, so the
 * model reads a result and never compares heights itself. */
static size_t verdict_text(const struct json_value *row, char *out, size_t cap, size_t used)
{
    int64_t height = -1, reference = -1;
    if (!count_of(row, "height", &height)) return append(out, cap, used, "not counted in sync: its node is not answering");
    if (height < 0) return append(out, cap, used, "height unknown, not counted in sync");
    if (host_ok(row)) return append(out, cap, used, "in sync");
    if (!count_of(row, "reference_height", &reference) || reference < 0)
        return append(out, cap, used, "not counted in sync: zclassicd height unknown%s",
                      strcmp(text_of(row, "synced"), "yes") ? "" : " although the node reports itself synced");
    int64_t gap = height < reference ? reference - height : height - reference;
    char by[32];
    if (gap <= IN_SYNC_SKEW) return append(out, cap, used, "not in sync: the node reports itself not synced");
    return append(out, cap, used, "not in sync: %s %s %s", zapp_grouped(gap, by), gap == 1 ? "block" : "blocks",
                  height < reference ? "behind" : "ahead of its zclassicd");
}
static size_t verdict_row(const struct json_value *row, char *out, size_t cap, size_t used)
{
    const struct json_value *reachable = json_get(row, "reachable");
    int64_t ms = 0, disk = 0;
    (void)count_of(row, "probe_ms", &ms);
    if (!reachable || reachable->type != JSON_BOOL || !json_get_bool(reachable))
        return append(out, cap, used, "\n%s: host not answering after %lld.%lld s\n", text_of(row, "host"),
            (long long)(ms / 1000), (long long)(ms % 1000 / 100));
    used = append(out, cap, used, "\n%s: ", text_of(row, "host"));
    used = verdict_text(row, out, cap, used);
    if (count_of(row, "disk_free_gb", &disk) && disk >= 0 && disk < LOW_DISK_GB)
        used = append(out, cap, used, "; low on disk, %lld GB free", (long long)disk);
    return append(out, cap, used, "\n");
}
bool zapp_hosts_verdicts(const char *json, char *out, size_t cap)
{
    return hosts_report(json, out, cap, verdict_row);
}
const char *zapp_fleet_line(const char *report, bool stale, bool paired, char *out, size_t cap)
{
    size_t n = report ? strcspn(report, "\n") : 0;
    if (stale && (n || paired)) snprintf(out, cap, "Fleet · no current report");
    else if (n && n < 140) snprintf(out, cap, "Fleet · %.*s", (int)n, report);
    else snprintf(out, cap, "%s", paired && !n ? "Fleet · checking" : "");
    return out;
}
int zapp_fleet_attention(const char *report)
{
    unsigned healthy = 0, total = 0;
    if (!report || sscanf(report, "%u of %u hosts in sync", &healthy, &total) != 2 || healthy > total) return 0;
    return (int)(total - healthy);
}
/* Label of the first host row a zapp_hosts_format report shows out of sync, or "". */
static void first_attention_host(const char *report, char *label, size_t cap)
{
    static const char sep[] = " · ";
    label[0] = 0;
    for (const char *line = report ? strchr(report, '\n') : NULL; line && *line == '\n';) {
        line++;
        size_t n = strcspn(line, "\n"), name = strspn(line, "abcdefghijklmnopqrstuvwxyz0123456789-");
        if (name && name < cap && name + sizeof(sep) - 1 <= n && !strncmp(line + name, sep, sizeof(sep) - 1) &&
            strncmp(line + name + sizeof(sep) - 1, "in sync", 7)) {
            snprintf(label, cap, "%.*s", (int)name, line);
            return;
        }
        line += n;
    }
}
/* Copies the first offered question after the one just asked, wrapping around and never repeating it. */
static void next_question(const char *const ask[], size_t count, const char *asked, char *out, size_t cap)
{
    size_t start = 0;
    bool answered = asked && asked[0];
    for (size_t i = 0; answered && i < count; i++)
        if (ask[i][0] && !strcasecmp(ask[i], asked)) start = i + 1;
    for (size_t i = 0; !out[0] && i < count; i++) {
        const char *q = ask[(start + i) % count];
        if (q[0] && !(answered && !strcasecmp(q, asked))) snprintf(out, cap, "%s", q);
    }
}
const char *zapp_suggestion(bool paired, bool responding, int64_t height, int64_t target, int64_t peers,
                            const char *report, const char *asked, char *out, size_t cap)
{
    char host[16], drill[48] = "";
    first_attention_host(report, host, sizeof(host));
    if (host[0]) snprintf(drill, sizeof(drill), "What is wrong with %s?", host);
    const char *const ask[] = {
        responding && ((peers >= 0 && peers < ZAPP_CHAIN_MIN_PEERS) || target <= 0) ? "Why is my node waiting for peers?" : "",
        responding && height >= 0 && height < target ? "How long until my node catches up?" : "",
        zapp_fleet_attention(report) > 0 ? "Which hosts need attention?" : "", drill, "How is my fleet?"};
    out[0] = 0;
    if (paired) next_question(ask, sizeof(ask) / sizeof(ask[0]), asked, out, cap);
    return out;
}
static const char *str_of(const struct json_value *root, const char *key)
{
    const char *s = json_get_str(json_get(root, key));
    return s ? s : "";
}
bool zapp_hosts_label(const char *report, size_t index, char label[16])
{
    const char *line = report ? strchr(report, '\n') : NULL;
    for (size_t row = 0; line; line = strchr(line + 1, '\n')) {
        const char *start = line + 1, *dot = strstr(start, " \xc2\xb7 "), *end = strchr(start, '\n');
        size_t n = dot ? (size_t)(dot - start) : 0;
        if (*start == '\n' || *start == ' ' || !dot || (end && dot > end) || !n || n >= 16) continue;
        if (row++ == index) { memcpy(label, start, n); label[n] = 0; return true; }
    }
    return false;
}
bool zapp_ops_view(const char *json, char *text, size_t cap, char plan[33])
{
    struct json_value root = {0};
    plan[0] = 0;
    bool ok = json && json_read(&root, json, strlen(json)) && root.type == JSON_OBJ;
    const char *host = str_of(&root, "host"), *error = str_of(&root, "error"), *body = str_of(&root, "text"),
        *action = str_of(&root, "action"), *id = str_of(&root, "plan_id");
    if (!ok) snprintf(text, cap, "The host's reply could not be read.");
    else if (error[0]) { snprintf(text, cap, "%s%s%s", host, host[0] ? ": " : "", error); ok = false; }
    else if (!strcmp(action, "errors")) snprintf(text, cap, "%s · recent errors\n%s", host, body);
    else if (!strcmp(action, "plan") && strlen(id) == 32) {
        snprintf(plan, 33, "%s", id);
        snprintf(text, cap, "%s\nTap Confirm restart to restart it, or leave it.", body);
    } else if (!strcmp(action, "confirm")) snprintf(text, cap, "%s · %s", host, body);
    else { snprintf(text, cap, "The host's reply was not understood."); ok = false; }
    json_cleanse_strings(&root); json_free(&root);
    return ok;
}
