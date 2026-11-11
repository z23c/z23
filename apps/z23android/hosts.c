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
struct chain_verdict { enum zapp_chain state; int64_t reference; char reason[48]; bool onion_wait; };
static int64_t abs_gap(int64_t a, int64_t b) { return a > b ? a - b : b - a; }
/* Why a node within the skew still cannot confirm its chain is current, or false when it can. */
static bool unconfirmed_reason(bool fleet_agrees, int64_t peers, int64_t quiet, char *reason, size_t cap)
{
    if (fleet_agrees) return false;
    if (peers < ZAPP_CHAIN_MIN_PEERS)
        snprintf(reason, cap, peers == 1 ? "only 1 peer" : peers == 0 ? "no peers" : "peer count unknown");
    else if (quiet > ZAPP_CHAIN_QUIET_SECS)
        snprintf(reason, cap, "no new block for %lld min", (long long)(quiet / 60));
    else return false;
    return true;
}
static struct chain_verdict chain_verdict(int64_t height, int64_t target, int64_t peers,
                                          const struct zapp_chain_evidence *ev)
{
    const int64_t fleet = ev ? ev->fleet_height : -1, quiet = ev ? ev->quiet_secs : -1;
    struct chain_verdict v = {.reference = target > fleet ? target : fleet};
    const bool fleet_agrees = fleet >= 0 && abs_gap(fleet, height) <= ZAPP_CHAIN_SKEW;
    /* Private mode dials only onion peers, so too few peers there means too few onion peers. */
    v.onion_wait = ev && ev->onion_only && !fleet_agrees && peers < ZAPP_CHAIN_MIN_PEERS;
    if (v.reference <= 0) { v.state = ZAPP_CHAIN_WAITING; return v; }
    if (v.reference - height > ZAPP_CHAIN_SKEW) { v.state = ZAPP_CHAIN_BEHIND; return v; }
    v.state = unconfirmed_reason(fleet_agrees, peers, quiet, v.reason, sizeof(v.reason)) ? ZAPP_CHAIN_UNCONFIRMED : ZAPP_CHAIN_CURRENT;
    return v;
}
/* "1 of 2" for a reported count, "count unknown" when the node reported none. */
static const char *onion_count(int64_t peers, char *out, size_t cap)
{
    if (peers >= 0) snprintf(out, cap, "%lld of %d", (long long)peers, ZAPP_CHAIN_MIN_PEERS);
    else snprintf(out, cap, "count unknown");
    return out;
}
const char *zapp_node_line(bool responding, bool process_running, bool stopping, bool onion_ready,
                           int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap)
{
    char at[32], top[32], count[40] = "", ratio[32];
    const char *onion = responding ? (onion_ready ? " · onion ready" : " · onion starting") : "";
    if (peers >= 0) snprintf(count, sizeof(count), " · %lld %s", (long long)peers, peers == 1 ? "peer" : "peers");
    const struct chain_verdict v = chain_verdict(height, target, peers, evidence);
    if (stopping) snprintf(out, cap, "Node stopping");
    else if (!responding) snprintf(out, cap, "Node %s", process_running ? "starting" : "stopped");
    else if (height < 0) snprintf(out, cap, "Node running%s%s", count, onion);
    else if (v.onion_wait)
        snprintf(out, cap, "Private · waiting for onion peers (%s)%s", onion_count(peers, ratio, sizeof(ratio)), onion);
    else if (v.state == ZAPP_CHAIN_WAITING) snprintf(out, cap, "Node waiting for peers · %s%s", zapp_grouped(height, at), onion);
    else if (v.state == ZAPP_CHAIN_BEHIND)
        snprintf(out, cap, "Behind · %s of %s%s", zapp_grouped(height, at), zapp_grouped(v.reference, top), onion);
    else if (v.state == ZAPP_CHAIN_UNCONFIRMED)
        snprintf(out, cap, "Height %s · %s, cannot confirm it is current%s", zapp_grouped(height, at), v.reason, onion);
    else snprintf(out, cap, "Node in sync · %s%s%s", zapp_grouped(height, at), count, onion);
    return out;
}
enum zapp_pace zapp_getnodepace_pace(const char *reply)
{
    struct json_value root = {0};
    enum zapp_pace pace = ZAPP_PACE_NORMAL;
    if (!reply || !json_read(&root, reply, strlen(reply))) return pace;
    const char *word = json_get_str(json_get(json_get(&root, "result"), "pace"));
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
    else if (process_running && pace == ZAPP_PACE_PAUSE) text = ZAPP_PAUSED_LINE;
    snprintf(out, cap, "%s", text ? text : "");
    return out;
}
const char *zapp_paced_sync_line(enum zapp_pace pace, bool process_running, bool stopping, const char *sync_line,
                                 char *out, size_t cap)
{
    const bool paused = process_running && !stopping && pace == ZAPP_PACE_PAUSE;
    const char *text = paused ? ZAPP_PAUSED_LINE : sync_line;
    snprintf(out, cap, "%s", text ? text : "");
    return out;
}
const char *zapp_sync_line(bool responding, bool process_running, int64_t height, int64_t target, int64_t peers,
                           const struct zapp_chain_evidence *evidence, char *out, size_t cap)
{
    char gap[32];
    char ratio[32];
    const struct chain_verdict v = chain_verdict(height, target, peers, evidence);
    if (!responding) snprintf(out, cap, "%s", process_running ?
        "Waiting for the node to answer." : "Start the node to begin synchronization.");
    else if (height < 0) snprintf(out, cap, "Waiting for the node to report its height.");
    else if (v.onion_wait && peers < 0)
        snprintf(out, cap, "Private mode dials only onion peers. The node has not reported its peer count.");
    else if (v.onion_wait)
        snprintf(out, cap, "Private mode dials only onion peers. This node has %s.", onion_count(peers, ratio, sizeof(ratio)));
    else if (v.state == ZAPP_CHAIN_WAITING) snprintf(out, cap, "Waiting for a peer that reports the current chain.");
    else if (v.state == ZAPP_CHAIN_BEHIND) snprintf(out, cap, "%s %s to go.", zapp_grouped(v.reference - height, gap),
                                            v.reference - height == 1 ? "block" : "blocks");
    else if (v.state == ZAPP_CHAIN_UNCONFIRMED)
        snprintf(out, cap, "Your node has every block it can see, but with %s it cannot confirm it is current.", v.reason);
    else snprintf(out, cap, "Your node has every block its peers report.");
    return out;
}
struct zapp_chain_status zapp_chain_check(int64_t height, int64_t target, int64_t peers, const struct zapp_chain_evidence *evidence)
{
    struct zapp_chain_status status = {.state = ZAPP_CHAIN_NONE, .reference = -1};
    if (height < 0) return status;
    const struct chain_verdict v = chain_verdict(height, target, peers, evidence);
    status.state = v.state;
    status.reference = v.reference > 0 ? v.reference : -1;
    if (v.state == ZAPP_CHAIN_UNCONFIRMED) snprintf(status.reason, sizeof(status.reason), "%s", v.reason);
    else if (v.state == ZAPP_CHAIN_WAITING) snprintf(status.reason, sizeof(status.reason), "No peer has reported a block height yet");
    return status;
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
    else if (!strcmp(action, "plugins")) snprintf(text, cap, "%s · plugin inventory\n%s", host, body);
    else if (!strcmp(action, "plan") && strlen(id) == 32) {
        snprintf(plan, 33, "%s", id);
        snprintf(text, cap, "%s\nTap Confirm restart to restart it, or leave it.", body);
    } else if (!strcmp(action, "confirm")) snprintf(text, cap, "%s · %s", host, body);
    else { snprintf(text, cap, "The host's reply was not understood."); ok = false; }
    json_cleanse_strings(&root); json_free(&root);
    return ok;
}
/* True when text[0..len) is one token of [a-z0-9-]. */
static bool name_token(const char *text, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (!((text[i] >= 'a' && text[i] <= 'z') || (text[i] >= '0' && text[i] <= '9') || text[i] == '-')) return false;
    return len > 0;
}
/* Roster lines as written by zapp_fleet_onion_peers: the onion token, then an optional name. */
static bool roster_new(const char *line, size_t token, char onion[][ZAPP_ONION_PEER_MAX + 1], size_t known)
{
    char one[ZAPP_ONION_PEER_MAX + 1];
    memcpy(one, line, token);
    one[token] = 0;
    if (!zapp_onion_peer_valid(one)) return false;
    for (size_t i = 0; i < known; i++)
        if (!strcmp(onion[i], one)) return false;
    return true;
}
static size_t roster_parse(const char *text, char onion[][ZAPP_ONION_PEER_MAX + 1], struct zapp_fleet_peers *out)
{
    size_t known = 0;
    for (const char *line = text; line && *line && known < ZAPP_PRIVATE_PEERS_MAX; line += strcspn(line, "\n"), line += *line == '\n') {
        const size_t end = strcspn(line, "\n"), token = strcspn(line, " \n");
        if (!token || token > ZAPP_ONION_PEER_MAX || !roster_new(line, token, onion, known)) continue;
        memcpy(onion[known], line, token);
        onion[known][token] = 0;
        const size_t name = end > token + 1 && line[token] == ' ' ? end - token - 1 : 0;
        if (name && name <= ZAPP_FLEET_NAME_MAX && name_token(line + token + 1, name)) memcpy(out->peer[known].name, line + token + 1, name);
        known++;
    }
    return known;
}
/* Marks the roster entry that peer's addr names as connected and folds its best_height into the two highest. */
static void peer_connect(const struct json_value *peer, char onion[][ZAPP_ONION_PEER_MAX + 1], struct zapp_fleet_peers *out,
                         int64_t *top, int64_t *second)
{
    const char *addr = peer && peer->type == JSON_OBJ ? json_get_str(json_get(peer, "addr")) : NULL;
    for (size_t k = 0; addr && k < out->known; k++) {
        if (out->peer[k].connected || strcmp(addr, onion[k])) continue;
        int64_t height = -1;
        (void)count_of(peer, "best_height", &height);
        out->peer[k].connected = true;
        out->connected++;
        if (height > *top) { *second = *top; *top = height; }
        else if (height > *second) *second = height;
    }
}
bool zapp_fleet_peers(const char *peerinfo_json, const char *roster_text, struct zapp_fleet_peers *out)
{
    char onion[ZAPP_PRIVATE_PEERS_MAX][ZAPP_ONION_PEER_MAX + 1] = {{0}};
    int64_t top = -1, second = -1;
    memset(out, 0, sizeof(*out));
    out->height = -1;
    out->known = roster_parse(roster_text, onion, out);
    struct json_value root = {0};
    const bool read = peerinfo_json && json_read(&root, peerinfo_json, strlen(peerinfo_json));
    const struct json_value *list = read && root.type == JSON_OBJ ? json_get(&root, "result") : read ? &root : NULL;
    const bool ok = list && list->type == JSON_ARR;
    for (size_t i = 0; ok && i < list->num_children; i++) peer_connect(json_at(list, i), onion, out, &top, &second);
    out->height = second;
    json_free(&root);
    return ok;
}
/* Appends names joined as "a", "a and b" or "a, b and c": those with connected == want. */
static size_t join_names(const struct zapp_fleet_peers *p, bool want, char *out, size_t cap, size_t used)
{
    size_t left = 0;
    for (size_t i = 0; i < p->known; i++) left += p->peer[i].connected == want;
    for (size_t i = 0; i < p->known; i++) {
        if (p->peer[i].connected != want) continue;
        used = append(out, cap, used, "%s%s", p->peer[i].name, --left > 1 ? ", " : left == 1 ? " and " : "");
    }
    return used;
}
const char *zapp_fleet_peers_line(const struct zapp_fleet_peers *p, char *out, size_t cap)
{
    bool named = p->known > 0;
    for (size_t i = 0; i < p->known; i++) named = named && p->peer[i].name[0];
    size_t used = append(out, cap, 0, ZAPP_FLEET_LINE_PREFIX);
    if (!p->known) used = append(out, cap, used, "not paired yet");
    else if (!p->connected) used = append(out, cap, used, "not connected yet");
    else if (!named) used = append(out, cap, used, "%zu of %zu connected", p->connected, p->known);
    else {
        used = join_names(p, true, out, cap, used);
        used = append(out, cap, used, " connected");
        if (p->connected < p->known) {
            used = append(out, cap, used, " \xc2\xb7 ");
            used = join_names(p, false, out, cap, used);
            used = append(out, cap, used, " not reachable");
        }
    }
    char grouped[32];
    if (p->height >= 0) used = append(out, cap, used, " \xc2\xb7 at %s", zapp_grouped(p->height, grouped));
    if (used >= cap && cap) out[cap - 1] = 0;
    return out;
}
bool zapp_fleet_laptop_current(bool laptop_source, bool stale)
{
    return laptop_source && !stale;
}
bool zapp_fleet_peers_wanted(bool laptop_source, bool laptop_stale, const struct zapp_fleet_peers *peers, bool paired)
{
    return !zapp_fleet_laptop_current(laptop_source, laptop_stale) && !(paired && !peers->known);
}
