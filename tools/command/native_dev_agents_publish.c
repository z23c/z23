/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: `fleet agents --publish` and `--fleet` — the second slice of the
 *          fleet agent dashboard, the one that leaves this box.
 *
 * `--publish` posts this box's RUNNING-NOW and GRADES rows as one
 * fleet-scoped `agents` post through the SAME `fleet_board` RPC method
 * `fleet board post` already uses — never a private file, never a
 * shell-out. `--fleet` reads the newest such post per host back through
 * `fleet board list` and merges it with this box's own live scan.
 *
 * Both fail closed exactly like `fleet board *`: no local node, no answer.
 * That is a feature here too — a dashboard that silently fell back to a
 * private file would be the same notebook problem the board exists to
 * remove.
 */

#include "command/native_dev_agents.h"

#include "controllers/rpc_client.h"
#include "fleet_enrol.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* tools/command is compiled for ZCL_TARGET=windows-x86_64 like every other
 * release translation unit, so <sys/utsname.h> cannot be reached
 * unconditionally. Same split, same reason, as
 * tools/command/native_fleet_triggers_eval.c. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/utsname.h>
#endif

#define AG_PUB_PARAMS_MAX 24576
#define AG_PUB_MINUTE 60

/* A JSON string field, or "" — every RPC reply field is read through this
 * rather than handed raw to snprintf's %s, which is undefined on NULL. */
static const char *ag_str(const struct json_value *obj, const char *key)
{
    const char *v = json_get_str(json_get(obj, key));
    return v ? v : "";
}

/* ── host name ────────────────────────────────────────────────────────── */

void zcl_agents_host_name(char *out, size_t cap)
{
    if (!out || cap == 0) return;
    out[0] = '\0';
    /* uname(), not gethostname(), and GetComputerNameA on Windows: the same
     * two calls this tree already uses to name a box
     * (tools/dev/fleet_enrol_facts.c), so this leaf costs no new external
     * symbol on either target. */
#if defined(_WIN32)
    {
        char name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD name_len = (DWORD)sizeof(name);
        if (GetComputerNameA(name, &name_len) && name[0]) {
            (void)snprintf(out, cap, "%s", name);
            return;
        }
    }
#else
    {
        struct utsname sys;
        if (uname(&sys) == 0 && sys.nodename[0]) {
            (void)snprintf(out, cap, "%s", sys.nodename);
            return;
        }
    }
#endif
    (void)snprintf(out, cap, "%s", "unknown-host");
}

/* ── the compact post body ───────────────────────────────────────────── */

/* One RUNNING-NOW row, trimmed to what a reader on another box needs: name,
 * kind, head, dirty count, process count. Ages and paths stay local. */
static size_t ag_pub_row(const struct json_value *row, char *out, size_t cap)
{
    const char *name = json_get_str(json_get(row, "name"));
    const char *kind = json_get_str(json_get(row, "kind"));
    const char *head = json_get_str(json_get(row, "head"));
    int64_t dirty = json_get_int(json_get(row, "dirty"));
    int64_t procs = json_get_int(json_get(row, "process_count"));
    return (size_t)snprintf(out, cap, "R|%s|%s|%s|%lld|%lld\n",
                            name ? name : "", kind ? kind : "",
                            head ? head : "", (long long)dirty,
                            (long long)procs);
}

/* One GRADES row: key, tasks, success, failure, success rate, letter. */
static size_t ag_pub_grade(const struct json_value *row, char *out, size_t cap)
{
    const char *key = json_get_str(json_get(row, "key"));
    const char *grade = json_get_str(json_get(row, "grade"));
    int64_t tasks = json_get_int(json_get(row, "tasks"));
    int64_t success = json_get_int(json_get(row, "success"));
    int64_t failure = json_get_int(json_get(row, "failure"));
    int64_t rate_bp = json_get_int(json_get(row, "success_rate_bp"));
    return (size_t)snprintf(out, cap, "G|%s|%lld|%lld|%lld|%lld|%s\n",
                            key ? key : "", (long long)tasks,
                            (long long)success, (long long)failure,
                            (long long)rate_bp, grade ? grade : "");
}

/* Appends rows from `arr` using `one_row`, stopping before any row would
 * push `*used` past `cap`, so a growing fleet trims rows rather than
 * overflow the board's per-post text ceiling. */
static void ag_pub_append(const struct json_value *arr,
                          size_t (*one_row)(const struct json_value *, char *,
                                            size_t),
                          char *out, size_t cap, size_t *used)
{
    if (!arr) return;
    for (size_t i = 0; i < json_size(arr); i++) {
        char line[256];
        size_t n = one_row(json_at(arr, i), line, sizeof(line));
        if (n == 0 || n >= sizeof(line) || *used + n >= cap) return;
        memcpy(out + *used, line, n);
        *used += n;
    }
}

size_t zcl_agents_publish_text(const struct json_value *running,
                               const struct json_value *grades,
                               const char *host_name, int64_t now,
                               char *out, size_t cap)
{
    size_t used = 0;
    if (!out || cap == 0) return 0;
    used = (size_t)snprintf(out, cap, "v1|host=%s|now=%lld\n",
                            host_name ? host_name : "", (long long)now);
    if (used >= cap) { out[0] = '\0'; return 0; }
    ag_pub_append(running ? json_get(running, "rows") : NULL, ag_pub_row, out,
                 cap, &used);
    ag_pub_append(grades ? json_get(grades, "rows") : NULL, ag_pub_grade, out,
                 cap, &used);
    out[used < cap ? used : cap - 1] = '\0';
    return used;
}

/* ── dedupe ──────────────────────────────────────────────────────────── */

bool zcl_agents_publish_is_duplicate(const char *prev_text,
                                     int64_t prev_created, const char *candidate,
                                     int64_t now)
{
    if (!prev_text || !candidate) return false;
    if (strcmp(prev_text, candidate) != 0) return false;
    return prev_created / AG_PUB_MINUTE == now / AG_PUB_MINUTE;
}

/* ── the local node RPC round trip ──────────────────────────────────── */

/* One `fleet_board` call. Mirrors native_fleet_board_command.c's own round
 * trip exactly (same method, same JSON-array-of-one-object envelope) rather
 * than a second client: this leaf reuses the model by calling the node the
 * same way the board CLI does, never by shelling out to it. `in` is written
 * through `json_write`, which owns escaping, so a post body carrying
 * newlines or quotes is never hand-spliced into the wire bytes. `body` is
 * filled with the node's answer on true; a transport failure or a board
 * refusal both return false with `body` set to a synthesized
 * `{"ok":false,...}`. */
static bool ag_pub_call(const struct json_value *in, struct json_value *body)
{
    char params[AG_PUB_PARAMS_MAX];
    params[0] = '[';
    size_t n = json_write(in, params + 1, sizeof(params) - 2);
    if (n == 0 || n >= sizeof(params) - 2) {
        json_set_object(body);
        (void)json_push_kv_bool(body, "ok", false);
        return false;
    }
    params[1 + n] = ']';
    params[2 + n] = '\0';
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call("fleet_board", params);
    if (!raw || !json_read(body, raw, strlen(raw)) || body->type != JSON_OBJ) {
        free(raw);
        json_set_object(body);
        (void)json_push_kv_bool(body, "ok", false);
        return false;
    }
    free(raw);
    return json_get_bool(json_get(body, "ok"));
}

/* The one refusal that matters, worded exactly like `fleet board`'s own: no
 * private copy exists, so no node means no publish and no fleet merge. */
static void ag_pub_no_node(struct zcl_command_reply *reply)
{
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "NODE_UNAVAILABLE", "dispatch", true, false,
        "no local node answered; --publish and --fleet read and write the "
        "board through it. Start one with `build/bin/zclassic23 -daemon`.",
        "fleet.agents");
    (void)zcl_command_reply_add_next(reply, "core.status", "{}",
                                     "confirm a local node is running");
}

/* This node's own board identity, as hex, via `fleet_board status` — never
 * a second identity file, and status creates no key of its own. */
static bool ag_pub_own_host_hex(char *out, size_t cap)
{
    struct json_value in, body;
    json_init(&in); json_init(&body);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "status");
    bool ok = ag_pub_call(&in, &body);
    const char *host = ok ? json_get_str(json_get(&body, "host")) : NULL;
    if (host) (void)snprintf(out, cap, "%s", host);
    json_free(&in); json_free(&body);
    return host != NULL;
}

/* This box's most recent own `agents` post, if any: its text and the minute
 * it was made, the two facts the dedupe check needs. Returns false when
 * there is none yet — the very first publish is never a duplicate. */
static bool ag_pub_latest_own(const char *host_hex, char *text, size_t cap,
                              int64_t *created_at)
{
    struct json_value in, body;
    json_init(&in); json_init(&body);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "list");
    (void)json_push_kv_str(&in, "kind", "agents");
    (void)json_push_kv_str(&in, "scope", "fleet");
    (void)json_push_kv_str(&in, "host", host_hex);
    (void)json_push_kv_int(&in, "limit", 1);
    bool ok = ag_pub_call(&in, &body);
    const struct json_value *posts = ok ? json_get(&body, "posts") : NULL;
    bool found = posts && json_size(posts) > 0;
    if (found) {
        const struct json_value *p = json_at(posts, 0);
        (void)snprintf(text, cap, "%s", ag_str(p, "text"));
        *created_at = json_get_int(json_get(p, "created_at"));
    }
    json_free(&in); json_free(&body);
    return found;
}

void zcl_agents_do_publish(const struct zcl_agents_options *options,
                           const struct json_value *running,
                           const struct json_value *grades,
                           struct zcl_command_reply *reply)
{
    char host_name[128], host_hex[65], candidate[ZCL_AGENTS_PUBLISH_TEXT_MAX + 1];
    char prev_text[ZCL_AGENTS_PUBLISH_TEXT_MAX + 1] = "";
    int64_t prev_created = 0;

    zcl_agents_host_name(host_name, sizeof(host_name));
    (void)zcl_agents_publish_text(running, grades, host_name,
                                  options->now_unix, candidate,
                                  sizeof(candidate));
    if (!ag_pub_own_host_hex(host_hex, sizeof(host_hex))) {
        ag_pub_no_node(reply);
        return;
    }
    bool have_prev = ag_pub_latest_own(host_hex, prev_text, sizeof(prev_text),
                                       &prev_created);
    bool duplicate = have_prev &&
        zcl_agents_publish_is_duplicate(prev_text, prev_created, candidate,
                                        options->now_unix);

    json_set_object(&reply->data);
    (void)json_push_kv_str(&reply->data, "schema", "zcl.fleet_agents_publish.v1");
    (void)json_push_kv_str(&reply->data, "host", host_name);
    if (duplicate) {
        (void)json_push_kv_bool(&reply->data, "posted", false);
        (void)json_push_kv_str(&reply->data, "note",
                               "unchanged since the last publish this minute; "
                               "not reposted");
        return;
    }
    struct json_value in, body;
    json_init(&in); json_init(&body);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "op", "post");
    (void)json_push_kv_str(&in, "kind", "agents");
    (void)json_push_kv_str(&in, "scope", "fleet");
    (void)json_push_kv_str(&in, "agent", host_name);
    (void)json_push_kv_str(&in, "text", candidate);
    bool ok = ag_pub_call(&in, &body);
    json_free(&in);
    if (!ok) {
        json_free(&reply->data);
        ag_pub_no_node(reply);
        json_free(&body);
        return;
    }
    (void)json_push_kv_bool(&reply->data, "posted", true);
    (void)json_push_kv_str(&reply->data, "id", ag_str(&body, "id"));
    json_free(&body);
}

/* ── --fleet: read the board back and merge ─────────────────────────── */

/* The self-reported name from another host's own post header
 * (`v1|host=<name>|now=<n>`). This box never learned that name from any
 * registry: no seam in this tree maps a board key to a human name today
 * (the fleet machine roster keys enrolment identities, not board DHT
 * identities), so each host names itself in its own publish, the same way
 * `agent` already names a post's author for a human reader. */
static void ag_parse_header_name(const char *text, char *name, size_t cap)
{
    const char *h = text ? strstr(text, "host=") : NULL;
    name[0] = '\0';
    if (!h) return;
    h += 5;
    const char *end = strpbrk(h, "|\n");
    size_t len = end ? (size_t)(end - h) : strlen(h);
    if (len >= cap) len = cap - 1;
    memcpy(name, h, len);
    name[len] = '\0';
}

static bool ag_host_seen(char (*seen)[65], size_t n, const char *hex)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(seen[i], hex) == 0) return true;
    return false;
}

/* Lines beginning `prefix|` in a publish body: the row counts a reader on
 * another box can get without re-running anything. */
static int64_t ag_count_lines(const char *text, char prefix)
{
    int64_t n = 0;
    for (const char *p = text; p && *p; p++)
        if (*p == prefix && p[1] == '|' && (p == text || p[-1] == '\n')) n++;
    return n;
}

static void ag_push_host_row(struct json_value *hosts, const char *name,
                             const char *hex, int64_t age_s, bool is_self,
                             int64_t running_rows, int64_t grade_rows)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", name && name[0] ? name : hex);
    (void)json_push_kv_str(&row, "host", hex);
    (void)json_push_kv_bool(&row, "self", is_self);
    (void)json_push_kv_int(&row, "age_s", age_s);
    (void)json_push_kv_bool(&row, "stale",
                            !is_self && age_s > ZCL_AGENTS_STALE_SECONDS);
    (void)json_push_kv_int(&row, "running_rows", running_rows);
    (void)json_push_kv_int(&row, "grade_rows", grade_rows);
    (void)json_push_back(hosts, &row);
    json_free(&row);
}

/* This box's own count is always current; every other host's is whatever
 * `agents` post is newest in the local board replica, which the RPC list
 * already returns newest-first, so the first occurrence of a host wins. */
static size_t ag_fold_posts(const struct json_value *posts, int64_t now,
                            struct json_value *hosts)
{
    char seen[ZCL_AGENTS_MAX_HOST_ROWS][65];
    size_t seen_n = 0;
    for (size_t i = 0; posts && i < json_size(posts) &&
                       seen_n < ZCL_AGENTS_MAX_HOST_ROWS; i++) {
        const struct json_value *p = json_at(posts, i);
        const char *hex = ag_str(p, "host");
        if (!hex[0] || ag_host_seen(seen, seen_n, hex)) continue;
        (void)snprintf(seen[seen_n++], 65, "%s", hex);
        char name[128];
        const char *text = ag_str(p, "text");
        ag_parse_header_name(text, name, sizeof(name));
        int64_t created = json_get_int(json_get(p, "created_at"));
        ag_push_host_row(hosts, name, hex, now - created, false,
                         ag_count_lines(text, 'R'), ag_count_lines(text, 'G'));
    }
    return seen_n;
}

/* How many boxes this fleet has ever admitted, from the machine roster
 * (tools/dev/fleet_enrol.h) — the one durable, signed count of "how many
 * machines" that exists in this tree today. Falls back to `reporting`
 * (never claims fewer machines than are visibly answering) when this box
 * has no roster of its own to read. */
static void ag_noop_visit(const struct fleet_machine *m, void *user)
{ (void)m; (void)user; }

static int64_t ag_known_hosts(int64_t reporting)
{
    uint8_t operator_pubkey[FLEET_ENROL_PUBKEY_BYTES];
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own[FLEET_ENROL_PUBKEY_BYTES];
    struct fleet_roster_scan scan = {0};
    const char *why = NULL;
    bool joined = false, present = false;
    if (!fleet_enrol_operator_read(operator_pubkey, &joined, &why))
        return reporting;
    if (!joined) {
        if (!fleet_enrol_key_load(seed, own, false, &present, &why) ||
            !present)
            return reporting;
        memcpy(operator_pubkey, own, FLEET_ENROL_PUBKEY_BYTES);
    }
    if (!fleet_roster_each(operator_pubkey, ag_noop_visit, NULL, &scan, &why))
        return reporting;
    int64_t total = (int64_t)scan.rows + 1; /* +1: this box, not on its own roster */
    return total > reporting ? total : reporting;
}

static void ag_merge_note(char *out, size_t cap, int64_t reporting,
                          int64_t known, bool board_read)
{
    (void)snprintf(out, cap,
                   "hosts reporting: %lld of %lld known (stale > 15m marked)%s",
                   (long long)reporting, (long long)known,
                   board_read ? "" : " — no local node to read the board");
}

void zcl_agents_do_fleet_merge(const struct json_value *running,
                               const struct json_value *grades,
                               int64_t now, struct json_value *out)
{
    char host_name[128], note[192];
    struct json_value in, body, hosts;
    zcl_agents_host_name(host_name, sizeof(host_name));
    json_init(&in); json_init(&body); json_init(&hosts);
    json_set_object(&in); json_set_array(&hosts);
    (void)json_push_kv_str(&in, "op", "list");
    (void)json_push_kv_str(&in, "kind", "agents");
    (void)json_push_kv_str(&in, "scope", "fleet");
    (void)json_push_kv_int(&in, "limit", (int64_t)ZCL_AGENTS_MAX_HOST_ROWS);
    bool ok = ag_pub_call(&in, &body);
    json_free(&in);

    ag_push_host_row(&hosts, host_name, "self", 0, true,
                     running ? (int64_t)json_size(json_get(running, "rows")) : 0,
                     grades ? (int64_t)json_size(json_get(grades, "rows")) : 0);
    size_t others = ok ? ag_fold_posts(json_get(&body, "posts"), now, &hosts) : 0;
    json_free(&body);

    int64_t reporting = (int64_t)others + 1;
    int64_t known = ag_known_hosts(reporting);
    json_set_object(out);
    (void)json_push_kv_str(out, "schema", "zcl.fleet_agents_fleet.v1");
    (void)json_push_kv_str(out, "state", ok ? "observed" : "unavailable");
    (void)json_push_kv_int(out, "hosts_reporting", reporting);
    (void)json_push_kv_int(out, "hosts_known", known);
    ag_merge_note(note, sizeof(note), reporting, known, ok);
    (void)json_push_kv_str(out, "note", note);
    (void)json_push_kv(out, "hosts", &hosts);
    json_free(&hosts);
}
