/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: fleet.vitals.table - one table of every named machine's load,
 *          memory and disk, measured now.
 *
 * Read-only. A local row calls the shared measurement directly
 * (zcl_fleet_vitals_measure). A remote row spawns ONE fixed ssh argv whose
 * ProxyCommand is this binary's raw HOST client and whose remote command is
 * the fixed read leaf `<slot> fleet vitals read --json`; stdout is captured
 * (64 KiB) under the per-machine deadline and its zcl.result.v1 `data` is
 * taken. Remote rows run on their own threads, so the wall time is about the
 * slowest machine, not the sum. Nothing is written locally or remotely.
 *
 * INPUT  machines[1..16] {label [a-z0-9-]{1,16}, and either local:true or
 *        route_file (absolute path of a client.json), slot (absolute path of
 *        the REMOTE z23) and host_alias [A-Za-z0-9._-]{1,64}};
 *        deadline_ms 1000..20000 (default 8000).
 * NO INPUT (no machines key): this box alone, measured now, with a note on
 *        what a remote row needs. Never a refusal. Fleet ledger vitals rows do
 *        not replicate between hosts, so no recorded remote row is shown.
 * OUTPUT zcl.fleet_vitals_table.v1: rows[] (input order; each carries age_s 0,
 *        spare_cores_centi, load1_per_core_centi, jobs_running, jobs_queued and
 *        spare_rank), best, advice, age_note and screen (rank order). A machine that fails
 *        is {label, reachable:false, error}; it never fails the call. Error
 *        codes: DEADLINE, SPAWN_FAILED, REMOTE_EXIT, BAD_REPLY,
 *        SSH_UNRESOLVED, SELF_UNRESOLVED.
 * REFUSALS (before any spawn) TABLE_INPUT_REFUSED, TABLE_TOO_MANY_MACHINES,
 *        TABLE_LABEL_REFUSED, TABLE_ALIAS_REFUSED, TABLE_ROUTE_REFUSED,
 *        TABLE_SLOT_REFUSED, TABLE_DEADLINE_REFUSED. */

/* Z23_TOOL_V1
{
  "profile": "readonly-local-v1",
  "path": "fleet.vitals.table",
  "parent": "fleet.vitals",
  "handler": "zcl_native_handle_fleet_vitals_table",
  "summary": "Which machine has spare CPU: load, queue, memory and disk per machine",
  "semantics": [
    "Measures this box and, for each named remote machine, runs the fixed ",
    "read leaf fleet vitals read over the host tunnel with one pinned ssh ",
    "argv, concurrently, each under its own deadline. At most 16 machines. ",
    "A machine that cannot be reached shows as unreachable with an error ",
    "code and never fails the call. With no input it shows this box alone. ",
    "Each row carries spare cores, build queue depth and age, and the screen ",
    "ranks machines by spare cores; every number is measured during the ",
    "call. It writes nothing."
  ],
  "input_schema": "zcl.fleet_vitals_table_input.v1",
  "output_schema": "zcl.fleet_vitals_table.v1",
  "input_keys": ["machines", "deadline_ms"],
  "example": "z23 fleet vitals table",
  "tags": ["fleet", "vitals", "table", "load", "memory", "disk", "machines"],
  "authority": "operator",
  "budget_bytes": 32768,
  "latency": "foreground",
  "cost": "low",
  "test_group": "fleet_vitals_table"
}
*/

#include "command/native_command.h"
#include "command/native_fleet.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/spawn.h"
#include "util/workpool.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define VT_MACHINES_MAX 16u
#define VT_CAPTURE_MAX (64u * 1024u)
#define VT_DEADLINE_MIN 1000
#define VT_DEADLINE_MAX 20000
#define VT_DEADLINE_DEFAULT 8000
#define VT_BAR_CELLS 20

struct vt_machine {
    char label[17];
    bool local;
    bool no_route; /* valid input with no tunnel route: shown, never probed */
    char route[1024];
    char slot[1024];
    char alias[65];
    /* outcome */
    bool reachable;
    char error[24];
    int64_t rtt_ms;
    struct zcl_fleet_vitals_now now;
    bool implicit;      /* the no-input default row */
    int64_t spare_centi; /* (cpus - load1) * 100; INT64_MIN when unknown */
    int rank;           /* 1 = most spare capacity; 0 = not ranked */
    /* remote plumbing */
    const char *ssh;
    const char *self;
    int deadline_ms;
    char *capture;
};

/* ---- charset (the host shell's: nothing a shell or ssh would reread) --- */

static bool vt_alnum(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static bool vt_token_byte(unsigned char c)
{
    return vt_alnum(c) || c == '.' || c == '_' || c == '-';
}

static bool vt_token_valid(const char *text, size_t maximum)
{
    if (!text || !vt_alnum((unsigned char)text[0]))
        return false;
    size_t length = strnlen(text, maximum + 1);
    if (length > maximum)
        return false;
    for (size_t i = 0; i < length; ++i)
        if (!vt_token_byte((unsigned char)text[i]))
            return false;
    return true;
}

static bool vt_component_valid(const char *c, size_t size)
{
    if (!size || (size == 1 && c[0] == '.') || (size == 2 && !memcmp(c, "..", 2)))
        return false;
    for (size_t i = 0; i < size; ++i)
        if (!vt_token_byte((unsigned char)c[i]))
            return false;
    return true;
}

static bool vt_path_valid(const char *path)
{
    if (!path || path[0] != '/')
        return false;
    size_t length = strnlen(path, 1024);
    if (length >= 1024 || length < 2)
        return false;
    for (const char *c = path + 1; c <= path + length;) {
        const char *end = strchr(c, '/');
        size_t size = end ? (size_t)(end - c) : strlen(c);
        if (!vt_component_valid(c, size))
            return false;
        c += size + 1;
    }
    return true;
}

static bool vt_regular_file(const char *path)
{
#if !defined(_WIN32)
    struct stat st;
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
#else
    (void)path;
    return false;
#endif
}

static bool vt_label_valid(const char *s)
{
    size_t n = s ? strnlen(s, 17) : 0;
    if (n < 1 || n > 16)
        return false;
    for (size_t i = 0; i < n; ++i)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-'))
            return false;
    return true;
}

/* ---- input ------------------------------------------------------------- */

static void vt_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence)
{
    json_free(&reply->data);
    json_init(&reply->data);
    json_set_object(&reply->data);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "read", false,
                           false, message, evidence);
}

static const char *vt_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = json_get(o, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool vt_keys_known(const struct json_value *o, const char *const *keys, size_t n)
{
    for (size_t i = 0; i < o->num_children; ++i) {
        bool known = false;
        for (size_t k = 0; k < n; ++k)
            known = known || (o->keys[i] && !strcmp(o->keys[i], keys[k]));
        if (!known)
            return false;
    }
    return true;
}

/* The three remote fields, or the refusal code. */
static const char *vt_remote_refusal(const char *route, const char *slot, const char *alias)
{
    if (!route || !slot || !alias)
        return "TABLE_INPUT_REFUSED";
    if (!vt_token_valid(alias, 64))
        return "TABLE_ALIAS_REFUSED";
    if (!vt_path_valid(route) || !vt_regular_file(route))
        return "TABLE_ROUTE_REFUSED";
    if (!vt_path_valid(slot))
        return "TABLE_SLOT_REFUSED";
    return NULL;
}

/* A machine with no route is valid input (shown as no_route, never probed);
 * one with a route needs a valid slot and alias too. */
static const char *vt_route_fields(struct vt_machine *m, const char *route,
                                   const char *slot, const char *alias)
{
    if (!route) {
        if (slot && !vt_path_valid(slot))
            return "TABLE_SLOT_REFUSED";
        if (alias && !vt_token_valid(alias, 64))
            return "TABLE_ALIAS_REFUSED";
        m->no_route = true;
        return NULL;
    }
    const char *why = vt_remote_refusal(route, slot, alias);
    if (why)
        return why;
    snprintf(m->route, sizeof m->route, "%s", route);
    snprintf(m->slot, sizeof m->slot, "%s", slot);
    snprintf(m->alias, sizeof m->alias, "%s", alias);
    return NULL;
}

/* One machine object; returns the refusal code or NULL. */
static const char *vt_machine_parse(const struct json_value *o, struct vt_machine *m)
{
    static const char *const keys[] = {"label", "local", "route_file", "slot", "host_alias"};
    if (!o || o->type != JSON_OBJ || !vt_keys_known(o, keys, 5))
        return "TABLE_INPUT_REFUSED";
    const char *label = vt_str(o, "label");
    if (!vt_label_valid(label))
        return "TABLE_LABEL_REFUSED";
    snprintf(m->label, sizeof m->label, "%s", label);
    const struct json_value *local = json_get(o, "local");
    const char *route = vt_str(o, "route_file"), *slot = vt_str(o, "slot"),
               *alias = vt_str(o, "host_alias");
    if (local) {
        if (local->type != JSON_BOOL || !json_get_bool(local) || route || slot || alias)
            return "TABLE_INPUT_REFUSED";
        m->local = true;
        return NULL;
    }
    return vt_route_fields(m, route, slot, alias);
    return NULL;
}

static bool vt_deadline(const struct json_value *input, int *out)
{
    const struct json_value *d = input ? json_get(input, "deadline_ms") : NULL;
    *out = VT_DEADLINE_DEFAULT;
    if (!d)
        return true;
    if (d->type != JSON_INT)
        return false;
    int64_t v = json_get_int(d);
    if (v < VT_DEADLINE_MIN || v > VT_DEADLINE_MAX)
        return false;
    *out = (int)v;
    return true;
}

/* Parse every entry; the refusal code of the first bad one, or NULL. */
static const char *vt_parse_list(const struct json_value *list, struct vt_machine *m)
{
    for (size_t i = 0; i < json_size(list); ++i) {
        memset(&m[i], 0, sizeof m[i]);
        const char *why = vt_machine_parse(json_at(list, i), &m[i]);
        if (why)
            return why;
        for (size_t j = 0; j < i; ++j)
            if (!strcmp(m[i].label, m[j].label))
                return "TABLE_LABEL_REFUSED";
    }
    return NULL;
}

/* The list shape, count and deadline; the refusal code or NULL. */
static const char *vt_shape_refusal(const struct json_value *list, const struct json_value *input,
                                    int *deadline)
{
    if (!list || list->type != JSON_ARR || json_size(list) == 0)
        return "TABLE_INPUT_REFUSED";
    if (json_size(list) > VT_MACHINES_MAX)
        return "TABLE_TOO_MANY_MACHINES";
    if (!vt_deadline(input, deadline))
        return "TABLE_DEADLINE_REFUSED";
    return NULL;
}

/* Lowercase letters and digits pass, a dot or hyphen after the first byte
 * becomes a hyphen, anything else is dropped; at most 16 bytes. */
static size_t vt_label_from_host(const char *host, char label[17])
{
    size_t n = 0;
    for (const char *c = host; *c && n < 16; ++c) {
        char ch = (*c >= 'A' && *c <= 'Z') ? (char)(*c - 'A' + 'a') : *c;
        bool alnum = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (alnum)
            label[n++] = ch;
        else if (n > 0 && (ch == '-' || ch == '.'))
            label[n++] = '-';
    }
    label[n] = 0;
    return n;
}

/* The no-input row: this box, labelled from its host name, measured now. */
static void vt_default_machine(struct vt_machine *m)
{
    char host[65] = "";
    memset(m, 0, sizeof *m);
#if !defined(_WIN32)
    if (gethostname(host, sizeof host - 1) != 0)
        host[0] = 0;
#endif
    if (vt_label_from_host(host, m->label) == 0)
        snprintf(m->label, sizeof m->label, "this-box");
    m->local = true;
    m->implicit = true;
}

/* Fills `m`/`count` or the refusal; nothing is spawned here. */
static bool vt_input(const struct zcl_command_request *request,
                     struct vt_machine m[VT_MACHINES_MAX], size_t *count,
                     int *deadline, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *list = input ? json_get(input, "machines") : NULL;
    struct json_value parsed = {0};
    const char *why = NULL;
    if (!list) { /* no machines key at all: this box alone, never a refusal */
        if (!vt_deadline(input, deadline)) {
            vt_refuse(reply, "TABLE_DEADLINE_REFUSED",
                      "deadline_ms is 1000 to 20000; refused before any spawn", "deadline_ms");
            return false;
        }
        vt_default_machine(&m[0]);
        *count = 1;
        return true;
    }
    if (list && list->type == JSON_STR) { /* the CLI may carry it as JSON text */
        const char *text = json_get_str(list);
        if (!text || !json_read(&parsed, text, strlen(text)))
            why = "TABLE_INPUT_REFUSED";
        list = &parsed;
    }
    if (!why)
        why = vt_shape_refusal(list, input, deadline);
    if (!why)
        why = vt_parse_list(list, m);
    *count = why ? 0 : json_size(list);
    if (why)
        vt_refuse(reply, why, "machines is 1 to 16 valid machine objects; refused before any spawn",
                  "machines");
    json_free(&parsed);
    return why == NULL;
}

/* ---- measurement ------------------------------------------------------- */

static int64_t vt_field(const struct json_value *data, const char *key)
{
    const struct json_value *v = json_get(data, key);
    if (!v || v->type == JSON_NULL)
        return -1;
    if (v->type != JSON_INT)
        return -2;
    int64_t n = json_get_int(v);
    return n >= 0 && n < INT64_C(1000000000000000) ? n : -2;
}

/* The remote reply: zcl.result.v1 with data zcl.fleet_vitals_read.v1. */
static bool vt_parse_reply(const char *text, struct zcl_fleet_vitals_now *now)
{
    const char *start = strchr(text, '{');
    struct json_value root = {0};
    if (!start || !json_read(&root, start, strlen(start)))
        return false;
    const struct json_value *data = root.type == JSON_OBJ ? json_get(&root, "data") : NULL;
    const char *schema = data && data->type == JSON_OBJ ? vt_str(data, "schema") : NULL;
    bool ok = schema && !strcmp(schema, "zcl.fleet_vitals_read.v1");
    if (ok) {
        struct {
            const char *key;
            int64_t *dst;
        } map[] = {
            {"cpus", &now->cpus}, {"load1_centi", &now->load1_centi},
            {"load5_centi", &now->load5_centi}, {"load15_centi", &now->load15_centi},
            {"mem_total_mib", &now->mem_total_mib}, {"mem_avail_mib", &now->mem_avail_mib},
            {"mem_used_mib", &now->mem_used_mib}, {"disk_total_mib", &now->disk_total_mib},
            {"disk_used_mib", &now->disk_used_mib}, {"disk_free_mib", &now->disk_free_mib},
            {"uptime_s", &now->uptime_s}, {"jobs_running", &now->jobs_running},
            {"jobs_queued", &now->jobs_queued},
        };
        for (size_t i = 0; ok && i < sizeof map / sizeof map[0]; ++i) {
            *map[i].dst = vt_field(data, map[i].key);
            ok = *map[i].dst != -2;
        }
        const char *host = vt_str(data, "host");
        snprintf(now->host, sizeof now->host, "%s", host ? host : "");
    }
    json_free(&root);
    return ok;
}

static void vt_set_error(struct vt_machine *m, const char *code)
{
    m->reachable = false;
    snprintf(m->error, sizeof m->error, "%s", code);
}

/* The remote answered with a zcl.result error for a command it does not have
 * (a slot older than fleet vitals read). */
static bool vt_leaf_missing(const char *text)
{
    const char *start = strchr(text, '{');
    struct json_value root = {0};
    bool missing = false;
    if (start && json_read(&root, start, strlen(start)) && root.type == JSON_OBJ) {
        const char *code = vt_str(json_get(&root, "error"), "code");
        missing = code && !strcmp(code, "UNKNOWN_COMMAND");
    }
    json_free(&root);
    return missing;
}

static void vt_remote(struct vt_machine *m)
{
    char kex[] = "KexAlgorithms=sntrup761x25519-sha512@openssh.com";
    char connect[40], proxy[2300];
    int seconds = m->deadline_ms / 1000;
    snprintf(connect, sizeof connect, "ConnectTimeout=%d", seconds < 1 ? 1 : seconds);
    if (snprintf(proxy, sizeof proxy,
                 "ProxyCommand=%s ops mesh device host client --input-file=%s",
                 m->self, m->route) >= (int)sizeof proxy) {
        vt_set_error(m, "SPAWN_FAILED");
        return;
    }
    const char *const argv[] = {
        m->ssh, "-o", "BatchMode=yes", "-o", kex, "-o", "StrictHostKeyChecking=yes",
        "-o", "ControlPath=none", "-o", connect, "-o", proxy, "--", m->alias,
        m->slot, "fleet", "vitals", "read", "--json", NULL};
    bool timed_out = false;
    int64_t begun = platform_time_monotonic_ms();
    int rc = zcl_spawn_capture_observed(argv, m->capture, VT_CAPTURE_MAX, m->deadline_ms, &timed_out);
    m->rtt_ms = platform_time_monotonic_ms() - begun;
    if (timed_out)
        vt_set_error(m, "DEADLINE");
    else if (rc < 0)
        vt_set_error(m, "SPAWN_FAILED");
    else if (vt_leaf_missing(m->capture))
        vt_set_error(m, "REMOTE_LEAF_MISSING");
    else if (rc != 0)
        vt_set_error(m, "REMOTE_EXIT");
    else if (!vt_parse_reply(m->capture, &m->now))
        vt_set_error(m, "BAD_REPLY");
    else
        m->reachable = true;
}

static bool vt_job(void *item)
{
    vt_remote(item);
    return true;
}

/* Local rows are measured now; a remote row is armed and returned true when
 * it needs an ssh run. */
static bool vt_arm(struct vt_machine *m, const char *ssh, const char *self,
                   const char *ssh_error, int deadline)
{
    if (m->no_route) {
        vt_set_error(m, "NO_ROUTE");
        return false;
    }
    if (m->local) {
        zcl_fleet_vitals_measure(&m->now);
        zcl_fleet_vitals_measure_queue(&m->now);
        m->reachable = true;
        return false;
    }
    if (ssh_error) {
        vt_set_error(m, ssh_error);
        return false;
    }
    m->ssh = ssh;
    m->self = self;
    m->deadline_ms = deadline;
    m->capture = zcl_calloc(1, VT_CAPTURE_MAX + 1, "vitals table capture");
    if (!m->capture)
        vt_set_error(m, "SPAWN_FAILED");
    return m->capture != NULL;
}

/* One worker per remote row, so every deadline runs at once. */
static void vt_run_jobs(void **jobs, size_t njobs)
{
    struct workpool pool;
    if (njobs == 0)
        return;
    if (workpool_init(&pool, (int)njobs, njobs, vt_job)) {
        (void)workpool_run(&pool, jobs, njobs);
        workpool_destroy(&pool);
        return;
    }
    for (size_t i = 0; i < njobs; ++i)
        vt_remote(jobs[i]);
}

static void vt_measure_all(struct vt_machine *m, size_t count, int deadline)
{
    char self[1024], ssh[1100];
    const char *ssh_error = NULL;
    void *jobs[VT_MACHINES_MAX];
    size_t njobs = 0;
    if (!os_proc_exe_path(self, sizeof self) || !vt_path_valid(self))
        ssh_error = "SELF_UNRESOLVED";
    else if (!zcl_native_device_host_shell_resolve(getenv("PATH"), ssh, sizeof ssh))
        ssh_error = "SSH_UNRESOLVED";
    for (size_t i = 0; i < count; ++i)
        if (vt_arm(&m[i], ssh, self, ssh_error, deadline))
            jobs[njobs++] = &m[i];
    vt_run_jobs(jobs, njobs);
    for (size_t i = 0; i < count; ++i) {
        free(m[i].capture);
        m[i].capture = NULL;
    }
}

/* ---- spare capacity ---------------------------------------------------- */

#define VT_COLS 9

/* (cpus - load1) in centi-cores; negative means the box is over-committed. */
static void vt_spare(struct vt_machine *m)
{
    const struct zcl_fleet_vitals_now *n = &m->now;
    m->spare_centi = INT64_MIN;
    if (m->reachable && n->cpus > 0 && n->load1_centi >= 0)
        m->spare_centi = n->cpus * 100 - n->load1_centi;
}

/* true when a should be ahead of b: more spare cores, then a shorter queue. */
static bool vt_ahead(const struct vt_machine *a, const struct vt_machine *b)
{
    if (a->spare_centi != b->spare_centi)
        return a->spare_centi > b->spare_centi;
    int64_t qa = a->now.jobs_queued < 0 ? 0 : a->now.jobs_queued;
    int64_t qb = b->now.jobs_queued < 0 ? 0 : b->now.jobs_queued;
    return qa < qb;
}

/* Fills m[i].rank (1 = most spare) and order[] (rank order, then every
 * unranked machine in input order); returns the ranked count. */
static size_t vt_rank(struct vt_machine *m, size_t count, size_t order[VT_MACHINES_MAX])
{
    size_t ranked = 0;
    for (size_t i = 0; i < count; ++i) {
        vt_spare(&m[i]);
        m[i].rank = 0;
        if (m[i].spare_centi != INT64_MIN) {
            size_t at = ranked++;
            while (at > 0 && vt_ahead(&m[i], &m[order[at - 1]])) {
                order[at] = order[at - 1];
                --at;
            }
            order[at] = i;
        }
    }
    for (size_t r = 0; r < ranked; ++r)
        m[order[r]].rank = (int)r + 1;
    size_t next = ranked;
    for (size_t i = 0; i < count; ++i)
        if (!m[i].rank)
            order[next++] = i;
    return ranked;
}

/* ---- screen ------------------------------------------------------------ */

struct vt_cells {
    char cell[VT_MACHINES_MAX][VT_COLS][160];
};

static size_t vt_width(const char *s)
{
    size_t n = 0;
    for (; *s; ++s)
        if (((unsigned char)*s & 0xC0) != 0x80)
            ++n;
    return n;
}

static void vt_bar(char *out, size_t cap, int64_t used, int64_t total)
{
    int filled = total > 0 ? (int)((used * VT_BAR_CELLS + total / 2) / total) : 0;
    size_t len = 0;
    filled = filled < 0 ? 0 : filled > VT_BAR_CELLS ? VT_BAR_CELLS : filled;
    out[0] = '\0';
    for (int i = 0; i < VT_BAR_CELLS && len + 4 < cap; ++i)
        len += (size_t)snprintf(out + len, cap - len, "%s", i < filled ? "\xE2\x96\x88" : "\xE2\x96\x91");
}

static void vt_gib(char *out, size_t cap, int64_t mib)
{
    int64_t tenths = mib * 10 / 1024;
    snprintf(out, cap, "%lld.%lld", (long long)(tenths / 10), (long long)(tenths % 10));
}

/* A centi value as "12.34" or "-1.50". */
static void vt_centi(char *out, size_t cap, int64_t centi)
{
    const char *sign = centi < 0 ? "-" : "";
    uint64_t a = centi < 0 ? (uint64_t)0 - (uint64_t)centi : (uint64_t)centi;
    snprintf(out, cap, "%s%llu.%02llu", sign, (unsigned long long)(a / 100),
             (unsigned long long)(a % 100));
}

static void vt_fill_unreached(const struct vt_machine *m, char c[VT_COLS][160])
{
    for (size_t k = 1; k < VT_COLS; ++k)
        snprintf(c[k], 160, "-");
    if (m->no_route) {
        snprintf(c[5], 160, "\xC2\xB7\xC2\xB7 no tunnel route \xC2\xB7\xC2\xB7");
        snprintf(c[6], 160, "\xC2\xB7\xC2\xB7 no tunnel route \xC2\xB7\xC2\xB7");
    } else {
        snprintf(c[5], 160, "unreachable: %s", m->error);
    }
}

static void vt_fill_mem_disk(const struct zcl_fleet_vitals_now *n, char c[VT_COLS][160])
{
    char bar[96], a[24], b[24];
    snprintf(c[5], 160, "-");
    snprintf(c[6], 160, "-");
    if (n->mem_total_mib > 0 && n->mem_used_mib >= 0) {
        vt_bar(bar, sizeof bar, n->mem_used_mib, n->mem_total_mib);
        vt_gib(a, sizeof a, n->mem_used_mib);
        vt_gib(b, sizeof b, n->mem_total_mib);
        snprintf(c[5], 160, "%s %s/%sG", bar, a, b);
    }
    if (n->disk_total_mib > 0 && n->disk_used_mib >= 0) {
        vt_bar(bar, sizeof bar, n->disk_used_mib, n->disk_total_mib);
        vt_gib(a, sizeof a, n->disk_used_mib);
        vt_gib(b, sizeof b, n->disk_total_mib);
        snprintf(c[6], 160, "%s %s/%sG %lld%%", bar, a, b,
                 (long long)((n->disk_used_mib * 100 + n->disk_total_mib / 2) / n->disk_total_mib));
    }
}

static void vt_fill_cells(const struct vt_machine *m, char c[VT_COLS][160])
{
    snprintf(c[0], 160, "%s", m->label);
    if (m->no_route || !m->reachable) {
        vt_fill_unreached(m, c);
        return;
    }
    const struct zcl_fleet_vitals_now *n = &m->now;
    for (size_t k = 1; k < 5; ++k)
        snprintf(c[k], 160, "-");
    if (n->cpus >= 0)
        snprintf(c[1], 160, "%lld", (long long)n->cpus);
    if (n->load1_centi >= 0)
        vt_centi(c[2], 160, n->load1_centi);
    if (m->spare_centi != INT64_MIN)
        vt_centi(c[3], 160, m->spare_centi);
    if (n->jobs_running >= 0 && n->jobs_queued >= 0)
        snprintf(c[4], 160, "%lld run %lld wait", (long long)n->jobs_running,
                 (long long)n->jobs_queued);
    vt_fill_mem_disk(n, c);
    snprintf(c[7], 160, "0s live");
    snprintf(c[8], 160, "%lld", (long long)m->rtt_ms);
}

static void vt_put(char *out, size_t cap, size_t *len, const char *s)
{
    size_t n = strlen(s);
    if (*len + n < cap) {
        memcpy(out + *len, s, n + 1);
        *len += n;
    }
}

static void vt_rule(char *out, size_t cap, size_t *len, const size_t w[VT_COLS],
                    const char *l, const char *mid, const char *r)
{
    vt_put(out, cap, len, l);
    for (size_t c = 0; c < VT_COLS; ++c) {
        for (size_t i = 0; i < w[c] + 2; ++i)
            vt_put(out, cap, len, "\xE2\x94\x80");
        vt_put(out, cap, len, c == VT_COLS - 1 ? r : mid);
    }
    vt_put(out, cap, len, "\n");
}

static void vt_row(char *out, size_t cap, size_t *len, const size_t w[VT_COLS],
                   char c[VT_COLS][160])
{
    for (size_t k = 0; k < VT_COLS; ++k) {
        vt_put(out, cap, len, "\xE2\x94\x82 ");
        vt_put(out, cap, len, c[k]);
        for (size_t i = vt_width(c[k]); i < w[k]; ++i)
            vt_put(out, cap, len, " ");
        vt_put(out, cap, len, " ");
    }
    vt_put(out, cap, len, "\xE2\x94\x82\n");
}

/* The line an agent acts on: the machine with the most spare cores. */
static void vt_advice(const struct vt_machine *m, size_t count, const size_t order[VT_MACHINES_MAX],
                      size_t ranked, char *out, size_t cap)
{
    if (ranked == 0) {
        snprintf(out, cap, "no machine has a usable measurement, so none is recommended");
        return;
    }
    const struct vt_machine *best = &m[order[0]];
    char spare[32];
    vt_centi(spare, sizeof spare, best->spare_centi);
    snprintf(out, cap, "most spare capacity: %s (%s spare cores of %lld, measured now)%s",
             best->label, spare, (long long)best->now.cpus,
             count > ranked ? "; machines without a measurement are listed last, not ranked" : "");
}

static void vt_screen(const struct vt_machine *m, size_t count, const size_t order[VT_MACHINES_MAX],
                      const char *advice, char *out, size_t cap)
{
    static const char *const heads[VT_COLS] = {
        "machine", "cpus", "load1", "spare cores", "build queue",
        "memory used/total G", "disk used/total G pct", "age", "rtt ms"};
    struct vt_cells *cells = zcl_calloc(1, sizeof *cells, "vitals table cells");
    size_t len = 0, w[VT_COLS];
    out[0] = '\0';
    if (!cells)
        return;
    for (size_t c = 0; c < VT_COLS; ++c)
        w[c] = vt_width(heads[c]);
    for (size_t i = 0; i < count; ++i) {
        vt_fill_cells(&m[order[i]], cells->cell[i]);
        for (size_t c = 0; c < VT_COLS; ++c)
            if (vt_width(cells->cell[i][c]) > w[c])
                w[c] = vt_width(cells->cell[i][c]);
    }
    char head[VT_COLS][160];
    for (size_t c = 0; c < VT_COLS; ++c)
        snprintf(head[c], 160, "%s", heads[c]);
    vt_rule(out, cap, &len, w, "\xE2\x94\x8C", "\xE2\x94\xAC", "\xE2\x94\x90");
    vt_row(out, cap, &len, w, head);
    vt_rule(out, cap, &len, w, "\xE2\x94\x9C", "\xE2\x94\xBC", "\xE2\x94\xA4");
    for (size_t i = 0; i < count; ++i)
        vt_row(out, cap, &len, w, cells->cell[i]);
    vt_rule(out, cap, &len, w, "\xE2\x94\x94", "\xE2\x94\xB4", "\xE2\x94\x98");
    size_t up = 0;
    char total[64];
    for (size_t i = 0; i < count; ++i)
        up += m[i].reachable ? 1u : 0u;
    snprintf(total, sizeof total, "%zu/%zu machines reachable\n", up, count);
    vt_put(out, cap, &len, total);
    vt_put(out, cap, &len,
           "every number above was measured during this call (age 0s); none is recorded or cached\n");
    vt_put(out, cap, &len, advice);
    vt_put(out, cap, &len, "\n");
    free(cells);
}

/* ---- rows -------------------------------------------------------------- */

static bool vt_push(struct json_value *obj, const char *key, int64_t value)
{
    if (value >= 0)
        return json_push_kv_int(obj, key, value);
    struct json_value null = {0};
    json_set_null(&null);
    bool ok = json_push_kv(obj, key, &null);
    json_free(&null);
    return ok;
}

static bool vt_push_load_cpu(struct json_value *row, const struct vt_machine *m)
{
    const struct zcl_fleet_vitals_now *n = &m->now;
    bool ok = json_push_kv_str(row, "host", n->host) && vt_push(row, "rtt_ms", m->rtt_ms) &&
              vt_push(row, "cpus", n->cpus) && vt_push(row, "load1_centi", n->load1_centi) &&
              vt_push(row, "load5_centi", n->load5_centi) &&
              vt_push(row, "load15_centi", n->load15_centi) &&
              vt_push(row, "jobs_running", n->jobs_running) &&
              vt_push(row, "jobs_queued", n->jobs_queued);
    /* spare may be negative (over-committed), so it is not clamped to null */
    struct json_value null = {0};
    json_set_null(&null);
    if (ok && m->spare_centi != INT64_MIN)
        ok = json_push_kv_int(row, "spare_cores_centi", m->spare_centi) &&
             json_push_kv_int(row, "load1_per_core_centi", n->load1_centi / n->cpus);
    else if (ok)
        ok = json_push_kv(row, "spare_cores_centi", &null) &&
             json_push_kv(row, "load1_per_core_centi", &null);
    json_free(&null);
    return ok && vt_push(row, "spare_rank", m->rank);
}

static bool vt_push_mem_disk(struct json_value *row, const struct zcl_fleet_vitals_now *n)
{
    return vt_push(row, "mem_total_mib", n->mem_total_mib) &&
           vt_push(row, "mem_avail_mib", n->mem_avail_mib) &&
           vt_push(row, "mem_used_mib", n->mem_used_mib) &&
           vt_push(row, "disk_total_mib", n->disk_total_mib) &&
           vt_push(row, "disk_used_mib", n->disk_used_mib) &&
           vt_push(row, "disk_free_mib", n->disk_free_mib) && vt_push(row, "uptime_s", n->uptime_s);
}

static bool vt_row_json(const struct vt_machine *m, struct json_value *rows)
{
    struct json_value row = {0};
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "label", m->label) &&
              json_push_kv_str(&row, "source", m->local ? "local" : m->no_route ? "no_route" : "live") &&
              json_push_kv_bool(&row, "reachable", m->reachable);
    if (ok && !m->reachable)
        ok = json_push_kv_str(&row, "error", m->error);
    else if (ok)
        ok = json_push_kv_int(&row, "age_s", 0) && vt_push_load_cpu(&row, m) &&
             vt_push_mem_disk(&row, &m->now);
    ok = ok && json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static const char k_vt_implicit_note[] =
    "No machines were given, so only this box is shown. A remote machine needs one "
    "machines[] entry {label, route_file, slot, host_alias} (zcl.fleet_vitals_table_input.v1) "
    "and is then measured live over its host tunnel. Fleet vitals ledger rows do not replicate "
    "between hosts today, so there is no recorded remote row to show here; a number is only "
    "ever shown when it was measured during this call.";

static bool vt_summary_json(struct json_value *data, const struct vt_machine *m, bool implicit,
                            const size_t order[VT_MACHINES_MAX], size_t ranked, const char *advice)
{
    struct json_value null = {0};
    json_set_null(&null);
    bool ok = ranked ? json_push_kv_str(data, "best", m[order[0]].label)
                     : json_push_kv(data, "best", &null);
    json_free(&null);
    return ok && json_push_kv_str(data, "advice", advice) &&
           json_push_kv_str(data, "age_note",
                            "every number was measured during this call (age_s 0); none is recorded or cached") &&
           (!implicit || json_push_kv_str(data, "note", k_vt_implicit_note));
}

void zcl_native_handle_fleet_vitals_table(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    zcl_command_reply_init(reply, "zcl.fleet_vitals_table.v1");
    struct vt_machine *m = zcl_calloc(VT_MACHINES_MAX, sizeof *m, "vitals table machines");
    char *screen = zcl_calloc(1, 16384, "vitals table screen");
    size_t count = 0;
    int deadline = VT_DEADLINE_DEFAULT;
    if (!m || !screen) {
        vt_refuse(reply, "TABLE_ALLOC", "the table could not be built", "alloc");
    } else if (vt_input(request, m, &count, &deadline, reply)) {
        vt_measure_all(m, count, deadline);
        size_t order[VT_MACHINES_MAX];
        size_t ranked = vt_rank(m, count, order);
        char advice[256];
        vt_advice(m, count, order, ranked, advice, sizeof advice);
        struct json_value rows = {0};
        json_set_array(&rows);
        bool ok = true;
        for (size_t i = 0; ok && i < count; ++i)
            ok = vt_row_json(&m[i], &rows);
        vt_screen(m, count, order, advice, screen, 16384);
        ok = ok && json_push_kv_str(&reply->data, "schema", "zcl.fleet_vitals_table.v1") &&
             json_push_kv(&reply->data, "rows", &rows) &&
             vt_summary_json(&reply->data, m, m[0].implicit, order, ranked, advice) &&
             json_push_kv_str(&reply->data, "screen", screen);
        json_free(&rows);
        if (ok) {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
        } else {
            vt_refuse(reply, "TABLE_ALLOC", "the table could not be built", "alloc");
        }
    }
    free(screen);
    free(m);
}
