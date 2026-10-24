/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The producers behind `fleet.goals`: one function per goal that
 *          reads a real local probe and grades its row pass, partial, fail or
 *          unmeasured. A producer that cannot measure says why; it never
 *          returns a guessed grade.
 *
 * Rows whose probe is a future leaf share one table entry with the reason
 * the tree cannot answer today. Host-set goals take their hosts from the
 * admitted roster (`fleet machines`) and are unmeasured without one. */

#include "native_fleet_goals.h"

#include "native_fleet_goals_feedback.h"
#include "native_fleet_objectives.h"

#include "command/native_command.h"
#include "config/cli_lane_defaults.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/compare.h"
#include "util/spawn.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOALS_DAY_S 86400
#define GOALS_LOOKUP_SAMPLES 5
#define GOALS_DEFAULT_CADENCE_S 300
#define GOALS_PAGES_MAX 200
#define GOALS_TRAINS_MAX 256
#define GOALS_CLAIM_LINE_MAX 16384
#define GOALS_BENCH_MAX 8192
#define GOALS_BENCH_STALE_S (7 * GOALS_DAY_S)
#define GOALS_TUNNEL_MIB_S_MIN 150.0
#define GOALS_BENCH_SCHEMA "zcl.tunnel_bench.v1"
#define GOALS_PQFS_SUITE "Noise_XXhfs_25519+MLKEM768_ChaChaPoly_SHA256"

static const struct zcl_goal_row k_goals[] = {
#define Z23_GOAL(id_, title_, bar_) {id_, title_, bar_},
#include "../../engine/composition/goals.def"
#undef Z23_GOAL
};

size_t zcl_goals_catalog(const struct zcl_goal_row **out)
{
    if (out)
        *out = k_goals;
    return sizeof(k_goals) / sizeof(k_goals[0]);
}

const char *zcl_goal_grade_name(enum zcl_goal_grade grade)
{
    static const char *const names[] = {"pass", "partial", "fail",
                                        "unmeasured"};
    return (unsigned)grade < 4u ? names[grade] : "unmeasured";
}

/* ── graders ──────────────────────────────────────────────────────────── */

enum zcl_goal_grade zcl_goals_grade_trains(int64_t trains, int64_t failed)
{
    if (trains <= 0)
        return ZCL_GOAL_FAIL;
    return trains >= ZCL_GOALS_TRAIN_MIN && failed == 0 ? ZCL_GOAL_PASS
                                                         : ZCL_GOAL_PARTIAL;
}

/* Latency is one of the bar's numeric clauses; the token reduction is the
 * other and has no producer, so a fast lookup caps at partial. */
enum zcl_goal_grade zcl_goals_grade_lookup(int64_t median_ms)
{
    return median_ms <= ZCL_GOALS_LOOKUP_MS_MAX ? ZCL_GOAL_PARTIAL
                                                : ZCL_GOAL_FAIL;
}

/* Freshness does not measure the one-second collection bound. */
enum zcl_goal_grade zcl_goals_grade_fresh(size_t fresh, size_t hosts)
{
    return hosts > 0 && fresh == 0 ? ZCL_GOAL_FAIL : ZCL_GOAL_PARTIAL;
}

enum zcl_goal_grade zcl_goals_grade_claims(int64_t live)
{
    return live <= 0 ? ZCL_GOAL_FAIL : ZCL_GOAL_PARTIAL;
}

/* The bar also requires host roles and paths to come only from
 * configuration, which no probe measures, so an empty allowlist caps at
 * partial too. */
enum zcl_goal_grade zcl_goals_grade_scripts(int64_t scripts)
{
    (void)scripts;
    return ZCL_GOAL_PARTIAL;
}

/* ── result helpers ───────────────────────────────────────────────────── */

struct zcl_goal_result zcl_goal_make(enum zcl_goal_grade grade,
                                     const char *next, const char *fmt, ...)
{
    struct zcl_goal_result r = {0};
    va_list args;
    r.grade = grade;
    va_start(args, fmt);
    (void)vsnprintf(r.evidence, sizeof(r.evidence), fmt, args);
    va_end(args);
    (void)snprintf(r.next, sizeof(r.next), "%s", next);
    return r;
}

#define gr_unmeasured(next, ...) \
    zcl_goal_make(ZCL_GOAL_UNMEASURED, (next), __VA_ARGS__)

static int64_t gr_now(const struct zcl_goals_options *o)
{
    return o && o->now_unix > 0 ? o->now_unix : (int64_t)platform_time_wall_time_t();
}

/* Top-level of the git worktree that holds `dir`; false when git names none. */
static bool gr_toplevel(const char *dir, char *out, size_t cap)
{
    char buf[1024];
    const char *argv[] = {"git", "-C", dir, "rev-parse", "--show-toplevel",
                          NULL};
    size_t n;
    if (zcl_spawn_capture(argv, buf, sizeof(buf), 5000) != 0)
        return false;
    n = strcspn(buf, "\r\n");
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, buf, n);
    out[n] = '\0';
    return true;
}

/* The git worktree a producer reads: the explicit repo input, else the top
 * level of the current directory, else the checkout that holds the running
 * binary's source. False when none resolves; nothing is guessed. */
static bool gr_repo(const struct zcl_goals_options *o, char *out, size_t cap)
{
    out[0] = '\0';
    if (o && o->repo && o->repo[0])
        return snprintf(out, cap, "%s", o->repo) < (int)cap;
    if (gr_toplevel(".", out, cap))
        return true;
    return o && o->source_root && o->source_root[0] &&
           gr_toplevel(o->source_root, out, cap);
}

/* Reason a git-backed row gives when no checkout resolves. */
#define GR_NO_CHECKOUT                                                       \
    "no git checkout: the current directory is not inside one, no repo "     \
    "input was given, and no source checkout is recorded or configured"

/* ── in-process leaf calls ────────────────────────────────────────────── */

/* Runs a registered leaf's handler in this process. True when it passed. */
static bool gr_call(const char *path, const struct json_value *input,
                    struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    struct zcl_command_request request;
    memset(&request, 0, sizeof(request));
    request.input = input;
    request.spec = spec;
    zcl_command_reply_init(reply, spec ? spec->output_schema : "");
    if (!spec || !spec->handler) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LEAF_UNAVAILABLE",
                               "prepare", false, false, path, "");
        return false;
    }
    spec->handler(&request, reply);
    return reply->status == ZCL_COMMAND_STATUS_PASSED;
}

static void gr_reason(const struct zcl_command_reply *reply, char *out,
                      size_t cap)
{
    (void)snprintf(out, cap, "%s", reply->error.code[0] ? reply->error.code
                                                        : "no reply");
}

/* ── roster ───────────────────────────────────────────────────────────── */

struct gr_roster {
    bool ok;
    bool truncated;
    char reason[200];
    struct zcl_goals_host hosts[ZCL_GOALS_HOSTS_MAX];
    size_t count;
};

static void gr_roster_row(const struct json_value *machine,
                          struct gr_roster *r)
{
    const struct json_value *v = json_get(machine, "verified");
    const struct json_value *s = json_get(machine, "self_reported");
    struct zcl_goals_host *h = &r->hosts[r->count];
    (void)snprintf(h->name, sizeof(h->name), "%s",
                   json_get_str(json_get(v, "name")));
    (void)snprintf(h->box, sizeof(h->box), "%s",
                   json_get_str(json_get(v, "box_pubkey")));
    (void)snprintf(h->os, sizeof(h->os), "%s",
                   json_get_str(json_get(s, "os")));
    r->count++;
}

/* Reads one page of the roster. Returns the next offset, or -1 when the
 * roster is finished or a page failed (r->reason then names why). */
static int64_t gr_roster_page(struct gr_roster *r, int64_t offset)
{
    struct json_value input;
    struct zcl_command_reply reply;
    const struct json_value *rows;
    int64_t next = -1;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "offset", offset);
    if (!gr_call("fleet.machines", &input, &reply)) {
        char code[100];
        gr_reason(&reply, code, sizeof(code));
        (void)snprintf(r->reason, sizeof(r->reason),
                       "no admitted roster: fleet machines failed (%s)", code);
    } else {
        rows = json_get(&reply.data, "machines");
        for (size_t i = 0; rows && i < rows->num_children; i++) {
            if (r->count == ZCL_GOALS_HOSTS_MAX) {
                r->truncated = true;
                break;
            }
            gr_roster_row(&rows->children[i], r);
        }
        next = json_get_int(json_get(&reply.data, "next_offset"));
    }
    zcl_command_reply_free(&reply);
    json_free(&input);
    return next;
}

static void gr_roster_load(const struct zcl_goals_options *o,
                           struct gr_roster *r)
{
    memset(r, 0, sizeof(*r));
    if (o && o->hosts_given) {
        for (size_t i = 0; i < o->host_count; i++) {
            if (r->count == ZCL_GOALS_HOSTS_MAX)
                r->truncated = true;
            else
                r->hosts[r->count++] = o->hosts[i];
        }
    } else {
        int64_t next = 0;
        for (int page = 0; next >= 0 && page < GOALS_PAGES_MAX; page++)
            next = gr_roster_page(r, next);
        if (next >= 0 && !r->reason[0])
            r->truncated = true;
    }
    if (r->truncated)
        (void)snprintf(r->reason, sizeof(r->reason),
                       "roster has more than %u admitted machines; the card "
                       "will not grade a host list it cannot hold",
                       ZCL_GOALS_HOSTS_MAX);
    else if (r->count == 0 && !r->reason[0])
        (void)snprintf(r->reason, sizeof(r->reason),
                       "no admitted roster: no machines are enrolled");
    r->ok = r->count > 0 && !r->truncated;
}

static struct zcl_goal_result gr_no_roster(const struct gr_roster *r)
{
    return gr_unmeasured("admit machines with `z23 fleet invite` and "
                         "`z23 fleet admit`, then rerun",
                         "%s", r->reason);
}

/* ── rows whose probe is not in the tree yet ──────────────────────────── */

struct gr_static {
    const char *id;
    bool host_set;
    const char *reason;
    const char *next;
};

static const struct gr_static k_static[] = {
    {"G2", false, "no k-of-n hybrid signing probe exists in the tree",
     "card: a signing-quorum status leaf reporting hosts and last signed "
     "release"},
    {"G5", true, "no peer-fetch and atomic-install receipt reader exists",
     "card: a plugin swarm status leaf listing per-host installs"},
    {"G10", false, "node liveness needs the canonical datadirs, which this "
                   "card never opens",
     "run `z23 status` on each node host and post the result as a receipt"},
    {"G11", false, "no spend ledger summary is read by this card",
     "card: report `fleet usage` totals as ZCL spent"},
    {"C8", false, "needs 168 h of observation, have 0 h: no producer "
                  "persists a parity mismatch count",
     "card: write parity samples to a ledger"},
    {"D1", false, "no reader counts finished runs with complete provider "
                  "counters across hosts",
     "card: report recorded-run share per host from the experiment ledger"},
    {"D2", false, "requests per accepted change are not aggregated",
     "card: aggregate provider requests per landed change"},
    {"D3", false, "no known-answer review set with seeded defects exists",
     "card: build the seeded-defect review set"},
    {"D4", false, "first-time acceptance is not recorded per delivery",
     "card: record review verdicts per delivery"},
};

static const struct gr_static *gr_find_static(const char *id)
{
    for (size_t i = 0; i < sizeof(k_static) / sizeof(k_static[0]); i++)
        if (strcmp(k_static[i].id, id) == 0)
            return &k_static[i];
    return NULL;
}

static struct zcl_goal_result gr_from_static(
    const struct zcl_goals_options *o, const struct gr_static *s)
{
    struct gr_roster roster;
    if (s->host_set) {
        gr_roster_load(o, &roster);
        if (!roster.ok)
            return gr_no_roster(&roster);
        return gr_unmeasured(s->next, "%zu admitted host(s); %s", roster.count,
                             s->reason);
    }
    return gr_unmeasured(s->next, "%s", s->reason);
}

static struct zcl_goal_result gr_g12(const struct zcl_goals_options *o)
{
    struct gr_roster roster;
    size_t mac = 0;
    gr_roster_load(o, &roster);
    if (!roster.ok)
        return gr_no_roster(&roster);
    for (size_t i = 0; i < roster.count; i++)
        if (strcmp(roster.hosts[i].os, "Darwin") == 0 ||
            strcmp(roster.hosts[i].os, "macOS") == 0)
            mac++;
    if (mac == 0)
        return gr_unmeasured("admit the Darwin host, then add a parity receipt",
                             "%zu admitted host(s), none reports Darwin",
                             roster.count);
    return gr_unmeasured("card: a mac parity receipt from the Darwin host",
                         "%zu of %zu admitted host(s) report Darwin; no "
                         "build, confinement or pairing parity receipt "
                         "exists",
                         mac, roster.count);
}

/* ── G1: tunnel throughput receipt ────────────────────────────────────── */

static bool gr_number(const struct json_value *v)
{
    return v && (v->type == JSON_INT || v->type == JSON_REAL);
}

static bool gr_bench_read(const char *path, struct json_value *out)
{
    char text[GOALS_BENCH_MAX];
    size_t n = 0;
    if (!path || path[0] != '/' ||
        !zcl_native_device_host_input_file_read(path, text, sizeof(text), &n))
        return false;
    json_init(out);
    if (!json_read(out, text, n)) {
        json_free(out);
        return false;
    }
    return true;
}

/* Grade of a parsed receipt whose throughput and age are known. The outer
 * tunnel is a static PSK with no forward secrecy (docs/spec/
 * TUNNEL_PQ_FORWARD_SECRECY.md); only a receipt recording the hybrid Noise
 * suite as the outer handshake passes, and no producer writes one yet. */
static struct zcl_goal_result gr_g1_grade(const struct json_value *rc,
                                          const char *path, int64_t age_s)
{
    static const char next[] =
        "run `z23 ops mesh device host bench --receipt_out=<path>` on each "
        "host; PASS needs an outer PQ+FS handshake that no producer records";
    const struct json_value *hs = json_get(rc, "outer_handshake");
    double fwd = json_get_real(json_get(rc, "forward_mib_s"));
    double rev = json_get_real(json_get(rc, "reverse_mib_s"));
    long long age_h = (long long)(age_s / 3600);
    if (age_s > GOALS_BENCH_STALE_S)
        return zcl_goal_make(ZCL_GOAL_FAIL, next,
                             "stale: receipt %s is %lld h old, window %d d",
                             path, age_h, GOALS_BENCH_STALE_S / GOALS_DAY_S);
    if (fwd < GOALS_TUNNEL_MIB_S_MIN || rev < GOALS_TUNNEL_MIB_S_MIN)
        return zcl_goal_make(ZCL_GOAL_FAIL, next,
                             "under the %.0f MiB/s bar: forward %.1f, reverse "
                             "%.1f MiB/s, receipt %s, %lld h old",
                             GOALS_TUNNEL_MIB_S_MIN, fwd, rev, path, age_h);
    if (hs && hs->type == JSON_STR &&
        strcmp(json_get_str(hs), GOALS_PQFS_SUITE) == 0)
        return zcl_goal_make(ZCL_GOAL_PASS, next,
                             "forward %.1f, reverse %.1f MiB/s over %s, "
                             "receipt %s, %lld h old",
                             fwd, rev, GOALS_PQFS_SUITE, path, age_h);
    return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                         "forward %.1f, reverse %.1f MiB/s in-process on one "
                         "host, receipt %s, %lld h old; outer tunnel static "
                         "PSK, no forward secrecy; PQ only inside ssh",
                         fwd, rev, path, age_h);
}

static struct zcl_goal_result gr_g1(const struct zcl_goals_options *o)
{
    static const char next[] =
        "run `z23 ops mesh device host bench --receipt_out=<path>`, then "
        "point ZCL_TUNNEL_BENCH_RECEIPT at it";
    char buf[512];
    struct json_value rc;
    struct zcl_goal_result r;
    const char *schema;
    int64_t ts_ms, age_s;
    const char *path = zcl_goals_state_path(
        o ? o->tunnel_bench : NULL, "ZCL_TUNNEL_BENCH_RECEIPT",
        ".local/state/z23/tunnel-bench/latest.json", o && o->skip_probes, buf,
        sizeof(buf));
    if (!path)
        return gr_unmeasured(next, "tunnel bench receipt probe skipped");
    if (!gr_bench_read(path, &rc))
        return gr_unmeasured(next, "no readable bench receipt at %s", path);
    schema = json_get_str(json_get(&rc, "schema"));
    ts_ms = json_get_int(json_get(&rc, "timestamp_unix_ms"));
    if (!schema || strcmp(schema, GOALS_BENCH_SCHEMA) != 0 || ts_ms <= 0 ||
        !gr_number(json_get(&rc, "forward_mib_s")) ||
        !gr_number(json_get(&rc, "reverse_mib_s")) ||
        json_get(&rc, "timestamp_unix_ms")->type != JSON_INT) {
        json_free(&rc);
        return gr_unmeasured(next, "%s is not a %s receipt", path,
                             GOALS_BENCH_SCHEMA);
    }
    age_s = gr_now(o) - ts_ms / 1000;
    if (age_s < 0) {
        json_free(&rc);
        return gr_unmeasured(next, "receipt %s is dated in the future", path);
    }
    r = gr_g1_grade(&rc, path, age_s);
    json_free(&rc);
    return r;
}

/* ── G3: shell grants, offline ────────────────────────────────────────── */

static struct zcl_goal_result gr_g3(const struct zcl_goals_options *o)
{
    static const char next[] =
        "PASS needs a round-trip receipt; `ops mesh device host shell` execs "
        "ssh interactively and has no non-interactive command mode";
    char dir_buf[512], path[1100], bad[160] = "";
    struct gr_roster roster;
    size_t ok = 0, shown = 0;
    const char *dir = zcl_goals_state_path(
        o ? o->shell_routes : NULL, "ZCL_SHELL_ROUTE_DIR",
        ".config/z23/shell-routes", o && o->skip_probes, dir_buf,
        sizeof(dir_buf));
    gr_roster_load(o, &roster);
    if (!roster.ok)
        return gr_no_roster(&roster);
    if (!dir)
        return gr_unmeasured(next, "shell route probe skipped");
    for (size_t i = 0; i < roster.count; i++) {
        const char *name = roster.hosts[i].name;
        const char *why = "route_name_refused";
        if (name[0] && name[0] != '.' && !strchr(name, '/') &&
            snprintf(path, sizeof(path), "%s/%s.json", dir, name) <
                (int)sizeof(path))
            why = zcl_native_device_host_shell_route_check(
                path, (uint64_t)gr_now(o));
        if (!why)
            ok++;
        else if (shown++ < 3)
            (void)snprintf(bad + strlen(bad), sizeof(bad) - strlen(bad),
                           " %s:%s", name, why);
    }
    return zcl_goal_make(ok == roster.count ? ZCL_GOAL_PARTIAL : ZCL_GOAL_FAIL,
                         next,
                         "%zu of %zu admitted host(s) have a valid, unexpired "
                         "shell route and grant in %s (offline check, no round "
                         "trip)%s",
                         ok, roster.count, dir, bad);
}

/* ── G6: release slot ─────────────────────────────────────────────────── */

static struct zcl_goal_result gr_g6(const struct zcl_goals_options *o)
{
    struct gr_roster roster;
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "zcode.node.update.status", NULL);
    gr_roster_load(o, &roster);
    if (!roster.ok)
        return gr_no_roster(&roster);
    if (spec && spec->availability == ZCL_COMMAND_PLANNED)
        return gr_unmeasured("land the node release feed so `zcode node "
                             "update status` answers",
                             "%zu admitted host(s); the release slot reader "
                             "is planned: %s",
                             roster.count, spec->availability_reason);
    return gr_unmeasured("card: read each host's running release against "
                         "origin/main",
                         "%zu admitted host(s); the update status leaf is "
                         "ready but reports one node, not each host",
                         roster.count);
}

/* ── G4: wiki read path ───────────────────────────────────────────────── */

/* Newest created_at over the index rows whose host is not this node. */
static void gr_wiki_foreign(const struct json_value *posts, const char *own,
                            size_t *count, int64_t *newest)
{
    *count = 0;
    *newest = 0;
    for (size_t i = 0; posts && posts->type == JSON_ARR && i < posts->num_children;
         i++) {
        const struct json_value *row = &posts->children[i];
        const char *host = json_get_str(json_get(row, "host"));
        int64_t ts = json_get_int(json_get(row, "created_at"));
        if (!host || !host[0] || strcmp(host, own) == 0)
            continue;
        if (*count == 0 || ts > *newest)
            *newest = ts;
        (*count)++;
    }
}

struct zcl_goal_result zcl_goals_wiki_grade(bool answered, const char *why,
                                            const struct json_value *data,
                                            const char *own_host,
                                            int64_t now, int64_t latency_ms)
{
    const char *next = "card: write a probe page and read it back from "
                       "every admitted host";
    const char *tail = "; all-host propagation and pinned expiry not probed";
    size_t foreign = 0;
    int64_t newest = 0, age = 0;
    char newest_txt[32] = "none";
    if (!answered)
        return gr_unmeasured(next, "wiki list did not answer on this node: %s",
                             why);
    if (!own_host || !own_host[0])
        return gr_unmeasured(next, "this node own host id is unreadable, so "
                             "rows from other hosts cannot be told apart");
    gr_wiki_foreign(json_get(data, "posts"), own_host, &foreign, &newest);
    if (foreign > 0) {
        age = now - newest;
        (void)snprintf(newest_txt, sizeof(newest_txt), "%lld s old",
                       (long long)age);
    }
    if (latency_ms > ZCL_GOALS_WIKI_MS_MAX)
        return zcl_goal_make(ZCL_GOAL_FAIL, next,
                             "fleet.wiki.list answered in %lld ms on this "
                             "node (bar %d ms); %zu row(s) from other hosts, "
                             "newest %s; the list is over the bar%s",
                             (long long)latency_ms, ZCL_GOALS_WIKI_MS_MAX,
                             foreign, newest_txt, tail);
    if (foreign > 0 && age >= 0 && age <= ZCL_GOALS_WIKI_FRESH_S)
        return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                             "fleet.wiki.list answered in %lld ms on this "
                             "node (bar %d ms); %zu row(s) from other hosts, "
                             "newest %s; a row from another host is newer "
                             "than the %d s freshness bound%s",
                             (long long)latency_ms, ZCL_GOALS_WIKI_MS_MAX,
                             foreign, newest_txt, ZCL_GOALS_WIKI_FRESH_S, tail);
    if (foreign == 0)
        return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                             "fleet.wiki.list answered in %lld ms on this "
                             "node (bar %d ms); 0 row(s) from other hosts; "
                             "no row from another host yet%s",
                             (long long)latency_ms, ZCL_GOALS_WIKI_MS_MAX, tail);
    return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                         "fleet.wiki.list answered in %lld ms on this node "
                         "(bar %d ms); %zu row(s) from other hosts, newest %s; "
                         "no row from another host is newer than the %d s "
                         "freshness bound%s",
                         (long long)latency_ms, ZCL_GOALS_WIKI_MS_MAX, foreign,
                         newest_txt, ZCL_GOALS_WIKI_FRESH_S, tail);
}

/* This node board host id in hex, from the local board status; empty when
 * the status call did not answer. */
static void gr_own_host(char *out, size_t cap)
{
    struct json_value input;
    struct zcl_command_reply reply;
    out[0] = '\0';
    json_init(&input);
    json_set_object(&input);
    if (gr_call("fleet.board.status", &input, &reply))
        (void)snprintf(out, cap, "%s",
                       json_get_str(json_get(&reply.data, "host")));
    zcl_command_reply_free(&reply);
    json_free(&input);
}

/* The board RPC is aimed at the datadir this process bound. A process with
 * nothing bound, or only the dev lane's default bound, reaches no node there.
 * Like the objectives node rows, G4 aims its synchronous calls at the release
 * node datadir (the one `z23 status` reads) unless the operator named one,
 * then gives the process its own binding back. */
struct gr_rpc_target {
    bool rebound;
    char saved[512];
    int saved_port;
};

static bool gr_rpc_target_free(const char *bound, const char *home)
{
    char lane[512];
    if (zcl_native_command_datadir_is_explicit())
        return false;
    if (!bound[0])
        return true;
    return zcl_cli_lane_default_datadir(lane, sizeof(lane), home) &&
           strcmp(bound, lane) == 0;
}

static void gr_rpc_target_enter(struct gr_rpc_target *t)
{
    char release[512];
    const char *home = getenv("HOME");
    const char *bound = zcl_native_command_datadir();
    t->rebound = false;
    t->saved_port = zcl_native_command_rpc_port();
    (void)snprintf(t->saved, sizeof(t->saved), "%s", bound);
    if (!home || !home[0] || !gr_rpc_target_free(bound, home) ||
        !zcl_cli_release_default_datadir(release, sizeof(release), home))
        return;
    /* Initialize first so chain params are selected; a bind alone marks the
     * bridge ready and would skip that. */
    zcl_native_bridge_ensure_rpc();
    zcl_native_bridge_bind_rpc(release, ZCL_CLI_RELEASE_RPC_PORT);
    t->rebound = true;
}

static void gr_rpc_target_leave(const struct gr_rpc_target *t)
{
    if (t->rebound)
        zcl_native_bridge_bind_rpc(t->saved, t->saved_port);
}

static struct zcl_goal_result gr_g4(const struct zcl_goals_options *o)
{
    struct json_value input;
    struct zcl_command_reply reply;
    struct gr_rpc_target target;
    char why[256] = "", own[65] = "";
    int64_t t0, ms;
    bool answered;
    struct zcl_goal_result r;
    const char *next = "card: write a probe page and read it back from "
                       "every admitted host";
    if (o && o->skip_probes)
        return gr_unmeasured(next, "wiki probe skipped");
    json_init(&input);
    json_set_object(&input);
    gr_rpc_target_enter(&target);
    t0 = platform_time_monotonic_ms();
    answered = gr_call("fleet.wiki.list", &input, &reply);
    ms = platform_time_monotonic_ms() - t0;
    if (!answered)
        gr_reason(&reply, why, sizeof(why));
    else
        gr_own_host(own, sizeof(own));
    gr_rpc_target_leave(&target);
    r = zcl_goals_wiki_grade(answered, why, &reply.data, own, gr_now(o), ms);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return r;
}

/* ── G7: warm code lookup ─────────────────────────────────────────────── */

static bool gr_lookup_once(int64_t *ms, char *why, size_t cap)
{
    struct json_value input;
    struct zcl_command_reply reply;
    int64_t t0 = platform_time_monotonic_ms();
    bool ok;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "text", "hotswap");
    (void)json_push_kv_int(&input, "limit", 5);
    ok = gr_call("code.find", &input, &reply);
    *ms = platform_time_monotonic_ms() - t0;
    if (!ok)
        gr_reason(&reply, why, cap);
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static struct zcl_goal_result gr_g7(const struct zcl_goals_options *o)
{
    int64_t ms[GOALS_LOOKUP_SAMPLES], cold, median;
    char why[256];
    const char *next = "card: measure tokens per task with and without MCP "
                       "and report the reduction";
    if (o && o->skip_probes)
        return gr_unmeasured(next, "code lookup probe skipped");
    if (!gr_lookup_once(&cold, why, sizeof(why)))
        return gr_unmeasured("restore the code index in this checkout (see `z23 code guide`)",
                             "code find did not answer: %s", why);
    for (int i = 0; i < GOALS_LOOKUP_SAMPLES; i++)
        if (!gr_lookup_once(&ms[i], why, sizeof(why)))
            return gr_unmeasured(next, "code find stopped answering: %s", why);
    for (int i = 1; i < GOALS_LOOKUP_SAMPLES; i++)
        for (int j = i; j > 0 && ms[j - 1] > ms[j]; j--) {
            int64_t swap = ms[j];
            ms[j] = ms[j - 1];
            ms[j - 1] = swap;
        }
    median = ms[GOALS_LOOKUP_SAMPLES / 2];
    return zcl_goal_make(zcl_goals_grade_lookup(median), next,
                         "code find median %lld ms over %d warm samples "
                         "(first call %lld ms), bar %d ms; token reduction and MCP "
                         "coverage are not measured",
                         (long long)median, GOALS_LOOKUP_SAMPLES, (long long)cold,
                         ZCL_GOALS_LOOKUP_MS_MAX);
}

/* ── G8: vitals sample age per admitted host ──────────────────────────── */

struct gr_age {
    bool found;
    int64_t newest_ts;
    int64_t cadence_s;
    int64_t age_s;
};

static void gr_age_rows(const struct json_value *rows, struct gr_age *a)
{
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        int64_t ts = json_get_int(json_get(row, "timestamp"));
        if (!a->found || ts > a->newest_ts) {
            a->found = true;
            a->newest_ts = ts;
            a->cadence_s = json_get_int(json_get(row, "cadence_s"));
        }
    }
}

/* Walks one host's vitals history to its newest row. False names why not. */
static bool gr_host_age(const struct gr_roster *r, size_t host, int64_t now,
                        struct gr_age *a, char *why, size_t cap)
{
    int64_t after = 0;
    memset(a, 0, sizeof(*a));
    for (int page = 0; page < GOALS_PAGES_MAX; page++) {
        struct json_value input;
        struct zcl_command_reply reply;
        bool ok, more = false;
        json_init(&input);
        json_set_object(&input);
        (void)json_push_kv_str(&input, "box", r->hosts[host].box);
        (void)json_push_kv_int(&input, "after_seq", after);
        ok = gr_call("fleet.vitals.history", &input, &reply);
        if (ok) {
            gr_age_rows(json_get(&reply.data, "rows"), a);
            more = json_get_bool(json_get(&reply.data, "more"));
            after = json_get_int(json_get(&reply.data, "next_seq"));
        } else {
            gr_reason(&reply, why, cap);
        }
        zcl_command_reply_free(&reply);
        json_free(&input);
        if (!ok)
            return false;
        if (!more)
            break;
        if (page == GOALS_PAGES_MAX - 1) {
            (void)snprintf(why, cap, "history longer than %d pages",
                           GOALS_PAGES_MAX);
            return false;
        }
    }
    if (!a->found) {
        (void)snprintf(why, cap, "no vitals row recorded");
        return false;
    }
    a->age_s = now - a->newest_ts;
    return true;
}

static bool gr_age_fresh(const struct gr_age *a)
{
    int64_t cadence = a->cadence_s > 0 ? a->cadence_s : GOALS_DEFAULT_CADENCE_S;
    return a->age_s >= 0 && a->age_s <= 3 * cadence;
}

static struct zcl_goal_result gr_g8(const struct zcl_goals_options *o)
{
    struct gr_roster roster;
    size_t fresh = 0, silent = 0;
    int64_t oldest = 0, now = gr_now(o);
    char why[200] = "";
    const char *next = "card: sample vitals from every admitted host on a "
                       "timer and time the collection";
    gr_roster_load(o, &roster);
    if (!roster.ok)
        return gr_no_roster(&roster);
    for (size_t i = 0; i < roster.count; i++) {
        struct gr_age a;
        if (!gr_host_age(&roster, i, now, &a, why, sizeof(why))) {
            silent++;
            continue;
        }
        fresh += gr_age_fresh(&a) ? 1u : 0u;
        oldest = a.age_s > oldest ? a.age_s : oldest;
    }
    if (silent == roster.count)
        return gr_unmeasured(next, "%zu admitted host(s), no vitals history "
                             "readable on this node (%s)", roster.count, why);
    return zcl_goal_make(zcl_goals_grade_fresh(fresh, roster.count), next,
                         "%zu of %zu admitted host(s) have a vitals sample within "
                         "3 cadences (%zu without a readable history, oldest "
                         "sample %lld s); the one-second collection bound is not "
                         "measured",
                         fresh, roster.count, silent, (long long)oldest);
}

/* ── landing ledger: G9 trains and D7 groups ──────────────────────────── */

#define GOALS_LEDGER_SLACK_S 3600
#define GOALS_GROUPS 20
#define GOALS_SPACING_MAX_S 1200

/* Newest timestamped row of the local ledger, whatever its state. */
struct gr_ledger {
    int64_t newest;
    char newest_ts[64];
};

static void gr_ledger_note(struct gr_ledger *l, const struct json_value *row)
{
    const char *s = json_get_str(json_get(row, "ts"));
    int64_t ts;
    if (!zcl_objectives_parse_iso8601(s, &ts) || ts <= l->newest)
        return;
    l->newest = ts;
    (void)snprintf(l->newest_ts, sizeof(l->newest_ts), "%s", s);
}

/* Commit time of origin/main, which every host holds; 0 when git cannot say. */
static int64_t gr_origin_tip_time(const struct zcl_goals_options *o,
                                  const char *repo)
{
    char out[64];
    const char *argv[] = {"git", "-C", repo, "log", "-1", "--format=%ct",
                          "origin/main", NULL};
    if (o && o->origin_tip_unix > 0)
        return o->origin_tip_unix;
    if (zcl_spawn_capture(argv, out, sizeof(out), 5000) != 0)
        return 0;
    return strtoll(out, NULL, 10);
}

/* The outcomes ledger is written only on the host that lands. A copy whose
 * newest row predates origin/main by more than the slack is missing evidence
 * about the landings since, not a measurement of them. */
static bool gr_ledger_stale(const struct zcl_goals_options *o,
                            const char *repo,
                            const struct gr_ledger *l, char *why, size_t cap)
{
    int64_t tip = gr_origin_tip_time(o, repo);
    if (tip <= 0 || tip <= l->newest + GOALS_LEDGER_SLACK_S)
        return false;
    (void)snprintf(why, cap, "ledger stale since %s, read on the lander host",
                   l->newest_ts[0] ? l->newest_ts : "never");
    return true;
}

struct gr_trains {
    int64_t since;
    int64_t until;
    int64_t failed;
    int64_t unreadable;
    size_t count;
    char (*keys)[128];
    size_t cap;
    struct gr_ledger led;
};

static bool gr_train_seen(const struct gr_trains *t, const char *key)
{
    for (size_t i = 0; i < t->count; i++)
        if (strcmp(t->keys[i], key) == 0)
            return true;
    return false;
}

static void gr_train_add(struct gr_trains *t, const char *key)
{
    if (t->count == t->cap || gr_train_seen(t, key))
        return;
    (void)snprintf(t->keys[t->count++], sizeof(t->keys[0]), "%s", key);
}

static void gr_train_row(const struct json_value *row, void *user)
{
    struct gr_trains *t = user;
    const char *state = json_get_str(json_get(row, "state"));
    const char *note = json_get_str(json_get(row, "note"));
    const char *key = note[0] ? note : json_get_str(json_get(row, "worktree"));
    int64_t ts;
    gr_ledger_note(&t->led, row);
    if (strcmp(state, "landed") != 0 && strcmp(state, "failed") != 0)
        return;
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &ts)) {
        t->unreadable++;
        return;
    }
    if (ts < t->since || ts > t->until)
        return;
    if (strcmp(state, "landed") == 0)
        gr_train_add(t, key);
    else if (strcmp(state, "failed") == 0)
        t->failed++;
}

/* Commits that reached origin/main in the window; -1 when git cannot say. */
static int64_t gr_origin_commits(const char *repo, int64_t since)
{
    char after[40], out[65536];
    const char *argv[] = {"git", "-C", repo, "log", "origin/main",
                          "--format=%h", after, NULL};
    int64_t n = 0;
    (void)snprintf(after, sizeof(after), "--since=%lld", (long long)since);
    if (zcl_spawn_capture(argv, out, sizeof(out), 5000) != 0)
        return -1;
    for (const char *p = out; *p; p++)
        n += *p == '\n';
    return n;
}

static struct zcl_goal_result gr_g9(const struct zcl_goals_options *o)
{
    struct zcl_objectives_options oo;
    static char keys[GOALS_TRAINS_MAX][128];
    struct gr_trains t = {.keys = keys, .cap = GOALS_TRAINS_MAX};
    char path[512], reason[256] = "", repo[512];
    const char *use = NULL;
    int64_t now = gr_now(o), commits;
    char seen[48];
    const char *next = "land through `dev land` so every train is recorded "
                       "in the outcomes ledger";
    if (!gr_repo(o, repo, sizeof(repo)))
        return gr_unmeasured(next, "%s", GR_NO_CHECKOUT);
    memset(&oo, 0, sizeof(oo));
    oo.outcomes = o ? o->outcomes : NULL;
    if (!zcl_objectives_outcomes_path(&oo, path, sizeof(path), &use))
        return gr_unmeasured(next, "state root unavailable");
    t.since = now - GOALS_DAY_S;
    t.until = now;
    memset(keys, 0, sizeof(keys));
    if (!zcl_objectives_ledger_walk(use, gr_train_row, &t, reason,
                                    sizeof(reason)))
        return gr_unmeasured(next, "%s", reason);
    if (t.unreadable > 0)
        return gr_unmeasured(next, "%lld landed or failed row(s) in %s have "
                             "no readable timestamp", (long long)t.unreadable,
                             use);
    if (gr_ledger_stale(o, repo, &t.led, reason, sizeof(reason)))
        return gr_unmeasured(next, "%s (%s)", reason, use);
    commits = gr_origin_commits(repo, t.since);
    if (commits < 0)
        (void)snprintf(seen, sizeof(seen), "origin/main unreadable");
    else
        (void)snprintf(seen, sizeof(seen), "%lld commit(s) on origin/main",
                       (long long)commits);
    return zcl_goal_make(
              zcl_goals_grade_trains((int64_t)t.count, t.failed), next,
              "%zu landed train(s) and %lld failed attempt(s) in the outcomes "
              "ledger over 24 h, bar %d trains and 0 failures; %s in the same window",
              t.count, (long long)t.failed, ZCL_GOALS_TRAIN_MIN, seen);
}

/* ── D7: the most recent landing groups ───────────────────────────────── */

/* A group is one landed train (consecutive landed rows sharing a note) or
 * one failed attempt. A failure is named when its row carries a dimension. */
struct gr_group {
    int64_t ts;
    char key[128];
    bool landed;
    bool named;
};

struct gr_groups {
    struct gr_group ring[GOALS_GROUPS];
    size_t total;
    int64_t unreadable;
    struct gr_ledger led;
};

static void gr_group_row(const struct json_value *row, void *user)
{
    struct gr_groups *g = user;
    const char *state = json_get_str(json_get(row, "state"));
    const char *note = json_get_str(json_get(row, "note"));
    const char *key = note[0] ? note : json_get_str(json_get(row, "worktree"));
    bool landed = strcmp(state, "landed") == 0;
    struct gr_group *last = g->total ? &g->ring[(g->total - 1) % GOALS_GROUPS]
                                     : NULL;
    struct gr_group *cur;
    int64_t ts;
    gr_ledger_note(&g->led, row);
    if (!landed && strcmp(state, "failed") != 0)
        return;
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &ts)) {
        g->unreadable++;
        return;
    }
    if (landed && last && last->landed && strcmp(last->key, key) == 0) {
        last->ts = ts > last->ts ? ts : last->ts;
        return;
    }
    cur = &g->ring[g->total++ % GOALS_GROUPS];
    cur->ts = ts;
    cur->landed = landed;
    cur->named = json_get_str(json_get(row, "dimension"))[0] != '\0';
    (void)snprintf(cur->key, sizeof(cur->key), "%s", key);
}

/* Median gap between consecutive landed groups, oldest first; -1 when fewer
 * than two landed. Also counts the failures without a named cause. */
static int64_t gr_group_spacing(const struct gr_groups *g, int64_t *unnamed)
{
    int64_t gaps[GOALS_GROUPS], prev = 0;
    size_t n = 0, first = g->total > GOALS_GROUPS ? g->total - GOALS_GROUPS : 0;
    bool have_prev = false;
    *unnamed = 0;
    for (size_t i = first; i < g->total; i++) {
        const struct gr_group *c = &g->ring[i % GOALS_GROUPS];
        if (!c->landed) {
            *unnamed += c->named ? 0 : 1;
            continue;
        }
        if (have_prev)
            gaps[n++] = c->ts > prev ? c->ts - prev : 0;
        prev = c->ts;
        have_prev = true;
    }
    if (n == 0)
        return -1;
    qsort(gaps, n, sizeof(gaps[0]), zcl_cmp_i64);
    return n % 2 ? gaps[n / 2] : (gaps[n / 2 - 1] + gaps[n / 2]) / 2;
}

static struct zcl_goal_result gr_d7(const struct zcl_goals_options *o)
{
    struct zcl_objectives_options oo;
    struct gr_groups g;
    char path[512], reason[256] = "", repo[512];
    const char *use = NULL;
    int64_t unnamed, median;
    const char *next = "land through `dev land` so groups are recorded; "
                       "the under-backlog clause needs a queue-depth record";
    if (!gr_repo(o, repo, sizeof(repo)))
        return gr_unmeasured(next, "%s", GR_NO_CHECKOUT);
    memset(&oo, 0, sizeof(oo));
    memset(&g, 0, sizeof(g));
    oo.outcomes = o ? o->outcomes : NULL;
    if (!zcl_objectives_outcomes_path(&oo, path, sizeof(path), &use))
        return gr_unmeasured(next, "state root unavailable");
    if (!zcl_objectives_ledger_walk(use, gr_group_row, &g, reason,
                                    sizeof(reason)))
        return gr_unmeasured(next, "%s", reason);
    if (g.unreadable > 0)
        return gr_unmeasured(next, "%lld landed or failed row(s) in %s have "
                             "no readable timestamp", (long long)g.unreadable,
                             use);
    if (gr_ledger_stale(o, repo, &g.led, reason, sizeof(reason)))
        return gr_unmeasured(next, "%s (%s)", reason, use);
    if (g.total < GOALS_GROUPS)
        return gr_unmeasured(next, "%zu landing group(s) recorded in %s, the "
                             "bar reads %d consecutive groups", g.total, use,
                             GOALS_GROUPS);
    median = gr_group_spacing(&g, &unnamed);
    if (median < 0)
        return gr_unmeasured(next, "fewer than two landed groups in the last "
                             "%d groups of %s", GOALS_GROUPS, use);
    return zcl_goal_make(unnamed > 0 ? ZCL_GOAL_FAIL : ZCL_GOAL_PARTIAL, next,
                         "%lld of the last %d groups failed without a named cause "
                         "(bar 0); median spacing of landed groups %lld s (bar %d "
                         "s under backlog); the backlog clause is not measured",
                         (long long)unnamed, GOALS_GROUPS, (long long)median,
                         GOALS_SPACING_MAX_S);
}

/* ── D5: tokens per landed change, graded from the objective ──────────── */

/* The D5 card is the objective `tokens_per_landed_commit` itself: unmeasured
 * when that objective is, else PARTIAL with its value. It is not PASS while
 * the 7-day window still mixes rows the producer over-counted. */
static struct zcl_goal_result gr_d5(const struct zcl_goals_options *o)
{
    static const char next[] =
        "measured by `z23 fleet objectives` (bar 200000 tokens per landed "
        "commit); PASS waits for the window to clear 2026-10-30";
    struct zcl_objectives_options oo;
    struct zcl_objective_value v;
    memset(&oo, 0, sizeof(oo));
    oo.outcomes = o ? o->outcomes : NULL;
    oo.experiments = o ? o->experiments : NULL;
    oo.now = gr_now(o);
    v = zcl_objectives_measure(&oo, "tokens_per_landed_commit");
    if (!v.measured)
        return gr_unmeasured(next, "%s", v.reason);
    return zcl_goal_make(ZCL_GOAL_PARTIAL, next,
                         "%lld tokens per landed commit over 7 days, %s",
                         (long long)v.value, v.note);
}

/* ── G13: active lane claims ──────────────────────────────────────────── */

/* The claims ledger: the explicit claims input, else the git common dir of
 * the resolved repo. False when neither gives a path. */
static bool gr_claims_path(const struct zcl_goals_options *o, const char *repo,
                           char *out, size_t cap)
{
    char common[512];
    const char *argv[] = {"git", "-C", repo, "rev-parse",
                          "--path-format=absolute", "--git-common-dir", NULL};
    char buf[1024];
    size_t n;
    if (o && o->claims)
        return snprintf(out, cap, "%s", o->claims) < (int)cap;
    if (!repo[0] || zcl_spawn_capture(argv, buf, sizeof(buf), 5000) != 0)
        return false;
    n = strcspn(buf, "\r\n");
    if (n == 0 || n >= sizeof(common))
        return false;
    memcpy(common, buf, n);
    common[n] = '\0';
    return snprintf(out, cap, "%s/z23-agent-claims.jsonl", common) < (int)cap;
}

/* A claim is live when its lease has not expired; a legacy row without an
 * expiry stays live until released. */
static bool gr_claim_live(const struct json_value *row, int64_t now)
{
    const struct json_value *e = json_get(row, "expires_unix");
    return !e || e->type != JSON_INT || json_get_int(e) > now;
}

/* Counts live claim rows. A line that is not a JSON object is counted as
 * unreadable rather than guessed at. False when the file cannot be opened. */
static bool gr_claims_scan(const char *path, int64_t now, int64_t *live,
                           int64_t *unreadable)
{
    static char line[GOALS_CLAIM_LINE_MAX];
    FILE *fp = fopen(path, "r");
    if (!fp)
        return false;
    while (fgets(line, sizeof(line), fp)) {
        struct json_value row;
        size_t len = strlen(line);
        bool whole = len > 0 && line[len - 1] == '\n';
        json_init(&row);
        if (whole && json_read(&row, line, len) && row.type == JSON_OBJ)
            *live += gr_claim_live(&row, now) ? 1 : 0;
        else
            *unreadable += len > 1 || !whole;
        json_free(&row);
        while (!whole && fgets(line, sizeof(line), fp))
            whole = strchr(line, '\n') != NULL;
    }
    (void)fclose(fp);
    return true;
}

static struct zcl_goal_result gr_g13(const struct zcl_goals_options *o)
{
    int64_t live = 0, unreadable = 0;
    char path[1024], repo[512];
    const char *next = "card: report review queue age per reviewer";
    if (!gr_repo(o, repo, sizeof(repo)) && !(o && o->claims))
        return gr_unmeasured(next, "%s", GR_NO_CHECKOUT);
    if (!gr_claims_path(o, repo, path, sizeof(path)))
        return gr_unmeasured(next, "no git common dir to hold the claims "
                             "ledger under %s", repo);
    if (!gr_claims_scan(path, gr_now(o), &live, &unreadable))
        return gr_unmeasured(next, "claims ledger %s is missing or "
                             "unreadable", path);
    return zcl_goal_make(zcl_goals_grade_claims(live), next,
                         "%lld live lane claim(s) in the claims ledger (%lld "
                         "unreadable line(s)); review latency is not measured",
                         (long long)live, (long long)unreadable);
}

/* ── D8: shell scripts left on the allowlist ──────────────────────────── */

static int64_t gr_count_entries(const char *path)
{
    char line[1024];
    int64_t n = 0;
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    while (fgets(line, sizeof(line), fp)) {
        const char *p = line + strspn(line, " \t");
        n += *p != '#' && *p != '\n' && *p != '\r' && *p != '\0';
    }
    (void)fclose(fp);
    return n;
}

static struct zcl_goal_result gr_d8(const struct zcl_goals_options *o)
{
    char path[1024], repo[512] = "";
    int64_t n;
    const char *next = "convert allowlisted scripts to nested z23 leaves; "
                       "the allowlist may only shrink";
    if (o && o->bash_allowlist)
        (void)snprintf(path, sizeof(path), "%s", o->bash_allowlist);
    else if (!gr_repo(o, repo, sizeof(repo)))
        return gr_unmeasured(next, "%s", GR_NO_CHECKOUT);
    else
        (void)snprintf(path, sizeof(path), "%s/tools/lint/bash_allowlist.txt",
                       repo);
    n = gr_count_entries(path);
    if (n < 0)
        return gr_unmeasured(next, "no shell script allowlist at %s", path);
    return zcl_goal_make(zcl_goals_grade_scripts(n), next,
                         "%lld shell script(s) on the check-no-new-bash allowlist; the "
                         "host-configuration clause is not measured",
                         (long long)n);
}

/* ── D6: delivery-to-verdict time, in native_fleet_goals_feedback.c ───── */

static struct zcl_goal_result gr_d6(const struct zcl_goals_options *o)
{
    return zcl_goals_feedback_d6(o);
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

typedef struct zcl_goal_result (*gr_fn)(const struct zcl_goals_options *);

static const struct {
    const char *id;
    gr_fn fn;
} k_producers[] = {
    {"G1", gr_g1},   {"G3", gr_g3},   {"G4", gr_g4},   {"G6", gr_g6},
    {"G7", gr_g7},   {"G8", gr_g8},
    {"G9", gr_g9},   {"G12", gr_g12}, {"G13", gr_g13}, {"D7", gr_d7},
    {"D8", gr_d8},   {"D5", gr_d5},  {"D6", gr_d6},
};

struct zcl_goal_result zcl_goals_measure(
    const struct zcl_goals_options *options, const char *id)
{
    const struct gr_static *s;
    struct zcl_goal_result receipt;
    for (size_t i = 0; i < sizeof(k_producers) / sizeof(k_producers[0]); i++)
        if (strcmp(k_producers[i].id, id) == 0)
            return k_producers[i].fn(options);
    if (zcl_goals_receipt_measure(options, id, &receipt))
        return receipt;
    s = gr_find_static(id);
    if (s)
        return gr_from_static(options, s);
    return gr_unmeasured("add a producer in native_fleet_goals.c",
                         "no producer wired for id %s", id);
}
