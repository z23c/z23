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

#include "native_fleet_objectives.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GOALS_DAY_S 86400
#define GOALS_LOOKUP_SAMPLES 5
#define GOALS_DEFAULT_CADENCE_S 300
#define GOALS_PAGES_MAX 200
#define GOALS_TRAINS_MAX 256
#define GOALS_CLAIM_LINE_MAX 16384

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

enum zcl_goal_grade zcl_goals_grade_scripts(int64_t scripts)
{
    return scripts == 0 ? ZCL_GOAL_PASS : ZCL_GOAL_PARTIAL;
}

/* ── result helpers ───────────────────────────────────────────────────── */

static struct zcl_goal_result gr_make(enum zcl_goal_grade grade,
                                      const char *next, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static struct zcl_goal_result gr_make(enum zcl_goal_grade grade,
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
    gr_make(ZCL_GOAL_UNMEASURED, (next), __VA_ARGS__)

static int64_t gr_now(const struct zcl_goals_options *o)
{
    return o && o->now_unix > 0 ? o->now_unix : (int64_t)platform_time_wall_time_t();
}

static const char *gr_repo(const struct zcl_goals_options *o)
{
    return o && o->repo ? o->repo : ".";
}

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

static void gr_roster_load(const struct zcl_goals_options *o,
                           struct gr_roster *r)
{
    struct json_value input;
    struct zcl_command_reply reply;
    const struct json_value *rows;
    memset(r, 0, sizeof(*r));
    if (o && o->hosts_given) {
        for (size_t i = 0; i < o->host_count && i < ZCL_GOALS_HOSTS_MAX; i++)
            r->hosts[r->count++] = o->hosts[i];
    } else {
        json_init(&input);
        json_set_object(&input);
        if (!gr_call("fleet.machines", &input, &reply))
            gr_reason(&reply, r->reason, sizeof(r->reason));
        else if ((rows = json_get(&reply.data, "machines")) != NULL)
            for (size_t i = 0; i < rows->num_children &&
                               r->count < ZCL_GOALS_HOSTS_MAX; i++)
                gr_roster_row(&rows->children[i], r);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }
    if (r->count == 0 && !r->reason[0])
        (void)snprintf(r->reason, sizeof(r->reason),
                       "no admitted machines in the roster");
    r->ok = r->count > 0;
}

static struct zcl_goal_result gr_no_roster(const struct gr_roster *r)
{
    return gr_unmeasured("admit machines with `z23 fleet invite` and "
                         "`z23 fleet admit`, then rerun",
                         "no admitted roster: %s", r->reason);
}

/* ── rows whose probe is not in the tree yet ──────────────────────────── */

struct gr_static {
    const char *id;
    bool host_set;
    const char *reason;
    const char *next;
};

static const struct gr_static k_static[] = {
    {"G1", true, "no per-pair throughput receipt reader exists; a directed "
                 "pair probe (`fleet link probe`) dials peers and is not run "
                 "by a read-only card",
     "card: store link probe receipts per directed pair, then read them here"},
    {"G2", false, "no k-of-n hybrid signing probe exists in the tree",
     "card: a signing-quorum status leaf reporting hosts and last signed "
     "release"},
    {"G3", true, "no offline remote-shell reachability receipt exists; "
                 "reaching a host dials it",
     "card: a shell reachability receipt per admitted host"},
    {"G5", true, "no peer-fetch and atomic-install receipt reader exists",
     "card: a plugin swarm status leaf listing per-host installs"},
    {"G10", false, "node liveness needs the canonical datadirs, which this "
                   "card never opens",
     "run `z23 status` on each node host and post the result as a receipt"},
    {"G11", false, "no spend ledger summary is read by this card",
     "card: report `fleet usage` totals as ZCL spent"},
    {"C1", false, "needs a current-candidate install receipt (`make mvp`)",
     "make ci-install-linger"},
    {"C2", false, "needs a current-candidate onion bootstrap receipt",
     "make mvp-onion-local"},
    {"C3", false, "needs a current-candidate cold-start sync receipt",
     "make mvp-coldstart-local"},
    {"C4", false, "needs a current-candidate shielded payment receipt",
     "make test-shielded-payment"},
    {"C5", false, "needs a current-candidate store sale receipt",
     "make ci-mvp-gates"},
    {"C6", false, "needs a 168 h soak evidence report", "make soak-evidence-report"},
    {"C7", false, "needs a current-candidate kill -9 recovery receipt",
     "make test-crash-bootstrap"},
    {"C8", false, "needs a parity service window report from a live node",
     "make soak-evidence-report"},
    {"D1", false, "no reader counts finished runs with complete provider "
                  "counters across hosts",
     "card: report recorded-run share per host from the experiment ledger"},
    {"D2", false, "requests per accepted change are not aggregated",
     "card: aggregate provider requests per landed change"},
    {"D3", false, "no known-answer review set with seeded defects exists",
     "card: build the seeded-defect review set"},
    {"D4", false, "first-time acceptance is not recorded per delivery",
     "card: record review verdicts per delivery"},
    {"D5", false, "tokens per landed change have no producer "
                  "(`tokens_per_landed_commit` is unmeasured)",
     "card: wire the experiment ledger into fleet objectives"},
    {"D6", false, "delivery-to-verdict time is not recorded",
     "card: stamp delivery and verdict times in the test lane"},
    {"D7", false, "unnamed failures and group spacing are not derived from "
                  "the landing ledger",
     "land through `dev land` so groups are recorded"},
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

static struct zcl_goal_result gr_g4(const struct zcl_goals_options *o)
{
    struct json_value input;
    struct zcl_command_reply reply;
    char why[256];
    int64_t t0, ms;
    struct zcl_goal_result r;
    const char *next = "card: write a probe page and read it back from "
                       "every admitted host";
    if (o && o->skip_probes)
        return gr_unmeasured(next, "wiki probe skipped");
    json_init(&input);
    json_set_object(&input);
    t0 = platform_time_monotonic_ms();
    if (!gr_call("fleet.wiki.list", &input, &reply)) {
        gr_reason(&reply, why, sizeof(why));
        r = gr_unmeasured(next, "wiki list did not answer on this node: %s",
                          why);
    } else {
        ms = platform_time_monotonic_ms() - t0;
        r = gr_make(ZCL_GOAL_PARTIAL, next,
                    "fleet.wiki.list answered in %lld ms on this node; "
                    "cross-host read and pinned expiry are not probed",
                    (long long)ms);
    }
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
    return gr_make(zcl_goals_grade_lookup(median), next,
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
    return gr_make(zcl_goals_grade_fresh(fresh, roster.count), next,
                   "%zu of %zu admitted host(s) have a vitals sample within "
                   "3 cadences (%zu without a readable history, oldest "
                   "sample %lld s); the one-second collection bound is not "
                   "measured",
                   fresh, roster.count, silent, (long long)oldest);
}

/* ── G9: landed trains in the last 24 h ───────────────────────────────── */

struct gr_trains {
    int64_t since;
    int64_t until;
    int64_t failed;
    size_t count;
    char (*keys)[128];
    size_t cap;
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
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")), &ts))
        return;
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
    char path[512], reason[256] = "";
    const char *use = NULL;
    int64_t now = gr_now(o), commits;
    char seen[48];
    const char *next = "land through `dev land` so every train is recorded "
                       "in the outcomes ledger";
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
    commits = gr_origin_commits(gr_repo(o), t.since);
    if (commits < 0)
        (void)snprintf(seen, sizeof(seen), "origin/main unreadable");
    else
        (void)snprintf(seen, sizeof(seen), "%lld commit(s) on origin/main",
                       (long long)commits);
    return gr_make(
        zcl_goals_grade_trains((int64_t)t.count, t.failed), next,
        "%zu landed train(s) and %lld failed attempt(s) in the outcomes "
        "ledger over 24 h, bar %d trains and 0 failures; %s in the same window",
        t.count, (long long)t.failed, ZCL_GOALS_TRAIN_MIN, seen);
}

/* ── G13: active lane claims ──────────────────────────────────────────── */

static bool gr_claims_path(const struct zcl_goals_options *o, char *out,
                           size_t cap)
{
    char common[512];
    const char *argv[] = {"git", "-C", gr_repo(o), "rev-parse",
                          "--path-format=absolute", "--git-common-dir", NULL};
    char buf[1024];
    size_t n;
    if (o && o->claims)
        return snprintf(out, cap, "%s", o->claims) < (int)cap;
    if (zcl_spawn_capture(argv, buf, sizeof(buf), 5000) != 0)
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
    char path[1024];
    const char *next = "card: report review queue age per reviewer";
    if (!gr_claims_path(o, path, sizeof(path)))
        return gr_unmeasured(next, "no git common dir to hold the claims "
                             "ledger under %s", gr_repo(o));
    if (!gr_claims_scan(path, gr_now(o), &live, &unreadable) && access(path, F_OK) == 0)
        return gr_unmeasured(next, "claims ledger %s is not readable", path);
    return gr_make(zcl_goals_grade_claims(live), next,
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
    char path[1024];
    int64_t n;
    const char *next = "convert allowlisted scripts to nested z23 leaves; "
                       "the allowlist may only shrink";
    if (o && o->bash_allowlist)
        (void)snprintf(path, sizeof(path), "%s", o->bash_allowlist);
    else
        (void)snprintf(path, sizeof(path), "%s/tools/lint/bash_allowlist.txt",
                       gr_repo(o));
    n = gr_count_entries(path);
    if (n < 0)
        return gr_unmeasured(next, "no bash allowlist at %s", path);
    return gr_make(zcl_goals_grade_scripts(n), next,
                   "%lld bash script(s) on the check-no-new-bash allowlist",
                   (long long)n);
}

/* ── dispatch ─────────────────────────────────────────────────────────── */

typedef struct zcl_goal_result (*gr_fn)(const struct zcl_goals_options *);

static const struct {
    const char *id;
    gr_fn fn;
} k_producers[] = {
    {"G4", gr_g4},   {"G6", gr_g6},   {"G7", gr_g7},   {"G8", gr_g8},
    {"G9", gr_g9},   {"G12", gr_g12}, {"G13", gr_g13}, {"D8", gr_d8},
};

struct zcl_goal_result zcl_goals_measure(
    const struct zcl_goals_options *options, const char *id)
{
    const struct gr_static *s;
    for (size_t i = 0; i < sizeof(k_producers) / sizeof(k_producers[0]); i++)
        if (strcmp(k_producers[i].id, id) == 0)
            return k_producers[i].fn(options);
    s = gr_find_static(id);
    if (s)
        return gr_from_static(options, s);
    return gr_unmeasured("add a producer in native_fleet_goals.c",
                         "no producer wired for id %s", id);
}
