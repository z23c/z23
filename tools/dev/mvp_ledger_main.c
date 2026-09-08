/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: CLI shim for the MVP experiment ledger — build/bin/z23-mvp-ledger.
 *          The measurement itself lives in tools/dev/mvp_ledger.c,
 *          mvp_ledger_tsv.c, mvp_ledger_plan.c, mvp_ledger_join.c and
 *          mvp_ledger_kpi.c so the test harness links it without a main(). */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"
#include "mvp_ledger_internal.h"

#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { MVL_RENDER_CAP = 65536 };

struct mvl_opts {
    const char *mode;
    const char *session;
    const char *plan;
    const char *out;
    const char *trains;
    const char *ancestry;
    const char *origin_main;
    const char *note;
    const char *since;
    const char *utc;
    const char *scratch;
    const char *groups;
    const char *lanes;
};

/* The evidence world, plus the tables its view points into. One loader and
 * one releaser, so every mode asks the same questions of the same files. */
struct mvl_world {
    struct mvl_evidence_world view;
    char (*ancestry)[MVL_ID_CAP];
    struct mvl_names verdict_lanes;
    struct mvl_names groups;
};

static void mvl_usage(void)
{
    fputs(
"z23-mvp-ledger <mode> [options] — measure the 144-loop MVP experiment.\n"
"\n"
"MODES\n"
"  agents    scan a Claude session and write <out>/agents.tsv. Columns:\n"
"            agent_id description lane kind model first_utc last_utc wall_s\n"
"            turns tool_uses tokens_out thinking_tokens tokens_in\n"
"            input_tokens cache_creation_tokens cache_read_tokens\n"
"            harness_tokens outcome.\n"
"            One row per subagent transcript, one per workflow (design)\n"
"            agent under subagents/workflows/*/, and one for the\n"
"            orchestrator session itself with lane=orchestrator.\n"
"  loops     read the plan of record and <out>/agents.tsv, write\n"
"            <out>/loops.tsv. Columns: id title state lane evidence agents\n"
"            tokens_out tokens_in tool_uses wall_s first_utc last_utc\n"
"            verifier_rounds landed verified_by. Agents join a loop by lane\n"
"            name; a train assembler is split evenly across the loops whose\n"
"            lane is on that train, a design workflow across the loops whose\n"
"            evidence names it.\n"
"  snapshot  append one row to <out>/snapshots.tsv. Columns: utc landed\n"
"            train ready in_flight designing verify_first queued dropped\n"
"            verified_pct tokens_out tokens_in tool_uses agent_wall_s\n"
"            origin_main note.\n"
"  kpi       append one row to <out>/kpi.tsv — verified MVP progress per\n"
"            token. Columns: utc window verified_loops verified_subrows\n"
"            landed_loops sweep_loops sweep_unregistered tokens_raw\n"
"            tokens_out tcu loops_per_mtcu tcu_per_loop note.\n"
"  progress  print the per-milestone bars and the MVP bar; with --session,\n"
"            add the cost line and the KPI line.\n"
"\n"
"WHAT VERIFIES A LOOP (the verified_by column, in this order)\n"
"  landed    evidence is a commit, a comma-separated list of them, or a\n"
"            range `a..b`, and every sha (the `b` of a range) is in\n"
"            --ancestry\n"
"  sweep     evidence is `ONLY=<group>` and <group> is registered in the\n"
"            --groups catalog. A sweep is how the experiment verifies a\n"
"            loop whose capability already existed.\n"
"  verdict   the loop's lane has a VERDICT under --scratch whose first line\n"
"            starts with LAND, written at or after --since\n"
"  sweep_group_unregistered  a sweep naming a group the catalog does not\n"
"            carry: UNVERIFIED, and reported on stderr with its plan line\n"
"  sweep_not_asked  a sweep with no --groups given: UNVERIFIED\n"
"  -         nothing proves it. A doc path never verifies a loop.\n"
"\n"
"OPTIONS\n"
"  --session <dir>      the session directory holding subagents/ (its\n"
"                       sibling <dir>.jsonl is the orchestrator transcript)\n"
"  --plan <file>        the plan of record (TODO grammar)\n"
"  --out <dir>          where agents/loops/snapshots/kpi .tsv live\n"
"  --trains <dir>       holds trainN/late_picks.txt for the assembler split\n"
"  --ancestry <file>    one `git rev-list <ref>` output; without it the\n"
"                       landed column stays '-' (not asked)\n"
"  --groups <file>      one `git show <ref>:tools/dev/test_group_catalog.def`\n"
"                       output — the SAME ref the ancestry came from\n"
"  --lanes <dir>        lane worktrees, for attributing a \"Fix …\" agent\n"
"                       (default $HOME/.z23/lanes)\n"
"  --origin-main <sha>  recorded in the snapshot row\n"
"  --note <text>        recorded in the snapshot or KPI row\n"
"  --since <utc>        t0: drop agents whose last turn is before it, and\n"
"                       count only VERDICTs written at or after it\n"
"  --scratch <dir>      holds v<lane>/VERDICT (default\n"
"                       $HOME/.local/state/zclassic23/scratch)\n"
"  --utc <stamp>        the appended row's timestamp (default: now)\n"
"\n"
"An append refuses when the ledger's first line is not this build's header.\n"
"Exit status is 0 only when every input parsed. Every refusal names the\n"
"file, the line number and the reason. A sweep naming an unregistered group\n"
"is reported the same way but does not stop the run: it is a fact about one\n"
"plan row, not a malformed input.\n", stdout);
}

static const char *mvl_arg(int argc, char **argv, int *i)
{
    if (*i + 1 >= argc)
        return NULL;
    *i += 1;
    return argv[*i];
}

static bool mvl_parse_opts(int argc, char **argv, struct mvl_opts *o)
{
    static const struct {
        const char *flag;
        size_t offset;
    } table[] = {
        {"--session", offsetof(struct mvl_opts, session)},
        {"--plan", offsetof(struct mvl_opts, plan)},
        {"--out", offsetof(struct mvl_opts, out)},
        {"--trains", offsetof(struct mvl_opts, trains)},
        {"--ancestry", offsetof(struct mvl_opts, ancestry)},
        {"--origin-main", offsetof(struct mvl_opts, origin_main)},
        {"--note", offsetof(struct mvl_opts, note)},
        {"--since", offsetof(struct mvl_opts, since)},
        {"--scratch", offsetof(struct mvl_opts, scratch)},
        {"--groups", offsetof(struct mvl_opts, groups)},
        {"--lanes", offsetof(struct mvl_opts, lanes)},
        {"--utc", offsetof(struct mvl_opts, utc)},
    };

    for (int i = 2; i < argc; i++) {
        bool matched = false;

        for (size_t k = 0; k < sizeof table / sizeof table[0]; k++) {
            const char **slot;

            if (strcmp(argv[i], table[k].flag) != 0)
                continue;
            slot = (const char **)(void *)((char *)o + table[k].offset);
            *slot = mvl_arg(argc, argv, &i);
            if (!*slot) {
                fprintf(stderr, "z23-mvp-ledger: %s needs a value\n",
                        table[k].flag);
                return false;
            }
            matched = true;
            break;
        }
        if (!matched) {
            fprintf(stderr, "z23-mvp-ledger: unknown option %s\n", argv[i]);
            return false;
        }
    }
    return true;
}

static bool mvl_need(const char *value, const char *flag)
{
    if (value)
        return true;
    fprintf(stderr, "z23-mvp-ledger: %s is required for this mode\n", flag);
    return false;
}

static void mvl_path(char *buf, size_t cap, const char *dir, const char *name)
{
    if (!mvl_path_of(buf, cap, dir, "/", name, ""))
        buf[0] = '\0';
}

static void mvl_now(const char *given, char *out, size_t cap)
{
    time_t t;
    struct tm tmv;

    if (given) {
        (void)snprintf(out, cap, "%s", given);
        return;
    }
    t = time(NULL);
    if (gmtime_r(&t, &tmv))
        (void)strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    else
        (void)snprintf(out, cap, "1970-01-01T00:00:00Z");
}

static void mvl_scratch_dir(const struct mvl_opts *o, char *out, size_t cap)
{
    const char *home = getenv("HOME");

    if (o->scratch)
        (void)snprintf(out, cap, "%s", o->scratch);
    else
        (void)snprintf(out, cap, "%s/.local/state/zclassic23/scratch",
                       home ? home : ".");
}

/* Drops the agents that finished before --since, keeping the table dense. */
static void mvl_apply_since(struct mvl_agents *agents, const char *since)
{
    size_t kept = 0;

    if (!since)
        return;
    for (size_t i = 0; i < agents->count; i++) {
        if (strcmp(agents->rows[i].last_utc, since) < 0)
            continue;
        agents->rows[kept++] = agents->rows[i];
    }
    agents->count = kept;
}

static bool mvl_load(const struct mvl_opts *o, struct mvl_plan *plan,
                     struct mvl_agents *agents, char *err, size_t err_cap)
{
    char path[MVL_PATH_CAP];

    if (!mvl_plan_alloc(plan) || !mvl_agents_alloc(agents)) {
        (void)snprintf(err, err_cap, "-:0: mvl_overflow: no tables");
        return false;
    }
    if (!mvl_parse_plan(o->plan, plan, err, err_cap))
        return false;
    mvl_path(path, sizeof path, o->out, "agents.tsv");
    if (!mvl_read_agents(path, agents, err, err_cap))
        return false;
    mvl_apply_since(agents, o->since);
    return true;
}

static bool mvl_load_ancestry(const struct mvl_opts *o, struct mvl_world *w,
                              char *err, size_t err_cap)
{
    if (!o->ancestry)
        return true;
    w->ancestry = zcl_calloc(MVL_MAX_ANCESTRY, MVL_ID_CAP, "mvl_ancestry");
    if (!w->ancestry) {
        (void)snprintf(err, err_cap, "%s:0: mvl_overflow: no ancestry table",
                       o->ancestry);
        return false;
    }
    w->view.ancestry = (const char (*)[MVL_ID_CAP])w->ancestry;
    return mvl_read_ancestry(o->ancestry, w->ancestry, MVL_MAX_ANCESTRY,
                             &w->view.ancestry_count, err, err_cap);
}

/* The lanes a verifier landed at or after t0. `--since` is t0; without it
 * every VERDICT counts. */
static bool mvl_load_verdicts(const struct mvl_opts *o, struct mvl_world *w,
                              char *err, size_t err_cap)
{
    char scratch[MVL_PATH_CAP];
    int64_t t0 = 0;

    if (o->since && !mvl_parse_timestamp(o->since, &t0)) {
        (void)snprintf(err, err_cap, "--since:0: mvl_bad_timestamp: %s",
                       o->since);
        return false;
    }
    if (!mvl_names_alloc(&w->verdict_lanes, MVL_MAX_TRAIN_LANES)) {
        (void)snprintf(err, err_cap, "-:0: mvl_overflow: no lane table");
        return false;
    }
    w->view.verdict_lanes = &w->verdict_lanes;
    mvl_scratch_dir(o, scratch, sizeof scratch);
    return mvl_verified_lanes(scratch, t0, &w->verdict_lanes, err, err_cap);
}

static bool mvl_load_groups(const struct mvl_opts *o, struct mvl_world *w,
                            char *err, size_t err_cap)
{
    if (!o->groups)
        return true;
    if (!mvl_names_alloc(&w->groups, MVL_MAX_NAMES)) {
        (void)snprintf(err, err_cap, "%s:0: mvl_overflow: no group table",
                       o->groups);
        return false;
    }
    w->view.groups = &w->groups;
    return mvl_read_groups(o->groups, &w->groups, err, err_cap);
}

/* Loads every input a loop's status is decided against. A missing option
 * leaves that field absent, which the columns report as "not asked" — the
 * one thing this never does is fill a gap with a guessed no. */
static bool mvl_world_load(const struct mvl_opts *o, struct mvl_world *w,
                           char *err, size_t err_cap)
{
    memset(w, 0, sizeof *w);
    if (!mvl_load_ancestry(o, w, err, err_cap))
        return false;
    if (!mvl_load_verdicts(o, w, err, err_cap))
        return false;
    return mvl_load_groups(o, w, err, err_cap);
}

static void mvl_world_free(struct mvl_world *w)
{
    free(w->ancestry);
    mvl_names_free(&w->verdict_lanes);
    mvl_names_free(&w->groups);
    memset(w, 0, sizeof *w);
}

/* Every mode that resolves evidence reports its sweep refusals: a refusal a
 * reader cannot see is not a refusal. */
static void mvl_report_sweeps(const struct mvl_opts *o,
                              const struct mvl_plan *plan,
                              const struct mvl_world *w)
{
    (void)mvl_report_sweep_refusals(plan, &w->view, o->plan, stderr);
}

/* The lane names a "Fix …" description can be attributed to. */
static bool mvl_load_lane_names(const struct mvl_opts *o,
                                struct mvl_names *known, char *err,
                                size_t err_cap)
{
    char scratch[MVL_PATH_CAP];
    char lanes[MVL_PATH_CAP];
    const char *home = getenv("HOME");

    if (!mvl_names_alloc(known, MVL_MAX_NAMES)) {
        (void)snprintf(err, err_cap, "-:0: mvl_overflow: no lane-name table");
        return false;
    }
    mvl_scratch_dir(o, scratch, sizeof scratch);
    if (o->lanes)
        (void)snprintf(lanes, sizeof lanes, "%s", o->lanes);
    else
        (void)snprintf(lanes, sizeof lanes, "%s/.z23/lanes",
                       home ? home : ".");
    return mvl_read_lane_names(lanes, scratch, known, err, err_cap);
}

/* Scans the session with the lane names loaded, so a "Fix …" agent lands on
 * the lane it names instead of in the unattributed pile. */
static bool mvl_scan_with_lanes(const struct mvl_opts *o,
                                struct mvl_agents *agents, char *err,
                                size_t err_cap)
{
    struct mvl_names known = {0};
    bool ok = mvl_load_lane_names(o, &known, err, err_cap);

    if (ok)
        ok = mvl_scan_session(o->session, &known, agents, err, err_cap);
    mvl_names_free(&known);
    return ok;
}

static int mvl_mode_agents(const struct mvl_opts *o)
{
    struct mvl_agents agents = {0};
    char err[MVL_ERR_CAP] = "";
    char path[MVL_PATH_CAP];
    bool ok;

    if (!mvl_need(o->session, "--session") || !mvl_need(o->out, "--out"))
        return 2;
    if (!mvl_agents_alloc(&agents))
        return 2;
    ok = mvl_scan_with_lanes(o, &agents, err, sizeof err);
    if (ok) {
        mvl_apply_since(&agents, o->since);
        mvl_path(path, sizeof path, o->out, "agents.tsv");
        ok = mvl_write_agents(path, &agents, err, sizeof err);
        if (ok)
            printf("agents: %zu rows -> %s\n", agents.count, path);
    }
    if (!ok)
        fprintf(stderr, "z23-mvp-ledger: %s\n", err);
    mvl_agents_free(&agents);
    return ok ? 0 : 1;
}

static int mvl_mode_loops(const struct mvl_opts *o)
{
    struct mvl_plan plan = {0};
    struct mvl_agents agents = {0};
    struct mvl_world world = {0};
    struct mvl_join *joins;
    char err[MVL_ERR_CAP] = "";
    char path[MVL_PATH_CAP];
    bool ok;

    if (!mvl_need(o->plan, "--plan") || !mvl_need(o->out, "--out"))
        return 2;
    ok = mvl_load(o, &plan, &agents, err, sizeof err);
    if (ok)
        ok = mvl_world_load(o, &world, err, sizeof err);
    joins = ok ? zcl_calloc(MVL_MAX_LOOPS, sizeof *joins, "mvl_joins") : NULL;
    if (ok && !joins) {
        (void)snprintf(err, sizeof err, "-:0: mvl_overflow: no join table");
        ok = false;
    }
    if (ok) {
        mvl_join_loops(&plan, &agents, o->trains, &world.view, joins);
        mvl_report_sweeps(o, &plan, &world);
        mvl_path(path, sizeof path, o->out, "loops.tsv");
        ok = mvl_write_loops(path, &plan, joins, err, sizeof err);
        if (ok)
            printf("loops: %zu rows (%lld in the 144 universe) -> %s\n",
                   plan.loop_count, (long long)plan.universe, path);
    }
    if (!ok)
        fprintf(stderr, "z23-mvp-ledger: %s\n", err);
    free(joins);
    mvl_world_free(&world);
    mvl_agents_free(&agents);
    mvl_plan_free(&plan);
    return ok ? 0 : 1;
}

static int mvl_mode_snapshot(const struct mvl_opts *o)
{
    struct mvl_plan plan = {0};
    struct mvl_agents agents = {0};
    char err[MVL_ERR_CAP] = "";
    char path[MVL_PATH_CAP];
    char utc[MVL_UTC_CAP];
    bool ok;

    if (!mvl_need(o->plan, "--plan") || !mvl_need(o->out, "--out"))
        return 2;
    mvl_now(o->utc, utc, sizeof utc);
    ok = mvl_load(o, &plan, &agents, err, sizeof err);
    if (ok) {
        mvl_path(path, sizeof path, o->out, "snapshots.tsv");
        ok = mvl_append_snapshot(path, &plan, &agents, utc, o->origin_main,
                                 o->note, err, sizeof err);
        if (ok)
            printf("snapshot: %s appended to %s\n", utc, path);
    }
    if (!ok)
        fprintf(stderr, "z23-mvp-ledger: %s\n", err);
    mvl_agents_free(&agents);
    mvl_plan_free(&plan);
    return ok ? 0 : 1;
}

static int mvl_mode_kpi(const struct mvl_opts *o)
{
    struct mvl_plan plan = {0};
    struct mvl_agents agents = {0};
    struct mvl_kpi kpi = {0};
    struct mvl_world world = {0};
    char err[MVL_ERR_CAP] = "";
    char path[MVL_PATH_CAP];
    char utc[MVL_UTC_CAP];
    char window[MVL_UTC_CAP * 2 + 4];
    char line[512];
    bool ok;

    if (!mvl_need(o->plan, "--plan") || !mvl_need(o->out, "--out"))
        return 2;
    mvl_now(o->utc, utc, sizeof utc);
    (void)snprintf(window, sizeof window, "%s..%s",
                   o->since ? o->since : "all", utc);
    ok = mvl_load(o, &plan, &agents, err, sizeof err);
    if (ok)
        ok = mvl_world_load(o, &world, err, sizeof err);
    if (ok) {
        mvl_compute_kpi(&plan, &agents, &world.view, &kpi);
        mvl_report_sweeps(o, &plan, &world);
        mvl_path(path, sizeof path, o->out, "kpi.tsv");
        ok = mvl_append_kpi(path, &kpi, utc, window, o->note, err, sizeof err);
        if (ok && mvl_render_kpi(&kpi, line, sizeof line) < sizeof line)
            fputs(line, stdout);
    }
    if (!ok)
        fprintf(stderr, "z23-mvp-ledger: %s\n", err);
    mvl_world_free(&world);
    mvl_agents_free(&agents);
    mvl_plan_free(&plan);
    return ok ? 0 : 1;
}

/* The cost and KPI tails `progress` prints when a session was given. */
static bool mvl_progress_tail(const struct mvl_opts *o,
                              const struct mvl_plan *plan, char *render,
                              char *err, size_t err_cap)
{
    struct mvl_agents agents = {0};
    struct mvl_kpi kpi = {0};
    struct mvl_world world = {0};
    bool ok;

    if (!mvl_agents_alloc(&agents)) {
        (void)snprintf(err, err_cap, "-:0: mvl_overflow: no agent table");
        return false;
    }
    ok = mvl_scan_with_lanes(o, &agents, err, err_cap);
    if (ok) {
        mvl_apply_since(&agents, o->since);
        if (mvl_render_cost(&agents, render, MVL_RENDER_CAP) < MVL_RENDER_CAP)
            fputs(render, stdout);
        ok = mvl_world_load(o, &world, err, err_cap);
    }
    if (ok) {
        mvl_compute_kpi(plan, &agents, &world.view, &kpi);
        mvl_report_sweeps(o, plan, &world);
        if (mvl_render_kpi(&kpi, render, MVL_RENDER_CAP) < MVL_RENDER_CAP)
            fputs(render, stdout);
    }
    mvl_world_free(&world);
    mvl_agents_free(&agents);
    return ok;
}

static int mvl_mode_progress(const struct mvl_opts *o)
{
    struct mvl_plan plan = {0};
    char err[MVL_ERR_CAP] = "";
    char *render;
    bool ok;

    if (!mvl_need(o->plan, "--plan"))
        return 2;
    if (!mvl_plan_alloc(&plan))
        return 2;
    ok = mvl_parse_plan(o->plan, &plan, err, sizeof err);
    render = ok ? zcl_calloc(1, MVL_RENDER_CAP, "mvl_render") : NULL;
    if (ok && !render) {
        (void)snprintf(err, sizeof err, "-:0: mvl_overflow: no render buffer");
        ok = false;
    }
    if (ok) {
        if (mvl_render_progress(&plan, render, MVL_RENDER_CAP)
            < MVL_RENDER_CAP)
            fputs(render, stdout);
        if (o->session)
            ok = mvl_progress_tail(o, &plan, render, err, sizeof err);
    }
    if (!ok)
        fprintf(stderr, "z23-mvp-ledger: %s\n", err);
    free(render);
    mvl_plan_free(&plan);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    struct mvl_opts o = {0};

    if (argc < 2 || strcmp(argv[1], "--help") == 0
        || strcmp(argv[1], "help") == 0) {
        mvl_usage();
        return argc < 2 ? 2 : 0;
    }
    o.mode = argv[1];
    if (!mvl_parse_opts(argc, argv, &o))
        return 2;
    if (strcmp(o.mode, "agents") == 0)
        return mvl_mode_agents(&o);
    if (strcmp(o.mode, "loops") == 0)
        return mvl_mode_loops(&o);
    if (strcmp(o.mode, "snapshot") == 0)
        return mvl_mode_snapshot(&o);
    if (strcmp(o.mode, "kpi") == 0)
        return mvl_mode_kpi(&o);
    if (strcmp(o.mode, "progress") == 0)
        return mvl_mode_progress(&o);
    fprintf(stderr, "z23-mvp-ledger: unknown mode %s\n", o.mode);
    mvl_usage();
    return 2;
}
