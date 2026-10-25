/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for tokens_per_landed_commit
 * (tools/command/native_fleet_objectives_tokens.c and the agent index in
 * native_fleet_objectives_lanes.c).
 *
 * Fixture ledgers, outcome rows and agent meta files in a tmpdir only. The
 * cases lived in test_fleet_objectives.c, which is over its size limit.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet_objectives.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── tokens_per_landed_commit ─────────────────────────────────────────── */

/* The window is the 7 days before FOX_TOK_NOW (2026-10-23T12:00:00Z). */
#define FOX_TOK_NOW ((int64_t)1792756800)
#define FOX_TOK_IN_A "2026-10-22T10:00:00Z"
#define FOX_TOK_IN_B "2026-10-20T10:00:00Z"
#define FOX_TOK_OLD "2026-09-01T00:00:00Z"
#define FOX_TOK_HEAD                                                        \
    "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\tmodel\t" \
    "effort\ttokens_in\ttokens_out\ttokens_cache\ttokens_reasoning\t"        \
    "tool_uses\tturns\twall_s\toutcome\tlines_added\tlines_removed\t"        \
    "defects\tnote\n"

/* One 22-column experiment ledger row for agent `id` with the given token
 * columns (the 11th, 12th and 13th); the rest is a closed-vocabulary
 * filler. */
static bool fox_tok_row(FILE *f, const char *kind, const char *id,
                        const char *tin, const char *tout, const char *cache)
{
    return fprintf(f,
                   "%s\t%s\tnode1\t%s\tverify\tunknown\tclaude-opus\t"
                   "agent-tool\tm\tmedium\t%s\t%s\t%s\t0\t0\t0\t0\tunknown\t"
                   "0\t0\t0\tfixture\n",
                   FOX_TOK_IN_A, kind, id, tin, tout, cache) > 0;
}

/* One outcomes.jsonl row: a landed/failed attempt whose note starts
 * `<lane>:`. */
static bool fox_tok_outcome(FILE *f, const char *ts, const char *state,
                            const char *lane)
{
    return fprintf(f,
                   "{\"seq\":1,\"ts\":\"%s\",\"state\":\"%s\","
                   "\"note\":\"%s: split a file\"}\n",
                   ts, state, lane) > 0;
}

/* One agent-<id>.meta.json under <root>/s/subagents/workflows/r. */
static bool fox_tok_meta(const char *root, const char *id, const char *label)
{
    char dir[512], path[640];
    FILE *f;
    bool ok;
    (void)snprintf(dir, sizeof(dir), "%s/s", root);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/s/subagents", root);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/s/subagents/workflows", root);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/s/subagents/workflows/r", root);
    (void)mkdir(dir, 0700);
    (void)snprintf(path, sizeof(path), "%s/agent-%s.meta.json", dir, id);
    f = fopen(path, "wb");
    if (!f)
        return false;
    ok = fprintf(f, "{\"agentType\":\"x\",\"description\":\"%s\"}\n", label) > 0;
    return fclose(f) == 0 && ok;
}

static struct zcl_objective_value fox_tok_measure(const char *ledger,
                                                  const char *outcomes)
{
    struct zcl_objectives_options o;
    memset(&o, 0, sizeof(o));
    o.experiments = ledger;
    o.outcomes = outcomes;
    o.now = FOX_TOK_NOW;
    return zcl_objectives_measure(&o, "tokens_per_landed_commit");
}

/* Agents: alpha has a writer (1000 + 200) and a reviewer (300 + 500) = 2000;
 * beta has one fixer (5000 + 1000) = 6000; delta (a failed land) has a
 * writer of 1000000; r1 is research, an unlabeled agent that must not join.
 * The ledger also holds a predict row, a malformed row, and cache reads of
 * 5000 + 100 (alpha) and 300 (beta). */
static bool fox_tok_write_ledger(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fputs(FOX_TOK_HEAD, f) >= 0 &&
         fox_tok_row(f, "result", "a1", "1000", "200", "5000") &&
         fox_tok_row(f, "result", "a2", "300", "500", "100") &&
         fox_tok_row(f, "result", "b1", "5000", "1000", "300") &&
         fox_tok_row(f, "result", "d1", "900000", "100000", "0") &&
         fox_tok_row(f, "result", "r1", "7777777", "1", "0") &&
         fox_tok_row(f, "predict", "a1", "9999", "9999", "0") &&
         fox_tok_row(f, "result", "a1", "12x", "5", "0") &&
         fputs("2026-10-22T10:00:00Z\tresult\tnode1\tshort\n", f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool fox_tok_write_meta(const char *root)
{
    return fox_tok_meta(root, "a1", "write:alpha") &&
           fox_tok_meta(root, "a2", "review:alpha") &&
           fox_tok_meta(root, "b1", "fix:beta") &&
           fox_tok_meta(root, "d1", "write:delta") &&
           fox_tok_meta(root, "r1", "Fix inbound body re-fetch gap");
}

/* Landed in the window: alpha, beta and gamma (no agent). delta failed, and
 * old landed long before the window. */
static bool fox_tok_write_outcomes(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fox_tok_outcome(f, FOX_TOK_IN_A, "landed", "alpha") &&
         fox_tok_outcome(f, FOX_TOK_IN_B, "landed", "beta") &&
         fox_tok_outcome(f, FOX_TOK_IN_B, "landed", "gamma") &&
         fox_tok_outcome(f, FOX_TOK_IN_A, "failed", "delta") &&
         fox_tok_outcome(f, FOX_TOK_OLD, "landed", "old");
    return fclose(f) == 0 && ok;
}

static int fox_case_tokens_measure(const char *root)
{
    int failures = 0;
    char ledger[1024], outcomes[1024];
    struct zcl_objective_value v;
    (void)snprintf(ledger, sizeof(ledger), "%s/rows.tsv", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/tok_outcomes.jsonl", root);
    TEST("objectives: tokens_per_landed_commit is the median over landed "
         "lanes of their agents' uncached input + output") {
        ASSERT(fox_tok_write_ledger(ledger));
        ASSERT(fox_tok_write_outcomes(outcomes));
        ASSERT(fox_tok_write_meta(root));
        ASSERT(setenv("Z23_AGENT_META_ROOT", root, 1) == 0);
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(v.measured);
        /* alpha 2000, beta 6000: the median is their mean. */
        ASSERT_EQ(v.value, (int64_t)4000);
        ASSERT(strstr(v.note, "2 landed lanes joined") != NULL);
        ASSERT(strstr(v.note, "1 landed without an agent") != NULL);
        ASSERT(strstr(v.note, "p90 6000") != NULL);
        /* cache reads: alpha 5100, beta 300, median 2700. */
        ASSERT(strstr(v.note, "cache-read median 2700") != NULL);
        ASSERT(strstr(v.note, "2 malformed") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int fox_case_tokens_refuse(const char *root)
{
    int failures = 0;
    char ledger[1024], outcomes[1024], none[1024];
    struct zcl_objective_value v;
    FILE *f;
    (void)snprintf(ledger, sizeof(ledger), "%s/rows.tsv", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/tok_outcomes.jsonl", root);
    (void)snprintf(none, sizeof(none), "%s/no_such_rows.tsv", root);
    TEST("objectives: tokens_per_landed_commit is unmeasured, naming the "
         "cause, when the ledger is missing") {
        ASSERT(fox_tok_write_outcomes(outcomes));
        v = fox_tok_measure(none, outcomes);
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "missing experiment ledger") != NULL);
        PASS();
    }
    TEST("objectives: tokens_per_landed_commit is unmeasured when no landed "
         "lane joins an agent") {
        ASSERT(fox_tok_write_ledger(ledger));
        f = fopen(outcomes, "wb");
        ASSERT(f != NULL);
        ASSERT(fox_tok_outcome(f, FOX_TOK_IN_A, "landed", "gamma"));
        ASSERT(fox_tok_outcome(f, FOX_TOK_IN_A, "landed", "r1"));
        ASSERT(fclose(f) == 0);
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "no landed lane joins") != NULL);
        PASS();
    }
    TEST("objectives: tokens_per_landed_commit is unmeasured when the window "
         "has no landed row") {
        ASSERT(fox_tok_write_ledger(ledger));
        f = fopen(outcomes, "wb");
        ASSERT(f != NULL);
        ASSERT(fox_tok_outcome(f, FOX_TOK_IN_A, "failed", "alpha"));
        ASSERT(fox_tok_outcome(f, FOX_TOK_OLD, "landed", "alpha"));
        ASSERT(fclose(f) == 0);
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(!v.measured);
        ASSERT(strstr(v.reason, "no landed row") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int fox_case_tokens(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "tokens");
    failures += fox_case_tokens_measure(root);
    failures += fox_case_tokens_refuse(root);
    (void)unsetenv("Z23_AGENT_META_ROOT");
    (void)test_rm_rf_recursive(root);
    return failures;
}

/* One landed outcomes.jsonl row whose note is free text and whose
 * "worktree" is the absolute lane path. */
static bool fox_tok_wt_outcome(FILE *f, const char *note, const char *wt)
{
    return fprintf(f,
                   "{\"seq\":1,\"ts\":\"%s\",\"state\":\"landed\","
                   "\"note\":\"%s\",\"worktree\":\"%s\"}\n",
                   FOX_TOK_IN_A, note, wt) > 0;
}

/* One ledger file holding a single result row for `id` (the rows the join
 * cases below sum). */
static bool fox_tok_one_ledger(const char *path, const char *id,
                               const char *tin, const char *tout)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fputs(FOX_TOK_HEAD, f) >= 0 &&
         fox_tok_row(f, "result", id, tin, tout, "0");
    return fclose(f) == 0 && ok;
}

static bool fox_tok_one_outcome(const char *path, const char *note,
                                const char *wt)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = wt ? fox_tok_wt_outcome(f, note, wt)
            : fox_tok_outcome(f, FOX_TOK_IN_A, "landed", note);
    return fclose(f) == 0 && ok;
}

static int fox_case_tokens_join(const char *root)
{
    int failures = 0;
    char ledger[1024], outcomes[1024];
    struct zcl_objective_value v;
    (void)snprintf(ledger, sizeof(ledger), "%s/join_rows.tsv", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/join_outcomes.jsonl", root);
    TEST("objectives: tokens_per_landed_commit joins a landed row by its "
         "worktree basename when the note has no lane prefix") {
        ASSERT(fox_tok_one_ledger(ledger, "j1", "1000", "200"));
        ASSERT(fox_tok_meta(root, "j1", "write:gamma-lane"));
        ASSERT(fox_tok_one_outcome(outcomes, "restart: nothing",
                                   "/srv/lanes/z23/gamma-lane/"));
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)1200);
        ASSERT(strstr(v.note, "1 landed lanes joined") != NULL);
        PASS();
    }
    TEST("objectives: tokens_per_landed_commit still joins a landed row with "
         "no worktree by its note prefix") {
        ASSERT(fox_tok_one_ledger(ledger, "n1", "5000", "1000"));
        ASSERT(fox_tok_meta(root, "n1", "fix:theta"));
        ASSERT(fox_tok_one_outcome(outcomes, "theta", NULL));
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)6000);
        PASS();
    }
    TEST("objectives: tokens_per_landed_commit sums a lane's design: and "
         "check: agents into its cost") {
        FILE *f = fopen(ledger, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs(FOX_TOK_HEAD, f) >= 0);
        ASSERT(fox_tok_row(f, "result", "e1", "100", "50", "0"));
        ASSERT(fox_tok_row(f, "result", "e2", "300", "200", "0"));
        ASSERT(fox_tok_row(f, "result", "e3", "10", "20", "0"));
        ASSERT(fclose(f) == 0);
        ASSERT(fox_tok_meta(root, "e1", "write:epsilon"));
        ASSERT(fox_tok_meta(root, "e2", "design:epsilon"));
        ASSERT(fox_tok_meta(root, "e3", "check:epsilon"));
        ASSERT(fox_tok_one_outcome(outcomes, "epsilon", NULL));
        v = fox_tok_measure(ledger, outcomes);
        ASSERT(v.measured);
        /* 150 (write) + 500 (design) + 30 (check). */
        ASSERT_EQ(v.value, (int64_t)680);
        PASS();
    }
_test_next:;
    return failures;
}

static int fox_case_tokens_wired(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "tokens_join");
    (void)setenv("Z23_AGENT_META_ROOT", root, 1);
    failures += fox_case_tokens_join(root);
    (void)unsetenv("Z23_AGENT_META_ROOT");
    (void)test_rm_rf_recursive(root);
    return failures;
}

/* ── fleet.objectives.value ───────────────────────────────────────────── */

/* One result row with its model column set (the 9th, 0-based 8th, field). */
static bool fox_val_row(FILE *f, const char *id, const char *model,
                        const char *tin, const char *tout, const char *cache)
{
    return fprintf(f,
                   "%s\tresult\tnode1\t%s\tverify\tunknown\tagent-tool\t"
                   "agent-tool\t%s\tmedium\t%s\t%s\t%s\t0\t0\t0\t0\tunknown\t"
                   "0\t0\t0\tfixture\n",
                   FOX_TOK_IN_A, id, model, tin, tout, cache) > 0;
}

/* Agents: a1 (write:alpha, haiku, 1200 fresh, 5000 cache), a3 (write:alpha,
 * haiku, 100, 0), a2 (review:alpha, sonnet, 800, 100), b1 (fix:beta, haiku,
 * 6000, 300), b2 (write:beta, sonnet, 500, 50). d1 is a failed lane's agent
 * and r1 a research agent: neither counts. One malformed line is skipped. */
static bool fox_val_write_ledger(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fputs(FOX_TOK_HEAD, f) >= 0 &&
         fox_val_row(f, "a1", "claude-haiku-5-5", "1000", "200", "5000") &&
         fox_val_row(f, "a2", "claude-sonnet-4-6", "300", "500", "100") &&
         fox_val_row(f, "a3", "claude-haiku-5-5", "100", "0", "0") &&
         fox_val_row(f, "b1", "claude-haiku-5-5", "5000", "1000", "300") &&
         fox_val_row(f, "b2", "claude-sonnet-4-6", "400", "100", "50") &&
         fox_val_row(f, "d1", "claude-opus-4-7", "900000", "100000", "0") &&
         fox_val_row(f, "r1", "claude-opus-4-7", "7777777", "1", "0") &&
         fputs("2026-10-22T10:00:00Z\tresult\tnode1\tshort\n", f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool fox_val_write_meta(const char *root)
{
    return fox_tok_meta(root, "a1", "write:alpha") &&
           fox_tok_meta(root, "a2", "review:alpha") &&
           fox_tok_meta(root, "a3", "write:alpha") &&
           fox_tok_meta(root, "b1", "fix:beta") &&
           fox_tok_meta(root, "b2", "write:beta") &&
           fox_tok_meta(root, "d1", "write:delta") &&
           fox_tok_meta(root, "r1", "Fix inbound body re-fetch gap");
}

/* A lead transcript: two assistant lines with usage (input 2+3, creation
 * 100+200, cache read 1000+3000, output 50+70), a user line and a line that
 * does not parse. */
static bool fox_lead_write(const char *path)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fputs("{\"type\":\"assistant\",\"message\":{\"usage\":{\"input_tokens\":2,"
               "\"cache_creation_input_tokens\":100,"
               "\"cache_read_input_tokens\":1000,\"output_tokens\":50}}}\n",
               f) >= 0 &&
         fputs("{\"type\":\"user\",\"message\":{\"content\":\"hi\"}}\n", f) >= 0 &&
         fputs("{\"type\":\"assistant\",\"message\":{\"usage\":{\"input_tokens\":3,"
               "\"cache_creation_input_tokens\":200,"
               "\"cache_read_input_tokens\":3000,\"output_tokens\":70}}}\n",
               f) >= 0 &&
         fputs("{\"type\":\"assistant\",\"message\":{\"usage\"\n", f) >= 0;
    return fclose(f) == 0 && ok;
}

/* The lead row on the fixture: 2 calls, fresh 5 + 300 + 120 = 425, cache
 * reads 4000 of 4000 + 5450 worker reads (42 percent), outputs 120 of
 * 120 + 1800 (6 percent), one line skipped. */
static bool fox_lead_is(const struct json_value *data)
{
    const struct json_value *l = json_get(data, "lead");
    return json_get_bool(json_get(l, "measured")) &&
           json_get_int(json_get(l, "calls")) == 2 &&
           json_get_int(json_get(l, "input_tokens")) == 5 &&
           json_get_int(json_get(l, "cache_creation_tokens")) == 300 &&
           json_get_int(json_get(l, "cache_read_tokens")) == 4000 &&
           json_get_int(json_get(l, "output_tokens")) == 120 &&
           json_get_int(json_get(l, "fresh_total")) == 425 &&
           json_get_int(json_get(l, "skipped")) == 1 &&
           json_get_int(json_get(l, "share_cache_read_pct")) == 42 &&
           json_get_int(json_get(l, "share_output_pct")) == 6;
}

/* Runs the report on the fixture; `data` is an object the caller frees.
 * `session` is the lead transcript; a missing path leaves the lead unmeasured. */
static bool fox_val_run(const char *ledger, const char *outcomes,
                        const char *session, struct json_value *data,
                        char *reason, size_t cap)
{
    struct zcl_objectives_options o;
    memset(&o, 0, sizeof(o));
    o.experiments = ledger;
    o.outcomes = outcomes;
    o.session = session;
    o.now = FOX_TOK_NOW;
    json_init(data);
    json_set_object(data);
    return zcl_objectives_value_data(&o, data, reason, cap);
}

struct fox_val_want {
    const char *role;
    const char *model;
    int64_t agents, fresh, fresh_median, cache_median, share;
};

static bool fox_val_row_is(const struct json_value *rows, size_t i,
                           const struct fox_val_want *w)
{
    const struct json_value *r = json_at(rows, i);
    return r && strcmp(json_get_str(json_get(r, "role")), w->role) == 0 &&
           strcmp(json_get_str(json_get(r, "model")), w->model) == 0 &&
           json_get_int(json_get(r, "agents")) == w->agents &&
           json_get_int(json_get(r, "fresh_total")) == w->fresh &&
           json_get_int(json_get(r, "fresh_median")) == w->fresh_median &&
           json_get_int(json_get(r, "cache_median")) == w->cache_median &&
           json_get_int(json_get(r, "share_pct")) == w->share;
}

struct fox_val_role_want {
    const char *role;
    int64_t agents, fresh, share;
};

/* The role summary: write splits across two model families and must total
 * 1800 (20 percent), not two per-model shares. Roles in role order. */
static bool fox_val_role_is(const struct json_value *roles, size_t i,
                            const struct fox_val_role_want *w)
{
    const struct json_value *r = json_at(roles, i);
    return r && strcmp(json_get_str(json_get(r, "role")), w->role) == 0 &&
           json_get_int(json_get(r, "agents")) == w->agents &&
           json_get_int(json_get(r, "fresh_total")) == w->fresh &&
           json_get_int(json_get(r, "share_pct")) == w->share;
}

static bool fox_val_roles_check(const struct json_value *data)
{
    static const struct fox_val_role_want want[] = {
        {"write", 3, 1800, 20},
        {"review", 1, 800, 9},
        {"fix", 1, 6000, 69},
    };
    const struct json_value *roles = json_get(data, "roles");
    if (json_size(roles) != 3u)
        return false;
    for (size_t i = 0; i < 3u; i++)
        if (!fox_val_role_is(roles, i, &want[i]))
            return false;
    return true;
}

/* Rows sorted by fresh total, then the roles, totals, skipped and the
 * screen. */
static bool fox_val_check(const struct json_value *data)
{
    static const struct fox_val_want want[] = {
        {"fix", "haiku", 1, 6000, 6000, 300, 69},
        {"write", "haiku", 2, 1300, 650, 2500, 15},
        {"review", "sonnet", 1, 800, 800, 100, 9},
        {"write", "sonnet", 1, 500, 500, 50, 5},
    };
    const struct json_value *rows = json_get(data, "rows");
    const struct json_value *t = json_get(data, "totals");
    if (json_size(rows) != 4u)
        return false;
    for (size_t i = 0; i < 4u; i++)
        if (!fox_val_row_is(rows, i, &want[i]))
            return false;
    if (!fox_val_roles_check(data))
        return false;
    return json_get_int(json_get(t, "lanes_landed")) == 3 &&
           json_get_int(json_get(t, "lanes_joined")) == 2 &&
           json_get_int(json_get(t, "agents")) == 5 &&
           json_get_int(json_get(t, "fresh_total")) == 8600 &&
           json_get_int(json_get(data, "skipped")) == 1 &&
           strstr(json_get_str(json_get(data, "screen")), "fix") != NULL;
}

static int fox_case_value(const char *root)
{
    int failures = 0;
    char ledger[1024], outcomes[1024], reason[ZCL_OBJECTIVES_REASON_MAX] = "";
    char none[1024], session[1024];
    struct json_value data;
    struct zcl_objective_value kpi;
    bool ok;
    (void)snprintf(ledger, sizeof(ledger), "%s/value_rows.tsv", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/value_outcomes.jsonl", root);
    (void)snprintf(none, sizeof(none), "%s/no_such_rows.tsv", root);
    (void)snprintf(session, sizeof(session), "%s/value_lead.jsonl", root);
    TEST("objectives: fleet.objectives.value groups joined agents by role and "
         "model with exact medians, totals and shares") {
        ASSERT(fox_val_write_ledger(ledger));
        ASSERT(fox_tok_write_outcomes(outcomes));
        ASSERT(fox_val_write_meta(root));
        ASSERT(setenv("Z23_AGENT_META_ROOT", root, 1) == 0);
        ok = fox_val_run(ledger, outcomes, none, &data, reason, sizeof(reason));
        if (ok)
            ok = fox_val_check(&data);
        json_free(&data);
        ASSERT(ok);
        PASS();
    }
    TEST("objectives: fleet.objectives.value reads the lead's usage from the "
         "session transcript, skipping the malformed line") {
        ASSERT(fox_val_write_ledger(ledger));
        ASSERT(fox_tok_write_outcomes(outcomes));
        ASSERT(fox_val_write_meta(root));
        ASSERT(fox_lead_write(session));
        ASSERT(setenv("Z23_AGENT_META_ROOT", root, 1) == 0);
        ok = fox_val_run(ledger, outcomes, session, &data, reason,
                         sizeof(reason));
        if (ok)
            ok = fox_lead_is(&data);
        json_free(&data);
        ASSERT(ok);
        PASS();
    }
    TEST("objectives: fleet.objectives.value marks the lead unmeasured, naming "
         "the cause, when the session transcript is missing") {
        const struct json_value *l;
        ASSERT(fox_val_write_ledger(ledger));
        ASSERT(fox_tok_write_outcomes(outcomes));
        ASSERT(fox_val_write_meta(root));
        ASSERT(setenv("Z23_AGENT_META_ROOT", root, 1) == 0);
        ok = fox_val_run(ledger, outcomes, none, &data, reason, sizeof(reason));
        l = json_get(&data, "lead");
        ok = ok && !json_get_bool(json_get(l, "measured")) &&
             strstr(json_get_str(json_get(l, "reason")),
                    "missing lead transcript") != NULL;
        json_free(&data);
        ASSERT(ok);
        PASS();
    }
    TEST("objectives: fleet.objectives.value leaves tokens_per_landed_commit "
         "unchanged on the same fixture") {
        ASSERT(fox_val_write_ledger(ledger));
        ASSERT(fox_tok_write_outcomes(outcomes));
        ASSERT(fox_val_write_meta(root));
        ASSERT(setenv("Z23_AGENT_META_ROOT", root, 1) == 0);
        ok = fox_val_run(ledger, outcomes, none, &data, reason, sizeof(reason));
        json_free(&data);
        ASSERT(ok);
        /* alpha 2100 (1200 + 800 + 100), beta 6500: the median is their mean. */
        kpi = fox_tok_measure(ledger, outcomes);
        ASSERT(kpi.measured);
        ASSERT_EQ(kpi.value, (int64_t)4300);
        ASSERT(strstr(kpi.note, "2 landed lanes joined") != NULL);
        PASS();
    }
    TEST("objectives: fleet.objectives.value is unmeasured, naming the cause, "
         "when the ledger is missing") {
        ok = fox_val_run(none, outcomes, none, &data, reason, sizeof(reason));
        json_free(&data);
        ASSERT(!ok);
        ASSERT(strstr(reason, "missing experiment ledger") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int fox_case_value_wired(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "value");
    failures += fox_case_value(root);
    (void)unsetenv("Z23_AGENT_META_ROOT");
    (void)test_rm_rf_recursive(root);
    return failures;
}

int test_fleet_objectives_tokens(void);
int test_fleet_objectives_tokens(void)
{
    int failures = 0;
    failures += fox_case_tokens();
    failures += fox_case_tokens_wired();
    failures += fox_case_value_wired();
    if (failures == 0)
        printf("test_fleet_objectives_tokens: all passed\n");
    else
        printf("test_fleet_objectives_tokens: %d FAILED\n", failures);
    return failures;
}
