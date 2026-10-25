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

int test_fleet_objectives_tokens(void);
int test_fleet_objectives_tokens(void)
{
    int failures = 0;
    failures += fox_case_tokens();
    failures += fox_case_tokens_wired();
    if (failures == 0)
        printf("test_fleet_objectives_tokens: all passed\n");
    else
        printf("test_fleet_objectives_tokens: %d FAILED\n", failures);
    return failures;
}
