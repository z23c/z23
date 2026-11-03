/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Acceptance cases for repairs to the fleet objectives reader
 *          (tools/command/native_fleet_objectives_read.c and the agent
 *          index in native_fleet_objectives_lanes.c). Each case pins one
 *          defect: outcome rows stamped after the captured clock, git date
 *          pruning and future commits, train identities longer than the old
 *          note bound, incomplete attempt collections, ranking from a partial
 *          outcome read, hotswap module runs in wall time, baseline keys the
 *          lint loader refuses, and lane labels truncated into an alias.
 *          Called from test_fleet_objectives. */

#include "test/test_core.h"
#include "base/safe_alloc.h"

#include "command/native_fleet_objectives.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

/* 2026-10-22T10:00:00Z: the captured clock every case measures from. */
#define RPR_NOW 1792663200LL
#define RPR_DAY 86400LL

static bool rpr_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len;
    bool wrote;
    if (!f)
        return false;
    len = strlen(text);
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

/* ── landing windows bounded by the captured clock ───────────────────── */

static int rpr_case_window_future(const char *root)
{
    int failures = 0;
    char path[1024];
    struct zcl_objectives_options o = {0};
    (void)snprintf(path, sizeof(path), "%s/window_future.jsonl", root);
    o.now = RPR_NOW;
    o.outcomes = path;
    TEST("objectives: a landing stamped after the captured clock is not counted today") {
        struct zcl_objective_value today;
        ASSERT(rpr_write(path,
            "{\"state\":\"landed\",\"ts\":\"2026-10-22T09:00:00Z\"}\n"
            "{\"state\":\"landed\",\"ts\":\"2026-10-22T10:00:01Z\"}\n"));
        today = zcl_objectives_measure(&o, "landed_rows_today");
        ASSERT(today.measured);
        ASSERT_EQ(today.value, (int64_t)1);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── git windows: date pruning and future commits ───────────────────── */

static int rpr_git(const char *repo, const char *a, const char *b,
                   const char *c, const char *d)
{
    const char *argv[] = {"git", "-C", repo, "-c", "user.name=fixture",
                          "-c", "user.email=fixture@example.invalid",
                          "-c", "commit.gpgsign=false", a, b, c, d, NULL};
    char out[4096];
    return zcl_spawn_capture(argv, out, sizeof(out), 20000);
}

static bool rpr_repo_init(const char *repo)
{
    return mkdir(repo, 0700) == 0 && rpr_git(repo, "init", "-q", NULL, NULL) == 0;
}

/* Writes f.txt with a fresh body and commits it at unix time `when`. */
static bool rpr_commit(const char *repo, long long when, int serial)
{
    char path[1200], body[32], date[64];
    bool ok;
    (void)snprintf(path, sizeof(path), "%s/f.txt", repo);
    (void)snprintf(body, sizeof(body), "%d\n", serial);
    (void)snprintf(date, sizeof(date), "%lld +0000", when);
    if (!rpr_write(path, body))
        return false;
    (void)setenv("GIT_AUTHOR_DATE", date, 1);
    (void)setenv("GIT_COMMITTER_DATE", date, 1);
    ok = rpr_git(repo, "add", "f.txt", NULL, NULL) == 0 &&
         rpr_git(repo, "commit", "-q", "-m", "fixture") == 0;
    (void)unsetenv("GIT_AUTHOR_DATE");
    (void)unsetenv("GIT_COMMITTER_DATE");
    return ok;
}

/* An old-dated HEAD must not prune the walk before today's commit. */
static int rpr_case_git_skew(const char *root)
{
    int failures = 0;
    char repo[1024];
    struct zcl_objectives_options o = {0};
    (void)snprintf(repo, sizeof(repo), "%s/skew", root);
    o.now = RPR_NOW;
    o.repo = repo;
    TEST("objectives: an old-dated commit cannot hide recent ancestors from today's count") {
        struct zcl_objective_value v;
        ASSERT(rpr_repo_init(repo));
        ASSERT(rpr_commit(repo, RPR_NOW - 3600, 1));
        ASSERT(rpr_commit(repo, RPR_NOW - 400 * RPR_DAY, 2));
        v = zcl_objectives_measure(&o, "commits_landed_today");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)1);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── train identities kept whole ─────────────────────────────────────── */

/* Two trains share a 300-byte note prefix. Under a 256-byte identity they
 * merge, and the newest train's latency starts at the other train's row. */
static int rpr_case_train_identity(const char *root)
{
    int failures = 0;
    char path[1024], prefix[304], text[1400];
    struct zcl_objectives_options o = {0};
    (void)snprintf(path, sizeof(path), "%s/train_identity.jsonl", root);
    memset(prefix, 'p', 300);
    prefix[300] = '\0';
    o.now = RPR_NOW;
    o.outcomes = path;
    TEST("objectives: train identities longer than 255 bytes do not merge") {
        struct zcl_objective_value v;
        (void)snprintf(text, sizeof(text),
            "{\"state\":\"failed\",\"ts\":\"2026-10-22T08:00:00Z\","
            "\"note\":\"%sA\"}\n"
            "{\"state\":\"landed\",\"ts\":\"2026-10-22T09:00:00Z\","
            "\"landed_at\":1792663200,\"note\":\"%sB\"}\n", prefix, prefix);
        ASSERT(rpr_write(path, text));
        v = zcl_objectives_measure(&o, "landing_latency_s");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)3600);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── attempt collections complete or refused ──────────────────────────── */

static bool rpr_mkdir(const char *path) { return mkdir(path, 0700) == 0; }

static bool rpr_set_mtime(const char *path, long sec)
{
    struct timeval tv[2] = {{sec, 0}, {sec, 0}};
    return utimes(path, tv) == 0;
}

/* One completed proof attempt <dir>/<name>/logs/ in the layout the proof
 * writes it; the key is the name before its last dot. */
static bool rpr_attempt(const char *dir, const char *name, long long cumulative_ms,
                        const char *test_wall_s, long mtime)
{
    char path[1400], logs[1200], attempt[1100], text[4096], key[200];
    const char *dot = strrchr(name, '.');
    (void)snprintf(key, sizeof(key), "%.*s", dot ? (int)(dot - name) : (int)strlen(name), name);
    (void)snprintf(attempt, sizeof(attempt), "%s/%s", dir, name);
    (void)snprintf(logs, sizeof(logs), "%s/logs", attempt);
    if (!rpr_mkdir(attempt) || !rpr_mkdir(logs))
        return false;
    (void)snprintf(text, sizeof(text),
        "zcl.dev_proof_phase.v1 worktree_exact_root               167 ms  "
        "(cumulative      167 ms)\n"
        "zcl.dev_proof_phase.v1 dimension_lint_and_test %10lld ms  "
        "(cumulative %10lld ms)\n", cumulative_ms - 972798, cumulative_ms);
    (void)snprintf(path, sizeof(path), "%s/phases.txt", logs);
    if (!rpr_write(path, text) || !rpr_set_mtime(path, mtime))
        return false;
    (void)snprintf(text, sizeof(text), "PASS check-toolchain 1607 ms\n"
                   "run_lint.sh: NOTE - wall 1000 ms within budget\n");
    (void)snprintf(path, sizeof(path), "%s/%s.lint.log", logs, key);
    if (!rpr_write(path, text))
        return false;
    (void)snprintf(text, sizeof(text),
        "ALL TESTS PASSED - 0/1359 groups failed, 0 skipped "
        "(%ss wall, 28 workers) [--exact filtered]\n", test_wall_s);
    (void)snprintf(path, sizeof(path), "%s/%s.test.log", logs, key);
    return rpr_write(path, text);
}

/* Seventeen completed attempts force one growth of the candidate set. A
 * failed growth must refuse the whole collection, not rank the first sixteen. */
static int rpr_case_attempt_growth(const char *root)
{
    int failures = 0;
    char dir[1024], outcomes[1024], name[64];
    struct zcl_objectives_options o = {0};
    (void)snprintf(dir, sizeof(dir), "%s/growth", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/growth_outcomes.jsonl", root);
    o.attempts_dir = dir;
    o.outcomes = outcomes;
    o.now = RPR_NOW;
    TEST("objectives: a failed growth of the attempt collection is never measured") {
        struct zcl_objective_value v;
        bool consumed;
        ASSERT(rpr_mkdir(dir));
        ASSERT(rpr_write(outcomes, ""));
        for (int i = 0; i < 17; i++) {
            (void)snprintf(name, sizeof(name), "tip%02d-base.r%02d", i, i);
            ASSERT(rpr_attempt(dir, name, 1000000 + i, "10.0", 1000000000L + i));
        }
        zcl_alloc_fault_fail_nth("fleet_objectives_attempts", 2);
        v = zcl_objectives_measure(&o, "proof_wall_s");
        consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed);
        ASSERT(!v.measured);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── agent lane labels kept whole ─────────────────────────────────────── */

/* One agent-<id>.meta.json under <root>/s/subagents/workflows/r. */
static bool rpr_lane_meta(const char *root, const char *id, const char *label)
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

/* A 103-byte lane is the longest the index keeps. A 104-byte lane must be
 * refused, not truncated into the 103-byte lane it shares a prefix with. */
static int rpr_case_lane_labels(const char *root)
{
    int failures = 0;
    char meta[512], lane[104], label[112];
    (void)snprintf(meta, sizeof(meta), "%s/lane_labels", root);
    TEST("objectives: an overlong agent lane label is refused, not truncated") {
        struct zcl_agent_index ix;
        const char *exact;
        bool built, matched, refused, oom;
        memset(lane, 'a', 103);
        lane[103] = '\0';
        ASSERT(rpr_mkdir(meta));
        ASSERT(setenv("Z23_AGENT_META_ROOT", meta, 1) == 0);
        (void)snprintf(label, sizeof(label), "write:%s", lane);
        ASSERT(rpr_lane_meta(meta, "lane_exact", label));
        (void)snprintf(label, sizeof(label), "write:%sx", lane);
        ASSERT(rpr_lane_meta(meta, "lane_overlong", label));
        (void)snprintf(label, sizeof(label), "write:%sxy", lane);
        ASSERT(rpr_lane_meta(meta, "lane_longer", label));
        built = zcl_objectives_agent_index_build(&ix);
        exact = zcl_objectives_agent_lane(&ix, "lane_exact");
        matched = exact && strcmp(exact, lane) == 0;
        refused = zcl_objectives_agent_lane(&ix, "lane_overlong") == NULL &&
                  zcl_objectives_agent_lane(&ix, "lane_longer") == NULL;
        oom = ix.oom;
        zcl_objectives_agent_index_free(&ix);
        (void)unsetenv("Z23_AGENT_META_ROOT");
        ASSERT(built && !oom);
        ASSERT(matched);
        ASSERT(refused);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── outcome ranking dropped on a failed read ─────────────────────────── */

/* Attempt A is recorded by a valid outcome row, so it outranks B by its
 * recorded time. Once the ledger cannot be read to its end, no row may rank
 * anything: the newest by mtime, B, must win. */
static int rpr_case_outcome_fallback(const char *root)
{
    int failures = 0;
    char dir[1024], outcomes[1024], text[5600];
    const char *row =
        "{\"local\":\"tipA\",\"base\":\"baseA\",\"started\":1792663000,"
        "\"state\":\"landed\"}\n";
    size_t n;
    struct zcl_objectives_options o = {0};
    (void)snprintf(dir, sizeof(dir), "%s/outcome_rank", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/outcome_rank.jsonl", root);
    o.attempts_dir = dir;
    o.outcomes = outcomes;
    o.now = RPR_NOW;
    TEST("objectives: a partially read outcome ledger does not rank attempts") {
        struct zcl_objective_value v;
        ASSERT(rpr_mkdir(dir));
        ASSERT(rpr_attempt(dir, "tipA-baseA.r1", 1000000, "100.0", 1000000000L));
        ASSERT(rpr_attempt(dir, "tipB-baseB.r2", 2000000, "200.0", 2000000000L));
        ASSERT(rpr_write(outcomes, row));
        v = zcl_objectives_measure(&o, "proof_test_wall_s");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)100);
        n = (size_t)snprintf(text, sizeof(text), "%s", row);
        memset(text + n, 'x', 5000);
        text[n + 5000] = '\n';
        text[n + 5001] = '\0';
        ASSERT(rpr_write(outcomes, text));
        v = zcl_objectives_measure(&o, "proof_test_wall_s");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)200);
        PASS();
    }
_test_next:;
    return failures;
}

/* ── hotswap module runs out of ordinary proof timing ─────────────────── */

/* A hotswap module run marks its own suite line; that body is not the wall
 * of the ordinary proof, so a log holding only such a line measures nothing,
 * while an ordinary line still measures. */
static int rpr_case_module_wall(const char *root)
{
    int failures = 0;
    char dir[1024], outcomes[1024], log[1200];
    struct zcl_objectives_options o = {0};
    (void)snprintf(dir, sizeof(dir), "%s/hotswap", root);
    (void)snprintf(outcomes, sizeof(outcomes), "%s/hotswap_outcomes.jsonl", root);
    (void)snprintf(log, sizeof(log), "%s/hot-base.r1/logs/hot-base.test.log", dir);
    o.attempts_dir = dir;
    o.outcomes = outcomes;
    o.now = RPR_NOW;
    TEST("objectives: a hotswap module run does not supply the ordinary suite wall") {
        struct zcl_objective_value v;
        ASSERT(rpr_mkdir(dir));
        ASSERT(rpr_write(outcomes, ""));
        ASSERT(rpr_attempt(dir, "hot-base.r1", 1000000, "10.0", 1000000000L));
        ASSERT(rpr_write(log,
            "ALL TESTS PASSED (HOTSWAP MODULE 0123456789ab) 0/1 groups failed "
            "(30.0s wall, 1 workers)\n"));
        v = zcl_objectives_measure(&o, "proof_test_wall_s");
        ASSERT(!v.measured);
        ASSERT(rpr_write(log,
            "ALL TESTS PASSED 0/1 groups failed (12.0s wall, 1 workers)\n"));
        v = zcl_objectives_measure(&o, "proof_test_wall_s");
        ASSERT(v.measured);
        ASSERT_EQ(v.value, (int64_t)12);
        PASS();
    }
_test_next:;
    return failures;
}

int fox_repair_cases(void);
int fox_repair_cases(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "repair");
    failures += rpr_case_window_future(root);
    failures += rpr_case_git_skew(root);
    failures += rpr_case_train_identity(root);
    failures += rpr_case_attempt_growth(root);
    failures += rpr_case_lane_labels(root);
    failures += rpr_case_outcome_fallback(root);
    failures += rpr_case_module_wall(root);
    (void)test_rm_rf_recursive(root);
    return failures;
}
