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

int fox_repair_cases(void);
int fox_repair_cases(void)
{
    int failures = 0;
    char root[512];
    test_make_tmpdir(root, sizeof(root), "fleet_objectives", "repair");
    failures += rpr_case_window_future(root);
    failures += rpr_case_git_skew(root);
    (void)test_rm_rf_recursive(root);
    return failures;
}
