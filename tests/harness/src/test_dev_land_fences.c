/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: fence scenarios, origin config, attestation, beats and launcher join.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


static int dlx_fence_case_lossy(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced lossy") {
            if (t->scenario == 7 || t->scenario == 8) {
                char wrapper[1400], marker[1400], script[3000], diagnostic[1400];
                dlx_landdir(t->land, sizeof(t->land));
                (void)snprintf(wrapper, sizeof(wrapper), "%s/reject-new", t->land);
                (void)snprintf(marker, sizeof(marker), "%s/new-attempts", t->land);
                (void)snprintf(script, sizeof(script),
                    "#!/bin/sh\nprintf 'sent\\n' >> '%s'\nprintf 'stderr-only-refusal\\033[31m\\n' >&2\nexit 91\n", marker);
                ASSERT(dlx_write(wrapper, script)); ASSERT(chmod(wrapper, 0700) == 0);
                const char *intercept[] = { "config", "--worktree", "remote.origin.receivepack", wrapper, NULL };
                ASSERT(dlx_git(t->rig.clone, intercept) == 0);
                if (t->scenario == 7) {
                    (void)snprintf(diagnostic, sizeof(diagnostic), "%s/logs/push-2-a1.diagnostic", t->land);
                    ASSERT(mkdir(diagnostic, 0700) == 0); /* Durable-storage refusal. */
                }
                for (unsigned beat = 0; beat < 4; ++beat) {
                    dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                    ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
                }
                size_t count = 0; char sends[128], transcript[4096];
                ASSERT(dlx_slurp(marker, sends, sizeof(sends), &count));
                ASSERT(count == strlen("sent\n") * (t->scenario == 7 ? 1 : 3));
                ASSERT(dlx_origin_main(&t->rig, t->remote)); ASSERT_STR_EQ(t->remote, t->base);
                if (t->scenario == 8) {
                    (void)snprintf(diagnostic, sizeof(diagnostic), "%s/logs/push-2-a1.diagnostic", t->land);
                    ASSERT(dlx_slurp(diagnostic, transcript, sizeof(transcript) - 1, &count));
                    transcript[count] = '\0';
                    ASSERT(strstr(transcript, "stderr-only-refusal?") != NULL);
                    ASSERT(strstr(transcript, "exit_observed=1") != NULL);
                    ASSERT(strstr(transcript, "END publication diagnostic") != NULL);
                }
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_both_heads(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced both_heads") {
            if (t->scenario == 9) {
                char tree[64], combined[64], ref[160];
                const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
                ASSERT(dlx_git_out(t->rig.clone, lookup, tree, sizeof(tree)) == 0);
                const char *merge[] = { "commit-tree", "-S", tree, "-p", t->rig.tip,
                                        "-p", t->successor, "-m", "contains both", NULL };
                ASSERT(dlx_git_out(t->rig.clone, merge, combined, sizeof(combined)) == 0);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", combined);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
                dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OBSERVATION_INCONSISTENT"); dlx_end(&t->c);
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_dispatch(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced dispatch") {
            if (t->scenario == 1) {
                char ref[160];
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", t->rig.tip);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
            } else if (t->scenario == 3) {
                ASSERT(dlx_fence_crash_step("before_dispatch"));
                dlx_begin(&t->c, "step");
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
                ASSERT(dlx_origin_main(&t->rig, t->remote)); ASSERT_STR_EQ(t->remote, t->base);
                /* A checkpointed send cannot be changed to another identity. */
                dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->base);
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_IDENTITY_FROZEN"); dlx_end(&t->c);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY");
                unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore(); t->stop = true; return failures;
            } else if (t->scenario == 4) {
                ASSERT(dlx_fence_crash_step("after_dispatch"));
            } else {
                dlx_begin(&t->c, "step");
                ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(&t->c);
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_rewind(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced rewind") {
            ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
            ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
            if (t->scenario == 5) ASSERT(dlx_fence_crash_step("paired"));
            if (t->scenario == 6) {
                ASSERT(dlx_fence_crash_step("old_projection"));
                dlx_begin(&t->c, "status");
                ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
                const struct json_value *outcomes = dlx_arr(&t->c, "outcomes");
                ASSERT(outcomes && outcomes->num_children == 1);
                t->old_recorded_at = dlx_fence_old_recorded();
                ASSERT(t->old_recorded_at > 0);
                dlx_end(&t->c);
            }
            if (t->scenario == 10) {
                ASSERT(dlx_fence_crash_step("paired"));
                /* External administrative policy violation t->after observation:
                 * force a rewind through fixture update-ref, not receive-pack. */
                const char *rewind[] = { "update-ref", "refs/heads/main", t->base, t->successor, NULL };
                ASSERT(dlx_git(t->rig.bare, rewind) == 0);
                dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
                ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OBSERVATION_INCONSISTENT"); dlx_end(&t->c);
                ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
                ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
                unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
                dlx_restore(); t->stop = true; return failures;
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_settlement(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced settlement") {
            dlx_begin(&t->c, "step");
            ASSERT(dlx_run(&t->c));
            if (!dlx_ok(&t->c)) printf("fence scenario=%u error=%s ", t->scenario, dlx_err_code(&t->c));
            ASSERT(dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), t->scenario == 1 ? "fenced" : "landed");
            dlx_end(&t->c);
            dlx_begin(&t->c, "status");
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            const struct json_value *outcomes = dlx_arr(&t->c, "outcomes");
            ASSERT(outcomes && outcomes->num_children == 2);
            const struct json_value *old = &outcomes->children[0];
            const struct json_value *next = &outcomes->children[1];
            if (t->scenario == 6)
                ASSERT(dlx_fence_old_recorded() == t->old_recorded_at);
            ASSERT_STR_EQ(json_get_str(json_get(old, "state")), t->scenario == 1 ? "landed" : "fenced");
            ASSERT_STR_EQ(json_get_str(json_get(old, "historical_git_acceptance")),
                           t->scenario == 1 ? "verified" : "unknown");
            ASSERT_STR_EQ(json_get_str(json_get(old, "future_dispatch")),
                           t->scenario == 1 ? "complete" : "fenced");
            ASSERT_STR_EQ(json_get_str(json_get(next, "state")), t->scenario == 1 ? "fenced" : "landed");
            ASSERT(json_get_int(json_get(old, "fence_peer")) == 2);
            ASSERT(json_get_int(json_get(next, "fence_peer")) == 1);
            const struct json_value *winner = t->scenario == 1 ? old : next;
            ASSERT(strlen(json_get_str(json_get(winner, "remote_signature"))) == 128);
            ASSERT_STR_EQ(json_get_str(json_get(old, "tip")), t->rig.tip);
            ASSERT(json_get_int(json_get(old, "attempt")) == 1);
            dlx_end(&t->c);
            ASSERT(dlx_origin_main(&t->rig, t->remote));
            ASSERT_STR_EQ(t->remote, t->scenario == 1 ? t->rig.tip : t->successor);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_delayed(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced delayed") {
            /* A delayed competing exact-base CAS cannot undo the winner. */
            char lease[128], competing[128];
            (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", t->base);
            (void)snprintf(competing, sizeof(competing), "%s:refs/heads/main",
                           t->scenario == 1 ? t->successor : t->rig.tip);
            const char *delayed[] = { "push", lease, "origin", competing, NULL };
            const char *restore[] = { "config", "--worktree", "--unset", "remote.origin.receivepack", NULL };
            (void)dlx_git(t->wt, restore);
            ASSERT(dlx_git(t->scenario == 1 ? t->rig.clone : t->wt, delayed) != 0);
            ASSERT(dlx_origin_main(&t->rig, t->remote));
            ASSERT_STR_EQ(t->remote, t->scenario == 1 ? t->rig.tip : t->successor);
            dlx_begin(&t->c, "step"); ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), "empty"); dlx_end(&t->c);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_case_run(unsigned scenario)
{
    int failures = 0;
    struct dlx_fence_case t = {0};
    t.scenario = scenario;
    (void)snprintf(t.tag, sizeof(t.tag), "fence_%u", scenario);
    dlx_isolate(t.tag);
    TEST("land: compound same-tree fenced case") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        ASSERT(dlx_fence_case_admission(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_lossy(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_both_heads(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_dispatch(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_rewind(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_settlement(&t) == 0);
        if (t.stop) goto _test_next;
        ASSERT(dlx_fence_case_delayed(&t) == 0);
        if (t.stop) goto _test_next;
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_LAND_TEST_FENCE_CRASH");
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

int dlx_fence_cases(void)
{
    int failures = 0;
    for (unsigned scenario = 0; scenario < 11; ++scenario)
        failures += dlx_fence_case_run(scenario);
    return failures;
}

static void dlx_fence_race_child(unsigned old_wins, int ready[2], int release[2],
                                  struct dlx_rig *rig, const char *base, const char *wt)
{
    struct dlx_call call; char lease[128], ref[128];
                (void)close(ready[0]); (void)close(release[1]);
                if (old_wins) {
                    dlx_begin(&call, "step");
                    bool ok = dlx_run(&call) && !dlx_ok(&call) &&
                        strcmp(dlx_err_code(&call), "FENCE_PUSH_OUTCOME_UNKNOWN") == 0;
                    dlx_end(&call); _exit(ok ? 0 : 89);
                }
                char byte;
                if (write(ready[1], "R", 1) != 1 || read(release[0], &byte, 1) != 1 || byte != 'G')
                    _exit(90);
                (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", base);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", rig->tip);
                const char *push[] = { "push", lease, "origin", ref, NULL };
                _exit(dlx_git(wt, push) != 0 ? 0 : 91);
}

static int dlx_fence_race_parent(unsigned old_wins, struct dlx_rig *rig,
                                  struct dlx_call *call, const char *base, const char *wt, const char *tip)
{
    int failures = 0; char lease[128], ref[128];
    TEST("land: fenced race parent") {
            if (old_wins) {
                dlx_fence_call(call, rig, base, rig->tip, tip);
                ASSERT(dlx_run(call) && !dlx_ok(call));
                ASSERT_STR_EQ(dlx_err_code(call), "STEP_BUSY"); dlx_end(call);
                (void)snprintf(lease, sizeof(lease), "--force-with-lease=refs/heads/main:%s", base);
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", rig->tip);
                const char *push[] = { "push", lease, "origin", ref, NULL };
                ASSERT(dlx_git(wt, push) == 0);
            } else {
                dlx_begin(call, "step"); ASSERT(dlx_run(call) && !dlx_ok(call));
                ASSERT_STR_EQ(dlx_err_code(call), "FENCE_PUSH_OUTCOME_UNKNOWN"); dlx_end(call);
            }
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_fence_concurrent_case(unsigned old_wins)
{
    int failures = 0;
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    TEST("land: competing delayed exact-base CAS and concurrent replacement respect the single compound owner") {
            struct dlx_rig rig; struct dlx_call call;
            char base[64], wt[1400], tip[64], remote[64];
            dlx_isolate(old_wins ? "fence_old_race" : "fence_new_race");
            ASSERT(dlx_fence_prepare(&rig, old_wins ? "fence_old_race" : "fence_new_race", base, wt, tip));
            dlx_fence_call(&call, &rig, base, rig.tip, tip);
            ASSERT(dlx_run(&call) && dlx_ok(&call)); dlx_end(&call);
            ASSERT(dlx_pick_barrier_open(ready, release));
            if (old_wins) zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
            child = fork(); ASSERT(child >= 0);
            if (child == 0) dlx_fence_race_child(old_wins, ready, release, &rig, base, wt);
            (void)close(ready[1]); ready[1] = -1;
            (void)close(release[0]); release[0] = -1;
            char byte; ASSERT(read(ready[0], &byte, 1) == 1 && byte == 'R');
            zcl_native_dev_land_test_pick_barrier(-1, -1);
            ASSERT(dlx_fence_race_parent(old_wins, &rig, &call, base, wt, tip) == 0);
            ASSERT(write(release[1], "G", 1) == 1);
            (void)close(release[1]); release[1] = -1;
            int status = 0;
            ASSERT(waitpid(child, &status, 0) == child);
            child = -1; ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            (void)close(ready[0]); ready[0] = -1;
            dlx_begin(&call, "step"); ASSERT(dlx_run(&call) && dlx_ok(&call));
            ASSERT_STR_EQ(dlx_str(&call, "state"), old_wins ? "fenced" : "landed"); dlx_end(&call);
            ASSERT(dlx_origin_main(&rig, remote)); ASSERT_STR_EQ(remote, old_wins ? rig.tip : tip);
            unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
        PASS();
    } _test_next:;
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; ++i) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) { int status = 0; (void)waitpid(child, &status, 0); }
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}
static bool dlx_fence_expect(struct dlx_fence_case *t, const char *action, const char *code)
{
    if (strcmp(action, "fence_replace") == 0)
        dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
    else dlx_begin(&t->c, action);
    bool ok = dlx_run(&t->c) && !dlx_ok(&t->c) && strcmp(dlx_err_code(&t->c), code) == 0;
    if (!ok) printf("fence negative expected=%s actual=%s ", code, dlx_err_code(&t->c));
    dlx_end(&t->c);
    return ok;
}

bool dlx_fence_same_queue(struct dlx_fence_case *t)
{
    return dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len) &&
        t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0;
}

static bool dlx_fence_bad_hook(struct dlx_fence_case *t)
{
    char hooks[1400];
    if (!dlx_hooks_dir(hooks, sizeof(hooks), "fence_unrelated_noop", 0)) return false;
    const char *set[] = { "config", "--worktree", "core.hooksPath", hooks, NULL };
    return dlx_git(t->rig.clone, set) == 0 &&
        dlx_fence_expect(t, "fence_replace", "FENCE_WORKTREE_INVALID");
}

/* All configuration changes are confined to fresh isolated throwaway rigs. */
static bool dlx_fence_receiver_config(struct dlx_fence_case *t, unsigned kind)
{
    char other[1400], key[1600];
    (void)snprintf(other, sizeof(other), "%s.other", t->rig.bare);
    const char *init[] = { "init", "--bare", "--quiet", other, NULL };
    if (dlx_git(NULL, init) != 0) return false;
    if (kind == 1) {
        const char *add[] = { "config", "--worktree", "--add", "remote.origin.url", other, NULL };
        return dlx_git(t->rig.clone, add) == 0;
    }
    if (kind == 2) {
        const char *first[] = { "config", "--worktree", "--add", "remote.origin.pushurl", t->rig.bare, NULL };
        const char *second[] = { "config", "--worktree", "--add", "remote.origin.pushurl", other, NULL };
        return dlx_git(t->rig.clone, first) == 0 && dlx_git(t->rig.clone, second) == 0;
    }
    if (kind == 3) {
        const char *single[] = { "config", "--worktree", "remote.origin.pushurl", other, NULL };
        return dlx_git(t->rig.clone, single) == 0;
    }
    if (kind == 6) {
        const char *first[] = { "config", "--worktree", "--add", "remote.origin.pushurl", t->rig.bare, NULL };
        const char *empty[] = { "config", "--worktree", "--add", "remote.origin.pushurl", "", NULL };
        return dlx_git(t->rig.clone, first) == 0 && dlx_git(t->rig.clone, empty) == 0;
    }
    if (kind == 5) {
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", other);
        const char *rewrite[] = { "config", "--worktree", key, t->rig.bare, NULL };
        return dlx_git(t->rig.clone, rewrite) == 0;
    }
    (void)snprintf(key, sizeof(key), "url.%s.pushInsteadOf", other);
    const char *rewrite[] = { "config", "--worktree", key, t->rig.bare, NULL };
    return dlx_git(t->rig.clone, rewrite) == 0;
}

static int dlx_fence_negative_receiver(unsigned kind, bool after_arm)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_receiver_%u_%u", kind, after_arm);
    dlx_isolate(t.tag);
    TEST("land: complete effective receiver set refuses before arming or dispatch") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        if (after_arm) {
            dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
            ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        }
        ASSERT(dlx_fence_receiver_config(&t, kind));
        ASSERT(dlx_fence_expect(&t, after_arm ? "step" : "fence_replace",
                               after_arm ? "FENCE_IDENTITY_INVALID" : "FENCE_NEW_PAIR_UNQUALIFIED"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        char other[1400]; (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *head[] = { "rev-parse", "--verify", "refs/heads/main", NULL };
        ASSERT(dlx_git(other, head) != 0);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static bool dlx_fence_stale_hook(struct dlx_fence_case *t)
{
    if (!dlx_write_dep(t->rig.clone, "build/bin/z23-git-hook", "current canonical fixture binary\n")) return false;
    char installed[1400];
    (void)snprintf(installed, sizeof(installed), "%s/z23-git-hook", g_dlx_hooks_ok);
    return dlx_write(installed, "stale installed fixture binary\n") &&
        dlx_fence_expect(t, "fence_replace", "FENCE_WORKTREE_INVALID");
}

static bool dlx_fence_signed_merge(struct dlx_fence_case *t)
{
    char tree[64], merge[64];
    const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
    if (dlx_git_out(t->rig.clone, lookup, tree, sizeof(tree)) != 0) return false;
    const char *make[] = { "commit-tree", "-S", tree, "-p", t->rig.tip, "-p", t->successor,
                           "-m", "signed merge rejected", NULL };
    if (dlx_git_out(t->rig.clone, make, merge, sizeof(merge)) != 0) return false;
    (void)snprintf(t->successor, sizeof(t->successor), "%s", merge);
    const char *checkout[] = { "checkout", "--quiet", "-B", "merge-proposal", merge, NULL };
    return dlx_git(t->rig.clone, checkout) == 0 &&
        dlx_fence_expect(t, "fence_replace", "FENCE_NEW_PAIR_UNQUALIFIED");
}

static int dlx_fence_negative_admission(unsigned kind)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_admission_%u", kind);
    dlx_isolate(t.tag);
    TEST("land: stale unrelated executable hook and signed merge are inadmissible") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        ASSERT(kind == 0 ? dlx_fence_bad_hook(&t) :
               kind == 1 ? dlx_fence_signed_merge(&t) : dlx_fence_stale_hook(&t));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static bool dlx_fence_conflicting_outcome(struct dlx_fence_case *t)
{
    char path[1400], content[65536]; size_t len = 0;
    dlx_landdir(t->land, sizeof(t->land));
    (void)snprintf(path, sizeof(path), "%s/fence.jsonl", t->land);
    if (!dlx_slurp(path, content, sizeof(content) - 1, &len)) return false;
    content[len] = '\0';
    char *row = strchr(content, '\n'); if (!row) return false;
    row = strchr(row + 1, '\n'); if (!row) return false; ++row;
    char *end = strchr(row, '\n'); if (!end) return false; *end = '\0';
    char *peer = strstr(row, "\"fence_peer\":2"); if (!peer) return false;
    peer[strlen("\"fence_peer\":")] = '9';
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", t->land);
    return dlx_write(path, row);
}

static int dlx_fence_negative_replay(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    dlx_isolate("fence_conflicting_outcome");
    TEST("land: contradictory prior terminal peer never replaces sealed paired outcome") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_conflicting_outcome", t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PUSH_OUTCOME_UNKNOWN"));
        ASSERT(dlx_fence_crash_step("paired"));
        ASSERT(dlx_fence_conflicting_outcome(&t));
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PROJECT_PENDING"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PROJECT_PENDING"));
        ASSERT(dlx_fence_same_queue(&t));
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_observer_rewrite(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    char config[1400], key[1600], other[1400];
    const char *prior = getenv("GIT_CONFIG_GLOBAL");
    char *saved = prior ? strdup(prior) : NULL;
    dlx_isolate("fence_observer_rewrite");
    TEST("land: observer-only rewrite cannot substitute the signed receiver") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_observer_rewrite", t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_PUSH_OUTCOME_UNKNOWN"));
        dlx_landdir(t.land, sizeof(t.land));
        (void)snprintf(config, sizeof(config), "%s/observer.gitconfig", t.land);
        (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *init[] = { "init", "--bare", "--quiet", other, NULL };
        ASSERT(dlx_git(NULL, init) == 0);
        /* Global shorter-prefix rewrite applies only to the fresh observer;
         * the source checkout's longer identity mapping preserves its URL. */
        char prefix[1400]; (void)snprintf(prefix, sizeof(prefix), "%s", t.rig.bare);
        char *slash = strrchr(prefix, '/'); ASSERT(slash != NULL); slash[1] = '\0';
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", other);
        const char *global[] = { "config", "--file", config, key, prefix, NULL };
        ASSERT(dlx_git(NULL, global) == 0);
        (void)snprintf(key, sizeof(key), "url.%s.insteadOf", t.rig.bare);
        const char *local[] = { "config", key, t.rig.bare, NULL };
        ASSERT(dlx_git(t.rig.clone, local) == 0);
        setenv("GIT_CONFIG_GLOBAL", config, 1);
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_WINNER_RECEIPT_UNAVAILABLE"));
        ASSERT(dlx_fence_same_queue(&t));
        PASS();
    } _test_next:;
    if (saved) setenv("GIT_CONFIG_GLOBAL", saved, 1); else unsetenv("GIT_CONFIG_GLOBAL");
    free(saved);
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_dispatch_receiver_race(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    int ready[2] = {-1, -1}, release[2] = {-1, -1}; pid_t child = -1;
    dlx_isolate("fence_dispatch_receiver_race");
    TEST("land: receiver changes after checkpoint still refuse before actual send") {
        ASSERT(dlx_fence_prepare(&t.rig, "fence_dispatch_receiver_race", t.base, t.wt, t.successor));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        ASSERT(dlx_pick_barrier_open(ready, release));
        zcl_native_dev_land_test_pick_barrier(ready[1], release[0]);
        child = fork(); ASSERT(child >= 0);
        if (child == 0) dlx_fence_race_child(1, ready, release, &t.rig, t.base, t.wt);
        (void)close(ready[1]); ready[1] = -1;
        (void)close(release[0]); release[0] = -1;
        char marker; ASSERT(read(ready[0], &marker, 1) == 1 && marker == 'R');
        zcl_native_dev_land_test_pick_barrier(-1, -1);
        ASSERT(dlx_fence_receiver_config(&t, 2));
        ASSERT(write(release[1], "G", 1) == 1);
        (void)close(release[1]); release[1] = -1;
        int status = 0; ASSERT(waitpid(child, &status, 0) == child); child = -1;
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        char other[1400]; (void)snprintf(other, sizeof(other), "%s.other", t.rig.bare);
        const char *head[] = { "rev-parse", "--verify", "refs/heads/main", NULL };
        ASSERT(dlx_git(other, head) != 0);
        PASS();
    } _test_next:;
    zcl_native_dev_land_test_pick_barrier(-1, -1);
    for (size_t i = 0; i < 2; ++i) {
        if (ready[i] >= 0) (void)close(ready[i]);
        if (release[i] >= 0) (void)close(release[i]);
    }
    if (child > 0) { int status = 0; (void)waitpid(child, &status, 0); }
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_checkout_drift(bool dirty)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_checkout_drift_%u", dirty);
    dlx_isolate(t.tag);
    TEST("land: armed replacement checkout drift refuses new send") {
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_queue_bytes(t.before, sizeof(t.before), &t.before_len));
        dlx_fence_call(&t.c, &t.rig, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c) && dlx_ok(&t.c)); dlx_end(&t.c);
        if (dirty) {
            const char *modify[] = { "config", "--worktree", "core.filemode", "true", NULL };
            ASSERT(dlx_git(t.rig.clone, modify) == 0);
            const char *remove[] = { "rm", "-r", "--cached", ".", NULL };
            ASSERT(dlx_git(t.rig.clone, remove) == 0);
        } else {
            const char *switch_head[] = { "checkout", "--detach", t.base, NULL };
            ASSERT(dlx_git(t.rig.clone, switch_head) == 0);
        }
        ASSERT(dlx_fence_expect(&t, "step", "FENCE_WORKTREE_INVALID"));
        ASSERT(dlx_fence_same_queue(&t));
        ASSERT(dlx_origin_main(&t.rig, t.remote)); ASSERT_STR_EQ(t.remote, t.base);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

/* The replacement is a separate repository (as live): a no-local clone of
 * the fenced successor branch, so the old head object exists only in the
 * landing worktree's store. Signing identity is copied from the landing repo. */
static bool dlx_fence_clone_to(const struct dlx_rig *rig, const char *path)
{
    static const char *keys[] = { "gpg.format", "user.signingkey", "commit.gpgsign",
                                  "gpg.ssh.allowedSignersFile", "user.name", "user.email" };
    const char *clone[] = { "clone", "--quiet", "--no-local", "--single-branch",
                            "--branch", "fence-successor", rig->clone, path, NULL };
    const char *origin[] = { "remote", "set-url", "origin", rig->bare, NULL };
    const char *hooks[] = { "config", "--worktree", "core.hooksPath", g_dlx_hooks_ok, NULL };
    if (dlx_git(NULL, clone) != 0 || dlx_git(path, origin) != 0) return false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        char value[1400];
        const char *get[] = { "config", "--get", keys[i], NULL };
        if (dlx_git_out(rig->clone, get, value, sizeof(value)) != 0) return false;
        const char *set[] = { "config", keys[i], value, NULL };
        if (dlx_git(path, set) != 0) return false;
    }
    return dlx_git(path, hooks) == 0;
}

/* Sibling of the (land-resident) replacement checkout, so inside the land. */
static bool dlx_fence_foreign_checkout(const struct dlx_rig *rig, char path[600])
{
    (void)snprintf(path, 600, "%s.foreign", rig->clone);
    return dlx_fence_clone_to(rig, path);
}

/* The pre-push hook admits main pushes only from checkouts inside the land
 * directory, so a replacement checkout elsewhere is refused up front. It is
 * otherwise a valid, prepared checkout at the exact tip: only the location
 * rule can refuse it. */
static int dlx_fence_outside_land(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_outside_land");
    dlx_isolate(t.tag);
    TEST("land: a replacement checkout outside the land directory is refused") {
        char outside[600];
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        (void)snprintf(outside, sizeof(outside), "%s.outside", t.rig.bare);
        ASSERT(dlx_fence_clone_to(&t.rig, outside));
        struct dlx_rig other = t.rig;
        (void)snprintf(other.clone, sizeof(other.clone), "%s", outside);
        dlx_fence_call(&t.c, &other, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c));
        ASSERT(!dlx_ok(&t.c));
        ASSERT_STR_EQ(dlx_err_code(&t.c), "FENCE_WORKTREE_INVALID");
        dlx_end(&t.c);
        /* The same checkout inside the land directory is admitted. */
        char inside[600];
        ASSERT(dlx_fence_foreign_checkout(&t.rig, inside));
        (void)snprintf(other.clone, sizeof(other.clone), "%s", inside);
        dlx_fence_call(&t.c, &other, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c));
        ASSERT(dlx_ok(&t.c) || strcmp(dlx_err_code(&t.c), "FENCE_WORKTREE_INVALID") != 0);
        dlx_end(&t.c);
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

static int dlx_fence_missing_old_head(void)
{
    int failures = 0; struct dlx_fence_case t = {0};
    (void)snprintf(t.tag, sizeof(t.tag), "fence_old_head_missing");
    dlx_isolate(t.tag);
    TEST("land: a replacement checkout lacking the old head is never armed unless it can drive") {
        char foreign[600];
        ASSERT(dlx_fence_prepare(&t.rig, t.tag, t.base, t.wt, t.successor));
        ASSERT(dlx_fence_foreign_checkout(&t.rig, foreign));
        const char *have[] = { "cat-file", "-e", NULL, NULL };
        char spec[96]; (void)snprintf(spec, sizeof(spec), "%s^{commit}", t.rig.tip);
        have[2] = spec;
        ASSERT(dlx_git(foreign, have) != 0); /* the old head is absent there */
        ASSERT(dlx_git(t.rig.clone, have) == 0);
        struct dlx_rig other = t.rig;
        (void)snprintf(other.clone, sizeof(other.clone), "%s", foreign);
        dlx_fence_call(&t.c, &other, t.base, t.rig.tip, t.successor);
        ASSERT(dlx_run(&t.c));
        if (dlx_ok(&t.c)) {
            /* Armed: it must drive, not answer an ancestry error forever. */
            dlx_end(&t.c);
            ASSERT(dlx_git(foreign, have) == 0);
            dlx_begin(&t.c, "step");
            ASSERT(dlx_run(&t.c));
            ASSERT(dlx_ok(&t.c) || strcmp(dlx_err_code(&t.c), "FENCE_OBSERVATION_INCONSISTENT") != 0);
            dlx_end(&t.c);
        } else {
            ASSERT_STR_EQ(dlx_err_code(&t.c), "FENCE_OLD_HEAD_UNREACHABLE");
            dlx_end(&t.c);
        }
        PASS();
    } _test_next:;
    unsetenv("ZCL_LAND_TEST_FENCE_POLICY"); unsetenv("ZCL_DEVLOOP_TEST_PROCESS"); dlx_restore();
    return failures;
}

int dlx_fence_negative_cases(void)
{
    int failures = dlx_fence_negative_admission(0) + dlx_fence_negative_admission(1) + dlx_fence_negative_admission(2) +
        dlx_fence_negative_replay() + dlx_fence_observer_rewrite() + dlx_fence_dispatch_receiver_race() +
        dlx_fence_checkout_drift(false) + dlx_fence_checkout_drift(true) +
        dlx_fence_missing_old_head() + dlx_fence_outside_land();
    for (unsigned kind = 1; kind <= 6; ++kind) {
        failures += dlx_fence_negative_receiver(kind, false);
        failures += dlx_fence_negative_receiver(kind, true);
    }
    return failures;
}

int dlx_fence_concurrent(void)
{
    return dlx_fence_concurrent_case(0) + dlx_fence_concurrent_case(1);
}
#endif

int dlx_origin_config_cases(void)
{
    int failures = 0;
    static const struct { const char *wire; size_t length; bool valid; } cases[] = {
#define DLX_CONFIG_CASE(s, ok) {s, sizeof(s) - 1, ok}
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0", true),
        DLX_CONFIG_CASE("remote.origin.pushurl\nfixture\0remote.origin.url\nfixture\0", true),
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0remote.origin.pushurl\nfixture\0", true),
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0remote.origin.pushurl\n\0", false),
        DLX_CONFIG_CASE("remote.origin.pushurl\n\0remote.origin.url\nfixture\0", false),
        DLX_CONFIG_CASE("remote.origin.url\n\0", false),
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0remote.origin.url\nfixture\0", false),
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0remote.origin.pushurl\na\0remote.origin.pushurl\nb\0", false),
        DLX_CONFIG_CASE("remote.origin.pushurl\nfixture\0", false),
        DLX_CONFIG_CASE("remote.origin.url\nfixture", false),
        DLX_CONFIG_CASE("remote.origin.url fixture\0", false),
        DLX_CONFIG_CASE("remote.origin.url\nfi\nxture\0", false),
        DLX_CONFIG_CASE("remote.origin.urls\nfixture\0", false),
        DLX_CONFIG_CASE("remote.origin.url\nfixture\0\0", false),
        DLX_CONFIG_CASE("", false),
#undef DLX_CONFIG_CASE
    };
    TEST("land receiver: raw configured URL framing preserves empty and duplicate entries") {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            ASSERT_EQ(zcl_native_dev_land_test_origin_config(cases[i].wire, cases[i].length), cases[i].valid);
        ASSERT(!zcl_native_dev_land_test_origin_config(NULL, 1));
        PASS();
    }
_test_next:;
    return failures;
}

int dlx_attest_only_cases(void)
{
    int failures = 0;
    char land[2048], path[2304], wire[ZCL_LAND_ATTEST_CAP], before[2048], after[2048];
    size_t before_len = 0, after_len = 0;
    struct dlx_call c;
    const char *row = "{\"seq\":410,\"tip\":\"db648476e77c14308d77501ad85655e2444043b3\",\"state\":\"inflight\",\"attempt\":2,\"phase\":\"prove\",\"base\":\"3a93e60ebf922af3d119b9facc1d95803f42844b\",\"local\":\"db648476e77c14308d77501ad85655e2444043b3\",\"tree\":\"4514cfd63acc408be3d37023656a8e88bc1be2c6\"}\n";
    TEST("land attest-only: self capture honors image identity in four BOOL cases without mutation") {
        dlx_isolate("attest-only");
        dlx_landdir(land, sizeof(land));
        ASSERT(dlx_mkdir_p(land));
        ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
        ASSERT(dlx_write(path, row));
        ASSERT(dlx_slurp(path, before, sizeof(before), &before_len));
        before[before_len] = 0;
        for (int i = 0; i < 4; ++i) {
            ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", (i & 1) ? "1" : "not-one", 1) == 0);
            ASSERT(setenv("ZCL_LAND_PROOF_STUB", (i & 2) ? "PRIVATE-FIXTURE-VALUE-NOT-OUTPUT" : "", 1) == 0);
            dlx_begin(&c, "attest_only");
            ASSERT(dlx_run(&c));
            if (os_proc_self_exe_identity() == OS_PROC_IMAGE_IDENTITY_RUNNING_IMAGE) {
                ASSERT(dlx_ok(&c));
                ASSERT_STR_EQ(dlx_str(&c, "service_origin"), "UNKNOWN");
                ASSERT_EQ(json_get(&c.reply.data, "allow_unsigned_is_one")->val.b, !!(i & 1));
                ASSERT_EQ(json_get(&c.reply.data, "proof_stub_nonempty")->val.b, !!(i & 2));
                size_t n = json_write(&c.reply.data, wire, sizeof(wire));
                ASSERT(n > 0 && n < sizeof(wire));
                ASSERT(strstr(wire, "PRIVATE-FIXTURE") == NULL);
                bool enabled = true;
                const char *image = dlx_str(&c, "executable_sha256");
                const char *source = dlx_str(&c, "compiled_source_sha256");
                int64_t clock = dlx_int(&c, "observed_at_ms");
                ASSERT(zcl_dev_land_attestation_decode(wire, n, image, source, clock, &enabled));
                ASSERT_EQ(enabled, i == 3);
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, clock + 5001, &enabled));
                ASSERT(!enabled);
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, 0, &enabled));
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, source, "bad-source", clock, &enabled));
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, source, image, clock, &enabled));
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, NULL, source, clock, &enabled));
                ASSERT(!zcl_dev_land_attestation_decode(wire, n - 1, image, source, clock, &enabled));
                ASSERT(json_push_kv_str(&c.reply.data, "service_origin", "timer"));
                n = json_write(&c.reply.data, wire, sizeof(wire));
                ASSERT(!zcl_dev_land_attestation_decode(wire, n, image, source, clock, &enabled));
            } else {
                ASSERT(!dlx_ok(&c));
                ASSERT_STR_EQ(dlx_err_code(&c), "ATTESTATION_UNKNOWN");
            }
            dlx_end(&c);
            ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
            ASSERT_EQ(before_len, after_len);
            ASSERT(memcmp(before, after, before_len) == 0);
        }
        const char *absent[] = {"step.lock", "queue.lock", "outcomes.jsonl", "logs", "wt"};
        for (size_t i = 0; i < sizeof(absent)/sizeof(absent[0]); ++i) {
            ASSERT(snprintf(path, sizeof(path), "%s/%s", land, absent[i]) < (int)sizeof(path));
            ASSERT(access(path, F_OK) != 0);
        }
        const char *markers[] = {"\"seq\":41", "\"base\":\"", "\"tree\":\"", "\"local\":\""};
        for (size_t i = 0; i < sizeof(markers)/sizeof(markers[0]); ++i) {
            char changed[2048];
            memcpy(changed, before, before_len + 1);
            char *at = strstr(changed, markers[i]);
            ASSERT(at != NULL);
            at += strlen(markers[i]);
            *at = *at == '1' ? '2' : '1';
            ASSERT(snprintf(path, sizeof(path), "%s/queue.jsonl", land) < (int)sizeof(path));
            ASSERT(dlx_write(path, changed));
            dlx_begin(&c, "attest_only");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(dlx_err_code(&c), "ATTESTATION_UNKNOWN");
            dlx_end(&c);
            ASSERT(dlx_slurp(path, after, sizeof(after), &after_len));
            ASSERT_EQ(before_len, after_len);
            ASSERT(memcmp(changed, after, after_len) == 0);
        }
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_attest_bounded_wire_cases(void)
{
    int failures = 0;
    TEST("land attestation: malformed Unicode exact spans refuse before JSON") {
        const char *vectors[] = {"{\"x\":\"\\", "{\"x\":\"\\u", "{\"x\":\"\\u0",
            "{\"x\":\"\\u00", "{\"x\":\"\\u000", "{\"x\":\"\\uZZZZ\"}",
            "{\"x\":\"\\uD800\"}", "{\"x\":\"\\uDC00\"}",
            "{\"x\":\"\\uD800\\u", "{\"x\":\"\\u0000\"}"};
        char digest[65];
        memset(digest, 'a', 64);
        digest[64] = 0;
        for (size_t i = 0; i < sizeof(vectors)/sizeof(vectors[0]); ++i) {
            size_t n = strlen(vectors[i]);
            char *span = malloc(n);
            ASSERT(span != NULL);
            memcpy(span, vectors[i], n);
            bool enabled = true;
            bool accepted = zcl_dev_land_attestation_decode(span, n, digest, digest, 1, &enabled);
            bool unchanged = memcmp(span, vectors[i], n) == 0;
            free(span);
            ASSERT(!accepted && !enabled && unchanged);
            unsigned char guarded[128];
            memset(guarded, 0xa5, sizeof(guarded));
            memcpy(guarded + 1, vectors[i], n);
            enabled = true;
            ASSERT(!zcl_dev_land_attestation_decode((char *)guarded + 1, n,
                digest, digest, 1, &enabled));
            ASSERT(!enabled && guarded[0] == 0xa5 && guarded[n + 1] == 0xa5);
        }
        PASS();
    }
_test_next:;
    return failures;
}

static int dlx_beat_case(const char *beat, int64_t start, int64_t end,
                          const char *duration)
{
    int failures = 0;
    TEST("land beat timing: injected intervals retain exact identity") {
        char wire[768];
        struct zcl_land_beat b = { beat, "base", "candidate", "tree", 41, 2, start, end };
        ASSERT(zcl_dev_land_beat_format(&b, wire, sizeof(wire)));
        ASSERT(strstr(wire, "zcl.dev_land.beat.v1 seq=41 attempt=2") != NULL);
        ASSERT(strstr(wire, "base=base local=candidate tree=tree") != NULL);
        ASSERT(strstr(wire, beat) != NULL);
        ASSERT(strstr(wire, duration) != NULL);
        ASSERT(!zcl_dev_land_beat_format(&b, wire, 1));
        ASSERT_STR_EQ(wire, "");
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_beat_duration(const char *duration, size_t width)
{
    if (width == 7 && memcmp(duration, "unknown", 7) == 0) return true;
    if (width == 0 || width > 19) return false;
    for (size_t i = 0; i < width; i++)
        if (duration[i] < '0' || duration[i] > '9') return false;
    return true;
}

static bool dlx_beat_log_bytes(char *log, size_t len, const char *expected)
{
    const char *tag = "zcl.dev_land.beat.v1 ";
    size_t offset = 0, wanted = strlen(expected);
    bool found = false;
    if (memchr(log, 0, len)) return false;
    log[len] = '\0';
    while (offset < len) {
        char *record = log + offset;
        char *newline = memchr(record, '\n', len - offset);
        size_t width = newline ? (size_t)(newline - record) : len - offset;
        record[width] = '\0';
        bool is_beat = strncmp(record, tag, strlen(tag)) == 0;
        if (is_beat) {
            const char *duration = strstr(record, " elapsed_us=");
            if (!duration) return false;
            duration += strlen(" elapsed_us=");
            if (!dlx_beat_duration(duration, width - (size_t)(duration - record)))
                return false;
            if (width >= wanted && memcmp(record, expected, wanted) == 0)
                found = true;
        } else if (!newline) return false;
        offset += width;
        if (newline) offset++;
    }
    return found;
}

bool dlx_beat_log_record(const char *prefix, const char *beat)
{
    char landdir[1200], path[1400], log[32768], expected[768];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    int n = snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    if (!dlx_slurp(path, log, sizeof(log) - 1, &len)) return false;
    n = snprintf(expected, sizeof(expected), "%s beat=%s elapsed_us=", prefix, beat);
    if (n <= 0 || (size_t)n >= sizeof(expected)) return false;
    return dlx_beat_log_bytes(log, len, expected);
}

static int dlx_beat_reader_case(const char *label, const char *wire,
                                size_t len, bool accepted)
{
    int failures = 0;
    TEST("land beat reader: bounded complete records") {
        char log[1024];
        printf("checking beat reader=%s\n", label);
        ASSERT(len < sizeof(log));
        memcpy(log, wire, len);
        log[len] = '\0';
        ASSERT(dlx_beat_log_bytes(log, len,
            "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=") == accepted);
        PASS();
    } _test_next:;
    return failures;
}

static int dlx_beat_reader_cases(void)
{
    static const struct { const char *label, *wire; size_t len; bool accepted; } cases[] = {
#define DLX_BEAT_READER(label, wire, accepted) { label, wire, sizeof(wire) - 1, accepted }
        DLX_BEAT_READER("newline", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n", true),
        DLX_BEAT_READER("EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1", true),
        DLX_BEAT_READER("unknown EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=unknown", true),
        DLX_BEAT_READER("NUL suffix", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n\0garbage", false),
        DLX_BEAT_READER("torn suffix", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\ntorn", false),
        DLX_BEAT_READER("torn beat", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2", false),
        DLX_BEAT_READER("trailing garbage", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1garbage\n", false),
        DLX_BEAT_READER("empty duration", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=\n", false),
        DLX_BEAT_READER("long duration", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=12345678901234567890\n", false),
        DLX_BEAT_READER("unknown garbage", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=unknown!\n", false),
        DLX_BEAT_READER("complete unrelated records", "ordinary\nzcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nother\n", true),
        DLX_BEAT_READER("unrelated beat EOF", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2 beat=prepare elapsed_us=unknown", true),
        DLX_BEAT_READER("malformed unrelated beat", "zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\nzcl.dev_land.beat.v1 seq=2 beat=prepare elapsed_us=x\n", false),
        DLX_BEAT_READER("mid-record match", "other zcl.dev_land.beat.v1 seq=1 beat=push elapsed_us=1\n", false),
        DLX_BEAT_READER("empty log", "", false),
#undef DLX_BEAT_READER
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
        failures += dlx_beat_reader_case(cases[i].label, cases[i].wire,
                                         cases[i].len, cases[i].accepted);
    return failures;
}

static bool dlx_beat_row_prefix(char *out, size_t cap)
{
    struct dlx_call c;
    if (out && cap) out[0] = '\0';
    if (!out || !cap) return false;
    dlx_begin(&c, "status");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    const struct json_value *row = json_get(&c.reply.data, "in_flight");
    int n = 0;
    if (ok && row) {
        n = snprintf(out, cap,
            "zcl.dev_land.beat.v1 seq=1 attempt=1 base=%s local=%s tree=%s",
            dlx_jstr(row, "base"), dlx_jstr(row, "local"), dlx_jstr(row, "tree"));
        ok = strlen(dlx_jstr(row, "base")) == 40 &&
             strlen(dlx_jstr(row, "local")) == 40 &&
             strlen(dlx_jstr(row, "tree")) == 40;
    } else ok = false;
    dlx_end(&c);
    return ok && n > 0 && (size_t)n < cap;
}

static bool dlx_beat_fixture(struct dlx_rig *rig, char *prefix, size_t cap)
{
    struct dlx_call c;
    memset(rig, 0, sizeof(*rig));
    if (prefix && cap) prefix[0] = '\0';
    dlx_isolate("beat_log");
    if (!dlx_rig_make(rig, "beat_log_rig")) return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
         dlx_eq_str(dlx_str(&c, "state"), "started");
    dlx_end(&c);
    return ok && dlx_beat_row_prefix(prefix, cap);
}

static bool dlx_beat_publish(void)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              dlx_eq_str(dlx_str(&c, "state"), "attached");
    dlx_end(&c);
    if (!ok) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
         dlx_eq_str(dlx_str(&c, "state"), "landed");
    dlx_end(&c);
    return ok;
}

static int dlx_beat_production_case(const char *beat)
{
    int failures = 0;
    TEST("land beat logging: isolated production record retains row identity") {
        struct dlx_rig rig;
        char prefix[512];
        ASSERT(dlx_beat_fixture(&rig, prefix, sizeof(prefix)));
        if (strcmp(beat, "prepare") != 0) ASSERT(dlx_beat_publish());
        printf("checking production beat=%s\n", beat);
        ASSERT(dlx_beat_log_record(prefix, beat));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_beat_attach_case(void)
{
    int failures = 0;
    TEST("land beat logging: attach proof read records its exact row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], prefix[512], landdir[1200], path[1400];
        dlx_isolate("beat_attach");
        ASSERT(dlx_attach_proven_pair(&rig, "beat_attach", base));
        ASSERT(dlx_beat_row_prefix(prefix, sizeof(prefix)));
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir) < (int)sizeof(path));
        ASSERT(dlx_write(path, ""));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_FAILED");
        dlx_end(&c);
        ASSERT(dlx_beat_log_record(prefix, "proof_status"));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

static int dlx_beat_production_cases(void)
{
    return dlx_beat_attach_case() + dlx_beat_production_case("prepare") +
        dlx_beat_production_case("proof_status") +
        dlx_beat_production_case("push") +
        dlx_beat_production_case("fresh_observation");
}

static int dlx_beat_cases(void)
{
    return dlx_beat_case("push", 100, 900, "elapsed_us=800") +
        dlx_beat_case("fresh_observation", 100, 2100, "elapsed_us=2000") +
        dlx_beat_case("prepare", 0, 0, "elapsed_us=0") +
        dlx_beat_case("proof_status", 100, 99, "elapsed_us=unknown") +
        dlx_beat_case("push", -1, 100, "elapsed_us=unknown");
}

int dlx_attest_refusal_cases(void)
{
    int failures = 0;
    struct dlx_call c;
    TEST("land attest-only: unavailable root refuses without creating state") {
        dlx_isolate("attest-missing-root");
        dlx_begin(&c, "attest_only");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTESTATION_UNKNOWN");
        ASSERT(access(g_dlx_state, F_OK) != 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures + dlx_beat_cases() + dlx_beat_production_cases() +
        dlx_beat_reader_cases();
}

static void dlx_join_bad_identity(int kind, struct zcl_land_launcher_capture *c,
                                  struct zcl_land_launcher_frame *f)
{
    switch (kind) {
    case 0: c->complete = false; break;
    case 1: c->frame_count = 0; break;
    case 2: c->frame_count = 2; break;
    case 3: c->frames = NULL; break;
    case 4: c->before.unit = "foreign.service"; break;
    case 5: c->after.descriptor_sha256 = f->identity.boot_id; break;
    case 6: f->identity.invocation_id = f->identity.boot_id; break;
    case 7: f->identity.boot_id = f->identity.invocation_id; break;
    case 8: c->after.manager_uid++; break;
    case 9: f->uid++; break;
    }
}

static void dlx_join_bad_frame(int kind, struct zcl_land_launcher_capture *c,
                               struct zcl_land_launcher_frame *f)
{
    switch (kind) {
    case 10: c->after.pid++; break;
    case 11: f->transport = "journal"; break;
    case 12: f->cursor = NULL; break;
    case 13: c->before.captured_at_ms = 4999; break;
    case 14: c->after.captured_at_ms = 10001; break;
    case 15: f->identity.captured_at_ms = 9999; break;
    case 16: f->journal_at_ms = 4999; break;
    case 17: f->length--; break;
    case 18: f->wire = "{}"; f->length = 2; break;
    case 19: f->identity.pid++; break;
    }
}

int dlx_launcher_join_cases(void)
{
    int failures = 0;
    const char *wire = "{\"schema\":\"zcl.dev_land.self_attestation.v1\",\"seq\":410,\"candidate\":\"db648476e77c14308d77501ad85655e2444043b3\",\"base\":\"3a93e60ebf922af3d119b9facc1d95803f42844b\",\"tree\":\"4514cfd63acc408be3d37023656a8e88bc1be2c6\",\"unsealed\":true,\"executable_sha256\":\"d6810cf72e0c0ea08c05e89cb5cd20f37c9d8ecb6f069fc3c38f909bf26af564\",\"compiled_source_sha256\":\"6f0feb89be24e387e3b9cc67074c95172ddb78d9af093dda11dcf3e135bb5248\",\"observed_at_ms\":10000,\"allow_unsigned_is_one\":false,\"proof_stub_nonempty\":false,\"fixture_exception_enabled\":false,\"service_origin\":\"UNKNOWN\"}";
    struct zcl_land_launcher_identity expected = {
        .unit = "fixture-attest.service",
        .descriptor_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .invocation_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .boot_id = "cccccccccccccccccccccccccccccccc",
        .manager_uid = 1000, .pid = 123, .captured_at_ms = 10000
    };
    struct zcl_land_launcher_frame frame = {
        .identity = expected, .uid = 1000, .transport = "stdout",
        .cursor = "fixture-cursor", .wire = wire, .length = strlen(wire),
        .journal_at_ms = 10000
    };
    struct zcl_land_launcher_capture original = {
        .before = expected, .after = expected, .frames = &frame,
        .frame_count = 1, .complete = true
    };
    TEST("land launcher join: one exact frame and inclusive 5000ms fixture boundary") {
        bool enabled = true;
        ASSERT(zcl_dev_land_launcher_join(&expected, &original, 15000, &enabled));
        ASSERT(!enabled);
        ASSERT(!zcl_dev_land_launcher_join(&expected, &original, 15001, &enabled));
        ASSERT(!enabled);
        PASS();
    }
    TEST("land launcher join: missing stale foreign duplicate and truncated captures UNKNOWN") {
        for (int kind = 0; kind < 20; ++kind) {
            struct zcl_land_launcher_frame altered = frame;
            struct zcl_land_launcher_capture capture = original;
            capture.frames = &altered;
            dlx_join_bad_identity(kind, &capture, &altered);
            dlx_join_bad_frame(kind, &capture, &altered);
            bool enabled = true;
            ASSERT(!zcl_dev_land_launcher_join(&expected, &capture, 10000, &enabled));
            ASSERT(!enabled);
        }
        PASS();
    }
    TEST("land launcher join: image source and contradictory journal clocks UNKNOWN") {
        const char *markers[] = {"\"executable_sha256\":\"", "\"compiled_source_sha256\":\""};
        for (size_t i = 0; i < 4; ++i) {
            char changed[ZCL_LAND_ATTEST_CAP];
            ASSERT(strlen(wire) < sizeof(changed));
            memcpy(changed, wire, strlen(wire) + 1);
            struct zcl_land_launcher_frame altered = frame;
            struct zcl_land_launcher_capture capture = original;
            capture.frames = &altered;
            if (i < 2) {
                char *at = strstr(changed, markers[i]);
                ASSERT(at != NULL);
                at += strlen(markers[i]);
                *at = '0';
                altered.wire = changed;
            } else {
                altered.journal_at_ms = i == 2 ? 9999 : 10001;
            }
            bool enabled = true;
            ASSERT(!zcl_dev_land_launcher_join(&expected, &capture, 10001, &enabled));
            ASSERT(!enabled);
        }
        PASS();
    }
_test_next:;
    return failures;
}

bool dlx_hold_field_replace(const char *replacement)
{
    char body[16384], changed[16384], land[1200], path[1400];
    size_t len = 0;
    if (!dlx_queue_bytes(body, sizeof(body), &len)) return false;
    char *field = strstr(body, ",\"publication_hold\":");
    char *end = field ? strchr(field, '}') : strchr(body, '}');
    if (!field) field = end;
    if (!end) return false;
    int n = snprintf(changed, sizeof(changed), "%.*s%s%s",
                     (int)(field - body), body, replacement, end);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    return n > 0 && (size_t)n < sizeof(changed) && dlx_write(path, changed);
}

bool dlx_priority_replace(const char *value)
{
    char body[16384], changed[16384], land[1200], path[1400];
    size_t len = 0;
    if (!dlx_queue_bytes(body, sizeof(body), &len)) return false;
    char *field = strstr(body, "\"priority_seq\":");
    if (!field) return false;
    field += strlen("\"priority_seq\":");
    char *end = strchr(field, ',');
    if (!end) return false;
    int n = snprintf(changed, sizeof(changed), "%.*s%s%s",
                     (int)(field - body), body, value, end);
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    return n > 0 && (size_t)n < sizeof(changed) && dlx_write(path, changed);
}

bool dlx_priority_is(const char *value)
{
    char body[16384];
    size_t len = 0;
    return dlx_queue_bytes(body, sizeof(body), &len) && strstr(body, value) != NULL;
}

int dlx_guarded_priority_case(void)
{
    int failures = 0;
    TEST("land: held priority rejects malformed markers without queue rewrite") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[16384], after[16384], canonical[16384], land[1200], path[1400];
        size_t first = 0, second = 0;
        dlx_isolate("held_priority");
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_rig_make(&rig, "held_priority_rig"));
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_hold_field_replace(",\"publication_hold\":true"));
        ASSERT(dlx_queue_bytes(canonical, sizeof(canonical), &first));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        const char *bad[] = {"\"held:0\"", "\"held:-1\"", "\"held:+1\"",
            "\"held:01\"", "\"held: 1\"", "\"held:1 \"", "\"held:1x\"",
            "\"held:\"", "\"held:2\"", "\"held:9223372036854775808\"",
            "\"held:1\\u0000junk\"", "true", "0", "-1", "2",
            "\"held:1\",\"priority_seq\":1"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(dlx_write(path, canonical));
            ASSERT(dlx_priority_replace(bad[i]));
            ASSERT(dlx_queue_bytes(before, sizeof(before), &first));
            dlx_begin(&c, "status");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_queue_bytes(after, sizeof(after), &second));
            ASSERT(first == second && memcmp(before, after, first) == 0);
        }
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

int dlx_guarded_hold_mismatch_case(void)
{
    int failures = 0;
    TEST("land: guarded priority requires true hold and survives other-row rewrites") {
        struct dlx_rig rig, other;
        struct dlx_call c;
        dlx_isolate("guarded_mismatch");
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_rig_make(&rig, "guarded_mismatch_rig"));
        ASSERT(dlx_rig_make(&other, "guarded_other_rig"));
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_priority_replace("\"held:1\""));
        const char *hold[] = {"", ",\"publication_hold\":false",
            ",\"publication_hold\":true,\"publication_hold\":true"};
        for (size_t i = 0; i < sizeof(hold) / sizeof(hold[0]); i++) {
            ASSERT(dlx_hold_field_replace(hold[i]));
            dlx_begin(&c, "status");
            ASSERT(dlx_run(&c) && !dlx_ok(&c));
            ASSERT_STR_EQ(c.reply.error.code, "QUEUE_READ_FAILED"); dlx_end(&c);
            ASSERT(dlx_hold_field_replace(",\"publication_hold\":true"));
        }
        dlx_submit(&c, &other, other.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        dlx_begin(&c, "hold");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_priority_is("\"priority_seq\":\"held:1\""));
        ASSERT(dlx_priority_is("\"priority_seq\":\"held:2\""));
        dlx_begin(&c, "release");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_priority_is("\"priority_seq\":\"held:1\""));
        ASSERT(dlx_priority_is("\"priority_seq\":2,"));
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}

int dlx_hold_legacy_case(void)
{
    int failures = 0;
    TEST("land: a legacy row without publication_hold retains normal publication") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64];
        dlx_isolate("hold_legacy");
        ASSERT(dlx_rig_make(&rig, "hold_legacy_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        ASSERT(dlx_hold_field_replace(""));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c)); dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        /* Also remove the field from the reopened in-flight row. */
        ASSERT(dlx_hold_field_replace(""));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed"); dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(before, after) != 0);
        PASS();
    }
_test_next:
    dlx_restore();
    return failures;
}
