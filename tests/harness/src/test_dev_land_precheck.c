/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: precheck rigs, gate sets, history shipping and early step cases.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


/* The actual checker stays a real child; only unrelated core gates use the
 * existing fixture's checker. The canonical table is copied unchanged. */
static bool dlx_pc_select_purpose(void)
{
    char row[1024];
    dlx_pc_row(row, sizeof(row), 1, "failed", "lint", 1,
               "check-file-purpose failed");
    return dlx_pc_outcomes(row);
}

static bool dlx_pc_purpose_refusal(const struct dlx_call *c)
{
    return strcmp(dlx_err_code(c), "PRECHECK_FAILED") == 0 &&
        strcmp(dlx_str(c, "gate"), "check-file-purpose") == 0;
}

static bool dlx_pc_build_sentinel(const struct dlx_rig *rig)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/Makefile", rig->clone);
    return dlx_write(path, "%:\n\t@touch build/unexpected-build\n");
}

static bool dlx_pc_no_build(const struct dlx_rig *rig)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/build/unexpected-build", rig->clone);
    return !dlx_file_exists(path);
}

static bool dlx_pc_mode_setup(struct dlx_rig *rig)
{
    char cwd[4096], source[8192], target[1400], reader[65536];
    size_t len;
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(source, sizeof(source), "%s/tools/lint/run_lint.sh", cwd) >= (int)sizeof(source) ||
        !dlx_slurp(source, reader, sizeof(reader), &len) ||
        !dlx_pc_rig(rig, "precheck_canonical", true,
                    "check-core-seal\ncheck-file-purpose\n"))
        return false;
    if (!dlx_pc_select_purpose())
        return false;
    reader[len] = 0;
    (void)snprintf(target, sizeof(target), "%s/tools/lint", rig->clone);
    if (!dlx_mkdir_p(target))
        return false;
    (void)snprintf(target, sizeof(target), "%s/tools/lint/run_lint.sh", rig->clone);
    if (!dlx_write(target, reader))
        return false;
    (void)snprintf(source, sizeof(source), "%s/build/bin/z23-lint", cwd);
    (void)snprintf(target, sizeof(target), "%s/build/bin/real-lint", rig->clone);
    return symlink(source, target) == 0 &&
        dlx_write_dep(rig->clone, "tools/probe.c", "int probe;\n");
}

static bool dlx_pc_repaired_control(const struct dlx_rig *rig)
{
    struct dlx_call c;
    if (!dlx_write_dep(rig->clone, "tools/probe.c",
                       "/* purpose: Isolated precheck fixture. */\nint probe;\n"))
        return false;
    dlx_pc_submit(&c, rig, NULL, NULL);
    bool ok = dlx_run(&c) && dlx_ok(&c) && dlx_queue_has_one() &&
        dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-file-purpose") &&
        strcmp(getenv("ZCL_LINT_MODE"), "WARN") == 0 && dlx_pc_no_build(rig);
    dlx_end(&c);
    return ok;
}

static bool dlx_pc_canonical_mode_inner(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char path[1400], out[4096];
    if (!dlx_pc_mode_setup(&rig))
        return false;
    (void)snprintf(path, sizeof(path), "%s/build/bin/z23-lint", rig.clone);
    if (!dlx_write(path, "#!/bin/sh\n"
        "if [ \"$1\" = --list ]; then cat build/precheck-known; exit 0; fi\n"
        "if [ \"$1\" = check-file-purpose ]; then\n"
        "  exec ./build/bin/real-lint \"$@\"\nfi\n"
        "exit 0\n"))
        return false;
    if (!dlx_pc_build_sentinel(&rig))
        return false;
    setenv("ZCL_FILE_PURPOSE_ROOT", rig.clone, 1);
    setenv("ZCL_LINT_MODE", "WARN", 1);
    const char *raw[] = {"sh", "-c", "cd \"$1\" && exec build/bin/z23-lint check-file-purpose",
                         "sh", rig.clone, NULL};
    bool ok = zcl_spawn_capture(raw, out, sizeof(out), 30000) == 0;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = dlx_run(&c) && !dlx_ok(&c) && dlx_queue_empty() && dlx_pc_purpose_refusal(&c) && ok;
    dlx_end(&c);
    ok = dlx_pc_repaired_control(&rig) && ok;
    unsetenv("ZCL_FILE_PURPOSE_ROOT");
    unsetenv("ZCL_LINT_MODE");
    dlx_restore();
    return ok;
}

static void dlx_pc_restore_env(const char *name, char *saved)
{
    if (saved)
        (void)setenv(name, saved, 1);
    else
        (void)unsetenv(name);
    free(saved);
}

static bool dlx_pc_canonical_mode(void)
{
    const char *root = getenv("ZCL_FILE_PURPOSE_ROOT");
    const char *mode = getenv("ZCL_LINT_MODE");
    char *saved_root = root ? strdup(root) : NULL;
    char *saved_mode = mode ? strdup(mode) : NULL;
    bool saved = (!root || saved_root) && (!mode || saved_mode);
    bool ok = saved && dlx_pc_canonical_mode_inner();
    if (saved) {
        dlx_pc_restore_env("ZCL_FILE_PURPOSE_ROOT", saved_root);
        dlx_pc_restore_env("ZCL_LINT_MODE", saved_mode);
    } else {
        free(saved_root);
        free(saved_mode);
    }
    return ok;
}

static bool dlx_pc_bad_metadata_one(const char *body)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char path[1400];
    if (!dlx_pc_rig(&rig, "precheck_metadata", true, "check-file-purpose\n"))
        return false;
    if (!dlx_pc_select_purpose())
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint", rig.clone);
    if (!dlx_mkdir_p(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint/run_lint.sh", rig.clone);
    if (!dlx_pc_build_sentinel(&rig))
        return false;
    if (body && !dlx_write(path, body))
        return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ok = dlx_run(&c) && !dlx_ok(&c) && dlx_queue_empty() &&
        !dlx_pc_ran(&rig, "check-file-purpose") && dlx_pc_no_build(&rig) &&
        strcmp(dlx_err_code(&c), "PRECHECK_UNAVAILABLE") == 0;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_pc_bad_metadata(void)
{
    return dlx_pc_bad_metadata_one(NULL) &&
        dlx_pc_bad_metadata_one("exit 1\n") &&
        dlx_pc_bad_metadata_one("exit 0\n") &&
        dlx_pc_bad_metadata_one("printf 'if\\n'\n") &&
        dlx_pc_bad_metadata_one("printf 'echo ok\\necho hidden\\n'\n") &&
        dlx_pc_bad_metadata_one(
            "printf '%05000d' 0\n");
}

static bool dlx_pc_deadline_one(bool reader_only)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char path[1400];
    if (!dlx_pc_rig(&rig, "precheck_deadline", true, "check-file-purpose\n"))
        return false;
    if (!dlx_pc_select_purpose())
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint", rig.clone);
    if (!dlx_mkdir_p(path))
        return false;
    (void)snprintf(path, sizeof(path), "%s/tools/lint/run_lint.sh", rig.clone);
    const char *body = reader_only
        ? "touch build/deadline-reader-started\nsleep 6\nprintf 'touch build/deadline-completed\\n'\n"
        : "touch build/deadline-reader-started\nsleep 2\nprintf 'touch build/deadline-command-started; sleep 4; touch build/deadline-completed\\n'\n";
    if (!dlx_write(path, body))
        return false;
    zcl_dev_land_precheck_test_budget(5000);
    dlx_pc_submit(&c, &rig, NULL, NULL);
    bool ran = dlx_run(&c);
    zcl_dev_land_precheck_test_budget(0);
    bool ok = ran && !dlx_ok(&c) && dlx_queue_empty() &&
        strcmp(c.reply.error.code, "PRECHECK_TIMEOUT") == 0;
    (void)snprintf(path, sizeof(path), "%s/build/deadline-reader-started", rig.clone);
    ok = dlx_file_exists(path) && ok;
    if (!reader_only) {
        (void)snprintf(path, sizeof(path), "%s/build/deadline-command-started", rig.clone);
        ok = dlx_file_exists(path) && ok;
    }
    (void)snprintf(path, sizeof(path), "%s/build/deadline-completed", rig.clone);
    ok = !dlx_file_exists(path) && ok;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_pc_unknown_gate_skipped(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char rows[1024], one[512];
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_unknown", true,
                    "check-file-size-ceiling\ncheck-core-seal\n"
                    "check-learned-one\n"))
        return false;
    rows[0] = '\0';
    dlx_pc_row(one, sizeof(one), 1, "failed", "lint", 1,
               "check-learned-one and check-gone-gate failed");
    (void)strcat(rows, one);
    if (!dlx_pc_outcomes(rows))
        return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = dlx_run(&c) && dlx_ok(&c) &&
         dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-learned-one") &&
         dlx_pc_has(dlx_arr(&c, "precheck_skipped"), "check-gone-gate") &&
         dlx_pc_has(dlx_arr(&c, "precheck_skipped"),
                    "check-arm-symbol-single") &&
         !dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-gone-gate");
    dlx_end(&c);
    ok = ok && dlx_pc_ran(&rig, "check-learned-one") &&
         !dlx_pc_ran(&rig, "check-gone-gate");
    dlx_restore();
    return ok;
}

static bool dlx_pc_missing_lint_refused(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_nolint", false, ""))
        return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = dlx_run(&c) && !dlx_ok(&c) &&
         strcmp(dlx_err_code(&c), "PRECHECK_UNAVAILABLE") == 0 &&
         strstr(c.reply.error.message,
                "make build/bin/z23-lint docs-capability-inventory") != NULL;
    dlx_end(&c);
    ok = ok && dlx_queue_empty();
    dlx_restore();
    return ok;
}

/* The gates lint the worktree, so a tip that is not its HEAD is refused. */
static bool dlx_pc_tip_not_head_refused(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char parent[64];
    const char *rev[] = { "rev-parse", "HEAD~1", NULL };
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_tip", true, "check-core-seal\n") ||
        dlx_git_out(rig.clone, rev, parent, sizeof(parent)) != 0)
        return false;
    parent[strcspn(parent, "\n")] = '\0';
    dlx_begin(&c, NULL);
    (void)json_push_kv_str(&c.input, "action", "submit");
    (void)json_push_kv_str(&c.input, "tip", parent);
    (void)json_push_kv_str(&c.input, "worktree", rig.clone);
    ok = dlx_run(&c) && !dlx_ok(&c) &&
         strcmp(dlx_err_code(&c), "PRECHECK_TIP_NOT_HEAD") == 0;
    dlx_end(&c);
    ok = ok && dlx_queue_empty() && !dlx_pc_ran(&rig, "check-core-seal");
    dlx_restore();
    return ok;
}

void zcl_native_dev_land_test_qualify_head(bool on);
void zcl_native_dev_land_submit_received(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply);

static const char *const DLX_PC_ALL_GATES =
    "check-file-size-ceiling\ncheck-cyclomatic-complexity\n"
    "check-core-seal\ncheck-arm-symbol-single\n";

/* --qualify (stood in for by the test seam, which qualifies HEAD) does not
 * re-run the gates, yet still validates the mode and marks a skip. */
static bool dlx_pc_qualify_modes(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_qualify", true, DLX_PC_ALL_GATES) ||
        !dlx_pc_file(&rig, "precheck-fail", "check-core-seal"))
        return false;
    zcl_native_dev_land_test_qualify_head(true);
    for (int pass = 0; pass < 2; pass++) {
        dlx_begin(&c, NULL);
        (void)json_push_kv_str(&c.input, "action", "submit");
        (void)json_push_kv_str(&c.input, "worktree", rig.clone);
        (void)json_push_kv_bool(&c.input, "qualify", true);
        (void)json_push_kv_str(&c.input, "precheck", pass ? "skip" : "bogus");
        (void)json_push_kv_str(&c.input, "note", "q");
        if (pass == 0) {
            ok = dlx_run(&c) && strcmp(dlx_err_code(&c), "BAD_INPUT") == 0;
            dlx_end(&c);
            ok = ok && dlx_queue_empty();
        } else {
            ok = ok && dlx_run(&c) && dlx_ok(&c);
            dlx_end(&c);
        }
        if (!ok)
            break;
    }
    zcl_native_dev_land_test_qualify_head(false);
    ok = ok && dlx_pc_queued_note("q [precheck skipped]") &&
         !dlx_pc_ran(&rig, "check-core-seal");
    dlx_restore();
    return ok;
}

/* The receive entry queues without running a gate that would fail. */
static bool dlx_pc_received_skips_gates(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_received", true, DLX_PC_ALL_GATES) ||
        !dlx_pc_file(&rig, "precheck-fail", "check-core-seal"))
        return false;
    dlx_pc_submit(&c, &rig, NULL, "r");
    zcl_native_dev_land_submit_received(&c.request, &c.reply);
    ok = dlx_ok(&c);
    dlx_end(&c);
    ok = ok && dlx_queue_has_one() && dlx_pc_queued_note("r") &&
         !dlx_pc_ran(&rig, "check-core-seal");
    dlx_restore();
    return ok;
}

/* Re-submitting an already queued tip after the worktree moved on attaches
 * to its live row; the precheck neither runs nor refuses. */
static bool dlx_pc_retry_attaches(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char newer[64];
    bool ok;
    if (!dlx_pc_rig(&rig, "precheck_retry", true, DLX_PC_ALL_GATES))
        return false;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    ok = ok && dlx_commit(rig.clone, "moved.txt", "moved\n", newer) &&
         strcmp(newer, rig.tip) != 0;
    dlx_pc_submit(&c, &rig, NULL, NULL);
    ok = ok && dlx_run(&c) && dlx_ok(&c) && dlx_int(&c, "seq") == 1;
    dlx_end(&c);
    ok = ok && dlx_queue_has_one();
    dlx_restore();
    return ok;
}

static int dlx_case_history_precheck(void)
{
    int failures = 0;
    TEST("land: retained failed train learns ship despite later landing and absent native gate") {
        ASSERT(dlx_pc_history_ship_pass());
        PASS();
    }
    TEST("land: executed ship failure refuses without queuing") {
        ASSERT(dlx_pc_history_ship_refusal("1", true));
        PASS();
    }
    TEST("land: executed ship exit 2 is a failure, not an unproven native gate") {
        ASSERT(dlx_pc_history_ship_refusal("2", true));
        PASS();
    }
    TEST("land: missing ship prerequisite is explicitly unproven without execution") {
        ASSERT(dlx_pc_history_ship_refusal("0", false));
        PASS();
    }
    TEST("land: uncertain, interrupted and no-verdict history preserves outcome learning") {
        ASSERT(dlx_pc_history_ignored("history_old", 8, "child_proof_failed_exit_2", false));
        ASSERT(dlx_pc_history_ignored("history_future", -1, "child_proof_failed_exit_2", false));
        ASSERT(dlx_pc_history_ignored("history_interrupted", 1, "proof_interrupted_child_proof_failed_exit_2", false));
        ASSERT(dlx_pc_history_ignored("history_no_verdict", 1, "proof_producer_source_mismatch", false));
        ASSERT(dlx_pc_history_ignored("history_nonlint", 1,
            "child_proof_failed_exit_2\ntest: FAIL check-ship-remote-transaction", false));
        PASS();
    }
    TEST("land: unsafe history discards any partial learned gates but preserves outcomes") {
        ASSERT(dlx_pc_history_ignored("history_unsafe", 1, "child_proof_failed_exit_2", true));
        PASS();
    }
    TEST("land: history allocation failure remains unproven and preserves outcome gates") {
        ASSERT(dlx_pc_history_allocation_unproven());
        PASS();
    }
    TEST("land: busy legacy observation preserves outcome gates and explicitly reports unproven") {
        ASSERT(dlx_pc_observation_busy());
        PASS();
    }
    TEST("land: aged observation proves failure old without refreshing it or treating recent observation as event time") {
        ASSERT(dlx_pc_observation_aged());
        PASS();
    }
_test_next:;
    zcl_dev_land_precheck_test_now(0);
    return failures;
}

static int dlx_pc_mode_cases(void)
{
    int failures = 0;
    TEST("land: canonical reader and execution share the remaining deadline") {
        ASSERT(dlx_pc_deadline_one(true));
        ASSERT(dlx_pc_deadline_one(false));
        PASS();
    }
    TEST("land: canonical file-purpose rejects WARN false success and accepts repair") {
        ASSERT(dlx_pc_canonical_mode());
        PASS();
    }
    TEST("land: missing or malformed canonical metadata refuses without queueing") {
        ASSERT(dlx_pc_bad_metadata());
        PASS();
    }
_test_next:;
    return failures;
}

int dlx_case_precheck(void)
{
    int failures = dlx_case_history_precheck() + dlx_pc_mode_cases();
    TEST("land: submit refuses a lane whose precheck gate fails and queues nothing") {
        ASSERT(dlx_pc_failing_gate_refused());
        PASS();
    }
    TEST("land: precheck skips a gate that cannot decide (exit 2) and queues") {
        ASSERT(dlx_pc_unproven_gate_skipped());
        PASS();
    }
    TEST("land: submit queues a lane whose precheck gates are clean") {
        ASSERT(dlx_pc_clean_lane_queued());
        PASS();
    }
    TEST("land: precheck=skip queues with the note marker and refuses overflow") {
        ASSERT(dlx_pc_skip_marks_note());
        PASS();
    }
    TEST("land: the precheck gate set learns check-* names from failed lint rows") {
        ASSERT(dlx_pc_gate_set_learns());
        PASS();
    }
    TEST("land: precheck skips and reports a gate the lane lint does not know") {
        ASSERT(dlx_pc_unknown_gate_skipped());
        PASS();
    }
    TEST("land: precheck without a lane z23-lint refuses with the prime hint") {
        ASSERT(dlx_pc_missing_lint_refused());
        PASS();
    }
    TEST("land: precheck refuses a tip that is not the worktree HEAD") {
        ASSERT(dlx_pc_tip_not_head_refused());
        PASS();
    }
    TEST("land: qualify validates the precheck mode and marks a skip") {
        ASSERT(dlx_pc_qualify_modes());
        PASS();
    }
    TEST("land: the receive entry queues without running a failing gate") {
        ASSERT(dlx_pc_received_skips_gates());
        PASS();
    }
    TEST("land: a retry of a queued tip attaches though the worktree moved on") {
        ASSERT(dlx_pc_retry_attaches());
        PASS();
    }
_test_next:;
    zcl_dev_land_precheck_test_now(0);
    zcl_dev_land_precheck_test_force(false);
    return failures;
}

int dlx_case_empty_step(void)
{
    int failures = 0;
    TEST("land: a step over an empty queue is a no-op that leaves the queue empty") {
        struct dlx_call c;
        dlx_isolate("empty");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        ASSERT(dlx_queue_empty());
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_step_lock(void)
{
    int failures = 0;
    TEST("land: a step finds its own lock already held and says STEP_BUSY, "
        "retryable, touching nothing; released, it proceeds") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200];
        char qpath[1400];
        char before[4096], after[4096];
        size_t before_len = 0, after_len = 0;
        int lockfd;

        dlx_isolate("stepbusy");
        ASSERT(dlx_rig_make(&rig, "stepbusy_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);

        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir);
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));

        /* Take the same step.lock dev.land's own dl_step_lock() takes,
         * through the identical open+flock(LOCK_EX|LOCK_NB) discipline. */
        lockfd = dlx_step_lock_take(landdir);
        ASSERT(lockfd >= 0);

        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT(strcmp(dlx_err_code(&c), "STEP_BUSY") == 0);
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "queue=") != NULL);
        {
#if defined(__linux__)
            char want[48];
            (void)snprintf(want, sizeof(want), "holder_pid=%d ",
                           (int)getpid());
            ASSERT(strstr(dlx_err_evidence(&c), want) != NULL);
#else
            /* The holder is read from /proc/locks, which only Linux has. */
            ASSERT(strstr(dlx_err_evidence(&c), "holder_pid=unknown") != NULL);
#endif
        }
        ASSERT(strstr(dlx_err_evidence(&c), landdir) != NULL);
        dlx_end(&c);

        /* Untouched: the queued row is still queued, never rebased. */
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT_EQ((long long)before_len, (long long)after_len);
        ASSERT(memcmp(before, after, before_len) == 0);

        /* Released, a step proceeds exactly as it would have. */
        dlx_step_lock_release(lockfd);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);

        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_starts_proof(void)
{
    int failures = 0;
    TEST("land: the step that asks for a proof returns before it finishes") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], logpath[1400];
        dlx_isolate("start");
        ASSERT(dlx_rig_make(&rig, "start_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Asked for, not answered: the request is in flight and the verb
         * came back. A step that waited would still be inside the proof. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strcmp(dlx_str(&c, "phase"), "prove") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A second step while the proof is still pending changes nothing
         * and still returns. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        dlx_end(&c);
        /* The private landing worktree was created once and reused. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/wt/.git", landdir);
        ASSERT(dlx_file_exists(logpath));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_absent_watcher(void)
{
    int failures = 0;
    TEST("land: an absent resident watcher is named, twice, not hidden") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("watcher_absent");
        ASSERT(dlx_rig_make(&rig, "watcher_absent_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "watcher_absent", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(strcmp(dlx_str(&c, "detail"),
                      "resident_proof_watcher_absent") == 0);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        ASSERT(strcmp(dlx_str(&c, "detail"),
                      "resident_proof_watcher_absent") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_unarmed_proof(void)
{
    int failures = 0;
    TEST("land: an unarmed proof has an exact worker-stealable step") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("manual_proof");
        ASSERT(dlx_rig_make(&rig, "manual_proof_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "manual", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "phase"), "prove") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "dev proof step") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), rig.tip) != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "proving") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "dev proof step") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_stub_detail(void)
{
    int failures = 0;
    TEST("land: an unrelated stub value still reports its own detail") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("stub_running");
        ASSERT(dlx_rig_make(&rig, "stub_running_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "detail"), "proof stub: running") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_lands_proof(void)
{
    int failures = 0;
    TEST("land: a passing proof fast-forwards the real origin and lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], local[64];
        const struct json_value *outcomes;
        dlx_isolate("land");
        ASSERT(dlx_rig_make(&rig, "land_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The proof answers between steps, exactly as the real one does. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        (void)snprintf(local, sizeof(local), "%s", dlx_str(&c, "tip_pushed"));
        ASSERT(strlen(local) == 40);
        dlx_end(&c);
        /* The bare origin moved, and to exactly the commit that was proved. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT(strcmp(after, local) == 0);
        /* The outcome is durable and the queue is empty again. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        ASSERT(json_get(&c.reply.data, "in_flight") == NULL);
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "landed") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_hook_refusal(void)
{
    int failures = 0;
    TEST("land: pushes through the pre-push hook — a refusing hook wins") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hooks_dir[1024];
        bool done = false;
        int i;
        dlx_isolate("hookguard");
        ASSERT(dlx_rig_make(&rig, "hookguard_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        /* Arm a REAL pre-push hook in the landing worktree that always
         * refuses. dev.land no longer pushes with --no-verify (the fleet
         * rule this whole change exists to satisfy), so if that hook is
         * genuinely consulted the land can never succeed no matter how
         * many times the (stubbed) proof passes — proving the removal is
         * real and not merely cosmetic. */
        ASSERT(dlx_hooks_dir(hooks_dir, sizeof(hooks_dir), "hookguard_hooks",
                             1));
        setenv("ZCL_LAND_HOOKS_STUB_DIR", hooks_dir, 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        for (i = 0; i < 16 && !done; i++) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            if (strcmp(dlx_str(&c, "state"), "failed") == 0) {
                ASSERT(strcmp(dlx_str(&c, "dimension"), "push") == 0);
                done = true;
            }
            dlx_end(&c);
        }
        ASSERT(done);
        /* The refusing hook actually stopped it: the bare origin never
         * moved. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_proof_failure(void)
{
    int failures = 0;
    TEST("land: a failing proof records the dimension and a log path") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], logpath[4200];
        const struct json_value *outcomes;
        dlx_isolate("fail");
        ASSERT(dlx_rig_make(&rig, "fail_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *inflight = json_get(&c.reply.data, "in_flight");
        ASSERT(inflight != NULL);
        /* The published outcome must not mistake a passing gate's name
         * for the proof failure, even when it precedes the failure log. */
        char landdir[1200];
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log", landdir);
        ASSERT(dlx_write(logpath, "  PASS check-pipefail-status-pipe 5977 ms\n"));
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
        ASSERT_STR_EQ(dlx_str(&c, "detail"), "proof stub: fail");
        (void)snprintf(logpath, sizeof(logpath), "%s", dlx_str(&c,
                                                               "log_path"));
        ASSERT(logpath[0] != '\0');
        ASSERT(dlx_file_exists(logpath));
        dlx_end(&c);
        /* A red proof pushes nothing. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes != NULL);
        ASSERT_EQ((long long)outcomes->num_children, 1);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "state")) &&
               strcmp(json_get_str(json_get(&outcomes->children[0],
                                            "state")), "failed") == 0);
        ASSERT(json_get_str(json_get(&outcomes->children[0], "log_path")) &&
               json_get_str(json_get(&outcomes->children[0],
                                     "log_path"))[0] != '\0');
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_timing_detail(void)
{
    int failures = 0;
    TEST("land: a lint timing-table row never becomes a proof failure detail") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], logpath[4200];
        dlx_isolate("timingrow");
        ASSERT(dlx_rig_make(&rig, "timingrow_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        /* Plant the lint slowest-gates summary row in the attempt log: it
         * names gates with no PASS prefix, so a gate with "fail" in its
         * name matches the triage needles. The recorded outcome must
         * still name the proof's own typed failure, never that timing
         * row. */
        char landdir[1200];
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log", landdir);
        ASSERT(dlx_write(logpath,
                         "  slowest gates:\n    5977 ms  check-pipefail-status-pipe\n"));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "lint") == 0);
        ASSERT_STR_EQ(dlx_str(&c, "detail"), "proof stub: fail");
        dlx_end(&c);
        /* A red proof pushes nothing. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_moved_base(void)
{
    int failures = 0;
    TEST("land: a base that moved while proving re-rebases, never lands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char stranger[64], main_now[64];
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600];
        dlx_isolate("moved");
        ASSERT(dlx_rig_make(&rig, "moved_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* A STRANGER lands on main while this request is proving. */
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        ASSERT(dlx_git(side, branch) == 0);
        ASSERT(dlx_commit(side, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(side, push) == 0);
        ASSERT(dlx_git(side, back) == 0);
        ASSERT(dlx_git(side, fetch) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* The receipt is about a base nobody is on. It rebases instead. */
        ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        /* main is still the stranger's commit: nothing was landed on a
         * stale receipt. */
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT(strcmp(main_now, stranger) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_cancel_request(void)
{
    int failures = 0;
    TEST("land: cancel drops one request by sequence number") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("cancel");
        ASSERT(dlx_rig_make(&rig, "cancel_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        /* A sequence number nobody submitted is refused, not invented. */
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 99);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "cancelled") == 0);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ((long long)dlx_arr(&c, "queued")->num_children, 0);
        dlx_end(&c);
        /* A cancelled request is a step's no-op, not a landing. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static size_t dlx_case_trim_row(char *line)
{
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    return len;
}

int dlx_case_concurrent_submit(void)
{
    int failures = 0;
    TEST("land: two concurrent exact submitters attach one complete row") {
        struct dlx_rig rig;
        char landdir[1200], qf[1400], line[8192];
        pid_t a, b;
        int sa = 0, sb = 0, nlines = 0;
        FILE *f;
        dlx_isolate("fork");
        ASSERT(dlx_rig_make(&rig, "fork_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        a = fork();
        ASSERT(a >= 0);
        if (a == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        b = fork();
        ASSERT(b >= 0);
        if (b == 0) {
            struct dlx_call c;
            dlx_submit(&c, &rig, rig.tip);
            (void)json_push_kv_str(&c.input, "note", "second");
            (void)dlx_run(&c);
            _exit(dlx_ok(&c) ? 0 : 1);
        }
        while (waitpid(a, &sa, 0) < 0)
            ;
        while (waitpid(b, &sb, 0) < 0)
            ;
        ASSERT(WIFEXITED(sa) && WEXITSTATUS(sa) == 0);
        ASSERT(WIFEXITED(sb) && WEXITSTATUS(sb) == 0);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qf, sizeof(qf), "%s/queue.jsonl", landdir);
        f = fopen(qf, "r");
        ASSERT(f != NULL);
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = dlx_case_trim_row(line);
                if (len == 0)
                    continue;
                nlines++;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                json_free(&v);
            }
            (void)fclose(f);
        }
        ASSERT_EQ((long long)nlines, 1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_dense_detail(void)
{
    int failures = 0;
    TEST("land: a control-byte-dense detail persists instead of "
        "un-committing the row") {
        struct dlx_rig rig;
        struct dlx_call c;
        char stub[300], detail[300];
        size_t i;
        dlx_isolate("ctrlbytes");
        ASSERT(dlx_rig_make(&rig, "ctrlbytes_rig"));
        /* Dense control bytes, no NUL: dl_escape() would need to expand
         * every one of these into a 6-byte "\u00XX" sequence. Before
         * e_detail was sized for detail's true worst case, a value this
         * dense made dl_encode_row refuse and the "started" commit never
         * reached queue.jsonl at all — the reply would still have to
         * report something, but the row would never be durably marked
         * in flight. */
        for (i = 0; i < sizeof(stub) - 1; i++)
            stub[i] = (char)(1 + (i % 30)); /* 0x01..0x1e, never '\0' */
        stub[sizeof(stub) - 1] = '\0';
        setenv("ZCL_LAND_PROOF_STUB", stub, 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Committed for real, not silently dropped: the reply is the
         * normal "started" with no persist failure. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        ASSERT(dlx_str(&c, "persist")[0] == '\0');
        (void)snprintf(detail, sizeof(detail), "%s", dlx_str(&c, "detail"));
        dlx_end(&c);
        /* A second step reads the row back from queue.jsonl: the round
         * trip through dl_encode_row/dl_escape and back through
         * dl_parse_row survived. */
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_missing_hook(void)
{
    int failures = 0;
    TEST("land: a hooksPath naming no real pre-push cannot skip admission") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], mid[64], after[64], landdir[1200], wt[1400];
        char badhooks[1200], second[64];
        const char *cfg[4];
        dlx_isolate("hookslie");
        ASSERT(dlx_rig_make(&rig, "hookslie_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Land a first row all the way through: this creates the landing
         * worktree and arms it with the (test-only) good hook stub, and
         * frees dl_step's picker — it always prefers an inflight row, so
         * the second row below is only ever picked once nothing is
         * inflight any more. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, mid));
        ASSERT(strcmp(mid, before) != 0);
        /* Corrupt the landing worktree's own hooksPath to a directory
         * that carries no real, executable pre-push. Before this fix,
         * dl_wt_hooks_ready() treated any NONEMPTY core.hooksPath as
         * proof enough and never looked at the file it named. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(wt, sizeof(wt), "%s/wt", landdir);
        test_make_tmpdir(badhooks, sizeof(badhooks), "dev_land_badhooks",
                         "hookslie_bad");
        cfg[0] = "config"; cfg[1] = "--worktree"; cfg[2] = "core.hooksPath";
        cfg[3] = badhooks;
        {
            const char *args[] = { cfg[0], cfg[1], cfg[2], cfg[3], NULL };
            ASSERT(dlx_git(wt, args) == 0);
        }
        /* A second, independent tip. No test hook stub this time: a real
         * worktree with no Makefile to run `make install-hooks` in must
         * refuse the request rather than accept the broken config as
         * already armed and push straight through it. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        unsetenv("ZCL_LAND_HOOKS_STUB_DIR");
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree") == 0);
        dlx_end(&c);
        /* No second push happened: the broken hook config never got a
         * chance to wave one through. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, mid) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_cancel_race(void)
{
    int failures = 0;
    TEST("land: a cancel that beats a landing records exactly one outcome") {
        struct dlx_rig rig;
        struct dlx_call c, cancelc;
        char landdir[1200], opath[1400], line[8192];
        pid_t child;
        int st = 0;
        long long ntotal = 0, nlanded = 0, ncancelled = 0;
        FILE *f;
        dlx_isolate("racecancel");
        ASSERT(dlx_rig_make(&rig, "racecancel_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        /* ZCL_LAND_TEST_PICK_DELAY_MS makes the race deterministic: the
         * child pauses right after dl_step() picks this row (under the
         * slot lock only) and before it drives the pushing/committing
         * work below — exactly the published race window ("step loads
         * rows under only the slot lock, cancel deletes under the row
         * lock"). The parent's cancel (one flock and one small rewrite)
         * easily finishes inside that window. Whichever side had won
         * without the delay, exactly one outcome for this seq may ever
         * land in outcomes.jsonl — a cancelled row must never ALSO get a
         * second, later outcome appended on top of cancel's own. */
        setenv("ZCL_LAND_TEST_PICK_DELAY_MS", "200", 1);
        child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(0);
        }
        /* Give the child time to run its own picker (dl_step reads the
         * queue under only the slot lock) before this cancel takes the
         * row lock and deletes — the published race window. Without this
         * the fork/schedule overhead alone lets cancel finish before the
         * child is even scheduled, which would race nothing. 30ms is
         * comfortably inside the child's own 200ms post-pick delay
         * (ZCL_LAND_TEST_PICK_DELAY_MS) below. */
        {
            struct timespec ts = { 0, 30 * 1000 * 1000L };
            (void)nanosleep(&ts, NULL);
        }
        dlx_begin(&cancelc, "cancel");
        (void)json_push_kv_int(&cancelc.input, "seq", 1);
        ASSERT(dlx_run(&cancelc));
        ASSERT(dlx_ok(&cancelc));
        ASSERT(strcmp(dlx_str(&cancelc, "state"), "cancelled") == 0);
        dlx_end(&cancelc);
        while (waitpid(child, &st, 0) < 0)
            ;
        ASSERT(WIFEXITED(st));
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir);
        f = fopen(opath, "r");
        if (f) {
            while (fgets(line, sizeof(line), f)) {
                struct json_value v;
                size_t len = dlx_case_trim_row(line);
                const struct json_value *seqv, *statev;
                if (len == 0)
                    continue;
                json_init(&v);
                ASSERT(json_read(&v, line, len) && v.type == JSON_OBJ);
                seqv = json_get(&v, "seq");
                statev = json_get(&v, "state");
                if (seqv && seqv->type == JSON_INT && json_get_int(seqv) == 1) {
                    ntotal++;
                    if (statev && statev->type == JSON_STR) {
                        if (strcmp(json_get_str(statev), "landed") == 0)
                            nlanded++;
                        if (strcmp(json_get_str(statev), "cancelled") == 0)
                            ncancelled++;
                    }
                }
                json_free(&v);
            }
            (void)fclose(f);
        }
        /* Cancel won (guaranteed by the delay): exactly its own outcome,
         * never a second "landed" row appended after the fact. */
        ASSERT_EQ(ncancelled, 1);
        ASSERT_EQ(nlanded, 0);
        ASSERT_EQ(ntotal, 1);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_aged_successor(void)
{
    int failures = 0;
    TEST("land: moving main keeps the aged successor ahead of newer work") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64], following[64], original_ts[64];
        bool done = false;
        int i;
        dlx_isolate("moveforever");
        ASSERT(dlx_rig_make(&rig, "moveforever_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "following.txt", "following\n",
                          following));
        dlx_submit(&c, &rig, following);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        ASSERT(dlx_priority_snapshot(&c, original_ts));
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        /* Every cycle: rebase onto the current tip and ask for the proof
         * ("started"), then a stranger lands on main again before the
         * next step reads the answer, so the receipt is always about a
         * base nobody is on. Before DL_ATTEMPT_MAX capped this specific
         * retry, one drive session could run forever. The bounded session
         * stops, while the original tip retains its claim priority under
         * the new sequence. */
        for (i = 0; i < 8 && !done; i++) {
            char tag[32];
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
            dlx_end(&c);
            (void)snprintf(tag, sizeof(tag), "s%d.txt", i);
            ASSERT(dlx_git(side, branch) == 0);
            ASSERT(dlx_commit(side, tag, "elsewhere\n", stranger));
            ASSERT(dlx_git(side, push) == 0);
            ASSERT(dlx_git(side, back) == 0);
            ASSERT(dlx_git(side, fetch) == 0);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            if (strcmp(dlx_str(&c, "state"), "queued") == 0) {
                ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
                ASSERT_EQ(dlx_int(&c, "seq"), 3);
                ASSERT(strcmp(dlx_str(&c, "tip"), rig.tip) == 0);
                done = true;
            } else {
                ASSERT(strcmp(dlx_str(&c, "state"), "rebased") == 0);
            }
            dlx_end(&c);
        }
        ASSERT(done);
        ASSERT(dlx_priority_successor_status(&c, original_ts));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 3);
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_option_path(void)
{
    int failures = 0;
    TEST("land: a worktree that looks like a git option is refused at "
        "parse, never reaches git") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], mid[64], after[64], landdir[1200], qpath[1400];
        char line[8192], second[64];
        FILE *f;
        dlx_isolate("wtinj");
        ASSERT(dlx_rig_make(&rig, "wtinj_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Land a first row all the way through: this creates the landing
         * worktree, so the crafted row below hits the SAME "fetch the tip
         * from row->worktree" fallback a normal cross-worktree row would
         * (dl_wt_ensure short-circuits on an already-ready d->wt without
         * ever touching row->worktree again), rather than failing earlier
         * for an unrelated reason. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, mid));
        ASSERT(strcmp(mid, before) != 0);
        /* A hand-written row — the shape a foreign write to queue.jsonl
         * can take, never anything dl_submit itself produces — names a git
         * OPTION instead of a path, and a tip nothing here has ever seen.
         * Before the fix this string reached dl_already_landed()'s and
         * dl_rebase()'s fetch calls as a bare positional argument. */
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir);
        (void)snprintf(
            line, sizeof(line),
            "{\"seq\":99,\"ts\":\"2026-01-01T00:00:00Z\","
            "\"tip\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\","
            "\"worktree\":\"--upload-pack=/bin/false\",\"note\":\"\","
            "\"state\":\"queued\",\"phase\":\"\",\"attempt\":1,"
            "\"started\":0,\"base\":\"\",\"local\":\"\","
            "\"tip_pushed\":\"\",\"dimension\":\"\",\"log_path\":\"\","
            "\"detail\":\"\"}\n");
        f = fopen(qpath, "a");
        ASSERT(f != NULL);
        if (f) {
            size_t len = strlen(line);
            ASSERT(fwrite(line, 1, len, f) == len);
            ASSERT(fclose(f) == 0);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        ASSERT_STR_EQ(dlx_err_evidence(&c), "malformed_queue_record_1");
        dlx_end(&c);
        /* Explicit fixture repair is required; a step never erases the
         * foreign row just because its path was unsafe. */
        ASSERT(dlx_write(qpath, ""));
        /* A normal, valid absolute worktree still lands: the parser
         * refuses only the shape it must, not every row that follows it. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, mid) != 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_dependency_links(void)
{
    int failures = 0;
    TEST("land: a dependency link whose only extra name sits in the "
        "leaf's own generation pool is repaired, not refused") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400], gendir[1400], genfile[1400];
        char second[64], exclude[1400];
        struct stat before_st, after_st, gen_st;
        dlx_isolate("gendeplink");
        ASSERT(dlx_rig_make(&rig, "gendeplink_rig"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/libtor.a", "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone, "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        /* The landing worktree now owns its own independent copy of
         * vendor/lib/libfoo.a. Simulate the legacy state item A's fix
         * leaves behind: an older binary once linked a proof generation's
         * materialised copy straight from this exact file, so the two
         * still share an inode -- but the OTHER name lives under this
         * leaf's own disk generation pool (<land>/.z23p/<tag>/...), never
         * under a foreign path, so it is this code's own link to explain
         * and repair rather than a stranger's alias to refuse over. */
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a", wt);
        ASSERT(stat(check, &before_st) == 0 && before_st.st_nlink == 1);
        (void)snprintf(gendir, sizeof(gendir),
                       "%s/.z23p/0123456789abcdef0123456789abcdef/vendor/lib",
                       wt);
        ASSERT(dlx_mkdir_p(gendir));
        (void)snprintf(genfile, sizeof(genfile), "%s/libfoo.a", gendir);
        ASSERT(link(check, genfile) == 0);
        ASSERT(stat(check, &before_st) == 0 && before_st.st_nlink == 2);
        /* dlx_commit() runs `git add -A`; without excluding vendor/ and
         * build/ here the untracked dependency fixtures would be staged
         * and committed, and the landing worktree's later checkout of
         * that commit would overwrite `check` with a fresh blob before
         * this repair ever runs -- silently discarding the very hardlink
         * this test exists to exercise. */
        (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude",
                       rig.clone);
        ASSERT(dlx_write(exclude, "vendor/\nbuild/\n"));
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        /* Repaired, not refused: the attempt proceeds past worktree_deps. */
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        ASSERT(stat(check, &after_st) == 0 && S_ISREG(after_st.st_mode));
        ASSERT(after_st.st_nlink == 1);
        ASSERT(before_st.st_dev != after_st.st_dev ||
              before_st.st_ino != after_st.st_ino);
        /* The generation pool's own copy is untouched: same inode as
         * before, now missing only the landing worktree's name. */
        ASSERT(stat(genfile, &gen_st) == 0 && S_ISREG(gen_st.st_mode));
        ASSERT(gen_st.st_nlink == 1);
        ASSERT(gen_st.st_dev == before_st.st_dev &&
              gen_st.st_ino == before_st.st_ino);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#endif /* !defined(_WIN32) */
