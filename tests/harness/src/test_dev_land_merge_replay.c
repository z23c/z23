/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: integrated merge, preparation, restart, terminal replay and objectives.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


int test_dev_land_integrated_merge(bool signing_failure)
{
    int failures = 0;
    TEST("land: an integrated upstream merge preserves its resolved tree") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], observed[64], landwt[1300], prepared[64], tree[64], base[64];
        const char *checkout[] = { "checkout", "--quiet", "keep-tip", NULL };
        const char *merge[] = { "-c", "user.name=land", "-c",
            "user.email=land@z23.invalid", "merge", "--quiet",
            "-s", "ours", "-m", "resolved integration",
            "origin/main", NULL };
        const char *head[] = { "rev-parse", "HEAD", NULL };
        const char *remote[] = { "rev-parse", "main", NULL };
        const char *ancestor[] = { "merge-base", "--is-ancestor",
            "origin/main", "HEAD", NULL };
        const char *resolved[] = { "show", "HEAD:change.txt", NULL };
        const char *tree_args[] = { "rev-parse", "HEAD^{tree}", NULL };
        const char *base_args[] = { "rev-parse", "origin/main", NULL };
        const char *parent_args[] = { "show", "-s", "--format=%P", "HEAD", NULL };
        const char *signature_args[] = { "log", "-1", "--format=%G?", NULL };
        const char *message_args[] = { "log", "-1", "--format=%B", NULL };
        dlx_isolate(signing_failure ? "merge_signfail" : "integratedmerge");
        ASSERT(dlx_rig_make(&rig, signing_failure ? "merge_signfail_rig" : "integratedmerge_rig"));
        ASSERT(dlx_generated_conflict(&rig, "change.txt", tip));
        ASSERT(dlx_sign_arm(rig.clone, signing_failure ? "merge_signfail_key" : "integratedmerge_sign"));
        ASSERT(dlx_git(rig.clone, checkout) == 0);
        /* Both parents changed the same source. This fixture's explicit
         * resolution keeps the submitted version, then integrates main. */
        ASSERT(dlx_git(rig.clone, merge) == 0);
        ASSERT(dlx_git(rig.clone, ancestor) == 0);
        ASSERT(dlx_git_out(rig.clone, head, tip, sizeof(tip)) == 0);
        ASSERT(dlx_git_out(rig.clone, tree_args, tree, sizeof(tree)) == 0);
        ASSERT(dlx_git_out(rig.clone, base_args, base, sizeof(base)) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        if (signing_failure) {
            const char *broken_signer[] = { "config", "gpg.ssh.program", "false", NULL };
            ASSERT(dlx_git(rig.clone, broken_signer) == 0);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        if (signing_failure) {
            ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
            ASSERT_STR_EQ(dlx_str(&c, "phase"), "rebase");
            ASSERT_STR_EQ(dlx_str(&c, "detail"),
                "cannot prepare a tree-preserving linear landing candidate");
            dlx_end(&c);
            ASSERT(dlx_git_out(rig.bare, remote, observed, sizeof(observed)) == 0);
            ASSERT_STR_EQ(observed, base);
            PASS();
            goto _test_next;
        }
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_STR_EQ(dlx_str(&c, "tip"), tip);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(landwt, head, prepared, sizeof(prepared)) == 0);
        ASSERT(strcmp(prepared, tip) != 0);
        ASSERT(dlx_git_out(landwt, tree_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, tree);
        ASSERT(dlx_git_out(landwt, parent_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, base);
        ASSERT(dlx_git_out(landwt, signature_args, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, "G");
        char message[512], expected[512];
        (void)snprintf(expected, sizeof(expected),
            "Prepare integrated candidate for linear publication\n\n"
            "Original-Candidate: %s\nIntegrated-Base: %s\nSource-Tree: %s",
            tip, base, tree);
        ASSERT(dlx_git_out(landwt, message_args, message, sizeof(message)) == 0);
        ASSERT_STR_EQ(message, expected);
        ASSERT(dlx_git_out(landwt, resolved, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, "mine");
        /* The signed integrated candidate is established. Permit this
         * fixture's stubbed proof through the unsigned publication seam. */
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.bare, remote, observed, sizeof(observed)) == 0);
        ASSERT_STR_EQ(observed, prepared);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Exercise the proof-tools preparation adapter: a cold worktree triggers
 * exactly one docs-proof-tools build, a warm one builds nothing, and both
 * a make failure and a silent no-produce refuse by name. */
int test_dev_land_proof_tools_preparation(void)
{
    int failures = 0;
    TEST("land: proof tools preparation builds the missing checker tools "
        "exactly once") {
        char root[1024], path[1200], body[128], why[512];
        size_t len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "proof_tools");
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@mkdir -p build/bin\n"
            "\t@cp prepared-tool build/bin/z23-lint\n"
            "\t@cp prepared-tool build/bin/z23-fleet-observe\n"
            "\t@cp prepared-tool build/bin/gen_capability_inventory\n"
            "\t@echo built >> build/proof-tools.log\n"));
        ASSERT(dlx_write_dep(root, "prepared-tool", "tool\n"));
        ASSERT(zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT((size_t)snprintf(path, sizeof(path),
                                "%s/build/proof-tools.log", root) <
               sizeof(path));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("built\n"));
        ASSERT(memcmp(body, "built\n", len) == 0);
        /* Warm: every tool present, so no second make runs. */
        ASSERT(zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("built\n"));
        /* A failed make preserves the make failure as the reason. */
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@echo 'FAIL: proof tools refused' >&2\n\t@exit 1\n"));
        (void)remove(path);
        (void)snprintf(path, sizeof(path), "%s/build/bin/z23-fleet-observe",
                       root);
        ASSERT(remove(path) == 0);
        ASSERT(!zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why, "proof tools refused") != NULL);
        /* A make that succeeds without producing a member refuses with the
         * exact dependency the proof would later name. */
        ASSERT(dlx_write_dep(root, "Makefile",
            "docs-proof-tools:\n"
            "\t@mkdir -p build/bin\n"
            "\t@cp prepared-tool build/bin/z23-lint\n"
            "\t@cp prepared-tool build/bin/gen_capability_inventory\n"));
        ASSERT(!zcl_dev_land_proof_tools_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why,
                      "proof_generation_dependency_unavailable:"
                      "build/bin/z23-fleet-observe") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_prepare_log_contains(const char *path, const char *text)
{
    size_t len;
    char *body = calloc(270000, 1);
    if (!body) return false;
    bool ok = dlx_slurp(path, body, 269999, &len) && strstr(body, text) != NULL;
    free(body);
    return ok;
}

static int dlx_prepare_failed_output(void)
{
    int failures = 0;
    TEST("land: failed preparation appends child output to the attempt log") {
        char root[1024], log[1200], why[512];
        test_make_tmpdir(root, sizeof(root), "dev_land", "prepare_output");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        ASSERT(dlx_write_dep(root, "Makefile",
            "broken:\n\t@printf stdout-marker\n\t@printf stderr-marker >&2\n\t@exit 7\n"));
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "broken", 10000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) != 0);
        ASSERT(dlx_prepare_log_contains(log, "target=broken rc="));
        ASSERT(dlx_prepare_log_contains(log, "timed_out=0 elapsed_ms="));
        ASSERT(dlx_prepare_log_contains(log, "possibly_truncated=0"));
        ASSERT(dlx_prepare_log_contains(log, "stdout-markerstderr-marker"));
        ASSERT(dlx_prepare_log_contains(log, "\n--- preparation output end ---\n"));
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "allocation", 10000,
            true, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) == -1);
        ASSERT(dlx_prepare_log_contains(log, "target=allocation rc=-1"));
        ASSERT(dlx_prepare_log_contains(log, "out of memory running make allocation"));
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_prepare_large_input(const char *root)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/large.txt", root);
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < 300000; i++)
        if (fputc('x', f) == EOF) { ok = false; break; }
    return fclose(f) == 0 && ok;
}

static int dlx_prepare_bounded_output(void)
{
    int failures = 0;
    TEST("land: preparation reports saturated capture and real-child timeout") {
        char root[1024], log[1200], why[512];
        test_make_tmpdir(root, sizeof(root), "dev_land", "prepare_bound");
        snprintf(log, sizeof(log), "%s/attempt.log", root);
        ASSERT(dlx_prepare_large_input(root));
        ASSERT(dlx_write_dep(root, "Makefile",
            "large:\n\t@cat large.txt\n\t@exit 1\n"
            "slow:\n\t@printf before-timeout\n\t@sleep 20\n"));
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "large", 10000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) != 0);
        ASSERT(dlx_prepare_log_contains(log, "captured_bytes=262143 possibly_truncated=1"));
        ASSERT(unlink(log) == 0);
        ASSERT(zcl_dev_land_prepare_make_for_test(root, "slow", 5000,
            false, zcl_dev_land_prepare_log_for_test, log, why, sizeof(why)) != 0);
        ASSERT(dlx_prepare_log_contains(log, "timed_out=1"));
        ASSERT(dlx_prepare_log_contains(log, "before-timeout"));
        ASSERT(strstr(why, "timed out"));
        PASS();
    } _test_next:;
    return failures;
}

/* Exercise the actual preparation adapter with an existing stale plan. */
int test_dev_land_final_plan_preparation(void)
{
    int failures = 0;
    failures += dlx_prepare_failed_output();
    failures += dlx_prepare_bounded_output();
    TEST("land: final preparation refreshes an existing plan and preserves make failures") {
        char root[1024], path[1200], body[128], why[512];
        size_t len = 0;
        test_make_tmpdir(root, sizeof(root), "dev_land", "final_plan");
        ASSERT(dlx_write_dep(root, "Makefile",
            ".PHONY: FORCE\nFORCE:\n"
            "build/dev-loop/restart.env: FORCE\n"
            "\t@mkdir -p build/dev-loop\n"
            "\t@cp prepared-input build/dev-loop/restart.env\n"));
        ASSERT(dlx_write_dep(root, "prepared-input", "generation-one\n"));
        ASSERT(zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT(dlx_write_dep(root, "prepared-input", "generation-two\n"));
        ASSERT(zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT((size_t)snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", root) < sizeof(path));
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("generation-two\n"));
        ASSERT(memcmp(body, "generation-two\n", len) == 0);
        ASSERT(dlx_write_dep(root, "Makefile",
            ".PHONY: FORCE\nFORCE:\n"
            "build/dev-loop/restart.env: FORCE\n"
            "\t@echo 'FAIL: final preparation refused' >&2\n\t@exit 1\n"));
        ASSERT(!zcl_dev_land_restart_plan_prepare(root, why, sizeof(why)));
        ASSERT(strstr(why, "final preparation refused") != NULL);
        ASSERT(dlx_slurp(path, body, sizeof(body), &len));
        ASSERT(len == strlen("generation-two\n"));
        ASSERT(memcmp(body, "generation-two\n", len) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_land_explicit_main(void)
{
    int failures = 0;
    TEST("land: observes main even when configured fetch excludes it") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], main_now[64];
        dlx_isolate("main_refspec");
        ASSERT(dlx_rig_make(&rig, "main_refspec_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                base, NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        const char *other[] = { "update-ref", "refs/heads/other", base, NULL };
        const char *cached[] = { "update-ref", "refs/remotes/origin/main",
                                base, NULL };
        const char *mapping[] = { "config", "--replace-all", "remote.origin.fetch",
                                 "refs/heads/other:refs/remotes/origin/other", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_git(rig.bare, other) == 0);
        ASSERT(dlx_git(rig.clone, cached) == 0);
        ASSERT(dlx_git(rig.clone, mapping) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT(strstr(dlx_str(&c, "detail"), "successor queued") != NULL);
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, stranger);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* The candidate edits change.txt. A newer main that edits that same file
 * makes the in-flight proof's base older than the edit. The row is queued
 * again with the proof binding cleared, and it is not landed. */
int test_dev_land_stale_file_retests(void)
{
    int failures = 0;
    TEST("land: a file edited after the tested base is retested before landing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], newer[64];
        dlx_isolate("stale_file");
        ASSERT(dlx_rig_make(&rig, "stale_file_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                base, NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "change.txt", "newer than the proof\n",
                          newer));
        ASSERT(dlx_git(rig.clone, push) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT(strstr(dlx_str(&c, "detail"), "successor queued") != NULL);
        ASSERT_STR_EQ(dlx_str(&c, "proof_intent"), "");
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") != 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_missing_main(void)
{
    int failures = 0;
    TEST("land: missing remote main blocks despite a cached tracking ref") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], main_now[64];
        dlx_isolate("missing_main");
        ASSERT(dlx_rig_make(&rig, "missing_main_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        const char *remove_main[] = { "update-ref", "-d", "refs/heads/main", NULL };
        const char *restore_main[] = { "update-ref", "refs/heads/main", base, NULL };
        ASSERT(dlx_git(rig.bare, remove_main) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(dlx_refusal_serializes(&c));
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(!dlx_origin_main(&rig, main_now));
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
        dlx_end(&c);
        ASSERT(dlx_git(rig.bare, restore_main) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_initial_remote_missing(void)
{
    int failures = 0;
    TEST("land: unavailable remote before initial proof remains retryable") {
        struct dlx_rig rig;
        struct dlx_call c;
        char offline[700];
        dlx_isolate("initial_remote_missing");
        ASSERT(dlx_rig_make(&rig, "initial_remote_missing_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        (void)snprintf(offline, sizeof(offline), "%s.offline", rig.bare);
        ASSERT(rename(rig.bare, offline) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(rename(offline, rig.bare) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT_EQ(dlx_int(&c, "attempt"), 1);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_final_observation_missing(void)
{
    int failures = 0;
    TEST("land: second remote observation failure preserves the proven pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], main_now[64], upload_pack[700];
        char landdir[1200], queue_path[1240], calls_path[740], calls[16];
        char queue_before[16384], queue_after[16384];
        size_t before_len, after_len, calls_len;
        dlx_isolate("prepush_remote_missing");
        ASSERT(dlx_rig_make(&rig, "prepush_remote_missing_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack", rig.bare);
        ASSERT(dlx_write(upload_pack,
            "#!/bin/sh\n"
            "calls=${0}.calls\n"
            "count=0\n"
            "if test -f \"$calls\"; then read -r count < \"$calls\" || exit 70; fi\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$calls\" || exit 70\n"
            "test \"$count\" -ne 2 || exit 75\n"
            "exec git-upload-pack \"$@\"\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.uploadpack",
                                   upload_pack, NULL };
        const char *restore[] = { "config", "--unset", "remote.origin.uploadpack", NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_landdir(landdir, sizeof(landdir));
        (void)snprintf(queue_path, sizeof(queue_path), "%s/queue.jsonl", landdir);
        ASSERT(dlx_slurp(queue_path, queue_before, sizeof(queue_before), &before_len));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        (void)snprintf(calls_path, sizeof(calls_path), "%s.calls", upload_pack);
        ASSERT(dlx_slurp(calls_path, calls, sizeof(calls), &calls_len));
        ASSERT_EQ(calls_len, 2);
        ASSERT(memcmp(calls, "2\n", 2) == 0);
        ASSERT(dlx_slurp(queue_path, queue_after, sizeof(queue_after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(queue_before, queue_after, before_len) == 0);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, base);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "prove");
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), base);
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "attempt"), 1);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_lost_persistence(void)
{
    int failures = 0;
    TEST("land: a queue-commit failure after a real push is reported, "
        "not silently claimed, and the row self-heals") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], hook[1400], script[1600], before[64], after[64];
        dlx_isolate("persistfail");
        ASSERT(dlx_rig_make(&rig, "persistfail_rig"));
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
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_landdir(landdir, sizeof(landdir));
        /* Lose the outcome write only after the exact push pair has been
         * durably prepared. Git's pre-push hook runs after that checkpoint. */
        ASSERT((size_t)snprintf(hook, sizeof(hook), "%s/pre-push",
                                g_dlx_hooks_ok) < sizeof(hook));
        ASSERT((size_t)snprintf(script, sizeof(script),
            "#!/bin/sh\nchmod 0500 '%s'\n", landdir) < sizeof(script));
        ASSERT(dlx_write(hook, script) && chmod(hook, 0755) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        ASSERT(strcmp(dlx_str(&c, "persist"), "failed") == 0);
        dlx_end(&c);
        /* The push already happened for real: origin/main moved even
         * though the queue could not record it. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT(chmod(landdir, 0700) == 0);
        /* A cached origin/main still contains the pushed commit when the
         * remote disappears. It cannot establish a fresh observation:
         * retain the inflight row, then reconcile after access returns. */
        char offline[700];
        (void)snprintf(offline, sizeof(offline), "%s.offline", rig.bare);
        ASSERT(rename(rig.bare, offline) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT(strcmp(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE") == 0);
        ASSERT(c.reply.error.retryable);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        ASSERT(rename(offline, rig.bare) == 0);
        /* Recoverable: a later step finds the tip is already an ancestor
         * of origin/main and records it landed without pushing again. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        ASSERT(dlx_str(&c, "persist")[0] == '\0');
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "empty") == 0);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

/* A finished proof is separate from the landing verdict. Kill a step after
 * it observes PASS, before it can push or persist a phase change. The next
 * process must consume the same exact row and finish once. The test-only
 * proof stub supplies PASS; this tests landing recovery, not proof validity. */
int test_dev_land_after_proof_restart(void)
{
    int failures = 0;
    TEST("land: death after proof PASS before verdict preserves the row for restart") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], landdir[1200], qpath[1400];
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        int child_status = 0;
        dlx_isolate("after_proof_restart");
        ASSERT(dlx_rig_make(&rig, "after_proof_restart_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "running", 1) == 0);
        ASSERT(setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1) == 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(dlx_slurp(qpath, before, sizeof(before), &before_len));
        ASSERT(setenv("ZCL_LAND_PROOF_STUB", "pass", 1) == 0);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            (void)setenv("ZCL_LAND_TEST_DIE_AFTER_PROOF", "1", 1);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(waitpid(child, &child_status, 0) == child);
        ASSERT(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 82);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        ASSERT(dlx_slurp(qpath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(after, before, before_len) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_mail_outcome_found(const char *tip);

int test_dev_land_terminal_replay(void)
{
    int failures = 0;
    TEST("land: failed outcome append keeps the pushed row reclaimable") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], qpath[1400], maildir[1400];
        char opath[1400], queue[8192], outcome[8192];
        char remote[64];
        size_t queue_len, outcome_len;
        dlx_isolate("outcome_append_failure");
        ASSERT(dlx_rig_make(&rig, "outcome_append_failure_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(maildir, sizeof(maildir), "%s/../mail", landdir) <
               (int)sizeof(maildir));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND", "1", 1);
        setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
        unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
        ASSERT(dlx_write(maildir, "not a mail directory"));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, outcome, sizeof(outcome), &outcome_len));
        ASSERT(outcome_len > 0);
        /* The landed outcome carries the landing instant; ts is the submit time. */
        ASSERT(strstr(outcome, "\"state\":\"landed\"") != NULL);
        ASSERT(strstr(outcome, "\"landed_at\":") != NULL);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        ASSERT(unlink(maildir) == 0 && mkdir(maildir, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        char again[8192];
        size_t again_len;
        ASSERT(dlx_slurp(opath, again, sizeof(again), &again_len));
        ASSERT_EQ(again_len, outcome_len);
        ASSERT(memcmp(again, outcome, outcome_len) == 0);
        ASSERT(dlx_mail_outcome_found(rig.tip));
        dlx_restore();
        PASS();
    }

    TEST("land: death after outcome append replays once without another push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], opath[1400], qpath[1400], before[8192];
        char after[8192], queue[8192], remote[64];
        size_t before_len, after_len, queue_len;
        int child_status = 0;
        dlx_isolate("outcome_replay_death");
        ASSERT(dlx_rig_make(&rig, "outcome_replay_death_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            (void)setenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME", "1", 1);
            (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(waitpid(child, &child_status, 0) == child);
        ASSERT(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 81);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(opath, before, sizeof(before), &before_len));
        ASSERT(before_len > 0);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "TERMINAL_REPLAY_PENDING");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        /* A terminal receipt for the same request but another proof base
         * cannot authorize replay or silently replace the candidate. */
        char bad_pair[sizeof(before)];
        ASSERT(before_len + 1 < sizeof(bad_pair));
        memcpy(bad_pair, before, before_len);
        bad_pair[before_len] = '\0';
        char *base = strstr(bad_pair, "\"base\":\"");
        ASSERT(base != NULL);
        base += strlen("\"base\":\"");
        ASSERT(strlen(base) >= 40);
        base[0] = base[0] == 'a' ? 'b' : 'a';
        ASSERT(dlx_write(opath, bad_pair));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        before[before_len] = '\0';
        ASSERT(dlx_write(opath, before));
        /* A second terminal claim for this exact request is not a
         * "latest wins" verdict. Preserve the queue and name the conflict. */
        char conflicting[sizeof(before) * 2];
        ASSERT(before_len * 2 + 1 < sizeof(conflicting));
        memcpy(conflicting, before, before_len);
        memcpy(conflicting + before_len, before, before_len);
        conflicting[before_len * 2] = '\0';
        char *state = strstr(conflicting + before_len, "\"state\":\"landed\"");
        ASSERT(state != NULL);
        memcpy(state + strlen("\"state\":\""), "failed", 6);
        ASSERT(dlx_write(opath, conflicting));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "QUEUE_READ_FAILED");
        dlx_end(&c);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT(queue_len > 0);
        before[before_len] = '\0';
        ASSERT(dlx_write(opath, before));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, after, sizeof(after), &after_len));
        ASSERT_EQ(after_len, before_len);
        ASSERT(memcmp(after, before, before_len) == 0);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

/* ── the objectives snapshot (native_dev_land_objectives.c) ──────────────
 *
 * Every landed outcome appends one line to <land>/objectives.jsonl, written
 * from the same outcome path that appends outcomes.jsonl and posts the mail
 * note. The checks below read the producer's catalog rather than a copy of
 * it, so a new objective row cannot leave this test behind. */

static const char *dlx_snap_str(const struct json_value *v)
{
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

static bool dlx_snapshot_bad(const char *what, const char *id)
{
    printf("[objectives snapshot: %s %s] ", what, id);
    return false;
}

static const struct json_value *dlx_snapshot_row(const struct json_value *rows,
                                                 const char *id)
{
    for (size_t i = 0; rows && i < rows->num_children; i++)
        if (strcmp(dlx_snap_str(json_get(&rows->children[i], "id")), id) == 0)
            return &rows->children[i];
    return NULL;
}

/* One row's value fields: a number with its verdict and no reason, or null
 * with null verdict and a reason. */
static bool dlx_snapshot_value_ok(const struct json_value *r,
                                  const struct zcl_objective_row *cat)
{
    const struct json_value *value = json_get(r, "value");
    const struct json_value *met = json_get(r, "met");
    bool has_reason = dlx_snap_str(json_get(r, "reason"))[0] != '\0';
    if (value && value->type == JSON_INT) {
        int64_t v = json_get_int(value);
        bool want = strcmp(cat->direction, "max") == 0 ? v >= cat->target
                                                        : v <= cat->target;
        return met && met->type == JSON_BOOL && json_get_bool(met) == want &&
               !has_reason;
    }
    return value && value->type == JSON_NULL && met &&
           met->type == JSON_NULL && has_reason;
}

/* Every catalog row, in catalog order, with the catalog's own target and
 * direction. */
static bool dlx_snapshot_rows_ok(const struct json_value *rows)
{
    const struct zcl_objective_row *catalog;
    size_t n = zcl_objectives_catalog(&catalog);
    if (!rows || rows->type != JSON_ARR || rows->num_children != n)
        return dlx_snapshot_bad("row count", "");
    for (size_t i = 0; i < n; i++) {
        const struct json_value *r = &rows->children[i];
        if (strcmp(dlx_snap_str(json_get(r, "id")), catalog[i].id) != 0 ||
            json_get_int(json_get(r, "target")) != catalog[i].target ||
            strcmp(dlx_snap_str(json_get(r, "direction")),
                   catalog[i].direction) != 0)
            return dlx_snapshot_bad("catalog mismatch", catalog[i].id);
        if (!dlx_snapshot_value_ok(r, &catalog[i]))
            return dlx_snapshot_bad("value fields", catalog[i].id);
    }
    return true;
}

/* The snapshot names the landed outcome row: its seq, tip and landing instant. */
static bool dlx_snapshot_header_ok(const struct json_value *doc,
                                   const struct json_value *row)
{
    int64_t ts = json_get_int(json_get(doc, "ts"));
    return strcmp(dlx_snap_str(json_get(doc, "schema")),
                  "zcl.objectives_snapshot.v1") == 0 &&
           strcmp(dlx_snap_str(json_get(row, "state")), "landed") == 0 &&
           json_get_int(json_get(doc, "seq")) ==
               json_get_int(json_get(row, "seq")) &&
           strcmp(dlx_snap_str(json_get(doc, "tip")),
                  dlx_snap_str(json_get(row, "tip"))) == 0 &&
           ts > 0 && ts == json_get_int(json_get(row, "landed_at"));
}

/* Read from this queue's own outcomes.jsonl, which holds the one landed row. */
static bool dlx_snapshot_outcomes_ok(const struct json_value *rows)
{
    const struct json_value *today =
        dlx_snapshot_row(rows, "landed_rows_today");
    const struct json_value *rate =
        dlx_snapshot_row(rows, "land_success_rate_7d");
    bool ok = today && rate && json_get_int(json_get(today, "value")) == 1 &&
              !json_get_bool(json_get(today, "met")) &&
              json_get_int(json_get(rate, "value")) == 100 &&
              json_get_bool(json_get(rate, "met"));
    return ok ? true : dlx_snapshot_bad("outcomes readers", "landed_rows_today");
}

/* The paths the lander hands the producer, named by its own reasons: the
 * landing worktree's proof attempts, lint families and complexity baseline,
 * never the working directory's. */
static bool dlx_snapshot_wired_ok(const struct json_value *rows,
                                  const char *landdir)
{
    static const struct {
        const char *id;
        const char *tail;
    } wired[] = {
        {"proof_lint_wall_s", "/wt/.cache/zcl-dev-proof/attempts"},
        {"lint_families_over_ceiling", "/wt/tools/lint/lintc"},
        {"functions_over_complexity_cap",
         "/wt/tools/lint/cyclomatic_complexity_baseline.txt"},
    };
    char want[1700];
    for (size_t i = 0; i < sizeof(wired) / sizeof(wired[0]); i++) {
        const struct json_value *r = dlx_snapshot_row(rows, wired[i].id);
        (void)snprintf(want, sizeof(want), "%s%s", landdir, wired[i].tail);
        if (!r || !strstr(dlx_snap_str(json_get(r, "reason")), want))
            return dlx_snapshot_bad("producer path", wired[i].id);
    }
    return true;
}

/* `snap` is exactly one newline-terminated line that parses as a snapshot of
 * the landed outcome row in `outcome`. */
static bool dlx_snapshot_matches(const char *snap, size_t snap_len,
                                 const char *outcome, size_t outcome_len,
                                 const char *landdir)
{
    struct json_value doc, row;
    const struct json_value *rows;
    bool ok = snap_len > 1 && snap[snap_len - 1] == '\n' &&
              memchr(snap, '\n', snap_len) == snap + snap_len - 1;
    json_init(&doc);
    json_init(&row);
    ok = ok && json_read(&doc, snap, snap_len - 1) &&
         json_read(&row, outcome, outcome_len) &&
         dlx_snapshot_header_ok(&doc, &row);
    if (!ok)
        (void)dlx_snapshot_bad("header", "does not match the outcome row");
    rows = json_get(&doc, "objectives");
    ok = ok && dlx_snapshot_rows_ok(rows) && dlx_snapshot_outcomes_ok(rows) &&
         dlx_snapshot_wired_ok(rows, landdir);
    json_free(&row);
    json_free(&doc);
    return ok;
}

/* The first step starts a held proof; the land state is ready after it. */
static bool dlx_snapshot_start(struct dlx_rig *rig, const char *tag,
                               char *landdir, size_t cap)
{
    struct dlx_call c;
    char rigtag[64];
    bool ok;
    dlx_isolate(tag);
    (void)snprintf(rigtag, sizeof(rigtag), "%s_rig", tag);
    if (!dlx_rig_make(rig, rigtag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
         strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    dlx_landdir(landdir, cap);
    return ok;
}

int test_dev_land_objectives_snapshot(void)
{
    int failures = 0;
    TEST("land: a landed outcome appends one objectives snapshot, once across a mail retry") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], opath[1400], spath[1400], maildir[1400];
        char outcome[8192], snap[16384], again[16384];
        size_t outcome_len, snap_len, again_len;
        ASSERT(dlx_snapshot_start(&rig, "objectives_snapshot", landdir,
                                  sizeof(landdir)));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(spath, sizeof(spath), "%s/objectives.jsonl", landdir) <
               (int)sizeof(spath));
        ASSERT(snprintf(maildir, sizeof(maildir), "%s/../mail", landdir) <
               (int)sizeof(maildir));
        ASSERT(access(spath, F_OK) != 0);
        /* The mail post fails after the outcome is durable, so the next two
         * steps replay the recorded row: none may sense it again. */
        ASSERT(dlx_write(maildir, "not a mail directory"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, outcome, sizeof(outcome), &outcome_len));
        ASSERT(dlx_slurp(spath, snap, sizeof(snap), &snap_len));
        ASSERT(dlx_snapshot_matches(snap, snap_len, outcome, outcome_len,
                                    landdir));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "failed");
        dlx_end(&c);
        ASSERT(unlink(maildir) == 0 && mkdir(maildir, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "");
        dlx_end(&c);
        ASSERT(dlx_slurp(spath, again, sizeof(again), &again_len));
        ASSERT_EQ(again_len, snap_len);
        ASSERT(memcmp(again, snap, snap_len) == 0);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_objectives_append_blocked(void)
{
    int failures = 0;
    TEST("land: a snapshot that cannot be appended is logged and the landing stands") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], opath[1400], spath[1400], qpath[1400];
        char logpath[1400], remote[64], outcome[8192], queue[8192];
        char log[65536];
        size_t outcome_len, queue_len, log_len;
        struct stat st;
        ASSERT(dlx_snapshot_start(&rig, "objectives_blocked", landdir,
                                  sizeof(landdir)));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(spath, sizeof(spath), "%s/objectives.jsonl", landdir) <
               (int)sizeof(spath));
        ASSERT(snprintf(qpath, sizeof(qpath), "%s/queue.jsonl", landdir) <
               (int)sizeof(qpath));
        ASSERT(snprintf(logpath, sizeof(logpath), "%s/logs/land-1-a1.log",
                        landdir) < (int)sizeof(logpath));
        /* A directory where the snapshot file belongs: open() cannot append. */
        ASSERT(mkdir(spath, 0700) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "persist"), "");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        ASSERT(dlx_slurp(opath, outcome, sizeof(outcome), &outcome_len));
        ASSERT(strstr(outcome, "\"state\":\"landed\"") != NULL);
        ASSERT(dlx_slurp(qpath, queue, sizeof(queue), &queue_len));
        ASSERT_EQ(queue_len, 0);
        ASSERT(stat(spath, &st) == 0 && S_ISDIR(st.st_mode));
        ASSERT(dlx_slurp(logpath, log, sizeof(log) - 1, &log_len));
        log[log_len] = '\0';
        ASSERT(strstr(log, "objectives snapshot not recorded for seq 1: "
                           "cannot append the snapshot line") != NULL);
        ASSERT(strstr(log, spath) != NULL);
        dlx_restore();
        PASS();
    }

_test_next:;
    return failures;
}

int test_dev_land_objectives_failed_outcome(void)
{
    int failures = 0;
    TEST("land: a failed outcome appends no objectives snapshot") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], opath[1400], spath[1400], outcome[8192];
        size_t outcome_len;
        ASSERT(dlx_snapshot_start(&rig, "objectives_failed", landdir,
                                  sizeof(landdir)));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(opath));
        ASSERT(snprintf(spath, sizeof(spath), "%s/objectives.jsonl", landdir) <
               (int)sizeof(spath));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
        dlx_end(&c);
        ASSERT(dlx_slurp(opath, outcome, sizeof(outcome), &outcome_len));
        ASSERT(strstr(outcome, "\"state\":\"failed\"") != NULL);
        ASSERT(access(spath, F_OK) != 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

pid_t dlx_wait_child(pid_t child, int *status)
{
    pid_t waited;
    do { waited = waitpid(child, status, 0); } while (waited < 0 && errno == EINTR);
    return waited;
}

/* A publisher killed mid-push by the remote's post-receive hook leaves its
 * Git descendants running: the orphaned `git push` still reads the remote's
 * report and then updates the landing worktree's refs/remotes/origin/main.
 * A recovery step that starts before they exit races that ref update — its
 * own fetch cannot lock the ref, and the lander correctly answers
 * REMOTE_OBSERVATION_UNAVAILABLE (retryable) — so the case would be judging
 * scheduling, not recovery. The publisher child calls setsid() first, so
 * every process it started stays in its session; after reaping it, wait
 * until that session has no member left: exactly when its work has ended.
 * The group watchdog bounds a descendant that never exits. */
pid_t dlx_wait_publisher(pid_t publisher, int *status)
{
    pid_t waited = dlx_wait_child(publisher, status);
    while (waited == publisher &&
           zcl_devloop_process_session_members(publisher, 0) > 0) {
        struct timespec pause = { 0, 10 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: other processes' exit */
    }
    return waited;
}

bool dlx_resume_after_death(void)
{
    struct dlx_call c;
    (void)alarm(30);
    for (unsigned retry = 0; retry < 100; ++retry) {
        dlx_begin(&c, "step");
        bool ran = dlx_run(&c);
        bool ok = ran && dlx_ok(&c) &&
            strcmp(dlx_str(&c, "state"), "landed") == 0;
        bool busy = ran && strcmp(dlx_err_code(&c), "STEP_BUSY") == 0;
        dlx_end(&c);
        if (!busy) return ok;
        struct timespec pause = { 0, 10 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: STEP_BUSY is another process's flock; no fake-clock seam reaches its release. */
    }
    return false;
}

/* ── land outcomes stay visible in agent mail ────────────────────────────
 *
 * The land leaf reports queued/phase/outcome rows through the mail leaf so
 * agents learn results by pulling. A raw append once wrote rows the mail
 * parser could not read (no to/body, kind outside the mail set, land-queue
 * seq colliding with the outbox seq space): every pull skipped them while
 * the global cursor stood still. This test drives a real submit and pulls
 * the outcome back by tip. */

struct dlx_mail_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlx_mail_begin(struct dlx_mail_call *m)
{
    json_init(&m->input);
    json_set_object(&m->input);
    memset(&m->request, 0, sizeof(m->request));
    m->request.input = &m->input;
    m->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "dev.agent.mail",
                                  NULL);
    zcl_command_reply_init(&m->reply, "zcl.agent_mail.v1");
}

static void dlx_mail_end(struct dlx_mail_call *m)
{
    zcl_command_reply_free(&m->reply);
    json_free(&m->input);
}

static bool dlx_mail_ok(const struct dlx_mail_call *m)
{
    return m->request.spec != NULL &&
        m->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool dlx_mail_post(const char *to, const char *kind, const char *body,
                          const char *ref, const char *from)
{
    struct dlx_mail_call m;
    bool ok;
    dlx_mail_begin(&m);
    ok = json_push_kv_str(&m.input, "action", "post") &&
         json_push_kv_str(&m.input, "to", to) &&
         json_push_kv_str(&m.input, "kind", kind) &&
         json_push_kv_str(&m.input, "body", body) &&
         json_push_kv_str(&m.input, "ref", ref) &&
         json_push_kv_str(&m.input, "from", from);
    if (ok)
        zcl_native_handle_dev_agent_mail(&m.request, &m.reply);
    ok = ok && dlx_mail_ok(&m);
    dlx_mail_end(&m);
    return ok;
}

static bool dlx_mail_str_eq(const struct json_value *obj, const char *key,
                            const char *want)
{
    const struct json_value *v = json_get(obj, key);
    return v && v->type == JSON_STR && json_get_str(v) &&
        strcmp(json_get_str(v), want) == 0;
}

/* One pulled row is the wanted land note; records its seq. */
static bool dlx_mail_row_match(const struct json_value *row, const char *from,
                               const char *kind, const char *ref,
                               long long *seq)
{
    const struct json_value *v;
    if (!dlx_mail_str_eq(row, "from", from))
        return false;
    if (!dlx_mail_str_eq(row, "kind", kind))
        return false;
    if (!dlx_mail_str_eq(row, "ref", ref))
        return false;
    v = json_get(row, "seq");
    if (v && v->type == JSON_INT)
        *seq = json_get_int(v);
    return true;
}

/* One page's rows into the match accumulator. */
static void dlx_mail_page_scan(const struct json_value *rows, const char *from,
                               const char *kind, const char *ref,
                               long long *seq, bool *found)
{
    size_t n;
    if (!rows || rows->type != JSON_ARR)
        return;
    n = rows->num_children;
    for (size_t i = 0; i < n; i++) {
        if (dlx_mail_row_match(&rows->children[i], from, kind, ref, seq))
            *found = true;
    }
}

/* The token resuming the next page into *more. False when a further page
 * exists but its token does not fit: fail closed instead of re-reading
 * one page. */
static bool dlx_mail_advance(const struct zcl_command_reply *reply,
                             bool *more, char *since, size_t cap)
{
    const struct json_value *tok, *tr;
    tr = json_get(&reply->data, "truncated");
    *more = tr && tr->type == JSON_BOOL && json_get_bool(tr);
    if (!*more)
        return true;
    tok = json_get(&reply->data, "next_since");
    if (!tok || tok->type != JSON_STR || !json_get_str(tok) ||
        strlen(json_get_str(tok)) >= cap)
        return false;
    (void)snprintf(since, cap, "%s", json_get_str(tok));
    return true;
}

/* One pull page at `since`: sums its skipped count, scans its rows, and
 * advances the cursor. */
struct dlx_mail_page {
    bool ok;
    bool more;
    long long skipped;
};

static void dlx_mail_page(struct dlx_mail_page *pg, const char *since,
                          const char *from, const char *kind, const char *ref,
                          long long *seq, bool *found, char *next, size_t cap)
{
    struct dlx_mail_call m;
    const struct json_value *rows, *sk;
    pg->ok = false;
    pg->more = false;
    pg->skipped = 0;
    dlx_mail_begin(&m);
    pg->ok = json_push_kv_str(&m.input, "action", "pull") &&
             json_push_kv_str(&m.input, "since", since);
    if (pg->ok)
        zcl_native_handle_dev_agent_mail(&m.request, &m.reply);
    pg->ok = pg->ok && dlx_mail_ok(&m);
    if (!pg->ok) {
        dlx_mail_end(&m);
        return;
    }
    sk = json_get(&m.reply.data, "skipped");
    if (sk && sk->type == JSON_INT)
        pg->skipped = json_get_int(sk);
    rows = json_get(&m.reply.data, "rows");
    dlx_mail_page_scan(rows, from, kind, ref, seq, found);
    pg->ok = dlx_mail_advance(&m.reply, &pg->more, next, cap);
    dlx_mail_end(&m);
}

/* Drain every pull page following next_since. Sets *found when one row
 * matches from/kind/ref, *seq to that row's seq, and *skipped to the summed
 * skipped count across pages. */
static bool dlx_mail_find(const char *from, const char *kind, const char *ref,
                          long long *seq, long long *skipped, bool *found)
{
    char since[4096] = "0";
    char next[4096] = "0";
    *found = false;
    *skipped = 0;
    for (int page = 0; page < 64; page++) {
        struct dlx_mail_page pg;
        dlx_mail_page(&pg, since, from, kind, ref, seq, found, next,
                      sizeof(next));
        if (!pg.ok)
            return false;
        *skipped += pg.skipped;
        if (!pg.more)
            return true;
        (void)snprintf(since, sizeof(since), "%s", next);
    }
    return false;
}

static bool dlx_mail_outcome_found(const char *tip)
{
    long long seq = -1, skipped = -1;
    bool found = false;
    return dlx_mail_find("dev.land", "note", tip, &seq, &skipped, &found) &&
           found && seq > 0 && skipped == 0;
}

int test_dev_land_outcome_visible_in_mail(void)
{
    int failures = 0;
    TEST("land: a submitted outcome posts through the mail leaf and pulls back by tip") {
        struct dlx_rig rig;
        struct dlx_call c;
        long long seq = -1, skipped = -1;
        bool found = false;
        dlx_isolate("mailvisible");
        ASSERT(dlx_rig_make(&rig, "mailvisible_rig"));
        /* The mail dir pre-exists on every real host (receiver/steer
         * activity); establish it here through the mail leaf itself, the
         * way production does. */
        ASSERT(dlx_mail_post("*", "note", "seed", "seed", "test"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_mail_find("dev.land", "note", rig.tip, &seq, &skipped,
                             &found));
        ASSERT(found);
        /* Mail-allocated seq after the seed row, never the land queue's
         * own seq 1 colliding with the outbox seq space. */
        ASSERT_EQ(seq, 2);
        /* Nothing in the store is skipped as malformed: every row parses. */
        ASSERT_EQ(skipped, 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#endif /* !defined(_WIN32) */
