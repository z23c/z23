/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: vendor dependencies, tree types, source binding and watcher admission.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


static int test_dev_land_attach_target_ambiguous(void)
{
    int failures = 0;
    TEST("land: attach without seq refuses two proven rows and lists both") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_target_ambiguous");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_target_ambiguous", base));
        ASSERT(dlx_duplicate_proven_row());
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_AMBIGUOUS");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "candidates=1,2") != NULL);
        const struct json_value *cands = dlx_arr(&c, "candidates");
        ASSERT(cands && cands->num_children == 2);
        ASSERT(json_get_int(&cands->children[0]) == 1);
        ASSERT(json_get_int(&cands->children[1]) == 2);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        /* An explicit seq still wins over the ambiguity. */
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        ASSERT_STR_EQ(dlx_str(&c, "target"), "explicit");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_target_cases(void)
{
    int failures = 0;
    failures += test_dev_land_blocked_names_attach_target();
    failures += test_dev_land_attach_resolves_single_row();
    failures += test_dev_land_attach_publish_one_window();
    failures += test_dev_land_attach_publish_exact_pair();
    failures += test_dev_land_attach_publish_malformed_pair();
    failures += test_dev_land_attach_publish_wait_expires();
    failures += test_dev_land_attach_publish_wait_failure();
    failures += test_dev_land_attach_publish_wait_busy();
    failures += test_dev_land_attach_publish_moved_base();
    failures += test_dev_land_attach_publish_push_checkpoint();
    failures += test_dev_land_cancel_push_checkpoint();
    failures += test_dev_land_attach_target_none();
    failures += test_dev_land_attach_explicit_unattachable();
    failures += test_dev_land_attach_target_ambiguous();
    return failures;
}

/* Model a damaged local projection, while the proof stub deliberately admits
 * the pair. The real client must still enforce ancestry before dispatch. */
static bool dlx_replace_prepared_candidate(const char *ancestor)
{
    char land[1200], wt[1400], path[1400], wire[8192], divergent[64];
    size_t length;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, sizeof(wt), "%s/wt", land);
    const char *commit[] = { "-c", "user.name=land", "-c",
        "user.email=land@z23.invalid", "commit-tree", "HEAD^{tree}",
        "-p", ancestor, "-m", "divergent prepared candidate", NULL };
    if (dlx_git_out(wt, commit, divergent, sizeof(divergent)) != 0 ||
        strlen(divergent) != 40)
        return false;
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, wire, sizeof(wire), &length)) return false;
    wire[length] = '\0';
    char *local = strstr(wire, "\"local\":\"");
    if (!local || strlen(local + 9) < 41 || local[49] != '"') return false;
    memcpy(local + 9, divergent, 40);
    return dlx_write(path, wire);
}

int test_dev_land_nonfastforward_client_guard(void)
{
    int failures = 0;
    TEST("land: expected-base comparison never authorizes non-fast-forward dispatch") {
        struct dlx_rig rig;
        struct dlx_call c;
        char ancestor[64], base[64], after[64], wrapper[700], marker[700];
        char first_log[1400];
        dlx_isolate("nonfastforward_client");
        ASSERT(dlx_rig_make(&rig, "nonfastforward_client_rig"));
        ASSERT(dlx_origin_main(&rig, ancestor));
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", rig.tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        (void)snprintf(first_log, sizeof(first_log), "%s", dlx_str(&c, "log_path"));
        dlx_end(&c);
        ASSERT(dlx_replace_prepared_candidate(ancestor));
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/push-invoked", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' > \"$1/hooks/push-invoked\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_file_exists(marker));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, base);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "attempt")), 2);
        char log[8192];
        size_t log_length;
        ASSERT(dlx_slurp(first_log, log, sizeof(log), &log_length));
        log[log_length] = '\0';
        ASSERT(strstr(log, "proven base is not an ancestor of candidate") != NULL);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_expected_base_race(void)
{
    int failures = 0;
    TEST("land: a fast-forward push still requires the proven remote base") {
        struct dlx_rig rig;
        struct dlx_call c;
        char ancestor[64], after[64], wrapper[700], marker[700], script[1800];
        dlx_isolate("expected_base_race");
        ASSERT(dlx_rig_make(&rig, "expected_base_race_rig"));
        ASSERT(dlx_origin_main(&rig, ancestor));
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, push) == 0);
        char base[64];
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", rig.tip));
        const char *protect[] = { "config", "receive.denyNonFastForwards", "true", NULL };
        ASSERT(dlx_git(rig.bare, protect) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/base-rewound", rig.bare);
        (void)snprintf(script, sizeof(script),
            "#!/bin/sh\n"
            "git -C \"$1\" update-ref refs/heads/main %s %s || exit 73\n"
            "printf 'rewound\\n' > \"$1/hooks/base-rewound\" || exit 74\n"
            "exec git-receive-pack \"$@\"\n", ancestor, base);
        ASSERT(dlx_write(wrapper, script));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_file_exists(marker));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, ancestor);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(json_get_int(json_get(&c.reply.data, "attempt")), 2);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_recovery_ignores_replace_refs(void)
{
    int failures = 0;
    TEST("land: restart cannot mistake a replaced remote commit for publication") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64], land[1200], wt[1400];
        char tree[64], forged[64], body[64];
        dlx_isolate("recovery_replace_ref");
        ASSERT(dlx_rig_make(&rig, "recovery_replace_ref_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);

        /* A competing integrator moves the real remote to a sibling tip.
         * A local replacement object lies about that tip's parent. This
         * simulates recovery after the persisted prove phase, not a push. */
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base, NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_landdir(land, sizeof(land));
        (void)snprintf(wt, sizeof(wt), "%s/wt", land);
        const char *tree_args[] = { "rev-parse", "HEAD^{tree}", NULL };
        ASSERT(dlx_git_out(rig.clone, tree_args, tree, sizeof(tree)) == 0);
        const char *forge[] = { "-c", "user.name=land", "-c",
            "user.email=land@z23.invalid", "commit-tree", tree,
            "-p", rig.tip, "-m", "false local ancestry", NULL };
        ASSERT(dlx_git_out(wt, forge, forged, sizeof(forged)) == 0);
        const char *replace[] = { "replace", stranger, forged, NULL };
        ASSERT(dlx_git(wt, replace) == 0);
        const char *apparent[] = { "merge-base", "--is-ancestor",
            rig.tip, stranger, NULL };
        const char *actual[] = { "--no-replace-objects", "merge-base",
            "--is-ancestor", rig.tip, stranger, NULL };
        ASSERT(dlx_git(wt, apparent) == 0);
        ASSERT(dlx_git(wt, actual) == 1);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);

        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);

        /* Keep the misleading local ref in place. The persisted request
         * must still replay the candidate onto the real sibling and land
         * its bytes, not converge to an empty rebase of the fake history. */
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        const char *show[] = { "show", "main:change.txt", NULL };
        ASSERT(dlx_git_out(rig.bare, show, body, sizeof(body)) == 0);
        ASSERT_STR_EQ(body, "one");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_postpush_result_unconfirmed(void)
{
    int failures = 0;
    TEST("land: reachable remote must still contain the pushed candidate") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hook[700], marker[700], received[80];
        size_t received_len;
        dlx_isolate("postpush_result_unconfirmed");
        ASSERT(dlx_rig_make(&rig, "postpush_result_unconfirmed_rig"));
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
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/received-tip", rig.bare);
        ASSERT(dlx_write(hook,
            "#!/bin/sh\n"
            "read -r old new ref || exit 73\n"
            "test \"$ref\" = refs/heads/main || exit 74\n"
            "printf '%s\\n' \"$new\" > hooks/received-tip || exit 75\n"
            "git update-ref \"$ref\" \"$old\" \"$new\"\n"));
        ASSERT(chmod(hook, 0700) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, strlen(rig.tip) + 1);
        ASSERT(memcmp(received, rig.tip, strlen(rig.tip)) == 0);
        ASSERT(received[received_len - 1] == '\n');
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_RESULT_UNCONFIRMED");
        ASSERT(dlx_refusal_serializes(&c));
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), 1);
        dlx_end(&c);
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#endif /* !defined(_WIN32) */

#if !defined(_WIN32)
int test_dev_land_vendor_dependencies(void)
{
    int failures = 0;
    TEST("land: the landing worktree gets the proof's vendored "
        "dependencies from the submitting checkout") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400], source[1400], exclude[1400];
        char abandoned[1500];
        char alias_dir[512], alias[700];
        char aaa_source[1400], aaa_target[1400], aaa_bytes[2][8] = {{0}};
        char second[64], third[64], bytes[3][8] = {{0}};
        struct stat st, source_st, landed_st, alias_st;
        FILE *file;
        dlx_isolate("depsok");
        ASSERT(dlx_rig_make(&rig, "depsok_rig"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/sqlite3.c", "sqlite\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/.provenance", "stamp\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/tor/Makefile", "CC=gcc\n"));
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libfoo.a", "fake\n"));
        (void)snprintf(source, sizeof(source), "%s/vendor/lib/libfoo.a",
                       rig.clone);
        const struct timespec pinned[2] = {
            { .tv_sec = 1700000000, .tv_nsec = 123456789 },
            { .tv_sec = 1700000000, .tv_nsec = 123456789 },
        };
        ASSERT(chmod(source, 0640) == 0);
        ASSERT(utimensat(AT_FDCWD, source, pinned, 0) == 0);
        ASSERT(stat(source, &source_st) == 0 && S_ISREG(source_st.st_mode));
        ASSERT(dlx_write_dep(rig.clone, "vendor/include/foo.h", "fake\n"));
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
        /* Forces dl_wt_vendor_ensure()/dl_wt_hotswap_ensure() to run for
         * real even though ZCL_LAND_PROOF_STUB replaces the proof itself —
         * see dl_deps_test_force()'s comment in native_dev_land.c. The
         * hooks refresh shares the forced prerequisite set, so the
         * submitting checkout also carries a hook binary to install from. */
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
        /* Every dependency the proof's own dependencies[] array names (the
         * vendor group, plus the Linux hotswap fixtures) is now present in
         * the landing worktree, materialized from the submitting checkout
         * rather than left for the proof to discover missing. */
        dlx_landdir(wt, sizeof(wt));
        const char *const required_inputs[] = {
            "vendor/sqlite3.c", "vendor/tor/.provenance", "vendor/tor/Makefile",
        };
        const char *const required_bytes[] = { "sqlite\n", "stamp\n", "CC=gcc\n" };
        for (size_t i = 0; i < 3; ++i) {
            char copied[16] = {0};
            (void)snprintf(source, sizeof(source), "%s/%s", rig.clone,
                           required_inputs[i]);
            (void)snprintf(check, sizeof(check), "%s/wt/%s", wt,
                           required_inputs[i]);
            ASSERT(stat(source, &source_st) == 0);
            ASSERT(stat(check, &landed_st) == 0);
            ASSERT(source_st.st_dev != landed_st.st_dev ||
                   source_st.st_ino != landed_st.st_ino);
            file = fopen(check, "rb");
            ASSERT(file != NULL);
            ASSERT(fread(copied, 1, sizeof(copied), file) ==
                   strlen(required_bytes[i]));
            ASSERT(fclose(file) == 0);
            ASSERT(strcmp(copied, required_bytes[i]) == 0);
        }
        (void)snprintf(source, sizeof(source), "%s/vendor/lib/libfoo.a",
                       rig.clone);
        ASSERT(stat(source, &source_st) == 0);
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a",
                       wt);
        ASSERT(stat(check, &st) == 0 && S_ISREG(st.st_mode));
        /* A landing generation must own its dependency inode. A hard link
         * lets later donor metadata or byte changes mutate sealed evidence. */
        ASSERT(st.st_dev != source_st.st_dev || st.st_ino != source_st.st_ino);
        ASSERT((st.st_mode & 07777) == (source_st.st_mode & 07777));
#if defined(__APPLE__)
        ASSERT(st.st_mtimespec.tv_sec == source_st.st_mtimespec.tv_sec);
        ASSERT(st.st_mtimespec.tv_nsec == source_st.st_mtimespec.tv_nsec);
#else
        ASSERT(st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
#endif
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/include/foo.h",
                       wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/build/hotswap/zcl_rollback_fixture_a.so", wt);
        ASSERT(stat(check, &st) == 0);
        (void)snprintf(
            check, sizeof(check),
            "%s/wt/build/hotswap/zcl_rollback_fixture_b.so", wt);
        ASSERT(stat(check, &st) == 0);

        /* An old generation may explain exactly two links: the submitting
         * dependency and the landing copy. Repair that known old shape. */
        (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude",
                       rig.clone);
        ASSERT(dlx_write(exclude, "vendor/\nbuild/\n"));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/lib/libfoo.a", wt);
        ASSERT(unlink(check) == 0);
        ASSERT(link(source, check) == 0);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 2);
        /* A prior repair died before rename. The historical PID-only temp
         * name must not block this exact two-link recovery after PID reuse. */
        int abandoned_len = snprintf(abandoned, sizeof(abandoned),
                                     "%s.tmp.%ld", check, (long)getpid());
        ASSERT(abandoned_len > 0);
        ASSERT(abandoned_len < (int)sizeof(abandoned));
        ASSERT(dlx_write(abandoned, "abandoned\n"));
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        const char *const ignored[] = {
            "check-ignore", "-q", "vendor/lib/libfoo.a", NULL,
        };
        const char *const tracked[] = {
            "ls-files", "--error-unmatch", "vendor/lib/libfoo.a", NULL,
        };
        ASSERT(dlx_git(rig.clone, ignored) == 0);
        ASSERT(dlx_git(rig.clone, tracked) != 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 1);
        ASSERT(stat(check, &landed_st) == 0 && landed_st.st_nlink == 1);
        ASSERT(st.st_ino != landed_st.st_ino);
        ASSERT(stat(abandoned, &st) == 0 && st.st_nlink == 1);
        ASSERT(unlink(abandoned) == 0);
        ASSERT(st.st_dev != landed_st.st_dev || st.st_ino != landed_st.st_ino);
        ASSERT((landed_st.st_mode & 07777) == (source_st.st_mode & 07777));
#if defined(__APPLE__)
        ASSERT(landed_st.st_mtimespec.tv_sec == source_st.st_mtimespec.tv_sec);
        ASSERT(landed_st.st_mtimespec.tv_nsec ==
               source_st.st_mtimespec.tv_nsec);
#else
        ASSERT(landed_st.st_mtim.tv_sec == source_st.st_mtim.tv_sec);
        ASSERT(landed_st.st_mtim.tv_nsec == source_st.st_mtim.tv_nsec);
#endif
        file = fopen(check, "rb");
        ASSERT(file != NULL);
        ASSERT(fread(bytes[0], 1, sizeof(bytes[0]), file) == 5);
        ASSERT(fclose(file) == 0);
        ASSERT(memcmp(bytes[0], "fake\n", 5) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);

        /* A third spelling has no unique explanation. Refuse atomically,
         * leaving every link and byte untouched for operator inspection. */
        test_make_tmpdir(alias_dir, sizeof(alias_dir), "dev_land",
                         "dependency_extra_alias");
        (void)snprintf(alias, sizeof(alias), "%s/libfoo.alias", alias_dir);
        ASSERT(dlx_write_dep(rig.clone, "vendor/lib/libaaa.a", "aaa\n"));
        (void)snprintf(aaa_source, sizeof(aaa_source),
                       "%s/vendor/lib/libaaa.a", rig.clone);
        (void)snprintf(aaa_target, sizeof(aaa_target),
                       "%s/wt/vendor/lib/libaaa.a", wt);
        ASSERT(link(aaa_source, aaa_target) == 0);
        ASSERT(stat(aaa_source, &st) == 0 && st.st_nlink == 2);
        ASSERT(unlink(check) == 0);
        ASSERT(link(source, check) == 0);
        ASSERT(link(source, alias) == 0);
        ASSERT(stat(source, &st) == 0 && st.st_nlink == 3);
        ASSERT(dlx_commit(rig.clone, "third.txt", "three\n", third));
        const char *const ignored_aaa[] = {
            "check-ignore", "-q", "vendor/lib/libaaa.a", NULL,
        };
        const char *const tracked_aaa[] = {
            "ls-files", "--error-unmatch", "vendor/lib/libaaa.a", NULL,
        };
        ASSERT(dlx_git(rig.clone, ignored_aaa) == 0);
        ASSERT(dlx_git(rig.clone, tracked_aaa) != 0);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, third);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unexplained_links:"
                      "vendor/lib/libfoo.a") != NULL);
        dlx_end(&c);
        const char *const aaa_paths[] = {aaa_source, aaa_target};
        for (size_t i = 0; i < 2; i++) {
            ASSERT(stat(aaa_paths[i], &alias_st) == 0);
            ASSERT(alias_st.st_nlink == 2);
            file = fopen(aaa_paths[i], "rb");
            ASSERT(file != NULL);
            ASSERT(fread(aaa_bytes[i], 1, sizeof(aaa_bytes[i]), file) == 4);
            ASSERT(fclose(file) == 0);
            ASSERT(memcmp(aaa_bytes[i], "aaa\n", 4) == 0);
        }
        const char *const linked_paths[] = {source, check, alias};
        for (size_t i = 0; i < 3; i++) {
            ASSERT(stat(linked_paths[i], &alias_st) == 0);
            ASSERT(alias_st.st_nlink == 3);
            file = fopen(linked_paths[i], "rb");
            ASSERT(file != NULL);
            ASSERT(fread(bytes[i], 1, sizeof(bytes[i]), file) == 5);
            ASSERT(fclose(file) == 0);
            ASSERT(memcmp(bytes[i], "fake\n", 5) == 0);
        }
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

#if !defined(_WIN32)
int test_dev_land_missing_tor_makefile(void)
{
    int failures = 0;
    TEST("land: missing Tor Makefile refuses before requesting proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *const available[] = {
            "vendor/lib/libfoo.a", "vendor/include/foo.h",
            "vendor/sqlite3.c", "vendor/tor/libtor.a",
            "vendor/tor/.provenance",
            "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
            "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "build/hotswap/zcl_rollback_fixture_a.so",
            "build/hotswap/zcl_rollback_fixture_b.so",
        };
        dlx_isolate("tormakemissing");
        ASSERT(dlx_rig_make(&rig, "tormakemissing_rig"));
        for (size_t i = 0; i < sizeof(available) / sizeof(available[0]); ++i)
            ASSERT(dlx_write_dep(rig.clone, available[i], "fixture\n"));
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
        ASSERT(strcmp(dlx_str(&c, "state"), "failed") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "worktree_deps") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:"
                      "vendor/tor/Makefile ") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_dev_land(void);
#if !defined(_WIN32)
static bool dlx_tree_bytes(const char *path, const void *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool dlx_tree_types_make(struct dlx_rig *rig)
{
    if (!dlx_rig_make(rig, "tree_types")) return false;
    char path[1200];
    (void)snprintf(path, sizeof(path), "%s/space\tline\n.bin", rig->clone);
    static const unsigned char bytes[] = { 'A', 0, 'B' };
    if (!dlx_tree_bytes(path, bytes, sizeof(bytes))) return false;
    (void)snprintf(path, sizeof(path), "%s/run", rig->clone);
    if (!dlx_write(path, "") || chmod(path, 0755) != 0) return false;
    (void)snprintf(path, sizeof(path), "%s/link", rig->clone);
    if (symlink("../untrusted-target", path) != 0) return false;
    if (!dlx_commit(rig->clone, "marker", "types\n", rig->tip)) return false;
    char dependency[64];
    memcpy(dependency, rig->tip, sizeof(dependency));
    return dlx_gitlink_commit(rig->clone, "dependency", dependency, "unused", rig->tip);
}

static bool dlx_tree_types_match(const struct zcl_dev_git_tree *tree)
{
    bool executable = false, symlink_bytes = false, binary = false;
    unsigned char expected[32];
    static const unsigned char tagged[] = { 0x20, 'A', 0, 'B' };
    sha3_256(tagged, sizeof(tagged), expected);
    unsigned char link_hash[32];
    static const unsigned char link_bytes[] = "\x20../untrusted-target";
    sha3_256(link_bytes, sizeof(link_bytes) - 1, link_hash);
    for (size_t i = 0; i < tree->files.count; ++i) {
        const struct vcs_entry *entry = &tree->files.entries[i];
        if (!strcmp(entry->path, "run")) executable = entry->mode == 0100755u && entry->size == 0;
        if (!strcmp(entry->path, "link")) symlink_bytes = entry->mode == 0120000u &&
            entry->size == 19 && !memcmp(entry->blob, link_hash, 32);
        if (!strcmp(entry->path, "space\tline\n.bin")) binary = !memcmp(entry->blob, expected, 32);
    }
    return executable && symlink_bytes && binary;
}

static bool dlx_tree_closure_changes_with_gitlink(struct dlx_rig *rig,
    const uint8_t files_root[32], const uint8_t closure_root[32])
{
    char prior_tip[64];
    (void)snprintf(prior_tip, sizeof(prior_tip), "%s", rig->tip);
    if (!dlx_gitlink_commit(rig->clone, "dependency", prior_tip,
                            "unused", rig->tip))
        return false;
    struct zcl_dev_git_tree later = {0};
    struct zcl_result result = zcl_dev_git_tree_read(
        rig->clone, rig->tip, 10000, &later);
    bool ok = result.ok && later.gitlinks == 1 &&
        memcmp(files_root, later.file_manifest_root, 32) == 0 &&
        memcmp(closure_root, later.source_closure_root, 32) != 0 &&
        strcmp(later.links[0].oid, prior_tip) == 0;
    zcl_dev_git_tree_free(&later);
    return ok;
}

static bool dlx_tree_dependency_observation(struct dlx_rig *rig,
    const struct zcl_dev_git_tree *super)
{
    struct zcl_dev_git_tree dependency = {0};
    struct zcl_result result = zcl_dev_git_tree_read(
        rig->clone, super->links[0].oid, 10000, &dependency);
    if (!result.ok || dependency.gitlinks != 0) {
        zcl_dev_git_tree_free(&dependency);
        return false;
    }
    struct zcl_dev_git_dependency_input input = {
        .path = "dependency", .repo_locator = rig->clone,
    };
    memcpy(input.expected_source_closure_root,
           dependency.source_closure_root, 32);
    zcl_dev_git_tree_free(&dependency);
    struct zcl_dev_git_dependency_check check;
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (!result.ok || !check.complete || check.dependencies_verified != 1 ||
        memcmp(check.super_source_closure_root,
               super->source_closure_root, 32) != 0 ||
        !zcl_bytes_any_set(check.verified_dependency_root, 32))
        return false;
    input.expected_source_closure_root[0] ^= 1;
    memset(&check, 0xa5, sizeof(check));
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&check,
                                      sizeof(check))) return false;
    input.expected_source_closure_root[0] ^= 1;
    input.path = "other";
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        &input, 1, 10000, &check);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&check,
                                      sizeof(check))) return false;
    result = zcl_dev_git_tree_verify_dependencies(rig->clone, rig->tip,
        NULL, 0, 10000, &check);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&check, sizeof(check));
}

static bool dlx_tree_malformed_head(struct dlx_rig *rig, const char *a, const char *b,
                                   char head[64])
{
    char oid[64], tree_oid[64], path[1200];
    const char *lookup[] = { "rev-parse", "HEAD:change.txt", NULL };
    if (dlx_git_out(rig->clone, lookup, oid, sizeof(oid)) != 0) return false;
    unsigned char raw[1024], address[20]; size_t len = 0;
    for (size_t i = 0; i < sizeof(address); ++i) {
        unsigned value = 0;
        if (sscanf(oid + i * 2, "%2x", &value) != 1) return false;
        address[i] = (unsigned char)value;
    }
    const char *names[] = { a, b };
    for (size_t i = 0; i < 2; ++i) {
        int n = snprintf((char *)raw + len, sizeof(raw) - len, "100644 %s", names[i]);
        if (n < 0 || (size_t)n + 1 + sizeof(address) > sizeof(raw) - len) return false;
        len += (size_t)n + 1;
        memcpy(raw + len, address, sizeof(address)); len += sizeof(address);
    }
    (void)snprintf(path, sizeof(path), "%s/raw-tree", rig->clone);
    if (!dlx_tree_bytes(path, raw, len)) return false;
    const char *store[] = { "hash-object", "--literally", "-t", "tree", "-w", path, NULL };
    if (dlx_git_out(rig->clone, store, tree_oid, sizeof(tree_oid)) != 0) return false;
    const char *commit[] = { "-c", "user.name=tree", "-c", "user.email=tree@z23.invalid",
        "commit-tree", tree_oid, "-m", "malformed fixture", NULL };
    return dlx_git_out(rig->clone, commit, head, 64) == 0;
}

int test_dev_land_tree_types(void)
{
    int failures = 0;
    TEST("land: tree observation preserves binary paths, modes and unresolved gitlinks") {
        struct dlx_rig rig;
        ASSERT(dlx_tree_types_make(&rig));
        char expected_link[64];
        const char *lookup[] = { "rev-parse", "HEAD:dependency", NULL };
        ASSERT(dlx_git_out(rig.clone, lookup, expected_link, sizeof(expected_link)) == 0);
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        bool matched = r.ok && tree.files.count == 7 && tree.gitlinks == 1 && tree.symlinks == 1;
        if (matched) matched = !strcmp(tree.links[0].path, "dependency") &&
            !strcmp(tree.links[0].oid, expected_link) && dlx_tree_types_match(&tree);
        uint8_t files_root[32], closure_root[32];
        if (matched) {
            memcpy(files_root, tree.file_manifest_root, 32);
            memcpy(closure_root, tree.source_closure_root, 32);
            matched = zcl_bytes_any_set(files_root, 32) &&
                      zcl_bytes_any_set(closure_root, 32);
        }
        if (matched) matched = dlx_tree_dependency_observation(&rig, &tree);
        zcl_dev_git_tree_free(&tree);
        ASSERT(matched);
        ASSERT(dlx_tree_closure_changes_with_gitlink(&rig,
            files_root, closure_root));
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_land_tree_replacements(void)
{
    int failures = 0;
    TEST("land: exact tree ignores replacement refs and inherited repository override") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "tree_replacement"));
        char original[64], replacement[64];
        (void)snprintf(original, sizeof(original), "%s", rig.tip);
        ASSERT(dlx_commit(rig.clone, "later.txt", "replacement bytes\n", replacement));
        const char *replace[] = { "replace", original, replacement, NULL };
        ASSERT(dlx_git(rig.clone, replace) == 0);
        char saved[4096];
        const char *prior = getenv("GIT_DIR");
        bool had = prior != NULL;
        ASSERT(!prior || strlen(prior) < sizeof(saved));
        (void)snprintf(saved, sizeof(saved), "%s", prior ? prior : "");
        ASSERT(setenv("GIT_DIR", rig.bare, 1) == 0);
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, original, 10000, &tree);
        int restored = had ? setenv("GIT_DIR", saved, 1) : unsetenv("GIT_DIR");
        bool exact = r.ok && tree.files.count == 2;
        zcl_dev_git_tree_free(&tree);
        ASSERT(restored == 0);
        ASSERT(exact);
        PASS();
    } _test_next:;
    return failures;
}

static bool dlx_tree_promisor(struct dlx_rig *rig, char marker[1200], char oid[64])
{
    if (!dlx_rig_make(rig, "tree_promisor")) return false;
    char helper[1200], body[1600], remote[1300], object[1200];
    (void)snprintf(marker, 1200, "%s/fetch-marker", rig->clone);
    (void)snprintf(helper, sizeof(helper), "%s/fetch-helper", rig->clone);
    (void)snprintf(body, sizeof(body), "#!/bin/sh\nprintf invoked > '%s'\nexit 1\n", marker);
    if (!dlx_write(helper, body) || chmod(helper, 0755) != 0) return false;
    (void)snprintf(remote, sizeof(remote), "ext::%s", helper);
    const char *promisor[] = { "config", "remote.trap.promisor", "true", NULL };
    const char *url[] = { "config", "remote.trap.url", remote, NULL };
    const char *partial[] = { "config", "extensions.partialClone", "trap", NULL };
    const char *lookup[] = { "rev-parse", "HEAD:change.txt", NULL };
    if (dlx_git(rig->clone, promisor) || dlx_git(rig->clone, url) ||
        dlx_git(rig->clone, partial) || dlx_git_out(rig->clone, lookup, oid, 64)) return false;
    (void)snprintf(object, sizeof(object), "%s/.git/objects/%.2s/%s", rig->clone, oid, oid + 2);
    return unlink(object) == 0;
}

int test_dev_land_tree_missing(void)
{
    int failures = 0;
    TEST("land: missing promisor blob refuses without invoking its armed remote helper") {
        struct dlx_rig rig; char marker[1200], oid[64];
        ASSERT(dlx_tree_promisor(&rig, marker, oid));
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        bool refused = !r.ok && !tree.files.entries && !tree.links;
        zcl_dev_git_tree_free(&tree);
        ASSERT(refused);
        ASSERT(!dlx_file_exists(marker));
        const char *control[] = { "/usr/bin/env", "GIT_ALLOW_PROTOCOL=ext", "git", "-C", rig.clone,
            "-c", "protocol.ext.allow=always", "cat-file", "blob", oid, NULL };
        char sink[8];
        (void)zcl_spawn_capture(control, sink, sizeof(sink), 5000);
        ASSERT(dlx_file_exists(marker));
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_land_tree_malformed(void)
{
    int failures = 0;
    TEST("land: duplicate, ancestor-collision and traversal trees refuse") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "tree_malformed"));
        const char *first[] = { "same", "a", "../escape" };
        const char *second[] = { "same", "a/b", "valid" };
        for (size_t i = 0; i < 3; ++i) {
            char head[64];
            ASSERT(dlx_tree_malformed_head(&rig, first[i], second[i], head));
            struct zcl_dev_git_tree tree = {0};
            struct zcl_result r = zcl_dev_git_tree_read(rig.clone, head, 10000, &tree);
            bool refused = !r.ok && !tree.files.entries && !tree.links && tree.gitlinks == 0;
            zcl_dev_git_tree_free(&tree);
            ASSERT(refused);
        }
        PASS();
    } _test_next:;
    return failures;
}
#endif

int test_dev_land_exact_tree(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: committed blob bytes retain canonical hashes despite dirty worktree") {
        struct dlx_rig rig;
        ASSERT(dlx_rig_make(&rig, "exact_tree"));
        char path[1200];
        (void)snprintf(path, sizeof(path), "%s/change.txt", rig.clone);
        ASSERT(dlx_write(path, "different worktree bytes\n"));
        struct zcl_dev_git_tree tree = {0};
        struct zcl_result r = zcl_dev_git_tree_read(rig.clone, rig.tip, 10000, &tree);
        unsigned char expected[32];
        static const unsigned char tagged[] = { 0x20, 'o', 'n', 'e', '\n' };
        sha3_256(tagged, sizeof(tagged), expected);
        bool matched = r.ok && tree.files.count == 2;
        if (matched)
            matched = strcmp(tree.files.entries[0].path, "change.txt") == 0 &&
                tree.files.entries[0].size == 4 &&
                memcmp(tree.files.entries[0].blob, expected, 32) == 0;
        matched = matched && tree.gitlinks == 0 && tree.symlinks == 0;
        zcl_dev_git_tree_free(&tree);
        ASSERT(matched);
        PASS();
    } _test_next:;
#endif
    return failures;
}

#if !defined(_WIN32)
/* State threaded between the three phases below: one worktree fixture whose
 * committed content is bound by a single captured source_root across mode
 * refusal, bounded-admission refusal, and post-commit drift detection. Split
 * out of one TEST body (each phase kept its own assertions verbatim) only to
 * bring per-function cyclomatic complexity under the lint cap. */
struct dlx_source_binding_state {
    struct dlx_rig rig;
    char change_path[1200];
    char seed_path[1200];
    uint8_t source[32];
    uint8_t wrong_root[32];
    uint8_t publication_root[32];
    uint8_t attachment_root[32];
    uint8_t publisher_secret[32];
    uint8_t publisher_signer[32];
    char publication_head[80];
    char bundle_path[1200];
    size_t wire_len;
};

/* Fixture with two 0600 files, plus the mode-refusal check: an admission
 * comparator refuses unrepresentable file modes before it looks at content. */
static bool dlx_source_binding_setup_fixture(struct dlx_source_binding_state *st)
{
    if (!dlx_rig_make(&st->rig, "source_binding")) return false;
    char exclude[1200];
    (void)snprintf(exclude, sizeof(exclude), "%s/.git/info/exclude", st->rig.clone);
    if (!dlx_write(exclude, ".zvcs/\n")) return false;
    (void)snprintf(st->change_path, sizeof(st->change_path), "%s/change.txt", st->rig.clone);
    (void)snprintf(st->seed_path, sizeof(st->seed_path), "%s/seed.txt", st->rig.clone);
    if (chmod(st->change_path, 0600) != 0) return false;
    if (chmod(st->seed_path, 0600) != 0) return false;
    if (vcs_tree_capture_path(st->rig.clone, st->source) != 0) return false;
    struct zcl_dev_git_source_check mode_check = {0};
    struct zcl_result mode_result = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &mode_check);
    if (mode_result.ok) return false;
    if (!mode_check.observed) return false;
    if (mode_check.unrepresentable_modes != 2) return false;
    return true;
}

/* Representable modes admitted under an exact entry budget; stashes an
 * object addressed under a wrong root for the next phase's refusal checks. */
static bool dlx_source_binding_setup_admit(struct dlx_source_binding_state *st)
{
    if (chmod(st->change_path, 0644) != 0) return false;
    if (chmod(st->seed_path, 0644) != 0) return false;
    if (vcs_tree_capture_path(st->rig.clone, st->source) != 0) return false;
    struct vcs_manifest admitted = {0};
    if (!vcs_tree_load_bounded(st->rig.clone, st->source, 8u * 1024u * 1024u, 2, &admitted))
        return false;
    if (admitted.count != 2) { vcs_manifest_free(&admitted); return false; }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!vcs_manifest_serialize(&admitted, &wire, &wire_len)) {
        vcs_manifest_free(&admitted);
        return false;
    }
    memset(st->wrong_root, 0, sizeof(st->wrong_root));
    st->wrong_root[0] = 0xA5;
    bool put_ok = vcs_object_put_addressed(st->rig.clone, st->wrong_root, wire, wire_len);
    free(wire);
    vcs_manifest_free(&admitted);
    if (!put_ok) return false;
    st->wire_len = wire_len;
    return true;
}

static bool dlx_source_binding_setup(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_setup_fixture(st)) return false;
    if (!dlx_source_binding_setup_admit(st)) return false;
    return true;
}

static bool dlx_source_attachment_store(struct dlx_source_binding_state *st,
    const struct vcs_zcode_publication_v1 *intent,
    const uint8_t publication_root[32], uint8_t attachment_root[32])
{
    struct vcs_zcode_publication_attachment_v1 attachment = {
        .schema_version = 1, .created_unix = intent->created_unix + 1,
    };
    memcpy(attachment.publication_root, publication_root, 32);
    memcpy(attachment.expected_base, intent->expected_base, 32);
    memcpy(attachment.head_commit, intent->head_commit, 32);
    return zcl_hex_decode_lower(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            attachment.bundle_sha256, 32) &&
        vcs_zcode_publication_attachment_seal(&attachment,
            st->publisher_secret, st->publisher_signer) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_attachment_store_verified(st->rig.clone,
            &attachment, st->publisher_signer, attachment_root);
}

static bool dlx_source_publication_fixture(
    struct dlx_source_binding_state *st,
    struct vcs_zcode_publication_v1 *out_intent, char base[80])
{
    uint8_t seed[32] = {41};
    ed25519_keypair(st->publisher_signer, st->publisher_secret, seed);
    struct vcs_zcode_candidate_v1 candidate = {
        .schema_version = 1, .sequence = 1, .created_unix = 1000,
    };
    memset(candidate.task_root, 1, 32);
    memset(candidate.base_source_root, 2, 32);
    memset(candidate.patch_root, 3, 32);
    memcpy(candidate.candidate_source_root, st->source, 32);
    memset(candidate.adapter_policy_root, 4, 32);
    memcpy(candidate.author_pubkey, st->publisher_signer, 32);
    uint8_t candidate_root[32], candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_root(&candidate, candidate_root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_serialize(&candidate, candidate_wire) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed(st->rig.clone, candidate_root,
                                  candidate_wire, sizeof(candidate_wire)))
        return false;
    if (!dlx_origin_main(&st->rig, base)) return false;
    struct vcs_zcode_publication_v1 intent = {
        .schema_version = 1,
        .git_object_format = VCS_ZCODE_PUBLICATION_GIT_OID_20,
        .target_ref = "refs/heads/main",
        .created_unix = 1001,
    };
    memcpy(intent.candidate_root, candidate_root, 32);
    memset(intent.proof_set_root, 5, 32);
    memset(intent.target_identity_root, 6, 32);
    memset(intent.authority_root, 7, 32);
    if (!zcl_hex_decode_lower(base, intent.expected_base, 20) ||
        !zcl_hex_decode_lower(st->rig.tip, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK)
        return false;
    if (!vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, st->publication_root))
        return false;
    (void)snprintf(st->bundle_path, sizeof(st->bundle_path),
                   "%s/.zvcs/test.bundle", st->rig.clone);
    if (!dlx_write(st->bundle_path, "abc")) return false;
    if (!dlx_source_attachment_store(st, &intent, st->publication_root,
                                     st->attachment_root))
        return false;
    (void)snprintf(st->publication_head, sizeof(st->publication_head), "%s",
                   st->rig.tip);
    *out_intent = intent;
    return true;
}

static bool dlx_source_publication_binding(struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    char base[80];
    if (!dlx_source_publication_fixture(st, &intent, base)) return false;
    struct zcl_dev_git_publication_check checked = {0};
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root,
        intent.target_ref, base, st->rig.tip, 1024, 10000, &checked);
    if (!result.ok || !checked.verified ||
        memcmp(checked.attachment_root, st->attachment_root, 32) != 0 ||
        memcmp(checked.source_root, st->source, 32) != 0 ||
        strcmp(checked.expected_base, base) != 0 ||
        strcmp(checked.head, st->rig.tip) != 0)
        return false;
    memset(&checked, 0xa5, sizeof(checked));
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, "refs/heads/other", base,
        st->rig.tip, 1024, 10000, &checked);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    uint8_t wrong_target[32];
    memcpy(wrong_target, intent.target_identity_root, 32);
    wrong_target[0] ^= 1;
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        wrong_target, intent.target_ref, base, st->rig.tip,
        1024, 10000, &checked);
    if (result.ok || zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    result = zcl_dev_git_publication_check(st->rig.clone, st->publication_root,
        st->attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, intent.target_ref,
        st->rig.tip, st->rig.tip, 1024, 10000, &checked);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_bundle_refusals(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    char base[80];
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent) ||
        !dlx_origin_main(&st->rig, base) ||
        !dlx_write(st->bundle_path, "abd"))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root, intent.target_ref,
        base, st->rig.tip, 1024, 10000, &checked);
    if (result.ok || strcmp(result.message,
            "git-publication: actual bundle digest mismatch") != 0 ||
        zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)) ||
        !dlx_write(st->bundle_path, "abc"))
        return false;
    result = zcl_dev_git_publication_check(st->rig.clone,
        st->publication_root, st->attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root, intent.target_ref,
        base, st->rig.tip, 2, 10000, &checked);
    return !result.ok &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_content_drift(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent))
        return false;
    char base[80];
    if (!dlx_origin_main(&st->rig, base)) return false;
    /* The new head descends from the base, but its committed content is no
     * longer the candidate's source. A freshly signed intent cannot hide it. */
    if (!zcl_hex_decode_lower(st->rig.tip, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK)
        return false;
    uint8_t drift_root[32];
    if (!vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, drift_root))
        return false;
    uint8_t drift_attachment_root[32];
    if (!dlx_source_attachment_store(st, &intent, drift_root,
                                     drift_attachment_root))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone,
        drift_root, drift_attachment_root, st->bundle_path,
        st->publisher_signer, intent.target_identity_root,
        intent.target_ref, base, st->rig.tip, 1024, 10000, &checked);
    if (result.ok || strcmp(result.message,
            "git-publication: committed source differs from candidate") != 0 ||
        zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked)))
        return false;
    return true;
}

static bool dlx_source_publication_competing_base(
    struct dlx_source_binding_state *st)
{
    struct vcs_zcode_publication_v1 intent;
    uint8_t drift_root[32];
    if (!vcs_zcode_publication_load_verified(st->rig.clone,
            st->publication_root, st->publisher_signer, &intent))
        return false;
    /* A competing base younger than the frozen head passes pair equality,
     * but fails the independent fast-forward ancestry check. */
    if (!zcl_hex_decode_lower(st->rig.tip, intent.expected_base, 20) ||
        !zcl_hex_decode_lower(st->publication_head, intent.head_commit, 20) ||
        vcs_zcode_publication_seal(&intent, st->publisher_secret,
                                   st->publisher_signer) != VCS_ZCODE_DEV_OK ||
        !vcs_zcode_publication_store_verified(st->rig.clone, &intent,
            st->publisher_signer, drift_root))
        return false;
    uint8_t drift_attachment_root[32];
    if (!dlx_source_attachment_store(st, &intent, drift_root,
                                     drift_attachment_root))
        return false;
    struct zcl_dev_git_publication_check checked;
    memset(&checked, 0xa5, sizeof(checked));
    struct zcl_result result = zcl_dev_git_publication_check(st->rig.clone, drift_root,
        drift_attachment_root, st->bundle_path, st->publisher_signer,
        intent.target_identity_root, intent.target_ref,
        st->rig.tip, st->publication_head, 1024, 10000, &checked);
    return !result.ok && strcmp(result.message,
        "git-publication: expected base is not an ancestor") == 0 &&
        !zcl_bytes_any_set((const uint8_t *)&checked, sizeof(checked));
}

static bool dlx_source_publication_drift(struct dlx_source_binding_state *st)
{
    return dlx_source_publication_content_drift(st) &&
           dlx_source_publication_competing_base(st);
}

/* Bounded admission refuses a wrong structural root, an over-large declared
 * entry count, a truncated byte budget and a too-small entry budget, while
 * the exact root/byte-budget/entry-budget combination — and the unbounded
 * loader — both admit the same two entries. */
/* A wrong structural root and an over-large declared entry count are both
 * refused, each leaving the output manifest empty. */
static bool dlx_source_binding_bounds_refusals(struct dlx_source_binding_state *st)
{
    struct vcs_manifest admitted = {0};
    if (vcs_tree_load_bounded(st->rig.clone, st->wrong_root, st->wire_len, 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    uint8_t excessive[9] = {VCS_MANIFEST_VERSION, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff};
    uint8_t excessive_root[32] = {0xA6};
    if (!vcs_object_put_addressed(st->rig.clone, excessive_root, excessive, sizeof(excessive)))
        return false;
    if (vcs_tree_load_bounded(st->rig.clone, excessive_root, sizeof(excessive), 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    return true;
}

/* The exact root/byte-budget/entry-budget combination admits; a truncated
 * byte budget and a too-small entry budget both refuse; the unbounded
 * loader admits the same two entries. */
static bool dlx_source_binding_bounds_admits(struct dlx_source_binding_state *st)
{
    struct vcs_manifest admitted = {0};
    if (!vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len, 2, &admitted))
        return false;
    vcs_manifest_free(&admitted);
    if (vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len - 1, 2, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    if (vcs_tree_load_bounded(st->rig.clone, st->source, st->wire_len, 1, &admitted))
        return false;
    if (admitted.entries || admitted.count != 0) return false;
    if (!vcs_tree_load(st->rig.clone, st->source, &admitted)) return false;
    if (admitted.count != 2) { vcs_manifest_free(&admitted); return false; }
    vcs_manifest_free(&admitted);
    return true;
}

static bool dlx_source_binding_bounds(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_bounds_refusals(st)) return false;
    if (!dlx_source_binding_bounds_admits(st)) return false;
    return true;
}

/* An exact match, then one committed edit at a time: a same-size content
 * change, an excluded extra, an unexpected extra, and a missing file — each
 * observed and reported by exactly the field it should set. */
/* The initial exact match: every field a complete match sets, and the
 * root/head the check reports back verbatim. */
static bool dlx_source_binding_drift_initial(struct dlx_source_binding_state *st)
{
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (!r.ok) return false;
    if (!check.observed) return false;
    if (!check.complete_content_matches) return false;
    if (check.matched != 2) return false;
    if (memcmp(check.source_root, st->source, 32) != 0) return false;
    if (strcmp(check.head, st->rig.tip) != 0) return false;
    return true;
}

/* A same-size content change is caught as `changed`, not silently accepted. */
static bool dlx_source_binding_drift_changed(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "change.txt", "two\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.changed != 1) return false;
    if (check.source_projection_matches) return false;
    if (check.complete_content_matches) return false;
    return true;
}

/* An excluded extra is classified as `excluded`: the projection still
 * matches (exclusions are outside its scope) but complete content does not. */
static bool dlx_source_binding_drift_excluded(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "change.txt", "one\n", st->rig.tip)) return false;
    if (!dlx_commit(st->rig.clone, "extra.log", "excluded\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.excluded != 1) return false;
    if (!check.source_projection_matches) return false;
    if (check.complete_content_matches) return false;
    return true;
}

/* An extra committed path the manifest never expected is `unexpected`,
 * distinct from the excluded one that is still committed alongside it. */
static bool dlx_source_binding_drift_unexpected(struct dlx_source_binding_state *st)
{
    if (!dlx_commit(st->rig.clone, "extra.txt", "unexpected\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.unexpected != 1) return false;
    if (check.excluded != 1) return false;
    return true;
}

/* A canonical file removed from the worktree is `missing`. */
static bool dlx_source_binding_drift_missing(struct dlx_source_binding_state *st)
{
    if (unlink(st->change_path) != 0) return false;
    if (!dlx_commit(st->rig.clone, "seed.txt", "seed\n", st->rig.tip)) return false;
    struct zcl_dev_git_source_check check = {0};
    struct zcl_result r = zcl_dev_git_tree_check_source(
        st->rig.clone, st->rig.tip, st->source, 10000, &check);
    if (r.ok) return false;
    if (!check.observed) return false;
    if (check.missing != 1) return false;
    return true;
}

static bool dlx_source_binding_drift(struct dlx_source_binding_state *st)
{
    if (!dlx_source_binding_drift_initial(st)) return false;
    if (!dlx_source_binding_drift_changed(st)) return false;
    if (!dlx_source_binding_drift_excluded(st)) return false;
    if (!dlx_source_binding_drift_unexpected(st)) return false;
    if (!dlx_source_binding_drift_missing(st)) return false;
    return true;
}
#endif

int test_dev_land_source_binding(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: canonical source root binds exact committed content, including same-size changes") {
        struct dlx_source_binding_state st = {0};
        ASSERT(dlx_source_binding_setup(&st));
        ASSERT(dlx_source_binding_bounds(&st));
        ASSERT(dlx_source_publication_binding(&st));
        ASSERT(dlx_source_publication_bundle_refusals(&st));
        ASSERT(dlx_source_binding_drift(&st));
        ASSERT(dlx_source_publication_drift(&st));
        PASS();
    } _test_next:;
#endif
    return failures;
}
