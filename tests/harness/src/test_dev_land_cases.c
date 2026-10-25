/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: step, proof, hook, dependency and conflict cases.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


int dlx_case_missing_dependency(void)
{
    int failures = 0;
    TEST("land: a proof-generation dependency missing from the submitting "
        "checkout too refuses by name instead of proceeding") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("depsmissing");
        ASSERT(dlx_rig_make(&rig, "depsmissing_rig"));
        /* No vendor/lib at all in the submitting checkout: the landing
         * worktree cannot materialize what does not exist anywhere, so the
         * step must refuse by name rather than silently proceed to a proof
         * request the real dependencies[] check would only fail later. */
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
                      "proof_generation_dependency_unavailable:vendor/lib")
              != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "make vendor") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_tor_gitlink(void)
{
    int failures = 0;
    TEST("land: vendor/tor as a real submodule gitlink is initialised "
        "before any archive is materialized, and a failed init refuses by "
        "name without ever copying one") {
        struct dlx_rig rig;
        struct dlx_call c;
        char wt[1200], check[1400];
        dlx_isolate("subinitfail");
        ASSERT(dlx_rig_make(&rig, "subinitfail_rig"));
        /* vendor/tor recorded as a real gitlink (mode 160000) in the tip,
         * .gitmodules pointing at a URL nothing can ever clone. The
         * archive itself IS present in the submitting checkout — proving
         * the refusal comes from the failed submodule init, ahead of the
         * archive copy, and not from a missing source file. */
        /* update-index --cacheinfo requires the named object to exist in
         * THIS repo's own object database even for a gitlink (it does not
         * dereference it as a submodule commit) — the tip's own current
         * commit id is a convenient, always-present stand-in. */
        ASSERT(dlx_gitlink_commit(rig.clone, "vendor/tor", rig.tip,
                                  "/no/such/path/does-not-exist.git",
                                  rig.tip));
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
                      "proof_generation_dependency_unavailable:vendor/tor")
              != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule init failed") !=
              NULL);
        /* Ordering: the archive that WAS available in the submitting
         * checkout must never have been copied, because the failed
         * submodule init refused before dl_wt_vendor_ensure() ever reached
         * the materialize step for it. */
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(!dlx_file_exists(check));
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_tor_head(void)
{
    int failures = 0;
    TEST("land: a submitting checkout whose vendor/tor HEAD differs from "
        "the tip's pinned gitlink refuses by name, naming both commits, "
        "instead of reusing the stale archive") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char wt[1200], check[1400];
        dlx_isolate("submismatch");
        ASSERT(dlx_rig_make(&rig, "submismatch_rig"));
        ASSERT(dlx_subrepo_make(&sub, "submismatch_sub"));
        /* A real submodule add: the tip's gitlink pins rev_b (the bare
         * repo's HEAD at add time). */
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
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
        /* Now drift the SUBMITTING checkout's own submodule working tree
         * onto rev_a, without touching the superproject's committed
         * gitlink — exactly the staleness dl_wt_vendor_tor_pin_matches()
         * exists to catch: the tip still pins rev_b. */
        ASSERT(dlx_submodule_checkout(rig.clone, "vendor/tor", sub.rev_a));
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
                      "vendor/tor/libtor.a") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule commit") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), sub.rev_a) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), sub.rev_b) != NULL);
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(!dlx_file_exists(check));
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_hook_drift(void)
{
    int failures = 0;
    TEST("land: a landing worktree whose installed native hooks drifted "
        "from the binary its own lint rebuilt is repaired before the proof "
        "is asked for, and missing hook names are relinked") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landwt[1200], bin[1400], installed[1400], link[1400], tip2[64];
        char bin_body[256] = {0}, installed_body[256] = {0};
        dlx_isolate("hooksrefresh");
        ASSERT(dlx_rig_make(&rig, "hooksrefresh_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Row 1 without forcing: the step only creates the landing
         * worktree. */
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* Land row 1 so the next step takes a fresh row through
         * dl_step_start. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        dlx_landdir(landwt, sizeof(landwt));
        (void)snprintf(landwt + strlen(landwt),
                       sizeof(landwt) - strlen(landwt), "/wt");
        /* The drift this repair exists for: the worktree's freshly linked
         * hook binary no longer matches the installed copy, and two of
         * the four hook names are gone. */
        (void)snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook",
                       landwt);
        (void)snprintf(installed, sizeof(installed),
                       "%s/build/githooks/z23-git-hook", landwt);
        ASSERT(dlx_write_dep(landwt, "build/bin/z23-git-hook",
                             "#!/bin/sh\nrebuilt today\n"));
        (void)snprintf(bin, sizeof(bin), "%s/build/bin/z23-git-hook",
                       landwt);
        ASSERT(chmod(bin, 0755) == 0);
        ASSERT(dlx_write_dep(landwt, "build/githooks/z23-git-hook",
                             "old hook bytes\n"));
        /* Two of the four hook names are gone — the fixture worktree never
         * had install-hooks run, so at most stray files exist here. */
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-commit", landwt);
        (void)unlink(link);
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-merge", landwt);
        (void)unlink(link);
        /* Row 2 with dependency forcing on: vendor deps present in the
         * submitting checkout, so the step's only obstacle would be an
         * unrepaired hook drift. */
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
            rig.clone,
            "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
            "fake\n"));
        ASSERT(dlx_write_dep(
            rig.clone,
            "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
            "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_a.so",
                             "fake\n"));
        ASSERT(dlx_write_dep(rig.clone,
                             "build/hotswap/zcl_rollback_fixture_b.so",
                             "fake\n"));
        ASSERT(dlx_commit(rig.clone, "two.txt", "two\n", tip2));
        ASSERT(dlx_plant_hook_bin(rig.clone));
        setenv("ZCL_LAND_DEPS_TEST_FORCE", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, tip2);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The installed copy now matches the rebuilt binary byte for
         * byte, and both removed names are links to it again. */
        ASSERT(dlx_slurp(bin, bin_body, sizeof(bin_body), NULL));
        ASSERT(dlx_slurp(installed, installed_body,
                         sizeof(installed_body), NULL));
        ASSERT(strcmp(bin_body, installed_body) == 0);
        ASSERT(strcmp(installed_body, "#!/bin/sh\nrebuilt today\n") == 0);
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-commit", landwt);
        ASSERT(dlx_hook_link(link));
        (void)snprintf(link, sizeof(link),
                       "%s/build/githooks/post-merge", landwt);
        ASSERT(dlx_hook_link(link));
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_idle_proof(void)
{
    int failures = 0;
    TEST("land: a queued proof request no worker claims past the idle "
        "bound is named, not read as an ordinary pending") {
        char detail[192];
        /* The 36-hour silent-resident shape in miniature: a pending detail
         * for a request whose age crosses the bound gains the named note,
         * a fresh one does not, and the bound follows its environment
         * override. The judgment is dl_proof_read's; the seam runs exactly
         * that function's helper without forking a resident in a rig. */
        setenv("ZCL_LAND_PROOF_IDLE_SEC", "900", 1);
        (void)snprintf(detail, sizeof(detail), "%s",
                       "resident_proof_request_queued");
        ASSERT(!zcl_native_dev_land_test_idle_note(899, detail,
                                                   sizeof(detail)));
        ASSERT(strcmp(detail, "resident_proof_request_queued") == 0);
        ASSERT(zcl_native_dev_land_test_idle_note(901, detail,
                                                  sizeof(detail)));
        ASSERT(strstr(detail, "resident_proof_request_queued;") != NULL);
        ASSERT(strstr(detail, "proof_request_idle_age_s=901") != NULL);
        ASSERT(strstr(detail, "no worker has claimed") != NULL);
        setenv("ZCL_LAND_PROOF_IDLE_SEC", "1", 1);
        ASSERT(zcl_native_dev_land_test_idle_bound() == 1);
        unsetenv("ZCL_LAND_PROOF_IDLE_SEC");
        ASSERT(zcl_native_dev_land_test_idle_bound() == 900);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_unclaimed_proof(void)
{
    int failures = 0;
    TEST("land: step on a prove row whose request sat unclaimed past the idle "
        "bound answers PROOF_UNCLAIMED with the exact drive command; a fresh "
        "request is left untouched") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("proof_unclaimed");
        ASSERT(dlx_rig_make(&rig, "proof_unclaimed_rig"));
        unsetenv("ZCL_LAND_PROOF_IDLE_SEC");
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        /* Fresh request: an ordinary proving state, no verdict to act on. */
        setenv("ZCL_LAND_PROOF_STUB", "idle_fresh", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "proving");
        ASSERT(json_get(&c.reply.data, "code") == NULL);
        ASSERT(c.reply.next_count == 0);
        dlx_end(&c);
        /* Idle past the bound: typed, non-human, with the exact next command. */
        setenv("ZCL_LAND_PROOF_STUB", "idle_unclaimed", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "proving");
        ASSERT_STR_EQ(dlx_str(&c, "code"), "PROOF_UNCLAIMED");
        ASSERT(!json_get_bool(json_get(&c.reply.data, "human_action_required")));
        ASSERT(c.reply.next_count == 1);
        ASSERT_STR_EQ(c.reply.next[0].command, "dev land drive");
        ASSERT_STR_EQ(c.reply.next[0].input_json, "{\"prove\":true}");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_missing_hook_binary(void)
{
    int failures = 0;
    TEST("land: a landing worktree with no rebuilt hook binary at all "
        "fails the step by name instead of asking a proof for hooks it "
        "cannot vouch for") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("hooksmissing");
        ASSERT(dlx_rig_make(&rig, "hooksmissing_rig"));
        /* Neither the landing worktree nor the submitting checkout carries
         * a hook binary: the refresh must refuse by name rather than ask
         * a proof for hooks it cannot vouch for. */
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
                      "landing_worktree_hook_binary_missing") != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_quiet_hooks(void)
{
    int failures = 0;
    TEST("land: a step quiets the armed hooks' proof scheduling for its "
        "own transient checkouts, so a rebase's throwaway HEAD can never "
        "enqueue a doomed proof pair") {
        struct dlx_rig rig;
        struct dlx_call c;
        char hooks[1200], markdir[1400], marker[1440], script[1500];
        char body[64] = {0}, tip2[64];
        dlx_isolate("hookquiet");
        ASSERT(dlx_rig_make(&rig, "hookquiet_rig"));
        /* A post-checkout hook that records the guard env it inherited.
         * dl_tip_checkout fires it on every step that starts a row, which
         * is exactly the window the guard exists for. */
        test_make_tmpdir(markdir, sizeof(markdir), "dev_land", "hookmark");
        (void)snprintf(marker, sizeof(marker), "%s/marker", markdir);
        (void)snprintf(hooks, sizeof(hooks), "%s/post-checkout",
                       g_dlx_hooks_ok);
        (void)snprintf(script, sizeof(script),
                       "#!/bin/sh\nprintf '%%s' \"${ZCL_LAND_HOOK_QUIET:-"
                       "unset}\" > '%s'\n", marker);
        ASSERT(dlx_write(hooks, script));
        ASSERT(chmod(hooks, 0755) == 0);
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
        /* Row 2 drives another tip checkout through the armed hook. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "landed") == 0);
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "two.txt", "two\n", tip2));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_submit(&c, &rig, tip2);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
        dlx_end(&c);
        /* The hook ran during the step and saw the guard set to exactly
         * "1". An absent marker means the hook never fired and this case
         * proved nothing; "unset" means the step leaked its transient
         * checkouts to the proof scheduler. */
        /* post-checkout is synchronous inside the step's own git calls, so
         * the marker exists by the time the step replies — assert the
         * outcome directly rather than poll toward a wall-clock deadline
         * (check-no-real-clock-test-deadline exists exactly for this). */
        char fired = dlx_slurp(marker, body, sizeof(body), NULL);
        ASSERT(fired);
        ASSERT(strcmp(body, "1") == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_uninitialised_tor(void)
{
    int failures = 0;
    TEST("land: an uninitialised vendor/tor in the SUBMITTING checkout "
        "refuses by name and by fix, never as a phantom pin mismatch") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char suffix[256];
        dlx_isolate("subuninit");
        ASSERT(dlx_rig_make(&rig, "subuninit_rig"));
        ASSERT(dlx_subrepo_make(&sub, "subuninit_sub"));
        /* The pin is CORRECT: the tip's gitlink and the submodule the
         * checkout holds are the same commit. The only defect is that the
         * checkout's vendor/tor is not checked out. */
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
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
        ASSERT(dlx_submodule_uninit(rig.clone, "vendor/tor"));
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
        /* The whole point: NOT "submodule commit <superproject sha> != tip
         * <pin>". A bare `git -C <checkout>/vendor/tor rev-parse HEAD`
         * walks up to the enclosing superproject and answers with a commit
         * that is not a submodule commit at all. */
        ASSERT(strstr(dlx_str(&c, "detail"), "submodule commit") == NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "proof_generation_dependency_unavailable:vendor/tor "
                      "(submodule uninitialised in ") != NULL);
        (void)snprintf(suffix, sizeof(suffix),
                       "; run git submodule update --init vendor/tor)");
        ASSERT(strstr(dlx_str(&c, "detail"), suffix) != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), rig.clone) != NULL);
        dlx_end(&c);
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_current_tor(void)
{
    int failures = 0;
    TEST("land: a landing worktree already standing on the tip's vendor/tor "
        "pin with the archive in place never consults the submitting "
        "checkout again") {
        struct dlx_rig rig;
        struct dlx_subrepo sub;
        struct dlx_call c;
        char wt[1200], check[1400], second[64];
        dlx_isolate("subtrust");
        ASSERT(dlx_rig_make(&rig, "subtrust_rig"));
        ASSERT(dlx_subrepo_make(&sub, "subtrust_sub"));
        ASSERT(dlx_submodule_add(rig.clone, sub.bare, "vendor/tor",
                                 rig.tip));
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
        /* Round one: an ordinary landing, which initialises the landing
         * worktree's own vendor/tor at the tip's pin and materializes
         * libtor.a beside it. */
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
        dlx_landdir(wt, sizeof(wt));
        (void)snprintf(check, sizeof(check), "%s/wt/vendor/tor/libtor.a",
                       wt);
        ASSERT(dlx_file_exists(check));
        /* Round two: a new tip carrying the SAME gitlink, submitted from a
         * checkout whose vendor/tor is now uninitialised. Nothing over
         * there can answer for the pin any more — and nothing has to. */
        ASSERT(dlx_commit(rig.clone, "second.txt", "two\n", second));
        ASSERT(dlx_submodule_uninit(rig.clone, "vendor/tor"));
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
        unsetenv("ZCL_LAND_DEPS_TEST_FORCE");
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The queue never regenerates, amends or merges a generated document. A
 * rebase conflict confined to them is a plain conflict that names the make
 * target an author runs; neither side is picked and nothing reaches origin. */
int dlx_case_generated_conflict(void)
{
    int failures = 0;
    TEST("land: a rebase conflict confined to generated documents is "
        "refused naming the make target, with no side picked and no "
        "regeneration") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], before[64], after[64];
        dlx_isolate("genconf");
        ASSERT(dlx_rig_make(&rig, "genconf_rig"));
        ASSERT(dlx_sign_arm(rig.clone, "genconf_key"));
        ASSERT(dlx_generated_conflict(&rig, NULL, tip));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "rebase");
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/agent/EXECUTOR_HEURISTICS.md: generated "
                      "document") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "run `make docs-executor-routing`") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/dev/CODEBASE_MAP.md: generated document") !=
               NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "run `make fix-doc-counts`") !=
               NULL);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_rerere_conflict(void)
{
    int failures = 0;
    TEST("land: rerere autoupdate cannot hide a previously resolved "
        "generated-document conflict; it is still refused by name") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], landwt[1300], configured[16];
        const char *get_autoupdate[] = { "config", "--get",
                                         "rerere.autoupdate", NULL };
        dlx_isolate("genrerere");
        ASSERT(dlx_rig_make(&rig, "genrerere_rig"));
        ASSERT(dlx_generated_conflict(&rig, NULL, tip));
        ASSERT(dlx_rerere_autoupdate_prime(&rig));
        ASSERT(dlx_sign_arm(rig.clone, "genrerere_key"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT(strstr(dlx_str(&c, "detail"), "run `make fix-doc-counts`") !=
               NULL);
        dlx_end(&c);
        dlx_land_wt(landwt, sizeof(landwt));
        ASSERT(dlx_git_out(rig.clone, get_autoupdate, configured,
                           sizeof(configured)) == 0);
        ASSERT(strcmp(configured, "true") == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A row queued before the generated files left git still modifies the old
 * tracked copy; rebased onto a main that deleted it that is a modify/delete
 * conflict. The queue picks no side: it refuses, naming the git rm the
 * author runs, and keeps the row's own work out of origin. */
int dlx_case_retired_generated_conflict(void)
{
    int failures = 0;
    TEST("land: a modify/delete conflict on a retired generated file is "
        "refused by name, never resolved by the queue") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64], basec[64], removed[64], before[64], after[64];
        const char *branch[] = { "branch", "keep-tip", NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *reset[] = { "reset", "--quiet", "--hard", basec, NULL };
        const char *retire[] = { "rm", "-q", "--",
                                 "docs/CAPABILITY_INVENTORY.jsonl",
                                 "docs/API_REFERENCE.md", NULL };
        dlx_isolate("genretired");
        ASSERT(dlx_rig_make(&rig, "genretired_rig"));
        ASSERT(dlx_write_dep(rig.clone, "docs/CAPABILITY_INVENTORY.jsonl",
                             "base\n"));
        ASSERT(dlx_write_dep(rig.clone, "docs/API_REFERENCE.md", "base\n"));
        ASSERT(dlx_commit_tree(rig.clone, "tracked generated files", basec));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_write_dep(rig.clone, "docs/CAPABILITY_INVENTORY.jsonl",
                             "mine\n"));
        ASSERT(dlx_write_dep(rig.clone, "docs/API_REFERENCE.md", "mine\n"));
        ASSERT(dlx_write_dep(rig.clone, "retired_work.txt", "work\n"));
        ASSERT(dlx_commit_tree(rig.clone, "the submitted work", tip));
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_git(rig.clone, reset) == 0);
        ASSERT(dlx_git(rig.clone, retire) == 0);
        ASSERT(dlx_commit_tree(rig.clone, "the files leave git", removed));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_sign_arm(rig.clone, "genretired_key"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "conflict");
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "run `git rm docs/CAPABILITY_INVENTORY.jsonl") != NULL);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int dlx_case_mixed_conflict(void)
{
    int failures = 0;
    TEST("land: one conflicted path beside the generated documents keeps "
        "the whole conflict a conflict, every path named") {
        struct dlx_rig rig;
        struct dlx_call c;
        char tip[64];
        dlx_isolate("genmixed");
        ASSERT(dlx_rig_make(&rig, "genmixed_rig"));
        ASSERT(dlx_generated_conflict(&rig, "change.txt", tip));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT(strcmp(dlx_str(&c, "state"), "conflict") == 0);
        ASSERT(strcmp(dlx_str(&c, "dimension"), "rebase") == 0);
        ASSERT(strstr(dlx_str(&c, "detail"), "change.txt") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"),
                      "docs/agent/EXECUTOR_HEURISTICS.md") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "docs/dev/CODEBASE_MAP.md") !=
              NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── LAND-WINDOW: deferral, announce, close ─────────────────────────────
 * The lander's window posts are off in test builds unless armed; the
 * fixture mail dir lives under the isolated state root. */

static void dlx_window_arm(const char *on)
{
    (void)setenv("ZCL_LAND_WINDOW", on, 1);
    (void)setenv("ZCL_LAND_WINDOW_HOST", "hosta", 1);
}

static bool dlx_window_maildir(char *out, size_t cap)
{
    char landdir[1200];
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(out, cap, "%s/../mail", landdir) >= (int)cap)
        return false;
    return dlx_mkdir_p(out);
}

static void dlx_window_clock(int64_t t, char iso[32], char hhmm[8])
{
    time_t tt = (time_t)t;
    struct tm tm;
    (void)gmtime_r(&tt, &tm);
    (void)strftime(iso, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
    (void)strftime(hhmm, 8, "%H:%MZ", &tm);
}

/* The peer inbox: hostb proving candidate aaaaaaaaaa on `base10`, announced
 * at `ts` and expected done at `done`, optionally released a minute later. */
static bool dlx_window_peer(const char *base10, int64_t ts, int64_t done,
                            bool released)
{
    char mail[1400], path[1500], iso[32], hhmm[8], dhhmm[8], riso[32];
    char rows[2048];
    if (!dlx_window_maildir(mail, sizeof(mail)))
        return false;
    dlx_window_clock(ts, iso, hhmm);
    dlx_window_clock(done, riso, dhhmm);
    dlx_window_clock(ts + 60, riso, hhmm);
    int n = snprintf(rows, sizeof(rows),
        "{\"seq\":1,\"ts\":\"%s\",\"from\":\"agent-b\",\"to\":\"*\","
        "\"kind\":\"note\",\"body\":\"LAND-WINDOW hostb, candidate "
        "aaaaaaaaaa on base %.10s, proving now, expected done %s.\","
        "\"ref\":\"astra-board-runs\"}\n",
        iso, base10, dhhmm);
    if (n <= 0 || (size_t)n >= sizeof(rows))
        return false;
    if (released &&
        snprintf(rows + n, sizeof(rows) - (size_t)n,
                 "{\"seq\":2,\"ts\":\"%s\",\"from\":\"agent-b\",\"to\":\"*\","
                 "\"kind\":\"note\",\"body\":\"RELEASED hostb, candidate "
                 "aaaaaaaaaa on base %.10s.\",\"ref\":\"astra-board-runs\"}\n",
                 riso, base10) >= (int)(sizeof(rows) - (size_t)n))
        return false;
    return snprintf(path, sizeof(path), "%s/inbox.peer.jsonl", mail) <
               (int)sizeof(path) &&
           dlx_write(path, rows);
}

static bool dlx_window_outbox_has(const char *needle)
{
    char mail[1400], path[1500];
    static char text[1u << 20];
    size_t len = 0;
    if (!dlx_window_maildir(mail, sizeof(mail)) ||
        snprintf(path, sizeof(path), "%s/outbox.jsonl", mail) >=
            (int)sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0'; /* dlx_slurp does not terminate */
    return strstr(text, needle) != NULL;
}

/* Isolated rig, armed lander window, a queued submission of the rig tip. */
static bool dlx_window_rig(struct dlx_rig *rig, const char *tag,
                           const char *on, char base[64])
{
    struct dlx_call c;
    char mail[1400];
    bool ok;
    dlx_isolate(tag);
    dlx_window_arm(on);
    if (!dlx_rig_make(rig, tag) || !dlx_origin_main(rig, base) ||
        !dlx_window_maildir(mail, sizeof(mail)))
        return false;
    (void)setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    (void)setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

/* Step once; "" state on a refusal, with the refusal code in `code`. */
static void dlx_window_step(char state[32], char code[64], char evidence[512])
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    state[0] = code[0] = evidence[0] = '\0';
    if (dlx_run(&c)) {
        if (dlx_ok(&c) && dlx_str(&c, "state"))
            (void)snprintf(state, 32, "%s", dlx_str(&c, "state"));
        else if (!dlx_ok(&c)) {
            (void)snprintf(code, 64, "%s", dlx_err_code(&c));
            (void)snprintf(evidence, 512, "%s", dlx_err_evidence(&c));
        }
    }
    dlx_end(&c);
}

int test_dev_land_window_defer(void)
{
    int failures = 0;
    struct dlx_rig rig;
    char base[64], state[32], code[64], evidence[512], want[160];
    int64_t now = platform_time_wall_unix();

    TEST("land window: a foreign window on the same base defers the proof") {
        ASSERT(dlx_window_rig(&rig, "window_defer", "1", base));
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(code, "STEP_DEFERRED");
        ASSERT(strstr(evidence, "host=hostb") != NULL);
        ASSERT(strstr(evidence, "candidate=aaaaaaaaaa") != NULL);
        ASSERT(strstr(evidence, "seconds_left=") != NULL);
        ASSERT(!dlx_window_outbox_has("LAND-WINDOW hosta"));
        /* hostb released: the proof starts and hosta announces it */
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, true));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        (void)snprintf(want, sizeof(want), "on base %.10s, proving now, "
                       "expected done ", base);
        ASSERT(dlx_window_outbox_has("\"body\":\"LAND-WINDOW hosta, candidate "));
        ASSERT(dlx_window_outbox_has(want));
        /* the publish closes the window with LANDED */
        (void)setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "landed");
        ASSERT(dlx_window_outbox_has("\"body\":\"LANDED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        dlx_restore();
        PASS();
    }

    TEST("land window: a window on another base does not defer; a failure releases") {
        ASSERT(dlx_window_rig(&rig, "window_other_base", "1", base));
        ASSERT(dlx_window_peer("cccccccccc", now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        ASSERT(dlx_window_outbox_has("\"body\":\"LAND-WINDOW hosta, candidate "));
        (void)setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_window_step(state, code, evidence);
        ASSERT(state[0] != '\0' && strcmp(state, "landed") != 0);
        ASSERT(dlx_window_outbox_has("\"body\":\"RELEASED hosta, candidate "));
        dlx_restore();
        PASS();
    }

    TEST("land window: a window past expected-done + 10 min does not defer") {
        ASSERT(dlx_window_rig(&rig, "window_expired", "1", base));
        ASSERT(dlx_window_peer(base, now - 3000, now - 900, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        dlx_restore();
        PASS();
    }

    TEST("land window: ZCL_LAND_WINDOW=0 neither defers nor posts") {
        ASSERT(dlx_window_rig(&rig, "window_off", "0", base));
        ASSERT(dlx_window_peer(base, now - 300, now + 1500, false));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        ASSERT(!dlx_window_outbox_has("LAND-WINDOW hosta"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The step that would have settled died right after its outcome append:
 * this host's window is still open in the sidecar while the row is
 * terminal. `proof` is the stub the dying step runs ("pass" -> landed,
 * "fail" -> a non-landed terminal). Returns the next step's state. */
static bool dlx_window_crash(const char *tag, const char *on,
                             const char *proof, char state[32],
                             char code[64], bool *sidecar,
                             bool *pre_side, bool *pre_landed,
                             bool *pre_released)
{
    struct dlx_rig rig;
    struct dlx_call c;
    char base[64], evidence[512], landdir[1200], side[1300];
    int child_status = 0;
    if (!dlx_window_rig(&rig, tag, on, base))
        return false;
    dlx_window_step(state, code, evidence);
    if (strcmp(state, "started") != 0)
        return false;
    (void)setenv("ZCL_LAND_PROOF_STUB", proof, 1);
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0) {
        (void)setenv("ZCL_LAND_TEST_DIE_AFTER_OUTCOME", "1", 1);
        (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
        dlx_begin(&c, "step");
        (void)dlx_run(&c);
        _exit(90);
    }
    if (dlx_wait_child(child, &child_status) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 81)
        return false;
    dlx_landdir(landdir, sizeof(landdir));
    if (snprintf(side, sizeof(side), "%s/window.state", landdir) >=
        (int)sizeof(side))
        return false;
    /* Observed after the crash and before the replay step. */
    *pre_side = dlx_file_exists(side);
    *pre_landed = dlx_window_outbox_has("\"body\":\"LANDED hosta");
    *pre_released = dlx_window_outbox_has("\"body\":\"RELEASED hosta");
    dlx_window_step(state, code, evidence);
    *sidecar = *pre_side && dlx_file_exists(side);
    return true;
}

int test_dev_land_window_replay(void)
{
    int failures = 0;
    char state[32], code[64], ref[32];
    bool sidecar, pre_side, pre_landed, pre_released;

    TEST("land window: a terminal replay closes the open window with LANDED") {
        /* reference: the same crash with the window off */
        ASSERT(dlx_window_crash("window_replay_off", "0", "pass", ref, code,
                                &sidecar, &pre_side, &pre_landed,
                                &pre_released));
        ASSERT_STR_EQ(ref, "landed");
        dlx_restore();
        ASSERT(dlx_window_crash("window_replay_landed", "1", "pass", state,
                                code, &sidecar, &pre_side, &pre_landed,
                                &pre_released));
        ASSERT(pre_side);
        ASSERT(!pre_landed);
        ASSERT(!pre_released);
        ASSERT_STR_EQ(state, ref);
        ASSERT_STR_EQ(code, "");
        ASSERT(dlx_window_outbox_has("\"body\":\"LANDED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        ASSERT(!sidecar);
        dlx_restore();
        PASS();
    }

    TEST("land window: a terminal replay of a failed row closes with RELEASED") {
        ASSERT(dlx_window_crash("window_replay_off2", "0", "fail", ref, code,
                                &sidecar, &pre_side, &pre_landed,
                                &pre_released));
        ASSERT(ref[0] != '\0' && strcmp(ref, "landed") != 0);
        dlx_restore();
        ASSERT(dlx_window_crash("window_replay_failed", "1", "fail", state,
                                code, &sidecar, &pre_side, &pre_landed,
                                &pre_released));
        ASSERT(pre_side);
        ASSERT(!pre_landed);
        ASSERT(!pre_released);
        ASSERT_STR_EQ(state, ref);
        ASSERT_STR_EQ(code, "");
        ASSERT(dlx_window_outbox_has("\"body\":\"RELEASED hosta, candidate "));
        ASSERT(!dlx_window_outbox_has("\"body\":\"LANDED hosta"));
        ASSERT(!sidecar);
        dlx_restore();
        PASS();
    }

    TEST("land window: a row still proving keeps its window across a step") {
        struct dlx_rig rig;
        char base[64], evidence[512], landdir[1200], side[1300];
        ASSERT(dlx_window_rig(&rig, "window_replay_proving", "1", base));
        dlx_window_step(state, code, evidence);
        ASSERT_STR_EQ(state, "started");
        dlx_window_step(state, code, evidence); /* stub still running */
        ASSERT(strcmp(state, "started") == 0 || strcmp(state, "proving") == 0);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(side, sizeof(side), "%s/window.state", landdir) <
               (int)sizeof(side));
        ASSERT(dlx_file_exists(side));
        ASSERT(!dlx_window_outbox_has("\"body\":\"LANDED hosta"));
        ASSERT(!dlx_window_outbox_has("\"body\":\"RELEASED hosta"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#endif /* !defined(_WIN32) */

/* ── test-only hatches stay test-only ───────────────────────────────────
 * A getenv in dev.land whose name carries STUB, TEST or FAKE skips or fakes
 * a gate, proof, hook or signature. The dev build lands code too, so each
 * such read must sit under `#if defined(ZCL_TESTING)` alone: an
 * `ZCL_DEV_BUILD || ZCL_TESTING` guard would let the dev binary honour it.
 * The scanner reads the three dev.land sources and checks every such site. */

int repo_path(char *out, size_t outsz, const char *rel);

#define DLX_HATCH_DEPTH 64
#define DLX_HATCH_LINE 8192
#define DLX_HATCH_NAME 128
#define DLX_HATCH_DIR 256
#define DLX_HATCH_MAX ((size_t)4 * 1024 * 1024)

struct dlx_hatch_scan {
    int depth;
    bool testing[DLX_HATCH_DEPTH]; /* this #if is the ZCL_TESTING opener */
    bool in_else[DLX_HATCH_DEPTH]; /* this #if has passed its #else or #elif */
    int guarded;                   /* in-scope getenv reads under the guard */
    int unguarded;                 /* in-scope getenv reads outside it */
    bool error;                    /* unbalanced, unreadable or unclassifiable */
    char first[DLX_HATCH_NAME];    /* the first unguarded name */
};

/* Every STUB, TEST or FAKE name is in scope, plus the unsigned bypass, which
 * skips the signature check and so is named without one of those words. */
static bool dlx_hatch_in_scope(const char *name)
{
    if (strcmp(name, "ZCL_LAND_ALLOW_UNSIGNED") == 0)
        return true;
    return strstr(name, "STUB") != NULL || strstr(name, "TEST") != NULL ||
           strstr(name, "FAKE") != NULL;
}

static bool dlx_hatch_word(const char *dir, const char *word)
{
    size_t n = strlen(word);
    return strncmp(dir, word, n) == 0 &&
           (dir[n] == '\0' || dir[n] == ' ' || dir[n] == '\t' || dir[n] == '/');
}

/* Exactly the test-build opener, or a conjunction that still requires it. */
static bool dlx_hatch_opener(const char *dir)
{
    static const char and_form[] = "#if defined(ZCL_TESTING) &&";
    if (strcmp(dir, "#if defined(ZCL_TESTING)") == 0)
        return true;
    return strncmp(dir, and_form, sizeof(and_form) - 1) == 0 &&
           strchr(dir, '|') == NULL;
}

static bool dlx_hatch_guarded(const struct dlx_hatch_scan *s)
{
    for (int i = 0; i < s->depth; i++) {
        if (s->testing[i] && !s->in_else[i])
            return true;
    }
    return false;
}

static void dlx_hatch_directive(struct dlx_hatch_scan *s, const char *dir)
{
    int top = s->depth - 1;
    if (strncmp(dir, "#if", 3) == 0) {
        if (s->depth >= DLX_HATCH_DEPTH) {
            s->error = true;
            return;
        }
        s->testing[s->depth] = dlx_hatch_opener(dir);
        s->in_else[s->depth] = false;
        s->depth++;
    } else if (dlx_hatch_word(dir, "#else") || dlx_hatch_word(dir, "#elif")) {
        if (top < 0)
            s->error = true;
        else
            s->in_else[top] = true;
    } else if (dlx_hatch_word(dir, "#endif")) {
        if (top < 0)
            s->error = true;
        else
            s->depth--;
    }
}

static void dlx_hatch_getenv(struct dlx_hatch_scan *s, const char *line)
{
    const char *p = line;
    while ((p = strstr(p, "getenv(")) != NULL) {
        char name[DLX_HATCH_NAME];
        size_t n = 0;
        p += strlen("getenv(");
        if (*p != '"') {
            s->error = true; /* a computed name cannot be classified */
            return;
        }
        for (p++; *p != '"'; p++) {
            if (*p == '\0' || n + 1 >= sizeof(name)) {
                s->error = true;
                return;
            }
            name[n++] = *p;
        }
        name[n] = '\0';
        p++;
        if (!dlx_hatch_in_scope(name))
            continue;
        if (dlx_hatch_guarded(s)) {
            s->guarded++;
            continue;
        }
        if (s->unguarded == 0)
            (void)snprintf(s->first, sizeof(s->first), "%s", name);
        s->unguarded++;
    }
}

static void dlx_hatch_line(struct dlx_hatch_scan *s, const char *line)
{
    const char *p = line;
    char dir[DLX_HATCH_DIR];
    size_t n;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '#') {
        dlx_hatch_getenv(s, line);
        return;
    }
    n = strlen(p);
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t' || p[n - 1] == '\r'))
        n--;
    if (n >= sizeof(dir)) {
        s->error = true;
        return;
    }
    memcpy(dir, p, n);
    dir[n] = '\0';
    dlx_hatch_directive(s, dir);
}

static void dlx_hatch_scan_text(const char *text, struct dlx_hatch_scan *s)
{
    char line[DLX_HATCH_LINE];
    const char *p = text;
    memset(s, 0, sizeof(*s));
    while (*p != '\0' && !s->error) {
        const char *eol = strchr(p, '\n');
        size_t n = eol ? (size_t)(eol - p) : strlen(p);
        if (n >= sizeof(line)) {
            s->error = true;
            return;
        }
        memcpy(line, p, n);
        line[n] = '\0';
        dlx_hatch_line(s, line);
        p = eol ? eol + 1 : p + n;
    }
    if (s->depth != 0)
        s->error = true;
}

static char *dlx_hatch_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *buf = NULL;
    long n;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) >= 0 &&
        (size_t)n < DLX_HATCH_MAX && fseek(f, 0, SEEK_SET) == 0) {
        buf = calloc((size_t)n + 1, 1);
        if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    return buf;
}

int test_dev_land_test_hatches_testing_only(void)
{
    static const char *const files[] = {
        "tools/command/native_dev_land.c",
        "tools/command/native_dev_land_prepare.c",
        "tools/command/native_dev_land_train.c",
        "tools/command/native_dev_land_window.c",
    };
    int failures = 0;
    TEST("land: every STUB, TEST or FAKE getenv in dev.land sits under #if defined(ZCL_TESTING) alone") {
        struct dlx_hatch_scan s;
        int total = 0;
        /* The scanner's own verdicts first, so a silent scanner cannot pass. */
        dlx_hatch_scan_text("#if defined(ZCL_TESTING)\n"
                            "    if (getenv(\"ZCL_LAND_TEST_X\")) return;\n"
                            "#endif\n", &s);
        ASSERT(!s.error && s.guarded == 1 && s.unguarded == 0);
        dlx_hatch_scan_text("#if defined(ZCL_TESTING) && !defined(_WIN32)\n"
                            "    (void)getenv(\"ZCL_LAND_TEST_X\");\n"
                            "#else\n    (void)0;\n#endif /* not windows */\n", &s);
        ASSERT(!s.error && s.guarded == 1 && s.unguarded == 0);
        dlx_hatch_scan_text("#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)\n"
                            "    (void)getenv(\"ZCL_LAND_TEST_X\");\n#endif\n", &s);
        ASSERT(!s.error && s.unguarded == 1);
        dlx_hatch_scan_text("#if defined(ZCL_TESTING)\n#else\n"
                            "    (void)getenv(\"ZCL_LAND_TEST_X\");\n#endif\n", &s);
        ASSERT(!s.error && s.unguarded == 1);
        dlx_hatch_scan_text("static void f(void) { (void)getenv(\"ZCL_LAND_HOOKS_STUB_DIR\"); }\n", &s);
        ASSERT(!s.error && s.unguarded == 1);
        ASSERT(strcmp(s.first, "ZCL_LAND_HOOKS_STUB_DIR") == 0);
        dlx_hatch_scan_text("(void)getenv(\"HOME\");\n(void)getenv(\"ZCL_LAND_PROOF_STUB\");\n", &s);
        ASSERT(!s.error && s.unguarded == 1 && s.guarded == 0);
        ASSERT(strcmp(s.first, "ZCL_LAND_PROOF_STUB") == 0);
        dlx_hatch_scan_text("(void)getenv(\"ZCL_LAND_ALLOW_UNSIGNED\");\n", &s);
        ASSERT(!s.error && s.unguarded == 1);
        dlx_hatch_scan_text("#if defined(ZCL_TESTING)\n    (void)getenv(\"ZCL_LAND_TEST_X\");\n", &s);
        ASSERT(s.error);
        dlx_hatch_scan_text("#endif\n", &s);
        ASSERT(s.error);
        /* Then the real sources: no in-scope read may sit outside the guard. */
        for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
            char path[1024];
            char *text;
            ASSERT(repo_path(path, sizeof(path), files[i]) == 0);
            text = dlx_hatch_read(path);
            ASSERT(text != NULL);
            dlx_hatch_scan_text(text, &s);
            free(text);
            if (s.unguarded != 0)
                (void)fprintf(stderr, "dev.land hatch outside ZCL_TESTING: %s in %s\n",
                              s.first, files[i]);
            ASSERT(!s.error);
            ASSERT(s.unguarded == 0);
            total += s.guarded;
        }
        /* Non-vacuous: the sources really do carry the guarded hatch reads.
         * The floor is the exact count: 20 until the two regen-stub reads
         * (ZCL_LAND_REGEN_MAKE_STUB, ZCL_LAND_REGEN_GATE_STUB_FAIL) were
         * deleted with the regen phase they stubbed. */
        ASSERT(total >= 18);
        PASS();
    }
_test_next:;
    return failures;
}
