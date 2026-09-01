/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the size and shape gates: the file-size ceiling and
 * long-function ratchets (E1, enforced tier plus the lib/ warn tier), and the
 * eight-shape purity rules — E3 (a shape .c includes its own header), E4
 * (projections stay pure), E5 (a reducer stage advances or names a blocker),
 * E6 (one write path), E7 (no authoritative RAM state), E12 (honest witness),
 * domain purity, and shape include direction.
 *
 * Each check plants a violating fixture in the scanned tree, asserts the gate
 * trips, removes it, and asserts the gate recovers. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every check compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

/* Gate #12 (check_long_functions.sh) ENFORCED tier, extended to engine/composition/src/
 * (this test exercises the mechanism via an isolated test-tmp/ scan dir +
 * baseline, so it stands in for either real ENFORCED root — controllers/
 * services/config-src share one code path). Matches the
 * shrinking-floor breadth of t_service_result_convergence_ratchet above:
 * baseline-matched is clean, a lowered baseline trips as a REGRESSION, an
 * empty baseline trips as NEW, and the `// long-function-ok:` tag exempts
 * the same function entirely — then recovery. */
int t_long_functions_enforced_ratchet(void)
{
    int failures = 0;
    char dir_path[PATH_MAX];
    if (repo_path(dir_path, sizeof(dir_path), LONGFN_ENFORCED_DIR_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve long-fn enforced dir path\n");
        return 1;
    }
    (void)mkdir(dir_path, 0700);
    unlink_rel(LONGFN_ENFORCED_FIXTURE_REL);
    unlink_rel(LONGFN_ENFORCED_BASELINE_REL);
    /* keep.c: a permanent, always-clean (well under the cap) sibling file
     * so the gate's non-empty-scan-set floor stays satisfied through the
     * recovery case below, independent of whatever fixture.c is doing. */
    int wrote_keep = write_file(LONGFN_ENFORCED_KEEP_REL,
        "void longfn_enforced_keep_placeholder(void) {}\n");

    /* Case A: fixture is 520 lines; baseline records it at 520 — matched,
     * must be clean. */
    int planted_a = plant_long_function_file(
        LONGFN_ENFORCED_FIXTURE_REL, "longfn_case_matched", 520, NULL);
    char baseline_matched[PATH_MAX + 32];
    (void)snprintf(baseline_matched, sizeof(baseline_matched),
                   "%s longfn_case_matched 520\n", LONGFN_ENFORCED_FIXTURE_REL);
    int wrote_baseline_a = write_file(LONGFN_ENFORCED_BASELINE_REL, baseline_matched);
    int matched_rc =
        (planted_a == 0 && wrote_baseline_a == 0)
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_ENFORCED_ROOTS", LONGFN_ENFORCED_DIR_REL,
                  "ZCL_LONGFN_BASELINE", LONGFN_ENFORCED_BASELINE_REL)
            : -999;

    /* Case B: same fixture (still 520 lines), baseline lowered to 400 —
     * must trip as a REGRESSION (grew past its recorded length). */
    char baseline_grown[PATH_MAX + 32];
    (void)snprintf(baseline_grown, sizeof(baseline_grown),
                   "%s longfn_case_matched 400\n", LONGFN_ENFORCED_FIXTURE_REL);
    int wrote_baseline_b = write_file(LONGFN_ENFORCED_BASELINE_REL, baseline_grown);
    int grown_rc =
        wrote_baseline_b == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_ENFORCED_ROOTS", LONGFN_ENFORCED_DIR_REL,
                  "ZCL_LONGFN_BASELINE", LONGFN_ENFORCED_BASELINE_REL)
            : -999;
    char grown_out_path[PATH_MAX];
    char *grown_out = NULL;
    int grown_read =
        (grown_rc >= 0 &&
         lint_gate_out_path(grown_out_path, sizeof(grown_out_path)) == 0)
            ? read_entire_file(grown_out_path, &grown_out)
            : -1;

    /* Case C: EMPTY baseline, no tag — must trip as a NEW unlisted long
     * function. */
    int wrote_baseline_empty = write_file(LONGFN_ENFORCED_BASELINE_REL, "");
    int new_rc =
        wrote_baseline_empty == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_ENFORCED_ROOTS", LONGFN_ENFORCED_DIR_REL,
                  "ZCL_LONGFN_BASELINE", LONGFN_ENFORCED_BASELINE_REL)
            : -999;
    char new_out_path[PATH_MAX];
    char *new_out = NULL;
    int new_read =
        (new_rc >= 0 &&
         lint_gate_out_path(new_out_path, sizeof(new_out_path)) == 0)
            ? read_entire_file(new_out_path, &new_out)
            : -1;

    /* Case D: same EMPTY baseline, but the signature now carries
     * `// long-function-ok:<tag>` — the override must exempt it entirely,
     * no baseline entry required. */
    int planted_d = plant_long_function_file(
        LONGFN_ENFORCED_FIXTURE_REL, "longfn_case_matched", 520,
        "test_fixture_reason");
    int tagged_rc =
        planted_d == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_ENFORCED_ROOTS", LONGFN_ENFORCED_DIR_REL,
                  "ZCL_LONGFN_BASELINE", LONGFN_ENFORCED_BASELINE_REL)
            : -999;

    /* Recovery: remove fixture + baseline entirely. */
    unlink_rel(LONGFN_ENFORCED_FIXTURE_REL);
    int wrote_baseline_recover = write_file(LONGFN_ENFORCED_BASELINE_REL, "");
    int recover_rc =
        wrote_baseline_recover == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_ENFORCED_ROOTS", LONGFN_ENFORCED_DIR_REL,
                  "ZCL_LONGFN_BASELINE", LONGFN_ENFORCED_BASELINE_REL)
            : -999;

    unlink_rel(LONGFN_ENFORCED_FIXTURE_REL);
    unlink_rel(LONGFN_ENFORCED_BASELINE_REL);
    unlink_rel(LONGFN_ENFORCED_KEEP_REL);
    (void)rmdir(dir_path);

    TEST("[lint-gate] gate#12 ENFORCED (engine/composition/src+controllers/services): matched clean, grown/new trip, tag exempts, recovers") {
        ASSERT(wrote_keep == 0);
        ASSERT(planted_a == 0);
        ASSERT(matched_rc == 0);
        ASSERT(grown_rc != 0);
        ASSERT(grown_read == 0);
        ASSERT(grown_out != NULL && strstr(grown_out, "REGRESSION") != NULL);
        ASSERT(new_rc != 0);
        ASSERT(new_read == 0);
        ASSERT(new_out != NULL && strstr(new_out, "NEW long function") != NULL);
        ASSERT(planted_d == 0);
        ASSERT(tagged_rc == 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;

    free(grown_out);
    free(new_out);
    return failures;
}

/* Gate #12 WARN tier — lib/ (excl. tests/harness/include/test/). Same mechanism, but a
 * violation must PRINT (WARN) and never fail the build (exit 0), mirroring
 * E1's lib/domain WARN tier. */
int t_long_functions_lib_warn_tier(void)
{
    int failures = 0;
    char dir_path[PATH_MAX];
    if (repo_path(dir_path, sizeof(dir_path), LONGFN_LIB_DIR_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve long-fn lib dir path\n");
        return 1;
    }
    (void)mkdir(dir_path, 0700);
    unlink_rel(LONGFN_LIB_FIXTURE_REL);
    unlink_rel(LONGFN_LIB_BASELINE_REL);
    /* keep.c: a permanent, always-clean sibling file so the gate's
     * non-empty-scan-set floor stays satisfied through the recovery case
     * below, independent of whatever fixture.c is doing. */
    int wrote_keep = write_file(LONGFN_LIB_KEEP_REL,
        "void longfn_lib_keep_placeholder(void) {}\n");

    /* Case A: EMPTY baseline, unbaselined 520-line function — must WARN
     * (print) but exit 0. */
    int planted_a = plant_long_function_file(
        LONGFN_LIB_FIXTURE_REL, "longfn_lib_case_new", 520, NULL);
    int wrote_baseline_empty = write_file(LONGFN_LIB_BASELINE_REL, "");
    int new_rc =
        (planted_a == 0 && wrote_baseline_empty == 0)
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_LIB_ROOTS", LONGFN_LIB_DIR_REL,
                  "ZCL_LONGFN_LIB_BASELINE", LONGFN_LIB_BASELINE_REL)
            : -999;
    char new_out_path[PATH_MAX];
    char *new_out = NULL;
    int new_read =
        (new_rc >= 0 &&
         lint_gate_out_path(new_out_path, sizeof(new_out_path)) == 0)
            ? read_entire_file(new_out_path, &new_out)
            : -1;

    /* Case B: baseline lowered below the fixture's actual length — must
     * WARN as "grew past its baselined length" but still exit 0. */
    char baseline_grown[PATH_MAX + 32];
    (void)snprintf(baseline_grown, sizeof(baseline_grown),
                   "%s longfn_lib_case_new 400\n", LONGFN_LIB_FIXTURE_REL);
    int wrote_baseline_grown = write_file(LONGFN_LIB_BASELINE_REL, baseline_grown);
    int grown_rc =
        wrote_baseline_grown == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_LIB_ROOTS", LONGFN_LIB_DIR_REL,
                  "ZCL_LONGFN_LIB_BASELINE", LONGFN_LIB_BASELINE_REL)
            : -999;
    char grown_out_path[PATH_MAX];
    char *grown_out = NULL;
    int grown_read =
        (grown_rc >= 0 &&
         lint_gate_out_path(grown_out_path, sizeof(grown_out_path)) == 0)
            ? read_entire_file(grown_out_path, &grown_out)
            : -1;

    /* Recovery: remove fixture + baseline entirely. */
    unlink_rel(LONGFN_LIB_FIXTURE_REL);
    int wrote_baseline_recover = write_file(LONGFN_LIB_BASELINE_REL, "");
    int recover_rc =
        wrote_baseline_recover == 0
            ? run_gate_script_with_env2(LONGFN_SCRIPT_REL,
                  "ZCL_LONGFN_LIB_ROOTS", LONGFN_LIB_DIR_REL,
                  "ZCL_LONGFN_LIB_BASELINE", LONGFN_LIB_BASELINE_REL)
            : -999;
    char recover_out_path[PATH_MAX];
    char *recover_out = NULL;
    int recover_read =
        (recover_rc >= 0 &&
         lint_gate_out_path(recover_out_path, sizeof(recover_out_path)) == 0)
            ? read_entire_file(recover_out_path, &recover_out)
            : -1;

    unlink_rel(LONGFN_LIB_FIXTURE_REL);
    unlink_rel(LONGFN_LIB_BASELINE_REL);
    unlink_rel(LONGFN_LIB_KEEP_REL);
    (void)rmdir(dir_path);

    /* NOTE: the gate's own CLEAN line for this tier reads "...(cap 500,
     * lib/, WARN tier)" — the bare word "WARN" appears there as a tier
     * label even when nothing tripped. Assert on the violation HEADING
     * ("WARN — long-function watch"), never the bare word, or a clean run
     * false-passes/false-fails this check. */
    TEST("[lint-gate] gate#12 WARN (lib/, excl. tests/harness/include/test/): new/grown WARN-print but exit 0, recovers") {
        ASSERT(wrote_keep == 0);
        ASSERT(planted_a == 0);
        ASSERT(new_rc == 0);
        ASSERT(new_read == 0);
        ASSERT(new_out != NULL &&
               strstr(new_out, "WARN — long-function watch") != NULL);
        ASSERT(new_out != NULL && strstr(new_out, "NEW long function") != NULL);
        ASSERT(grown_rc == 0);
        ASSERT(grown_read == 0);
        ASSERT(grown_out != NULL &&
               strstr(grown_out, "grew past its baselined length") != NULL);
        ASSERT(recover_rc == 0);
        ASSERT(recover_read == 0);
        ASSERT(recover_out != NULL &&
               strstr(recover_out, "WARN — long-function watch") == NULL);
        PASS();
    } _test_next:;

    free(new_out);
    free(grown_out);
    free(recover_out);
    return failures;
}

/* E1 is the one gate that is a compiled binary, so — unlike a script — it
 * does not simply ride into a shard's sandbox with the source tree (see
 * lint_sandbox_build, which copies it in explicitly). If it is absent, say
 * so in those words instead of reporting an unexplained exit 127. */
static int e1_gate_binary_present(void)
{
    char path[PATH_MAX];
    if (repo_path(path, sizeof(path), E1_GATE_REL) != 0) return 0;
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr,
                "[lint-gate] E1: gate binary missing at %s — build it with "
                "`make tools/file_size_policy`\n", path);
        return 0;
    }
    fclose(fp);
    return 1;
}

/* E1 bands — the whole policy in one check, run against the REAL tree.
 *
 *   1. baseline: the tree as committed is clean (exit 0).
 *   2. a 900-line file planted in app/ is in the 801..1500 BUFFER band and
 *      must NOT fail. This is the regression the redesign exists to prevent:
 *      the predecessor gate hard-failed at 801 lines, so adding three lines
 *      to an 877-line file broke the build and forced a split in the middle
 *      of unrelated work.
 *   3. a 1600-line file planted in lib/ is over the 1500 HARD LIMIT and is
 *      not in the baseline, so it MUST fail — and say which file and why.
 *      Planting this one in lib/ (not app/) also pins that the old
 *      ENFORCED-app/ vs WARN-lib/ split is gone: one policy, one number.
 *   4. remove both -> clean again. */
int t_e1_file_size_bands(void)
{
    int failures = 0;
    int gate_present = e1_gate_binary_present();
    unlink_rel(E1_BUFFER_FIXTURE_DST);
    unlink_rel(E1_OVER_LIMIT_FIXTURE_DST);

    int baseline_rc = run_gate_script(E1_GATE_REL, NULL);

    int planted_buffer = plant_oversized_file(E1_BUFFER_FIXTURE_DST, 900);
    int buffer_rc = planted_buffer == 0 ? run_gate_script(E1_GATE_REL, NULL)
                                        : -1;
    char *buffer_out = NULL;
    char buffer_path[PATH_MAX];
    int buffer_read = (planted_buffer == 0 &&
                       lint_gate_out_path(buffer_path, sizeof(buffer_path)) == 0)
                          ? read_entire_file(buffer_path, &buffer_out)
                          : -1;

    int planted_over = plant_oversized_file(E1_OVER_LIMIT_FIXTURE_DST, 1600);
    int over_rc = planted_over == 0 ? run_gate_script(E1_GATE_REL, NULL) : -1;
    char *over_out = NULL;
    char over_path[PATH_MAX];
    int over_read = (planted_over == 0 &&
                     lint_gate_out_path(over_path, sizeof(over_path)) == 0)
                        ? read_entire_file(over_path, &over_out)
                        : -1;

    unlink_rel(E1_BUFFER_FIXTURE_DST);
    unlink_rel(E1_OVER_LIMIT_FIXTURE_DST);
    int recover_rc = run_gate_script(E1_GATE_REL, NULL);

    TEST("[lint-gate] E1 file-size bands: buffer 801-1500 passes, over 1500 fails, recovers") {
        ASSERT(gate_present == 1);
        ASSERT(baseline_rc == 0);

        /* Buffer band: allowed, and the pass line still reports the counts. */
        ASSERT(planted_buffer == 0);
        if (buffer_rc != 0)
            fprintf(stderr, "[lint-gate] E1: a 900-line file must be ALLOWED "
                            "(buffer band), got exit %d\n", buffer_rc);
        ASSERT(buffer_rc == 0);
        ASSERT(buffer_read == 0);
        ASSERT(buffer_out != NULL && strstr(buffer_out, "PASS") != NULL);
        ASSERT(buffer_out != NULL && strstr(buffer_out, "buffer") != NULL);

        /* Over the hard limit: fails, names the file, names the action. */
        ASSERT(planted_over == 0);
        if (over_rc == 0)
            fprintf(stderr, "[lint-gate] E1: a 1600-line unbaselined file must "
                            "FAIL, got exit 0\n");
        ASSERT(over_rc == 1);
        ASSERT(over_read == 0);
        ASSERT(over_out != NULL && strstr(over_out, "FAIL") != NULL);
        ASSERT(over_out != NULL &&
               strstr(over_out, "OVER THE HARD LIMIT") != NULL);
        ASSERT(over_out != NULL &&
               strstr(over_out, E1_OVER_LIMIT_FIXTURE_DST) != NULL);

        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    free(buffer_out);
    free(over_out);
    return failures;
}

/* E1 legacy baseline + hollow scan. Both cases run against an ISOLATED scan
 * root and an ISOLATED baseline (same convention as LONGFN above) so they
 * never touch the real tree or the real baseline file:
 *
 *   - a baselined file sitting AT its recorded count is clean;
 *   - growing it by five lines FAILS. The baseline is shrink-only, so this
 *     is the mechanism that keeps the 23 legacy over-limit files closing
 *     instead of drifting;
 *   - pointing the scan at an empty directory exits 2. A gate that scanned
 *     nothing must never report clean — that is worse than no gate. */
int t_e1_file_size_baseline_and_hollow_scan(void)
{
    int gate_present = e1_gate_binary_present();
    int failures = 0;

    char scan_dir[PATH_MAX];
    char empty_dir[PATH_MAX];
    char baseline_abs[PATH_MAX];
    int setup = repo_path(scan_dir, sizeof(scan_dir), E1_ISO_SCAN_DIR_REL);
    if (setup == 0)
        setup = repo_path(empty_dir, sizeof(empty_dir), E1_EMPTY_SCAN_DIR_REL);
    if (setup == 0)
        setup = repo_path(baseline_abs, sizeof(baseline_abs),
                          E1_ISO_BASELINE_REL);
    if (setup == 0) {
        (void)mkdir(scan_dir, 0700);
        (void)mkdir(empty_dir, 0700);
    }

    /* At its recorded count: clean. */
    int planted = setup == 0 ? plant_oversized_file(E1_ISO_LEGACY_REL, 1700)
                             : -1;
    int wrote_baseline = -1;
    if (planted == 0) {
        FILE *bf = fopen(baseline_abs, "wb");
        if (bf) {
            fprintf(bf, "%s 1700\n", E1_ISO_LEGACY_REL);
            fclose(bf);
            wrote_baseline = 0;
        }
    }
    int held_rc = wrote_baseline == 0
        ? run_gate_script_with_env2(E1_GATE_REL,
                                    E1_BASELINE_ENV, baseline_abs,
                                    E1_SCAN_ROOTS_ENV, E1_ISO_SCAN_DIR_REL)
        : -1;

    /* Grown past it: FAIL. */
    int regrown = wrote_baseline == 0
        ? plant_oversized_file(E1_ISO_LEGACY_REL, 1705) : -1;
    int grown_rc = regrown == 0
        ? run_gate_script_with_env2(E1_GATE_REL,
                                    E1_BASELINE_ENV, baseline_abs,
                                    E1_SCAN_ROOTS_ENV, E1_ISO_SCAN_DIR_REL)
        : -1;
    char *grown_out = NULL;
    char grown_path[PATH_MAX];
    int grown_read = (regrown == 0 &&
                      lint_gate_out_path(grown_path, sizeof(grown_path)) == 0)
                         ? read_entire_file(grown_path, &grown_out)
                         : -1;

    /* Scanned nothing: exit 2, never a quiet pass. */
    int hollow_rc = setup == 0
        ? run_gate_script_with_env2(E1_GATE_REL,
                                    E1_BASELINE_ENV, baseline_abs,
                                    E1_SCAN_ROOTS_ENV, E1_EMPTY_SCAN_DIR_REL)
        : -1;

    char partial_roots[PATH_MAX];
    int partial_len = snprintf(partial_roots, sizeof(partial_roots), "%s:%s",
                               E1_ISO_SCAN_DIR_REL,
                               E1_MISSING_SCAN_DIR_REL);
    int partial_rc = setup == 0 && partial_len > 0 &&
                             (size_t)partial_len < sizeof(partial_roots)
        ? run_gate_script_with_env2(E1_GATE_REL,
                                    E1_BASELINE_ENV, baseline_abs,
                                    E1_SCAN_ROOTS_ENV, partial_roots)
        : -1;

    unlink_rel(E1_ISO_LEGACY_REL);
    unlink_rel(E1_ISO_BASELINE_REL);
    (void)rmdir(scan_dir);
    (void)rmdir(empty_dir);

    TEST("[lint-gate] E1 legacy baseline is shrink-only and a zero-file scan exits 2") {
        ASSERT(gate_present == 1);
        ASSERT(setup == 0);
        ASSERT(planted == 0);
        ASSERT(wrote_baseline == 0);
        ASSERT(held_rc == 0);

        ASSERT(regrown == 0);
        if (grown_rc == 0)
            fprintf(stderr, "[lint-gate] E1: a baselined file that GREW must "
                            "FAIL, got exit 0\n");
        ASSERT(grown_rc == 1);
        ASSERT(grown_read == 0);
        ASSERT(grown_out != NULL &&
               strstr(grown_out, "LEGACY FILE GREW") != NULL);

        if (hollow_rc != 2)
            fprintf(stderr, "[lint-gate] E1: an empty scan set must exit 2 "
                            "(fail-loud), got %d\n", hollow_rc);
        ASSERT(hollow_rc == 2);
        if (partial_rc != 2)
            fprintf(stderr, "[lint-gate] E1: one populated root plus one "
                            "missing root must exit 2, got %d\n", partial_rc);
        ASSERT(partial_rc == 2);
        PASS();
    } _test_next:;
    free(grown_out);
    return failures;
}

/* E3 — shape-includes-header HARD: a condition file that includes neither
 * framework/condition.h nor a conditions/ header trips the gate; removing
 * it restores green. */
int t_e3_shape_includes_header(void)
{
    int failures = 0;
    unlink_rel(E3_FIXTURE_DST);
    int baseline_rc = run_gate_script(E3_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E3_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "/* mislabeled condition: no shape header */\n"
                       "int e3_fixture;\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E3_SCRIPT_REL, NULL) : -1;
    unlink_rel(E3_FIXTURE_DST);
    int recover_rc = run_gate_script(E3_SCRIPT_REL, NULL);
    TEST("[lint-gate] E3 shape-includes-header HARD: clean, trips headerless condition, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E4 — projections-pure HARD: a projection file that includes an app-layer
 * (services/) header trips the gate; removing it restores green. */
int t_e4_projections_pure(void)
{
    int failures = 0;
    unlink_rel(E4_FIXTURE_DST);
    int baseline_rc = run_gate_script(E4_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E4_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "#include \"services/sync_monitor.h\"\n"
                       "int e4_fixture;\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E4_SCRIPT_REL, NULL) : -1;
    unlink_rel(E4_FIXTURE_DST);
    int recover_rc = run_gate_script(E4_SCRIPT_REL, NULL);
    TEST("[lint-gate] E4 projections-pure HARD: clean, trips app-layer include, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate #45 — domain/ source purity HARD: a domain/ file that includes an
 * app-layer (services/) header trips the gate (rule a); an unlisted lib/
 * subsystem prefix also trips it (rule b); a bare domain-local sibling include
 * stays clean. Removing the fixture restores green. */
int t_domain_purity(void)
{
    int failures = 0;
    char path[PATH_MAX];

    unlink_rel(DOMAIN_PURITY_FIXTURE_DST);
    int baseline_rc = run_gate_script(DOMAIN_PURITY_SCRIPT_REL, NULL);

    /* Rule (a): an app-layer (services/) include must trip the gate. */
    int planted_app = (repo_path(path, sizeof(path),
                                 DOMAIN_PURITY_FIXTURE_DST) == 0 &&
                       write_file(path,
                           "#include \"services/foo.h\"\n"
                           "int domain_purity_fixture;\n") == 0)
                      ? 0 : -1;
    int trip_app_rc = planted_app == 0
                      ? run_gate_script(DOMAIN_PURITY_SCRIPT_REL, NULL) : -1;
    unlink_rel(DOMAIN_PURITY_FIXTURE_DST);

    /* Rule (b): an unlisted lib/ subsystem prefix must also trip the gate. */
    int planted_lib = (repo_path(path, sizeof(path),
                                 DOMAIN_PURITY_FIXTURE_DST) == 0 &&
                       write_file(path,
                           "#include \"storage/foo.h\"\n"
                           "int domain_purity_fixture;\n") == 0)
                      ? 0 : -1;
    int trip_lib_rc = planted_lib == 0
                      ? run_gate_script(DOMAIN_PURITY_SCRIPT_REL, NULL) : -1;
    unlink_rel(DOMAIN_PURITY_FIXTURE_DST);

    /* A bare domain-local sibling include (no slash) must NOT trip the gate. */
    int planted_sib = (repo_path(path, sizeof(path),
                                 DOMAIN_PURITY_FIXTURE_DST) == 0 &&
                       write_file(path,
                           "#include \"reject_out.h\"\n"
                           "int domain_purity_fixture;\n") == 0)
                      ? 0 : -1;
    int sibling_rc = planted_sib == 0
                     ? run_gate_script(DOMAIN_PURITY_SCRIPT_REL, NULL) : -1;
    unlink_rel(DOMAIN_PURITY_FIXTURE_DST);

    int recover_rc = run_gate_script(DOMAIN_PURITY_SCRIPT_REL, NULL);

    TEST("[lint-gate] #45 domain-purity HARD: clean, trips app+lib includes, allows sibling, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted_app == 0);
        ASSERT(trip_app_rc != 0);
        ASSERT(planted_lib == 0);
        ASSERT(trip_lib_rc != 0);
        ASSERT(planted_sib == 0);
        ASSERT(sibling_rc == 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate #49 — check-shape-include-direction RATCHET: a models/ file with an
 * upward #include "services/..." trips the gate; removing it restores
 * green. (The services/ -> controllers/ edge already carries
 * grandfathered baseline entries — see shape_include_direction_baseline.txt
 * — so this fixture targets the models/ edge instead, which is the one
 * this gate's own introduction paid down to zero.) */
int t_shape_include_direction(void)
{
    int failures = 0;
    char path[PATH_MAX];

    unlink_rel(SHAPE_DIR_FIXTURE_DST);
    int baseline_rc = run_gate_script(SHAPE_DIR_SCRIPT_REL, NULL);

    int planted = (repo_path(path, sizeof(path), SHAPE_DIR_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "#include \"services/foo.h\"\n"
                       "int shape_dir_fixture;\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(SHAPE_DIR_SCRIPT_REL, NULL) : -1;
    unlink_rel(SHAPE_DIR_FIXTURE_DST);
    int recover_rc = run_gate_script(SHAPE_DIR_SCRIPT_REL, NULL);

    TEST("[lint-gate] #49 shape-include-direction RATCHET: clean, trips models->services include, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E5 — stage-advances-or-blocks HARD: a Job step file that only ever returns
 * JOB_ADVANCED and references no cursor trips the gate; removing it restores
 * green. */
int t_e5_stage_advances_or_blocks(void)
{
    int failures = 0;
    unlink_rel(E5_FIXTURE_DST);
    int baseline_rc = run_gate_script(E5_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E5_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "/* mislabeled Job stage: advances only, no cursor */\n"
                       "typedef int job_result_t;\n"
                       "#define JOB_ADVANCED 0\n"
                       "job_result_t fixture_stage_step_once(void){ return JOB_ADVANCED; }\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E5_SCRIPT_REL, NULL) : -1;
    unlink_rel(E5_FIXTURE_DST);
    int recover_rc = run_gate_script(E5_SCRIPT_REL, NULL);
    TEST("[lint-gate] E5 stage-advances-or-blocks HARD: clean, trips advance-only stage, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E6 — one-write-path RATCHET: a new production write surface outside the
 * baseline trips the gate; removing it restores green. */
int t_e6_one_write_path(void)
{
    int failures = 0;
    unlink_rel(E6_FIXTURE_DST);
    int baseline_rc = run_gate_script(E6_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E6_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "struct active_chain; struct block_index;\n"
                       "int active_chain_set_tip(struct active_chain *, struct block_index *);\n"
                       "int e6_fixture(struct active_chain *c, struct block_index *b){ return active_chain_set_tip(c, b); }\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E6_SCRIPT_REL, NULL) : -1;
    unlink_rel(E6_FIXTURE_DST);
    int recover_rc = run_gate_script(E6_SCRIPT_REL, NULL);
    TEST("[lint-gate] E6 one-write-path RATCHET: clean, trips new writer, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E7 — no-authoritative-RAM-state RATCHET: a new direct active_chain
 * internals access trips the gate; removing it restores green. */
int t_e7_no_authoritative_ram_state(void)
{
    int failures = 0;
    unlink_rel(E7_FIXTURE_DST);
    int baseline_rc = run_gate_script(E7_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E7_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "struct main_state { struct { int height; } chain_active; };\n"
                       "int e7_fixture(struct main_state *s){ return s->chain_active.height; }\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E7_SCRIPT_REL, NULL) : -1;
    unlink_rel(E7_FIXTURE_DST);
    int recover_rc = run_gate_script(E7_SCRIPT_REL, NULL);
    TEST("[lint-gate] E7 no-authoritative-RAM-state RATCHET: clean, trips direct RAM state, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E12 — honest witness (Law 7). The live tree is clean (FAIL mode passes:
 * every witness reads observable progress or carries a reviewed
 * // honest-witness-ok hatch). Plant a condition .c whose witness is a
 * PURE-INVERSE of detect ("return !detect_x()") — the canonical Law-7 lie
 * a no-op/self-certifying remedy hides behind — and assert the gate trips;
 * removing it restores green. This proves the gate has teeth and the
 * baseline is honestly empty. */
int t_e12_honest_witness(void)
{
    int failures = 0;
    unlink_rel(E12_FIXTURE_DST);
    int baseline_rc = run_gate_script(E12_SCRIPT_REL, "FAIL");
    char path[PATH_MAX];
    int planted_good = (repo_path(path, sizeof(path), E12_FIXTURE_DST) == 0 &&
                        write_file(path,
                            "#include <stdbool.h>\n"
                            "#include <stdint.h>\n"
                            "static bool reducer_frontier_compute_hstar(void *db, int32_t *h, int32_t *s){\n"
                            "    (void)db; *h = 42; *s = 42; return true;\n"
                            "}\n"
                            "static bool witness_e12_frontier(int64_t t){\n"
                            "    int32_t hstar = -1;\n"
                            "    int32_t served = -1;\n"
                            "    return reducer_frontier_compute_hstar(0, &hstar, &served) && hstar >= (int)t;\n"
                            "}\n") == 0)
                       ? 0 : -1;
    int good_rc = planted_good == 0 ? run_gate_script(E12_SCRIPT_REL, "FAIL") : -1;
    unlink_rel(E12_FIXTURE_DST);
    int planted = (repo_path(path, sizeof(path), E12_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "#include <stdbool.h>\n"
                       "#include <stdint.h>\n"
                       "static bool detect_e12_fixture(void){ return true; }\n"
                       "static bool witness_e12_fixture(int64_t t){\n"
                       "    (void)t;\n"
                       "    return !detect_e12_fixture();\n"
                       "}\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E12_SCRIPT_REL, "FAIL") : -1;
    unlink_rel(E12_FIXTURE_DST);
    int recover_rc = run_gate_script(E12_SCRIPT_REL, "FAIL");
    TEST("[lint-gate] E12 honest-witness FAIL: accepts reducer H*, trips pure-inverse witness, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted_good == 0);
        ASSERT(good_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_sz_unit;

#endif /* ZCL_TESTING */
