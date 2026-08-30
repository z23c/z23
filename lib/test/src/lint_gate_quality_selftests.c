/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the gates that keep the codebase legible and its error
 * handling loud: E2 (one result type) and the service-result convergence
 * ratchet, E10 (framework shape ratchet, no raw SQL in controllers), E11 (doc
 * accuracy), E13 (consensus parity), E14 (condition cooldown), gate 22
 * (framework filename suffix), the P1/P2/P3 legibility gates (file purpose,
 * group purpose, orphan placement), markdown links, the model ActiveRecord
 * lifecycle, silent bool errors, and the LOG_* macro return-type gate.
 *
 * Each check plants a violating fixture, asserts the gate trips, removes it,
 * and asserts the gate recovers. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every check compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"

/* E14 — condition cooldown re-arm: the live app/conditions/src tree must
 * pass (baseline), and the script's own isolated-tmp-dir selftest (which
 * plants/removes a cooldown-less network-dependent COND_CRITICAL fixture
 * and asserts exit 2 with the offending condition named, plus every
 * sibling pass case) must report clean. Mirrors t_systemd_memory_budget's
 * setenv/run/unsetenv shape. */
int t_e14_condition_cooldown_gate(void)
{
    int failures = 0;
    int baseline_rc = run_gate_script(CONDITION_COOLDOWN_SCRIPT_REL, NULL);
    int env_rc = setenv("ZCL_CONDITION_COOLDOWN_SELFTEST", "1", 1);
    int selftest_rc =
        env_rc == 0 ? run_gate_script(CONDITION_COOLDOWN_SCRIPT_REL, NULL) : -1;
    (void)unsetenv("ZCL_CONDITION_COOLDOWN_SELFTEST");
    TEST("[lint-gate] E14 condition cooldown: baseline and selftest pass") {
        ASSERT(baseline_rc == 0);
        ASSERT(env_rc == 0);
        ASSERT(selftest_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* check-fuzz-artifact-ledger — every saved fuzz finding under
 * lib/test/fuzz_seeds/ carries a written verdict in ARTIFACT_VERDICTS.txt.
 *
 * This gate exists because a real hang sat unread for two weeks: on 2026-07-14
 * a fuzzer found that a five-byte script from any peer spins the node forever,
 * the bytes were committed to the corpus, and no build ever read the verdict —
 * three separate mechanisms had already replayed them and already gone red.
 * The regression this test protects against is that gate quietly losing the
 * ability to fail, which would restore the original silence exactly.
 *
 * Proof, all four steps inside the script's own --selftest:
 * (1) the clean tree passes; (2) an untriaged artifact planted into a real
 * corpus dir trips it; (3) the failure output NAMES that exact file (a red
 * build must not send anyone hunting); (4) removing it recovers green.
 * Then here: (5) the gate is wired into the Makefile LINT_GATES list and
 * documented in DEFENSIVE_CODING.md's canonical block.
 *
 * The replay half (make fuzz-replay) is deliberately NOT exercised here — it
 * needs the nine libFuzzer binaries, which are a 5m45s build. */
int t_fuzz_artifact_ledger_gate(void)
{
    int failures = 0;
    char path[PATH_MAX];
    char *makefile_buf = NULL;
    char *doc_buf = NULL;

    int baseline_rc = run_gate_script_with_env(
        FUZZ_ARTIFACT_REPLAY_SCRIPT_REL, "ZCL_FUZZ_REPLAY_LEDGER_ONLY", "1");
    /* A bare ASSERT(baseline_rc == 0) below gives no way to tell a real gate
     * violation (script printed a named finding, exit 1) from a harness-level
     * fork() failure (fork_with_retry() exhausted its retries under load,
     * exit -1) apart from the numeric value, which the TEST()/ASSERT() macros
     * do not print. On any baseline failure, capture+print the script's own
     * output NOW: the out file is a fixed per-pid name
     * (lint_gate_out_path()) and the very next call overwrites it, so this
     * has to happen before that call, not after. This is what makes a future
     * occurrence of this flake (see t_fuzz_artifact_ledger_gate history,
     * 2026-07-30) diagnosable straight from the captured
     * test-tmp/test_parallel_*.log instead of needing another investigation
     * to add the same instrumentation again. */
    if (baseline_rc != 0) {
        char diag_out_path[PATH_MAX];
        char *diag_buf = NULL;
        fprintf(stderr,
                "[lint-gate] check-fuzz-artifact-ledger baseline_rc=%d "
                "(pid=%ld)\n", baseline_rc, (long)getpid());
        if (lint_gate_out_path(diag_out_path, sizeof(diag_out_path)) == 0 &&
            read_entire_file(diag_out_path, &diag_buf) == 0) {
            fprintf(stderr,
                    "[lint-gate] baseline script captured output (%s):\n%s\n"
                    "[lint-gate] --- end captured output ---\n",
                    diag_out_path, diag_buf);
            free(diag_buf);
        } else {
            fprintf(stderr,
                    "[lint-gate] could not read captured output at %s "
                    "(errno=%d %s)\n", diag_out_path, errno, strerror(errno));
        }
    }
    int selftest_rc = run_gate_script_with_env(
        FUZZ_ARTIFACT_REPLAY_SCRIPT_REL, "ZCL_FUZZ_REPLAY_SELFTEST", "1");

    int makefile_wired = 0;
    if (repo_path(path, sizeof(path), "Makefile") == 0 &&
        read_entire_file(path, &makefile_buf) == 0) {
        makefile_wired =
            strstr(makefile_buf, "check-fuzz-artifact-ledger:") != NULL &&
            strstr(makefile_buf, "check-fuzz-artifact-ledger \\") != NULL &&
            /* The replay half must stay reachable from `make ci`, or the
             * verdict has nowhere to go again. */
            strstr(makefile_buf, "fuzz-replay:") != NULL &&
            strstr(makefile_buf, "$(MAKE) fuzz-replay") != NULL;
    }
    int doc_wired = 0;
    if (repo_path(path, sizeof(path), "docs/DEFENSIVE_CODING.md") == 0 &&
        read_entire_file(path, &doc_buf) == 0) {
        doc_wired = strstr(doc_buf, "check-fuzz-artifact-ledger") != NULL;
    }

    /* The ledger itself must exist and be non-trivial: an empty or deleted
     * ARTIFACT_VERDICTS.txt is the shape this whole lane exists to prevent. */
    char *ledger_buf = NULL;
    int ledger_present = 0;
    if (repo_path(path, sizeof(path),
                  "lib/test/fuzz_seeds/ARTIFACT_VERDICTS.txt") == 0 &&
        read_entire_file(path, &ledger_buf) == 0) {
        ledger_present = strstr(ledger_buf, "regression-seed") != NULL;
    }

    TEST("[lint-gate] check-fuzz-artifact-ledger: clean passes, planted "
         "artifact trips and is named, recovers, wired into lint + ci") {
        ASSERT(baseline_rc == 0);
        ASSERT(selftest_rc == 0);
        ASSERT(makefile_wired);
        ASSERT(doc_wired);
        ASSERT(ledger_present);
        PASS();
    } _test_next:;
    free(makefile_buf);
    free(doc_buf);
    free(ledger_buf);
    return failures;
}

/* Local Markdown target gate: production scans the tracked repository and the
 * script's isolated Git fixtures prove valid targets pass, missing targets
 * fail with source context, outbound symlinks fail containment, untracked
 * Markdown is ignored, and an empty scan exits fail-loud. No live services,
 * network, or repository files are used by the self-test. */
int t_markdown_links_gate(void)
{
    int failures = 0;
    int baseline_rc = run_gate_script(MARKDOWN_LINK_SCRIPT_REL, NULL);
    int env_rc = setenv("ZCL_MARKDOWN_LINKS_SELFTEST", "1", 1);
    int selftest_rc =
        env_rc == 0 ? run_gate_script(MARKDOWN_LINK_SCRIPT_REL, NULL) : -1;
    (void)unsetenv("ZCL_MARKDOWN_LINKS_SELFTEST");
    TEST("[lint-gate] local Markdown targets: baseline and selftest pass") {
        ASSERT(baseline_rc == 0);
        ASSERT(env_rc == 0);
        ASSERT(selftest_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* check-telemetry-ontology — a telemetry field that ships with no meaning row
 * must FAIL the gate and be NAMED. Proven four ways, because a gate that only
 * ever passes proves nothing:
 *   1. the real tree is clean (exit 0);
 *   2. the checked-in fixture manifest trips it (exit 1, not 2 — a real
 *      violation, not a scan error). That manifest now carries ONE ROW PER
 *      ROW KIND, because the two kinds prove coverage by different mechanisms
 *      and a fixture for one proves nothing about the other:
 *        FUNC  telemetry_unannotated_dump.c.fixture — a hand-written dumper
 *              emitting `field_that_ships_with_no_meaning`;
 *        TABLE telemetry_table_unannotated_fields.def — a table-driven domain
 *              whose TL_LEAF resolves to no ontology row. That is the blind
 *              spot the emission scan structurally cannot see: a table-driven
 *              domain emits everything from one generic renderer, so the scan
 *              extracts ZERO fields for it and its EXTRACTED floor still
 *              clears on the hand-written domains alone;
 *   3. an empty scan manifest is exit 2, so a broken scan can never be
 *      mistaken for a clean tree;
 *   4. the script's own `--selftest` runs the full 13-case matrix — including
 *      the cases that need a bad input built on the fly and so cannot be
 *      checked-in fixtures: a mis-paired `#define TL_SUB` over a field table,
 *      a domain registered but never pasted into g_fields[], a leaf count
 *      below its shrink-only floor, a `*_fill.c` provider that hand-writes
 *      json_push_kv_*, and both directions of fill-provider count drift.
 * The fixture manifest is APPENDED to the real one, so the trip runs against
 * the real ontology and the real floors. */
int t_telemetry_ontology_gate(void)
{
    int failures = 0;
    int baseline_rc = run_gate_script(TELEMETRY_ONTOLOGY_SCRIPT_REL, NULL);
    int trip_rc = run_gate_script_with_env(TELEMETRY_ONTOLOGY_SCRIPT_REL,
                                           TELEMETRY_ONTOLOGY_EXTRA_ENV,
                                           TELEMETRY_ONTOLOGY_EXTRA_REL);
    int hollow_rc = run_gate_script_with_env(TELEMETRY_ONTOLOGY_SCRIPT_REL,
                                             TELEMETRY_ONTOLOGY_MANIFEST_ENV,
                                             "");
    int matrix_rc = run_gate_script_selftest(TELEMETRY_ONTOLOGY_SCRIPT_REL);
    int recover_rc = run_gate_script(TELEMETRY_ONTOLOGY_SCRIPT_REL, NULL);
    TEST("[lint-gate] telemetry-ontology: clean, trips an unannotated FUNC "
         "field and an unannotated TABLE leaf, exit 2 on a hollow scan, full "
         "--selftest matrix green, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(trip_rc == 1);
        ASSERT(hollow_rc == 2);
        ASSERT(matrix_rc == 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E10a — framework shape RATCHET: an off-shape app/.c file (not in the
 * allowlist) trips the gate in RATCHET mode; removing it restores green. */
int t_e10_framework_shape_ratchet(void)
{
    int failures = 0;
    unlink_rel(E10_SHAPE_FIXTURE_DST);
    int baseline_rc = run_gate_script(E10_SHAPE_SCRIPT_REL, "RATCHET");
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E10_SHAPE_FIXTURE_DST) == 0 &&
                   write_file(path, "int e10_shape_fixture;\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E10_SHAPE_SCRIPT_REL, "RATCHET") : -1;
    unlink_rel(E10_SHAPE_FIXTURE_DST);
    int recover_rc = run_gate_script(E10_SHAPE_SCRIPT_REL, "RATCHET");
    TEST("[lint-gate] E10 framework-shape RATCHET: clean, trips off-shape, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E10b — no-raw-sqlite-in-controllers RATCHET: a NEW controller file
 * (not in the baseline) with a raw sqlite call trips the gate; removing
 * it restores green. */
int t_e10_no_raw_sqlite_ratchet(void)
{
    int failures = 0;
    unlink_rel(E10_SQL_FIXTURE_DST);
    int baseline_rc = run_gate_script(E10_SQL_SCRIPT_REL, "RATCHET");
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E10_SQL_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "void f(void){ sqlite3_prepare_v2(d, s, n, &st, 0); }\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E10_SQL_SCRIPT_REL, "RATCHET") : -1;
    unlink_rel(E10_SQL_FIXTURE_DST);
    int recover_rc = run_gate_script(E10_SQL_SCRIPT_REL, "RATCHET");
    TEST("[lint-gate] E10 no-raw-sqlite RATCHET: clean, trips new file, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate #22 — framework filename suffix (HARD): a file in a shape folder
 * whose name carries a FOREIGN shape suffix (here a *_controller.c planted
 * under app/services/src/) trips the gate; removing it restores green. */
int t_gate22_framework_filename_suffix(void)
{
    int failures = 0;
    unlink_rel(FSUF_FIXTURE_DST);
    int baseline_rc = run_gate_script(FSUF_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), FSUF_FIXTURE_DST) == 0 &&
                   write_file(path, "int fsuf_fixture;\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(FSUF_SCRIPT_REL, NULL) : -1;
    unlink_rel(FSUF_FIXTURE_DST);
    int recover_rc = run_gate_script(FSUF_SCRIPT_REL, NULL);
    TEST("[lint-gate] #22 framework-filename-suffix: clean, trips foreign suffix, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate P2 (docs/work/palace-design.md §3) — check-group-purpose (HARD): a
 * group node whose ci_group_purpose() case returns "" trips the gate; the
 * unmodified source is clean. Never touches the live codeindex_group.c —
 * copies it into test-tmp/, blanks one known case (lib/bloom) in the copy,
 * and points the gate at each fixture via ZCL_GROUP_PURPOSE_SRC. */
int t_gate_p2_group_purpose(void)
{
    int failures = 0;
    char real_path[PATH_MAX], ok_path[PATH_MAX], bad_path[PATH_MAX];
    char test_tmp_dir[PATH_MAX];
    int paths_ok =
        (repo_path(real_path, sizeof(real_path), GRPPURPOSE_REAL_SRC_REL) == 0 &&
         repo_path(ok_path, sizeof(ok_path), GRPPURPOSE_OK_FIXTURE_REL) == 0 &&
         repo_path(bad_path, sizeof(bad_path), GRPPURPOSE_BAD_FIXTURE_REL) == 0 &&
         repo_path(test_tmp_dir, sizeof(test_tmp_dir), "test-tmp") == 0)
            ? 1 : 0;
    if (paths_ok) (void)mkdir(test_tmp_dir, 0700);

    unlink_rel(GRPPURPOSE_OK_FIXTURE_REL);
    unlink_rel(GRPPURPOSE_BAD_FIXTURE_REL);

    int copied = (paths_ok && copy_file(real_path, ok_path) == 0) ? 0 : -1;

    char *ok_contents = NULL;
    int read_ok = (copied == 0) ? read_entire_file(ok_path, &ok_contents) : -1;

    const char *needle =
        "if (strcmp(group, \"lib/bloom\") == 0) return "
        "\"bloom filters + merkle proofs for lightweight block/tx filtering\";";
    const char *repl = "if (strcmp(group, \"lib/bloom\") == 0) return \"\";";
    char *bad_contents =
        (read_ok == 0) ? str_replace_once(ok_contents, needle, repl) : NULL;
    int wrote_bad = bad_contents ? write_file(bad_path, bad_contents) : -1;

    int ok_rc = (copied == 0 && read_ok == 0)
        ? run_gate_script_with_env2(GRPPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "FAIL",
                                    "ZCL_GROUP_PURPOSE_SRC", ok_path)
        : -1;
    int bad_rc = (wrote_bad == 0)
        ? run_gate_script_with_env2(GRPPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "FAIL",
                                    "ZCL_GROUP_PURPOSE_SRC", bad_path)
        : -1;
    int recover_rc = (copied == 0 && read_ok == 0)
        ? run_gate_script_with_env2(GRPPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "FAIL",
                                    "ZCL_GROUP_PURPOSE_SRC", ok_path)
        : -1;

    unlink_rel(GRPPURPOSE_OK_FIXTURE_REL);
    unlink_rel(GRPPURPOSE_BAD_FIXTURE_REL);
    free(ok_contents);
    free(bad_contents);

    TEST("[lint-gate] P2 group-purpose: clean copy passes, blanked purpose trips, recovers") {
        ASSERT(paths_ok);
        ASSERT(copied == 0);
        ASSERT(read_ok == 0);
        /* bad_contents == NULL means the needle wasn't found — the real
         * source's lib/bloom case text drifted out from under this fixture. */
        ASSERT(bad_contents != NULL);
        ASSERT(wrote_bad == 0);
        ASSERT(ok_rc == 0);
        ASSERT(bad_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate P1 (docs/work/palace-design.md §3) — check-file-purpose: a file whose
 * first code token precedes any comment (no derivable purpose) trips the gate
 * in FAIL mode; a file with a substantive leading block comment passes. The
 * gate is pointed at an isolated test-tmp/ fixture tree via
 * ZCL_FILE_PURPOSE_ROOT so it never scans (or depends on) the real tree. */
int t_gate_p1_file_purpose(void)
{
    int failures = 0;
    char root_abs[PATH_MAX], plant_abs[PATH_MAX];
    char bad_src[PATH_MAX], ok_src[PATH_MAX], dir_abs[PATH_MAX];
    int paths_ok =
        (repo_path(root_abs, sizeof(root_abs), FILEPURPOSE_ROOT_REL) == 0 &&
         repo_path(plant_abs, sizeof(plant_abs), FILEPURPOSE_PLANT_REL) == 0 &&
         repo_path(bad_src, sizeof(bad_src), FILEPURPOSE_BAD_FIXTURE_REL) == 0 &&
         repo_path(ok_src, sizeof(ok_src), FILEPURPOSE_OK_FIXTURE_REL) == 0)
            ? 1 : 0;

    /* Build test-tmp/_file_purpose_root_tmp/app/services/src level by level
     * (mkdir has no -p; EEXIST is fine). */
    int dirs_ok = 0;
    if (paths_ok) {
        static const char *const levels[] = {
            "test-tmp",
            FILEPURPOSE_ROOT_REL,
            FILEPURPOSE_ROOT_REL "/app",
            FILEPURPOSE_ROOT_REL "/app/services",
            FILEPURPOSE_ROOT_REL "/app/services/src",
        };
        dirs_ok = 1;
        for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
            if (repo_path(dir_abs, sizeof(dir_abs), levels[i]) != 0 ||
                (mkdir(dir_abs, 0700) != 0 && errno != EEXIST)) {
                dirs_ok = 0;
                break;
            }
        }
    }

    (void)unlink(plant_abs);
    int planted_bad = (dirs_ok && copy_file(bad_src, plant_abs) == 0) ? 0 : -1;
    int bad_rc = (planted_bad == 0)
        ? run_gate_script_with_env2(FILEPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "FAIL",
                                    "ZCL_FILE_PURPOSE_ROOT", root_abs)
        : -1;

    int planted_ok = (dirs_ok && copy_file(ok_src, plant_abs) == 0) ? 0 : -1;
    int ok_rc = (planted_ok == 0)
        ? run_gate_script_with_env2(FILEPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "FAIL",
                                    "ZCL_FILE_PURPOSE_ROOT", root_abs)
        : -1;

    /* RATCHET must also trip on the purpose-less file — it is NOT in the
     * shrink-only baseline (the baseline holds root-relative real-tree paths,
     * never fixture paths). */
    int ratchet_bad_rc = (planted_bad == 0 && copy_file(bad_src, plant_abs) == 0)
        ? run_gate_script_with_env2(FILEPURPOSE_SCRIPT_REL,
                                    "ZCL_LINT_MODE", "RATCHET",
                                    "ZCL_FILE_PURPOSE_ROOT", root_abs)
        : -1;

    (void)unlink(plant_abs);

    TEST("[lint-gate] P1 file-purpose: purpose-less fixture trips (FAIL+RATCHET), purposed passes") {
        ASSERT(paths_ok);
        ASSERT(dirs_ok);
        ASSERT(planted_bad == 0);
        ASSERT(bad_rc != 0);
        ASSERT(planted_ok == 0);
        ASSERT(ok_rc == 0);
        ASSERT(ratchet_bad_rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate P3 (docs/work/palace-design.md §3) — check-no-orphan-placement: a path
 * outside every known navigator top resolves to the catch-all "root" group and
 * trips the gate in FAIL/RATCHET mode; a lib/-placed path passes. The scan set
 * is overridden via ZCL_ORPHAN_PLACEMENT_FILES so git ls-files (which cannot
 * see an untracked planted file) is bypassed entirely. */
int t_gate_p3_orphan_placement(void)
{
    int failures = 0;

    int bad_rc = run_gate_script_with_env2(ORPHAN_SCRIPT_REL,
                                           "ZCL_LINT_MODE", "FAIL",
                                           "ZCL_ORPHAN_PLACEMENT_FILES",
                                           "_orphan_fixture_dir_tmp/orphan.c");
    int ok_rc = run_gate_script_with_env2(ORPHAN_SCRIPT_REL,
                                          "ZCL_LINT_MODE", "FAIL",
                                          "ZCL_ORPHAN_PLACEMENT_FILES",
                                          "lib/util/src/placed.c");
    /* RATCHET must also trip — the orphan path is not in the baseline. */
    int ratchet_bad_rc = run_gate_script_with_env2(ORPHAN_SCRIPT_REL,
                                                   "ZCL_LINT_MODE", "RATCHET",
                                                   "ZCL_ORPHAN_PLACEMENT_FILES",
                                                   "_orphan_fixture_dir_tmp/orphan.c");

    TEST("[lint-gate] P3 orphan-placement: rootless path trips (FAIL+RATCHET), lib/ path passes") {
        ASSERT(bad_rc != 0);
        ASSERT(ok_rc == 0);
        ASSERT(ratchet_bad_rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate E13 — check-consensus-parity HARD: the single most safety-critical
 * gate (docs/CONSENSUS_PARITY_DOCTRINE.md) has NO selftest today proving it
 * still fires. Plant a verbatim forbidden mechanism token
 * (VersionBitsState) under lib/validation/src (a scanned PATHS entry) —
 * must trip; remove — must recover. */
int t_e13_consensus_parity_fixture(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(CONSENSUS_PARITY_FIXTURE_DST);
    int baseline_rc = run_gate_script(CONSENSUS_PARITY_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path),
                             CONSENSUS_PARITY_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "/* Transient lint-gate selftest fixture for "
                       "check-consensus-parity (E13);\n"
                       " * planted+removed by test_make_lint_gates.c. Not "
                       "part of the build. */\n"
                       "static int VersionBitsState_fixture_probe(void) "
                       "{ return 0; }\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0
        ? run_gate_script(CONSENSUS_PARITY_SCRIPT_REL, NULL) : -1;
    unlink_rel(CONSENSUS_PARITY_FIXTURE_DST);
    int recover_rc = run_gate_script(CONSENSUS_PARITY_SCRIPT_REL, NULL);
    TEST("[lint-gate] E13 consensus-parity HARD: clean, trips on forbidden mechanism token, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate check-silent-errors-bool RATCHET: no selftest today proving a fresh
 * swallowed call-guard (`if (!call()) return false;`, no LOG_*, no
 * raw-return-ok marker) actually trips it. Plant under app/services/src (a
 * scanned dir) with a never-baselined key — must trip; remove — must
 * recover. */
int t_silent_errors_bool_fixture(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(SILENT_BOOL_FIXTURE_DST);
    int baseline_rc = run_gate_script(SILENT_BOOL_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path),
                             SILENT_BOOL_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "/* Transient lint-gate selftest fixture for "
                       "check-silent-errors-bool;\n"
                       " * planted+removed by test_make_lint_gates.c. Not "
                       "part of the build. */\n"
                       "#include <stdbool.h>\n\n"
                       "static bool fixture_fallible_call(void) "
                       "{ return true; }\n\n"
                       "bool _silent_bool_fixture_case(void)\n"
                       "{\n"
                       "    if (!fixture_fallible_call())\n"
                       "        return false;\n"
                       "    return true;\n"
                       "}\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0
        ? run_gate_script(SILENT_BOOL_SCRIPT_REL, NULL) : -1;
    unlink_rel(SILENT_BOOL_FIXTURE_DST);
    int recover_rc = run_gate_script(SILENT_BOOL_SCRIPT_REL, NULL);
    TEST("[lint-gate] check-silent-errors-bool RATCHET: clean, trips on new swallowed call-guard, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Returning LOG_* macros must match the enclosing function's return type:
 * LOG_ERR in bool functions used to return -1, which converts to true.
 *
 * The trip fixture's only violation sits directly after an #include: the
 * scanner resolves a function from the declaration text accumulated since the
 * last ';' or '}', and preprocessor lines used to be re-appended to that
 * accumulator, so any function declared after a directive carried a poisoned
 * '#' prefix, never resolved, and every LOG_* inside it went unchecked. The
 * trip therefore pins that path: if directive poisoning returns, this fixture
 * goes invisible, trip_rc hits 0, and the check fails. */
int t_log_macro_return_type_gate(void)
{
    int failures = 0;
    unlink_rel(LOG_MACRO_RETURN_FIXTURE_DST);
    int baseline_rc = run_gate_script(LOG_MACRO_RETURN_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted =
        (repo_path(path, sizeof(path), LOG_MACRO_RETURN_FIXTURE_DST) == 0 &&
         write_file(path,
                    "#include <stdbool.h>\n"
                    "#include \"util/log_macros.h\"\n"
                    "bool bad_bool(void)\n"
                    "{\n"
                    "    LOG_ERR(\"fixture\", \"bad\");\n"
                    "    return true;\n"
                    "}\n"
                    "int plain_int_after_brace(void) { return 0; }\n") == 0)
            ? 0
            : -1;
    int trip_rc =
        planted == 0 ? run_gate_script(LOG_MACRO_RETURN_SCRIPT_REL, NULL) : -1;
    unlink_rel(LOG_MACRO_RETURN_FIXTURE_DST);
    int recover_rc = run_gate_script(LOG_MACRO_RETURN_SCRIPT_REL, NULL);

    TEST("[lint-gate] LOG_* return-type gate: clean, trips after #include, "
         "recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E11 — doc accuracy: the in-tree DEFENSIVE_CODING.md gate block matches
 * the Makefile lint: target, so the gate passes.
 *
 * The clean-run assertion alone cannot tell "the docs are right" from "the
 * gate stopped looking". It could not: E11 checked exactly one filename, so
 * docs/BUILD.md ("40 defensive-coding gates") and docs/TENACITY.md ("36 lint
 * gates") sat wrong against a real list of 98 with this test green. E11 now
 * derives the count and scans every in-tree .md, and the plant/trip/recover
 * case below proves that scan is live: a stale count written into a doc the
 * gate has never heard of must fail it. The fixture states a deliberately
 * impossible count, so the case stays valid as gates are added or removed. */
int t_e11_doc_accuracy(void)
{
    int failures = 0;
    unlink_rel(E11_FIXTURE_DST);
    int baseline_rc = run_gate_script(E11_SCRIPT_REL, NULL);

    char path[PATH_MAX];
    int planted = -1;
    if (repo_path(path, sizeof(path), E11_FIXTURE_DST) == 0)
        planted = write_file(path,
                       "# E11 fixture\n\n"
                       "This page claims 999999 lint gates, which the repo\n"
                       "cannot have. E11 must reject it even though no code\n"
                       "names this file.\n");
    int trip_rc = run_gate_script(E11_SCRIPT_REL, NULL);

    unlink_rel(E11_FIXTURE_DST);
    int recover_rc = run_gate_script(E11_SCRIPT_REL, NULL);

    TEST("[lint-gate] E11 gate list matches Makefile; stale count in an "
         "unnamed doc trips it") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Model AR lifecycle gate — model sources must not hand-run save callback
 * internals, and real db_<model>_save() definitions must reach the AR save
 * macros so validation and hooks stay one mechanical lifecycle. */
int t_model_ar_lifecycle_gate(void)
{
    int failures = 0;
    unlink_rel(MODEL_AR_FIXTURE_DST);
    int baseline_rc = run_gate_script(MODEL_AR_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted =
        (repo_path(path, sizeof(path), MODEL_AR_FIXTURE_DST) == 0 &&
         write_file(path,
                    "#include \"models/activerecord.h\"\n"
                    "void fixture(struct ar_callbacks *cbs, void *row) {\n"
                    "    ar_run_after_save(cbs, row);\n"
                    "}\n") == 0)
            ? 0
            : -1;
    int direct_trip_rc =
        planted == 0 ? run_gate_script(MODEL_AR_SCRIPT_REL, NULL) : -1;
    unlink_rel(MODEL_AR_FIXTURE_DST);
    int planted_bare_save =
        (repo_path(path, sizeof(path), MODEL_AR_FIXTURE_DST) == 0 &&
         write_file(path,
                    "#include <stdbool.h>\n"
                    "struct node_db;\n"
                    "bool db_fixture_save(struct node_db *ndb, const void *row) {\n"
                    "    (void)ndb;\n"
                    "    (void)row;\n"
                    "    return true;\n"
                    "}\n") == 0)
            ? 0
            : -1;
    int bare_save_trip_rc =
        planted_bare_save == 0 ? run_gate_script(MODEL_AR_SCRIPT_REL, NULL) : -1;
    unlink_rel(MODEL_AR_FIXTURE_DST);
    int recover_rc = run_gate_script(MODEL_AR_SCRIPT_REL, NULL);

    TEST("[lint-gate] model AR lifecycle gate: clean, trips bypasses, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(direct_trip_rc != 0);
        ASSERT(planted_bare_save == 0);
        ASSERT(bare_save_trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* E2 — one-result-type RATCHET: a NEW (non-baselined) service file that
 * returns bare bool (no struct zcl_result) trips the gate; removing it
 * restores green. */
int t_e2_one_result_type(void)
{
    int failures = 0;
    unlink_rel(E2_FIXTURE_DST);
    int baseline_rc = run_gate_script(E2_SCRIPT_REL, NULL);
    char path[PATH_MAX];
    int planted = (repo_path(path, sizeof(path), E2_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "#include <stdbool.h>\n"
                       "bool e2_fixture(void){ return false; }\n") == 0)
                  ? 0 : -1;
    int trip_rc = planted == 0 ? run_gate_script(E2_SCRIPT_REL, NULL) : -1;
    unlink_rel(E2_FIXTURE_DST);
    int recover_rc = run_gate_script(E2_SCRIPT_REL, NULL);
    TEST("[lint-gate] E2 one-result-type RATCHET: clean, trips bare-bool service, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Phase 3 service-result-convergence shrinking-floor ratchet: unlike E2
 * (file-granularity — clean the moment a file mentions zcl_result anywhere),
 * this gate counts exported bare-bool function DEFINITIONS per file and
 * fails on: (a) a baselined file's live count GROWING past its recorded
 * count, (b) a NEW unbaselined/unmarked file with any legacy bool export,
 * (c) a baseline entry whose file no longer exists, and (d) a baseline
 * entry left behind for a file that is now clean or marker-exempt (the
 * "shrinking floor"). Run hermetically via ZCL_SERVICE_RESULT_CONVERGENCE_
 * SCAN_DIR/_BASELINE overrides so it never mutates the real tree/baseline. */
int t_service_result_convergence_ratchet(void)
{
    int failures = 0;
    char test_tmp[PATH_MAX];
    char scan_dir[PATH_MAX];
    char keep_path[PATH_MAX];
    char fixture_path[PATH_MAX];
    char baseline_path[PATH_MAX];

    if (repo_path(test_tmp, sizeof(test_tmp), "test-tmp") != 0 ||
        repo_path(scan_dir, sizeof(scan_dir), SVC_CONV_SCAN_DIR_REL) != 0 ||
        repo_path(keep_path, sizeof(keep_path), SVC_CONV_KEEP_REL) != 0 ||
        repo_path(fixture_path, sizeof(fixture_path),
                  SVC_CONV_FIXTURE_REL) != 0 ||
        repo_path(baseline_path, sizeof(baseline_path),
                  SVC_CONV_BASELINE_REL) != 0) {
        fprintf(stderr,
                "[lint-gate] could not resolve service-result-convergence "
                "fixture paths\n");
        return 1;
    }
    (void)mkdir(test_tmp, 0700);
    (void)mkdir(scan_dir, 0700);
    (void)unlink(fixture_path);
    (void)unlink(baseline_path);

    /* keep.c: a permanent, always-clean (0 legacy exports) file so the
     * gate's non-empty-scan floor is satisfied in every sub-case below,
     * independent of whatever fixture.c is doing. */
    int wrote_keep = write_file(keep_path,
        "int svc_conv_keep_placeholder;\n");

    /* Case A: fixture.c exports exactly 2 legacy bool functions; baseline
     * records it at 2 — matched, must be clean. */
    int wrote_fixture_2 = write_file(fixture_path,
        "#include <stdbool.h>\n"
        "bool svc_conv_fixture_a(void)\n"
        "{\n"
        "    return false;\n"
        "}\n"
        "\n"
        "bool svc_conv_fixture_b(void)\n"
        "{\n"
        "    return false;\n"
        "}\n");
    char baseline_2[PATH_MAX + 16];
    (void)snprintf(baseline_2, sizeof(baseline_2), "%s 2\n", SVC_CONV_FIXTURE_REL);
    int wrote_baseline_2 = write_file(baseline_path, baseline_2);
    int matched_rc =
        (wrote_keep == 0 && wrote_fixture_2 == 0 && wrote_baseline_2 == 0)
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;

    /* Case B: same fixture (still 2), baseline lowered to 1 — must trip as
     * a REGRESSION (grown past its recorded count). */
    char baseline_1[PATH_MAX + 16];
    (void)snprintf(baseline_1, sizeof(baseline_1), "%s 1\n", SVC_CONV_FIXTURE_REL);
    int wrote_baseline_1 = write_file(baseline_path, baseline_1);
    int grown_rc =
        wrote_baseline_1 == 0
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;
    char grown_out_path[PATH_MAX];
    char *grown_out = NULL;
    int grown_read =
        (grown_rc >= 0 &&
         lint_gate_out_path(grown_out_path, sizeof(grown_out_path)) == 0)
            ? read_entire_file(grown_out_path, &grown_out)
            : -1;

    /* Case C: same fixture (2), EMPTY baseline — must trip as a NEW
     * unlisted file with legacy bool exports. */
    int wrote_baseline_empty = write_file(baseline_path, "");
    int new_rc =
        wrote_baseline_empty == 0
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;
    char new_out_path[PATH_MAX];
    char *new_out = NULL;
    int new_read =
        (new_rc >= 0 &&
         lint_gate_out_path(new_out_path, sizeof(new_out_path)) == 0)
            ? read_entire_file(new_out_path, &new_out)
            : -1;

    /* Case D: fixture.c REMOVED, baseline still references it at 2 — must
     * trip as a STALE baseline entry (file no longer exists). */
    (void)unlink(fixture_path);
    int wrote_baseline_stale = write_file(baseline_path, baseline_2);
    int stale_rc =
        wrote_baseline_stale == 0
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;
    char stale_out_path[PATH_MAX];
    char *stale_out = NULL;
    int stale_read =
        (stale_rc >= 0 &&
         lint_gate_out_path(stale_out_path, sizeof(stale_out_path)) == 0)
            ? read_entire_file(stale_out_path, &stale_out)
            : -1;

    /* Case E: fixture.c restored but now fully CLEAN (0 legacy exports),
     * baseline still lists it at 2 — must trip as a stale "now clean"
     * entry (the shrinking-floor requirement: a converted file cannot
     * stay listed). */
    int wrote_fixture_clean = write_file(fixture_path,
        "int svc_conv_fixture_now_clean;\n");
    int wrote_baseline_for_clean = write_file(baseline_path, baseline_2);
    int clean_stale_rc =
        (wrote_fixture_clean == 0 && wrote_baseline_for_clean == 0)
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;
    char clean_out_path[PATH_MAX];
    char *clean_out = NULL;
    int clean_read =
        (clean_stale_rc >= 0 &&
         lint_gate_out_path(clean_out_path, sizeof(clean_out_path)) == 0)
            ? read_entire_file(clean_out_path, &clean_out)
            : -1;

    /* Case F — one-line-brace regression fixture: a signature whose opening
     * brace shares the (possibly wrapped) signature's last line instead of
     * sitting alone, e.g. `bool foo(void) {` or a multi-arg wrap ending
     * `) {`. Before the awk fix, count_legacy_bool_exports() only matched a
     * line that was EXACTLY `{` after trimming, so both styles below were
     * silently uncounted — a regression could slip past the shrinking-floor
     * gate. With an EMPTY baseline this must trip as a NEW unlisted file. */
    int wrote_fixture_oneline = write_file(fixture_path,
        "#include <stdbool.h>\n"
        "bool svc_conv_fixture_oneline(void) {\n"
        "    return false;\n"
        "}\n"
        "\n"
        "bool svc_conv_fixture_wrapped(int a,\n"
        "    int b) {\n"
        "    return false;\n"
        "}\n");
    int wrote_baseline_empty3 = write_file(baseline_path, "");
    int oneline_rc =
        (wrote_fixture_oneline == 0 && wrote_baseline_empty3 == 0)
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;
    char oneline_out_path[PATH_MAX];
    char *oneline_out = NULL;
    int oneline_read =
        (oneline_rc >= 0 &&
         lint_gate_out_path(oneline_out_path, sizeof(oneline_out_path)) == 0)
            ? read_entire_file(oneline_out_path, &oneline_out)
            : -1;

    /* Recovery: remove fixture.c and the baseline entry entirely — only
     * keep.c (0 legacy exports, unbaselined) remains, so the gate must
     * report clean again. */
    (void)unlink(fixture_path);
    int wrote_baseline_empty2 = write_file(baseline_path, "");
    int recover_rc =
        wrote_baseline_empty2 == 0
            ? run_gate_script_with_env2(SVC_CONV_SCRIPT_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_SCAN_DIR",
                  SVC_CONV_SCAN_DIR_REL,
                  "ZCL_SERVICE_RESULT_CONVERGENCE_BASELINE",
                  SVC_CONV_BASELINE_REL)
            : -999;

    (void)unlink(fixture_path);
    (void)unlink(keep_path);
    (void)unlink(baseline_path);
    (void)rmdir(scan_dir);

    TEST("[lint-gate] service-result-convergence shrinking-floor: matched clean, grown/new/stale/clean-stale/oneline-brace all trip, recovers") {
        ASSERT(matched_rc == 0);
        ASSERT(grown_rc != 0);
        ASSERT(grown_read == 0);
        ASSERT(grown_out != NULL && strstr(grown_out, "REGRESSION") != NULL);
        ASSERT(new_rc != 0);
        ASSERT(new_read == 0);
        ASSERT(new_out != NULL && strstr(new_out, "NEW file") != NULL);
        ASSERT(stale_rc != 0);
        ASSERT(stale_read == 0);
        ASSERT(stale_out != NULL &&
               strstr(stale_out, "no longer exists") != NULL);
        ASSERT(clean_stale_rc != 0);
        ASSERT(clean_read == 0);
        ASSERT(clean_out != NULL &&
               strstr(clean_out, "fully converted") != NULL);
        ASSERT(oneline_rc != 0);
        ASSERT(oneline_read == 0);
        ASSERT(oneline_out != NULL &&
               strstr(oneline_out, "has 2 legacy bool export") != NULL);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;

    free(grown_out);
    free(new_out);
    free(stale_out);
    free(clean_out);
    free(oneline_out);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_ql_unit;

#endif /* ZCL_TESTING */
