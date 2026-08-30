/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the gates that keep every long-running thing on the liveness
 * tree and every privileged transition witnessed: the thread-supervision and
 * supervisor-registration ratchets, the supervisor-domain worker lock-in, the
 * hot-swap eligible/swappable manifest shape and static-state gates, the
 * privileged-transition receipt gate, the trust-state ordering gate, the
 * blocker-escape registration gate, and the meta gate that makes a lint gate
 * whose scan matched nothing fail loudly instead of passing hollow.
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

/* Gate #23 — universal thread supervision ratchet. Runs hermetically via the
 * ZCL_THREADSUP_SCAN_ROOTS / ZCL_THREADSUP_BASELINE overrides so it never
 * touches the live tree/baseline: an unaccounted thread_registry_spawn trips
 * the gate; a baseline entry OR a // supervised: marker clears it; a stale
 * baseline entry (no matching uncovered spawn) trips it (shrink-only). */
#define THREADSUP_SCRIPT_REL   "tools/lint/check_thread_supervision.sh"
#define THREADSUP_SCAN_DIR_REL "test-tmp/_threadsup_scan_dir_tmp"
#define THREADSUP_KEEP_REL     "test-tmp/_threadsup_scan_dir_tmp/keep.c"
#define THREADSUP_FIXTURE_REL  "test-tmp/_threadsup_scan_dir_tmp/_threadsup_probe_tmp.c"
#define THREADSUP_BASELINE_REL "test-tmp/_threadsup_baseline_tmp.txt"

int t_thread_supervision_ratchet(void)
{
    int failures = 0;
    char test_tmp[PATH_MAX];
    char scan_dir[PATH_MAX];
    char keep_path[PATH_MAX];
    char fixture_path[PATH_MAX];
    char baseline_path[PATH_MAX];

    if (repo_path(test_tmp, sizeof(test_tmp), "test-tmp") != 0 ||
        repo_path(scan_dir, sizeof(scan_dir), THREADSUP_SCAN_DIR_REL) != 0 ||
        repo_path(keep_path, sizeof(keep_path), THREADSUP_KEEP_REL) != 0 ||
        repo_path(fixture_path, sizeof(fixture_path),
                  THREADSUP_FIXTURE_REL) != 0 ||
        repo_path(baseline_path, sizeof(baseline_path),
                  THREADSUP_BASELINE_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve thread-supervision "
                        "fixture paths\n");
        return 1;
    }
    (void)mkdir(test_tmp, 0700);
    (void)mkdir(scan_dir, 0700);

    /* Non-spawning keep file so the non-empty-scan floor is always met. */
    int wrote_keep = write_file(keep_path, "int threadsup_keep_placeholder;\n");

    /* Case A: an unaccounted spawn + EMPTY baseline must trip. */
    int wrote_fixture_spawn = write_file(fixture_path,
        "void demo(void)\n"
        "{\n"
        "    thread_registry_spawn(\"zcl_probe_thread\", worker, 0, 0);\n"
        "}\n");
    int wrote_empty_baseline = write_file(baseline_path, "");
    int unaccounted_rc =
        (wrote_keep == 0 && wrote_fixture_spawn == 0 &&
         wrote_empty_baseline == 0)
            ? run_gate_script_with_env2(THREADSUP_SCRIPT_REL,
                  "ZCL_THREADSUP_SCAN_ROOTS", THREADSUP_SCAN_DIR_REL,
                  "ZCL_THREADSUP_BASELINE", THREADSUP_BASELINE_REL)
            : -999;
    char un_out_path[PATH_MAX];
    char *un_out = NULL;
    int un_read =
        (unaccounted_rc >= 0 &&
         lint_gate_out_path(un_out_path, sizeof(un_out_path)) == 0)
            ? read_entire_file(un_out_path, &un_out)
            : -1;

    /* Case B: same fixture, thread now BASELINED — must pass. */
    int wrote_baseline_entry = write_file(baseline_path,
        "zcl_probe_thread  bounded  self-test fixture thread\n");
    int baselined_rc =
        wrote_baseline_entry == 0
            ? run_gate_script_with_env2(THREADSUP_SCRIPT_REL,
                  "ZCL_THREADSUP_SCAN_ROOTS", THREADSUP_SCAN_DIR_REL,
                  "ZCL_THREADSUP_BASELINE", THREADSUP_BASELINE_REL)
            : -999;

    /* Case C: same thread, EMPTY baseline but the spawn now carries a
     * // supervised: marker — must pass. */
    int wrote_fixture_marked = write_file(fixture_path,
        "void demo(void)\n"
        "{\n"
        "    // supervised:zcl_probe_thread\n"
        "    thread_registry_spawn(\"zcl_probe_thread\", worker, 0, 0);\n"
        "}\n");
    int wrote_empty_baseline2 = write_file(baseline_path, "");
    int marked_rc =
        (wrote_fixture_marked == 0 && wrote_empty_baseline2 == 0)
            ? run_gate_script_with_env2(THREADSUP_SCRIPT_REL,
                  "ZCL_THREADSUP_SCAN_ROOTS", THREADSUP_SCAN_DIR_REL,
                  "ZCL_THREADSUP_BASELINE", THREADSUP_BASELINE_REL)
            : -999;

    /* Case D: fixture no longer spawns, baseline still lists the thread —
     * must trip as a STALE (shrink-only) entry. */
    int wrote_fixture_nospawn = write_file(fixture_path,
        "int threadsup_fixture_now_quiet;\n");
    int wrote_baseline_stale = write_file(baseline_path,
        "zcl_probe_thread  bounded  self-test fixture thread\n");
    int stale_rc =
        (wrote_fixture_nospawn == 0 && wrote_baseline_stale == 0)
            ? run_gate_script_with_env2(THREADSUP_SCRIPT_REL,
                  "ZCL_THREADSUP_SCAN_ROOTS", THREADSUP_SCAN_DIR_REL,
                  "ZCL_THREADSUP_BASELINE", THREADSUP_BASELINE_REL)
            : -999;
    char stale_out_path[PATH_MAX];
    char *stale_out = NULL;
    int stale_read =
        (stale_rc >= 0 &&
         lint_gate_out_path(stale_out_path, sizeof(stale_out_path)) == 0)
            ? read_entire_file(stale_out_path, &stale_out)
            : -1;

    (void)unlink(fixture_path);
    (void)unlink(keep_path);
    (void)unlink(baseline_path);
    (void)rmdir(scan_dir);

    TEST("[lint-gate] thread-supervision ratchet: unaccounted/stale trip, baselined/marked pass") {
        ASSERT(unaccounted_rc != 0);
        ASSERT(un_read == 0);
        ASSERT(un_out != NULL && strstr(un_out, "unaccounted") != NULL);
        ASSERT(baselined_rc == 0);
        ASSERT(marked_rc == 0);
        ASSERT(stale_rc != 0);
        ASSERT(stale_read == 0);
        ASSERT(stale_out != NULL && strstr(stale_out, "STALE") != NULL);
        PASS();
    } _test_next:;

    free(un_out);
    free(stale_out);
    return failures;
}

/* Gate #15 — supervisor-registration ratchet, scoped to
 * app/controllers, app/conditions, app/jobs, config/src, and audited
 * lib/net, lib/health, lib/rpc (see check_supervisor_registration.sh). Runs
 * hermetically via ZCL_SERVICES_DIR / ZCL_SUPREG_BASELINE so it never
 * touches the live tree/baseline: a planted unsupervised raw pthread_create
 * (the acceptance-bar shape: "a planted unsupervised thread in
 * app/controllers") trips the gate; a baseline entry OR a
 * // supervisor-ok: marker clears it; the real (widened) tree stays green. */
#define SUPREG_SCRIPT_REL   "tools/scripts/check_supervisor_registration.sh"
#define SUPREG_SCAN_DIR_REL "test-tmp/_supreg_scan_dir_tmp"
#define SUPREG_KEEP_REL     "test-tmp/_supreg_scan_dir_tmp/keep.c"
#define SUPREG_FIXTURE_REL  "test-tmp/_supreg_scan_dir_tmp/_supreg_probe_tmp.c"
#define SUPREG_BASELINE_REL "test-tmp/_supreg_baseline_tmp.txt"

int t_supervisor_registration_widened_ratchet(void)
{
    int failures = 0;
    char scan_dir[PATH_MAX];
    char keep_path[PATH_MAX];
    char fixture_path[PATH_MAX];
    char baseline_path[PATH_MAX];

    if (repo_path(scan_dir, sizeof(scan_dir), SUPREG_SCAN_DIR_REL) != 0 ||
        repo_path(keep_path, sizeof(keep_path), SUPREG_KEEP_REL) != 0 ||
        repo_path(fixture_path, sizeof(fixture_path),
                  SUPREG_FIXTURE_REL) != 0 ||
        repo_path(baseline_path, sizeof(baseline_path),
                  SUPREG_BASELINE_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve supervisor-registration "
                        "fixture paths\n");
        return 1;
    }
    (void)mkdir(scan_dir, 0700);

    /* Non-spawning keep file so the non-empty-scan floor is always met. */
    int wrote_keep = write_file(keep_path, "int supreg_keep_placeholder;\n");

    /* Case A: an unsupervised raw pthread_create (mirrors
     * api_controller.c's api_start_detached_thread shape) + EMPTY baseline
     * must trip — this is the acceptance-bar plant. */
    int wrote_fixture_spawn = write_file(fixture_path,
        "#include <pthread.h>\n"
        "static void *worker(void *arg) { (void)arg; return 0; }\n"
        "void demo(void)\n"
        "{\n"
        "    pthread_t t;\n"
        "    pthread_create(&t, 0, worker, 0);\n"
        "}\n");
    int wrote_empty_baseline = write_file(baseline_path, "");
    int unaccounted_rc =
        (wrote_keep == 0 && wrote_fixture_spawn == 0 &&
         wrote_empty_baseline == 0)
            ? run_gate_script_with_env2(SUPREG_SCRIPT_REL,
                  "ZCL_SERVICES_DIR", SUPREG_SCAN_DIR_REL,
                  "ZCL_SUPREG_BASELINE", SUPREG_BASELINE_REL)
            : -999;
    char un_out_path[PATH_MAX];
    char *un_out = NULL;
    int un_read =
        (unaccounted_rc >= 0 &&
         lint_gate_out_path(un_out_path, sizeof(un_out_path)) == 0)
            ? read_entire_file(un_out_path, &un_out)
            : -1;

    /* Case B: same fixture, file now BASELINED — must pass. */
    int wrote_baseline_entry = write_file(baseline_path,
        SUPREG_FIXTURE_REL "\n");
    int baselined_rc =
        wrote_baseline_entry == 0
            ? run_gate_script_with_env2(SUPREG_SCRIPT_REL,
                  "ZCL_SERVICES_DIR", SUPREG_SCAN_DIR_REL,
                  "ZCL_SUPREG_BASELINE", SUPREG_BASELINE_REL)
            : -999;

    /* Case C: same shape, EMPTY baseline but a // supervisor-ok: marker
     * — must pass. */
    int wrote_fixture_marked = write_file(fixture_path,
        "#include <pthread.h>\n"
        "static void *worker(void *arg) { (void)arg; return 0; }\n"
        "// supervisor-ok:probe-fixture\n"
        "void demo(void)\n"
        "{\n"
        "    pthread_t t;\n"
        "    pthread_create(&t, 0, worker, 0);\n"
        "}\n");
    int wrote_empty_baseline2 = write_file(baseline_path, "");
    int marked_rc =
        (wrote_fixture_marked == 0 && wrote_empty_baseline2 == 0)
            ? run_gate_script_with_env2(SUPREG_SCRIPT_REL,
                  "ZCL_SERVICES_DIR", SUPREG_SCAN_DIR_REL,
                  "ZCL_SUPREG_BASELINE", SUPREG_BASELINE_REL)
            : -999;

    /* Case D: the real (widened) tree, with its OWN default scan roots and
     * real baseline, must stay green. */
    int real_tree_rc = run_gate_script(SUPREG_SCRIPT_REL, NULL);

    (void)unlink(fixture_path);
    (void)unlink(keep_path);
    (void)unlink(baseline_path);
    (void)rmdir(scan_dir);

    TEST("[lint-gate] supervisor-registration widened ratchet: planted "
         "app/controllers-shaped thread trips; baselined/marked pass; real "
         "widened tree stays green") {
        ASSERT(unaccounted_rc != 0);
        ASSERT(un_read == 0);
        ASSERT(un_out != NULL &&
               strstr(un_out, "NEW long-running service") != NULL);
        ASSERT(baselined_rc == 0);
        ASSERT(marked_rc == 0);
        ASSERT(real_tree_rc == 0);
        PASS();
    } _test_next:;

    free(un_out);
    return failures;
}

/* Gate #21 background-worker lock-in (Shape 5 — Supervisor). The widened
 * check_supervisor_domain.sh ALSO scans the boot worker file and fails any
 * thread spawn not paired with supervisor_register_in_domain. This self-test
 * proves the widened scan has teeth and the (intentionally empty) baseline is
 * honest: plant a worker that spawns a pthread with NO register and assert the
 * gate FLAGS it (exit != 0); then a worker WITH a register and assert it
 * PASSES (exit == 0). Fixtures are fed via ZCL_SUPERVISOR_WORKER_FILES so the
 * result does not depend on the live boot_background_workers.c state. */
int t_gate21_supervisor_worker_lockin(void)
{
    int failures = 0;
    char bad_path[PATH_MAX];
    char ok_path[PATH_MAX];
    if (repo_path(bad_path, sizeof(bad_path), SUPDOM_BAD_WORKER_REL) != 0 ||
        repo_path(ok_path, sizeof(ok_path), SUPDOM_OK_WORKER_REL) != 0) {
        fprintf(stderr,
                "[lint-gate] could not resolve supervisor worker fixture paths\n");
        return 1;
    }

    /* Unsupervised worker: spawns a thread, never registers a contract. */
    const char *bad =
        "/* fixture: boot background worker without a liveness contract */\n"
        "void *worker(void *a){ return a; }\n"
        "int boot_start_fixture_service(void){\n"
        "    pthread_create(&t, 0, worker, 0);\n"
        "    return 0;\n"
        "}\n";
    /* Same worker, now paired with a domain registration. */
    const char *ok =
        "/* fixture: boot background worker with a liveness contract */\n"
        "void *worker(void *a){ return a; }\n"
        "int boot_start_fixture_service(void){\n"
        "    pthread_create(&t, 0, worker, 0);\n"
        "    supervisor_register_in_domain(g_op_sup, &g_fixture_contract);\n"
        "    return 0;\n"
        "}\n";

    (void)unlink(bad_path);
    (void)unlink(ok_path);
    int planted_bad = write_file(bad_path, bad);
    int trip_rc = planted_bad == 0
        ? run_gate_script_with_worker_files(SUPDOM_SCRIPT_REL, "FAIL",
                                            SUPDOM_BAD_WORKER_REL)
        : -1;
    (void)unlink(bad_path);

    int planted_ok = write_file(ok_path, ok);
    int pass_rc = planted_ok == 0
        ? run_gate_script_with_worker_files(SUPDOM_SCRIPT_REL, "FAIL",
                                            SUPDOM_OK_WORKER_REL)
        : -1;
    (void)unlink(ok_path);

    TEST("[lint-gate] #21 supervisor worker lock-in: unsupervised spawn trips, registered passes") {
        ASSERT(planted_bad == 0);
        ASSERT(trip_rc != 0);
        ASSERT(planted_ok == 0);
        ASSERT(pass_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* META-GATE: every gate hardened this wave must FAIL LOUD (exit 2) on an empty
 * scan set instead of reporting "clean" exit 0 (a hollow pass). Each gate
 * exposes a ZCL_*_SCAN_* override of its scan root so we can point it at a
 * guaranteed-empty dir (it EXISTS — a bare -d check would pass — but holds zero
 * source files, the exact hollow vector). See
 * docs/work/lint-gate-hollowness-audit.md. */
/* Run a hot-swap manifest gate against a specific manifest fixture by exporting
 * ZCL_HOTSWAP_MANIFEST (resolved to an absolute path). */
int run_hotswap_gate_with_manifest(const char *script_rel,
                                          const char *manifest_rel)
{
    char manifest_abs[PATH_MAX];
    if (repo_path(manifest_abs, sizeof(manifest_abs), manifest_rel) != 0)
        return -1;
    return run_gate_script_with_env(script_rel, "ZCL_HOTSWAP_MANIFEST",
                                    manifest_abs);
}

int t_hotswap_eligible_scope_gate(void)
{
    int failures = 0;
    TEST("hotswap eligible-scope gate: real manifest passes, forbidden root trips") {
        /* The committed manifest is all app-layer surfaces → clean (exit 0). */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_SCOPE_SCRIPT_REL,
                                              HOTSWAP_MANIFEST_REL) == 0);
        /* A seeded manifest that lists a lib/consensus TU trips the gate
         * (exit 1) — proof it is not hollow. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_SCOPE_SCRIPT_REL,
                                              HOTSWAP_BAD_SCOPE_MANIFEST_REL) == 1);
        /* An app-layer TU that does NOT invoke ZCL_HOTSWAP_EXPORT_LEAVES (so it
         * could never actually export a generation) also trips the gate —
         * proof the macro-presence check added in Wave 3.1 is not hollow. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_SCOPE_SCRIPT_REL,
                                              HOTSWAP_NO_MACRO_MANIFEST_REL) == 1);
        /* Recovery: back on the real manifest the gate passes again. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_SCOPE_SCRIPT_REL,
                                              HOTSWAP_MANIFEST_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Run the swappable-shape gate against a specific allowlist fixture by
 * exporting ZCL_HOTSWAP_SWAPPABLE_MANIFEST (resolved to an absolute path). */
int run_hotswap_swappable_gate(const char *manifest_rel)
{
    char manifest_abs[PATH_MAX];
    if (repo_path(manifest_abs, sizeof(manifest_abs), manifest_rel) != 0)
        return -1;
    return run_gate_script_with_env(HOTSWAP_SWAPPABLE_SCRIPT_REL,
                                    "ZCL_HOTSWAP_SWAPPABLE_MANIFEST",
                                    manifest_abs);
}

int t_hotswap_swappable_shape_gate(void)
{
    int failures = 0;
    TEST("hotswap swappable-shape gate: real allowlist passes, forbidden root trips") {
        /* The committed allowlist is all shape-leaf surfaces → clean (exit 0). */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        /* A seeded allowlist that points a row at a lib/consensus TU trips
         * the gate (exit 1) — proof the shape half is not hollow. */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_BAD_MANIFEST_REL) == 1);
        char manifest_abs[PATH_MAX], islands_abs[PATH_MAX];
        ASSERT(repo_path(manifest_abs, sizeof(manifest_abs),
                         HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        ASSERT(repo_path(islands_abs, sizeof(islands_abs),
                         HOTSWAP_ISLAND_BAD_SCOPE_REL) == 0);
        /* A valid owner cannot smuggle storage ownership into its island. */
        ASSERT(run_gate_script_with_env2(
                   HOTSWAP_SWAPPABLE_SCRIPT_REL,
                   "ZCL_HOTSWAP_SWAPPABLE_MANIFEST", manifest_abs,
                   "ZCL_HOTSWAP_ISLAND_MANIFEST", islands_abs) == 1);
        /* Recovery: back on the real allowlist the gate passes again. */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The READY-read-only half of the hard line. Before the swappable def carried a
 * leaf column this gate checked shape FOLDERS only: a leaf that was mutating or
 * non-READY reached the runtime unchallenged, invisible only because the six
 * allowlisted files happened to match config/hotswap_eligible.def. Both seeded
 * fixtures below MUST trip, or the widened batch has no static guard. */
int t_hotswap_swappable_leaf_contract_gate(void)
{
    int failures = 0;
    TEST("hotswap swappable gate: a non-READY_READ leaf and a duplicate leaf trip") {
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        /* An in-shape controller row whose leaf list names a mutating
         * (ZCL_COMMAND_READY_COMMAND) leaf trips the gate (exit 1). */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_NOT_READY_READ_REL) == 1);
        /* One leaf claimed by two source files trips the gate (exit 1) — a leaf
         * belongs to exactly one module, so two modules can never both publish
         * a handler for it. */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_DUP_LEAF_REL) == 1);
        /* Recovery. */
        ASSERT(run_hotswap_swappable_gate(HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_hotswap_static_state_gate(void)
{
    int failures = 0;
    TEST("hotswap static-state gate: real manifest passes, mutable static trips") {
        /* Every committed eligible TU is free of mutable file-scope statics. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_STATIC_SCRIPT_REL,
                                              HOTSWAP_MANIFEST_REL) == 0);
        /* A seeded manifest that points at a fixture TU carrying a mutable
         * file-scope static trips the gate (exit 1). */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_STATIC_SCRIPT_REL,
                                              HOTSWAP_BAD_STATIC_MANIFEST_REL) == 1);
        /* Recovery. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_STATIC_SCRIPT_REL,
                                              HOTSWAP_MANIFEST_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The static-state scan must cover the UNION of the eligible AND swappable
 * manifests. It used to read config/hotswap_eligible.def only; a TU reachable
 * ONLY through config/hotswap_swappable.def could carry mutable file-scope
 * state, get a zero-initialized copy inside its module .so, and silently lose
 * live process state — no crash, just wrong answers. This proves the swappable
 * half of the scan really fires. */
int t_hotswap_static_state_covers_swappable(void)
{
    int failures = 0;
    TEST("hotswap static-state gate scans the swappable manifest too (union)") {
        char real_abs[PATH_MAX], bad_abs[PATH_MAX], bad_islands_abs[PATH_MAX];
        ASSERT(repo_path(real_abs, sizeof(real_abs),
                         HOTSWAP_SWAPPABLE_MANIFEST_REL) == 0);
        ASSERT(repo_path(bad_abs, sizeof(bad_abs),
                         HOTSWAP_SWAPPABLE_BAD_STATIC_REL) == 0);
        ASSERT(repo_path(bad_islands_abs, sizeof(bad_islands_abs),
                         HOTSWAP_ISLAND_BAD_STATIC_REL) == 0);
        /* Real pair → clean. */
        ASSERT(run_gate_script_with_env(HOTSWAP_STATIC_SCRIPT_REL,
                                        "ZCL_HOTSWAP_SWAPPABLE_MANIFEST",
                                        real_abs) == 0);
        /* A SWAPPABLE-only row pointing at the mutable-static fixture TU trips
         * the gate (exit 1) while the eligible manifest stays the real, clean
         * one — the exact hole the union closes. */
        ASSERT(run_gate_script_with_env(HOTSWAP_STATIC_SCRIPT_REL,
                                        "ZCL_HOTSWAP_SWAPPABLE_MANIFEST",
                                        bad_abs) == 1);
        /* Island-only members are part of the same mutable-static union. */
        ASSERT(run_gate_script_with_env(HOTSWAP_STATIC_SCRIPT_REL,
                                        "ZCL_HOTSWAP_ISLAND_MANIFEST",
                                        bad_islands_abs) == 1);
        /* Recovery. */
        ASSERT(run_hotswap_gate_with_manifest(HOTSWAP_STATIC_SCRIPT_REL,
                                              HOTSWAP_MANIFEST_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_hotswap_service_island_gate(void)
{
    int failures = 0;
    TEST("hot-swap service gate rejects state, SQLite and stale contracts") {
        char bad_abs[PATH_MAX], stale_abs[PATH_MAX];
        ASSERT(run_gate_script(HOTSWAP_SERVICE_SCRIPT_REL, NULL) == 0);
        ASSERT(repo_path(bad_abs, sizeof(bad_abs),
                         HOTSWAP_SERVICE_BAD_MANIFEST_REL) == 0);
        ASSERT(run_gate_script_with_env2(
                   HOTSWAP_SERVICE_SCRIPT_REL,
                   "ZCL_HOTSWAP_SERVICE_MANIFEST", bad_abs,
                   "ZCL_HOTSWAP_SERVICE_FIXTURE", "1") == 1);
        ASSERT(repo_path(stale_abs, sizeof(stale_abs),
                         HOTSWAP_SERVICE_STALE_CONTRACT_REL) == 0);
        ASSERT(run_gate_script_with_env2(
                   HOTSWAP_SERVICE_SCRIPT_REL,
                   "ZCL_HOTSWAP_SERVICE_MANIFEST", stale_abs,
                   "ZCL_HOTSWAP_SERVICE_FIXTURE", "1") == 1);
        ASSERT(run_gate_script(HOTSWAP_SERVICE_SCRIPT_REL, NULL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate #48 (Law 7, OS-A1): the privileged-transition-receipt gate is not
 * hollow. Real tree passes; an empty baseline makes every owner-mutating leaf
 * undispositioned (trip, exit 1); an empty command-def dir enumerates nothing
 * (fail-loud, exit 2). Uses the gate's ZCL_PRIV_RECEIPT_* test overrides. */
int t_privileged_transition_receipt_gate(void)
{
    int failures = 0;
    TEST("privileged-transition-receipt gate: clean real tree, trips, fails loud") {
        /* Real config/commands + committed baseline → all dispositioned. */
        ASSERT(run_gate_script(PRIV_RECEIPT_SCRIPT_REL, NULL) == 0);
        /* An empty baseline leaves every owner-mutating leaf undispositioned
         * → exit 1 (proof the disposition check is not hollow). */
        ASSERT(run_gate_script_with_env(PRIV_RECEIPT_SCRIPT_REL,
                                        "ZCL_PRIV_RECEIPT_BASELINE",
                                        "/dev/null") == 1);
        /* An empty command-def dir enumerates zero leaves → exit 2 (fail-loud,
         * never a hollow clean). */
        char empty_dir[PATH_MAX];
        if (repo_path(empty_dir, sizeof(empty_dir),
                      "test-tmp/_priv_receipt_empty_defs") != 0) {
            fprintf(stderr, "[lint-gate] could not resolve empty-def dir path\n");
            failures++;
            goto _test_next;
        }
        (void)mkdir(empty_dir, 0700);
        ASSERT(run_gate_script_with_env(PRIV_RECEIPT_SCRIPT_REL,
                                        "ZCL_PRIV_RECEIPT_DEF_DIR",
                                        empty_dir) == 2);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate check-dumper-never-blocks: a `*_dump_state_json` OR `*_dump_state_fill`
 * body must never reach a blocking primitive, because both run on the
 * native/RPC thread while the reducer fold owns progress_store_tx_lock — take
 * that lock blocking there and `dumpstate`/`status` go dark exactly when the
 * node is busiest.
 *
 * It lives in THIS group, not lint_gate_operator_contracts.c, on subject
 * matter: this file's checks EXECUTE gate scripts to prove a runtime-liveness
 * invariant, while operator_contracts asserts on the TEXT of tools and docs.
 * "The observability plane keeps answering while the reducer runs" is the same
 * family of question as "is anything on the liveness tree actually running".
 *
 * The matrix itself lives in the script's `--selftest`, which builds a
 * throwaway scan root and an empty baseline in its own mktemp dir and asserts
 * every case: a clean sandbox passes; a blocking call inside a
 * `*_dump_state_fill` trips (the collector blind spot — a table-driven
 * provider is where the reads moved, and the pre-widening scan could not see
 * it); the SAME call in a non-dumper function in the same file stays clean, so
 * the scan is still body-scoped; the original `*_dump_state_json` spelling
 * still trips; an empty scan root is a loud exit 2, never a hollow pass; and
 * the real tree is clean. Dispatching the flag beats restating the matrix in C
 * — the shell already owns the sandbox, and a second copy is a second thing to
 * keep in step. */
int t_dumper_never_blocks_gate(void)
{
    int failures = 0;
    TEST("[lint-gate] dumper-never-blocks: json AND fill bodies are scanned, "
         "non-dumper code is not, empty scan is loud") {
        ASSERT(run_gate_script(DUMPER_BLOCKING_SCRIPT_REL, NULL) == 0);
        ASSERT(run_gate_script_selftest(DUMPER_BLOCKING_SCRIPT_REL) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate check-no-trust-state-ordering: the sync_trust_state enumerators are
 * ORTHOGONAL provenance facts, so any </<=/>/>= comparison against a
 * SYNC_TRUST_* value is forbidden (it invites the `state >= X` mis-grant bug).
 * Real tree is clean; a planted fixture carrying `st >= SYNC_TRUST_SOVEREIGN`
 * trips (exit 1); removing it recovers. Mirrors t_e13_consensus_parity_fixture. */
int t_no_trust_state_ordering_gate(void)
{
    int failures = 0;
    char path[PATH_MAX];
    unlink_rel(TRUST_ORDER_FIXTURE_DST);
    int baseline_rc = run_gate_script(TRUST_ORDER_SCRIPT_REL, NULL);
    int planted = (repo_path(path, sizeof(path), TRUST_ORDER_FIXTURE_DST) == 0 &&
                   write_file(path,
                       "/* Transient lint-gate selftest fixture for "
                       "check-no-trust-state-ordering;\n"
                       " * planted+removed by test_make_lint_gates.c. Not "
                       "part of the build. */\n"
                       "#include \"services/sync_trust_policy.h\"\n"
                       "int _trust_order_fixture_probe(enum sync_trust_state st)"
                       "\n{\n"
                       "    if (st >= SYNC_TRUST_SOVEREIGN)\n"
                       "        return 1;\n"
                       "    return 0;\n"
                       "}\n") == 0) ? 0 : -1;
    int trip_rc = planted == 0
        ? run_gate_script(TRUST_ORDER_SCRIPT_REL, NULL) : -1;
    unlink_rel(TRUST_ORDER_FIXTURE_DST);
    int recover_rc = run_gate_script(TRUST_ORDER_SCRIPT_REL, NULL);
    TEST("[lint-gate] no-trust-state-ordering: clean, trips on ordinal cmp, recovers") {
        ASSERT(baseline_rc == 0);
        ASSERT(planted == 0);
        ASSERT(trip_rc != 0);
        ASSERT(recover_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Gate #49 — blocker escape-action totality. The fixture is fed directly to
 * the gate via ZCL_BLOCKER_ESCAPE_SCAN_FILES (a test-tmp/ path, never under
 * app/), so the self-test never touches the real tree; the registry side
 * always scans the real tree (the one real registration is
 * "activation_drive_connect", used as the OK-fixture literal). */
#define BLOCKER_ESCAPE_SCRIPT_REL \
    "tools/scripts/check_blocker_escape_registered.sh"
#define BLOCKER_ESCAPE_BAD_FIXTURE_REL \
    "test-tmp/_blocker_escape_fixture_bad_tmp.c"
#define BLOCKER_ESCAPE_OK_FIXTURE_REL \
    "test-tmp/_blocker_escape_fixture_ok_tmp.c"
/* An identifier literal naming a registered condition-engine healer (a
 * ZCL_CONDITION() entry in condition_registry.def) — not a registered
 * escape function, still a valid form. */
#define BLOCKER_ESCAPE_COND_FIXTURE_REL \
    "test-tmp/_blocker_escape_fixture_cond_tmp.c"
/* A whitespace-bearing human-readable remedy phrase — never dispatched,
 * exempt unconditionally regardless of the registry/condition table. */
#define BLOCKER_ESCAPE_PHRASE_FIXTURE_REL \
    "test-tmp/_blocker_escape_fixture_phrase_tmp.c"

/* Gate #49 — blocker escape-action totality. escape_action is dual-purpose;
 * a literal is valid in any of three forms, and the gate must accept all
 * three while still tripping on a mistyped identifier that matches none:
 *   1. a registered dispatch key ("activation_drive_connect", via
 *      blocker_register_escape());
 *   2. an identifier naming a registered condition-engine healer
 *      ("reducer_frontier_reconcile_light", a ZCL_CONDITION() entry in
 *      condition_registry.def);
 *   3. a whitespace-bearing human-readable remedy phrase ("resume the
 *      matching offline producer"), exempt unconditionally.
 * Mirrors t_privileged_transition_receipt_gate's env-override self-test
 * shape. */
int t_blocker_escape_registered_gate(void)
{
    int failures = 0;
    char bad_path[PATH_MAX], ok_path[PATH_MAX], cond_path[PATH_MAX],
         phrase_path[PATH_MAX], test_tmp_dir[PATH_MAX];
    int paths_ok =
        (repo_path(bad_path, sizeof(bad_path),
                   BLOCKER_ESCAPE_BAD_FIXTURE_REL) == 0 &&
         repo_path(ok_path, sizeof(ok_path),
                   BLOCKER_ESCAPE_OK_FIXTURE_REL) == 0 &&
         repo_path(cond_path, sizeof(cond_path),
                   BLOCKER_ESCAPE_COND_FIXTURE_REL) == 0 &&
         repo_path(phrase_path, sizeof(phrase_path),
                   BLOCKER_ESCAPE_PHRASE_FIXTURE_REL) == 0 &&
         repo_path(test_tmp_dir, sizeof(test_tmp_dir), "test-tmp") == 0)
            ? 1 : 0;
    if (paths_ok) (void)mkdir(test_tmp_dir, 0700);

    unlink_rel(BLOCKER_ESCAPE_BAD_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_OK_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_COND_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_PHRASE_FIXTURE_REL);

    int wrote_bad = paths_ok ? write_file(bad_path,
        "void fixture_bad(void)\n"
        "{\n"
        "    struct blocker_record rec;\n"
        "    if (blocker_init(&rec, \"id\", \"owner\", BLOCKER_DEPENDENCY,\n"
        "                     \"reason\")) {\n"
        "        snprintf(rec.escape_action, sizeof(rec.escape_action),\n"
        "                 \"totally_unregistered_escape_name_xyz\");\n"
        "        (void)blocker_set(&rec);\n"
        "    }\n"
        "}\n") : -1;
    int wrote_ok = paths_ok ? write_file(ok_path,
        "void fixture_ok(void)\n"
        "{\n"
        "    struct blocker_record rec;\n"
        "    if (blocker_init(&rec, \"id\", \"owner\", BLOCKER_DEPENDENCY,\n"
        "                     \"reason\")) {\n"
        "        snprintf(rec.escape_action, sizeof(rec.escape_action),\n"
        "                 \"activation_drive_connect\");\n"
        "        (void)blocker_set(&rec);\n"
        "    }\n"
        "}\n") : -1;
    int wrote_cond = paths_ok ? write_file(cond_path,
        "void fixture_cond(void)\n"
        "{\n"
        "    struct blocker_record rec;\n"
        "    if (blocker_init(&rec, \"id\", \"owner\", BLOCKER_DEPENDENCY,\n"
        "                     \"reason\")) {\n"
        "        snprintf(rec.escape_action, sizeof(rec.escape_action),\n"
        "                 \"reducer_frontier_reconcile_light\");\n"
        "        (void)blocker_set(&rec);\n"
        "    }\n"
        "}\n") : -1;
    int wrote_phrase = paths_ok ? write_file(phrase_path,
        "void fixture_phrase(void)\n"
        "{\n"
        "    struct blocker_record rec;\n"
        "    if (blocker_init(&rec, \"id\", \"owner\", BLOCKER_DEPENDENCY,\n"
        "                     \"reason\")) {\n"
        "        snprintf(rec.escape_action, sizeof(rec.escape_action),\n"
        "                 \"resume the matching offline producer\");\n"
        "        (void)blocker_set(&rec);\n"
        "    }\n"
        "}\n") : -1;

    int bad_rc = (wrote_bad == 0)
        ? run_gate_script_with_env(BLOCKER_ESCAPE_SCRIPT_REL,
                                   "ZCL_BLOCKER_ESCAPE_SCAN_FILES", bad_path)
        : -1;
    int ok_rc = (wrote_ok == 0)
        ? run_gate_script_with_env(BLOCKER_ESCAPE_SCRIPT_REL,
                                   "ZCL_BLOCKER_ESCAPE_SCAN_FILES", ok_path)
        : -1;
    int cond_rc = (wrote_cond == 0)
        ? run_gate_script_with_env(BLOCKER_ESCAPE_SCRIPT_REL,
                                   "ZCL_BLOCKER_ESCAPE_SCAN_FILES", cond_path)
        : -1;
    int phrase_rc = (wrote_phrase == 0)
        ? run_gate_script_with_env(BLOCKER_ESCAPE_SCRIPT_REL,
                                   "ZCL_BLOCKER_ESCAPE_SCAN_FILES", phrase_path)
        : -1;
    int clean_rc = run_gate_script(BLOCKER_ESCAPE_SCRIPT_REL, NULL);

    unlink_rel(BLOCKER_ESCAPE_BAD_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_OK_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_COND_FIXTURE_REL);
    unlink_rel(BLOCKER_ESCAPE_PHRASE_FIXTURE_REL);

    TEST("[lint-gate] blocker escape-action totality: unregistered literal "
         "trips; registered literal, condition-name literal, and a "
         "whitespace remedy phrase all pass; real tree passes") {
        ASSERT(paths_ok);
        ASSERT(wrote_bad == 0);
        ASSERT(wrote_ok == 0);
        ASSERT(wrote_cond == 0);
        ASSERT(wrote_phrase == 0);
        ASSERT(bad_rc == 1);
        ASSERT(ok_rc == 0);
        ASSERT(cond_rc == 0);
        ASSERT(phrase_rc == 0);
        ASSERT(clean_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_lint_gates_fail_loud_on_empty_scan(void)
{
    int failures = 0;

    /* A guaranteed-empty scan dir under the repo's test-tmp. mkdir is
     * idempotent; we never write into it, so it stays empty. */
    char empty_dir[PATH_MAX];
    if (repo_path(empty_dir, sizeof(empty_dir),
                  "test-tmp/_lint_empty_scan_dir") != 0) {
        fprintf(stderr, "[lint-gate] could not resolve empty-scan dir path\n");
        return 1;
    }
    (void)mkdir(empty_dir, 0700);

    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_one_write_path.sh", "ZCL_OWP_SCAN_ROOTS", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_projections_pure.sh", "ZCL_PROJ_SCAN_DIR", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_stage_advances_or_blocks.sh", "ZCL_JOBS_DIR", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_supervisor_registration.sh", "ZCL_SERVICES_DIR", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_coins_lookup_nullcheck.sh", "ZCL_COINS_LOOKUP_SCAN_DIR", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/check_no_secret_printf.sh", "ZCL_SECRET_PRINTF_SCAN_DIRS", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/lint/check_supervisor_domain.sh", "ZCL_SUPDOM_SCAN_ROOTS", empty_dir);
    failures += meta_gate_empty_scan_trips(
        "tools/lint/check_thread_supervision.sh", "ZCL_THREADSUP_SCAN_ROOTS", empty_dir);
    failures += meta_gate_empty_scan_trips(
        LONGFN_SCRIPT_REL, "ZCL_LONGFN_ENFORCED_ROOTS", empty_dir);
    failures += meta_gate_empty_scan_trips(
        LONGFN_SCRIPT_REL, "ZCL_LONGFN_LIB_ROOTS", empty_dir);

    /* The reorg-ratchet gate's hollow vector is a DRIFTED file list (a tracked
     * stage-log store moved/renamed), not an empty scan dir. Point its file
     * override at a nonexistent path and assert the drifted-surface preflight
     * fires exit 2 (the old code exit 1'd / a swallowed grep would mask it). */
    failures += meta_gate_empty_scan_trips(
        "tools/scripts/gate_stage_log_reorg_unsafe_ratchet.sh",
        "ZCL_REORG_RATCHET_FILES", "/nonexistent/_lint_missing_store.c");

    (void)rmdir(empty_dir);
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_sup_unit;

#endif /* ZCL_TESTING */
