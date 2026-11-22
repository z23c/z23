/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: the submit precheck always runs
 * check-no-new-bash and check-capability-closure, with no ledger history
 * naming them. Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h.
 *
 * The fixture z23-lint models the two real gates: no-new-bash compares
 * build/shell-lines with build/shell-budget; capability-closure is UNPROVEN
 * (exit 2) until build/closure-objects exists, and with it a planted
 * build/cap-violation is a VIOLATION (exit 1). */

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)

static const char dlx_late_lint[] =
    "#!/bin/sh\n"
    "if [ \"$1\" = --list ]; then cat build/precheck-known; exit 0; fi\n"
    "echo \"$1\" >> build/precheck-ran\n"
    "if [ \"$1\" = check-no-new-bash ]; then\n"
    "  l=$(cat build/shell-lines); b=$(cat build/shell-budget)\n"
    "  if [ \"$l\" -gt \"$b\" ]; then\n"
    "    echo \"check-no-new-bash: shell lines $l of budget $b\"; exit 1\n"
    "  fi\n"
    "fi\n"
    "if [ \"$1\" = check-capability-closure ]; then\n"
    "  if [ ! -f build/closure-objects ]; then\n"
    "    echo 'check_capability_closure: UNPROVEN - no build/dev-obj/epochs/*'\n"
    "    exit 2\n"
    "  fi\n"
    "  if [ -f build/cap-violation ]; then\n"
    "    echo 'check_capability_closure: VIOLATION - undeclared reach'; exit 1\n"
    "  fi\n"
    "fi\n"
    "exit 0\n";

/* One lane: no ledger rows, both gates known to the lane's z23-lint. The
 * submit result is left in `c` for the caller to judge. */
static bool dlx_late_rig(struct dlx_rig *rig, struct dlx_call *c,
                         const char *tag, const char *lines, bool objects,
                         bool violation)
{
    bool ok = dlx_pc_rig(rig, tag, true,
                         "check-no-new-bash\ncheck-capability-closure\n") &&
              dlx_pc_file(rig, "bin/z23-lint", dlx_late_lint) &&
              dlx_pc_file(rig, "shell-lines", lines) &&
              dlx_pc_file(rig, "shell-budget", "100\n") &&
              (!objects || dlx_pc_file(rig, "closure-objects", "x\n")) &&
              (!violation || dlx_pc_file(rig, "cap-violation", "x\n"));
    dlx_pc_submit(c, rig, NULL, NULL);
    return dlx_run(c) && ok;
}

static bool dlx_late_refused(struct dlx_call *c, const char *gate,
                             const char *reproduce)
{
    return !dlx_ok(c) && !strcmp(dlx_str(c, "gate"), gate) &&
           strstr(dlx_str(c, "hint"), reproduce) != NULL && dlx_queue_empty();
}

static bool dlx_late_shell_over_budget(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok = dlx_late_rig(&rig, &c, "late_shell_over", "101\n", true, false) &&
              dlx_late_refused(&c, "check-no-new-bash",
                               "build/bin/z23-lint check-no-new-bash");
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_late_shell_within_budget(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok = dlx_late_rig(&rig, &c, "late_shell_ok", "100\n", true, false) &&
              dlx_ok(&c) && dlx_queue_has_one() &&
              dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-no-new-bash") &&
              dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-capability-closure");
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_late_closure_violation(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok = dlx_late_rig(&rig, &c, "late_closure_bad", "1\n", true, true) &&
              dlx_late_refused(&c, "check-capability-closure",
                               "make check-capability-closure");
    dlx_end(&c);
    dlx_restore();
    return ok;
}

/* No objects in the lane: skipped, never silently passed, and the reason
 * names the exact command that proves it. */
static bool dlx_late_closure_unproven(void)
{
    struct dlx_rig rig;
    struct dlx_call c;
    bool ok = dlx_late_rig(&rig, &c, "late_closure_unproven", "1\n", false, true) &&
              dlx_ok(&c) && dlx_queue_has_one() &&
              dlx_pc_has(dlx_arr(&c, "precheck_skipped"), "check-capability-closure") &&
              !dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-capability-closure") &&
              dlx_pc_has(dlx_arr(&c, "precheck_ran"), "check-no-new-bash") &&
              strstr(dlx_str(&c, "precheck_unproven"),
                     "run: make check-capability-closure") != NULL;
    dlx_end(&c);
    dlx_restore();
    return ok;
}

int dlx_case_precheck_late(void)
{
    int failures = 0;
    TEST("land: submit refuses a lane over the shell line budget, ledger empty") {
        ASSERT(dlx_late_shell_over_budget());
        ASSERT(dlx_late_shell_within_budget());
        PASS();
    }
    TEST("land: submit refuses a capability violation when objects exist") {
        ASSERT(dlx_late_closure_violation());
        PASS();
    }
    TEST("land: capability closure without objects is skipped with its command") {
        ASSERT(dlx_late_closure_unproven());
        PASS();
    }
_test_next:;
    zcl_dev_land_precheck_test_force(false);
    return failures;
}

#else
int dlx_case_precheck_late(void) { return 0; }
#endif
