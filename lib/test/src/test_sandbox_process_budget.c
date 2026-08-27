/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression: the confined-build process budget must not vary with the
 * host's unrelated process count.
 *
 * The defect this pins. tools/package_verify.c used to install
 *
 *     RLIMIT_NPROC = pv_uid_task_count() + PV_ZBUILD_COMPILE_NPROC
 *
 * i.e. a snapshot of every TASK the real uid was running (measured on this
 * box at 686-828 tasks across 79-115 processes: agent shells, editors, other
 * make trees) plus a 16-task margin. RLIMIT_NPROC is charged per REAL UID,
 * kernel-wide, so that margin was never the sandboxed child's budget — any
 * process the same uid started between the snapshot and gcc's fork consumed
 * it. Under a 32-worker suite gcc then died with
 *
 *     cc: fatal error: cannot execute '.../cc1':
 *         posix_spawn: Resource temporarily unavailable
 *
 * which the build fabric reported as an ordinary COMPILE failure. Measured:
 * 40 of 40 zbuild compile actions failed with a process-churn generator
 * running, 0 of 40 with it stopped. It cost three gate cycles because the
 * wedge and a real build defect were indistinguishable.
 *
 * The invariant chosen instead, and asserted here:
 *
 *   1. the value installed on RLIMIT_NPROC is an ABSOLUTE backstop,
 *      independent of the uid's task count. The uid's NPROC HARD limit —
 *      host configuration, which does not move while a suite runs — is the
 *      only thing that may lower it.
 *   2. whether the host has process table left is a SEPARATE admission
 *      decision, reported with both numbers in it, never folded into a
 *      child's exit status.
 *   3. the action's real process budget is enforced subtree-scoped, by a
 *      census of the child's own process group, so concurrent work of the
 *      same uid is neither counted against an action nor punished by it.
 */

#define _GNU_SOURCE

#include "test/test_core.h"
#include "platform/os_sandbox.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define SPB_EXTRA 24

/* Spawn SPB_EXTRA children into one process group led by the first of them,
 * and return that group id (0 on failure). Each child blocks until the write
 * end of `keepalive` closes, so the parent decides exactly when they die. */
static pid_t spb_spawn_group(int *keepalive_write, pid_t *pids)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return 0;
    pid_t leader = 0;
    for (int i = 0; i < SPB_EXTRA; i++) {
        pid_t p = fork();
        if (p < 0) break;
        if (p == 0) {
            close(pipefd[1]);
            (void)setpgid(0, leader);
            char c;
            ssize_t got;
            do { got = read(pipefd[0], &c, 1); } while (got < 0 &&
                                                        errno == EINTR);
            _exit(0);
        }
        (void)setpgid(p, leader ? leader : p);
        if (!leader) leader = p;
        pids[i] = p;
    }
    close(pipefd[0]);
    *keepalive_write = pipefd[1];
    return leader;
}

static void spb_reap_group(int keepalive_write, pid_t *pids)
{
    close(keepalive_write);
    for (int i = 0; i < SPB_EXTRA; i++) {
        if (pids[i] <= 0) continue;
        int st = 0;
        (void)waitpid(pids[i], &st, 0);
    }
}

/* THE defect, stated as an assertion: same requested ceiling, wildly
 * different concurrent load, one installed limit. The old snapshot+margin
 * policy fails this by construction — its limit WAS (uid tasks + margin) and
 * so was a different number in every case below. */
static int spb_ceiling_ignores_load(void)
{
    int failures = 0;
    TEST("process budget: the installed ceiling ignores the uid's task count") {
        const uint64_t requested = 65536, required = 32;
        struct os_sandbox_process_budget quiet =
            os_sandbox_process_budget_at(requested, required, 0, 381835);
        struct os_sandbox_process_budget busy =
            os_sandbox_process_budget_at(requested, required, 828, 381835);
        struct os_sandbox_process_budget swamped =
            os_sandbox_process_budget_at(requested, required, 40000, 381835);
        ASSERT_EQ(quiet.ceiling, requested);
        ASSERT_EQ(busy.ceiling, requested);
        ASSERT_EQ(swamped.ceiling, requested);
        /* Load moves the HEADROOM — a separate, separately reported
         * quantity — never the limit. */
        ASSERT_EQ(quiet.headroom, requested);
        ASSERT_EQ(busy.headroom, requested - 828);
        ASSERT_EQ(swamped.headroom, requested - 40000);
        ASSERT(quiet.admitted && busy.admitted && swamped.admitted);
        PASS();
    } _test_next:;
    return failures;
}

static int spb_only_hard_limit_clamps(void)
{
    int failures = 0;
    TEST("process budget: only the STATIC hard limit may lower the ceiling") {
        /* setrlimit cannot raise a hard limit, so this clamp must exist. It
         * is host CONFIGURATION, not host LOAD: it does not move while a
         * suite runs, so it cannot reintroduce the flake. */
        struct os_sandbox_process_budget clamped =
            os_sandbox_process_budget_at(65536, 32, 100, 4096);
        ASSERT_EQ(clamped.ceiling, UINT64_C(4096));
        ASSERT_EQ(clamped.requested, UINT64_C(65536));
        ASSERT_EQ(clamped.hard, UINT64_C(4096));
        /* An unlimited hard limit must not clamp at all. */
        struct os_sandbox_process_budget unlimited =
            os_sandbox_process_budget_at(65536, 32, 100,
                                         OS_SANDBOX_RLIMIT_KEEP);
        ASSERT_EQ(unlimited.ceiling, UINT64_C(65536));
        /* The clamp is the ONLY input that lowers it: the same hard limit
         * with any load gives the same answer. */
        struct os_sandbox_process_budget clamped_busy =
            os_sandbox_process_budget_at(65536, 32, 3000, 4096);
        ASSERT_EQ(clamped_busy.ceiling, clamped.ceiling);
        PASS();
    } _test_next:;
    return failures;
}

static int spb_exhaustion_is_an_admission_verdict(void)
{
    int failures = 0;
    TEST("process budget: exhaustion is an admission verdict, not a build "
         "failure") {
        /* A host with no process table left is REFUSED before the fork,
         * carrying both numbers an operator needs — the limit and the uid's
         * task count — so the wedge can never again read as the compiler
         * rejecting the input. */
        struct os_sandbox_process_budget wedged =
            os_sandbox_process_budget_at(700, 32, 828, 700);
        ASSERT(!wedged.admitted);
        ASSERT_EQ(wedged.headroom, UINT64_C(0));
        ASSERT_EQ(wedged.uid_tasks, UINT64_C(828));
        ASSERT_EQ(wedged.ceiling, UINT64_C(700));
        ASSERT_EQ(wedged.required, UINT64_C(32));
        /* Exactly at the boundary is admitted; one task past it is not. */
        struct os_sandbox_process_budget exact =
            os_sandbox_process_budget_at(1000, 32, 968, 381835);
        struct os_sandbox_process_budget over =
            os_sandbox_process_budget_at(1000, 32, 969, 381835);
        ASSERT(exact.admitted);
        ASSERT(!over.admitted);
        PASS();
    } _test_next:;
    return failures;
}

static int spb_live_reading_and_census(void)
{
    int failures = 0;
    TEST("process budget: the live ceiling holds while real uid tasks start") {
        struct os_sandbox_process_budget before =
            os_sandbox_process_budget_live(65536, 32);
        /* If /proc is unreadable the rest proves nothing, so say so here. */
        ASSERT(before.uid_tasks > 0);
        pid_t pids[SPB_EXTRA] = {0};
        int keepalive = -1;
        pid_t pgid = spb_spawn_group(&keepalive, pids);
        ASSERT(pgid > 0);
        struct os_sandbox_process_budget during =
            os_sandbox_process_budget_live(65536, 32);
        /* The end-to-end form of the first assertion, against real processes
         * rather than supplied numbers. Under the old policy this second
         * reading was ~SPB_EXTRA higher; that drift IS the defect.
         *
         * The ceiling under test is the requested one surviving intact:
         * min(requested, static hard limit) by policy. Where the host's
         * kernel bind is generous (typical Linux dev hosts) that is exactly
         * 65536; where the OS caps this uid lower (macOS kern.maxprocperuid)
         * honoring it IS the admission contract, so the expectation derives
         * from the same published static limit rather than assuming it away. */
        uint64_t expected_ceiling = UINT64_C(65536);
        uint64_t static_hard = os_sandbox_nproc_hard_limit();
        if (static_hard != OS_SANDBOX_RLIMIT_KEEP && static_hard < expected_ceiling)
            expected_ceiling = static_hard;
        ASSERT_EQ(before.ceiling, expected_ceiling);
        ASSERT_EQ(during.ceiling, expected_ceiling);

        /* The census — the mechanism that DOES bound an action — sees the
         * group and nothing else the uid is running. */
        uint64_t census = os_sandbox_process_group_census(pgid);
        ASSERT(census >= (uint64_t)SPB_EXTRA);
        ASSERT(census < during.uid_tasks);
        /* A missing group censuses to zero; a bad id is not a wildcard. */
        ASSERT_EQ(os_sandbox_process_group_census(0), UINT64_C(0));
        ASSERT_EQ(os_sandbox_process_group_census(-1), UINT64_C(0));

        spb_reap_group(keepalive, pids);
        ASSERT_EQ(os_sandbox_process_group_census(pgid), UINT64_C(0));
        PASS();
    } _test_next:;
    return failures;
}

static int spb_hard_limit_readable(void)
{
    int failures = 0;
    TEST("process budget: the uid's own NPROC hard limit is readable") {
        uint64_t hard = os_sandbox_nproc_hard_limit();
        /* Either a real ceiling or the explicit unlimited sentinel — never a
         * silent zero, which would refuse every action on this host. */
        ASSERT(hard > 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_sandbox_process_budget(void)
{
    printf("\n=== sandbox process budget tests ===\n");
    int failures = 0;
    failures += spb_ceiling_ignores_load();
    failures += spb_only_hard_limit_clamps();
    failures += spb_exhaustion_is_an_admission_verdict();
    failures += spb_live_reading_and_census();
    failures += spb_hard_limit_readable();
    printf("=== sandbox process budget tests done: %d failure(s) ===\n",
           failures);
    return failures;
}
