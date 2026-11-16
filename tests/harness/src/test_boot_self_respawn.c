/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_self_respawn — the off-systemd self-respawn ARMING decision
 * (engine/composition/src/boot_self_respawn.c). This is the contract every clean-shutdown
 * exit point relies on to decide "re-exec /proc/self/exe": engine/entry/main.c's
 * post-app_shutdown() path calls boot_self_respawn_exec_or_return(), which
 * re-execs iff boot_self_respawn_armed() (the straggler-guard _exit in
 * boot_services_shutdown.c does not call it). The truth table proven here:
 *
 *   respawn flag latched   argv captured   systemd notify   => armed?
 *   -------------------------------------------------------------------
 *   no                     yes             no               => NO
 *   yes                    no              no               => NO
 *   yes                    yes             no               => YES  (the off-
 *                                                                    systemd
 *                                                                    recovery)
 *   yes                    yes             yes              => NO   (systemd
 *                                                                    Restart=
 *                                                                    always owns
 *                                                                    respawn)
 *
 * The execv itself is not exercisable in-process (it would replace the test
 * binary); the NOT-armed path of exec_or_return() is proven to RETURN cleanly
 * (the test keeps running past it), which is the property the straggler guard
 * depends on to fall through to its unchanged _exit(0).
 */

#include "test/test_core.h"

#include "config/boot_self_respawn.h"
#include "services/chain_tip_watchdog.h"
#include "util/supervisor_backstop.h"
#include "util/sd_notify.h"
#include "util/shutdown_stagewatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define BSR_CHECK(name, expr) do {                                       \
    if (expr) { printf("  boot_self_respawn: %s... OK\n", (name)); }      \
    else { printf("  boot_self_respawn: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Put the respawn subsystems into a known off-systemd, no-flag baseline. */
static void bsr_baseline(void)
{
    chain_tip_watchdog_test_reset_runtime();  /* clears the respawn latch */
    supervisor_backstop_test_reset();          /* clears its respawn latch */
    sd_notify_reset_for_testing();             /* g_active = 0 -> off systemd */
    unsetenv("NOTIFY_SOCKET");
    boot_self_respawn_set_argv(NULL);          /* no argv captured */
    boot_self_respawn_clear_operator_stop_for_testing(); /* no stop noted */
}

/* Test seams for exec_or_return(): count exec attempts; the window hook lands
 * an operator stop after the armed() check, before the final one. */
static int g_bsr_exec_calls;
static char *const *g_bsr_exec_argv;

static int bsr_fake_exec(const char *path, char *const argv[])
{
    (void)path;
    g_bsr_exec_calls++;
    g_bsr_exec_argv = argv;
    return -1;
}

static void bsr_window_stop(void)
{
    boot_self_respawn_note_operator_stop();
}

static bool bsr_reason_is_operator(const char *dir)
{
    char reason[64] = "";
    bool forced = false;
    return shutdown_stagewatch_read_exit_reason(dir, reason, sizeof(reason),
                                                &forced) &&
           strcmp(reason, SHUTDOWN_EXIT_REASON_OPERATOR) == 0;
}

/* Armed state with the stagewatch pointed at a scratch datadir of our own, so
 * no breadcrumb is ever written outside the test's scratch. */
static bool bsr_armed_in_scratch(char **argv, char *dir, size_t n)
{
    bsr_baseline();
    shutdown_stagewatch_reset_for_test();
    if (!test_mkdtemp(dir, n, "bsr_stop"))
        return false;
    shutdown_stagewatch_begin(dir);
    boot_self_respawn_set_argv(argv);
    chain_tip_watchdog_request_respawn();
    g_bsr_exec_calls = 0;
    g_bsr_exec_argv = NULL;
    return true;
}

static void bsr_scratch_done(const char *dir)
{
    boot_self_respawn_set_test_hooks(NULL, NULL);
    shutdown_stagewatch_reset_for_test();
    (void)test_rm_rf_recursive(dir);
    bsr_baseline();
}

/* The window between armed() and execv: with no stop the exec is attempted
 * with the captured argv (control); a stop landing in the window declines it
 * and records the operator breadcrumb. */
static int bsr_exec_window_rows(char **argv)
{
    int failures = 0;
    char dir[512];

    if (!bsr_armed_in_scratch(argv, dir, sizeof(dir))) {
        printf("  boot_self_respawn: scratch datadir... FAIL\n");
        return 1;
    }
    boot_self_respawn_set_test_hooks(NULL, bsr_fake_exec);
    boot_self_respawn_exec_or_return();
    BSR_CHECK("armed, no stop -> exec attempted once with the captured argv",
              g_bsr_exec_calls == 1 && g_bsr_exec_argv == argv);
    BSR_CHECK("armed, no stop -> no operator breadcrumb",
              !bsr_reason_is_operator(dir));
    bsr_scratch_done(dir);

    if (!bsr_armed_in_scratch(argv, dir, sizeof(dir))) {
        printf("  boot_self_respawn: scratch datadir... FAIL\n");
        return failures + 1;
    }
    boot_self_respawn_set_test_hooks(bsr_window_stop, bsr_fake_exec);
    boot_self_respawn_exec_or_return();
    BSR_CHECK("stop landing after armed() -> no exec (declined)",
              g_bsr_exec_calls == 0);
    BSR_CHECK("stop landing after armed() -> operator breadcrumb recorded",
              bsr_reason_is_operator(dir));
    bsr_scratch_done(dir);
    return failures;
}

/* A stop noted before the call: declined by armed(); the decline path ran,
 * proven by the operator breadcrumb in our scratch datadir and zero execs. */
static int bsr_declined_rows(char **argv)
{
    int failures = 0;
    char dir[512];

    if (!bsr_armed_in_scratch(argv, dir, sizeof(dir))) {
        printf("  boot_self_respawn: scratch datadir... FAIL\n");
        return 1;
    }
    boot_self_respawn_set_test_hooks(NULL, bsr_fake_exec);
    boot_self_respawn_note_operator_stop();
    boot_self_respawn_exec_or_return();
    BSR_CHECK("noted stop: exec_or_return() returned without exec",
              g_bsr_exec_calls == 0);
    BSR_CHECK("noted stop: decline path recorded the operator breadcrumb",
              bsr_reason_is_operator(dir));
    bsr_scratch_done(dir);
    return failures;
}

/* Row 3b: an operator stop (SIGINT/SIGTERM noted by the handler) beats a
 * latched respawn. Both latches, off systemd, argv captured: still NOT armed.
 * Without the stop the same state is armed (row 3), so the stop alone flips it. */
static int bsr_operator_stop_rows(char **argv)
{
    int failures = 0;

    bsr_baseline();
    boot_self_respawn_set_argv(argv);
    chain_tip_watchdog_request_respawn();
    BSR_CHECK("latched + argv, no stop noted -> ARMED (control)",
              boot_self_respawn_armed());
    boot_self_respawn_note_operator_stop();
    BSR_CHECK("latched + argv + operator stop noted -> NOT armed",
              !boot_self_respawn_armed());

    /* The stop note is only a gate: clearing it restores the armed state, so
     * armed() reads it live, not a cache. */
    boot_self_respawn_clear_operator_stop_for_testing();
    BSR_CHECK("stop cleared -> latch ARMED again",
              boot_self_respawn_armed());

    /* The restart-pending app_init path exits as an operator stop only when a
     * stop was noted (and never under systemd). */
    bsr_baseline();
    BSR_CHECK("no stop noted -> operator_stop_exit() false",
              !boot_self_respawn_operator_stop_exit());
    boot_self_respawn_note_operator_stop();
    {
        /* Writes its breadcrumb: keep it inside our own scratch datadir. */
        char dir[512];
        shutdown_stagewatch_reset_for_test();
        bool have = test_mkdtemp(dir, sizeof(dir), "bsr_stopexit") != NULL;
        if (have)
            shutdown_stagewatch_begin(dir);
        BSR_CHECK("stop noted off systemd -> operator_stop_exit() true",
                  have && boot_self_respawn_operator_stop_exit());
        BSR_CHECK("operator_stop_exit() wrote the operator breadcrumb",
                  have && bsr_reason_is_operator(dir));
        shutdown_stagewatch_reset_for_test();
        if (have)
            (void)test_rm_rf_recursive(dir);
    }
    bsr_baseline();
    failures += bsr_declined_rows(argv);
    failures += bsr_exec_window_rows(argv);
    return failures;
}

int test_boot_self_respawn(void);
int test_boot_self_respawn(void)
{
    printf("\n=== boot_self_respawn tests ===\n");
    int failures = 0;

    /* A representative argv the node-mode entry would capture. */
    static char a0[] = "zclassic23";
    static char a1[] = "-datadir=/tmp/x";
    static char *fake_argv[] = { a0, a1, NULL };

    /* ── Row 1: no flag latched -> NOT armed (even with argv, off systemd). */
    bsr_baseline();
    boot_self_respawn_set_argv(fake_argv);
    BSR_CHECK("no respawn flag latched -> NOT armed", !boot_self_respawn_armed());

    /* ── Row 2: flag latched but NO argv captured -> NOT armed (nothing to
     *    exec with). */
    bsr_baseline();
    chain_tip_watchdog_request_respawn();
    BSR_CHECK("flag latched but argv NULL -> NOT armed", !boot_self_respawn_armed());

    /* ── Row 3: flag latched + argv captured + off systemd -> ARMED. This is
     *    the exact off-systemd liveness recovery the install-respawn seam and
     *    the straggler guard depend on. */
    bsr_baseline();
    boot_self_respawn_set_argv(fake_argv);
    chain_tip_watchdog_request_respawn();
    BSR_CHECK("chain-tip flag + argv + off-systemd -> ARMED", boot_self_respawn_armed());

    /* The supervisor-backstop latch is the equally-valid trigger (Pillar 7):
     * clearing the chain-tip flag while the process is otherwise armed drops
     * back to NOT armed, proving armed() reads the live latches, not a cache. */
    chain_tip_watchdog_test_reset_runtime();
    BSR_CHECK("clearing the only latch -> NOT armed again", !boot_self_respawn_armed());

    failures += bsr_operator_stop_rows(fake_argv);

    /* ── Row 4: flag latched + argv captured but systemd notify ACTIVE -> NOT
     *    armed. Under systemd, Restart=always is the sole respawn authority; a
     *    self-exec there would double-restart. sd_notify_init() activates from
     *    the NOTIFY_SOCKET env alone (no live socket needed). */
    bsr_baseline();
    boot_self_respawn_set_argv(fake_argv);
    chain_tip_watchdog_request_respawn();
    setenv("NOTIFY_SOCKET", "/tmp/zcl-fake-notify.sock", 1);
    (void)sd_notify_init();
    if (sd_notify_is_active()) {
        BSR_CHECK("flag + argv but systemd notify active -> NOT armed (systemd owns respawn)",
                  !boot_self_respawn_armed());
    } else {
        printf("  boot_self_respawn: sd_notify_init did not activate in this env — "
               "on-systemd suppression sub-check skipped (armed() still gates on "
               "!sd_notify_is_active())\n");
    }
    sd_notify_reset_for_testing();
    unsetenv("NOTIFY_SOCKET");

#if defined(__linux__)
    {
        /* A child that vanished between readdir and lstat counts as zero
         * bytes; the root itself missing is still a refusal. */
        char gone[64];
        int gone_n = snprintf(gone, sizeof(gone), "/var/tmp/zcl-bsr-gone-%d", (int)getpid());
        uint64_t used = 0;
        BSR_CHECK("tmpfs size: vanished child (lstat ENOENT) is skipped",
                  gone_n > 0 && (size_t)gone_n < sizeof(gone) &&
                  test_tmpfs_size_at(gone, &used, true) && used == 0);
        BSR_CHECK("tmpfs size: missing root is still refused",
                  !test_tmpfs_size_at(gone, &used, false));
    }
#endif

#if !defined(_WIN32)
    bsr_baseline();
    boot_self_respawn_set_argv(fake_argv);
    /* sd_notify keeps a 108-byte sun_path. A tmpdir under a long checkout
     * (the test-tmp fallback when the shared tmpfs root is exhausted) does
     * not fit, so use a short per-process path; nothing binds it. */
    char notify_path[64];
    int notify_n = snprintf(notify_path, sizeof(notify_path),
                            "/var/tmp/zcl-bsr-%d.sock", (int)getpid());
    BSR_CHECK("early restart notify path fits sun_path (< 108 bytes)",
              notify_n > 0 && (size_t)notify_n < sizeof(notify_path) &&
              strlen(notify_path) < 108);
    setenv("NOTIFY_SOCKET", notify_path, 1);
    BSR_CHECK("early restart detects systemd before services",
              boot_self_respawn_prepare_early() && sd_notify_is_active() &&
              !boot_self_respawn_armed());
    sd_notify_reset_for_testing();
    unsetenv("NOTIFY_SOCKET");
#endif

    /* ── exec_or_return() when NOT armed must RETURN (not exec, not abort) —
     *    the straggler guard relies on this to fall through to its _exit(0).
     *    Reaching the line after it is the proof. */
    bsr_baseline();
    boot_self_respawn_exec_or_return();
    BSR_CHECK("exec_or_return() when not armed returns cleanly (no exec/abort)", true);

    /* Leave global respawn/notify state clean for the next group. */
    bsr_baseline();

    printf("=== boot_self_respawn: %d failure(s) ===\n", failures);
    return failures;
}
