/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_self_respawn — the off-systemd self-respawn ARMING decision
 * (engine/composition/src/boot_self_respawn.c). This is the contract every clean-shutdown
 * exit point relies on to decide "re-exec /proc/self/exe": engine/entry/main.c's
 * post-app_shutdown() path AND boot_services_shutdown.c's straggler-guard
 * _exit path both call boot_self_respawn_exec_or_return(), which re-execs iff
 * boot_self_respawn_armed(). The truth table proven here:
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

#include <stdio.h>
#include <stdlib.h>

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
