/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression for the 2026-09-08 node1 outage: after a restart the embedded
 * Tor thread failed to bind its bootstrap SocksPort, tor_run_main returned
 * -1, the thread exited — and nothing named it, nothing retried it, and the
 * systemd status line said only `descriptor=no` for 27 minutes, which is
 * exactly what a healthy slow bootstrap says too.
 *
 * Each test below fails without the corresponding half of boot_tor_watch:
 *
 *   reason_is_the_cause_not_the_consequence — the failed start logs THREE
 *     warnings and the last one blames the config. Quoting the last line
 *     tells an operator to go fix a torrc that was never wrong.
 *   retry_schedule / retry_runs_the_wrapper — nothing retried at all.
 *   status_distinguishes_failed_from_starting — `descriptor=no` could not
 *     tell "never came up" from "bootstrapping".
 *   status_never_names_an_onion — the reason text is read out of Tor's own
 *     log, which routinely names the service being registered; an operator
 *     status line and a blocker record must not publish that.
 */

#include "test/test_core.h"

#include "config/boot_tor_watch.h"
#include "net/tor_integration.h"
#include "net/tor_request_state.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The three lines node1's tor.log carried, in the order Tor wrote them. */
static const char *const k_incident_log =
    "Sep 08 03:08:13.508 [notice] Opening Socks listener on 127.0.0.1:19999\n"
    "Sep 08 03:08:13.509 [warn] Could not bind to 127.0.0.1:19999: Address "
    "already in use. Is Tor already running?\n"
    "Sep 08 03:08:13.509 [warn] Failed to parse/validate config: Failed to "
    "bind one of the listener ports.\n"
    "Sep 08 03:08:13.509 [err] Reading config failed--see warnings above.\n";

static int g_restart_calls;

static bool count_restart(void *ctx)
{
    (void)ctx;
    g_restart_calls++;
    return true;
}

static bool write_file(const char *path, const char *body)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(body, f) >= 0;
    return fclose(f) == 0 && ok;
}

static int test_tor_watch_backoff_schedule(void)
{
    int failures = 0;

    TEST("tor_watch_backoff_schedule") {
        /* 5s, 15s, 45s, 135s, then the 5-minute cap, forever. */
        ASSERT_EQ(boot_tor_watch_delay_us(0), 5LL * 1000000LL);
        ASSERT_EQ(boot_tor_watch_delay_us(1), 15LL * 1000000LL);
        ASSERT_EQ(boot_tor_watch_delay_us(2), 45LL * 1000000LL);
        ASSERT_EQ(boot_tor_watch_delay_us(3), 135LL * 1000000LL);
        ASSERT_EQ(boot_tor_watch_delay_us(4), BOOT_TOR_RETRY_CAP_US);
        /* A node that has been failing for a week must still be on the cap,
         * not on an overflowed delay. */
        ASSERT_EQ(boot_tor_watch_delay_us(4096), BOOT_TOR_RETRY_CAP_US);
        ASSERT_EQ(boot_tor_watch_delay_us(-1), BOOT_TOR_RETRY_FIRST_US);
        PASS();
    } _test_next:;
    return failures;
}

static int test_tor_watch_classify(void)
{
    int failures = 0;

    TEST("tor_watch_classify") {
        ASSERT_EQ((int)boot_tor_fault_classify(
                      "[warn] Could not bind to 127.0.0.1:19999: Address "
                      "already in use. Is Tor already running?"),
                  (int)BOOT_TOR_FAULT_PORT_IN_USE);
        ASSERT_EQ((int)boot_tor_fault_classify(
                      "[warn] Failed to parse/validate config: bad line"),
                  (int)BOOT_TOR_FAULT_CONFIG_INVALID);
        ASSERT_EQ((int)boot_tor_fault_classify(
                      "[warn] Permission denied on DataDirectory"),
                  (int)BOOT_TOR_FAULT_DATADIR);
        /* Unknown text is still a NAMED state, never a silent one. */
        ASSERT_EQ((int)boot_tor_fault_classify("[warn] something new"),
                  (int)BOOT_TOR_FAULT_EXITED);
        ASSERT_EQ((int)boot_tor_fault_classify(NULL),
                  (int)BOOT_TOR_FAULT_EXITED);
        ASSERT_STR_EQ(boot_tor_fault_name(BOOT_TOR_FAULT_PORT_IN_USE),
                      "port_in_use");
        PASS();
    } _test_next:;
    return failures;
}

/* THE regression on reason quality: the last warning in a failed Tor start
 * blames the config, and the config was fine. */
static int test_tor_watch_reason_is_the_cause(void)
{
    int failures = 0;
    char dir[512];
    char path[640];
    char reason[BOOT_TOR_REASON_MAX];

    TEST("tor_watch_reason_is_the_cause_not_the_consequence") {
        ASSERT(test_mkdtemp(dir, sizeof(dir), "tor_watch") != NULL);
        snprintf(path, sizeof(path), "%s/tor.log", dir);
        ASSERT(write_file(path, k_incident_log));

        enum boot_tor_fault fault =
            boot_tor_log_scan_fault(path, 0, reason, sizeof(reason));
        ASSERT_EQ((int)fault, (int)BOOT_TOR_FAULT_PORT_IN_USE);
        ASSERT(strstr(reason, "Address already in use") != NULL);
        /* The quote is one line, ready for a status/blocker string. */
        ASSERT(strchr(reason, '\n') == NULL);

        /* A log with no warning at all is not a fabricated diagnosis. */
        ASSERT(write_file(path, "[notice] all quiet\n"));
        ASSERT_EQ((int)boot_tor_log_scan_fault(path, 0, reason,
                                               sizeof(reason)),
                  (int)BOOT_TOR_FAULT_NONE);
        ASSERT_EQ(reason[0], '\0');

        /* An unreadable log is NONE with an empty quote, never a crash. */
        ASSERT_EQ((int)boot_tor_log_scan_fault("/nonexistent/tor.log", 0,
                                               reason, sizeof(reason)),
                  (int)BOOT_TOR_FAULT_NONE);
        unlink(path);
        rmdir(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_tor_watch_redacts_onion(void)
{
    int failures = 0;
    char out[BOOT_TOR_REASON_MAX];
    static const char *const k_addr =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx";

    TEST("tor_watch_status_never_names_an_onion") {
        char line[320];
        snprintf(line, sizeof(line),
                 "[warn] Could not upload descriptor for %s.onion: timeout",
                 k_addr);
        ASSERT(boot_tor_redact_onion(line, out, sizeof(out)));
        ASSERT(strstr(out, k_addr) == NULL);
        ASSERT(strstr(out, "<onion>") != NULL);
        ASSERT(strstr(out, "Could not upload descriptor") != NULL);

        /* A bare v3 address with no suffix is still an address. */
        ASSERT(boot_tor_redact_onion(k_addr, out, sizeof(out)));
        ASSERT_STR_EQ(out, "<onion>");

        /* Ordinary words are not addresses. */
        ASSERT(boot_tor_redact_onion("[warn] bind failed on port",
                                     out, sizeof(out)));
        ASSERT_STR_EQ(out, "[warn] bind failed on port");
        PASS();
    } _test_next:;
    return failures;
}

static int test_tor_watch_retries(void)
{
    int failures = 0;
    struct boot_tor_watch w = {0};

    TEST("tor_watch_retry_runs_the_wrapper_on_the_schedule") {
        g_restart_calls = 0;
        boot_tor_watch_arm(&w, "/nonexistent-datadir", count_restart, NULL);
        ASSERT(boot_tor_watch_current() == &w);

        /* First attempt is due immediately — an outgoing process usually
         * frees the port within a second or two. */
        ASSERT(boot_tor_watch_due(&w, 0));
        ASSERT(boot_tor_watch_retry(&w, 0));
        ASSERT_EQ(g_restart_calls, 1);

        /* ...and the next one is not due until the backoff elapses. */
        ASSERT(!boot_tor_watch_due(&w, 4LL * 1000000LL));
        ASSERT(boot_tor_watch_due(&w, 5LL * 1000000LL));
        ASSERT(boot_tor_watch_retry(&w, 5LL * 1000000LL));
        ASSERT_EQ(g_restart_calls, 2);
        ASSERT(!boot_tor_watch_due(&w, 19LL * 1000000LL));
        ASSERT(boot_tor_watch_due(&w, 20LL * 1000000LL));

        /* Tor came up: the schedule resets, so the NEXT episode starts at
         * 5s again instead of inheriting an hour-long backoff. */
        boot_tor_watch_note_up(&w);
        ASSERT(boot_tor_watch_due(&w, 20LL * 1000000LL));

        boot_tor_watch_disarm(&w);
        ASSERT(boot_tor_watch_current() == NULL);
        /* A disarmed watch never retries and never claims a failure. */
        ASSERT(!boot_tor_watch_due(&w, 1000LL * 1000000LL));
        ASSERT(!boot_tor_watch_retry(&w, 1000LL * 1000000LL));
        ASSERT_EQ(g_restart_calls, 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_tor_watch_status_labels(void)
{
    int failures = 0;
    struct boot_tor_watch w = {0};
    char label[64];

    TEST("tor_watch_status_distinguishes_failed_from_starting") {
        /* Nobody asked for an onion. */
        tor_integration_stop();
        boot_tor_watch_status(NULL, label, sizeof(label));
        ASSERT_STR_EQ(label, "tor=off");

        /* Requested, watch not armed yet: Tor is coming up. */
        tor_integration_mark_requested();
        boot_tor_watch_status(NULL, label, sizeof(label));
        ASSERT_STR_EQ(label, "tor=starting");

        /* Requested, watch armed, thread not running: this is the state the
         * operator could not see on 2026-09-08. */
        boot_tor_watch_arm(&w, "/nonexistent-datadir", count_restart, NULL);
        atomic_store(&w.fault, (int)BOOT_TOR_FAULT_PORT_IN_USE);
        boot_tor_watch_status(&w, label, sizeof(label));
        ASSERT_STR_EQ(label, "tor=failed(port_in_use)");
        ASSERT(boot_tor_watch_failed(&w));

        boot_tor_watch_disarm(&w);
        ASSERT(!boot_tor_watch_failed(&w));
        tor_integration_stop();
        PASS();
    } _test_next:;
    return failures;
}

int test_tor_watch(void)
{
    int failures = 0;
    printf("\n=== Tor start watch (2026-09-08 outage regression) ===\n");
    failures += test_tor_watch_backoff_schedule();
    failures += test_tor_watch_classify();
    failures += test_tor_watch_reason_is_the_cause();
    failures += test_tor_watch_redacts_onion();
    failures += test_tor_watch_retries();
    failures += test_tor_watch_status_labels();
    printf("Tor start watch: %d failures\n", failures);
    return failures;
}
