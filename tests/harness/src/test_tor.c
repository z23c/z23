/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Tor integration: no-SOCKS torrc, persistent .onion keys.
 *
 * Our forked Tor uses dynhost — NO SOCKS, NO extra ports.
 * These tests verify that invariant is never violated. */

#include "test/test_core.h"
#include "base/compiler.h"
#include "net/tor_integration.h"
#include "net/file_service.h"
#include "net/onion_service.h"
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"
#include "net/netaddr.h"
#include "net/netbase.h"
#include "util/log_rotate.h"
#include "config/boot_internal.h"
#include "platform/time_compat.h"
#include "platform/clock.h"
#include "util/thread_registry.h"
#include "util/signal_handler.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>

extern bool msg_version_file_port_for_test(const struct p2p_node *node,
                                           uint16_t *port);

/* Remove a fixture tree by delegating to the shared test_rm_rf_recursive():
 * the top argument is normalized (trailing separators stripped) and classified
 * with platform_file_shape_read before use, a link is removed as a link and is
 * never enumerated, and each entry is classified before descent. Child paths
 * are rebuilt by name, so ancestor and concurrent swaps are NOT covered. A
 * missing path is logged by the helper and otherwise ignored. */
static void remove_tree(const char *path)
{
    (void)test_rm_rf_recursive(path);
}

static int test_tor_initial_state(void)
{
    int failures = 0;
    printf("test_tor_initial_state: ");

    if (tor_integration_is_ready()) {
        printf("FAIL (should not be ready before start)\n");
        failures++;
    } else {
        printf("OK\n");
    }

    printf("test_tor_dial_initial_state: ");
    if (tor_integration_is_dial_ready()) {
        printf("FAIL (should not queue dials before start)\n");
        failures++;
    } else {
        printf("OK\n");
    }

    printf("test_tor_get_onion_null: ");
    if (tor_integration_get_onion_address() != NULL) {
        printf("FAIL (should be NULL before start)\n");
        failures++;
    } else {
        printf("OK\n");
    }

    return failures;
}

static int test_tor_requested_without_start(void)
{
    int failures = 0;
    printf("test_tor_requested_without_start: ");

    tor_integration_stop();
    if (tor_integration_is_requested() || tor_integration_is_enabled()) {
        printf("FAIL (requested/enabled after stop)\n");
        return 1;
    }
    tor_integration_mark_requested();
    if (!tor_integration_is_requested()) {
        printf("FAIL (mark_requested did not stick)\n");
        failures++;
    } else if (tor_integration_is_enabled() || tor_integration_is_ready()) {
        printf("FAIL (requested must not imply running)\n");
        failures++;
    } else {
        printf("OK\n");
    }
    tor_integration_stop();
    return failures;
}

static int test_tor_stop_when_not_running(void)
{
    int failures = 0;
    printf("test_tor_stop_when_not_running: ");

    tor_integration_stop();

    if (!tor_integration_is_ready() &&
        !tor_integration_is_dial_ready()) {
        printf("OK\n");
    } else {
        printf("FAIL (should not be ready after stop)\n");
        failures++;
    }

    return failures;
}

/* Tor is the DEFAULT: a build that linked real Tor opens its onion with no
 * flag at all, and -no-tor is the only thing that stops it. This used to
 * assert the opposite — that an absent -tor left Tor idle — which was the
 * behaviour that let a node boot clearnet-only because a unit file forgot a
 * flag.
 *
 * Two halves, because only one of them can be exercised without starting a
 * real Tor: the OFF path runs boot_onion_tor_start_early() for real and
 * insists nothing came up, and the ON path asserts the decision
 * (boot_profile_has_onion) rather than paying 30 s to watch Tor bootstrap in
 * a unit test. */
static int test_boot_onion_early_skips_only_when_told(void)
{
    int failures = 0;
    printf("test_boot_onion_early_skips_only_when_told: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "tor", "earlyskip");
    struct app_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = tmpdir;
    ctx.no_tor = true;
    ctx.p2p_port = 39040;
    bool ok = boot_onion_tor_start_early(&ctx);
    bool idle = !tor_integration_is_enabled() && !tor_integration_is_ready();

    /* -no-tor leaves Tor idle whichever Tor this binary linked. */
    if (!ok || !idle) {
        printf("FAIL (-no-tor: ok=%d enabled=%d ready=%d)\n",
               ok, tor_integration_is_enabled(), tor_integration_is_ready());
        failures++;
        tor_integration_stop();
        remove_tree(tmpdir);
        return failures;
    }

    /* Same datadir, no flags at all: a real-Tor build must decide to start,
     * a stub build must not — and the decision must track the LINKED Tor,
     * not a build-time define. */
    struct app_context def;
    memset(&def, 0, sizeof(def));
    def.datadir = tmpdir;
    def.p2p_port = 39040;
    if (boot_profile_has_onion(&def) != app_tor_real_build_linked()) {
        printf("FAIL (default: has_onion=%d real_tor_linked=%d)\n",
               boot_profile_has_onion(&def), app_tor_real_build_linked());
        failures++;
        remove_tree(tmpdir);
        return failures;
    }

    /* And -no-tor must beat the default on either build. */
    if (boot_profile_has_onion(&ctx)) {
        printf("FAIL (-no-tor did not beat the default)\n");
        failures++;
        remove_tree(tmpdir);
        return failures;
    }

    printf("OK\n");
    remove_tree(tmpdir);
    return failures;
}

/* ── torrc generation tests ────────────────────────────────── */

/* Verify torrc uses localhost-only bootstrap port derived from p2p_port.
 * The SocksPort is a Tor bootstrap workaround — nothing connects to it.
 * It must be localhost-only and derived from p2p_port to avoid collisions. */
static int test_tor_write_torrc_bootstrap_port(void)
{
    int failures = 0;
    printf("test_tor_write_torrc_bootstrap_port: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "nosocks");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    /* Default port 8033 → bootstrap port 19999 */
    bool ok = tor_write_torrc(tmpdir, 8033, false);
    if (!ok) {
        printf("FAIL (tor_write_torrc returned false)\n");
        remove_tree(tmpdir);
        return 1;
    }

    char torrc_path[512];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", tmpdir);
    FILE *f = fopen(torrc_path, "r");
    if (!f) {
        printf("FAIL (torrc not written)\n");
        remove_tree(tmpdir);
        return 1;
    }

    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    /* Must be localhost-only (127.0.0.1) */
    bool has_localhost = strstr(buf, "SocksPort 127.0.0.1:") != NULL;
    /* Must derive correctly: 8033 + 11966 = 19999 */
    bool has_correct_port = strstr(buf, "SocksPort 127.0.0.1:19999") != NULL;
    bool has_datadir = strstr(buf, "DataDirectory") != NULL;
    bool has_log = strstr(buf, "Log notice") != NULL;
    bool has_rend_info = strstr(buf, "Log info [rend]") != NULL;

    if (has_localhost && has_correct_port && has_datadir && has_log &&
        has_rend_info) {
        printf("OK\n");
    } else {
        printf("FAIL (localhost=%d port=%d datadir=%d log=%d rend=%d)\n",
               has_localhost, has_correct_port, has_datadir, has_log,
               has_rend_info);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* Different p2p_port must produce different bootstrap port — no collisions */
static int test_tor_write_torrc_no_collision(void)
{
    int failures = 0;
    printf("test_tor_write_torrc_no_collision: ");

    char tmpdir1[512];
    char tmpdir2[512];
    test_make_tmpdir(tmpdir1, sizeof(tmpdir1), "torrc", "collision1");
    test_make_tmpdir(tmpdir2, sizeof(tmpdir2), "torrc", "collision2");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir1);
    mkdir(td, 0700);
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir2);
    mkdir(td, 0700);

    /* Port 8033 and 8035 should produce different bootstrap ports */
    tor_write_torrc(tmpdir1, 8033, false);
    tor_write_torrc(tmpdir2, 8035, false);

    char path1[512], path2[512];
    snprintf(path1, sizeof(path1), "%s/torrc", tmpdir1);
    snprintf(path2, sizeof(path2), "%s/torrc", tmpdir2);

    FILE *f1 = fopen(path1, "r");
    FILE *f2 = fopen(path2, "r");
    char buf1[2048] = "", buf2[2048] = "";
    if (f1) { size_t n = fread(buf1, 1, sizeof(buf1)-1, f1); buf1[n] = '\0'; fclose(f1); }
    if (f2) { size_t n = fread(buf2, 1, sizeof(buf2)-1, f2); buf2[n] = '\0'; fclose(f2); }

    /* 8033+11966=19999, 8035+11966=20001 — different ports */
    bool port1_ok = strstr(buf1, ":19999") != NULL;
    bool port2_ok = strstr(buf2, ":20001") != NULL;

    if (port1_ok && port2_ok) {
        printf("OK\n");
    } else {
        printf("FAIL (port1=%d port2=%d)\n", port1_ok, port2_ok);
        failures++;
    }

    remove_tree(tmpdir1);
    remove_tree(tmpdir2);
    return failures;
}

/* Verify torrc has correct DataDirectory path */
static int test_tor_write_torrc_datadir(void)
{
    int failures = 0;
    printf("test_tor_write_torrc_datadir: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "datadir");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    tor_write_torrc(tmpdir, 8033, false);

    char torrc_path[512];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", tmpdir);
    FILE *f = fopen(torrc_path, "r");
    if (!f) {
        printf("FAIL (torrc not written)\n");
        remove_tree(tmpdir);
        return 1;
    }

    char buf[2048];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    char expected[512];
    snprintf(expected, sizeof(expected), "DataDirectory %s/tor_data", tmpdir);

    if (strstr(buf, expected)) {
        printf("OK\n");
    } else {
        printf("FAIL (expected '%s')\n", expected);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* Verify torrc is idempotent — calling twice produces same result */
static int test_tor_write_torrc_idempotent(void)
{
    int failures = 0;
    printf("test_tor_write_torrc_idempotent: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "idempotent");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    tor_write_torrc(tmpdir, 8033, false);

    char torrc_path[512];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", tmpdir);

    /* Read first write */
    FILE *f = fopen(torrc_path, "r");
    char buf1[2048] = "";
    if (f) {
        size_t n = fread(buf1, 1, sizeof(buf1) - 1, f);
        buf1[n] = '\0';
        fclose(f);
    }

    /* Write again */
    tor_write_torrc(tmpdir, 8033, false);

    f = fopen(torrc_path, "r");
    char buf2[2048] = "";
    if (f) {
        size_t n = fread(buf2, 1, sizeof(buf2) - 1, f);
        buf2[n] = '\0';
        fclose(f);
    }

    if (strcmp(buf1, buf2) == 0 && strlen(buf1) > 0) {
        printf("OK\n");
    } else {
        printf("FAIL (torrc changed between writes)\n");
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* ── .onion address tests ──────────────────────────────────── */

static int test_tor_persistent_hostname_read(void)
{
    int failures = 0;
    printf("test_tor_persistent_hostname_read: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "hostname");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);
    snprintf(td, sizeof(td), "%s/tor_data/onion_service", tmpdir);
    mkdir(td, 0700);

    char hostname_path[512];
    snprintf(hostname_path, sizeof(hostname_path),
             "%s/tor_data/onion_service/hostname", tmpdir);

    const char *fake_onion =
        "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion";

    FILE *f = fopen(hostname_path, "w");
    if (!f) {
        printf("SKIP (cannot write hostname file)\n");
        remove_tree(tmpdir);
        return 0;
    }
    fprintf(f, "%s\n", fake_onion);
    fclose(f);

    onion_service_set_address(fake_onion);
    const char *addr = onion_service_get_address();

    if (addr && strcmp(addr, fake_onion) == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (got '%s', expected '%s')\n",
               addr ? addr : "NULL", fake_onion);
        failures++;
    }

    onion_service_set_address(NULL);
    remove_tree(tmpdir);
    return failures;
}

static int test_tor_address_persists_across_restarts(void)
{
    int failures = 0;
    printf("test_tor_address_persists_across_restarts: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "persist");

    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);
    snprintf(td, sizeof(td), "%s/tor_data/onion_service", tmpdir);
    mkdir(td, 0700);

    const char *expected =
        "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv1234.onion";

    char hostname_path[512];
    snprintf(hostname_path, sizeof(hostname_path),
             "%s/tor_data/onion_service/hostname", tmpdir);
    FILE *f = fopen(hostname_path, "w");
    if (!f) {
        printf("SKIP (cannot write hostname)\n");
        remove_tree(tmpdir);
        return 0;
    }
    fprintf(f, "%s\n", expected);
    fclose(f);

    /* Simulate first run */
    onion_service_set_address(expected);
    const char *addr1 = onion_service_get_address();

    /* Simulate restart: clear */
    onion_service_set_address(NULL);
    const char *cleared = onion_service_get_address();

    /* Simulate second run: re-read from hostname file */
    f = fopen(hostname_path, "r");
    char line[128] = "";
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
        }
        fclose(f);
    }
    onion_service_set_address(line);
    const char *addr2 = onion_service_get_address();

    bool ok = addr1 && strcmp(addr1, expected) == 0
           && cleared == NULL
           && addr2 && strcmp(addr2, expected) == 0;

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (addr1='%s' cleared='%s' addr2='%s')\n",
               addr1 ? addr1 : "NULL",
               cleared ? cleared : "NULL",
               addr2 ? addr2 : "NULL");
        failures++;
    }

    onion_service_set_address(NULL);
    remove_tree(tmpdir);
    return failures;
}

static int test_tor_set_address_null_clears(void)
{
    int failures = 0;
    printf("test_tor_set_address_null_clears: ");

    onion_service_set_address("test.onion");
    const char *a = onion_service_get_address();
    bool had = a && strcmp(a, "test.onion") == 0;

    onion_service_set_address(NULL);
    bool gone = onion_service_get_address() == NULL;

    if (had && gone) {
        printf("OK\n");
    } else {
        printf("FAIL (had=%d gone=%d)\n", had, gone);
        failures++;
    }

    return failures;
}

/* The dynhost log appends across boots and every Tor start mints a fresh
 * ephemeral service: the scan must return the LAST address at/after the
 * caller's start offset, never an earlier (dead) one. Covers the live
 * defect where first-match-from-zero republished boot #1's dead onion
 * after every restart. */
static int test_tor_log_last_ephemeral_address(void)
{
    int failures = 0;
    printf("test_tor_log_last_ephemeral_address: ");

    char tmpdir[PATH_MAX];
    if (!test_mkdtemp(tmpdir, sizeof tmpdir, "zcl_test_torlog")) {
        printf("FAIL (mkdtemp)\n");
        return 1;
    }
    char log_path[1100];
    snprintf(log_path, sizeof(log_path), "%s/tor.log", tmpdir);

    const char *boot1 =
        "Jun 11 [notice] Activating dynhost ephemeral service\n"
        "Jun 11 [notice] Dynamic onion host ephemeral service created "
        "with address: aaaaboot1dead\n";
    const char *boot2 =
        "Jun 12 [notice] Bootstrapped 100% (done)\n"
        "Jun 12 [notice] Dynamic onion host ephemeral service created "
        "with address: bbbbboot2live\n";

    FILE *f = fopen(log_path, "w");
    if (!f) {
        printf("FAIL (open log)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs(boot1, f);
    long boot2_offset = ftell(f);
    fputs(boot2, f);
    fclose(f);

    char out[128];

    /* From boot 2's start offset: only the live address is visible. */
    bool ok_offset =
        tor_log_last_ephemeral_address(log_path, boot2_offset, out,
                                       sizeof(out)) &&
        strcmp(out, "bbbbboot2live") == 0;

    /* From offset 0 the LAST match still wins (never the dead first). */
    bool ok_last =
        tor_log_last_ephemeral_address(log_path, 0, out, sizeof(out)) &&
        strcmp(out, "bbbbboot2live") == 0;

    /* Offset beyond EOF (file rotated/shrank): falls back to full scan. */
    bool ok_shrunk =
        tor_log_last_ephemeral_address(log_path, 1 << 20, out,
                                       sizeof(out)) &&
        strcmp(out, "bbbbboot2live") == 0;

    /* No match at/after the offset => false. */
    f = fopen(log_path, "a");
    long tail_offset = 0;
    if (f) {
        tail_offset = ftell(f);
        fputs("Jun 12 [notice] nothing relevant here\n", f);
        fclose(f);
    }
    bool ok_nomatch =
        !tor_log_last_ephemeral_address(log_path, tail_offset, out,
                                        sizeof(out));

    /* Missing file => false. */
    char missing[1100];
    snprintf(missing, sizeof(missing), "%s/absent.log", tmpdir);
    bool ok_missing =
        !tor_log_last_ephemeral_address(missing, 0, out, sizeof(out));

    if (ok_offset && ok_last && ok_shrunk && ok_nomatch && ok_missing) {
        printf("OK\n");
    } else {
        printf("FAIL (offset=%d last=%d shrunk=%d nomatch=%d missing=%d)\n",
               ok_offset, ok_last, ok_shrunk, ok_nomatch, ok_missing);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* Hostname-only is not publication. First-boot READY must wait for a
 * successful HSDir upload line (or the DESCRIPTOR PUBLICATION marker).
 * Drives the shipped scanner; does not reimplement it. */
static int test_tor_log_has_descriptor_publication(void)
{
    int failures = 0;
    printf("test_tor_log_has_descriptor_publication: ");

    char tmpdir[PATH_MAX];
    if (!test_mkdtemp(tmpdir, sizeof tmpdir, "zcl_test_tordesc")) {
        printf("FAIL (mkdtemp)\n");
        return 1;
    }
    char path[1100];

    const char *hostname_only =
        "Jun 11 [notice] Dynamic onion host ephemeral service created "
        "with address: aaaaboot1dead\n"
        "Jun 11 [notice] Bootstrapped 100% (done)\n";
    const char *failed_upload =
        "Jun 12 [info] Uploaded hidden service descriptor (status 503 "
        "(Service Unavailable))\n";
    const char *published =
        "Jun 13 [info] Uploaded hidden service descriptor (status 200 "
        "(OK))\n";
    const char *marker =
        "Jun 14 [notice] DESCRIPTOR PUBLICATION observed for "
        "bbbbboot2live.onion\n";

    snprintf(path, sizeof(path), "%s/host.log", tmpdir);
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("FAIL (open host.log)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs(hostname_only, f);
    fclose(f);
    bool ok_host = !tor_log_has_descriptor_publication(path, 0);

    snprintf(path, sizeof(path), "%s/fail.log", tmpdir);
    f = fopen(path, "w");
    if (!f) {
        printf("FAIL (open fail.log)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs(failed_upload, f);
    fclose(f);
    bool ok_fail = !tor_log_has_descriptor_publication(path, 0);

    snprintf(path, sizeof(path), "%s/pub.log", tmpdir);
    f = fopen(path, "w");
    if (!f) {
        printf("FAIL (open pub.log)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs(hostname_only, f);
    long after_host = ftell(f);
    fputs(published, f);
    fclose(f);
    bool ok_pub = tor_log_has_descriptor_publication(path, 0);
    bool ok_offset = tor_log_has_descriptor_publication(path, after_host);

    snprintf(path, sizeof(path), "%s/marker.log", tmpdir);
    f = fopen(path, "w");
    if (!f) {
        printf("FAIL (open marker.log)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs(marker, f);
    fclose(f);
    bool ok_marker = tor_log_has_descriptor_publication(path, 0);

    snprintf(path, sizeof(path), "%s/absent.log", tmpdir);
    bool ok_missing = !tor_log_has_descriptor_publication(path, 0);

    if (ok_host && ok_fail && ok_pub && ok_offset && ok_marker &&
        ok_missing) {
        printf("OK\n");
    } else {
        printf("FAIL (host=%d fail=%d pub=%d offset=%d marker=%d "
               "missing=%d)\n",
               ok_host, ok_fail, ok_pub, ok_offset, ok_marker, ok_missing);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* The dynhost reassembly buffer is the one place an unauthenticated
 * onion client directly drives node memory: everything it sends before
 * its request completes lands there. Pin the admission rule (capped,
 * overflow-safe) and the completion predicate's honest refusals, so the
 * cap the drain loop enforces cannot quietly regress to unbounded
 * accumulation — and so a stalled or oversized client is bounded by the
 * cap, never by the client's goodwill.
 *
 * The handlers live in the vendored Tor archive, which stub-only builds
 * (Darwin, offline default) do not link; the weak declarations resolve
 * to NULL there and the checks report a skip instead of failing the
 * link. On any host that builds the full embedded Tor — the profile the
 * serving node ships — they are live assertions. */
static int test_dynhost_reassembly_cap(void)
{
    extern size_t dynhost_reassembly_cap(void) __attribute__((weak));
    extern int dynhost_reassembly_admits(size_t accumulated, size_t incoming)
        __attribute__((weak));
    extern int dynhost_webserver_has_complete_request(const uint8_t *data,
                                                      size_t len)
        __attribute__((weak));

    int failures = 0;
    printf("test_dynhost_reassembly_cap: ");

    if (!dynhost_reassembly_cap || !dynhost_reassembly_admits ||
        !dynhost_webserver_has_complete_request) {
        printf("SKIP (stub Tor build: vendored dynhost not linked)\n");
        return 0;
    }

    const size_t cap = dynhost_reassembly_cap();
    bool ok = cap >= 65536; /* must hold the production response buffer */
    ok = ok && dynhost_reassembly_admits(0, cap) == 1;
    ok = ok && dynhost_reassembly_admits(0, cap + 1) == 0;
    ok = ok && dynhost_reassembly_admits(cap - 1, 1) == 1;
    ok = ok && dynhost_reassembly_admits(cap, 1) == 0;
    ok = ok && dynhost_reassembly_admits(SIZE_MAX, 1) == 0;

    /* Completion semantics the cap leans on: a stream with no header
     * terminator never completes, and a POST that declares a body it
     * never sends never completes either — both used to accumulate
     * forever, both now hit the cap and close. */
    static const uint8_t GET_FULL[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    static const uint8_t GET_PARTIAL[] = "GET / HTTP/1.1\r\nHost: a\r\n";
    static const uint8_t POST_STALLED[] =
        "POST / HTTP/1.1\r\nHost: a\r\n"
        "Content-Length: 2147483647\r\n\r\n";
    ok = ok && dynhost_webserver_has_complete_request(
                    GET_FULL, sizeof(GET_FULL) - 1) == 1;
    ok = ok && dynhost_webserver_has_complete_request(
                    GET_PARTIAL, sizeof(GET_PARTIAL) - 1) == 0;
    ok = ok && dynhost_webserver_has_complete_request(
                    POST_STALLED, sizeof(POST_STALLED) - 1) == 0;

    if (ok) {
        printf("OK\n");
    } else {
        printf("FAIL (cap=%zu)\n", cap);
        failures++;
    }
    return failures;
}

/* The C5 remote buyer path weak-imports dynhost_client_fetch_ex from the
 * vendored Tor archive; core has declared tor_integration_fetch_onion_post
 * since fc42ddd333, so any parent pin at or beyond the POST client commit
 * MUST ship the symbol. A full embedded-Tor link that resolves
 * dynhost_client_fetch but NOT dynhost_client_fetch_ex means the vendor
 * pin moved backwards under a core that sells the POST path — exactly the
 * dead buyer path that shipped when a resident-launch commit reverted the
 * pin (2026-09-14). Fail LOUD on that mismatch; skip only on stub builds
 * where no dynhost client is linked at all (Darwin, offline default). */
static int test_dynhost_post_client_pin(void)
{
    extern int dynhost_client_fetch(const char *, uint16_t, const char *,
        void (*)(int, const uint8_t *, size_t, void *), void *, int)
        __attribute__((weak));
    extern int dynhost_client_fetch_ex(const char *, uint16_t, const char *,
        const char *, const uint8_t *, size_t,
        void (*)(int, const uint8_t *, size_t, void *), void *, int)
        __attribute__((weak));

    int failures = 0;
    printf("test_dynhost_post_client_pin: ");

    if (!dynhost_client_fetch && !dynhost_client_fetch_ex) {
        printf("SKIP (stub Tor build: vendored dynhost not linked)\n");
        return 0;
    }
    if (dynhost_client_fetch && !dynhost_client_fetch_ex) {
        printf("FAIL (full Tor link without dynhost_client_fetch_ex — "
               "vendor pin behind the POST client commit; remotebuy is "
               "stub-dead)\n");
        return 1;
    }
    printf("OK\n");
    return failures;
}

/* ── log level and log rotation ──────────────────────────────────────
 *
 * A field box carried a 1,319 MB tor.log FULL of "[info]" lines under a
 * torrc whose first Log line says "Log notice file". The cause was the
 * SECOND Log line: "Log info [rend] file <same file>" silently raised the
 * level of the same destination. The [rend] info stream is genuinely needed
 * (Tor reports a successful HSDir descriptor upload at info level), so the
 * fix is a separate destination — which is exactly what this pins. */
static int test_tor_torrc_log_levels(void)
{
    int failures = 0;
    printf("test_tor_torrc_log_levels: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "loglevels");
    char td[600];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    if (!tor_write_torrc(tmpdir, 8033, false)) {
        printf("FAIL (tor_write_torrc returned false)\n");
        remove_tree(tmpdir);
        return 1;
    }

    char torrc_path[600];
    snprintf(torrc_path, sizeof(torrc_path), "%s/torrc", tmpdir);
    FILE *f = fopen(torrc_path, "r");
    if (!f) {
        printf("FAIL (torrc not written)\n");
        remove_tree(tmpdir);
        return 1;
    }
    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    char notice_line[900], info_line[900];
    snprintf(notice_line, sizeof(notice_line), "Log notice file %s/%s\n",
             tmpdir, TOR_LOG_BASENAME);
    snprintf(info_line, sizeof(info_line), "Log info [rend] file %s/%s\n",
             tmpdir, TOR_REND_LOG_BASENAME);

    bool notice_to_tor_log = strstr(buf, notice_line) != NULL;
    bool info_to_its_own_file = strstr(buf, info_line) != NULL;
    /* THE regression: no info-level line may name tor.log. */
    char info_to_tor_log_str[900];
    snprintf(info_to_tor_log_str, sizeof(info_to_tor_log_str),
             "Log info [rend] file %s/%s\n", tmpdir, TOR_LOG_BASENAME);
    bool info_leaks_into_tor_log = strstr(buf, info_to_tor_log_str) != NULL;

    if (notice_to_tor_log && info_to_its_own_file && !info_leaks_into_tor_log) {
        printf("OK\n");
    } else {
        printf("FAIL (notice=%d rend_own_file=%d info_leak=%d)\n",
               notice_to_tor_log, info_to_its_own_file,
               info_leaks_into_tor_log);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* Both Tor logs are size-bounded. Driven with a fake file rather than a real
 * Tor: the rotation must be provable without a network. */
static int test_tor_log_rotation(void)
{
    int failures = 0;
    printf("test_tor_log_rotation: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torlog", "rotate");

    char tor_log[700], rend_log[700], tor_prev[740];
    if (!tor_log_path(tmpdir, tor_log, sizeof(tor_log)) ||
        !tor_rend_log_path(tmpdir, rend_log, sizeof(rend_log))) {
        printf("FAIL (log paths did not compose)\n");
        remove_tree(tmpdir);
        return 1;
    }
    snprintf(tor_prev, sizeof(tor_prev), "%s.1", tor_log);

    /* Nothing on disk: nothing to rotate, and no invented files. */
    bool none_when_absent = tor_logs_rotate(tmpdir, 64 * 1024) == 0;

    /* One log over the bound, one under. Only the over-bound one moves. */
    bool wrote = true;
    FILE *f = fopen(tor_log, "wb");
    if (f) {
        char block[4096];
        memset(block, 'n', sizeof(block));
        for (int i = 0; i < 40 && wrote; i++)
            wrote = fwrite(block, 1, sizeof(block), f) == sizeof(block);
        fclose(f);
    } else {
        wrote = false;
    }
    f = fopen(rend_log, "wb");
    if (f) {
        fputs("one short line\n", f);
        fclose(f);
    }

    int rotated = tor_logs_rotate(tmpdir, 64 * 1024);
    bool only_the_big_one = rotated == 1;
    bool tor_log_emptied = log_rotate_file_size(tor_log) == 0;
    bool history_kept = log_rotate_file_size(tor_prev) == 40 * 4096;
    bool rend_untouched = log_rotate_file_size(rend_log) > 0;

    if (wrote && none_when_absent && only_the_big_one && tor_log_emptied &&
        history_kept && rend_untouched) {
        printf("OK\n");
    } else {
        printf("FAIL (wrote=%d absent=%d rotated=%d emptied=%d kept=%d "
               "rend=%d)\n", wrote, none_when_absent, rotated,
               tor_log_emptied, history_kept, rend_untouched);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

#if !defined(_WIN32)
/* Checked, non-recursive cleanup of the symlink fixture: the link first. */
static bool nofollow_cleanup(const char *root, const char *target,
                             const char *sentinel, const char *link)
{
    (void)unlink(link);
    bool clean = true;
    if (unlink(sentinel) != 0 && errno != ENOENT) clean = false;
    if (rmdir(target) != 0 && errno != ENOENT) clean = false;
    if (rmdir(root) != 0 && errno != ENOENT) clean = false;
    return clean;
}

/* The remover must unlink a symbolic link at its top, never walk through it.
 * The link points (relative) at a sibling directory this test creates and
 * fills with one sentinel; cleanup is checked unlink/rmdir only, and the link
 * is unlinked before anything else runs. */
static int test_remove_tree_does_not_follow_symlink(void)
{
    int failures = 0;
    printf("test_remove_tree_does_not_follow_symlink: ");

    char root[512], target[640], sentinel[704], link[640];
    test_make_tmpdir(root, sizeof(root), "torrc", "nofollow");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) remove_tree(link);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d clean=%d)\n",
               linked, link_gone, kept, clean);
        failures++;
    }
    return failures;
}

/* Trailing-separator control: "root/link/" must not resolve the link's
 * referent. The link points (relative) at a sibling directory this case
 * creates and fills with one sentinel. The shared normalizer strips the
 * separator, so the link is removed as a link and the sentinel and target
 * directory survive. Cleanup is checked unlink/rmdir only, link first, and
 * runs before any assertion. */
static int test_remove_tree_trailing_separator_keeps_target(void)
{
    int failures = 0;
    printf("test_remove_tree_trailing_separator_keeps_target: ");

    char root[512], target[640], sentinel[704], link[640], slashed[648];
    test_make_tmpdir(root, sizeof(root), "torrc", "nofollow_slash");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);
    snprintf(slashed, sizeof(slashed), "%s/", link);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) remove_tree(slashed);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;
    bool target_kept = linked && stat(target, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && target_kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d target_kept=%d clean=%d)\n",
               linked, link_gone, kept, target_kept, clean);
        failures++;
    }
    return failures;
}
#endif

/* ── blocking onion fetch abandons on process shutdown ───────────────
 * An in-flight blocking fetch polled out its full timeout (60 s by
 * default) at shutdown. The shutdown flag is process-wide and cannot be
 * reset, so the probe runs in a forked child that _exit()s, which keeps the
 * parent's buffered stdout out of the child. The fake dispatcher accepts
 * the request and never calls back; the child then completes the callback
 * reference itself so the fetch context is freed rather than leaked. */
static tor_fetch_callback_fn g_shutdown_probe_cb;
static void *g_shutdown_probe_ctx;

static int shutdown_probe_fake_dispatch(const char *onion_address,
                                        const char *path, bool use_post,
                                        const uint8_t *body, size_t body_len,
                                        tor_fetch_callback_fn callback,
                                        void *ctx, int timeout_secs)
{
    (void)onion_address;
    (void)path;
    (void)use_post;
    (void)body;
    (void)body_len;
    (void)timeout_secs;
    g_shutdown_probe_cb = callback;
    g_shutdown_probe_ctx = ctx;
    return 0;
}

static int shutdown_probe_child(void)
{
    struct onion_fetch_result res;
    memset(&res, 0, sizeof(res));
    int64_t t0 = platform_time_monotonic_ms();
    thread_registry_request_shutdown();
    int rc = tor_integration_fetch_onion_blocking_for_test(
        "probe.onion", "/", &res, 30, shutdown_probe_fake_dispatch);
    int64_t elapsed = platform_time_monotonic_ms() - t0;
    if (g_shutdown_probe_cb)
        g_shutdown_probe_cb(200, NULL, 0, g_shutdown_probe_ctx);
    return (rc == -1 && elapsed < 2000) ? 0 : 1;
}

static int test_blocking_fetch_abandons_on_shutdown(void)
{
    printf("test_blocking_fetch_abandons_on_shutdown: ");
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL (fork)\n");
        return 1;
    }
    if (pid == 0)
        _exit(shutdown_probe_child());

    int status = 0;
    bool done = false;
    for (int i = 0; i < 150 && !done; i++) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            done = true;
        else if (w < 0)
            break;
        else
            platform_sleep_ms(100); /* real-clock: bounds the wait on a forked child's exit; the child measures the fetch on its own monotonic clock */
    }
    if (!done) {
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        printf("FAIL (child still blocked after 15 s)\n");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("FAIL (fetch did not return -1 within 2 s of shutdown)\n");
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* Padding reduction is opt-in. reduced_padding=false must write exactly the
 * four base lines servers run with; reduced_padding=true appends the two Tor
 * mobile-client lines that only the Android build requests. */
static bool read_torrc_text(const char *dir, char *buf, size_t size)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/torrc", dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    size_t n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return true;
}

/* Embedded Tor must not install its own libevent handlers for SIGTERM/SIGINT:
 * it would swallow the node's shutdown signal, exit 0 on its own, and leave
 * the node running until SIGKILL. The torrc must say so, padding on or off. */
static int test_tor_write_torrc_disables_signal_handlers(void)
{
    printf("test_tor_write_torrc_disables_signal_handlers: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "nosig");
    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    char got[3072];
    bool off_ok = tor_write_torrc(tmpdir, 8033, false) &&
                  read_torrc_text(tmpdir, got, sizeof(got)) &&
                  strstr(got, "\n__DisableSignalHandlers 1\n") != NULL;
    bool on_ok = tor_write_torrc(tmpdir, 8033, true) &&
                 read_torrc_text(tmpdir, got, sizeof(got)) &&
                 strstr(got, "\n__DisableSignalHandlers 1\n") != NULL;

    remove_tree(tmpdir);
    if (off_ok && on_ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (padding_off=%d padding_on=%d)\n", off_ok, on_ok);
    return 1;
}

/* A failed torrc write must not leave a half-written torrc behind: a
 * truncated file could omit __DisableSignalHandlers and still be read by Tor.
 * /dev/full accepts the open and refuses the write, so the only way the
 * writer can notice is by checking fflush/fclose; pointing the datadir at a
 * path whose torrc cannot be created covers the open failure. */
static int test_tor_write_torrc_reports_write_failure(void)
{
    printf("test_tor_write_torrc_reports_write_failure: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "wfail");
    char missing[600];
    snprintf(missing, sizeof(missing), "%s/no_such_dir", tmpdir);
    bool open_fail_reported = !tor_write_torrc(missing, 8033, false);

    /* torrc as a symlink to /dev/full: open succeeds, every write fails.
     * Prove the fixture is what it claims (a link that really points at
     * /dev/full) before trusting any verdict drawn from it; without
     * /dev/full the check cannot run and says so. */
    char torrc[600];
    snprintf(torrc, sizeof(torrc), "%s/torrc", tmpdir);
    struct stat dev_full_st;
    if (stat("/dev/full", &dev_full_st) != 0) {
        /* Only a truly absent /dev/full skips; any other stat error fails. */
        int stat_errno = errno;
        remove_tree(tmpdir);
        if (stat_errno != ENOENT) {
            printf("FAIL (stat /dev/full: %s)\n", strerror(stat_errno));
            return 1;
        }
        printf("OK (skipped write-failure half: /dev/full absent; open-failure=%d)\n",
               open_fail_reported);
        return open_fail_reported ? 0 : 1;
    }
    bool linked = symlink("/dev/full", torrc) == 0;
    char target[64] = {0};
    struct stat lst;
    bool fixture_ok = linked && lstat(torrc, &lst) == 0 && S_ISLNK(lst.st_mode) &&
                      readlink(torrc, target, sizeof(target) - 1) > 0 &&
                      strcmp(target, "/dev/full") == 0;
    bool write_fail_reported = fixture_ok && !tor_write_torrc(tmpdir, 8033, false);
    /* lstat, not stat: a surviving dangling link must not count as gone. */
    bool partial_removed = fixture_ok && lstat(torrc, &lst) != 0 && errno == ENOENT;

    remove_tree(tmpdir);
    if (open_fail_reported && fixture_ok && write_fail_reported && partial_removed) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (open=%d fixture=%d write=%d removed=%d)\n",
           open_fail_reported, fixture_ok, write_fail_reported, partial_removed);
    return 1;
}

static volatile sig_atomic_t g_node_term_seen;
static void node_term_handler(int sig)
{
    g_node_term_seen = sig;
}

/* Poll tor.log until Tor's main loop has run handle_signals(): the
 * "Bootstrapped 0%" notice is logged right after it. */
static bool wait_tor_main_loop(const char *datadir, int seconds)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/" TOR_LOG_BASENAME, datadir);
    for (int i = 0; i < seconds * 10; i++) {
        char buf[16384];
        FILE *f = fopen(path, "r");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            buf[n] = '\0';
            fclose(f);
            if (strstr(buf, "Bootstrapped 0%")) return true;
        }
        platform_sleep_ms(100); /* real-clock: waits on another thread's Tor init */
    }
    return false;
}

/* The real thing: start embedded Tor in this process with the torrc the node
 * writes, install the node's termination handler, deliver SIGTERM and SIGINT, and
 * require that the NODE's handler saw it and Tor did not take it and exit on
 * its own. With Tor's signal handlers enabled, libevent replaces the node's
 * SIGTERM disposition, Tor logs "Catching signal TERM" and its thread ends
 * (tor_integration_is_enabled() drops to false) while the node never learns
 * of the signal. Needs a binary that linked real Tor; Tor's bootstrap
 * attempts are disabled with DisableNetwork 1 (test seam), and Tor is stopped by
 * tor_integration_stop(). */
static int test_tor_leaves_sigterm_to_the_node(void)
{
    printf("test_tor_leaves_sigterm_to_the_node: ");
    if (!app_tor_real_build_linked()) {
        printf("OK (stub Tor linked: torrc content checked by the "
               "disables_signal_handlers test)\n");
        return 0;
    }

    tor_integration_stop();
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "livesig");

    struct sigaction old_term, old_int;
    sigaction(SIGTERM, NULL, &old_term);
    sigaction(SIGINT, NULL, &old_int);
    g_node_term_seen = 0;
    /* Local fixtures only: Tor must not bootstrap to the public network. */
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");

    int fails = 0;
    const char *why = "";
    if (signal_handler_install_termination(node_term_handler) != 0) {
        fails = 1; why = "install_termination";
    } else if (!tor_integration_start(tmpdir, 39250)) {
        fails = 1; why = "tor_integration_start";
    } else if (!wait_tor_main_loop(tmpdir, 90)) {
        fails = 1; why = "tor main loop never reached";
    } else {
        kill(getpid(), SIGTERM);
        for (int i = 0; i < 30 && !g_node_term_seen; i++)
            platform_sleep_ms(100); /* real-clock: signal delivery to this process */
        platform_sleep_ms(1000); /* real-clock: give a rogue Tor handler time to end its thread */
        if (g_node_term_seen != SIGTERM) { fails = 1; why = "node handler never saw SIGTERM"; }
        else if (!tor_integration_is_enabled()) { fails = 1; why = "Tor exited on its own"; }
        if (!fails) {
            g_node_term_seen = 0;
            kill(getpid(), SIGINT);
            for (int i = 0; i < 30 && !g_node_term_seen; i++)
                platform_sleep_ms(100); /* real-clock: signal delivery to this process */
            if (g_node_term_seen != SIGINT) { fails = 1; why = "node handler never saw SIGINT"; }
            else if (!tor_integration_is_enabled()) { fails = 1; why = "Tor exited on SIGINT"; }
        }
    }

    tor_integration_stop();
    tor_integration_set_extra_torrc_for_test("");
    sigaction(SIGTERM, &old_term, NULL);
    sigaction(SIGINT, &old_int, NULL);
    remove_tree(tmpdir);
    if (!fails) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL (%s)\n", why);
    return 1;
}

/* ── Node stop with an onion dial in flight ──────────────────────────────
 *
 * Measured on a phone: Stop node took 165 s because a peer dial was queued
 * in dynhost when Tor exited. Nothing fired the stream's terminal event, so
 * the dial waited out its 60 s circuit budget, its 5 s terminal wait, and
 * then the same again for a retry that dynhost queued after Tor had gone.
 *
 * The real thing: embedded Tor with DisableNetwork 1 never completes a
 * circuit and never processes the queued stream, exactly as on a phone
 * without a reachable network. The dial runs on the production budget
 * (two 60 s attempts) through a backend that forwards to the real dynhost
 * calls and counts what they do. Stopping Tor must end the dial within a
 * few seconds: one terminal event for the queued stream, and the retry's
 * open refused at once. */
extern struct dynhost_stream *dynhost_stream_open(const char *onion,
    uint16_t port,
    void (*read_cb)(struct dynhost_stream *, const uint8_t *, size_t, void *),
    void (*event_cb)(struct dynhost_stream *, int, void *),
    void *ctx, int timeout_secs) ZCL_WEAK_IMPORT;
extern int dynhost_stream_write(struct dynhost_stream *, const uint8_t *,
                                size_t) ZCL_WEAK_IMPORT;
extern void dynhost_stream_close(struct dynhost_stream *) ZCL_WEAK_IMPORT;

#define STOP_DIAL_BUDGET_MS ONION_STREAM_RETRY_MIN_TOTAL_MS
#define STOP_DIAL_END_LIMIT_MS 5000

struct stop_dial_stream {
    onion_stream_read_fn  read_cb;
    onion_stream_event_fn event_cb;
    void                 *ctx;
    _Atomic int           terminal_events;
};

static struct stop_dial_stream g_stop_dial_streams[2];
static _Atomic int g_stop_dial_opens;
static _Atomic int g_stop_dial_queued;
static _Atomic int g_stop_dial_refused;

static void stop_dial_read(struct dynhost_stream *s, const uint8_t *data,
                           size_t len, void *ctx)
{
    struct stop_dial_stream *rec = ctx;
    rec->read_cb((struct onion_stream_raw *)s, data, len, rec->ctx);
}

static void stop_dial_event(struct dynhost_stream *s, int event, void *ctx)
{
    struct stop_dial_stream *rec = ctx;
    if (event == ONION_STREAM_EVENT_CLOSED || event == ONION_STREAM_EVENT_TIMEOUT)
        atomic_fetch_add(&rec->terminal_events, 1);
    rec->event_cb((struct onion_stream_raw *)s, event, rec->ctx);
}

static struct onion_stream_raw *stop_dial_open(
    const char *onion, uint16_t port, onion_stream_read_fn read_cb,
    onion_stream_event_fn event_cb, void *ctx, int lifetime_secs)
{
    int slot = atomic_fetch_add(&g_stop_dial_opens, 1);
    if (slot >= 2)
        return NULL;
    struct stop_dial_stream *rec = &g_stop_dial_streams[slot];
    rec->read_cb = read_cb;
    rec->event_cb = event_cb;
    rec->ctx = ctx;
    atomic_store(&rec->terminal_events, 0);
    struct dynhost_stream *s = dynhost_stream_open(onion, port, stop_dial_read,
                                                   stop_dial_event, rec,
                                                   lifetime_secs);
    atomic_fetch_add(s ? &g_stop_dial_queued : &g_stop_dial_refused, 1);
    return (struct onion_stream_raw *)s;
}

static int stop_dial_write(struct onion_stream_raw *s, const uint8_t *data,
                           size_t len)
{
    return dynhost_stream_write((struct dynhost_stream *)s, data, len);
}

static void stop_dial_close(struct onion_stream_raw *s)
{
    dynhost_stream_close((struct dynhost_stream *)s);
}

static const struct onion_stream_backend g_stop_dial_backend = {
    .open = stop_dial_open,
    .write = stop_dial_write,
    .close = stop_dial_close,
};

struct stop_dial_run {
    struct net_service svc;
    bool               connected;
    _Atomic bool       done;
    int64_t            done_ms;
};

static void *stop_dial_thread(void *arg)
{
    struct stop_dial_run *run = arg;
    zcl_socket_t sock = ZCL_INVALID_SOCKET;
    run->connected = onion_stream_connect_backend_for_test(
        &run->svc, &sock, STOP_DIAL_BUDGET_MS, &g_stop_dial_backend);
    if (sock != ZCL_INVALID_SOCKET)
        close_socket(&sock);
    run->done_ms = platform_time_monotonic_ms();
    atomic_store(&run->done, true);
    return NULL;
}

static bool stop_dial_service(struct net_service *svc)
{
    uint8_t pub[32];
    for (int i = 0; i < 32; i++)
        pub[i] = (uint8_t)(0x51 + i);
    char host[ONION_V3_ADDRESS_LEN + 1];
    net_service_init(svc);
    if (!onion_v3_address_from_pubkey(pub, host) ||
        !net_addr_from_onion(host, &svc->addr))
        return false;
    svc->port = 8033;
    return true;
}

/* Returns true once the dial thread finished; waits at most limit_ms. */
static bool stop_dial_wait_done(struct stop_dial_run *run, int limit_ms)
{
    for (int waited = 0; waited < limit_ms && !atomic_load(&run->done);
         waited += 25)
        platform_sleep_ms(25); /* real-clock: the dial runs on its own thread */
    return atomic_load(&run->done);
}

/* Queue one dial against a running Tor, stop Tor, and time the end. */
static const char *stop_dial_measure(const char *tmpdir, int64_t *end_ms)
{
    static struct stop_dial_run run;
    memset(&run, 0, sizeof(run));
    pthread_t tid;
    if (!stop_dial_service(&run.svc))
        return "onion fixture address";
    if (!tor_integration_start(tmpdir, 39251))
        return "tor_integration_start";
    if (!wait_tor_main_loop(tmpdir, 90))
        return "tor main loop never reached";
    if (pthread_create(&tid, NULL, stop_dial_thread, &run) != 0)
        return "dial thread";
    for (int i = 0; i < 200 && atomic_load(&g_stop_dial_queued) == 0; i++)
        platform_sleep_ms(25); /* real-clock: the dial thread queues the stream */
    int64_t stop_ms = platform_time_monotonic_ms();
    tor_integration_stop();
    bool ended = stop_dial_wait_done(&run, STOP_DIAL_BUDGET_MS + 15000);
    pthread_join(tid, NULL);
    *end_ms = run.done_ms - stop_ms;
    if (!ended)
        return "dial never ended";
    return run.connected ? "dial reported a circuit" : NULL;
}

extern void dynhost_stream_init(void) ZCL_WEAK_IMPORT;
extern void dynhost_stream_cleanup(void) ZCL_WEAK_IMPORT;

struct stop_race {
    _Atomic int entered;
    _Atomic int closed;
    _Atomic int events;
    _Atomic int write_result;
};

static void stop_race_read(struct dynhost_stream *s, const uint8_t *data,
                           size_t len, void *ctx)
{
    (void)s; (void)data; (void)len; (void)ctx;
}

static void stop_race_event(struct dynhost_stream *s, int event, void *ctx)
{
    struct stop_race *race = ctx;
    if (event != ONION_STREAM_EVENT_CLOSED) return;
    atomic_fetch_add(&race->events, 1);
    atomic_store(&race->entered, 1);
    for (int i = 0; i < 5000 && !atomic_load(&race->closed); i++)
        platform_sleep_ms(1); /* real-clock: synchronize with close thread */
    const uint8_t byte = 0;
    atomic_store(&race->write_result, dynhost_stream_write(s, &byte, 1));
}

static void *stop_race_cleanup(void *ctx)
{
    (void)ctx;
    dynhost_stream_cleanup();
    return NULL;
}

static bool stop_lifecycle_available(void)
{
    return app_tor_real_build_linked() && dynhost_stream_init &&
           dynhost_stream_cleanup && dynhost_stream_open &&
           dynhost_stream_close && dynhost_stream_write;
}

static int test_tor_stop_close_race(void)
{
    printf("test_tor_stop_close_race: ");
    if (!stop_lifecycle_available()) {
        printf("OK (stub Tor linked)\n");
        return 0;
    }
    struct stop_race race = {0};
    dynhost_stream_init();
    struct dynhost_stream *s = dynhost_stream_open("fixture.onion", 80,
        stop_race_read, stop_race_event, &race, 60);
    if (!s) { printf("FAIL (open)\n"); return 1; }
    pthread_t tid;
    if (pthread_create(&tid, NULL, stop_race_cleanup, NULL) != 0) {
        dynhost_stream_close(s);
        dynhost_stream_cleanup();
        printf("FAIL (thread)\n"); return 1;
    }
    for (int i = 0; i < 5000 && !atomic_load(&race.entered); i++)
        platform_sleep_ms(1); /* real-clock: wait for terminal callback */
    bool entered = atomic_load(&race.entered) != 0;
    dynhost_stream_close(s);
    atomic_store(&race.closed, 1);
    pthread_join(tid, NULL);
    bool ok = entered && atomic_load(&race.events) == 1 &&
              atomic_load(&race.write_result) == -1;
    struct dynhost_stream *refused = dynhost_stream_open("fixture.onion", 80,
        stop_race_read, stop_race_event, &race, 60);
    ok = ok && !refused;
    if (refused) dynhost_stream_close(refused);
    dynhost_stream_init();
    struct dynhost_stream *again = dynhost_stream_open("fixture.onion", 80,
        stop_race_read, stop_race_event, &race, 60);
    ok = ok && again;
    if (again) dynhost_stream_close(again);
    dynhost_stream_cleanup();
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int test_tor_stop_ends_onion_dial(void)
{
    printf("test_tor_stop_ends_onion_dial: ");
    if (!app_tor_real_build_linked() || !dynhost_stream_open ||
        !dynhost_stream_write || !dynhost_stream_close) {
        printf("OK (stub Tor linked: no dynhost streams to end)\n");
        return 0;
    }
    tor_integration_stop();
    memset(g_stop_dial_streams, 0, sizeof(g_stop_dial_streams));
    atomic_store(&g_stop_dial_opens, 0);
    atomic_store(&g_stop_dial_queued, 0);
    atomic_store(&g_stop_dial_refused, 0);
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stopdial");
    /* Local fixtures only: Tor must not bootstrap to the public network. */
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");

    int64_t end_ms = -1;
    const char *why = stop_dial_measure(tmpdir, &end_ms);
    tor_integration_stop();
    tor_integration_set_extra_torrc_for_test("");
    remove_tree(tmpdir);

    int queued = atomic_load(&g_stop_dial_queued);
    int refused = atomic_load(&g_stop_dial_refused);
    int terminal = atomic_load(&g_stop_dial_streams[0].terminal_events);
    if (!why && end_ms > STOP_DIAL_END_LIMIT_MS)
        why = "dial outlived the stop";
    if (!why && (queued != 1 || terminal != 1 || refused != 1))
        why = "stream events";
    printf("%s (end_after_stop_ms=%lld queued=%d terminal=%d refused=%d%s%s)\n",
           why ? "FAIL" : "OK", (long long)end_ms, queued, terminal, refused,
           why ? " reason=" : "", why ? why : "");
    return why ? 1 : 0;
}

/* ── Stop hands off to Tor's own thread ──────────────────────────────────
 *
 * Tor's event base has no locks, so tor_integration_stop() must not call into
 * it. Stop ends Tor by closing the owning control connection, which Tor reads
 * on its own thread. This line in Tor's log records that route; the old
 * cross-thread call never writes it. */
#define TOR_OWNER_CLOSED_LINE "Owning controller connection has closed"

/* True when Tor's log names the owner close. The test is about the route, so
 * it reads the whole file and takes no time limit beyond Tor's own exit. */
static bool tor_log_shows_owner_close(const char *datadir)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/" TOR_LOG_BASENAME, datadir);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    char buf[8192 + sizeof(TOR_OWNER_CLOSED_LINE) - 1];
    size_t carry = 0;
    bool found = false;
    while (!found) {
        size_t n = fread(buf + carry, 1, 8192, f);
        if (!n) break;
        buf[carry + n] = '\0';
        found = strstr(buf, TOR_OWNER_CLOSED_LINE) != NULL;
        carry = sizeof(TOR_OWNER_CLOSED_LINE) - 1;
        memmove(buf, buf + n, carry);
    }
    fclose(f);
    return found;
}

/* Run one stop and print how long it took; the number is reported, not
 * asserted, so a busy host cannot flip the verdict. */
static void stop_handoff_timed(const char *label)
{
    int64_t t0 = platform_time_monotonic_ms();
    tor_integration_stop();
    printf("[%s stop_ms=%lld] ", label,
           (long long)(platform_time_monotonic_ms() - t0));
}

static const char *stop_handoff_check_ended(const char *tmpdir, bool real_tor)
{
    if (tor_integration_is_enabled() || tor_integration_is_ready() ||
        tor_integration_is_dial_ready())
        return "Tor still reports running after stop";
    if (real_tor && !tor_log_shows_owner_close(tmpdir))
        return "Tor did not exit through its owning control connection";
    return NULL;
}

/* The run's two control sockets, identified by inode: a descriptor number may
 * be reused once closed, the inode of a closed socket is gone. */
struct stop_handoff_sockets {
    bool held;
    int fd[2];
    uint64_t dev[2];
    uint64_t ino[2];
};

/* Tor's end comes from the seam: Tor may close it at any moment, so this thread
 * does not touch it until the stop has joined Tor. */
static void stop_handoff_sockets_capture(struct stop_handoff_sockets *s)
{
    int64_t ours = -1, tors = -1;
    s->held = tor_integration_control_sockets_for_test(&ours, &tors,
                                                       &s->dev[1], &s->ino[1]);
    s->fd[0] = (int)ours;
    s->fd[1] = (int)tors;
    struct stat id;
    if (s->held && fstat(s->fd[0], &id) == 0) {
        s->dev[0] = (uint64_t)id.st_dev;
        s->ino[0] = (uint64_t)id.st_ino;
    } else {
        s->held = false;
    }
}

static bool stop_handoff_socket_open(const struct stop_handoff_sockets *s, int i)
{
    struct stat now;
    return fstat(s->fd[i], &now) == 0 && (uint64_t)now.st_dev == s->dev[i] &&
           (uint64_t)now.st_ino == s->ino[i];
}

/* Call only once no Tor is running: a live Tor may close its end at any moment. */
static bool stop_handoff_sockets_any_open(const struct stop_handoff_sockets *s)
{
    return s->held && (stop_handoff_socket_open(s, 0) ||
                       stop_handoff_socket_open(s, 1));
}

static uint16_t g_tor_ingress_before_join;

static void stop_handoff_capture_ingress(void)
{
    g_tor_ingress_before_join = net_onion_ingress_port();
}

static const char *stop_handoff_ingress_window(const char *why)
{
    g_tor_ingress_before_join = 0;
    net_set_onion_ingress_port(39252);
    tor_integration_before_join_for_test(stop_handoff_capture_ingress);
    stop_handoff_timed("running");
    tor_integration_before_join_for_test(NULL);
    bool ok = g_tor_ingress_before_join == 39252 && net_onion_ingress_port() == 0;
    net_set_onion_ingress_port(0);
    if (why || ok)
        return why;
    return "ingress classification was not retained until Tor join";
}

/* Stop a Tor that reached its main loop, then stop it again. */
static const char *stop_handoff_running_case(bool real_tor)
{
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stoprun");
    const char *why = NULL;
    struct stop_handoff_sockets sockets = { .held = false };
    if (!tor_integration_start(tmpdir, 39252))
        why = "tor_integration_start";
    else if (real_tor && !wait_tor_main_loop(tmpdir, 90))
        why = "tor main loop never reached";
    stop_handoff_sockets_capture(&sockets);
    if (!why && real_tor != sockets.held)
        why = "a real Tor owns a control connection and the stub none";
    if (!why && sockets.held && !(fcntl(sockets.fd[0], F_GETFD) & FD_CLOEXEC))
        why = "a child process would inherit the control connection";
    why = stop_handoff_ingress_window(why);
    if (!why)
        why = stop_handoff_check_ended(tmpdir, real_tor);
    if (!why && stop_handoff_sockets_any_open(&sockets))
        why = "a control socket outlived the stop";
    stop_handoff_timed("second");
    if (!why && tor_integration_is_enabled())
        why = "a second stop left Tor running";
    remove_tree(tmpdir);
    return why;
}

/* The monitor closes the gate while a stop is running: both ask Tor to exit
 * through the same socket and neither may close it under the other. */
static const char *stop_handoff_gate_race_case(void)
{
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stopgate");
    tor_integration_set_serve_onion(false);
    tor_integration_close_gate_for_test(true);
    const char *why = NULL;
    if (!tor_integration_start(tmpdir, 39255))
        why = "tor_integration_start";
    tor_integration_stop();
    if (!why)
        why = stop_handoff_check_ended(tmpdir, true);
    tor_integration_close_gate_for_test(false);
    tor_integration_service_reset_for_test();
    remove_tree(tmpdir);
    return why;
}

/* How many times Tor's log names the owner close: one per run that left that
 * way, since the log is appended to across runs in one datadir. */
static int tor_log_owner_close_count(const char *datadir)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/" TOR_LOG_BASENAME, datadir);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    int count = 0;
    for (const char *at = strstr(buf, TOR_OWNER_CLOSED_LINE); at;
         at = strstr(at + 1, TOR_OWNER_CLOSED_LINE))
        count++;
    return count;
}

/* A run Tor ended by itself still holds a thread and a socket. */
static const char *stop_handoff_wait_self_end(void)
{
    for (int i = 0; tor_integration_is_enabled() && i < 1200; i++)
        platform_sleep_ms(100); /* real-clock: Tor ends on its own thread; the bound only catches a hang */
    if (tor_integration_is_enabled())
        return "Tor did not end after the gate closed";
    /* With Tor gone a late command must fail plainly and must not report the
     * network enabled. */
    tor_integration_enable_reset_for_test();
    bool answered = tor_integration_enable_network_for_test();
    tor_integration_enable_reset_for_test();
    return answered ? "a command succeeded after Tor ended" : NULL;
}

/* The first run: the gate closes and Tor ends by itself. */
static const char *stop_handoff_self_end_first_run(const char *tmpdir,
                                                   struct stop_handoff_sockets *old)
{
    tor_integration_set_serve_onion(false);
    tor_integration_close_gate_for_test(true);
    const char *why = NULL;
    if (!tor_integration_start(tmpdir, 39255))
        why = "tor_integration_start";
    stop_handoff_sockets_capture(old);
    if (!why && !old->held)
        why = "the first run holds no control connection";
    if (!why)
        why = stop_handoff_wait_self_end();
    tor_integration_close_gate_for_test(false);
    tor_integration_service_reset_for_test();
    return why;
}

/* The second run: the watch's own route, since no stop ran a retry may start Tor. */
static const char *stop_handoff_self_end_second_run(const char *tmpdir,
                                                    const struct stop_handoff_sockets *old)
{
    struct stop_handoff_sockets fresh = { .held = false };
    const char *why = NULL;
    if (!tor_integration_retry_start(tmpdir, 39255))
        why = "the start after Tor ended by itself was refused";
    if (!why && !tor_integration_is_enabled())
        why = "the start after Tor ended by itself did not run Tor";
    stop_handoff_sockets_capture(&fresh);
    if (!why && (!fresh.held || fresh.ino[0] == old->ino[0]))
        why = "the new run did not make its own control connection";
    stop_handoff_timed("early");
    /* Only now: the new run may hold the old descriptor numbers, and its Tor may
     * close them at any moment. An old socket nothing closed still has its inode
     * here, because the stop closes only the new run's. */
    if (!why && stop_handoff_sockets_any_open(old))
        why = "the start did not close the ended run's control sockets";
    if (!why && tor_log_owner_close_count(tmpdir) != 2)
        why = "the second run did not exit through its control connection";
    if (!why && tor_integration_is_enabled())
        why = "Tor still reports running after stop";
    return why;
}

/* Tor ends by itself, then a start with no stop in between: it joins that run
 * and closes its sockets before making new ones. The new run is stopped at once,
 * before Tor has parsed its configuration, so the request also has to survive
 * until Tor's loop runs. */
static const char *stop_handoff_self_end_case(void)
{
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stopself");
    struct stop_handoff_sockets old = { .held = false };
    const char *why = stop_handoff_self_end_first_run(tmpdir, &old);
    if (why)
        stop_handoff_timed("early");
    else
        why = stop_handoff_self_end_second_run(tmpdir, &old);
    remove_tree(tmpdir);
    return why;
}

/* Stop at once, before Tor has parsed its configuration: the request has to
 * survive until Tor's loop runs. */
static const char *stop_handoff_early_case(bool real_tor)
{
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stopearly");
    const char *why = NULL;
    if (!tor_integration_start(tmpdir, 39253))
        why = "tor_integration_start";
    stop_handoff_timed("early");
    if (!why)
        why = stop_handoff_check_ended(tmpdir, real_tor);
    remove_tree(tmpdir);
    return why;
}

static pthread_t g_race_stopper;
static _Atomic bool g_race_stopper_made;
static _Atomic bool g_race_stopper_done;

static void *stop_handoff_stopper(void *arg)
{
    (void)arg;
    tor_integration_stop();
    atomic_store(&g_race_stopper_done, true);
    return NULL;
}

/* Inside a start, after the Tor thread exists and before the run can be stopped.
 * The stop must wait for the start to finish, so this normally sits out the whole
 * limit; the limit lets it run in the same test with a correct start. */
static void stop_handoff_start_window(void)
{
    atomic_store(&g_race_stopper_made,
                 pthread_create(&g_race_stopper, NULL, stop_handoff_stopper,
                                NULL) == 0);
    for (int i = 0; atomic_load(&g_race_stopper_made) &&
                    !atomic_load(&g_race_stopper_done) && i < 100; i++)
        platform_sleep_ms(10); /* real-clock: gives a stop that ignores the lock time to return */
}

/* A stop arriving in the middle of a start, with no further stop afterwards. It
 * waits for the start and then ends that whole run. A stop that does not wait
 * finds nothing to end yet and returns, and Tor is left running after the stop.
 * On a correct start no timing can fail this. Without the lock it fails unless
 * the stopper thread is held off the CPU for the whole limit. */
static const char *stop_handoff_start_race_case(void)
{
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "stoprace");
    const char *why = NULL;
    atomic_store(&g_race_stopper_done, false);
    tor_integration_set_start_window_for_test(stop_handoff_start_window);
    bool started = tor_integration_start(tmpdir, 39254);
    tor_integration_set_start_window_for_test(NULL);
    if (!atomic_load(&g_race_stopper_made))
        why = "stopper thread";
    else
        pthread_join(g_race_stopper, NULL);
    if (!why && !started)
        why = "tor_integration_start";
    if (!why && tor_integration_is_enabled())
        why = "Tor still running after a stop that raced its start";
    tor_integration_stop();
    remove_tree(tmpdir);
    return why;
}

static int test_tor_stop_hands_off_to_tor_thread(void)
{
    printf("test_tor_stop_hands_off_to_tor_thread: ");
    bool real_tor = app_tor_real_build_linked();
    tor_integration_stop();
    /* Local fixtures only: Tor must not bootstrap to the public network. */
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");
    const char *why = stop_handoff_running_case(real_tor);
    if (!why && !real_tor)
        why = stop_handoff_early_case(real_tor);
    if (!why)
        why = stop_handoff_start_race_case();
    if (!why && real_tor)
        why = stop_handoff_self_end_case();
    if (!why && real_tor)
        why = stop_handoff_gate_race_case();
    tor_integration_stop();
    tor_integration_set_extra_torrc_for_test("");
    printf("%s%s%s\n", why ? "FAIL (" : "OK", why ? why : "", why ? ")" : "");
    return why ? 1 : 0;
}

/* Wait for the persistent service to be installed: the monitor sets dial-ready
 * only after it. A failed install ends the wait at once; the limit catches a
 * hang, it does not measure anything. */
static bool persist_wait_installed(void)
{
    for (int i = 0; i < 1200; i++) {
        struct tor_onion_port_map map;
        tor_integration_port_map_snapshot(&map);
        if (map.state == TOR_ONION_PORT_MAP_FAILED)
            return false;
        if (tor_integration_is_dial_ready())
            return true;
        platform_sleep_ms(100); /* real-clock: the monitor installs on its own thread */
    }
    return false;
}

extern void *dynhost_get_global_service(void) ZCL_WEAK_IMPORT;

/* Onion HTTP reaches the node only when dynhost's slot holds the service Tor
 * registered for our address. A non-NULL slot proves nothing: the install holds
 * it with a sentinel before it registers anything. */
static const char *persist_slot_problem(const char *datadir)
{
    uint8_t seed[32];
    char addr[57];
    bool created = false;
    if (!onion_identity_ensure(datadir, seed, addr, sizeof(addr), &created) ||
        created)
        return "the install left no persistent identity to read";
    void *service = tor_integration_find_service_for_test(addr);
    if (!service)
        return "Tor has no service for the persistent address";
    if (*(void **)dynhost_get_global_service() != service)
        return "dynhost does not point at the persistent service";
    return NULL;
}

/* -onion-persist against the real Tor, network disabled: the node's own
 * identity is registered while Tor's loop runs and dynhost points at it. */
static int test_tor_persist_install_with_loop_running(void)
{
    printf("test_tor_persist_install_with_loop_running: ");
    if (!app_tor_real_build_linked()) {
        printf("OK (stub Tor linked: no service to install)\n");
        return 0;
    }
    tor_integration_stop();
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "persist");
    /* Local fixtures only: Tor must not bootstrap to the public network. */
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");
    tor_integration_configure_identity(true, false);

    const char *why = NULL;
    if (!tor_integration_start(tmpdir, 39256))
        why = "tor_integration_start";
    else if (!wait_tor_main_loop(tmpdir, 90))
        why = "tor main loop never reached";
    else if (!persist_wait_installed())
        why = "the persistent identity was not installed";
    else
        why = persist_slot_problem(tmpdir);
    tor_integration_stop();
    if (!why)
        why = stop_handoff_check_ended(tmpdir, true);

    tor_integration_configure_identity(false, false);
    tor_integration_set_extra_torrc_for_test("");
    remove_tree(tmpdir);
    printf("%s%s%s\n", why ? "FAIL (" : "OK", why ? why : "", why ? ")" : "");
    return why ? 1 : 0;
}

/* A watch retry decided on before the stop arrives at the lock after it: Tor
 * stays down, and it starts no thread, so this uses no start. */
static int test_tor_retry_after_stop_stays_down(void)
{
    printf("test_tor_retry_after_stop_stays_down: ");
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "retrystop");
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");
    tor_integration_stop();
    const char *why = NULL;
    if (tor_integration_retry_start(tmpdir, 39257))
        why = "the retry after stop reported a start";
    else if (tor_integration_is_enabled())
        why = "the retry after stop brought Tor back";
    tor_integration_stop();
    tor_integration_set_extra_torrc_for_test("");
    remove_tree(tmpdir);
    printf("%s%s%s\n", why ? "FAIL (" : "OK", why ? why : "", why ? ")" : "");
    return why ? 1 : 0;
}

/* Against the real Tor, after the cases above used up every start: the next one
 * is refused, nothing starts, and the process is still here to say so. */
static int test_tor_start_limit_holds(void)
{
    printf("test_tor_start_limit_holds: ");
    if (!app_tor_real_build_linked()) {
        printf("OK (stub Tor linked: no name tables, no limit)\n");
        return 0;
    }
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "startlimit");
    tor_integration_set_extra_torrc_for_test("DisableNetwork 1");
    const char *why = NULL;
    if (!tor_integration_start_limit_reached())
        why = "the cases above did not use every start";
    else if (tor_integration_start(tmpdir, 39259))
        why = "a start past the limit was not refused";
    else if (tor_integration_is_enabled())
        why = "a start past the limit ran Tor";
    tor_integration_stop();
    tor_integration_set_extra_torrc_for_test("");
    remove_tree(tmpdir);
    printf("%s%s%s\n", why ? "FAIL (" : "OK", why ? why : "", why ? ")" : "");
    return why ? 1 : 0;
}

/* Its own group, so it gets its own process, which may start Tor only
 * TOR_MAX_STARTS_IN_PROCESS times. These cases use all of them. */
int test_tor_stop(void)
{
    int failures = test_tor_retry_after_stop_stays_down();
    failures += test_tor_stop_hands_off_to_tor_thread();
    failures += test_tor_persist_install_with_loop_running();
    failures += test_tor_start_limit_holds();
    printf("Tor stop: %d failures\n", failures);
    return failures;
}

static int test_tor_write_torrc_reduced_padding(void)
{
    int failures = 0;
    printf("test_tor_write_torrc_reduced_padding: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "padding");
    char td[512];
    snprintf(td, sizeof(td), "%s/tor_data", tmpdir);
    mkdir(td, 0700);

    char want_off[2048], want_on[3072], got[3072];
    snprintf(want_off, sizeof(want_off),
        "SocksPort 127.0.0.1:19999\n"
        "DataDirectory %s/tor_data\n"
        "Log notice file %s/" TOR_LOG_BASENAME "\n"
        "Log info [rend] file %s/" TOR_REND_LOG_BASENAME "\n"
        "__DisableSignalHandlers 1\n"
        "Schedulers KISTLite,Vanilla\n",
        tmpdir, tmpdir, tmpdir);
    snprintf(want_on, sizeof(want_on),
        "%sReducedConnectionPadding 1\n", want_off);

    bool off_ok = tor_write_torrc(tmpdir, 8033, false) &&
                  read_torrc_text(tmpdir, got, sizeof(got)) &&
                  strcmp(got, want_off) == 0;
    bool on_ok = tor_write_torrc(tmpdir, 8033, true) &&
                 read_torrc_text(tmpdir, got, sizeof(got)) &&
                 strcmp(got, want_on) == 0;

    if (off_ok && on_ok) {
        printf("OK\n");
    } else {
        printf("FAIL (false_exact=%d true_exact=%d)\n", off_ok, on_ok);
        failures++;
    }

    remove_tree(tmpdir);
    return failures;
}

/* Stand-in for the head of dynhost's service record. */
struct test_service_head {
    void *hs_service;
};

/* A node that serves no onion claims dynhost's service slot; a node that does
 * leaves it to dynhost. Drives the shipped claim and verification step over a
 * stand-in for dynhost's head. */
static int test_tor_no_service_claim(void)
{
    int failures = 0;
    printf("test_tor_no_service_claim: ");
    struct test_service_head head = { NULL };
    tor_integration_service_reset_for_test();
    int serving = tor_integration_service_step_for_test(&head, true);
    bool control = serving == 0 && head.hs_service == NULL;
    int held = tor_integration_service_step_for_test(&head, false);
    bool claimed = held == 1 && head.hs_service != NULL &&
                   !tor_integration_service_violated();
    int again = tor_integration_service_step_for_test(&head, false);
    bool stable = again == 1 && !tor_integration_service_violated();
    struct test_service_head minted = { (void *)&head };
    tor_integration_set_dial_ready_for_test(true);
    int lost = tor_integration_service_step_for_test(&minted, false);
    bool fail_closed = lost == 2 && tor_integration_service_violated() &&
                       !tor_integration_is_dial_ready();
    tor_integration_set_dial_ready_for_test(false);
    tor_integration_service_reset_for_test();
    if (!(control && claimed && stable && fail_closed)) {
        printf("FAIL (control=%d claimed=%d stable=%d fail_closed=%d "
               "lost=%d violated=%d dial_ready=%d)\n", control, claimed,
               stable, fail_closed, lost, tor_integration_service_violated(),
               tor_integration_is_dial_ready());
        failures++;
    } else {
        printf("OK\n");
    }
    return failures;
}

static int g_gate_enable_calls;
static bool g_gate_enable_saw_claim;
static bool g_gate_enable_result = true;
static struct test_service_head *g_gate_head;

static bool gate_enable(void)
{
    g_gate_enable_calls++;
    g_gate_enable_saw_claim = g_gate_head && g_gate_head->hs_service != NULL;
    return g_gate_enable_result;
}

static bool torrc_has_line(const char *dir, const char *line)
{
    char path[1100], buf[2048];
    snprintf(path, sizeof(path), "%s/torrc", dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, line) != NULL;
}

/* No claim yet: the gate waits and enables nothing. A claim lost to a real
 * service keeps the network off and marks the node violated. */
static bool gate_waits_and_stays_off(void)
{
    struct test_service_head stranger = { (void *)&stranger };
    bool enabled = false;
    bool lost_enabled = false;
    g_gate_head = &stranger;
    g_gate_enable_calls = 0;
    int early = tor_integration_network_gate_step_for_test(
        NULL, false, gate_enable, &enabled);
    int lost = tor_integration_network_gate_step_for_test(
        &stranger, false, gate_enable, &lost_enabled);
    bool ok = early == 0 && !enabled && lost == 2 && !lost_enabled &&
              g_gate_enable_calls == 0 && tor_integration_service_violated();
    tor_integration_service_reset_for_test();
    return ok;
}

/* The network is enabled only after the slot holds the claim; a refused
 * enable is retried. */
static bool gate_enables_after_claim(void)
{
    struct test_service_head head = { NULL };
    bool enabled = false;
    g_gate_head = &head;
    g_gate_enable_result = false;
    g_gate_enable_calls = 0;
    int refused = tor_integration_network_gate_step_for_test(
        &head, false, gate_enable, &enabled);
    bool retries = refused == 0 && !enabled && g_gate_enable_calls == 1;
    g_gate_enable_result = true;
    g_gate_enable_calls = 0;
    g_gate_enable_saw_claim = false;
    int opened = tor_integration_network_gate_step_for_test(
        &head, false, gate_enable, &enabled);
    return retries && opened == 1 && enabled && g_gate_enable_calls == 1 &&
           g_gate_enable_saw_claim;
}

/* A node that serves an onion is untouched: the gate enables nothing, and
 * the torrc carries DisableNetwork only on request. */
static bool gate_serving_node_untouched(void)
{
    struct test_service_head untouched = { NULL };
    bool serve_enabled = false;
    g_gate_enable_calls = 0;
    int serving = tor_integration_network_gate_step_for_test(
        &untouched, true, gate_enable, &serve_enabled);
    bool gate_ok = serving == 1 && g_gate_enable_calls == 0 &&
                   !serve_enabled && untouched.hs_service == NULL;
    char tmpdir[PATH_MAX];
    bool torrc_ok = test_mkdtemp(tmpdir, sizeof tmpdir, "zcl_test_torgate") &&
        tor_write_torrc_ex(tmpdir, 8033, false, true) &&
        torrc_has_line(tmpdir, "DisableNetwork 1") &&
        tor_write_torrc(tmpdir, 8033, false) &&
        !torrc_has_line(tmpdir, "DisableNetwork");
    remove_tree(tmpdir);
    return gate_ok && torrc_ok;
}

/* The network stays disabled until the claim on dynhost's service slot has
 * verified, and stays disabled when the claim is lost. */
static int test_tor_network_gate_order(void)
{
    printf("test_tor_network_gate_order: ");
    g_gate_enable_result = true;
    tor_integration_service_reset_for_test();
    bool waits = gate_waits_and_stays_off();
    bool opens = gate_enables_after_claim();
    bool control = gate_serving_node_untouched();
    tor_integration_service_reset_for_test();
    if (!(waits && opens && control)) {
        printf("FAIL (waits_and_stays_off=%d enables_after_claim=%d "
               "serving_untouched=%d)\n", waits, opens, control);
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* A network enable that keeps failing backs off: a tight retry loop makes a
 * handful of attempts, not one per call. */
static int test_tor_enable_backs_off(void)
{
    printf("test_tor_enable_backs_off: ");
    tor_integration_enable_reset_for_test();
    bool any = false;
    for (int i = 0; i < 1000; i++)
        any = tor_integration_enable_network_for_test() || any;
    unsigned failures = tor_integration_enable_failures_for_test();
    tor_integration_enable_reset_for_test();
    if (any || failures < 1 || failures > 3) {
        printf("FAIL (enabled=%d attempts=%u of 1000 calls)\n", any,
               failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}

/* Bootstrap control replies distinguish completion from progress and errors. */
static int test_tor_bootstrap_control_reply(void)
{
    static const struct { const char *reply; int expected; } cases[] = {
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n", 1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=80 TAG=conn SUMMARY=\"Connecting\"\r\n250 OK\r\n", 0},
        {"250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=80 TAG=conn SUMMARY=\"Connecting\" WARNING=\"slow\" REASON=TIMEOUT COUNT=1 RECOMMENDATION=ignore HOSTID=\"?\" HOSTADDR=\"?\"\r\n250 OK\r\n", 0},
        {"250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=80 TAG=conn SUMMARY=\"Connecting\" WARNING=\"trunc\r\n250 OK\r\n", 0},
        {"250-status/bootstrap-phase=\r\n250 OK\r\n", 0},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=1000 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=doneish SUMMARY=\"Done\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n", -1},
        {"550 error\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\" garbage\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Other\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"D\rone\"\r\n250 OK\r\n", -1},
        {"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\nextra", -1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (tor_integration_bootstrap_reply_for_test(cases[i].reply) !=
            cases[i].expected) {
            printf("test_tor_bootstrap_control_reply: FAIL (%zu)\n", i);
            return 1;
        }
    }
    printf("test_tor_bootstrap_control_reply: OK\n");
    return 0;
}

struct bootstrap_peer_fixture {
    int peer;
    int client;
    const char *reply;
    size_t reply_len;
    bool fragmented;
    bool cancel;
    bool command_ok;
    bool setconf;
};

static void *bootstrap_peer(void *arg)
{
    struct bootstrap_peer_fixture *f = arg;
    const char *command = f->setconf ? "SETCONF DisableNetwork=0\r\n" :
                                       "GETINFO status/bootstrap-phase\r\n";
    size_t command_len = strlen(command);
    char input[64];
    size_t have = 0;
    while (have < command_len) {
        ssize_t n = recv(f->peer, input + have, command_len - have, 0);
        if (n <= 0)
            return NULL;
        have += (size_t)n;
    }
    f->command_ok = memcmp(input, command, command_len) == 0;
    if (f->cancel) {
        (void)shutdown(f->client, SHUT_RDWR);
    } else if (!f->reply) {
        platform_sleep_ms(250);
    } else if (f->fragmented) {
        size_t first = f->reply_len / 2;
        (void)send(f->peer, f->reply, first, 0);
        platform_sleep_ms(10);
        (void)send(f->peer, f->reply + first, f->reply_len - first, 0);
    } else {
        (void)send(f->peer, f->reply, f->reply_len, 0);
    }
    return NULL;
}

static bool bootstrap_exchange_case(const char *reply, size_t len,
                                    bool fragmented, bool cancel,
                                    int timeout_ms, int expected, bool prompt,
                                    bool setconf)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return false;
    struct bootstrap_peer_fixture fixture = {
        .peer = pair[1], .client = pair[0], .reply = reply,
        .reply_len = len, .fragmented = fragmented, .cancel = cancel,
        .setconf = setconf,
    };
    pthread_t thread;
    if (pthread_create(&thread, NULL, bootstrap_peer, &fixture) != 0) {
        close(pair[0]);
        close(pair[1]);
        return false;
    }
    int64_t start = clock_now_monotonic_raw_us();
    int result = setconf ? tor_integration_setconf_exchange_for_test(pair[0], timeout_ms) :
                           tor_integration_bootstrap_exchange_for_test(pair[0], timeout_ms);
    int64_t elapsed = clock_now_monotonic_raw_us() - start;
    pthread_join(thread, NULL);
    bool shutdown_seen = true;
    if (expected < 0) {
        char c;
        shutdown_seen = recv(pair[1], &c, 1, MSG_DONTWAIT) == 0;
    }
    close(pair[0]);
    close(pair[1]);
    return fixture.command_ok && result == expected && shutdown_seen &&
           (!prompt || elapsed < 750000);
}

static bool test_tor_setconf_exchange_cases(void)
{
    static const char error[] = "550 unavailable\r\n";
    return bootstrap_exchange_case("250 OK\r\n", 8, true, false, 1000, 0, false, true) &&
        bootstrap_exchange_case(error, sizeof(error) - 1, false, false, 1000, 1, true, true) &&
        bootstrap_exchange_case("250", 3, false, false, 100, -1, false, true) &&
        bootstrap_exchange_case(NULL, 0, false, true, 1000, -1, true, true);
}

static int test_tor_bootstrap_exchange(void)
{
    static const char done[] = "250-status/bootstrap-phase=NOTICE BOOTSTRAP "
        "PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n";
    static const char error[] = "550 unavailable\r\n";
    static const char partial[] = "250-status/bootstrap-phase=NOTICE";
    char oversized[2200];
    memset(oversized, 'x', sizeof(oversized));
    char large[1200];
    static const char prefix[] = "250-status/bootstrap-phase=";
    int head = snprintf(large, sizeof(large), "%sWARN BOOTSTRAP PROGRESS=80 "
        "TAG=conn SUMMARY=\"Connecting\" WARNING=\"", prefix);
    if (head < 0 || (size_t)head < sizeof(prefix) - 1)
        return 1;
    size_t message_head = (size_t)head - (sizeof(prefix) - 1);
    if (message_head >= 1023 || sizeof(prefix) - 1 + 1023 + 10 > sizeof(large))
        return 1;
    size_t fill = 1023 - message_head;
    memset(large + head, 'a', fill);
    size_t large_len = (size_t)head + fill;
    memcpy(large + large_len, "\r\n250 OK\r\n", 10);
    large_len += 10;
    bool ok = bootstrap_exchange_case(done, sizeof(done) - 1, false, false, 1000, 1, false, false) &&
        bootstrap_exchange_case(done, sizeof(done) - 1, true, false, 1000, 1, false, false) &&
        bootstrap_exchange_case(error, sizeof(error) - 1, false, false, 1000, -1, true, false) &&
        bootstrap_exchange_case(NULL, 0, false, false, 100, -1, false, false) &&
        bootstrap_exchange_case(partial, sizeof(partial) - 1, false, false, 100, -1, false, false) &&
        bootstrap_exchange_case(NULL, 0, false, true, 1000, -1, true, false) &&
        bootstrap_exchange_case(oversized, sizeof(oversized), false, false, 1000, -1, true, false) &&
        bootstrap_exchange_case(large, large_len, true, false, 1000, 0, false, false) &&
        test_tor_setconf_exchange_cases();
    printf("test_tor_bootstrap_exchange: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int bootstrap_done_fixture(void) { return 1; }
static int bootstrap_stop_fixture(void)
{
    tor_integration_clear_readiness_for_test();
    return 1;
}

static int test_tor_bootstrap_publication_order(void)
{
    unsigned descriptor = tor_integration_observe_for_test(0, true, false);
    bool descriptor_first = descriptor == 1 &&
        tor_integration_observe_for_test(descriptor, false, true) == 3;
    unsigned bootstrap = tor_integration_observe_for_test(0, false, true);
    bool bootstrap_first = bootstrap == 2 &&
        tor_integration_observe_for_test(bootstrap, true, false) == 3;
    bool serving = tor_integration_monitor_bootstrap_for_test(bootstrap_done_fixture, false, true);
    bool outbound = tor_integration_monitor_bootstrap_for_test(bootstrap_done_fixture, true, true);
    bool serving_stop = tor_integration_monitor_bootstrap_for_test(bootstrap_stop_fixture, false, false);
    bool outbound_stop = tor_integration_monitor_bootstrap_for_test(bootstrap_stop_fixture, true, false);
    bool ok = descriptor_first && bootstrap_first && serving && outbound && serving_stop && outbound_stop;
    printf("test_tor_bootstrap_publication_order: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static _Atomic bool g_fs_fixture_stopping_tor;
static _Atomic bool g_fs_fixture_release_tor;

static void fs_fixture_stop_tor(void)
{
    atomic_store(&g_fs_fixture_stopping_tor, true);
    while (!atomic_load(&g_fs_fixture_release_tor))
        platform_sleep_ms(1);
}

static void *fs_fixture_stop_thread(void *arg)
{
    (void)arg;
    fs_server_stop();
    return NULL;
}

static bool fs_fixture_wait(_Atomic bool *flag)
{
    for (int i = 0; i < 2000 && !atomic_load(flag); i++)
        platform_sleep_ms(1);
    return atomic_load(flag);
}

static bool fs_fixture_retiring_snapshot(const struct fs_onion_listener *first)
{
    struct fs_onion_listener during;
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    uint16_t published_port = 0;
    return fs_server_onion_retiring() &&
           !fs_server_is_running() &&
           !fs_server_onion_published_port(&published_port) &&
           fs_server_onion_pin(&during) &&
           during.decision == FS_ONION_RETIRING &&
           getsockname((int)first->fd, (struct sockaddr *)&address, &length) == 0;
}

static bool fs_fixture_advertisement(bool published, uint16_t expected_port)
{
    struct p2p_node direct = {0}, onion = {0}, local = {0};
    static const unsigned char direct_ip[4] = { 192, 0, 2, 1 };
    static const unsigned char local_ip[4] = { 127, 0, 0, 1 };
    net_addr_set_ipv4(&direct.addr.svc.addr, direct_ip);
    net_addr_set_ipv4(&local.addr.svc.addr, local_ip);
    onion.addr.svc.addr.has_torv3 = true;
    local.inbound = true;
    local.accepted_local_port = 8233;
    uint16_t previous = net_onion_ingress_port();
    net_set_onion_ingress_port(8233);
    uint16_t port = 0;
    bool direct_ok = msg_version_file_port_for_test(&direct, &port) && port == expected_port;
    bool onion_ok = msg_version_file_port_for_test(&onion, &port) == published;
    bool local_ok = msg_version_file_port_for_test(&local, &port) == published;
    net_set_onion_ingress_port(previous);
    return direct_ok && onion_ok && local_ok;
}

static bool fs_fixture_pin(struct fs_onion_listener *first)
{
    uint16_t port = 0;
    if (!fs_server_onion_pin(first) || first->decision != FS_ONION_AVAILABLE ||
        first->fd < 0 || first->port == 0 ||
        fs_server_onion_published_port(&port) ||
        !fs_fixture_advertisement(false, first->port) ||
        fs_server_onion_publish(first->generation + 1) ||
        !fs_server_onion_publish(first->generation))
        return false;
    return fs_server_onion_published_port(&port) && port == first->port &&
           fs_fixture_advertisement(true, first->port);
}

static bool test_fs_onion_retirement_case(bool fatal)
{
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "zcl_test_onion_fs"))
        return false;
    atomic_store(&g_fs_fixture_stopping_tor, false);
    atomic_store(&g_fs_fixture_release_tor, false);
    fs_server_onion_stop_hook_for_test(fs_fixture_stop_tor);
    bool ok = fs_server_start(dir, 0, "127.0.0.1");
    for (int i = 0; i < 2000 && !fs_server_is_running(); i++)
        platform_sleep_ms(1);
    struct fs_onion_listener first;
    ok = ok && fs_fixture_pin(&first);
    pthread_t stopper;
    bool started = false;
    if (ok && fatal) {
        fs_server_onion_fatal_for_test();
        started = true;
    } else if (ok && pthread_create(&stopper, NULL, fs_fixture_stop_thread, NULL) == 0) {
        started = true;
    } else {
        ok = false;
    }
    if (started) {
        ok = fs_fixture_wait(&g_fs_fixture_stopping_tor) && ok;
        ok = fs_fixture_retiring_snapshot(&first) && ok;
        atomic_store(&g_fs_fixture_release_tor, true);
        if (!fatal)
            pthread_join(stopper, NULL);
    }
    atomic_store(&g_fs_fixture_release_tor, true);
    fs_server_stop();
    fs_server_onion_stop_hook_for_test(NULL);
    remove_tree(dir);
    return ok;
}

static int test_fs_onion_retirement(void)
{
    bool stop = test_fs_onion_retirement_case(false);
    bool fatal = test_fs_onion_retirement_case(true);
    printf("test_fs_onion_retirement: %s\n", stop && fatal ? "OK" : "FAIL");
    return stop && fatal ? 0 : 1;
}

static int test_fs_onion_decisions(void)
{
    const enum fs_onion_decision cases[] = {
        FS_ONION_DISABLED, FS_ONION_DEFERRED, FS_ONION_FAILED,
    };
    bool ok = true;
    fs_server_stop();
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct fs_onion_listener listener;
        fs_server_onion_decide(cases[i]);
        if (!fs_server_onion_pin(&listener) || listener.decision != cases[i] ||
            listener.fd != -1 || listener.port != 0)
            ok = false;
    }
    printf("test_fs_onion_decisions: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool test_tor_route_address(struct fs_onion_listener *file,
                                   const char *address, const char *route)
{
    char cmd[512];
    snprintf(file->address, sizeof(file->address), "%s", address);
    return tor_integration_compose_routes_for_test(8233, file, cmd, sizeof(cmd)) &&
           strstr(cmd, route);
}

static int test_tor_file_routes(void)
{
    char cmd[512];
    struct fs_onion_listener file = {
        .decision = FS_ONION_AVAILABLE, .fd = 17, .port = 42999,
        .address = "127.0.0.1",
    };
    bool available = tor_integration_compose_routes_for_test(8233, &file, cmd, sizeof(cmd)) &&
        strstr(cmd, "Port=80,unix:/dev/null/no-target") &&
        strstr(cmd, "Port=8233,127.0.0.1:8233") &&
        strstr(cmd, "Port=42999,127.0.0.1:42999");
    file.decision = FS_ONION_FAILED;
    bool failed = tor_integration_compose_routes_for_test(8233, &file, cmd, sizeof(cmd)) &&
                  !strstr(cmd, "Port=42999,");
    file.decision = FS_ONION_AVAILABLE;
    bool ipv6_any = test_tor_route_address(&file, "::", "Port=42999,[::1]:42999");
    bool ipv4_any = test_tor_route_address(&file, "0.0.0.0", "Port=42999,127.0.0.1:42999");
    bool ipv6_specific = test_tor_route_address(&file, "::1", "Port=42999,[::1]:42999");
    file.port = 8233;
    bool collision = tor_integration_compose_routes_for_test(8233, &file, cmd, sizeof(cmd)) &&
                     strstr(cmd, "Port=8233,127.0.0.1:8233") &&
                     !strstr(cmd, "Port=8233,[::1]:8233");
    bool ok = available && failed && ipv6_any && ipv4_any && ipv6_specific && collision;
    printf("test_tor_file_routes: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int test_tor_log_has_bootstrap_complete(void)
{
    int failures = 0;
    printf("test_tor_log_has_bootstrap_complete: ");
    char tmpdir[PATH_MAX];
    if (!test_mkdtemp(tmpdir, sizeof tmpdir, "zcl_test_torboot")) {
        printf("FAIL (mkdtemp)\n");
        return 1;
    }
    char path[1100];
    snprintf(path, sizeof(path), "%s/boot.log", tmpdir);
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("FAIL (open)\n");
        remove_tree(tmpdir);
        return 1;
    }
    fputs("Jun 11 [notice] Bootstrapped 100% (done): Done\n", f);
    long old_end = ftell(f);
    fputs("Jun 12 [notice] Bootstrapped 80% (ap_conn): Connecting\n", f);
    fclose(f);
    bool seen = tor_log_has_bootstrap_complete(path, 0);
    bool only_new = !tor_log_has_bootstrap_complete(path, old_end);
    bool missing = !tor_log_has_bootstrap_complete("/nonexistent/tor.log", 0);
    remove_tree(tmpdir);
    if (!(seen && only_new && missing)) {
        printf("FAIL (seen=%d only_new=%d missing=%d)\n", seen, only_new,
               missing);
        failures++;
    } else {
        printf("OK\n");
    }
    return failures;
}

/* -onion-rotate gives one new identity per process: the first start rotates, and
 * a later start in the same process keeps the address the first one announced. */
static int test_tor_rotate_once_per_process(void)
{
    printf("test_tor_rotate_once_per_process: ");
    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "torrc", "rotateonce");
    uint8_t seed[32];
    char before[57], first[57], second[57];
    bool created = false;
    tor_integration_configure_identity(true, true);
    const char *why = NULL;
    if (!onion_identity_ensure(tmpdir, seed, before, sizeof(before), &created))
        why = "could not make the first identity";
    else if (!tor_integration_rotate_once_for_test(tmpdir) ||
             !onion_identity_ensure(tmpdir, seed, first, sizeof(first), &created))
        why = "the first start's rotation failed";
    else if (strcmp(before, first) == 0)
        why = "the first start did not rotate";
    else if (!tor_integration_rotate_once_for_test(tmpdir) ||
             !onion_identity_ensure(tmpdir, seed, second, sizeof(second), &created))
        why = "the second start's rotation step failed";
    else if (strcmp(first, second) != 0)
        why = "a second start in one process rotated the identity again";
    tor_integration_configure_identity(false, false);
    remove_tree(tmpdir);
    printf("%s%s%s\n", why ? "FAIL (" : "OK", why ? why : "", why ? ")" : "");
    return why ? 1 : 0;
}

int test_tor(void)

{
    int failures = 0;
    printf("\n=== Tor Integration Tests ===\n");

    failures += test_tor_rotate_once_per_process();

    failures += test_tor_initial_state();
    failures += test_tor_requested_without_start();
    failures += test_tor_stop_when_not_running();
    failures += test_boot_onion_early_skips_only_when_told();

    /* torrc generation — bootstrap port derivation */
    failures += test_tor_write_torrc_bootstrap_port();
    failures += test_tor_write_torrc_reduced_padding();
    failures += test_tor_write_torrc_disables_signal_handlers();
    failures += test_tor_write_torrc_reports_write_failure();
    failures += test_tor_leaves_sigterm_to_the_node();
    failures += test_tor_stop_ends_onion_dial();
    failures += test_tor_stop_close_race();
    failures += test_tor_write_torrc_no_collision();
    failures += test_tor_write_torrc_datadir();
    failures += test_tor_write_torrc_idempotent();
    failures += test_tor_torrc_log_levels();
    failures += test_tor_log_rotation();
#if !defined(_WIN32)
    failures += test_remove_tree_does_not_follow_symlink();
    failures += test_remove_tree_trailing_separator_keeps_target();
#endif

    /* .onion address persistence */
    failures += test_tor_persistent_hostname_read();
    failures += test_tor_address_persists_across_restarts();
    failures += test_tor_set_address_null_clears();
    failures += test_tor_log_last_ephemeral_address();
    failures += test_tor_log_has_descriptor_publication();
    failures += test_tor_log_has_bootstrap_complete();
    failures += test_tor_bootstrap_control_reply();
    failures += test_tor_bootstrap_exchange();
    failures += test_tor_bootstrap_publication_order();
    failures += test_fs_onion_retirement();
    failures += test_fs_onion_decisions();
    failures += test_tor_file_routes();
    failures += test_tor_no_service_claim();
    failures += test_tor_network_gate_order();
    failures += test_tor_enable_backs_off();

    /* dynhost reassembly admission cap (vendored handlers under test) */
    failures += test_dynhost_reassembly_cap();

    /* vendor pin must ship the POST client core already sells */
    failures += test_dynhost_post_client_pin();

    /* shutdown must not wait out an in-flight blocking onion fetch */
    failures += test_blocking_fetch_abandons_on_shutdown();

    printf("Tor integration: %d failures\n", failures);
    return failures;
}
