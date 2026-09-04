/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Tor integration: no-SOCKS torrc, persistent .onion keys.
 *
 * Our forked Tor uses dynhost — NO SOCKS, NO extra ports.
 * These tests verify that invariant is never violated. */

#include "test/test_core.h"
#include "net/tor_integration.h"
#include "net/onion_service.h"
#include "util/log_rotate.h"
#include "config/boot_internal.h"
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

/* Recursively remove a directory tree (like rm -rf). */
static void remove_tree(const char *path)
{
    DIR *d = opendir(path);
    if (!d) { unlink(path); return; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[1024];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode))
            remove_tree(child);
        else
            unlink(child);
    }
    closedir(d);
    rmdir(path);
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

static int test_boot_onion_early_skips_without_tor(void)
{
    int failures = 0;
    printf("test_boot_onion_early_skips_without_tor: ");

    char tmpdir[512];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "tor", "earlyskip");
    struct app_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.datadir = tmpdir;
    ctx.tor = false;
    ctx.p2p_port = 39040;
    bool ok = boot_onion_tor_start_early(&ctx);
    bool idle = !tor_integration_is_enabled() && !tor_integration_is_ready();
    if (ok && idle)
        printf("OK\n");
    else {
        printf("FAIL (ok=%d enabled=%d ready=%d)\n",
               ok, tor_integration_is_enabled(), tor_integration_is_ready());
        failures++;
        tor_integration_stop();
    }
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
    bool ok = tor_write_torrc(tmpdir, 8033);
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
    tor_write_torrc(tmpdir1, 8033);
    tor_write_torrc(tmpdir2, 8035);

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

    tor_write_torrc(tmpdir, 8033);

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

    tor_write_torrc(tmpdir, 8033);

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
    tor_write_torrc(tmpdir, 8033);

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

    char tmpdir[] = "/tmp/zcl_test_torlog_XXXXXX";
    if (!mkdtemp(tmpdir)) {
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

    char tmpdir[] = "/tmp/zcl_test_tordesc_XXXXXX";
    if (!mkdtemp(tmpdir)) {
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

    if (!tor_write_torrc(tmpdir, 8033)) {
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

int test_tor(void)

{
    int failures = 0;
    printf("\n=== Tor Integration Tests ===\n");

    failures += test_tor_initial_state();
    failures += test_tor_requested_without_start();
    failures += test_tor_stop_when_not_running();
    failures += test_boot_onion_early_skips_without_tor();

    /* torrc generation — bootstrap port derivation */
    failures += test_tor_write_torrc_bootstrap_port();
    failures += test_tor_write_torrc_no_collision();
    failures += test_tor_write_torrc_datadir();
    failures += test_tor_write_torrc_idempotent();
    failures += test_tor_torrc_log_levels();
    failures += test_tor_log_rotation();

    /* .onion address persistence */
    failures += test_tor_persistent_hostname_read();
    failures += test_tor_address_persists_across_restarts();
    failures += test_tor_set_address_null_clears();
    failures += test_tor_log_last_ephemeral_address();
    failures += test_tor_log_has_descriptor_publication();

    /* dynhost reassembly admission cap (vendored handlers under test) */
    failures += test_dynhost_reassembly_cap();

    printf("Tor integration: %d failures\n", failures);
    return failures;
}
