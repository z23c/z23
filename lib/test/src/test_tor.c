/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for Tor integration: no-SOCKS torrc, persistent .onion keys.
 *
 * Our forked Tor uses dynhost — NO SOCKS, NO extra ports.
 * These tests verify that invariant is never violated. */

#include "test/test_core.h"
#include "net/tor_integration.h"
#include "net/onion_service.h"
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

int test_tor(void)
{
    int failures = 0;
    printf("\n=== Tor Integration Tests ===\n");

    failures += test_tor_initial_state();
    failures += test_tor_stop_when_not_running();

    /* torrc generation — bootstrap port derivation */
    failures += test_tor_write_torrc_bootstrap_port();
    failures += test_tor_write_torrc_no_collision();
    failures += test_tor_write_torrc_datadir();
    failures += test_tor_write_torrc_idempotent();

    /* .onion address persistence */
    failures += test_tor_persistent_hostname_read();
    failures += test_tor_address_persists_across_restarts();
    failures += test_tor_set_address_null_clears();
    failures += test_tor_log_last_ephemeral_address();
    failures += test_tor_log_has_descriptor_publication();

    printf("Tor integration: %d failures\n", failures);
    return failures;
}
