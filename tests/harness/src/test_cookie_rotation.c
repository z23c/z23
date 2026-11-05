#define _DEFAULT_SOURCE  /* usleep */

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for Wave 10 #4: RPC cookie rotation.
 * Verifies timed rotation, dual-password grace window, disk write,
 * env config, and explicit-user bypass. */

#include "test/test_core.h"
#include "rpc/httpserver.h"
#include "rpc/server.h"
#include "encoding/utilstrencodings.h"
#include "platform/socket_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── helpers ─────────────────────────────────────────────────── */

static uint16_t reserve_test_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

/* Read cookie from datadir/.cookie, return just the password part */
static bool read_cookie_password(const char *datadir, char *pass, size_t passsz)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/.cookie", datadir);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char buf[256];
    if (!fgets(buf, (int)sizeof(buf), f)) { fclose(f); return false; }
    fclose(f);
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
        buf[--len] = '\0';
    char *colon = strchr(buf, ':');
    if (!colon) return false;
    snprintf(pass, passsz, "%s", colon + 1);
    return true;
}

/* Send an RPC request with given credentials, return HTTP status code.
 * Returns -1 on connection/network error. */
static int rpc_with_auth(uint16_t port, const char *user, const char *pass)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    /* Short I/O timeout */
    (void)platform_socket_set_send_timeout(fd, 2000);
    (void)platform_socket_set_receive_timeout(fd, 2000);

    if (platform_socket_connect(fd, (struct sockaddr *)&addr,
                                sizeof(addr)) != 0) {
        platform_socket_close(fd);
        return -1;
    }

    char creds[256];
    snprintf(creds, sizeof(creds), "%s:%s", user, pass);
    char b64[512];
    EncodeBase64((const unsigned char *)creds, strlen(creds),
                 b64, sizeof(b64));

    const char *body = "{\"method\":\"getblockcount\",\"params\":[],\"id\":1}";
    char req[2048];
    int reqlen = snprintf(req, sizeof(req),
        "POST / HTTP/1.1\r\n"
        "Authorization: Basic %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s", b64, strlen(body), body);

    if (!platform_socket_send_all(fd, req, (size_t)reqlen)) {
        platform_socket_close(fd);
        return -1;
    }

    /* Read response — just need the status line */
    char resp[4096];
    int n = platform_socket_receive(fd, resp, sizeof(resp) - 1);
    platform_socket_close(fd);
    if (n <= 0) return -1;
    resp[n] = '\0';

    int status = 0;
    if (sscanf(resp, "HTTP/1.1 %d", &status) != 1) return -1;
    return status;
}

/* Poll until the RPC listener answers. A deliberately-wrong password is
 * probed so readiness never depends on cookie state: any HTTP status (200 or
 * 401) proves the server is routing; -1 means not yet listening. Monotonic
 * 5 s deadline; 10 ms retry, doubling up to 100 ms. */
static void wait_rpc_ready(uint16_t port)
{
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);  // platform-ok:test-rpc-ready-realtime-deadline
    long backoff_us = 10000;          /* 10 ms */
    const long max_backoff_us = 100000; /* 100 ms */
    const double timeout_s = 5.0;

    for (;;) {
        if (rpc_with_auth(port, "__cookie__", "__readiness_probe__") >= 0)
            return; /* server accepted a connection and returned a status */

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);  // platform-ok:test-rpc-ready-realtime-deadline
        double elapsed = (double)(now.tv_sec - start.tv_sec)
                       + (double)(now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= timeout_s)
            return; /* give up polling; the test's own assertion still runs */

        usleep((useconds_t)backoff_us);
        backoff_us *= 2;
        if (backoff_us > max_backoff_us)
            backoff_us = max_backoff_us;
    }
}

/* ── tests ───────────────────────────────────────────────────── */

static bool cookie_rotation_check_initial_written(
    const struct rpc_table *table, const char *tmpdir)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass, sizeof(pass));
    ok = ok && (strlen(pass) == 32); /* 2x16 hex chars */

    rpc_http_stop();
    return ok;
}

static bool cookie_rotation_check_rotate_changes_password(
    const struct rpc_table *table, const char *tmpdir)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass_before[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_before, sizeof(pass_before));

    rpc_http_cookie_rotate();

    char pass_after[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_after, sizeof(pass_after));
    ok = ok && (strcmp(pass_before, pass_after) != 0);
    ok = ok && (strlen(pass_after) == 32);

    rpc_http_stop();
    return ok;
}

static bool cookie_rotation_check_current_authenticates(
    const struct rpc_table *table, const char *tmpdir, int *status_out)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass, sizeof(pass));

    /* Wait for the server to start accepting connections */
    wait_rpc_ready(port);

    int status = rpc_with_auth(port, "__cookie__", pass);
    ok = ok && (status == 200);

    rpc_http_stop();
    *status_out = status;
    return ok;
}

static bool cookie_rotation_check_previous_valid_after_rotate(
    const struct rpc_table *table, const char *tmpdir, int *s1_out,
    int *s2_out)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass_v1[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v1, sizeof(pass_v1));

    rpc_http_cookie_rotate();

    char pass_v2[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v2, sizeof(pass_v2));

    wait_rpc_ready(port);

    /* Both v1 (previous) and v2 (current) should authenticate */
    int s2 = rpc_with_auth(port, "__cookie__", pass_v2);
    int s1 = rpc_with_auth(port, "__cookie__", pass_v1);
    ok = ok && (s2 == 200) && (s1 == 200);

    rpc_http_stop();
    *s1_out = s1;
    *s2_out = s2;
    return ok;
}

static bool cookie_rotation_check_v1_rejected_after_second_rotate(
    const struct rpc_table *table, const char *tmpdir, int *s1_out,
    int *s2_out, int *s3_out)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass_v1[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v1, sizeof(pass_v1));

    rpc_http_cookie_rotate();
    char pass_v2[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v2, sizeof(pass_v2));

    rpc_http_cookie_rotate();
    char pass_v3[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v3, sizeof(pass_v3));

    wait_rpc_ready(port);

    /* v3 current, v2 previous — both work */
    int s3 = rpc_with_auth(port, "__cookie__", pass_v3);
    int s2 = rpc_with_auth(port, "__cookie__", pass_v2);
    ok = ok && (s3 == 200) && (s2 == 200);

    /* v1 should be rejected */
    int s1 = rpc_with_auth(port, "__cookie__", pass_v1);
    ok = ok && (s1 == 401);

    rpc_http_stop();
    *s1_out = s1;
    *s2_out = s2;
    *s3_out = s3;
    return ok;
}

static bool cookie_rotation_check_wrong_password_rejected(
    const struct rpc_table *table, const char *tmpdir, int *status_out)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    wait_rpc_ready(port);
    int s = rpc_with_auth(port, "__cookie__", "totallyWrongPassword123");
    ok = ok && (s == 401);

    rpc_http_stop();
    *status_out = s;
    return ok;
}

static bool cookie_rotation_check_explicit_auth_ignores_rotate(
    const struct rpc_table *table)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, "testuser", "testpass", NULL);

    wait_rpc_ready(port);
    ok = ok && (rpc_with_auth(port, "testuser", "testpass") == 200);

    /* rotate is a no-op in explicit auth mode */
    rpc_http_cookie_rotate();
    ok = ok && (rpc_with_auth(port, "testuser", "testpass") == 200);

    rpc_http_stop();
    return ok;
}

static bool cookie_rotation_owner_start_read_initial(
    const struct rpc_table *table, const char *tmpdir, uint16_t *port_out,
    char *initial, size_t initsz)
{
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "1", 1);
    uint16_t port = reserve_test_port();
    *port_out = port;
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    if (ok) {
        wait_rpc_ready(port);
        ok = read_cookie_password(tmpdir, initial, initsz);
    }
    return ok;
}

static bool cookie_rotation_owner_poll_rotated(
    uint16_t port, const char *tmpdir, const char *initial, char *current,
    size_t currentsz, bool ok)
{
    bool rotated = false;
    /* Authenticate continuously while the one-second owner thread
     * rotates. The old cookie must remain valid across the handoff, and
     * the new durable cookie must become usable before the bound ends. */
    for (int attempt = 0; ok && !rotated && attempt < 200; attempt++) {
        ok = rpc_with_auth(port, "__cookie__", initial) == 200;
        if (read_cookie_password(tmpdir, current, currentsz) &&
            strcmp(current, initial) != 0) {
            rotated = true;
            break;
        }
        usleep(20000); /* real-clock: pre-existing bounded poll loop, seeded when check_no_real_clock_test_deadline.sh was introduced */
    }
    ok = ok && rotated;
    return ok;
}

static bool cookie_rotation_owner_check_handoff(
    uint16_t port, const char *initial, const char *current, bool ok)
{
    if (ok) {
        ok = rpc_with_auth(port, "__cookie__", initial) == 200;
        ok = ok && rpc_with_auth(port, "__cookie__", current) == 200;
    }
    rpc_http_stop();
    return ok;
}

static bool cookie_rotation_owner_check_restart(
    const struct rpc_table *table, const char *tmpdir, char *current,
    size_t currentsz, bool ok)
{
    /* A stopped rotation owner must leave no thread or liveness identity
     * behind that can collide with a fresh server instance. */
    uint16_t restart_port = reserve_test_port();
    ok = ok && restart_port != 0;
    if (ok)
        ok = rpc_http_start(table, restart_port, NULL, NULL,
                            tmpdir);
    if (ok) {
        wait_rpc_ready(restart_port);
        ok = read_cookie_password(tmpdir, current, currentsz);
        ok = ok && rpc_with_auth(restart_port, "__cookie__", current) == 200;
    }
    rpc_http_stop();
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "0", 1);
    return ok;
}

static bool cookie_rotation_check_env_configures_interval(
    const struct rpc_table *table, const char *tmpdir)
{
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "3600", 1);
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    ok = ok && (rpc_http_cookie_rotate_sec() == 3600);

    rpc_http_stop();
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "0", 1);
    return ok;
}

/* A stalled cookie-file write must not park authentication. The hook models
 * a disk stall: it announces entry, then blocks until released (bounded). */
static _Atomic bool g_stall_entered;
static _Atomic bool g_stall_release;

static void cookie_stall_hook(void)
{
    atomic_store(&g_stall_entered, true);
    for (int i = 0; i < 500 && !atomic_load(&g_stall_release); i++)
        usleep(10000); /* real-clock: bounded wait modelling a stalled disk */
}

static void *cookie_stall_rotate_fn(void *arg)
{
    (void)arg;
    rpc_http_cookie_rotate();
    return NULL;
}

/* After the stall is released the rotation must complete: new secret on disk
 * and accepted, old secret still inside the grace window. */
static bool cookie_stall_check_rotated(uint16_t port, const char *tmpdir,
                                       const char *pass_v1)
{
    char pass_v2[128] = {0};
    bool ok = read_cookie_password(tmpdir, pass_v2, sizeof(pass_v2));
    ok = ok && strcmp(pass_v1, pass_v2) != 0;
    ok = ok && rpc_with_auth(port, "__cookie__", pass_v2) == 200;
    ok = ok && rpc_with_auth(port, "__cookie__", pass_v1) == 200;
    return ok;
}

static bool cookie_rotation_check_auth_not_blocked_by_write(
    const struct rpc_table *table, const char *tmpdir, int *status_out)
{
    uint16_t port = reserve_test_port();
    bool ok = (port != 0);
    if (ok)
        ok = rpc_http_start(table, port, NULL, NULL, tmpdir);

    char pass_v1[128] = {0};
    ok = ok && read_cookie_password(tmpdir, pass_v1, sizeof(pass_v1));
    wait_rpc_ready(port);

    atomic_store(&g_stall_entered, false);
    atomic_store(&g_stall_release, false);
    rpc_http_cookie_write_test_hook(cookie_stall_hook);

    pthread_t rot;
    bool started = ok && pthread_create(&rot, NULL, cookie_stall_rotate_fn,
                                        NULL) == 0;
    for (int i = 0; started && i < 500 && !atomic_load(&g_stall_entered); i++)
        usleep(10000); /* real-clock: bounded wait for the stalled write */
    ok = ok && started && atomic_load(&g_stall_entered);

    /* The write is stalled; the current secret must still authenticate. */
    int status = ok ? rpc_with_auth(port, "__cookie__", pass_v1) : -1;
    ok = ok && status == 200;

    atomic_store(&g_stall_release, true);
    if (started) pthread_join(rot, NULL);
    rpc_http_cookie_write_test_hook(NULL);

    ok = ok && cookie_stall_check_rotated(port, tmpdir, pass_v1);

    rpc_http_stop();
    *status_out = status;
    return ok;
}

/* A startup cookie write that cannot stage must not leave the cookie from an
 * earlier run on disk: its secret is no longer the one the server accepts. A
 * directory at the staging name makes the write fail; the failure must reach
 * stderr and the stale cookie must be gone. */
static bool cookie_write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool wrote = fputs(text, f) >= 0;
    return fclose(f) == 0 && wrote;
}

static bool cookie_startup_capture_start(const struct rpc_table *table,
                                         uint16_t port, const char *dir,
                                         const char *log)
{
    fflush(stderr);
    int saved = dup(STDERR_FILENO);
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (saved >= 0 && fd >= 0) (void)dup2(fd, STDERR_FILENO);
    bool started = rpc_http_start(table, port, NULL, NULL, dir);
    fflush(stderr);
    if (saved >= 0) {
        (void)dup2(saved, STDERR_FILENO);
        close(saved);
    }
    if (fd >= 0) close(fd);
    return started && saved >= 0 && fd >= 0;
}

static bool cookie_startup_log_names_failure(const char *log,
                                             const char *cookie)
{
    char text[4096] = {0};
    FILE *f = fopen(log, "r");
    if (!f) return false;
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';
    return strstr(text, "RPC cookie write failed") != NULL &&
           strstr(text, cookie) != NULL && strstr(text, "errno") != NULL;
}

static bool cookie_startup_write_failure_check(const struct rpc_table *table)
{
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "zcl_cookie_stale")) return false;
    char cookie[PATH_MAX + 16];
    char stage[PATH_MAX + 16];
    char log[PATH_MAX + 16];
    char port_file[PATH_MAX + 16];
    snprintf(cookie, sizeof(cookie), "%s/.cookie", dir);
    snprintf(stage, sizeof(stage), "%s/.cookie.tmp", dir);
    snprintf(log, sizeof(log), "%s/stderr.txt", dir);
    snprintf(port_file, sizeof(port_file), "%s/.rpcport", dir);

    bool ok = cookie_write_text(cookie, "__cookie__:stale_from_crash\n");
    ok = ok && mkdir(stage, 0700) == 0;
    uint16_t port = reserve_test_port();
    ok = ok && port != 0;
    ok = ok && cookie_startup_capture_start(table, port, dir, log);
    rpc_http_stop();

    /* No cookie may survive: a client must see a missing cookie, not 401. */
    ok = ok && access(cookie, F_OK) != 0 && errno == ENOENT;
    ok = ok && cookie_startup_log_names_failure(log, cookie);

    unlink(log);
    unlink(port_file);
    unlink(cookie);
    rmdir(stage);
    rmdir(dir);
    return ok;
}

int test_cookie_rotation(void)
{
    int failures = 0;

    char tmpdir[PATH_MAX];
    if (!test_mkdtemp(tmpdir, sizeof(tmpdir), "zcl_cookie_test")) {
        printf("cookie_rotation: cannot create tmpdir... SKIP\n");
        return 0;
    }

    /* Empty RPC table — safe to dispatch against (returns "method not found") */
    static struct rpc_table empty_table;
    rpc_table_init(&empty_table);

    /* Disable background rotation for tests — we rotate manually */
    setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "0", 1);

    printf("cookie_rotation: initial cookie written to disk... ");
    {
        bool ok = cookie_rotation_check_initial_written(&empty_table, tmpdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: rotation changes password on disk... ");
    {
        bool ok = cookie_rotation_check_rotate_changes_password(
            &empty_table, tmpdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: current password authenticates... ");
    {
        int status = 0;
        bool ok = cookie_rotation_check_current_authenticates(
            &empty_table, tmpdir, &status);
        if (ok) printf("OK\n"); else { printf("FAIL (status=%d)\n", status); failures++; }
    }

    printf("cookie_rotation: previous password valid after rotate... ");
    {
        int s1 = 0;
        int s2 = 0;
        bool ok = cookie_rotation_check_previous_valid_after_rotate(
            &empty_table, tmpdir, &s1, &s2);
        if (ok) printf("OK\n"); else { printf("FAIL (s1=%d s2=%d)\n", s1, s2); failures++; }
    }

    printf("cookie_rotation: v1 rejected after second rotate... ");
    {
        int s1 = 0;
        int s2 = 0;
        int s3 = 0;
        bool ok = cookie_rotation_check_v1_rejected_after_second_rotate(
            &empty_table, tmpdir, &s1, &s2, &s3);
        if (ok) printf("OK\n"); else { printf("FAIL (s1=%d s2=%d s3=%d)\n", s1, s2, s3); failures++; }
    }

    printf("cookie_rotation: wrong password always rejected... ");
    {
        int s = 0;
        bool ok = cookie_rotation_check_wrong_password_rejected(
            &empty_table, tmpdir, &s);
        if (ok) printf("OK\n"); else { printf("FAIL (status=%d)\n", s); failures++; }
    }

    printf("cookie_rotation: explicit user/pass ignores rotate... ");
    {
        bool ok = cookie_rotation_check_explicit_auth_ignores_rotate(
            &empty_table);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: background owner rotates during auth and restarts cleanly... ");
    {
        uint16_t port = 0;
        char initial[128] = {0};
        char current[128] = {0};
        bool ok = cookie_rotation_owner_start_read_initial(
            &empty_table, tmpdir, &port, initial, sizeof(initial));
        ok = cookie_rotation_owner_poll_rotated(
            port, tmpdir, initial, current, sizeof(current), ok);
        ok = cookie_rotation_owner_check_handoff(port, initial, current, ok);
        ok = cookie_rotation_owner_check_restart(
            &empty_table, tmpdir, current, sizeof(current), ok);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: auth not blocked by a stalled cookie write... ");
    {
        int status = 0;
        bool ok = cookie_rotation_check_auth_not_blocked_by_write(
            &empty_table, tmpdir, &status);
        if (ok) printf("OK\n"); else { printf("FAIL (status=%d)\n", status); failures++; }
    }

    printf("cookie_rotation: env configures interval... ");
    {
        bool ok = cookie_rotation_check_env_configures_interval(
            &empty_table, tmpdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: failed startup write leaves no stale cookie and logs... ");
    {
        bool ok = cookie_startup_write_failure_check(&empty_table);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Cleanup */
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/.cookie", tmpdir);
        unlink(path);
        rmdir(tmpdir);
    }

    return failures;
}
