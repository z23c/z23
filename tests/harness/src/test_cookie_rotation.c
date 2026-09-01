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

/* Poll until the RPC listener is accepting and dispatching, replacing a
 * fixed sleep that raced against thread-scheduler startup. We probe with a
 * deliberately-wrong password so readiness never depends on cookie state;
 * ANY real HTTP status (200 or 401) proves the server is up and routing,
 * while a not-yet-listening server returns -1 (connect/read error). This
 * only establishes liveness — each test still makes its own auth assertion
 * afterward, so a genuinely broken auth path still fails deterministically.
 * Monotonic 5 s deadline; 10 ms initial retry, doubling up to 100 ms. */
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

int test_cookie_rotation(void)
{
    int failures = 0;

    char tmpdir[] = "/tmp/zcl_cookie_test_XXXXXX";
    if (!mkdtemp(tmpdir)) {
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
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

        char pass[128] = {0};
        ok = ok && read_cookie_password(tmpdir, pass, sizeof(pass));
        ok = ok && (strlen(pass) == 32); /* 2x16 hex chars */

        rpc_http_stop();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: rotation changes password on disk... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

        char pass_before[128] = {0};
        ok = ok && read_cookie_password(tmpdir, pass_before, sizeof(pass_before));

        rpc_http_cookie_rotate();

        char pass_after[128] = {0};
        ok = ok && read_cookie_password(tmpdir, pass_after, sizeof(pass_after));
        ok = ok && (strcmp(pass_before, pass_after) != 0);
        ok = ok && (strlen(pass_after) == 32);

        rpc_http_stop();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: current password authenticates... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

        char pass[128] = {0};
        ok = ok && read_cookie_password(tmpdir, pass, sizeof(pass));

        /* Wait for the server to start accepting connections */
        wait_rpc_ready(port);

        int status = rpc_with_auth(port, "__cookie__", pass);
        ok = ok && (status == 200);

        rpc_http_stop();
        if (ok) printf("OK\n"); else { printf("FAIL (status=%d)\n", status); failures++; }
    }

    printf("cookie_rotation: previous password valid after rotate... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

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
        if (ok) printf("OK\n"); else { printf("FAIL (s1=%d s2=%d)\n", s1, s2); failures++; }
    }

    printf("cookie_rotation: v1 rejected after second rotate... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

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
        if (ok) printf("OK\n"); else { printf("FAIL (s1=%d s2=%d s3=%d)\n", s1, s2, s3); failures++; }
    }

    printf("cookie_rotation: wrong password always rejected... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

        wait_rpc_ready(port);
        int s = rpc_with_auth(port, "__cookie__", "totallyWrongPassword123");
        ok = ok && (s == 401);

        rpc_http_stop();
        if (ok) printf("OK\n"); else { printf("FAIL (status=%d)\n", s); failures++; }
    }

    printf("cookie_rotation: explicit user/pass ignores rotate... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, "testuser", "testpass", NULL);

        wait_rpc_ready(port);
        ok = ok && (rpc_with_auth(port, "testuser", "testpass") == 200);

        /* rotate is a no-op in explicit auth mode */
        rpc_http_cookie_rotate();
        ok = ok && (rpc_with_auth(port, "testuser", "testpass") == 200);

        rpc_http_stop();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cookie_rotation: env configures interval... ");
    {
        setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "3600", 1);
        uint16_t port = reserve_test_port();
        bool ok = (port != 0);
        if (ok)
            ok = rpc_http_start(&empty_table, port, NULL, NULL, tmpdir);

        ok = ok && (rpc_http_cookie_rotate_sec() == 3600);

        rpc_http_stop();
        setenv("ZCL_RPC_COOKIE_ROTATE_SEC", "0", 1);
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
