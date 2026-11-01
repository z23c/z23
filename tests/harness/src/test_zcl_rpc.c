/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcl_rpc — regressions for the small RPC client (tools/zcl-rpc.c ->
 * build/bin/zcl-rpc).
 *
 * Every failure of the HTTP exchange must name its case on stderr and exit
 * nonzero: a node that closes the connection before replying, a connect
 * refused, a reply that never arrives, a non-200 reply (with or without a JSON
 * body), a 200 reply whose body is truncated and an oversize reply. Each
 * failure prints exactly one line naming the reason, then the endpoint and
 * method, and nothing else. A closed socket and a timeout used to look the same
 * (rc=1, no output). A successful reply must stay byte-identical. Each case runs
 * against a local listener on 127.0.0.1 with a cookie-only datadir. */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(_WIN32)

int test_zcl_rpc(void)
{
    return 0;
}

#else

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ZCL_RPC_BIN "build/bin/zcl-rpc"
#define ZCL_RPC_RUN_TIMEOUT_MS 30000
#define ZCL_RPC_CHILD_LIFE_S 30
#define ZCL_RPC_REAP_CAP_MS 30000
#define ZCL_RPC_REPLY_CAP (2 * 1024 * 1024 + 4096)
#define ZCL_RPC_JSON_REPLY "{\"result\":42,\"error\":null,\"id\":1}"
/* zcl-rpc's reply buffer size (response[] in main): 1 MiB plus 256 bytes. */
#define ZCL_RPC_REPLY_BUF_BYTES 1048832

/* Bind 127.0.0.1 on an ephemeral port, read the port back, and optionally
 * start listening. The port is read from the bound socket, so no other
 * process can take it between a probe and the real bind. Returns the fd, or
 * -1. */
static int zrpc_bind(int *port_out, bool listening)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    socklen_t len = sizeof(addr);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        (listening && listen(fd, 4) != 0) ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

/* Listener on 127.0.0.1 with an ephemeral port. Returns the fd, or -1. */
static int zrpc_listen(int *port_out)
{
    return zrpc_bind(port_out, true);
}

/* A bound loopback port that does not listen, so a connect is refused. The
 * fd stays open for the whole run, so no other process can take the port. */
static int zrpc_refusing(int *port_out)
{
    return zrpc_bind(port_out, false);
}

/* A datadir holding only a cookie, so zcl-rpc authenticates without
 * touching any conf file. */
static bool zrpc_datadir(char *dir, size_t cap)
{
    test_make_tmpdir(dir, cap, "zcl_rpc", "case");
    char path[4200];
    int n = snprintf(path, sizeof(path), "%s/.cookie", dir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool wrote = fputs("user:pass\n", f) >= 0;
    return fclose(f) == 0 && wrote;
}

/* Read the whole request, headers then Content-Length bytes of body, so the
 * close that follows sends FIN, not RST: bytes left unread at close would
 * turn curl's "empty reply" (52) into "connection reset" (56) when the
 * request arrives in more than one segment. */
static void zrpc_drain_request(int cfd)
{
    char req[8192];
    size_t got = 0;
    while (got < sizeof(req) - 1) {
        ssize_t n = read(cfd, req + got, sizeof(req) - 1 - got);
        if (n <= 0) return;
        got += (size_t)n;
        req[got] = '\0';
        const char *end = strstr(req, "\r\n\r\n");
        if (!end) continue;
        size_t body = 0;
        const char *cl = strstr(req, "Content-Length:");
        if (cl && cl < end)
            for (cl += 15; *cl == ' '; cl++) {}
        if (cl && cl < end)
            for (; *cl >= '0' && *cl <= '9'; cl++) body = body * 10 + (size_t)(*cl - '0');
        if (got >= (size_t)(end + 4 - req) + body) return;
    }
}

/* Child side of a fork: accept one connection, read the request, send
 * reply_len bytes (possibly none) and close. The alarm bounds the child's
 * own lifetime. Only async-signal-safe calls run before _exit, so no atexit
 * handler touches the parent's state. */
static void zrpc_serve_once(int lfd, const char *reply, size_t reply_len)
{
    (void)alarm(ZCL_RPC_CHILD_LIFE_S);
    int cfd = accept(lfd, NULL, NULL);
    if (cfd >= 0) {
        zrpc_drain_request(cfd);
        size_t off = 0;
        while (off < reply_len) {
            ssize_t n = write(cfd, reply + off, reply_len - off);
            if (n <= 0) break;
            off += (size_t)n;
        }
        close(cfd);
    }
    _exit(0);
}

/* Wait for the fake-node child this test forked, polling WNOHANG for at most
 * ZCL_RPC_REAP_CAP_MS. Returns true when it exited in time. On timeout only
 * this child's PID is killed and reaped, and the caller fails its case. */
static bool zrpc_reap(pid_t pid)
{
    int status = 0;
    struct timespec tick = {0, 10 * 1000 * 1000};
    for (int waited_ms = 0; waited_ms < ZCL_RPC_REAP_CAP_MS; waited_ms += 10) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) return true;
        if (r < 0 && errno != EINTR) return false;
        (void)nanosleep(&tick, NULL);
    }
    fprintf(stderr, "zcl_rpc: fake node pid %ld did not exit within %d s; "
                    "killing that child\n", (long)pid,
            ZCL_RPC_REAP_CAP_MS / 1000);
    (void)kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
    return false;
}

/* Run `zcl-rpc dumpstate` against 127.0.0.1:port with merged stdout and
 * stderr in out. max_secs > 0 sets ZCL_RPC_MAX_TIME_SECS for the child;
 * 0 leaves it unset so the client default applies. The environment is set
 * for the child only and is cleared again afterwards. Returns the exit
 * status, or -1 when the spawn itself failed. *timed_out reports whether the
 * harness had to stop the child. The child is started by fork and execv
 * inside zcl_spawn; no shell runs. */
static int zrpc_run(const char *dir, int port, int max_secs, char *out,
                    size_t out_cap, bool *timed_out)
{
    char port_s[16] = "", secs_s[16] = "";
    (void)snprintf(port_s, sizeof(port_s), "%d", port);
    (void)snprintf(secs_s, sizeof(secs_s), "%d", max_secs);
    bool ok = setenv("ZCL_DATADIR", dir, 1) == 0 &&
              setenv("ZCL_RPCPORT", port_s, 1) == 0;
    if (max_secs > 0)
        ok = ok && setenv("ZCL_RPC_MAX_TIME_SECS", secs_s, 1) == 0;
    else
        (void)unsetenv("ZCL_RPC_MAX_TIME_SECS");
    int rc = -1;
    *timed_out = false;
    if (ok) {
        const char *argv[] = {ZCL_RPC_BIN, "dumpstate", NULL};
        rc = zcl_spawn_capture_merged_observed(argv, out, out_cap,
                                               ZCL_RPC_RUN_TIMEOUT_MS,
                                               timed_out);
    }
    (void)unsetenv("ZCL_DATADIR");
    (void)unsetenv("ZCL_RPCPORT");
    (void)unsetenv("ZCL_RPC_MAX_TIME_SECS");
    return rc;
}

/* The exact stderr line zcl-rpc prints for reason, against 127.0.0.1:port
 * and method dumpstate. */
static void zrpc_want_line(char *want, size_t cap, const char *reason,
                           int port)
{
    (void)snprintf(want, cap,
                   "zcl-rpc: %s (127.0.0.1:%d method=dumpstate)\n", reason,
                   port);
}

/* Build a reply: header block followed by body_len bytes of body. */
static size_t zrpc_build_reply(char *out, size_t cap, const char *status_line,
                               const char *body, size_t body_len)
{
    int n = snprintf(out, cap,
                     "%s\r\nContent-Type: application/json\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     status_line, body_len);
    if (n <= 0 || (size_t)n + body_len >= cap) return 0;
    memcpy(out + n, body, body_len);
    return (size_t)n + body_len;
}

static int test_zcl_rpc_closed_before_reply(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    int port = 0;
    TEST("zcl-rpc: node closing the connection before replying is named") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, "", 0);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node closed the connection before replying", port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_rpc_timeout(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    int port = 0;
    TEST("zcl-rpc: a node that never replies is named as a timeout") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        /* Nothing calls accept(): the connection waits in the backlog and
         * curl's one-second budget expires before any reply arrives. */
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 1, out, sizeof(out), &timed_out);
        close(lfd);
        zrpc_want_line(want, sizeof(want),
                       "timed out waiting for the node's reply after 1 s",
                       port);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_rpc_connect_refused(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    TEST("zcl-rpc: a refused connection is named as a connect failure") {
        int port = 0;
        int fd = zrpc_refusing(&port);
        ASSERT(fd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        close(fd);
        zrpc_want_line(want, sizeof(want), "could not connect to the node",
                       port);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A cookie path that exists but cannot be opened is named and stops the
 * call; it is never taken for a missing cookie and silently replaced by the
 * conf fallback. Here the datadir is a regular file, so opening
 * <datadir>/.cookie fails with ENOTDIR whoever runs the test (EACCES would
 * not reproduce as root). Auth runs before any connection, so no node. */
static int test_zcl_rpc_cookie_open_error(void)
{
    int failures = 0;
    char dir[4096] = "";
    char file[4200] = "";
    char out[2048] = "";
    char want[4400] = "";
    TEST("zcl-rpc: a cookie path that cannot be opened is named, not skipped") {
        test_make_tmpdir(dir, sizeof(dir), "zcl_rpc", "case");
        int n = snprintf(file, sizeof(file), "%s/datadir-is-a-file", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(file));
        FILE *f = fopen(file, "w");
        ASSERT(f != NULL);
        ASSERT_EQ(fclose(f), 0);
        bool timed_out = false;
        int rc = zrpc_run(file, 1, 0, out, sizeof(out), &timed_out);
        (void)snprintf(want, sizeof(want),
                       "zcl-rpc: opening %s/.cookie failed: %s\n", file,
                       strerror(ENOTDIR));
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A cookie that opens but cannot be read (a directory named .cookie: read
 * fails with EISDIR) is named and stops the call. */
static int test_zcl_rpc_cookie_read_error(void)
{
    int failures = 0;
    char dir[4096] = "";
    char cookie[4200] = "";
    char out[2048] = "";
    char want[4400] = "";
    TEST("zcl-rpc: a cookie that cannot be read is named, not skipped") {
        test_make_tmpdir(dir, sizeof(dir), "zcl_rpc", "case");
        int n = snprintf(cookie, sizeof(cookie), "%s/.cookie", dir);
        ASSERT(n > 0 && (size_t)n < sizeof(cookie));
        ASSERT_EQ(mkdir(cookie, 0700), 0);
        bool timed_out = false;
        int rc = zrpc_run(dir, 1, 0, out, sizeof(out), &timed_out);
        (void)snprintf(want, sizeof(want),
                       "zcl-rpc: reading %s failed: %s\n", cookie,
                       strerror(EISDIR));
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_rpc_non_json_status(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    int port = 0;
    static const char reply[] =
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    TEST("zcl-rpc: HTTP 500 without a JSON body is named, not silent") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, sizeof(reply) - 1);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node replied HTTP 500 without a JSON body", port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A non-200 body that starts like JSON but stops early is not a JSON body:
 * zcl-rpc must not print it as the node's answer. */
static int test_zcl_rpc_truncated_json_status(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    static char reply[4096];
    static const char truncated[] = "{\"error\":";
    int port = 0;
    TEST("zcl-rpc: HTTP 500 with a truncated JSON body is named, not printed") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        size_t reply_len = zrpc_build_reply(
            reply, sizeof(reply), "HTTP/1.1 500 Internal Server Error",
            truncated, sizeof(truncated) - 1);
        ASSERT(reply_len > 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, reply_len);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node replied HTTP 500 without a JSON body", port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A complete JSON-RPC error answered with a non-200 status is a failure: the
 * exit status must not report success, and the body is not printed as the
 * answer. */
static int test_zcl_rpc_json_error_status(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    static char reply[4096];
    static const char error_body[] =
        "{\"result\":null,\"error\":{\"code\":-5,\"message\":\"no\"},\"id\":1}";
    int port = 0;
    TEST("zcl-rpc: HTTP 500 with a JSON error body exits nonzero, named") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        size_t reply_len = zrpc_build_reply(
            reply, sizeof(reply), "HTTP/1.1 500 Internal Server Error",
            error_body, sizeof(error_body) - 1);
        ASSERT(reply_len > 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, reply_len);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node replied HTTP 500 with a JSON error body", port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

/* A 200 body cut short is not a usable answer: the status alone does not make
 * a truncated body a success. */
static int test_zcl_rpc_truncated_json_200(void)
{
    int failures = 0;
    char dir[4096] = "";
    char out[2048] = "";
    char want[256] = "";
    static char reply[4096];
    static const char truncated[] = "{\"result\":42,";
    int port = 0;
    TEST("zcl-rpc: HTTP 200 with a truncated JSON body is named, not printed") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        size_t reply_len = zrpc_build_reply(
            reply, sizeof(reply), "HTTP/1.1 200 OK", truncated,
            sizeof(truncated) - 1);
        ASSERT(reply_len > 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, reply_len);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node replied HTTP 200 with a truncated or non-JSON body",
                       port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_rpc_oversize_reply(void)
{
    int failures = 0;
    static char reply[ZCL_RPC_REPLY_CAP];
    static char out[ZCL_RPC_REPLY_CAP];
    static char want[256];
    char dir[4096] = "";
    int port = 0;
    static char body[1024 * 1024 + 1024];
    TEST("zcl-rpc: a reply larger than the reply buffer is refused") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        memset(body, 'x', sizeof(body));
        size_t reply_len = zrpc_build_reply(reply, sizeof(reply),
                                            "HTTP/1.1 200 OK", body,
                                            sizeof(body));
        ASSERT(reply_len > 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, reply_len);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        zrpc_want_line(want, sizeof(want),
                       "node reply exceeds the 1048832-byte reply buffer",
                       port);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(out, want);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_zcl_rpc_success_unchanged(void)
{
    int failures = 0;
    char dir[4096] = "";
    static char out[ZCL_RPC_REPLY_CAP];
    static char reply[4096];
    int port = 0;
    TEST("zcl-rpc: a JSON reply is printed byte-for-byte") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        size_t reply_len = zrpc_build_reply(reply, sizeof(reply),
                                            "HTTP/1.1 200 OK",
                                            ZCL_RPC_JSON_REPLY,
                                            strlen(ZCL_RPC_JSON_REPLY));
        ASSERT(reply_len > 0);
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, reply, reply_len);
        close(lfd);
        bool timed_out = false;
        int rc = zrpc_run(dir, port, 0, out, sizeof(out), &timed_out);
        bool reaped = zrpc_reap(pid);
        ASSERT(reaped);
        ASSERT(!timed_out);
        ASSERT(rc == 0);
        ASSERT(strcmp(out, ZCL_RPC_JSON_REPLY "\n") == 0);
        (void)test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcl_rpc(void)
{
    int failures = 0;
    struct stat st;
    if (stat(ZCL_RPC_BIN, &st) != 0 || (st.st_mode & S_IXUSR) == 0) {
        fprintf(stderr, "zcl_rpc: required " ZCL_RPC_BIN " missing (run: "
                        "make zcl-rpc)\n");
        return 1;
    }
    failures += test_zcl_rpc_closed_before_reply();
    failures += test_zcl_rpc_timeout();
    failures += test_zcl_rpc_connect_refused();
    failures += test_zcl_rpc_cookie_open_error();
    failures += test_zcl_rpc_cookie_read_error();
    failures += test_zcl_rpc_non_json_status();
    failures += test_zcl_rpc_truncated_json_status();
    failures += test_zcl_rpc_json_error_status();
    failures += test_zcl_rpc_truncated_json_200();
    failures += test_zcl_rpc_oversize_reply();
    failures += test_zcl_rpc_success_unchanged();
    return failures;
}

#endif
