/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcl_rpc — regressions for the small RPC client (tools/zcl-rpc.c ->
 * build/bin/zcl-rpc).
 *
 * Every failure of the HTTP exchange must name its case on stderr and exit
 * nonzero: a node that closes the connection before replying, a connect
 * refused, a reply that never arrives, a non-200 reply without a JSON body
 * and an oversize reply. A closed socket and a timeout used to look the same
 * (rc=1, no output). A successful reply must stay byte-identical. Each case
 * runs against a local listener on 127.0.0.1 with a cookie-only datadir. */

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
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ZCL_RPC_BIN "build/bin/zcl-rpc"
#define ZCL_RPC_RUN_TIMEOUT_MS 30000
#define ZCL_RPC_REPLY_CAP (2 * 1024 * 1024 + 4096)
#define ZCL_RPC_JSON_REPLY "{\"result\":42,\"error\":null,\"id\":1}"

/* Listener on 127.0.0.1 with an ephemeral port. Returns the fd, or -1. */
static int zrpc_listen(int *port_out)
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
        listen(fd, 4) != 0 ||
        getsockname(fd, (struct sockaddr *)&addr, &len) != 0) {
        close(fd);
        return -1;
    }
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

/* A loopback port with nothing listening: bind, learn the port, close. */
static int zrpc_dead_port(void)
{
    int port = 0;
    int fd = zrpc_listen(&port);
    if (fd >= 0) close(fd);
    return port;
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
 * reply_len bytes (possibly none) and close. Only async-signal-safe calls
 * run before _exit, so no atexit handler touches the parent's state. */
static void zrpc_serve_once(int lfd, const char *reply, size_t reply_len)
{
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

/* Run `zcl-rpc dumpstate` against 127.0.0.1:port with merged stdout and
 * stderr in out. extra_env is "" or a leading "NAME=value " assignment.
 * Returns the exit status, or -1 when the spawn itself failed. */
static int zrpc_run(const char *dir, int port, const char *extra_env,
                    char *out, size_t out_cap)
{
    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd),
                     "%sZCL_DATADIR='%s' ZCL_RPCPORT=%d " ZCL_RPC_BIN
                     " dumpstate",
                     extra_env, dir, port);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) return -1;
    const char *argv[] = {"sh", "-c", cmd, NULL};
    bool timed_out = false;
    return zcl_spawn_capture_merged_observed(argv, out, out_cap,
                                             ZCL_RPC_RUN_TIMEOUT_MS,
                                             &timed_out);
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
    int port = 0;
    TEST("zcl-rpc: node closing the connection before replying is named") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        pid_t pid = fork();
        ASSERT(pid >= 0);
        if (pid == 0)
            zrpc_serve_once(lfd, "", 0);
        close(lfd);
        int rc = zrpc_run(dir, port, "", out, sizeof(out));
        int status = 0;
        (void)waitpid(pid, &status, 0);
        ASSERT(rc == 1);
        ASSERT(strstr(out, "closed the connection before replying") != NULL);
        ASSERT(strstr(out, "method=dumpstate") != NULL);
        ASSERT(strstr(out, "127.0.0.1:") != NULL);
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
    int port = 0;
    TEST("zcl-rpc: a node that never replies is named as a timeout") {
        int lfd = zrpc_listen(&port);
        ASSERT(lfd >= 0 && zrpc_datadir(dir, sizeof(dir)));
        /* Nothing calls accept(): the connection waits in the backlog and
         * curl's one-second budget expires before any reply arrives. */
        int rc = zrpc_run(dir, port, "ZCL_RPC_MAX_TIME_SECS=1 ", out,
                          sizeof(out));
        close(lfd);
        ASSERT(rc == 1);
        ASSERT(strstr(out, "timed out waiting for the node's reply") != NULL);
        ASSERT(strstr(out, "method=dumpstate") != NULL);
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
    TEST("zcl-rpc: a refused connection is named as a connect failure") {
        int port = zrpc_dead_port();
        ASSERT(port > 0 && zrpc_datadir(dir, sizeof(dir)));
        int rc = zrpc_run(dir, port, "", out, sizeof(out));
        ASSERT(rc == 1);
        ASSERT(strstr(out, "could not connect") != NULL);
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
        int rc = zrpc_run(dir, port, "", out, sizeof(out));
        int status = 0;
        (void)waitpid(pid, &status, 0);
        ASSERT(rc == 1);
        ASSERT(strstr(out, "HTTP 500 without a JSON body") != NULL);
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
        int rc = zrpc_run(dir, port, "", out, sizeof(out));
        int status = 0;
        (void)waitpid(pid, &status, 0);
        ASSERT(rc == 1);
        ASSERT(strstr(out, "exceeds") != NULL);
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
        int rc = zrpc_run(dir, port, "", out, sizeof(out));
        int status = 0;
        (void)waitpid(pid, &status, 0);
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
    failures += test_zcl_rpc_non_json_status();
    failures += test_zcl_rpc_oversize_reply();
    failures += test_zcl_rpc_success_unchanged();
    return failures;
}

#endif
