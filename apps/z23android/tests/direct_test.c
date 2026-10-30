/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include "rpc.h"
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* "__cookie__:token" in base64. */
#define AUTH "Authorization: Basic X19jb29raWVfXzp0b2tlbg=="
#define STATUS_REPLY \
    "{\"result\":{\"subsystem\":\"status_frontdoor\",\"state\":{\"provable_tip\":120,\"max_peer_height\":130," \
    "\"peers\":7,\"pace\":\"gentle\"}},\"error\":null,\"id\":1}"
#define BALANCE_REPLY \
    "{\"result\":{\"transparent\":\"0.00000000\",\"private\":\"1.25000000\",\"encumbered\":\"0.00000000\"," \
    "\"total\":\"1.25000000\",\"transparent_source\":\"durable_projection\",\"transparent_sources_agree\":true," \
    "\"wallet_height\":20,\"chain_height\":20},\"error\":null,\"id\":1}"

enum mode { SERVE_OK, SERVE_HTTP_401, SERVE_RPC_ERROR, SERVE_GARBAGE, SERVE_SILENT, SERVE_CHUNKED, SERVE_SHORT, SERVE_LARGE };
static atomic_int mode;
static int listener;
static pthread_mutex_t seen_lock = PTHREAD_MUTEX_INITIALIZER;
static char seen[4096];
static atomic_int served;

/* Reads one request, records it, and answers according to the current mode. */
static void serve(int fd)
{
    char request[4096];
    size_t used = 0;
    const char *split = NULL;
    while (used < sizeof(request) - 1 && !(split = memmem(request, used, "\r\n\r\n", 4))) {
        ssize_t n = recv(fd, request + used, sizeof(request) - 1 - used, 0);
        if (n <= 0) return;
        used += (size_t)n;
    }
    const char *length = strcasestr(request, "Content-Length:");
    size_t body = length ? strtoul(length + 15, NULL, 10) : 0;
    while (split && used < (size_t)(split + 4 - request) + body) {
        ssize_t n = recv(fd, request + used, sizeof(request) - 1 - used, 0);
        if (n <= 0) return;
        used += (size_t)n;
    }
    request[used] = 0;
    pthread_mutex_lock(&seen_lock);
    snprintf(seen, sizeof(seen), "%s", request);
    pthread_mutex_unlock(&seen_lock);
    const char *reply = strstr(request, "dumpstate") ? STATUS_REPLY : BALANCE_REPLY;
    char out[4096];
    int mode_now = atomic_load(&mode);
    if (mode_now == SERVE_SILENT) { usleep(600000); return; }
    char large[2600];
    if (mode_now == SERVE_LARGE) {
        memset(large, 0, sizeof(large));
        memset(large + 1, 'x', 2400);
        large[0] = '{';
        large[2401] = '}';
        reply = large;
    }
    if (mode_now == SERVE_HTTP_401) snprintf(out, sizeof(out), "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n");
    else if (mode_now == SERVE_GARBAGE) snprintf(out, sizeof(out), "not http at all");
    else if (mode_now == SERVE_CHUNKED)
        snprintf(out, sizeof(out), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%zx\r\n%s\r\n0\r\n\r\n", strlen(reply), reply);
    else if (mode_now == SERVE_SHORT)
        snprintf(out, sizeof(out), "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n%.20s", strlen(reply), reply);
    else {
        if (mode_now == SERVE_RPC_ERROR) reply = "{\"result\":null,\"error\":{\"code\":-28,\"message\":\"Loading\"},\"id\":1}";
        snprintf(out, sizeof(out), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                 "Connection: close\r\n\r\n%s", strlen(reply), reply);
    }
    (void)send(fd, out, strlen(out), MSG_NOSIGNAL);
}

static void *accept_loop(void *arg)
{
    (void)arg;
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) return NULL;
        atomic_fetch_add(&served, 1);
        serve(fd);
        close(fd);
    }
}

static unsigned start_server(pthread_t *thread)
{
    listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(a);
    assert(listener >= 0 && bind(listener, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(listener, 4) == 0);
    assert(getsockname(listener, (struct sockaddr *)&a, &length) == 0);
    assert(pthread_create(thread, NULL, accept_loop, NULL) == 0);
    return ntohs(a.sin_port);
}

static void write_file(const char *directory, const char *name, const char *text)
{
    char file[512];
    assert(snprintf(file, sizeof(file), "%s/%s", directory, name) > 0);
    FILE *f = fopen(file, "w");
    assert(f && fputs(text, f) >= 0 && fclose(f) == 0);
}

static void announce(const char *directory, unsigned port)
{
    char text[16];
    snprintf(text, sizeof(text), "%u\n", port);
    write_file(directory, ".rpcport", text);
    write_file(directory, ".cookie", "__cookie__:token\n");
}

static long log_lines(const char *file)
{
    FILE *f = fopen(file, "r");
    char line[512];
    long count = 0;
    assert(f);
    while (fgets(line, sizeof(line), f)) count += strstr(line, "node query failed") != NULL;
    fclose(f);
    return count;
}

/* Stands in for the CLI: only a fallback run reaches it. */
static int cli_child(int argc, char **argv)
{
    if (argc > 3 && !strcmp(argv[1], "core") && !strcmp(argv[2], "status")) {
        puts("{\"ok\":true,\"data\":{\"provable_tip\":1,\"max_peer_height\":2,\"peers\":9}}");
        return 0;
    }
    return 2;
}

static void protocol_cases(const char *directory, unsigned port)
{
    char out[8192], why[160];
    announce(directory, port);
    atomic_store(&mode, SERVE_OK);
    assert(zapp_rpc_call(directory, "dumpstate", "[\"status_frontdoor\"]", 2000, out, sizeof(out), why, sizeof(why)) == ZAPP_RPC_OK);
    assert(!strcmp(out, STATUS_REPLY));
    pthread_mutex_lock(&seen_lock);
    assert(!strncmp(seen, "POST / HTTP/1.1\r\n", 17) && strstr(seen, AUTH "\r\n"));
    assert(strstr(seen, "\"method\":\"dumpstate\",\"params\":[\"status_frontdoor\"]}"));
    pthread_mutex_unlock(&seen_lock);
    static const struct { enum mode mode; const char *reason; } failures[] = {
        {SERVE_HTTP_401, "HTTP 401"}, {SERVE_GARBAGE, "not HTTP"}, {SERVE_CHUNKED, "chunked"},
        {SERVE_SHORT, "incomplete"}, {SERVE_LARGE, "exchange: Message too long"},
        {SERVE_SILENT, "exchange: Connection timed out"}};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        atomic_store(&mode, failures[i].mode);
        assert(zapp_rpc_call(directory, "dumpstate", "[]", 200, out, 1024, why, sizeof(why)) == ZAPP_RPC_FAILED);
        assert(strstr(why, failures[i].reason));
    }
    atomic_store(&mode, SERVE_OK);
    assert(zapp_rpc_call(directory, "dumpstate", "[]", 2000, out, 128, why, sizeof(why)) == ZAPP_RPC_FAILED);
    assert(zapp_rpc_call(directory, "dumpstate", "[]", 2000, out, 255, why, sizeof(why)) == ZAPP_RPC_FAILED);
    write_file(directory, ".rpcport", "65535\n");
    assert(zapp_rpc_call(directory, "dumpstate", "[]", 2000, out, sizeof(out), why, sizeof(why)) == ZAPP_RPC_UNREACHABLE);
    write_file(directory, ".rpcport", "junk\n");
    assert(zapp_rpc_call(directory, "dumpstate", "[]", 2000, out, sizeof(out), why, sizeof(why)) == ZAPP_RPC_FAILED);
    char cookie[512];
    snprintf(cookie, sizeof(cookie), "%s/.cookie", directory);
    assert(unlink(cookie) == 0);
    write_file(directory, ".rpcport", "1\n");
    assert(zapp_rpc_call(directory, "dumpstate", "[]", 2000, out, sizeof(out), why, sizeof(why)) == ZAPP_RPC_UNREACHABLE);
}

static void operation_cases(struct zapp_runtime *r, const char *directory, unsigned port, const char *log)
{
    char out[ZAPP_TEXT_CAP / 8], balance[256];
    announce(directory, port);
    atomic_store(&mode, SERVE_OK);
    int before = atomic_load(&served);
    assert(zapp_operation_run(r, "status", out, sizeof(out)));
    assert(strstr(out, "\"ok\":true") && strstr(out, "\"provable_tip\":120") && strstr(out, "\"peers\":7") && !strstr(out, "\"peers\":9"));
    assert(zapp_operation_run(r, "wallet_balance", out, sizeof(out)));
    assert(zapp_balance_format(out, balance, sizeof(balance)) && !strncmp(balance, "Balance 1.25 ZCL", 16));
    assert(atomic_load(&served) == before + 2 && log_lines(log) == 0);
    /* A failing node answer falls back to the CLI and is logged once per failing streak. */
    atomic_store(&mode, SERVE_HTTP_401);
    for (int i = 0; i < 3; ++i) assert(zapp_operation_run(r, "status", out, sizeof(out)) && strstr(out, "\"peers\":9"));
    assert(log_lines(log) == 1);
    atomic_store(&mode, SERVE_RPC_ERROR);
    assert(zapp_operation_run(r, "status", out, sizeof(out)) && strstr(out, "\"peers\":9") && log_lines(log) == 1);
    atomic_store(&mode, SERVE_OK);
    assert(zapp_operation_run(r, "status", out, sizeof(out)) && strstr(out, "\"peers\":7") && !r->direct_reported);
    atomic_store(&mode, SERVE_GARBAGE);
    assert(zapp_operation_run(r, "status", out, sizeof(out)) && strstr(out, "\"peers\":9") && log_lines(log) == 2);
    /* No port file: the node is not serving, the CLI runs and nothing is logged. */
    char file[512];
    snprintf(file, sizeof(file), "%s/.rpcport", directory);
    assert(unlink(file) == 0);
    long lines = log_lines(log);
    assert(zapp_operation_run(r, "status", out, sizeof(out)) && strstr(out, "\"peers\":9") && log_lines(log) == lines);
}

int main(int argc, char **argv)
{
    if (argc > 1) return cli_child(argc, argv);
    char directory[] = "/tmp/zapp-direct-test-XXXXXX", log[512], file[512];
    assert(mkdtemp(directory));
    pthread_t thread;
    unsigned port = start_server(&thread);
    protocol_cases(directory, port);
    struct zapp_runtime r = {0};
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    assert(snprintf(r.executable, sizeof(r.executable), "%s", argv[0]) > 0);
    assert(snprintf(r.directory, sizeof(r.directory), "%s", directory) > 0);
    assert(snprintf(r.state_root, sizeof(r.state_root), "%s", directory) > 0);
    assert(snprintf(r.temporary_root, sizeof(r.temporary_root), "%s", directory) > 0);
    assert(snprintf(log, sizeof(log), "%s/stderr.log", directory) > 0);
    assert(freopen(log, "w", stderr));
    setvbuf(stderr, NULL, _IONBF, 0);
    operation_cases(&r, directory, port, log);
    pthread_mutex_destroy(&r.mutex);
    shutdown(listener, SHUT_RDWR);
    close(listener);
    pthread_join(thread, NULL);
    snprintf(file, sizeof(file), "%s/.cookie", directory);
    (void)unlink(file);
    assert(unlink(log) == 0 && rmdir(directory) == 0);
    puts("direct query tests passed");
    return 0;
}
