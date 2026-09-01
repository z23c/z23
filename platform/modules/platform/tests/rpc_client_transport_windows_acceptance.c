/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless adversarial acceptance for the native loopback RPC transport. */
#include "controllers/rpc_client.h" // lib-layer-ok:windows-rpc-acceptance
#include "platform/socket_compat.h"
#include "platform/time_compat.h"

#include <windows.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum server_mode { SERVER_REPLY, SERVER_SILENT, SERVER_PARTIAL };

struct server_case {
    platform_socket_t listener;
    enum server_mode mode;
};

static DWORD WINAPI server_thread(void *opaque)
{
    struct server_case *test = opaque;
    platform_socket_t peer = accept(test->listener, NULL, NULL);
    if (peer != PLATFORM_SOCKET_INVALID) {
        char request[4096];
        (void)platform_socket_receive(peer, request, sizeof(request));
        if (test->mode == SERVER_REPLY) {
            static const char reply[] =
                "HTTP/1.1 200 OK\r\nContent-Length: 38\r\n\r\n"
                "{\"result\":{\"ready\":true},\"error\":null}";
            (void)platform_socket_send_all(peer, reply, sizeof(reply) - 1);
            Sleep(10);
        } else if (test->mode == SERVER_PARTIAL) {
            static const char partial[] =
                "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{";
            (void)platform_socket_send_all(peer, partial, sizeof(partial) - 1);
            Sleep(300);
        } else {
            Sleep(300);
        }
        platform_socket_close(peer);
    }
    platform_socket_close(test->listener);
    return 0;
}

static int start_server(struct server_case *test, enum server_mode mode,
                        HANDLE *thread_out)
{
    test->listener = platform_socket_open(AF_INET, SOCK_STREAM, 0, true,
                                           false);
    if (test->listener == PLATFORM_SOCKET_INVALID) return -1;
    struct sockaddr_in endpoint = {0};
    endpoint.sin_family = AF_INET;
    endpoint.sin_port = 0;
    if (platform_socket_parse_address(AF_INET, "127.0.0.1",
                                      &endpoint.sin_addr) != 1 ||
        bind(test->listener, (const struct sockaddr *)&endpoint,
             (int)sizeof(endpoint)) != 0 || listen(test->listener, 1) != 0) {
        platform_socket_close(test->listener);
        return -1;
    }
    int size = (int)sizeof(endpoint);
    if (getsockname(test->listener, (struct sockaddr *)&endpoint, &size) != 0) {
        platform_socket_close(test->listener);
        return -1;
    }
    test->mode = mode;
    *thread_out = CreateThread(NULL, 0, server_thread, test, 0, NULL);
    if (!*thread_out) {
        platform_socket_close(test->listener);
        return -1;
    }
    return (int)ntohs(endpoint.sin_port);
}

static bool run_case(const char *datadir, enum server_mode mode,
                     const char *expected)
{
    struct server_case test;
    HANDLE thread = NULL;
    int port = start_server(&test, mode, &thread);
    if (port < 0) return false;
    int64_t started = platform_time_monotonic_ms();
    char *answer = node_rpc_call_at_deadline(datadir, port, "getinfo", "[]",
                                              100, 100);
    int64_t elapsed = platform_time_monotonic_ms() - started;
    bool ok = answer && strstr(answer, expected) != NULL && elapsed < 250;
    if (!ok)
        fprintf(stderr, // obs-ok:test-diagnostic
                "rpc case failed: mode=%d elapsed_ms=%lld answer=%s\n",
                (int)mode, (long long)elapsed, answer ? answer : "<null>");
    free(answer);
    WaitForSingleObject(thread, 1000);
    CloseHandle(thread);
    return ok;
}

int main(void)
{
    char temp[MAX_PATH];
    DWORD count = GetTempPathA((DWORD)sizeof(temp), temp);
    if (count == 0 || count >= sizeof(temp)) return 1;
    char datadir[4 * MAX_PATH];
    if (!GetTempFileNameA(temp, "zrp", 0, datadir) ||
        remove(datadir) != 0 || _mkdir(datadir) != 0) return 2;
    char cookie_path[4 * MAX_PATH + 16];
    int cookie_length = snprintf(cookie_path, sizeof(cookie_path),
                                 "%s/.cookie", datadir);
    if (cookie_length <= 0 || (size_t)cookie_length >= sizeof(cookie_path))
        return 3;
    FILE *cookie = fopen(cookie_path, "wb");
    if (!cookie) return 3;
    fputs("__cookie__:first\n", cookie);
    fclose(cookie);

    if (!run_case(datadir, SERVER_REPLY, "\"ready\":true")) return 4;
    if (!run_case(datadir, SERVER_SILENT, "did not answer")) return 5;
    if (!run_case(datadir, SERVER_PARTIAL, "truncated reply")) return 6;

    remove(cookie_path);
    _rmdir(datadir);
    puts("rpc_client_transport_acceptance: PASS");
    return 0;
}
