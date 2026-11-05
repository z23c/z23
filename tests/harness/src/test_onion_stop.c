/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Each case runs in a separate process: shutdown flags are process-global. */
#include "devloop.h"
#include "net/connman.h"
#include "net/onion_stream.h"
#include "net/onion_v3_address.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "util/thread_registry.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct onion_stream_raw { onion_stream_event_fn event; void *ctx; };
static struct onion_stream_raw raw;
static atomic_int opens, closes;
static atomic_bool done;
static const char *mode;
static struct net_service service;
static bool connected;
static int budget;
static pthread_t terminal_thread;
static bool terminal_started;
static atomic_bool terminal_delivered;

static struct onion_stream_raw *hold(const char *host, uint16_t port,
    onion_stream_read_fn read_cb, onion_stream_event_fn event, void *ctx, int life)
{
    (void)host; (void)port; (void)read_cb; (void)life;
    raw.event = event; raw.ctx = ctx;
    int n = atomic_fetch_add(&opens, 1) + 1;
    if (!strcmp(mode, "open-race")) {
        thread_registry_request_shutdown();
    } else if (!strcmp(mode, "connected-race")) {
        event(&raw, ONION_STREAM_EVENT_CONNECTED, ctx);
        thread_registry_request_shutdown();
    } else if (!strcmp(mode, "terminal-race")) {
        event(&raw, ONION_STREAM_EVENT_CLOSED, ctx);
        thread_registry_request_shutdown();
    } else if (!strcmp(mode, "retry") && n == 1) {
        event(&raw, ONION_STREAM_EVENT_CLOSED, ctx);
    } else if (!strcmp(mode, "retry") && n == 2) {
        event(&raw, ONION_STREAM_EVENT_CONNECTED, ctx);
    }
    return &raw;
}
static int discard(struct onion_stream_raw *s, const uint8_t *p, size_t n)
{ (void)s; (void)p; (void)n; return -1; }
static void *late_terminal(void *arg)
{
    struct onion_stream_raw *s = arg;
    platform_sleep_ms(!strcmp(mode, "late") ? 5200 : 200);
    s->event(s, ONION_STREAM_EVENT_CLOSED, s->ctx);
    atomic_store(&terminal_delivered, true);
    return NULL;
}
static void close_hold(struct onion_stream_raw *s)
{
    atomic_fetch_add(&closes, 1);
    if (!strcmp(mode, "delayed") || !strcmp(mode, "late")) {
        terminal_started = pthread_create(&terminal_thread, NULL, late_terminal, s) == 0;
    } else if (strcmp(mode, "terminal-race") &&
               (strcmp(mode, "retry") || atomic_load(&opens) != 1))
        s->event(s, ONION_STREAM_EVENT_CLOSED, s->ctx);
}
static const struct onion_stream_backend backend = { hold, discard, close_hold };
static void *dial(void *unused)
{
    (void)unused; zcl_socket_t sock = ZCL_INVALID_SOCKET;
    connected = onion_stream_connect_backend_for_test(&service, &sock, budget, &backend);
    if (sock != ZCL_INVALID_SOCKET) close(sock);
    atomic_store(&done, true); return NULL;
}
static bool child_setup(const char *which)
{
    mode = which;
    uint8_t key[32]; memset(key, 0x41, sizeof(key));
    char host[ONION_V3_ADDRESS_LEN + 1]; net_service_init(&service);
    if (!onion_v3_address_from_pubkey(key, host) ||
        !net_addr_from_onion(host, &service.addr)) return false;
    service.port = 8033;
    budget = !strcmp(mode, "long") || !strcmp(mode, "retry") ? 120000 : 2000;
    if (!strcmp(mode, "pre")) thread_registry_request_shutdown();
    return true;
}
static bool child_wait_open(pthread_t worker)
{
    int waited = 0;
    if (strcmp(mode, "pre"))
        while (!atomic_load(&opens) && waited < 3000) { platform_sleep_ms(10); waited += 10; }
    if (strcmp(mode, "pre") && !atomic_load(&opens)) { pthread_join(worker, NULL); return false; }
    return true;
}
static bool child_should_cancel(void)
{
    return !strcmp(mode, "short") || !strcmp(mode, "long") ||
           !strcmp(mode, "delayed") || !strcmp(mode, "late");
}
static int child_validate_delayed(const struct onion_stream_stages *st)
{
    return !(terminal_started && atomic_load(&terminal_delivered) &&
             !connected && atomic_load(&opens) == 1 &&
             atomic_load(&closes) == 1 && st->circuit_timeout == 0);
}
static int child_validate(int64_t elapsed, const struct onion_stream_stages *st)
{
    if (!strcmp(mode, "delayed") || !strcmp(mode, "late"))
        return child_validate_delayed(st);
    if (!strcmp(mode, "retry")) return !(connected && atomic_load(&opens) == 2 &&
        atomic_load(&closes) == 2 && st->circuit_timeout == 0);
    if (!strcmp(mode, "pre")) return !(elapsed < 500 && !connected && !atomic_load(&opens));
    return !(elapsed < 500 && !connected && atomic_load(&opens) == 1 &&
             atomic_load(&closes) == 1 && st->circuit_timeout == 0);
}
static int child_case(const char *which)
{
    if (!child_setup(which)) return 2;
    pthread_t worker;
    if (pthread_create(&worker, NULL, dial, NULL)) return 2;
    if (!child_wait_open(worker)) return 2;
    int64_t start = platform_time_monotonic_ms();
    if (child_should_cancel()) {
        thread_registry_request_shutdown(); connman_signal_stop(NULL);
    }
    while (!atomic_load(&done) && platform_time_monotonic_ms() - start < 3000)
        platform_sleep_ms(10);
    pthread_join(worker, NULL);
    int64_t elapsed = platform_time_monotonic_ms() - start;
    if (!strcmp(mode, "retry"))
        for (int i = 0; i < 100 && atomic_load(&closes) < 2; i++) platform_sleep_ms(10);
    if (terminal_started) pthread_join(terminal_thread, NULL);
    struct onion_stream_stages st; onion_stream_get_stages(&st);
    printf("case=%s elapsed_ms=%lld opens=%d closes=%d connected=%d timeout=%llu\n",
        mode, (long long)elapsed, atomic_load(&opens), atomic_load(&closes), connected,
        (unsigned long long)st.circuit_timeout);
    return child_validate(elapsed, &st);
}
void onion_stop_child_exit_if_requested(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--onion-stop-fixture-child") &&
        (!strcmp(argv[2], "pre") || !strcmp(argv[2], "short") ||
         !strcmp(argv[2], "long") || !strcmp(argv[2], "connected-race") || !strcmp(argv[2], "open-race") ||
         !strcmp(argv[2], "retry") || !strcmp(argv[2], "terminal-race") || !strcmp(argv[2], "delayed") ||
         !strcmp(argv[2], "late"))) {
        int rc = child_case(argv[2]); fflush(stdout); _exit(rc);
    }
}
int test_onion_stop(void)
{
    char path[4096];
    if (!os_proc_self_exe_open_path(path, sizeof(path))) return 1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 1;
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    if (prior && !saved) { close(fd); return 1; }
    if (setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0) {
        free(saved); close(fd); return 1;
    }
    const char *cases[] = { "pre", "short", "long", "connected-race", "open-race", "terminal-race", "retry", "delayed", "late" };
    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const char *args[] = { "onion-stop-fixture", "--onion-stop-fixture-child", cases[i], NULL };
        struct zcl_devloop_process_result result = {0};
        bool started = zcl_devloop_process_run_fd(".", fd, args, 12000, &result);
        printf("%s", result.output);
        failures += !started || result.timed_out || result.cancelled ||
                    result.output_truncated || result.term_signal || result.exit_code != 0;
    }
    int restored = saved ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1)
                         : unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    free(saved); close(fd);
    return failures + (restored != 0);
}
