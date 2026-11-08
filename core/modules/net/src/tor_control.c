/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Own Tor control-socket exchanges and bootstrap reply parsing. */
#include "tor_integration_priv.h"
#include "base/compiler.h"
#include "platform/clock.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

extern void *dynhost_get_global_service(void) ZCL_WEAK_IMPORT;

int64_t tor_wall_ms(void)
{
    return clock_now_wall_ms();
}

/* True when a real Tor is linked; the stub has no dynhost and no control
 * connection to own. */
bool tor_is_linked(void)
{
    return dynhost_get_global_service != NULL;
}

/* Open the owning control connection, before the Tor thread exists. The tor
 * stub never reads it, so it gets none. */
bool tor_control_open(void)
{
    if (!tor_is_linked())
        return true;
    platform_socket_t pair[2];
    /* A child process must not inherit either end: Tor pre-authenticates this
     * connection. Another thread may fork and exec at any moment, so where the
     * flag exists the pair is close-on-exec from birth. */
#ifdef SOCK_CLOEXEC
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
        return false;
#else
    if (!platform_socket_pair(pair))
        return false;
#ifndef _WIN32
    (void)fcntl(pair[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pair[1], F_SETFD, FD_CLOEXEC);
#endif
#endif
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (fstat(pair[1], &g_tor_control_peer_id) != 0) {
        (void)platform_socket_close(pair[0]);
        (void)platform_socket_close(pair[1]);
        return false;
    }
#endif
    g_tor_control = pair[0];
    g_tor_control_peer = pair[1];
    return true;
}

/* Ask Tor to exit, from any thread, any number of times. shutdown() rather
 * than close(): the number stays ours until the join, so a monitor blocked in
 * recv() wakes instead of reading a number some other thread now owns. */
void tor_request_exit(void)
{
    if (g_tor_control != PLATFORM_SOCKET_INVALID)
        (void)platform_socket_shutdown_both(g_tor_control);
}
static bool tor_bootstrap_quoted(const char **at, const char *end)
{
    const char *p = *at;
    if (p == end || *p++ != '"')
        return false;
    const char *start = p;
    while (p < end && *p != '"') {
        if ((unsigned char)*p < 32 || (unsigned char)*p == 127)
            return false;
        if (*p == '\\' && (++p == end || (*p != '\\' && *p != '"')))
            return false;
        p++;
    }
    if (p == end || p == start)
        return false;
    *at = p + 1;
    return true;
}

static bool tor_bootstrap_summary(const char **at, const char *end)
{
    static const char name[] = " SUMMARY=";
    if ((size_t)(end - *at) < sizeof(name) - 1 ||
        memcmp(*at, name, sizeof(name) - 1) != 0)
        return false;
    *at += sizeof(name) - 1;
    return tor_bootstrap_quoted(at, end);
}

static bool tor_bootstrap_progress(const char **at, const char *end,
                                   unsigned *progress)
{
    const char *p = *at;
    if (strncmp(p, "BOOTSTRAP PROGRESS=", 19) != 0)
        return false;
    p += 19;
    *progress = 0;
    unsigned digits = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        *progress = *progress * 10 + (unsigned)(*p++ - '0');
        if (++digits > 3)
            return false;
    }
    if (!digits || *progress > 100 || strncmp(p, " TAG=", 5) != 0)
        return false;
    *at = p + 5;
    return true;
}

static bool tor_bootstrap_tag(const char **at, const char *end, bool *done)
{
    const char *p = *at;
    const char *tag = p;
    while (p < end && *p != ' ') {
        if ((*p < 'a' || *p > 'z') && (*p < '0' || *p > '9') &&
            *p != '_')
            return false;
        p++;
    }
    if (p == tag || p == end)
        return false;
    *done = p - tag == 4 && memcmp(tag, "done", 4) == 0;
    *at = p;
    return true;
}

static bool tor_bootstrap_severity(const char **at, bool *warn)
{
    *warn = false;
    if (strncmp(*at, "NOTICE ", 7) == 0) {
        *at += 7;
        return true;
    }
    if (strncmp(*at, "WARN ", 5) == 0) {
        *warn = true;
        *at += 5;
        return true;
    }
    return false;
}

static bool tor_bootstrap_warn_tail(const char *at, const char *end)
{
    while (at < end) {
        if ((unsigned char)*at < 32 || (unsigned char)*at == 127)
            return false;
        at++;
    }
    return true;
}

static bool tor_bootstrap_completion(unsigned progress, bool done, bool warn,
                                     const char *at, const char *end)
{
    if ((progress == 100) != done || (warn && done))
        return false;
    return !done || (end - at == 15 && memcmp(at, " SUMMARY=\"Done\"", 15) == 0);
}

static int tor_bootstrap_value(const char *value, const char *eol)
{
    if (value == eol)
        return 0;
    bool warn;
    if (!tor_bootstrap_severity(&value, &warn))
        return -1;
    const char *p = value;
    unsigned progress;
    bool done;
    if (!tor_bootstrap_progress(&p, eol, &progress) ||
        !tor_bootstrap_tag(&p, eol, &done))
        return -1;
    if (!tor_bootstrap_completion(progress, done, warn, p, eol))
        return -1;
    if (!tor_bootstrap_summary(&p, eol))
        return -1;
    /* Tor may truncate its WARN message after the fixed summary. It cannot
     * indicate completion; retain the connection while that event is current. */
    if (warn && !tor_bootstrap_warn_tail(p, eol))
        return -1;
    if (!warn && p != eol)
        return -1;
    return done ? 1 : 0;
}

/* Returns -1 for an invalid reply, 0 for bootstrap in progress, 1 for done. */
static int tor_bootstrap_reply(const char *reply)
{
    static const char prefix[] = "250-status/bootstrap-phase=";
    static const char end[] = "\r\n250 OK\r\n";
    if (strncmp(reply, prefix, sizeof(prefix) - 1) != 0)
        return -1;
    const char *value = reply + sizeof(prefix) - 1;
    const char *eol = strstr(value, "\r\n");
    if (!eol || strcmp(eol, end) != 0)
        return -1;
    return tor_bootstrap_value(value, eol);
}

#ifdef ZCL_TESTING
int tor_integration_bootstrap_reply_for_test(const char *reply)
{
    return tor_bootstrap_reply(reply);
}
#endif

static bool tor_bootstrap_frame_complete(const char *reply)
{
    for (const char *line = reply;;) {
        const char *end = strstr(line, "\r\n");
        if (!end)
            return false;
        if (end - line >= 4 && line[0] >= '0' && line[0] <= '9' &&
            line[1] >= '0' && line[1] <= '9' &&
            line[2] >= '0' && line[2] <= '9' && line[3] == ' ')
            return true;
        line = end + 2;
    }
}

static bool tor_bounded_exchange(platform_socket_t socket,
                                 const _Atomic bool *running, int timeout_ms,
                                 const char *command, char *reply, size_t cap)
{
    size_t command_len = strlen(command);
    size_t have = 0;
    reply[0] = '\0';
    int64_t start = clock_now_monotonic_raw_us();
    if (timeout_ms <= 0 || platform_socket_set_send_timeout(socket, timeout_ms) != 0 ||
        send(socket, command, (int)command_len, 0) != (int)command_len)
        return false;
    if (platform_socket_set_send_timeout(socket, 0) != 0)
        return false;
    while (atomic_load(running) && have + 1 < cap) {
        int64_t remaining = (int64_t)timeout_ms * 1000 -
                            (clock_now_monotonic_raw_us() - start);
        if (remaining <= 0)
            return false;
        int wait_ms = remaining > 250000 ? 250 : (int)((remaining + 999) / 1000);
        int ready = platform_socket_wait_readable(socket, wait_ms);
        if (ready < 0)
            return false;
        if (!ready)
            continue;
        long n = (long)recv(socket, reply + have,
                            (int)(cap - 1 - have), 0);
        if (n <= 0)
            return false;
        if (memchr(reply + have, '\0', (size_t)n))
            return false;
        have += (size_t)n;
        reply[have] = '\0';
        if (tor_bootstrap_frame_complete(reply))
            return true;
    }
    return false;
}

static int tor_bootstrap_exchange(platform_socket_t socket,
                                  const _Atomic bool *running, int timeout_ms)
{
    /* The vendor message alone holds 1023 bytes, before control framing. */
    char reply[2048];
    if (!tor_bounded_exchange(socket, running, timeout_ms,
                              "GETINFO status/bootstrap-phase\r\n", reply,
                              sizeof(reply)))
        return -1;
    return tor_bootstrap_reply(reply);
}

/* A failed or incomplete exchange leaves the connection unusable. */
int tor_bootstrap_query(void)
{
    int result = tor_bootstrap_exchange(g_tor_control, &g_tor_running, 5000);
    if (result < 0)
        tor_request_exit();
    return result;
}

#ifdef ZCL_TESTING
int tor_integration_bootstrap_exchange_for_test(int64_t fd, int timeout_ms)
{
    _Atomic bool running = true;
    int result = tor_bootstrap_exchange((platform_socket_t)fd, &running,
                                         timeout_ms);
    if (result < 0)
        (void)platform_socket_shutdown_both((platform_socket_t)fd);
    return result;
}
#endif
static bool tor_control_reply_complete(const char *reply)
{
    for (const char *line = reply;;) {
        const char *eol = strstr(line, "\r\n");
        if (!eol)
            return false;
        if (eol - line >= 4 && line[3] == ' ')
            return true;
        line = eol + 2;
    }
}

/* Send one command over the owning control connection and read Tor's whole
 * reply. Tor answers from its loop, which may not be running yet, so this waits
 * for as long as Tor runs; a stop ends the wait at once by shutting the socket
 * down. False when Tor ended, or the reply did not fit. */
bool tor_control_exchange(const char *cmd, char *reply, size_t reply_size)
{
    size_t cmd_len = strlen(cmd);
    (void)platform_socket_set_receive_timeout(g_tor_control, 1000);
    if ((size_t)send(g_tor_control, cmd, (int)cmd_len, 0) != cmd_len)
        return false;
    size_t have = 0;
    while (atomic_load(&g_tor_running) && have + 1 < reply_size) {
        long n = (long)recv(g_tor_control, reply + have,
                            (int)(reply_size - 1 - have), 0);
        if (n > 0) {
            have += (size_t)n;
            reply[have] = '\0';
            if (tor_control_reply_complete(reply))
                return true;
            continue;
        }
        int error = platform_socket_last_error();
        if (n == 0 || (!platform_socket_error_would_block(error) &&
                       !platform_socket_error_timed_out(error) &&
                       !platform_socket_error_interrupted(error)))
            return false;
        thread_liveness_beat(&g_tor_monitor_liveness,
                             (int64_t)atomic_fetch_add(
                                 &g_tor_monitor_poll_count, 1) + 1);
    }
    return false;
}
#if !defined(_WIN32) || defined(ZCL_TESTING)
/* 0 accepted, 1 known refusal, -1 uncertain or invalid framing. */
static int tor_setconf_exchange(platform_socket_t socket,
                                const _Atomic bool *running, int timeout_ms)
{
    static const char cmd[] = "SETCONF DisableNetwork=0\r\n";
    char reply[1024];
    if (!tor_bounded_exchange(socket, running, timeout_ms, cmd, reply,
                              sizeof(reply)))
        return -1;
    if (strcmp(reply, "250 OK\r\n") == 0)
        return 0;
    const char *eol = strstr(reply, "\r\n");
    if (reply[0] == '5' && reply[1] >= '0' && reply[1] <= '9' &&
        reply[2] >= '0' && reply[2] <= '9' && reply[3] == ' ' && eol &&
        eol[2] == '\0')
        return 1;
    return -1;
}

#ifdef ZCL_TESTING
int tor_integration_setconf_exchange_for_test(int64_t fd, int timeout_ms)
{
    _Atomic bool running = true;
    int result = tor_setconf_exchange((platform_socket_t)fd, &running, timeout_ms);
    if (result < 0)
        (void)platform_socket_shutdown_both((platform_socket_t)fd);
    return result;
}
#endif
#endif

/* Clear DisableNetwork over the pre-authenticated owning connection. */
const char *tor_control_enable(void)
{
#ifdef _WIN32
    return "clearing DisableNetwork is not supported on this platform";
#else
    if (g_tor_control == PLATFORM_SOCKET_INVALID)
        return "no control connection to enable the network";
    int result = tor_setconf_exchange(g_tor_control, &g_tor_running, 5000);
    if (result == 0)
        return NULL;
    if (result > 0)
        return "SETCONF DisableNetwork=0 was refused";
    tor_request_exit();
    return "uncertain SETCONF reply; Tor is stopping";
#endif
}

/* A failed enable is retried with a doubling pause (20 ms up to about 5 s)
 * and logged on attempts 1, 2, 4, 8, ... only, so a missing control socket
 * does not spin the monitor or flood the log. */
bool tor_enable_network(void)
{
    if (tor_wall_ms() < atomic_load(&g_enable_retry_ms))
        return false;
    const char *why = tor_control_enable();
    if (why) {
        unsigned failures = atomic_fetch_add(&g_enable_failures, 1) + 1;
        unsigned shift = failures < 9 ? failures : 9;
        atomic_store(&g_enable_retry_ms, tor_wall_ms() + (10LL << shift));
        if ((failures & (failures - 1)) == 0)
            LOG_ERROR("tor", "%s (attempt %u); the network stays disabled "
                             "and the enable is retried", why, failures);
        return false;
    }
    atomic_store(&g_enable_failures, 0);
    atomic_store(&g_enable_retry_ms, 0);
    int64_t now = tor_wall_ms();
    atomic_store(&g_network_enabled_ms, now);
    printf("Tor: claim verified at %lld ms, network enabled at %lld ms "
           "(DisableNetwork 0)\n",
           (long long)atomic_load(&g_claim_ms), (long long)now);
    fflush(stdout);
    return true;
}
