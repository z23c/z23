/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for Winsock lifecycle, options and bounded receive. */
#include "platform/socket_compat.h"

#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/resource.h>
#endif

#if defined(_WIN32)
/* Qualify receive_nonblocking on exclusively owned blocking sockets. This
 * does not test concurrent mode preservation, mesh framing, auth or PQ KEX. */
#define RECEIVE_TEST_BYTES 65536u
#define RECEIVE_TEST_DEADLINE_MS 3000u
#define RECEIVE_CALL_BOUND_MS 1000u

static bool receive_failure(const char *case_name, int result, int error)
{
    fprintf(stderr, "socket_compat_acceptance: %s failed result=%d socket_error=%d\n",
            case_name, result, error);
    return false;
}

static bool receive_idle_would_block(platform_socket_t sock)
{
    uint8_t byte = 0;
    ULONGLONG started = GetTickCount64();
    int result = platform_socket_receive_nonblocking(sock, &byte, 1);
    int error = result < 0 ? platform_socket_last_error() : 0;
    ULONGLONG elapsed = GetTickCount64() - started;
    if (result < 0 && platform_socket_error_would_block(error) &&
        elapsed < RECEIVE_CALL_BOUND_MS)
        return true;
    fprintf(stderr, "socket_compat_acceptance: idle receive elapsed_ms=%llu\n",
            (unsigned long long)elapsed);
    return receive_failure("idle receive must promptly would-block", result, error);
}

static bool receive_transfer_progress(int result, size_t *offset,
                                      const char *operation)
{
    if (result > 0) {
        *offset += (size_t)result;
        return true;
    }
    int error = result < 0 ? platform_socket_last_error() : 0;
    if (result < 0 && (platform_socket_error_would_block(error) ||
                       platform_socket_error_interrupted(error)))
        return true;
    return receive_failure(operation, result, error);
}

static bool receive_exact_transfer(platform_socket_t sender,
                                    platform_socket_t receiver, uint8_t salt)
{
    static uint8_t source[RECEIVE_TEST_BYTES], actual[RECEIVE_TEST_BYTES];
    for (size_t i = 0; i < sizeof(source); i++)
        source[i] = (uint8_t)(i * 29u + (i >> 8) + salt);
    memset(actual, 0, sizeof(actual));
    size_t sent = 0, received = 0;
    ULONGLONG deadline = GetTickCount64() + RECEIVE_TEST_DEADLINE_MS;
    while (received < sizeof(actual)) {
        if (GetTickCount64() >= deadline)
            return receive_failure("exact transfer deadline", -1, 0);
        if (sent < sizeof(source) &&
            !receive_transfer_progress(platform_socket_send_nonblocking(
                sender, source + sent, sizeof(source) - sent), &sent, "transfer send"))
            return false;
        if (!receive_transfer_progress(platform_socket_receive_nonblocking(
                receiver, actual + received, sizeof(actual) - received),
                &received, "transfer receive"))
            return false;
        if (received < sizeof(actual)) Sleep(1);
    }
    if (sent != sizeof(source) || memcmp(source, actual, sizeof(source)) != 0)
        return receive_failure("exact transfer bytes", -1, 0);
    return true;
}

static bool receive_peer_eof(platform_socket_t sock)
{
    ULONGLONG deadline = GetTickCount64() + RECEIVE_TEST_DEADLINE_MS;
    for (;;) {
        uint8_t byte = 0;
        int result = platform_socket_receive_nonblocking(sock, &byte, 1);
        if (result == 0) return true;
        int error = result < 0 ? platform_socket_last_error() : 0;
        if (result > 0 || !platform_socket_error_would_block(error))
            return receive_failure("drained peer-close EOF", result, error);
        if (GetTickCount64() >= deadline)
            return receive_failure("peer-close EOF deadline", result, error);
        Sleep(1);
    }
}

static bool receive_pair_configure(platform_socket_t pair[2])
{
    for (size_t i = 0; i < 2; i++) {
        /* A broken helper must hit a distinguishable blocking timeout rather
         * than hang indefinitely; the outer headless run has its own bound. */
        if (platform_socket_set_receive_timeout(pair[i], 2000) != 0 ||
            platform_socket_set_send_timeout(pair[i], 2000) != 0)
            return receive_failure("pair timeout configuration", -1,
                                    platform_socket_last_error());
    }
    return true;
}

static bool receive_connected_cases(void)
{
    platform_socket_t pair[2] = {PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID};
    if (!platform_socket_pair(pair))
        return receive_failure("verified loopback pair", -1, platform_socket_last_error());
    bool ok = receive_pair_configure(pair) && receive_idle_would_block(pair[0]) &&
              receive_idle_would_block(pair[1]) &&
              receive_exact_transfer(pair[0], pair[1], 7) &&
              receive_exact_transfer(pair[1], pair[0], 193) &&
              receive_idle_would_block(pair[0]) && receive_idle_would_block(pair[1]);
    if (ok) {
        if (platform_socket_close(pair[0]) == 0) {
            pair[0] = PLATFORM_SOCKET_INVALID;
            ok = receive_peer_eof(pair[1]);
        } else {
            ok = receive_failure("peer close", -1, platform_socket_last_error());
        }
    }
    for (size_t i = 0; i < 2; i++) {
        if (pair[i] != PLATFORM_SOCKET_INVALID && platform_socket_close(pair[i]) != 0)
            ok = receive_failure("pair cleanup", -1, platform_socket_last_error());
    }
    return ok;
}
#endif
static int socket_completion_cases(platform_socket_t socket_handle)
{
    if (platform_socket_close(socket_handle) != 0) {
        fprintf(stderr, "socket_compat_acceptance: original socket cleanup failed\n");
        return 6;
    }
#if defined(_WIN32)
    if (!receive_connected_cases()) return 12;
#endif
    return 0;
}

/* Check IPv4 loopback parse and format behaviour; returns 0 or the failure code. */
static int verify_loopback_parse(void)
{
    struct in_addr address;
    const unsigned char loopback[4] = {127, 0, 0, 1};
    if (platform_socket_parse_address(AF_INET, "127.0.0.1", &address) != 1 ||
        memcmp(&address, loopback, sizeof(loopback)) != 0)
        return 2;
    if (platform_socket_parse_address(AF_INET, "not-an-address", &address) != 0)
        return 3;
    if (platform_socket_parse_address(AF_INET, "127.0.0.1", &address) != 1)
        return 10;
    char formatted[PLATFORM_IPV4_ADDRESS_TEXT_SIZE];
    if (!platform_socket_format_address(AF_INET, &address, formatted,
                                        sizeof(formatted)) ||
        strcmp(formatted, "127.0.0.1") != 0)
        return 8;
    char too_small[4];
    if (platform_socket_format_address(AF_INET, &address, too_small,
                                       sizeof(too_small)))
        return 9;
    return 0;
}

/* Resolve the loopback name and require the single mapped address; 0 or 11. */
static int verify_loopback_resolve(void)
{
    uint8_t resolved[2][16];
    size_t resolved_count = 0;
    const uint8_t mapped_loopback[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
    if (!platform_socket_resolve_addresses(
            "127.0.0.1", false, resolved, 2, &resolved_count) ||
        resolved_count != 1 ||
        memcmp(resolved[0], mapped_loopback, sizeof(mapped_loopback)) != 0)
        return 11;
    return 0;
}

/* Open the acceptance stream socket with short timeouts; returns 0, 4 or 5,
 * with the handle in *out on 0. */
static int open_timeout_socket(platform_socket_t *out)
{
    platform_socket_t socket_handle = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    *out = socket_handle;
    if (socket_handle == PLATFORM_SOCKET_INVALID)
        return 4;
    if (platform_socket_set_receive_timeout(socket_handle, 250) != 0 ||
        platform_socket_set_send_timeout(socket_handle, 250) != 0) {
        platform_socket_close(socket_handle);
        *out = PLATFORM_SOCKET_INVALID;
        return 5;
    }
    return 0;
}

#if !defined(_WIN32)
/* Ensure the soft descriptor limit exceeds FD_SETSIZE, then probe a high
 * handle; returns 0, 8 or 9. */
static int verify_high_descriptor_limits(platform_socket_t socket_handle)
{
    struct rlimit descriptors;
    if (getrlimit(RLIMIT_NOFILE, &descriptors) != 0) return 8;
    if (descriptors.rlim_cur <= FD_SETSIZE) {
        rlim_t needed = (rlim_t)FD_SETSIZE + 1u;
        if (needed > descriptors.rlim_max) return 8;
        descriptors.rlim_cur = needed;
        if (setrlimit(RLIMIT_NOFILE, &descriptors) != 0) return 8;
    }
    platform_socket_t high = fcntl(socket_handle, F_DUPFD, FD_SETSIZE);
    if (high < FD_SETSIZE || platform_socket_wait_writable(high, 0) < 0 ||
        platform_socket_wait_readable(high, 0) < 0 || close(high) != 0)
        return 9;
    return 0;
}
#endif
int main(void)
{
    if (!platform_socket_runtime_init()) return 1;
    int parse_status = verify_loopback_parse();
    if (parse_status != 0) return parse_status;
    int resolve_status = verify_loopback_resolve();
    if (resolve_status != 0) return resolve_status;
    platform_socket_t socket_handle;
    int open_status = open_timeout_socket(&socket_handle);
    if (open_status != 0) return open_status;
#if defined(_WIN32)
    if (!platform_socket_error_refused(WSAECONNREFUSED)) return 7;
#else
    if (!platform_socket_error_refused(ECONNREFUSED)) return 7;
    int high_status = verify_high_descriptor_limits(socket_handle);
    if (high_status != 0) return high_status;
#endif
    int completion = socket_completion_cases(socket_handle);
    if (completion != 0) return completion;
    puts("socket_compat_acceptance: PASS");
    return 0;
}
