/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for Winsock lifecycle and socket options. */
#include "platform/socket_compat.h"

#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/resource.h>
#endif

int main(void)
{
    if (!platform_socket_runtime_init()) return 1;
    struct in_addr address;
    const unsigned char loopback[4] = {127, 0, 0, 1};
    if (platform_socket_parse_address(AF_INET, "127.0.0.1", &address) != 1 ||
        memcmp(&address, loopback, sizeof(loopback)) != 0)
        return 2;
    if (platform_socket_parse_address(AF_INET, "not-an-address", &address) != 0)
        return 3;
    platform_socket_t socket_handle = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    if (socket_handle == PLATFORM_SOCKET_INVALID) return 4;
    if (platform_socket_set_receive_timeout(socket_handle, 250) != 0 ||
        platform_socket_set_send_timeout(socket_handle, 250) != 0) {
        platform_socket_close(socket_handle);
        return 5;
    }
#if defined(_WIN32)
    if (!platform_socket_error_refused(WSAECONNREFUSED)) return 7;
#else
    if (!platform_socket_error_refused(ECONNREFUSED)) return 7;
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
#endif
    if (platform_socket_close(socket_handle) != 0) return 6;
    puts("socket_compat_acceptance: PASS");
    return 0;
}
