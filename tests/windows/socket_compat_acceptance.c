/* Headless native acceptance for Winsock lifecycle and socket options. */
#include "platform/socket_compat.h"

#include <stdio.h>
#include <string.h>

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
    if (platform_socket_close(socket_handle) != 0) return 6;

    /* Reserve an ephemeral loopback port, release it, and prove that the
     * nonblocking connect path reports a refusal through the portable error
     * seam.  This exercises the exact readiness-probe path without relying
     * on a machine-specific fixed port or launching a helper process. */
    platform_socket_t reserved = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    if (reserved == PLATFORM_SOCKET_INVALID) return 7;
    struct sockaddr_in endpoint = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr = address,
    };
#if defined(_WIN32)
    int endpoint_size = (int)sizeof(endpoint);
    if (bind(reserved, (const struct sockaddr *)&endpoint,
             endpoint_size) != 0 ||
        getsockname(reserved, (struct sockaddr *)&endpoint,
                    &endpoint_size) != 0) {
#else
    socklen_t endpoint_size = sizeof(endpoint);
    if (bind(reserved, (const struct sockaddr *)&endpoint,
             endpoint_size) != 0 ||
        getsockname(reserved, (struct sockaddr *)&endpoint,
                    &endpoint_size) != 0) {
#endif
        platform_socket_close(reserved);
        return 8;
    }
    platform_socket_close(reserved);

    platform_socket_t probe = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, true);
    if (probe == PLATFORM_SOCKET_INVALID) return 9;
    int connect_result = platform_socket_connect(
        probe, (const struct sockaddr *)&endpoint, sizeof(endpoint));
    if (connect_result != 0) {
        int error = platform_socket_last_error();
        if (platform_socket_error_in_progress(error)) {
            int ready = platform_socket_wait_writable(probe, 1000);
            if (ready <= 0) {
                platform_socket_close(probe);
                return 10;
            }
            if (platform_socket_pending_error(probe, &error) != 0) {
                platform_socket_close(probe);
                return 11;
            }
        }
        if (!platform_socket_error_refused(error)) {
            platform_socket_close(probe);
            return 12;
        }
    } else {
        platform_socket_close(probe);
        return 13;
    }
    platform_socket_close(probe);
    puts("socket_compat_acceptance: PASS");
    return 0;
}
