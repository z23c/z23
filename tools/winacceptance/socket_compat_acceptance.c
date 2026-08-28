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
    uint8_t resolved[2][16];
    size_t resolved_count = 0;
    const uint8_t mapped_loopback[16] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1};
    if (!platform_socket_resolve_addresses(
            "127.0.0.1", false, resolved, 2, &resolved_count) ||
        resolved_count != 1 ||
        memcmp(resolved[0], mapped_loopback, sizeof(mapped_loopback)) != 0)
        return 11;
    platform_socket_t socket_handle = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    if (socket_handle == PLATFORM_SOCKET_INVALID) return 4;
    if (platform_socket_set_receive_timeout(socket_handle, 250) != 0 ||
        platform_socket_set_send_timeout(socket_handle, 250) != 0) {
        platform_socket_close(socket_handle);
        return 5;
    }
    if (platform_socket_close(socket_handle) != 0) return 6;

#if defined(_WIN32)
    if (!platform_socket_error_refused(WSAECONNREFUSED)) return 7;
#else
    if (!platform_socket_error_refused(ECONNREFUSED)) return 7;
#endif
    puts("socket_compat_acceptance: PASS");
    return 0;
}
