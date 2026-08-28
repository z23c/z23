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

#if defined(_WIN32)
    if (!platform_socket_error_refused(WSAECONNREFUSED)) return 7;
#else
    if (!platform_socket_error_refused(ECONNREFUSED)) return 7;
#endif
    puts("socket_compat_acceptance: PASS");
    return 0;
}
