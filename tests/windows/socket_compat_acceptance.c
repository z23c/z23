/* Headless native acceptance for Winsock lifecycle and socket options. */
#include "platform/socket_compat.h"

#include <stdio.h>

int main(void)
{
    if (!platform_socket_runtime_init()) return 1;
    platform_socket_t socket_handle = platform_socket_open(
        AF_INET, SOCK_STREAM, 0, true, false);
    if (socket_handle == PLATFORM_SOCKET_INVALID) return 2;
    if (platform_socket_set_receive_timeout(socket_handle, 250) != 0 ||
        platform_socket_set_send_timeout(socket_handle, 250) != 0) {
        platform_socket_close(socket_handle);
        return 3;
    }
    if (platform_socket_close(socket_handle) != 0) return 4;
    puts("socket_compat_acceptance: PASS");
    return 0;
}
