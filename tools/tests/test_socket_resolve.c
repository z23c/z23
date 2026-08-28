/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Verify portable IPv4 and IPv6 address resolution. */
#include "platform/socket_compat.h"

#include <string.h>

int main(void)
{
    uint8_t address[16];
    static const uint8_t mapped_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (!platform_socket_resolve_ip("127.0.0.1", address) ||
        memcmp(address, mapped_prefix, sizeof(mapped_prefix)) != 0 ||
        address[12] != 127 || address[13] != 0 || address[14] != 0 ||
        address[15] != 1)
        return 1;
    if (!platform_socket_resolve_ip("::1", address) || address[15] != 1)
        return 2;
    for (size_t i = 0; i < 15; i++)
        if (address[i] != 0)
            return 3;
    if (!platform_socket_resolve_ip("localhost", address))
        return 4;
    if (platform_socket_resolve_ip("invalid host name []", address))
        return 5;
    return 0;
}
