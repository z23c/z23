/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves platform_socket_resolve_ip() returns IPv4-mapped IPv6
 * bytes for a dotted quad, native bytes for ::1, resolves localhost, and
 * refuses a malformed hostname.
 *
 * Rehomed from tools/tests/test_socket_resolve.c, which only ever ran when a
 * human invoked tools/scripts/winacceptance.sh by hand. As a registered
 * group it executes on every suite run. The probe body below is the original
 * program verbatim; its distinct non-zero returns still name the step that
 * broke. */
#include "test/test_core.h"

#include "platform/socket_compat.h"

#include <string.h>

static int socket_resolve_probe(void)
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

int test_socket_resolve(void)
{
    int failures = 0;
    int rc = socket_resolve_probe();
    printf("socket_resolve: resolve_ip mapped/native/localhost/refusal... ");
    if (rc == 0) {
        printf("OK\n");
    } else {
        printf("FAIL (step %d)\n", rc);
        failures++;
    }
    return failures;
}
