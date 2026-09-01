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

#include "net/netbase.h"
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

    TEST("socket buffers: report the kernel grant after P2P configuration") {
        platform_socket_t pair[2];
        struct net_p2p_socket_buffer_stats before = {0};
        struct net_p2p_socket_buffer_stats after = {0};
        ASSERT(platform_socket_pair(pair));
        net_get_p2p_socket_buffer_stats(&before);
        ASSERT(net_configure_p2p_socket_buffers(pair[0]));
        net_get_p2p_socket_buffer_stats(&after);
        ASSERT_EQ(after.attempts_total, before.attempts_total + 1);
        ASSERT_EQ(after.fully_observed_total,
                  before.fully_observed_total + 1);
        ASSERT_EQ(after.degraded_total, before.degraded_total);
        ASSERT(after.minimum_actual_receive_bytes > 0);
        ASSERT(after.minimum_actual_send_bytes > 0);
#if defined(__linux__)
        ASSERT_EQ(after.requested_receive_bytes, 0);
        ASSERT_EQ(after.requested_send_bytes, 0);
#else
        ASSERT_EQ(after.requested_receive_bytes,
                  PLATFORM_P2P_SOCKET_BUFFER_SIZE);
        ASSERT_EQ(after.requested_send_bytes,
                  PLATFORM_P2P_SOCKET_BUFFER_SIZE);
#endif
        ASSERT_EQ(platform_socket_close(pair[0]), 0);
        ASSERT_EQ(platform_socket_close(pair[1]), 0);
        printf("request=%d actual_rx_min=%d actual_tx_min=%d ",
               after.requested_receive_bytes,
               after.minimum_actual_receive_bytes,
               after.minimum_actual_send_bytes);
        PASS();
    } _test_next:;
    return failures;
}
