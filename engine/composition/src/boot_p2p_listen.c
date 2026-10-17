/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Bind explicit P2P listener addresses without wildcard fallback. */
#include "config/boot.h"
#include "net/net.h"
#include "platform/socket_compat.h"
#include <stdio.h>
#include <string.h>

#ifdef ZCL_TESTING
static bool g_p2p_refuse_ipv6;
void boot_p2p_refuse_ipv6_for_test(bool refuse) { g_p2p_refuse_ipv6 = refuse; }
#endif

bool boot_p2p_parse_bind_address(const char *text, struct net_service *out)
{
    if (!out) return false;
    net_service_init(out);
    if (!text || !text[0] || strlen(text) >= PLATFORM_IPV6_ADDRESS_TEXT_SIZE)
        return false;
    unsigned char ipv4[4];
    if (platform_socket_parse_address(AF_INET, text, ipv4) == 1) {
        net_addr_set_ipv4(&out->addr, ipv4);
        return true;
    }
    if (platform_socket_parse_address(AF_INET6, text, out->addr.ip) == 1 &&
        !net_addr_is_ipv4(&out->addr)) return true;
    net_service_init(out);
    return false;
}

static void boot_p2p_default_listeners(struct net_manager *manager, uint16_t port)
{
    struct net_service bind4;
    net_service_init(&bind4);
    unsigned char any4[4] = {0, 0, 0, 0};
    net_addr_set_ipv4(&bind4.addr, any4);
    bind4.port = port;
    if (bind_listen_port(manager, &bind4, false))
        printf("P2P listening on 0.0.0.0:%d\n", port);
    struct net_service bind6;
    net_service_init(&bind6);
    bind6.port = port;
    if (bind_listen_port(manager, &bind6, false))
        printf("P2P listening on [::]:%d\n", port);
}

static bool boot_p2p_explicit_listener(struct net_manager *manager,
                                      const struct net_service *address)
{
    size_t previous = manager->num_listen_sockets;
    if (!bind_listen_port(manager, address, false)) return false;
    if (!net_addr_is_ipv4(&address->addr)) {
        int only = 0;
        bool verified = platform_socket_get_ipv6_only(
            manager->listen_sockets[previous].socket, &only) && only == 1;
#ifdef ZCL_TESTING
        verified = verified && !g_p2p_refuse_ipv6;
#endif
        if (!verified) {
            /* Keep the descriptor in its existing owner. A failed close can
             * release an fd on POSIX, so retrying it can close a reused fd.
             * The boot caller exits before starting P2P accept threads;
             * library callers must perform normal manager teardown. */
            fprintf(stderr, "P2P explicit IPv6 listener lacks verified IPV6_V6ONLY\n");
            return false;
        }
    }
    return true;
}

bool boot_p2p_listen(struct net_manager *manager, const struct app_context *ctx)
{
    if (!manager || !ctx) return false;
    if (!ctx->listen) return true;
    if (!ctx->p2p_bind_address) {
        boot_p2p_default_listeners(manager, (uint16_t)ctx->p2p_port);
        return true;
    }
    struct net_service address;
    if (ctx->p2p_port < 0 || ctx->p2p_port > 65535 ||
        !boot_p2p_parse_bind_address(ctx->p2p_bind_address, &address)) {
        fprintf(stderr, "P2P explicit bind address or port is invalid\n");
        return false;
    }
    address.port = (uint16_t)ctx->p2p_port;
    if (!boot_p2p_explicit_listener(manager, &address)) {
        fprintf(stderr, "P2P explicit bind failed: %s port %d (no fallback)\n",
                ctx->p2p_bind_address, ctx->p2p_port);
        return false;
    }
    printf("P2P listening on explicit address %s port %d\n",
           ctx->p2p_bind_address, ctx->p2p_port);
    return true;
}
