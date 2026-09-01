/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * NAT traversal — pure C23, no external libraries.
 * Supports NAT-PMP (RFC 6886) and UPnP IGD (SSDP + SOAP).
 * Graceful degradation: tries NAT-PMP first, then UPnP, then gives up. */

#ifndef ZCL_NET_NAT_H
#define ZCL_NET_NAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Try to open an external port mapping.
 * Tries NAT-PMP first, falls back to UPnP IGD.
 * Returns true if a mapping was created.
 * external_port: the port to open on the router
 * internal_port: the local port to forward to
 * lifetime: mapping lifetime in seconds (0 = delete)
 * protocol: "TCP" or "UDP"
 * public_ip_out: if non-NULL, filled with our public IP (4 bytes) */
bool nat_add_port_mapping(uint16_t external_port, uint16_t internal_port,
                           uint32_t lifetime, const char *protocol,
                           uint8_t public_ip_out[4]);

/* Discover public IP via NAT-PMP or UPnP. */
bool nat_discover_public_ip(uint8_t ip_out[4]);

/* Get the default gateway IP.
 * gw_out receives the 4 address bytes in NETWORK byte order, i.e. gw_out[0]
 * is the leading dotted-quad octet. Every platform arm returns that same
 * order; NAT-PMP copies the 4 bytes straight into sockaddr_in::sin_addr. */
bool nat_get_gateway(uint8_t gw_out[4]);

/* ── BSD/Darwin routing-table dump (core/modules/net/src/nat_route_dump.c) ─────
 * macOS has no /proc/net/route; the routing table is read with
 * sysctl({CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0}), which returns a
 * packed sequence of `struct rt_msghdr` records each followed by up to
 * eight variable-length, 4-byte-padded BSD sockaddrs.
 *
 * Walking that image is pure byte work, so it is split from the syscall
 * that produces it: the walker below compiles on every platform and is
 * unit-tested on Linux against synthetic buffers, while only the sysctl
 * shim is Darwin-only. The message layout is passed IN rather than baked
 * in, so the Darwin shim (sizeof/offsetof over the real system headers)
 * and the test (a transcribed struct) describe it from two independent
 * sources. */
struct nat_route_dump_abi {
    size_t   header_size;  /* sizeof(struct rt_msghdr) */
    unsigned version;      /* RTM_VERSION; other versions are skipped */
    unsigned af_inet;      /* AF_INET */
};

/* Find the IPv4 default route's next hop in a NET_RT_DUMP byte image.
 * Writes 4 network-order address bytes to gw_out and returns true only for
 * an up, non-host, gatewayed route whose destination is the 0.0.0.0
 * wildcard and whose gateway is a full AF_INET sockaddr holding a non-zero
 * address. Returns false — leaving gw_out untouched — for "no default
 * route" and for a malformed image alike. Never invents an address. */
bool nat_route_dump_find_default_gateway(const uint8_t *buf, size_t len,
                                         const struct nat_route_dump_abi *abi,
                                         uint8_t gw_out[4]);

#if defined(__APPLE__)
/* Darwin: dump the kernel IPv4 routing table and return its default
 * gateway. Fails closed when there is none. */
bool nat_route_dump_default_gateway(uint8_t gw_out[4]);
#endif

#endif
