/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Default-gateway discovery from a BSD/Darwin routing-socket table dump.
 *
 * macOS has no /proc/net/route. The kernel's routing table is instead read
 * with sysctl({CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0}), which hands
 * back one packed byte image holding a sequence of variable-length routing
 * messages: a `struct rt_msghdr` followed by up to eight variable-length
 * BSD sockaddrs, one per bit set in rtm_addrs, each padded up to a 4-byte
 * boundary.
 *
 * The file is deliberately two halves:
 *
 *   1. nat_route_dump_find_default_gateway() — a PURE walker over that byte
 *      image. No syscalls, no platform headers, no allocation. It is
 *      compiled on EVERY platform and unit-tested on Linux against
 *      synthetic buffers (lib/test/src/test_nat_route_dump.c), so the part
 *      that can actually be wrong — bounds, sockaddr padding, default-route
 *      selection, gateway byte order — is covered by a test that runs here.
 *
 *   2. nat_route_dump_default_gateway() — a thin __APPLE__-only shim that
 *      performs the sysctl and hands the bytes to the walker. It describes
 *      the message layout to the walker with sizeof/offsetof over the REAL
 *      system headers, and static_asserts every field offset and flag
 *      constant the walker hardcodes. A Darwin ABI change therefore breaks
 *      the BUILD instead of silently mis-parsing a routing table.
 *
 * Byte-order contract: the 4 bytes written to gw_out are the IPv4 address
 * in NETWORK byte order (gw_out[0] is the first dotted-quad octet), copied
 * straight out of the sockaddr_in's sin_addr — the same order the Linux
 * /proc/net/route arm and the Windows GetBestRoute2 arm of nat_get_gateway()
 * produce, and the order natpmp_send_recv() feeds to sin_addr. */

#include "net/nat.h"
#include "util/log_macros.h"

#include <stdint.h>
#include <string.h>

/* ── the rt_msghdr prefix this parser reads ───────────────────────────
 * Offsets into `struct rt_msghdr`. Every one is re-asserted against the
 * system header in the __APPLE__ section below. */
#define NAT_RD_OFF_MSGLEN   0u  /* u_short rtm_msglen  */
#define NAT_RD_OFF_VERSION  2u  /* u_char  rtm_version */
#define NAT_RD_OFF_TYPE     3u  /* u_char  rtm_type    */
#define NAT_RD_OFF_FLAGS    8u  /* int     rtm_flags   */
#define NAT_RD_OFF_ADDRS   12u  /* int     rtm_addrs   */
#define NAT_RD_MIN_HEADER  16u  /* last byte we read is at offset 15 */

/* rtm_flags bits. */
#define NAT_RD_RTF_UP        0x1u
#define NAT_RD_RTF_GATEWAY   0x2u
#define NAT_RD_RTF_HOST      0x4u

/* rtm_addrs bits, in the ascending order the sockaddrs are packed. */
#define NAT_RD_BIT_DST       0u  /* RTA_DST     == 0x1 */
#define NAT_RD_BIT_GATEWAY   1u  /* RTA_GATEWAY == 0x2 */
#define NAT_RD_ADDR_BITS     8u  /* RTA_DST .. RTA_BRD */

/* sockaddr prefix: BSD sockaddrs lead with `u_char sa_len; u_char sa_family;`
 * and a sockaddr_in carries sin_addr at offset 4. */
#define NAT_RD_SA_OFF_LEN     0u
#define NAT_RD_SA_OFF_FAMILY  1u
#define NAT_RD_SA_OFF_ADDR    4u
#define NAT_RD_SA_MIN_IPV4    8u  /* sa_len must cover sin_addr's last byte */

/* Native-ABI loads. This buffer is produced by the kernel of the machine
 * reading it, so rtm_msglen/rtm_flags/rtm_addrs are host-order native
 * integers — not a wire format, and deliberately not a byte-order codec. */
static uint16_t nat_rd_load_u16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

static uint32_t nat_rd_load_u32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return v;
}

/* BSD pads each sockaddr up to a 4-byte boundary; a zero sa_len still
 * consumes one padding unit. */
static size_t nat_rd_sa_stride(size_t sa_len)
{
    return sa_len > 0u ? (((sa_len - 1u) | 3u) + 1u) : 4u;
}

/* True when this sockaddr image denotes the wildcard destination 0.0.0.0.
 *
 * The kernel truncates trailing zero bytes off wildcard/mask sockaddrs, so a
 * default route's destination legitimately arrives as a 0-length sockaddr,
 * as a short one, or as a full 16-byte sockaddr_in holding 0.0.0.0. Bytes
 * past sa_len read as zero, which is exactly the truncation convention. */
static bool nat_rd_sa_is_wildcard(const uint8_t *sa, size_t sa_len,
                                  unsigned af_inet)
{
    if (sa_len < 2u) return true; /* no family byte: the /0 wildcard */
    if (sa[NAT_RD_SA_OFF_FAMILY] != (uint8_t)af_inet) return false;
    for (size_t i = 0; i < 4u; i++) {
        size_t at = NAT_RD_SA_OFF_ADDR + i;
        uint8_t byte = at < sa_len ? sa[at] : 0u;
        if (byte != 0u) return false;
    }
    return true;
}

/* Extract a usable IPv4 next hop. A truncated sockaddr or an AF_LINK next
 * hop (a directly attached route) is NOT a gateway, and 0.0.0.0 is never
 * handed back as a plausible-looking answer. */
static bool nat_rd_sa_ipv4_gateway(const uint8_t *sa, size_t sa_len,
                                   unsigned af_inet, uint8_t gw_out[4])
{
    if (sa_len < NAT_RD_SA_MIN_IPV4) return false;
    if (sa[NAT_RD_SA_OFF_FAMILY] != (uint8_t)af_inet) return false;
    const uint8_t *addr = sa + NAT_RD_SA_OFF_ADDR;
    if (addr[0] == 0u && addr[1] == 0u && addr[2] == 0u && addr[3] == 0u)
        return false;
    memcpy(gw_out, addr, 4);
    return true;
}

/* Walk one message's sockaddr area. RTA_DST is bit 0 and RTA_GATEWAY bit 1,
 * so the destination is always seen first and its wildcard test gates the
 * gateway read. Returns false for "this message is not the default route"
 * as well as for a truncated area — the caller moves on to the next
 * message either way. */
static bool nat_rd_message_gateway(const uint8_t *area, size_t area_len,
                                   uint32_t addrs, unsigned af_inet,
                                   uint8_t gw_out[4])
{
    size_t off = 0;
    bool dst_is_default = false;

    for (unsigned bit = 0; bit < NAT_RD_ADDR_BITS; bit++) {
        if ((addrs & (1u << bit)) == 0u) continue;
        if (off >= area_len) return false;      /* area ended early */

        const uint8_t *sa = area + off;
        size_t avail = area_len - off;
        size_t sa_len = sa[NAT_RD_SA_OFF_LEN];
        size_t stride = nat_rd_sa_stride(sa_len);
        if (stride > avail) return false;       /* sockaddr overruns area */

        if (bit == NAT_RD_BIT_DST) {
            if (!nat_rd_sa_is_wildcard(sa, sa_len, af_inet)) return false;
            dst_is_default = true;
        } else if (bit == NAT_RD_BIT_GATEWAY) {
            if (!dst_is_default) return false;
            return nat_rd_sa_ipv4_gateway(sa, sa_len, af_inet, gw_out);
        }
        off += stride;
    }
    return false;
}

bool nat_route_dump_find_default_gateway(const uint8_t *buf, size_t len,
                                         const struct nat_route_dump_abi *abi,
                                         uint8_t gw_out[4])
{
    if (!buf || !abi || !gw_out)
        LOG_FAIL("nat", "routing-dump walk called with a NULL argument");
    if (abi->header_size < NAT_RD_MIN_HEADER)
        LOG_FAIL("nat", "routing-dump header size %zu is below the %u-byte "
                        "rt_msghdr prefix this parser reads",
                 abi->header_size, (unsigned)NAT_RD_MIN_HEADER);
    if (abi->version > 0xFFu || abi->af_inet > 0xFFu)
        LOG_FAIL("nat", "routing-dump ABI has an out-of-range version %u or "
                        "address family %u", abi->version, abi->af_inet);

    size_t off = 0;
    while (len - off >= abi->header_size) {
        size_t remaining = len - off;
        size_t msglen = nat_rd_load_u16(buf + off + NAT_RD_OFF_MSGLEN);
        /* A message that does not fit its own header, or that claims more
         * bytes than remain, means the image is not what we think it is.
         * Refuse the whole dump rather than resynchronizing on a guess. */
        if (msglen < abi->header_size || msglen > remaining)
            LOG_FAIL("nat", "routing-dump message at offset %zu claims length "
                            "%zu, outside [%zu,%zu]",
                     off, msglen, abi->header_size, remaining);

        if (buf[off + NAT_RD_OFF_VERSION] == (uint8_t)abi->version) {
            uint32_t flags = nat_rd_load_u32(buf + off + NAT_RD_OFF_FLAGS);
            uint32_t addrs = nat_rd_load_u32(buf + off + NAT_RD_OFF_ADDRS);
            const uint32_t want_flags = NAT_RD_RTF_UP | NAT_RD_RTF_GATEWAY;
            const uint32_t want_addrs = (1u << NAT_RD_BIT_DST) |
                                        (1u << NAT_RD_BIT_GATEWAY);
            if ((flags & want_flags) == want_flags &&
                (flags & NAT_RD_RTF_HOST) == 0u &&
                (addrs & want_addrs) == want_addrs &&
                nat_rd_message_gateway(buf + off + abi->header_size,
                                       msglen - abi->header_size, addrs,
                                       abi->af_inet, gw_out))
                return true;
        }
        off += msglen;
    }
    LOG_FAIL("nat", "no IPv4 default route in the %zu-byte routing dump", len);
}

/* ════════════════════════════════════════════════════════════════
 *  Darwin syscall shim
 * ════════════════════════════════════════════════════════════════ */

#if defined(__APPLE__)

#include "base/safe_alloc.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <netinet/in.h>

/* The walker hardcodes the layout above; these pin it to the real headers,
 * so a Darwin ABI change is a compile error rather than a wrong gateway. */
static_assert(offsetof(struct rt_msghdr, rtm_msglen) == NAT_RD_OFF_MSGLEN,
              "rtm_msglen offset moved");
static_assert(sizeof(((struct rt_msghdr *)0)->rtm_msglen) == 2,
              "rtm_msglen is no longer 16-bit");
static_assert(offsetof(struct rt_msghdr, rtm_version) == NAT_RD_OFF_VERSION,
              "rtm_version offset moved");
static_assert(offsetof(struct rt_msghdr, rtm_type) == NAT_RD_OFF_TYPE,
              "rtm_type offset moved");
static_assert(offsetof(struct rt_msghdr, rtm_flags) == NAT_RD_OFF_FLAGS,
              "rtm_flags offset moved");
static_assert(sizeof(((struct rt_msghdr *)0)->rtm_flags) == 4,
              "rtm_flags is no longer 32-bit");
static_assert(offsetof(struct rt_msghdr, rtm_addrs) == NAT_RD_OFF_ADDRS,
              "rtm_addrs offset moved");
static_assert(sizeof(((struct rt_msghdr *)0)->rtm_addrs) == 4,
              "rtm_addrs is no longer 32-bit");
static_assert(sizeof(struct rt_msghdr) >= NAT_RD_MIN_HEADER,
              "rt_msghdr shorter than the prefix this parser reads");
static_assert(RTF_UP == NAT_RD_RTF_UP, "RTF_UP changed");
static_assert(RTF_GATEWAY == NAT_RD_RTF_GATEWAY, "RTF_GATEWAY changed");
static_assert(RTF_HOST == NAT_RD_RTF_HOST, "RTF_HOST changed");
static_assert(RTA_DST == (1 << NAT_RD_BIT_DST), "RTA_DST changed");
static_assert(RTA_GATEWAY == (1 << NAT_RD_BIT_GATEWAY), "RTA_GATEWAY changed");
static_assert(offsetof(struct sockaddr, sa_family) == NAT_RD_SA_OFF_FAMILY,
              "sockaddr has no leading sa_len byte");
static_assert(offsetof(struct sockaddr_in, sin_addr) == NAT_RD_SA_OFF_ADDR,
              "sin_addr offset moved");
static_assert(sizeof(((struct sockaddr_in *)0)->sin_addr) == 4,
              "sin_addr is no longer 4 bytes");

#define NAT_RD_MIB_LEN 6
#define NAT_RD_ATTEMPTS 4

static bool nat_rd_probe_size(int *mib, size_t *need_out)
{
    size_t need = 0;
    if (sysctl(mib, NAT_RD_MIB_LEN, NULL, &need, NULL, 0) != 0)
        LOG_FAIL("nat", "PF_ROUTE NET_RT_DUMP size probe failed: %s",
                 strerror(errno));
    if (need == 0)
        LOG_FAIL("nat", "kernel reports an empty IPv4 routing table");
    *need_out = need;
    return true;
}

bool nat_route_dump_default_gateway(uint8_t gw_out[4])
{
    if (!gw_out) LOG_FAIL("nat", "gateway output buffer is NULL");

    int mib[NAT_RD_MIB_LEN] = { CTL_NET, PF_ROUTE, 0, AF_INET,
                                NET_RT_DUMP, 0 };
    size_t need = 0;
    if (!nat_rd_probe_size(mib, &need)) return false;

    /* The table can grow between the size probe and the fetch, so keep a
     * slack margin and re-probe on ENOMEM a bounded number of times. */
    for (unsigned attempt = 0; attempt < NAT_RD_ATTEMPTS; attempt++) {
        size_t cap = need + need / 8u + 4096u;
        uint8_t *buf = zcl_malloc(cap, "nat_route_dump");
        if (!buf)
            LOG_FAIL("nat", "allocation of %zu bytes for the routing dump "
                            "failed", cap);

        size_t got = cap;
        if (sysctl(mib, NAT_RD_MIB_LEN, buf, &got, NULL, 0) != 0) {
            int err = errno;
            free(buf);
            if (err != ENOMEM)
                LOG_FAIL("nat", "PF_ROUTE NET_RT_DUMP failed: %s",
                         strerror(err));
            if (!nat_rd_probe_size(mib, &need)) return false;
            continue;
        }

        struct nat_route_dump_abi abi = {
            .header_size = sizeof(struct rt_msghdr),
            .version = (unsigned)RTM_VERSION,
            .af_inet = (unsigned)AF_INET,
        };
        bool found = nat_route_dump_find_default_gateway(buf, got, &abi,
                                                         gw_out);
        free(buf);
        return found;
    }
    LOG_FAIL("nat", "PF_ROUTE NET_RT_DUMP outgrew its buffer %d times",
             NAT_RD_ATTEMPTS);
}

#endif /* __APPLE__ */
