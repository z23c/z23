/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for nat_route_dump_find_default_gateway()
 * (core/modules/net/src/nat_route_dump.c) — the pure walker over the byte image
 * macOS's sysctl({CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0}) returns.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The Darwin arm of nat_get_gateway() cannot be executed on Linux, so the
 * part of it that can actually be wrong was deliberately factored out of
 * the syscall: message bounds, BSD sockaddr padding, default-route
 * selection, and the gateway's byte order are all pure functions of a byte
 * buffer. This file builds those buffers by hand and runs the real parser
 * against them, on this host, in this suite.
 *
 * HOW THE FIXTURES ARE BUILT
 * --------------------------
 * Not with the parser's own offsets — that would only prove the parser
 * agrees with itself. The messages are laid out through `struct
 * darwin_rt_msghdr` / `struct darwin_sockaddr_in` below, transcribed field
 * for field from Darwin's <net/route.h> and <netinet/in.h>. macOS (x86_64
 * and arm64) and Linux (x86_64) share the same LP64 alignment rules, so
 * offsetof/sizeof over the transcription reproduce Darwin's real offsets
 * here — the static_asserts pin them. If the parser's hardcoded offsets
 * ever disagree with that layout, these tests fail.
 *
 * WHAT THAT DOES AND DOES NOT PROVE: it proves the walker's logic and the
 * offsets it assumes. It does NOT prove the sysctl shim itself, which is
 * compiled only under __APPLE__ and has never been executed here; that shim
 * static_asserts the same offsets against the REAL system headers, so a
 * Darwin build fails loudly rather than mis-parsing. */

#include "test/test_core.h"

#include "net/nat.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RD_CHECK(name, expr) do {                                   \
    printf("nat_route_dump: %s... ", (name));                       \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* ── Darwin ABI, transcribed ──────────────────────────────────────── */

struct darwin_rt_metrics {
    uint32_t rmx_locks;
    uint32_t rmx_mtu;
    uint32_t rmx_hopcount;
    int32_t  rmx_expire;
    uint32_t rmx_recvpipe;
    uint32_t rmx_sendpipe;
    uint32_t rmx_ssthresh;
    uint32_t rmx_rtt;
    uint32_t rmx_rttvar;
    uint32_t rmx_pksent;
    uint32_t rmx_state;
    uint32_t rmx_filler[3];
};

struct darwin_rt_msghdr {
    uint16_t rtm_msglen;
    uint8_t  rtm_version;
    uint8_t  rtm_type;
    uint16_t rtm_index;
    int32_t  rtm_flags;
    int32_t  rtm_addrs;
    int32_t  rtm_pid;
    int32_t  rtm_seq;
    int32_t  rtm_errno;
    int32_t  rtm_use;
    uint32_t rtm_inits;
    struct darwin_rt_metrics rtm_rmx;
};

struct darwin_sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint8_t  sin_addr[4];
    uint8_t  sin_zero[8];
};

/* The offsets the parser hardcodes. A mismatch here means the parser and
 * Darwin's real rt_msghdr have diverged. */
static_assert(offsetof(struct darwin_rt_msghdr, rtm_msglen) == 0, "msglen@0");
static_assert(offsetof(struct darwin_rt_msghdr, rtm_version) == 2, "version@2");
static_assert(offsetof(struct darwin_rt_msghdr, rtm_type) == 3, "type@3");
static_assert(offsetof(struct darwin_rt_msghdr, rtm_flags) == 8, "flags@8");
static_assert(offsetof(struct darwin_rt_msghdr, rtm_addrs) == 12, "addrs@12");
static_assert(sizeof(struct darwin_rt_msghdr) == 92, "rt_msghdr is 92 bytes");
static_assert(offsetof(struct darwin_sockaddr_in, sin_addr) == 4, "sin_addr@4");
static_assert(sizeof(struct darwin_sockaddr_in) == 16, "sockaddr_in is 16");

#define DARWIN_RTM_VERSION 5
#define DARWIN_RTM_GET     4
#define DARWIN_AF_INET     2
#define DARWIN_AF_LINK    18

#define DARWIN_RTF_UP      0x1
#define DARWIN_RTF_GATEWAY 0x2
#define DARWIN_RTF_HOST    0x4
#define DARWIN_RTF_STATIC  0x800

#define DARWIN_RTA_DST     0x1
#define DARWIN_RTA_GATEWAY 0x2
#define DARWIN_RTA_NETMASK 0x4

/* ── fixture builder ──────────────────────────────────────────────── */

struct rd_dump {
    uint8_t bytes[1024];
    size_t  len;
};

static void rd_put(struct rd_dump *d, const void *src, size_t n)
{
    if (d->len + n > sizeof d->bytes) { d->len = sizeof d->bytes + 1; return; }
    memcpy(d->bytes + d->len, src, n);
    d->len += n;
}

/* Start a message; returns its offset so rd_msg_end() can patch rtm_msglen. */
static size_t rd_msg_begin(struct rd_dump *d, uint8_t version, int32_t flags,
                           int32_t addrs)
{
    struct darwin_rt_msghdr h;
    memset(&h, 0, sizeof h);
    h.rtm_version = version;
    h.rtm_type = DARWIN_RTM_GET;
    h.rtm_flags = flags;
    h.rtm_addrs = addrs;
    size_t at = d->len;
    rd_put(d, &h, sizeof h);
    return at;
}

static void rd_msg_end(struct rd_dump *d, size_t at)
{
    uint16_t msglen = (uint16_t)(d->len - at);
    memcpy(d->bytes + at, &msglen, sizeof msglen);
}

/* Append a BSD sockaddr, truncated to sa_len and padded to a 4-byte
 * boundary — exactly what the kernel emits. sa_len 0 still consumes 4. */
static void rd_put_sa(struct rd_dump *d, uint8_t sa_len, uint8_t family,
                      const uint8_t addr[4])
{
    struct darwin_sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_len = sa_len;
    sa.sin_family = family;
    if (addr) memcpy(sa.sin_addr, addr, 4);
    size_t stride = sa_len > 0u ? (((size_t)sa_len - 1u) | 3u) + 1u : 4u;
    if (stride > sizeof sa) stride = sizeof sa;
    rd_put(d, &sa, stride);
}

static const uint8_t RD_ZERO[4] = {0, 0, 0, 0};

/* The canonical shape: one up, gatewayed, non-host route whose destination
 * is the wildcard and whose next hop is a full AF_INET sockaddr. */
static void rd_default_route(struct rd_dump *d, const uint8_t gw[4])
{
    size_t at = rd_msg_begin(d, DARWIN_RTM_VERSION,
                             DARWIN_RTF_UP | DARWIN_RTF_GATEWAY |
                                 DARWIN_RTF_STATIC,
                             DARWIN_RTA_DST | DARWIN_RTA_GATEWAY |
                                 DARWIN_RTA_NETMASK);
    rd_put_sa(d, 16, DARWIN_AF_INET, RD_ZERO);
    rd_put_sa(d, 16, DARWIN_AF_INET, gw);
    rd_put_sa(d, 0, 0, NULL); /* the /0 netmask: a zero-length sockaddr */
    rd_msg_end(d, at);
}

static struct nat_route_dump_abi rd_abi(void)
{
    return (struct nat_route_dump_abi){
        .header_size = sizeof(struct darwin_rt_msghdr),
        .version = DARWIN_RTM_VERSION,
        .af_inet = DARWIN_AF_INET,
    };
}

/* ── tests ────────────────────────────────────────────────────────── */

int test_nat_route_dump(void)
{
    printf("\n=== nat route-dump parser tests ===\n");
    int failures = 0;
    struct nat_route_dump_abi abi = rd_abi();
    uint8_t gw[4];

    /* ── the byte-order contract. 192.168.1.254 must come back as
     * {192,168,1,254}, NOT byte-swapped. This is the check that fails if
     * anyone "fixes" the gateway read with an ntohl(). ─────────────── */
    {
        static const uint8_t want[4] = {192, 168, 1, 254};
        struct rd_dump d = {.len = 0};
        rd_default_route(&d, want);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("default route found, gateway in network byte order",
                 nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     memcmp(gw, want, 4) == 0);
    }

    /* An asymmetric address catches a swap that a palindrome would hide. */
    {
        static const uint8_t want[4] = {10, 0, 0, 1};
        struct rd_dump d = {.len = 0};
        rd_default_route(&d, want);
        memset(gw, 0xAA, sizeof gw);
        bool ok = nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw);
        RD_CHECK("10.0.0.1 is not returned as 1.0.0.10",
                 ok && gw[0] == 10 && gw[1] == 0 && gw[2] == 0 && gw[3] == 1);
    }

    /* ── the destination must be the wildcard ─────────────────────── */
    {
        static const uint8_t nexthop[4] = {192, 168, 1, 1};
        static const uint8_t dst[4] = {10, 20, 30, 0};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, dst);
        rd_put_sa(&d, 16, DARWIN_AF_INET, nexthop);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a non-default destination is not mistaken for the default",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* A zero-length destination sockaddr IS the wildcard — the kernel
     * truncates trailing zero bytes off wildcard sockaddrs. */
    {
        static const uint8_t nexthop[4] = {172, 16, 0, 1};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 0, 0, NULL);
        rd_put_sa(&d, 16, DARWIN_AF_INET, nexthop);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("zero-length destination sockaddr reads as the wildcard",
                 nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     memcmp(gw, nexthop, 4) == 0);
    }

    /* A truncated (odd sa_len) wildcard destination pads to the next
     * 4-byte boundary; the gateway that follows must still be located. */
    {
        static const uint8_t nexthop[4] = {192, 168, 7, 9};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 5, DARWIN_AF_INET, RD_ZERO); /* pads 5 -> 8 */
        rd_put_sa(&d, 16, DARWIN_AF_INET, nexthop);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("sockaddr padding is honoured (sa_len 5 consumes 8)",
                 nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     memcmp(gw, nexthop, 4) == 0);
    }

    /* ── flag filtering ───────────────────────────────────────────── */
    {
        struct {
            const char *name;
            int32_t flags;
        } cases[] = {
            {"a route without RTF_UP is skipped", DARWIN_RTF_GATEWAY},
            {"a directly-attached route (no RTF_GATEWAY) is skipped",
             DARWIN_RTF_UP},
            {"an RTF_HOST route is skipped",
             DARWIN_RTF_UP | DARWIN_RTF_GATEWAY | DARWIN_RTF_HOST},
        };
        static const uint8_t nexthop[4] = {192, 168, 1, 1};
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            struct rd_dump d = {.len = 0};
            size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION, cases[i].flags,
                                     DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
            rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
            rd_put_sa(&d, 16, DARWIN_AF_INET, nexthop);
            rd_msg_end(&d, at);
            memset(gw, 0xAA, sizeof gw);
            RD_CHECK(cases[i].name,
                     !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi,
                                                          gw) &&
                         gw[0] == 0xAA);
        }
    }

    /* A message that does not advertise RTA_GATEWAY has no next hop. */
    {
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("RTA_GATEWAY absent from rtm_addrs is skipped",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw));
    }

    /* ── fail closed: never invent a gateway ──────────────────────── */
    {
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO); /* 0.0.0.0 next hop */
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a 0.0.0.0 gateway is refused, not returned as success",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* An AF_LINK next hop is a directly attached route, not a gateway. */
    {
        static const uint8_t bytes[4] = {1, 2, 3, 4};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_put_sa(&d, 16, DARWIN_AF_LINK, bytes);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("an AF_LINK next hop is not read as an IPv4 gateway",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* A gateway sockaddr too short to hold sin_addr must be refused, NOT
     * read past. A NETMASK sockaddr follows it, so bytes 4..7 of a
     * 4-byte gateway sockaddr are the netmask's own header — a parser
     * that skipped the length check would hand back "16.2.0.0". */
    {
        static const uint8_t mask[4] = {255, 255, 255, 0};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY |
                                     DARWIN_RTA_NETMASK);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_put_sa(&d, 4, DARWIN_AF_INET, RD_ZERO); /* no sin_addr bytes */
        rd_put_sa(&d, 16, DARWIN_AF_INET, mask);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a truncated gateway sockaddr is refused, not read past",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* ── multi-message walking ────────────────────────────────────── */
    {
        static const uint8_t host_dst[4] = {10, 1, 1, 1};
        static const uint8_t nexthop[4] = {192, 168, 50, 254};
        static const uint8_t other[4] = {10, 1, 1, 2};
        struct rd_dump d = {.len = 0};
        /* two non-matching messages first, then the real default route */
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, host_dst);
        rd_put_sa(&d, 16, DARWIN_AF_INET, other);
        rd_msg_end(&d, at);
        at = rd_msg_begin(&d, DARWIN_RTM_VERSION, DARWIN_RTF_UP,
                          DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_put_sa(&d, 16, DARWIN_AF_LINK, other);
        rd_msg_end(&d, at);
        rd_default_route(&d, nexthop);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("the default route is found behind two non-matching messages",
                 nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     memcmp(gw, nexthop, 4) == 0);
    }

    /* A message whose rtm_version we do not understand is skipped, not
     * parsed with offsets that may no longer apply. */
    {
        static const uint8_t nexthop[4] = {192, 168, 99, 1};
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION + 1,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_put_sa(&d, 16, DARWIN_AF_INET, nexthop);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("an unknown rtm_version is skipped",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw));

        /* ...but a later message of the known version is still reached. */
        rd_default_route(&d, nexthop);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a known-version message after an unknown one is still found",
                 nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     memcmp(gw, nexthop, 4) == 0);
    }

    /* ── malformed images are refused, never resynchronized ───────── */
    {
        static const uint8_t nexthop[4] = {192, 168, 1, 1};
        struct rd_dump d = {.len = 0};
        rd_default_route(&d, nexthop);
        uint16_t bad = (uint16_t)(d.len + 8u); /* claims past the buffer */
        memcpy(d.bytes, &bad, sizeof bad);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a message claiming more bytes than remain is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw));

        bad = 4; /* shorter than the header itself */
        memcpy(d.bytes, &bad, sizeof bad);
        RD_CHECK("a message shorter than rt_msghdr is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw));
    }

    /* A self-consistent message (rtm_msglen matches the bytes present)
     * whose gateway sockaddr declares sa_len 16 but is only half there:
     * the walker must refuse it, not read the 8 bytes that follow the
     * message. */
    {
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        uint8_t half[8] = {16, DARWIN_AF_INET, 0, 0, 192, 168, 1, 1};
        rd_put(&d, half, sizeof half);
        rd_msg_end(&d, at);
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a gateway sockaddr overrunning its message is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* rtm_addrs promises a gateway sockaddr that was never appended. */
    {
        struct rd_dump d = {.len = 0};
        size_t at = rd_msg_begin(&d, DARWIN_RTM_VERSION,
                                 DARWIN_RTF_UP | DARWIN_RTF_GATEWAY,
                                 DARWIN_RTA_DST | DARWIN_RTA_GATEWAY);
        rd_put_sa(&d, 16, DARWIN_AF_INET, RD_ZERO);
        rd_msg_end(&d, at); /* area holds the destination only */
        memset(gw, 0xAA, sizeof gw);
        RD_CHECK("a promised-but-absent gateway sockaddr is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi, gw) &&
                     gw[0] == 0xAA);
    }

    /* ── argument and ABI guards ──────────────────────────────────── */
    {
        static const uint8_t nexthop[4] = {192, 168, 1, 1};
        struct rd_dump d = {.len = 0};
        rd_default_route(&d, nexthop);

        RD_CHECK("NULL buffer is refused",
                 !nat_route_dump_find_default_gateway(NULL, d.len, &abi, gw));
        RD_CHECK("NULL abi is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, NULL, gw));
        RD_CHECK("NULL output is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &abi,
                                                      NULL));
        RD_CHECK("an empty dump reports no default route",
                 !nat_route_dump_find_default_gateway(d.bytes, 0, &abi, gw));

        struct nat_route_dump_abi tiny = abi;
        tiny.header_size = 15; /* below the 16-byte prefix we read */
        RD_CHECK("a header size below the parsed prefix is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &tiny,
                                                      gw));

        struct nat_route_dump_abi wide = abi;
        wide.af_inet = 0x1234;
        RD_CHECK("an out-of-range address family is refused",
                 !nat_route_dump_find_default_gateway(d.bytes, d.len, &wide,
                                                      gw));
    }

    return failures;
}
