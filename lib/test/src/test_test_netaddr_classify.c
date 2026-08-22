/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic unit tests for the pure address-classification predicates in
 * lib/net/src/netaddr.c (RFC-special-use detection, routability, the
 * per-IP-inbound-cap exemption class, address grouping for peer-diversity
 * bucketing, and the two to-string formatters).
 * Every predicate here is a pure function of a `struct net_addr` /
 * `struct net_service` value — no network, no clock, no live DB, no
 * allocation. Fixtures are built in-line with net_addr_init() +
 * net_addr_set_ipv4() / raw ip[16] byte arrays, matching the byte layout
 * net_addr_get_byte(a, n) exposes (n=0 is the LAST byte of ip[], i.e.
 * a->ip[15 - n]).
 *
 * Uses a local CHECK macro (same technique as
 * test_validation_pack_conditions.c's VPC_CHECK) rather than the
 * TEST()/ASSERT() pair, because many independent one-line checks are
 * exercised per function and ASSERT's hard-coded `goto _test_next` label
 * only tolerates a single TEST() block per function. */

#include "test/test_core.h"

#include "net/netaddr.h"
#include "net/onion_v3_address.h"

#include <string.h>

#define NC_CHECK(name, expr) do {                              \
    printf("netaddr_classify: %s... ", (name));                \
    if (expr) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

/* ── fixture helpers ─────────────────────────────────────────────── */

static void addr_ipv4(struct net_addr *a, unsigned char b0, unsigned char b1,
                       unsigned char b2, unsigned char b3)
{
    net_addr_init(a);
    unsigned char ip4[4] = { b0, b1, b2, b3 };
    net_addr_set_ipv4(a, ip4);
}

static void addr_ipv6(struct net_addr *a, const unsigned char ip[16])
{
    net_addr_init(a);
    memcpy(a->ip, ip, 16);
}

static void addr_tor(struct net_addr *a)
{
    net_addr_init(a);
    a->has_torv3 = true;
    memset(a->torv3, 0xAB, TORV3_ADDR_SIZE);   /* nonzero: renderable */
}

/* ── net_addr_is_rfc1918 (10/8, 172.16/12, 192.168/16) ───────────── */

static int test_rfc1918(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 10, 1, 2, 3);
    NC_CHECK("rfc1918: 10.x.x.x matches", net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 192, 168, 5, 6);
    NC_CHECK("rfc1918: 192.168.x.x matches", net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 172, 16, 0, 1);
    NC_CHECK("rfc1918: 172.16.x.x (lower bound) matches",
             net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 172, 31, 255, 254);
    NC_CHECK("rfc1918: 172.31.x.x (upper bound) matches",
             net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 172, 15, 0, 1);
    NC_CHECK("rfc1918: 172.15.x.x (just below range) does not match",
             !net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 172, 32, 0, 1);
    NC_CHECK("rfc1918: 172.32.x.x (just above range) does not match",
             !net_addr_is_rfc1918(&a));

    addr_ipv4(&a, 8, 8, 8, 8);
    NC_CHECK("rfc1918: public IPv4 does not match", !net_addr_is_rfc1918(&a));

    {
        unsigned char ip[16] = {0};
        ip[0] = 0x20; ip[1] = 0x01;
        addr_ipv6(&a, ip);
        NC_CHECK("rfc1918: non-IPv4 (IPv6) never matches",
                 !net_addr_is_rfc1918(&a));
    }
    return failures;
}

/* ── net_addr_is_rfc2544 (198.18/15 benchmarking) ────────────────── */

static int test_rfc2544(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 198, 18, 1, 1);
    NC_CHECK("rfc2544: 198.18.x.x matches", net_addr_is_rfc2544(&a));

    addr_ipv4(&a, 198, 19, 1, 1);
    NC_CHECK("rfc2544: 198.19.x.x matches", net_addr_is_rfc2544(&a));

    addr_ipv4(&a, 198, 17, 1, 1);
    NC_CHECK("rfc2544: 198.17.x.x (below range) does not match",
             !net_addr_is_rfc2544(&a));

    addr_ipv4(&a, 198, 20, 1, 1);
    NC_CHECK("rfc2544: 198.20.x.x (above range) does not match",
             !net_addr_is_rfc2544(&a));
    return failures;
}

/* ── net_addr_is_rfc3927 (169.254/16 link-local) ─────────────────── */

static int test_rfc3927(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 169, 254, 7, 8);
    NC_CHECK("rfc3927: 169.254.x.x matches", net_addr_is_rfc3927(&a));

    addr_ipv4(&a, 169, 253, 7, 8);
    NC_CHECK("rfc3927: 169.253.x.x does not match", !net_addr_is_rfc3927(&a));

    addr_ipv4(&a, 169, 255, 7, 8);
    NC_CHECK("rfc3927: 169.255.x.x does not match", !net_addr_is_rfc3927(&a));
    return failures;
}

/* ── net_addr_is_rfc6598 (100.64/10 carrier-grade NAT) ───────────── */

static int test_rfc6598(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 100, 64, 0, 1);
    NC_CHECK("rfc6598: 100.64.x.x (lower bound) matches",
             net_addr_is_rfc6598(&a));

    addr_ipv4(&a, 100, 127, 255, 254);
    NC_CHECK("rfc6598: 100.127.x.x (upper bound) matches",
             net_addr_is_rfc6598(&a));

    addr_ipv4(&a, 100, 63, 0, 1);
    NC_CHECK("rfc6598: 100.63.x.x (below range) does not match",
             !net_addr_is_rfc6598(&a));

    addr_ipv4(&a, 100, 128, 0, 1);
    NC_CHECK("rfc6598: 100.128.x.x (above range) does not match",
             !net_addr_is_rfc6598(&a));
    return failures;
}

/* ── net_addr_is_rfc5737 (TEST-NET-1/2/3 documentation ranges) ───── */

static int test_rfc5737(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 192, 0, 2, 55);
    NC_CHECK("rfc5737: 192.0.2.x (TEST-NET-1) matches",
             net_addr_is_rfc5737(&a));

    addr_ipv4(&a, 198, 51, 100, 55);
    NC_CHECK("rfc5737: 198.51.100.x (TEST-NET-2) matches",
             net_addr_is_rfc5737(&a));

    addr_ipv4(&a, 203, 0, 113, 55);
    NC_CHECK("rfc5737: 203.0.113.x (TEST-NET-3) matches",
             net_addr_is_rfc5737(&a));

    addr_ipv4(&a, 192, 0, 3, 55);
    NC_CHECK("rfc5737: 192.0.3.x (neighbor of TEST-NET-1) does not match",
             !net_addr_is_rfc5737(&a));

    addr_ipv4(&a, 198, 51, 99, 55);
    NC_CHECK("rfc5737: 198.51.99.x (neighbor of TEST-NET-2) does not match",
             !net_addr_is_rfc5737(&a));
    return failures;
}

/* ── net_addr_is_rfc3964 (2002::/16 6to4) ────────────────────────── */

static int test_rfc3964(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x02;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc3964: 2002::/16 matches", net_addr_is_rfc3964(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x03;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc3964: 2003::/16 (off-by-one second byte) does not match",
             !net_addr_is_rfc3964(&a));
    return failures;
}

/* ── net_addr_is_rfc6052 (64:ff9b::/96 NAT64 well-known prefix) ──── */

static int test_rfc6052(void)
{
    int failures = 0;
    struct net_addr a;

    unsigned char ip_ok[16] =
        {0, 0x64, 0xFF, 0x9B, 0,0,0,0,0,0,0,0, 8,8,8,8};
    addr_ipv6(&a, ip_ok);
    NC_CHECK("rfc6052: 64:ff9b::/96 matches", net_addr_is_rfc6052(&a));

    unsigned char ip_bad[16] =
        {0, 0x65, 0xFF, 0x9B, 0,0,0,0,0,0,0,0, 8,8,8,8};
    addr_ipv6(&a, ip_bad);
    NC_CHECK("rfc6052: off-by-one prefix byte does not match",
             !net_addr_is_rfc6052(&a));
    return failures;
}

/* ── net_addr_is_rfc4380 (2001:0000::/32 Teredo) ─────────────────── */

static int test_rfc4380(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x01;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4380: 2001:0000::/32 matches", net_addr_is_rfc4380(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x01; ip[3] = 0x01;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4380: third word nonzero does not match",
             !net_addr_is_rfc4380(&a));
    return failures;
}

/* ── net_addr_is_rfc4862 (fe80::/64 link-local) ──────────────────── */

static int test_rfc4862(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFE; ip[1] = 0x80;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4862: fe80::/64 matches", net_addr_is_rfc4862(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFE; ip[1] = 0x80; ip[3] = 0x01;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4862: nonzero byte within the required all-zero prefix "
             "breaks the exact match", !net_addr_is_rfc4862(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFE; ip[1] = 0x81;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4862: fe81:: does not match", !net_addr_is_rfc4862(&a));
    return failures;
}

/* ── net_addr_is_rfc4193 (fc00::/7 ULA) ──────────────────────────── */

static int test_rfc4193(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFC;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4193: fc00:: matches", net_addr_is_rfc4193(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFD;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4193: fd00:: matches", net_addr_is_rfc4193(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFB;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4193: fb00:: (just below /7) does not match",
             !net_addr_is_rfc4193(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0xFE;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4193: fe00:: (just above /7) does not match",
             !net_addr_is_rfc4193(&a));
    return failures;
}

/* ── net_addr_is_rfc6145 (::ffff:0:0/96 translated) ───────────────── */

static int test_rfc6145(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[8] = 0xFF; ip[9] = 0xFF;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc6145: ::ffff:0:0/96 matches", net_addr_is_rfc6145(&a));

    memset(ip, 0, sizeof(ip)); ip[8] = 0xFF; ip[9] = 0xFF; ip[10] = 0x01;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc6145: trailing byte set breaks the exact 12-byte match",
             !net_addr_is_rfc6145(&a));
    return failures;
}

/* ── net_addr_is_rfc4843 (2001:10::/28 ORCHID) ───────────────────── */

static int test_rfc4843(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char ip[16];

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x01; ip[3] = 0x10;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4843: 2001:10::/28 matches", net_addr_is_rfc4843(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x01; ip[3] = 0x1F;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4843: low nibble within the block still matches "
             "(masked with 0xF0)", net_addr_is_rfc4843(&a));

    memset(ip, 0, sizeof(ip)); ip[0] = 0x20; ip[1] = 0x01; ip[3] = 0x20;
    addr_ipv6(&a, ip);
    NC_CHECK("rfc4843: 2001:20::/28 (next /28 block) does not match",
             !net_addr_is_rfc4843(&a));
    return failures;
}

/* ── net_addr_is_local (loopback: 127/8, 0/8 IPv4; ::1 IPv6) ─────── */

static int test_is_local(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 127, 0, 0, 1);
    NC_CHECK("is_local: 127.x.x.x matches", net_addr_is_local(&a));

    addr_ipv4(&a, 0, 1, 2, 3);
    NC_CHECK("is_local: 0.x.x.x matches", net_addr_is_local(&a));

    addr_ipv4(&a, 1, 2, 3, 4);
    NC_CHECK("is_local: public IPv4 does not match", !net_addr_is_local(&a));

    {
        unsigned char ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        addr_ipv6(&a, ip);
        NC_CHECK("is_local: ::1 matches", net_addr_is_local(&a));
    }
    {
        unsigned char ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
        addr_ipv6(&a, ip);
        NC_CHECK("is_local: ::2 does not match", !net_addr_is_local(&a));
    }
    return failures;
}

/* ── net_addr_is_operator_local ───────────────────────────────────
 * operator_local := !is_tor && (IPv4 127.0.0.0/8 || IPv6 ::1). LOOPBACK
 * ONLY. It is the only address class that gets a RAISED per-source
 * inbound admission cap in accept_connection(), so this test is the
 * boundary of that relaxation: every "does not match" line below is an
 * address class that still gets the ordinary cap of 3. Widening this
 * predicate widens a sybil-defence hole — a failure here is a security
 * signal, not a style nit.
 *
 * The RFC1918 lines are the F2 regression. RFC1918 was briefly inside
 * this predicate; it is not, and must not be. On any hosted machine with
 * provider private networking the neighbouring tenants are RFC1918
 * sources, so including 10/8, 172.16/12 and 192.168/16 hands a whole
 * shared segment a relaxed cap. The problem this predicate exists for is
 * several nodes on ONE host, and every one of those arrives on 127.0.0.1.
 *
 * 0.0.0.0/8 is excluded too: net_addr_is_local() answers true for it, but
 * it is a spoofable source address, not a same-host peer. */

static int test_is_operator_local(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 127, 0, 0, 1);
    NC_CHECK("operator_local: 127.0.0.1 matches",
             net_addr_is_operator_local(&a));

    addr_ipv4(&a, 127, 3, 2, 1);
    NC_CHECK("operator_local: 127/8 elsewhere matches",
             net_addr_is_operator_local(&a));

    {
        unsigned char ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        addr_ipv6(&a, ip);
        NC_CHECK("operator_local: ::1 matches",
                 net_addr_is_operator_local(&a));
    }

    /* Everything below stays SUBJECT to the ordinary per-IP cap. */
    addr_ipv4(&a, 10, 4, 5, 6);
    NC_CHECK("operator_local: 10/8 does NOT match (F2)",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 192, 168, 1, 7);
    NC_CHECK("operator_local: 192.168/16 does NOT match (F2)",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 172, 16, 0, 1);
    NC_CHECK("operator_local: 172.16/12 low edge does NOT match (F2)",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 172, 31, 255, 254);
    NC_CHECK("operator_local: 172.31 high edge does NOT match (F2)",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 0, 1, 2, 3);
    NC_CHECK("operator_local: 0.0.0.0/8 does NOT match (F2)",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 8, 8, 8, 8);
    NC_CHECK("operator_local: public IPv4 does not match",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 172, 15, 0, 1);
    NC_CHECK("operator_local: 172.15 (just below RFC1918) does not match",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 172, 32, 0, 1);
    NC_CHECK("operator_local: 172.32 (just above RFC1918) does not match",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 169, 254, 1, 1);
    NC_CHECK("operator_local: link-local does not match",
             !net_addr_is_operator_local(&a));

    addr_ipv4(&a, 100, 64, 0, 1);
    NC_CHECK("operator_local: CGNAT does not match",
             !net_addr_is_operator_local(&a));

    addr_tor(&a);
    NC_CHECK("operator_local: tor does not match",
             !net_addr_is_operator_local(&a));

    NC_CHECK("operator_local: NULL denies the exemption",
             !net_addr_is_operator_local(NULL));

    return failures;
}

/* ── net_addr_is_routable ─────────────────────────────────────────
 * routable := is_valid && !(rfc1918 || rfc2544 || rfc3927 || rfc4862 ||
 *             rfc6598 || rfc5737 || (rfc4193 && !is_tor) || rfc4843 ||
 *             is_local) */

static int test_is_routable(void)
{
    int failures = 0;
    struct net_addr a;

    addr_ipv4(&a, 8, 8, 8, 8);
    NC_CHECK("is_routable: public IPv4 is routable", net_addr_is_routable(&a));

    addr_ipv4(&a, 10, 0, 0, 1);
    NC_CHECK("is_routable: rfc1918 private range is not routable",
             !net_addr_is_routable(&a));

    addr_ipv4(&a, 127, 0, 0, 1);
    NC_CHECK("is_routable: loopback is not routable",
             !net_addr_is_routable(&a));

    net_addr_init(&a);
    NC_CHECK("is_routable: all-zero (invalid) address is not routable",
             !net_addr_is_routable(&a));

    {
        unsigned char ip[16] = {0}; ip[0] = 0xFC;
        addr_ipv6(&a, ip);
        NC_CHECK("is_routable: fc00::/7 ULA over plain IPv6 is not routable",
                 !net_addr_is_routable(&a));
    }
    {
        addr_tor(&a);
        a.ip[0] = 0xFC;
        NC_CHECK("is_routable: fc00::/7 carried over a .onion address IS "
                 "routable — the ULA exclusion is waived for Tor",
                 net_addr_is_routable(&a));
    }
    {
        addr_tor(&a);
        NC_CHECK("is_routable: a plain .onion address (no ULA bytes) "
                 "is routable", net_addr_is_routable(&a));
    }
    return failures;
}

/* ── net_addr_get_group (peer-diversity bucketing) ───────────────── */

static int test_get_group(void)
{
    int failures = 0;
    struct net_addr a;
    unsigned char out[NET_ADDR_GROUP_MAX];
    size_t n;

    addr_ipv4(&a, 127, 0, 0, 1);
    n = net_addr_get_group(&a, out, sizeof(out));
    NC_CHECK("get_group: local address groups as class 255, "
             "zero-length body", n == 1 && out[0] == 255);

    addr_ipv4(&a, 10, 1, 2, 3);
    n = net_addr_get_group(&a, out, sizeof(out));
    NC_CHECK("get_group: unroutable (rfc1918) groups as class "
             "NET_UNROUTABLE",
             n == 1 && out[0] == (unsigned char)NET_UNROUTABLE);

    addr_ipv4(&a, 8, 8, 8, 8);
    n = net_addr_get_group(&a, out, sizeof(out));
    NC_CHECK("get_group: routable IPv4 groups by class + first two octets",
             n == 3 && out[0] == (unsigned char)NET_IPV4 &&
             out[1] == 8 && out[2] == 8);

    {
        unsigned char ip[16] = {0};
        ip[0] = 0x20; ip[1] = 0x01;   /* 2001:0000::/32 (Teredo) */
        ip[12] = 0x01; ip[13] = 0x02; /* client's obscured IPv4 octets */
        addr_ipv6(&a, ip);
        n = net_addr_get_group(&a, out, sizeof(out));
        NC_CHECK("get_group: Teredo groups via the XOR'd early-return "
                 "path, independent of the generic byte walk",
                 n == 3 && out[0] == (unsigned char)NET_IPV4 &&
                 out[1] == (unsigned char)(0x01 ^ 0xFF) &&
                 out[2] == (unsigned char)(0x02 ^ 0xFF));
    }
    {
        unsigned char ip[16] = {0};
        ip[0] = 0x20; ip[1] = 0x01;
        addr_ipv6(&a, ip);
        unsigned char small[2];
        n = net_addr_get_group(&a, small, sizeof(small));
        NC_CHECK("get_group: Teredo early-return refuses to write with "
                 "too small an output buffer (out_size < 3)", n == 0);
    }
    {
        addr_tor(&a);
        a.ip[6] = 0xAB;
        n = net_addr_get_group(&a, out, sizeof(out));
        NC_CHECK("get_group: a .onion address groups under NET_ONION "
                 "using torv3-derived bytes (masked with the low nibble)",
                 n == 2 && out[0] == (unsigned char)NET_ONION &&
                 out[1] == (unsigned char)(0xAB | 0x0F));
    }
    {
        unsigned char ip[16] =
            {0x26,0x06,0x47,0x00,0,0,0,0,0,0,0,0,0,0,0,1};
        addr_ipv6(&a, ip);
        n = net_addr_get_group(&a, out, sizeof(out));
        NC_CHECK("get_group: a generic public IPv6 address groups by "
                 "class + the first four octets (/32 bucket)",
                 n == 5 && out[0] == (unsigned char)NET_IPV6 &&
                 out[1] == 0x26 && out[2] == 0x06 &&
                 out[3] == 0x47 && out[4] == 0x00);
    }
    {
        addr_ipv4(&a, 127, 0, 0, 1);
        unsigned char sentinel[1] = { 0x99 };
        n = net_addr_get_group(&a, sentinel, 0);
        NC_CHECK("get_group: a zero-length output buffer writes nothing "
                 "and returns 0, even for the simplest (local) class",
                 n == 0 && sentinel[0] == 0x99);
    }
    return failures;
}

/* ── net_addr_to_string / net_service_to_string ──────────────────── */

static int test_to_string(void)
{
    int failures = 0;
    struct net_addr a;
    char buf[64];
    int rc;

    addr_ipv4(&a, 192, 168, 1, 42);
    rc = net_addr_to_string(&a, buf, sizeof(buf));
    NC_CHECK("to_string: IPv4 renders dotted-quad",
             rc > 0 && strcmp(buf, "192.168.1.42") == 0);

    {
        unsigned char ip[16] =
            {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
        addr_ipv6(&a, ip);
        rc = net_addr_to_string(&a, buf, sizeof(buf));
        NC_CHECK("to_string: IPv6 renders eight lowercase-hex groups",
                 rc > 0 && strcmp(buf,
                     "2001:0db8:0000:0000:0000:0000:0000:0001") == 0);
    }

    addr_tor(&a);
    rc = net_addr_to_string(&a, buf, sizeof(buf));
    {
        char expect[ONION_V3_ADDRESS_LEN + 1];
        bool rendered = onion_v3_address_from_pubkey(a.torv3, expect);
        NC_CHECK("to_string: torv3 address renders the real v3 hostname",
                 rendered && rc > 0 && strcmp(buf, expect) == 0);
    }

    {
        /* The degenerate all-zero key cannot render a hostname — the
         * fixed placeholder remains as the defensive fallback. */
        net_addr_init(&a);
        a.has_torv3 = true;
        rc = net_addr_to_string(&a, buf, sizeof(buf));
        NC_CHECK("to_string: all-zero torv3 key falls back to placeholder",
                 rc > 0 && strcmp(buf, "[torv3]") == 0);
    }

    {
        addr_ipv4(&a, 192, 168, 1, 42);
        char small[6];
        rc = net_addr_to_string(&a, small, sizeof(small));
        NC_CHECK("to_string: undersized buffer truncates but reports the "
                 "full would-be length (snprintf contract)",
                 rc == (int)strlen("192.168.1.42") &&
                 small[sizeof(small) - 1] == '\0');
    }
    return failures;
}

static int test_service_to_string(void)
{
    int failures = 0;
    struct net_service s;
    char buf[64];
    int rc;

    net_service_init(&s);
    addr_ipv4(&s.addr, 10, 0, 0, 5);
    s.port = 8033;
    rc = net_service_to_string(&s, buf, sizeof(buf));
    NC_CHECK("service_to_string: IPv4 renders host:port",
             rc > 0 && strcmp(buf, "10.0.0.5:8033") == 0);

    {
        net_service_init(&s);
        unsigned char ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        addr_ipv6(&s.addr, ip);
        s.port = 18232;
        rc = net_service_to_string(&s, buf, sizeof(buf));
        NC_CHECK("service_to_string: plain IPv6 renders bracketed "
                 "[host]:port",
                 rc > 0 && strcmp(buf,
                     "[0000:0000:0000:0000:0000:0000:0000:0001]:18232") == 0);
    }

    {
        net_service_init(&s);
        addr_tor(&s.addr);
        s.port = 8033;
        char svcbuf[NET_SERVICE_STR_MAX + 1];
        rc = net_service_to_string(&s, svcbuf, sizeof(svcbuf));
        char expect[ONION_V3_ADDRESS_LEN + 1];
        bool rendered = onion_v3_address_from_pubkey(s.addr.torv3, expect);
        char expect_svc[NET_SERVICE_STR_MAX + 1];
        snprintf(expect_svc, sizeof(expect_svc), "%s:8033", expect);
        NC_CHECK("service_to_string: torv3 renders hostname:port, "
                 "NOT bracketed",
                 rendered && rc > 0 && strcmp(svcbuf, expect_svc) == 0);
    }
    return failures;
}

int test_netaddr_classify(void);
int test_netaddr_classify(void)
{
    int failures = 0;
    failures += test_rfc1918();
    failures += test_rfc2544();
    failures += test_rfc3927();
    failures += test_rfc6598();
    failures += test_rfc5737();
    failures += test_rfc3964();
    failures += test_rfc6052();
    failures += test_rfc4380();
    failures += test_rfc4862();
    failures += test_rfc4193();
    failures += test_rfc6145();
    failures += test_rfc4843();
    failures += test_is_local();
    failures += test_is_operator_local();
    failures += test_is_routable();
    failures += test_get_group();
    failures += test_to_string();
    failures += test_service_to_string();
    printf("\n=== netaddr_classify: %d failure(s) ===\n", failures);
    return failures;
}
