/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused unit tests for split_host_port() (core/modules/net/src/netbase.c),
 * a pure string state machine, and for net_name_is_onion(), which this binary
 * links and must call.
 *
 * test_net.c covers only bare IPv4:port and bracketed [::1]:port; this file
 * pins bracket detection, multi-colon (bare IPv6) detection, the ParseInt32
 * port-range guard (including the exclusive 0x10000 fence) and the host_out
 * truncation contract.
 *
 * Contract of netbase.c:
 *
 *   1. Find the LAST ':' in the input (or none).
 *   2. If found:
 *        bracketed   = in[0]=='[' && colon[-1]==']'
 *        multi_colon = another ':' appears strictly before that last colon
 *        If colon is not the first character, AND (bracketed OR NOT
 *        multi_colon), ParseInt32 the suffix. Only when that succeeds AND
 *        0 < n < 0x10000 is *port_out written and `len` truncated to exclude
 *        ":port". Any other outcome leaves `len` and *port_out untouched.
 *   3. If (possibly truncated) len>=2 and the string starts with '[' and ends
 *      with ']', strip one bracket pair, but only if the stripped host (len-2
 *      bytes + NUL) fits host_size; otherwise host_out is left untouched (a
 *      no-op, not a truncation).
 *   4. Otherwise copy up to host_size-1 bytes, always NUL-terminated.
 *
 * Deterministic, no I/O, no global state. Table-driven plus pointer-arithmetic
 * edge cases. */

#include "test/test_core.h"

#include "net/netbase.h"

#include <stdio.h>
#include <string.h>

#define NB_CHECK(name, expr) do {                                   \
    printf("netbase_split_host_port: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                   \
    else { printf("FAIL\n"); failures++; }                          \
} while (0)

/* Sentinel used to detect "port_out was never written". */
#define PORT_SENTINEL (-12345)

struct sh_case {
    const char *name;
    const char *in;
    const char *want_host;
    int want_port;          /* PORT_SENTINEL means "must stay untouched" */
};

/* True when split_host_port left the host buffer holding exactly want_host
 * and the port variable holding exactly want_port (PORT_SENTINEL for
 * "never written"). Pure comparison; no logging, so callers stay in charge
 * of every printf. */
static bool split_result_matches(const char *got_host, const char *want_host,
                                 int got_port, int want_port)
{
    return strcmp(got_host, want_host) == 0 && got_port == want_port;
}

/* True when every byte of buf[0..len) still holds the 0x5A sentinel fill,
 * i.e. split_host_port left host_out completely untouched. */
static bool sentinel_fill_untouched(const char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != (char)0x5A)
            return false;
    }
    return true;
}

int test_netbase_split_host_port(void)
{
    printf("\n=== netbase split_host_port tests ===\n");
    int failures = 0;
    char host[128];
    int port;

    /* ── happy path: table-driven ─────────────────────────────────── */
    static const struct sh_case cases[] = {
        /* bare IPv4 + port (baseline the rest of the table diffs against). */
        { "ipv4 with port",            "192.168.1.1:9033",  "192.168.1.1", 9033 },
        /* bracketed IPv6 + port. */
        { "bracketed ipv6 with port",  "[::1]:9033",         "::1",         9033 },
        /* bracketed IPv6 with no port: brackets are still stripped. */
        { "bracketed ipv6 no port",    "[::1]",              "::1",         PORT_SENTINEL },
        /* bracketed IPv6 with a longer host and a high (but valid) port. */
        { "bracketed ipv6 full addr",  "[2001:db8::ff00:42:8329]:65535",
                                        "2001:db8::ff00:42:8329", 65535 },
        /* bare IPv6 with multiple colons and no port: the multi-colon guard
         * leaves the whole string as host. */
        { "bare ipv6 multi-colon no port", "2001:db8::1", "2001:db8::1", PORT_SENTINEL },
        /* bare IPv6 short form, still multi-colon, still no port. */
        { "bare ipv6 loopback bare",   "::1",                "::1",         PORT_SENTINEL },
        /* plain hostname + port. */
        { "hostname with port",        "example.com:8033",  "example.com", 8033 },
        /* plain hostname, no colon at all. */
        { "hostname no colon",          "example.com",       "example.com", PORT_SENTINEL },
        /* port at the exact lower bound of the accepted range (n>0). */
        { "port lower bound 1",         "host:1",            "host",        1 },
        /* port at the exact upper bound of the accepted range (n<0x10000). */
        { "port upper bound 65535",     "host:65535",         "host",        65535 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(host, 0xAA, sizeof(host));
        port = PORT_SENTINEL;
        split_host_port(cases[i].in, host, sizeof(host), &port);
        bool case_ok = split_result_matches(host, cases[i].want_host, port,
                                            cases[i].want_port);
        NB_CHECK(cases[i].name, case_ok);
        if (!case_ok)
            printf("    (got host=\"%s\" port=%d)\n", host, port);
    }

    /* ── adversarial: port value out of uint16 range ─────────────────
     * ParseInt32("99999") succeeds but `n < 0x10000` rejects it, so the whole
     * original string becomes the host. Pins "far past the top", not 65536. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:99999", host, sizeof(host), &port);
    NB_CHECK("port overflow (99999) falls through to whole-string host",
             split_result_matches(host, "host:99999", port, PORT_SENTINEL));

    /* Exclusive-upper fence, accepted side: 65535 is the last port for which
     * `n < 0x10000` holds; it is written and the host truncated. Sits next to
     * 65536 so the two sides of the fence are one pair. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:65535", host, sizeof(host), &port);
    NB_CHECK("port 65535 (0xFFFF) accepted, host truncated to exclude port",
             split_result_matches(host, "host", port, 65535));

    /* Exclusive-upper fence, rejected side: 65536 (0x10000) is refused by
     * `n < 0x10000` and would be accepted by `n <= 0x10000`; no other
     * near-bound input distinguishes them. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:65536", host, sizeof(host), &port);
    NB_CHECK("port 65536 (0x10000) rejected, whole string becomes host",
             split_result_matches(host, "host:65536", port, PORT_SENTINEL));

    /* The same exclusive bound on the bracketed path: 65536 accepted would
     * strip brackets and write port 65536 (host "::1"). */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("[::1]:65536", host, sizeof(host), &port);
    NB_CHECK("bracketed port 65536 rejected, no strip and no port write",
             split_result_matches(host, "[::1]:65536", port, PORT_SENTINEL));

    /* ── adversarial: port value == 0 is rejected (n>0 required) ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:0", host, sizeof(host), &port);
    NB_CHECK("port zero rejected, whole string becomes host",
             split_result_matches(host, "host:0", port, PORT_SENTINEL));

    /* ── adversarial: negative port digits parse but fail n>0 ──────── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:-5", host, sizeof(host), &port);
    NB_CHECK("negative port rejected, whole string becomes host",
             split_result_matches(host, "host:-5", port, PORT_SENTINEL));

    /* ── adversarial: non-numeric suffix after colon ──────────────── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:abc", host, sizeof(host), &port);
    NB_CHECK("non-numeric port suffix rejected, whole string becomes host",
             split_result_matches(host, "host:abc", port, PORT_SENTINEL));

    /* ── adversarial: leading colon must not be a port separator ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port(":1234", host, sizeof(host), &port);
    NB_CHECK("leading colon (colon == in) not treated as separator",
             split_result_matches(host, ":1234", port, PORT_SENTINEL));

    /* A leading colon on a tail with no other colon: multi_colon is false, so
     * the `colon != in` guard alone must suppress port parsing. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port(":9033", host, sizeof(host), &port);
    NB_CHECK("bare leading colon with digits stays whole-string host",
             split_result_matches(host, ":9033", port, PORT_SENTINEL));

    /* ── adversarial: in[0]=='[' but the character before the LAST colon is
     * not ']', so `bracketed` is false and the multi-colon guard suppresses
     * port parsing; "[::1" does not end with ']' either, so the whole string
     * is the host. ─────────────────────────────────────────────── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("[::1", host, sizeof(host), &port);
    NB_CHECK("unterminated bracket left completely as host, no port",
             split_result_matches(host, "[::1", port, PORT_SENTINEL));

    /* ── host_size truncation: a longer unbracketed host is truncated to
     * host_size-1 and NUL-terminated, never overflowing. ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    {
        char small[4]; /* room for "abc\0" only */
        memset(small, 0xAA, sizeof(small));
        split_host_port("abcdefgh", small, sizeof(small), &port);
        NB_CHECK("unbracketed host truncated to host_size-1 + NUL, no overflow",
                 strcmp(small, "abc") == 0);
    }

    /* Truncation also applies after a valid port was parsed off first. */
    {
        char small[4];
        memset(small, 0xAA, sizeof(small));
        int p = PORT_SENTINEL;
        split_host_port("abcdefgh:9033", small, sizeof(small), &p);
        NB_CHECK("port parsed first, then host still truncated safely",
                 split_result_matches(small, "abc", p, 9033));
    }

    /* Exact fit: host_size == strlen(host)+1 must not truncate. */
    {
        char exact[4]; /* "abc" is 3 chars + NUL == 4 */
        memset(exact, 0xAA, sizeof(exact));
        int p = PORT_SENTINEL;
        split_host_port("abc", exact, sizeof(exact), &p);
        NB_CHECK("host_size exactly len+1 copies host untruncated",
                 strcmp(exact, "abc") == 0);
    }

    /* One byte short of exact fit drops exactly one character. */
    {
        char short_by_one[3]; /* only room for "ab\0" */
        memset(short_by_one, 0xAA, sizeof(short_by_one));
        int p = PORT_SENTINEL;
        split_host_port("abc", short_by_one, sizeof(short_by_one), &p);
        NB_CHECK("host_size one short truncates by exactly one char",
                 strcmp(short_by_one, "ab") == 0);
    }

    /* host_size == 1: room only for the NUL; must not overflow. */
    {
        char tiny[1];
        tiny[0] = (char)0xAA;
        int p = PORT_SENTINEL;
        split_host_port("abcdefgh", tiny, sizeof(tiny), &p);
        NB_CHECK("host_size==1 yields empty string, no overflow",
                 tiny[0] == '\0');
    }

    /* ── bracketed host_out no-op when it doesn't fit ────────────────
     * The bracket-stripping branch is gated by `len - 2 < host_size`; when the
     * host does not fit, host_out is not touched at all (no copy, no NUL).
     * Pinned with a sentinel-filled buffer. */
    {
        char tiny_bracket[2]; /* "::1" (len-2=3) can't fit in 2 bytes */
        memset(tiny_bracket, 0x5A, sizeof(tiny_bracket));
        int p = PORT_SENTINEL;
        split_host_port("[::1]", tiny_bracket, sizeof(tiny_bracket), &p);
        NB_CHECK("bracketed host too big for host_size leaves host_out untouched",
                 sentinel_fill_untouched(tiny_bracket, sizeof(tiny_bracket)));
    }

    /* A bracketed host that fits exactly at the boundary must copy (the guard
     * is strict '<': len-2 == host_size does not fit, host_size-1 does). */
    {
        /* "[::1]" -> stripped host "::1" is 3 chars, needs host_size>=4. */
        char exact_bracket[4];
        memset(exact_bracket, 0xAA, sizeof(exact_bracket));
        int p = PORT_SENTINEL;
        split_host_port("[::1]", exact_bracket, sizeof(exact_bracket), &p);
        NB_CHECK("bracketed host exact-fit boundary copies correctly",
                 strcmp(exact_bracket, "::1") == 0);

        char one_short[3]; /* one byte short of the "::1\0" requirement */
        memset(one_short, 0x5A, sizeof(one_short));
        p = PORT_SENTINEL;
        split_host_port("[::1]", one_short, sizeof(one_short), &p);
        NB_CHECK("bracketed host one byte short of fit is a no-op (untouched)",
                 sentinel_fill_untouched(one_short, sizeof(one_short)));
    }

    /* ── round-trip: bracketed host with port and a small buffer: the port
     * parses from the untruncated original before len is shortened. ── */
    {
        char h[8];
        memset(h, 0xAA, sizeof(h));
        int p = PORT_SENTINEL;
        split_host_port("[::1]:443", h, sizeof(h), &p);
        NB_CHECK("bracketed host with port: both host and port correct",
                 split_result_matches(h, "::1", p, 443));
    }

    /* Empty suffix after the colon: ParseInt32("") fails, so a trailing colon
     * is not a port and stays in the host. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:", host, sizeof(host), &port);
    NB_CHECK("empty port suffix rejected, whole string becomes host",
             split_result_matches(host, "host:", port, PORT_SENTINEL));

    /* ── net_name_is_onion: suffix detection, not v3 validation ──────
     * True when the host part of "host[:port]" carries ".onion": NULL is
     * false; split_host_port first; strip at most one trailing '.'; require
     * len > 6; case-fold A-Z on the last 6 bytes. */

    /* Pointer guard: NULL is false, without dereferencing. */
    NB_CHECK("net_name_is_onion NULL is false",
             !net_name_is_onion(NULL));

    /* Empty string: len==0 <= 6, false; pins the length bound. */
    NB_CHECK("net_name_is_onion empty string is false",
             !net_name_is_onion(""));

    /* A non-onion name (suffix mismatch); example.com must never match. */
    NB_CHECK("net_name_is_onion example.com is false",
             !net_name_is_onion("example.com"));

    /* Onion-shaped name: a v3-length local part plus ".onion"; detection
     * needs no valid checksum. */
    NB_CHECK("net_name_is_onion v3-shaped name is true",
             net_name_is_onion(
                 "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq.onion"));

    /* Shortest name that can carry the suffix: len==7, the first length
     * `len <= 6` does not refuse. */
    NB_CHECK("net_name_is_onion x.onion (shortest true) is true",
             net_name_is_onion("x.onion"));

    /* Exact suffix with no local part: len==6, so false (`len <= 6`); differs
     * from the empty string (len==0) and x.onion (len==7). */
    NB_CHECK("net_name_is_onion exact suffix .onion is false",
             !net_name_is_onion(".onion"));

    /* split_host_port runs first, or "x.onion:9050" would fail the tail
     * compare against the port digits. */
    NB_CHECK("net_name_is_onion host:port uses the host part",
             net_name_is_onion("x.onion:9050"));

    /* One trailing root dot is stripped before the suffix test; only one. */
    NB_CHECK("net_name_is_onion trailing root dot still matches",
             net_name_is_onion("x.onion."));

    /* A-Z on the suffix is folded to a-z before comparing to ".onion". */
    NB_CHECK("net_name_is_onion uppercase suffix still matches",
             net_name_is_onion("X.ONION"));

    /* The suffix must be at the end of the stripped host, not the middle. */
    NB_CHECK("net_name_is_onion .onion in the middle is false",
             !net_name_is_onion("x.onion.com"));

    return failures;
}
