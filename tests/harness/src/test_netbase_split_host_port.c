/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Extensive focused unit tests for split_host_port() (core/modules/net/src/netbase.c)
 * — a pure string state machine with no I/O, no clock, no allocation —
 * and for net_name_is_onion(), which this binary links and must actually
 * call. A function nothing calls cannot fail a test.
 *
 * test_net.c exercises only two shallow paths (bare IPv4:port and
 * bracketed [::1]:port). This file pins the richer interior state
 * machine: bracket detection, multi-colon (bare IPv6) detection, the
 * ParseInt32 port-range guard (including the exclusive 0x10000 fence
 * that a far-past overflow like 99999 cannot pin), and the host_out
 * truncation contract.
 *
 * Read straight off core/modules/net/src/netbase.c (as of this writing):
 *
 *   1. Find the LAST ':' in the input (or none).
 *   2. If found:
 *        bracketed   = in[0]=='[' && colon[-1]==']'
 *        multi_colon = another ':' appears strictly before that last colon
 *        If colon is not the very first character, AND (bracketed OR NOT
 *        multi_colon), attempt ParseInt32 on the suffix after the colon.
 *        Only when that parse succeeds AND 0 < n < 0x10000 does *port_out
 *        get written AND does `len` get truncated to exclude ":port".
 *        Any other outcome (out of range, non-numeric, leading colon,
 *        bare multi-colon IPv6) leaves `len` untouched (the whole
 *        original string remains the candidate host) and *port_out
 *        untouched.
 *   3. If (possibly truncated) len>=2 and the string still starts with
 *      '[' and ends with ']', strip exactly one bracket pair — but ONLY
 *      if the stripped host (len-2 bytes + NUL) fits host_size; if it
 *      doesn't fit, host_out is left completely untouched (a no-op, not
 *      a truncation).
 *   4. Otherwise copy up to host_size-1 bytes of the candidate host,
 *      always NUL-terminating within bounds (safe truncation).
 *
 * Pure: deterministic, no I/O, no global state, no clock. Table-driven
 * plus a handful of pointer-arithmetic edge cases that don't fit the
 * table shape. */

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

int test_netbase_split_host_port(void)
{
    printf("\n=== netbase split_host_port tests ===\n");
    int failures = 0;
    char host[128];
    int port;

    /* ── happy path: table-driven ─────────────────────────────────── */
    static const struct sh_case cases[] = {
        /* bare IPv4 + port (already covered in test_net.c; re-pinned here
         * as the baseline the rest of the table diffs against). */
        { "ipv4 with port",            "192.168.1.1:9033",  "192.168.1.1", 9033 },
        /* bracketed IPv6 + port. */
        { "bracketed ipv6 with port",  "[::1]:9033",         "::1",         9033 },
        /* bracketed IPv6 with NO port suffix at all — brackets must
         * still be stripped (no trailing colon to even consider). */
        { "bracketed ipv6 no port",    "[::1]",              "::1",         PORT_SENTINEL },
        /* bracketed IPv6 with a longer host and a high (but valid) port. */
        { "bracketed ipv6 full addr",  "[2001:db8::ff00:42:8329]:65535",
                                        "2001:db8::ff00:42:8329", 65535 },
        /* bare (unbracketed) IPv6 with multiple colons and NO port —
         * the multi-colon guard must refuse to treat the last colon
         * group as a port, leaving the whole string as host. */
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
        bool host_ok = strcmp(host, cases[i].want_host) == 0;
        bool port_ok = (port == cases[i].want_port);
        NB_CHECK(cases[i].name, host_ok && port_ok);
        if (!(host_ok && port_ok))
            printf("    (got host=\"%s\" port=%d)\n", host, port);
    }

    /* ── adversarial: port value out of uint16 range ─────────────────
     * ParseInt32("99999", &n) SUCCEEDS (n=99999 fits int32), but the
     * range guard `n < 0x10000` rejects it, so the whole branch that
     * would set *port_out and truncate `len` never runs. The ENTIRE
     * original string (colon and digits included) becomes the host.
     * This pins "far past the top" — it does NOT pin 65536, because
     * both `n < 0x10000` and `n <= 0x10000` reject 99999. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:99999", host, sizeof(host), &port);
    NB_CHECK("port overflow (99999) falls through to whole-string host",
             strcmp(host, "host:99999") == 0 && port == PORT_SENTINEL);

    /* Exclusive-upper fence, accepted side: 65535 is 0xFFFF, the last
     * value for which `n < 0x10000` is true. A mutant that changes `<`
     * to `<=` still accepts 65535, so this case alone cannot kill it;
     * it pins that the last legal port is still written and that the
     * host is truncated rather than left as "host:65535". The table
     * row of the same input is the happy-path copy; this copy sits
     * next to 65536 so the two sides of the fence are one pair. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:65535", host, sizeof(host), &port);
    NB_CHECK("port 65535 (0xFFFF) accepted, host truncated to exclude port",
             strcmp(host, "host") == 0 && port == 65535);

    /* Exclusive-upper fence, rejected side: 65536 is 0x10000, the
     * first value `n < 0x10000` refuses and `n <= 0x10000` would
     * accept. No other near-bound input distinguishes those two
     * predicates. If this were accepted, host would become "host"
     * and port 65536. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:65536", host, sizeof(host), &port);
    NB_CHECK("port 65536 (0x10000) rejected, whole string becomes host",
             strcmp(host, "host:65536") == 0 && port == PORT_SENTINEL);

    /* Same exclusive bound on the bracketed path, which still takes
     * the ParseInt32 range check even though the host contains colons.
     * If 65536 were accepted here, brackets would strip and port would
     * be written (host "::1", port 65536). */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("[::1]:65536", host, sizeof(host), &port);
    NB_CHECK("bracketed port 65536 rejected, no strip and no port write",
             strcmp(host, "[::1]:65536") == 0 && port == PORT_SENTINEL);

    /* ── adversarial: port value == 0 is rejected (n>0 required) ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:0", host, sizeof(host), &port);
    NB_CHECK("port zero rejected, whole string becomes host",
             strcmp(host, "host:0") == 0 && port == PORT_SENTINEL);

    /* ── adversarial: negative port digits parse but fail n>0 ──────── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:-5", host, sizeof(host), &port);
    NB_CHECK("negative port rejected, whole string becomes host",
             strcmp(host, "host:-5") == 0 && port == PORT_SENTINEL);

    /* ── adversarial: non-numeric suffix after colon ──────────────── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:abc", host, sizeof(host), &port);
    NB_CHECK("non-numeric port suffix rejected, whole string becomes host",
             strcmp(host, "host:abc") == 0 && port == PORT_SENTINEL);

    /* ── adversarial: leading colon must not be a port separator ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port(":1234", host, sizeof(host), &port);
    NB_CHECK("leading colon (colon == in) not treated as separator",
             strcmp(host, ":1234") == 0 && port == PORT_SENTINEL);

    /* A leading colon on a longer, still-multi-colon-free tail: the
     * `colon != in` guard alone must suppress port parsing, independent
     * of the multi_colon check (there is exactly one colon here, at
     * index 0, so multi_colon would be false — the guard that fires
     * must specifically be `colon != in`). */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port(":9033", host, sizeof(host), &port);
    NB_CHECK("bare leading colon with digits stays whole-string host",
             strcmp(host, ":9033") == 0 && port == PORT_SENTINEL);

    /* ── adversarial: bracketed host whose bracket[-1] isn't ']' ─────
     * "[::1" has no closing bracket before the (only, at index... none
     * here) colon test differently: use a case where in[0]=='[' but the
     * character before the LAST colon is not ']', so `bracketed` is
     * false and the multi-colon guard (true, since there are 2 earlier
     * colons) suppresses port parsing. Then the final bracket-stripping
     * check independently looks at whether the (untruncated) string
     * starts with '[' and ends with ']' — "[::1" does NOT end with ']',
     * so no stripping happens either; the whole string is the host. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("[::1", host, sizeof(host), &port);
    NB_CHECK("unterminated bracket left completely as host, no port",
             strcmp(host, "[::1") == 0 && port == PORT_SENTINEL);

    /* ── host_size truncation: unbracketed candidate host longer than
     * the buffer must be safely truncated (copy=min(len,host_size-1))
     * and always NUL-terminated within bounds — never overflow. ───── */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    {
        char small[4]; /* room for "abc\0" only */
        memset(small, 0xAA, sizeof(small));
        split_host_port("abcdefgh", small, sizeof(small), &port);
        NB_CHECK("unbracketed host truncated to host_size-1 + NUL, no overflow",
                 strcmp(small, "abc") == 0);
    }

    /* Truncation must also apply when a valid port WAS parsed off first
     * (host portion computed from the truncated `len`, independent of
     * host_size). */
    {
        char small[4];
        memset(small, 0xAA, sizeof(small));
        int p = PORT_SENTINEL;
        split_host_port("abcdefgh:9033", small, sizeof(small), &p);
        NB_CHECK("port parsed first, then host still truncated safely",
                 strcmp(small, "abc") == 0 && p == 9033);
    }

    /* Exact-fit boundary: host_size == strlen(host)+1 must NOT truncate
     * (copy == len exactly, host_out[len] == '\0' fits in bounds). */
    {
        char exact[4]; /* "abc" is 3 chars + NUL == 4 */
        memset(exact, 0xAA, sizeof(exact));
        int p = PORT_SENTINEL;
        split_host_port("abc", exact, sizeof(exact), &p);
        NB_CHECK("host_size exactly len+1 copies host untruncated",
                 strcmp(exact, "abc") == 0);
    }

    /* One byte short of exact fit must drop exactly one character. */
    {
        char short_by_one[3]; /* only room for "ab\0" */
        memset(short_by_one, 0xAA, sizeof(short_by_one));
        int p = PORT_SENTINEL;
        split_host_port("abc", short_by_one, sizeof(short_by_one), &p);
        NB_CHECK("host_size one short truncates by exactly one char",
                 strcmp(short_by_one, "ab") == 0);
    }

    /* host_size == 1: only room for the NUL terminator; must not
     * overflow (copy computed as 0, single NUL write). */
    {
        char tiny[1];
        tiny[0] = (char)0xAA;
        int p = PORT_SENTINEL;
        split_host_port("abcdefgh", tiny, sizeof(tiny), &p);
        NB_CHECK("host_size==1 yields empty string, no overflow",
                 tiny[0] == '\0');
    }

    /* ── bracketed host_out no-op when it doesn't fit ────────────────
     * The bracket-stripping branch is gated by `len - 2 < host_size`;
     * when the bracketed host does NOT fit, the code does nothing at
     * all to host_out (no truncated copy, no NUL) — this is a no-op,
     * not a truncation, and callers must not assume host_out was
     * touched. Pin that exact contract with a sentinel-filled buffer. */
    {
        char tiny_bracket[2]; /* "::1" (len-2=3) can't fit in 2 bytes */
        memset(tiny_bracket, 0x5A, sizeof(tiny_bracket));
        int p = PORT_SENTINEL;
        split_host_port("[::1]", tiny_bracket, sizeof(tiny_bracket), &p);
        NB_CHECK("bracketed host too big for host_size leaves host_out untouched",
                 tiny_bracket[0] == (char)0x5A && tiny_bracket[1] == (char)0x5A);
    }

    /* Bracketed host that fits EXACTLY at the boundary must still copy
     * (the guard is strict '<', so len-2 == host_size must NOT fit,
     * and len-2 == host_size-1 must fit). */
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
                 one_short[0] == (char)0x5A && one_short[1] == (char)0x5A &&
                 one_short[2] == (char)0x5A);
    }

    /* ── round-trip sanity: bracketed host WITH port, small buffer
     * fits the host but the port must still parse from the untruncated
     * original before len is shortened. ──────────────────────────── */
    {
        char h[8];
        memset(h, 0xAA, sizeof(h));
        int p = PORT_SENTINEL;
        split_host_port("[::1]:443", h, sizeof(h), &p);
        NB_CHECK("bracketed host with port: both host and port correct",
                 strcmp(h, "::1") == 0 && p == 443);
    }

    /* Empty suffix after the colon: ParseInt32("") fails its length-0
     * precheck, so the range guard is never reached. Pins that a
     * trailing colon is not a port of 0 (already refused by n>0) and
     * is not silently ignored either — the colon stays in the host. */
    memset(host, 0xAA, sizeof(host));
    port = PORT_SENTINEL;
    split_host_port("host:", host, sizeof(host), &port);
    NB_CHECK("empty port suffix rejected, whole string becomes host",
             strcmp(host, "host:") == 0 && port == PORT_SENTINEL);

    /* ── net_name_is_onion: suffix detection, not v3 validation ──────
     * Header contract: true when the host part of "host[:port]" carries
     * the ".onion" suffix. Detection only — no parsing, no resolution.
     * Implementation (netbase.c): NULL is false; split_host_port first;
     * strip at most one trailing '.'; require len > 6; case-fold A-Z
     * on the last 6 bytes and compare to ".onion". These cases exist
     * so mutations of a linked-but-uncalled function can go red. */

    /* Pointer guard: the first line is `if (!name) return false`.
     * Chosen because the function accepts NULL and a missing guard
     * would dereference. Distinct from the empty-string path. */
    NB_CHECK("net_name_is_onion NULL is false",
             !net_name_is_onion(NULL));

    /* Empty string: split_host_port copies "", len==0, 0 <= 6, false.
     * Pins the length bound rather than the pointer guard. */
    NB_CHECK("net_name_is_onion empty string is false",
             !net_name_is_onion(""));

    /* A name that is not an onion. Suffix mismatch. Chosen so a
     * mutant that hardcodes `return true` after the length check
     * goes red; example.com is the ordinary hostname this helper
     * must never claim. */
    NB_CHECK("net_name_is_onion example.com is false",
             !net_name_is_onion("example.com"));

    /* Real onion-shaped name: a v3-length local part plus ".onion".
     * Detection does not require a valid checksum; this pins the
     * true-return path a linked-but-uncalled function never hit. */
    NB_CHECK("net_name_is_onion v3-shaped name is true",
             net_name_is_onion(
                 "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopq.onion"));

    /* Shortest name that can carry the suffix: one local byte +
     * ".onion" is len==7, which is the first length `len <= 6`
     * does not refuse. Pins the true side of the length bound. */
    NB_CHECK("net_name_is_onion x.onion (shortest true) is true",
             net_name_is_onion("x.onion"));

    /* Exact suffix with no local part: len==6, `len <= 6` is true,
     * so this is false. Changing `<=` to `<` would accept ".onion"
     * because the tail then matches. Distinct from the empty string
     * (len==0) and from x.onion (len==7). */
    NB_CHECK("net_name_is_onion exact suffix .onion is false",
             !net_name_is_onion(".onion"));

    /* Header says the HOST part carries the suffix: split_host_port
     * must run first, or "x.onion:9050" would fail the tail compare
     * against the port digits. */
    NB_CHECK("net_name_is_onion host:port uses the host part",
             net_name_is_onion("x.onion:9050"));

    /* One trailing root dot is stripped before the suffix test
     * (`host[len-1] == '.'` then len--). Chosen because DNS names
     * may carry that dot and a detector that required a raw suffix
     * would miss them. Only one dot is stripped. */
    NB_CHECK("net_name_is_onion trailing root dot still matches",
             net_name_is_onion("x.onion."));

    /* A-Z on the suffix is folded to a-z; the compared literal is
     * lowercase ".onion". Chosen so a case-sensitive compare of a
     * wire-uppercase name would go red. */
    NB_CHECK("net_name_is_onion uppercase suffix still matches",
             net_name_is_onion("X.ONION"));

    /* Suffix must be at the end of the (stripped) host, not in the
     * middle. Pins that a contains-".onion" mutant is not enough. */
    NB_CHECK("net_name_is_onion .onion in the middle is false",
             !net_name_is_onion("x.onion.com"));

    return failures;
}
