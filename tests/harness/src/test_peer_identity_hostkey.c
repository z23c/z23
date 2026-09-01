/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Focused coverage for core/modules/net/src/peer_identity.c — pure, deterministic
 * logic with no I/O: the 3-branch host-key parser (zcl_peer_host_key)
 * and the fixed-capacity dedup host set (zcl_peer_host_set_*).
 *
 * zcl_peer_host_key() tries, in order:
 *   1. net_addr_to_string() on the parsed net_addr — succeeds whenever
 *      the caller's buffer is large enough for the printed form (IPv4
 *      dotted-quad, "[torv3]", or the 8-group hex IPv6 form; an
 *      all-zero net_addr prints as the 39-char hex IPv6 form since it
 *      does not match the IPv4-mapped prefix).
 *   2. If addr_name starts with '[', treat it as bracketed IPv6/hostname
 *      and extract up to the matching ']'.
 *   3. Otherwise copy addr_name up to (not including) the first ':'.
 * Every branch can additionally fail if the destination buffer is too
 * small for what it would extract — this must return false, never
 * truncate silently. */

#include "test/test_core.h"

#include "net/peer_identity.h"
#include "net/net.h"
#include "net/netaddr.h"

#include <string.h>

static void zero_node(struct p2p_node *node)
{
    memset(node, 0, sizeof(*node));
}

static void set_addr_name(struct p2p_node *node, const char *name)
{
    snprintf(node->addr_name, sizeof(node->addr_name), "%s", name);
}

/* ── zcl_peer_host_key: null / degenerate argument guards ──────────── */

static int test_host_key_null_out(void)
{
    int failures = 0;
    TEST("host_key: NULL out returns false") {
        struct p2p_node node;
        zero_node(&node);
        ASSERT(!zcl_peer_host_key(&node, NULL, 64));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_out_len_zero(void)
{
    int failures = 0;
    TEST("host_key: out_len == 0 returns false") {
        struct p2p_node node;
        char out[64];
        zero_node(&node);
        out[0] = 'x';
        ASSERT(!zcl_peer_host_key(&node, out, 0));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_null_node(void)
{
    int failures = 0;
    TEST("host_key: NULL node returns false and clears out[0]") {
        char out[64];
        memset(out, 'z', sizeof(out));
        ASSERT(!zcl_peer_host_key(NULL, out, sizeof(out)));
        ASSERT(out[0] == '\0');
        PASS();
    } _test_next:;
    return failures;
}

/* ── Branch 1: net_addr_to_string() succeeds ────────────────────────── */

static int test_host_key_primary_ipv4_wins(void)
{
    int failures = 0;
    TEST("host_key: valid IPv4 addr takes priority over addr_name") {
        struct p2p_node node;
        char out[64];
        unsigned char ip4[4] = {192, 168, 1, 5};

        zero_node(&node);
        net_addr_set_ipv4(&node.addr.svc.addr, ip4);
        /* addr_name would parse to something completely different —
         * proves branch 1 is tried first and wins. */
        set_addr_name(&node, "should-not-be-used.example:9999");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "192.168.1.5");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_primary_allzero_hex(void)
{
    int failures = 0;
    TEST("host_key: all-zero net_addr prints the 8-group hex IPv6 form") {
        struct p2p_node node;
        char out[64];

        zero_node(&node);
        /* addr_name deliberately left empty: this must not be consulted. */
        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "0000:0000:0000:0000:0000:0000:0000:0000");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_primary_exact_fit(void)
{
    int failures = 0;
    TEST("host_key: exact-fit buffer for the primary addr still succeeds") {
        struct p2p_node node;
        /* "192.168.1.5\0" is 12 bytes. */
        char out[12];
        unsigned char ip4[4] = {192, 168, 1, 5};

        zero_node(&node);
        net_addr_set_ipv4(&node.addr.svc.addr, ip4);

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "192.168.1.5");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_primary_one_byte_short_falls_through(void)
{
    int failures = 0;
    TEST("host_key: buffer one byte too small for primary addr falls back to addr_name") {
        struct p2p_node node;
        /* One byte short of "192.168.1.5\0" (12 bytes) — falls back to
         * addr_name since branch 1 cannot fit. addr_name has no colon,
         * so its whole content is copied verbatim. */
        char out[11];
        unsigned char ip4[4] = {192, 168, 1, 5};

        zero_node(&node);
        net_addr_set_ipv4(&node.addr.svc.addr, ip4);
        set_addr_name(&node, "fallback");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "fallback");
        PASS();
    } _test_next:;
    return failures;
}

/* ── Branch 2: bracketed addr_name fallback (out_len forces branch 1
 * to fail by being smaller than the 39-char all-zero hex IPv6 form) ── */

static int test_host_key_bracket_wellformed(void)
{
    int failures = 0;
    TEST("host_key: well-formed bracket extracts the inner host") {
        struct p2p_node node;
        char out[20]; /* < 39: forces branch 1 to fail */

        zero_node(&node);
        set_addr_name(&node, "[2001:db8::1]");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "2001:db8::1");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_open_no_close(void)
{
    int failures = 0;
    TEST("host_key: '[' with no closing ']' (end == NULL) returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "[");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_unterminated(void)
{
    int failures = 0;
    TEST("host_key: '[' with unterminated content returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "[2001:db8");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_empty(void)
{
    int failures = 0;
    TEST("host_key: empty bracket \"[]\" (end == addr_name+1) returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "[]");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_empty_trailing_garbage(void)
{
    int failures = 0;
    TEST("host_key: empty bracket with trailing garbage still returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "[]:8333");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_exact_fit(void)
{
    int failures = 0;
    TEST("host_key: bracket host exactly fits out_len - 1 succeeds") {
        struct p2p_node node;
        /* Inner content "abcdefghi" is 9 chars; out_len 10 fits (9 < 10). */
        char out[10];

        zero_node(&node);
        set_addr_name(&node, "[abcdefghi]");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "abcdefghi");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_bracket_one_too_long(void)
{
    int failures = 0;
    TEST("host_key: bracket host one byte too long for out_len fails cleanly") {
        struct p2p_node node;
        /* Same 9-char inner content, but out_len == 9: len(9) >= out_len(9). */
        char out[9];

        zero_node(&node);
        set_addr_name(&node, "[abcdefghi]");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

/* ── Branch 3: colon-split addr_name fallback ───────────────────────── */

static int test_host_key_colon_split_basic(void)
{
    int failures = 0;
    TEST("host_key: 'host:port' copies host up to the first colon") {
        struct p2p_node node;
        char out[20]; /* < 39: forces branch 1 to fail */

        zero_node(&node);
        set_addr_name(&node, "example.com:8333");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "example.com");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_no_colon_full_copy(void)
{
    int failures = 0;
    TEST("host_key: addr_name with no colon copies the whole string") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "justahost");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "justahost");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_colon_empty_host(void)
{
    int failures = 0;
    TEST("host_key: ':8333' (empty host before colon) returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, ":8333");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_empty_addr_name_no_colon(void)
{
    int failures = 0;
    TEST("host_key: empty addr_name with no colon returns false") {
        struct p2p_node node;
        char out[20];

        zero_node(&node);
        set_addr_name(&node, "");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_colon_exact_fit(void)
{
    int failures = 0;
    TEST("host_key: colon-split host exactly fits out_len - 1 succeeds") {
        struct p2p_node node;
        /* "abcdefghi" is 9 chars; out_len 10 fits. */
        char out[10];

        zero_node(&node);
        set_addr_name(&node, "abcdefghi:1234");

        ASSERT(zcl_peer_host_key(&node, out, sizeof(out)));
        ASSERT_STR_EQ(out, "abcdefghi");
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_colon_one_too_long(void)
{
    int failures = 0;
    TEST("host_key: colon-split host one byte too long fails cleanly, not truncated") {
        struct p2p_node node;
        /* Same 9-char host, out_len == 9: len(9) >= out_len(9) -> false. */
        char out[9];

        zero_node(&node);
        set_addr_name(&node, "abcdefghi:1234");
        memset(out, 'Z', sizeof(out)); /* sentinel: must NOT be silently filled */

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_key_no_colon_one_too_long(void)
{
    int failures = 0;
    TEST("host_key: no-colon host one byte too long fails cleanly") {
        struct p2p_node node;
        char out[9]; /* "abcdefghi" is 9 chars incl. no NUL room */

        zero_node(&node);
        set_addr_name(&node, "abcdefghi");

        ASSERT(!zcl_peer_host_key(&node, out, sizeof(out)));
        PASS();
    } _test_next:;
    return failures;
}

/* ── zcl_peer_host_set_init / find_host ─────────────────────────────── */

static int test_host_set_init_zeroes_garbage(void)
{
    int failures = 0;
    TEST("host_set: init zeroes count and overflow even from garbage") {
        struct zcl_peer_host_set set;

        memset(&set, 0xAA, sizeof(set));
        zcl_peer_host_set_init(&set);

        ASSERT(set.count == 0);
        ASSERT(!set.overflow);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_init_tolerates_null(void)
{
    int failures = 0;
    TEST("host_set: init tolerates NULL") {
        zcl_peer_host_set_init(NULL); /* must not crash */
        ASSERT(true);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_find_null_set(void)
{
    int failures = 0;
    TEST("host_set: find_host on NULL set returns -1") {
        ASSERT(zcl_peer_host_set_find_host(NULL, "host") == -1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_find_null_host(void)
{
    int failures = 0;
    TEST("host_set: find_host with NULL host returns -1") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_find_host(&set, NULL) == -1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_find_empty_host(void)
{
    int failures = 0;
    TEST("host_set: find_host with empty host returns -1") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_find_host(&set, "") == -1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_find_on_empty_set(void)
{
    int failures = 0;
    TEST("host_set: find_host on an empty (count == 0) set returns -1") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_find_host(&set, "anything") == -1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── zcl_peer_host_set_add_host ─────────────────────────────────────── */

static int test_host_set_add_host_null_guards(void)
{
    int failures = 0;
    TEST("host_set: add_host rejects NULL set / NULL host / empty host") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(!zcl_peer_host_set_add_host(NULL, "host"));
        ASSERT(!zcl_peer_host_set_add_host(&set, NULL));
        ASSERT(!zcl_peer_host_set_add_host(&set, ""));
        ASSERT(set.count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_first(void)
{
    int failures = 0;
    TEST("host_set: first add succeeds and is findable at index 0") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_add_host(&set, "10.0.0.1"));
        ASSERT(set.count == 1);
        ASSERT(zcl_peer_host_set_find_host(&set, "10.0.0.1") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_second(void)
{
    int failures = 0;
    TEST("host_set: second distinct add succeeds and is findable at index 1") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_add_host(&set, "10.0.0.1"));
        ASSERT(zcl_peer_host_set_add_host(&set, "10.0.0.2"));
        ASSERT(set.count == 2);
        ASSERT(zcl_peer_host_set_find_host(&set, "10.0.0.1") == 0);
        ASSERT(zcl_peer_host_set_find_host(&set, "10.0.0.2") == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_duplicate(void)
{
    int failures = 0;
    TEST("host_set: exact-duplicate add returns false and leaves count unchanged") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(zcl_peer_host_set_add_host(&set, "dup.example"));
        ASSERT(set.count == 1);
        ASSERT(!zcl_peer_host_set_add_host(&set, "dup.example"));
        ASSERT(set.count == 1);
        ASSERT(!set.overflow);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_overflow_fill_and_one_past(void)
{
    int failures = 0;
    TEST("host_set: fill to capacity, one-past-capacity returns TRUE "
         "(not false) and only sets overflow -- host is NOT stored") {
        struct zcl_peer_host_set set;
        char host[32];

        zcl_peer_host_set_init(&set);

        for (size_t i = 0; i < (size_t)ZCL_PEER_HOST_SET_MAX; i++) {
            snprintf(host, sizeof(host), "host-%zu", i);
            ASSERT(zcl_peer_host_set_add_host(&set, host));
        }
        ASSERT(set.count == (size_t)ZCL_PEER_HOST_SET_MAX);
        ASSERT(!set.overflow);

        /* One more, distinct host past the fixed capacity. */
        snprintf(host, sizeof(host), "host-%zu", (size_t)ZCL_PEER_HOST_SET_MAX);
        ASSERT(zcl_peer_host_set_add_host(&set, host));
        ASSERT(set.overflow);
        /* count must NOT have grown past capacity -- the host was
         * never actually written into the array. */
        ASSERT(set.count == (size_t)ZCL_PEER_HOST_SET_MAX);
        ASSERT(zcl_peer_host_set_find_host(&set, host) == -1);

        /* All originally-inserted hosts are still present and findable. */
        snprintf(host, sizeof(host), "host-%zu", (size_t)0);
        ASSERT(zcl_peer_host_set_find_host(&set, host) == 0);
        snprintf(host, sizeof(host), "host-%zu",
                (size_t)(ZCL_PEER_HOST_SET_MAX - 1));
        ASSERT(zcl_peer_host_set_find_host(&set, host)
              == (int)(ZCL_PEER_HOST_SET_MAX - 1));
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_duplicate_wins_over_overflow(void)
{
    int failures = 0;
    TEST("host_set: duplicate check still wins over overflow once full") {
        struct zcl_peer_host_set set;
        char host[32];

        zcl_peer_host_set_init(&set);
        for (size_t i = 0; i < (size_t)ZCL_PEER_HOST_SET_MAX; i++) {
            snprintf(host, sizeof(host), "dup-host-%zu", i);
            ASSERT(zcl_peer_host_set_add_host(&set, host));
        }
        ASSERT(!set.overflow);

        /* Re-adding an already-present host while full: found first,
         * so this is a duplicate rejection (false), NOT an overflow. */
        snprintf(host, sizeof(host), "dup-host-%zu", (size_t)0);
        ASSERT(!zcl_peer_host_set_add_host(&set, host));
        ASSERT(!set.overflow);
        ASSERT(set.count == (size_t)ZCL_PEER_HOST_SET_MAX);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_host_repeated_overflow_latched(void)
{
    int failures = 0;
    TEST("host_set: repeated overflow adds keep returning true and stay latched") {
        struct zcl_peer_host_set set;
        char host[32];

        zcl_peer_host_set_init(&set);
        for (size_t i = 0; i < (size_t)ZCL_PEER_HOST_SET_MAX; i++) {
            snprintf(host, sizeof(host), "cap-%zu", i);
            ASSERT(zcl_peer_host_set_add_host(&set, host));
        }

        snprintf(host, sizeof(host), "overflow-a");
        ASSERT(zcl_peer_host_set_add_host(&set, host));
        ASSERT(set.overflow);

        snprintf(host, sizeof(host), "overflow-b");
        ASSERT(zcl_peer_host_set_add_host(&set, host));
        ASSERT(set.overflow);
        ASSERT(set.count == (size_t)ZCL_PEER_HOST_SET_MAX);
        PASS();
    } _test_next:;
    return failures;
}

/* ── zcl_peer_host_set_add_peer (composition of host_key + add_host) ── */

static int test_host_set_add_peer_null(void)
{
    int failures = 0;
    TEST("host_set: add_peer with NULL node returns false") {
        struct zcl_peer_host_set set;

        zcl_peer_host_set_init(&set);
        ASSERT(!zcl_peer_host_set_add_peer(&set, NULL));
        ASSERT(set.count == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_peer_basic(void)
{
    int failures = 0;
    TEST("host_set: add_peer derives the host key and stores it") {
        struct zcl_peer_host_set set;
        struct p2p_node node;
        unsigned char ip4[4] = {203, 0, 113, 9};

        zcl_peer_host_set_init(&set);
        zero_node(&node);
        net_addr_set_ipv4(&node.addr.svc.addr, ip4);

        ASSERT(zcl_peer_host_set_add_peer(&set, &node));
        ASSERT(set.count == 1);
        ASSERT(zcl_peer_host_set_find_host(&set, "203.0.113.9") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_peer_duplicate(void)
{
    int failures = 0;
    TEST("host_set: add_peer twice for the same address is a duplicate") {
        struct zcl_peer_host_set set;
        struct p2p_node node_a, node_b;
        unsigned char ip4[4] = {203, 0, 113, 9};

        zcl_peer_host_set_init(&set);
        zero_node(&node_a);
        zero_node(&node_b);
        net_addr_set_ipv4(&node_a.addr.svc.addr, ip4);
        net_addr_set_ipv4(&node_b.addr.svc.addr, ip4);

        ASSERT(zcl_peer_host_set_add_peer(&set, &node_a));
        ASSERT(!zcl_peer_host_set_add_peer(&set, &node_b));
        ASSERT(set.count == 1);
        PASS();
    } _test_next:;
    return failures;
}

static int test_host_set_add_peer_two_distinct(void)
{
    int failures = 0;
    TEST("host_set: add_peer for two distinct addresses stores both") {
        struct zcl_peer_host_set set;
        struct p2p_node node_a, node_b;
        unsigned char ip4_a[4] = {198, 51, 100, 1};
        unsigned char ip4_b[4] = {198, 51, 100, 2};

        zcl_peer_host_set_init(&set);
        zero_node(&node_a);
        zero_node(&node_b);
        net_addr_set_ipv4(&node_a.addr.svc.addr, ip4_a);
        net_addr_set_ipv4(&node_b.addr.svc.addr, ip4_b);

        ASSERT(zcl_peer_host_set_add_peer(&set, &node_a));
        ASSERT(zcl_peer_host_set_add_peer(&set, &node_b));
        ASSERT(set.count == 2);
        ASSERT(zcl_peer_host_set_find_host(&set, "198.51.100.1") == 0);
        ASSERT(zcl_peer_host_set_find_host(&set, "198.51.100.2") == 1);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────────────────── */

int test_peer_identity_hostkey(void);

int test_peer_identity_hostkey(void)
{
    int failures = 0;

    failures += test_host_key_null_out();
    failures += test_host_key_out_len_zero();
    failures += test_host_key_null_node();
    failures += test_host_key_primary_ipv4_wins();
    failures += test_host_key_primary_allzero_hex();
    failures += test_host_key_primary_exact_fit();
    failures += test_host_key_primary_one_byte_short_falls_through();
    failures += test_host_key_bracket_wellformed();
    failures += test_host_key_bracket_open_no_close();
    failures += test_host_key_bracket_unterminated();
    failures += test_host_key_bracket_empty();
    failures += test_host_key_bracket_empty_trailing_garbage();
    failures += test_host_key_bracket_exact_fit();
    failures += test_host_key_bracket_one_too_long();
    failures += test_host_key_colon_split_basic();
    failures += test_host_key_no_colon_full_copy();
    failures += test_host_key_colon_empty_host();
    failures += test_host_key_empty_addr_name_no_colon();
    failures += test_host_key_colon_exact_fit();
    failures += test_host_key_colon_one_too_long();
    failures += test_host_key_no_colon_one_too_long();

    failures += test_host_set_init_zeroes_garbage();
    failures += test_host_set_init_tolerates_null();
    failures += test_host_set_find_null_set();
    failures += test_host_set_find_null_host();
    failures += test_host_set_find_empty_host();
    failures += test_host_set_find_on_empty_set();

    failures += test_host_set_add_host_null_guards();
    failures += test_host_set_add_host_first();
    failures += test_host_set_add_host_second();
    failures += test_host_set_add_host_duplicate();
    failures += test_host_set_add_host_overflow_fill_and_one_past();
    failures += test_host_set_add_host_duplicate_wins_over_overflow();
    failures += test_host_set_add_host_repeated_overflow_latched();

    failures += test_host_set_add_peer_null();
    failures += test_host_set_add_peer_basic();
    failures += test_host_set_add_peer_duplicate();
    failures += test_host_set_add_peer_two_distinct();

    return failures;
}
