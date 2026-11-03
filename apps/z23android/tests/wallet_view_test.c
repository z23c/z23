/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_view.h"
#include "base/cleanse.h"
#include "residue.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VALID_REPLY                                                                                  \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\","                                  \
    "\"spendable_zat\":123456789,\"spendable\":\"1.23456789\","                                      \
    "\"pending_zat\":50000000,\"pending\":\"0.50000000\",\"pending_notes\":2,"                       \
    "\"pending_min_confirmations_needed\":7,\"sending_zat\":0,\"sending\":\"0.00000000\","           \
    "\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":0,"                          \
    "\"immature\":\"0.00000000\",\"tip_height\":3000000,\"header_height\":3000000,"                  \
    "\"scanned_through_height\":3000000,\"blocks_behind\":0,\"current\":true,"                       \
    "\"locked\":false,\"encrypted\":true,\"shielded_keys\":1,\"send_allowed\":true,"                 \
    "\"send_blocked_reason\":\"\"}}"

/* Every key the view requires. Renaming one of them makes the reply malformed. */
static const char *const required_keys[] = {
    "schema", "spendable_zat", "spendable", "pending_zat", "pending", "pending_notes",
    "pending_min_confirmations_needed", "public_zat", "public", "immature_zat", "immature",
    "tip_height", "header_height", "scanned_through_height", "blocks_behind", "current",
    "locked", "encrypted", "shielded_keys", "send_allowed", "send_blocked_reason",
};

/* Copy src into dst with the first occurrence of from replaced by to. The fixture must contain
 * from. src may alias dst. */
static void replace_once(char *dst, size_t cap, const char *src, const char *from, const char *to)
{
    char copy[2048];
    assert(strlen(src) < sizeof(copy));
    memcpy(copy, src, strlen(src) + 1);
    const char *hit = strstr(copy, from);
    assert(hit);
    int n = snprintf(dst, cap, "%.*s%s%s", (int)(hit - copy), copy, to, hit + strlen(from));
    assert(n >= 0 && (size_t)n < cap);
}

static void assert_unknown(const struct wallet_view *v)
{
    assert(!v->known);
    assert(!v->send_allowed);
    assert(!strcmp(v->balance, "Balance unknown"));
    assert(!strstr(v->balance, "ZCL"));
    assert(!strcmp(v->pending, "Pending amount unknown"));
    assert(!strcmp(v->public_line, "Public amount unknown"));
    assert(!strcmp(v->sync, "Sync state unknown"));
    assert(!strcmp(v->immature_line, "Maturing amount unknown") && !strstr(v->immature_line, "0 ZCL"));
    assert(!v->scanning && !v->current);
    assert(!strcmp(v->send, "Sending is unavailable until the wallet state loads."));
}

static void test_valid_reply(void)
{
    struct wallet_view v;
    assert(wallet_view_from_summary(VALID_REPLY, &v));
    assert(v.known);
    assert(!strcmp(v.balance, "1.23456789 ZCL"));
    assert(!v.immature_line[0] && !v.scanning && v.current);
    assert(!strcmp(v.pending, "0.5 ZCL pending in 2 payments. The next arrives in 7 confirmations."));
    assert(!strcmp(v.public_line, "0.1 ZCL public: visible to everyone, not part of the spendable amount"));
    assert(!strcmp(v.sync, "Up to date at block 3000000"));
    assert(v.send[0] == '\0');
    assert(v.send_allowed);
    printf("  valid reply renders every line\n");
}

static void test_empty_lines_and_singular(void)
{
    char json[2048], json2[2048];
    struct wallet_view v;
    replace_once(json, sizeof(json), VALID_REPLY, "\"pending_zat\":50000000,\"pending\":\"0.50000000\"",
                 "\"pending_zat\":0,\"pending\":\"0.00000000\"");
    replace_once(json2, sizeof(json2), json, "\"public_zat\":10000000,\"public\":\"0.10000000\"",
                 "\"public_zat\":0,\"public\":\"0.00000000\"");
    assert(wallet_view_from_summary(json2, &v) && v.known);
    assert(v.pending[0] == '\0');
    assert(v.public_line[0] == '\0');

    replace_once(json, sizeof(json), VALID_REPLY, "\"pending_min_confirmations_needed\":7",
                 "\"pending_min_confirmations_needed\":1");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.pending, "0.5 ZCL pending in 2 payments. The next arrives in 1 confirmation."));

    replace_once(json, sizeof(json), VALID_REPLY, "\"pending_notes\":2", "\"pending_notes\":0");
    replace_once(json2, sizeof(json2), json, "\"pending_min_confirmations_needed\":7",
                 "\"pending_min_confirmations_needed\":0");
    assert(wallet_view_from_summary(json2, &v) && v.known);
    assert(!strcmp(v.pending, "0.5 ZCL pending"));

    /* Five notes of 1 ZCL and one of 5 ZCL need 1 and 10 confirmations: only the next one arrives in 1, so the
     * sum is never said to arrive in it. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"pending_zat\":50000000,\"pending\":\"0.50000000\"",
                 "\"pending_zat\":600000000,\"pending\":\"6.00000000\"");
    replace_once(json2, sizeof(json2), json, "\"pending_min_confirmations_needed\":7",
                 "\"pending_min_confirmations_needed\":1");
    assert(wallet_view_from_summary(json2, &v) && v.known);
    assert(!strcmp(v.pending, "6 ZCL pending in 2 payments. The next arrives in 1 confirmation.") && !strstr(v.pending, "arriving"));

    /* One note arrives whole. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"pending_notes\":2", "\"pending_notes\":1");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.pending, "0.5 ZCL arriving in 7 confirmations"));
    printf("  empty pending and public lines, singular confirmation, one note and several\n");
}

static void test_amount_format(void)
{
    static const struct { const char *zat; const char *str; const char *shown; } cases[] = {
        { "0", "0.00000000", "0 ZCL" },
        { "1", "0.00000001", "0.00000001 ZCL" },
        { "100000000", "1.00000000", "1 ZCL" },
        { "2500000000", "25.00000000", "25 ZCL" },
        { "1230000000", "12.30000000", "12.3 ZCL" },
        { "2100000000000000", "21000000.00000000", "21000000 ZCL" },
    };
    char json[2048], json2[2048], zat_field[64], str_field[64];
    struct wallet_view v;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        snprintf(zat_field, sizeof(zat_field), "\"spendable_zat\":%s", cases[i].zat);
        snprintf(str_field, sizeof(str_field), "\"spendable\":\"%s\"", cases[i].str);
        replace_once(json, sizeof(json), VALID_REPLY, "\"spendable_zat\":123456789", zat_field);
        replace_once(json2, sizeof(json2), json, "\"spendable\":\"1.23456789\"", str_field);
        assert(wallet_view_from_summary(json2, &v) && v.known);
        assert(!strcmp(v.balance, cases[i].shown));
    }
    /* A known zero is a real zero: the balance was read, so it may show 0. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"spendable_zat\":123456789",
                 "\"spendable_zat\":0");
    replace_once(json2, sizeof(json2), json, "\"spendable\":\"1.23456789\"",
                 "\"spendable\":\"0.00000000\"");
    assert(wallet_view_from_summary(json2, &v) && v.known);
    assert(!strcmp(v.balance, "0 ZCL"));
    printf("  zatoshi to balance without trailing zeros, no floating point\n");
}

/* Mined coins that are still maturing get their own line; the scan state tells a list of transactions it may be incomplete. */
static void test_immature_and_scan(void)
{
    char json[2048], json2[2048];
    struct wallet_view v;
    replace_once(json, sizeof(json), VALID_REPLY, "\"immature_zat\":0,\"immature\":\"0.00000000\"",
                 "\"immature_zat\":2000000000,\"immature\":\"20.00000000\"");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.immature_line, "20 ZCL of mined coins maturing, not yet spendable"));
    replace_once(json, sizeof(json), VALID_REPLY, "\"scanned_through_height\":3000000",
                 "\"scanned_through_height\":2999000");
    assert(wallet_view_from_summary(json, &v) && v.known && v.scanning);
    replace_once(json2, sizeof(json2), VALID_REPLY, "\"blocks_behind\":0,\"current\":true", "\"blocks_behind\":3,\"current\":true");
    assert(wallet_view_from_summary(json2, &v) && v.known && v.scanning);
    /* A node that is not current, with every block scanned, says it is not up to date and does not claim a scan. */
    replace_once(json2, sizeof(json2), VALID_REPLY, "\"blocks_behind\":0,\"current\":true", "\"blocks_behind\":0,\"current\":false");
    assert(wallet_view_from_summary(json2, &v) && v.known && !v.scanning && !v.current && !strstr(v.sync, "Up to date"));
    printf("  immature coins, scan state, a node that is not current\n");
}

static void test_sync_lines(void)
{
    char json[2048];
    struct wallet_view v;
    replace_once(json, sizeof(json), VALID_REPLY, "\"blocks_behind\":0,\"current\":true",
                 "\"blocks_behind\":5,\"current\":false");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.sync, "Updating your wallet. Amounts may change."));

    replace_once(json, sizeof(json), VALID_REPLY, "\"blocks_behind\":0,\"current\":true",
                 "\"blocks_behind\":0,\"current\":false");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.sync, "Catching up: amounts may change"));

    /* One block behind, even with current true, reads as updating: never as up to date. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"blocks_behind\":0,\"current\":true",
                 "\"blocks_behind\":1,\"current\":true");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.sync, "Updating your wallet. Amounts may change."));

    /* current true with a larger gap is inconsistent, and must not read as confirmed. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"blocks_behind\":0,\"current\":true",
                 "\"blocks_behind\":2,\"current\":true");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.sync, "Updating your wallet. Amounts may change."));
    /* The node is current, but the wallet has not scanned every block it knows: not up to date. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"scanned_through_height\":3000000",
                 "\"scanned_through_height\":2999000");
    assert(wallet_view_from_summary(json, &v) && v.known && v.current);
    assert(!strcmp(v.sync, "Still scanning your wallet history. Amounts may change."));
    printf("  sync line: up to date, catching up, one block, several blocks behind\n");
}

/* 21000000 ZCL is the largest amount read; one zatoshi more makes the whole reply unknown. */
static void test_zat_limit(void)
{
    char json[2048], json2[2048];
    struct wallet_view v;
    replace_once(json, sizeof(json), VALID_REPLY, "\"spendable_zat\":123456789",
                 "\"spendable_zat\":2100000000000000");
    replace_once(json2, sizeof(json2), json, "\"spendable\":\"1.23456789\"",
                 "\"spendable\":\"21000000.00000000\"");
    assert(wallet_view_from_summary(json2, &v) && v.known);
    assert(!strcmp(v.balance, "21000000 ZCL"));

    replace_once(json, sizeof(json), VALID_REPLY, "\"spendable_zat\":123456789",
                 "\"spendable_zat\":2100000000000001");
    replace_once(json2, sizeof(json2), json, "\"spendable\":\"1.23456789\"",
                 "\"spendable\":\"21000000.00000001\"");
    assert(!wallet_view_from_summary(json2, &v));
    assert_unknown(&v);

    replace_once(json, sizeof(json), VALID_REPLY, "\"public_zat\":10000000,\"public\":\"0.10000000\"",
                 "\"public_zat\":2100000000000001,\"public\":\"21000000.00000001\"");
    assert(!wallet_view_from_summary(json, &v));
    assert_unknown(&v);
    printf("  amounts at 21000000 ZCL read, one zatoshi more is unknown\n");
}

static void test_send_reasons(void)
{
    static const struct { const char *reason; const char *line; } cases[] = {
        { "release_assisted: not_self_derived",
          "Sending is paused until your phone has checked the latest blocks on its own." },
        { "release_assisted",
          "Sending is paused until your phone has checked the latest blocks on its own." },
        { "progress_store_unavailable",
          "Sending is paused because the wallet cannot save its progress right now." },
        { "something_new",
          "Sending is paused for a reason this app does not recognize." },
        { "",
          "Sending is paused for a reason this app does not recognize." },
    };
    char json[2048], json2[2048];
    struct wallet_view v;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        replace_once(json, sizeof(json), VALID_REPLY, "\"send_allowed\":true",
                     "\"send_allowed\":false");
        char field[256];
        snprintf(field, sizeof(field), "\"send_blocked_reason\":\"%s\"", cases[i].reason);
        replace_once(json2, sizeof(json2), json, "\"send_blocked_reason\":\"\"", field);
        assert(wallet_view_from_summary(json2, &v) && v.known);
        assert(!v.send_allowed);
        assert(!strcmp(v.send, cases[i].line));
        assert(!strstr(v.send, " tip") && !strstr(v.send, "verif") && !strstr(v.send, "store") && !strstr(v.send, "release") && !strstr(v.send, "trust"));
    }
    /* Sending allowed: the send line is empty whatever reason text the node sent. */
    replace_once(json, sizeof(json), VALID_REPLY, "\"send_blocked_reason\":\"\"",
                 "\"send_blocked_reason\":\"release_assisted\"");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(v.send_allowed && v.send[0] == '\0');
    printf("  send line: each known reason, generic unknown, empty when allowed\n");
}

/* Every missing required field gives the unknown state, never a zero balance. */
static void test_missing_fields_are_unknown(void)
{
    char json[2048];
    struct wallet_view v;
    for (size_t i = 0; i < sizeof(required_keys) / sizeof(required_keys[0]); i++) {
        char from[96], to[96];
        snprintf(from, sizeof(from), "\"%s\":", required_keys[i]);
        snprintf(to, sizeof(to), "\"zz_%s\":", required_keys[i]);
        replace_once(json, sizeof(json), VALID_REPLY, from, to);
        assert(!wallet_view_from_summary(json, &v));
        assert_unknown(&v);
    }
    replace_once(json, sizeof(json), VALID_REPLY, "\"data\":", "\"zz_data\":");
    assert(!wallet_view_from_summary(json, &v));
    assert_unknown(&v);
    printf("  each of %zu missing required fields is unknown\n",
           sizeof(required_keys) / sizeof(required_keys[0]));
}

/* Wrong types, a string that disagrees with its zatoshi, and negative counts are unknown. */
static void test_malformed_fields_are_unknown(void)
{
    static const struct { const char *from; const char *to; } cases[] = {
        { "\"spendable\":\"1.23456789\"", "\"spendable\":\"1.2345678\"" },
        { "\"spendable\":\"1.23456789\"", "\"spendable\":\"1.23456788\"" },
        { "\"spendable\":\"1.23456789\"", "\"spendable\":\"1.23456789 \"" },
        { "\"spendable\":\"1.23456789\"", "\"spendable\":1.23456789" },
        { "\"spendable_zat\":123456789", "\"spendable_zat\":-1" },
        { "\"spendable_zat\":123456789", "\"spendable_zat\":\"123456789\"" },
        { "\"spendable_zat\":123456789", "\"spendable_zat\":1.5" },
        { "\"pending_notes\":2", "\"pending_notes\":-2" },
        { "\"blocks_behind\":0", "\"blocks_behind\":-1" },
        { "\"current\":true", "\"current\":\"true\"" },
        { "\"locked\":false", "\"locked\":0" },
        { "\"send_allowed\":true", "\"send_allowed\":\"yes\"" },
        { "\"send_blocked_reason\":\"\"", "\"send_blocked_reason\":null" },
        { "\"schema\":\"zcl.wallet_summary.v1\"", "\"schema\":\"zcl.wallet_status.v1\"" },
        { "\"ok\":true", "\"ok\":false" },
        { "\"ok\":true", "\"ok\":\"true\"" },
    };
    char json[2048];
    struct wallet_view v;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        replace_once(json, sizeof(json), VALID_REPLY, cases[i].from, cases[i].to);
        assert(!wallet_view_from_summary(json, &v));
        assert_unknown(&v);
    }
    printf("  %zu malformed replies are unknown\n", sizeof(cases) / sizeof(cases[0]));
}

static void test_bad_input_is_unknown(void)
{
    static const char *const bad[] = {
        "", "{", "[]", "{}", "null", "{\"ok\":true}", "{\"ok\":true,\"data\":[]}",
        "{\"ok\":true,\"data\":{}}", "{\"ok\":true,\"data\":{\"total\":\"0\"}}",
    };
    struct wallet_view v;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        assert(!wallet_view_from_summary(bad[i], &v));
        assert_unknown(&v);
    }
    assert(!wallet_view_from_summary(NULL, &v));
    assert_unknown(&v);
    printf("  empty, null, invalid and wrong-shape input is unknown\n");
}

static void test_group_address(void)
{
    char out[64];
    assert(wallet_view_group_address("abcdefghij", out, sizeof(out)));
    assert(!strcmp(out, "abcd efgh ij"));
    assert(wallet_view_group_address("abcdefgh", out, sizeof(out)));
    assert(!strcmp(out, "abcd efgh"));
    assert(wallet_view_group_address("a", out, sizeof(out)));
    assert(!strcmp(out, "a"));
    assert(wallet_view_group_address("zs1q2w3e4r5t6y", out, sizeof(out)));
    assert(!strcmp(out, "zs1 q2w3 e4r5 t6y"));
    /* The prefix stays whole on every network; an address without one is grouped from its start. */
    assert(wallet_view_group_address("zregtestsapling1qpzry9x8gf2tvdw0s3jn54khce6mua7l", out, sizeof(out)));
    assert(!strcmp(out, "zregtestsapling1 qpzr y9x8 gf2t vdw0 s3jn 54kh ce6m ua7l"));
    assert(wallet_view_group_address("zs1qpzry", out, sizeof(out)) && !strcmp(out, "zs1 qpzr y"));
    assert(wallet_view_group_address("zs1", out, sizeof(out)) && !strcmp(out, "zs1"));
    assert(wallet_view_group_address("t1Xyz1abcdefg", out, sizeof(out)) && !strcmp(out, "t1Xy z1ab cdef g"));
    assert(!wallet_view_group_address("zs1qpzry", out, 10) && wallet_view_group_address("zs1qpzry", out, 11));
    /* Ten bytes hold "abcd efgh" plus its NUL; nine do not. */
    assert(!wallet_view_group_address("abcdefgh", out, 9));
    assert(wallet_view_group_address("abcdefgh", out, 10));
    assert(!wallet_view_group_address("", out, sizeof(out)) && out[0] == '\0');
    assert(!wallet_view_group_address(NULL, out, sizeof(out)) && out[0] == '\0');
    assert(!wallet_view_group_address("ab cd", out, sizeof(out)) && out[0] == '\0');
    assert(!wallet_view_group_address("ab\tcd", out, sizeof(out)) && out[0] == '\0');
    printf("  address grouping in blocks of four, malformed input refused\n");
}

/* The parsed reply is overwritten before it is freed: text in it is not left in the heap or the program's data. */
static void test_reply_text_is_wiped(void)
{
    static const char marker[] = "wallet-view-tree-marker-4f1c9e";
    char json[2048], planted[128];
    struct wallet_view v;
    snprintf(planted, sizeof(planted), "pad to pass the header %s", marker);
    replace_once(json, sizeof(json), VALID_REPLY, "\"spendable_zat\"", "\"note\":\"pad to pass the header wallet-view-tree-marker-4f1c9e\",\"spendable_zat\"");
    static char *volatile held;                       /* escapes, so the copy is really made */
    held = strdup(planted);
    assert(held && process_holds(marker));            /* the check sees text that is there */
    memory_cleanse(held, strlen(held));
    free(held);
    held = NULL;
    assert(!process_holds(marker));
    assert(wallet_view_from_summary(json, &v) && v.known);
    memory_cleanse(json, sizeof(json));
    memory_cleanse(planted, sizeof(planted));
    assert(!process_holds(marker));
}

/* Confirmed funds a send would refuse for now, and the total of all spendable notes, get their own lines; a node that
 * holds no viewing key hides every private amount; none of them is ever shown as zero. */
static void test_unready_total_and_hidden(void)
{
    static const char *const schema = "\"schema\":\"zcl.wallet_summary.v1\",";
    char json[2048];
    struct wallet_view v;
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"unready_zat\":5000000000,\"unready\":\"50.00000000\",\"unready_notes\":2,");
    assert(wallet_view_from_summary(json, &v) && v.known);
    assert(!strcmp(v.unready_line, "50 ZCL received, not spendable yet") && !v.total_line[0]);
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"unready_zat\":0,\"unready\":\"0.00000000\","
                 "\"spendable_total_zat\":900000000,\"spendable_total\":\"9.00000000\",");
    assert(wallet_view_from_summary(json, &v) && !v.unready_line[0]);
    assert(!strcmp(v.balance, "9 ZCL") && !strcmp(v.total_line, "You can send up to 1.23456789 ZCL at once, fee included"));
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"spendable_total_zat\":123456789,\"spendable_total\":\"1.23456789\",");
    assert(wallet_view_from_summary(json, &v) && !v.total_line[0] && !v.unready_line[0] && !strcmp(v.balance, "1.23456789 ZCL"));
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"spendable_total_zat\":5,\"spendable_total\":\"0.00000005\",");
    /* Corrected expectation: a spendable amount above the total cannot come from the node, so the reply is malformed and every amount is unknown. */
    assert(!wallet_view_from_summary(json, &v));
    assert_unknown(&v);
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"unready_zat\":null,\"unready\":null,");
    assert(wallet_view_from_summary(json, &v) && v.known && !strcmp(v.unready_line, "Funds received but not spendable yet: amount unknown"));
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"unready_zat\":5,\"unready\":\"0.5\",");
    assert(!wallet_view_from_summary(json, &v));
    assert_unknown(&v);
    replace_once(json, sizeof(json), VALID_REPLY, schema,
                 "\"schema\":\"zcl.wallet_summary.v1\",\"spendable_total_zat\":-1,\"spendable_total\":\"x\",");
    assert(!wallet_view_from_summary(json, &v));
    assert(!strstr(v.unready_line, " 0 ZCL"));
    printf("  unready and total lines\n");
}

/* A locked wallet with no viewing key hides every private amount and still reports the public ones. */
static void test_hidden_private_amounts(void)
{
    static const char *const schema = "\"schema\":\"zcl.wallet_summary.v1\",";
    char json[2048];
    struct wallet_view v;
    static const char hidden[] =
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":\"keys_unavailable\","
        "\"spendable_zat\":null,\"spendable\":null,\"pending_zat\":null,\"pending\":null,\"pending_notes\":null,"
        "\"pending_min_confirmations_needed\":null,\"unready_zat\":null,\"unready\":null,\"unready_notes\":null,"
        "\"public_zat\":10000000,\"public\":\"0.10000000\",\"immature_zat\":0,\"immature\":\"0.00000000\","
        "\"tip_height\":3000000,\"header_height\":3000000,\"scanned_through_height\":null,\"blocks_behind\":0,"
        "\"current\":false,\"locked\":true,\"encrypted\":true,\"shielded_keys\":0,\"send_allowed\":false,"
        "\"send_blocked_reason\":\"progress_store_unavailable\"}}";
    assert(wallet_view_from_summary(hidden, &v) && v.known);
    assert(!strcmp(v.balance, "Your private balance is hidden because the wallet is locked") && !strstr(v.balance, "ZCL"));
    assert(!v.pending[0] && !v.unready_line[0] && !v.total_line[0] && !v.current && v.scanning);
    assert(!strcmp(v.sync, "The wallet is locked, so private amounts are not shown"));
    /* Blocks behind keep the updating wording while locked: the public amounts may still change. */
    replace_once(json, sizeof(json), hidden, "\"blocks_behind\":0,", "\"blocks_behind\":500,");
    assert(wallet_view_from_summary(json, &v) && !strcmp(v.sync, "Updating your wallet. Amounts may change."));
    assert(!strncmp(v.public_line, "0.1 ZCL public", 14));
    assert(!strncmp(v.public_line, "0.1 ZCL public", 14));
    replace_once(json, sizeof(json), VALID_REPLY, schema, "\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":\"bogus\",");
    assert(!wallet_view_from_summary(json, &v));
    replace_once(json, sizeof(json), VALID_REPLY, schema, "\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":7,");
    assert(!wallet_view_from_summary(json, &v));
    replace_once(json, sizeof(json), VALID_REPLY, schema, "\"schema\":\"zcl.wallet_summary.v1\",\"shielded_state\":\"ok\",");
    assert(wallet_view_from_summary(json, &v) && v.known && !strcmp(v.balance, "1.23456789 ZCL"));
    printf("  hidden private amounts\n");
}

int main(void)
{
    printf("wallet view model:\n");
    test_valid_reply();
    test_empty_lines_and_singular();
    test_amount_format();
    test_immature_and_scan();
    test_sync_lines();
    test_zat_limit();
    test_send_reasons();
    test_missing_fields_are_unknown();
    test_malformed_fields_are_unknown();
    test_bad_input_is_unknown();
    test_group_address();
    test_unready_total_and_hidden();
    test_hidden_private_amounts();
    test_reply_text_is_wiped();
    printf("wallet view model: all tests passed\n");
    return 0;
}
