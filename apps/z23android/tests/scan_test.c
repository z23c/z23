/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "scan.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define HEX64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define HEX64_UPPER "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"

static char text[4096], value[4096];

static enum zapp_scan_kind scan(const char *payload)
{ return zapp_scan_classify(payload, value, sizeof(value)); }
/* Writes prefix followed by n copies of c into text. */
static void repeat(const char *prefix, char c, size_t n)
{
    size_t p = strlen(prefix);
    memcpy(text, prefix, p);
    memset(text + p, c, n);
    text[p + n] = 0;
}
static bool has_control(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
        if (*p < 0x20 || *p == 0x7f) return true;
    return false;
}
/* The payload has the shape of a secret: it is refused and none of it is returned for display. */
static bool unreadable(const char *payload)
{
    memset(value, 'x', sizeof(value) - 1); value[sizeof(value) - 1] = 0;
    return zapp_scan_classify(payload, value, sizeof(value)) == ZAPP_SCAN_UNREADABLE && !value[0];
}
static void typed_addresses(void)
{
    repeat("z23:clip:", 'a', 128);
    assert(scan(text) == ZAPP_SCAN_CLIP && !strcmp(value, text + 9));
    repeat("z23:author:", '0', 64);
    assert(scan(text) == ZAPP_SCAN_AUTHOR && !strcmp(value, text + 11));
    repeat("z23:rater:", '9', 64);
    assert(scan(text) == ZAPP_SCAN_RATER && !strcmp(value, text + 10));
}
static void wrong_lengths(void)
{
    repeat("z23:clip:", 'a', 127); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:clip:", 'a', 129); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:author:", '0', 63); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:author:", '0', 65); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:rater:", '9', 63); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:rater:", '9', 65); assert(scan(text) == ZAPP_SCAN_TEXT);
}
static void uppercase_hex(void)
{
    repeat("z23:clip:", 'A', 128); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:author:", 'F', 64); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23:rater:", 'g', 64); assert(scan(text) == ZAPP_SCAN_TEXT);
}
static void descriptors(void)
{
    snprintf(text, sizeof(text), "z23:pair:{\"port\":8770,\"token\":\"%s\"}", HEX64);
    assert(scan(text) == ZAPP_SCAN_PAIR && !strcmp(value, text + 9));
    snprintf(text, sizeof(text), "z23:pair:{\"port\":0,\"token\":\"%s\"}", HEX64);
    assert(unreadable(text));
    snprintf(text, sizeof(text), "z23:pair:{\"port\":8770,\"token\":\"%s\"}", HEX64_UPPER);
    assert(unreadable(text));
    snprintf(text, sizeof(text), "z23:pair:{\"port\":8770,\"token\":\"%.63s\"}", HEX64);
    assert(unreadable(text));
    snprintf(text, sizeof(text), "z23:pair:{\"port\":8770,\n\"token\":\"%s\"}", HEX64);
    assert(unreadable(text));
    snprintf(text, sizeof(text), "z23:pair:{\"port\":8770,\"token\":\"%s\",\"extra\":1}", HEX64);
    assert(unreadable(text));
}
static void fleet_invitations(void)
{
    repeat("z23 fleet join ", 'a', 200);
    assert(scan(text) == ZAPP_SCAN_FLEET && !strcmp(value, text + 15));
    repeat("", 'a', 128);
    assert(scan(text) == ZAPP_SCAN_FLEET && !strcmp(value, text));
    repeat("", 'a', 127); assert(scan(text) == ZAPP_SCAN_TEXT);
    repeat("z23 fleet join ", 'a', 127); assert(unreadable(text));
    repeat("z23 fleet join ", 'a', 2400); assert(unreadable(text));
    repeat("z23 fleet join ", 'a', 150); text[40] = '\n'; assert(unreadable(text));
    repeat("", 'a', 2333); assert(unreadable(text));
    repeat("", 'a', 200); text[100] = '.'; assert(scan(text) == ZAPP_SCAN_TEXT);
}
/* Spacing, case and a missing prefix do not turn a secret into text for display. */
static void loosely_written_secrets(void)
{
    char token[201];
    memset(token, 'a', 200); token[200] = 0;
    snprintf(text, sizeof(text), "%s\n", token); assert(unreadable(text));
    snprintf(text, sizeof(text), " z23 fleet join %s", token); assert(unreadable(text));
    snprintf(text, sizeof(text), "Z23 FLEET JOIN %s", token); assert(unreadable(text));
    snprintf(text, sizeof(text), "z23\tfleet\njoin %s", token); assert(unreadable(text));
    snprintf(text, sizeof(text), "%.100s %s", token, token + 100); assert(unreadable(text));
    snprintf(text, sizeof(text), "%.100s\n%s", token, token + 100); assert(unreadable(text));
    snprintf(text, sizeof(text), "%.100s\x01%s", token, token + 100); assert(unreadable(text));
    snprintf(text, sizeof(text), "Z23:PAIR:{\"port\":8770,\"token\":\"%s\"}", HEX64); assert(unreadable(text));
    snprintf(text, sizeof(text), " z23:pair:{\"port\":8770,\"token\":\"%s\"}", HEX64); assert(unreadable(text));
    snprintf(text, sizeof(text), "{\"port\":8770,\"token\":\"%s\"}", HEX64); assert(unreadable(text));
    snprintf(text, sizeof(text), "{\"port\":8770, \"TOKEN\" : \"%s\"}", HEX64); assert(unreadable(text));
    assert(unreadable("z23 fleet join short") && unreadable("z23\nfleet join short") && unreadable("Z23: PAIR:{}"));
    snprintf(text, sizeof(text), "see https://example.com/%.60s", token); assert(scan(text) == ZAPP_SCAN_TEXT);
}
static void other_text(void)
{
    snprintf(text, sizeof(text), "https://example.com/pay?to=zs1qqqqqqqqqqqqqqqqqqqqqqqq");
    assert(scan(text) == ZAPP_SCAN_TEXT && !strcmp(value, text));
    /* a bare run with the shape of an address that the parser refuses is a refusal, not shown text */
    snprintf(text, sizeof(text), "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    assert(scan(text) == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, "zs1q"));
    assert(scan("") == ZAPP_SCAN_TEXT && value[0] == 0);
}
static void control_bytes(void)
{
    repeat("z23:clip:", 'a', 128);
    text[20] = '\n';
    assert(scan(text) == ZAPP_SCAN_TEXT && value[20] == '?' && !has_control(value));
    snprintf(text, sizeof(text), "hello\x01world");
    assert(scan(text) == ZAPP_SCAN_TEXT && !strcmp(value, "hello?world"));
}
static void small_buffers(void)
{
    char small[129];
    repeat("z23:clip:", 'a', 128);
    assert(zapp_scan_classify(text, small, 128) == ZAPP_SCAN_TEXT && strlen(small) < 128);
    assert(zapp_scan_classify(text, small, 129) == ZAPP_SCAN_CLIP);
    repeat("z23 fleet join ", 'a', 200);
    assert(zapp_scan_classify(text, small, 128) == ZAPP_SCAN_UNREADABLE && !small[0]);
    assert(zapp_scan_classify(text, small, 0) == ZAPP_SCAN_TEXT);
    assert(zapp_scan_classify(NULL, small, sizeof(small)) == ZAPP_SCAN_TEXT);
}
/* A payment code opens the send review and does nothing else; a refused one says why; other text is untouched. */
static void payment_codes(void)
{
    char addr[ZAPP_PAY_ADDRESS_MAX], uri[512];
    struct zapp_payment pay;
    memcpy(addr, "zs1", 3); memset(addr + 3, 'q', 75); addr[78] = 0;
    assert(scan(addr) == ZAPP_SCAN_PAY && !value[0]);
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=1.5&memo=aGk", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY && !value[0]);
    assert(zapp_scan_payment(uri, &pay) == ZAPP_PAY_OK && pay.amount_zat == 150000000);
    snprintf(uri, sizeof(uri), "ZClassic:%s?amount=1", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY);
    char pub[ZAPP_PAY_ADDRESS_MAX];
    memcpy(pub, "t1", 2); memset(pub + 2, '2', 33); pub[35] = 0;
    assert(scan(pub) == ZAPP_SCAN_PAY);
    /* refused, never partly honoured, and the reason holds no part of the code */
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=1&req-x=1", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && strstr(value, "does not support") && !strstr(value, addr));
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=1.123456789", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && strstr(value, "8 decimal places"));
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=1&memo=aGk", pub);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && strstr(value, "memo"));
    char test[ZAPP_PAY_ADDRESS_MAX];
    memcpy(test, "ztestsapling1", 13); memset(test + 13, 'q', 75); test[88] = 0;
    assert(scan(test) == ZAPP_SCAN_PAY_REFUSED && strstr(value, "another network"));
    assert(scan("zclassic:nonsense") == ZAPP_SCAN_PAY_REFUSED && value[0]);
    assert(zapp_scan_refusal_text(ZAPP_PAY_OK)[0] == 0);
    for (int r = ZAPP_PAY_REFUSE_INPUT_TOO_LONG; r <= ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG; ++r)
        assert(strstr(zapp_scan_refusal_text((enum zapp_pay_refusal)r), "Nothing was done."));
    /* text that is not a payment code keeps what it was */
    assert(scan("hello world") == ZAPP_SCAN_TEXT && !strcmp(value, "hello world"));
    assert(scan("t1 is a short word") == ZAPP_SCAN_TEXT);
    assert(scan("t1abc") == ZAPP_SCAN_TEXT && !strcmp(value, "t1abc"));
    assert(scan("https://example.org/zclassic") == ZAPP_SCAN_TEXT);
    /* a long run that starts like an address is not read as a payment code */
    repeat("t1", 'a', 200);
    assert(scan(text) != ZAPP_SCAN_PAY && scan(text) != ZAPP_SCAN_PAY_REFUSED);
}

/* A payload with the scheme or the shape of an address that the parser refuses stays refused. Control bytes
 * around or inside it never turn it into text that reaches Home. */
static void refused_payments_never_become_text(void)
{
    char addr[ZAPP_PAY_ADDRESS_MAX], uri[512], mixed[512];
    memcpy(addr, "zs1", 3); memset(addr + 3, 'q', 75); addr[78] = 0;
    snprintf(uri, sizeof(uri), "zclassic:%s?amount=1\n", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, addr));
    snprintf(uri, sizeof(uri), "%s\n", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, addr));
    snprintf(uri, sizeof(uri), "%s\t ", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && !strstr(value, addr));
    snprintf(uri, sizeof(uri), " %s", addr);
    assert(scan(uri) != ZAPP_SCAN_TEXT);
    snprintf(mixed, sizeof(mixed), "zs1qqqqqqqq\x01%s", addr + 11);
    assert(scan(mixed) == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "qqqqqqqq"));
    snprintf(uri, sizeof(uri), "zclassic:\x7f%s?amount=1", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED);
    snprintf(uri, sizeof(uri), "ZCLASSIC:%s?amount=1\r\n", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && !strstr(value, addr));
    /* an address the parser knows is for another network is refused, with or without a stray byte */
    char test[ZAPP_PAY_ADDRESS_MAX];
    memcpy(test, "ztestsapling1", 13); memset(test + 13, 'q', 75); test[88] = 0;
    snprintf(uri, sizeof(uri), "%s\n", test);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED);
    /* a bare run that starts like an address but is not one is refused with a reason, not shown */
    assert(scan("zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqq") == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "zs1q"));
    /* a leading control byte or space, and upper case prefixes, do not turn a payment code into text */
    snprintf(uri, sizeof(uri), "\n %s", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, addr));
    snprintf(uri, sizeof(uri), "\x01\x02 zclassic:%s?amount=1", addr);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && !strstr(value, addr));
    char upper[ZAPP_PAY_ADDRESS_MAX];
    memcpy(upper, "ZS1", 3); memset(upper + 3, 'Q', 75); upper[78] = 0;
    assert(scan(upper) == ZAPP_SCAN_PAY_REFUSED && value[0] && !strstr(value, "ZS1"));
    snprintf(uri, sizeof(uri), "\n %s\n", upper);
    assert(scan(uri) == ZAPP_SCAN_PAY_REFUSED && !strstr(value, "ZS1"));
    char pubup[ZAPP_PAY_ADDRESS_MAX];
    memcpy(pubup, "T1", 2); memset(pubup + 2, '2', 33); pubup[35] = 0;
    assert(scan(pubup) == ZAPP_SCAN_PAY_REFUSED);
    /* sentences and short words that happen to start like an address stay text */
    assert(scan("tm is a long sentence with many words in it") == ZAPP_SCAN_TEXT);
    assert(scan("t1 and zs1 are prefixes of addresses") == ZAPP_SCAN_TEXT);
}

int main(void)
{
    typed_addresses();
    payment_codes();
    refused_payments_never_become_text();
    wrong_lengths();
    uppercase_hex();
    descriptors();
    fleet_invitations();
    loosely_written_secrets();
    other_text();
    control_bytes();
    small_buffers();
    puts("scan classification tests passed");
    return 0;
}
