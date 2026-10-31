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
    snprintf(text, sizeof(text), "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq");
    assert(scan(text) == ZAPP_SCAN_TEXT && !strcmp(value, text));
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
int main(void)
{
    typed_addresses();
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
