/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "scan.h"
#include "fleet.h"
#include "speech_client.h"
#include <ctype.h>
#include <stdbool.h>
#include <string.h>

/* Copies text into value only when it fits with its terminator. */
static bool fits(char *value, size_t cap, const char *text)
{
    size_t n = strlen(text);
    if (n >= cap) return false;
    memcpy(value, text, n + 1);
    return true;
}
/* True when text is exactly digits characters, each a lowercase hex digit. */
static bool lower_hex(const char *text, size_t digits)
{
    if (strlen(text) != digits) return false;
    for (size_t i = 0; i < digits; ++i) {
        bool digit = text[i] >= '0' && text[i] <= '9';
        bool letter = text[i] >= 'a' && text[i] <= 'f';
        if (!digit && !letter) return false;
    }
    return true;
}
static bool control_free(const char *payload)
{
    for (const unsigned char *p = (const unsigned char *)payload; *p; ++p)
        if (*p < 0x20 || *p == 0x7f) return false;
    return true;
}
/* A typed address: its prefix, then exactly digits lowercase hex digits. */
static bool typed_hex(const char *payload, const char *prefix, size_t digits, char *value, size_t cap)
{
    size_t n = strlen(prefix);
    if (strncmp(payload, prefix, n)) return false;
    return lower_hex(payload + n, digits) && fits(value, cap, payload + n);
}
/* A laptop pairing descriptor, checked by the rule the phone applies to a pairing it stores. */
static bool typed_pair(const char *payload, char *value, size_t cap)
{
    static const char prefix[] = "z23:pair:";
    size_t n = sizeof(prefix) - 1;
    if (strncmp(payload, prefix, n)) return false;
    const char *descriptor = payload + n;
    return zapp_speech_client_descriptor_valid(descriptor, strlen(descriptor)) && fits(value, cap, descriptor);
}
/* Copies the payload for display: control bytes become '?' and the text is cut to fit cap. */
static void display_text(char *value, size_t cap, const char *payload)
{
    size_t i = 0;
    for (; i + 1 < cap && payload[i]; ++i) {
        unsigned char c = (unsigned char)payload[i];
        value[i] = c < 0x20 || c == 0x7f ? '?' : payload[i];
    }
    value[i] = 0;
}
static bool ignorable(unsigned char c) { return c <= 0x20 || c == 0x7f; }
/* Whether text, skipping whitespace and control bytes and ignoring case, starts with prefix (which holds none). */
static bool starts_loosely(const char *text, const char *prefix)
{
    for (; *prefix; ++prefix, ++text) {
        while (*text && ignorable((unsigned char)*text)) ++text;
        if (tolower((unsigned char)*text) != *prefix) return false;
    }
    return true;
}
/* Whether the payload has the shape of a laptop pairing descriptor or a fleet invitation, valid or not:
 * its prefix, a "token" field, or a bare run of 128 or more token characters, however it is spaced or cased. */
static bool secret_shaped(const char *payload)
{
    size_t run = 0;
    bool token_chars = true;
    if (starts_loosely(payload, "z23:pair:") || starts_loosely(payload, "z23fleetjoin")) return true;
    for (const char *p = payload; *p; ++p) {
        if (starts_loosely(p, "\"token\"")) return true;
        if (ignorable((unsigned char)*p)) continue;
        token_chars = token_chars && zapp_fleet_invite_char(*p);
        ++run;
    }
    return token_chars && run >= 128;
}

enum zapp_scan_kind zapp_scan_classify(const char *payload, char *value, size_t cap)
{
    if (!payload || !value || !cap) return ZAPP_SCAN_TEXT;
    value[0] = 0;
    if (control_free(payload)) {
        if (typed_hex(payload, "z23:clip:", 128, value, cap)) return ZAPP_SCAN_CLIP;
        if (typed_hex(payload, "z23:author:", 64, value, cap)) return ZAPP_SCAN_AUTHOR;
        if (typed_hex(payload, "z23:rater:", 64, value, cap)) return ZAPP_SCAN_RATER;
        if (typed_pair(payload, value, cap)) return ZAPP_SCAN_PAIR;
        if (zapp_fleet_invite_text(payload, value, cap)) return ZAPP_SCAN_FLEET;
    }
    if (secret_shaped(payload)) return ZAPP_SCAN_UNREADABLE;
    display_text(value, cap, payload);
    return ZAPP_SCAN_TEXT;
}
