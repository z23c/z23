/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "scan.h"
#include "fleet.h"
#include "speech_client.h"
#include "base/cleanse.h"
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

/* ---- payment codes ---- */

static bool starts_ci(const char *text, const char *prefix)
{
    for (; *prefix; ++prefix, ++text)
        if (tolower((unsigned char)*text) != *prefix) return false;
    return true;
}
static const unsigned char *skip_blank(const unsigned char *p)
{
    while (*p == ' ' || (*p && *p < 0x20) || *p == 0x7f) ++p;
    return p;
}
/* Copies the letters and digits of a bare payload into run, skipping control bytes and spaces around it. Returns
 * the length, or 0 when anything else is in the way. */
static size_t bare_run(const char *payload, char run[ZAPP_PAY_ADDRESS_MAX])
{
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)payload;
    p = skip_blank(p);
    for (; *p; ++p) {
        if (*p < 0x20 || *p == 0x7f) continue;
        if (*p == ' ') {
            while (*p && (*p == ' ' || *p < 0x20 || *p == 0x7f)) ++p;
            break;
        }
        if (!isalnum(*p) || n + 1 >= ZAPP_PAY_ADDRESS_MAX) return 0;
        run[n++] = (char)*p;
    }
    if (*p) return 0;
    run[n] = 0;
    return n;
}
/* Whether the payload is meant as a payment: a zclassic: request, or a run of letters and digits that starts
 * as an address does. Control bytes inside the run and spaces around it are skipped, so they cannot hide the
 * shape. Any other text, including a short word that begins with "t1", is not. */
static bool payment_shaped(const char *payload)
{
    static const char *const starts[] = {"zs1", "ztestsapling1", "zregtestsapling1", "t1", "t2", "t3", "tm"};
    char run[ZAPP_PAY_ADDRESS_MAX];
    if (starts_loosely(payload, "zclassic:")) return true;
    if (bare_run(payload, run) < 26) return false;
    for (size_t i = 0; i < sizeof(starts) / sizeof(starts[0]); ++i)
        if (starts_ci(run, starts[i])) return true;
    return false;
}
const char *zapp_scan_refusal_text(enum zapp_pay_refusal refusal)
{
    static const char *const text[] = {
        [ZAPP_PAY_OK] = "",
        [ZAPP_PAY_REFUSE_INPUT_TOO_LONG] = "This payment code is too long. Nothing was done.",
        [ZAPP_PAY_REFUSE_EMBEDDED_NUL] = "This payment code has hidden characters. Nothing was done.",
        [ZAPP_PAY_REFUSE_MALFORMED] = "This is not a payment code this wallet can read. Nothing was done.",
        [ZAPP_PAY_REFUSE_BAD_ADDRESS] = "The address in this code is not a ZClassic address. Nothing was done.",
        [ZAPP_PAY_REFUSE_WRONG_NETWORK] = "The address in this code is for another network. Nothing was done.",
        [ZAPP_PAY_REFUSE_UNKNOWN_REQUIRED] = "This code asks for something this wallet does not support. Nothing was done.",
        [ZAPP_PAY_REFUSE_MULTIPLE] = "This code asks for more than one payment. Nothing was done.",
        [ZAPP_PAY_REFUSE_DUPLICATE] = "This payment code repeats a field. Nothing was done.",
        [ZAPP_PAY_REFUSE_AMOUNT_FORMAT] = "The amount in this code is not a plain number. Nothing was done.",
        [ZAPP_PAY_REFUSE_AMOUNT_PRECISION] = "The amount in this code has more than 8 decimal places. Nothing was done.",
        [ZAPP_PAY_REFUSE_AMOUNT_RANGE] = "The amount in this code is more than can exist. Nothing was done.",
        [ZAPP_PAY_REFUSE_MEMO_ON_PUBLIC] = "This code puts a memo on a public address, which cannot carry one. Nothing was done.",
        [ZAPP_PAY_REFUSE_MEMO_ENCODING] = "The memo in this code is not readable. Nothing was done.",
        [ZAPP_PAY_REFUSE_MEMO_TOO_LONG] = "The memo in this code is too long. Nothing was done.",
        [ZAPP_PAY_REFUSE_PERCENT] = "This payment code is damaged. Nothing was done.",
        [ZAPP_PAY_REFUSE_LABEL_INVALID] = "The label or message in this code is not readable. Nothing was done.",
        [ZAPP_PAY_REFUSE_LABEL_TOO_LONG] = "The label or message in this code is not readable. Nothing was done.",
        [ZAPP_PAY_REFUSE_MESSAGE_INVALID] = "The label or message in this code is not readable. Nothing was done.",
        [ZAPP_PAY_REFUSE_MESSAGE_TOO_LONG] = "The label or message in this code is not readable. Nothing was done.",
    };
    bool known = (unsigned)refusal < sizeof(text) / sizeof(text[0]) && text[refusal];
    return known ? text[refusal] : "This payment code was refused. Nothing was done.";
}
enum zapp_pay_refusal zapp_scan_payment(const char *payload, struct zapp_payment *out)
{
    return zapp_payment_parse(payload, strlen(payload), ZAPP_SCAN_NETWORK, out);
}
/* A payment-shaped payload opens the send review when the parser accepts it and is refused, with the reason,
 * otherwise: it never falls through to plain text. The parser sees the payload as scanned, so a stray
 * control byte refuses it. A payment code opens the send review and does nothing else. The parsed
 * payment holds an address, so it is cleansed here and value never carries it. */
static enum zapp_scan_kind classify_payment(const char *payload, char *value, size_t cap)
{
    struct zapp_payment pay;
    enum zapp_pay_refusal why = zapp_scan_payment(payload, &pay);
    memory_cleanse(&pay, sizeof(pay));
    value[0] = 0;
    if (why == ZAPP_PAY_OK) return ZAPP_SCAN_PAY;
    (void)fits(value, cap, zapp_scan_refusal_text(why));
    return ZAPP_SCAN_PAY_REFUSED;
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
    if (payment_shaped(payload)) return classify_payment(payload, value, cap);
    if (secret_shaped(payload)) return ZAPP_SCAN_UNREADABLE;
    display_text(value, cap, payload);
    return ZAPP_SCAN_TEXT;
}
