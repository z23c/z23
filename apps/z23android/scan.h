/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_SCAN_H
#define Z23_ANDROID_SCAN_H
#include "payment_code.h"
#include <stddef.h>

/* The network whose addresses a scanned payment code may name. */
#ifndef ZAPP_SCAN_NETWORK
#define ZAPP_SCAN_NETWORK ZAPP_PAY_MAINNET
#endif

enum zapp_scan_kind { ZAPP_SCAN_TEXT, ZAPP_SCAN_FLEET, ZAPP_SCAN_PAIR, ZAPP_SCAN_CLIP, ZAPP_SCAN_AUTHOR,
    ZAPP_SCAN_RATER, ZAPP_SCAN_UNREADABLE,
    /* A payment code that payment_code.h accepts: it opens the send review, nothing else. value is empty. */
    ZAPP_SCAN_PAY,
    /* A payment code that payment_code.h refuses: value is the reason in plain words. */
    ZAPP_SCAN_PAY_REFUSED };

/* Classifies a scanned payload. Nothing is opened, fetched or paid. value receives the part to act
 * on: the hex address, the pairing descriptor or the invitation token. A value that does not fit cap
 * is never acted on. A payload shaped like a pairing descriptor or an invitation (its prefix, a "token"
 * field, or 128 or more token characters, ignoring case, spacing and control bytes) that is not one is
 * UNREADABLE with an empty value, so a secret is never returned for display. Any other text is TEXT with
 * control bytes replaced, cut to fit cap. */
enum zapp_scan_kind zapp_scan_classify(const char *payload, char *value, size_t cap);

/* Reads a payment code accepted by zapp_scan_classify as ZAPP_SCAN_PAY. The payment holds an address, so the
 * caller hands it to the send review and cleanses it; it is never shown on Home or logged. */
enum zapp_pay_refusal zapp_scan_payment(const char *payload, struct zapp_payment *out);
/* The plain-words sentence for a refusal. */
const char *zapp_scan_refusal_text(enum zapp_pay_refusal refusal);
#endif
