/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_SCAN_H
#define Z23_ANDROID_SCAN_H
#include <stddef.h>

enum zapp_scan_kind { ZAPP_SCAN_TEXT, ZAPP_SCAN_FLEET, ZAPP_SCAN_PAIR, ZAPP_SCAN_CLIP, ZAPP_SCAN_AUTHOR,
    ZAPP_SCAN_RATER, ZAPP_SCAN_UNREADABLE };

/* Classifies a scanned payload. Nothing is opened, fetched or paid. value receives the part to act
 * on: the hex address, the pairing descriptor or the invitation token. A value that does not fit cap
 * is never acted on. A payload shaped like a pairing descriptor or an invitation (its prefix, a "token"
 * field, or 128 or more token characters, ignoring case, spacing and control bytes) that is not one is
 * UNREADABLE with an empty value, so a secret is never returned for display. Any other text is TEXT with
 * control bytes replaced, cut to fit cap. */
enum zapp_scan_kind zapp_scan_classify(const char *payload, char *value, size_t cap);
#endif
