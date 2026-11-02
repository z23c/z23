/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PAYMENT_NOTICE_H
#define ZAPP_PAYMENT_NOTICE_H

/* How a payment ended, as the notification says it. UNKNOWN is a commit with no usable answer: the payment may have
 * been sent, so it is never worded as "not sent". */
enum zapp_payment_result { ZAPP_PAYMENT_SENT, ZAPP_PAYMENT_NOT_SENT, ZAPP_PAYMENT_UNKNOWN };

/* The title shown on the lock screen in place of the full notification. It names no amount, address or outcome. */
#define ZAPP_PAYMENT_PUBLIC_TITLE "Z23 payment update"

struct zapp_payment_notice {
    const char *title;  /* the notification, when the phone is unlocked */
    const char *text;
};

/* The words of a notification. Neither carries an amount or an address. */
struct zapp_payment_notice zapp_payment_notice_of(enum zapp_payment_result result);
#endif
