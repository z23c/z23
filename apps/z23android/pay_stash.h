/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PAY_STASH_H
#define ZAPP_PAY_STASH_H
#include "scan.h"
#include <stdbool.h>

/* The hand-over of a scanned payment from the scan to the send screen. The controller reads a code on its worker,
 * and the payment it holds (an address, an amount, a memo) must not enter the view the app shows on Home. This
 * one-slot holder keeps the payment from the moment the code is classified until the shell takes it, and wipes it
 * when taken, when another scan begins and when the app is destroyed. It is guarded by a mutex and holds nothing
 * else. */

/* Empties the slot. Call when a scan begins. */
void zapp_pay_stash_clear(void);
/* Holds the payment of a scanned payload when kind is ZAPP_SCAN_PAY; any other kind empties the slot. Call with the
 * payload before it is replaced by the notice. True when a payment is now held. */
bool zapp_pay_stash_offer(const char *payload, enum zapp_scan_kind kind);
/* Moves the held payment into out and wipes the slot. False, with out zeroed, when none is held. */
bool zapp_pay_stash_take(struct zapp_payment *out);

#endif
