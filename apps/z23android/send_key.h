/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SEND_KEY_H
#define ZAPP_SEND_KEY_H
#include "payment_code.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The idempotency key of a payment request. The same wallet asked for the same address, amount and memo
 * always derives the same key, so a payment code scanned twice reaches the node with one key and the node's
 * send-once table, not the phone, says whether it was paid. A different address, amount, memo or wallet
 * gives a different key.
 * The recognition lasts as long as the node keeps its record: it deletes a committed record 90 days after its
 * creation (an unresolved one after 365 days) by its own clock, and it answers a replay only while its wallet still
 * holds the transaction. After that, or after a forward jump of the node's clock past those limits, the same
 * code is a new payment; it still needs a full review and a new authentication before anything is sent. The key is the first 16 bytes of
 *   SHA3-256("z23-pay-v1" || wallet id || len(address) || address || amount in zatoshi || len(memo) || memo)
 * in lowercase hex, which the node accepts (letters and digits, 1 to 128 characters).
 * The wallet id is 32 random bytes made once and kept next to the wallet; it is not a secret that unlocks
 * anything, and it keeps one wallet's keys from matching another's. */

#define ZAPP_SEND_KEY_ID 32u
#define ZAPP_SEND_KEY_HEX 32u

struct zapp_send_id { uint8_t bytes[ZAPP_SEND_KEY_ID]; };

/* Reads <dir>/wallet_id, or makes it on first use. False when the file cannot be read or written, or has
 * another size: the caller then sends nothing, because a key from a lost id could not match the earlier one. */
bool zapp_send_id_load(const char *dir, struct zapp_send_id *id);

/* Writes the key of pay into out as ZAPP_SEND_KEY_HEX characters and a NUL. False when pay has no amount. */
bool zapp_send_key_derive(const struct zapp_send_id *id, const struct zapp_payment *pay, char out[ZAPP_SEND_KEY_HEX + 1]);

#endif
