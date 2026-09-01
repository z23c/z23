/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZPAY v1 — bounded payment/invoice envelopes for Sapling memos.
 *
 * This is an application overlay only.  Sapling consensus treats all 512
 * memo bytes as opaque.  An optional ZID document authenticates the envelope
 * identity; anonymous is the default and is represented explicitly. */

#ifndef ZCL_ZID_ZPAY_H
#define ZCL_ZID_ZPAY_H

#include "zid/zid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZPAY_MEMO_LEN 512
#define ZPAY_VERSION 1
#define ZPAY_PAD_BYTE 0xF6
#define ZPAY_ASSET_MAX 65

enum zpay_network {
    ZPAY_NETWORK_MAINNET = 0,
    ZPAY_NETWORK_TESTNET = 1,
    ZPAY_NETWORK_REGTEST = 2
};

enum zpay_message_type {
    ZPAY_MESSAGE_INVOICE = 1,
    ZPAY_MESSAGE_PAYMENT = 2,
    ZPAY_MESSAGE_RECEIPT = 3
};

enum zpay_sender_authentication {
    ZPAY_SENDER_ANONYMOUS = 0,
    ZPAY_SENDER_ZID_VERIFIED = 1,
    ZPAY_SENDER_ZID_INVALID = 2
};

struct zpay_envelope {
    uint8_t network;
    uint8_t message_type;
    uint64_t created_at;
    uint64_t expires_at;
    uint8_t nonce[16];
    uint8_t request_id[16];
    uint8_t invoice_digest[32];
    char asset[ZPAY_ASSET_MAX + 1];
    uint8_t amount_commitment[32];
    bool has_reply;
    uint8_t reply_ref[32];

    enum zpay_sender_authentication sender_authentication;
    bool has_identity_doc;
    struct zid_doc identity_doc;
};

/* Encode an envelope into a complete 512-byte Sapling memo.  `zid_seed` may
 * be NULL for the normal anonymous form.  When supplied, a compact ZID
 * document signs "ZPAY" || SHA3-256(canonical envelope prefix). */
bool zpay_memo_encode(uint8_t out[ZPAY_MEMO_LEN],
                      const struct zpay_envelope *envelope,
                      const uint8_t zid_seed[32]);

/* Strictly decode the canonical envelope.  Signature verification is kept
 * separate because callers need to supply their own trusted clock. */
bool zpay_memo_decode(const uint8_t memo[ZPAY_MEMO_LEN],
                      struct zpay_envelope *out);

/* Verify the optional ZID document and its binding to this exact envelope.
 * Returns ANONYMOUS for an unsigned envelope and never upgrades an invalid
 * or expired document to an authenticated sender. */
enum zpay_sender_authentication
zpay_memo_authenticate(const uint8_t memo[ZPAY_MEMO_LEN], uint64_t now_unix,
                       struct zpay_envelope *decoded_out);

/* Network and time policy check used before accepting an invoice/payment.
 * The caller owns replay tracking for request_id/nonce. */
bool zpay_envelope_is_current(const struct zpay_envelope *envelope,
                              uint8_t expected_network, uint64_t now_unix);

#endif /* ZCL_ZID_ZPAY_H */
