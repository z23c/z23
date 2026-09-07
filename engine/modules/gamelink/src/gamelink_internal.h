/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal shape shared by the three gamelink translation units: the parsed
 * header, the codec, and the constant-time helpers. Not installed and not
 * part of the module's contract — engine/modules/gamelink/include/gamelink/
 * gamelink.h is. */

#ifndef ZCL_GAMELINK_INTERNAL_H
#define ZCL_GAMELINK_INTERNAL_H

#include "gamelink/gamelink.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The header as fields. Every one of them is big-endian on the wire and is
 * covered by the AEAD as additional data. */
struct gamelink_header {
    uint64_t session_id;
    uint64_t seq;
    uint64_t ack;      /* highest sequence the sender has accepted */
    uint32_t ack_bits; /* the 32 sequences below `ack`, bit 0 = ack-1 */
    uint8_t flags;
};

/* Byte-equality that does not branch on the bytes. Used on the magic and
 * version so a probe cannot time its way to "which field was wrong". */
bool gamelink_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Serialize the header into exactly GAMELINK_HEADER_BYTES bytes. */
void gamelink_wire_put_header(uint8_t out[GAMELINK_HEADER_BYTES],
                              const struct gamelink_header *header);

/* Parse a header from the front of a datagram. Every bound is checked before
 * any field is read; returns false on a short buffer, wrong magic, wrong
 * version, or a non-zero reserved byte. The caller counts the refusal — this
 * function never logs, because an open UDP port receives whatever the
 * internet feels like sending and a log line per packet is a denial of
 * service somebody else controls. */
bool gamelink_wire_parse_header(const uint8_t *in, size_t len,
                                struct gamelink_header *out);

/* Seal `payload` under `key` with the header as additional data and the
 * header's sequence number as the AEAD nonce. Writes header + ciphertext +
 * tag to `out` and the total length to `*out_len`. `out` must hold at least
 * GAMELINK_MAX_DATAGRAM bytes. */
bool gamelink_wire_seal(const uint8_t key[32],
                        const struct gamelink_header *header,
                        const uint8_t *payload, size_t len, uint8_t *out,
                        size_t *out_len);

/* Open one datagram: parse the header, verify the tag over it, and write the
 * plaintext to `payload_out` (which must hold GAMELINK_MAX_PAYLOAD bytes).
 * `*status` says which counter the caller should raise on a refusal. */
enum gamelink_open_result {
    GAMELINK_WIRE_OK = 0,
    GAMELINK_WIRE_MALFORMED,
    GAMELINK_WIRE_AUTH
};
enum gamelink_open_result gamelink_wire_open(const uint8_t key[32],
                                             const uint8_t *in, size_t in_len,
                                             struct gamelink_header *header,
                                             uint8_t *payload_out,
                                             size_t *payload_len);

/* Monotonic nanoseconds from the session's injected clock. */
int64_t gamelink_now_ns(const struct gamelink *link);

#endif /* ZCL_GAMELINK_INTERNAL_H */
