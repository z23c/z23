/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The gamelink datagram codec: one fixed 34-byte header, one ChaCha20-
 * Poly1305 tag, and nothing else on the wire.
 *
 *   offset  0  magic[3]    "ZGL"
 *   offset  3  version     1
 *   offset  4  session_id  8, big-endian
 *   offset 12  seq         8, big-endian — also the AEAD nonce
 *   offset 20  ack         8, big-endian — highest sequence the sender took
 *   offset 28  ack_bits    4, big-endian — the 32 sequences below `ack`
 *   offset 32  flags       1
 *   offset 33  reserved    1, must be zero
 *
 * The WHOLE header is the AEAD's additional data, so a flipped bit anywhere
 * in it — including the sequence number an attacker would want to move —
 * fails the tag rather than being accepted with a shifted meaning.
 *
 * Two rules this file exists to keep:
 *   1. Every bound is checked before any field is read. A datagram arrives
 *      from whoever felt like sending one; its length is an input.
 *   2. Nothing here logs, allocates, or returns a reason to the network.
 *      Garbage is dropped and counted. The counters are the diagnosis.
 */

#include "gamelink_internal.h"

#include "crypto/chacha20poly1305.h"

#include <string.h>

static const uint8_t k_gamelink_magic[3] = {'Z', 'G', 'L'};

bool gamelink_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b)
        return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void put_u64(uint8_t *out, uint64_t value)
{
    for (size_t i = 0; i < 8; i++)
        out[i] = (uint8_t)(value >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *in)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++)
        value = (value << 8) | in[i];
    return value;
}

static void put_u32(uint8_t *out, uint32_t value)
{
    for (size_t i = 0; i < 4; i++)
        out[i] = (uint8_t)(value >> (24 - 8 * i));
}

static uint32_t get_u32(const uint8_t *in)
{
    uint32_t value = 0;
    for (size_t i = 0; i < 4; i++)
        value = (value << 8) | in[i];
    return value;
}

void gamelink_wire_put_header(uint8_t out[GAMELINK_HEADER_BYTES],
                              const struct gamelink_header *header)
{
    if (!out || !header)
        return;
    memcpy(out, k_gamelink_magic, sizeof k_gamelink_magic);
    out[3] = (uint8_t)GAMELINK_VERSION;
    put_u64(out + 4, header->session_id);
    put_u64(out + 12, header->seq);
    put_u64(out + 20, header->ack);
    put_u32(out + 28, header->ack_bits);
    out[32] = header->flags;
    out[33] = 0;
}

bool gamelink_wire_parse_header(const uint8_t *in, size_t len,
                                struct gamelink_header *out)
{
    if (!in || !out)
        return false;
    /* Bound first. Everything below indexes a buffer this line proved is
     * long enough, and the length also has to leave room for the tag. */
    if (len < (size_t)GAMELINK_HEADER_BYTES + GAMELINK_TAG_BYTES)
        return false;
    if (len > (size_t)GAMELINK_MAX_DATAGRAM)
        return false;
    /* Accumulate the field checks instead of returning on the first one, so
     * the time this takes does not say which field was wrong. */
    uint8_t bad = 0;
    bad |= gamelink_ct_equal(in, k_gamelink_magic, sizeof k_gamelink_magic)
               ? 0u
               : 1u;
    bad |= (uint8_t)(in[3] ^ (uint8_t)GAMELINK_VERSION);
    bad |= in[33]; /* reserved */
    if (bad != 0)
        return false;
    out->session_id = get_u64(in + 4);
    out->seq = get_u64(in + 12);
    out->ack = get_u64(in + 20);
    out->ack_bits = get_u32(in + 28);
    out->flags = in[32];
    return true;
}

/* The 12-byte AEAD nonce is four zero bytes then the 64-bit sequence number.
 * The sequence number never repeats inside a session (gamelink_send refuses
 * to wrap it) and each direction has its own key, so no nonce is ever used
 * twice under one key. */
static void gamelink_nonce(uint64_t seq, uint8_t nonce[CHACHA20_NONCE_SIZE])
{
    memset(nonce, 0, CHACHA20_NONCE_SIZE);
    put_u64(nonce + 4, seq);
}

bool gamelink_wire_seal(const uint8_t key[32],
                        const struct gamelink_header *header,
                        const uint8_t *payload, size_t len, uint8_t *out,
                        size_t *out_len)
{
    if (!key || !header || !out || !out_len)
        return false;
    if (len > GAMELINK_MAX_PAYLOAD)
        return false;
    if (len > 0 && !payload)
        return false;
    gamelink_wire_put_header(out, header);
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    gamelink_nonce(header->seq, nonce);
    if (!chacha20poly1305_encrypt(payload, len, out, GAMELINK_HEADER_BYTES,
                                  nonce, key, out + GAMELINK_HEADER_BYTES)) {
        memset(nonce, 0, sizeof nonce);
        return false;
    }
    memset(nonce, 0, sizeof nonce);
    *out_len = (size_t)GAMELINK_HEADER_BYTES + len + GAMELINK_TAG_BYTES;
    return true;
}

enum gamelink_open_result gamelink_wire_open(const uint8_t key[32],
                                             const uint8_t *in, size_t in_len,
                                             struct gamelink_header *header,
                                             uint8_t *payload_out,
                                             size_t *payload_len)
{
    if (!key || !in || !header || !payload_out || !payload_len)
        return GAMELINK_WIRE_MALFORMED;
    if (!gamelink_wire_parse_header(in, in_len, header))
        return GAMELINK_WIRE_MALFORMED;
    size_t sealed = in_len - GAMELINK_HEADER_BYTES;
    if (sealed < GAMELINK_TAG_BYTES)
        return GAMELINK_WIRE_MALFORMED;
    size_t plain = sealed - GAMELINK_TAG_BYTES;
    if (plain > GAMELINK_MAX_PAYLOAD)
        return GAMELINK_WIRE_MALFORMED;
    uint8_t nonce[CHACHA20_NONCE_SIZE];
    gamelink_nonce(header->seq, nonce);
    bool ok = chacha20poly1305_decrypt(in + GAMELINK_HEADER_BYTES, sealed, in,
                                       GAMELINK_HEADER_BYTES, nonce, key,
                                       payload_out);
    memset(nonce, 0, sizeof nonce);
    if (!ok)
        return GAMELINK_WIRE_AUTH;
    *payload_len = plain;
    return GAMELINK_WIRE_OK;
}
