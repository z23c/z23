/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * session_transport implementation — length-prefixed ChaCha20-Poly1305 records
 * with per-direction nonce counters, epoch-in-AAD rekey, and the inner channel
 * tag. See noise/session_transport.h + docs/work/secure-transport-design.md
 * §4/§7. */

#include "noise/session_transport.h"

#include "crypto/chacha20poly1305.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <string.h>

/* Noise/ChaChaPoly nonce layout: 4×0x00 || LE64(counter). */
static void frame_nonce(uint64_t n, uint8_t nonce[12])
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

/* AAD = LE32(epoch) || LE24(length). Binds the rekey epoch and the wire length
 * into the tag, so an epoch-splice or truncation fails authentication. */
static void frame_aad(uint32_t epoch, uint32_t wire_len, uint8_t aad[7])
{
    aad[0] = (uint8_t)(epoch);
    aad[1] = (uint8_t)(epoch >> 8);
    aad[2] = (uint8_t)(epoch >> 16);
    aad[3] = (uint8_t)(epoch >> 24);
    aad[4] = (uint8_t)(wire_len);
    aad[5] = (uint8_t)(wire_len >> 8);
    aad[6] = (uint8_t)(wire_len >> 16);
}

/* REKEY (transport-design §7): k_next = first 32 bytes of
 * ChaCha20-Poly1305(k, nonce96(2^64-1), aad="", plaintext=32×0x00). Resets the
 * per-direction counter and increments the epoch. */
static bool rekey_direction(uint8_t key[32], uint32_t *epoch,
                            uint64_t *counter, uint64_t *bytes_epoch)
{
    uint8_t nonce[12];
    frame_nonce(UINT64_MAX, nonce);
    uint8_t zero[32] = {0};
    uint8_t ct[32 + SESSION_TAG_LEN];
    /* one-shot AEAD over 32 zero bytes; take the ciphertext (not the tag). */
    bool ok = chacha20poly1305_encrypt(zero, sizeof(zero), NULL, 0, nonce,
                                       key, ct);
    if (ok)
        memcpy(key, ct, 32);
    memory_cleanse(ct, sizeof(ct));
    memory_cleanse(zero, sizeof(zero));
    /* A failed derivation must NOT reset the counter — that would resume at
     * nonce 0 under the OLD key. Leave state untouched and fail closed. */
    if (!ok)
        return false;
    *epoch += 1;
    *counter = 0;
    *bytes_epoch = 0;
    return true;
}

void session_transport_init(struct session_transport *t,
                            const uint8_t send_key[32], const uint8_t recv_key[32])
{
    if (!t) return;
    memset(t, 0, sizeof(*t));
    memcpy(t->send_key, send_key, 32);
    memcpy(t->recv_key, recv_key, 32);
}

bool session_transport_encrypt(struct session_transport *t,
                               enum session_channel channel,
                               const uint8_t *plaintext, size_t len,
                               uint8_t *out, size_t *out_len)
{
    if (!t || !out || !out_len) LOG_FAIL("session", "encrypt: null arg");
    if (len > SESSION_MAX_PAYLOAD)
        LOG_FAIL("session", "encrypt: payload %zu exceeds max %d", len, SESSION_MAX_PAYLOAD);

    /* Rekey the send direction before this frame if a threshold is crossed. */
    if (t->send_n >= SESSION_REKEY_FRAME_LIMIT ||
        t->send_bytes_epoch >= SESSION_REKEY_BYTE_LIMIT) {
        if (!rekey_direction(t->send_key, &t->send_epoch, &t->send_n,
                             &t->send_bytes_epoch))
            LOG_FAIL("session", "encrypt: send rekey failed; refusing frame");
    }

    /* inner plaintext = [channel tag][payload] */
    uint8_t inner[SESSION_FRAME_MAX_PLAINTEXT];
    inner[0] = (uint8_t)channel;
    if (len) memcpy(inner + 1, plaintext, len);
    size_t inner_len = len + 1;

    uint32_t wire_len = (uint32_t)(inner_len + SESSION_TAG_LEN); /* ciphertext incl tag */
    uint8_t nonce[12]; frame_nonce(t->send_n, nonce);
    uint8_t aad[7];    frame_aad(t->send_epoch, wire_len, aad);

    out[0] = (uint8_t)(wire_len);
    out[1] = (uint8_t)(wire_len >> 8);
    out[2] = (uint8_t)(wire_len >> 16);
    if (!chacha20poly1305_encrypt(inner, inner_len, aad, sizeof(aad), nonce,
                                  t->send_key, out + SESSION_FRAME_LEN_BYTES)) {
        memory_cleanse(inner, sizeof(inner));
        LOG_FAIL("session", "encrypt: AEAD seal failed");
    }
    memory_cleanse(inner, sizeof(inner));

    *out_len = SESSION_FRAME_LEN_BYTES + wire_len;
    t->send_n++;
    t->send_bytes_epoch += inner_len;
    return true;
}

bool session_transport_decrypt(struct session_transport *t,
                               enum session_channel *channel,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t *out_len)
{
    if (!t || !in || !out || !out_len) LOG_FAIL("session", "decrypt: null arg");
    if (in_len < SESSION_FRAME_LEN_BYTES + SESSION_TAG_LEN)
        LOG_FAIL("session", "decrypt: frame too short (%zu)", in_len);

    uint32_t wire_len = (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16);
    if (wire_len < SESSION_TAG_LEN)
        LOG_FAIL("session", "decrypt: length %u below tag size", wire_len);
    if ((size_t)SESSION_FRAME_LEN_BYTES + wire_len > in_len)
        LOG_FAIL("session", "decrypt: declared length %u exceeds buffer %zu", wire_len, in_len);
    size_t inner_len = wire_len - SESSION_TAG_LEN;
    if (inner_len < 1 || inner_len > SESSION_FRAME_MAX_PLAINTEXT)
        LOG_FAIL("session", "decrypt: inner length %zu out of range", inner_len);

    /* Rekey the recv direction in lockstep with the sender (same thresholds). */
    if (t->recv_n >= SESSION_REKEY_FRAME_LIMIT ||
        t->recv_bytes_epoch >= SESSION_REKEY_BYTE_LIMIT) {
        if (!rekey_direction(t->recv_key, &t->recv_epoch, &t->recv_n,
                             &t->recv_bytes_epoch))
            LOG_FAIL("session", "decrypt: recv rekey failed; refusing frame");
    }

    uint8_t nonce[12]; frame_nonce(t->recv_n, nonce);
    uint8_t aad[7];    frame_aad(t->recv_epoch, wire_len, aad);

    uint8_t inner[SESSION_FRAME_MAX_PLAINTEXT];
    if (!chacha20poly1305_decrypt(in + SESSION_FRAME_LEN_BYTES, wire_len, aad, sizeof(aad),
                                  nonce, t->recv_key, inner)) {
        /* tamper OR replay/reorder (counter is bound into the nonce). Drop. */
        memory_cleanse(inner, sizeof(inner));
        LOG_FAIL("session", "decrypt: AEAD auth failed (tamper/replay/reorder) at n=%llu",
                 (unsigned long long)t->recv_n);
    }

    if (channel) *channel = (enum session_channel)inner[0];
    size_t payload_len = inner_len - 1;
    if (payload_len) memcpy(out, inner + 1, payload_len);
    *out_len = payload_len;
    memory_cleanse(inner, sizeof(inner));

    t->recv_n++;
    t->recv_bytes_epoch += inner_len;
    return true;
}

void session_transport_cleanse(struct session_transport *t)
{
    if (!t) return;
    memory_cleanse(t->send_key, sizeof(t->send_key));
    memory_cleanse(t->recv_key, sizeof(t->recv_key));
}
