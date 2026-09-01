/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * session_transport — the post-handshake record layer over the two directional
 * keys produced by noise_hs_split(). Frame = [3-byte LE length L][ChaCha20-
 * Poly1305 ciphertext L bytes incl 16-byte tag]. Each direction has its own key
 * and monotonic 64-bit nonce counter; the rekey epoch is bound into the AAD; a
 * 1-byte inner channel tag is the first plaintext byte (DATA/WINCH/AUTH/CTRL).
 * Strict counter-monotonicity (nonce binding) makes replay/reorder auth-fail.
 * See docs/work/secure-transport-design.md §4 + §7. No external dependencies. */

#ifndef ZCL_SESSION_SESSION_TRANSPORT_H
#define ZCL_SESSION_SESSION_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Inner channel tag — the first plaintext byte of every record. */
enum session_channel {
    SESSION_CH_DATA = 0, /* application byte stream (wrapped v1 message) */
    SESSION_CH_WINCH = 1,/* window-change / control-plane resize */
    SESSION_CH_AUTH = 2,  /* post-handshake auth exchange */
    SESSION_CH_CTRL = 3,  /* transport control (rekey signal, close) */
};

/* Frame geometry. The one-shot AEAD MAC scratch caps a single call near 2 KiB;
 * FRAME_MAX_PLAINTEXT stays safely under it (transport-design §4). Callers pass
 * at most SESSION_MAX_PAYLOAD data bytes (1 reserved for the channel tag). */
#define SESSION_FRAME_LEN_BYTES 3
#define SESSION_FRAME_MAX_PLAINTEXT 1536
#define SESSION_MAX_PAYLOAD (SESSION_FRAME_MAX_PLAINTEXT - 1)
#define SESSION_TAG_LEN 16
/* Worst-case wire bytes for one record: 3 length + tag byte + payload + AEAD tag. */
#define SESSION_FRAME_MAX_WIRE (SESSION_FRAME_LEN_BYTES + SESSION_FRAME_MAX_PLAINTEXT + SESSION_TAG_LEN)

/* Rekey thresholds, applied independently per direction (transport-design §7).
 * Fields below are poke-able so tests can exercise the boundary deterministically. */
#define SESSION_REKEY_FRAME_LIMIT ((uint64_t)1 << 20) /* 2^20 frames */
#define SESSION_REKEY_BYTE_LIMIT  ((uint64_t)1 << 30) /* 1 GiB       */

struct session_transport {
    uint8_t  send_key[32], recv_key[32];
    uint64_t send_n, recv_n;                 /* per-direction frame counter (nonce source) */
    uint32_t send_epoch, recv_epoch;         /* rekey epoch, bound into the AAD */
    uint64_t send_bytes_epoch, recv_bytes_epoch; /* bytes sealed/opened since last rekey */
};

/* Initialise from the two Split() keys. `send_key` is the key this side seals
 * with; `recv_key` the key it opens with — pass them exactly as noise_hs_split
 * returned them. Counters and epochs start at zero. */
void session_transport_init(struct session_transport *t,
                            const uint8_t send_key[32], const uint8_t recv_key[32]);

/* Seal one record. `channel` becomes the inner tag byte; `plaintext[0..len)` is
 * the payload (len <= SESSION_MAX_PAYLOAD). The complete wire frame (length
 * prefix + ciphertext + tag) is written to out[0..*out_len); out must hold at
 * least SESSION_FRAME_MAX_WIRE bytes. Triggers a send-direction rekey first if a
 * threshold is crossed. Returns false on oversize payload or AEAD failure. */
bool session_transport_encrypt(struct session_transport *t,
                               enum session_channel channel,
                               const uint8_t *plaintext, size_t len,
                               uint8_t *out, size_t *out_len);

/* Open one record. `in[0..in_len)` is a complete wire frame (length prefix +
 * ciphertext). On success *channel is the inner tag, plaintext is written to
 * out[0..*out_len) (out must hold SESSION_MAX_PAYLOAD bytes), and the recv
 * counter advances. Returns false on a malformed length, a short buffer, or an
 * AEAD auth failure — which covers tamper, replay, and reorder (the expected
 * counter is bound into the nonce). Callers MUST drop the connection on false. */
bool session_transport_decrypt(struct session_transport *t,
                               enum session_channel *channel,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t *out_len);

/* Zeroize both directional keys. */
void session_transport_cleanse(struct session_transport *t);

#endif /* ZCL_SESSION_SESSION_TRANSPORT_H */
