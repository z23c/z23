/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Noise Protocol Framework handshake — SymmetricState + HandshakeState,
 * pattern-parameterised so Noise_NK (client<->server sessions) and Noise_XX
 * (future P2P) share ONE token-table-driven implementation. Suite is
 * Noise_{NK,XX}_25519_ChaChaPoly_SHA256: SHA-256 transcript, HKDF-SHA256 KDF,
 * X25519 (via x25519_safe) DH, ChaCha20-Poly1305 AEAD. See
 * docs/work/secure-transport-design.md §3. cognition/modules/session depends only on
 * core/modules/crypto + platform/modules/support. No external dependencies. */

#ifndef ZCL_SESSION_NOISE_HANDSHAKE_H
#define ZCL_SESSION_NOISE_HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NOISE_HASHLEN 32
#define NOISE_DHLEN   32
#define NOISE_KEYLEN  32
#define NOISE_TAGLEN  16
/* Largest handshake message: two ephemeral/static pubkeys are the biggest
 * fixed fields; a caller-supplied handshake payload adds to it. Callers cap
 * their own payloads; the transport (session_transport.h) handles bulk data. */
#define NOISE_MAX_MESSAGE 4096

/* Noise message tokens. */
enum noise_token {
    NOISE_TOK_E = 1, /* ephemeral pubkey */
    NOISE_TOK_S,     /* static pubkey (encrypted once a key is established) */
    NOISE_TOK_EE,    /* DH(e_local, e_remote) */
    NOISE_TOK_ES,    /* DH over e-of-initiator, s-of-responder */
    NOISE_TOK_SE,    /* DH over s-of-initiator, e-of-responder */
    NOISE_TOK_SS,    /* DH(s_local, s_remote) */
};

/* Which party owns a premessage key (`-> s` / `<- s`). */
enum noise_premsg {
    NOISE_PRE_NONE = 0,
    NOISE_PRE_INITIATOR_S, /* initiator's static known ahead of time */
    NOISE_PRE_RESPONDER_S, /* responder's static known ahead of time (NK) */
};

/* A handshake pattern: protocol name (used verbatim as the initial h when
 * <=32 bytes, else SHA-256'd), the premessage, and up to 4 message patterns. */
struct noise_pattern {
    const char *name;
    enum noise_premsg premsg;
    struct { enum noise_token tok[8]; int n; } msg[4];
    int n_msgs;
};

/* Canonical patterns. */
const struct noise_pattern *noise_pattern_nk(void); /* premsg <- s ; -> e,es ; <- e,ee */
const struct noise_pattern *noise_pattern_xx(void); /* -> e ; <- e,ee,s,es ; -> s,se */

/* Noise SymmetricState. */
struct noise_symmetric {
    uint8_t ck[NOISE_HASHLEN];
    uint8_t h[NOISE_HASHLEN];
    uint8_t k[NOISE_KEYLEN];
    uint64_t n;
    bool has_key;
};

/* Noise HandshakeState. */
struct noise_handshake {
    struct noise_symmetric sym;
    const struct noise_pattern *pattern;
    bool initiator;
    int msg_index;   /* next message pattern to process */
    bool split_done;

    /* local static (optional) + ephemeral */
    uint8_t s_priv[32], s_pub[32]; bool have_s;
    uint8_t e_priv[32], e_pub[32]; bool have_e;
    /* remote keys learned during the handshake / premessage */
    uint8_t rs[32]; bool have_rs;
    uint8_t re[32]; bool have_re;
};

/* Initialise a handshake.
 *   pattern    — noise_pattern_nk() / noise_pattern_xx().
 *   initiator  — true for the dialing side.
 *   prologue   — bytes bound into h before any message (may be NULL).
 *   s_priv     — 32-byte local static scalar, or NULL if the pattern needs none
 *                on this side (NK initiator needs none; NK responder needs one).
 *   rs         — 32-byte remote static pubkey when the pattern's premessage
 *                gives it to this side (NK initiator MUST supply the responder
 *                static here), else NULL.
 * Returns false on a contract violation (missing required key material). */
bool noise_hs_init(struct noise_handshake *hs, const struct noise_pattern *pattern,
                   bool initiator, const uint8_t *prologue, size_t prologue_len,
                   const uint8_t *s_priv, const uint8_t *rs);

/* Testing hook: force the ephemeral scalar instead of drawing from the CSPRNG,
 * enabling deterministic transcripts / known-answer vectors. Call before the
 * first noise_hs_write_message on the side that emits `e`. */
void noise_hs_set_ephemeral(struct noise_handshake *hs, const uint8_t e_priv[32]);

/* Write the next handshake message (only valid when it is this side's turn):
 * processes the pattern's tokens, appends the AEAD-sealed payload, emits the
 * full message into out[0..*out_len). Returns false on turn/size/DH error. */
bool noise_hs_write_message(struct noise_handshake *hs,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t *out_len);

/* Read the next handshake message (only valid when it is the peer's turn):
 * consumes tokens, verifies + decrypts the payload into payload_out. Returns
 * false on turn error, malformed length, DH failure, or AEAD auth failure
 * (tampered handshake). */
bool noise_hs_read_message(struct noise_handshake *hs,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *payload_out, size_t *payload_len);

/* True once every message pattern has been processed and Split() is due. */
bool noise_hs_done(const struct noise_handshake *hs);

/* Split() — derive the two directional transport keys. `send_key` is the key
 * this side encrypts with; `recv_key` the key it decrypts with (role-adjusted).
 * Zeroizes all ephemeral/DH/chaining material. Returns false unless the
 * handshake is complete. */
bool noise_hs_split(struct noise_handshake *hs,
                    uint8_t send_key[32], uint8_t recv_key[32]);

/* Copy out the final transcript hash h (channel binding). Valid once done. */
bool noise_hs_transcript_hash(const struct noise_handshake *hs, uint8_t out[32]);

/* Expose the peer static learned during the handshake (XX responder auth /
 * TOFU pinning). Returns false if no remote static was received. */
bool noise_hs_remote_static(const struct noise_handshake *hs, uint8_t out[32]);

/* Zeroize all secret material in a handshake (call on abort). */
void noise_hs_cleanse(struct noise_handshake *hs);

#endif /* ZCL_SESSION_NOISE_HANDSHAKE_H */
