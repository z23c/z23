/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Noise handshake implementation — SymmetricState (MixHash/MixKey/HKDF2/
 * EncryptAndHash/DecryptAndHash/Split) + a token-table HandshakeState driving
 * both Noise_NK and Noise_XX. Canonical Noise ordering: EncryptAndHash and
 * DecryptAndHash BOTH use the current transcript hash h as AEAD associated
 * data, then MixHash the ciphertext (the transport-design §3 prose transposes
 * the decrypt order — canonical Noise is used here so a future KAT interops).
 * See noise/noise_handshake.h. */

#include "noise/noise_handshake.h"

#include "crypto/sha256.h"
#include "crypto/hkdf_sha256.h"
#include "crypto/x25519_safe.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/random_secret.h"
#include "support/cleanse.h"
#include "util/log_macros.h"

#include <string.h>

/* ── canonical patterns ─────────────────────────────────────────────────── */

static const struct noise_pattern k_nk = {
    .name = "Noise_NK_25519_ChaChaPoly_SHA256",
    .premsg = NOISE_PRE_RESPONDER_S,
    .msg = {
        { .tok = { NOISE_TOK_E, NOISE_TOK_ES }, .n = 2 }, /* -> e, es */
        { .tok = { NOISE_TOK_E, NOISE_TOK_EE }, .n = 2 }, /* <- e, ee */
    },
    .n_msgs = 2,
};

static const struct noise_pattern k_xx = {
    .name = "Noise_XX_25519_ChaChaPoly_SHA256",
    .premsg = NOISE_PRE_NONE,
    .msg = {
        { .tok = { NOISE_TOK_E }, .n = 1 },                                         /* -> e */
        { .tok = { NOISE_TOK_E, NOISE_TOK_EE, NOISE_TOK_S, NOISE_TOK_ES }, .n = 4 },/* <- e,ee,s,es */
        { .tok = { NOISE_TOK_S, NOISE_TOK_SE }, .n = 2 },                           /* -> s,se */
    },
    .n_msgs = 3,
};

const struct noise_pattern *noise_pattern_nk(void) { return &k_nk; }
const struct noise_pattern *noise_pattern_xx(void) { return &k_xx; }

/* ── SymmetricState primitives ──────────────────────────────────────────── */

static void sym_mixhash(struct noise_symmetric *s, const uint8_t *data, size_t len)
{
    struct sha256_ctx c;
    sha256_init(&c);
    sha256_write(&c, s->h, NOISE_HASHLEN);
    if (data && len) sha256_write(&c, data, len);
    sha256_finalize(&c, s->h);
}

static void sym_mixkey(struct noise_symmetric *s, const uint8_t dh[32])
{
    uint8_t new_ck[32], temp_k[32];
    hkdf_sha256_2(s->ck, NOISE_HASHLEN, dh, 32, new_ck, temp_k);
    memcpy(s->ck, new_ck, 32);
    memcpy(s->k, temp_k, 32);
    s->n = 0;
    s->has_key = true;
    memory_cleanse(new_ck, sizeof(new_ck));
    memory_cleanse(temp_k, sizeof(temp_k));
}

/* Noise ChaChaPoly nonce: 4×0x00 || LE64(n). */
static void sym_nonce(uint64_t n, uint8_t nonce[12])
{
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
}

/* EncryptAndHash: seal pt under (h, k, nonce(n)); MixHash(ct); n++. When no key
 * is established yet, the plaintext is emitted verbatim and hashed. */
static bool sym_encrypt_and_hash(struct noise_symmetric *s,
                                 const uint8_t *pt, size_t pt_len,
                                 uint8_t *out, size_t *out_len)
{
    if (!s->has_key) {
        if (pt_len && pt) memcpy(out, pt, pt_len);
        sym_mixhash(s, out, pt_len);
        *out_len = pt_len;
        return true;
    }
    uint8_t nonce[12];
    sym_nonce(s->n, nonce);
    if (!chacha20poly1305_encrypt(pt, pt_len, s->h, NOISE_HASHLEN, nonce, s->k, out))
        LOG_FAIL("noise", "EncryptAndHash: AEAD seal failed (pt_len=%zu)", pt_len);
    size_t ct_len = pt_len + NOISE_TAGLEN;
    sym_mixhash(s, out, ct_len);
    s->n++;
    *out_len = ct_len;
    return true;
}

/* DecryptAndHash: use current h as AAD to open ct, THEN MixHash(ct). */
static bool sym_decrypt_and_hash(struct noise_symmetric *s,
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *out, size_t *out_len)
{
    if (!s->has_key) {
        if (ct_len && ct) memcpy(out, ct, ct_len);
        sym_mixhash(s, ct, ct_len);
        *out_len = ct_len;
        return true;
    }
    if (ct_len < NOISE_TAGLEN)
        LOG_FAIL("noise", "DecryptAndHash: ciphertext %zu shorter than tag", ct_len);
    uint8_t nonce[12];
    sym_nonce(s->n, nonce);
    /* AAD is the pre-mix h; capture it before MixHash mutates it. */
    uint8_t aad[NOISE_HASHLEN];
    memcpy(aad, s->h, NOISE_HASHLEN);
    if (!chacha20poly1305_decrypt(ct, ct_len, aad, NOISE_HASHLEN, nonce, s->k, out))
        LOG_FAIL("noise", "DecryptAndHash: AEAD auth failed (tampered handshake)");
    sym_mixhash(s, ct, ct_len);
    s->n++;
    *out_len = ct_len - NOISE_TAGLEN;
    return true;
}

/* ── HandshakeState ─────────────────────────────────────────────────────── */

static void sym_init(struct noise_symmetric *s, const char *name)
{
    size_t nlen = strlen(name);
    memset(s->h, 0, NOISE_HASHLEN);
    if (nlen <= NOISE_HASHLEN) {
        memcpy(s->h, name, nlen); /* remaining bytes stay zero (Noise rule) */
    } else {
        struct sha256_ctx c;
        sha256_init(&c);
        sha256_write(&c, (const uint8_t *)name, nlen);
        sha256_finalize(&c, s->h);
    }
    memcpy(s->ck, s->h, NOISE_HASHLEN);
    memset(s->k, 0, NOISE_KEYLEN);
    s->n = 0;
    s->has_key = false;
}

bool noise_hs_init(struct noise_handshake *hs, const struct noise_pattern *pattern,
                   bool initiator, const uint8_t *prologue, size_t prologue_len,
                   const uint8_t *s_priv, const uint8_t *rs)
{
    if (!hs || !pattern) LOG_FAIL("noise", "hs_init: null hs/pattern");
    memset(hs, 0, sizeof(*hs));
    hs->pattern = pattern;
    hs->initiator = initiator;
    hs->msg_index = 0;

    sym_init(&hs->sym, pattern->name);
    sym_mixhash(&hs->sym, prologue, prologue_len);

    if (s_priv) {
        memcpy(hs->s_priv, s_priv, 32);
        if (!curve25519_scalarmult_base(hs->s_pub, hs->s_priv))
            LOG_FAIL("noise", "hs_init: static pubkey derivation failed");
        hs->have_s = true;
    }
    if (rs) { memcpy(hs->rs, rs, 32); hs->have_rs = true; }

    /* Premessage: MixHash the pre-shared static into h, in the Noise order
     * (initiator premessage keys first, then responder's). Both sides MUST end
     * with the same h, so each side supplies its own view of the shared key. */
    switch (pattern->premsg) {
    case NOISE_PRE_NONE:
        break;
    case NOISE_PRE_RESPONDER_S: {
        const uint8_t *key = initiator ? (hs->have_rs ? hs->rs : NULL)
                                       : (hs->have_s ? hs->s_pub : NULL);
        if (!key) LOG_FAIL("noise", "hs_init: NK premessage needs responder static "
                                    "(%s side missing it)", initiator ? "initiator" : "responder");
        sym_mixhash(&hs->sym, key, 32);
        break;
    }
    case NOISE_PRE_INITIATOR_S: {
        const uint8_t *key = initiator ? (hs->have_s ? hs->s_pub : NULL)
                                       : (hs->have_rs ? hs->rs : NULL);
        if (!key) LOG_FAIL("noise", "hs_init: premessage needs initiator static");
        sym_mixhash(&hs->sym, key, 32);
        break;
    }
    }
    return true;
}

void noise_hs_set_ephemeral(struct noise_handshake *hs, const uint8_t e_priv[32])
{
    if (!hs || !e_priv) return;
    memcpy(hs->e_priv, e_priv, 32);
    (void)curve25519_scalarmult_base(hs->e_pub, hs->e_priv);
    hs->have_e = true;
}

static bool hs_ensure_ephemeral(struct noise_handshake *hs)
{
    if (hs->have_e) return true;
    if (!zcl_random_secret_bytes(hs->e_priv, 32, "noise-eph"))
        LOG_FAIL("noise", "ephemeral generation failed (CSPRNG)");
    if (!curve25519_scalarmult_base(hs->e_pub, hs->e_priv))
        LOG_FAIL("noise", "ephemeral pubkey derivation failed");
    hs->have_e = true;
    return true;
}

/* Resolve the DH pair for a token from this side's perspective. */
static bool hs_dh_for_token(struct noise_handshake *hs, enum noise_token tok,
                            uint8_t out[32])
{
    const uint8_t *scalar = NULL, *point = NULL;
    switch (tok) {
    case NOISE_TOK_EE:
        scalar = hs->e_priv; point = hs->re;
        if (!hs->have_e || !hs->have_re) LOG_FAIL("noise", "ee: missing e/re");
        break;
    case NOISE_TOK_ES:
        if (hs->initiator) { scalar = hs->e_priv; point = hs->rs; }
        else               { scalar = hs->s_priv; point = hs->re; }
        break;
    case NOISE_TOK_SE:
        if (hs->initiator) { scalar = hs->s_priv; point = hs->re; }
        else               { scalar = hs->e_priv; point = hs->rs; }
        break;
    case NOISE_TOK_SS:
        scalar = hs->s_priv; point = hs->rs;
        break;
    default:
        LOG_FAIL("noise", "hs_dh: non-DH token %d", (int)tok);
    }
    if (!scalar || !point) LOG_FAIL("noise", "hs_dh: missing key material for token %d", (int)tok);
    if (!x25519_safe(out, scalar, point))
        LOG_FAIL("noise", "hs_dh: DH produced degenerate/zero secret (token %d)", (int)tok);
    return true;
}

static bool hs_my_turn(const struct noise_handshake *hs)
{
    /* message 0 (index 0) is written by the initiator; parity alternates. */
    bool initiator_writes = (hs->msg_index % 2 == 0);
    return hs->initiator == initiator_writes;
}

bool noise_hs_write_message(struct noise_handshake *hs,
                            const uint8_t *payload, size_t payload_len,
                            uint8_t *out, size_t *out_len)
{
    if (!hs || !out || !out_len) LOG_FAIL("noise", "write: null arg");
    if (hs->msg_index >= hs->pattern->n_msgs) LOG_FAIL("noise", "write: handshake already complete");
    if (!hs_my_turn(hs)) LOG_FAIL("noise", "write: not this side's turn (msg %d)", hs->msg_index);

    const int n = hs->pattern->msg[hs->msg_index].n;
    const enum noise_token *toks = hs->pattern->msg[hs->msg_index].tok;
    size_t pos = 0;

    for (int i = 0; i < n; i++) {
        switch (toks[i]) {
        case NOISE_TOK_E:
            if (!hs_ensure_ephemeral(hs)) return false;
            if (pos + 32 > NOISE_MAX_MESSAGE) LOG_FAIL("noise", "write: message overflow");
            memcpy(out + pos, hs->e_pub, 32); pos += 32;
            sym_mixhash(&hs->sym, hs->e_pub, 32);
            break;
        case NOISE_TOK_S: {
            if (!hs->have_s) LOG_FAIL("noise", "write: token s but no local static");
            size_t seg = 0;
            if (!sym_encrypt_and_hash(&hs->sym, hs->s_pub, 32, out + pos, &seg)) return false;
            pos += seg;
            break;
        }
        default: {
            uint8_t dh[32];
            if (!hs_dh_for_token(hs, toks[i], dh)) return false;
            sym_mixkey(&hs->sym, dh);
            memory_cleanse(dh, sizeof(dh));
            break;
        }
        }
    }

    size_t seg = 0;
    if (!sym_encrypt_and_hash(&hs->sym, payload, payload_len, out + pos, &seg)) return false;
    pos += seg;

    *out_len = pos;
    hs->msg_index++;
    return true;
}

bool noise_hs_read_message(struct noise_handshake *hs,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *payload_out, size_t *payload_len)
{
    if (!hs || !msg) LOG_FAIL("noise", "read: null arg");
    if (hs->msg_index >= hs->pattern->n_msgs) LOG_FAIL("noise", "read: handshake already complete");
    if (hs_my_turn(hs)) LOG_FAIL("noise", "read: it is this side's turn to write (msg %d)", hs->msg_index);

    const int n = hs->pattern->msg[hs->msg_index].n;
    const enum noise_token *toks = hs->pattern->msg[hs->msg_index].tok;
    size_t pos = 0;

    for (int i = 0; i < n; i++) {
        switch (toks[i]) {
        case NOISE_TOK_E:
            if (pos + 32 > msg_len) LOG_FAIL("noise", "read: truncated at token e");
            memcpy(hs->re, msg + pos, 32); pos += 32;
            hs->have_re = true;
            sym_mixhash(&hs->sym, hs->re, 32);
            break;
        case NOISE_TOK_S: {
            size_t seg_ct = hs->sym.has_key ? 32 + NOISE_TAGLEN : 32;
            if (pos + seg_ct > msg_len) LOG_FAIL("noise", "read: truncated at token s");
            size_t pt = 0;
            if (!sym_decrypt_and_hash(&hs->sym, msg + pos, seg_ct, hs->rs, &pt)) return false;
            if (pt != 32) LOG_FAIL("noise", "read: static payload wrong size %zu", pt);
            hs->have_rs = true;
            pos += seg_ct;
            break;
        }
        default: {
            uint8_t dh[32];
            if (!hs_dh_for_token(hs, toks[i], dh)) return false;
            sym_mixkey(&hs->sym, dh);
            memory_cleanse(dh, sizeof(dh));
            break;
        }
        }
    }

    if (pos > msg_len) LOG_FAIL("noise", "read: token consumption overran message");
    uint8_t discard[NOISE_MAX_MESSAGE];
    size_t pt = 0;
    if (!sym_decrypt_and_hash(&hs->sym, msg + pos, msg_len - pos,
                              payload_out ? payload_out : discard, &pt))
        return false;
    if (payload_len) *payload_len = pt;
    hs->msg_index++;
    return true;
}

bool noise_hs_done(const struct noise_handshake *hs)
{
    return hs && hs->msg_index >= hs->pattern->n_msgs;
}

bool noise_hs_split(struct noise_handshake *hs, uint8_t send_key[32], uint8_t recv_key[32])
{
    if (!hs || !send_key || !recv_key) LOG_FAIL("noise", "split: null arg");
    if (!noise_hs_done(hs)) LOG_FAIL("noise", "split: handshake not complete (%d/%d)",
                                     hs->msg_index, hs->pattern->n_msgs);

    uint8_t k1[32], k2[32];
    hkdf_sha256_2(hs->sym.ck, NOISE_HASHLEN, NULL, 0, k1, k2);
    /* Initiator sends with k1 / receives with k2; responder mirrors. */
    if (hs->initiator) { memcpy(send_key, k1, 32); memcpy(recv_key, k2, 32); }
    else               { memcpy(send_key, k2, 32); memcpy(recv_key, k1, 32); }

    hs->split_done = true;
    memory_cleanse(k1, sizeof(k1));
    memory_cleanse(k2, sizeof(k2));
    /* Zeroize all handshake secrets; keep only h for optional channel binding. */
    memory_cleanse(hs->sym.ck, sizeof(hs->sym.ck));
    memory_cleanse(hs->sym.k, sizeof(hs->sym.k));
    memory_cleanse(hs->s_priv, sizeof(hs->s_priv));
    memory_cleanse(hs->e_priv, sizeof(hs->e_priv));
    return true;
}

bool noise_hs_transcript_hash(const struct noise_handshake *hs, uint8_t out[32])
{
    if (!hs || !out) return false;
    memcpy(out, hs->sym.h, NOISE_HASHLEN);
    return true;
}

bool noise_hs_remote_static(const struct noise_handshake *hs, uint8_t out[32])
{
    if (!hs || !out || !hs->have_rs) return false;
    memcpy(out, hs->rs, 32);
    return true;
}

void noise_hs_cleanse(struct noise_handshake *hs)
{
    if (!hs) return;
    memory_cleanse(hs->sym.ck, sizeof(hs->sym.ck));
    memory_cleanse(hs->sym.k, sizeof(hs->sym.k));
    memory_cleanse(hs->s_priv, sizeof(hs->s_priv));
    memory_cleanse(hs->e_priv, sizeof(hs->e_priv));
}
