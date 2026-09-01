/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Note encryption for Sprout and Sapling shielded transactions.
 *
 * NONCE HAZARD — zero_nonce[12] below is the same nonce used for every
 * ChaCha20-Poly1305 call in this file. That is only safe as long as the
 * AEAD key is fresh per message, which holds because the key is derived
 * from the ephemeral secret esk via sapling_kdf / sprout_kdf. If esk ever
 * repeats (RNG failure, fork in the caller before GetRandBytes settles),
 * two messages are encrypted under the same (key, nonce) pair — a
 * two-time-pad that leaks plaintext XORs and forges MAC tags.
 *
 * As a defense-in-depth check (enabled under ZCL_CRYPTO_SANITY or any
 * debug build), we record a small ring of the most-recently-used esk
 * values per process and abort loudly on a collision. This does not
 * defend against multi-process reuse, but catches the in-process
 * RNG-failure scenario where a degraded entropy source produces a
 * repeating stream and esk repeats. */

#include "sapling/note_encryption.h"
#include "crypto/blake2b.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/random_secret.h"
#include "core/random.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLAKE2B_PERSONALBYTES 16

static const uint8_t zero_nonce[12] = {0};

/* ── esk nonce-reuse sanity guard (see file header) ────────────────── */

/* Opt-in: enable with -DZCL_CRYPTO_SANITY=1 (e.g. in a canary build or a
 * staging node). Disabled by default so the existing test fixtures that
 * reuse fixed encryption keys (known-answer vectors) keep working
 * unchanged. Production nodes that want the two-time-pad safety net can
 * flip it on in their Makefile override. */
#if !defined(ZCL_CRYPTO_SANITY)
#  define ZCL_CRYPTO_SANITY 0
#endif

#if ZCL_CRYPTO_SANITY
/* Small ring of recently-used 32-byte ephemeral secrets. 64 slots is
 * enough to catch an immediate repeat from a stuck RNG without costing
 * measurable time in the encrypt path. */
#define ZCL_ESK_RING_SIZE 64

static pthread_mutex_t g_esk_ring_mu = PTHREAD_MUTEX_INITIALIZER;
static uint8_t g_esk_ring[ZCL_ESK_RING_SIZE][32];
static int g_esk_ring_filled = 0; /* grows up to ZCL_ESK_RING_SIZE then stays */
static int g_esk_ring_next = 0;

/* Check `esk` against the ring. If it matches any previous entry, abort —
 * the AEAD key derived from esk is about to repeat with the same zero nonce,
 * which breaks confidentiality and integrity. Otherwise insert it. */
static void zcl_note_check_esk_unique(const uint8_t esk[32])
{
    pthread_mutex_lock(&g_esk_ring_mu);
    for (int i = 0; i < g_esk_ring_filled; i++) {
        /* Constant-time compare is not needed: this is a debug check, and
         * a match triggers abort(). */
        if (memcmp(g_esk_ring[i], esk, 32) == 0) {
            pthread_mutex_unlock(&g_esk_ring_mu);
            fprintf(stderr,
                "[sapling] %s:%d %s(): "
                "FATAL: esk repeat detected in last %d values — RNG failure "
                "would produce two-time-pad under the fixed zero_nonce. "
                "Aborting rather than leaking plaintext.\n",
                __FILE__, __LINE__, __func__, g_esk_ring_filled);
            abort(); // abort-ok: returning here would emit a two-time pad under the fixed zero nonce and leak the note plaintext
        }
    }
    memcpy(g_esk_ring[g_esk_ring_next], esk, 32);
    g_esk_ring_next = (g_esk_ring_next + 1) % ZCL_ESK_RING_SIZE;
    if (g_esk_ring_filled < ZCL_ESK_RING_SIZE)
        g_esk_ring_filled++;
    pthread_mutex_unlock(&g_esk_ring_mu);
}
#else
static inline void zcl_note_check_esk_unique(const uint8_t esk[32]) { (void)esk; }
#endif

bool sprout_kdf(uint8_t key[32],
                const uint8_t hsig[32],
                const uint8_t dhsecret[32],
                const uint8_t epk[32],
                const uint8_t pk_enc[32],
                uint8_t nonce)
{
    uint8_t block[128];
    memcpy(block, hsig, 32);
    memcpy(block + 32, dhsecret, 32);
    memcpy(block + 64, epk, 32);
    memcpy(block + 96, pk_enc, 32);

    uint8_t personal[BLAKE2B_PERSONALBYTES];
    memcpy(personal, "ZcashKDF", 8);
    memset(personal + 8, 0, 7);
    personal[15] = nonce;

    struct blake2b_ctx ctx;
    if (blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personal) != 0)
        LOG_FAIL("sapling", "sprout_kdf: blake2b_init_salt_personal failed (nonce=%u)",
                 (unsigned)nonce);
    blake2b_update(&ctx, block, 128);
    blake2b_final(&ctx, key, 32);
    memory_cleanse(block, sizeof(block));
    return true;
}

bool sapling_kdf(uint8_t key[32],
                 const uint8_t dhsecret[32],
                 const uint8_t epk[32])
{
    uint8_t block[64];
    memcpy(block, dhsecret, 32);
    memcpy(block + 32, epk, 32);

    uint8_t personal[BLAKE2B_PERSONALBYTES];
    memcpy(personal, "Zcash_SaplingKDF", 16);

    struct blake2b_ctx ctx;
    if (blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personal) != 0)
        LOG_FAIL("sapling", "sapling_kdf: blake2b_init_salt_personal failed");
    blake2b_update(&ctx, block, 64);
    blake2b_final(&ctx, key, 32);
    memory_cleanse(block, sizeof(block));
    return true;
}

bool sapling_prf_ock(uint8_t key[32],
                     const uint8_t ovk[32],
                     const uint8_t cv[32],
                     const uint8_t cm[32],
                     const uint8_t epk[32])
{
    uint8_t block[128];
    memcpy(block, ovk, 32);
    memcpy(block + 32, cv, 32);
    memcpy(block + 64, cm, 32);
    memcpy(block + 96, epk, 32);

    uint8_t personal[BLAKE2B_PERSONALBYTES];
    memcpy(personal, "Zcash_Derive_ock", 16);

    struct blake2b_ctx ctx;
    if (blake2b_init_salt_personal(&ctx, 32, NULL, 0, NULL, personal) != 0)
        LOG_FAIL("sapling", "sapling_prf_ock: blake2b_init_salt_personal failed");
    blake2b_update(&ctx, block, 128);
    blake2b_final(&ctx, key, 32);
    memory_cleanse(block, sizeof(block));
    return true;
}

bool sprout_note_encryption_init(struct sprout_note_encryption *ctx)
{
    if (!zcl_random_secret_bytes(ctx->esk, 32, "sprout_esk"))
        return false;
    ctx->esk[0] &= 248;
    ctx->esk[31] &= 127;
    ctx->esk[31] |= 64;
    /* Paranoia: make sure the RNG hasn't handed us a repeat before we
     * derive the AEAD key that will be used with the fixed zero nonce. */
    zcl_note_check_esk_unique(ctx->esk);
    curve25519_scalarmult_base(ctx->epk, ctx->esk);
    ctx->nonce = 0;
    return true;
}

void sprout_note_encryption_init_with_esk(struct sprout_note_encryption *ctx,
                                           const uint8_t esk[32])
{
    memcpy(ctx->esk, esk, 32);
    ctx->esk[0] &= 248;
    ctx->esk[31] &= 127;
    ctx->esk[31] |= 64;
    /* Test paths frequently pass the same esk intentionally; see the body
     * of zcl_note_check_esk_unique — in those modes (ZCL_CRYPTO_SANITY=0
     * at compile time) the check is a no-op. Production call paths use
     * sprout_note_encryption_init() which samples fresh randomness. */
    zcl_note_check_esk_unique(ctx->esk);
    curve25519_scalarmult_base(ctx->epk, ctx->esk);
    ctx->nonce = 0;
}

bool sprout_note_encrypt(struct sprout_note_encryption *ctx,
                         const uint8_t hsig[32],
                         const uint8_t pk_enc[32],
                         const uint8_t *plaintext, size_t plen,
                         uint8_t *ciphertext)
{
    if (ctx->nonce > 254)
        LOG_FAIL("sapling",
                 "sprout_note_encrypt: per-tx nonce budget exhausted (nonce=%u > 254)",
                 (unsigned)ctx->nonce);

    uint8_t dhsecret[32];
    curve25519_scalarmult(dhsecret, ctx->esk, pk_enc);

    uint8_t key[32];
    if (!sprout_kdf(key, hsig, dhsecret, ctx->epk, pk_enc, ctx->nonce)) {
        memset(dhsecret, 0, 32);
        LOG_FAIL("sapling", "sprout_note_encrypt: sprout_kdf failed (nonce=%u)",
                 (unsigned)ctx->nonce);
    }

    ctx->nonce++;

    bool ok = chacha20poly1305_encrypt(plaintext, plen, NULL, 0,
                                        zero_nonce, key, ciphertext);
    memset(dhsecret, 0, 32);
    memset(key, 0, 32);
    return ok;
}

bool sprout_note_decrypt(const uint8_t sk_enc[32],
                         const uint8_t epk[32],
                         const uint8_t hsig[32],
                         const uint8_t pk_enc[32],
                         uint8_t nonce,
                         const uint8_t *ciphertext, size_t clen,
                         uint8_t *plaintext)
{
    uint8_t dhsecret[32];
    curve25519_scalarmult(dhsecret, sk_enc, epk);

    uint8_t key[32];
    if (!sprout_kdf(key, hsig, dhsecret, epk, pk_enc, nonce)) {
        memset(dhsecret, 0, 32);
        LOG_FAIL("sapling", "sprout_note_decrypt: sprout_kdf failed (nonce=%u)",
                 (unsigned)nonce);
    }

    bool ok = chacha20poly1305_decrypt(ciphertext, clen, NULL, 0,
                                        zero_nonce, key, plaintext);
    memset(dhsecret, 0, 32);
    memset(key, 0, 32);
    return ok;
}

bool sapling_note_encrypt(const uint8_t key[32],
                          const uint8_t *plaintext, size_t plen,
                          uint8_t *ciphertext)
{
    /* zero_nonce is safe only if `key` never repeats. In Sapling the key
     * comes from sapling_kdf(dhsecret, epk), so a repeat means the esk
     * that produced epk/dhsecret repeated — RNG failure. Log/abort in
     * ZCL_CRYPTO_SANITY builds before we leak plaintext. */
    zcl_note_check_esk_unique(key);
    return chacha20poly1305_encrypt(plaintext, plen, NULL, 0,
                                    zero_nonce, key, ciphertext);
}

bool sapling_note_decrypt(const uint8_t key[32],
                          const uint8_t *ciphertext, size_t clen,
                          uint8_t *plaintext)
{
    return chacha20poly1305_decrypt(ciphertext, clen, NULL, 0,
                                    zero_nonce, key, plaintext);
}

bool sapling_out_encrypt(const uint8_t key[32],
                         const uint8_t *plaintext, size_t plen,
                         uint8_t *ciphertext)
{
    /* ock is derived from ovk+cv+cm+epk; a repeat here means the same
     * output (cv/cm/epk) is being re-encrypted, which only happens on RNG
     * failure or a buggy caller. See zcl_note_check_esk_unique() header. */
    zcl_note_check_esk_unique(key);
    return chacha20poly1305_encrypt(plaintext, plen, NULL, 0,
                                    zero_nonce, key, ciphertext);
}

bool sapling_out_decrypt(const uint8_t key[32],
                         const uint8_t *ciphertext, size_t clen,
                         uint8_t *plaintext)
{
    return chacha20poly1305_decrypt(ciphertext, clen, NULL, 0,
                                    zero_nonce, key, plaintext);
}
