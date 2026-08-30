/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wallet Backup Crypto - encrypted wallet backup file helpers.
 *
 * Split from wallet_backup_service.c so the service scheduler/rotation
 * path stays separate from the phase-2 ChaCha20-Poly1305 file format. */

#include "services/wallet_backup_service.h"

#include "core/random.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/pbkdf2_sha256.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"
#include "support/cleanse.h"
#include "util/file_io.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The existing chacha20poly1305_encrypt/_decrypt helpers in
 * lib/crypto use a 2048-byte stack buffer for the Poly1305 MAC
 * input, which is fine for Sapling notes and P2P handshakes but
 * too small for wallet backup SQLite files. Re-implement the
 * RFC 7539 AEAD construction locally with a heap buffer so we
 * can AEAD arbitrarily-sized messages without touching the
 * shared crypto code. */
static void wbs_pad16_len(size_t n, size_t *pad_out)
{
    *pad_out = (16 - (n % 16)) % 16;
}

static void wbs_store64_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static bool wbs_aead_encrypt(const uint8_t *plain, size_t plain_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t nonce[12],
                              const uint8_t key[32],
                              uint8_t *ciphertext_out,
                              uint8_t  tag_out[16])
{
    /* Derive the Poly1305 one-time key from ChaCha20 block 0. */
    uint8_t poly_block[64];
    chacha20_block(key, 0, nonce, poly_block);

    /* Encrypt with ChaCha20 starting at counter 1. */
    chacha20_encrypt(key, 1, nonce, plain, plain_len, ciphertext_out);

    /* Build the Poly1305 message:
     *   aad || pad16(aad) || ciphertext || pad16(ciphertext) ||
     *   le64(aad_len) || le64(plain_len)
     */
    size_t pad_aad, pad_ct;
    wbs_pad16_len(aad_len,    &pad_aad);
    wbs_pad16_len(plain_len,  &pad_ct);

    size_t mac_len = aad_len + pad_aad + plain_len + pad_ct + 16;
    uint8_t *mac_buf = zcl_calloc(1, mac_len > 0 ? mac_len : 1, "aead_encrypt mac_buf");
    if (!mac_buf) {
        memory_cleanse(poly_block, sizeof(poly_block));
        LOG_FAIL("wallet_backup", "aead_encrypt: mac_buf alloc failed (%zu bytes)", mac_len);
    }
    size_t pos = 0;
    if (aad_len)    { memcpy(mac_buf + pos, aad, aad_len); pos += aad_len; }
    pos += pad_aad; /* calloc zeroed, no action needed */
    if (plain_len)  { memcpy(mac_buf + pos, ciphertext_out, plain_len); pos += plain_len; }
    pos += pad_ct;
    wbs_store64_le(mac_buf + pos, (uint64_t)aad_len);   pos += 8;
    wbs_store64_le(mac_buf + pos, (uint64_t)plain_len); pos += 8;

    poly1305_mac(mac_buf, pos, poly_block, tag_out);

    memory_cleanse(mac_buf, mac_len);
    memory_cleanse(poly_block, sizeof(poly_block));
    free(mac_buf);
    return true;
}

static bool wbs_aead_decrypt(const uint8_t *ciphertext, size_t plain_len,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t *tag,
                              const uint8_t nonce[12],
                              const uint8_t key[32],
                              uint8_t *plain_out)
{
    uint8_t poly_block[64];
    chacha20_block(key, 0, nonce, poly_block);

    size_t pad_aad, pad_ct;
    wbs_pad16_len(aad_len,   &pad_aad);
    wbs_pad16_len(plain_len, &pad_ct);
    size_t mac_len = aad_len + pad_aad + plain_len + pad_ct + 16;
    uint8_t *mac_buf = zcl_calloc(1, mac_len > 0 ? mac_len : 1, "aead_decrypt mac_buf");
    if (!mac_buf) {
        memory_cleanse(poly_block, sizeof(poly_block));
        LOG_FAIL("wallet_backup", "aead_decrypt: mac_buf alloc failed (%zu bytes)", mac_len);
    }
    size_t pos = 0;
    if (aad_len)   { memcpy(mac_buf + pos, aad, aad_len); pos += aad_len; }
    pos += pad_aad;
    if (plain_len) { memcpy(mac_buf + pos, ciphertext, plain_len); pos += plain_len; }
    pos += pad_ct;
    wbs_store64_le(mac_buf + pos, (uint64_t)aad_len);   pos += 8;
    wbs_store64_le(mac_buf + pos, (uint64_t)plain_len); pos += 8;

    uint8_t computed[16];
    poly1305_mac(mac_buf, pos, poly_block, computed);

    memory_cleanse(mac_buf, mac_len);
    memory_cleanse(poly_block, sizeof(poly_block));
    free(mac_buf);

    /* Constant-time tag compare. */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= tag[i] ^ computed[i];
    memory_cleanse(computed, sizeof(computed));
    if (diff != 0) LOG_FAIL("wallet_backup", "aead_decrypt: tag verification failed");

    /* Tag verified - now decrypt. */
    chacha20_encrypt(key, 1, nonce, ciphertext, plain_len, plain_out);
    return true;
}

/* Publish bytes through a unique owner-private sibling and a durable,
 * handle-bound replacement. Existing destinations must already be private
 * regular files; links/reparse points fail closed. */
static bool wbs_write_file_atomic(const char *path,
                                   const uint8_t *buf, size_t len)
{
    if (!path || (!buf && len > 0))
        LOG_FAIL("wallet_backup", "write_file_atomic: NULL path or buf");

    char destination[1024], parent[1024];
    /* The message names the next action, not just the symptom. "not a safe
     * real directory" reads like corruption; the cause is almost always a
     * RELATIVE destination whose parent does not exist yet — a `-datadir=./x`
     * or a relative file argument. The resolver canonicalizes a relative
     * parent that DOES exist, so the two cases are worth distinguishing for
     * the reader rather than leaving them to guess. */
    if (!platform_private_destination_resolve(path, destination,
                                              sizeof(destination), parent,
                                              sizeof(parent)))
        LOG_FAIL("wallet_backup",
                 "write_file_atomic: cannot resolve the parent directory of "
                 "'%s' — pass an ABSOLUTE path and create the parent first "
                 "(a relative destination, or a relative -datadir=, lands "
                 "here)", path);

    struct platform_positioned_file existing;
    platform_positioned_file_init(&existing);
    bool exists = platform_positioned_file_open(&existing, destination);
    bool replaceable = exists &&
        platform_positioned_file_is_private(&existing);
    platform_positioned_file_close(&existing);
    if ((!exists && !platform_private_path_absent(destination)) ||
        (exists && !replaceable))
        LOG_FAIL("wallet_backup",
                 "write_file_atomic: destination is not private/no-reparse");

    static _Atomic uint64_t tmp_sequence;
    char tmp[1100];
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = false;
    for (unsigned int attempt = 0; attempt < 16 && !created; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &tmp_sequence, 1, memory_order_relaxed);
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%llu", destination,
                         (unsigned long long)sequence);
        if (n <= 0 || (size_t)n >= sizeof(tmp))
            LOG_FAIL("wallet_backup", "write_file_atomic: path too long (%s)",
                     path);
        created = platform_private_file_create(tmp, &staging);
    }
    if (!created)
        LOG_FAIL("wallet_backup",
                 "write_file_atomic: private staging creation failed");

    bool written = (len == 0 || platform_private_file_write_at(
                                  &staging, buf, len, 0)) &&
                   platform_private_file_flush(&staging);
    if (!written) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        LOG_FAIL("wallet_backup", "write_file_atomic: durable write failed");
    }
    if (!platform_private_file_replace(
            &staging, tmp, destination)) {
        (void)platform_private_file_retire(&staging, tmp);
        platform_private_file_close(&staging);
        LOG_FAIL("wallet_backup", "write_file_atomic: atomic replace failed");
    }
    if (!platform_private_parent_flush(parent))
        LOG_FAIL("wallet_backup",
                 "write_file_atomic: parent durability barrier failed");
    return true;
}

struct zcl_result wallet_backup_encrypt_file(const char *src_path,
                                 const char *dst_path,
                                 const char *password)
{
    if (!src_path || !dst_path || !password || !*password)
        return ZCL_ERR(-1, "encrypt_file: NULL or empty argument");

    uint8_t *plain = NULL;
    size_t   plen  = 0;
    if (!zcl_read_whole_file(src_path, 0, &plain, &plen, "wallet_backup"))
        return ZCL_ERR(-2, "encrypt_file: failed to read %s", src_path);

    /* Fresh salt + nonce from the system CSPRNG. */
    uint8_t salt[WALLET_BACKUP_ENC_SALT_LEN];
    uint8_t nonce[WALLET_BACKUP_ENC_NONCE_LEN];
    GetRandBytes(salt,  sizeof(salt));
    GetRandBytes(nonce, sizeof(nonce));

    /* Derive the AEAD key. */
    uint8_t key[WALLET_BACKUP_ENC_KEY_LEN];
    pbkdf2_hmac_sha256((const uint8_t *)password, strlen(password),
                        salt, sizeof(salt),
                        WALLET_BACKUP_ENC_ITERATIONS,
                        key, sizeof(key));

    /* Build the header (also serves as AAD). */
    uint8_t header[WALLET_BACKUP_ENC_HEADER_LEN];
    memset(header, 0, sizeof(header));
    memcpy(header, WALLET_BACKUP_ENC_MAGIC, 4);
    uint32_t ver = WALLET_BACKUP_ENC_VERSION;
    uint32_t its = WALLET_BACKUP_ENC_ITERATIONS;
    header[4]  = (uint8_t)(ver);
    header[5]  = (uint8_t)(ver >>  8);
    header[6]  = (uint8_t)(ver >> 16);
    header[7]  = (uint8_t)(ver >> 24);
    header[8]  = (uint8_t)(its);
    header[9]  = (uint8_t)(its >>  8);
    header[10] = (uint8_t)(its >> 16);
    header[11] = (uint8_t)(its >> 24);
    /* reserved [12..16] stays zero */
    memcpy(header + 16, salt,  sizeof(salt));
    memcpy(header + 32, nonce, sizeof(nonce));

    /* Allocate the output buffer: header + ciphertext + tag. */
    size_t out_len = sizeof(header) + plen + WALLET_BACKUP_ENC_TAG_LEN;
    uint8_t *out = zcl_malloc(out_len, "wallet_backup encrypt_buf");
    if (!out) {
        free(plain);
        memory_cleanse(key, sizeof(key));
        return ZCL_ERR(-3, "encrypt_file: malloc failed (%zu bytes) for %s", out_len, src_path);
    }
    memcpy(out, header, sizeof(header));

    /* Encrypt into out + header, tag follows. */
    bool ok = wbs_aead_encrypt(plain, plen,
                                header, sizeof(header),
                                nonce, key,
                                out + sizeof(header),
                                out + sizeof(header) + plen);
    /* Scrub sensitive material promptly. */
    memory_cleanse(key, sizeof(key));
    memory_cleanse(plain, plen);
    free(plain);

    if (!ok) {
        free(out);
        return ZCL_ERR(-4, "encrypt_file: AEAD encryption failed for %s", src_path);
    }

    bool wrote = wbs_write_file_atomic(dst_path, out, out_len);
    free(out);
    if (!wrote)
        return ZCL_ERR(-5, "encrypt_file: failed to write %s", dst_path);
    return ZCL_OK;
}

struct zcl_result wallet_backup_decrypt_file(const char *src_path,
                                 const char *dst_path,
                                 const char *password)
{
    if (!src_path || !dst_path || !password || !*password)
        return ZCL_ERR(-1, "decrypt_file: NULL or empty argument");

    uint8_t *enc = NULL;
    size_t   elen = 0;
    if (!zcl_read_whole_file(src_path, 0, &enc, &elen, "wallet_backup"))
        return ZCL_ERR(-2, "decrypt_file: failed to read %s", src_path);

    if (elen < (size_t)(WALLET_BACKUP_ENC_HEADER_LEN +
                         WALLET_BACKUP_ENC_TAG_LEN)) {
        free(enc); return ZCL_ERR(-3, "decrypt_file: %s too short (%zu bytes)", src_path, elen);
    }

    if (memcmp(enc, WALLET_BACKUP_ENC_MAGIC, 4) != 0) {
        free(enc); return ZCL_ERR(-4, "decrypt_file: bad magic in %s", src_path);
    }

    uint32_t ver = (uint32_t)enc[4]       |
                   ((uint32_t)enc[5] <<  8) |
                   ((uint32_t)enc[6] << 16) |
                   ((uint32_t)enc[7] << 24);
    if (ver != WALLET_BACKUP_ENC_VERSION) {
        free(enc); return ZCL_ERR(-5, "decrypt_file: unsupported version %u in %s", ver, src_path);
    }
    uint32_t its = (uint32_t)enc[8]       |
                   ((uint32_t)enc[9]  <<  8) |
                   ((uint32_t)enc[10] << 16) |
                   ((uint32_t)enc[11] << 24);
    if (its == 0 || its > (1u << 24)) { /* sanity cap */
        free(enc); return ZCL_ERR(-6, "decrypt_file: bad iteration count %u in %s", its, src_path);
    }

    const uint8_t *salt  = enc + 16;
    const uint8_t *nonce = enc + 32;

    uint8_t key[WALLET_BACKUP_ENC_KEY_LEN];
    pbkdf2_hmac_sha256((const uint8_t *)password, strlen(password),
                        salt, WALLET_BACKUP_ENC_SALT_LEN,
                        its, key, sizeof(key));

    size_t body_len  = elen - WALLET_BACKUP_ENC_HEADER_LEN;
    size_t plain_len = body_len - WALLET_BACKUP_ENC_TAG_LEN;

    uint8_t *plain = NULL;
    if (plain_len > 0) {
        plain = zcl_malloc(plain_len, "wallet_backup decrypt_buf");
        if (!plain) {
            free(enc);
            memory_cleanse(key, sizeof(key));
            return ZCL_ERR(-7, "decrypt_file: malloc failed (%zu bytes) for %s", plain_len, src_path);
        }
    }

    const uint8_t *ciphertext = enc + WALLET_BACKUP_ENC_HEADER_LEN;
    const uint8_t *tag        = ciphertext + plain_len;
    bool ok = wbs_aead_decrypt(ciphertext, plain_len,
                                enc, WALLET_BACKUP_ENC_HEADER_LEN,
                                tag, nonce, key, plain);
    memory_cleanse(key, sizeof(key));
    free(enc);

    if (!ok) {
        if (plain) memory_cleanse(plain, plain_len);
        free(plain);
        return ZCL_ERR(-8, "decrypt_file: AEAD decryption failed for %s", src_path);
    }

    bool wrote = wbs_write_file_atomic(dst_path, plain, plain_len);
    if (plain) memory_cleanse(plain, plain_len);
    free(plain);
    if (!wrote)
        return ZCL_ERR(-9, "decrypt_file: failed to write %s", dst_path);
    return ZCL_OK;
}
