/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "blue_secure.h"

#include <limits.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

EVP_PKEY *blue_key_generate(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    if (ctx && EVP_PKEY_keygen_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_group_name(ctx, "secp256k1") > 0 &&
        EVP_PKEY_keygen(ctx, &key) <= 0) key = NULL;
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int blue_key_public(EVP_PKEY *key, uint8_t output[65]) {
    size_t length = 0;
    return key && output &&
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                        output, 65, &length) > 0 &&
        length == 65 && output[0] == 4 ? 0 : -1;
}

int blue_sign(EVP_PKEY *key, const uint8_t *message, size_t length,
              uint8_t *signature, size_t *signature_length) {
    if (!key || !message || !signature || !signature_length) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t capacity = *signature_length;
    size_t needed = 0;
    int result = ctx && EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) > 0 &&
        EVP_DigestSign(ctx, NULL, &needed, message, length) > 0 &&
        needed <= capacity &&
        EVP_DigestSign(ctx, signature, &needed, message, length) > 0 &&
        needed <= capacity ? 0 : -1;
    EVP_MD_CTX_free(ctx);
    if (result == 0) *signature_length = needed;
    return result;
}

static EVP_PKEY *import_public(const uint8_t public_key[65]) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                (void *)public_key, 65),
        OSSL_PARAM_END
    };
    if (ctx && EVP_PKEY_fromdata_init(ctx) > 0 &&
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        key = NULL;
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int blue_verify(const uint8_t public_key[65], const uint8_t *message,
                size_t length, const uint8_t *signature, size_t signature_length) {
    if (!public_key || public_key[0] != 4 || !message || !signature) return -1;
    EVP_PKEY *key = import_public(public_key);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = key && ctx &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) > 0 &&
        EVP_DigestVerify(ctx, signature, signature_length, message, length) == 1
        ? 0 : -1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return result;
}

/* Loads the private scalar into *scalar (owned and cleared by the caller) and
 * computes shared = scalar * peer, rejecting off-curve and infinity points. */
static int ecdh_multiply(EVP_PKEY *local, const uint8_t peer[65],
                         const EC_GROUP *group, BN_CTX *ctx, EC_POINT *point,
                         EC_POINT *shared, BIGNUM **scalar) {
    return EVP_PKEY_get_bn_param(local, OSSL_PKEY_PARAM_PRIV_KEY, scalar) > 0 &&
        EC_POINT_oct2point(group, point, peer, 65, ctx) > 0 &&
        EC_POINT_is_on_curve(group, point, ctx) == 1 &&
        EC_POINT_mul(group, shared, NULL, point, *scalar, ctx) > 0 &&
        EC_POINT_is_at_infinity(group, shared) == 0 ? 0 : -1;
}

int blue_ecdh(EVP_PKEY *local, const uint8_t peer[65], uint8_t secret[32]) {
    if (!local || !peer || peer[0] != 4 || !secret) return -1;
    BIGNUM *scalar = NULL;
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    EC_POINT *shared = group ? EC_POINT_new(group) : NULL;
    uint8_t compressed[33];
    int result = ctx && group && point && shared &&
        ecdh_multiply(local, peer, group, ctx, point, shared, &scalar) == 0 &&
        EC_POINT_point2oct(group, shared, POINT_CONVERSION_COMPRESSED,
                           compressed, sizeof compressed, ctx) == sizeof compressed &&
        SHA256(compressed, sizeof compressed, secret) ? 0 : -1;
    OPENSSL_cleanse(compressed, sizeof compressed);
    BN_clear_free(scalar);
    EC_POINT_free(shared);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    return result;
}

static int derive_key(const uint8_t secret[32], uint32_t index,
                      uint8_t key[16]) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *order = BN_new();
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    uint8_t input[37] = {(uint8_t)(index >> 24), (uint8_t)(index >> 16),
                         (uint8_t)(index >> 8), (uint8_t)index, 0};
    uint8_t digest[32], public_key[65];
    memcpy(input + 5, secret, 32);
    int result = -1;
    if (!group || !ctx || !order || !point ||
        !EC_GROUP_get_order(group, order, ctx)) goto done;
    for (unsigned retry = 0; retry < 256; ++retry) {
        input[4] = (uint8_t)retry;
        if (!SHA256(input, sizeof input, digest)) break;
        BIGNUM *scalar = BN_bin2bn(digest, sizeof digest, NULL);
        if (!scalar) break;
        if (!BN_is_zero(scalar) && BN_cmp(scalar, order) < 0 &&
            EC_POINT_mul(group, point, scalar, NULL, NULL, ctx) > 0 &&
            EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                               public_key, sizeof public_key, ctx) == sizeof public_key &&
            SHA256(public_key, sizeof public_key, digest)) {
            memcpy(key, digest, 16);
            result = 0;
            BN_clear_free(scalar);
            break;
        }
        BN_clear_free(scalar);
    }
done:
    OPENSSL_cleanse(input, sizeof input);
    OPENSSL_cleanse(digest, sizeof digest);
    OPENSSL_cleanse(public_key, sizeof public_key);
    EC_POINT_free(point);
    BN_free(order);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return result;
}

int blue_secure_init(blue_secure_channel *channel, const uint8_t secret[32]) {
    if (!channel || !secret) return -1;
    memset(channel, 0, sizeof *channel);
    if (derive_key(secret, 0, channel->enc_key) < 0 ||
        derive_key(secret, 1, channel->mac_key) < 0) {
        OPENSSL_cleanse(channel, sizeof *channel);
        return -1;
    }
    return 0;
}

static int aes_cbc(const uint8_t key[16], const uint8_t iv[16],
                   const uint8_t *input, size_t length, uint8_t *output,
                   bool encrypt) {
    if (length > INT_MAX || length % 16) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, tail = 0;
    int result = ctx && EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key,
                                          iv, encrypt ? 1 : 0) > 0 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) > 0 &&
        EVP_CipherUpdate(ctx, output, &n, input, (int)length) > 0 &&
        EVP_CipherFinal_ex(ctx, output + n, &tail) > 0 &&
        (size_t)(n + tail) == length ? 0 : -1;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int blue_secure_wrap(blue_secure_channel *channel, const uint8_t *plain,
                     size_t plain_length, uint8_t *output, size_t capacity,
                     size_t *output_length) {
    if (!channel || (plain_length && !plain) || !output || !output_length) return -1;
    if (!plain_length) { *output_length = 0; return 0; }
    if (plain_length > SIZE_MAX - 16) return -1;
    size_t padded = (plain_length + 16) & ~(size_t)15;
    if (padded + 14 > capacity || padded > 240) return -1;
    uint8_t buffer[240], mac[240];
    memcpy(buffer, plain, plain_length);
    buffer[plain_length] = 0x80;
    memset(buffer + plain_length + 1, 0, padded - plain_length - 1);
    int result = aes_cbc(channel->enc_key, channel->enc_iv,
                         buffer, padded, output, true);
    if (result == 0) result = aes_cbc(channel->mac_key, channel->mac_iv,
                                      output, padded, mac, true);
    if (result == 0) {
        memcpy(channel->enc_iv, output + padded - 16, 16);
        memcpy(channel->mac_iv, mac + padded - 16, 16);
        memcpy(output + padded, channel->mac_iv + 2, 14);
        *output_length = padded + 14;
    }
    OPENSSL_cleanse(buffer, sizeof buffer);
    OPENSSL_cleanse(mac, sizeof mac);
    return result;
}

static bool unwrap_length_invalid(size_t input_length, size_t capacity) {
    return input_length < 30 || (input_length - 14) % 16 ||
        input_length - 14 > capacity || input_length - 14 > 240;
}

/* Strips the 0x80 00.. padding from the decrypted block and, only on success,
 * reports the plaintext length and advances both chaining IVs. */
static int unwrap_finish(blue_secure_channel *channel, const uint8_t *plain,
                         size_t ciphertext_length,
                         const uint8_t last_ciphertext[16], const uint8_t *mac,
                         size_t *plain_length) {
    size_t length = ciphertext_length;
    while (length && plain[length - 1] == 0) --length;
    if (!length || plain[length - 1] != 0x80) return -1;
    *plain_length = length - 1;
    memcpy(channel->enc_iv, last_ciphertext, 16);
    memcpy(channel->mac_iv, mac + ciphertext_length - 16, 16);
    return 0;
}

int blue_secure_unwrap(blue_secure_channel *channel, const uint8_t *input,
                       size_t input_length, uint8_t *plain, size_t capacity,
                       size_t *plain_length) {
    if (!channel || !input || !plain || !plain_length) return -1;
    if (!input_length) { *plain_length = 0; return 0; }
    if (unwrap_length_invalid(input_length, capacity)) return -1;
    size_t ciphertext_length = input_length - 14;
    uint8_t mac[240], last_ciphertext[16];
    memcpy(last_ciphertext, input + ciphertext_length - 16, 16);
    int result = aes_cbc(channel->mac_key, channel->mac_iv,
                         input, ciphertext_length, mac, true);
    if (result == 0 && CRYPTO_memcmp(mac + ciphertext_length - 14,
                                     input + ciphertext_length, 14) != 0)
        result = -1;
    if (result == 0) result = aes_cbc(channel->enc_key, channel->enc_iv,
                                      input, ciphertext_length, plain, false);
    if (result == 0)
        result = unwrap_finish(channel, plain, ciphertext_length,
                               last_ciphertext, mac, plain_length);
    if (result < 0) OPENSSL_cleanse(plain, capacity);
    OPENSSL_cleanse(mac, sizeof mac);
    return result;
}
