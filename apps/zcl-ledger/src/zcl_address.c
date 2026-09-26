/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_address.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <string.h>

static int valid_pubkey(const uint8_t pubkey[ZCL_COMPRESSED_PUBKEY_SIZE]) {
    if (pubkey[0] != 2 && pubkey[0] != 3) return 0;
    static const char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group,
                               sizeof group - 1),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pubkey,
                                ZCL_COMPRESSED_PUBKEY_SIZE),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    int valid = context && EVP_PKEY_fromdata_init(context) > 0 &&
                EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY,
                                  params) > 0;
    if (valid) {
        EVP_PKEY_CTX *check = EVP_PKEY_CTX_new(key, NULL);
        valid = check && EVP_PKEY_public_check(check) == 1;
        EVP_PKEY_CTX_free(check);
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return valid;
}

static int base58(const uint8_t *input, size_t length,
                  char output[ZCL_ADDRESS_SIZE]) {
    static const char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t digits[40] = {0};
    size_t used = 1;
    for (size_t i = 0; i < length; ++i) {
        unsigned int carry = input[i];
        for (size_t j = 0; j < used; ++j) {
            carry += (unsigned int)digits[j] * 256u;
            digits[j] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        while (carry) {
            if (used == sizeof digits) return -1;
            digits[used++] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
    }
    size_t zeros = 0;
    while (zeros < length && input[zeros] == 0) ++zeros;
    while (used && digits[used - 1] == 0) --used;
    if (zeros + used >= ZCL_ADDRESS_SIZE) return -1;
    size_t pos = 0;
    while (zeros--) output[pos++] = '1';
    while (used) output[pos++] = alphabet[digits[--used]];
    output[pos] = '\0';
    return 0;
}

int zcl_address_from_pubkey(const uint8_t pubkey[ZCL_COMPRESSED_PUBKEY_SIZE],
                            char address[ZCL_ADDRESS_SIZE]) {
    if (!pubkey || !address || !valid_pubkey(pubkey)) return -1;
    uint8_t digest[SHA256_DIGEST_LENGTH], checksum[SHA256_DIGEST_LENGTH];
    uint8_t payload[26];
    unsigned int hash_length = 0;
    if (!SHA256(pubkey, ZCL_COMPRESSED_PUBKEY_SIZE, digest) ||
        EVP_Digest(digest, sizeof digest, payload + 2, &hash_length,
                   EVP_ripemd160(), NULL) != 1 || hash_length != 20)
        return -1;
    payload[0] = 0x1c;
    payload[1] = 0xb8;
    if (!SHA256(payload, 22, digest) ||
        !SHA256(digest, sizeof digest, checksum)) return -1;
    memcpy(payload + 22, checksum, 4);
    return base58(payload, sizeof payload, address);
}
