/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_sign_test.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <string.h>

static EVP_PKEY *public_key(const uint8_t pubkey[33]) {
    static const char group[] = "secp256k1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)group,
                               sizeof group - 1),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pubkey, 33),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;
    if (!context || EVP_PKEY_fromdata_init(context) <= 0 ||
        EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

static bool valid_response(const uint8_t *reply, size_t length) {
    return reply && length >= 34 &&
        length <= 34 + ZCL_SIGN_TEST_MAX_DER &&
        (reply[0] == 2 || reply[0] == 3) &&
        reply[33] >= 8 && reply[33] <= ZCL_SIGN_TEST_MAX_DER &&
        length == 34u + (size_t)reply[33];
}

int zcl_sign_test_verify(const uint8_t *reply, size_t length,
                         uint8_t pubkey[ZCL_SIGN_TEST_PUBKEY_SIZE]) {
    if (!pubkey || !valid_response(reply, length)) return -1;
    EVP_PKEY *key = public_key(reply);
    EVP_PKEY_CTX *context = key ? EVP_PKEY_CTX_new(key, NULL) : NULL;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    static const char message[] = ZCL_SIGN_TEST_MESSAGE;
    int result = key && context && EVP_PKEY_public_check(context) == 1 &&
                 SHA256((const uint8_t *)message, sizeof message - 1,
                        digest) != NULL &&
                 EVP_PKEY_verify_init(context) > 0 &&
                 EVP_PKEY_CTX_set_signature_md(context, EVP_sha256()) > 0 &&
                 EVP_PKEY_verify(context, reply + 34, reply[33],
                                 digest, sizeof digest) == 1 ? 0 : -1;
    if (result == 0) memcpy(pubkey, reply, 33);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(key);
    return result;
}
