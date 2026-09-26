/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#include "zcl_sign_test.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#undef NDEBUG
#include <assert.h>
#include <string.h>

static EVP_PKEY *test_key(uint8_t pubkey[33]) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    assert(context && EVP_PKEY_keygen_init(context) > 0 &&
           EVP_PKEY_CTX_set_group_name(context, "secp256k1") > 0);
    EVP_PKEY *key = NULL;
    assert(EVP_PKEY_generate(context, &key) > 0);
    EVP_PKEY_CTX_free(context);
    uint8_t uncompressed[65];
    size_t length = sizeof uncompressed;
    assert(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                            uncompressed, length, &length) > 0);
    assert(length == 65 && uncompressed[0] == 4);
    pubkey[0] = (uint8_t)(2u | (uncompressed[64] & 1u));
    memcpy(pubkey + 1, uncompressed + 1, 32);
    return key;
}

int main(void) {
    uint8_t reply[34 + ZCL_SIGN_TEST_MAX_DER], parsed[33];
    EVP_PKEY *key = test_key(reply);
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new(key, NULL);
    assert(context && EVP_PKEY_sign_init(context) > 0 &&
           EVP_PKEY_CTX_set_signature_md(context, EVP_sha256()) > 0);
    static const char message[] = ZCL_SIGN_TEST_MESSAGE;
    uint8_t digest[32];
    assert(SHA256((const uint8_t *)message, sizeof message - 1,
                  digest) != NULL);
    size_t signature_length = ZCL_SIGN_TEST_MAX_DER;
    assert(EVP_PKEY_sign(context, reply + 34, &signature_length,
                          digest, sizeof digest) > 0);
    assert(signature_length >= 8 && signature_length <= ZCL_SIGN_TEST_MAX_DER);
    reply[33] = (uint8_t)signature_length;
    size_t response_length = 34 + signature_length;
    assert(zcl_sign_test_verify(reply, response_length, parsed) == 0);
    assert(memcmp(parsed, reply, 33) == 0);
    reply[response_length - 1] ^= 1;
    assert(zcl_sign_test_verify(reply, response_length, parsed) < 0);
    reply[response_length - 1] ^= 1;
    reply[0] = 4;
    assert(zcl_sign_test_verify(reply, response_length, parsed) < 0);
    reply[0] = parsed[0];
    assert(zcl_sign_test_verify(reply, response_length - 1, parsed) < 0);
    assert(zcl_sign_test_verify(reply, 0, parsed) < 0);
    EVP_PKEY_CTX_free(context);
    EVP_PKEY_free(key);
    return 0;
}
