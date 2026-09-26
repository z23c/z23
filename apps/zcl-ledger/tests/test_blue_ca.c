/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_ca.h"

#undef NDEBUG
#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void test_app_hash(void) {
    const uint8_t create[21] = {0x0b};
    const uint8_t version[] = {'2', '.', '1', '.', '1'};
    const uint8_t code[] = {1, 2, 3};
    const uint8_t params[] = {4, 5};
    const uint8_t expected[32] = {
        0x28, 0xfc, 0x9a, 0xae, 0xb6, 0xbd, 0x1d, 0x71,
        0x5e, 0x87, 0x98, 0x33, 0x55, 0xae, 0x99, 0x62,
        0x5e, 0x19, 0xc0, 0x65, 0x4b, 0x12, 0x6e, 0x00,
        0xfe, 0xe5, 0xea, 0xff, 0x75, 0xf5, 0x04, 0x02
    };
    uint8_t digest[32];
    assert(blue_ca_app_hash(0x31010004, version, sizeof version,
                            create, code, sizeof code,
                            params, sizeof params, digest) == 0);
    assert(memcmp(digest, expected, sizeof digest) == 0);
    assert(blue_ca_app_hash(0x31010004, version, 0, create, code,
                            sizeof code, params, sizeof params, digest) < 0);
}

static void test_key_file_and_signature(void) {
    char directory[] = "blue-ca-test-XXXXXX";
    assert(mkdtemp(directory));
    char path[sizeof directory + sizeof "/key.pem"];
    assert(snprintf(path, sizeof path, "%s/key.pem", directory) > 0);
    assert(blue_ca_generate(path) == 0);
    assert(blue_ca_generate(path) < 0);
    struct stat info;
    assert(stat(path, &info) == 0 && (info.st_mode & 077) == 0);
    EVP_PKEY *key = blue_ca_load(path);
    assert(key);
    uint8_t digest[32] = {1}, signature[73];
    size_t length = 0;
    assert(blue_ca_sign_digest(key, digest, signature, &length) == 0);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    assert(ctx && EVP_PKEY_verify_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0);
    assert(EVP_PKEY_verify(ctx, signature, length, digest, sizeof digest) == 1);
    EVP_PKEY_CTX *raw = EVP_PKEY_CTX_new(key, NULL);
    assert(raw && EVP_PKEY_verify_init(raw) > 0);
    assert(EVP_PKEY_verify(raw, signature, length, digest, sizeof digest) == 1);
    digest[0] = 2;
    assert(EVP_PKEY_verify(ctx, signature, length, digest, sizeof digest) != 1);
    EVP_PKEY_CTX_free(raw);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    assert(chmod(path, 0644) == 0 && blue_ca_load(path) == NULL);
    assert(unlink(path) == 0 && rmdir(directory) == 0);
}

int main(void) {
    test_app_hash();
    test_key_file_and_signature();
    return 0;
}
