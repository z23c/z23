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
    const uint8_t code[] = {1, 2, 3};
    const uint8_t params[] = {4, 5};
    const uint8_t expected[32] = {
        0x62, 0xe2, 0x5d, 0x7a, 0x11, 0x41, 0x09, 0xbd,
        0xa7, 0xb2, 0x70, 0x5d, 0xf3, 0x1c, 0x3e, 0x27,
        0x7d, 0xd8, 0x15, 0x9e, 0x3f, 0x00, 0xa7, 0x30,
        0x3b, 0x49, 0xc7, 0xd1, 0x0b, 0x4d, 0xb2, 0xff
    };
    uint8_t digest[32];
    assert(blue_ca_app_hash(0x31010004, create, code, sizeof code,
                            params, sizeof params, digest) == 0);
    assert(memcmp(digest, expected, sizeof digest) == 0);
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
    digest[0] = 2;
    assert(EVP_PKEY_verify(ctx, signature, length, digest, sizeof digest) != 1);
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
