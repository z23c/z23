/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
#define _POSIX_C_SOURCE 200809L
#include "blue_ca.h"
#include "blue_secure.h"

#include <fcntl.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool valid_curve(EVP_PKEY *key) {
    char group[32];
    size_t length = 0;
    return key && EVP_PKEY_is_a(key, "EC") == 1 &&
        EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                       group, sizeof group, &length) > 0 &&
        strcmp(group, "secp256k1") == 0;
}

int blue_ca_generate(const char *path) {
    if (!path) return -1;
    EVP_PKEY *key = blue_key_generate();
    if (!valid_curve(key)) { EVP_PKEY_free(key); return -1; }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  S_IRUSR | S_IWUSR);
    if (fd < 0) { EVP_PKEY_free(key); return -1; }
    FILE *file = fdopen(fd, "w");
    if (!file) { close(fd); unlink(path); EVP_PKEY_free(key); return -1; }
    int written = PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL);
    int closed = fclose(file);
    EVP_PKEY_free(key);
    if (written != 1 || closed != 0) { unlink(path); return -1; }
    return 0;
}

EVP_PKEY *blue_ca_load(const char *path) {
    if (!path) return NULL;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (fd < 0) return NULL;
    if (fstat(fd, &info) < 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 077) != 0) {
        close(fd);
        return NULL;
    }
    FILE *file = fdopen(fd, "r");
    if (!file) { close(fd); return NULL; }
    EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!valid_curve(key)) { EVP_PKEY_free(key); return NULL; }
    return key;
}

int blue_ca_sign_digest(EVP_PKEY *key, const uint8_t digest[32],
                        uint8_t signature[73], size_t *signature_length) {
    if (!valid_curve(key) || !digest || !signature || !signature_length) return -1;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    size_t length = 73;
    int result = ctx && EVP_PKEY_sign_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_sign(ctx, signature, &length, digest, 32) > 0 &&
        length <= 73 ? 0 : -1;
    EVP_PKEY_CTX_free(ctx);
    if (result == 0) *signature_length = length;
    return result;
}

int blue_ca_app_hash(uint32_t target, const uint8_t create[21],
                     const uint8_t *code, size_t code_length,
                     const uint8_t *params, size_t params_length,
                     uint8_t digest[32]) {
    if (!create || create[0] != 0x0b || !code || !params || !digest)
        return -1;
    const uint8_t target_bytes[4] = {
        (uint8_t)(target >> 24), (uint8_t)(target >> 16),
        (uint8_t)(target >> 8), (uint8_t)target
    };
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int length = 0;
    int result = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) > 0 &&
        EVP_DigestUpdate(ctx, target_bytes, sizeof target_bytes) > 0 &&
        EVP_DigestUpdate(ctx, create + 1, 20) > 0 &&
        EVP_DigestUpdate(ctx, code, code_length) > 0 &&
        EVP_DigestUpdate(ctx, params, params_length) > 0 &&
        EVP_DigestFinal_ex(ctx, digest, &length) > 0 &&
        length == 32 ? 0 : -1;
    EVP_MD_CTX_free(ctx);
    return result;
}
