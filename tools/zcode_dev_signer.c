/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: offline non-wallet development signer for ZCODE release digests. */

#define _POSIX_C_SOURCE 200809L

#include "base/cleanse.h"
#include "base/hex.h"

#include <secp256k1.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool signer_read_n(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, buf + off, len - off);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        off += (size_t)got;
    }
    return true;
}

static bool signer_read_exact(int fd, uint8_t *buf, size_t len)
{
    if (!signer_read_n(fd, buf, len))
        return false;
    uint8_t trailing;
    ssize_t got;
    do {
        got = read(fd, &trailing, 1);
    } while (got < 0 && errno == EINTR);
    return got == 0;
}

static bool signer_write_exact(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t put = write(fd, buf + off, len - off);
        if (put < 0 && errno == EINTR)
            continue;
        if (put <= 0)
            return false;
        off += (size_t)put;
    }
    return true;
}

static bool signer_fd_number(const char *text, int *out)
{
    if (!text || !text[0])
        return false;
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 0 || value > 1024)
        return false;
    *out = (int)value;
    return true;
}

static bool signer_key_fd(int fd, uint8_t secret[32])
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(stderr, "z23-package-sign: key fd must name a regular file\n");
        return false;
    }
    unsigned mode = (unsigned)(st.st_mode & 0777u);
    if (mode != 0600u && mode != 0400u) {
        fprintf(stderr,
                "z23-package-sign: key fd permissions are %03o; require 0600 or 0400\n",
                mode);
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0 || !signer_read_exact(fd, secret, 32)) {
        fprintf(stderr, "z23-package-sign: key fd must contain exactly 32 bytes\n");
        return false;
    }
    return true;
}

static bool signer_public(secp256k1_context *ctx, const uint8_t secret[32],
                          uint8_t out[33])
{
    secp256k1_pubkey pubkey;
    size_t len = 33;
    return secp256k1_ec_seckey_verify(ctx, secret) == 1 &&
           secp256k1_ec_pubkey_create(ctx, &pubkey, secret) == 1 &&
           secp256k1_ec_pubkey_serialize(ctx, out, &len, &pubkey,
                                        SECP256K1_EC_COMPRESSED) == 1 &&
           len == 33;
}

static int signer_generate(const char *path, secp256k1_context *ctx)
{
    int random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (random_fd < 0) {
        fprintf(stderr, "z23-package-sign: cannot open system RNG: %s\n",
                strerror(errno));
        return 1;
    }
    uint8_t secret[32];
    do {
        if (!signer_read_n(random_fd, secret, sizeof(secret))) {
            fprintf(stderr, "z23-package-sign: system RNG read failed\n");
            close(random_fd);
            memory_cleanse(secret, sizeof(secret));
            return 1;
        }
    } while (secp256k1_ec_seckey_verify(ctx, secret) != 1);
    close(random_fd);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        fprintf(stderr, "z23-package-sign: refusing to replace %s: %s\n",
                path, strerror(errno));
        memory_cleanse(secret, sizeof(secret));
        return 1;
    }
    bool wrote = signer_write_exact(fd, secret, sizeof(secret)) &&
                 fsync(fd) == 0;
    if (close(fd) != 0)
        wrote = false;
    if (!wrote) {
        fprintf(stderr, "z23-package-sign: key write failed: %s\n",
                strerror(errno));
        memory_cleanse(secret, sizeof(secret));
        return 1;
    }
    uint8_t pubkey[33];
    bool ok = signer_public(ctx, secret, pubkey);
    memory_cleanse(secret, sizeof(secret));
    if (!ok)
        return 1;
    char hex[67];
    zcl_hex_encode(pubkey, sizeof(pubkey), hex);
    printf("%s\n", hex);
    return 0;
}

static int signer_show_public(int key_fd, secp256k1_context *ctx)
{
    uint8_t secret[32], pubkey[33];
    if (!signer_key_fd(key_fd, secret))
        return 1;
    bool ok = signer_public(ctx, secret, pubkey);
    memory_cleanse(secret, sizeof(secret));
    if (!ok) {
        fprintf(stderr, "z23-package-sign: invalid secp256k1 secret\n");
        return 1;
    }
    char hex[67];
    zcl_hex_encode(pubkey, sizeof(pubkey), hex);
    printf("%s\n", hex);
    return 0;
}

static bool signer_sign_digest(int key_fd, const uint8_t digest[32],
                               uint8_t compact[64],
                               secp256k1_context *ctx)
{
    uint8_t secret[32];
    if (!signer_key_fd(key_fd, secret))
        return false;
    secp256k1_ecdsa_signature signature, normalized;
    bool ok = secp256k1_ecdsa_sign(ctx, &signature, digest, secret, NULL,
                                  NULL) == 1;
    memory_cleanse(secret, sizeof(secret));
    if (ok) {
        (void)secp256k1_ecdsa_signature_normalize(ctx, &normalized,
                                                  &signature);
        ok = secp256k1_ecdsa_signature_serialize_compact(ctx, compact,
                                                         &normalized) == 1;
    }
    memory_cleanse(&signature, sizeof(signature));
    memory_cleanse(&normalized, sizeof(normalized));
    return ok;
}

static int signer_sign(int key_fd, int digest_fd, int signature_fd,
                       secp256k1_context *ctx)
{
    uint8_t digest[32], compact[64];
    if (!signer_read_exact(digest_fd, digest, sizeof(digest))) {
        fprintf(stderr, "z23-package-sign: digest fd must contain exactly 32 bytes\n");
        return 1;
    }
    if (!signer_sign_digest(key_fd, digest, compact, ctx) ||
        !signer_write_exact(signature_fd, compact, sizeof(compact))) {
        fprintf(stderr, "z23-package-sign: signing or signature-fd write failed\n");
        memory_cleanse(compact, sizeof(compact));
        return 1;
    }
    memory_cleanse(compact, sizeof(compact));
    return 0;
}

static int signer_sign_hex(int key_fd, const char *digest_hex,
                           secp256k1_context *ctx)
{
    uint8_t digest[32], compact[64];
    if (!digest_hex || strlen(digest_hex) != 64u ||
        !zcl_hex_decode_lower(digest_hex, digest, sizeof(digest))) {
        fprintf(stderr,
                "z23-package-sign: --sign-digest requires exactly 64 lowercase hex characters\n");
        return 2;
    }
    if (!signer_sign_digest(key_fd, digest, compact, ctx)) {
        fprintf(stderr, "z23-package-sign: signing failed\n");
        memory_cleanse(compact, sizeof(compact));
        return 1;
    }
    char signature_hex[129];
    zcl_hex_encode(compact, sizeof(compact), signature_hex);
    memory_cleanse(compact, sizeof(compact));
    printf("%s\n", signature_hex);
    return 0;
}

static void signer_usage(void)
{
    fprintf(stderr,
            "usage:\n"
            "  z23-package-sign --generate PATH\n"
            "  z23-package-sign --public --key-fd N\n"
            "  z23-package-sign --sign-digest 64HEX --key-fd N\n"
            "  z23-package-sign --sign --key-fd N --digest-fd N --signature-fd N\n");
}

struct signer_options {
    const char *generate;
    const char *sign_digest;
    bool show_public, sign;
    int key_fd, digest_fd, signature_fd;
};

static bool signer_parse_mode_option(int argc, char **argv, int *i,
                                     struct signer_options *opt)
{
    if (strcmp(argv[*i], "--generate") == 0 && *i + 1 < argc)
        opt->generate = argv[++*i];
    else if (strcmp(argv[*i], "--public") == 0)
        opt->show_public = true;
    else if (strcmp(argv[*i], "--sign") == 0)
        opt->sign = true;
    else if (strcmp(argv[*i], "--sign-digest") == 0 && *i + 1 < argc)
        opt->sign_digest = argv[++*i];
    else
        return false;
    return true;
}

static bool signer_parse_fd_option(int argc, char **argv, int *i,
                                   struct signer_options *opt)
{
    if (strcmp(argv[*i], "--key-fd") == 0 && *i + 1 < argc &&
        signer_fd_number(argv[++*i], &opt->key_fd))
        return true;
    if (strcmp(argv[*i], "--digest-fd") == 0 && *i + 1 < argc &&
        signer_fd_number(argv[++*i], &opt->digest_fd))
        return true;
    return strcmp(argv[*i], "--signature-fd") == 0 && *i + 1 < argc &&
           signer_fd_number(argv[++*i], &opt->signature_fd);
}

static bool signer_options_valid(const struct signer_options *opt)
{
    unsigned modes = (opt->generate ? 1u : 0u) + (opt->show_public ? 1u : 0u) +
                     (opt->sign ? 1u : 0u) + (opt->sign_digest ? 1u : 0u);
    return !(modes != 1u ||
             ((opt->show_public || opt->sign || opt->sign_digest) &&
              opt->key_fd < 0) ||
             (opt->sign && (opt->digest_fd < 0 || opt->signature_fd < 0)) ||
             (opt->sign_digest &&
              (opt->digest_fd >= 0 || opt->signature_fd >= 0)));
}

static int signer_run_mode(const struct signer_options *opt,
                           secp256k1_context *ctx)
{
    return opt->generate ? signer_generate(opt->generate, ctx) :
           opt->show_public ? signer_show_public(opt->key_fd, ctx) :
           opt->sign_digest ?
               signer_sign_hex(opt->key_fd, opt->sign_digest, ctx) :
           signer_sign(opt->key_fd, opt->digest_fd, opt->signature_fd, ctx);
}

int main(int argc, char **argv)
{
    struct signer_options opt = {.key_fd = -1, .digest_fd = -1,
                                 .signature_fd = -1};
    for (int i = 1; i < argc; i++) {
        if (signer_parse_mode_option(argc, argv, &i, &opt))
            ;
        else if (signer_parse_fd_option(argc, argv, &i, &opt))
            ;
        else {
            signer_usage();
            return 2;
        }
    }
    if (!signer_options_valid(&opt)) {
        signer_usage();
        return 2;
    }
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx)
        return 1;
    int rc = signer_run_mode(&opt, ctx);
    secp256k1_context_destroy(ctx);
    return rc;
}
