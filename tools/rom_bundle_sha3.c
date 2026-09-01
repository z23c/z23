/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_bundle_sha3 — standalone SHA3-256 file digest tool. Used by
 * tools/scripts/rom-bundle-replicate.sh to verify a ROM bundle replication
 * copy byte-for-byte against its source, without pulling any external
 * hashing dependency (openssl/sha3sum/etc) into the dev toolchain — this
 * links only the project's own SHA3 implementation (platform/modules/sha3/src/sha3.c),
 * the same primitive every consensus-facing digest in the node uses.
 *
 * Usage: rom_bundle_sha3 FILE [FILE...]
 * Prints one "<64-hex-digest>  <path>\n" line per file, sha256sum-compatible
 * so it composes with the usual shell `cut`/`diff` idioms. Exit 0 iff every
 * named file opened and hashed cleanly; exit 1 on the first failure (with a
 * message on stderr identifying which file and why) so a replication script
 * fails closed rather than reporting a partial/garbled digest as success. */

#include "crypto/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int hash_one(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "rom_bundle_sha3: open '%s' failed: %s\n", path,
                strerror(errno));
        return -1;
    }

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            sha3_256_write(&ctx, buf, (size_t)n);
            continue;
        }
        if (n == 0)
            break;
        if (errno == EINTR)
            continue;
        fprintf(stderr, "rom_bundle_sha3: read '%s' failed: %s\n", path,
                strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    printf("%s  %s\n", hex, path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE [FILE...]\n", argv[0]);
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        if (hash_one(argv[i]) != 0)
            return 1;
    }
    return 0;
}
