/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — SHA3-256 artifact digest over an open file descriptor.
 * See hotswap/hotswap_artifact_digest.h for the fd-vs-path rationale and for
 * what a matching digest does and does not prove.
 */

#include "hotswap/hotswap_artifact_digest.h"

#include "base/hex.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <unistd.h>

bool hotswap_artifact_sha3_fd(int fd, char hex_out[65])
{
    if (fd < 0 || !hex_out || lseek(fd, 0, SEEK_SET) < 0)
        return false;
    hex_out[0] = '\0';
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) { sha3_256_write(&ctx, buf, (size_t)n); continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        return false;
    }
    if (lseek(fd, 0, SEEK_SET) < 0)
        return false;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, SHA3_256_OUTPUT_SIZE, hex_out);
    return true;
}
