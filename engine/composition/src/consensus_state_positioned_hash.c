/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: streaming SHA3-256 of a positioned file. Contract:
 * consensus_state_positioned_hash.h. */

#include "consensus_state_positioned_hash.h"

#include "crypto/sha3.h"
#include "platform/positioned_file.h"

#include <stddef.h>

bool consensus_state_hash_positioned_file(struct platform_positioned_file *file,
                                          uint64_t size,
                                          struct sha3_256_ctx *ctx)
{
    uint8_t buffer[32768];
    uint64_t offset = 0;
    while (offset < size) {
        size_t want = size - offset < sizeof(buffer)
                          ? (size_t)(size - offset)
                          : sizeof(buffer);
        int64_t n = platform_positioned_file_read(file, buffer, want, offset);
        if (n != (int64_t)want)
            return false;
        sha3_256_write(ctx, buffer, want);
        offset += want;
    }
    return true;
}
