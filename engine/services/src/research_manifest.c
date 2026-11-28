/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Checksum the Ironwood release manifest file. */

#include "services/research_manifest.h"

#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

#define MANIFEST_MAX 4096u

_Static_assert(SHA3_256_OUTPUT_SIZE == 32, "manifest checksum is 32 bytes");

static struct zcl_result hash_open_file(FILE *f,
                                        unsigned char digest[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    unsigned char buf[256];
    size_t total = 0;

    sha3_256_init(&ctx);
    for (;;) {
        size_t n = fread(buf, 1, sizeof buf, f);

        if (n > 0) {
            if (n > MANIFEST_MAX - total)
                return ZCL_ERR(-6, "Manifest too large");
            sha3_256_write(&ctx, buf, n);
            total += n;
        }
        if (n < sizeof buf)
            break;
    }
    if (ferror(f) != 0)
        return ZCL_ERR(-5, "Manifest unreadable");
    if (total == 0)
        return ZCL_ERR(-7, "Manifest empty");
    sha3_256_finalize(&ctx, digest);
    return ZCL_OK;
}

struct zcl_result research_manifest_read(const char *path,
                                         unsigned char *digest,
                                         size_t digest_cap)
{
    unsigned char got[SHA3_256_OUTPUT_SIZE];
    struct zcl_result r;
    FILE *f;

    if (!digest)
        return ZCL_ERR(-1, "Missing manifest");
    if (digest_cap < SHA3_256_OUTPUT_SIZE)
        return ZCL_ERR(-2, "Manifest cap refused");
    if (!path || path[0] == '\0')
        return ZCL_ERR(-3, "Missing manifest path");
    f = fopen(path, "rb");
    if (!f)
        return ZCL_ERR(-4, "Manifest unreadable");
    r = hash_open_file(f, got);
    if (fclose(f) != 0 && r.ok)
        return ZCL_ERR(-5, "Manifest unreadable");
    if (!r.ok)
        return r;
    memcpy(digest, got, SHA3_256_OUTPUT_SIZE);
    return ZCL_OK;
}
