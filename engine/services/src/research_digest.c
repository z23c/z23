/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Read the Ironwood genesis block SHA-256. */

#include "services/research_digest.h"

#include "chain/chainparams.h"
#include "crypto/sha256.h"

#include <string.h>

enum { DIGEST_LEN = SHA256_OUTPUT_SIZE };

struct zcl_result research_digest_read(unsigned char *raw, size_t raw_cap)
{
    const struct chain_research_descriptor *d;
    struct sha256_ctx ctx;

    if (!raw)
        return ZCL_ERR(-1, "Missing digest");
    if (raw_cap < DIGEST_LEN)
        return ZCL_ERR(-2, "Digest cap refused");
    d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    if (!d || !d->genesis_wire || d->genesis_wire_len == 0)
        return ZCL_ERR(-3, "Research digest missing");
    sha256_init(&ctx);
    sha256_write(&ctx, (const unsigned char *)d->genesis_wire,
                 d->genesis_wire_len);
    sha256_finalize(&ctx, raw);
    return ZCL_OK;
}
