/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Derive the Ironwood release fork identity. */

#include "services/research_fork.h"

#include "sha3/sha3.h"

#include <string.h>

static const char fork_label[] =
    "Z23/Ironwood/private-testnet/2026-11-29/release-1";

_Static_assert(SHA3_256_OUTPUT_SIZE == 32, "fork identity is 32 bytes");

struct zcl_result research_fork_read(unsigned char *fork_id, size_t fork_cap)
{
    unsigned char digest[SHA3_256_OUTPUT_SIZE];

    if (!fork_id)
        return ZCL_ERR(-1, "Missing fork identity");
    if (fork_cap < SHA3_256_OUTPUT_SIZE)
        return ZCL_ERR(-2, "Fork cap refused");
    sha3_256((const unsigned char *)fork_label, sizeof fork_label - 1,
             digest);
    memcpy(fork_id, digest, SHA3_256_OUTPUT_SIZE);
    return ZCL_OK;
}
