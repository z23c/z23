/* purpose: Match on-disk block framing for reads, prefetch and position repair. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_STORAGE_BLOCK_FILE_MAGIC_H
#define Z23_STORAGE_BLOCK_FILE_MAGIC_H

#include "chain/chainparams.h"
#include <string.h>

/* Ordinary archive readers historically accept records from the three
 * compiled networks. An explicitly selected research store has one magic. */
static inline const uint8_t *block_file_profile_magic(void)
{
    const struct chain_research_descriptor *d = chain_research_profile_current();
    return d ? d->chain->pchMessageStart : NULL;
}

static inline bool block_file_magic_matches(const uint8_t frame[4], const uint8_t *required)
{
    static const uint8_t legacy[][4] = {
        {0x24, 0xe9, 0x27, 0x64},
        {0xfa, 0x1a, 0xf9, 0xbf},
        {0xaa, 0xe8, 0x3f, 0x5f}
    };
    if (required) return memcmp(frame, required, 4) == 0;
    for (size_t i = 0; i < sizeof(legacy) / sizeof(legacy[0]); i++)
        if (!memcmp(frame, legacy[i], 4)) return true;
    return false;
}

#endif
