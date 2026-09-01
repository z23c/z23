/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Verify hash binding and existing consensus predicates on imported rows. */

#include "snapshot_import_row_verify.h"
#include "primitives/block.h"
#include "services/block_row_verify.h"
#include <stdio.h>
#include <string.h>

#define IMPORT_ROW_POW_STRIDE 10000

static void import_row_build_header(const struct disk_block_index *dbi,
                                    struct block_header *out)
{
    block_header_init(out);
    out->nVersion = dbi->nVersion;
    out->hashPrevBlock = dbi->hashPrev;
    out->hashMerkleRoot = dbi->hashMerkleRoot;
    out->hashFinalSaplingRoot = dbi->hashFinalSaplingRoot;
    out->nTime = dbi->nTime;
    out->nBits = dbi->nBits;
    out->nNonce = dbi->nNonce;
    size_t sol_len = dbi->nSolutionSize;
    if (sol_len > sizeof(out->nSolution))
        sol_len = sizeof(out->nSolution);
    memcpy(out->nSolution, dbi->nSolution, sol_len);
    out->nSolutionSize = sol_len;
}

bool snapshot_import_row_verify(const struct disk_block_index *dbi,
                                const uint8_t block_hash[32],
                                const struct chain_params *cp,
                                int64_t rom_checkpoint_height,
                                char *out_reason, size_t out_reason_size)
{
    bool full_check =
        (dbi->nHeight > 0 && (dbi->nHeight % IMPORT_ROW_POW_STRIDE) == 0) ||
        (rom_checkpoint_height >= 0 && dbi->nHeight > rom_checkpoint_height);

    struct block_header h;
    import_row_build_header(dbi, &h);

    switch (block_row_verify(block_hash, dbi->nBits, &h, cp, full_check)) {
        case BLOCK_ROW_VERIFY_OK:
            return true;
        case BLOCK_ROW_VERIFY_NO_PARAMS:
            snprintf(out_reason, out_reason_size, "no-chain-params");
            return false;
        case BLOCK_ROW_VERIFY_HASH_BIND_MISMATCH:
            snprintf(out_reason, out_reason_size, "hash-bind-mismatch");
            return false;
        case BLOCK_ROW_VERIFY_HIGH_HASH:
            snprintf(out_reason, out_reason_size, "high-hash");
            return false;
        case BLOCK_ROW_VERIFY_BAD_EQUIHASH:
            snprintf(out_reason, out_reason_size, "invalid-equihash-solution");
            return false;
    }
    snprintf(out_reason, out_reason_size, "unknown-verify-verdict");
    return false;
}
