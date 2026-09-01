/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The one shared test fixture that needs node block/transaction types.
 * Split out of test/test_helpers.h so a test that only needs assertions and
 * tmpdirs does not pull primitives/ into its include closure. */

#ifndef TEST_BLOCK_FIXTURES_H
#define TEST_BLOCK_FIXTURES_H

#include "test/test_core.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "util/safe_alloc.h"


/* Deep-copy a block (header + vtx with per-tx transaction_copy) for the
 * staged-pipeline fake readers. Shared by the body_persist / script_validate
 * / proof_validate / utxo_apply stage tests; `label` tags the vtx allocation
 * for leak attribution. Returns false on allocation/copy failure. */
static inline bool test_block_copy(struct block *dst, const struct block *src,
                                   const char *label)
{
    block_init(dst);
    dst->header = src->header;
    dst->num_vtx = src->num_vtx;
    if (src->num_vtx == 0) return true;
    dst->vtx = zcl_calloc(src->num_vtx, sizeof(struct transaction), label);
    if (!dst->vtx) return false;
    for (size_t i = 0; i < src->num_vtx; i++) {
        transaction_init(&dst->vtx[i]);
        if (!transaction_copy(&dst->vtx[i], &src->vtx[i]))
            return false;
    }
    return true;
}

#endif /* TEST_BLOCK_FIXTURES_H */
