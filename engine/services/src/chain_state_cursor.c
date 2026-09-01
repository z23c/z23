/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:in-memory-cursor-effect — csr_align_coins_best_block()
// has one coherent effect (set the in-memory coins best-block cursor under
// csr->lock) and makes no fallible service decision: a null/uninitialized csr
// or null hash is a benign no-op precondition, reported as a plain bool
// (false == nothing to align). There is no failure reason to carry, so
// struct zcl_result would add ceremony without information. Mirrors the bool
// contract of csr_restore_in_memory_view in chain_state_service.c.

/*
 * chain_state_cursor — narrow in-memory cursor alignment helpers split out of
 * chain_state_service.c to keep that file under the E1 ceiling. The single
 * helper here advances ONLY the in-memory coins-view best-block cursor under
 * csr->lock; it persists nothing and does not move the tip/header. See
 * services/chain_state_service.h for the contract.
 */

#include "services/chain_state_service.h"

#include <pthread.h>

bool csr_align_coins_best_block(struct chain_state_repository *csr,
                                const struct uint256 *hash)
{
    if (!csr || !csr->initialized || !hash)
        return false;
    pthread_mutex_lock(&csr->lock);
    bool ok = false;
    if (csr->coins_tip) {
        coins_view_cache_set_best_block(csr->coins_tip, hash);
        ok = true;
    }
    pthread_mutex_unlock(&csr->lock);
    return ok;
}
