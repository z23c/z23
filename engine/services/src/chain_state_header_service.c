/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Serialized, work-ranked validated-header publication. */

// one-result-type-ok:internal-csr-enum-contract-with-named-rejections

#include "chain_state_internal.h"

#include "core/arith_uint256.h"
#include "util/log_macros.h"

bool csr_internal_header_candidate_strictly_better(
    const struct block_index *candidate,
    const struct block_index *current)
{
    if (!candidate || candidate == current)
        return false;
    if (!current)
        return true;
    bool have_work = !arith_uint256_is_zero(&candidate->nChainWork) &&
                     !arith_uint256_is_zero(&current->nChainWork);
    if (have_work)
        return arith_uint256_compare(&candidate->nChainWork,
                                     &current->nChainWork) > 0;
    return candidate->nHeight > current->nHeight;
}

enum csr_result csr_promote_header_tip(
    struct chain_state_repository *csr,
    struct active_chain *expected_chain,
    struct block_index **expected_header_slot,
    struct block_index *candidate,
    const char *reason,
    bool *promoted)
{
    if (promoted)
        *promoted = false;
    if (!csr)
        return CSR_REJECTED_NULL_INPUT;

    pthread_mutex_lock(&csr->lock);
    if (!csr->initialized || !csr->pindex_best_hdr ||
        csr->chain_active != expected_chain ||
        csr->pindex_best_hdr != expected_header_slot) {
        pthread_mutex_unlock(&csr->lock);
        return CSR_REJECTED_NOT_INITIALIZED;
    }
    enum csr_result rc = csr_internal_validate_header_identity_locked(
        csr, candidate, reason);
    if (rc != CSR_OK) {
        csr->commits_rejected[rc]++;
        pthread_mutex_unlock(&csr->lock);
        LOG_WARN("csr", "header promotion rejected code=%s to=%d reason=%s",
                 csr_result_name(rc), candidate ? candidate->nHeight : -1,
                 reason ? reason : "");
        return rc;
    }

    struct block_index *current = *csr->pindex_best_hdr;
    bool advance = csr_internal_header_candidate_strictly_better(candidate,
                                                                 current);
    if (advance) {
        *csr->pindex_best_hdr = candidate;
        csr->commits_ok++;
    }
    pthread_mutex_unlock(&csr->lock);
    if (promoted)
        *promoted = advance;
    if (advance)
        LOG_INFO("csr", "header promoted from=%d to=%d reason=%s",
                 current ? current->nHeight : -1, candidate->nHeight, reason);
    return CSR_OK;
}
