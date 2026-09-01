/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mint_skip_crypto — see jobs/mint_skip_crypto.h. Modeled exactly on
 * mint_fold_ceiling: a single _Atomic, default OFF, set ONLY by the mint
 * driver. */

#include "jobs/mint_skip_crypto.h"

#include <stdatomic.h>
#include <string.h>

/* Default OFF: a normal boot never calls _set, so both crypto step bodies see
 * `mint_skip_crypto_get() == false` and run the REAL per-block crypto —
 * byte-identical to today. Only the -mint-anchor fast driver flips it true. */
static _Atomic bool g_mint_skip_crypto = false;

void mint_skip_crypto_set(bool skip)
{
    atomic_store_explicit(&g_mint_skip_crypto, skip, memory_order_relaxed);
}

bool mint_skip_crypto_get(void)
{
    return atomic_load_explicit(&g_mint_skip_crypto, memory_order_relaxed);
}

enum mint_validation_evidence mint_validation_evidence_parse(
    const void *bytes, size_t size)
{
    static const char verified[] = "verified";
    static const char checkpoint[] = "checkpoint_fold";
    if (bytes && size == sizeof(verified) - 1 &&
        memcmp(bytes, verified, sizeof(verified) - 1) == 0)
        return MINT_VALIDATION_EVIDENCE_VERIFIED;
    if (bytes && size == sizeof(checkpoint) - 1 &&
        memcmp(bytes, checkpoint, sizeof(checkpoint) - 1) == 0)
        return MINT_VALIDATION_EVIDENCE_CHECKPOINT_FOLD;
    return MINT_VALIDATION_EVIDENCE_INVALID;
}

enum mint_validation_evidence mint_validation_evidence_expected(bool skip)
{
    return skip ? MINT_VALIDATION_EVIDENCE_CHECKPOINT_FOLD
                : MINT_VALIDATION_EVIDENCE_VERIFIED;
}

const char *mint_validation_evidence_status(
    enum mint_validation_evidence evidence)
{
    switch (evidence) {
    case MINT_VALIDATION_EVIDENCE_VERIFIED: return "verified";
    case MINT_VALIDATION_EVIDENCE_CHECKPOINT_FOLD: return "checkpoint_fold";
    case MINT_VALIDATION_EVIDENCE_INVALID: break;
    }
    return "invalid";
}
