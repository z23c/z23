/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bg_validation_internal — sibling-private declarations shared between
 * bg_validation_service.c (the thread + public API) and the script/proof
 * verification translation units. This is not a public header. */

#ifndef ZCL_BG_VALIDATION_INTERNAL_H
#define ZCL_BG_VALIDATION_INTERNAL_H

#include "services/bg_validation_service.h"
#include "script/script.h"
#include "validation/sighash.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct transaction;
struct block;
struct block_index;
struct chain_params;

/* Read one exact active-chain body. A torn or falsely flagged disk position
 * enters the shared condition-driven repair rail and is retried at the same
 * height until a hash-verified replacement is readable or shutdown begins. */
bool bg_validation_read_body_resilient(
    struct bg_validation_service *svc, int height, const char *datadir,
    enum bg_validation_state ready_state, struct block *block,
    struct block_index **index_out);
bool bg_validation_index_is_active(
    struct main_state *ms, int height, const struct block_index *expected);
enum bg_validation_block_outcome bg_validation_validate_canonical_block(
    struct main_state *ms, int height, const struct block *block,
    struct block_index *index, const char *datadir,
    const struct chain_params *params, int num_workers,
    size_t max_script_batch, int64_t *sigs_out, int64_t *proofs_out,
    int64_t *skips_out);
void bg_validation_supervisor_heartbeat(
    const struct bg_validation_service *svc);

/* ── Single-block read-only full validation (bg_validation_verify_block.c) ──
 * Verifies Equihash + PoW, structure, contextual header, all shielded proofs,
 * and every transparent script sig (spent outputs recovered from undo data).
 * Never mutates the UTXO set. Returns false + LOG_WARN(height, reject_reason)
 * on any failure. Called by the genesis→tip walk AND the sampled re-verify. */
bool bg_validation_validate_block_proofs(const struct block *block,
                                         struct block_index *pindex,
                                         const char *datadir,
                                         const struct chain_params *params,
                                         int num_workers,
                                         size_t max_script_batch,
                                         int64_t *sigs_out,
                                         int64_t *proofs_out,
                                         int64_t *skips_out);

/* ── Parallel script verification (bg_validation_scripts.c) ───────── */

struct script_check_item {
    const struct transaction *tx;
    unsigned int input_index;
    int64_t amount;
    uint32_t branch_id;
    struct precomputed_tx_data txdata;
    struct script script_pub_key;
    uint32_t flags;
};

/* Verify all script items in parallel using num_workers threads.
 * Falls back to serial for small batches. */
bool bg_validation_verify_scripts_parallel(struct script_check_item *items,
                                           size_t count, int num_workers);

/* ── Shielded proof verification (bg_validation_proofs.c) ─────────── */

/* Verifies JoinSplit Ed25519 sigs, Sprout Groth16/PHGR13 proofs,
 * and Sapling spend/output proofs + binding signature.
 * Returns false on verification failure, sets *proofs_out. */
bool bg_validation_verify_shielded_proofs(const struct transaction *tx,
                                          int height, size_t tx_idx,
                                          uint32_t branch_id,
                                          int64_t *proofs_out);

#endif /* ZCL_BG_VALIDATION_INTERNAL_H */
