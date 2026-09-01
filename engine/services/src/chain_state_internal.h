/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_SERVICES_CHAIN_STATE_INTERNAL_H
#define ZCL_SERVICES_CHAIN_STATE_INTERNAL_H

#include "services/chain_state_service.h"

int64_t csr_internal_sqlite_max_block_height(struct node_db *ndb);
int64_t csr_internal_sqlite_utxo_count(struct node_db *ndb);
enum csr_result csr_internal_validate_header_identity_locked(
    struct chain_state_repository *csr,
    struct block_index *new_tip,
    const char *reason);
bool csr_internal_header_candidate_strictly_better(
    const struct block_index *candidate,
    const struct block_index *current);

#endif
