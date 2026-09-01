/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Declare exact hash-evidence checks used by the reducer frontier. */
#ifndef ZCL_JOBS_REDUCER_FRONTIER_EVIDENCE_H
#define ZCL_JOBS_REDUCER_FRONTIER_EVIDENCE_H

#include "jobs/mint_skip_crypto.h"

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;

/* The evidence a *_log success row must carry to COUNT toward a frontier.
 * VERIFIED on any normal boot; CHECKPOINT_FOLD only under the offline
 * fast-mint. See the definition for why this is not a literal constant. */
enum mint_validation_evidence reducer_frontier_required_evidence(void);

bool reducer_frontier_apply_hash_agreement(struct sqlite3 *db,
                                           int32_t anchor,
                                           int32_t *hstar);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_EVIDENCE_H */
