/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bg_validation_authority — publish a completed background validation walk
 * into the durable Chain Evidence Controller without allowing a partial walk,
 * missing undo coverage, or a moving coins frontier to become “fully
 * validated”. */

#ifndef ZCL_BG_VALIDATION_AUTHORITY_H
#define ZCL_BG_VALIDATION_AUTHORITY_H

#include "base/result.h"

#include <stdbool.h>
#include <stdint.h>

struct bg_validation_service;

/* Pure fail-closed predicate shared by production and the KAT. */
bool bg_validation_authority_claim_is_complete(
    int verified_height, int chain_height, int coins_height,
    int64_t script_skips, bool coverage_complete);

/* Recompute the authoritative coins SHA3 and bind a complete walk to CEC.
 * `external_seeded` selects the assisted-snapshot evidence preflight; false
 * requires a genuine no-snapshot genesis-history campaign. A non-ok result
 * raises bg_validation.full_history_unproven with the exact missing proof. */
struct zcl_result bg_validation_authority_publish(
    struct bg_validation_service *svc, bool external_seeded,
    bool coverage_complete);

#endif /* ZCL_BG_VALIDATION_AUTHORITY_H */
