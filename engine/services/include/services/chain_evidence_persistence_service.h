/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_CHAIN_EVIDENCE_PERSISTENCE_SERVICE_H
#define ZCL_SERVICES_CHAIN_EVIDENCE_PERSISTENCE_SERVICE_H

#include "services/chain_evidence_authority_service.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

/* Persist a node_state value for chain-evidence callers with a bounded retry
 * on SQLITE_BUSY / SQLITE_LOCKED. This is intentionally scoped to CEC: the
 * generic node_db_state_set primitive keeps its immediate-fail contract.
 * Returns ZCL_OK on success; a non-ok zcl_result names the bad input or the
 * sqlite error that survived every retry attempt (DEFENSIVE_CODING.md §2). */
struct zcl_result chain_evidence_state_set_retry(struct node_db *ndb,
                                                 const char *key,
                                                 const void *value,
                                                 size_t len,
                                                 const char *owner);
struct zcl_result chain_evidence_state_set_int_retry(struct node_db *ndb,
                                                     const char *key,
                                                     int64_t value,
                                                     const char *owner);

/* Persist a chain-evidence record under `key`. Returns ZCL_OK on success;
 * a non-ok zcl_result carrying the failing input or the node_db error
 * otherwise (DEFENSIVE_CODING.md §2). */
struct zcl_result chain_evidence_store_persist(
    struct chain_evidence_controller *authority,
    const char *key,
    const struct chain_evidence_record *evidence);

/* Load a chain-evidence record from `key` into *out. On any failure *out is
 * left zeroed (when out != NULL) and a non-ok zcl_result explains why
 * (null arg, missing key, or malformed record). */
struct zcl_result chain_evidence_store_load(struct node_db *ndb,
                                            const char *key,
                                            struct chain_evidence_record *out);

#endif /* ZCL_SERVICES_CHAIN_EVIDENCE_PERSISTENCE_SERVICE_H */
