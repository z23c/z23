/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SERVICES_UTXO_AUDIT_SERVICE_H
#define ZCL_SERVICES_UTXO_AUDIT_SERVICE_H

#include "models/database.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

enum utxo_audit_status {
    UTXO_AUDIT_LOCAL_ONLY = 0,
    UTXO_AUDIT_MATCH,
    UTXO_AUDIT_DRIFT,
    UTXO_AUDIT_ERROR,
};

struct utxo_audit_result {
    enum utxo_audit_status status;
    char local_sha3[65];
    char remote_sha3[65];
    char source[64];
    int32_t local_height;
    int32_t remote_height;
    uint64_t local_utxo_count;
    bool drift_detected;
    char error[128];
};

const char *utxo_audit_status_name(enum utxo_audit_status status);

struct zcl_result utxo_audit_local(struct node_db *ndb, int32_t height,
                                   struct utxo_audit_result *out);

struct zcl_result utxo_audit_compare_remote(struct node_db *ndb,
                                            const char *remote_sha3,
                                            int32_t remote_height,
                                            const char *source,
                                            struct utxo_audit_result *out);

/* Compare the local UTXO commitment against a pluggable reference source.
 *
 * `local_height` is the height the local utxos table currently reflects (the
 * live applied-coins height) — the comparison is honest ONLY at this height
 * because there is no historical "as-of" local commitment.
 *
 * Branches on src->exact:
 *   - exact   → fetch the reference 64-hex SHA3 at `local_height`; declare
 *               DRIFT only when the reference is at the SAME height. Any
 *               height skew is recorded as LOCAL_ONLY (never a byte DRIFT),
 *               which never pages. On a true same-height mismatch it persists
 *               'utxo_drift_detected'=1 (the Condition pages).
 *   - coarse  → height-only attestation; status MATCH when heights agree,
 *               else LOCAL_ONLY. NEVER declares DRIFT and explicitly CLEARS a
 *               stale 'utxo_drift_detected' so a prior exact drift cannot keep
 *               paging from a coarse confirmation.
 *
 * A reference-side error (commitment_at returns ZCL_ERR) yields status
 * LOCAL_ONLY and ZCL_ERR; the caller increments ref_errors and never pages.
 *
 * `struct utxo_reference_source` is declared in services/utxo_reference_source.h. */
struct utxo_reference_source;
struct zcl_result utxo_audit_compare_source(struct node_db *ndb,
                                            const struct utxo_reference_source *src,
                                            int32_t local_height,
                                            struct utxo_audit_result *out);

#endif /* ZCL_SERVICES_UTXO_AUDIT_SERVICE_H */
