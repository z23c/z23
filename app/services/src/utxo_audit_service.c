/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "services/utxo_audit_service.h"
#include "services/utxo_reference_source.h"

#include "coins/utxo_commitment.h"
#include "encoding/utilstrencodings.h"
#include "event/event.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

static bool is_sha3_hex(const char *hex)
{
    return hex && strlen(hex) == 64 && IsHex(hex);
}

const char *utxo_audit_status_name(enum utxo_audit_status status)
{
    switch (status) {
    case UTXO_AUDIT_LOCAL_ONLY: return "local_only";
    case UTXO_AUDIT_MATCH:      return "match";
    case UTXO_AUDIT_DRIFT:      return "drift";
    case UTXO_AUDIT_ERROR:      return "error";
    default:                    return "unknown";
    }
}

struct zcl_result utxo_audit_local(struct node_db *ndb, int32_t height,
                                   struct utxo_audit_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "utxo_audit: null out");
    memset(out, 0, sizeof(*out));
    out->status = UTXO_AUDIT_ERROR;

    if (!ndb || !ndb->open || !ndb->db) {
        snprintf(out->error, sizeof(out->error), "database not available");
        return ZCL_ERR(-2, "utxo_audit: local audit without open database");
    }

    uint8_t local_hash[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb->db, local_hash, &count);
    HexStr(local_hash, 32, false, out->local_sha3, sizeof(out->local_sha3));
    out->local_utxo_count = count;
    out->local_height = height;
    out->status = UTXO_AUDIT_LOCAL_ONLY;

    (void)node_db_state_set(ndb, "utxo_audit_last_local_sha3",
                            out->local_sha3, strlen(out->local_sha3));
    (void)node_db_state_set_int(ndb, "utxo_audit_last_height",
                                (int64_t)height);
    return ZCL_OK;
}

struct zcl_result utxo_audit_compare_remote(struct node_db *ndb,
                                            const char *remote_sha3,
                                            int32_t remote_height,
                                            const char *source,
                                            struct utxo_audit_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "utxo_audit: null out");
    struct zcl_result local = utxo_audit_local(ndb, remote_height, out);
    if (!local.ok)
        return local;

    if (!is_sha3_hex(remote_sha3)) {
        out->status = UTXO_AUDIT_ERROR;
        snprintf(out->error, sizeof(out->error), "remote_sha3 must be 64 hex chars");
        return ZCL_ERR(-3, "utxo_audit: invalid remote sha3");
    }

    snprintf(out->remote_sha3, sizeof(out->remote_sha3), "%s", remote_sha3);
    snprintf(out->source, sizeof(out->source), "%s",
             source && source[0] ? source : "peer-commitment");
    out->remote_height = remote_height;

    out->drift_detected = strcmp(out->local_sha3, out->remote_sha3) != 0;
    out->status = out->drift_detected ? UTXO_AUDIT_DRIFT : UTXO_AUDIT_MATCH;
    (void)node_db_state_set_int(ndb, "utxo_drift_detected",
                                out->drift_detected ? 1 : 0);
    (void)node_db_state_set(ndb, "utxo_audit_last_remote_sha3",
                            out->remote_sha3, strlen(out->remote_sha3));

    if (out->drift_detected) {
        event_emitf(EV_UTXO_DRIFT_DETECTED, 0,
                    "local_sha3=%s remote_sha3=%s height=%d source=%s",
                    out->local_sha3, out->remote_sha3, remote_height,
                    out->source);
    } else {
        event_emitf(EV_UTXO_AUDIT_OK, 0,
                    "sha3=%s height=%d source=%s utxos=%llu",
                    out->local_sha3, remote_height, out->source,
                    (unsigned long long)out->local_utxo_count);
    }

    return ZCL_OK;
}

struct zcl_result utxo_audit_compare_source(struct node_db *ndb,
                                            const struct utxo_reference_source *src,
                                            int32_t local_height,
                                            struct utxo_audit_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "utxo_audit: null out");
    if (!src || !src->commitment_at) {
        memset(out, 0, sizeof(*out));
        out->status = UTXO_AUDIT_ERROR;
        snprintf(out->error, sizeof(out->error), "no reference source");
        return ZCL_ERR(-2, "utxo_audit: null reference source");
    }

    /* Ask the reference for its commitment as of the SAME applied height the
     * local set reflects — same-height parity is the only honest comparison
     * because there is no historical "as-of height" local commitment. */
    char ref_sha3[65] = {0};
    int32_t ref_height = -1;
    struct zcl_result rr =
        src->commitment_at((void *)src->self, local_height,
                           ref_sha3, &ref_height);
    if (!rr.ok) {
        /* Reference unreachable/parse-fail: compute local for context but
         * stay LOCAL_ONLY. Never flag drift on a reference error. */
        (void)utxo_audit_local(ndb, local_height, out);
        out->status = UTXO_AUDIT_LOCAL_ONLY;
        snprintf(out->source, sizeof(out->source), "%s",
                 src->name ? src->name : "reference");
        snprintf(out->error, sizeof(out->error), "reference error: %.100s",
                 rr.message[0] ? rr.message : "unavailable");
        return rr;
    }

    if (src->exact) {
        /* Same-height guard: only an exact reference AT THE SAME height can
         * yield a byte-meaningful DRIFT. A height skew (the reference is
         * ahead/behind the live applied set) is recorded as LOCAL_ONLY and
         * never pages — this is what prevents the structural false-DRIFT. */
        if (ref_height != local_height) {
            (void)utxo_audit_local(ndb, local_height, out);
            out->status = UTXO_AUDIT_LOCAL_ONLY;
            out->remote_height = ref_height;
            snprintf(out->source, sizeof(out->source), "%s",
                     src->name ? src->name : "reference");
            snprintf(out->error, sizeof(out->error),
                     "height skew local=%d ref=%d", local_height, ref_height);
            return ZCL_OK;
        }
        /* Heights agree: delegate to the proven strcmp/persist/emit path,
         * which sets 'utxo_drift_detected' so the Condition pages on DRIFT. */
        return utxo_audit_compare_remote(ndb, ref_sha3, local_height,
                                         src->name, out);
    }

    /* Coarse source: height-only attestation. It cannot prove the UTXO-set
     * bytes, so it never declares DRIFT. Compute local for height/count and
     * EXPLICITLY clear any stale 'utxo_drift_detected' (a coarse confirmation
     * must not let a prior exact drift keep paging). */
    struct zcl_result local = utxo_audit_local(ndb, local_height, out);
    if (!local.ok)
        return local;
    snprintf(out->source, sizeof(out->source), "%s",
             src->name ? src->name : "coarse");
    out->remote_sha3[0] = '\0';
    out->remote_height = ref_height;
    out->drift_detected = false;
    out->status = (ref_height == local_height) ? UTXO_AUDIT_MATCH
                                               : UTXO_AUDIT_LOCAL_ONLY;
    (void)node_db_state_set_int(ndb, "utxo_drift_detected", 0);
    return ZCL_OK;
}
