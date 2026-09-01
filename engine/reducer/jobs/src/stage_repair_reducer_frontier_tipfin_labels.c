/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * PURPOSE: Provide stable operator labels for tip-finality repair refusals. */
// repair-rung-ok:test_tip_finalize_stage

#include "jobs/stage_repair.h"

const char *stage_repair_tipfin_refused_reason_label(int reason)
{
    switch ((enum stage_repair_tipfin_refused_reason)reason) {
    case STAGE_REPAIR_TIPFIN_REFUSED_NONE:
        return "none";
    case STAGE_REPAIR_TIPFIN_REFUSED_G1_COIN_UNKNOWN:
        return "G1_coin_unknown";
    case STAGE_REPAIR_TIPFIN_REFUSED_G2_EVIDENCE_ROW:
        return "G2_evidence_row";
    case STAGE_REPAIR_TIPFIN_REFUSED_G2_ROW_PRESENT:
        return "G2_row_present";
    case STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE:
        return "G3_missing_evidence";
    case STAGE_REPAIR_TIPFIN_REFUSED_G4_AT_SERVED_FLOOR:
        return "G4_at_served_floor";
    case STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING:
        return "G5_binder_missing";
    case STAGE_REPAIR_TIPFIN_REFUSED_G6_IN_TX_RECHECK:
        return "G6_in_tx_recheck";
    case STAGE_REPAIR_TIPFIN_REFUSED_G7_MARKER_SEEN:
        return "G7_marker_seen";
    case STAGE_REPAIR_TIPFIN_REFUSED_HSTAR_RANGE:
        return "hstar_out_of_range";
    }
    return "unknown";
}

const char *stage_repair_tipfin_refused_log_label(int log)
{
    switch ((enum stage_repair_tipfin_refused_log)log) {
    case STAGE_REPAIR_TIPFIN_LOG_UNKNOWN:
        return "unknown";
    case STAGE_REPAIR_TIPFIN_LOG_VALIDATE_HEADERS:
        return "validate_headers_log";
    case STAGE_REPAIR_TIPFIN_LOG_SCRIPT_VALIDATE:
        return "script_validate_log";
    case STAGE_REPAIR_TIPFIN_LOG_VALIDATE_SCRIPT_SPLIT:
        return "validate_headers_log/script_validate_log split";
    case STAGE_REPAIR_TIPFIN_LOG_BODY_PERSIST:
        return "body_persist_log";
    case STAGE_REPAIR_TIPFIN_LOG_PROOF_VALIDATE:
        return "proof_validate_log";
    case STAGE_REPAIR_TIPFIN_LOG_UTXO_APPLY:
        return "utxo_apply_log";
    case STAGE_REPAIR_TIPFIN_LOG_TIP_FINALIZE:
        return "tip_finalize_log";
    case STAGE_REPAIR_TIPFIN_LOG_HEADER_ADMIT:
        return "header_admit_log";
    }
    return "unknown";
}

bool stage_repair_tipfin_refusal_is_pending_forward(
    const struct stage_reducer_frontier_reconcile_result *rr)
{
    if (!rr || !rr->refused_coin_tear || !rr->coins_applied_found ||
        rr->coins_applied_height < 0)
        return false;
    if (rr->tipfin_backfill_refused_reason !=
            STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE &&
        rr->tipfin_backfill_refused_reason !=
            STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING)
        return false;
    return rr->tipfin_backfill_refused_height >= rr->coins_applied_height;
}
