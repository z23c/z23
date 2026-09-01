/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chain_state_result - names for chain-state repository result codes.
 */
// one-result-type-ok:total-result-name-table

#include "services/chain_state_service.h"

const char *csr_result_name(enum csr_result r)
{
    switch (r) {
    case CSR_OK:                          return "ok";
    case CSR_REJECTED_NULL_INPUT:         return "null_input";
    case CSR_REJECTED_NOT_INITIALIZED:    return "not_initialized";
    case CSR_REJECTED_TIP_NOT_IN_INDEX:   return "tip_not_in_index";
    case CSR_REJECTED_HASH_MISMATCH:      return "hash_mismatch";
    case CSR_REJECTED_MISSING_PREV:       return "missing_prev";
    case CSR_REJECTED_STALE_INDEX:        return "stale_index";
    case CSR_REJECTED_UTXO_DELTA_TOO_BIG: return "utxo_delta_too_big";
    case CSR_REJECTED_COINS_MISMATCH:     return "coins_mismatch";
    case CSR_REJECTED_HEADER_REGRESSION:  return "header_regression";
    case CSR_REJECTED_ROLLBACK_AUTH:      return "rollback_auth";
    case CSR_REJECTED_PERSIST:            return "persist";
    case CSR_REJECTED_DB_BUSY:            return "db_writer_busy";
    case CSR_REJECTED_OOM:                return "oom";
    case CSR_NUM_RESULTS:                 break;
    }
    return "unknown";
}
