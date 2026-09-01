/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Narrow public seam for idempotently replaying wallet effects from one exact
 * active block. Operator reconsideration uses this after the reducer has
 * reconnected a formerly invalidated segment. */

#ifndef ZCL_JOBS_TIP_FINALIZE_WALLET_RECONCILE_H
#define ZCL_JOBS_TIP_FINALIZE_WALLET_RECONCILE_H

#include <stdbool.h>

struct block_index;

bool tip_finalize_run_wallet_reconcile(struct block_index *pindex_new);

#endif
