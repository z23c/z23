/* purpose: Coordinate private checkpoint bootstrap with the apply stage. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_UTXO_APPLY_IRONWOOD_BOOTSTRAP_H
#define ZCL_UTXO_APPLY_IRONWOOD_BOOTSTRAP_H
#include <stdbool.h>
#define IRONWOOD_BOOTSTRAP_MARKER "utxo_apply.ironwood_frontier_bootstrap"
bool utxo_ironwood_bootstrap_post_commit(void);
void utxo_ironwood_bootstrap_shutdown(void);
void utxo_ironwood_bootstrap_context_change_begin(void);
void utxo_ironwood_bootstrap_context_change_end(void);
#endif
