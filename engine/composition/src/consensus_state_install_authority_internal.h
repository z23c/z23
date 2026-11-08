/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: canonical wallet cutover authority predicates
 */
#ifndef ZCL_CONSENSUS_STATE_INSTALL_AUTHORITY_INTERNAL_H
#define ZCL_CONSENSUS_STATE_INSTALL_AUTHORITY_INTERNAL_H
#include "config/consensus_state_install_runtime.h"
struct sqlite3;
struct consensus_state_proof_prefix;
struct wallet_cutover_binding;
bool icb_recovery_frontier(struct sqlite3 *db, const struct consensus_state_proof_prefix *prefix, bool *advanced);
enum wallet_install_reconcile icb_wallet_classify_locked(struct sqlite3 *db,
    const struct wallet_cutover_binding *binding);
#endif
