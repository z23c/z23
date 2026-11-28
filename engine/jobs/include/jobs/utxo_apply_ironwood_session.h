/* purpose: Coordinate authenticated replay with the private reducer transaction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_UTXO_APPLY_IRONWOOD_SESSION_H
#define ZCL_UTXO_APPLY_IRONWOOD_SESSION_H
#include "jobs/utxo_apply_ironwood.h"
#include "jobs/utxo_apply_ironwood_history.h"

/* Serialized by the stage lock. Reset at both ends of each database lifetime. */
void utxo_ironwood_session_reset(void);
bool utxo_ironwood_session_bootstrap_requested(void);
void utxo_ironwood_session_bootstrap_clear(void);
enum utxo_ironwood_result utxo_ironwood_session_prepare(struct sqlite3 *db,
    const struct block_index *bi, const struct block *block,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct utxo_ironwood_pending *out);
bool utxo_ironwood_session_publish(const struct utxo_ironwood_pending *pending);
#endif
