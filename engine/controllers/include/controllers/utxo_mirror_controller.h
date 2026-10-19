/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo mirror operator repair: the node-side RPC method that the CLI leaf
 * `ops.recovery.utxo_mirror` forwards to (see utxo_mirror_controller.c).
 *
 *   utxomirrorrebuild ["start"]            queue a rebuild on the mirror thread
 *   utxomirrorrebuild ["status", job_id]   poll it
 *
 * Operator-only (RPC cookie; not safe-mode); REMOTE_CLASS_NEVER for the leaf. */

#ifndef ZCL_CONTROLLERS_UTXO_MIRROR_CONTROLLER_H
#define ZCL_CONTROLLERS_UTXO_MIRROR_CONTROLLER_H

#include "rpc/server.h"

void register_utxo_mirror_rpc_commands(struct rpc_table *t);

#ifdef ZCL_TESTING
#include <stdint.h>
/* Override the CLI poll cadence and wait ceiling (negative = defaults). */
void zcl_utxo_mirror_controller_test_set_poll(int64_t interval_ms,
                                              int64_t max_wait_ms);
#endif

#endif /* ZCL_CONTROLLERS_UTXO_MIRROR_CONTROLLER_H */
