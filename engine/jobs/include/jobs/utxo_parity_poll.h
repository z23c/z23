/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_parity_poll — supervised cadence Job for the standing UTXO parity
 * service. Registers in the `chain` supervisor domain and calls
 * utxo_parity_tick_once() on each tick; the service owns all gating, so this
 * Job is a pure scheduling shim. */

#ifndef ZCL_JOBS_UTXO_PARITY_POLL_H
#define ZCL_JOBS_UTXO_PARITY_POLL_H

#include <stdbool.h>

/* Register the poll Job with the chain supervisor. Idempotent. */
void utxo_parity_poll_register(void);

/* True once the poll Job is registered with the supervisor. */
bool utxo_parity_poll_is_registered(void);

#endif /* ZCL_JOBS_UTXO_PARITY_POLL_H */
