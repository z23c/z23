/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * soak_attestation_poll — supervised cadence Job for the soak attestation
 * service. Registers in the `op` supervisor domain (g_op_sup) and calls
 * soak_attestation_tick() on each 60 s tick; all gating lives in the
 * service, so this Job is a pure scheduling shim. */

#ifndef ZCL_JOBS_SOAK_ATTESTATION_POLL_H
#define ZCL_JOBS_SOAK_ATTESTATION_POLL_H

#include <stdbool.h>

/* Register the poll Job with the op supervisor domain. Idempotent. */
void soak_attestation_poll_register(void);

/* True once the poll Job is registered with the supervisor. */
bool soak_attestation_poll_is_registered(void);

#endif /* ZCL_JOBS_SOAK_ATTESTATION_POLL_H */
