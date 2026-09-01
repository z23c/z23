/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * header_probe_poll - network-supervised header polling Job.
 *
 * Periodic supervisor child that drives header_probe's
 * polling cadence through header_probe_tick_once(), with a typed
 * liveness contract registered in the network supervisor domain.
 *
 * Why this shape:
 *   - The heartbeat ring is a shared sweeper thread (single point of
 *     failure; the supervisor split was motivated by an 8.6 h
 *     wedge of that thread). Moving each periodic to its own
 *     supervisor child gives operators (and `z23 dumpstate
 *     subsystem=supervisor`) visibility into stall age + ticks_run.
 *   - The Job owns scheduling ONLY. Peer selection, RPC, batched
 *     validation, accept_block_header — all stay in
 *     engine/services/src/header_probe.c.
 *
 * Boot wiring: call `header_probe_poll_register()` from
 * `engine/composition/src/boot_services.c` after `header_probe_init()`. The
 * network supervisor tree must already be started. */

#ifndef ZCL_JOB_HEADER_PROBE_POLL_H
#define ZCL_JOB_HEADER_PROBE_POLL_H

#include <stdbool.h>

/* Register the Job with the network supervisor domain. Idempotent —
 * second + subsequent calls are no-ops. The contract uses a 30 s
 * tick cadence (matching the legacy heartbeat default). */
void header_probe_poll_register(void);

/* True once `header_probe_poll_register` has produced a valid
 * supervisor child id. Used by tests + diagnostics. */
bool header_probe_poll_is_registered(void);

#endif /* ZCL_JOB_HEADER_PROBE_POLL_H */
