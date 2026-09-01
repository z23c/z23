/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `wallet` telemetry domain's PROVIDER — the one function that turns live
 * wallet-side subsystem state into a typed `struct wallet_snapshot`.
 *
 * Division of labour (util/telemetry_render.h, and it is strict):
 *   this file   fills a typed snapshot. Writes NO JSON and decides NO health.
 *   render      walks the descriptor table generated from
 *               util/telemetry/wallet_fields.def and emits every leaf.
 *   controller  picks a snapshot and a view. Names no field.
 *
 * WHAT THIS PROVIDER MAY PUBLISH. Posture, never account data. It reads the
 * wallet's key-handling and read-model state and must never place a private
 * key, a seed, a spending key, an address, or a confirmed balance into the
 * snapshot, nor any value from which one could be reconstructed. The field
 * table states the same rule at the row level; both halves have to hold,
 * because the table decides what CAN be published and this file decides what
 * IS. There is deliberately no accessor here that reaches key material.
 *
 * NON-BLOCKING BY CONTRACT. The collector runs on the same native/RPC thread
 * the old per-subsystem dumpers ran on, while the reducer fold owns
 * progress_store_tx_lock. It therefore takes no blocking store lock, runs no
 * SELECT COUNT(*), and performs no I/O: every read is an atomic load, a
 * process-global boolean, or a short in-memory status snapshot. A subsystem
 * that is not wired in the calling process is reported as UNAVAILABLE with a
 * static reason token — never as a zero, and never omitted.
 *
 * PROCESS SCOPE, stated because it changes how the answer must be read. Most
 * of these facts are process-local: they are real in the node process and
 * legitimately absent in a one-shot CLI process, where they report
 * unavailable with a named reason rather than a plausible zero. The Sapling
 * proving-backend leaves are the exception: they are build facts and answer
 * identically in any process.
 */

#ifndef ZCL_SERVICES_WALLET_TELEMETRY_H
#define ZCL_SERVICES_WALLET_TELEMETRY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct wallet_snapshot;

/* Fill EVERY leaf of the wallet domain snapshot.
 *
 * `snap` is zeroed first, so it starts with every leaf at TELEMETRY_UNSET —
 * the provider-defect signal — and each leaf is then written exactly once
 * through the telemetry setters. A leaf left unset after this returns is a bug
 * in this file, and the render layer reports it as such rather than hiding it.
 *
 * Reentrant and thread-safe. Returns false only on a NULL argument. */
bool wallet_dump_state_fill(struct wallet_snapshot *snap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SERVICES_WALLET_TELEMETRY_H */
