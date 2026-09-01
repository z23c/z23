/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* SHADOW-mode adapter for the pure sync kernel (sync/sync_reduce.h).
 * Builds the kernel's `sync_kernel_state` + `sync_event` from the
 * SAME inputs the reference offer-accept path (msgprocessor_snapshot.c)
 * already computed, calls `sync_reduce()`, and reports whether its
 * structural accept/reject decision agrees with the reference's. The
 * reference `snapshot_sync_service` FSM stays fully authoritative — nothing
 * here feeds back into any branch the reference takes; a caller that
 * ignores the result changes nothing about node behavior.
 *
 * Session modeling: the reference FSM has no explicit numeric "session id"
 * — a snapshot-sync attempt is scoped to whichever peer it is currently
 * negotiating/receiving with (`snapsync_status.serving_peer_id`). This
 * adapter treats that peer id as the kernel's session_id, so the kernel's
 * built-in stale-session guard (sync_reduce.h: an event whose session_id
 * doesn't match an already-active state.session_id is a no-op) structurally
 * mirrors the reference's "already busy with a different peer" rejection
 * (SNAPSYNC_OFFER_REJECTED_BUSY et al.) — `state_session_id == 0` means "no
 * session yet" on both sides and never gates.
 *
 * Pure: no I/O, no logging, no clock. The caller decides what to do with a
 * disagreement (the production call site logs it; the unit test asserts
 * it). */

#ifndef ZCL_NET_SYNC_REDUCE_ADAPTER_H
#define ZCL_NET_SYNC_REDUCE_ADAPTER_H

#include "sync/sync_reduce.h"
#include "sync/sync_state.h"

#include <stdbool.h>
#include <stdint.h>

/* Map the reference FSM's `enum snapshot_sync_state` onto the pure kernel's
 * `enum sync_phase`. SNAPSYNC_COMPLETE maps to SYNC_PHASE_STAGED — the
 * kernel's furthest reachable phase before the unrepresentable activation
 * door — mirroring the reference's own containment: SNAPSYNC_COMPLETE means
 * "verified", never "activated" (activation is CSR-gated separately). */
enum sync_phase sync_reduce_adapter_map_phase(enum snapshot_sync_state state);

/* Result of one shadow comparison. `kernel_decision` is exposed so a caller
 * can log or assert on more than just the accept/reject summary. */
struct sync_reduce_offer_shadow_result {
    struct sync_decision kernel_decision;
    bool kernel_accepts;     /* kernel emitted STORE_OFFER and moved to NEGOTIATING */
    bool reference_accepts;  /* caller-supplied: reference result == ACCEPTED */
    bool agrees;             /* kernel_accepts == reference_accepts */
};

/* Build state+event from the given inputs, call sync_reduce(), and compare.
 * Pure — same inputs always give the same result.
 *
 * state_session_id / event_session_id: see the session-modeling note above
 * (0 == no active session, never gates).
 * state_before: the reference FSM's state BEFORE this offer was handled.
 * offer_height / offer_utxo_root: the incoming offer's payload (carried into
 * the sync_event for adapter completeness; the current OFFER_RECEIVED arms
 * do not branch on them — the kernel's contract is intentionally coarser
 * than the reference's independent range/schema/finality/work validators).
 * reference_accepts: caller-computed (reference result == ACCEPTED). */
struct sync_reduce_offer_shadow_result sync_reduce_offer_shadow_check(
    uint64_t state_session_id, enum snapshot_sync_state state_before,
    uint64_t event_session_id, int32_t offer_height,
    const uint8_t offer_utxo_root[32], bool reference_accepts);

#endif /* ZCL_NET_SYNC_REDUCE_ADAPTER_H */
