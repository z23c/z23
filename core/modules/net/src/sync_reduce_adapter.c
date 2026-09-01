/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SHADOW-mode adapter for the pure sync kernel — see
 * net/sync_reduce_adapter.h. Pure: no I/O, no logging, no global state. */

#include "net/sync_reduce_adapter.h"

#include <string.h>

enum sync_phase sync_reduce_adapter_map_phase(enum snapshot_sync_state state)
{
    switch (state) {
    case SNAPSYNC_IDLE:        return SYNC_PHASE_IDLE;
    case SNAPSYNC_NEGOTIATING: return SYNC_PHASE_NEGOTIATING;
    case SNAPSYNC_RECEIVING:   return SYNC_PHASE_RECEIVING;
    case SNAPSYNC_VERIFYING:   return SYNC_PHASE_VERIFYING;
    case SNAPSYNC_COMPLETE:    return SYNC_PHASE_STAGED;
    case SNAPSYNC_FAILED:      return SYNC_PHASE_FAILED;
    case SNAPSYNC_NUM_STATES:  break; /* not a real state */
    }
    return SYNC_PHASE_IDLE;
}

struct sync_reduce_offer_shadow_result sync_reduce_offer_shadow_check(
    uint64_t state_session_id, enum snapshot_sync_state state_before,
    uint64_t event_session_id, int32_t offer_height,
    const uint8_t offer_utxo_root[32], bool reference_accepts)
{
    struct sync_kernel_state state;
    memset(&state, 0, sizeof(state));
    state.session_id.value = state_session_id;
    state.phase = sync_reduce_adapter_map_phase(state_before);

    struct sync_event event;
    memset(&event, 0, sizeof(event));
    event.session_id.value = event_session_id;
    event.kind = SYNC_EVENT_OFFER_RECEIVED;
    event.height.value = offer_height;
    if (offer_utxo_root)
        memcpy(event.utxo_root.bytes, offer_utxo_root, 32);

    /* The kernel now returns a full transition; the offer shadow only needs the
     * legacy phase-only view, so project it (compat). */
    struct sync_transition t = sync_reduce(state, event);

    struct sync_reduce_offer_shadow_result r;
    memset(&r, 0, sizeof(r));
    r.kernel_decision = sync_transition_to_decision(&t);

    r.kernel_accepts = false;
    for (int i = 0; i < r.kernel_decision.action_count; i++) {
        if (r.kernel_decision.actions[i] == SYNC_ACTION_STORE_OFFER) {
            r.kernel_accepts = true;
            break;
        }
    }

    r.reference_accepts = reference_accepts;
    r.agrees = (r.kernel_accepts == r.reference_accepts);
    return r;
}
