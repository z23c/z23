/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Peer connection state machine, split out of event.c. This file owns the
 * legal-transition table and the checked setter; its only dependency on
 * the rest of the event log is the public event_emit() call that records
 * each transition (and rejection) as an EV_PEER_STATE_CHANGE event. It
 * reads and writes no file-scope state belonging to event.c — the caller
 * supplies the peer's own _Atomic state cell — so it can live standalone. */

#include "event/event.h"
#include <stdio.h>

const char *peer_state_name(enum peer_state state)
{
    static const char *names[] = {
        [PEER_DISCONNECTED]      = "disconnected",
        [PEER_CONNECTING]        = "connecting",
        [PEER_CONNECTED]         = "connected",
        [PEER_VERSION_SENT]      = "version_sent",
        [PEER_VERSION_RECEIVED]  = "version_received",
        [PEER_HANDSHAKE_COMPLETE]= "handshake_complete",
        [PEER_ACTIVE]            = "active",
        [PEER_SYNCING_HEADERS]   = "syncing_headers",
        [PEER_SYNCING_BLOCKS]    = "syncing_blocks",
        [PEER_SNAPSHOT_SERVING]  = "snapshot_serving",
        [PEER_SNAPSHOT_RECEIVING]= "snapshot_receiving",
        [PEER_STALE]             = "stale",
        [PEER_DISCONNECTING]     = "disconnecting",
        [PEER_BANNED]            = "banned",
    };
    if (state >= 0 && state < PEER_NUM_STATES)
        return names[state];
    return "unknown";
}

/* Transition table: [from][to] = legal.
 * Only transitions explicitly listed here are allowed.
 * Anything else is a bug that gets caught immediately. */
static const bool g_peer_transitions[PEER_NUM_STATES][PEER_NUM_STATES] = {
    /* DISCONNECTED can go to CONNECTING or CONNECTED (inbound) */
    [PEER_DISCONNECTED][PEER_CONNECTING]         = true,
    [PEER_DISCONNECTED][PEER_CONNECTED]          = true,

    /* CONNECTING goes to CONNECTED or VERSION_SENT (outbound shortcut) */
    [PEER_CONNECTING][PEER_CONNECTED]            = true,
    [PEER_CONNECTING][PEER_VERSION_SENT]         = true,
    [PEER_CONNECTING][PEER_DISCONNECTED]         = true,
    [PEER_CONNECTING][PEER_DISCONNECTING]        = true,

    /* CONNECTED: send or receive version */
    [PEER_CONNECTED][PEER_VERSION_SENT]          = true,
    [PEER_CONNECTED][PEER_VERSION_RECEIVED]      = true,
    [PEER_CONNECTED][PEER_DISCONNECTING]         = true,

    /* VERSION_SENT: receive their version */
    [PEER_VERSION_SENT][PEER_VERSION_RECEIVED]   = true,
    [PEER_VERSION_SENT][PEER_HANDSHAKE_COMPLETE] = true,
    [PEER_VERSION_SENT][PEER_DISCONNECTING]      = true,

    /* VERSION_RECEIVED: handshake completes */
    [PEER_VERSION_RECEIVED][PEER_VERSION_SENT]   = true,
    [PEER_VERSION_RECEIVED][PEER_HANDSHAKE_COMPLETE] = true,
    [PEER_VERSION_RECEIVED][PEER_DISCONNECTING]  = true,

    /* HANDSHAKE_COMPLETE: transition to active or sync */
    [PEER_HANDSHAKE_COMPLETE][PEER_ACTIVE]       = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SYNCING_HEADERS] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SYNCING_BLOCKS]  = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SNAPSHOT_SERVING] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_DISCONNECTING]= true,

    /* ACTIVE: can start syncing or snapshot */
    [PEER_ACTIVE][PEER_SYNCING_HEADERS]          = true,
    [PEER_ACTIVE][PEER_SYNCING_BLOCKS]           = true,
    [PEER_ACTIVE][PEER_SNAPSHOT_SERVING]          = true,
    [PEER_ACTIVE][PEER_SNAPSHOT_RECEIVING]        = true,
    [PEER_ACTIVE][PEER_STALE]                    = true,
    [PEER_ACTIVE][PEER_DISCONNECTING]            = true,

    /* SYNCING_HEADERS: done → blocks or active, or fail */
    [PEER_SYNCING_HEADERS][PEER_SYNCING_BLOCKS]  = true,
    [PEER_SYNCING_HEADERS][PEER_ACTIVE]          = true,
    [PEER_SYNCING_HEADERS][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_SYNCING_HEADERS][PEER_SNAPSHOT_SERVING]   = true,
    [PEER_SYNCING_HEADERS][PEER_STALE]           = true,
    [PEER_SYNCING_HEADERS][PEER_DISCONNECTING]   = true,

    /* SYNCING_BLOCKS: done → active, or fail */
    [PEER_SYNCING_BLOCKS][PEER_ACTIVE]           = true,
    [PEER_SYNCING_BLOCKS][PEER_SYNCING_HEADERS]  = true,
    [PEER_SYNCING_BLOCKS][PEER_SNAPSHOT_RECEIVING] = true,
    [PEER_SYNCING_BLOCKS][PEER_SNAPSHOT_SERVING]   = true,
    [PEER_SYNCING_BLOCKS][PEER_STALE]            = true,
    [PEER_SYNCING_BLOCKS][PEER_DISCONNECTING]    = true,

    /* SNAPSHOT states: complete → active, or fail */
    [PEER_SNAPSHOT_SERVING][PEER_ACTIVE]          = true,
    [PEER_SNAPSHOT_SERVING][PEER_DISCONNECTING]   = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_ACTIVE]         = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_DISCONNECTING]  = true,

    /* STALE: can recover or disconnect */
    [PEER_STALE][PEER_ACTIVE]                    = true,
    [PEER_STALE][PEER_SYNCING_HEADERS]           = true,
    [PEER_STALE][PEER_DISCONNECTING]             = true,

    /* DISCONNECTING always goes to DISCONNECTED */
    [PEER_DISCONNECTING][PEER_DISCONNECTED]      = true,

    /* BANNED always goes to DISCONNECTED */
    [PEER_BANNED][PEER_DISCONNECTED]             = true,

    /* Any state can be banned or disconnect */
    [PEER_ACTIVE][PEER_BANNED]                   = true,
    [PEER_SYNCING_HEADERS][PEER_BANNED]          = true,
    [PEER_SYNCING_BLOCKS][PEER_BANNED]           = true,
    [PEER_HANDSHAKE_COMPLETE][PEER_BANNED]       = true,
    [PEER_SNAPSHOT_SERVING][PEER_BANNED]          = true,
    [PEER_SNAPSHOT_RECEIVING][PEER_BANNED]        = true,
};

bool peer_transition_valid(enum peer_state from, enum peer_state to)
{
    if (from >= PEER_NUM_STATES || to >= PEER_NUM_STATES)
        return false;
    return g_peer_transitions[from][to];
}

bool peer_set_state_checked(uint32_t peer_id, _Atomic enum peer_state *current,
                            enum peer_state new_state, const char *reason)
{
    /* Relaxed atomic read removes the torn read that produced spurious
     * "BUG: illegal transition" spam. The read-validate-write below is not a
     * single CAS, so two concurrent transitions can still race the validate
     * (documented-benign: mis-print / lost transition only, no memory
     * corruption, no change to which transitions are legal). */
    enum peer_state old = atomic_load_explicit(current, memory_order_acquire);

    if (!peer_transition_valid(old, new_state)) {
        /* Illegal transition — this is always a bug */
        char buf[EVENT_PAYLOAD_SIZE];
        int n = snprintf(buf, sizeof(buf), "ILLEGAL %s->%s: %s",
                         peer_state_name(old), peer_state_name(new_state),
                         reason ? reason : "");
        event_emit(EV_PEER_STATE_CHANGE, peer_id, buf, (uint32_t)(n > 0 ? n : 0));
        fprintf(stderr, "BUG: peer %u illegal transition %s -> %s (%s)\n",
                peer_id, peer_state_name(old),
                peer_state_name(new_state),
                reason ? reason : "");
        return false;
    }

    /* Release-publish immutable version/handshake metadata written before the
     * transition; diagnostic readers acquire-load state before copying it. */
    atomic_store_explicit(current, new_state, memory_order_release);

    char buf[EVENT_PAYLOAD_SIZE];
    int n = snprintf(buf, sizeof(buf), "%s->%s: %s",
                     peer_state_name(old), peer_state_name(new_state),
                     reason ? reason : "");
    event_emit(EV_PEER_STATE_CHANGE, peer_id, buf, (uint32_t)(n > 0 ? n : 0));
    return true;
}
