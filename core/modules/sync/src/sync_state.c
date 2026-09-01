/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Owner of g_sync_state and g_snapsync_state plus their transition
 * tables. See core/modules/sync/include/sync/sync_state.h for the rationale
 * behind the split from engine/modules/event/.
 *
 * EV_SYNC_STATE_CHANGE / EV_SNAPSYNC_STATE_CHANGE are still defined
 * in engine/modules/event/include/event/event.h and emitted via event_emit;
 * this file imports event.h for that purpose. The reverse direction is
 * intentionally forbidden: event.h does not re-export sync state APIs.
 */

#include "sync/sync_state.h"
#include "event/event.h"
#include "platform/time_compat.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/* ── Sync state machine ──────────────────────────────────── */

static _Atomic int g_sync_state = SYNC_IDLE;
static _Atomic int64_t g_sync_state_entered_time;
static _Atomic int g_sync_state_entry_height;

const char *sync_state_name(enum sync_state state)
{
    static const char *names[] = {
        [SYNC_IDLE]              = "idle",
        [SYNC_FINDING_PEERS]     = "finding_peers",
        [SYNC_HEADERS_DOWNLOAD]  = "headers_download",
        [SYNC_BLOCKS_DOWNLOAD]   = "blocks_download",
        [SYNC_CONNECTING_BLOCKS] = "connecting_blocks",
        [SYNC_AT_TIP]            = "at_tip",
        [SYNC_REORG]             = "reorg",
        [SYNC_REORG_RECOVERY]    = "reorg_recovery",
        [SYNC_SNAPSHOT_RECEIVE]  = "snapshot_receive",
        [SYNC_FAILED]            = "failed",
    };
    if (state >= 0 && state < SYNC_NUM_STATES)
        return names[state];
    return "unknown";
}

/* Sync transition table */
static const bool g_sync_transitions[SYNC_NUM_STATES][SYNC_NUM_STATES] = {
    [SYNC_IDLE][SYNC_FINDING_PEERS]       = true,
    [SYNC_IDLE][SYNC_HEADERS_DOWNLOAD]    = true,
    [SYNC_IDLE][SYNC_SNAPSHOT_RECEIVE]    = true,

    [SYNC_FINDING_PEERS][SYNC_HEADERS_DOWNLOAD]  = true,
    [SYNC_FINDING_PEERS][SYNC_SNAPSHOT_RECEIVE]   = true,
    [SYNC_FINDING_PEERS][SYNC_IDLE]               = true,
    [SYNC_FINDING_PEERS][SYNC_FAILED]             = true,

    [SYNC_HEADERS_DOWNLOAD][SYNC_BLOCKS_DOWNLOAD]   = true,
    [SYNC_HEADERS_DOWNLOAD][SYNC_CONNECTING_BLOCKS]  = true,
    [SYNC_HEADERS_DOWNLOAD][SYNC_AT_TIP]             = true,
    [SYNC_HEADERS_DOWNLOAD][SYNC_IDLE]               = true,
    [SYNC_HEADERS_DOWNLOAD][SYNC_FINDING_PEERS]      = true,  /* watchdog recovery */
    [SYNC_HEADERS_DOWNLOAD][SYNC_FAILED]             = true,
    [SYNC_HEADERS_DOWNLOAD][SYNC_SNAPSHOT_RECEIVE]   = true,

    [SYNC_BLOCKS_DOWNLOAD][SYNC_CONNECTING_BLOCKS]   = true,
    [SYNC_BLOCKS_DOWNLOAD][SYNC_AT_TIP]              = true,
    [SYNC_BLOCKS_DOWNLOAD][SYNC_HEADERS_DOWNLOAD]    = true,
    [SYNC_BLOCKS_DOWNLOAD][SYNC_IDLE]                = true,
    [SYNC_BLOCKS_DOWNLOAD][SYNC_FAILED]              = true,
    [SYNC_BLOCKS_DOWNLOAD][SYNC_SNAPSHOT_RECEIVE]    = true,

    [SYNC_CONNECTING_BLOCKS][SYNC_AT_TIP]            = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_HEADERS_DOWNLOAD]  = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_BLOCKS_DOWNLOAD]   = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_IDLE]              = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_FAILED]            = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_SNAPSHOT_RECEIVE]  = true,

    [SYNC_AT_TIP][SYNC_HEADERS_DOWNLOAD]   = true,
    [SYNC_AT_TIP][SYNC_REORG]              = true,
    [SYNC_AT_TIP][SYNC_IDLE]               = true,

    [SYNC_REORG][SYNC_AT_TIP]              = true,
    [SYNC_REORG][SYNC_CONNECTING_BLOCKS]   = true,
    [SYNC_REORG][SYNC_REORG_RECOVERY]      = true,

    /* Recovery can trigger from any block-processing state */
    [SYNC_BLOCKS_DOWNLOAD][SYNC_REORG_RECOVERY]    = true,
    [SYNC_CONNECTING_BLOCKS][SYNC_REORG_RECOVERY]  = true,
    [SYNC_IDLE][SYNC_REORG_RECOVERY]               = true,
    [SYNC_REORG][SYNC_FAILED]              = true,

    [SYNC_REORG_RECOVERY][SYNC_CONNECTING_BLOCKS] = true,
    [SYNC_REORG_RECOVERY][SYNC_BLOCKS_DOWNLOAD]   = true,
    [SYNC_REORG_RECOVERY][SYNC_IDLE]              = true,
    [SYNC_REORG_RECOVERY][SYNC_FAILED]             = true,

    [SYNC_SNAPSHOT_RECEIVE][SYNC_CONNECTING_BLOCKS] = true,
    [SYNC_SNAPSHOT_RECEIVE][SYNC_HEADERS_DOWNLOAD]  = true,
    [SYNC_SNAPSHOT_RECEIVE][SYNC_AT_TIP]            = true,
    [SYNC_SNAPSHOT_RECEIVE][SYNC_IDLE]              = true,
    [SYNC_SNAPSHOT_RECEIVE][SYNC_FAILED]            = true,

    [SYNC_FAILED][SYNC_IDLE]               = true,
    [SYNC_FAILED][SYNC_FINDING_PEERS]      = true,
};

enum sync_state sync_get_state(void)
{
    return (enum sync_state)atomic_load(&g_sync_state);
}

void sync_state_monitor_init(void)
{
    atomic_store(&g_sync_state_entered_time,
                 (int64_t)platform_time_wall_time_t());
    atomic_store(&g_sync_state_entry_height, 0);
}

int64_t sync_get_state_duration(void)
{
    int64_t entered = atomic_load(&g_sync_state_entered_time);
    if (entered == 0)
        return 0;
    int64_t now = (int64_t)platform_time_wall_time_t();
    return (now > entered) ? (now - entered) : 0;
}

int sync_get_state_entry_height(void)
{
    return atomic_load(&g_sync_state_entry_height);
}

#ifdef ZCL_TESTING
void sync_state_test_set_entered_unix(int64_t entered_unix)
{
    atomic_store(&g_sync_state_entered_time, entered_unix);
}
#endif

bool sync_set_state(enum sync_state new_state, const char *reason)
{
    enum sync_state old = (enum sync_state)atomic_load(&g_sync_state);

    if (old == new_state)
        return true; /* no-op */

    if (!g_sync_transitions[old][new_state]) {
        char buf[EVENT_PAYLOAD_SIZE];
        int n = snprintf(buf, sizeof(buf), "ILLEGAL %s->%s: %s",
                         sync_state_name(old), sync_state_name(new_state),
                         reason ? reason : "");
        event_emit(EV_SYNC_STATE_CHANGE, 0, buf, (uint32_t)(n > 0 ? n : 0));
        fprintf(stderr, "BUG: sync illegal transition %s -> %s (%s)\n",
                sync_state_name(old), sync_state_name(new_state),
                reason ? reason : "");
        return false;
    }

    atomic_store(&g_sync_state, (int)new_state);
    atomic_store(&g_sync_state_entered_time,
                 (int64_t)platform_time_wall_time_t());
    atomic_store(&g_sync_state_entry_height, 0);

    char buf[EVENT_PAYLOAD_SIZE];
    int n = snprintf(buf, sizeof(buf), "%s->%s: %s",
                     sync_state_name(old), sync_state_name(new_state),
                     reason ? reason : "");
    event_emit(EV_SYNC_STATE_CHANGE, 0, buf, (uint32_t)(n > 0 ? n : 0));

    printf("Sync: %s -> %s (%s)\n",
           sync_state_name(old), sync_state_name(new_state),
           reason ? reason : "");

    return true;
}

bool sync_try_transition(enum sync_state expected,
                         enum sync_state new_state,
                         const char *reason)
{
    if (expected < 0 || expected >= SYNC_NUM_STATES ||
        new_state < 0 || new_state >= SYNC_NUM_STATES)
        return false;
    if (expected == new_state)
        return sync_get_state() == expected;
    if (!g_sync_transitions[expected][new_state])
        return false;

    int observed = (int)expected;
    if (!atomic_compare_exchange_strong(&g_sync_state, &observed,
                                        (int)new_state))
        return false;

    atomic_store(&g_sync_state_entered_time,
                 (int64_t)platform_time_wall_time_t());
    atomic_store(&g_sync_state_entry_height, 0);

    char buf[EVENT_PAYLOAD_SIZE];
    int n = snprintf(buf, sizeof(buf), "%s->%s: %s",
                     sync_state_name(expected), sync_state_name(new_state),
                     reason ? reason : "");
    event_emit(EV_SYNC_STATE_CHANGE, 0, buf,
               (uint32_t)(n > 0 ? n : 0));
    printf("Sync: %s -> %s (%s)\n",
           sync_state_name(expected), sync_state_name(new_state),
           reason ? reason : "");
    return true;
}

/* ── Snapshot sync state machine ────────────────────────── */

static _Atomic int g_snapsync_state = SNAPSYNC_IDLE;

const char *snapsync_state_name(enum snapshot_sync_state state)
{
    static const char *names[] = {
        [SNAPSYNC_IDLE]        = "idle",
        [SNAPSYNC_NEGOTIATING] = "negotiating",
        [SNAPSYNC_RECEIVING]   = "receiving",
        [SNAPSYNC_VERIFYING]   = "verifying",
        [SNAPSYNC_COMPLETE]    = "complete",
        [SNAPSYNC_FAILED]      = "failed",
    };
    if (state >= 0 && state < SNAPSYNC_NUM_STATES)
        return names[state];
    return "unknown";
}

static const bool g_snapsync_transitions[SNAPSYNC_NUM_STATES][SNAPSYNC_NUM_STATES] = {
    [SNAPSYNC_IDLE][SNAPSYNC_NEGOTIATING]       = true,
    [SNAPSYNC_NEGOTIATING][SNAPSYNC_RECEIVING]   = true,
    [SNAPSYNC_NEGOTIATING][SNAPSYNC_FAILED]      = true,
    [SNAPSYNC_NEGOTIATING][SNAPSYNC_IDLE]        = true,
    [SNAPSYNC_RECEIVING][SNAPSYNC_VERIFYING]      = true,
    [SNAPSYNC_RECEIVING][SNAPSYNC_FAILED]         = true,
    [SNAPSYNC_RECEIVING][SNAPSYNC_IDLE]           = true,  /* stall reset */
    /* Phase-0 containment: COMPLETE is structurally unreachable until the
     * unified installer presents a durable activation receipt. Verification
     * alone must transition to FAILED/contained, never publication success. */
    [SNAPSYNC_VERIFYING][SNAPSYNC_COMPLETE]       = false,
    [SNAPSYNC_VERIFYING][SNAPSYNC_FAILED]         = true,
    [SNAPSYNC_COMPLETE][SNAPSYNC_IDLE]            = true,
    [SNAPSYNC_FAILED][SNAPSYNC_IDLE]              = true,
};

enum snapshot_sync_state snapsync_get_state(void)
{
    return (enum snapshot_sync_state)atomic_load(&g_snapsync_state);
}

bool snapsync_set_state(enum snapshot_sync_state new_state, const char *reason)
{
    enum snapshot_sync_state old =
        (enum snapshot_sync_state)atomic_load(&g_snapsync_state);

    if (old == new_state) return true;

    if (!g_snapsync_transitions[old][new_state]) {
        fprintf(stderr, "BUG: snapsync illegal %s -> %s (%s)\n",
                snapsync_state_name(old), snapsync_state_name(new_state),
                reason ? reason : "");
        return false;
    }

    atomic_store(&g_snapsync_state, (int)new_state);

    char buf[EVENT_PAYLOAD_SIZE];
    snprintf(buf, sizeof(buf), "%s->%s: %s",
             snapsync_state_name(old), snapsync_state_name(new_state),
             reason ? reason : "");
    event_emit(EV_SNAPSYNC_STATE_CHANGE, 0, buf, (uint32_t)strlen(buf));

    printf("[snapsync] %s -> %s (%s)\n",
           snapsync_state_name(old), snapsync_state_name(new_state),
           reason ? reason : "");
    return true;
}
