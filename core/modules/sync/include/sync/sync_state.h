/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sync state machines — single owner.
 *
 * Before this module landed, `enum sync_state` and `enum
 * snapshot_sync_state` lived in engine/modules/event/. The event bus owned the
 * sync FSM, which is a layering inversion: the event bus is for
 * recording state transitions, not deciding which ones are legal.
 *
 * After: the two FSMs and their atomic state globals live here.
 * engine/modules/event/ retains responsibility for emitting EV_SYNC_STATE_CHANGE
 * and EV_SNAPSYNC_STATE_CHANGE; the deciding-and-storing is done in
 * core/modules/sync/src/sync_state.c.
 *
 * Both setters consult a static transition table and reject illegal
 * edges with a BUG log + a false return. Callers that previously
 * ignored the bool return continue to work (no behavioural change),
 * but new code should check the return value so a refused transition
 * is visible.
 */

#ifndef ZCL_SYNC_STATE_H
#define ZCL_SYNC_STATE_H

#include <stdbool.h>
#include <stdint.h>

/* ── Top-level sync state machine ──────────────────────── */

enum sync_state {
    SYNC_IDLE = 0,
    SYNC_FINDING_PEERS,
    SYNC_HEADERS_DOWNLOAD,     /* IBD phase 1: accumulating headers */
    SYNC_BLOCKS_DOWNLOAD,      /* IBD phase 2: downloading block data */
    SYNC_CONNECTING_BLOCKS,    /* IBD phase 3: validating + connecting */
    SYNC_AT_TIP,               /* caught up, normal relay */
    SYNC_REORG,                /* processing a chain reorganization */
    SYNC_REORG_RECOVERY,       /* recovering from disconnect failure */
    SYNC_SNAPSHOT_RECEIVE,     /* fast sync from ZCL23 peer */
    SYNC_FAILED,               /* unrecoverable error */
    SYNC_NUM_STATES            /* sentinel */
};

enum sync_state sync_get_state(void);
bool sync_set_state(enum sync_state new_state, const char *reason);
/* Race-safe conditional edge for periodic evaluators. Returns true only when
 * `expected` was still current and the legal transition was committed (or
 * expected==new_state). A concurrent owner changing the state is a benign
 * false, not an illegal-transition BUG. */
bool sync_try_transition(enum sync_state expected,
                         enum sync_state new_state,
                         const char *reason);
const char *sync_state_name(enum sync_state state);
void sync_state_monitor_init(void);
int64_t sync_get_state_duration(void);
/* Chain height at which the current sync state was entered. Currently
 * always returns 0: entry-height tracking is not yet wired (the entry
 * height is only ever stored as 0 on init and on each transition).
 * Do not read it as a live metric until a real height is recorded. */
int sync_get_state_entry_height(void);
#ifdef ZCL_TESTING
void sync_state_test_set_entered_unix(int64_t entered_unix);
#endif

/* ── Snapshot sync state machine ──────────────────────── */

enum snapshot_sync_state {
    SNAPSYNC_IDLE = 0,
    SNAPSYNC_NEGOTIATING,      /* received offer, solving PoW */
    SNAPSYNC_RECEIVING,        /* streaming chunks from peer */
    SNAPSYNC_VERIFYING,        /* SHA3 + MMB root verification */
    SNAPSYNC_COMPLETE,         /* verified UTXOs; tip publication is CSR-gated */
    SNAPSYNC_FAILED,           /* verification failed, UTXOs wiped */
    SNAPSYNC_NUM_STATES
};

enum snapshot_sync_state snapsync_get_state(void);
bool snapsync_set_state(enum snapshot_sync_state new_state, const char *reason);
const char *snapsync_state_name(enum snapshot_sync_state state);

#endif /* ZCL_SYNC_STATE_H */
