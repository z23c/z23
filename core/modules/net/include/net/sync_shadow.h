/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Full-lifecycle SHADOW observer for the pure sync kernel (sync/sync_reduce.h).
 *
 * The reference snapshot-sync FSM stays FULLY authoritative. At each lifecycle
 * event the production code, STRICTLY AFTER the reference decision is computed,
 * hands this observer (a) the reference phase before/after and (b) the kernel
 * event that models the same transition. The observer folds the event through
 * the pure kernel and records a BOUNDED structured comparison — per-point
 * observed/agree/allowlisted/mismatch counters plus a small ring of the most
 * recent genuine mismatches. A non-allowlisted mismatch is LOUD (LOG_ERROR +
 * a counter + dumpstate-visible via sync_shadow_dump_state_json).
 *
 * It NEVER feeds back: no production branch reads its output. A caller that
 * drops the observation changes nothing about node behavior. This is how the
 * kernel becomes provably CAPABLE of being the single authority before any
 * authority is flipped.
 *
 * Diagnostics-only state: file-static atomic counters + a tiny mutex-guarded
 * mismatch ring. This is observability, NOT the sync FSM authority — there is
 * deliberately no mutable sync-state singleton here. */

#ifndef ZCL_NET_SYNC_SHADOW_H
#define ZCL_NET_SYNC_SHADOW_H

#include "sync/sync_reduce.h"
#include "sync/sync_state.h"

#include <stdbool.h>
#include <stdint.h>

/* The lifecycle points a shadow observation can be taken at. Kept a superset of
 * what is wired today so the enum is a stable catalog (unwired points simply
 * have zero observations). */
enum sync_shadow_point {
    SYNC_SHADOW_OFFER = 0,        /* offer received / accept-reject decided */
    SYNC_SHADOW_RECEIVE_BEGIN,    /* negotiation → receiving */
    SYNC_SHADOW_CHUNK_ACCEPTED,   /* a data chunk applied */
    SYNC_SHADOW_CHUNK_REJECTED,   /* a bad chunk / peer penalized */
    SYNC_SHADOW_RECEIVE_COMPLETE, /* all chunks → verifying */
    SYNC_SHADOW_PROOF_SUCCESS,    /* verification passed (→ contained today) */
    SYNC_SHADOW_PROOF_FAILURE,    /* verification failed → failed */
    SYNC_SHADOW_PEER_LOSS,        /* serving peer lost mid-session */
    SYNC_SHADOW_TIMEOUT,          /* stall/negotiation timeout */
    SYNC_SHADOW_STOP_RESET,       /* session abandoned → idle */
    SYNC_SHADOW_CONTAINMENT,      /* staged/verified state contained at activation */
    SYNC_SHADOW_POINT_COUNT
};

const char *sync_shadow_point_name(enum sync_shadow_point p);

/* One bounded observation. All phase fields are already mapped into the kernel's
 * phase space (via sync_reduce_adapter_map_phase for the reference side). */
struct sync_shadow_obs {
    enum sync_shadow_point point;
    uint64_t               session_id;
    enum sync_phase        kernel_before;
    enum sync_phase        kernel_after;
    enum sync_phase        ref_before;   /* mapped */
    enum sync_phase        ref_after;    /* mapped */
    bool                   agrees;       /* kernel_after == ref_after */
    const char            *expected_disagreement; /* allowlist reason, else NULL */
};

/* Pure comparator: fold `kernel_event` through the kernel from the reference's
 * pre-state and compare its resulting phase against the reference's post-state.
 * The known structural gaps (kernel stages where the reference re-marks FAILED
 * under activation containment; the kernel penalizes+holds a bad chunk where
 * the reference may hard-fail the write path) are classified as
 * `expected_disagreement`, not genuine mismatches. Pure — no logging, no
 * global; safe to unit-test in isolation. */
struct sync_shadow_obs sync_shadow_compare(
    enum sync_shadow_point point, uint64_t session_id,
    enum snapshot_sync_state ref_before, enum snapshot_sync_state ref_after,
    enum sync_event_kind kernel_event, bool proof_ok);

/* Record an observation into the diagnostics counters. A genuine (non-
 * allowlisted) mismatch is LOUD (LOG_ERROR) and stored in the mismatch ring.
 * Impure (atomics + a brief mutex); never touches the sync FSM. */
void sync_shadow_record(const struct sync_shadow_obs *obs);

/* Convenience: compare + record in one call (the production wiring path). */
void sync_shadow_observe(
    enum sync_shadow_point point, uint64_t session_id,
    enum snapshot_sync_state ref_before, enum snapshot_sync_state ref_after,
    enum sync_event_kind kernel_event, bool proof_ok);

/* dumpstate hook — see CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool sync_shadow_dump_state_json(struct json_value *out, const char *key);

/* Zero every counter + the mismatch ring (tests only). */
void sync_shadow_reset(void);

/* Total genuine (non-allowlisted) mismatches across all points (tests/health). */
uint64_t sync_shadow_total_mismatches(void);

#endif /* ZCL_NET_SYNC_SHADOW_H */
