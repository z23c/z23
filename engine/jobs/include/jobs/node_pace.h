/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * node_pace - one process-wide pace that lets a host (the phone app reading
 * Android thermal status) slow the node while it runs.
 *
 *   normal  today's behaviour, unchanged
 *   gentle  one pv_lookahead worker; the live reducer drain sleeps in
 *           proportion to the work each round took; history backfill
 *           queues no new below-tip bodies (in-flight ones finish)
 *   pause   no pv_lookahead workers; the live reducer drain does nothing, so
 *           block fetch and validation stop. P2P, pings and held headers are
 *           untouched. History backfill
 *           queues nothing.
 *
 * Control: the host writes one word (normal, gentle or pause) to
 * <datadir>/pace. The node reads it at most once per second from the places
 * that run continuously (pv_lookahead workers and the reducer drain). A
 * missing, empty or unrecognised file means normal, so a node whose pace file
 * was never written behaves exactly as before. The pace never alters a
 * validation verdict: it only delays prefetch and drain work.
 *
 * node_pace_get is a relaxed atomic load and is safe on any thread. */

#ifndef ZCL_JOBS_NODE_PACE_H
#define ZCL_JOBS_NODE_PACE_H

#include <stdbool.h>
#include <stdint.h>

enum node_pace {
    NODE_PACE_NORMAL = 0,
    NODE_PACE_GENTLE = 1,
    NODE_PACE_PAUSE = 2,
};

/* Bind the datadir whose "pace" file node_pace_poll reads; NULL or "" unbinds
 * (the pace then changes only through node_pace_set). */
void node_pace_set_datadir(const char *datadir);

enum node_pace node_pace_get(void);
void node_pace_set(enum node_pace pace);

const char *node_pace_name(enum node_pace pace);
bool node_pace_parse(const char *word, enum node_pace *out);

/* Re-read the pace file when at least a second passed since the last read by
 * any thread; otherwise a single atomic compare. No-op without a datadir. */
void node_pace_poll(void);

/* True while recovery machinery (condition remedies, the sticky escalator, the
 * blocker escape sweep) must not act on tip progress: during pause and for a
 * grace period after leaving it, so their detectors see the node advancing
 * again before they judge it. An app-requested cooldown is never a fault. */
bool node_pace_hold_recovery(void);

/* Sleep applied after one reducer drain round that took round_us: 0 at normal,
 * the round's own duration (capped) at gentle. Pause is handled by the caller
 * skipping the round. */
int node_pace_gentle_sleep_ms(int64_t round_us);

#ifdef ZCL_TESTING
void node_pace_test_end_resume_grace(void);
#endif

#endif
