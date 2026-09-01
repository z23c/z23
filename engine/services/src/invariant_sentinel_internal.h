/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * invariant_sentinel_internal - shared state for the fail-loud validation pack.
 *
 * Keep detection/audit behavior in invariant_sentinel.c. Keep state export,
 * health rollup, cross-module counters, and test reset helpers in
 * invariant_sentinel_state.c.
 */

#ifndef ZCL_SERVICES_INVARIANT_SENTINEL_INTERNAL_H
#define ZCL_SERVICES_INVARIANT_SENTINEL_INTERNAL_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct node_db;

extern _Atomic uint64_t g_isn_pair_checks_total;
extern _Atomic uint64_t g_isn_pair_violations_total;
extern _Atomic uint64_t g_isn_sweeps_total;
extern _Atomic uint64_t g_isn_sweep_violations_total;
extern _Atomic int64_t  g_isn_last_sweep_unix;
extern _Atomic uint64_t g_isn_commitment_audits_total;
extern _Atomic uint64_t g_isn_commitment_mismatches_total;
extern _Atomic uint64_t g_isn_commitment_skipped_tip_moved;
extern _Atomic int64_t  g_isn_last_audit_unix;
extern _Atomic bool     g_isn_sweep_blocker_active;
extern _Atomic bool     g_isn_audit_blocker_active;
extern _Atomic int      g_isn_commitment_candidate_streak;

extern pthread_mutex_t g_isn_detail_lock;
extern char g_isn_last_sweep_detail[200];
extern char g_isn_last_pair_detail[200];

extern uint64_t g_isn_prev_reorg_total;
extern int64_t  g_isn_prev_tip_finalize_cursor;
extern bool     g_isn_prev_sweep_valid;

extern char g_isn_pending_invariant[16];
extern int  g_isn_pending_first_bad_h;
extern bool g_isn_pending_valid;

extern int32_t g_isn_memo_ua_frontier;
extern int64_t g_isn_memo_ua_cursor;

#ifdef ZCL_TESTING
extern struct node_db *g_isn_test_ndb;
#endif

#endif /* ZCL_SERVICES_INVARIANT_SENTINEL_INTERNAL_H */
