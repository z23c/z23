/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Header range scheduler (NET-3) — range-parallel header acquisition.
 *
 * The defect this closes: cold header sync was redundancy-parallel, not
 * range-parallel. Every connected peer was asked for the SAME next batch
 * (msg_headers.c / header_sync_service.c), so N peers delivered ~1x
 * throughput and the whole download was serial-RTT-bound (and legacy
 * peers cap a batch at 160 headers).
 *
 * The fix, request-side only (header ACCEPTANCE and the band-closure
 * contiguity proof are UNTOUCHED — see header_band_service.c): partition
 * the missing header range into disjoint spans whose endpoints are
 * locally-known block hashes (compiled checkpoints, or the frontier tip),
 * and give each fast-sync-capable peer its OWN span. A peer forks its
 * span's low anchor and streams forward bounded by the span's high anchor
 * (getheaders hash_stop), so N peers cover N different checkpoint
 * intervals concurrently.
 *
 * Compiled checkpoints are the load-bearing anchors: they are hashes we
 * hold WITHOUT having synced the intervening headers, which is the only
 * way disjoint peers can fork at different heights across a cold gap. The
 * checkpoint list is a crypto-trust-foundation input (compiled into the
 * binary, PoW-consistent), never peer-provided.
 *
 * This module is the pure "brain": fixed-capacity, allocation-free, and
 * thread-safe (a single mutex around the span table). The net thread wires
 * the decisions to getheaders in msg_headers.c; stall demotion reuses the
 * existing peer_scoring primitive (PEER_OFFENCE_TIMEOUT) — this module
 * never invents its own scoring or ban policy.
 */

// one-result-type-ok:header-range-scheduler-selectors — every exported
// function is a pure planner decision (should_/partition/assign/note/
// sweep/peer_span/count answers), an ANSWER not a fallible op. There is no
// I/O, DB, or allocation to carry a struct zcl_result for; the one -1
// return (hrs_assign "no free span") is a legitimate answer, marked
// raw-return-ok at the site. Cf. header_band_service.c / header_sync_service.c.

#ifndef ZCL_SERVICES_HEADER_RANGE_SCHEDULER_H
#define ZCL_SERVICES_HEADER_RANGE_SCHEDULER_H

#include "util/sync.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Capacity of the disjoint-span table. Mainnet has 63 compiled
 * checkpoints, so a full genesis->tip cold gap produces at most ~64
 * checkpoint-anchored spans; the table is sized with headroom. */
#define HRS_MAX_SPANS 128

/* One disjoint header span [lo, hi]. Both endpoints are locally-known
 * hashes (a compiled checkpoint height, or the local frontier). At most
 * one peer owns a span at a time. */
struct hrs_span {
    int32_t  lo;           /* anchor height (start) — locally-known hash */
    int32_t  hi;           /* upper-bound height — locally-known hash */
    int32_t  peer_id;      /* owning peer (valid iff assigned) */
    int64_t  deadline_us;  /* assignment expiry, microseconds (iff assigned) */
    bool     assigned;     /* in-flight with a peer */
    bool     completed;    /* frontier reached hi — span done */
};

struct header_range_scheduler {
    zcl_mutex_t     lock;
    bool            inited;
    struct hrs_span spans[HRS_MAX_SPANS];
    size_t          n_spans;
    int32_t         range_lo;
    int32_t         range_hi;
    int64_t         span_timeout_us;
    /* Introspection counters (monotone). */
    uint64_t        stat_assigns;
    uint64_t        stat_reassigns;
    uint64_t        stat_completions;
    uint64_t        stat_timeouts;
};

/* ── Pure decisions (no scheduler state) ──────────────────────── */

/* Range-parallel is worth it only with >=2 fast-sync-capable peers AND a
 * missing-header gap larger than one wire batch. One peer, or a gap a
 * single batch closes, keeps the existing single-peer path unchanged
 * (regression: behaves exactly like today). */
bool hrs_should_parallelize(int fast_peer_count, int32_t gap, int32_t batch);

/* Partition (lo, hi] into disjoint contiguous spans at the supplied
 * anchor heights. `anchors` must be sorted ascending; each entry is a
 * locally-known hash boundary. lo and hi are implicit endpoints (anchors
 * at or outside [lo, hi] are ignored; duplicates are collapsed). Produces
 * spans [b_i, b_{i+1}] over the sorted boundary set. Returns the number
 * written (<= max_out). Interior granularity is bounded by the anchors —
 * a boundary whose hash we do not hold is never fabricated. */
size_t hrs_partition(int32_t lo, int32_t hi,
                     const int32_t *anchors, size_t n_anchors,
                     struct hrs_span *out, size_t max_out);

/* ── Stateful scheduler ───────────────────────────────────────── */

void hrs_init(struct header_range_scheduler *s, int64_t span_timeout_us);
void hrs_reset(struct header_range_scheduler *s);

/* (Re)partition the missing range. Idempotent across kicks: an existing
 * span with identical [lo, hi] carries over its assignment / deadline /
 * completed flag; spans that fell out of the new range (already synced)
 * are dropped. Safe to call every planning tick. */
void hrs_plan(struct header_range_scheduler *s, int32_t lo, int32_t hi,
              const int32_t *anchors, size_t n_anchors);

/* Assign a free span (unassigned and not completed) to peer_id, stamping
 * deadline = now_us + span_timeout_us. A peer already holding a live span
 * is not given a second one (one span per peer). Returns the span index,
 * or -1 when no span is free or the peer is already busy. */
int hrs_assign(struct header_range_scheduler *s, int32_t peer_id,
               int64_t now_us);

/* Frontier advanced to `height`: complete every span with hi <= height
 * and free its peer slot. Partially-covered spans are left assigned (their
 * low anchor stays a known hash — we never advance lo to a hash we lack).
 * Returns the number newly completed. */
size_t hrs_note_frontier(struct header_range_scheduler *s, int32_t height);

/* Expire in-flight spans past their deadline: free each slot for
 * reassignment and record the stalling peer_id into `stalled` (up to
 * `max`). Returns the count. The caller demotes each peer via
 * peer_scoring_record(PEER_OFFENCE_TIMEOUT). One stalling peer frees its
 * span for another peer — it never stalls the whole sync. */
size_t hrs_sweep_expired(struct header_range_scheduler *s, int64_t now_us,
                         int32_t *stalled, size_t max);

/* Report the live span currently held by peer_id. Returns true and fills
 * out_lo/out_hi iff the peer holds an assigned, not-yet-expired span. */
bool hrs_peer_span(struct header_range_scheduler *s, int32_t peer_id,
                   int64_t now_us, int32_t *out_lo, int32_t *out_hi);

/* Non-mutating: true iff peer_id currently owns an assigned span whose
 * deadline has passed. The net wiring reads this on a peer's own tick
 * (before the global sweep frees the slot) to attribute the timeout to
 * the right peer and demote it via peer_scoring — no cross-peer lookup,
 * so no lock-order hazard against the net manager's node table. */
bool hrs_peer_owns_expired_span(struct header_range_scheduler *s,
                                int32_t peer_id, int64_t now_us);

/* Total spans currently partitioned. */
size_t hrs_span_count(struct header_range_scheduler *s);

/* Spans that are neither assigned nor completed (assignable right now). */
size_t hrs_free_span_count(struct header_range_scheduler *s);

/* Process-global scheduler used by the net thread wiring. Lazily
 * initialized on first use with the default span timeout. */
struct header_range_scheduler *header_range_scheduler_global(void);

/* Test seam: reset the process-global scheduler to empty. Unit fixtures
 * that exercise the global (or the net wiring) must clear it between
 * cases. Pairs with hrs_reset() for caller-owned instances. */
void header_range_scheduler_reset_for_testing(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool header_range_scheduler_dump_state_json(struct json_value *out,
                                            const char *key);

#endif /* ZCL_SERVICES_HEADER_RANGE_SCHEDULER_H */
