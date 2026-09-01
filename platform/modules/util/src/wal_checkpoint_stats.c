/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * wal_checkpoint_stats — see util/wal_checkpoint_stats.h for why the frame
 * counts, not the result code, are the thing worth publishing.
 *
 * Everything here is lock-free by construction: counters are relaxed atomic
 * scalars and the three string fields are atomic pointers to STATIC strings.
 * A recorder is a handful of atomic adds on a path that has just done disk
 * I/O, and a reader can never wedge a checkpoint by observing it. The
 * consequence a reader must accept is that a snapshot is not a consistent
 * instant: two counters can be read on either side of one attempt. That is
 * the right trade for a diagnostic — the totals are what matter, and no
 * verdict here is derived from two counters having to agree.
 */

#include "util/wal_checkpoint_stats.h"

#include "platform/time_compat.h"

#include <stdatomic.h>

/* Static strings; stored by pointer, so they must outlive every reader. */
static const char *const WCS_STATE_NOT_STARTED = "not_started";

static struct {
    _Atomic bool         periodic_armed;
    _Atomic(const char *) periodic_state;

    _Atomic int64_t attempts_total;
    _Atomic int64_t drained_total;
    _Atomic int64_t partial_total;
    _Atomic int64_t noop_total;
    _Atomic int64_t busy_total;
    _Atomic int64_t error_total;
    _Atomic int64_t frames_moved_total;

    _Atomic int64_t last_unix;
    _Atomic int64_t last_log_frames;
    _Atomic int64_t last_ckpt_frames;
    _Atomic int     last_rc;
    _Atomic(const char *) last_outcome;
    _Atomic(const char *) last_source;

    _Atomic int64_t periodic_last_wait_us;
    _Atomic int64_t periodic_last_exec_us;
    _Atomic int64_t periodic_max_wait_us;
    _Atomic int64_t periodic_max_exec_us;
    _Atomic int64_t periodic_runs_total;
} g_wcs;

/* ── classification ──────────────────────────────────────────────────── */

enum wal_ckpt_outcome wal_ckpt_classify(bool completed, bool busy,
                                        int64_t log_frames,
                                        int64_t ckpt_frames)
{
    /* Busy is checked before completed: SQLite reports internal contention as
     * a SUCCESSFUL call whose result row carries busy=1, so a caller that
     * ranked "completed" first would file the one outcome that reclaims
     * nothing under the one that reclaims everything. */
    if (busy)
        return WAL_CKPT_BUSY;
    if (!completed)
        return WAL_CKPT_ERROR;
    if (log_frames < 0 || ckpt_frames < 0)
        return WAL_CKPT_UNKNOWN;
    if (ckpt_frames >= log_frames)
        return WAL_CKPT_DRAINED;   /* includes the empty-WAL 0/0 case */
    if (ckpt_frames == 0)
        return WAL_CKPT_NOOP;
    return WAL_CKPT_PARTIAL;
}

const char *wal_ckpt_outcome_name(enum wal_ckpt_outcome o)
{
    switch (o) {
    case WAL_CKPT_ERROR:   return "error";
    case WAL_CKPT_BUSY:    return "busy";
    case WAL_CKPT_NOOP:    return "noop";
    case WAL_CKPT_PARTIAL: return "partial";
    case WAL_CKPT_DRAINED: return "drained";
    case WAL_CKPT_UNKNOWN: break;
    }
    return "unknown";
}

bool wal_ckpt_outcome_reclaimed_nothing(enum wal_ckpt_outcome o)
{
    return o == WAL_CKPT_NOOP || o == WAL_CKPT_BUSY || o == WAL_CKPT_ERROR;
}

/* ── recording ───────────────────────────────────────────────────────── */

void wal_ckpt_stats_note(const struct wal_ckpt_record *r)
{
    if (!r)
        return;

    atomic_fetch_add_explicit(&g_wcs.attempts_total, 1, memory_order_relaxed);

    switch (r->outcome) {
    case WAL_CKPT_DRAINED:
        atomic_fetch_add_explicit(&g_wcs.drained_total, 1,
                                  memory_order_relaxed);
        break;
    case WAL_CKPT_PARTIAL:
        atomic_fetch_add_explicit(&g_wcs.partial_total, 1,
                                  memory_order_relaxed);
        break;
    case WAL_CKPT_NOOP:
        atomic_fetch_add_explicit(&g_wcs.noop_total, 1, memory_order_relaxed);
        break;
    case WAL_CKPT_BUSY:
        atomic_fetch_add_explicit(&g_wcs.busy_total, 1, memory_order_relaxed);
        break;
    case WAL_CKPT_ERROR:
        atomic_fetch_add_explicit(&g_wcs.error_total, 1, memory_order_relaxed);
        break;
    case WAL_CKPT_UNKNOWN:
        break;
    }

    if (r->ckpt_frames > 0)
        atomic_fetch_add_explicit(&g_wcs.frames_moved_total, r->ckpt_frames,
                                  memory_order_relaxed);

    atomic_store_explicit(&g_wcs.last_unix, platform_time_wall_unix(),
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_log_frames, r->log_frames,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_ckpt_frames, r->ckpt_frames,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_rc, r->rc, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_outcome,
                          wal_ckpt_outcome_name(r->outcome),
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_source, r->source ? r->source : "unknown",
                          memory_order_relaxed);
}

void wal_ckpt_stats_note_periodic_timing(int64_t wait_us, int64_t exec_us)
{
    if (wait_us < 0 || exec_us < 0)
        return;
    atomic_store_explicit(&g_wcs.periodic_last_wait_us, wait_us,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_last_exec_us, exec_us,
                          memory_order_relaxed);
    if (wait_us > atomic_load_explicit(&g_wcs.periodic_max_wait_us,
                                       memory_order_relaxed))
        atomic_store_explicit(&g_wcs.periodic_max_wait_us, wait_us,
                              memory_order_relaxed);
    if (exec_us > atomic_load_explicit(&g_wcs.periodic_max_exec_us,
                                       memory_order_relaxed))
        atomic_store_explicit(&g_wcs.periodic_max_exec_us, exec_us,
                              memory_order_relaxed);
    atomic_fetch_add_explicit(&g_wcs.periodic_runs_total, 1,
                              memory_order_relaxed);
}

void wal_ckpt_stats_set_periodic_armed(bool armed, const char *state)
{
    atomic_store_explicit(&g_wcs.periodic_armed, armed, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_state,
                          state ? state : (armed ? "armed"
                                                 : WCS_STATE_NOT_STARTED),
                          memory_order_relaxed);
}

/* ── reading ─────────────────────────────────────────────────────────── */

void wal_ckpt_stats_snapshot(struct wal_ckpt_stats *out)
{
    const char *s;

    if (!out)
        return;

    out->periodic_armed = atomic_load_explicit(&g_wcs.periodic_armed,
                                               memory_order_relaxed);
    s = atomic_load_explicit(&g_wcs.periodic_state, memory_order_relaxed);
    out->periodic_state = s ? s : WCS_STATE_NOT_STARTED;

    out->attempts_total = atomic_load_explicit(&g_wcs.attempts_total,
                                               memory_order_relaxed);
    out->drained_total  = atomic_load_explicit(&g_wcs.drained_total,
                                               memory_order_relaxed);
    out->partial_total  = atomic_load_explicit(&g_wcs.partial_total,
                                               memory_order_relaxed);
    out->noop_total     = atomic_load_explicit(&g_wcs.noop_total,
                                               memory_order_relaxed);
    out->busy_total     = atomic_load_explicit(&g_wcs.busy_total,
                                               memory_order_relaxed);
    out->error_total    = atomic_load_explicit(&g_wcs.error_total,
                                               memory_order_relaxed);
    out->frames_moved_total =
        atomic_load_explicit(&g_wcs.frames_moved_total, memory_order_relaxed);

    out->last_unix = atomic_load_explicit(&g_wcs.last_unix,
                                          memory_order_relaxed);
    out->last_log_frames = atomic_load_explicit(&g_wcs.last_log_frames,
                                                memory_order_relaxed);
    out->last_ckpt_frames = atomic_load_explicit(&g_wcs.last_ckpt_frames,
                                                 memory_order_relaxed);
    out->last_rc = atomic_load_explicit(&g_wcs.last_rc, memory_order_relaxed);
    s = atomic_load_explicit(&g_wcs.last_outcome, memory_order_relaxed);
    out->last_outcome = s ? s : "unknown";
    s = atomic_load_explicit(&g_wcs.last_source, memory_order_relaxed);
    out->last_source = s ? s : "none";

    out->periodic_last_wait_us =
        atomic_load_explicit(&g_wcs.periodic_last_wait_us,
                             memory_order_relaxed);
    out->periodic_last_exec_us =
        atomic_load_explicit(&g_wcs.periodic_last_exec_us,
                             memory_order_relaxed);
    out->periodic_max_wait_us =
        atomic_load_explicit(&g_wcs.periodic_max_wait_us,
                             memory_order_relaxed);
    out->periodic_max_exec_us =
        atomic_load_explicit(&g_wcs.periodic_max_exec_us,
                             memory_order_relaxed);
    out->periodic_runs_total =
        atomic_load_explicit(&g_wcs.periodic_runs_total,
                             memory_order_relaxed);
}

void wal_ckpt_stats_reset(void)
{
    atomic_store_explicit(&g_wcs.periodic_armed, false, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_state, WCS_STATE_NOT_STARTED,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.attempts_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.drained_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.partial_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.noop_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.busy_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.error_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.frames_moved_total, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_unix, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_log_frames, -1, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_ckpt_frames, -1, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_rc, 0, memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_outcome, "unknown", memory_order_relaxed);
    atomic_store_explicit(&g_wcs.last_source, "none", memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_last_wait_us, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_last_exec_us, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_max_wait_us, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_max_exec_us, 0,
                          memory_order_relaxed);
    atomic_store_explicit(&g_wcs.periodic_runs_total, 0, memory_order_relaxed);
}
