// one-result-type-ok:json-dump-bool — the only bool-returning export here is
// segment_sealer_dump_state_json, the native dump-state function, whose
// convention (CLAUDE.md "Adding state introspection") mandates a bool return.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Segment Sealer Service — see services/segment_sealer_service.h for design.
 *
 * The seal loop, per tick:
 *   1. frontier = active_chain_height - finality_depth  (finalized, immutable)
 *   2. next-range = first unsealed, fully-below-frontier, 10k-aligned segment
 *   3. seal exactly that ONE segment via chain_segment_seal_range, reading each
 *      body through the ordinary disk path (never reducer internals)
 * One segment per tick bounds the IO so the sealer never races the reducer
 * drive. The body source fails closed on any height that is off the active
 * chain or missing HAVE_DATA, so seal_range leaves no partial segment behind.
 */

#include "platform/time_compat.h"
#include "services/segment_sealer_service.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "event/event.h"
#include "json/json.h"
#include "primitives/block.h"
#include "services/block_pruning_service.h"
#include "storage/chain_segment.h"
#include "storage/disk_block_io.h"
#include "supervisors/domains.h"
#include "util/file_tree_ops.h"
#include "util/log_macros.h"
#include "util/result.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct segment_sealer_service *g_segment_sealer = NULL;

static struct liveness_contract g_seal_contract;
static _Atomic supervisor_child_id g_seal_supervisor_id = SUPERVISOR_INVALID_ID;

/* ── Range selection (pure) ─────────────────────────────────────────────── */

bool segment_sealer_next_range(uint32_t frontier_incl,
                               const struct chain_segment_store *store,
                               uint32_t *first, uint32_t *count)
{
    const uint32_t seg = CHAIN_SEGMENT_BLOCKS_PER_SEG;
    /* Walk aligned segments from genesis; return the first one that is fully
     * below the frontier and not already sealed. The scan is a few hundred
     * cheap covers() probes at most — bounded by chain_height / 10000. */
    for (uint32_t k = 0;; k++) {
        uint32_t f = k * seg;
        uint32_t top = f + seg - 1;
        if (top < f) return false;             /* overflow guard */
        if (top > frontier_incl) return false; /* not yet finalized */
        bool sealed = store && chain_segment_store_covers(store, f);
        if (!sealed) {
            if (first) *first = f;
            if (count) *count = seg;
            return true;
        }
    }
}

/* ── Disk-backed body source (mirrors chain_segment_controller) ─────────── */

struct seal_body_ctx {
    struct main_state *ms;
    const char *datadir;
};

static bool seal_body_read(void *user, uint32_t height,
                           uint8_t **bytes, size_t *len)
{
    struct seal_body_ctx *c = user;
    *bytes = NULL; *len = 0;

    struct block_index *bi = active_chain_at(&c->ms->chain_active, (int)height);
    if (!bi || !bi->phashBlock ||
        !(block_index_status_load(bi) & BLOCK_HAVE_DATA))
        return false;

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index_pread(&blk, bi, c->datadir)) {
        block_free(&blk);
        return false;
    }

    struct byte_stream s;
    stream_init(&s, 4096);
    if (!block_serialize(&blk, &s) || s.size == 0) {
        stream_free(&s);
        block_free(&blk);
        return false;
    }
    uint8_t *copy = zcl_malloc(s.size, "segment_sealer/body");
    if (copy) {
        memcpy(copy, s.data, s.size);
        *bytes = copy;
        *len = s.size;
    }
    stream_free(&s);
    block_free(&blk);
    return copy != NULL;
}

/* ── Pure single-seal primitive (no service state) ──────────────────────────
 * Seal the single oldest unsealed, fully-below-frontier segment in `dir`. This
 * re-opens the coverage table on every call, so looping it walks the backlog
 * forward one segment at a time: after sealing [f, f+SEG) the next call sees
 * that segment covered and returns the next one. The frontier gate lives in
 * segment_sealer_next_range, which never returns a range whose top exceeds
 * `frontier_incl`, so this NEVER writes a segment above the finalized frontier.
 */
int segment_sealer_seal_next(const char *dir, uint32_t frontier_incl,
                             chain_segment_body_fn body, void *user,
                             uint32_t *out_first, char *err, size_t errlen)
{
    if (err && errlen) err[0] = 0;
    if (!dir || !dir[0] || !body)
        LOG_ERR("segment_sealer", "seal_next: null dir/body");

    struct chain_segment_store *store = NULL;
    char oerr[256] = {0};
    enum cseg_status ost = chain_segment_store_open(dir, &store, oerr, sizeof(oerr));
    if (ost != CSEG_OK) {
        LOG_WARN("segment_sealer", "[segment_sealer] store open %s: %s (%s)",
                 dir, cseg_status_str(ost), oerr);
        if (err && errlen) snprintf(err, errlen, "store open: %s", oerr);
        return -1; // raw-return-ok:logged-warn-above; caller records last_status
    }

    uint32_t first = 0, count = 0;
    bool have = segment_sealer_next_range(frontier_incl, store, &first, &count);
    chain_segment_store_close(store);
    if (!have)
        return 0; /* nothing eligible at/below the frontier */

    struct zcl_result mk = zcl_mkdir_p(dir, 0755);
    if (!mk.ok) {
        LOG_WARN("segment_sealer", "[segment_sealer] mkdir %s: %s",
                 dir, mk.message);
        if (err && errlen) snprintf(err, errlen, "mkdir: %s", mk.message);
        return -1; // raw-return-ok:logged-warn-above; caller records last_status
    }

    enum cseg_status st =
        chain_segment_seal_range(dir, body, user, first, count, err, errlen);
    if (st != CSEG_OK) {
        LOG_WARN("segment_sealer",
                 "[segment_sealer] seal [%u,%u) failed: %s (%s)",
                 first, first + count, cseg_status_str(st), err ? err : "");
        return -1; // raw-return-ok:logged-warn-above; caller records last_status
    }
    if (out_first) *out_first = first;
    return 1;
}

/* ── Prune-after-seal (post-seal verify gate) ───────────────────────────────
 * Re-open the segment just written (a full mmap + whole-segment SHA3 re-verify
 * off disk via chain_segment_open — NOT trusting the writer's own digest) and,
 * only when that independently succeeds AND a prune target has been wired,
 * prune the now-redundant blk*.dat range strictly below this segment's top. A
 * verify failure prunes nothing — the blk*.dat bodies remain the sole copy
 * until a later seal attempt succeeds. */
static void seal_verify_and_prune(struct segment_sealer_service *svc,
                                  const char *dir, uint32_t first,
                                  uint32_t count)
{
    char seg_path[3300];
    snprintf(seg_path, sizeof(seg_path), "%s/seg-%u-%u.dat", dir, first, count);
    char verr[256] = {0};
    struct chain_segment *vseg = NULL;
    enum cseg_status vst = chain_segment_open(seg_path, &vseg, verr,
                                              sizeof(verr));
    if (vst != CSEG_OK) {
        atomic_fetch_add(&svc->verify_failures, 1);
        LOG_WARN("segment_sealer",
                 "[segment_sealer] post-seal verify failed for [%u,%u): %s "
                 "(%s) — prune-after-seal skipped", first, first + count,
                 cseg_status_str(vst), verr);
        return;
    }
    chain_segment_close(vseg);
    atomic_fetch_add(&svc->segments_verified, 1);
    if (!svc->prune_svc)
        return;
    int npruned = block_pruning_prune_sealed_range(svc->prune_svc,
                                                   first + count);
    if (npruned > 0) {
        atomic_fetch_add(&svc->sealed_prune_files, npruned);
        LOG_INFO("segment_sealer",
                 "[segment_sealer] prune-after-seal: %d file(s) below "
                 "verified top=%u", npruned, first + count);
    }
}

/* ── Bounded backfill catch-up (one tick's work) ────────────────────────────
 * Seal up to `max_segments` oldest-unsealed segments below the finalized
 * frontier this pass. One segment per iteration via segment_sealer_seal_next,
 * bounded by max_segments so a single tick is O(max_segments) writes, never
 * O(chain). Updates the service's atomics + emits a decision event per seal. */
int segment_sealer_run_catchup(struct segment_sealer_service *svc,
                               uint32_t max_segments, bool force)
{
    if (!svc || !svc->ms || !svc->datadir)
        return 0;
    if (!force && !svc->enabled)
        return 0;
    if (max_segments == 0)
        return 0;

    int chain_height = active_chain_height(&svc->ms->chain_active);
    if (chain_height <= svc->finality_depth) {
        atomic_store(&svc->frontier, -1);
        return 0; /* chain too short to have any finalized segment */
    }
    uint32_t frontier = (uint32_t)(chain_height - svc->finality_depth);
    atomic_store(&svc->frontier, (int64_t)frontier);

    char dir[3200];
    snprintf(dir, sizeof(dir), "%s/segments", svc->datadir);

    struct seal_body_ctx bctx = { .ms = svc->ms, .datadir = svc->datadir };
    int sealed = 0;
    for (uint32_t i = 0; i < max_segments; i++) {
        uint32_t first = 0;
        char err[256] = {0};
        int r = segment_sealer_seal_next(dir, frontier, seal_body_read, &bctx,
                                         &first, err, sizeof(err));
        if (r < 0) {
            atomic_store(&svc->last_status, (int)CSEG_ERR_IO);
            atomic_fetch_add(&svc->seal_failures, 1);
            /* Keep any progress already made; stop this tick and retry next. */
            return sealed > 0 ? sealed
                              : -1; // raw-return-ok:logged-in-seal_next-above
        }
        if (r == 0)
            break; /* backlog drained for now */
        atomic_store(&svc->last_status, (int)CSEG_OK);
        atomic_fetch_add(&svc->segments_sealed, 1);
        atomic_store(&svc->last_sealed_first, (int64_t)first);
        event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                    "source=chain.segment_sealer decision=sealed "
                    "first=%u count=%u frontier=%u",
                    first, first + CHAIN_SEGMENT_BLOCKS_PER_SEG, frontier);
        LOG_INFO("segment_sealer",
                 "[segment_sealer] sealed segment [%u,%u) frontier=%u",
                 first, first + CHAIN_SEGMENT_BLOCKS_PER_SEG, frontier);
        seal_verify_and_prune(svc, dir, first, CHAIN_SEGMENT_BLOCKS_PER_SEG);
        sealed++;
    }
    return sealed;
}

/* ── Supervision ────────────────────────────────────────────────────────── */

static int64_t seal_deadline_secs(const struct segment_sealer_service *svc)
{
    int tick = svc && svc->tick_seconds > 0
        ? svc->tick_seconds : SEGMENT_SEALER_DEFAULT_TICK_SECONDS;
    return (int64_t)tick * 3 + 30;
}

static void seal_heartbeat(struct segment_sealer_service *svc)
{
    supervisor_child_id id = atomic_load(&g_seal_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID) return;
    supervisor_progress(id, svc ? atomic_load(&svc->segments_sealed) : 0);
    supervisor_tick(id);
}

static void seal_on_stall(struct liveness_contract *c)
{
    struct segment_sealer_service *svc =
        c ? (struct segment_sealer_service *)c->ctx : NULL;
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    LOG_WARN("segment_sealer",
             "[segment_sealer] supervisor stall reason=%s sealed=%lld failures=%lld",
             reason, svc ? (long long)atomic_load(&svc->segments_sealed) : 0,
             svc ? (long long)atomic_load(&svc->seal_failures) : 0);
}

static struct zcl_result seal_register_supervisor(
    struct segment_sealer_service *svc)
{
    if (!svc)
        return ZCL_ERR(-1, "segment_sealer: register: null svc");
    if (!supervisor_start())
        return ZCL_ERR(-2, "segment_sealer: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_seal_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        g_seal_contract.ctx = svc;
        supervisor_set_period(id, 0);
        supervisor_set_deadline(id, seal_deadline_secs(svc));
        seal_heartbeat(svc);
        return ZCL_OK;
    }

    liveness_contract_init(&g_seal_contract, "chain.segment_sealer");
    atomic_store(&g_seal_contract.period_secs, 0);
    atomic_store(&g_seal_contract.deadline_secs, seal_deadline_secs(svc));
    atomic_store(&g_seal_contract.progress_max_quiet_us, 0);
    g_seal_contract.ctx = svc;
    g_seal_contract.on_tick = NULL;
    g_seal_contract.on_stall = seal_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_seal_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-3, "segment_sealer: supervisor_register failed");
    atomic_store(&g_seal_supervisor_id, id);
    seal_heartbeat(svc);
    return ZCL_OK;
}

/* ── Background thread ──────────────────────────────────────────────────── */

static void *segment_sealer_thread(void *arg)
{
    struct segment_sealer_service *svc = arg;
    atomic_store(&svc->state, 1);

    pthread_mutex_lock(&svc->ready_mutex);
    svc->ready = true;
    pthread_cond_signal(&svc->ready_cond);
    pthread_mutex_unlock(&svc->ready_mutex);

    while (!atomic_load(&svc->stop_requested)) {
        if (svc->enabled) {
            /* Boundary backfill catch-up: seal up to catchup_batch oldest
             * segments per wake — bounded IO, no reducer race, but a node with
             * an existing backlog steps forward several segments per tick
             * instead of one. */
            int batch = svc->catchup_batch > 0
                ? svc->catchup_batch : SEGMENT_SEALER_DEFAULT_CATCHUP_BATCH;
            (void)segment_sealer_run_catchup(svc, (uint32_t)batch, false);
        }
        seal_heartbeat(svc);

        int total_ms = svc->tick_seconds * 1000;
        int slept = 0;
        while (slept < total_ms) {
            if (atomic_load(&svc->stop_requested)) break;
            platform_sleep_ms(500);
            slept += 500;
        }
    }
    atomic_store(&svc->state, 2);
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void segment_sealer_init(struct segment_sealer_service *svc,
                         struct main_state *ms, const char *datadir)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->datadir = datadir;
    pthread_mutex_init(&svc->ready_mutex, NULL);
    pthread_cond_init(&svc->ready_cond, NULL);
    atomic_store(&svc->stop_requested, false);
    atomic_store(&svc->state, 0);
    atomic_store(&svc->frontier, -1);
    atomic_store(&svc->last_status, (int)CSEG_OK);

    svc->finality_depth = SEGMENT_SEALER_DEFAULT_FINALITY_DEPTH;
    svc->tick_seconds = SEGMENT_SEALER_DEFAULT_TICK_SECONDS;
    svc->catchup_batch = SEGMENT_SEALER_DEFAULT_CATCHUP_BATCH;

    const char *env = getenv("ZCL_SEGMENT_SEALER");
    svc->enabled = env && env[0] == '1' && env[1] == '\0';
    /* svc->prune_svc is already NULL from the memset above — prune-after-seal
     * stays disabled until the caller explicitly wires a target. */
}

void segment_sealer_set_prune_service(struct segment_sealer_service *svc,
                                      struct block_pruning_service *prune_svc)
{
    if (!svc) return;
    svc->prune_svc = prune_svc;
}

struct zcl_result segment_sealer_start(struct segment_sealer_service *svc)
{
    if (!svc || !svc->ms || !svc->datadir)
        return ZCL_ERR(-1, "segment_sealer: start: null svc/ms/datadir");
    if (svc->thread_started)
        return ZCL_ERR(-2, "segment_sealer: start: already running");

    atomic_store(&svc->stop_requested, false);
    svc->ready = false;
    if (thread_registry_spawn("zcl_segment_seal", segment_sealer_thread, svc,
                              &svc->thread) != 0)
        return ZCL_ERR(-3, "segment_sealer: thread create failed: %s",
                       strerror(errno));
    svc->thread_started = true;

    pthread_mutex_lock(&svc->ready_mutex);
    bool ready_ok = true;
    while (!svc->ready) {
        struct timespec deadline;
        platform_time_realtime_timespec(&deadline);
        deadline.tv_sec += 30;
        int rc = pthread_cond_timedwait(&svc->ready_cond, &svc->ready_mutex,
                                        &deadline);
        if (rc == ETIMEDOUT && !svc->ready) { ready_ok = false; break; }
    }
    pthread_mutex_unlock(&svc->ready_mutex);
    if (!ready_ok) {
        atomic_store(&svc->stop_requested, true);
        pthread_join(svc->thread, NULL);
        svc->thread_started = false;
        return ZCL_ERR(-4, "segment_sealer: thread did not signal ready in 30s");
    }

    struct zcl_result sup = seal_register_supervisor(svc);
    if (!sup.ok) {
        atomic_store(&svc->stop_requested, true);
        pthread_join(svc->thread, NULL);
        svc->thread_started = false;
        return sup;
    }
    printf("[segment_sealer] started — enabled=%d finality_depth=%d tick=%ds "
           "catchup_batch=%d\n",
           svc->enabled, svc->finality_depth, svc->tick_seconds,
           svc->catchup_batch);
    return ZCL_OK;
}

void segment_sealer_stop(struct segment_sealer_service *svc)
{
    if (!svc || !svc->thread_started) return;
    supervisor_child_id id = atomic_load(&g_seal_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
    atomic_store(&svc->stop_requested, true);
    pthread_join(svc->thread, NULL);
    svc->thread_started = false;
#ifdef ZCL_TESTING
    id = atomic_exchange(&g_seal_supervisor_id, SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
    pthread_mutex_destroy(&svc->ready_mutex);
    pthread_cond_destroy(&svc->ready_cond);
    printf("[segment_sealer] stopped\n");
}

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool segment_sealer_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    if (!g_segment_sealer) {
        json_push_kv_bool(out, "running", false);
        return true;
    }
    struct segment_sealer_service *svc = g_segment_sealer;
    json_push_kv_bool(out, "running", svc->thread_started);
    json_push_kv_bool(out, "enabled", svc->enabled);
    json_push_kv_int(out, "finality_depth", svc->finality_depth);
    json_push_kv_int(out, "tick_seconds", svc->tick_seconds);
    json_push_kv_int(out, "catchup_batch", svc->catchup_batch);
    json_push_kv_int(out, "segments_sealed", atomic_load(&svc->segments_sealed));
    json_push_kv_int(out, "seal_failures", atomic_load(&svc->seal_failures));
    json_push_kv_int(out, "last_sealed_first", atomic_load(&svc->last_sealed_first));
    json_push_kv_int(out, "frontier", atomic_load(&svc->frontier));
    json_push_kv_bool(out, "prune_after_seal_enabled", svc->prune_svc != NULL);
    json_push_kv_int(out, "segments_verified", atomic_load(&svc->segments_verified));
    json_push_kv_int(out, "verify_failures", atomic_load(&svc->verify_failures));
    json_push_kv_int(out, "sealed_prune_files", atomic_load(&svc->sealed_prune_files));
    json_push_kv_str(out, "last_status",
                     cseg_status_str((enum cseg_status)atomic_load(&svc->last_status)));
    return true;
}
