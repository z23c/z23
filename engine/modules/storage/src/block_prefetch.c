/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_prefetch — implementation. See storage/block_prefetch.h.
 *
 * One worker thread. It polls the fold's leading height via g_cursor_fn, and
 * warms the OS page cache for the contiguous NEW slice of
 * [H+lead, H+lead+window) it has not warmed yet (a per-pass frontier keeps the
 * cost O(delta), never O(window) re-scans). Warming a height: resolve its
 * blk*.dat frame, PROBE residency with preadv2(RWF_NOWAIT), and only on a
 * not-resident probe issue a blocking pread to pull the frame into the page
 * cache (optionally retaining the raw bytes in a bounded LRU).
 *
 * Thread model: the worker is the SOLE writer of the LRU (guarded by g_lru_mu
 * so cross-thread readers — block_prefetch_lru_get, the dumper — see a
 * consistent snapshot) and of the frontier. Stats are plain atomics. The
 * worker never blocks the fold; the fold never calls into the worker on its
 * hot path. */

#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include "storage/block_prefetch.h"

#include "json/json.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#if defined(__linux__)
#include <sys/uio.h>
#endif

/* preadv2 + RWF_NOWAIT (Linux 4.14+/glibc 2.26+). Where absent we degrade to
 * an unconditional warming pread (no residency probe, no hit/miss split). */
#if defined(__linux__) && defined(RWF_NOWAIT)
#define BP_HAVE_NOWAIT_PROBE 1
#else
#define BP_HAVE_NOWAIT_PROBE 0
#endif

#define BP_MAX_BLOCK_BYTES 2000000u /* mirrors read_block_from_disk_pread cap */
#define BP_IDLE_WAIT_MS    25
#define BP_LRU_MAX_ENTRIES 8192

/* ── Config + wiring (written under g_mu before the worker spawns) ─────── */
static struct block_prefetch_config g_cfg;
static char  g_datadir[2048];
static block_prefetch_cursor_fn g_cursor_fn;
static void *g_cursor_user;
static block_prefetch_pos_fn    g_pos_fn;
static void *g_pos_user;

/* ── Worker lifecycle ──────────────────────────────────────────────────── */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;
static pthread_t g_thread;
static bool      g_thread_started = false;
static bool      g_running = false;       /* under g_mu */
static bool      g_stop = false;          /* under g_mu */
static _Atomic bool g_running_fast = false;
static int64_t   g_warm_frontier = -1;    /* under g_mu: highest+1 warmed */

static struct liveness_contract g_contract;
static _Atomic int g_child_id = SUPERVISOR_INVALID_ID;

/* ── Stats ─────────────────────────────────────────────────────────────── */
static _Atomic uint64_t g_warm_hits = 0;
static _Atomic uint64_t g_warmed = 0;
static _Atomic uint64_t g_nowait_misses = 0;
static _Atomic uint64_t g_bytes = 0;
static _Atomic uint64_t g_resolve_gaps = 0;
static _Atomic uint64_t g_read_fails = 0;
static _Atomic uint64_t g_passes = 0;
static _Atomic int64_t  g_start_us = 0;

/* ── Bounded raw-body LRU (worker writes; readers under g_lru_mu) ───────── */
struct bp_lru_entry {
    int          nFile;
    unsigned int nPos;
    uint32_t     len;
    uint8_t     *bytes;
};
static pthread_mutex_t g_lru_mu = PTHREAD_MUTEX_INITIALIZER;
static struct bp_lru_entry g_lru[BP_LRU_MAX_ENTRIES];
static int    g_lru_head = 0;   /* next insert slot (ring) */
static int    g_lru_count = 0;
static size_t g_lru_bytes = 0;

static void bp_lru_clear_locked(void)
{
    for (int i = 0; i < BP_LRU_MAX_ENTRIES; i++) {
        free(g_lru[i].bytes);
        g_lru[i].bytes = NULL;
        g_lru[i].len = 0;
    }
    g_lru_head = 0;
    g_lru_count = 0;
    g_lru_bytes = 0;
}

/* Evict the oldest entry (ring FIFO). Caller holds g_lru_mu. */
static void bp_lru_evict_oldest_locked(void)
{
    if (g_lru_count == 0)
        return;
    int oldest = (g_lru_head - g_lru_count + BP_LRU_MAX_ENTRIES) % BP_LRU_MAX_ENTRIES;
    if (g_lru[oldest].bytes) {
        g_lru_bytes -= g_lru[oldest].len;
        free(g_lru[oldest].bytes);
        g_lru[oldest].bytes = NULL;
        g_lru[oldest].len = 0;
    }
    g_lru_count--;
}

/* Retain a copy of `bytes[0..len)` for `pos`, evicting oldest entries until it
 * fits inside the byte budget. No-op when the budget is 0 or a single body
 * already exceeds it. Worker-only writer. */
static void bp_lru_store(const struct disk_block_pos *pos,
                         const uint8_t *bytes, uint32_t len)
{
    if (g_cfg.max_bytes == 0 || len == 0 || (size_t)len > g_cfg.max_bytes)
        return;
    uint8_t *copy = zcl_malloc(len, "bp_lru_body");
    if (!copy)
        return; /* fail-safe: retention is best-effort, never fatal */
    memcpy(copy, bytes, len);

    pthread_mutex_lock(&g_lru_mu);
    while ((g_lru_count == BP_LRU_MAX_ENTRIES) ||
           (g_lru_bytes + len > g_cfg.max_bytes && g_lru_count > 0))
        bp_lru_evict_oldest_locked();
    struct bp_lru_entry *e = &g_lru[g_lru_head];
    free(e->bytes); /* defensive: slot should already be empty */
    e->nFile = pos->nFile;
    e->nPos = pos->nPos;
    e->len = len;
    e->bytes = copy;
    g_lru_head = (g_lru_head + 1) % BP_LRU_MAX_ENTRIES;
    g_lru_count++;
    g_lru_bytes += len;
    pthread_mutex_unlock(&g_lru_mu);
}

ssize_t block_prefetch_lru_get(const struct disk_block_pos *pos,
                               uint8_t *buf, size_t buflen)
{
    if (!pos || !buf)
        return -1; // raw-return-ok:bad args to an optional best-effort fast path
    ssize_t out = -1;
    pthread_mutex_lock(&g_lru_mu);
    for (int i = 0; i < g_lru_count; i++) {
        int idx = (g_lru_head - 1 - i + BP_LRU_MAX_ENTRIES) % BP_LRU_MAX_ENTRIES;
        struct bp_lru_entry *e = &g_lru[idx];
        if (e->bytes && e->nFile == pos->nFile && e->nPos == pos->nPos) {
            if (buflen >= e->len) {
                memcpy(buf, e->bytes, e->len);
                out = (ssize_t)e->len;
            }
            break;
        }
    }
    pthread_mutex_unlock(&g_lru_mu);
    return out;
}

/* ── Frame geometry ─────────────────────────────────────────────────────
 * A blk*.dat frame is [4 magic][4 LE size][payload]. block_index positions
 * store the PAYLOAD offset; some import paths store the FRAME offset. Mirror
 * disk_block_io's locate logic so warming reads exactly the payload span. */
static bool bp_frame_size(const uint8_t hdr[8], uint32_t *out_size)
{
    bool magic_ok = (hdr[0] == 0x24 && hdr[1] == 0xe9 && hdr[2] == 0x27 && hdr[3] == 0x64) ||
                    (hdr[0] == 0xfa && hdr[1] == 0x1a && hdr[2] == 0xf9 && hdr[3] == 0xbf) ||
                    (hdr[0] == 0xaa && hdr[1] == 0xe8 && hdr[2] == 0x3f && hdr[3] == 0x5f);
    uint32_t sz = 0;
    memcpy(&sz, hdr + 4, 4);
    if (!magic_ok || sz == 0 || sz > BP_MAX_BLOCK_BYTES)
        return false;
    if (out_size)
        *out_size = sz;
    return true;
}

static void bp_locate(const struct platform_positioned_file *file,
                      const struct disk_block_pos *pos,
                      uint64_t *payload_off, size_t *payload_len)
{
    uint8_t hdr[8];
    uint32_t sz = 0;
    if (pos->nPos >= 8) {
        if (platform_positioned_file_read(file, hdr, 8,
                                          (uint64_t)pos->nPos - 8) == 8 &&
            bp_frame_size(hdr, &sz)) {
            *payload_off = pos->nPos;
            *payload_len = sz;
            return;
        }
    }
    if (platform_positioned_file_read(file, hdr, 8, pos->nPos) == 8 &&
        bp_frame_size(hdr, &sz) &&
        pos->nPos <= UINT32_MAX - 8u) {
        *payload_off = (uint64_t)pos->nPos + 8;
        *payload_len = sz;
        return;
    }
    *payload_off = pos->nPos;
    *payload_len = BP_MAX_BLOCK_BYTES;
}

/* Warm one block frame into the page cache. Best-effort: every failure is a
 * counted no-op. `scratch` is a reusable BP_MAX_BLOCK_BYTES buffer owned by the
 * worker. `file_cache`/`nfile_cache` reuse one handle across the (usually
 * same-file) window. */
static void bp_warm_one(const struct disk_block_pos *pos, uint8_t *scratch,
                        struct platform_positioned_file *file_cache,
                        int *nfile_cache)
{
    if (pos->nFile < 0)
        return;

    if (file_cache->native == UINTPTR_MAX || *nfile_cache != pos->nFile) {
        platform_positioned_file_close(file_cache);
        char leaf[64];
        int written = pos->nFile == 255
            ? snprintf(leaf, sizeof(leaf), "blocks/blk_sync.dat")
            : snprintf(leaf, sizeof(leaf), "blocks/blk%05d.dat", pos->nFile);
        platform_positioned_file_init(file_cache);
        *nfile_cache = pos->nFile;
        if (written <= 0 || (size_t)written >= sizeof(leaf) ||
            !platform_positioned_file_open_beneath(file_cache, g_datadir,
                                                   leaf)) {
            atomic_fetch_add(&g_read_fails, 1);
            return; /* fail-safe: a missing file is the drive's problem, not ours */
        }
    }
    uint64_t off = pos->nPos;
    size_t len = BP_MAX_BLOCK_BYTES;
    bp_locate(file_cache, pos, &off, &len);
    if (len == 0 || len > BP_MAX_BLOCK_BYTES)
        len = BP_MAX_BLOCK_BYTES;

#if BP_HAVE_NOWAIT_PROBE
    if (!g_cfg.force_warm) {
        struct iovec iov = { .iov_base = scratch, .iov_len = len };
        ssize_t probe = preadv2((int)file_cache->native, &iov, 1,
                                (off_t)off, RWF_NOWAIT);
        if (probe == (ssize_t)len) {
            /* Every requested page was already resident — nothing to warm. */
            atomic_fetch_add(&g_warm_hits, 1);
            return;
        }
        /* EAGAIN (or a short read: at least one page cold) ⇒ warm it. */
        atomic_fetch_add(&g_nowait_misses, 1);
    }
#endif

    int64_t n = platform_positioned_file_read(file_cache, scratch, len, off);
    if (n <= 0) {
        atomic_fetch_add(&g_read_fails, 1);
        return;
    }
    atomic_fetch_add(&g_warmed, 1);
    atomic_fetch_add(&g_bytes, (uint64_t)n);
    bp_lru_store(pos, scratch, (uint32_t)n);
}

/* One warming pass. Returns after warming the NEW slice ahead of `cursor`.
 * `scratch` is the worker's reusable buffer. Advances g_warm_frontier under
 * g_mu. Never blocks the fold. */
static void bp_run_pass_locked_released(int32_t cursor, uint8_t *scratch)
{
    /* g_mu is HELD on entry; released around the reads, re-acquired on exit. */
    int window = g_cfg.window > 0 ? g_cfg.window : 32;
    int lead = g_cfg.lead > 0 ? g_cfg.lead : window;

    int64_t want_lo = (int64_t)cursor + lead;
    int64_t want_hi = want_lo + window; /* exclusive */
    if (want_lo < 0)
        want_lo = 0;

    /* A cursor that moved BACKWARD (reorg / restart) resets the frontier so we
     * re-warm the new forward window rather than skip it. */
    if (g_warm_frontier < want_lo || g_warm_frontier > want_hi)
        g_warm_frontier = want_lo;
    int64_t start = g_warm_frontier;
    int64_t end = want_hi;
    pthread_mutex_unlock(&g_mu);

    struct platform_positioned_file file_cache;
    platform_positioned_file_init(&file_cache);
    int nfile_cache = -1;
    int64_t warmed_to = start;
    for (int64_t h = start; h < end; h++) {
        if (h > INT32_MAX)
            break;
        bool stop;
        pthread_mutex_lock(&g_mu);
        stop = g_stop;
        pthread_mutex_unlock(&g_mu);
        if (stop)
            break;

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        if (g_pos_fn && g_pos_fn(g_pos_user, (int32_t)h, &pos)) {
            bp_warm_one(&pos, scratch, &file_cache, &nfile_cache);
        } else {
            /* A gap ahead of the fold: stop this pass at the gap so the frontier
             * does not skip past a not-yet-available height (it may fill in
             * later; we re-probe from here next pass). */
            atomic_fetch_add(&g_resolve_gaps, 1);
            break;
        }
        warmed_to = h + 1;
    }
    platform_positioned_file_close(&file_cache);

    pthread_mutex_lock(&g_mu);
    if (warmed_to > g_warm_frontier)
        g_warm_frontier = warmed_to;
}

static void *bp_worker_entry(void *arg)
{
    (void)arg;
    int child = atomic_load(&g_child_id);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_alive(child);

    uint8_t *scratch = zcl_malloc(BP_MAX_BLOCK_BYTES, "bp_scratch");
    if (!scratch) {
        LOG_WARN("block_prefetch",
                 "[block_prefetch] scratch alloc failed — worker exits, fold "
                 "reads cold (no correctness impact)");
        if (child != SUPERVISOR_INVALID_ID)
            supervisor_worker_exited(child);
        thread_registry_unregister_self();
        return NULL;
    }

    pthread_mutex_lock(&g_mu);
    while (!g_stop) {
        if (child != SUPERVISOR_INVALID_ID) {
            supervisor_tick(child);
            supervisor_progress(child, (int64_t)atomic_load(&g_warmed));
        }
        int32_t cursor = 0;
        bool have_cursor = false;
        pthread_mutex_unlock(&g_mu);
        if (g_cursor_fn)
            have_cursor = g_cursor_fn(g_cursor_user, &cursor);
        pthread_mutex_lock(&g_mu);
        if (g_stop)
            break;

        if (have_cursor) {
            atomic_fetch_add(&g_passes, 1);
            bp_run_pass_locked_released(cursor, scratch); /* releases+reacquires g_mu */
        }

        /* Bounded idle wait: re-poll the cursor even without a wakeup. */
        struct timespec until;
        if (platform_time_realtime_timespec(&until) == 0) {
            until.tv_nsec += (long)BP_IDLE_WAIT_MS * 1000000L;
            if (until.tv_nsec >= 1000000000L) {
                until.tv_sec += 1;
                until.tv_nsec -= 1000000000L;
            }
            (void)pthread_cond_timedwait(&g_cv, &g_mu, &until);
        }
    }
    pthread_mutex_unlock(&g_mu);

    free(scratch);
    if (child != SUPERVISOR_INVALID_ID)
        supervisor_worker_exited(child);
    thread_registry_unregister_self();
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void block_prefetch_config_default(struct block_prefetch_config *cfg)
{
    if (!cfg)
        return;
    cfg->enabled = false;              /* default OFF (see header) */
    cfg->max_bytes = 64u * 1024u * 1024u;
    cfg->window = 32;
    cfg->lead = 0;                     /* 0 ⇒ derive lead = window at run time */
    cfg->force_warm = false;
}

bool block_prefetch_start(const char *datadir,
                          const struct block_prefetch_config *cfg,
                          block_prefetch_cursor_fn cursor_fn, void *cursor_user,
                          block_prefetch_pos_fn pos_fn, void *pos_user)
{
    struct block_prefetch_config local;
    if (cfg)
        local = *cfg;
    else
        block_prefetch_config_default(&local);

    if (!local.enabled)
        return true; /* disabled ⇒ started=false, a benign no-op */

    if (!cursor_fn || !pos_fn) {
        LOG_WARN("block_prefetch",
                 "[block_prefetch] start: NULL cursor_fn/pos_fn — not starting");
        return false;
    }

    pthread_mutex_lock(&g_mu);
    if (g_running) {
        pthread_mutex_unlock(&g_mu);
        LOG_WARN("block_prefetch", "[block_prefetch] start: already running");
        return false;
    }
    g_cfg = local;
    snprintf(g_datadir, sizeof(g_datadir), "%s", datadir ? datadir : "");
    g_cursor_fn = cursor_fn;
    g_cursor_user = cursor_user;
    g_pos_fn = pos_fn;
    g_pos_user = pos_user;
    g_stop = false;
    g_warm_frontier = -1;
    atomic_store(&g_warm_hits, 0);
    atomic_store(&g_warmed, 0);
    atomic_store(&g_nowait_misses, 0);
    atomic_store(&g_bytes, 0);
    atomic_store(&g_resolve_gaps, 0);
    atomic_store(&g_read_fails, 0);
    atomic_store(&g_passes, 0);
    atomic_store(&g_start_us, platform_time_monotonic_us());
    pthread_mutex_lock(&g_lru_mu);
    bp_lru_clear_locked();
    pthread_mutex_unlock(&g_lru_mu);
    pthread_mutex_unlock(&g_mu);

    /* Join the liveness tree BEFORE spawning so the worker sees a valid id.
     * Heartbeat-only (deadline, no progress-quiet gate): an idle window ahead
     * of a stalled cursor legitimately warms nothing, which is not a stall.
     * TEMPORARY policy, no on_respawn: a dead worker degrades to cold reads,
     * never a mid-fold respawn. */
    liveness_contract_init(&g_contract, "chain.block_prefetch");
    g_contract.deadline_secs = 10;
    /* Register under the "chain" domain (idempotent by label — the same domain
     * app/supervisors creates; supervisor_create_domain lives in platform/modules/util so no
     * app dependency). The prefetcher is fold-adjacent, alongside pv_lookahead. */
    supervisor_domain_t *dom = supervisor_create_domain("chain");
    supervisor_child_id cid = dom ? supervisor_register_in_domain(dom, &g_contract)
                                  : SUPERVISOR_INVALID_ID;
    atomic_store(&g_child_id, cid);
    if (cid == SUPERVISOR_INVALID_ID)
        LOG_WARN("block_prefetch",
                 "[block_prefetch] supervisor registry full — running "
                 "unsupervised");

    // thread-supervision-ok:single-worker joined in block_prefetch_stop; idle-blocked on g_cv, warms a bounded window
    int rc = thread_registry_spawn("block_prefetch", bp_worker_entry, NULL,
                                   &g_thread);
    if (rc != 0) {
        LOG_WARN("block_prefetch",
                 "[block_prefetch] worker spawn failed rc=%d — fold reads cold",
                 rc);
        supervisor_unregister(atomic_load(&g_child_id));
        atomic_store(&g_child_id, SUPERVISOR_INVALID_ID);
        pthread_mutex_lock(&g_mu);
        g_cursor_fn = NULL;
        g_pos_fn = NULL;
        pthread_mutex_unlock(&g_mu);
        return false;
    }
    pthread_mutex_lock(&g_mu);
    g_thread_started = true;
    g_running = true;
    atomic_store_explicit(&g_running_fast, true, memory_order_release);
    pthread_mutex_unlock(&g_mu);
    LOG_INFO("block_prefetch",
             "[block_prefetch] started (window=%d lead=%d lru_budget=%zuB)",
             local.window, local.lead, local.max_bytes);
    return true;
}

void block_prefetch_stop(void)
{
    pthread_mutex_lock(&g_mu);
    bool was_running = g_running;
    if (was_running) {
        g_stop = true;
        g_running = false;
        atomic_store_explicit(&g_running_fast, false, memory_order_release);
        pthread_cond_broadcast(&g_cv);
    }
    bool started = g_thread_started;
    pthread_mutex_unlock(&g_mu);
    if (!was_running)
        return;

    if (started)
        pthread_join(g_thread, NULL);

    supervisor_unregister(atomic_load(&g_child_id));
    atomic_store(&g_child_id, SUPERVISOR_INVALID_ID);

    pthread_mutex_lock(&g_mu);
    g_thread_started = false;
    g_cursor_fn = NULL;
    g_pos_fn = NULL;
    g_warm_frontier = -1;
    pthread_mutex_unlock(&g_mu);

    pthread_mutex_lock(&g_lru_mu);
    bp_lru_clear_locked();
    pthread_mutex_unlock(&g_lru_mu);

    LOG_INFO("block_prefetch",
             "[block_prefetch] stopped (hits=%llu warmed=%llu bytes=%llu)",
             (unsigned long long)atomic_load(&g_warm_hits),
             (unsigned long long)atomic_load(&g_warmed),
             (unsigned long long)atomic_load(&g_bytes));
}

bool block_prefetch_running(void)
{
    return atomic_load_explicit(&g_running_fast, memory_order_acquire);
}

uint64_t block_prefetch_warm_hits(void)     { return atomic_load(&g_warm_hits); }
uint64_t block_prefetch_warmed(void)        { return atomic_load(&g_warmed); }
uint64_t block_prefetch_nowait_misses(void) { return atomic_load(&g_nowait_misses); }

size_t block_prefetch_lru_bytes(void)
{
    pthread_mutex_lock(&g_lru_mu);
    size_t n = g_lru_bytes;
    pthread_mutex_unlock(&g_lru_mu);
    return n;
}

size_t block_prefetch_lru_count(void)
{
    pthread_mutex_lock(&g_lru_mu);
    size_t n = (size_t)g_lru_count;
    pthread_mutex_unlock(&g_lru_mu);
    return n;
}

bool block_prefetch_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("block_prefetch", "dump_state_json: NULL out");
    json_set_object(out);

    bool running = block_prefetch_running();
    uint64_t hits = atomic_load(&g_warm_hits);
    uint64_t warmed = atomic_load(&g_warmed);
    uint64_t nowait = atomic_load(&g_nowait_misses);
    uint64_t bytes = atomic_load(&g_bytes);
    uint64_t gaps = atomic_load(&g_resolve_gaps);
    uint64_t rfails = atomic_load(&g_read_fails);
    uint64_t passes = atomic_load(&g_passes);
    int64_t start_us = atomic_load(&g_start_us);

    pthread_mutex_lock(&g_mu);
    int window = g_cfg.window;
    int lead = g_cfg.lead;
    bool force_warm = g_cfg.force_warm;
    int64_t frontier = g_warm_frontier;
    pthread_mutex_unlock(&g_mu);

    pthread_mutex_lock(&g_lru_mu);
    size_t lru_bytes = g_lru_bytes;
    int lru_count = g_lru_count;
    pthread_mutex_unlock(&g_lru_mu);

    json_push_kv_bool(out, "running", running);
    json_push_kv_bool(out, "nowait_probe", BP_HAVE_NOWAIT_PROBE ? true : false);
    json_push_kv_bool(out, "force_warm", force_warm);
    json_push_kv_int(out, "window", (int64_t)window);
    json_push_kv_int(out, "lead", (int64_t)lead);
    json_push_kv_int(out, "warm_frontier", frontier);
    json_push_kv_int(out, "hits", (int64_t)hits);
    json_push_kv_int(out, "warmed", (int64_t)warmed);
    json_push_kv_int(out, "nowait_misses", (int64_t)nowait);
    json_push_kv_int(out, "bytes", (int64_t)bytes);
    json_push_kv_int(out, "resolve_gaps", (int64_t)gaps);
    json_push_kv_int(out, "read_fails", (int64_t)rfails);
    json_push_kv_int(out, "passes", (int64_t)passes);
    json_push_kv_int(out, "lru_bytes", (int64_t)lru_bytes);
    json_push_kv_int(out, "lru_count", (int64_t)lru_count);

    uint64_t probed = hits + nowait;
    double resident_rate = probed > 0 ? (double)hits / (double)probed : 0.0;
    json_push_kv_real(out, "resident_rate", resident_rate);

    double warm_per_sec = 0.0;
    if (running && start_us > 0) {
        int64_t elapsed = platform_time_monotonic_us() - start_us;
        if (elapsed > 0)
            warm_per_sec = (double)warmed * 1000000.0 / (double)elapsed;
    }
    json_push_kv_real(out, "warm_blk_per_sec", warm_per_sec);

    int child = atomic_load(&g_child_id);
    json_push_kv_bool(out, "supervised", child != SUPERVISOR_INVALID_ID);
    json_push_kv_int(out, "supervisor_child_id", (int64_t)child);
    return true;
}
