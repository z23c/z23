/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_rung_install_strand — see conditions/checkpoint_rung_install_strand.h.
 * Read-only: every input is a lookup (compiled ladder, island facts, the
 * projection singleton, the event-log tail, the reducer frontier). Nothing here
 * writes any durable state; the two sites log once per process, the episode-end
 * reason line once per episode. */

#include "conditions/checkpoint_rung_install_strand.h"

#include "chain/checkpoints.h"                        /* compiled keystone + ladder rungs */
#include "config/consensus_state_install_runtime.h"   /* boot_staged_bundle_wait_target */
#include "config/flysync_island.h"                    /* flysync_island_phase/requested */
#include "jobs/reducer_frontier.h"                    /* reducer_frontier_compute_hstar */
#include "jobs/tip_finalize_stage.h"                  /* tip_finalize_stage_block_hash_at */
#include "platform/time_compat.h"                     /* test-only hold measurement */
#include "services/island_anchor.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"               /* ev_block_header_parse */
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define CRS_SUBSYS "condition"

/* Log-tail bytes one arm-site lookup may read: one sequential pread pass, run
 * on the conditions thread with no projection, progress-store or log lock held
 * (event_log_stream takes the log lock only to snapshot the end offset). */
#define CRS_TAIL_BUDGET_BYTES ((uint64_t)64 << 20)

static _Atomic bool g_arm_logged;
static _Atomic bool g_install_logged;
static _Atomic bool g_episode_end_logged;
#ifdef ZCL_TESTING
static _Atomic int g_test_arm_skips;
static _Atomic int g_test_episode_end_logs;
static _Atomic int g_test_hstar_reads;
static _Atomic int64_t g_test_max_hold_us;
static _Atomic uint64_t g_test_last_scan_bytes;
#endif

/* The arm-site log-tail lookup, remembered for this process per (projection,
 * rung hash): where it stopped (a record boundary), whether it found the rung
 * header, and whether it decided ABSENT up to that boundary (with the H* read
 * then). The log is append-only and replay never deletes a row, so a found
 * header stays found; a decided ABSENT and its H* stand only while the log end
 * has not moved. Every persisted block appends a block-status event, so on a
 * syncing node the pair is dropped about once per poll; while it stands its H*
 * can lag the real one (see crs_tail_cached_locked for why that can only
 * delay, never arm). */
static struct {
    pthread_mutex_t mu;
    block_index_projection_t *projection;
    uint8_t hash[32];
    uint64_t cursor;
    uint64_t budget;
    int32_t hstar;
    bool found;
    bool absent;
} g_tail = { .mu = PTHREAD_MUTEX_INITIALIZER, .budget = CRS_TAIL_BUDGET_BYTES };

const struct rom_state_rung *checkpoint_rung_at(int32_t height, const uint8_t hash[32])
{
    const struct rom_state_checkpoint *keystone = get_rom_state_checkpoint();
    if (!keystone || !hash || height <= keystone->height)
        return NULL;
    for (size_t i = 0; i < get_rom_state_rung_count(); i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height == height)
            return memcmp(r->cp.block_hash, hash, 32) == 0 ? r : NULL;
    }
    return NULL;
}

bool checkpoint_rung_window_route(void)
{
    return flysync_island_phase() == FLYSYNC_OFF && !flysync_island_requested() &&
           !island_anchor_registered() &&
           island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_NONE;
}

bool checkpoint_rung_install_strands(int32_t target_h, const uint8_t target_hash[32],
                                     bool legacy_binding, bool window_route,
                                     enum checkpoint_rung_row row, int32_t hstar)
{
    return checkpoint_rung_at(target_h, target_hash) && legacy_binding && window_route &&
           row != CHECKPOINT_RUNG_ROW_PROJECTED && hstar > 0 && hstar < target_h;
}

/* The pending boot rebuilds from this projection. No open projection or a
 * lookup error cannot prove the row is there: UNKNOWN (refuse, never worse). */
static enum checkpoint_rung_row crs_row(const uint8_t hash[32])
{
    block_index_projection_t *p = block_index_projection_singleton();
    if (!p)
        return CHECKPOINT_RUNG_ROW_UNKNOWN;
    struct disk_block_index disk;
    disk_block_index_init(&disk);
    enum bip_lookup_result r = block_index_projection_lookup_strict(p, hash, &disk);
    return r == BIP_LOOKUP_PRESENT ? CHECKPOINT_RUNG_ROW_PROJECTED :
           r == BIP_LOOKUP_ABSENT ? CHECKPOINT_RUNG_ROW_ABSENT : CHECKPOINT_RUNG_ROW_UNKNOWN;
}

/* H* exactly as consensus_state_publication_cas_capture_frontier_locked binds a
 * positive height: compute_hstar succeeded AND block_hash_at(H*) resolves. Its
 * only other success branch (the clean-genesis fallback) binds 0, and a failed
 * capture binds nothing, so both read here as -1 (not stranding). The capture
 * itself is not called because before the boot warm it logs an ERROR on the
 * fresh H*=0 node that then installs fine. */
static int32_t crs_hstar(void)
{
    sqlite3 *db = progress_store_db();
    if (!db)
        return -1; // raw-return-ok:no-open-progress-store-means-no-bindable-frontier
    int32_t hstar = -1, served_floor = -1;
    uint8_t hash[32];
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_hstar_reads, 1);
#endif
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, &hstar, &served_floor) && hstar >= 0 &&
              tip_finalize_stage_block_hash_at(db, hstar, hash);
    progress_store_tx_unlock();
    return ok ? hstar : -1;
}

struct crs_scan {
    const uint8_t *hash;
    uint64_t limit;   /* stop before a record that starts at or past this offset */
    uint64_t next;    /* the record boundary after the last record examined */
    bool found, more, bad;
};

/* The exact acceptance block_index_projection_lookup_strict applies to the row
 * the next catch-up would write from this event. */
static bool crs_scan_cb(uint64_t offset, enum event_log_type type, const void *payload,
                        size_t len, void *user)
{
    struct crs_scan *s = user;
    if (offset >= s->limit) {
        s->more = true;
        return false;
    }
    s->next = offset + EVENT_LOG_FRAME_OVERHEAD + (uint64_t)len;
    if (type != EV_BLOCK_HEADER)
        return true;
    struct ev_block_header h;
    const uint8_t *solution = NULL;
    if (!payload || !ev_block_header_parse(payload, len, &h, &solution)) {
        s->bad = true;   /* the catch-up would stop here too */
        return false;
    }
    s->found = len == ev_block_header_wire_size(h.nSolutionSize) && h.reserved[0] == 0 &&
               h.reserved[1] == 0 && memcmp(h.hash, s->hash, 32) == 0;
    return !s->found;
}

/* One bounded step from max(cursor, consumed offset); g_tail.mu held. A
 * finished lookup that found nothing records the H* it was asked for. */
static enum checkpoint_rung_row crs_tail_step(event_log_t *log, uint64_t consumed, int32_t hstar)
{
    uint64_t start = g_tail.cursor > consumed ? g_tail.cursor : consumed;
    struct crs_scan s = { .hash = g_tail.hash, .limit = start + g_tail.budget, .next = start };
    g_tail.absent = false;
    if (event_log_stream(log, start, crs_scan_cb, &s) != 0 || s.bad)
        return CHECKPOINT_RUNG_ROW_UNKNOWN;
#ifdef ZCL_TESTING
    atomic_store(&g_test_last_scan_bytes, s.next - start);
#endif
    g_tail.cursor = s.next;
    g_tail.found = s.found;
    g_tail.absent = !s.found && !s.more;
    g_tail.hstar = hstar;
    return s.found ? CHECKPOINT_RUNG_ROW_PROJECTED :
           s.more ? CHECKPOINT_RUNG_ROW_PENDING : CHECKPOINT_RUNG_ROW_ABSENT;
}

/* Start over when the projection or the rung hash changed; g_tail.mu held. */
static void crs_tail_bind_locked(block_index_projection_t *p, const uint8_t hash[32])
{
    if (g_tail.projection == p && memcmp(g_tail.hash, hash, 32) == 0)
        return;
    g_tail.projection = p;
    memcpy(g_tail.hash, hash, 32);
    g_tail.cursor = 0;
    g_tail.found = false;
    g_tail.absent = false;
}

/* The remembered answer: a found header stays found; a decided ABSENT, with
 * the H* it was decided at, stands (no H* read, no tail read: only the log end
 * offset) only while the log end is still where the lookup stopped (no event
 * of any kind appended since). Every block the node persists and validates
 * appends a block-status event (body_persist, script_validate), so on a
 * syncing node the log end moves between almost every two polls: the pair is
 * dropped, H* is folded again under the progress-store lock about once per
 * 5 s poll, and the tail step reads only the newly appended bytes. The pair
 * saves work only on a quiet node. While it stands its H* can lag the real
 * one. That can only
 * DELAY, never arm: crs_tail_answer reaches crs_tail_step (which stores the
 * ABSENT and its H*) only past its 0 < H* < target guard, and the hash key
 * fixes the target, so the remembered pair always answers "strand"
 * (checkpoint_rung_install_strands). The lag lasts until the next appended
 * event of any type (on a syncing node, the next block); on a node where
 * nothing is appended it is not bounded in time. g_tail.mu held. */
static bool crs_tail_cached_locked(event_log_t *log, struct checkpoint_rung_install_strand *s)
{
    if (g_tail.found) {
        s->row = CHECKPOINT_RUNG_ROW_PROJECTED;
        return true;
    }
    if (!g_tail.absent || event_log_size(log) != g_tail.cursor)
        return false; // raw-return-ok:the-log-grew-or-the-lookup-is-unfinished-recompute
    s->row = CHECKPOINT_RUNG_ROW_ABSENT;
    s->hstar = g_tail.hstar;
    return true;
}

/* Will the next boot's catch-up write the rung row the projection lacks now?
 * One bounded step; the projection, progress-store and log locks are not held
 * across it (event_log_stream takes the log lock only to read the end). */
static enum checkpoint_rung_row crs_tail_row(block_index_projection_t *p, event_log_t *log,
                                             uint64_t consumed, const uint8_t hash[32],
                                             int32_t hstar)
{
#ifdef ZCL_TESTING
    int64_t t0 = platform_time_monotonic_us();
#endif
    pthread_mutex_lock(&g_tail.mu);
    crs_tail_bind_locked(p, hash);
    enum checkpoint_rung_row row = g_tail.found ? CHECKPOINT_RUNG_ROW_PROJECTED :
                                   crs_tail_step(log, consumed, hstar);
    pthread_mutex_unlock(&g_tail.mu);
#ifdef ZCL_TESTING
    int64_t held = platform_time_monotonic_us() - t0;
    if (held > atomic_load(&g_test_max_hold_us))
        atomic_store(&g_test_max_hold_us, held);
#endif
    return row;
}

/* Arm site, the projection lacks the row: the remembered answer when it is
 * still current (no H* read, no tail read: only the log end offset), else H*
 * and, only while
 * 0 < H* < target, one bounded tail step. H* is read outside g_tail.mu. */
static void crs_tail_answer(int32_t target_h, const uint8_t hash[32],
                            struct checkpoint_rung_install_strand *s)
{
    block_index_projection_t *p = block_index_projection_singleton();
    event_log_t *log = event_log_singleton();
    uint64_t consumed = block_index_projection_consumed_offset(p);
    bool usable = p && log && consumed != UINT64_MAX;
    bool cached = false;
    if (usable) {
        pthread_mutex_lock(&g_tail.mu);
        crs_tail_bind_locked(p, hash);
        cached = crs_tail_cached_locked(log, s);
        pthread_mutex_unlock(&g_tail.mu);
    }
    if (cached)
        return;
    s->hstar = crs_hstar();
    if (s->hstar <= 0 || s->hstar >= target_h)
        return;
    s->row = usable ? crs_tail_row(p, log, consumed, hash, s->hstar) : CHECKPOINT_RUNG_ROW_UNKNOWN;
}

/* Cheap conjuncts first; H* only when the projection lacks the row; the log
 * tail only at the arm site and only while 0 < H* < target. */
static bool crs_would_strand(int32_t target_h, const uint8_t target_hash[32],
                             bool legacy_binding, bool tail,
                             struct checkpoint_rung_install_strand *out)
{
    struct checkpoint_rung_install_strand s = { .target_height = target_h, .hstar = -1,
                                                .row = CHECKPOINT_RUNG_ROW_UNKNOWN };
    bool route = legacy_binding && checkpoint_rung_at(target_h, target_hash) &&
                 checkpoint_rung_window_route();
    if (route)
        s.row = crs_row(target_hash);
    if (route && tail && s.row == CHECKPOINT_RUNG_ROW_ABSENT)
        crs_tail_answer(target_h, target_hash, &s);
    else if (route && s.row != CHECKPOINT_RUNG_ROW_PROJECTED)
        s.hstar = crs_hstar();
    if (out)
        *out = s;
    return checkpoint_rung_install_strands(target_h, target_hash, legacy_binding, route,
                                           s.row, s.hstar);
}

bool checkpoint_rung_install_would_strand(int32_t target_h, const uint8_t target_hash[32],
                                          bool legacy_binding,
                                          struct checkpoint_rung_install_strand *out)
{
    return crs_would_strand(target_h, target_hash, legacy_binding, false, out);
}

bool checkpoint_rung_arm_would_strand(int32_t target_h, const uint8_t target_hash[32],
                                      struct checkpoint_rung_install_strand *out)
{
    return crs_would_strand(target_h, target_hash, true, true, out);
}

/* No typed blocker (lead decision): the node is not blocked, it keeps syncing,
 * so a blocker or a page would be untrue. The once-per-process WARN carries
 * the operator text. */
void checkpoint_rung_install_strand_note_arm(const struct checkpoint_rung_install_strand *s)
{
    if (!s || s->row == CHECKPOINT_RUNG_ROW_PENDING)
        return; // raw-return-ok:the-log-tail-lookup-is-still-running-nothing-to-say-yet
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_arm_skips, 1);
#endif
    if (atomic_exchange(&g_arm_logged, true))
        return;
    LOG_WARN(CRS_SUBSYS, "[condition:checkpoint_bundle_install_ready] fast start skipped because "
             "this node already applied %d blocks (H*=%d) below the checkpoint rung h=%d and its "
             "block index does not hold the rung row; the bundle install is not armed and the node "
             "keeps syncing normally", (int)s->hstar, (int)s->hstar, (int)s->target_height);
}

bool checkpoint_rung_strand_decided(const struct checkpoint_rung_install_strand *s)
{
    return s && s->row == CHECKPOINT_RUNG_ROW_ABSENT && s->hstar > 0 &&
           s->hstar < s->target_height;
}

void checkpoint_rung_install_strand_note_episode_open(void)
{
    atomic_store(&g_episode_end_logged, false);
}

void checkpoint_rung_install_strand_note_episode_end(const struct checkpoint_rung_install_strand *s)
{
    if (!s || atomic_exchange(&g_episode_end_logged, true))
        return; // raw-return-ok:the-reason-line-is-logged-once-per-episode
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_episode_end_logs, 1);
#endif
    LOG_WARN(CRS_SUBSYS, "[condition:checkpoint_bundle_install_ready] no install happened and none "
             "is armed: this node already applied %d blocks (H*=%d) below the checkpoint rung h=%d "
             "whose row its block index does not hold, so this condition has nothing left to do on "
             "this node and ends its episode; the node keeps syncing block by block",
             (int)s->hstar, (int)s->hstar, (int)s->target_height);
}

bool checkpoint_rung_install_strand_refuses(const char *bundle_path, char *reason, size_t cap)
{
    int32_t target_h = 0;
    uint8_t target_hash[32];
    struct checkpoint_rung_install_strand s;
    if (!bundle_path || !boot_staged_bundle_wait_target(bundle_path, &target_h, target_hash) ||
        !checkpoint_rung_install_would_strand(target_h, target_hash, true, &s))
        return false;
    if (reason && cap)
        snprintf(reason, cap, "fast start skipped: this node already applied %d blocks (H*=%d "
                 "below rung h=%d, rung row not in its block index); the bundle is kept, not "
                 "installed, and the node keeps syncing normally", (int)s.hstar, (int)s.hstar,
                 (int)s.target_height);
    if (!atomic_exchange(&g_install_logged, true))
        LOG_WARN(CRS_SUBSYS, "install of %s refused (retriable, not marked .failed): %s",
                 bundle_path, reason && cap ? reason : "strand");
    return true;
}

#ifdef ZCL_TESTING
void checkpoint_rung_install_strand_test_reset(void)
{
    atomic_store(&g_arm_logged, false);
    atomic_store(&g_install_logged, false);
    atomic_store(&g_episode_end_logged, false);
    atomic_store(&g_test_arm_skips, 0);
    atomic_store(&g_test_episode_end_logs, 0);
    atomic_store(&g_test_hstar_reads, 0);
    atomic_store(&g_test_max_hold_us, 0);
    atomic_store(&g_test_last_scan_bytes, 0);
    pthread_mutex_lock(&g_tail.mu);
    g_tail.projection = NULL;
    memset(g_tail.hash, 0, sizeof(g_tail.hash));
    g_tail.cursor = 0;
    g_tail.budget = CRS_TAIL_BUDGET_BYTES;
    g_tail.hstar = -1;
    g_tail.found = false;
    g_tail.absent = false;
    pthread_mutex_unlock(&g_tail.mu);
}

int checkpoint_rung_install_strand_test_arm_skips(void)
{
    return atomic_load(&g_test_arm_skips);
}

int checkpoint_rung_install_strand_test_episode_end_logs(void)
{
    return atomic_load(&g_test_episode_end_logs);
}

int checkpoint_rung_install_strand_test_hstar_reads(void)
{
    return atomic_load(&g_test_hstar_reads);
}

int64_t checkpoint_rung_install_strand_test_max_hold_us(void)
{
    return atomic_load(&g_test_max_hold_us);
}

uint64_t checkpoint_rung_install_strand_test_last_scan_bytes(void)
{
    return atomic_load(&g_test_last_scan_bytes);
}

void checkpoint_rung_install_strand_test_set_scan_budget(uint64_t bytes)
{
    pthread_mutex_lock(&g_tail.mu);
    g_tail.budget = bytes ? bytes : CRS_TAIL_BUDGET_BYTES;
    pthread_mutex_unlock(&g_tail.mu);
}
#endif
