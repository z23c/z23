/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Background block hash verification — recomputes SHA256d of every block
 * header on disk and compares against the stored hash in the block index.
 * See bg_hash_verification_service.h for design overview. */

#include "platform/time_compat.h"
#include "services/bg_hash_verification_service.h"
#include "adapters/outbound/persistence/bg_hash_verify_store_sqlite.h"
#include "ports/bg_hash_verify_store_port.h"
#include "supervisors/domains.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "event/event.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "util/log_macros.h"
#include "util/result.h"
#include "util/supervisor.h"
#include "util/thread_qos.h"
#include "util/thread_registry.h"

#define SAVE_INTERVAL 1000
#define LOG_INTERVAL  10000
#define BG_HASH_VERIFY_SUPERVISOR_DEADLINE_SEC 300

struct bg_hash_verification_service *g_bg_hash_verify = NULL;

static _Atomic supervisor_child_id g_bg_hash_supervisor_id =
    SUPERVISOR_INVALID_ID;
static struct liveness_contract g_bg_hash_contract;

static int64_t bg_hash_verify_progress_marker(
    const struct bg_hash_verification_service *svc)
{
    if (!svc)
        return 0;
    return atomic_load(&svc->progress.verified_height);
}

static void bg_hash_verify_supervisor_heartbeat(
    const struct bg_hash_verification_service *svc)
{
    supervisor_child_id id = atomic_load(&g_bg_hash_supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
    supervisor_progress(id, bg_hash_verify_progress_marker(svc));
}

static void bg_hash_verify_supervisor_done(void)
{
    supervisor_child_id id = atomic_load(&g_bg_hash_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_set_deadline(id, 0);
}

static void bg_hash_verify_on_stall(struct liveness_contract *c)
{
    const struct bg_hash_verification_service *svc =
        c ? (const struct bg_hash_verification_service *)c->ctx : NULL;
    const char *reason = c
        ? supervisor_stall_reason_name(
              (enum supervisor_stall_reason)atomic_load(&c->stall_reason))
        : "unknown";
    int verified = svc ? atomic_load(&svc->progress.verified_height) : 0;
    int chain_height = svc ? atomic_load(&svc->progress.chain_height) : 0;
    int mismatches = svc ? atomic_load(&svc->progress.mismatches) : 0;
    int state = svc ? atomic_load(&svc->progress.state) : BG_HASH_VERIFY_IDLE;
    LOG_WARN("bg_hash_verify",
             "[bg-hash-verify] supervisor stall reason=%s verified=%d chain_height=%d mismatches=%d state=%s",
             reason, verified, chain_height, mismatches,
             bg_hash_verify_state_name((enum bg_hash_verify_state)state));
    event_emitf(EV_CHAIN_ADVANCE_DECISION, 0,
                "source=chain.bg_hash_verify decision=worker_stall "
                "reason=%s verified=%d chain_height=%d mismatches=%d state=%s",
                reason, verified, chain_height, mismatches,
                bg_hash_verify_state_name((enum bg_hash_verify_state)state));
}

static struct zcl_result bg_hash_verify_register_supervisor(
    struct bg_hash_verification_service *svc)
{
    if (!supervisor_start())
        return ZCL_ERR(-3, "bg_hash_verify_start: supervisor_start failed");

    supervisor_child_id id = atomic_load(&g_bg_hash_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID) {
        supervisor_set_deadline(id, BG_HASH_VERIFY_SUPERVISOR_DEADLINE_SEC);
        supervisor_progress(id, bg_hash_verify_progress_marker(svc));
        supervisor_tick(id);
        return ZCL_OK;
    }

    liveness_contract_init(&g_bg_hash_contract, "chain.bg_hash_verify");
    atomic_store(&g_bg_hash_contract.period_secs, 0);
    atomic_store(&g_bg_hash_contract.deadline_secs,
                 BG_HASH_VERIFY_SUPERVISOR_DEADLINE_SEC);
    atomic_store(&g_bg_hash_contract.progress_max_quiet_us, 0);
    g_bg_hash_contract.ctx = svc;
    g_bg_hash_contract.on_stall = bg_hash_verify_on_stall;

    supervisor_domains_init();
    id = supervisor_register_in_domain(g_chain_sup, &g_bg_hash_contract);
    if (id == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-4, "bg_hash_verify_start: supervisor_register failed");
    atomic_store(&g_bg_hash_supervisor_id, id);
    supervisor_progress(id, bg_hash_verify_progress_marker(svc));
    supervisor_tick(id);
    return ZCL_OK;
}

/* ── Progress persistence ─────────────────────────────────────── */

static int load_progress(const struct bg_hash_verify_store_port *store)
{
    int val = 0;
    if (store && store->load_progress &&
        store->load_progress(store->self, &val))
        return val;
    return 0;
}

static void save_progress(const struct bg_hash_verify_store_port *store,
                          int height)
{
    if (store && store->save_progress)
        store->save_progress(store->self, height);
}

/* ── State names ──────────────────────────────────────────────── */

const char *bg_hash_verify_state_name(enum bg_hash_verify_state state)
{
    switch (state) {
    case BG_HASH_VERIFY_IDLE:     return "idle";
    case BG_HASH_VERIFY_RUNNING:  return "running";
    case BG_HASH_VERIFY_COMPLETE: return "complete";
    case BG_HASH_VERIFY_FAILED:   return "failed";
    default:                      return "unknown";
    }
}

/* ── Main verification thread ─────────────────────────────────── */

static void *bg_hash_verify_thread(void *arg)
{
    struct bg_hash_verification_service *svc = arg;
    struct main_state *ms = svc->ms;

    /* Genuinely-background bulk walker (historical block hash
     * re-verification from genesis) — never the reducer/net/RPC/tip-follow
     * path. Apply OS QoS armor before any work (lane/os-armor). */
    zcl_thread_qos_background();

    bg_hash_verify_supervisor_heartbeat(svc);

    int start_height = load_progress(&svc->progress_store);
    if (start_height < 1) start_height = 1; /* skip genesis (no block file) */

    zcl_mutex_lock(&ms->cs_main);
    int chain_height = active_chain_height(&ms->chain_active);
    zcl_mutex_unlock(&ms->cs_main);
    atomic_store(&svc->progress.chain_height, chain_height);

    if (start_height > chain_height) {
        atomic_store(&svc->progress.state, BG_HASH_VERIFY_COMPLETE);
        printf("[bg-hash-verify] Already complete (verified to h=%d)\n",
               start_height);
        bg_hash_verify_supervisor_done();
        return NULL;
    }

    printf("[bg-hash-verify] Starting hash verification from h=%d to h=%d\n",
           start_height, chain_height);
    atomic_store(&svc->progress.state, BG_HASH_VERIFY_RUNNING);

    struct timespec ts_start;
    platform_time_monotonic_timespec(&ts_start);

    int verified = 0;
    int mismatches = 0;

    for (int h = start_height; h <= chain_height; h++) {
        if (atomic_load(&svc->stop_requested)) break;

        /* Take cs_main briefly to snapshot block_index fields.
         * Without this lock, active_chain_move_window_tip() can realloc the
         * chain array or swap entries during reorgs, causing SIGSEGV
         * when we read stale/freed pointers. */
        struct disk_block_pos snap_pos;
        struct uint256 snap_hash;
        bool have_data = false;
        disk_block_pos_init(&snap_pos);

        zcl_mutex_lock(&ms->cs_main);
        {
            const struct block_index *pindex =
                active_chain_at(&ms->chain_active, h);
            if (pindex && pindex->phashBlock &&
                (pindex->nStatus & BLOCK_HAVE_DATA)) {
                snap_pos.nFile = pindex->nFile;
                snap_pos.nPos = pindex->nDataPos;
                snap_hash = *pindex->phashBlock;
                have_data = true;
            }
        }
        zcl_mutex_unlock(&ms->cs_main);

        if (!have_data) continue;

        /* Read block from disk (pread — thread-safe, no FILE* cache).
         * All disk I/O happens OUTSIDE cs_main to avoid blocking P2P. */
        struct block blk;
        block_init(&blk);
        if (!read_block_from_disk_pread(&blk, &snap_pos, svc->datadir)) {
            block_free(&blk);
            continue; /* block file may be missing — not a hash error */
        }

        /* Recompute hash from the deserialized header */
        struct uint256 computed;
        block_header_get_hash(&blk.header, &computed);
        block_free(&blk);

        /* Compare against stored hash (snapshot — no lock needed) */
        if (uint256_cmp(&computed, &snap_hash) != 0) {
            char exp[65], got[65];
            uint256_get_hex(&snap_hash, exp);
            uint256_get_hex(&computed, got);
            LOG_WARN("bg", "[bg-hash-verify] MISMATCH at h=%d!\n" "  stored:   %s\n  computed: %s", h, exp, got);
            mismatches++;
            atomic_store(&svc->progress.mismatches, mismatches);
        }

        verified++;
        atomic_store(&svc->progress.verified_height, h);
        bg_hash_verify_supervisor_heartbeat(svc);

        /* Periodic save + log */
        if (h % SAVE_INTERVAL == 0)
            save_progress(&svc->progress_store, h);
        if (h % LOG_INTERVAL == 0) {
            struct timespec now;
            platform_time_monotonic_timespec(&now);
            double elapsed = (now.tv_sec - ts_start.tv_sec) +
                (now.tv_nsec - ts_start.tv_nsec) / 1e9;
            double bps = elapsed > 0 ? verified / elapsed : 0;
            printf("[bg-hash-verify] h=%d/%d (%.0f blocks/s, %d mismatches)\n",
                   h, chain_height, bps, mismatches);
        }

        /* Update chain height periodically (chain may grow) */
        if (h % SAVE_INTERVAL == 0) {
            zcl_mutex_lock(&ms->cs_main);
            int new_tip = active_chain_height(&ms->chain_active);
            zcl_mutex_unlock(&ms->cs_main);
            if (new_tip > chain_height) chain_height = new_tip;
            atomic_store(&svc->progress.chain_height, chain_height);
        }
    }

    /* Final save */
    if (!atomic_load(&svc->stop_requested))
        save_progress(&svc->progress_store, chain_height);

    struct timespec ts_end;
    platform_time_monotonic_timespec(&ts_end);
    double total = (ts_end.tv_sec - ts_start.tv_sec) +
        (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;

    if (mismatches > 0) {
        LOG_WARN("bg", "[bg-hash-verify] FAILED: %d mismatches in %d blocks " "(%.0fs)", mismatches, verified, total);
        atomic_store(&svc->progress.state, BG_HASH_VERIFY_FAILED);
    } else if (!atomic_load(&svc->stop_requested)) {
        printf("[bg-hash-verify] Complete: %d blocks verified, 0 mismatches "
               "(%.0fs)\n", verified, total);
        atomic_store(&svc->progress.state, BG_HASH_VERIFY_COMPLETE);
    }

    bg_hash_verify_supervisor_done();
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────── */

void bg_hash_verify_init(struct bg_hash_verification_service *svc,
                         struct main_state *ms,
                         struct node_db *ndb,
                         const char *datadir,
                         const struct chain_params *params)
{
    memset(svc, 0, sizeof(*svc));
    svc->ms = ms;
    svc->ndb = ndb;
    /* Retain the BYTES, never the caller's pointer: boot resolves the
     * net-specific directory into a stack buffer that is gone by the time the
     * worker thread preads a body (a dangling pointer formatted straight into
     * the blk path, which reads as a missing body rather than as a defect). */
    int datadir_len = datadir
        ? snprintf(svc->datadir_storage, sizeof(svc->datadir_storage),
                   "%s", datadir)
        : -1;
    if (datadir_len > 0 &&
        (size_t)datadir_len < sizeof(svc->datadir_storage)) {
        svc->datadir = svc->datadir_storage;
    } else {
        svc->datadir_storage[0] = '\0';
        svc->datadir = NULL;
        LOG_ERROR("bg",
                  "bg_hash_verify_init: datadir is empty or exceeds %zu bytes",
                  sizeof(svc->datadir_storage) - 1u);
    }
    svc->params = params;
    bg_hash_verify_store_sqlite_bind(ndb, &svc->progress_store);
    atomic_store(&svc->stop_requested, false);
    atomic_store(&svc->progress.state, BG_HASH_VERIFY_IDLE);
}

struct zcl_result bg_hash_verify_start(struct bg_hash_verification_service *svc)
{
    /* No datadir => every pread misses and the walk would report
     * "0 mismatches" over blocks it never read. Refuse instead of publishing
     * that false green (bg_validation_start refuses on the same ground). */
    if (!svc || !svc->ms || !svc->datadir || svc->thread_started)
        return ZCL_ERR(-1,
            "bg_hash_verify_start: null svc=%d ms=%d datadir=%d or already "
            "started=%d",
            !svc, svc ? !svc->ms : 1, svc ? !svc->datadir : 1,
            svc ? svc->thread_started : 0);

    struct zcl_result sup_r = bg_hash_verify_register_supervisor(svc);
    if (!sup_r.ok)
        return sup_r;

    if (thread_registry_spawn("zcl_bg_hash", bg_hash_verify_thread, svc,
                                  &svc->thread) != 0) {
        bg_hash_verify_supervisor_done();
        return ZCL_ERR(-2, "thread_registry_spawn failed");
    }

    svc->thread_started = true;
    g_bg_hash_verify = svc;
    return ZCL_OK;
}

void bg_hash_verify_stop(struct bg_hash_verification_service *svc)
{
    if (!svc || !svc->thread_started) return;
    bg_hash_verify_supervisor_done();
    atomic_store(&svc->stop_requested, true);
    pthread_join(svc->thread, NULL);
    svc->thread_started = false;
#ifdef ZCL_TESTING
    supervisor_child_id id = atomic_exchange(&g_bg_hash_supervisor_id,
                                             SUPERVISOR_INVALID_ID);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_unregister(id);
#endif
}

struct bg_hash_verify_progress bg_hash_verify_get_progress(
    const struct bg_hash_verification_service *svc)
{
    struct bg_hash_verify_progress p;
    p.verified_height = atomic_load(&svc->progress.verified_height);
    p.chain_height = atomic_load(&svc->progress.chain_height);
    p.mismatches = atomic_load(&svc->progress.mismatches);
    p.state = atomic_load(&svc->progress.state);
    return p;
}
