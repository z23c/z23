/* Copyright 2026 Rhett Creighton - Apache License 2.0
// supervisor-ok:bounded-projection-warmup — one-shot thread, joined at shutdown; no resident service
 *
 * Boot projection storage — the event_log + reducer read-model projections.
 *
 * Opens the append-only event log + the per-domain projections (mempool,
 * peers, block_index, znam, wallet, contacts, onion-announcements, hodl-history)
 * during boot and tears them down in reverse on shutdown. The handles live in
 * module-static pointers so they can be freed regardless of singleton state.
 *
 * boot_ensure_event_log / boot_ensure_block_index_projection stay extern —
 * boot.c opens them early (the event-log singleton must be published before the
 * coins read view + the other projections bind; first-opener wins). The
 * canonical UTXO set is the kernel coins store (coins_kv), read live through
 * coins_view_kv — there is no separate event-log-fed UTXO projection.
 */

#include "config/boot_internal.h"
#include "config/boot_fast_restart.h"
#include "platform/file_metadata.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"
#include "storage/progress_store.h"
#include "storage/projection_store.h"
#include "storage/mempool_projection.h"
#include "storage/peers_projection.h"
#include "storage/block_index_projection.h"
#include "storage/znam_projection.h"
#include "storage/wallet_projection.h"
#include "storage/small_projections.h"
#include "storage/topology_store.h"
#include "config/boot_background_workers.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "util/thread_registry.h"
#include "boot_timing_marks_internal.h"
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Event-log publication is needed during replay, but recognizing old coins as
 * self-derived must wait until the pending replay has finished its epilogue. */
static void boot_rebuild_coins_without_pending_replay(void)
{
    sqlite3 *db = progress_store_db();
    if (!db) return;
    struct shielded_replay_session session;
    bool pending = false;
    if (!shielded_history_read_full_replay(db, &session, &pending)) {
        fprintf(stderr, // obs-ok:phase4-storage
                "[phase4] invalid replay session; preserving unstamped coins authority\n");
        return;
    }
    if (!pending) (void)coins_kv_boot_rebuild_if_needed(db);
}

static event_log_t               *g_phase4_event_log = NULL;
static mempool_projection_t      *g_phase4_mempool_projection = NULL;
static peers_projection_t        *g_phase4_peers_projection = NULL;
static block_index_projection_t  *g_phase4_block_index_projection = NULL;
static znam_projection_t         *g_phase4_znam_projection = NULL;
static wallet_projection_t       *g_phase4_wallet_projection = NULL;
static contacts_projection_t     *g_phase4_contacts_projection = NULL;
static onion_ann_projection_t    *g_phase4_onion_ann_projection = NULL;
static hodl_history_projection_t *g_phase4_hodl_history_projection = NULL;

/* Idempotent open of the append-only event_log. boot.c must publish this
 * handle (event_log_set_singleton non-NULL) before it builds the coins_tip
 * read view (coins_view_kv) and before the other per-domain projections bind,
 * which is well before app_init_services runs. So this is hoisted here and
 * called twice: once early from app_init and once from
 * boot_start_projection_storage (the rest of the projection fan-out). The
 * second call is a no-op reuse — first opener wins, one handle, no
 * split-brain. Returns true once the event log is open and published. */
bool boot_ensure_event_log(const char *datadir)
{
    if (g_phase4_event_log) {
        /* The retry the stamp comment below promises. It must run ABOVE the
         * already-open early return: this helper is called twice (boot.c's
         * coins-read-view bind, then the projection fan-out) and the second
         * call is the one that reaches a later-opened progress.kv. Leaving it
         * under the return made "retried on the later fan-out call" a comment
         * the code never executed. */
        boot_rebuild_coins_without_pending_replay();
        return true;
    }
    if (!datadir || !datadir[0])
        return false;

    char event_path[PATH_MAX];
    int ne = snprintf(event_path, sizeof(event_path), "%s/event_log.dat",
                      datadir);
    if (ne <= 0 || (size_t)ne >= sizeof(event_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log path too long\n");
        return false;
    }

    int64_t t_open = boot_clock_ms();
    g_phase4_event_log = event_log_open(event_path);
    if (!g_phase4_event_log) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log unavailable; projections disabled\n");
        return false;
    }
    event_log_set_singleton(g_phase4_event_log);
    int64_t t_rebuild = boot_submark("coins.event_log_open", t_open);

    /* Stamp the coins_kv migration marker on existing forward-built datadirs so
     * the read path is recognised as canonical. No-op before progress.kv opens
     * (retried on the later fan-out call) and on an empty coins_kv, which
     * re-derives from block bodies via the normal fold (pre-1.0: legacy
     * datadirs may re-derive). */
    boot_rebuild_coins_without_pending_replay();
    (void)boot_submark("coins.kv_boot_rebuild", t_rebuild);
    return true;
}

/* Idempotent open of the block_index_projection (the log-derived
 * authoritative source for load_block_index_from_projection). Like
 * boot_ensure_event_log
 * this is hoisted so boot.c can open + publish + catch up the projection
 * BEFORE the block-index load (which optionally rebuilds from it under
 * -rebuildfromlog), well before app_init_services runs. Called twice: once
 * early from boot.c and once (no-op reuse) from boot_start_projection_storage.
 * First opener wins — one handle, no split-brain. Requires the event log
 * to already be published (boot_ensure_event_log first).
 * Returns the published projection or NULL. */
block_index_projection_t *boot_ensure_block_index_projection(const char *datadir)
{
    block_index_projection_t *existing = block_index_projection_singleton();
    if (existing)
        return existing;
    if (!datadir || !datadir[0])
        return NULL;
    if (!g_phase4_event_log)
        return NULL;  /* event log must be published first */

    char bip_path[PATH_MAX];
    int n5 = snprintf(bip_path, sizeof(bip_path),
                      "%s/block_index_projection.db", datadir);
    if (n5 <= 0 || (size_t)n5 >= sizeof(bip_path)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] block_index_projection path too long\n");
        return NULL;
    }
    g_phase4_block_index_projection =
        block_index_projection_open(bip_path, g_phase4_event_log);
    if (!g_phase4_block_index_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] block_index_projection unavailable\n");
        return NULL;
    }
    block_index_projection_set_singleton(g_phase4_block_index_projection);
    (void)block_index_projection_catch_up(g_phase4_block_index_projection);
    return g_phase4_block_index_projection;
}

/* Should THIS boot defer progress.kv's integrity scan to the background?
 *
 * The same answer node.db gives (boot_shutdown_marker_quick_check_probe in
 * boot_shutdown_marker.c:379-411), for the same reason: an EXISTING store
 * with no verified-clean binding is the case where quick_check costs hours
 * of uninterruptible I/O and holds listen/READY hostage, and a fresh or
 * absent file is the case where it costs nothing and the cheap blocking
 * check plus quarantine-rebuild is strictly better. Storage class is NOT
 * part of this decision — exactly as for node.db. The class decides how the
 * background scan is PACED (config/boot_fast_restart.h), not whether the
 * boot thread runs it: no disk is fast enough to justify holding READY. */
static bool boot_projection_defer_quick_check(const char *path)
{
    struct platform_file_metadata metadata;
    return path &&
           platform_file_metadata_read(path, &metadata) ==
               PLATFORM_FILE_METADATA_OK &&
           metadata.size > 0;
}

static void boot_projection_scan_result(bool ok, void *ctx)
{
    (void)ctx;
    projection_store_integrity_scan_result(ok);
}

static void boot_projection_quick_check_now(void)
{
    char path[PROJECTION_STORE_PATH_MAX];
    if (!projection_store_integrity_pending(path, sizeof(path)))
        return;

    struct boot_bg_quick_check_target target;
    memset(&target, 0, sizeof(target));
    int n = snprintf(target.path, sizeof(target.path), "%s", path);
    snprintf(target.label, sizeof(target.label), "progress.kv");
    snprintf(target.kind, sizeof(target.kind),
             "deferred projection scan (no clean-close receipt)");
    target.on_result = boot_projection_scan_result;
    /* A spawn that fails reports NOTHING: the store stays unverified, writes
     * no receipt at close, and the next boot scans again. Claiming either
     * verdict here would be inventing evidence. */
    if (n < 0 || (size_t)n >= sizeof(target.path) ||
        !boot_bg_quick_check_start(&target))
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] projection integrity scan NOT started for %s; it "
                "runs again on the next start\n", path);
}

/* ── Projection warm-up (off the restart critical path) ───────────────────
 *
 * What stays synchronous (consensus / serving inputs, opened by boot.c before
 * the block-index load and merely re-ensured here): the event log and the
 * block_index_projection. Their readers are the block-index loaders, the
 * header-by-hash lookup the reducer and header serving use, the flat-cache
 * bind at shutdown, and event emission from block validation.
 *
 * What moves to one tracked warm-up thread, started right after the network
 * kernel: the second progress.kv handle and the mempool / peers / topology /
 * znam / wallet / contacts / onion / hodl projections. Every reader of those
 * goes through a singleton or projection_store_db() and treats NULL as idle
 * (peer reputation, crawler, explorer RPCs, index services, hodl history). None
 * feeds block validation, the reducer, chain selection, header or block
 * serving, or mempool acceptance (acceptance only appends to the event log,
 * which stays synchronous and is replayed by each projection's catch-up).
 *
 * The RPC_READY_PROJECTION bit stays clear until the thread finishes. */
enum warm_state { WARM_IDLE = 0, WARM_PENDING, WARM_DONE };

static pthread_mutex_t g_warm_mu = PTHREAD_MUTEX_INITIALIZER;
static enum warm_state g_warm_state = WARM_IDLE;   /* under g_warm_mu */
static bool g_warm_qc_wanted = false;              /* under g_warm_mu */
static bool g_warm_thread_started = false;
static pthread_t g_warm_thread;
static atomic_bool g_warm_stop = false;
static size_t g_warm_stage_limit = 0;
static char g_warm_datadir[PATH_MAX];
#ifdef ZCL_TESTING
static atomic_bool g_warm_hold = false;
#endif

static void warm_catch_up_log(const char *name, uint64_t off)
{
    if (off == UINT64_MAX)
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] %s catch_up failed\n", name);
    else
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] %s caught up to offset=%llu\n", name,
                (unsigned long long)off);
}

static bool warm_path(char *out, size_t cap, const char *datadir,
                      const char *file, const char *what)
{
    int n = snprintf(out, cap, "%s/%s", datadir, file);
    if (n > 0 && (size_t)n < cap)
        return true;
    fprintf(stderr,  // obs-ok:phase4-storage
            "[phase4] %s path too long\n", what);
    return false;
}

/* Each stage returns false to end the sequence early (the same points where
 * the old synchronous fan-out returned). */
static bool warm_store_open(const char *datadir)
{
    /* Second handle to the already-open progress.kv for the address_index /
     * txindex / created_outputs co-writers (own connection + tx lock). A
     * fold that finds no handle idles its tick. */
    if (!projection_store_open(datadir))
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] projection_store unavailable; projection folds idle\n");
    return true;
}

static bool warm_mempool(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "mempool_projection.db",
                   "projection storage"))
        return false;
    g_phase4_mempool_projection =
        mempool_projection_open(path, g_phase4_event_log);
    if (!g_phase4_mempool_projection)
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] mempool_projection unavailable; projection disabled\n");
    else
        warm_catch_up_log("mempool_projection",
                          mempool_projection_catch_up(g_phase4_mempool_projection));
    return true;
}

static bool warm_peers(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "peers_projection.db",
                   "projection storage"))
        return false;
    g_phase4_peers_projection =
        peers_projection_open(path, g_phase4_event_log);
    if (!g_phase4_peers_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] peers_projection unavailable; projection disabled\n");
        return false;
    }
    warm_catch_up_log("peers_projection",
                      peers_projection_catch_up(g_phase4_peers_projection));
    return true;
}

/* topology_store: the addr-gossip / crawler-result GRAPH ("who advertises
 * whom"). Its own file, no event log — best-effort. */
static bool warm_topology(const char *datadir)
{
    if (!topology_store_open(datadir))
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] topology_store unavailable; graph disabled\n");
    return true;
}

static bool warm_znam(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "znam_projection.db",
                   "znam_projection"))
        return false;
    g_phase4_znam_projection = znam_projection_open(path, g_phase4_event_log);
    if (!g_phase4_znam_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] znam_projection unavailable; projection disabled\n");
        return false;
    }
    warm_catch_up_log("znam_projection",
                      znam_projection_catch_up(g_phase4_znam_projection));
    return true;
}

/* Wallet-view projection replay. The event-log emitter is set only after the
 * initial replay so boot catch-up cannot race new wallet view events. */
static bool warm_wallet(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "wallet_projection.db",
                   "wallet_projection"))
        return false;
    g_phase4_wallet_projection =
        wallet_projection_open(path, g_phase4_event_log);
    if (!g_phase4_wallet_projection) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] wallet_projection unavailable; projection disabled\n");
        return false;
    }
    warm_catch_up_log("wallet_projection",
                      wallet_projection_catch_up(g_phase4_wallet_projection));
    wallet_projection_set_event_log(g_phase4_event_log);
    return true;
}

static bool warm_contacts(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "contacts_projection.db",
                   "small projections"))
        return true;
    g_phase4_contacts_projection =
        contacts_projection_open(path, g_phase4_event_log);
    if (!g_phase4_contacts_projection)
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] contacts_projection unavailable; projection disabled\n");
    else
        warm_catch_up_log("contacts_projection",
                          contacts_projection_catch_up(g_phase4_contacts_projection));
    return true;
}

static bool warm_onion_ann(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir,
                   "onion_announcements_projection.db", "small projections"))
        return true;
    g_phase4_onion_ann_projection =
        onion_ann_projection_open(path, g_phase4_event_log);
    if (!g_phase4_onion_ann_projection)
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] onion_announcements_projection unavailable; "
                "projection disabled\n");
    else
        warm_catch_up_log("onion_announcements_projection",
                          onion_ann_projection_catch_up(g_phase4_onion_ann_projection));
    return true;
}

static bool warm_hodl_history(const char *datadir)
{
    char path[PATH_MAX];
    if (!warm_path(path, sizeof(path), datadir, "hodl_history_projection.db",
                   "small projections"))
        return true;
    g_phase4_hodl_history_projection =
        hodl_history_projection_open(path, g_phase4_event_log);
    if (!g_phase4_hodl_history_projection)
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] hodl_history_projection unavailable; "
                "projection disabled\n");
    else
        warm_catch_up_log("hodl_history_projection",
                          hodl_history_projection_catch_up(g_phase4_hodl_history_projection));
    return true;
}

struct warm_stage {
    const char *name;
    bool (*run)(const char *datadir);
};

static const struct warm_stage g_warm_stages[] = {
    { "proj.store_open", warm_store_open },
    { "proj.mempool",    warm_mempool },
    { "proj.peers",      warm_peers },
    { "proj.topology",   warm_topology },
    { "proj.znam",       warm_znam },
    { "proj.wallet",     warm_wallet },
    { "proj.contacts",   warm_contacts },
    { "proj.onion_ann",  warm_onion_ann },
    { "proj.hodl",       warm_hodl_history },
};
#define WARM_STAGE_COUNT (sizeof(g_warm_stages) / sizeof(g_warm_stages[0]))
#define WARM_STAGES_BEFORE_BIP 4u /* store_open .. topology */

/* Run the stages in order. false when a stop request interrupted the walk. */
static bool warm_run_stages(const char *datadir)
{
    for (size_t i = 0; i < g_warm_stage_limit; i++) {
        if (atomic_load(&g_warm_stop))
            return false;
        int64_t t = boot_clock_ms();
        bool go = g_warm_stages[i].run(datadir);
        printf("[boot]   %-28s %lldms (background)\n", g_warm_stages[i].name,
               (long long)(boot_clock_ms() - t));
        if (!go)
            break;
    }
    return true;
}

static void warm_finish(bool completed, int64_t t0)
{
    pthread_mutex_lock(&g_warm_mu);
    g_warm_state = WARM_DONE;
    bool qc = g_warm_qc_wanted;
    g_warm_qc_wanted = false;
    if (completed)
        rpc_ready_set(RPC_READY_PROJECTION, true);
    pthread_mutex_unlock(&g_warm_mu);
    if (!completed)
        return;
    printf("[boot] projections ready after %lld ms (background)\n",
           (long long)(boot_clock_ms() - t0));
    /* The deferred scan was requested at READY while we were still opening;
     * it runs now, against an open store, never a NULL one. */
    if (qc)
        boot_projection_quick_check_now();
}

static void *warm_thread_main(void *arg)
{
    (void)arg;
    int64_t t0 = boot_clock_ms();
#ifdef ZCL_TESTING
    while (atomic_load(&g_warm_hold) && !atomic_load(&g_warm_stop))
        platform_sleep_ms(2);
#endif
    bool completed = warm_run_stages(g_warm_datadir);
    warm_finish(completed, t0);
    return NULL;
}

void boot_start_projection_storage(const char *datadir)
{
    if (!datadir || !datadir[0])
        return;

    /* Boot ceremony only: a plain projection_store_open (tests, tools) keeps
     * the synchronous integrity gate it has always had. */
    projection_store_set_quick_check_defer_probe(
        boot_projection_defer_quick_check);

    if (snprintf(g_warm_datadir, sizeof(g_warm_datadir), "%s", datadir) >=
        (int)sizeof(g_warm_datadir)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] projection storage paths too long\n");
        return;
    }
    size_t limit = WARM_STAGE_COUNT;
    /* Consensus / serving inputs stay synchronous, in the old order. */
    if (!boot_ensure_event_log(datadir)) {
        fprintf(stderr,  // obs-ok:phase4-storage
                "[phase4] event log unavailable; projections disabled\n");
        limit = 1;
    } else {
        mempool_projection_set_event_log(g_phase4_event_log);
        peers_projection_set_event_log(g_phase4_event_log);
        znam_projection_set_event_log(g_phase4_event_log);
        contacts_projection_set_event_log(g_phase4_event_log);
        onion_ann_projection_set_event_log(g_phase4_event_log);
        hodl_history_projection_set_event_log(g_phase4_event_log);
        if (!boot_ensure_block_index_projection(datadir)) {
            fprintf(stderr,  // obs-ok:phase4-storage
                    "[phase4] block_index_projection unavailable\n");
            limit = WARM_STAGES_BEFORE_BIP;
        }
    }
    g_warm_stage_limit = limit;
    atomic_store(&g_warm_stop, false);
    pthread_mutex_lock(&g_warm_mu);
    g_warm_state = WARM_PENDING;
    g_warm_qc_wanted = false;
    pthread_mutex_unlock(&g_warm_mu);
}

void boot_start_projection_warmup(void)
{
    pthread_mutex_lock(&g_warm_mu);
    bool pending = g_warm_state == WARM_PENDING && !g_warm_thread_started;
    pthread_mutex_unlock(&g_warm_mu);
    if (!pending)
        return;
    // thread-supervision-ok: one warm-up thread, joined by boot_projection_warmup_stop before any store closes
    if (thread_registry_spawn("zcl_proj_warm", warm_thread_main, NULL,
                              &g_warm_thread) == 0) {
        g_warm_thread_started = true;
        return;
    }
    fprintf(stderr,  // obs-ok:phase4-storage
            "[phase4] projection warm-up thread failed to start; opening "
            "projections inline\n");
    (void)warm_thread_main(NULL);
}

void boot_projection_warmup_stop(void)
{
    atomic_store(&g_warm_stop, true);
    if (!g_warm_thread_started)
        return;
    /* Bounded wait, then a final join: the stores must not close under the
     * thread. The stagewatch deadline is the outer bound. */
    (void)boot_join_thread_bounded(g_warm_thread, "projection warm-up", 30);
    g_warm_thread_started = false;
}

void boot_projection_warmup_publish_rpc(void)
{
    pthread_mutex_lock(&g_warm_mu);
    if (g_warm_state == WARM_PENDING)
        rpc_ready_set(RPC_READY_PROJECTION, false);
    pthread_mutex_unlock(&g_warm_mu);
}

void boot_start_projection_bg_quick_check(void)
{
    pthread_mutex_lock(&g_warm_mu);
    if (g_warm_state == WARM_PENDING) {
        g_warm_qc_wanted = true;
        pthread_mutex_unlock(&g_warm_mu);
        return;
    }
    pthread_mutex_unlock(&g_warm_mu);
    boot_projection_quick_check_now();
}

#ifdef ZCL_TESTING
void boot_projection_warmup_test_hold(bool hold)
{
    atomic_store(&g_warm_hold, hold);
}

bool boot_projection_warmup_test_done(void)
{
    pthread_mutex_lock(&g_warm_mu);
    bool done = g_warm_state == WARM_DONE;
    pthread_mutex_unlock(&g_warm_mu);
    return done;
}
#endif

void boot_stop_projection_storage(void)
{
    /* The warm-up thread opens and folds these stores: it is joined before any
     * of them (or the event log) closes. Idempotent when shutdown already
     * stopped it in worker-drain. */
    int64_t t = boot_clock_ms();
    boot_projection_warmup_stop();
    t = shutdown_submark("stop.warmup_join", t);
    /* Order: detach emitters before closing the projections so no
     * in-flight emit lands on a stale handle. Then close projections
     * before the event log they point to. */
    mempool_projection_set_event_log(NULL);
    peers_projection_set_event_log(NULL);
    wallet_projection_set_event_log(NULL);
    contacts_projection_set_event_log(NULL);
    onion_ann_projection_set_event_log(NULL);
    hodl_history_projection_set_event_log(NULL);
    t = shutdown_submark("stop.detach_emitters", t);
    if (g_phase4_mempool_projection) {
        mempool_projection_close(g_phase4_mempool_projection);
        g_phase4_mempool_projection = NULL;
    }
    t = shutdown_submark("stop.mempool_close", t);
    if (g_phase4_peers_projection) {
        peers_projection_close(g_phase4_peers_projection);
        g_phase4_peers_projection = NULL;
    }
    t = shutdown_submark("stop.peers_close", t);
    znam_projection_set_event_log(NULL);
    if (g_phase4_znam_projection) {
        znam_projection_close(g_phase4_znam_projection);
        g_phase4_znam_projection = NULL;
    }
    t = shutdown_submark("stop.znam_close", t);
    if (g_phase4_wallet_projection) {
        wallet_projection_close(g_phase4_wallet_projection);
        g_phase4_wallet_projection = NULL;
    }
    t = shutdown_submark("stop.wallet_close", t);
    if (g_phase4_contacts_projection) {
        contacts_projection_close(g_phase4_contacts_projection);
        g_phase4_contacts_projection = NULL;
    }
    t = shutdown_submark("stop.contacts_close", t);
    if (g_phase4_onion_ann_projection) {
        onion_ann_projection_close(g_phase4_onion_ann_projection);
        g_phase4_onion_ann_projection = NULL;
    }
    t = shutdown_submark("stop.onion_ann_close", t);
    if (g_phase4_hodl_history_projection) {
        hodl_history_projection_close(g_phase4_hodl_history_projection);
        g_phase4_hodl_history_projection = NULL;
    }
    t = shutdown_submark("stop.hodl_history_close", t);
    topology_store_close();
    t = shutdown_submark("stop.topology_close", t);
    block_index_projection_set_singleton(NULL);
    if (g_phase4_block_index_projection) {
        block_index_projection_close(g_phase4_block_index_projection);
        g_phase4_block_index_projection = NULL;
    }
    t = shutdown_submark("stop.block_index_close", t);
    event_log_set_singleton(NULL);
    if (g_phase4_event_log) {
        event_log_close(g_phase4_event_log);
        g_phase4_event_log = NULL;
    }
    t = shutdown_submark("stop.event_log_close", t);
    /* Close the Wave A2 projection handle to progress.kv (no-op if unopened).
     * progress_store's own close still owns the WAL checkpoint of the file. */
    projection_store_close();
    t = shutdown_submark("stop.projection_store_close", t);
    pthread_mutex_lock(&g_warm_mu);
    g_warm_state = WARM_IDLE;
    g_warm_qc_wanted = false;
    pthread_mutex_unlock(&g_warm_mu);
}
