/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_bundle_install_ready — see conditions/checkpoint_bundle_install_ready.h.
 *
 * This condition NEVER installs in-process: the atomic consensus-state installer
 * (consensus_state_snapshot_install_activate) resets the reducer's stage cursors
 * and tip_finalize log and must run single-threaded at boot, not concurrently
 * with the live reducer. So the remedy ARMS the durable install-on-next-boot
 * request and pulls the supervised-respawn trigger — byte-for-byte the shielded
 * ladder's Rung B pattern (shielded_selfheal_ladder.c) — and the install runs at
 * the next boot's app_init, where the header chain is durably at the checkpoint.
 * CONSENSUS PARITY: nothing here relaxes a check; it only re-times the EXISTING
 * ROM/PoW-gated installer to fire once the header chain genuinely owns the
 * compiled checkpoint block. */

#include "framework/condition.h"

#include "conditions/checkpoint_bundle_install_ready.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "chain/chain.h"                              /* block_index_get_ancestor */
#include "chain/checkpoints.h"                        /* get_sha3_utxo_checkpoint */
#include "conditions/checkpoint_header_solution_repair.h" /* solution-available gate */
#include "config/consensus_state_install_runtime.h"   /* autodetect + arm + ready predicate */
#include "config/boot_consensus_bundle_marker.h"      /* sovereign-marker witness */
#include "config/flysync_island.h"                    /* the island window verifier */
#include "controllers/agent_controller.h"             /* agent_runtime_context_datadir */
#include "event/event.h"
#include "jobs/stage_repair.h"                         /* header_solution_repair save */
#include "net/checkpoint_header_fetch.h"               /* window walk */
#include "platform/time_compat.h"
#include "primitives/block.h"
#include "services/chain_tip_watchdog.h"               /* chain_tip_watchdog_request_respawn */
#include "services/island_anchor.h"
#include "services/sync_monitor.h"                     /* sync_monitor_main_state */
#include "storage/node_db_runtime.h"                   /* the pending restore's header loader */
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"                      /* thread_registry_request_shutdown */
#include "validation/main_state.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBIR_SUBSYS "condition"
#define CBIR_NAME   "checkpoint_bundle_install_ready"
#define CBIR_WINDOW_BLOCKER_ID "checkpoint_rung_window_pending"
#define CBIR_WINDOW_STALL_MS INT64_C(120000)
#define CBIR_WINDOW_REFUSALS_MAX 3

#ifdef ZCL_TESTING
static _Atomic(struct main_state *) g_test_ms;
static const char *g_test_datadir;
static _Atomic bool g_test_suppress_restart;
static _Atomic int g_test_remedy_calls;
#endif

static struct main_state *cbir_main_state(void)
{
#ifdef ZCL_TESTING
    struct main_state *t = atomic_load(&g_test_ms);
    if (t)
        return t;
#endif
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        ms = condition_engine_main_state();
    return ms;
}

static const char *cbir_datadir(void)
{
#ifdef ZCL_TESTING
    if (g_test_datadir && g_test_datadir[0])
        return g_test_datadir;
#endif
    return agent_runtime_context_datadir();
}

static bool detect_checkpoint_bundle_install_ready(void)
{
    struct main_state *ms = cbir_main_state();
    const char *datadir = cbir_datadir();
    if (!ms || !datadir || !datadir[0])
        return false;

    /* Tip position does NOT gate the arm. A fresh instant-on node is BELOW the
     * checkpoint; the live-cure node sits ABOVE it on BORROWED shielded state and
     * still needs the bundle install to close its anchor/nullifier gap. The
     * staged-bundle predicate below (autodetect != NULL, which returns NULL once
     * the sovereign marker exists) is the real scope — a healthy sovereign node
     * short-circuits there and never arms. */
    /* A staged, installable bundle must still be present. autodetect returns
     * NULL once the sovereign marker exists (installed), when no installable
     * bundle is present under bundles/, or when every candidate carries a
     * .failed sibling. Side-effect free (pure discovery). The staged bundle's
     * baked height (keystone or ladder rung) decides which header + solution the
     * install waits on; a bundle at no baked height waits on the compiled
     * checkpoint exactly as before. */
    char *bundle = boot_autodetect_consensus_bundle(datadir);
    if (!bundle)
        return false;
    int32_t target_h = 0;
    uint8_t target_hash[32];
    bool have_target = boot_staged_bundle_wait_target(bundle, &target_h,
                                                      target_hash);
    free(bundle);
    if (!have_target)
        return false; // raw-return-ok:no-compiled-checkpoint

    /* The header chain must genuinely own the baked block before the install can
     * bind — the exact precondition the boot-time deferral waits on. */
    if (!consensus_state_install_header_ready_for(ms, target_h, target_hash))
        return false; // raw-return-ok:detect-poll-headers-not-yet-at-checkpoint-is-normal

    /* The header's Equihash solution must be durably available so the install
     * can actually bind. On a headers-first substrate the solution is absent
     * until checkpoint_header_solution_repair peer-fetches + persists it; arming
     * the install-on-next-boot before then would only burn the bounded install
     * budget (BOOT_INSTALL_BUNDLE_MAX) on a solutionless retriable defer. Wait
     * for the sibling repair to land it first. */
    {
        struct uint256 cp_hash;
        memcpy(cp_hash.data, target_hash, 32);
        if (!checkpoint_header_solution_available(target_h, &cp_hash))
            return false; // raw-return-ok:checkpoint-header-solution-not-yet-backfilled
    }
    return true;
}

/* ── Rung header window (legacy rung install only) ──────────────────────────
 * The pending boot after a legacy install at a baked rung rebuilds its index
 * from the projection only and proves the coins tip through an in-memory
 * island (engine/composition/src/boot_pending_island.c). That boot does no
 * network fetch, so the 28 full headers rung-27..rung must be durable before
 * the install is armed. They load through the same loader the pending restore
 * uses; when they do not, the existing window walk fetches them, each must hash
 * to this node's own header chain, the island window verifier proves them
 * (hash links down from the compiled rung hash, frozen PoW + Equihash), and
 * each is saved in the existing hash-bound header_solution_repair table. */
enum cbir_window { CBIR_WINDOW_NOT_APPLICABLE, CBIR_WINDOW_READY, CBIR_WINDOW_WAIT,
                   CBIR_WINDOW_REFUSED };

static _Atomic int64_t g_window_armed_ms;   /* 0: this condition holds no walk */
static _Atomic int64_t g_window_moved_ms;
static _Atomic int g_window_seen;
static _Atomic int g_window_baseline;       /* progressing() delta baseline */
static _Atomic int g_window_refusals;

/* The compiled ladder rung at the staged bundle's height, strictly above the
 * keystone, at exactly the bundle's hash. */
static const struct rom_state_rung *cbir_rung(int32_t height, const uint8_t hash[32])
{
    const struct rom_state_checkpoint *keystone = get_rom_state_checkpoint();
    if (!keystone || height <= keystone->height)
        return NULL;
    for (size_t i = 0; i < get_rom_state_rung_count(); i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height == height)
            return memcmp(r->cp.block_hash, hash, 32) == 0 ? r : NULL;
    }
    return NULL;
}

/* -flysync and every datadir holding an island fact keep their own route. */
static bool cbir_window_route(void)
{
    return flysync_island_phase() == FLYSYNC_OFF && !flysync_island_requested() &&
           !island_anchor_registered() &&
           island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_NONE;
}

/* This node's own header chain at rung..rung-27, top first. The rung row's
 * chainwork must equal the compiled rung chainwork the island root work is
 * derived from (T2); a mismatch is a hard refusal. */
static enum cbir_window cbir_own_window(struct main_state *ms,
                                        const struct rom_state_rung *rung,
                                        struct uint256 *own)
{
    int32_t rung_h = rung->cp.height;
    struct block_index *best = ms->pindex_best_header;
    struct block_index *p = best && best->nHeight >= rung_h ?
        block_index_get_ancestor(best, (int)rung_h) : NULL;
    if (!p || !p->phashBlock || memcmp(p->phashBlock->data, rung->cp.block_hash, 32) != 0)
        return CBIR_WINDOW_WAIT;
    struct arith_uint256 want;
    island_anchor_work_from_be(&want, rung->chainwork);
    if (arith_uint256_compare(&p->nChainWork, &want) != 0) {
        char have_hex[65], want_hex[65];
        arith_uint256_get_hex(&p->nChainWork, have_hex);
        arith_uint256_get_hex(&want, want_hex);
        LOG_ERROR(CBIR_SUBSYS, "[condition:%s] REFUSED: this node's header chainwork at rung h=%d "
                  "is %s but the compiled rung chainwork is %s; the rung window is not staged and "
                  "the install is not armed", CBIR_NAME, (int)rung_h, have_hex, want_hex);
        return CBIR_WINDOW_REFUSED;
    }
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW; i++, p = p->pprev) {
        if (!p || !p->phashBlock || p->nHeight != rung_h - i)
            return CBIR_WINDOW_WAIT;
        own[i] = *p->phashBlock;
    }
    return CBIR_WINDOW_READY;
}

/* All 28 durable through the pending restore's loader, then proven again. */
static bool cbir_window_durable(int32_t rung_h, const struct uint256 *own, struct block_header *w)
{
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW; i++)
        if (!node_db_runtime_load_header_by_hash_height(rung_h - i, own[i].data, &w[i]))
            return false; // raw-return-ok:window-not-yet-staged-is-the-normal-wait
    struct island_anchor a;
    char why[192];
    if (flysync_island_verify_window(w, ISLAND_ANCHOR_WINDOW, rung_h, &a, why, sizeof(why)))
        return true;
    LOG_ERROR(CBIR_SUBSYS, "[condition:%s] stored rung window h=%d does not verify: %s",
              CBIR_NAME, (int)rung_h, why);
    return false;
}

static bool cbir_window_matches_own(const struct block_header *w, const struct uint256 *own)
{
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW; i++) {
        struct uint256 hash;
        block_header_get_hash(&w[i], &hash);
        if (!uint256_eq(&hash, &own[i]))
            return false; // raw-return-ok:caller-logs-the-refused-window
    }
    return true;
}

/* Fetched bytes are untrusted until the verifier passes; nothing is saved
 * before it does. */
static bool cbir_window_stage(const struct block_header *w, int n, int32_t top,
                              int32_t rung_h, const struct uint256 *own)
{
    struct island_anchor a;
    char why[192] = "the window is not 28 headers at the rung or differs from this node's "
                    "own header chain";
    bool ok = n == ISLAND_ANCHOR_WINDOW && top == rung_h && cbir_window_matches_own(w, own) &&
              flysync_island_verify_window(w, n, rung_h, &a, why, sizeof(why));
    sqlite3 *db = ok ? progress_store_db() : NULL;
    for (int i = 0; ok && i < n; i++)
        ok = db && stage_repair_header_solution_save(db, rung_h - i, &own[i], &w[i]);
    if (!ok) {
        atomic_fetch_add(&g_window_refusals, 1);
        LOG_WARN(CBIR_SUBSYS, "[condition:%s] fetched rung window h=%d not staged: %s; "
                 "fetching again", CBIR_NAME, (int)rung_h, why);
        return false;
    }
    LOG_INFO(CBIR_SUBSYS, "[condition:%s] rung window h=%d..%d verified (hash-linked from the "
             "compiled rung, frozen PoW/Equihash) and staged in header_solution_repair",
             CBIR_NAME, (int)(rung_h - (n - 1)), (int)rung_h);
    return true;
}

static void cbir_window_take(int32_t rung_h, const struct uint256 *own)
{
    struct block_header *w = zcl_calloc(CHECKPOINT_HEADER_FETCH_WINDOW_MAX, sizeof(*w),
                                        "rung window take");
    if (!w) {
        LOG_WARN(CBIR_SUBSYS, "[condition:%s] rung window buffer allocation failed", CBIR_NAME);
        return;
    }
    int32_t top = -1;
    int n = checkpoint_header_fetch_take_window(w, CHECKPOINT_HEADER_FETCH_WINDOW_MAX, &top);
    if (n > 0) {
        atomic_store(&g_window_armed_ms, 0);
        (void)cbir_window_stage(w, n, top, rung_h, own);
    }
    free(w);
}

/* Arm the walk when this condition holds none or it stalled. The single-header
 * repair has finished: detect requires the rung solution to be durable. */
static void cbir_window_arm_if_stalled(const struct rom_state_rung *rung)
{
    int64_t now = platform_time_monotonic_ms();
    int have = checkpoint_header_fetch_window_progress();
    if (have != atomic_load(&g_window_seen)) {
        atomic_store(&g_window_seen, have);
        atomic_store(&g_window_moved_ms, now);
    }
    if (atomic_load(&g_window_armed_ms) != 0 && checkpoint_header_fetch_is_armed() &&
        now - atomic_load(&g_window_moved_ms) < CBIR_WINDOW_STALL_MS)
        return;
    struct uint256 top;
    memcpy(top.data, rung->cp.block_hash, 32);
    checkpoint_header_fetch_arm_window(rung->cp.height, &top, ISLAND_ANCHOR_WINDOW);
    atomic_store(&g_window_armed_ms, now);
    atomic_store(&g_window_moved_ms, now);
    atomic_store(&g_window_seen, 0);
}

static void cbir_window_blocker(int32_t rung_h)
{
    struct blocker_record r;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason), "the checkpoint-bundle install at rung h=%d waits for the 28 "
             "full headers h=%d..%d from peers; the node keeps syncing meanwhile",
             (int)rung_h, (int)(rung_h - (ISLAND_ANCHOR_WINDOW - 1)), (int)rung_h);
    if (blocker_init(&r, CBIR_WINDOW_BLOCKER_ID, "checkpoint_fetch", BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&r);
}

/* Durable already, or durable after staging a completed walk; else (re)arm. */
static enum cbir_window cbir_window_load_or_fetch(const struct rom_state_rung *rung,
                                                  const struct uint256 *own)
{
    int32_t rung_h = rung->cp.height;
    struct block_header *w = zcl_calloc(ISLAND_ANCHOR_WINDOW, sizeof(*w), "rung window load");
    if (!w) {
        LOG_WARN(CBIR_SUBSYS, "[condition:%s] rung window buffer allocation failed", CBIR_NAME);
        return CBIR_WINDOW_WAIT;
    }
    bool durable = cbir_window_durable(rung_h, own, w);
    if (!durable) {
        cbir_window_take(rung_h, own);
        durable = cbir_window_durable(rung_h, own, w);
    }
    free(w);
    if (durable)
        return CBIR_WINDOW_READY;
    cbir_window_arm_if_stalled(rung);
    return CBIR_WINDOW_WAIT;
}

static enum cbir_window cbir_window_ready(struct main_state *ms, int32_t target_h,
                                          const uint8_t target_hash[32])
{
    const struct rom_state_rung *rung = cbir_rung(target_h, target_hash);
    if (!rung || !cbir_window_route())
        return CBIR_WINDOW_NOT_APPLICABLE;
    struct uint256 own[ISLAND_ANCHOR_WINDOW];
    enum cbir_window state = cbir_own_window(ms, rung, own);
    if (state == CBIR_WINDOW_READY)
        state = cbir_window_load_or_fetch(rung, own);
    if (state == CBIR_WINDOW_WAIT) {
        cbir_window_blocker(target_h);
    } else {
        /* No longer waiting on a walk: progressing() stops vouching for it,
         * so READY and REFUSED rounds count toward the budget as before. */
        atomic_store(&g_window_armed_ms, 0);
        blocker_clear(CBIR_WINDOW_BLOCKER_ID);
    }
    return state;
}

static enum condition_remedy_result remedy_checkpoint_bundle_install_ready(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&g_test_remedy_calls, 1);
#endif
    struct main_state *ms = cbir_main_state();
    const char *datadir = cbir_datadir();
    if (!ms || !datadir || !datadir[0])
        return COND_REMEDY_SKIP; // raw-return-ok:runtime-not-wired-this-tick

    /* Re-confirm at remedy time: never respawn to install a bundle whose
     * baked header (keystone or ladder rung of the staged bundle) is not (still)
     * genuinely on-chain with its solution durable. */
    char *bundle = boot_autodetect_consensus_bundle(datadir);
    if (!bundle)
        return COND_REMEDY_SKIP; // raw-return-ok:installed/failed-between-detect-and-remedy
    int32_t target_h = 0;
    uint8_t target_hash[32];
    if (!boot_staged_bundle_wait_target(bundle, &target_h, target_hash) ||
        !consensus_state_install_header_ready_for(ms, target_h, target_hash)) {
        free(bundle);
        return COND_REMEDY_SKIP; // raw-return-ok:precondition-regressed-this-tick
    }
    {
        struct uint256 cp_hash;
        memcpy(cp_hash.data, target_hash, 32);
        if (!checkpoint_header_solution_available(target_h, &cp_hash)) {
            free(bundle);
            return COND_REMEDY_SKIP; // raw-return-ok:solution-not-yet-backfilled-do-not-burn-budget
        }
    }
    /* A legacy install at a baked rung arms only once its header window is
     * durable: the pending boot after it does no network fetch. */
    enum cbir_window window = cbir_window_ready(ms, target_h, target_hash);
    if (window == CBIR_WINDOW_WAIT || window == CBIR_WINDOW_REFUSED) {
        free(bundle);
        return window == CBIR_WINDOW_WAIT ? COND_REMEDY_SKIP : COND_REMEDY_FAILED;
    }
    /* Arm the durable, bounded install-on-next-boot request. Idempotent while
     * pending (the attempt count only bumps at CONSUME/boot), so repeated ticks
     * never inflate the budget; a spent budget returns TERMINAL. */
    int armed = boot_install_bundle_request(datadir, bundle);
    if (armed == BOOT_INSTALL_BUNDLE_TERMINAL) {
        LOG_WARN(CBIR_SUBSYS,
                 "[condition:%s] install-on-next-boot budget exhausted for %s — "
                 "NOT respawning (operator paged); a genuinely uninstallable "
                 "bundle degrades to normal sync", CBIR_NAME, bundle);
        free(bundle);
        return COND_REMEDY_FAILED;
    }
    if (armed <= 0) {
        LOG_WARN(CBIR_SUBSYS,
                 "[condition:%s] could not arm install-on-next-boot for %s",
                 CBIR_NAME, bundle);
        free(bundle);
        return COND_REMEDY_FAILED;
    }

    LOG_WARN(CBIR_SUBSYS,
             "[condition:%s] header chain reached the checkpoint (h=%d) — ARMED "
             "checkpoint-bundle install-on-next-boot of %s (attempt %d); "
             "requesting a supervised respawn so the atomic ROM/PoW-gated "
             "installer runs at the next single-threaded boot",
             CBIR_NAME, (int)target_h, bundle, armed);
    event_emitf(EV_RECOVERY_ACTION, 0,
                "action=checkpoint_bundle_install_armed height=%d attempt=%d",
                (int)target_h, armed);
    free(bundle);

#ifdef ZCL_TESTING
    if (!atomic_load(&g_test_suppress_restart))
#endif
    {
        chain_tip_watchdog_request_respawn();
        thread_registry_request_shutdown();
    }
    return COND_REMEDY_OK;
}

static bool witness_checkpoint_bundle_install_ready(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* The install runs on the NEXT boot and writes the sovereign consensus-bundle
     * marker (consensus_state_install_runtime.c). That marker's existence is the
     * honest OBSERVABLE clear for BOTH cases: the fresh instant-on node (which
     * also climbs H* onto the bundle) AND the live-cure node already ABOVE the
     * checkpoint on borrowed state — where a `provable_tip >= checkpoint` witness
     * would be TRIVIALLY TRUE and clear the episode before the remedy ever armed
     * (condition.c checks the witness before running the remedy). Pre-respawn
     * (this process) the marker does not exist yet, so the arm-and-respawn remedy
     * is correctly unwitnessed; the reboot's install writes it. */
    const char *datadir = cbir_datadir();
    // honest-witness-ok: NOT poison-absence and NOT this condition's own FSM flag.
    // The sovereign consensus-bundle marker is a DURABLE artifact written by a
    // DIFFERENT subsystem — the atomic installer (consensus_state_install_runtime),
    // and only AFTER it commits self-verified state — so a node whose install
    // never ran cannot have it (correctly stays unwitnessed). It is the exact
    // forward fact this remedy's arm-and-respawn produces, observable across the
    // reboot, and unlike a tip-height witness it is honest for the live-cure node
    // that already sits above the checkpoint before the install.
    return datadir && datadir[0] &&
           boot_consensus_bundle_marker_exists(datadir);
}

/* A completed rung window walk waits to be verified and staged: consume it on
 * the next tick (cheap atomic read; the remedy re-verifies). */
static bool urgent_checkpoint_bundle_install_ready(void)
{
    return checkpoint_header_fetch_window_progress() >= ISLAND_ANCHOR_WINDOW;
}

/* The rung window walk advanced since the last round, or this condition holds
 * a walk it armed and still waits on (re-armed when it stalls): keep the
 * bounded attempt budget from latching a walk that is converging. A slow first
 * reply must not latch it (measured: the third skipped round latched 66 s after
 * the walk armed; the walk completed 30 s later). A walk whose fetched windows
 * keep failing verification stops counting as progress, so the budget latches
 * after CBIR_WINDOW_REFUSALS_MAX refused windows. The node keeps syncing while
 * it waits; nothing restarts. */
static bool progressing_checkpoint_bundle_install_ready(int64_t target_at_detect)
{
    (void)target_at_detect;
    int have = checkpoint_header_fetch_window_progress();
    int before = atomic_exchange(&g_window_baseline, have);
    return atomic_load(&g_window_refusals) < CBIR_WINDOW_REFUSALS_MAX &&
           (have > before || atomic_load(&g_window_armed_ms) != 0);
}

static struct condition c_checkpoint_bundle_install_ready = {
    .name = CBIR_NAME,
    .severity = COND_WARN,
    .poll_secs = 5,
    .backoff_secs = 30,
    .max_attempts = 3,
    .detect = detect_checkpoint_bundle_install_ready,
    .remedy = remedy_checkpoint_bundle_install_ready,
    .witness = witness_checkpoint_bundle_install_ready,
    .progressing = progressing_checkpoint_bundle_install_ready,
    .urgent = urgent_checkpoint_bundle_install_ready,
    .witness_window_secs = 30,
};

void register_checkpoint_bundle_install_ready(void)
{
    (void)condition_register(&c_checkpoint_bundle_install_ready);
}

#ifdef ZCL_TESTING
void checkpoint_bundle_install_ready_test_reset(void)
{
    atomic_store(&g_test_ms, NULL);
    g_test_datadir = NULL;
    atomic_store(&g_test_suppress_restart, false);
    atomic_store(&g_test_remedy_calls, 0);
    atomic_store(&g_window_armed_ms, 0);
    atomic_store(&g_window_moved_ms, 0);
    atomic_store(&g_window_seen, 0);
    atomic_store(&g_window_baseline, 0);
    atomic_store(&g_window_refusals, 0);
    blocker_clear(CBIR_WINDOW_BLOCKER_ID);
    condition_reset_state(&c_checkpoint_bundle_install_ready);
}

void checkpoint_bundle_install_ready_test_set_main_state(struct main_state *ms)
{
    atomic_store(&g_test_ms, ms);
}

void checkpoint_bundle_install_ready_test_set_datadir(const char *datadir)
{
    g_test_datadir = datadir;
}

void checkpoint_bundle_install_ready_test_suppress_restart(bool suppress)
{
    atomic_store(&g_test_suppress_restart, suppress);
}

int checkpoint_bundle_install_ready_test_remedy_calls(void)
{
    return atomic_load(&g_test_remedy_calls);
}

bool checkpoint_bundle_install_ready_test_detect(void)
{
    return detect_checkpoint_bundle_install_ready();
}

int checkpoint_bundle_install_ready_test_remedy(void)
{
    return (int)remedy_checkpoint_bundle_install_ready();
}

bool checkpoint_bundle_install_ready_test_progressing(void)
{
    return progressing_checkpoint_bundle_install_ready(0);
}
#endif
