/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle_exporter — the STANDING live consensus-state bundle exporter (lane C1
 * of the Instant-Sync program). See config/include/config/bundle_exporter.h for
 * the contract and the precise provenance claim this proves.
 *
 * Structure mirrors app/services/src/wallet_backup_service.c: a dedicated worker
 * pthread runs the heavy job (the export walks millions of rows, so it must NOT
 * run on the supervisor's on_tick thread), and a supervised liveness_contract
 * heartbeats via supervisor_tick from the worker loop. The contract uses
 * period_secs=0 / deadline_secs=0 / progress_max_quiet_us=0: best-effort, no
 * stall — a degraded exporter is a named dumpstate degradation, never a boot
 * blocker.
 *
 * FAIL-SAFE: bundle_exporter_start NEVER returns false for a qualification or
 * producer-session failure; it records a dumpstate-visible degradation reason
 * and still arms the worker. It returns false only on a hard wiring error (NULL
 * progress handle / datadir), which the boot caller ignores anyway.
 */
#include "config/bundle_exporter.h"
#include "config/consensus_state_producer_receipt.h"
#include "config/consensus_state_snapshot_export.h"
#include "config/consensus_state_bundle_validate.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/coins_ram.h"
#include "storage/consensus_state_bundle_codec.h"
#include "net/rom_seed.h"   /* reseed the produced bundle so it serves now */
#include "jobs/tip_finalize_stage.h"
#include "services/sync_trust_policy.h"
#include "services/node_health_service.h"
#include "kernel/service_kernel.h"
#include "util/blocker.h"
#include "util/supervisor.h"
#include "supervisors/domains.h"
#include "util/thread_registry.h"
#include "util/clientversion.h"
#include "util/log_macros.h"
#include "json/json.h"
#include "core/utiltime.h"
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
/* Native Windows export/retention stays fail-closed until the snapshot writer,
 * durable installation, and pruning transaction have passed the Windows
 * private-directory and atomic-file acceptance suite.  These exported gates
 * execute before any pathname is opened or created. */
bool bundle_exporter_start(sqlite3 *pdb, const char *datadir)
{
    (void)pdb;
    (void)datadir;
    return false;
}
void bundle_exporter_stop(void) {}
bool bundle_exporter_register_service(struct zcl_service_kernel *kernel,
                                      const char *datadir)
{
    (void)kernel;
    (void)datadir;
    return false;
}
bool bundle_exporter_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_bool(out, "session_open", false);
    json_push_kv_bool(out, "qualified", false);
    json_push_kv_str(out, "degradation_reason",
                     "native Windows bundle export is security-refused");
    json_push_kv_str(out, "last_refusal",
                     "windows_export_retention_not_qualified");
    return true;
}
#ifdef ZCL_TESTING
bool bundle_exporter_source_identity_is_exact_for_test(const char *source_id)
{
    if (!source_id || strlen(source_id) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!((source_id[i] >= '0' && source_id[i] <= '9') ||
              (source_id[i] >= 'a' && source_id[i] <= 'f')))
            return false;
    return true;
}
bool bundle_exporter_at_tip_ok_for_test(bool synced, int log_head_gap,
                                        int64_t max_tip_gap)
{
    return synced || (log_head_gap >= 0 &&
                      (int64_t)log_head_gap <= max_tip_gap);
}
bool bundle_exporter_export_due_for_test(
    int64_t h, int64_t last_h, int64_t elapsed_secs, int64_t every_blocks,
    int64_t every_secs, int64_t min_secs)
{
    return h > last_h && elapsed_secs >= min_secs &&
           ((h - last_h) >= every_blocks || elapsed_secs >= every_secs);
}
void bundle_exporter_rotate_for_test(const char *dir, int keep,
                                     const char *datadir)
{
    (void)dir;
    (void)keep;
    (void)datadir;
}
void bundle_exporter_set_rotate_skip_validate_for_test(bool on) { (void)on; }
#endif
#else
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "bundle_exporter_generations_internal.h"
/* ── Module state ───────────────────────────────────────────────── */
static struct {
    pthread_mutex_t lock;
    sqlite3 *pdb;                 /* owned progress.kv handle (borrowed) */
    char     datadir[1024];
    char     bundles_dir[1100];   /* "<datadir>/bundles" */
    bool     session_open;        /* producer receipt session is held open */
    bool     qualified;           /* provenance qualified at start */
    char     degradation_reason[256];
    char     last_refusal[256];
    int64_t  every_blocks;        /* ZCL_BUNDLE_EXPORT_EVERY_BLOCKS (>=1) */
    int64_t  every_secs;          /* ZCL_BUNDLE_EXPORT_EVERY_SECS ceiling  */
    int64_t  min_secs;            /* ZCL_BUNDLE_EXPORT_MIN_SECS floor      */
    int64_t  max_tip_gap;         /* ZCL_BUNDLE_EXPORT_MAX_TIP_GAP at-tip  */
    int      keep;                /* ZCL_BUNDLE_EXPORT_KEEP (>=1) */
    int64_t  tick_secs;           /* ZCL_BUNDLE_EXPORT_TICK_SECS worker poll */
    pthread_t worker;
    bool      worker_running;     /* true iff `worker` is joinable */
} g_bx = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};
static _Atomic int32_t g_bx_last_export_height   = -1;
static _Atomic int64_t g_bx_last_export_time_us  = 0;
static _Atomic int64_t g_bx_last_export_duration_us = 0;
static _Atomic int64_t g_bx_exports_ok           = 0;
static _Atomic int64_t g_bx_exports_failed       = 0;
static atomic_bool g_bx_running = false;
static _Atomic supervisor_child_id g_bx_supervisor_id = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_bx_contract;
/* ── Small helpers ──────────────────────────────────────────────── */
static void bx_note_refusal(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&g_bx.lock);
    snprintf(g_bx.last_refusal, sizeof g_bx.last_refusal, "%s", buf);
    pthread_mutex_unlock(&g_bx.lock);
}
/* A degraded exporter is a SILENT production outage, and that is the whole
 * reason this exists. Qualification and the producer session are decided ONCE,
 * in bundle_exporter_start; nothing re-runs them in-process. So a node that
 * comes up degraded logs one WARN at boot and then ticks forever, exporting
 * nothing, while `dumpstate bundle_exporter` reports exports_ok=0 AND
 * exports_failed=0 — the shape of a node that is working fine, not one that
 * stopped a month ago. Measured on the canonical node 2026-08-19: the last
 * mint was 2026-07-24, 165,288 blocks behind its own tip, because a binary
 * upgrade left the stored producer session foreign to the running build. The
 * refusal was correct; the silence was not. Every cold-starting peer inherits
 * that staleness as crawl time, so the outage is named here with the numbers
 * that make it actionable.
 *
 * BLOCKER_DEPENDENCY: the gates never re-run, so nothing in this process can
 * clear it and dependency blockers never TTL-retire. The optional exporter
 * must not hard-gate validation, relay, or serving. Re-mint only after an
 * operator restarts the node on a matching build. */
static void bx_name_degraded(const char *degradation)
{
    int32_t last_h = atomic_load(&g_bx_last_export_height);
    int64_t last_us = atomic_load(&g_bx_last_export_time_us);
    int64_t age_secs = last_us > 0 ? (GetTimeMicros() - last_us) / 1000000 : -1;
    /* blocker_init applies the shared visible-cut policy to this full reason. */
    char reason[512];
    if (last_h >= 0 && age_secs >= 0)
        snprintf(reason, sizeof reason,
                 "no consensus-state bundle minted for %lld day(s) (newest is "
                 "h=%d): %.110s — cold-starting peers must crawl block bodies "
                 "from h=%d, and no in-process retry exists",
                 (long long)(age_secs / 86400), last_h, degradation, last_h);
    else
        snprintf(reason, sizeof reason,
                 "no consensus-state bundle has ever been minted here: "
                 "%.110s — cold-starting peers get no state source from this "
                 "node, and no in-process retry exists", degradation);
    struct blocker_record b;
    if (blocker_init(&b, "bundle_exporter.degraded", "bundle_exporter",
                     BLOCKER_DEPENDENCY, reason))
        (void)blocker_set(&b);
}
static int64_t bx_env_i64(const char *name, int64_t dflt)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return dflt;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(v, &end, 10);
    if (errno != 0 || end == v || (end && *end))
        return dflt;
    return (int64_t)parsed;
}
/* True iff `s` is the exact lowercase SHA-256 source identity baked by the
 * canonical build. Git object IDs intentionally stay outside the sovereign
 * executable (clientversion.c); producer receipts bind this same 32-byte
 * source identity, so the exporter must gate on it rather than on the legacy
 * external-only Git trace string. */
static bool bx_is_exact_source_id(const char *s)
{
    if (!s)
        return false;
    size_t n = strlen(s);
    if (n != 64)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}
/* The qualification gate — ALL must hold or the producer session stays closed
 * and `reason` names the first failing rung. The coins predicates read the
 * shared singleton progress.kv handle, which is only safe under
 * progress_store_tx_lock (SQLite statements on one connection must be
 * serialized across threads; coins_kv_is_proven_authority does NOT self-lock).
 * The lock is recursive, so coins_kv_contains_refold_marker's internal acquire
 * nests cleanly. Callers must NOT hold g_bx.lock here — this module keeps
 * g_bx.lock and progress_store_tx_lock strictly disjoint. */
static bool bx_qualified(sqlite3 *pdb, char *reason, size_t cap)
{
    if (coins_ram_active()) {
        snprintf(reason, cap, "in-RAM coins overlay active");
        return false;
    }
    progress_store_tx_lock();
    bool proven = coins_kv_is_proven_authority(pdb, NULL);
    bool refolded = proven && coins_kv_contains_refold_marker(pdb);
    progress_store_tx_unlock();
    /* Route ONLY the provenance-bit portion of the gate through the central
     * trust table (services/sync_trust_policy.h). EXPORT_BUNDLE is granted
     * exactly in the X states (HEADERS_VERIFIED, SOVEREIGN), i.e. iff
     * (proven && refold); it is independent of the self_derived bit, so that
     * input is immaterial here and passed false. X = proven && refolded
     * (refolded already carries proven), so the derived answer is identical to
     * the old `!proven || !refolded` gate. Every other rung (coins_ram above,
     * exact source-identity rung below) stays exactly where it is and is never
     * weakened. */
    if (!sync_trust_cap_allowed(
            sync_trust_derive(proven, refolded, /*self_derived=*/false),
            SYNC_CAP_EXPORT_BUNDLE)) {
        snprintf(reason, cap, "%s",
                 !proven ? "coins not proven authority"
                         : "coins lacks self-folded refold marker");
        return false;
    }
    if (!bx_is_exact_source_id(zcl_build_source_id_sha256())) {
        snprintf(reason, cap, "build has no exact source identity; unstamped");
        return false;
    }
    if (cap)
        reason[0] = '\0';
    return true;
}
#ifdef ZCL_TESTING
bool bundle_exporter_source_identity_is_exact_for_test(const char *source_id)
{
    return bx_is_exact_source_id(source_id);
}
#endif
/* ── GAP-1: at-tip + time-cadence gates (pure, unit-tested) ─────────── */
/* GAP-1a — is the node close enough to the network tip to publish a STARTER
 * bundle? A fresh consumer must land on a near-tip generation; a
 * still-catching-up node would mint a stale starter. True iff SYNC_AT_TIP, or
 * the Prime-Directive lag (log_head_gap = network_tip − log_head) is within
 * `max_tip_gap`. An unknown gap (health could not resolve the network tip:
 * log_head_gap < 0) while not synced fails CLOSED — never publish on an
 * unprovable tip. Pure. */
static bool bx_at_tip_ok(bool synced, int log_head_gap, int64_t max_tip_gap)
{
    if (synced)
        return true;
    if (log_head_gap < 0)
        return false;
    return (int64_t)log_head_gap <= max_tip_gap;
}
/* GAP-1b — is an export DUE, given the durable tip height `h`, the last exported
 * height `last_h`, seconds since the last export `elapsed_secs`, and the three
 * cadence knobs? Two triggers, both fenced by a minimum-interval FLOOR so a
 * burst of blocks can never double-export:
 *   - every_blocks CEILING by height: (h - last_h) >= every_blocks — the primary
 *     "enough new chain accrued" trigger; OR
 *   - every_secs CEILING by time:     elapsed >= every_secs (with h > last_h) —
 *     publish at least this often so a quiet-but-advancing chain still refreshes;
 *   - min_secs FLOOR:                 elapsed >= min_secs — never re-export
 *     within the floor window, even when blocks flooded in.
 * `h <= last_h` is never due (nothing new). The at-tip gate is applied
 * separately by the caller (bx_at_tip_ok). Pure. */
static bool bx_export_due(int64_t h, int64_t last_h, int64_t elapsed_secs,
                          int64_t every_blocks, int64_t every_secs,
                          int64_t min_secs)
{
    if (h <= last_h)
        return false;
    bool blocks_due = (h - last_h) >= every_blocks;
    bool time_due = elapsed_secs >= every_secs; /* h > last_h already holds */
    if (!(blocks_due || time_due))
        return false;
    return elapsed_secs >= min_secs;
}
#ifdef ZCL_TESTING
bool bundle_exporter_at_tip_ok_for_test(bool synced, int log_head_gap,
                                        int64_t max_tip_gap)
{
    return bx_at_tip_ok(synced, log_head_gap, max_tip_gap);
}
bool bundle_exporter_export_due_for_test(int64_t h, int64_t last_h,
                                         int64_t elapsed_secs,
                                         int64_t every_blocks,
                                         int64_t every_secs, int64_t min_secs)
{
    return bx_export_due(h, last_h, elapsed_secs, every_blocks, every_secs,
                         min_secs);
}
#endif
/* ── One export attempt ─────────────────────────────────────────── */
static void bx_try_export_once(void)
{
    pthread_mutex_lock(&g_bx.lock);
    sqlite3 *pdb = g_bx.pdb;
    int64_t every = g_bx.every_blocks;
    int64_t every_secs = g_bx.every_secs;
    int64_t min_secs = g_bx.min_secs;
    int64_t max_tip_gap = g_bx.max_tip_gap;
    int keep = g_bx.keep;
    char bundles_dir[1100];
    char datadir[1024];
    snprintf(bundles_dir, sizeof bundles_dir, "%s", g_bx.bundles_dir);
    snprintf(datadir, sizeof datadir, "%s", g_bx.datadir);
    pthread_mutex_unlock(&g_bx.lock);
    /* Belt+braces: the proof independently refuses while the overlay is live,
     * but never even finalize the receipt against a mutable in-RAM view. */
    if (coins_ram_active()) {
        bx_note_refusal("in-RAM overlay active");
        return;
    }
    /* The durable-tip read touches the shared singleton handle and does NOT
     * self-lock; serialize it with the reducer's batches. Brief: two indexed
     * lookups. (The receipt finalize + the snapshot pin below each take the
     * lock themselves.) */
    int h = -1;
    uint8_t hash[32];
    progress_store_tx_lock();
    bool tip_ok = tip_finalize_stage_resolve_durable_tip(pdb, &h, hash);
    progress_store_tx_unlock();
    if (!tip_ok || h < 0) {
        bx_note_refusal("durable tip unavailable");
        return;
    }
    /* GAP-1b — time + block cadence. elapsed is measured from the last export's
     * wall-clock time (seeded from the newest on-disk generation's mtime at
     * start, so both cadences survive a restart). A zero/absent last-time means
     * "no prior generation" → treat elapsed as unbounded so the first export is
     * governed by the block ceiling / the floor passes. */
    int32_t last = atomic_load(&g_bx_last_export_height);
    int64_t last_time_us = atomic_load(&g_bx_last_export_time_us);
    int64_t now_us = GetTimeMicros();
    int64_t elapsed_secs;
    if (last_time_us <= 0)
        elapsed_secs = INT64_MAX;
    else if (now_us <= last_time_us)
        elapsed_secs = 0; /* clock skew → fail the floor, fail-safe */
    else
        elapsed_secs = (now_us - last_time_us) / 1000000;
    if (!bx_export_due((int64_t)h, (int64_t)last, elapsed_secs, every,
                       every_secs, min_secs))
        return; /* not due yet (block ceiling / time ceiling / min-secs floor) */
    /* GAP-1a — at-tip gate. A STARTER bundle must be near the network tip so a
     * fresh consumer lands there; a still-catching-up node would mint a stale
     * generation. node_health_collect(NULL,NULL) self-resolves the runtime
     * singletons (same call the soak/healthcheck background paths use); it is
     * invoked here holding NO progress_store_tx_lock, so its internal locks
     * never nest with this module's. Refusal is observable via last_refusal /
     * dumpstate. */
    struct node_health_snapshot snap;
    node_health_collect(&snap, NULL, NULL);
    if (!bx_at_tip_ok(snap.synced, snap.log_head_gap, max_tip_gap)) {
        bx_note_refusal("not at tip: synced=%d log_head_gap=%d > max_tip_gap=%lld",
                        snap.synced ? 1 : 0, snap.log_head_gap,
                        (long long)max_tip_gap);
        return;
    }
    char name[128];
    snprintf(name, sizeof name, BX_BUNDLE_PREFIX "%d" BX_BUNDLE_SUFFIX, h);
    /* Already exported this generation? Treat as done. */
    char full[1300];
    snprintf(full, sizeof full, "%s/%s", bundles_dir, name);
    struct stat stx;
    if (stat(full, &stx) == 0) {
        atomic_store(&g_bx_last_export_height, h);
        return;
    }
    /* Roll the source receipt forward to the current durable tip. Monotonic:
     * an equal height is idempotent, a lower one is refused inside finalize. */
    char err[256] = "";
    if (!consensus_state_producer_receipt_finalize(pdb, h, hash,
                                                   err, sizeof err)) {
        bx_note_refusal("%s", err[0] ? err : "receipt finalize failed");
        atomic_fetch_add(&g_bx_exports_failed, 1);
        return;
    }
    int dir_fd = open(bundles_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        bx_note_refusal("open bundles dir failed: %s", strerror(errno));
        atomic_fetch_add(&g_bx_exports_failed, 1);
        return;
    }
    struct consensus_state_snapshot_export_request req;
    memset(&req, 0, sizeof req);
    req.output_dir_fd = dir_fd;
    req.output_name = name;
    req.expected_height = h;
    memcpy(req.expected_block_hash, hash, 32);
    struct consensus_state_export_result res;
    memset(&res, 0, sizeof res);
    int64_t t0 = GetTimeMicros();
    bool ok = consensus_state_snapshot_export_from_progress_snapshot(&req, &res);
    close(dir_fd);
    int64_t dur = GetTimeMicros() - t0;
    if (ok && res.status == CONSENSUS_EXPORT_EXPORTED) {
        atomic_store(&g_bx_last_export_height, h);
        atomic_store(&g_bx_last_export_time_us, GetTimeMicros());
        atomic_store(&g_bx_last_export_duration_us, dur);
        atomic_fetch_add(&g_bx_exports_ok, 1);
        pthread_mutex_lock(&g_bx.lock);
        g_bx.last_refusal[0] = '\0';
        pthread_mutex_unlock(&g_bx.lock);
        LOG_INFO("bundle_exporter",
                 "exported %s height=%d duration_us=%lld",
                 name, h, (long long)dur);
        /* Serve it THIS boot. The boot rom_seed scan
         * (config/src/boot_frontend_services.c boot_rom_seed_start ->
         * rom_seed_scan_datadir) is single-shot and already ran, so a
         * generation produced now would otherwise not be offered until the
         * next boot. Register it with the seeder immediately — the same
         * post-produce reseed the fetch path performs
         * (config/src/boot_bundle_fetch.c). rom_seed_register re-derives every
         * digest from the bytes on disk; a failure here is logged and non-fatal
         * (this same boot's rom_seed scan, or a later boot, still picks it up)
         * and keeps no durable state of its own. */
        char rel[ROM_SEED_NAME_MAX];
        int rn = snprintf(rel, sizeof rel, "%s/%s",
                          ROM_SEED_BUNDLES_SUBDIR, name);
        if (rn > 0 && (size_t)rn < sizeof rel) {
            enum rom_register_result rrc =
                rom_seed_register(datadir, rel, NULL, NULL);
            if (rrc == ROM_REG_OK)
                LOG_INFO("bundle_exporter",
                         "reseed: registered %s with rom_seed — this node now "
                         "serves the fresh generation to the swarm", rel);
            else
                LOG_WARN("bundle_exporter",
                         "reseed: could not register %s (rc=%d) — the next "
                         "rom_seed scan will pick it up", rel, (int)rrc);
        }
        bx_rotate(bundles_dir, keep, datadir);
    } else {
        bx_note_refusal("%s", res.reason[0] ? res.reason : "export refused");
        atomic_fetch_add(&g_bx_exports_failed, 1);
        LOG_WARN("bundle_exporter",
                 "export refused height=%d status=%d reason=%s",
                 h, (int)res.status,
                 res.reason[0] ? res.reason : "(none)");
    }
}
/* ── Worker loop ────────────────────────────────────────────────── */
static void *bx_worker_main(void *arg)
{
    (void)arg;
    supervisor_child_id id = atomic_load(&g_bx_supervisor_id);
    while (atomic_load(&g_bx_running)) {
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_tick(id); /* heartbeat */
        pthread_mutex_lock(&g_bx.lock);
        int64_t tick = g_bx.tick_secs;
        pthread_mutex_unlock(&g_bx.lock);
        if (tick < 1)
            tick = 1;
        /* Sleep in <=1s increments so _stop stays responsive. */
        for (int64_t i = 0; i < tick && atomic_load(&g_bx_running); i++) {
            struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        }
        if (!atomic_load(&g_bx_running))
            break;
        pthread_mutex_lock(&g_bx.lock);
        bool session = g_bx.session_open;
        pthread_mutex_unlock(&g_bx.lock);
        if (!session) {
            /* Degraded — keep heartbeating, never export, and SAY SO every
             * tick. blocker_set's own token bucket collapses the repeats, so
             * this costs one stored record and keeps it from being retired as
             * stale evidence while the outage is still real. */
            pthread_mutex_lock(&g_bx.lock);
            char degradation[256];
            snprintf(degradation, sizeof degradation, "%s",
                     g_bx.degradation_reason[0] ? g_bx.degradation_reason
                                                : "producer session not open");
            pthread_mutex_unlock(&g_bx.lock);
            bx_name_degraded(degradation);
            continue;
        }
        bx_try_export_once();
    }
    return NULL;
}
/* ── Lifecycle ──────────────────────────────────────────────────── */
bool bundle_exporter_start(sqlite3 *pdb, const char *datadir)
{
    if (!pdb || !datadir || !*datadir)
        LOG_FAIL("bundle_exporter",
                 "start: NULL progress handle or datadir — not armed");
    pthread_mutex_lock(&g_bx.lock);
    if (atomic_load(&g_bx_running)) {
        pthread_mutex_unlock(&g_bx.lock);
        return true; /* idempotent */
    }
    g_bx.pdb = pdb;
    snprintf(g_bx.datadir, sizeof g_bx.datadir, "%s", datadir);
    snprintf(g_bx.bundles_dir, sizeof g_bx.bundles_dir, "%s/bundles", datadir);
    g_bx.every_blocks = bx_env_i64("ZCL_BUNDLE_EXPORT_EVERY_BLOCKS", 5000);
    if (g_bx.every_blocks < 1)
        g_bx.every_blocks = 1;
    /* Time cadence (GAP-1b): every_secs is the daily CEILING (refresh even if
     * fewer than every_blocks arrived, provided the tip advanced), min_secs is
     * the FLOOR that forbids double-exporting in a burst. */
    g_bx.every_secs = bx_env_i64("ZCL_BUNDLE_EXPORT_EVERY_SECS", 86400);
    if (g_bx.every_secs < 1)
        g_bx.every_secs = 1;
    g_bx.min_secs = bx_env_i64("ZCL_BUNDLE_EXPORT_MIN_SECS", 900);
    if (g_bx.min_secs < 0)
        g_bx.min_secs = 0;
    /* At-tip gate (GAP-1a): publish only within max_tip_gap of the network tip. */
    g_bx.max_tip_gap = bx_env_i64("ZCL_BUNDLE_EXPORT_MAX_TIP_GAP", 4);
    if (g_bx.max_tip_gap < 0)
        g_bx.max_tip_gap = 0;
    g_bx.keep = (int)bx_env_i64("ZCL_BUNDLE_EXPORT_KEEP", 3);
    if (g_bx.keep < 1)
        g_bx.keep = 1;
    g_bx.tick_secs = bx_env_i64("ZCL_BUNDLE_EXPORT_TICK_SECS", 30);
    if (g_bx.tick_secs < 1)
        g_bx.tick_secs = 1;
    if (mkdir(g_bx.bundles_dir, 0700) != 0 && errno != EEXIST)
        LOG_WARN("bundle_exporter", "mkdir %s failed: %s",
                 g_bx.bundles_dir, strerror(errno));
    char bundles_dir[1100];
    int64_t every = g_bx.every_blocks;
    int keep = g_bx.keep;
    int64_t tick = g_bx.tick_secs;
    snprintf(bundles_dir, sizeof bundles_dir, "%s", g_bx.bundles_dir);
    pthread_mutex_unlock(&g_bx.lock);
    /* Qualify + (maybe) open the producer session — OUTSIDE g_bx.lock: both
     * bx_qualified and receipt_begin take progress_store_tx_lock, and this
     * module keeps the two locks strictly disjoint (no nesting order exists,
     * so no lock-order edge). Single-threaded here: the worker is not spawned
     * yet and g_bx_running is still false, so the fields written below cannot
     * be observed concurrently. NEVER fail here. */
    bool session_open = false;
    bool qualified = false;
    char degradation[256] = "";
    char reason[256] = "";
    if (bx_qualified(pdb, reason, sizeof reason)) {
        char err[256] = "";
        if (consensus_state_producer_receipt_begin(
                pdb, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof err)) {
            session_open = true;
            qualified = true;
            LOG_INFO("bundle_exporter",
                     "producer session opened (qualified); standing exporter "
                     "armed every=%lld keep=%d tick=%llds",
                     (long long)every, keep, (long long)tick);
        } else {
            snprintf(degradation, sizeof degradation, "%s",
                     err[0] ? err : "producer session refused");
            LOG_WARN("bundle_exporter",
                     "producer session refused: %s (degraded, still armed)",
                     degradation);
        }
    } else {
        snprintf(degradation, sizeof degradation, "%s", reason);
        LOG_WARN("bundle_exporter",
                 "not qualified: %s (degraded, still armed)", reason);
    }
    pthread_mutex_lock(&g_bx.lock);
    g_bx.session_open = session_open;
    g_bx.qualified = qualified;
    snprintf(g_bx.degradation_reason, sizeof g_bx.degradation_reason, "%s",
             degradation);
    pthread_mutex_unlock(&g_bx.lock);
    int64_t newest_mtime_us = 0;
    atomic_store(&g_bx_last_export_height,
                 bx_scan_newest(bundles_dir, &newest_mtime_us));
    atomic_store(&g_bx_last_export_time_us, newest_mtime_us);
    /* Name it now, not one worker tick from now: the generation scan above is
     * what supplies the staleness numbers, so this is the first moment the
     * blocker can carry them. The worker re-fires it on every tick. */
    if (!session_open)
        bx_name_degraded(degradation[0] ? degradation
                                        : "producer session not open");
    /* Register the supervised (best-effort, no-stall) contract. */
    if (supervisor_start()) {
        liveness_contract_init(&g_bx_contract, "ops.bundle_exporter");
        atomic_store(&g_bx_contract.period_secs, 0);
        atomic_store(&g_bx_contract.deadline_secs, 0);
        atomic_store(&g_bx_contract.progress_max_quiet_us, 0);
        supervisor_domains_init();
        supervisor_child_id id =
            supervisor_register_in_domain(g_op_sup, &g_bx_contract);
        atomic_store(&g_bx_supervisor_id, id);
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_tick(id);
    } else {
        LOG_WARN("bundle_exporter",
                 "supervisor_start failed; exporter runs unsupervised");
    }
    atomic_store(&g_bx_running, true);
    int rc = thread_registry_spawn("zcl_bundle_exp", bx_worker_main, NULL,
                                   &g_bx.worker);
    if (rc != 0) {
        atomic_store(&g_bx_running, false);
        pthread_mutex_lock(&g_bx.lock);
        g_bx.worker_running = false;
        pthread_mutex_unlock(&g_bx.lock);
        LOG_WARN("bundle_exporter",
                 "worker spawn failed (%d); exporter not running", rc);
        return true; /* fail-safe: never block boot */
    }
    pthread_mutex_lock(&g_bx.lock);
    g_bx.worker_running = true;
    pthread_mutex_unlock(&g_bx.lock);
    return true;
}
void bundle_exporter_stop(void)
{
    atomic_store(&g_bx_running, false);
    pthread_t th;
    bool joinable = false;
    pthread_mutex_lock(&g_bx.lock);
    if (g_bx.worker_running) {
        th = g_bx.worker;
        joinable = true;
        g_bx.worker_running = false;
    }
    pthread_mutex_unlock(&g_bx.lock);
    if (joinable)
        pthread_join(th, NULL);
    atomic_store(&g_bx_contract.completed, true);
    supervisor_child_id id = atomic_load(&g_bx_supervisor_id);
    if (id != SUPERVISOR_INVALID_ID)
        supervisor_child_complete(id);
}
/* ── Boot service registration ──────────────────────────────────── */
static bool bx_service_start(void *ctx)
{
    const char *datadir = ctx;
    if (!datadir)
        return true;
    (void)bundle_exporter_start(progress_store_db(), datadir);
    return true;
}
static void bx_service_stop(void *ctx)
{
    (void)ctx;
    bundle_exporter_stop();
}
bool bundle_exporter_register_service(struct zcl_service_kernel *kernel,
                                      const char *datadir)
{
    const struct zcl_service_spec spec = {
        .name = "bundle_exporter",
        .start = bx_service_start,
        .stop = bx_service_stop,
        .ctx = (void *)datadir,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(kernel, &spec);
}
/* ── `z23 dumpstate bundle_exporter` ────────────────────── */
bool bundle_exporter_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);
    /* Atomics read directly; string fields under a brief lock. */
    char degradation_reason[256];
    char last_refusal[256];
    char bundles_dir[1100];
    bool session_open, qualified;
    int64_t every_blocks, every_secs, min_secs, max_tip_gap;
    int keep;
    pthread_mutex_lock(&g_bx.lock);
    session_open = g_bx.session_open;
    qualified = g_bx.qualified;
    every_blocks = g_bx.every_blocks;
    every_secs = g_bx.every_secs;
    min_secs = g_bx.min_secs;
    max_tip_gap = g_bx.max_tip_gap;
    keep = g_bx.keep;
    snprintf(degradation_reason, sizeof degradation_reason, "%s",
             g_bx.degradation_reason);
    snprintf(last_refusal, sizeof last_refusal, "%s", g_bx.last_refusal);
    snprintf(bundles_dir, sizeof bundles_dir, "%s", g_bx.bundles_dir);
    pthread_mutex_unlock(&g_bx.lock);
    json_push_kv_bool(out, "session_open", session_open);
    json_push_kv_bool(out, "qualified", qualified);
    json_push_kv_str(out, "degradation_reason", degradation_reason);
    json_push_kv_str(out, "last_refusal", last_refusal);
    json_push_kv_int(out, "last_export_height",
                     atomic_load(&g_bx_last_export_height));
    json_push_kv_int(out, "last_export_time_us",
                     atomic_load(&g_bx_last_export_time_us));
    json_push_kv_int(out, "last_export_duration_us",
                     atomic_load(&g_bx_last_export_duration_us));
    json_push_kv_int(out, "exports_ok", atomic_load(&g_bx_exports_ok));
    json_push_kv_int(out, "exports_failed", atomic_load(&g_bx_exports_failed));
    json_push_kv_int(out, "every_blocks", every_blocks);
    json_push_kv_int(out, "every_secs", every_secs);
    json_push_kv_int(out, "min_secs", min_secs);
    json_push_kv_int(out, "max_tip_gap", max_tip_gap);
    json_push_kv_int(out, "keep", keep);
    json_push_kv_str(out, "bundles_dir", bundles_dir);
    /* Generations currently on disk (heights present), newest first. */
    struct bx_gen gens[BX_MAX_GENERATIONS];
    int n = 0;
    DIR *d = opendir(bundles_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL && n < BX_MAX_GENERATIONS) {
            long h;
            if (bx_parse_bundle_height(e->d_name, &h)) {
                gens[n].h = h;
                gens[n].name[0] = '\0';
                n++;
            }
        }
        closedir(d);
    }
    qsort(gens, (size_t)n, sizeof gens[0], bx_gen_cmp_desc);
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_int(&item, gens[i].h);
        json_push_back(&arr, &item);
        json_free(&item);
    }
    json_push_kv(out, "generations", &arr);
    json_free(&arr);
    return true;
}
#endif /* _WIN32 */
