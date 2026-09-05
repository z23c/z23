/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle_exporter — the STANDING live consensus-state bundle exporter (lane C1
 * of the Instant-Sync program). See engine/composition/include/config/bundle_exporter.h for
 * the contract and the precise provenance claim this proves.
 *
 * Structure mirrors contexts/wallet/services/src/wallet_backup_service.c: a dedicated worker
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
/* ── Recovery policy (both platform arms) ───────────────────────────
 * The exporter used to decide qualification and the producer session ONCE, at
 * boot, and never again. A node upgraded twice a day therefore stopped minting
 * forever the first time its executable changed (see bx_recover_session for the
 * exact mechanism). Recovery is now a normal tick step, with three constants:
 *
 * BX_DEGRADED_AFTER_FAILURES — how many CONSECUTIVE failed attempts before the
 *   outage is named as bundle_exporter.degraded. 3, not 1: the first attempt
 *   happens during boot, when the coins store may still be opening, the refold
 *   marker may not have landed, and the in-RAM overlay may still be draining —
 *   all of which clear on their own within a tick or two. At the default 30s
 *   tick, 3 puts the blocker up ~60-90s into a real outage: far too fast to
 *   matter to an operator, far too slow to fire on boot ordering. It is also
 *   not 1 for a second reason — a one-shot raise cannot tell a blip from an
 *   outage, and the whole point of this record is that it means something.
 *
 * BX_RECOVER_BACKOFF_MAX_SECS — a failed recovery attempt costs a durable read
 *   and a BEGIN IMMEDIATE on the shared progress store, so a hopeless cause (a
 *   real source change; see bx_epoch_adoptable) must not re-run it every tick.
 *   Doubling from one tick to an hour keeps the fast cases fast and the
 *   hopeless case cheap, and never stops retrying entirely. */
#define BX_DEGRADED_AFTER_FAILURES   3
#define BX_RECOVER_BACKOFF_MAX_SECS  3600
#define BX_DEGRADED_BLOCKER_ID       "bundle_exporter.degraded"
/* May a FOREIGN producer session be retired and re-derived from the running
 * binary? Only when the source epoch already stamped into this datadir's fold
 * rows is byte-identical to this build's. Platform-independent and pure, so it
 * lives above the split and has exactly one definition; either side absent
 * fails CLOSED. See the block above bx_recover_session for why this is the
 * whole safety argument. */
static inline bool bx_epoch_adoptable(const uint8_t *stamped,
                                      const uint8_t *current)
{
    return stamped && current && memcmp(stamped, current, 32) == 0;
}
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
/* Native Windows export is security-refused before any path is composed, so
 * there is no module state and no session to recover. These are the per-arm
 * STATIC halves of the recovery seams; the one exported definition of each
 * lives past the platform split at the bottom of the file. */
static bool bx_recover_once_impl(void) { return false; }
static void bx_note_export_ok_impl(void) {}
static void bx_inject_session_failure_impl(const char *err) { (void)err; }
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
    int      consecutive_failures; /* consecutive failed mint/recovery attempts */
    int64_t  recover_backoff_secs; /* current bounded recovery backoff */
    int64_t  recover_next_us;      /* earliest next recovery attempt */
    bool     blocker_raised;       /* BX_DEGRADED_BLOCKER_ID is set by us */
#ifdef ZCL_TESTING
    /* Test-only injection: the recovery step treats qualification as passed
     * and the producer-session begin as REFUSED with this text, so the
     * mismatch -> re-derive -> retry path is reachable from a unit fixture
     * without a fully folded, proven-authority datadir. */
    bool     inject_session_failure;
    char     inject_session_err[256];
#endif
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
 * reason this exists. Measured on the canonical node 2026-08-19: the last mint
 * was 2026-07-24, 165,288 blocks behind its own tip, because a binary upgrade
 * left the stored producer session foreign to the running build. The refusal
 * was correct; the silence, and the absence of any in-process recovery, were
 * not. The exporter now RETRIES on its own tick with bounded backoff
 * (bx_recover_session) and only names the outage after
 * BX_DEGRADED_AFTER_FAILURES consecutive failures, with the LITERAL cause
 * leading the reason.
 *
 * BLOCKER_DEPENDENCY: dependency blockers never TTL-retire, and the optional
 * exporter must not hard-gate validation, relay, or serving. The record is
 * cleared by this process the moment a mint succeeds or the session is
 * re-derived (bx_attempt_succeeded).
 *
 * REASON BUDGET — this used to overflow. blocker_init copies into a
 * BLOCKER_REASON_MAX (256) field through the shared visible-cut policy, and
 * the old framing produced intended_len=275 for a real producer-session
 * refusal: the record was stored with a "[cut" marker and the operator lost
 * the tail. `degradation` carries the one thing an operator needs — the exact
 * refusal, e.g. producer_session_mismatch_detail's "field=X expected=Y
 * actual=Z" — so it leads and gets the first 160 bytes. The framing below is
 * bounded at 90 bytes (39 lead-in + 6 days + 11 + 10 height + 24 tail), so the
 * whole reason is at most 250 bytes and always FITS. Do not lengthen either
 * half without re-doing this arithmetic; the capacity is not the thing to
 * raise. */
static void bx_name_degraded(const char *degradation)
{
    int32_t last_h = atomic_load(&g_bx_last_export_height);
    int64_t last_us = atomic_load(&g_bx_last_export_time_us);
    int64_t age_secs = last_us > 0 ? (GetTimeMicros() - last_us) / 1000000 : -1;
    char reason[512];
    if (last_h >= 0 && age_secs >= 0)
        snprintf(reason, sizeof reason,
                 "%.160s (no consensus-state bundle minted for %lldd, "
                 "newest h=%d; retrying with backoff)",
                 degradation, (long long)(age_secs / 86400), last_h);
    else
        snprintf(reason, sizeof reason,
                 "%.160s (no consensus-state bundle minted here yet; "
                 "retrying with backoff)", degradation);
    struct blocker_record b;
    if (blocker_init(&b, BX_DEGRADED_BLOCKER_ID, "bundle_exporter",
                     BLOCKER_DEPENDENCY, reason))
        (void)blocker_set(&b);
}
/* One failed attempt (a refused mint, or a refused recovery). Records the
 * literal cause, advances the bounded recovery backoff, and names the outage
 * once — and only once — BX_DEGRADED_AFTER_FAILURES consecutive failures have
 * accrued. Callers must NOT hold g_bx.lock. */
static void bx_attempt_failed(const char *cause)
{
    char degradation[256];
    bool name_it;
    pthread_mutex_lock(&g_bx.lock);
    if (g_bx.consecutive_failures < INT32_MAX)
        g_bx.consecutive_failures++;
    snprintf(g_bx.degradation_reason, sizeof g_bx.degradation_reason, "%s",
             cause && cause[0] ? cause : "producer session not open");
    snprintf(degradation, sizeof degradation, "%s", g_bx.degradation_reason);
    int64_t backoff = g_bx.recover_backoff_secs;
    if (backoff <= 0)
        backoff = g_bx.tick_secs > 0 ? g_bx.tick_secs : 1;
    else if (backoff < BX_RECOVER_BACKOFF_MAX_SECS)
        backoff *= 2;
    if (backoff > BX_RECOVER_BACKOFF_MAX_SECS)
        backoff = BX_RECOVER_BACKOFF_MAX_SECS;
    g_bx.recover_backoff_secs = backoff;
    g_bx.recover_next_us = GetTimeMicros() + backoff * 1000000;
    name_it = g_bx.consecutive_failures >= BX_DEGRADED_AFTER_FAILURES;
    if (name_it)
        g_bx.blocker_raised = true;
    pthread_mutex_unlock(&g_bx.lock);
    if (name_it)
        bx_name_degraded(degradation);
}
/* One successful attempt (a minted generation, or a re-derived session). The
 * named cause is provably gone, so the record goes with it and the backoff
 * resets. Callers must NOT hold g_bx.lock. */
static void bx_attempt_succeeded(void)
{
    pthread_mutex_lock(&g_bx.lock);
    g_bx.consecutive_failures = 0;
    g_bx.recover_backoff_secs = 0;
    g_bx.recover_next_us = 0;
    g_bx.degradation_reason[0] = '\0';
    bool clear = g_bx.blocker_raised;
    g_bx.blocker_raised = false;
    pthread_mutex_unlock(&g_bx.lock);
    if (clear)
        blocker_clear(BX_DEGRADED_BLOCKER_ID);
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
/* ── Producer-session recovery ──────────────────────────────────────
 * WHY AN UPGRADE STOPS THE MINT. The durable session row
 * (consensus_state_producer_session) is bound to running_binary_digest =
 * SHA3-256 of the running executable's on-disk image
 * (producer_running_binary_digest). consensus_state_producer_receipt_begin
 * ADOPTS NOTHING: it recomputes this build's claim and refuses unless the
 * stored row matches exactly, running_binary_digest FIRST
 * (producer_session_matches_current in consensus_state_producer_receipt.c).
 * Any relink changes the image bytes, so every binary upgrade — even a rebuild
 * of the identical source tree — makes the stored session foreign and begin()
 * returns "session mismatch field=running_binary_digest ...". Until now nothing
 * in-process re-ran it, so the node never minted again.
 *
 * WHY RE-DERIVING IS SOUND, AND ONLY SOMETIMES. The export proof does not care
 * which executable IMAGE stamped the fold rows; it requires every genesis..H*
 * row of every source-epoch-bound stage to carry the receipt's
 * source_epoch_digest (consensus_export_prove_stage_rows in
 * consensus_state_snapshot_export_proof.c), and it re-checks the finalized
 * receipt's running_binary_digest against the LIVE /proc/self/exe itself. The
 * epoch is SHA3(source_tree_root || toolchain_digest || build_inputs_digest ||
 * source_clean) — consensus_state_source_epoch_digest — and does NOT include
 * the image digest. So:
 *
 *   - epoch stamped in this datadir == this build's epoch: the rows already on
 *     disk still prove out verbatim under a session owned by this executable.
 *     Retiring the foreign row and re-deriving one is a rubber stamp — the same
 *     act consensus_state_producer_session_retire performs, reaching the same
 *     bundle, with the export's own proof re-run from scratch afterwards.
 *
 *   - epoch differs: the source tree, toolchain, or build inputs actually
 *     changed. Every stamped row carries the OLD epoch, so a re-derived receipt
 *     would prove nothing and the export would refuse with MISSING_PROOF
 *     anyway. Retiring here would destroy the audit row for no gain. We do NOT.
 *     That case stays exactly as fail-closed as it was, named with its literal
 *     cause, and needs a re-fold (or an operator's explicit retire).
 *
 * Nothing below weakens a rung: bx_qualified is re-run in full every attempt,
 * begin() still refuses what it always refused, retire() still refuses to
 * delete a session this build owns, and the export proof is unchanged.
 * bx_epoch_adoptable itself lives above the platform split. */
/* Is the source epoch already stamped into this datadir's fold rows exactly
 * this build's epoch? Callers must NOT hold g_bx.lock (progress_store_tx_lock
 * and g_bx.lock stay strictly disjoint in this module). */
static bool bx_stamped_epoch_is_this_build(sqlite3 *pdb)
{
    uint8_t current[32];
    if (!consensus_state_producer_receipt_current_binary_epoch(current))
        return false;
    uint8_t stamped[32];
    size_t got = 0;
    bool found = false;
    progress_store_tx_lock();
    bool read_ok = progress_meta_get_blob_exact(
        pdb, CONSENSUS_STATE_SOURCE_EPOCH_META_KEY, stamped, sizeof stamped,
        &got, &found);
    progress_store_tx_unlock();
    if (!read_ok || !found || got != sizeof stamped)
        return false;
    return bx_epoch_adoptable(stamped, current);
}
/* One recovery attempt: re-qualify, re-open the producer session, and — only
 * when the stamped epoch says it is a rubber stamp — retire the foreign
 * session row and re-derive one from this running binary. Returns true iff a
 * session is open afterwards. Accounts exactly one failure or one success.
 * `force` skips the backoff window (test seam). */
static bool bx_recover_session(bool force)
{
    pthread_mutex_lock(&g_bx.lock);
    sqlite3 *pdb = g_bx.pdb;
    int64_t next_us = g_bx.recover_next_us;
#ifdef ZCL_TESTING
    bool inject = g_bx.inject_session_failure;
    char inject_err[256];
    snprintf(inject_err, sizeof inject_err, "%s", g_bx.inject_session_err);
#endif
    pthread_mutex_unlock(&g_bx.lock);
    if (!pdb) {
        bx_attempt_failed("progress store handle unavailable");
        return false;
    }
    if (!force && next_us > 0 && GetTimeMicros() < next_us)
        return false; /* inside the backoff window: no attempt, no accounting */
    char err[256] = "";
#ifdef ZCL_TESTING
    if (inject) {
        snprintf(err, sizeof err, "%s",
                 inject_err[0] ? inject_err : "injected session refusal");
    } else
#endif
    {
        char reason[256] = "";
        if (!bx_qualified(pdb, reason, sizeof reason)) {
            bx_attempt_failed(reason[0] ? reason
                                        : "provenance does not qualify");
            return false;
        }
        if (consensus_state_producer_receipt_begin(
                pdb, CONSENSUS_STATE_VALIDATION_FULL, err, sizeof err)) {
            pthread_mutex_lock(&g_bx.lock);
            g_bx.session_open = true;
            g_bx.qualified = true;
            pthread_mutex_unlock(&g_bx.lock);
            bx_attempt_succeeded();
            return true;
        }
    }
    /* begin() refused. Re-derive ONLY when the epoch on disk is ours. */
    if (bx_stamped_epoch_is_this_build(pdb)) {
        char rerr[256] = "";
        enum consensus_state_producer_session_retire_result rc =
            consensus_state_producer_session_retire(pdb, NULL, rerr,
                                                    sizeof rerr);
        if (rc == CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_RETIRED ||
            rc == CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT) {
            char err2[256] = "";
            if (consensus_state_producer_receipt_begin(
                    pdb, CONSENSUS_STATE_VALIDATION_FULL, err2,
                    sizeof err2)) {
                LOG_INFO("bundle_exporter",
                         "producer session re-derived from this running "
                         "binary (same source epoch); minting resumes");
                pthread_mutex_lock(&g_bx.lock);
                g_bx.session_open = true;
                g_bx.qualified = true;
                pthread_mutex_unlock(&g_bx.lock);
                bx_attempt_succeeded();
                return true;
            }
            snprintf(err, sizeof err, "%s",
                     err2[0] ? err2 : "producer session refused after "
                                      "re-derive");
        } else if (rc == CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR) {
            snprintf(err, sizeof err, "%s",
                     rerr[0] ? rerr : "producer session retire failed");
        }
    }
    bx_attempt_failed(err[0] ? err : "producer session refused");
    return false;
}
#ifdef ZCL_TESTING
/* Per-arm STATIC halves of the recovery seams; the one exported definition of
 * each lives past the platform split at the bottom of the file. */
static bool bx_recover_once_impl(void)
{
    return bx_recover_session(true);
}
static void bx_note_export_ok_impl(void)
{
    bx_attempt_succeeded();
}
static void bx_inject_session_failure_impl(const char *err)
{
    pthread_mutex_lock(&g_bx.lock);
    g_bx.inject_session_failure = err != NULL;
    snprintf(g_bx.inject_session_err, sizeof g_bx.inject_session_err, "%s",
             err ? err : "");
    pthread_mutex_unlock(&g_bx.lock);
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
        bx_attempt_failed(err[0] ? err : "receipt finalize failed");
        return;
    }
    int dir_fd = open(bundles_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        bx_note_refusal("open bundles dir failed: %s", strerror(errno));
        atomic_fetch_add(&g_bx_exports_failed, 1);
        char why[256];
        snprintf(why, sizeof why, "open bundles dir failed: %s",
                 strerror(errno));
        bx_attempt_failed(why);
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
         * (engine/composition/src/boot_frontend_services.c boot_rom_seed_start ->
         * rom_seed_scan_datadir) is single-shot and already ran, so a
         * generation produced now would otherwise not be offered until the
         * next boot. Register it with the seeder immediately — the same
         * post-produce reseed the fetch path performs
         * (engine/composition/src/boot_bundle_fetch.c). rom_seed_register re-derives every
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
        /* A minted generation is the definition of "not degraded": the record
         * and the failure streak both go. */
        bx_attempt_succeeded();
    } else {
        bx_note_refusal("%s", res.reason[0] ? res.reason : "export refused");
        atomic_fetch_add(&g_bx_exports_failed, 1);
        LOG_WARN("bundle_exporter",
                 "export refused height=%d status=%d reason=%s",
                 h, (int)res.status,
                 res.reason[0] ? res.reason : "(none)");
        bx_attempt_failed(res.reason[0] ? res.reason : "export refused");
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
            /* Degraded — keep heartbeating and TRY TO FIX IT. bx_recover_session
             * re-runs every qualification rung and re-opens the producer
             * session, re-deriving it from this running binary when (and only
             * when) the epoch stamped in this datadir is already ours. It
             * self-rate-limits with bounded backoff and names the outage once
             * BX_DEGRADED_AFTER_FAILURES consecutive attempts have failed. */
            if (!bx_recover_session(false))
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
    /* A fresh arm starts a fresh streak. */
    g_bx.consecutive_failures = 0;
    g_bx.recover_backoff_secs = 0;
    g_bx.recover_next_us = 0;
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
    /* Account it now, not one worker tick from now: the generation scan above
     * is what supplies the staleness numbers, so this is the first moment a
     * blocker could carry them. This counts as attempt #1 of
     * BX_DEGRADED_AFTER_FAILURES — a boot that has not yet finished opening
     * the coins store is not yet an outage — and the worker retries from
     * there. */
    if (!session_open)
        bx_attempt_failed(degradation[0] ? degradation
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
    int keep, consecutive_failures;
    int64_t recover_backoff_secs;
    pthread_mutex_lock(&g_bx.lock);
    session_open = g_bx.session_open;
    qualified = g_bx.qualified;
    consecutive_failures = g_bx.consecutive_failures;
    recover_backoff_secs = g_bx.recover_backoff_secs;
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
    /* Recovery is observable: how long the current failure streak is, how far
     * it still is from naming the outage, and how long until the next try. */
    json_push_kv_int(out, "consecutive_failures", consecutive_failures);
    json_push_kv_int(out, "degraded_after_failures",
                     BX_DEGRADED_AFTER_FAILURES);
    json_push_kv_int(out, "recover_backoff_secs", recover_backoff_secs);
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
#ifdef ZCL_TESTING
/* ── Recovery seams: ONE definition each, past the platform split ────
 * Both arms above expose only static halves, so none of these becomes a
 * per-arm duplicate symbol. */
bool bundle_exporter_epoch_adoptable_for_test(const uint8_t *stamped,
                                              const uint8_t *current)
{
    return bx_epoch_adoptable(stamped, current);
}
bool bundle_exporter_recover_once_for_test(void)
{
    return bx_recover_once_impl();
}
void bundle_exporter_note_export_ok_for_test(void)
{
    bx_note_export_ok_impl();
}
void bundle_exporter_inject_session_failure_for_test(const char *err)
{
    bx_inject_session_failure_impl(err);
}
int bundle_exporter_degraded_after_failures_for_test(void)
{
    return BX_DEGRADED_AFTER_FAILURES;
}
#endif
