/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_security_posture.h"

#include "config/runtime.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/chain_evidence_authority_service.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"

#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>

#ifdef ZCL_TESTING
static _Atomic int g_test_review_required = -1;
#endif

static void posture_str(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0)
        return;
    snprintf(dst, dst_sz, "%s", src ? src : "");
}

/* ── Last-live posture snapshot (see agent_security_posture.h) ──────────
 *
 * Every live collection republishes this cache. When the shared node.db
 * connection is busy with a long maintenance op, collect() serves this cache
 * instead of issuing reads that would serialize behind the op. The critical
 * section is a bare struct copy (microseconds); it is guarded by a plain mutex,
 * NOT the DB, so a reader can never block on maintenance — the whole point. */
static pthread_mutex_t g_posture_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static struct agent_security_posture g_posture_cache;
static int64_t g_posture_cache_ms;
static bool g_posture_cache_valid;

static void posture_cache_store(const struct agent_security_posture *p)
{
    if (!p)
        return;
    pthread_mutex_lock(&g_posture_cache_lock);
    g_posture_cache = *p;
    g_posture_cache.served_from_cache = false;
    g_posture_cache.cache_age_ms = 0;
    g_posture_cache_ms = platform_time_monotonic_ms();
    g_posture_cache_valid = true;
    pthread_mutex_unlock(&g_posture_cache_lock);
}

static bool posture_cache_load(struct agent_security_posture *out)
{
    bool ok;
    if (!out)
        return false;
    pthread_mutex_lock(&g_posture_cache_lock);
    ok = g_posture_cache_valid;
    if (ok) {
        *out = g_posture_cache;
        int64_t now = platform_time_monotonic_ms();
        out->served_from_cache = true;
        out->cache_age_ms = now > g_posture_cache_ms
            ? now - g_posture_cache_ms : 0;
    }
    pthread_mutex_unlock(&g_posture_cache_lock);
    return ok;
}

/* ── Ordinary write-contention guard (not a NAMED long op) ──────────────
 *
 * Live forensics on a wedged node with a write-retry storm: node_db_long_op_
 * active() only routes around the rarer NAMED long ops that opt in via
 * db_long_op_start/finish (PRAGMA quick_check, the staging-cleanup DELETE —
 * see database_long_op.c). Ordinary write contention never names itself: a
 * writer thread retrying SQLITE_BUSY inside one long-running SQLite step
 * holds SQLite's own per-connection mutex (every public API call on a
 * connection opened with SQLITE_OPEN_FULLMUTEX — see db_open_raw in
 * database.c — serializes behind it) for up to that connection's
 * ZCL_NODE_DB_BUSY_TIMEOUT_MS (10s) while it retries. Any other thread
 * calling into that SAME connection, including this collect's ~dozen reads
 * via chain_evidence_controller_snapshot(), then queues behind it for the
 * same duration — measured ~10s via the chain_evidence dumpers, matching
 * ZCL_NODE_DB_BUSY_TIMEOUT_MS exactly.
 *
 * node.db has no equivalent app-level write-serialization mutex to trylock
 * (unlike progress.kv's progress_store_tx_lock, guarded non-blockingly by
 * progress_store_tx_trylock() — see test_stage_dump_trylock.c), so this
 * uses SQLite's own connection mutex directly via sqlite3_db_mutex(), a
 * documented public primitive for exactly this "another thread already
 * owns this handle" case. Trying it non-blockingly first and holding it for
 * the whole bootstrap read on success gives the identical non-blocking
 * guarantee at the connection level: acquired -> no other thread can hold
 * a long call on this connection while we read, so our reads proceed at
 * native speed; not acquired -> someone else already is, so we bail to the
 * last-known-good snapshot immediately instead of queuing. sqlite3_mutex_
 * try/enter/leave are documented no-ops on a NULL db/mutex, so this is safe
 * to call even when ndb is not backed by a real handle. */
static bool posture_ndb_try_lock(struct node_db *ndb)
{
    if (!ndb || !ndb->db)
        return false;
    return sqlite3_mutex_try(sqlite3_db_mutex(ndb->db)) == SQLITE_OK;
}

static void posture_ndb_unlock(struct node_db *ndb)
{
    if (ndb && ndb->db)
        sqlite3_mutex_leave(sqlite3_db_mutex(ndb->db));
}

/* Shared filler for both busy paths below (named long op / ordinary write
 * contention): name the state truthfully, invent no review gate, and never
 * claim node_db_available. Distinct `status`/`next_action` per path so an
 * operator can tell "a known maintenance op is running" apart from
 * "the connection is just contended right now". */
static void posture_fill_busy_partial(struct agent_security_posture *out,
                                      const char *status,
                                      const char *next_action)
{
    out->node_db_available = false;
    out->served_from_cache = true;
    out->cache_age_ms = -1;
    posture_str(out->status, sizeof(out->status), status);
    posture_str(out->next_action, sizeof(out->next_action), next_action);
    posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                "unknown_db_busy");
    posture_str(out->full_history_validation_state,
                sizeof(out->full_history_validation_state),
                "unknown_db_busy");
}

static void posture_collect_bootstrap(struct agent_security_posture *out,
                                      struct node_db *ndb)
{
    struct chain_evidence_controller cec;
    struct chain_evidence_controller_view view;

    if (!out)
        return;
    if (!ndb)
        ndb = app_runtime_node_db();
    out->node_db_available = ndb != NULL;
    if (!ndb) {
        posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                    "unknown_no_node_db");
        posture_str(out->full_history_validation_state,
                    sizeof(out->full_history_validation_state),
                    "unknown_no_node_db");
        return;
    }

    /* This function holds sqlite3_db_mutex across the bounded bootstrap
     * snapshot. A mutating CEC initializer can submit a DB-service write and
     * wait for the worker that is itself waiting on this mutex. Observation
     * must therefore use the explicitly read-only binding. */
    chain_evidence_controller_init_readonly(&cec, ndb, csr_instance());
    chain_evidence_controller_snapshot(&cec, &view);
    out->snapshot_anchor_height = view.snapshot_anchor_height;
    out->background_validation_height = view.background_validation_height;
    out->snapshot_evidence_present =
        view.snapshot_evidence_loaded &&
        (view.snapshot_anchor_height >= 0 ||
         view.snapshot_evidence.source_class == CEC_SOURCE_CLASS_SNAPSHOT ||
         view.snapshot_evidence.full_validation_complete);
    out->snapshot_full_validation_complete =
        view.state == CEC_FULLY_VALIDATED &&
        view.snapshot_evidence_loaded &&
        view.full_validation_origin ==
            CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT &&
        view.snapshot_evidence.full_validation_complete;
    posture_str(out->full_history_validation_origin,
                sizeof(out->full_history_validation_origin),
                chain_evidence_full_validation_origin_name(
                    view.full_validation_origin));
    out->full_history_validation_complete =
        view.state == CEC_FULLY_VALIDATED &&
        (view.full_validation_origin ==
             CEC_FULL_VALIDATION_GENESIS_HISTORY ||
         (view.full_validation_origin ==
              CEC_FULL_VALIDATION_ASSISTED_SNAPSHOT &&
          out->snapshot_full_validation_complete));
    out->snapshot_utxo_sha3_verified =
        view.snapshot_evidence.utxo_sha3_verified;
    out->snapshot_flyclient_verified =
        view.snapshot_evidence.mmb_flyclient_proof_verified;
    out->snapshot_chunk_hash_coverage_verified =
        view.snapshot_evidence.chunk_hash_coverage_verified;
    out->trusted_state_present =
        out->snapshot_evidence_present &&
        !out->snapshot_full_validation_complete;

    if (out->full_history_validation_complete &&
        view.full_validation_origin ==
            CEC_FULL_VALIDATION_GENESIS_HISTORY) {
        posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                    "genesis_full_history_validated");
        posture_str(out->full_history_validation_state,
                    sizeof(out->full_history_validation_state), "complete");
    } else if (out->snapshot_full_validation_complete) {
        posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                    "assisted_snapshot_promoted_by_full_history_validation");
        posture_str(out->full_history_validation_state,
                    sizeof(out->full_history_validation_state), "complete");
    } else if (out->snapshot_evidence_present) {
        posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                    "assisted_snapshot_chain_location_verified");
        posture_str(out->full_history_validation_state,
                    sizeof(out->full_history_validation_state),
                    "snapshot_seed_not_from_genesis_verified");
    } else {
        posture_str(out->bootstrap_model, sizeof(out->bootstrap_model),
                    "no_snapshot_evidence_recorded");
        posture_str(out->full_history_validation_state,
                    sizeof(out->full_history_validation_state),
                    "unknown_no_snapshot_evidence");
    }
}

static void posture_collect_anchors(struct agent_security_posture *out,
                                    sqlite3 *db)
{
    bool sprout_found = false;
    bool sapling_found = false;

    if (!out)
        return;
    if (!db) {
        posture_str(out->anchor_history_state,
                    sizeof(out->anchor_history_state),
                    "unknown_no_progress_store");
        return;
    }
    bool read_ok = anchor_kv_activation_cursor(
        db, ANCHOR_POOL_SPROUT,
        &out->sprout_anchor_activation_cursor, &sprout_found) &&
        anchor_kv_activation_cursor(
            db, ANCHOR_POOL_SAPLING,
            &out->sapling_anchor_activation_cursor, &sapling_found);
    if (!read_ok) {
        posture_str(out->anchor_history_state,
                    sizeof(out->anchor_history_state),
                    "unknown_activation_read_failed");
        return;
    }

    out->anchor_cursor_known = sprout_found && sapling_found;
    out->anchor_backfill_gap =
        !out->anchor_cursor_known ||
        out->sprout_anchor_activation_cursor > 0 ||
        out->sapling_anchor_activation_cursor > 0 ||
        blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    out->anchor_history_complete =
        out->anchor_cursor_known && !out->anchor_backfill_gap;
    posture_str(out->anchor_history_state,
                sizeof(out->anchor_history_state),
                !out->anchor_cursor_known
                    ? "unknown_missing_activation_provenance"
                    : out->anchor_backfill_gap
                        ? "gap_below_activation_cursor"
                        : "complete_from_genesis_or_backfilled");
}

static void posture_collect_nullifiers(struct agent_security_posture *out,
                                       sqlite3 *db)
{
    bool found = false;
    int64_t cursor = -1;

    if (!out)
        return;
    out->progress_store_available = db != NULL;
    if (!out->progress_store_available) {
        posture_str(out->nullifier_history_state,
                    sizeof(out->nullifier_history_state),
                    "unknown_no_progress_store");
        return;
    }
    bool read_ok = nullifier_kv_activation_cursor(db, &cursor, &found);
    if (!read_ok) {
        posture_str(out->nullifier_history_state,
                    sizeof(out->nullifier_history_state),
                    "unknown_activation_read_failed");
        return;
    }
    out->nullifier_cursor_known = found;
    out->nullifier_activation_cursor = found ? cursor : -1;
    out->nullifier_backfill_gap = !found || cursor > 0 ||
        blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    out->nullifier_history_complete = !out->nullifier_backfill_gap;
    posture_str(out->nullifier_history_state,
                sizeof(out->nullifier_history_state),
                !out->nullifier_cursor_known
                    ? "unknown_missing_activation_provenance"
                    : out->nullifier_backfill_gap
                        ? "gap_below_activation_cursor"
                        : "complete_from_genesis_or_backfilled");
}

static void posture_finalize(struct agent_security_posture *out)
{
    if (!out)
        return;
    out->review_required =
        !out->node_db_available ||
        !out->progress_store_available ||
        out->trusted_state_present ||
        !out->full_history_validation_complete ||
        !out->anchor_cursor_known ||
        out->anchor_backfill_gap ||
        !out->anchor_history_complete ||
        !out->nullifier_cursor_known ||
        out->nullifier_backfill_gap ||
        !out->nullifier_history_complete;

    if (out->anchor_backfill_gap) {
        posture_str(out->status, sizeof(out->status),
                    "review_required_anchor_backfill_gap");
        posture_str(out->next_action, sizeof(out->next_action),
                    "run_shielded_history_backfill_or_from_genesis_refold");
    } else if (out->nullifier_backfill_gap) {
        posture_str(out->status, sizeof(out->status),
                    "review_required_nullifier_backfill_gap");
        posture_str(out->next_action, sizeof(out->next_action),
                    "run_shielded_history_backfill_or_from_genesis_refold");
    } else if (!out->node_db_available || !out->progress_store_available ||
               !out->anchor_cursor_known || !out->nullifier_cursor_known) {
        posture_str(out->status, sizeof(out->status),
                    "review_required_unknown");
        posture_str(out->next_action, sizeof(out->next_action),
                    "query_running_node_datadir_security_posture");
    } else if (out->trusted_state_present ||
               !out->full_history_validation_complete) {
        posture_str(out->status, sizeof(out->status),
                    "review_required_bootstrap_trust");
        posture_str(out->next_action, sizeof(out->next_action),
                    "finish_sovereign_refold_and_full_history_validation");
    } else {
        posture_str(out->status, sizeof(out->status), "ok");
        posture_str(out->next_action, sizeof(out->next_action), "none");
    }
}

void agent_security_posture_collect(struct agent_security_posture *out,
                                    struct node_db *ndb)
{
    struct agent_security_posture empty = {0};
    sqlite3 *progress_reader = NULL;
    struct node_db *resolved_ndb;
    bool ndb_locked;

    if (!out)
        return;
    *out = empty;
    out->snapshot_anchor_height = -1;
    out->background_validation_height = -1;
    out->sprout_anchor_activation_cursor = -1;
    out->sapling_anchor_activation_cursor = -1;
    out->nullifier_activation_cursor = -1;

    resolved_ndb = ndb ? ndb : app_runtime_node_db();

    /* If a long maintenance op holds the shared node.db connection, every read
     * below would serialize behind it (once observed at ~11 minutes). Route
     * around it: serve the last live snapshot so status never goes dark. */
    if (node_db_long_op_active(NULL, NULL)) {
        if (posture_cache_load(out))
            return;
        /* No snapshot has ever been published (e.g. maintenance at first boot).
         * Answer truthfully rather than block: name the maintenance state and
         * do NOT invent a review gate — the caller's db_maintenance field and
         * the typed blocker carry the maintenance signal. Cache the partial
         * too (labeled) so a sustained outage's later calls warm from this
         * instead of recomputing the identical placeholder every time; the
         * moment a real collect succeeds it overwrites this unconditionally
         * (this branch never fires again once posture_cache_load() above
         * finds a valid entry). */
        posture_fill_busy_partial(out, "db_maintenance_in_progress",
                                  "wait_db_maintenance");
        posture_cache_store(out);
        return;
    }

    /* Ordinary write contention: no NAMED long op is running, so the check
     * above sees nothing, but the shared connection may still be held by a
     * writer mid-SQLITE_BUSY-retry (see posture_ndb_try_lock's doc comment).
     * Try, don't wait: on a miss, serve the last-known-good snapshot (or a
     * labeled busy partial the first time) instead of queuing behind it. */
    ndb_locked = posture_ndb_try_lock(resolved_ndb);
    if (resolved_ndb && !ndb_locked) {
        if (posture_cache_load(out))
            return;
        posture_fill_busy_partial(out, "posture_unavailable_busy",
                                  "retry_status_query");
        posture_cache_store(out);
        return;
    }

    posture_collect_bootstrap(out, resolved_ndb);
    if (ndb_locked)
        posture_ndb_unlock(resolved_ndb);
    progress_reader = progress_store_open_reader();
    out->progress_store_available = progress_reader != NULL;
    posture_collect_anchors(out, progress_reader);
    posture_collect_nullifiers(out, progress_reader);
    if (progress_reader)
        sqlite3_close(progress_reader);
    posture_finalize(out);
    posture_cache_store(out);
#ifdef ZCL_TESTING
    int override = atomic_load(&g_test_review_required);
    if (override >= 0) {
        out->review_required = override != 0;
        posture_str(out->status, sizeof(out->status),
                    out->review_required ? "review_required_test" : "ok");
        posture_str(out->next_action, sizeof(out->next_action),
                    out->review_required ? "test_review" : "none");
    }
#endif
}

bool agent_security_posture_allows_public_serving(
    const struct agent_security_posture *posture)
{
    return posture && !posture->review_required;
}

void agent_push_security_posture_snapshot_json(
    struct json_value *out, const char *key,
    const struct agent_security_posture *posture)
{
    struct json_value obj = {0};

    if (!out || !posture)
        return;
    json_set_object(&obj);
    json_push_kv_str(&obj, "schema", "zcl.security_posture.v1");
    json_push_kv_int(&obj, "schema_version", 1);
    json_push_kv_str(&obj, "status", posture->status);
    json_push_kv_bool(&obj, "review_required", posture->review_required);
    json_push_kv_bool(&obj, "public_serving_allowed",
        agent_security_posture_allows_public_serving(posture));
    /* Never serve stale/partial posture silently: a busy-partial or
     * last-known-good snapshot always carries served_from_cache=true plus
     * its age (or -1 the first time, before anything has ever been cached),
     * so any caller embedding this object sees the same freshness label the
     * "agent"/status front door surfaces at its top level (source/age_ms —
     * see event_agent_summary.c). A live collection leaves these false/0. */
    json_push_kv_bool(&obj, "served_from_cache", posture->served_from_cache);
    json_push_kv_int(&obj, "cache_age_ms", posture->cache_age_ms);
    json_push_kv_bool(&obj, "node_db_available", posture->node_db_available);
    json_push_kv_bool(&obj, "progress_store_available",
                      posture->progress_store_available);
    json_push_kv_str(&obj, "bootstrap_model", posture->bootstrap_model);
    json_push_kv_bool(&obj, "snapshot_evidence_present",
                      posture->snapshot_evidence_present);
    json_push_kv_bool(&obj, "trusted_state_present",
                      posture->trusted_state_present);
    json_push_kv_int(&obj, "snapshot_anchor_height",
                     posture->snapshot_anchor_height);
    json_push_kv_int(&obj, "background_validation_height",
                     posture->background_validation_height);
    json_push_kv_bool(&obj, "snapshot_full_validation_complete",
                      posture->snapshot_full_validation_complete);
    json_push_kv_bool(&obj, "full_history_validation_complete",
                      posture->full_history_validation_complete);
    json_push_kv_str(&obj, "full_history_validation_origin",
                     posture->full_history_validation_origin);
    json_push_kv_bool(&obj, "snapshot_utxo_sha3_verified",
                      posture->snapshot_utxo_sha3_verified);
    json_push_kv_bool(&obj, "snapshot_flyclient_verified",
                      posture->snapshot_flyclient_verified);
    json_push_kv_bool(&obj, "snapshot_chunk_hash_coverage_verified",
                      posture->snapshot_chunk_hash_coverage_verified);
    json_push_kv_str(&obj, "full_history_validation_state",
                     posture->full_history_validation_state);
    json_push_kv_bool(&obj, "anchor_cursor_known",
                      posture->anchor_cursor_known);
    json_push_kv_int(&obj, "sprout_anchor_activation_cursor",
                     posture->sprout_anchor_activation_cursor);
    json_push_kv_int(&obj, "sapling_anchor_activation_cursor",
                     posture->sapling_anchor_activation_cursor);
    json_push_kv_bool(&obj, "anchor_history_complete",
                      posture->anchor_history_complete);
    json_push_kv_bool(&obj, "anchor_backfill_gap",
                      posture->anchor_backfill_gap);
    json_push_kv_str(&obj, "anchor_history_state",
                     posture->anchor_history_state);
    json_push_kv_bool(&obj, "nullifier_cursor_known",
                      posture->nullifier_cursor_known);
    json_push_kv_int(&obj, "nullifier_activation_cursor",
                     posture->nullifier_activation_cursor);
    json_push_kv_bool(&obj, "nullifier_history_complete",
                      posture->nullifier_history_complete);
    json_push_kv_bool(&obj, "nullifier_backfill_gap",
                      posture->nullifier_backfill_gap);
    json_push_kv_str(&obj, "nullifier_history_state",
                     posture->nullifier_history_state);
    json_push_kv_str(&obj, "next_action", posture->next_action);
    json_push_kv_str(&obj, "semantics",
                     "public serving and healthy fail closed while bootstrap "
                     "or shielded-history trust requires review");
    json_push_kv(out, key && key[0] ? key : "security_posture", &obj);
    json_free(&obj);
}

void agent_push_security_posture_json(struct json_value *out, const char *key,
                                      struct node_db *ndb)
{
    struct agent_security_posture posture;
    if (!out)
        return;
    agent_security_posture_collect(&posture, ndb);
    agent_push_security_posture_snapshot_json(out, key, &posture);
}

#ifdef ZCL_TESTING
void agent_security_posture_test_override_review_required(int required)
{
    atomic_store(&g_test_review_required,
                 required < 0 ? -1 : (required != 0));
}
#endif
