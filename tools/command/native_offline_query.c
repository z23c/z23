/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OFFLINE_COPY native leaves: inspect a STOPPED or COPIED datadir's SQLite
 * stores directly, with NO node contact and NO RPC.
 *
 * The gap this closes: `core.storage.query` (dbquery_controller.c) is
 * scoped to a RUNNING node's RPC only, and `dumpstate reducer_frontier`
 * likewise answers only for the live process. Neither can answer "what's
 * H* in this datadir I just copied off a stalled node?" without booting a
 * full second node against it. `tools/sqlq.c` exists precisely for this
 * ("cannot reach a copied fixture datadir") but is an unregistered raw
 * binary requiring hand-known table/column names — the enum value
 * ZCL_COMMAND_SCOPE_OFFLINE_COPY (engine/modules/kernel/include/kernel/command_
 * registry.h) has existed with zero leaves using it until this file.
 *
 * The leaves below open an AD HOC handle straight at the caller-supplied
 * `--datadir=<path>` and run the SAME production primitive a live node
 * would use — dbquery_execute() for storage.query.offline,
 * reducer_frontier_compute_hstar() for sync.frontier.offline — so the
 * safety envelope (SELECT-only, no secrets, budget/row caps for the
 * former; the pure L0 H* fold for the latter) is identical to the
 * RPC-backed leaves, just without requiring a booted node. The one
 * write-scoped exception is producer-session.retire: an OFFLINE operator
 * mutation of a FOREIGN start session, refuse-gated on node liveness and
 * on the retire primitive's own build-identity match. */

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "config/consensus_state_producer_receipt.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/rpc_client.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "json/json.h"
#include "models/database.h"
#include "services/sync_trust_policy.h"
#include "storage/coins_kv.h"
#include "storage/consensus_db.h"
#include "storage/progress_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ── core.storage.query.offline ──────────────────────────────────────── */

void zcl_native_handle_core_storage_query_offline(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given", "core.storage.query.offline");
        return;
    }
    const char *sql = json_get_str(json_get(request->input, "sql"));
    int64_t limit = json_get_int_or(request->input, "limit", 10);

    /* The shared read-only open (command/native_command.h): READONLY, no
     * CREATE, so a missing node.db fails closed rather than silently
     * creating one, plus PRAGMA query_only as a second refusal of any
     * write — the same story tools/sqlq.c's xck_open_ro() serves. */
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "this datadir's node.db",
                                             &db, &ndb))
        return;
    /* Copied BEFORE the close: the shim's path field is cleared with it. */
    char path[sizeof(ndb.path)];
    snprintf(path, sizeof(path), "%s", ndb.path);

    struct json_value result;
    json_init(&result);
    bool ok = dbquery_execute(db, sql, limit, &result);
    zcl_native_node_db_close_readonly(&db, &ndb);

    if (!ok) {
        const char *msg = json_get_str(&result);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "QUERY_REJECTED",
                               "execute", false, false,
                               msg && msg[0] ? msg : "query rejected", path);
        json_free(&result);
        return;
    }

    (void)json_push_kv_str(&result, "datadir", datadir);
    json_copy(&reply->data, &result);
    json_free(&result);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.storage.schema.offline ─────────────────────────────────────── */

/* Builds "<datadir>/node.db" into path (path_cap bytes); on overflow or a
 * snprintf failure, replies FAILED itself and returns false. Split out of
 * zcl_native_handle_core_storage_schema_offline() to keep that leaf's own
 * cyclomatic complexity low. */
static bool schema_offline_resolve_path(const char *datadir,
                                        struct zcl_command_reply *reply,
                                        char *path, size_t path_cap)
{
    int n = snprintf(path, path_cap, "%s/node.db", datadir);
    if (n <= 0 || (size_t)n >= path_cap) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "DATADIR_PATH_TOO_LONG", "normalize", false,
                               false, "datadir path too long", datadir);
        return false;
    }
    return true;
}

/* Runs the read-only schema preflight against path and turns its three
 * non-classifiable outcomes (report call itself failed, no node.db yet,
 * an unrecognized schema marker) into the typed reply each already has a
 * name for; on any of those replies itself and returns false. */
static bool schema_offline_get_report(const char *path,
                                      struct zcl_command_reply *reply,
                                      struct node_db_schema_report *rep)
{
    if (!node_db_schema_report_for_path(path, rep)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "SCHEMA_REPORT_FAILED", "execute", false,
                               false, "schema classification failed", path);
        return false;
    }
    if (rep->fresh) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "NODE_DB_NOT_FOUND",
                               "execute", true, false,
                               "no existing node.db at this datadir to "
                               "classify — boot a node here once first",
                               path);
        return false;
    }
    if (rep->unknown) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "SCHEMA_VERSION_UNKNOWN", "execute", true,
                               false,
                               rep->detail && rep->detail[0]
                                   ? rep->detail
                                   : "node.db schema could not be classified",
                               path);
        return false;
    }
    return true;
}

static const char *schema_offline_verdict_name(
    enum node_db_schema_verdict verdict)
{
    switch (verdict) {
    case NODE_DB_SCHEMA_VERDICT_SAME:
        return "same";
    case NODE_DB_SCHEMA_VERDICT_DOWNGRADE_OK:
        return "downgrade_ok";
    case NODE_DB_SCHEMA_VERDICT_DOWNGRADE_REFUSED:
        return "downgrade_refused";
    case NODE_DB_SCHEMA_VERDICT_UPGRADE:
    default:
        return "upgrade";
    }
}

void zcl_native_handle_core_storage_schema_offline(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given",
                               "core.storage.schema.offline");
        return;
    }

    char path[1200];
    if (!schema_offline_resolve_path(datadir, reply, path, sizeof(path)))
        return;

    /* node_db_schema_report_for_path is the read-only preflight (never
     * create, migrate, or write) so this answers even when the live node
     * would refuse to boot against the same file. */
    struct node_db_schema_report rep;
    if (!schema_offline_get_report(path, reply, &rep))
        return;

    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_str(&reply->data, "node_db", path);
    (void)json_push_kv_int(&reply->data, "schema_version", rep.schema_version);
    (void)json_push_kv_int(&reply->data, "schema_compat_floor",
                           rep.schema_compat_floor);
    (void)json_push_kv_int(&reply->data, "node_db_max_schema",
                           NODE_DB_MAX_SCHEMA);
    (void)json_push_kv_str(&reply->data, "verdict",
                           schema_offline_verdict_name(rep.verdict));
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.sync.frontier.offline ──────────────────────────────────────── */

/* Opens this datadir's kernel store read-only for the frontier leaf below;
 * on any non-OK status writes the typed reply that status already has a
 * name for and returns false. Split out of
 * zcl_native_handle_core_sync_frontier_offline() to keep that leaf's own
 * cyclomatic complexity low. */
static bool frontier_offline_open_kernel_store(
    const char *datadir, struct zcl_command_reply *reply, sqlite3 **db_out,
    char *kernel_path, size_t kernel_path_cap)
{
    /* The shared read-only kernel-store open (command/native_command.h).
     *
     * This leaf used to call progress_store_open(datadir), which is
     * READWRITE|CREATE, runs the progress.kv rename migration, ensures the
     * kernel schema, and — on a failed integrity check — rename()s
     * consensus.db aside to consensus.db.corrupt-<ts> and installs a fresh
     * empty one. So a question about a copied datadir ("what is H* here?")
     * could answer by DESTROYING the append-only fact log it was asked
     * about, and an operator file that merely happened to sit at that path
     * was quarantined outright. Read-only closes all of it: no CREATE (a
     * mistyped datadir fails instead of minting an empty store and reporting
     * a meaningless H*=0), no migration, no schema ensure, no quarantine —
     * and no claim on the process singleton either. */
    enum zcl_node_db_ro_status ro_st = zcl_native_kernel_store_open_readonly(
        datadir, db_out, kernel_path, kernel_path_cap);
    if (ro_st == ZCL_NODE_DB_RO_OK)
        return true;
    switch (ro_st) {
    case ZCL_NODE_DB_RO_PATH_TOO_LONG:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "DATADIR_PATH_TOO_LONG", "normalize", false,
                               false, "datadir path too long", datadir);
        return false;
    case ZCL_NODE_DB_RO_ABSENT:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "KERNEL_STORE_NOT_FOUND", "execute", true,
                               false,
                               "no consensus.db/progress.kv at this "
                               "datadir", kernel_path);
        return false;
    case ZCL_NODE_DB_RO_UNREADABLE:
    case ZCL_NODE_DB_RO_NO_DATADIR:
    default:
        /* Distinct from NOT_FOUND on purpose: the file IS there and
         * would not open read-only, which is never the same answer as
         * "this datadir has no kernel store". */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "KERNEL_STORE_UNAVAILABLE", "execute", true,
                               false,
                               "the kernel store at this datadir exists "
                               "but would not open read-only", kernel_path);
        return false;
    }
}

/* Folds H* under the lock the fold's contract demands; on failure closes
 * db, writes the HSTAR_COMPUTE_FAILED reply and returns false. Split out
 * of zcl_native_handle_core_sync_frontier_offline() to keep that leaf's
 * own cyclomatic complexity low. */
static bool frontier_offline_compute_hstar(
    sqlite3 *db, struct zcl_command_reply *reply, const char *kernel_path,
    int32_t *hstar, int32_t *served_floor)
{
    /* reducer_frontier_compute_hstar's documented contract is that the caller
     * holds this lock; honoured even though `db` is this call's own private
     * handle and not the singleton, so the contract cannot rot if the fold
     * ever reaches a helper that assumes it. */
    progress_store_tx_lock();
    bool ok = reducer_frontier_compute_hstar(db, hstar, served_floor);
    progress_store_tx_unlock();

    if (!ok) {
        sqlite3_close(db);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "HSTAR_COMPUTE_FAILED", "execute", false,
                               false,
                               "reducer_frontier_compute_hstar failed",
                               kernel_path);
        return false;
    }
    return true;
}

/* The derived outputs of the static spend-gate half, bundled so the
 * derivation and the report below can each stay a single small function. */
struct frontier_offline_static_trust {
    int32_t applied_height;
    bool applied_found;
    bool applied_read_ok;
    bool proven;
    bool refold;
    bool static_self_derived;
    char self_derived_reason[96];
    enum sync_trust_state trust_state;
    bool spend_allowed;
};

/* Report the exact STATIC half of the spend gate from this copied store.
 * This is deliberately derived through the same coins_kv predicates and
 * sync-trust capability table as the live sovereignty controller, never
 * from filenames or a hand-maintained approximation.  G-SOV part 1 (the
 * required two-sample H* climb) remains a runtime/copy-proof obligation,
 * so the field names say `static`: this leaf must not turn one stopped
 * snapshot into a claim that a live node is safe to spend from. */
static void frontier_offline_derive_static_trust(
    sqlite3 *db, int32_t hstar, struct frontier_offline_static_trust *out)
{
    out->applied_height = -1;
    out->applied_found = false;
    out->applied_read_ok = coins_kv_get_applied_height(
        db, &out->applied_height, &out->applied_found);
    out->proven = coins_kv_is_proven_authority(db, NULL);
    out->refold = coins_kv_contains_refold_marker(db);
    memset(out->self_derived_reason, 0, sizeof(out->self_derived_reason));
    out->static_self_derived = coins_kv_tip_is_self_derived(
        db, hstar, out->self_derived_reason,
        sizeof(out->self_derived_reason));
    out->trust_state = sync_trust_derive(out->proven, out->refold,
                                         out->static_self_derived);
    out->spend_allowed = sync_trust_cap_allowed(out->trust_state,
                                                SYNC_CAP_WALLET_SPEND);
}

/* Pushes the frontier leaf's full reply body from the folded H* and the
 * derived static trust. Split out of
 * zcl_native_handle_core_sync_frontier_offline() to keep that leaf's own
 * cyclomatic complexity low. */
static void frontier_offline_push_report(
    struct zcl_command_reply *reply, const char *datadir,
    const char *kernel_path, int32_t hstar, int32_t served_floor,
    const struct frontier_offline_static_trust *trust)
{
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_str(&reply->data, "kernel_store", kernel_path);
    (void)json_push_kv_int(&reply->data, "hstar", hstar);
    (void)json_push_kv_int(&reply->data, "served_floor", served_floor);
    (void)json_push_kv_int(&reply->data, "compiled_anchor",
                           REDUCER_FRONTIER_TRUSTED_ANCHOR);
    (void)json_push_kv_bool(&reply->data, "refold_in_progress",
                            refold_in_progress());
    (void)json_push_kv_bool(&reply->data, "coins_applied_height_known",
                            trust->applied_read_ok && trust->applied_found);
    if (trust->applied_read_ok && trust->applied_found)
        (void)json_push_kv_int(&reply->data, "coins_applied_height",
                               trust->applied_height);
    (void)json_push_kv_bool(&reply->data, "proven_authority", trust->proven);
    (void)json_push_kv_bool(&reply->data, "self_folded_marker", trust->refold);
    (void)json_push_kv_bool(&reply->data, "static_self_derived",
                            trust->static_self_derived);
    (void)json_push_kv_str(&reply->data, "static_self_derived_reason",
                           trust->static_self_derived ? "ok" :
                           (trust->self_derived_reason[0] ?
                            trust->self_derived_reason : "not_self_derived"));
    (void)json_push_kv_str(&reply->data, "static_trust_state",
                           sync_trust_state_name(trust->trust_state));
    (void)json_push_kv_bool(&reply->data, "wallet_spend_static_allowed",
                            trust->spend_allowed);
    (void)json_push_kv_str(&reply->data, "wallet_spend_static_reason",
                           trust->spend_allowed ? "granted" :
                           (trust->self_derived_reason[0] ?
                            trust->self_derived_reason :
                            "trust_state_denied"));
    (void)json_push_kv_str(&reply->data, "runtime_proof_required",
                           "two_sample_hstar_climb_and_current_money_snapshot");
}

void zcl_native_handle_core_sync_frontier_offline(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given", "core.sync.frontier.offline");
        return;
    }

    sqlite3 *db = NULL;
    char kernel_path[1200];
    if (!frontier_offline_open_kernel_store(datadir, reply, &db, kernel_path,
                                            sizeof(kernel_path)))
        return;

    /* A one-shot native CLI process has no app_init(): reducer_frontier_
     * compute_hstar() reads the compiled anchor via chain_params_get(),
     * which asserts pCurrentParams non-NULL — fatal if nothing ever called
     * chain_params_select() (the RPC bridge path selects it in
     * bridge_ensure_rpc_client(); this OFFLINE_COPY path never goes through
     * the bridge, so it must select for itself). Idempotent — safe even if
     * something upstream already selected. Mainnet-only: the offline-copy
     * story targets mainnet datadirs; a testnet/regtest copy would need a
     * network hint this leaf does not yet accept. */
    chain_params_select(CHAIN_MAIN);

    /* Refresh the process-wide refold-in-progress cache from THIS datadir's
     * OWN persisted progress_meta before folding — without this the cache
     * defaults conservatively to "not refolding", which would misreport a
     * copied mid-refold datadir's H* floor. See refold_progress.h. */
    (void)refold_progress_refresh(db);

    int32_t hstar = 0, served_floor = 0;
    if (!frontier_offline_compute_hstar(db, reply, kernel_path, &hstar,
                                        &served_floor))
        return;

    struct frontier_offline_static_trust trust;
    frontier_offline_derive_static_trust(db, hstar, &trust);
    frontier_offline_push_report(reply, datadir, kernel_path, hstar,
                                 served_floor, &trust);
    sqlite3_close(db);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── core.consensus.producer-session.retire ─────────────────────────── */

/* Writes the NODE_RUNNING refusal and returns true when something is
 * listening on this datadir's RPC port; returns false when retirement may
 * proceed. Split out of
 * zcl_native_handle_core_consensus_producer_session_retire() to keep that
 * leaf's own cyclomatic complexity low. */
static bool producer_session_retire_refuse_live_node(
    const struct zcl_command_request *request, const char *datadir,
    struct zcl_command_reply *reply)
{
    /* Retirement is an OFFLINE act against a stopped datadir. A live node's
     * exporter may own exactly the session being deleted, so when something
     * is listening on this datadir's RPC port, refuse and name the remedy.
     * The probe is the socket-level oracle, NOT node_rpc_call*: every call
     * variant returns a non-NULL self-describing error body when the connect
     * is refused, so "any reply means running" reads a stopped node as live
     * (that exact false positive blocked a real deploy). Cookie presence
     * gates the probe — no port inventable beyond the explicit input / CLI
     * binding — because the decisive ownership test is the retire
     * primitive's own build-identity match: it refuses to touch a session
     * this very binary owns, which is the case where a mid-run delete would
     * actually bite. */
    char cookie_path[1200];
    if (snprintf(cookie_path, sizeof(cookie_path), "%s/.cookie", datadir) <
            (int)sizeof(cookie_path) &&
        access(cookie_path, F_OK) == 0) {
        int64_t given_port = json_get_int_or(request->input, "rpc_port", 0);
        int port = given_port > 0 && given_port <= 65535
                       ? (int)given_port
                       : zcl_native_command_rpc_port();
        if (port > 0 && node_rpc_port_listening(port, 250)) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_BLOCKED, "NODE_RUNNING", "normalize",
                true, false,
                "a node is listening on this datadir's RPC port — stop it "
                "first; retirement is offline and the exporter requalifies "
                "at next boot", datadir);
            return true;
        }
    }
    return false;
}

/* Opens this datadir's kernel store for the retire; on any failure writes
 * the typed reply that failure already has a name for and returns NULL.
 * Split out of zcl_native_handle_core_consensus_producer_session_retire()
 * to keep that leaf's own cyclomatic complexity low. */
static sqlite3 *producer_session_retire_open_store(
    const char *datadir, char *kernel_path, size_t kernel_path_cap,
    struct zcl_command_reply *reply)
{
    /* Read-write, but NO CREATE: retiring is meaningless against a datadir
     * with no kernel store, and a mistyped path must fail closed instead of
     * minting an empty consensus.db. */
    if (!consensus_db_kernel_store_path(datadir, kernel_path,
                                        kernel_path_cap)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "DATADIR_PATH_TOO_LONG", "normalize", false,
                               false, "datadir path too long", datadir);
        return NULL;
    }
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(kernel_path, &db, SQLITE_OPEN_READWRITE, NULL) !=
        SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "KERNEL_STORE_NOT_FOUND", "execute", true,
                               false,
                               "no consensus.db/progress.kv at this datadir "
                               "to retire a session from",
                               kernel_path);
        return NULL;
    }
    return db;
}

/* Turns the retire primitive's result into the reply each outcome already
 * has a name for: the RETIRED evidence body, or the typed failure.
 * Split out of zcl_native_handle_core_consensus_producer_session_retire()
 * to keep that leaf's own cyclomatic complexity low. */
static void producer_session_retire_reply_result(
    struct zcl_command_reply *reply,
    enum consensus_state_producer_session_retire_result r,
    const struct consensus_state_producer_session_retired *evidence,
    const char *why, const char *datadir, const char *kernel_path)
{
    switch (r) {
    case CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_RETIRED:
        (void)json_push_kv_str(&reply->data, "datadir", datadir);
        (void)json_push_kv_str(&reply->data, "kernel_store", kernel_path);
        (void)json_push_kv_str(&reply->data, "retired_running_binary_digest",
                               evidence->running_binary_digest);
        (void)json_push_kv_str(&reply->data, "retired_source_tree_root",
                               evidence->source_tree_root);
        (void)json_push_kv_str(&reply->data, "retired_source_epoch_digest",
                               evidence->source_epoch_digest);
        (void)json_push_kv_int(&reply->data, "retired_validation_profile",
                               evidence->validation_profile);
        (void)json_push_kv_int(&reply->data, "retired_started_us",
                               evidence->started_us);
        (void)json_push_kv_bool(&reply->data, "restart_required", true);
        (void)json_push_kv_str(
            &reply->data, "remedy",
            "foreign session retired; the next boot's begin() inserts a "
            "fresh session owned by that build and the exporter "
            "requalifies");
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        reply->exit_code = ZCL_COMMAND_EXIT_OK;
        return;
    case CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ABSENT:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "SESSION_ABSENT",
                               "execute", true, false,
                               "no producer session in this datadir — "
                               "nothing to retire",
                               kernel_path);
        return;
    case CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_CURRENT:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "SESSION_CURRENT",
                               "execute", false, false,
                               why[0] ? why : "stored session matches this "
                                              "running build",
                               kernel_path);
        return;
    case CONSENSUS_STATE_PRODUCER_SESSION_RETIRE_ERROR:
    default:
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RETIRE_FAILED",
                               "execute", false, false,
                               why[0] ? why : "producer session retire "
                                              "failed",
                               kernel_path);
        return;
    }
}

void zcl_native_handle_core_consensus_producer_session_retire(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given",
                               "core.consensus.producer-session.retire");
        return;
    }

    if (producer_session_retire_refuse_live_node(request, datadir, reply))
        return;

    char kernel_path[1200];
    sqlite3 *db = producer_session_retire_open_store(
        datadir, kernel_path, sizeof(kernel_path), reply);
    if (!db)
        return;

    struct consensus_state_producer_session_retired evidence;
    char why[256];
    enum consensus_state_producer_session_retire_result r =
        consensus_state_producer_session_retire(db, &evidence, why,
                                                sizeof(why));
    sqlite3_close(db);

    producer_session_retire_reply_result(reply, r, &evidence, why, datadir,
                                         kernel_path);
}
