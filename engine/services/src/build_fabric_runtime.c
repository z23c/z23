/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-loud liveness contracts for build scheduling and workers. */

#include "services/build_fabric_runtime.h"

#include "base/hex.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_worker.h"
#include "services/subordinate_work_admission.h"

#include "config/runtime.h"
#include "json/json.h"
#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "platform/time_compat.h"
#include "crypto/random_secret.h"
#include "supervisors/domains.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_qos.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

enum { BF_RUNTIME_JOB_LIMIT = 100 };
#define BF_RUNTIME_PERIOD_SECS 2
#define BF_RUNTIME_MAX_QUIET_US ((int64_t)120 * 1000 * 1000)

static struct liveness_contract g_requester_contract;
static struct liveness_contract g_worker_contract;
static _Atomic supervisor_child_id g_requester_id = SUPERVISOR_INVALID_ID;
static _Atomic supervisor_child_id g_worker_id = SUPERVISOR_INVALID_ID;
static _Atomic bool g_worker_enabled;
static _Atomic uint64_t g_requester_ticks;
static _Atomic uint64_t g_worker_ticks;
static _Atomic uint64_t g_jobs_active;
static _Atomic uint64_t g_actions_active;
static _Atomic uint64_t g_jobs_terminal;
static _Atomic uint64_t g_accepted_or_cache;
static _Atomic uint64_t g_leases_recovered;
static _Atomic uint64_t g_recovery_failures;
static _Atomic uint64_t g_worker_dispatches;
static _Atomic uint64_t g_worker_failures;
static _Atomic uint64_t g_worker_resource_deferrals;
static _Atomic int g_worker_admission_reason;
static struct db_build_worker g_local_worker;
static uint8_t g_local_secret[32];
static uint8_t g_local_pubkey[32];
static char g_worker_workspace[4096];
static char g_worker_datadir[4096];
static pthread_t g_worker_thread;
static _Atomic bool g_worker_started;

extern volatile sig_atomic_t g_shutdown_requested;

/* A live node can execute both requester-owned and peer-admitted actions.
 * Peer admission imports its immutable context into the node process
 * workspace. Requester admission instead records the originating project as
 * a local locator in the append-only proof projection. Resolve that locator
 * before executing; the action/task roots remain the authority and are
 * rechecked by build_fabric_worker_execute(). The short wait closes the
 * submit-to-REQUESTED handoff without making foreground admission wait for a
 * worker. */
static bool bf_runtime_execution_workspace(
    struct node_db *ndb, const struct db_build_action *action,
    char out[4096])
{
    if (!ndb || !action || !out) return false;
    if (action->task_root_sha3[0]) {
        for (unsigned int attempt = 0; attempt < 100u; attempt++) {
            struct db_build_proof_event event;
            if (db_build_proof_event_latest(ndb, action->action_id, &event) &&
                strcmp(event.task_root_sha3, action->task_root_sha3) == 0 &&
                strcmp(event.candidate_root_sha3,
                       action->candidate_root_sha3) == 0 &&
                strcmp(event.proof_policy_root_sha3,
                       action->proof_policy_root_sha3) == 0) {
                int n = snprintf(out, 4096, "%s", event.workspace);
                return n > 0 && n < 4096;
            }
            if (g_shutdown_requested) return false;
            platform_sleep_ms(10);
        }
    }
    int n = snprintf(out, 4096, "%s", g_worker_workspace);
    return n > 0 && n < 4096;
}

static bool bf_runtime_state_active(const char *state)
{
    return state && (strcmp(state, "QUEUED") == 0 ||
                     strcmp(state, "CLAIMED") == 0 ||
                     strcmp(state, "RUNNING") == 0 ||
                     strcmp(state, "VERIFYING") == 0);
}

static bool bf_runtime_state_terminal(const char *state)
{
    return state && (strcmp(state, "ACCEPTED") == 0 ||
                     strcmp(state, "CACHE_HIT") == 0 ||
                     strcmp(state, "LOCAL_FALLBACK") == 0 ||
                     strcmp(state, "DISPUTED") == 0 ||
                     strcmp(state, "CANCELLED") == 0 ||
                     strcmp(state, "FAILED") == 0);
}

static void bf_runtime_snapshot(uint64_t *active_jobs,
                                uint64_t *active_actions,
                                uint64_t *terminal_jobs,
                                uint64_t *accepted)
{
    *active_jobs = *active_actions = *terminal_jobs = *accepted = 0;
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !ndb->open) return;
    struct db_build_job jobs[BF_RUNTIME_JOB_LIMIT];
    int count = db_build_jobs_recent(ndb, jobs, BF_RUNTIME_JOB_LIMIT);
    for (int i = 0; i < count; i++) {
        if (bf_runtime_state_active(jobs[i].state)) (*active_jobs)++;
        if (bf_runtime_state_terminal(jobs[i].state)) (*terminal_jobs)++;
        if (strcmp(jobs[i].state, "ACCEPTED") == 0 ||
            strcmp(jobs[i].state, "CACHE_HIT") == 0) (*accepted)++;
        struct db_build_action actions[16];
        int action_count = db_build_job_actions(ndb, jobs[i].job_id,
                                                 actions, 16);
        for (int j = 0; j < action_count; j++)
            if (bf_runtime_state_active(actions[j].state)) (*active_actions)++;
    }
    atomic_store(&g_jobs_active, *active_jobs);
    atomic_store(&g_actions_active, *active_actions);
    atomic_store(&g_jobs_terminal, *terminal_jobs);
    atomic_store(&g_accepted_or_cache, *accepted);
}

static void bf_requester_tick(struct liveness_contract *contract)
{
    (void)contract;
    struct node_db *ndb = app_runtime_node_db();
    if (ndb && ndb->open) {
        size_t recovered = 0;
        struct zcl_result recovery = build_fabric_recover_expired(
            ndb, (int64_t)platform_time_wall_unix(), &recovered);
        if (recovery.ok)
            atomic_fetch_add(&g_leases_recovered, recovered);
        else {
            atomic_fetch_add(&g_recovery_failures, 1);
            LOG_WARN("build_fabric", "expired lease recovery failed: %s",
                     recovery.message);
        }
    }
    uint64_t active_jobs, active_actions, terminal_jobs, accepted;
    bf_runtime_snapshot(&active_jobs, &active_actions, &terminal_jobs, &accepted);
    supervisor_child_id id = atomic_load(&g_requester_id);
    if (active_jobs == 0) supervisor_progress_idle(id);
    else supervisor_progress(id, (int64_t)terminal_jobs);
    atomic_fetch_add(&g_requester_ticks, 1);
    supervisor_tick(id);
}

static void bf_worker_tick(struct liveness_contract *contract)
{
    (void)contract;
    uint64_t active_jobs, active_actions, terminal_jobs, accepted;
    bf_runtime_snapshot(&active_jobs, &active_actions, &terminal_jobs, &accepted);
    supervisor_child_id id = atomic_load(&g_worker_id);
    if (atomic_load(&g_worker_enabled)) {
        if (active_actions == 0) supervisor_progress_idle(id);
        else supervisor_progress(id, (int64_t)accepted);
    }
    atomic_fetch_add(&g_worker_ticks, 1);
    supervisor_tick(id);
}

static void *bf_worker_loop(void *arg)
{
    (void)arg;
    (void)zcl_thread_qos_background();
    /* The daemon's node.db has one mutable owner.  A second long-lived
     * sqlite connection in this thread used to look harmless, but its WAL
     * lifetime was independent of the boot connection: closing/restarting
     * peer workers could unlink the pathname while the canonical connection
     * still held the old inode.  The next action then failed with SQLITE_IOERR
     * even though both action and receipt identities were valid.
     *
     * The runtime handle is FULLMUTEX and remains alive until registered
     * workers have joined, so consume it directly.  This makes worker states
     * projections of the canonical action ledger and leaves exactly one WAL
     * authority in the process. */
    struct node_db *ndb = app_runtime_node_db();
    if (!ndb || !app_runtime_node_db_handle_open(ndb)) {
        atomic_fetch_add(&g_worker_failures, 1);
        return NULL;
    }
    uint64_t completed = 0;
    while (!g_shutdown_requested) {
        supervisor_child_id id = atomic_load(&g_worker_id);
        struct subordinate_work_facts facts;
        struct zcl_result observation = subordinate_work_admission_observe(
            !g_shutdown_requested, app_runtime_node_db_handle_open(ndb), ndb,
            &facts);
        enum subordinate_work_refusal admission = observation.ok
            ? subordinate_work_admission_decide(&facts)
            : SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE;
        atomic_store(&g_worker_admission_reason, admission);
        if (admission != SUBORDINATE_WORK_ADMIT) {
            atomic_fetch_add(&g_worker_resource_deferrals, 1);
            supervisor_progress_idle(id);
            supervisor_tick(id);
            platform_sleep_ms(250);
            continue;
        }
        uint8_t lease_raw[32];
        char lease_id[65];
        if (!zcl_random_secret_bytes(lease_raw, sizeof(lease_raw),
                                     "zbuild_lease")) {
            atomic_fetch_add(&g_worker_failures, 1);
            supervisor_tick(id);
            platform_sleep_ms(1000);
            continue;
        }
        zcl_hex_encode(lease_raw, sizeof(lease_raw), lease_id);
        memset(lease_raw, 0, sizeof(lease_raw));
        struct db_build_action action;
        bool claimed = false;
        int64_t claim_started_us = platform_time_monotonic_us();
        struct zcl_result claim = build_fabric_claim(
            ndb, g_local_worker.worker_id, lease_id,
            (int64_t)platform_time_wall_unix(),
            BUILD_FABRIC_LEASE_SECONDS_MAX, &action, &claimed);
        if (!claim.ok) {
            atomic_fetch_add(&g_worker_failures, 1);
            supervisor_tick(id);
            platform_sleep_ms(1000);
            continue;
        }
        if (!claimed) {
            supervisor_progress_idle(id);
            supervisor_tick(id);
            platform_sleep_ms(250);
            continue;
        }
        int64_t claimed_us = platform_time_realtime_us();
        int64_t queue_us = action.created_at > 0
            ? claimed_us - action.created_at * INT64_C(1000000) : 0;
        LOG_INFO("zcode.proof_perf",
                 "schema=zcl.async_proof_perf.v1 action=%s "
                 "stage=worker_lease at_unix_us=%lld claim_us=%lld "
                 "queue_us=%lld "
                 "attempt=%lld",
                 action.action_id, (long long)claimed_us,
                 (long long)(platform_time_monotonic_us() - claim_started_us),
                 (long long)(queue_us < 0 ? 0 : queue_us),
                 (long long)action.attempt_count);
        atomic_fetch_add(&g_worker_dispatches, 1);
        char execution_workspace[4096];
        if (!bf_runtime_execution_workspace(
                ndb, &action, execution_workspace)) {
            struct zcl_result failed = build_fabric_finish_leased(
                ndb, action.action_id, action.lease_id, "LOCAL_FALLBACK",
                "zcode-workspace-locator-unavailable",
                (int64_t)platform_time_wall_unix());
            if (!failed.ok)
                LOG_ERROR("build_fabric",
                          "workspace locator failure could not finish %s: %s",
                          action.action_id, failed.message);
            atomic_fetch_add(&g_worker_failures, 1);
            supervisor_tick(id);
            continue;
        }
        struct db_build_receipt receipt;
        struct zcl_result run = build_fabric_worker_execute(
            ndb, execution_workspace, g_worker_datadir, action.action_id,
            lease_id,
            g_local_secret, g_local_pubkey, &receipt, NULL);
        if (run.ok) {
            struct zcl_result admitted = build_fabric_receipt_admit(
                ndb, execution_workspace, receipt.receipt_id,
                (int64_t)platform_time_wall_unix());
            if (admitted.ok)
                supervisor_progress(id, (int64_t)++completed);
            else {
                LOG_ERROR("build_fabric",
                          "supervisor refused quarantined result %s: %s",
                          receipt.receipt_id, admitted.message);
                atomic_fetch_add(&g_worker_failures, 1);
            }
        } else
            atomic_fetch_add(&g_worker_failures, 1);
        supervisor_tick(id);
    }
    return NULL;
}

static supervisor_child_id bf_runtime_child(
    struct liveness_contract *contract, const char *name,
    void (*tick)(struct liveness_contract *))
{
    liveness_contract_init(contract, name);
    atomic_store(&contract->period_secs, BF_RUNTIME_PERIOD_SECS);
    atomic_store(&contract->deadline_secs, 10);
    contract->on_tick = tick;
    return supervisor_register_in_domain(g_op_sup, contract);
}

struct zcl_result build_fabric_runtime_register(bool worker_enabled,
                                                const char *datadir)
{
    supervisor_domains_init();
    atomic_store(&g_worker_enabled, worker_enabled);
    if (worker_enabled && !atomic_load(&g_worker_started)) {
        if (!datadir || !getcwd(g_worker_workspace,
                                sizeof(g_worker_workspace)))
            return ZCL_ERR(-1, "build worker cannot resolve its workspace");
        int ddn = snprintf(g_worker_datadir, sizeof(g_worker_datadir),
                           "%s", datadir);
        if (ddn <= 0 || (size_t)ddn >= sizeof(g_worker_datadir))
            return ZCL_ERR(-1, "build worker datadir is too long");
        ZCL_CHECK(build_fabric_worker_identity_load(
            datadir, &g_local_worker, g_local_secret, g_local_pubkey));
        struct node_db *ndb = app_runtime_node_db();
        if (!ndb || !ndb->open)
            return ZCL_ERR(-1, "build worker database is unavailable");
        int64_t now = (int64_t)platform_time_wall_unix();
        g_local_worker.approved_at = now;
        g_local_worker.last_seen_at = now;
        ZCL_CHECK(build_fabric_worker_approve(ndb, &g_local_worker, now));
    }
    if (atomic_load(&g_requester_id) == SUPERVISOR_INVALID_ID) {
        supervisor_child_id id = bf_runtime_child(
            &g_requester_contract, "build.requester", bf_requester_tick);
        atomic_store(&g_requester_id, id);
        if (id == SUPERVISOR_INVALID_ID)
            LOG_WARN("build_fabric", "requester supervisor registration failed");
        else
            supervisor_set_progress_max_quiet(id, BF_RUNTIME_MAX_QUIET_US);
    }
    if (atomic_load(&g_worker_id) == SUPERVISOR_INVALID_ID) {
        supervisor_child_id id = bf_runtime_child(
            &g_worker_contract, "build.worker",
            worker_enabled ? NULL : bf_worker_tick);
        atomic_store(&g_worker_id, id);
        if (id == SUPERVISOR_INVALID_ID)
            LOG_WARN("build_fabric", "worker supervisor registration failed");
        else if (worker_enabled) {
            atomic_store(&g_worker_contract.period_secs, 0);
            atomic_store(&g_worker_contract.deadline_secs, 600);
            supervisor_set_progress_max_quiet(
                id, (int64_t)610 * 1000 * 1000);
        }
        else
            supervisor_set_progress_exempt(id, "-buildworker not enabled");
    }
    if (atomic_load(&g_requester_id) == SUPERVISOR_INVALID_ID ||
        atomic_load(&g_worker_id) == SUPERVISOR_INVALID_ID)
        return ZCL_ERR(-1, "build runtime supervisor registration failed");
    if (worker_enabled && !atomic_exchange(&g_worker_started, true)) {
        // supervised:build.worker (g_worker_contract registered above)
        int rc = thread_registry_spawn("zcl_build_worker", bf_worker_loop,
                                       NULL, &g_worker_thread);
        if (rc != 0) {
            atomic_store(&g_worker_started, false);
            return ZCL_ERR(-1, "build worker thread spawn failed: %d", rc);
        }
    }
    return ZCL_OK;
}

bool build_fabric_dump_state_json(struct json_value *out, const char *key)
{
    if (!out) return false;
    json_set_object(out);
    if (key && key[0]) {
        uint8_t action_root[32];
        (void)json_push_kv_str(out, "schema",
                              "zcl.build_fabric_action_state.v1");
        (void)json_push_kv_str(out, "action_id", key);
        if (!zcl_hex_decode_lower(key, action_root, sizeof(action_root))) {
            (void)json_push_kv_bool(out, "found", false);
            (void)json_push_kv_str(out, "reason",
                                  "action_id_not_lowercase_sha3");
            return true;
        }
        struct node_db *ndb = app_runtime_node_db();
        struct db_build_proof_event event;
        if (!app_runtime_node_db_handle_open(ndb) ||
            !db_build_proof_event_latest(ndb, key, &event)) {
            (void)json_push_kv_bool(out, "found", false);
            (void)json_push_kv_str(out, "reason",
                                  "proof_event_not_found");
            return true;
        }
        (void)json_push_kv_bool(out, "found", true);
        (void)json_push_kv_str(out, "state", event.state);
        (void)json_push_kv_str(out, "event_root", event.event_root);
        (void)json_push_kv_str(out, "prior_event_root",
                              event.prior_event_root);
        (void)json_push_kv_str(out, "source_root",
                              event.source_root_sha3);
        (void)json_push_kv_str(out, "task_root", event.task_root_sha3);
        (void)json_push_kv_str(out, "candidate_root",
                              event.candidate_root_sha3);
        (void)json_push_kv_str(out, "proof_policy_root",
                              event.proof_policy_root_sha3);
        (void)json_push_kv_str(out, "context_root",
                              event.context_root_sha3);
        (void)json_push_kv_str(out, "receipt_root",
                              event.receipt_root_sha3);
        (void)json_push_kv_int(out, "peer_id", (int64_t)event.peer_id);
        (void)json_push_kv_int(out, "request_id",
                              (int64_t)event.request_id);
        (void)json_push_kv_int(out, "deadline_at", event.deadline_at);
        (void)json_push_kv_int(out, "elapsed_us", event.elapsed_us);
        (void)json_push_kv_int(out, "created_at", event.created_at);
        (void)json_push_kv_bool(out, "event_root_rederived", true);
        return true;
    }
    (void)json_push_kv_str(out, "schema", "zcl.build_fabric_state.v1");
    (void)json_push_kv_bool(out, "worker_enabled", atomic_load(&g_worker_enabled));
    (void)json_push_kv_int(out, "requester_ticks", (int64_t)atomic_load(&g_requester_ticks));
    (void)json_push_kv_int(out, "worker_ticks", (int64_t)atomic_load(&g_worker_ticks));
    (void)json_push_kv_int(out, "jobs_active", (int64_t)atomic_load(&g_jobs_active));
    (void)json_push_kv_int(out, "actions_active", (int64_t)atomic_load(&g_actions_active));
    (void)json_push_kv_int(out, "jobs_terminal", (int64_t)atomic_load(&g_jobs_terminal));
    (void)json_push_kv_int(out, "accepted_or_cache", (int64_t)atomic_load(&g_accepted_or_cache));
    (void)json_push_kv_int(out, "leases_recovered", (int64_t)atomic_load(&g_leases_recovered));
    (void)json_push_kv_int(out, "recovery_failures", (int64_t)atomic_load(&g_recovery_failures));
    (void)json_push_kv_int(out, "worker_dispatches", (int64_t)atomic_load(&g_worker_dispatches));
    (void)json_push_kv_int(out, "worker_failures", (int64_t)atomic_load(&g_worker_failures));
    enum subordinate_work_refusal admission =
        atomic_load(&g_worker_admission_reason);
    (void)json_push_kv_str(out, "worker_admission",
                          subordinate_work_refusal_token(admission));
    (void)json_push_kv_int(
        out, "worker_resource_deferrals",
        (int64_t)atomic_load(&g_worker_resource_deferrals));
    (void)json_push_kv_bool(out, "worker_thread_started", atomic_load(&g_worker_started));
    (void)json_push_kv_int(out, "requester_deadline_s", 10);
    (void)json_push_kv_int(out, "worker_deadline_s", 10);
    (void)json_push_kv_int(out, "max_quiet_s", 120);
    (void)json_push_kv_int(out, "max_actions_per_job", 256);
    (void)json_push_kv_int(out, "worker_cpu_limit", 1);
    (void)json_push_kv_int(out, "worker_memory_mb", 2048);
    (void)json_push_kv_int(out, "worker_timeout_s", 120);
    (void)json_push_kv_bool(out, "worker_network_allowed", false);
    (void)json_push_kv_int(out, "supervisor_child_headroom",
                           supervisor_child_headroom());
    bool supervised = atomic_load(&g_requester_id) != SUPERVISOR_INVALID_ID &&
                      atomic_load(&g_worker_id) != SUPERVISOR_INVALID_ID;
    diag_push_health(out, supervised, supervised ? "supervised" : "not_registered");
    return true;
}
