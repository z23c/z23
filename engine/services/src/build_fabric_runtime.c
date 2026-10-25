/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-loud liveness contracts for build scheduling and workers. */

#include "services/build_fabric_runtime.h"

#include "base/hex.h"
#include "services/build_fabric_attach.h"
#include "services/build_fabric_proof_context.h"
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
#include "support/log_throttle.h"
#include "util/log_macros.h"
#include "util/supervisor.h"
#include "util/thread_qos.h"
#include "util/thread_registry.h"
#include "vcs/build_action.h"
#include "vcs/package_store.h"

#include <pthread.h>
#include <openssl/crypto.h>
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
/* Set (release) only after the worker thread has loaded the identity, captured
 * the toolchain and enrolled; g_local_* are written before and read only after
 * an acquire of it. Not ready reads exactly like a disabled worker. */
static _Atomic bool g_worker_ready;
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
/* The worker thread opens this once at start and every step receives it as an
 * explicit argument; only the diagnostics dump reads it here, for its stats.
 * It lives for the process, like the worker key it holds a copy of. */
static _Atomic(struct build_fabric_proof_context *) g_proof;
static pthread_t g_worker_thread;
static _Atomic bool g_worker_started;
/* An admission refusal is a silent 250ms spin: without this the worker can
 * decline every action for a whole run and leave no trace but a QUEUED row.
 * Keyed by refusal so a changed reason prints at once and a stuck one
 * re-prints on keepalive with the count it suppressed. */
static struct log_throttle g_worker_admission_throttle = LOG_THROTTLE_INIT;

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

/* Peek only at the next local compile before taking a physical lease. The
 * attach service fences the complete donor replay and publishes atomically;
 * a miss or named refusal leaves the ordinary claim/execution path intact. */
static struct zcl_result bf_runtime_try_attach_queued(
    struct node_db *ndb, const char *workspace,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *receipt,
    struct build_fabric_attach_report *report, bool *decided)
{
    *decided = false;
    if (!ndb || !workspace || !signer_secret || !signer_pubkey ||
        !receipt || !report)
        return ZCL_ERR(-1, "queued attachment requires workspace and worker");
    memset(report, 0, sizeof(*report));
    struct db_build_action action;
    if (db_build_actions_queued(ndb, &action, 1) != 1 ||
        strcmp(action.kind, VCS_BUILD_ACTION_KIND_V1) != 0 ||
        action.task_root_sha3[0] || action.candidate_root_sha3[0] ||
        action.proof_policy_root_sha3[0])
        return ZCL_OK;
    struct db_build_job job;
    if (!db_build_job_find(ndb, action.job_id, &job)) {
        report->disposition = BUILD_FABRIC_ATTACH_REFUSED;
        (void)snprintf(report->refusal, sizeof(report->refusal),
                       "attach-refused-job-missing");
        return ZCL_ERR(-1, "%s", report->refusal);
    }
    if (strcmp(job.profile, VCS_BUILD_PROFILE_PHYSICAL_REPRODUCTION_V1) == 0)
        return ZCL_OK;
    *decided = true;
    return build_fabric_attach(ndb, workspace, NULL, &job, &action,
                               signer_secret, signer_pubkey, receipt, report);
}

struct build_fabric_proof_context *build_fabric_runtime_proof_open(
    struct node_db *ndb, const char *datadir, const char *worker_id,
    const uint8_t seed[32])
{
    struct build_fabric_proof_context *proof = NULL;
    struct zcl_result opened = build_fabric_proof_context_open(
        ndb, datadir, worker_id, seed, &proof);
    if (opened.ok) return proof;
    LOG_ERROR("build_fabric", "worker runs without proof state: %s",
              opened.message);
    return NULL;
}

struct zcl_result build_fabric_runtime_attach_step(
    struct node_db *ndb, const char *workspace,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct build_fabric_proof_context *proof,
    struct db_build_receipt *receipt,
    struct build_fabric_attach_report *report)
{
    bool decided = false;
    struct zcl_result attach = bf_runtime_try_attach_queued(
        ndb, workspace, signer_secret, signer_pubkey, receipt, report,
        &decided);
    if (decided && proof)
        (void)build_fabric_proof_shadow_attach(proof, ndb, workspace,
                                               signer_pubkey, report);
    return attach;
}

struct zcl_result build_fabric_runtime_execute_step(
    struct node_db *ndb, const char *workspace, const char *datadir,
    const struct db_build_action *action, const char *lease_id,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct build_fabric_proof_context *proof,
    struct db_build_receipt *receipt,
    struct build_fabric_host_accounting *accounting)
{
    if (!ndb || !workspace || !action || !receipt || !accounting)
        return ZCL_ERR(-1, "execute step requires action and outputs");
    ZCL_CHECK(build_fabric_worker_execute(
        ndb, workspace, datadir, action->action_id, lease_id, signer_secret,
        signer_pubkey, receipt, NULL, accounting));
    ZCL_CHECK(build_fabric_receipt_admit(ndb, workspace, receipt->receipt_id,
                                         (int64_t)platform_time_wall_unix()));
    if (proof)
        (void)build_fabric_proof_issue_executed(proof, ndb, workspace, action,
                                                receipt, accounting);
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result build_fabric_runtime_try_attach_queued_for_test(
    struct node_db *ndb, const char *workspace,
    const uint8_t signer_secret[32], const uint8_t signer_pubkey[32],
    struct db_build_receipt *receipt,
    struct build_fabric_attach_report *report)
{
    bool decided = false;
    return bf_runtime_try_attach_queued(ndb, workspace, signer_secret,
                                        signer_pubkey, receipt, report,
                                        &decided);
}
#endif

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

static void bf_worker_log_admission(enum subordinate_work_refusal admission)
{
    uint64_t suppressed = 0;
    if (!log_throttle_should_emit(&g_worker_admission_throttle,
                                  (uint64_t)admission,
                                  platform_time_wall_unix(), 60, &suppressed))
        return;
    LOG_WARN("build_fabric",
             "build worker declines every action: admission=%s "
             "(%llu suppressed repeats)",
             subordinate_work_refusal_token(admission),
             (unsigned long long)suppressed);
}

/* The loop's entire admission step: observe the live facts, run the one
 * production decision, publish the standing reason the diagnostics dump
 * reports, and count and log a refusal. Extracted so the refusal path has a
 * single implementation rather than one here and a copy in a test. */
static enum subordinate_work_refusal bf_worker_admission_step(
    bool running, bool persistence_ready, struct node_db *ndb)
{
    struct subordinate_work_facts facts;
    struct zcl_result observation = subordinate_work_admission_observe(
        running, persistence_ready, ndb, &facts);
    enum subordinate_work_refusal admission = observation.ok
        ? subordinate_work_admission_decide(&facts)
        : SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE;
    atomic_store(&g_worker_admission_reason, admission);
    if (admission != SUBORDINATE_WORK_ADMIT) {
        atomic_fetch_add(&g_worker_resource_deferrals, 1);
        bf_worker_log_admission(admission);
    }
    return admission;
}

#ifdef ZCL_TESTING
enum subordinate_work_refusal build_fabric_worker_admission_step_for_test(
    bool running, bool persistence_ready, struct node_db *ndb)
{
    return bf_worker_admission_step(running, persistence_ready, ndb);
}
#endif

static void bf_runtime_execute_claimed(struct node_db *ndb,
                                       const struct db_build_action *action,
                                       const char *lease_id,
                                       supervisor_child_id id,
                                       uint64_t *completed)
{
    char execution_workspace[4096];
    if (!bf_runtime_execution_workspace(ndb, action, execution_workspace)) {
        struct zcl_result failed = build_fabric_finish_leased(
            ndb, action->action_id, action->lease_id, "LOCAL_FALLBACK",
            "zcode-workspace-locator-unavailable",
            (int64_t)platform_time_wall_unix());
        if (!failed.ok)
            LOG_ERROR("build_fabric",
                      "workspace locator failure could not finish %s: %s",
                      action->action_id, failed.message);
        atomic_fetch_add(&g_worker_failures, 1);
        supervisor_tick(id);
        return;
    }
    struct db_build_receipt receipt;
    struct build_fabric_host_accounting accounting;
    memset(&receipt, 0, sizeof(receipt));
    struct zcl_result run = build_fabric_runtime_execute_step(
        ndb, execution_workspace, g_worker_datadir, action, lease_id,
        g_local_secret, g_local_pubkey, atomic_load(&g_proof), &receipt,
        &accounting);
    if (run.ok)
        supervisor_progress(id, (int64_t)++*completed);
    else {
        LOG_ERROR("build_fabric", "build action %s not accepted: %s",
                  action->action_id, run.message);
        atomic_fetch_add(&g_worker_failures, 1);
    }
    supervisor_tick(id);
}

/* The cheap, synchronous half of enrolling the local worker: where it runs
 * and keeps its data. The identity load (toolchain capture: compiler probe
 * subprocesses and SHA3 of the toolchain files) and the node_db enroll run on
 * the worker thread (bf_worker_enroll_step), never on the boot thread. */
static struct zcl_result bf_runtime_prepare_worker(const char *datadir)
{
    if (!datadir || !getcwd(g_worker_workspace,
                            sizeof(g_worker_workspace)))
        return ZCL_ERR(-1, "build worker cannot resolve its workspace");
    int ddn = snprintf(g_worker_datadir, sizeof(g_worker_datadir),
                       "%s", datadir);
    if (ddn <= 0 || (size_t)ddn >= sizeof(g_worker_datadir))
        return ZCL_ERR(-1, "build worker datadir is too long");
    atomic_store_explicit(&g_worker_ready, false, memory_order_release);
    return ZCL_OK;
}

static struct zcl_result bf_runtime_enroll_worker(struct node_db *ndb)
{
    ZCL_CHECK(build_fabric_worker_identity_load(
        g_worker_datadir, &g_local_worker, g_local_secret, g_local_pubkey));
    if (g_shutdown_requested)
        return ZCL_ERR(-1, "build worker enroll stopped by shutdown");
    if (!ndb || !ndb->open)
        return ZCL_ERR(-1, "build worker database is unavailable");
    int64_t now = (int64_t)platform_time_wall_unix();
    g_local_worker.approved_at = now;
    g_local_worker.last_seen_at = now;
    return build_fabric_worker_enroll_local(ndb, &g_local_worker, now);
}

/* First step of the worker thread: identity, toolchain capture and local
 * enroll, then publish readiness. A failure leaves the worker disabled with
 * the message the boot thread used to log, and its supervisor child exempt
 * (it was never going to make progress). */
static bool bf_worker_enroll_step(struct node_db *ndb)
{
    int64_t started_us = platform_time_monotonic_us();
    struct zcl_result enrolled = bf_runtime_enroll_worker(ndb);
    int64_t took_ms = (platform_time_monotonic_us() - started_us) / 1000;
    if (!enrolled.ok) {
        atomic_store(&g_worker_enabled, false);
        atomic_store_explicit(&g_worker_ready, false, memory_order_release);
        supervisor_child_id id = atomic_load(&g_worker_id);
        if (id != SUPERVISOR_INVALID_ID)
            supervisor_set_progress_exempt(id, "build worker enroll failed");
        LOG_WARN("build_fabric", "%s", enrolled.message);
        return false;
    }
    atomic_store_explicit(&g_worker_ready, true, memory_order_release);
    LOG_INFO("build_fabric",
             "build worker identity ready on worker thread: capture+enroll %lldms",
             (long long)took_ms);
    return true;
}

bool build_fabric_runtime_worker_ready(void)
{
    return atomic_load_explicit(&g_worker_ready, memory_order_acquire);
}

#ifdef ZCL_TESTING
struct zcl_result build_fabric_runtime_prepare_worker_for_test(
    const char *datadir)
{
    atomic_store(&g_worker_enabled, true);
    return bf_runtime_prepare_worker(datadir);
}

bool build_fabric_runtime_enroll_step_for_test(struct node_db *ndb)
{
    return bf_worker_enroll_step(ndb);
}

bool build_fabric_runtime_worker_enabled_for_test(void)
{
    return atomic_load(&g_worker_enabled);
}

const char *build_fabric_runtime_local_worker_id_for_test(void)
{
    return build_fabric_runtime_worker_ready() ? g_local_worker.worker_id
                                               : NULL;
}
#endif

static bool bf_worker_recover_at_start(struct node_db *ndb)
{
    struct db_build_worker worker;
    uint8_t secret[32] = {0}, pubkey[32], seed[32] = {0};
    struct zcl_result result = build_fabric_worker_identity_load_with_seed(
        g_worker_datadir, &worker, secret, pubkey, seed);
    if (result.ok && (strcmp(worker.worker_id, g_local_worker.worker_id) != 0 ||
                      memcmp(pubkey, g_local_pubkey, sizeof(pubkey)) != 0))
        result = ZCL_ERR(-1, "build worker recovery identity changed");
    /* Proof state is feedback: whatever its open returns, the worker starts
     * on the identity checks above alone. */
    struct build_fabric_proof_context *proof = result.ok
        ? build_fabric_runtime_proof_open(ndb, g_worker_datadir,
                                          g_local_worker.worker_id, seed)
        : NULL;
    struct build_fabric_proof_context *none = NULL;
    if (proof && !atomic_compare_exchange_strong(&g_proof, &none, proof))
        build_fabric_proof_context_close(proof);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(secret, sizeof(secret));
    if (!result.ok)
        LOG_ERROR("build_fabric", "worker recovery refused: %s",
                  result.message);
    return result.ok;
}

static bool bf_worker_wait_for_recovery(struct node_db *ndb)
{
    while (!g_shutdown_requested && !bf_worker_recover_at_start(ndb)) {
        atomic_fetch_add(&g_recovery_failures, 1);
        supervisor_child_id id = atomic_load(&g_worker_id);
        supervisor_progress_idle(id);
        supervisor_tick(id);
        for (unsigned int second = 0; second < 60u &&
                                      !g_shutdown_requested; second++)
            platform_sleep_ms(1000);
    }
    return !g_shutdown_requested;
}

/* Enroll first (the capture the boot thread no longer pays), then recover
 * the same identity from the key file. */
static bool bf_worker_start_identity(struct node_db *ndb)
{
    return bf_worker_enroll_step(ndb) && bf_worker_wait_for_recovery(ndb);
}

static void *bf_worker_loop(void *arg)
{
    (void)arg;
    (void)zcl_thread_qos_background();
    /* The daemon's node.db has one mutable owner.  A second long-lived
     * sqlite connection in this thread would have a WAL lifetime independent
     * of the boot connection: restarting peer workers could unlink the
     * pathname while the canonical connection still held the old inode.
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
    if (!bf_worker_start_identity(ndb)) return NULL;
    uint64_t completed = 0;
    while (!g_shutdown_requested) {
        supervisor_child_id id = atomic_load(&g_worker_id);
        enum subordinate_work_refusal admission = bf_worker_admission_step(
            !g_shutdown_requested, app_runtime_node_db_handle_open(ndb), ndb);
        if (admission != SUBORDINATE_WORK_ADMIT) {
            supervisor_progress_idle(id);
            supervisor_tick(id);
            platform_sleep_ms(250);
            continue;
        }
        struct db_build_receipt attached_receipt;
        struct build_fabric_attach_report attach_report;
        struct zcl_result attach = build_fabric_runtime_attach_step(
            ndb, g_worker_workspace, g_local_secret, g_local_pubkey,
            atomic_load(&g_proof), &attached_receipt, &attach_report);
        if (attach.ok &&
            attach_report.disposition == BUILD_FABRIC_ATTACH_HIT) {
            supervisor_progress(id, (int64_t)++completed);
            supervisor_tick(id);
            continue;
        }
        if (!attach.ok)
            LOG_WARN("build_fabric", "queued attachment refused: %s",
                     attach_report.refusal[0] ? attach_report.refusal
                                              : attach.message);
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
        bf_runtime_execute_claimed(ndb, &action, lease_id, id, &completed);
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
    if (worker_enabled && !atomic_load(&g_worker_started))
        ZCL_CHECK(bf_runtime_prepare_worker(datadir));
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
    (void)json_push_kv_bool(out, "worker_ready", build_fabric_runtime_worker_ready());
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
    struct build_fabric_proof_stats proof_stats;
    build_fabric_proof_context_stats(atomic_load(&g_proof), &proof_stats);
    struct json_value proof;
    json_init(&proof);
    build_fabric_proof_stats_json(&proof_stats, &proof);
    (void)json_push_kv(out, "proof", &proof);
    json_free(&proof);
    bool supervised = atomic_load(&g_requester_id) != SUPERVISOR_INVALID_ID &&
                      atomic_load(&g_worker_id) != SUPERVISOR_INVALID_ID;
    diag_push_health(out, supervised, supervised ? "supervised" : "not_registered");
    return true;
}
