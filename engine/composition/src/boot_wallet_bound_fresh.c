/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Bound-request terminal startup using retained, independently verified history. */
#include "boot_cutover_startup_internal.h"
#if !defined(_WIN32)
#include "config/boot.h"
#include "config/boot_datadir_lock.h"
#include "config/boot_wallet_cold_prefix.h"
#include "config/boot_wallet_pending_restore.h"
#include "config/consensus_state_install_runtime.h"
#include "consensus_state_install_stage.h"
#include "consensus_state_install_terminal_internal.h"
#include "config/consensus_state_snapshot_install.h"
#include "platform/private_directory.h"
#include "services/block_index_loader.h"
#include "services/chain_state_service.h"
#include "services/chain_activation_service.h"
#include "services/wallet_history_capability.h"
#include "wallet/wallet_sqlite.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/thread_registry.h"
#include "validation/chainstate.h"
#include "chain/chainparams.h"
#include "util/sysinit.h"
#include "validation/main_state.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct boot_bound_fresh_work {
    struct boot_bound_bundle_observation request;
    struct wallet_history_capability history;
    struct consensus_state_artifact_evidence *source, *staged;
    struct bound_history_preflight *preflight;
    boot_wallet_cold_prefix_t *prefix;
    uintptr_t directory;
    bool directory_open, terminal, old_retry;
    struct wallet_cutover_binding expected;
    bool used;
    char staged_path[BOOT_BOUND_PATH_CAP];
};
#ifdef ZCL_TESTING
static void (*boot_completed_before_proof)(struct boot_cutover_env *, struct app_context *, void *);
static void *boot_completed_before_proof_context;
void boot_test_completed_before_proof(void (*hook)(struct boot_cutover_env *, struct app_context *, void *), void *context)
{ boot_completed_before_proof = hook; boot_completed_before_proof_context = context; }
void boot_test_run_completed_before_proof(struct boot_cutover_env *env, struct app_context *ctx)
{ if (boot_completed_before_proof) boot_completed_before_proof(env, ctx, boot_completed_before_proof_context); }
#endif

static struct boot_bound_fresh_work g_bound_fresh;
static bool boot_bound_request_fields_equal(const struct boot_bound_bundle_observation *a,
                                            const struct boot_bound_bundle_observation *b)
{
    return b->endpoint_height == a->endpoint_height &&
        !strcmp(a->bundle_path, b->bundle_path) && !strcmp(a->private_history_path, b->private_history_path) &&
        !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) && !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32);
}
static bool boot_bound_request_after_consume(const struct boot_bound_bundle_observation *a,
                                              const struct boot_bound_bundle_observation *b)
{ return b->attempts == a->attempts + 1 && boot_bound_request_fields_equal(a, b); }
static bool boot_bound_request_still_current(const char *datadir,
    const struct boot_bound_bundle_observation *expected, bool old_retry)
{
    struct boot_bound_bundle_observation current = {0};
    enum boot_bound_read_result read = boot_install_bound_bundle_read(datadir, &current);
    return (read == BOOT_BOUND_READ_READY || (old_retry && read == BOOT_BOUND_READ_TERMINAL)) &&
        current.attempts == expected->attempts && boot_bound_request_fields_equal(expected, &current);
}
static bool boot_bound_stage_artifact(struct boot_bound_fresh_work *w, const char *datadir)
{
    uint8_t whole[32], logical[32];
    if (!consensus_state_artifact_evidence_open(w->request.bundle_path, -1, &w->source).ok ||
        !consensus_state_artifact_evidence_file_digest(w->source, whole) ||
        memcmp(whole, w->request.snapshot_sha3, 32) ||
        !consensus_state_artifact_evidence_digest(w->source, logical) ||
        !consensus_state_install_stage(datadir, w->source, w->staged_path, sizeof(w->staged_path), &w->staged) ||
        !consensus_state_stage_evidence_matches(w->staged, whole, logical)) return false;
    return consensus_state_artifact_evidence_close(&w->source);
}
static bool boot_bound_capture_frontier(struct boot_wallet_frontier *frontier)
{
    sqlite3 *db = progress_store_db();
    if (!db || !progress_store_tx_trylock()) return false;
    bool opened = sqlite3_get_autocommit(db) && sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK;
    bool ok = opened && boot_wallet_frontier_read_locked(db, frontier);
    if (opened && sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
        if (!sqlite3_get_autocommit(db) && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
            LOG_ERROR("wallet", "bound frontier rollback failed: %s", sqlite3_errmsg(db));
        LOG_ERROR("wallet", "bound frontier snapshot could not be closed");
        ok = false;
    }
    progress_store_tx_unlock();
    return ok;
}
static bool boot_bound_fresh_cleanup(struct boot_bound_fresh_work *w)
{
    bool ok = true;
    if (w->prefix && !boot_wallet_cold_prefix_release(w->prefix)) ok = false;
    bound_history_preflight_close(&w->preflight);
    if (!consensus_state_artifact_evidence_close(&w->staged)) ok = false;
    if (!consensus_state_artifact_evidence_close(&w->source)) ok = false;
    wallet_history_capability_release(&w->history);
    if (w->directory_open) platform_private_directory_close(w->directory);
    return ok;
}
static bool boot_bound_fresh_stop(void *context)
{ (void)context; return thread_registry_shutdown_requested(); }

enum boot_bound_acquire_result { BOOT_BOUND_ACQUIRE_READY, BOOT_BOUND_ACQUIRE_FAILED, BOOT_BOUND_ACQUIRE_STOPPED };

static enum boot_bound_acquire_result boot_bound_fresh_acquire(struct boot_bound_fresh_work *w,
    struct app_context *ctx, const struct boot_bound_bundle_observation *before)
{
    if (w->old_retry) {
        w->request = *before;
        if (!boot_bound_request_still_current(ctx->datadir, &w->request, w->old_retry)) return BOOT_BOUND_ACQUIRE_FAILED;
    } else if (boot_install_bound_bundle_consume(ctx->datadir, before) != BOOT_BOUND_CONSUME_OK ||
        boot_install_bound_bundle_read(ctx->datadir, &w->request) != BOOT_BOUND_READ_READY ||
        !boot_bound_request_after_consume(before, &w->request)) return BOOT_BOUND_ACQUIRE_FAILED;
    if (!boot_bound_stage_artifact(w, ctx->datadir)) return BOOT_BOUND_ACQUIRE_FAILED;
    enum boot_pending_replay_result acquired = boot_bound_history_acquire_observed(
        ctx->datadir, &w->request, w->old_retry, &w->history);
    if (acquired == BOOT_PENDING_STOPPED) return BOOT_BOUND_ACQUIRE_STOPPED;
    if (acquired != BOOT_PENDING_COMPLETE) return BOOT_BOUND_ACQUIRE_FAILED;
    return BOOT_BOUND_ACQUIRE_READY;
}

static bool boot_bound_fresh_prepare(struct boot_bound_fresh_work *w,
    struct boot_cutover_env *env, struct app_context *ctx)
{
    if (!platform_private_directory_open_validated_traverse(ctx->datadir, &w->directory)) return false;
    w->directory_open = true;
    if (!boot_datadir_lock_matches_fd((int)w->directory)) return false;
    sqlite3 *progress = progress_store_db();
    if (!progress) {
        if (!progress_store_open_existing(ctx->datadir)) return false;
        progress = progress_store_db();
    }
    if (!progress || !progress_store_directory_matches_fd(progress, (int)w->directory)) return false;
    struct boot_wallet_frontier old;
    if (!boot_bound_capture_frontier(&old)) return false;
    if (w->old_retry && (old.coins != w->expected.old_height ||
        old.generation_present != w->expected.old_generation_present ||
        old.generation != w->expected.old_generation ||
        memcmp(old.coins_hash.data, w->expected.old_hash, 32))) return false;
    struct zcl_result ready = bound_history_preflight_open(&w->preflight, &w->request, w->staged,
        &w->history, old.coins, old.coins_hash.data);
    return ready.ok && boot_bound_request_still_current(ctx->datadir, &w->request, w->old_retry) &&
        boot_bound_memory_bind(env);
}

static bool boot_bound_fresh_install(struct boot_bound_fresh_work *w, struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params, struct wallet_cutover_binding *committed)
{
    struct block_index *genesis = chainstate_insert_block_index((struct chainstate *)env->state,
        &params->consensus.hashGenesisBlock);
    if (!genesis || !block_index_initialize_genesis(genesis, params)) return false;
    enum boot_wallet_cold_result staged = boot_wallet_cold_prefix_stage_with_history(env->state,
        (int)w->directory, 3500000, w->preflight, boot_bound_fresh_stop, NULL, &w->prefix);
    if (staged != BOOT_WALLET_COLD_READY ||
        !boot_bound_request_still_current(ctx->datadir, &w->request, w->old_retry)) return false;
    enum boot_wallet_cold_result adopted = boot_wallet_cold_prefix_adopt(w->prefix, csr_instance(),
        w->preflight, &w->request, w->staged, &w->history);
    if (adopted != BOOT_WALLET_COLD_ADOPTED) return false;
    if (!boot_wallet_cold_prefix_close_readers(w->prefix)) return false;
    if (!sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, ctx).ok ||
        !boot_bound_request_still_current(ctx->datadir, &w->request, w->old_retry)) return false;
    struct consensus_state_install_runtime_result installed = {0};
    struct zcl_result rc = w->old_retry ?
        bound_history_preflight_install_old_retry(w->preflight, &w->request, &w->history,
            env->node, env->state, ctx->datadir, env->wallet_db, env->wallet, &w->expected, &installed) :
        bound_history_preflight_install(w->preflight, &w->request, &w->history,
            env->node, env->state, ctx->datadir, env->wallet_db, env->wallet, &installed);
    return rc.ok && installed.state_installed &&
        wallet_sqlite_cutover_read(env->wallet_db, committed) == WALLET_CUTOVER_PENDING;
}

static bool boot_bound_fresh_arguments_valid(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params,
    const struct boot_bound_bundle_observation *before, struct wallet_cutover_binding *committed)
{
    return env && ctx && params && before && committed && !g_bound_fresh.used &&
        boot_cutover_mode_supported(ctx);
}

/* Every path after inserting the compiled genesis is terminal for this process. */
enum boot_bound_fresh_result boot_bound_fresh_terminal(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params,
    const struct boot_bound_bundle_observation *before, struct wallet_cutover_binding *committed)
{
    if (!boot_bound_fresh_arguments_valid(env, ctx, params, before, committed))
        return BOOT_BOUND_FRESH_FAILED;
    struct boot_bound_fresh_work *w = &g_bound_fresh;
    w->used = true; wallet_history_capability_init(&w->history);
    enum boot_bound_fresh_result result = BOOT_BOUND_FRESH_FAILED;
    enum boot_bound_acquire_result acquired = boot_bound_fresh_acquire(w, ctx, before);
    if (acquired != BOOT_BOUND_ACQUIRE_READY) {
        if (acquired == BOOT_BOUND_ACQUIRE_STOPPED) result = BOOT_BOUND_FRESH_STOPPED;
        goto done;
    }
    if (!boot_bound_fresh_prepare(w, env, ctx)) goto done;
    if (thread_registry_shutdown_requested()) { result = BOOT_BOUND_FRESH_STOPPED; goto done; }
    w->terminal = true;
    if (!boot_bound_fresh_install(w, env, ctx, params, committed)) goto done;
    /* Retain the stage, archive, evidence and lease until shutdown/exec. */
    return BOOT_BOUND_FRESH_INSTALLED;
done:
    if (result != BOOT_BOUND_FRESH_STOPPED) LOG_ERROR("wallet", "bound fresh startup refused");
    if (w->terminal) _exit(EXIT_FAILURE);
    if (!boot_bound_fresh_cleanup(w)) return BOOT_BOUND_FRESH_FAILED;
    return result;
}
static bool boot_bound_old_request_matches(enum boot_bound_read_result read,
    const struct boot_bound_bundle_observation *request, const struct wallet_cutover_binding *binding)
{
    return (read == BOOT_BOUND_READ_READY || read == BOOT_BOUND_READ_TERMINAL) &&
        request->endpoint_height == binding->target_height &&
        !memcmp(request->endpoint_hash, binding->target_hash, 32) &&
        !memcmp(request->snapshot_sha3, binding->snapshot_whole_sha3, 32) &&
        !memcmp(request->history_manifest_root, binding->history_manifest_root, 32);
}

static bool boot_bound_old_generation_matches(struct boot_cutover_env *env,
    struct boot_bound_fresh_work *w, const struct wallet_cutover_binding *binding)
{
    struct wallet_cutover_binding current;
    bool present = false; uint64_t generation = 0;
    return consensus_state_wallet_install_classify(env->wallet_db, env->node, (int)w->directory,
        &present, &generation) == WALLET_INSTALL_OLD &&
        present == binding->old_generation_present && generation == binding->old_generation &&
        wallet_sqlite_cutover_read(env->wallet_db, &current) == WALLET_CUTOVER_PENDING &&
        wallet_cutover_binding_equal(binding, &current);
}

static bool boot_bound_old_arguments_valid(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding)
{
    return env && ctx && params && binding && binding->history_identity_present &&
        !g_bound_fresh.used && boot_cutover_mode_supported(ctx);
}

static bool boot_bound_old_cold_retry_impl(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding)
{
    if (!boot_bound_old_arguments_valid(env, ctx, params, binding)) return false;
    struct boot_bound_fresh_work *w = &g_bound_fresh;
    w->used = true; w->old_retry = true; w->expected = *binding;
    wallet_history_capability_init(&w->history);
    struct boot_bound_bundle_observation request = {0};
    enum boot_bound_read_result read = boot_install_bound_bundle_read(ctx->datadir, &request);
    bool ok = boot_bound_old_request_matches(read, &request, binding) &&
        boot_bound_fresh_acquire(w, ctx, &request) == BOOT_BOUND_ACQUIRE_READY &&
        boot_bound_fresh_prepare(w, env, ctx) && !thread_registry_shutdown_requested();
    if (ok) ok = boot_bound_old_generation_matches(env, w, binding);
    if (ok) {
        struct wallet_cutover_binding committed;
        w->terminal = true;
        ok = boot_bound_fresh_install(w, env, ctx, params, &committed) &&
             boot_cutover_verify_committed(env, ctx->datadir, binding);
        if (!ok) {
            LOG_ERROR("wallet", "bound old cold-start failed after chain insertion");
            _exit(EXIT_FAILURE);
        }
        return true;
    }
    LOG_ERROR("wallet", "bound old cold-start preflight refused");
    if (!boot_bound_fresh_cleanup(w)) return false;
    return false;
}
bool boot_bound_request_matches_completed(const struct boot_bound_bundle_observation *request,
                                                  const struct wallet_cutover_binding *binding)
{
    return binding->history_identity_present && binding->target_height == request->endpoint_height &&
        !memcmp(binding->target_hash, request->endpoint_hash, 32) &&
        !memcmp(binding->snapshot_whole_sha3, request->snapshot_sha3, 32) &&
        !memcmp(binding->history_manifest_root, request->history_manifest_root, 32);
}
static enum boot_bound_dispatch_result boot_bound_completed_start(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params, struct block_index **tip,
    const struct wallet_cutover_binding *binding, const struct boot_bound_bundle_observation *request,
    struct chain_activation_controller *activation)
{
    if (!boot_cutover_mode_supported(ctx) || !progress_store_open_existing(ctx->datadir) ||
        !boot_cutover_load_completed_chain(env, ctx, params, tip, binding) ||
        !sysinit_run_stage(BOOT_STAGE_CHAIN_TIP_RESOLVED, ctx).ok) return BOOT_BOUND_DISPATCH_FAILED;
    if (request) {
        uintptr_t directory = 0;
        if (!platform_private_directory_open_validated_traverse(ctx->datadir, &directory))
            return BOOT_BOUND_DISPATCH_FAILED;
        enum boot_bound_completion_result retired = boot_bound_completed_retire(env->wallet_db,
            env->node, env->wallet, env->state, ctx->datadir, (int)directory, binding, request);
        platform_private_directory_close(directory);
        if (retired != BOOT_BOUND_COMPLETION_RETIRED) return BOOT_BOUND_DISPATCH_FAILED;
    }
    if (!boot_cutover_publish_completed(env, ctx, true))
        return BOOT_BOUND_DISPATCH_FAILED;
    activation_boot_complete(activation, "wallet_cutover_complete");
    return BOOT_BOUND_DISPATCH_COMPLETED;
}
static bool boot_bound_dispatch_arguments_valid(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, struct wallet_cutover_binding *binding,
    struct chain_activation_controller *activation)
{
    return env && ctx && params && tip && binding && activation;
}

enum boot_bound_dispatch_result boot_bound_dispatch(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, struct wallet_cutover_binding *binding,
    struct chain_activation_controller *activation)
{
    if (!boot_bound_dispatch_arguments_valid(env, ctx, params, tip, binding, activation))
        return BOOT_BOUND_DISPATCH_FAILED;
    struct boot_bound_bundle_observation request = {0};
    enum boot_bound_read_result read = boot_install_bound_bundle_read(ctx->datadir, &request);
    if (read == BOOT_BOUND_READ_LEGACY) return BOOT_BOUND_DISPATCH_UNARMED;
    if (read == BOOT_BOUND_READ_ABSENT) {
        enum wallet_cutover_observation_status completed = wallet_sqlite_cutover_observe_completed(env->wallet_db, binding);
        if (completed == WALLET_CUTOVER_OBS_ABSENT) return BOOT_BOUND_DISPATCH_UNARMED;
        if (completed != WALLET_CUTOVER_OBS_FOUND || !binding->history_identity_present)
            return BOOT_BOUND_DISPATCH_FAILED;
        return boot_bound_completed_start(env, ctx, params, tip, binding, NULL, activation);
    }
    if (read != BOOT_BOUND_READ_READY && read != BOOT_BOUND_READ_TERMINAL) return BOOT_BOUND_DISPATCH_FAILED;
    enum wallet_cutover_observation_status observed = wallet_sqlite_cutover_observe_completed(env->wallet_db, binding);
    if (observed == WALLET_CUTOVER_OBS_FOUND) {
        if (!boot_bound_request_matches_completed(&request, binding)) return BOOT_BOUND_DISPATCH_FAILED;
        return boot_bound_completed_start(env, ctx, params, tip, binding, &request, activation);
    }
    if (observed != WALLET_CUTOVER_OBS_ABSENT || read != BOOT_BOUND_READ_READY)
        return BOOT_BOUND_DISPATCH_FAILED;
    enum boot_bound_fresh_result fresh = boot_bound_fresh_terminal(env, ctx, params, &request, binding);
    if (fresh != BOOT_BOUND_FRESH_INSTALLED) return BOOT_BOUND_DISPATCH_FAILED;
    if (!boot_cutover_verify_committed(env, ctx->datadir, binding)) _exit(EXIT_FAILURE);
    return BOOT_BOUND_DISPATCH_INSTALLED;
}
#else
#include "boot_cutover_startup_internal.h"
static bool boot_bound_old_cold_retry_impl(struct boot_cutover_env *env, struct app_context *ctx, const struct chain_params *params, const struct wallet_cutover_binding *binding)
{ (void)env; (void)ctx; (void)params; (void)binding; return false; }
enum boot_bound_fresh_result boot_bound_fresh_terminal(struct boot_cutover_env *env,
    struct app_context *ctx, const struct chain_params *params,
    const struct boot_bound_bundle_observation *before, struct wallet_cutover_binding *committed)
{ (void)env; (void)ctx; (void)params; (void)before; (void)committed; return BOOT_BOUND_FRESH_FAILED; }
enum boot_bound_dispatch_result boot_bound_dispatch(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip, struct wallet_cutover_binding *binding,
    struct chain_activation_controller *activation)
{ (void)env; (void)ctx; (void)params; (void)tip; (void)binding; (void)activation; return BOOT_BOUND_DISPATCH_UNARMED; }
#endif

bool boot_bound_old_cold_retry(struct boot_cutover_env *env, struct app_context *ctx,
    const struct chain_params *params, const struct wallet_cutover_binding *binding)
{ return boot_bound_old_cold_retry_impl(env, ctx, params, binding); }
