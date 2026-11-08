/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Old, prebinding and bound chain installation for pending wallet startup. */
#include "boot_cutover_startup_internal.h"
#include "config/boot_internal.h"
#include "config/boot_wallet_pending_restore.h"
#include "config/consensus_state_install_runtime.h"
#include "config/flysync_island.h"
#include "chain/chain.h"
#include "jobs/stage_repair.h"
#include "services/block_index_loader.h"
#include "services/chain_state_service.h"
#include "services/wallet_history_capability.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/sysinit.h"
#include "wallet/wallet_sqlite.h"
#include <fcntl.h>
#include <unistd.h>

static bool boot_prebinding_restore_view(struct boot_cutover_env *e,
    struct chain_state_repository *csr, int datadir_fd)
{
    enum boot_pending_restore_result restored = boot_wallet_prebinding_restore(
        e->state, csr, datadir_fd);
    if (restored == BOOT_PENDING_RESTORE_OK) return true;
    LOG_ERROR("wallet", "prebinding old wallet chain restore refused: %d", (int)restored);
    return false;
}

#ifdef ZCL_TESTING
bool boot_test_prebinding_restore_view(struct main_state *state,
    struct chain_state_repository *csr, int datadir_fd)
{
    struct boot_cutover_env env = {.state = state};
    return boot_prebinding_restore_view(&env, csr, datadir_fd);
}
#endif

static bool boot_prebinding_finish(struct boot_cutover_env *e, struct app_context *ctx,
    struct block_index **tip)
{
#if defined(_WIN32)
    (void)e; (void)ctx; (void)tip;
    return false;
#else
    int datadir_fd = open(ctx->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool restored = datadir_fd >= 0 &&
        boot_prebinding_restore_view(e, csr_instance(), datadir_fd);
    int close_result = datadir_fd >= 0 ? close(datadir_fd) : -1;
    if (!restored || close_result != 0) return false;
    *tip = active_chain_tip(&e->state->chain_active);
    if (!*tip || !stage_reducer_frontier_restore_script(progress_store_db(), e->state, *tip))
        return false;
    return e->gate_index(ctx, true) && sysinit_run_stage(BOOT_STAGE_BLOCK_INDEX_LOADED, ctx).ok;
#endif
}

bool boot_cutover_load_prebinding_chain(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, struct block_index **tip)
{
    struct wallet_cutover_binding binding;
    if (!e || !ctx || !params || !tip ||
        wallet_sqlite_cutover_read(e->wallet_db, &binding) != WALLET_CUTOVER_ABSENT ||
        !boot_pending_bind_storage(e, ctx)) return false;
    struct zcl_result loaded = boot_try_rebuild_block_index_from_projection(
        e->state, params, 0, false);
    return loaded.ok && flysync_island_boot_materialize(e->state) &&
        boot_prebinding_finish(e, ctx, tip);
}

#ifdef ZCL_TESTING
static boot_cutover_test_prebinding_loader_fn g_test_prebinding_loader;
void boot_cutover_test_set_prebinding_loader(boot_cutover_test_prebinding_loader_fn loader)
{
    g_test_prebinding_loader = loader;
}
#endif

bool boot_cutover_install_bound(struct boot_cutover_env *e, struct app_context *ctx,
    const struct chain_params *params, const struct boot_bound_bundle_observation *observation)
{
    if (!e || !ctx || !params || !observation) return false;
    enum boot_bound_consume_result consumed = boot_install_bound_bundle_consume(
        ctx->datadir, observation);
    if (consumed != BOOT_BOUND_CONSUME_OK) {
        LOG_ERROR("wallet", "bound install request consume failed: %d", (int)consumed);
        return false;
    }
    struct wallet_history_capability history;
    wallet_history_capability_init(&history);
    struct zcl_result acquired = wallet_history_capability_acquire_bound(&history,
        observation->private_history_path, observation->snapshot_sha3,
        observation->history_manifest_root);
    if (!acquired.ok) {
        LOG_ERROR("wallet", "bound history acquisition failed: %s", acquired.message);
        wallet_history_capability_release(&history);
        return false;
    }
    struct block_index *tip = NULL;
    bool loaded = false;
#ifdef ZCL_TESTING
    if (g_test_prebinding_loader)
        loaded = g_test_prebinding_loader(e, ctx, params, &tip);
    else
#endif
        loaded = boot_cutover_load_prebinding_chain(e, ctx, params, &tip);
    if (!loaded) {
        wallet_history_capability_release(&history);
        return false;
    }
    struct consensus_state_install_runtime_result result = {0};
    struct zcl_result installed = consensus_state_install_from_bound_bundle_terminal_guarded(
        e->node, e->state, ctx->datadir, e->wallet_db, e->wallet, observation, &history, &result);
    wallet_history_capability_release(&history);
    if (!installed.ok || !result.state_installed) {
        LOG_ERROR("wallet", "bound terminal install failed: %s", result.reason);
        return false;
    }
    struct wallet_cutover_binding binding;
    if (wallet_sqlite_cutover_read(e->wallet_db, &binding) != WALLET_CUTOVER_PENDING)
        return false;
    boot_install_bundle_clear(ctx->datadir);
    boot_cutover_restart_arm(&binding);
    return false;
}
