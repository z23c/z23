/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Terminal bundle preparation and guarded wallet install entrypoints. */
#if !defined(_WIN32)
#include "consensus_state_install_terminal_internal.h"
#include "consensus_state_snapshot_install_internal.h"
#include "config/boot_internal.h"
#include "services/block_index_loader.h"
#include "config/consensus_state_install_runtime.h"
#include "config/flysync_island.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "platform/fd_path.h"
#include "platform/private_directory.h"
#include "services/chain_state_service.h"
#include "storage/consensus_state_bundle_codec.h"
#include "util/safe_alloc.h"
#include "validation/main_state.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct zcl_result icb_terminal_prepare(struct icb_terminal_context *terminal,
    const char *datadir, struct main_state *ms,
    const struct consensus_state_bundle_manifest *manifest)
{
    const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
    const struct rom_state_checkpoint *rung =
        consensus_state_baked_trust_root_for_height(manifest->height);
    if (!rom || !rung || manifest->height <= rom->height ||
        consensus_state_header_chain_owns(ms, rung->height, rung->block_hash))
        return ZCL_OK;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/wallet-history", datadir);
    if (n < 0 || (size_t)n >= sizeof(path) ||
        !platform_private_directory_open_validated_traverse(path, &terminal->history_handle))
        return ZCL_ERR(-1, "wallet history directory is unavailable or not private");
    terminal->history_open = true;
    if (!platform_fd_path(path, sizeof(path), (int)terminal->history_handle, NULL))
        return ZCL_ERR(-1, "wallet history directory handle path is too long");
    terminal->archive = zcl_calloc(1, sizeof(*terminal->archive), "wallet history archive state");
    if (!terminal->archive) return ZCL_ERR(-1, "wallet history state allocation failed");
    main_state_init(terminal->archive);
    struct zcl_result rc = block_index_history_archive_open(
        terminal->archive, path, 3500000, manifest->height,
        manifest->block_hash, terminal->window);
    if (!rc.ok) return rc;
    struct chain_state_frontier_view frontier;
    struct zcl_result bound = csr_capture_frontiers(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header,
        manifest->height, &frontier);
    if (!bound.ok) return bound;
    struct chain_state_view view;
    csr_snapshot(csr_instance(), &view);
    struct block_index *old_tip = active_chain_tip(&ms->chain_active);
    struct block_index *top = flysync_island_prepare_terminal_window(
        ms, terminal->window, ISLAND_ANCHOR_WINDOW, manifest->height);
    if (!top) return ZCL_ERR(-1, "terminal header window preparation refused");
    if (!csr_restore_in_memory_view(csr_instance(), old_tip, top, &view.coins_best_block))
        return ZCL_ERR(-1, "terminal header frontier restore refused");
    terminal->prepared = true;
    return ZCL_OK;
}

struct zcl_result consensus_state_install_from_bundle_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    struct consensus_state_install_runtime_result *out)
{
    if (!boot_wallet_cutover_startup_context_matches(ndb, ws, wallet, ms)) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "wallet cutover requires the startup context");
        }
        return ZCL_ERR(-1, "wallet cutover requires the startup context");
    }
    return icb_install_wallet_guarded(ndb, ms, bundle_path, datadir, ws, wallet, NULL, out);
}

struct zcl_result consensus_state_install_from_bundle_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    struct consensus_state_install_runtime_result *out)
{
    if (!boot_wallet_cutover_startup_context_matches(ndb, ws, wallet, ms)) {
        if (out) {
            memset(out, 0, sizeof(*out));
            out->owner_gate_refused = true;
            snprintf(out->reason, sizeof(out->reason), "wallet cutover requires the startup context");
        }
        return ZCL_ERR(-1, "wallet cutover requires the startup context");
    }
    struct icb_terminal_context terminal = {0};
    struct zcl_result rc = icb_install_wallet_guarded(
        ndb, ms, bundle_path, datadir, ws, wallet, &terminal, out);
    if (terminal.archive) {
        main_state_free(terminal.archive);
        free(terminal.archive);
    }
    if (terminal.history_open) platform_private_directory_close(terminal.history_handle);
    return rc;
}
#endif
