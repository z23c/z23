/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Terminal bundle preparation and guarded wallet install entrypoints. */
#if !defined(_WIN32)
#include "consensus_state_install_terminal_internal.h"
#include "consensus_state_install_stage.h"
#include "consensus_state_snapshot_install_internal.h"
#include "config/boot_internal.h"
#include "services/block_index_loader.h"
#include "services/wallet_history_capability.h"
#include "config/consensus_state_install_runtime.h"
#include "config/flysync_island.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "jobs/stage_repair.h"
#include "storage/progress_store.h"
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

/* Preflight before inserting any window rows into the startup map. */
bool icb_terminal_archive_has_frontier(const struct icb_terminal_context *terminal,
    const struct block_index *old_tip)
{
    if (!terminal || !terminal->archive || !old_tip || !old_tip->phashBlock ||
        old_tip->nHeight < 0) return false;
    struct block_index *row = terminal->archive->pindex_best_header;
    if (!row || row->nHeight < ISLAND_ANCHOR_WINDOW ||
        old_tip->nHeight > row->nHeight - ISLAND_ANCHOR_WINDOW) return false;
    while (row && row->nHeight > old_tip->nHeight) row = row->pprev;
    return row && row->phashBlock && row->nHeight == old_tip->nHeight &&
        uint256_eq(row->phashBlock, old_tip->phashBlock);
}

/* Match all inserted rows against the authenticated archive before linking. */
static bool icb_terminal_collect_window(struct block_index *top,
    struct block_index *archive, struct block_index *rows[ISLAND_ANCHOR_WINDOW],
    struct block_index **parent)
{
    struct block_index *window = top;
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW; ++i) {
        if (!window || !archive || !window->phashBlock || !archive->phashBlock ||
            window->nHeight != archive->nHeight || !uint256_eq(window->phashBlock, archive->phashBlock))
            return false;
        rows[i] = window;
        if (i + 1 < ISLAND_ANCHOR_WINDOW) window = window->pprev;
        archive = archive->pprev;
    }
    if (window->pprev || !archive) return false;
    *parent = archive;
    return true;
}

static bool icb_terminal_parent_has_frontier(struct block_index *parent,
    const struct block_index *old_tip)
{
    if (old_tip->nHeight < 0 || old_tip->nHeight > parent->nHeight) return false;
    while (parent && parent->nHeight > old_tip->nHeight) parent = parent->pprev;
    return parent && parent->phashBlock && parent->nHeight == old_tip->nHeight &&
        uint256_eq(parent->phashBlock, old_tip->phashBlock);
}

/* The archive reader has already authenticated every parent to network genesis.
 * Only the newly inserted window borrows archive nodes, until terminal cleanup. */
bool icb_terminal_link_window(struct icb_terminal_context *terminal,
    struct block_index *top, struct block_index *old_tip)
{
    if (!terminal || !terminal->archive || !top || !old_tip || !old_tip->phashBlock ||
        !terminal->archive->pindex_best_header || terminal->bridge_window[0]) return false;
    struct block_index *rows[ISLAND_ANCHOR_WINDOW];
    struct block_index *parent = NULL;
    if (!icb_terminal_collect_window(top, terminal->archive->pindex_best_header,
                                     rows, &parent) ||
        !icb_terminal_parent_has_frontier(parent, old_tip)) return false;
    memcpy(terminal->bridge_window, rows, sizeof(rows));
    rows[ISLAND_ANCHOR_WINDOW - 1]->pprev = parent;
    for (int i = ISLAND_ANCHOR_WINDOW - 1; i >= 0; --i) {
        rows[i]->pskip = NULL;
        block_index_build_skip(rows[i]);
    }
    return true;
}

void icb_terminal_unlink_window(struct icb_terminal_context *terminal)
{
    if (!terminal || !terminal->bridge_window[0]) return;
    terminal->bridge_window[ISLAND_ANCHOR_WINDOW - 1]->pprev = NULL;
    for (int i = ISLAND_ANCHOR_WINDOW - 1; i >= 0; --i) {
        struct block_index *row = terminal->bridge_window[i];
        row->pskip = NULL;
        block_index_build_skip(row);
    }
    memset(terminal->bridge_window, 0, sizeof(terminal->bridge_window));
}

static struct zcl_result icb_terminal_open_history(struct icb_terminal_context *terminal,
    const char *datadir, const struct consensus_state_bundle_manifest *manifest)
{
    char path[PATH_MAX];
    if (terminal->history_capability) {
        const char *p = wallet_history_capability_path(terminal->history_capability);
        int n = p ? snprintf(path, sizeof(path), "%s", p) : -1;
        if (n < 0 || (size_t)n >= sizeof(path))
            return ZCL_ERR(-1, "wallet history capability is unavailable");
    } else {
        int n = snprintf(path, sizeof(path), "%s/wallet-history", datadir);
        if (n < 0 || (size_t)n >= sizeof(path) ||
            !platform_private_directory_open_validated_traverse(path, &terminal->history_handle))
            return ZCL_ERR(-1, "wallet history directory is unavailable or not private");
        terminal->history_open = true;
        if (!platform_fd_path(path, sizeof(path), (int)terminal->history_handle, NULL))
            return ZCL_ERR(-1, "wallet history directory handle path is too long");
    }
    terminal->archive = zcl_calloc(1, sizeof(*terminal->archive), "wallet history archive state");
    if (!terminal->archive) return ZCL_ERR(-1, "wallet history state allocation failed");
    main_state_init(terminal->archive);
    return block_index_history_archive_open(terminal->archive, path, 3500000,
        manifest->height, manifest->block_hash, terminal->window);
}

static struct zcl_result icb_terminal_select_window(struct icb_terminal_context *terminal,
    struct main_state *ms, const struct consensus_state_bundle_manifest *manifest)
{
    struct chain_state_frontier_view frontier;
    struct zcl_result bound = csr_capture_frontiers(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header,
        manifest->height, &frontier);
    if (!bound.ok) return bound;
    struct chain_state_view view;
    csr_snapshot(csr_instance(), &view);
    struct block_index *old_tip = active_chain_tip(&ms->chain_active);
    if (!icb_terminal_archive_has_frontier(terminal, old_tip))
        return ZCL_ERR(-1, "terminal history does not contain the active frontier");
    (void)stage_reducer_frontier_restore_script(progress_store_db(), ms, old_tip);
    struct block_index *top = flysync_island_prepare_terminal_window(
        ms, terminal->window, ISLAND_ANCHOR_WINDOW, manifest->height);
    if (!top) return ZCL_ERR(-1, "terminal header window preparation refused");
    if (!icb_terminal_link_window(terminal, top, old_tip))
        return ZCL_ERR(-1, "terminal history does not contain the active frontier");
    if (!csr_restore_in_memory_view(csr_instance(), old_tip, top, &view.coins_best_block))
        return ZCL_ERR(-1, "terminal header frontier restore refused");
    terminal->prepared = true;
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result icb_terminal_select_window_test(struct icb_terminal_context *terminal,
    struct main_state *ms, const struct consensus_state_bundle_manifest *manifest)
{
    return icb_terminal_select_window(terminal, ms, manifest);
}
#endif

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
    struct zcl_result rc = icb_terminal_open_history(terminal, datadir, manifest);
    return rc.ok ? icb_terminal_select_window(terminal, ms, manifest) : rc;
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
    return icb_install_wallet_guarded(ndb, ms, bundle_path, datadir, ws, wallet, NULL, NULL, NULL, out);
}

#ifdef ZCL_TESTING
static void (*icb_after_stage_hook)(void *);
static void *icb_after_stage_context;
void consensus_state_install_test_after_stage(void (*hook)(void *), void *context)
{
    icb_after_stage_hook = hook;
    icb_after_stage_context = context;
}
#endif

static struct zcl_result icb_terminal_context_check(
    struct node_db *ndb, struct main_state *ms, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history,
    struct consensus_state_install_runtime_result *out)
{
    if (observation && (!history || !wallet_history_capability_matches(history,
            observation->history_manifest_root).ok)) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "wallet history root does not match request");
        }
        return ZCL_ERR(-1, "wallet history root does not match request");
    }
    if (observation && !wallet_history_capability_matches_path(history, observation->private_history_path).ok) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "wallet history path does not match request");
        }
        return ZCL_ERR(-1, "wallet history path does not match request");
    }
    if (!boot_wallet_cutover_startup_context_matches(ndb, ws, wallet, ms)) {
        if (out) {
            memset(out, 0, sizeof(*out));
            out->owner_gate_refused = true;
            snprintf(out->reason, sizeof(out->reason), "wallet cutover requires the startup context");
        }
        return ZCL_ERR(-1, "wallet cutover requires the startup context");
    }
    return ZCL_OK;
}
struct icb_terminal_stage {
    struct consensus_state_artifact_evidence *staged;
    uint8_t whole[32], logical[32];
    char retained[PATH_MAX];
};
static const char *icb_terminal_source_refusal(struct consensus_state_artifact_evidence *source,
    const uint8_t whole[32], const struct boot_bound_bundle_observation *observation)
{
    if (!observation) return NULL;
    if (memcmp(whole, observation->snapshot_sha3, 32)) return "bundle digest does not match request";
    struct consensus_state_bundle_manifest manifest;
    if (!consensus_state_artifact_evidence_manifest_copy(source, &manifest) ||
        manifest.height != observation->endpoint_height ||
        memcmp(manifest.block_hash, observation->endpoint_hash, 32))
        return "bundle endpoint does not match request";
    return NULL;
}
static struct zcl_result icb_terminal_stage_bound(const char *bundle_path, const char *datadir,
    const struct boot_bound_bundle_observation *observation, struct icb_terminal_stage *stage,
    struct consensus_state_install_runtime_result *out)
{
    struct consensus_state_artifact_evidence *source = NULL;
    bool ok = consensus_state_artifact_evidence_open(bundle_path, -1, &source).ok &&
        consensus_state_artifact_evidence_file_digest(source, stage->whole) &&
        consensus_state_artifact_evidence_digest(source, stage->logical);
    const char *refusal = ok ? icb_terminal_source_refusal(source, stage->whole, observation) : NULL;
    ok = ok && !refusal && consensus_state_install_stage(datadir, source, stage->retained, sizeof(stage->retained), &stage->staged) &&
        (!observation || consensus_state_stage_evidence_matches(stage->staged, stage->whole, stage->logical));
    if (!consensus_state_artifact_evidence_close(&source)) ok = false;
    if (!ok) {
        (void)consensus_state_artifact_evidence_close(&stage->staged);
        if (out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "%s", refusal ? refusal : "retained bundle staging failed"); }
        return ZCL_ERR(-1, "%s", refusal ? refusal : "retained bundle staging failed");
    }
    return ZCL_OK;
}
static struct zcl_result icb_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history,
    struct consensus_state_install_runtime_result *out)
{
    struct zcl_result rc = icb_terminal_context_check(ndb, ms, ws, wallet, observation, history, out);
    if (!rc.ok) return rc;
    struct icb_terminal_stage stage = {0};
    rc = icb_terminal_stage_bound(bundle_path, datadir, observation, &stage, out);
    if (!rc.ok) return rc;
#ifdef ZCL_TESTING
    if (icb_after_stage_hook) icb_after_stage_hook(icb_after_stage_context);
#endif
    struct icb_terminal_context terminal = {0};
    terminal.history_capability = history;
    terminal.observation = observation;
    rc = icb_install_wallet_guarded(
        ndb, ms, stage.retained, datadir, ws, wallet, stage.whole, stage.logical, &terminal, out);
    if (!consensus_state_artifact_evidence_close(&stage.staged) && rc.ok) {
        rc = ZCL_ERR(-1, "retained bundle evidence close failed");
        if (out) snprintf(out->reason, sizeof(out->reason), "%s", rc.message);
    }
    icb_terminal_unlink_window(&terminal);
    if (terminal.archive) {
        main_state_free(terminal.archive);
        free(terminal.archive);
    }
    if (terminal.history_open) platform_private_directory_close(terminal.history_handle);
    return rc;
}
struct zcl_result consensus_state_install_from_bundle_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    struct consensus_state_install_runtime_result *out)
{
    return icb_terminal_guarded(ndb, ms, bundle_path, datadir, ws, wallet, NULL, NULL, out);
}
struct zcl_result consensus_state_install_from_bound_bundle_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history,
    struct consensus_state_install_runtime_result *out)
{
    if (!observation) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "bound request is unavailable");
        }
        return ZCL_ERR(-1, "bound request is unavailable");
    }
    return icb_terminal_guarded(ndb, ms, observation->bundle_path, datadir,
        ws, wallet, observation, history, out);
}
struct zcl_result consensus_state_install_from_bundle_terminal_old_retry(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    struct icb_terminal_context terminal = {0};
    struct zcl_result rc = icb_install_wallet_old_retry(
        ndb, ms, bundle_path, datadir, ws, wallet, expected, &terminal, out);
    icb_terminal_unlink_window(&terminal);
    if (terminal.archive) {
        main_state_free(terminal.archive);
        free(terminal.archive);
    }
    if (terminal.history_open) platform_private_directory_close(terminal.history_handle);
    return rc;
}
#endif
