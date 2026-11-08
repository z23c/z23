/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Terminal bundle preparation and guarded wallet install entrypoints. */
#if !defined(_WIN32)
#include "consensus_state_install_terminal_internal.h"
#include "consensus_state_install_stage.h"
#include "consensus_state_snapshot_install_internal.h"
#include "config/boot_internal.h"
#include "services/block_index_loader.h"
#include "storage/blocks_mmap_reader.h"
#include "core/serialize.h"
#include "util/thread_registry.h"
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
static bool icb_terminal_archive_has_endpoint(const struct icb_terminal_context *terminal,
    int32_t old_height, const uint8_t old_hash[32])
{
    if (!terminal || !terminal->archive || !old_hash || old_height < 0) return false;
    struct block_index *row = terminal->archive->pindex_best_header;
    if (!row || row->nHeight < ISLAND_ANCHOR_WINDOW ||
        old_height > row->nHeight - ISLAND_ANCHOR_WINDOW) return false;
    while (row && row->nHeight > old_height) row = row->pprev;
    return row && row->phashBlock && row->nHeight == old_height &&
        !memcmp(row->phashBlock->data, old_hash, 32);
}
bool icb_terminal_archive_has_frontier(const struct icb_terminal_context *terminal,
    const struct block_index *old_tip)
{
    return old_tip && old_tip->phashBlock &&
        icb_terminal_archive_has_endpoint(terminal, old_tip->nHeight, old_tip->phashBlock->data);
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

#ifdef ZCL_TESTING
static unsigned bound_history_archive_opens;
void bound_history_preflight_test_reset_archive_opens(void) { bound_history_archive_opens = 0; }
unsigned bound_history_preflight_test_archive_opens(void) { return bound_history_archive_opens; }
#endif

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
#ifdef ZCL_TESTING
    ++bound_history_archive_opens;
#endif
    return block_index_history_archive_open(terminal->archive, path, 3500000,
        manifest->height, manifest->block_hash, terminal->window);
}

struct bound_history_preflight {
    struct icb_terminal_context terminal;
    struct blocks_mmap *reader;
    const struct consensus_state_artifact_evidence *artifact;
    const struct wallet_history_capability *capability;
    struct boot_bound_bundle_observation request;
    bool selected;
    int32_t old_height;
    uint8_t old_hash[32];
};

static bool bound_history_request_inputs(const struct boot_bound_bundle_observation *request,
    const struct wallet_history_capability *held)
{
    return memchr(request->private_history_path, 0, sizeof(request->private_history_path)) &&
        memchr(request->bundle_path, 0, sizeof(request->bundle_path)) &&
        wallet_history_capability_matches(held, request->history_manifest_root).ok &&
        wallet_history_capability_matches_path(held, request->private_history_path).ok;
}
static bool bound_history_artifact_inputs(const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact, struct consensus_state_bundle_manifest *manifest)
{
    uint8_t whole[32], logical[32];
    return consensus_state_artifact_evidence_file_digest(artifact, whole) &&
        !memcmp(whole, request->snapshot_sha3, 32) &&
        consensus_state_artifact_evidence_manifest_copy(artifact, manifest) &&
        consensus_state_artifact_evidence_digest(artifact, logical) &&
        !memcmp(logical, manifest->artifact_digest, 32) &&
        manifest->height == request->endpoint_height &&
        !memcmp(manifest->block_hash, request->endpoint_hash, 32) &&
        consensus_state_rom_checkpoint_content_matches(manifest);
}
static bool bound_history_inputs(const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, struct consensus_state_bundle_manifest *manifest)
{
    return request && artifact && held && manifest && bound_history_request_inputs(request, held) &&
        bound_history_artifact_inputs(request, artifact, manifest);
}

static bool bound_history_request_same(const struct boot_bound_bundle_observation *a,
    const struct boot_bound_bundle_observation *b)
{
    return !memcmp(a->snapshot_sha3, b->snapshot_sha3, 32) &&
        !memcmp(a->history_manifest_root, b->history_manifest_root, 32) &&
        a->attempts == b->attempts && a->endpoint_height == b->endpoint_height &&
        !memcmp(a->endpoint_hash, b->endpoint_hash, 32) &&
        !strcmp(a->private_history_path, b->private_history_path) &&
        !strcmp(a->bundle_path, b->bundle_path);
}

static bool bound_history_identity(const struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, const struct block_index *old_tip)
{
    return p && request && artifact && held && old_tip && old_tip->phashBlock &&
        p->artifact == artifact && p->capability == held && old_tip->nHeight == p->old_height &&
        !memcmp(old_tip->phashBlock->data, p->old_hash, 32) &&
        bound_history_request_same(request, &p->request);
}

struct zcl_result bound_history_preflight_recheck(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, const struct block_index *old_tip)
{
    struct consensus_state_bundle_manifest manifest;
    if (!bound_history_inputs(request, artifact, held, &manifest) ||
        !bound_history_identity(p, request, artifact, held, old_tip) ||
        !icb_terminal_archive_has_frontier(&p->terminal, old_tip))
        return ZCL_ERR(-1, "bound preflight identity or authority unavailable");
    return ZCL_OK;
}

static void bound_history_preflight_close_impl(struct bound_history_preflight **object)
{
    if (!object || !*object) return;
    struct bound_history_preflight *p = *object;
    icb_terminal_unlink_window(&p->terminal);
    if (p->reader) bmr_close(p->reader);
    if (p->terminal.archive) { main_state_free(p->terminal.archive); free(p->terminal.archive); }
    free(p); *object = NULL;
}

struct icb_terminal_context *bound_history_preflight_terminal(struct bound_history_preflight *p)
{ return p ? &p->terminal : NULL; }

static bool bound_history_cached_header(const struct block_index *row, struct block_header *header)
{
    const struct block_index_hdrext *ext = block_index_hdrext_peek(row);
    if (!ext || !ext->nSolution || !ext->nSolutionSize || ext->nSolutionSize > MAX_SOLUTION_SIZE)
        return false;
    block_header_init(header);
    header->nVersion = row->nVersion;
    if (row->pprev && row->pprev->phashBlock) header->hashPrevBlock = *row->pprev->phashBlock;
    header->hashMerkleRoot = ext->hashMerkleRoot;
    header->hashFinalSaplingRoot = row->hashFinalSaplingRoot;
    header->nTime = row->nTime; header->nBits = row->nBits; header->nNonce = ext->nNonce;
    memcpy(header->nSolution, ext->nSolution, ext->nSolutionSize);
    header->nSolutionSize = ext->nSolutionSize;
    return true;
}

static struct zcl_result bound_history_read_uncached(struct bound_history_preflight *p,
    const struct block_index *row, struct block_header *header)
{
    if (!p->reader) {
        char blocks[128]; const char *path = wallet_history_capability_path(p->capability);
        int n = path ? snprintf(blocks, sizeof(blocks), "%s/blocks", path) : -1;
        if (n < 0 || (size_t)n >= sizeof(blocks) || !bmr_open(blocks, &p->reader))
            return ZCL_ERR(BOUND_HISTORY_HEADER_CORRUPT, "history block directory unavailable");
    }
    size_t len = 0;
    const uint8_t *payload = row->nFile >= 0 ? bmr_get_payload(p->reader, row->nFile, row->nDataPos, &len) : NULL;
    if (!payload) return ZCL_ERR(BOUND_HISTORY_HEADER_CORRUPT, "history block payload unavailable");
    struct byte_stream stream; stream_init_from_data(&stream, payload, len);
    block_header_init(header);
    if (!block_header_deserialize(header, &stream)) return ZCL_ERR(BOUND_HISTORY_HEADER_CORRUPT, "history block header invalid");
    return ZCL_OK;
}
static bool bound_history_header_matches(const struct block_index *row, const struct uint256 *key,
                                         const struct block_header *header)
{
    struct uint256 actual; block_header_get_hash(header, &actual);
    return uint256_eq(&actual, key) && header->nVersion == row->nVersion &&
        header->nTime == row->nTime && header->nBits == row->nBits &&
        uint256_eq(&header->hashFinalSaplingRoot, &row->hashFinalSaplingRoot);
}
static struct zcl_result bound_history_header_request(struct bound_history_preflight *p,
    int32_t height, const uint8_t *hash, const struct block_header *out)
{
    if (!p || height < 0 || !hash || !out) return ZCL_ERR(BOUND_HISTORY_HEADER_INVALID, "invalid history header request");
    if (thread_registry_shutdown_requested()) return ZCL_ERR(BOUND_HISTORY_HEADER_CANCELLED, "history header read cancelled");
    if (!p->terminal.archive || !wallet_history_capability_matches(p->capability,
        p->request.history_manifest_root).ok) return ZCL_ERR(BOUND_HISTORY_HEADER_UNAVAILABLE, "retained history unavailable");
    return ZCL_OK;
}
static bool bound_history_row_matches(const struct block_index *row, int32_t height, const uint8_t hash[32])
{
    return row && row->nHeight == height && row->phashBlock && !memcmp(row->phashBlock->data, hash, 32);
}
struct zcl_result bound_history_preflight_read_header(struct bound_history_preflight *p,
    int32_t height, const uint8_t hash[32], struct block_header *out)
{
    struct zcl_result request = bound_history_header_request(p, height, hash, out);
    if (!request.ok) return request;
    struct uint256 key; memcpy(key.data, hash, 32);
    const struct block_index *row = block_map_find(&p->terminal.archive->map_block_index, &key);
    if (!bound_history_row_matches(row, height, hash))
        return ZCL_ERR(BOUND_HISTORY_HEADER_UNAVAILABLE, "history header is unavailable");
    struct block_header header;
    if (!bound_history_cached_header(row, &header)) {
        struct zcl_result read = bound_history_read_uncached(p, row, &header);
        if (!read.ok) return read;
    }
    if (header.nSolutionSize > MAX_SOLUTION_SIZE)
        return ZCL_ERR(BOUND_HISTORY_HEADER_CORRUPT, "history block solution is oversized");
    if (!bound_history_header_matches(row, &key, &header))
        return ZCL_ERR(BOUND_HISTORY_HEADER_CORRUPT, "history block header identity mismatch");
    *out = header;
    return ZCL_OK;
}

static bool bound_history_archive_matches(const struct bound_history_preflight *p)
{
    return icb_terminal_archive_has_endpoint(&p->terminal, p->old_height, p->old_hash);
}

struct zcl_result bound_history_preflight_open(struct bound_history_preflight **out,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, int32_t old_height, const uint8_t old_hash[32])
{
    if (out) *out = NULL;
    struct consensus_state_bundle_manifest manifest;
    if (!out || old_height < 0 || !old_hash ||
        !bound_history_inputs(request, artifact, held, &manifest))
        return ZCL_ERR(-1, "bound preflight input or authority unavailable");
    struct bound_history_preflight *p = zcl_calloc(1, sizeof(*p), "bound history preflight");
    if (!p) return ZCL_ERR(-1, "bound preflight allocation failed");
    p->artifact = artifact; p->capability = held; p->request = *request;
    p->old_height = old_height; memcpy(p->old_hash, old_hash, 32);
    p->terminal.history_capability = held; p->terminal.observation = &p->request;
    p->terminal.preflight_owner = p;
    struct zcl_result rc = icb_terminal_open_history(&p->terminal, NULL, &manifest);
    if (rc.ok && (!bound_history_inputs(request, artifact, held, &manifest) ||
                  !bound_history_request_same(request, &p->request) || !bound_history_archive_matches(p)))
        rc = ZCL_ERR(-1, "bound preflight authority changed");
    if (!rc.ok) { bound_history_preflight_close_impl(&p); return rc; }
    *out = p; return ZCL_OK;
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

struct zcl_result bound_history_preflight_prepare(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, struct main_state *ms)
{
    if (!ms) return ZCL_ERR(-1, "bound preflight main state unavailable");
    struct zcl_result rc = bound_history_preflight_recheck(p, request, artifact, held,
                                                         active_chain_tip(&ms->chain_active));
    if (!rc.ok || p->selected) return rc.ok ? ZCL_ERR(-1, "bound preflight already selected") : rc;
    struct consensus_state_bundle_manifest manifest;
    if (!consensus_state_artifact_evidence_manifest_copy(artifact, &manifest))
        return ZCL_ERR(-1, "bound preflight artifact unavailable");
    rc = icb_terminal_select_window(&p->terminal, ms, &manifest);
    if (rc.ok) p->selected = true;
    return rc;
}

#ifdef ZCL_TESTING
struct zcl_result icb_terminal_select_window_test(struct icb_terminal_context *terminal,
    struct main_state *ms, const struct consensus_state_bundle_manifest *manifest)
{
    return icb_terminal_select_window(terminal, ms, manifest);
}
#endif

static struct zcl_result icb_terminal_prepare_borrowed(struct icb_terminal_context *terminal,
    struct main_state *ms, const struct consensus_state_bundle_manifest *manifest)
{
    struct bound_history_preflight *p = terminal->preflight_owner;
    if (!ms || !manifest || terminal != &p->terminal || !p->selected)
        return ZCL_ERR(-1, "bound preflight handoff refused");
    struct zcl_result checked = bound_history_preflight_recheck(p, terminal->observation,
        p->artifact, terminal->history_capability, active_chain_tip(&ms->chain_active));
    struct consensus_state_bundle_manifest retained;
    if (!checked.ok || !consensus_state_artifact_evidence_manifest_copy(p->artifact, &retained) ||
        retained.height != manifest->height || memcmp(retained.block_hash, manifest->block_hash, 32) ||
        memcmp(retained.artifact_digest, manifest->artifact_digest, 32))
        return ZCL_ERR(-1, "bound preflight handoff refused");
    return ZCL_OK;
}
struct zcl_result icb_terminal_prepare(struct icb_terminal_context *terminal,
    const char *datadir, struct main_state *ms,
    const struct consensus_state_bundle_manifest *manifest)
{
    if (terminal && terminal->preflight_owner)
        return icb_terminal_prepare_borrowed(terminal, ms, manifest);
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
static struct zcl_result icb_terminal_check_borrowed(struct bound_history_preflight *borrowed,
    struct main_state *ms, const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history, const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    if (!borrowed) return ZCL_OK;
    struct zcl_result rc;
    if (!ms || borrowed->selected || (expected &&
        (!expected->history_identity_present || expected->old_height != borrowed->old_height ||
         memcmp(expected->old_hash, borrowed->old_hash, 32) ||
         expected->target_height != borrowed->request.endpoint_height ||
         memcmp(expected->target_hash, borrowed->request.endpoint_hash, 32) ||
         memcmp(expected->snapshot_whole_sha3, borrowed->request.snapshot_sha3, 32) ||
         memcmp(expected->history_manifest_root, borrowed->request.history_manifest_root, 32))))
        rc = ZCL_ERR(-1, "bound preflight handoff unavailable");
    else rc = bound_history_preflight_recheck(borrowed, observation, borrowed->artifact, history,
                                               active_chain_tip(&ms->chain_active));
    if (!rc.ok && out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "%s", rc.message); }
    return rc;
}
static struct zcl_result icb_terminal_choose_context(struct bound_history_preflight *borrowed,
    struct main_state *ms, const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history, struct icb_terminal_context *local,
    struct icb_terminal_context **terminal, struct consensus_state_install_runtime_result *out)
{
    if (!borrowed) {
        local->history_capability = history;
        local->observation = observation;
        return ZCL_OK;
    }
    struct zcl_result rc = bound_history_preflight_prepare(borrowed, observation, borrowed->artifact, history, ms);
    if (!rc.ok) {
        if (out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "%s", rc.message); }
    } else *terminal = &borrowed->terminal;
    return rc;
}
static struct zcl_result icb_terminal_close_staged(struct icb_terminal_stage *stage,
    struct consensus_state_install_runtime_result *out, struct zcl_result rc)
{
    if (!consensus_state_artifact_evidence_close(&stage->staged) && rc.ok) {
        rc = ZCL_ERR(-1, "retained bundle evidence close failed");
        if (out) snprintf(out->reason, sizeof(out->reason), "%s", rc.message);
    }
    return rc;
}
static void icb_terminal_close_local(struct icb_terminal_context *local, struct bound_history_preflight *borrowed)
{
    if (borrowed) return;
    icb_terminal_unlink_window(local);
    if (local->archive) { main_state_free(local->archive); free(local->archive); }
    if (local->history_open) platform_private_directory_close(local->history_handle);
}
static struct zcl_result icb_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history,
    const struct wallet_cutover_binding *expected,
    struct bound_history_preflight *borrowed,
    struct consensus_state_install_runtime_result *out)
{
    struct zcl_result rc = icb_terminal_context_check(ndb, ms, ws, wallet, observation, history, out);
    if (!rc.ok) return rc;
    rc = icb_terminal_check_borrowed(borrowed, ms, observation, history, expected, out);
    if (!rc.ok) return rc;
    struct icb_terminal_stage stage = {0};
    rc = icb_terminal_stage_bound(bundle_path, datadir, observation, &stage, out);
    if (!rc.ok) return rc;
#ifdef ZCL_TESTING
    if (icb_after_stage_hook) icb_after_stage_hook(icb_after_stage_context);
#endif
    struct icb_terminal_context local = {0};
    struct icb_terminal_context *terminal = &local;
    rc = icb_terminal_choose_context(borrowed, ms, observation, history, &local, &terminal, out);
    if (rc.ok) rc = expected ? icb_install_wallet_old_retry(
        ndb, ms, stage.retained, datadir, ws, wallet, expected, terminal, stage.whole, stage.logical, out)
        : icb_install_wallet_guarded(
        ndb, ms, stage.retained, datadir, ws, wallet, stage.whole, stage.logical, terminal, out);
    rc = icb_terminal_close_staged(&stage, out, rc);
    icb_terminal_close_local(&local, borrowed);
    return rc;
}
struct zcl_result bound_history_preflight_install(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, struct consensus_state_install_runtime_result *out)
{
    if (!p || !observation || !history) {
        if (out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "bound preflight unavailable"); }
        return ZCL_ERR(-1, "bound preflight unavailable");
    }
    return icb_terminal_guarded(ndb, ms, observation->bundle_path, datadir,
                                ws, wallet, observation, history, NULL, p, out);
}
struct zcl_result bound_history_preflight_install_old_retry(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    if (!p || !observation || !history || !expected || !expected->history_identity_present ||
        observation->endpoint_height != expected->target_height ||
        memcmp(observation->endpoint_hash, expected->target_hash, 32) ||
        memcmp(observation->snapshot_sha3, expected->snapshot_whole_sha3, 32) ||
        memcmp(observation->history_manifest_root, expected->history_manifest_root, 32)) {
        if (out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "bound old retry does not match pending binding"); }
        return ZCL_ERR(-1, "bound old retry does not match pending binding");
    }
    return icb_terminal_guarded(ndb, ms, observation->bundle_path, datadir,
                                ws, wallet, observation, history, expected, p, out);
}
#ifdef ZCL_TESTING
static struct zcl_result (*boot_test_terminal_hook)(struct node_db *, struct main_state *,
    const char *, const char *, struct wallet_sqlite *, struct wallet *,
    struct consensus_state_install_runtime_result *);
void boot_test_set_terminal_hook(struct zcl_result (*hook)(struct node_db *, struct main_state *,
    const char *, const char *, struct wallet_sqlite *, struct wallet *,
    struct consensus_state_install_runtime_result *))
{
    boot_test_terminal_hook = hook;
}
#endif

struct zcl_result consensus_state_install_from_bundle_terminal_guarded(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    struct consensus_state_install_runtime_result *out)
{
#ifdef ZCL_TESTING
    if (boot_test_terminal_hook) return boot_test_terminal_hook(ndb, ms, bundle_path, datadir,
        ws, wallet, out);
#endif
    return icb_terminal_guarded(ndb, ms, bundle_path, datadir, ws, wallet, NULL, NULL, NULL, NULL, out);
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
        ws, wallet, observation, history, NULL, NULL, out);
}
struct zcl_result consensus_state_install_from_bound_bundle_terminal_old_retry(
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet,
    const struct boot_bound_bundle_observation *observation,
    const struct wallet_history_capability *history,
    const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    if (!observation || !expected || !expected->history_identity_present) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "bound old retry requires request and pending binding");
        }
        return ZCL_ERR(-1, "bound old retry requires request and pending binding");
    }
    if (observation->endpoint_height != expected->target_height ||
        memcmp(observation->endpoint_hash, expected->target_hash, 32) ||
        memcmp(observation->snapshot_sha3, expected->snapshot_whole_sha3, 32) ||
        memcmp(observation->history_manifest_root, expected->history_manifest_root, 32)) {
        if (out) {
            memset(out, 0, sizeof(*out));
            snprintf(out->reason, sizeof(out->reason), "bound old retry does not match pending binding");
        }
        return ZCL_ERR(-1, "bound old retry does not match pending binding");
    }
    return icb_terminal_guarded(ndb, ms, observation->bundle_path, datadir,
        ws, wallet, observation, history, expected, NULL, out);
}
struct zcl_result consensus_state_install_from_bundle_terminal_old_retry(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct wallet_sqlite *ws, struct wallet *wallet,
    const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    struct icb_terminal_context terminal = {0};
    struct zcl_result rc = icb_install_wallet_old_retry(
        ndb, ms, bundle_path, datadir, ws, wallet, expected, &terminal, NULL, NULL, out);
    icb_terminal_unlink_window(&terminal);
    if (terminal.archive) {
        main_state_free(terminal.archive);
        free(terminal.archive);
    }
    if (terminal.history_open) platform_private_directory_close(terminal.history_handle);
    return rc;
}
#else
#include "consensus_state_install_terminal_internal.h"
#include "config/consensus_state_install_runtime.h"
#include <stdio.h>
#include <string.h>
struct zcl_result bound_history_preflight_install(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, struct consensus_state_install_runtime_result *out)
{
    (void)p; (void)observation; (void)history; (void)ndb; (void)ms; (void)datadir;
    (void)ws; (void)wallet;
    if (out) {
        memset(out, 0, sizeof(*out));
        snprintf(out->reason, sizeof(out->reason), "bound history preflight is not qualified on Windows");
    }
    return ZCL_ERR(-1, "bound history preflight is not qualified on Windows");
}
struct zcl_result bound_history_preflight_install_old_retry(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *observation, const struct wallet_history_capability *history,
    struct node_db *ndb, struct main_state *ms, const char *datadir,
    struct wallet_sqlite *ws, struct wallet *wallet, const struct wallet_cutover_binding *expected,
    struct consensus_state_install_runtime_result *out)
{
    (void)p; (void)observation; (void)history; (void)ndb; (void)ms; (void)datadir;
    (void)ws; (void)wallet; (void)expected;
    if (out) { memset(out, 0, sizeof(*out)); snprintf(out->reason, sizeof(out->reason), "bound history preflight is not qualified on Windows"); }
    return ZCL_ERR(-1, "bound history preflight is not qualified on Windows");
}
struct zcl_result bound_history_preflight_read_header(struct bound_history_preflight *p,
    int32_t height, const uint8_t hash[32], struct block_header *out)
{
    (void)p; (void)height; (void)hash; (void)out;
    return ZCL_ERR(BOUND_HISTORY_HEADER_UNAVAILABLE, "bound history preflight is not qualified on Windows");
}
struct zcl_result bound_history_preflight_open(struct bound_history_preflight **out,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, int32_t old_height, const uint8_t old_hash[32])
{
    (void)request; (void)artifact; (void)held; (void)old_height; (void)old_hash;
    if (out) *out = NULL;
    return ZCL_ERR(-1, "bound history preflight is not qualified on Windows");
}
struct zcl_result bound_history_preflight_recheck(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, const struct block_index *tip)
{
    (void)p; (void)request; (void)artifact; (void)held; (void)tip;
    return ZCL_ERR(-1, "bound history preflight is not qualified on Windows");
}
struct zcl_result bound_history_preflight_prepare(struct bound_history_preflight *p,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held, struct main_state *ms)
{
    (void)p; (void)request; (void)artifact; (void)held; (void)ms;
    return ZCL_ERR(-1, "bound history preflight is not qualified on Windows");
}
struct icb_terminal_context *bound_history_preflight_terminal(struct bound_history_preflight *p)
{ (void)p; return NULL; }
static void bound_history_preflight_close_impl(struct bound_history_preflight **p)
{ if (p) *p = NULL; }
#endif

void bound_history_preflight_close(struct bound_history_preflight **p)
{ bound_history_preflight_close_impl(p); }
