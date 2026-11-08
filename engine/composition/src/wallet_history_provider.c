/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Export and retain the selected snapshot's immutable history. */
#include "config/wallet_history_provider.h"
#include "config/consensus_state_snapshot_install.h"
#include "config/boot_internal.h"
#include "config/boot_legacy_blocks.h"
#include "services/wallet_history_export.h"
#include "services/wallet_history_manifest.h"
#include "platform/fd_path.h"
#include "base/serialize_le.h"
#include "base/hex.h"
#include "util/safe_alloc.h"
#include "core/uint256.h"
#include "services/chain_frontier_snapshot_service.h"
#include "services/chain_state_service.h"
#include "jobs/validate_headers_stage.h"
#include "storage/consensus_state_bundle_codec.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "platform/directory_transaction.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "net/file_service.h"
#include "util/util.h"
#include "util/thread_registry.h"
#include "net/rom_seed.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool provider_decimal(const char *text, uint64_t *out)
{
    if (!text || !*text)
        return false;
    uint64_t value = 0;
    for (const char *p = text; *p; p++) {
        if (*p < '0' || *p > '9' || value > (UINT64_MAX - (unsigned)(*p - '0')) / 10)
            return false;
        value = value * 10 + (unsigned)(*p - '0');
    }
    *out = value;
    return value > 0;
}

enum wallet_history_provider_config_result wallet_history_provider_parse_budget(
    const char *parent, const char *rows, const char *bytes, const char *free_bytes,
    struct wallet_history_provider_budget *out)
{
    if (!out)
        return WALLET_HISTORY_PROVIDER_INVALID;
    memset(out, 0, sizeof(*out));
    if (!parent && !rows && !bytes && !free_bytes)
        return WALLET_HISTORY_PROVIDER_DISABLED;
    uint64_t r, b, f;
    if (!parent || parent[0] != '/' || !parent[1] ||
        !provider_decimal(rows, &r) || (uint64_t)(size_t)r != r ||
        !provider_decimal(bytes, &b) || !provider_decimal(free_bytes, &f))
        return WALLET_HISTORY_PROVIDER_INVALID;
    out->private_parent = parent;
    out->max_rows = (size_t)r;
    out->max_bytes = b;
    out->min_free_bytes = f;
    return WALLET_HISTORY_PROVIDER_CONFIGURED;
}

enum wallet_history_provider_config_result wallet_history_provider_read_budget(
    struct wallet_history_provider_budget *out)
{
    return wallet_history_provider_parse_budget(
        GetArg("-history-export-parent", NULL),
        GetArg("-history-export-max-rows", NULL),
        GetArg("-history-export-max-bytes", NULL),
        GetArg("-history-export-min-free-bytes", NULL), out);
}

static bool provider_served_covers(const struct chain_frontier_snapshot *snapshot,
                                   int32_t height)
{
    return snapshot->served.height_known && height <= snapshot->served.height;
}

#ifdef ZCL_TESTING
bool wallet_history_provider_served_covers_for_test(int32_t served, int32_t requested)
{
    struct chain_frontier_snapshot snapshot = {0};
    snapshot.served.height_known = true;
    snapshot.served.height = served;
    return provider_served_covers(&snapshot, requested);
}
#endif

static bool provider_endpoint(const struct wallet_history_provider_request *r)
{
    struct chain_frontier_snapshot before, after;
    struct chain_state_frontier_view view;
    progress_store_tx_lock();
    chain_frontier_snapshot_collect(&before, r->main);
    struct zcl_result captured = csr_capture_frontiers(csr_instance(),
        &r->main->chain_active, &r->main->pindex_best_header,
        r->endpoint_height, &view);
    bool ok = captured.ok && view.window.requested &&
        view.window.requested->phashBlock &&
        view.window.requested->nHeight == r->endpoint_height &&
        memcmp(view.window.requested->phashBlock->data, r->endpoint_hash, 32) == 0 &&
        block_index_is_valid(view.window.requested, BLOCK_VALID_SCRIPTS) &&
        !block_has_any_failure(view.window.requested) &&
        validate_headers_stage_has_pass_record(r->endpoint_height,
                                               view.window.requested->phashBlock);
    chain_frontier_snapshot_collect(&after, r->main);
    ok = ok && chain_frontier_snapshot_consistent(&before) &&
         chain_frontier_snapshot_consistent(&after) &&
         chain_frontier_snapshot_equal(&before, &after) &&
         provider_served_covers(&before, r->endpoint_height) &&
         provider_served_covers(&after, r->endpoint_height);
    progress_store_tx_unlock();
    return ok;
}

#ifdef ZCL_TESTING
bool wallet_history_provider_endpoint_for_test(struct main_state *main, int32_t height,
                                               const uint8_t hash[32])
{
    struct wallet_history_provider_request request = {.main = main, .endpoint_height = height};
    memcpy(request.endpoint_hash, hash, 32);
    return provider_endpoint(&request);
}
#endif

static bool provider_evidence(const struct wallet_history_provider_request *r,
                              struct consensus_state_artifact_evidence **out)
{
    *out = NULL;
    struct zcl_result opened = consensus_state_artifact_evidence_open(r->snapshot_path, -1, out);
    if (!opened.ok || !*out)
        return false;
    struct consensus_state_bundle_manifest manifest;
    uint8_t digest[32];
    return consensus_state_artifact_evidence_manifest_copy(*out, &manifest) &&
        consensus_state_artifact_evidence_file_digest(*out, digest) &&
        manifest.history_complete && manifest.source_clean &&
        manifest.validation_profile == CONSENSUS_STATE_VALIDATION_FULL &&
        manifest.height == r->endpoint_height &&
        memcmp(manifest.block_hash, r->endpoint_hash, 32) == 0 &&
        memcmp(digest, r->snapshot_digest, 32) == 0;
}

static bool provider_request_valid(const struct wallet_history_provider_request *r)
{
    return r && r->main && r->source_datadir && r->private_parent &&
        r->private_parent[0] == '/' && r->staging_leaf && r->destination_leaf &&
        r->snapshot_path && r->endpoint_height > 0 && r->max_rows &&
        r->max_bytes && r->min_free_bytes;
}

static bool provider_request_cancelled(const struct wallet_history_provider_request *r)
{
    return thread_registry_shutdown_requested() ||
           (r->cancelled && r->cancelled(r->cancel_context));
}

bool wallet_history_provider_recheck(const struct wallet_history_provider_request *r)
{
    if (!provider_request_valid(r))
        return false;
    struct consensus_state_artifact_evidence *evidence = NULL;
    bool ok = provider_evidence(r, &evidence) && provider_endpoint(r);
    if (evidence && !consensus_state_artifact_evidence_close(&evidence))
        ok = false;
    return ok;
}

static struct wallet_history_export_request provider_export_request(
    const struct wallet_history_provider_request *r)
{
    struct wallet_history_export_request request = {
        .source_datadir = r->source_datadir, .private_parent = r->private_parent,
        .staging_leaf = r->staging_leaf, .destination_leaf = r->destination_leaf,
        .endpoint_height = r->endpoint_height, .max_rows = r->max_rows,
        .max_bytes = r->max_bytes, .min_free_bytes = r->min_free_bytes,
        .cancelled = r->cancelled, .cancel_context = r->cancel_context,
    };
    memcpy(request.endpoint_hash, r->endpoint_hash, 32);
    return request;
}

enum { PROVIDER_RECORD_SIZE = 112 };
static const char provider_record_leaf[] = "history-completion.v1";

/* The record describes a candidate. It grants no authority without a fresh
 * archive, manifest, snapshot, endpoint and retained-directory verification. */
static unsigned provider_manifest_files(const struct file_manifest *manifest)
{
    unsigned count = 0;
    for (uint32_t i = 0; i < manifest->num_chunks; i++) {
        unsigned index = manifest->chunks[i].file_index;
        if (index < 253 && index + 1 > count) count = index + 1;
    }
    return count;
}

static void provider_record_encode(uint8_t record[PROVIDER_RECORD_SIZE],
    const struct wallet_history_provider_request *r, const struct file_manifest *manifest)
{
    memcpy(record, "Z23HST01", 8);
    zcl_write_u32_le(record + 8, (uint32_t)r->endpoint_height);
    zcl_write_u32_le(record + 12, provider_manifest_files(manifest));
    memcpy(record + 16, manifest->root_hash, 32);
    memcpy(record + 48, r->snapshot_digest, 32);
    memcpy(record + 80, r->endpoint_hash, 32);
}

static bool provider_record_publish(struct platform_directory_transaction *root,
    const struct wallet_history_provider_request *r, const struct file_manifest *manifest)
{
    uint8_t record[PROVIDER_RECORD_SIZE];
    if (!provider_manifest_files(manifest)) return false;
    provider_record_encode(record, r, manifest);
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_create(root, ".history-completion.v1.stage", &file) &&
        platform_directory_child_write_exact(&file, record, sizeof(record), 0) &&
        platform_directory_child_flush(&file) &&
        platform_directory_child_move_between(root, &file, root, provider_record_leaf, true) ==
            PLATFORM_DIRECTORY_OK;
    platform_directory_child_close(&file);
    return ok;
}

#if defined(__linux__) || defined(ZCL_TESTING)
static bool provider_record_read(struct platform_directory_transaction *root,
    const struct wallet_history_provider_request *r, uint8_t record[PROVIDER_RECORD_SIZE])
{
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_open(root, provider_record_leaf, &file) &&
        platform_directory_child_info(&file, &info) && info.size == PROVIDER_RECORD_SIZE &&
        info.current_user_only && info.link_count == 1 &&
        platform_directory_child_read_exact(&file, record, PROVIDER_RECORD_SIZE, 0) &&
        memcmp(record, "Z23HST01", 8) == 0 &&
        zcl_read_u32_le(record + 8) == (uint32_t)r->endpoint_height &&
        zcl_read_u32_le(record + 12) > 0 && zcl_read_u32_le(record + 12) <= 253 &&
        memcmp(record + 48, r->snapshot_digest, 32) == 0 &&
        memcmp(record + 80, r->endpoint_hash, 32) == 0;
    platform_directory_child_close(&file);
    return ok;
}

#endif

#ifdef ZCL_TESTING
bool wallet_history_provider_record_test(struct platform_directory_transaction *root,
    const struct wallet_history_provider_request *request, const struct file_manifest *manifest,
    bool publish)
{
    uint8_t record[PROVIDER_RECORD_SIZE];
    return publish ? provider_record_publish(root, request, manifest) :
        provider_record_read(root, request, record);
}
#endif

#if defined(__linux__)
static bool provider_size_add(struct platform_directory_transaction *dir, const char *leaf,
                              uint64_t limit, uint64_t *total)
{
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_child_init(&file);
    bool ok = platform_directory_child_open(dir, leaf, &file) &&
        platform_directory_child_info(&file, &info) && info.size > 0 &&
        info.size <= limit - *total;
    if (ok) *total += info.size;
    platform_directory_child_close(&file);
    return ok;
}

static bool provider_size_preflight(struct platform_directory_transaction *root,
                                    unsigned files, uint64_t limit)
{
    struct platform_directory_transaction blocks;
    platform_directory_transaction_init(&blocks);
    uint64_t total = 0;
    bool ok = platform_directory_transaction_open_child(root, "blocks", false, &blocks) ==
        PLATFORM_DIRECTORY_OK && provider_size_add(root, "block_index.bin", limit, &total);
    for (unsigned i = 0; ok && i < files; i++) {
        char name[24];
        int n = snprintf(name, sizeof(name), "blk%05u.dat", i);
        ok = n > 0 && (size_t)n < sizeof(name) && provider_size_add(&blocks, name, limit, &total);
    }
    platform_directory_transaction_close(&blocks);
    return ok;
}

#ifdef ZCL_TESTING
bool wallet_history_provider_size_preflight_for_test(
    struct platform_directory_transaction *root, unsigned files, uint64_t limit)
{
    return provider_size_preflight(root, files, limit);
}
#endif

#ifdef ZCL_TESTING
struct zcl_result wallet_history_export_test_validate_archive(const struct wallet_history_export_request *,
    const char *, const struct uint256 *);
#endif
static bool provider_archive_valid(const struct wallet_history_export_request *request,
                                   const char *path, const struct uint256 *test_genesis)
{
#ifdef ZCL_TESTING
    if (test_genesis) return wallet_history_export_test_validate_archive(request, path, test_genesis).ok;
#else
    (void)test_genesis;
#endif
    return wallet_history_export_validate_archive(request, path).ok;
}

#endif

static bool provider_recover(struct platform_directory_transaction *root,
    const struct wallet_history_provider_request *r, struct file_manifest *manifest,
    const struct uint256 *test_genesis)
{
#if defined(__linux__)
    uint8_t record[PROVIDER_RECORD_SIZE];
    char path[128];
    struct wallet_history_export_request request = provider_export_request(r);
    return provider_record_read(root, r, record) &&
        provider_size_preflight(root, zcl_read_u32_le(record + 12), r->max_bytes) &&
        platform_fd_path(path, sizeof(path), (int)root->native, NULL) &&
        !provider_request_cancelled(r) &&
        provider_archive_valid(&request, path, test_genesis) &&
        !provider_request_cancelled(r) &&
        wallet_history_manifest_build(manifest, path, zcl_read_u32_le(record + 12)).ok &&
        manifest->total_bytes <= r->max_bytes &&
        memcmp(manifest->root_hash, record + 16, 32) == 0 &&
        !provider_request_cancelled(r) && platform_directory_transaction_flush(root);
#else
    (void)root; (void)r; (void)manifest; (void)test_genesis;
    return false;
#endif
}

#ifdef ZCL_TESTING
bool wallet_history_provider_recover_for_test(struct platform_directory_transaction *root,
    const struct wallet_history_provider_request *request, struct file_manifest *manifest,
    const struct uint256 *genesis)
{
    return provider_recover(root, request, manifest, genesis);
}
#endif

static bool provider_materialize(const struct wallet_history_provider_request *r,
    struct consensus_state_artifact_evidence *evidence,
    struct platform_directory_transaction *parent, struct platform_directory_transaction *root,
    struct wallet_history_export_result *result)
{
    enum platform_directory_result found =
        platform_directory_transaction_open_child(parent, r->destination_leaf, false, root);
    bool ok = true;
    if (found == PLATFORM_DIRECTORY_MISSING) {
        struct wallet_history_export_request request = provider_export_request(r);
        ok = wallet_history_export_run(&request, result).ok &&
            result->outcome == WALLET_HISTORY_EXPORT_PUBLISHED &&
            platform_directory_transaction_open_child(parent, r->destination_leaf, false, root) ==
                PLATFORM_DIRECTORY_OK &&
            consensus_state_artifact_evidence_revalidate(evidence) && provider_endpoint(r) &&
            !provider_request_cancelled(r) && provider_record_publish(root, r, &result->manifest);
    } else if (found == PLATFORM_DIRECTORY_OK) {
        ok = provider_recover(root, r, &result->manifest, NULL);
    } else {
        ok = false;
    }
    return ok;
}

bool wallet_history_provider_prepare(const struct wallet_history_provider_request *r,
                                     struct fs_history_generation *out)
{
    if (!provider_request_valid(r) || !out || out->ready) return false;
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct platform_directory_transaction parent, root;
    platform_directory_transaction_init(&parent);
    platform_directory_transaction_init(&root);
    bool ok = provider_evidence(r, &evidence) && provider_endpoint(r) &&
        platform_directory_transaction_open(&parent, r->private_parent) &&
        wallet_history_export_parent_outside_source(r->source_datadir, &parent).ok;
    struct wallet_history_export_result result = {0};
    if (ok) ok = provider_materialize(r, evidence, &parent, &root, &result);
    if (ok)
        ok = consensus_state_artifact_evidence_revalidate(evidence) &&
             provider_endpoint(r) && !provider_request_cancelled(r);
    if (ok) {
        result.manifest.chain_height = r->endpoint_height;
        ok = fs_history_generation_take(out, &root, &result.manifest,
            r->snapshot_digest, r->endpoint_height, r->endpoint_hash);
    }
    platform_directory_transaction_close(&root);
    platform_directory_transaction_close(&parent);
    if (evidence && !consensus_state_artifact_evidence_close(&evidence)) {
        if (ok) fs_history_generation_close(out);
        ok = false;
    }
    return ok;
}

static bool provider_adopt(const struct wallet_history_provider_request *r,
    struct fs_history_generation *generation, uint16_t port, const char *bind_address)
{
    return !provider_request_cancelled(r) &&
        fs_server_start_with_history(generation, r->source_datadir, port, bind_address);
}

#ifdef ZCL_TESTING
bool wallet_history_provider_adopt_for_test(const struct wallet_history_provider_request *r,
    struct fs_history_generation *generation)
{
    return provider_adopt(r, generation, 0, NULL);
}
#endif

bool wallet_history_provider_prepare_and_start(
    const struct wallet_history_provider_request *r, uint16_t port,
    const char *bind_address)
{
    struct fs_history_generation generation;
    fs_history_generation_init(&generation);
    bool ok = wallet_history_provider_prepare(r, &generation);
    if (ok)
        ok = !provider_request_cancelled(r) &&
             wallet_history_provider_recheck(r) &&
             provider_adopt(r, &generation, port, bind_address);
    fs_history_generation_close(&generation);
    return ok;
}

struct provider_binding {
    struct wallet_history_provider_request request;
    char source[1024], parent[1024], stage[128], destination[128], snapshot[2048];
    struct platform_positioned_file_snapshot snapshot_id;
    bool ready;
};
static struct provider_binding g_provider_binding;
static pthread_mutex_t g_provider_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_provider_attempted;

static bool provider_cancelled(void *context)
{
    (void)context;
    return thread_registry_shutdown_requested();
}

static bool provider_candidate(const char *datadir, struct main_state *main,
                               const struct rom_artifact *art,
                               struct provider_binding *candidate)
{
    if (!art->used || art->kind != ROM_ARTIFACT_CONSENSUS_BUNDLE)
        return false;
    int n = snprintf(candidate->snapshot, sizeof(candidate->snapshot), "%s/%s",
                     datadir, art->filename);
    if (n <= 0 || (size_t)n >= sizeof(candidate->snapshot))
        return false;
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct zcl_result opened = consensus_state_artifact_evidence_open(
        candidate->snapshot, -1, &evidence);
    struct consensus_state_bundle_manifest manifest;
    uint8_t digest[32];
    bool ok = opened.ok && evidence &&
        consensus_state_artifact_evidence_manifest_copy(evidence, &manifest) &&
        consensus_state_artifact_evidence_file_digest(evidence, digest) &&
        manifest.history_complete && manifest.source_clean &&
        manifest.validation_profile == CONSENSUS_STATE_VALIDATION_FULL &&
        memcmp(digest, art->whole_sha3, 32) == 0;
    if (evidence && !consensus_state_artifact_evidence_close(&evidence))
        ok = false;
    if (!ok)
        return false;
    candidate->request.main = main;
    candidate->request.endpoint_height = manifest.height;
    memcpy(candidate->request.endpoint_hash, manifest.block_hash, 32);
    memcpy(candidate->request.snapshot_digest, digest, 32);
    return provider_endpoint(&candidate->request);
}

static void provider_binding_paths(struct provider_binding *b)
{
    b->request.source_datadir = b->source;
    b->request.private_parent = b->parent;
    b->request.staging_leaf = b->stage;
    b->request.destination_leaf = b->destination;
    b->request.snapshot_path = b->snapshot;
}

static bool provider_attest_identity(struct provider_binding *b)
{
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct platform_positioned_file_snapshot retained, current;
    bool ok = provider_evidence(&b->request, &evidence) &&
        provider_endpoint(&b->request) &&
        consensus_state_artifact_evidence_snapshot(evidence, &retained) &&
        boot_file_snapshot(b->snapshot, &current) &&
        platform_positioned_file_snapshot_equal(&retained, &current);
    if (evidence && !consensus_state_artifact_evidence_close(&evidence)) ok = false;
    if (ok) b->snapshot_id = retained;
    return ok;
}

static bool provider_select(struct main_state *main, const char *datadir,
                            struct provider_binding *selected)
{
    struct rom_artifact *artifacts = zcl_calloc(ROM_SEED_MAX_ARTIFACTS, sizeof(*artifacts), "history provider artifacts");
    struct provider_binding *trial = zcl_calloc(1, sizeof(*trial), "history provider trial");
    if (!artifacts || !trial) {
        free(artifacts); free(trial);
        return false;
    }
    int count = rom_seed_list(artifacts, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < count && !provider_cancelled(NULL); i++) {
        memset(trial, 0, sizeof(*trial));
        if (provider_candidate(datadir, main, &artifacts[i], trial) &&
            (!selected->ready || trial->request.endpoint_height > selected->request.endpoint_height ||
             (trial->request.endpoint_height == selected->request.endpoint_height &&
              memcmp(trial->request.snapshot_digest, selected->request.snapshot_digest, 32) < 0))) {
            *selected = *trial;
            selected->ready = true;
        }
    }
    bool ok = selected->ready && !provider_cancelled(NULL);
    free(artifacts); free(trial);
    return ok;
}

static void provider_configure(struct provider_binding *selected, const char *datadir,
                               const struct wallet_history_provider_budget *budget)
{
    snprintf(selected->source, sizeof(selected->source), "%s", datadir);
    snprintf(selected->parent, sizeof(selected->parent), "%s", budget->private_parent);
    char digest_hex[65];
    zcl_hex_encode(selected->request.snapshot_digest, 32, digest_hex);
    snprintf(selected->destination, sizeof(selected->destination), "history-%d-%s",
             selected->request.endpoint_height, digest_hex);
    snprintf(selected->stage, sizeof(selected->stage), ".history-%d-%s-stage",
             selected->request.endpoint_height, digest_hex);
    selected->request.max_rows = budget->max_rows;
    selected->request.max_bytes = budget->max_bytes;
    selected->request.min_free_bytes = budget->min_free_bytes;
    selected->request.cancelled = provider_cancelled;
    provider_binding_paths(selected);
}

static bool provider_take_attempt(bool *attempted)
{
    bool first = !*attempted;
    *attempted = true;
    return first;
}

#ifdef ZCL_TESTING
bool wallet_history_provider_attempt_for_test(bool *attempted)
{
    return attempted && provider_take_attempt(attempted);
}
#endif

bool wallet_history_provider_run_selected(struct main_state *main,
    const char *datadir, const struct wallet_history_provider_budget *budget,
    uint16_t port, const char *bind_address)
{
    if (!main || !datadir || !budget || !budget->private_parent ||
        strlen(datadir) >= sizeof(g_provider_binding.source) ||
        strlen(budget->private_parent) >= sizeof(g_provider_binding.parent))
        return false;
    pthread_mutex_lock(&g_provider_lock);
    bool first_attempt = provider_take_attempt(&g_provider_attempted);
    pthread_mutex_unlock(&g_provider_lock);
    if (!first_attempt)
        return false;
    struct provider_binding *selected = zcl_calloc(1, sizeof(*selected), "history provider selection");
    if (!selected)
        return false;
    bool ok = provider_select(main, datadir, selected);
    if (ok) {
        provider_configure(selected, datadir, budget);
        struct fs_history_generation generation;
        fs_history_generation_init(&generation);
        ok = wallet_history_provider_prepare(&selected->request, &generation) &&
             !provider_request_cancelled(&selected->request) &&
             provider_attest_identity(selected) &&
             provider_adopt(&selected->request, &generation, port, bind_address);
        fs_history_generation_close(&generation);
    }
    if (ok) {
        pthread_mutex_lock(&g_provider_lock);
        g_provider_binding = *selected;
        provider_binding_paths(&g_provider_binding);
        pthread_mutex_unlock(&g_provider_lock);
    }
    free(selected);
    return ok;
}

static bool provider_binding_matches(const struct provider_binding *binding,
    const uint8_t digest[32], int32_t height, const uint8_t hash[32])
{
    return binding->ready && binding->request.endpoint_height == height &&
        memcmp(binding->request.snapshot_digest, digest, 32) == 0 &&
        memcmp(binding->request.endpoint_hash, hash, 32) == 0;
}

#ifdef ZCL_TESTING
bool wallet_history_provider_binding_matches_for_test(const uint8_t expected_digest[32],
    int32_t expected_height, const uint8_t expected_hash[32],
    const uint8_t digest[32], int32_t height, const uint8_t hash[32])
{
    struct provider_binding binding = {.ready = true};
    binding.request.endpoint_height = expected_height;
    memcpy(binding.request.snapshot_digest, expected_digest, 32);
    memcpy(binding.request.endpoint_hash, expected_hash, 32);
    return provider_binding_matches(&binding, digest, height, hash);
}
#endif

bool wallet_history_provider_offer_allowed(const uint8_t digest[32],
                                           int32_t height, const uint8_t hash[32])
{
    struct wallet_history_provider_budget budget;
    enum wallet_history_provider_config_result config = wallet_history_provider_read_budget(&budget);
    if (config == WALLET_HISTORY_PROVIDER_DISABLED)
        return true;
    if (config != WALLET_HISTORY_PROVIDER_CONFIGURED || !digest || !hash)
        return false;
    pthread_mutex_lock(&g_provider_lock);
    struct provider_binding copy = g_provider_binding;
    pthread_mutex_unlock(&g_provider_lock);
    if (!provider_binding_matches(&copy, digest, height, hash))
        return false;
    provider_binding_paths(&copy);
    struct platform_positioned_file_snapshot current;
    return fs_server_history_matches(digest, height, hash) &&
           boot_file_snapshot(copy.snapshot, &current) &&
           platform_positioned_file_snapshot_equal(&copy.snapshot_id, &current) &&
           provider_endpoint(&copy.request) &&
           fs_server_history_matches(digest, height, hash);
}

static bool provider_wait_scan(const char *datadir, int64_t *checkpoint,
                               void (*beat)(int64_t *))
{
    while (!thread_registry_shutdown_requested()) {
        struct rom_seed_scan_status status;
        bool matching = rom_seed_scan_status(datadir, &status);
        if (matching && status.state == ROM_SEED_SCAN_ENDED)
            return true;
        if ((matching && (status.state == ROM_SEED_SCAN_CANCELLED ||
                          status.state == ROM_SEED_SCAN_START_FAILED)) ||
            ((!matching || status.state == ROM_SEED_SCAN_NOT_STARTED) &&
             boot_frontend_async_done()))
            return false;
        beat(checkpoint);
        platform_sleep_ms(100);
    }
    return false;
}

void wallet_history_provider_boot(struct boot_svc_ctx *svc, int64_t *checkpoint,
                                  void (*beat)(int64_t *))
{
    struct wallet_history_provider_budget budget;
    enum wallet_history_provider_config_result config =
        wallet_history_provider_read_budget(&budget);
    if (config == WALLET_HISTORY_PROVIDER_DISABLED)
        return;
    bool ready = config == WALLET_HISTORY_PROVIDER_CONFIGURED && svc && svc->app_ctx &&
        checkpoint && beat && boot_profile_has_file_service(svc->app_ctx) &&
        !svc->defer_offer_service && GetBoolArg("-romseed", true) &&
        provider_wait_scan(svc->datadir, checkpoint, beat) &&
        wallet_history_provider_run_selected(svc->state, svc->datadir, &budget,
            (uint16_t)svc->app_ctx->fs_port, svc->app_ctx->p2p_bind_address);
    if (!ready) {
        fs_server_onion_decide(FS_ONION_FAILED);
        fprintf(stderr, "History provider unavailable: configuration, scan, admission or export failed\n");
    }
}
