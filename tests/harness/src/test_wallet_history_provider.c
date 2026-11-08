/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "config/wallet_history_provider.h"
#include "services/wallet_history_export.h"
#include "net/file_service.h"
#include "platform/directory_transaction.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "chain/chainparams.h"
#include "test/test_block_map.h"
#include "services/chain_state_service.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "coins/coins_view.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include <sqlite3.h>
#include "test/test_core.h"
#include <stdio.h>
#include <string.h>
#if defined(__linux__)
#include <sys/stat.h>
#include <unistd.h>
#endif

int test_wallet_history_provider(void);
bool wallet_history_provider_endpoint_for_test(struct main_state *, int32_t, const uint8_t[32]);
#if defined(__linux__)
bool wallet_history_export_fixture_for_provider(const char *, const char *, struct uint256 *,
    uint8_t[32], struct file_manifest *);
bool wallet_history_provider_recover_for_test(struct platform_directory_transaction *,
    const struct wallet_history_provider_request *, struct file_manifest *, const struct uint256 *);
#endif
bool wallet_history_provider_binding_matches_for_test(const uint8_t[32], int32_t,
    const uint8_t[32], const uint8_t[32], int32_t, const uint8_t[32]);
bool wallet_history_provider_size_preflight_for_test(
    struct platform_directory_transaction *, unsigned, uint64_t);
bool wallet_history_provider_attempt_for_test(bool *);
bool wallet_history_provider_adopt_for_test(const struct wallet_history_provider_request *,
    struct fs_history_generation *);
bool wallet_history_provider_record_test(struct platform_directory_transaction *,
    const struct wallet_history_provider_request *, const struct file_manifest *, bool);

static bool provider_descendant_refused(void)
{
#if defined(__linux__)
    char source[512], child[600], stage[700];
    if (!test_mkdtemp(source, sizeof(source), "zcl_provider_source"))
        return false;
    int a = snprintf(child, sizeof(child), "%s/nested", source);
    int b = snprintf(stage, sizeof(stage), "%s/stage", child);
    bool ok = a > 0 && (size_t)a < sizeof(child) && b > 0 &&
              (size_t)b < sizeof(stage) && mkdir(child, 0700) == 0;
    struct wallet_history_export_request request = {
        .source_datadir = source, .private_parent = child,
        .staging_leaf = "stage", .destination_leaf = "dest",
        .endpoint_height = 1, .max_rows = 1, .max_bytes = 1,
        .min_free_bytes = 1,
    };
    request.endpoint_hash[0] = 1;
    struct wallet_history_export_result result;
    if (ok) {
        struct zcl_result exported = wallet_history_export_run(&request, &result);
        bool present = access(stage, F_OK) == 0;
        ok = !exported.ok && result.outcome == WALLET_HISTORY_EXPORT_FAILED && !present;
        printf("provider descendant: rc=%d outcome=%d stage_present=%d message=%s\n",
               exported.ok, result.outcome, present, exported.message);
    }
    return test_rm_rf_recursive(source) == 0 && ok;
#else
    return true;
#endif
}

#if defined(__linux__)
static bool provider_test_cancelled(void *context)
{
    return *(const bool *)context;
}
#endif

struct provider_endpoint_fixture {
    char dir[512];
    struct main_state main;
    struct coins_view backing;
    struct coins_view_cache coins;
    struct uint256 hashes[3];
    struct block_index blocks[3];
};

static bool provider_seed_row(sqlite3 *db, const char *sql, int height, const uint8_t hash[32])
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) return false;
    sqlite3_bind_int(statement, 1, height);
    sqlite3_bind_blob(statement, 2, hash, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(statement) == SQLITE_DONE; // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(statement);
    return ok;
}

static bool provider_seed_endpoint(sqlite3 *db, const struct provider_endpoint_fixture *f)
{
    const char *schema =
        "CREATE TABLE IF NOT EXISTS tip_finalize_log(height INTEGER PRIMARY KEY,status TEXT NOT NULL,"
        "ok INTEGER NOT NULL,work_delta_high INTEGER NOT NULL,work_delta_low INTEGER NOT NULL,"
        "utxo_size_after INTEGER NOT NULL,reorg_depth INTEGER NOT NULL,finalized_at INTEGER NOT NULL,tip_hash BLOB);"
        "CREATE TABLE IF NOT EXISTS validate_headers_log(height INTEGER PRIMARY KEY,hash BLOB NOT NULL,"
        "ok INTEGER NOT NULL,fail_reason TEXT,validated_at INTEGER NOT NULL);";
    return sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK && // raw-sql-ok:test-fixture-seeding
        provider_seed_row(db, "INSERT INTO tip_finalize_log VALUES(?1,'anchor',1,0,0,0,0,0,?2)",
                          1, f->hashes[1].data) &&
        provider_seed_row(db, "INSERT INTO validate_headers_log(height,hash,ok,validated_at) VALUES(?1,?2,1,0)",
                          1, f->hashes[1].data) &&
        provider_seed_row(db, "INSERT INTO validate_headers_log(height,hash,ok,validated_at) VALUES(?1,?2,1,0)",
                          2, f->hashes[2].data);
}

static bool provider_endpoint_chain(struct provider_endpoint_fixture *f)
{
    for (int i = 0; i < 3; i++) {
        memset(f->hashes[i].data, i + 1, 32);
        block_index_init(&f->blocks[i]);
        f->blocks[i].phashBlock = &f->hashes[i];
        f->blocks[i].nHeight = i;
        f->blocks[i].pprev = i ? &f->blocks[i - 1] : NULL;
        f->blocks[i].nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        arith_uint256_set_u64(&f->blocks[i].nChainWork, (uint64_t)i + 1);
        test_block_map_insert(&f->main.map_block_index, &f->hashes[i], &f->blocks[i]);
        const struct block_index *canonical = block_map_find(&f->main.map_block_index, &f->hashes[i]);
        if (!canonical) return false;
        f->blocks[i].phashBlock = canonical->phashBlock;
    }
    f->main.pindex_best_header = &f->blocks[2];
    return active_chain_move_window_tip(&f->main.chain_active, &f->blocks[2]);
}

static bool provider_endpoint_cases(void)
{
    struct provider_endpoint_fixture f = {0};
    csr_test_reset_singleton();
    reducer_frontier_provable_tip_reset();
    reducer_frontier_test_reset_high_water();
    tip_finalize_stage_test_reset();
    main_state_init(&f.main);
    if (!test_mkdtemp(f.dir, sizeof(f.dir), "provider_endpoint")) {
        main_state_free(&f.main); return false;
    }
    bool opened = progress_store_open(f.dir);
    bool ok = opened && provider_endpoint_chain(&f) && provider_seed_endpoint(progress_store_db(), &f);
    coins_view_cache_init(&f.coins, &f.backing);
    csr_init(csr_instance(), &f.main.map_block_index, &f.main.chain_active,
             &f.main.pindex_best_header, &f.coins, NULL, NULL);
    reducer_frontier_provable_tip_set(1);
    if (ok) {
        uint8_t wrong[32]; memcpy(wrong, f.hashes[1].data, 32); wrong[0] ^= 1;
        ok = wallet_history_provider_endpoint_for_test(&f.main, 1, f.hashes[1].data) &&
            !wallet_history_provider_endpoint_for_test(&f.main, 1, wrong) &&
            !wallet_history_provider_endpoint_for_test(&f.main, 2, f.hashes[2].data);
    }
    csr_free(csr_instance()); coins_view_cache_free(&f.coins); main_state_free(&f.main);
    if (opened) progress_store_close();
    reducer_frontier_provable_tip_reset(); reducer_frontier_test_reset_high_water();
    tip_finalize_stage_test_reset(); csr_test_reset_singleton();
    return test_rm_rf_recursive(f.dir) == 0 && ok;
}

static bool provider_binding_cases(void)
{
    uint8_t digest[32] = {1}, hash[32] = {2}, wrong[32] = {3};
    return wallet_history_provider_binding_matches_for_test(digest, 100, hash, digest, 100, hash) &&
        !wallet_history_provider_binding_matches_for_test(digest, 100, hash, wrong, 100, hash) &&
        !wallet_history_provider_binding_matches_for_test(digest, 100, hash, digest, 101, hash) &&
        !wallet_history_provider_binding_matches_for_test(digest, 100, hash, digest, 100, wrong);
}

static bool provider_size_cases(struct platform_directory_transaction *root)
{
#if defined(__linux__)
    struct platform_directory_transaction blocks;
    struct platform_directory_child index, block;
    platform_directory_transaction_init(&blocks);
    platform_directory_child_init(&index); platform_directory_child_init(&block);
    const uint8_t bytes[2] = {1, 2};
    bool ok = platform_directory_transaction_open_child(root, "blocks", true, &blocks) ==
        PLATFORM_DIRECTORY_OK && platform_directory_child_create(root, "block_index.bin", &index) &&
        platform_directory_child_write_exact(&index, bytes, sizeof(bytes), 0) &&
        platform_directory_child_create(&blocks, "blk00000.dat", &block) &&
        platform_directory_child_write_exact(&block, bytes, sizeof(bytes), 0);
    platform_directory_child_close(&index); platform_directory_child_close(&block);
    platform_directory_transaction_close(&blocks);
    return ok && wallet_history_provider_size_preflight_for_test(root, 1, 4) &&
        !wallet_history_provider_size_preflight_for_test(root, 1, 3);
#else
    (void)root;
    return true;
#endif
}

static bool provider_record_corruption(struct platform_directory_transaction *root,
    struct wallet_history_provider_request *request, const struct file_manifest *manifest)
{
    request->snapshot_digest[0] ^= 1;
    bool wrong_digest = !wallet_history_provider_record_test(root, request, manifest, false);
    request->snapshot_digest[0] ^= 1;
    struct platform_directory_child file;
    platform_directory_child_init(&file);
    uint8_t extra = 0;
    bool appended = platform_directory_child_open(root, "history-completion.v1", &file) &&
        platform_directory_child_write_exact(&file, &extra, 1, 112);
    platform_directory_child_close(&file);
    bool extra_refused = !wallet_history_provider_record_test(root, request, manifest, false);
    platform_directory_child_init(&file);
    bool truncated = platform_directory_child_open(root, "history-completion.v1", &file) &&
        platform_directory_child_truncate(&file, 7);
    platform_directory_child_close(&file);
    bool short_refused = !wallet_history_provider_record_test(root, request, manifest, false) &&
        !wallet_history_provider_record_test(root, request, manifest, true);
    return wrong_digest && appended && extra_refused && truncated && short_refused;
}

static bool provider_record_cases(void)
{
    char path[512];
    if (!test_mkdtemp(path, sizeof(path), "zcl_provider_record")) return false;
    struct platform_directory_transaction root;
    platform_directory_transaction_init(&root);
    struct wallet_history_provider_request request = {.endpoint_height = 17};
    struct file_manifest manifest = {.num_chunks = 1};
    manifest.chunks[0].file_index = 0;
    request.endpoint_hash[0] = 1; request.snapshot_digest[0] = 2;
    bool opened = platform_directory_transaction_open(&root, path);
    bool sized = opened && provider_size_cases(&root);
    bool missing = sized && !wallet_history_provider_record_test(&root, &request, &manifest, false);
    bool published = missing && wallet_history_provider_record_test(&root, &request, &manifest, true);
    bool recovered = published && wallet_history_provider_record_test(&root, &request, &manifest, false);
    printf("provider record: opened=%d sized=%d missing=%d published=%d recovered=%d\n",
           opened, sized, missing, published, recovered);
    bool ok = opened && sized && missing && published && recovered &&
        provider_record_corruption(&root, &request, &manifest);
    platform_directory_transaction_close(&root);
    return test_rm_rf_recursive(path) == 0 && ok;
}

#if defined(__linux__)
static bool provider_corrupt_block(struct platform_directory_transaction *root)
{
    struct platform_directory_transaction blocks;
    struct platform_directory_child block;
    platform_directory_transaction_init(&blocks); platform_directory_child_init(&block);
    uint8_t bad = 255;
    bool ok = platform_directory_transaction_open_child(root, "blocks", false, &blocks) ==
        PLATFORM_DIRECTORY_OK && platform_directory_child_open(&blocks, "blk00000.dat", &block) &&
        platform_directory_child_write_exact(&block, &bad, 1, 8);
    platform_directory_child_close(&block); platform_directory_transaction_close(&blocks);
    return ok;
}
#endif

#if defined(__linux__)
static bool provider_cancel_with_generation(struct platform_directory_transaction *root,
    struct wallet_history_provider_request *request, struct file_manifest *manifest)
{
    struct fs_history_generation generation;
    fs_history_generation_init(&generation);
    manifest->chain_height = request->endpoint_height;
    if (!fs_history_generation_take(&generation, root, manifest, request->snapshot_digest,
                                    request->endpoint_height, request->endpoint_hash)) return false;
    bool cancelled = true;
    request->cancelled = provider_test_cancelled; request->cancel_context = &cancelled;
    bool cancel_refused = !wallet_history_provider_adopt_for_test(request, &generation) && generation.ready;
    if (!cancel_refused) fs_server_stop();
    cancelled = false;
    bool accepted = cancel_refused && wallet_history_provider_adopt_for_test(request, &generation);
    printf("provider adopt: cancel_refused=%d accepted=%d ready=%d\n",
           cancel_refused, accepted, generation.ready);
    if (accepted) fs_server_stop();
    fs_history_generation_close(&generation);
    request->cancelled = NULL; request->cancel_context = NULL;
    return cancel_refused && accepted;
}
#endif

#if defined(__linux__)
static bool provider_restart_validate(struct platform_directory_transaction *root,
    struct wallet_history_provider_request *request, const struct uint256 *genesis,
    const struct file_manifest *original)
{
    struct file_manifest recovered;
    bool missing = !wallet_history_provider_recover_for_test(root, request, &recovered, genesis);
    bool published = missing && wallet_history_provider_record_test(root, request, original, true);
    bool reopened = published && wallet_history_provider_recover_for_test(root, request, &recovered, genesis);
    bool matches = reopened && original->total_bytes == recovered.total_bytes &&
        memcmp(original->root_hash, recovered.root_hash, 32) == 0;
    bool adopted = matches && provider_cancel_with_generation(root, request, &recovered);
    printf("provider restart: missing=%d published=%d reopened=%d matches=%d adopted=%d\n",
           missing, published, reopened, matches, adopted);
    return missing && published && reopened && matches && adopted;
}
#endif

static bool provider_restart_cases(void)
{
#if defined(__linux__)
    char source[512], parent[512];
    if (!test_mkdtemp(source, sizeof(source), "provider_restart_source")) return false;
    if (!test_mkdtemp(parent, sizeof(parent), "provider_restart_parent")) {
        test_rm_rf_recursive(source); return false;
    }
    struct uint256 genesis;
    struct file_manifest original, recovered;
    struct wallet_history_provider_request request = {
        .source_datadir = source, .endpoint_height = 1, .max_rows = 3,
        .max_bytes = 1048576, .min_free_bytes = 1,
    };
    struct platform_directory_transaction base, root;
    platform_directory_transaction_init(&base); platform_directory_transaction_init(&root);
    bool exported = wallet_history_export_fixture_for_provider(source, parent, &genesis,
                  request.endpoint_hash, &original);
    bool base_open = exported && platform_directory_transaction_open(&base, parent);
    bool root_open = base_open && platform_directory_transaction_open_child(&base, "ready", false, &root) ==
        PLATFORM_DIRECTORY_OK;
    bool validated = root_open && provider_restart_validate(&root, &request, &genesis, &original);
    bool reopened = validated && platform_directory_transaction_open_child(&base, "ready", false, &root) ==
        PLATFORM_DIRECTORY_OK;
    printf("provider restart setup: exported=%d base=%d root=%d validated=%d reopened=%d\n",
           exported, base_open, root_open, validated, reopened);
    bool ok = exported && base_open && root_open && validated && reopened;
    ok = ok && provider_corrupt_block(&root);
    ok = ok && !wallet_history_provider_recover_for_test(&root, &request, &recovered, &genesis);
    platform_directory_transaction_close(&root); platform_directory_transaction_close(&base);
    bool removed_source = test_rm_rf_recursive(source) == 0;
    bool removed_parent = test_rm_rf_recursive(parent) == 0;
    return ok && removed_source && removed_parent;
#else
    return true;
#endif
}

static bool provider_budget_cases(void)
{
    struct wallet_history_provider_budget budget;
    bool disabled = wallet_history_provider_parse_budget(NULL, NULL, NULL, NULL, &budget) ==
                    WALLET_HISTORY_PROVIDER_DISABLED;
    bool missing = wallet_history_provider_parse_budget("/var/private", "100", NULL, "20", &budget) ==
                   WALLET_HISTORY_PROVIDER_INVALID;
    bool relative = wallet_history_provider_parse_budget("relative", "100", "200", "20", &budget) ==
                    WALLET_HISTORY_PROVIDER_INVALID;
    bool overflow = wallet_history_provider_parse_budget("/var/private", "18446744073709551616", "200", "20", &budget) ==
                    WALLET_HISTORY_PROVIDER_INVALID;
    bool zero = wallet_history_provider_parse_budget("/var/private", "100", "0", "20", &budget) ==
                WALLET_HISTORY_PROVIDER_INVALID;
    bool valid = wallet_history_provider_parse_budget("/var/private", "100", "200", "20", &budget) ==
                 WALLET_HISTORY_PROVIDER_CONFIGURED && budget.max_rows == 100 &&
                 budget.max_bytes == 200 && budget.min_free_bytes == 20;
    return disabled && missing && relative && overflow && zero && valid;
}

static bool provider_generation_cases(void)
{
    bool attempted = false;
    bool once = wallet_history_provider_attempt_for_test(&attempted) &&
                !wallet_history_provider_attempt_for_test(&attempted);
    struct fs_history_generation generation;
    fs_history_generation_init(&generation);
    bool refused = !wallet_history_provider_prepare(NULL, &generation) &&
                   !wallet_history_provider_recheck(NULL) && !generation.ready;
    fs_history_generation_close(&generation);
    bool frontier = !wallet_history_provider_served_covers_for_test(100, 101) &&
                    wallet_history_provider_served_covers_for_test(100, 100);
    return once && refused && frontier;
}

static bool provider_fixture_cases(void)
{
    return provider_budget_cases() && provider_descendant_refused() && provider_record_cases() &&
        provider_binding_cases() && provider_restart_cases() && provider_endpoint_cases();
}

int test_wallet_history_provider(void)
{
    const char *network = chain_params_get()->strNetworkID;
    enum chain_network previous = !strcmp(network, "regtest") ? CHAIN_REGTEST :
        !strcmp(network, "test") ? CHAIN_TESTNET : CHAIN_MAIN;
    chain_params_select(CHAIN_REGTEST);
    bool generation = provider_generation_cases();
    bool fixtures = provider_fixture_cases();
    printf("provider cases: generation=%d fixtures=%d\n", generation, fixtures);
    bool ok = generation && fixtures;
    printf("wallet_history_provider: %s\n", ok ? "OK" : "FAIL");
    chain_params_select(previous);
    return ok ? 0 : 1;
}
