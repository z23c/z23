/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Real retained-history, two-header terminal adoption fixture. */
#ifndef ZCL_CONSENSUS_STATE_COLD_ADOPTION_TEST_H
#define ZCL_CONSENSUS_STATE_COLD_ADOPTION_TEST_H
#if defined(__linux__)
#include "config/boot_wallet_cold_prefix.h"
#include "config/boot_wallet_pending_restore.h"
#include "jobs/block_header_emit.h"
#include "services/block_row_verify.h"
#include "storage/anchor_kv.h"
#include "storage/block_index_projection.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"
#include "validation/check_block.h"
#include "chain/pow.h"
#include "platform/time_compat.h"
#include <sys/resource.h>
void reducer_frontier_test_set_compiled_anchor(int32_t height);

struct csi_cold_stop { struct main_state *ms; size_t before, calls; bool now, after_insert; };
struct csi_cold_fixture {
    char dir[PATH_MAX]; int fd;
    struct wallet_history_capability cap;
    struct consensus_state_artifact_evidence *artifact;
    struct bound_history_preflight *preflight;
    event_log_t *log; block_index_projection_t *projection;
    struct block_header headers[2]; struct block_index rows[2];
    struct uint256 hash[2];
};
static bool csi_cold_stop(void *opaque)
{
    struct csi_cold_stop *stop = opaque; ++stop->calls;
    return stop->now || (stop->after_insert && stop->ms &&
        block_map_count(&stop->ms->map_block_index) > stop->before);
}
static bool csi_cold_capability(const struct csi_real_paths *p, struct csi_cold_fixture *f)
{
    struct wallet_history_names names;
    struct platform_directory_transaction parent, root;
    struct platform_directory_lock lease;
    platform_directory_transaction_init(&parent); platform_directory_transaction_init(&root);
    platform_directory_lock_init(&lease); wallet_history_capability_init(&f->cap);
    bool ok = wallet_history_capability_names(csi_real_bound_observation.snapshot_sha3,
            csi_real_bound_observation.history_manifest_root, &names).ok &&
        platform_directory_transaction_open(&parent, p->data) &&
        platform_directory_lock_acquire(&parent, names.lock, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&parent, names.root, false, &root) == PLATFORM_DIRECTORY_OK &&
        wallet_history_capability_acquire(&f->cap, &parent, &root, &lease, names.root, names.lock, 52,
            csi_real_bound_observation.history_manifest_root).ok;
    platform_directory_transaction_close(&root); platform_directory_lock_release(&lease);
    platform_directory_transaction_close(&parent); return ok;
}
static bool csi_cold_preflight(const struct csi_real_paths *p, struct csi_cold_fixture *f)
{
    int64_t start = platform_time_monotonic_ms();
    if (!csi_cold_capability(p, f)) return false;
    int64_t cap_done = platform_time_monotonic_ms();
    if (!consensus_state_artifact_evidence_open(p->bundle, -1, &f->artifact).ok) return false;
    int64_t artifact_done = platform_time_monotonic_ms();
    struct block_index_flat_cursor *cursor = NULL; uint8_t root[32];
    struct zcl_result opened = block_index_flat_cursor_open(wallet_history_capability_path(&f->cap), &cursor);
    bool ok = opened.ok && block_index_flat_cursor_read(cursor, 2, f->hash[1].data, root).ok;
    if (cursor) block_index_flat_cursor_close(cursor);
    int64_t flat_done = platform_time_monotonic_ms();
    if (!ok || !bound_history_preflight_open(&f->preflight, &csi_real_bound_observation,
            f->artifact, &f->cap, 2, f->hash[1].data).ok) return false;
    int64_t archive_done = platform_time_monotonic_ms();
    fprintf(stderr, "COLD_PREFLIGHT capability_ms=%lld artifact_ms=%lld flat_ms=%lld archive_ms=%lld\n",
        (long long)(cap_done-start), (long long)(artifact_done-cap_done),
        (long long)(flat_done-artifact_done), (long long)(archive_done-flat_done));
    if (!bound_history_preflight_read_header(f->preflight, 2, f->hash[1].data, &f->headers[1]).ok) return false;
    f->hash[0] = f->headers[1].hashPrevBlock;
    return bound_history_preflight_read_header(f->preflight, 1, f->hash[0].data, &f->headers[0]).ok;
}
static bool csi_cold_validate_headers(struct csi_cold_fixture *f, struct block_index *genesis)
{
    const struct chain_params *params = chain_params_get(); struct block_index *parent = genesis;
    for (int i = 0; i < 2; ++i) {
        struct block_header *h = &f->headers[i]; struct validation_state state; validation_state_init(&state);
        if (!uint256_eq(&h->hashPrevBlock, parent->phashBlock) ||
            block_row_verify(f->hash[i].data, h->nBits, h, params, true) != BLOCK_ROW_VERIFY_OK ||
            !contextual_check_block_header(h, &state, params, parent, true)) return false;
        struct block_index *row = &f->rows[i]; block_index_init(row);
        row->hashBlock = f->hash[i]; row->phashBlock = &row->hashBlock; row->pprev = parent;
        row->nHeight = i + 1; row->nStatus = BLOCK_VALID_TREE; row->nVersion = h->nVersion;
        row->nTime = h->nTime; row->nBits = h->nBits; row->hashFinalSaplingRoot = h->hashFinalSaplingRoot;
        struct arith_uint256 proof = GetBlockProof(row); arith_uint256_add(&row->nChainWork, &parent->nChainWork, &proof);
        parent = row;
    }
    return true;
}
static bool csi_cold_seed_cursors(sqlite3 *db)
{
    return hs_set_cursor(db, "validate_headers", 3) && hs_set_cursor(db, "script_validate", 2) &&
        hs_set_cursor(db, "body_persist", 2) && hs_set_cursor(db, "proof_validate", 2) &&
        hs_set_cursor(db, "utxo_apply", 3) && hs_set_cursor(db, "tip_finalize", 1);
}
static bool csi_cold_seed_rows(sqlite3 *db, const struct csi_cold_fixture *f)
{
    return hs_ins(db, "INSERT INTO validate_headers_log(height,hash,ok,validated_at) VALUES(?1,?2,1,0)", 1, f->hash[0].data) &&
        hs_ins(db, "INSERT INTO validate_headers_log(height,hash,ok,validated_at) VALUES(?1,?2,1,0)", 2, f->hash[1].data) &&
        hs_ins(db, "INSERT INTO utxo_apply_log(height,status,ok,spent_count,added_count,total_value_delta,applied_at) VALUES(?1,'verified',1,0,0,0,0)", 2, NULL) &&
        hs_ins(db, "INSERT INTO utxo_apply_delta(height,branch_hash,spent_blob,added_blob) VALUES(?1,?2,x'',x'')", 2, f->hash[1].data) &&
        hs_put_anchor_hash(db, 1, f->hash[0].data);
}
static bool csi_cold_seed_progress(sqlite3 *db, struct block_index *genesis, const struct csi_cold_fixture *f)
{
    if (!hs_ensure_forward_schema(db) || !coins_kv_ensure_schema(db) || !anchor_kv_ensure_schema(db) ||
        !anchor_kv_initialize_history(db, 0)) return false;
    reducer_frontier_test_set_compiled_anchor(0); reducer_frontier_provable_tip_reset(); tip_finalize_stage_test_reset();
    tip_finalize_stage_warm_authority_caches(db, genesis, "cold-adoption-fixture");
    struct incremental_merkle_tree empty; sapling_tree_init(&empty);
    if (!anchor_kv_add_tree(db, ANCHOR_POOL_SAPLING, &empty, 0)) return false;
    const uint8_t one = 1, txid[32] = {1}, generation[8] = {0}; uint8_t applied[8] = {3};
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) return false;
    bool ok = coins_kv_add(db, txid, 0, 1, 1, false, NULL, 0) &&
        progress_meta_set_in_tx(db, COINS_APPLIED_HEIGHT_KEY, applied, sizeof(applied)) &&
        progress_meta_set_in_tx(db, COINS_KV_MIGRATION_COMPLETE_KEY, &one, 1) &&
        progress_meta_set_in_tx(db, COINS_KV_AUTHORITY_GENERATION_KEY, generation, sizeof(generation)) &&
        csi_cold_seed_cursors(db) && csi_cold_seed_rows(db, f);
    if (sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) return false;
    return ok;
}
struct csi_cold_state {
    struct main_state ms;
    struct coins_view backing;
    struct coins_view_cache cache;
    struct chain_state_repository csr;
    struct block_index *genesis, *far;
};
static bool csi_cold_state_init(struct csi_cold_state *s, bool far)
{
    memset(s, 0, sizeof(*s)); main_state_init(&s->ms);
    const struct chain_params *cp = chain_params_get();
    s->genesis = chainstate_insert_block_index((struct chainstate *)&s->ms, &cp->consensus.hashGenesisBlock);
    if (!s->genesis || !block_index_initialize_genesis(s->genesis, cp)) return false;
    if (!active_chain_move_window_tip(&s->ms.chain_active, s->genesis)) return false;
    coins_view_cache_init(&s->cache, &s->backing);
    coins_view_cache_set_best_block(&s->cache, &cp->consensus.hashGenesisBlock);
    csr_init(&s->csr, &s->ms.map_block_index, &s->ms.chain_active, &s->ms.pindex_best_header, &s->cache, NULL, NULL);
    if (far) {
        struct uint256 hash = {0}; hash.data[0] = 0x77; hash.data[31] = 0x55;
        s->far = chainstate_insert_block_index((struct chainstate *)&s->ms, &hash);
        if (!s->far) return false;
        s->far->nHeight = 3000000; s->far->nStatus = BLOCK_VALID_TREE;
        s->ms.pindex_best_header = s->far;
    } else s->ms.pindex_best_header = s->genesis;
    return true;
}
static bool csi_cold_unchanged(struct csi_cold_state *s, size_t count, struct block_index *header)
{
    struct active_chain_window_snapshot window; struct uint256 best;
    coins_view_cache_get_best_block(&s->cache, &best);
    return block_map_count(&s->ms.map_block_index) == count && s->ms.pindex_best_header == header &&
        active_chain_capture_window(&s->ms.chain_active, -1, &window) && window.tip == s->genesis &&
        uint256_eq(&best, s->genesis->phashBlock) && !s->ms.sapling_tree_loaded;
}
static bool csi_cold_emit(struct csi_cold_fixture *f, int i)
{
    return block_index_emit_header_event(&f->rows[i], "cold-linked-test", NULL, NULL) &&
        event_log_flush(f->log) && block_index_projection_catch_up(f->projection) != UINT64_MAX;
}
struct csi_cold_pixel_stop { size_t calls, limit; };
static bool csi_cold_pixel_stop(void *opaque)
{
    struct csi_cold_pixel_stop *s = opaque; return ++s->calls >= s->limit;
}
/* Optional measurement uses an already-private copy of public-chain stores.
 * It stages only; the preflight is bound to the separate height-2 test. */
static bool csi_cold_pixel_stages(struct csi_cold_fixture *f, struct main_state *ms,
    int fd, int64_t start, int64_t ready)
{
    bool ok = false;
    boot_wallet_cold_prefix_t *stage = NULL; struct csi_cold_pixel_stop stop = {0, SIZE_MAX};
    int64_t begin = platform_time_monotonic_ms();
    enum boot_wallet_cold_result result = boot_wallet_cold_prefix_stage_with_history(ms, fd, 100000,
        f->preflight, csi_cold_pixel_stop, &stop, &stage);
    int64_t end = platform_time_monotonic_ms();
    const struct block_index *tip = stage ? boot_wallet_cold_prefix_tip(stage) : NULL;
    struct rusage usage; long rss = getrusage(RUSAGE_SELF, &usage) == 0 ? usage.ru_maxrss : -1;
    fprintf(stderr, "COLD_PIXEL setup_ms=%lld stage_ms=%lld result=%d height=%d callbacks=%zu map=%zu peak_kib=%ld\n",
        (long long)(ready-start), (long long)(end-begin), (int)result, tip ? tip->nHeight : -1,
        stop.calls, block_map_count(&ms->map_block_index), rss);
    ok = result == BOOT_WALLET_COLD_READY && tip && tip->nHeight == 64854 && block_map_count(&ms->map_block_index) == 1;
    if (stage && !boot_wallet_cold_prefix_release(stage)) ok = false;
    stage = NULL; stop.calls = 0; stop.limit = 2000; begin = platform_time_monotonic_ms();
    result = boot_wallet_cold_prefix_stage_with_history(ms, fd, 100000, f->preflight,
        csi_cold_pixel_stop, &stop, &stage);
    end = platform_time_monotonic_ms();
    fprintf(stderr, "COLD_PIXEL_STOP elapsed_ms=%lld result=%d callbacks=%zu map=%zu\n",
        (long long)(end-begin), (int)result, stop.calls, block_map_count(&ms->map_block_index));
    ok = ok && result == BOOT_WALLET_COLD_STOPPED && !stage && block_map_count(&ms->map_block_index) == 1;
    if (stage) (void)boot_wallet_cold_prefix_release(stage);
    return ok;
}
static bool csi_cold_pixel_measure(struct csi_cold_fixture *f, const char *path)
{
    if (!path || !path[0]) {
        const char *required = getenv("ZCL_TEST_COLD_PUBLIC_REQUIRED");
        if (required && !strcmp(required, "1")) {
            fprintf(stderr, "COLD_PIXEL required input unavailable\n");
            return false;
        }
        return true;
    }
    int64_t start = platform_time_monotonic_ms();
    struct main_state *ms = zcl_calloc(1, sizeof(*ms), "public cold measurement state");
    if (!ms) return false;
    main_state_init(ms); const struct chain_params *cp = chain_params_get();
    struct block_index *g = chainstate_insert_block_index((struct chainstate *)ms, &cp->consensus.hashGenesisBlock);
    bool opened = g && block_index_initialize_genesis(g, cp) && progress_store_open_existing(path);
    int fd = opened ? open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
    int64_t ready = platform_time_monotonic_ms(); bool ok = false;
    if (opened && fd >= 0) ok = csi_cold_pixel_stages(f, ms, fd, start, ready);
    if (fd >= 0) close(fd);
    if (opened) progress_store_close();
    main_state_free(ms); free(ms); return ok;
}
static bool csi_cold_data(const struct csi_real_paths *p, struct csi_cold_fixture *f, struct csi_cold_state *s)
{
    if (!csi_real_path(f->dir, sizeof(f->dir), p->root, "cold-linked") || mkdir(f->dir, 0700) ||
        !progress_store_open(f->dir)) return false;
    f->fd = open(f->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (f->fd < 0 || !csi_cold_state_init(s, true) || !csi_cold_validate_headers(f, s->genesis) ||
        !csi_cold_seed_progress(progress_store_db(), s->genesis, f)) return false;
    char log[PATH_MAX], projection[PATH_MAX];
    if (!csi_real_path(log, sizeof(log), f->dir, "events.log") ||
        !csi_real_path(projection, sizeof(projection), f->dir, "block_index_projection.db") ||
        event_log_singleton() || block_index_projection_singleton()) return false;
    f->log = event_log_open(log); f->projection = f->log ? block_index_projection_open(projection, f->log) : NULL;
    if (!f->projection) return false;
    event_log_set_singleton(f->log); block_index_projection_set_singleton(f->projection);
    return csi_cold_emit(f, 0) && csi_cold_emit(f, 1);
}
static bool csi_cold_reject_rows(struct csi_cold_fixture *f, struct csi_cold_state *s, struct csi_cold_stop *stop)
{
    const struct block_header *h = &f->headers[0]; boot_wallet_cold_prefix_t *stage = NULL;
    size_t before = block_map_count(&s->ms.map_block_index);
    uint32_t original = f->rows[0].nBits; f->rows[0].nBits ^= 1u;
    bool changed = csi_cold_emit(f, 0);
    bool stable = changed && boot_wallet_cold_prefix_stage_with_history(&s->ms, f->fd, 3, f->preflight,
        csi_cold_stop, stop, &stage) == BOOT_WALLET_COLD_UNAVAILABLE && !stage && csi_cold_unchanged(s, before, s->far);
    f->rows[0].nBits = original;
    uint8_t fake_solution = 7;
    bool extended = block_index_set_hdrext(&f->rows[0], &h->hashMerkleRoot, &h->nNonce, &fake_solution, 1) && csi_cold_emit(f, 0);
    bool noncompact = extended && boot_wallet_cold_prefix_stage_with_history(&s->ms, f->fd, 3, f->preflight,
        csi_cold_stop, stop, &stage) == BOOT_WALLET_COLD_UNAVAILABLE && !stage && csi_cold_unchanged(s, before, s->far);
    block_index_hdrext_free(&f->rows[0]);
    bool restored = csi_cold_emit(f, 0);
    fprintf(stderr, "cold linked: stable-field refusal=%d noncompact refusal=%d restored=%d\n", stable, noncompact, restored);
    return stable && noncompact && restored;
}
static bool csi_cold_generation(sqlite3 *db, uint8_t value)
{
    uint8_t raw[8] = {0}; raw[0] = value;
    progress_store_tx_lock();
    bool begun = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    bool wrote = begun && progress_meta_set_in_tx(db, COINS_KV_AUTHORITY_GENERATION_KEY, raw, sizeof(raw));
    bool finished = begun && sqlite3_exec(db, wrote ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK;
    progress_store_tx_unlock(); return wrote && finished;
}
static bool csi_cold_guard_cases(struct csi_cold_fixture *f, struct csi_cold_state *s,
                                 boot_wallet_cold_prefix_t *stage, struct csi_cold_stop *stop)
{
    size_t before = block_map_count(&s->ms.map_block_index);
    struct boot_bound_bundle_observation stale = csi_real_bound_observation; ++stale.attempts;
    bool request = boot_wallet_cold_prefix_adopt(stage, &s->csr, f->preflight, &stale,
        f->artifact, &f->cap) == BOOT_WALLET_COLD_UNAVAILABLE && csi_cold_unchanged(s, before, s->far);
    bool bumped = csi_cold_generation(progress_store_db(), 1);
    bool frontier = bumped && boot_wallet_cold_prefix_adopt(stage, &s->csr, f->preflight,
        &csi_real_bound_observation, f->artifact, &f->cap) == BOOT_WALLET_COLD_UNAVAILABLE &&
        csi_cold_unchanged(s, before, s->far);
    bool restored = csi_cold_generation(progress_store_db(), 0);
    stop->now = true;
    bool cancelled = boot_wallet_cold_prefix_adopt(stage, &s->csr, f->preflight,
        &csi_real_bound_observation, f->artifact, &f->cap) == BOOT_WALLET_COLD_STOPPED &&
        csi_cold_unchanged(s, before, s->far);
    stop->now = false;
    fprintf(stderr, "cold linked: stale-request=%d stale-frontier=%d restore=%d stop-before=%d\n", request, frontier, restored, cancelled);
    return request && frontier && restored && cancelled;
}
static bool csi_cold_adoption_witness(struct csi_cold_fixture *f, struct csi_cold_state *s,
    enum boot_wallet_cold_result adopted, boot_wallet_cold_prefix_t *stage, unsigned reads)
{
    struct active_chain_window_snapshot window;
    struct uint256 best; coins_view_cache_get_best_block(&s->cache, &best);
    struct block_index *h1 = block_map_find(&s->ms.map_block_index, &f->hash[0]);
    struct block_index *h2 = block_map_find(&s->ms.map_block_index, &f->hash[1]);
    return adopted == BOOT_WALLET_COLD_ADOPTED && h1 && h2 && h1->pprev == s->genesis && h2->pprev == h1 &&
        active_chain_capture_window(&s->ms.chain_active, -1, &window) && window.tip == h2 &&
        s->ms.pindex_best_header == h2 && uint256_eq(&best, &f->hash[1]) &&
        block_map_find(&s->ms.map_block_index, s->far->phashBlock) == s->far && reads == 2 &&
        !boot_wallet_cold_prefix_release(stage) && boot_wallet_cold_prefix_close_readers(stage);
}
static bool csi_cold_success(struct csi_cold_fixture *f, struct csi_cold_state *s)
{
    struct csi_cold_stop stop = {.ms = &s->ms}; boot_wallet_cold_prefix_t *stage = NULL;
    if (!csi_cold_reject_rows(f, s, &stop)) return false;
    enum boot_wallet_cold_result staged = boot_wallet_cold_prefix_stage_with_history(&s->ms, f->fd, 3,
        f->preflight, csi_cold_stop, &stop, &stage);
    if (staged != BOOT_WALLET_COLD_READY || !stage) return false;
    const struct block_index *tip = boot_wallet_cold_prefix_tip(stage);
    bool compact = tip && tip->nHeight == 2 && tip->phashBlock && uint256_eq(tip->phashBlock, &f->hash[1]);
    if (!compact || !csi_cold_guard_cases(f, s, stage, &stop)) return false;
    /* A stop is sticky: release the unadopted stage and build a fresh one. */
    if (!boot_wallet_cold_prefix_release(stage)) return false;
    stage = NULL; stop.now = false;
    if (boot_wallet_cold_prefix_stage_with_history(&s->ms, f->fd, 3, f->preflight,
            csi_cold_stop, &stop, &stage) != BOOT_WALLET_COLD_READY || !stage) return false;
    (void)boot_wallet_prebinding_test_take_header_reads();
    enum boot_wallet_cold_result adopted = boot_wallet_cold_prefix_adopt(stage, &s->csr, f->preflight,
        &csi_real_bound_observation, f->artifact, &f->cap);
    unsigned reads = boot_wallet_prebinding_test_take_header_reads();
    bool ok = csi_cold_adoption_witness(f, s, adopted, stage, reads);
    fprintf(stderr, "cold linked: compact=%d adopted=%d far-retained=%d header-reads=%u\n", compact,
        adopted == BOOT_WALLET_COLD_ADOPTED, s->far != NULL, reads);
    return ok;
}
/* Call last in this dedicated child: after one insertion the arena is held
 * until _exit and no ordinary startup path is entered. */
static bool csi_cold_stop_after_insert(struct csi_cold_fixture *f)
{
    struct csi_cold_state *s = zcl_calloc(1, sizeof(*s), "cold linked terminal state");
    if (!s || !csi_cold_state_init(s, false)) return false;
    struct csi_cold_stop stop = {.ms = &s->ms}; boot_wallet_cold_prefix_t *stage = NULL;
    if (boot_wallet_cold_prefix_stage_with_history(&s->ms, f->fd, 3, f->preflight,
            csi_cold_stop, &stop, &stage) != BOOT_WALLET_COLD_READY || !stage) return false;
    stop.before = block_map_count(&s->ms.map_block_index); stop.after_insert = true;
    enum boot_wallet_cold_result result = boot_wallet_cold_prefix_adopt(stage, &s->csr, f->preflight,
        &csi_real_bound_observation, f->artifact, &f->cap);
    bool ok = result == BOOT_WALLET_COLD_TERMINAL && !boot_wallet_cold_prefix_release(stage) &&
        csi_cold_unchanged(s, stop.before + 1, s->genesis);
    fprintf(stderr, "cold linked: stop-after-insert terminal=%d map=%zu\n", ok,
            block_map_count(&s->ms.map_block_index));
    return ok;
}
static bool csi_cold_linked_run(const struct csi_real_paths *p)
{
    struct csi_cold_fixture f = {.fd = -1};
    struct csi_cold_state *s = zcl_calloc(1, sizeof(*s), "cold linked state");
    chain_params_select(CHAIN_MAIN);
    bool preflight = s && csi_cold_preflight(p, &f);
    const char *pixel = getenv("ZCL_TEST_COLD_PUBLIC_DIR");
    return preflight && csi_cold_pixel_measure(&f, pixel) && csi_cold_data(p, &f, s) &&
        csi_cold_success(&f, s) && csi_cold_stop_after_insert(&f);
}
static bool csi_cold_linked_child(const struct csi_real_paths *p)
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(79);
        alarm(900); _exit(csi_cold_linked_run(p) ? 0 : 1);
    }
    int status = 0;
    return child > 0 && csi_real_wait_child(child, &status) && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif
#endif
