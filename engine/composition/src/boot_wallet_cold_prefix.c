/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Stage a verified old header prefix without publishing chain state. */
#include "config/boot_wallet_cold_prefix.h"
#include "boot_wallet_cold_prefix_internal.h"
#include "consensus_state_install_terminal_internal.h"
#include "config/boot_wallet_pending_restore.h"
#include "chain/chainparams.h"
#include "chain/pow.h"
#include "primitives/block.h"
#include "jobs/reducer_frontier.h"
#include "services/block_index_loader.h"
#include "services/block_row_verify.h"
#include "storage/block_index_projection.h"
#include "storage/progress_store.h"
#include "validation/check_block.h"
#include "validation/main_state.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct boot_wallet_cold_prefix {
    struct main_state *ms;
    struct bound_history_preflight *history;
    int dirfd;
    sqlite3 *progress;
    bool transaction;
    bip_existing_snapshot_t *projection;
    struct boot_wallet_frontier authority;
    struct block_index *arena;
    struct block_index **chosen;
    size_t count;
    bool (*stop)(void *);
    void *ctx;
    bool cancel_observed;
    bool io_error;
    bool insertion_started;
};
/* Both handles must still name the retained directory entry. The caller keeps
 * this namespace stable throughout startup. */
static bool cold_progress_identity(struct boot_wallet_cold_prefix *s)
{
    sqlite3 *singleton = progress_store_db();
    if (!singleton || !s->progress || !progress_store_directory_matches_fd(singleton, s->dirfd)) return false;
    int singleton_moved = 1, reader_moved = 1;
    progress_store_tx_lock();
    bool ok = sqlite3_file_control(singleton, "main", SQLITE_FCNTL_HAS_MOVED, &singleton_moved) == SQLITE_OK &&
        sqlite3_file_control(s->progress, "main", SQLITE_FCNTL_HAS_MOVED, &reader_moved) == SQLITE_OK &&
        !singleton_moved && !reader_moved;
    progress_store_tx_unlock();
    return ok;
}
static bool cold_stopped(struct boot_wallet_cold_prefix *s)
{
    if (s->stop && s->stop(s->ctx)) s->cancel_observed = true;
    return s->cancel_observed;
}

static void cold_header(const struct disk_block_index *d, struct block_header *h)
{
    block_header_init(h);
    h->nVersion = d->nVersion; h->hashPrevBlock = d->hashPrev;
    h->hashMerkleRoot = d->hashMerkleRoot;
    h->hashFinalSaplingRoot = d->hashFinalSaplingRoot;
    h->nTime = d->nTime; h->nBits = d->nBits; h->nNonce = d->nNonce;
    h->nSolutionSize = d->nSolutionSize;
    memcpy(h->nSolution, d->nSolution, d->nSolutionSize);
}
static bool cold_header_fields_match(const struct block_header *full, const struct block_header *h)
{
    return full->nVersion == h->nVersion && full->nTime == h->nTime && full->nBits == h->nBits &&
        uint256_eq(&full->hashPrevBlock, &h->hashPrevBlock) &&
        uint256_eq(&full->hashFinalSaplingRoot, &h->hashFinalSaplingRoot) &&
        (uint256_is_null(&h->hashMerkleRoot) || uint256_eq(&full->hashMerkleRoot, &h->hashMerkleRoot)) &&
        (uint256_is_null(&h->nNonce) || uint256_eq(&full->nNonce, &h->nNonce));
}
static bool cold_header_from_history(struct boot_wallet_cold_prefix *s, const struct uint256 *hash,
                                     int32_t height, struct block_header *h)
{
    if (!s->history) return false;
    struct block_header full;
    struct zcl_result loaded = bound_history_preflight_read_header(s->history, height, hash->data, &full);
    if (!loaded.ok) {
        if (loaded.code == BOUND_HISTORY_HEADER_CANCELLED) s->cancel_observed = true;
        else if (loaded.code != BOUND_HISTORY_HEADER_UNAVAILABLE) s->io_error = true;
        return false;
    }
    if (!full.nSolutionSize || full.nSolutionSize > sizeof(full.nSolution)) return false;
    struct uint256 actual; block_header_get_hash(&full, &actual);
    if (!uint256_eq(&actual, hash) || !cold_header_fields_match(&full, h)) return false;
    *h = full; return true;
}
static bool cold_row(struct boot_wallet_cold_prefix *s, const struct uint256 *hash,
                     int32_t height, struct disk_block_index *d, struct block_header *h)
{
    enum bip_snapshot_lookup found = block_index_projection_snapshot_lookup(s->projection, hash->data, d);
    if (found == BIP_SNAPSHOT_LOOKUP_STOPPED) s->cancel_observed = true;
    if (found == BIP_SNAPSHOT_LOOKUP_ERROR) s->io_error = true;
    if (found != BIP_SNAPSHOT_PRESENT || d->nHeight != height ||
        d->nSolutionSize > sizeof(h->nSolution)) return false;
    cold_header(d, h);
    struct uint256 actual; block_header_get_hash(h, &actual);
    if (uint256_eq(&actual, hash)) return true;
    return d->nSolutionSize == 0 && cold_header_from_history(s, hash, height, h);
}
static bool cold_genesis(struct main_state *ms, const struct chain_params *params,
                         struct block_index **out)
{
    struct block_index *g = block_map_find(&ms->map_block_index, &params->consensus.hashGenesisBlock);
    if (!g || !g->phashBlock || g->pprev || block_has_any_failure(g) ||
        !g->nStatus || !g->nBits || !g->nTx || !g->nChainTx || block_is_revalidation_pending(g)) return false;
    struct block_index copy = *g;
    if (!block_index_initialize_genesis(&copy, params)) return false;
    *out = g; return true;
}
static bool cold_collect(struct boot_wallet_cold_prefix *s, const struct chain_params *params)
{
    struct uint256 expected = s->authority.coins_hash;
    for (size_t i = s->count - 1; i > 0; --i) {
        if (cold_stopped(s)) return false;
        struct disk_block_index d; struct block_header h;
        if (!cold_row(s, &expected, (int32_t)i, &d, &h)) return false;
        struct block_index *p = &s->arena[i]; block_index_init(p);
        p->hashBlock = expected; p->phashBlock = &p->hashBlock;
        p->nHeight = (int)i; p->nVersion = d.nVersion; p->nTime = d.nTime;
        p->nBits = d.nBits; p->hashFinalSaplingRoot = d.hashFinalSaplingRoot;
        p->nStatus = d.nStatus;
        if (block_has_any_failure(p) || block_is_revalidation_pending(p)) return false;
        p->nStatus = BLOCK_VALID_TREE;
        expected = h.hashPrevBlock;
    }
    return uint256_eq(&expected, &params->consensus.hashGenesisBlock) &&
        cold_genesis(s->ms, params, &s->chosen[0]);
}
/* The reducer verdict and exact hash are read from the same snapshot. */
static bool cold_receipt(struct boot_wallet_cold_prefix *s, int32_t height, const struct uint256 *hash, bool *present)
{
    *present = false;
    enum reducer_header_receipt verdict = reducer_frontier_header_receipt(s->progress, height);
    if (verdict == REDUCER_HEADER_RECEIPT_ABSENT) return true;
    if (verdict == REDUCER_HEADER_RECEIPT_ERROR) s->io_error = true;
    if (verdict != REDUCER_HEADER_RECEIPT_PASS) return false;
    uint8_t actual[32]; bool found = false;
    if (!reducer_frontier_log_hash_at(s->progress, "validate_headers_log", "hash", height, actual, &found)) {
        s->io_error = true; return false;
    }
    if (!found || memcmp(actual, hash->data, 32) != 0) return false;
    *present = true; return true;
}
static bool cold_resident_header_matches(const struct block_index *p, const struct block_header *h)
{
    if (p->nVersion != h->nVersion || p->nTime != h->nTime || p->nBits != h->nBits ||
        !uint256_eq(&p->hashFinalSaplingRoot, &h->hashFinalSaplingRoot)) return false;
    const struct block_index_hdrext *ext = block_index_hdrext_peek(p);
    if (!ext) return true;
    struct uint256 merkle = block_index_merkle_root(p), nonce = block_index_nonce(p);
    if (!uint256_eq(&merkle, &h->hashMerkleRoot) || !uint256_eq(&nonce, &h->nNonce)) return false;
    size_t n = 0; const unsigned char *solution = block_index_solution(p, &n);
    return !n || (solution && n == h->nSolutionSize && memcmp(solution, h->nSolution, n) == 0);
}
static bool cold_resident_matches(const struct block_index *p, const struct block_index *expected,
                                  const struct block_header *h)
{
    return p && p->phashBlock && uint256_eq(p->phashBlock, expected->phashBlock) &&
        p->nHeight == expected->nHeight && p->pprev == expected->pprev &&
        arith_uint256_compare(&p->nChainWork, &expected->nChainWork) == 0 &&
        block_index_is_valid(p, BLOCK_VALID_TREE) && !block_has_any_failure(p) &&
        !block_is_revalidation_pending(p) && cold_resident_header_matches(p, h);
}
static bool cold_verify_one(struct boot_wallet_cold_prefix *s,
                            const struct chain_params *params, size_t i)
{
    struct block_index *p = &s->arena[i]; struct disk_block_index d; struct block_header h;
    if (!cold_row(s, p->phashBlock, (int32_t)i, &d, &h) ||
        !uint256_eq(&h.hashPrevBlock, s->chosen[i - 1]->phashBlock)) return false;
    bool pass = false;
    if (!cold_receipt(s, (int32_t)i, p->phashBlock, &pass)) return false;
    if (!pass && block_row_verify(p->phashBlock->data, h.nBits, &h, params, true) != BLOCK_ROW_VERIFY_OK)
        return false;
    struct validation_state validation; validation_state_init(&validation);
    p->pprev = s->chosen[i - 1];
    if (!contextual_check_block_header(&h, &validation, params, p->pprev, s->ms->fCheckpointsEnabled)) return false;
    struct arith_uint256 proof = GetBlockProof(p);
    arith_uint256_add(&p->nChainWork, &p->pprev->nChainWork, &proof);
    struct block_index *resident = block_map_find(&s->ms->map_block_index, p->phashBlock);
    if (resident && !cold_resident_matches(resident, p, &h)) return false;
    if (resident) s->chosen[i] = resident;
    else { block_index_build_skip(p); s->chosen[i] = p; }
    return true;
}
static bool cold_verify(struct boot_wallet_cold_prefix *s, const struct chain_params *params)
{
    for (size_t i = 1; i < s->count; ++i)
        if (cold_stopped(s) || !cold_verify_one(s, params, i)) return false;
    return true;
}
bool boot_wallet_cold_prefix_close_readers(boot_wallet_cold_prefix_t *s)
{
    if (!s) return false;
    bool ok = true;
    if (s->progress && !cold_progress_identity(s)) ok = false;
    if (s->projection && !block_index_projection_snapshot_close(s->projection)) ok = false;
    s->projection = NULL;
    if (s->transaction && sqlite3_exec(s->progress, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) ok = false;
    s->transaction = false;
    if (s->progress) {
        if (sqlite3_close(s->progress) != SQLITE_OK) ok = false;
        else s->progress = NULL;
    }
    return ok;
}
bool boot_wallet_cold_prefix_release(boot_wallet_cold_prefix_t *s)
{
    if (!s || s->insertion_started) return false;
    bool ok = boot_wallet_cold_prefix_close_readers(s);
    free(s->chosen); free(s->arena); free(s); return ok;
}
const struct block_index *boot_wallet_cold_prefix_tip(const boot_wallet_cold_prefix_t *s)
{ return s && s->count ? s->chosen[s->count - 1] : NULL; }

static enum boot_wallet_cold_result cold_stage_open(struct boot_wallet_cold_prefix *s, size_t max_headers)
{
    s->progress = progress_store_open_reader();
    if (!s->progress || sqlite3_exec(s->progress, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return BOOT_WALLET_COLD_ERROR;
    s->transaction = true;
    if (!cold_progress_identity(s)) return BOOT_WALLET_COLD_ERROR;
    if (!boot_wallet_frontier_read_locked(s->progress, &s->authority) ||
        s->authority.coins < 1 || (uint64_t)s->authority.coins + 1 > max_headers)
        return BOOT_WALLET_COLD_UNAVAILABLE;
    s->count = (size_t)s->authority.coins + 1;
    if (s->count > SIZE_MAX / sizeof(*s->arena) || s->count > SIZE_MAX / sizeof(*s->chosen))
        return BOOT_WALLET_COLD_UNAVAILABLE;
    s->arena = zcl_calloc(s->count, sizeof(*s->arena), "cold prefix indices");
    s->chosen = zcl_calloc(s->count, sizeof(*s->chosen), "cold prefix pointers");
    if (!s->arena || !s->chosen) return BOOT_WALLET_COLD_ERROR;
    enum bip_snapshot_result opened = block_index_projection_snapshot_open(s->dirfd, s->stop, s->ctx, &s->projection);
    if (opened == BIP_SNAPSHOT_OK) return BOOT_WALLET_COLD_READY;
    if (opened == BIP_SNAPSHOT_STOPPED) return BOOT_WALLET_COLD_STOPPED;
    if (opened == BIP_SNAPSHOT_ERROR) return BOOT_WALLET_COLD_ERROR;
    return BOOT_WALLET_COLD_UNAVAILABLE;
}
static enum boot_wallet_cold_result cold_stage_verify(struct boot_wallet_cold_prefix *s)
{
    const struct chain_params *params = chain_params_get();
    if (!params || !cold_collect(s, params) || !cold_verify(s, params)) {
        if (s->io_error) return BOOT_WALLET_COLD_ERROR;
        if (s->cancel_observed) return BOOT_WALLET_COLD_STOPPED;
        return BOOT_WALLET_COLD_UNAVAILABLE;
    }
    if (!s->chosen[s->authority.served] ||
        !uint256_eq(s->chosen[s->authority.served]->phashBlock, &s->authority.served_hash))
        return BOOT_WALLET_COLD_UNAVAILABLE;
    return cold_progress_identity(s) ? BOOT_WALLET_COLD_READY : BOOT_WALLET_COLD_ERROR;
}
enum boot_wallet_cold_result boot_wallet_cold_prefix_stage_with_history(struct main_state *ms, int dirfd,
    size_t max_headers, struct bound_history_preflight *history,
    bool (*stop)(void *), void *ctx, boot_wallet_cold_prefix_t **out)
{
    if (!out) return BOOT_WALLET_COLD_ERROR;
    *out = NULL;
    if (!ms || dirfd < 0 || !max_headers || !progress_store_directory_matches_fd(progress_store_db(), dirfd))
        return BOOT_WALLET_COLD_ERROR;
    struct boot_wallet_cold_prefix *s = zcl_calloc(1, sizeof(*s), "cold prefix");
    if (!s) return BOOT_WALLET_COLD_ERROR;
    s->ms = ms; s->dirfd = dirfd; s->history = history; s->stop = stop; s->ctx = ctx;
    enum boot_wallet_cold_result result = cold_stage_open(s, max_headers);
    if (result == BOOT_WALLET_COLD_READY) result = cold_stage_verify(s);
    if (result == BOOT_WALLET_COLD_READY) { *out = s; return result; }
    if (!boot_wallet_cold_prefix_release(s)) return BOOT_WALLET_COLD_ERROR;
    return result;
}

enum boot_wallet_cold_result boot_wallet_cold_prefix_stage(struct main_state *ms, int dirfd,
    size_t max_headers, bool (*stop)(void *), void *ctx, boot_wallet_cold_prefix_t **out)
{ return boot_wallet_cold_prefix_stage_with_history(ms, dirfd, max_headers, NULL, stop, ctx, out); }

/* The startup owner excludes all writers from staging through this commit. */
static bool cold_frontier_current(const struct boot_wallet_cold_prefix *s)
{
    sqlite3 *db = progress_store_db(); struct boot_wallet_frontier now = {0}; bool ok = false;
    progress_store_tx_lock();
    if (db && sqlite3_get_autocommit(db) && sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) == SQLITE_OK) {
        ok = boot_wallet_frontier_read_locked(db, &now) && boot_wallet_frontier_equal(&s->authority, &now);
        if (sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
            if (!sqlite3_get_autocommit(db) && sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
                LOG_ERROR("wallet", "cold frontier rollback failed: %s", sqlite3_errmsg(db));
            ok = false;
        }
    }
    progress_store_tx_unlock(); return ok;
}
static bool cold_header_source(void *ctx, int32_t height, const uint8_t hash[32], struct block_header *out)
{
    struct boot_wallet_cold_prefix *s = ctx;
    if (!s || !out || height < 1 || (size_t)height >= s->count || cold_stopped(s)) return false;
    struct uint256 key; memcpy(key.data, hash, 32);
    struct disk_block_index d;
    return cold_row(s, &key, height, &d, out);
}
static bool cold_adopt_eligible(struct boot_wallet_cold_prefix *s,
                                const struct boot_wallet_cold_terminal_guard *guard)
{
    struct block_index *tip = s->chosen[s->count - 1];
    struct zcl_result eligible = bound_history_preflight_recheck(guard->preflight,
        guard->request, guard->artifact, guard->held, tip);
    return eligible.ok && cold_progress_identity(s) && cold_frontier_current(s);
}
static enum boot_wallet_cold_result cold_adopt_insert(struct boot_wallet_cold_prefix *s)
{
    size_t existing = block_map_count(&s->ms->map_block_index);
    if (s->count > SIZE_MAX - existing || existing + s->count > SIZE_MAX / 4 ||
        !block_map_reserve(&s->ms->map_block_index, existing + s->count)) return BOOT_WALLET_COLD_ERROR;
    for (size_t i = 1; i < s->count; ++i) {
        if (cold_stopped(s)) return s->insertion_started ? BOOT_WALLET_COLD_TERMINAL : BOOT_WALLET_COLD_STOPPED;
        if (s->chosen[i] != &s->arena[i]) continue;
        s->insertion_started = true;
        if (!block_map_insert(&s->ms->map_block_index, s->arena[i].phashBlock, &s->arena[i]))
            return BOOT_WALLET_COLD_TERMINAL;
    }
    return BOOT_WALLET_COLD_READY;
}
static bool cold_adopt_inputs_valid(struct boot_wallet_cold_prefix *s, struct chain_state_repository *csr,
                                    const struct boot_wallet_cold_terminal_guard *guard)
{
    return s && csr && guard->preflight && guard->request && guard->artifact && guard->held && s->projection &&
        s->progress && s->count && !s->insertion_started && s->history == guard->preflight;
}
enum boot_wallet_cold_result boot_wallet_cold_prefix_adopt(boot_wallet_cold_prefix_t *s,
    struct chain_state_repository *csr, struct bound_history_preflight *preflight,
    const struct boot_bound_bundle_observation *request,
    const struct consensus_state_artifact_evidence *artifact,
    const struct wallet_history_capability *held)
{
    struct boot_wallet_cold_terminal_guard guard = {preflight, request, artifact, held};
    if (!cold_adopt_inputs_valid(s, csr, &guard)) return BOOT_WALLET_COLD_ERROR;
    if (cold_stopped(s)) return BOOT_WALLET_COLD_STOPPED;
    if (!cold_adopt_eligible(s, &guard)) return BOOT_WALLET_COLD_UNAVAILABLE;
    enum boot_wallet_cold_result inserted = cold_adopt_insert(s);
    if (inserted != BOOT_WALLET_COLD_READY) return inserted;
    enum boot_pending_restore_result restored = boot_wallet_prebinding_restore_terminal(
        s->ms, csr, s->dirfd, &s->authority, cold_header_source, s, &guard);
    return restored == BOOT_PENDING_RESTORE_OK ? BOOT_WALLET_COLD_ADOPTED : BOOT_WALLET_COLD_TERMINAL;
}
