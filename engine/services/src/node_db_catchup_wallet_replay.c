/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: bounded Sapling wallet replay against an authenticated endpoint. */
#include "services/node_db_catchup_wallet_replay.h"
#include "base/result.h"
#include "util/log_macros.h"
#include "node_db_catchup_internal.h"
#include "config/db_service.h"
#include "domain/consensus/check_block.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "sapling/incremental_merkle_tree.h"
#include "sha3/sha3.h"
#include "support/cleanse.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "validation/main_state.h"
#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(ZCL_TESTING) && !defined(_WIN32)
#include <unistd.h>
static bool replay_test_crash_before_delivery;
void node_db_sapling_replay_test_crash_before_delivery(void)
{
    replay_test_crash_before_delivery = true;
}
#endif

#ifdef ZCL_TESTING
static void (*replay_test_before_revalidate)(void *), (*replay_test_after_revalidate)(void *);
static void *replay_test_revalidate_ctx;
void node_db_sapling_replay_test_revalidate_hooks(void (*before)(void *), void (*after)(void *), void *ctx)
{
    replay_test_before_revalidate = before; replay_test_after_revalidate = after;
    replay_test_revalidate_ctx = ctx;
}
static void (*replay_test_after_keys)(void *);
static void *replay_test_after_keys_ctx;
void node_db_sapling_replay_test_after_keys(void (*hook)(void *), void *ctx)
{
    replay_test_after_keys = hook;
    replay_test_after_keys_ctx = ctx;
}
static void (*replay_test_after_read)(void *);
static void *replay_test_after_read_ctx;
void node_db_sapling_replay_test_after_read(void (*hook)(void *), void *ctx)
{
    replay_test_after_read = hook;
    replay_test_after_read_ctx = ctx;
}
#endif

/* A range owns one immutable public scan snapshot through its synchronous jobs. */
enum catchup_scan_snapshot_status node_db_catchup_scan_snapshot(
    struct wallet *wallet, const uint8_t expected[32], struct wallet_scan_snapshot **out)
{
    if (out) *out = NULL;
    if (!wallet || !expected || !out) return CATCHUP_SCAN_REFUSED;
    if (!zcl_mutex_trylock(&wallet->cs)) return CATCHUP_SCAN_BUSY;
    if (!zcl_mutex_trylock(&wallet->keystore.cs)) {
        zcl_mutex_unlock(&wallet->cs);
        return CATCHUP_SCAN_BUSY;
    }
    if (!zcl_mutex_trylock(&wallet->sapling_keys.cs)) {
        zcl_mutex_unlock(&wallet->keystore.cs);
        zcl_mutex_unlock(&wallet->cs);
        return CATCHUP_SCAN_BUSY;
    }
    bool ok = wallet_scan_snapshot_capture_locked(wallet, expected, out);
    zcl_mutex_unlock(&wallet->sapling_keys.cs);
    zcl_mutex_unlock(&wallet->keystore.cs);
    zcl_mutex_unlock(&wallet->cs);
    return ok ? CATCHUP_SCAN_OK : CATCHUP_SCAN_REFUSED;
}

#define SAPLING_REPLAY_MAX_BLOCKS 256

struct replay_keys {
    struct sapling_key_entry *entries;
    size_t count;
    uint8_t digest[32];
};

/* Caller holds keys->cs. Only public viewing material is copied. */
static bool replay_keys_capture_locked(struct sapling_keystore *keys,
                                       struct replay_keys *out)
{
    if (!keys->num_keys || keys->locked || keys->num_unscannable || keys->num_damaged ||
        keys->num_keys > MAX_SAPLING_KEYS || wallet_lock_is_locked())
        return false;
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    const uint8_t domain[] = "z23-sapling-replay-keys-v1";
    sha3_256_write(&hash, domain, sizeof(domain) - 1);
    for (size_t i = 0; i < keys->num_keys; i++) {
        const struct sapling_key_entry *key = &keys->keys[i];
        if (!key->used) return false;
        if (out->entries) {
            out->entries[i].used = true;
            memcpy(out->entries[i].ivk, key->ivk, 32);
            memcpy(out->entries[i].xfvk.fvk.ak, key->xfvk.fvk.ak, 32);
            memcpy(out->entries[i].xfvk.fvk.nk, key->xfvk.fvk.nk, 32);
        }
        sha3_256_write(&hash, key->ivk, 32);
        sha3_256_write(&hash, key->xfvk.fvk.ak, 32);
        sha3_256_write(&hash, key->xfvk.fvk.nk, 32);
    }
    out->count = keys->num_keys;
    sha3_256_finalize(&hash, out->digest);
    return true;
}

static bool replay_keys_snapshot(struct wallet *wallet, struct replay_keys *out)
{
    struct sapling_keystore *keys = &wallet->sapling_keys;
    if (!zcl_mutex_trylock(&keys->cs)) return false;
    size_t count = keys->num_keys;
    out->entries = count && count <= MAX_SAPLING_KEYS ?
        zcl_calloc(count, sizeof(*out->entries), "sapling replay public keys") : NULL;
    bool ok = (!count || out->entries) && replay_keys_capture_locked(keys, out);
    zcl_mutex_unlock(&keys->cs);
    return ok;
}

struct replay_block {
    struct main_state *state;
    struct wallet *wallet;
    struct node_db *db;
    struct replay_keys *keys;
    struct catchup_parallel_state *parallel;
    struct sapling_replay_delivery delivery;
    struct block *block;
    int height, end, found, reference_height;
    struct uint256 hash, endpoint, reference;
    const uint8_t *scan_identity;
    const struct wallet_scan_snapshot *scan_snapshot;
    enum sapling_replay_phase phase;
    enum sapling_replay_status status;
};

static bool replay_lock_wallet(struct replay_block *job)
{
    if (job->scan_identity) {
        if (!zcl_mutex_trylock(&job->wallet->cs)) return false;
        if (!zcl_mutex_trylock(&job->wallet->keystore.cs)) {
            zcl_mutex_unlock(&job->wallet->cs);
            return false;
        }
    }
    if (zcl_mutex_trylock(&job->wallet->sapling_keys.cs)) return true;
    if (job->scan_identity) {
        zcl_mutex_unlock(&job->wallet->keystore.cs);
        zcl_mutex_unlock(&job->wallet->cs);
    }
    return false;
}

static void replay_unlock_wallet(struct replay_block *job)
{
    zcl_mutex_unlock(&job->wallet->sapling_keys.cs);
    if (job->scan_identity) {
        zcl_mutex_unlock(&job->wallet->keystore.cs);
        zcl_mutex_unlock(&job->wallet->cs);
    }
}

/* The strict path compares the independent range key capture under the key lock. */
static bool replay_keys_match_locked(const struct sapling_keystore *keys,
                                     const struct replay_keys *captured)
{
    if (!keys->num_keys || keys->num_keys > MAX_SAPLING_KEYS || keys->locked ||
        keys->num_unscannable || keys->num_damaged || wallet_lock_is_locked() ||
        keys->num_keys != captured->count || !captured->entries) return false;
    for (size_t i = 0; i < keys->num_keys; ++i) {
        const struct sapling_key_entry *key = &keys->keys[i];
        const struct sapling_key_entry *old = &captured->entries[i];
        if (!key->used || memcmp(key->ivk, old->ivk, 32) ||
            memcmp(key->xfvk.fvk.ak, old->xfvk.fvk.ak, 32) ||
            memcmp(key->xfvk.fvk.nk, old->xfvk.fvk.nk, 32)) return false;
    }
    return true;
}

static bool replay_keys_current(struct replay_block *job)
{
    struct sapling_keystore *keys = &job->wallet->sapling_keys;
    if (job->scan_identity) return replay_keys_match_locked(keys, job->keys);
    struct replay_keys current = {0};
    return replay_keys_capture_locked(keys, &current) &&
        current.count == job->keys->count &&
        memcmp(current.digest, job->keys->digest, 32) == 0;
}

static bool replay_full_identity_current(struct replay_block *job)
{
    if (!job->scan_identity) return true;
    return wallet_readiness_get_locked(job->wallet).state == WALLET_READINESS_PENDING &&
        wallet_scan_snapshot_matches_locked(job->wallet, job->scan_snapshot);
}

static bool replay_reference_current(const struct replay_block *job)
{
    if (!job->scan_identity) return true;
    struct block_index *ref = active_chain_at(&job->state->chain_active, job->reference_height);
    struct block_index *end = active_chain_at(&job->state->chain_active, job->end);
    struct block_index *at = active_chain_at(&job->state->chain_active, job->height);
    return ref && ref->phashBlock && uint256_eq(ref->phashBlock, &job->reference) &&
        end && at && block_index_get_ancestor(ref, job->end) == end &&
        block_index_get_ancestor(ref, job->height) == at;
}

static bool replay_chain_current(const struct replay_block *job)
{
    const struct block_index *p = active_chain_at(&job->state->chain_active, job->height);
    const struct block_index *end = active_chain_at(&job->state->chain_active, job->end);
    return p && p->phashBlock && uint256_eq(p->phashBlock, &job->hash) &&
           end && end->phashBlock && uint256_eq(end->phashBlock, &job->endpoint) &&
           replay_reference_current(job);
}

static bool replay_spends(struct node_db *db, struct transaction *tx)
{
    transaction_compute_hash(tx);
    for (size_t i = 0; i < tx->num_shielded_spend; i++) {
        enum db_mark_spent_result r = db_sapling_note_mark_spent(
            db, tx->v_shielded_spend[i].nullifier.data, tx->hash.data);
        if (r == DB_MARK_SPENT_ERROR) {
            LOG_ERROR("sapling_replay", "failed to mark replayed note spent");
            return false;
        }
    }
    return true;
}

static bool replay_apply_block(struct replay_block *job)
{
    for (size_t i = 0; i < job->block->num_vtx; i++) {
        struct transaction *tx = &job->block->vtx[i];
        if (job->phase == SAPLING_REPLAY_DISCOVER) {
            int found = 0;
            if (!node_db_catchup_replay_sapling_decrypt_parallel(job->db, tx,
                    job->keys->entries, job->keys->count, job->height, &found, &job->delivery, job->parallel))
                return false;
            job->found += found;
        } else if (!replay_spends(job->db, tx)) {
            return false; // raw-return-ok:callee-logs-spend-failure
        }
    }
    return true;
}

static enum sapling_replay_status replay_revalidate(struct replay_block *job)
{
    if (!zcl_mutex_trylock(&job->state->cs_main)) return SAPLING_REPLAY_BUSY;
    if (!replay_lock_wallet(job)) {
        zcl_mutex_unlock(&job->state->cs_main);
        return SAPLING_REPLAY_BUSY;
    }
    bool key_ok = replay_keys_current(job);
    bool wallet_ok = replay_full_identity_current(job);
    bool chain_ok = replay_chain_current(job);
    replay_unlock_wallet(job);
    zcl_mutex_unlock(&job->state->cs_main);
    return !key_ok ? SAPLING_REPLAY_KEYS_UNAVAILABLE :
           (!wallet_ok ? SAPLING_REPLAY_WALLET_CHANGED :
            (!chain_ok ? SAPLING_REPLAY_CHAIN_CHANGED : SAPLING_REPLAY_COMPLETE));
}

static void replay_fail_if_transaction_live(struct node_db *db)
{
    if (!sqlite3_get_autocommit(db->db)) {
        fputs("fatal: Sapling replay transaction unresolved; terminating to preserve database integrity\n", stderr);
        _Exit(EXIT_FAILURE);
    }
}

static void replay_rollback(struct node_db *db)
{
    if (!node_db_rollback(db)) replay_fail_if_transaction_live(db);
}

#ifdef ZCL_TESTING
void node_db_sapling_replay_test_rollback(struct node_db *db)
{
    replay_rollback(db);
}
#endif

static bool replay_flush_batch(struct node_db *db)
{
    if (!db->sync_in_batch || node_db_sync_flush(db)) return true;
    replay_fail_if_transaction_live(db);
    (void)node_db_rollback(db); /* Discard hooks after SQLite auto-rollback. */
    return false;
}

#ifdef ZCL_TESTING
struct zcl_result node_db_sapling_replay_test_flush_batch(struct node_db *db)
{
    if (!replay_flush_batch(db)) return ZCL_ERR(-1, "replay batch flush failed");
    return ZCL_OK;
}
#endif

/* DB worker never waits on a chain or wallet mutex. */
static sqlite3_mutex *replay_begin(struct node_db *db, struct replay_block *job)
{
    if (db != job->db || !db->db) { job->status = SAPLING_REPLAY_DB_ERROR; return NULL; }
    sqlite3_mutex *mu = sqlite3_db_mutex(db->db);
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) {
        job->status = SAPLING_REPLAY_BUSY;
        return NULL;
    }
    if ((job->scan_identity && db->sync_in_batch) ||
        (!db->sync_in_batch && !sqlite3_get_autocommit(db->db))) {
        sqlite3_mutex_leave(mu); job->status = SAPLING_REPLAY_BUSY; return NULL;
    }
    bool ready = replay_flush_batch(db);
    if (ready) ready = node_db_begin_immediate(db);
    if (!ready) {
        replay_fail_if_transaction_live(db);
        sqlite3_mutex_leave(mu); job->status = SAPLING_REPLAY_DB_ERROR; return NULL;
    }
    if (!zcl_mutex_trylock(&job->state->cs_main)) {
        replay_rollback(db); sqlite3_mutex_leave(mu);
        job->status = SAPLING_REPLAY_BUSY; return NULL;
    }
    if (!replay_lock_wallet(job)) {
        zcl_mutex_unlock(&job->state->cs_main); replay_rollback(db);
        sqlite3_mutex_leave(mu); job->status = SAPLING_REPLAY_BUSY; return NULL;
    }
    return mu;
}

static enum sapling_replay_status replay_write_failure(bool key_ok, bool wallet_ok, bool chain_ok)
{
    return !key_ok ? SAPLING_REPLAY_KEYS_UNAVAILABLE :
        (!wallet_ok ? SAPLING_REPLAY_WALLET_CHANGED :
         (!chain_ok ? SAPLING_REPLAY_CHAIN_CHANGED : SAPLING_REPLAY_DB_ERROR));
}

static enum sapling_replay_status replay_deliver(struct replay_block *job)
{
    if (!db_sapling_replay_delivery_flush(&job->delivery)) return SAPLING_REPLAY_EVENT_UNAVAILABLE;
#ifdef ZCL_TESTING
    if (replay_test_before_revalidate) replay_test_before_revalidate(replay_test_revalidate_ctx);
#endif
    enum sapling_replay_status status = replay_revalidate(job);
#ifdef ZCL_TESTING
    if (replay_test_after_revalidate) replay_test_after_revalidate(replay_test_revalidate_ctx);
#endif
    return status;
}

static bool replay_write(struct node_db *db, void *opaque)
{
    struct replay_block *job = opaque;
    sqlite3_mutex *mu = replay_begin(db, job);
    if (!mu) return false;
    bool key_ok = replay_keys_current(job);
    bool wallet_ok = replay_full_identity_current(job);
    bool chain_ok = replay_chain_current(job);
    bool ok = key_ok && wallet_ok && chain_ok && replay_apply_block(job);
    if (ok) ok = node_db_commit(db);
    if (!ok) replay_rollback(db);
    replay_unlock_wallet(job);
    zcl_mutex_unlock(&job->state->cs_main);
    sqlite3_mutex_leave(mu);
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (ok && replay_test_crash_before_delivery) _exit(88);
#endif
    job->status = !ok ? replay_write_failure(key_ok, wallet_ok, chain_ok) : replay_deliver(job);
    db_sapling_replay_delivery_clear(&job->delivery);
    return job->status == SAPLING_REPLAY_COMPLETE;
}

struct replay_location {
    int file;
    unsigned int offset;
    struct uint256 hash;
};

static enum sapling_replay_status replay_location_snapshot(
    struct replay_block *job, struct replay_location *loc)
{
    struct main_state *state = job->state;
    if (!zcl_mutex_trylock(&state->cs_main)) return SAPLING_REPLAY_BUSY;
    const struct block_index *p = active_chain_at(&state->chain_active, job->height);
    const struct block_index *e = active_chain_at(&state->chain_active, job->end);
    enum sapling_replay_status status = SAPLING_REPLAY_INCOMPLETE;
    if ((job->scan_identity && !replay_reference_current(job)) ||
        (e && e->phashBlock && !uint256_eq(e->phashBlock, &job->endpoint)))
        status = SAPLING_REPLAY_CHAIN_CHANGED;
    else if (p && p->phashBlock && e && e->phashBlock && p->nFile >= 0) {
        loc->file = p->nFile; loc->offset = p->nDataPos; loc->hash = *p->phashBlock;
        status = SAPLING_REPLAY_COMPLETE;
    }
    zcl_mutex_unlock(&state->cs_main);
    return status;
}

struct zcl_result node_db_catchup_read_authenticated_block(const char *datadir, int file,
    unsigned int offset, const struct uint256 *expected_hash, struct block *block)
{
    struct node_db_catchup_block_mapping map;
    node_db_catchup_block_mapping_init(&map);
    struct zcl_result opened = node_db_catchup_block_mapping_open_quiet(&map, datadir, file);
    bool mapped = opened.ok && map.mapping.data && (size_t)offset < map.mapping.size;
    bool decoded = false;
    if (mapped) {
        struct byte_stream s;
        stream_init_from_data(&s, map.mapping.data + offset, map.mapping.size - offset);
        decoded = block_deserialize(block, &s);
    }
    node_db_catchup_block_mapping_close(&map);
    if (!mapped) return ZCL_ERR(-1, "wallet replay block mapping or offset unavailable");
    if (!decoded) return ZCL_ERR(-1, "wallet replay block deserialization failed");
    struct uint256 got;
    block_get_hash(block, &got);
    if (!uint256_eq(&got, expected_hash))
        return ZCL_ERR(-1, "wallet replay block hash mismatch");
    for (size_t i = 0; i < block->num_vtx; i++)
        transaction_compute_hash(&block->vtx[i]);
    struct zcl_result merkle = domain_consensus_check_block_merkle_root(block, NULL, 0, NULL);
    if (!merkle.ok) return ZCL_ERR(-1, "wallet replay block Merkle validation failed");
    return ZCL_OK;
}

static enum sapling_replay_status replay_one(struct db_service *svc,
    struct replay_block *job, const char *datadir)
{
    struct replay_location loc;
    enum sapling_replay_status status = replay_location_snapshot(job, &loc);
    if (status != SAPLING_REPLAY_COMPLETE) return status;
    struct block block;
    block_init(&block);
    struct zcl_result read = node_db_catchup_read_authenticated_block(datadir, loc.file, loc.offset, &loc.hash, &block);
    if (!read.ok) {
        LOG_WARN("sapling_replay", "authenticated block unavailable: height=%d reason=%s", job->height, read.message);
        block_free(&block); return SAPLING_REPLAY_INCOMPLETE;
    }
#ifdef ZCL_TESTING
    if (replay_test_after_read) replay_test_after_read(replay_test_after_read_ctx);
#endif
    job->block = &block;
    job->hash = loc.hash;
    job->status = SAPLING_REPLAY_BUSY;
    bool ok = db_service_try_run_write(svc, replay_write, job);
    status = ok ? SAPLING_REPLAY_COMPLETE : job->status;
    block_free(&block);
    return status;
}

static bool replay_range_valid(int start, int end, enum sapling_replay_phase phase,
                               const uint8_t *expected_key_digest)
{
    return start >= 0 && end >= start && end - start < SAPLING_REPLAY_MAX_BLOCKS &&
        (phase == SAPLING_REPLAY_DISCOVER || phase == SAPLING_REPLAY_SPENDS) &&
        (phase != SAPLING_REPLAY_SPENDS || expected_key_digest);
}

static bool replay_context_valid(struct db_service *svc, struct node_db *db,
    struct main_state *state, struct wallet *wallet, const char *datadir,
    const uint8_t *endpoint_hash)
{
    return svc && db && state && wallet && datadir && datadir[0] && endpoint_hash &&
           db_service_is_started(svc) && db_service_node_db(svc) == db;
}

static bool replay_reference_valid(bool strict, int reference_height, int end,
                                   const uint8_t *reference, const uint8_t *identity)
{
    return !strict || (reference && identity && reference_height >= end);
}

static bool replay_capture_keys(struct wallet *wallet, const uint8_t *expected,
    struct replay_keys *keys, struct sapling_replay_result *result)
{
    if (!replay_keys_snapshot(wallet, keys)) {
        result->status = SAPLING_REPLAY_KEYS_UNAVAILABLE;
        return false;
    }
    memcpy(result->key_digest, keys->digest, 32);
    if (expected && memcmp(expected, keys->digest, 32) != 0) {
        result->status = SAPLING_REPLAY_KEYS_UNAVAILABLE;
        return false;
    }
    return true;
}

static void replay_run_blocks(struct db_service *svc, struct replay_block *job,
    const char *datadir, int start, int end, bool strict, struct sapling_replay_result *result)
{
    for (int h = start;; h++) {
        if (strict && thread_registry_shutdown_requested()) {
            result->status = SAPLING_REPLAY_STOPPED;
            break;
        }
        job->height = h; job->found = 0;
        result->status = replay_one(svc, job, datadir);
        if (result->status != SAPLING_REPLAY_COMPLETE) break;
        result->last_complete = h;
        result->notes_found += job->found;
        if (strict && thread_registry_shutdown_requested()) {
            result->status = SAPLING_REPLAY_STOPPED;
            break;
        }
        if (h == end) break;
    }
}

static struct sapling_replay_result replay_run(
    struct db_service *svc, struct node_db *db, struct main_state *state,
    struct wallet *wallet, const char *datadir, int start, int end,
    enum sapling_replay_phase phase, const uint8_t endpoint_hash[32],
    const uint8_t expected_key_digest[32], int reference_height,
    const uint8_t *reference_hash, const uint8_t *scan_identity, bool strict)
{
    struct sapling_replay_result result = {.status = SAPLING_REPLAY_INVALID, .last_complete = -1};
    result.phase = phase; result.start_height = start; result.end_height = end;
    if (!replay_context_valid(svc, db, state, wallet, datadir, endpoint_hash) ||
        !replay_range_valid(start, end, phase, expected_key_digest) ||
        !replay_reference_valid(strict, reference_height, end, reference_hash, scan_identity))
        return result;
    result.last_complete = start - 1;
    memcpy(result.endpoint_hash, endpoint_hash, 32);
    if (strict) {
        result.reference_height = reference_height;
        memcpy(result.reference_hash, reference_hash, 32);
        memcpy(result.scan_identity, scan_identity, 32);
    }
    struct replay_keys keys = {0};
    struct catchup_parallel_state parallel = {0};
    struct wallet_scan_snapshot *scan_snapshot = NULL;
    if (!replay_capture_keys(wallet, expected_key_digest, &keys, &result)) goto done;
#ifdef ZCL_TESTING
    if (replay_test_after_keys) replay_test_after_keys(replay_test_after_keys_ctx);
#endif
    if (strict) {
        enum catchup_scan_snapshot_status captured =
            node_db_catchup_scan_snapshot(wallet, scan_identity, &scan_snapshot);
        if (captured != CATCHUP_SCAN_OK) {
            result.status = captured == CATCHUP_SCAN_BUSY ? SAPLING_REPLAY_BUSY : SAPLING_REPLAY_WALLET_CHANGED;
            goto done;
        }
    }
    struct replay_block job = {.state = state, .wallet = wallet, .db = db,
        .keys = &keys, .parallel = &parallel, .end = end, .phase = phase,
        .reference_height = reference_height, .scan_identity = scan_identity,
        .scan_snapshot = scan_snapshot};
    memcpy(job.endpoint.data, endpoint_hash, 32);
    if (strict) memcpy(job.reference.data, reference_hash, 32);
    replay_run_blocks(svc, &job, datadir, start, end, strict, &result);
done:
    node_db_catchup_parallel_free(&parallel);
    wallet_scan_snapshot_free(scan_snapshot);
    if (keys.entries) {
        memory_cleanse(keys.entries, keys.count * sizeof(*keys.entries));
        free(keys.entries);
    }
    return result;
}

struct sapling_replay_result node_db_catchup_sapling_replay(
    struct db_service *svc, struct node_db *db, struct main_state *state,
    struct wallet *wallet, const char *datadir, int start, int end,
    enum sapling_replay_phase phase, const uint8_t endpoint_hash[32],
    const uint8_t expected_key_digest[32])
{
    return replay_run(svc, db, state, wallet, datadir, start, end, phase,
                      endpoint_hash, expected_key_digest, end, NULL, NULL, false);
}

struct sapling_replay_result node_db_catchup_sapling_replay_at_reference(
    struct db_service *svc, struct node_db *db, struct main_state *state,
    struct wallet *wallet, const char *datadir, int start, int end,
    int reference_height, const uint8_t reference_hash[32],
    enum sapling_replay_phase phase, const uint8_t endpoint_hash[32],
    const uint8_t expected_scan_identity[32], const uint8_t expected_key_digest[32])
{
    return replay_run(svc, db, state, wallet, datadir, start, end, phase,
                      endpoint_hash, expected_key_digest, reference_height,
                      reference_hash, expected_scan_identity, true);
}
