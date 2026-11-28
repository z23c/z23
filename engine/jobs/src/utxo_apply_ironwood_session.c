/* purpose: Check the private reducer's durable frontier against canonical replay. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "jobs/utxo_apply_ironwood_session.h"
#include "jobs/utxo_apply_ironwood_bootstrap.h"
#include "utxo_apply_ironwood_bootstrap_internal.h"
#include "storage/progress_store.h"
#include "base/safe_alloc.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "storage/repair_marker.h"
#include "platform/time_compat.h"
#include "services/ironwood_resident_params.h"
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

static _Atomic bool bootstrap_requested;
bool utxo_ironwood_session_bootstrap_requested(void)
{ return atomic_load(&bootstrap_requested); }
void utxo_ironwood_session_bootstrap_clear(void)
{ atomic_store(&bootstrap_requested, false); }

static struct ironwood_checkpoint_session store;
static struct ironwood_history_cursor replay;
static const struct block_index **slots;
static struct ironwood_history_event verified;

/* One prepare call replays at most this many ancestry links and bodies; a
 * longer replay resumes at the next call from the kept cursor. After a
 * process start the first new block replays from genesis, and one step per
 * stage tick left a restarted node idle for minutes. */
#define UTXO_IRONWOOD_REPLAY_STEP_BUDGET 1024u
static unsigned replay_step_budget = UTXO_IRONWOOD_REPLAY_STEP_BUDGET;
/* After the first step the replay loop also stops when one soft time slice
 * is spent (the bootstrap slice): the loop itself runs for at most one slice
 * plus one step, whatever that step costs. The slice bounds the loop only.
 * The store audit, the ancestry slot allocation, the empty-root setup and
 * the final preparation also run inside the caller's stage transaction, but
 * outside this timer. */
#define UTXO_IRONWOOD_REPLAY_SOFT_SLICE_US 100000
static int64_t replay_soft_slice_us = UTXO_IRONWOOD_REPLAY_SOFT_SLICE_US;

static void end_replay(void)
{
    free(slots);
    slots = NULL;
    replay = (struct ironwood_history_cursor){0};
}

void utxo_ironwood_session_reset(void)
{
    utxo_ironwood_session_bootstrap_clear();
    end_replay();
    store = (struct ironwood_checkpoint_session){0};
    verified = (struct ironwood_history_event){0};
}

#ifdef ZCL_TESTING
void utxo_ironwood_session_test_step_budget(unsigned steps)
{
    replay_step_budget = steps ? steps : 1;
}
void utxo_ironwood_session_test_soft_slice_us(int64_t us)
{
    replay_soft_slice_us = us;
}
#endif

static bool genesis_matches(const struct block_index *bi)
{
    const struct chain_research_descriptor *research = chain_research_profile_current();
    return research && research->id == CHAIN_RESEARCH_IRONWOOD && bi && !bi->pprev &&
        bi->nHeight == 0 && bi->phashBlock &&
        uint256_eq(bi->phashBlock, &research->chain->consensus.hashGenesisBlock);
}

static bool genesis_transaction_shape(const struct transaction *tx)
{
    if (tx->overwintered || tx->version != 1 || tx->num_vin != 1 || !tx->vin ||
        tx->num_vout != 1 || !tx->vout) return false;
    return tx->vin[0].script_sig.size <= MAX_SCRIPT_SIZE &&
        tx->vout[0].script_pub_key.size <= MAX_SCRIPT_SIZE &&
        !tx->num_joinsplit && !tx->num_shielded_spend && !tx->num_shielded_output &&
        !tx->value_balance && !tx->ironwood_value_balance && !tx->v6_wire.size && !tx->v6_wire.data;
}

static bool genesis_body_matches(const struct block_index *bi, const struct block *block)
{
    if (!genesis_matches(bi) || block->header.nSolutionSize > MAX_SOLUTION_SIZE ||
        block->num_vtx != 1 || !block->vtx || !genesis_transaction_shape(block->vtx) ||
        !uint256_eq(&block->vtx->hash, &block->header.hashMerkleRoot)) return false;
    const struct chain_research_descriptor *profile = chain_research_profile_current();
    struct byte_stream wire;
    stream_init(&wire, profile->genesis_wire_len);
    bool match = block_serialize(block, &wire) && wire.size == profile->genesis_wire_len &&
        !memcmp(wire.data, profile->genesis_wire, wire.size);
    stream_free(&wire);
    return match;
}

static bool empty_root(uint8_t root[32])
{
    size_t size;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    struct ironwood_note_frontier empty = {0};
    return ironwood_note_frontier_extend(&empty, NULL, 0, params, size, root).ok;
}

static enum utxo_ironwood_result seed_store(struct sqlite3 *db, const struct block_index *bi)
{
    if (!genesis_matches(bi) && !(bi->nHeight == 1 && genesis_matches(bi->pprev))) {
        atomic_store(&bootstrap_requested, true);
        return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    }
    uint8_t root[32], zero[32] = {0};
    if (!empty_root(root) || !ironwood_checkpoint_begin_replay(db, zero, root))
        return UTXO_IRONWOOD_LOCAL_ERROR;
    if (!ironwood_checkpoint_refresh(db, &store)) return UTXO_IRONWOOD_LOCAL_ERROR;
    if (bi->nHeight == 1 && !ironwood_checkpoint_append(&store, 0,
            bi->pprev->phashBlock->data, zero, root, 0, NULL, 0))
        return UTXO_IRONWOOD_LOCAL_ERROR;
    return UTXO_IRONWOOD_OK;
}

static const uint8_t bootstrap_marker_key[32] = {0};

static bool bootstrap_is_pending(struct sqlite3 *db, bool *pending)
{
    size_t payload_len = 0;
    return repair_marker_table_ensure(db) &&
        repair_marker_have(db, IRONWOOD_BOOTSTRAP_MARKER, 0, bootstrap_marker_key,
                           pending, NULL, 0, &payload_len);
}

static enum utxo_ironwood_result open_store(struct sqlite3 *db, const struct block_index *bi)
{
    bool pending = false;
    if (!db || sqlite3_get_autocommit(db) || !bootstrap_is_pending(db, &pending))
        return UTXO_IRONWOOD_LOCAL_ERROR;
    if (pending) {
        atomic_store(&bootstrap_requested, true);
        return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    }
    if (store.audited && store.db == db) {
        int64_t generation = store.generation;
        if (ironwood_checkpoint_refresh(db, &store)) {
            if (generation != store.generation) {
                verified.available = false;
                end_replay();
            }
            return UTXO_IRONWOOD_OK;
        }
        /* The first transaction can roll back the baseline itself. Probe
         * again and only initialize if both tables are genuinely empty. */
    }
    utxo_ironwood_session_reset();
    if (!db || sqlite3_get_autocommit(db) || !ironwood_checkpoint_ensure_schema(db))
        return UTXO_IRONWOOD_LOCAL_ERROR;
    enum ironwood_checkpoint_probe_result probe = ironwood_checkpoint_probe(db);
    if (probe == IRONWOOD_CHECKPOINT_PROBE_ERROR) return UTXO_IRONWOOD_LOCAL_ERROR;
    if (probe == IRONWOOD_CHECKPOINT_UNINITIALIZED) return seed_store(db, bi);
    return ironwood_checkpoint_refresh(db, &store) ? UTXO_IRONWOOD_OK : UTXO_IRONWOOD_LOCAL_ERROR;
}

static bool matches_row(const struct ironwood_history_event *event)
{
    struct ironwood_checkpoint row;
    return ironwood_checkpoint_latest_before(&store, (int64_t)event->height + 1, &row)
            == IRONWOOD_CHECKPOINT_FOUND && row.height == event->height &&
        row.count == event->count && !memcmp(row.root, event->root, sizeof row.root) &&
        !memcmp(row.block_hash, event->block_hash.data, sizeof row.block_hash);
}

static bool start_replay(const struct block_index *parent)
{
    end_replay();
    size_t count = (size_t)parent->nHeight + 1;
    slots = zcl_calloc(count, sizeof *slots, "ironwood canonical ancestry");
    return slots && utxo_ironwood_history_begin(parent, slots, count, &replay).ok;
}

static enum utxo_ironwood_result resume_replay(const struct block_index *parent,
    ironwood_history_reader_fn reader, const char *datadir, void *user)
{
    struct ironwood_history_cursor next;
    struct ironwood_history_event event = {0};
    int64_t started = platform_time_monotonic_us();
    for (unsigned steps = 0; ; ++steps) {
        struct zcl_result step =
            utxo_ironwood_history_step(&replay, reader, datadir, user, &next, &event);
        if (!step.ok) return step.code == UTXO_IRONWOOD_HISTORY_BODY_MISSING ?
            UTXO_IRONWOOD_HISTORY_INCOMPLETE : UTXO_IRONWOOD_LOCAL_ERROR;
        if (event.available && !matches_row(&event)) return UTXO_IRONWOOD_LOCAL_ERROR;
        replay = next;
        if (next.complete) break;
        if (steps + 1 >= replay_step_budget ||
            platform_time_monotonic_us() - started >= replay_soft_slice_us)
            return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    }
    if (!event.available || event.height != parent->nHeight ||
        !uint256_eq(&event.block_hash, parent->phashBlock)) return UTXO_IRONWOOD_LOCAL_ERROR;
    verified = event;
    end_replay();
    return UTXO_IRONWOOD_OK;
}

static bool bootstrap_snapshot_matches(struct ironwood_checkpoint_session *snapshot,
    const struct ironwood_history_event *event, const struct ironwood_note_frontier *frontier)
{
    int64_t tip, generation; struct ironwood_checkpoint row;
    uint8_t bytes[IRONWOOD_FRONTIER_STORAGE_MAX]; size_t size = 0;
    return ironwood_checkpoint_progress(snapshot, &tip, &generation) &&
        tip == event->height && generation == snapshot->generation &&
        ironwood_checkpoint_latest_before(snapshot, tip + 1, &row) == IRONWOOD_CHECKPOINT_FOUND &&
        row.count == event->count && !memcmp(row.root, event->root, 32) &&
        !memcmp(row.block_hash, event->block_hash.data, 32) &&
        ironwood_frontier_encode(frontier, bytes, sizeof bytes, &size).ok &&
        row.payload_size == size && !memcmp(row.payload, bytes, size);
}

static enum utxo_ironwood_result recover_parent(const struct block_index *parent,
    ironwood_history_reader_fn reader, const char *datadir, void *user)
{
    if (!parent || !parent->phashBlock || parent->nHeight < 0) return UTXO_IRONWOOD_LOCAL_ERROR;
    if (verified.available && verified.height == parent->nHeight &&
        uint256_eq(&verified.block_hash, parent->phashBlock) && matches_row(&verified))
        return UTXO_IRONWOOD_OK;
    struct ironwood_history_event completed = {0};
    struct ironwood_note_frontier frontier = {0};
    struct ironwood_checkpoint_session snapshot = {0};
    if (utxo_ironwood_bootstrap_completed(store.db, progress_store_epoch(), parent,
            &completed, &frontier, &snapshot) &&
        bootstrap_snapshot_matches(&snapshot, &completed, &frontier)) {
        store = snapshot; verified = completed; end_replay(); return UTXO_IRONWOOD_OK;
    }
    int64_t checkpoint_tip, generation;
    if (!ironwood_checkpoint_progress(&store, &checkpoint_tip, &generation))
        return UTXO_IRONWOOD_LOCAL_ERROR;
    if (checkpoint_tip < parent->nHeight) {
        atomic_store(&bootstrap_requested, true);
        return UTXO_IRONWOOD_HISTORY_INCOMPLETE;
    }
    if (!slots || replay.parent != parent || !uint256_eq(&replay.parent_hash, parent->phashBlock)) {
        if (!start_replay(parent)) return UTXO_IRONWOOD_LOCAL_ERROR;
    }
    return resume_replay(parent, reader, datadir, user);
}

enum utxo_ironwood_result utxo_ironwood_session_prepare(struct sqlite3 *db,
    const struct block_index *bi, const struct block *block,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct utxo_ironwood_pending *out)
{
    if (!bi || !block || !out) return UTXO_IRONWOOD_LOCAL_ERROR;
    enum utxo_ironwood_result r = open_store(db, bi);
    if (r != UTXO_IRONWOOD_OK) return r;
    if (bi->nHeight == 0) {
        if (!genesis_body_matches(bi, block))
            return UTXO_IRONWOOD_LOCAL_ERROR;
        struct utxo_ironwood_pending genesis = {0};
        if (!empty_root(genesis.checkpoint.root)) return UTXO_IRONWOOD_LOCAL_ERROR;
        memcpy(genesis.checkpoint.block_hash, bi->phashBlock->data, 32);
        *out = genesis;
        return UTXO_IRONWOOD_OK;
    }
    r = recover_parent(bi->pprev, reader, datadir, user);
    if (r != UTXO_IRONWOOD_OK) return r;
    struct utxo_ironwood_parent expected = {.count = verified.count};
    memcpy(expected.root, verified.root, sizeof expected.root);
    size_t size;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    return utxo_apply_ironwood_prepare(&store, bi, block, &expected, params, size, out);
}

bool utxo_ironwood_session_publish(const struct utxo_ironwood_pending *pending)
{
    const struct ironwood_checkpoint *row = &pending->checkpoint;
    if (!ironwood_checkpoint_append(&store, row->height, row->block_hash,
            pending->parent_hash, row->root, row->count,
            pending->changed ? row->payload : NULL, row->payload_size)) return false;
    /* The outer transaction can still roll back. Recheck row and generation
     * before any subsequent use, including the next block in this batch. */
    verified.height = (int)row->height;
    memcpy(verified.block_hash.data, row->block_hash, 32);
    memcpy(verified.root, row->root, 32);
    verified.count = row->count;
    verified.available = true;
    return true;
}
