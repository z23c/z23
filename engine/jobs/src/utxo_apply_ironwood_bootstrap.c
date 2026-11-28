/* purpose: Reconstruct private Ironwood checkpoints in bounded transactions. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "utxo_apply_ironwood_bootstrap_internal.h"
#include "base/serialize_le.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "jobs/utxo_apply_stage.h"
#include "jobs/utxo_apply_ironwood_session.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/progress_store.h"
#include "util/stage.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/main_state.h"
#include "utxo_apply_stage_internal.h"
#include <pthread.h>
#include "services/ironwood_resident_params.h"
#include "platform/time_compat.h"
#include "storage/ironwood_frontier_store.h"
#include "storage/repair_marker.h"
#include <limits.h>
#include <string.h>

static void bootstrap_local_error(const char *reason)
{
    struct blocker_record rec;
    if (blocker_init(&rec, "utxo_apply.ironwood_bootstrap", "utxo_apply",
                     BLOCKER_TRANSIENT, reason)) (void)blocker_set(&rec);
}

static pthread_mutex_t bootstrap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ironwood_bootstrap_cursor bootstrap_cursor;

static const uint8_t marker_key[32] = {0};
static const uint8_t marker_tag[8] = { 'I', 'W', 'B', 'O', 'O', 'T', '0', '1' };
struct bootstrap_marker { int64_t height, generation; struct uint256 hash; };

static bool marker_read(sqlite3 *db, bool *have, struct bootstrap_marker *out)
{
    uint8_t bytes[56]; size_t len = 0;
    if (!repair_marker_table_ensure(db) ||
        !repair_marker_have(db, IRONWOOD_BOOTSTRAP_MARKER, 0, marker_key,
                            have, bytes, sizeof bytes, &len)) return false;
    if (!*have) return true;
    if (len != sizeof bytes || memcmp(bytes, marker_tag, 8) ||
        zcl_read_u64_le(bytes + 8) > INT_MAX || zcl_read_u64_le(bytes + 48) > INT64_MAX)
        return false;
    out->height = (int64_t)zcl_read_u64_le(bytes + 8);
    memcpy(out->hash.data, bytes + 16, 32);
    out->generation = (int64_t)zcl_read_u64_le(bytes + 48);
    return true;
}
static bool marker_write(sqlite3 *db, const struct bootstrap_marker *m)
{
    uint8_t bytes[56];
    memcpy(bytes, marker_tag, 8); zcl_write_u64_le(bytes + 8, (uint64_t)m->height);
    memcpy(bytes + 16, m->hash.data, 32); zcl_write_u64_le(bytes + 48, (uint64_t)m->generation);
    return repair_marker_note_in_tx(db, IRONWOOD_BOOTSTRAP_MARKER, 0, marker_key, bytes, sizeof bytes);
}
static bool bootstrap_empty(struct ironwood_bootstrap_cursor *c)
{
    size_t size = 0;
    const uint8_t *params = ironwood_resident_merkle_parameters(&size);
    struct zcl_result r = ironwood_note_frontier_extend(&c->frontier, NULL, 0, params, size, c->root);
    if (!r.ok) LOG_FAIL("utxo_apply", "Ironwood empty frontier unavailable: %s", r.message);
    return true;
}
static bool marker_matches(const struct bootstrap_marker *m, const struct block_index *parent)
{
    return parent && parent->phashBlock && m->height == parent->nHeight &&
           uint256_eq(&m->hash, parent->phashBlock);
}
static bool same_cursor(const struct ironwood_bootstrap_cursor *c, sqlite3 *db,
    uint64_t epoch, const struct bootstrap_marker *m)
{
    return c->active && c->db == db && c->epoch == epoch &&
        c->target_height == m->height && c->generation == m->generation &&
        uint256_eq(&c->target_hash, &m->hash);
}
static bool row_matches(struct ironwood_checkpoint_session *store,
                        const struct ironwood_history_event *event,
                        const struct ironwood_note_frontier *frontier)
{
    struct ironwood_checkpoint row;
    uint8_t encoded[IRONWOOD_FRONTIER_STORAGE_MAX]; size_t size = 0;
    if (!ironwood_frontier_encode(frontier, encoded, sizeof encoded, &size).ok) return false;
    return ironwood_checkpoint_latest_before(store, (int64_t)event->height + 1, &row)
        == IRONWOOD_CHECKPOINT_FOUND && row.height == event->height &&
        row.count == event->count && !memcmp(row.root, event->root, 32) &&
        !memcmp(row.block_hash, event->block_hash.data, 32) &&
        row.payload_size == size && !memcmp(row.payload, encoded, size);
}
static bool append_event(struct ironwood_checkpoint_session *store,
    const struct ironwood_history_event *event, const struct uint256 *previous,
    const struct ironwood_note_frontier *before, const struct ironwood_note_frontier *after)
{
    uint8_t payload[IRONWOOD_FRONTIER_STORAGE_MAX]; size_t size = 0;
    bool changed = before->count != after->count;
    if (changed && !ironwood_frontier_encode(after, payload, sizeof payload, &size).ok) return false;
    return ironwood_checkpoint_append(store, event->height, event->block_hash.data,
        previous->data, event->root, event->count, changed ? payload : NULL, size);
}
enum ironwood_bootstrap_result utxo_ironwood_bootstrap_prepare(
    const struct block_index *parent, const struct ironwood_bootstrap_cursor *cursor,
    ironwood_history_reader_fn reader, const char *datadir, void *user,
    struct ironwood_bootstrap_slice *out)
{
    if (!parent || !parent->phashBlock || !cursor || !cursor->active || !out ||
        parent->nHeight != cursor->target_height ||
        !uint256_eq(parent->phashBlock, &cursor->target_hash)) return IRONWOOD_BOOTSTRAP_ERROR;
    struct ironwood_bootstrap_slice slice = {0}; slice.base = *cursor;
    struct ironwood_bootstrap_cursor c = *cursor;
    int64_t limit = c.retarget ? c.persisted_tip : c.target_height;
    int64_t started = platform_time_monotonic_us();
    while (slice.count < IRONWOOD_BOOTSTRAP_MAX_STEPS && c.next_height <= limit) {
        if (slice.count && platform_time_monotonic_us() - started >= 100000) break;
        struct ironwood_bootstrap_item *item = &slice.items[slice.count];
        item->previous = c.previous;
        struct zcl_result r = utxo_ironwood_history_indexed_step(parent, (int)c.next_height,
            &c.previous, &c.frontier, c.root, reader, datadir, user,
            &item->frontier, item->root, &item->event);
        if (!r.ok) {
            if (r.code == UTXO_IRONWOOD_HISTORY_BODY_MISSING) break;
            return IRONWOOD_BOOTSTRAP_ERROR;
        }
        c.previous = item->event.block_hash; c.frontier = item->frontier;
        memcpy(c.root, item->root, 32); ++c.next_height; ++slice.count;
    }
    slice.ready = true; *out = slice;
    return IRONWOOD_BOOTSTRAP_MORE;
}

static bool bootstrap_apply_item(const struct block_index *replacement,
    const struct ironwood_bootstrap_item *item, struct ironwood_checkpoint_session *store,
    int64_t *tip, struct ironwood_bootstrap_cursor *c)
{
    const struct ironwood_note_frontier *next = &item->frontier;
    const struct ironwood_history_event event = item->event;
    if (!event.available || event.height != c->next_height ||
        !uint256_eq(&item->previous, &c->previous)) return false;
    if (c->next_height <= *tip) {
        if (!row_matches(store, &event, next)) return false;
    } else {
        if (!append_event(store, &event, &c->previous, &c->frontier, next)) return false;
        ++*tip;
    }
    if (c->retarget && c->divergence < 0) {
        const struct block_index *other = c->next_height <= replacement->nHeight ?
            block_index_get_ancestor((struct block_index *)replacement, (int)c->next_height) : NULL;
        if (c->next_height <= replacement->nHeight && (!other || !other->phashBlock)) return false;
        if (!other || !uint256_eq(other->phashBlock, &event.block_hash)) c->divergence = c->next_height;
    }
    c->previous = event.block_hash; c->frontier = *next; c->last = event;
    memcpy(c->root, item->root, 32); ++c->next_height;
    return true;
}

static enum ironwood_bootstrap_result bootstrap_finish_retarget(sqlite3 *db,
    const struct block_index *replacement, struct ironwood_checkpoint_session *store,
    int64_t tip, struct ironwood_bootstrap_cursor *c)
{
    if (c->divergence >= 0 && tip >= c->divergence) {
        int64_t first = tip - (IRONWOOD_BOOTSTRAP_MAX_STEPS - 1);
        if (first < c->divergence) first = c->divergence;
        if (!ironwood_checkpoint_delete_range(db, first, tip)) return IRONWOOD_BOOTSTRAP_ERROR;
        store->generation++; c->generation = store->generation;
        tip = first - 1; c->persisted_tip = tip;
    }
    if (c->divergence < 0 || tip < c->divergence) {
        c->target_height = replacement->nHeight; c->target_hash = *replacement->phashBlock;
        c->active = false;
    }
    struct bootstrap_marker m = { .height = c->target_height, .generation = c->generation,
                                  .hash = c->target_hash };
    return marker_write(db, &m) ? IRONWOOD_BOOTSTRAP_MORE : IRONWOOD_BOOTSTRAP_ERROR;
}

static enum ironwood_bootstrap_result bootstrap_advance(sqlite3 *db,
    const struct block_index *replacement, const struct ironwood_bootstrap_slice *slice,
    struct ironwood_checkpoint_session *store, int64_t tip, struct ironwood_bootstrap_cursor *c)
{
    for (size_t i = 0; i < slice->count; ++i)
        if (!bootstrap_apply_item(replacement, &slice->items[i], store, &tip, c))
            return IRONWOOD_BOOTSTRAP_ERROR;
    int64_t observed_tip, generation;
    if (!ironwood_checkpoint_progress(store, &observed_tip, &generation) || observed_tip != tip)
        return IRONWOOD_BOOTSTRAP_ERROR;
    c->generation = generation; c->persisted_tip = tip;
    if (c->retarget && c->next_height > tip)
        return bootstrap_finish_retarget(db, replacement, store, tip, c);
    if (c->next_height <= c->target_height) {
        struct bootstrap_marker m = { .height = c->target_height, .generation = generation,
                                      .hash = c->target_hash };
        return marker_write(db, &m) ? IRONWOOD_BOOTSTRAP_MORE : IRONWOOD_BOOTSTRAP_ERROR;
    }
    if (!c->last.available || !uint256_eq(&c->last.block_hash, &c->target_hash) || tip != c->target_height)
        return IRONWOOD_BOOTSTRAP_ERROR;
    return repair_marker_forget_in_tx(db, IRONWOOD_BOOTSTRAP_MARKER, 0, marker_key) ?
        IRONWOOD_BOOTSTRAP_DONE : IRONWOOD_BOOTSTRAP_ERROR;
}

static bool slice_cursor_matches(const struct ironwood_bootstrap_cursor *b,
                                 const struct ironwood_bootstrap_cursor *c)
{
    return b->db == c->db && b->epoch == c->epoch && b->generation == c->generation &&
        b->next_height == c->next_height && b->persisted_tip == c->persisted_tip &&
        b->target_height == c->target_height && b->retarget == c->retarget &&
        b->divergence == c->divergence && b->replacement_height == c->replacement_height &&
        uint256_eq(&b->target_hash, &c->target_hash) &&
        uint256_eq(&b->replacement_hash, &c->replacement_hash) &&
        uint256_eq(&b->previous, &c->previous) && !memcmp(b->root, c->root, 32) &&
        !memcmp(&b->frontier, &c->frontier, sizeof c->frontier);
}
static bool slice_matches(const struct ironwood_bootstrap_slice *s,
                          const struct ironwood_bootstrap_cursor *c)
{
    return s->ready && s->count <= IRONWOOD_BOOTSTRAP_MAX_STEPS &&
        slice_cursor_matches(&s->base, c);
}

struct bootstrap_open {
    struct bootstrap_marker marker;
    struct ironwood_checkpoint_session store;
    int64_t tip, generation;
};
static bool bootstrap_inputs_valid(sqlite3 *db, const struct block_index *parent,
    const struct ironwood_bootstrap_cursor *in, const struct ironwood_bootstrap_cursor *out)
{
    const struct chain_research_descriptor *d = chain_research_profile_get(CHAIN_RESEARCH_IRONWOOD);
    return db && !sqlite3_get_autocommit(db) && d && chain_research_profile_current() == d &&
        chain_params_get() == d->chain && parent && parent->phashBlock && parent->nHeight >= 0 &&
        in && out && in != out;
}
static bool bootstrap_existing_complete(struct ironwood_checkpoint_session *store,
    sqlite3 *db, const struct block_index *parent)
{
    int64_t tip, generation; struct ironwood_checkpoint row;
    return ironwood_checkpoint_refresh(db, store) &&
        ironwood_checkpoint_progress(store, &tip, &generation) && tip == parent->nHeight &&
        ironwood_checkpoint_latest_before(store, tip + 1, &row) == IRONWOOD_CHECKPOINT_FOUND &&
        !memcmp(row.block_hash, parent->phashBlock->data, 32);
}
static bool bootstrap_initialize(sqlite3 *db, const struct block_index *parent,
                                 struct bootstrap_open *open)
{
    struct ironwood_bootstrap_cursor initial = {0};
    if (!bootstrap_empty(&initial) || !ironwood_checkpoint_begin_replay(db, marker_key, initial.root) ||
        !ironwood_checkpoint_refresh(db, &open->store)) return false; // raw-return-ok:bootstrap-caller-reports-local-error
    open->marker = (struct bootstrap_marker){ .height = parent->nHeight, .hash = *parent->phashBlock,
                                              .generation = open->store.generation };
    return marker_write(db, &open->marker);
}
static bool bootstrap_existing_marker_valid(sqlite3 *db,
    const struct block_index *parent, const struct block_index *old_parent,
    enum ironwood_checkpoint_probe_result probe, struct bootstrap_open *open)
{
    return probe == IRONWOOD_CHECKPOINT_PRESENT &&
        (marker_matches(&open->marker, parent) || marker_matches(&open->marker, old_parent)) &&
        ironwood_checkpoint_refresh(db, &open->store);
}
static enum ironwood_bootstrap_result bootstrap_open_prefix(sqlite3 *db,
    const struct block_index *parent, struct bootstrap_open *open)
{
    if (bootstrap_existing_complete(&open->store, db, parent)) return IRONWOOD_BOOTSTRAP_DONE;
    if (!ironwood_checkpoint_refresh(db, &open->store) ||
        !ironwood_checkpoint_progress(&open->store, &open->tip, &open->generation) ||
        open->tip >= parent->nHeight) return IRONWOOD_BOOTSTRAP_ERROR;
    open->marker = (struct bootstrap_marker){ .height = parent->nHeight,
        .hash = *parent->phashBlock, .generation = open->generation };
    return marker_write(db, &open->marker) ? IRONWOOD_BOOTSTRAP_MORE : IRONWOOD_BOOTSTRAP_ERROR;
}
static enum ironwood_bootstrap_result bootstrap_choose_store(sqlite3 *db, uint64_t epoch,
    const struct block_index *parent, const struct block_index *old_parent,
    const struct ironwood_bootstrap_cursor *in, struct bootstrap_open *open,
    bool have, enum ironwood_checkpoint_probe_result probe)
{
    if (have && same_cursor(in, db, epoch, &open->marker)) open->store = in->storage;
    if (!have && in->active && in->db == db && in->epoch == epoch)
        return IRONWOOD_BOOTSTRAP_ERROR;
    if (!have && probe == IRONWOOD_CHECKPOINT_PRESENT) {
        enum ironwood_bootstrap_result r = bootstrap_open_prefix(db, parent, open);
        if (r != IRONWOOD_BOOTSTRAP_MORE) return r;
        have = true;
    }
    if (!have) {
        if (!bootstrap_initialize(db, parent, open)) return IRONWOOD_BOOTSTRAP_ERROR;
    } else if (!bootstrap_existing_marker_valid(db, parent, old_parent, probe, open))
        return IRONWOOD_BOOTSTRAP_ERROR;
    return IRONWOOD_BOOTSTRAP_MORE;
}
static enum ironwood_bootstrap_result bootstrap_open_store(sqlite3 *db, uint64_t epoch,
    const struct block_index *parent, const struct block_index *old_parent,
    const struct ironwood_bootstrap_cursor *in, struct bootstrap_open *open)
{
    bool have = false;
    if (!marker_read(db, &have, &open->marker) || !ironwood_checkpoint_ensure_schema(db))
        return IRONWOOD_BOOTSTRAP_ERROR;
    enum ironwood_checkpoint_probe_result probe = ironwood_checkpoint_probe(db);
    if (probe == IRONWOOD_CHECKPOINT_PROBE_ERROR) return IRONWOOD_BOOTSTRAP_ERROR;
    enum ironwood_bootstrap_result r = bootstrap_choose_store(db, epoch, parent, old_parent, in, open, have, probe);
    if (r != IRONWOOD_BOOTSTRAP_MORE) return r;
    if (!ironwood_checkpoint_progress(&open->store, &open->tip, &open->generation) ||
        open->generation != open->marker.generation || open->tip > open->marker.height)
        return IRONWOOD_BOOTSTRAP_ERROR;
    return IRONWOOD_BOOTSTRAP_MORE;
}
static bool bootstrap_continue_cursor(const struct ironwood_bootstrap_cursor *in,
    sqlite3 *db, uint64_t epoch, const struct block_index *parent, const struct bootstrap_open *open)
{
    bool retarget = !marker_matches(&open->marker, parent);
    return same_cursor(in, db, epoch, &open->marker) && in->retarget == retarget &&
        (!retarget || (in->replacement_height == parent->nHeight &&
         uint256_eq(&in->replacement_hash, parent->phashBlock)));
}
static bool bootstrap_new_cursor(sqlite3 *db, uint64_t epoch, const struct block_index *parent,
    const struct bootstrap_open *open, struct ironwood_bootstrap_cursor *c)
{
    c->db = db; c->epoch = epoch; c->active = true; c->target_height = (int)open->marker.height;
    c->target_hash = open->marker.hash; c->generation = open->generation; c->persisted_tip = open->tip;
    c->retarget = !marker_matches(&open->marker, parent); c->divergence = -1;
    if (c->retarget) { c->replacement_height = parent->nHeight; c->replacement_hash = *parent->phashBlock; }
    c->storage = open->store;
    return bootstrap_empty(c);
}
enum ironwood_bootstrap_result utxo_ironwood_bootstrap_step(sqlite3 *db,
    uint64_t epoch, const struct block_index *parent, const struct block_index *old_parent,
    const struct ironwood_bootstrap_slice *slice,
    const struct ironwood_bootstrap_cursor *in, struct ironwood_bootstrap_cursor *out)
{
    if (!bootstrap_inputs_valid(db, parent, in, out)) return IRONWOOD_BOOTSTRAP_ERROR;
    struct bootstrap_open open = {0};
    enum ironwood_bootstrap_result r = bootstrap_open_store(db, epoch, parent, old_parent, in, &open);
    if (r != IRONWOOD_BOOTSTRAP_MORE) return r;
    struct ironwood_bootstrap_cursor c = {0};
    if (!bootstrap_continue_cursor(in, db, epoch, parent, &open)) {
        if (!bootstrap_new_cursor(db, epoch, parent, &open, &c)) return IRONWOOD_BOOTSTRAP_ERROR;
        *out = c; return IRONWOOD_BOOTSTRAP_MORE;
    }
    c = *in;
    if (!slice || !slice_matches(slice, &c)) return IRONWOOD_BOOTSTRAP_ERROR;
    r = bootstrap_advance(db, parent, slice, &open.store, open.tip, &c);
    if (r != IRONWOOD_BOOTSTRAP_ERROR) {
        c.storage = open.store;
        if (r == IRONWOOD_BOOTSTRAP_DONE) { c.active = false; c.completed = true; }
        *out = c;
    }
    return r;
}

static bool bootstrap_durable_parent(sqlite3 *db, int height, const struct uint256 *hash)
{
    if (height == 0) {
        const struct chain_research_descriptor *d = chain_research_profile_current();
        return d && uint256_eq(hash, &d->chain->consensus.hashGenesisBlock);
    }
    uint8_t durable[32];
    return height > 0 && tip_finalize_stage_block_hash_at(db, height, durable) &&
        !memcmp(durable, hash->data, 32);
}

static const struct block_index *bootstrap_parent(struct main_state *ms, int height)
{
    if (height < 0) return NULL;
    return active_chain_at(&ms->chain_active, height);
}

struct bootstrap_run {
    sqlite3 *db;
    struct main_state *ms;
    utxo_apply_reader_fn reader;
    void *user;
    char datadir[2048];
    uint64_t epoch;
    int64_t cursor;
    int height;
    struct uint256 hash;
    const struct block_index *parent, *old_parent;
    bool have, marker_ok, durable, transaction_failed;
    struct bootstrap_marker marker;
    struct ironwood_bootstrap_slice slice;
    struct ironwood_bootstrap_cursor next;
    enum ironwood_bootstrap_result result;
};
static bool bootstrap_context(struct bootstrap_run *r)
{
    r->db = progress_store_db();
    if (!r->db || !utxo_apply_stage_handle() ||
        !utxo_apply_stage_seed_context(&r->ms, r->datadir, sizeof r->datadir, &r->reader, &r->user))
        return false;
    r->epoch = progress_store_epoch();
    return true;
}
static bool bootstrap_slice_prepare(struct bootstrap_run *r)
{
    if (!bootstrap_cursor.active || bootstrap_cursor.db != r->db || bootstrap_cursor.epoch != r->epoch)
        return true;
    if (!zcl_mutex_trylock(&r->ms->cs_main)) return false;
    int height = bootstrap_cursor.retarget ? bootstrap_cursor.replacement_height : bootstrap_cursor.target_height;
    const struct uint256 *hash = bootstrap_cursor.retarget ?
        &bootstrap_cursor.replacement_hash : &bootstrap_cursor.target_hash;
    const struct block_index *current = bootstrap_parent(r->ms, height);
    const struct block_index *scan = bootstrap_cursor.retarget ?
        block_map_find(&r->ms->map_block_index, &bootstrap_cursor.target_hash) : current;
    bool stable = current && current->phashBlock && uint256_eq(current->phashBlock, hash) && scan;
    zcl_mutex_unlock(&r->ms->cs_main);
    if (!stable) return true;
    if (utxo_ironwood_bootstrap_prepare(scan, &bootstrap_cursor, r->reader,
            r->datadir, r->user, &r->slice) != IRONWOOD_BOOTSTRAP_ERROR) return true;
    bootstrap_local_error("Ironwood bootstrap body or ancestry verification failed");
    return false;
}
static bool bootstrap_begin(struct bootstrap_run *r)
{
    progress_store_tx_lock();
    if (r->db != progress_store_db() || r->epoch != progress_store_epoch() ||
        sqlite3_exec(r->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        progress_store_tx_unlock(); return false;
    }
    return true;
}
static bool bootstrap_target(struct bootstrap_run *r)
{
    r->cursor = (int64_t)stage_cursor_persisted(r->db, "utxo_apply", "utxo_apply");
    r->height = r->cursor > 0 && r->cursor <= (int64_t)INT_MAX + 1 ? (int)(r->cursor - 1) : -1;
    r->marker_ok = marker_read(r->db, &r->have, &r->marker);
    if (!zcl_mutex_trylock(&r->ms->cs_main)) return false;
    r->parent = bootstrap_parent(r->ms, r->height);
    if (r->parent && r->parent->phashBlock) r->hash = *r->parent->phashBlock;
    else r->parent = NULL;
    if (r->marker_ok && r->have && r->parent && !marker_matches(&r->marker, r->parent))
        r->old_parent = block_map_find(&r->ms->map_block_index, &r->marker.hash);
    zcl_mutex_unlock(&r->ms->cs_main);
    r->durable = r->parent && r->marker_ok && bootstrap_durable_parent(r->db, r->height, &r->hash);
    return true;
}
static bool bootstrap_finish_transaction(struct bootstrap_run *r)
{
    if (!zcl_mutex_trylock(&r->ms->cs_main)) return false;
    const struct block_index *check = bootstrap_parent(r->ms, r->height);
    bool pinned = check && check->phashBlock && uint256_eq(check->phashBlock, &r->hash);
    bool ok = r->result != IRONWOOD_BOOTSTRAP_ERROR && pinned &&
        bootstrap_durable_parent(r->db, r->height, &r->hash) && r->epoch == progress_store_epoch() &&
        r->cursor == (int64_t)stage_cursor_persisted(r->db, "utxo_apply", "utxo_apply");
    int rc = sqlite3_exec(r->db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        ok = false;
        if (!sqlite3_get_autocommit(r->db)) (void)sqlite3_exec(r->db, "ROLLBACK", NULL, NULL, NULL);
        r->transaction_failed = true;
    }
    zcl_mutex_unlock(&r->ms->cs_main);
    if (ok) {
        bootstrap_cursor = r->next;
        if (r->result == IRONWOOD_BOOTSTRAP_DONE) utxo_ironwood_session_bootstrap_clear();
    } else bootstrap_cursor = (struct ironwood_bootstrap_cursor){0};
    return ok;
}
static bool bootstrap_transaction(struct bootstrap_run *r)
{
    if (!bootstrap_begin(r)) return false;
    if (!bootstrap_target(r)) {
        (void)sqlite3_exec(r->db, "ROLLBACK", NULL, NULL, NULL);
        progress_store_tx_unlock(); return false;
    }
    r->result = r->durable ? utxo_ironwood_bootstrap_step(r->db, r->epoch,
        r->parent, r->old_parent, &r->slice, &bootstrap_cursor, &r->next) : IRONWOOD_BOOTSTRAP_ERROR;
    bool ok = bootstrap_finish_transaction(r);
    if (!sqlite3_get_autocommit(r->db)) (void)sqlite3_exec(r->db, "ROLLBACK", NULL, NULL, NULL);
    progress_store_tx_unlock();
    if (r->transaction_failed) bootstrap_local_error("Ironwood bootstrap transaction failed");
    else if (!r->marker_ok || (r->durable && r->result == IRONWOOD_BOOTSTRAP_ERROR &&
        (!r->have || marker_matches(&r->marker, r->parent) || r->old_parent)))
        bootstrap_local_error("Ironwood bootstrap local checkpoint verification failed");
    else if (ok && (r->slice.count || r->result == IRONWOOD_BOOTSTRAP_DONE))
        blocker_clear("utxo_apply.ironwood_bootstrap");
    return ok;
}
bool utxo_ironwood_bootstrap_post_commit(void)
{
    const struct chain_research_descriptor *d = chain_research_profile_current();
    if (!d || d->id != CHAIN_RESEARCH_IRONWOOD || chain_params_get() != d->chain ||
        !utxo_ironwood_session_bootstrap_requested()) return true;
    if (pthread_mutex_trylock(&bootstrap_lock) != 0) return false;
    struct bootstrap_run run = {0};
    bool ok = bootstrap_context(&run) && bootstrap_slice_prepare(&run) && bootstrap_transaction(&run);
    pthread_mutex_unlock(&bootstrap_lock);
    return ok;
}

void utxo_ironwood_bootstrap_shutdown(void)
{
    pthread_mutex_lock(&bootstrap_lock);
    bootstrap_cursor = (struct ironwood_bootstrap_cursor){0};
    pthread_mutex_unlock(&bootstrap_lock);
}

void utxo_ironwood_bootstrap_context_change_begin(void)
{
    pthread_mutex_lock(&bootstrap_lock);
    bootstrap_cursor = (struct ironwood_bootstrap_cursor){0};
}
void utxo_ironwood_bootstrap_context_change_end(void)
{
    pthread_mutex_unlock(&bootstrap_lock);
}

bool utxo_ironwood_bootstrap_completed(sqlite3 *db, uint64_t epoch,
    const struct block_index *parent, struct ironwood_history_event *event,
    struct ironwood_note_frontier *frontier, struct ironwood_checkpoint_session *store)
{
    if (!db || !parent || !parent->phashBlock || !event || !frontier || !store ||
        pthread_mutex_trylock(&bootstrap_lock) != 0) return false;
    bool ok = bootstrap_cursor.completed && bootstrap_cursor.db == db &&
        bootstrap_cursor.epoch == epoch && bootstrap_cursor.last.available &&
        bootstrap_cursor.last.height == parent->nHeight &&
        uint256_eq(&bootstrap_cursor.last.block_hash, parent->phashBlock);
    if (ok) { *event = bootstrap_cursor.last; *frontier = bootstrap_cursor.frontier;
              *store = bootstrap_cursor.storage; }
    pthread_mutex_unlock(&bootstrap_lock);
    return ok;
}

#ifdef ZCL_TESTING
void utxo_ironwood_bootstrap_publish_for_test(const struct ironwood_bootstrap_cursor *cursor)
{
    pthread_mutex_lock(&bootstrap_lock);
    bootstrap_cursor = *cursor;
    pthread_mutex_unlock(&bootstrap_lock);
}
#endif
