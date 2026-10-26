/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_coin_backfill_scan — chunked, resumable, CHAIN-BOUND
 * no-spend scan (guard G9 of the coin-backfill guard ladder; see
 * stage_repair_coin_backfill.c's top-of-file comment for G0-G10).
 *
 * Proves that none of the candidate backfill outpoints U is spent by any
 * applied active-chain block in [floor .. frontier_at_start-1] (the creator
 * block is included — it catches a later tx in the same block spending the
 * coin; the creating tx itself cannot false-positive because its inputs
 * reference OTHER outpoints), then extends the walk linkage-only through
 * [frontier_at_start .. H] and requires the terminal block H hash to equal
 * the hole row's hash. A candidate spend is not terminal evidence until that
 * final hash binding succeeds; otherwise a mid-scan reorg can make an
 * off-branch spend look active for one height. NO spend refusal in the
 * terminal window: a spend in the unapplied [frontier..H-1] band is *correct*
 * coins state at the frontier snapshot — utxo_apply will consume the coin
 * forward at the spend height and then genuinely reject block H's re-spend
 * (verified forward semantics — see the insert transaction's re-checks in
 * stage_repair_coin_backfill.c, which re-bind this scan's CLEAN verdict to
 * the insert-time active chain before it is trusted).
 *
 * Chain binding: the persisted record carries a running
 * last-scanned hash. EVERY block processed — chunk start, kill-9 resume,
 * and mid-chunk alike — must prev-link (blk.hashPrevBlock) against that
 * persisted lineage before it is examined, and the lineage then advances to
 * the block's own hash-verified active-index hash. The seed is the active
 * hash at floor-1. By second-preimage resistance of double-SHA256, when the
 * walk terminates at hash(H) == hole hash, every scanned block is provably
 * the ancestor, at its height, of the chain block H extends — no
 * reorg/oscillation interleaving can stitch branches into the proof. A
 * prev-link mismatch is COIN_SCAN_CHAIN_REBOUND: the record is discarded
 * and the scan restarts from floor with a fresh seed (bounded restart, not
 * a refusal). Digest/frontier mismatch or a malformed record on resume also
 * restarts from floor. An unreadable block is COIN_SCAN_GAP (resumable once
 * the body appears).
 *
 * The scan itself is read-only on consensus state; its only writes are the
 * progress_meta record under key coin_backfill.scan.<H>.<holehash>
 * (internally locked own-tx — a kill-9 mid-chunk just rescans one
 * idempotent read-only chunk). No allocation happens in the scan loop
 * beyond the block reader's own deserialize buffers (freed per block). */

#include "stage_repair_coin_backfill_internal.h"

#include "crypto/common.h"
#include "crypto/sha3.h"
#include "platform/clock.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ── Record digest / codec ─────────────────────────────────────────── */

static int outpoint_set_entry_cmp(const struct coin_backfill_outpoint *a,
                                  const struct coin_backfill_outpoint *b)
{
    int r = memcmp(a->txid, b->txid, 32);
    if (r != 0)
        return r;
    if (a->vout < b->vout)
        return -1;  // raw-return-ok:comparator-order-sentinel
    if (a->vout > b->vout)
        return 1;
    return 0;
}

/* Stable insertion sort of index handles (n <= 64; no allocation). */
static void sort_set_indices(const struct coin_backfill_outpoint *set,
                             size_t n,
                             uint8_t idx[COIN_BACKFILL_MAX_OUTPOINTS])
{
    for (size_t i = 0; i < n; i++)
        idx[i] = (uint8_t)i;
    for (size_t i = 1; i < n; i++) {
        uint8_t k = idx[i];
        size_t j = i;
        while (j > 0 && outpoint_set_entry_cmp(&set[idx[j - 1]], &set[k]) > 0) {
            idx[j] = idx[j - 1];
            j--;
        }
        idx[j] = k;
    }
}

bool coin_backfill_scan_set_digest(const struct coin_backfill_outpoint *set,
                                   size_t n, uint8_t out_digest[32])
{
    if (!set || !out_digest || n == 0 || n > COIN_BACKFILL_MAX_OUTPOINTS)
        LOG_FAIL("stage_repair",
                 "[coin_backfill] set digest: bad input n=%zu", n);

    uint8_t idx[COIN_BACKFILL_MAX_OUTPOINTS];
    sort_set_indices(set, n, idx);

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (size_t i = 0; i < n; i++) {
        const struct coin_backfill_outpoint *o = &set[idx[i]];
        uint8_t vout_le[4];
        WriteLE32(vout_le, o->vout);
        sha3_256_write(&ctx, o->txid, 32);
        sha3_256_write(&ctx, vout_le, sizeof(vout_le));
    }
    sha3_256_finalize(&ctx, out_digest);
    return true;
}

bool coin_backfill_scan_record_load(struct sqlite3 *db, int hole_height,
                                    const struct uint256 *hole_hash,
                                    struct coin_backfill_scan_record *rec,
                                    bool *found)
{
    if (!rec || !found || !db || !hole_hash)
        LOG_FAIL("stage_repair", "[coin_backfill] scan record load: NULL input");
    *found = false;
    memset(rec, 0, sizeof(*rec));

    uint8_t buf[COIN_BACKFILL_SCAN_REC_PENDING_LEN];
    size_t len = 0;
    bool present = false;
    if (!repair_marker_have(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                            hole_height, hole_hash->data, &present,
                            buf, sizeof(buf), &len))
        LOG_FAIL("stage_repair",
                 "[coin_backfill] scan record read failed h=%d", hole_height);
    if (!present)
        return true;

    bool clean_form = len == COIN_BACKFILL_SCAN_REC_CLEAN_LEN &&
                      buf[COIN_BACKFILL_SCAN_REC_CLEAN_LEN - 1] == 1;
    bool pending_form = len == COIN_BACKFILL_SCAN_REC_PENDING_LEN &&
                        buf[COIN_BACKFILL_SCAN_REC_PENDING_LEN - 1] == 2;
    if (len != COIN_BACKFILL_SCAN_REC_BASE_LEN && !clean_form && !pending_form) {
        /* Malformed: treated as absent so the scan restarts from floor. */
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan record malformed h=%d len=%zu; "
                 "treating as absent (restart from floor)",
                 hole_height, len);
        return true;
    }

    rec->next_height = (int32_t)ReadLE32(buf + 0);
    rec->frontier_at_start = (int32_t)ReadLE32(buf + 4);
    memcpy(rec->last_scanned_hash, buf + 8, 32);
    memcpy(rec->set_digest, buf + 40, 32);
    rec->clean = clean_form;
    if (clean_form)
        memcpy(rec->top_hash, buf + 72, 32);
    rec->pending_spent = pending_form;
    if (pending_form) {
        rec->spent_height = (int32_t)ReadLE32(buf + 72);
        memcpy(rec->spender_txid, buf + 76, 32);
    }
    *found = true;
    return true;
}

static bool scan_record_store(struct sqlite3 *db, int hole_height,
                              const struct uint256 *hole_hash,
                              int32_t next_height, int32_t frontier_at_start,
                              const struct uint256 *lineage,
                              const uint8_t set_digest[32],
                              bool clean, const struct uint256 *top_hash,
                              bool pending_spent, int32_t spent_height,
                              const uint8_t spender_txid[32])
{
    uint8_t rec[COIN_BACKFILL_SCAN_REC_PENDING_LEN];
    memset(rec, 0, sizeof(rec));
    WriteLE32(rec + 0, (uint32_t)next_height);
    WriteLE32(rec + 4, (uint32_t)frontier_at_start);
    memcpy(rec + 8, lineage->data, 32);
    memcpy(rec + 40, set_digest, 32);
    size_t len = COIN_BACKFILL_SCAN_REC_BASE_LEN;
    if (clean && pending_spent)
        LOG_FAIL("stage_repair",
                 "[coin_backfill] scan record store: clean+pending h=%d",
                 hole_height);
    if (clean) {
        if (!top_hash)
            LOG_FAIL("stage_repair",
                     "[coin_backfill] scan record store: CLEAN without "
                     "top_hash h=%d", hole_height);
        memcpy(rec + 72, top_hash->data, 32);
        rec[COIN_BACKFILL_SCAN_REC_CLEAN_LEN - 1] = 1;
        len = COIN_BACKFILL_SCAN_REC_CLEAN_LEN;
    } else if (pending_spent) {
        if (!spender_txid || spent_height < 0)
            LOG_FAIL("stage_repair",
                     "[coin_backfill] scan record store: bad pending spend "
                     "h=%d height=%d", hole_height, (int)spent_height);
        WriteLE32(rec + 72, (uint32_t)spent_height);
        memcpy(rec + 76, spender_txid, 32);
        rec[COIN_BACKFILL_SCAN_REC_PENDING_LEN - 1] = 2;
        len = COIN_BACKFILL_SCAN_REC_PENDING_LEN;
    }
    if (!repair_marker_note(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                            hole_height, hole_hash->data, rec, len))
        LOG_FAIL("stage_repair",
                 "[coin_backfill] scan record write failed h=%d next=%d",
                 hole_height, next_height);
    return true;
}

/* ── Scan internals ──────────────────────────────────────────────── */

/* Active-chain hash at floor-1, the lineage seed. Reads the full block via
 * the hash-verified reader (the io seam exposes no header-only read; one
 * extra body read per scan start/restart is fine). */
static bool scan_seed_lineage(const struct coin_backfill_io *io,
                              int floor_height, struct uint256 *out_seed)
{
    struct block blk;
    struct uint256 hash;
    block_init(&blk);
    bool ok = io->read_block(io->user, floor_height - 1, &blk, &hash);
    block_free(&blk);
    if (!ok)
        LOG_FAIL("stage_repair",
                 "[coin_backfill] scan seed unreadable h=%d (floor-1)",
                 floor_height - 1);
    *out_seed = hash;
    return true;
}

/* Binary search of prevout in the sorted index. Returns set index or -1. */
static int set_lookup(const struct coin_backfill_outpoint *set,
                      const uint8_t *idx, size_t n,
                      const struct outpoint *prevout)
{
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const struct coin_backfill_outpoint *o = &set[idx[mid]];
        int r = memcmp(o->txid, prevout->hash.data, 32);
        if (r == 0)
            r = o->vout < prevout->n ? -1 : (o->vout > prevout->n ? 1 : 0);
        if (r == 0)
            return (int)idx[mid];
        if (r < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return -1;  // raw-return-ok:not-found-sentinel
}

/* True iff any input of any tx in blk spends a member of the set; fills the
 * spender's (recomputed-at-deserialize) txid. Null prevouts (coinbase) are
 * skipped. */
static bool block_spends_set(const struct block *blk,
                             const struct coin_backfill_outpoint *set,
                             const uint8_t *idx, size_t n,
                             uint8_t out_spender_txid[32])
{
    for (size_t t = 0; t < blk->num_vtx; t++) {
        const struct transaction *tx = &blk->vtx[t];
        for (size_t i = 0; i < tx->num_vin; i++) {
            const struct outpoint *po = &tx->vin[i].prevout;
            if (outpoint_is_null(po))
                continue;
            if (set_lookup(set, idx, n, po) >= 0) {
                memcpy(out_spender_txid, tx->hash.data, 32);
                return true;
            }
        }
    }
    return false;
}

/* Prev-link break (or terminal hash mismatch): discard the record, re-seed
 * at floor-1, persist a fresh floor record, report CHAIN_REBOUND. Bounded:
 * each restart requires an actual lineage break (a reorg event); refusal
 * markers upstream stop rescans for terminal refusals. */
static enum coin_backfill_scan_verdict scan_restart_from_floor(
    struct sqlite3 *db, const struct coin_backfill_io *io,
    int hole_height, const struct uint256 *hole_hash,
    int floor_height, int32_t frontier_at_start,
    const uint8_t set_digest[32], const char *reason, int at_height,
    int *out_next_height)
{
    LOG_WARN("stage_repair",
             "[coin_backfill] scan chain_rebound hole=%d at h=%d (%s): "
             "discarding record, restarting from floor=%d",
             hole_height, at_height, reason, floor_height);
    if (!repair_marker_forget(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                              hole_height, hole_hash->data)) {
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan record delete failed h=%d", hole_height);
        return COIN_SCAN_GAP;
    }
    struct uint256 seed;
    if (!scan_seed_lineage(io, floor_height, &seed)) {
        /* Seed block itself unreadable — surfaces as a gap at floor-1. */
        *out_next_height = floor_height;
        return COIN_SCAN_GAP;
    }
    if (!scan_record_store(db, hole_height, hole_hash, floor_height,
                           frontier_at_start, &seed, set_digest, false, NULL,
                           false, -1, NULL))
        return COIN_SCAN_GAP; /* logged in helper */
    *out_next_height = floor_height;
    return COIN_SCAN_CHAIN_REBOUND;
}

enum coin_scan_action {
    COIN_SCAN_ACT_LOG_NULL = 0,
    COIN_SCAN_ACT_LOG_BAD_SET,
    COIN_SCAN_ACT_LOG_BOUNDS,
    COIN_SCAN_ACT_LOG_WINDOW,
    COIN_SCAN_ACT_LOG_TABLES,
    COIN_SCAN_ACT_RETURN_GAP,
    COIN_SCAN_ACT_LOG_STALE,
    COIN_SCAN_ACT_RETURN_CLEAN,
    COIN_SCAN_ACT_LOG_SEEDED,
    COIN_SCAN_ACT_WALK,
    COIN_SCAN_ACT_LOG_CKPT_NOTOP,
    COIN_SCAN_ACT_LOG_PROGRESS,
    COIN_SCAN_ACT_LOG_GAP,
    COIN_SCAN_ACT_RETURN_REBOUND,
    COIN_SCAN_ACT_LOG_SPEND_FOUND,
    COIN_SCAN_ACT_LOG_NO_TOP,
    COIN_SCAN_ACT_LOG_DELETE_FAIL,
    COIN_SCAN_ACT_LOG_SPENT,
    COIN_SCAN_ACT_LOG_CLEAN,
    COIN_SCAN_ACT_COUNT
};

/* `&&label` is an address, not a branch. The complexity lexer counts the
 * adjacent '&' characters, so the table lives in this macro and the LOG_*
 * calls stay in coin_backfill_scan_step (those macros print __func__). */
#define COIN_SCAN_LABELS \
    &&coin_scan_log_null, \
    &&coin_scan_log_bad_set, \
    &&coin_scan_log_bounds, \
    &&coin_scan_log_window, \
    &&coin_scan_log_tables, \
    &&coin_scan_return_gap, \
    &&coin_scan_log_stale, \
    &&coin_scan_return_clean, \
    &&coin_scan_log_seeded, \
    &&coin_scan_at_walk, \
    &&coin_scan_log_ckpt_notop, \
    &&coin_scan_log_progress, \
    &&coin_scan_log_gap, \
    &&coin_scan_return_rebound, \
    &&coin_scan_log_spend_found, \
    &&coin_scan_log_no_top, \
    &&coin_scan_log_delete_fail, \
    &&coin_scan_log_spent, \
    &&coin_scan_log_clean

struct coin_scan_walk {
    struct sqlite3 *db;
    const struct coin_backfill_io *io;
    int hole_height;
    const struct uint256 *hole_hash;
    const struct coin_backfill_outpoint *set;
    size_t n;
    int floor_height;
    int top_height;
    int frontier_at_start;
    int max_blocks;
    int64_t max_wall_ms;
    int *out_next_height;
    int *out_spent_height;
    uint8_t *out_spender_txid;
    uint8_t set_digest[32];
    uint8_t sorted_idx[COIN_BACKFILL_MAX_OUTPOINTS];
    struct coin_backfill_scan_record rec;
    int digest_ok;
    int next;
    struct uint256 lineage;
    bool pending_spent;
    int32_t pending_spent_height;
    uint8_t pending_spender[32];
    struct uint256 top_hash;
    bool have_top;
    int64_t start_ns;
    int blocks_done;
    int h;
    struct block blk;
    struct uint256 block_hash;
    int32_t persist_next;
    struct uint256 persist_hash;
    enum coin_backfill_scan_verdict rebound_verdict;
};

static bool coin_scan_inputs_missing(struct sqlite3 *db,
                                    const struct coin_backfill_io *io,
                                    const struct uint256 *hole_hash,
                                    const struct coin_backfill_outpoint *set,
                                    int *out_next_height,
                                    int *out_spent_height,
                                    uint8_t *out_spender_txid)
{
    return !db || !io || !io->read_block || !hole_hash || !set ||
           !out_next_height || !out_spent_height || !out_spender_txid;
}

static bool coin_scan_set_size_rejected(size_t n)
{
    return n == 0 || n > COIN_BACKFILL_MAX_OUTPOINTS;
}

static bool coin_scan_bounds_inconsistent(int floor_height, int top_height,
                                         int frontier_at_start,
                                         int hole_height)
{
    return floor_height < 1 || floor_height > top_height ||
           top_height != frontier_at_start - 1 ||
           hole_height < frontier_at_start;
}

static bool coin_scan_window_over_budget(int max_blocks, int hole_height,
                                        int frontier_at_start)
{
    return max_blocks > 0 &&
           hole_height - frontier_at_start + 1 > max_blocks;
}

static bool coin_scan_tables_unready(struct sqlite3 *db)
{
    if (!progress_meta_table_ensure(db))
        return true;
    return !repair_marker_table_ensure(db);
}

static bool coin_scan_resume_range_ok(const struct coin_backfill_scan_record *rec,
                                     int floor_height, int hole_height,
                                     int top_height)
{
    return rec->next_height >= floor_height &&
           (rec->clean ? rec->next_height == hole_height + 1
                       : (rec->pending_spent
                              ? rec->next_height <= hole_height
                              : rec->next_height <= top_height + 1));
}

static bool coin_scan_resume_pending_ok(const struct coin_backfill_scan_record *rec,
                                       int floor_height, int top_height)
{
    return !rec->pending_spent ||
           (rec->spent_height >= floor_height &&
            rec->spent_height <= top_height);
}

static void coin_scan_arm_walk(struct coin_scan_walk *r)
{
    /* Persisted-next invariant: next <= frontier (= top+1). When resuming
     * exactly at the frontier, the lineage IS the hash at top_height. */
    uint256_set_null(&r->top_hash);
    r->have_top = false;
    if (r->next == r->top_height + 1) {
        r->top_hash = r->lineage;
        r->have_top = true;
    }
}

static enum coin_scan_action coin_scan_seed_fresh(struct coin_scan_walk *r)
{
    if (!scan_seed_lineage(r->io, r->floor_height, &r->lineage)) {
        *r->out_next_height = r->floor_height;
        return COIN_SCAN_ACT_RETURN_GAP; /* logged in helper */
    }
    r->next = r->floor_height;
    return COIN_SCAN_ACT_LOG_SEEDED;
}

static enum coin_scan_action coin_scan_apply_resume(struct coin_scan_walk *r)
{
    bool digest_ok = memcmp(r->rec.set_digest, r->set_digest, 32) == 0;
    bool frontier_ok = r->rec.frontier_at_start == r->frontier_at_start;
    bool range_ok = coin_scan_resume_range_ok(&r->rec, r->floor_height,
                                              r->hole_height, r->top_height);
    bool pending_ok = coin_scan_resume_pending_ok(&r->rec, r->floor_height,
                                                 r->top_height);
    r->digest_ok = digest_ok;
    if (!digest_ok || !frontier_ok || !range_ok || !pending_ok) {
        /* Design: digest/frontier mismatch on resume → restart from
         * floor. The fresh-start persist below overwrites the record. */
        return COIN_SCAN_ACT_LOG_STALE;
    }
    if (r->rec.clean) {
        /* Already proven; the insert tx re-binds to the insert-time
         * active chain (G10), so returning without rescanning is safe
         * and bounded. */
        *r->out_next_height = r->rec.next_height;
        return COIN_SCAN_ACT_RETURN_CLEAN;
    }
    r->next = r->rec.next_height;
    memcpy(r->lineage.data, r->rec.last_scanned_hash, 32);
    if (r->rec.pending_spent && pending_ok) {
        r->pending_spent = true;
        r->pending_spent_height = r->rec.spent_height;
        memcpy(r->pending_spender, r->rec.spender_txid, 32);
    }
    coin_scan_arm_walk(r);
    return COIN_SCAN_ACT_WALK;
}

static enum coin_scan_action coin_scan_open(struct coin_scan_walk *r)
{
    if (coin_scan_inputs_missing(r->db, r->io, r->hole_hash, r->set,
                                 r->out_next_height, r->out_spent_height,
                                 r->out_spender_txid))
        return COIN_SCAN_ACT_LOG_NULL;
    *r->out_next_height = r->floor_height;
    *r->out_spent_height = -1;
    memset(r->out_spender_txid, 0, 32);
    if (coin_scan_set_size_rejected(r->n))
        return COIN_SCAN_ACT_LOG_BAD_SET;
    if (coin_scan_bounds_inconsistent(r->floor_height, r->top_height,
                                      r->frontier_at_start, r->hole_height))
        return COIN_SCAN_ACT_LOG_BOUNDS;
    /* TG-F1 guard: the terminal window [frontier..H] must complete in ONE
     * chunk — a mid-window checkpoint clamps persist_next back to the
     * frontier (the record format has no pre-CLEAN top_hash slot), so a
     * window larger than max_blocks would pin next at the frontier forever:
     * SCANNING on every tick, claiming the dispatcher, never paging. Refuse
     * loudly instead of livelocking. */
    if (coin_scan_window_over_budget(r->max_blocks, r->hole_height,
                                     r->frontier_at_start))
        return COIN_SCAN_ACT_LOG_WINDOW;
    if (coin_scan_tables_unready(r->db))
        return COIN_SCAN_ACT_LOG_TABLES;
    if (!coin_backfill_scan_set_digest(r->set, r->n, r->set_digest))
        return COIN_SCAN_ACT_RETURN_GAP; /* logged in helper */
    sort_set_indices(r->set, r->n, r->sorted_idx);

    /* ── Resume or seed ──────────────────────────────────────────── */
    bool found = false;
    if (!coin_backfill_scan_record_load(r->db, r->hole_height, r->hole_hash,
                                        &r->rec, &found))
        return COIN_SCAN_ACT_RETURN_GAP; /* logged in helper */

    r->next = r->floor_height;
    uint256_set_null(&r->lineage);
    r->pending_spent = false;
    r->pending_spent_height = -1;
    memset(r->pending_spender, 0, 32);
    if (found)
        return coin_scan_apply_resume(r);
    return coin_scan_seed_fresh(r);
}

static bool coin_scan_chunk_budget_spent(const struct coin_scan_walk *r)
{
    bool over_blocks = r->max_blocks > 0 && r->blocks_done >= r->max_blocks;
    bool over_wall =
        r->max_wall_ms > 0 &&
        clock_now_monotonic_ns() - r->start_ns >= r->max_wall_ms * 1000000LL;
    return over_blocks || over_wall;
}

static void coin_scan_checkpoint_cursor(const struct coin_scan_walk *r,
                                       int32_t *persist_next,
                                       const struct uint256 **pl)
{
    *persist_next = r->h <= r->top_height ? r->h : r->top_height + 1;
    *pl = r->h <= r->top_height ? &r->lineage : &r->top_hash;
    if (r->pending_spent) {
        *persist_next = r->h;
        *pl = &r->lineage;
    }
}

static bool coin_scan_store_progress(const struct coin_scan_walk *r,
                                    int32_t persist_next,
                                    const struct uint256 *pl)
{
    return scan_record_store(r->db, r->hole_height, r->hole_hash, persist_next,
                             r->frontier_at_start, pl, r->set_digest, false,
                             NULL, r->pending_spent, r->pending_spent_height,
                             r->pending_spent ? r->pending_spender : NULL);
}

static enum coin_scan_action coin_scan_write_checkpoint(struct coin_scan_walk *r)
{
    /* Checkpoint. A clean/no-spend candidate clamps terminal-window
     * checkpoints back to the frontier so top_hash stays recoverable.
     * A pending-spend candidate persists its own lineage instead; it
     * will never be consumed by the insert path. */
    int32_t persist_next;
    const struct uint256 *pl;
    coin_scan_checkpoint_cursor(r, &persist_next, &pl);
    if (!r->pending_spent && r->h > r->top_height && !r->have_top)
        return COIN_SCAN_ACT_LOG_CKPT_NOTOP;
    if (!coin_scan_store_progress(r, persist_next, pl))
        return COIN_SCAN_ACT_RETURN_GAP; /* logged in helper */
    r->persist_next = persist_next;
    r->persist_hash = *pl;
    return COIN_SCAN_ACT_LOG_PROGRESS;
}

static enum coin_scan_action coin_scan_note_unreadable(struct coin_scan_walk *r)
{
    block_free(&r->blk);
    int32_t persist_next;
    const struct uint256 *pl;
    coin_scan_checkpoint_cursor(r, &persist_next, &pl);
    if (r->h <= r->top_height || r->have_top || r->pending_spent)
        (void)coin_scan_store_progress(r, persist_next, pl); /* failure logged */
    return COIN_SCAN_ACT_LOG_GAP;
}

static bool coin_scan_capture_spend(struct coin_scan_walk *r)
{
    bool in_window = !r->pending_spent && r->h <= r->top_height;
    if (!in_window)
        return false;
    bool hit = block_spends_set(&r->blk, r->set, r->sorted_idx, r->n,
                                r->out_spender_txid);
    if (hit) {
        r->pending_spent = true;
        r->pending_spent_height = r->h;
        memcpy(r->pending_spender, r->out_spender_txid, 32);
    }
    return hit;
}

static void coin_scan_advance_linked_block(struct coin_scan_walk *r)
{
    r->lineage = r->block_hash;
    block_free(&r->blk);
    if (r->h == r->top_height) {
        r->top_hash = r->lineage;
        r->have_top = true;
    }
    r->blocks_done++;
    r->h++;
}

static enum coin_scan_action coin_scan_publish_spend(struct coin_scan_walk *r)
{
    memcpy(r->out_spender_txid, r->pending_spender, 32);
    *r->out_spent_height = r->pending_spent_height;
    *r->out_next_height = r->pending_spent_height;
    return COIN_SCAN_ACT_LOG_SPENT;
}

static enum coin_scan_action coin_scan_forget_on_spend(struct coin_scan_walk *r)
{
    if (!repair_marker_forget(r->db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                              r->hole_height, r->hole_hash->data))
        return COIN_SCAN_ACT_LOG_DELETE_FAIL;
    return coin_scan_publish_spend(r);
}

static enum coin_scan_action coin_scan_bind_terminal(struct coin_scan_walk *r)
{
    /* ── Terminal linkage — the walk ended at H; lineage == hash(H) ── */
    if (uint256_cmp(&r->lineage, r->hole_hash) != 0) {
        /* The prev-linked active-chain walk does not end at the hole row's
         * hash: the hole block itself was reorged (or the row is stale).
         * Not CLEAN — restart; G3 upstream refuses a permanently stale
         * hole row. */
        r->rebound_verdict = scan_restart_from_floor(
            r->db, r->io, r->hole_height, r->hole_hash, r->floor_height,
            r->frontier_at_start, r->set_digest,
            "terminal hash(H) != hole hash", r->hole_height,
            r->out_next_height);
        return COIN_SCAN_ACT_RETURN_REBOUND;
    }
    if (!r->pending_spent && !r->have_top)
        return COIN_SCAN_ACT_LOG_NO_TOP;
    if (r->pending_spent)
        return coin_scan_forget_on_spend(r);
    if (!scan_record_store(r->db, r->hole_height, r->hole_hash,
                           r->hole_height + 1, r->frontier_at_start,
                           &r->lineage, r->set_digest, true, &r->top_hash,
                           false, -1, NULL))
        return COIN_SCAN_ACT_RETURN_GAP; /* logged in helper */
    return COIN_SCAN_ACT_LOG_CLEAN;
}

static enum coin_scan_action coin_scan_walk_blocks(struct coin_scan_walk *r)
{
    /* ── Chunk loop — prev-link EVERY block before processing it ──── */
    for (;;) {
        if (r->h > r->hole_height)
            return coin_scan_bind_terminal(r);
        if (coin_scan_chunk_budget_spent(r))
            return coin_scan_write_checkpoint(r);
        block_init(&r->blk);
        if (!r->io->read_block(r->io->user, r->h, &r->blk, &r->block_hash))
            return coin_scan_note_unreadable(r);
        if (uint256_cmp(&r->blk.header.hashPrevBlock, &r->lineage) != 0) {
            block_free(&r->blk);
            r->rebound_verdict = scan_restart_from_floor(
                r->db, r->io, r->hole_height, r->hole_hash, r->floor_height,
                r->frontier_at_start, r->set_digest, "prev-link mismatch",
                r->h, r->out_next_height);
            return COIN_SCAN_ACT_RETURN_REBOUND;
        }
        if (coin_scan_capture_spend(r))
            return COIN_SCAN_ACT_LOG_SPEND_FOUND;
        coin_scan_advance_linked_block(r);
    }
}

enum coin_backfill_scan_verdict coin_backfill_scan_step(
    struct sqlite3 *db, struct main_state *ms, const struct coin_backfill_io *io,
    int hole_height, const struct uint256 *hole_hash,
    const struct coin_backfill_outpoint *set, size_t n,
    int floor_height, int top_height, int frontier_at_start,
    int max_blocks, int64_t max_wall_ms,
    int *out_next_height, int *out_spent_height, uint8_t out_spender_txid[32])
{
    /* G0 — programming errors fail loudly; GAP maps to REFUSED_UNPROVABLE
     * upstream (the safe direction: refuse, never guess). `ms` is reserved
     * for signature parity with the repair entry points; all chain reads go
     * through the io seam. */
    (void)ms;
    struct coin_scan_walk run = {0};
    run.db = db;
    run.io = io;
    run.hole_height = hole_height;
    run.hole_hash = hole_hash;
    run.set = set;
    run.n = n;
    run.floor_height = floor_height;
    run.top_height = top_height;
    run.frontier_at_start = frontier_at_start;
    run.max_blocks = max_blocks;
    run.max_wall_ms = max_wall_ms;
    run.out_next_height = out_next_height;
    run.out_spent_height = out_spent_height;
    run.out_spender_txid = out_spender_txid;

    enum coin_scan_action act = coin_scan_open(&run);
    void *const labels[] = { COIN_SCAN_LABELS };
    _Static_assert(sizeof labels / sizeof labels[0] == COIN_SCAN_ACT_COUNT,
                   "coin scan action labels");
    goto *labels[act];

coin_scan_log_null:
    LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
               "[coin_backfill] scan: NULL input");
coin_scan_log_bad_set:
    LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
               "[coin_backfill] scan: bad set size n=%zu", n);
coin_scan_log_bounds:
    LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
               "[coin_backfill] scan: inconsistent bounds floor=%d "
               "top=%d frontier=%d hole=%d",
               floor_height, top_height, frontier_at_start, hole_height);
coin_scan_log_window:
    LOG_RETURN(COIN_SCAN_WINDOW_OVER_BUDGET, "stage_repair",
               "[coin_backfill] scan terminal window [%d..%d] (%d blocks)"
               " exceeds chunk budget max_blocks=%d — refusing (would "
               "livelock at the frontier clamp)",
               frontier_at_start, hole_height,
               hole_height - frontier_at_start + 1, max_blocks);
coin_scan_log_tables:
    LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
               "[coin_backfill] scan: table ensure failed");
coin_scan_return_gap:
    return COIN_SCAN_GAP;
coin_scan_log_stale:
    {
        int digest_ok = run.digest_ok;
        struct coin_backfill_scan_record rec = run.rec;
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan record stale hole=%d "
                 "(digest_ok=%d frontier=%d/%d next=%d): restart from "
                 "floor=%d",
                 hole_height, digest_ok, rec.frontier_at_start,
                 frontier_at_start, rec.next_height, floor_height);
    }
    act = coin_scan_seed_fresh(&run);
    goto *labels[act];
coin_scan_return_clean:
    return COIN_SCAN_CLEAN;
coin_scan_log_seeded:
    {
        char seed_hex[65];
        uint256_get_hex(&run.lineage, seed_hex);
        LOG_INFO("stage_repair",
                 "[coin_backfill] scan seeded hole=%d floor=%d top=%d "
                 "lineage=%.8s n=%zu",
                 hole_height, floor_height, top_height, seed_hex, n);
    }
    coin_scan_arm_walk(&run);
    goto coin_scan_at_walk;
coin_scan_at_walk:
    run.start_ns = clock_now_monotonic_ns();
    run.blocks_done = 0;
    run.h = run.next;
    act = coin_scan_walk_blocks(&run);
    goto *labels[act];
coin_scan_log_ckpt_notop:
    {
        int h = run.h;
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan checkpoint without top "
                   "hash h=%d (programming error)", h);
    }
coin_scan_log_progress:
    {
        int32_t persist_next = run.persist_next;
        char lin_hex[65];
        int blocks_done = run.blocks_done;
        uint256_get_hex(&run.persist_hash, lin_hex);
        LOG_INFO("stage_repair",
                 "[coin_backfill] scan progress hole=%d next=%d top=%d "
                 "lineage=%.8s blocks=%d",
                 hole_height, persist_next, top_height, lin_hex,
                 blocks_done);
        *out_next_height = persist_next;
    }
    return COIN_SCAN_IN_PROGRESS;
coin_scan_log_gap:
    {
        int h = run.h;
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan gap: block unreadable h=%d "
                 "hole=%d (deep body missing — fetch via rebuild_recent "
                 "/ -cold-import)",
                 h, hole_height);
        *out_next_height = h;
    }
    return COIN_SCAN_GAP;
coin_scan_return_rebound:
    return run.rebound_verdict;
coin_scan_log_spend_found:
    {
        int h = run.h;
        char sp_hex[65];
        struct uint256 sp;
        memcpy(sp.data, run.pending_spender, 32);
        uint256_get_hex(&sp, sp_hex);
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan SPEND FOUND hole=%d h=%d "
                 "spender=%s — deferring refusal until terminal linkage",
                 hole_height, h, sp_hex);
    }
    coin_scan_advance_linked_block(&run);
    act = coin_scan_walk_blocks(&run);
    goto *labels[act];
coin_scan_log_no_top:
    LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
               "[coin_backfill] scan finished without top hash hole=%d "
               "(programming error)", hole_height);
coin_scan_log_delete_fail:
    LOG_WARN("stage_repair",
             "[coin_backfill] scan record delete failed h=%d",
             hole_height);
    act = coin_scan_publish_spend(&run);
    goto *labels[act];
coin_scan_log_spent:
    {
        int32_t pending_spent_height = run.pending_spent_height;
        char sp_hex[65];
        struct uint256 sp;
        memcpy(sp.data, run.pending_spender, 32);
        uint256_get_hex(&sp, sp_hex);
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan SPEND CONFIRMED hole=%d h=%d "
                 "spender=%s after terminal linkage",
                 hole_height, (int)pending_spent_height, sp_hex);
    }
    return COIN_SCAN_SPENT_FOUND;
coin_scan_log_clean:
    {
        struct uint256 top_hash = run.top_hash;
        char top_hex[65];
        char hole_hex[65];
        uint256_get_hex(&top_hash, top_hex);
        uint256_get_hex(hole_hash, hole_hex);
        LOG_INFO("stage_repair",
                 "[coin_backfill] scan CLEAN hole=%d hash=%.8s: no spend in "
                 "[%d..%d], terminal linkage [%d..%d] bound, top_hash=%.8s",
                 hole_height, hole_hex, floor_height, top_height,
                 frontier_at_start, hole_height, top_hex);
        *out_next_height = hole_height + 1;
    }
    return COIN_SCAN_CLEAN;
}

