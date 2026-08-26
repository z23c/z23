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
    if (!db || !io || !io->read_block || !hole_hash || !set ||
        !out_next_height || !out_spent_height || !out_spender_txid)
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan: NULL input");
    *out_next_height = floor_height;
    *out_spent_height = -1;
    memset(out_spender_txid, 0, 32);
    if (n == 0 || n > COIN_BACKFILL_MAX_OUTPOINTS)
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan: bad set size n=%zu", n);
    if (floor_height < 1 || floor_height > top_height ||
        top_height != frontier_at_start - 1 || hole_height < frontier_at_start)
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan: inconsistent bounds floor=%d "
                   "top=%d frontier=%d hole=%d",
                   floor_height, top_height, frontier_at_start, hole_height);

    /* TG-F1 guard: the terminal window [frontier..H] must complete in ONE
     * chunk — a mid-window checkpoint clamps persist_next back to the
     * frontier (the record format has no pre-CLEAN top_hash slot), so a
     * window larger than max_blocks would pin next at the frontier forever:
     * SCANNING on every tick, claiming the dispatcher, never paging. Refuse
     * loudly instead of livelocking. */
    if (max_blocks > 0 && hole_height - frontier_at_start + 1 > max_blocks)
        LOG_RETURN(COIN_SCAN_WINDOW_OVER_BUDGET, "stage_repair",
                   "[coin_backfill] scan terminal window [%d..%d] (%d blocks)"
                   " exceeds chunk budget max_blocks=%d — refusing (would "
                   "livelock at the frontier clamp)",
                   frontier_at_start, hole_height,
                   hole_height - frontier_at_start + 1, max_blocks);

    if (!progress_meta_table_ensure(db) || !repair_marker_table_ensure(db))
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan: table ensure failed");

    uint8_t set_digest[32];
    if (!coin_backfill_scan_set_digest(set, n, set_digest))
        return COIN_SCAN_GAP; /* logged in helper */
    uint8_t sorted_idx[COIN_BACKFILL_MAX_OUTPOINTS];
    sort_set_indices(set, n, sorted_idx);

    /* ── Resume or seed ──────────────────────────────────────────── */
    struct coin_backfill_scan_record rec;
    bool found = false;
    if (!coin_backfill_scan_record_load(db, hole_height, hole_hash, &rec,
                                        &found))
        return COIN_SCAN_GAP; /* logged in helper */

    int next = floor_height;
    struct uint256 lineage;
    uint256_set_null(&lineage);
    bool resumed = false;
    bool pending_spent = false;
    int32_t pending_spent_height = -1;
    uint8_t pending_spender_txid[32] = {0};

    if (found) {
        bool digest_ok = memcmp(rec.set_digest, set_digest, 32) == 0;
        bool frontier_ok = rec.frontier_at_start == frontier_at_start;
        bool range_ok =
            rec.next_height >= floor_height &&
            (rec.clean ? rec.next_height == hole_height + 1
                       : (rec.pending_spent
                              ? rec.next_height <= hole_height
                              : rec.next_height <= top_height + 1));
        bool pending_ok = !rec.pending_spent ||
                          (rec.spent_height >= floor_height &&
                           rec.spent_height <= top_height);
        if (!digest_ok || !frontier_ok || !range_ok || !pending_ok) {
            /* Design: digest/frontier mismatch on resume → restart from
             * floor. The fresh-start persist below overwrites the record. */
            LOG_WARN("stage_repair",
                     "[coin_backfill] scan record stale hole=%d "
                     "(digest_ok=%d frontier=%d/%d next=%d): restart from "
                     "floor=%d",
                     hole_height, digest_ok, rec.frontier_at_start,
                     frontier_at_start, rec.next_height, floor_height);
        } else if (rec.clean) {
            /* Already proven; the insert tx re-binds to the insert-time
             * active chain (G10), so returning without rescanning is safe
             * and bounded. */
            *out_next_height = rec.next_height;
            return COIN_SCAN_CLEAN;
        } else {
            next = rec.next_height;
            memcpy(lineage.data, rec.last_scanned_hash, 32);
            if (rec.pending_spent && pending_ok) {
                pending_spent = true;
                pending_spent_height = rec.spent_height;
                memcpy(pending_spender_txid, rec.spender_txid, 32);
            }
            resumed = true;
        }
    }
    if (!resumed) {
        if (!scan_seed_lineage(io, floor_height, &lineage)) {
            *out_next_height = floor_height;
            return COIN_SCAN_GAP; /* logged in helper */
        }
        next = floor_height;
        char seed_hex[65];
        uint256_get_hex(&lineage, seed_hex);
        LOG_INFO("stage_repair",
                 "[coin_backfill] scan seeded hole=%d floor=%d top=%d "
                 "lineage=%.8s n=%zu",
                 hole_height, floor_height, top_height, seed_hex, n);
    }

    /* Persisted-next invariant: next <= frontier (= top+1). When resuming
     * exactly at the frontier, the lineage IS the hash at top_height. */
    struct uint256 top_hash;
    uint256_set_null(&top_hash);
    bool have_top = false;
    if (next == top_height + 1) {
        top_hash = lineage;
        have_top = true;
    }

    /* ── Chunk loop — prev-link EVERY block before processing it ──── */
    int64_t start_ns = clock_now_monotonic_ns();
    int blocks_done = 0;
    struct block blk;

    for (int h = next; h <= hole_height; h++) {
        bool over_blocks = max_blocks > 0 && blocks_done >= max_blocks;
        bool over_wall =
            max_wall_ms > 0 &&
            clock_now_monotonic_ns() - start_ns >= max_wall_ms * 1000000LL;
        if (over_blocks || over_wall) {
            /* Checkpoint. A clean/no-spend candidate clamps terminal-window
             * checkpoints back to the frontier so top_hash stays recoverable.
             * A pending-spend candidate persists its own lineage instead; it
             * will never be consumed by the insert path. */
            int32_t persist_next = h <= top_height ? h : top_height + 1;
            const struct uint256 *pl = h <= top_height ? &lineage : &top_hash;
            if (pending_spent) {
                persist_next = h;
                pl = &lineage;
            }
            if (!pending_spent && h > top_height && !have_top)
                LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                           "[coin_backfill] scan checkpoint without top "
                           "hash h=%d (programming error)", h);
            if (!scan_record_store(db, hole_height, hole_hash, persist_next,
                                   frontier_at_start, pl, set_digest, false,
                                   NULL, pending_spent, pending_spent_height,
                                   pending_spent ? pending_spender_txid : NULL))
                return COIN_SCAN_GAP; /* logged in helper */
            char lin_hex[65];
            uint256_get_hex(pl, lin_hex);
            LOG_INFO("stage_repair",
                     "[coin_backfill] scan progress hole=%d next=%d top=%d "
                     "lineage=%.8s blocks=%d",
                     hole_height, persist_next, top_height, lin_hex,
                     blocks_done);
            *out_next_height = persist_next;
            return COIN_SCAN_IN_PROGRESS;
        }

        struct uint256 hash;
        block_init(&blk);
        if (!io->read_block(io->user, h, &blk, &hash)) {
            block_free(&blk);
            int32_t persist_next = h <= top_height ? h : top_height + 1;
            const struct uint256 *pl = h <= top_height ? &lineage : &top_hash;
            if (pending_spent) {
                persist_next = h;
                pl = &lineage;
            }
            if (h <= top_height || have_top || pending_spent)
                (void)scan_record_store(db, hole_height, hole_hash,
                                        persist_next, frontier_at_start, pl,
                                        set_digest, false, NULL, pending_spent,
                                        pending_spent_height,
                                        pending_spent ? pending_spender_txid
                                                      : NULL); /* failure logged */
            LOG_WARN("stage_repair",
                     "[coin_backfill] scan gap: block unreadable h=%d "
                     "hole=%d (deep body missing — fetch via rebuild_recent "
                     "/ -cold-import)",
                     h, hole_height);
            *out_next_height = h;
            return COIN_SCAN_GAP;
        }

        if (uint256_cmp(&blk.header.hashPrevBlock, &lineage) != 0) {
            block_free(&blk);
            return scan_restart_from_floor(db, io, hole_height, hole_hash,
                                           floor_height, frontier_at_start,
                                           set_digest, "prev-link mismatch",
                                           h, out_next_height);
        }

        if (!pending_spent && h <= top_height &&
            block_spends_set(&blk, set, sorted_idx, n, out_spender_txid)) {
            pending_spent = true;
            pending_spent_height = h;
            memcpy(pending_spender_txid, out_spender_txid, 32);
            char sp_hex[65];
            struct uint256 sp;
            memcpy(sp.data, pending_spender_txid, 32);
            uint256_get_hex(&sp, sp_hex);
            LOG_WARN("stage_repair",
                     "[coin_backfill] scan SPEND FOUND hole=%d h=%d "
                     "spender=%s — deferring refusal until terminal linkage",
                     hole_height, h, sp_hex);
        }

        lineage = hash;
        block_free(&blk);
        if (h == top_height) {
            top_hash = lineage;
            have_top = true;
        }
        blocks_done++;
    }

    /* ── Terminal linkage — the walk ended at H; lineage == hash(H) ── */
    if (uint256_cmp(&lineage, hole_hash) != 0) {
        /* The prev-linked active-chain walk does not end at the hole row's
         * hash: the hole block itself was reorged (or the row is stale).
         * Not CLEAN — restart; G3 upstream refuses a permanently stale
         * hole row. */
        return scan_restart_from_floor(db, io, hole_height, hole_hash,
                                       floor_height, frontier_at_start,
                                       set_digest,
                                       "terminal hash(H) != hole hash",
                                       hole_height, out_next_height);
    }
    if (!pending_spent && !have_top)
        LOG_RETURN(COIN_SCAN_GAP, "stage_repair",
                   "[coin_backfill] scan finished without top hash hole=%d "
                   "(programming error)", hole_height);

    if (pending_spent) {
        if (!repair_marker_forget(db, REPAIR_MARKER_KIND_COIN_BACKFILL_SCAN,
                                  hole_height, hole_hash->data))
            LOG_WARN("stage_repair",
                     "[coin_backfill] scan record delete failed h=%d",
                     hole_height);
        memcpy(out_spender_txid, pending_spender_txid, 32);
        *out_spent_height = pending_spent_height;
        *out_next_height = pending_spent_height;
        char sp_hex[65];
        struct uint256 sp;
        memcpy(sp.data, pending_spender_txid, 32);
        uint256_get_hex(&sp, sp_hex);
        LOG_WARN("stage_repair",
                 "[coin_backfill] scan SPEND CONFIRMED hole=%d h=%d "
                 "spender=%s after terminal linkage",
                 hole_height, (int)pending_spent_height, sp_hex);
        return COIN_SCAN_SPENT_FOUND;
    }

    if (!scan_record_store(db, hole_height, hole_hash, hole_height + 1,
                           frontier_at_start, &lineage, set_digest, true,
                           &top_hash, false, -1, NULL))
        return COIN_SCAN_GAP; /* logged in helper */

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
    return COIN_SCAN_CLEAN;
}
