/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Loader: read the block_index.bin flat file and the LevelDB
 * block tree. The flat writer lives in block_index_flat_save.c, the SQLite
 * cache in block_index_sqlite_cache.c, and the post-load pointer-graph
 * derivation plus header-frontier promotion in block_index_post_load.c. */
// one-result-type-ok:height-sorted-predicate — block_index_ptrs_height_sorted
// is a pure total classification (already height-sorted, or not) over a
// caller-owned array; it never fails, so zcl_result would only relabel
// true/false as OK/ERR. Every other exported function in this file already
// returns struct zcl_result.

#include "platform/time_compat.h"
#include "platform/read_mapping.h"
#include "services/block_index_loader.h"
#include "block_index_flat_internal.h"
#include "services/block_index_flat_anchor.h"
#include "services/block_row_verify.h"
#include "services/block_index_integrity.h"
#include "services/chain_state_service.h"
#include "services/chain_tip.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/pow.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "storage/block_index_db.h"
#include "storage/sha3_sidecar_io.h"
#include "crypto/sha3.h"
#include "models/database.h"
#include "models/block.h"
#include "primitives/block.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif
#include <time.h>
#include <errno.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"

/* Flat rows omit the complete header, so their inner admission only rechecks
 * hash-versus-target. The outer SHA3 envelope and quarantine cap remain the
 * whole-artifact guards; failed rows are left for P2P to re-supply. */
static _Atomic int64_t g_flat_row_quarantined = 0;
static struct log_throttle g_flat_row_quarantine_log = LOG_THROTTLE_INIT;

static void flat_read_mapping_close(struct platform_read_mapping *mapping,
                                    int fd)
{
    platform_read_mapping_close(mapping);
    if (fd >= 0)
        close(fd);
}
int64_t block_index_flat_row_quarantined(void)
{
    return atomic_load_explicit(&g_flat_row_quarantined, memory_order_relaxed);
}

/* Record one dropped flat row: bump the process counter + this-load count,
 * name the (rate-limited) typed blocker, and emit a throttled WARN. Never
 * aborts the caller — the row is simply skipped. */
static void flat_quarantine_row(int32_t height, const uint8_t hash[32],
                                int64_t *bad_count)
{
    (*bad_count)++;
    atomic_fetch_add_explicit(&g_flat_row_quarantined, 1, memory_order_relaxed);

    char hex[65];
    struct uint256 hh;
    memcpy(hh.data, hash, 32);
    uint256_get_hex(&hh, hex);

    bool gross = (*bad_count > BLOCKS_HYDRATE_MAX_QUARANTINE);
    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "block_index.bin flat row quarantined height=%d hash=%s "
             "reason=high-hash (dropped from map; header sync + body_fetch "
             "re-supply)%s", height, hex,
             gross ? " — > outer bound, deferring to whole-file SHA3 + reindex"
                   : "");
    if (blocker_init(&rec, "block_index.flat_row_quarantine", "block_index",
                     gross ? BLOCKER_PERMANENT : BLOCKER_TRANSIENT, reason))
        (void)blocker_set(&rec);

    uint64_t reps = 0;
    if (log_throttle_should_emit(&g_flat_row_quarantine_log,
                                 (uint64_t)(uint32_t)height,
                                 platform_time_wall_unix(), 60, &reps))
        LOG_WARN("block_index_flat",
                 "flat row quarantined height=%d hash=%s reason=high-hash "
                 "(dropped, load continues; repeats=%llu)",
                 height, hex, (unsigned long long)reps);
}

/* ── Flat file format ────────────────────────────────────── */

/* ── Persisted-FAILED-bit trust policy ───────────────────── */

/* Process-monotonic tallies (see block_index_loader.h). The loaders run
 * single-threaded, but the dumpstate reader is a separate thread, so keep the
 * counters atomic. */
static _Atomic int64_t g_failed_bits_stripped = 0;
static _Atomic int64_t g_failed_bits_demoted = 0;

int64_t block_index_failed_bits_stripped(void)
{
    return atomic_load_explicit(&g_failed_bits_stripped, memory_order_relaxed);
}

int64_t block_index_failed_bits_demoted(void)
{
    return atomic_load_explicit(&g_failed_bits_demoted, memory_order_relaxed);
}

enum block_index_failure_trust_action
block_index_apply_persisted_failure_trust(struct block_index *pindex,
                                           int32_t checkpoint_height)
{
    if (!pindex)
        return BLOCK_FAILURE_TRUST_NONE;

    /* The revalidation-pending marker is runtime-derived, never trusted from
     * disk: clear any bit a prior save round-tripped so nStatus reflects only
     * THIS load's verdict. */
    unsigned int status = pindex->nStatus & ~(unsigned int)BLOCK_REVALIDATE_PENDING;

    if (!(status & (unsigned int)BLOCK_FAILED_MASK)) {
        pindex->nStatus = status; /* no persisted verdict; stale marker cleared */
        return BLOCK_FAILURE_TRUST_NONE;
    }

    /* A persisted BLOCK_FAILED_VALID/FAILED_CHILD is present. Clear the real
     * FAILED bits so a stale bit can never exclude this candidate from chain
     * selection before revalidation re-confirms it. */
    status &= ~(unsigned int)BLOCK_FAILED_MASK;

    if (pindex->nHeight <= checkpoint_height) {
        /* Below the baked ROM checkpoint: state is checkpoint-trusted and
         * re-derived from the baked keystone — never honor a persisted verdict,
         * and do not flag revalidation. */
        pindex->nStatus = status;
        atomic_fetch_add_explicit(&g_failed_bits_stripped, 1,
                                  memory_order_relaxed);
        return BLOCK_FAILURE_TRUST_STRIPPED;
    }

    /* Above the checkpoint: demote to a lazy revalidation candidate. The stages
     * re-run full validation when the fold reaches the block; a block that is
     * genuinely invalid gets its FAILED bit re-set by the connect path once
     * revalidation reaches and rejects it. */
    pindex->nStatus = status | (unsigned int)BLOCK_REVALIDATE_PENDING;
    atomic_fetch_add_explicit(&g_failed_bits_demoted, 1, memory_order_relaxed);
    return BLOCK_FAILURE_TRUST_DEMOTED;
}

/* Height comparator for forward-pass input. Non-static so the
 * throughput harness times the exact production comparison. */
int block_index_ptr_cmp_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;
    if (pa->nHeight < pb->nHeight) return -1; // raw-return-ok:qsort-comparator
    if (pa->nHeight > pb->nHeight) return 1;
    return 0;
}

/* True iff pointer array is already non-decreasing by height. The flat
 * loader collects in file order and genuine files are height-sorted by
 * the writer, so this lets it skip the qsort (see the call site). */
bool block_index_ptrs_height_sorted(struct block_index *const *arr, size_t n)
{
    for (size_t i = 1; i < n; i++) {
        if (arr[i - 1]->nHeight > arr[i]->nHeight)
            return false;
    }
    return true;
}

/* Sort a forward-pass pointer array by height, skipping the qsort when the
 * array is already ordered (see block_index_ptrs_height_sorted). Kept as
 * its own function, called unconditionally, so a caller's own branch count
 * never grows just because this call learned to skip redundant work. */
static void block_index_sort_forward_pass_input(
    struct block_index **arr, size_t n)
{
    if (!block_index_ptrs_height_sorted(arr, n))
        qsort(arr, n, sizeof(*arr), block_index_ptr_cmp_height);
}

/* ── save/load block_index_flat ──────────────────────────── */

struct zcl_result save_block_index_flat_identity(
    const char *datadir, struct main_state *ms,
    struct block_index_flat_identity *out)
{
    struct zcl_result result = block_index_flat_write_identity(
        datadir, ms, out);
    if (!result.ok)
        LOG_WARN("block_index_flat", "save_block_index_flat failed: %s",
                 result.message);
    return result;
}

void save_block_index_flat(const char *datadir, struct main_state *ms)
{
    ZCL_IGNORE_RESULT(save_block_index_flat_identity(datadir, ms, NULL),
                      "legacy shutdown wrapper logs write failure");
}

/* Boot-composition seam: see block_index_loader.h. */
void boot_persist_block_index(const char *datadir, struct main_state *ms)
{
    save_block_index_flat(datadir, ms);
}

/* Boot scan flat-save gate: see block_index_loader.h. */
void save_block_index_flat_if_mutated(const char *datadir,
                                      struct main_state *ms,
                                      int marked, int cleared)
{
    if ((marked > 0 || cleared > 0) && ms->map_block_index.size > 1000)
        save_block_index_flat(datadir, ms);
}

enum bil_flat_admit {
    BIL_FLAT_ADMIT_CLAIMED = 1,
    BIL_FLAT_ADMIT_DUPLICATE = 0,
    BIL_FLAT_ADMIT_FULL = -1,
};

/* Bulk-insert probe carrying the same cap block_map_insert_internal has:
 * the resident table can already occupy every bucket when an earlier rung
 * (rebuild-from-log) populated the map and then failed without clearing it,
 * and an uncapped probe over a full table with no duplicate never
 * terminates — the boot watchdog kills every retry and the node never
 * serves. CLAIMED writes the bucket (key, index, occupied, size++). */
static enum bil_flat_admit bil_flat_probe_claim(struct block_map *bm,
                                                const uint8_t hash[32],
                                                struct block_index *pindex)
{
    uint64_t h;
    memcpy(&h, hash, 8);
    size_t slot = h & (bm->capacity - 1);
    for (size_t probe = 0; probe < bm->capacity; probe++) {
        if (!bm->buckets[slot].occupied) {
            memcpy(bm->buckets[slot].hash.data, hash, 32);
            bm->buckets[slot].index = pindex;
            bm->buckets[slot].occupied = true;
            bm->size++;
            return BIL_FLAT_ADMIT_CLAIMED;
        }
        if (uint256_eq(&bm->buckets[slot].hash,
                       (const struct uint256 *)hash))
            return BIL_FLAT_ADMIT_DUPLICATE;
        slot = (slot + 1) & (bm->capacity - 1);
    }
    return BIL_FLAT_ADMIT_FULL;
}

/* Copy one flat row into its arena block_index (Option A: phashBlock points
 * at per-node storage; the bucket keeps its own key copy). */
static void bil_flat_fill_pindex(struct block_index *pindex,
                                 const struct block_index_flat *row)
{
    block_index_init(pindex);
    memcpy(pindex->hashBlock.data, row->hash, 32);
    pindex->phashBlock = &pindex->hashBlock;
    pindex->nHeight = row->height;
    pindex->nBits = row->n_bits;
    pindex->nTime = row->n_time;
    pindex->nVersion = row->n_version;
    pindex->nStatus = row->n_status;
    pindex->nFile = row->n_file;
    pindex->nDataPos = row->n_data_pos;
    pindex->nUndoPos = row->n_undo_pos;
    pindex->nTx = row->n_tx;
    pindex->nChainTx = row->n_chain_tx;
    memcpy(pindex->nChainWork.pn, row->chain_work, 32);
    pindex->nCachedBranchId = row->n_cached_branch_id;
    memcpy(pindex->hashFinalSaplingRoot.data, row->sapling_root, 32);
}

/* The front door owns mapping/fd cleanup, including every parse refusal. */
static struct zcl_result bil_flat_mapping_open(
    const char *datadir, int *fd_out, struct platform_read_mapping *mapping,
    size_t *file_size_out)
{
    *fd_out = -1;
    *file_size_out = 0;
    platform_read_mapping_init(mapping);
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    *fd_out = open(path, O_RDONLY);
    if (*fd_out < 0)
        return ZCL_ERR(-1, "block_index_flat: cannot open %s: %s",
                       path, strerror(errno));
    struct stat st;
    if (fstat(*fd_out, &st) != 0)
        return ZCL_ERR(-2, "block_index_flat: fstat failed: %s",
                       strerror(errno));
    if (st.st_size < 0 || (uintmax_t)st.st_size > SIZE_MAX)
        return ZCL_ERR(-3, "block_index_flat: invalid file size (%jd bytes)",
                       (intmax_t)st.st_size);
    *file_size_out = (size_t)st.st_size;
    if (*file_size_out < 8)
        return ZCL_ERR(-3, "block_index_flat: file too small (%zu bytes)",
                       *file_size_out);
    if (!platform_read_mapping_open(mapping, *fd_out, *file_size_out))
        return ZCL_ERR(-4, "block_index_flat: mapping failed (%zu bytes)",
                       *file_size_out);
    platform_read_mapping_advise_sequential(mapping);
    return ZCL_OK;
}

struct bil_flat_input {
    const struct block_index_flat *entries;
    uint32_t count;
    size_t expected;
    struct block_index_flat_identity identity;
    bool have_identity;
};

static struct zcl_result bil_flat_payload_read(
    const char *datadir, const uint8_t *data, size_t file_size,
    struct bil_flat_input *out)
{
    *out = (struct bil_flat_input){0};
    /* BIIE embeds a 48-byte integrity header; legacy ZCLI starts at zero. */
    uint64_t payload_off = 0;
    if (memcmp(data, BII_EMBEDDED_MAGIC, 4) == 0) {
        struct ssio_sidecar_header ehdr;
        int ev = bii_verify_embedded(datadir, &ehdr, &payload_off);
        if (ev != 0)
            return ZCL_ERR(-5, "block_index_flat: embedded integrity check "
                           "FAILED (verdict=%d) — refusing the body", ev);
        memcpy(out->identity.payload_sha3, ehdr.body_sha3, 32);
        out->identity.payload_size = ehdr.body_size;
        out->have_identity = true;
    }
    if (payload_off > file_size - 8)
        return ZCL_ERR(-6, "block_index_flat: payload offset %llu exceeds "
                       "mapped file (%zu bytes)",
                       (unsigned long long)payload_off, file_size);
    uint32_t magic, count;
    memcpy(&magic, data + payload_off, 4);
    memcpy(&count, data + payload_off + 4, 4);
    if (magic != 0x5A434C49)
        return ZCL_ERR(-6, "block_index_flat: bad payload magic 0x%08x "
                       "(expected 0x5A434C49)", magic);
    if (count > 10000000)
        return ZCL_ERR(-7, "block_index_flat: count %u too large (max 10M)", count);
    if (count == 0)
        return ZCL_ERR(-8, "block_index_flat: empty index (count 0)");
    size_t prefix = (size_t)payload_off + 8;
    if (count > (SIZE_MAX - prefix) / sizeof(struct block_index_flat))
        return ZCL_ERR(-9, "block_index_flat: row size overflow (%u entries)", count);
    size_t expected = prefix + (size_t)count * sizeof(struct block_index_flat);
    if (file_size < expected)
        return ZCL_ERR(-9, "block_index_flat: truncated — %zu bytes < %zu "
                       "expected (%u entries)", file_size, expected, count);
    out->entries = (const struct block_index_flat *)(data + prefix);
    out->count = count;
    out->expected = expected;
    return ZCL_OK;
}

/* No pprev or forward-pass work has run on refusal. Remove only this
 * attempt's arena pointers before releasing the arena; resident entries
 * retain their bytes and probe chains. Integer addresses avoid relational
 * comparisons between unrelated C objects. The caller checked arena size. */
static void bil_flat_rollback(struct block_map *bm,
                               struct block_index *arena, uint32_t count)
{
    uintptr_t start = (uintptr_t)arena;
    size_t bytes = (size_t)count * sizeof(*arena);
    for (size_t slot = 0; slot < bm->capacity; slot++) {
        uintptr_t index = (uintptr_t)bm->buckets[slot].index;
        if (bm->buckets[slot].occupied && index >= start &&
            index - start < bytes) {
            bm->buckets[slot] = (struct block_map_entry){0};
            bm->size--;
        }
    }
}

static uint32_t bil_selected_genesis_bits(const struct chain_params *cp)
{
    struct arith_uint256 limit;
    uint256_to_arith(&limit, &cp->consensus.powLimit);
    return arith_uint256_get_compact(&limit, false);
}

/* Legacy fresh loaders persisted mainnet bits on every network. Correct only
 * the compiled genesis identity; the ordinary PoW admission still runs. */
static uint32_t bil_flat_effective_bits(const struct block_index_flat *row,
                                      const struct chain_params *cp)
{
    static const uint8_t zero[32] = {0};
    if (cp && row->height == 0 &&
        memcmp(row->hash, cp->consensus.hashGenesisBlock.data, 32) == 0 &&
        memcmp(row->prev_hash, zero, 32) == 0)
        return bil_selected_genesis_bits(cp);
    return row->n_bits;
}

static struct zcl_result bil_flat_insert_rows(
    struct main_state *ms, const struct block_index_flat *entries,
    uint32_t count, struct block_index *arena)
{
    /* Bulk insert directly into the hash table; loader is single-threaded. */
    struct block_map *bm = &ms->map_block_index;
    /* Persisted-FAILED trust boundary: the baked ROM checkpoint height. Fetched
     * once; the per-entry reconcile below is O(1) and adds no extra scan. */
    int32_t ckpt_h = get_rom_state_checkpoint()->height;
    /* Chain params for the per-row PoW-target admission gate (header==NULL:
     * the flat cache stores no solution to hash-bind or re-check Equihash).
     * NULL is not expected this late in boot; if it is, the gate is skipped so
     * a missing params table cannot drop the whole index. */
    const struct chain_params *cp = chain_params_get();
    int64_t stripped_failed = 0, demoted_failed = 0;
    int64_t flat_bad_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        /* Feed the supervisor_backstop liveness marker every 64K entries so
         * this single-threaded pre-serving loop over ~3.1M entries is not
         * mistaken for a frozen supervisor sweep (util/boot_phase.h). */
        if ((i & 0xFFFF) == 0)
            boot_progress_note("block_index.flat_insert", i, count);
        if (uint256_is_null((const struct uint256 *)entries[i].hash))
            continue;

        /* Per-row inner admission gate (POINT 1 admission strength): re-check
         * the stored hash meets its own PoW target. A failing row is dropped
         * per-row (not inserted → header sync + body_fetch re-supply it) rather
         * than admitted below PoW strength. Skipped when cp is NULL (see above)
         * so it can never drop every row on a missing params table. */
        uint32_t effective_bits = bil_flat_effective_bits(&entries[i], cp);
        if (cp && block_row_verify(entries[i].hash, effective_bits, NULL,
                                   cp, false) != BLOCK_ROW_VERIFY_OK) {
            flat_quarantine_row(entries[i].height, entries[i].hash,
                                &flat_bad_count);
            continue;
        }

        struct block_index *pindex = &arena[i];
        enum bil_flat_admit admit =
            bil_flat_probe_claim(bm, entries[i].hash, pindex);
        if (admit == BIL_FLAT_ADMIT_FULL) {
            bil_flat_rollback(bm, arena, count);
            return ZCL_ERR(-11, "block_index_flat: hash table full "
                           "(capacity=%zu, resident=%zu) inserting row %u — "
                           "an earlier rung left no headroom; refusing "
                           "instead of probing forever",
                           bm->capacity, bm->size, i);
        }
        if (admit == BIL_FLAT_ADMIT_DUPLICATE)
            continue;
        bil_flat_fill_pindex(pindex, &entries[i]);
        pindex->nBits = effective_bits;

        /* Reconcile the persisted FAILED verdict against the ROM checkpoint
         * before the forward pass runs (so a stripped/demoted entry does not
         * re-propagate BLOCK_FAILED_CHILD to its descendants). */
        switch (block_index_apply_persisted_failure_trust(pindex, ckpt_h)) {
            case BLOCK_FAILURE_TRUST_STRIPPED: stripped_failed++; break;
            case BLOCK_FAILURE_TRUST_DEMOTED:  demoted_failed++;  break;
            case BLOCK_FAILURE_TRUST_NONE:     break;
        }
    }
    if (stripped_failed || demoted_failed)
        LOG_INFO("block_index_flat",
                 "block_index_flat: persisted-FAILED trust reconcile: "
                 "%lld stripped (<=ckpt h=%d), %lld demoted to revalidation "
                 "candidates (>ckpt)",
                 (long long)stripped_failed, ckpt_h, (long long)demoted_failed);

    return ZCL_OK;
}

static void bil_flat_link_rows(
    struct block_map *bm, const struct block_index_flat *entries,
    uint32_t count, struct block_index *arena)
{
    /* Link pprev HASH-ONLY: resolve each entry's parent by its stored
     * prev_hash, never by a height guess. The insert loop above has already
     * fully populated the block_map (linking is a separate second pass), so a
     * prev_hash that still misses means the parent genuinely is not loaded —
     * pprev then stays NULL (honest), which the ancestry-break / typed-blocker
     * machinery (utxo_recovery_block_ancestry_break + the scoped relink)
     * handles by design. A by-HEIGHT fallback would instead wire a WRONG parent
     * from a scrambled stored height, forming a pprev lasso — the ~103k-node
     * cycle the live-cure wedge traced to — that no height relabel can cure and
     * that the scoped relink can only fail-closed (cycle=1) refuse. The stored
     * hashPrev bytes are the sole authority; the SQLite-cache and node.db
     * hydrate loaders already link hash-only, and this brings the flat loader
     * in line. An all-zero prev_hash is genesis. Once the graph is acyclic, a
     * pure height-label scramble is curable by the scoped ancestry relink
     * (terminus-pinned to the compiled checkpoint), not by the loader. */
    for (uint32_t i = 0; i < count; i++) {
        if ((i & 0xFFFF) == 0)
            boot_progress_note("block_index.flat_link", i, count);
        struct block_index *pindex = &arena[i];
        bool has_prev = false;
        for (int pb = 0; pb < 32; pb++)
            if (entries[i].prev_hash[pb]) { has_prev = true; break; }
        if (has_prev) {
            struct uint256 prev;
            memcpy(prev.data, entries[i].prev_hash, 32);
            struct block_index *pp = block_map_find(bm, &prev);
            if (pp)
                pindex->pprev = pp;
            /* else: parent not loaded — leave pprev NULL (see above). */
        }
    }

}

static void bil_flat_forward_rows(
    struct block_index *arena, uint32_t count, struct block_index **sorted)
{
    /* Recompute every pointer-graph-derived field through the canonical
     * forward pass (nChainWork, nChainTx, skip links, cached branch id,
     * failed-child propagation) — the same helper the LevelDB loader and
     * the projection rebuild use. The flat file may carry stale values
     * for blocks saved mid-sync. The forward pass zeroes nChainTx
     * whenever an ancestor is header-only (pprev->nChainTx == 0), so
     * nChainTx > 0 means "every ancestor's tx count is known" — without
     * this, wrongly-eligible entries reach find_most_work_chain.
     * Inserted entries are marked by phashBlock != NULL (dropped and
     * duplicate arena slots never get it set).
     *
     * This pass ALWAYS runs (measured ~861ms on a 3.19M-entry index). The
     * former "trust-flat" fast-restart skip that trusted the flat's stored
     * derived fields was removed: it saved <1s but a stale binding (saved best
     * <= the coins/fold tip) left pindex_best_header pinned at the coins tip,
     * so chain_advance_coordinator saw local==best_header and the reducer drive
     * converged with unfolded on-disk bodies — a live wedge. Re-deriving from
     * the pointer graph is the canonical, wedge-proof path. */
    if (sorted) {
        size_t n = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (arena[i].phashBlock)
                sorted[n++] = &arena[i];
        }
        /* Genuine flat files are height-sorted by the writer and the arena
         * above preserves file order, so the collected array is already
         * the forward-pass order and qsort would be an identity
         * permutation at O(n log n) cost (~3M pointers on a full index).
         * block_index_sort_forward_pass_input skips it exactly then and
         * qsorts exactly otherwise. Skipping is behaviour-identical:
         * block_index_forward_pass derives every field from the
         * already-linked pprev (strictly lower height, so always
         * processed first in ANY height-sorted order), and equal-height
         * rows share no ancestry — their relative order cannot change any
         * output. A foreign/legacy unsorted file still takes the qsort,
         * bit for bit as before. */
        block_index_sort_forward_pass_input(sorted, n);
        block_index_forward_pass(sorted, n);
    } else {
        /* boot's later multi-pass nChainTx propagation still runs;
         * work/skip recompute is what we lose — log it. */
        LOG_WARN("block_index_flat", "block_index_flat: forward-pass alloc failed "
                 "(%u entries) — chain stats may be stale", count);
    }

}

static bool bil_flat_allocation_sizes_valid(size_t count)
{
    return count <= SIZE_MAX / sizeof(struct block_index) &&
           count <= SIZE_MAX / sizeof(struct block_index *);
}

struct zcl_result load_block_index_flat(const char *datadir, struct main_state *ms)
{
    /* A failed or legacy load cannot inherit a verified snapshot identity. */
    block_index_flat_identity_forget();
    int fd;
    size_t file_size;
    struct platform_read_mapping mapping;
    struct zcl_result result = bil_flat_mapping_open(datadir, &fd, &mapping,
                                                     &file_size);
    if (!result.ok) {
        flat_read_mapping_close(&mapping, fd);
        return result;
    }
    struct bil_flat_input input;
    result = bil_flat_payload_read(datadir, mapping.data, file_size, &input);
    if (!result.ok) {
        flat_read_mapping_close(&mapping, fd);
        return result;
    }
    uint32_t count = input.count;
    if (!bil_flat_allocation_sizes_valid(count)) {
        flat_read_mapping_close(&mapping, fd);
        return ZCL_ERR(-10, "block_index_flat: allocation size overflow (%u entries)",
                       count);
    }
    int64_t t0 = (int64_t)platform_time_wall_time_t();
    int64_t t0_ms = platform_time_monotonic_ms();
    if (!block_map_reserve(&ms->map_block_index, count)) {
        flat_read_mapping_close(&mapping, fd);
        return ZCL_ERR(-10, "block_index_flat: map reserve failed (%u entries)", count);
    }
    struct block_index *arena = zcl_calloc(count, sizeof(struct block_index), "block_index arena");
    if (!arena) {
        flat_read_mapping_close(&mapping, fd);
        return ZCL_ERR(-10, "block_index_flat: calloc failed for %u entries "
                       "(%zu bytes)", count,
                       (size_t)count * sizeof(struct block_index));
    }
    memset(arena, 0, count * sizeof(struct block_index)); /* pre-fault */
    void *release = arena;
    int64_t t_parse_ms = 0, t_fwd_ms = 0;
    result = bil_flat_insert_rows(ms, input.entries, count, arena);
    if (!result.ok) {
        goto finish;
    }
    bil_flat_link_rows(&ms->map_block_index, input.entries, count, arena);
    /* Old files end at expected; old readers ignore the new trailer. */
    if (file_size > input.expected) {
        struct zcl_result ar = block_index_flat_anchor_apply(
            ms, mapping.data + input.expected, file_size - input.expected);
        if (!ar.ok)
            LOG_WARN("block_index_flat", "%s", ar.message);
    }
    t_parse_ms = platform_time_monotonic_ms() - t0_ms;
    t_fwd_ms = platform_time_monotonic_ms();
    struct block_index **sorted =
        zcl_malloc((size_t)count * sizeof(*sorted), "flat forward pass");
    release = sorted; /* successful arena is retained by the map */
    bil_flat_forward_rows(arena, count, sorted);
finish:
    free(release);
    flat_read_mapping_close(&mapping, fd);
    if (!result.ok)
        return result;
    t_fwd_ms = platform_time_monotonic_ms() - t_fwd_ms;
    printf("[boot]   %-28s %lldms\n", "blkidx.flat_parse_insert",
           (long long)t_parse_ms);
    printf("[boot]   %-28s %lldms\n", "blkidx.flat_forward_pass",
           (long long)t_fwd_ms);
    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index_flat", "Block index flat: loaded %u entries in %llds",
             count, (long long)elapsed);
    if (input.have_identity) {
        input.identity.row_count = count;
        block_index_flat_identity_remember(datadir, &input.identity);
    }
    return result;
}

/* save_block_index_recent() / load_block_index_sqlite() — the SQLite
 * block_index_cache save/load, including its integrity envelope
 * (services/block_index_cache_envelope.h) AND the persisted-FAILED trust
 * reconcile (block_index_apply_persisted_failure_trust) — live in
 * block_index_sqlite_cache.c (E1 file-size split); both are declared in
 * services/block_index_loader.h. */

/* ── load_block_index (LevelDB + post-process) ──────────── */

static struct block_index *insert_block_index_cb(void *ctx_ptr,
                                                  const struct uint256 *hash)
{
    struct main_state *ms = (struct main_state *)ctx_ptr;
    return chainstate_insert_block_index(
        (struct chainstate *)ms, hash);
}

struct zcl_result load_block_index(struct main_state *ms,
                       const struct chain_params *params,
                       struct block_tree_db *btdb, bool btdb_open)
{
    if (btdb_open) {
        if (!block_tree_db_load_block_index_guts(btdb,
                                                  insert_block_index_cb, ms))
            return ZCL_ERR(-1, "load_block_index: LevelDB block-tree "
                           "deserialization failed (corrupt block tree db)");
    }

    /* Option A: ensure every node owns its hash in per-node storage and
     * phashBlock references it (not the reallocatable bucket array).
     * The inner loader loop and chainstate_insert_block_index already do
     * this at insert; this pass is a belt-and-suspenders re-seed that is
     * also safe under concurrent grow (it writes per-node storage, never
     * re-points into buckets). */
    {
        size_t iter = 0;
        struct block_index *pi;
        const struct uint256 *hash;
        while (block_map_next(&ms->map_block_index, &iter, &hash, &pi)) {
            if (pi && hash) {
                pi->hashBlock = *hash;
                pi->phashBlock = &pi->hashBlock;
            }
        }
    }

    if (ms->map_block_index.size == 0) {
        struct block_index *genesis = chainstate_insert_block_index(
            (struct chainstate *)ms,
            &params->consensus.hashGenesisBlock);
        if (genesis) {
            genesis->nHeight = 0;
            genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            genesis->nTx = 1;
            genesis->nChainTx = 1;
            genesis->nBits = bil_selected_genesis_bits(params);
            genesis->nChainWork = GetBlockProof(genesis);
            struct chain_state_rollback_authorization rollback_auth = {
                .source = CSR_ROLLBACK_SOURCE_RESTORE,
                .decision = POLICY_ALLOW,
                .from_height = active_chain_height(&ms->chain_active),
                .to_height = genesis->nHeight,
                .max_depth = INT64_MAX,
                .evidence_class = "block_index_loader_genesis_verified",
                .reason = "loader_init_genesis",
            };
            struct chain_state_commit commit = {
                .new_tip = genesis,
                .new_coins_best = *genesis->phashBlock,
                .expected_utxo_count = 0,
                .update_header_tip = true,
                .rollback_auth = &rollback_auth,
                .wallet_scan_height = -1,
                .reason = "loader_init_genesis",
            };
            enum csr_result rc = csr_commit_tip(csr_instance(), &commit);
            if (rc == CSR_OK) {
                return ZCL_OK;
            }
#ifdef ZCL_TESTING
            if (rc == CSR_REJECTED_NOT_INITIALIZED) {
                (void)chain_set_active_tip(ms, genesis, TIP_FROM_RESTORE,
                                      "loader_init_genesis_csr_uninit");
                ms->pindex_best_header = genesis;
                return ZCL_OK;
            }
#endif
            return ZCL_ERR(-3, "load_block_index: csr rejected genesis tip "
                           "commit (%s)", csr_result_name(rc));
        }
        return ZCL_OK;
    }

    /* Post-load: compute nChainWork, nChainTx, skip links */
    size_t count = ms->map_block_index.size;
    struct block_index **sorted = zcl_malloc(count * sizeof(struct block_index *), "block_index sorted load");
    if (!sorted)
        return ZCL_ERR(-2, "load_block_index: out of memory allocating %zu "
                       "sorted block_index pointers", count);

    size_t idx = 0;
    size_t iter = 0;
    struct block_index *pindex;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &pindex)) {
        if (pindex && idx < count)
            sorted[idx++] = pindex;
    }
    count = idx;

    qsort(sorted, count, sizeof(struct block_index *),
          block_index_ptr_cmp_height);

    block_index_forward_pass(sorted, count);

    /* THE LINCHPIN: make the header frontier real so active_chain_tip() is not
     * NULL over this just-loaded map and header sync anchors above genesis. */
    promote_best_header_after_load(ms, sorted, count);

    free(sorted);
    return ZCL_OK;
}
