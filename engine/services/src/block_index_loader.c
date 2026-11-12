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
#include "services/island_anchor.h"
#include "storage/blocks_mmap_reader.h"
#include "core/serialize.h"
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
#include <sys/mman.h>
#endif
#include <time.h>
#include <errno.h>
#include <sqlite3.h>

#include "util/ar_step_readonly.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "util/thread_registry.h"
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
 * serves. CLAIMED writes the key into the node and the bucket (index, size++). */
static enum bil_flat_admit bil_flat_probe_claim(struct block_map *bm,
                                                const uint8_t hash[32],
                                                struct block_index *pindex)
{
    uint64_t h;
    memcpy(&h, hash, 8);
    size_t slot = h & (bm->capacity - 1);
    for (size_t probe = 0; probe < bm->capacity; probe++) {
        if (!bm->buckets[slot].index) {
            /* The key lives in the node: write it before the claim so the
             * next probe that reaches this bucket can compare it. */
            memcpy(pindex->hashBlock.data, hash, 32);
            bm->buckets[slot].index = pindex;
            bm->size++;
            return BIL_FLAT_ADMIT_CLAIMED;
        }
        if (uint256_eq(&bm->buckets[slot].index->hashBlock,
                       (const struct uint256 *)hash))
            return BIL_FLAT_ADMIT_DUPLICATE;
        slot = (slot + 1) & (bm->capacity - 1);
    }
    return BIL_FLAT_ADMIT_FULL;
}

/* Copy one flat row into its arena block_index (Option A: phashBlock points
 * at per-node storage; the bucket key is that per-node hashBlock). */
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
        if (bm->buckets[slot].index && index >= start &&
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

static bool bil_genesis_metadata_valid(const struct block_index *genesis, uint32_t bits)
{
    struct arith_uint256 work = GetBlockProof(genesis);
    return genesis->nBits == bits && genesis->nTx == 1 && genesis->nChainTx == 1 &&
        (genesis->nStatus & BLOCK_FAILED_ANY_MASK) == 0 &&
        (genesis->nStatus & BLOCK_HAVE_DATA) != 0 &&
        (genesis->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_SCRIPTS &&
        !arith_uint256_is_zero(&work) && arith_uint256_compare(&genesis->nChainWork, &work) == 0;
}

bool block_index_initialize_genesis(struct block_index *genesis, const struct chain_params *params)
{
    if (!genesis || !params || !genesis->phashBlock || genesis->nHeight != 0 || genesis->pprev ||
        !uint256_eq(genesis->phashBlock, &params->consensus.hashGenesisBlock)) return false;
    uint32_t bits = bil_selected_genesis_bits(params);
    if (!genesis->nStatus && !genesis->nBits && !genesis->nTx && !genesis->nChainTx &&
        arith_uint256_is_zero(&genesis->nChainWork)) {
        genesis->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        genesis->nTx = 1; genesis->nChainTx = 1; genesis->nBits = bits;
        genesis->nChainWork = GetBlockProof(genesis);
    }
    return bil_genesis_metadata_valid(genesis, bits);
}

/* Legacy fresh loaders persisted mainnet bits on every network. Correct only
 * the compiled genesis identity; the ordinary PoW admission still runs. */
static uint32_t bil_effective_bits(int32_t height, const uint8_t hash[32],
                                   const uint8_t prev_hash[32], uint32_t n_bits,
                                   const struct chain_params *cp)
{
    static const uint8_t zero[32] = {0};
    if (cp && height == 0 &&
        memcmp(hash, cp->consensus.hashGenesisBlock.data, 32) == 0 &&
        memcmp(prev_hash, zero, 32) == 0)
        return bil_selected_genesis_bits(cp);
    return n_bits;
}

bool block_index_row_admissible(int32_t height, const uint8_t hash[32],
                           const uint8_t prev_hash[32], uint32_t n_bits,
                           const struct chain_params *cp, uint32_t *effective_bits)
{
    uint32_t bits = bil_effective_bits(height, hash, prev_hash, n_bits, cp);
    if (effective_bits)
        *effective_bits = bits;
    return !cp || block_row_verify(hash, bits, NULL, cp, false) ==
                      BLOCK_ROW_VERIFY_OK;
}

bool block_index_row_admit(int32_t height, const uint8_t hash[32],
                           const uint8_t prev_hash[32], uint32_t n_bits,
                           const struct chain_params *cp,
                           int64_t *bad_count, uint32_t *effective_bits)
{
    if (block_index_row_admissible(height, hash, prev_hash, n_bits, cp,
                                   effective_bits))
        return true;
    flat_quarantine_row(height, hash, bad_count);
    return false;
}

/* Rows already consumed by a pass are dropped from the file mapping in 64K-row
 * steps so the mapping and the arena are not both fully resident at the peak.
 * Both row passes read the mapping front to back; a dropped page that a later
 * pass touches faults back in from the file. */
struct bil_flat_release {
    const struct platform_read_mapping *mapping;
    const struct block_index_flat *entries;
    size_t released;
};

static void bil_flat_release_rows(struct bil_flat_release *rel, uint32_t next)
{
    size_t consumed = (size_t)((const uint8_t *)(rel->entries + next) -
                               rel->mapping->data);
    rel->released = platform_read_mapping_release_below(
        rel->mapping, rel->released, consumed);
}

#ifdef ZCL_TESTING
static int64_t g_bil_cancel_row = -1;
void block_index_history_test_cancel_row(int64_t row);
void block_index_history_test_cancel_row(int64_t row)
{
    g_bil_cancel_row = row;
}
#endif

static bool bil_flat_insert_cancelled(bool cancellable, uint32_t row)
{
    bool cancel = cancellable && (row & 0xFFFF) == 0 && thread_registry_shutdown_requested();
#ifdef ZCL_TESTING
    cancel = cancel || (cancellable && (int64_t)row == g_bil_cancel_row);
#endif
    return cancel;
}

static struct zcl_result bil_flat_insert_rows(
    struct main_state *ms, struct bil_flat_release *rel,
    uint32_t count, struct block_index *arena, bool cancellable)
{
    /* Bulk insert directly into the hash table; loader is single-threaded. */
    const struct block_index_flat *entries = rel->entries;
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
        if (bil_flat_insert_cancelled(cancellable, i)) {
            bil_flat_rollback(bm, arena, count);
            return ZCL_ERR(-5, "history archive: cancelled");
        }
        /* Feed the supervisor_backstop liveness marker every 64K entries so
         * this single-threaded pre-serving loop over ~3.1M entries is not
         * mistaken for a frozen supervisor sweep (util/boot_phase.h). */
        if ((i & 0xFFFF) == 0) {
            boot_progress_note("block_index.flat_insert", i, count);
            bil_flat_release_rows(rel, i);
        }
        if (uint256_is_null((const struct uint256 *)entries[i].hash))
            continue;

        /* Per-row inner admission gate (POINT 1 admission strength): re-check
         * the stored hash meets its own PoW target. A failing row is dropped
         * per-row (not inserted → header sync + body_fetch re-supply it) rather
         * than admitted below PoW strength. Skipped when cp is NULL (see above)
         * so it can never drop every row on a missing params table. */
        uint32_t effective_bits;
        if (!block_index_row_admit(entries[i].height, entries[i].hash,
                                   entries[i].prev_hash, entries[i].n_bits, cp,
                                   &flat_bad_count, &effective_bits))
            continue;

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
    struct block_map *bm, struct bil_flat_release *rel,
    uint32_t count, struct block_index *arena)
{
    const struct block_index_flat *entries = rel->entries;
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
        if ((i & 0xFFFF) == 0) {
            boot_progress_note("block_index.flat_link", i, count);
            bil_flat_release_rows(rel, i);
        }
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

/* ── File-backed load arena ────────────────────────────────
 *
 * Scout-verified design (lane block-index-arena-mmap-1111): the bulk-load
 * arena is a MAP_SHARED mapping over a REAL datadir file — deliberately a
 * file, not memfd and not the former zcl_calloc anonymous block. Dirty
 * arena pages write back to the page cache and become evictable clean
 * pages under memory pressure WITHOUT swap; anonymous arena pages stay
 * unswappable resident memory for the whole process lifetime, and this
 * loader already sheds the source mapping in steps so the mapping and the
 * arena do not peak together (see bil_flat_release_rows above).
 *
 * <datadir>/.block_index.arena is PROCESS-LIFETIME SCRATCH: never a
 * parseable format, never read by any loader. It holds raw struct
 * block_index images with ABSOLUTE POINTERS valid only in this process,
 * and must not appear in backups or snapshots. The dot-prefix follows
 * this datadir's scratch-file convention (.cookie,
 * .install-request-XXXXXX); the datadir has no central exclusion
 * registry beyond that naming convention.
 *
 * Arena invariants (future edits must preserve): write-after-load only,
 * entries never individually freed, never resized. block_map_free
 * (chainstate.c) documents that block_index entries live for process
 * lifetime — it frees only the buckets — and post-boot inserts allocate
 * per-entry with zcl_calloc in chainstate_insert_block_index, so on
 * success this mapping is never munmap'd; process exit tears it down
 * with the map intact.
 *
 * O_CREAT|O_TRUNC gives every boot a freshly zeroed file whose
 * ftruncate extension reads as zeros, which is why bil_flat_load needs
 * no pre-fault memset. The fd is closed immediately after mmap — the
 * mapping holds the file open. On failure the scratch file is unlinked
 * and the caller falls back to a zcl_calloc arena: no POSIX mmap
 * (Windows), an unusable datadir path, or open/ftruncate/mmap refusal.
 * On success the file is left in place — the simpler portable shape:
 * the next boot's O_TRUNC reuses it (it never accumulates), while
 * unlink-after-mmap (also correct, the mapping pins the inode) would
 * only hide the arena footprint. One trade-off accepted: ENOSPC on
 * writeback of a MAP_SHARED page raises SIGBUS; a full datadir is
 * already fatal for a node that cannot write blocks. */
static bool bil_arena_file_map(const char *datadir, size_t count,
                               struct block_index **arena_out,
                               char *path_out, size_t path_cap)
{
    *arena_out = NULL;
    path_out[0] = '\0';
#if defined(_WIN32)
    /* No writable POSIX mmap here; the caller keeps the zcl_calloc arena. */
    (void)datadir; (void)count; (void)path_cap;
    return false;
#else
    size_t bytes = count * sizeof(struct block_index);
    if (!datadir || !datadir[0])
        return false;
    int n = snprintf(path_out, path_cap, "%s/.block_index.arena", datadir);
    if (n < 0 || (size_t)n >= path_cap) {
        path_out[0] = '\0';
        return false;
    }
    int afd = open(path_out, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (afd < 0)
        return false;
    /* bytes cannot exceed off_t here (64-bit off_t targets; a truncated
     * off_t would mmap past EOF and SIGBUS on first touch), but guard the
     * cast anyway before ftruncate. */
    /* Roundtrip-exact off_t check: on a 32-bit off_t target a bytes value
     * beyond its range would truncate in the casts below, mmap past EOF
     * and SIGBUS on first touch; the roundtrip refuses that here. */
    bool sized = (uintmax_t)(off_t)bytes == bytes &&
                 ftruncate(afd, (off_t)bytes) == 0;
    if (sized) {
        /* Best-effort full pre-allocation: the loader dirties every page
         * during load, so on a filesystem that supports it this surfaces
         * ENOSPC here as a clean refusal (anonymous fallback) instead of
         * an uncatchable SIGBUS mid-load. Tmpfs and friends may refuse
         * fallocate itself; proceeding then matches the pre-lane risk and
         * keeps the mapping testable on such datadirs. */
        (void)posix_fallocate(afd, 0, (off_t)bytes);
    }
    void *view = sized ? mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED,
                              afd, 0) : MAP_FAILED;
    close(afd); /* the mapping holds the file open from here */
    if (view == MAP_FAILED) {
        unlink(path_out);
        return false;
    }
    *arena_out = (struct block_index *)view;
    return true;
#endif
}

/* Allocate the load arena: file-backed when the datadir allows it (see
 * bil_arena_file_map above), the anonymous zcl_calloc fallback otherwise.
 * Returns the arena or NULL; *mapped_out tells bil_arena_release which
 * release form applies. */
static struct block_index *bil_arena_alloc(const char *datadir,
                                           uint32_t count, bool *mapped_out,
                                           char *path_out, size_t path_cap)
{
    struct block_index *arena = NULL;
    *mapped_out = bil_arena_file_map(datadir, count, &arena, path_out,
                                     path_cap);
    if (!arena)
        arena = zcl_calloc(count, sizeof(struct block_index), "block_index arena");
    return arena;
}

/* End-of-load arena disposition. Success keeps the arena: entries live for
 * process lifetime (invariants above) and the map retains it. Failure
 * releases it whole — bil_flat_insert_rows already rolled every arena
 * pointer out of the map before refusing. */
static void bil_arena_release(struct block_index *arena, bool mapped,
                              size_t bytes, const char *path, bool failed)
{
    if (!failed)
        return;
#if defined(_WIN32)
    (void)mapped; (void)bytes; (void)path; /* mapped is never true here */
    free(arena);
#else
    if (mapped) {
        munmap(arena, bytes);
        unlink(path);
    } else {
        free(arena);
    }
#endif
}

static struct zcl_result bil_flat_load(const char *datadir, struct main_state *ms,
                                       size_t max_entries, bool publish_identity)
{
    /* A failed or legacy load cannot inherit a verified snapshot identity. */
    if (publish_identity) block_index_flat_identity_forget();
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
    if ((size_t)count > max_entries) {
        flat_read_mapping_close(&mapping, fd);
        return ZCL_ERR(-12, "block_index_flat: %u entries exceed budget %zu", count, max_entries);
    }
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
    /* File-backed arena (see bil_arena_file_map and bil_arena_alloc); the
     * zcl_calloc fallback keeps every platform or path without a usable
     * mapping loading identically. */
    char arena_path[1024];
    size_t arena_bytes = (size_t)count * sizeof(struct block_index);
    bool arena_mapped;
    struct block_index *arena = bil_arena_alloc(datadir, count, &arena_mapped,
                                                arena_path,
                                                sizeof(arena_path));
    if (!arena) {
        flat_read_mapping_close(&mapping, fd);
        return ZCL_ERR(-10, "block_index_flat: arena allocation failed for %u "
                       "entries (%zu bytes)", count, arena_bytes);
    }
    /* No pre-fault memset (the former calloc path faulted pages here):
     * O_CREAT|O_TRUNC hands every boot a freshly zeroed file whose
     * ftruncate extension faults in zero-filled, exactly like the calloc
     * fallback's demand-zero anonymous pages. */
    void *release = NULL; /* heap scratch (the sorted array) freed at finish */
    int64_t t_parse_ms = 0, t_fwd_ms = 0;
    struct bil_flat_release rel = {.mapping = &mapping,
                                   .entries = input.entries};
    result = bil_flat_insert_rows(ms, &rel, count, arena, !publish_identity);
    if (!result.ok) {
        goto finish;
    }
    rel.released = 0;
    bil_flat_link_rows(&ms->map_block_index, &rel, count, arena);
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
    bil_arena_release(arena, arena_mapped, arena_bytes, arena_path,
                      !result.ok);
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
    if (arena_mapped)
        LOG_INFO("block_index_flat",
                 "Block index arena: file-backed mapping %zu bytes at %s",
                 arena_bytes, arena_path);
    if (publish_identity && input.have_identity) {
        input.identity.row_count = count;
        block_index_flat_identity_remember(datadir, &input.identity);
    }
    return result;
}

struct zcl_result load_block_index_flat_bounded(const char *datadir, struct main_state *ms,
                                                size_t max_entries)
{
    return bil_flat_load(datadir, ms, max_entries, true);
}

static struct zcl_result load_block_index_flat_archive(const char *datadir, struct main_state *ms,
                                                size_t max_entries)
{
    return bil_flat_load(datadir, ms, max_entries, false);
}

struct zcl_result block_index_history_index_load(const char *datadir, struct main_state *ms,
                                                  size_t max_entries)
{
    if (!datadir || !datadir[0] || !ms || !max_entries || ms->map_block_index.size ||
        ms->pindex_best_header || active_chain_cached_height(&ms->chain_active) >= 0)
        return ZCL_ERR(-1, "history index: invalid input or nonempty state");
    return load_block_index_flat_archive(datadir, ms, max_entries);
}

struct zcl_result load_block_index_flat(const char *datadir, struct main_state *ms)
{
    return load_block_index_flat_bounded(datadir, ms, SIZE_MAX);
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
        while (block_map_next(&ms->map_block_index, &iter, NULL, &pi)) {
            if (pi) {
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
            if (!block_index_initialize_genesis(genesis, params))
                return ZCL_ERR(-1, "load_block_index: compiled genesis initialization failed");
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
static bool bha_header(struct blocks_mmap *reader, const struct block_index *row,
                       struct block_header *header)
{
    size_t len = 0;
    if (!row || !row->phashBlock || row->nFile < 0) return false;
    const uint8_t *payload = bmr_get_payload(reader, row->nFile, row->nDataPos, &len);
    if (!payload) return false;
    struct byte_stream stream;
    stream_init_from_data(&stream, payload, len);
    block_header_init(header);
    if (!block_header_deserialize(header, &stream)) return false;
    struct uint256 hash;
    block_header_get_hash(header, &hash);
    return uint256_eq(&hash, row->phashBlock) && header->nVersion == row->nVersion &&
        header->nTime == row->nTime && header->nBits == row->nBits &&
        uint256_eq(&header->hashFinalSaplingRoot, &row->hashFinalSaplingRoot);
}

static bool bha_row_valid(struct main_state *state, struct blocks_mmap *reader,
                          struct block_index *row, int32_t height, struct block_header *header)
{
    return row && row->nHeight == height && row->phashBlock &&
        block_map_find(&state->map_block_index, row->phashBlock) == row && bha_header(reader, row, header);
}

static bool bha_link_valid(const struct block_index *row, const struct block_header *header,
                           int32_t height, const struct uint256 *genesis)
{
    if (height == 0)
        return !row->pprev && uint256_eq(row->phashBlock, genesis) && uint256_is_null(&header->hashPrevBlock);
    return row->pprev && row->pprev->phashBlock &&
        uint256_eq(&header->hashPrevBlock, row->pprev->phashBlock);
}

#ifdef ZCL_TESTING
static int32_t g_bha_cancel_height = -1;
void block_index_history_test_cancel_height(int32_t height);
void block_index_history_test_cancel_height(int32_t height)
{
    g_bha_cancel_height = height;
}
#endif

static bool bha_cancelled(int32_t height)
{
#ifdef ZCL_TESTING
    if (height == g_bha_cancel_height) return true;
#else
    (void)height;
#endif
    return thread_registry_shutdown_requested();
}

static bool bha_chain(struct main_state *state, struct blocks_mmap *reader,
                      struct block_index *tip, int32_t height, const struct uint256 *genesis,
                      struct block_header *top_window, bool *cancelled)
{
    struct block_index *row = tip;
    for (int32_t h = height; h >= 0; h--) {
        if (bha_cancelled(h)) { *cancelled = true; return false; }
        struct block_header header;
        if (!bha_row_valid(state, reader, row, h, &header) ||
            !bha_link_valid(row, &header, h, genesis)) {
            LOG_WARN("block_index_flat", "history archive header or ancestry invalid at height %d", (int)h);
            return false;
        }
        if (height - h < ISLAND_ANCHOR_WINDOW) {
            if (!block_index_set_hdrext(row, &header.hashMerkleRoot, &header.nNonce,
                                        header.nSolution, header.nSolutionSize)) {
                LOG_WARN("block_index_flat", "history archive header extension failed at height %d", (int)h);
                return false;
            }
            if (top_window) top_window[height - h] = header;
        }
        if (h == 0) return true;
        row = row->pprev;
    }
    return false;
}

static bool bha_input_valid(const struct main_state *state, const char *dir, size_t max_entries,
                            int32_t height, const uint8_t *hash, const struct uint256 *genesis,
                            const struct block_header *window)
{
    return state && dir && dir[0] && hash && genesis && height >= 0 && max_entries > 0 &&
        (size_t)height < max_entries && (!window || height >= ISLAND_ANCHOR_WINDOW - 1) &&
        !state->map_block_index.size && !state->pindex_best_header &&
        active_chain_cached_height(&state->chain_active) < 0;
}

static struct zcl_result bha_open(struct main_state *state,
    const char *archive_dir, size_t max_entries, int32_t endpoint_height,
    const uint8_t endpoint_hash[32], const struct uint256 *genesis, struct block_header *top_window)
{
    if (top_window) memset(top_window, 0, ISLAND_ANCHOR_WINDOW * sizeof(*top_window));
    if (!bha_input_valid(state, archive_dir, max_entries, endpoint_height, endpoint_hash, genesis, top_window))
        return ZCL_ERR(-1, "history archive: invalid input or nonempty state");
    struct zcl_result loaded = load_block_index_flat_archive(archive_dir, state, max_entries);
    if (!loaded.ok) return loaded;
    if (bha_cancelled(endpoint_height)) return ZCL_ERR(-5, "history archive: cancelled");
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/blocks", archive_dir);
    struct blocks_mmap *reader = NULL;
    if (n < 0 || (size_t)n >= sizeof(path) || !bmr_open(path, &reader))
        return ZCL_ERR(-2, "history archive: cannot open block directory");
    bmr_advise_reverse(reader);
    struct uint256 hash; memcpy(hash.data, endpoint_hash, sizeof(hash.data));
    struct block_index *tip = block_map_find(&state->map_block_index, &hash);
    bool cancelled = false;
    bool valid = bha_chain(state, reader, tip, endpoint_height, genesis, top_window, &cancelled);
    bmr_close(reader);
    if (!valid) {
        if (top_window) memset(top_window, 0, ISLAND_ANCHOR_WINDOW * sizeof(*top_window));
        if (cancelled) return ZCL_ERR(-5, "history archive: cancelled");
        return ZCL_ERR(-3, "history archive: header ancestry invalid or unavailable");
    }
    if (!active_chain_move_window_tip(&state->chain_active, tip)) {
        if (top_window) memset(top_window, 0, ISLAND_ANCHOR_WINDOW * sizeof(*top_window));
        return ZCL_ERR(-4, "history archive: active-chain selection refused");
    }
    state->pindex_best_header = tip;
    return ZCL_OK;
}

struct zcl_result block_index_history_archive_open(struct main_state *state,
    const char *archive_dir, size_t max_entries, int32_t endpoint_height,
    const uint8_t endpoint_hash[32], struct block_header *top_window)
{
    const struct chain_params *params = chain_params_get();
    if (!params) {
        if (top_window) memset(top_window, 0, ISLAND_ANCHOR_WINDOW * sizeof(*top_window));
        return ZCL_ERR(-1, "history archive: network unavailable");
    }
    return bha_open(state, archive_dir, max_entries, endpoint_height, endpoint_hash,
                    &params->consensus.hashGenesisBlock, top_window);
}
#ifdef ZCL_TESTING
struct zcl_result block_index_history_archive_test_open(struct main_state *state,
    const char *archive_dir, size_t max_entries, int32_t endpoint_height,
    const uint8_t endpoint_hash[32], const struct uint256 *genesis, struct block_header *top_window)
{
    return bha_open(state, archive_dir, max_entries, endpoint_height, endpoint_hash, genesis, top_window);
}
#endif
