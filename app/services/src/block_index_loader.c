/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block Index Loader: read/write block_index.bin flat file, SQLite cache, and
 * LevelDB block tree compatibility. */

#include "platform/time_compat.h"
#include "services/block_index_loader.h"
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
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
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

/* Compact on-disk format: height-sorted, 172 bytes per entry (packed). The
 * size-on-disk math below uses sizeof(struct block_index_flat), so it tracks
 * this layout automatically. */
struct __attribute__((packed)) block_index_flat {
    uint8_t  hash[32];
    uint8_t  prev_hash[32];
    int32_t  height;
    uint32_t n_bits;
    uint32_t n_time;
    int32_t  n_version;
    uint32_t n_status;
    int32_t  n_file;
    uint32_t n_data_pos;
    uint32_t n_undo_pos;
    uint32_t n_tx;
    uint32_t n_chain_tx;
    uint8_t  chain_work[32];
    uint32_t n_cached_branch_id;
    uint8_t  sapling_root[32];
};

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

static int cmp_height(const void *a, const void *b)
{
    const struct block_index *pa = *(const struct block_index *const *)a;
    const struct block_index *pb = *(const struct block_index *const *)b;
    if (pa->nHeight < pb->nHeight) return -1; // raw-return-ok:qsort-comparator
    if (pa->nHeight > pb->nHeight) return 1;
    return 0;
}

/* Forward pass over a height-sorted block_index array: recompute nChainWork,
 * nChainTx, skip links, cached branch id, and failed-child propagation from
 * each entry's already-linked pprev. Shared by the legacy LevelDB loader and
 * the event-log projection rebuild so both compute pointer-graph-derived
 * fields through one helper. Declared in services/block_index_loader.h. */
void block_index_forward_pass(struct block_index **sorted,
                              size_t count)
{
    for (size_t i = 0; i < count; i++) {
        struct block_index *pindex = sorted[i];

        struct arith_uint256 proof = GetBlockProof(pindex);
        if (pindex->pprev)
            arith_uint256_add(&pindex->nChainWork,
                              &pindex->pprev->nChainWork, &proof);
        else
            pindex->nChainWork = proof;

        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx)
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                else
                    pindex->nChainTx = 0;
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }

        block_index_build_skip(pindex);

        if (pindex->pprev) {
            if (block_index_is_valid(pindex, BLOCK_VALID_CONSENSUS) &&
                !pindex->nCachedBranchId)
                pindex->nCachedBranchId = pindex->pprev->nCachedBranchId;
        }

        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev &&
            (pindex->pprev->nStatus & BLOCK_FAILED_MASK))
            pindex->nStatus |= BLOCK_FAILED_CHILD;
    }
}

/* After the map is loaded and the forward pass has recomputed nChainWork,
 * make the header frontier REAL: publish the max-chainwork header into
 * pindex_best_header and seat it in the active_chain[] window.
 *
 * THE LINCHPIN. On a full-index boot (`--importblockindex` then a normal
 * boot) load_block_index fills the header MAP but the empty-datadir fallback
 * is the ONLY path that ever set pindex_best_header or the active_chain
 * window. So active_chain_tip() stays NULL over a map of millions of headers,
 * push_getheaders falls to a genesis-only locator, and header sync pins near
 * genesis with nothing to escalate it. Promoting the best header here anchors
 * the getheaders locator at the true frontier so block bodies can be fetched
 * and folded forward.
 *
 * This changes ONLY which header the chain/locator anchors at — never
 * consensus validity, coins, or H*. active_chain_height()/tip() defer to the
 * reducer authority once tip_finalize registers it, and getblockcount/health
 * read H* (the committed reducer prefix), so a served tip seated above coins
 * is the designed recovered-datadir state (see tip_finalize_stage_init), not a
 * false "synced" claim. Idempotent (work-ranked promotion never downgrades)
 * and safe: a later coins-reconcile (bii_anchor) only restores the tip UP to
 * the coins height, never below this frontier. */
void promote_best_header_after_load(struct main_state *ms,
                                    struct block_index **sorted,
                                    size_t count)
{
    if (!ms || !sorted || count == 0)
        return;

    struct block_index *best = NULL;
    for (size_t i = 0; i < count; i++) {
        struct block_index *pi = sorted[i];
        if (!pi || !pi->phashBlock)
            continue;
        if (pi->nStatus & BLOCK_FAILED_MASK)
            continue;
        if (!best) {
            best = pi;
            continue;
        }
        bool have_work = !arith_uint256_is_zero(&pi->nChainWork) &&
                         !arith_uint256_is_zero(&best->nChainWork);
        bool better = have_work
            ? arith_uint256_compare(&pi->nChainWork, &best->nChainWork) > 0
            : pi->nHeight > best->nHeight;
        if (better)
            best = pi;
    }
    if (!best)
        return;

    /* (1) Publish the header frontier through the work-ranked CSR seam — the
     * same primitive header_admit_stage uses on the live path. Idempotent:
     * a strictly-better candidate wins, otherwise this is a no-op. */
    bool promoted = false;
    enum csr_result prc = csr_promote_header_tip(
        csr_instance(), &ms->chain_active, &ms->pindex_best_header, best,
        "loader_best_header", &promoted);
    if (prc != CSR_OK) {
#ifdef ZCL_TESTING
        /* Isolated fixtures do not boot the process-wide CSR — mirror
         * header_admit_stage's test-only fallback so the frontier is still
         * published. */
        if (prc == CSR_REJECTED_NOT_INITIALIZED) {
            struct block_index *current = ms->pindex_best_header;
            bool advance = current == NULL;
            if (current && current != best) {
                bool have_work =
                    !arith_uint256_is_zero(&best->nChainWork) &&
                    !arith_uint256_is_zero(&current->nChainWork);
                advance = have_work
                    ? arith_uint256_compare(&best->nChainWork,
                                            &current->nChainWork) > 0
                    : best->nHeight > current->nHeight;
            }
            if (advance)
                ms->pindex_best_header = best;
        } else
#endif
        LOG_WARN("block_index",
                 "loader: best-header promotion rejected code=%s h=%d",
                 csr_result_name(prc), best->nHeight);
    }

    /* (2) Seat the frontier in the active_chain[] window so active_chain_tip()
     * is non-NULL over a non-empty map. Only advance — never downgrade a
     * higher window a prior step may have installed. chain_set_active_tip
     * publishes the served-tip authority + events; a NULL/OOM refusal is
     * non-fatal (pindex_best_header still carries the frontier and the
     * NULL-tip locator anchors there). */
    struct block_index *cur = active_chain_cached_tip(&ms->chain_active);
    if (!cur || best->nHeight > cur->nHeight) {
        struct zcl_result r = chain_set_active_tip(ms, best,
                                                   TIP_FROM_P2P_REPAIR,
                                                   "loader_best_header");
        if (!r.ok)
            LOG_WARN("block_index",
                     "loader: best-header window seat failed h=%d: %s",
                     best->nHeight, r.message);
    }
}

/* ── save_block_index_flat ───────────────────────────────── */

/* Stream "ZCLI"+count+entries after the integrity header while hashing the
 * exact payload. The shared helper back-patches its commitment and publishes
 * the whole file with one atomic rename. */
struct bif_emit_ctx {
    struct main_state  *ms;
    struct block_index **sorted;
    size_t               count;
};
static bool bif_emit_payload(FILE *f, void *vctx,
                             uint64_t *out_payload_size,
                             uint8_t out_payload_sha3[32])
{
    struct bif_emit_ctx *c = (struct bif_emit_ctx *)vctx;
    struct sha3_256_ctx hctx;
    sha3_256_init(&hctx);
    uint64_t bytes = 0;
    uint32_t magic = 0x5A434C49; /* "ZCLI" payload magic */
    uint32_t count32 = (uint32_t)c->count;
    if (fwrite(&magic, 4, 1, f) != 1 || // disk-io-lock: private-fd (block index flat file)
        fwrite(&count32, 4, 1, f) != 1) {
        LOG_FAIL("block_index_flat",
                 "save_block_index_flat: payload header write failed");
    }
    sha3_256_write(&hctx, (const uint8_t *)&magic, 4);
    sha3_256_write(&hctx, (const uint8_t *)&count32, 4);
    bytes += 8;

    for (size_t i = 0; i < c->count; i++) {
        struct block_index_flat entry;
        memset(&entry, 0, sizeof(entry));
        if (c->sorted[i]->phashBlock)
            memcpy(entry.hash, c->sorted[i]->phashBlock->data, 32);
        if (c->sorted[i]->pprev && c->sorted[i]->pprev->phashBlock)
            memcpy(entry.prev_hash, c->sorted[i]->pprev->phashBlock->data, 32);
        entry.height = c->sorted[i]->nHeight;
        entry.n_bits = c->sorted[i]->nBits;
        entry.n_time = c->sorted[i]->nTime;
        entry.n_version = c->sorted[i]->nVersion;
        entry.n_status = c->sorted[i]->nStatus;
        entry.n_file = c->sorted[i]->nFile;
        entry.n_data_pos = c->sorted[i]->nDataPos;
        entry.n_undo_pos = c->sorted[i]->nUndoPos;
        entry.n_tx = c->sorted[i]->nTx;
        entry.n_chain_tx = c->sorted[i]->nChainTx;
        memcpy(entry.chain_work, c->sorted[i]->nChainWork.pn, 32);
        entry.n_cached_branch_id = (uint32_t)c->sorted[i]->nCachedBranchId;
        memcpy(entry.sapling_root, c->sorted[i]->hashFinalSaplingRoot.data, 32);
        if (fwrite(&entry, sizeof(entry), 1, f) != 1) { // disk-io-lock: private-fd
            LOG_FAIL("block_index_flat",
                     "save_block_index_flat: write failed at entry "
                     "%zu/%zu: %s", i, c->count, strerror(errno));
        }
        sha3_256_write(&hctx, (const uint8_t *)&entry, sizeof(entry));
        bytes += sizeof(entry);
    }
    uint8_t anchor[BIFA_TRAILER_MAX];
    size_t anchor_len = 0;
    struct zcl_result ar = block_index_flat_anchor_encode(
        c->ms, c->sorted, c->count, anchor, sizeof(anchor), &anchor_len);
    if (!ar.ok)
        return false;
    if (anchor_len) {
        if (fwrite(anchor, anchor_len, 1, f) != 1) {
            LOG_FAIL("block_index_flat",
                     "save_block_index_flat: anchor trailer write failed");
        }
        sha3_256_write(&hctx, anchor, anchor_len);
        bytes += anchor_len;
    }
    sha3_256_finalize(&hctx, out_payload_sha3);
    *out_payload_size = bytes;
    return true;
}

void save_block_index_flat(const char *datadir, struct main_state *ms)
{
    size_t count = ms->map_block_index.size;
    struct block_index **sorted = zcl_malloc(count * sizeof(void *), "block_index sorted save");
    if (!sorted) {
        LOG_WARN("block_index_flat",
                 "save_block_index_flat: malloc failed for %zu entries",
                 count);
        return;
    }

    size_t idx = 0, iter = 0;
    struct block_index *p;
    while (block_map_next(&ms->map_block_index, &iter, NULL, &p)) {
        if (p && idx < count) sorted[idx++] = p;
    }
    count = idx;

    qsort(sorted, count, sizeof(struct block_index *), cmp_height);

    int64_t t0 = (int64_t)platform_time_wall_time_t();

    /* ONE file, ONE rename. The 48-byte integrity header (magic
     * "BIIE", version 2, payload size + SHA3-256) prefixes the body
     * inside block_index.bin itself, so a kill anywhere before the
     * single rename leaves only the old good file — there is no second
     * sidecar file and therefore no inter-rename window that can strand
     * a fresh body under a stale commitment. No lock is taken on this
     * path (it only iterates the single-threaded block_map), so the
     * shutdown/drive lock order is unaffected. */
    struct bif_emit_ctx ectx = { .ms = ms, .sorted = sorted, .count = count };
    struct zcl_result wr = bii_write_embedded(datadir, bif_emit_payload, &ectx);
    free(sorted);
    if (!wr.ok) {
        LOG_WARN("save_block_index_flat",
                 "save_block_index_flat: embedded write failed: %s",
                 wr.message);
        return;
    }

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index_flat",
             "Block index flat file: %zu entries, %zuMB (%llds)",
             count, count * sizeof(struct block_index_flat) / (1024*1024),
             (long long)elapsed);
}

/* ── load_block_index_flat ───────────────────────────────── */

struct zcl_result load_block_index_flat(const char *datadir, struct main_state *ms)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ZCL_ERR(-1, "block_index_flat: cannot open %s: %s",
                       path, strerror(errno));

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        close(fd);
        return ZCL_ERR(-2, "block_index_flat: fstat failed: %s",
                       strerror(saved_errno));
    }
    size_t file_size = (size_t)st.st_size;
    if (file_size < 8) {
        close(fd);
        return ZCL_ERR(-3, "block_index_flat: file too small (%zu bytes)",
                       file_size);
    }

    uint8_t *data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED)
        return ZCL_ERR(-4, "block_index_flat: mmap failed (%zu bytes): %s",
                       file_size, strerror(errno));

    /* BIIE embeds a 48-byte integrity header; legacy ZCLI begins at offset 0.
     * Verify the embedded payload before reading any row. */
    uint64_t payload_off = 0;
    {
        uint32_t lead;
        memcpy(&lead, data, 4);
        uint32_t embedded_magic;
        memcpy(&embedded_magic, BII_EMBEDDED_MAGIC, 4);
        if (lead == embedded_magic) {
            /* Re-hash before trusting the payload. */
            struct ssio_sidecar_header ehdr;
            int ev = bii_verify_embedded(datadir, &ehdr, &payload_off);
            if (ev != 0) {
                munmap(data, file_size);
                return ZCL_ERR(-5, "block_index_flat: embedded integrity check "
                               "FAILED (verdict=%d) — refusing the body", ev);
            }
        }
        /* Legacy ZCLI keeps payload_off=0; its sidecar gate is downstream. */
    }

    uint32_t magic, count;
    memcpy(&magic, data + payload_off, 4);
    memcpy(&count, data + payload_off + 4, 4);
    if (magic != 0x5A434C49) {
        munmap(data, file_size);
        return ZCL_ERR(-6, "block_index_flat: bad payload magic 0x%08x "
                       "(expected 0x5A434C49)", magic);
    }
    if (count > 10000000) {
        munmap(data, file_size);
        return ZCL_ERR(-7, "block_index_flat: count %u too large (max 10M)",
                       count);
    }
    if (count == 0) {
        /* An empty index is useless and would make entries[count-1] below an
         * out-of-bounds read (entries[-1]); reject so the caller re-derives. */
        munmap(data, file_size);
        return ZCL_ERR(-8, "block_index_flat: empty index (count 0)");
    }

    size_t expected = payload_off + 8 + (size_t)count * sizeof(struct block_index_flat);
    if (file_size < expected) {
        munmap(data, file_size);
        return ZCL_ERR(-9, "block_index_flat: truncated — %zu bytes < %zu "
                       "expected (%u entries)", file_size, expected, count);
    }

    int64_t t0 = (int64_t)platform_time_wall_time_t();
    int64_t t0_ms = platform_time_monotonic_ms();  /* ms-resolution split timer */
    const struct block_index_flat *entries =
        (const struct block_index_flat *)(data + payload_off + 8);

    /* Pre-size hash map + arena. Pre-fault memory. */
    block_map_reserve(&ms->map_block_index, count);
    struct block_index *arena = zcl_calloc(count, sizeof(struct block_index), "block_index arena");
    if (!arena) {
        munmap(data, file_size);
        return ZCL_ERR(-10, "block_index_flat: calloc failed for %u entries "
                       "(%zu bytes)", count,
                       (size_t)count * sizeof(struct block_index));
    }
    memset(arena, 0, count * sizeof(struct block_index)); /* pre-fault */

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
        if (cp && block_row_verify(entries[i].hash, entries[i].n_bits, NULL,
                                   cp, false) != BLOCK_ROW_VERIFY_OK) {
            flat_quarantine_row(entries[i].height, entries[i].hash,
                                &flat_bad_count);
            continue;
        }

        struct block_index *pindex = &arena[i];
        block_index_init(pindex);

        uint64_t h;
        memcpy(&h, entries[i].hash, 8);
        size_t slot = h & (bm->capacity - 1);
        bool duplicate = false;
        while (bm->buckets[slot].occupied) {
            if (uint256_eq(&bm->buckets[slot].hash,
                           (const struct uint256 *)entries[i].hash)) {
                duplicate = true;
                break;
            }
            slot = (slot + 1) & (bm->capacity - 1);
        }
        if (duplicate) continue;
        memcpy(bm->buckets[slot].hash.data, entries[i].hash, 32);
        bm->buckets[slot].index = pindex;
        bm->buckets[slot].occupied = true;
        bm->size++;

        /* Option A: point phashBlock at per-node storage, not the bucket.
         * The bucket keeps its own .hash key (memcpy above) for lookups. */
        memcpy(pindex->hashBlock.data, entries[i].hash, 32);
        pindex->phashBlock = &pindex->hashBlock;
        pindex->nHeight = entries[i].height;
        pindex->nBits = entries[i].n_bits;
        pindex->nTime = entries[i].n_time;
        pindex->nVersion = entries[i].n_version;
        pindex->nStatus = entries[i].n_status;
        pindex->nFile = entries[i].n_file;
        pindex->nDataPos = entries[i].n_data_pos;
        pindex->nUndoPos = entries[i].n_undo_pos;
        pindex->nTx = entries[i].n_tx;
        pindex->nChainTx = entries[i].n_chain_tx;
        memcpy(pindex->nChainWork.pn, entries[i].chain_work, 32);
        pindex->nCachedBranchId = entries[i].n_cached_branch_id;
        memcpy(pindex->hashFinalSaplingRoot.data, entries[i].sapling_root, 32);

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

    /* Old files end at `expected`; old readers ignore the new trailer. */
    if (file_size > expected) {
        struct zcl_result ar = block_index_flat_anchor_apply(
            ms, data + expected, file_size - expected);
        if (!ar.ok)
            LOG_WARN("block_index_flat", "%s", ar.message);
    }

    /* Timing only (no behavior change): the qsort + forward pass below is a
     * distinct cost class from the parse/insert loop above (it sorts and walks
     * all ~3M entries a second time). Split them so the warm-start profile can
     * tell parse/insert time from forward-pass time. Cheap monotonic reads. */
    int64_t t_parse_ms = platform_time_monotonic_ms() - t0_ms;
    int64_t t_fwd_ms = platform_time_monotonic_ms();

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
    struct block_index **sorted =
        zcl_malloc((size_t)count * sizeof(*sorted), "flat forward pass");
    if (sorted) {
        size_t n = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (arena[i].phashBlock)
                sorted[n++] = &arena[i];
        }
        qsort(sorted, n, sizeof(*sorted), cmp_height);
        block_index_forward_pass(sorted, n);
        free(sorted);
    } else {
        /* boot's later multi-pass nChainTx propagation still runs;
         * work/skip recompute is what we lose — log it. */
        LOG_WARN("block_index_flat", "block_index_flat: forward-pass alloc failed "
                 "(%u entries) — chain stats may be stale", count);
    }

    munmap(data, file_size);

    t_fwd_ms = platform_time_monotonic_ms() - t_fwd_ms;
    printf("[boot]   %-28s %lldms\n", "blkidx.flat_parse_insert",
           (long long)t_parse_ms);
    printf("[boot]   %-28s %lldms\n", "blkidx.flat_forward_pass",
           (long long)t_fwd_ms);

    int64_t elapsed = (int64_t)platform_time_wall_time_t() - t0;
    LOG_INFO("block_index_flat",
             "Block index flat: loaded %u entries in %llds",
             count, (long long)elapsed);

    return ZCL_OK;
}

/* ── block_index_flat_header_at ────────────────────────────── */
struct zcl_result block_index_flat_header_at(const char *datadir,
                                             int32_t height,
                                             uint8_t out_hash[32],
                                             uint8_t out_root[32])
{
    if (!datadir || height < 0 || !out_hash || !out_root)
        return ZCL_ERR(-100, "block_index_flat_header_at: bad args");

    char path[1024];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ZCL_ERR(-101, "block_index_flat_header_at: cannot open "
                       "%s: %s", path, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int saved_errno = errno;
        close(fd);
        return ZCL_ERR(-102, "block_index_flat_header_at: fstat: %s",
                       strerror(saved_errno));
    }
    size_t file_size = (size_t)st.st_size;
    if (file_size < 8) {
        close(fd);
        return ZCL_ERR(-103, "block_index_flat_header_at: file too "
                       "small (%zu bytes)", file_size);
    }
    uint8_t *data = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED)
        return ZCL_ERR(-104, "block_index_flat_header_at: mmap "
                       "(%zu bytes): %s", file_size, strerror(errno));

    /* Same integrity posture as load_block_index_flat: a BIIE-magic file
     * is trusted only after the embedded SHA3 verifies; a legacy "ZCLI"
     * body has no embedded commitment and is REFUSED here — a bind this
     * load-bearing does not read unverified bytes. */
    uint64_t payload_off = 0;
    {
        uint32_t lead;
        memcpy(&lead, data, 4);
        uint32_t embedded_magic;
        memcpy(&embedded_magic, BII_EMBEDDED_MAGIC, 4);
        if (lead != embedded_magic) {
            munmap(data, file_size);
            return ZCL_ERR(-105, "block_index_flat_header_at: no "
                           "embedded integrity header (legacy format) — "
                           "refusing unverified bytes");
        }
        struct ssio_sidecar_header ehdr;
        int ev = bii_verify_embedded(datadir, &ehdr, &payload_off);
        if (ev != 0) {
            munmap(data, file_size);
            return ZCL_ERR(-106, "block_index_flat_header_at: "
                           "embedded integrity check FAILED (verdict=%d)",
                           ev);
        }
    }

    uint32_t magic, count;
    memcpy(&magic, data + payload_off, 4);
    memcpy(&count, data + payload_off + 4, 4);
    if (magic != 0x5A434C49) {
        munmap(data, file_size);
        return ZCL_ERR(-107, "block_index_flat_header_at: bad payload "
                       "magic 0x%08x", magic);
    }
    if (count == 0 || count > 10000000) {
        munmap(data, file_size);
        return ZCL_ERR(-108, "block_index_flat_header_at: count %u "
                       "out of range", count);
    }
    size_t expected = payload_off + 8 +
                      (size_t)count * sizeof(struct block_index_flat);
    if (file_size < expected) {
        munmap(data, file_size);
        return ZCL_ERR(-109, "block_index_flat_header_at: truncated "
                       "(%zu < %zu bytes for %u entries)",
                       file_size, expected, count);
    }

    /* Height-sorted rows: lower-bound binary search, exact-height test.
     * Siblings sharing a height return an arbitrary one — a caller binding
     * a shielded frontier against a foreign root fails CLOSED downstream
     * (the by-root source lookup), never a silent misbind. */
    const struct block_index_flat *entries =
        (const struct block_index_flat *)(data + payload_off + 8);
    uint32_t lo = 0, hi = count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (entries[mid].height < height)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo >= count || entries[lo].height != height) {
        int32_t max_h = count ? entries[count - 1].height : -1;
        munmap(data, file_size);
        return ZCL_ERR(-110, "block_index_flat_header_at: no row at "
                       "height %d (flat tip %d) — the last flat save "
                       "predates that header", height, max_h);
    }
    memcpy(out_hash, entries[lo].hash, 32);
    memcpy(out_root, entries[lo].sapling_root, 32);
    munmap(data, file_size);
    return ZCL_OK;
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
            genesis->nBits = 0x1f07ffff;
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

    qsort(sorted, count, sizeof(struct block_index *), cmp_height);

    block_index_forward_pass(sorted, count);

    /* THE LINCHPIN: make the header frontier real so active_chain_tip() is not
     * NULL over this just-loaded map and header sync anchors above genesis. */
    promote_best_header_after_load(ms, sorted, count);

    free(sorted);
    return ZCL_OK;
}
